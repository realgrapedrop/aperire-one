package interrogate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// The ten menu items, §4. Naming them as constants rather than leaving the
// strings to scatter through the package is what makes knownReads and the
// switch in validateRequest exhaustive by inspection.
const (
	ReadNodeLedgers       = "node_ledgers"
	ReadMetricHistory     = "metric_history"
	ReadMetricRecent      = "metric_recent"
	ReadAgreementWindow   = "agreement_window"
	ReadMissedLedgers     = "missed_ledgers"
	ReadAlerts            = "alerts"
	ReadFiring            = "firing"
	ReadPublicLedger      = "public_ledger"
	ReadPublicLedgerRange = "public_ledger_range"
	ReadPublicValidator   = "public_validator"
	ReadHost              = "host_read"
	// ReadRestartAssessment is the readings, the measured expectation and
	// the concerns /v1/check computes for RB-002 before an operator is
	// asked for a final yes (ADR 0016, amended 2026-08-19). It is NOT a
	// privileged host read: it names no verb, reaches no wrapper argument
	// the model chose, and returns exactly what the tab already polls on
	// its own every thirty seconds. So it is available at both tiers and
	// costs nothing against the privileged-read cap — a model that has to
	// break glass to look before it proposes an act would be a model that
	// proposes the act first.
	//
	// What it deliberately does NOT carry: plan_id, fingerprint and
	// confirm_code. Those identify and authorise a plan, and the model has
	// no business holding them — the service mints them itself when it
	// validates the action, and the page renders the gate from the
	// service's copy.
	ReadRestartAssessment = "restart_assessment"
	// ReadUpgradeAssessment is the same idea for RB-001: the readings
	// /v1/check computes before an operator is asked to approve an upgrade
	// — what is running, what the deployment names, what release is
	// available, every precondition's verdict, and how long the node is
	// expected to be away. Available at both tiers and free against the
	// privileged-read cap, for the same reason restart_assessment is: a
	// model that has to break glass before it may LOOK is a model that
	// proposes the act first and looks afterwards.
	//
	// It withholds plan_id, fingerprint and confirm_code, exactly as the
	// restart's does. Those identify and authorise a plan; the service
	// mints its own copy when it validates the action, and a model that
	// never sees a confirm code cannot leak one into an answer.
	ReadUpgradeAssessment = "upgrade_assessment"
	// ReadConfigAssessment is RB-003's equivalent — ADR 0018. What the four
	// allow-listed settings are set to on this node right now, what band
	// each may move within, whether the key is read at startup (all four
	// are), when the node last restarted, and how consensus looks. It is
	// available at both tiers and free against the privileged-read cap for
	// the reason the other two assessments are: a model that has to break
	// glass before it may LOOK is a model that proposes first and looks
	// afterwards.
	//
	// It withholds plan_id, fingerprint and confirm_code, exactly as they
	// do. It also withholds the raw before/after lines: the diff the
	// operator approves is computed by the service from the node's own
	// configuration and travels in the action block, never through the
	// model's context.
	ReadConfigAssessment = "config_assessment"
	// ReadRollbackAssessment is RB-004's — ADR 0019. What this node would
	// roll back TO, where that version was derived from (the newest dated
	// deployment copy naming another version, and the node's own run
	// history), how long the running build has been in place, and whether it
	// has been writing the data store since it arrived.
	//
	// Available at both tiers and free against the privileged-read cap, for
	// the reason the other three assessments are. It withholds plan_id,
	// fingerprint and confirm_code, exactly as they do — and the target it
	// names is a reading, not a permission: the service re-derives it when it
	// validates the action and refuses anything else.
	ReadRollbackAssessment = "rollback_assessment"
	// ReadNodeConfig is the four allow-listed rippled settings a node runs,
	// node_size, ledger_history, online_delete, advisory_delete, as that
	// node's own dashboard read them from its rippled.cfg (#59, ADR 0008's
	// `node-config` route).
	//
	// It exists because "what is node_size on that other node" was the
	// question that opened the issue and nothing on this menu could answer
	// it for anybody but this host. config_assessment reads THIS host
	// through the privilege wrapper and cannot be pointed at a peer (the
	// registry cannot express a wrapper, risk S1); this reads the same four
	// settings out of a dashboard, which is a channel the registry already
	// expresses, so it is nodeable.
	//
	// It carries the four values and nothing else: no path, no credential,
	// no other stanza. Two of the four are already served to any holder of
	// the read token by the `system` route, and the other two are sizing
	// settings of the same kind, so this widens nothing.
	ReadNodeConfig = "node_config"
)

var knownReads = map[string]bool{
	ReadNodeLedgers: true, ReadMetricHistory: true, ReadMetricRecent: true,
	ReadAgreementWindow: true, ReadMissedLedgers: true, ReadAlerts: true,
	ReadFiring: true, ReadPublicLedger: true, ReadPublicLedgerRange: true,
	ReadPublicValidator: true, ReadHost: true, ReadRestartAssessment: true,
	ReadUpgradeAssessment: true, ReadConfigAssessment: true,
	ReadRollbackAssessment: true, ReadNodeConfig: true,
}

// hostVerbs mirrors the ten verbs in internal/host's Probes list (§4.3: "verb
// ∈ the ten host.Probes verbs"). Duplicated here rather than imported so this
// package keeps zero dependency on anything but the standard library — it is
// the package that carries the security properties, and the build note asks
// for it to be reviewable in isolation. If host.Probes ever gains or loses a
// verb this list needs the matching edit; there is no way to enforce that at
// compile time without giving up the independence, so a test in
// internal/host or internal/interrogate that fails loudly on drift is worth
// adding when the concrete Menu (a later step) wires the two together.
var hostVerbs = map[string]bool{
	"show-config": true, "resources": true, "sysctl-relevant": true,
	"disk": true, "limits": true, "show-validators": true,
	"show-toml": true, "unit-status": true, "node-log": true, "journal": true,
}

var validRanges = map[string]bool{"1h": true, "6h": true, "12h": true, "24h": true, "7d": true, "30d": true}
var validAggs = map[string]bool{"avg": true, "max": true, "min": true}

// nodeLabelRe bounds a fleet peer's Node field to the same shape
// internal/fleet's Load enforces at the registry layer — duplicated rather
// than imported for the same reason hostVerbs is duplicated from
// internal/host: this package keeps zero dependency beyond the standard
// library. enhancement-plan.md step 5: "[a-z0-9-], 1 to 32 characters."
var nodeLabelRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// nodeableReads is every read menu item that goes through the dashboard's
// read API and can therefore be pointed at a fleet peer
// (d2-registry-placement-options.md §7, "three things option C must
// build"). host_read reaches the privilege wrapper, which the registry
// cannot express (risk S1); public_ledger, public_ledger_range and
// public_validator reach the public XRPL API, which answers the same
// regardless of which node asked. Neither is a fleet-peer-shaped read, so
// a Node on either is refused at parse time rather than silently ignored.
var nodeableReads = map[string]bool{
	ReadNodeLedgers: true, ReadMetricHistory: true, ReadMetricRecent: true,
	ReadAgreementWindow: true, ReadMissedLedgers: true, ReadAlerts: true,
	ReadFiring: true, ReadNodeConfig: true,
}

// minLedgerIndex is the earliest ledger the network can name (the first
// flag ledger after genesis) — the floor for public_ledger and
// public_ledger_range, per §4.2.
const minLedgerIndex = 32570

// Every cap and default from §4's tables, named rather than left as literals
// inside validateRequest's switch. §8 point 1 requires the prompt's menu
// table to be "rendered from the Go menu definition so the prompt cannot
// drift from what the code serves" — Menu.Describe() is a concrete Menu's
// job (a later step), but it can only render from this package's own
// definition if that definition exists somewhere other than inline in a
// validation switch. These constants are that single source; validateRequest
// reads them below instead of repeating the numbers.
const (
	maxWhyChars = 120

	defaultNodeLedgersSpan = 21
	maxNodeLedgersSpan     = 61
	maxNodeLedgersLatest   = 200

	defaultMetricRecentLimit = 60
	maxMetricRecentLimit     = 200

	defaultMissedLedgersLimit = 50
	maxMissedLedgersLimit     = 100

	defaultAlertsLimit = 50
	maxAlertsLimit     = 100

	maxPublicLedgerRangeSpan = 12

	defaultHostReadLinesNodeLog = 80
	defaultHostReadLinesJournal = 60
	maxHostReadLines            = 200
)

// validatorKeyRe is a loose shape check for an "nH…"-style validator public
// key, not a full base58 decode — good enough to reject "not even trying to
// look like a key" at the parser layer; a Menu implementation talking to the
// real XRPL client is the one that finds out whether it actually resolves.
var validatorKeyRe = regexp.MustCompile(`^n[1-9A-HJ-NP-Za-km-z]{25,60}$`)

// rawRequest is the wire shape of one <lookup> entry, decoded before
// structural validation turns it into a Request. Pointers distinguish "the
// model did not supply this" from "the model supplied the zero value" for
// the few fields where that distinction matters (around vs. latest on
// node_ledgers).
type rawRequest struct {
	Read string `json:"read"`
	Why  string `json:"why"`
	// Node names a fleet peer, per §"nodeableReads" above — see Request.Node.
	Node string `json:"node"`

	Around  *int   `json:"around"`
	Span    *int   `json:"span"`
	Latest  *int   `json:"latest"`
	Limit   *int   `json:"limit"`
	Index   *int   `json:"index"`
	From    *int   `json:"from"`
	To      *int   `json:"to"`
	Lines   *int   `json:"lines"`
	SinceMs *int64 `json:"since_ms"`

	Metric string `json:"metric"`
	Range  string `json:"range"`
	Agg    string `json:"agg"`
	Key    string `json:"key"`
	Verb   string `json:"verb"`
}

// validateRequest turns one decoded entry into a Request, or reports why it
// cannot. The service range-checks every parameter itself here (§2, point
// 3) — it does not trust the model's reasoning about what is safe or
// sensible to ask for, and does not defer that judgement to the Menu that
// eventually performs the read either.
//
// validNodes is the fleet roster this question may address — nil or empty
// for a deployment with no fleet registered, in which case any non-empty
// Node is refused, locally, naming the label (S2: "An unknown label is a
// local refusal naming the label, never a remote attempt"). Passed in
// rather than read from disk here, so this package stays pure — the roster
// is data the caller supplies, exactly like every other bounded check in
// this file.
// roster is what the host this question was asked on knows EXISTS (#59),
// which is a wider set than validNodes, what this process can READ. The
// difference is the whole point: advisord's peer table drops any fleet row
// whose read token this host holds no copy of, so without the roster a
// registered-but-unreadable node and a name nobody ever registered came out
// of here as the same sentence. A zero Roster is every caller that has none,
// and behaves exactly as this function did before it existed.
// refusal is why one entry never became a Request, and, when a real
// registered node was named and could not be read, which node that was.
//
// The node is carried rather than parsed back out of Reason, because a
// consumer discriminating on prose is how a message change silently breaks
// a guard. The one consumer that needs it is the round's fleet-completeness
// check: a fleet-wide claim built from a subset of the fleet is correct
// about what it contains and silently wrong about what it represents, and
// the check can only say so if a peer that was named and not read counts as
// a peer that did not answer.
type refusal struct {
	Reason string
	// Node is set only where the name resolved to a REGISTERED node. Left
	// empty for a name nobody registered and for an ambiguous one: there is
	// no node there, and carrying the asker's string into a fleet coverage
	// line would report a host that does not exist as one that stayed
	// silent.
	Node string
}

func validateRequest(raw rawRequest, validNodes map[string]bool, roster Roster) (Request, refusal, bool) {
	if !knownReads[raw.Read] {
		return Request{}, refusal{Reason: fmt.Sprintf("no such read %q", raw.Read)}, false
	}
	if strings.TrimSpace(raw.Why) == "" {
		return Request{}, refusal{Reason: `every request needs a one-line "why"`}, false
	}
	if len(raw.Why) > maxWhyChars {
		return Request{}, refusal{Reason: fmt.Sprintf(`"why" is %d characters, exceeding the maximum of %d`, len(raw.Why), maxWhyChars)}, false
	}

	node := strings.TrimSpace(raw.Node)
	if node != "" {
		if !nodeLabelRe.MatchString(node) {
			return Request{}, refusal{Reason: fmt.Sprintf("node %q is not a valid fleet peer label", node)}, false
		}
		if !nodeableReads[raw.Read] {
			return Request{}, refusal{Reason: fmt.Sprintf("%s cannot be directed at a fleet peer", raw.Read)}, false
		}
		if roster.Known() {
			// #59. Resolve against what this HOST knows, then check what
			// this PROCESS can read. The resolution's Label is what goes
			// onward, never the string that arrived, so a close form the
			// operator used cannot travel into a dispatch or into
			// service-authored text.
			res := roster.Resolve(node)
			switch res.Kind {
			case ResolvedPeer:
				if !validNodes[res.Label] {
					// The roster says readable and the peer table has no
					// client: the two were wired from the same registry, so
					// this is a build fault, not an operator-reachable
					// state. Refused by name rather than dispatched to a
					// nil client.
					return Request{}, refusal{Node: res.Label, Reason: fmt.Sprintf(
						"%s is registered on this host but this Advisor holds no read client for it",
						res.Label)}, false
				}
				node = res.Label
			case ResolvedSelf:
				// The operator named this host. That is a legitimate way to
				// ask about it, and the answer is this node's own data,
				// which is what an empty Node means everywhere else.
				node = ""
			default:
				// Unreachable knows exactly which registered node it means,
				// and carrying that label is what lets the round's fleet
				// coverage count it as a peer that was asked and did not
				// answer. Unregistered and Ambiguous resolve to no node and
				// carry none.
				return Request{}, refusal{Reason: res.Refusal, Node: res.Label}, false
			}
		} else if !validNodes[node] {
			return Request{}, refusal{Reason: fmt.Sprintf("no such fleet peer %q", node)}, false
		}
	}

	req := Request{Read: raw.Read, Why: raw.Why, Node: node}

	switch raw.Read {
	case ReadNodeLedgers:
		hasAround, hasLatest := raw.Around != nil, raw.Latest != nil
		switch {
		case hasAround && hasLatest:
			return Request{}, refusal{Reason: "node_ledgers takes either around or latest, not both"}, false
		case hasAround:
			req.Around = *raw.Around
			span := defaultNodeLedgersSpan
			if raw.Span != nil {
				span = *raw.Span
			}
			if span < 1 || span > maxNodeLedgersSpan {
				return Request{}, refusal{Reason: fmt.Sprintf("span %d exceeds the maximum of %d", span, maxNodeLedgersSpan)}, false
			}
			req.Span = span
		case hasLatest:
			if *raw.Latest < 1 || *raw.Latest > maxNodeLedgersLatest {
				return Request{}, refusal{Reason: fmt.Sprintf("latest %d exceeds the maximum of %d", *raw.Latest, maxNodeLedgersLatest)}, false
			}
			req.Latest = *raw.Latest
		default:
			return Request{}, refusal{Reason: "node_ledgers needs around or latest"}, false
		}

	case ReadMetricHistory:
		if strings.TrimSpace(raw.Metric) == "" {
			return Request{}, refusal{Reason: "metric_history needs a metric name"}, false
		}
		if !validRanges[raw.Range] {
			return Request{}, refusal{Reason: fmt.Sprintf("range %q is not one of 1h, 6h, 12h, 24h, 7d, 30d", raw.Range)}, false
		}
		agg := raw.Agg
		if agg == "" {
			agg = "avg"
		}
		if !validAggs[agg] {
			return Request{}, refusal{Reason: fmt.Sprintf("agg %q is not one of avg, max, min", agg)}, false
		}
		req.Metric, req.Range, req.Agg = raw.Metric, raw.Range, agg

	case ReadMetricRecent:
		if strings.TrimSpace(raw.Metric) == "" {
			return Request{}, refusal{Reason: "metric_recent needs a metric name"}, false
		}
		limit := defaultMetricRecentLimit
		if raw.Limit != nil {
			limit = *raw.Limit
		}
		if limit < 1 || limit > maxMetricRecentLimit {
			return Request{}, refusal{Reason: fmt.Sprintf("limit %d exceeds the maximum of %d", limit, maxMetricRecentLimit)}, false
		}
		req.Metric, req.Limit = raw.Metric, limit

	case ReadAgreementWindow:
		var since int64
		if raw.SinceMs != nil {
			since = *raw.SinceMs
		}
		if since < 0 {
			return Request{}, refusal{Reason: "since_ms cannot be negative"}, false
		}
		req.SinceMs = since

	case ReadMissedLedgers:
		limit := defaultMissedLedgersLimit
		if raw.Limit != nil {
			limit = *raw.Limit
		}
		if limit < 1 || limit > maxMissedLedgersLimit {
			return Request{}, refusal{Reason: fmt.Sprintf("limit %d exceeds the maximum of %d", limit, maxMissedLedgersLimit)}, false
		}
		req.Limit = limit

	case ReadAlerts:
		limit := defaultAlertsLimit
		if raw.Limit != nil {
			limit = *raw.Limit
		}
		if limit < 1 || limit > maxAlertsLimit {
			return Request{}, refusal{Reason: fmt.Sprintf("limit %d exceeds the maximum of %d", limit, maxAlertsLimit)}, false
		}
		var since int64
		if raw.SinceMs != nil {
			since = *raw.SinceMs
		}
		if since < 0 {
			return Request{}, refusal{Reason: "since_ms cannot be negative"}, false
		}
		req.Limit, req.SinceMs = limit, since

	case ReadFiring:
		// No parameters.

	case ReadUpgradeAssessment:
		// No parameters. The target is the service's own — see the read's
		// doc comment: a model naming a version here would be choosing one.
		fallthrough
	case ReadRestartAssessment:
		// No parameters. Not in nodeableReads either: the assessment is of
		// the node THIS service supervises, and a peer's own advisord is
		// the only thing that can assess a peer.

	case ReadPublicLedger:
		if raw.Index == nil {
			return Request{}, refusal{Reason: "public_ledger needs an index"}, false
		}
		if *raw.Index < minLedgerIndex {
			return Request{}, refusal{Reason: fmt.Sprintf("index %d is below the earliest possible ledger, %d", *raw.Index, minLedgerIndex)}, false
		}
		req.Index = *raw.Index

	case ReadPublicLedgerRange:
		if raw.From == nil || raw.To == nil {
			return Request{}, refusal{Reason: "public_ledger_range needs from and to"}, false
		}
		from, to := *raw.From, *raw.To
		if from < minLedgerIndex || to < minLedgerIndex {
			return Request{}, refusal{Reason: fmt.Sprintf("from and to must both be at least %d", minLedgerIndex)}, false
		}
		span := to - from + 1
		if span < 1 {
			return Request{}, refusal{Reason: "to must not be before from"}, false
		}
		if span > maxPublicLedgerRangeSpan {
			return Request{}, refusal{Reason: fmt.Sprintf("range covers %d ledgers, exceeding the maximum of %d", span, maxPublicLedgerRangeSpan)}, false
		}
		req.From, req.To = from, to

	case ReadPublicValidator:
		if !validatorKeyRe.MatchString(raw.Key) {
			return Request{}, refusal{Reason: fmt.Sprintf("key %q does not look like a validator public key", raw.Key)}, false
		}
		req.Key = raw.Key

	case ReadHost:
		if !hostVerbs[raw.Verb] {
			return Request{}, refusal{Reason: fmt.Sprintf("no such host verb %q", raw.Verb)}, false
		}
		req.Verb = raw.Verb
		if raw.Verb == "node-log" || raw.Verb == "journal" {
			lines := defaultHostReadLinesNodeLog
			if raw.Verb == "journal" {
				lines = defaultHostReadLinesJournal
			}
			if raw.Lines != nil {
				lines = *raw.Lines
			}
			if lines < 1 || lines > maxHostReadLines {
				return Request{}, refusal{Reason: fmt.Sprintf("lines %d exceeds the maximum of %d", lines, maxHostReadLines)}, false
			}
			req.Lines = lines
		}
	}

	return req, refusal{}, true
}

// decodeLookupBlock is factored out of the parser so a malformed-JSON test
// can exercise exactly the failure it names.
func decodeLookupBlock(jsonText string) ([]rawRequest, error) {
	var raws []rawRequest
	if err := json.Unmarshal([]byte(jsonText), &raws); err != nil {
		return nil, err
	}
	return raws, nil
}
