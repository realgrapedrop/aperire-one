// The concrete read menu — plan-interrogative-loop §4, §9.5, build order
// step 7. This is the one place interrogate.Request turns into an actual
// read: the dashboard's read API (ADR 0008), the public XRPL lookup client,
// and the privilege wrapper's read-only verbs. Everything the interrogate
// package itself guarantees (structural validation, sanitisation, budgeting)
// already happened before Perform is ever called; this file's only job is
// "go get the data", honestly, through channels this process already holds.
package main

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"aperire-advisor/internal/dashread"
	"aperire-advisor/internal/fleet"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/xrpl"
)

// dashboardReadTimeout, hostReadTimeout: §6.1's per-read timeouts. Public
// reads are bounded by xrpl.RangeTimeout (public_ledger_range) and this
// service's shared *http.Client timeout (single-ledger and validator
// lookups) — the same client main.go already uses for the seed lookups —
// so they are not wrapped again here.
const (
	dashboardReadTimeout = 10 * time.Second
	hostReadTimeout      = 20 * time.Second
)

// rippleEpochOffset converts a rippled close time (seconds since
// 2000-01-01 UTC) to a Unix timestamp. Duplicated from internal/xrpl's
// unexported rippleEpoch rather than imported — this file already imports
// that package for the lookup client; the constant itself is small enough
// that a second copy is cheaper than exporting an implementation detail
// across a package boundary for one file to use once.
const rippleEpochOffset = 946684800

// liveMenu is the interrogate.Menu this process actually runs. It holds
// nothing the model ever sees directly — every field is a channel already
// governed by its own authorisation (the read token, the wrapper, the
// lookup config), never a new one opened for this package.
type liveMenu struct {
	dash       *dashread.Client
	httpClient *http.Client
	stateDir   string
	runner     host.Runner
	wrapper    string
	// peers is the fleet roster's read clients, one per registered peer,
	// keyed by label — D2 option C. Nil or empty is exactly today's
	// single-node behaviour: no peer read ever validates past
	// interrogate's own parse-time check (menu_items.go's nodeableReads +
	// the roster it is checked against), so Perform never even looks here
	// in that case.
	peers map[string]*dashread.Client
	// fleetReg is the SAME registry peers was derived from, kept whole so
	// Describe can say what each peer IS and what this host is, not just
	// which labels exist. Nil is supported and means today's exact prompt:
	// a build with no registry file has no topology to state, and inventing
	// one would be the guess the design note forbids.
	//
	// Read for description only. Nothing here decides a channel — the
	// clients in peers are the only way a peer is reached, and they were
	// built at boot from origin + token_path alone.
	fleetReg *fleet.Registry
	// roster is what this HOST knows exists, #59. Wider than peers, which
	// is what this PROCESS can read: the dashboard's fleet registry names
	// every node in the fleet, including ones whose read token this host
	// holds no copy of, and those are exactly the nodes that used to come
	// back as "no such fleet peer". Describe names them as registered and
	// not readable from here, so the model offers the honest sentence
	// rather than the wrong one.
	//
	// Read for description and for resolution. Like fleetReg it decides no
	// channel: the clients in peers are still the only way a peer is
	// reached. The zero Roster is a host that was never told, and renders
	// exactly as this menu rendered before #59.
	roster interrogate.Roster
	// hostBudget is the SAME *host.Budget the seed probes (host.Inspect,
	// called in ask before the loop starts) already share — one counter, so
	// the three-privileged-reads-per-question cap holds across both instead
	// of resetting for the menu (plan-interrogative-loop §9.4).
	hostBudget *host.Budget
	// restartAssess performs the restart_assessment read — the service's own
	// evaluation of RB-002 against this host, which is the one thing on the
	// menu that needs the SERVER rather than a channel this struct holds
	// (it resolves the runbook, evaluates preconditions and reads the node).
	// Injected as a function so this file keeps its property of holding
	// channels rather than a server, and so a menu built in a test performs
	// no host reads by accident. Nil is supported and refuses honestly:
	// three construction sites means a nil field would otherwise panic the
	// whole ask on whichever one was missed.
	restartAssess func(ctx context.Context) interrogate.Result
	// upgradeAssess performs the upgrade_assessment read — this service's own
	// evaluation of RB-001 against this host. Injected as a function for
	// exactly the reasons restartAssess is, and nil is supported the same
	// way: three construction sites means a nil field would otherwise panic
	// the whole ask on whichever one was missed.
	upgradeAssess func(ctx context.Context) interrogate.Result
	// configAssess performs the config_assessment read — this service's own
	// evaluation of RB-003 against this host. Injected for exactly the
	// reasons the other two are, and nil is supported the same way.
	configAssess func(ctx context.Context) interrogate.Result
	// rollbackAssess performs the rollback_assessment read — this service's
	// own evaluation of RB-004 against this host, including the target it
	// derives from the deployment backups and the run history. Injected for
	// exactly the reasons the other three are, and nil is supported the same
	// way.
	rollbackAssess func(ctx context.Context) interrogate.Result
	// selfContainer is the node's container on THIS host — named in the
	// prompt beside the fleet label so the confirmation table has a real
	// value rather than an invented one. Taken from configuration, not from
	// a host read: Describe runs before the first round and must not stall
	// on docker.
	selfContainer string
	// role is the asker's role, stamped on the question by the dashboard
	// proxy from the signed-in session — never typed by the browser, and
	// never derived from anything the model said. It decides one thing
	// here: whether host_read may reach the seven sensitive verbs
	// (interrogate.RoleMayReadVerb, and advisor/knowledge/role-policy.md
	// for the rules in words). Empty is an admin — see that function's
	// comment for why a caller with no session is the host operator.
	role string
	// resultClampBytes bounds a single wrapper read before it ever reaches
	// interrogate.Budget's own per-result ceiling — §11.1 raises this from
	// 6 KB (ungated) to 12 KB for a gated session. Zero means "use the
	// ungated default", so every existing construction of liveMenu (B1)
	// needs no edit.
	resultClampBytes int
}

// clampBytes is resultClampBytes with the ungated default folded in.
func (m *liveMenu) clampBytes() int {
	if m.resultClampBytes > 0 {
		return m.resultClampBytes
	}
	return 6000
}

// Describe renders the prompt's menu table. interrogate.MenuGuide() itself
// is untouched and returns byte-identical text to before this package ever
// heard of a fleet (TestDescribe_EmptyFleetIsByteIdenticalToMenuGuide
// pins this) — the peer section is appended here, and only when the
// roster is non-empty, so a single-node deployment's prompt does not
// change by one byte just because the fleet package now exists in the
// binary.
func (m *liveMenu) Describe() string {
	g := interrogate.MenuGuide()
	self := m.fleetReg.SelfIdentity()
	// #59. A host whose dashboard holds a fleet registry has something to
	// say even with no readable peers of its own, that is the state the
	// issue was reported from. A host with neither still renders the menu
	// unchanged, byte for byte.
	unread := m.unreadablePeers()
	if len(m.peers) == 0 && !self.Known() && len(unread) == 0 {
		return g
	}

	var b strings.Builder
	b.WriteString(g)
	b.WriteString("\nFLEET\n")

	// What this host IS, before what it can reach. A host that cannot state
	// its own role has been answering as though every host were a node —
	// the aggregator whose Advisor believed it supervised a validator
	// container and found out otherwise by failing to run docker, forever.
	// Emitted even with zero peers: a single-host install that has declared
	// itself is exactly the case that self-blindness cost.
	if self.Known() {
		b.WriteString(describeSelf(self))
		b.WriteString(m.describeSelfIdentity())
	}

	if len(m.peers) > 0 {
		labels := make([]string, 0, len(m.peers))
		for label := range m.peers {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		b.WriteString("This node is not alone. node_ledgers, metric_history, metric_recent, " +
			"agreement_window, missed_ledgers, alerts, firing and node_config each accept an optional \"node\" field " +
			"naming one registered fleet peer instead of this node — omit it for this node (the default, " +
			"and the only option for host_read and every public_* read). A peer's own reading, never this " +
			"node's. Registered peers: ")
		described := make([]string, 0, len(labels))
		for _, label := range labels {
			described = append(described, describePeer(label, m.fleetReg))
		}
		b.WriteString(strings.Join(described, "; "))
		b.WriteString(".\n")
	}

	// #59. The nodes this HOST knows about and this Advisor cannot read.
	// Named, because the alternative is what the issue reported: a real
	// fleet node coming back as a name nobody registered. The model is told
	// the sentence to use rather than left to compose one, and it is told
	// plainly that it must not try the read.
	if len(unread) > 0 {
		b.WriteString("This host's fleet ALSO registers nodes this Advisor holds no read credential for, " +
			"so a \"node\" naming one is refused here rather than attempted: ")
		b.WriteString(strings.Join(unread, "; "))
		b.WriteString(". Asked about one of them, say it is registered in this fleet and cannot be read " +
			"from this host, give the last time this host's dashboard saw it answer, and point at the " +
			"dashboard that holds the fleet. Never say it is not registered, it is.\n")
	}
	return b.String()
}

// unreadablePeers renders every node the host's fleet registry names that
// this Advisor holds no read client for, each with the last time this host's
// dashboard saw it answer (#59).
//
// The age is the dashboard's last SUCCESSFUL poll, dated against the
// roster's own clock rather than this process's, so two hosts with drifting
// clocks cannot make one reading disagree with itself.
func (m *liveMenu) unreadablePeers() []string {
	var out []string
	for _, n := range m.roster.Peers() {
		if n.Readable {
			continue
		}
		out = append(out, describeUnreadable(n, m.roster.NowMs))
	}
	sort.Strings(out)
	return out
}

func describeUnreadable(n interrogate.RosterNode, nowMs int64) string {
	line := n.Label
	if n.Role != "" {
		line += " (role " + n.Role
	} else {
		line += " (role not recorded"
	}
	switch {
	case n.LastAnsweredMs <= 0:
		line += ", has not answered this host's dashboard since that dashboard started"
	case nowMs >= n.LastAnsweredMs:
		line += ", last answered this host's dashboard " +
			interrogate.HumanAge(nowMs-n.LastAnsweredMs) + " ago"
	}
	return line + ")"
}

// describeSelf renders the one line naming the host the reader is on. Says
// only what the registry was told: an unlabelled self states its role and
// nothing else, and a self with no role says the label alone. Neither
// invents the other half.
func describeSelf(self fleet.Self) string {
	switch {
	case self.Label != "" && self.Role != "":
		return fmt.Sprintf("You are running on %q, whose role in this fleet is %s. %s\n",
			self.Label, self.Role, roleMeaning(self.Role))
	case self.Label != "":
		return fmt.Sprintf("You are running on %q. Its role in this fleet has not been "+
			"recorded — do not assume one.\n", self.Label)
	default:
		return fmt.Sprintf("This host's role in the fleet is %s. %s\n", self.Role, roleMeaning(self.Role))
	}
}

// describeSelfIdentity names this box the way an operator would: the
// hostname the kernel reports and the container the node runs in, beside
// the fleet label describeSelf already stated.
//
// It exists for the confirmation step the operator asked for (2026-08-19):
// before a restart the Advisor presents the fleet and stars the node it
// believes is meant, and a table whose hostname column the model had to
// invent would be worse than no table. Only this host's own names appear —
// a peer's hostname is not in the registry, and a guessed one in a
// confirmation table is the exact mistake the table exists to prevent.
//
// Emitted only inside the self block, so a host with no registry at all
// still produces a prompt byte-identical to MenuGuide().
func (m *liveMenu) describeSelfIdentity() string {
	var parts []string
	if h := hostname(); h != "" {
		parts = append(parts, "its hostname is "+h)
	}
	if m.selfContainer != "" {
		parts = append(parts, "its node runs in the container "+m.selfContainer)
	}
	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, ", ") +
		". This is the only node you can ever act on: a restart of any other host " +
		"has to be asked for on that host's own dashboard.\n"
}

// roleMeaning states the one consequence of a role that changes an answer:
// what is, and is not, on the host. Kept to what the estate can back up —
// a relay is not claimed to be absent from an aggregator, because on this
// estate the aggregator runs one.
func roleMeaning(role string) string {
	switch role {
	case fleet.RoleAggregator:
		return "An aggregator host runs a dashboard over the fleet and has NO node of its own — " +
			"its host readings (CPU, memory, swap, disk) are real and are this host's, but any " +
			"remedy that names a node, a container or the node's own config belongs on a node host, not here."
	case fleet.RoleValidator:
		return "A validator host runs a node that signs validations; changes here affect the network's " +
			"view of this operator, so name the cost of a restart before proposing one."
	case fleet.RoleNode:
		return "A node host runs a node that follows the network without signing validations."
	case fleet.RoleRelay:
		// Deliberately says only what the word means, and nothing about what
		// else is on the box. On this estate the relay is CO-LOCATED — it
		// runs beside a node, and beside the aggregator too — so "a relay
		// host runs no node of its own" would be a fleet shape this estate
		// does not have. That is the exact mistake sitting in
		// advisor/knowledge/metrics-ports-and-relay-feed.md today, and the
		// design note flagged it: a corpus teaching a topology the estate
		// contradicts. Not repeating it here in the prompt.
		return "A relay forwards this host's own metrics to a dashboard."
	default:
		return ""
	}
}

// describePeer renders one roster entry: its label, what it is, and what
// identity the operator declared it to be.
//
// The pin is rendered as a DECLARATION, never as a verified fact, because
// that is what it currently is — nothing on the read path checks it yet
// (fleet.Peer.ExpectedPubkeyNode). Writing "identity verified" here would
// be this project's own characteristic bug in prompt form: a configured
// value presented to the model as an observed one.
func describePeer(label string, reg *fleet.Registry) string {
	p, ok := reg.PeerByLabel(label)
	if !ok || (p.Role == "" && p.ExpectedPubkeyNode == "") {
		return label
	}
	var parts []string
	if p.Role != "" {
		parts = append(parts, "role "+p.Role)
	}
	if p.ExpectedPubkeyNode != "" {
		parts = append(parts, "declared node key "+p.ExpectedPubkeyNode+
			", recorded from this host's config and not re-checked on each read")
	}
	return label + " (" + strings.Join(parts, ", ") + ")"
}

// Perform runs one read and, when it was directed at a fleet peer, stamps
// the answer with where it came from and how fresh that is (#59).
//
// The stamp is added HERE, once, rather than in each of the eight peer-
// capable reads, because the property it carries is about the answer and not
// about the read: an operator asking about another node has to be able to
// tell, from the answer itself, which host it describes and when that host
// said it. Source and the node= in Params already name the host in two other
// places; this is the line that dates it.
//
// Three clocks exist on this path and they are never blurred. This one is
// "read live", the peer's own dashboard answered THIS request, so the
// reading is as fresh as the request. The peer's last-answered time from the
// fleet roster is a different clock and appears only when a peer cannot be
// read at all. And a value that is older than the request carrying it
// (node_config's rippled.cfg parse) dates itself, inside its own body.
func (m *liveMenu) Perform(ctx context.Context, req interrogate.Request) interrogate.Result {
	res := m.perform(ctx, req)
	if req.Node != "" && res.Status == interrogate.StatusOK {
		res.Body = peerProvenance(req.Node) + "\n" + res.Body
	}
	return res
}

// peerProvenance is the one line that says whose reading this is. Written
// from the request's own Node, the exact roster label validateRequest
// resolved to, never a string the model or the operator composed.
func peerProvenance(node string) string {
	return fmt.Sprintf("SOURCE, %s's own dashboard, read live at %s. %s's reading, not this node's.",
		node, time.Now().UTC().Format("2006-01-02 15:04:05Z"), node)
}

func (m *liveMenu) perform(ctx context.Context, req interrogate.Request) interrogate.Result {
	switch req.Read {
	case interrogate.ReadNodeLedgers:
		return m.nodeLedgers(ctx, req)
	case interrogate.ReadMetricHistory:
		return m.metricHistory(ctx, req)
	case interrogate.ReadMetricRecent:
		return m.metricRecent(ctx, req)
	case interrogate.ReadAgreementWindow:
		return m.agreementWindow(ctx, req)
	case interrogate.ReadMissedLedgers:
		return m.missedLedgers(ctx, req)
	case interrogate.ReadAlerts:
		return m.alerts(ctx, req)
	case interrogate.ReadFiring:
		return m.firing(ctx, req)
	case interrogate.ReadNodeConfig:
		return m.nodeConfig(ctx, req)
	case interrogate.ReadPublicLedger:
		return m.publicLedger(ctx, req)
	case interrogate.ReadPublicLedgerRange:
		return m.publicLedgerRange(ctx, req)
	case interrogate.ReadPublicValidator:
		return m.publicValidator(ctx, req)
	case interrogate.ReadHost:
		return m.hostRead(ctx, req)
	case interrogate.ReadRestartAssessment:
		if m.restartAssess == nil {
			return interrogate.Result{
				Status: interrogate.StatusFailed,
				Detail: "this service has no restart assessment wired in",
			}
		}
		return m.restartAssess(ctx)
	case interrogate.ReadUpgradeAssessment:
		if m.upgradeAssess == nil {
			return interrogate.Result{
				Status: interrogate.StatusFailed,
				Detail: "this service has no upgrade assessment wired in",
			}
		}
		return m.upgradeAssess(ctx)
	case interrogate.ReadConfigAssessment:
		if m.configAssess == nil {
			return interrogate.Result{
				Status: interrogate.StatusFailed,
				Detail: "this service has no configuration assessment wired in",
			}
		}
		return m.configAssess(ctx)
	case interrogate.ReadRollbackAssessment:
		if m.rollbackAssess == nil {
			return interrogate.Result{
				Status: interrogate.StatusFailed,
				Detail: "this service has no rollback assessment wired in",
			}
		}
		return m.rollbackAssess(ctx)
	default:
		// Unreachable in practice — validateRequest already rejects any
		// name outside knownReads before a Request is ever built — but a
		// Menu implementation returning nothing for an unhandled case would
		// render as a step with no status, which §14's own test forbids.
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: fmt.Sprintf("no handler for read %q", req.Read)}
	}
}

func (m *liveMenu) lookupConfig() (xrpl.LookupConfig, error) {
	return xrpl.LoadLookupConfig(filepath.Join(m.stateDir, "xrpl-lookup.json"))
}

// notEnabled is §4.2's stated behaviour for the public lookup being off:
// refused, never a failure, never silent. Left with an empty RefusedBecause
// — this is not one of §7.1's three budget/tier/key-material reasons, it is
// a fourth, simpler case ("this host does not have this turned on") that
// RenderRefusal's default branch already renders correctly from Detail
// alone.
func notEnabled() interrogate.Result {
	return interrogate.Result{Status: interrogate.StatusRefused, Detail: "the public ledger lookup is not enabled on this host"}
}

// ── dashboard read API (ADR 0008) ──────────────────────────────────────

// dashSource names the channel a dashboard-read-API result came through —
// this node's own, or a registered fleet peer's — for the result's own
// Source field (rendered next to the OK line in both the drawer and the
// results turn the model reads back). Additional to, never a substitute
// for, the node= in Params() and the "(fleet peer …)" in the step's Label
// (§7, DI1): three surfaces stating the same fact independently is the
// point on a read this project treats as evidence.
func dashSource(node string) string {
	if node == "" {
		return "dashboard read API"
	}
	return "dashboard read API — fleet peer " + node
}

// dashClientFor resolves which dashread.Client a request should use: this
// node's own (node == "", the default) or a registered fleet peer's.
// Reached only after interrogate's own parse-time check has already
// confirmed node is either empty or a member of the roster m.peers was
// built from — the same registry, loaded once at start — so a miss here
// would be a bug in how the two were wired together, not an
// operator-reachable state. Guarded anyway: a missing client fails the
// read cleanly, by name, rather than dereferencing a nil Client.
func (m *liveMenu) dashClientFor(node string) *dashread.Client {
	if node == "" {
		return m.dash
	}
	return m.peers[node]
}

func (m *liveMenu) nodeLedgers(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)

	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}

	if req.Around != 0 {
		win, err := client.LedgerWindow(rctx, int64(req.Around), req.Span)
		if err != nil {
			return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
				Source: source, ElapsedMS: elapsedMS(start)}
		}
		var b strings.Builder
		// §4.1: the applied span and requested-vs-returned, always — this is
		// the read the acceptance test turns on, and the one place a silent
		// gap would recreate the exact defect this design exists to fix.
		b.WriteString(interrogate.RequestedReturnedNote(win.Requested, win.Returned))
		b.WriteString("\n")
		b.WriteString(renderLedgerRows(win.Ledgers))
		return interrogate.Result{
			Body: b.String(), Status: interrogate.StatusOK, Source: source,
			ElapsedMS: elapsedMS(start), Requested: win.Requested, Returned: win.Returned,
		}
	}

	rows, err := client.LatestLedgers(rctx, req.Latest)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	return interrogate.Result{
		Body: renderLedgerRows(rows), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

func renderLedgerRows(rows []dashread.LedgerRow) string {
	if len(rows) == 0 {
		return "(no ledgers on record for this window)"
	}
	var b strings.Builder
	b.WriteString("index       closed (UTC)          interval  txns  money market nft accts\n")
	for _, r := range rows {
		closed := time.Unix(r.CloseTS+rippleEpochOffset, 0).UTC().Format("2006-01-02 15:04:05")
		fmt.Fprintf(&b, "%-11d %s   %6.2fs  %4d  %4d   %4d  %3d  %4d\n",
			r.LedgerIndex, closed, r.CloseTime, r.TxnCount, r.FamMoney, r.FamMarket, r.FamNFT, r.FamAccts)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m *liveMenu) metricHistory(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	points, err := client.History(rctx, req.Metric, req.Range, req.Agg)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	return interrogate.Result{
		Body: renderPoints(points), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

func (m *liveMenu) metricRecent(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	points, err := client.Recent(rctx, req.Metric, req.Limit)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	return interrogate.Result{
		Body: renderPoints(points), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

func renderPoints(points []dashread.HistoryPoint) string {
	if len(points) == 0 {
		return "(no samples in range)"
	}
	var b strings.Builder
	b.WriteString("ts (UTC)             value\n")
	for _, p := range points {
		fmt.Fprintf(&b, "%s  %v\n", time.UnixMilli(p.TS).UTC().Format("2006-01-02 15:04:05"), p.Value)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m *liveMenu) agreementWindow(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	win, err := client.Agreement(rctx, req.SinceMs)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "retention %d days; applied since_ms=%d\n", win.RetentionDays, win.SinceMs)
	if len(win.Rows) == 0 {
		b.WriteString("(no rows in this window)")
	} else {
		b.WriteString("ledger_index  voted  ts (UTC)\n")
		for _, r := range win.Rows {
			fmt.Fprintf(&b, "%-13d %-6d %s\n", r.LedgerIndex, r.OurVoted,
				time.UnixMilli(r.TS).UTC().Format("2006-01-02 15:04:05"))
		}
	}
	return interrogate.Result{
		Body: strings.TrimRight(b.String(), "\n"), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

func (m *liveMenu) missedLedgers(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	rows, err := client.MissedLedgers(rctx, req.Limit)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	if len(rows) == 0 {
		return interrogate.Result{Body: "(no missed ledgers on record)", Status: interrogate.StatusOK,
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	var b strings.Builder
	b.WriteString("ledger_index  ts (UTC)             validations_seen  trusted_unl  peers  state\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-13d %s  %-17s %-12s %-6s %s\n",
			r.LedgerIndex, time.UnixMilli(r.TS).UTC().Format("2006-01-02 15:04:05"),
			intOrNA(r.ValidationsSeen), intOrNA(r.TrustedUNL), intOrNA(r.PeerCount), strOrNA(r.ServerState))
	}
	return interrogate.Result{
		Body: strings.TrimRight(b.String(), "\n"), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

// nodeConfig is #59's read: the four allow-listed rippled settings a node
// runs, for THIS node or for any registered peer, out of that node's own
// dashboard.
//
// It dates its answer by the PARSE, never by the request. Each dashboard
// reads its rippled.cfg once at startup, so a reply that arrived a
// millisecond ago can be carrying a value read a week ago, and an answer
// dated by the request would be dated by the wrong clock. A dashboard that
// never read a cfg at all says that, rather than reporting four settings as
// unset.
func (m *liveMenu) nodeConfig(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	cfg, err := client.NodeConfig(rctx)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	return interrogate.Result{
		Body: renderNodeConfig(cfg), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

func renderNodeConfig(cfg *dashread.NodeConfig) string {
	if cfg == nil || !cfg.CfgRead {
		return "(that dashboard has read no rippled.cfg, no path is configured for it, or the file could not be read. " +
			"This is not the same as those settings being unset.)"
	}
	var b strings.Builder
	if cfg.ParsedAtMs != nil && *cfg.ParsedAtMs > 0 {
		fmt.Fprintf(&b, "Read from that host's rippled.cfg at %s UTC, when its dashboard started. That is the age of these values.\n",
			time.UnixMilli(*cfg.ParsedAtMs).UTC().Format("2006-01-02 15:04:05"))
	} else {
		b.WriteString("That dashboard did not say when it read the file, so these values carry no age.\n")
	}
	b.WriteString("setting          value       shape\n")
	// Absent is printed as absent, never as a default. rippled's own default
	// for a missing [node_size] is tiny, and printing "tiny" here would put a
	// value in the operator's hands that their file does not contain.
	fmt.Fprintf(&b, "%-16s %-11s %s\n", "node_size", strOrAbsent(cfg.NodeSize), "stanza")
	fmt.Fprintf(&b, "%-16s %-11s %s\n", "ledger_history", strOrAbsent(cfg.LedgerHistory), "stanza")
	fmt.Fprintf(&b, "%-16s %-11s %s\n", "online_delete", int64OrAbsent(cfg.OnlineDelete), "kv, [node_db]")
	fmt.Fprintf(&b, "%-16s %-11s %s", "advisory_delete", boolOrAbsent(cfg.AdvisoryDelete), "kv, [node_db]")
	return b.String()
}

func strOrAbsent(v *string) string {
	if v == nil || *v == "" {
		return "(absent)"
	}
	return *v
}

func int64OrAbsent(v *int64) string {
	if v == nil {
		return "(absent)"
	}
	return strconv.FormatInt(*v, 10)
}

func boolOrAbsent(v *bool) string {
	if v == nil {
		return "(absent)"
	}
	if *v {
		return "1"
	}
	return "0"
}

func (m *liveMenu) alerts(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	rows, err := client.Alerts(rctx, req.SinceMs, req.Limit)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	if len(rows) == 0 {
		return interrogate.Result{Body: "(no alert transitions in range)", Status: interrogate.StatusOK,
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	var b strings.Builder
	b.WriteString("ts (UTC)             metric              severity  state     value\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s  %-19s %-9s %-9s %s\n",
			time.UnixMilli(r.TS).UTC().Format("2006-01-02 15:04:05"), r.Metric, r.Severity, r.State, floatOrNA(r.Value))
	}
	return interrogate.Result{
		Body: strings.TrimRight(b.String(), "\n"), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

func (m *liveMenu) firing(ctx context.Context, req interrogate.Request) interrogate.Result {
	rctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()
	start := time.Now()
	source := dashSource(req.Node)
	client := m.dashClientFor(req.Node)
	if client == nil {
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: fmt.Sprintf("no read client configured for fleet peer %q", req.Node), Source: source}
	}
	rows, err := client.Firing(rctx)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	if len(rows) == 0 {
		return interrogate.Result{Body: "(nothing firing)", Status: interrogate.StatusOK,
			Source: source, ElapsedMS: elapsedMS(start)}
	}
	var b strings.Builder
	b.WriteString("metric              severity  fired (UTC)          value\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-19s %-9s %s  %s\n", r.Metric, r.Severity,
			time.UnixMilli(r.FiredTS).UTC().Format("2006-01-02 15:04:05"), floatOrNA(r.LastValue))
	}
	return interrogate.Result{
		Body: strings.TrimRight(b.String(), "\n"), Status: interrogate.StatusOK,
		Source: source, ElapsedMS: elapsedMS(start),
	}
}

// ── public XRPL lookup client ───────────────────────────────────────────

func (m *liveMenu) publicLedger(ctx context.Context, req interrogate.Request) interrogate.Result {
	cfg, err := m.lookupConfig()
	if err != nil || !cfg.Enabled {
		return notEnabled()
	}
	start := time.Now()
	sum, err := xrpl.Lookup(ctx, m.httpClient, cfg.Endpoint, int64(req.Index))
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: "public XRPL API", ElapsedMS: elapsedMS(start)}
	}
	return interrogate.Result{Body: sum.Describe(), Status: interrogate.StatusOK,
		Source: "public XRPL API", ElapsedMS: elapsedMS(start)}
}

func (m *liveMenu) publicLedgerRange(ctx context.Context, req interrogate.Request) interrogate.Result {
	cfg, err := m.lookupConfig()
	if err != nil || !cfg.Enabled {
		return notEnabled()
	}
	start := time.Now()
	summaries, errs := xrpl.LookupRange(ctx, m.httpClient, cfg.Endpoint, int64(req.From), int64(req.To))
	elapsed := elapsedMS(start)
	if len(summaries) == 0 {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: joinErrs(errs),
			Source: "public XRPL API", ElapsedMS: elapsed}
	}
	var b strings.Builder
	for _, s := range summaries {
		b.WriteString(s.Describe())
		b.WriteString("\n")
	}
	res := interrogate.Result{Body: strings.TrimRight(b.String(), "\n"), Status: interrogate.StatusOK,
		Source: "public XRPL API", ElapsedMS: elapsed}
	// A partial range is still OK — the summaries it got are real — but the
	// unfetched indices are a fact about the read, stated rather than
	// dropped, exactly as §5.4's ladder requires for every other partial
	// result on this menu.
	if len(errs) > 0 {
		res.Detail = joinErrs(errs)
	}
	return res
}

func (m *liveMenu) publicValidator(ctx context.Context, req interrogate.Request) interrogate.Result {
	cfg, err := m.lookupConfig()
	if err != nil || !cfg.Enabled || cfg.ValidatorEndpoint == "" {
		return notEnabled()
	}
	start := time.Now()
	v, err := xrpl.LookupValidator(ctx, m.httpClient, cfg.ValidatorEndpoint, req.Key)
	if err != nil {
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: "public validator registry", ElapsedMS: elapsedMS(start)}
	}
	return interrogate.Result{Body: v.Describe(), Status: interrogate.StatusOK,
		Source: "public validator registry", ElapsedMS: elapsedMS(start)}
}

// ── the privilege wrapper's read-only verbs ────────────────────────────

// hostRead is where obligation (1) from the build handoff lives: every
// wrapper-sourced result MUST pass through interrogate.DisclosuresFrom
// before it becomes a Result, or a wrapper-cut log (or a config with key
// material stripped out of it) renders to the operator — and back to the
// model — as though it were a complete reading. §7.2 is explicit that this
// package's Clamp and the wrapper's own redaction markers are the only
// authority on what is missing; this function's job is to ask that
// authority, once, and set the fields from what it says — never to guess.
func (m *liveMenu) hostRead(ctx context.Context, req interrogate.Request) interrogate.Result {
	// Role first, before the wrapper is even consulted. A read this asker
	// may not make was never attempted, so it does not spend the shared
	// host.Budget — same reasoning as the unconfigured-wrapper branch
	// below: charging for it would let a monitor's question burn its three
	// privileged reads on refusals and then be told the cap is spent,
	// which is a second, wrong explanation for the first one.
	if !interrogate.RoleMayReadVerb(m.role, req.Verb) {
		return interrogate.Result{
			Status:         interrogate.StatusRefused,
			RefusedBecause: interrogate.RefusedRole,
			Detail: "this read describes the host itself (its configuration, logs, kernel settings, " +
				"limits, validator list sites or domain file) and is available to an admin, not to a monitor",
			Source: "the privilege wrapper",
		}
	}
	if m.wrapper == "" {
		// Fails closed WITHOUT spending the shared host.Budget — an empty
		// wrapper path is a deployment state ("not configured"), not a read
		// that was attempted and lost. Charging the budget for it would let
		// a host with no wrapper burn through the question's three
		// privileged reads on nothing.
		return interrogate.Result{Status: interrogate.StatusFailed,
			Detail: "the privilege wrapper is not configured on this host", Source: "the privilege wrapper"}
	}

	rctx, cancel := context.WithTimeout(ctx, hostReadTimeout)
	defer cancel()
	start := time.Now()

	arg := ""
	if req.Lines != 0 {
		arg = strconv.Itoa(req.Lines)
	}
	out, err := host.ReadVerb(rctx, m.runner, m.wrapper, m.hostBudget, req.Verb, arg)
	if err != nil {
		// The loop's own budget already mirrors this counter's starting
		// count (main.go charges it with hostBudget.Used() right after the
		// seed probes run, before the loop's first round), so in the
		// ordinary case the loop's own "refused: ceiling" catches a
		// fourth privileged read before this call is ever made. This
		// branch is what runs if that ever stops being true — including a
		// wrapper failure that has nothing to do with budget at all (a
		// bad verb, a wrapper crash) — so it is rendered as a plain failed
		// read rather than guessed into one of §7.1's three reasons.
		return interrogate.Result{Status: interrogate.StatusFailed, Detail: err.Error(),
			Source: "the privilege wrapper", ElapsedMS: elapsedMS(start)}
	}

	out = host.Clamp(out, m.clampBytes())
	redactions, omitted, truncated := interrogate.DisclosuresFrom(out)
	return interrogate.Result{
		Body: out, Status: interrogate.StatusOK, Source: "the privilege wrapper",
		ElapsedMS: elapsedMS(start), Redactions: redactions, Omitted: omitted, Truncated: truncated,
	}
}

// ── small helpers ───────────────────────────────────────────────────────

func elapsedMS(start time.Time) int64 { return time.Since(start).Milliseconds() }

func intOrNA(p *int) string {
	if p == nil {
		return "n/a"
	}
	return strconv.Itoa(*p)
}

func floatOrNA(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%v", *p)
}

func strOrNA(p *string) string {
	if p == nil || *p == "" {
		return "n/a"
	}
	return *p
}

func joinErrs(errs []error) string {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}
