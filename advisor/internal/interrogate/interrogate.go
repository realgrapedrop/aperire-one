// Package interrogate is the model's read menu and the bounded loop that
// serves it.
//
// Before this package, every read the Advisor performed was chosen by the
// service and guessed at from the operator's words before the model had even
// seen them — one context assembly, one model call, no way for the model to
// ask for more. That is what made an answer read as canned: not a bad
// prompt, an absent capability. This package inverts who CHOOSES a read —
// the model now names one from a fixed menu — while leaving who PERFORMS it
// exactly where it always was: the service, never the model, and only
// through channels it already holds. The full design lives in the
// maintainer's notes; this file is deliberately not a restatement of it.
//
// The property this package exists to guarantee is structural, not
// behavioural. Request cannot express a command, a path, a URL, or a SQL
// fragment — every field is a bounded int, a bounded string enum, or a value
// checked against a fixed list before it is ever handed to a Menu
// implementation. A model that wanted to ask for something off the menu has
// no field to put it in, the same property execute.Step has for actions.
//
// This package is pure. It performs no I/O of its own — Menu and Caller are
// interfaces the caller supplies, so the parser, the sanitiser, the budget
// and the loop can all be driven by scripted fakes in tests, with no
// provider, no dashboard and no host. The concrete Menu that reaches the
// dashboard's read API, the public XRPL lookup client and the privilege
// wrapper is a separate piece of work, built after this one and bound into
// main.go's ask handler.
package interrogate

import (
	"context"
	"fmt"
	"strings"
)

// Menu is the read side's equivalent of an ActionPlan runbook: a fixed,
// named set of things that may be done, each performed by the service and
// never by the model. Concrete implementations bind in a later step; this
// interface is what makes the loop testable without one.
type Menu interface {
	// Perform executes one validated Request and returns a Result built
	// from what actually happened. It never returns an error — a failed
	// read is a Result with Status == StatusFailed, because a failure the
	// operator is not told about is indistinguishable from a read that
	// never happened, and §7 exists to close exactly that gap.
	Perform(ctx context.Context, req Request) Result

	// Describe renders the prompt's menu table from the menu's own
	// definition, so the prompt cannot drift from what the code actually
	// serves (§8, point 1).
	Describe() string
}

// Request is one entry from a <lookup> block, after decoding and structural
// validation. Every field is a bounded int, a bounded string enum, or a
// value checked against a fixed list — there is no field here that can
// carry a command, a path, a URL, or a SQL fragment. A model that wanted to
// ask for something off the menu has nowhere to put it.
//
// Fields are shared across menu items rather than nested per-item, because
// a nested "one of eleven shapes" union is harder to range-check
// exhaustively than "every field is always safe, and validateRequest
// decides which ones apply." The zero value of every field means "not
// supplied" — safe because no legitimate value in this menu is ever
// genuinely zero (the earliest ledger index is 32570, every limit is at
// least 1, every count is positive).
type Request struct {
	// Read names the menu item. Checked against the fixed list in
	// knownReads before anything else runs.
	Read string
	// Why is the model's own one-line reason, required and capped at 120
	// characters (§5.1). It becomes the step label the operator sees, and
	// is carried verbatim into a ceiling refusal so the operator can see
	// what they did not get, not just that something was denied.
	Why string

	// Node names the fleet peer this read should be directed at — a
	// registered peer's label, checked against the roster before anything
	// runs (menu_items.go's validateRequest, exactly as Read is checked
	// against knownReads and Verb against hostVerbs). Empty means this
	// node's own data — today's only behaviour, and still the only
	// behaviour when no fleet is registered (D2 option C,
	// advisor-enhancement/decisions.md). Only the dashboard-read-API menu
	// items accept a non-empty Node; host_read reaches the privilege
	// wrapper and public_* reaches the public XRPL API, neither of which
	// the registry can express or needs, so both refuse a non-empty Node
	// at parse time rather than silently ignoring it.
	Node string

	// node_ledgers
	Around int
	Span   int
	Latest int

	// metric_recent, missed_ledgers, alerts
	Limit int

	// public_ledger
	Index int

	// public_ledger_range
	From int
	To   int

	// host_read (node-log / journal only)
	Lines int

	// agreement_window, alerts
	SinceMs int64

	// metric_history, metric_recent
	Metric string
	// metric_history
	Range string
	Agg   string

	// public_validator
	Key string

	// host_read
	Verb string
}

// Params renders the request's non-empty parameters for a step header line,
// e.g. "around=106133679 span=21" — in the same order the §4 tables
// document the read, so the rendered line reads the way the spec does.
func (r Request) Params() string {
	var parts []string
	switch r.Read {
	case ReadNodeLedgers:
		if r.Around != 0 {
			parts = append(parts, fmt.Sprintf("around=%d", r.Around))
		}
		if r.Span != 0 {
			parts = append(parts, fmt.Sprintf("span=%d", r.Span))
		}
		if r.Latest != 0 {
			parts = append(parts, fmt.Sprintf("latest=%d", r.Latest))
		}
	case ReadMetricHistory:
		parts = append(parts, "metric="+r.Metric, "range="+r.Range, "agg="+r.Agg)
	case ReadMetricRecent:
		parts = append(parts, "metric="+r.Metric, fmt.Sprintf("limit=%d", r.Limit))
	case ReadAgreementWindow:
		parts = append(parts, fmt.Sprintf("since_ms=%d", r.SinceMs))
	case ReadMissedLedgers:
		parts = append(parts, fmt.Sprintf("limit=%d", r.Limit))
	case ReadAlerts:
		parts = append(parts, fmt.Sprintf("since_ms=%d", r.SinceMs), fmt.Sprintf("limit=%d", r.Limit))
	case ReadFiring:
		// no parameters
	case ReadRestartAssessment:
		// no parameters
	case ReadConfigAssessment:
		// no parameters
	case ReadRollbackAssessment:
		// no parameters
	case ReadPublicLedger:
		parts = append(parts, fmt.Sprintf("index=%d", r.Index))
	case ReadPublicLedgerRange:
		parts = append(parts, fmt.Sprintf("from=%d", r.From), fmt.Sprintf("to=%d", r.To))
	case ReadPublicValidator:
		parts = append(parts, "key="+r.Key)
	case ReadHost:
		parts = append(parts, "verb="+r.Verb)
		if r.Lines != 0 {
			parts = append(parts, fmt.Sprintf("lines=%d", r.Lines))
		}
	}
	// node is service-authored provenance, not model prose (§7): it is set
	// here from the request's own validated field, in the same
	// mechanically-rendered line the model sees back in the results turn
	// (RenderResultsTurn), never folded into Why. Appended last, after
	// every read-specific parameter, so the line still reads the way the
	// spec's per-read tables do before this addition.
	if r.Node != "" {
		parts = append(parts, "node="+r.Node)
	}
	return strings.Join(parts, " ")
}

// Status is what happened to one read.
type Status string

const (
	StatusOK            Status = "ok"
	StatusFailed        Status = "failed"
	StatusRefused       Status = "refused"
	StatusSkippedCached Status = "skipped_cached"
)

// RefusedBecause classifies a refusal per §7.1. Four reasons a read does not
// happen, and each reads completely differently to the operator —
// collapsing them into one "refused" would be the same silence in a
// different font.
type RefusedBecause string

const (
	// RefusedKeyMaterial: the product spec's §7 exclusion. No gate exists
	// and none will — there is nothing for an approval to authorise.
	RefusedKeyMaterial RefusedBecause = "key_material"
	// RefusedTier: the read exists on the menu but this tier may not reach
	// it. A gate exists (break glass, Phase B2, not built by this step).
	RefusedTier RefusedBecause = "tier"
	// RefusedCeiling: budget exhausted — rounds, reads, bytes, privileged
	// reads, or wall clock.
	RefusedCeiling RefusedBecause = "ceiling"
	// RefusedRole: the asker's role may not make this read at any tier —
	// see role.go and advisor/knowledge/role-policy.md. Deliberately NOT
	// RefusedTier: a tier refusal names a gate the person in front of it
	// can open, and a monitor cannot open a break-glass window at all. An
	// offer attached to this would be a button that refuses whoever clicks
	// it, which is why the offer machinery keys on RefusedTier by name
	// rather than on "any refusal".
	RefusedRole RefusedBecause = "role"
)

// Result is what a Menu implementation reports back for one Request. The
// service builds every downstream record — the step, the summary line, the
// injected results text — from a Result, never by parsing back out what the
// model claims happened. That is the mechanism behind §7's honesty
// guarantee: a step exists and carries a status whether or not the model
// ever mentions it.
type Result struct {
	// Body is the read's own data, ready to be embedded in the results
	// turn — a table, a rendered JSON blob, whatever answers the read.
	// Empty unless Status == StatusOK.
	Body string

	// Status is set by the Menu, or by this package for a refusal raised
	// before a Menu implementation is ever reached (an unknown read, a bad
	// parameter, or a budget ceiling).
	Status Status

	// Detail is a one-line human explanation: an error message, the reason
	// for a refusal, or something the read is honest about even though it
	// succeeded (a clamp, a gap in the record). Always set when
	// Status != StatusOK.
	Detail string

	// RefusedBecause classifies a refusal per §7.1. Empty unless
	// Status == StatusRefused.
	RefusedBecause RefusedBecause

	// Source names the channel the read went through — "dashboard read
	// API", "public XRPL API", "the privilege wrapper" — for the step
	// line and the results turn.
	Source string

	// Redactions counts markers the privilege wrapper itself left in Body.
	// Never re-derived here — see §7.2, "one redactor, one truth": the
	// wrapper is the only party that ever holds the unredacted bytes, so
	// it is the only party that gets to say what is missing.
	Redactions int
	// Omitted and Truncated record the other two members of §7.2's
	// three-way split. Neither is a redaction, and neither should ever be
	// rendered as one.
	Omitted   bool
	Truncated bool

	// Requested and Returned let a windowed read (node_ledgers) state what
	// it asked for against what the record actually held (§4.1). Zero for
	// reads where the distinction does not apply.
	Requested int
	Returned  int

	// ElapsedMS is wall time the read took, in milliseconds, rendered into
	// the step and the results turn.
	ElapsedMS int64
}

// Step is the disclosure record for one read, exactly as shown in §7 — built
// by the service from a Result, never authored by the model. Every read a
// round attempted appears here exactly once, whatever its outcome.
//
// JSON tags match §7's worked example verbatim (main.go's /v1/ask response
// marshals []Step directly rather than through a second, parallel type — two
// shapes for the same record is exactly the drift this package's disclosure
// guarantee exists to prevent). Body carries no tag: it is what the model
// reads, not what the operator's step line shows.
type Step struct {
	N      int    `json:"n"`
	Round  int    `json:"round"`
	Read   string `json:"read"`
	Params string `json:"params,omitempty"`
	// Label carries the request's own "why" into the record verbatim —
	// the operator-facing description of what was checked. When Node is
	// non-empty, newStep appends "(fleet peer <label>)" to it itself,
	// service-authored, rather than trusting the model to have said so in
	// Why (§7, decision-log.md §9's "fleet peer <label>" wording) — this is
	// what the tab's stepText renders (s.label) with no edit of its own.
	Label string `json:"label"`
	// Node names the fleet peer this read was directed at, empty for a
	// read of this node's own data — set by the service from Request.Node,
	// never derived from Label or Params text. Carried on the wire for a
	// future UI to use directly; today's tab needs no edit to keep working.
	Node   string `json:"node,omitempty"`
	Source string `json:"source,omitempty"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Ms is Result.ElapsedMS, carried through.
	Ms             int64          `json:"ms,omitempty"`
	RefusedBecause RefusedBecause `json:"refused_because,omitempty"`
	Redactions     int            `json:"redactions,omitempty"`
	Omitted        bool           `json:"omitted,omitempty"`
	Truncated      bool           `json:"truncated,omitempty"`
	Requested      int            `json:"requested,omitempty"`
	Returned       int            `json:"returned,omitempty"`

	// Body is the read's full data, needed to build the injected results
	// turn (§5.2). It is not part of what the operator's step line shows —
	// the drawer renders Label/Source/Status/Detail, per §7's JSON shape —
	// but the loop needs somewhere to carry it from Result through to the
	// renderer.
	Body string `json:"-"`
}

// newStep folds a Request and the Result a Menu (or this package) produced
// for it into the one record kept about that read.
func newStep(n, round int, req Request, res Result) Step {
	label := req.Why
	if req.Node != "" {
		label = fmt.Sprintf("%s (fleet peer %s)", label, req.Node)
	}
	return Step{
		N: n, Round: round, Read: req.Read, Params: req.Params(), Label: label,
		Node:   req.Node,
		Source: res.Source, Status: res.Status, Detail: res.Detail,
		Ms:             res.ElapsedMS,
		RefusedBecause: res.RefusedBecause,
		Redactions:     res.Redactions,
		Omitted:        res.Omitted,
		Truncated:      res.Truncated,
		Requested:      res.Requested,
		Returned:       res.Returned,
		Body:           res.Body,
	}
}

// ceilingDetail is how every service-synthesised refusal (as opposed to one
// a Menu implementation produced from an actual failed read) states what it
// denied. §7.1 requires a ceiling refusal to name what it did not get to —
// "I ran out of budget" tells the operator nothing they can act on, and it
// is the one refusal where the model had a plan the operator can finish by
// hand.
func ceilingDetail(reason, why string) string {
	if why == "" {
		return reason
	}
	return fmt.Sprintf("%s — %q went unmade", reason, why)
}

// refuseStep builds a Step for a read that never reached a Menu at all: an
// unknown read name, a bad parameter, a missing "why", a duplicate block, or
// a budget ceiling. reason should already be a complete sentence fragment;
// ceilingDetail folds the request's own "why" into it so the record names
// what was denied, not just that something was.
func refuseStep(n, round int, req Request, rb RefusedBecause, reason string) Step {
	return newStep(n, round, req, Result{
		Status:         StatusRefused,
		RefusedBecause: rb,
		Detail:         ceilingDetail(reason, req.Why),
	})
}
