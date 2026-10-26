// Package breakglass is the break-glass window — plan-interrogative-loop
// §11.3a. One approval (approval.StageInvestigate, spent when the window
// opens) now authorises several gated investigations rather than one act,
// bounded on four independent axes at once so that widening never becomes
// unbounded: a duration clock, a count of gated questions, a count of
// privileged host reads, and a token spend. Whichever bound is hit first
// closes the window, and which one is recorded — never averaged, never
// silently the maximum.
//
// This package is pure, like internal/interrogate: no I/O, no clock of its
// own. Every mutating method takes `now time.Time` explicitly, so the four
// bounds — including "an investigation started one second before expiry
// completes under its own ceilings" — are testable without sleeping a real
// clock. Concurrency is the caller's job: a Window is a plain struct with no
// internal locking, exactly as interrogate.Budget is, because the thing that
// holds a Window (a map keyed by window id, restart-volatile like NonceStore
// and the turn ring) is where a mutex belongs, not here.
package breakglass

import "time"

// CloseReason names which of the four bounds ended the window, or that the
// operator closed it early. This is what breakglass.closed's summary line
// answers with, and it is a closed set on purpose — an auditor reading the
// ledger should never see a reason this package did not itself produce.
type CloseReason string

const (
	ClosedEarly           CloseReason = "closed_early"
	ClosedExpired         CloseReason = "expired"
	ClosedQuestions       CloseReason = "questions"
	ClosedPrivilegedReads CloseReason = "privileged_reads"
	ClosedSpend           CloseReason = "spend"
	// ClosedServiceRestart is the fifth ending, and the only one this package
	// never observes itself: the process holding the window went away. The
	// Store is in memory, so a restart re-seals the glass for free — but "for
	// free" also meant "with no record and no word to the operator", which is
	// how a window vanished under someone mid-investigation and their next
	// question ran ungated with no explanation (validator1, 2026-08-21). It is
	// written by the boot scan that reads the ledger back, never by a live
	// window, and it belongs in this closed set so an auditor reading the
	// record sees one vocabulary of endings rather than two.
	ClosedServiceRestart CloseReason = "service_restart"
)

// The four bounds — plan-interrogative-loop §11.3a's table, verbatim. A
// review of this design should be able to find every ceiling by reading
// this block alone, the same promise interrogate.Budget's doc comment makes
// for the ungated tier.
const (
	// Duration is measured from FIRST USE, not from grant — the second of
	// the design's two clocks. The approval's own ExpiresAt (5 minutes) is
	// the clock that gates OPENING the window; this one gates how long it
	// stays open once opened.
	Duration = 15 * time.Minute
	// MaxQuestions is the gated-question count a single window may spend.
	MaxQuestions = 5
	// MaxPrivilegedReads is the window-wide cap on reads through the
	// root-owned wrapper — tighter than MaxQuestions × the per-question
	// ceiling would allow, deliberately (§11.3a).
	MaxPrivilegedReads = 40
	// MaxSpendTokens sums prompt and completion tokens across every gated
	// question the window has run. A default with a stated basis, not a
	// settled number (§11.3a, open question #5) — the first figure to
	// revise once B1's real per-question token counts are in hand.
	MaxSpendTokens = 400000
	// CachedTokenWeight discounts a cache-hit prompt token's contribution to
	// the spend ceiling relative to a fresh one — token-efficiency work,
	// part 3: "ceiling math sees the cheaper reality." This package never
	// imports internal/model (like interrogate, it stays free of every
	// sibling import), so it cannot pick the discount that matches whatever
	// provider shape is actually configured: Anthropic's cache-read rate is
	// roughly 10% of fresh (weight 0.1), OpenAI's automatic cache discount
	// is roughly 50% (weight 0.5). This uses the SMALLER discount — the more
	// conservative of the two — so the ceiling never under-counts spend
	// regardless of which shape produced the tokens. The consequence is
	// asymmetric on purpose: an Anthropic deployment's window closes a
	// little earlier than its true cost justifies; that is the safe
	// direction for a ceiling to be wrong in, the same reasoning
	// MaxPrivilegedReads and the other three bounds already apply.
	CachedTokenWeight = 0.5
)

// Identity is who did something, as plain strings.
//
// Deliberately not ledger.Actor: this package imports nothing but time, and
// that purity is the reason its four bounds are testable without a clock or a
// filesystem. The caller that owns the ledger maps this across — one small
// translation, in exchange for a package that still has no dependencies.
type Identity struct {
	Operator     string
	Role         string
	CredentialID string
	Origin       string
	// Verified names what was actually proved about Operator, in the ledger
	// package's vocabulary. Carried as a string so this package does not have
	// to know that vocabulary, only pass it along unaltered.
	Verified string
}

// Window is one break-glass grant in progress. Exported fields, like
// interrogate.Budget, because tests need to manufacture edge states (two
// bounds crossed in the same tick) directly rather than through a sequence
// of calls that might not be able to reach them.
type Window struct {
	ID       string
	Node     string
	OpenedBy string // whose passkey opened it — the ledger's "whose"
	// Opener is the same person with everything else that was established
	// about them: role, passkey, origin, and what was actually proved. Every
	// privileged read inside this window carries it, which is what turns "a
	// read happened in a window someone opened" into "this person read this".
	Opener    Identity
	OpenedAt  time.Time
	ExpiresAt time.Time // OpenedAt + Duration; the moment "starting" stops being permitted on the clock bound alone

	Questions       int
	PrivilegedReads int
	// PromptTokens is the total across every gated question this window has
	// run; CachedPromptTokens is the subset of it billed at the provider's
	// cache-read discount — see model.Usage. tripped()'s spend check reads
	// both, never PromptTokens alone.
	PromptTokens       int
	CachedPromptTokens int
	CompletionTokens   int
	// InFlight counts gated questions currently running. A window can close
	// (Closed becomes true, blocking new starts) while InFlight > 0 — that
	// is exactly §11.3a's "the window gates starting gated work, not
	// finishing it." The in-flight question is not interrupted by this
	// package; it is bounded by its own interrogate.Budget instead.
	InFlight int

	Closed   bool
	ClosedAt time.Time
	ClosedBy CloseReason
	// Closer is the PERSON who closed it early, where a person did. Empty for
	// the three bounds and the clock, which nobody closes.
	//
	// This is the field that fixes a real reading hazard: the ledger used to
	// put a CloseReason ("expired", "questions") in a field called closed_by,
	// directly beside opened_by, which holds a person. An auditor reading the
	// two together would misread it every time. The reason now records as
	// closed_because; closed_by is reserved for someone with a name.
	Closer Identity

	// onClose is called the instant this window closes, whichever of the
	// bounds or the operator ended it. It is the fix for the defect that made
	// the ledger's record of endings conditional on WHICH CALLER noticed: the
	// closing entry used to be written at two call sites in advisord (the
	// operator's Close, and the end of a gated question), so a window that
	// simply ran out its clock while nothing else was happening closed inside
	// a status poll and was never recorded at all (issue #38). close() is the
	// one choke point every ending passes through, so the notice belongs here
	// and nowhere else.
	//
	// Injected by Store.Open, never constructed here — this package still does
	// no I/O of its own, and a Window built directly (as every test in this
	// package does) has no hook and behaves exactly as it always did.
	//
	// The contract for whoever supplies it: it MUST NOT call back into the
	// Store. The poll paths (Store.OpenForNode, Store.Touch) hold the Store's
	// mutex while Touch runs, so a hook that reached back in would deadlock.
	// Appending a ledger entry does not, which is the only thing it is for.
	onClose func(*Window, time.Time)
	// closeAnnounced is belt to close()'s braces. Every caller of close()
	// already guards on !w.Closed, so it can only run once per window; this
	// makes a second notice impossible rather than merely unreachable, because
	// the cost of being wrong is a duplicate entry in a hash-chained record,
	// which reads exactly like tampering.
	closeAnnounced bool
}

// SetOnClose wires the close notice. Store.Open calls it; a caller holding a
// Window directly may too, which is what the tests in this package do.
func (w *Window) SetOnClose(fn func(*Window, time.Time)) { w.onClose = fn }

// Open starts a new window. Called the moment the break-glass approval is
// spent (§11.3: "spend-on-open"), not when the first question begins —
// there is no separate "armed but not yet used" state.
func Open(id, node, openedBy string, now time.Time) *Window {
	return OpenAs(id, node, Identity{Operator: openedBy}, now)
}

// OpenAs is Open with the full identity of whoever's passkey opened it.
func OpenAs(id, node string, opener Identity, now time.Time) *Window {
	return &Window{
		ID: id, Node: node, OpenedBy: opener.Operator, Opener: opener,
		OpenedAt: now, ExpiresAt: now.Add(Duration),
	}
}

// tripped reports which bound is already exhausted as of now, or "" if
// none is. Evaluated in a fixed order — the three counters before the
// clock — so a call that crosses two bounds in the same tick records
// exactly one of them, deterministically, rather than both or neither.
//
// The clock is checked last on purpose. It is ambient: past ExpiresAt it
// would be true on every single call regardless of what actually just
// happened, so checking it first would mean an expired window ALWAYS
// reports "expired" even when the call that triggered the check was, say,
// the read that just pushed PrivilegedReads over 40 — masking the counter
// that is the more specific, more actionable reason.
func (w *Window) tripped(now time.Time) CloseReason {
	switch {
	case w.Questions >= MaxQuestions:
		return ClosedQuestions
	case w.PrivilegedReads >= MaxPrivilegedReads:
		return ClosedPrivilegedReads
	case w.spendTokens() >= float64(MaxSpendTokens):
		return ClosedSpend
	case !now.Before(w.ExpiresAt):
		return ClosedExpired
	default:
		return ""
	}
}

// spendTokens is the ceiling's own accounting, not a display number:
// fresh prompt tokens and completion tokens count in full, and a cache-hit
// prompt token counts at CachedTokenWeight — "so ceiling math sees the
// cheaper reality" (token-efficiency work, part 3) instead of a cache-heavy
// question closing the window at the same rate as an all-fresh one.
func (w *Window) spendTokens() float64 {
	fresh := w.PromptTokens - w.CachedPromptTokens
	if fresh < 0 {
		// Defensive only: CachedPromptTokens is defined as a subset of
		// PromptTokens (model.Usage's doc comment), so this should be
		// unreachable from any real caller. A negative "fresh" reads as
		// spend the window never actually incurred, which is the wrong
		// direction to be wrong in here — floor it rather than let the
		// ceiling under-count.
		fresh = 0
	}
	return float64(fresh) + float64(w.CachedPromptTokens)*CachedTokenWeight + float64(w.CompletionTokens)
}

// close is the one place a window ends. Everything about the ending — the
// flag, the moment, the reason, and the notice that lets the ledger record it
// — happens here, so no future caller can end a window in a way the record
// misses.
//
// Closer, where there is one, is set by the caller BEFORE this runs: the hook
// reads the whole window, and a closed_by field filled in a line after the
// notice fired would name nobody.
func (w *Window) close(now time.Time, reason CloseReason) {
	w.Closed = true
	w.ClosedAt = now
	w.ClosedBy = reason
	if w.onClose != nil && !w.closeAnnounced {
		w.closeAnnounced = true
		w.onClose(w, now)
	}
}

// StartQuestion reports whether a new gated question may begin right now,
// and — only if it may — reserves the slot. This is the ONLY point at
// which the window's bounds are enforced (§11.3a: "the check happens once,
// when a gated question begins — not per round and not per read"). A
// question that was already let through is never retroactively refused by
// this package; it runs out its own interrogate.Budget ceilings instead.
func (w *Window) StartQuestion(now time.Time) (ok bool, reason string) {
	if w.Closed {
		return false, closedMessage(w.ClosedBy)
	}
	if r := w.tripped(now); r != "" {
		w.close(now, r)
		return false, closedMessage(r)
	}
	w.Questions++
	w.InFlight++
	return true, ""
}

// EndQuestion records that one gated question has finished, whatever its
// outcome, and folds its cost into the window's running totals. Reads and
// tokens are charged HERE — at question end, from the session's own
// authoritative count — never re-derived from anything the model claimed
// mid-session, the same "kept vs observed" discipline the rest of this
// project holds everywhere else.
//
// outlivedWindow tells the caller whether this question was still running
// when the window's duration bound passed — carried straight into
// investigate.ended's own outlived_window field (§11.3a, §11.10).
func (w *Window) EndQuestion(now time.Time, privilegedReads, promptTokens, cachedPromptTokens, completionTokens int) (outlivedWindow bool) {
	if w.InFlight > 0 {
		w.InFlight--
	}
	outlivedWindow = now.After(w.ExpiresAt)
	w.PrivilegedReads += privilegedReads
	w.PromptTokens += promptTokens
	w.CachedPromptTokens += cachedPromptTokens
	w.CompletionTokens += completionTokens
	return outlivedWindow
}

// Touch re-checks the bounds without starting or ending anything, and
// closes the window if one has since been crossed. Callers with no other
// reason to touch the window — the status and progress-poll endpoints,
// principally — call this on every poll, so a window that has run out its
// clock or its budget closes close to the moment that actually happened
// rather than only the next time something tries to use it.
func (w *Window) Touch(now time.Time) {
	if w.Closed {
		return
	}
	if r := w.tripped(now); r != "" {
		w.close(now, r)
	}
}

// CloseEarly is the operator's one-click Close (§11.12, §4.5). Idempotent:
// closing an already-closed window changes nothing about ClosedBy — a
// window that expired a second before the click stays recorded as expired,
// not overwritten as an early close the operator did not actually perform.
func (w *Window) CloseEarly(now time.Time) {
	w.CloseEarlyBy(now, Identity{})
}

// CloseEarlyBy is CloseEarly naming who clicked.
//
// Not necessarily the person who opened it: admin A can open a window and
// admin B can close it, and the record should say both. Idempotent in the
// same way — a window that expired a second before the click keeps its
// reason and gains no closer, because nobody closed it.
func (w *Window) CloseEarlyBy(now time.Time, by Identity) {
	if w.Closed {
		return
	}
	// Before close, not after: close() fires the notice that writes the
	// ledger's closing entry, and it reads Closer for both the closed_by field
	// and the entry's actor. Setting it afterwards recorded an early close
	// nobody performed.
	w.Closer = by
	w.close(now, ClosedEarly)
}

// Summary is breakglass.closed's payload (§11.10) — "one line answers what
// that break-glass session cost and what it touched."
type Summary struct {
	WindowID string `json:"window_id"`
	// ClosedBecause is a bound, never a person — see Window.Closer for why the
	// json name is not closed_by.
	ClosedBecause      CloseReason   `json:"closed_because"`
	ClosedByOperator   string        `json:"closed_by,omitempty"`
	OpenedBy           string        `json:"opened_by"`
	Questions          int           `json:"questions"`
	PrivilegedReads    int           `json:"privileged_reads"`
	PromptTokens       int           `json:"prompt_tokens"`
	CachedPromptTokens int           `json:"cached_prompt_tokens"`
	CompletionTokens   int           `json:"completion_tokens"`
	DurationHeld       time.Duration `json:"duration_held_ns"`
}

// Summary reports the closing summary. Safe to call on an open window (a
// live "so far" reading for the chip); Closed distinguishes a final summary
// from an in-progress one for a caller that cares.
func (w *Window) Summary(now time.Time) Summary {
	end := now
	if w.Closed {
		end = w.ClosedAt
	}
	return Summary{
		WindowID: w.ID, ClosedBecause: w.ClosedBy,
		ClosedByOperator: w.Closer.Operator, OpenedBy: w.OpenedBy,
		Questions: w.Questions, PrivilegedReads: w.PrivilegedReads,
		PromptTokens: w.PromptTokens, CachedPromptTokens: w.CachedPromptTokens,
		CompletionTokens: w.CompletionTokens,
		DurationHeld:     end.Sub(w.OpenedAt),
	}
}

func closedMessage(reason CloseReason) string {
	switch reason {
	case ClosedEarly:
		return "the break-glass window was closed"
	case ClosedExpired:
		return "the break-glass window has expired"
	case ClosedQuestions:
		return "the break-glass window's investigation limit is reached"
	case ClosedPrivilegedReads:
		return "the break-glass window's privileged-read limit is reached"
	case ClosedSpend:
		return "the break-glass window's token spend limit is reached"
	case ClosedServiceRestart:
		return "the Advisor service restarted, which closes any open break-glass window"
	default:
		return "the break-glass window is closed"
	}
}
