package interrogate

import "fmt"

// Budget enforces §6.1's ceilings in code, in one place, so a Menu
// implementation cannot forget one and a review can find every ceiling by
// reading this file alone. "Bounded by construction" (§2, point 4) means
// every one of these is a number checked here, never a number requested in
// a prompt.
//
// A Budget is per-question. Per-round ceilings (reads per round, bytes per
// round) reset every round and are enforced by the loop itself rather than
// tracked as running state here, because they are stateless per round; the
// counters below are the ones that must survive across rounds.
type Budget struct {
	MaxRounds               int
	MaxReadsPerRound        int
	MaxReadsPerQuestion     int
	MaxHostReadsPerQuestion int
	MaxBytesPerResult       int
	MaxBytesPerRound        int
	MaxBytesPerQuestion     int

	// Gated is true for a break-glass session's Budget (NewGatedBudget) and
	// false for the ungated one (NewBudget). It decides nothing about the
	// numbers above — it decides how a ceiling hit is CLASSIFIED. See
	// RefusalReason.
	Gated bool

	reads         int
	hostReads     int
	roundBytes    int
	questionBytes int
}

// MaxModelCalls is §6.1's "model calls per question" ceiling: one opening
// call plus at most three lookup rounds. Exported because main.go's ask
// handler needs this exact number to size the request context BEFORE the
// loop runs a single round — the context has to be wide enough for all four
// calls before the first one is made, not discovered by counting them as
// they happen. Kept in lock-step with NewBudget's MaxRounds by construction
// (NewBudget reads this constant rather than repeating the literal 4), so
// the two can never drift against each other.
const MaxModelCalls = 4

// NewBudget returns the ungated ceilings from §6.1.
func NewBudget() *Budget {
	return &Budget{
		MaxRounds:               MaxModelCalls,
		MaxReadsPerRound:        4,
		MaxReadsPerQuestion:     12,
		MaxHostReadsPerQuestion: 3,
		MaxBytesPerResult:       6 * 1024,
		MaxBytesPerRound:        16 * 1024,
		MaxBytesPerQuestion:     32 * 1024,
		Gated:                   false,
	}
}

// MaxGatedModelCalls is the break-glass tier's model-calls-per-question
// ceiling (§11.1: "Model calls: 8"), exported for the same reason
// MaxModelCalls is: main.go has to size a gated question's context budget
// before the loop runs a single round.
const MaxGatedModelCalls = 8

// NewGatedBudget returns the break-glass, per-question ceilings — §11.1's
// table, raised from NewBudget's. This is the ceiling a single gated
// QUESTION may spend; the WINDOW's own separate four bounds (duration,
// questions, privileged reads, spend — internal/breakglass) are enforced
// on top of this, not instead of it, and both apply at once (§11.3a).
//
// MaxBytesPerRound has no number in §11.1's table — only per-result (12 KB)
// and per-question (96 KB) are given. Scaled from NewBudget's own
// round:question ratio (16 KB : 32 KB = 1:2) rather than guessed
// independently, so the two budgets stay proportioned the same way if
// either one is revised later.
func NewGatedBudget() *Budget {
	return &Budget{
		MaxRounds:               MaxGatedModelCalls,
		MaxReadsPerRound:        6,
		MaxReadsPerQuestion:     30,
		MaxHostReadsPerQuestion: 12,
		MaxBytesPerResult:       12 * 1024,
		MaxBytesPerRound:        48 * 1024,
		MaxBytesPerQuestion:     96 * 1024,
		Gated:                   true,
	}
}

// RefusalReason is how a ceiling hit is classified — the correction that
// makes §11.4 condition 5 and the offer's anchor point true. At the
// UNGATED tier every one of the numbers above is raised by break glass
// (§11.1's table has no row where the gated column equals the ungated
// one), so hitting any of them there means a higher tier exists that would
// plausibly change the answer: RefusedTier, which is what the offer
// attaches to (ui-design §3: "the tier-refused .istep that anchors it").
// At the GATED tier there is no higher tier to point at, so the identical
// exhaustion is RefusedCeiling instead — the same distinction §11.3a's
// gated-tier test table draws by requiring "no tier refusal" inside an
// open window.
func (b *Budget) RefusalReason() RefusedBecause {
	if b.Gated {
		return RefusedCeiling
	}
	return RefusedTier
}

// ChargeSeedHostReads pre-charges host reads performed before the loop
// started — the named-ledger lookup, the validator-key lookup, and the
// regex-matched host probes main.go's existing context assembly already
// runs. §4.3 is explicit that the three-per-question cap is shared with
// those seeds and is a QUESTION-level counter, not a round-level one: a
// naive per-round cap would let the loop re-arm it every round and turn
// three privileged commands per question into nine — "the single most
// important number in the design from a security review's point of view."
func (b *Budget) ChargeSeedHostReads(n int) {
	b.hostReads += n
}

// Reserve reports whether one more read may proceed against the
// question-level ceilings, and — only if it may — increments the counters.
// A round-level ceiling (reads per round) is a separate, stateless check
// the loop makes itself before ever calling Reserve, because it resets
// every round and this method has no notion of "round".
func (b *Budget) Reserve(isHost bool) (bool, string) {
	if b.reads >= b.MaxReadsPerQuestion {
		return false, fmt.Sprintf("reads-per-question ceiling of %d reached", b.MaxReadsPerQuestion)
	}
	if isHost && b.hostReads >= b.MaxHostReadsPerQuestion {
		return false, fmt.Sprintf("privileged host reads are capped at %d per question", b.MaxHostReadsPerQuestion)
	}
	b.reads++
	if isHost {
		b.hostReads++
	}
	return true, ""
}

// ReadsUsed and ReadsRemaining report the question-level read counter, for
// the "Budget: N reads remain" line the results turn renders (§5.2).
func (b *Budget) ReadsUsed() int { return b.reads }

func (b *Budget) ReadsRemaining() int {
	r := b.MaxReadsPerQuestion - b.reads
	if r < 0 {
		return 0
	}
	return r
}

// HostReadsUsed reports how many privileged reads this question has spent,
// seeds included.
func (b *Budget) HostReadsUsed() int { return b.hostReads }

// ResetRound clears the round-scoped byte counter. Called by the loop once
// at the start of every round that actually dispatches reads — the round
// ceiling (§6.1: 16 KB) is stateless per round, unlike the question ceiling,
// which is why it is not reset here.
func (b *Budget) ResetRound() {
	b.roundBytes = 0
}

// ReserveBytes reports whether n more bytes may be injected without
// crossing either the per-round (16 KB) or per-question (32 KB) byte
// ceiling, and — only if both hold — charges both counters. This runs
// AFTER a read has already been performed and clamped to MaxBytesPerResult,
// because the size of a result is only known once the read has happened;
// unlike a read count, there is nothing to reserve ahead of time. A read
// that clears this check is injected; one that does not has its Body
// withheld and is rendered as a ceiling refusal instead — the read still
// cost the read-count budget Reserve already charged, but the operator is
// not shown data that would have blown the round or the question past what
// §6.1 promises the prompt will grow by.
func (b *Budget) ReserveBytes(n int) (bool, string) {
	if b.roundBytes+n > b.MaxBytesPerRound {
		return false, fmt.Sprintf("this round's byte budget of %d bytes is used up", b.MaxBytesPerRound)
	}
	if b.questionBytes+n > b.MaxBytesPerQuestion {
		return false, fmt.Sprintf("this question's byte budget of %d bytes is used up", b.MaxBytesPerQuestion)
	}
	b.roundBytes += n
	b.questionBytes += n
	return true, ""
}

// BytesUsed reports the running per-question total ReserveBytes has
// charged.
func (b *Budget) BytesUsed() int { return b.questionBytes }
