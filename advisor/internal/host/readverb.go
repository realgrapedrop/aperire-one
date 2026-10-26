package host

import (
	"context"
	"fmt"
)

// MaxPrivilegedHostReads is the ceiling on privileged host reads one
// question may spend — unchanged from the seed probes' long-standing
// maxProbes. The interrogative loop's read menu shares this same number
// rather than granting a fresh three per round or per caller: a naive port
// of "three per Inspect call" to "three per round" would let a four-round
// question spend the cap four times over, which is the amplification this
// design exists to prevent (plan-interrogative-loop, §4.3).
const MaxPrivilegedHostReads = 3

// Budget bounds how many privileged host reads one question may spend. It is
// the single counter every caller shares — the seed probes in Inspect today,
// and the read menu's host_read requests once the interrogative loop lands —
// so the question-level cap holds across both instead of resetting per
// caller. One counter, not one per code path, is what makes the number in
// MaxPrivilegedHostReads actually mean what it says.
type Budget struct {
	// Max is exported so a caller can report "N of Max used" without a
	// second accessor.
	Max  int
	used int
}

// NewBudget starts a budget with nothing spent yet.
func NewBudget(max int) *Budget {
	return &Budget{Max: max}
}

// Take reserves one read and reports whether the budget had room. A nil
// Budget always refuses — a caller that forgot to wire one up fails closed
// rather than reading without limit.
func (b *Budget) Take() bool {
	if b == nil || b.used >= b.Max {
		return false
	}
	b.used++
	return true
}

// Used is how many reads have been spent so far.
func (b *Budget) Used() int {
	if b == nil {
		return 0
	}
	return b.used
}

// Remaining is how many reads are left; never negative.
func (b *Budget) Remaining() int {
	if b == nil {
		return 0
	}
	if r := b.Max - b.used; r > 0 {
		return r
	}
	return 0
}

// ReadVerb runs one read-only verb through the root-owned wrapper, spending
// one unit of budget. It is the single path both Inspect's seed probes and
// the read menu's host_read item call — one counter, one place the
// three-per-question cap can be gotten wrong instead of two.
//
// verb is checked against the exact Probes list rather than trusted from the
// caller, the same independent-validation discipline the wrapper itself
// applies: an unrecognised verb is refused before anything runs and before
// it spends any budget, and a recognised one is still only ever passed as
// one argv element to the wrapper — never interpolated into a command line,
// so nothing here can become a string that reaches a shell.
func ReadVerb(ctx context.Context, r Runner, wrapper string, budget *Budget, verb, arg string) (string, error) {
	if !validVerb(verb) {
		return "", fmt.Errorf("refused: no such host read verb %q", verb)
	}
	if !budget.Take() {
		return "", fmt.Errorf("refused: privileged host reads are capped at %d per question", budget.Max)
	}
	args := []string{verb}
	if arg != "" {
		args = append(args, arg)
	}
	out, err := r.Run(ctx, wrapper, args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func validVerb(verb string) bool {
	for _, p := range Probes {
		if p.Verb == verb {
			return true
		}
	}
	return false
}
