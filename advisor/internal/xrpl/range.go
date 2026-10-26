package xrpl

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// MaxRangeSpan is the largest window LookupRange will ever fetch. Enforced
// inside the function rather than left to the caller, so the cap holds
// whether the request came from a range-checked menu item or from a mistake
// at some future call site — see plan-interrogative-loop §4.2.
const MaxRangeSpan = 12

// RangeTimeout bounds the whole call, not any one ledger inside it. A public
// cluster degrading partway through a range must turn into a partial result
// with the unfetched indices named, not a multi-minute stall on one
// investigative read.
const RangeTimeout = 15 * time.Second

// LookupRange fetches a small run of consecutive public ledger summaries —
// the fallback for a ledger outside the dashboard's 30-day local window, or
// one this node never observed at all (plan-interrogative-loop §4.2).
//
// It reuses Lookup for each index, so retries, the lgrNotFound explanation
// and the close-interval-from-the-predecessor behaviour are identical to a
// single-ledger lookup.
//
// Partial success is a real result, not a failure: the summaries it managed
// to fetch are returned alongside one named error per index it did not get
// to, so a caller can report "9 of 12 fetched, 3 failed: ..." instead of
// discarding a mostly-successful range because the tail timed out. A
// request wider than MaxRangeSpan is clamped, and the clamp itself is one
// more named entry in the error slice — never a silently narrower answer.
func LookupRange(ctx context.Context, client *http.Client, endpoint string, from, to int64) ([]Summary, []error) {
	if to < from {
		from, to = to, from
	}

	var errs []error
	if requested := to - from + 1; requested > MaxRangeSpan {
		// The menu range-checks span <= 12 before ever calling this, so in
		// practice this clamp is belt-and-braces. But a clamp that happens
		// silently is exactly the defect this plan treats as a bug
		// everywhere else it can occur (§4.1's ledgers window, §9.1's echo
		// rule) — one named notice, not one per dropped index, so a caller
		// summing summaries against errors still accounts for every index
		// asked about.
		clampedTo := from + MaxRangeSpan - 1
		errs = append(errs, fmt.Errorf(
			"requested range %d–%d (%d ledgers) exceeds the maximum span of %d; serving %d–%d",
			from, to, requested, MaxRangeSpan, from, clampedTo))
		to = clampedTo
	}

	ctx, cancel := context.WithTimeout(ctx, RangeTimeout)
	defer cancel()

	var summaries []Summary
	for idx := from; idx <= to; idx++ {
		s, err := Lookup(ctx, client, endpoint, idx)
		if err != nil {
			errs = append(errs, fmt.Errorf("ledger %d: %w", idx, err))
			// Once the range's own clock has run out, every remaining index
			// will fail the same way. Name each of them rather than
			// spending the rest of the timeout finding that out one at a
			// time.
			if ctx.Err() != nil {
				for j := idx + 1; j <= to; j++ {
					errs = append(errs, fmt.Errorf("ledger %d: %w", j, ctx.Err()))
				}
				break
			}
			continue
		}
		summaries = append(summaries, s)
	}
	return summaries, errs
}
