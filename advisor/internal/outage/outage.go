// Package outage says how long this node is out of consensus when it is
// restarted, from the node's own record of the restarts it came back from.
//
// It exists because of #1014. The upgrade gate promised "about 30 seconds
// offline". On a lab validator (17bc, 2026-10-11) a container validator was out of
// proposing for about 8.5 and about 7 minutes across two upgrades, and an
// earlier run on another lab node took about 11. The 30 seconds was a
// container coming back up, not a validator coming back into consensus, and
// nobody had measured it as the second. The rollback gate said "about seven
// when this was last measured", a figure from a different node on a different
// day, so the two gates also disagreed.
//
// The figure now comes from one place: the run.completed and
// run.confirmed_late entries the executor writes when the node proves it is
// back in full sync. Each carries applied_at, when the run's interrupting step
// began, and observed_at, when the reading that proved the node back was
// taken. Their difference is the outage that run caused, measured on this
// node. Every gate, the run transcript and the model read the same sentence.
//
// With no such run on record there is no number, and the sentence says so
// rather than borrowing one.
package outage

import (
	"fmt"
	"time"

	"aperire-advisor/internal/ledger"
)

// recent is how many of the newest runs the range is taken over. Enough that
// one unusual run does not stand for the node; few enough that a node whose
// peers or hardware changed is described by how it behaves now.
const recent = 5

// Reading is the measured outage over this node's most recent restarts.
type Reading struct {
	// Runs is how many restarts the range covers, newest first; zero when
	// none has been timed.
	Runs int
	// Shortest and Longest bound those runs.
	Shortest, Longest time.Duration
	// LastAt is when the newest of them was proved back in full sync.
	LastAt time.Time
}

// FromLedger reads the restarts this node came back from.
//
// Only entries that carry both times count. A run.unconfirmed standing alone
// is not one: it records a node that did not prove it was back, so it has no
// end to measure to. A late confirmation does count, and its observed_at is
// the late reading, so a slow return reads as slow.
func FromLedger(entries []ledger.Entry) Reading {
	var took []time.Duration
	var lastAt time.Time
	for i := len(entries) - 1; i >= 0 && len(took) < recent; i-- {
		e := entries[i]
		if e.Kind != ledger.KindRunCompleted && e.Kind != ledger.KindRunConfirmedLate {
			continue
		}
		applied, ok1 := timeField(e.Data, "applied_at")
		observed, ok2 := timeField(e.Data, "observed_at")
		if !ok1 || !ok2 || !observed.After(applied) {
			continue
		}
		if len(took) == 0 {
			lastAt = observed
		}
		took = append(took, observed.Sub(applied))
	}
	r := Reading{Runs: len(took), LastAt: lastAt}
	for i, d := range took {
		if i == 0 || d < r.Shortest {
			r.Shortest = d
		}
		if d > r.Longest {
			r.Longest = d
		}
	}
	return r
}

// FromLedgerFile is FromLedger over the file at path. An unreadable or absent
// ledger is no runs, which the sentence states plainly.
func FromLedgerFile(path string) Reading {
	entries, _ := ledger.Entries(path)
	return FromLedger(entries)
}

func timeField(data map[string]any, key string) (time.Time, bool) {
	s, _ := data[key].(string)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// Sentence is how long the node is out of consensus once the restart begins,
// as a phrase a gate can put after "it stops proposing for the restart at the
// end:". Whole minutes, because the polls behind it are seconds apart and a
// figure finer than a minute would claim a precision the reading does not
// have.
func (r Reading) Sentence() string {
	if r.Runs == 0 {
		return "several minutes out of consensus once the restart begins; no restart of this " +
			"node has been timed yet, so there is no measured figure for it"
	}
	day := r.LastAt.UTC().Format("2006-01-02")
	if r.Runs == 1 {
		return fmt.Sprintf("%s out of consensus once the restart begins, measured on this node's "+
			"last restart (%s)", about(nearest(r.Longest)), day)
	}
	// The range holds every run it covers: the shortest rounded down, the
	// longest rounded up, so 7m11s and 8m29s read as 7 to 9, never 7 to 8.
	lo, hi := floorMin(r.Shortest), ceilMin(r.Longest)
	span := about(lo)
	if lo != hi {
		span = fmt.Sprintf("%d to %d minutes", lo, hi)
	}
	return fmt.Sprintf("%s out of consensus once the restart begins, over this node's last %d "+
		"restarts (the newest on %s)", span, r.Runs, day)
}

// nearest, floorMin and ceilMin give whole minutes, never below one: a node
// that came back in forty seconds was still offline, and "0 minutes" says it
// was not.
func nearest(d time.Duration) int  { return atLeastOne(int((d + 30*time.Second) / time.Minute)) }
func floorMin(d time.Duration) int { return atLeastOne(int(d / time.Minute)) }
func ceilMin(d time.Duration) int  { return atLeastOne(int((d + time.Minute - 1) / time.Minute)) }

func atLeastOne(m int) int {
	if m < 1 {
		return 1
	}
	return m
}

func about(m int) string {
	if m == 1 {
		return "about a minute"
	}
	return fmt.Sprintf("about %d minutes", m)
}
