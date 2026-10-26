// Break glass across a restart — issues #38 and #40.
//
// The Store is in memory, so a restart closes every open window. That is the
// design (§11.3a: "glass re-seals when the service restarts") and it stays.
// What did not work was everything around it: the window ended with no entry
// in the ledger, and the operator was told nothing — on validator1
// (2026-08-21) a deploy restarted advisord mid-investigation, the window
// vanished, and the next question ran ungated with no explanation.
//
// So the record is repaired on the way back up. This file reads the ledger for
// windows that were opened and never closed, and closes them with the reason
// the record itself supports: the service restarted while they were open, or
// they had already run out their clock. It also holds the "a window just
// ended, and here is why" fact that /v1/status hands the tab.
//
// Two properties this must have, and both are tested:
//
//   - Idempotent. A window that already has a closing entry is never closed a
//     second time. Booting twice on the same ledger must produce exactly one
//     breakglass.closed per window, because a duplicate in a hash-chained
//     record is indistinguishable from tampering.
//   - Honest about what it could not know. The counts are rebuilt from the
//     rows the old process managed to write, and a question interrupted
//     mid-flight never wrote its token cost anywhere. A reconstructed entry
//     says so rather than presenting a partial total in the same shape a live
//     close uses.
package main

import (
	"log"
	"time"

	"aperire-advisor/internal/breakglass"
	"aperire-advisor/internal/ledger"
)

// endedRecency is how long after a window ends the tab is still told about
// it. Long enough that an operator who was away from the drawer when the
// service restarted still finds out why their window is gone; short enough
// that a window from this morning does not greet them at lunch.
const endedRecency = 10 * time.Minute

// windowEnded is the fact the drawer needs: a window ended, this is which one
// and this is why. Reconstructed marks the ones the boot scan closed, which
// the tab renders differently — "the Advisor service restarted" is a
// different thing to tell someone than "your window expired".
type windowEnded struct {
	WindowID string
	// Node is context for the reader, and nothing may be routed off it. The
	// two paths that fill it cannot agree: the live notice has the window's
	// own Node (what the window was opened with, the value close and continue
	// are matched against), and the boot scan has only the name this process
	// was started with, because it runs before any docker profile is
	// resolved. Those two differ in the ordinary case, for the reasons set out
	// beside the open window's `node` field in status — which is exactly why
	// that one is taken from the window and this one is not a substitute for it.
	Node     string
	OpenedBy string
	Reason   breakglass.CloseReason
	At       time.Time
	// Reconstructed is true when this ending was rebuilt from the ledger at
	// startup rather than observed by a running window.
	Reconstructed bool
}

// noteWindowEnded remembers the most recent ending. Most recent by the time
// the window ACTUALLY ended, not by when this was called: the boot scan closes
// several windows in a row and the newest of them is the one that matters.
func (s *server) noteWindowEnded(e windowEnded) {
	s.endedMu.Lock()
	defer s.endedMu.Unlock()
	if s.endedWindow != nil && s.endedWindow.At.After(e.At) {
		return
	}
	s.endedWindow = &e
}

// clearWindowEnded drops the notice. Called when a new window opens: the
// operator is plainly not waiting to hear that the last one ended.
func (s *server) clearWindowEnded() {
	s.endedMu.Lock()
	defer s.endedMu.Unlock()
	s.endedWindow = nil
}

// recentlyEnded is what /v1/status reports, or nil.
func (s *server) recentlyEnded(now time.Time) *windowEnded {
	s.endedMu.Lock()
	defer s.endedMu.Unlock()
	if s.endedWindow == nil || now.Sub(s.endedWindow.At) > endedRecency {
		return nil
	}
	e := *s.endedWindow
	return &e
}

// orphanWindow is one window the ledger says was opened and never closed,
// with everything the record can still say about it.
type orphanWindow struct {
	Summary   breakglass.Summary
	OpenedAt  time.Time
	ExpiresAt time.Time
	// EndedAt is when it really stopped. For an expired window that is exact:
	// expiry is a deterministic consequence of the opening entry. For one the
	// restart killed it is the last thing the window was seen doing, which is
	// a LOWER BOUND, not the moment — nothing recorded when the old process
	// went away.
	EndedAt            time.Time
	DurationLowerBound bool
	// TokensPartial is true when a question started inside this window and
	// never recorded its end, which is exactly what happens to the question in
	// flight when the service stops. Its tokens are in no row, so the totals
	// below are a floor.
	TokensPartial bool
}

// scanEntry is the small amount of the ledger this scan cares about, pulled
// out so the accumulation below reads as bookkeeping rather than as JSON
// spelunking. Data comes back from ledger.Entries as a decoded map, so every
// number is a float64 and every time is a string.
func dataString(e ledger.Entry, key string) string {
	v, _ := e.Data[key].(string)
	return v
}

func dataInt(e ledger.Entry, key string) int {
	switch n := e.Data[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func dataTime(e ledger.Entry, key string) time.Time {
	switch v := e.Data[key].(type) {
	case string:
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return time.Time{}
		}
		return t.UTC()
	case time.Time:
		return v.UTC()
	}
	return time.Time{}
}

// reconstructOpenWindows is the whole scan, as a pure function over the
// ledger's entries — no file, no clock of its own, so every branch is
// reachable from a test.
//
// Windows are returned oldest first.
func reconstructOpenWindows(entries []ledger.Entry, now time.Time) []orphanWindow {
	type acc struct {
		orphanWindow
		started, ended int
		closed         bool
		lastSeen       time.Time
	}
	byID := map[string]*acc{}
	var order []string

	for _, e := range entries {
		id := dataString(e, "window_id")
		if id == "" {
			continue
		}
		switch e.Kind {
		case ledger.KindBreakglassOpened:
			a, ok := byID[id]
			if !ok {
				a = &acc{}
				byID[id] = a
				order = append(order, id)
			}
			a.Summary.WindowID = id
			a.Summary.OpenedBy = dataString(e, "opened_by")
			a.OpenedAt = e.At.UTC()
			a.ExpiresAt = dataTime(e, "expires_at")
			if a.ExpiresAt.IsZero() {
				// An entry from a build that did not carry expires_at. The
				// bound is a constant of this package, so derive rather than
				// give up on the window entirely.
				a.ExpiresAt = a.OpenedAt.Add(breakglass.Duration)
			}
			a.lastSeen = e.At.UTC()
		case ledger.KindBreakglassClosed:
			if a, ok := byID[id]; ok {
				a.closed = true
			}
		case ledger.KindInvestigateStarted:
			if a, ok := byID[id]; ok {
				a.started++
				a.lastSeen = e.At.UTC()
			}
		case ledger.KindInvestigateRead:
			if a, ok := byID[id]; ok {
				// One row per privileged read, so the rows ARE the count —
				// and a more complete one than summing investigate.ended
				// would give, because the reads of an interrupted question
				// are here and its end is nowhere.
				a.Summary.PrivilegedReads++
				a.lastSeen = e.At.UTC()
			}
		case ledger.KindInvestigateEnded:
			if a, ok := byID[id]; ok {
				a.ended++
				a.Summary.PromptTokens += dataInt(e, "prompt_tokens")
				a.Summary.CachedPromptTokens += dataInt(e, "cached_prompt_tokens")
				a.Summary.CompletionTokens += dataInt(e, "completion_tokens")
				a.lastSeen = e.At.UTC()
			}
		}
	}

	var out []orphanWindow
	for _, id := range order {
		a := byID[id]
		if a.closed || a.OpenedAt.IsZero() {
			continue
		}
		w := a.orphanWindow
		w.Summary.Questions = a.started
		w.TokensPartial = a.started > a.ended
		if now.Before(a.ExpiresAt) {
			// Its clock had not run out, so something else ended it, and the
			// only thing that could is this service going away.
			w.Summary.ClosedBecause = breakglass.ClosedServiceRestart
			w.EndedAt = a.lastSeen
			w.DurationLowerBound = true
		} else {
			w.Summary.ClosedBecause = breakglass.ClosedExpired
			w.EndedAt = a.ExpiresAt
			// A window that reaches its expiry while the service is up is
			// closed live, by the notice, and never reaches this scan. Getting
			// here means the process was gone before the clock ran out, so how
			// long it was actually HELD is unknown — expiry is when it stopped
			// being usable, not when it stopped being used.
			w.DurationLowerBound = false
		}
		w.Summary.DurationHeld = w.EndedAt.Sub(w.OpenedAt)
		if w.Summary.DurationHeld < 0 {
			// Only reachable if the host's clock moved backwards between the
			// opening entry and the ending this derives. A negative duration
			// held would be read as a defect in this scan rather than as the
			// clock problem it is, so it floors at zero and the two timestamps
			// stay on the entry for anyone who wants to see the disagreement.
			w.Summary.DurationHeld = 0
		}
		out = append(out, w)
	}
	return out
}

// closeOrphanWindows runs once at boot, before the listener. It appends one
// breakglass.closed for every window the ledger left open, and remembers the
// most recent so the tab can say what happened. Returns how many it closed.
func (s *server) closeOrphanWindows(now time.Time) int {
	entries, err := ledger.Entries(s.ledgerPath())
	if err != nil {
		// A ledger that does not verify is not a reason to refuse to start,
		// and appending to a broken chain would bury the break. Say so and
		// leave it alone.
		log.Printf("[breakglass] could not read the ledger to reconcile open windows: %v", err)
		return 0
	}
	orphans := reconstructOpenWindows(entries, now)
	for _, o := range orphans {
		note := "Reconstructed at startup from the record: the window was open when this service last stopped."
		if o.Summary.ClosedBecause == breakglass.ClosedExpired {
			note = "Reconstructed at startup from the record: the window ran out its clock while this service was not running."
		}
		if o.TokensPartial {
			note += " One investigation never recorded its end, so the token counts are a floor, not a total."
		}
		extra := map[string]any{
			// The flag an auditor needs to keep these apart from a live close:
			// the counts came from reading the chain back, not from a window
			// that was there to be measured.
			"reconstructed":    true,
			"reconstructed_at": now.UTC(),
			"opened_at":        o.OpenedAt,
			"expires_at":       o.ExpiresAt,
			"ended_at":         o.EndedAt,
		}
		if o.TokensPartial {
			extra["tokens_partial"] = true
		}
		if o.DurationLowerBound {
			extra["duration_is_lower_bound"] = true
		}
		// The service closed it, from its own reading of the record, and the
		// entry says so rather than being anonymous or borrowing the opener's
		// name for an act they did not perform.
		s.appendBreakglassClosed(o.Summary, serviceActor("the Advisor"), note, extra)
		log.Printf("[breakglass] window %s was left open by the last run; recorded closed (%s) after %s",
			o.Summary.WindowID, o.Summary.ClosedBecause, o.Summary.DurationHeld.Round(time.Second))
		// Two different clocks, deliberately. EndedAt is when the window
		// stopped being USED, which is what duration_held_seconds is measured
		// against. The notice needs when the operator LOST it, which for a
		// restart is the restart, not their last read.
		//
		// Taking EndedAt for both suppresses the notice in exactly the case
		// this exists for: someone opens a window, asks a question, then reads
		// the answer for twelve minutes before a deploy restarts under them.
		// Their last row is twelve minutes old, the recency window is ten, and
		// the tab says nothing about a window that vanished seconds ago.
		lostAt := o.EndedAt
		if o.Summary.ClosedBecause == breakglass.ClosedServiceRestart {
			lostAt = now
		}
		s.noteWindowEnded(windowEnded{
			WindowID: o.Summary.WindowID, Node: s.container, OpenedBy: o.Summary.OpenedBy,
			Reason: o.Summary.ClosedBecause, At: lostAt, Reconstructed: true,
		})
	}
	return len(orphans)
}
