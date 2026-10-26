// The live-progress surface for an in-flight /v1/ask — plan-interrogative-
// loop §9.5/§10.1, build order step 8. A three-round loop can take the best
// part of a minute; an unchanged "thinking" placeholder for that long is
// the exact silence the operator's original complaint was about, one layer
// up from the single-pass fix. This file exists so the drawer can show the
// steps as they happen instead of only the answer at the end.
//
// In-memory, never persisted: a restart re-seals nothing here, because
// there is nothing to re-seal — a lost progress row means the drawer's next
// poll gets a 404 and falls back to waiting for the POST to resolve, which
// is exactly what it did before this file existed.
package main

import (
	"net/http"
	"regexp"
	"sync"
	"time"

	"aperire-advisor/internal/interrogate"
)

// askIDValidRe is the id shape §9.5 and the dashboard's proxy allow-list
// both check against (server.ts mirrors this exact pattern). A page that
// sends anything else gets no progress rather than a 500 — progress is a
// convenience, and a malformed id must never be able to break the ask
// itself (§10.1: "a malformed one disables progress for that question
// rather than failing the ask").
var askIDValidRe = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// progressTTL and maxProgressIDs bound the store: §10.1 names both — a
// 5-minute TTL per entry, and at most 32 concurrent ids. A page that never
// polls again (closed tab, network loss) leaks nothing past the TTL sweep;
// a burst of abandoned ask_ids cannot grow this map without bound between
// sweeps because the cap is enforced on every registration too.
const (
	progressTTL    = 5 * time.Minute
	maxProgressIDs = 32
)

type progressEntry struct {
	steps []interrogate.Step
	at    time.Time

	// The terminal fields break glass grows this store with (plan-
	// interrogative-loop §11.8, build step 18: "one polling client serves
	// both tiers"). An ungated ask answers synchronously — but its handler
	// ALSO records its terminal state here, because the POST carrying the
	// synchronous answer can die at a CDN edge (~100s request cap, seen
	// live as HTTP 524) while the loop is still working; the page then
	// recovers the answer from this store instead of losing it.
	//
	// state is "" while running for an ungated ask ("running" for a gated
	// session from beginGated), and "answered"/"ended" once finish() runs.
	state       string
	answer      string
	endedReason string

	// The action block (a confirm gate), carried so a confirm turn whose POST
	// died at the CDN edge (~100s cap) can still deliver its gate: the page's
	// recovery poll reads it from here and renders the gate, instead of the
	// operator getting an answer with no way to approve (#56). Safe because the
	// gate's confirm code is minted and TTL-checked server-side — approving a
	// recovered gate is validated exactly like a live one. The break-glass
	// OFFER is deliberately still not carried (an offer is a fresh invitation,
	// not a record); the action is a record, with its own expiry.
	action any

	// round is how many model calls this question has completed. It exists
	// because steps[] cannot answer "is this still moving": a step is
	// produced by a READ, and a round that answers without reading anything
	// emits none at all (interrogate.Loop.Run calls the model, then only
	// serveRound emits). The page's recovery poll gives up on a STALL — no
	// new step for two minutes — so a gated question spending several
	// read-free rounds on a large prompt looked identical to a service that
	// had stopped answering, and the operator was told the connection
	// dropped while the question was still running (#72).
	//
	// It is a count of completed model calls and nothing more. Reporting it
	// says the loop advanced, which is true; it does not claim the question
	// is close to finishing.
	round int
}

// progressStore is one process-wide ring of in-flight (or just-finished)
// asks, keyed by the ask_id the page minted. Guarded by a mutex because
// Loop.OnStep fires from the request goroutine handling the ask, while
// GET /v1/ask/progress is answered on a different goroutine per poll —
// exactly the shape -race is built to catch.
type progressStore struct {
	mu      sync.Mutex
	entries map[string]*progressEntry
}

func newProgressStore() *progressStore {
	return &progressStore{entries: map[string]*progressEntry{}}
}

// begin registers an empty entry for id, so the first poll — which can
// arrive before the loop has produced a single step — sees "0 steps so
// far" rather than "unknown id". A malformed id is silently not
// registered: OnStep callbacks for it become no-ops (see append), which is
// the "disables progress, never fails the ask" behaviour §10.1 requires.
func (p *progressStore) begin(id string) {
	if !askIDValidRe.MatchString(id) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	if _, exists := p.entries[id]; !exists && len(p.entries) >= maxProgressIDs {
		p.evictOldestLocked()
	}
	p.entries[id] = &progressEntry{at: time.Now()}
}

// beginGated is begin plus the "running" state a gated session's poller
// needs from the first poll onward — the id here is a session_id minted by
// /v1/investigate or /v1/investigate/continue, not a page-chosen ask_id, so
// the shape check is skipped: the service minted this one itself.
func (p *progressStore) beginGated(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	if _, exists := p.entries[id]; !exists && len(p.entries) >= maxProgressIDs {
		p.evictOldestLocked()
	}
	p.entries[id] = &progressEntry{at: time.Now(), state: "running"}
}

// finish records a gated session's terminal state — called once, from the
// background goroutine that ran it, after loop.Run returns. A caller that
// polls after this sees the answer and why the session ended without a
// second request.
func (p *progressStore) finish(id, state, answer, endedReason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[id]
	if !ok {
		return
	}
	e.state, e.answer, e.endedReason = state, answer, endedReason
	e.at = time.Now()
}

// setAction records the confirm gate for id, so a recovery poll can restore it
// when the answering POST never reached the page. Called before finish() in the
// ask handler, so a poll that sees the terminal state also sees the gate. No-op
// for an unknown id (evicted/malformed) — the live POST is still authoritative.
func (p *progressStore) setAction(id string, action any) {
	if id == "" || action == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[id]
	if !ok {
		return
	}
	e.action = action
	e.at = time.Now()
}

// setRound records that the loop finished another model call for id, so a
// polling page can tell "still working" from "stopped answering" on a
// question whose rounds perform no reads. Monotonic by construction (the
// loop counts up) and a no-op for an unknown id, like every other writer
// here — progress is a convenience and must never fail an ask.
func (p *progressStore) setRound(id string, round int) {
	if id == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[id]
	if !ok {
		return
	}
	e.round = round
	e.at = time.Now()
}

// append records one more step for id. A no-op for an id that was never
// begun (malformed, or the store evicted it under pressure) — dropping a
// progress update is always safe, because the final /v1/ask response is
// the authoritative record regardless of whether any poll ever saw it.
func (p *progressStore) append(id string, s interrogate.Step) {
	if id == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[id]
	if !ok {
		return
	}
	e.steps = append(e.steps, s)
	e.at = time.Now()
}

// snapshot returns the steps recorded so far for id, and whether id is
// known at all — a poll for an id this process never began (wrong id, or
// swept past its TTL) is a 404, not an empty, misleadingly-valid list.
func (p *progressStore) snapshot(id string) ([]interrogate.Step, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[id]
	if !ok {
		return nil, false
	}
	out := make([]interrogate.Step, len(e.steps))
	copy(out, e.steps)
	return out, true
}

// progressSnapshot is one entry copied out under the lock — what askProgress
// serves and what a recovery poll reads. A struct rather than a return list
// because the list had already reached six values and a caller wanting only
// `state` was writing five blanks to get it, which is how the wrong one ends
// up read.
type progressSnapshot struct {
	Steps       []interrogate.Step
	State       string
	Answer      string
	EndedReason string
	Action      any
	Round       int
}

// snapshotFull is snapshot plus the terminal fields — what askProgress
// needs to serve a gated session's poll (state/answer/ended_reason) without
// changing snapshot's existing signature and every ungated call site with
// it.
func (p *progressStore) snapshotFull(id string) (progressSnapshot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, exists := p.entries[id]
	if !exists {
		return progressSnapshot{}, false
	}
	out := make([]interrogate.Step, len(e.steps))
	copy(out, e.steps)
	return progressSnapshot{
		Steps: out, State: e.state, Answer: e.answer,
		EndedReason: e.endedReason, Action: e.action, Round: e.round,
	}, true
}

// sweepLocked drops every entry past the TTL. Callers must hold p.mu.
func (p *progressStore) sweepLocked() {
	cutoff := time.Now().Add(-progressTTL)
	for id, e := range p.entries {
		if e.at.Before(cutoff) {
			delete(p.entries, id)
		}
	}
}

// evictOldestLocked drops the least-recently-touched entry, so a burst of
// concurrent asks past maxProgressIDs degrades the OLDEST question's
// progress rather than refusing the newest one. Callers must hold p.mu.
func (p *progressStore) evictOldestLocked() {
	var oldestID string
	var oldestAt time.Time
	for id, e := range p.entries {
		if oldestID == "" || e.at.Before(oldestAt) {
			oldestID, oldestAt = id, e.at
		}
	}
	if oldestID != "" {
		delete(p.entries, oldestID)
	}
}

// askProgress serves GET /v1/ask/progress?id=<ask_id>: the growing prefix
// of steps[] a live ask has produced so far. Registered through readOnly,
// so GET and the service token are already enforced before this runs.
func (s *server) askProgress(_ http.ResponseWriter, r *http.Request) (any, int) {
	id := r.URL.Query().Get("id")
	if !askIDValidRe.MatchString(id) {
		return map[string]any{"error": "bad or missing id"}, http.StatusBadRequest
	}
	snap, ok := s.progress.snapshotFull(id)
	if !ok {
		return map[string]any{"error": "unknown ask id — it may have finished and aged out, or never existed"}, http.StatusNotFound
	}
	steps := snap.Steps
	if steps == nil {
		steps = []interrogate.Step{}
	}
	body := map[string]any{"steps": steps}
	// How many model calls have completed. The page treats an advancing round
	// as advancement, exactly like a new step, so a question whose rounds
	// perform no reads is not mistaken for a service that stopped answering
	// (#72). Always present, 0 included: an Advisor that predates this field
	// omits it entirely, and the page's "did the round advance" test is false
	// against a missing key, which is the old behaviour rather than a crash.
	body["round"] = snap.Round
	// The confirm gate, when this ask minted one — so a recovery poll can render
	// it even though the answering POST never reached the page (#56).
	if snap.Action != nil {
		body["action"] = snap.Action
	}
	// The terminal fields — state/answer/ended_reason, plan-interrogative-
	// loop §11.8 build step 18: "one polling client serves both tiers."
	// Present once an ask reaches its end (gated sessions from their
	// background goroutine, ordinary asks from the handler itself), and
	// omitted only while a question is genuinely still running.
	if snap.State != "" {
		body["state"] = snap.State
		body["answer"] = snap.Answer
		if snap.EndedReason != "" {
			body["ended_reason"] = snap.EndedReason
		}
	}
	return body, http.StatusOK
}
