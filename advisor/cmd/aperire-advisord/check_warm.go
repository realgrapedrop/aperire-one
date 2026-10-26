package main

import (
	"context"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Keeping /v1/check warm — issue #250.
//
// The Operations card cannot paint its head until /v1/check answers, and a
// cold evaluation is expensive: 7.06 s on stock-node1 (a docker inspect, the
// wrapper's rotation read, the public-API lookups the preconditions make),
// 2 ms on the next call. Prod never shows it, because prod's own dashboard
// polls its own Advisor every 30 s and the cache is never cold. A fleet
// aggregator asks a NODE's Advisor only when an operator opens that node's
// tab, so on every node nobody watches, the operator IS the cold call. The
// operator raised it twice.
//
// So the daemon keeps its own last answer warm while it is idle. It knows
// which plan to keep warm because it remembers the parameters of the last
// /v1/check it served (the key, and the query string that names the plan),
// and it re-runs that evaluation through refreshCheck's own path, so the
// rotation key (#93), the generation guard and the one-refresh-in-flight rule
// all hold exactly as they do behind a stale poll.
//
// What bounds the work, because this is a validator host and nothing here may
// probe docker forever:
//
//   - Never while a run is in flight. An executor run is already editing the
//     compose file and reading the node; the keeper stands aside for it.
//   - Never on a host with no node of its own. The aggregator is installed
//     with --container=none and has no docker binary, so there is nothing to
//     keep warm and nothing to say about it every few seconds (#120).
//   - Backoff, doubling to a cap, while the evaluation fails or runs slow.
//   - Idle stop. A day with nobody asking and the keeper stops probing; the
//     next request starts it again.
const (
	// checkWarmSlow is the evaluation cost above which the keeper treats the
	// host as unwell and spaces itself out. Picked from the timings this code
	// already logs: a healthy cold evaluation is 2.7 to 3.9 s on the aperire4
	// VPS and 7.06 s on stock-node1, and the pathological case validator1
	// produced when its path to the registry stalled was 34.7 s and 70.4 s
	// (see registry_cache.go). 15 s sits above every healthy reading and well
	// below the sick ones, so a normal cold node is kept warm and a sick one
	// is left alone.
	checkWarmSlow = 15 * time.Second
	// checkWarmBase is the idle cadence; see checkWarmEvery for the reasoning
	// and the measurement behind it. Well inside checkStaleMax (10 min), so
	// one slow evaluation and one doubled backoff still leave the entry
	// servable.
	checkWarmBase = 3 * time.Minute
	// checkWarmBackoffMax is as far apart as the attempts get. Deliberately
	// BELOW checkStaleMax: at a ten-minute cadence the entry reaches the
	// serving-stale bound and the next viewer evaluates in line, which is the
	// cost this whole file exists to remove. Five minutes still bounds a
	// broken box at thirty times the base cadence.
	checkWarmBackoffMax = 5 * time.Minute
	// checkWarmIdleStop is how long the daemon goes unasked before the keeper
	// stops. A node nobody has opened for a day does not need its check kept
	// warm, and the first request after that starts it again.
	checkWarmIdleStop = 24 * time.Hour
	// checkWarmSaveEvery bounds how often the remembered plans are written
	// down when nothing about the set has changed. The stamps decide one
	// thing, a 24-hour cutoff, so a minute of drift is free.
	checkWarmSaveEvery = time.Minute
)

// checkWarmFile is where the remembered plans live between restarts, under the
// state directory beside the other things this service keeps.
//
// Why they are kept at all: measured on stock-node1 after this shipped, a plan
// asked once since the restart answered in 0.01s after eleven idle minutes,
// and a plan asked only BEFORE the restart came back cold at 3.25s. Every
// fleet update restarts the daemon and the operator opens the tab right after,
// so without this the first open still pays once per update. What is written
// is the query strings and when each was last asked. Nothing else: no verdict,
// no confirm code, no reading of the node. A measurement is never restored
// from disk, only the question worth re-measuring.
const checkWarmFile = "check-warm.json"

// checkWarmQueryMax bounds one remembered query string. The file is written by
// this service into its own 0750 state directory, so this is not a trust
// boundary; it is the rule that a file which has gone wrong cannot become an
// unbounded request URL.
const checkWarmQueryMax = 256

type checkWarmSaved struct {
	Protocol int              `json:"protocol"`
	Plans    []checkWarmEntry `json:"plans"`
}

type checkWarmEntry struct {
	Query string    `json:"query"`
	Asked time.Time `json:"asked"`
}

func (s *server) checkWarmPath() string {
	dir := strings.TrimSpace(s.stateDir)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, checkWarmFile)
}

// saveWarmPlans writes the ring down. Called from the request path, so it is
// one small atomic write and never a reason a request fails: a state directory
// that cannot be written is logged and the keeper carries on in memory.
func (s *server) saveWarmPlans() {
	path := s.checkWarmPath()
	if path == "" {
		return
	}
	out := checkWarmSaved{Protocol: 1}
	for _, p := range s.warm.plan() {
		out.Plans = append(out.Plans, checkWarmEntry{Query: p.rawQuery, Asked: p.asked.UTC()})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		log.Printf("[check-warm] could not write %s: %v", path, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[check-warm] could not replace %s: %v", path, err)
		os.Remove(tmp)
	}
}

// loadWarmPlans reads them back at start, so the keeper begins warm rather
// than waiting for somebody to ask first. One log line either way.
//
// Every way this can go wrong ends in an empty ring and a running daemon: a
// missing file (the normal first start), an unreadable one, malformed JSON, a
// query string that will not parse, an entry older than the idle stop. None of
// them is a reason to refuse to start, and none of them costs more than the
// cold evaluation this exists to avoid.
func (s *server) loadWarmPlans() {
	path := s.checkWarmPath()
	if path == "" {
		return
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[check-warm] starting with no remembered plans, %s could not be read: %v", path, err)
		}
		return
	}
	var in checkWarmSaved
	if err := json.Unmarshal(body, &in); err != nil {
		log.Printf("[check-warm] starting with no remembered plans, %s is not readable as JSON: %v", path, err)
		return
	}
	idleStop := s.warm.dur(s.warm.idleStop, checkWarmIdleStop)
	var kept []warmPlan
	dropped := 0
	for _, e := range in.Plans {
		q := strings.TrimSpace(e.Query)
		if q == "" || len(q) > checkWarmQueryMax {
			dropped++
			continue
		}
		if _, err := url.ParseQuery(q); err != nil {
			dropped++
			continue
		}
		// Older than the idle stop is a plan the keeper would have gone quiet
		// on anyway. Restoring it would start a day's probing for a tab
		// nobody has opened since yesterday.
		if e.Asked.IsZero() || time.Since(e.Asked) >= idleStop {
			dropped++
			continue
		}
		kept = append(kept, warmPlan{key: "check-warm:" + q, rawQuery: q, asked: e.Asked})
		if len(kept) >= checkWarmPlans {
			break
		}
	}
	if len(kept) == 0 {
		if dropped > 0 {
			log.Printf("[check-warm] starting with no remembered plans, %d in %s were stale or unusable",
				dropped, path)
		}
		return
	}
	s.warm.restore(kept)
	log.Printf("[check-warm] starting warm on %d remembered plan(s) from %s", len(kept), path)
}

// checkWarmEvery is the base cadence: three minutes, measured from the END
// of the previous evaluation so two never overlap.
//
// It was four fifths of the cache TTL, 8 s, so that a viewer always found
// an entry inside its TTL. Measured on stock-node1 on 2026-09-09 that cost
// 439 wrapper calls into the node's container in ten minutes, each a sudo
// and a docker exec, about twenty times what the node's own dashboard had
// been asking for, and the operator asked what it cost. The premise was
// wrong: /v1/check already serves any entry younger than checkStaleMax at
// once and refreshes it behind the request (see "Serving stale"). The
// keeper's whole job is to keep the entry INSIDE that bound, and a
// three-minute cadence does that with room to spare through a slow
// evaluation and one backoff step. The body a cold tab paints is at most a
// few minutes old, says so in evaluated_at, and the tab's own first poll
// brings the fresh one seconds later. The TTL is not consulted: a shorter
// TTL is about how long a fresh answer stays fresh, not how often to probe.
func checkWarmEvery(ttl time.Duration) time.Duration {
	_ = ttl
	return checkWarmBase
}

// warmPlan is one plan the keeper keeps warm: how a request named it, the key
// its answer is stored under, and when a request last named it. The key is not
// persisted — it is derived from the rotation reading current at the time, so
// a key from before a restart would name an entry that no longer exists.
type warmPlan struct {
	key, rawQuery string
	asked         time.Time
}

// checkWarmPlans is how many of them are remembered. Not one, because a cold
// open of the Advisor tab asks about TWO: the plan the Operations card paints
// (loadChecks, ?target=...) and the restart plan the shared terminal reads its
// last_run from (?runbook=restart-node&intent=...). Keeping only the last one
// named would leave whichever lost the race cold, which is the whole defect
// wearing a different query string. Three leaves room for a target the
// operator asked about by hand without letting the ring grow into a reason to
// keep probing.
const checkWarmPlans = 3

// checkWarm is what the keeper remembers between turns: which plan to
// re-evaluate, when a request last named one, and how badly the last
// evaluations went. Guarded by its own mutex — cacheMu is held by the request
// path around the cache map, and this is read from a background goroutine.
type checkWarm struct {
	mu sync.Mutex
	// on is the --check-warm switch, read once at boot. debug is the
	// per-refresh line, which is off unless AP_CHECK_WARM_DEBUG is set: at
	// the base cadence it is around ten thousand journal lines a day, and a
	// periodic line on a healthy box is exactly what #120 was about.
	on, debug bool
	// The plans recent requests named, most recent first. A plan is its
	// query string (how the tab named it) and the cache entry's key, which is
	// also the token refreshCheck dedupes on.
	plans []warmPlan
	// When a request last named a plan, and whether the keeper has gone quiet
	// because none has for checkWarmIdleStop.
	lastAsk time.Time
	idle    bool
	// Consecutive failed or slow evaluations, which is the backoff exponent.
	fails int
	// When the ring was last written to disk.
	lastSave time.Time
	// Test seams; zero means the constants above.
	every, slow, backoffMax, idleStop, saveEvery time.Duration
}

// asked records that a request named a plan, and puts that plan at the front
// of the ring. Called from /v1/check, on the request path, so it takes no host
// read and does no work beyond a slice shuffle.
//
// This is the ONLY place the asked stamp moves. The keeper's own refreshes go
// through note() below, which does not touch it: a keeper that reset its own
// idle clock would never go quiet, and a plan nobody has asked for in a day
// would look freshly wanted forever.
//
// woke says this request found a keeper that had gone quiet, which is worth
// saying out loud exactly once. persist says the remembered set changed enough
// to be worth writing down.
func (w *checkWarm) asked(rawQuery string) (woke, persist bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	w.lastAsk = now
	before := len(w.plans)
	found := -1
	for i := range w.plans {
		if w.plans[i].rawQuery == rawQuery {
			found = i
			break
		}
	}
	if found >= 0 {
		p := w.plans[found]
		p.asked = now
		copy(w.plans[1:found+1], w.plans[:found])
		w.plans[0] = p
	} else {
		// A key it has not been given yet. Named after the plan so two
		// unkeyed plans cannot collide in the one-refresh-in-flight map; the
		// first evaluation replaces it with the entry's real key.
		w.plans = append([]warmPlan{{key: "check-warm:" + rawQuery, rawQuery: rawQuery, asked: now}}, w.plans...)
		if len(w.plans) > checkWarmPlans {
			w.plans = w.plans[:checkWarmPlans]
		}
	}
	if w.idle {
		w.idle = false
		woke = true
	}
	// Written when the set changed, and otherwise at most once a minute: the
	// stamps only decide a 24-hour cutoff, so a minute of drift costs nothing
	// and a file write per poll would be pure noise on the request path.
	persist = found < 0 || before != len(w.plans) ||
		now.Sub(w.lastSave) >= w.dur(w.saveEvery, checkWarmSaveEvery)
	if persist {
		w.lastSave = now
	}
	return woke, persist
}

// note records the key a plan's answer is stored under, which is also the
// token refreshCheck dedupes on. Called where both the key and the query are
// known — the stale-serving branch of check(), and the store at the end of
// checkEvaluate.
//
// Keyed on the query string, not on the cache key: one plan has two keys, one
// per rotation state (#93), and they are the same plan under a clock that
// moved. A plan that is no longer remembered is not put back: the ring is
// what requests asked for, and a refresh is not a request.
func (w *checkWarm) note(key, rawQuery string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.plans {
		if w.plans[i].rawQuery == rawQuery {
			w.plans[i].key = key
			return
		}
	}
}

// restore seeds the ring at start. The idle clock is set from the most recent
// stamp, so a daemon restarted an hour into a quiet day carries on counting
// that day rather than starting it again.
func (w *checkWarm) restore(plans []warmPlan) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.plans = append([]warmPlan(nil), plans...)
	for _, p := range plans {
		if p.asked.After(w.lastAsk) {
			w.lastAsk = p.asked
		}
	}
}

func (w *checkWarm) plan() []warmPlan {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]warmPlan(nil), w.plans...)
}

func (w *checkWarm) enabled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.on
}

func (w *checkWarm) dur(seam, def time.Duration) time.Duration {
	if seam > 0 {
		return seam
	}
	return def
}

// goneQuiet reports whether nothing has asked for a check in long enough to
// stop, and marks the keeper idle the first time it does.
func (w *checkWarm) goneQuiet() (quiet, first bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastAsk.IsZero() || time.Since(w.lastAsk) < w.dur(w.idleStop, checkWarmIdleStop) {
		return false, false
	}
	if w.idle {
		return true, false
	}
	w.idle = true
	return true, true
}

// backOff counts one bad evaluation and returns how long to wait before the
// next attempt: the base cadence doubled once per consecutive failure, capped.
func (w *checkWarm) backOff(base time.Duration) time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fails++
	max := w.dur(w.backoffMax, checkWarmBackoffMax)
	d := base
	for i := 0; i < w.fails; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}

// recovered clears the backoff and reports whether there was one to clear.
func (w *checkWarm) recovered() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fails == 0 {
		return false
	}
	w.fails = 0
	return true
}

func (w *checkWarm) debugf(format string, args ...any) {
	w.mu.Lock()
	on := w.debug
	w.mu.Unlock()
	if on {
		log.Printf("[check-warm] "+format, args...)
	}
}

// runInFlight reports whether an executor run holds this node right now. The
// same flag /v1/run gates on, read under the same lock, so the keeper cannot
// decide from a different fact than the thing it is standing aside for.
func (s *server) runInFlight() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.running
}

// checkWarmLoop is the keeper. Started once at boot beside the registry
// refresher, which is the daemon's existing pattern for holding an answer off
// the request path.
func (s *server) checkWarmLoop(ctx context.Context) {
	if !s.warm.enabled() {
		log.Printf("[check-warm] switched off; /v1/check is evaluated on demand")
		return
	}
	// Nothing to keep warm, said once and then the goroutine ends rather than
	// idling on a timer — the #120 shape. s.container is set at boot and never
	// reassigned, so nothing this loop could wake for will change the answer.
	if s.noLocalNode() {
		log.Printf("[check-warm] no local node on this host; nothing to keep warm")
		return
	}
	// What was being kept warm before the last restart. Here rather than in
	// main so there is one place the keeper is started and one place it
	// learns what to start on.
	s.loadWarmPlans()
	base := s.warm.dur(s.warm.every, checkWarmEvery(s.cacheTTL))
	log.Printf("[check-warm] keeping the last /v1/check plans warm every %s while this daemon is idle", base)
	wait := base
	for {
		select {
		case <-ctx.Done():
			log.Printf("[check-warm] stopping")
			return
		case <-time.After(wait):
		}
		wait = s.checkWarmTurn(ctx, base)
	}
}

// checkWarmTurn is one turn of the keeper: decide whether to re-evaluate, do
// it in line, and say how long to wait before the next turn.
func (s *server) checkWarmTurn(ctx context.Context, base time.Duration) time.Duration {
	plans := s.warm.plan()
	if len(plans) == 0 {
		// Nobody has asked for a check on this daemon yet, so there is no
		// plan to keep warm. Nothing is logged: this is the resting state of
		// a node whose tab has not been opened since the last restart.
		return base
	}
	if quiet, first := s.warm.goneQuiet(); quiet {
		if first {
			log.Printf("[check-warm] no request for %s; going quiet until the next one",
				s.warm.dur(s.warm.idleStop, checkWarmIdleStop))
		}
		return base
	}
	if s.runInFlight() {
		s.warm.debugf("skipping this turn, a run is in flight")
		return base
	}
	// Every remembered plan, one after another rather than at once: they
	// share the profile and rotation reads through their caches, so in series
	// the second is cheap, and in parallel it would be a burst of wrapper
	// execs, which is the storm rotation_cache.go exists to stop.
	var firstErr error
	var worst time.Duration
	evaluated := 0
	for _, p := range plans {
		if ctx.Err() != nil {
			return base
		}
		rctx, cancel := context.WithTimeout(ctx, checkRefreshTimeout)
		t0 := time.Now()
		ran, err := s.refreshCheckNow(rctx, p.key, p.rawQuery)
		cancel()
		took := time.Since(t0).Round(time.Millisecond)
		if !ran {
			// A poll of its own found the entry stale and is already
			// measuring this plan. One evaluation is the whole point of the
			// in-flight rule.
			s.warm.debugf("skipping %s, a refresh of it is already running", p.key)
			continue
		}
		evaluated++
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if took > worst {
			worst = took
		}
		s.warm.debugf("refreshed %s in %s", p.rawQuery, took)
	}
	if evaluated == 0 {
		return base
	}
	slow := s.warm.dur(s.warm.slow, checkWarmSlow)
	switch {
	case firstErr != nil:
		d := s.warm.backOff(base)
		log.Printf("[check-warm] the evaluation failed (%v); backing off to every %s", firstErr, d)
		return d
	case worst > slow:
		d := s.warm.backOff(base)
		log.Printf("[check-warm] the evaluation took %s, past the %s bound; backing off to every %s",
			worst, slow, d)
		return d
	}
	if s.warm.recovered() {
		log.Printf("[check-warm] the evaluation recovered in %s; back to every %s", worst, base)
	}
	return base
}

// checkWarmDebugFromEnv reads the per-refresh debug switch. An env var rather than
// a second flag: it is a thing you turn on for an hour while looking at a
// journal, not a thing a unit file should carry.
func checkWarmDebugFromEnv() bool {
	v := os.Getenv("AP_CHECK_WARM_DEBUG")
	return v == "1" || v == "true"
}
