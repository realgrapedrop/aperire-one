package main

import (
	"strings"
	"sync"
	"time"

	"aperire-advisor/internal/host"
)

// The rotation read, cached — the #93 follow-up.
//
// #93 put host.State.RotationInFlight behind /v1/check and the four act
// assessments. Each read is a wrapper exec (sudo, then a docker-log read),
// and host.State is rebuilt per request, so every poll of the Operations
// card paid a fresh exec. On a VPS-class host that stacked up: the journal
// for 2026-08-27 18:31 shows five concurrent wrapper execs inside one
// second, rotation-state reads dying on their exec deadline ("sudo:
// signal: killed"), and the ask path starving behind them until the
// dashboard reported the question never reached the Advisor.
//
// One short-lived answer fixes all of that. The cache is on the server,
// not on host.State, because the State dies with the request. The mutex is
// held across the exec on purpose: a burst of callers coalesces into ONE
// wrapper exec, with the rest waiting for its answer instead of each
// spawning their own (the single-flight half of the fix).
//
// Ten seconds is safe because this read was never the safety boundary. The
// wrapper's own exit-64 refusal still runs on the privileged side at the
// moment of the act, and the RunStage guard — the one that keeps a doomed
// act from spending the operator's approval — deliberately does NOT use
// this cache: main.go and the CLI executor inject the fresh read there. A
// rotation that begins inside the ten-second window is therefore still
// caught where it matters; the only thing at stake here is how early an
// assessment or the card learns about it, against readings that today were
// being killed under load and failing open anyway.
//
// Errors are cached like answers. An erroring wrapper polled at full card
// rate is exactly the storm this exists to stop, and the callers already
// treat an error as not-in-flight, so handing them the same error for ten
// seconds changes nothing about behaviour, only about load.
const rotationReadTTL = 10 * time.Second

type rotationCache struct {
	// Two locks. `flight` is held across the wrapper exec, which is the
	// single-flight: a burst of readers waits for the one exec. `mu` guards
	// the fields alone and is never held across the exec, so a caller that
	// only wants the last reading (last, below) is not queued behind a read
	// that may be waiting on docker. Serving /v1/check stale depends on
	// that: the poll being answered from the cache must not block on the
	// refresh it started.
	flight sync.Mutex
	mu     sync.Mutex
	at     time.Time
	ttl    time.Duration
	val    bool
	// state is the wrapper's word behind val: "rotating", "idle", "stale",
	// "unknown", or "" when the read errored. val is state == "rotating";
	// the rotation precondition needs the word, because only "idle" says
	// nothing is running (PR #1049 review).
	state  string
	detail string
	err    error
}

func (c *rotationCache) fresh() (bool, string, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.ttl
	if ttl == 0 {
		ttl = rotationReadTTL
	}
	if !c.at.IsZero() && time.Since(c.at) < ttl {
		return c.val, c.detail, c.err, true
	}
	return false, "", nil, false
}

// read answers from the cache when it is fresh, and takes the one wrapper
// read for everyone otherwise.
func (c *rotationCache) read(st *host.State) (bool, string, error) {
	if v, d, err, ok := c.fresh(); ok {
		return v, d, err
	}
	c.flight.Lock()
	defer c.flight.Unlock()
	// Whoever held the flight before us may have just answered this.
	if v, d, err, ok := c.fresh(); ok {
		return v, d, err
	}
	state, d, err := st.RotationStateNow()
	v := state == "rotating"
	c.mu.Lock()
	c.val, c.state, c.detail, c.err, c.at = v, state, d, err, time.Now()
	c.mu.Unlock()
	return v, d, err
}

// rotationInFlightCached is what /v1/check and the four act assessments
// read. The RunStage spend guard must never call this — it gets the fresh
// read injected, see the Executor wiring in this file's main.go.
func (s *server) rotationInFlightCached(st *host.State) (bool, string, error) {
	return s.rotCache.read(st)
}

// lastReading is last with the wrapper's state word and the read's error,
// for the one caller that tells "idle" from "unknown" and an errored read
// from a quiet one: the rotation precondition, at or past its window (#833).
func (c *rotationCache) lastReading(maxAge time.Duration) (state, detail string, err error, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) > maxAge {
		return "", "", nil, false
	}
	return c.state, c.detail, c.err, true
}

// rotationForVerdict is the rotation reading the rotation precondition
// folds in when the store is at or past its window (#833). The one this
// evaluation already took, when there is one: a check reads rotation-state
// before it evaluates, and the window read in between can take most of a
// minute, which outlasts the ten-second cache. Reading again would cost a
// second log read inside the 90-second check (#1043) and could disagree
// with the reading the check's cache key was split on (#93). Only when no
// reading is that recent does this take one, through the cache.
func (s *server) rotationForVerdict(st *host.State) (string, string, error) {
	if state, d, err, ok := s.rotCache.lastReading(checkRefreshTimeout); ok {
		return state, d, err
	}
	_, _, _ = s.rotCache.read(st)
	state, d, err, _ := s.rotCache.lastReading(checkRefreshTimeout)
	return state, d, err
}

// last is the most recent reading, if there is one younger than maxAge, and
// whether there is. It never takes a read. What /v1/check wants from it is
// the NAME of the cache entry to look for (the key is split on the rotation
// state, #93); the entry itself was built from the reading that was current
// when it was evaluated, so a name from an older reading finds an entry that
// is at most as old, or finds nothing and evaluates in line.
func (c *rotationCache) last(maxAge time.Duration) (rotating bool, detail string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) > maxAge {
		return false, "", false
	}
	return c.val, c.detail, true
}

// How often the store rotates, for the sentence chat is handed (#1058).
//
// A refusal during a rotation used to end "the window is brief and runs
// daily". That is a claim about a schedule nobody measured: a node at
// online_delete=512 rotates about every 34 minutes, and the rotation check on
// the same screen said so with the node's own numbers. The sentence now comes
// from the same arithmetic the check uses (host.RotationEvery), or says the
// interval was not measured.
//
// The interval comes from online_delete, which changes only with a restart,
// so the reading is kept for rotationRhythmTTL and read at all only while a
// rotation is in flight, which is when a refusal needs the sentence. A
// failed read is kept for a shorter time, so a broken wrapper is not asked
// on every turn of a chat.
const (
	rotationRhythmTTL     = 10 * time.Minute
	rotationRhythmFailTTL = 30 * time.Second
)

type rotationRhythmCache struct {
	mu   sync.Mutex
	at   time.Time
	ttl  time.Duration
	text string
}

func (c *rotationRhythmCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = time.Time{}
}

// rotationRhythm is the sentence about how often this node's store rotates,
// for the four act assessments to carry when they refuse during a rotation.
func (s *server) rotationRhythm(st *host.State) string {
	c := &s.rotRhythm
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < c.ttl {
		return c.text
	}
	w := st.RotationWindowNow()
	ttl := rotationRhythmTTL
	var text string
	if sched := s.rotationScheduleFor(st, w); sched != "" {
		text = "How often this node's store rotates, from its own settings: " + sched +
			". Quote that if you give a schedule."
	} else {
		why := strings.TrimSpace(w.Reason)
		if why == "" {
			why = "the node reported no online_delete"
		}
		text = "How often this node's store rotates was not measured (" + why + "). " +
			"If asked, say so."
		if w.Failed {
			ttl = rotationRhythmFailTTL
		}
	}
	text += " Never describe the rotation as daily or on any other schedule you were not given here."
	c.at, c.ttl, c.text = time.Now(), ttl, text
	return text
}

// rotationScheduleFor is the clause for a node whose window was read: its
// online_delete, with the advisory_delete setting and the daily window beside
// it, because on advisory_delete=1 the window, not the interval, sets the
// pace (host.RotationSchedule). "" when the window was not read.
func (s *server) rotationScheduleFor(st *host.State, w host.RotationWindow) string {
	if !w.Known || host.RotationEvery(w.OnlineDelete) == "" {
		return ""
	}
	file := ""
	if cfg, err := st.NodeConfiguration(); err == nil {
		if v, ok := cfg.Setting("advisory_delete"); ok {
			file = v
		} else {
			file = "0" // absent: rippled's own default
		}
	}
	// What the running node says decides it, not the file (review of #1101).
	live, _ := st.AdvisoryDeleteLive()
	timer := ""
	if live == host.AdvisoryLiveEnabled {
		timer, _ = st.CanDeleteWindow()
	}
	return host.RotationSchedule(w.OnlineDelete, file, live, timer)
}

// rotationRhythmWhile is rotationRhythm while a rotation is in flight and
// nothing otherwise, so a plan built with the store idle costs no read.
func (s *server) rotationRhythmWhile(rotating bool, st *host.State) string {
	if !rotating {
		return ""
	}
	return s.rotationRhythm(st)
}

// afterRotation joins the rhythm sentence to the one before it, or adds
// nothing when no rhythm was read.
func afterRotation(rhythm string) string {
	if rhythm == "" {
		return ""
	}
	return " " + rhythm
}
