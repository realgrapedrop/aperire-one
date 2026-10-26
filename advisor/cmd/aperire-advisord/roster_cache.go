package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"aperire-advisor/internal/interrogate"
)

// errNoDashRead is the one way readRoster can fail without a network call.
var errNoDashRead = errors.New("this server has no dashboard read client wired in")

// The fleet roster, off the request path, #59.
//
// The defect: asked on stock-node1 about stock-node2, a real node in the same
// fleet, the Advisor answered that it had no registered peer by that name and
// could not read anything about another host. It was right about its own peer
// table and wrong about the fleet. advisord's peer table is generated from
// the dashboard's fleet.yaml, and a row whose read token this host holds no
// copy of is deliberately LEFT OUT of it rather than guessed at
// (dashboard/lib/advisor-registry-gen.ts). So "nobody registered that name"
// and "that host is in the fleet and I hold no way to read it" arrived here
// as one fact, and both came out as the first.
//
// The roster is the dashboard's own answer to "who is in this fleet", read
// through the ADR 0008 contract's `fleet` route against THIS host's
// dashboard. It decides what may be NAMED. The peer table still decides what
// may be READ, and nothing here opens a channel: every peer read still goes
// through the client built at boot from an origin and a token path.
//
// Cached and refreshed in the background for the reason registryCache beside
// it is: a monitoring page must not have a network dependency in the path
// that answers a question. A fleet's membership changes on the scale of an
// operator editing a file, so a minute-old answer is the right answer, and a
// dashboard that is not answering leaves the last roster in place rather than
// collapsing the fleet to nothing.
const (
	// rosterTTL is how long a roster is believed. Long enough that a
	// question never waits on the dashboard, short enough that a node added
	// to the fleet is nameable within the minute.
	rosterTTL = time.Minute
	// rosterRefreshEvery keeps it warm, so the inline path below is the
	// exception rather than the rule.
	rosterRefreshEvery = 45 * time.Second
	// rosterProbeTimeout bounds the one inline fetch a cold cache may cost.
	// The dashboard is on loopback; anything slower than this is a fault,
	// and a question must not wait on it.
	rosterProbeTimeout = 3 * time.Second
)

type rosterCache struct {
	mu      sync.Mutex
	roster  interrogate.Roster
	at      time.Time
	ttl     time.Duration // test seam; zero means rosterTTL
	lastErr string
}

// get returns the last roster this host was told, whatever its age.
//
// Deliberately not TTL-gated. The TTL governs REFRESHING; it does not make a
// roster expire into nothing. A fleet that vanished the moment the dashboard
// hiccuped would turn "registered here, cannot be read from here" straight
// back into "no such node", which is the answer this whole change exists to
// stop, and it would do it exactly when a node is having trouble.
func (c *rosterCache) get() (interrogate.Roster, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return interrogate.Roster{}, false
	}
	return c.roster, true
}

// fresh reports whether the cached roster is inside its TTL. The refresher
// uses it; readers do not, because a stale roster is still the truth about
// who is registered.
func (c *rosterCache) fresh() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() {
		return false
	}
	ttl := c.ttl
	if ttl == 0 {
		ttl = rosterTTL
	}
	return time.Since(c.at) < ttl
}

func (c *rosterCache) put(r interrogate.Roster) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roster, c.at, c.lastErr = r, time.Now(), ""
}

func (c *rosterCache) putErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = err.Error()
}

// readRoster asks this host's own dashboard who is in the fleet and marks
// each row with whether THIS process holds a read client for it.
//
// Readable is the one field the dashboard cannot supply: it is a fact about
// this Advisor's credentials, not about the fleet. Merging it here is what
// makes the difference between the two rosters expressible.
func (s *server) readRoster(ctx context.Context) (interrogate.Roster, error) {
	if s.dashRead == nil {
		// main() sets this before any handler runs, so this is a server
		// built directly (a test). Answered as "no roster", which is the
		// pre-#59 behaviour, rather than by dereferencing nothing.
		return interrogate.Roster{}, errNoDashRead
	}
	raw, err := s.dashRead.FleetRoster(ctx)
	if err != nil {
		return interrogate.Roster{}, err
	}
	out := interrogate.Roster{Registered: raw.Registered, NowMs: raw.NowMs}
	// On a host with no fleet registry the dashboard names itself from its
	// OS hostname, because there is no registry row to take a label from.
	// This process has a better answer: the label the operator gave it with
	// --self-label, which is the name the menu description already uses. Two
	// names for one box inside one answer is worse than either name alone,
	// so the declared one wins wherever it exists.
	fv := s.fleetNow()
	selfLabel := ""
	if !raw.Registered {
		selfLabel = fv.reg.SelfIdentity().Label
	}
	for _, n := range raw.Nodes {
		var last int64
		if n.LastAnsweredMs != nil {
			last = *n.LastAnsweredMs
		}
		label := n.Label
		if n.Self && selfLabel != "" {
			label = selfLabel
		}
		out.Nodes = append(out.Nodes, interrogate.RosterNode{
			Label: label, Role: n.Role, Self: n.Self,
			// This host is always readable by this process: its own
			// dashboard is the client every non-peer read already uses.
			Readable:       n.Self || fv.nodes[n.Label],
			LastAnsweredMs: last,
			Detail:         n.Detail,
		})
	}
	return out, nil
}

// roster is what every question resolves a named node against. Answers from
// the cache when there is anything there at all, and pays for one short
// fetch only on a cold start.
func (s *server) roster(ctx context.Context) interrogate.Roster {
	if r, ok := s.rosterCache.get(); ok {
		return r
	}
	rctx, cancel := context.WithTimeout(ctx, rosterProbeTimeout)
	defer cancel()
	r, err := s.readRoster(rctx)
	if err != nil {
		s.rosterCache.putErr(err)
		// An empty roster is this build's behaviour before #59: a named node
		// falls back to the peer table, and an unknown one is refused
		// locally by name. Never an invented fleet.
		return interrogate.Roster{}
	}
	s.rosterCache.put(r)
	return r
}

// refreshRoster keeps the answer warm.
func (s *server) refreshRoster(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, rosterProbeTimeout)
	defer cancel()
	r, err := s.readRoster(rctx)
	if err != nil {
		s.rosterCache.putErr(err)
		return
	}
	s.rosterCache.put(r)
}

func (s *server) rosterRefreshLoop(ctx context.Context) {
	s.refreshRoster(ctx)
	if !s.rosterCache.fresh() {
		// Said once at boot, not on every tick: a dashboard that does not
		// serve the route (an older one on a half-upgraded host) would
		// otherwise write the same line to the journal forever, and that
		// reads as a fault on a box that is working.
		log.Printf("[fleet] the dashboard did not answer the fleet roster; node names resolve against this Advisor's own peer table until it does")
	}
	// A ticker rather than registry_cache.go's "say it once and end the
	// goroutine" (#120). That loop ends because its answer is about a node
	// this host does not have, and nothing it could wake for would change
	// it. This one CAN change: a dashboard that 404s the roster today is a
	// half-upgraded host, and it starts answering the moment its own update
	// lands, with no advisord restart. So it keeps asking, quietly, the
	// log line above is written once at boot and never on a tick, because a
	// line every 45 seconds on a box that is working reads as a fault.
	t := time.NewTicker(rosterRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshRoster(ctx)
		}
	}
}
