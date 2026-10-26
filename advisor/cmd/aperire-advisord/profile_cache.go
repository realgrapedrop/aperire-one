package main

import (
	"context"
	"sync"
	"time"

	"aperire-advisor/internal/host"
)

// The profile read, cached — the validator1 finding of 2026-08-28.
//
// Every request that needs to know which container this service tends paid a
// fresh DiscoverProfile, and DiscoverProfile is a wrapper exec: sudo, the
// wrapper, `docker inspect`. On a loopback-fast host that is ~100ms and
// invisible. On validator1 it measured ~1 second, and requests arrive
// constantly — the dashboard's status probe, the operator's open tab polling
// through the aggregator — so the box ran a steady one-per-second inspect
// queue (29 in a 28s journal window) and every /v1/check joined the back of
// it: 34.7s measured for one cold check, which the operator experienced as
// minutes of "Checking this node's Advisor" over a panel whose neighbours
// answered instantly.
//
// What the read returns is deployment IDENTITY: the container's name, image,
// compose labels, mounts. It changes when the deployment changes — an
// upgrade's recreate, an operator editing the compose file — and at no other
// time. Twenty seconds of reuse is invisible against that rate of change,
// and the one reader that must never reuse it does not come through here:
// ProfileMatches (ADR 0005, "checked before every plan rather than trusted
// from setup") calls DiscoverProfile itself on the State's own runner, so a
// plan's gate still re-reads the deployment fresh every time.
//
// Same shape as rotationCache, for the same reasons: the mutex is held
// across the exec so a burst of callers coalesces into ONE read, and an
// error is cached like an answer because an erroring inspect polled at full
// rate is the same storm.
const profileReadTTL = 20 * time.Second

type profileCache struct {
	mu  sync.Mutex
	at  time.Time
	ttl time.Duration
	p   host.Profile
	err error
}

func (c *profileCache) read(fetch func() (host.Profile, error)) (host.Profile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.ttl
	if ttl == 0 {
		ttl = profileReadTTL
	}
	if !c.at.IsZero() && time.Since(c.at) < ttl {
		return c.p, c.err
	}
	c.p, c.err = fetch()
	c.at = time.Now()
	return c.p, c.err
}

// reset forgets the cached profile. Called from cacheReset, which runs when
// an act has just changed what the host looks like — the one moment a
// twenty-second-old deployment identity could actually be wrong.
func (c *profileCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = time.Time{}
}

// discoverProfileCached is what s.state and s.profile read. Startup discovery
// and ProfileMatches stay on the fresh read: the first because it runs once
// before anything is cached, the second by construction (see above).
func (s *server) discoverProfileCached(ctx context.Context) (host.Profile, error) {
	return s.profCache.read(func() (host.Profile, error) {
		return host.DiscoverProfile(ctx, s.runner, s.container, s.adminRPC)
	})
}
