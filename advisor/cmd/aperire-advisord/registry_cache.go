package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/runbook"
)

// The registry, taken off the request path — the second validator1 finding
// of 2026-08-28.
//
// A cold /v1/check paid for Docker Hub inline: the anonymous token, the
// tags list when the latest-release cache had lapsed, and a manifest HEAD
// for ImagePublished on every single readiness evaluation, uncached. Each
// call is bounded only by the client's 15-second timeout, and on a host
// whose IPv6 path to the Hub stalls mid-connection that bound is the cost:
// checks measured at 34.7s and 70.4s, experienced as minutes of "Checking
// this node's Advisor" while panels with no registry dependency answered
// instantly. An strace of one check showed a single 443 connection holding
// the whole window open.
//
// A monitoring page must not have a WAN dependency in its refresh loop.
// What the registry answers changes on the scale of releases — days — so
// the answers are cached on the server and kept warm by a background
// refresher, and a request that does have to ask (a target nobody has
// asked about before) asks under a short deadline instead of the client's
// generous one. Fails exactly as the uncached path failed: an unreachable
// registry still reads as "not proven pullable", never as published.
const (
	// registryProbeTimeout bounds the one inline fetch a never-seen target
	// may cost. Five seconds is enough for a healthy path to the Hub and
	// short enough that a stalled IPv6 connection cannot hold a page load.
	registryProbeTimeout = 5 * time.Second
	// publishedOkTTL is how long "this tag exists" is believed. A published
	// image does not unpublish; ten minutes only bounds how long a deleted
	// tag could still read as pullable.
	publishedOkTTL = 10 * time.Minute
	// publishedErrTTL is how long a FAILED reading is held before the
	// registry is asked again. Long enough that a down registry does not
	// stall every check; short enough that recovery is noticed.
	publishedErrTTL = time.Minute
	// registryRefreshEvery is the background cadence that keeps the latest
	// release and its published answer warm, so the inline path above is
	// the exception, not the rule.
	registryRefreshEvery = 4 * time.Minute
)

type publishedEntry struct {
	ok     bool
	detail string
	at     time.Time
}

type registryCache struct {
	mu  sync.Mutex
	pub map[string]publishedEntry
	// Test seams; zero values mean the constants above.
	okTTL, errTTL time.Duration
}

func (c *registryCache) get(version string) (publishedEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.pub[version]
	if !ok {
		return publishedEntry{}, false
	}
	ttl := c.okTTL
	if ttl == 0 {
		ttl = publishedOkTTL
	}
	if !e.ok {
		if c.errTTL != 0 {
			ttl = c.errTTL
		} else {
			ttl = publishedErrTTL
		}
	}
	if time.Since(e.at) >= ttl {
		return publishedEntry{}, false
	}
	return e, true
}

func (c *registryCache) put(version string, ok bool, detail string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pub == nil {
		c.pub = map[string]publishedEntry{}
	}
	c.pub[version] = publishedEntry{ok: ok, detail: detail, at: time.Now()}
}

// readinessHost is what evaluateReadiness hands the preconditions: the
// State, with the one WAN-touching read answered from the server's cache.
// Everything else — ProfileMatches and its deliberate fresh re-read
// included — passes straight through to the State.
type readinessHost struct {
	*host.State
	srv *server
}

func (h readinessHost) ImagePublished(version string) (bool, string) {
	// The image on this host is asked every time, never cached (#1015). On
	// a lab validator (17bc, 2026-10-11) localhost/xrpld:3.4.1 was removed at
	// 23:15:11 and /v1/check evaluated at 23:17:05 still read "3.4.1 is
	// already on this host": this whole answer, local branch included, sat in
	// the release cache for ten minutes. The local read is one wrapper call
	// and needs no network, and it is the half an operator changes. The
	// release half below is somebody else's service and stays cached.
	//
	// It says when it was read, so a /v1/check body served from the check
	// cache shows the age of this row on the row itself.
	//
	// The miss says so too, with its time (#1012 review, L5): after a
	// removal the answer is the release half, and without this the row gave
	// no sign of when the host was last looked at.
	local := ""
	if h.State.Kind() != "native" {
		ok, d := h.State.ImageLocal(version)
		read := ", read " + time.Now().UTC().Format("15:04:05") + " UTC"
		if ok {
			return true, d + read
		}
		local = "; on this host: " + d + read
	}
	if e, ok := h.srv.regCache.get(version); ok {
		return e.ok, e.detail + local
	}
	// A target nobody has asked about. Ask once, under the short deadline,
	// on a State of our own so the request's generous context does not
	// stretch the probe.
	//
	// The probe carries the privilege wrapper: on a native host the release
	// answer is the wrapper's package-available verb, and a State built
	// without it answers "no privilege wrapper is configured" every time.
	ctx, cancel := context.WithTimeout(context.Background(), registryProbeTimeout)
	defer cancel()
	probe := host.New(ctx, h.State.Profile, h.State.Runner, h.State.HTTP)
	probe.Wrapper = h.State.Wrapper
	ok, detail := probe.ImageReleased(version)
	h.srv.regCache.put(version, ok, detail)
	return ok, detail + local
}

// OfficialDigestPublished is the rollback's registry read (#984), taken off
// the request path the way ImagePublished is: cached under the version and
// the digest together, and asked inline only once, under the short deadline.
// A failed reading is held for the shorter TTL and still refuses.
func (h readinessHost) OfficialDigestPublished(version, digest string) (bool, string) {
	key := "official-digest:" + version + "@" + digest
	if e, ok := h.srv.regCache.get(key); ok {
		return e.ok, e.detail
	}
	ctx, cancel := context.WithTimeout(context.Background(), registryProbeTimeout)
	defer cancel()
	probe := host.New(ctx, h.State.Profile, h.State.Runner, h.State.HTTP)
	probe.Wrapper = h.State.Wrapper
	probe.LedgerPath = h.State.LedgerPath
	ok, detail := probe.OfficialDigestPublished(version, digest)
	h.srv.regCache.put(key, ok, detail)
	return ok, detail
}

// FarFromRotation is the State's, with the rotation reading taken from the
// server's cache rather than read again: see rotationForVerdict.
func (h readinessHost) FarFromRotation(need time.Duration) runbook.Measurement {
	return h.State.FarFromRotationWith(need, func() (string, string, error) {
		return h.srv.rotationForVerdict(h.State)
	})
}

func (s *server) readinessHost(st *host.State) runbook.HostState {
	return readinessHost{State: st, srv: s}
}

// refreshRegistry keeps the answers the panel needs warm: which release is
// latest, and whether it is pullable. Runs once at start and then on the
// cadence above, so a page load finds the answers already on the shelf.
func (s *server) refreshRegistry(ctx context.Context) {
	profile, st, err := s.state(ctx)
	if err != nil {
		log.Printf("[registry] skipping a refresh, the host could not be read: %v", err)
		return
	}
	_ = profile
	latest, err := s.latestRelease(st)
	if err != nil {
		log.Printf("[registry] skipping a refresh, the latest release could not be resolved: %v", err)
		return
	}
	// Through the same cached path the preconditions read, so this warm
	// call and a request's call can never disagree about what was asked.
	s.readinessHost(st).ImagePublished(latest.Version)
	// And where that release's image would come from (#682), on the same
	// shelf the ceremony paths read and never refresh for themselves. Kept
	// warm here for the same reason the two above are, plus one of its own:
	// a cutover run as its own request after a long prepare would otherwise
	// find the shelf lapsed, compute a fingerprint with no digest in it, and
	// be refused after the operator had already approved. Nothing is asked
	// of the registry on a native host; UpgradeSource answers that from the
	// deployment kind before any request is made.
	s.upgradeSource(st, latest.Version)
}

// noLocalNode reports whether this host has no node of its own BY DESIGN,
// rather than a node that could not be read.
//
// The aggregator is the case: it watches other nodes and runs none itself, so
// it is installed with --container=none and has no docker binary at all. That
// is a healthy configuration, not a fault, and the two must not look alike. A
// node host whose docker is genuinely broken still reports the failure
// honestly, because its container is a real name and this returns false.
//
// Empty is included defensively. main.go resolves an empty --container to the
// wrapper's SERVICE or "rippledvalidator" before the server is built, so it
// cannot be empty in production; a server constructed directly (a test) can.
func (s *server) noLocalNode() bool {
	c := strings.TrimSpace(s.container)
	return c == "" || c == "none"
}

func (s *server) registryRefreshLoop(ctx context.Context) {
	// #120. On the aggregator this loop asked for the host every four minutes
	// forever, and every four minutes logged that it could not read it:
	//
	//   [registry] skipping a refresh, the host could not be read:
	//   inspect "none": docker: exec: "docker": executable file not found
	//
	// systemctl status shows the most recent lines, so that was the first
	// thing an operator saw on a completely healthy box, and it reads as a
	// fault. There is nothing to keep warm here: the registry answers are
	// about the image a LOCAL node runs, and this host runs none.
	//
	// Said once, then the goroutine ends rather than idling on a ticker.
	// s.container is set at boot and never reassigned, so nothing this loop
	// could wake up for will change the answer.
	if s.noLocalNode() {
		log.Printf("[registry] no local node on this host; registry refresh idle")
		return
	}
	s.refreshRegistry(ctx)
	t := time.NewTicker(registryRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshRegistry(ctx)
		}
	}
}
