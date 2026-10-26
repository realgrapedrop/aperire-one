package main

import (
	"context"
	"sync"
	"time"

	"aperire-advisor/internal/dashread"
)

// The concern-card history reads, cached — #119, and the third instance of
// the disease rotationCache and profileCache already carry.
//
// baseContext assembles four concern cards for every question, and each card
// takes History(metric, "30d", "avg") from the dashboard's read API. On the
// dashboard side that is a 30-day aggregation over roughly 2.6M metric rows,
// on a single-threaded event loop, measured on node1 at up to ~600ms each.
// node1 has 13 live clients against one on its siblings, so it was paying
// that four times per question with nothing between the questions and the
// SQL. The box burst to 100% CPU for about a second every five, HTTP stalled
// behind it, the aggregator's peer proxy timed out at 504, and the operator
// was told the request did not reach the Advisor.
//
// Five minutes against a 4h bucket. A 30d range buckets at 14400s, so the
// newest bucket is filled over four hours and five minutes of reuse is one
// forty-eighth of one bucket. The card reports a 30-day trend and a change
// point dated to the day; neither can move meaningfully inside that. Both
// existing caches justify their TTL against the rate of change of the thing
// measured rather than against a feeling about staleness, and this is the
// same argument with more headroom.
//
// Same shape as rotationCache and profileCache, deliberately: the mutex is
// held across the fetch so a burst of callers coalesces into ONE read with
// the rest waiting on its answer, which is the single-flight half. The
// difference is that this one is keyed, because there are four cards rather
// than one host fact.
const historyReadTTL = 5 * time.Minute

// An error is cached too, and briefly. An erroring read surface polled at
// full ask rate is the same storm this exists to stop, but a five-minute
// error would keep saying "no measurements are available" for five minutes
// after the dashboard came back. Fifteen seconds is long enough to absorb a
// burst and short enough that recovery is not something the operator waits
// out.
const historyErrTTL = 15 * time.Second

type historyEntry struct {
	at  time.Time
	pts []dashread.HistoryPoint
	err error
}

type historyCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	errTTL time.Duration
	m      map[string]historyEntry
}

// read answers from the cache when the entry is fresh, and takes the one read
// for everyone otherwise. Keyed per metric + range + agg: the four cards are
// four different questions and must not share an answer.
func (c *historyCache) read(key string, fetch func() ([]dashread.HistoryPoint, error)) ([]dashread.HistoryPoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl, errTTL := c.ttl, c.errTTL
	if ttl == 0 {
		ttl = historyReadTTL
	}
	if errTTL == 0 {
		errTTL = historyErrTTL
	}
	if e, ok := c.m[key]; ok && !e.at.IsZero() {
		live := ttl
		if e.err != nil {
			live = errTTL
		}
		if time.Since(e.at) < live {
			return e.pts, e.err
		}
	}
	pts, err := fetch()
	if c.m == nil {
		c.m = map[string]historyEntry{}
	}
	c.m[key] = historyEntry{at: time.Now(), pts: pts, err: err}
	return pts, err
}

// reset forgets every cached series. Called from cacheReset alongside the
// profile cache, for the same reason: an act has just changed the node, and
// the next question should read what it did rather than what preceded it.
func (c *historyCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = nil
}

// assembleMetricsCached is what baseContext calls. Recent() is deliberately
// NOT cached: it is an indexed LIMIT 5 measured under 20ms for all four
// cards together, and it is the half that carries "now", which is the number
// an operator would notice going stale.
func (s *server) assembleMetricsCached(ctx context.Context) ([]dashread.Summary, error) {
	return dashread.AssembleMetricsWith(ctx, s.dashRead,
		func(ctx context.Context, metric, rng, agg string) ([]dashread.HistoryPoint, error) {
			return s.histCache.read(metric+"|"+rng+"|"+agg, func() ([]dashread.HistoryPoint, error) {
				return s.dashRead.History(ctx, metric, rng, agg)
			})
		})
}
