package main

import (
	"errors"
	"sync"

	"aperire-advisor/internal/ledger"
)

// The ledger route's memory of the chain point it last verified, ADR 0021
// build step 1.
//
// GET /v1/ledger used to re-verify the whole file on every call: 728
// entries recomputing 728 SHA-256 hashes, on every 30s poll of every open
// tab, and it only grows. This cache is what lets a request that finds
// nothing new hash nothing at all: it holds no entries, only a position
// (how many the file had, and the hash of the last one), and
// ledger.EntriesSince re-verifies forward from THAT position regardless of
// what since_seq a caller asks for. since_seq controls only what comes back
// in the answer; this controls what gets re-hashed.
//
// One instance per server. This daemon watches one node and therefore one
// ledger file, so a single mutex-guarded point is enough, no map, no path
// as a key.
type ledgerHeadCache struct {
	mu    sync.Mutex
	point ledger.ChainPoint
	// set is false for a server that has never read the ledger yet, or one
	// whose trusted point was just reset. A false set means "verify the
	// whole file", which is exactly what the zero ChainPoint asks
	// EntriesSince to do.
	set bool
}

func (c *ledgerHeadCache) trusted() ledger.ChainPoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set {
		return ledger.ChainPoint{}
	}
	return c.point
}

func (c *ledgerHeadCache) store(count int, head string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.point = ledger.ChainPoint{Seq: count, Hash: head}
	c.set = true
}

// reset drops what was trusted. Called whenever a read proves the file no
// longer agrees with it, a genuine chain break, reported to the caller as
// such, so the NEXT request re-verifies from the start rather than
// trusting a point a read just showed was wrong.
func (c *ledgerHeadCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.point = ledger.ChainPoint{}
	c.set = false
}

// tail answers one incremental ledger read: entries after `since`, verified
// from whatever this cache currently trusts. A trusted point the file no
// longer matches (ledger.ErrCachedPointStale, a reinstalled node's fresh
// chain, or a wipe) is not an error a caller sees: it falls back to
// verifying the whole file, exactly as a first read would, and reseeds the
// cache from that.
func (c *ledgerHeadCache) tail(path string, since int) (tail []ledger.Entry, count int, head string, err error) {
	tail, count, head, err = ledger.EntriesSince(path, c.trusted(), since)
	if err == nil {
		c.store(count, head)
		return tail, count, head, nil
	}
	if !errors.Is(err, ledger.ErrCachedPointStale) {
		// A genuine chain break. What was trusted is worth nothing now,
		// the next request must not build forward from a point a read
		// just proved wrong.
		c.reset()
		return nil, 0, "", err
	}
	full, count2, head2, err2 := ledger.EntriesSince(path, ledger.ChainPoint{}, since)
	if err2 != nil {
		c.reset()
		return nil, 0, "", err2
	}
	c.store(count2, head2)
	return full, count2, head2, nil
}
