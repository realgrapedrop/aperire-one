package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"aperire-advisor/internal/interrogate"
)

// offerTTL is the approval's own 5-minute use-it-or-lose-it clock plus the
// gated tier's own 600s session ceiling (plan-interrogative-loop §11.9) —
// long enough that an operator who takes the full five minutes to touch
// their passkey, then runs the longest possible gated session, never finds
// the offer's transcript aged out from under them. Past this an offer
// resume is refused by name ("that investigation offer has expired; ask
// the question again"), never silently restarted cold.
const offerTTL = 5*time.Minute + 600*time.Second

// maxOffers bounds the store the same way progressStore bounds itself —
// a handful of concurrent operators, not an unbounded map.
const maxOffers = 32

// offerRecord is everything an accepted offer needs to resume the
// conversation that produced it, "in the same in-memory ring as the
// progress" the architecture calls for (§11.9) — restart-volatile, TTL-
// swept, exactly like progressStore and approval.NonceStore.
type offerRecord struct {
	Node     string
	Question string // the trigger — what InvestigationFingerprint's trigger_sha256 names
	Messages []interrogate.Message
	Why      string
	// WouldRead is already resolved to the service's own labels — nothing
	// downstream re-resolves it.
	WouldRead []string
	createdAt time.Time
}

type offerStore struct {
	mu      sync.Mutex
	entries map[string]*offerRecord
}

func newOfferStore() *offerStore { return &offerStore{entries: map[string]*offerRecord{}} }

// mintOfferID is a fresh, unguessable identifier the SERVICE chooses — never
// the page, never derived from the question — because §11.3's fingerprint
// binds to whichever offer_id opened the window, and an offer_id a caller
// could choose would let two different browsers collide on one investigation
// or let a captured id be replayed against a different offer.
func mintOfferID() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "off_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *offerStore) put(id string, rec *offerRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if _, exists := s.entries[id]; !exists && len(s.entries) >= maxOffers {
		s.evictOldestLocked()
	}
	rec.createdAt = time.Now()
	s.entries[id] = rec
}

// get returns the record if it exists and has not aged out. A caller that
// gets ok == false must refuse with the named reason (§11.9) rather than
// silently starting a fresh, shorter-context session.
func (s *offerStore) get(id string) (*offerRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	r, ok := s.entries[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

func (s *offerStore) sweepLocked() {
	cutoff := time.Now().Add(-offerTTL)
	for id, r := range s.entries {
		if r.createdAt.Before(cutoff) {
			delete(s.entries, id)
		}
	}
}

func (s *offerStore) evictOldestLocked() {
	var oldestID string
	var oldestAt time.Time
	for id, r := range s.entries {
		if oldestID == "" || r.createdAt.Before(oldestAt) {
			oldestID, oldestAt = id, r.createdAt
		}
	}
	if oldestID != "" {
		delete(s.entries, oldestID)
	}
}
