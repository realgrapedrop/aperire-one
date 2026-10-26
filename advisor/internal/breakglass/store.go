package breakglass

import (
	"sync"
	"time"
)

// Store holds at most a handful of windows in memory — like NonceStore and
// the ask/investigate turn ring, restart-volatile by design. "An advisord
// restart closes the window" (§11.3a: "glass re-seals when the service
// restarts") falls out of this for free: a fresh process starts a fresh,
// empty Store, so a window that existed before the restart simply is not
// there to be found.
//
// What did NOT fall out for free is anyone knowing it happened. A restart
// left no close entry and told the operator nothing: their window vanished
// mid-investigation and the next question ran ungated (validator1,
// 2026-08-21, issue #40). Fail-closed on restart is right and stays; silent
// was the bug. The record is repaired on the way back up, by a boot scan that
// reads the ledger for windows opened and never closed — this Store cannot
// help with that, because the whole point is that it is empty.
type Store struct {
	mu sync.Mutex
	// onClose is handed to every window this Store opens, so that a window
	// closing on ANY path — a poll's lazy Touch, a question that crossed a
	// bound, the operator's Close — is recorded once, at the moment it
	// happens. See Window.onClose for the contract it must honour.
	onClose func(*Window, time.Time)
	byNode  map[string]*Window // at most one open window per node at a time
	windows map[string]*Window // by window id, for lookups that already have it
}

func NewStore() *Store {
	return &Store{byNode: map[string]*Window{}, windows: map[string]*Window{}}
}

// SetOnClose installs the close notice for every window opened from here on.
// Called once at boot, before the listener starts.
func (s *Store) SetOnClose(fn func(*Window, time.Time)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onClose = fn
}

// Open records a freshly-opened window, replacing any prior one for the
// same node (there should never be one — StartQuestion callers check
// OpenForNode first — but a Store that could silently hold two live
// windows for one node would make "no offer while a window is open"
// (§11.4 condition 6) unenforceable).
func (s *Store) Open(w *Window) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.SetOnClose(s.onClose)
	s.byNode[w.Node] = w
	s.windows[w.ID] = w
}

// OpenForNode returns the currently open window for a node, if its bounds
// have not already been exhausted as of now — Touch is applied first, so a
// window that has quietly expired since it was last touched is treated as
// closed here rather than reported open. Returns (nil, false) if there is
// none, or it is closed.
func (s *Store) OpenForNode(node string, now time.Time) (*Window, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.byNode[node]
	if !ok {
		return nil, false
	}
	w.Touch(now)
	if w.Closed {
		return nil, false
	}
	return w, true
}

// ByID returns a window regardless of open/closed state — the close
// endpoint and the status/progress pollers need to see a just-closed
// window long enough to render its final chip state, not have it vanish
// the instant it closes.
func (s *Store) ByID(id string) (*Window, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[id]
	return w, ok
}

// Touch re-checks the named window's bounds without starting or ending a
// question — the read side of the "checked once, when a gated question
// begins" rule (§11.3a) plus the poll-driven lazy close Window.Touch
// documents.
func (s *Store) Touch(id string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.windows[id]; ok {
		w.Touch(now)
	}
}
