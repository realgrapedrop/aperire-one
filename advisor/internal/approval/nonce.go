package approval

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Nonces are the challenges the Advisor issues for the passkey ceremony, and
// they exist because of what went wrong without them.
//
// The dashboard runs the ceremony: it generates a challenge, asks the browser
// to sign it, verifies the result, and tells the Advisor what was approved.
// The Advisor verifies the assertion again, against credentials it holds
// itself — that second check is what stops a stolen service token from forging
// an approval. But it was checking a challenge the dashboard had chosen, and
// that challenge committed to nothing. It named no plan and no stage.
//
// So a captured "I approve prepare" could be resubmitted as "I approve the
// cutover" and it verified: same signature, same challenge, different word in
// a field nobody had signed. Prepare is reversible and takes nothing offline.
// The cutover restarts a validator. That distinction is the entire reason
// there are two stages.
//
// A nonce issued HERE fixes both halves. It binds the operator's signature to
// one plan and one stage, and it makes the Advisor's verification genuinely
// independent — it is now checking its own challenge rather than re-checking
// somebody else's. Single use, short lived, and burned even on a failed
// attempt, because a nonce that survives a bad try is a nonce an attacker may
// keep guessing against.
type Nonce struct {
	Value       string    `json:"value"`
	Fingerprint string    `json:"fingerprint"`
	Stage       string    `json:"stage"`
	Expires     time.Time `json:"expires"`
}

var (
	ErrNoNonce      = errors.New("this approval carries no challenge issued by the Advisor")
	ErrUnknownNonce = errors.New("challenge was never issued, has already been used, or has expired")
	ErrNonceStage   = errors.New("challenge was issued for a different stage")
	ErrNoncePlan    = errors.New("challenge was issued for a different plan")
)

// NonceStore is in memory on purpose. A ceremony lasts seconds, and an
// advisord restart mid-ceremony should invalidate what was outstanding rather
// than survive it — failing closed here costs one retry and nothing else.
type NonceStore struct {
	mu sync.Mutex
	n  map[string]Nonce
}

func NewNonceStore() *NonceStore { return &NonceStore{n: map[string]Nonce{}} }

// Issue mints a challenge bound to one plan and one stage.
func (s *NonceStore) Issue(fingerprint, stage string, ttl time.Duration) (Nonce, error) {
	if fingerprint == "" || stage == "" {
		return Nonce{}, fmt.Errorf("a challenge must name a plan and a stage")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Nonce{}, err
	}
	// base64url, unpadded — the exact shape WebAuthn challenges travel in, so
	// the value the browser signs is the value stored here, byte for byte.
	v := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, old := range s.n { // opportunistic prune; the map stays tiny
		if now.After(old.Expires) {
			delete(s.n, k)
		}
	}
	nn := Nonce{Value: v, Fingerprint: fingerprint, Stage: stage, Expires: now.Add(ttl)}
	s.n[v] = nn
	return nn, nil
}

// Consume spends a challenge, and spends it exactly once. A value that is
// present is always removed, including when it fails the plan or stage check —
// a mismatch is the attack this exists to stop, and leaving it usable would
// invite the next attempt.
func (s *NonceStore) Consume(value, fingerprint, stage string) error {
	if value == "" {
		return ErrNoNonce
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nn, ok := s.n[value]
	if !ok {
		return ErrUnknownNonce
	}
	delete(s.n, value)
	if time.Now().After(nn.Expires) {
		return ErrUnknownNonce
	}
	if nn.Fingerprint != fingerprint {
		return ErrNoncePlan
	}
	if nn.Stage != stage {
		return ErrNonceStage
	}
	return nil
}

// Outstanding is for diagnostics only.
func (s *NonceStore) Outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.n)
}
