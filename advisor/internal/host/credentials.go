package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aperire-advisor/internal/webauthn"
)

// CredentialStore is the Advisor's own list of passkeys allowed to approve.
//
// Separate from the dashboard's store on purpose. If the Advisor fetched the
// public key from whoever presented the approval, or from a service that
// presented it, verification would prove nothing: an attacker who can supply
// the key can supply a signature to match. Enrolment is a deliberate act the
// operator performs and the ledger records.
//
// The expectations live here too — the origins an assertion may come from and
// the relying party it must be for. Those are as load-bearing as the keys: an
// assertion is only meaningful relative to where it was produced, and taking
// that from the request would let a caller name its own origin.
type CredentialStore struct {
	RPID        string                `json:"rp_id"`
	Origins     []string              `json:"origins"`
	Credentials []webauthn.Credential `json:"credentials"`
	UpdatedAt   time.Time             `json:"updated_at"`
	Notes       map[string]string     `json:"notes,omitempty"`
}

// LoadCredentials reads the store. A missing file is not an error: it means
// nothing is enrolled, which is the correct state for a host where the
// operator has not set web approval up.
func LoadCredentials(path string) (*CredentialStore, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &CredentialStore{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s CredentialStore
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// SaveCredentials writes the store at 0640.
func SaveCredentials(path string, s *CredentialStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	s.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o640)
}

// Enroll adds or replaces a credential. Replacing is allowed and recorded —
// re-enrolling the same id with a different key is exactly what an attacker
// would do, so it must be visible rather than silent.
func (s *CredentialStore) Enroll(c webauthn.Credential) (replaced bool) {
	c.EnrolledAt = time.Now().UTC().Format(time.RFC3339)
	for i := range s.Credentials {
		if s.Credentials[i].ID == c.ID {
			s.Credentials[i] = c
			return true
		}
	}
	s.Credentials = append(s.Credentials, c)
	return false
}

// Remove drops a credential by id.
func (s *CredentialStore) Remove(id string) bool {
	for i := range s.Credentials {
		if s.Credentials[i].ID == id {
			s.Credentials = append(s.Credentials[:i], s.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// ErrNotEnrolled marks the one verification failure that is not about the
// passkey at all: this node's replica of "who may approve" does not carry the
// credential being presented. Every other failure in Verify is a real
// cryptographic refusal; this one usually means the trust bundle never
// reached this host, or reached it before the operator enrolled.
//
// It is a sentinel rather than a string match because the remedy has to be
// attached where the node's own label is known — the HTTP handlers — and this
// file is pure policy with no idea what the node is called. errors.Is is what
// lets the handler recognise it without parsing prose.
var ErrNotEnrolled = errors.New("the passkey presented is not enrolled with the Advisor on this node")

// Verify implements approval.Verifier.
//
// Everything it checks against comes from this store: the key, the origins,
// the relying party. The only thing taken from the caller is the assertion
// itself and the challenge it claims to have signed — and the challenge is
// read from the approval record the Advisor wrote, not from the request.
func (s *CredentialStore) Verify(a webauthn.Assertion, challenge string) error {
	if len(s.Credentials) == 0 {
		return fmt.Errorf("%w — no passkey is enrolled here at all", ErrNotEnrolled)
	}
	if s.RPID == "" || len(s.Origins) == 0 {
		return fmt.Errorf("the credential store records no relying party or origin to check against")
	}
	if challenge == "" {
		return fmt.Errorf("the approval records no challenge")
	}
	var cred webauthn.Credential
	found := false
	for _, c := range s.Credentials {
		if c.ID == a.CredentialID {
			cred, found = c, true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w (credential %s)", ErrNotEnrolled, abbrev(a.CredentialID))
	}
	return webauthn.Verify(a, cred, webauthn.Expectations{
		Challenge: challenge,
		Origins:   s.Origins,
		RPIDHash:  webauthn.RPIDHash(s.RPID),
	})
}

func abbrev(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// Describe is a one-line summary for the operator.
func (s *CredentialStore) Describe() string {
	if len(s.Credentials) == 0 {
		return "no passkey enrolled — web approval is unavailable"
	}
	ids := make([]string, 0, len(s.Credentials))
	for _, c := range s.Credentials {
		label := c.Label
		if label == "" {
			label = abbrev(c.ID)
		}
		ids = append(ids, label)
	}
	return fmt.Sprintf("%d enrolled (%s) for %s", len(s.Credentials), strings.Join(ids, ", "), s.RPID)
}

// Fingerprint is a digest of what this store will actually accept: the
// credential ids and public keys, sorted so the value depends on the set and
// not on file order.
//
// It exists so a second party can notice disagreement without being handed
// the store. The dashboard is the source of truth for who may approve; this
// service holds a verified replica, and a replica that has silently fallen
// behind is worse than no replica — a passkey enrolled after the last sync
// fails at the moment of approval with an error blaming the passkey, and a
// demoted admin keeps approving until someone remembers to re-run the sync.
// Publishing this lets the dashboard say so plainly instead.
//
// Labels and timestamps are deliberately excluded: renaming a device is not
// a change in who can approve.
func (s *CredentialStore) Fingerprint() string {
	if s == nil || len(s.Credentials) == 0 {
		return "empty"
	}
	// Each field is hex-encoded before joining. Concatenating the raw values
	// around a ":" and "\n" looks fine and is not: a public key holding those
	// two characters makes one row hash identically to two real ones, so a
	// store with an extra key can be made to match a store without it —
	// exactly the drift this is here to catch. Hex output is [0-9a-f] only, so
	// no value can contain a delimiter and the encoding stays unambiguous.
	//
	// Both sides of the comparison must agree byte for byte; the dashboard's
	// trustFingerprint() in auth.ts is the mirror of this and changes with it.
	rows := make([]string, 0, len(s.Credentials))
	for _, c := range s.Credentials {
		rows = append(rows, hex.EncodeToString([]byte(c.ID))+":"+
			hex.EncodeToString([]byte(c.PublicKey)))
	}
	// Sorted because the two stores are built from different databases with
	// different natural orderings, and row order says nothing about trust.
	sort.Strings(rows)
	sum := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(sum[:])
}
