package host

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"aperire-advisor/internal/webauthn"
)

// Trust-bundle install — ADR 0014 decision 4. The aggregator publishes a
// signed bundle of its admin passkeys (public keys only) and pushes it to
// each node's advisord over the existing forward. The node verifies the
// signature against the aggregator's public key it already holds, applies
// the credential set, and — the security crux — PINS rp_id + origins on the
// first accept and refuses any later bundle that changes them. That pin is
// what stops a compromised aggregator from redirecting a node's notion of
// which origin may approve, which is otherwise the cheapest attack here.
//
// This file is pure policy + crypto: no I/O, no server, no YAML. The wiring
// (reading the aggregator key from fleet-trust.yaml, the POST handler, the
// ledger write, the two-token gate) lives in the server; every rule that
// decides whether a bundle is ACCEPTED lives here, where it is unit-tested
// against a real Ed25519 keypair and a pin-violation vector.

// Bundle is the wire shape the aggregator signs and pushes. Field names and
// order are load-bearing: SigningBytes() serializes exactly these, and the
// aggregator's builder must produce byte-identical input or the signature
// will not verify. Public keys only — nothing here is secret, the signature
// authenticates the SENDER, not the contents' confidentiality.
type Bundle struct {
	RPID        string       `json:"rp_id"`
	Origins     []string     `json:"origins"`
	Credentials []BundleCred `json:"credentials"`
	Serial      string       `json:"serial"`       // credentialDigest() — the cross-language fingerprint
	IssuedAt    string       `json:"issued_at"`    // RFC3339; informational, NOT part of the pin
	IssuerLabel string       `json:"issuer_label"` // which peers.<label> key verifies this
}

// BundleCred is one credential on the wire.
//
// User and Role are omitempty and that is load-bearing, not tidiness. They
// are INSIDE the signature — a role the wire could rewrite would be worse
// than no role at all — and omitempty is what keeps a bundle built by an
// aggregator that predates them serializing to the exact same bytes it always
// did, so an upgraded node still verifies an older aggregator's push. The
// reverse direction (new aggregator, old node) fails closed with a signature
// error, which is the correct way round for a field that says who may
// approve.
type BundleCred struct {
	CredentialID string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	Label        string `json:"label"`
	User         string `json:"user,omitempty"`
	Role         string `json:"role,omitempty"`
}

// Binding is the pinned half: the first accepted bundle records these, and
// every later bundle must match them exactly. Stored by the server beside
// the credential store; compared here.
type Binding struct {
	RPID    string   `json:"rp_id"`
	Origins []string `json:"origins"`
	// PairedUnder is the id of the node's pairing record (#991) the last
	// accepted bundle was taken under, or empty. CheckBinding never reads
	// it: the pin is rp_id and origins. advisord sets it on accept, and a
	// re-pairing whose record this is not may replace the pin, once.
	PairedUnder string `json:"paired_under,omitempty"`
}

// SigningBytes is the canonical input both sides sign/verify. Deterministic
// by construction: a fixed struct field order via json.Marshal of an
// explicitly-ordered shape, origins and credentials sorted so the two
// languages' natural orderings cannot diverge. The signature covers the
// binding (rp_id, origins) AND the credential set AND the issuer label —
// everything a node acts on. issued_at is included so a captured older
// bundle cannot be replayed as newer; it is NOT part of the pin.
func (b *Bundle) SigningBytes() ([]byte, error) {
	origins := append([]string(nil), b.Origins...)
	sort.Strings(origins)
	creds := append([]BundleCred(nil), b.Credentials...)
	sort.Slice(creds, func(i, j int) bool { return creds[i].CredentialID < creds[j].CredentialID })
	// A hand-ordered map-free shape: json.Marshal of a struct emits fields
	// in declaration order, so this is stable across Go versions and needs
	// no canonical-JSON library. The aggregator builds the identical string.
	ordered := struct {
		RPID        string       `json:"rp_id"`
		Origins     []string     `json:"origins"`
		Credentials []BundleCred `json:"credentials"`
		Serial      string       `json:"serial"`
		IssuedAt    string       `json:"issued_at"`
		IssuerLabel string       `json:"issuer_label"`
	}{b.RPID, origins, creds, b.Serial, b.IssuedAt, b.IssuerLabel}
	// SetEscapeHTML(false) so Go matches JavaScript's JSON.stringify exactly:
	// Go's default escapes <, > and & to \u00xx, JS does not. A device label
	// or any field carrying one of those would otherwise sign to different
	// bytes on the two sides — a signature that never verifies, read as a
	// broken passkey. The aggregator (Node) uses JSON.stringify; this makes
	// the Go twin agree byte-for-byte. Both are pinned to the shared vector
	// in the test beside this file.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ordered); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a trailing newline; the signed message does not
	// include it (JSON.stringify produces none).
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// VerifySignature checks the bundle's detached Ed25519 signature against the
// aggregator's public key. Both key and signature are base64url (no pad),
// matching aperire-fleet-add.sh's key encoding. A failure here is the whole
// gate: an unsigned or wrongly-signed bundle is refused before any pin or
// credential logic runs.
func (b *Bundle) VerifySignature(sigB64URL, pubKeyB64URL string) error {
	pub, err := decodeB64URL(pubKeyB64URL)
	if err != nil {
		return fmt.Errorf("aggregator public key is not valid base64url: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("aggregator public key is %d bytes, expected %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := decodeB64URL(sigB64URL)
	if err != nil {
		return fmt.Errorf("bundle signature is not valid base64url: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bundle signature is %d bytes, expected %d", len(sig), ed25519.SignatureSize)
	}
	msg, err := b.SigningBytes()
	if err != nil {
		return fmt.Errorf("could not serialize bundle for verification: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("bundle signature does not verify against the aggregator's pinned key")
	}
	return nil
}

// CheckBinding enforces the pin. `pinned` is nil on a host that has never
// accepted a bundle (first install); non-nil thereafter. On first install
// it returns the binding to record. On every later install it REFUSES any
// change to rp_id or origins, accepting only credential-set changes — the
// property that makes a pushed bundle safe against a compromised aggregator
// redirecting which origin may approve.
func (b *Bundle) CheckBinding(pinned *Binding) (record *Binding, err error) {
	incoming := &Binding{RPID: b.RPID, Origins: sortedCopy(b.Origins)}
	if b.RPID == "" || len(b.Origins) == 0 {
		return nil, fmt.Errorf("bundle carries no rp_id or origins to bind to")
	}
	if pinned == nil {
		// First accept IS the migration step (the ADR's named case: every lab
		// node already has a node-local credentials.json from an earlier
		// advisor-sync; the first bundle replaces that binding once and pins).
		return incoming, nil
	}
	if pinned.RPID != incoming.RPID {
		return nil, fmt.Errorf("refused: this node is pinned to rp_id %q; the bundle carries %q. "+
			"Changing a pinned binding is a node-local act by hand, not a pushed change", pinned.RPID, incoming.RPID)
	}
	if !sameStringSet(pinned.Origins, incoming.Origins) {
		return nil, fmt.Errorf("refused: this node is pinned to origins %v; the bundle carries %v. "+
			"Changing a pinned binding is a node-local act by hand, not a pushed change", pinned.Origins, incoming.Origins)
	}
	return pinned, nil // unchanged binding; credential set may still differ
}

// ToStore turns an accepted bundle into the CredentialStore shape advisord
// verifies approvals against. Called only after VerifySignature and
// CheckBinding have both passed.
func (b *Bundle) ToStore() *CredentialStore {
	creds := make([]webauthn.Credential, 0, len(b.Credentials))
	for _, c := range b.Credentials {
		creds = append(creds, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Label:     c.Label,
			User:      c.User,
			Role:      c.Role,
		})
	}
	return &CredentialStore{
		RPID:        b.RPID,
		Origins:     sortedCopy(b.Origins),
		Credentials: creds,
	}
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := sortedCopy(a), sortedCopy(b)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
