// Package webauthn verifies an assertion against a credential the operator
// enrolled with the Advisor directly.
//
// Why the Advisor verifies at all, when the dashboard already did:
//
// An approval used to be authorised by existing. Anything that could write the
// file, or call /v1/approve with the service token, produced an approval —
// and on a host where both services run as the same user, that is not much of
// a bar. Carrying the assertion into the record and checking it here moves the
// authority from "this file exists" to "a passkey was physically touched".
// Stealing the token no longer helps. Writing the file directly no longer
// helps.
//
// The credential list is enrolled deliberately and read from the Advisor's own
// state, never supplied by the caller. A verifier that accepts the public key
// alongside the signature is checking that the attacker can do arithmetic.
//
// No CBOR dependency: a COSE_Key is a small map with a fixed shape, and the
// two algorithms that matter are ES256 and Ed25519. The reader below handles
// exactly that and refuses anything else, which is a smaller surface than a
// general decoder.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// Assertion is what the browser produced, as the dashboard forwarded it.
type Assertion struct {
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"` // base64url
	ClientDataJSON    string `json:"client_data_json"`   // base64url
	Signature         string `json:"signature"`          // base64url
}

// Credential is an enrolled public key.
//
// User and Role exist so this service can answer "which operator does this
// passkey belong to" from something it holds, instead of taking the
// dashboard's word for it at the moment of an approval. Verification does not
// use either — a signature is checked against PublicKey and nothing else —
// and neither is part of Fingerprint(), because renaming or re-roling a
// person does not change which keys will be accepted and the fingerprint is
// pinned byte-for-byte to the dashboard's mirror of it.
//
// Both are optional. A credential that arrives without them (an older sync,
// or a trust bundle from an aggregator that predates this) is recorded with a
// weaker `verified` on the ledger rather than silently attributed.
type Credential struct {
	ID         string `json:"credential_id"`
	PublicKey  string `json:"public_key"` // base64url COSE_Key
	Label      string `json:"label,omitempty"`
	User       string `json:"user,omitempty"`
	Role       string `json:"role,omitempty"`
	EnrolledAt string `json:"enrolled_at,omitempty"`
}

// Expectations are the things the assertion has to agree with. All of them
// come from the Advisor's own state, never from the request.
type Expectations struct {
	Challenge string   // base64url, as the RP issued it
	Origins   []string // exact match required
	RPIDHash  [32]byte // SHA-256 of the RP ID
}

var b64 = base64.RawURLEncoding

func decode(s string) ([]byte, error) {
	// Browsers emit unpadded base64url; some intermediaries add padding.
	if n := len(s) % 4; n != 0 {
		return base64.URLEncoding.DecodeString(s + "===="[n:])
	}
	return b64.DecodeString(s)
}

// Verify checks the assertion. Every failure is distinct, because "the
// signature is wrong" and "this was signed for a different challenge" call for
// very different responses from whoever reads the refusal.
func Verify(a Assertion, cred Credential, exp Expectations) error {
	if a.CredentialID == "" || a.CredentialID != cred.ID {
		return fmt.Errorf("assertion is for a different credential")
	}
	authData, err := decode(a.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("authenticator data is not base64url: %w", err)
	}
	if len(authData) < 37 {
		return fmt.Errorf("authenticator data is too short to be one")
	}
	clientData, err := decode(a.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("client data is not base64url: %w", err)
	}
	sig, err := decode(a.Signature)
	if err != nil {
		return fmt.Errorf("signature is not base64url: %w", err)
	}

	// 1. The client data must agree about what was signed and where.
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return fmt.Errorf("client data is not JSON: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return fmt.Errorf("client data type is %q, not an assertion", cd.Type)
	}
	if cd.Challenge != exp.Challenge {
		// This is the binding that makes an approval for one plan useless for
		// another: the challenge was derived from the plan.
		return fmt.Errorf("assertion was signed for a different challenge")
	}
	okOrigin := false
	for _, o := range exp.Origins {
		if cd.Origin == o {
			okOrigin = true
			break
		}
	}
	if !okOrigin {
		return fmt.Errorf("assertion came from origin %q, which is not expected", cd.Origin)
	}

	// 2. The authenticator data must be for this RP, with the user verified.
	var rpid [32]byte
	copy(rpid[:], authData[:32])
	if rpid != exp.RPIDHash {
		return fmt.Errorf("assertion is for a different relying party")
	}
	flags := authData[32]
	const flagUserPresent, flagUserVerified = 0x01, 0x04
	if flags&flagUserPresent == 0 {
		return fmt.Errorf("no user was present")
	}
	if flags&flagUserVerified == 0 {
		// The whole point of requiring a biometric or PIN. A touch alone means
		// someone was there, not that it was the operator.
		return fmt.Errorf("the authenticator did not verify the user")
	}

	// 3. The signature covers authenticatorData || SHA-256(clientDataJSON).
	sum := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), sum[:]...)

	raw, err := decode(cred.PublicKey)
	if err != nil {
		return fmt.Errorf("enrolled public key is not base64url: %w", err)
	}
	key, err := parseCOSE(raw)
	if err != nil {
		return fmt.Errorf("enrolled public key: %w", err)
	}

	digest := sha256.Sum256(signed)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return fmt.Errorf("signature does not verify")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signed, sig) {
			return fmt.Errorf("signature does not verify")
		}
	default:
		return fmt.Errorf("unsupported key type")
	}
	return nil
}

// RPIDHash is SHA-256 of the relying party id, which is what the authenticator
// signs rather than the id itself.
func RPIDHash(rpID string) [32]byte { return sha256.Sum256([]byte(rpID)) }

// ── minimal COSE_Key reader ───────────────────────────────────────────
//
// Only what a WebAuthn credential can be: EC2/P-256 with ES256, or OKP with
// Ed25519. Anything else is refused rather than guessed at.

func parseCOSE(b []byte) (any, error) {
	m, err := cborMap(b)
	if err != nil {
		return nil, err
	}
	kty, ok := m[1]
	if !ok {
		return nil, fmt.Errorf("no key type")
	}
	switch toInt(kty) {
	case 2: // EC2
		if toInt(m[3]) != -7 {
			return nil, fmt.Errorf("EC2 key with algorithm %d; only ES256 is supported", toInt(m[3]))
		}
		if toInt(m[-1]) != 1 {
			return nil, fmt.Errorf("EC2 key on a curve other than P-256")
		}
		x, xok := m[-2].([]byte)
		y, yok := m[-3].([]byte)
		if !xok || !yok || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("EC2 key coordinates are malformed")
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	case 1: // OKP
		if toInt(m[3]) != -8 {
			return nil, fmt.Errorf("OKP key with algorithm %d; only EdDSA is supported", toInt(m[3]))
		}
		x, ok := m[-2].([]byte)
		if !ok || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("OKP key is malformed")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("unsupported key type %d", toInt(kty))
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	}
	return 0
}

// cborMap decodes exactly the subset a COSE_Key uses: a definite-length map
// with integer keys and integer or byte-string values.
func cborMap(b []byte) (map[int64]any, error) {
	p := &reader{b: b}
	major, n, err := p.head()
	if err != nil {
		return nil, err
	}
	if major != 5 {
		return nil, fmt.Errorf("COSE key is not a map")
	}
	out := map[int64]any{}
	for i := uint64(0); i < n; i++ {
		k, err := p.value()
		if err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out[toInt(k)] = v
	}
	return out, nil
}

type reader struct {
	b []byte
	i int
}

func (r *reader) head() (major byte, n uint64, err error) {
	if r.i >= len(r.b) {
		return 0, 0, fmt.Errorf("truncated")
	}
	c := r.b[r.i]
	r.i++
	major = c >> 5
	ai := c & 0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		if r.i+1 > len(r.b) {
			return 0, 0, fmt.Errorf("truncated")
		}
		n = uint64(r.b[r.i])
		r.i++
	case ai == 25:
		if r.i+2 > len(r.b) {
			return 0, 0, fmt.Errorf("truncated")
		}
		n = uint64(r.b[r.i])<<8 | uint64(r.b[r.i+1])
		r.i += 2
	case ai == 26:
		if r.i+4 > len(r.b) {
			return 0, 0, fmt.Errorf("truncated")
		}
		for k := 0; k < 4; k++ {
			n = n<<8 | uint64(r.b[r.i+k])
		}
		r.i += 4
	default:
		return 0, 0, fmt.Errorf("unsupported CBOR length encoding")
	}
	return major, n, nil
}

func (r *reader) value() (any, error) {
	major, n, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return int64(n), nil
	case 1:
		return -1 - int64(n), nil
	case 2:
		if r.i+int(n) > len(r.b) {
			return nil, fmt.Errorf("truncated byte string")
		}
		v := r.b[r.i : r.i+int(n)]
		r.i += int(n)
		return v, nil
	case 3:
		if r.i+int(n) > len(r.b) {
			return nil, fmt.Errorf("truncated text string")
		}
		v := string(r.b[r.i : r.i+int(n)])
		r.i += int(n)
		return v, nil
	}
	return nil, fmt.Errorf("unsupported CBOR major type %d in a COSE key", major)
}
