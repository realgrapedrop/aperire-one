// Package fleetrecord is the one shape advisord accepts as an append from the
// aggregator that manages this node (#455).
//
// Everything else in the ledger is written by this service about something it
// did or observed. These two kinds are the exception the record could not do
// without: an act the DASHBOARD performs ON a node rather than through it. A
// link revoked and a pinned node key replaced both happen at the aggregator,
// under a passkey, and the node they are about is the one place an operator
// looks for what has been done to it. Without this surface the Advisor tab's
// ledger card shows a trust set that changed and never says what changed it.
//
// Three rules keep an append surface from becoming a way to write history:
//
//   - The KIND is closed. A record naming anything but the two kinds below is
//     refused by name, and nothing in this package can express a third.
//   - The SUMMARY is never on the wire. advisord composes the sentence from
//     the kind and the fields, so a caller cannot put words in the ledger's
//     mouth. There is no free-form member here, and adding one would undo the
//     whole point.
//   - The FIELDS are per-kind. A revoke that carries a repin's keys is
//     malformed rather than tolerated: an entry whose shape is not the shape
//     of the act it names is not a record of that act.
//
// The signature is the same scheme every other fleet write to advisord uses,
// and deliberately not a new one: a detached Ed25519 signature over canonical
// bytes, verified against the aggregator's public key this node already holds
// in fleet-trust.yaml under peers.<issuer_label>, exactly as internal/host's
// trust bundle and internal/knowledge's manifest are verified. The bearer
// gate at the door is the service token, as on every advisord write.
//
// This file is pure policy plus crypto: no I/O, no server, no ledger. The
// wiring (the token, the key lookup, the replay scan, the append) lives in
// the handler, and every rule that decides whether a record is ACCEPTED lives
// here, where it is unit-tested against a real keypair.
package fleetrecord

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"aperire-advisor/internal/ledger"
)

// Kind is what a record says was done. The set is closed, and this is it.
type Kind string

const (
	// KindLinkRevoked: the aggregator closed this node's link and dropped its
	// registry row. Carries the key that was pinned for it, where one was.
	KindLinkRevoked Kind = "fleet.link_revoked"
	// KindNodeKeyRepinned: an administrator compared the key this node now
	// reports against the one the fleet pinned, and accepted the new one.
	KindNodeKeyRepinned Kind = "fleet.node_key_repinned"
	// KindAdvisorAttached: the aggregator was given this node's own Advisor
	// credential and now reaches its Advisor. Carries the key the fleet pins
	// for this node, which is the key the whole act was addressed to.
	KindAdvisorAttached Kind = "fleet.advisor_attached"
	// KindAdvisorDetached: that reach taken away again. The Advisor on this
	// box is untouched by it, and the summary says so rather than reading as
	// an uninstall.
	KindAdvisorDetached Kind = "fleet.advisor_detached"
)

// LedgerKind is the ledger's own name for a record's kind.
//
// They are the same strings, and this function exists so they stay that way:
// the ledger package declares the closed set an operator reads, and a wire
// kind with no ledger kind cannot be appended at all.
func LedgerKind(k Kind) (ledger.Kind, bool) {
	switch k {
	case KindLinkRevoked:
		return ledger.KindFleetLinkRevoked, true
	case KindNodeKeyRepinned:
		return ledger.KindFleetNodeKeyRepinned, true
	case KindAdvisorAttached:
		return ledger.KindFleetAdvisorAttached, true
	case KindAdvisorDetached:
		return ledger.KindFleetAdvisorDetached, true
	default:
		return "", false
	}
}

// The shapes each field must have. The node key shape is the one every other
// component of this product already uses (NODE_KEY_RE in
// scripts/aperire-fleet-broker.sh), and the label shape is fleet.yaml's.
var (
	labelRe    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	nodeKeyRe  = regexp.MustCompile(`^n[1-9A-HJ-NP-Za-km-z]{20,60}$`)
	recordIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	originRe   = regexp.MustCompile(`^https?://[A-Za-z0-9.:-]{1,120}$`)
)

// Unpinned is what a revoke carries in place of a node key when the row it
// revoked pinned none.
//
// A registry row without expected_pubkey_node is supported, and the oldest
// rows on a fleet are exactly the ones that have none, so this is not an edge
// case to refuse. It is a word and not a key by construction: the shape rule
// above is "n" plus at least twenty base58 characters, and this is neither,
// so it can never be read back as a key that was pinned.
const Unpinned = "unpinned"

// Freshness bounds how far a record's issued_at may be from this node's clock,
// either way. The same five minutes the fleet-write surface allows, and for
// the same reason: a signed record is a bearer instrument for as long as it is
// fresh, and the replay scan in the handler closes what is left.
const Freshness = 5 * time.Minute

// MaxBodyBytes bounds the JSON envelope at the door. A record is a handful of
// short strings; anything larger is not one of these.
const MaxBodyBytes = 8 << 10

// Record is the wire shape the aggregator signs and POSTs.
//
// Field names and ORDER are load-bearing: SigningBytes serializes exactly
// these, in exactly this order, and the aggregator's builder must produce
// byte-identical input or the signature will not verify. Every optional field
// is omitempty, which is what lets each kind carry only its own fields and
// still sign to a stable string on both sides.
type Record struct {
	Kind Kind   `json:"kind"`
	Node string `json:"node"`
	// Who the aggregator's session says did this. Never proved here, and the
	// actor written from it says so.
	Operator string `json:"operator"`
	Role     string `json:"role,omitempty"`
	// The passkey that signed the approval at the aggregator. Recorded, not
	// verified here: this node checked the AGGREGATOR's signature, which is a
	// different proof from the operator's.
	CredentialID string `json:"credential_id,omitempty"`
	Origin       string `json:"origin,omitempty"`
	// KindLinkRevoked, KindAdvisorAttached and KindAdvisorDetached: the key
	// the row pinned, or Unpinned where the rule allows it. All three are
	// single-key acts and they share this member rather than growing one
	// each, so they also share one validation branch and one shape.
	PubkeyNode string `json:"pubkey_node,omitempty"`
	// KindNodeKeyRepinned only: the pair the operator compared.
	WasPubkeyNode string `json:"was_pubkey_node,omitempty"`
	NowPubkeyNode string `json:"now_pubkey_node,omitempty"`
	// RecordID is the aggregator's own name for this act, and the replay
	// guard: the handler refuses an id its ledger already holds.
	RecordID string `json:"record_id"`
	// IssuedAt is RFC3339 and is INSIDE the signature, so a captured record
	// cannot be replayed later wearing a newer time.
	IssuedAt string `json:"issued_at"`
	// IssuerLabel names which peers.<label> key verifies this.
	IssuerLabel string `json:"issuer_label"`
}

// SigningBytes is the canonical input both sides sign and verify.
//
// Deterministic by construction: a hand-ordered struct, marshalled with
// SetEscapeHTML(false) so Go matches JavaScript's JSON.stringify byte for
// byte (Go escapes <, > and & by default and JavaScript does not, which would
// make an origin carrying one of them sign to different bytes on the two
// sides, and the failure reads as a broken passkey). The twin is
// fleetRecordSigningBytes in dashboard/lib/advisor-ledger-append.ts, and both
// are pinned to the shared vectors in the tests beside them.
func (r *Record) SigningBytes() ([]byte, error) {
	ordered := struct {
		Kind          Kind   `json:"kind"`
		Node          string `json:"node"`
		Operator      string `json:"operator"`
		Role          string `json:"role,omitempty"`
		CredentialID  string `json:"credential_id,omitempty"`
		Origin        string `json:"origin,omitempty"`
		PubkeyNode    string `json:"pubkey_node,omitempty"`
		WasPubkeyNode string `json:"was_pubkey_node,omitempty"`
		NowPubkeyNode string `json:"now_pubkey_node,omitempty"`
		RecordID      string `json:"record_id"`
		IssuedAt      string `json:"issued_at"`
		IssuerLabel   string `json:"issuer_label"`
	}{
		r.Kind, r.Node, r.Operator, r.Role, r.CredentialID, r.Origin,
		r.PubkeyNode, r.WasPubkeyNode, r.NowPubkeyNode,
		r.RecordID, r.IssuedAt, r.IssuerLabel,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ordered); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a newline; the signed message does not include
	// it, because JSON.stringify produces none.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// VerifySignature checks the record's detached Ed25519 signature against the
// aggregator's public key. Both key and signature are base64url without
// padding, the encoding aperire-fleet-add.sh writes.
//
// Every way this can fail is one answer to the caller: an unsigned record, a
// record signed by another key, and a good signature over different bytes are
// all "this did not come from the aggregator this node trusts".
func (r *Record) VerifySignature(sigB64URL, pubKeyB64URL string) error {
	pub, err := decodeB64URL(pubKeyB64URL)
	if err != nil {
		return fmt.Errorf("aggregator public key is not valid base64url: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("aggregator public key is %d bytes, expected %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := decodeB64URL(sigB64URL)
	if err != nil {
		return fmt.Errorf("record signature is not valid base64url: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("record signature is %d bytes, expected %d", len(sig), ed25519.SignatureSize)
	}
	msg, err := r.SigningBytes()
	if err != nil {
		return fmt.Errorf("could not serialize the record for verification: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return errors.New("record signature does not verify against the aggregator's pinned key")
	}
	return nil
}

// ErrUnknownKind is what a record naming anything outside the closed set gets,
// and it is deliberately its own error: an operator reading a refused push
// needs to know the node runs an older build rather than that something was
// malformed.
var ErrUnknownKind = errors.New("that is not a kind this Advisor records")

// Validate answers whether this record may be appended at all, on shape
// alone. Called after the signature verifies, because a malformed record from
// the trusted aggregator is a bug worth a named refusal, and a malformed one
// from anybody else is not worth reading.
//
// now is passed rather than read, so the freshness rule is testable without a
// clock.
func (r *Record) Validate(now time.Time) error {
	if _, ok := LedgerKind(r.Kind); !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKind, string(r.Kind))
	}
	if !labelRe.MatchString(r.Node) {
		return errors.New("node must be a fleet label, [a-z0-9-] up to 32 characters")
	}
	if n := len(r.Operator); n == 0 || n > 64 {
		return errors.New("operator must name somebody, up to 64 characters")
	}
	if len(r.Role) > 32 {
		return errors.New("role is longer than any role this product has")
	}
	if len(r.CredentialID) > 256 {
		return errors.New("credential_id is longer than any credential id this product mints")
	}
	if r.Origin != "" && !originRe.MatchString(r.Origin) {
		return errors.New("origin must be a bare http(s) origin")
	}
	if !recordIDRe.MatchString(r.RecordID) {
		return errors.New("record_id must be 8 to 64 characters of [A-Za-z0-9_-]")
	}
	if strings.TrimSpace(r.IssuerLabel) == "" {
		return errors.New("the record carries no issuer_label")
	}
	at, err := time.Parse(time.RFC3339, r.IssuedAt)
	if err != nil {
		return errors.New("issued_at is not an RFC3339 time")
	}
	if d := now.Sub(at); d > Freshness || d < -Freshness {
		return fmt.Errorf("issued_at is %s away from this node's clock, and the window is %s",
			d.Round(time.Second).String(), Freshness.String())
	}
	return r.validateFields()
}

// validateFields is the per-kind half: each kind carries ITS fields and none
// of the other's. Stated as two explicit branches rather than a table,
// because the value of the rule is that a reader can see what each kind may
// say without following an indirection.
func (r *Record) validateFields() error {
	switch r.Kind {
	case KindLinkRevoked, KindAdvisorDetached:
		if r.PubkeyNode != Unpinned && !nodeKeyRe.MatchString(r.PubkeyNode) {
			return fmt.Errorf("pubkey_node must be a node key, or %q for a row that pinned none", Unpinned)
		}
		if r.WasPubkeyNode != "" || r.NowPubkeyNode != "" {
			return errors.New("that act carries one key, not a pair")
		}
	case KindAdvisorAttached:
		// UNPINNED IS REFUSED HERE, and only here among the single-key kinds.
		// A revoke closes a link and needs no address, and a detach forgets
		// one, so both are reachable on a row that pins nothing. An attach is
		// addressed to a node key end to end: the reveal job names it, the
		// aggregator refuses an unpinned row before it asks the node
		// anything, and the root broker checks it against two files. A record
		// of one that says "unpinned" describes an act that cannot have
		// happened.
		if !nodeKeyRe.MatchString(r.PubkeyNode) {
			return errors.New("pubkey_node must be a node key: an Advisor is only ever attached to a pinned row")
		}
		if r.WasPubkeyNode != "" || r.NowPubkeyNode != "" {
			return errors.New("that act carries one key, not a pair")
		}
	case KindNodeKeyRepinned:
		if !nodeKeyRe.MatchString(r.WasPubkeyNode) || !nodeKeyRe.MatchString(r.NowPubkeyNode) {
			return errors.New("was_pubkey_node and now_pubkey_node must both be node keys")
		}
		if r.WasPubkeyNode == r.NowPubkeyNode {
			return errors.New("a re-pin replaces one key with a different one")
		}
		if r.PubkeyNode != "" {
			return errors.New("a re-pin carries the pair it replaced, not a single key")
		}
	}
	return nil
}

// Summary is the sentence the ledger keeps, composed HERE from the kind and
// the fields.
//
// It is never taken off the wire, and that is the rule this surface is worth
// having: a caller that could write the summary could write anything into the
// record of what was done to this node. Anything added to Record later that a
// caller supplies as prose reopens that, whatever it is called.
//
// self says which key verified this record, so the sentence reads correctly
// on the chain it lands on: false is the node's own ledger, where "this
// node's link" is the node speaking about itself, and true is the
// aggregator's own ledger (#477), where the same phrase would misname
// somebody else's node as "this" one. It is a parameter here rather than a
// field the record carries, because it is never carried at all: the door
// derives it from which key verified the signature, one label at a time, and
// nothing about it is ever written onto Record itself. r.IssuerLabel happens
// to hold "self" too, but this is decided by the caller's own resolution, not
// by Summary reading that field back.
func (r *Record) Summary(self bool) string {
	switch r.Kind {
	case KindLinkRevoked:
		if r.PubkeyNode == Unpinned || r.PubkeyNode == "" {
			if self {
				return fmt.Sprintf("this aggregator revoked the link for %q; the row pinned no node key", r.Node)
			}
			return fmt.Sprintf("the aggregator revoked this node's link as %q; the row pinned no node key", r.Node)
		}
		if self {
			return fmt.Sprintf("this aggregator revoked the link for %q, node key %s", r.Node, r.PubkeyNode)
		}
		return fmt.Sprintf("the aggregator revoked this node's link as %q, node key %s", r.Node, r.PubkeyNode)
	case KindNodeKeyRepinned:
		who := "the aggregator"
		if self {
			who = "this aggregator"
		}
		return fmt.Sprintf("%s accepted a changed node key for %q: %s replaces %s",
			who, r.Node, r.NowPubkeyNode, r.WasPubkeyNode)
	case KindAdvisorAttached:
		if self {
			return fmt.Sprintf("this aggregator attached the Advisor on %q, node key %s", r.Node, r.PubkeyNode)
		}
		return fmt.Sprintf("the aggregator attached this node's Advisor as %q, node key %s; it reads this node's Advisor from now on", r.Node, r.PubkeyNode)
	case KindAdvisorDetached:
		// NOT worded as a removal of anything on this box, because it is
		// not one: the aggregator stopped reaching an Advisor that is still
		// running here, holding a credential this node never rotated. An
		// entry reading "the Advisor was removed" would be this node's own
		// permanent record of something that did not happen to it.
		if r.PubkeyNode == Unpinned || r.PubkeyNode == "" {
			if self {
				return fmt.Sprintf("this aggregator stopped reaching the Advisor on %q; the row pinned no node key", r.Node)
			}
			return fmt.Sprintf("the aggregator stopped reaching this node's Advisor as %q; the row pinned no node key. The Advisor here is untouched", r.Node)
		}
		if self {
			return fmt.Sprintf("this aggregator stopped reaching the Advisor on %q, node key %s", r.Node, r.PubkeyNode)
		}
		return fmt.Sprintf("the aggregator stopped reaching this node's Advisor as %q, node key %s. The Advisor here is untouched", r.Node, r.PubkeyNode)
	}
	return ""
}

// Data is what the entry carries beside its summary. Only the fields the
// record actually holds, so a revoke's entry has no empty repin members to
// read as meaningful.
func (r *Record) Data() map[string]any {
	d := map[string]any{
		"node":      r.Node,
		"record_id": r.RecordID,
		"issuer":    r.IssuerLabel,
		"issued_at": r.IssuedAt,
	}
	switch r.Kind {
	case KindLinkRevoked, KindAdvisorAttached, KindAdvisorDetached:
		d["pubkey_node"] = r.PubkeyNode
	case KindNodeKeyRepinned:
		d["was_pubkey_node"] = r.WasPubkeyNode
		d["now_pubkey_node"] = r.NowPubkeyNode
	}
	return d
}

func decodeB64URL(s string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
}
