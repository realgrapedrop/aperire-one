package host

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LoadBinding reads the pinned rp_id+origins recorded on the first accepted
// bundle. A missing file means this node has never accepted one — the caller
// treats nil as "first install", which is what CheckBinding expects.
func LoadBinding(path string) (*Binding, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b Binding
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &b, nil
}

// SaveBinding records the pin at 0640. Written once on first install and
// left alone thereafter (CheckBinding returns the unchanged binding on
// later installs), but re-writing the same bytes is harmless.
func SaveBinding(path string, b *Binding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o640)
}

// A deliberately minimal, strict reader for fleet-trust.yaml — just enough
// to answer one question: what public key does peers.<label> hold?
//
// advisord carries ZERO external dependencies, a property worth keeping for
// a binary that verifies signatures against a validator's approval trust.
// Rather than pull a YAML library in for one lookup, this parses the exact
// block shape aperire-fleet-add.sh writes (python yaml.safe_dump, block
// style, sort_keys=False):
//
//	private_key: <b64url>          # this node's own key; ignored here
//	peers:
//	  aggregator: <b64url>         # the key we want
//	  other-node: <b64url>
//
// It is strict: two-space indent under `peers:`, one `label: value` per
// line, values are bare tokens (no quotes, no flow syntax). Anything it does
// not recognize is skipped, and a missing label is a plain not-found — never
// a guess. If an operator hand-writes something exotic here, the bundle push
// fails closed with "no key for <label>", which is the safe direction.
func AggregatorPubKey(fleetTrustPath, label string) (string, error) {
	fleetTrustPath = TrustReadPath(fleetTrustPath)
	f, err := openTrustFile(fleetTrustPath)
	if err != nil {
		return "", fmt.Errorf("cannot read fleet-trust.yaml at %s: %w", fleetTrustPath, err)
	}
	defer f.Close()

	inPeers := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// A top-level key (no leading space) ends the peers block.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inPeers = strings.TrimSpace(strings.TrimSuffix(line, ":")) == "peers"
			continue
		}
		if !inPeers {
			continue
		}
		// A peers entry: "  <label>: <value>". Exactly one colon splits it.
		trimmed := strings.TrimSpace(line)
		idx := strings.IndexByte(trimmed, ':')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(trimmed[:idx])
		v := strings.TrimSpace(trimmed[idx+1:])
		// Strip optional surrounding quotes yaml.safe_dump may add for some
		// values (it won't for bare base64url, but be tolerant).
		v = strings.Trim(v, `"'`)
		if k == label {
			if v == "" {
				return "", fmt.Errorf("peers.%s in %s has an empty value", label, fleetTrustPath)
			}
			return v, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no key for peer %q in %s (run the fleet-add trust exchange first)", label, fleetTrustPath)
}

// OwnPubKey derives this node's own Ed25519 public key from the top-level
// `private_key:` seed in fleet-trust.yaml.
//
// Needed for exactly one purpose: verifying a record whose issuer_label is
// the literal "self" (#477), the aggregator's own copy of an act it did to a
// node, appended to its own advisord over loopback. Every other issuer
// resolves through peers.<label> (AggregatorPubKey above), and self is the
// one label a node answers out of its OWN key rather than a peer's. The
// caller resolves this BEFORE peers is ever consulted, so a peers entry that
// happens to be labelled self can never be read as this rule; that ordering
// lives in the caller, not here, and this function does not read peers at
// all.
//
// The seed is the raw 32-byte Ed25519 seed, base64url, no padding, exactly
// what dashboard/lib/trust-bundle.ts's readOwnPrivateKey and
// readOwnPublicKey read on the other side, and the same one
// aperire-fleet-add.sh writes. It is scanned at the top level only: a line
// that starts with whitespace is under some other key, most likely peers,
// and is not this node's own.
func OwnPubKey(fleetTrustPath string) (string, error) {
	fleetTrustPath = TrustReadPath(fleetTrustPath)
	f, err := openTrustFile(fleetTrustPath)
	if err != nil {
		return "", fmt.Errorf("cannot read fleet-trust.yaml at %s: %w", fleetTrustPath, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// The public file (#868) carries the public half as it is. Same
		// top-level rule as private_key below: an indented line belongs to
		// some other key, most likely peers, and is never this host's own.
		if strings.HasPrefix(line, "public_key:") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "public_key:")), `"'`)
			if v == "" {
				return "", fmt.Errorf("public_key in %s is empty", fleetTrustPath)
			}
			raw, err := decodeB64URL(v)
			if err != nil {
				return "", fmt.Errorf("public_key in %s is not valid base64url: %w", fleetTrustPath, err)
			}
			if len(raw) != ed25519.PublicKeySize {
				return "", fmt.Errorf("public_key in %s is %d bytes, expected %d", fleetTrustPath, len(raw), ed25519.PublicKeySize)
			}
			return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw), nil
		}
		if !strings.HasPrefix(line, "private_key:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "private_key:"))
		v = strings.Trim(v, `"'`)
		if v == "" {
			return "", fmt.Errorf("private_key in %s is empty", fleetTrustPath)
		}
		seed, err := decodeB64URL(v)
		if err != nil {
			return "", fmt.Errorf("private_key in %s is not valid base64url: %w", fleetTrustPath, err)
		}
		if len(seed) != ed25519.SeedSize {
			return "", fmt.Errorf("private_key in %s is %d bytes, expected %d", fleetTrustPath, len(seed), ed25519.SeedSize)
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pub), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no public_key or private_key in %s (this host holds no fleet signing key)", fleetTrustPath)
}

// TrustPublicFile is the name of the public half of fleet-trust.yaml, beside
// it in dashboard/config (#868, ADR 0024 row 19). On a host whose
// fleet-trust.yaml holds a private_key, scripts/fleet-trust-split.sh writes
// this file, readable by the Advisor's account, and leaves fleet-trust.yaml
// 0600 to the dashboard account, so the Advisor never holds the key that
// signs trust bundles and model.seal jobs. It is fleet-trust.yaml with the
// private_key line taken out and a public_key line put in: the same peers
// block, byte for byte, so every lookup above reads it unchanged.
const TrustPublicFile = "fleet-trust.pub.yaml"

// TrustReadPath is the file advisord actually reads for a configured
// fleet-trust.yaml path: the public file beside it when there is one, and
// the configured file itself when there is not. A node's file holds no
// private key and has no public file, so it is read as it always was.
//
// The public file wins whenever it exists, and there is no fallback from it
// to fleet-trust.yaml when it cannot be read or holds no answer. A fallback
// would only ever succeed on a host where the Advisor can still read the
// private key, which is the shape this file exists to end.
//
// The public file is opened with O_NOFOLLOW and must be a regular file with
// one link (openTrustFile). Anything else at that name is a refusal, never a
// reason to read fleet-trust.yaml instead (#873 review, L1): a link there
// would give the trust anchor a second name that pairing's ownership of
// fleet-trust.yaml does not cover. Its owner is not checked; root creates it
// on a real host, but the content is the dashboard account's either way.
func TrustReadPath(fleetTrustPath string) string {
	pub := filepath.Join(filepath.Dir(fleetTrustPath), TrustPublicFile)
	if _, err := os.Lstat(pub); err == nil {
		return pub
	}
	return fleetTrustPath
}

// AcceptedBundle is the receipt for the last trust bundle this node took —
// which issuer signed it, which credential set it carried, and when it was
// applied.
//
// It is deliberately NOT folded into Binding. CheckBinding returns the
// PINNED binding unchanged on every install after the first (that is the
// whole point of a pin), so a serial carried there would freeze at the first
// bundle and read as permanently up to date — the exact lie this record
// exists to prevent. The test beside this file pins that.
//
// It is also not the same claim as CredentialStore.Fingerprint(). The
// fingerprint says what the store hashes to RIGHT NOW, and it moves for a
// local advisor-sync or a hand edit as readily as for a push. This says what
// this node last ACCEPTED FROM AN ISSUER. The two are equal on a healthy
// fleet node and differ the moment something writes the store locally, which
// is worth being able to see.
type AcceptedBundle struct {
	Serial     string `json:"serial"`
	Issuer     string `json:"issuer"`
	AcceptedAt string `json:"accepted_at"` // RFC3339 UTC
}

// LoadAcceptedBundle reads the receipt. A missing file is not an error: it
// means this node has never been pushed to, which is a real and reportable
// state (nil), not a failure.
func LoadAcceptedBundle(path string) (*AcceptedBundle, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a AcceptedBundle
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &a, nil
}

// SaveAcceptedBundle records the receipt at 0640, beside the store it
// describes. Written on every accepted push, so the serial and the timestamp
// always describe the bundle that is actually installed.
func SaveAcceptedBundle(path string, a *AcceptedBundle) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o640)
}

// openTrustFile opens a trust file for reading. The public file is held to
// the anti-swap rule above; fleet-trust.yaml itself is opened as it always
// was.
func openTrustFile(path string) (*os.File, error) {
	if filepath.Base(path) != TrustPublicFile {
		return os.Open(path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("%s has %d links, so it is also reachable under another name", path, st.Nlink)
	}
	return f, nil
}
