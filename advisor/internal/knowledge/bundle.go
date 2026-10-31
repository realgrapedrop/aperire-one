package knowledge

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// The signed knowledge bundle — ADR 0017 decision 3. The aggregator tars its
// knowledge-fleet/, lists every file with its hash in a manifest, signs the
// manifest with the SAME Ed25519 key the trust bundle uses, and POSTs the
// three to each node. The node verifies the signature, verifies every hash,
// refuses a sequence it has already seen or passed, and applies the whole
// thing or none of it.
//
// This file is policy plus crypto plus the filesystem swap: no HTTP, no
// server, no ledger. Every rule that decides whether a bundle is ACCEPTED
// lives here, where it is unit-tested against a real keypair and against each
// of the ways a tar can lie about what it contains.
//
// What a bundle may NOT do is as load-bearing as what it may. Knowledge
// shapes advice and grants nothing: no path in an accepted bundle can reach
// outside knowledge-fleet/, name the per-node namespace, or be called
// role-policy.md. Those are refusals here, at the door, in addition to the
// loader's own — the door is the primary gate because it is the one place
// that sees the content before it exists on disk.

// The caps. Each one closes a way a bundle could cost more than it says.
const (
	// MaxBundleBytes is the compressed archive. Four megabytes is two orders
	// of magnitude past today's whole corpus.
	MaxBundleBytes = 4 << 20
	// MaxUncompressedBytes bounds what the archive expands to. The
	// compressed cap does nothing on its own here: a few kilobytes of zeros
	// expand without limit, and the reader would happily write them all.
	MaxUncompressedBytes = 16 << 20
	// MaxEntries bounds the file count, so a bundle cannot cost a node an
	// unbounded number of small writes.
	MaxEntries = 2000
)

// Named errors, so a caller reports the actual refusal rather than a generic
// failure. Every one of these is a fail-closed path: nothing is applied.
var (
	ErrSignature   = errors.New("the bundle signature does not verify against the aggregator's key")
	ErrSequence    = errors.New("the bundle sequence is not newer than the one already applied")
	ErrHash        = errors.New("a file in the bundle does not match its manifest hash")
	ErrManifest    = errors.New("the archive and the manifest do not describe the same set of files")
	ErrPath        = errors.New("the bundle carries a path it may not")
	ErrTooLarge    = errors.New("the bundle is larger than a knowledge bundle may be")
	ErrArchive     = errors.New("the archive could not be read")
	ErrNoIssuer    = errors.New("the manifest names no issuer")
)

// ManifestFile is one file: its path relative to knowledge-fleet/ (so
// "local/xrpl/validations.md"), and the SHA-256 of its bytes, lowercase hex.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest is what the aggregator signs. Everything a node acts on is inside
// it: which files, with which contents, in which order of pushes, from whom,
// and on whose authority.
//
// IssuerLabel and PushedBy are in the SIGNED bytes deliberately. The issuer
// decides which public key verifies the push, and pushed_by is written into
// the node's ledger as the actor — a field the wire could rewrite would be an
// audit trail that records whatever the pusher felt like claiming.
type Manifest struct {
	Seq         int64          `json:"seq"`
	Files       []ManifestFile `json:"files"`
	CreatedAt   string         `json:"created_at"`   // RFC3339 UTC
	IssuerLabel string         `json:"issuer_label"` // which peers.<label> key verifies this
	PushedBy    string         `json:"pushed_by"`    // the operator account that built it
}

// SigningBytes is the canonical input both sides sign and verify.
// Deterministic by construction, and mirroring the trust bundle's own twin
// (internal/host/trustbundle.go) so there is one shape of this problem in the
// project rather than two: a hand-ordered struct (json.Marshal emits fields
// in declaration order), files sorted by path, HTML escaping off so Go and
// JavaScript's JSON.stringify agree byte for byte, and no trailing newline.
//
// Do not "tidy" this without changing the aggregator's twin
// (dashboard/lib/knowledge-bundle.ts) and re-checking the shared vector both
// sides' tests pin.
func (m *Manifest) SigningBytes() ([]byte, error) {
	files := append([]ManifestFile(nil), m.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	// An empty list signs as "files":null, never []. Every released node
	// computes null here (append to nil of nothing is nil), and the twin
	// matches it, so an empty bundle (#1219) verifies on a node from before
	// empty bundles were accepted and is refused there by name, not as a bad
	// signature. Explicit, so a tidy-up cannot change it by accident.
	if len(files) == 0 {
		files = nil
	}
	ordered := struct {
		Seq         int64          `json:"seq"`
		Files       []ManifestFile `json:"files"`
		CreatedAt   string         `json:"created_at"`
		IssuerLabel string         `json:"issuer_label"`
		PushedBy    string         `json:"pushed_by"`
	}{m.Seq, files, m.CreatedAt, m.IssuerLabel, m.PushedBy}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ordered); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// VerifySignature checks the detached Ed25519 signature over SigningBytes.
// Key and signature are base64url without padding, the same encoding
// aperire-fleet-add.sh writes and the trust bundle already uses.
func (m *Manifest) VerifySignature(sigB64URL, pubKeyB64URL string) error {
	pub, err := decodeB64URL(pubKeyB64URL)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: the aggregator public key is not a %d-byte base64url key", ErrSignature, ed25519.PublicKeySize)
	}
	sig, err := decodeB64URL(sigB64URL)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the signature is not a %d-byte base64url signature", ErrSignature, ed25519.SignatureSize)
	}
	msg, err := m.SigningBytes()
	if err != nil {
		return fmt.Errorf("%w: the manifest could not be serialized", ErrSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrSignature
	}
	return nil
}

// CheckSequence enforces monotonicity. A bundle at or below the applied
// sequence is a replay — including a replay of a bundle this node itself
// accepted an hour ago, which is how a rolled-back corpus would be
// reinstated without anyone editing anything.
func (m *Manifest) CheckSequence(applied int64) error {
	if m.Seq <= applied {
		return fmt.Errorf("%w: this node has applied sequence %d and the bundle carries %d",
			ErrSequence, applied, m.Seq)
	}
	return nil
}

// checkPath is every rule about where a bundle entry may land, in one place.
// It returns the cleaned relative path.
//
// The first three rules are the classic archive refusals (absolute paths,
// traversal, anything that is not a plain file or directory). The last three
// are this project's: a knowledge bundle carries markdown into exactly two
// directories, it does not carry the per-node namespace's own word, and it
// does not carry the file that says what each role may do.
func checkPath(name string, typeflag byte) (string, error) {
	if typeflag != tar.TypeReg && typeflag != tar.TypeDir {
		return "", fmt.Errorf("%w: %q is not a regular file or a directory (type %q) — "+
			"a knowledge bundle carries neither links nor devices", ErrPath, name, string(typeflag))
	}
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) || strings.Contains(name, `\`) {
		return "", fmt.Errorf("%w: %q is not a relative path", ErrPath, name)
	}
	clean := path.Clean(strings.TrimSuffix(name, "/"))
	if clean == "." || clean == "" {
		return "", nil // the archive root itself
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		if s == ".." || s == "." {
			return "", fmt.Errorf("%w: %q walks outside the corpus", ErrPath, name)
		}
		if s == "nodes" {
			return "", fmt.Errorf("%w: %q uses nodes/, which belongs to per-node knowledge written on the node itself", ErrPath, name)
		}
	}
	if segs[0] != "base" && segs[0] != "local" {
		return "", fmt.Errorf("%w: %q is outside base/ and local/, the only two layers a bundle carries", ErrPath, name)
	}
	if typeflag == tar.TypeDir {
		return clean, nil
	}
	if len(segs) < 2 {
		return "", fmt.Errorf("%w: %q is a file where a layer directory belongs", ErrPath, name)
	}
	base := segs[len(segs)-1]
	if !strings.HasSuffix(base, ".md") {
		return "", fmt.Errorf("%w: %q is not markdown; a knowledge bundle carries notes and nothing else", ErrPath, name)
	}
	if base == "role-policy.md" {
		return "", fmt.Errorf("%w: %q — role-policy.md states what each role may do and is shipped with the release, never pushed", ErrPath, name)
	}
	return clean, nil
}

// Stats is what changed, for the ledger and the reply. Counts only: the
// operator gets numbers here and the whole file list in the manifest.
type Stats struct {
	Added   int
	Changed int
	Removed int
	Files   int
}

// Extract verifies an archive against its manifest and writes it into dest,
// which must be an empty directory the caller owns.
//
// The verification is symmetric on purpose. Every entry must appear in the
// manifest with a matching hash — otherwise an unsigned file rides along
// inside a signed bundle — and every manifest entry must appear in the
// archive, or a file the signature promises is silently missing.
//
// A manifest with no files is a bundle (#1219): it is how an aggregator
// withdraws the last note it promoted. It grants nothing a one-file bundle
// does not, since any bundle already replaces the whole corpus, and the
// archive is held to the same rule, so it must carry no file either.
func Extract(gz []byte, m *Manifest, dest string) error {
	if len(gz) > MaxBundleBytes {
		return fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, len(gz), MaxBundleBytes)
	}
	want := map[string]string{}
	for _, f := range m.Files {
		clean, err := checkPath(f.Path, tar.TypeReg)
		if err != nil {
			return err
		}
		if _, dup := want[clean]; dup {
			return fmt.Errorf("%w: %q is listed twice", ErrManifest, f.Path)
		}
		want[clean] = strings.ToLower(f.SHA256)
	}
	if len(want) > MaxEntries {
		return fmt.Errorf("%w: %d files, the limit is %d", ErrTooLarge, len(want), MaxEntries)
	}

	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArchive, err)
	}
	defer zr.Close()
	// The limit that matters: the compressed cap above says nothing about
	// what the archive expands to.
	tr := tar.NewReader(io.LimitReader(zr, MaxUncompressedBytes+1))

	seen := map[string]bool{}
	total := int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchive, err)
		}
		clean, perr := checkPath(h.Name, h.Typeflag)
		if perr != nil {
			return perr
		}
		if clean == "" {
			continue
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(clean)), 0o750); err != nil {
				return err
			}
			continue
		}
		if len(seen) >= MaxEntries {
			return fmt.Errorf("%w: more than %d files", ErrTooLarge, MaxEntries)
		}
		hash, ok := want[clean]
		if !ok {
			return fmt.Errorf("%w: %q is in the archive but not in the signed manifest", ErrManifest, h.Name)
		}
		if seen[clean] {
			return fmt.Errorf("%w: %q appears twice in the archive", ErrManifest, h.Name)
		}
		// The header's own size first, before a single byte is read: the
		// LimitReader above stops a bomb from being written, but it stops it
		// by truncating, which would surface as a hash mismatch rather than
		// as the size refusal it is. A header that lies low is caught by the
		// hash anyway.
		if h.Size > MaxUncompressedBytes || total+h.Size > MaxUncompressedBytes {
			return fmt.Errorf("%w: the archive expands past %d bytes", ErrTooLarge, MaxUncompressedBytes)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchive, err)
		}
		total += int64(len(body))
		if total > MaxUncompressedBytes {
			return fmt.Errorf("%w: the archive expands past %d bytes", ErrTooLarge, MaxUncompressedBytes)
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != hash {
			return fmt.Errorf("%w: %s hashes to %s, the manifest says %s", ErrHash, clean, got[:12], firstN(hash, 12))
		}
		full := filepath.Join(dest, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return err
		}
		// Modes are forced, never taken from the archive: a pushed file does
		// not get to decide it is executable or world-readable.
		if err := os.WriteFile(full, body, 0o640); err != nil {
			return err
		}
		seen[clean] = true
	}
	for p := range want {
		if !seen[p] {
			return fmt.Errorf("%w: the manifest lists %q and the archive does not carry it", ErrManifest, p)
		}
	}
	return nil
}

// hashTree is every *.md file under root with its hash, keyed by the path a
// manifest would use. Used to describe what a push changed.
func hashTree(root string) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree just does not count as present
		}
		// Staging and retiring directories live inside root during a swap,
		// and a crash can leave one behind. Neither is corpus, and counting
		// one would make "what changed" describe the wrong thing. The walk's
		// own starting directory is exempt: hashTree is called ON a staging
		// directory as well as on the corpus.
		if p != root && strings.HasPrefix(e.Name(), ".") {
			if e.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if e.IsDir() || !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".md") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		sum := sha256.Sum256(b)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out
}

// bundleLayers is the two directories a bundle carries, and the unit of the
// swap below.
var bundleLayers = []string{"base", "local"}

// Install verifies a bundle and swaps it into place, or changes nothing.
//
// Everything happens INSIDE root — staging, the retiring copy, the renames.
// That is the whole shape of this function and it is not incidental: the
// service's unit grants ReadWritePaths on advisor/knowledge-fleet and nothing
// above it, so under ProtectSystem=strict the parent directory is on a
// read-only mount. An install that staged beside root would verify the
// signature and every hash and then fail EROFS at the swap, on every real
// node. Granting the parent instead would hand the service advisor/knowledge/,
// persona.md and its own binary — the three things that unit exists to keep
// out of its reach. The test beside this file holds the property with file
// modes, since a mount namespace needs root to build.
//
// The swap is per LAYER, two renames each, because os.Rename onto a non-empty
// directory fails: the current layer moves aside, the new one takes its name,
// and only then is the old one removed. If the second rename fails the first
// is undone. So the honest claim is per-layer rather than whole-corpus: no
// layer is ever half-applied, and a failure part-way leaves the layers not yet
// reached exactly as they were.
//
// A layer the manifest does not carry is removed, so a bundle describes the
// whole corpus rather than adding to it — the same semantic a whole-directory
// swap had.
func Install(root string, gz []byte, m *Manifest) (Stats, error) {
	var st Stats
	if err := os.MkdirAll(root, 0o750); err != nil {
		return st, fmt.Errorf(
			"cannot create the fleet knowledge directory %s (%v) — re-run the Advisor installer on this host: "+
				"it creates the directory and grants the service permission to write it", root, err)
	}
	// Measured before staging exists, so the staging and retiring directories
	// cannot count as corpus files.
	before := hashTree(root)

	staging, err := os.MkdirTemp(root, ".incoming-")
	if err != nil {
		return st, fmt.Errorf(
			"cannot stage inside %s (%v) — re-run the Advisor installer on this host: "+
				"the service must be able to write that directory", root, err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o750); err != nil {
		return st, err
	}
	if err := Extract(gz, m, staging); err != nil {
		return st, err
	}

	after := hashTree(staging)
	for p, h := range after {
		switch prev, had := before[p]; {
		case !had:
			st.Added++
		case prev != h:
			st.Changed++
		}
	}
	for p := range before {
		if _, still := after[p]; !still {
			st.Removed++
		}
	}
	st.Files = len(after)

	for _, layer := range bundleLayers {
		src := filepath.Join(staging, layer)
		dst := filepath.Join(root, layer)
		if _, err := os.Stat(src); err != nil {
			// The bundle does not carry this layer: it is gone, not kept.
			_ = os.RemoveAll(dst)
			continue
		}
		retired := ""
		if _, err := os.Stat(dst); err == nil {
			retired = filepath.Join(root, ".retiring-"+layer)
			_ = os.RemoveAll(retired)
			if err := os.Rename(dst, retired); err != nil {
				return st, fmt.Errorf("could not move the current %s layer aside: %w", layer, err)
			}
		}
		if err := os.Rename(src, dst); err != nil {
			if retired != "" {
				// Put it back. A node missing a layer entirely is a worse
				// state than a node still holding the previous one.
				_ = os.Rename(retired, dst)
			}
			return st, fmt.Errorf("could not put the new %s layer in place: %w", layer, err)
		}
		if retired != "" {
			_ = os.RemoveAll(retired)
		}
	}
	return st, nil
}

// Applied is the node's receipt: which bundle it is running, from whom, and
// when it took it. Beside the corpus it describes, in the state directory,
// so a state directory restored from a backup carries the pair or neither.
type Applied struct {
	Seq       int64  `json:"seq"`
	SHA256    string `json:"sha256"` // of the compressed archive, as pushed
	PushedBy  string `json:"pushed_by"`
	Issuer    string `json:"issuer"`
	AppliedAt string `json:"applied_at"` // RFC3339 UTC
}

// LoadApplied reads the receipt. A missing file is not an error: it means no
// bundle has ever been applied, which is the state every node starts in and a
// real thing to report.
func LoadApplied(path string) (*Applied, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a Applied
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &a, nil
}

// SaveApplied writes the receipt at 0640.
func SaveApplied(path string, a *Applied) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o640)
}

// AppliedSeq is the sequence to compare a bundle against: zero when nothing
// has ever been applied, so the first bundle any node accepts is seq 1.
func AppliedSeq(a *Applied) int64 {
	if a == nil {
		return 0
	}
	return a.Seq
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
