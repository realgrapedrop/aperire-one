package host

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"aperire-advisor/internal/ledger"
)

// The official image, and what has to be true before a node runs one.
//
// The ruling (#682, 2026-09-27): for a container node the official
// rippleci/xrpld image is the FIRST upgrade source. A build from the signed
// package is what gets offered when no tag exists and the operator
// approves, or when the operator asks for a build.
//
// Two things stay exactly as they were, and they are the reason this is
// narrow. What is NEWEST comes only from the package index at
// packages.xrplf.org: a release exists when the Foundation publishes a
// signed package, not when somebody pushes a tag. And a release the index
// does not carry is not a release, whatever a registry says. The registry is
// asked one question, about one tag, by name.

// OfficialImageRepo is the repository the XRPL release process publishes to.
// Announced by Mayukha Vadari on 2026-09-19, and WietseWind/docker-xrpld#31
// retires xrpllabsofficial/xrpld in its favour.
//
// A constant for the same reason LocalImageRepo is one: a configured
// repository would be a name an operator's own configuration could point at
// any registry, and what comes back from it is root-run code.
const OfficialImageRepo = "rippleci/xrpld"

// OfficialImageSource is what to call that origin in a sentence an operator
// reads.
const OfficialImageSource = "the official image"

// officialTagURL asks about ONE tag, by name.
//
// Not a tag list. The repository carries 916 tags and pages them, and most
// of them are neither releases nor meant to be run by anyone: commit hashes
// (21560cdf82d0…), `develop`, release candidates, `ripple--se--supported`.
// A walk of that list is a thing to filter correctly forever; a request for
// one plain version tag cannot be confused by any of them, and a tag that
// is not there is a 404 rather than an absence inferred from a page nobody
// finished reading.
func officialTagURL(version string) string {
	return "https://hub.docker.com/v2/repositories/" + OfficialImageRepo + "/tags/" + version
}

// officialTagMaxBytes bounds the reply. A real one is about 1 KB.
const officialTagMaxBytes = 1 << 18

// OfficialTagFact is the registry's answer about one release.
type OfficialTagFact struct {
	Version string
	// Exists is false for a clean 404: the release is real (the index says
	// so) and no official image carries it yet. That is the build offer's
	// case, and it is not an error.
	Exists bool
	// IndexDigest is the digest the TAG points at, which is what
	// RepoDigests reports back after a pull and therefore the one the
	// deployment and `docker inspect` can both name. This is the pin.
	IndexDigest string
	// AmdDigest is the amd64 manifest inside that index, recorded beside it
	// because it is what a single-platform store may report and a reader
	// comparing the wrong one reads a two-hop mismatch as tampering.
	AmdDigest string
}

// OfficialTag asks whether the official image carries this exact release.
//
// Fails closed, like every read in this package: a registry that would not
// answer is an error, never a quiet "no tag" that would send a node down
// the build path without anyone deciding to.
func (s *State) OfficialTag(version string) (OfficialTagFact, error) {
	var f OfficialTagFact
	// The shape first, and with it the URL's safety: a version reaching
	// this has passed releaseRe, so the path can carry digits and dots and
	// nothing else. Checked here rather than assumed, because the caller
	// may be a plan parameter rather than the index.
	if len(version) > releaseMaxLen || !releaseRe.MatchString(version) {
		return f, fmt.Errorf("refusing to ask the registry about %q: a release is digits and dots", trunc(version, releaseMaxLen))
	}
	// Before the registry is asked at all: is this node the software that
	// image carries? The same gate packagesIndexBody takes, for the same
	// reason. A fork with its own repository and its own amendment set
	// offered an xrpld image is not being offered an upgrade, it is being
	// offered a different program, and the tag read must not be the hole
	// that route walks through.
	if err := s.xrpldFamilyOrRefusal(); err != nil {
		return f, err
	}
	return s.officialTagRead(version)
}

// officialTagRead is OfficialTag's registry read, for a caller that has
// already checked the version's shape and the node's family.
func (s *State) officialTagRead(version string) (OfficialTagFact, error) {
	var f OfficialTagFact
	if len(version) > releaseMaxLen || !releaseRe.MatchString(version) {
		return f, fmt.Errorf("refusing to ask the registry about %q: a release is digits and dots", trunc(version, releaseMaxLen))
	}
	f.Version = version
	req, err := http.NewRequestWithContext(s.context(), http.MethodGet, officialTagURL(version), nil)
	if err != nil {
		return f, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return f, fmt.Errorf("could not ask the registry whether an official image carries %s: %w", version, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, officialTagMaxBytes))
	if err != nil {
		return f, fmt.Errorf("could not read the registry's answer for %s: %w", version, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		// The real no-tag case, and the only one that is not an error.
		return f, nil
	}
	if resp.StatusCode != http.StatusOK {
		return f, fmt.Errorf("the registry returned %s when asked about %s:%s", resp.Status, OfficialImageRepo, version)
	}
	var body struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
		Images []struct {
			Digest       string `json:"digest"`
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"images"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return f, fmt.Errorf("could not decode the registry's answer for %s: %w", version, err)
	}
	// The tag that came back has to be the tag that was asked for. A
	// registry answering 200 for something else is not an answer to this
	// question.
	if body.Name != "" && body.Name != version {
		return f, fmt.Errorf("asked the registry about %s and it answered about %q", version, trunc(body.Name, 40))
	}
	if !isDigest(body.Digest) {
		return f, fmt.Errorf("the registry named no usable digest for %s:%s", OfficialImageRepo, version)
	}
	f.Exists = true
	f.IndexDigest = body.Digest
	for _, im := range body.Images {
		if im.Architecture == "amd64" && (im.OS == "" || im.OS == "linux") && isDigest(im.Digest) {
			f.AmdDigest = im.Digest
			break
		}
	}
	return f, nil
}

// isDigest is the one shape a digest may have, everywhere in this package.
func isDigest(d string) bool {
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		return false
	}
	for _, c := range d[len("sha256:"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── Is one official digest still served (#984) ───────────────────────────

// The registry API, asked for one manifest by digest. Not the Hub API the
// tag read uses: that one answers about tags, and a rollback needs to know
// about a digest whose tag may have moved on. An anonymous pull token for
// this one repository, then a HEAD for the manifest. Both constants, for the
// reason OfficialImageRepo is one.
const (
	officialRegistryTokenURL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" +
		OfficialImageRepo + ":pull"
	officialRegistryManifestURL = "https://registry-1.docker.io/v2/" + OfficialImageRepo + "/manifests/"
	// officialManifestAccept names every manifest shape the repository may
	// hold, so the registry answers about the digest rather than refusing
	// the media type. An index is what a release tag points at.
	officialManifestAccept = "application/vnd.oci.image.index.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, " +
		"application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.v2+json"
	officialTokenMaxBytes = 1 << 16
)

// OfficialDigestPublished answers whether the official repository still
// serves this exact digest, which is what a rollback to a pruned official
// image fetches (#984).
//
// The tag is asked first, because it is the read this package already
// trusts and it usually settles it: the tag for the release still points at
// the digest. When it has moved, the digest passes only if this node's own
// ledger shows a run here completed on it as that release, and the registry
// still serves it by digest. Fails closed, and
// every negative names what it could not read, so an unreachable registry
// reads as unreachable rather than as "not carried".
func (s *State) OfficialDigestPublished(version, digest string) (bool, string) {
	if !isDigest(digest) {
		return false, fmt.Sprintf("%q is not a digest, so there is nothing to ask the official repository for", trunc(digest, 80))
	}
	f, err := s.OfficialTag(version)
	if err != nil {
		return false, fmt.Sprintf("the official registry could not be reached to ask about %s (%v), so nothing "+
			"here shows it still serves %s", version, err, digest)
	}
	if f.Exists && (f.IndexDigest == digest || f.AmdDigest == digest) {
		return true, fmt.Sprintf("%s:%s still points at %s, so it can be fetched", OfficialImageRepo, version, digest)
	}
	moved := fmt.Sprintf("no official tag carries %s now", version)
	if f.Exists {
		moved = fmt.Sprintf("the official %s tag now points at %s", version, f.IndexDigest)
	}
	// With the tag gone from it, the registry serving a digest says nothing
	// about which release it is: the same repository publishes development
	// builds under commit-hash tags, and the pull tags whatever it fetched
	// as the target version. Only this node's own record can say the digest
	// is that release: a run here completed on it, as that version (review
	// of PR #1000). Asked before the network, so an unvouched digest costs
	// no registry call.
	if ok, why := s.RanOfficialDigest(version, digest); !ok {
		return false, fmt.Sprintf("%s, and %s, so nothing shows %s is %s", moved, why, digest, version)
	}
	served, err := s.officialManifestServed(digest)
	switch {
	case err != nil:
		return false, fmt.Sprintf("%s, and the official registry could not be reached to ask for %s itself (%v)",
			moved, digest, err)
	case served:
		return true, fmt.Sprintf("%s, but the official repository still serves %s by digest, so it can be fetched",
			moved, digest)
	}
	return false, fmt.Sprintf("%s, and the official repository no longer serves %s", moved, digest)
}

// RanOfficialDigest reports whether this node's own ledger shows a run that
// completed on this digest as this version: a step that read the image at
// that digest for that version (image-digest or pull, which record the
// digest they read), and a completion of the same plan reporting that
// version. Both from one plan, so a digest read in one run cannot borrow a
// version reported by another.
func (s *State) RanOfficialDigest(version, digest string) (bool, string) {
	if s.LedgerPath == "" {
		return false, "this node's record of its own runs was not available to read"
	}
	entries, err := ledger.Entries(s.LedgerPath)
	if err != nil && len(entries) == 0 {
		return false, fmt.Sprintf("this node's record of its own runs could not be read (%v)", err)
	}
	bare := func(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }
	want := bare(version)
	read := map[string]bool{}
	// Rows a ledger repair carried inside its own row are still this node's
	// record of its runs.
	entries, dropped := ledger.WithCarried(entries)
	for _, d := range dropped {
		log.Printf("[ledger] %s", d)
	}
	for _, e := range entries {
		if e.Kind != ledger.KindStepSucceeded || e.PlanID == "" {
			continue
		}
		verb, _ := e.Data["verb"].(string)
		d, _ := e.Data["digest"].(string)
		arg, _ := e.Data["arg"].(string)
		if (verb == "image-digest" || verb == "pull") && d == digest && bare(arg) == want {
			read[e.PlanID] = true
		}
	}
	for _, e := range entries {
		if e.Kind != ledger.KindRunCompleted && e.Kind != ledger.KindRunConfirmedLate {
			continue
		}
		if v, _ := e.Data["version"].(string); read[e.PlanID] && bare(v) == want {
			return true, fmt.Sprintf("a run on this node completed on it as %s (%s)", version, e.PlanID)
		}
	}
	return false, fmt.Sprintf("no run on this node completed on it as %s", version)
}

// officialManifestServed asks the registry for one manifest by digest. A 200
// whose own digest header names the same digest is served, a 404 is not, and
// anything else is an error rather than either answer.
func (s *State) officialManifestServed(digest string) (bool, error) {
	req, err := http.NewRequestWithContext(s.context(), http.MethodGet, officialRegistryTokenURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("asking for a pull token: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, officialTokenMaxBytes))
	resp.Body.Close()
	if err != nil {
		return false, fmt.Errorf("reading the pull token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("the token service returned %s", resp.Status)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Token == "" {
		return false, fmt.Errorf("the token service answered without a token")
	}

	req, err = http.NewRequestWithContext(s.context(), http.MethodHead, officialRegistryManifestURL+digest, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", officialManifestAccept)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err = s.HTTP.Do(req)
	if err != nil {
		return false, fmt.Errorf("asking for the manifest: %w", err)
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
			return false, fmt.Errorf("the registry answered for %q when asked for %s", trunc(got, 80), digest)
		}
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("the registry returned %s for the manifest", resp.Status)
}

// ── What an image says about itself ──────────────────────────────────────

// ImageOrigin is where a node's image came from. Three values, because two
// booleans cannot express three origins and the rollback needs to know
// which verb puts each one back.
type ImageOrigin string

const (
	// OriginLocalBuild is an image this host built from the signed package.
	OriginLocalBuild ImageOrigin = "local-build"
	// OriginOfficial is the XRPL release process's own image.
	OriginOfficial ImageOrigin = "official"
	// OriginThirdParty is any other registry.
	OriginThirdParty ImageOrigin = "third-party"
	// OriginUnknown is a reference nothing could be read from.
	OriginUnknown ImageOrigin = "unknown"
)

// OriginOf decides an image's origin from the reference itself, read off the
// host rather than from a configured repository: a node is mid-upgrade or
// mid-rollback often enough that the configuration and the file disagree,
// and the file is what compose will act on.
func OriginOf(ref string) ImageOrigin {
	switch {
	case ref == "":
		return OriginUnknown
	case strings.HasPrefix(ref, LocalImageRepo+":"), strings.HasPrefix(ref, LocalImageRepo+"@"):
		return OriginLocalBuild
	case strings.HasPrefix(ref, OfficialImageRepo+":"), strings.HasPrefix(ref, OfficialImageRepo+"@"):
		return OriginOfficial
	default:
		return OriginThirdParty
	}
}

// Sentence is the origin in the words a card uses.
func (o ImageOrigin) Sentence() string {
	switch o {
	case OriginLocalBuild:
		return "built on this host from the signed package"
	case OriginOfficial:
		return "the official image"
	case OriginThirdParty:
		return "a registry image"
	default:
		return "an image whose origin could not be read"
	}
}

// ImageProvenance is what the wrapper's image-provenance verb reports: what
// an image says about its own origin, plus the hash of the binary it holds.
type ImageProvenance struct {
	Ref          string
	Digest       string
	DebSHA256    string
	Base         string
	User         string
	Entrypoint   string
	Cmd          string
	BinarySHA256 string
	// Read is false when the verb would not answer. #679's rule: an
	// unmeasurable check must not read as a pass.
	Read bool
	Note string
}

// ParseImageProvenance reads the verb's key=value lines. Unknown keys are
// ignored rather than raised: the verb may learn a field before this does,
// and a new line is not a reason to refuse an upgrade.
func ParseImageProvenance(out string) ImageProvenance {
	var p ImageProvenance
	for _, ln := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "ref":
			p.Ref = v
		case "digest":
			p.Digest = v
		case "deb_sha256":
			p.DebSHA256 = v
		case "base":
			p.Base = v
		case "user":
			p.User = v
		case "entrypoint":
			p.Entrypoint = v
		case "cmd":
			p.Cmd = v
		case "binary_sha256":
			p.BinarySHA256 = v
		}
	}
	p.Read = p.Ref != "" && isHex64(p.BinarySHA256)
	if !p.Read {
		p.Note = "the image would not report what it holds"
	}
	return p
}

func isHex64(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ImageProvenanceNow asks the wrapper about a version's image on this host.
func (s *State) ImageProvenanceNow(version string) (ImageProvenance, error) {
	out, err := s.wrapperOut("image-provenance", version)
	if err != nil {
		return ImageProvenance{Note: err.Error()}, err
	}
	return ParseImageProvenance(out), nil
}

// SignedRelease is what the XRPL Foundation's signed package chain says a
// release is: the package apt verified, the SHA-256 of the xrpld binary
// inside it, and what that binary reports about itself.
//
// This is the check the operator ruled must happen before a swap, and it is
// the only one that binds the bytes that would run to the Foundation's
// signing key: the image's DEB_SHA256 and its --version are claims about a
// package its build fetched off an upload host and hashed once.
//
// Commit is where "the announced commit" comes from. Not a table somebody
// types a hash into after reading an announcement (#668 decision 1 rules
// that out, and a release with no row would have nothing to compare
// against): the binary the signed chain just verified, saying so itself.
// Empty when the build does not print one, and the caller says so rather
// than treating silence as a match.
type SignedRelease struct {
	Package      string
	BinarySHA256 string
	Version      string
	Commit       string
}

// SignedReleaseNow derives all of it, fresh, every time it is asked.
func (s *State) SignedReleaseNow(version string) (SignedRelease, error) {
	var r SignedRelease
	out, err := s.wrapperOut("signed-binary-sha256", version)
	if err != nil {
		return r, err
	}
	for _, ln := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "package":
			r.Package = v
		case "binary_sha256":
			r.BinarySHA256 = v
		case "binary_version":
			r.Version = v
		case "binary_commit":
			r.Commit = v
		}
	}
	if !isHex64(r.BinarySHA256) {
		return SignedRelease{}, fmt.Errorf(
			"the signed package chain answered with %q for %s's binary, which is not a sha256",
			trunc(r.BinarySHA256, 70), version)
	}
	if r.Version != version {
		return SignedRelease{}, fmt.Errorf(
			"asked the signed package chain for %s and its binary reports %q", version, trunc(r.Version, 24))
	}
	if r.Commit != "" && !isCommit(r.Commit) {
		return SignedRelease{}, fmt.Errorf(
			"the signed package chain answered with %q for %s's commit", trunc(r.Commit, 50), version)
	}
	return r, nil
}

// isCommit is the one shape a git commit may have here.
func isCommit(v string) bool {
	if len(v) != 40 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// wrapperOut runs one wrapper verb and returns its stdout. The same shape
// every other reader in this package uses, in one place because #682 adds
// four of them.
func (s *State) wrapperOut(verb string, args ...string) (string, error) {
	if s.Wrapper == "" {
		return "", fmt.Errorf("no privilege wrapper is configured, so %s was not asked", verb)
	}
	name := s.Wrapper
	argv := append([]string{verb}, args...)
	out, err := s.Runner.Run(s.context(), name, argv...)
	if err != nil {
		return "", fmt.Errorf("the wrapper refused %s: %v", verb, err)
	}
	return string(out), nil
}

// ── Verification, before any swap ────────────────────────────────────────

// VerifyCheck is one named check, with both values, so a failure can be
// rendered as what was expected against what was found rather than as a
// verdict nobody can argue with.
type VerifyCheck struct {
	Name     string
	Pass     bool
	Expected string
	Found    string
	// Measured is false when the check could not be run at all. An
	// unmeasured check is never a pass (#679); it stops the swap and says
	// what it could not read.
	Measured bool
	Detail   string
}

// VerifyOfficialImage holds an image to the four facts the ruling names,
// each on its own so a failure says which one.
//
// Pure: everything it compares has already been read, so the whole thing is
// testable offline and each check can be failed on its own in a test.
//
//   - signed is what the Foundation's signed chain says this release is:
//     its binary's hash, and the commit that binary reports. Both derived,
//     neither typed. An empty Commit means the build prints none, and the
//     first check then holds the image to the version string alone and
//     says so.
//   - indexSHA256 is the .deb hash the package index publishes for the
//     target, read fresh from the index rather than from any file.
func VerifyOfficialImage(version, indexSHA256, versionOut string, signed SignedRelease, p ImageProvenance) (bool, []VerifyCheck) {
	checks := []VerifyCheck{
		verifyVersionAndCommit(version, signed.Commit, versionOut),
		verifyPackageHash(indexSHA256, p),
		verifyBaseAndUser(p),
		verifyBinary(signed.BinarySHA256, p),
	}
	all := true
	for _, c := range checks {
		if !c.Pass || !c.Measured {
			all = false
		}
	}
	return all, checks
}

func verifyVersionAndCommit(version, announcedCommit, versionOut string) VerifyCheck {
	c := VerifyCheck{Name: "it reports the release the announcement names"}
	out := strings.TrimSpace(versionOut)
	if out == "" {
		c.Detail = "the image would not report a version, so what it holds is unproven"
		return c
	}
	c.Measured = true
	gotVersion := ""
	gotCommit := ""
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if v, ok := strings.CutPrefix(t, "xrpld version "); ok {
			gotVersion = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(t, "rippled version "); ok {
			gotVersion = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(t, "Git commit hash: "); ok {
			gotCommit = strings.TrimSpace(v)
		}
	}
	if announcedCommit == "" {
		c.Expected = "xrpld version " + version
		c.Found = "xrpld version " + gotVersion
		c.Pass = gotVersion == version
		c.Detail = "the signed package's own binary prints no commit for " + version +
			", so this is the version string alone"
		return c
	}
	c.Expected = "xrpld version " + version + ", git commit " + announcedCommit
	c.Found = "xrpld version " + gotVersion + ", git commit " + gotCommit
	c.Pass = gotVersion == version && gotCommit == announcedCommit
	return c
}

func verifyPackageHash(indexSHA256 string, p ImageProvenance) VerifyCheck {
	c := VerifyCheck{Name: "it was built from the same package this node would have built from"}
	if !isHex64(indexSHA256) {
		c.Detail = "the package index did not give a SHA-256 for this release, so there is nothing to compare the image against"
		return c
	}
	if !isHex64(p.DebSHA256) {
		c.Measured = true
		c.Expected = indexSHA256
		c.Found = "the image records no package hash"
		return c
	}
	c.Measured = true
	c.Expected = indexSHA256
	c.Found = p.DebSHA256
	c.Pass = p.DebSHA256 == indexSHA256
	return c
}

func verifyBaseAndUser(p ImageProvenance) VerifyCheck {
	c := VerifyCheck{Name: "base and runtime account are what was expected"}
	if p.Base == "" || p.Base == "unknown" {
		c.Detail = "the image would not name its base"
		return c
	}
	c.Measured = true
	c.Expected = "a named account, not root"
	c.Found = p.Base + ", runs as " + userOrRoot(p.User)
	// The base is recorded, not required to be any particular thing: the
	// official image is ubuntu:22.04 and ours is 24.04, and neither is
	// wrong. What IS required is that the image does not default to root:
	// an image with no USER runs as uid 0 wherever a deployment names no
	// user, which is the #668 refusal this keeps in front of the swap.
	c.Pass = p.User != "" && p.User != "root" && p.User != "0" && !strings.HasPrefix(p.User, "0:")
	if !c.Pass {
		c.Detail = "the image names no account of its own, so it would run as root wherever a deployment names no user"
	}
	return c
}

func userOrRoot(u string) string {
	if u == "" {
		return "root"
	}
	return u
}

func verifyBinary(signedBinary string, p ImageProvenance) VerifyCheck {
	c := VerifyCheck{Name: "the binary is the binary in the signed package"}
	if !isHex64(signedBinary) {
		c.Detail = "the signed package chain did not answer, so the bytes this image would run are unproven"
		return c
	}
	if !isHex64(p.BinarySHA256) {
		c.Measured = true
		c.Expected = signedBinary
		c.Found = "the image would not hash its own /usr/bin/xrpld"
		return c
	}
	c.Measured = true
	c.Expected = signedBinary
	c.Found = p.BinarySHA256
	c.Pass = p.BinarySHA256 == signedBinary
	return c
}

// ── What the root-side verify verb answered ──────────────────────────────
//
// #682, review of 2026-09-27. Everything that decides whether a node may
// take an official image is measured on the HOST, by the wrapper's
// verify-official-image verb, with none of that image's own code running:
// the container is created and never started, and the binary is streamed
// out of it with docker cp and hashed here. This is the reading of that
// verb's answer, and the checks below are what the run path refuses on.
//
// The shape this replaces was unsound and shipped green: the steps only
// checked that a `binary_sha256=` line appeared, the hash on it came from
// the image's OWN sha256sum, and VerifyOfficialImage had no caller outside
// a test. A prepare stage with the wrong commit, the wrong binary hash, an
// unknown package hash and no runtime user completed with no error, and a
// compound grant chains straight into the cutover.
type VerifyOfficial struct {
	Ref                 string
	Digest              string
	Version             string
	BinarySHA256        string // measured on this host, out of the image
	SignedBinarySHA256  string // out of the .deb apt verified
	SignedBinaryVersion string
	SignedBinaryCommit  string
	DebSHA256           string // the image's own claim
	IndexSHA256         string // the signed index's, read fresh
	Base                string
	User                string
	LDPreload           string // absent | present
	LDEnv               string // none, or the LD_* names the image sets
	PackageFiles        string // yes | no | unmeasured
	// LoadedFiles is the verdict on everything in the image that decides
	// what the node's process loads: every shared object and every loader
	// configuration file, against the image's own package records (#682,
	// second review). The binary's hash covers one file; an NSS module
	// dropped beside it runs inside xrpld's own process.
	LoadedFiles       string // yes | no | unmeasured
	LoadedFilesDetail string
	// BaseLayer is the first layer of the image, recorded per release so a
	// base that moves under a release is visible in the record.
	BaseLayer          string
	PackageFilesDetail string
	Verified           string // yes | no
	// SignedPackage is the revision the signed chain read (xrpld=3.4.1-1),
	// chosen by the image's own package hash, and NewestRevision the newest
	// signed revision of the release (3.4.1-2). They differ when the image
	// carries a superseded revision, which still verifies (#1001).
	SignedPackage  string
	NewestRevision string
	Read           bool
	Note           string
}

// SupersededNote is the one line said when a verified image carries a
// package revision that is not the newest signed revision of its release.
// Information only, by the operator's ruling on #1001: the image is the
// signed package it names, and an older revision is still a signed one.
// Empty when the image carries the newest revision, did not verify, or the
// newest could not be read.
func (v VerifyOfficial) SupersededNote() string {
	pkg := strings.TrimPrefix(v.SignedPackage, XrpldPackage+"=")
	if v.Verified != "yes" || pkg == "" || v.NewestRevision == "" || v.NewestRevision == "unknown" ||
		pkg == v.NewestRevision {
		return ""
	}
	return "This image carries package " + pkg + "; " + v.NewestRevision + " is the newest signed revision."
}

// ParseVerifyOfficial reads the verb's key=value lines. Unknown keys are
// ignored; a missing one leaves its field empty, and Checks below refuses
// an empty field rather than treating it as agreement.
func ParseVerifyOfficial(out string) VerifyOfficial {
	var v VerifyOfficial
	for _, ln := range strings.Split(out, "\n") {
		k, val, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "ref":
			v.Ref = val
		case "digest":
			v.Digest = val
		case "version":
			v.Version = val
		case "binary_sha256":
			v.BinarySHA256 = val
		case "signed_binary_sha256":
			v.SignedBinarySHA256 = val
		case "signed_binary_version":
			v.SignedBinaryVersion = val
		case "signed_binary_commit":
			v.SignedBinaryCommit = val
		case "deb_sha256":
			v.DebSHA256 = val
		case "index_sha256":
			v.IndexSHA256 = val
		case "base":
			v.Base = val
		case "user":
			v.User = val
		case "ld_preload":
			v.LDPreload = val
		case "ld_env":
			v.LDEnv = val
		case "loaded_files":
			v.LoadedFiles = val
		case "loaded_detail":
			v.LoadedFilesDetail = val
		case "base_layer":
			v.BaseLayer = val
		case "package_files":
			v.PackageFiles = val
		case "package_files_detail":
			v.PackageFilesDetail = val
		case "verified":
			v.Verified = val
		case "signed_package":
			v.SignedPackage = val
		case "newest_revision":
			v.NewestRevision = val
		}
	}
	v.Read = v.Ref != "" && v.Digest != ""
	if !v.Read {
		v.Note = "the verify verb answered nothing this side recognises"
	}
	return v
}

// Checks is the verdict, one named check at a time, each with both values.
// EVERY one has to be measured and equal: an unmeasured check is never a
// pass (#679), and this is the one place on the run path where that rule
// decides whether a validator takes somebody else's image.
func (v VerifyOfficial) Checks(target, digest string) (bool, []VerifyCheck) {
	var out []VerifyCheck
	add := func(c VerifyCheck) { out = append(out, c) }

	c := VerifyCheck{Name: "the verify ran on this host and answered"}
	c.Measured = v.Read
	c.Expected, c.Found = "a reading of "+digest, v.Ref+" "+v.Digest
	c.Pass = v.Read && v.Digest == digest && v.Version == target
	if !c.Pass {
		c.Detail = "the answer is about " + trunc(v.Digest, 80) + " for " + trunc(v.Version, 24) +
			", and this plan is about " + trunc(digest, 80) + " for " + trunc(target, 24)
	}
	add(c)

	c = VerifyCheck{Name: "the binary is the binary in the signed package"}
	c.Measured = isHex64(v.BinarySHA256) && isHex64(v.SignedBinarySHA256)
	c.Expected, c.Found = v.SignedBinarySHA256, v.BinarySHA256
	c.Pass = c.Measured && v.BinarySHA256 == v.SignedBinarySHA256
	if !c.Measured {
		c.Detail = "one of the two hashes was not produced, so the bytes that would run are unproven"
	}
	add(c)

	c = VerifyCheck{Name: "it reports the release the signed package's own binary reports"}
	c.Measured = v.SignedBinaryVersion != "" && v.SignedBinaryVersion != "unknown"
	c.Expected, c.Found = target, v.SignedBinaryVersion
	c.Pass = c.Measured && v.SignedBinaryVersion == target
	add(c)

	c = VerifyCheck{Name: "nothing loads before the node's own code"}
	c.Measured = v.LDPreload != "" && v.LDEnv != ""
	c.Expected = "no /etc/ld.so.preload and no LD_* in the image's environment"
	c.Found = "ld.so.preload " + v.LDPreload + ", environment " + v.LDEnv
	c.Pass = c.Measured && v.LDPreload == "absent" && v.LDEnv == "none"
	if c.Measured && !c.Pass {
		c.Detail = "the binary's hash says nothing about a library loaded into the process before it"
	}
	add(c)

	c = VerifyCheck{Name: "every file the package owns is the file the signed package ships"}
	c.Measured = v.PackageFiles == "yes" || v.PackageFiles == "no"
	c.Expected, c.Found = "yes", v.PackageFiles
	c.Pass = v.PackageFiles == "yes"
	c.Detail = v.PackageFilesDetail
	add(c)

	c = VerifyCheck{Name: "nothing else in it loads into the node's process unaccounted for"}
	c.Measured = v.LoadedFiles == "yes" || v.LoadedFiles == "no"
	c.Expected, c.Found = "yes", v.LoadedFiles
	c.Pass = v.LoadedFiles == "yes"
	c.Detail = v.LoadedFilesDetail
	if !c.Measured {
		c.Detail = "the image's shared objects and loader files were not read: " + v.LoadedFilesDetail
	}
	add(c)

	c = VerifyCheck{Name: "it was built from the package the signed index publishes"}
	c.Measured = isHex64(v.IndexSHA256) && isHex64(v.DebSHA256)
	c.Expected, c.Found = v.IndexSHA256, v.DebSHA256
	c.Pass = c.Measured && v.DebSHA256 == v.IndexSHA256
	if !c.Measured {
		c.Detail = "the image records no package hash, or the index published none for this release"
	}
	add(c)

	c = VerifyCheck{Name: "it runs as an account of its own"}
	c.Measured = v.User != ""
	c.Expected = "a named account, not root"
	c.Found = userOrRoot(strings.TrimSuffix(v.User, "unset"))
	c.Pass = v.User != "" && v.User != "unset" && v.User != "root" && v.User != "0" &&
		!strings.HasPrefix(v.User, "0:")
	add(c)

	c = VerifyCheck{Name: "the host's own verdict"}
	c.Measured = v.Verified != ""
	c.Expected, c.Found = "yes", v.Verified
	c.Pass = v.Verified == "yes"
	add(c)

	all := true
	for _, x := range out {
		if !x.Pass || !x.Measured {
			all = false
		}
	}
	return all, out
}

// FailedChecks is the sentence a step refuses with: which checks failed,
// with both values, so nobody has to go and look.
func FailedChecks(checks []VerifyCheck) string {
	var bad []string
	for _, c := range checks {
		if c.Pass && c.Measured {
			continue
		}
		s := c.Name
		if !c.Measured {
			s += ": not measured"
			if c.Detail != "" {
				s += " (" + c.Detail + ")"
			}
		} else {
			s += ": expected " + trunc(c.Expected, 80) + ", found " + trunc(c.Found, 80)
			if c.Detail != "" {
				s += " (" + c.Detail + ")"
			}
		}
		bad = append(bad, s)
	}
	return strings.Join(bad, "; ")
}

// ── The package index's own hash for a release ───────────────────────────

// PackageIndexSHA256 is the .deb SHA-256 the signed index publishes for one
// release. Read fresh, every time, so nothing downstream compares an image
// against a number somebody typed.
func (s *State) PackageIndexSHA256(version string) (string, error) {
	raw, err := s.packagesIndexBody()
	if err != nil {
		return "", err
	}
	if h := DebSHA256For(raw, XrpldPackage, version); h != "" {
		return h, nil
	}
	if n := debRevisionsOf(raw, XrpldPackage, version); n > 1 {
		return "", fmt.Errorf("the package index at %s lists %s %s as %d package revisions, each its own .deb; "+
			"which one an image carries is its own package hash's to say, and the first or newest is never assumed",
			PackagesIndexSource, XrpldPackage, version, n)
	}
	return "", fmt.Errorf("the package index at %s lists no %s %s", PackagesIndexSource, XrpldPackage, version)
}

// DebSHA256For finds one release's .deb hash in a Debian Packages index.
// Exported so the test can hold it to a real index body.
//
// Only when the release is published as exactly one .deb (#1001). xrpld
// 3.4.1 has two revisions since 2026-10-09, each with its own binary, and
// "the first stanza for 3.4.1" is one of them picked by the index's order.
// The wrapper's verify picks by the image's own package hash; a lookup that
// is given only a release has nothing to pick by, so it answers nothing.
func DebSHA256For(text, pkg, version string) string {
	if pkg == "" {
		pkg = XrpldPackage
	}
	hashes := debHashesOf(text, pkg, version)
	if len(hashes) != 1 {
		return ""
	}
	for h := range hashes {
		return h
	}
	return ""
}

// debHashesOf is every distinct .deb hash the index lists for one release.
func debHashesOf(text, pkg, version string) map[string]bool {
	body := strings.ReplaceAll(text, "\r\n", "\n")
	out := map[string]bool{}
	for _, stanza := range stanzas(body) {
		if fieldOf(stanza, "Package") != pkg {
			continue
		}
		if ReleaseFromDebVersion(fieldOf(stanza, "Version")) != version {
			continue
		}
		if h := fieldOf(stanza, "SHA256"); isHex64(h) {
			out[h] = true
		}
	}
	return out
}

func debRevisionsOf(text, pkg, version string) int { return len(debHashesOf(text, pkg, version)) }
