package host

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aperire-advisor/internal/runbook"
)

// The signed package index, and the image a container node builds from it.
//
// From 3.4.x on, an xrpld release ships as a signed DEB package first, and
// sometimes only as one: 3.4.1 exists at packages.xrplf.org, has no source
// tag on GitHub, and has no official Docker image anywhere. Docker Hub is
// therefore no longer an answer to "is there a newer release" for a
// container node, and it was giving the wrong one: xrpllabsofficial/xrpld
// stops at 3.3.0, so a node sitting on an amendment-blocking deadline would
// have been told it was current.
//
// So both release questions a container asks are asked of the package index,
// which is where the release actually is:
//
//	LatestRelease    what is the newest xrpld release
//	ImagePublished   can this host get the version a plan names
//
// The answer feeds a build on this host, not a pull: the Advisor builds
// localhost/xrpld:<release> from that same signed package (operator ruling,
// 2026-09-26), which is why "published" and "installable" are one question
// here rather than the two they used to be.
//
// This is a second implementation of a parser the dashboard also has
// (dashboard/lib/release-feed.ts, #660), and that is deliberate rather than
// careless. The alternative was to carry the fact across the ADR 0008 read
// API, which would make an Advisor on a host with no dashboard unable to
// answer a question about its own node, exactly the coupling ADR 0016 took
// out. The two parsers hold to the same rules and are tested against the
// same fixture, byte for byte, so a drift between them fails a test rather
// than a host.

// LocalImageRepo is the name a locally built xrpld image carries. The
// localhost/ prefix can never resolve to a registry: a pull of it dials
// https://localhost/ and fails, rather than fetching somebody else's image
// under a name that looks like ours.
const LocalImageRepo = "localhost/xrpld"

// PackagesIndexURL is the index of the repository the install guide's apt
// line configures:
//
//	deb [signed-by=…] https://packages.xrplf.org/repository/deb-stable any main
//
// The repository is a Nexus apt host with no directory listing; its Release
// file names exactly this path, and only amd64.
const PackagesIndexURL = "https://packages.xrplf.org/repository/deb-stable/dists/any/main/binary-amd64/Packages"

// PackagesIndexSource is what to call that origin in a sentence an operator
// reads.
const PackagesIndexSource = "packages.xrplf.org"

// packagesIndexMaxBytes is well past any real size. The real index is under
// 4 KB.
const packagesIndexMaxBytes = 1 << 20

// XrpldPackage is the package name an xrpld release is published under.
// Named because two other packages in the same index carry the same version
// numbers and are not it, see ParseDebPackagesIndex.
const XrpldPackage = "xrpld"

// The shape AND the size. Digits and dots is not a bound: a Version line of
// a megabyte of digits is digits and dots, and it would ride from the index
// all the way to the card as a release to offer. Same limit the wrapper's
// require_version holds and the same one versionish() applies on the native
// path, so an index entry can never name a version the executor would then
// refuse.
var releaseRe = regexp.MustCompile(`^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$`)

// releaseMaxLen is that limit's other half, checked before the pattern so a
// pathological line is dropped without running a regex over it.
const releaseMaxLen = 24

// ReleaseFromDebVersion maps a Debian version ([epoch:]upstream[-revision])
// to the release it packages, or "" when that is not a plain dotted release.
// 3.4.1-1 is 3.4.1. A pre-release (3.5.0~rc1-1) is "", the same way the
// GitHub read skips pre-releases: an operator is never nudged toward one.
func ReleaseFromDebVersion(debVersion string) string {
	v := strings.TrimSpace(debVersion)
	// Bounded before anything else. An index is a file fetched over the
	// network, and every later reader of this string (the card, a plan
	// parameter, a build argument) is entitled to assume it is a release.
	if len(v) > releaseMaxLen {
		return ""
	}
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	if len(v) > releaseMaxLen || !releaseRe.MatchString(v) {
		return ""
	}
	return v
}

// ParseDebPackagesIndex lists every release of pkg in a Debian Packages
// index, oldest first, without repeats.
//
// Only a stanza whose own Package: is exactly pkg counts. The same index
// carries xrpld-assert, which Provides: xrpld, and the -dbgsym packages;
// both carry the same version numbers and neither is the release an operator
// installs. Anything unparseable is skipped rather than raised: an index
// half-read is not a version to recommend, and a 404 page is not an error
// this needs to describe twice.
func ParseDebPackagesIndex(text, pkg string) []string {
	if pkg == "" {
		pkg = XrpldPackage
	}
	body := strings.ReplaceAll(text, "\r\n", "\n")
	seen := map[string]bool{}
	var out []string
	for _, stanza := range stanzas(body) {
		if fieldOf(stanza, "Package") != pkg {
			continue
		}
		rel := ReleaseFromDebVersion(fieldOf(stanza, "Version"))
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		out = append(out, rel)
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) < 0 })
	return out
}

// stanzas splits a Debian control file on blank lines. A line holding only
// spaces or tabs separates too, which is what the dashboard's own split does.
func stanzas(body string) []string {
	var out []string
	var cur []string
	for _, ln := range strings.Split(body, "\n") {
		if strings.TrimSpace(ln) == "" {
			if len(cur) > 0 {
				out = append(out, strings.Join(cur, "\n"))
				cur = nil
			}
			continue
		}
		cur = append(cur, ln)
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, "\n"))
	}
	return out
}

// fieldOf reads a field from one stanza. Only a line that IS the field, at
// the start of a line with nothing after the value, so a Depends: line
// naming xrpld cannot be read as the stanza's own Package.
func fieldOf(stanza, key string) string {
	for _, ln := range strings.Split(stanza, "\n") {
		if !strings.HasPrefix(ln, key+":") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(ln, key+":"))
		if v == "" || strings.ContainsAny(v, " \t") {
			return ""
		}
		return v
	}
	return ""
}

// packagesIndexReleases fetches the index and returns every xrpld release in
// it, oldest first.
//
// Fails closed, like every read in this package: an index that could not be
// fetched or that carried no xrpld stanza is an error, never an empty list
// that would read as "nothing newer exists".
func (s *State) packagesIndexReleases() ([]string, error) {
	raw, err := s.packagesIndexBody()
	if err != nil {
		return nil, err
	}
	rel := ParseDebPackagesIndex(raw, XrpldPackage)
	if len(rel) == 0 {
		return nil, fmt.Errorf("the package index at %s lists no %s release", PackagesIndexSource, XrpldPackage)
	}
	return rel, nil
}

// packagesIndexBody is the index itself, fetched once and handed to whoever
// asked. Two readers now: the release list, and the .deb SHA-256 an
// official image's own DEB_SHA256 is measured against (#682).
func (s *State) packagesIndexBody() (string, error) {
	// Before the index is read at all: is this node the software that index
	// publishes? A fork with its own repository and its own amendment set
	// offered an xrpld release is not being offered an upgrade, it is being
	// offered a different program.
	if err := s.xrpldFamilyOrRefusal(); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(s.context(), http.MethodGet, PackagesIndexURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", PackagesIndexSource, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, packagesIndexMaxBytes))
	if err != nil {
		return "", fmt.Errorf("could not read the package index: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned %s for the package index", PackagesIndexSource, resp.Status)
	}
	return string(raw), nil
}

// packagesIndexNewest is LatestRelease's container half: the newest xrpld
// release the signed package repository carries.
func (s *State) packagesIndexNewest() (string, error) {
	rel, err := s.packagesIndexReleases()
	if err != nil {
		return "", err
	}
	return rel[len(rel)-1], nil
}

// packagesIndexHas answers ImagePublished's container half: is this exact
// version in the signed package repository, which is where a build on this
// host would take it from.
func (s *State) packagesIndexHas(version string) (bool, string) {
	if version == "" {
		return false, "no version to look for"
	}
	rel, err := s.packagesIndexReleases()
	if err != nil {
		// Inconclusive, not negative, and the wording says so. Both refuse
		// the plan, but an operator reading "could not determine" goes and
		// checks, while one reading "not published" waits for a release that
		// already shipped.
		return false, fmt.Sprintf("could not determine whether %s is published: %v", version, err)
	}
	for _, r := range rel {
		if r == version {
			return true, fmt.Sprintf("%s %s is in the signed package repository at %s, which is where this host builds its image from",
				XrpldPackage, version, PackagesIndexSource)
		}
	}
	return false, fmt.Sprintf("%s %s is not in the signed package repository at %s (it carries %s)",
		XrpldPackage, version, PackagesIndexSource, strings.Join(rel, ", "))
}

// RuntimeAccount reports the account this node's container runs as, what the
// deployment file asks for, and the stop grace the running container was
// created with.
//
// Three readings, one question: does the node come back as the same account
// it went down as. An image swap can change that underneath a node, and on
// this path it can change it silently. The image this project built from the
// signed package defaults to 997:997, and a deployment whose container
// records no user has been running as root, because an image's own default
// is what applies when nothing overrides it. uid 997 on the host is then
// whatever account happened to take that number, which on one lab
// validator's host was another service's account entirely (2026-09-26). The
// store and the wallet are on a volume owned by root there, so the node
// would come up unable to read its own data.
//
// containerUser is empty for a container running as root. composeUser is
// what the deployment file names, empty when it names nothing. stopTimeout
// is the grace the running container carries, empty when it names none, and
// it is here because it is the number a stop actually gets (#665) and an
// operator reading a plan should see it rather than the one in the file.
//
// The deployment file is read in this process, the same way DeploymentTag
// reads it: this is a fact about the file rather than about the node, and
// the wrapper's own verbs answer about the node.
func (s *State) RuntimeAccount() (runbook.RuntimeShape, error) {
	var sh runbook.RuntimeShape
	if s.Kind() == "native" {
		return sh, fmt.Errorf("a native host runs no container")
	}
	sh.ContainerUser = s.Profile.RuntimeUser
	if s.Profile.StopTimeout != nil {
		sh.StopTimeout = strconv.Itoa(*s.Profile.StopTimeout)
	}
	if s.Profile.ComposeFile == "" {
		return sh, fmt.Errorf("the profile records no deployment file")
	}
	raw, rerr := os.ReadFile(s.Profile.ComposeFile)
	if rerr != nil {
		return sh, rerr
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "user:") && sh.ComposeUser == "" {
			sh.ComposeUser = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "user:")), `"'`)
			continue
		}
		// A bind mount landing on the path xrpld reads. Matched on the
		// destination rather than on the source, because the source is
		// wherever this host keeps its config and the destination is the
		// only half that decides whether the entrypoint has work to do.
		if strings.Contains(t, ":"+EtcConfigPath+":") || strings.HasSuffix(t, ":"+EtcConfigPath) {
			sh.ConfigAtEtc = true
		}
	}
	return sh, nil
}

// EtcConfigPath is where xrpld reads its configuration inside the image, and
// where the entrypoint copies /config to when nothing is mounted there.
const EtcConfigPath = "/etc/xrpld/xrpld.cfg"

// ComposeImageRef is the image reference a deployment file names for one
// node: the whole reference, repository and tag.
//
// Three keys, in order, and the order is the point.
//
//  1. The repository the caller knows this node by (the profile's, read from
//     the running container).
//  2. LocalImageRepo, because an upgrade points the file at that before the
//     container it was read from has been replaced.
//  3. The node's own service block, because a ROLLBACK writes the registry
//     repository back while the container still runs the locally built
//     image, and for that moment the file names neither of the first two.
//     That is the moment the cutover reads this to decide whether what it
//     is about to restart is what was approved, and reading it wrong left
//     the node on the version it was rolling back FROM with the file naming
//     the other one.
//
// The third key takes the first image line at or after the service's own
// key, since a service's image precedes the next service's. Empty when the
// file names none of them.
func ComposeImageRef(body, repo, service string) string {
	lines := strings.Split(body, "\n")
	if i := composeImageLine(lines, repo, service); i >= 0 {
		ln := lines[i]
		return imageRefOnLine(ln)
	}
	return ""
}

// imageRefOnLine takes the reference off an image line and leaves anything
// after it behind.
//
// An official image is named by DIGEST, with its tag in a trailing comment
// (`image: rippleci/xrpld@sha256:e77e…  # 3.4.1`): the digest is the only
// thing compose may act on, and the version has nowhere else to live on
// that line. Without this the whole tail travelled as the reference, and a
// DeploymentTag reading the last colon would have answered "3.4.1" out of a
// comment rather than out of anything the node runs.
//
// The comment is never read back as data. What version a node is on comes
// from the node's own build_version.
func imageRefOnLine(ln string) string {
	v := strings.TrimSpace(ln[strings.Index(ln, "image:")+len("image:"):])
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		v = v[:i]
	}
	return v
}

// composeImageLine is ComposeImageRef's index, for the readers that need to
// rewrite or blank the line rather than read it.
func composeImageLine(lines []string, repo, service string) int {
	// "image: " with one space, then the repository, then a colon. The
	// wrapper's own lookbehind is exactly that, and being looser here than
	// the verb that WRITES the line would make the two routes disagree
	// about a file, which is the one property both this and the wrapper's
	// compose_image_ref exist to keep.
	//
	// A fourth shape since #682: the official repository, named by digest
	// rather than by tag. Both separators are matched for it, because the
	// deployment carries `image: rippleci/xrpld@sha256:…` and a reader that
	// only knew the colon form would find no image line on every node that
	// had already taken the official image, and every plan after the first
	// swap would refuse as drift.
	known := func(ln string) bool {
		return (repo != "" && strings.Contains(ln, "image: "+repo+":")) ||
			strings.Contains(ln, "image: "+LocalImageRepo+":") ||
			strings.Contains(ln, "image: "+OfficialImageRepo+":") ||
			strings.Contains(ln, "image: "+OfficialImageRepo+"@")
	}
	for i, ln := range lines {
		if known(ln) {
			return i
		}
	}
	if service == "" {
		return -1
	}
	key := service + ":"
	inService := false
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == key {
			inService = true
			continue
		}
		if !inService {
			continue
		}
		if j := strings.Index(ln, "image: "); j >= 0 &&
			strings.TrimSpace(ln[j+len("image: "):]) != "" {
			return i
		}
	}
	return -1
}
