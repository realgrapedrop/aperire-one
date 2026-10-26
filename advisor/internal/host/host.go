package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"aperire-advisor/internal/runbook"
)

// Doer is the HTTP surface used for the registry and the node's admin RPC.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// State implements runbook.HostState against a live Docker Compose
// deployment. It holds no credentials: the admin RPC is reachable because it
// is bound to loopback, and the registry check is an anonymous read.
type State struct {
	Profile Profile
	Runner  Runner
	HTTP    Doer
	// BackupDir is where dated backups are expected. Empty means "beside the
	// artefact", which is where the Field Guide's cp .bak convention puts them.
	BackupDir string
	// MaxBackupAge bounds how old a backup may be and still count. A backup
	// from six months ago does not describe the config you are about to
	// change, and treating it as cover is worse than having none, because it
	// reads as protection.
	MaxBackupAge time.Duration
	// EvidencePath is the diagnostic snapshot captured before any change.
	EvidencePath string

	// Now is the clock, and it is here for one reason: the amendment check
	// has to be testable on both sides of an enablement date. Nil is
	// time.Now, which is what every caller but a test uses.
	Now func() time.Time
	// Wrapper is the privilege wrapper. Set when this process must not open
	// the node's files itself — which is the arrangement that lets the
	// Advisor's account be refused the config directory outright, so §7's
	// "never reads validator key material" is enforced by the filesystem
	// rather than by this code choosing not to look. How a call to it
	// reaches root is the Runner's business (ViaWrapper and its socket, ADR
	// 0025), never sudo. Empty Wrapper means read directly, which is what the
	// operator running the CLI on their own account does.
	Wrapper string

	// amendmentSafety is RollbackSafeFromAmendments' answer, per target,
	// for the life of this State. A State is built per request, so this
	// shares one reading between the two places a rollback gate renders it
	// rather than caching an answer across requests (#676).
	amendmentSafety map[string]runbook.Measurement

	// LedgerPath is this node's own ledger, read for one question only:
	// did a run here complete on an official digest as a given release
	// (#984). Empty means no ledger to read, and that question answers no.
	LedgerPath string

	ctx context.Context

	// The server_info reads taken on this State and whether any failed,
	// behind a lock because an evaluation can read from more than one
	// goroutine. See NodeRead.
	infoMu     sync.Mutex
	infoReads  int
	infoFailed bool
}

// New builds a State with the defaults the v1 runbooks assume.
func New(ctx context.Context, p Profile, r Runner, h Doer) *State {
	return &State{
		Profile:      p,
		Runner:       r,
		HTTP:         h,
		MaxBackupAge: 7 * 24 * time.Hour,
		ctx:          ctx,
	}
}

func (s *State) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// Kind normalises the recorded profile's shape to what every kind-aware
// precondition and plan branches on. Anything that is not literally "native"
// reads as a container, the same rule the wrapper's own KIND parsing
// follows, so a profile from before the native design note, or one nobody
// has set, describes exactly the host it always did.
func (s *State) Kind() string {
	if s.Profile.Kind == "native" {
		return "native"
	}
	return "container"
}

// ProfileMatches re-reads the deployment and compares it to the recorded
// profile. ADR 0005: checked before every plan rather than trusted from setup.
func (s *State) ProfileMatches() (bool, string) {
	live, err := DiscoverProfile(s.context(), s.Runner, s.Profile.Container, s.Profile.AdminRPC)
	if err != nil {
		return false, fmt.Sprintf("could not re-read the deployment: %v", err)
	}
	if d := s.Profile.Differs(live); len(d) > 0 {
		return false, "profile no longer describes the host — " + strings.Join(d, "; ")
	}
	if live.Kind == "native" {
		// Unit and package only, same reasoning as the compose case below:
		// no path, no version, this is shown to every role, and the paths
		// are already in the profile for anyone who holds the state directory.
		return true, fmt.Sprintf("%s (%s)", live.Unit, live.Package)
	}
	// Project and service name only. The compose file's path is a location
	// on the host, and this detail is shown to every role (the card's verdicts,
	// the Advisor's assessment reads); the path is in the profile for anyone
	// who holds the state directory.
	return true, fmt.Sprintf("%s/%s", live.ComposeProject, live.Service)
}

// rpcResult is the envelope rippled's HTTP JSON-RPC returns.
type rpcResult struct {
	Result struct {
		Info   serverInfoFields `json:"info"`
		Status string           `json:"status"`
		Error  string           `json:"error"`
	} `json:"result"`
}

// serverInfoFields is the subset of server_info this package reads, named
// rather than inlined because the diagnostic snapshot is a copy of it and
// the identity check decodes that snapshot back into the same shape. One
// definition, so a field added for the live read is a field the comparison
// can see too.
type serverInfoFields struct {
	BuildVersion     string `json:"build_version"`
	ServerState      string `json:"server_state"`
	AmendmentBlocked bool   `json:"amendment_blocked"`
	Peers            int    `json:"peers"`
	ValidationQuorum int    `json:"validation_quorum"`
	// The node's own identity, and its validator identity where it has one.
	// These are what a version number cannot tell you: a node can report the
	// build that was asked for and still be the wrong node, or the same node
	// with its validator identity gone.
	PubkeyNode      string `json:"pubkey_node"`
	PubkeyValidator string `json:"pubkey_validator"`
	// The UNL this node is running on. Absent on a node that has not
	// fetched one, which is why it is a pointer: an absent list and a list
	// of zero publishers are different states.
	ValidatorList *struct {
		Count  int    `json:"count"`
		Status string `json:"status"`
	} `json:"validator_list"`
	// Uptime is seconds since the node process started. Carried as a
	// pointer because absent is not zero: a missing field would
	// otherwise read as "started this second" and fire the restart
	// assessment's restart-loop concern on every healthy node.
	Uptime       *int `json:"uptime"`
	ClosedLedger *struct {
		Age int `json:"age"`
	} `json:"closed_ledger"`
	ValidatedLedger *struct {
		Seq int `json:"seq"`
		Age int `json:"age"`
	} `json:"validated_ledger"`
}

// NodeRead says whether the node answered the server_info reads taken on this
// State since ResetNodeRead (#1106): "ok" when every one answered, "failed"
// when any did not, and ok=false when none was taken. A failed read is the
// call itself failing (the dial, the status, the body, the node's own error),
// never an answer that is merely unhappy: a node that says it is desynced has
// answered. This is the Advisor deciding that the node could not be read,
// instead of a page guessing it from the words of a sentence.
func (s *State) NodeRead() (read string, ok bool) {
	s.infoMu.Lock()
	defer s.infoMu.Unlock()
	switch {
	case s.infoFailed:
		return "failed", true
	case s.infoReads > 0:
		return "ok", true
	}
	return "", false
}

// ResetNodeRead forgets the reads taken so far, so the next NodeRead speaks
// for one evaluation and not for whatever built the State.
func (s *State) ResetNodeRead() {
	s.infoMu.Lock()
	s.infoReads, s.infoFailed = 0, false
	s.infoMu.Unlock()
}

// serverInfo asks the node about itself. This is a read: `server_info` reports
// state and changes none.
func (s *State) serverInfo() (*rpcResult, error) {
	out, err := s.serverInfoCall()
	s.infoMu.Lock()
	s.infoReads++
	if err != nil {
		s.infoFailed = true
	}
	s.infoMu.Unlock()
	return out, err
}

func (s *State) serverInfoCall() (*rpcResult, error) {
	body := strings.NewReader(`{"method":"server_info","params":[{}]}`)
	req, err := http.NewRequestWithContext(s.context(), http.MethodPost, s.Profile.AdminRPC, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin rpc returned %s", resp.Status)
	}
	var out rpcResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode server_info: %w", err)
	}
	if out.Result.Error != "" {
		return nil, fmt.Errorf("admin rpc error: %s", out.Result.Error)
	}
	return &out, nil
}

// RunningVersion asks the node what it is running rather than reading the image
// tag. The tag is a label someone chose; the node's own answer is the fact. A
// deployment pinned to :latest has a tag that says nothing at all.
func (s *State) RunningVersion() (string, error) {
	info, err := s.serverInfo()
	if err != nil {
		return "", err
	}
	v := NormalizeVersion(info.Result.Info.BuildVersion)
	if v == "" {
		return "", fmt.Errorf("node reported no build version")
	}
	return v, nil
}

// NormalizeVersion strips the fork prefix some builds carry so a version from
// the node and a version from a registry tag can be compared. Forks rename the
// binary across releases; the number is the stable part.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	for _, p := range []string{"rippled-", "xrpld-", "xahaud-", "v"} {
		v = strings.TrimPrefix(v, p)
	}
	if i := strings.IndexAny(v, "+-"); i > 0 {
		v = v[:i]
	}
	return v
}

// BackupExists reports whether a recent backup of the named artefact is present
// and readable.
//
// Readable matters as much as present. A backup that exists but cannot be
// opened is not a rollback, and RB-002 depends on this being true rather than
// merely recorded.
func (s *State) BackupExists(artefact string) (bool, string) {
	origin, err := s.originPath(artefact)
	if err != nil {
		return false, err.Error()
	}
	base := filepath.Base(origin)
	dir := s.BackupDir
	if dir == "" {
		dir = filepath.Dir(origin)
	}

	// The reads happen through the privilege wrapper when one is configured,
	// so this process never opens the node's config directory. See
	// artefactHashes for why that matters more than the digest it returns.
	rows, err := s.artefactHashes(artefact)
	if err != nil {
		return false, fmt.Sprintf("%s: %v", artefact, err)
	}
	live, siblings := originOf(rows)
	if live.readErr || live.plain == "" {
		return false, fmt.Sprintf("%s: cannot read %s", artefact, origin)
	}

	// What makes a backup a rollback is that it is identical to the file about
	// to change — not that it is recent, and not that someone put ".bak" in
	// the name.
	//
	// An earlier version of this check tested for a recent name-matched file
	// and refused this operator's host, which had two byte-identical copies
	// sitting beside the originals under a different naming convention. Age is
	// a proxy, and it is the wrong one in both directions: a copy from six
	// weeks ago that still matches is a perfect rollback point, and a .bak
	// taken yesterday of a config that has since changed is not one at all.
	var cands []artefactRow
	for _, c := range siblings {
		if c.name == base || !isBackupCandidate(base, c.name) {
			continue
		}
		if c.readErr || c.size == 0 {
			continue // empty, oversized or unreadable is not a rollback
		}
		cands = append(cands, c)
	}
	if len(cands) == 0 {
		return false, fmt.Sprintf("%s: no copy of %s found in %s", artefact, base, dir)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })

	for _, c := range cands {
		if c.plain == live.plain {
			return true, fmt.Sprintf("%s is identical to the current %s (%s old)",
				c.name, base, age(time.Since(c.mod)))
		}
	}

	// Mid-plan, identity is the wrong question for the deployment definition.
	// Prepare's own last step edits the image line, so from that moment until
	// the cutover no backup can match the current file — the plan's own
	// progress was failing the cutover's precondition, and the operator was
	// told their rollback was missing at the exact moment it mattered most.
	// A backup that matches the current file everywhere EXCEPT the image tag
	// is precisely that rollback: prepare's pre-change copy. Any other drift
	// still fails.
	if artefact == "deployment-definition" && s.Profile.ImageRepo != "" && live.norm != "" {
		for _, c := range cands {
			if c.norm != "" && c.norm == live.norm {
				return true, fmt.Sprintf(
					"%s matches the current %s up to the image tag — the plan's own change (%s old)",
					c.name, base, age(time.Since(c.mod)))
			}
		}
	}
	return false, fmt.Sprintf("%s: %d cop%s of %s exist in %s but none matches the current file — "+
		"newest is %s (%s old); take a fresh copy before changing anything",
		artefact, len(cands), plural(len(cands)), base, dir,
		cands[0].name, age(time.Since(cands[0].mod)))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// isBackupCandidate reports whether a sibling filename could be a copy of base.
//
// Prefix-matching the artefact's own name is what keeps this away from
// everything else in the directory. On a real validator that directory also
// holds validator-keys.json, and §7 is absolute that the Advisor never reads
// validator key material — so the rule is that only siblings of the artefact
// are ever opened, enforced here rather than left to the accident of a naming
// convention.
func isBackupCandidate(base, name string) bool {
	if !strings.HasPrefix(name, base) {
		// Also allow the "<stem>.<version>.<ext>" convention operators use for
		// configs, e.g. docker-compose.3.2.0.yml beside docker-compose.yml.
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		if stem == base || !strings.HasPrefix(name, stem+".") {
			return false
		}
		return filepath.Ext(name) == filepath.Ext(base)
	}
	return true
}

// hashFile digests a file's contents. Bounded: these are configs and compose
// files, and a multi-gigabyte "backup" in the config directory is not one.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArtefactBytes))
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("file is empty")
	}
	if n == maxArtefactBytes {
		return "", fmt.Errorf("file is larger than %d bytes; not a config", maxArtefactBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

const maxArtefactBytes = 8 << 20

// hashNormalized digests a file with the node's image line blanked and its
// pull_policy line dropped, so two revisions of a compose file that differ
// only by that one planned change hash the same.
//
// The WHOLE reference goes, repository included, not just the tag. An
// upgrade that builds the image on this host changes the repository as well:
// the copy taken before it names the registry repository, the file after it
// names localhost/xrpld, and a normalisation that kept the repository would
// report the plan's own change as unrelated drift and refuse the cutover for
// a missing rollback that is sitting right there. pull_policy goes with it,
// because set-image-local writes that line as the other half of the same
// edit.
//
// This must stay byte for byte what the wrapper's artefact-hashes verb does.
// Two implementations of one normalisation is how the two routes come to
// disagree about a file, so both were changed together and the test compares
// their output.
func hashNormalized(path, repo, service string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) == 0 || len(b) >= maxArtefactBytes {
		return "", fmt.Errorf("not a config-sized file")
	}
	h := sha256.Sum256([]byte(NormalizeComposeBody(string(b), repo, service)))
	return hex.EncodeToString(h[:]), nil
}

// NormalizeComposeBody is that normalisation on its own, exported so the
// test that proves the wrapper and this agree can call it.
func NormalizeComposeBody(body, repo, service string) string {
	lines := strings.Split(body, "\n")
	blank := composeImageLine(lines, repo, service)
	out := make([]string, 0, len(lines))
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimLeft(ln, " \t"), "pull_policy:") {
			continue
		}
		if i == blank {
			ln = ln[:strings.Index(ln, "image:")] + "image: @"
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func age(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// ImagePublished reports whether the target image or package exists at its
// origin, WITHOUT installing it, a registry manifest for a container host, a
// repository entry for a native one.
//
// The container half is the check that was live on this operator's own host
// for most of a day: 3.2.1 tagged in the source repo, image not yet on the
// registry. An upgrade plan that assumes a release is installable because it
// was announced stops the node and then cannot start it again. The native
// half asks the same question of the host's own package repositories,
// through the wrapper's package-available verb, the native design note's
// answer to "is this version real", since there is no digest to pull and
// inspect first.
func (s *State) ImagePublished(version string) (bool, string) {
	if s.Kind() == "native" {
		return s.packageAvailable(version)
	}
	// A container node's image is built on this host from the signed package
	// (operator ruling, 2026-09-26), so "can this host get it" is a question
	// about the package repository, not about a registry. Asking Docker Hub
	// would have refused every 3.4.x upgrade on a node that can build one in
	// a minute: the Hub image this project used stops at 3.3.0, and nothing
	// answers for localhost/xrpld at all.
	//
	// An image already built and sitting on this host is the other way for
	// the answer to be yes, and it is checked first: it needs no network, and
	// it is the state a re-run of a plan finds after its own build step.
	if ok, d := s.ImageLocal(version); ok {
		return true, d
	}
	return s.ImageReleased(version)
}

// ImageReleased is ImagePublished without the look at this host's own
// images: whether the release itself is published, which is a question about
// somewhere else and changes on the scale of releases. Split out (#1015) so a
// cache can hold this half for minutes while the local half, which an
// operator can change with one `docker image rm`, is asked fresh every time.
//
// The registry is deliberately NOT asked here, even though #682 made the
// official image the first source. Whether a release exists is the signed
// index's to say and only its: a tag can be pushed for something the
// Foundation never published, and answering "yes, this is installable" off a
// tag alone would offer a node an image with no release behind it. The tag
// decides where an image COMES FROM, which is TargetSource below, after this
// has said the release is real.
func (s *State) ImageReleased(version string) (bool, string) {
	if s.Kind() == "native" {
		return s.packageAvailable(version)
	}
	return s.packagesIndexHas(version)
}

// BuiltHereSource is TargetSource's answer for an image built on this host.
// It rests on a local read, so a cache holding it must re-check (#1015).
const BuiltHereSource = "built here"

// TargetSource names where THIS version's image would come from, in the
// words the card uses. Separate from LatestReleaseSource, which answers a
// different question and still only ever answers packages.xrplf.org: what
// is newest is the index's to say, and where an image comes from is this.
//
// The official image is asked about FIRST, ahead of an image already built
// here, because that is the ruling: official first, a build when no tag
// exists or when the operator asks for one. A host that built 3.4.1 last
// week and can now pull the official 3.4.1 is offered the official one,
// which is the source switch prod and the lab node both need.
func (s *State) TargetSource(version string) string {
	if s.Kind() == "native" {
		return "package repository"
	}
	if f, err := s.OfficialTag(version); err == nil && f.Exists {
		return OfficialImageSource
	}
	if ok, _ := s.ImageLocal(version); ok {
		return BuiltHereSource
	}
	return PackagesIndexSource
}

// UpgradeSource is TargetSource and the pin it implies, in one reading.
//
// Asked once and carried, rather than re-derived by each caller: the
// registry is a network origin, and a plan whose card said "the official
// image" while its executor built from the package would be two answers to
// one question.
func (s *State) UpgradeSource(version string) (string, string, string) {
	src := s.TargetSource(version)
	if src != OfficialImageSource {
		return src, "", fmt.Sprintf("%s would come from %s", version, src)
	}
	digest, why := s.OfficialTargetDigest(version)
	if digest == "" {
		// The tag was there a moment ago and is not now, or the registry
		// stopped answering between the two reads. Not an error: the
		// package index still carries the release and a build still
		// reaches it, so this falls back to the source that needs no
		// registry and says why.
		return PackagesIndexSource, "", fmt.Sprintf(
			"an official image was found for %s and then could not be pinned (%s), so this would build from the signed package",
			version, why)
	}
	return OfficialImageSource, digest, why
}

// RunSource is where an upgrade's image comes from, and its pin, read for
// the moment a run binds its plan (#1033). One registry read, and its
// error: UpgradeSource reads the registry twice and turns a failed read
// into "build from the package", which is the right fallback for a card and
// the wrong one here. A run that bound a build because the registry did not
// answer would read as the node's answer having moved since the approval,
// when nothing about the node moved at all.
//
// A node this cannot offer the official image to (a native host, a fork)
// is answered the way UpgradeSource answers it, with no read and no error.
func (s *State) RunSource(version string) (src, digest string, err error) {
	if s.Kind() == "native" {
		return "package repository", "", nil
	}
	if s.xrpldFamilyOrRefusal() == nil {
		f, err := s.OfficialTag(version)
		if err != nil {
			return "", "", err
		}
		if f.Exists {
			return OfficialImageSource, f.IndexDigest, nil
		}
	}
	if ok, _ := s.ImageLocal(version); ok {
		return BuiltHereSource, "", nil
	}
	return PackagesIndexSource, "", nil
}

// OfficialPin is RunSource's answer to the one question the approval
// ceremony binds (#1061): is this version the official image, and at which
// digest. One registry read and no wrapper call, so approve/begin keeps its
// single host read (#105), and no call to the node: the fork is judged by
// the recorded profile. Where the image would come from otherwise (built
// here, or built from the package) changes nothing a plan is bound to, so
// it is not asked. "" with no error is "not the official image".
func (s *State) OfficialPin(version string) (string, error) {
	if name, _ := s.profileFork(); s.Kind() == "native" || !xrpldFamily[name] {
		return "", nil
	}
	f, err := s.officialTagRead(version)
	if err != nil {
		return "", err
	}
	if !f.Exists {
		return "", nil
	}
	return f.IndexDigest, nil
}

// OfficialTargetDigest is the pin for an official upgrade to this version,
// or "" when no official image carries it.
//
// One place, so the plan, the card and the executor cannot each ask the
// registry and get different answers if a tag moves between them. The
// answer is the INDEX digest: that is what RepoDigests reports after a
// pull, proved on aperire1's containerd store on 2026-09-27, so the
// deployment file, docker inspect and running-digest all name one thing.
func (s *State) OfficialTargetDigest(version string) (string, string) {
	if s.Kind() == "native" {
		return "", "a native host runs no image"
	}
	f, err := s.OfficialTag(version)
	if err != nil {
		return "", err.Error()
	}
	if !f.Exists {
		return "", fmt.Sprintf("no official image carries %s yet", version)
	}
	return f.IndexDigest, fmt.Sprintf("%s:%s is published, pinned at %s",
		OfficialImageRepo, version, f.IndexDigest)
}

// SourceSwitchAvailable reports whether this node could move to the
// official image WITHOUT changing version.
//
// This is not a nicety. Both the lab node and production run
// localhost/xrpld:3.4.1 today, and the whole point of #682 for them is to
// take the official 3.4.1: same release, different source. Every other
// reading in this package asks "is there something NEWER", which is false
// for both of them, so without this the official path is unreachable on
// exactly the two hosts it was ruled for.
func (s *State) SourceSwitchAvailable() (bool, string, string) {
	if s.Kind() == "native" {
		return false, "", "a native host runs no image"
	}
	origin, detail := s.DeploymentOrigin()
	if origin == OriginOfficial {
		return false, "", "this node already runs the official image"
	}
	if origin == OriginUnknown {
		return false, "", detail
	}
	running, err := s.RunningVersion()
	if err != nil || running == "" {
		return false, "", "the node did not say which build it is running, so nothing here was measured"
	}
	digest, why := s.OfficialTargetDigest(running)
	if digest == "" {
		return false, "", why
	}
	return true, digest, fmt.Sprintf(
		"this node runs %s, and the official image carries the same release (%s)", running, why)
}

// DeploymentOrigin is where the image the deployment file names came from.
// Read off the file rather than off a configured repository, because the
// two disagree at exactly the moments this is asked: prepare points the
// file at one origin while the container still runs another.
func (s *State) DeploymentOrigin() (ImageOrigin, string) {
	img, err := s.DeploymentImage()
	if err != nil {
		return OriginUnknown, err.Error()
	}
	o := OriginOf(img)
	return o, fmt.Sprintf("%s names %s, which is %s", s.Profile.ComposeFile, img, o.Sentence())
}

// packageAvailable asks the wrapper's package-available verb whether version
// is installable from this host's own repositories, ImagePublished's native
// half, routed here because it is one question asked of two origins rather
// than a second interface method.
//
// The wrapper prints three tab-separated fields: yes/no/unknown/retired, the
// matched release (or "-"), and a detail sentence. "retired" (#802) is a host
// whose only source is the retired repos.ripple.com, and its sentence names
// the command that moves the source. "unknown" fails closed like every
// read in this package, but its detail says the package manager would not
// answer rather than claiming a negative nobody measured, the same
// discipline ConfigReadable's three verdicts follow, applied to a version
// instead of a file.
func (s *State) packageAvailable(version string) (bool, string) {
	if version == "" {
		return false, "no version to look for"
	}
	if s.Wrapper == "" {
		return false, "no privilege wrapper is configured, so this host's own repositories were not asked"
	}
	name := s.Wrapper
	args := []string{"package-available", version}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		return false, fmt.Sprintf("could not ask the package manager: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(string(out)), "\t", 3)
	if len(fields) != 3 {
		return false, fmt.Sprintf("the wrapper's answer was not the three fields expected: %q", strings.TrimSpace(string(out)))
	}
	switch fields[0] {
	case "yes":
		return true, fields[2]
	case "no":
		return false, fields[2]
	case "retired":
		// #802: the host's only source is the retired repos.ripple.com.
		// Measured, not unknown, so the wrapper's own sentence (which names
		// the fix) is the detail, without the "could not be determined"
		// that would send an operator looking at the package manager.
		return false, fields[2]
	default:
		return false, "could not be determined: " + fields[2]
	}
}

// packageVersion asks the wrapper's package-version verb what the package
// database says is installed right now, DeploymentTag's native half. Not
// what the last plan intended, the same ground-truth rule DeploymentTag's own
// doc comment states for a compose file, read from the database instead.
//
// Normalised through NormalizeVersion before it is returned, dpkg-query
// reports a Debian revision (3.3.0-1) and rpm reports VERSION-RELEASE
// (3.3.0-1.el9), and DeploymentTag's whole contract is that every caller
// compares it against RunningVersion or a bound target_version with a bare
// equality check, never a normaliser of its own. Left unnormalised here,
// every one of those comparisons on a native host would fail on every
// version: the "install" comparison inside the interrupting-step check
// (execute.go) and the "the deployment names the version the node is
// running" precondition RB-002, RB-003 and RB-004 all carry would refuse
// every native restart, config change, upgrade cutover and rollback, always,
// which is not a native cost stated anywhere in this tree, it would simply
// never have worked.
func (s *State) packageVersion() (string, error) {
	if s.Wrapper == "" {
		return "", fmt.Errorf("no privilege wrapper is configured, so the package database was not read")
	}
	name := s.Wrapper
	args := []string{"package-version"}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		return "", err
	}
	fields := strings.SplitN(strings.TrimSpace(string(out)), "\t", 2)
	if len(fields) != 2 || fields[1] == "" {
		return "", fmt.Errorf("the wrapper's package-version answer was not the two fields expected: %q", strings.TrimSpace(string(out)))
	}
	v := NormalizeVersion(fields[1])
	if v == "" {
		return "", fmt.Errorf("the package database's version %q left nothing after normalising", fields[1])
	}
	return v, nil
}

// UserAgent identifies the executor to whatever it reads over HTTP. Sending
// something honest and specific means an operator reading their own egress
// logs, or the repository operator applying rate limits, can tell what this
// traffic is.
const UserAgent = "aperire-advisor-executor/0.1 (+read-only release check)"

// ConsensusHealthy makes §7's caution checkable. A validator that is
// desynced-but-participating and one that is restarting have very different
// network effects, so an operation that restarts the node is not offered while
// consensus looks anomalous.
func (s *State) ConsensusHealthy() (bool, string) {
	info, err := s.serverInfo()
	if err != nil {
		return false, fmt.Sprintf("could not read server_info: %v", err)
	}
	return healthOf(info.Result.Info)
}

// Observe is one server_info reading, whole: version, uptime and health from
// the same answer, so they describe the same process (#769). It is what a
// run's post-state is judged from, and nothing about it is remembered.
func (s *State) Observe() (runbook.Observation, error) {
	info, err := s.serverInfo()
	if err != nil {
		return runbook.Observation{}, err
	}
	i := info.Result.Info
	ok, detail := healthOf(i)
	return runbook.Observation{
		Version:     NormalizeVersion(i.BuildVersion),
		UptimeSec:   i.Uptime,
		ServerState: i.ServerState,
		Healthy:     ok,
		Detail:      detail,
	}, nil
}

// healthOf is ConsensusHealthy's rule over a reading already taken, so the
// single-reading Observe and the plain check cannot disagree about it.
func healthOf(i serverInfoFields) (bool, string) {
	if i.AmendmentBlocked {
		return false, "the node is amendment blocked — that is its own incident, not an upgrade precondition"
	}
	switch i.ServerState {
	case "proposing", "full", "validating":
	default:
		return false, fmt.Sprintf("server_state is %q, not proposing or full", i.ServerState)
	}
	if i.Peers <= 0 {
		return false, "the node reports no peers"
	}
	if i.ValidatedLedger == nil {
		return false, "the node reports no validated ledger"
	}
	if i.ValidatedLedger.Age > 30 {
		return false, fmt.Sprintf("the last validated ledger is %ds old", i.ValidatedLedger.Age)
	}
	return true, fmt.Sprintf("%s, %d peers, validated ledger %d age %ds",
		i.ServerState, i.Peers, i.ValidatedLedger.Seq, i.ValidatedLedger.Age)
}

// Readings is the node as one server_info call plus one statfs sees it —
// ADR 0016's restart assessment, and nothing else. Every field here is
// already read somewhere on the /v1/check path, which is the point: an
// assessment shown before a restart must not add a privileged read or a
// wrapper call to an endpoint the tab polls.
//
// Three fields are pointers because absent is not zero. A node that reports
// no validated ledger has not measured an age of zero seconds; a build that
// omits uptime has not just started; a data path that cannot be measured has
// not run out of disk. Rendering any of those as 0 would state a measurement
// the node never made, and each one would fire a concern that reads as fact.
type Readings struct {
	ServerState           string   `json:"server_state"`
	Peers                 int      `json:"peers"`
	ValidatedLedgerAgeSec *int     `json:"validated_ledger_age_sec"`
	UptimeSec             *int     `json:"uptime_sec"`
	RunningVersion        string   `json:"running_version"`
	DeploymentTag         string   `json:"deployment_tag"`
	DiskFreePct           *float64 `json:"disk_free_pct"`
}

// Readings gathers them. The error is reserved for the node not answering at
// all: that is the one failure that leaves nothing worth showing. A
// deployment file or a data path that cannot be read leaves its own field
// empty and says so there, because the rest of the picture is still true.
func (s *State) Readings() (Readings, error) {
	tag, terr := s.DeploymentTag()
	if terr != nil {
		tag = ""
	}
	return s.ReadingsWithTag(tag)
}

// ReadingsWithTag is Readings for a caller that has already read the
// deployment tag. One response must not carry two answers to the same
// measurement: /v1/check publishes deployment_tag at the top level AND
// inside the assessment, and read twice they can disagree by whatever
// happened in between — which is the same trap the shared precondition
// evaluation exists to close ("one evaluation, two renderings").
func (s *State) ReadingsWithTag(tag string) (Readings, error) {
	info, err := s.serverInfo()
	if err != nil {
		return Readings{}, err
	}
	i := info.Result.Info
	r := Readings{
		ServerState:    i.ServerState,
		Peers:          i.Peers,
		UptimeSec:      i.Uptime,
		RunningVersion: NormalizeVersion(i.BuildVersion),
	}
	if i.ValidatedLedger != nil {
		age := i.ValidatedLedger.Age
		r.ValidatedLedgerAgeSec = &age
	}
	r.DeploymentTag = tag
	if pct, _, derr := s.DiskHeadroomPct(); derr == nil {
		r.DiskFreePct = &pct
	}
	return r, nil
}

// EvidenceCaptured reports whether a diagnostic snapshot was taken before any
// state change. Runbook 11 opens with "do not restart yet, a restart destroys
// the evidence"; an upgrade is a restart with extra steps.
func (s *State) EvidenceCaptured() (bool, string) {
	// A snapshot captured by one process has to be visible to another. The
	// first version only knew about a snapshot this same State had written, so
	// the CLI reported 8 of 8 passing while the web service reported the plan
	// blocked — and the approval ceremony refuses a blocked plan. Two answers
	// to the same question, on the same host, at the same moment.
	if s.EvidencePath == "" {
		return false, "no evidence snapshot has been captured for this plan"
	}
	fi, err := os.Stat(s.EvidencePath)
	if err != nil {
		return false, fmt.Sprintf("evidence snapshot %s: %v", s.EvidencePath, err)
	}
	if fi.Size() == 0 {
		return false, fmt.Sprintf("evidence snapshot %s is empty", s.EvidencePath)
	}
	if time.Since(fi.ModTime()) > time.Hour {
		return false, fmt.Sprintf("evidence snapshot %s is %s old and a fresh one could not be taken",
			s.EvidencePath, age(time.Since(fi.ModTime())))
	}
	return true, fmt.Sprintf("%s (%d bytes, %s old)", filepath.Base(s.EvidencePath), fi.Size(), age(time.Since(fi.ModTime())))
}

// DeploymentTag reads which image tag the deployment file names right now.
// This is the ground truth for "has prepare staged the change": the file
// cannot be wrong about itself, where an inference from records can be —
// and was, for a whole afternoon.
//
// On a native host there is no deployment file to be wrong about itself: the
// package database is the ground truth instead, read through the wrapper's
// package-version verb. An install run by hand, outside the wrapper, is the
// native equivalent of a staged-but-uncommitted compose edit, and this is
// the read that catches it.
func (s *State) DeploymentTag() (string, error) {
	if s.Kind() == "native" {
		return s.packageVersion()
	}
	raw, err := os.ReadFile(s.Profile.ComposeFile)
	if err != nil {
		return "", err
	}
	// Either origin, and failing both, this node's own service block. The
	// repository in the file is not a constant across an upgrade: prepare
	// builds localhost/xrpld:<target> and points the deployment at it while
	// the container is still running the registry image it started on, and
	// a rollback writes the registry repository back while the container
	// still runs the built one. Matching the profile's repository alone
	// returned "no image line" at exactly those moments, which are the
	// moments the cutover reads this to decide whether what it is about to
	// restart is what was approved. ComposeImageRef holds the rule.
	img := ComposeImageRef(string(raw), s.Profile.ImageRepo, s.Profile.Service)
	if img == "" {
		return "", fmt.Errorf("no image line for %s in %s (looked for %s, %s, and the service's own block)",
			s.Profile.Service, s.Profile.ComposeFile, s.Profile.ImageRepo, LocalImageRepo)
	}
	// A digest-pinned line has no tag in the reference at all, and the
	// digest's own hex ends in no colon a tag reader could survive: the
	// last colon in `rippleci/xrpld@sha256:e77e…` opens the hash. The
	// version an official swap staged lives in the comment beside it, and
	// that comment is the ONLY thing this reads it from, for this one
	// question: has the file been staged to the target. What version a
	// node is RUNNING is never read here; that is build_version, off the
	// node itself.
	if strings.Contains(img, "@sha256:") {
		v := stagedVersionComment(string(raw), img)
		if v == "" {
			return "", fmt.Errorf("%s names %s by digest with no version beside it, so what it was staged to cannot be read from the file",
				s.Profile.ComposeFile, img)
		}
		return v, nil
	}
	if j := strings.LastIndex(img, ":"); j >= 0 {
		return img[j+1:], nil
	}
	return img, nil
}

// stagedVersionComment reads the version out of the comment on a
// digest-pinned image line, and only when it is a plain release.
func stagedVersionComment(body, ref string) string {
	for _, ln := range strings.Split(body, "\n") {
		if !strings.Contains(ln, "image: "+ref) {
			continue
		}
		_, after, ok := strings.Cut(ln, "#")
		if !ok {
			return ""
		}
		v := strings.TrimSpace(after)
		if len(v) > releaseMaxLen || !releaseRe.MatchString(v) {
			return ""
		}
		return v
	}
	return ""
}

// DeploymentImage is DeploymentTag's whole answer: the full reference the
// deployment names, repository included. The cutover needs the tag; the
// rollback needs to know WHICH origin holds it, because a locally built
// image is swapped in by a different verb from a registry one.
func (s *State) DeploymentImage() (string, error) {
	if s.Kind() == "native" {
		return "", fmt.Errorf("a native host has no deployment file and no image")
	}
	raw, err := os.ReadFile(s.Profile.ComposeFile)
	if err != nil {
		return "", err
	}
	img := ComposeImageRef(string(raw), s.Profile.ImageRepo, s.Profile.Service)
	if img == "" {
		return "", fmt.Errorf("no image line for %s in %s (looked for %s, %s, and the service's own block)",
			s.Profile.Service, s.Profile.ComposeFile, s.Profile.ImageRepo, LocalImageRepo)
	}
	return img, nil
}

// ConventionalEvidencePath is where every process on a host looks for the
// pre-change snapshot. One convention, shared, because a snapshot is evidence
// about the host — not about whichever process happened to take it. The name
// carries no version: the picture is of the node, not of any particular plan.
func ConventionalEvidencePath(stateDir string) string {
	return filepath.Join(stateDir, "evidence", "pre-change.json")
}

// EnsureEvidence refreshes the snapshot when it is missing or stale.
//
// The snapshot is a read. It needs no privilege and no approval — which is
// exactly why asking the operator to click a button for it was wrong: it was
// ceremony that protected nothing, and it taught that some buttons are just
// buttons. The Advisor takes its own reading as part of doing its job; the
// precondition now only ever fails when the reading itself fails, which is a
// real problem worth stopping for.
func (s *State) EnsureEvidence() error {
	if s.EvidencePath == "" {
		return nil
	}
	if ok, _ := s.EvidenceCaptured(); ok {
		return nil
	}
	return s.CaptureEvidence(s.EvidencePath)
}

// CaptureEvidence writes the diagnostic snapshot the precondition looks for.
//
// This is the one thing in this package that writes, and it writes only to the
// path it is given, never to the node's own files. It is separated from the
// checks so a dry run can be told to capture evidence without being able to
// do anything else.
func (s *State) CaptureEvidence(path string) error {
	info, err := s.serverInfo()
	if err != nil {
		return fmt.Errorf("server_info: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{
		"captured_at": time.Now().UTC(),
		"profile":     s.Profile,
		"server_info": info.Result.Info,
	}); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o640); err != nil {
		return err
	}
	s.EvidencePath = path
	// And, beside it, what THIS build supports, keyed by the version that
	// answered. That file is the only thing that can ever prove an older
	// build carries an amendment the network has since enabled: it is that
	// build's own reply, taken while it was the build running here. A
	// rollback reads it back by version.
	//
	// Best effort. A node that will not answer `feature` still gets its
	// snapshot; the rollback check says "unproven" rather than this
	// failing an upgrade over a file it only needs much later.
	s.recordSupportedAmendments(filepath.Dir(path), info.Result.Info.BuildVersion)
	return nil
}

// LatestRelease asks the node's own origin which version is newest: the
// signed package index on a container host, this host's own package
// repositories on a native one.
//
// This is the difference between the Advisor deciding and the Advisor
// displaying a decision someone hardcoded. The recommendation "upgrade to X"
// has to come from data the Advisor gathered itself - the page briefly
// carried the target as a string constant, which meant the moment the next
// release shipped, the tab would keep recommending the old one.
//
// It branches on kind for the same reason ImagePublished does, and #421 is
// what a single-origin answer cost: on a native host every /v1/check that
// did not name a target refused with "the profile records no image
// repository", so the Operations card sat on CHECK UNAVAILABLE and retried
// forever, on a host that has no images and never will. An origin a host
// does not have is not a reason to refuse the question.
//
// The container side used to read Docker Hub's tag list, and that answer is
// now wrong rather than merely narrow: from 3.4.x an xrpld release ships as
// a signed package first, and sometimes only as one. The Hub image this
// project deployed stops at 3.3.0, so a node facing an amendment deadline
// was being told it was current. Both kinds therefore read a package
// repository, and the container's is the upstream index its image is built
// from. The native side is packageLatest, below.
func (s *State) LatestRelease() (string, error) {
	if s.Kind() == "native" {
		return s.packageLatest()
	}
	return s.packagesIndexNewest()
}

// LatestReleaseSource names the origin LatestRelease read, in the words an
// operator would use for it. Derived from the recorded kind rather than
// remembered from the call, so the two cannot come to disagree.
func (s *State) LatestReleaseSource() string {
	if s.Kind() == "native" {
		return "package repository"
	}
	return PackagesIndexSource
}

// packageLatest is LatestRelease's native half: the newest version this
// host's own package repositories offer, through the wrapper's
// package-latest verb.
//
// The repository is where a package-install would take the release from, so
// it is the only answer that cannot disagree with what an install would
// actually do. The alternative considered and set aside on #421 was to teach
// this project's release registry a package name per fork, which is a second
// source of truth for one fact and would be wrong on any host whose operator
// pins a repository of their own.
//
// The three fields are package-available's, verbatim, because this is the
// same question asked without a version. "unknown" is a real answer and is
// reported as one: a package manager that would not speak has not told us
// there is no newer release.
//
// "retired" is the one #802 added: the host's only source is the retired
// repos.ripple.com, which stopped at 3.3.0. What it lists last is not the
// newest release, so no target is derived from it, and the refusal carries
// the wrapper's sentence, which names the command that moves the source.
// Read as anything but a refusal, that host's Operations card said its node
// was current while an amendment it cannot run was on the way.
//
// The answer is normalised the way packageVersion's is. apt reports a Debian
// revision (3.3.0-1) and rpm a VERSION-RELEASE, and a target carrying that
// suffix would fail the runbook's own version shape and could never be
// bound, so it is the upstream version that comes back here. The release
// suffix is re-resolved at install time by the wrapper's own pkg_match,
// which is where it belongs: this host picks the release, not the plan.
func (s *State) packageLatest() (string, error) {
	const because = "could not determine the latest release from the package repository, because "
	if s.Wrapper == "" {
		return "", fmt.Errorf(because + "no privilege wrapper is configured, so this host's own repositories were not asked")
	}
	name := s.Wrapper
	args := []string{"package-latest"}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		return "", fmt.Errorf(because+"the package manager could not be asked: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(string(out)), "\t", 3)
	if len(fields) != 3 {
		return "", fmt.Errorf(because+"the wrapper's answer was not the three fields expected: %q", strings.TrimSpace(string(out)))
	}
	if fields[0] != "yes" {
		return "", fmt.Errorf(because + fields[2])
	}
	v := NormalizeVersion(fields[1])
	if !versionish(v) {
		return "", fmt.Errorf(because+"the newest version offered, %q, is not a release this Advisor can name in a plan", fields[1])
	}
	return v, nil
}

// versionish is digits and dots only — the same shape the runbook parameter
// accepts, so a recommendation can never name a version the executor would
// then refuse.
func versionish(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// CompareVersions orders dotted-numeric versions segment by segment, so
// 3.10.0 sorts above 3.9.9 — the case a string comparison gets wrong.
func CompareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var an, bn int
		if i < len(as) {
			fmt.Sscanf(as[i], "%d", &an)
		}
		if i < len(bs) {
			fmt.Sscanf(bs[i], "%d", &bn)
		}
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ConfigReadable asks the node's own container whether it can read the
// configuration it would start with — ADR 0018, and punch #10.
//
// The whole reading happens inside the privilege wrapper's `config-readable`
// verb: it resolves where the config is mounted, runs `test -r` on that path
// inside the container, and prints one tab-separated verdict row. This
// process never opens the node's config directory, for the reason
// artefactHashes gives at length — that directory holds rippled.cfg, which
// holds the validator token.
//
// Three verdicts, and the third is not a failure. No wrapper configured, a
// container that is not running, an image with no shell, a config that
// arrives by a route docker inspect does not show: all of them mean nothing
// was measured, and reporting them as "unreadable" would refuse a change on
// evidence that does not exist.
//
// Without a wrapper this returns unknown rather than reading directly. The
// direct fallback the other reads have is a host-side read; this question is
// specifically about the CONTAINER's view, and a stat on this side answers a
// different question — which is exactly the inference that hid the 2026-08-19
// incident for two days.
func (s *State) ConfigReadable() (verdict, detail string) {
	if s.Wrapper == "" {
		return runbook.ConfigReadableUnknown,
			"no privilege wrapper is configured, so the container's own view of the config was not asked for"
	}
	name := s.Wrapper
	rest := []string{"config-readable"}
	out, err := s.Runner.Run(s.context(), name, rest...)
	if err != nil {
		return runbook.ConfigReadableUnknown,
			fmt.Sprintf("the wrapper's config-readable verb did not answer: %v", err)
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Split(line, "\t")
	if len(fields) != 3 {
		return runbook.ConfigReadableUnknown,
			fmt.Sprintf("the wrapper's config-readable verb said something this does not understand: %q", line)
	}
	path, why := fields[1], fields[2]
	switch fields[0] {
	case runbook.ConfigReadableYes:
		return runbook.ConfigReadableYes, fmt.Sprintf("%s: %s", path, why)
	case runbook.ConfigReadableNo:
		return runbook.ConfigReadableNo, fmt.Sprintf("%s: %s", path, why)
	case runbook.ConfigReadableUnknown:
		return runbook.ConfigReadableUnknown, why
	}
	return runbook.ConfigReadableUnknown,
		fmt.Sprintf("the wrapper reported an unrecognised verdict %q", fields[0])
}
