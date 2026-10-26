// Package host reads live host state for the executor's own preconditions.
//
// Everything here is read-only. Nothing in this package pulls an image, stops
// a container, writes a file, or calls an admin RPC that changes state — which
// is what makes --dry-run meaningful rather than a promise.
//
// Every read fails closed. A check that cannot be evaluated returns an error
// and the precondition treats that as a refusal. Reporting "I could not check"
// as "it is fine" is how a safety check becomes theatre.
package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Profile is the recorded description of how this node is deployed — ADR 0005.
//
// It is a precondition, not a parameter: RB-001 checks that the profile still
// describes the host before anything else runs. 3.2.0 renamed the binary, the
// config path and the data path in one release, so a stale profile is not
// hypothetical, and a plan written against one would target paths that have
// moved.
type Profile struct {
	Kind string `json:"kind"` // "docker-compose" or "native", ADR 0023

	ComposeProject string `json:"compose_project"`
	ComposeFile    string `json:"compose_file"`
	ComposeWorkDir string `json:"compose_working_dir"`
	Service        string `json:"service"`
	Container      string `json:"container"`

	ImageRepo string `json:"image_repo"` // e.g. rippleci/xrpld
	ImageTag  string `json:"image_tag"`  // e.g. 3.2.0, empty on a digest-pinned reference
	// ImageDigest is the digest a pinned reference names, empty otherwise
	// (#682). A deployment pinned by digest carries no tag at all, so
	// anything rendering "repo:tag" for one printed a bare trailing colon;
	// this is what it renders instead, and it is also the honest answer to
	// "which image is this", because the digest is what actually ran.
	ImageDigest string `json:"image_digest,omitempty"`

	// RuntimeUser is the account the container is configured to run as, and
	// EMPTY means it runs as root: the image's own default applies, and on
	// the images this project deploys that used to be root. It is read
	// because an image swap can change it underneath the node. The image
	// built from the signed package defaults to 997:997, and uid 997 on a
	// host is whatever account happened to take it, which on one lab
	// validator's host was another service's (2026-09-26). Kept out of
	// Differs for the reason ImageTag is: the swap itself changes it.
	RuntimeUser string `json:"runtime_user,omitempty"`
	// StopTimeout is the stop grace the RUNNING container was created with,
	// in seconds, and absent when it names none. The file's current
	// stop_grace_period is a different number and does not apply to the
	// stop an upgrade performs (#665).
	StopTimeout *int `json:"stop_timeout,omitempty"`

	// Native only. Unit is the systemd unit name (xrpld.service), Package
	// the vendor package the wrapper's conf names (xrpld, rippled), and
	// PackageVersion what the package database reports right now. This is
	// the native ImageTag, and it is kept out of Differs for the same
	// reason ImageTag is: a version is expected to change, and package-
	// install making it change is the whole point of running it.
	Unit           string `json:"unit,omitempty"`
	Package        string `json:"package,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`

	ConfigPath     string `json:"config_path"`
	ValidatorsPath string `json:"validators_path"`
	DataPath       string `json:"data_path"`

	AdminRPC string `json:"admin_rpc"` // http://127.0.0.1:5005

	CapturedAt time.Time `json:"captured_at"`
}

// Runner executes a command and returns its stdout. It is an interface so the
// executor's host reads can be exercised against known output in tests — the
// one thing you cannot do is test a precondition by breaking a production node.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

// ViaWrapper runs commands for real, except that it refuses to invoke docker
// and routes the one docker read this package needs through the privilege
// wrapper instead.
//
// The point is what it makes possible: the Advisor can run as an account with
// no docker group. Docker group membership is root-equivalent — an account in
// it can mount the host filesystem into a container and reach everything the
// wrapper exists to constrain — so as long as this process could call docker
// itself, the wrapper was an audit trail rather than a boundary. The wrapper's
// `inspect` verb is read-only and takes no argument from here, which is the
// same discipline every other verb follows.
//
// Socket is the root socket the wrapper is reached through (ADR 0025): the
// Advisor's account may connect to it and nothing else, and root runs the
// wrapper on the other side. There is no sudo path. With no Socket the
// wrapper runs directly as this process, which is what an operator running
// the CLI on their own account gets.
type ViaWrapper struct {
	Wrapper string
	Socket  string
}

// RunLines routes the streamed call the same way Run routes the buffered
// one, so the execute path gets live output through the socket as well.
// Anything that is not a call to the wrapper itself falls back to the
// buffered run and reports its output at the end: the only step that needs
// streaming is a wrapper verb, and a docker read that streamed would be noise.
func (w ViaWrapper) RunLines(ctx context.Context, sink func(string), name string, args ...string) ([]byte, error) {
	if name == w.Wrapper && w.Wrapper != "" {
		if w.Socket != "" {
			return wrapperSocketCall(ctx, w.Socket, w.Wrapper, sink, args...)
		}
		return ExecRunner{}.RunLines(ctx, sink, w.Wrapper, args...)
	}
	return w.Run(ctx, name, args...)
}

func (w ViaWrapper) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// A call to the wrapper ITSELF — every verb the execute path performs.
	// This branch did not exist: only `docker inspect` was routed to the
	// privileged side, and a wrapper invocation fell through to the plain
	// runner below. The whole execute path therefore ran the wrapper
	// unprivileged, and on a dedicated-account install that account cannot
	// read the node's config by design — so the first step of an upgrade
	// failed with "CONFIG_FILE … does not exist" about a file that was there
	// all along.
	if name == w.Wrapper && w.Wrapper != "" {
		if w.Socket != "" {
			return wrapperSocketCall(ctx, w.Socket, w.Wrapper, nil, args...)
		}
		return ExecRunner{}.Run(ctx, w.Wrapper, args...)
	}
	if name != "docker" {
		return ExecRunner{}.Run(ctx, name, args...)
	}
	// Only the read this package performs. Anything else reaching here is a
	// new docker call someone added without deciding how it crosses the
	// boundary, and should fail loudly rather than silently bypass it.
	if len(args) != 2 || args[0] != "inspect" {
		return nil, fmt.Errorf("refusing to run docker %v directly: add a wrapper verb for it", args)
	}
	return w.Run(ctx, w.Wrapper, "inspect")
}

// RunLines is Run with the output reported line by line as it lands.
//
// It exists for one step: the image build, which takes about a minute and
// used to send an operator nothing until it finished, then 120 lines all
// stamped at the same second (#678). The Operations card's working line is
// keyed to the recipe's own phases and cannot advance on a burst.
//
// stdout is what comes back for the caller to parse, exactly as Run gives
// it. The sink sees stdout AND stderr, because that is what a person
// watching the step should see, and because the wrapper says the
// interesting things about a failing build on stderr.
func (ExecRunner) RunLines(ctx context.Context, sink func(string), name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	var mu sync.Mutex
	emit := func(s string) {
		if sink == nil || s == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		sink(s)
	}
	var stdout bytes.Buffer
	var stderrTail strings.Builder
	var wg sync.WaitGroup
	wg.Add(2)
	// Both pipes are drained to the end whatever happens. A reader that
	// stops early leaves the child blocked on a full pipe, and the step
	// then hangs rather than failing, which is worse than no streaming at
	// all.
	go func() { defer wg.Done(); drainLines(outPipe, &stdout, emit) }()
	go func() { defer wg.Done(); drainLines(errPipe, &stderrTail, emit) }()
	wg.Wait()
	werr := cmd.Wait()
	if werr != nil {
		if tail := strings.TrimSpace(stderrTail.String()); tail != "" {
			return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, werr, lastLines(tail, 20))
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w", name, werr)
	}
	return stdout.Bytes(), nil
}

// drainLines copies r into keep and hands each complete line to emit.
//
// ReadString rather than bufio.Scanner: a Scanner gives up on a line over
// 64 KB, and a docker build can produce one. Giving up means the child
// blocks on a pipe nobody is reading, so the rule here is that everything
// is read, always, however long a line is.
func drainLines(r io.Reader, keep io.Writer, emit func(string)) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			keep.Write([]byte(line))
			emit(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			return
		}
	}
}

// lastLines keeps the tail of a failure, so an error carries the part that
// says what went wrong rather than a whole build log.
func lastLines(s string, n int) string {
	ls := strings.Split(s, "\n")
	if len(ls) <= n {
		return s
	}
	return strings.Join(ls[len(ls)-n:], "\n")
}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		// docker puts the useful part of a failure on stderr, so surface it
		// rather than reporting a bare exit status.
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// dockerInspect is the subset of `docker inspect` output the profile needs.
// Decoding a named struct rather than a map keeps a rename in Docker's schema
// a compile-time or empty-field problem instead of a silent nil.
type dockerInspect struct {
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
		// StopTimeout is the grace the container was CREATED with, in
		// seconds. It matters because that, not the file's current
		// stop_grace_period, is what a `compose up -d` with no -t gives the
		// stop it performs (#665).
		StopTimeout *int `json:"StopTimeout"`
	} `json:"Config"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
}

// DiscoverProfile reads the deployment description off the wrapper's
// `inspect` verb, the same call for both kinds.
//
// The wrapper answers in one of two shapes, and which one comes back is the
// host's own kind; it is not something this call declares or is told in
// advance. A container answers with docker's JSON array, which always opens
// with '['. A native host answers with a systemctl show dump followed by the
// wrapper's own AperireKind=native line, which never does. Sniffing the
// answer rather than branching on a caller-supplied kind is what keeps every
// existing call site, the daemon's cached read, --print-profile, the CLI,
// native-capable with no change: none of them need to know which kind of
// host they are pointed at, and ViaWrapper's routing does not change either,
// because it was never kind-aware to begin with. It only ever intercepted
// "docker" "inspect" <container> and handed the reply back unexamined; a
// native host's <container> is simply unused from here on, which is what
// lets discovery work with no --container argument at all.
//
// A `profile` verb, kept separate from `inspect`, was considered and set
// aside: `inspect` already carries every fact a native Profile needs
// (AperireUnit, AperirePackage, AperirePackageVersion, AperireConfigFile,
// AperireDataPath), and a second verb answering the same question would be
// two things to keep in sync instead of one.
func DiscoverProfile(ctx context.Context, r Runner, container, adminRPC string) (Profile, error) {
	out, err := r.Run(ctx, "docker", "inspect", container)
	if err != nil {
		return Profile{}, fmt.Errorf("inspect %q: %w", container, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(out)), "[") {
		return parseNativeInspect(out, adminRPC)
	}
	return parseContainerInspect(out, container, adminRPC)
}

// parseContainerInspect is DiscoverProfile's container half, unchanged from
// before native support existed except for the name.
//
// Compose records the project, the file it was started from and the service
// name as container labels, so the deployment does not have to be described
// twice and cannot drift from what is actually running. The config and data
// paths come from the bind mounts for the same reason.
func parseContainerInspect(out []byte, container, adminRPC string) (Profile, error) {
	var all []dockerInspect
	if err := json.Unmarshal(out, &all); err != nil {
		return Profile{}, fmt.Errorf("inspect %q: decode: %w", container, err)
	}
	if len(all) != 1 {
		return Profile{}, fmt.Errorf("inspect %q: expected 1 container, got %d", container, len(all))
	}
	d := all[0]

	repo, tag := splitImage(d.Config.Image)
	digest := ""
	if i := strings.LastIndex(d.Config.Image, "@"); i >= 0 {
		digest = d.Config.Image[i+1:]
	}
	p := Profile{
		Kind:           "docker-compose",
		ComposeProject: d.Config.Labels["com.docker.compose.project"],
		ComposeFile:    d.Config.Labels["com.docker.compose.project.config_files"],
		ComposeWorkDir: d.Config.Labels["com.docker.compose.project.working_dir"],
		Service:        d.Config.Labels["com.docker.compose.service"],
		Container:      strings.TrimPrefix(d.Name, "/"),
		ImageRepo:      repo,
		ImageTag:       tag,
		ImageDigest:    digest,
		RuntimeUser:    d.Config.User,
		StopTimeout:    d.Config.StopTimeout,
		AdminRPC:       adminRPC,
		CapturedAt:     time.Now().UTC(),
	}
	for _, m := range d.Mounts {
		switch {
		case strings.HasSuffix(m.Destination, "rippled.cfg"), strings.HasSuffix(m.Destination, "xrpld.cfg"):
			p.ConfigPath = m.Source
		case strings.HasSuffix(m.Destination, "validators.txt"):
			p.ValidatorsPath = m.Source
		case m.Destination == "/var/lib/rippled", m.Destination == "/var/lib/xrpld":
			p.DataPath = m.Source
		}
	}

	if p.ComposeProject == "" || p.Service == "" {
		return Profile{}, fmt.Errorf("container %q carries no compose labels; it was not started by compose", container)
	}
	if p.ConfigPath == "" {
		return Profile{}, fmt.Errorf("container %q exposes no node config mount", container)
	}
	if p.DataPath == "" {
		return Profile{}, fmt.Errorf("container %q exposes no data mount", container)
	}
	return p, nil
}

// splitImage separates xrpllabsofficial/xrpld:3.2.0 into repo and tag. A
// digest-pinned or untagged reference yields an empty tag, which the caller
// treats as "the running version cannot be read from the image".
func splitImage(ref string) (repo, tag string) {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return ref, ""
	}
	return ref[:i], ref[i+1:]
}

// AperireFacts pulls the wrapper's own AperireX=Y lines out of any answer it
// prints, ignoring everything around them.
//
// One reader for every verb that speaks this shape. `inspect` prints a
// systemctl show dump before its own lines and `store-size` prints nothing
// else at all, and both are read here rather than by two loops that could
// come to disagree about what a key looks like, the same rule this file
// already states for not re-deriving a fact systemd also knows.
//
// Last-wins on a repeated key, which never happens in practice: every
// property systemd defines is named without the "Aperire" prefix precisely
// so it cannot collide with these.
func AperireFacts(out []byte) map[string]string {
	facts := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(ln, "Aperire") {
			continue
		}
		if i := strings.IndexByte(ln, '='); i >= 0 {
			facts[ln[:i]] = strings.TrimRight(ln[i+1:], "\r")
		}
	}
	return facts
}

// parseNativeInspect reads the wrapper's inspect answer for a native
// deployment: a systemctl show dump followed by the wrapper's own
// AperireX=Y lines. Only those trailing lines are read here, they are the
// wrapper's own resolved answer (unit, package, version, paths), already
// normalised from the conf and the package database, and re-deriving them
// from systemd's own properties here would just be a second parser that
// could disagree with the first.
//
// Last-wins on a repeated key, which never happens in practice: the wrapper
// prints the systemctl show dump first and its own lines after, and every
// property systemd defines is named without the "Aperire" prefix precisely
// so it cannot collide with these.
func parseNativeInspect(out []byte, adminRPC string) (Profile, error) {
	text := string(out)
	facts := AperireFacts(out)
	if facts["AperireKind"] != "native" {
		return Profile{}, fmt.Errorf(
			"inspect: the wrapper's answer is neither a container's JSON nor a native AperireKind=native line: %s",
			excerpt(text))
	}
	p := Profile{
		Kind:           "native",
		Unit:           facts["AperireUnit"],
		Package:        facts["AperirePackage"],
		PackageVersion: facts["AperirePackageVersion"],
		ConfigPath:     facts["AperireConfigFile"],
		ValidatorsPath: facts["AperireValidatorsPath"],
		DataPath:       facts["AperireDataPath"],
		AdminRPC:       adminRPC,
		CapturedAt:     time.Now().UTC(),
	}
	switch {
	case p.Unit == "":
		return Profile{}, fmt.Errorf("inspect: a native answer with no AperireUnit: %s", excerpt(text))
	case p.Package == "":
		return Profile{}, fmt.Errorf("inspect: a native answer with no AperirePackage: %s", excerpt(text))
	case p.ConfigPath == "":
		return Profile{}, fmt.Errorf("inspect: a native answer with no AperireConfigFile: %s", excerpt(text))
	case p.DataPath == "":
		return Profile{}, fmt.Errorf("inspect: a native answer with no AperireDataPath: %s", excerpt(text))
	}
	return p, nil
}

// excerpt bounds an unrecognised answer for an error message. Long enough to
// show what went wrong, short enough that a stray dump of a whole systemctl
// show does not become the message.
func excerpt(s string) string {
	const max = 200
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty)"
	}
	if len(s) > max {
		return s[:max] + "… (truncated)"
	}
	return s
}

// Differs reports the load-bearing fields on which two profiles disagree.
// Deliberately not a whole-struct comparison: CapturedAt and the running
// version change in normal operation, and treating those as drift would make
// the check cry wolf until it was ignored.
func (p Profile) Differs(other Profile) []string {
	var out []string
	cmp := func(name, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("%s: recorded %q, host has %q", name, a, b))
		}
	}
	cmp("kind", p.Kind, other.Kind)
	if p.Kind == "native" || other.Kind == "native" {
		// A container profile carries nothing in these fields, so comparing
		// the compose set below instead would pass two empty strings and
		// call it a match, the vacuous pass this design exists to close.
		// PackageVersion is deliberately absent: it is the native ImageTag,
		// expected to change on every package-install, and the wrapper's own
		// "unknown" answer for a package database that would not respond is
		// not drift either.
		cmp("unit", p.Unit, other.Unit)
		cmp("package", p.Package, other.Package)
		cmp("config path", p.ConfigPath, other.ConfigPath)
		// The validators file, compared here and nowhere else. It is the
		// file that says whose validations this node trusts, so a host
		// where it has moved is a host running on a different trust set
		// than the one recorded, and until the wrapper's inspect answer
		// carried the path, this comparison was two empty strings, which
		// is the vacuous pass the native design note names by name.
		cmp("validators path", p.ValidatorsPath, other.ValidatorsPath)
		cmp("data path", p.DataPath, other.DataPath)
		return out
	}
	cmp("compose project", p.ComposeProject, other.ComposeProject)
	cmp("compose file", p.ComposeFile, other.ComposeFile)
	cmp("service", p.Service, other.Service)
	cmp("container", p.Container, other.Container)
	cmp("image repo", p.ImageRepo, other.ImageRepo)
	cmp("config path", p.ConfigPath, other.ConfigPath)
	cmp("data path", p.DataPath, other.DataPath)
	return out
}

// Describe renders this profile as the operator-facing node identity and
// deployment line, for every reader that shows one, today that is
// baseContext's chat context, and it is meant to be the same function a
// future plan header calls, rather than a second place inventing its own
// wording for the same profile.
//
// node is what to call this deployment in a sentence: the container name on
// a compose host, the systemd unit on a native one, the same fields
// ProfileMatches already names in its own match detail, above. deployment is
// the one-line "what is actually running" a human or a model reads before
// anything is proposed against it; it names the native kind explicitly
// rather than leaving it to be inferred from the absence of a container
// word. fork and version are the pair a caller folds into a knowledge-
// selection target: native's fork is the bare package name, and
// Target.applies is a substring match against fork or version rather than
// exact equality, so "xrpld" reaches the same applies_to entries
// "xrpllabsofficial/xrpld" does today.
//
// PackageVersion is the one native field parseNativeInspect does not require
// a package manager that will not answer is not a version that is
// missing, so a native profile can reach here with it empty. That renders
// as "version unknown" rather than a trailing blank.
func (p Profile) Describe() (node, deployment, fork, version string) {
	if p.Kind == "native" {
		v := p.PackageVersion
		if v == "" {
			v = "version unknown"
		} else {
			v = "version " + v
		}
		return p.Unit,
			fmt.Sprintf("native package install: %s, %s, config %s", p.Package, v, p.ConfigPath),
			p.Package, p.PackageVersion
	}
	return p.Container,
		fmt.Sprintf("%s:%s · %s/%s", p.ImageRepo, p.ImageTag, p.ComposeProject, p.Service),
		p.ImageRepo, p.ImageTag
}

// IdentityKey is the one string this node is keyed by: every approval
// fingerprint, every break-glass window, every compact lookup, and the plan
// id and confirm code derived from them.
//
// It was profile.Container at each of those sites, which a native profile
// leaves empty by design (native identity lives in Unit). Every plan on a
// native host would therefore have been signed against the empty string, and
// two native nodes, or a native node and a container one, would have matched
// each other's approvals and each other's windows. An approval is "for one
// plan, on one node" in the compact's own words, and a key that cannot tell
// two nodes apart cannot carry that.
//
// Per kind:
//
//   - container: the container name, unchanged, byte for byte. Every approval
//     file and every open window on every deployed host is keyed by that
//     string today and keeps matching after this.
//   - native: the systemd unit. Systemd cannot hold two units under one name,
//     so two native nodes on one host are two units and two keys. The config
//     path adds nothing to that distinctness, and leaving it out keeps this
//     identical to what Describe returns, which is the value the offer store
//     already keys an investigation on before investigate/begin compares it
//     against the profile's own key.
//
// A profile with no kind recorded is a container profile written before Kind
// existed, and keys exactly as it always did.
//
// It refuses rather than returning "". A key that can be empty is the defect
// this exists to close, and handing one back from the failure path would put
// that defect straight back at every call site.
func (p Profile) IdentityKey() (string, error) {
	if p.Kind == "native" {
		if p.Unit == "" {
			return "", fmt.Errorf("this native profile names no systemd unit, so it cannot identify its node")
		}
		return p.Unit, nil
	}
	if p.Container == "" {
		return "", fmt.Errorf("this profile names no container, so it cannot identify its node")
	}
	return p.Container, nil
}
