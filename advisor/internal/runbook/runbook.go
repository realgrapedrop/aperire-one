// Package runbook is the registry. It is the second half of the security
// boundary: the ActionPlan type means the agent cannot express a command, and
// the registry means the executor will not perform one that is not declared
// here. No runbook, no action.
//
// Preconditions in this package are the executor's own. They exist to be
// evaluated against live host state at execution time, not to be trusted from
// whatever the plan claimed. ADR 0001 Rule 2 turns each §7 caution into a
// precondition rather than a warning, which is what makes those boundaries
// enforceable instead of advisory.
package runbook

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Class groups runbooks for the operator compact. An operator opts in per
// class, so they can allow configuration edits while refusing restarts.
// ADR 0007.
type Class string

const (
	ClassUpgrade Class = "upgrade" // upgrade and roll back
	ClassRestart Class = "restart" // restart the node or a proxy
	ClassConfig  Class = "config"  // change a configuration value
	ClassRestore Class = "restore" // restore configuration from a backup
	// ClassInvestigate permits break-glass reading — plan-interrogative-loop
	// §11.6. It names no runbook: nothing in the registry ever runs under
	// it, because reading the host is not an action the registry declares.
	// Reusing ClassUpgrade for this would mean an operator who accepted an
	// upgrade ceiling had silently also granted host-log reading into a
	// model provider's context — a widening they never read and never
	// agreed to.
	ClassInvestigate Class = "investigate"
)

// KnownClasses is every class the compact may ever record — the set
// `--classes` is checked against at acceptance time (§11.6's "papercut"
// closed by step 13). ClassInvestigate is included even though it names no
// runbook: it is still a real ceiling the compact can grant or withhold.
func KnownClasses() []Class {
	return []Class{ClassUpgrade, ClassRestart, ClassConfig, ClassRestore, ClassInvestigate}
}

// KnownClass reports whether c is one of KnownClasses — used to catch a typo
// in --classes at accept time rather than letting it write a compact that
// silently permits nothing (or permits a class that will never match a
// registry entry).
func KnownClass(c Class) bool {
	for _, k := range KnownClasses() {
		if k == c {
			return true
		}
	}
	return false
}

// ParamKind is the declared type of a runbook parameter. The registry owns
// this, not the plan: a plan that asserted its own parameter types would be
// grading its own homework.
type ParamKind string

const (
	KindVersion ParamKind = "version" // a release identifier, e.g. 3.2.1
	KindEnum    ParamKind = "enum"
	KindInt     ParamKind = "int"
	KindPath    ParamKind = "path" // a reference to a known artefact, never a free path
	// KindDigest is an image digest, pinned when the operator approved the
	// plan and carried to the run that acts on it (#682). Its own kind
	// rather than a free string, because it is the one value standing
	// between an approval and whatever a tag points at by the time the
	// cutover runs.
	KindDigest ParamKind = "digest"
)

type Param struct {
	Name     string
	Kind     ParamKind
	Required bool
	Allowed  []string // for KindEnum
	Min, Max int      // for KindInt
}

// Verdict is the outcome of one precondition.
//
// Passed is the blocking bit and nothing else reads as one: the executor
// re-evaluates these at run time and refuses on a false, so anything that
// must not proceed has to be false here.
//
// Unmeasured is the third state the list needs, and it exists because
// "pass" was being used for two different things. A check that looked and
// found the host healthy, and a check whose tool errored and never looked at
// all, both rendered green (#679, read on a lab node where a root-owned
// wrapper log made four verbs fail). An operator cannot act on that: the
// store-rotation guard reading `pass` when it never ran is the one place
// this project's own "absent is not zero" rule must not break. So a reading
// nobody took says so, and whether it also refuses is the caller's decision
// per check, taken in Measurement.Verdict below.
type Verdict struct {
	Name   string
	Passed bool
	Detail string
	// Unmeasured marks a verdict whose evidence was never read. It is
	// independent of Passed: an unmeasured check may still be allowed to
	// proceed (a rotation clock a healthy node simply has nothing to say
	// about), and a safety-critical one refuses.
	Unmeasured bool
	// NoOp marks a failure whose only cause is that the plan would change
	// nothing: the node already runs what the plan would put there (#838).
	// It refuses all the same, but it is the finished state, not a safety
	// refusal, and a reader that paints it as one tells an operator whose
	// upgrade just landed that it is stuck. Never set beside a reading that
	// failed: a running version nobody could read is not "nothing to do".
	NoOp bool
}

// Observation is one reading of the node, taken from the node itself.
//
// UptimeSec is a pointer because absent is not zero: a build that did not
// report an uptime has not just started, and reading it as zero would prove
// a restart nobody saw. Healthy and Detail are ConsensusHealthy's answer
// over the SAME reading as the version and the uptime.
type Observation struct {
	Version     string
	UptimeSec   *int
	ServerState string
	Healthy     bool
	Detail      string
}

// Measurement is one host reading, carried as data rather than as a phrase
// the caller has to parse back out of Detail. Two surfaces string-matching
// the same reading is how #676 came about, so the state travels typed.
type Measurement struct {
	// OK is the reading's own answer, meaningful only when Unmeasured is
	// false.
	OK bool
	// Detail is what to render either way, in the host's own words.
	Detail string
	// Unmeasured: no reading was taken.
	Unmeasured bool
	// Failed: the attempt to take it errored (the wrapper refused, a log
	// could not be written) rather than the host simply having nothing to
	// report. The difference decides whether an unmeasured safety check
	// refuses: a node with no rotation to report is ordinary, a node whose
	// rotation clock could not be asked is not.
	Failed bool
	// Unproven: the reading was taken and the one piece of evidence the
	// answer rests on does not exist on this host, so nothing can be
	// vouched for either way. It is not measured, and it refuses on every
	// kind of check, advisory included: an advisory check lets an unread
	// tool through so a sick node keeps its remedy, but a question that was
	// asked and has no evidence behind it is a different fact. The
	// rollback's amendment check is the case (#676): no record of what the
	// target supports means the gate refuses, and the concern beside it
	// says the answer is unknown. Both surfaces read this one field.
	Unproven bool
}

// Measured is the ordinary reading: it was taken, and this is its answer.
func Measured(ok bool, detail string) Measurement {
	return Measurement{OK: ok, Detail: detail}
}

// NotMeasured is a reading the host had nothing to give. Benign: the tool
// answered and there was nothing to read.
func NotMeasured(why string) Measurement {
	return Measurement{Detail: "not measured: " + why, Unmeasured: true}
}

// FailedToMeasure is a reading whose tool errored. This is the state that
// used to arrive as a pass.
func FailedToMeasure(why string) Measurement {
	return Measurement{Detail: "not measured: " + why, Unmeasured: true, Failed: true}
}

// Unproven is a reading taken with nothing to prove its answer by. See the
// field of the same name.
func Unproven(detail string) Measurement {
	return Measurement{Detail: detail, Unproven: true}
}

// Verdict renders a measurement as one precondition.
//
// safety says what an unmeasured reading means for this particular check.
// On a safety-critical one a tool that errored refuses: the Advisor could
// not look, and a swap it cannot vouch for is not one it should invite an
// operator to approve. A benign unmeasured reading never refuses on either
// kind, because a node that simply has nothing to report (no rotation in
// the last day, advisory_delete off) must still be able to upgrade. An
// unproven reading refuses on both kinds and reads "NOT MEASURED, refuses".
func (m Measurement) Verdict(name string, safety bool) Verdict {
	if m.Unproven {
		return Verdict{Name: name, Passed: false, Detail: m.Detail, Unmeasured: true}
	}
	if m.Unmeasured {
		return Verdict{Name: name, Passed: !(safety && m.Failed), Detail: m.Detail, Unmeasured: true}
	}
	return Verdict{Name: name, Passed: m.OK, Detail: m.Detail}
}

// Word is how one verdict reads in a list, and every text surface uses
// this one so they cannot drift apart. Four states, not two: a check that
// could not be taken says so, and says whether that also refuses.
func (v Verdict) Word() string {
	switch {
	case v.Unmeasured && !v.Passed:
		return "NOT MEASURED, refuses"
	case v.Unmeasured:
		return "not measured"
	case !v.Passed:
		return "REFUSES"
	}
	return "pass"
}

// SafetyCritical and Advisory name the two kinds at the call site, so a
// precondition reads as what it is rather than as a bare boolean.
const (
	SafetyCritical = true
	Advisory       = false
)

// HostState is everything a precondition may look at. It is an interface so
// the executor's checks can be exercised against known states in tests without
// a validator present — the one thing you cannot do is test a precondition by
// breaking a production node.
type HostState interface {
	// Kind reports the node's deployment shape: "container" or "native",
	// the one declared fact the native design note builds on. A precondition
	// that needs to speak differently by shape asks this rather than
	// inferring it from which fields happen to be populated, because an
	// unmeasured field on a broken profile and an absent field on a native
	// host must not read the same way.
	Kind() string
	// ProfileMatches reports whether the recorded environment profile still
	// describes the host. ADR 0005: a stale profile is why this is checked
	// before every plan rather than trusted from setup.
	ProfileMatches() (bool, string)
	// RunningVersion is what the node reports right now.
	RunningVersion() (string, error)
	// DiskHeadroomPct is free space on the filesystem the node's data path
	// sits on, as a percentage, and the path that reading was taken on.
	//
	// The path comes back beside the number because the two shapes take this
	// reading in different places: the Advisor statfs's the store itself
	// where it can traverse it, and asks the privilege wrapper to do it as
	// root where it cannot (#465). A precondition that says "82.4% free" and
	// cannot say of what is a reading nobody can check.
	DiskHeadroomPct() (pct float64, path string, err error)
	// BackupExists reports whether a dated backup of the named artefact is
	// present and readable.
	BackupExists(artefact string) (bool, string)
	// ImagePublished reports whether the target image or package exists and is
	// pullable, without touching the running node. It asks the REGISTRY, and
	// it fails closed: unreachable is not evidence the tag exists.
	ImagePublished(version string) (bool, string)
	// ImageLocal reports whether the image for this version is already on
	// this host, without pulling and without a network call — ADR 0019.
	//
	// It exists because of what a rollback is FOR. The target of a rollback
	// is, almost by definition, an image this host was running until the
	// upgrade, so it is already on the disk; and the moment a rollback is
	// wanted is a bad release, in the middle of an incident, which is
	// precisely when a registry lookup is worth nothing to depend on.
	// ImagePublished alone would refuse that rollback with the image sitting
	// right there.
	ImageLocal(version string) (bool, string)
	// PackageKept is ImageLocal's native twin, issue #393's second half: does
	// this host hold a local install artefact for this version, kept beside
	// the config backups before an earlier upgrade replaced it, without
	// asking a repository. The same argument ImageLocal's own comment makes
	// applies here unchanged, the moment a rollback is wanted is a bad
	// release in the middle of an incident, which is exactly when asking a
	// repository is worth nothing to depend on.
	//
	// No wrapper configured answers "not determined here", never "no",
	// absent is not zero, and a caller that read it as a negative would
	// refuse a rollback on evidence nobody gathered.
	PackageKept(version string) (bool, string)
	// ConsensusHealthy is the §7 caution made checkable: a validator that is
	// desynced-but-participating and one that is restarting have very
	// different network effects, so restart is not offered while consensus
	// looks unhealthy.
	ConsensusHealthy() (bool, string)
	// Observe is the node's own account of itself from ONE server_info
	// reading: the build it runs, how long its process has been up, and
	// whether it is in full sync. One reading, because the question it
	// answers after a restart is "is THIS process the one that came back",
	// and a version from one call beside an uptime from another could be
	// two different processes (#769).
	Observe() (Observation, error)
	// RuntimeAccount reports the account the node's container runs as, what
	// its deployment file asks for, and the stop grace that container was
	// created with. Container only; a native host answers with an error,
	// and the precondition that reads this says "not applicable" there.
	//
	// It exists because an image swap can change the account a node runs as
	// without anybody asking. An image built from the signed package
	// defaults to 997:997, a container that records no user has been
	// running as root, and uid 997 on the host is whatever account happened
	// to take that number (on one lab validator's host, another service's).
	// A node that comes back unable to read its own store is the failure
	// this catches before the stop rather than after it.
	RuntimeAccount() (RuntimeShape, error)
	// ImageHeadroom is free space where docker keeps its IMAGES, which is
	// not the node's data path: a build writes its layers where docker
	// lives, and on many hosts that is a different filesystem from the one
	// the ledger store is on. Container only; a native host has neither.
	ImageHeadroom() (availBytes int64, path string, err error)
	// ImageRecipeReady reports whether this host holds the root-owned
	// recipe its image is built from, asked of the privilege wrapper that
	// would do the building. Container only.
	ImageRecipeReady() Measurement
	// FarFromRotation reports whether the node's next store rotation is
	// further off than the time an operation needs. The wrapper's own guard
	// refuses a stop inside a rotation it can SEE; this is the other half,
	// a rotation that has not started yet and would start during the swap.
	// A clock that could not be read comes back unmeasured, and says
	// whether the attempt errored, which is what decides between "this
	// node has nothing to report" and "nobody looked" (#679).
	FarFromRotation(need time.Duration) Measurement
	// RollbackSafeFromAmendments reports whether the version a rollback
	// would return to can be expected to come up unblocked. It reasons from
	// the network's own amendment clock, because nothing here can ask an
	// image what its build supports without running it, and running a
	// second copy of a validator's build against its own config is the one
	// thing an operator must never do.
	RollbackSafeFromAmendments(target string) Measurement
	// IdentityUnchanged compares the node answering now with the diagnostic
	// snapshot taken before the change: the same node key, the same
	// validator key, an active validator list of the same size, and not
	// amendment blocked. A version number cannot tell you any of that, and
	// all four are things an operator checks by hand after a swap.
	IdentityUnchanged() (bool, string)
	// DeploymentTag is the version the deployment definition names right now.
	// The interrupting step brings the service up from that file, so this is
	// the difference between restarting onto what was approved and restarting
	// onto whatever the file happens to say by then.
	DeploymentTag() (string, error)
	// RollbackTargetOrigin is where the image for a rollback target came
	// from, and whether that image is on this host right now.
	//
	// Two answers, because they are two different facts and deriving one
	// from the other is #680: presence used to stand in for origin, so
	// "built on this host and since pruned", the one case a rebuild
	// exists for, could not be expressed, and the rollback fell through
	// to a pull of a localhost/ name no registry can answer. The origin is
	// read off the image when it is here, and off the dated deployment
	// copy that named it when it is not.
	//
	// The origins are "local-build", "official", "third-party" or
	// "unknown", and "unknown" is a real answer: a caller refuses rather
	// than guessing which verb puts the image back.
	// DeploymentImage is the WHOLE image reference the deployment names,
	// repository and tag or digest. The tag is not always the staging
	// check: a source switch keeps the version and changes the digest,
	// so on that path this is what says whether the file holds what was
	// approved.
	DeploymentImage() (string, error)
	// RollbackImaging takes the version and the BASENAME of the dated
	// copy the derivation named, so a caller can never restore a file
	// other than the one the approval covers (#682, second review).
	RollbackImaging(version, restoreCopy string) RollbackImaging
	// UpgradeSource says where this version's image would come from, and
	// on the official path the digest it would be pinned to.
	//
	// One reading, asked once, so the plan, the card and the executor
	// cannot each ask the registry and act on different answers if a tag
	// moves between them. source is "official image", "built here",
	// "packages.xrplf.org" or "package repository".
	UpgradeSource(version string) (source, digest, detail string)
	// OfficialDigestPublished is whether the official repository still
	// serves this exact digest, the image a rollback to a pruned official
	// target fetches (#984). Fails closed, and the detail names what could
	// not be read.
	OfficialDigestPublished(version, digest string) (bool, string)
	// NodeShape is the narrow view of the deployment's profile a
	// precondition reads. See DeploymentShape.
	NodeShape() DeploymentShape
	// EvidenceCaptured reports whether a diagnostic snapshot was taken before
	// any state change. Runbook 11 opens with "do not restart yet, a restart
	// destroys the evidence"; missed-ledger-forensics reached the same
	// conclusion independently.
	EvidenceCaptured() (bool, string)
	// ConfigReadable asks the node's own container whether it can read the
	// configuration it would start with. Three verdicts, not two: a container
	// with no shell, one that is not running, and a config that arrives by a
	// route the wrapper cannot see are all cases where the honest answer is
	// that nothing was measured. ADR 0018, and the 2026-08-19 incident where
	// a config the container could not read made the node come up on the
	// image's defaults with no error anywhere.
	ConfigReadable() (verdict, detail string)
}

// The three ConfigReadable verdicts. Named here rather than in the host
// package because the preconditions that branch on them live here, and a
// string literal in a precondition is a typo that fails by passing.
const (
	ConfigReadableYes     = "readable"
	ConfigReadableNo      = "unreadable"
	ConfigReadableUnknown = "unknown"
)

// Precondition is a named check the executor runs itself.
// KeyChangesSomething is the Key of the precondition that refuses a plan
// which would change nothing, on the upgrade and on the rollback alike.
// Its verdict's Detail names the running version.
const KeyChangesSomething = "changes_something"

type Precondition struct {
	Name  string
	Check func(p Params, h HostState) Verdict

	// Key names the check for a machine reader. Name is a sentence and has
	// been reworded before: #682 renamed "target version differs from what
	// is running" to "this run changes something", and the Operations card,
	// which found that check by its words, stopped recognising a finished
	// upgrade (#838). Empty for every check no reader needs to find.
	Key string

	// Gates names the stage this precondition must pass before. Empty means
	// every stage, which is the right default for anything describing the
	// host's fitness to be touched at all.
	//
	// StageCutover exists for a precondition that an earlier stage is what
	// SATISFIES. The two backup checks are the case that forced this: a
	// dated backup is what prepare's first two steps produce, so requiring
	// one before prepare may be approved makes a first upgrade on a host
	// that has never been upgraded impossible — the tab refuses to offer
	// the approval, and nothing else creates the file. The backups still
	// gate the step that interrupts validation, which is the step they
	// exist to make recoverable.
	Gates string
}

// RollbackImaging is everything RB-004's step list turns on: where the
// image it is going back TO came from, whether that image is here, what
// the deployment names right now, and the dated copy to restore when the
// whole file has to go back rather than one line of it.
//
// Four facts rather than two booleans, because two booleans derived from
// each other is #680: presence stood in for origin, so "built here and
// since pruned" could not be said and the branch that rebuilds it was
// unreachable. And the file's own origin is a different fact from the
// target's: the swap that has to be undone wrote an entrypoint/command
// pair beside the image line, so what decides "restore the whole copy" is
// what the file says now, not where the target came from.
type RollbackImaging struct {
	TargetOrigin string
	ImageLocal   bool
	LiveOrigin   string
	RestorePath  string
	// Detail is what to say about the reading, including what could not
	// be read. Never empty.
	Detail string
	// RestoreDigest is the digest the copy named in RestorePath pins its
	// image to, empty when that copy names a tag instead. An official
	// target is fetched and verified against THIS digest rather than
	// against a tag: the copy is the record of what the node ran, and a
	// tag could have moved since (#682, second review).
	RestoreDigest string
	// LiveDigest is the digest the deployment names right now, empty when
	// it names a tag instead (#682). Undoing a source switch leaves the
	// release where it was, so this is the only reading that says the
	// container was really replaced rather than the file quietly restored
	// under a container nobody recreated.
	LiveDigest string
	// RunningOrigin is where the image the container is RUNNING came from,
	// read off the container rather than the file (#664). The two differ
	// between a build's prepare, which points the file at the build, and
	// its cutover, which is what puts the container on it: a check that
	// read the file there called a run half done "nothing to do". Empty
	// when it was not read.
	RunningOrigin string
}

// RuntimeShape is what an upgrade has to know about a container deployment
// before it stops it: who it runs as, how long its stop actually gets, and
// whether the node's config reaches /etc/xrpld by a mount or by a copy the
// entrypoint performs.
//
// The last one is not decoration. The image built from the signed package
// copies /config/rippled.cfg to /etc/xrpld/xrpld.cfg at start and fails
// LOUDLY when it cannot, which is the right behaviour and a behaviour change
// from the image it replaces. A legacy deployment mounts the config only at
// /config/rippled.cfg and names no user: as root the copy succeeds, as
// anyone else it cannot write /etc/xrpld and the container exits 1. That is
// a node that does not come back, found after the stop rather than before
// it, unless this is read first.
type RuntimeShape struct {
	// ContainerUser is what the RUNNING container is configured as. Empty
	// means root: the image's own default applies when nothing overrides it.
	ContainerUser string
	// ComposeUser is what the deployment file asks for, empty when it asks
	// for nothing.
	ComposeUser string
	// StopTimeout is the grace the running container was created with, in
	// seconds, and empty when it names none. That, not the file's current
	// stop_grace_period, is what its stop gets unless -t says otherwise.
	StopTimeout string
	// ConfigAtEtc is true when the deployment mounts the node config at
	// /etc/xrpld/xrpld.cfg, so the entrypoint has nothing to copy.
	ConfigAtEtc bool
}

// Params is the validated parameter set handed to a precondition.
type Params map[string]string

// Runbook is a declared, permitted operation.
type Runbook struct {
	ID            string
	Class         Class
	Summary       string
	Params        []Param
	Preconditions []Precondition
	// Reversible records whether a completed run can be undone, and by what.
	// Seven of the eight v1 runbooks are; the exception is restart, which
	// carries the heaviest preconditions instead. ADR 0001.
	//
	// ReversedBy must name a runbook that EXISTS in the registry — it was
	// pointing at one that had never been written, so the plan endpoint
	// published a reversal the product could not perform. Leave it empty and
	// describe the manual path in ReversalNote when there is no runbook yet;
	// a registry test enforces the rule.
	Reversible bool
	ReversedBy string
	// ReversalNote is how a run is undone when no runbook does it. Shown to
	// the operator instead of a promise nothing can keep.
	ReversalNote string
	// Why is the deterministic condition that raises this runbook — ADR 0001
	// calls it the trigger. Carried here so a plan can say where it came from.
	// A recommendation that appears without one reads as an opinion, and an
	// operator has no way to judge an opinion about their own validator.
	Why []string
	// Expected is what should be true once it has run: ADR 0001's hypothesis.
	// It is also the verification — a change with no stated expectation cannot
	// be said to have worked, only to have finished.
	Expected []string
	// Stages are the stages this runbook runs, in order. RB-001 declares two,
	// RB-002 one — ADR 0016. They exist because stagesInOrder, evaluateReadiness
	// and the execute handler's stage check were all hardcoded to the upgrade's
	// prepare/cutover pair, so a one-stage runbook was refused by code that had
	// never been told there could be one.
	Stages []string
	// GrantScopes are the scopes an approval ceremony may be held for. A
	// superset of Stages: the upgrade adds the compound "upgrade" scope, which
	// is signed over once and covers both of its stages in sequence (see
	// approval.Covers). Nothing RUNS a scope that is not also a stage.
	GrantScopes []string

	// ValidateParams is a rule that spans two parameters, checked after every
	// individual one has bound. Param cannot express it: BindParams validates
	// each declaration on its own, and RB-003's band for `value` is a
	// function of `key`.
	//
	// It hangs off the runbook rather than being a special case inside
	// BindParams so that every binding site inherits it with no new call —
	// and there are three of them (check, approve, execute), all of which
	// must agree, because the parameters are inside the fingerprint.
	ValidateParams func(Params) error
}

// DeclaresParam reports whether this runbook declares a parameter by name.
//
// The executor asks before it compares the deployment tag to a version:
// RB-002 takes no version, so a comparison against an absent parameter
// refused every restart. Gated on the DECLARATION, never on the bound
// value — a runbook that declares target_version and binds it empty is a
// different problem, and the refusal for that one stays where it is
// (ADR 0016 §5).
func (b Runbook) DeclaresParam(name string) bool {
	for _, p := range b.Params {
		if p.Name == name {
			return true
		}
	}
	return false
}

var (
	ErrUnknownRunbook = errors.New("no such runbook")
	ErrBadParams      = errors.New("parameters rejected")
)

// Registry holds the permitted set. Nothing outside it can be executed.
type Registry struct{ books map[string]Runbook }

func NewRegistry(rs ...Runbook) *Registry {
	r := &Registry{books: map[string]Runbook{}}
	for _, b := range rs {
		r.books[b.ID] = b
	}
	return r
}

func (r *Registry) Lookup(id string) (Runbook, error) {
	b, ok := r.books[id]
	if !ok {
		return Runbook{}, fmt.Errorf("%w: %q", ErrUnknownRunbook, id)
	}
	return b, nil
}

func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.books))
	for id := range r.books {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// BindParams checks the plan's parameters against what the runbook declares
// and returns them as strings. Anything undeclared is rejected rather than
// ignored: a parameter the registry does not know about is one nothing has
// reasoned about.
func (b Runbook) BindParams(raw map[string]any) (Params, error) {
	out := Params{}
	declared := map[string]Param{}
	for _, p := range b.Params {
		declared[p.Name] = p
	}
	var probs []string

	for k := range raw {
		if _, ok := declared[k]; !ok {
			probs = append(probs, fmt.Sprintf("undeclared parameter %q", k))
		}
	}
	for _, p := range b.Params {
		v, present := raw[p.Name]
		if !present {
			if p.Required {
				probs = append(probs, fmt.Sprintf("missing required parameter %q", p.Name))
			}
			continue
		}
		s := fmt.Sprintf("%v", v)
		switch p.Kind {
		case KindVersion:
			if !versionPattern(s) {
				probs = append(probs, fmt.Sprintf("parameter %q is not a version: %q", p.Name, s))
			}
		case KindEnum:
			if !contains(p.Allowed, s) {
				probs = append(probs, fmt.Sprintf("parameter %q must be one of %v, got %q", p.Name, p.Allowed, s))
			}
		case KindDigest:
			if !digestPattern(s) {
				probs = append(probs, fmt.Sprintf(
					"parameter %q is not a digest: %q", p.Name, trunc80(s)))
			}
		case KindPath:
			// A path parameter names a known artefact, never a free filesystem
			// location. Anything that could climb out of it is rejected here.
			if strings.ContainsAny(s, "/\\") || strings.Contains(s, "..") {
				probs = append(probs, fmt.Sprintf("parameter %q must name an artefact, not a path: %q", p.Name, s))
			}
		}
		out[p.Name] = s
	}
	if len(probs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrBadParams, strings.Join(probs, "; "))
	}
	// Last, and only once every declared parameter has bound: a cross-field
	// rule reading a value that failed its own check would report the wrong
	// problem.
	if b.ValidateParams != nil {
		if err := b.ValidateParams(out); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadParams, err.Error())
		}
	}
	return out, nil
}

// digestPattern is the one shape a digest may have, and it is the same one
// the wrapper's require_digest enforces. Both check it, because either one
// could be reached first and neither is entitled to assume the other ran.
func digestPattern(s string) bool {
	const p = "sha256:"
	if len(s) != len(p)+64 || !strings.HasPrefix(s, p) {
		return false
	}
	for _, c := range s[len(p):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func trunc80(s string) string {
	if len(s) <= 80 {
		return s
	}
	return s[:80] + "…"
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// versionPattern accepts digits and dots only. Deliberately narrow: this value
// reaches an image tag and a package pin, so anything else is a problem.
func versionPattern(s string) bool {
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

// diskHeadroomVerdict is the disk-headroom precondition, shared by the four
// runbooks that carry it. Only the floor differs between them, and the floor
// is the one thing each call site states for itself.
//
// The reading names the path it was taken on, because on a native host it is
// not taken by this process at all: the node's state directory belongs to the
// node's own account, and the privilege wrapper measures it as root (#465). A
// percentage with no path behind it cannot be checked against the box.
//
// A reading nobody could take refuses. That is the #427 rule, and it is why
// this returns false rather than skipping the check: unmeasured is never
// healthy.
func diskHeadroomVerdict(name string, floorPct float64, h HostState) Verdict {
	pct, path, err := h.DiskHeadroomPct()
	if err != nil {
		// Refuses, and says it was not measured rather than implying a
		// reading was taken and came back short (#679).
		return FailedToMeasure(fmt.Sprintf("could not read disk headroom: %v", err)).
			Verdict(name, SafetyCritical)
	}
	where := ""
	if path != "" {
		where = " on " + path
	}
	if pct < floorPct {
		return Verdict{Name: name, Passed: false, Detail: fmt.Sprintf("%.1f%% free%s, floor is %.0f%%", pct, where, floorPct)}
	}
	return Verdict{Name: name, Passed: true, Detail: fmt.Sprintf("%.1f%% free%s", pct, where)}
}

// The two names a precondition needs from the host package without
// importing it: the dependency runs host to runbook, never the other way.
// A test holds these equal to host's own constants, the same way the
// executor's copies of the image repositories are held to theirs.
const (
	OfficialImageSourceName = "the official image"
	OriginOfficialName      = "official"
	OriginLocalBuildName    = "local-build"
	OriginThirdPartyName    = "third-party"
)

// EtcConfigPathName is where xrpld reads its configuration inside every
// image this project deals with, spelled here for the same reason the two
// names above are. A test holds it equal to host's and to the executor's.
const EtcConfigPathName = "/etc/xrpld/xrpld.cfg"

// srcOrBuild is what to call a source in a sentence when it may be empty.
func srcOrBuild(src string) string {
	if src == "official" {
		return OfficialImageSourceName
	}
	return "a build from the signed package"
}

// originWords is an origin in the words a verdict uses.
func originWords(origin string) string {
	switch origin {
	case OriginOfficialName:
		return OfficialImageSourceName
	case OriginThirdPartyName:
		return "a registry image"
	case OriginLocalBuildName:
		return "a build on this host"
	default:
		return "an image whose origin could not be read"
	}
}

// containsArg reports whether a command line carries a flag, written either
// as its own word or as flag=value.
func containsArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// BuildPathDoubleConf is RB-001's one refusal on the build path (#664): a
// command that passes --conf with no entrypoint of its own hands the built
// image's entrypoint script a second --conf, and xrpld refuses that twice
// over. One predicate for the precondition and for the card's gating rows
// (host.FindingsForTarget), so the row that says "write the arguments down"
// is on the card exactly when this check refuses, and in no other build
// case (#1009).
func BuildPathDoubleConf(entrypoint, command []string) bool {
	return len(entrypoint) == 0 && containsArg(command, "--conf")
}

// DeploymentShape is the part of the node's profile a precondition reads.
//
// A narrow view on purpose. The whole profile is a large structure with a
// verdict for every field, and a precondition that took it would be a
// precondition that could quietly start depending on any of it. These five
// are what decides whether a deployment can run an image that carries no
// entrypoint of its own.
type DeploymentShape struct {
	// Read is false when the deployment could not be resolved. #679: a
	// shape nobody could read is not a shape that passed.
	Read bool
	// Notes is why, when it could not.
	Notes []string
	// ConfigAtEtc is true when the node's config is mounted where xrpld
	// reads it, rather than copied there by an entrypoint script.
	ConfigAtEtc bool
	// ArgsWrittenDown is true when the deployment names both an
	// entrypoint and a command, so the arguments do not come from
	// whichever image it happens to point at.
	ArgsWrittenDown bool
	// Silent is --silent among those arguments.
	Silent bool
	// CommandOverride is what the deployment says the node runs with.
	CommandOverride []string
	// EntrypointOverride is the entrypoint the deployment names, empty
	// when it leaves the image's own in place. A build's image has an
	// entrypoint script that adds --conf itself, so whether this is set
	// decides whether a --conf in the command reaches xrpld once or twice.
	EntrypointOverride []string
}
