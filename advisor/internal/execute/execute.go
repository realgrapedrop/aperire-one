// Package execute performs an approved plan through the privilege wrapper.
//
// The security property is the shape, not the wrapper. Look at Step: it has a
// Verb from a closed set and at most one argument. There is no field that can
// carry a command, no string that gets concatenated into a shell, and no path
// supplied by the caller — the wrapper holds every path itself. An agent that
// wanted this package to do something not listed in Steps() has no way to
// express the request.
//
// The wrapper is defence in depth on top of that. On a host where the calling
// user is in the docker group it is an allow-list and an audit trail rather
// than containment, and the compact says so.
//
// Three things happen around every step, and they are the reason this is not
// a shell script:
//
//   - Preconditions are re-evaluated immediately before the stage that
//     interrupts validation, not once at the start. Consensus health measured
//     four minutes ago is a memory, and the whole point of the check is that
//     it is a measurement.
//   - Each step's result is verified against the host, not against the exit
//     code. `docker pull` succeeding does not mean the image is what the tag
//     claimed.
//   - Every start, result and refusal is written to the ledger by this code,
//     from what it observed. Nothing records itself.
package execute

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/runbook"
)

// Stage names, matching the approval stages. Splitting them is what keeps the
// reversible work and the outage as separate decisions.
const (
	StagePrepare = approval.StagePrepare
	StageCutover = approval.StageCutover
	// StageRestart is RB-002's only stage. There is nothing reversible to
	// separate from the outage, so there is nothing to split — ADR 0016.
	StageRestart = approval.StageRestart
	// StageConfig is RB-003's reversible half: the dated copy and the edit —
	// ADR 0018. The interrupting half is StageRestart, reused unchanged.
	StageConfig = approval.StageConfig
	// StageRollback is RB-004's only stage — ADR 0019. One stage, because the
	// rollback IS the restart: there is no reversible half to separate from
	// the outage, and separating one would leave the deployment naming a
	// version the node is not running.
	StageRollback = approval.StageRollback
)

// rotationRefuses names the stages a store rotation stands in the way of:
// the three that take the node off the network.
//
// It is the same set the wrapper refuses with exit 64, spelled here rather
// than inferred from Step.Interrupts, because the decision has to be made
// BEFORE the steps are walked — the interrupting step is inside the loop the
// Spend defer already covers, which is the whole problem issue #93 describes.
//
// StagePrepare and StageConfig are absent on purpose. Both are the reversible
// half of a two-stage act: prepare pulls an image, config writes a file, and
// the wrapper does either happily while a rotation runs. Refusing them would
// stop work that is safe now and would have to be redone later, and — for a
// compound grant — would do it at the stage that does not spend the grant,
// which is exactly the retryable half the grant is designed to protect.
func rotationRefuses(stage string) bool {
	switch stage {
	case StageRestart, StageCutover, StageRollback:
		return true
	}
	return false
}

// Step is one wrapper call. Note what it cannot hold.
type Step struct {
	Name  string
	Stage string
	// Verb is one of the wrapper's fixed verbs.
	Verb string
	// Arg is the single argument, derived from validated runbook parameters.
	// Empty for verbs that take none.
	Arg string
	// Arg2 is the second, and exactly one kind of value goes in it: the
	// digest an official image was pinned to (#682). The wrapper shapes it
	// itself before acting on it, and the verbs that accept one are a
	// closed list there.
	Arg2 string
	// Why is carried into the ledger so the record explains itself to someone
	// reading it a year later without the code.
	Why string
	// Interrupts marks the step that takes the node off the network.
	Interrupts bool
	// MayRestart marks a step that is not meant to take the node down but
	// can: a package install, whose maintainer scripts restart the unit on
	// some platforms (#415). What the node did during it is read afterwards,
	// never assumed (#769).
	MayRestart bool
	// RestoreOnFailure asks the executor to put the deployment file back
	// as it was, and recreate again, when this step fails.
	//
	// Only the recreate carries it, and only on a path that EDITED the
	// deployment first. Everything else in this project prints a rollback
	// hint and leaves the operator to judge, deliberately. The difference
	// here is what the failure leaves behind: a node that is down, on a
	// file naming an image it could not come up on, with the copy that
	// worked sitting beside it. There is no judgement in that; waiting for
	// a person is the node being off the network for as long as it takes
	// someone to read a page.
	RestoreOnFailure bool
	// Verify checks the host after the step. A nil Verify means the step is
	// its own evidence; most are not.
	Verify func(out string, st runbook.HostState) error
	// Undo is what an operator would run. Recorded, never executed
	// automatically.
	Undo string
}

// Runner invokes the privilege wrapper.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// LineRunner is a Runner that can hand back each line of output as it
// lands, rather than all of it when the step ends.
//
// Optional: a Runner that does not implement it still works, and its steps
// report at the end as they always did. The one that matters is the real
// one, because a step taking a minute with nothing on screen is the thing
// #678 is about. The step's own transcript lines are written from the sink,
// so they carry the time each line actually arrived.
type LineRunner interface {
	RunLines(ctx context.Context, sink func(string), name string, args ...string) ([]byte, error)
}

// Executor performs one plan.
type Executor struct {
	PlanID      string
	Runbook     runbook.Runbook
	Params      runbook.Params
	Wrapper     string
	State       runbook.HostState
	Ledger      *ledger.Ledger
	Runner      Runner
	ApprovalDir string
	Fingerprint string
	Node        string
	Now         func() time.Time
	// Sleep replaces time.Sleep in the late watcher; tests inject one.
	Sleep func(time.Duration)
	// Verifier checks the passkey assertion carried by an approval. Required:
	// without it an approval is authorised by existing, and anything that can
	// write the file gets to act.
	Verifier approval.Verifier

	// Actor is who this run is attributed to, and it is NOT set by the caller.
	//
	// RunStage populates it from the approval it has just verified, and every
	// entry this package writes afterwards carries it. That is deliberate and
	// load-bearing: the request that starts a run (advisord's executeRequest,
	// or the command-line tool) carries no identity and must not gain one —
	// an actor taken from the caller would be a field an attacker fills in.
	// Reading it off the verified approval is the same "recompute here, never
	// trust the caller" discipline the fingerprint already gets, and it makes
	// the web path and the CLI path produce identical attribution with no new
	// input surface on either.
	Actor ledger.Actor

	// Backups records what the run created, so the rollback it prints refers
	// to files it saw appear rather than to files it hopes exist.
	Backups map[string]string
	// Log is the live transcript, if one is open. Separate from the ledger:
	// that is the audit, this is what someone watching needs.
	Log *RunLog

	// DigestDir persists what the pulled tag resolved to, so a cutover in a
	// later process can refuse an image that moved since prepare verified it.
	// Empty disables the check rather than failing closed — an operator who
	// upgraded mid-plan should not be stranded by a directory that did not
	// exist when prepare ran.
	DigestDir string

	// RotationInFlight asks whether the node's ledger store is mid-rotation,
	// with the wrapper's own one-line explanation beside it — issue #93.
	//
	// A function rather than a dependency, because this package must not
	// import internal/host: the whole shape of Step is "nothing the caller
	// supplies widens what can happen", and a host handle in here is a second
	// way for a caller to reach the node that is not a wrapper verb. The
	// service and the CLI both hand it host.State.RotationInFlight, which is
	// the same reading the wrapper's own restart guard performs.
	//
	// Nil means no reader, which reads as NOT in flight. Every table test and
	// any future non-node caller constructs an Executor without one, and a nil
	// that refused would turn "this caller cannot see the node" into "this
	// caller may not act".
	RotationInFlight func() (bool, string, error)

	// ClaimedBy names the program this run is in, for the claim it puts on
	// its approval (#1063): a second run refused by that claim says which
	// process holds it. Empty reads as this program's own name.
	ClaimedBy string
	// claimRun is this run's claim value, made once and kept across the
	// stages of a merged run. claims are the grant scopes this run claimed
	// and has not yet spent or given back.
	claimRun string
	claims   map[string]bool
	// lastStep is the step the run was at, for the note a stop leaves on
	// the approval, and used whether this run spent one. claimMu guards these: a signal handler settles the
	// claim from another goroutine (Interrupt).
	lastStep string
	used     bool
	claimMu  sync.Mutex
	// ledgerErr is the first write to the ledger that failed during this run
	// (#1091). A run whose acts it cannot record does not go on to act.
	ledgerMu  sync.Mutex
	ledgerErr error

	pulledDigest string
	// appliedAt is when this run's interrupting step began. See RunStage.
	appliedAt time.Time
	// began is when this run first acted under a verified approval, and
	// mayRestartAt when a step that can restart the node as a side effect
	// first began. Every reading taken outside the confirmation loops is
	// judged against one of them.
	began, mayRestartAt time.Time
	// staged is the release a reversible stage left the node set to start
	// on next, and how: "deployment" when the deployment file now names it,
	// "package" when the package is installed under a process still running
	// the old one. Empty when nothing the node starts from has changed.
	staged, stagedHow string
	// touched is set the moment a step that can change the deployment or
	// the node BEGINS, whether or not it then succeeds: a set-image that
	// failed half way may already have written the file. RollbackHint reads
	// it, so a run that halted with nothing past its backups and checks
	// never prints a restore-and-recreate for a node nobody changed (#1001).
	touched bool

	// What this stage did to the deployment file, so a stage stopped by a
	// lapsed approval can put back the change it had already made (#1047,
	// review). Reset at the start of every RunStage. stageCopy is the dated
	// copy of the file as it stood before the stage's first edit;
	// stageEdits counts the edits that began; the three "at start" values
	// are what the run had touched and staged when the stage began, which
	// is what it goes back to once the file is back.
	stageEdits                  int
	stageCopy                   string
	stageTouched                bool
	stageStaged, stageStagedHow string
}

// leavesDeploymentAsItWas is every wrapper verb a run uses that reads, copies
// or fetches and never changes the deployment file or the node. A closed
// list on purpose, the other way round from a list of verbs that change
// things: a verb added later and missing here counts as a change, so the
// way back is printed rather than silently dropped.
var leavesDeploymentAsItWas = map[string]bool{
	"backup-compose": true, "backup-config": true, "package-keep": true,
	"pull": true, "pull-official": true, "build-image": true,
	"verify-official-image": true, "image-digest": true, "image-version": true,
	"running-digest": true, "artefact-hashes": true, "package-available": true,
	"inspect": true, "status": true, "disk": true, "journal": true, "limits": true,
	"node-log": true, "resources": true, "config-readable": true, "show-config": true,
	"show-toml": true, "show-validators": true, "sysctl-relevant": true, "unit-status": true,
}

// readsOnly is every wrapper verb that reads the host and leaves it exactly
// as it was: no file written, no image fetched or built, no container
// created, nothing restarted (#1047). Every other step needs the approval
// to still stand at the moment it begins, so RunStage asks again before it.
//
// Not leavesDeploymentAsItWas. That list answers "is the deployment file
// changed", so it rightly holds pull, build-image and the backups. This one
// answers "does the step change the host at all", read off the wrapper's
// own case for each verb, and those do: an image in the store, a dated copy
// on disk. verify-official-image and image-version are out too: each makes
// a throwaway container from the image, one to copy its binary out, the
// other to run it for its version.
//
// A closed list the same way round as that one: a verb added later and
// missing here asks for consent before it runs. The reads that follow a
// restart (running-digest, inspect, node-log) are here on purpose. A restart
// that began under a valid approval is checked to the end, never left
// unverified because the approval ran out while the node came back.
var readsOnly = map[string]bool{
	"status": true, "inspect": true, "image-digest": true, "running-digest": true,
	"artefact-hashes": true, "package-available": true, "config-readable": true, "node-log": true,
}

// ErrConsentLapsed is a stage that stopped before a step that changes the
// host because the approval no longer covered it (#1047).
var ErrConsentLapsed = errors.New("the approval no longer covers this run")

// ConsentLapsedError says which step did not run, and why the approval no
// longer covered it: errors.Is finds ErrConsentLapsed and the approval
// package's own cause (ErrExpired, ErrNone, ...) through it.
type ConsentLapsedError struct {
	Stage, Step string
	Cause       error
	// Restored is the dated copy put back over the deployment file because
	// this stage had already changed it, empty when it had not or when the
	// put-back failed. RestoreErr is why it failed. Nothing is recreated
	// either way: the file goes back, the node is left as it is.
	Restored   string
	RestoreErr error
}

func (e *ConsentLapsedError) Error() string {
	msg := fmt.Sprintf("stage %s: %v before %q, so it and every step after it did not run",
		e.Stage, e.Cause, e.Step)
	switch {
	case e.Restored != "":
		msg += "; the deployment change this stage had made was put back from " + e.Restored +
			" and nothing was recreated"
	case e.RestoreErr != nil:
		msg += "; this stage had changed the deployment and putting it back failed: " + e.RestoreErr.Error()
	}
	return msg
}

func (e *ConsentLapsedError) Unwrap() []error { return []error{ErrConsentLapsed, e.Cause} }

// consentStands asks again, immediately before a step that changes the
// host, whether the approval this stage verified still covers it. The same
// signed check RunStage opened with, against this run's clock: an approval
// that expired or was withdrawn since then stops the run here, before the
// step, and the ledger says which step and why.
//
// A stage that had already changed the deployment file when its approval
// lapsed puts that change back, from the copy taken before it, and does
// not recreate (#1047, review). The refusal comes after a change there, so
// the one honest way to stop is to undo the change the stage made under the
// consent it no longer has. A recreate would be a second act nobody
// approved.
func (e *Executor) consentStands(ctx context.Context, stage string, s Step) error {
	a, err := approval.CheckSigned(e.ApprovalDir, e.PlanID, e.Fingerprint, e.Node, stage, e.now(), e.Verifier)
	if err == nil {
		// And it is still this run's (#1063). A grant held by another run,
		// or one with no claim at all (written again since this run claimed
		// it), is not the consent this run started under.
		if err = e.stillHeld(a); err == nil {
			return nil
		}
	}
	e.record(ledger.KindRefusal, "executor refused: the approval no longer covers this run, before "+s.Name,
		map[string]any{"stage": stage, "step": s.Name, "verb": s.Verb, "error": err.Error(),
			"reason": "approval_lapsed"})
	lapse := &ConsentLapsedError{Stage: stage, Step: s.Name, Cause: err}
	if e.stageEdits > 0 {
		e.putBackStage(ctx, s, lapse)
	}
	return lapse
}

// editsDeployment is every verb that rewrites the deployment file. Each
// takes a dated copy of its own first and names it on a "backup: " line,
// except restore-compose, which puts a named copy back.
var editsDeployment = map[string]bool{
	"set-image": true, "set-image-local": true, "set-image-official": true, "restore-compose": true,
	"set-runtime-user": true, "add-config-mount": true, "set-node-args": true,
}

// putBackStage restores the deployment file to the copy taken before this
// stage's first edit, and says what happened either way.
func (e *Executor) putBackStage(ctx context.Context, s Step, lapse *ConsentLapsedError) {
	if e.stageCopy == "" {
		lapse.RestoreErr = errors.New("this stage took no copy of the deployment before changing it")
		e.Log.Write("note", s.Name, "this stage changed the deployment and took no copy before it, "+
			"so it could not be put back")
		return
	}
	name := filepath.Base(e.stageCopy)
	out, err := e.Runner.Run(ctx, e.Wrapper, "restore-compose", name)
	if err != nil {
		lapse.RestoreErr = fmt.Errorf("%v (%s)", err, lastLine(strings.TrimSpace(string(out))))
		e.record(ledger.KindRunHalted, "the deployment could not be put back after the approval lapsed",
			map[string]any{"backup": name, "error": err.Error(), "output": strings.TrimSpace(string(out))})
		e.Log.Write("fail", s.Name, "the deployment change this stage made could not be put back: "+err.Error())
		return
	}
	lapse.Restored = name
	e.record(ledger.KindStepSucceeded, "put the deployment back as it was before this stage; the approval lapsed",
		map[string]any{"backup": name, "stage": lapse.Stage})
	e.Log.Write("note", s.Name, "the approval lapsed after this stage changed the deployment, so "+name+
		" was put back over it. Nothing was recreated")
	e.touched, e.staged, e.stagedHow = e.stageTouched, e.stageStaged, e.stageStagedHow
	word := deploymentUnchanged
	if e.touched {
		word = deploymentChanged
	}
	e.recordDeploymentOrSay(s.Name, word)
}

// keptPathFrom reads the kept package's path off package-keep's
// "kept<TAB>path<TAB>version<TAB>sha256" line.
func keptPathFrom(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Split(strings.TrimSpace(ln), "\t"); len(f) >= 2 && f[0] == "kept" {
			return f[1]
		}
	}
	return ""
}

// Kept is the package this run kept before installing another, empty when
// it kept none.
func (e *Executor) Kept() string { return e.Backups["package-keep"] }

// Touched reports whether this run began any step that can change the
// deployment or the node.
func (e *Executor) Touched() bool { return e.touched }

// Staged is the release this run has already set the node to start on next,
// and how, without having restarted it. A run that stops before its restart
// with something staged has NOT left the node untouched: the next restart,
// by anyone, starts that release (#769).
func (e *Executor) Staged() (version, how string) { return e.staged, e.stagedHow }

// AppliedAt is when this run's interrupting step began, zero if it never
// did.
func (e *Executor) AppliedAt() time.Time { return e.appliedAt }

// Reading is one judged reading of the node against the moment this run
// began: NotRestarted means the process answering was there before the run
// touched anything. It is what a stop, a halt or a finished reversible stage
// says about the node, instead of assuming (#769). Nil where there is no
// node to ask.
func (e *Executor) Reading(expected string) *Proof {
	if e.State == nil || e.began.IsZero() {
		return nil
	}
	obs, err := e.State.Observe()
	return Judge(obs, err, e.began, e.now(), expected)
}

// PrepareRestarted answers whether a step that may restart the node (a
// package install) already did: a process newer than that step. A look
// that records nothing and adopts nothing, so the caller can spend the
// grant first and refuse the adoption when the spend fails (#781).
func (e *Executor) PrepareRestarted(target string) (*Proof, bool) {
	if e.State == nil || e.mayRestartAt.IsZero() {
		return nil, false
	}
	obs, err := e.State.Observe()
	p := Judge(obs, err, e.mayRestartAt, e.now(), target)
	return p, p.Restarted()
}

// AdoptPrepareRestart takes the restart PrepareRestarted saw as this run's
// own. On the target, that restart is this run's apply moment, so the
// cutover's own restart is not needed and the confirmation judges against
// it. On a node the package scripts had just restarted, the cutover's
// consensus re-measure would otherwise refuse a node that is only catching
// up, and the run would stop over an upgrade that had in fact happened.
func (e *Executor) AdoptPrepareRestart(p *Proof) {
	if p.State() != WrongVersion {
		e.appliedAt = e.mayRestartAt
	}
	e.record(ledger.KindStepSucceeded, "the package install restarted the node itself; "+
		"the run's own restart step was not needed", p.Wire())
}

// observe is one judged reading of the node, against this run's own apply
// moment.
func (e *Executor) observe(expected string) *Proof {
	obs, err := e.State.Observe()
	return Judge(obs, err, e.appliedAt, e.now(), expected)
}

// StopBeforeApply records a run that ended before its interrupting step:
// on the ledger, attributed to the run's operator, and as the transcript's
// terminal line. Nothing about the node changed because of it, and the
// entry says so rather than leaving the ledger silent after the last step
// that did run.
//
// p is the node's own reading, taken when the run stopped (Reading). It is
// carried on the line and the entry, because what the node did during the
// run is not something a stop can assume: a package install restarts it on
// some platforms (#769, #415).
func (e *Executor) StopBeforeApply(summary string, p *Proof, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["stopped"] = StoppedBeforeApply
	if e.staged != "" {
		data["staged"], data["staged_how"] = e.staged, e.stagedHow
	}
	if p != nil {
		data["reading"] = p.Wire()
	}
	e.record(ledger.KindRunHalted, summary, data)
	e.Log.StopBeforeApply(summary, e.staged, p)
}

// HaltWithReading writes a run's terminal halt with what it had staged and
// the node's own reading at that moment, so the page never has to infer the
// node's condition from which steps happen to be in the transcript.
func (e *Executor) HaltWithReading(text, expected string) {
	e.Log.HaltWith(text, e.staged, e.Reading(expected))
}

// digestFrom pulls the repo digest out of wrapper output, which prints it on
// its own line as repo@sha256:… — tolerant of surrounding noise so a docker
// progress line does not defeat it.
func digestFrom(out string) string {
	for _, f := range strings.Fields(out) {
		if i := strings.Index(f, "@sha256:"); i >= 0 {
			return strings.TrimSpace(f[i+1:])
		}
		if strings.HasPrefix(f, "sha256:") {
			return strings.TrimSpace(f)
		}
	}
	return ""
}

func (e *Executor) digestPath() string {
	if e.DigestDir == "" {
		return ""
	}
	return filepath.Join(e.DigestDir, e.PlanID+".digest")
}

// rememberDigest is best effort. Failing to write it must not fail a prepare
// that otherwise succeeded; the cutover treats an absent record as "nothing
// to compare against" and says so.
func (e *Executor) rememberDigest() {
	p := e.digestPath()
	if p == "" || e.pulledDigest == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err == nil {
		os.WriteFile(p, []byte(e.pulledDigest+"\n"), 0o640)
	}
}

// backupPath, rememberBackup and recalledBackup are the digest's siblings,
// and they exist for the same reason.
//
// A prepare and a cutover are separate runs in separate processes with the
// operator's pause between them. e.Backups is built as steps run, so on the
// cutover run it starts empty: the copy backup-compose took in prepare is
// on the disk and this process has never heard of it. The automatic restore
// after a failed recreate would then find nothing and say "this run took no
// copy", which is true of the process and false of the plan, and the ruled
// restore would be dead code on every real upgrade.
//
// Written beside the digest, keyed by plan, so a second plan's copy cannot
// be restored by this one.
func (e *Executor) backupPath() string {
	if e.DigestDir == "" {
		return ""
	}
	return filepath.Join(e.DigestDir, e.PlanID+".compose-backup")
}

func (e *Executor) rememberBackup(path string) {
	p := e.backupPath()
	if p == "" || path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err == nil {
		os.WriteFile(p, []byte(path+"\n"), 0o640)
	}
}

func (e *Executor) recalledBackup() string {
	p := e.backupPath()
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// changedPath, recordDeployment and cutoverOwesWayBack are the record of
// whether an earlier stage of this plan changed the deployment, for a
// cutover that runs in its own process (#1001, #1006 review M1 and M2).
//
// One file beside the recalled backup, keyed by plan, in the same
// advisord-owned directory, holding one word:
//
//   - every stage other than the cutover writes "unchanged" at its start,
//     so a marker left by an earlier approval of the same plan (the plan ID
//     is the fingerprint's, and approving the same upgrade again after a
//     rollback reuses it) never speaks for this attempt;
//   - it writes "changed" when a step that can change the deployment
//     begins, before the wrapper is asked, so a step that failed half way
//     still counts.
//
// Only the cutover reads it, and the rule errs toward printing: it stays
// quiet only on a confirmed "unchanged". "changed", or a marker that is
// missing, empty, unreadable or not a regular file while a backup of the
// deployment was recalled, prints the way back. A write that fails is said
// in the transcript, and leaves the marker in one of those printing states.
// Opened without following a link both ways, so a planted link can only
// make the cutover print, never write through to somewhere else.
func (e *Executor) changedPath() string {
	if e.DigestDir == "" {
		return ""
	}
	return filepath.Join(e.DigestDir, e.PlanID+".deployment-changed")
}

const (
	deploymentChanged   = "changed"
	deploymentUnchanged = "unchanged"
)

func (e *Executor) recordDeployment(word string) error {
	p := e.changedPath()
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		// The word on disk may be the previous one. "unchanged" is the
		// only one that keeps a cutover quiet, so it must not be left
		// standing for a stage that has just changed the deployment.
		if word == deploymentChanged {
			_ = os.Remove(p)
		}
		return err
	}
	_, werr := f.WriteString(word + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// recordDeploymentOrSay writes the word, and says in the transcript when it
// could not, with what that means for a later cutover.
func (e *Executor) recordDeploymentOrSay(step, word string) {
	if err := e.recordDeployment(word); err != nil {
		e.Log.Write("note", step, "could not record whether this plan changed the deployment ("+
			err.Error()+"); a later restart of this plan will print the way back to be safe")
	}
}

func (e *Executor) cutoverOwesWayBack() bool {
	p := e.changedPath()
	if p == "" {
		return false
	}
	word := ""
	if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0); err == nil {
		if fi, serr := f.Stat(); serr == nil && fi.Mode().IsRegular() {
			b := make([]byte, 32)
			n, _ := f.Read(b)
			word = strings.TrimSpace(string(b[:n]))
		}
		f.Close()
	}
	switch word {
	case deploymentChanged:
		return true
	case deploymentUnchanged:
		return false
	}
	return e.recalledBackup() != ""
}

func (e *Executor) recalledDigest() string {
	p := e.digestPath()
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// sleep is time.Sleep unless a test injects a clock; a late watcher that
// waits thirty real seconds per poll is not something a unit test can wait
// through.
func (e *Executor) sleep(d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(d)
		return
	}
	time.Sleep(d)
}

// LocalImageUpgradeSteps is RB-001 on a container host whose image is built
// here, from the XRPL Foundation's signed package, rather than pulled.
//
// It is the ordered contract in the field guide's "Contract for the Advisor
// operation" expressed as wrapper calls. The shape is the same as the pulled
// path's, with the fetch replaced by a build and the swap replaced by the
// verb that writes `pull_policy: never` beside the image line, so everything
// the pulled path already proves still holds: backups first, the slow and
// failure-prone part done while the node is still validating, one line
// changed, and one step that interrupts.
//
// Why a build at all: from 3.4.x an xrpld release ships as a signed DEB
// package first, and sometimes only as one. 3.4.1 has no official image
// anywhere, and it carries an amendment deadline. Building it from the
// package the install guide configures is the only way to run it in a
// container on the day it ships, and the authority for that build is the
// chain apt already verifies, the pinned key fingerprint, the signed
// InRelease, the Packages entry's SHA-256, and the .deb that hash names.
//
// The build step is NOT marked Interrupts and does not need to be: it writes
// a new image under a new tag, touches no container, and the node keeps
// validating throughout. The tag the node runs does not move until
// set-image-local names it.
//
// image-digest between the build and the swap is not ceremony. It is what
// pins the bytes: the executor remembers what that verb printed, and re-runs
// the same verb immediately before the cutover to refuse a tag that moved in
// between. The recipe already refuses to rebuild an existing tag for the
// same reason; this is the check on the other side of the operator's pause.
func LocalImageUpgradeSteps(target string) []Step {
	return []Step{
		{
			Name: "back up the node config", Stage: StagePrepare, Verb: "backup-config",
			Why:  "the config is what an upgrade can invalidate; without a copy there is no rollback",
			Undo: "none needed, this only adds a file",
			Verify: func(out string, st runbook.HostState) error {
				if !strings.Contains(out, ".bak") {
					return fmt.Errorf("wrapper did not report a backup path: %q", out)
				}
				if ok, d := st.BackupExists("node-config"); !ok {
					return fmt.Errorf("backup reported but not confirmed on the host: %s", d)
				}
				return nil
			},
		},
		{
			Name: "back up the deployment definition", Stage: StagePrepare, Verb: "backup-compose",
			Why:  "the compose file records the running image; restoring it is the rollback",
			Undo: "none needed, this only adds a file",
			Verify: func(out string, st runbook.HostState) error {
				if !strings.Contains(out, ".bak") {
					return fmt.Errorf("wrapper did not report a backup path: %q", out)
				}
				if ok, d := st.BackupExists("deployment-definition"); !ok {
					return fmt.Errorf("backup reported but not confirmed on the host: %s", d)
				}
				return nil
			},
		},
		{
			Name: "build the image from the signed package", Stage: StagePrepare,
			Verb: "build-image", Arg: target,
			Why: "the slow, failure-prone part, done while the node is still validating. The " +
				"recipe checks the signing key's fingerprint, installs one exact package version " +
				"through apt's own signature checking, and proves what it built before it keeps " +
				"the tag. Nothing the node runs changes here",
			Undo: "docker image rm " + LocalImageRepo + ":" + target + ", if this run built it and nothing uses it",
			Verify: func(out string, st runbook.HostState) error {
				if !strings.Contains(out, "built "+LocalImageRepo+":"+target) {
					return fmt.Errorf("the build did not report an image for %s: %q", target, lastLine(out))
				}
				// A build must leave the node exactly where it found it.
				if ok, d := st.ConsensusHealthy(); !ok {
					return fmt.Errorf("the node stopped looking healthy during a build: %s", d)
				}
				return nil
			},
		},
		{
			Name: "confirm the built image reports the target version", Stage: StagePrepare,
			Verb: "image-version", Arg: target,
			Why:  "a tag is a label someone chose and can be moved; ask the image itself",
			Undo: "none needed, this runs a throwaway container",
			Verify: func(out string, _ runbook.HostState) error {
				if strings.TrimSpace(out) == "" {
					// The wrapper refuses an empty answer now, so this is
					// defence in depth rather than the live path.
					return errUnconfirmed
				}
				if !strings.Contains(out, target) {
					return fmt.Errorf("image reports %q, which does not contain %s", strings.TrimSpace(out), target)
				}
				return nil
			},
		},
		{
			Name: "record what the built image resolves to", Stage: StagePrepare,
			Verb: "image-digest", Arg: target,
			Why: "what the cutover compares against. A tag is a moving label, and between this " +
				"stage and the operator's approval of the next one the same tag can be made to " +
				"point somewhere else; this is the reading that would show it",
			Undo: "none needed, this reads",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "sha256:") {
					return fmt.Errorf("the built image reports no digest: %q", out)
				}
				return nil
			},
		},
		{
			Name: "point the deployment at the built image", Stage: StagePrepare,
			Verb: "set-image-local", Arg: target,
			Why: "one line, plus the pull_policy that makes a missing image a loud failure instead " +
				"of a surprise download. Mounts, ports and restart policy stay exactly as they are",
			Undo: "restore the dated compose backup from step 2",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "->") || !strings.Contains(out, target) {
					return fmt.Errorf("wrapper did not confirm the edit: %q", out)
				}
				if !strings.Contains(out, "pull_policy: never") {
					return fmt.Errorf("wrapper did not confirm the pull policy: %q", out)
				}
				return nil
			},
		},
		{
			Name: "recreate the node on the built image", Stage: StageCutover, Verb: "recreate",
			Why: "the only step that interrupts validation. The old container's stop comes first " +
				"and may take the whole stop grace, so nothing times this from the command",
			Interrupts: true,
			Undo:       "restore the compose backup and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "running") {
					return fmt.Errorf("container is not running after recreate: %q", out)
				}
				return nil
			},
		},
		{
			Name: "confirm the container came up on the image that was built", Stage: StageCutover,
			Verb: "running-digest",
			Why: "the tag was pinned before the operator's approval and checked again immediately before " +
				"the swap; this is the reading on the other side of it, so what the container is actually " +
				"running is compared with what was verified rather than assumed from the tag it names",
			Undo: "restore the compose backup and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "sha256:") {
					return fmt.Errorf("the running container reports no digest: %q", strings.TrimSpace(out))
				}
				// The comparison itself is in RunStage, which holds the pin.
				return nil
			},
		},
		{
			Name: "confirm the node's own config reached it", Stage: StageCutover,
			Verb: "node-log", Arg: entrypointLogLines,
			Why: "the built image copies /config to /etc/xrpld at start and refuses to run on the " +
				"package's default config when it cannot. A deployment that mounts the config only " +
				"at /config and does not run as root hits exactly that, and the difference between " +
				"reading this line now and waiting for the health window is half an hour of a node " +
				"that was never coming back",
			Undo: "restore the compose backup and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if strings.Contains(out, "entrypoint: could not copy") {
					return fmt.Errorf("the container refused to start on its own config: %s",
						firstLineContaining(out, "entrypoint: could not copy"))
				}
				// Anything else passes, and the whole read is on the record
				// either way.
				//
				// Only the refusal is a verdict. An older image's entrypoint
				// says none of this, a container that has only just started
				// may have written nothing yet, and a node already several
				// seconds in can have pushed these lines past the tail. None
				// of those is evidence of a problem, and HALTING on them
				// would be worse than not reading at all: an unconfirmed
				// step stops the stage before the health watch starts, so a
				// perfectly good upgrade would end at "could not be
				// confirmed" and its only way forward would re-run the
				// cutover, recreate included.
				return nil
			},
		},
	}
}

// entrypointLogLines is how much of the node's log the cutover reads looking
// for the entrypoint's own first lines. Two hundred rather than a handful:
// xrpld writes steadily from its first second, and the lines this looks for
// are the oldest ones the new container has, so a tail too short misses them
// on a node that took a moment to be asked. The wrapper's own bound is 2000.
const entrypointLogLines = "200"

// firstLineContaining is for a refusal message: the wrapper hands back a
// couple of hundred lines of node log, and one of them is the sentence worth
// quoting.
func firstLineContaining(out, needle string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, needle) {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// LocalImageRepo is the name a locally built xrpld image carries. Spelled
// here rather than imported from internal/host, because this package
// deliberately does not depend on that one (see Executor.RotationInFlight
// for the same rule); the wrapper owns the value and both sides are held to
// it by test.
const LocalImageRepo = "localhost/xrpld"

// pinStepDigest is the digest the run's own image-digest step asked by,
// empty when it asked by version. The pre-restart re-read compares against
// that step's answer, so it has to ask the same question.
func pinStepDigest(steps []Step) string {
	for _, s := range steps {
		if s.Verb == "image-digest" && s.Arg2 != "" {
			return s.Arg2
		}
	}
	return ""
}

// RecipeKeptExistingTag is the image recipe's own sentence for a tag it found
// already on the host and verified rather than rebuilt. Read off build-image's
// output because the wrapper passes the recipe's lines through as they land;
// a test holds this string to scripts/build-xrpld-image.sh, so a reworded
// recipe fails there rather than quietly turning the note off.
const RecipeKeptExistingTag = "already exists: verifying it, not rebuilding"

// OfficialImageRepo is the repository the XRPL release process publishes
// to, spelled here for the same reason LocalImageRepo is: this package
// reads wrapper OUTPUT and deliberately does not import host, so the
// dependency runs one way only. A test holds the two copies equal.
const OfficialImageRepo = "rippleci/xrpld"

// NativeUpgradeSteps is RB-001 expressed as wrapper calls on a native host,
// the native design note's first property, built as steps rather than
// described in one.
//
// Three steps, not six, and the shape is forced rather than chosen: a
// package manager fetches and installs in one call, so there is nothing to
// split the way a container's pull-then-set-image is split, and the
// deployment-definition backup that container upgrades take has nothing
// native to back up (RB-001's own precondition says so). What survives
// unchanged is the config backup, because both kinds have a config file to
// lose.
//
// package-install stays in StagePrepare, not StageCutover, and that is a
// real cost rather than an oversight: the executor's interrupting-step check
// re-reads DeploymentTag and refuses unless it already equals the target,
// and on native that reads the package database, so package-install has to
// have already run before the interrupting step, or every native upgrade
// would refuse itself at its own cutover. The honest consequence is that
// prepare is not outage-free here the way it is on a container: the
// package's own maintainer scripts can restart the unit before this
// runbook's own restart step ever runs, and the wrapper takes the same
// rotation guard there for exactly that reason. Say that in the step text,
// not just in this comment, an operator approving "prepare" on native is
// approving something a container operator would call the outage.
//
// That ordering carries one more consequence, closed here rather than left
// open, issue #394: executeStage's own consensus re-measure runs only
// immediately before a step marked Interrupts, and package-install carries
// none, by the same reasoning above. Marking it Interrupts would break the
// DeploymentTag ordering this comment just explained, so instead
// nativeConsensusReMeasure is its own step, placed immediately before
// package-install, asking the identical question the container path's own
// re-measure asks immediately before its recreate, without touching which
// step is the one that trips DeploymentTag's check.
//
// package-keep sits between package-available and that re-measure, not
// ahead of package-available, issue #401. package-available is the cheap
// read that fails fast; package-keep downloads an artefact and writes it to
// disk, and an upgrade that package-available is about to refuse should not
// pay for that first. It captures the version this upgrade is about to
// replace, so RB-004's kept-artefact fallback has something to install if a
// later rollback finds the repository no longer offers it.
func NativeUpgradeSteps(target string) []Step {
	return []Step{
		{
			Name: "back up the node config", Stage: StagePrepare, Verb: "backup-config",
			Why:  "the config is what an upgrade can invalidate; without a copy there is no rollback",
			Undo: "none needed, this only adds a file",
			Verify: func(out string, st runbook.HostState) error {
				if !strings.Contains(out, ".bak") {
					return fmt.Errorf("wrapper did not report a backup path: %q", out)
				}
				if ok, d := st.BackupExists("node-config"); !ok {
					return fmt.Errorf("backup reported but not confirmed on the host: %s", d)
				}
				return nil
			},
		},
		{
			Name: "confirm the target version is installable", Stage: StagePrepare,
			Verb: "package-available", Arg: target,
			Why: "the read that would have caught a version announced but not yet published to " +
				"this host's own repositories, before anything is installed",
			Undo: "none needed, this reads",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyPackageAvailable(out)
			},
		},
		{
			Name: "keep the currently installed package", Stage: StagePrepare, Verb: "package-keep",
			Why: "captures the artefact for the version this upgrade is about to replace, before " +
				"package-install runs, so a rollback later has something to install if the " +
				"repository no longer offers that version by then",
			Undo:   "none needed, this only adds a file",
			Verify: verifyPackageKept,
		},
		nativeConsensusReMeasure(StagePrepare, "the package install"),
		{
			Name: "install the target version", Stage: StagePrepare, Verb: "package-install", Arg: target,
			MayRestart: true,
			Why: "the package manager verifies the vendor's signature and installs. Its own " +
				"maintainer scripts can restart the node here, so this step is not the outage-free " +
				"half a pulled image is, the restart step below is what makes the cutover " +
				"deterministic regardless of what the package scripts did",
			Undo: "install the previous version instead through a rollback; there is no equivalent " +
				"of removing a pulled image",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyPackageInstalled(out, target)
			},
		},
		{
			Name: "restart the node onto the installed version", Stage: StageCutover, Verb: "restart",
			Why: "guarantees the cutover even where the package's own maintainer scripts did not " +
				"restart the unit, the only step here that interrupts validation on purpose",
			Interrupts: true,
			Undo:       "install the previous version and restart again",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyRestarted(out)
			},
		},
	}
}

// verifyPackageAvailable reads the wrapper's package-available answer: three
// tab-separated fields, yes/no/unknown/retired first. "unknown" refuses like "no"
// does, a package manager that would not answer is not evidence a version
// exists, but the error says so rather than claiming a negative nobody
// measured, the same "said as different, never as equal" rule the design
// note applies to the upgrade's own integrity guarantee.
func verifyPackageAvailable(out string) error {
	fields := strings.SplitN(strings.TrimSpace(out), "\t", 3)
	if len(fields) != 3 {
		return fmt.Errorf("wrapper did not answer in the three fields expected: %q", out)
	}
	switch fields[0] {
	case "yes":
		return nil
	case "no":
		return fmt.Errorf("not offered by this host's repositories: %s", fields[2])
	case "retired":
		// #802: the only source is the retired repos.ripple.com. A measured
		// answer with its own fix in the sentence, not an unknown.
		return fmt.Errorf("this host's package source is retired: %s", fields[2])
	default:
		return fmt.Errorf("could not be determined: %s", fields[2])
	}
}

// verifyPackageInstalled reads the wrapper's package-install answer, its
// last line: "before -> after", the package database's own before-and-after
// rather than what the command printed or what was asked for.
func verifyPackageInstalled(out, target string) error {
	if !strings.Contains(out, "->") {
		return fmt.Errorf("wrapper did not confirm the before/after install: %q", out)
	}
	if !strings.Contains(out, target) {
		return fmt.Errorf("the package database does not report %s installed: %q", target, out)
	}
	return nil
}

// verifyPackageKept reads the wrapper's package-keep answer, issue #401:
// four tab-separated fields, "kept" or "already kept" first, the path, the
// version and its sha256. Either success word passes.
//
// A different first field means nothing was captured, the wrapper's own
// package-keep verb only reaches that shape after refusing outright (a
// nonzero exit the executor already turns into a hard failure before this
// runs), but this reads the four fields defensively anyway, the same
// "trust the read, not the assumption" verifyPackageAvailable already
// applies to its own three. When it happens, it is only survivable when the
// repository still offers the version that went unkept: that is the exact
// version a rollback would need, and if neither the kept artefact nor the
// repository can produce it, a rollback has nowhere to go, and this refuses
// by name rather than letting the upgrade proceed on a rollback path that
// does not exist yet.
func verifyPackageKept(out string, st runbook.HostState) error {
	fields := strings.SplitN(strings.TrimSpace(out), "\t", 4)
	if len(fields) != 4 {
		return fmt.Errorf("wrapper did not answer in the four fields expected: %q", out)
	}
	if fields[0] == "kept" || fields[0] == "already kept" {
		return nil
	}
	version := fields[2]
	if version != "" {
		if ok, _ := st.ImagePublished(version); ok {
			return nil
		}
	}
	return fmt.Errorf("nothing was kept for %s, and the repository does not offer %s either; "+
		"a rollback would have nowhere to go: %q", version, version, out)
}

// nativeConsensusReMeasure closes issue #394. package-install is not marked
// Interrupts (NativeUpgradeSteps and NativeRollbackSteps both explain why:
// marking it so would break the DeploymentTag ordering their own comments
// depend on), so executeStage's built-in re-measure, the one immediately
// ahead of a step marked Interrupts, never runs ahead of it. This step is
// that same measurement, taken as its own step immediately before
// package-install instead, refusing by name when the node is mid-round
// rather than relying on the precondition read at the top of the stage,
// which can be a minute or more stale by the time package-install actually
// runs.
//
// It calls the wrapper's "status" verb, which both kinds already answer with
// nothing but a server_info read, so this adds no new capability to what the
// wrapper grants. The verb's own output is not inspected, Verify reads the
// host directly, the same call ConsensusHealthy makes everywhere else in
// this package, so the question asked here is exactly the one the
// interrupting-step check asks, not a looser approximation of it.
func nativeConsensusReMeasure(stage, before string) Step {
	return Step{
		Name: "confirm consensus still looks healthy", Stage: stage, Verb: "status",
		Why: "package-install carries no Interrupts flag, so nothing else here re-measures " +
			"consensus immediately before it; this is that measurement, taken as close to " + before +
			" as the container path's own re-measure is taken to its recreate",
		Undo: "none needed, this reads",
		Verify: func(_ string, st runbook.HostState) error {
			if ok, d := st.ConsensusHealthy(); !ok {
				return fmt.Errorf("consensus no longer looks healthy immediately before %s: %s", before, d)
			}
			return nil
		},
	}
}

// RestartSteps is RB-002 expressed as wrapper calls: one call, which is the
// one that interrupts validation.
//
// It takes no argument. The intent the operator chose identifies the plan and
// lands in the ledger; it is not something the wrapper is told, because the
// wrapper's whole property is that the set of possible operations is finite
// and nothing the caller supplies widens it.
func RestartSteps() []Step {
	return []Step{
		{
			Name: "restart the node in place", Stage: StageRestart, Verb: "restart",
			Why:        "the only step, and the one that takes the node off the network",
			Interrupts: true,
			Undo: "nothing to put back — the node returns on the same image and the same config. " +
				"If it does not come back, the way forward is the node's own logs, not a second restart",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyRestarted(out)
			},
		},
	}
}

// verifyRestarted reads the wrapper's own restart verb output, which says
// two different things depending on the kind: docker's Status word for a
// container ("running"), or systemd's ActiveState for a unit ("active",
// "activating"). Both are checked as whole fields, not substrings, systemd
// also reports "inactive" for a service that failed to (re)start, and that
// string CONTAINS "active", so a plain Contains check would read a failed
// restart as a healthy one.
//
// The result is the LAST line. The restart verb narrates before it answers:
// the store-rotation guard's reading first, then the stop grace the node
// got, and on a native host whether the unit's failure counter was cleared.
// Only the final line is the outcome, and lastLine is what the backup verbs
// in this file already read for the same reason.
//
// #425. This read was strings.Fields(out)[0] for four days, and
// strings.Fields splits on newlines as well as spaces, so it took the first
// word of the WHOLE output rather than of the answer. Since the rotation
// guard landed, that word is "store", "warning", "note" or "refusing", never
// one of the three below, so every RB-002 restart and every RB-001 cutover
// failed its own verification on both shapes after a restart that had
// actually worked. The suite stayed green because the stub answered one
// line, which is not what the wrapper prints; the row that pins this now
// runs the real script.
func verifyRestarted(out string) error {
	fields := strings.Fields(lastLine(out))
	if len(fields) > 0 {
		switch fields[0] {
		case "running", "active", "activating":
			return nil
		}
	}
	return fmt.Errorf("the node does not report running after the restart: %q", out)
}

// errUnconfirmed marks a step whose check could not reach a verdict. It is
// neither pass nor fail: the run pauses and asks rather than guessing.
var errUnconfirmed = fmt.Errorf("could not be confirmed")

// IsUnconfirmed reports whether a step verification was inconclusive.
func IsUnconfirmed(err error) bool { return err == errUnconfirmed }

// record appends an entry attributed to whoever this run is running for.
//
// Every act this package performs goes through here. CheckPreconditions does
// NOT — see the note on it — and that is the only exception, stated in one
// place so "stamp everything" cannot creep in by accident.
func (e *Executor) record(kind ledger.Kind, summary string, data map[string]any) {
	if _, err := e.Ledger.AppendAs(kind, e.PlanID, summary, data, e.Actor); err != nil {
		e.ledgerMu.Lock()
		if e.ledgerErr == nil {
			e.ledgerErr = fmt.Errorf("%s: %w", kind, err)
		}
		e.ledgerMu.Unlock()
	}
}

// ErrLedgerWrite is a run stopped because the ledger could not take a row.
var ErrLedgerWrite = errors.New("the ledger could not be written")

// ledgerStopped is the check a run makes after it records a step and before
// it goes on: an act the ledger has no row for is an act nobody can
// reconstruct, so the run stops, names the ledger, and does nothing further.
func (e *Executor) ledgerStopped(step string) error {
	e.ledgerMu.Lock()
	err := e.ledgerErr
	e.ledgerMu.Unlock()
	if err == nil {
		return nil
	}
	msg := fmt.Sprintf("the ledger could not be written (%v), so this run stopped after step %q and "+
		"did nothing further; what was done so far is in this transcript and the rows before this one", err, step)
	e.Log.Write("halt", step, msg)
	return fmt.Errorf("%w: %s", ErrLedgerWrite, msg)
}

// Refuse records a refusal and returns it. Every path that declines to act
// goes through here, so the ledger explains the outage that did not happen as
// carefully as the ones that did.
func (e *Executor) Refuse(reason string, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	data["reason"] = reason
	e.Log.Write("halt", "", "refused: "+reason)
	e.record(ledger.KindRefusal, "executor refused: "+reason, data)
	return fmt.Errorf("refused: %s", reason)
}

// CheckPreconditions evaluates the preconditions that gate one stage and
// records the result. Called before the run and again before the
// interrupting stage.
//
// Stage-scoped, because a precondition an earlier stage SATISFIES cannot
// also forbid it: the dated backups are taken by prepare's own first two
// steps, so counting them here refused prepare on every host that had never
// been upgraded. A precondition with no stage named gates everything, which
// is the right default for anything describing the host's fitness to be
// touched at all.
func (e *Executor) CheckPreconditions(stage, when string) ([]runbook.Verdict, bool) {
	var vs []runbook.Verdict
	ok := true
	for _, pc := range e.Runbook.Preconditions {
		if pc.Gates != "" && pc.Gates != stage {
			continue
		}
		v := pc.Check(e.Params, e.State)
		vs = append(vs, v)
		if !v.Passed {
			ok = false
		}
	}
	data := map[string]any{"when": when, "stage": stage, "all_passed": ok}
	for _, v := range vs {
		row := map[string]any{"passed": v.Passed, "detail": v.Detail}
		// The ledger keeps the third state too (#679). A record that only
		// said "passed: true" for a check whose tool errored would read, a
		// year later, as evidence the Advisor looked and found the host
		// healthy.
		if v.Unmeasured {
			row["unmeasured"] = true
		}
		data[v.Name] = row
	}
	// A precondition is a MEASUREMENT of the host, not an act a person chose —
	// nobody decides that consensus is healthy, so it is never attributed to an
	// operator. But the record keeps no anonymous rows: an automated
	// measurement names the service that produced it — "system" over the
	// service source — which stays distinct from a person's act (the operator
	// is the literal "system", never an operator's name, and nothing is claimed
	// to be proved about a person). Joined to the run that prompted it by
	// plan_id, as before.
	e.Ledger.AppendAs(ledger.KindPreconditions, e.PlanID,
		fmt.Sprintf("preconditions evaluated %s: %d of %d passed%s", when, countPassed(vs), len(vs),
			unmeasuredNote(vs)), data,
		ledger.Actor{Operator: "system", Source: ledger.SourceService, Verified: ledger.VerifiedNone})
	return vs, ok
}

// unmeasuredNote names the checks nobody could take, so the one-line
// summary cannot read as "all measured and fine".
func unmeasuredNote(vs []runbook.Verdict) string {
	n := 0
	for _, v := range vs {
		if v.Unmeasured {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d not measured)", n)
}

func countPassed(vs []runbook.Verdict) int {
	n := 0
	for _, v := range vs {
		if v.Passed {
			n++
		}
	}
	return n
}

// RunStage performs the steps of one stage, after checking approval for it.
func (e *Executor) RunStage(ctx context.Context, stage string, steps []Step,
	confirmUnverified func(Step, string) bool) (err error) {

	// An earlier stage of this plan may already have changed the
	// deployment, in another process: on the build path, prepare's
	// set-image-local points it at the new image before the cutover runs.
	// A cutover refused before it changes anything itself still owes the
	// way back then, and only then: on the official path prepare changes
	// nothing and set-image-official is the cutover's own step. Read from
	// the marker that stage left (see changedPath), never from the stage
	// name, and from the recalled backup only when the marker cannot say
	// (#1001, #1006 review).
	if stage == StageCutover && e.cutoverOwesWayBack() {
		e.touched = true
	}

	a, err := approval.CheckSigned(e.ApprovalDir, e.PlanID, e.Fingerprint, e.Node, stage, e.now(), e.Verifier)
	if err != nil {
		// A refusal here means no identity was ESTABLISHED — the approval was
		// missing, expired, bound elsewhere, or its assertion did not verify.
		// The name on the file that failed is still worth keeping ("someone
		// tried to approve a cutover as X and failed" is the entry that
		// answers the question an auditor actually asks), so it is recorded
		// as a claim with verified:"none" rather than as an attribution. The
		// distinction is the point of the verified field.
		e.Ledger.AppendAs(ledger.KindApprovalRefused, e.PlanID,
			fmt.Sprintf("stage %s not approved", stage),
			map[string]any{"stage": stage, "error": err.Error()},
			e.claimedActor(stage))
		return fmt.Errorf("stage %s: %w", stage, err)
	}
	// The grant becomes this run's before anything below writes run state
	// (#1063): a run that loses it must not, say, clear the marker the run
	// that holds it wrote. A grant another run holds is refused here, and
	// is not this run's to spend.
	if cerr := e.claimGrant(stage, a); cerr != nil {
		return cerr
	}
	// How this stage leaves its grant, decided below and carried out on
	// every return from here: given back, spent, or kept for the next stage
	// of the same run. See settleGrant.
	settle := settleRelease
	defer func() { err = e.settleGrant(stage, a.Stage, settle, err) }()
	// From here on this run has an operator, and it came from a file this
	// service verified rather than from the request that started the run.
	e.Actor = actorFromApproval(a)
	// This approved attempt starts the plan's record over, so a marker left
	// by an earlier approval of the same plan never speaks for it. Only
	// after the approval verified: an unapproved request must not be able
	// to wipe a "changed" a real stage wrote.
	if stage != StageCutover {
		e.recordDeploymentOrSay("", deploymentUnchanged)
	}
	e.stageEdits, e.stageCopy = 0, ""
	e.stageTouched, e.stageStaged, e.stageStagedHow = e.touched, e.staged, e.stagedHow
	if e.began.IsZero() {
		e.began = e.now()
	}
	e.Log.Printf("start", "", "stage %s — approved by %s", stage, a.GrantedBy)
	e.record(ledger.KindApprovalGranted,
		fmt.Sprintf("stage %s approved by %s, expires %s", stage, a.GrantedBy, a.ExpiresAt.Format(time.RFC3339)),
		// granted_scope is what the operator actually signed over; stage is
		// what this run is doing under it. They differ for every compound
		// grant, and recording only the requested stage left the ledger
		// unable to answer the question an auditor asks first — a run
		// authorised by one config-restart ceremony logged "config" and
		// "restart" as if they had been approved separately.
		map[string]any{"stage": stage, "granted_scope": a.Stage, "granted_by": a.GrantedBy,
			"granted_at": a.GrantedAt, "expires_at": a.ExpiresAt, "reason": a.Reason,
			"credential_id": credOf(a), "origin": a.Origin})

	// The store-rotation refusal, and it lives HERE for one reason: this is the
	// last line before the approval is committed to being spent — issue #93.
	//
	// #80 and #90 ask the same question at assessment time, so the chat path
	// never OFFERS a gate the wrapper is going to refuse with exit 64. The
	// Operations card does not go through that assessment: it mints its gate
	// from /v1/check, so it reached the passkey ceremony, and then this
	// function, with the rotation never read. Guarding the handler instead
	// would have meant guarding the primary stage, the upgrade's auto-chained
	// cutover and the config change's auto-chained restart separately, and the
	// next caller after those by hand. One check where every path converges is
	// the guarantee; the assessment-time checks are the courtesy that keeps a
	// doomed ceremony from being offered at all.
	//
	// Below this the grant is spent on return, win or lose, because the
	// spend fires on the ATTEMPT. Returning from here gives this run's claim
	// back and spends nothing: the operator waits out the rotation and runs
	// the same plan on the same passkey touch.
	//
	// Only the stages that take the node off the network. StageConfig is
	// deliberately absent — its own half is the reversible edit, which the
	// wrapper is happy to make mid-rotation, and its interrupting half IS
	// StageRestart, already named here.
	//
	// FAILS OPEN, exactly as host.State.RotationInFlight does: a read that
	// errored is noted and treated as not in flight. The safety boundary is the
	// wrapper's own refusal, which runs privileged and cannot be talked out of
	// it. A read that failed closed would let one broken docker call lock an
	// operator out of restarting their own node.
	if e.RotationInFlight != nil && rotationRefuses(stage) {
		rotating, detail, rerr := e.RotationInFlight()
		switch {
		case rerr != nil:
			e.Log.Printf("note", "", "the store-rotation state could not be read, "+
				"treating it as not in flight: %v", rerr)
		case rotating:
			return e.Refuse("the ledger store is mid-rotation, so the node refuses to stop: "+detail+
				". Nothing was done and your approval was not spent. Ask again once the rotation "+
				"finishes",
				map[string]any{"stage": stage, "rotation_in_flight": true, "rotation_detail": detail})
		}
	}

	// An approval is spent when it is used, not when it expires. Otherwise a
	// fifteen-minute grant authorises two cutovers inside its window.
	//
	// The stage that spends it is the one the grant was for, or the
	// terminal, interrupting stage of a compound grant: cutover for the
	// upgrade, restart for a config change. That stage spends it win or
	// lose, because an attempt at it is the use that burns it. The
	// exact-match arm comes first, so a restart approved on its own (RB-002,
	// a.Stage == stage == "restart") spends its own grant.
	//
	// Any stop spends it too, the first stop after the claim (#1063): the
	// grant was consent to one run, and a run that stopped is over. That
	// includes a prepare that fails under a compound grant, which used to
	// leave it live for a retry: the retry is another run. The one exception
	// is above, the rotation refusal, which comes before any step and gives
	// the grant back. A reversible stage that finishes under a compound
	// grant keeps the claim: the same run goes on to the stage after it, or
	// the caller's Finish spends it.
	settle = settleKeep
	if a.Stage == stage || stage == StageCutover || stage == StageRestart {
		settle = settleSpend
	}

	for _, s := range steps {
		if s.Stage != stage {
			continue
		}
		e.atStep(s.Name)
		// Consent first, before anything below marks the plan changed or
		// takes the apply moment (#1047). The check at the top of this
		// function was the only one, so an approval that ran out during a
		// slow build still let set-image-local rewrite the deployment.
		if !readsOnly[s.Verb] {
			if err := e.consentStands(ctx, stage, s); err != nil {
				return err
			}
		}
		// The interrupting step gets a fresh measurement of the node, taken
		// now rather than remembered from the start of the run.
		if s.Interrupts {
			if ok, d := e.State.ConsensusHealthy(); !ok {
				return e.Refuse("consensus no longer looks healthy immediately before the restart: "+d,
					map[string]any{"step": s.Name})
			}
			// Everything below compares the run against a VERSION, so it
			// applies only to a runbook that declares one. RB-002 restarts
			// the node on the image it is already running and names no
			// version at all; read against its parameters, `want` was
			// always empty and the tag comparison refused every restart
			// with a sentence naming a version nobody had asked for
			// (ADR 0016 §5).
			//
			// Gated on the DECLARATION, never on the bound value. `want !=
			// ""` would read the same and quietly delete the refusal below:
			// an upgrade whose target bound empty would skip the check
			// instead of being stopped by it, and that check is the only
			// thing standing between an empty target and a restart onto
			// whatever the deployment file happens to say.
			//
			// The consensus re-measure above is deliberately outside this:
			// it applies to any interrupting step, whatever its runbook.
			if e.Runbook.DeclaresParam("target_version") {
				// The interrupting step brings the service up from the deployment
				// file and names no version itself — so what actually restarts is
				// whatever that file says at this instant, not what was approved.
				// Between the approval and here, another prepare could have staged
				// a different version; the node would come up on it and only the
				// health check afterwards would notice, minutes later, with the
				// validator already running something nobody approved.
				want := e.Params["target_version"]
				got, err := e.State.DeploymentTag()
				switch {
				case err != nil:
					return e.Refuse("could not read which version the deployment names, and this step "+
						"restarts whatever it names: "+err.Error(), map[string]any{"step": s.Name})
				case want == "" || got != want:
					return e.Refuse(fmt.Sprintf(
						"the deployment names %s but %s was approved; nothing was restarted", got, want),
						map[string]any{"step": s.Name, "deployment_tag": got, "approved": want})
				}

				// On the official path the version is not the staging
				// check. A source switch does not change it: the file
				// says 3.4.1 before the swap and 3.4.1 after it, so the
				// comparison above is true either way and proves nothing.
				// What was staged is a DIGEST, and it is what the file
				// has to name.
				if d := e.Params["digest"]; d != "" {
					img, ierr := e.State.DeploymentImage()
					switch {
					case ierr != nil:
						return e.Refuse("could not read which image the deployment names, and this step "+
							"restarts whatever it names: "+ierr.Error(), map[string]any{"step": s.Name})
					case !strings.Contains(img, d):
						return e.Refuse(fmt.Sprintf(
							"the deployment names %s but %s was approved; nothing was restarted", img, d),
							map[string]any{"step": s.Name, "deployment_image": img, "approved_digest": d})
					}
				}

				// The build path's twin of the check above (#664). A build
				// of the release the node already runs keeps the version
				// too: an official file names 3.4.1 in the comment beside
				// its digest, so the tag comparison passes on a file that
				// set-image-local never touched, and the recreate would
				// bring the node back on the official image it was already
				// running. What a build stages is the local name, and that
				// is what the file has to say. Keyed on the plan's own
				// source, which only RB-001 declares, so a rollback or a
				// restart never reaches it.
				if e.Params["source"] == "build" {
					wantRef := LocalImageRepo + ":" + want
					img, ierr := e.State.DeploymentImage()
					switch {
					case ierr != nil:
						return e.Refuse("could not read which image the deployment names, and this step "+
							"restarts whatever it names: "+ierr.Error(), map[string]any{"step": s.Name})
					case img != wantRef:
						return e.Refuse(fmt.Sprintf(
							"the deployment names %s but a build of %s was approved; nothing was restarted",
							img, wantRef),
							map[string]any{"step": s.Name, "deployment_image": img, "approved_image": wantRef})
					}
				}

				// A tag is a moving label. The deployment naming the right tag is
				// not the same as the right bytes being behind it: between prepare
				// verifying an image and the operator approving this restart, the
				// same tag can be republished. Compare what prepare pulled with
				// what that tag resolves to right now, locally, without pulling —
				// re-pulling here would fetch the substitution rather than detect
				// it.
				if pulled := e.recalledDigest(); pulled != "" {
					// With the digest, when the plan pinned one. Without
					// it this asks about a VERSION, and the wrapper's own
					// lookup prefers localhost/xrpld, which every host
					// this project has upgraded carries: the re-check
					// would read the local build's digest, find it is not
					// the pinned one, and refuse every official cutover
					// on exactly the hosts #682 was ruled for.
					//
					// Otherwise the re-read asks exactly what the step that
					// took the pin asked (#664). A rollback onto an official
					// image asks by the copy's digest, and by version alone
					// the wrapper would answer with the local build the node
					// is rolling away from and refuse the restart as a moved
					// tag. A rollback onto a third-party image asks by
					// version, and the copy's digest must not be added there:
					// the wrapper reads any digest as the OFFICIAL
					// repository's, which would refuse a rollback main ran.
					reread := []string{"image-digest", want}
					if d := e.Params["digest"]; d != "" {
						reread = append(reread, d)
					} else if d := pinStepDigest(steps); d != "" {
						reread = append(reread, d)
					}
					out, derr := e.Runner.Run(ctx, e.Wrapper, reread...)
					now := digestFrom(string(out))
					switch {
					case derr != nil:
						return e.Refuse("could not read the image digest immediately before the restart: "+
							derr.Error(), map[string]any{"step": s.Name})
					case now == "":
						return e.Refuse("the image reports no digest immediately before the restart",
							map[string]any{"step": s.Name, "approved_digest": pulled})
					case now != pulled:
						return e.Refuse(fmt.Sprintf(
							"the image behind %s changed after it was verified: prepare pulled %s, the tag now resolves to %s; nothing was restarted",
							want, shortDigest(pulled), shortDigest(now)),
							map[string]any{"step": s.Name, "verified_digest": pulled, "current_digest": now})
					}
					e.Log.Write("ok", s.Name, "image digest unchanged since prepare verified it ("+shortDigest(pulled)+")")
				}
			}
		}

		// The moment this run touches the node, taken after every refusal
		// above and immediately before the wrapper is asked. The post-state
		// verifier judges every reading against it: a process older than
		// this is the one that was already there (#769). Zero means the run
		// never got here, and nothing it later says can call it finished.
		if s.Interrupts {
			// Asked again here, after the re-measures above and the
			// image-digest re-read (#1047, review). Those take time, and an
			// approval withdrawn while they ran must not still reach the
			// restart.
			if err := e.consentStands(ctx, stage, s); err != nil {
				return err
			}
			e.appliedAt = e.now()
		}
		if editsDeployment[s.Verb] {
			e.stageEdits++
		}
		if s.MayRestart && e.mayRestartAt.IsZero() {
			e.mayRestartAt = e.now()
		}
		if !leavesDeploymentAsItWas[s.Verb] {
			e.touched = true
			// The cutover too: one that began set-image-official and could
			// not be put back leaves the deployment changed for the next
			// approval of this plan. Writing it can only make a later
			// cutover print the way back.
			e.recordDeploymentOrSay(s.Name, deploymentChanged)
		}
		e.record(ledger.KindStepStarted, s.Name,
			map[string]any{"verb": s.Verb, "arg": s.Arg, "why": s.Why, "stage": stage})
		// Not before the wrapper is asked, if this row did not land: the
		// step would change the node with nothing on record that it began.
		if err := e.ledgerStopped(s.Name); err != nil {
			return err
		}
		e.Log.Write("step", s.Name, s.Name)
		e.Log.Printf("out", s.Name, "%s %s %s", e.Wrapper, s.Verb, s.Arg)

		// Streamed where the runner can: each line is written to the
		// transcript at the moment it arrives, so the page reading that
		// transcript sees a build happening rather than a timer (#678).
		// The lines are written once, here or below, never twice.
		var (
			out      []byte
			err      error
			streamed bool
		)
		if lr, ok := e.Runner.(LineRunner); ok {
			name := s.Name
			out, err = lr.RunLines(ctx, func(ln string) {
				streamed = true
				e.Log.Write("out", name, ln)
			}, e.Wrapper, argv(s)...)
		} else {
			out, err = e.Runner.Run(ctx, e.Wrapper, argv(s)...)
		}
		text := strings.TrimSpace(string(out))
		if err != nil {
			e.record(ledger.KindStepFailed, s.Name,
				map[string]any{"verb": s.Verb, "arg": s.Arg, "error": err.Error(), "output": text})
			e.Log.Write("fail", s.Name, err.Error())
			e.restoreAfterFailure(ctx, s)
			return fmt.Errorf("step %q failed: %w", s.Name, err)
		}
		// What the node will start on next has moved the moment the wrapper
		// says it made the change, whether or not this run ever restarts it
		// and whatever the step's own check says after. Recorded here, before
		// any branch below can skip it, so a stop before the restart can say
		// so instead of "untouched" (#769).
		switch s.Verb {
		case "set-image", "set-image-local", "set-image-official":
			e.staged, e.stagedHow = s.Arg, "deployment"
		case "package-install":
			e.staged, e.stagedHow = s.Arg, "package"
		}
		// The copy a lapse puts back: the file as it stood before this
		// stage's first edit. A dated copy taken by this stage before any
		// edit is that file; the first edit's own copy is too, and is the
		// nearer one. A later edit's copy already holds the first edit.
		switch {
		case s.Verb == "backup-compose" && e.stageEdits == 0:
			e.stageCopy = lastLine(text)
		case editsDeployment[s.Verb] && e.stageEdits == 1:
			if b := BackupPathFrom(text); b != "" {
				e.stageCopy = b
			}
		}
		// The package a native host can go back to, named so a stop
		// before the restart can say how (#1047, review).
		if s.Verb == "package-keep" {
			if k := keptPathFrom(text); k != "" {
				if e.Backups == nil {
					e.Backups = map[string]string{}
				}
				e.Backups["package-keep"] = k
			}
		}
		if text != "" && !streamed {
			for _, ln := range strings.Split(text, "\n") {
				e.Log.Write("out", s.Name, ln)
			}
		}

		if s.Verify != nil {
			verr := s.Verify(text, e.State)
			switch {
			case verr == nil:
			case IsUnconfirmed(verr):
				if confirmUnverified == nil || !confirmUnverified(s, text) {
					return e.Refuse("step could not be confirmed and was not overridden",
						map[string]any{"step": s.Name, "output": text})
				}
				e.record(ledger.KindStepSucceeded, s.Name+" (unconfirmed, operator continued)",
					map[string]any{"verb": s.Verb, "output": text, "unconfirmed": true})
				continue
			default:
				e.record(ledger.KindStepFailed, s.Name,
					map[string]any{"verb": s.Verb, "arg": s.Arg,
						"verification_error": verr.Error(), "output": text})
				e.restoreAfterFailure(ctx, s)
				return fmt.Errorf("step %q did not verify: %w", s.Name, verr)
			}
		}

		if s.Verb == "backup-config" || s.Verb == "backup-compose" {
			if e.Backups == nil {
				e.Backups = map[string]string{}
			}
			e.Backups[s.Verb] = lastLine(text)
			if s.Verb == "backup-compose" {
				e.rememberBackup(lastLine(text))
			}
		}
		// The deployment verbs take a dated copy of their own before they
		// write, and print its path on a "backup: " line. That copy is
		// this stage's own, taken seconds before the recreate, so it is
		// the better one to put back when the recreate fails: it is the
		// file as it stood immediately before this change rather than
		// before the whole plan.
		if s.Verb == "set-image" || s.Verb == "set-image-local" || s.Verb == "set-image-official" {
			if b := BackupPathFrom(text); b != "" {
				if e.Backups == nil {
					e.Backups = map[string]string{}
				}
				e.Backups["backup-compose"] = b
				e.rememberBackup(b)
			}
		}
		// set-config takes its OWN dated copy, which the caller cannot skip,
		// and prints its path on a "backup: " line among five others — so
		// lastLine would take the wrapper's closing sentence instead. That
		// copy is the one the reversal note and the gate's backup sentence
		// both point at, so it is named in the transcript rather than left
		// as one line of wrapper output among several.
		if s.Verb == "set-config" {
			if b := BackupPathFrom(text); b != "" {
				if e.Backups == nil {
					e.Backups = map[string]string{}
				}
				e.Backups[s.Verb] = b
				e.Log.Write("note", s.Name, "the file as it was, before this edit: "+b)
				e.record(ledger.KindStepSucceeded, "dated copy taken before the edit",
					map[string]any{"verb": s.Verb, "backup": b})
			}
		}
		// An official image that verified on a superseded package revision
		// (3.4.1-1 while 3.4.1-2 is published) says so, in one line. It
		// still verified: the ruling on #1001 makes this information, not
		// a refusal. Nothing is said when it carries the newest.
		if s.Verb == "verify-official-image" {
			if n := supersededNote(text); n != "" {
				e.Log.Write("note", s.Name, n)
			}
		}
		// What the tag resolved to, kept so the cutover — a separate act, in a
		// separate process, after however long the operator paused — can tell
		// "the same image" from "the same label".
		//
		// image-digest counts as well as pull, and it has to: an image built
		// on this host is never pulled, so an upgrade through a local build
		// had no pin at all and the moved-tag check ahead of the cutover
		// quietly did nothing. The same verb produces both readings, which
		// is what makes them comparable: the cutover re-runs image-digest
		// and compares its output to this.
		if s.Verb == "pull" || s.Verb == "image-digest" {
			if d := digestFrom(text); d != "" {
				e.pulledDigest = d
				e.rememberDigest()
			}
		}

		// Contract step 7's after-reading: the container that came up is
		// running the image that was verified, not merely the tag that was
		// named. The pin is this executor's own, so the comparison lives
		// here rather than in the step's Verify, which sees only the output.
		//
		// A digest the run never took is nothing to compare against and is
		// said as that. A MISMATCH is a halt: the node is up, on an image
		// nobody verified, and the operator gets the rollback in front of
		// them rather than a run reported as finished.
		if s.Verb == "running-digest" {
			pinned, got := e.recalledDigest(), digestFrom(text)
			switch {
			case pinned == "":
				e.Log.Write("note", s.Name,
					"no verified digest was recorded for this run, so what came up could not be compared against it")
			case got == "":
				e.Log.Write("note", s.Name,
					"the running container reported no digest, so it could not be compared against the verified one")
			case got != pinned:
				e.record(ledger.KindStepFailed, s.Name, map[string]any{
					"verb": s.Verb, "verified_digest": pinned, "running_digest": got, "output": text,
				})
				return fmt.Errorf(
					"the node came up on %s and the image that was verified is %s; it is running something "+
						"this run did not check", shortDigest(got), shortDigest(pinned))
			default:
				e.Log.Write("ok", s.Name, "running the image that was verified ("+shortDigest(pinned)+")")
			}
		}

		stepData := map[string]any{"verb": s.Verb, "arg": s.Arg, "output": text}
		if (s.Verb == "pull" || s.Verb == "image-digest") && e.pulledDigest != "" {
			stepData["digest"] = e.pulledDigest
		}
		// A build of a tag already on this host builds nothing (#664). The
		// recipe never rebuilds an existing tag: it checks that image
		// against the signed package and keeps it, and the wrapper still
		// ends on "built <tag>". Correct, and it must not read as a fresh
		// build, so the transcript says which one happened and the record
		// carries it as a field.
		if s.Verb == "build-image" && strings.Contains(text, RecipeKeptExistingTag) {
			stepData["kept_existing"] = true
			e.Log.Write("note", s.Name, LocalImageRepo+":"+s.Arg+" was already on this host, so it was "+
				"checked against the signed package and kept, not built again")
		}
		e.record(ledger.KindStepSucceeded, s.Name, stepData)
		e.Log.Write("ok", s.Name, s.Name)
		if err := e.ledgerStopped(s.Name); err != nil {
			return err
		}
	}
	// `ok`, not `done`. Both callers append work after this returns — the
	// cutover waits for the node to come back, and the command-line tool does
	// its own waiting — so a terminal verdict here is a claim the operation
	// finished when it has not. It read as "✓ Restart complete, back in
	// consensus" on a node that was still syncing, five minutes before the
	// same run reported a failure. The caller owns the single terminal line.
	e.Log.Printf("ok", "", "every step of %s is done", stage)
	return nil
}

// ErrNotYetHealthy reports that the node was acted on successfully but had not
// rejoined consensus before the window closed. Distinct from a failure on
// purpose: the restart happened, and the node is most likely still syncing.
var ErrNotYetHealthy = errors.New("the node has not returned to full sync yet")

// AwaitHealthyLate keeps watching after AwaitHealthy gave up: the run is on
// record as unconfirmed, the node was recreated and is answering, and the
// only open question is whether it makes it back. Polls at a gentler rate,
// reports a reading to tick when the state WORD changes or every fifth
// minute (so a transcript tail stays current without growing by a line every
// few seconds), and on a Verified reading records run.confirmed_late with how
// late. Past `limit` it records nothing more: the unconfirmed entry stands.
//
// The success test is the verifier's, the same one AwaitHealthy uses: a
// process newer than the run's restart step, on the target, in full sync.
// The proof comes back so the caller can write the verdict line from it.
func (e *Executor) AwaitHealthyLate(target string, limit time.Duration, since time.Time,
	tick func(version, detail string)) (*Proof, bool) {

	deadline := e.now().Add(limit)
	lastWord, lastTick := "", e.now()
	for e.now().Before(deadline) {
		e.sleep(30 * time.Second)
		p := e.observe(target)
		if p.State() == NotApplied {
			return p, false
		}
		detail := p.Detail()
		if p.State() == Unread {
			detail = p.readErr
		}
		word := detail
		if i := strings.Index(detail, ","); i > 0 {
			word = detail[:i]
		}
		if tick != nil && (word != lastWord || e.now().Sub(lastTick) >= 5*time.Minute) {
			if p.State() == Unread {
				tick("?", detail)
			} else {
				tick(p.Version(), detail)
			}
			lastWord, lastTick = word, e.now()
		}
		if p.State() == Verified {
			late := e.now().Sub(since).Round(time.Second)
			data := p.Wire()
			data["late_by"] = late.String()
			data["detail"] = p.Detail()
			e.record(ledger.KindRunConfirmedLate,
				LedgerSynced(OpUpgrade, p, late.String()),
				data)
			return p, true
		}
	}
	return nil, false
}

func argv(s Step) []string {
	if s.Arg == "" {
		return []string{s.Verb}
	}
	if s.Arg2 == "" {
		return []string{s.Verb, s.Arg}
	}
	return []string{s.Verb, s.Arg, s.Arg2}
}

func lastLine(s string) string {
	parts := strings.Split(strings.TrimSpace(s), "\n")
	return parts[len(parts)-1]
}

// ErrWrongVersion reports a node that restarted after this run's step and
// came back on a build other than the one approved. A finding, not a slow
// sync: waiting longer does not change which build is running.
var ErrWrongVersion = errors.New("the node came back on a different build")

// ErrRestartNotObserved reports a window that closed without one reading
// from a process newer than this run's restart step. The steps may have
// said they ran; the node never showed it.
var ErrRestartNotObserved = errors.New("the node was not seen restarting")

// AwaitHealthy polls until the node proves the upgrade: a process newer than
// this run's restart step, reporting the target, in full sync. A running
// container is not a validating node, and a node on the target is not
// proof this run put it there.
//
// Every reading is judged by the verifier. The old process still answering
// while it comes down is ordinary and waited through. A NEW process on
// another build is a finding and ends the wait at once. The proof of the
// last reading comes back so the caller writes its verdict line from it.
func (e *Executor) AwaitHealthy(target string, timeout time.Duration,
	tick func(version, detail string)) (*Proof, error) {

	var last *Proof
	deadline := e.now().Add(timeout)
	for {
		p := e.observe(target)
		last = p
		if tick != nil {
			if p.State() == Unread || p.State() == NotApplied {
				tick("?", p.readErr)
			} else {
				tick(p.Version(), p.Detail())
			}
		}
		switch p.State() {
		case NotApplied:
			// The restart step never began. Nothing to wait for.
			e.record(ledger.KindRunHalted, NotRestartedNote(p), p.Wire())
			return p, fmt.Errorf("%w: %s", ErrRestartNotObserved, NotRestartedNote(p))
		case WrongVersion:
			data := p.Wire()
			e.record(ledger.KindRunHalted,
				fmt.Sprintf("the node restarted on %s, not the %s this run approved", p.Version(), target), data)
			return p, fmt.Errorf("%w: it restarted on %s, not the %s this run approved",
				ErrWrongVersion, p.Version(), target)
		case Verified:
			// Contract step 8, and the last thing this run does before it
			// calls itself finished: the node reporting the right version
			// in full sync is not proof it is the same node. Compared
			// against the snapshot taken before anything changed, so a node
			// that came back with a different key, without its validator
			// identity, off its publisher lists, or amendment blocked, ends
			// the run with the rollback in front of the operator rather
			// than a green line.
			same, why := e.State.IdentityUnchanged()
			if !same {
				data := p.Wire()
				data["identity"] = why
				e.record(ledger.KindRunUnconfirmed,
					"the node is running "+target+" and is not the node that went down: "+why, data)
				return p, fmt.Errorf("the node is running %s and is not the node that went down: %s", target, why)
			}
			data := p.Wire()
			data["detail"], data["identity"] = p.Detail(), why
			e.record(ledger.KindRunCompleted,
				LedgerSynced(OpUpgrade, p, ""), data)
			return p, nil
		}
		if !e.now().Before(deadline) {
			break
		}
		e.sleep(5 * time.Second)
	}
	if last.State() == CatchingUp {
		// Not halted. The node was recreated on the target and is answering;
		// it simply has not caught up inside the window. A real restart here
		// took about six minutes against a five-minute window and was
		// reported as a failed upgrade, with a rollback hint, on a node that
		// was healthy.
		data := last.Wire()
		data["timeout"] = timeout.String()
		e.record(ledger.KindRunUnconfirmed,
			fmt.Sprintf("node restarted on %s and had not returned to full sync within %s", target, timeout), data)
		return last, fmt.Errorf("%w: it restarted on %s and did not return to full sync within %s",
			ErrNotYetHealthy, target, timeout)
	}
	// Never once a process newer than the restart step: the old one kept
	// answering, or nothing did. Either way nothing proves this run moved
	// the node, and "still catching up" would be a claim that it had.
	data := last.Wire()
	data["timeout"] = timeout.String()
	e.record(ledger.KindRunHalted, NotRestartedNote(last), data)
	return last, fmt.Errorf("%w: %s", ErrRestartNotObserved, NotRestartedNote(last))
}

// restoreAfterFailure puts the deployment back and recreates, for the one
// step that asks for it.
//
// What it will not do: touch anything when this run took no copy of its
// own. Restoring a file this run did not write is a guess about which
// state an operator wanted, made by a program that has already been
// surprised once. It says so in the transcript and leaves the hint instead.
//
// It also does not treat its own failure as fatal: the step that called it
// has already failed and its error is what the caller returns. What a
// failed restore adds is a louder record, because that is the state where
// a person has to look.
func (e *Executor) restoreAfterFailure(ctx context.Context, s Step) {
	if !s.RestoreOnFailure {
		return
	}
	bak := e.Backups["backup-compose"]
	if bak == "" {
		// The plan's copy, taken by an earlier stage in an earlier
		// process. Without this the restore is dead on every real
		// upgrade, because prepare and cutover never share a map.
		bak = e.recalledBackup()
	}
	if bak == "" {
		e.Log.Write("note", s.Name,
			"this plan took no copy of the deployment, so nothing was restored automatically")
		return
	}
	e.Log.Write("step", s.Name, "restoring the deployment as it was, and recreating")
	// By file name, for the same reason as the cancel path (ADR 0025).
	if out, rerr := e.Runner.Run(ctx, e.Wrapper, "restore-compose", filepath.Base(bak)); rerr != nil {
		e.record(ledger.KindRunHalted, "the deployment could not be restored after a failed "+s.Name,
			map[string]any{"backup": bak, "error": rerr.Error(), "output": strings.TrimSpace(string(out))})
		e.Log.Write("fail", s.Name, "the deployment could not be restored: "+rerr.Error())
		return
	}
	e.record(ledger.KindStepSucceeded, "restored the deployment after a failed "+s.Name,
		map[string]any{"backup": bak})
	if out, rerr := e.Runner.Run(ctx, e.Wrapper, "recreate"); rerr != nil {
		e.record(ledger.KindRunHalted, "the node could not be recreated on the restored deployment",
			map[string]any{"backup": bak, "error": rerr.Error(), "output": strings.TrimSpace(string(out))})
		e.Log.Write("fail", s.Name, "the node could not be recreated on the restored deployment: "+rerr.Error())
		return
	}
	// The command returned. Nothing here has read the node since, and the
	// line says exactly that much (#769).
	e.record(ledger.KindStepSucceeded, "the recreate on the restored deployment returned; the node was not read afterwards",
		map[string]any{"backup": bak})
	e.Log.Write("ok", s.Name, "the deployment file is back as it was and the recreate command returned. "+
		"Nothing has read the node since: check its version and sync state on Overview")
}

// RollbackHint is what an operator would run. Printed, never executed: two
// restarts in quick succession while consensus looks unhealthy is its own
// hazard, and a person watching is better placed to judge than a program that
// has already been surprised once.
//
// Empty when no step that can change the deployment or the node began
// (#1001). A halt at the official-image check, after the backups, printed a
// restore-compose and a recreate, and an operator who followed it restarted
// a validator that run had never touched. Every caller already treats an
// empty hint as "nothing to print".
func (e *Executor) RollbackHint() string {
	if !e.touched {
		return ""
	}
	compose := e.Backups["backup-compose"]
	if compose == "" {
		// A cutover in its own process: prepare's copy, recalled the same
		// way restoreAfterFailure recalls it.
		compose = e.recalledBackup()
	}
	if compose == "" {
		return "no compose backup was taken by this run; nothing to roll back to from here"
	}
	return fmt.Sprintf(
		"  %s restore-compose %s\n  %s recreate",
		e.Wrapper, compose, e.Wrapper)
}

// credOf names the passkey that authorised an approval, for the ledger.
func credOf(a approval.Approval) string {
	if a.Assertion == nil {
		return ""
	}
	return a.Assertion.CredentialID
}

// actorFromApproval turns a VERIFIED approval into an attribution.
//
// What was actually proved here: an enrolled passkey signed the challenge
// this approval carries, checked against keys this service holds. What was
// not: that the name on the file belongs to that passkey — the Advisor's
// credential store has no user column to answer that with (yet), so the name
// is the granting dashboard's claim and is recorded as one. verified:
// "approval" says exactly that much and no more, which is the point of the
// field: an auditor can tell a cryptographic attribution from a service's
// word for it without reading this code.
func actorFromApproval(a approval.Approval) ledger.Actor {
	src := ""
	if a.Origin != "" {
		// Only a browser ceremony records an origin.
		src = ledger.SourceWeb
	}
	return ledger.Actor{
		Operator:     a.GrantedBy,
		Role:         a.GrantedByRole,
		CredentialID: credOf(a),
		Source:       src,
		Origin:       a.Origin,
		Verified:     ledger.VerifiedApproval,
		ClaimedBy:    "dashboard",
	}
}

// claimedActor names whoever the approval file on disk SAYS granted this
// stage, for the entry that records the run being refused.
//
// Nothing here is verified — that is the whole situation being recorded. It
// is worth keeping anyway: "someone tried to spend an approval in X's name
// and it did not check out" is the entry an auditor wants, and until now a
// refusal named nobody at all. A compound upgrade grant lives under its own
// stage, so both are looked for.
func (e *Executor) claimedActor(stage string) ledger.Actor {
	for _, s := range []string{stage, approval.StageUpgrade} {
		a, found, err := approval.Peek(e.ApprovalDir, e.PlanID, s)
		if err != nil || !found || a.GrantedBy == "" {
			continue
		}
		return ledger.Actor{
			ClaimedOperator: a.GrantedBy,
			Role:            a.GrantedByRole,
			CredentialID:    credOf(a),
			Origin:          a.Origin,
			Verified:        ledger.VerifiedNone,
			ClaimedBy:       "approval file",
		}
	}
	return ledger.Actor{}
}

// shortDigest renders a digest for a human sentence. The full value always
// goes to the ledger; this is for the line an operator reads at the moment of
// a refusal, where sixty-four hex characters twice would obscure the point.
func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return "sha256:" + d[:12] + "…"
	}
	return d
}
