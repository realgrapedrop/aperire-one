package execute

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/runbook"
)

// RB-004's steps and its confirmation. ADR 0019, and ADR 0023 for the
// official image's own rollback.

// RollbackShape is everything RB-004's step list turns on, named rather
// than positional because three of the four are easy to swap by accident
// and two of them are origins that look alike.
type RollbackShape struct {
	// Target is the version being rolled back TO.
	Target string
	// TargetOrigin is where THAT version's image came from, read off the
	// image when it is here and off the dated copy that named it when it
	// is not (#680). It decides the fetch.
	TargetOrigin ImageOrigin
	// ImageLocal says that image is on this host right now. Separate from
	// the origin on purpose: deriving one from the other is the bug #680
	// records, because "built here and since pruned" then cannot be said.
	ImageLocal bool
	// LiveOrigin is what the deployment file names right now. It decides
	// whether the file is restored whole or has one line rewritten.
	LiveOrigin ImageOrigin
	// RestorePath is the dated copy to restore, required when LiveOrigin
	// is official. Empty is not a fallback: the wrapper refuses a
	// restore-compose with no path and nothing on the node changes, and
	// RB-004's own precondition is what stops the run before that.
	RestorePath string
	// RestoreDigest is the digest the copy in RestorePath pins its image
	// to. An official target is fetched and checked against THIS, never
	// against a tag: the copy is the record of what this node ran, and a
	// tag in that repository can point somewhere else by now (#682,
	// second review).
	RestoreDigest string
	// LiveDigest is the digest the deployment names right now, read before
	// anything is restored (#682). It is what the confirmation after a
	// source rollback compares against: the release does not move, so the
	// only thing that says the container was really replaced is that it is
	// no longer on this.
	LiveDigest string
}

// RollbackShapeFrom converts the host's reading into this package's shape.
// One place, so the two callers that build a rollback cannot disagree about
// which origin means what.
func RollbackShapeFrom(target string, im runbook.RollbackImaging) RollbackShape {
	return RollbackShape{
		Target:        target,
		TargetOrigin:  ImageOrigin(im.TargetOrigin),
		ImageLocal:    im.ImageLocal,
		LiveOrigin:    ImageOrigin(im.LiveOrigin),
		RestorePath:   im.RestorePath,
		RestoreDigest: im.RestoreDigest,
		LiveDigest:    im.LiveDigest,
	}
}

// ErrRestoreDigestChanged is what a run refuses with when the copy it is
// about to restore no longer names the digest the approval covered.
var ErrRestoreDigestChanged = errors.New("the copy this would restore no longer names the digest that was approved")

// RollbackShapeChecked is RollbackShapeFrom with the approval's own value
// held against the reading taken now (#682, third review).
//
// The steps are built at RUN time, from a fresh read of the named copy,
// while the fingerprint the passkey signed was computed when the plan was
// made. Between those two moments the copy is a file in a directory the
// node's account owns. Nothing else compared the two, so a copy edited in
// between would have been fetched, checked and installed under an approval
// for a different digest.
//
// An approval that carried no digest (a local-build target) constrains
// nothing here, and says so by being empty.
func RollbackShapeChecked(target, approvedDigest string, im runbook.RollbackImaging) (RollbackShape, error) {
	sh := RollbackShapeFrom(target, im)
	if approvedDigest != "" && sh.RestoreDigest != approvedDigest {
		return sh, fmt.Errorf("%w: approved %s, the copy names %s",
			ErrRestoreDigestChanged, approvedDigest, orNone(sh.RestoreDigest))
	}
	return sh, nil
}

func orNone(s string) string {
	if s == "" {
		return "no digest at all"
	}
	return s
}

// ImageOrigin is where a node's image came from. Spelled here as well as in
// host for the reason LocalImageRepo is: this package reads wrapper output
// and does not import host. A test holds the two sets of values equal.
type ImageOrigin string

const (
	ImageOriginLocalBuild ImageOrigin = "local-build"
	ImageOriginOfficial   ImageOrigin = "official"
	ImageOriginThirdParty ImageOrigin = "third-party"
	ImageOriginUnknown    ImageOrigin = "unknown"
)

// RollbackSteps is RB-004 expressed as wrapper calls: five, and only the last
// one interrupts.
//
// The order is the design. The dated copy comes first so the version this run
// is leaving is on disk before anything moves — that copy is what makes the
// next rollback go forward. The pull comes before the edit, not after it,
// because `compose up` would otherwise do the download with the node already
// down: a tag withdrawn from the registry between the assessment and the
// approval would leave a stopped node whose deployment names an image that
// does not exist, which is the incident a rollback exists to prevent.
//
// It sets the image rather than restoring the copy it just took a sibling of.
// One line changes, so mounts, ports and the restart policy stay exactly as
// they are — and a copy taken before the last upgrade may also predate
// unrelated deployment edits that restoring the whole file would revert
// without saying so. The copy is named in the record as the file to restore
// by hand when the deployment itself needs reverting.
// imageLocal says the target image is already on this host, measured before
// the steps are built. When it is, nothing here touches the network at all:
// the download becomes a reading that confirms what is already on the disk.
// That is what makes a rollback possible during the incident it exists for —
// a bad release live and the registry unreachable — and it is honest rather
// than lenient, because the step that replaces the pull still has to produce
// a digest for the exact tag before the run goes on.
// origin says where that image came from, and it decides both the fetch and
// the verb that writes the deployment file. It is read off the host or,
// when the image is gone, off the dated deployment copy that named it.
// Never off the configured repository, because a node that upgraded through
// a build is on the other origin from the one its wrapper was configured
// with.
//
// It used to be a second boolean, localBuild, and both callers computed it
// as "local AND the local reference is localhost/xrpld". That made
// localBuild imply imageLocal, so the one branch below that matters most on
// a node building its own images (built here, and since pruned) could
// never be reached, and a rollback landed on a pull of localhost/xrpld:<v>
// that no registry can answer (#680). Three origins do not fit in two
// booleans derived from each other.
//
// ImageOriginUnknown is handled rather than guessed: it takes the registry
// pull, which is the only fetch attemptable without knowing, and RB-004's
// own precondition is what stops a run whose origin could not be read.
func RollbackSteps(sh RollbackShape) []Step {
	target := sh.Target
	imageLocal := sh.ImageLocal
	localBuild := sh.TargetOrigin == ImageOriginLocalBuild
	// Whether the deployment is RESTORED whole turns on what the live file
	// names, not on where the target came from. The swap that has to be
	// undone is the one that wrote the official image line together with
	// an entrypoint/command pair, and the target of that undo is almost
	// always a locally built image, which is the branch that would
	// otherwise edit the image line alone and leave the arguments behind.
	restoreWhole := sh.LiveOrigin == ImageOriginOfficial
	fetch := Step{
		Name: "pull the rollback target", Stage: StageRollback, Verb: "pull", Arg: target,
		Why: "the slow, failure-prone part, done while the node is still validating. Without " +
			"it the download happens with the node already down, and a withdrawn tag leaves " +
			"a stopped node naming an image that does not exist",
		Undo: "docker image rm " + target,
		Verify: func(out string, st runbook.HostState) error {
			if !strings.Contains(out, "sha256:") {
				return fmt.Errorf("pull did not yield a digest: %q", out)
			}
			if ok, d := st.ConsensusHealthy(); !ok {
				return fmt.Errorf("the node stopped looking healthy during a pull: %s", d)
			}
			return nil
		},
	}
	if sh.TargetOrigin == ImageOriginOfficial && imageLocal {
		// Already here, so nothing is downloaded: RB-004's local-first
		// order, kept. The check that follows does not need the registry
		// either, so a rollback still works with the registry down,
		// which is the incident this runbook exists for.
		//
		// Asked BY DIGEST (#664). By version alone the wrapper answers with
		// the local build first, and a node just built back from the
		// official image has both: this step read the build's digest, said
		// "the official image is on this host", and pinned the run to the
		// image it was rolling away from.
		fetch = Step{
			Name: "confirm the official image for " + target + " is on this host", Stage: StageRollback,
			Verb: "image-digest", Arg: target, Arg2: sh.RestoreDigest,
			Why: "the official image this node was running until the upgrade is still here, " +
				"so nothing is downloaded and the registry is not needed",
			Undo: "none needed, this reads",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "sha256:") {
					return fmt.Errorf("the image on this host reports no digest: %q", out)
				}
				if sh.RestoreDigest == "" || !strings.Contains(out, sh.RestoreDigest) {
					return fmt.Errorf("the image on this host is not the one the copy pins (%s): %q",
						orNone(sh.RestoreDigest), strings.TrimSpace(out))
				}
				return nil
			},
		}
	} else if sh.TargetOrigin == ImageOriginOfficial {
		// Not here, so it has to be fetched, and it is fetched BY DIGEST
		// (#682, second review). A pull by tag takes whatever that tag
		// points at today, which on a rollback is the release the
		// operator is trying to get away from, or anything pushed since.
		fetch = Step{
			Name:  "pull the official image for " + target + ", pinned to the digest it ran on",
			Stage: StageRollback, Verb: "pull-official", Arg: target, Arg2: sh.RestoreDigest,
			Why: "the copy this restores names a digest, and that is what gets fetched: a tag " +
				"in that repository can point somewhere else by now, including at the release " +
				"this is rolling away from",
			Undo: "docker image rm " + sh.RestoreDigest,
			Verify: func(out string, st runbook.HostState) error {
				if sh.RestoreDigest == "" || !strings.Contains(out, sh.RestoreDigest) {
					return fmt.Errorf("the pull did not confirm %s: %q", sh.RestoreDigest, out)
				}
				if ok, d := st.ConsensusHealthy(); !ok {
					return fmt.Errorf("the node stopped looking healthy during a pull: %s", d)
				}
				return nil
			},
		}
	} else if localBuild && !imageLocal {
		// The origin says "built here" and the image is not here: it was
		// pruned since the reading that chose this target. Nothing can pull
		// it, so the honest fetch is to build it again from the same signed
		// package, and a version the package repository no longer carries
		// fails loudly at that step rather than at the recreate.
		fetch = Step{
			Name: "rebuild the rollback target from the signed package", Stage: StageRollback,
			Verb: "build-image", Arg: target,
			Why: "this node runs an image built on this host and that image is no longer here, " +
				"so there is nothing to pull; the same recipe that made it makes it again, with " +
				"the node still validating throughout",
			Undo: "none needed, this adds an image and touches no container",
			Verify: func(out string, st runbook.HostState) error {
				if !strings.Contains(out, "built "+LocalImageRepo+":"+target) {
					return fmt.Errorf("the build did not report an image for %s: %q", target, out)
				}
				if ok, d := st.ConsensusHealthy(); !ok {
					return fmt.Errorf("the node stopped looking healthy during a build: %s", d)
				}
				return nil
			},
		}
	} else if imageLocal {
		fetch = Step{
			Name: "confirm the rollback target is on this host", Stage: StageRollback,
			Verb: "image-digest", Arg: target,
			Why: "this image is already here — it is what the node was running until the " +
				"upgrade — so nothing is downloaded and the registry is not needed. What it " +
				"resolves to locally is read and recorded instead",
			Undo: "none needed — this reads",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "sha256:") {
					return fmt.Errorf("the image on this host reports no digest: %q", out)
				}
				return nil
			},
		}
	}
	setImage := Step{
		Name: "point the deployment back at " + target, Stage: StageRollback,
		Verb: "set-image", Arg: target,
		Why:  "one line; mounts, ports and restart policy stay exactly as they are",
		Undo: "restore the dated copy taken in step 1",
		Verify: func(out string, _ runbook.HostState) error {
			if !strings.Contains(out, "->") || !strings.Contains(out, target) {
				return fmt.Errorf("wrapper did not confirm the edit: %q", out)
			}
			return nil
		},
	}
	if restoreWhole {
		// Restoring the whole copy, not the image line alone. The upgrade
		// that put this node on the official image also wrote an
		// entrypoint/command pair; leaving that behind and changing only
		// the image would hand the older image's own entrypoint a --conf
		// it then adds a second time, and xrpld refuses --conf twice. The
		// copy taken before the swap has neither line, so restoring it
		// byte for byte is the rollback.
		setImage = Step{
			Name: "restore the deployment as it stood before the swap", Stage: StageRollback,
			// The copy's file name, not its path: the wrapper resolves it
			// beside the compose file it already knows, and the Advisor's
			// root socket takes no paths (ADR 0025). The name is also what
			// the approval's restore_path covers.
			Verb: "restore-compose", Arg: filepath.Base(sh.RestorePath), Arg2: target,
			Why: "the whole file, not the image line: the swap to the official image also " +
				"wrote the arguments this node runs with, and an older image's own entrypoint " +
				"would add a second --conf to them, which xrpld refuses",
			Undo: "the copy taken in step 1 names the state this is leaving",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "restored ") {
					return fmt.Errorf("wrapper did not confirm the restore: %q", out)
				}
				return nil
			},
		}
	} else if sh.TargetOrigin == ImageOriginOfficial {
		// One line rewritten rather than a whole file: the deployment does
		// not name the official image yet, so there are no arguments from a
		// swap to put back. It still goes through the official verb, which
		// refuses a digest this host has not verified, rather than through
		// the plain one, which would write an unpinned tag with no check
		// behind it (#682, second review).
		setImage.Verb = "set-image-official"
		setImage.Arg2 = sh.RestoreDigest
		setImage.Why = "one line, pinned to the digest this host just checked against the " +
			"signed package; mounts, ports and restart policy stay exactly as they are"
		setImage.Verify = func(out string, _ runbook.HostState) error {
			if !strings.Contains(out, "->") || !strings.Contains(out, sh.RestoreDigest) {
				return fmt.Errorf("wrapper did not confirm the edit at %s: %q", sh.RestoreDigest, out)
			}
			return nil
		}
	} else if localBuild {
		setImage.Verb = "set-image-local"
		setImage.Why = "one line, plus the pull_policy that keeps compose from reaching for a " +
			"registry no name like this one can be served from; mounts, ports and restart " +
			"policy stay exactly as they are"
		setImage.Verify = func(out string, _ runbook.HostState) error {
			if !strings.Contains(out, "->") || !strings.Contains(out, target) {
				return fmt.Errorf("wrapper did not confirm the edit: %q", out)
			}
			if !strings.Contains(out, "pull_policy: never") {
				return fmt.Errorf("wrapper did not confirm the pull policy: %q", out)
			}
			return nil
		}
	}
	// What confirms the image is the right one. For anything this host
	// built or pulled by tag, the image is asked its own version, which
	// runs it. For an official image that is not allowed: running an
	// image to find out whether it is trustworthy is the shape the first
	// review threw out, and a rollback reached it by another door (#682,
	// second review). The official target is checked the way the upgrade
	// checks one: on this host, against the signed package, with the
	// container created and never started.
	confirm := Step{
		Name: "confirm the image reports the rollback target", Stage: StageRollback,
		Verb: "image-version", Arg: target,
		Why:  "a tag is a label someone chose and can be moved; ask the image itself",
		Undo: "none needed — this runs a throwaway container",
		Verify: func(out string, _ runbook.HostState) error {
			if strings.TrimSpace(out) == "" {
				return errUnconfirmed
			}
			if !strings.Contains(out, target) {
				return fmt.Errorf("image reports %q, which does not contain %s",
					strings.TrimSpace(out), target)
			}
			return nil
		},
	}
	if sh.TargetOrigin == ImageOriginOfficial {
		confirm = Step{
			Name: "check that image against the signed package, on this host", Stage: StageRollback,
			Verb: "verify-official-image", Arg: target, Arg2: sh.RestoreDigest,
			Why: "the same check the upgrade makes, for the same reason: the bytes that would " +
				"run are compared here, on this host, with nothing from that image running",
			Undo: "none needed — this creates a container, copies files out and removes it",
			Verify: func(out string, _ runbook.HostState) error {
				v := host.ParseVerifyOfficial(out)
				if !v.Read {
					return fmt.Errorf("the verify answered nothing this side recognises: %q", lastLine(out))
				}
				ok, checks := v.Checks(target, sh.RestoreDigest)
				if !ok {
					return fmt.Errorf("this image is not what it claims to be, so nothing was "+
						"restored: %s", host.FailedChecks(checks))
				}
				return nil
			},
		}
	}
	steps := []Step{
		{
			Name: "back up the current deployment definition", Stage: StageRollback,
			Verb: "backup-compose",
			Why: "the version this rolls back FROM, on disk, before anything moves — it is what " +
				"the next rollback derives as its target, so going forward again is this same act",
			Undo: "none needed — this only adds a file",
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
		fetch,
		confirm,
		setImage,
		{
			Name: "recreate the node on " + target, Stage: StageRollback, Verb: "recreate",
			Why:        "the only step that interrupts validation",
			Interrupts: true,
			Undo:       "restore the dated copy taken in step 1 and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "running") {
					return fmt.Errorf("container is not running after recreate: %q", out)
				}
				return nil
			},
		},
	}
	// One more, and only where the version cannot tell the two images apart
	// (#682). Undoing a source switch leaves the release exactly where it
	// was, so "the image reports 3.4.1" is true of the image it came FROM as
	// well as the one it went back to: a restore that silently did nothing
	// would pass every step above. The digest is what differs, and it is
	// read off the container that is now running.
	if sh.RestorePath != "" {
		steps = append(steps, Step{
			Name: "confirm the node came back on a different image", Stage: StageRollback,
			Verb: "running-digest",
			Why: "the release did not move here, the source did, so the version proves nothing. " +
				"The digest the container reports is what says the restore took effect",
			Undo: "none needed — this only reads",
			Verify: func(out string, _ runbook.HostState) error {
				got := strings.TrimSpace(out)
				if got == "" {
					return errUnconfirmed
				}
				if !strings.Contains(got, "sha256:") {
					return fmt.Errorf("the running container reports no digest: %q", got)
				}
				// The digest it must NOT still be on is the one the
				// deployment named before the restore. Carried on the shape
				// so this compares a reading against a reading rather than
				// against a constant.
				if sh.LiveDigest != "" && strings.Contains(got, sh.LiveDigest) {
					return fmt.Errorf(
						"the node is still on %s, so the deployment was restored and the "+
							"container was not replaced", sh.LiveDigest)
				}
				return nil
			},
		})
	} else if sh.TargetOrigin == ImageOriginOfficial && sh.RestoreDigest != "" {
		// The same proof for a rollback that rewrites one line onto the
		// official image (#664). Going back from a build of 3.4.1 to the
		// official 3.4.1 moves no release either, and the live file named
		// a local tag with no digest, so "not still on the old digest" has
		// nothing to compare against. The positive reading does: the
		// container has to be on the digest the copy pins. A rollback to an
		// official image of another release gets the same check, which it
		// never had, and it can only be true when the swap took.
		steps = append(steps, Step{
			Name: "confirm the container runs the official image this host checked", Stage: StageRollback,
			Verb: "running-digest",
			Why: "a tag names a release, and both images here report the same one. The digest the " +
				"container reports is what says the node is on the image this host just checked",
			Undo: "none needed, this only reads",
			Verify: func(out string, _ runbook.HostState) error {
				got := strings.TrimSpace(out)
				if got == "" {
					return errUnconfirmed
				}
				if !strings.Contains(got, sh.RestoreDigest) {
					return fmt.Errorf("the node came back on %s, not on %s; the deployment was "+
						"rewritten and the container is not on the image that was checked",
						got, sh.RestoreDigest)
				}
				return nil
			},
		})
	}
	return steps
}

// NativeRollbackSteps is RollbackSteps' native twin: three steps instead of
// five, and the missing two are gaps this note names rather than papers
// over. There is no deployment-definition equivalent to take a dated copy of
// first (issue #393 tracks derivation's own dependence on that copy), and a
// package manager fetches and installs in one call, so there is nothing to
// split the way a container's pull-then-confirm-then-set-image is split.
//
// package-install runs before the interrupting restart for the same reason
// NativeUpgradeSteps' does: the interrupting step re-reads the package
// database and refuses unless it already names the target, so the install
// has to have already happened. RB-004's own "the rollback target is
// installable" precondition is the pre-cutover half of package-available's
// question; this is the step that asks it again, immediately before use,
// the same defence in depth the container path's own pull re-confirms.
//
// The same gap NativeUpgradeSteps names applies here without any change of
// reasoning, package-install carries no Interrupts flag, so
// nativeConsensusReMeasure sits immediately ahead of it for the same reason,
// closing issue #394 on both native paths from one function.
//
// package-keep sits here too, between package-available and that re-measure,
// issue #401, for the same reason NativeUpgradeSteps places it there: the
// cheap read goes first, and the version this rollback is about to replace,
// the release it is rolling away FROM, is kept in case the next act rolls
// forward again and finds the repository no longer offers it.
func NativeRollbackSteps(target string) []Step {
	return []Step{
		{
			Name: "confirm the rollback target is installable", Stage: StageRollback,
			Verb: "package-available", Arg: target,
			Why: "the read that would refuse an uninstallable rollback target by name, before " +
				"anything changes, rather than discovering it with the node already stopped",
			Undo: "none needed, this reads",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyPackageAvailable(out)
			},
		},
		{
			Name: "keep the currently installed package", Stage: StageRollback, Verb: "package-keep",
			Why: "captures the artefact for the version this rollback is about to replace, before " +
				"package-install runs, so rolling forward again later has something to install if " +
				"the repository no longer offers that version by then",
			Undo:   "none needed, this only adds a file",
			Verify: verifyPackageKept,
		},
		nativeConsensusReMeasure(StageRollback, "the package install"),
		{
			Name: "install the rollback target", Stage: StageRollback, Verb: "package-install", Arg: target,
			MayRestart: true,
			Why: "the package manager verifies the vendor's signature and installs. Its own " +
				"maintainer scripts can restart the node here, so this step is not the outage-free " +
				"half a pulled image is",
			Undo: "roll forward with another rollback, once this one is confirmed",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyPackageInstalled(out, target)
			},
		},
		{
			Name: "restart the node onto " + target, Stage: StageRollback, Verb: "restart",
			Why:        "the only step here that interrupts validation on purpose",
			Interrupts: true,
			Undo:       "roll forward with another rollback and restart again",
			Verify: func(out string, _ runbook.HostState) error {
				return verifyRestarted(out)
			},
		},
	}
}

// PollRollback is PollRestart with one tolerance, and the tolerance is the
// whole reason this function exists.
//
// PollRestart returns RestartVersionChanged on the first reading that is not
// `expected`, which is right for RB-002 — expected is the version the node
// was already running, so anything else is a finding. It is wrong for a
// rollback: "not the expected version" includes the version the node was
// running a second ago, still answering while the old container comes down.
// Unamended, every rollback halts on its first poll with a finding that is
// just the ordinary shape of the act.
//
// So `outgoing` is tolerated, and only for `tolerate`. Past that it is a
// finding again, and a loud one: a node still reporting the version this run
// was supposed to move it off means the recreate did not take, and waiting
// longer does not change that. Any THIRD version halts immediately, whenever
// it appears — that is a node that came back on something nobody approved.
//
// The tolerance applies to the OLD process only, and that is now a reading
// rather than a guess (#769): a reading whose process started before the
// rollback's restart step is the node coming down, and one that started
// after it is the node that came back. The old process past the tolerance
// means the recreate did not take. A new process on anything but the target
// is a finding at once, including the outgoing version: that is a recreate
// that came back on what the file used to say.
func PollRollback(read NodeReader, expected, outgoing string, appliedAt time.Time, tolerate, window time.Duration,
	now func() time.Time, sleep func(time.Duration),
	tick func(version, detail string)) (RestartVerdict, string, *Proof) {

	start := now()
	deadline := start.Add(window)
	outgoing = strings.TrimSpace(outgoing)
	var last *Proof
	for {
		obs, err := read.Observe()
		p := Judge(obs, err, appliedAt, now(), expected)
		last = p
		if tick != nil {
			if err != nil {
				tick("?", err.Error())
			} else {
				tick(obs.Version, obs.Detail)
			}
		}
		switch p.State() {
		case NotApplied:
			return RestartNotObserved, "", p
		case Verified:
			return RestartBack, p.Version(), p
		case WrongVersion:
			return RestartVersionChanged, p.Version(), p
		case NotRestarted:
			// The old process, still answering. Nothing is concluded from it
			// while it is the outgoing build and the tolerance holds.
			if !(outgoing != "" && p.Version() == outgoing && now().Sub(start) < tolerate) &&
				p.Version() != expected {
				return RestartVersionChanged, p.Version(), p
			}
		}
		if !now().Before(deadline) {
			break
		}
		sleep(5 * time.Second)
	}
	if last.State() == CatchingUp {
		return RestartStillCatchingUp, expected, last
	}
	return RestartNotObserved, last.Version(), last
}

// RollbackTolerance is how long the outgoing version may still be answering
// before it becomes a finding.
//
// Two minutes against a container that comes back in about thirty seconds:
// long enough that a slow stop is not reported as a failure, short enough
// that a recreate which did nothing is caught inside the confirmation window
// rather than at the end of it.
const RollbackTolerance = 2 * time.Minute

// AwaitRollback polls and records. The verdict comes back for the caller to
// render, and the ledger entry is written here, once, so the web path and the
// command line leave the same record of the same fact — the placement
// AwaitRestart's own comment argues for.
func (e *Executor) AwaitRollback(target, outgoing string, window time.Duration,
	tick func(version, detail string)) (RestartVerdict, string, *Proof) {

	verdict, found, p := PollRollback(e.State, target, outgoing, e.appliedAt,
		RollbackTolerance, window, e.now, e.sleep, tick)
	data := p.Wire()
	data["rolled_back_from"] = outgoing
	switch verdict {
	case RestartBack:
		data["detail"] = p.Detail()
		e.record(ledger.KindRunCompleted,
			LedgerSynced(OpRollback, p, ""), data)
	case RestartVersionChanged:
		data["expected"], data["found"] = target, found
		e.record(ledger.KindRunHalted,
			"rollback halted: the node is not reporting "+target, data)
	case RestartStillCatchingUp:
		// The version is recorded as the TARGET, because that is what a
		// process newer than the restart step reported. Whether it can use
		// the store the newer build wrote is the open question, and the
		// entry says the run is unconfirmed rather than done.
		data["timeout"] = window.String()
		e.record(ledger.KindRunUnconfirmed,
			fmt.Sprintf("node had not returned to full sync within %s after the rollback", window), data)
	case RestartNotObserved:
		e.record(ledger.KindRunHalted, NotRestartedNote(p), data)
	}
	return verdict, found, p
}

// RollbackStalledNote is what an operator is told when the node is not on the
// version this run moved it to. Two shapes, because the two causes have
// different next steps and one sentence covering both would name neither.
func RollbackStalledNote(target, found, outgoing string) string {
	if found == outgoing && outgoing != "" {
		return "the node is still running " + outgoing + ", the version this run was moving it " +
			"off. The deployment names " + target + ", so the container did not come back on " +
			"what the file says: the recreate did not take. This run is halted rather than " +
			"reported as slow, because waiting longer does not restart a container."
	}
	return "the node came back running " + found + ", not the " + target + " this rollback " +
		"approved. Something other than this run decided which image it starts on: the " +
		"deployment file, a moved tag, or a hand-run command. This run is halted rather than " +
		"reported as slow, because waiting longer does not make it the approved build."
}

// RollbackUnconfirmedNote is the honest path when the node came back on the
// older build and has not validated — the 2026-08-06 failure mode, which is a
// node that starts, peers, and never acquires a validated ledger.
//
// It says what to do, because a transcript that ends on "not yet" leaves the
// operator watching a spinner for the one outcome this act was warned about.
func RollbackUnconfirmedNote(target, outgoing, wrapper string) string {
	return "The node is running " + target + " and has not returned to full sync. Some of that " +
		"is ordinary: a node that changed version catches up from its store, and a rollback may " +
		"have to rebuild from the network, which took about seven minutes when this was last " +
		"measured. Watch the state on Overview — it moves through connected to full.\n\n" +
		"If it stays out of full sync with peers connected and no validated ledger, there are " +
		"TWO known causes and they look identical from here. Check both rather than the first " +
		"one.\n\n" +
		"  1. the data store. " + runbook.StoreRiskLesson + "\n" +
		"  2. an amendment. If an amendment has been enabled on the network since " + target +
		" was current, this build can be amendment-blocked coming back — which also presents " +
		"as a node that started, peered, and never validated. server_info reports " +
		"amendment_blocked, and the node's own log names the amendment.\n\n" +
		"The way back to " + outgoing + " is another rollback, which now derives " + outgoing +
		" as its target — ask for one. By hand it is:\n" +
		"  " + wrapper + " set-image " + outgoing + "\n" +
		"  " + wrapper + " recreate"
}
