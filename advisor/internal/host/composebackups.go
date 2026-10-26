package host

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/rollback"
	"aperire-advisor/internal/runbook"
)

// The deployment's dated copies, and the tag each of them names — ADR 0019.
//
// This is half of where a rollback target comes from. `backup-compose` runs
// before `set-image` in both the upgrade's prepare and the rollback's own
// stage, so every dated copy beside the compose file is the deployment as it
// stood before a version change, and the image tag inside it is the version
// this node was running then.
//
// It goes through the privilege wrapper for the reason artefactHashes does:
// the account can then be refused the deployment directory outright, and the
// wrapper prints the path, the modification time and the tag rather than the
// file — a compose file can carry environment values, and none of them are
// this question's business.

// ComposeBackup is one row: the live deployment file, or a dated copy of it.
type ComposeBackup struct {
	// Origin marks the live file. Exactly one row has it.
	Origin bool
	// Tag is the image tag the file names, empty when the file names no image
	// from this node's repository. Empty is not an error and not a version:
	// it means the file cannot say what the node would have run.
	Tag string
	// Name is the file's base name. Callers join it to the deployment
	// directory when they need a path, and the wrapper's restore verb
	// re-checks that path itself.
	Name string
	// At is the file's modification time.
	At time.Time
	// Ref is the whole image reference the file names, repository included.
	//
	// #680: the only reading of "where did this rollback target come from"
	// used to be whether the image is on this host right now, which is
	// false in exactly the case that needs the answer: an image built
	// here and since pruned. The copy taken before the change still names
	// it, whether or not the image survived. Empty when the file names no
	// image, or when the wrapper predates the fifth field.
	Ref string
}

// ComposeBackups reads the deployment file and every dated copy beside it.
func (s *State) ComposeBackups() ([]ComposeBackup, error) {
	if s.Wrapper == "" {
		return s.composeBackupsDirect()
	}
	name := s.Wrapper
	rest := []string{"compose-backups"}
	out, err := s.Runner.Run(s.context(), name, rest...)
	if err != nil {
		return nil, fmt.Errorf("reading the deployment backups through the wrapper: %w", err)
	}
	return parseComposeBackups(string(out))
}

// parseComposeBackups reads the wrapper's tab-separated fields: kind,
// mtime, tag, basename, and since #680 the whole image reference. A row it
// cannot read is an error rather than a skipped line, since a rollback target
// derived from a partially understood listing is a version nobody chose.
//
// Four fields is still a row. A host whose wrapper has not been refreshed
// yet answers with four, and losing the reference there costs the origin
// reading rather than the whole listing.
func parseComposeBackups(out string) ([]ComposeBackup, error) {
	var rows []ComposeBackup
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 && len(f) != 5 {
			return nil, fmt.Errorf("unreadable row from the wrapper: %q", line)
		}
		mod, _ := strconv.ParseInt(f[1], 10, 64)
		tag := f[2]
		// The wrapper writes "-" for a file that names no image from this
		// repository. Carried through as empty, which is what "this file
		// cannot say" looks like to every caller above.
		if tag == "-" {
			tag = ""
		}
		ref := ""
		if len(f) == 5 && f[4] != "-" {
			ref = f[4]
		}
		rows = append(rows, ComposeBackup{
			Origin: f[0] == "origin",
			Tag:    tag,
			Name:   f[3],
			At:     time.Unix(mod, 0),
			Ref:    ref,
		})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the wrapper returned no rows")
	}
	return rows, nil
}

// composeBackupsDirect is the same reading done in this process, for the
// operator running the command-line tool as themselves with no wrapper
// configured. It produces the identical shape, so nothing above it can tell
// which route supplied the rows.
func (s *State) composeBackupsDirect() ([]ComposeBackup, error) {
	origin := s.Profile.ComposeFile
	if origin == "" {
		return nil, fmt.Errorf("the profile records no deployment file")
	}
	dir := filepath.Dir(origin)
	base := filepath.Base(origin)

	read := func(p string, isOrigin bool) (ComposeBackup, bool) {
		fi, err := os.Lstat(p)
		// The same predicate the wrapper applies, and the same one
		// restore-compose enforces: a regular file, not a symlink, of a
		// sane size.
		if err != nil || !fi.Mode().IsRegular() || fi.Size() >= 1<<20 {
			return ComposeBackup{}, false
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return ComposeBackup{}, false
		}
		return ComposeBackup{
			Origin: isOrigin,
			Tag:    composeTag(string(b), s.Profile.ImageRepo, s.Profile.Service),
			Name:   filepath.Base(p),
			At:     fi.ModTime(),
			Ref:    ComposeImageRef(string(b), s.Profile.ImageRepo, s.Profile.Service),
		}, true
	}

	var rows []ComposeBackup
	if r, ok := read(origin, true); ok {
		rows = append(rows, r)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", dir, err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, base+".") || !strings.HasSuffix(n, ".bak") {
			continue
		}
		if r, ok := read(filepath.Join(dir, n), false); ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no deployment file at %s", origin)
	}
	return rows, nil
}

// composeTag pulls the tag off the first image line naming this node's
// repository.
//
// The pattern is the wrapper's, character for character: `image: ` with one
// space, then the repository, then a run of non-space. Being LOOSER here than
// the verb would make the two routes disagree about a file, which is the one
// property the parse above and this function exist to keep — and being
// stricter would do the same in the other direction. set-image writes exactly
// this shape, so it is also what every file either route sees looks like.
// Either origin counts, and failing both, this node's own service block:
// the same rule the wrapper's compose_tag follows, and the same reason.
// A node that upgraded through a locally built image has copies on both
// sides of that swap, and a listing that knew only one of them would report
// "-" for half of them and lose those rollback targets. ComposeImageRef
// holds the rule; this takes the tag off what it finds.
func composeTag(body, repo, service string) string {
	ref := ComposeImageRef(body, repo, service)
	// A digest-pinned official image names no tag at all, and its last
	// colon opens the hash. The version lives in the comment beside it,
	// which is what set-image-official wrote there and the only thing in
	// the file that carries it.
	if strings.Contains(ref, "@sha256:") {
		// repo:tag@sha256:... first. The installer's own default writes
		// that shape, and a reader that went straight to the comment
		// answered "no version" for every node installed from it, which is
		// what a rollback looks its target up by (#682, review of
		// 2026-09-27). The comment is the fallback, for the line
		// set-image-official writes.
		if before, _, ok := strings.Cut(ref, "@"); ok {
			if i := strings.LastIndex(before, ":"); i >= 0 && !strings.Contains(before[i+1:], "/") {
				return before[i+1:]
			}
		}
		return stagedVersionComment(body, ref)
	}
	// A reference with no tag says nothing about which version this file
	// would run, which is the only question this answers.
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ""
	}
	return ref[i+1:]
}

// rollbackTargetOrigin is where the image for a rollback target came from,
// read WITHOUT depending on that image still being on this host.
//
// #680: RollbackSteps has a branch for "this node builds its own images and
// the target has been pruned", and it was unreachable, because both callers
// derived "built here" from whether the image was present. Present implies
// not pruned, so the one case the branch exists for could never reach it,
// and the rollback fell through to a pull of localhost/xrpld:<version>,
// which no registry can answer.
//
// Two readings, in order:
//
//  1. The image on this host, when it is here: the reference that answered
//     names its own origin, and that is the strongest evidence there is.
//  2. The dated deployment copy taken before the change that left this
//     version behind. That file names the reference the node ran then,
//     whether or not the image survived. This is the pruned case.
//
// Neither reading found: OriginUnknown with the reason. Unknown is not
// local-build and is not a registry image; the caller refuses rather than
// guessing which verb to use on a node it could not read.
// RollbackImaging is the whole reading RB-004's steps turn on: where the
// target's image came from, whether it is here, what the deployment names
// right now, and which dated copy a whole-file restore would put back.
//
// It is one method rather than four because the four have to describe one
// moment. Asked separately, a rollback could read the origin before a
// recreate and the live file after it.
// restoreCopy is the BASENAME of the dated copy the derivation named and
// the operator approved, or empty when the caller has no derivation to
// hand (RB-001 reads only LiveOrigin). Naming it is the fix for the
// second review's HIGH 1: this used to pick "the newest copy that is not
// official" on its own, which on an official-to-official rollback is a
// different file from the one the card showed and the approval covered,
// and on a node installed straight onto the official image is no file at
// all. What gets restored is now the copy that was approved, or nothing.
func (s *State) RollbackImaging(version, restoreCopy string) runbook.RollbackImaging {
	origin, local, detail := s.rollbackTargetOrigin(version)
	im := runbook.RollbackImaging{
		TargetOrigin: origin,
		ImageLocal:   local,
		LiveOrigin:   string(OriginUnknown),
		Detail:       detail,
	}
	live, liveDetail := s.DeploymentOrigin()
	im.LiveOrigin = string(live)
	im.RunningOrigin = string(s.RunningOrigin())
	im.Detail += "; " + liveDetail
	// The digest the file names now, if it names one. Read off the same
	// reference DeploymentOrigin just read, never resolved again: the two
	// have to be about one file.
	if ref, rerr := s.DeploymentImage(); rerr == nil {
		if i := strings.LastIndex(ref, "@"); i >= 0 {
			im.LiveDigest = ref[i+1:]
		}
	}
	if live != OriginOfficial {
		// One line is rewritten, so no copy has to be restored whole. The
		// dated copy the rollback takes for itself in step 1 is still what
		// an operator restores by hand.
		//
		// The digest still has to be read, though (#682, third review):
		// rolling FROM a locally built image TO an official one takes the
		// official verbs, and those need the digest the copy names. Read
		// here, off the named copy, so a shape with no digest refuses at a
		// precondition rather than dying mid-stage at require_digest.
		if restoreCopy != "" {
			if _, digest, origin := s.copyFacts(restoreCopy); digest != "" || origin != "" {
				im.RestoreDigest = digest
				if origin != "" && origin != string(OriginUnknown) {
					im.TargetOrigin = origin
				}
				s.officialImageLocal(&im, version)
			}
		}
		return im
	}
	// The file names the official image, so the swap that put it there
	// also wrote the arguments this node runs with, and only restoring
	// the whole copy undoes both. WHICH copy is not this function's
	// choice: it is the one the derivation named and the operator
	// approved, passed in.
	if restoreCopy == "" {
		im.Detail += "; no dated copy was named for this rollback, so there is no whole-file " +
			"restore to make"
		return im
	}
	path, digest, why := s.namedDeploymentCopy(restoreCopy, version)
	im.RestorePath, im.RestoreDigest = path, digest
	im.Detail += "; " + why
	if path != "" {
		// Where the target's image came from is what the COPY says, not
		// what happens to be on this host. A node holding both a local
		// 3.4.1 and an official 3.4.1 answers local-build to the host
		// reading, and the steps then skip the check an official image
		// needs while the restored file pins its digest.
		if _, _, origin := s.copyFacts(restoreCopy); origin != "" &&
			origin != string(OriginUnknown) {
			im.TargetOrigin = origin
			im.Detail += "; that copy names an image from " + origin
		}
		s.officialImageLocal(&im, version)
	}
	return im
}

// officialImageLocal re-measures ImageLocal for an official target, at the
// digest the copy pins (#664).
//
// The first reading asks by version, and the wrapper answers a version with
// the local build first. A node built back from the official image holds
// both: "3.4.1 is on this host" was true of the build, the rollback then
// skipped the download of an official image that might be gone, and its
// confirm step read the build's digest. Asked by digest, the answer is about
// the one image the run will install. Nothing changes for a target that is
// not official, or a copy that pins no digest.
func (s *State) officialImageLocal(im *runbook.RollbackImaging, version string) {
	if im.TargetOrigin != string(OriginOfficial) || im.RestoreDigest == "" {
		return
	}
	if s.Wrapper == "" {
		im.ImageLocal = false
		im.Detail += "; no privilege wrapper is configured, so whether the official image at " +
			im.RestoreDigest + " is here was not read"
		return
	}
	out, err := s.Runner.Run(s.context(), s.Wrapper, "image-digest", version, im.RestoreDigest)
	im.ImageLocal = err == nil && strings.Contains(string(out), im.RestoreDigest)
	if im.ImageLocal {
		im.Detail += "; the official image at " + im.RestoreDigest + " is on this host"
	} else {
		im.Detail += "; the official image at " + im.RestoreDigest + " is not on this host, so it is fetched by that digest"
	}
}

// namedDeploymentCopy resolves one dated copy by name and refuses anything
// that is not the copy this rollback may restore.
//
// Three things are checked here rather than trusted: that the name really
// is one of this deployment's dated copies (never a path), that the copy
// still exists and is a regular file, and that the image line inside it
// names the version being rolled back to. That last one is what binds the
// file to the approval: a copy naming some other release is a different
// act from the one the operator read on the card.
func (s *State) namedDeploymentCopy(name, version string) (path, digest, detail string) {
	base := filepath.Base(s.Profile.ComposeFile)
	if name != filepath.Base(name) || !strings.HasPrefix(name, base+".") || !strings.HasSuffix(name, ".bak") {
		return "", "", fmt.Sprintf("%q is not a dated copy of %s, so nothing is restored", name, base)
	}
	rows, err := s.ComposeBackups()
	if err != nil {
		return "", "", fmt.Sprintf("the deployment's dated copies could not be read: %v", err)
	}
	for _, r := range rows {
		if r.Origin || filepath.Base(r.Name) != name {
			continue
		}
		if normaliseVersion(r.Tag) != normaliseVersion(version) {
			return "", "", fmt.Sprintf(
				"the copy %s names %s and this rollback is to %s, so it is not the file that "+
					"goes back", name, r.Tag, version)
		}
		full := filepath.Join(filepath.Dir(s.Profile.ComposeFile), name)
		if fi, serr := os.Lstat(full); serr != nil || !fi.Mode().IsRegular() {
			return "", "", fmt.Sprintf("%s is not a readable regular file, so nothing is restored", name)
		}
		d := ""
		if i := strings.LastIndex(r.Ref, "@"); i >= 0 {
			d = r.Ref[i+1:]
		}
		return full, d, "going back to the deployment as it stood in " + name
	}
	return "", "", fmt.Sprintf("no dated copy of the deployment is named %s on this host", name)
}

// preSwapDeploymentCopy is the newest dated copy whose image line names
// something other than the official image: the deployment as it stood
// before the source switch.
//
// Named by ORIGIN rather than by version, because a source switch does not
// change the version. Both production and the lab node run
// localhost/xrpld:3.4.1 and would take rippleci's 3.4.1, so a copy chosen
// by "a version other than the running one" finds nothing on exactly the
// two hosts this was ruled for.
func (s *State) preSwapDeploymentCopy() (string, string) {
	rows, err := s.ComposeBackups()
	if err != nil {
		return "", fmt.Sprintf("the deployment's dated copies could not be read: %v", err)
	}
	var best ComposeBackup
	for _, r := range rows {
		if r.Origin || r.Ref == "" || OriginOf(r.Ref) == OriginOfficial {
			continue
		}
		if best.Name == "" || r.At.After(best.At) {
			best = r
		}
	}
	if best.Name == "" {
		return "", "no dated copy of the deployment names an image other than the official one, " +
			"so there is nothing to restore this node to"
	}
	return filepath.Join(filepath.Dir(s.Profile.ComposeFile), best.Name),
		fmt.Sprintf("%s is the copy taken before the swap, naming %s", best.Name, best.Ref)
}

func (s *State) rollbackTargetOrigin(version string) (string, bool, string) {
	if version == "" {
		return string(OriginUnknown), false, "no version to look for"
	}
	if ok, ref, detail := s.ImageLocalRef(version); ok {
		if ref != "" {
			return string(OriginOf(ref)), true, fmt.Sprintf("%s is on this host as %s", version, ref)
		}
		return string(OriginUnknown), true, fmt.Sprintf("%s is on this host but the wrapper named no reference for it (%s)", version, detail)
	}
	rows, err := s.ComposeBackups()
	if err != nil {
		return string(OriginUnknown), false, fmt.Sprintf("%s is not on this host, and its deployment copies could not be read: %v", version, err)
	}
	// Newest first: the most recent copy naming this version is the one
	// that describes how the node last ran it.
	var best ComposeBackup
	for _, r := range rows {
		if r.Tag != version || r.Ref == "" {
			continue
		}
		if best.Ref == "" || r.At.After(best.At) {
			best = r
		}
	}
	if best.Ref == "" {
		return string(OriginUnknown), false, fmt.Sprintf("%s is not on this host and no deployment copy names it, so where its image came from could not be read", version)
	}
	return string(OriginOf(best.Ref)), false, fmt.Sprintf("%s is not on this host; %s names it as %s", version, best.Name, best.Ref)
}

// ImageLocal reports whether the image for this version is already on this
// host — ADR 0019.
//
// Through the wrapper's `image-digest` verb, which is documented as "what a
// LOCAL image resolves to, without pulling". No network call, so it still
// answers when the registry does not, which is the case a rollback has to
// survive: the target is the image this node was running until the upgrade,
// and the moment it is wanted is an incident.
//
// A wrapper that is not configured answers "not determined here" rather than
// "no". Absent is not zero: the caller falls back to the registry, and
// reporting an unmeasured local image as absent would send it there on a host
// where the answer was available.
func (s *State) ImageLocal(version string) (bool, string) {
	if version == "" {
		return false, "no version to look for"
	}
	if s.Wrapper == "" {
		return false, "no privilege wrapper is configured, so this host's own images were not listed"
	}
	name := s.Wrapper
	rest := []string{"image-digest", version}
	out, err := s.Runner.Run(s.context(), name, rest...)
	if err != nil {
		// docker image inspect exits non-zero for an image that is not here,
		// which is the ordinary negative answer rather than a fault.
		return false, fmt.Sprintf("%s is not on this host: %v", version, err)
	}
	d := strings.TrimSpace(string(out))
	if d == "" {
		return false, fmt.Sprintf("%s is not on this host", version)
	}
	return true, fmt.Sprintf("%s is already on this host (%s)", version, d)
}

// ImageLocalRef is ImageLocal plus the reference that answered.
//
// The wrapper's image-digest prints the reference it resolved beside the
// digest, and which one it is decides the caller's next move: a locally
// built image is swapped in with set-image-local and never pulled, a
// registry one with set-image. Reading it off the host is the same
// "recompute, never assume" rule the rest of this package follows; the
// configured repository is a record of what the node ran when the wrapper
// was configured, and an upgrade through a local build makes that one swap
// out of date.
func (s *State) ImageLocalRef(version string) (bool, string, string) {
	ok, detail := s.ImageLocal(version)
	if !ok {
		return false, "", detail
	}
	// "<reference> <digest>" since #664; a wrapper that predates it prints
	// the digest alone, and an empty reference is how the caller sees that.
	for _, f := range strings.Fields(detail) {
		if strings.Contains(f, ":"+version) && !strings.Contains(f, "sha256:") {
			return true, f, detail
		}
	}
	return true, "", detail
}

// PackageKept is ImageLocal's native twin, issue #393's second half: does
// this host hold a local install artefact for this version, kept beside the
// config backups before an earlier upgrade replaced it, through the
// wrapper's package-kept verb, which lists every artefact package-keep is
// holding rather than asking about one.
//
// The wire shape is package-kept's: four tab-separated fields per row,
// version, path, sha256, status, the same contract
// scripts/test-node-wrapper-native.sh pins on the wrapper's own stdout. The
// two halves are proven separately, one against real stdout, one against a
// canned string, and this comment is what stops them drifting apart quietly.
//
// Matched the way the wrapper's own pkg_match matches a caller's version
// against a package release: equal, or equal followed by a dash, because
// RB-004's target_version is bare (rollback.Normalise strips it) and a kept
// artefact's own name carries the release dpkg or rpm actually installed
// (3.3.0-1). "3.3" must never match "3.3.1", the same anchor pkg_match's own
// comment states.
//
// A row whose sha256 no longer matches what package-keep recorded is not
// reported as kept: installing from a file this host's own read says has
// changed would be worse than finding nothing, so matching continues past
// it rather than returning it as available.
//
// No wrapper configured, or nothing held, both answer false without an
// error: "not determined here" and "asked, and there is none" are different
// facts from ImagePublished's own perspective, but PackageKept's caller only
// needs the bool, and the detail says which one it was.
func (s *State) PackageKept(version string) (bool, string) {
	if version == "" {
		return false, "no version to look for"
	}
	if s.Wrapper == "" {
		return false, "no privilege wrapper is configured, so this host's own kept packages were not listed"
	}
	name := s.Wrapper
	rest := []string{"package-kept"}
	out, err := s.Runner.Run(s.context(), name, rest...)
	if err != nil {
		return false, fmt.Sprintf("could not read this host's kept packages: %v", err)
	}
	var mismatch string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			// Includes the "no kept package artefacts in <dir>" line the
			// wrapper prints when it is holding nothing, which is a fact,
			// not a row to parse.
			continue
		}
		ver, path, status := f[0], f[1], f[3]
		if ver != version && !strings.HasPrefix(ver, version+"-") {
			continue
		}
		if status != "ok" {
			mismatch = fmt.Sprintf("%s is kept at %s, but %s", ver, path, status)
			continue
		}
		return true, fmt.Sprintf("%s is kept on this host at %s", ver, path)
	}
	if mismatch != "" {
		return false, mismatch
	}
	return false, version + " is not kept on this host"
}

// normaliseVersion trims what a version may be written with and nothing
// else. Spelled here rather than imported from rollback, which imports
// nothing from this package and must keep it that way.
func normaliseVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// RollbackDerivation is what a rollback from this host would be: the same
// derivation the card renders, computed here so both doors can bind it.
//
// running is the version this node reports now, read by the caller: both
// doors already have it, and asking for it here made this untestable on a
// fixture that has no live node.
//
// history is this node's run history, which only the service has. The copy
// the derivation names does not depend on it (that comes from the dated
// copies alone); it decides the ambiguity refusal, and a caller without one
// passes nil.
func (s *State) RollbackDerivation(running string, history []rollback.Completion) rollback.Derivation {
	if running == "" {
		return rollback.Derivation{Refusal: rollback.RefusedNoTarget,
			Detail: "the running version could not be read, so no rollback target can be derived"}
	}
	rows, berr := s.ComposeBackups()
	if berr != nil {
		return rollback.Derivation{Running: running, Refusal: rollback.RefusedNoTarget,
			Detail: "the deployment's dated copies could not be read: " + berr.Error()}
	}
	return rollback.Derive(running, DerivationBackups(rows), history)
}

// RollbackRestoreCopy names the dated copy a rollback would put back and the
// digest that copy pins its image to.
//
// It is THE DERIVATION'S OWN CHOICE, not a second rule that usually agrees
// with it (#682, second review). A second rule is how the card came to show
// one file while the run restored another: they agreed on the histories
// anyone had tested and disagreed on the one prod is about to have, where a
// local 3.4.1 copy and an official 3.4.1 copy both name the target.
//
// Empty when the derivation refuses or names nothing. The caller refuses; it
// does not fall back to some other file.
func (s *State) RollbackRestoreCopy(running string, history []rollback.Completion) (name, digest, origin string) {
	d := s.RollbackDerivation(running, history)
	if d.Refusal != "" || d.BackupName == "" {
		return "", "", ""
	}
	return s.copyFacts(filepath.Base(d.BackupName))
}

// PlannedRestoreCopy is the dated copy a rollback plan binds, and the digest
// that copy pins: the running version read from the node, this node's run
// history read from its own ledger, and the derivation's choice from both.
//
// The one call both binaries make (#1029). The service and the command line
// used to bind the copy separately, the service through a cache that lapsed
// in seconds and the command line with no history at all, and a rollback was
// approved under one fingerprint and evaluated under another. A plan id is
// computed from the bound parameters, so the copy has to be read the same way
// at every door or the doors mint different plans.
//
// One reading of each fact: the running version and the dated copies are
// read once, and the copy's digest comes off the same rows the derivation
// chose it from. A read that fails is an error, never an empty copy: an empty
// copy is a different plan, and a reading that failed is not the node's
// answer changing (#1029, review). Empty with no error when the derivation
// names no copy, and on a native host, which has no deployment file to copy.
func (s *State) PlannedRestoreCopy() (name, digest string, err error) {
	if s.Kind() == "native" {
		return "", "", nil
	}
	running, err := s.RunningVersion()
	if err != nil {
		return "", "", fmt.Errorf("the node did not say what version it is running: %w", err)
	}
	rows, err := s.ComposeBackups()
	if err != nil {
		return "", "", fmt.Errorf("the deployment's dated copies could not be read: %w", err)
	}
	d := rollback.Derive(running, DerivationBackups(rows), VersionHistory(s.LedgerPath))
	name, digest = RestoreCopyOf(d, rows)
	return name, digest, nil
}

// DerivationBackups is the dated copies in the shape the derivation reads,
// each with where its image came from, read off the reference the copy itself
// names, never off a configured repository (#682).
func DerivationBackups(rows []ComposeBackup) []rollback.Backup {
	bs := make([]rollback.Backup, 0, len(rows))
	for _, r := range rows {
		bs = append(bs, rollback.Backup{
			Origin: r.Origin, Tag: r.Tag, Name: r.Name, At: r.At,
			ImageOrigin: string(OriginOf(r.Ref)),
		})
	}
	return bs
}

// RestoreCopyOf is the copy a derivation names and the digest it pins, read
// off the same rows the derivation was taken from, so the two cannot come
// from different readings of the host. Empty when the derivation refuses or
// names no copy.
func RestoreCopyOf(d rollback.Derivation, rows []ComposeBackup) (name, digest string) {
	if d.Refusal != "" || d.BackupName == "" {
		return "", ""
	}
	name, digest, _ = copyFactsIn(rows, filepath.Base(d.BackupName))
	return name, digest
}

// VersionHistory is every version a run on this node has COMPLETED on, read
// from its own ledger.
//
// Both terminal kinds count. An upgrade slower than the fifteen-minute
// confirmation window writes run.unconfirmed and then run.confirmed_late, and
// never a run.completed at all; a reading that counted only the first kind
// would skip that release entirely and derive a target one version too far
// back. A run.unconfirmed standing alone is deliberately NOT counted: it
// records that the node never confirmed, which is the opposite of evidence
// that it ran.
//
// A ledger that cannot be read, or no ledger path at all, yields nothing
// rather than an error. The derivation treats an absent history as
// uncorroborated and says so, which is the honest answer for a host whose
// Advisor is newer than its last upgrade.
func VersionHistory(ledgerPath string) []rollback.Completion {
	if ledgerPath == "" {
		return nil
	}
	entries, err := ledger.Entries(ledgerPath)
	if err != nil && len(entries) == 0 {
		return nil
	}
	var out []rollback.Completion
	entries, dropped := ledger.WithCarried(entries)
	for _, d := range dropped {
		log.Printf("[ledger] %s", d)
	}
	for _, e := range entries {
		if e.Kind != ledger.KindRunCompleted && e.Kind != ledger.KindRunConfirmedLate {
			continue
		}
		v, _ := e.Data["version"].(string)
		if strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, rollback.Completion{Version: v, At: e.At})
	}
	return out
}

// copyFacts reads what one dated copy NAMES: the digest it pins and where
// that image came from. Both off the copy, never off what happens to be on
// the host: a node with a local 3.4.1 and an official 3.4.1 both present
// answers "local-build" to the host reading while the copy pins the
// official digest, and the run then skips the check the official image
// needs (#682, second review).
func (s *State) copyFacts(name string) (string, string, string) {
	rows, err := s.ComposeBackups()
	if err != nil {
		return "", "", ""
	}
	return copyFactsIn(rows, name)
}

func copyFactsIn(rows []ComposeBackup, name string) (string, string, string) {
	for _, r := range rows {
		if r.Origin || filepath.Base(r.Name) != name {
			continue
		}
		digest := ""
		if i := strings.LastIndex(r.Ref, "@"); i >= 0 {
			digest = r.Ref[i+1:]
		}
		return name, digest, string(OriginOf(r.Ref))
	}
	return "", "", ""
}

// RunningOrigin is where the image the container is running came from, read
// off the profile, which is discovered from that container's own inspect
// (and at most profileReadTTL old in advisord). Not the deployment file: a
// build's prepare points the file at the build an approval and a restart
// before the container runs it (#664). Unknown on a native host, and when
// the profile names no image.
func (s *State) RunningOrigin() ImageOrigin {
	if s.Kind() == "native" || s.Profile.ImageRepo == "" {
		return OriginUnknown
	}
	ref := s.Profile.ImageRepo + ":" + s.Profile.ImageTag
	if s.Profile.ImageDigest != "" {
		ref = s.Profile.ImageRepo + "@" + s.Profile.ImageDigest
	}
	return OriginOf(ref)
}
