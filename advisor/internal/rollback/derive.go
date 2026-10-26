// Package rollback derives what "last known good" means on one node — ADR
// 0019.
//
// A rollback target is never guessed and never taken from a model. It is
// derived twice, from two things this node produced itself, and the two must
// agree:
//
//   - the dated copies of the deployment file, each of which was taken before
//     a version change and names the tag that was running then;
//   - the node's own run history, which is the sequence of versions runs on
//     this node have completed on.
//
// The package is pure: no host, no ledger, no clock. Everything it needs
// arrives as values, so the rule that decides which version a validator would
// be put back on can be exercised as a table rather than as a deployment.
package rollback

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Backup is one deployment file: the live one, or a dated copy beside it.
type Backup struct {
	// Origin marks the live deployment file. It is skipped by the
	// derivation — it names what is running now, which is what a rollback
	// is moving away from — and it is carried anyway so the rule that skips
	// it is here, in one testable place, rather than in a caller's filter.
	Origin bool
	Tag    string
	// ImageOrigin is WHERE that copy's image came from: "local-build",
	// "official", "third-party" or "" when it could not be read (#682). A
	// release can be reached from two sources now, so a copy is identified
	// by the pair and not by the tag alone: after a source switch every
	// dated copy names the same release, and a derivation reading tags
	// alone finds nothing to roll back to on exactly the node that just
	// changed something.
	ImageOrigin string
	// Name is the file's base name, as the wrapper reports it.
	Name string
	At   time.Time
}

// Completion is one run this node finished, and the version it finished on.
// Both `run.completed` and `run.confirmed_late` are completions: an upgrade
// that took longer than the confirmation window writes the second one, and a
// reading that counted only the first would skip that release entirely and
// derive a target one version too far back.
type Completion struct {
	Version string
	At      time.Time
}

// The store verdicts. Three, not two, for the reason ConfigReadable has
// three: "I did not look" must never render as "I looked and it was fine".
const (
	// StoreWritten: this node's run history shows the running build arrived
	// by a completed version change, so it has been writing the data store
	// since. RB-001's reversal note applies.
	StoreWritten = "written"
	// StoreUnknown: nothing in the run history says how the running build
	// got here. The risk is not measured, which is not the same as absent.
	StoreUnknown = "unknown"
	// StoreUnwritten: nothing produces this in v1. It exists so a later
	// determination — a store snapshot, a format check — has somewhere to
	// land rather than being squeezed into "unknown".
	StoreUnwritten = "unwritten"
)

// The two refusals this derivation can reach. Both are named rather than
// returned as a bare error because the page renders one remedy per reason.
const (
	// RefusedNoTarget: no dated deployment copy names another version, so
	// there is nothing to derive a target from.
	RefusedNoTarget = "no_rollback_target"
	// RefusedAmbiguous: the backups and the run history name different
	// versions. Refused rather than resolved: picking one would be this
	// service deciding which of its own two records to believe, at the
	// moment a validator's version is about to change.
	RefusedAmbiguous = "ambiguous_target"
)

// Derivation is the whole answer, including the parts that say what could not
// be determined.
type Derivation struct {
	// Running is the version the node reports, normalised.
	Running string
	// Target is the version a rollback would put back. Empty when Refusal
	// is set.
	Target string
	// BackupName and BackupAt are the dated copy the target was READ FROM.
	//
	// Not "the file that would be restored": the rollback edits the image
	// line and leaves the rest of the deployment alone, so this file is the
	// evidence for the version and the thing an operator restores by hand
	// when the deployment itself needs reverting.
	BackupName string
	BackupAt   time.Time
	// FromHistory is what the run history derived, empty when it could not
	// derive anything. Kept beside Target even when they agree, so the
	// assessment can say the two agreed rather than implying it.
	FromHistory string
	// ChangedAt is when the running build's arrival completed, zero when the
	// history does not show it. It is what "up since the upgrade" is measured
	// from, and it is not the node's uptime: a node restarted twice since an
	// upgrade has a short uptime and an old version change.
	ChangedAt time.Time
	// Store is one of the three verdicts above, with the sentence that
	// explains it.
	Store       string
	StoreDetail string
	// SourceRollback marks the one case where Target equals Running: the
	// release does not move and the SOURCE of its image does (#682). The
	// whole dated copy is restored rather than the image line rewritten,
	// because the swap that made it also wrote the arguments and the
	// mounts, and undoing half of that is worse than undoing none.
	SourceRollback bool
	// Refusal is empty when a target was derived. Otherwise it is one of the
	// two constants above, and Detail is the sentence the operator reads.
	Refusal string
	Detail  string
	// Note is what could not be corroborated on a derivation that still
	// succeeded — the honest "one of the two sources was silent".
	Note string
}

// Normalise strips a leading "v" and surrounding space. Exported because the
// caller compares a model's proposed target against Derivation.Target and
// must do it the same way.
func Normalise(v string) string {
	v = strings.TrimSpace(v)
	return strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
}

// Derive is the whole rule.
func Derive(running string, backups []Backup, history []Completion) Derivation {
	run := Normalise(running)
	d := Derivation{Running: run, Store: StoreUnknown}

	seq := VersionSequence(history)
	d.FromHistory, d.ChangedAt = historyTarget(seq, run)
	d.Store, d.StoreDetail = storeVerdict(seq, run)

	tag, name, at, found := backupTarget(backups, run)
	// A copy that names another SOURCE for this release is a rollback target
	// too: the version does not move, the whole copy goes back, and with it
	// the arguments and the mounts that swap wrote (#682).
	//
	// Which of the two wins is decided by DATE, not by kind. A rollback
	// undoes the last change this node made, and on a node whose last change
	// was a source swap the older release is not what "roll back" means:
	// offering it would take a node two releases back to undo a swap that
	// moved no release at all. Observed on the lab node, 2026-09-28, where
	// the Advisor offered 3.4.1 to 3.3.0 after a same-release source switch.
	sname, sat, sorigin, sfound := sourceBackupTarget(backups, run, liveOrigin(backups))
	if sfound && found && sat.After(at) {
		found = false
	}
	if !found {
		if !sfound {
			d.Refusal = RefusedNoTarget
			d.Detail = "no dated copy of the deployment file names a version other than " + run +
				", or the same version from another source, so there is nothing to roll back to " +
				"that this node has a record of"
			return d
		}
		d.Target, d.BackupName, d.BackupAt = run, sname, sat
		d.SourceRollback = true
		// Two facts the version case computes are not facts here, and both
		// rendered as confident sentences over a change that moves no
		// release (lab node, 2026-09-28):
		//
		//   "this node's own run history agrees: it was on 3.3.0 before"
		//     — it agrees about nothing. The release this goes back to is
		//       the one running, and the dated copy is the only record of
		//       the change being undone.
		//   "the newer build has been writing this node's data store"
		//     — there is no newer build. The binary does not change, so
		//       the store-format risk RB-001 warns about cannot arise.
		//
		// Both are cleared here rather than special-cased in the page: the
		// page renders what the service publishes and derives none of it.
		d.FromHistory = ""
		d.Store = StoreUnwritten
		d.StoreDetail = "the release does not move, so the same build keeps reading and writing " +
			"this node's data store and there is no store-format risk to weigh"

		// The swap being undone is the one TO the live origin, and the
		// copy is what the node is going back to. The sentence used to
		// name the copy's origin as the swap's destination, which read
		// backwards in both directions (#985).
		live := liveOrigin(backups)
		d.Note = "this changes where " + run + "'s image comes from, not which release runs: " +
			"from " + live + " back to " + sorigin + ", the deployment as it stood before the swap to " +
			live + ", which puts its arguments and its mounts back with it"
		return d
	}
	d.BackupName, d.BackupAt = name, at

	if d.FromHistory != "" && d.FromHistory != tag {
		d.Refusal = RefusedAmbiguous
		d.Detail = fmt.Sprintf(
			"the deployment backups say this node was running %s before %s, and its own run "+
				"history says %s. Two records of the same fact disagree, so no target is derived "+
				"and the rollback is refused rather than guessed", tag, run, d.FromHistory)
		return d
	}

	d.Target = tag
	if d.FromHistory == "" {
		d.Note = "the run history does not record a version change on this node, so the target " +
			"comes from the deployment backup alone and is not corroborated"
	}
	return d
}

// PackageChange is one completed package-install this node ran, from what
// the package database said before it to what it said after, the wrapper's
// own "before -> after" line, read back from the ledger entry that install's
// step wrote at the time.
//
// This is the artefact DeriveNative reads first, and the reason is precision:
// it is not a version this service INFERS the node passed through by
// collapsing a sequence of runs, it is the version that specific install
// recorded overwriting, at the moment it did. One install is enough to
// produce one of these, where a sequence needs two runs on two different
// versions before it can name anything at all.
type PackageChange struct {
	From string
	To   string
	At   time.Time
}

// DeriveNative is Derive's native twin, issue #393.
//
// Derive requires two things this node produced itself to agree: the dated
// deployment-file copies and the run history. A native host has no
// deployment file, so it has no dated copy of one, and the compose-backup
// half of that agreement cannot exist here, not "is empty", a different
// thing, and this function does not paper over the difference by treating an
// empty backup list the way Derive already does (Derive's own tests pin that
// history alone never authorises, which is the container rule, not this
// one).
//
// What plays the deployment backup's role instead is PackageChange: the
// version each completed package-install recorded replacing. It is preferred
// over the run-history sequence (FromHistory, VersionSequence's own reading)
// for the reason a first rollback matters most, a node that has completed
// exactly ONE Advisor-driven upgrade has exactly one entry in its run
// history, on the version it is running now, and a sequence needs a SECOND,
// earlier entry before historyTarget can name anything: it would refuse the
// rollback an operator asks for immediately after the upgrade that prompted
// it, which is the ordinary case, not an edge one. One completed
// package-install already names what it replaced, with no second run
// required.
//
// The two sources still cross-check each other when both exist, the same
// agreement Derive itself requires, just built from a different pair of
// artefacts: a package-install record and a history sequence that disagree
// is refused rather than resolved, and either one standing alone still
// derives, with a Note saying it was not corroborated.
func DeriveNative(running string, changes []PackageChange, history []Completion) Derivation {
	run := Normalise(running)
	d := Derivation{Running: run, Store: StoreUnknown}

	seq := VersionSequence(history)
	d.FromHistory, d.ChangedAt = historyTarget(seq, run)
	d.Store, d.StoreDetail = storeVerdict(seq, run)

	from, changedAt, found := packageChangeTarget(changes, run)
	switch {
	case !found && d.FromHistory == "":
		d.Refusal = RefusedNoTarget
		d.Detail = "no completed package install on this node names a version other than " + run +
			", and its run history records no version change either, so there is nothing to " +
			"roll back to that this node has a record of"
		return d
	case !found:
		// The install record is silent, this Advisor was installed after
		// its last upgrade, or an operator changed the package by hand, but
		// the run history still names one. The same shape Derive's own
		// "backups alone" case takes, the source swapped.
		d.Target = d.FromHistory
		d.Note = "no completed package install on this node names the version before " + run +
			"; the target comes from this node's own run history alone"
		return d
	case d.FromHistory != "" && d.FromHistory != from:
		d.Refusal = RefusedAmbiguous
		d.Detail = fmt.Sprintf(
			"the package install that put this node on %s recorded %s as what it replaced, and "+
				"this node's own run history says %s. Two records of the same fact disagree, so no "+
				"target is derived and the rollback is refused rather than guessed", run, from, d.FromHistory)
		return d
	}

	d.Target = from
	d.ChangedAt = changedAt
	if d.FromHistory == "" {
		d.Note = "this node's run history does not corroborate this; the target comes from the " +
			"package install's own before-and-after record alone"
	}
	return d
}

// packageChangeTarget is the most recent completed package-install that
// ended on `running`, and the version it recorded replacing.
//
// Newest first, the same reasoning backupTarget applies to a compose file's
// dated copies: more than one install can end on the same version (a retry
// after a verification the operator overrode, say), and only the last one
// describes what actually put the node where it is now.
//
// "not installed" is the wrapper's own word for a package database with
// nothing in it yet, this host's first-ever install, not a version change,
// and is excluded by name rather than read as a version nobody chose.
func packageChangeTarget(changes []PackageChange, running string) (from string, at time.Time, found bool) {
	rows := make([]PackageChange, 0, len(changes))
	for _, c := range changes {
		to := Normalise(c.To)
		from := Normalise(c.From)
		if to != running || from == "" || from == to || strings.EqualFold(from, "not installed") {
			continue
		}
		rows = append(rows, PackageChange{From: from, To: to, At: c.At})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
	if len(rows) == 0 {
		return "", time.Time{}, false
	}
	return rows[0].From, rows[0].At, true
}

// backupTarget is the tag of the newest dated copy that names a version other
// than what is running.
//
// Newest first, because each copy was taken before a version change: the most
// recent one is the deployment as it stood immediately before the change that
// produced what is running now. "Other than what is running" is what makes a
// rollback that has already happened roll FORWARD — this run takes its own
// copy before it edits, so the newest copy then names the version it came
// from.
// liveOrigin is where the deployment file names its image from right now,
// read off the copy the wrapper marks as the live one.
func liveOrigin(backups []Backup) string {
	for _, b := range backups {
		if b.Origin {
			return b.ImageOrigin
		}
	}
	return ""
}

// sourceBackupTarget is backupTarget's sibling for a source switch: the
// newest dated copy naming the SAME release from a DIFFERENT source than the
// deployment names now. Returns the copy, and the origin it would go back to.
func sourceBackupTarget(backups []Backup, running, live string) (name string, at time.Time, origin string, found bool) {
	if live == "" || running == "" {
		return "", time.Time{}, "", false
	}
	rows := make([]Backup, 0, len(backups))
	for _, b := range backups {
		if b.Origin || Normalise(b.Tag) != running || b.ImageOrigin == "" || b.ImageOrigin == live {
			continue
		}
		rows = append(rows, b)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
	if len(rows) == 0 {
		return "", time.Time{}, "", false
	}
	return rows[0].Name, rows[0].At, rows[0].ImageOrigin, true
}

func backupTarget(backups []Backup, running string) (tag, name string, at time.Time, found bool) {
	rows := make([]Backup, 0, len(backups))
	for _, b := range backups {
		if b.Origin || Normalise(b.Tag) == "" {
			continue
		}
		rows = append(rows, b)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
	for _, b := range rows {
		if t := Normalise(b.Tag); t != running {
			return t, b.Name, b.At, true
		}
	}
	return "", "", time.Time{}, false
}

// Step is one entry in the version sequence: a version, and when this node
// first completed a run on it.
type Step struct {
	Version string
	At      time.Time
}

// VersionSequence collapses the run history into the versions this node has
// been on, in order, with consecutive repeats removed.
//
// Repeats are removed because most completions are not version changes: a
// restart completes on the version it was already running, and a node
// restarted five times would otherwise look like five changes. What is left
// is the shape this derivation reads — where the node has been.
//
// Exported so the assessment can render it and a test can pin it directly.
func VersionSequence(history []Completion) []Step {
	sorted := make([]Completion, 0, len(history))
	for _, c := range history {
		if Normalise(c.Version) == "" {
			continue
		}
		sorted = append(sorted, c)
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })

	var out []Step
	for _, c := range sorted {
		v := Normalise(c.Version)
		if len(out) > 0 && out[len(out)-1].Version == v {
			continue
		}
		out = append(out, Step{Version: v, At: c.At})
	}
	return out
}

// Versions is the sequence as bare strings, for rendering.
func Versions(seq []Step) []string {
	out := make([]string, 0, len(seq))
	for _, s := range seq {
		out = append(out, s.Version)
	}
	return out
}

// historyTarget is the last version in the sequence that differs from what is
// running, and when the running one arrived.
func historyTarget(seq []Step, running string) (target string, changedAt time.Time) {
	// Scanning backwards: skip the running version, recording when it
	// arrived, and stop at the first version that is not it. A history whose
	// last entry is some OTHER version — a build that arrived by hand, with
	// no run of ours behind it — returns that entry with no arrival time,
	// which is honest: this service did not put the node where it is.
	for i := len(seq) - 1; i >= 0; i-- {
		if seq[i].Version == running {
			changedAt = seq[i].At
			continue
		}
		return seq[i].Version, changedAt
	}
	return "", changedAt
}

// storeVerdict answers whether the running build has been writing this node's
// data store since it arrived.
func storeVerdict(seq []Step, running string) (verdict, detail string) {
	if len(seq) == 0 {
		return StoreUnknown, "this node's run history records no completed run, so how the " +
			"build it is running got here is not known here"
	}
	last := seq[len(seq)-1]
	if last.Version != running {
		return StoreUnknown, fmt.Sprintf(
			"the last run this node completed was on %s and it is running %s, so the running "+
				"build did not arrive by a run this service recorded", last.Version, running)
	}
	if len(seq) < 2 {
		return StoreUnknown, "this node's run history shows no version change, so whether the " +
			"running build wrote a store an older one cannot read is not known here"
	}
	return StoreWritten, fmt.Sprintf(
		"this node completed a change from %s to %s on %s, and has been writing its data store "+
			"as %s ever since", seq[len(seq)-2].Version, running,
		last.At.UTC().Format("2006-01-02"), running)
}
