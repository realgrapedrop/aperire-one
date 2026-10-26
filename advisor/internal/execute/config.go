package execute

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"aperire-advisor/internal/runbook"
)

// RB-003's steps — ADR 0018.
//
// Four calls, and three of them are checks. That ratio is the design: the
// wrapper's set-config already takes its own dated copy, enforces the
// allow-list and the band, rewrites every assignment and refuses a rewrite
// that touched anything else. What this adds is evidence that all of that
// happened, recorded where an operator reads it.
//
// The one thing here that is not verification is the explicit backup-config
// call. It is deliberately redundant with the copy set-config takes: the
// backup verb prints the path it wrote, which is what puts a named,
// restorable file into the run log BEFORE the edit runs. Two dated copies
// exist afterwards, both from before the change, and the run log says so
// rather than leaving an operator to wonder which one is which.

// ConfigSteps is RB-003's edit expressed as wrapper calls. The restart is
// RB-002's own step, appended by the caller, unchanged.
//
// expectLines is how many assignments of this key the service found when it
// computed the diff the operator approved. The wrapper reports how many it
// rewrote, and the two must agree: the diff promised the operator a specific
// set of lines, and a rewrite that touched a different number of them has
// changed something they did not read. The wrapper's own check is that it
// touched no MORE than the key's lines; this is the independent one, and it
// is the check that ties the file back to the page.
func ConfigSteps(key, value string, expectLines int) []Step {
	return []Step{
		{
			Name: "back up the node config", Stage: StageConfig, Verb: "backup-config",
			Why: "a named, dated copy in the record before anything is written — the edit takes " +
				"its own as well, and both are from before the change",
			Undo: "none needed — this only adds a file",
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
			Name: "change " + key + " to " + value, Stage: StageConfig,
			Verb: "set-config", Arg: key + "=" + value,
			Why: "one allow-listed setting, matched against its safe band on the privileged side, " +
				"with every assignment of it rewritten and the file's owner, group and mode proven " +
				"unchanged",
			Undo: "restore the dated backup this step named, then restart",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "set "+key+"="+value) {
					return fmt.Errorf("the wrapper did not confirm the edit: %q", out)
				}
				if !strings.Contains(out, "backup: ") {
					return fmt.Errorf("the wrapper reported no backup for the edit: %q", out)
				}
				// The ownership check the wrapper performs, read back here so
				// its absence is a failure rather than a silence. A wrapper
				// that stopped verifying would otherwise look identical.
				if !strings.Contains(out, "(unchanged)") {
					return fmt.Errorf("the wrapper did not confirm the file's owner and mode "+
						"survived the rewrite: %q", out)
				}
				n, ok := LinesChanged(out)
				if !ok {
					return fmt.Errorf("the wrapper did not say how many lines it rewrote: %q", out)
				}
				if n != expectLines {
					return fmt.Errorf("the change shown for approval named %d %s line(s) and the "+
						"wrapper rewrote %d; the file is not what it was when the diff was computed",
						expectLines, key, n)
				}
				return nil
			},
		},
		{
			Name: "digest the config and its backups", Stage: StageConfig, Verb: "artefact-hashes",
			Arg: "node-config",
			Why: "the file's hash and every dated copy beside it, so the record says what was " +
				"changed and what it could be put back to — without this process opening any of them",
			Undo: "none needed — this reads",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "origin\t") {
					return fmt.Errorf("the digest listing does not identify the live file: %q", out)
				}
				return nil
			},
		},
		{
			Name: "confirm the container can still read the config", Stage: StageConfig,
			Verb: "config-readable",
			Why: "a config the container cannot read makes the node start on the image's defaults " +
				"without saying so; the restart that follows is what would surface it, hours later, " +
				"as a validator that quietly stopped being configured",
			Undo: "restore the dated backup this run named, then restart",
			Verify: func(out string, _ runbook.HostState) error {
				verdict, _, _ := strings.Cut(strings.TrimSpace(out), "\t")
				switch verdict {
				case runbook.ConfigReadableYes:
					return nil
				case runbook.ConfigReadableNo:
					return fmt.Errorf("the node's container cannot read the configuration this run "+
						"just wrote: %s", strings.TrimSpace(out))
				default:
					// Not proof it is wrong, and not proof it is right. The
					// run pauses and asks rather than guessing — the same
					// treatment the image-version step gets.
					return errUnconfirmed
				}
			},
		},
	}
}

var linesChangedRe = regexp.MustCompile(`(?m)^lines changed:\s*([0-9]+)\s*$`)

// LinesChanged reads the count the wrapper prints after a set-config.
//
// Exported so the same parse serves the step's verification and a test that
// pins it against the wrapper's real output — two readings of one line is how
// they end up disagreeing about what the wrapper said.
func LinesChanged(out string) (int, bool) {
	m := linesChangedRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// BackupPathFrom reads the dated copy the wrapper named. Both the backup verb
// and set-config print one; this recognises either shape, because the run log
// records both and the ledger records the second.
func BackupPathFrom(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if rest, ok := strings.CutPrefix(ln, "backup: "); ok {
			return strings.TrimSpace(rest)
		}
		if strings.HasSuffix(ln, ".bak") && strings.HasPrefix(ln, "/") {
			return ln
		}
	}
	return ""
}
