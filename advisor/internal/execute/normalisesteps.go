package execute

import (
	"fmt"
	"strings"

	"aperire-advisor/internal/runbook"
)

// RB-005's steps, ADR 0023.
//
// One change, one recreate, and a proof that the node came back as itself.
// Never two changes in one run: a node that gains an argument and a mount
// in the same recreate has two ways to fail and no way to tell them apart,
// which is state 3 of the approved #664 mockup and state 6 of #682's.
//
// The change is named by the runbook's own enum, so this function chooses
// a verb from a closed set and never builds one from a caller's string.
func NormaliseSteps(change, user string) []Step {
	// The image this node runs BEFORE the change, captured by the first
	// step and compared by the last (#682, review of 2026-09-27). This
	// change touches no image, so "a digest exists afterwards" proved
	// nothing at all: the comparison is what says the container came back
	// on the same bytes it went down on.
	var before string
	var edit Step
	switch change {
	case "runtime-user":
		edit = Step{
			Name: "write the account this node runs as", Stage: StageNormalise,
			Verb: "set-runtime-user", Arg: user,
			Why: "the image's own default applies wherever a deployment names nothing, and on this " +
				"host that number belongs to whoever holds it. Naming the account the node already " +
				"runs as keeps the behaviour it has and takes the guess out of every later swap",
			Undo: "restore the dated copy this step printed",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "user: \""+user+"\"") {
					return fmt.Errorf("the wrapper did not confirm the account: %q", lastLine(out))
				}
				return nil
			},
		}
	case "config-mount":
		edit = Step{
			Name: "mount this node's config where xrpld reads it", Stage: StageNormalise,
			Verb: "add-config-mount",
			Why: "read-only, from the path this deployment already uses. The /config pair stays: a " +
				"rollback to the current image needs it, and so does the non-root migration",
			Undo: "restore the dated copy this step printed",
			Verify: func(out string, _ runbook.HostState) error {
				if strings.Contains(out, "already mounted") {
					return nil
				}
				if !strings.Contains(out, EtcConfigPath) {
					return fmt.Errorf("the wrapper did not confirm the mount: %q", lastLine(out))
				}
				return nil
			},
		}
	case "node-args":
		edit = Step{
			Name: "write down the arguments this node runs with", Stage: StageNormalise,
			Verb: "set-node-args",
			Why: "two lines, and they are the arguments this node runs today. After them the node " +
				"starts the same way on any image, and the upgrade really is one line",
			Undo: "restore the dated copy this step printed",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "/usr/bin/xrpld") || !strings.Contains(out, EtcConfigPath) {
					return fmt.Errorf("the wrapper did not confirm the arguments: %q", lastLine(out))
				}
				if strings.Contains(out, "--silent") || strings.Contains(out, "--net") {
					return fmt.Errorf("the arguments written are not the ones this node runs: %q", lastLine(out))
				}
				return nil
			},
		}
	default:
		// Unreachable through the runbook, whose enum is closed. Here so
		// a caller that bypassed it gets a refusal rather than a plan
		// with no steps, which would read as a change that succeeded.
		return nil
	}
	return []Step{
		{
			Name: "record the image this node is running now", Stage: StageNormalise,
			Verb: "running-digest",
			Why: "the reading the last step is compared against. This change moves no image, so " +
				"what proves it came back as itself is that the digest did not move",
			Undo: "none needed, this reads",
			Verify: func(out string, _ runbook.HostState) error {
				got := strings.TrimSpace(out)
				if !strings.Contains(got, "sha256:") {
					return fmt.Errorf("the running container reports no digest, so nothing after "+
						"this change could be compared against it: %q", got)
				}
				if i := strings.Index(got, "sha256:"); i >= 0 {
					f := strings.Fields(got[i:])
					if len(f) > 0 {
						before = f[0]
					}
				}
				return nil
			},
		},
		{
			Name: "back up the deployment definition", Stage: StageNormalise, Verb: "backup-compose",
			Why: "the file as it stands. Restoring it is the whole reversal, and it is also what " +
				"a failed recreate is put back from without anyone being asked",
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
		edit,
		{
			Name: "recreate the node on the changed deployment", Stage: StageNormalise, Verb: "recreate",
			Why: "the only step that interrupts validation. Nothing about the image changes here: " +
				"this is the same build on a deployment that now says one more thing out loud",
			Interrupts:       true,
			RestoreOnFailure: true,
			Undo:             "restore the dated copy and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "running") {
					return fmt.Errorf("container is not running after recreate: %q", out)
				}
				return nil
			},
		},
		{
			Name: "confirm the container came up on the image it went down on", Stage: StageNormalise,
			Verb: "running-digest",
			Why: "this change touches no image, so the one it comes back on has to be the one it " +
				"left on. A digest that moved here would mean something else changed the deployment",
			Undo: "restore the dated copy and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				got := strings.TrimSpace(out)
				if !strings.Contains(got, "sha256:") {
					return fmt.Errorf("the running container reports no digest: %q", got)
				}
				// Against the digest recorded BEFORE the change, not merely
				// "a digest exists" (#682, review of 2026-09-27). This
				// change touches no image, so the one it comes back on has
				// to be the one it left on; a digest that moved here means
				// something else rewrote the deployment while this ran, and
				// the node is running an image nobody approved.
				if before != "" && !strings.Contains(got, before) {
					return fmt.Errorf("this change moved no image, and the node came back on %s "+
						"rather than %s. Restore the dated copy this run printed and recreate",
						got, before)
				}
				return nil
			},
		},
	}
}

// StageNormalise is RB-005's one stage.
const StageNormalise = "normalise"
