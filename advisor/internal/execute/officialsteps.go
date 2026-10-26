package execute

import (
	"aperire-advisor/internal/host"
	"encoding/json"
	"fmt"
	"strings"

	"aperire-advisor/internal/runbook"
)

// RB-001 on a container host taking the official image, ADR 0023.
//
// The ruling (#682, 2026-09-27): the official rippleci/xrpld image is the
// FIRST source for a container node. A build from the signed package is
// what gets offered when no tag carries the release and the operator
// approves, or when the operator asks for a build.
//
// The shape is the local build path's, with the build replaced by a pull
// and three checks added in front of the swap. Everything that path already
// proves still holds: backups first, the slow and failure-prone part done
// while the node is still validating, one line changed, one step that
// interrupts.
//
// Four things are different, and each of them is a ruling:
//
//  1. The pull is BY DIGEST, and the digest came from the reading the
//     operator approved. Resolving a tag at cutover time is exactly the
//     substitution the pin exists to prevent.
//  2. Nothing is verified by version. Every host this project has upgraded
//     carries localhost/xrpld:<version>, so asking about "3.4.1" on one of
//     them answers about the image it built, and four checks would pass
//     against bytes nobody pulled. The digest is the reference.
//  3. The cutover's proof does not read the entrypoint's log line. The
//     official image has no entrypoint script and prints none, and its own
//     default arguments include --silent, which would blank the stream
//     even if it did. The proof is static (the container's own Args and
//     mounts) and then from server_info.
//  4. A recreate that fails restores the deployment copy and recreates
//     again, rather than leaving a node down on a file nobody approved.
func OfficialImageUpgradeSteps(target, digest string) []Step {
	ref := OfficialImageRepo + "@" + digest
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
			Why: "the file as it stands, before the image line and nothing else changes. It is " +
				"also what a failed recreate is restored from, without anyone being asked",
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
			Name: "pull the official image, pinned to the digest you approved", Stage: StagePrepare,
			Verb: "pull-official", Arg: target, Arg2: digest,
			Why: "the slow part, done while the node is still validating. By digest rather than " +
				"by tag, so a tag moved between the approval and now cannot change what lands",
			Undo: "docker image rm " + ref + ", if nothing else uses it",
			Verify: func(out string, st runbook.HostState) error {
				if !strings.Contains(out, digest) {
					return fmt.Errorf("the pull did not report the digest it was given: %q", lastLine(out))
				}
				if ok, d := st.ConsensusHealthy(); !ok {
					return fmt.Errorf("the node stopped looking healthy during a pull: %s", d)
				}
				return nil
			},
		},
		{
			Name: "check this image against the signed package, on this host", Stage: StagePrepare,
			Verb: "verify-official-image", Arg: target, Arg2: digest,
			Why: "the check the whole swap turns on, and the one that must not be delegated to " +
				"the thing being checked. Root creates a container from the pinned digest and " +
				"never starts it, streams /usr/bin/xrpld out with docker cp, and hashes it HERE " +
				"against the binary in the .deb apt just verified. It also refuses an image that " +
				"loads code before the node's own, and compares every file the package owns. " +
				"Nothing of that image runs at any point",
			Undo: "none needed, this reads and starts nothing",
			// THE gate. Every check has to be measured and equal; an
			// unmeasured one is never a pass (#679). Before the review of
			// 2026-09-27 this step list only checked that a
			// `binary_sha256=` line appeared, and the hash on it came from
			// the image's own sha256sum: a prepare with the wrong commit,
			// the wrong hash and no runtime user completed with no error,
			// and a compound grant chains straight into the cutover.
			Verify: func(out string, _ runbook.HostState) error {
				v := host.ParseVerifyOfficial(out)
				if !v.Read {
					return fmt.Errorf("the verify answered nothing this side recognises: %q", lastLine(out))
				}
				ok, checks := v.Checks(target, digest)
				if !ok {
					return fmt.Errorf("this image is not what it claims to be, so nothing was "+
						"swapped: %s", host.FailedChecks(checks))
				}
				return nil
			},
		},
		{
			Name: "record what the pull resolves to", Stage: StagePrepare,
			Verb: "image-digest", Arg: target, Arg2: digest,
			Why: "the pin the cutover re-reads. Between this stage and the operator's approval " +
				"of the next one, this is the reading that would show a substitution",
			Undo: "none needed, this reads",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, digest) {
					return fmt.Errorf("the image on this host resolves to %q, not %s", lastLine(out), digest)
				}
				return nil
			},
		},
		{
			Name: "point the deployment at it", Stage: StageCutover,
			Verb: "set-image-official", Arg: target, Arg2: digest,
			Why: "one line: the digest as the reference, the version in the comment beside it. " +
				"Mounts, ports and restart policy stay exactly as they are",
			Undo: "restore the dated copy taken in step 2",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "->") || !strings.Contains(out, digest) {
					return fmt.Errorf("wrapper did not confirm the edit: %q", out)
				}
				return nil
			},
		},
		{
			Name: "recreate the node on the official image", Stage: StageCutover, Verb: "recreate",
			Why: "the only step that interrupts validation. The old container's stop comes first " +
				"and may take the whole stop grace, so nothing times this from the command",
			Interrupts:       true,
			RestoreOnFailure: true,
			Undo:             "restore the copy taken in step 2 and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, "running") {
					return fmt.Errorf("container is not running after recreate: %q", out)
				}
				return nil
			},
		},
		{
			Name: "confirm the container came up on the image that was verified", Stage: StageCutover,
			Verb: "running-digest",
			Why: "what the container is actually running, compared with what was pinned, rather " +
				"than assumed from the reference it names",
			// A node that came back on something other than the digest that
			// was verified is a node running an image nobody checked, and
			// the deployment is already pointing at it. The copy taken
			// before the swap goes back without anybody being asked (#682,
			// review of 2026-09-27).
			RestoreOnFailure: true,
			Undo:             "restore the copy taken in step 2 and recreate again",
			Verify: func(out string, _ runbook.HostState) error {
				if !strings.Contains(out, digest) {
					return fmt.Errorf("the container is running %q, not the pinned %s",
						strings.TrimSpace(out), digest)
				}
				return nil
			},
		},
		{
			Name:             "confirm the node runs the arguments and the config the deployment names",
			RestoreOnFailure: true,
			Stage:            StageCutover, Verb: "inspect",
			Why: "static, from the new container itself, before anything is asked of the node. " +
				"The official image has no entrypoint script, so there is no log line saying the " +
				"config arrived, and its own default arguments carry --silent, which would blank " +
				"the stream anyway. A container that would boot on the package's stock config " +
				"fails this before it has a chance to look healthy, which is minutes before a " +
				"health window would have noticed",
			Undo:   "restore the copy taken in step 2 and recreate again",
			Verify: verifyNewContainer,
		},
		// There is no "ask the node who it is" step here, and that is
		// deliberate rather than missing. The node is not answering yet:
		// the recreate has just returned, xrpld is opening its store, and
		// a server_info a second later gets nothing back. Every path in
		// this project already checks the build, the keys and the
		// amendment state where it can be checked, in AwaitHealthy, which
		// polls until the node reports the target and is back in
		// consensus and only then compares it against the snapshot taken
		// before anything changed. A step here would fail on every real
		// run and pass in every test that stubbed the node.
	}
}

// containerNow is the part of `docker inspect` this reads. Parsed rather
// than searched: the whole object carries labels, an environment and an
// image reference, and a Contains("--silent") over all of it would fire on
// any of them.
type containerNow struct {
	Path   string   `json:"Path"`
	Args   []string `json:"Args"`
	Config struct {
		Cmd        []string `json:"Cmd"`
		Entrypoint []string `json:"Entrypoint"`
	} `json:"Config"`
	Mounts []struct {
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// verifyNewContainer is the cutover's static proof.
func verifyNewContainer(out string, _ runbook.HostState) error {
	// docker inspect prints a one-element array.
	var many []containerNow
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &many); err != nil || len(many) == 0 {
		var one containerNow
		if err2 := json.Unmarshal([]byte(strings.TrimSpace(out)), &one); err2 != nil {
			return fmt.Errorf("the new container could not be read: %v", err)
		}
		many = []containerNow{one}
	}
	c := many[0]
	mounted := false
	for _, m := range c.Mounts {
		if m.Destination == EtcConfigPath {
			mounted = true
		}
	}
	if !mounted {
		return fmt.Errorf("the new container has no %s mounted, so it would run on the package's "+
			"own config: someone else's settings and no validator key", EtcConfigPath)
	}
	args := append(append(append([]string{c.Path}, c.Args...),
		c.Config.Entrypoint...), c.Config.Cmd...)
	for _, a := range args {
		if a == "--silent" {
			return fmt.Errorf("the new container runs with --silent (%s), which blanks docker logs; "+
				"the rotation guard and the can-delete timer both read that stream",
				strings.TrimSpace(strings.Join(args, " ")))
		}
	}
	return nil
}

// EtcConfigPath is where xrpld reads its configuration inside every image
// this project deals with. Spelled here as well as in host for the reason
// the image repositories are: this package reads wrapper output and does
// not import host. A test holds the two equal.
const EtcConfigPath = "/etc/xrpld/xrpld.cfg"

// supersededNote reads a verify-official-image answer for the one line the
// run writes when the image carries a package revision that is not the
// newest signed one (#1001). Here, beside the steps that read the same
// answer, so the executor itself names no host type.
func supersededNote(out string) string {
	return host.ParseVerifyOfficial(out).SupersededNote()
}
