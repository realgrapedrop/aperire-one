// Package advise renders a plan as instructions for a person to run, rather
// than as operations for the executor to perform.
//
// This is the tier below every privilege option in ADR 0007. The Advisor
// diagnoses, decides, and prints; the operator runs. Nothing is granted,
// because nothing is executed — which makes it the only tier that works on
// every deployment, including a node running as root, and the honest default
// on a host where the account managing the node is already root-equivalent
// through the docker group.
//
// The failure mode this package is designed against is a wall of copy-paste
// commands with no reasoning. That trains an operator to paste without
// reading, which is worse than offering nothing. So every step carries what it
// is for, what it changes, what "good" looks like afterwards, and how to undo
// it. That is the same content the action ledger records when the executor
// performs a step itself — addressed to a person instead of to an audit trail.
package advise

import (
	"fmt"
	"path/filepath"
	"strings"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/runbook"
)

// Step is one instruction.
type Step struct {
	// Title is what this step accomplishes, in the operator's terms.
	Title string
	// Why is the reason it is in the list. A step without one does not ship.
	Why string
	// Command is what to run. Empty for a step that is a judgement rather than
	// a command — "watch this for two minutes" is a real step.
	Command string
	// Expect describes what success looks like, so the operator can tell a
	// working step from one that printed something and did nothing.
	Expect string
	// Undo returns the host to its previous state, where that is possible.
	Undo string
}

// Plan is the rendered advice for one runbook against one host.
type Plan struct {
	RunbookID string
	Summary   string
	Profile   host.Profile
	Verdicts  []runbook.Verdict
	Steps     []Step
	// Blocked is true when a precondition failed. The steps are still
	// rendered — an operator who can see what would have run is better placed
	// to fix the blocker than one who is told only that something is wrong —
	// but they are presented as blocked, not as a to-do list.
	Blocked bool
}

// Failures returns the preconditions that did not pass.
func (p Plan) Failures() []runbook.Verdict {
	var out []runbook.Verdict
	for _, v := range p.Verdicts {
		if !v.Passed {
			out = append(out, v)
		}
	}
	return out
}

// UpgradeSteps renders RB-001 for the host's own kind, a Docker Compose
// deployment, or the vendor's native package. This is what an operator reads
// in chat before approving anything, so the shape has to be named plainly:
// two kinds, two different sequences, never one description bent to cover
// both.
func UpgradeSteps(p host.Profile, target string) []Step {
	if p.Kind == "native" {
		return nativeUpgradeSteps(p, target)
	}
	return containerUpgradeSteps(p, target)
}

// containerUpgradeSteps is the shape the Field Guide's fetch-inspect-then-
// cutover pattern names, where the fetch is a build: make the new image
// while the node keeps running, confirm it is what you think it is, and only
// then take the short outage to swap. Backups come first because RB-002 is
// not a rollback if there is nothing to roll back to.
//
// The fetch is a build because from 3.4.x an xrpld release ships as a signed
// DEB package first, and sometimes only as one: 3.4.1 exists at
// packages.xrplf.org and has no official image anywhere, while carrying an
// amendment deadline. The recipe follows the install guide's own apt steps
// inside an image, checks the signing key's fingerprint, and pins one exact
// package version.
func containerUpgradeSteps(p host.Profile, target string) []Step {
	compose := fmt.Sprintf("docker compose -f %s", shellQuote(p.ComposeFile))
	image := fmt.Sprintf("%s:%s", host.LocalImageRepo, target)
	stamp := "$(date +%Y%m%d-%H%M%S)"

	return []Step{
		backupConfigStep(p, stamp),
		{
			Title:   "Back up the deployment definition",
			Why:     "The compose file records which image is running. Restoring it is how you get back to the current version if the new one misbehaves.",
			Command: fmt.Sprintf("cp -a %s %s.%s.bak", shellQuote(p.ComposeFile), shellQuote(p.ComposeFile), stamp),
			Expect:  "a dated copy beside the compose file",
			Undo:    "nothing to undo, this only adds a file",
		},
		{
			Title: "Build the image from the signed package, without touching the running node",
			Why: "Building is the slow, failure-prone part. Doing it while the node is still validating means a failed build costs you nothing. " +
				"The node keeps running on its current image until you say otherwise, and the build refuses outright if the package signing key's fingerprint is not the published one.",
			Command: fmt.Sprintf("sudo bash /usr/local/lib/aperire/build-xrpld-image.sh --version %s", target),
			Expect:  fmt.Sprintf("the fingerprint line, the package version check, and %s verified, with the node still proposing throughout", image),
			Undo:    fmt.Sprintf("docker image rm %s", image),
		},
		{
			Title:   "Confirm the built image is the version you expect",
			Why:     "A tag is a label someone chose, and it can be moved. Ask the image what it is before you run it.",
			Command: fmt.Sprintf("docker run --rm --network none --entrypoint xrpld %s --version", image),
			Expect:  fmt.Sprintf("a version string containing %s", target),
			Undo:    "nothing to undo, this runs a throwaway container that exits immediately",
		},
		{
			Title: "Point the deployment at the built image",
			Why: "This edits one line and adds one beside it. Everything else about the deployment (mounts, ports, restart policy) stays exactly as it is. " +
				"pull_policy: never is what makes a missing image a loud failure instead of a trip to a registry that cannot serve this name.",
			Command: fmt.Sprintf("sed -i 's|image: %s:%s|image: %s|' %s   # then add a 'pull_policy: never' line under it",
				p.ImageRepo, p.ImageTag, image, shellQuote(p.ComposeFile)),
			Expect: fmt.Sprintf("grep -A1 image: %s shows %s and pull_policy: never", shellQuote(p.ComposeFile), image),
			Undo:   "restore the dated backup taken in step 2",
		},
		{
			Title: "Cut over",
			Why: "This is the only step that interrupts validation. It stops the container and starts a replacement on the new image; expect tens of seconds, not minutes. Everything before this was reversible without an outage. " +
				"The -t matters: with no -t, compose gives the stop the timeout the OLD container was created with, not the stop_grace_period the file names now, so raising that before an upgrade does nothing for the one stop the upgrade performs. 300 seconds is what the package's own systemd unit gives the same binary.",
			Command: fmt.Sprintf("%s up -d -t 300 %s", compose, p.Service),
			Expect:  fmt.Sprintf("'Recreated' for %s, then the container reporting healthy", p.Service),
			Undo:    fmt.Sprintf("restore the compose backup and run %s up -d -t 300 %s again", compose, p.Service),
		},
		confirmVersionStep(target, "if it does not return to proposing, restore the compose backup and cut back over"),
		watchAgreeStep("restore the compose backup and cut back over"),
	}
}

// backupConfigStep is identical on both kinds: both have a config file to
// lose, and neither Undo needs a kind-specific word.
func backupConfigStep(p host.Profile, stamp string) Step {
	return Step{
		Title:   "Back up the node config",
		Why:     "The config is the part an upgrade can invalidate, 3.2.0 renamed paths that had been stable for years. Without a dated copy there is no rollback, only a reinstall.",
		Command: fmt.Sprintf("cp -a %s %s.%s.bak", shellQuote(p.ConfigPath), shellQuote(p.ConfigPath), stamp),
		Expect:  fmt.Sprintf("a new file beside %s with today's date in the name", p.ConfigPath),
		Undo:    "nothing to undo, this only adds a file",
	}
}

// confirmVersionStep is the RPC read that decides whether the cutover
// actually worked, unchanged by kind: server_info answers the same question
// of a container and of a systemd unit. Only the way back, in Undo, differs.
func confirmVersionStep(target, undo string) Step {
	return Step{
		Title:   "Confirm the node came back on the new version",
		Why:     "A running process is not the same as a node that is validating. Check what it reports about itself, not that the process exists.",
		Command: `curl -s --data '{"method":"server_info","params":[{}]}' http://127.0.0.1:5005 | head -c 400`,
		Expect:  fmt.Sprintf("build_version %s, and server_state back to proposing", target),
		Undo:    undo,
	}
}

// watchAgreeStep is the same closing judgement either way: an immediate
// green light is not proof the upgrade worked.
func watchAgreeStep(undo string) Step {
	return Step{
		Title:   "Watch it agree for a few minutes before walking away",
		Why:     "A node can start, sync, and still disagree with the network. Agreement over several ledgers is the signal that the upgrade actually worked; an immediate green light is not.",
		Command: "",
		Expect:  "the dashboard's agreement figure holding, peers back to their usual count, and no missed validations accumulating",
		Undo:    undo,
	}
}

// nativeUpgradeSteps is the native design note's first property, written as
// instructions for a person to run: the package manager fetches and
// installs in one call, which is why there is no pull-then-confirm-then-set
// sequence to mirror, and why the install step's own Why says plainly that
// it can restart the node itself, through the vendor's maintainer scripts,
// rather than implying the reversibility a container's staged pull has.
//
// The commands shown are the Debian/Ubuntu form, with the RHEL form noted
// alongside, the deb path is the one proven on a real box (the design
// note's own lab plan), and showing both rather than guessing at one is
// this project's rule about naming what was measured.
func nativeUpgradeSteps(p host.Profile, target string) []Step {
	stamp := "$(date +%Y%m%d-%H%M%S)"
	pkg := p.Package
	unit := p.Unit
	// Beside the config, the same place backupConfigStep puts its own dated
	// copy: one directory you already know to look in for this upgrade's
	// artefacts, not a second one invented for a package.
	keepDir := shellQuote(filepath.Dir(p.ConfigPath))

	return []Step{
		backupConfigStep(p, stamp),
		{
			Title: "Confirm the target version is offered by your repositories",
			Why: "A version that is only announced, not yet published to the repository this host " +
				"trusts, cannot be installed. Asking first is the read that would have caught it, " +
				"before the node is touched.",
			Command: fmt.Sprintf("apt-cache madison %s | grep %s   # RHEL: dnf --showduplicates list %s",
				pkg, target, pkg),
			Expect: fmt.Sprintf("%s listed among the versions your repositories offer", target),
			Undo:   "nothing to undo, this only reads",
		},
		{
			Title: "Keep the currently installed package before installing the target",
			Why: "If the install below goes wrong and your repository no longer offers the " +
				"version this host is running right now, a rollback would have nothing to " +
				"install. Copying that package aside first, beside your config backup rather " +
				"than wherever your shell happens to be, is what gives a rollback somewhere " +
				"to go.",
			Command: fmt.Sprintf(
				"cd %s && sudo apt-get download %s=$(dpkg-query -W -f='${Version}' %s)   "+
					"# RHEL: cd %s && sudo dnf download %s-$(rpm -q --qf '%%{VERSION}-%%{RELEASE}' %s)",
				keepDir, pkg, pkg, keepDir, pkg, pkg),
			Expect: fmt.Sprintf(
				"a .deb (or .rpm on RHEL) for %s's currently installed version, in %s", pkg, keepDir),
			Undo: "nothing to undo, this only adds a file",
		},
		{
			Title: "Install the target version",
			Why: "The package manager verifies the vendor's signature before it installs, a " +
				"different guarantee from a pulled image's digest, not a weaker one. Its own " +
				"maintainer scripts can restart the node here, so treat this as the outage, not as " +
				"the safe half a container's pull is.",
			Command: fmt.Sprintf(
				"sudo apt-get install -y --no-install-recommends --allow-downgrades %s=%s   # RHEL: sudo dnf install -y %s-%s",
				pkg, target, pkg, target),
			Expect: fmt.Sprintf("the package manager reports %s installed", target),
			Undo: fmt.Sprintf("install the previous version instead (%s=<previous>), if you noted "+
				"what was running before this, there is no equivalent of removing a pulled image", pkg),
		},
		{
			Title: "Restart the unit to guarantee the cutover",
			Why: "Confirms the node is running the target build even where the package's own " +
				"scripts did not restart it, the same cutover a container's recreate performs, on a " +
				"systemd unit instead of a container.",
			Command: fmt.Sprintf("sudo systemctl restart %s", unit),
			Expect:  fmt.Sprintf("systemctl status %s reports active (running)", unit),
			Undo:    "see the previous step, going back is another install, not a restart",
		},
		confirmVersionStep(target, fmt.Sprintf(
			"if it does not return to proposing, install the previous version and restart %s again", unit)),
		watchAgreeStep(fmt.Sprintf("install the previous version and restart %s again", unit)),
	}
}

// shellQuote wraps a path in single quotes when it contains anything a shell
// would interpret. These strings are printed for a person to run, not passed to
// a shell by this program — but a path with a space in it that silently
// splits into two arguments is a bad instruction regardless of who runs it.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r == '/' || r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Render writes the plan as text for a terminal.
func (p Plan) Render(w *strings.Builder) {
	fmt.Fprintf(w, "Runbook   %s\n", p.RunbookID)
	if p.Profile.Kind == "native" {
		// Every field a container header would print (Container,
		// ComposeProject, ComposeFile) is empty on a native profile, so this
		// says which shape the node is rather than printing "Node ( / )"
		// above a plan full of apt-get and systemctl commands.
		fmt.Fprintf(w, "Node      native (%s, package %s)\n\n", p.Profile.Unit, p.Profile.Package)
	} else {
		fmt.Fprintf(w, "Node      %s (%s/%s)\n", p.Profile.Container, p.Profile.ComposeProject, p.Profile.Service)
		fmt.Fprintf(w, "Compose   %s\n\n", p.Profile.ComposeFile)
	}

	w.WriteString("PRECONDITIONS\n")
	for _, v := range p.Verdicts {
		fmt.Fprintf(w, "  [%s] %s\n         %s\n", v.Word(), v.Name, v.Detail)
	}
	w.WriteString("\n")

	if p.Blocked {
		w.WriteString("BLOCKED — the steps below are what would run once the failures above are cleared.\n")
		w.WriteString("Nothing has been done to the node.\n\n")
	} else {
		w.WriteString("All preconditions pass. The steps below are what the executor would perform.\n")
		w.WriteString("Nothing has been done to the node.\n\n")
	}

	w.WriteString("STEPS\n")
	for i, s := range p.Steps {
		fmt.Fprintf(w, "\n%d. %s\n", i+1, s.Title)
		fmt.Fprintf(w, "   why      %s\n", wrap(s.Why, 68, "            "))
		if s.Command != "" {
			fmt.Fprintf(w, "   run      %s\n", s.Command)
		}
		fmt.Fprintf(w, "   expect   %s\n", wrap(s.Expect, 68, "            "))
		fmt.Fprintf(w, "   undo     %s\n", wrap(s.Undo, 68, "            "))
	}
}

// wrap breaks long prose so a terminal at 80 columns does not ragged-wrap it
// mid-word into the label gutter.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := 0
	for i, wd := range words {
		if line > 0 && line+1+len(wd) > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(wd)
		line += len(wd)
	}
	return b.String()
}
