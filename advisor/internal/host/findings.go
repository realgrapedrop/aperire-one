package host

import (
	"fmt"
	"strings"

	"aperire-advisor/internal/runbook"
)

// What the Advisor thinks of the deployment it just read.
//
// The operator's requirement, 2026-09-27: most people running this are not
// xrpld experts, so the Advisor notes weak or risky choices with one plain
// sentence and the exact lines that would fix them. Read-only. Nothing here
// changes anything, and nothing here asks to.
//
// Three verdicts, and only one of them stops anything:
//
//   - VerdictGates: an upgrade is refused until this is fixed. Five of
//     them, and each is a node that does not come back or comes back as
//     something else.
//   - VerdictImprove: advice. It renders in "Your node's setup" and stays
//     advice until the operator asks for the change.
//   - VerdictFine: read, and said so, because a panel that only lists
//     problems cannot be told from one that failed to read.
//
// The Advisor's plain-and-short default applies: the finding, what it
// means, one step. More on request.

// Verdict is one of the three.
type Verdict string

const (
	VerdictFine    Verdict = "fine"
	VerdictImprove Verdict = "worth improving"
	VerdictGates   Verdict = "risky"
)

// Finding is one row of the panel.
type Finding struct {
	// Field is what was looked at, in the operator's words.
	Field   string  `json:"field"`
	Verdict Verdict `json:"verdict"`
	// Value is what this deployment actually says. Always present, so a
	// row can be argued with.
	Value string `json:"value"`
	// Sentence is what it means, in one sentence. Empty for a fine row:
	// there is nothing to explain about a thing that is right.
	Sentence string `json:"sentence,omitempty"`
	// Change is the exact lines that would fix it, when there are any.
	Change string `json:"change,omitempty"`
	// Fix names the ONE RB-005 change that makes it, when the Advisor can
	// make it at all (ADR 0023). Decided here rather than by a page
	// matching sentences to verbs: the row that says what is wrong is the
	// row that knows which change puts it right, and a second table
	// mapping one to the other is the copy that rots. Empty means there is
	// no approved operation for this row and the lines are for the
	// operator's own hand.
	Fix string `json:"fix,omitempty"`
	// Gating marks the ones an upgrade waits on. They render in the
	// Operations card rather than in the advice panel, because they are
	// what the upgrade is waiting on.
	Gating bool `json:"gating"`
	// Measured is false when the reading could not be taken. An
	// unmeasurable row is never a pass (#679); a gating one refuses.
	Measured bool `json:"measured"`
}

// ShapeFindings is the whole panel for one node.
//
// Order is fixed and is not severity: gating first, in the order an
// operator would fix them, then the advice in the order it appears in the
// deployment. A panel that reordered itself between reads would be a panel
// nobody could scan twice.
//
// official says where the upgrade's image comes from: the official image
// (true) or a build on this host (false). Two rows turn on it (#1009).
func (s *State) ShapeFindings(official bool) ([]Finding, NodeShape) {
	sh := s.NodeShapeNow()
	return FindingsForTarget(sh, official), sh
}

// FindingsFor is the judgement on its own, over a shape already read, so
// every row can be tested against a real captured deployment with no host
// anywhere near it. It reads the shape for the official image, the strict
// reading: the one a caller that does not say gets.
func FindingsFor(sh NodeShape) []Finding {
	return FindingsForTarget(sh, true)
}

// FindingsForTarget is FindingsFor for a named image source. The only row
// the source changes is "the arguments this node runs with are written
// down". The official image has no entrypoint script, so a deployment that
// names no arguments would start on the image's own defaults and the row
// gates. A build's image carries its own entrypoint and starts the node
// without them (RB-001 reads "not applicable" there), so the row stays on
// the card as advice and gates only where RB-001's build-path check
// refuses: a command that passes --conf with no entrypoint. Gating it
// anywhere else held a /config-only node on a change RB-005 itself refuses
// until the mount exists, and the build the node could take was never
// offered (#1009).
func FindingsForTarget(sh NodeShape, official bool) []Finding {
	if !sh.Read {
		why := "the deployment could not be read"
		if len(sh.Notes) > 0 {
			why = strings.Join(sh.Notes, "; ")
		}
		return []Finding{{
			Field: "this node's deployment", Verdict: VerdictGates, Gating: true,
			Value:    "not measured",
			Sentence: "nothing here was read, so nothing here is a pass: " + why,
		}}
	}
	var out []Finding
	out = append(out, gatingFindings(sh, official)...)
	out = append(out, adviceFindings(sh)...)
	return out
}

// ── the five that gate ───────────────────────────────────────────────────

func gatingFindings(sh NodeShape, official bool) []Finding {
	var out []Finding

	// 1. The config has to reach the path xrpld reads, or the node comes up
	// on the package's own config: someone else's settings, no validator
	// key, and a healthcheck that passes.
	f := Finding{Field: "the config reaches the path the node reads", Gating: true, Measured: true}
	switch {
	case sh.ConfigAtEtc:
		f.Verdict, f.Value = VerdictFine, mountSummary(sh.ConfigMounts)
	case len(sh.ConfigMounts) > 0 && len(sh.EntrypointOverride) == 0:
		// A /config-only deployment whose image still has its own
		// entrypoint script. It works today; it stops working the moment
		// the arguments are written down or the image changes.
		f.Verdict, f.Value = VerdictImprove, mountSummary(sh.ConfigMounts)
		f.Sentence = "this node depends on its image's own entrypoint copying the config to " +
			EtcConfigPath + " at start. Mount it there as well and it stops depending on that."
		f.Change, f.Fix = configMountChange(sh), runbook.NormaliseConfigMount
		f.Gating = false
	default:
		f.Verdict, f.Value = VerdictGates, mountSummary(sh.ConfigMounts)
		f.Sentence = "nothing puts this node's config where xrpld reads it, so it would come up on " +
			"the package's own: someone else's settings, no validator key, and a container reporting healthy."
		f.Change, f.Fix = configMountChange(sh), runbook.NormaliseConfigMount
	}
	out = append(out, f)

	// 2. --silent, which is not a preference. The rotation guard and the
	// can-delete timer both read docker logs, and #679's ruling is that a
	// guard which cannot read its evidence refuses rather than passes: a
	// silent node would refuse every restart this project drives.
	if sh.Silent {
		out = append(out, Finding{
			Field: "the node's arguments", Verdict: VerdictGates, Gating: true, Measured: true,
			Value: strings.Join(append(append([]string{}, sh.EntrypointOverride...), sh.CommandOverride...), " "),
			Sentence: "--silent blanks docker logs, and that stream is where the rotation guard and the " +
				"can-delete timer read what the ledger store is doing. A guard that cannot read its " +
				"evidence refuses, so this node would refuse every restart the Advisor drives.",
			Change: "    command: [\"--conf\", \"" + EtcConfigPath + "\"]",
			Fix:    runbook.NormaliseNodeArgs,
		})
	}

	// 3. The arguments have to be written down before an image swap, or
	// they change with the image and nobody asked for it.
	if !sh.ArgsWrittenDown {
		f = Finding{
			Field: "the arguments this node runs with are written down", Gating: true, Measured: true,
			Verdict: VerdictImprove,
			Value:   "no entrypoint: and no command: in the deployment",
			Sentence: "the arguments come from whichever image this node runs, so swapping the image " +
				"would change how it starts without anyone asking for it.",
			Change: "    entrypoint: [\"/usr/bin/xrpld\"]\n    command: [\"--conf\", \"" + EtcConfigPath + "\"]",
			Fix:    runbook.NormaliseNodeArgs,
		}
		// A build's image carries its own entrypoint, which a deployment
		// that names an entrypoint: of its own replaces. So the row relaxes
		// only where none is named, and says what the deployment does name.
		if !official && len(sh.EntrypointOverride) == 0 &&
			!runbook.BuildPathDoubleConf(sh.EntrypointOverride, sh.CommandOverride) {
			f.Gating = false
			if len(sh.CommandOverride) == 0 {
				f.Sentence = "the arguments come from whichever image this node runs. This upgrade builds an " +
					"image with its own entrypoint, so it does not need them written down, but a later swap " +
					"to another image would change how the node starts without anyone asking for it."
			} else {
				f.Value = "no entrypoint: in the deployment; command: " + strings.Join(sh.CommandOverride, " ")
				f.Sentence = "the image's own entrypoint decides how this node starts, ahead of the command: " +
					"it names. This upgrade builds an image with its own entrypoint, so it does not need an " +
					"entrypoint: written down, but a later swap to another image would change how the node " +
					"starts without anyone asking for it."
			}
		}
		out = append(out, f)
	}

	// 4. Who it comes back as. #668's refusal, kept in front of the stop.
	f = Finding{Field: "the account this node runs as", Gating: true, Measured: true}
	switch {
	case sh.ContainerUser == "" && sh.ComposeUser == "":
		f.Verdict, f.Value = VerdictGates, "the container names none and the deployment names none"
		f.Sentence = "the image's own default uid applies, and on this host that number belongs to " +
			"whoever holds it. Name the account the node already runs as, out loud."
		f.Change, f.Fix = "    user: \"0:0\"", runbook.NormaliseRuntimeUser
	case sh.ContainerUser != "" && sh.ComposeUser != "" && sh.ContainerUser != sh.ComposeUser:
		f.Verdict = VerdictGates
		f.Value = "the container runs as " + sh.ContainerUser + ", the deployment says " + sh.ComposeUser
		f.Sentence = "those disagree, and an image swap is not the moment to find out which one wins."
		f.Change, f.Fix = "    user: \""+sh.ContainerUser+"\"", runbook.NormaliseRuntimeUser
	default:
		f.Verdict = VerdictFine
		f.Value = firstNonEmpty(sh.ContainerUser, sh.ComposeUser, "root, named in the deployment")
	}
	out = append(out, f)

	// 5. A stop with no grace hard-kills NuDB at ten seconds.
	f = Finding{Field: "the stop grace", Gating: true, Measured: true}
	switch {
	case sh.StopTimeout == "" && sh.StopGraceFile == "":
		f.Verdict, f.Value = VerdictGates, "none anywhere"
		f.Sentence = "docker gives an unconfigured stop ten seconds, and NuDB is hard-killed at the end of it."
		f.Change = "    stop_grace_period: 90s"
	case sh.StopGraceFile != "" && belowNinetySeconds(sh.StopGraceFile):
		f.Verdict, f.Value = VerdictImprove, sh.StopGraceFile+" in the deployment"
		f.Sentence = "measured stops on this project's nodes ran to about 100 seconds."
		f.Change = "    stop_grace_period: 90s"
		f.Gating = false
	default:
		f.Verdict = VerdictFine
		f.Value = firstNonEmpty(sh.StopGraceFile, sh.StopTimeout+"s on the running container")
	}
	out = append(out, f)
	return out
}

// ── everything else: advice, and it stays advice ─────────────────────────

func adviceFindings(sh NodeShape) []Finding {
	var out []Finding

	// Admin ports on anything but loopback.
	var exposed []string
	for _, p := range sh.Ports {
		if !isAdminPort(p.Target) {
			continue
		}
		if p.HostIP == "" || p.HostIP == "0.0.0.0" || p.HostIP == "::" {
			exposed = append(exposed, fmt.Sprintf("%d", p.Target))
		}
	}
	if len(exposed) > 0 {
		out = append(out, Finding{
			Field: "the admin ports", Verdict: VerdictImprove, Measured: true,
			Value: strings.Join(exposed, ", ") + " published on every interface",
			Sentence: "anything that reaches an admin port can ask this node to stop, or read what " +
				"it is doing.",
			Change: "      - \"127.0.0.1:" + exposed[0] + ":" + exposed[0] + "\"",
		})
	} else {
		out = append(out, Finding{
			Field: "the admin ports", Verdict: VerdictFine, Measured: true,
			Value: "loopback only",
		})
	}

	// The debug log: the path comes from the node's own config, and there
	// are three ways for it to be a lie.
	out = append(out, debugLogFinding(sh))

	// Hardening.
	if !hasAll(sh.CapDrop) || !sh.NoNewPrivileges {
		out = append(out, Finding{
			Field: "capabilities", Verdict: VerdictImprove, Measured: true,
			Value:    fmt.Sprintf("cap_drop %v, no-new-privileges %v", sh.CapDrop, sh.NoNewPrivileges),
			Sentence: "the node needs no capability it is not given, and cannot acquire one.",
			Change:   "    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL",
		})
	} else {
		out = append(out, Finding{
			Field: "capabilities", Verdict: VerdictFine, Measured: true,
			Value: "cap_drop ALL, no-new-privileges",
		})
	}

	// The container log, which is also where the rotation guard reads.
	if sh.LogMaxSize == "" || sh.LogMaxFile == "" {
		out = append(out, Finding{
			Field: "the container log", Verdict: VerdictImprove, Measured: true,
			Value: firstNonEmpty(sh.LogDriver, "docker's default") + ", uncapped",
			Sentence: "one node's container log reached 2.9 GB, and docker's json log has no index, " +
				"so every bounded read of it scanned the whole file.",
			Change: "    logging:\n      driver: \"json-file\"\n      options:\n" +
				"        max-size: \"100m\"\n        max-file: \"5\"\n        compress: \"true\"",
		})
	} else {
		out = append(out, Finding{
			Field: "the container log", Verdict: VerdictFine, Measured: true,
			Value: sh.LogDriver + " " + sh.LogMaxSize + " x " + sh.LogMaxFile,
		})
	}

	// Restart policy.
	switch sh.RestartPolicy {
	case "unless-stopped":
		out = append(out, Finding{Field: "the restart policy", Verdict: VerdictFine,
			Measured: true, Value: "unless-stopped"})
	case "always":
		out = append(out, Finding{
			Field: "the restart policy", Verdict: VerdictImprove, Measured: true, Value: "always",
			Sentence: "with always, a node you stopped on purpose comes back the next time docker " +
				"starts. unless-stopped restarts it after a reboot and leaves a deliberate stop alone.",
			Change: "    restart: unless-stopped",
		})
	default:
		out = append(out, Finding{
			Field: "the restart policy", Verdict: VerdictImprove, Measured: true,
			Value:    firstNonEmpty(sh.RestartPolicy, "none"),
			Sentence: "a rebooted host comes back without a node.",
			Change:   "    restart: unless-stopped",
		})
	}

	// Memory.
	if sh.MemLimit == "" {
		out = append(out, Finding{
			Field: "the memory limit", Verdict: VerdictImprove, Measured: true, Value: "not set",
			Sentence: "a node that grows takes the host with it, and on most of these boxes the " +
				"dashboard and the relay are on the same host.",
			Change: "    mem_limit: \"20g\"\n    memswap_limit: \"20g\"",
		})
	} else {
		out = append(out, Finding{Field: "the memory limit", Verdict: VerdictFine,
			Measured: true, Value: sh.MemLimit})
	}

	// The healthcheck, and what it calls healthy.
	out = append(out, healthFinding(sh))

	// A localhost image with nothing stopping compose reaching for a
	// registry that cannot answer for that name.
	if sh.ImageOrigin == OriginLocalBuild && sh.PullPolicy != "never" {
		out = append(out, Finding{
			Field: "the pull policy", Verdict: VerdictImprove, Measured: true,
			Value:    firstNonEmpty(sh.PullPolicy, "not set"),
			Sentence: "a missing image sends compose to a registry that cannot answer for a localhost/ name.",
			Change:   "    pull_policy: never",
		})
	}

	// host networking, which makes the loopback claim above untrue.
	if sh.NetworkMode == "host" {
		out = append(out, Finding{
			Field: "the network", Verdict: VerdictImprove, Measured: true, Value: "network_mode: host",
			Sentence: "with host networking the admin ports are not loopback-only in the way the " +
				"deployment claims: the container binds the host's own interfaces.",
			Change: "    ports:\n      - \"127.0.0.1:5005:5005\"\n      - \"127.0.0.1:6006:6006\"",
		})
	}
	return out
}

func debugLogFinding(sh NodeShape) Finding {
	f := Finding{Field: "the debug log", Measured: true}
	switch {
	case sh.LogPathInConfig == "":
		f.Verdict, f.Value = VerdictFine, "not set; docker logs is the log"
	case strings.HasPrefix(sh.LogPathInConfig, "/var/log/xrpld"):
		// Both images ship that directory 0750 owned by their own uid, and
		// with cap_drop ALL even root has no CAP_DAC_OVERRIDE, so nobody
		// can write it. Measured on aperire1, 2026-09-27, as 0:0 and as
		// 993:984, on both images.
		f.Verdict, f.Value = VerdictImprove, sh.LogPathInConfig
		f.Sentence = "that directory is 0750 owned by the image's own account, and with every " +
			"capability dropped nothing in this container can write it. So there is no debug log, " +
			"which is the first thing anyone wants after an incident."
		f.Change = "      - /home/<you>/rippled/logs:/var/log/xrpld"
	case !sh.LogOnVolume:
		f.Verdict, f.Value = VerdictImprove, sh.LogPathInConfig+", in the container layer"
		f.Sentence = "the log is written inside the container, so it dies with it: every recreate " +
			"takes the log an incident would have been read from."
		f.Change = "      - /home/<you>/rippled/logs:" + parentDir(sh.LogPathInConfig)
	default:
		f.Verdict, f.Value = VerdictFine, sh.LogPathInConfig+", on a mount"
	}
	return f
}

func healthFinding(sh NodeShape) Finding {
	f := Finding{Field: "the healthcheck", Measured: true}
	if !sh.Healthcheck.Read {
		f.Verdict, f.Value = VerdictImprove, "none"
		f.Sentence = "docker reports the process, not the node: a container whose node stopped " +
			"answering still reads as up."
		f.Change = "    healthcheck:\n      test: [\"CMD-SHELL\", \"xrpld --conf " + EtcConfigPath +
			" -q server_info | grep -Eq '\\\"server_state\\\"\\\\s*:\\\\s*\\\"(proposing|full)\\\"'\"]"
		return f
	}
	if len(sh.Healthcheck.States) == 0 {
		f.Verdict, f.Value = VerdictFine, "present"
		f.Sentence = ""
		return f
	}
	f.Value = "accepts " + strings.Join(sh.Healthcheck.States, ", ")
	lax := false
	for _, st := range sh.Healthcheck.States {
		if st == "connected" || st == "syncing" || st == "tracking" {
			lax = true
		}
	}
	if !lax {
		f.Verdict = VerdictFine
		return f
	}
	// Advice either way, and the sentence says why it is advice: only the
	// operator knows whether this node validates. The installer template is
	// the lax one, deliberately, because a fresh node spends its first
	// hours syncing.
	f.Verdict = VerdictImprove
	f.Sentence = "on a validator, only proposing or full is doing the job, and this container would " +
		"report healthy while it was not validating. The stricter test costs an unhealthy container " +
		"through every resync, which is honest rather than annoying."
	f.Change = "      test: [\"CMD-SHELL\", \"xrpld --conf " + EtcConfigPath +
		" -q server_info | grep -Eq '\\\"server_state\\\"\\\\s*:\\\\s*\\\"(proposing|full)\\\"'\"]"
	return f
}

// ── small readings ───────────────────────────────────────────────────────

// isAdminPort is the two ports anything reaching can ask the node to stop.
func isAdminPort(target int) bool { return target == 5005 || target == 6006 || target == 5006 }

func hasAll(caps []string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, "ALL") {
			return true
		}
	}
	return false
}

func mountSummary(ms []MountFact) string {
	if len(ms) == 0 {
		return "no config is mounted at all"
	}
	var out []string
	for _, m := range ms {
		s := m.Target
		if m.ReadOnly {
			s += " (read-only)"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// configMountChange names the host path the deployment ALREADY uses, never
// a path invented here: whatever file this node reads is the file it keeps
// reading.
func configMountChange(sh NodeShape) string {
	src := ""
	for _, m := range sh.ConfigMounts {
		if src == "" {
			src = m.Source
		}
	}
	if src == "" {
		return "      - /home/<you>/rippled/config/rippled.cfg:" + EtcConfigPath + ":ro"
	}
	out := "      - " + src + ":" + EtcConfigPath + ":ro"
	for _, m := range sh.ValidatorsMounts {
		out += "\n      - " + m.Source + ":/etc/xrpld/validators.txt:ro"
		break
	}
	return out
}

// belowNinetySeconds reads compose's own rendering of a duration ("1m30s",
// "5m0s", "45s"). Anything it cannot read is not called short: a reading
// nobody took is not a finding.
func belowNinetySeconds(d string) bool {
	secs, ok := durationSeconds(d)
	return ok && secs < 90
}

func durationSeconds(d string) (int, bool) {
	d = strings.TrimSpace(d)
	if d == "" {
		return 0, false
	}
	total, cur, any := 0, 0, false
	for _, c := range d {
		switch {
		case c >= '0' && c <= '9':
			cur = cur*10 + int(c-'0')
			any = true
		case c == 'h':
			total += cur * 3600
			cur = 0
		case c == 'm':
			total += cur * 60
			cur = 0
		case c == 's':
			total += cur
			cur = 0
		default:
			return 0, false
		}
	}
	if !any {
		return 0, false
	}
	return total + cur, true
}

func parentDir(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return p
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" && v != "s on the running container" {
			return v
		}
	}
	return "not set"
}

// GatingFindings is the subset an upgrade waits on, for the Operations card.
func GatingFindings(all []Finding) []Finding {
	var out []Finding
	for _, f := range all {
		// Gating alone, not Gating AND risky. The two fields say different
		// things: Gating is "an upgrade waits on this", Verdict is how bad
		// it is on its own. The arguments not being written down is exactly
		// that pair — it is worth improving on a node nobody is upgrading,
		// and it stops the swap on a node that is, because the image's own
		// default would change how the node starts. Requiring both meant
		// the Operations card showed no gating row while RB-001's own
		// precondition refused for it, which is one page saying two things.
		// Observed on aperire1, 2026-09-27.
		if f.Gating && f.Verdict != VerdictFine {
			out = append(out, f)
		}
	}
	return out
}
