package runbook

import (
	"fmt"
	"strings"
	"time"
)

// RB001Upgrade is the v1 upgrade runbook from ADR 0001.
//
// Its preconditions are the ones the ADR names, and the rules baked in here
// come from the Field Guide's "Upgrading Rippled" section and runbook 10 of
// xrpld-agentic-ops. Two of them are worth calling out because they are the
// difference between an upgrade and an incident:
//
//   - Back up before changing. Runbook 10 requires a dated .bak of the compose
//     file and the config. Without it there is no rollback, and RB-002 exists
//     precisely because a rollback must be possible.
//   - Pull without touching the running node, and confirm the target actually
//     exists first. The Field Guide's pull-inspect-then-cutover pattern is what
//     turns a breaking release into a non-event.
//
// Deliberately absent: automatic updates. The Field Guide is explicit that a
// compromised repository would deploy itself, and that auto-update is not
// recommended for high stakes validators. This runbook only ever runs from an
// approved plan.
//
// On a native host "pull without touching the running node" has no exact
// twin: the package manager fetches and installs in one call, and its own
// maintainer scripts can restart the unit before this runbook's own cutover
// step ever runs. That is the native design note's first property, stated
// plainly rather than smoothed over, a vendor-signed package plus a
// version-after-restart comparison is a real guarantee, and a different one
// from a verified digest, never the same guarantee reached a different way.
// The one precondition that has nothing to check on native, the deployment
// definition's own backup, says so rather than refusing on a fact that does
// not apply to this kind.
func RB001Upgrade() Runbook {
	return Runbook{
		ID:      "upgrade-xrpld",
		Class:   ClassUpgrade,
		Summary: "Upgrade the node to a named release, after backing up and confirming the target is available.",
		Params: []Param{
			{Name: "target_version", Kind: KindVersion, Required: true},
			// Where the image comes from (#682). Empty is the ruling's
			// own order: the official image first, a build when no tag
			// carries the release. "build" is the operator asking for a
			// build anyway, which the card's own button sends and which
			// is checked before the registry is asked at all.
			{Name: "source", Kind: KindEnum, Allowed: []string{"", "official", "build"}},
			// The digest the official image was pinned to when this plan
			// was made. Carried in the plan rather than resolved when the
			// run reaches the pull: resolving it there is exactly the
			// substitution pinning exists to prevent, and a plan whose
			// approval covered one set of bytes must not install another.
			{Name: "digest", Kind: KindDigest},
		},
		ValidateParams: func(p Params) error {
			if p["source"] == "build" && p["digest"] != "" {
				return fmt.Errorf("a build takes no image digest, and this plan carries one")
			}
			if p["source"] == "official" && p["digest"] == "" {
				return fmt.Errorf("an official image is installed by digest, and this plan names none")
			}
			return nil
		},
		// Two stages, and the compound "upgrade" scope beside them: one
		// ceremony that covers prepare and then cutover in sequence. Declared
		// here rather than hardcoded in advisord, ADR 0016.
		Stages:      []string{"prepare", "cutover"},
		GrantScopes: []string{"prepare", "cutover", "upgrade"},
		Reversible:  true,
		// RB-004 reverses this one — ADR 0019. It is named here rather than
		// left empty because it exists in the registry, which is what
		// ReversedBy requires and what the registry test enforces.
		//
		// The note stays, and its second sentence is the reason the rollback
		// gate shows a concern rather than a button: a build that has written
		// the node's data store may leave the previous build unable to use it.
		// Observed on 2026-08-06, downgrading 3.2.1 to 3.2.0 with the store
		// intact — the node started, peered, and never acquired a validated
		// ledger. RB-004's gate quotes the sentence below verbatim rather than
		// paraphrasing it, so the two cannot drift.
		ReversedBy: "rollback-node",
		ReversalNote: "Ask the Advisor to roll this node back, which restores the version the " +
			"deployment named before this run. " + StoreRiskLesson,
		// ADR 0001's trigger, verbatim. All three are deterministic — this
		// runbook is raised without a model having any say in it, which is
		// what makes the recommendation checkable rather than an opinion.
		Why: []string{
			"the node is amendment blocked — it has stopped participating in consensus",
			"the running build is behind the current published release",
			"the log carries the warning that a majority of trusted validators run a higher version",
		},
		// ADR 0001's hypothesis. Stated before the change so it can be checked
		// after: a change with no expectation can only be said to have
		// finished, never to have worked.
		Expected: []string{
			"the node reports the target version",
			"amendment_blocked is absent or false",
			"server_state returns to proposing or full",
			"validation_quorum is unchanged",
			"peers rebuild toward their previous baseline",
		},
		Preconditions: []Precondition{
			{
				Name: "environment profile still matches the host",
				Check: func(_ Params, h HostState) Verdict {
					ok, d := h.ProfileMatches()
					return Verdict{Name: "environment profile still matches the host", Passed: ok, Detail: d}
				},
			},
			{
				// "differs" means the version OR the source.
				//
				// A source switch does not change the version, and it is
				// the case #682 was ruled for: production and the lab node
				// both run localhost/xrpld:3.4.1 today and the whole point
				// for them is to take the official 3.4.1. A precondition
				// that only compared versions refused this on exactly the
				// two hosts it exists to serve, with "already running
				// 3.4.1; nothing to do".
				Name: "this run changes something",
				Key:  KeyChangesSomething,
				Check: func(p Params, h HostState) Verdict {
					const n = "this run changes something"
					cur, err := h.RunningVersion()
					if err != nil {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read running version: %v", err)}
					}
					want := p["target_version"]
					if cur != want {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf("running %s, target %s", cur, want)}
					}
					// Same release. Only a change of source is left, and
					// only when the deployment is not already on it.
					// No copy named: this reads LiveOrigin only, which
					// does not depend on one.
					im := h.RollbackImaging(want, "")
					// The other direction (#664). A node on the official
					// image whose operator asked for a build of the same
					// release is changing where its image comes from just
					// as much as the move toward official is. Mainnet runs
					// one release today (fixBatchV1_2 is new in 3.4.1), so
					// this is the only build a node can take until the next
					// one ships, and it was refused as "nothing to do".
					//
					// Only when the plan says build in so many words. A plan
					// with no source on an official node is still asking for
					// the official image it already runs. Read before the
					// registry is asked, because a build the operator asked
					// for needs no registry, the same rule pinSource holds.
					//
					// Judged by what the container RUNS, not by the file
					// (#664, review of PR #981). Prepare points the file at
					// the build and the cutover is what puts the container
					// on it, and this check runs again before the cutover:
					// read off the file, a run half done read "nothing to
					// do" there, stopped short of the restart, and left a
					// file naming one image under a container running
					// another, which a fresh plan then also called nothing
					// to do. The pre-restart check in the executor is what
					// holds the file to the build; this holds the node.
					if p["source"] == "build" {
						switch im.RunningOrigin {
						case OriginOfficialName, OriginThirdPartyName:
							if im.LiveOrigin == OriginLocalBuildName {
								return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
									"running %s from %s, and the deployment already names the build of it; "+
										"the restart onto that build is what is left", cur, originWords(im.RunningOrigin))}
							}
							return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
								"running %s already, and this changes where its image comes from: "+
									"built here from the signed package instead of %s", cur, originWords(im.RunningOrigin))}
						case OriginLocalBuildName:
							return Verdict{Name: n, Passed: false, NoOp: true, Detail: fmt.Sprintf(
								"already running %s built on this host; nothing to do", cur)}
						default:
							// #679's rule: a reading nobody could take is not
							// "nothing to do", and it is not a change either.
							return FailedToMeasure(fmt.Sprintf(
								"which image the container runs could not be read, so whether a build of %s "+
									"changes anything was not measured", cur)).Verdict(n, SafetyCritical)
						}
					}
					// Toward the official image, judged by what the container
					// RUNS as well (#664, second review of PR #981). A build
					// whose restart was refused leaves the file naming the
					// build under a container still on the official image.
					// Read off the file, that passed as a change and recreated
					// the validator onto the image it already ran. Unread
					// (a stub, an old reading) falls back to the file, which
					// is what this check always read.
					running := im.RunningOrigin
					if running == "" {
						running = im.LiveOrigin
					}
					src, digest, why := h.UpgradeSource(want)
					// The host reports a container it could not read as
					// "unknown", not empty, and "unknown" is not "not the
					// official image": it is a reading nobody took (#679),
					// the same answer the build branch above gives.
					if src == OfficialImageSourceName && digest != "" && running == "unknown" {
						return FailedToMeasure(fmt.Sprintf(
							"which image the container runs could not be read, so whether the official "+
								"image of %s changes anything was not measured", cur)).Verdict(n, SafetyCritical)
					}
					if src == OfficialImageSourceName && digest != "" && running != OriginOfficialName {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"running %s already, and this changes where its image comes from: %s", cur, why)}
					}
					return Verdict{Name: n, Passed: false, NoOp: true, Detail: fmt.Sprintf(
						"already running %s from %s; nothing to do", cur, originWords(running))}
				},
			},
			{
				// #682. Three things have to be true before a node takes
				// an image with no entrypoint script of its own, and all
				// three are read from the deployment rather than assumed.
				//
				// They gate only an OFFICIAL target. On the build path
				// the image carries the entrypoint that copies the config
				// and adds the --conf itself, so a /config-only node is
				// fine there and refusing it would stop an upgrade that
				// works. The advice panel still says what it thinks of
				// that shape; this is the line between advice and a
				// refusal, and it is drawn by the target.
				Name: "this deployment can take an image with no entrypoint of its own",
				Check: func(p Params, h HostState) Verdict {
					const n = "this deployment can take an image with no entrypoint of its own"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true,
							Detail: "not applicable on a native host: there is no image and no entrypoint"}
					}
					// The plan's own answer first. It is the enum the
					// operator's choice bound to, and it was decided when
					// the plan was made; asking the host again here would
					// let a tag appearing since then turn a build the
					// operator asked for into an official swap.
					official := p["source"] == "official"
					if p["source"] == "" {
						src, _, _ := h.UpgradeSource(p["target_version"])
						official = src == OfficialImageSourceName
					}
					if !official {
						// One shape the build path cannot take (#664). The
						// built image's entrypoint script runs xrpld with
						// its own --conf. A deployment whose command passes
						// --conf and names no entrypoint of its own hands
						// that script a second one, and xrpld refuses --conf
						// twice: the recreate would leave the node down. A
						// deployment that names both, which is what the
						// Advisor's own swap to the official image writes,
						// runs xrpld directly and never reaches the script,
						// so it is fine. Refused only on a shape that was
						// read; an unread one is what this gate never asked
						// about on the build path, and it still does not.
						if sh := h.NodeShape(); sh.Read &&
							BuildPathDoubleConf(sh.EntrypointOverride, sh.CommandOverride) {
							return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
								"this deployment's command passes --conf (%s) and names no entrypoint, and "+
									"the image a build makes starts xrpld through a script that adds its own "+
									"--conf. xrpld refuses --conf twice, so the node would not come back. "+
									"Name the entrypoint (%q) beside that command, or drop --conf from it, "+
									"as its own change first",
								strings.Join(sh.CommandOverride, " "), "/usr/bin/xrpld")}
						}
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"not applicable: %s would come from %s, whose image carries its own entrypoint",
							p["target_version"], srcOrBuild(p["source"]))}
					}
					return officialShapeVerdict(n, h)
				},
			},
			{
				Name: "target release is published and pullable",
				Check: func(p Params, h HostState) Verdict {
					const n = "target release is published and pullable"
					ok, d := h.ImagePublished(p["target_version"])
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				Name: "disk headroom above floor",
				Check: func(_ Params, h HostState) Verdict {
					const n = "disk headroom above floor"
					// The Field Guide's pre-upgrade checklist requires verifying
					// disk space. 15% is the floor below which an upgrade plus a
					// re-sync is not a safe bet.
					const floorPct = 15.0
					return diskHeadroomVerdict(n, floorPct, h)
				},
			},
			{
				// The OTHER disk. The check above measures where the ledger
				// store lives; a build writes its layers where docker lives,
				// and those are different filesystems on plenty of hosts.
				// A build that runs out of room there fails halfway, which
				// is survivable and still better known before an operator
				// has approved anything.
				Name: "room where docker keeps its images",
				Check: func(_ Params, h HostState) Verdict {
					const n = "room where docker keeps its images"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: no images, and the package manager writes where the package manager writes"}
					}
					avail, path, err := h.ImageHeadroom()
					if err != nil {
						// Unmeasured, and it refuses (#679). This used to
						// pass with "not measured" in its detail, which on
						// a node whose wrapper could not run at all put a
						// green beside a reading nobody took. The build
						// would still fail loudly, but after the approval
						// rather than before it.
						return FailedToMeasure(err.Error()).Verdict(n, SafetyCritical)
					}
					if avail < imageBuildFloorBytes {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
							"%s has %s free and a build needs about %s. Free some room where docker keeps its images, then run this again",
							path, humanBytes(avail), humanBytes(imageBuildFloorBytes))}
					}
					return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf("%s free on %s", humanBytes(avail), path)}
				},
			},
			{
				// The recipe this host builds its image from, checked
				// before the approval rather than at the build (#675).
				//
				// A container node builds its own image from the signed
				// package, and the recipe that does it is root-owned and
				// installed separately. An update placed nothing, so every
				// node installed before that shipped had a card reading
				// "11 of 11 preconditions pass" and a run that refused at
				// the build step, after the operator had approved. Gates
				// nothing in particular on purpose: the build runs in
				// prepare, so this has to hold back prepare as well.
				Name: "the recipe this node builds its image from is installed",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the recipe this node builds its image from is installed"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true,
							Detail: "not applicable on a native host: the package manager installs the release, nothing is built here"}
					}
					return h.ImageRecipeReady().Verdict(n, SafetyCritical)
				},
			},
			{
				// The rotation that has not started yet. The wrapper refuses
				// a stop inside one it can see in the log; this refuses a
				// swap that would land inside the next one. A store stopped
				// mid-rotation came back empty and rebuilt from the network
				// (#79, 2026-08-25).
				Name:  "the next store rotation is further off than this swap",
				Gates: "cutover", // prepare stops nothing
				Check: func(_ Params, h HostState) Verdict {
					const n = "the next store rotation is further off than this swap"
					// Safety-critical: this is the guard that keeps a stop
					// out of a rotation window, so a reading whose tool
					// errored refuses rather than passing (#679).
					return h.FarFromRotation(SwapNeeds).Verdict(n, SafetyCritical)
				},
			},
			{
				Name:  "dated backup of the node config exists",
				Gates: "cutover", // prepare is what takes it
				Check: func(_ Params, h HostState) Verdict {
					const n = "dated backup of the node config exists"
					ok, d := h.BackupExists("node-config")
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				// Container only. A native host has no deployment definition
				// to have a copy of, nothing edits a file to name a version,
				// a package install names one directly, so requiring a
				// backup of a file that does not exist would refuse every
				// native upgrade's cutover on a fact about the wrong kind.
				Name:  "dated backup of the deployment definition exists",
				Gates: "cutover", // prepare is what takes it
				Check: func(_ Params, h HostState) Verdict {
					const n = "dated backup of the deployment definition exists"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: there is no deployment definition"}
					}
					ok, d := h.BackupExists("deployment-definition")
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				// The account the node comes back as, read before the stop
				// rather than after it.
				//
				// A container node's image is built on its own host from the
				// signed package, and that image's default account is
				// 997:997. A deployment whose container records NO user has
				// been running as root, because an image's own default is
				// what applies when nothing overrides it, and uid 997 on the
				// host is whatever account happened to take that number. On
				// one lab validator's host it was another service's account,
				// and the node's store and wallet are root's there: the node
				// would have come back unable to read its own data, minutes
				// after the swap, with the operator watching a healthy
				// container.
				//
				// So a root-running node is refused until its deployment
				// says user: "0:0" out loud. That is one line, it is
				// reversible, and it keeps the behaviour the node already
				// has. Moving the data to a non-root account is the better
				// end state and it is a different change on a different day.
				Name: "the node comes back as the account it went down as",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the node comes back as the account it went down as"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: the package's own unit decides the account, and an upgrade does not change it"}
					}
					sh, err := h.RuntimeAccount()
					if err != nil {
						// Already a refusal, and now it also says the
						// reading was never taken rather than reading as a
						// judgement about the account (#679).
						return FailedToMeasure(fmt.Sprintf("could not read what account this node runs as: %v", err)).
							Verdict(n, SafetyCritical)
					}
					grace := sh.StopTimeout
					if grace == "" {
						grace = "none recorded"
					}
					root := isRootUser(sh.ComposeUser)
					// The legacy shape, and the one that does not come back.
					// The built image copies /config to /etc/xrpld at start
					// and fails loudly when it cannot; a deployment that
					// mounts the config only at /config and runs as anyone
					// but root cannot write that path, so the container
					// exits 1 on the first start after the swap.
					if !sh.ConfigAtEtc && !root && sh.ContainerUser != "" {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
							"this deployment mounts the node config only at /config and runs as %s. The image built "+
								"from the signed package copies that config to %s at start and refuses to run when it "+
								"cannot, and %s cannot write there. Mount the same config read-only at %s as well, as "+
								"a separate change, then run this again",
							sh.ContainerUser, "/etc/xrpld/xrpld.cfg", sh.ContainerUser, "/etc/xrpld/xrpld.cfg")}
					}
					if sh.ContainerUser != "" {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"runs as %s, which the deployment carries across the swap (stop grace on the running container: %s)",
							sh.ContainerUser, grace)}
					}
					if root {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"runs as root, and the deployment says user: %q, so the built image's own 997:997 default does not apply (stop grace on the running container: %s)",
							sh.ComposeUser, grace)}
					}
					if sh.ComposeUser != "" {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
							"this node runs as root (its container names no user) while the deployment says user: %q. "+
								"Those disagree, and an image swap is not the moment to find out which one wins", sh.ComposeUser)}
					}
					return Verdict{Name: n, Passed: false, Detail: RootRuntimeRefusal}
				},
			},
			{
				Name: "consensus is not anomalous",
				Check: func(_ Params, h HostState) Verdict {
					const n = "consensus is not anomalous"
					// An upgrade restarts the node, so §7's caution against
					// restarting during consensus trouble applies here as much
					// as it does to the restart runbook.
					ok, d := h.ConsensusHealthy()
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				Name: "diagnostic snapshot captured before any change",
				Check: func(_ Params, h HostState) Verdict {
					const n = "diagnostic snapshot captured before any change"
					ok, d := h.EvidenceCaptured()
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
		},
	}
}

// V1 is the accepted v1 registry. Adding to it is a decision, not a code
// change made in passing — ADR 0001 fixed the inventory deliberately small.
// RB-002 joined it by ADR 0016, which is that decision taken again, RB-003
// by ADR 0018, and RB-004 by ADR 0019.
func V1() *Registry {
	return NewRegistry(RB001Upgrade(), RB002Restart(), RB003ConfigChange(), RB004Rollback(),
		RB005Normalise())
}

// RootRuntimeRefusal is what a container node running as root is told. A
// constant because the plan text and the Operations card quote it rather
// than paraphrasing: an operator reading two wordings of one refusal has to
// work out first whether they are the same refusal.
const RootRuntimeRefusal = "this node runs as root (its container names no user), and the image built from " +
	"the signed package defaults to 997:997. On this host that uid is whatever account holds it, which " +
	"may be another service's. Add `user: \"0:0\"` to the deployment to keep the behaviour this node already " +
	"has, then run this again. While it runs as root, /var/log/xrpld/debug.log usually lives in the " +
	"container's own layer and the recreate deletes it: copy it out first if you want it."

// isRootUser reads a compose `user:` value as root or not. Four spellings,
// because all four appear in real deployment files and a swap that treated
// "root" as "some account" would refuse a node that is already doing the
// right thing.
func isRootUser(v string) bool {
	switch v {
	case "0:0", "0", "root", "root:root":
		return true
	}
	return false
}

// imageBuildFloorBytes is the room a build wants where docker keeps its
// images: the contract's 2 GB. The image itself is about 90 MB; the rest is
// the base image, the package download and the build's own layers, and a
// floor that only covered the finished image would pass a host that cannot
// get there.
const imageBuildFloorBytes = 2 << 30

// SwapNeeds is how long the interrupting half of an upgrade takes, from the
// stop to a node back in sync. Measured on the lab: 43 to 100 seconds
// without RPC, and 9 to 13 minutes to reach full. Thirty minutes is the
// window the health watch already allows, and it is the number the rotation
// check compares against, because the question is whether a rotation would
// start while any of that is happening.
const SwapNeeds = 30 * time.Minute

// humanBytes renders a size the way an operator reads one. Two significant
// figures is enough for a headroom sentence.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/float64(1<<20))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

// officialShapeVerdict is the gate in front of any run that ends with the
// node on the official image while its deployment is edited, not restored
// whole: RB-001's official target, and since #664 RB-004's one-line
// rollback onto an official image. Three things the official image needs
// from the deployment, because it has no entrypoint script of its own, all
// read off the deployment rather than assumed. One function, so the two
// runbooks cannot come to disagree about what an official image needs.
func officialShapeVerdict(n string, h HostState) Verdict {
	sh := h.NodeShape()
	if !sh.Read {
		// #679's rule. A shape nobody could read is not a
		// shape that passed.
		return FailedToMeasure("the deployment could not be read, so nothing here was checked: "+
			strings.Join(sh.Notes, "; ")).Verdict(n, SafetyCritical)
	}
	if !sh.ConfigAtEtc {
		return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
			"this node's config does not reach %s, and the official image has no entrypoint "+
				"script to copy it there. The node would come up on the package's own config: "+
				"someone else's settings, no validator key, and a container reporting healthy. "+
				"Add the mount as its own change first", EtcConfigPathName)}
	}
	if !sh.ArgsWrittenDown {
		return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
			"this deployment names no entrypoint and no command, so the arguments come from "+
				"whichever image it runs. The official image's own default is "+
				"--net --silent --conf %s, and swapping the image would change how this node "+
				"starts without anyone asking. Write the arguments down as its own change first",
			EtcConfigPathName)}
	}
	if sh.Silent {
		return Verdict{Name: n, Passed: false, Detail: "this node runs with --silent, which " +
			"blanks docker logs. The rotation guard and the can-delete timer both read that " +
			"stream, and a guard that cannot read its evidence refuses, so this node would " +
			"refuse every restart the Advisor drives"}
	}
	return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
		"the config is mounted at %s and the arguments are written down (%s)",
		EtcConfigPathName, strings.Join(sh.CommandOverride, " "))}
}
