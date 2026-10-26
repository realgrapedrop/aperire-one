package runbook

import "fmt"

// StoreRiskLesson is the 2026-08-06 downgrade, in one sentence, in the words
// RB-001's reversal note already used.
//
// It is a constant because it is said in two places that must not drift: the
// note an operator reads after an upgrade, and the amber concern the rollback
// gate shows before one. Two copies of a lesson is how one of them gets
// softened, and the softened one is always the one shown at the moment it
// matters.
const StoreRiskLesson = "If the release changed the data store, the store has to be restored " +
	"from backup too — the older build may not be able to read what the newer one wrote, " +
	"and it fails by never validating rather than by refusing to start."

// RB004Rollback puts the node back on the release it was running before the
// last version change — ADR 0019.
//
// It is the upgrade's inverse and shares its class. runbook.go's own
// definition reads `ClassUpgrade Class = "upgrade" // upgrade and roll back`,
// which predates this runbook by months: the class an operator already
// accepted names this capability, so a separate one would refuse the act on
// every host in the fleet until each re-ran the compact for something already
// inside the ceiling they agreed to.
//
// Three things about it are not the upgrade's, and each is a decision:
//
//   - It fetches the target INSIDE its one stage, before the recreate rather
//     than leaving it to `compose up` with the node already down — a tag
//     withdrawn from the registry would otherwise leave a stopped node whose
//     deployment names an image that does not exist. And when the image is
//     already on this host, which for a rollback is the ordinary case, it
//     confirms that instead of pulling: the moment a rollback is wanted is a
//     bad release in the middle of an incident, and an act that needed the
//     registry then would refuse in exactly the situation it exists for.
//   - It sets the image rather than restoring the compose backup. One line
//     changes, so mounts, ports and the restart policy stay exactly as they
//     are; a backup taken before the last upgrade may also predate unrelated
//     deployment edits, and restoring the file would revert them silently.
//     The backup is named in the record as the file to restore by hand when
//     the deployment itself needs reverting.
//   - The data-store risk is a CONCERN, never a precondition. RB-001's own
//     reversal note says an older build may be unable to read what a newer one
//     wrote, and that it fails by never validating rather than by refusing to
//     start (observed 2026-08-06). A precondition made of that would refuse
//     exactly the rollback that matters, which is the one after an upgrade.
//     It is measured, quoted verbatim and shown above the confirm code.
//
// The target is derived by the service and re-checked here: the precondition
// below refuses a target equal to the running version, and the action decider
// refuses one that is not the version this host derived from its own backups
// and run history. The parameter exists so the operator approves a version
// they can read, not so anything upstream can choose one.
//
// On a native host the guarantee this rolls back onto is a different one, and
// the preconditions say so rather than pretending it is the same check on a
// different transport. "The rollback target is on this host, or still
// published" is a container question, there is no local image cache on
// native to ask ImageLocal about, so it steps aside there, and "the rollback
// target is installable" asks whether this host holds the artefact itself
// or, failing that, whether the package repositories still do, before the
// cutover rather than during it. That is the native design note's second
// property: reversibility is weaker (a version can leave a repository the way
// it never leaves a registry a host already pulled from), and this
// precondition is the mitigation, checking it early rather than discovering
// it with the node already stopped.
func RB004Rollback() Runbook {
	return Runbook{
		ID:      "rollback-node",
		Class:   ClassUpgrade,
		Summary: "Roll the node back to the release it was running before the last version change.",
		Params: []Param{
			{Name: "target_version", Kind: KindVersion, Required: true},
			// The operator's category, in the fingerprint and in the ledger —
			// RB-002's reasoning applied to a second act. It is NOT an
			// acknowledgement of the store risk: a category describing why a
			// rollback is happening must not double as a checkbox, or the
			// ledger records a reason nobody meant. Typing the confirm code is
			// the acknowledgement, as it is for every other act.
			{Name: "intent", Kind: KindEnum, Required: true, Allowed: []string{
				"planned-rollback", "regression-suspected", "operator-judgement",
			}},
			// The dated copy this rollback restores, by name, and the
			// digest that copy pins its image to (#682, second review).
			//
			// They are parameters rather than something the executor
			// works out for itself because the fingerprint is computed
			// from the bound parameters: the file the operator approved
			// on the card and the file the run restores are the same file
			// only if the approval covers its name. Before this, the card
			// showed the copy the derivation chose and the run restored
			// "the newest copy that is not official", which on a node
			// going from one official release to another is a different
			// file, two releases back.
			//
			// KindPath, so it is a NAME and never a path: anything with a
			// separator or a relative segment is refused at binding.
			{Name: "restore_path", Kind: KindPath},
			{Name: "restore_digest", Kind: KindDigest},
		},
		// One stage. The rollback IS the restart, so there is no reversible
		// half to split off — and splitting one off would leave the deployment
		// naming one version while the node runs another, which is the state
		// the third precondition below refuses.
		Stages:      []string{"rollback"},
		GrantScopes: []string{"rollback"},
		Reversible:  true,
		ReversedBy:  "",
		ReversalNote: "Roll forward with another rollback. This run takes its own dated copy of the " +
			"deployment before it edits anything, so the version it came from is what the next " +
			"rollback derives as its target — the same act, the other direction. It does not put " +
			"the data store back: if the newer build wrote a store the older one cannot read, the " +
			"store has to be restored from its own backup.",
		// Empty on purpose, as RB-002's and RB-003's are. Nothing
		// deterministic says "roll back now": a release the operator dislikes
		// is a judgement, and the assessment is what makes it an informed one.
		Why: nil,
		Expected: []string{
			"the node reports the rollback target",
			"server_state returns to proposing or full",
			"peers rebuild toward their previous count",
			"a validated ledger is acquired — the reading that would show the older build " +
				"cannot use the store the newer one wrote",
		},
		Preconditions: []Precondition{
			{
				Name: "environment profile still matches the host",
				Check: func(_ Params, h HostState) Verdict {
					const n = "environment profile still matches the host"
					ok, d := h.ProfileMatches()
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				Name: "this rollback changes something",
				Key:  KeyChangesSomething,
				Check: func(p Params, h HostState) Verdict {
					const n = "this rollback changes something"
					cur, err := h.RunningVersion()
					if err != nil {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read the running version: %v", err)}
					}
					want := p["target_version"]
					if cur != want {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf("running %s, would roll back to %s", cur, want)}
					}
					// The same release from a different source is a real
					// rollback, and it is the one this project's own two
					// container hosts need (#682). Both ran
					// localhost/xrpld:3.4.1 and both take rippleci's 3.4.1:
					// the version does not move, the ORIGIN does, and the way
					// back is the whole dated copy of the deployment taken
					// before the swap. A check that compared versions alone
					// answered "already running 3.4.1; nothing to roll back
					// to" and left the node with no way back through the
					// Advisor at all.
					im := h.RollbackImaging(want, p["restore_path"])
					if im.RestorePath != "" {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"running %s from %s, and going back to the deployment as it stood before "+
								"that swap (%s)", cur, im.LiveOrigin, im.RestorePath)}
					}
					// The other direction (#664): the node was built here
					// from the signed package, and the copy taken before
					// that build names the official image at a digest. No
					// whole file goes back, because the build rewrote one
					// line and nothing else, so RestorePath is empty here
					// by design. What says this is a real change is the
					// copy the derivation named: another origin, pinned.
					//
					// Live origin local-build exactly, not "anything but
					// official" (review of PR #981): a third-party image, or
					// one whose origin could not be read, is not the state a
					// build leaves, and it is not this rollback's to undo.
					//
					// And the CONTAINER on the build too (second review): a
					// build whose restart was refused leaves the file naming
					// it under a container still on the official image, and
					// "going back" there would recreate the validator onto
					// the digest it already runs.
					if p["restore_path"] != "" && im.TargetOrigin == OriginOfficialName &&
						im.LiveOrigin == OriginLocalBuildName && im.RunningOrigin == OriginLocalBuildName &&
						im.RestoreDigest != "" {
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"running %s from %s, and going back to the official image it ran before "+
								"that build, at %s (%s)", cur, im.LiveOrigin, im.RestoreDigest, p["restore_path"])}
					}
					return Verdict{Name: n, Passed: false, NoOp: true, Detail: fmt.Sprintf(
						"already running %s, from the same source, and no dated copy of the deployment "+
							"names another one; nothing to roll back to: %s", cur, im.Detail)}
				},
			},
			{
				Name: "the deployment names the version the node is running",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the deployment names the version the node is running"
					// Inherited from RB-002 for its own reason — a version
					// change while the deployment names some other tag is an
					// unapproved version change whichever runbook asked — and
					// kept here for a second one: it is what makes the target
					// derivation well defined. A half-run upgrade (prepare
					// done, cutover never ran) leaves compose naming the new
					// tag while the node runs the old one, and the newest
					// deployment backup then names the RUNNING version, so
					// "the newest backup naming another version" would reach
					// past it to something stale.
					running, err := h.RunningVersion()
					if err != nil {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read the running version: %v", err)}
					}
					tag, err := h.DeploymentTag()
					if err != nil {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read what the deployment names: %v", err)}
					}
					if tag != running {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
							"the deployment names %s and the node is running %s; the version this would roll "+
								"back FROM is not settled, so it is refused", tag, running)}
					}
					return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf("both %s", running)}
				},
			},
			{
				// A container-only question. ImageLocal has nothing behind
				// it on a native host, there is no local image cache to
				// resolve, only the package database and the repositories,
				// so this precondition steps aside on native rather than
				// asking a question it cannot answer, and "the rollback
				// target is installable" below asks the one it can.
				Name: "the rollback target is on this host, or still published",
				Check: func(p Params, h HostState) Verdict {
					const n = "the rollback target is on this host, or still published"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: installability is asked directly, below"}
					}
					// LOCAL FIRST, and that order is the point.
					//
					// The target of a rollback is the image this node was
					// running until the upgrade, so it is almost always
					// already on the disk — and the moment a rollback is
					// wanted is a bad release in the middle of an incident,
					// which is exactly when a registry lookup is worth
					// nothing to depend on. ImagePublished is an HTTP call to
					// the registry and fails closed, so asking it first would
					// refuse the rollback this runbook exists for, with the
					// image sitting right there.
					//
					// The registry stays as the fallback for the case it
					// answers well: a host that has since pruned the image.
					//
					// An official target is asked by the DIGEST its dated copy
					// pins, never by version (#984). Asked by version, the
					// wrapper answers with the local build of that release
					// first, so a node holding a build and not the official
					// image read "already on this host" while the run, which
					// fetches and checks by digest, would then halt.
					if im := h.RollbackImaging(p["target_version"], p["restore_path"]); im.TargetOrigin == OriginOfficialName {
						return officialTargetPresentVerdict(n, p["target_version"], im, h)
					}
					if ok, d := h.ImageLocal(p["target_version"]); ok {
						return Verdict{Name: n, Passed: true, Detail: d + ", so this needs no registry"}
					}
					ok, d := h.ImagePublished(p["target_version"])
					if !ok {
						return Verdict{Name: n, Passed: false, Detail: "it is not on this host, and " + d}
					}
					return Verdict{Name: n, Passed: true, Detail: "not on this host, but " + d}
				},
			},
			{
				// The way back, checked BEFORE anything is fetched
				// (#682, second review).
				//
				// A deployment that names the official image cannot be
				// rolled back by rewriting one line: the swap that put it
				// there wrote the arguments the node runs with beside the
				// image, so the whole dated copy has to go back. If that
				// copy is missing, or names a different release from the
				// one being rolled back to, there is no rollback to make
				// and the operator has to hear it here rather than after
				// a pull, with the node still validating.
				//
				// A node installed straight onto the official image has
				// no earlier copy at all, and so does one whose copies
				// have been pruned. Before this, both of those ran the
				// whole stage and died at restore-compose.
				Name: "the way back is a copy this host still has",
				// (the official-target half of this is the precondition
				// below: a digest, or there is nothing to fetch by)
				Check: func(p Params, h HostState) Verdict {
					const n = "the way back is a copy this host still has"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: a package is put back, not a file"}
					}
					im := h.RollbackImaging(p["target_version"], p["restore_path"])
					if im.LiveOrigin != OriginOfficialName {
						return Verdict{Name: n, Passed: true, Detail: "the deployment names an image this can point back " +
							"one line at a time, so no copy has to be restored"}
					}
					if im.RestorePath == "" {
						return Verdict{Name: n, Passed: false, Detail: im.Detail}
					}
					return Verdict{Name: n, Passed: true, Detail: "restoring " + im.RestorePath + " puts the deployment, " +
						"its arguments and its mounts back together"}
				},
			},
			{
				// An official target is fetched and checked BY DIGEST, so
				// it needs one before the stage starts (#682, third
				// review). Two shapes had none: a rollback from a locally
				// built image to an official one, and a copy that names
				// the official image by tag rather than by digest. Both
				// passed every precondition and died mid-stage, at the
				// wrapper's own require_digest, with the node already
				// committed to the run.
				Name: "an official rollback target names the digest it goes back to",
				Check: func(p Params, h HostState) Verdict {
					const n = "an official rollback target names the digest it goes back to"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: a package is put back, not an image"}
					}
					im := h.RollbackImaging(p["target_version"], p["restore_path"])
					if im.TargetOrigin != OriginOfficialName {
						return Verdict{Name: n, Passed: true, Detail: "this target is not an official image, so no digest is needed to fetch it"}
					}
					if im.RestoreDigest == "" {
						return Verdict{Name: n, Passed: false, Detail: "the copy this would go back to names " +
							"the official image without a digest, and an official image is fetched and checked by " +
							"digest; there is nothing here to fetch by"}
					}
					return Verdict{Name: n, Passed: true, Detail: "going back to " + im.RestoreDigest +
						", which is what gets fetched and checked"}
				},
			},
			{
				// The official image has no entrypoint script of its own,
				// so it needs three things from the deployment, and RB-001
				// refuses an official target without them. A rollback that
				// restores a whole dated copy puts back the arguments and
				// mounts that copy ran the official image with. One that
				// rewrites the image line alone does not, and since #664
				// that is reachable at the same release: a node built here
				// goes back to the official image by one line. A file that
				// lost its entrypoint/command pair or its /etc mount since
				// would bring the official image up on its own defaults
				// (--silent, or the package config with no validator key),
				// and every digest check after it would still pass. The
				// same three refusals as RB-001, from the same function.
				Name: "an official rollback target can start on this deployment as it stands",
				Check: func(p Params, h HostState) Verdict {
					const n = "an official rollback target can start on this deployment as it stands"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a native host: there is no image and no entrypoint"}
					}
					im := h.RollbackImaging(p["target_version"], p["restore_path"])
					if im.TargetOrigin != OriginOfficialName {
						return Verdict{Name: n, Passed: true, Detail: "not applicable: this target is not an official image"}
					}
					if im.RestorePath != "" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable: the whole copy goes back, " +
							"with the arguments and mounts it ran the official image with"}
					}
					return officialShapeVerdict(n, h)
				},
			},
			{
				// The native design note's second property, made a
				// precondition rather than a discovery: reversibility on
				// native depends on the previous version still being
				// installable, and that is checked BEFORE the cutover, not
				// found out during it. Two ways to answer "yes", asked in
				// the order the container precondition above already
				// argues for: PackageKept first, because the moment a
				// rollback is wanted is a bad release in the middle of an
				// incident, which is exactly when a repository lookup is
				// worth nothing to depend on, and it is a local file read
				// rather than a call to the repository's own metadata.
				// ImagePublished (the wrapper's package-available verb) is
				// the fallback, the same question RB-001's own "target
				// release is published and pullable" precondition asks, of
				// the version this run is moving away from. Only when
				// neither answers "yes" is the rollback refused, and the
				// refusal names which one it is missing from, issue #393's
				// second half, the kept .deb/.rpm beside the config
				// backups this precondition's own comment used to say did
				// not exist yet.
				Name: "the rollback target is installable",
				Check: func(p Params, h HostState) Verdict {
					const n = "the rollback target is installable"
					if h.Kind() != "native" {
						return Verdict{Name: n, Passed: true, Detail: "not applicable on a container deployment"}
					}
					if ok, d := h.PackageKept(p["target_version"]); ok {
						return Verdict{Name: n, Passed: true, Detail: d + ", so this needs no repository"}
					}
					ok, d := h.ImagePublished(p["target_version"])
					if !ok {
						return Verdict{Name: n, Passed: false, Detail: "it is not kept on this host, and refusing to name an uninstallable rollback target: " + d}
					}
					return Verdict{Name: n, Passed: true, Detail: "not kept on this host, but " + d}
				},
			},
			{
				// Step 2 of the upgrade contract, asked of a rollback: would
				// the version this returns to come up amendment blocked?
				//
				// This is the one precondition here that can refuse a
				// rollback outright rather than asking for a different
				// target, and it says why in the same breath. A node that
				// comes back blocked is a worse outcome than the release
				// this rollback is for: it stops participating entirely,
				// and the way out is forward, not back.
				Name: "the rollback target will not come back amendment blocked",
				Check: func(p Params, h HostState) Verdict {
					const n = "the rollback target will not come back amendment blocked"
					// Advisory when unmeasured, on purpose: the node that
					// will not answer `feature` is often the node being
					// rolled back, and taking the remedy away from it is
					// the worse outcome. It reads "not measured" rather
					// than "pass" either way (#679).
					return h.RollbackSafeFromAmendments(p["target_version"]).Verdict(n, Advisory)
				},
			},
			{
				// The rotation that has not started yet, the same question
				// RB-001's cutover asks. A rollback is a stop like any
				// other, and it is usually run in a hurry, which is exactly
				// when this gets skipped by hand.
				Name: "the next store rotation is further off than this swap",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the next store rotation is further off than this swap"
					return h.FarFromRotation(SwapNeeds).Verdict(n, SafetyCritical)
				},
			},
			{
				Name: "consensus is not anomalous",
				Check: func(_ Params, h HostState) Verdict {
					const n = "consensus is not anomalous"
					// The compact's clause 5, in the words the operator
					// hashed. A rollback restarts the node, so it inherits the
					// boundary verbatim rather than a looser version of it.
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
			{
				Name: "disk headroom above floor",
				Check: func(_ Params, h HostState) Verdict {
					const n = "disk headroom above floor"
					// The upgrade's floor, not the restart's: this pulls an
					// image, and it may leave the node rebuilding a store from
					// the network afterwards.
					const floorPct = 15.0
					return diskHeadroomVerdict(n, floorPct, h)
				},
			},
		},
	}
}

// officialTargetPresentVerdict answers "on this host, or still published"
// for an official rollback target, by the digest the copy pins (#984).
//
// On this host is RollbackImaging's own reading, which for an official
// target is taken at that digest. Still published is the official
// repository still serving that digest: the tag pointing at it, or the
// registry answering for the digest itself after the tag has moved. A
// registry that cannot be reached refuses, and says that is why.
func officialTargetPresentVerdict(n, version string, im RollbackImaging, h HostState) Verdict {
	if im.RestoreDigest == "" {
		return Verdict{Name: n, Passed: false, Detail: "the copy this goes back to names the official image " +
			"without a digest, so there is no one official image to look for on this host or in the repository"}
	}
	if im.ImageLocal {
		return Verdict{Name: n, Passed: true, Detail: "the official image at " + im.RestoreDigest +
			" is already on this host, so this needs no registry"}
	}
	ok, why := h.OfficialDigestPublished(version, im.RestoreDigest)
	if ok {
		return Verdict{Name: n, Passed: true, Detail: "the official image at " + im.RestoreDigest +
			" is not on this host, but " + why}
	}
	return Verdict{Name: n, Passed: false, Detail: "the official image at " + im.RestoreDigest +
		" is not on this host, and " + why}
}
