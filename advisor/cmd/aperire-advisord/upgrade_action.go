package main

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/outage"
	"aperire-advisor/internal/runbook"
)

// The upgrade action — ADR 0016, amended again 2026-08-19.
//
// Operator ruling: "break glass should be one thing that allows things like
// upgrade, restarts, forensics." So an upgrade can be asked for in the drawer
// the way a restart is: the same first-turn gate, the same fleet table naming
// the node, the same confirm code and passkey under the answer that argued
// for it.
//
// The Upgrade CARD is unchanged and stays. This is an addition, not a
// replacement, and the difference from the restart's amendment is deliberate:
// the card was never the problem for an upgrade, because an upgrade card that
// exists is a card the operator went looking for. What was missing was the
// other door — an operator who starts by asking rather than by scrolling.
//
// Both doors reach ONE plan. planIdentity is the single derivation of plan_id,
// fingerprint and confirm code, shared with /v1/check, so a gate minted here
// and the card's gate for the same target are the same plan with the same
// code — and the page's own per-plan grant latch makes approving either one
// stand the other down.

// The upgrade's expected outage on a container host is measured, never a
// literal (#1014). It was "about 30 seconds offline once the restart begins",
// which is a container coming back up; a validator coming back into
// consensus was measured on a lab validator at about 7 and about 8.5 minutes, and
// the gate printed the 30 seconds over both. upgradeExpectationFor now takes
// this node's own measured sentence (internal/outage), the one the rollback
// gate and the run transcript read too.
//
// It is still NOT restartExpectation. That one is a lab measurement of a node
// returning from a cold store, and the two must not be swapped for each
// other, the mistake ADR 0016 named.

// upgradeExpectationNative is the same sentence's honest answer on a native
// host, and it is deliberately not a number (#528).
//
// NativeUpgradeSteps (advisor/internal/execute/execute.go) runs
// package-install in StagePrepare, before the restart step this act gates,
// and that step's own comment says plainly why: the package's maintainer
// scripts can restart the unit on their own, ahead of the runbook's restart
// step, so prepare is not outage-free the way a container's pull is. The
// restart step still guarantees the cutover regardless of what the scripts
// did, but there is no fixed duration behind it to report: the outage may
// already be over by the time this step runs, or may start here. Inventing
// a number for that would be the same mistake upgradeExpectation exists to
// avoid, aimed at the other deployment shape.
const upgradeExpectationNative = "no fixed offline window: the package install may restart the node on its own, and the restart step that follows completes the cutover regardless"

// upgradeExpectationFor is the one decision behind upgradePlan.Expected,
// pulled out of upgradePlanWith so it can be tested against the one fact it
// turns on (profile.Kind) without a live host, a runbook or a wrapper
// (#528). The same shape selfRestartNode already uses for this node's
// identity.
func upgradeExpectationFor(kind, measured string) string {
	if kind == "native" {
		return upgradeExpectationNative
	}
	return measured
}

// offlineExpectation is this node's measured outage, as one sentence, from
// the ledger this service writes (#1014).
func (s *server) offlineExpectation() string {
	return outage.FromLedgerFile(s.ledgerPath()).Sentence()
}

// upgradeRunbookID is RB-001's identifier, named once for the same reason
// restartRunbookID is: several behaviours key off it, and a typo in any of
// them fails by doing nothing.
const upgradeRunbookID = defaultRunbook

// upgradeAction refusal reasons. The first five are the restart's, by the
// same names and in the same order — one vocabulary for both acts, because
// the page renders one remedy per reason and two vocabularies would be two
// renderers drifting apart.
//
// upgradeRefusedWrongTarget is the sixth and belongs to this act alone: an
// upgrade names a version, and a version is the one thing in either action
// block that the model could otherwise invent.
const (
	upgradeRefusedWrongTarget = "wrong_target"
	// upgradeRefusedPlanUnavailable: this service could not evaluate the
	// upgrade at all. A seventh reason rather than a silent nil, because for
	// THIS act the state is reachable in ways the restart's is not:
	// resolveRunbookByID asks the release registry which version is current,
	// and that lookup can fail on the turn the operator says yes even though
	// it succeeded on the turn before (the cache is fifty seconds and the
	// turns are minutes apart), or return something BindParams refuses —
	// versionPattern accepts digits and dots only, so a registry publishing
	// a suffixed release fails every time.
	//
	// Silence there is the worst answer available: the operator has just
	// read a reply saying the upgrade is starting, and would get no gate, no
	// refusal, and nothing to do. The card path surfaces the same failure as
	// a 400 from /v1/check; this one must not be less honest than the door
	// beside it.
	upgradeRefusedPlanUnavailable = "plan_unavailable"
)

// upgradeActionInputs is everything the decision turns on, with no server, no
// host and no clock — so the matrix is a table rather than a deployment.
type upgradeActionInputs struct {
	// Role is askRequest.Role, stamped by the dashboard proxy.
	Role string
	// AskedNode is the model's node attribute, verbatim.
	AskedNode string
	// AskedTarget is the model's target attribute, already shape-checked and
	// v-stripped by interrogate.ParseAction.
	AskedTarget string
	// DerivedTarget is what /v1/check resolves for this host from the
	// release registry — the ONE authority on which version this is.
	DerivedTarget string
	// Self is who this Advisor serves.
	Self restartNode
	// CompactPermitsUpgrade is acc.Permits(runbook.ClassUpgrade).
	CompactPermitsUpgrade bool
	// WindowOpen is a break-glass window open on this node.
	WindowOpen bool
	// Blocked is the upgrade runbook's own blocked verdict for this target.
	Blocked bool
	// Rotating is a NuDB store rotation in flight on this node, read at
	// assessment time from the same wrapper verb the wrapper's own restart
	// guard reads. False when it could not be read, see RotationInFlight.
	Rotating bool
}

// decideUpgradeAction applies the refusals in the order that gives the
// operator the remedy they can act on next — the restart's order, with the
// target check inserted where it belongs.
//
//   - monitor first, for the reason decideRestartAction gives: telling a
//     monitor to break glass points at a control their role hides.
//   - the wrong node second: no window on THIS host authorises an act on
//     another one, so "break glass here" is the wrong answer to "upgrade
//     node2".
//   - the wrong target third, and ahead of the compact deliberately. A
//     mismatch means the model named a version this host did not derive, and
//     the plan the operator would be shown is not the plan they asked about.
//     Telling them to widen their compact first, and only then that the
//     version was wrong, is two ceremonies for one mistake.
//   - the compact fourth: breaking glass does not add a class.
//   - the node's own facts fifth: a store rotation in flight, then a blocked
//     precondition. Issue #387 extends issue #92's ruling (operator ruling
//     2026-09-15, restart-only at the time) to this act: this turn has
//     already read the node and knows the upgrade cannot happen, so a
//     no-window admin asking during a rotation is told so directly, rather
//     than sent to spend a passkey opening a window that a fact already read
//     makes pointless. decideUpgradeGate (turn one, no host read) still
//     answers break glass first and cannot see either fact. This is turn
//     two diverging from turn one on purpose, in the one case where turn two
//     knows something turn one cannot.
//   - break glass last. Reached only once the node's own facts have cleared,
//     so an upgrade that IS possible once a window opens is the only one
//     still asking the operator to open one.
//
// The rotation sits ahead of blocked for the reason decideRestartAction gives
// (issue #80): it is the shorter and more certain clock, and preconditions
// read DURING a rotation are partly reporting the rotation's own effects.
//
// An upgrade ends in a recreate, which is the same stop the wrapper refuses
// with exit 64 mid-rotation. approval.Spend fires on the attempt, not on the
// success, so the refusal belongs HERE, before any caller mints a gate, or it
// costs the operator a passkey ceremony to learn what this read already knew.
// Recreate has no separate door: the upgrade's cutover is the only way to
// reach it, so covering the upgrade covers it.
//
// This no longer calls decideUpgradeGate as a single unit: issue #387 needs
// rotating and blocked spliced between the compact check and the window
// check, which one call to decideUpgradeGate cannot express. The three
// conditions the two decisions share are reproduced here in the same
// relative order, so TestTheTwoUpgradeDecisionsNeverDisagree still holds
// with rotating and blocked both false, turn one's own view.
func decideUpgradeAction(in upgradeActionInputs) (reason string, ok bool) {
	if in.Role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !in.Self.namesThisNode(in.AskedNode) {
		return restartRefusedWrongNode, false
	}
	if !sameVersion(in.AskedTarget, in.DerivedTarget) {
		return upgradeRefusedWrongTarget, false
	}
	if !in.CompactPermitsUpgrade {
		return restartRefusedNotPermitted, false
	}
	if in.Rotating {
		return restartRefusedRotating, false
	}
	if in.Blocked {
		return restartRefusedBlocked, false
	}
	if !in.WindowOpen {
		return restartRefusedBreakGlass, false
	}
	return "", true
}

// decideUpgradeGate is the FIRST-turn question, before any assessment: may
// this person do this here at all? It knows nothing about a node, a plan or a
// version, because none of them exists yet.
//
// decideUpgradeAction runs the same three checks, in the same relative
// order, rather than calling this function directly, issue #387 needs the
// node's own facts spliced in between the compact check and the window
// check, which only turn two can see. That is the one case where the second
// turn's answer is allowed to diverge from the first turn's: this function
// still answers break glass first, because it has nothing else to go on.
func decideUpgradeGate(role string, compactPermitsUpgrade, windowOpen bool) (reason string, ok bool) {
	if role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !compactPermitsUpgrade {
		return restartRefusedNotPermitted, false
	}
	if !windowOpen {
		return restartRefusedBreakGlass, false
	}
	return "", true
}

// sameVersion compares what the model proposed with what this host derived.
//
// Exact, after trimming and dropping a leading "v" — the parser already
// strips one, and this repeats it so the comparison is right whether or not
// the value came through that parser. Nothing looser: "3.2" is not "3.2.1",
// and a prefix match would approve a plan for a version the operator did not
// read. An empty derived target is never equal to anything: a host that could
// not determine a release has no target to agree with, and defaulting to
// agreement there would let the release registry being unreachable authorise
// whatever the model happened to say.
func sameVersion(asked, derived string) bool {
	norm := func(v string) string {
		return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	}
	a, d := norm(asked), norm(derived)
	return a != "" && d != "" && a == d
}

// upgradePlan is one evaluation of RB-001 for one target, carrying both what
// the model may read and what only the operator's gate may hold.
type upgradePlan struct {
	Target   string
	Node     restartNode
	Verdicts []stageVerdict
	Blocked  bool
	// Rotating is a store rotation in flight, and RotationDetail is the
	// wrapper's own sentence about it. Carried beside Blocked rather than
	// folded into it, and deliberately NOT appended to Verdicts. The two have
	// different remedies (wait a few minutes, versus go and look at
	// something), and a refusal that renders the wrong remedy is worse than
	// one that renders none.
	Rotating       bool
	RotationDetail string
	// RotationRhythm is the sentence about how often this node's store
	// rotates, read only while one is running (#1058).
	RotationRhythm string
	Stages         []string
	Readings       host.Readings
	ReadErr        error
	Expected       string
	PlanID         string
	Fingerprint    string
	ConfirmCode    string
}

// upgradePlanFor evaluates the upgrade runbook exactly the way /v1/check does
// and mints the same identity from the same fingerprint call.
//
// target may be empty, which is the ordinary case for the assessment read:
// resolveRunbookByID then asks the release registry what the newest published
// release is, which is the same derivation the card displays. A caller with a
// target in hand (the action) passes it so the plan evaluated is the plan the
// operator was shown.
func (s *server) upgradePlanFor(ctx context.Context, target string) (upgradePlan, error) {
	profile, st, err := s.state(ctx)
	if err != nil {
		return upgradePlan{}, err
	}
	return s.upgradePlanWith(profile, st, target)
}

// upgradePlanWith is upgradePlanFor's body for a caller that has already
// discovered the host — considerUpgradeAction has, because it needs this
// node's own identity before it can decide whether the model named another.
// Discovering the profile twice in one turn is two answers to "what is this
// host" in a response whose whole job is to name it once.
func (s *server) upgradePlanWith(profile host.Profile, st *host.State, target string) (upgradePlan, error) {
	resolved, rb, params, _, err := s.resolveRunbookByID(st, upgradeRunbookID, planParams{Target: target})
	if err != nil {
		return upgradePlan{}, err
	}
	// Read here, in the ONE place both the model's assessment and the gate
	// decision are built from, so the sentence the model reads and the reason
	// the operator is given come from a single reading of the node. Two reads
	// of a state that moves is how an assessment saying "a rotation is
	// running" ends up beside a gate that offers the cutover anyway. Read
	// BEFORE the preconditions, because one of them now reads it too (#833):
	// the rotation row, at or past its window, takes this same reading
	// through rotationForVerdict rather than an older one.
	//
	// A failed read is logged and treated as not in flight, never returned as
	// an error: RotationInFlight fails open on purpose, and turning its error
	// into a failed plan would make an unreadable log block every upgrade.
	rotating, rotationDetail, roterr := s.rotationInFlightCached(st)
	if roterr != nil {
		log.Printf("[upgrade-action] the store-rotation state could not be read, treating it as not in flight: %v", roterr)
	}
	vs, blocked, _ := evaluateReadiness(rb, params, s.readinessHost(st))
	tag, terr := st.DeploymentTag()
	if terr != nil {
		tag = ""
	}
	readings, rerr := st.ReadingsWithTag(tag)
	// The identity this plan is signed against (#398): the container name on
	// a compose host, the unit on a native one. A profile that cannot name
	// its node returns no plan, rather than one signed against "".
	node, err := profile.IdentityKey()
	if err != nil {
		return upgradePlan{}, err
	}
	planID, fp, confirmCode := planIdentity(rb.ID, node, params)
	// Which sentence is true depends on which shape actually runs
	// (NativeUpgradeSteps vs UpgradeSteps in advisor/internal/execute), the
	// same fact selfRestartNode above already branches on for this node's
	// identity (#528).
	expected := upgradeExpectationFor(profile.Kind, s.offlineExpectation())
	return upgradePlan{
		Target:         resolved,
		Node:           s.selfRestartNode(profile),
		Verdicts:       vs,
		Blocked:        blocked,
		Rotating:       rotating,
		RotationDetail: rotationDetail,
		RotationRhythm: s.rotationRhythmWhile(rotating, st),
		// From the runbook, never a literal. RB-001 declares its own stages
		// and the page renders what it is told; a hardcoded pair here would
		// be a second opinion about a runbook that already has one.
		Stages:      rb.Stages,
		Readings:    readings,
		ReadErr:     rerr,
		Expected:    expected,
		PlanID:      planID,
		Fingerprint: fp,
		ConfirmCode: confirmCode,
	}, nil
}

// ── the read the model performs before it proposes ──────────────────────

// renderUpgradeAssessment renders the assessment for the model: what is
// running, what the deployment names, what is available, the preconditions,
// the two stages in plain words and the expected offline time.
//
// What is missing from it is the point, exactly as for the restart's:
// plan_id, fingerprint and confirm_code identify and authorise a plan, the
// model has no business holding any of them, and it does not need them.
func renderUpgradeAssessment(p upgradePlan) string {
	var b strings.Builder
	b.WriteString("UPGRADE ASSESSMENT — " + p.Node.Label)
	var id []string
	if p.Node.Hostname != "" {
		id = append(id, "host "+p.Node.Hostname)
	}
	if p.Node.Container != "" {
		id = append(id, "container "+p.Node.Container)
	}
	if p.Node.Role != "" {
		id = append(id, "role "+p.Node.Role)
	}
	if len(id) > 0 {
		b.WriteString(" (" + strings.Join(id, ", ") + ")")
	}
	b.WriteString("\nThis is the only node this Advisor can upgrade.\n\n")

	b.WriteString("readings\n")
	if p.ReadErr != nil {
		// The node not answering IS part of the assessment. Said here rather
		// than rendered as zeroes: absent is not zero, and a peer count of 0
		// nobody counted reads as a node with no peers.
		b.WriteString("  the node did not answer: " + p.ReadErr.Error() + "\n")
	} else {
		b.WriteString(renderRestartReadings(p.Readings))
	}
	b.WriteString("  target release available: " + strOrDash(p.Target) + "\n")

	b.WriteString("\nwhat an upgrade does here\n")
	b.WriteString("  two stages, one approval. " + strings.Join(p.Stages, " then ") +
		". prepare backs up the deployment file and the node config, then downloads and " +
		"verifies the release without touching anything running — it is reversible on its " +
		"own. cutover rewrites the deployment to the new tag and recreates the container, " +
		"and from that point going back is not one click.\n")
	b.WriteString("  expected: " + p.Expected + ". Past 15 minutes without rejoining, " +
		"the run reports \"restarted, still catching up\", which is not a failure.\n")

	b.WriteString("\npreconditions\n")
	for _, v := range p.Verdicts {
		line := "  " + word(v) + " — " + v.Name + ": " + v.Detail
		if v.Gates != "" {
			line += " (gates " + v.Gates + " only)"
		}
		b.WriteString(line + "\n")
	}
	// The rotation reads as a precondition to the model because that is what
	// it is: a check the service made before proposing, which refuses. It is
	// rendered here rather than added to Verdicts so the gate's own refusal
	// can carry its distinct remedy, and it is stated in BOTH branches so a
	// node with no rotation says so, instead of leaving the model to read an
	// absent line as an unmade measurement.
	if p.Rotating {
		b.WriteString("  REFUSES — store rotation: " + p.RotationDetail + "\n")
		b.WriteString("\nblocked: yes — a store rotation is in flight. Do not propose an upgrade: " +
			"the cutover recreates the container, the node would refuse to stop, and the operator's " +
			"approval would be spent on the attempt. Tell them to ask again once the rotation " +
			"finishes." + afterRotation(p.RotationRhythm) + "\n")
		return b.String()
	}
	// Absent is not zero. RotationInFlight fails open, so "not rotating" and
	// "could not be read" both arrive here as false, and only the wrapper's
	// detail line distinguishes them. Printing "pass" for the second would
	// state a measurement nobody made.
	if p.RotationDetail != "" {
		b.WriteString("  pass — store rotation: " + p.RotationDetail + "\n")
	} else {
		b.WriteString("  not measured — store rotation: the node's rotation state could not be read " +
			"on this host, so nothing here proves one is or is not running\n")
	}
	if p.Blocked {
		b.WriteString("\nblocked: yes — an upgrade cannot be proposed while a precondition refuses.\n")
	} else {
		b.WriteString("\nblocked: no\n")
	}
	return b.String()
}

func strOrDash(s string) string {
	if s == "" {
		return "not determined"
	}
	return s
}

// upgradeAssessmentResult is the Menu side of the read. Its source names the
// channel honestly: this is the service's own evaluation, not a wrapper call
// and not a dashboard read.
func (s *server) upgradeAssessmentResult(ctx context.Context) interrogate.Result {
	p, err := s.upgradePlanFor(ctx, "")
	if err != nil {
		return interrogate.Result{
			Status: interrogate.StatusFailed,
			Detail: "the upgrade assessment could not be evaluated: " + err.Error(),
			Source: "this service's own evaluation",
		}
	}
	return interrogate.Result{
		Status: interrogate.StatusOK,
		Body:   renderUpgradeAssessment(p),
		Source: "this service's own evaluation",
	}
}

// ── the proposal the operator sees ──────────────────────────────────────

// considerUpgradeAction turns a model's parsed <action kind="upgrade"/> into
// either the gate the page renders under that answer, or the one honest
// reason it cannot. Exactly one of the two is non-nil; both are nil only when
// this service could not read its own host, in which case there is nothing
// truthful to say about an upgrade at all.
func (s *server) considerUpgradeAction(ctx context.Context, a interrogate.ActionRequest, role string, asker ledger.Actor) (action, refused map[string]any) {
	profile, node, st, err := s.stateKeyed(ctx)
	if err != nil {
		// Named, never silent — the same contract plan_unavailable below
		// states: an operator who said yes must get a gate or a reason.
		log.Printf("[upgrade-action] the host could not be read: %v", err)
		return nil, map[string]any{
			"kind": interrogate.ActionKindUpgrade, "reason": upgradeRefusedPlanUnavailable,
			"detail": "the node's own state could not be read just now",
		}
	}
	// Evaluated with NO target, so the plan below carries the version this
	// host derives rather than the one the model proposed. That ordering is
	// what makes the comparison meaningful: evaluating the model's target and
	// then comparing it to itself would agree every time.
	plan, perr := s.upgradePlanWith(profile, st, "")
	if perr != nil {
		log.Printf("[upgrade-action] the upgrade plan could not be evaluated: %v", perr)
		// Named, with the reason, and still carrying this node's identity —
		// the profile above is what that comes from, so a plan that could
		// not be evaluated does not cost the operator the name of the host
		// they were asking about.
		return nil, map[string]any{
			"kind": interrogate.ActionKindUpgrade, "reason": upgradeRefusedPlanUnavailable,
			"node": s.selfRestartNode(profile), "detail": perr.Error(),
		}
	}

	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())

	reason, ok := decideUpgradeAction(upgradeActionInputs{
		Role:                  role,
		AskedNode:             a.Node,
		AskedTarget:           a.Target,
		DerivedTarget:         plan.Target,
		Self:                  plan.Node,
		CompactPermitsUpgrade: accErr == nil && acc.Permits(runbook.ClassUpgrade),
		WindowOpen:            windowOpen,
		Blocked:               plan.Blocked,
		Rotating:              plan.Rotating,
	})
	if !ok {
		return nil, s.withCompactReason(s.upgradeActionRefusal(reason, a, plan), reason, node, accErr)
	}

	// Recorded before the response is written, and as the ASKER — the Advisor
	// is proposing an act on a person's behalf, and the trail names the
	// person who asked for it. It is not an approval and grants nothing: the
	// passkey ceremony that follows writes its own approval.granted, and a
	// proposal nobody acts on stays in the record as a proposal nobody acted
	// on.
	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		l.AppendAs(ledger.KindActionProposed, plan.PlanID,
			"an upgrade of "+plan.Node.Label+" to "+plan.Target+" was proposed",
			map[string]any{
				"kind": interrogate.ActionKindUpgrade, "runbook": upgradeRunbookID,
				"target": plan.Target, "node": plan.Node.Label,
				"hostname": plan.Node.Hostname, "container": plan.Node.Container,
				"plan_id": plan.PlanID, "confirm_code": plan.ConfirmCode,
			}, asker)
	}

	return map[string]any{
		"kind": interrogate.ActionKindUpgrade, "runbook": upgradeRunbookID,
		"target": plan.Target, "node": plan.Node,
		"plan_id": plan.PlanID, "fingerprint": plan.Fingerprint,
		"confirm_code": plan.ConfirmCode,
		"verdicts":     plan.Verdicts, "expected": plan.Expected,
		"stages": plan.Stages,
	}, nil
}

// upgradeActionRefusal renders one refusal with the one remedy that follows
// from it. Every reason carries the node, because a refusal about an upgrade
// still has to say which node it is about.
func (s *server) upgradeActionRefusal(reason string, a interrogate.ActionRequest, plan upgradePlan) map[string]any {
	out := map[string]any{
		"kind": interrogate.ActionKindUpgrade, "reason": reason, "node": plan.Node,
	}
	switch reason {
	case restartRefusedWrongNode:
		out["asked_for"] = a.Node
		out["this_node"] = plan.Node.Label
		out["hostname"] = plan.Node.Hostname
	case upgradeRefusedWrongTarget:
		// Both versions, so the page can say the sentence with neither of
		// them guessed. This is the one refusal whose cause is the model
		// rather than the operator, and the remedy is to ask again — the
		// service's own derived target is right there in the message.
		out["asked_for"] = a.Target
		out["target"] = plan.Target
	case restartRefusedNotPermitted:
		out["command"] = s.reacceptCommand()
	case restartRefusedBlocked:
		out["verdicts"] = failingVerdicts(plan.Verdicts)
	case restartRefusedRotating:
		// The wrapper's own sentence, verbatim, because it carries how many
		// minutes the rotation has been running. "Try again later" without a
		// number is the kind of remedy an operator has to guess at.
		out["detail"] = plan.RotationDetail
	}
	return out
}

// considerUpgradeGate answers a first-turn <intent kind="upgrade"/> marker:
// the model has recognised an act, and the service says whether this person
// may take it here, in the same action_blocked vocabulary the second turn
// uses. Returns nil when they may.
//
// It performs no host read, for the reason considerRestartGate gives: the
// answer to "may you" does not depend on how the node is doing, and making
// the operator wait for a precondition sweep before being told to break glass
// would be the delay this exists to remove.
func (s *server) considerUpgradeGate(ctx context.Context, role string) map[string]any {
	node, keyErr := s.nodeKey(ctx)
	if keyErr != nil {
		// The reasoning is considerRestartGate's, #398: a gate keyed on ""
		// reports the wrong refusal to the operator.
		log.Printf("[upgrade-gate] no node identity to gate against: %v", keyErr)
		return map[string]any{
			"kind": interrogate.ActionKindUpgrade, "reason": upgradeRefusedPlanUnavailable,
			"detail": keyErr.Error(),
		}
	}
	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())
	reason, ok := decideUpgradeGate(role, accErr == nil && acc.Permits(runbook.ClassUpgrade), windowOpen)
	if ok {
		return nil
	}
	out := map[string]any{"kind": interrogate.ActionKindUpgrade, "reason": reason}
	if reason == restartRefusedNotPermitted {
		out["command"] = s.reacceptCommand()
	}
	return s.withCompactReason(out, reason, node, accErr)
}

// upgradeClassLine is the compact's own answer for the upgrade class, for the
// ASKER AND ACCESS block. Kept beside the restart's rather than folded into
// it: they are separate classes, an operator can hold one and not the other,
// and one line covering both would say something false on that host.
func upgradeClassLine(permitted bool) string {
	if permitted {
		return "  upgrade class: permitted by the operator compact accepted on this host\n"
	}
	return "  upgrade class: NOT permitted by the operator compact accepted on this host — " +
		"an upgrade is refused here until it is re-accepted with the wider class list\n"
}
