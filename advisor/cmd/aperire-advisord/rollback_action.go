package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/execute"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/rollback"
	"aperire-advisor/internal/runbook"
)

// The rollback action — ADR 0019, RB-004.
//
// The fourth act, and the only one whose parameter the service works out for
// itself. An upgrade's target comes from the release registry and a config
// change's value comes from the operator; a rollback's target comes from what
// this node did in the past — the tag inside the newest dated copy of its
// deployment file, cross-checked against the versions its own runs have
// completed on. internal/rollback holds that rule, pure; this file is where
// the readings it needs are taken and where the answer becomes either a gate
// or one honest refusal.
//
// The risk it carries is not the outage. It is that an older build may be
// unable to read the store a newer one wrote, which was observed on this
// fleet on 2026-08-06 and fails by never validating rather than by refusing
// to start. That is measured here, quoted from RB-001's own note, and shown
// above the confirm code — never a precondition, because a precondition made
// of it would refuse exactly the rollback that matters.

// rollbackRunbookID is RB-004's identifier, named once for the reason the
// other three are.
const rollbackRunbookID = "rollback-node"

// rollbackExpectation is the upgrade's measured outage with the one thing a
// rollback adds to it (#1014): the node may not be able to use its store and
// have to rebuild from the network. It used to carry "about seven when this
// was last measured", a figure from node1 on 2026-08-15, while the upgrade
// gate on the same node promised 30 seconds. Both now read this node's own
// restarts, so the two gates say the same thing about the same node.
//
// Still not restartExpectation, for the reason upgradeExpectationFor gives.
func rollbackExpectation(measured string) string {
	return measured + "; a rollback may also have to rebuild from the network, and the node " +
		"is not validating while it does"
}

// rollbackRefused* are RB-004's own refusals, taken from the derivation so
// the reason the page renders and the reason the rule reached are one string.
const (
	rollbackRefusedNoTarget  = rollback.RefusedNoTarget
	rollbackRefusedAmbiguous = rollback.RefusedAmbiguous
)

// ── the derivation ──────────────────────────────────────────────────────

// deriveRollback takes both readings and applies the rule.
//
// The run history is read from the ledger this service writes itself, so a
// node whose Advisor was installed after its last upgrade simply has none —
// which is a note on the derivation, not a refusal. The backups are read
// through the privilege wrapper; without them there is no target at all.
//
// A native host has no deployment file and so no dated copy of one to read
// through the wrapper, compose-backups is a container-only verb and refuses
// there by name (issue #393). What plays that role instead is
// packageChangeHistory: the wrapper's own before-and-after record of each
// completed package-install, which one upgrade is enough to produce, where
// the run-history sequence alone would need a second, earlier run before it
// could name anything, the gap that would have refused the rollback an
// operator asks for right after the upgrade that prompted it.
func (s *server) deriveRollback(st *host.State) (rollback.Derivation, error) {
	d, _, err := s.deriveRollbackCopy(st)
	return d, err
}

// restoreCopy is the dated copy a rollback restores and the digest it pins.
// Both empty when the derivation names none, which a native host never does.
type restoreCopy struct{ Name, Digest string }

// deriveRollbackCopy is deriveRollback plus the copy the derivation names,
// taken off the SAME rows (#1029, review). A door that derived the target
// here and then read the copy in a second reading could pass the gate and
// fail the second read, and an empty copy is a different plan: the run then
// told the operator the node's answer had changed when it had only failed to
// answer twice.
func (s *server) deriveRollbackCopy(st *host.State) (rollback.Derivation, restoreCopy, error) {
	running, err := st.RunningVersion()
	if err != nil {
		return rollback.Derivation{}, restoreCopy{}, fmt.Errorf(
			"the node did not say what version it is running, so there is nothing to roll back from: %w", err)
	}
	if st.Kind() == "native" {
		return rollback.DeriveNative(running, s.packageChangeHistory(), s.versionHistory()), restoreCopy{}, nil
	}
	rows, err := st.ComposeBackups()
	if err != nil {
		return rollback.Derivation{}, restoreCopy{}, fmt.Errorf(
			"the deployment's dated copies could not be read, so no rollback target can be derived: %w", err)
	}
	// Where each copy's image came from, so a source switch can be told from
	// a version change (#682): the same conversion the command line uses.
	d := rollback.Derive(running, host.DerivationBackups(rows), s.versionHistory())
	name, digest := host.RestoreCopyOf(d, rows)
	return d, restoreCopy{name, digest}, nil
}

// versionHistory is every version a run on this node has COMPLETED on, read
// by the one rule both binaries share (host.VersionHistory, #1029).
func (s *server) versionHistory() []rollback.Completion {
	return host.VersionHistory(s.ledgerPath())
}

// packageChangeHistory is DeriveNative's preferred source, issue #393's
// derivation half. (Its other half, keeping the previous .deb/.rpm beside the
// config backups so a rollback needs no repository at all, is still unbuilt;
// see the note on RB-004's "the rollback target is installable" precondition.)
//
// The wrapper's package-install verb prints "before -> after", and
// executeStage records that whole output verbatim in the step.succeeded
// entry the install itself writes, with no extra capture needed: the value
// is already on the ledger the moment the install completes. This reads it
// back, rather than adding a second, parallel place that value would have to
// be written for a later, separate rollback request to find it.
//
// A ledger that cannot be read yields nothing rather than an error, the same
// rule versionHistory follows: an absent or unreadable history is
// uncorroborated, not a fault.
func (s *server) packageChangeHistory() []rollback.PackageChange {
	entries, err := ledger.Entries(s.ledgerPath())
	if err != nil && len(entries) == 0 {
		return nil
	}
	var out []rollback.PackageChange
	entries, dropped := ledger.WithCarried(entries)
	for _, d := range dropped {
		log.Printf("[ledger] %s", d)
	}
	for _, e := range entries {
		if e.Kind != ledger.KindStepSucceeded {
			continue
		}
		if verb, _ := e.Data["verb"].(string); verb != "package-install" {
			continue
		}
		text, _ := e.Data["output"].(string)
		from, to, ok := parsePackageInstallOutput(text)
		if !ok {
			continue
		}
		out = append(out, rollback.PackageChange{From: from, To: to, At: e.At})
	}
	return out
}

// parsePackageInstallOutput reads the wrapper's package-install answer for
// its "before -> after" line, the same line verifyPackageInstalled checks
// at run time (there with Contains, not "must be the last line"), read back
// here from the ledger's own record of it.
//
// Scanned for the LAST line matching the shape, rather than requiring it be
// the file's last line outright: the package manager's own install output is
// redirected to stderr in the wrapper script, so in the ordinary case the
// before/after printf really is last, but whether a caller's Runner keeps
// that ordering under combined stdout/stderr capture is not this function's
// business to assume.
//
// dpkg and rpm both report a release suffix this line's two sides do not
// share with server_info's build_version, "3.3.0-1" from dpkg-query,
// "3.3.0-1.el9" from rpm, against "3.3.0" from the node itself, the same
// shape the wrapper's own pkg_match resolves a bare version against
// ("exactly this version, or this version followed by a dash"). Both sides
// are normalised through host.NormalizeVersion, the same function
// RunningVersion already applies to server_info's answer, so a value
// compared against `running` or bound as `target_version` is in the one
// shape both of those already expect.
func parsePackageInstallOutput(out string) (from, to string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, "->", 2)
		if len(parts) != 2 {
			continue
		}
		f := host.NormalizeVersion(strings.TrimSpace(parts[0]))
		t := host.NormalizeVersion(strings.TrimSpace(parts[1]))
		if f == "" || t == "" {
			continue
		}
		from, to, ok = f, t, true
	}
	return from, to, ok
}

// ── the assessment the model reads ──────────────────────────────────────

// rollbackAssessment is what the model is given: what is running, what it
// would go back to, where that came from, and what it costs. It carries no
// plan_id, no fingerprint and no confirm code, exactly as the other three do
// not.
func rollbackAssessment(st *host.State, d rollback.Derivation, deploymentTag, measured string) map[string]any {
	out := map[string]any{
		"expected":     rollbackExpectation(measured),
		"running":      d.Running,
		"target":       d.Target,
		"from_backup":  d.BackupName,
		"from_history": d.FromHistory,
		"store":        d.Store,
		"store_detail": d.StoreDetail,
	}
	if !d.BackupAt.IsZero() {
		out["backup_at"] = d.BackupAt.UTC()
		out["backup_age"] = humanDuration(int(time.Since(d.BackupAt).Seconds()))
	}
	if !d.ChangedAt.IsZero() {
		out["changed_at"] = d.ChangedAt.UTC()
		out["in_place_for"] = humanDuration(int(time.Since(d.ChangedAt).Seconds()))
	}
	if d.Refusal != "" {
		out["refusal"] = d.Refusal
		out["refusal_detail"] = d.Detail
	}
	if d.Note != "" {
		out["note"] = d.Note
	}

	r, rerr := st.ReadingsWithTag(deploymentTag)
	if rerr != nil {
		out["readings"] = host.Readings{}
		out["concerns"] = []concern{{
			Name:   "the node could not be read",
			Detail: rerr.Error(),
			State:  stateUndetermined,
		}}
		return out
	}
	out["readings"] = r
	// The amendment reading, taken once and shared. The State memoises it,
	// so the concern below and the precondition the gate evaluates are one
	// answer rather than two reads that can disagree (#676).
	//
	// Not asked at all when the derivation refused: there is no target to
	// ask about, no preconditions are evaluated on that path either, and a
	// question about the empty string would come back as a reading of
	// something. Unmeasured is the honest state there, and it is what the
	// concern renders.
	amendments := runbook.Measurement{Unmeasured: true,
		Detail: "not measured: there is no rollback target to check"}
	if d.Target != "" {
		amendments = st.RollbackSafeFromAmendments(d.Target)
	}
	out["concerns"] = rollbackConcerns(r, d, amendments)
	return out
}

// rollbackConcerns is the amber material. The store risk leads it, because it
// is the one an operator would regret not reading.
func rollbackConcerns(r host.Readings, d rollback.Derivation, amendments runbook.Measurement) []concern {
	var out []concern
	switch d.Store {
	case rollback.StoreWritten:
		out = append(out, concern{
			Name:   "the newer build has written this node's data store",
			Detail: d.StoreDetail + ". " + runbook.StoreRiskLesson,
			State:  stateConcern,
		})
	case rollback.StoreUnknown:
		out = append(out, concern{
			Name: "whether the newer build has written this node's data store could not be determined",
			Detail: d.StoreDetail + ". " + runbook.StoreRiskLesson +
				" This is unknown rather than fine.",
			State: stateUndetermined,
		})
	}
	// The resync, measured. Its own concern rather than a line in the
	// expectation, because it is the difference between this act and the
	// upgrade it reverses.
	out = append(out, concern{
		Name: "a rollback may have to rebuild from the network",
		Detail: "rolling this fleet's node1 back on 2026-08-15 came up with complete_ledgers " +
			"empty and took about seven minutes to reach full. The node is not in consensus " +
			"for that window.",
		State: stateConcern,
	})
	// The second candidate cause of the failure this act's whole warning is
	// about, ADR 0019 §10. An amendment enabled on the network since the
	// target was current can leave that build amendment-blocked coming
	// back, which presents exactly as the store problem does: started,
	// peered, never validated.
	//
	// This block used to say, always, that nothing had checked it. That was
	// true when it was written and stopped being true with #668, which
	// reads the target's own recorded `feature` reply. It is the SAME
	// verdict the precondition renders, handed in rather than re-derived,
	// so the two surfaces of one gate cannot tell an operator different
	// things (#676).
	out = append(out, amendmentConcernFrom(d, amendments))
	switch {
	case d.SourceRollback && d.Note != "":
		// A source rollback's note is not a gap in the evidence (#999). The
		// derivation cleared the history agreement on purpose, because the
		// release does not move, and the note says what does: where the
		// image comes from, and that the whole dated copy goes back with
		// its arguments and mounts. Measured, and worth reading before the
		// approval, so it is a concern under its own name.
		out = append(out, concern{
			Name:   "this rollback changes where the image comes from, not the release",
			Detail: d.Note,
			State:  stateConcern,
		})
	case d.Note != "":
		out = append(out, concern{
			Name:   "the target is derived from one source rather than two",
			Detail: d.Note,
			State:  stateUndetermined,
		})
	}
	if r.Peers < 5 {
		out = append(out, concern{
			Name: "peers below baseline",
			Detail: fmt.Sprintf("%d peers. A node rebuilding from a low peer count takes longer "+
				"to come back, and this act may have it rebuilding from the network.", r.Peers),
			State: stateConcern,
		})
	}
	return out
}

// amendmentConcernFrom renders the gate's own amendment verdict as the
// concern above the approve button. Four states, because there are four
// answers, and each reads the way its precondition does (#676):
//
//   - the record covers the target: clear, and the precondition passes;
//   - the check refused on what it read (the record says the target lacks
//     an enabled amendment, the node is blocked now, or an amendment is
//     past its window): a concern that says the gate refuses, never
//     "undetermined", because the precondition is a definite REFUSES;
//   - there is no record for the target: undetermined, and it says the gate
//     refuses for that reason, which is what the precondition's
//     "NOT MEASURED, refuses" says;
//   - the node would not answer at all: undetermined, and the precondition
//     reads "not measured" and lets it through.
func amendmentConcernFrom(d rollback.Derivation, m runbook.Measurement) concern {
	switch {
	case m.Unproven:
		return concern{
			Name: "whether the target supports every enabled amendment is unproven, so this rollback is refused",
			Detail: m.Detail + ". An amendment enabled since " + target(d) + " was current can leave " +
				"that build amendment-blocked on the way back, and it fails the same way the data " +
				"store does: started, peered, never validating.",
			State: stateUndetermined,
		}
	case m.Unmeasured:
		return concern{
			Name: "whether the target still supports every enabled amendment was not measured",
			Detail: m.Detail + ". An amendment enabled since " + target(d) + " was current can leave " +
				"that build amendment-blocked on the way back, and it fails the same way the data " +
				"store does: started, peered, never validating.",
			State: stateUndetermined,
		}
	case m.OK:
		return concern{
			Name:   "the target's own record says it supports every enabled amendment",
			Detail: m.Detail + ". So this rollback is not expected to come back amendment blocked.",
			State:  stateClear,
		}
	default:
		return concern{
			Name: "the amendment check refuses this rollback",
			Detail: m.Detail + ". A build that comes back blocked fails the same way the data store " +
				"does: started, peered, never validating.",
			State: stateConcern,
		}
	}
}

// target names the version a concern is about, falling back to a phrase
// rather than an empty gap when the derivation refused and there is none.
func target(d rollback.Derivation) string {
	if d.Target == "" {
		return "the target"
	}
	return d.Target
}

// renderRollbackAssessment is the assessment as the model reads it.
func renderRollbackAssessment(p rollbackPlan) string {
	var b strings.Builder
	b.WriteString("ROLLBACK ASSESSMENT — " + p.Node.Label)
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
	b.WriteString("\nThis is the only node this Advisor can roll back.\n\n")

	a := p.Assessment
	b.WriteString("what a rollback would do here\n")
	fmt.Fprintf(&b, "  running now: %s\n", strOrDash(str(a["running"])))
	if p.Derivation.Refusal != "" {
		fmt.Fprintf(&b, "  target: NONE — %s\n", str(a["refusal_detail"]))
		fmt.Fprintf(&b, "  refusal: %s\n", str(a["refusal"]))
		b.WriteString("\nThere is nothing to propose. Say this plainly and stop; do not offer a " +
			"version of your own.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "  would roll back to: %s\n", strOrDash(str(a["target"])))
	if p.Derivation.SourceRollback {
		// Named outright (#1012). Without it the model read "running 3.4.1,
		// would roll back to 3.4.1" as no rollback at all, wrote a block with
		// no target, and then remembered that a same-release change "is not a
		// rollback". It is one, and this is the line that says so.
		fmt.Fprintf(&b, "  kind: a SOURCE rollback. The release does not move, and this is still a "+
			"rollback: %s. The action block carries target=\"%s\".\n",
			strOrDash(p.Derivation.Note), p.Target)
	}
	// Measured now, and it outranks anything recalled about the target. A
	// note this Advisor wrote earlier saying there is no target, or that a
	// same-release change is not a rollback, is its own past guess; this
	// derivation is the node's present answer (#1012). Scoped to the target:
	// whether the rollback can run right now is the preconditions' to say
	// below, and a note about that may well be true.
	b.WriteString("  This target was derived just now. If anything RECALLED says this node has no " +
		"rollback target, or that this is not a rollback, that note is wrong: say so in one line " +
		"and go on from this assessment.\n")
	fmt.Fprintf(&b, "  derived from: the dated deployment copy %s", strOrDash(str(a["from_backup"])))
	if age := str(a["backup_age"]); age != "" {
		fmt.Fprintf(&b, " (%s old)", age)
	}
	b.WriteString("\n")
	if fh := str(a["from_history"]); fh != "" {
		fmt.Fprintf(&b, "  this node's own run history agrees: it was on %s before %s\n",
			fh, str(a["running"]))
	} else {
		b.WriteString("  this node's run history records no version change, so the target is " +
			"not corroborated by it\n")
	}
	if ip := str(a["in_place_for"]); ip != "" {
		fmt.Fprintf(&b, "  the running build has been in place for %s\n", ip)
	}
	fmt.Fprintf(&b, "  data store: %s — %s\n", str(a["store"]), str(a["store_detail"]))

	b.WriteString("\nreadings\n")
	if r, ok := a["readings"].(host.Readings); ok {
		b.WriteString(renderRestartReadings(r))
	}
	b.WriteString("\nexpected: " + str(a["expected"]) + "\n")

	b.WriteString("\nconcerns\n")
	concerns, _ := a["concerns"].([]concern)
	if len(concerns) == 0 {
		b.WriteString("  none\n")
	}
	for _, c := range concerns {
		b.WriteString("  [" + c.State + "] " + c.Name + " — " + c.Detail + "\n")
	}

	b.WriteString("\npreconditions\n")
	for _, v := range p.Verdicts {
		b.WriteString("  " + word(v) + " — " + v.Name + ": " + v.Detail + "\n")
	}
	// The rotation reads as a precondition to the model because that is what
	// it is: a check the service made before proposing, which refuses. It is
	// rendered here rather than added to Verdicts so the gate's own refusal
	// can carry its distinct remedy, and it is stated in BOTH branches so a
	// node with no rotation says so, instead of leaving the model to read an
	// absent line as an unmade measurement.
	if p.Rotating {
		b.WriteString("  REFUSES — store rotation: " + p.RotationDetail + "\n")
		b.WriteString("\nblocked: yes — a store rotation is in flight. Do not propose a rollback: " +
			"it recreates the container, the node would refuse to stop, and the operator's approval " +
			"would be spent on the attempt. Tell them to ask again once the rotation finishes." +
			afterRotation(p.RotationRhythm) + "\n")
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
		b.WriteString("\nblocked: yes — a rollback cannot be proposed while a precondition refuses.\n")
	} else {
		b.WriteString("\nblocked: no\n")
	}
	return b.String()
}

// str reads a string out of the assessment map without a type assertion at
// every call site. An absent key renders as empty, which the callers above
// turn into "not determined" where that is the honest word.
func str(v any) string {
	s, _ := v.(string)
	return s
}

// rollbackAssessmentResult is the Menu side of the read.
func (s *server) rollbackAssessmentResult(ctx context.Context) interrogate.Result {
	p, err := s.rollbackPlanFor(ctx, assessmentProbeIntent)
	if err != nil {
		return interrogate.Result{
			Status: interrogate.StatusFailed,
			Detail: "the rollback assessment could not be evaluated: " + err.Error(),
			Source: "this service's own evaluation",
		}
	}
	return interrogate.Result{
		Status: interrogate.StatusOK,
		Body:   renderRollbackAssessment(p),
		Source: "this service's own evaluation",
	}
}

// assessmentProbeIntent binds a plan so the preconditions can be evaluated at
// all, for the reason RB-003's probe key and value exist: BindParams requires
// every declared parameter, and a runbook with unbound parameters evaluates
// nothing.
//
// Nothing downstream sees it. No confirm code reaches the operator from the
// assessment, and the plan they approve is evaluated again with the intent
// the model actually proposed.
const assessmentProbeIntent = "operator-judgement"

// ── the plan ────────────────────────────────────────────────────────────

// rollbackPlan is one evaluation of RB-004 for one intent, carrying the
// derivation it was built from.
type rollbackPlan struct {
	Intent     string
	Target     string
	Derivation rollback.Derivation
	Node       restartNode
	Verdicts   []stageVerdict
	Blocked    bool
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
	Assessment     map[string]any
	PlanID         string
	Fingerprint    string
	ConfirmCode    string
}

func (s *server) rollbackPlanFor(ctx context.Context, intent string) (rollbackPlan, error) {
	profile, st, err := s.state(ctx)
	if err != nil {
		return rollbackPlan{}, err
	}
	return s.rollbackPlanWith(profile, st, intent)
}

// rollbackPlanWith is rollbackPlanFor's body for a caller that has already
// discovered the host — considerRollbackAction has, for the reason the other
// three actions have.
//
// A derivation that refuses still produces a plan: it carries the node's
// identity, the assessment and the refusal, and no fingerprint. Returning an
// error there would cost the operator the name of the host they asked about.
func (s *server) rollbackPlanWith(profile host.Profile, st *host.State, intent string) (rollbackPlan, error) {
	d, derr := s.deriveRollback(st)
	if derr != nil {
		return rollbackPlan{}, derr
	}
	tag, terr := st.DeploymentTag()
	if terr != nil {
		tag = ""
	}
	// Read here, in the ONE place both the model's assessment and the gate
	// decision are built from, so the sentence the model reads and the reason
	// the operator is given come from a single reading of the node. Taken
	// above the refusal return below, so a plan with no target still carries
	// what was measured rather than carrying a false "not rotating".
	//
	// A failed read is logged and treated as not in flight, never returned as
	// an error: RotationInFlight fails open on purpose, and turning its error
	// into a failed plan would make an unreadable log block every rollback,
	// which is the recovery path that must never lock an operator out.
	rotating, rotationDetail, roterr := s.rotationInFlightCached(st)
	if roterr != nil {
		log.Printf("[rollback-action] the store-rotation state could not be read, treating it as not in flight: %v", roterr)
	}
	p := rollbackPlan{
		Intent:         intent,
		Target:         d.Target,
		Derivation:     d,
		Node:           s.selfRestartNode(profile),
		Rotating:       rotating,
		RotationDetail: rotationDetail,
		RotationRhythm: s.rotationRhythmWhile(rotating, st),
		Assessment:     rollbackAssessment(st, d, tag, s.offlineExpectation()),
	}
	if d.Refusal != "" {
		// Nothing binds without a target, so there are no preconditions to
		// evaluate and no plan identity to mint. Blocked is left false on
		// purpose: this is not a host that refuses the act, it is a node
		// with nothing to roll back to, and the two read differently.
		return p, nil
	}
	_, rb, params, _, err := s.resolveRunbookByID(st, rollbackRunbookID,
		planParams{Target: d.Target, Intent: intent})
	if err != nil {
		return rollbackPlan{}, err
	}
	vs, blocked, _ := evaluateReadiness(rb, params, s.readinessHost(st))
	p.Verdicts, p.Blocked = vs, blocked
	// The identity this plan is signed against (#398): the container name on
	// a compose host, the unit on a native one. A profile that cannot name
	// its node returns no plan, rather than one signed against "".
	node, err := profile.IdentityKey()
	if err != nil {
		return rollbackPlan{}, err
	}
	p.PlanID, p.Fingerprint, p.ConfirmCode = planIdentity(rb.ID, node, params)
	return p, nil
}

// rollbackTargetGate re-derives this node's rollback target and answers the
// refusal for an ask the derivation does not agree with, or nil (#966, #998).
//
// Every door a rollback passes through asks it: the plan, the check, the
// approval's begin and finish, and the run. Binding alone accepts any
// version of the right shape, and RB-004's preconditions are not built to
// refuse a target nobody derived: an older release this node holds an
// amendment record for can pass them all, and the store-format risk is a
// concern, never a refusal. A derivation that cannot be taken refuses too,
// with its own error: no target can be vouched for on a node whose history
// could not be read.
func (s *server) rollbackTargetGate(st *host.State, asked string) (rollback.Derivation, map[string]any) {
	d, _, refusal := s.rollbackTargetGateCopy(st, asked)
	return d, refusal
}

// rollbackTargetGateCopy is the gate plus the copy its derivation names, for
// the ceremony doors and the run: they bind that copy into the plan rather
// than reading the host a second time (#1029, review).
func (s *server) rollbackTargetGateCopy(st *host.State, asked string) (rollback.Derivation, restoreCopy, map[string]any) {
	d, cp, err := s.deriveRollbackCopy(st)
	if err != nil {
		return d, restoreCopy{}, map[string]any{
			"error":     "no rollback target could be derived on this node, so nothing is planned or approved for " + asked + ": " + err.Error(),
			"reason":    upgradeRefusedPlanUnavailable,
			"asked_for": asked,
		}
	}
	return d, cp, rollbackPlanRefusal(asked, d)
}

// recordRollbackTargetRefusal writes a door's refusal to the ledger: which
// door, the reason, the target asked for and the one this node derives. An
// approval or a run refused for its target is a decision about a validator,
// and the record keeps it the way it keeps every other refusal (review of
// PR #1000, L3). Existing kinds: approval.refused at the approval,
// executor.refused at the run.
func (s *server) recordRollbackTargetRefusal(kind ledger.Kind, door string, refusal map[string]any, who ledger.Actor) {
	l, err := ledger.Open(s.ledgerPath())
	if err != nil || l == nil {
		log.Printf("[rollback-target] %s refused %v and the ledger could not be opened: %v", door, refusal["asked_for"], err)
		return
	}
	data := map[string]any{"door": door, "runbook": rollbackRunbookID}
	for _, k := range []string{"reason", "asked_for", "target", "error"} {
		if v, ok := refusal[k]; ok {
			data[k] = v
		}
	}
	summary := fmt.Sprintf("%s refused: a rollback to %v is not this node's derived target", door, refusal["asked_for"])
	if t, ok := refusal["target"]; ok {
		summary += fmt.Sprintf(" (%v)", t)
	}
	l.AppendAs(kind, "", summary, data, who)
}

// rollbackPlanRefusal is /v1/plan's answer to a rollback asked for by a
// target this node did not derive, or nil when the two agree (#966).
//
// The fields are rollbackActionRefusal's own: reason, asked_for, and the
// target this node would use. "error" carries the sentence, because that is
// the field every reader of a refused plan already renders.
func rollbackPlanRefusal(asked string, d rollback.Derivation) map[string]any {
	if d.Refusal != "" {
		return map[string]any{
			"error":     "there is no rollback target for this node, so no plan is made for " + asked + ": " + d.Detail,
			"reason":    d.Refusal,
			"asked_for": asked,
		}
	}
	if !sameVersion(asked, d.Target) {
		return map[string]any{
			"error": asked + " is not this node's rollback target. The target derived from its own " +
				"deployment history is " + d.Target + ", and a rollback plan is made for that one only",
			"reason":    upgradeRefusedWrongTarget,
			"asked_for": asked,
			"target":    d.Target,
		}
	}
	return nil
}

// ── the decision ────────────────────────────────────────────────────────

type rollbackActionInputs struct {
	Role      string
	AskedNode string
	Self      restartNode
	// AskedTarget is the model's target attribute, already shape-checked by
	// interrogate.ParseAction.
	AskedTarget string
	// DerivedTarget is what this host worked out from its own backups and run
	// history. Empty when the derivation refused.
	DerivedTarget string
	// DerivationRefusal is rollback.RefusedNoTarget or RefusedAmbiguous, or
	// empty. It precedes the target comparison: a model that named a version
	// on a node with no derivable target should be told there is nothing to
	// roll back to, not that its version disagreed with a blank.
	DerivationRefusal     string
	CompactPermitsUpgrade bool
	WindowOpen            bool
	Blocked               bool
	// Rotating is a NuDB store rotation in flight on this node, read at
	// assessment time from the same wrapper verb the wrapper's own restart
	// guard reads. False when it could not be read, see RotationInFlight.
	Rotating bool
}

// decideRollbackAction applies the refusals in the order that gives the
// operator the remedy they can act on next — the upgrade's order, with the
// derivation's own refusals inserted ahead of the target check.
//
//   - monitor first, for the reason decideRestartAction gives.
//   - the wrong node second: no window on THIS host authorises an act on
//     another one.
//   - the derivation third. "There is nothing to roll back to" and "the two
//     records disagree" are facts about this node that no ceremony changes,
//     and telling an operator to widen their compact before telling them
//     that is two ceremonies for one dead end.
//   - the wrong target fourth: the model named a version this host did not
//     derive, so the plan the operator would be shown is not the one they
//     asked about.
//   - the compact fifth: breaking glass does not add a class.
//   - the node's own facts sixth: a store rotation in flight, then a blocked
//     precondition. Issue #387 extends issue #92's ruling (operator ruling
//     2026-09-15, restart-only at the time) to this act: this turn has
//     already read the node and knows the rollback cannot happen, so a
//     no-window admin asking during a rotation is told so directly, rather
//     than sent to spend a passkey opening a window that a fact already read
//     makes pointless. decideRollbackGate (turn one, no host read) still
//     answers break glass first and cannot see either fact. This is turn
//     two diverging from turn one on purpose, in the one case where turn two
//     knows something turn one cannot.
//   - break glass last. Reached only once the node's own facts have cleared,
//     so a rollback that IS possible once a window opens is the only one
//     still asking the operator to open one.
//
// The rotation sits ahead of blocked for the reason decideRestartAction gives
// (issue #80): it is the shorter and more certain clock, and preconditions
// read DURING a rotation are partly reporting the rotation's own effects.
//
// A rollback recreates the container, which is the stop the wrapper refuses
// with exit 64 mid-rotation. approval.Spend fires on the attempt, not on the
// success, so the refusal belongs HERE, before any caller mints a gate, or it
// costs the operator a passkey ceremony to learn what this read already knew.
// It matters most on this act: a rollback is what someone reaches for
// when the node is already misbehaving, and that is the worst moment to spend
// their approval on an attempt that cannot start.
//
// This no longer calls decideRollbackGate as a single unit: issue #387 needs
// rotating and blocked spliced between the compact check and the window
// check, which one call to decideRollbackGate cannot express. The three
// conditions the two decisions share are reproduced here in the same
// relative order, so TestTheTwoRollbackDecisionsNeverDisagree still holds
// with rotating and blocked both false, turn one's own view.
func decideRollbackAction(in rollbackActionInputs) (reason string, ok bool) {
	if in.Role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !in.Self.namesThisNode(in.AskedNode) {
		return restartRefusedWrongNode, false
	}
	if in.DerivationRefusal != "" {
		return in.DerivationRefusal, false
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

// decideRollbackGate is the first-turn question, and it is the upgrade's
// three conditions unchanged — a rollback is permitted by the UPGRADE class,
// because it changes the node's version, which is what that class covers
// (runbook.go's own definition: "upgrade and roll back").
func decideRollbackGate(role string, compactPermitsUpgrade, windowOpen bool) (reason string, ok bool) {
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

// ── the proposal the operator sees ──────────────────────────────────────

// considerRollbackAction turns a model's parsed <action kind="rollback"/>
// into either the gate the page renders under that answer, or the one honest
// reason it cannot.
func (s *server) considerRollbackAction(ctx context.Context, a interrogate.ActionRequest, role string, asker ledger.Actor) (action, refused map[string]any) {
	profile, node, st, err := s.stateKeyed(ctx)
	if err != nil {
		// Named, never silent — the same contract the plan_unavailable
		// branch below states: an operator who said yes must get a gate or
		// a reason.
		log.Printf("[rollback-action] the host could not be read: %v", err)
		return nil, map[string]any{
			"kind": interrogate.ActionKindRollback, "reason": upgradeRefusedPlanUnavailable,
			"detail": "the node's own state could not be read just now",
		}
	}
	plan, perr := s.rollbackPlanWith(profile, st, a.Intent)
	if perr != nil {
		log.Printf("[rollback-action] the rollback plan could not be evaluated: %v", perr)
		// Named rather than silent, for the reason the upgrade's
		// plan_unavailable exists: the operator has just read a reply saying
		// the rollback is starting, and silence would leave them with no
		// gate, no refusal and nothing to do.
		return nil, map[string]any{
			"kind": interrogate.ActionKindRollback, "reason": upgradeRefusedPlanUnavailable,
			"node": s.selfRestartNode(profile), "detail": perr.Error(),
		}
	}

	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())

	// A block that named no target asks for the one this node derives
	// (#1012). Filled from THIS evaluation's derivation, the same one the
	// gate below names, so what the operator approves is the node's answer
	// and never the model's. When the derivation refused there is no target
	// to fill, and the derivation's own refusal answers first below.
	asked, targetFrom := rollbackAskedTarget(a, plan.Target)

	reason, ok := decideRollbackAction(rollbackActionInputs{
		Role:                  role,
		AskedNode:             a.Node,
		Self:                  plan.Node,
		AskedTarget:           asked,
		DerivedTarget:         plan.Target,
		DerivationRefusal:     plan.Derivation.Refusal,
		CompactPermitsUpgrade: accErr == nil && acc.Permits(runbook.ClassUpgrade),
		WindowOpen:            windowOpen,
		Blocked:               plan.Blocked,
		Rotating:              plan.Rotating,
	})
	if !ok {
		return nil, s.withCompactReason(s.rollbackActionRefusal(reason, a, plan), reason, node, accErr)
	}

	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		l.AppendAs(ledger.KindActionProposed, plan.PlanID,
			"a rollback of "+plan.Node.Label+" from "+plan.Derivation.Running+
				" to "+plan.Target+" was proposed",
			map[string]any{
				"kind": interrogate.ActionKindRollback, "runbook": rollbackRunbookID,
				"target": plan.Target, "from": plan.Derivation.Running,
				"intent": plan.Intent, "node": plan.Node.Label,
				"hostname": plan.Node.Hostname, "container": plan.Node.Container,
				// Where the target came from, in the record. A rollback
				// derived from a file nobody can name afterwards is a version
				// change with no evidence behind it.
				"from_backup":  plan.Derivation.BackupName,
				"from_history": plan.Derivation.FromHistory,
				"store":        plan.Derivation.Store,
				"plan_id":      plan.PlanID, "confirm_code": plan.ConfirmCode,
				// Whether the Advisor's block named this version or left it
				// to the node. Either way it is the derived one; the record
				// says which, so an audit can tell the two apart.
				"target_from": targetFrom,
			}, asker)
	}

	return map[string]any{
		"kind": interrogate.ActionKindRollback, "runbook": rollbackRunbookID,
		"target": plan.Target, "from": plan.Derivation.Running,
		"intent": plan.Intent, "node": plan.Node,
		"plan_id": plan.PlanID, "fingerprint": plan.Fingerprint,
		"confirm_code": plan.ConfirmCode,
		"target_from":  targetFrom,
		// The scope is named by the service, not chosen by the page. One
		// stage, one scope, no compound: the rollback IS the restart.
		"scope": "rollback",
		// What the gate renders as the change: two versions and the file the
		// target was read from. The page computes none of it.
		"change": map[string]any{
			"from": plan.Derivation.Running, "to": plan.Target,
			// A rollback that undoes a change of image SOURCE moves no
			// release, so the gate must not say "this changes the release
			// only" over a diff whose two lines are the same version. The
			// service says which kind this is; the page renders it (#682).
			"source_rollback": plan.Derivation.SourceRollback,
			"source_note":     plan.Derivation.Note,
			"backup":          plan.Derivation.BackupName,
			"backup_age":      str(plan.Assessment["backup_age"]),
			"from_history":    plan.Derivation.FromHistory,
			"store":           plan.Derivation.Store,
			"store_detail":    plan.Derivation.StoreDetail,
			"store_lesson":    runbook.StoreRiskLesson,
		},
		"assessment": plan.Assessment, "verdicts": plan.Verdicts,
		"expected": plan.Assessment["expected"],
	}, nil
}

// rollbackAskedTarget is the target a rollback block asks for, and where it
// came from: "named" when the block wrote one, "derived" when it left the
// target to the node (#1012) and this evaluation's derivation supplies it.
//
// The derived target is the only thing the empty case can mean. Nothing the
// model wrote reaches the plan either way: a named target is compared with the
// derivation and refused when they differ, and an unnamed one IS the
// derivation.
func rollbackAskedTarget(a interrogate.ActionRequest, derived string) (target, from string) {
	if a.TargetFromNode {
		return derived, "derived"
	}
	return a.Target, "named"
}

// rollbackActionRefusal renders one refusal with the one remedy that follows
// from it.
func (s *server) rollbackActionRefusal(reason string, a interrogate.ActionRequest, plan rollbackPlan) map[string]any {
	out := map[string]any{
		"kind": interrogate.ActionKindRollback, "reason": reason, "node": plan.Node,
		"from": plan.Derivation.Running,
	}
	switch reason {
	case restartRefusedWrongNode:
		out["asked_for"] = a.Node
		out["this_node"] = plan.Node.Label
		out["hostname"] = plan.Node.Hostname
	case rollbackRefusedNoTarget, rollbackRefusedAmbiguous:
		// The detail IS the derivation's own sentence, which names the
		// versions and the files it read. Rendered verbatim: a refusal an
		// operator cannot act on costs them a support question.
		out["detail"] = plan.Derivation.Detail
		if plan.Derivation.FromHistory != "" {
			out["from_history"] = plan.Derivation.FromHistory
		}
	case upgradeRefusedWrongTarget:
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

// considerRollbackGate answers a first-turn <intent kind="rollback"/> marker.
// No host read: the answer to "may you" does not depend on how the node is
// doing, and it does not depend on whether a target exists either — that is
// turn one's question, and answering it here would make the operator wait for
// a wrapper read before being told to break glass.
func (s *server) considerRollbackGate(ctx context.Context, role string) map[string]any {
	node, keyErr := s.nodeKey(ctx)
	if keyErr != nil {
		// The reasoning is considerRestartGate's, #398.
		log.Printf("[rollback-gate] no node identity to gate against: %v", keyErr)
		return map[string]any{
			"kind": interrogate.ActionKindRollback, "reason": upgradeRefusedPlanUnavailable,
			"detail": keyErr.Error(),
		}
	}
	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())
	reason, ok := decideRollbackGate(role, accErr == nil && acc.Permits(runbook.ClassUpgrade), windowOpen)
	if ok {
		return nil
	}
	out := map[string]any{"kind": interrogate.ActionKindRollback, "reason": reason}
	if reason == restartRefusedNotPermitted {
		out["command"] = s.reacceptCommand()
	}
	return s.withCompactReason(out, reason, node, accErr)
}

// awaitRollbackHealthy waits for the node to come back on the version this
// run moved it TO, and writes the verdict.
//
// It tolerates the outgoing version for a bounded moment, which is the whole
// difference from awaitRestartHealthy: the version the node was running a
// second ago is the ordinary shape of a rollback in flight, and reporting it
// as a finding would halt every rollback on its first poll.
func awaitRollbackHealthy(ex *execute.Executor, rl *execute.RunLog, target, outgoing, wrapper, expected string) {
	rl.Write("step", "", "waiting for the node to come back on "+target+" and return to full sync")
	rl.Write("out", "", "Expected: "+expected+".")

	verdict, found, p := ex.AwaitRollback(target, outgoing, 15*time.Minute, func(v, d string) {
		rl.Printf("out", "", "version=%s  %s", v, d)
	})

	// Every verdict line from the verifier's proof (#769): done only from a
	// process newer than the restart step, on the target, in full sync.
	switch verdict {
	case execute.RestartBack:
		rl.Complete(p, execute.SyncedLine(execute.OpRollback, p, false))
	case execute.RestartVersionChanged:
		rl.Halt(p, execute.RollbackStalledNote(target, found, outgoing))
	case execute.RestartNotObserved:
		rl.Halt(p, execute.NotRestartedNote(p))
	case execute.RestartStillCatchingUp:
		rl.Pending(p, execute.CatchingUpLine(execute.OpRollback, p))
		rl.Write("out", "", execute.RollbackUnconfirmedNote(target, outgoing, wrapper))
		closedAt := time.Now()
		rl.Write("note", "", "still watching: readings continue below and the run is confirmed "+
			"the moment the node reports full sync on "+target)
		if lp, ok := ex.AwaitHealthyLate(target, 2*time.Hour, closedAt, func(v, d string) {
			rl.Printf("out", "", "version=%s  %s", v, d)
		}); ok {
			rl.Complete(lp, execute.SyncedLine(execute.OpRollback, lp, true))
		}
	}
}

// rollbackClassLine is deliberately absent. A rollback is permitted by the
// upgrade class, so upgradeClassLine already answers for it — a second line
// saying the same thing under another name would teach an operator to look
// for a class list entry that does not exist.
