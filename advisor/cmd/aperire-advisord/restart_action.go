package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/breakglass"
	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/model"
	"aperire-advisor/internal/runbook"
)

// The restart action — ADR 0016, amended 2026-08-19.
//
// The standing Restart card is gone. An admin asks the Advisor to restart
// the node, the model reads restart_assessment and proposes, and this file
// is what decides whether that proposal reaches the operator as a gate.
//
// Everything the page needs to render that gate is minted HERE and travels
// in one response: the plan id, the fingerprint, the confirm code, the
// readings, the concerns and the preconditions. Not because a second call
// would be slow, but because a second call is a second evaluation — and two
// evaluations of one plan is exactly how a confirm code ends up identifying
// something other than what the operator is looking at.

// restartNode is who this Advisor would be restarting, in four independent
// namings. The operator's ruling is that the confirmation must present the
// hostname ("we don't want the wrong node or validator restarted"), so the
// identity is part of the action rather than something the page assembles
// from three other endpoints and hopes agrees.
type restartNode struct {
	// Label is how the fleet refers to this host. Falls back to Container
	// for a deployment with no fleet registry: a name the operator will
	// recognise, never an invented one.
	Label string `json:"label"`
	// Hostname is this box, from the kernel. Empty when it cannot be read,
	// which renders as absent rather than as something else's name.
	Hostname string `json:"hostname"`
	// Container is the node's container on a compose host, or its systemd
	// unit on a native one: whatever host.Profile.Describe() names this
	// node. The two kinds share the slot because they are the same idea,
	// the one name the deployment goes by, and every reader of this field
	// (namesThisNode included) already treats it as one name rather than
	// asking which kind it came from.
	Container string `json:"container"`
	// Package is the vendor package a native host runs: "xrpld", "rippled"
	// or "xahaud" as the running binary reports it (ADR 0002's alias
	// registry). Empty on a compose host. The container name and the image
	// repo already name that deployment there, and Describe()'s fork value
	// on a compose host is the image repo, not this bare name, so folding
	// it in here would add a name a compose host never answered to.
	Package string `json:"package,omitempty"`
	// Role is "validator", "stock node", or whatever the registry recorded
	// — empty when this host has not been told. A validator is the one that
	// stops proposing for the length of the restart, and the gate says so.
	Role string `json:"role"`
	// Validator is Role resolved to the one consequence that changes what
	// the gate says. Never inferred from the label.
	Validator bool `json:"validator"`
}

// hostname is the kernel's answer, asked each time rather than cached: a
// host renamed under a running service should say its new name, and the
// syscall costs nothing beside the host reads on either side of it. A
// hostname that cannot be read is empty and renders as absent — this is an
// identity check the operator performs by eye, so a placeholder standing in
// for it would be worse than a gap.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// selfRestartNode assembles the identity from the three sources that each
// know one part of it: the fleet registry (label, role), the host profile
// (container or unit, plus the package on a native host), and the kernel
// (hostname).
//
// Before #400, Container here was profile.Container directly, which is
// empty by design on a native host, so a native install answered to nothing
// but its hostname and its (usually unset) fleet label. Reading through
// Describe() instead names this node the same way on both kinds: the
// container name, unchanged, on a compose host, and the systemd unit on a
// native one. That is the exact value the model is shown and can echo back.
func (s *server) selfRestartNode(profile host.Profile) restartNode {
	self := s.fleetNow().reg.SelfIdentity()
	node, _, fork, _ := profile.Describe()
	n := restartNode{
		Label:     self.Label,
		Hostname:  hostname(),
		Container: node,
	}
	if profile.Kind == "native" {
		n.Package = fork
	}
	if n.Label == "" {
		n.Label = n.Container
	}
	switch self.Role {
	case "validator":
		n.Role, n.Validator = "validator", true
	case "node":
		n.Role = "stock node"
	default:
		n.Role = self.Role
	}
	return n
}

// namesThisNode reports whether the model's node string is one of the names
// this host answers to. Empty is this node — the model omitting the field is
// the ordinary case, and the gate names the node regardless.
//
// Case-insensitive, and a name's first label counts: an operator saying
// "restart aperire-node1" when the box is aperire-node1.internal has named
// this host, and refusing that would teach them the field is a riddle. The
// same cut is what lets "restart xrpld" reach a native host whose unit is
// xrpld.service with no second rule for it: a unit name is a name with a dot
// in it like any other, not a special case.
func (n restartNode) namesThisNode(asked string) bool {
	asked = strings.TrimSpace(strings.ToLower(asked))
	if asked == "" {
		return true
	}
	for _, name := range []string{n.Label, n.Hostname, n.Container, n.Package} {
		name = strings.ToLower(name)
		if name == "" {
			continue
		}
		if asked == name {
			return true
		}
		if short, _, ok := strings.Cut(name, "."); ok && asked == short {
			return true
		}
	}
	return false
}

// restartAction refusal reasons. Named constants because the page renders a
// different remedy for each and a typo in either half fails by rendering
// nothing.
const (
	restartRefusedMonitor      = "monitor"
	restartRefusedWrongNode    = "wrong_node"
	restartRefusedNotPermitted = "class_not_permitted"
	restartRefusedBlocked      = "blocked"
	restartRefusedBreakGlass   = "break_glass_required"
	restartRefusedRotating     = "rotation_in_flight"
)

// restartActionInputs is everything the decision below turns on, with no
// server, no host and no clock — so the matrix is exercised as a table
// rather than as a deployment.
type restartActionInputs struct {
	// Role is askRequest.Role, stamped by the dashboard proxy from the
	// session cookie. Never typed by the browser.
	Role string
	// AskedNode is the model's node attribute, verbatim.
	AskedNode string
	// Self is who this Advisor serves.
	Self restartNode
	// CompactPermitsRestart is acc.Permits(runbook.ClassRestart).
	CompactPermitsRestart bool
	// WindowOpen is a break-glass window open on this node.
	WindowOpen bool
	// Blocked is the restart runbook's own blocked verdict for this intent.
	Blocked bool
	// Rotating is a NuDB store rotation in flight on this node, read at
	// assessment time from the same wrapper verb the wrapper's own restart
	// guard reads. False when it could not be read, see RotationInFlight.
	Rotating bool
}

// decideRestartAction applies the six refusals in the order that gives the
// operator the remedy they can actually act on next.
//
// The order is the design, not an accident of writing:
//
//   - monitor first. A monitor asking inside a window an admin opened is a
//     real state — a window makes every question on this node gated, whoever
//     asks it — and telling that person to "break glass first" points at a
//     control the page hides for their role.
//   - the wrong node second. "Break glass here first" is the wrong answer to
//     "restart node2": no window on THIS host would ever authorise it.
//   - the compact third. Breaking glass does not add a class, so a host that
//     has not permitted restart should be told the command that does.
//   - the node's own facts fourth: a store rotation in flight, then a
//     blocked precondition. Operator ruling 2026-09-15 (issue #92) moved
//     these two ahead of the break-glass re-check below, because this turn
//     has already read the node and knows the restart cannot happen, a
//     no-window admin asking during a rotation is told so directly, rather
//     than sent to spend a passkey opening a window that a fact already
//     read makes pointless. Turn one (decideRestartGate, which does no host
//     read) cannot see either fact and still answers break glass first;
//     this is turn two diverging from turn one on purpose, in the one case
//     where turn two knows something turn one cannot.
//   - break glass last. Reached only once the node's own facts have cleared,
//     so a restart that IS possible once a window opens is the only one
//     still asking the operator to open one.
//
// A store rotation in flight sits ahead of blocked (issue #80). Ahead rather
// than behind, because when both are true the rotation is the shorter and
// more certain clock: the operator must wait for it whatever the
// preconditions say, and the preconditions read DURING a rotation are partly
// reporting the rotation's own effects on disk and on the ledger, so naming
// them first would send someone to investigate a reading that is about to
// change on its own.
//
// It refuses HERE, before any caller mints a gate, and that placement is the
// whole point of the issue: approval.Spend fires on the attempt, not on the
// success, so a restart the wrapper is going to refuse with exit 64 must
// never be offered as a gate. Offered, it costs the operator a passkey
// ceremony to learn something this read already knew.
func decideRestartAction(in restartActionInputs) (reason string, ok bool) {
	// The three conditions shared with decideRestartGate are not called as
	// one unit here, issue #92 needs rotating and blocked spliced between
	// the compact check and the window check, which a single call to
	// decideRestartGate cannot express. TestTheActionAndTheGateAgreeOnTheirSharedConditions
	// still holds: with rotating and blocked both false (turn one's own
	// view), the three run in the same relative order decideRestartGate
	// gives, so the two turns cannot disagree about them.
	if in.Role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !in.Self.namesThisNode(in.AskedNode) {
		return restartRefusedWrongNode, false
	}
	if !in.CompactPermitsRestart {
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

// roleMonitor is the one role that may not act. Stamped by the dashboard
// proxy from the session cookie; an empty role is NOT a monitor, because a
// caller that is not the proxy (the CLI, a test) has no session to stamp and
// is already holding the service token.
//
// Aliased from interrogate rather than spelled again: the read menu refuses
// the same role by the same name, and two string literals meaning one role is
// how one of them gets fixed and the other does not.
const roleMonitor = interrogate.RoleMonitor

// decideRestartGate is the FIRST-turn question, asked before any assessment:
// may this person do this here at all? — operator ruling 2026-08-19, "if any
// operation that requires break glass is identified it should IMMEDIATELY
// check if break glass is already approved, or tell the admin to use the
// break glass button".
//
// It knows nothing about a node or a plan, so it answers the three
// conditions that are true before either exists. decideRestartAction runs
// the same three checks, in the same relative order, rather than calling
// this function directly, issue #92 needs the node's own facts spliced in
// between the compact check and the window check, which only turn two can
// see. That is the one case where the second turn's answer is allowed to
// diverge from the first turn's: this function still answers break glass
// first, because it has nothing else to go on.
func decideRestartGate(role string, compactPermitsRestart, windowOpen bool) (reason string, ok bool) {
	if role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !compactPermitsRestart {
		return restartRefusedNotPermitted, false
	}
	if !windowOpen {
		return restartRefusedBreakGlass, false
	}
	return "", true
}

// restartPlan is one evaluation of RB-002 for one intent, carrying both what
// the model is allowed to read and what only the operator's gate may hold.
type restartPlan struct {
	Intent   string
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
	Assessment     map[string]any
	Expected       string
	PlanID         string
	Fingerprint    string
	ConfirmCode    string
}

// restartPlanFor evaluates the restart runbook exactly the way /v1/check
// does, and mints the same identity from the same fingerprint call.
//
// It deliberately shares no cache with check(): the ten-second check cache
// is keyed on the plan and returns a marshalled map, and reconstructing a
// typed plan out of it would be a second decoding of the same facts. The
// cost is one more host read on the turn an action is proposed, which is
// the turn where being right matters most.
func (s *server) restartPlanFor(ctx context.Context, intent string) (restartPlan, error) {
	profile, st, err := s.state(ctx)
	if err != nil {
		return restartPlan{}, err
	}
	return s.restartPlanWith(profile, st, intent)
}

// restartPlanWith is restartPlanFor's body for a caller that has already
// discovered the host. considerRestartAction has: it needs this node's own
// identity before it can decide whether the model named another one, and
// discovering the profile twice in one turn is two answers to "what is this
// host" in a response whose whole job is to name it once.
func (s *server) restartPlanWith(profile host.Profile, st *host.State, intent string) (restartPlan, error) {
	_, rb, params, _, err := s.resolveRunbookByID(st, restartRunbookID, planParams{Intent: intent})
	if err != nil {
		return restartPlan{}, err
	}
	vs, blocked, _ := evaluateReadiness(rb, params, s.readinessHost(st))
	tag, terr := st.DeploymentTag()
	if terr != nil {
		tag = ""
	}
	assessment := restartAssessment(st, tag)
	expected, _ := assessment["expected"].(string)
	// The identity this plan is signed against (#398): the container name on
	// a compose host, the unit on a native one. A profile that cannot name
	// its node returns no plan, rather than one signed against "".
	node, err := profile.IdentityKey()
	if err != nil {
		return restartPlan{}, err
	}
	planID, fp, confirmCode := planIdentity(rb.ID, node, params)
	// Read here, in the ONE place both the model's assessment and the gate
	// decision are built from, so the sentence the model reads and the reason
	// the operator is given come from a single reading of the node. Two reads
	// of a state that moves is how an assessment saying "a rotation is
	// running" ends up beside a gate that offers the restart anyway.
	//
	// A failed read is logged and treated as not in flight, never returned as
	// an error: RotationInFlight fails open on purpose, and turning its error
	// into a failed plan would make an unreadable log block every restart,
	// exactly the lockout the fail-open exists to avoid.
	rotating, rotationDetail, rerr := s.rotationInFlightCached(st)
	if rerr != nil {
		log.Printf("[restart-action] the store-rotation state could not be read, treating it as not in flight: %v", rerr)
	}
	return restartPlan{
		Intent:         intent,
		Node:           s.selfRestartNode(profile),
		Verdicts:       vs,
		Blocked:        blocked,
		Rotating:       rotating,
		RotationDetail: rotationDetail,
		RotationRhythm: s.rotationRhythmWhile(rotating, st),
		Assessment:     assessment,
		Expected:       expected,
		PlanID:         planID,
		Fingerprint:    fp,
		ConfirmCode:    confirmCode,
	}, nil
}

// word is how one evaluated precondition reads in an assessment the model
// is handed. It is runbook.Verdict.Word's shape for the wire type, so the
// four states read identically wherever a list of checks is rendered.
func word(v stageVerdict) string {
	return runbook.Verdict{Passed: v.Passed, Unmeasured: v.Unmeasured}.Word()
}

// failingVerdicts is what a blocked refusal carries: the checks that refuse,
// never all of them. A page rendering "5 preconditions" under a refusal
// would bury the one line that explains it.
func failingVerdicts(vs []stageVerdict) []stageVerdict {
	var out []stageVerdict
	for _, v := range vs {
		if !v.Passed {
			out = append(out, v)
		}
	}
	return out
}

// reacceptCommand is the exact line that adds the restart class on THIS
// host, with this host's own directory and account — the same values
// /v1/status publishes under host_run, for the same reason: a command
// printed from the layout the release was built on failed for everyone who
// did not build it.
func (s *server) reacceptCommand() string {
	dir := filepath.Dir(s.stateDir)
	acct := "<advisor account>"
	if u, err := user.Current(); err == nil && u.Username != "" {
		acct = u.Username
	}
	return fmt.Sprintf("cd %s\nsudo -u %s ./bin/aperire-executor compact \\\n"+
		"  --accept --privilege=D1 --classes=upgrade,investigate,restart,config", dir, acct)
}

// reacceptCommandFor is that command for a host whose acceptance no longer
// applies to the node it runs (#466), which is the one refusal where the old
// acceptance is sitting right there and readable.
//
// It carries that acceptance's own privilege and classes, and names the node
// this host runs. The generic line above offers D1 and all four classes,
// which on a host that chose N1 and restart alone would be this service
// nudging an operator into a wider privilege than they picked, to recover
// from a change of node shape they did not ask about either. The same line
// the native install path prints at the end of a conversion, so an operator
// who sees both sees one command.
//
// Peek, not Load: Load is what just refused. Nothing here decides whether an
// act may happen, and an unreadable or half-written file falls back to the
// generic line rather than printing a command built out of nothing.
func (s *server) reacceptCommandFor(node string) string {
	if node == "" {
		return s.reacceptCommand()
	}
	acc, err := compact.Peek(filepath.Join(s.stateDir, "compact.json"))
	if err != nil || acc.Privilege == "" || len(acc.Classes) == 0 {
		return s.reacceptCommand()
	}
	classes := make([]string, 0, len(acc.Classes))
	for _, c := range acc.Classes {
		classes = append(classes, string(c))
	}
	dir := filepath.Dir(s.stateDir)
	acct := "<advisor account>"
	if u, err := user.Current(); err == nil && u.Username != "" {
		acct = u.Username
	}
	return fmt.Sprintf("cd %s\nsudo -u %s ./bin/aperire-executor compact \\\n"+
		"  --accept --container=%s --privilege=%s --classes=%s",
		dir, acct, node, acc.Privilege, strings.Join(classes, ","))
}

// withCompactReason puts the compact's own sentence on a class refusal when
// the acceptance on this host could not be loaded at all.
//
// The gate reads one bool: does the compact permit this class. That bool is
// false for three different facts, and two of them are not what the page
// then says. A host that moved from a container node to a native one keeps
// the acceptance it made, and the acceptance names a node this host no
// longer runs (#466): every privileged class is refused, correctly, while
// the operator is told their compact does not name the class. The words for
// that are already in the load error, and this is where they were being
// dropped.
//
// Only for the class refusal, and only when the load itself failed. A
// compact that loaded and does not name this class needs no extra sentence:
// the page's own copy is exactly right about it.
func (s *server) withCompactReason(out map[string]any, reason, node string, accErr error) map[string]any {
	if reason == restartRefusedNotPermitted && accErr != nil {
		out["detail"] = accErr.Error()
		// And the command that follows from THIS refusal rather than the
		// generic one: the acceptance is readable, so it can carry what was
		// already agreed to.
		out["command"] = s.reacceptCommandFor(node)
	}
	return out
}

// ── the read the model performs before it proposes ──────────────────────

// restartAssessmentBody renders the assessment for the model: the readings,
// the expectation, the concerns and the preconditions, and nothing else.
//
// What is missing from it is the point. plan_id, fingerprint and
// confirm_code identify and authorise a plan; the model has no business
// holding any of them, and it does not need them — the service mints its own
// copy when it validates the action, and the page renders the gate from
// that. A model that never sees a confirm code cannot leak one into an
// answer, and cannot be talked into repeating one back.
func renderRestartAssessment(p restartPlan) string {
	var b strings.Builder
	b.WriteString("RESTART ASSESSMENT — " + p.Node.Label)
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
	b.WriteString("\nThis is the only node this Advisor can restart.\n\n")

	b.WriteString("readings\n")
	if r, ok := p.Assessment["readings"].(host.Readings); ok {
		b.WriteString(renderRestartReadings(r))
	}
	b.WriteString("\nexpected: " + p.Expected + "\n")

	b.WriteString("\nconcerns\n")
	concerns, _ := p.Assessment["concerns"].([]concern)
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
		b.WriteString("\nblocked: yes — a store rotation is in flight. Do not propose a restart: " +
			"the node would refuse to stop, and the operator's approval would be spent on the " +
			"attempt. Tell them to ask again once the rotation finishes." + afterRotation(p.RotationRhythm) + "\n")
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
		b.WriteString("\nblocked: yes — a restart cannot be proposed while a precondition refuses.\n")
	} else {
		b.WriteString("\nblocked: no\n")
	}
	return b.String()
}

// renderRestartReadings states an unmeasured value as unmeasured. Absent is
// not zero: server_info is where the state word and the peer count both come
// from, so a node that did not answer publishes peers as a plain 0 that
// nobody counted.
func renderRestartReadings(r host.Readings) string {
	answered := r.ServerState != ""
	line := func(k, v string) string {
		if v == "" {
			v = "not measured"
		}
		return "  " + k + ": " + v + "\n"
	}
	out := line("state", r.ServerState)
	if answered {
		out += line("peers", fmt.Sprintf("%d", r.Peers))
	} else {
		out += line("peers", "")
	}
	if answered && r.ValidatedLedgerAgeSec != nil {
		out += line("validated ledger age", fmt.Sprintf("%ds", *r.ValidatedLedgerAgeSec))
	} else {
		out += line("validated ledger age", "")
	}
	if answered && r.UptimeSec != nil {
		out += line("up for", humanDuration(*r.UptimeSec))
	} else {
		out += line("up for", "")
	}
	out += line("running version", r.RunningVersion)
	out += line("deployment names", r.DeploymentTag)
	if r.DiskFreePct != nil {
		out += line("disk free", fmt.Sprintf("%.1f%%", *r.DiskFreePct))
	} else {
		out += line("disk free", "")
	}
	return out
}

// restartAssessmentResult is the Menu side of the read. Its source names the
// channel honestly: this is the service's own evaluation, not a wrapper call
// and not a dashboard read.
func (s *server) restartAssessmentResult(ctx context.Context) interrogate.Result {
	_, res := s.restartAssessmentPlan(ctx)
	return res
}

// restartAssessmentPlan is the same read, with the evaluated plan handed
// back beside the model's copy of it.
//
// It exists for the deterministic confirm (restart_confirm.go): the gated
// path needs to know that THIS question showed the operator a restart the
// service itself found proposable, and the rendered body is the wrong place
// to learn that from — a caller parsing "blocked: no" back out of prose the
// model reads would be a second derivation of a fact this function already
// holds. The Result is unchanged, so every existing caller sees exactly what
// it saw before.
//
// A failed evaluation returns the zero plan with a failed Result. Callers
// decide on the Result's status, never on the plan alone.
func (s *server) restartAssessmentPlan(ctx context.Context) (restartPlan, interrogate.Result) {
	p, err := s.restartPlanFor(ctx, restartAssessmentIntent)
	if err != nil {
		// The node not answering IS the assessment, and restartAssessment
		// says so itself — this branch is the earlier failure, where the
		// host profile or the runbook could not be resolved at all.
		return restartPlan{}, interrogate.Result{
			Status: interrogate.StatusFailed,
			Detail: "the restart assessment could not be evaluated: " + err.Error(),
			Source: "this service's own evaluation",
		}
	}
	return p, interrogate.Result{
		Status: interrogate.StatusOK,
		Body:   renderRestartAssessment(p),
		Source: "this service's own evaluation",
	}
}

// ── the proposal the operator sees ──────────────────────────────────────

// considerRestartAction turns a model's parsed <action> block into either
// the gate the page renders under that answer, or the one honest reason it
// cannot. Exactly one of the two is non-nil; both are nil only when this
// service could not read its own host, in which case there is nothing
// truthful to say about a restart at all.
//
// Called on BOTH ask paths. In practice the ordinary path always refuses
// with break_glass_required — a window makes every question gated, so a
// permitted action arrives on the gated path — but the block is parsed,
// stripped and answered identically either way, because "in practice" is
// not a boundary.
func (s *server) considerRestartAction(ctx context.Context, a interrogate.ActionRequest, role string, asker ledger.Actor) (action, refused map[string]any) {
	profile, node, st, err := s.stateKeyed(ctx)
	if err != nil {
		// Named, never silent — the same contract the upgrade's
		// plan_unavailable states: an operator who said yes must get a gate
		// or a reason, and a nil here is neither.
		log.Printf("[restart-action] the host could not be read: %v", err)
		return nil, map[string]any{
			"kind": interrogate.ActionKindRestart, "reason": upgradeRefusedPlanUnavailable,
			"detail": "the node's own state could not be read just now",
		}
	}
	plan, perr := s.restartPlanWith(profile, st, a.Intent)
	if perr != nil {
		log.Printf("[restart-action] the restart plan could not be evaluated: %v", perr)
		return nil, map[string]any{
			"kind": interrogate.ActionKindRestart, "reason": upgradeRefusedPlanUnavailable,
			"node": s.selfRestartNode(profile), "detail": perr.Error(),
		}
	}

	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	// The same node key breakglassOpen and breakglassClose use, so a
	// window opened by the panel's header is the window found here.
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())

	reason, ok := decideRestartAction(restartActionInputs{
		Role:                  role,
		AskedNode:             a.Node,
		Self:                  plan.Node,
		CompactPermitsRestart: accErr == nil && acc.Permits(runbook.ClassRestart),
		WindowOpen:            windowOpen,
		Blocked:               plan.Blocked,
		Rotating:              plan.Rotating,
	})
	if !ok {
		return nil, s.withCompactReason(s.restartActionRefusal(reason, a, plan), reason, node, accErr)
	}

	// Recorded before the response is written, and as the ASKER — this is
	// the Advisor proposing an act on a person's behalf, and the trail
	// should name the person who asked for it, not the service. It is not
	// an approval and grants nothing: the passkey ceremony that follows
	// writes its own approval.granted, and a proposal nobody acts on stays
	// in the record as a proposal nobody acted on.
	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		l.AppendAs(ledger.KindActionProposed, plan.PlanID,
			"a restart of "+plan.Node.Label+" was proposed",
			map[string]any{
				"kind": interrogate.ActionKindRestart, "runbook": restartRunbookID,
				"intent": plan.Intent, "node": plan.Node.Label,
				"hostname": plan.Node.Hostname, "container": plan.Node.Container,
				"plan_id": plan.PlanID, "confirm_code": plan.ConfirmCode,
			}, asker)
	}

	return map[string]any{
		"kind": interrogate.ActionKindRestart, "runbook": restartRunbookID,
		"intent": plan.Intent, "node": plan.Node,
		"plan_id": plan.PlanID, "fingerprint": plan.Fingerprint,
		"confirm_code": plan.ConfirmCode,
		"assessment":   plan.Assessment, "verdicts": plan.Verdicts,
		"expected": plan.Expected,
	}, nil
}

// restartActionRefusal renders one refusal with the one remedy that follows
// from it. Every reason carries the node, because a refusal about a restart
// still has to say which node it is about.
func (s *server) restartActionRefusal(reason string, a interrogate.ActionRequest, plan restartPlan) map[string]any {
	out := map[string]any{
		"kind": interrogate.ActionKindRestart, "reason": reason, "node": plan.Node,
	}
	switch reason {
	case restartRefusedWrongNode:
		// Both names, so the page can say the sentence with neither of them
		// guessed: this Advisor serves one node, and it is not the one that
		// was asked for.
		out["asked_for"] = a.Node
		out["this_node"] = plan.Node.Label
		out["hostname"] = plan.Node.Hostname
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

// ── the first turn: who is asking, and may they act here ────────────────

// sessionContext renders the ASKER AND ACCESS block — the three facts that
// decide whether an act is even possible for this person on this host,
// stated to the model BEFORE the measurements so it can lead with them.
//
// Operator ruling, 2026-08-19: an admin who has not broken glass should be
// told to break glass, and a monitor should be told an admin does this,
// immediately — not after a paragraph of assessment they turn out not to be
// able to act on. A model that cannot see this state cannot lead with it,
// and the ceremony block below says nothing about break glass.
//
// Deliberately says "not stated" rather than "monitor" for an absent role:
// the CLI and the tests reach this endpoint with the service token and no
// session, and rendering them as the least-privileged role would teach the
// model to refuse them.
func (s *server) sessionContext(role, node string, now time.Time) string {
	var b strings.Builder
	b.WriteString("ASKER AND ACCESS\n")
	if role == "" {
		b.WriteString("  asker: role not stated (this request did not come through a dashboard session)\n")
	} else {
		b.WriteString("  asker: role=" + role + "\n")
	}
	if role == roleMonitor {
		b.WriteString("  a monitor. They may read this node's metrics, consensus, peers, alerts and " +
			"records, and approve nothing. The seven host reads that describe the host itself " +
			"(show-config, node-log, journal, sysctl-relevant, limits, show-validators, show-toml) " +
			"are refused for this asker at every tier — do not paraphrase that material from " +
			"memory or from an earlier conversation either. Any act — a restart, an upgrade or a " +
			"configuration change included — is an admin's, inside a break-glass window.\n")
	}

	if win, open := s.breakglass.OpenForNode(node, now); open {
		left := win.ExpiresAt.Sub(now).Round(time.Second)
		if left < 0 {
			left = 0
		}
		fmt.Fprintf(&b, "  break glass: a window IS open — %s remaining, %d of %d questions used, "+
			"%d of %d privileged reads used\n",
			left, win.Questions, breakglass.MaxQuestions,
			win.PrivilegedReads, breakglass.MaxPrivilegedReads)
	} else {
		b.WriteString("  break glass: no window is open on this node. An admin opens one with the " +
			"Break glass button at the top of this panel; it takes a passkey and lasts 15 minutes.\n")
	}

	if acc, err := compact.Load(filepath.Join(s.stateDir, "compact.json"), node); err == nil {
		if acc.Permits(runbook.ClassRestart) {
			b.WriteString("  restart class: permitted by the operator compact accepted on this host\n")
		} else {
			b.WriteString("  restart class: NOT permitted by the operator compact accepted on this host — " +
				"a restart is refused here until it is re-accepted with the wider class list\n")
		}
		// Its own line, not folded into the restart's. They are separate
		// classes and an operator can hold one and not the other, so one
		// sentence covering both would be false on that host.
		b.WriteString(upgradeClassLine(acc.Permits(runbook.ClassUpgrade)))
		b.WriteString(configClassLine(acc.Permits(runbook.ClassConfig)))
	} else {
		// A compact that could not be loaded used to leave this block with
		// nothing in it about the compact at all, so the model answered a
		// restart request without mentioning the gate that was about to
		// refuse it. The three class lines above cannot be written (there is
		// no acceptance to read them from), and the fact that replaces them
		// is the load's own sentence.
		//
		// #466: on a host that moved from a container node to a native one
		// the acceptance still names the container, the node key is the unit
		// now, and this is the line that says so where the operator is
		// asking rather than in a status block they have no reason to read.
		b.WriteString("  operator compact: NOT in force on this host. " + err.Error() +
			". Every privileged class is refused here until it is accepted again for " +
			"this node, and accepting terms is the operator's own act: say that, with " +
			"the reason above, instead of offering a plan\n")
	}
	return b.String()
}

// considerRestartGate answers a first-turn <intent kind="restart"/> marker:
// the model has recognised an act, and the service says whether this person
// may take it here, in the same action_blocked vocabulary the second turn
// uses. Returns nil when they may — the model is then on turn one and the
// page renders nothing extra.
//
// It performs no host read. That is the point of separating it from
// considerRestartAction: the answer to "may you" does not depend on how the
// node is doing, and making the operator wait for a precondition sweep
// before being told to break glass would be the delay this exists to remove.
func (s *server) considerRestartGate(ctx context.Context, role string) map[string]any {
	node, keyErr := s.nodeKey(ctx)
	if keyErr != nil {
		// #398. This used to fall back to s.container and carry on, which on
		// a native host means gating on "": the compact lookup misses, the
		// window lookup misses, and the operator is told their compact does
		// not permit a restart when the real fact is that the service cannot
		// say which node this is. Refused, with the fact.
		log.Printf("[restart-gate] no node identity to gate against: %v", keyErr)
		return map[string]any{
			"kind": interrogate.ActionKindRestart, "reason": upgradeRefusedPlanUnavailable,
			"detail": keyErr.Error(),
		}
	}
	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())
	reason, ok := decideRestartGate(role, accErr == nil && acc.Permits(runbook.ClassRestart), windowOpen)
	if ok {
		return nil
	}
	out := map[string]any{"kind": interrogate.ActionKindRestart, "reason": reason}
	if reason == restartRefusedNotPermitted {
		out["command"] = s.reacceptCommand()
	}
	return s.withCompactReason(out, reason, node, accErr)
}

// ── one strip, both ask paths ───────────────────────────────────────────

// replySignal is what a model's final reply asked the service to do, once
// the markup is out of it.
type replySignal struct {
	Action    interrogate.ActionRequest
	HasAction bool
	// BrokenAction is set when the reply carried an <action> tag the parser
	// refused — validator1, 2026-08-21: a mangled tag used to fall into the
	// no-tag case, and the operator sat in front of a reply saying
	// Confirmed while no gate appeared and nothing said why. BrokenWhy is
	// the parser's reason, already bounded on that side.
	BrokenAction bool
	BrokenWhy    string
	// MarkerKind is the kind on a first-turn <intent kind="…"/>: the model
	// recognised an act and has not proposed one. Empty when there was no
	// marker. Ignored when HasAction is set — a reply carrying both is on
	// turn two, and the action is the stronger statement.
	//
	// It carries the KIND rather than a bool, and that became load-bearing
	// the moment there were two acts: a signal saying only "there was a
	// marker" would answer an upgrade question with the restart's gate.
	MarkerKind string
	// RouteNode is the peer a <route node="…"/> marker suggests handing off
	// to — the operator named a node that is not this host. Shape-checked
	// here; validated against the real roster in routeSuggestion, so a
	// hallucinated label never becomes an offer.
	RouteNode string
}

// echoedActionWhy is the refusal a repeated block gets, in the drawer's
// words. The interrogate package names it, with its sibling for text encoded
// past the decoding cap.
const echoedActionWhy = interrogate.EchoWhyRepeated

// stripReplySignalsGiven removes every action-protocol block from a reply
// and reports what was in it. Called on BOTH ask paths, and on the gated
// path it is called where extractMemory is, beside the progress store's own
// write, not after the runner returns. The page recovers a dead POST by
// polling that store, so a strip that happened only in the HTTP handler
// would leave the raw markup in the copy the operator actually reads.
//
// injected is the text the turn carried that the model did not write
// (#1020). An action block that only repeats a block from that text is
// refused as unreadable, never turned into a gate, and the refusal is logged
// and ledgered by answerAction like any other unreadable proposal. There is
// no form of this without injected: a path that strips a reply has to say
// what its turn read, and TestEveryReplyIsStrippedWithItsTurnsContext holds
// every production call to that.
func stripReplySignalsGiven(reply string, injected []string) (string, replySignal) {
	var sig replySignal
	a, clean, parse := interrogate.ParseAction(reply)
	sig.Action, sig.HasAction = a, parse.Found
	sig.BrokenAction, sig.BrokenWhy = parse.Broken, parse.Why
	// Defence in depth, never the control: see internal/interrogate/echo.go
	// for what it adds and the residual it cannot cover.
	if parse.Found {
		if refuse, why := interrogate.EchoVerdict(reply, injected); refuse {
			log.Printf("[action] refused a %s block: %s", a.Kind, why)
			sig.Action, sig.HasAction = interrogate.ActionRequest{}, false
			sig.BrokenAction, sig.BrokenWhy = true, why
		}
	}
	kind, clean, markerFound := interrogate.ParseActionIntent(clean)
	if markerFound {
		sig.MarkerKind = kind
	}
	routeNode, clean, routeFound := interrogate.ParseRouteSuggestion(clean)
	if routeFound {
		sig.RouteNode = routeNode
	}
	return clean, sig
}

// defangedTurns is the conversation the page posted back, with every
// protocol tag in it defanged (#1020). A turn is text the model did not write
// this round: the page holds the earlier replies and posts them with the next
// question, and whatever a turn says, including a block an earlier reply
// quoted, must not be something the model can repeat into a proposal. The
// echo check does not cover it, on purpose: it compares a reply with what the
// turn's prompt carried from outside, and an assistant turn is the model's
// own, so a yes turn that repeats its own earlier block is not refused. The
// turn the model sees is therefore the one with the tags already defanged.
func defangedTurns(history []model.Turn) []model.Turn {
	out := make([]model.Turn, 0, len(history)+1)
	for i, t := range history {
		t.Content = interrogate.SanitizeHistory(t.Content)
		if t.Content == interrogate.HistoryWithheld {
			log.Printf("[ask] history turn %d (%s) was withheld: still decoding past the decode cap, so no layer is left for the model to decode (#1020)", i, t.Role)
		}
		out = append(out, t)
	}
	return out
}

// injectedText is what a turn's prompt carried that the model did not
// write: every message but its own (the system prompt with knowledge, the
// reference material with recalled notes, every read result). The final
// assistant turn is the reply itself and is never in it.
func injectedText(msgs []interrogate.Message) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if m.Role != "assistant" {
			out = append(out, m.Content)
		}
	}
	return out
}

// routeSuggestion turns a <route> marker into the response's `route` block,
// or nil. Kept out of answerAction on purpose: a route is not an action and
// carries no gate, and it is only ever offered when the reply proposes
// nothing else — a model that both proposes an act and suggests a handoff
// is confused, and the act is the stronger statement.
//
// The node is validated against the live roster HERE, server-side, which is
// what makes the marker safe to let the model emit: a label that is not a
// registered peer is dropped, so a hallucinated node never becomes an offer
// the operator can accept.
func (s *server) routeSuggestion(sig replySignal) map[string]any {
	if sig.HasAction || sig.BrokenAction || sig.MarkerKind != "" {
		return nil
	}
	if sig.RouteNode == "" || !s.fleetNow().nodes[sig.RouteNode] {
		return nil
	}
	return map[string]any{"node": sig.RouteNode}
}

// answerAction turns a stripped reply's signal into the response's `action`
// or `action_blocked` block. Exactly one is ever non-nil, and both are nil
// for the overwhelming majority of replies, which propose nothing.
func (s *server) answerAction(ctx context.Context, sig replySignal, role string, asker ledger.Actor) (action, refused map[string]any) {
	if sig.BrokenAction {
		// A proposal the model wrote and the parser refused. The operator
		// asked for an act and is reading a reply that believes it proposed
		// one, so the refusal must reach the drawer AND the ledger — a tab
		// showing nothing here is indistinguishable from the model never
		// having tried, which is what made validator1's 2026-08-21 failure
		// cost the operator their turn with no trace anywhere.
		log.Printf("[action] a model proposal was refused as unreadable: %s", sig.BrokenWhy)
		if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
			l.AppendAs(ledger.KindActionRefused, "",
				"an action the Advisor proposed could not be read and was refused",
				map[string]any{"reason": "unreadable_proposal", "detail": sig.BrokenWhy}, asker)
		}
		return nil, map[string]any{"kind": "", "reason": "unreadable_proposal", "detail": sig.BrokenWhy}
	}
	if sig.HasAction {
		switch sig.Action.Kind {
		case interrogate.ActionKindRestart:
			return s.considerRestartAction(ctx, sig.Action, role, asker)
		case interrogate.ActionKindUpgrade:
			return s.considerUpgradeAction(ctx, sig.Action, role, asker)
		case interrogate.ActionKindConfig:
			return s.considerConfigAction(ctx, sig.Action, role, asker)
		case interrogate.ActionKindRollback:
			return s.considerRollbackAction(ctx, sig.Action, role, asker)
		}
		// Unreachable: ParseAction drops any kind outside its own set rather
		// than returning one a caller has no branch for. Falling through to
		// nil rather than defaulting to either act, because guessing which
		// one a reply meant is the wrong-act mistake this protocol exists to
		// make impossible.
		return nil, nil
	}
	switch sig.MarkerKind {
	case interrogate.ActionKindRestart:
		return nil, s.considerRestartGate(ctx, role)
	case interrogate.ActionKindUpgrade:
		return nil, s.considerUpgradeGate(ctx, role)
	case interrogate.ActionKindConfig:
		return nil, s.considerConfigGate(ctx, role)
	case interrogate.ActionKindRollback:
		return nil, s.considerRollbackGate(ctx, role)
	}
	return nil, nil
}

// planIdentity is the ONE derivation of what a plan is called, what its
// fingerprint is, and what code the operator types to confirm it.
//
// It exists because the restart action mints these outside /v1/check, and a
// second derivation of the same three values is how a confirm code ends up
// identifying a plan the approval endpoint then recomputes differently —
// which surfaces as a 409 AFTER the passkey touch, the one place a
// disagreement costs the operator a ceremony. Both callers go through here;
// there is no third way to compute them.
func planIdentity(runbookID, container string, params runbook.Params) (planID, fingerprint, confirmCode string) {
	fp := approval.Fingerprint(runbookID, container, params)
	return "plan-" + fp[:12], fp, approval.ConfirmCode(fp)
}
