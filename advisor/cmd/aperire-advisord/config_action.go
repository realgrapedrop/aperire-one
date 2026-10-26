package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/execute"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/runbook"
)

// The configuration action — ADR 0018, RB-003.
//
// Same two turns as the restart and the upgrade, and one thing neither of
// them has: this act CHANGES a file, so the operator is shown exactly which
// lines would change before they are asked for a passkey.
//
// The diff is computed HERE, from the node's own configuration read through
// the privilege wrapper, and never from the model's text. That is the whole
// design point of this file. A model that wrote out a before/after would be
// writing something an operator might approve on the strength of having read
// it, and the one thing the operator cannot check by eye is whether the
// sentence matches the file.

// configRunbookID is RB-003's identifier, named once for the reason the other
// two are: several behaviours key off it and a typo fails by doing nothing.
const configRunbookID = "config-change"

// configDiff is what the gate renders. Every field is measured or derived
// from a measurement.
type configDiff struct {
	// File is the path the wrapper reported reading, verbatim.
	File string `json:"file"`
	// Host is the machine the wrapper reported. An operator running two nodes
	// reads a bare filename as ambiguous.
	Host  string `json:"host"`
	Key   string `json:"key"`
	Value string `json:"value"`
	// Stanza is the section header the change sits under, bare and without
	// its brackets — "node_size" for a stanza-shaped setting, empty for a
	// key=value one. rippled writes node_size and ledger_history as a header
	// with the value on the line below it, so the header is what names the
	// setting and the value line alone is what changes.
	//
	// It is rendered as context above the diff and is deliberately NOT part
	// of Before or After: the header does not change, colouring it red and
	// green would claim it does, and its line would be counted as one of the
	// lines the wrapper rewrites, which is a number the run verifies against.
	Stanza string `json:"stanza,omitempty"`
	// Before is every line that would change, in file order and verbatim. For
	// a key=value setting that is every assignment of it, not the first: this
	// operator's node has two online_delete lines and the wrapper rewrites
	// both. For a stanza setting it is the one value line under the header.
	Before []string `json:"before"`
	// After is what those lines become — the wrapper writes "key=value" with
	// no spacing for the kv shape and the bare value for the stanza shape,
	// one line per line it replaced, so this mirrors what the operator will
	// actually get rather than reformatting it.
	After []string `json:"after"`
	// BackupPattern is the shape of the dated copy the wrapper takes before
	// it writes. Not the actual name: it carries the timestamp of the moment
	// the edit runs, which has not happened yet. The run log records the real
	// one.
	BackupPattern string `json:"backup_pattern"`
	// RestartRequired is true when the node reads this key at startup — all
	// four in v1 — which is what makes the approval compound.
	RestartRequired bool `json:"restart_required"`
	// RestartExpected is how long the node is away, measured, and it is
	// restartExpectation rather than the upgrade's number: this is a node
	// returning to consensus, not a container coming back.
	RestartExpected string `json:"restart_expected"`
	// Band is what this key may be set to, in the words the refusal uses.
	Band string `json:"band"`
	// What the setting does, one line.
	What string `json:"what"`
}

// backupPatternFor mirrors the wrapper's own naming: "$CONFIG_FILE." plus a
// date stamp plus ".bak". Written out rather than formatted from time.Now, so
// it reads as a pattern and cannot be mistaken for a file that exists.
func backupPatternFor(file string) string {
	return file + ".YYYYMMDD-HHMMSS.bak"
}

// configDiffFor reads the node's configuration and derives what the change
// would do to it.
//
// The error it returns is shown to the operator verbatim as the refusal
// detail, so it says what is wrong in terms of their file — "there is no
// node_size= line to change" rather than "read failed".
func configDiffFor(st *host.State, key, value string) (configDiff, error) {
	meta, known := runbook.LookupConfigKey(key)
	if !known {
		return configDiff{}, fmt.Errorf("%s is not a setting the Advisor may change", key)
	}
	cfg, err := st.NodeConfiguration()
	if err != nil {
		return configDiff{}, fmt.Errorf("the node's configuration could not be read, so the change "+
			"cannot be shown before it is approved: %v", err)
	}
	// Both shapes, and every refusal the wrapper would make, made here first.
	// A diff the operator approves and a wrapper that then declines to write
	// it is exactly the gap between the page and the file this file exists to
	// close — and it is the shape of the 2026-08-19 report, where the reading
	// said a stanza-shaped setting was not there at all.
	ch, err := cfg.ChangeFor(key, value)
	if err != nil {
		return configDiff{}, err
	}
	if ch.Current == value {
		return configDiff{}, fmt.Errorf("%s is already %s on %s, so this change would do nothing",
			key, value, cfg.File)
	}
	return configDiff{
		File: cfg.File, Host: cfg.Host, Key: key, Value: value,
		Stanza: ch.Stanza, Before: ch.Before, After: ch.After,
		BackupPattern:   backupPatternFor(cfg.File),
		RestartRequired: meta.StartupRead,
		RestartExpected: restartExpectation,
		Band:            meta.Band,
		What:            meta.What,
	}, nil
}

// ── the read the model performs before it proposes ──────────────────────

// configAssessment is what the model is given: the four settings as they are
// on this node right now, the band each may move within, whether it is read at
// startup, when the node last started, and how consensus looks.
//
// It does NOT carry the file's lines, the file's path, plan_id, fingerprint or
// confirm_code. The current VALUE of a key is what a recommendation has to be
// grounded in; the lines that would change are what the operator approves, and
// those are measured by the service and rendered in the gate.
func configAssessment(st *host.State, deploymentTag string) map[string]any {
	out := map[string]any{
		"expected":     restartExpectation,
		"startup_read": true,
	}
	settings, cerr := configSettingRows(st)
	out["settings"] = settings
	if cerr != nil {
		out["config_read_error"] = cerr.Error()
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
	out["concerns"] = configConcerns(r, st)
	return out
}

// configSettingRows is the four settings as they stand in the file right now.
//
// Its own function because it is the reading that was wrong: it looked for a
// `key=` line for every key, and for the two rippled writes as sections it
// found nothing and said so. Separating it lets it be tested against a
// scripted show-config without a node behind it.
func configSettingRows(st *host.State) ([]map[string]any, error) {
	settings := make([]map[string]any, 0, len(runbook.ConfigKeys()))
	cfg, cerr := st.NodeConfiguration()
	for _, k := range runbook.ConfigKeys() {
		// shape is in the row because the model explains the change in
		// words, and the two shapes read differently in a sentence: one is a
		// line reading `online_delete=32768`, the other is a `[node_size]`
		// section with `huge` under it. Without it the model described every
		// setting as a key=value line — and when the read said absent, told
		// the operator the setting did not exist.
		row := map[string]any{
			"key": k.Name, "band": k.Band, "what": k.What,
			"startup_read": k.StartupRead, "shape": string(k.Shape),
		}
		if cerr != nil {
			// Absent is not zero, and unread is not absent. A key whose file
			// could not be read has no current value, and says so.
			row["current"] = nil
			row["read"] = false
		} else if v, ok := cfg.Setting(k.Name); ok {
			row["current"] = v
			row["read"] = true
		} else {
			// Genuinely not in the file — not "we looked for the wrong shape
			// and did not find it", which is what absent used to mean for
			// node_size and ledger_history on every node that has them.
			row["current"] = nil
			row["read"] = true
			row["absent"] = true
		}
		// The observed fact issue #106 asked for, attached to the ONE row
		// it is about. advisory_delete says what the node will do on paper;
		// can_delete_timer says whether the daily window (#79) that actually
		// calls can_delete is installed and enabled on this host, so the
		// model answers from a measurement instead of arguing from what it
		// does not see, which is the failure the ruling on #106 records.
		if k.Name == "advisory_delete" {
			state, detail := st.CanDeleteWindow()
			row["can_delete_timer"] = state
			row["can_delete_timer_detail"] = detail
			// And the running node's own answer (review of #1101): the file
			// can say 1 while the node has not restarted since the edit.
			live, liveDetail := st.AdvisoryDeleteLive()
			row["advisory_live"] = live
			row["advisory_live_detail"] = liveDetail
		}
		settings = append(settings, row)
	}
	return settings, cerr
}

// configConcerns is the amber material, as a function of the readings and one
// wrapper verdict — the refusals are the preconditions and they are elsewhere.
func configConcerns(r host.Readings, st *host.State) []concern {
	var out []concern
	if r.UptimeSec == nil {
		out = append(out, concern{
			Name:   "how long the node has been up could not be read",
			Detail: "so how long this change would sit unapplied before the restart is unknown",
			State:  stateUndetermined,
		})
	} else {
		out = append(out, concern{
			Name: "the node restarts as part of this change",
			Detail: fmt.Sprintf("it has been up %s and will go away for %s. Every setting the "+
				"Advisor can change is read at startup, so the change does nothing until it does.",
				humanDuration(*r.UptimeSec), restartExpectation),
			State: stateConcern,
		})
	}
	if r.Peers < 5 {
		out = append(out, concern{
			Name: "peers below baseline",
			Detail: fmt.Sprintf("%d peers. A node rebuilding from a low peer count takes longer to "+
				"come back after the restart this change needs.", r.Peers),
			State: stateConcern,
		})
	}
	// The 2026-08-19 incident, now measured rather than assumed. An unknown
	// verdict is named as unknown: "I did not look" must not render as "I
	// looked and it was fine".
	verdict, detail := st.ConfigReadable()
	switch verdict {
	case runbook.ConfigReadableNo:
		out = append(out, concern{
			Name: "the node's container cannot read its configuration",
			Detail: detail + ". A node started now would come up on the image's defaults without " +
				"saying so. This refuses the restart, so the change cannot be applied until it is fixed.",
			State: stateConcern,
		})
	case runbook.ConfigReadableUnknown:
		out = append(out, concern{
			Name: "whether the node's container can read its configuration could not be measured",
			Detail: detail + ". A config the container cannot read makes the node start on the " +
				"image's defaults silently, and that has happened here before, so this is unknown " +
				"rather than fine.",
			State: stateUndetermined,
		})
	}
	return out
}

// configAdvisoryOf reads advisory_delete's value and its daily window's state
// off the assessment's rows: "" for either when it was not read.
func configAdvisoryOf(rows []map[string]any) (file, live, timer string) {
	for _, r := range rows {
		if r["key"] != "advisory_delete" {
			continue
		}
		if v, ok := r["current"].(string); ok {
			file = strings.TrimSpace(v)
		} else if absent, _ := r["absent"].(bool); absent {
			file = "0"
		}
		live, _ = r["advisory_live"].(string)
		timer, _ = r["can_delete_timer"].(string)
	}
	return file, live, timer
}

// renderConfigAssessment is the assessment as the model reads it.
func renderConfigAssessment(p configPlan) string {
	var b strings.Builder
	b.WriteString("CONFIGURATION ASSESSMENT — " + p.Node.Label)
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
	b.WriteString("\nThis is the only node whose configuration this Advisor can change.\n\n")

	b.WriteString("settings you may propose a change to\n")
	rows, _ := p.Assessment["settings"].([]map[string]any)
	for _, row := range rows {
		cur := "not read"
		if v, ok := row["current"].(string); ok && v != "" {
			cur = v
		} else if absent, _ := row["absent"].(bool); absent {
			cur = "not present in this node's configuration — it cannot be changed, only a " +
				"setting the file already has can be"
		}
		fmt.Fprintf(&b, "  %s = %s\n      band: %s\n      what it does: %s\n      read at startup: %v\n",
			row["key"], cur, row["band"], row["what"], row["startup_read"])
		// The observed fact from issue #106, printed beside the setting it is
		// about. advisory_delete=0 (free-running) and advisory_delete=1 with
		// this window enabled are both legitimate; the line says which is
		// actually running here, so a question about rotation is answered
		// from this reading rather than argued from memory.
		if row["key"] == "online_delete" {
			// The schedule is the numbers, not a habit (#1058): the same
			// arithmetic the rotation check holds against a swap's need, with
			// advisory_delete and its daily window beside it, because with
			// advisory_delete=1 the window sets the pace.
			if n, err := strconv.Atoi(strings.TrimSpace(cur)); err == nil {
				file, live, timer := configAdvisoryOf(rows)
				if sched := host.RotationSchedule(n, file, live, timer); sched != "" {
					fmt.Fprintf(&b, "      %s; quote that if you give a schedule\n", sched)
				}
			}
		}
		if row["key"] == "advisory_delete" {
			if state, ok := row["can_delete_timer"].(string); ok {
				fmt.Fprintf(&b, "      daily rotation window (aperire-can-delete.timer): %s, %s\n",
					state, row["can_delete_timer_detail"])
			}
			if live, ok := row["advisory_live"].(string); ok {
				fmt.Fprintf(&b, "      the running node itself: %s, %s (the file is read at startup, so it can differ)\n",
					live, row["advisory_live_detail"])
			}
		}
	}
	if e, ok := p.Assessment["config_read_error"].(string); ok {
		b.WriteString("\nthe configuration could not be read: " + e + "\n")
	}

	b.WriteString("\nreadings\n")
	if r, ok := p.Assessment["readings"].(host.Readings); ok {
		b.WriteString(renderRestartReadings(r))
	}
	b.WriteString("\napplying any of these needs a restart: " + restartExpectation + "\n")

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
		b.WriteString("\nblocked: yes — a store rotation is in flight. Do not propose a change: " +
			"every setting here is read at startup, so one approval covers the edit and the restart, " +
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
		b.WriteString("\nblocked: yes — a configuration change cannot be proposed while a precondition refuses.\n")
	} else {
		b.WriteString("\nblocked: no\n")
	}
	return b.String()
}

// configAssessmentResult is the Menu side of the read.
func (s *server) configAssessmentResult(ctx context.Context) interrogate.Result {
	// Evaluated against a representative plan so the preconditions are real.
	// The key and value chosen here do not reach the operator: the assessment
	// lists every key's current value, and the plan the operator approves is
	// evaluated again, with their key and their value, when the action is
	// validated.
	p, err := s.configPlanFor(ctx, assessmentProbeKey, assessmentProbeValue)
	if err != nil {
		return interrogate.Result{
			Status: interrogate.StatusFailed,
			Detail: "the configuration assessment could not be evaluated: " + err.Error(),
			Source: "this service's own evaluation",
		}
	}
	return interrogate.Result{
		Status: interrogate.StatusOK,
		Body:   renderConfigAssessment(p),
		Source: "this service's own evaluation",
	}
}

// assessmentProbeKey/Value bind a plan so the preconditions can be evaluated
// at all — BindParams requires both, and a runbook with unbound parameters
// evaluates nothing.
//
// They are deliberately a value inside the band and NOT a proposal: nothing
// downstream sees them, no confirm code is minted from them, and the
// assessment's own text never names them. The alternative — making the
// parameters optional for an assessment — would mean the same runbook binds
// differently depending on who is asking, which is how a fingerprint ends up
// computed two ways.
const (
	assessmentProbeKey   = "node_size"
	assessmentProbeValue = "medium"
)

// ── the plan ────────────────────────────────────────────────────────────

// configPlan is one evaluation of RB-003 for one key and value.
type configPlan struct {
	Key      string
	Value    string
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
	PlanID         string
	Fingerprint    string
	ConfirmCode    string
}

func (s *server) configPlanFor(ctx context.Context, key, value string) (configPlan, error) {
	profile, st, err := s.state(ctx)
	if err != nil {
		return configPlan{}, err
	}
	return s.configPlanWith(profile, st, key, value)
}

// configPlanWith is configPlanFor's body for a caller that has already
// discovered the host — considerConfigAction has, because it needs this
// node's identity before it can tell whether the model named another one.
func (s *server) configPlanWith(profile host.Profile, st *host.State, key, value string) (configPlan, error) {
	_, rb, params, _, err := s.resolveRunbookByID(st, configRunbookID, planParams{Key: key, Value: value})
	if err != nil {
		return configPlan{}, err
	}
	vs, blocked, _ := evaluateReadiness(rb, params, s.readinessHost(st))
	tag, terr := st.DeploymentTag()
	if terr != nil {
		tag = ""
	}
	// The identity this plan is signed against (#398): the container name on
	// a compose host, the unit on a native one. A profile that cannot name
	// its node returns no plan, rather than one signed against "".
	node, err := profile.IdentityKey()
	if err != nil {
		return configPlan{}, err
	}
	planID, fp, confirmCode := planIdentity(rb.ID, node, params)
	// Read here, in the ONE place both the model's assessment and the gate
	// decision are built from, so the sentence the model reads and the reason
	// the operator is given come from a single reading of the node. Two reads
	// of a state that moves is how an assessment saying "a rotation is
	// running" ends up beside a gate that offers the change anyway.
	//
	// A failed read is logged and treated as not in flight, never returned as
	// an error: RotationInFlight fails open on purpose, and turning its error
	// into a failed plan would make an unreadable log block every change.
	rotating, rotationDetail, roterr := s.rotationInFlightCached(st)
	if roterr != nil {
		log.Printf("[config-action] the store-rotation state could not be read, treating it as not in flight: %v", roterr)
	}
	return configPlan{
		Key: key, Value: value,
		Node:           s.selfRestartNode(profile),
		Verdicts:       vs,
		Blocked:        blocked,
		Rotating:       rotating,
		RotationDetail: rotationDetail,
		RotationRhythm: s.rotationRhythmWhile(rotating, st),
		Assessment:     configAssessment(st, tag),
		PlanID:         planID,
		Fingerprint:    fp,
		ConfirmCode:    confirmCode,
	}, nil
}

// ── the decision ────────────────────────────────────────────────────────

// configRefusedInvalid is RB-003's own refusal, and it sits AHEAD of the
// compact check for the reason wrong_target does on the upgrade: telling an
// operator to widen their class list, and only then that the value was outside
// its band, is two ceremonies for one mistake.
const configRefusedInvalid = "invalid_change"

type configActionInputs struct {
	Role      string
	AskedNode string
	Self      restartNode
	// InvalidWhy is the sentence explaining why this key and value cannot be
	// applied to this node — an empty string means they can. It covers three
	// things the operator reads identically: a key outside the allow-list, a
	// value outside its band, and a key the file does not have (or already
	// holds this value).
	InvalidWhy           string
	CompactPermitsConfig bool
	WindowOpen           bool
	Blocked              bool
	// Rotating is a NuDB store rotation in flight on this node, read at
	// assessment time from the same wrapper verb the wrapper's own restart
	// guard reads. False when it could not be read, see RotationInFlight.
	Rotating bool
}

// decideConfigAction applies the seven refusals in the order that gives the
// operator the remedy they can act on next — the restart's order, with the
// change's own validity inserted where the upgrade puts its target check.
//
//   - monitor first, for the reason decideRestartAction gives.
//   - the wrong node second: no window on THIS host authorises an act on
//     another one.
//   - the change's own validity third, ahead of the compact deliberately.
//     Telling an operator to widen their class list and only then that the
//     value was outside its band is two ceremonies for one mistake.
//   - the compact fourth: breaking glass does not add a class.
//   - the node's own facts fifth: a store rotation in flight, then a blocked
//     precondition. Issue #387 extends issue #92's ruling (operator ruling
//     2026-09-15, restart-only at the time) to this act: this turn has
//     already read the node and knows the config change cannot happen, so a
//     no-window admin asking during a rotation is told so directly, rather
//     than sent to spend a passkey opening a window that a fact already read
//     makes pointless. decideConfigGate (turn one, no host read) still
//     answers break glass first and cannot see either fact. This is turn
//     two diverging from turn one on purpose, in the one case where turn two
//     knows something turn one cannot.
//   - break glass last. Reached only once the node's own facts have cleared,
//     so a config change that IS possible once a window opens is the only
//     one still asking the operator to open one.
//
// The rotation sits ahead of blocked for the reason decideRestartAction gives
// (issue #80): it is the shorter and more certain clock, and preconditions
// read DURING a rotation are partly reporting the rotation's own effects.
//
// Every key in v1 is read at startup, so this act ends in the restart the
// wrapper refuses with exit 64 mid-rotation. One approval covers the edit and
// that restart, so a rotation spends the operator's grant on the half that
// cannot run. Refusing HERE, before any caller mints a gate, is
// what keeps the file from being rewritten for a node that then will not
// come back to read it.
//
// This no longer calls decideConfigGate as a single unit: issue #387 needs
// rotating and blocked spliced between the compact check and the window
// check, which one call to decideConfigGate cannot express. The three
// conditions the two decisions share are reproduced here in the same
// relative order, so TestTheConfigGateAndTheConfigActionAgreeOnWhatTheyShare
// still holds with rotating and blocked both false, turn one's own view.
func decideConfigAction(in configActionInputs) (reason string, ok bool) {
	if in.Role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !in.Self.namesThisNode(in.AskedNode) {
		return restartRefusedWrongNode, false
	}
	if in.InvalidWhy != "" {
		return configRefusedInvalid, false
	}
	if !in.CompactPermitsConfig {
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

// decideConfigGate is the first-turn question, and it is the restart's three
// conditions with the config class in place of the restart class.
func decideConfigGate(role string, compactPermitsConfig, windowOpen bool) (reason string, ok bool) {
	if role == roleMonitor {
		return restartRefusedMonitor, false
	}
	if !compactPermitsConfig {
		return restartRefusedNotPermitted, false
	}
	if !windowOpen {
		return restartRefusedBreakGlass, false
	}
	return "", true
}

// ── the proposal the operator sees ──────────────────────────────────────

// considerConfigAction turns a model's parsed <action kind="config"/> into
// either the gate the page renders under that answer, or the one honest
// reason it cannot.
func (s *server) considerConfigAction(ctx context.Context, a interrogate.ActionRequest, role string, asker ledger.Actor) (action, refused map[string]any) {
	profile, node, st, err := s.stateKeyed(ctx)
	if err != nil {
		// Named, never silent: the operator has just said yes to a change,
		// and a nil here leaves them with no gate, no refusal and nothing to
		// do — the validator1 failure of 2026-08-21, from a different door.
		log.Printf("[config-action] the host could not be read: %v", err)
		return nil, map[string]any{
			"kind": interrogate.ActionKindConfig, "reason": upgradeRefusedPlanUnavailable,
			"key": a.Key, "value": a.Value,
			"detail": "the node's own state could not be read just now",
		}
	}

	// The band first, because a value outside it cannot bind — and a plan
	// that will not bind cannot be evaluated at all, so the refusal has to be
	// available before the plan is.
	invalidWhy := ""
	if err := runbook.ValidateConfigChange(a.Key, a.Value); err != nil {
		invalidWhy = err.Error()
	}

	// The identity comes from the profile, which is available whether or not
	// the plan is: a refusal about a config change still has to name the node
	// it is about.
	self := s.selfRestartNode(profile)

	var plan configPlan
	var diff configDiff
	if invalidWhy == "" {
		p, perr := s.configPlanWith(profile, st, a.Key, a.Value)
		if perr != nil {
			log.Printf("[config-action] the config plan could not be evaluated: %v", perr)
			return nil, map[string]any{
				"kind": interrogate.ActionKindConfig, "reason": upgradeRefusedPlanUnavailable,
				"key": a.Key, "value": a.Value, "node": self,
				"detail": perr.Error(),
			}
		}
		plan = p
		// The diff is a reading of the node's own file, and its failure modes
		// are the operator's to read: no such line, or already this value.
		d, derr := configDiffFor(st, a.Key, a.Value)
		if derr != nil {
			invalidWhy = derr.Error()
		} else {
			diff = d
		}
	}
	plan.Node = self

	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())

	reason, ok := decideConfigAction(configActionInputs{
		Role:                 role,
		AskedNode:            a.Node,
		Self:                 self,
		InvalidWhy:           invalidWhy,
		CompactPermitsConfig: accErr == nil && acc.Permits(runbook.ClassConfig),
		WindowOpen:           windowOpen,
		Blocked:              plan.Blocked,
		// False on the invalid path, where no plan was evaluated and no
		// rotation was read. That costs nothing: configRefusedInvalid is
		// answered before the gate, so a rotation could not have changed the
		// refusal the operator gets.
		Rotating: plan.Rotating,
	})
	if !ok {
		return nil, s.withCompactReason(s.configActionRefusal(reason, a, plan, invalidWhy), reason, node, accErr)
	}

	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		l.AppendAs(ledger.KindActionProposed, plan.PlanID,
			"a configuration change on "+plan.Node.Label+" was proposed",
			map[string]any{
				"kind": interrogate.ActionKindConfig, "runbook": configRunbookID,
				"key": plan.Key, "value": plan.Value, "node": plan.Node.Label,
				"hostname": plan.Node.Hostname, "container": plan.Node.Container,
				// stanza is empty for a key=value setting and is the section
				// header for the other shape. Recorded beside the lines
				// because the lines alone do not name what changed: "medium"
				// to "large" is not an entry anyone can audit.
				"file": diff.File, "stanza": diff.Stanza,
				"before": diff.Before, "after": diff.After,
				"plan_id": plan.PlanID, "confirm_code": plan.ConfirmCode,
			}, asker)
	}

	return map[string]any{
		"kind": interrogate.ActionKindConfig, "runbook": configRunbookID,
		"key": plan.Key, "value": plan.Value, "node": plan.Node,
		"plan_id": plan.PlanID, "fingerprint": plan.Fingerprint,
		"confirm_code": plan.ConfirmCode,
		// The scope the ceremony must be held for. Named by the service, not
		// chosen by the page: a compound grant is what makes one passkey
		// cover the edit and the restart, and a page picking "config" alone
		// would leave the change sitting unapplied behind a second ceremony
		// nobody was told about.
		"scope":      configScopeFor(diff),
		"diff":       diff,
		"assessment": plan.Assessment, "verdicts": plan.Verdicts,
		"expected": restartExpectation,
	}, nil
}

// configScopeFor names the ceremony this change needs. Every key in v1 is read
// at startup, so this is always the compound scope today — derived rather than
// hardcoded, because a fifth key that took effect live would need the other
// one and a constant here would silently restart the node anyway.
func configScopeFor(d configDiff) string {
	if d.RestartRequired {
		return "config-restart"
	}
	return "config"
}

// configActionRefusal renders one refusal with the one remedy that follows
// from it.
func (s *server) configActionRefusal(reason string, a interrogate.ActionRequest, plan configPlan, invalidWhy string) map[string]any {
	out := map[string]any{
		"kind": interrogate.ActionKindConfig, "reason": reason, "node": plan.Node,
		"key": a.Key, "value": a.Value,
	}
	switch reason {
	case restartRefusedWrongNode:
		out["asked_for"] = a.Node
		out["this_node"] = plan.Node.Label
		out["hostname"] = plan.Node.Hostname
	case configRefusedInvalid:
		// The detail IS the band, or the reason the file cannot take this
		// change. Rendered verbatim: a refusal an operator cannot act on is a
		// refusal that costs them a support question.
		out["detail"] = invalidWhy
		// Names, not the ConfigKey structs: the drawer joins this list into a
		// sentence, and the struct form JSON-encoded to "[object Object]" in
		// the operator's face (observed on stock-node2, 2026-08-21).
		out["allowed"] = runbook.ConfigKeyNames()
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

// considerConfigGate answers a first-turn <intent kind="config"/> marker.
// No host read: the answer to "may you" does not depend on how the node is
// doing.
func (s *server) considerConfigGate(ctx context.Context, role string) map[string]any {
	node, keyErr := s.nodeKey(ctx)
	if keyErr != nil {
		// The reasoning is considerRestartGate's, #398.
		log.Printf("[config-gate] no node identity to gate against: %v", keyErr)
		return map[string]any{
			"kind": interrogate.ActionKindConfig, "reason": upgradeRefusedPlanUnavailable,
			"detail": keyErr.Error(),
		}
	}
	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())
	reason, ok := decideConfigGate(role, accErr == nil && acc.Permits(runbook.ClassConfig), windowOpen)
	if ok {
		return nil
	}
	out := map[string]any{"kind": interrogate.ActionKindConfig, "reason": reason}
	if reason == restartRefusedNotPermitted {
		out["command"] = s.reacceptCommand()
	}
	return s.withCompactReason(out, reason, node, accErr)
}

// configClassLine is the compact's own sentence about this class, for the
// ASKER AND ACCESS block. Its own line beside the other two, because an
// operator can hold one class and not the others and one sentence covering
// all three would be false on most hosts.
func configClassLine(permitted bool) string {
	if permitted {
		return "  config class: permitted by the operator compact accepted on this host\n"
	}
	return "  config class: NOT permitted by the operator compact accepted on this host — " +
		"a configuration change is refused here until it is re-accepted with the wider class list\n"
}

// configLeftAs says what a config change that stopped before its restart
// left behind, from the node's reading as it stopped (#769): "not in
// effect" only when the process answering is the one from before the edit.
func configLeftAs(p *execute.Proof, diff configDiff) string {
	written := diff.Key + "=" + diff.Value + " is written to " + diff.File
	switch {
	case p.State() == execute.NotRestarted:
		return "The node was not restarted, so " + written + " but not in effect: the process " +
			"answering, read just now, is the one that started on the old configuration."
	case p.Restarted():
		return written + ". The node restarted during this run by some other hand and reports " +
			p.Version() + ", " + p.ServerState() + "; whether it read the new value is not known from here."
	}
	return written + ". The node did not give a reading as the run stopped (" + p.ReadError() +
		"), so whether the new value is in effect is not known from here."
}

// finishConfigStage is what happens after the edit — ADR 0018 step 5.
//
// It mirrors the upgrade's prepare handoff line for line, deliberately: the
// two are the same shape (a reversible stage, then an interrupting one under
// one grant), and a second implementation of "re-check the grant, re-measure
// the preconditions, hand off" is a second place for the handoff to be wrong.
//
// The difference is what it says when there is no restart to chain into. An
// upgrade's prepare that stops there has staged a version. A config change
// that stops there has written a setting the node has not read, and the
// operator has to be told that in the sentence they are looking at.
func (s *server) finishConfigStage(ex *execute.Executor, rl *execute.RunLog,
	req executeRequest, rb runbook.Runbook, params runbook.Params, diff configDiff,
	steps []execute.Step, confirm func(execute.Step, string) bool,
	approvalsDir, planID, fingerprint, node, baseline string, st *host.State, chained bool) {

	applied := fmt.Sprintf("%s=%s is now in %s. The dated copy taken before the edit is named "+
		"above; restoring it puts the old value back.", diff.Key, diff.Value, diff.File)

	// Re-checked NOW, never reused from before the edit ran: a compound
	// approval revoked, or one that expired while the edit was in flight,
	// must not still be treated as covering the restart it was granted
	// alongside.
	if _, cerr := approval.Check(approvalsDir, planID, fingerprint, node,
		approval.StageRestart, time.Now()); cerr != nil {
		// A config change approved on its own ends here, and the edit is
		// what it was for. A MERGED config-and-restart run does not: its
		// transcript is filed under "config-restart", and a done here read
		// as "Configuration changed and the node restarted to read it" over
		// a node that was never restarted (#769).
		unspent := settled(ex)
		reading := ex.Reading(baseline)
		if chained {
			stopBeforeRestart(ex, "the restart", cerr, reading, configLeftAs(reading, diff)+
				" The dated copy taken before the edit is named above; restoring it puts the old "+
				"value back. Approve the change again to run the restart."+unspent)
			return
		}
		rl.StageDone(reading, applied+" The node reads this setting at startup, so it is not in "+
			"effect yet: it takes effect at the next restart, which is its own approval."+unspent)
		return
	}

	rl.Write("handoff", "", "the configuration is written — one approval covers the restart too; "+
		"continuing automatically. "+diff.Key+" takes effect when the node comes back.")

	// Preconditions gating the interrupting stage, re-measured immediately
	// before it. The container-can-read check is among them, and this is the
	// second time it runs: once as a step, right after the rewrite, and once
	// here, as the thing that decides whether the node may be restarted at
	// all. A config the container cannot read is the one failure that makes a
	// restart worse than no restart.
	if verdicts, ok := ex.CheckPreconditions(approval.StageRestart, "before restart (auto-chained)"); !ok {
		// The reading that refused, not a second one (#1169): see the
		// upgrade's chained cutover in main.go.
		var failed []string
		for _, v := range verdicts {
			if !v.Passed {
				failed = append(failed, v.Name+" — "+v.Detail)
			}
		}
		unspent := settled(ex)
		reading := ex.Reading(baseline)
		ex.StopBeforeApply("stopped before the restart: its preconditions refused ("+
			strings.Join(failed, "; ")+"), so the restart did not run. "+configLeftAs(reading, diff)+
			" A fresh approval will try again."+unspent,
			reading, map[string]any{"stage": approval.StageRestart, "failed": failed})
		return
	}

	if err := ex.RunStage(context.Background(), approval.StageRestart, steps, confirm); err != nil {
		endStage(ex, rl, err, baseline)
		return
	}
	awaitRestartHealthy(ex, rl, baseline)
}
