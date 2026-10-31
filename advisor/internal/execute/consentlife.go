package execute

import (
	"fmt"
	"time"

	"aperire-advisor/internal/approval"
)

// How long an approval has to last for the run it is about to start (#772).
//
// RunStage asks again before every step that changes the host (#1047), so an
// approval that runs out mid-run stops it before the next such step, and the
// stop says so honestly (#769). What that never prevented is starting a run
// that was always going to stop that way. The lab case: "Try the upgrade
// again" pressed at 06:27:14 on a grant that expired at 06:27:17, a prepare
// that took 29 seconds, and a real image pull spent on a run that could never
// reach its restart (aperire4, 2026-09-30).
//
// So the question consentStands will ask at each step is asked once, up
// front, against the clock: will the grant covering each stage still be
// live when that stage's last host-changing step begins? A step that only
// reads after it (the verifier's polls after a restart) needs no consent, and
// readsOnly is the same closed list consentStands uses, so the two can never
// disagree about which steps need the approval.
//
// The timings are budgets, not measurements of this host. They are generous
// on purpose: a run refused here costs the operator a fresh passkey touch,
// and a run that stops partway costs that plus a prepare. They also have to
// stay well inside the shortest life a fresh grant gets (ten minutes, the
// restart card's and the service's default; the upgrade card asks for
// thirty), or a freshly approved run would be refused and nothing could
// ever start.

// stepBudgets is how long each verb is allowed for, where the default is not
// enough. Sourced where a figure exists; the rest are stated as estimates.
var stepBudgets = map[string]time.Duration{
	// A whole official prepare took 29 seconds on aperire4, pull and
	// verification included (#772). Each half gets more than that alone.
	"pull-official":         90 * time.Second,
	"verify-official-image": 60 * time.Second,
	// The tag pull is the same fetch without the pin.
	"pull": 90 * time.Second,
	// The image build from the signed package "takes about a minute" (#678).
	"build-image": 3 * time.Minute,
	// Not measured in the tree: a package download and install. An
	// estimate, three times what a pull is given.
	"package-install": 2 * time.Minute,
	"package-keep":    30 * time.Second,
}

// defaultStepBudget covers every other verb: a backup, a one-line rewrite, a
// digest read. Each is a wrapper call that returns in seconds.
const defaultStepBudget = 10 * time.Second

// stageOverhead is what each stage spends before its first step: the signed
// approval check, the store-rotation read, and, at the hand-off into a
// chained restart, the preconditions measured again.
const stageOverhead = 20 * time.Second

func stepBudget(verb string) time.Duration {
	if d, ok := stepBudgets[verb]; ok {
		return d
	}
	return defaultStepBudget
}

// ConsentDeadline is one stage's answer: how far into the run its last step
// that needs the approval begins, and which step that is.
type ConsentDeadline struct {
	Stage string
	Step  string
	At    time.Duration
}

// ConsentNeeded walks the run's stages in the order they run and says, for
// each, how long after the run starts its last host-changing step begins.
// A stage with no such step needs nothing and is left out.
func ConsentNeeded(stages []string, steps []Step) []ConsentDeadline {
	var out []ConsentDeadline
	var elapsed time.Duration
	for _, stage := range stages {
		elapsed += stageOverhead
		var last *ConsentDeadline
		for _, s := range steps {
			if s.Stage != stage {
				continue
			}
			if !readsOnly[s.Verb] {
				last = &ConsentDeadline{Stage: stage, Step: s.Name, At: elapsed}
			}
			elapsed += stepBudget(s.Verb)
		}
		if last != nil {
			out = append(out, *last)
		}
	}
	return out
}

// ShortApprovalError is a run refused before it started because its approval
// would run out before the run reached a step that needs it.
type ShortApprovalError struct {
	Stage   string
	Step    string
	Scope   string
	Left    time.Duration
	Need    time.Duration
	Expires time.Time
}

func (e *ShortApprovalError) Error() string {
	return fmt.Sprintf("the approval has %s left, and this run needs it for about %s more, "+
		"until the step %q begins, so it would stop partway. Nothing was done and the approval "+
		"was not used. Revoke it and approve again, or approve again once it runs out at %s",
		roundLife(e.Left), roundLife(e.Need), e.Step, e.Expires.UTC().Format("15:04:05 MST"))
}

// Data is the ledger row's detail for this refusal, the same on both doors.
func (e *ShortApprovalError) Data() map[string]any {
	return map[string]any{
		"reason": "approval_too_short", "stage": e.Stage, "step": e.Step, "granted_scope": e.Scope,
		"left_seconds": int(e.Left.Seconds()), "need_seconds": int(e.Need.Seconds()),
		"expires_at": e.Expires,
	}
}

func roundLife(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 2*time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Round(time.Second).Seconds()))
	}
	return fmt.Sprintf("%d minutes", int(d.Round(time.Minute).Minutes()))
}

// ApprovalLasts refuses a run whose approval would run out before the run
// reaches a step that needs it. Each stage is checked against the grant that
// covers it, found the way RunStage finds it, so a merged run's compound
// grant is held to the restart at the end and a stage approved on its own to
// its own steps.
//
// A stage with no usable grant at all is not this check's to refuse: RunStage
// refuses that in its own words, and saying "too short" over "none" would
// name the wrong cause.
func ApprovalLasts(dir, planID, fingerprint, node string, stages []string, steps []Step, now time.Time) error {
	for _, d := range ConsentNeeded(stages, steps) {
		a, err := approval.Check(dir, planID, fingerprint, node, d.Stage, now)
		if err != nil {
			continue
		}
		if left := a.ExpiresAt.Sub(now); left < d.At {
			return &ShortApprovalError{Stage: d.Stage, Step: d.Step, Scope: a.Stage,
				Left: left, Need: d.At, Expires: a.ExpiresAt}
		}
	}
	return nil
}
