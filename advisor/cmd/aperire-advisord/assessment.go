package main

import (
	"fmt"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/runbook"
)

// The restart assessment — ADR 0016 decision 3.
//
// An operator restarting a healthy node is not being stopped by anything;
// they are being asked to look once before they act. So the amber material
// lives here, beside the preconditions and not among them: `failuresFor` in
// the dashboard filters on !passed, so an advisory precondition would refuse
// the UPGRADE ceremony too, on a node where nothing is wrong.
//
// Deterministic, with no model involved. Every reading is already on the
// /v1/check path, and a model sentence written at the moment of a restart is
// an opinion the operator has no way to check. The cost is a plainer summary,
// and it is worth paying.

// restartExpectation is the measured one, from the 2026-08-19 resync lab:
// plain restart on 8 vCPU / 31 GB, 8 to 10 minutes back to full, dominated by
// a 6 to 9 minute connected phase. A node configured node_size: small is 1 to
// 2 minutes slower.
//
// It must not inherit the upgrade gate's "about 30 seconds offline". That
// number describes the container coming back, not the node returning to
// consensus, and an operator told 30 seconds who watches nine minutes of
// `connected` has been told something false at the worst possible moment.
const restartExpectation = "8 to 10 minutes back to full on a node of this class"

// concern is one thing worth naming before a restart. Never a refusal of
// its own: the preconditions are the refusals, and they are elsewhere. A
// concern may REPORT one, when it renders a precondition's own verdict (the
// rollback's amendment check, #676), so the two surfaces say the same thing.
type concern struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	// State is "concern" — measured, and worth reading — "undetermined",
	// which says the Advisor could not tell, or "clear", which says it
	// looked and the answer is good. An undetermined concern is not a
	// softer concern; it is an honest gap, and collapsing the two would let
	// "I did not look" render as "I looked and it was fine".
	//
	// "clear" is the state #676 was missing. A block that can only say
	// "amber" or "I did not look" has to keep saying it did not look after
	// the thing it worried about has been measured, which is what the
	// rollback gate did for a week: its own precondition read the target's
	// recorded amendment support and vouched for the rollback, and four
	// lines below it the concern insisted the question was never asked.
	State string `json:"state"`
}

const (
	stateConcern      = "concern"
	stateUndetermined = "undetermined"
	stateClear        = "clear"
)

// restartConcerns is the whole rule set, as a pure function of the readings —
// so the wording and the thresholds can be exercised without a host.
func restartConcerns(r host.Readings) []concern {
	var out []concern

	switch {
	case r.UptimeSec == nil:
		out = append(out, concern{
			Name:   "how long the node has been up could not be read",
			Detail: "the node did not report an uptime, so a restart loop would not be visible here",
			State:  stateUndetermined,
		})
	case *r.UptimeSec < 30*60:
		out = append(out, concern{
			Name: "the node started recently",
			Detail: fmt.Sprintf("it has been up %s. If it was restarted a moment ago and is being "+
				"restarted again, the reason it came back unwell is worth finding before the second one.",
				humanDuration(*r.UptimeSec)),
			State: stateConcern,
		})
	}

	if r.Peers < 5 {
		out = append(out, concern{
			Name: "peers below baseline",
			Detail: fmt.Sprintf("%d peers. Consensus still looks healthy or this plan would be "+
				"blocked, but a node rebuilding from a low peer count takes longer to come back.", r.Peers),
			State: stateConcern,
		})
	}

	switch {
	case r.DiskFreePct == nil:
		out = append(out, concern{
			Name:   "disk headroom could not be measured",
			Detail: "the data path did not answer, so free space is unknown rather than fine",
			State:  stateUndetermined,
		})
	case *r.DiskFreePct < 15:
		// Below 10% is precondition 5 and blocks. This band is the one where
		// a restart is allowed and still worth a second look.
		out = append(out, concern{
			Name: "disk headroom is thin",
			Detail: fmt.Sprintf("%.1f%% free. Above the 10%% floor this refuses below, and below the "+
				"15%% an upgrade wants.", *r.DiskFreePct),
			State: stateConcern,
		})
	}

	return out
}

// configReadableConcern is the 2026-08-19 incident, measured — ADR 0018 built
// the wrapper verb this reads. A config the container could not read made the
// node start on the image's default configuration, silently, and it kept
// running for two days looking healthy.
//
// It is a concern here rather than a precondition, and that is the difference
// between the two runbooks: a restart does not touch the file, so an
// unreadable one is something the operator should see before they restart
// into it, not a refusal. RB-003 rewrites the file, so there the same reading
// gates the restart it chains into.
//
// The verdict is reported as it comes. "unknown" is named as unknown, because
// "I could not look" must never render as "I looked and it was fine".
func configReadableConcern(verdict, detail string) (concern, bool) {
	switch verdict {
	case runbook.ConfigReadableNo:
		return concern{
			Name: "the node's container cannot read its configuration",
			Detail: detail + ". A restart re-reads the configuration, and a node that cannot read it " +
				"comes up on the image's defaults without saying so. That has happened here before.",
			State: stateConcern,
		}, true
	case runbook.ConfigReadableUnknown:
		return concern{
			Name: "whether the node can read the config it will start with could not be measured",
			Detail: detail + ". A restart re-reads the configuration, and a config the container " +
				"cannot read makes the node start on the image's defaults without saying so. This " +
				"reading did not happen, so it is unknown rather than fine.",
			State: stateUndetermined,
		}, true
	}
	return concern{}, false
}

// restartAssessment is what /v1/check and /v1/plan publish for RB-002. Shape
// is ADR 0016 decision 3, verbatim: readings, expected, concerns.
// The deployment tag arrives from the caller because /v1/check already
// published it once at the top level, and one response saying two different
// things about the same file is worse than one saying nothing.
func restartAssessment(st *host.State, deploymentTag string) map[string]any {
	r, err := st.ReadingsWithTag(deploymentTag)
	if err != nil {
		// The node not answering is itself the assessment. Nothing here
		// pretends to a reading it does not have — and the preconditions
		// will refuse this plan anyway, from the same silence.
		return map[string]any{
			"readings": host.Readings{},
			"expected": restartExpectation,
			"concerns": []concern{{
				Name:   "the node could not be read",
				Detail: err.Error(),
				State:  stateUndetermined,
			}},
		}
	}
	concerns := restartConcerns(r)
	// Asked once, here, rather than inside the pure rule set — the wrapper
	// call is a host read and restartConcerns stays exercisable without one.
	if c, ok := configReadableConcern(st.ConfigReadable()); ok {
		concerns = append(concerns, c)
	}
	return map[string]any{
		"readings": r,
		"expected": restartExpectation,
		"concerns": concerns,
	}
}

// humanDuration renders seconds the way the card reads them.
func humanDuration(sec int) string {
	switch {
	case sec < 60:
		return fmt.Sprintf("%d seconds", sec)
	case sec < 120:
		return "a minute"
	default:
		return fmt.Sprintf("%d minutes", sec/60)
	}
}
