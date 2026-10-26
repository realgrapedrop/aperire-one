package runbook

import "fmt"

// RB002Restart restarts the node in place, on the image it is already
// running — ADR 0016.
//
// It adds nothing to what the executor can do to a node. RB-001's cutover
// stage is already a restart, under the same passkey gate and the same
// wrapper; this removes the requirement to change the version in order to
// use it. What it adds is the assessment: five blocking preconditions, and
// a summary of anything amber, before an operator is asked for a final yes.
//
// Two of the five are worth calling out.
//
//   - Consensus not anomalous is the scope line, not a formality. The
//     compact's clause 5 says the Advisor never restarts the node while
//     consensus looks anomalous, in text the operator hashed. So a wedged,
//     unreachable or amendment-blocked node fails it and this runbook
//     refuses: recovering a hung node stays a manual act. Loosening that
//     needs new compact wording and a re-acceptance on every host.
//   - The deployment naming the version the node is running is what stops a
//     restart becoming an unapproved cutover. `docker compose restart`
//     almost certainly cannot pick up a staged tag, but the precondition is
//     the enforcement and the verb is defence in depth — that ordering
//     survives a change in compose's behaviour and the reverse does not.
//     On a native host the same check reads the package database instead
//     of a compose file, an install run outside the wrapper, by hand, is
//     the equivalent staged tag, and the wrapper's own restart verb takes
//     the rotation guard identically on both kinds, so nothing here changes
//     to reach a native unit instead of a container.
func RB002Restart() Runbook {
	return Runbook{
		ID:      "restart-node",
		Class:   ClassRestart,
		Summary: "Restart the node in place, on the image it is already running.",
		// One enum parameter for an operation that takes none.
		//
		// Fingerprint(id, node, params) with empty params is a constant per
		// node, so the confirm code would be a constant an operator types
		// from muscle memory and the run identifier would be one transcript
		// that grows forever. Four intents give four codes per node instead
		// of one, and land the operator's category in the ledger. Residual
		// cost, stated rather than hidden: two restarts with the same intent
		// share a code, bounded by single use plus a short expiry.
		//
		// It is called intent, not reason, and the distinction is
		// load-bearing: approval.Approval.Reason is free text, set by the
		// tab, and deliberately outside the fingerprint. This is an enum and
		// is inside it. Two fields named reason on one request is how one
		// gets fed to the other.
		Params: []Param{
			{Name: "intent", Kind: KindEnum, Required: true, Allowed: []string{
				"apply-config", "resource-pressure", "planned-maintenance", "operator-judgement",
			}},
		},
		Stages:      []string{"restart"},
		GrantScopes: []string{"restart"},
		Reversible:  true,
		ReversedBy:  "",
		ReversalNote: "Nothing to put back. The node returns on the same image and the same config. " +
			"If it does not come back, the way forward is the node's own logs, not a second restart.",
		// Empty on purpose. This runbook is operator-initiated and is never
		// raised by the service: there is no deterministic condition that
		// says "restart now", which is exactly why the assessment exists.
		Why: nil,
		Expected: []string{
			"server_state returns to proposing or full",
			"the build version is unchanged",
			"peers rebuild toward their previous count",
			"the validated ledger age falls back under 30s",
		},
		Preconditions: []Precondition{
			{
				Name: "environment profile still matches the host",
				Check: func(_ Params, h HostState) Verdict {
					const n = "environment profile still matches the host"
					// ADR 0005. A stale profile means the wrapper's paths
					// name something else.
					ok, d := h.ProfileMatches()
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				Name: "consensus is not anomalous",
				Check: func(_ Params, h HostState) Verdict {
					const n = "consensus is not anomalous"
					ok, d := h.ConsensusHealthy()
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				Name: "the deployment names the version the node is running",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the deployment names the version the node is running"
					running, err := h.RunningVersion()
					if err != nil {
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read the running version: %v", err)}
					}
					tag, err := h.DeploymentTag()
					if err != nil {
						if h.Kind() == "native" {
							return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read what the package database says is installed: %v", err)}
						}
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf("could not read what the deployment names: %v", err)}
					}
					if tag != running {
						if h.Kind() == "native" {
							return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
								"the package database says %s is installed and the node is running %s; restarting here would be an "+
									"unapproved upgrade, so it is refused", tag, running)}
						}
						return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
							"the deployment names %s and the node is running %s; restarting here would be an "+
								"unapproved upgrade, so it is refused", tag, running)}
					}
					return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf("both %s", running)}
				},
			},
			{
				Name: "diagnostic snapshot captured before any change",
				Check: func(_ Params, h HostState) Verdict {
					const n = "diagnostic snapshot captured before any change"
					// Runbook 11 opens with "do not restart yet, a restart
					// destroys the evidence".
					ok, d := h.EvidenceCaptured()
					return Verdict{Name: n, Passed: ok, Detail: d}
				},
			},
			{
				Name: "disk headroom above floor",
				Check: func(_ Params, h HostState) Verdict {
					const n = "disk headroom above floor"
					// 10%, where the upgrade's floor is 15%. An upgrade adds
					// an image; a restart adds none.
					const floorPct = 10.0
					return diskHeadroomVerdict(n, floorPct, h)
				},
			},
		},
	}
}
