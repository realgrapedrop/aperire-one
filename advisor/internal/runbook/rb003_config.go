package runbook

import "fmt"

// RB003ConfigChange changes one allow-listed configuration setting and, for a
// setting the node reads at startup, restarts it under the same approval —
// ADR 0018.
//
// It adds nothing to what the executor can do that the wrapper did not
// already permit. `set-config` and `backup-config` exist, are finite, and
// enforce the bands themselves. What this adds is the half a wrapper cannot
// do: showing the operator the exact lines that would change, before they
// approve, computed from the node's own configuration rather than from
// anything a model wrote.
//
// Two stages, and the split is the same one RB-001 makes for a different
// reason. `config` is reversible — the wrapper takes a dated copy it cannot
// be told to skip, and the node keeps validating throughout. `restart` is the
// interruption. They are one ceremony rather than two because the change does
// nothing until the restart happens, and asking for a second passkey between
// the edit and the restart leaves a node running one configuration and
// holding another.
//
// Preconditions worth calling out:
//
//   - The container-can-read check gates the RESTART stage, not everything.
//     A config the container already cannot read is not made worse by an edit,
//     and blanket-gating would make the first change on such a host impossible
//     through the Advisor — the same shape as requiring a dated backup before
//     the prepare stage that takes one. It refuses only on a definite
//     "unreadable": an unknown verdict is not evidence of failure and is
//     reported as a concern instead.
//   - Consensus not anomalous is the compact's clause 5, exactly as RB-002
//     reads it. This runbook restarts the node, so it inherits that boundary
//     verbatim rather than a looser version of it.
func RB003ConfigChange() Runbook {
	return Runbook{
		ID:      "config-change",
		Class:   ClassConfig,
		Summary: "Change one allow-listed configuration setting, and restart the node so it takes effect.",
		Params: []Param{
			// The enum comes from the allow-list table, so the parameter and
			// the band check can never name different sets.
			{Name: "key", Kind: KindEnum, Required: true, Allowed: ConfigKeyNames()},
			// The value is free-form to Param and bounded by ValidateParams
			// below, because its band is a function of the key. Declared as
			// an enum with no Allowed list would refuse everything; declared
			// as an int would refuse node_size.
			{Name: "value", Kind: ParamKind(""), Required: true},
		},
		// The reason the operator gives is NOT a parameter, and that is
		// deliberate. Fingerprint hashes every parameter, so free text inside
		// it moves the confirm code on every keystroke and the code the
		// operator was shown stops matching what /v1/approve recomputes — a
		// 409 after the passkey touch. It travels as approval.Approval.Reason
		// and lands in the ledger, exactly as RB-002's does.
		ValidateParams: func(p Params) error {
			return ValidateConfigChange(p["key"], p["value"])
		},
		Stages: []string{"config", "restart"},
		// The compound scope, mirroring the upgrade's. One ceremony, signed
		// over "config-restart" itself, covering the edit and then the
		// restart — see approval.Covers for why this is a distinct scope
		// rather than two grants minted from one assertion.
		GrantScopes: []string{"config", "restart", "config-restart"},
		Reversible:  true,
		ReversedBy:  "",
		ReversalNote: "Restore the dated backup the wrapper took before the edit — its path is in the " +
			"run log and in the ledger entry for this run. The node reads this setting at startup, so " +
			"the restored value takes effect on the next restart, exactly as the change did.",
		// Empty on purpose, as RB-002's is. No deterministic condition says
		// "change this setting now": the Advisor recommends, the operator
		// decides, and the assessment is what makes that decision informed.
		Why: nil,
		Expected: []string{
			"the setting reads back as the approved value in the node's own configuration",
			"the file's owner, group and mode are unchanged",
			"the node's container can still read the configuration",
			"server_state returns to proposing or full after the restart",
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
				Name: "consensus is not anomalous",
				Check: func(_ Params, h HostState) Verdict {
					const n = "consensus is not anomalous"
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
					// The restart's floor, not the upgrade's: this adds a
					// dated copy of a configuration file, not an image.
					const floorPct = 10.0
					return diskHeadroomVerdict(n, floorPct, h)
				},
			},
			{
				Name:  "the node's container can read its configuration",
				Gates: "restart",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the node's container can read its configuration"
					verdict, detail := h.ConfigReadable()
					switch verdict {
					case ConfigReadableNo:
						return Verdict{Name: n, Passed: false, Detail: detail + " — restarting now would start the node on " +
							"the image's defaults without saying so"}
					case ConfigReadableUnknown:
						// Passes, and says it did not measure. An unknown
						// verdict is not evidence of failure, and refusing on
						// one would refuse every deployment whose image has
						// no shell.
						return Verdict{Name: n, Passed: true, Detail: "not measured: " + detail}
					default:
						return Verdict{Name: n, Passed: true, Detail: detail}
					}
				},
			},
			{
				Name: "the deployment names the version the node is running",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the deployment names the version the node is running"
					// Inherited from RB-002 unchanged. This runbook restarts
					// the node, and a restart while the deployment names some
					// other tag is an unapproved upgrade whichever runbook
					// asked for it.
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
							"the deployment names %s and the node is running %s; restarting here would be an "+
								"unapproved upgrade, so it is refused", tag, running)}
					}
					return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf("both %s", running)}
				},
			},
		},
	}
}
