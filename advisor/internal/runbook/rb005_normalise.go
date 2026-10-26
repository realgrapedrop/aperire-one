package runbook

import (
	"fmt"
	"strings"
)

// RB005Normalise makes one change to the deployment an operator wrote, so a
// node can take an image that carries no entrypoint of its own. ADR 0023.
//
// Why it is a runbook and not a step inside the upgrade. The operator's
// ruling of 2026-09-27: the Advisor adapts to the compose it finds, changes
// only what an operation needs, shows each change as a diff, and takes each
// one on its own approval. A change hidden inside an upgrade has no ledger
// entry of its own, no rollback of its own, and no way for an operator to
// make it days before the release they are waiting for. This has all three.
//
// Why it is not a parameter of RB-003. RB-003 changes the node's own
// configuration and restarts it; this changes the DEPLOYMENT and recreates
// the container. Different file, different verbs, different reversal, and
// the code says an addition to the V1 registry is an ADR decision every
// time (0016 for RB-002, 0018 for RB-003, 0019 for RB-004). This one is
// 0023.
//
// One change per run, and the order between them is ENFORCED rather than
// documented. node-args writes entrypoint: ["/usr/bin/xrpld"], which
// bypasses an image's own entrypoint script. On a /config-only deployment
// that script is the only thing putting the operator's config where xrpld
// reads it, so writing the arguments first would take a validator off the
// network quietly: the node comes back on the package's stock config, with
// someone else's settings, no validator key, and a container reporting
// healthy. The wrapper refuses that, this refuses it earlier, and the lab
// plan proves the refusal before it proves the change.
func RB005Normalise() Runbook {
	return Runbook{
		ID:      normaliseRunbookID,
		Class:   ClassConfig,
		Summary: "Make one change to this node's deployment, so it can run an image that carries no entrypoint of its own.",
		Params: []Param{
			{Name: "change", Kind: KindEnum, Required: true, Allowed: NormaliseChanges()},
			// runtime-user's value. Declared only for that change, and
			// ValidateParams below refuses it for the other two: a
			// parameter that is meaningful for one value of an enum and
			// meaningless for another is a parameter that has to say so.
			{Name: "user", Kind: ParamKind("")},
		},
		ValidateParams: func(p Params) error {
			switch p["change"] {
			case "runtime-user":
				if !userSpec(p["user"]) {
					return fmt.Errorf("runtime-user needs a numeric uid:gid, for instance 997:997")
				}
			default:
				if p["user"] != "" {
					return fmt.Errorf("%s takes no user", p["change"])
				}
			}
			return nil
		},
		// One stage. The change and the recreate are one act: a
		// deployment edited and not recreated is a node running one file
		// and holding another, which is the state RB-003's own two stages
		// exist to avoid and the reason they are one ceremony.
		Stages:      []string{"normalise"},
		GrantScopes: []string{"normalise"},
		Reversible:  true,
		ReversedBy:  "",
		ReversalNote: "Restore the dated copy the wrapper took before the edit. Its path is in the run " +
			"log and in the ledger entry for this run, and restoring it puts the deployment back exactly " +
			"as it was, including anything else that was in the file.",
		// Nothing here fires on its own. A deployment that could be
		// normalised is not a deployment that has to be: the advice panel
		// says what it thinks, and the upgrade's own precondition is what
		// makes it necessary, for the one target that needs it.
		Why: nil,
		Expected: []string{
			"the deployment names exactly the change that was approved, and nothing else moved",
			"the node comes back with the same node key and the same validator key",
			"the node comes back on the same build it went down on",
			"the file's owner, group and mode are unchanged",
		},
		Preconditions: []Precondition{
			{
				Name: "this is a container deployment",
				Check: func(_ Params, h HostState) Verdict {
					const n = "this is a container deployment"
					if h.Kind() == "native" {
						return Verdict{Name: n, Passed: false, Detail: "a native host has no deployment file to change"}
					}
					return Verdict{Name: n, Passed: true, Detail: "this node runs in a container"}
				},
			},
			{
				Name: "environment profile still matches the host",
				Check: func(_ Params, h HostState) Verdict {
					ok, d := h.ProfileMatches()
					return Verdict{Name: "environment profile still matches the host", Passed: ok, Detail: d}
				},
			},
			{
				Name: "the deployment was read",
				Check: func(_ Params, h HostState) Verdict {
					const n = "the deployment was read"
					sh := h.NodeShape()
					if !sh.Read {
						return FailedToMeasure("the deployment could not be read, so nothing about it was " +
							"checked: " + strings.Join(sh.Notes, "; ")).Verdict(n, SafetyCritical)
					}
					return Verdict{Name: n, Passed: true, Detail: "the resolved deployment was read"}
				},
			},
			{
				// The one that matters, and the reason this runbook
				// exists rather than three steps in a row.
				Name: "this change is the next one this deployment needs",
				Check: func(p Params, h HostState) Verdict {
					const n = "this change is the next one this deployment needs"
					sh := h.NodeShape()
					if !sh.Read {
						return FailedToMeasure("the deployment could not be read").Verdict(n, SafetyCritical)
					}
					switch p["change"] {
					case "config-mount":
						if sh.ConfigAtEtc {
							return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
								"this node's config already reaches %s; there is nothing to add", EtcConfigPathName)}
						}
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"the config does not reach %s yet, and this mounts it there read-only, "+
								"keeping the /config pair a rollback needs", EtcConfigPathName)}
					case "node-args":
						if !sh.ConfigAtEtc {
							return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
								"writing an entrypoint here would bypass the image's own script, which is the "+
									"only thing putting this node's config at %s. The node would come back on "+
									"the package's stock config: someone else's settings, no validator key, and "+
									"a container reporting healthy. Mount the config there first",
								EtcConfigPathName)}
						}
						if sh.ArgsWrittenDown {
							return Verdict{Name: n, Passed: false, Detail: fmt.Sprintf(
								"this deployment already names the arguments it runs with (%s)",
								strings.Join(sh.CommandOverride, " "))}
						}
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"the config is mounted at %s, so the arguments can be written down without "+
								"bypassing anything", EtcConfigPathName)}
					case "runtime-user":
						return Verdict{Name: n, Passed: true, Detail: fmt.Sprintf(
							"this writes user: %q, which the deployment carries across every later recreate",
							p["user"])}
					}
					return Verdict{Name: n, Passed: false, Detail: "unknown change"}
				},
			},
			{
				Name: "a dated copy of the deployment is taken before the edit",
				Gates: "normalise",
				Check: func(_ Params, _ HostState) Verdict {
					const n = "a dated copy of the deployment is taken before the edit"
					// The wrapper takes it itself and cannot be told to
					// skip it, the same guarantee set-config gives. Stated
					// as a precondition so the operator reads it before
					// approving rather than finding it in a transcript.
					return Verdict{Name: n, Passed: true, Detail: "the wrapper copies the file before it " +
						"writes, and prints the path; restoring that copy is the whole reversal"}
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
		},
	}
}

// normaliseRunbookID is the id, spelled once.
const normaliseRunbookID = "normalise-deployment"

// NormaliseChanges is the closed set, in the order they have to happen.
//
// The order is not a suggestion: node-args on a deployment whose config
// does not reach /etc/xrpld is the one mistake in this whole design that
// would take a validator off the network without saying anything, and
// production is the shape it applies to.
func NormaliseChanges() []string {
	return []string{NormaliseRuntimeUser, NormaliseConfigMount, NormaliseNodeArgs}
}

// The three, named. A finding says which change puts it right (host's
// Finding.Fix), the card's button sends that name back, and the runbook
// binds it: one spelling, in one place, rather than the same three strings
// typed into four files.
const (
	NormaliseRuntimeUser = "runtime-user"
	NormaliseConfigMount = "config-mount"
	NormaliseNodeArgs    = "node-args"
)

// userSpec is the same shape the wrapper's require_userspec enforces.
// Numeric, because a name resolves differently inside the container than
// on this host and the whole point of writing the line is that the account
// the node comes back as is the account it went down as.
func userSpec(v string) bool {
	if v == "" || len(v) > 21 {
		return false
	}
	uid, gid, ok := strings.Cut(v, ":")
	if !ok {
		return false
	}
	return allDigits(uid) && allDigits(gid)
}

func allDigits(v string) bool {
	if v == "" || len(v) > 10 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
