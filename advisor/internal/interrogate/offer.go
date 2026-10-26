package interrogate

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// The break-glass offer protocol — plan-interrogative-loop §11.4. This file
// is the security core of Phase B2, and the shape of it says so: the model
// contributes exactly two things (Why, WouldRead), the service decides
// whether an offer happens at all and supplies everything else (the confirm
// code, the fingerprint, the resolved labels), and the page renders only
// what the service handed it. A model that wanted to author its own gate
// text, its own consequences, or its own button has no field here to put
// any of it in — the same structural property Request has for reads.

// offerBlockRe extracts a fenced <offer>{...}</offer> block, the same
// house idiom lookupBlockRe uses for the same reason (§5.1's trade-off:
// one text-fence protocol that survives every provider shape model.Config
// supports).
var offerBlockRe = regexp.MustCompile(`(?is)<offer>\s*(\{.*?\})\s*</offer>`)

// maxWhyLen is §11.4's own cap on the model's one sentence.
const maxOfferWhyLen = 160

// OfferRequest is the model's entire contribution to a break-glass offer.
// Nothing else about the offer — the confirm code, the button, the
// ceremony copy — has a field here to be authored into.
type OfferRequest struct {
	// Why is the model's one-sentence case for investigating deeper,
	// rendered inline on the nudge (ui-design §3). Capped and stripped of
	// markup — it is the one piece of model-authored text the operator
	// reads on this surface, and it carries no links and no formatting.
	Why string
	// WouldRead names menu items (host_read verbs) the model believes a
	// gated session would reach for. Resolved against the service's own
	// label registry by ResolveWouldRead — never echoed verbatim.
	WouldRead []string
}

type rawOffer struct {
	Why       string   `json:"why"`
	WouldRead []string `json:"would_read"`
}

func decodeOfferBlock(jsonText string, into *rawOffer) error {
	return json.Unmarshal([]byte(jsonText), into)
}

// angleOrLinkRe strips exactly what §11.4/ui-design §3 forbid in Why:
// markup and links. Applied after truncation so a long string that only
// becomes markup-shaped near its cut point cannot smuggle a tag through.
var angleOrLinkRe = regexp.MustCompile(`[<>\[\]]`)

// ParseOffer looks for a single <offer>{...}</offer> block in a model's
// FINAL reply (a reply with no <lookup> block — the caller establishes
// that; this function does not re-check it) and, if found, extracts it and
// returns the reply with the block removed. found is false when no block is
// present at all, which is the ordinary case for most replies.
func ParseOffer(reply string) (offer OfferRequest, cleanReply string, found bool) {
	m := offerBlockRe.FindStringSubmatchIndex(reply)
	if m == nil {
		return OfferRequest{}, reply, false
	}
	blockStart, blockEnd := m[0], m[1]
	jsonStart, jsonEnd := m[2], m[3]
	clean := strings.TrimSpace(reply[:blockStart] + reply[blockEnd:])

	var raw rawOffer
	if err := decodeOfferBlock(reply[jsonStart:jsonEnd], &raw); err != nil {
		// A malformed offer block costs the operator nothing: it is simply
		// not offered. Unlike a malformed <lookup> block there is no
		// corrective round here — the offer is a bonus on a final answer,
		// not something the operator is waiting on, so silently dropping it
		// is the honest behaviour, not a bug hidden by tolerance.
		return OfferRequest{}, clean, false
	}

	why := strings.TrimSpace(raw.Why)
	if len(why) > maxOfferWhyLen {
		why = why[:maxOfferWhyLen]
	}
	why = angleOrLinkRe.ReplaceAllString(why, "")
	if why == "" {
		return OfferRequest{}, clean, false
	}

	return OfferRequest{Why: why, WouldRead: raw.WouldRead}, clean, true
}

// hostVerbLabels resolves a host_read verb into the operator-facing label
// the offer and the gate show (ui-design §3's "would_read... resolved,
// not echoed", §11.4's "the resolved read labels" belonging to the
// service). Deliberately its own small registry rather than importing
// internal/host's Probe.Title — this package stays dependency-free of
// everything but the standard library (menu_items.go's own note on
// hostVerbs says the same about drift risk, accepted there for the same
// reason).
var hostVerbLabels = map[string]string{
	"show-config":     "the node's configuration (key material already removed)",
	"resources":       "memory, swap and load",
	"sysctl-relevant": "kernel settings that affect a validator",
	"disk":            "disk on the node's data path",
	"limits":          "the node process's resource limits",
	"show-validators": "the configured validator list sites",
	"show-toml":       "the domain verification file this node publishes",
	"unit-status":     "systemd state of the Aperire units",
	"node-log":        "the node's log tail",
	"journal":         "the journal for the Aperire units",
}

// ResolveWouldRead turns the model's raw would_read entries into labels
// resolved from the service's own registry, in the registry's own words —
// an entry that does not name a real host_read verb is dropped, never
// echoed (§11.4). Order is preserved and duplicates are collapsed, so a
// model that names "node-log" twice does not produce a doubled list.
func ResolveWouldRead(entries []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range entries {
		label, ok := hostVerbLabels[strings.TrimSpace(e)]
		if !ok || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	return out
}

// readLabels names the non-host reads in the operator's words, for an offer
// the service authors itself when a read was refused for tier and the model
// wrote no <offer> block. Host reads name their verb through hostVerbLabels.
var readLabels = map[string]string{
	ReadNodeLedgers:        "more of this node's ledger record",
	ReadMetricHistory:      "more metric history",
	ReadMetricRecent:       "more recent metric samples",
	ReadAgreementWindow:    "more of the agreement record",
	ReadMissedLedgers:      "more of the missed-validation record",
	ReadAlerts:             "more of the alert record",
	ReadFiring:             "the firing alerts again",
	ReadPublicLedger:       "more public ledger lookups",
	ReadPublicLedgerRange:  "more public ledger ranges",
	ReadPublicValidator:    "more public validator lookups",
	ReadRestartAssessment:  "the restart assessment",
	ReadUpgradeAssessment:  "the upgrade assessment",
	ReadConfigAssessment:   "the configuration assessment",
	ReadRollbackAssessment: "the rollback assessment",
}

// SynthesizeOffer builds the offer the operator should always see when the
// ordinary tier refused something: the model may not have authored an
// <offer> block (it often does not), and a refusal line with no way forward
// reads as a dead end to anyone new to break glass (operator, 2026-08-19:
// "5 lookups. 1 refused: metric_history (needs an approved break-glass
// session)" and nothing to click). Why is service-authored, plain, and says
// what break glass is; WouldRead names the refused reads in the registry's
// words. Returns ok=false when nothing was refused for tier.
func SynthesizeOffer(steps []Step) (req OfferRequest, resolved []string, ok bool) {
	seen := map[string]bool{}
	var names []string
	for _, st := range steps {
		if st.RefusedBecause != RefusedTier {
			continue
		}
		label := ""
		if st.Read == ReadHost {
			verb := strings.Fields(st.Params)
			if len(verb) > 0 {
				label = hostVerbLabels[verb[0]]
			}
			if label == "" && st.Label != "" {
				// The service's own up-front refusal ("further host reads
				// this question") carries no verb; its label is the reading.
				label = st.Label
			}
			if label == "" {
				label = "a host read"
			}
		} else if l, found := readLabels[st.Read]; found {
			label = l
		} else if st.Read != "" {
			label = st.Read
		}
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		names = append(names, label)
	}
	if len(names) == 0 {
		return OfferRequest{}, nil, false
	}
	n := len(names)
	why := "The ordinary tier stopped short of what this needs"
	if n == 1 {
		why += " (one read refused)."
	} else {
		why += " (" + strconv.Itoa(n) + " reads refused)."
	}
	why += " A break-glass window lifts those limits for fifteen minutes; an admin approves it with a passkey, and every read inside it is recorded."
	return OfferRequest{Why: why, WouldRead: names}, names, true
}

// OfferConditions bundles the facts §11.4's gating conditions 2, 3, 5 and 6
// need — condition 1 ("a model is configured and the reply is a final
// answer") is guaranteed by the caller before ParseOffer is even consulted,
// and condition 4 ("at least one would_read entry resolves") is checked by
// ShouldOffer directly against the already-resolved list, so it needs no
// field here.
type OfferConditions struct {
	// CompactPermitsInvestigate is acc.Permits(runbook.ClassInvestigate) —
	// condition 2.
	CompactPermitsInvestigate bool
	// WrapperPresent is s.wrapper != "" — condition 3.
	WrapperPresent bool
	// TierRefusalOrCeilingChange is true when this answer contains at
	// least one step refused_because:"tier", OR the raised ceilings would
	// plausibly change the answer — condition 5. Because interrogate.Budget
	// now classifies every ungated ceiling hit as RefusedTier
	// (Budget.RefusalReason), the practical test a caller runs is simply
	// "any step in this answer has RefusedBecause == RefusedTier" — folded
	// to a bool here so this package does not need to re-walk []Step
	// itself.
	TierRefusalOrCeilingChange bool
	// WindowOpen is true when a break-glass window is already open for
	// this node — condition 6. An offer is dropped outright while one is
	// open: "offering to break glass to an operator whose glass is already
	// broken" (§11.4).
	WindowOpen bool
}

// ShouldOffer applies §11.4's five service-side gating conditions (of six —
// condition 1 is the caller's job, see OfferConditions) and reports whether
// an offer should be rendered at all. The service drops the block silently
// when any condition fails; there is no partial offer.
func ShouldOffer(resolvedWouldRead []string, c OfferConditions) bool {
	if !c.CompactPermitsInvestigate {
		return false
	}
	if !c.WrapperPresent {
		return false
	}
	if len(resolvedWouldRead) == 0 {
		return false
	}
	if !c.TierRefusalOrCeilingChange {
		return false
	}
	if c.WindowOpen {
		return false
	}
	return true
}
