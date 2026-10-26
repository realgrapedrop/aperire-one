package interrogate

import (
	"regexp"
	"strings"
)

// The restart action protocol — ADR 0016, amended 2026-08-19.
//
// Before this file the Advisor's restart was a standing card on the tab: a
// control sitting there whether or not anyone had asked for one. The
// operator's ruling replaced it with a conversation — the admin asks, the
// Advisor looks, and the gate appears under the answer that qualifies it.
//
// This file is the model's entire contribution to that, and the shape of it
// says so: three bounded strings, checked against fixed lists here before a
// caller ever sees them. The model does not author the confirm code, the
// fingerprint, the readings, the preconditions or the button, and it has no
// field to put any of them in — the same structural property OfferRequest
// has for break glass and Request has for reads. What the model contributes
// is a proposal that an operator, holding a passkey, may then refuse.
//
// It cannot name another host, either. Node is carried so the service can
// REFUSE a mismatch loudly rather than silently restarting whatever this
// advisord happens to supervise (operator, 2026-08-19: "we don't want the
// wrong node or validator restarted"). A model that names a peer gets a
// refusal naming both hosts, never a routed act.

// The kinds this protocol carries. Named as constants because the parser
// refuses anything else, and a third kind has to be added in both places.
//
// Operator ruling, 2026-08-19: "break glass should be one thing that allows
// things like upgrade, restarts, forensics." So an upgrade is asked for the
// same way a restart is — same two turns, same window, same passkey — and
// the Upgrade card stays where it is for the operator who would rather start
// from a control than from a sentence.
const (
	ActionKindRestart = "restart"
	ActionKindUpgrade = "upgrade"
	// ActionKindConfig is RB-003 — ADR 0018. One allow-listed configuration
	// setting, changed and then applied by a restart under one approval.
	//
	// It carries the two parameters that identify the change and nothing
	// else. The operator's REASON is not here: it is free text, it lands in
	// the approval and the ledger, and a free-text field inside the model's
	// block would be text the service has to sanitise before rendering. The
	// model's contribution stays what it is for the other two acts — a
	// proposal made of bounded values checked against fixed lists.
	ActionKindConfig = "config"
	// ActionKindRollback is RB-004 — ADR 0019. The upgrade's inverse: put the
	// node back on the release it was running before the last version change.
	//
	// It carries a target the way an upgrade does, and for the same reason —
	// the operator must read WHICH version they are approving in the sentence
	// that names the node — and it is even less the model's choice here. The
	// service derives the target from the node's own deployment backups and
	// run history and refuses anything else, so this field is what the
	// operator sees, never what decides.
	ActionKindRollback = "rollback"
)

// actionKinds is the set the parser accepts, so an unknown kind is dropped
// here rather than switched on by a caller who has no branch for it.
var actionKinds = map[string]bool{
	ActionKindRestart:  true,
	ActionKindUpgrade:  true,
	ActionKindConfig:   true,
	ActionKindRollback: true,
}

// restartIntents is RB-002's own enum, duplicated here for the same reason
// hostVerbs is duplicated from internal/host: this package keeps zero
// dependency beyond the standard library so it stays reviewable in
// isolation. runbook.RB002Restart's Params list is the enforcing copy —
// BindParams refuses an unknown value there regardless of what happens
// here, so a drift between the two costs a refused plan, never a wrong one.
var restartIntents = map[string]bool{
	"apply-config":        true,
	"resource-pressure":   true,
	"planned-maintenance": true,
	"operator-judgement":  true,
}

// RestartIntents is the enum in declaration order, for the prompt guide.
func RestartIntents() []string {
	return []string{"planned-maintenance", "apply-config", "resource-pressure", "operator-judgement"}
}

// configKeys is RB-003's own allow-list, duplicated here for the same reason
// restartIntents is: this package keeps zero dependency beyond the standard
// library. runbook.ConfigKeyNames is the enforcing copy — BindParams refuses
// an unknown key there regardless of what happens here, and the privilege
// wrapper refuses it again below that — so a drift between the three costs a
// refused plan, never a wrong one.
var configKeys = map[string]bool{
	"online_delete":   true,
	"advisory_delete": true,
	"node_size":       true,
	"ledger_history":  true,
}

// rollbackIntents is RB-004's own enum, duplicated here for the reason
// restartIntents is. runbook.RB004Rollback's Params list is the enforcing
// copy, so a drift between the two costs a refused plan, never a wrong one.
//
// Three, and none of them is an acknowledgement: the store risk is a concern
// the gate shows, not a category the operator picks to say they read it.
var rollbackIntents = map[string]bool{
	"planned-rollback":     true,
	"regression-suspected": true,
	"operator-judgement":   true,
}

// RollbackIntents is the enum in declaration order, for the prompt guide.
func RollbackIntents() []string {
	return []string{"regression-suspected", "planned-rollback", "operator-judgement"}
}

// ConfigKeys is the allow-list in declaration order, for the prompt guide.
func ConfigKeys() []string {
	return []string{"online_delete", "advisory_delete", "node_size", "ledger_history"}
}

// configValueRe bounds a proposed value's SHAPE, and nothing more. The band —
// which values of which key are safe — is the service's, checked against the
// same table the wrapper enforces; this only keeps a value that is not a short
// alphanumeric token out of the plan machinery.
//
// It is deliberately not a per-key pattern. A parser that knew the bands would
// be a third copy of them, and the one that matters is the wrapper's.
var configValueRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// actionOpenRe extracts an <action .../> tag and its attribute text. The
// attribute form rather than <offer>'s JSON body is deliberate: an action
// carries three short values and no prose, and an empty element cannot
// accidentally swallow the sentence after it the way an unterminated fenced
// block can.
var actionOpenRe = regexp.MustCompile(`(?is)<action\b([^>]*)>`)

// actionCloseRe strips a stray closing tag. Applied whether or not an open
// tag was found: a reply carrying only "</action>" is a model that mangled
// its own markup, and leaking raw markup to the operator is the failure
// mode, not the malformed half of it.
var actionCloseRe = regexp.MustCompile(`(?is)</action\s*>`)

// actionAttrRe reads one attribute. Quoted with straight quotes is the form
// the prompt shows; the bare-token alternative exists because a model that
// writes kind=config instead of kind="config" has made a proposal the
// operator asked for, and the values are checked against fixed lists either
// way — tolerating the shape costs nothing the validation does not keep.
var actionAttrRe = regexp.MustCompile(`(?is)([a-z_]+)\s*=\s*(?:"([^"]*)"|([A-Za-z0-9][A-Za-z0-9._-]*))`)

// attrQuoteNormalizer maps the quote characters models actually emit onto the
// one the attribute pattern reads. Curly quotes are what broke validator1 on
// 2026-08-21: a tag written with U+201C/U+201D parsed as having no attributes
// at all, and the original contract dropped it without a word. Applied to the
// TAG TEXT only, never to the reply the operator reads.
var attrQuoteNormalizer = strings.NewReplacer(
	"“", `"`, "”", `"`, // “ ”
	"„", `"`, "‟", `"`, // „ ‟
	"‘", `"`, "’", `"`, // ‘ ’
	"'", `"`,
)

// parseAttrs reads every attribute in a tag's text, quote-normalized.
func parseAttrs(tagText string) map[string]string {
	attrs := map[string]string{}
	for _, a := range actionAttrRe.FindAllStringSubmatch(attrQuoteNormalizer.Replace(tagText), -1) {
		v := a[2]
		if v == "" && a[3] != "" {
			v = a[3]
		}
		attrs[strings.ToLower(a[1])] = strings.TrimSpace(v)
	}
	return attrs
}

// ActionParse is what ParseAction made of a reply: no tag at all (the
// ordinary case), a well-formed proposal, or a tag that was present but
// could not be accepted.
//
// Broken is the state validator1 earned on 2026-08-21. The original
// contract dropped a malformed tag silently, reasoning that "failing to
// make it costs them nothing" — and the operator then sat in front of a
// reply that said Confirmed while no gate appeared, no ledger entry was
// written and nothing anywhere said why. A tag the model wrote and the
// service refused is a fact the operator must be shown, so it travels out
// of here with a reason instead of vanishing into the no-tag case.
type ActionParse struct {
	Found  bool
	Broken bool
	// Why is set when Broken is: which check refused the tag, in words the
	// drawer can show. Values are bounded here — nothing model-authored
	// travels in it unclipped.
	Why string
}

// clip bounds a model-authored fragment before it rides in a refusal reason.
// By runes, not bytes: a fragment cut mid-rune would put invalid UTF-8 into
// a ledger entry.
func clip(s string) string {
	r := []rune(s)
	if len(r) > 32 {
		return string(r[:32]) + "…"
	}
	return s
}

// actionNodeRe bounds the node name. Looser than nodeLabelRe because this
// field accepts what an operator would SAY — a fleet label, a container
// name, a hostname — and the service resolves it against its own identity
// afterwards. It is never a path, a URL or a channel: every use of it is a
// string comparison against values the service already holds.
var actionNodeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// actionTargetRe bounds an upgrade's target version to exactly what
// runbook.versionPattern accepts — digits and dots, 32 characters — so a
// value this parser passes is a value BindParams will bind rather than one
// that fails two layers later with a message about a parameter the operator
// never typed.
//
// The service refuses a target that is not the one /v1/check derived
// regardless, so this is a shape check and never the authority on WHICH
// version. Both exist: the range check keeps a malformed string out of the
// plan machinery, and the equality check keeps a model-invented version out
// of a confirm code.
var actionTargetRe = regexp.MustCompile(`^[0-9][0-9.]{0,31}$`)

// ActionRequest is the model's proposal, parsed and structurally validated.
type ActionRequest struct {
	// Kind is one of actionKinds — anything else is dropped by the parser
	// rather than passed along for a caller to switch on.
	Kind string
	// Intent is one of RestartIntents() or, for a rollback, one of
	// RollbackIntents() — bound into the plan's fingerprint by the runbook
	// and landed in the audit trail. Never free text: a free-text reason is
	// approval.Approval.Reason, which sits outside the fingerprint on
	// purpose. An upgrade carries no intent; its own parameter is the
	// version. A rollback carries both, because it names a version AND a
	// category.
	Intent string
	// Target is the release an upgrade proposes, or the release a rollback
	// would return to.
	// A leading "v" is stripped before the shape is checked, so a model
	// writing v3.2.1 and a model writing 3.2.1 propose the same plan rather
	// than one of them proposing nothing.
	//
	// It is not the model's decision. The service compares it to the target
	// /v1/check derives from the release registry and refuses a mismatch —
	// this field exists so the operator can be shown WHICH version they are
	// about to approve in the same sentence that names the node, not so the
	// model can pick one.
	Target string
	// TargetFromNode is set on a rollback whose block named no target at
	// all (#1012). Target is empty, and the service uses the target this
	// node derives. Never set on an upgrade: an upgrade with no target is
	// refused, because there the service would be choosing a version.
	TargetFromNode bool
	// Key and Value are RB-003's parameters: which setting to change and
	// what to change it to. Key is checked against the allow-list here;
	// Value is only shape-checked, because the band it has to satisfy
	// depends on the key and lives in one place — the table the privilege
	// wrapper enforces.
	//
	// Neither is the model's decision in the sense that matters: the service
	// re-validates both against that table before a confirm code exists, and
	// computes the before/after diff from the node's own configuration rather
	// than from anything written here.
	Key   string
	Value string
	// Node is the host the model believes was meant, in whatever vocabulary
	// the operator used. Empty means "the node this Advisor serves", which
	// is the only node it can ever be — the service still names it in the
	// gate so an empty value is never an unnamed act.
	Node string
}

// ParseAction looks for a single <action .../> tag in a model's FINAL reply
// and, if it is well-formed, extracts it and returns the reply with the tag
// removed. A reply with no tag — the ordinary case — parses to the zero
// ActionParse. A tag that is present but cannot be accepted parses to
// Broken, with the refusing check named: never staged, never defaulted, and
// never silent. Rendering half a proposal would cost the operator a confirm
// code under the wrong node's name, so nothing partial ever comes back —
// but the FACT that a proposal was refused always does.
//
// cleanReply is ALWAYS returned stripped, whatever the outcome. The one
// thing this function must never do is let markup reach the operator.
func ParseAction(reply string) (action ActionRequest, cleanReply string, parse ActionParse) {
	m := actionOpenRe.FindStringSubmatchIndex(reply)
	if m == nil {
		return ActionRequest{}, strings.TrimSpace(actionCloseRe.ReplaceAllString(reply, "")), ActionParse{}
	}
	clean := strings.TrimSpace(reply[:m[0]] + reply[m[1]:])
	clean = strings.TrimSpace(actionCloseRe.ReplaceAllString(clean, ""))

	broken := func(why string) (ActionRequest, string, ActionParse) {
		return ActionRequest{}, clean, ActionParse{Broken: true, Why: why}
	}

	attrs := parseAttrs(reply[m[2]:m[3]])

	kind := strings.ToLower(attrs["kind"])
	if !actionKinds[kind] {
		if kind == "" {
			return broken("the tag names no kind")
		}
		return broken("the kind " + clip(kind) + " is not restart, upgrade, config or rollback")
	}

	node := attrs["node"]
	if node != "" && !actionNodeRe.MatchString(node) {
		// A node name this parser cannot make sense of is NOT treated as
		// absent. Empty means "this node", and quietly converting a name
		// the model meant as another host into "this node" is exactly the
		// wrong-node act this field exists to prevent.
		return broken("the node name could not be read")
	}

	// The two kinds carry different parameters, and neither borrows the
	// other's. An upgrade with an intent, or a restart with a target, is a
	// model confusing the two acts; the field it needed is missing either
	// way, so both fall out of the checks below rather than needing a rule
	// of their own.
	switch kind {
	case ActionKindRestart:
		intent := strings.ToLower(attrs["intent"])
		if !restartIntents[intent] {
			// No default. An intent is recorded in the audit trail and bound
			// into the confirm code; picking one on the model's behalf would
			// put a category in the record that nobody chose.
			return broken("the restart intent " + clip(intent) + " is not one of the fixed list")
		}
		return ActionRequest{Kind: ActionKindRestart, Intent: intent, Node: node}, clean, ActionParse{Found: true}

	case ActionKindConfig:
		key := strings.ToLower(strings.TrimSpace(attrs["key"]))
		if !configKeys[key] {
			// No default, for the reason the intent has none and a stronger
			// one: a key chosen on the model's behalf would be a setting
			// nobody asked to change, presented to the operator under a
			// confirm code.
			return broken("the key " + clip(key) + " is not one of the four changeable settings")
		}
		value := strings.TrimSpace(attrs["value"])
		if !configValueRe.MatchString(value) {
			return broken("the value for " + clip(key) + " could not be read as a setting value")
		}
		return ActionRequest{Kind: ActionKindConfig, Key: key, Value: value, Node: node}, clean, ActionParse{Found: true}

	case ActionKindRollback:
		// The intent is required: it is a category the operator meant, bound
		// into the fingerprint and landed in the audit trail, and picking one
		// on the model's behalf would record a reason nobody gave.
		//
		// The target is not, when it is left out (#1012). A rollback's target
		// was never the model's call: the service derives it from this node's
		// own deployment copies and run history and refuses any other, and the
		// gate names the derived version in the sentence the operator approves.
		// So an absent or empty target is "the one this node derives", which
		// the service fills in and shows. Refusing it instead cost the operator
		// their "yes" twice on a lab validator (2026-10-11) for a same-release
		// rollback to the official image, the case where nothing in the ask
		// looks like a version change and the model wrote no version.
		//
		// A target that IS written and cannot be read stays a refusal. That is
		// a model that named something, and turning a name nobody can read
		// into the derived version would be the service guessing what it
		// meant. A readable target that differs from the derived one is
		// refused by the service as wrong_target, as before.
		raw := strings.TrimSpace(attrs["target"])
		target := strings.TrimPrefix(strings.TrimPrefix(raw, "v"), "V")
		fromNode := raw == ""
		if !fromNode && !actionTargetRe.MatchString(target) {
			return broken("the rollback names no readable target version")
		}
		// Left out means left to the node only when the block names no
		// version anywhere (#1012 review, L4). A block with version="3.4.0"
		// and no target is a model that meant 3.4.0 and wrote it in the
		// wrong place; filling the derived version in would put a gate under
		// prose naming another one.
		if fromNode {
			for k, v := range attrs {
				if k == "kind" || k == "intent" || k == "node" || k == "target" {
					continue
				}
				if actionTargetRe.MatchString(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")) {
					return broken("the rollback names a version in " + clip(k) + " rather than in target")
				}
			}
		}
		intent := strings.ToLower(attrs["intent"])
		if !rollbackIntents[intent] {
			return broken("the rollback intent " + clip(intent) + " is not one of the fixed list")
		}
		return ActionRequest{Kind: ActionKindRollback, Target: target, TargetFromNode: fromNode,
			Intent: intent, Node: node}, clean, ActionParse{Found: true}

	case ActionKindUpgrade:
		target := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(attrs["target"]), "v"), "V")
		if !actionTargetRe.MatchString(target) {
			// No default here either, and for a stronger reason than the
			// intent's: an absent target defaulted to "the latest release"
			// would be the service picking a version and the operator
			// approving it under the impression the Advisor had named one.
			return broken("the upgrade names no readable target version")
		}
		return ActionRequest{Kind: ActionKindUpgrade, Target: target, Node: node}, clean, ActionParse{Found: true}
	}
	return broken("the tag could not be read")
}

// intentOpenRe extracts the <intent kind="restart"/> marker — the model's
// signal, on the FIRST turn, that the operator has asked for an act rather
// than a question.
//
// It exists because of an operator ruling (2026-08-19): an act that needs
// break glass must be answered with that fact IMMEDIATELY, before any
// assessment. The prompt tells the model to lead with it, and this marker is
// the belt to that braces — the service reads it and renders the amber nudge
// (or the monitor line) under the answer regardless of how the model phrased
// its prose. Without a marker the service has no honest way to know a reply
// is about an act: guessing from the operator's words is the keyword-matching
// this whole package exists to replace.
//
// It authorises nothing and names no node. A model that emits it on every
// reply produces a nudge the operator can ignore; a model that never emits it
// loses the nudge and keeps every other guarantee.
var intentOpenRe = regexp.MustCompile(`(?is)<intent\b([^>]*)>`)

var intentCloseRe = regexp.MustCompile(`(?is)</intent\s*>`)

// ParseActionIntent finds the marker, returns its kind, and strips it. Same
// contract as ParseAction: cleanReply is always stripped, and anything
// malformed is dropped rather than half-rendered.
//
// The kind is RETURNED rather than collapsed to a bool, and that is
// load-bearing now that there are two: a caller holding only "there was a
// marker" would render the restart gate for an operator who asked about an
// upgrade.
func ParseActionIntent(reply string) (kind string, cleanReply string, found bool) {
	m := intentOpenRe.FindStringSubmatchIndex(reply)
	if m == nil {
		return "", strings.TrimSpace(intentCloseRe.ReplaceAllString(reply, "")), false
	}
	clean := strings.TrimSpace(reply[:m[0]] + reply[m[1]:])
	clean = strings.TrimSpace(intentCloseRe.ReplaceAllString(clean, ""))

	if k := strings.ToLower(parseAttrs(reply[m[2]:m[3]])["kind"]); actionKinds[k] {
		return k, clean, true
	}
	return "", clean, false
}

// routeOpenRe and routeCloseRe carry the <route node="…"/> marker — the
// model's SUGGESTION, when the operator names a node that is not this host
// but resembles a registered peer, that the conversation move to that peer.
var routeOpenRe = regexp.MustCompile(`(?is)<route\b([^>]*)>`)
var routeCloseRe = regexp.MustCompile(`(?is)</route\s*>`)

// ParseRouteSuggestion finds a <route node="…"/> marker, returns the node
// the model proposes handing off to, and strips it.
//
// It authorises NOTHING, and that is what lets a model emit it at all: the
// caller validates the node against the real roster (a hallucinated label
// is dropped), the operator has to confirm before anything moves, and a
// route only changes which node's Advisor answers the NEXT question — it
// reaches no host and runs no verb. The security property "no model output
// moves the conversation to another machine" is intact: this moves nothing,
// it offers a move a human then makes. Same strip-always contract as the
// other markers — malformed markup never reaches the operator.
func ParseRouteSuggestion(reply string) (node string, cleanReply string, found bool) {
	m := routeOpenRe.FindStringSubmatchIndex(reply)
	if m == nil {
		return "", strings.TrimSpace(routeCloseRe.ReplaceAllString(reply, "")), false
	}
	clean := strings.TrimSpace(reply[:m[0]] + reply[m[1]:])
	clean = strings.TrimSpace(routeCloseRe.ReplaceAllString(clean, ""))
	node = parseAttrs(reply[m[2]:m[3]])["node"]
	if node == "" || !actionNodeRe.MatchString(node) {
		return "", clean, false
	}
	return node, clean, true
}
