package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
)

// The deterministic restart confirm — issue #72, the root cause.
//
// The recovery half of #72 is in restart_action.go and breakglass.go: a gate
// recorded before the terminal write, a round published for a read-free
// model call. That made the failure survivable. This file makes it stop
// happening.
//
// What the lab measured on the turn that failed:
//
//	[ask] gated: 1 rounds, 0 reads, ...
//
// The operator's "yes" read NOTHING. It ran one model call whose only job
// was to re-emit, as an <action> block, the plan the model had already been
// shown on the previous turn. That call took the best part of four minutes
// against a gateway that caps a single request at about a hundred seconds,
// so the one turn in the whole protocol that MUST arrive was the one most
// likely to die in transit.
//
// Because that turn reads nothing, minting the gate from the previous turn's
// proposal loses no information. So: when a gated question shows the operator
// a restart they can say yes to, the service remembers that it did. When the
// next question from the same person on the same node is a plain affirmative,
// the gate is minted here, from the stored proposal, through the same
// considerRestartAction the model path uses. No model call.
//
// Three things this deliberately does NOT do:
//
//   - It does not weaken the gate. The passkey ceremony is unchanged, the
//     confirm code is minted by planIdentity exactly as before, and the
//     eligibility matrix is re-evaluated at confirm time against live state
//     rather than replayed from what was true when the proposal was stored.
//     A wrongly detected affirmative costs the operator a gate they decline.
//   - It does not replace the model path. Anything that is not a plain
//     affirmative with a live proposal behind it falls through untouched, and
//     the two-turn prompt in prompt_guide.go still describes the flow the
//     model follows when it does.
//   - It does not remember for long. The proposal is valid for the very next
//     gated turn (settlePendingRestart clears it otherwise) with a TTL behind
//     that as a backstop.

// restartProposalTTL is the backstop, not the primary bound. The bound that
// does the work is settlePendingRestart: a gated question that does not
// itself show a restart clears whatever was pending, so a proposal is
// normally exactly one turn old. The TTL catches the case where no second
// question ever arrives — an operator who walked away, a tab that closed —
// and a break-glass window is fifteen minutes long, so anything longer than
// this would outlive the only state in which it could be used anyway.
const restartProposalTTL = 10 * time.Minute

// restartAssessmentIntent is the intent the assessment read is evaluated
// under, and therefore the intent a deterministic confirm mints its gate
// with. One constant rather than two string literals: the plan the operator
// was SHOWN and the plan they are asked to approve have to be the same plan,
// and planIdentity's fingerprint includes the intent — two spellings here
// would be two confirm codes for one restart.
const restartAssessmentIntent = "operator-judgement"

// pendingRestart is the record that turn one happened: this operator, on
// this node, was shown a restart assessment that the service itself found
// proposable.
//
// It stores identity, not authority. Nothing in here is trusted at confirm
// time beyond "which node, which intent, whose turn" — the eligibility, the
// readings, the preconditions and the confirm code are all derived fresh by
// considerRestartAction when the affirmative arrives.
type pendingRestart struct {
	// Node is the label the assessment named, passed back through
	// ActionRequest.Node so namesThisNode re-checks it at confirm time. A
	// host that has been renamed, or a proposal that somehow crossed
	// services, meets the wrong-node refusal rather than a gate.
	Node string
	// Intent is what the assessment was evaluated under.
	Intent string
	// At is when it was stored, for the TTL.
	At time.Time
}

// restartProposalKey binds a proposal to one node and one person. Both
// halves matter: an operator confirming while the header points at another
// node must not mint this node's gate, and one admin's "yes" must not
// consume another admin's proposal. Every write, clear and read goes through
// this function so the three cannot drift — a clear that misses its key
// leaves a proposal armed, and nothing in a single-turn test would show it.
func restartProposalKey(node, operator string) string {
	return strings.ToLower(strings.TrimSpace(node)) + "\x00" + strings.ToLower(strings.TrimSpace(operator))
}

// pendingRestartStore holds at most one pending proposal per key. In memory
// and restart-volatile, like the progress store and the break-glass window
// it depends on: a service that restarts has closed every window, so a
// proposal that survived would be one nothing could act on.
type pendingRestartStore struct {
	mu sync.Mutex
	m  map[string]pendingRestart
}

func newPendingRestartStore() *pendingRestartStore {
	return &pendingRestartStore{m: map[string]pendingRestart{}}
}

// record stores one proposal, replacing whatever this key held. A second
// assessment supersedes the first: the operator was shown something newer,
// and the older reading is not what they would be saying yes to.
//
// Nil-safe, like every method here. A server assembled by a test that does
// not care about this path has a nil store, and a nil store simply never
// arms a fast path.
func (p *pendingRestartStore) record(key string, pr pendingRestart) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[key] = pr
}

func (p *pendingRestartStore) clear(key string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, key)
}

// lookup is deliberately non-destructive. The confirm consumes explicitly,
// after it knows whether it reached a decision — a refusal that means "the
// host could not be read just now" decides nothing, and consuming there
// would spend the operator's proposal on a transient.
func (p *pendingRestartStore) lookup(key string, now time.Time) (pendingRestart, bool) {
	if p == nil {
		return pendingRestart{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, ok := p.m[key]
	if !ok {
		return pendingRestart{}, false
	}
	if now.Sub(pr.At) > restartProposalTTL {
		delete(p.m, key)
		return pendingRestart{}, false
	}
	return pr, true
}

// ── what counts as "yes" ────────────────────────────────────────────────

// restartAffirmatives is the whole vocabulary, matched EXACTLY after
// normalisation. Not a prefix match, and not a regex.
//
// The page has a prefix regex of its own for the route handoff
// (affirmativeRe in advisor.html), and that is right for what it does:
// routing changes which node answers next and runs nothing. This list guards
// a different thing, so it is stricter in two ways that matter.
//
//   - Exact match is what makes "yes, restart node2" fall through to the
//     model. A prefix match would see "yes" and mint THIS node's gate for a
//     sentence naming another one.
//   - "restart" and "restart it" are deliberately absent. Every entry here
//     is an answer to a question. A bare "restart" is how an operator OPENS
//     a conversation, and taking it as a confirm would skip turn one — the
//     operator would be handed a gate having been shown no assessment at
//     all. That is the one mis-detection that is not harmless, because it is
//     not a misread confirm, it is a missing turn.
var restartAffirmatives = map[string]bool{
	"y": true, "ye": true, "yes": true, "yep": true, "yeah": true, "yup": true,
	"yes please": true, "yes go ahead": true, "yes do it": true,
	"yes restart": true, "yes restart it": true, "yes confirm": true,
	"ok": true, "okay": true, "sure": true, "go": true, "go ahead": true,
	"do it": true, "please do": true, "please proceed": true, "proceed": true,
	"confirm": true, "confirmed": true, "affirmative": true, "approve": true, "approved": true,
}

// isRestartAffirmative normalises a message and asks whether it is one of
// the words above and nothing else.
//
// A question mark disqualifies outright: "yes?" and "ok?" are not consent,
// and neither is anything ending in one. So does a line break — a pasted
// block that happens to start with "yes" is not a one-word answer.
func isRestartAffirmative(msg string) bool {
	if strings.ContainsAny(msg, "?\n\r") {
		return false
	}
	norm := strings.ToLower(strings.TrimSpace(msg))
	norm = strings.Trim(norm, " \t.!,;:'\"")
	// A comma inside the phrase is punctuation, not a word: "yes, please" and
	// "yes please" are the same answer, and only one of them should have to be
	// in the list above. It does not widen what matches — "yes, restart node2"
	// normalises to "yes restart node2", which is in no list and goes to the
	// model, which is the whole point of matching exactly.
	norm = strings.ReplaceAll(norm, ",", " ")
	norm = strings.Join(strings.Fields(norm), " ")
	if norm == "" {
		return false
	}
	return restartAffirmatives[norm]
}

// ── the confirm itself ──────────────────────────────────────────────────

// confirmRestartDirectly answers a confirm turn without a model call, or
// declines to and hands the question back to the ordinary gated path.
//
// handled is false for everything that is not "a plain affirmative, from the
// person who was shown a restart on this node, while that proposal is still
// live". That covers a fresh question, a non-affirmative reply, an expired
// proposal, a different operator and a different node, and each of those
// runs exactly as it did before this file existed.
//
// It is called with a break-glass window already open on this node (the
// caller is inside that branch), and considerRestartAction re-checks the
// window anyway, along with the role, the node, the compact class and the
// preconditions. Nothing here is decided from the stored proposal except
// WHICH restart is being confirmed.
func (s *server) confirmRestartDirectly(ctx context.Context, req askRequest, node string, now time.Time) (map[string]any, bool) {
	return s.confirmRestartWith(ctx, req, node, now, s.considerRestartAction)
}

// restartActionFn is considerRestartAction's shape.
type restartActionFn func(context.Context, interrogate.ActionRequest, string, ledger.Actor) (map[string]any, map[string]any)

// confirmRestartWith is confirmRestartDirectly's body with the proposal
// evaluation passed in, the same split restartPlanFor/restartPlanWith and
// runGatedQuestion/runGatedQuestionWithHostBudget already use.
//
// The evaluation is the half that needs a live node: a running container to
// inspect, an admin RPC that answers, a compact on disk and a runbook sweep.
// The DECISIONS around it — is this an affirmative, is there a live proposal,
// whose is it, is it spent or left armed — are the half that has to be right
// on a host nobody has, so they are exercised here directly.
func (s *server) confirmRestartWith(ctx context.Context, req askRequest, node string, now time.Time, consider restartActionFn) (map[string]any, bool) {
	if !isRestartAffirmative(req.Question) {
		return nil, false
	}
	key := restartProposalKey(node, req.Operator)
	pr, ok := s.pendingRestarts.lookup(key, now)
	if !ok {
		return nil, false
	}

	asker := sessionActor(req.Operator, req.Role)
	action, refused := consider(ctx,
		interrogate.ActionRequest{Kind: interrogate.ActionKindRestart, Intent: pr.Intent, Node: pr.Node},
		req.Role, asker)
	if action == nil && refused == nil {
		// Unreachable: considerRestartAction returns exactly one of the two.
		// Falling back to the model rather than answering with nothing, for
		// the same reason answerAction refuses to guess an act's kind.
		return nil, false
	}

	if action == nil {
		reason, _ := refused["reason"].(string)
		if reason == upgradeRefusedPlanUnavailable {
			// The host could not be read. That decides nothing about the
			// restart, so the proposal stays armed and the question goes to
			// the model, which will meet the same host and say so in its own
			// words. Consuming here would spend the operator's proposal on a
			// transient and send their next "yes" down the slow path this
			// whole file exists to remove.
			log.Printf("[restart-confirm] the plan was unavailable; falling back to the model path")
			return nil, false
		}
		// Every other refusal is a decision: a monitor, the wrong node, a
		// class this host has not permitted, a precondition that refuses, a
		// window that closed between the branch above and here. The operator
		// gets the reason and the remedy, and the proposal is spent.
		s.pendingRestarts.clear(key)
		log.Printf("[restart-confirm] refused without a model call: %s", reason)
		return s.confirmBody(restartConfirmRefusedReply(reason), nil, refused), true
	}

	s.pendingRestarts.clear(key)
	label := pr.Node
	if n, ok := action["node"].(restartNode); ok && n.Label != "" {
		label = n.Label
	}
	log.Printf("[restart-confirm] a gate was minted from the stored proposal, no model call")
	return s.confirmBody(restartConfirmReply(label), action, nil), true
}

// restartConfirmReply is what the operator reads above the gate.
//
// Written by the service, and it says so in the only way that matters: it
// points at the assessment they were already shown rather than describing
// the node again. The gate below it carries the readings, the preconditions
// and the node's four names; a paragraph repeating them here would be a
// second telling of one plan, which is the same failure mode planIdentity
// exists to prevent one layer down.
func restartConfirmReply(label string) string {
	// Your yes is received and nothing more: no "confirmed", no "approved",
	// no act in the present tense, because the gate below is not approved
	// until the passkey is (#1102, the same rule as #1044).
	return "Your yes is received. The restart of " + label + " is ready to approve below, from the " +
		"assessment in my last reply. Check it names the right node, then type the confirm code and " +
		"approve with your passkey. Nothing changes until you do."
}

// restartConfirmRefusedReply is the one line above a refusal. Short on
// purpose: the block underneath renders the reason and the remedy in full,
// and two sentences saying the same thing differently is how one of them
// ends up wrong.
func restartConfirmRefusedReply(reason string) string {
	switch reason {
	case restartRefusedMonitor:
		return "A restart is an admin's, inside a break-glass window."
	case restartRefusedWrongNode:
		return "That restart is not this node's to propose."
	case restartRefusedBreakGlass:
		return "The break-glass window has closed, so the restart cannot be proposed now."
	case restartRefusedBlocked:
		return "The restart is refused by its own preconditions right now."
	case restartRefusedRotating:
		return "The ledger store is mid-rotation, so the node would refuse to stop right now."
	}
	return "The restart could not be proposed."
}

// confirmBody is the /v1/ask response shape, minus everything a model call
// would have filled in. gated is true because it IS gated — this answer is
// only reachable with a window open, and the tab labels the tier from it.
// spend is reported as the zeroes it actually is: the whole point is that
// this turn spent nothing.
func (s *server) confirmBody(reply string, action, refused map[string]any) map[string]any {
	body := map[string]any{
		"configured": true, "reply": reply, "gated": true,
		"steps": []interrogate.Step{},
		"spend": map[string]any{
			"rounds": 0, "reads": 0, "prompt_tokens": 0, "completion_tokens": 0,
			"cached_prompt_tokens": 0, "reported": false,
		},
	}
	if action != nil {
		body["action"] = action
	}
	if refused != nil {
		body["action_blocked"] = refused
	}
	return body
}

// recordConfirmProgress puts this turn into the progress store the way every
// other ask records itself, so a page polling the id finds an answer rather
// than a 404, and a fast confirm whose POST still managed to die recovers
// through the same path as a slow one.
//
// The order is the #72 order and is not negotiable: the action lands BEFORE
// the terminal state, because the page's recovery poll stops on the first
// snapshot that says "answered".
func (s *server) recordConfirmProgress(askID string, body map[string]any) {
	s.progress.begin(askID)
	if action, ok := body["action"].(map[string]any); ok && action != nil {
		s.progress.setAction(askID, action)
	}
	reply, _ := body["reply"].(string)
	s.progress.finish(askID, "answered", reply, "")
}

// ── the record that turn one happened ───────────────────────────────────

// proposalFromAssessment is the condition under which a restart assessment
// counts as "the operator was shown a restart they can say yes to".
//
// Both halves are required and neither is inferred from the other. The read
// has to have SUCCEEDED — a failed assessment told the operator nothing —
// and the plan has to be proposable, because an assessment that says
// "blocked: yes" is the prompt's own stop sign and the model is told to end
// the turn there. Nothing was proposed, so nothing is pending.
//
// It returns the proposal rather than setting one, so the decision can be
// exercised without a live node while the read that feeds it cannot be.
func proposalFromAssessment(plan restartPlan, res interrogate.Result, now time.Time) *pendingRestart {
	// Rotating counts as not proposable for the same reason Blocked does: the
	// assessment the operator just read says REFUSES, and arming a "yes" under
	// a refusal is what the both-halves-required rule exists to prevent.
	//
	// Consistency, not safety. Without this line the "yes" still reaches
	// considerRestartAction, which refuses it with rotation_in_flight and
	// clears the proposal, so no gate is minted and no passkey is spent either
	// way. The line keeps the store from disagreeing with the prose above it.
	if res.Status != interrogate.StatusOK || plan.Blocked || plan.Rotating {
		return nil
	}
	return &pendingRestart{Node: plan.Node.Label, Intent: plan.Intent, At: now}
}

// settlePendingRestart is the second half of the store's contract, and the
// reason a proposal is normally exactly one turn old.
//
// proposed is non-nil when THIS question performed a restart assessment the
// service found proposable (prepareGatedQuestion wires the closure that sets
// it). Everything else clears:
//
//   - the run failed. The operator was shown nothing, so there is nothing to
//     say yes to.
//   - the reply carried an <action>. The model took turn two itself and the
//     gate is already minted; a proposal left armed behind it would arm a
//     second gate for a restart already waiting on a passkey.
//   - the reply carried a BROKEN action. The parser refused it and the
//     operator was told so. Leaving the proposal armed would let the next
//     "yes" launder a refusal into a gate.
//   - the question was about something else entirely. This is the ordinary
//     case, and it is what keeps a ten-minute-old assessment from turning an
//     unrelated "yes" into a restart gate.
func (s *server) settlePendingRestart(node, operator string, proposed *pendingRestart, res gatedResult, err error) {
	key := restartProposalKey(node, operator)
	if err != nil || proposed == nil || res.Signal.HasAction || res.Signal.BrokenAction {
		s.pendingRestarts.clear(key)
		return
	}
	s.pendingRestarts.record(key, *proposed)
}
