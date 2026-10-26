package interrogate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Message is one turn sent to the model. Kept local to this package rather
// than importing internal/model, so the loop can be driven by a scripted
// fake with no provider — and so a later step is free to change how the
// real model client's messages are shaped without this package noticing,
// as long as it can still produce a []Message.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
	// CacheBoundary marks this message as the end of a stable prefix worth
	// a provider-side cache breakpoint (token-efficiency work, part 1). Set
	// by the caller assembling the seed — always the last entry, never by
	// this package and never by anything replayed from a round the model
	// produced. caller.go is the only place that reads it back out.
	CacheBoundary bool
}

// Usage is the token accounting §6.3 requires: never estimated. An
// estimated token count presented as a measurement is the kept-versus-
// observed defect in its cheapest form, so a provider that reports nothing
// yields Reported == false and zero counts rather than a guess.
type Usage struct {
	PromptTokens int
	// CachedPromptTokens is the subset of PromptTokens billed at the
	// provider's cache-read discount — see model.Usage's doc comment for
	// what each API shape actually reports into it.
	CachedPromptTokens int
	CompletionTokens   int
	Reported           bool
}

// Caller is the seam to the model. Whatever wires the real model.Client in
// (a later step) adapts it to satisfy this interface; tests supply a
// scripted fake instead.
type Caller interface {
	Ask(ctx context.Context, messages []Message) (reply string, usage Usage, err error)
}

// SeedResult registers a read the caller already performed before the loop
// started — the named-ledger lookup, the validator-key lookup, and the
// regex-matched host probes main.go's existing context assembly runs. If
// the model asks for the same thing again it is served from this seeded
// cache as StatusSkippedCached rather than spending its own budget —
// exactly what §5.4 means by "this is also what makes the seed reads
// harmless to re-request."
type SeedResult struct {
	Request Request
	Result  Result
}

// Spend is the per-question cost accounting §6.3 returns alongside the
// answer, and what open decision #3 (a Tier 3/4 monthly budget) will
// eventually gate against. This package supplies the accounting; it does
// not set any ceiling on it.
type Spend struct {
	Rounds int
	Reads  int
	// PromptTokens is the total across every round; CachedPromptTokens is
	// the subset of that total billed at the provider's cache-read
	// discount — see model.Usage. Both sum the same way UsageReported
	// tracks: a round that reports no usage block leaves both counts short
	// by an unknown amount, which is exactly what UsageReported == false
	// exists to disclose.
	PromptTokens       int
	CachedPromptTokens int
	CompletionTokens   int
	UsageReported      bool
}

// Outcome is what one interrogative loop produced.
type Outcome struct {
	// FinalReply is the clean text to show the operator: no <lookup>
	// block (stripped or never present), and a <remember> block left
	// intact if the model's actual final reply carried one — extractMemory
	// runs on the final reply only (§6.4) and must reach it untouched.
	FinalReply string
	// Steps is every read this question attempted, across every round,
	// each exactly once, in order.
	Steps []Step
	Spend Spend
	// Messages is the conversation state at the moment this question
	// finished — every seed message, every round's assistant/user pair, and
	// the final assistant turn (the model's raw reply, before FinalReply's
	// own <remember>-preserving cleanup). Break glass (§11.9) resumes an
	// accepted investigation offer from exactly this, rather than replaying
	// the question cold: "the gated session CONTINUES from those turns."
	// Ungated callers that never look at this pay nothing for it beyond one
	// slice header.
	Messages []Message
}

// Loop drives the interrogative rounds against a Caller and a Menu,
// enforcing every ceiling in Budget. It performs no I/O of its own —
// everything reaches the network, the dashboard or the host through the
// two interfaces it holds, which is what makes it testable with scripted
// fakes and none of those three things present.
type Loop struct {
	Caller Caller
	Menu   Menu
	Budget *Budget
	// Seeded primes the per-question cache before round 1. See SeedResult.
	Seeded []SeedResult

	// Nodes is the fleet roster this question may address — the registered
	// peer labels a Request.Node is checked against before anything runs
	// (menu_items.go's validateRequest). Nil or empty for a deployment with
	// no fleet registered, which reproduces today's single-node behaviour
	// exactly: any Node a model names is refused locally, and no fleet
	// completeness step is ever synthesised (D2 option C).
	Nodes map[string]bool

	// Roster is what the HOST this question was asked on knows exists (#59)
	//, every node in its fleet registry, readable or not, plus itself.
	// Wider than Nodes, which is only what this process holds a read client
	// for, and the gap between the two is a real state with its own answer:
	// "registered here, cannot be read from here", with the last time it
	// answered. The zero Roster is every deployment that has none and
	// behaves exactly as this loop did before it existed.
	Roster Roster

	// OnStep, if set, is called once for every Step this question produces,
	// in order, as soon as it is finalised — after sanitisation and
	// budgeting, immediately after it is appended to the running Steps
	// slice. It exists so a caller can offer live progress (§10.1: the
	// drawer polls a growing list while the loop is still running) without
	// this package knowing anything about HTTP, polling, or JSON. Run's own
	// returned Outcome is still the complete, authoritative record whether
	// or not a callback is set — OnStep is a side channel, never the source
	// of truth.
	//
	// Called from the same goroutine that is running Run. A caller that
	// reads the callback's Step from a different goroutine (a progress
	// poller answering concurrent HTTP requests, say) must synchronise that
	// read itself; this package performs no locking of its own because it
	// has no shared state to protect on this path.
	OnStep func(Step)

	// OnRound, if set, is called once for every model call this question
	// COMPLETES, with the round number, immediately after the provider's
	// reply is in hand and before anything is parsed out of it.
	//
	// It exists because OnStep cannot answer "is this question still
	// moving". A Step is produced by a READ; a round where the model
	// answers, or asks for nothing servable, produces none at all. A caller
	// offering live progress over a transport that gives up on silence
	// therefore cannot tell a long read-free question from a service that
	// has stopped — which is exactly how an operator was told the
	// connection had dropped while their restart was still being assessed
	// (#72).
	//
	// It reports a completed model call and claims nothing else: not that
	// the question is close to done, and not that the round produced
	// anything useful. Same goroutine and same locking contract as OnStep.
	OnRound func(round int)
}

// emitAll appends newSteps to steps and, if a callback is wired up, reports
// each of them in order — the single place every Step this package ever
// produces passes through, so "OnStep fires once per step, in the order
// Steps holds them" is true by construction rather than by every call site
// (the isLastRound branch's synthesised refusals, and serveRound's own
// results) remembering to call it individually.
func (l *Loop) emitAll(steps []Step, newSteps []Step) []Step {
	for _, s := range newSteps {
		if l.OnStep != nil {
			l.OnStep(s)
		}
	}
	return append(steps, newSteps...)
}

// Run performs one question's interrogative loop. seed is the opening
// message list (system prompt, assembled context, the operator's question
// as the first user turn — assembled by the caller exactly as it is today).
// question is restated at the end of every results turn per §5.2.
func (l *Loop) Run(ctx context.Context, seed []Message, question string) (Outcome, error) {
	budget := l.Budget
	if budget == nil {
		budget = NewBudget()
	}

	messages := append([]Message{}, seed...)
	cache := make(map[string]Result, len(l.Seeded))
	for _, sd := range l.Seeded {
		// Seeds are host probe output and public API text — the least
		// trustworthy text in the system, per §5.3 — and reach the cache
		// without going through finishResult. Sanitizing here is what
		// keeps the "no bypass path" guarantee true for this entry point
		// too, not only for a Menu.Perform result.
		cache[cacheKey(sd.Request)] = sanitizeResult(sd.Result)
	}

	var steps []Step
	var spend Spend
	// UsageReported answers "is this SUM a measurement" (§6.3), not "did
	// any single round report one." A total summed across four rounds
	// where even one provider response carried no usage block is short by
	// an unknown amount while still claiming to be measured — the same
	// kept-versus-observed shape §6.3 names by name. So this starts true
	// and is withdrawn permanently the moment any round fails to report,
	// rather than being set true the moment any round does.
	spend.UsageReported = true
	consecutiveUnserved := 0
	forceFinal := false

	for round := 1; round <= budget.MaxRounds; round++ {
		if err := ctx.Err(); err != nil {
			return Outcome{Steps: steps, Spend: spend}, err
		}

		reply, usage, err := l.Caller.Ask(ctx, messages)
		if err != nil {
			return Outcome{Steps: steps, Spend: spend}, err
		}
		// Reported here rather than at the top of the iteration: "round 3
		// started" fires at the beginning of the very wait a live-progress
		// caller is trying to survive, and would say nothing new for as long
		// as that call takes. "Round 3 finished" is the signal that the loop
		// actually advanced.
		if l.OnRound != nil {
			l.OnRound(round)
		}
		spend.Rounds = round
		spend.PromptTokens += usage.PromptTokens
		spend.CachedPromptTokens += usage.CachedPromptTokens
		spend.CompletionTokens += usage.CompletionTokens
		if !usage.Reported {
			spend.UsageReported = false
		}

		parsed := ParseLookupWithRoster(reply, l.Nodes, l.Roster)
		isLastRound := round == budget.MaxRounds

		// Normal exit (no lookup block), or the round forced final by two
		// consecutive rounds where nothing was served: whatever this
		// reply contains is the answer, sealed through l.seal so a
		// fragment this parser did not recognise still cannot reach the
		// operator as a stray tag.
		if !parsed.HasBlock || forceFinal {
			spend.Reads = budget.ReadsUsed()
			finalMessages := append(append([]Message{}, messages...), Message{Role: "assistant", Content: reply})
			sealedReply, sealedSteps := l.seal(withoutOnlyARequest(parsed), round, steps)
			return Outcome{FinalReply: sealedReply, Steps: sealedSteps, Spend: spend, Messages: finalMessages}, nil
		}

		// §6.2: the fourth call's reply is the answer whatever it
		// contains. A lookup block here is dropped from what is served
		// and recorded as refused, naming what it did not get to — unless
		// the block itself never parsed, in which case there is no
		// Request to name a refusal against. §5.4 is explicit that a
		// failed parse must never hand back the raw fragment as the
		// "answer" just because no round remains to retry it; a stated,
		// disclosure-honest sentence and one failed step take its place.
		if isLastRound {
			n := len(steps)
			var final []Step
			cleanReply := parsed.CleanReply
			if parsed.Malformed {
				n++
				final = append(final, Step{
					N: n, Round: round, Read: "(lookup)",
					Label:  "a lookup was attempted but could not be parsed, and no rounds remained to retry",
					Status: StatusFailed,
					Detail: parsed.MalformedReason,
				})
				cleanReply = "A lookup was attempted here but could not be parsed, and no further " +
					"rounds remained to retry it — answering without it."
			} else {
				for _, req := range parsed.Requests {
					n++
					final = append(final, refuseStep(n, round, req, budget.RefusalReason(), "no rounds remain"))
				}
				for _, pd := range parsed.PreDispatch {
					n++
					final = append(final, preDispatchStep(n, round, pd))
				}
			}
			steps = l.emitAll(steps, final)
			spend.Reads = budget.ReadsUsed()
			finalMessages := append(append([]Message{}, messages...), Message{Role: "assistant", Content: reply})
			if strings.TrimSpace(cleanReply) == "" {
				cleanReply = onlyARequestSentence
			}
			sealedReply, sealedSteps := l.seal(cleanReply, round, steps)
			return Outcome{FinalReply: sealedReply, Steps: sealedSteps, Spend: spend, Messages: finalMessages}, nil
		}

		if parsed.Malformed {
			// A malformed round spends no read budget and is not counted
			// toward the two-consecutive-unserved-rounds rule below —
			// that rule watches "the model asked for reads and none were
			// served," and a malformed round never produced a servable
			// request to begin with. This is bounded regardless: MaxRounds
			// caps how many corrective rounds a question can spend before
			// isLastRound forces a final answer, so an unbounded retry
			// loop is not possible even without this counter.
			messages = append(messages, Message{Role: "assistant", Content: reply})
			messages = append(messages, Message{Role: "user", Content: RenderMalformedResultsTurn(parsed.MalformedReason, question)})
			continue
		}

		budget.ResetRound()
		roundSteps, served := l.serveRound(ctx, budget, cache, round, len(steps), parsed)
		// DI1a: a picture built from some of the fleet's peers is correct
		// about what it contains and silently wrong about what it
		// represents unless the record also states what it does not
		// contain. Appended to THIS round's steps (never synthesised when
		// no Node-carrying read failed to answer) so it counts toward
		// `served` the same as any other line the round produced.
		if fc, ok := fleetCompletenessStep(len(steps)+len(roundSteps)+1, round, l.registeredCount(), roundSteps); ok {
			roundSteps = append(roundSteps, fc)
		}
		steps = l.emitAll(steps, roundSteps)

		assistantTurn := stripIntermediateRemember(reply)
		messages = append(messages, Message{Role: "assistant", Content: assistantTurn})

		if served == 0 {
			consecutiveUnserved++
		} else {
			consecutiveUnserved = 0
		}

		if consecutiveUnserved >= 2 {
			messages = append(messages, Message{Role: "user", Content: RenderNoFurtherLookupsTurn(question)})
			forceFinal = true
			continue
		}

		messages = append(messages, Message{
			Role:    "user",
			Content: RenderResultsTurn(roundSteps, budget.ReadsRemaining(), budget.MaxRounds-round, question),
		})
	}

	// Every path above returns from inside the loop; falling out of it
	// would mean MaxRounds was exhausted without ever hitting the
	// isLastRound branch, which the loop bounds (round <= budget.MaxRounds)
	// make unreachable. Kept as an explicit, honest outcome rather than a
	// panic, in case a future edit changes that invariant without noticing.
	spend.Reads = budget.ReadsUsed()
	return Outcome{Steps: steps, Spend: spend}, nil
}

// onlyARequestSentence stands in for an answer when the reply that had to be
// the answer was nothing but a read request. The request itself is never
// shown (#1092): the steps above it say what was asked and what was refused.
const onlyARequestSentence = "I asked for another read and none could be run, so I have no " +
	"answer to give from it. Ask again, or narrow the question."

// withoutOnlyARequest is what a forced-final reply shows: its prose with the
// request cut out, or one plain sentence when that leaves nothing.
func withoutOnlyARequest(parsed ParseOutcome) string {
	if parsed.HasBlock && strings.TrimSpace(parsed.CleanReply) == "" {
		return onlyARequestSentence
	}
	return parsed.CleanReply
}

// seal is the belt every FinalReply passes through on its way out of Run:
// StripResidualLookupTags, and — only when it actually found and removed
// something — one more Step disclosing that a residual marker was stripped
// rather than shown. §5.4 requires this never be silent: a strip nobody is
// told about is the same undisclosed loss §7 exists to close, just at the
// exit instead of the entry. The common case (nothing to strip) costs one
// regexp match and returns the inputs unchanged.
func (l *Loop) seal(reply string, round int, steps []Step) (string, []Step) {
	cleaned, stripped := StripResidualLookupTags(reply)
	if !stripped {
		return reply, steps
	}
	if cleaned == "" {
		cleaned = "A lookup marker was found in the reply with nothing else to show."
	}
	step := Step{
		N: len(steps) + 1, Round: round, Read: "(sanitize)",
		Label:  "a residual <lookup>/</lookup> fragment was found in the reply and stripped before it reached the operator",
		Status: StatusFailed,
		Detail: "the reply was not recognised as a servable lookup block by the parser but still carried a stray tag",
	}
	steps = l.emitAll(steps, []Step{step})
	return cleaned, steps
}

// serveRound dispatches one round's validated requests against the budget
// and the cache, and turns every pre-dispatch refusal into a step too. It
// returns every step the round produced and how many requests actually
// reached the Menu or a cache hit — the "served" count the loop's two-
// consecutive-unserved-rounds rule watches.
func (l *Loop) serveRound(ctx context.Context, budget *Budget, cache map[string]Result, round, stepBase int, parsed ParseOutcome) (steps []Step, served int) {
	n := stepBase
	for _, pd := range parsed.PreDispatch {
		n++
		steps = append(steps, preDispatchStep(n, round, pd))
	}

	readsThisRound := 0
	for _, req := range parsed.Requests {
		if readsThisRound >= budget.MaxReadsPerRound {
			n++
			steps = append(steps, refuseStep(n, round, req, budget.RefusalReason(),
				"reads-per-round ceiling of "+strconv.Itoa(budget.MaxReadsPerRound)+" reached"))
			continue
		}

		key := cacheKey(req)
		if cached, ok := cache[key]; ok {
			cached.Status = StatusSkippedCached
			n++
			steps = append(steps, newStep(n, round, req, cached))
			served++
			continue
		}

		isHost := req.Read == ReadHost
		if ok, reason := budget.Reserve(isHost); !ok {
			n++
			steps = append(steps, refuseStep(n, round, req, budget.RefusalReason(), reason))
			continue
		}

		res := l.Menu.Perform(ctx, req)
		res = finishResult(res, budget, req.Why)
		// Only a successful read is cached. A failed read that is cached
		// and then re-requested comes back StatusSkippedCached, and
		// renderStepLine's cached branch does not carry Detail — the
		// failure reason would silently vanish from the record on the
		// repeat, which is exactly the honesty §7 exists to prevent.
		if res.Status == StatusOK {
			cache[key] = res
		}
		readsThisRound++
		served++
		n++
		steps = append(steps, newStep(n, round, req, res))
	}

	return steps, served
}

// preDispatchStep turns a structural refusal (unknown read, bad parameter,
// missing "why", duplicate block) into a Step. These are not budget
// refusals, so RefusedBecause is left empty — §7.1's three-reason enum
// classifies why a MENU declines a read, and a request that never had a
// valid shape never reached one.
func preDispatchStep(n, round int, pd PreDispatchRefusal) Step {
	// Node carries through when the refusal was ABOUT a registered node
	// (#59): a peer named and not read is a peer that did not answer, and
	// the round's fleet-completeness check keys on Step.Node to say so.
	// Without it, a fleet-wide question that reached three of four nodes
	// would produce three clean answers and no line saying the fourth was
	// never read.
	req := Request{Read: pd.Read, Why: pd.Why, Node: pd.Node}
	return newStep(n, round, req, Result{Status: StatusRefused, Detail: pd.Reason})
}

// finishResult is where every read result — whatever a Menu implementation
// returned — passes through SanitizeInjected (Body and Detail, per §5.3's
// "no exceptions, no bypass path"), the per-result byte clamp (§6.1: 6 KB),
// and the per-round and per-question byte ceilings, before it can be cached
// or rendered. No Menu implementation is trusted to have done any of this
// itself; this is the one place all of it happens.
//
// The per-result clamp is known ahead of injecting the result, so it
// truncates in place. The round and question ceilings can only be checked
// AFTER a result's size is known — unlike a read count, there is nothing to
// reserve in advance — so a result that would cross either one is not
// clamped further, it is withheld entirely and rendered as a ceiling
// refusal instead. The read still cost the read-count budget Reserve
// already charged; what changes is whether its data reaches the prompt.
func finishResult(res Result, budget *Budget, why string) Result {
	res = sanitizeResult(res)

	if res.Body != "" && budget.MaxBytesPerResult > 0 && len(res.Body) > budget.MaxBytesPerResult {
		res.Body = res.Body[:budget.MaxBytesPerResult] +
			"\n… truncated at the per-result byte cap; ask for a narrower range if you need more."
		res.Truncated = true
	}

	if res.Body == "" {
		return res
	}

	if ok, reason := budget.ReserveBytes(len(res.Body)); !ok {
		return Result{
			Status:         StatusRefused,
			RefusedBecause: budget.RefusalReason(),
			Detail:         ceilingDetail(reason, why),
			Source:         res.Source,
		}
	}
	return res
}

// cacheKey is a deterministic identity for a Request, used both for the
// per-question cache and to recognise "the model asked for the same thing
// twice" (§5.4). Built by hand rather than via json.Marshal so the key is
// stable across Go versions' map/struct encoding behaviour and never
// depends on JSON's own quoting rules.
//
// Node is part of the key. Without it, a peer's metric_recent and this
// node's own metric_recent would collide in the per-question cache and the
// second one would be served StatusSkippedCached from the FIRST one's
// data — one node's reading handed back labelled as another's, DI1
// verbatim, and silent: nothing about a cache hit looks wrong.
func cacheKey(r Request) string {
	i := strconv.Itoa
	return r.Read + "|" + r.Node + "|" + i(r.Around) + "|" + i(r.Span) + "|" + i(r.Latest) + "|" +
		i(r.Limit) + "|" + i(r.Index) + "|" + i(r.From) + "|" + i(r.To) + "|" +
		i(r.Lines) + "|" + strconv.FormatInt(r.SinceMs, 10) + "|" + r.Metric + "|" + r.Range + "|" +
		r.Agg + "|" + r.Key + "|" + r.Verb
}

// registeredCount is how many peers the fleet HAS, for the coverage line,
// which is the roster's count when there is one, and only otherwise the
// count of peers this process can read (#59).
//
// The two differ exactly where the issue bit: a fleet of three whose
// credentials this host holds for two would have reported "2 registered" and
// called a two-node answer complete. The roster is what this host knows
// exists, so it is the honest denominator.
func (l *Loop) registeredCount() int {
	if n := len(l.Roster.Peers()); n > 0 {
		return n
	}
	return len(l.Nodes)
}

// fleetCompletenessStep is DI1a's mitigation: a fleet-wide claim built from
// a subset of the fleet's peers is correct about what it contains and
// silently wrong about what it represents unless the record also states
// what it does not contain. Synthesised once per round, and only when at
// least one peer this round was asked and did not answer — an all-success
// round (whether it touched one peer or several) needs no extra line;
// ordinary provenance on each read's own Step already covers it (§7's
// first half, DI1). registered is the fleet's total roster size: two peers
// asked and both answering still understates the fleet if a third peer
// exists and was never asked at all, which is why the count is carried
// even though it does not, by itself, decide whether this step fires.
func fleetCompletenessStep(n, round, registered int, roundSteps []Step) (Step, bool) {
	type peerState struct {
		answered bool
		reason   string
	}
	peers := map[string]*peerState{}
	var order []string
	for _, s := range roundSteps {
		if s.Node == "" {
			continue
		}
		ps, seen := peers[s.Node]
		if !seen {
			ps = &peerState{}
			peers[s.Node] = ps
			order = append(order, s.Node)
		}
		switch s.Status {
		case StatusOK, StatusSkippedCached:
			ps.answered = true
		default:
			if ps.reason == "" {
				if s.Detail != "" {
					ps.reason = s.Detail
				} else {
					ps.reason = string(s.Status)
				}
			}
		}
	}
	if len(order) == 0 {
		return Step{}, false
	}

	answered := 0
	var absent []string
	for _, label := range order {
		if peers[label].answered {
			answered++
		} else {
			absent = append(absent, label)
		}
	}
	if len(absent) == 0 {
		return Step{}, false
	}

	var body strings.Builder
	for _, label := range absent {
		fmt.Fprintf(&body, "%s — %s\n", label, peers[label].reason)
	}

	return Step{
		N: n, Round: round, Read: "(fleet)",
		Label:  fmt.Sprintf("fleet coverage: %d registered, %d asked, %d answered", registered, len(order), answered),
		Status: StatusOK,
		Detail: fmt.Sprintf("%d of %d asked peers answered", answered, len(order)),
		Body:   strings.TrimRight(body.String(), "\n"),
	}, true
}
