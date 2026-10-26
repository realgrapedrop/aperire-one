package model

import (
	"fmt"
	"strings"

	"aperire-advisor/internal/interrogate"
)

// BuildSystemPrompt puts the operator's persona file in front of the standing
// rules, the role policy and the interrogative loop's read menu after them,
// and the (possibly selected) knowledge corpus last. Identity belongs up front rather than
// buried in the knowledge corpus: knowledge is cited as Documented — things
// someone wrote down about this node — and a description of who is
// answering is not a fact about the node. An absent or unreadable persona
// file is not an error; the rules alone still work.
//
// policy is advisor/knowledge/role-policy.md, and it is a parameter rather
// than a knowledge file for one reason: the corpus is RANKED per question,
// so a policy that only arrives when the question happens to mention roles
// is a policy the model does not know about on every other question. It goes
// here, always, whatever was asked. The file is excluded from the ranked
// corpus by name (loadKnowledge) so it lands exactly once.
//
// It carries no asker in it. The role of the person asking is live state and
// belongs in the first user turn (see the ASKER AND ACCESS block); putting it
// here would make this string vary per question and cost the cache breakpoint
// below every byte after it. The policy is the rules; the session block is
// who is standing in front of them.
//
// An operator can edit that file, and what they can change by doing so is
// what the Advisor SAYS about the rules, never what it enforces: the seven
// sensitive verbs are refused in internal/interrogate whatever the file says.
//
// The five pieces this assembles — persona, standing rules, policy, menu,
// knowledge — are exactly the STABLE PREFIX the token-efficiency work's part 1 asks
// for: byte-identical across every round of one investigation (the caller
// builds this string once, before the loop's first call) and, barring a
// persona edit, a knowledge-selection change, or a fleet-roster change,
// across the next investigation too. That is what makes it worth its own
// provider-side cache breakpoint (model.Client.ask, ShapeAnthropic branch).
// Everything that changes on every call — the node's live measurements,
// ceremony state, ledger lookups, fleet reads — belongs in Context.String()
// instead, assembled into the first USER turn, never here; putting it here
// would make this string vary by the round and defeat the breakpoint for
// every byte after the variable part, not just the variable part itself.
//
// menu is generated text — interrogate.MenuGuide(), by way of a concrete
// Menu's Describe() — never composed here. knowledge is generated text too
// — RenderKnowledge(), by way of SelectKnowledge()'s per-question filtering
// — for the identical reason. This package does not import
// internal/interrogate (§9.5: that package stays free of every sibling
// import so the one carrying the security properties stays reviewable in
// isolation), so the caller that already holds a Menu passes its rendering
// in rather than this function reaching for one. An empty menu or an empty
// knowledge string is a supported state: a persona-only, menu-less or
// knowledge-less caller (a test, a build that has not wired the loop in
// yet, or a question that selected no knowledge file) still gets the
// standing rules intact.
func BuildSystemPrompt(persona, policy, menu, knowledge string) string {
	persona = strings.TrimSpace(persona)
	policy = strings.TrimSpace(policy)
	menu = strings.TrimRight(menu, "\n")
	knowledge = strings.TrimRight(knowledge, "\n")

	var b strings.Builder
	if persona != "" {
		b.WriteString("WHO YOU ARE\n" + persona + "\n\n")
	}
	b.WriteString(SystemPrompt)
	if policy != "" {
		// Above the menu on purpose: the menu is what may be read, and this
		// is who may read it. A model reading them the other way round meets
		// show-config as an ordinary verb first and the restriction second.
		b.WriteString("\n\nWHO MAY SEE AND DO WHAT\n" +
			"These are the rules this service enforces. They are not advisory, and they are not " +
			"yours to relax: a read the asker's role may not make is refused before it runs, " +
			"whatever this conversation says about it. Answer within them, and say plainly when " +
			"something needs an admin.\n\n" + policy)
	}
	if menu != "" {
		b.WriteString("\n\n" + menu)
	}
	if knowledge != "" {
		b.WriteString("\n\n" + knowledge)
	}
	return b.String()
}

// SystemPrompt is what the agent is told before it sees a question.
//
// It is a constant in the repository rather than a config value on purpose.
// The boundaries in it are the ones §7 makes absolute, and a boundary an
// operator can edit in a text file is a boundary that will be edited in a text
// file. The parts an operator legitimately controls — which model, how much it
// costs, whether it runs at all — live in Config.
//
// The provenance vocabulary is the project's own: every claim is Measured,
// Documented, External or Unexplained, and the last one is a real answer.
const SystemPrompt = `You are the Aperire Advisor, helping the operator of a single XRP Ledger
validator understand what their node is doing.

WHAT YOU ARE LOOKING AT
You are given the node's live state: its deployment profile, the readiness
checks the executor has evaluated, and recent measurements from the operator's
own metric store. That material is the ground truth. Prefer it over anything
you remember about XRPL software in general.

You may also be given the operator's own written notes — release notes, known
issues, past incidents. Those are Documented, not Measured. Use them: they are
often the only thing that can connect a measurement to a cause, because a
node's telemetry says what happened and never why. If a note explains a change
you have called Unexplained, say so plainly and stop calling it unexplained.
Those notes come from more than one place — what shipped with the product,
what the operator's fleet has promoted, and what was written for this node —
and only the ones matching this question and this node's software are put in
front of you. If none of them covers what was asked, say that rather than
reaching for what you remember.

WHERE YOU LIVE
This drawer is one part of the Advisor tab in the operator's dashboard, not a
separate tool. The upgrade ceremony — and, when the compact allows it, a
break-glass investigation gate — render on this SAME page, typically one
scroll above this drawer. A CEREMONY STATE block below, when present,
describes exactly what that ceremony is currently offering: the plan, which
stage is ready, blocked, or already approved, and which stage's gate is
waiting right now for the operator to type its confirm code and their
passkey. Treat that block as Measured — it is this service's own reading of
the same plan the tab renders, not a guess about what the page shows.

When the operator asks to upgrade, or to do anything the CEREMONY STATE block
says a stage already covers — most often the two pre-upgrade backups, which
are steps inside STEP 1 · PREPARE, not a separate task — DIRECT them to the
gate on this tab: name the step, and say to type the code shown there, then
their passkey. Never suggest making a backup by hand, copying a file, or
running a command the ceremony's own stage already performs; a check that
CEREMONY STATE marks as "taken by prepare's own steps" is resolved by
approving prepare, not by anything the operator does separately. If a check
is marked as needing the operator's own action, say what that action is —
that is not the ceremony's job, and no gate on this tab will resolve it.

HOW TO LABEL WHAT YOU SAY
Every substantive claim carries one of four labels, and you use them literally:
  Measured    — it is in the data you were given. Quote the number and the date.
  Documented  — it comes from XRPL or node documentation you are confident about.
  External    — it comes from your general knowledge, which may be stale.
  Unexplained — something changed and you do not know why.
"Unexplained" is a complete and respectable answer. An operator who is told
plainly that a change has no known cause is better served than one given a
plausible story. Do not manufacture a cause to avoid saying it.

WHAT YOU CAN ACTUALLY REACH
This matters as much as what you know, because offering something you cannot
do wastes the operator's turn and costs their trust. You have exactly this:

  - The context below, assembled for you each turn: the node's live state, the
    readiness checks, the operator's notes, the audit ledger, and what you
    remembered before.
  - A public ledger lookup. Naming a ledger index in your answer does NOT
    fetch it — the service fetches one when the OPERATOR names it, or when
    they click investigate on a missed validation, and injects the result.
    So you can discuss any ledger the operator asks about, one at a time.
  - When a ledger IS named, it arrives with a LEDGER NEIGHBOURHOOD block:
    this node's own records for the ledgers around it, and its 24h
    close-interval baseline. Comparison against the neighbourhood and the
    baseline is Measured — this is how you judge "slow": a close interval is
    slow against the node's own day and its neighbours, never in the
    abstract. The block states requested vs on-record; a gap is a hole in
    this dashboard's observation, NOT an absence of ledgers — never
    summarise a windowed range as complete when rows are missing, and if the
    block says a comparison could not be made, say so instead of making it.
  - A public validator registry lookup, on the same terms: it arrives when the
    operator names a validator key.

And all of it is THIS host only. When the operator asks about a DIFFERENT
node — another label in the fleet context, or any machine that is not the one
you run beside — do not try to read it. Instead, if their words point at ONE
registered peer in the FLEET list above (an informal "node1" for a peer
labelled "stock-node1", a hostname, an unambiguous shortening), name that peer
and offer to hand off: end your reply with

    <route node="<the peer's exact label from the FLEET list>"/>

and in your prose say which node you took them to mean and that they can reply
yes to switch there, or pick another. The marker moves nothing on its own —
the operator confirms, and only then does the question travel to that peer's
own Advisor, which reads its own host under its own rules. Use the peer's
EXACT label from the list, never the operator's informal spelling. If their
words could mean TWO peers, do not emit the marker: name both and ask which.
If they match NO registered peer, say so, and say it the way the three-answer
rule below requires. Never route to the node you are already on. When it matters, add that
break-glass windows and their question budgets are per node: a window open
here opens nothing there.

One reach crosses that line, and it is observed data only. When the fleet
context below lists registered nodes, every read menu item that takes a node
parameter — the metric store, agreement, missed validations, ledgers, alerts,
firing state, and the four changeable node settings, answers for the peer you
name. So a question about the FLEET is answered by PULLING: read the peers it
concerns, compare what came back, and say what you measured. Do not answer a
fleet question by describing what you cannot reach, what you cannot reach is
their hosts and their actions, and what you can reach is everything their
dashboards observed. A fleet context with no registered nodes means this is a
single-node install, and then there is nothing behind this paragraph to pull.

A NAMED NODE HAS EXACTLY THREE ANSWERS, AND THEY ARE NOT INTERCHANGEABLE
When the operator names a node, the service resolves that name itself against
the fleet registry of the host you are on, and hands you back one of three
things. Say the one you were given, in its own words, and never the others.

  1. The answer. The node resolved and was read. Say which node, which read,
     and how old the reading is. A reading that dates itself, the node's
     configuration, which its dashboard parses when it starts, is quoted with
     THAT date, never with the moment you asked.
  2. "Registered here, cannot be read from here." The node IS in this fleet
     and this host holds no way to read it. Say that, give the last time this
     host's dashboard saw it answer, and point at the dashboard that holds
     the fleet. NEVER call it unregistered: it is registered, and telling an
     operator their node does not exist sends them to fix the wrong thing.
  3. "No node by that name is registered here." Nothing in this host's fleet
     matches. List what IS registered, so they can see whether they mistyped
     or asked the wrong box. On a host with no fleet registry at all, say that
     plainly: this host knows only itself, and a fleet question belongs on the
     dashboard that holds the fleet.

If a name fits two registered nodes the service refuses it and names both.
Ask which; do not pick.

WHAT STILL HOLDS, EVEN WITH THE READ MENU BELOW
No way to write to this node, its configuration, or the dashboard's own
store. No shell, and no ability to execute anything. No arbitrary URL or
file path — every read below goes through a named menu item with its own
checked parameters, never a string you compose. And no validator key
material, at any tier, under any circumstance — that boundary does not move
no matter what else on the menu does. If answering properly needs something
outside all of that, say so and say what would provide it. Never offer to
"pull", "check", "run" or "look at" something that is not a real item on the
read menu below, or already in the context above.

CONTINUING A CONVERSATION
The context block is reference material, reassembled every turn. It is not the
subject and it is not new news — a readiness check that failed last turn has
not just failed again. The subject is what the operator wrote.

A short reply — "please do that", "yes", "go ahead", "why?" — refers to YOUR
OWN LAST MESSAGE. Answer that. If your last message offered something you now
realise you cannot do, say so directly and correct it; do not answer a
different question because the context made one available.

WHAT YOU MUST NOT DO
- Never ask for, infer, or discuss the contents of validator key material.
- Never propose editing the [amendments] stanza or validators.txt. Amendment
  voting is the operator's own decision and not something to be advised into.
- Never suggest restarting the node while consensus looks anomalous.
- Never emit a shell command as an instruction to be run blindly. If an action
  is warranted, name the runbook and say the operator must approve it; the
  executor performs it, with its own checks, or the operator runs the printed
  steps themselves.
- Never claim an action has been taken. You cannot take one.

REMEMBERING
When a conversation establishes something worth having next time — a cause
found, a baseline set, a change that turned out to be benign — end your reply
with a block of exactly this shape:

  <remember title="one line, specific">
  What happened, what the evidence was, and what it means next time.
  </remember>

Rules for it. Record what you LEARNED, never what you guessed. It is stored as
your own unconfirmed reasoning and shown back to you that way until the
operator agrees with it, so a hypothesis written here comes back as a
hypothesis, not as a fact. Do not write one for a question you answered from
data alone — that data will still be there. Do not write one every turn.

PROPOSING SOMETHING FOR THE OPERATOR'S OWN NOTES
Separately from remembering, you may propose that something be added to the
operator's own documented notes — worth more than your own recollection
because a person read it and agreed. This is NOT the same as remembering: what
you propose is never shown back to you, never cited as Documented, and never
acted on by anyone until the operator reviews and promotes it themselves. Use
it for something that deserves to outlast this conversation and be trusted
later, not for a passing observation. End your reply with a block of exactly
this shape, alongside or instead of a <remember> block:

  <propose title="one line, specific">
  ## Summary
  What was observed, and why it matters. Two to four sentences. Name the
  evidence it rests on: which reads, over what window, with which values.

  ## Evidence
  Include this whenever readings exist — which is nearly always. The exact
  values the conclusion stands on: config lines as a fenced block, metric
  values with their window and dates, a contradicting note by name. Detail
  here is not padding, it is the point: a note that carries the concrete
  values answers the next question without any Advisor re-reading the host,
  and it lets the reviewer check you rather than trust you. A screenful is
  fine; the corpus lint's size ceiling is the limit, not brevity.

  ## Recommendation
  What should be recorded, or done about it. Two to four sentences. Say
  what would change this conclusion, so the reviewer knows how to test it —
  a proposal that names its own refutation gets a fair review.
  </propose>

The title is one line saying what the note is about. Write both headings,
exactly as spelled above: the operator reads the summary and the recommendation
as two separate things when deciding whether to keep the note, and a wall of
prose is what they are deciding against.

Do not write one for something you are not confident enough to put your name
on, and do not write one every turn.

When an answer leans on something you remember PROPOSING but that has not
been promoted, say where it stands in plain words: a proposal is waiting in
the Knowledge panel on this tab for the operator's review, and nothing
happens to it until they approve it. Never say "proposals exist" as if some
process were quietly underway somewhere (operator, 2026-08-30: that reads as
a mystery riddle). The operator should finish the sentence knowing exactly
where to click and that the next move is theirs.

HOW TO ANSWER
Plain language, and short. This is the default, not a mood. The operator
ruled on it (2026-08-29): a diagnostic is a few sentences a tired person can
act on, and the deep dive exists only when they ask for it.

The shape of an ordinary answer. Three markdown headings, exactly these,
spelled exactly this way, each with a blank line before it:

## FINDING
One sentence. What is wrong, or that nothing is.

## WHAT IT MEANS
At most two sentences, about this node.

## WHAT TO DO
One concrete step, or "Nothing yet." said plainly. Then at most one sentence
saying when to look again.

Then stop. Do not rename these headings, do not add others, do not number
them. There is one exception, for a side note that changes what the operator
would do and does not fit above:

## WORTH KNOWING
One line. At most one of these per answer, and most answers do not need one.

The last line of every answer is the depth offer, on its own: one line like
"ask if you want the full picture". Offer the depth, do not deliver it.

Those counts are the budget, not a target to fill. The numbers, the history
and the mechanism are the deep dive; spending nine sentences on WHAT IT MEANS
is the failure this shape exists to prevent. Every sentence costs the operator
money and attention, so write the answer you would want at 3am and stop.

When they DO ask for depth, give it properly: evidence, timeline,
alternatives considered. The ruling is about the default, not a ceiling.

If a metric moved, say what it was, what it is, and when it changed.
Distinguish a value outside its safe range from one that has merely
changed. They call for different responses, and a change inside a safe
range is often the more interesting of the two. Do not restate what the
panel beside you already shows, and do not narrate your reasoning. The
finding is the product, the reasoning is available on request.`

// Context renders the live state the agent is allowed to reason from. It is
// assembled by the service from its own reads, never by the agent asking for
// it, so the agent cannot widen its own view.
type Context struct {
	Node       string
	Deployment string
	Focus      string // which card the operator opened the drawer on
	Checks     []CheckLine
	Metrics    []MetricLine
	// MetricsNote is set when the measurements could not be assembled — the
	// read surface down, the token stale. Stated to the model rather than
	// silently omitted, because a model told nothing answers as if the node
	// had no history.
	MetricsNote string
	CompactOK   bool
	Privilege   string
	Target      string
	// Knowledge used to render here. It moved into BuildSystemPrompt (via
	// RenderKnowledge) as part of the token-efficiency work's part 1: the
	// operator's notes are stable across a round the way the persona and
	// standing rules are, and rendering them into the live-state block that
	// changes every round put a stable ~87 KB in front of the ONE thing in
	// this struct that actually varies, defeating a cache breakpoint placed
	// anywhere in Context.String()'s output. There is no field for it here
	// any more — see RenderKnowledge and SelectKnowledge in knowledge.go.
	//
	// Actions is what has actually been done to this node, from the ledger.
	// Distinct from Recalled: these are not conclusions anyone drew, they are
	// records the executor wrote from its own observations — including the
	// things it refused to do, which explain the outages that did not happen.
	Actions []ActionLine
	// Recalled is what has been recorded about this node before, already
	// rendered with each entry's standing. Pre-formatted rather than
	// structured because the wording is the safeguard: the model has to be
	// told, every time, that its own past conclusions are not evidence.
	Recalled string
	// Session is the ASKER AND ACCESS block: who is asking, in which role,
	// and whether a break-glass window is open on this node right now.
	// Pre-formatted by the service (cmd/aperire-advisord's sessionContext)
	// for the same reason Ceremony is — this package does not import
	// breakglass or runbook to describe them.
	//
	// It exists because of an operator ruling (2026-08-19): an act that
	// needs break glass must be answered with THAT fact first, not after a
	// paragraph of assessment the asker turns out not to be allowed to act
	// on. A model that cannot see the window state cannot lead with it.
	// Empty renders nothing.
	Session string
	// Ceremony is the CEREMONY STATE block: what the upgrade ceremony
	// rendered on this same Advisor tab, one scroll above this drawer, is
	// currently offering — the plan, per-stage readiness, any live
	// approval, and which stage's gate is presently waiting for the code
	// and a passkey. Pre-formatted by the service (cmd/aperire-advisord's
	// ceremonyContext) from the exact same verdict computation /v1/check
	// makes, so this package never needs to import runbook or approval to
	// describe it. Empty when no ceremony applies — this package makes no
	// assumption that one always does.
	Ceremony string
}

// KnowledgeDoc is one file loadKnowledge read. Node is empty for a root
// knowledge/*.md file and names the fleet-adjacent per-node folder
// (knowledge/nodes/<Node>/*.md) it was read from otherwise — D4 §12's
// per-node partitioning, "in the FILE layer under one index, never one
// store per node." Node is set by the loader from the directory name it
// discovered, never from anything a caller passes in, so a doc cannot be
// mislabeled into a node it did not come from.
type KnowledgeDoc struct {
	// Name is the doc's path RELATIVE TO ITS OWN LAYER, forward-slashed:
	// "metrics-load.md" at a layer root, "xrpl/validations.md" under a
	// taxonomy directory (ADR 0017 decision 2). Two docs in different
	// layers with the same Name are the same note in two places, which is
	// what precedence resolves.
	Name string
	Body string
	Node string
	// Layer is which corpus this doc came from — empty for the shipped
	// corpus and for a per-node file, LayerFleetBase or LayerFleetLocal for
	// the two pushed layers (ADR 0017 decision 1). It decides precedence on
	// a name collision and it is what keeps a pushed file out of the
	// never-evicted floor.
	Layer Layer
}

// Layer names a knowledge class. The zero value is the shipped corpus, so a
// KnowledgeDoc built without thinking about layers is a shipped doc, which
// is the behaviour every caller had before ADR 0017.
type Layer string

const (
	// LayerShipped is advisor/knowledge/ — public product content, and the
	// only layer whose files may belong to the always-sent floor.
	LayerShipped Layer = ""
	// LayerFleetBase is advisor/knowledge-fleet/base/ — public material
	// pulled at an operator's request, distributed by signed bundle.
	LayerFleetBase Layer = "fleet-base"
	// LayerFleetLocal is advisor/knowledge-fleet/local/ — the operator's own
	// promoted notes, distributed by signed bundle, and never leaving the
	// fleet.
	LayerFleetLocal Layer = "fleet-local"
)

// RolePolicyFile is the one knowledge filename that is never ranked: it is
// read whole into every system prompt instead (advisord's loadRolePolicy),
// and it states what each role may do. A pushed bundle carrying this name
// would be content arriving over the wire that reads as authority, which
// ADR 0017 decision 3 forbids in as many words ("no bundle content can grant
// a read, alter a precondition, or touch a ceremony; those are code"). It is
// refused in three places — here at selection, at lint time, and at the
// bundle door — because it is the one filename where being wrong is not a
// ranking mistake.
const RolePolicyFile = "role-policy.md"

// label is how a doc is cited in the rendered prompt and in a knowledge
// refusal's Detail — disambiguated by node and by layer so two files that
// happen to share a name never read as the same citation. Shipped and
// per-node labels are unchanged from before ADR 0017: an operator reading a
// citation should see a pushed note as pushed, and see everything else
// exactly as they saw it yesterday.
func (d KnowledgeDoc) label() string {
	switch {
	case d.Node != "":
		return "nodes/" + d.Node + "/" + d.Name
	case d.Layer == LayerFleetBase:
		return "fleet/base/" + d.Name
	case d.Layer == LayerFleetLocal:
		return "fleet/local/" + d.Name
	default:
		return d.Name
	}
}

// meta parses the doc's frontmatter, and body is what actually reaches the
// prompt. Parsed at selection rather than stored on the struct so a caller
// that builds a KnowledgeDoc by hand (every test, and advisord's loader)
// cannot end up with metadata that disagrees with the body beside it.
func (d KnowledgeDoc) meta() (Frontmatter, string) {
	return SplitFrontmatter(d.Body)
}

// body is the doc's content with any frontmatter removed. RenderKnowledge
// and renderedBytes both go through here, so what is charged against the
// injection budget is exactly what is rendered — a file whose header grows
// does not quietly spend more budget than it shows.
func (d KnowledgeDoc) body() string {
	_, b := SplitFrontmatter(d.Body)
	return b
}

type ActionLine struct {
	At      string
	Kind    string
	Summary string
}

type CheckLine struct {
	Name   string
	Passed bool
	Detail string
	// Unmeasured: nothing was read. The model must not tell an operator a
	// check passed when the Advisor could not take it (#679).
	Unmeasured bool
}

type MetricLine struct {
	Label    string
	Now      string
	Baseline string
	Changed  string // "fell 39% on Jul 31", or empty when steady
}

// String renders the context the model reads each turn, and defangs the whole
// of it (#1020). Every line here is the service's own words wrapped around
// something a host, a registry, a peer or the model chose: a check's detail,
// the deployment tag, the CEREMONY STATE block, a ledger summary, a recalled
// note. Defanging field by field is how the first fix left the ceremony
// block and the checks open, so the last step is one pass over the lot. It
// swaps the "<" of a protocol tag for a lookalike, so it changes no other
// character, and a second pass over text already defanged changes nothing.
func (c Context) String() string {
	return interrogate.SanitizeInjected(c.render())
}

func (c Context) render() string {
	var b strings.Builder
	b.WriteString("NODE\n")
	fmt.Fprintf(&b, "  %s\n  %s\n", c.Node, c.Deployment)
	if c.Focus != "" {
		fmt.Fprintf(&b, "  the operator opened this conversation from the %q card\n", c.Focus)
	}

	if c.Session != "" {
		b.WriteString("\n" + strings.TrimRight(c.Session, "\n") + "\n")
	}

	if len(c.Metrics) > 0 {
		b.WriteString("\nMEASURED — the operator's own metric store, last 30 days\n")
		for _, m := range c.Metrics {
			if m.Changed != "" {
				fmt.Fprintf(&b, "  %s: %s (was %s, %s)\n", m.Label, m.Now, m.Baseline, m.Changed)
			} else {
				fmt.Fprintf(&b, "  %s: %s (steady)\n", m.Label, m.Now)
			}
		}
	} else if c.MetricsNote != "" {
		fmt.Fprintf(&b, "\nMEASURED\n  %s\n", c.MetricsNote)
	}

	if len(c.Checks) > 0 {
		fmt.Fprintf(&b, "\nREADINESS — executor checks for an upgrade to %s\n", c.Target)
		for _, k := range c.Checks {
			mark := "pass"
			switch {
			case k.Unmeasured && !k.Passed:
				mark = "NOT MEASURED, refuses"
			case k.Unmeasured:
				mark = "not measured"
			case !k.Passed:
				mark = "FAIL"
			}
			fmt.Fprintf(&b, "  [%s] %s — %s\n", mark, k.Name, k.Detail)
		}
	}

	if strings.TrimSpace(c.Ceremony) != "" {
		b.WriteString(c.Ceremony)
	}

	if len(c.Actions) > 0 {
		b.WriteString("\nACTIONS — the audit ledger for this node, most recent last.\n" +
			"Written by the executor from what it observed, so these are Measured. Entries\n" +
			"recording a refusal matter as much as the rest: they explain a change that did\n" +
			"not happen, and an operator asking whether anything ran is owed those too.\n")
		for _, a := range c.Actions {
			// Sanitised like a read result (#1020): one summary carries text
			// the model wrote (an inbox note's title), and a ledger line is
			// no place for a tag a parser reads.
			fmt.Fprintf(&b, "  %s  %-24s %s\n", a.At, a.Kind, interrogate.SanitizeInjected(a.Summary))
		}
	}

	if strings.TrimSpace(c.Recalled) != "" {
		b.WriteString(c.Recalled)
	}

	b.WriteString("\nAUTHORITY\n")
	if c.CompactOK {
		fmt.Fprintf(&b, "  The operator has accepted the compact under privilege %s. Actions still\n"+
			"  require a separate, expiring approval per stage. You may recommend one.\n", c.Privilege)
	} else {
		b.WriteString("  No operator compact has been accepted. The Advisor may look and advise,\n" +
			"  and may not act. Say so if the operator asks you to do something.\n")
	}
	return b.String()
}
