package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"aperire-advisor/internal/interrogate"
)

// knowledgeHeader is RenderKnowledge's fixed preamble. Pulled out to a
// package var (rather than inlined in RenderKnowledge) so the injection
// budget below can charge its exact byte cost once, from the same literal
// RenderKnowledge writes — one source of truth for what "rendered knowledge
// bytes" means, which is what the security sign-off's P2-005 checkable
// measures ("a test asserting rendered knowledge bytes stay at or under
// [the budget]").
const knowledgeHeader = "DOCUMENTED — the operator's own notes. Cite these as Documented,\n" +
	"never as Measured: they are what someone wrote down, not what the node reported.\n"

// RenderKnowledge renders the operator's own notes for the system prompt.
// This is exactly what Context.String() used to inline under a "DOCUMENTED"
// heading before the token-efficiency work's part 1 moved it into
// BuildSystemPrompt — the wording is unchanged, only where it is called
// from moved, so an operator who already reads these citations sees no
// difference in what the model is told.
func RenderKnowledge(docs []KnowledgeDoc) string {
	if len(docs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(knowledgeHeader)
	for _, d := range docs {
		fmt.Fprintf(&b, "\n--- %s ---\n%s\n", interrogate.SanitizeInjected(d.label()), renderedBody(d))
	}
	return b.String()
}

// renderedBody is a doc's body as it reaches the prompt: trimmed, and passed
// through the same sanitiser every read result is (#1020). Knowledge comes
// from the operator's folder, from the aggregator's fleet layer and from the
// pulled field guide, and none of those is this service's own text. A doc
// holding an <action> block, repeated by the model, parsed as a rollback the
// operator never asked for; defanged, it is a line of text.
func renderedBody(d KnowledgeDoc) string {
	return interrogate.SanitizeInjected(strings.TrimSpace(d.body()))
}

// renderedBytes is exactly what one more doc costs RenderKnowledge's output
// — the same "\n--- %s ---\n%s\n" shape, on the same trimmed body, so the
// budget below counts what actually reaches the prompt rather than the raw
// bytes on disk (a file with a lot of trailing whitespace should not spend
// more budget than it renders).
func renderedBytes(d KnowledgeDoc) int {
	return len(fmt.Sprintf("\n--- %s ---\n%s\n", interrogate.SanitizeInjected(d.label()), renderedBody(d)))
}

// selectablePrefixes names which knowledge files are topic-scoped rather
// than core — knowledge-audit.md §7 item 1: "identified by a filename
// prefix rather than front matter — metrics-*.md today, tuning-*.md and
// panels-*.md as items 1 and 2 land." Everything NOT matching a prefix here
// answers questions about THIS node regardless of topic (node-profile.md,
// releases.md, incident write-ups, and the pre-metrics field-guide files)
// and is a candidate regardless of the question's own words — see
// scoreCoreWeight for how that plays out once ranking is budget-aware.
// Extending selection to a second topic is a one-line addition to this
// slice, never a second selection mechanism.
var selectablePrefixes = []string{"metrics-"}

// IsSelectable reports whether a knowledge file's inclusion in a given
// question's prompt depends on the question, versus being a candidate
// regardless of topic.
func IsSelectable(name string) bool {
	for _, p := range selectablePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// floorFiles is the P2-004 floor (security sign-off, 2026-08-09): "a named
// floor that ranking never evicts... Floor membership is an explicit named
// set, never a filename prefix" — so a promoted note cannot join the floor
// by being named for it the way selectablePrefixes lets a file join
// "selectable" by a naming convention.
//
// Membership is deliberately narrower than "all of today's core": the
// operating manual (how to read this node's data, how to act on it) plus
// this node's own identity — the three things every answer needs regardless
// of topic or budget. releases.md and incident-*.md stay in "core" (D4 §10
// change 1: "always a candidate, weighted highest" among the ranked
// remainder, scoreCoreWeight below) rather than the floor, because they are
// exactly the class D4 §4.2 names as the one that grows without bound (more
// incident write-ups, more per-node profiles over time) — the corpus should
// be able to scale by adding ranked, evictable-under-pressure candidates,
// not by growing the set that can never be cut. A floor that grew with the
// corpus would just be maxTotal's silent-eviction failure moved earlier.
//
// Only matches a ROOT file (KnowledgeDoc.Node == ""): a per-node file that
// happens to share one of these names (a future "node-profile.md" moved
// under knowledge/nodes/<node>/) is NOT floor — the floor is about what
// every question needs regardless of WHICH node, and a per-node file is by
// definition about one node.
var floorFiles = map[string]bool{
	"field-guide-diagnostics.md": true,
	"field-guide-maintenance.md": true,
	"field-guide-upgrading.md":   true,
	"node-profile.md":            true,
}

// scoreCoreWeight is the rank every non-floor core candidate (IsSelectable
// false, e.g. releases.md, an incident write-up, a per-node profile) gets —
// high enough that it always sorts ahead of a matched selectable file, which
// keeps D4 §10 change 1's ordering ("core becomes always a candidate,
// weighted highest, rather than always sent") without needing core and
// selectable candidates to share one scoring scale. A matched selectable
// file's score is its match count (see matchScore), always small relative
// to this.
const scoreCoreWeight = 1 << 20

// scorePerNodeBoost is added on top of a candidate's base score (core or
// matched-selectable) when the doc is scoped to the node being asked about
// (KnowledgeDoc.Node == the caller's node). Without this, a per-node doc and
// a root doc land on the exact same score and are ordered only by label() —
// "nodes/<label>/..." sorts after most bare root filenames, so THIS node's
// own profile would be the first thing dropped under budget pressure, which
// inverts the whole point of per-node knowledge: a doc scoped to the node
// actually being asked about is strictly MORE specific to the question than
// a node-agnostic one, and should win a tie, not lose one to string order.
const scorePerNodeBoost = 1 << 10

// scoreFleetLocalBoost is added when the doc is in knowledge-fleet/local/ —
// a note the operator themselves promoted to the whole fleet. Above any
// realistic match count (a question's words number in the tens) and below
// scorePerNodeBoost, so the ordering under budget pressure reads: this
// node's own docs, then the operator's promoted notes, then everything else
// by match. It exists because of stock-node2 and the aggregator, 2026-08-21 (#39):
// after a 145 KB field-guide pull, pulled public pages with strong keyword
// overlap were boarding ahead of the operator's own 1 KB promoted notes,
// which then never fit — inverting the promote flow's whole promise. ADR
// 0017's layer precedence only ever resolved same-NAME collisions; this is
// the same judgement applied to the budget competition. Promoted notes are
// small and curated by a person: they board first.
const scoreFleetLocalBoost = 1 << 8

// KnowledgeInjectionBudget is the operative limit on what SelectKnowledge
// may hand to RenderKnowledge — moved here from loadKnowledge's maxTotal
// (main.go) per D4 §10 change 1 and security sign-off P2-005: "no commit
// relaxes or removes maxTotal unless the same commit adds the injection
// budget as a constant in code, with a test asserting rendered knowledge
// bytes stay at or under it." Set at the same 96 KB the load-time cap held.
//
// Re-measured 2026-09-27: the shipped corpus is 20 files and 125.5 KB, and
// it no longer fits this budget whole. What one QUESTION renders still does,
// with room to spare: 61.7 KB for "why did my peers count drop overnight"
// and 69.2 KB for "should I upgrade this node", both with no refusals
// (knowledge_fleet_load_test.go holds those two numbers). The difference is
// the selection: a question gets the notes ranked highest for it, not the
// whole shelf, and anything left out is named rather than dropped silently
// by os.ReadDir name order, which is what this replaced.
//
// The budget is not raised here. It is a signed-off constant (P2-005) and it
// is about what one question may cost, not about how much this project has
// written down. What the growth means in practice is that the headroom is
// now about 27 KB on the larger of those two questions rather than the whole
// corpus fitting by luck.
const KnowledgeInjectionBudget = 96 << 10

// stopwords replaces the old "skip any word under four characters" rule
// (knowledge-audit.md §7 item 3's known miss: "cpu", "ram", "tps" and "p50"
// are all three characters or fewer and none is in knowledgeAliases, so a
// question asking about cpu selected nothing"). D4 §7.2 item 2 names the
// fix directly: "The four-character floor becomes a stopword list, the
// correct instrument" — so short DOMAIN words (cpu, p50) can match while
// short ENGLISH words (the, was, is) still cannot, which a length cutoff
// alone cannot express.
//
// Lowering the floor to three characters (below, in matchScore) admits new
// three-letter words a length-four floor used to filter for free, so this
// list was checked against every ### heading in the real corpus rather than
// written from intuition alone: "use" is a literal substring of
// mem_used_pct and swap_used_pct (metrics-host-cpu-and-memory.md) — "how much memory does
// it use" would otherwise select a host metrics file on "use" alone — and
// "out"/"low" are literal substrings of peers_outbound and
// jq_trans_overflow respectively. TestSelectionLoadsNoneOnAMiss carries a
// regression guard of exactly this shape (natural phrasing dense in
// three-letter words) so a future heading addition that opens a new
// collision fails a test rather than silently degrading selection, which is
// the same "drifts, and it will drift" risk D4 §4.4 already named for the
// alias table.
var stopwords = map[string]bool{
	"the": true, "was": true, "and": true, "for": true, "has": true,
	"had": true, "can": true, "not": true, "but": true, "you": true,
	"are": true, "why": true, "how": true, "now": true, "out": true,
	"per": true, "yet": true, "its": true, "our": true, "any": true,
	"all": true, "did": true, "use": true, "low": true, "who": true,
	"let": true, "yes": true, "get": true, "got": true, "new": true,
	"old": true, "top": true, "big": true, "bad": true, "off": true,
	"too": true, "own": true,
}

// headingRe pulls the selection key straight from the files — knowledge-
// audit.md §7 item 2: "Parse the `### ` headings of each selectable file
// once per load; those headings are the metric names. No second list to
// drift from the first." A file that renames or adds a heading changes what
// it matches on its own; nothing here needs editing to keep up.
var headingRe = regexp.MustCompile(`(?m)^### (.+)$`)

// knowledgeAliases maps a word an operator actually types to a substring
// worth matching against a selectable file's headings, for the words that
// are not themselves a fragment of the metric name they mean —
// knowledge-audit.md §7 item 3 names exactly these five: "agreement,
// peers, swap, bandwidth, disk." Three of the five (agreement, peers, swap)
// already match by plain substring against today's headings
// (agreement_pct, peer_count, swap_used_pct) and are listed here anyway for
// resilience against a future rename. The other two do not appear in any
// current heading and would otherwise never match anything:
//
//   - "bandwidth" has no metric literally named that; rx_bps, tx_bps,
//     rx_pps and tx_pps are what it means.
//   - "disk" has no series in the corpus at all today (knowledge-audit.md
//     §4 lists it as an uncovered area) — nudb_size, the database's own
//     size on disk, is the closest thing on file, so a disk question is not
//     left matching nothing until a dedicated file exists.
//
// "ram" is added for the same reason as "bandwidth": mem_used_pct is what it
// means, and "ram" does not appear literally in that heading.
var knowledgeAliases = map[string][]string{
	"agreement": {"agreement"},
	"peers":     {"peer"},
	"peer":      {"peer"},
	"swap":      {"swap"},
	"bandwidth": {"bps", "pps", "rx_", "tx_"},
	"disk":      {"nudb"},
	"ram":       {"mem"},
}

// isTopicScoped decides whether a file's inclusion depends on the question.
//
// Three ways to be topic-scoped, and they are the same mechanism read three
// ways — ADR 0017 decision 2 ("the keyword ranker gains path- and
// tag-scoping"):
//
//   - the filename prefix that already meant this (metrics-*), now read from
//     the file's base name so a file filed under a taxonomy directory keeps
//     its meaning;
//   - a `tags:` list in the frontmatter, which is an author saying in as many
//     words what their file is about;
//   - a taxonomy directory (xrpl/…, os/…, devops/…), which is the same claim
//     made by where the file was filed.
//
// Everything else stays core: always a candidate whatever was asked. That is
// the whole shipped corpus today, unchanged — no file in it has frontmatter
// or sits in a subdirectory.
func isTopicScoped(d KnowledgeDoc, fm Frontmatter) bool {
	return IsSelectable(baseName(d.Name)) || len(fm.Tags) > 0 || strings.Contains(d.Name, "/")
}

// searchKey is what a topic-scoped file's match is computed against: its
// `### ` headings (as before), plus its tags and the directories it was filed
// under. Underscores and dashes in a path segment become spaces so
// "xrpl/peer-latency.md" is searchable by either word.
func searchKey(d KnowledgeDoc, fm Frontmatter) string {
	var b strings.Builder
	b.WriteString(headingWords(d.body()))
	for _, t := range fm.Tags {
		b.WriteString(strings.ToLower(t))
		b.WriteByte(' ')
	}
	if fm.Title != "" {
		b.WriteString(strings.ToLower(fm.Title))
		b.WriteByte(' ')
	}
	path := strings.ToLower(d.Name)
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[:i]
	} else {
		path = ""
	}
	for _, sep := range []string{"/", "_", "-"} {
		path = strings.ReplaceAll(path, sep, " ")
	}
	b.WriteString(path)
	return b.String()
}

// headingWords lowercases and flattens a file's `### ` headings into one
// search string, splitting a combined heading — "peers_inbound and
// peers_outbound", "rx_bps and tx_bps" — on the separators the corpus
// actually uses so a question naming only one of the pair still matches.
func headingWords(body string) string {
	var b strings.Builder
	for _, m := range headingRe.FindAllStringSubmatch(body, -1) {
		h := strings.ToLower(m[1])
		for _, sep := range []string{" and ", ",", "/"} {
			h = strings.ReplaceAll(h, sep, " ")
		}
		b.WriteString(h)
		b.WriteByte(' ')
	}
	return b.String()
}

// matchScore is matchesQuestion's ranking-aware successor: instead of a
// boolean, it counts how many of the question's own words (or an alias
// standing in for one) were found in a selectable file's headings — the
// existing heading/alias matching, extended into a scoring seed rather than
// replaced by one, per the D4 build's item A ("the existing heading/alias
// matching is the scoring seed — extend it, don't invent an embedding").
// More matched words is read as more specific to the file, and ranks it
// higher among selectable candidates competing for the same budget.
//
// Substring matching without word-boundary normalisation is deliberate,
// same as before: "peer" has to hit both inside a typed "peers" and inside
// the heading "peers_inbound" without either side stripping plurals or
// underscores first.
func matchScore(headings, question string) (score int, matched bool) {
	for _, word := range strings.Fields(question) {
		word = strings.Trim(word, ".,?!:;\"'()")
		if len(word) < 3 || stopwords[word] {
			continue
		}
		if strings.Contains(headings, word) {
			score++
			matched = true
			continue
		}
		for _, alias := range knowledgeAliases[word] {
			if strings.Contains(headings, alias) {
				score++
				matched = true
				break
			}
		}
	}
	return score, matched
}

// KnowledgeRefusal is one file that did not reach the prompt, either because
// it lost out to the injection budget or because it was part of the floor
// and the floor alone overran the budget (P2-004, P2-005). Named so a
// caller can fold it into the same interrogate.Step vocabulary a read
// refusal already uses (main.go's knowledgeRefusalSteps) — this package
// does not import internal/interrogate itself, for the same reason
// BuildSystemPrompt's doc comment gives: interrogate stays free of every
// sibling import so the package carrying the security properties stays
// reviewable in isolation.
type KnowledgeRefusal struct {
	// Name is the doc's label() — "nodes/<node>/<file>.md" for a per-node
	// doc, the bare filename for a root one — so the operator sees exactly
	// what did not fit, disambiguated the same way the prompt citation is.
	Name string
	// Floor is true when Name was part of the never-evicted floor set and
	// the floor itself could not fit the budget — the one failure mode that
	// is "not an acceptable failure mode" (P2-004) rather than an ordinary
	// budget cut.
	Floor bool
	// Detail is the human-readable reason, ready for an interrogate.Step's
	// Detail field.
	Detail string
}

// KnowledgeSelection is SelectKnowledge's result: the docs ready for
// RenderKnowledge, plus every file a caller should disclose to the operator
// as not having made it in.
//
// Refusals is still empty on the common path, and the reason has changed.
// It used to be that the whole corpus fitted the budget; re-measured
// 2026-09-27 it does not (125.5 KB across 20 files against 96 KB). What
// fits is what one question SELECTS, which is 61.7 KB and 69.2 KB for the
// two questions the load test measures, both with nothing refused. As the
// corpus grows this stops being true question by question rather than all
// at once, and the list is what says so: a caller that drops it is hiding
// what an answer was not written from.
type KnowledgeSelection struct {
	Selected []KnowledgeDoc
	Refusals []KnowledgeRefusal
}

// SelectKnowledge is knowledge-audit.md §7's selection change, and D4 §10's
// three changes wired in: ranked, budget-aware selection (change 1), a
// node key so per-node docs are only ever a candidate for their own node
// (change 2, P2-003), and a visible refusal for anything ranking or the
// budget dropped (change 3, P2-004/P2-005).
//
// node identifies which node's per-node docs are eligible. It MUST be
// resolved by the caller from its own service-side context — the ask's
// mc.Node (main.go's baseContext, itself profile.Container or s.container)
// — and never from interrogate.Request.Node, the model's own tool-call
// field: P2-003 names this exactly ("wiring the selector to the [model's]
// field hands the model a lever on what enters its own next round"). Fixed
// once per question, at the same two call sites (main.go's ask,
// breakglass.go's investigateContinue) that already compute it once from
// req.Question rather than the loop, for the identical reason: a value the
// model could move by naming something in its own output would let it grow
// its own context turn over turn.
//
// Compute this ONCE per question, from the operator's original question
// text, before the interrogative loop's first round — never per round, and
// never from anything a reply says. §7 item 4 is explicit about why: a
// model that could grow its own next-round knowledge by naming a metric in
// its OWN output would be widening its own context, the same class of
// problem SanitizeInjected exists to close for read results, arriving
// through the knowledge door instead. Computing it once also keeps
// BuildSystemPrompt's output byte-identical across every round of the same
// investigation, which is what part 1's cache breakpoint needs to be worth
// anything.
func SelectKnowledge(docs []KnowledgeDoc, question, node string) KnowledgeSelection {
	return selectWithBudget(docs, question, node, Target{}, KnowledgeInjectionBudget)
}

// Target is what a doc's `applies_to` is judged against: this node's fork and
// version, as the service itself discovered them (host.Profile's ImageRepo
// and ImageTag), never anything a model or a request said.
//
// The zero value means "this service does not know what it is running", and
// that case includes every doc rather than excluding it. That is a deliberate
// fail-OPEN, and it is the right direction here for one reason: knowledge
// shapes advice and grants nothing (ADR 0017 decision 3). Excluding on an
// unknown target would silently empty an aggregator's corpus — an aggregator
// has no node to inspect at all — and the failure would look like an Advisor
// that had forgotten everything it was told. A doc that names a fork this
// node is not running is a different matter: that is a known mismatch, and it
// is excluded with a visible refusal.
type Target struct {
	Fork    string // host.Profile.ImageRepo, e.g. "rippleci/xrpld"
	Version string // host.Profile.ImageTag, e.g. "3.2.0"
}

// Known reports whether this target can judge an applies_to at all.
func (t Target) Known() bool { return t.Fork != "" || t.Version != "" }

// applies reports whether a doc's applies_to list covers this target.
//
// An entry matches when every whitespace-separated token in it appears in
// either the fork or the version string: "xrpld" matches
// "xrpllabsofficial/xrpld", "xrpld 3.2" matches that fork at tag 3.2.0, and
// "rippled" matches neither. Substring matching, no version algebra: a
// ">=" mini-language would be a comparison surface with no users today and
// several ways to be subtly wrong. The lint warns on an entry it cannot make
// sense of; nothing here guesses.
func (t Target) applies(list []string) bool {
	if len(list) == 0 || !t.Known() {
		return true
	}
	fork, version := strings.ToLower(t.Fork), strings.ToLower(t.Version)
	for _, entry := range list {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" || e == "*" || e == "any" || e == "all" {
			return true
		}
		all := true
		for _, tok := range strings.Fields(e) {
			if !strings.Contains(fork, tok) && !strings.Contains(version, tok) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// SelectKnowledgeFor is SelectKnowledge with the node's own fork and version
// supplied, so a doc carrying `applies_to` can be filtered against what this
// host actually runs. Every caller inside advisord uses this; SelectKnowledge
// remains for callers (and tests) with no target to offer, and behaves
// identically on a corpus that carries no applies_to — which is all of
// today's.
func SelectKnowledgeFor(docs []KnowledgeDoc, question, node string, t Target) KnowledgeSelection {
	return selectWithBudget(docs, question, node, t, KnowledgeInjectionBudget)
}

// baseName is the filename at the end of a layer-relative path. Selectability
// by filename prefix (metrics-*) has to keep working for a file that has been
// filed under a taxonomy directory.
func baseName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// layerRank orders the four knowledge classes for a name collision — ADR 0017
// decision 1's precedence, most specific first: a note written on the node
// beats one pushed to the fleet, an operator's promoted note beats a pulled
// public one, and both beat what the release shipped.
//
// Per-node docs are their own namespace (label() carries the node, so two
// files named the same for different nodes are never the same citation) and
// so are never actually in collision with the node-agnostic layers. Their
// precedence shows up as scorePerNodeBoost instead, which is what wins them a
// tie for the budget. The rank is stated here anyway because the ordering is
// the ADR's and reading it in one place is worth a line.
// trustRank orders the layers by who curated them, for the budget
// comparator's tie-break — a different question from layerRank's
// same-filename precedence, and a different order: shipped sits ABOVE
// fleet-base here, because a doc written for this product is a better
// equal-match seat-holder than a page pulled from a public repository,
// while for the same FILENAME the deliberately-pulled copy still wins.
func trustRank(d KnowledgeDoc) int {
	if d.Node != "" {
		return 3
	}
	switch d.Layer {
	case LayerFleetLocal:
		return 2
	case LayerFleetBase:
		return 0
	default:
		return 1
	}
}

func layerRank(d KnowledgeDoc) int {
	if d.Node != "" {
		return 3
	}
	switch d.Layer {
	case LayerFleetLocal:
		return 2
	case LayerFleetBase:
		return 1
	default:
		return 0
	}
}

// resolveShadowing keeps one doc per (node, name) — the highest-ranked layer
// — and reports every copy it dropped.
//
// Two rules make this safe rather than merely tidy:
//
// A floor file is never shadowed. floorFiles names the always-sent core
// (P2-004), and if a pushed bundle could replace one of those files by
// filename it would be replacing a guarantee, not a note: the shipped copy
// wins and the pushed one is refused by name. The same reasoning as the
// floor being an explicit named set rather than a filename prefix — nothing
// joins or displaces that set by being called something.
//
// role-policy.md is refused outright in a fleet layer. It is never ranked at
// all in the shipped corpus (advisord reads it whole into every prompt), so a
// pushed copy would not shadow anything — it would simply be injected as
// ordinary knowledge that reads like policy. See RolePolicyFile.
// displaces reports whether a challenger takes the place of the doc already
// held for the same (node, name). A floor filename is answered first and
// answered the same way in both directions: only the shipped copy of a floor
// file ever holds that name.
func displaces(challenger, held KnowledgeDoc) bool {
	if challenger.Node == "" && floorFiles[challenger.Name] {
		return challenger.Layer == LayerShipped
	}
	return layerRank(challenger) > layerRank(held)
}

func resolveShadowing(docs []KnowledgeDoc) ([]KnowledgeDoc, []KnowledgeRefusal) {
	type key struct{ node, name string }
	best := map[key]KnowledgeDoc{}
	order := []key{}
	var refusals []KnowledgeRefusal

	for _, d := range docs {
		if d.Layer != LayerShipped && baseName(d.Name) == RolePolicyFile {
			refusals = append(refusals, KnowledgeRefusal{
				Name: d.label(),
				Detail: d.label() + " was not loaded: " + RolePolicyFile +
					" states what each role may do and is read from the shipped corpus only — a pushed bundle cannot supply it",
			})
			continue
		}
		k := key{d.Node, d.Name}
		prev, seen := best[k]
		if !seen {
			best[k] = d
			order = append(order, k)
			continue
		}
		winner, loser := prev, d
		if displaces(d, prev) {
			winner, loser = d, prev
		}
		best[k] = winner
		detail := loser.label() + " was not used: " + winner.label() + " takes precedence for the same file"
		if winner.Layer == LayerShipped && winner.Node == "" && floorFiles[winner.Name] {
			detail = loser.label() + " was not used: " + winner.label() +
				" is part of the always-sent core and cannot be replaced by a pushed bundle"
		}
		refusals = append(refusals, KnowledgeRefusal{Name: loser.label(), Detail: detail})
	}

	out := make([]KnowledgeDoc, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out, refusals
}

// selectWithBudget is SelectKnowledge's implementation, with the budget
// pulled out as a parameter so a test can exercise ranking and eviction
// against a small budget instead of needing a corpus sized to overrun 96 KB.
// SelectKnowledge itself, and at least one test, exercise the real
// KnowledgeInjectionBudget end to end so P2-005's literal checkable — the
// constant, not a stand-in — is what is actually asserted somewhere.
func selectWithBudget(docs []KnowledgeDoc, question, node string, target Target, budget int) KnowledgeSelection {
	q := strings.ToLower(question)

	type candidate struct {
		doc      KnowledgeDoc
		score    int
		priority bool
	}

	var floor []KnowledgeDoc
	var candidates []candidate

	// Precedence first, ranking second: a file that lost its name to a
	// higher layer never competes for the budget, and says so.
	docs, shadowed := resolveShadowing(docs)

	for _, d := range docs {
		// P2-003's isolation, enforced here rather than trusted to a
		// caller: a per-node doc is never a candidate for any node but its
		// own, whatever the question text says — see the second half of
		// TestSelectKnowledge_QuestionNamingAnotherNodeStillExcludesIt.
		// node == "" (an unresolved node identity) fails this for every
		// per-node doc, which is the fail-closed behaviour a missing
		// identity should have: no per-node doc is ever inferred in.
		if d.Node != "" && d.Node != node {
			continue
		}
		fm, _ := d.meta()
		// applies_to, when the file carries one and this service knows what
		// the node runs. A mismatch is a refusal rather than a silent drop:
		// an operator who wrote a note for the fork they used to run should
		// be able to see why their note stopped being cited.
		if !target.applies(fm.AppliesTo) {
			sel := KnowledgeRefusal{
				Name: d.label(),
				Detail: fmt.Sprintf("%s applies to %s; this node runs %s %s",
					d.label(), strings.Join(fm.AppliesTo, ", "), target.Fork, target.Version),
			}
			shadowed = append(shadowed, sel)
			continue
		}
		// The floor is shipped-corpus only. A pushed file cannot join the
		// set that is never evicted, whatever it is called — see floorFiles.
		if d.Node == "" && d.Layer == LayerShipped && floorFiles[d.Name] {
			floor = append(floor, d)
			continue
		}
		// scorePerNodeBoost: a doc scoped to THIS node (d.Node == node,
		// node non-empty — d.Node == "" already means "for every node") is
		// more specific to the question than an otherwise-identically
		// scored root doc, and must win the tie rather than lose it to
		// label() ordering.
		boost := 0
		if d.Node != "" {
			boost = scorePerNodeBoost
		}
		if d.Layer == LayerFleetLocal {
			boost += scoreFleetLocalBoost
		}
		high := fm.Priority == "high"
		if !isTopicScoped(d, fm) {
			// Core-shaped (root or per-node), not floor: always a
			// candidate, weighted highest among the ranked remainder — D4
			// §10 change 1.
			candidates = append(candidates, candidate{d, scoreCoreWeight + boost, high})
			continue
		}
		if score, matched := matchScore(searchKey(d, fm), q); matched {
			candidates = append(candidates, candidate{d, score + boost, high})
		}
	}

	// Deterministic total order: score descending, then label ascending.
	// Ties are the common case (every core-shaped candidate shares
	// scoreCoreWeight), and an order that depended on os.ReadDir's
	// directory-read order would make BuildSystemPrompt's output vary
	// across restarts with no question-visible reason — defeating the
	// cache breakpoint the same way a question-dependent reorder would.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		// priority: high breaks a tie and only a tie (ADR 0017 decision 2).
		// Deliberately not a score addend: an addend would let an author
		// out-rank a file that matched the question better simply by
		// declaring itself important, which is how every priority field
		// ends up set to high on every file.
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority
		}
		// Curation trust breaks what priority did not (#39): between a
		// shipped doc and a pulled fleet-base page on the same match, the
		// one written for this product boards first. A tie-break and only a
		// tie-break, for the reason priority is: an addend would let a
		// layer out-rank a better match.
		if ti, tj := trustRank(candidates[i].doc), trustRank(candidates[j].doc); ti != tj {
			return ti > tj
		}
		return candidates[i].doc.label() < candidates[j].doc.label()
	})

	sel := KnowledgeSelection{Refusals: shadowed}
	used := 0
	headerCharged := false

	include := func(d KnowledgeDoc, floorMember bool) bool {
		cost := renderedBytes(d)
		if !headerCharged {
			cost += len(knowledgeHeader)
		}
		if used+cost > budget {
			reason := fmt.Sprintf("%s matched but did not fit the %dKB knowledge budget",
				d.label(), budget>>10)
			if floorMember {
				reason = fmt.Sprintf(
					"%s is part of the always-sent core and did not fit the %dKB knowledge budget",
					d.label(), budget>>10)
			}
			sel.Refusals = append(sel.Refusals, KnowledgeRefusal{
				Name: d.label(), Floor: floorMember, Detail: reason,
			})
			return false
		}
		used += cost
		headerCharged = true
		sel.Selected = append(sel.Selected, d)
		return true
	}

	// Floor files count against the budget first, in a fixed order
	// (floorFiles' own iteration is a map, so sort for determinism) — P2-004:
	// "Floor files count against the budget first; if the floor alone
	// exceeds the budget, that is a visible steps[] refusal." Each file is
	// included whole or refused whole — never truncated — so "no truncated
	// core body" holds by construction, not by a length check.
	sort.Slice(floor, func(i, j int) bool { return floor[i].Name < floor[j].Name })
	for _, d := range floor {
		include(d, true)
	}

	for _, c := range candidates {
		include(c.doc, false)
	}

	return sel
}
