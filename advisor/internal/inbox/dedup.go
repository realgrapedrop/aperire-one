package inbox

import (
	"fmt"
	"sort"
	"strings"
)

// The pending-inbox guard, issue #115.
//
// stock-node1's Knowledge panel held five near-identical proposals to
// re-baseline the load_factor alert, written across four days. Every one of
// them was honest work: the alert kept firing on network fee spikes, the
// Advisor kept investigating it, and each investigation reached the same
// conclusion. What was missing is the one thing that makes a queue a queue:
// a check that the answer is already sitting in it. The WAITING badge said
// five and the operator had one decision to make, and those two numbers being
// different is what made the panel worth a little less each time it was
// right.
//
// prompt.go already tells the model to say a proposal is WAITING in the
// Knowledge panel instead of proposing it again (the 2026-08-30 ruling). That
// is the behaviour I want, and it is not a guard. It depends on the model
// remembering, on the conversation still holding the turn the proposal was
// written in, and on nothing having restarted in between. Memory is not a
// mechanism. This is the mechanism, and it lives in Write so it holds for
// every caller rather than for the one that remembered to ask.
//
// WHY A DERIVED KEY AND NOT A SIMILARITY SCORE
//
// proposalrank already has a blunt title-overlap test, and it is right for
// what it does: a false positive there caps a note at rank 2, which costs the
// operator one line of reading. Here a false positive DROPS a note the
// operator never sees. Those two mistakes are not the same size, so this does
// not reuse that machinery and does not score anything. It derives a key by
// exact match against closed vocabularies, and compares keys for equality.
// No threshold, nothing to tune, and the same text always yields the same
// key.
//
// WHY THE MODEL DOES NOT SUPPLY THE KEY
//
// The obvious design is an attribute on the <propose> block. I am not doing
// that, for the reason proposalrank's package doc gives at length: a model
// that authors its own metadata is how #41 happened. A key the model writes
// is a key the model can vary, deliberately or by accident, and the guard
// would be back to depending on the thing it exists to backstop. Everything
// below is computed by the service from text the model wrote for the operator
// to read, which is a different thing from asking it for a field.
//
// FAIL OPEN, ALWAYS
//
// No subject recognised, or no direction recognised, means no key, and no key
// means the note is written. A missed duplicate costs the operator one extra
// line in a queue they are already reading. A false duplicate swallows a
// recommendation nobody ever hears. Given the choice this refuses to be
// clever.

// dedupSubjects is the allow-list of things a proposal can be ABOUT: the
// metric names the interrogative loop already publishes to the model
// (internal/interrogate's prompt guide) plus the four settings the config
// runbook may change (internal/runbook's table).
//
// Written out rather than derived from those two packages on purpose, and
// this is the same call measuredReads makes: importing them would couple the
// write path to a menu that changes for reasons that have nothing to do with
// deduplication, and a name joining this set should be somebody's decision.
// A name that is missing here costs a duplicate, never a dropped note.
var dedupSubjects = map[string]bool{
	// Consensus and ledger.
	"close_time": true, "converge_time": true, "txn_count": true,
	"load_factor": true, "validation_rate": true, "agreement_pct": true,
	// Peers.
	"peer_count": true, "peers_inbound": true, "peers_outbound": true,
	"peers_insane": true, "peer_latency_p50": true, "peer_latency_p90": true,
	// Network and host.
	"rx_bps": true, "tx_bps": true, "tcp_retrans_per_sec": true,
	"cpu_busy_pct": true, "cpu_iowait_pct": true, "mem_used_pct": true,
	"swap_used_pct": true, "nudb_size": true, "rippled_cpu_pct": true,
	"relay_feed_age_s": true,
	// The settings RB-003 may change.
	"online_delete": true, "advisory_delete": true,
	"node_size": true, "ledger_history": true,
}

// dedupDirections is the closed set of things a proposal can ask for, and the
// ORDER is load-bearing: the first canonical direction whose words appear in
// the text wins. Two consequences I want, both deliberate.
//
// An explicit up or down outranks re-baseline, so "re-baseline this: raise it
// to 200" and "raise it to 200" are the same recommendation and collapse
// together, which is the shape #114's five notes actually took.
//
// A proposal naming both directions ("raise the threshold, shorten the hold")
// resolves to up. That is not a judgement about which half matters. It is
// declaration order, and its only job is to make the key a function of the
// text rather than of the word order the model happened to use.
var dedupDirections = []struct {
	canonical string
	words     []string
}{
	// "longer" is deliberately absent, and the test that put it there is why:
	// "load_factor thresholds no longer match the network" is a description
	// of a problem, and it read as a request to lengthen something. Every
	// word here has to be a verb somebody is asking for, not an adverb.
	{"up", []string{
		"raise", "raised", "raising", "increase", "increased", "increasing",
		"higher", "lengthen", "lengthened", "lengthening",
		"widen", "widened", "loosen", "loosened", "relax", "relaxed",
	}},
	{"down", []string{
		"lower", "lowered", "lowering", "decrease", "decreased", "decreasing",
		"reduce", "reduced", "reducing", "shorten", "shortened", "shortening",
		"tighten", "tightened", "narrow", "narrowed",
	}},
	{"rebaseline", []string{
		"rebaseline", "rebaselined", "rebaselining", "recalibrate",
		"recalibrated", "recalibrating", "retune", "retuned", "retuning",
	}},
}

// DedupKey is the identity of one recommendation: which node, about what, and
// which way. Shaped after the alert rules' own dedup_key (subject:severity in
// the read contract) so the two read alike to anyone who has seen one of
// them, with the node in front because a recommendation about a peer's
// load_factor is not the same recommendation as one about this node's.
//
// Empty means "I could not tell what this is", never "this matches nothing".
func DedupKey(node, title, body string) string {
	toks := keyTokens(title + "\n" + recommendation(body))
	if len(toks) == 0 {
		return ""
	}
	subjects := make([]string, 0, 2)
	for t := range toks {
		if dedupSubjects[t] {
			subjects = append(subjects, t)
		}
	}
	if len(subjects) == 0 {
		return ""
	}
	// Sorted so that "load_factor and peer_count" and "peer_count and
	// load_factor" are one key. A proposal naming two metrics is a different
	// recommendation from either of them alone, and keeping both in the key
	// is what keeps it that way.
	sort.Strings(subjects)

	direction := ""
	for _, d := range dedupDirections {
		for _, w := range d.words {
			if toks[w] {
				direction = d.canonical
				break
			}
		}
		if direction != "" {
			break
		}
	}
	if direction == "" {
		return ""
	}
	return fmt.Sprintf("%s|%s:%s", strings.ToLower(strings.TrimSpace(node)),
		strings.Join(subjects, "+"), direction)
}

// recommendation returns the body's "## Recommendation" section, which
// prompt.go requires the model to write and spells out for it. That heading
// is the structured part of a proposal body: it is where the model says what
// should change, as opposed to the summary (what was seen) and the evidence
// (the readings). Scanning the whole body instead would let a value quoted in
// the evidence decide the direction.
//
// A body with no such heading returns empty, and the key is then derived from
// the title alone, which usually yields no direction, and therefore no key,
// and therefore a written note. Fail open, same as everywhere else here.
func recommendation(body string) string {
	lines := strings.Split(body, "\n")
	start := -1
	for i, ln := range lines {
		t := strings.ToLower(strings.TrimSpace(ln))
		if t == "## recommendation" || t == "##recommendation" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "## ") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// keyTokens reduces text to its distinct lowercase words, keeping the
// underscore because every metric name and every config key is written with
// one.
//
// A hyphen is admitted BOTH ways, and the union is the point: the model
// writes "re-baseline" as often as "rebaseline", and "close-time" as often as
// "close_time". Deleting the hyphen catches the first, turning it into an
// underscore catches the second, and doing both costs one extra pass over a
// few hundred bytes. Picking one would have quietly halved the guard's reach.
func keyTokens(s string) map[string]bool {
	s = strings.ToLower(s)
	out := map[string]bool{}
	for _, variant := range []string{
		strings.ReplaceAll(s, "-", ""),
		strings.ReplaceAll(s, "-", "_"),
	} {
		for _, f := range strings.FieldsFunc(variant, func(r rune) bool {
			return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_'
		}) {
			f = strings.Trim(f, "_")
			if f != "" {
				out[f] = true
			}
		}
	}
	return out
}

// DuplicatePendingError is what Write returns instead of a sixth copy of a
// recommendation already waiting for the operator. It carries the note that
// blocked it, because the only useful thing to say in a log line here is
// WHICH file the operator should be looking at.
//
// Refusal, not replacement, and I went looking for the alternative first.
// Revise is the only writer that can rewrite a pending note's body, and it
// stamps revised_by / revised_at with the operator who verified it, so
// writing a supersede through it would put a person's name on a change the
// Advisor made, in a package that keeps operator, OS account and service
// attribution deliberately apart. A new writer that edited the note in place would be
// worse: the operator may have already read it, the queue entry would change
// under them with nothing on the file to say it had, and the note whose id
// they were about to decide on would no longer be the note they read.
//
// So a superseding proposal is refused too, and the loop still closes
// honestly. The operator deciding the pending note, promoting it or
// rejecting it, unblocks the next one immediately, which is the same shape
// as the rejected-before cap: a decision the operator made is what moves the
// queue, not the Advisor's persistence.
type DuplicatePendingError struct {
	// Key is the identity the two notes share.
	Key string
	// Existing is the pending note already holding it. The newest one,
	// because that is the one at the top of the operator's panel.
	Existing Note
}

func (e *DuplicatePendingError) Error() string {
	return fmt.Sprintf("a pending proposal already covers %s: %q (%s)",
		e.Key, e.Existing.Title, e.Existing.Path)
}

// ErrDuplicatePending lets a caller test for this with errors.Is, alongside
// the sentinel comparisons the rest of the package already uses.
var ErrDuplicatePending = fmt.Errorf("a pending proposal already covers this recommendation")

func (e *DuplicatePendingError) Is(target error) bool { return target == ErrDuplicatePending }
