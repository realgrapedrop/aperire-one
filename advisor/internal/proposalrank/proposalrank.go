// Package proposalrank grades one knowledge proposal from the record of the
// investigation that produced it.
//
// THE RANK IS COMPUTED FROM WHAT THE INVESTIGATION DID, NOT FROM WHAT THE
// MODEL CLAIMS. Nothing in this package reads the note's body, its tone, its
// length or any self-assessment inside it. A model that rates its own note is
// the failure this exists to stop: on 2026-08-13 an Advisor proposed "this
// aggregator has no swap" — a host fact it never read — the note read
// confidently, it was promoted in good faith, and it poisoned the fleet
// (issue #41). A self-assigned score would have rated that note highly. The
// investigation's own record would not have: it contained no successful host
// read at all.
//
// So there are exactly three inputs, and all three are the service's or the
// operator's — never the model's:
//
//   - the steps the interrogative loop recorded for the question, each one
//     written by the service after it performed (or refused) a read
//   - the inbox's own history, which is where a note the operator already
//     rejected leaves its mark
//   - whether an operator verified this note against the node, which is an
//     act they performed and the service witnessed, not a claim in a body
//
// The promise the caps encode:
//
//   - an INFERRED proposal can never rank above 2, however it reads. There is
//     no body a model can write that lifts it, and no operator click either:
//     verifying against an investigation that measured nothing verifies
//     nothing.
//   - a title the operator has already rejected can never rank above 2 either,
//     measured or not. They said no once; a re-proposal arrives as a footnote,
//     not as a decision waiting to be made again.
package proposalrank

import (
	"strings"

	"aperire-advisor/internal/inbox"
	"aperire-advisor/internal/interrogate"
)

// measuredReads is the allowlist, written out rather than derived, because
// the derivation is where this goes wrong. internal/interrogate's menu holds
// fifteen read names; four of them (restart_assessment, upgrade_assessment,
// config_assessment, rollback_assessment) are the runbook gates' own
// summaries rather than a reading of anything, and a rule of "any step that
// succeeded" would let one of those corroborate a claim about swap.
//
// Everything in this set returns a measurement: this node's records through
// the dashboard read API, a privileged probe of the host, or the public XRPL
// APIs. If a read is added to the menu it does not join this set by default —
// somebody has to decide it measures something.
var measuredReads = map[string]bool{
	interrogate.ReadHost:              true,
	interrogate.ReadMetricRecent:      true,
	interrogate.ReadMetricHistory:     true,
	interrogate.ReadNodeLedgers:       true,
	interrogate.ReadAgreementWindow:   true,
	interrogate.ReadMissedLedgers:     true,
	interrogate.ReadAlerts:            true,
	interrogate.ReadFiring:            true,
	interrogate.ReadPublicLedger:      true,
	interrogate.ReadPublicLedgerRange: true,
	interrogate.ReadPublicValidator:   true,
}

// Verdict is what the service writes onto the note.
type Verdict struct {
	Provenance string // inbox.ProvenanceMeasured | inbox.ProvenanceInferred
	Rank       int    // inbox.RankMin .. inbox.RankMax
	// Reads is the count the rank was computed from, kept for the log line
	// and for anyone reading a decision back later. Not persisted.
	Reads int
	// RejectedBefore records that the cap was applied because the operator
	// has already said no to a note like this one.
	RejectedBefore bool
}

// Input is everything Score grades one proposal from. A struct rather than
// positional arguments because of the field added last: OperatorVerified is
// the only input that can reach rank 5, and a caller passing it by accident in
// the fourth position of a call is not a mistake this package should be able
// to make quietly.
type Input struct {
	// Steps is the investigation record for the question that produced (or
	// verified) the note — interrogate.Outcome.Steps, or the same record read
	// back out of the progress store.
	Steps []interrogate.Step
	// Title is the proposal's own title, which is what the rejected-before
	// cap matches on.
	Title string
	// Prior is this inbox's existing notes — every status, not only the
	// rejected ones, so the caller has nothing to filter and nothing to get
	// wrong.
	Prior []inbox.Note
	// OperatorVerified says an operator ran an investigation against this
	// node, read what it measured, and folded the result into the note.
	//
	// The service still counts the readings itself: this flag is the
	// operator's ACT, and Steps is what that act was performed against.
	// Together they are the only route to rank 5. Alone it lifts nothing —
	// see the zero-reads branch below, which is the anti-#41 ceiling and
	// holds against a verification of an investigation that read nothing.
	OperatorVerified bool
}

// Score grades one proposal.
func Score(in Input) Verdict {
	v := Verdict{
		Provenance:     inbox.ProvenanceInferred,
		Rank:           inbox.RankMin,
		Reads:          countMeasured(in.Steps),
		RejectedBefore: rejectedBefore(in.Title, in.Prior),
	}

	if v.Reads == 0 {
		// The anti-#41 ceiling. Two, and only two, whatever the note says
		// about itself: an assertion nobody verified is worth a glance and
		// no more. One if this argument has already been had.
		//
		// OperatorVerified is deliberately not consulted here. An operator
		// who verifies a note against an investigation that measured nothing
		// has confirmed nothing, and a rank that said otherwise would be the
		// #41 failure with a second signature on it.
		if v.RejectedBefore {
			return v
		}
		v.Rank = 2
		return v
	}

	v.Provenance = inbox.ProvenanceMeasured
	// Measured but already rejected: the readings do not reopen a decision
	// the operator made. Capped at the inferred ceiling on purpose — the
	// operator's "no" outranks the Advisor's evidence, because they may have
	// rejected it knowing something the readings cannot show.
	//
	// This cap is the OUTER one, and it outranks OperatorVerified too. The
	// two are not in conflict as often as they look: verifying a note the
	// operator already rejected is worth doing, and the card says what came
	// of it ("measured, and still ranked low"). What it must not do is walk a
	// rejected claim back to the top of the queue one investigation at a time.
	if v.RejectedBefore {
		v.Rank = 2
		return v
	}
	v.Rank = 3
	if v.Reads >= 3 {
		// Corroboration, not volume: the reads are counted distinct, so
		// three here means three different things were measured, not one
		// thing measured three times.
		v.Rank++
	}
	if in.OperatorVerified {
		// The top of the scale, and the only thing that reaches it. Rank 4 is
		// what the service can establish on its own: several readings agree
		// with what the note says. Five is a person having checked, against
		// this node, and kept the result — which is a stronger claim than any
		// number of corroborating reads, because the operator is who the rank
		// exists to inform. Set rather than incremented: reaching 5 must not
		// depend on how many reads the verifying question happened to make.
		v.Rank = inbox.RankMax
	}
	if v.Rank > inbox.RankMax {
		v.Rank = inbox.RankMax
	}
	return v
}

// countMeasured counts the DISTINCT successful measured reads in a record.
//
// Two judgement calls, both of them in the direction of not overstating:
//
//   - StatusSkippedCached counts. It means the service already held that
//     reading — either it performed it earlier in the same question, or
//     main.go seeded it before the loop started (the named-ledger and
//     validator-key lookups). Only a SUCCESSFUL read is ever cached or
//     seeded, so a cache hit is a measurement that happened, not one that
//     was skipped. Refused and failed steps count for nothing: main.go
//     appends a synthetic refused step to every record whose host budget ran
//     out, and a spent budget is the opposite of a measurement.
//   - identity is read + node + params, so the model asking twice for the
//     same thing corroborates nothing, and a peer's metric_recent is a
//     different reading from this node's.
func countMeasured(steps []interrogate.Step) int {
	seen := map[string]bool{}
	for _, s := range steps {
		if !measuredReads[s.Read] {
			continue
		}
		if s.Status != interrogate.StatusOK && s.Status != interrogate.StatusSkippedCached {
			continue
		}
		seen[s.Read+"|"+s.Node+"|"+s.Params] = true
	}
	return len(seen)
}

// rejectedBefore answers whether the operator has already turned down a note
// like this one. Titles only: the body of a re-proposal is rewritten every
// time (that is what makes it feel new), and the title is what the operator
// read when they said no.
func rejectedBefore(title string, prior []inbox.Note) bool {
	want := words(title)
	if len(want) == 0 {
		return false
	}
	for _, p := range prior {
		if p.Status != inbox.StatusRejected {
			continue
		}
		if similar(want, words(p.Title)) {
			return true
		}
	}
	return false
}

// similar is a deliberately blunt overlap test: how much of the SHORTER
// title the two share. Blunt in the safe direction — a false positive caps a
// note at 2, which costs the operator one line of reading, while a false
// negative hands them a note they have already rejected as if it were new.
func similar(a, b map[string]bool) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	shared := 0
	for w := range a {
		if b[w] {
			shared++
		}
	}
	shorter := len(a)
	if len(b) < shorter {
		shorter = len(b)
	}
	return shared*10 >= shorter*7
}

// words reduces a title to its distinct significant words: lowercased,
// punctuation dropped, and the handful of filler words that carry no meaning
// removed so "the swap on this host" and "swap on host" still meet.
func words(s string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(f) < 2 || filler[f] {
			continue
		}
		out[f] = true
	}
	return out
}

var filler = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "but": true, "by": true, "for": true, "from": true, "has": true,
	"in": true, "is": true, "it": true, "its": true, "no": true, "not": true,
	"of": true, "on": true, "or": true, "the": true, "this": true, "to": true,
	"was": true, "with": true,
}
