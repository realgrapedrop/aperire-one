package interrogate

import (
	"fmt"
	"regexp"
	"strings"
)

// lookupBlockRe extracts a fenced <lookup>[...]</lookup> block, mirroring
// the house convention already in cmd/aperire-advisord/main.go's
// rememberRe: a fenced text marker rather than provider-native tool calls,
// because model.Config spans two API shapes and local runners and this is
// the one idiom that survives all of them unchanged (§5.1's trade-off).
var lookupBlockRe = regexp.MustCompile(`(?is)<lookup>\s*(\[.*?\])\s*</lookup>`)

// anyLookupOpenRe finds an opening tag whether or not it is ever closed —
// used to tell "no lookup at all" (the loop's normal exit) apart from "a
// lookup was attempted but never closed" (malformed, §5.4).
var anyLookupOpenRe = regexp.MustCompile(`(?is)<lookup>`)

// anyLookupCloseRe finds a closing tag whether or not it was ever paired
// with a matched opening one. Without checking for this separately, a
// reply whose opening tag was lost — dropped by the model mid-format-drift,
// or by something upstream — reads as an ordinary final answer: the request
// array and the stray "</lookup>" are handed back to the operator verbatim,
// and nothing ever reaches a Menu. This is the exact shape one operator
// transcript recorded (§5.4).
var anyLookupCloseRe = regexp.MustCompile(`(?is)</lookup>`)

// fencedBlockRe finds a Markdown code fence and captures what is inside it.
// The language tag, if any, is ignored: a model told to "put it in a block"
// reaches for ```json as readily as for a bare fence (#1092).
var fencedBlockRe = regexp.MustCompile("(?s)```[A-Za-z]*[ \\t]*\\r?\\n(.*?)```")

// lookupSpan is one read request found in a reply: where it sits, so it can
// be cut out of what is shown, and the JSON array it carries.
type lookupSpan struct {
	start, end int
	json       string
}

// readArray reports whether text is a JSON array of read requests, and the
// array's text trimmed. The test is deliberately narrow: every entry has to
// be an object with a non-empty string "read". A fence holding some other
// array, a list of numbers or a block of config, is an answer and not a
// request, and "why" is not part of the test: a request that omits it is
// refused by the normal path with a step the operator can read, where
// requiring it here would show the block raw.
func readArray(text string) (string, bool) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return "", false
	}
	raws, err := decodeLookupBlock(t)
	if err != nil || len(raws) == 0 {
		return "", false
	}
	for _, r := range raws {
		if r.Read == "" {
			return "", false
		}
	}
	return t, true
}

// untaggedLookups finds read requests a model wrote without the <lookup>
// tag: an array of reads inside a code fence, or a bare array that is the
// whole reply (#1092). Both are the same request the tagged form carries,
// and a reply made only of one must not reach the operator as an answer.
// It is consulted only when the reply has no <lookup> marker at all.
func untaggedLookups(reply string) []lookupSpan {
	var out []lookupSpan
	for _, m := range fencedBlockRe.FindAllStringSubmatchIndex(reply, -1) {
		if arr, ok := readArray(reply[m[2]:m[3]]); ok {
			out = append(out, lookupSpan{start: m[0], end: m[1], json: arr})
		}
	}
	if len(out) > 0 {
		return out
	}
	if arr, ok := readArray(reply); ok {
		out = append(out, lookupSpan{start: 0, end: len(reply), json: arr})
	}
	return out
}

// maxTokensCutoffMarker is the exact fragment model.Ask appends when a
// provider's stop_reason is max_tokens (internal/model/model.go). Its
// presence means everything after the point of truncation — including a
// <lookup> block that happens to look complete — cannot be trusted: the
// model may have been mid-way through a longer or better-formed request
// when the provider cut it off. §5.4 treats this the same as an unclosed
// tag: malformed, not a request.
const maxTokensCutoffMarker = "cut off here"

// PreDispatchRefusal is one entry that never reached a Menu at all: the
// read name was not recognised, a parameter was out of range, "why" was
// missing, or the reply carried a second <lookup> block. Recorded with the
// same honesty as a Menu-performed read, because a refusal decided by the
// parser is still a refusal the operator is owed (§7).
type PreDispatchRefusal struct {
	Read   string
	Why    string
	Reason string
	// Node names the fleet peer this refusal is ABOUT, when there is one,
	// #59. Set only where a real registered node was named and could not be
	// read from here, so the round's fleet-completeness check counts it as a
	// peer that was asked and did not answer. Left empty for a name nobody
	// registered and for an ambiguous one: there is no node there, and
	// carrying the asker's string into a fleet coverage line would report a
	// host that does not exist as one that stayed silent.
	Node string
}

// ParseOutcome is what came out of trying to read a <lookup> block from one
// model reply.
type ParseOutcome struct {
	// CleanReply is the reply with the (first, served) lookup block
	// removed. Prose outside the block in a lookup-bearing reply is not
	// shown to the operator (§5.1) — this is what a caller may display;
	// the loop feeds the model's own original reply back into history for
	// continuity, per §6.4.
	CleanReply string

	// Requests are entries that parsed and passed structural validation,
	// in order, ready to be dispatched to a Menu.
	Requests []Request

	// PreDispatch carries one entry for every request rejected before
	// dispatch.
	PreDispatch []PreDispatchRefusal

	// Malformed is true when nothing in the reply constituted a servable
	// request at all: unparseable JSON, or an opening tag with no close
	// (whether from a genuine mistake or a max_tokens cut-off). Per §5.4
	// this costs a round and spends no read budget.
	Malformed bool
	// MalformedReason is the sentence handed back in the corrective round.
	MalformedReason string

	// HasBlock is true whenever the reply carried any <lookup> marker at
	// all, closed or not — including the cut-off case, where a "<lookup"
	// substring may or may not be present but the reply is still not a
	// plain final answer. A reply with HasBlock == false and
	// Malformed == false is the loop's normal exit: the answer is final.
	HasBlock bool
}

// ParseLookup extracts and validates the (at most one, ever served)
// <lookup> block from a model reply, against no fleet roster at all — every
// existing caller and test that has never heard of a fleet peer. Node is
// still shape-checked; there is simply nothing it can ever match, so any
// non-empty Node is refused, which is exactly today's single-node
// behaviour. Loop.Run uses ParseLookupWithNodes instead, with whatever
// roster this question's Loop was built with.
func ParseLookup(reply string) ParseOutcome {
	return ParseLookupWithNodes(reply, nil)
}

// ParseLookupWithNodes is ParseLookup with a fleet roster to validate a
// request's Node field against — see validateRequest's own doc for why the
// roster is a parameter here rather than something this package reads for
// itself.
func ParseLookupWithNodes(reply string, validNodes map[string]bool) ParseOutcome {
	return ParseLookupWithRoster(reply, validNodes, Roster{})
}

// ParseLookupWithRoster is ParseLookupWithNodes with the fleet ROSTER the
// host this question was asked on holds (#59), which is a wider set than
// validNodes, and deliberately so. validNodes is what this process can
// READ; the roster is what this host knows EXISTS, and a node in the second
// and not the first is a real state with its own sentence ("registered here,
// cannot be read from here") rather than a name nobody recognises.
//
// A zero Roster is every caller that has no roster to give, and behaves
// exactly as ParseLookupWithNodes always did.
func ParseLookupWithRoster(reply string, validNodes map[string]bool, roster Roster) ParseOutcome {
	if strings.Contains(reply, maxTokensCutoffMarker) {
		return ParseOutcome{
			HasBlock:        strings.Contains(reply, "<lookup"),
			Malformed:       true,
			MalformedReason: "the reply was cut off before it finished (max_tokens); treating anything after the cut as unreliable and asking again",
			CleanReply:      reply,
		}
	}

	var spans []lookupSpan
	for _, m := range lookupBlockRe.FindAllStringSubmatchIndex(reply, -1) {
		spans = append(spans, lookupSpan{start: m[0], end: m[1], json: reply[m[2]:m[3]]})
	}
	if len(spans) == 0 {
		if anyLookupOpenRe.MatchString(reply) {
			return ParseOutcome{
				HasBlock:        true,
				Malformed:       true,
				MalformedReason: "a <lookup> block was opened but never closed — the reply may have been cut off mid-block; ask again with one complete block",
				CleanReply:      reply,
			}
		}
		if anyLookupCloseRe.MatchString(reply) {
			return ParseOutcome{
				HasBlock:        true,
				Malformed:       true,
				MalformedReason: "a </lookup> closing tag was found with no opening <lookup> tag before it — the reply may have dropped the opening tag; ask again with one complete <lookup>...</lookup> block",
				CleanReply:      reply,
			}
		}
		spans = untaggedLookups(reply)
		if len(spans) == 0 {
			// No lookup marker anywhere: the normal exit.
			return ParseOutcome{CleanReply: reply}
		}
	}

	first := spans[0]
	jsonText := first.json
	clean := strings.TrimSpace(reply[:first.start] + reply[first.end:])

	out := ParseOutcome{HasBlock: true, CleanReply: clean}

	raws, err := decodeLookupBlock(jsonText)
	if err != nil {
		out.Malformed = true
		out.MalformedReason = fmt.Sprintf("the <lookup> block was not valid JSON: %v", err)
		return out
	}

	for _, raw := range raws {
		req, ref, ok := validateRequest(raw, validNodes, roster)
		if !ok {
			out.PreDispatch = append(out.PreDispatch, PreDispatchRefusal{
				Read: raw.Read, Why: raw.Why, Reason: ref.Reason, Node: ref.Node,
			})
			continue
		}
		out.Requests = append(out.Requests, req)
	}

	if len(spans) > 1 {
		out.PreDispatch = append(out.PreDispatch, PreDispatchRefusal{Reason: "only one lookup block per reply"})
	}

	return out
}

// residualLookupTagRe matches a bare <lookup> or </lookup> tag on its own —
// not the fenced block lookupBlockRe already strips, but a fragment of one
// that reached this point anyway. It is the belt behind ParseLookup's own
// detection (§5.4): every reply Loop.Run is about to hand back to the
// operator is checked against this, independent of and after everything
// above, so a shape the parser was not taught to recognise still cannot
// surface as a stray tag rather than prose.
var residualLookupTagRe = regexp.MustCompile(`(?is)</?lookup\s*>`)

// StripResidualLookupTags removes any bare <lookup>/</lookup> fragment from
// a reply and reports whether it found one. Exported so a caller other than
// this package's own Loop (a future one, or a test) can apply the same
// belt without re-deriving the pattern.
func StripResidualLookupTags(s string) (cleaned string, stripped bool) {
	if !residualLookupTagRe.MatchString(s) {
		return s, false
	}
	return strings.TrimSpace(residualLookupTagRe.ReplaceAllString(s, "")), true
}
