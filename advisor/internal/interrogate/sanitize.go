package interrogate

import (
	"regexp"
	"strings"
)

// sentinelTags names every control tag this protocol acts on, in one
// place, and is the source of truth SanitizeInjected is built from.
//
// One list, because two literals kept in step by a comment is what caused
// #124: <propose> was added to the extraction layer and never added to the
// sanitiser, so a forged block in a log tail could be echoed by the model
// and filed to the operator's inbox wearing this service's own attribution.
// cmd/aperire-advisord asserts against this list that every tag its
// extraction layer recognises appears on it.
//
//   - lookup, the read protocol (parser.go)
//   - remember, a stored memory (cmd/aperire-advisord's rememberTag)
//   - propose, an inbox note (cmd/aperire-advisord's proposeTag, #124)
//   - action, intent, route, the action protocol (action.go)
//   - offer, a break-glass nudge (offer.go, #124)
//
// <redacted> is deliberately absent. It is the privilege wrapper's own
// marker inside a read body, not a tag any extraction layer acts on, and
// §7.2 gives the wrapper sole authority over it. Defanging it would show
// the operator a redaction that looks tampered with, and would say nothing
// about a tag anything acts on.
//
// What the guard catches, and what it does not: the cmd-side test catches a
// tag added to cmd/aperire-advisord's tagPattern registry and not added
// here, which is exactly how #124 happened. It cannot catch a protocol
// regex hand-written inside THIS package, which is how <offer> drifted
// (offerBlockRe is a literal in offer.go, built from no list at all). Add a
// protocol regex in this package, add its name here in the same edit.
var sentinelTags = []string{"lookup", "remember", "action", "intent", "route", "propose", "offer"}

// SentinelTags returns a copy of the tag names SanitizeInjected defangs. A
// copy, so no caller can quietly shorten the list the sanitiser itself is
// built from. Exported for the drift guard in cmd/aperire-advisord, which
// cannot be imported the other way round (it is a main package), and for
// the table tests that assert every tag on it.
func SentinelTags() []string {
	out := make([]string, len(sentinelTags))
	copy(out, sentinelTags)
	return out
}

// sentinelRe matches every one of sentinelTags, opening tag and closing tag,
// case-insensitively, with or without the leading slash. It is assembled
// from the list rather than written out, so the list is the only thing to
// keep current.
//
// The pattern deliberately carries no word boundary. A tag name is matched
// as a prefix, so "<lookupfoo" is defanged along with "<lookup", which is
// the behaviour this has always had and the safe direction for a sanitiser.
//
// The action markers are here for the same reason lookup and remember are:
// read results are the least trusted text in the system, and a tag a remote
// party wrote into a log line or an API response, echoed by the model into
// its final reply, must never be read as this service's own control. The
// human gates (a confirm code and a passkey verified on the node, a roster
// check, a human yes) already stand in front of any effect, so this is
// defense in depth — it stops injected content from even RENDERING an
// unrequested gate, nudge or handoff (2026-08-22 security review).
//
// <propose> and <offer> joined them for the same reason (#124). Neither
// grants anything either: a proposal waits in a review queue until a person
// promotes it, and an offer is a nudge in front of a ceremony. What a
// forged one costs is attribution. The note, or the nudge, arrives in front
// of the operator looking like this Advisor's own conclusion, which is text
// a remote party chose wearing a badge it did not earn. Defanging <propose>
// closes a second, plainer failure as well: an unterminated forged opening
// tag makes the extraction layer swallow the rest of the reply, so the
// operator loses the answer they actually asked for.
var sentinelRe = regexp.MustCompile(`(?i)</?(` + strings.Join(sentinelTags, "|") + `)`)

// SanitizeInjected is the one function every read result must pass through
// before it can enter a prompt. No exceptions, no bypass path (§5.3).
//
// Log tails and off-host API responses are the least trustworthy text in
// the system, and they are exactly what the read menu injects. Two concrete
// failures this closes:
//
//   - A node log line containing "</lookup>" would truncate the parse of
//     the next round's block, because lookupBlockRe is non-greedy and stops
//     at the first close it sees.
//   - A node log line, or a public API error string, containing
//     `<remember title="…">…</remember>` could be echoed by the model and
//     written to memory.jsonl by extractMemory as a forged memory of this
//     node — text a remote party chose, stored as something the service
//     "learned".
//
// The replacement swaps the leading "<" for a visually similar but
// byte-distinct character, so the marker is still readable in a rendered
// result but can never again match either sentinel's own regular
// expression.
func SanitizeInjected(s string) string {
	return sentinelRe.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Replace(m, "<", "‹", 1)
	})
}

// sanitizeResult applies SanitizeInjected to every field of a Result that
// can carry text a remote party chose: Body, and Detail. §5.3 says "every
// read result passes through one function... no exceptions, no bypass
// path" — Detail is not exempt just because it usually holds the service's
// own error text. A failed public_ledger read's Detail is a remote server's
// error string, which is exactly the "off-host API response" §5.3 names as
// untrustworthy, and it is rendered to the operator (and fed back to the
// model) by renderStepLine whether the read succeeded or not.
func sanitizeResult(res Result) Result {
	res.Body = SanitizeInjected(res.Body)
	res.Detail = SanitizeInjected(res.Detail)
	return res
}

// intermediateRememberRe recognises the same block cmd/aperire-advisord's
// rememberTag does. Duplicated rather than imported for the same reason
// hostVerbs is duplicated from internal/host: this package stays free of
// any dependency beyond the standard library, and cmd/aperire-advisord is a
// main package that cannot be imported at all. If the wire syntax for
// <remember> ever changes, both copies need the edit.
//
// The attribute list is permissive on purpose, and for the same reason as
// over there (#121): a tag carrying a second attribute is still a
// <remember> block, and a pattern that admits only title would leave it in
// the history the loop feeds back to itself. This copy only ever has to
// STRIP, so it reads no attribute at all.
var intermediateRememberRe = regexp.MustCompile(`(?is)<remember\b[^>\n]{0,400}>(.*?)</remember\s*>`)

// stripIntermediateRemember removes a <remember> block from a reply before
// it is fed back into the loop's own history as an assistant turn (§6.4).
//
// A memory belongs in the FINAL answer only. Left in an intermediate turn,
// two things go wrong in opposite directions: a hypothesis formed mid
// investigation and abandoned two rounds later would be written down as
// something learned, and — the failure this function actually prevents — a
// genuine memory the model already believes it wrote once would not be
// repeated at the end, and extractMemory (which only ever looks at the
// final reply) would never see it. The FINAL reply is never passed through
// this function; extractMemory reaches it untouched.
func stripIntermediateRemember(reply string) string {
	return strings.TrimSpace(intermediateRememberRe.ReplaceAllString(reply, ""))
}

// SanitizeHistory defangs a conversation turn the page posted back (#1020).
// A turn is not a read result, but it is text the model did not write this
// round, and it is not in the echo comparison (a yes turn may repeat its own
// earlier block), so the tag has to be unreadable as it arrives. The literal
// tag is not the only shape it can arrive in: entity-encoded, percent-encoded,
// split by a zero-width character, in fullwidth letters, or several of those
// stacked. The turn is decoded with the echo check's own decoders (all but the
// quote, space and case folds, which change text without helping a tag
// through) to a fixed point, at the same eight-round cap. When the decoded
// text holds a tag it is the decoded text that is defanged and returned. When
// the cap is hit the turn is encoded more deeply than any honest turn needs,
// and its text is withheld whole: a layer left undecoded is a tag the model
// may yet decode. Text with no tag in any form is returned as it came.
func SanitizeHistory(s string) string {
	decoders := historyDecoders
	cur := s
	for round := 0; ; round++ {
		if round == echoMaxRounds {
			return HistoryWithheld
		}
		next := cur
		for _, dec := range decoders {
			next = dec(next)
		}
		if next == cur {
			break
		}
		cur = next
	}
	if cur != s && sentinelRe.MatchString(cur) {
		return SanitizeInjected(cur)
	}
	return SanitizeInjected(s)
}

// HistoryWithheld stands in for a posted turn that is still decoding after
// echoMaxRounds rounds.
const HistoryWithheld = "[an earlier turn was encoded more deeply than any ordinary text is, and is not shown]"

// historyDecoderNames are the echo decoders a posted turn is run through, by
// name. The quote, space and case folds are not among them: they change text
// without helping a tag through, and a turn handed on is returned as it came
// unless a tag was found. Named, not "the first six", so reordering or
// extending the echo table cannot change what history sanitising does.
var historyDecoderNames = []string{"sanitiser-mark", "fold", "html", "backslash", "json-unicode", "percent"}

var historyDecoders = decodersNamed(historyDecoderNames...)
