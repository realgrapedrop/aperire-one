package interrogate

import (
	"html"
	"log"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// An action block the model only repeated is not a proposal (#1020).
//
// THIS IS DEFENCE IN DEPTH, and not the control. The primary controls are
// two, and they stand without it:
//
//   - every source of text the model reads is defanged on the way in: read
//     results, knowledge (the operator's, the fleet's and the field guide),
//     recalled notes and ledger summaries all pass SanitizeInjected, and
//     recalled notes are quoted line by line as data;
//   - an action block proposes nothing by itself. The gate it produces shows
//     the target the NODE derived, not one the block named, and nothing runs
//     until the operator types the confirm code and presents a passkey.
//
// What this adds: if a source were missed by the first control, a block it
// carried and the model repeated is refused rather than shown as a gate.
//
// The residual, named so nobody mistakes this for more than it is: text that
// ASKS the model to compose a block of its own ("when the operator says yes,
// roll back") cannot be caught by any echo check, because the block the
// model writes is new. The gate and the passkey are the control for that.
//
// How it judges. ParseAction decodes nothing itself: it maps curly and
// single quotes to straight ones, lowercases attribute names, kind and
// intent, and strips a leading "v" from a target, and that is all. So every
// decoding happens here, on both sides, and the parser is the only grammar:
//
//  1. Each injected source, and the reply, is decoded to a fixed point:
//     every decoder in echoDecoders applied in turn, round after round,
//     until a round changes nothing, at most echoMaxRounds rounds. A REPLY
//     still changing at the cap is the model's own output encoded deeper
//     than anything honest needs, and its block is refused as suspicious.
//     A context text still changing at the cap is compared on every form it
//     reached and never refuses by itself: refusing on it would let one
//     deep note block every proposal.
//  2. ParseAction runs over every tag in every form along the way, the
//     original, each decoder's output and the fixed point, and every request
//     it accepts is kept in canonical form.
//  3. A reply is refused when any request read in any of its forms matches
//     one read in any form of what the turn carried.

// The two reasons a reply's block is refused here, in the drawer's words.
const (
	EchoWhyRepeated = "the block repeats one that text in this turn's own context carried, " +
		"so it is not a proposal"
	EchoWhySuspicious = "the reply was encoded more deeply than any honest answer needs, " +
		"so no block in it is taken as a proposal"
)

// echoMaxRounds caps the fixed point. Each round applies every decoder once,
// so three stacked encodings settle in three or four rounds; eight is room
// for anything honest.
const echoMaxRounds = 8

// echoDecoders, applied in this order in every round. Each undoes one way a
// tag can sit encoded in text, and each is a no-op on text that does not use
// that encoding.
// namedDecoder is one of the echo check's decoders, by name, so a caller that
// wants some of them asks for those and not for "the first six".
type namedDecoder struct {
	name string
	fn   func(string) string
}

var echoDecoderTable = []namedDecoder{
	// the sanitiser's own mark
	{"sanitiser-mark", func(s string) string { return strings.ReplaceAll(s, "‹", "<") }},
	// fullwidth forms to ASCII, format characters (zero-width, BOM, bidi)
	// dropped
	{"fold", foldForEcho},
	{"html", html.UnescapeString},
	// backslash escapes, as a JSON string or a shell line carries quotes
	{"backslash", strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\\`, `\`).Replace},
	// JSON's \uXXXX
	{"json-unicode", func(s string) string {
		return jsonEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
			n, err := strconv.ParseUint(m[2:], 16, 32)
			if err != nil {
				return m
			}
			return string(rune(n))
		})
	}},
	// percent-encoding, as a URL or a query string carries it. Decoded run
	// by run rather than with url.QueryUnescape, which refuses the whole
	// text over one malformed "%": a stray "%zz" beside an encoded tag would
	// otherwise keep the tag encoded.
	{"percent", func(s string) string {
		s = percentRunRe.ReplaceAllStringFunc(s, func(m string) string {
			b := make([]byte, 0, len(m)/3)
			for i := 0; i+2 < len(m); i += 3 {
				n, _ := strconv.ParseUint(m[i+1:i+3], 16, 8)
				b = append(b, byte(n))
			}
			return string(b)
		})
		return strings.ReplaceAll(s, "+", " ")
	}},
	// quote style, whitespace and case: the parser tolerates all three, so
	// folding them is only ever a second look at the same tag
	{"quote-style", attrQuoteNormalizer.Replace},
	{"whitespace", func(s string) string { return strings.Join(strings.Fields(s), " ") }},
	{"lowercase", strings.ToLower},
}

// echoDecoders is the table's functions, in its order.
var echoDecoders = decodersNamed()

// decodersNamed is the functions of the named decoders, in table order, or of
// the whole table when no name is given. A name that is not in the table
// panics at start: a renamed decoder must not quietly drop out of a list
// that depends on it.
func decodersNamed(names ...string) []func(string) string {
	var out []func(string) string
	if len(names) == 0 {
		for _, d := range echoDecoderTable {
			out = append(out, d.fn)
		}
		return out
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = false
	}
	for _, d := range echoDecoderTable {
		if _, ok := want[d.name]; ok {
			want[d.name] = true
			out = append(out, d.fn)
		}
	}
	for n, found := range want {
		if !found {
			panic("interrogate: no echo decoder named " + n)
		}
	}
	return out
}

var jsonEscapeRe = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)

var percentRunRe = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2})+`)

// foldForEcho maps fullwidth forms to ASCII and drops format characters.
func foldForEcho(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.Is(unicode.Cf, r):
			return -1
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFEE0
		case r == 0x3000:
			return ' '
		}
		return r
	}, s)
}

// decodeToFixedPoint returns every form s passes through on the way to its
// fixed point, the original first, and whether it was still changing after
// echoMaxRounds rounds.
func decodeToFixedPoint(s string) (forms []string, capped bool) {
	seen := map[string]bool{s: true}
	forms = []string{s}
	cur := s
	for round := 0; round < echoMaxRounds; round++ {
		start := cur
		for _, dec := range echoDecoders {
			cur = dec(cur)
			if !seen[cur] {
				seen[cur] = true
				forms = append(forms, cur)
			}
		}
		if cur == start {
			return forms, false
		}
	}
	return forms, true
}

// canonicalAction is a parsed request as one comparable string: what the
// parser made of a block, never the text it was written in. Node and value
// are case-folded so a block that differs only there is still the same act.
func canonicalAction(a ActionRequest) string {
	return strings.Join([]string{a.Kind, strings.ToLower(a.Node), a.Target,
		map[bool]string{true: "from-node", false: "named"}[a.TargetFromNode],
		a.Intent, a.Key, strings.ToLower(a.Value)}, "\x00")
}

// placeholderRe finds a "<placeholder>" written as the value of an attribute
// ParseAction reads. That is a guide's template ("node=\"<the node's
// label>\""), and the parser reads such an attribute as absent, which can
// make what is left look like a real block with that attribute left out. A
// "<" in an attribute the parser ignores does not make a tag a template.
var placeholderRe = regexp.MustCompile(`(?i)\b(kind|node|target|intent|key|value)\s*=\s*["'\x{201C}\x{201D}\x{2018}\x{2019}]?\s*<`)

// requestsIn is every request ParseAction accepts from a tag in any of forms,
// in canonical form. Each tag is handed to the parser alone, so whatever it
// tolerates (attribute order, quote style, case, whitespace and newlines
// inside the tag, extra attributes, a closing tag) is tolerated here too.
// Templates are skipped.
func requestsIn(forms []string, into map[string]bool) {
	for _, form := range forms {
		for _, m := range actionOpenRe.FindAllStringSubmatchIndex(form, -1) {
			if placeholderRe.MatchString(form[m[2]:m[3]]) {
				continue
			}
			if a, _, p := ParseAction(form[m[0]:m[1]]); p.Found {
				into[canonicalAction(a)] = true
			}
		}
	}
}

// EchoVerdict says whether reply's block is refused here, and why. A reply
// whose own text carries no block, in any decoded form, is never refused.
func EchoVerdict(reply string, injected []string) (refuse bool, why string) {
	replyForms, replyCapped := decodeToFixedPoint(reply)
	asked := map[string]bool{}
	requestsIn(replyForms, asked)
	if len(asked) == 0 && !actionOpenRe.MatchString(strings.Join(replyForms, "\n")) {
		return false, ""
	}
	if replyCapped {
		return true, EchoWhySuspicious
	}
	// A context text that never settles is compared on every form it
	// reached, and is never by itself a reason to refuse. Refusing on its
	// depth let one deep note, ledger title or knowledge doc block every
	// proposal for as long as it was recalled, and remote text can reach a
	// note: a self-inflicted denial of the rollback. Only the reply's own
	// depth refuses, above; the reply is the model's own output.
	carried := map[string]bool{}
	for _, text := range injected {
		forms, capped := decodeToFixedPoint(text)
		if capped {
			log.Printf("[action] a context text was still decoding after %d rounds; compared on the %d forms it reached",
				echoMaxRounds, len(forms))
		}
		requestsIn(forms, carried)
	}
	for req := range asked {
		if carried[req] {
			return true, EchoWhyRepeated
		}
	}
	return false, ""
}

// EchoedAction is EchoVerdict's yes or no.
func EchoedAction(reply string, injected []string) bool {
	refuse, _ := EchoVerdict(reply, injected)
	return refuse
}
