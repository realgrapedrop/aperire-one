package main

import (
	"regexp"
	"strings"
)

// The yes turn's own words, checked by the service (#1044).
//
// The guide tells the model that the operator's yes asks for the gate and
// approves nothing. That is a request, and a model can ignore it. On a lab
// validator (2026-10-12) a rollback's yes turn opened "Approved, rolling
// <node> back" 39 seconds before the passkey, above a gate still waiting for
// one. So when a reply comes back WITH a gate, the service reads it: a
// sentence that opens by claiming the act is approved or under way is
// replaced with one that says what is true.
//
// Narrow on purpose: only an explicit claim is touched, because a caution
// that disappears just above the gate is worse than a claim that stays
// (PR #1049 re-review). The claims it rewrites:
//   - a sentence that opens "Approved", "Confirmed" or "Authorised", also
//     behind a label ("FINDING: Approved ...", "**Finding** Approved ...")
//     or an acknowledgement ("OK, ...");
//   - the act as a bare present participle that names what it is doing to,
//     and says nothing else: "Rolling validator1 back to 3.4.1 now.",
//     "Restarting validator1 now.". Closed on purpose, a sentence with any
//     other word in it is not this;
//   - the act in progress with a subject: "I am rolling ...", "the node is
//     now restarting", "we're upgrading";
//   - "has been approved", or the act itself has started ("the rollback has
//     started").
// Everything else stays, cautions above all: "Rolling back to 3.3.0 takes
// the node off the network", "Upgrading now is not advised", "Restarting now
// would land inside a rotation", "a store rotation has started". What it
// cannot catch, a claim worded some other way, the gate itself still
// answers: nothing runs until the operator types the confirm code and
// presents a passkey.

// yesTurnCorrection replaces a premature claim. It says only what is true
// of every gate the moment it is drawn.
const yesTurnCorrection = "Nothing is approved or under way yet: the gate below waits for your " +
	"confirm code and passkey, and nothing changes until you approve it."

var (
	// A sentence that opens with a claim of approval.
	claimDone = regexp.MustCompile(`(?i)^(approved|confirmed|authori[sz]ed|approval\s+(received|granted|given|confirmed))\b`)
	// The act first, then approved: "Rollback approved.", "The rollback is
	// approved", "Restart has been confirmed". Anchored at the sentence's
	// start and with no room for a "not" between, so the correction's own
	// "Nothing is approved" and a caution such as "The rollback is not
	// approved until ..." are not this.
	claimActApproved = regexp.MustCompile(`(?i)^(?:the\s+)?(?:rollback|restart|upgrade|change)\s+(?:is\s+|has\s+been\s+|was\s+)?(?:now\s+)?(?:approved|confirmed|authori[sz]ed)\b`)
	// The first word of a sentence that is only "done" or "started".
	claimDoneWord = regexp.MustCompile(`(?i)^(?:done|started|underway|under way)\s*[.!]+\s*$`)
	// "I'll roll it back now": the act promised before the gate is approved.
	claimWillAct = regexp.MustCompile(`(?i)\b(?:i'll|i will|i'm going to|let me)\s+(?:now\s+)?(?:roll|restart|upgrade|apply)\b`)
	// A conditional label ("Once you approve:", "If you say yes:") describes
	// what follows approval, and the claim patterns do not read past it.
	conditionalLabelRe = regexp.MustCompile(`(?i)\b(?:once|if|when|after|before|until|unless|should|would)\b`)
	// What may stand in front of a claim on its sentence without making it
	// something else: a label ("FINDING:", "**Finding**", "**Finding:**")
	// and an acknowledgement ("OK,", "Got it -"). Stripped before the claim
	// patterns look, never from the text that is kept.
	labelRe = regexp.MustCompile(`^(?:[*_]{1,2}[^*_\n]{1,24}[*_]{1,2}:?|[A-Za-z][A-Za-z ]{0,23}[*_]{1,2}:?|[A-Za-z][A-Za-z '\x{2019}]{0,23}:)\s*`)
	ackRe   = regexp.MustCompile(`(?i)^(?:ok(?:ay)?|got it|understood|done|yes|sure|alright|will do|on it|great|good|perfect|thanks|thank you|noted|right|absolutely|certainly|of course)\b[\s,.:;!\x{2014}\x{2013}-]*`)
	// "Approved" read after a label counts only as a claim when a stop, dash
	// or comma follows it ("FINDING: Approved." or "Approved,"), not when a
	// noun does ("Note: approved amendments ...").
	claimDoneAfterLabel = regexp.MustCompile(`(?i)^(?:approved|confirmed|authori[sz]ed)\s*(?:[.,!:;\x{2014}\x{2013}-]|$)`)
	// The sentence's first word when it is the act as a participle.
	participleRe = regexp.MustCompile(`(?i)^(rolling|restarting|upgrading|applying|starting|proceeding|initiating|rolled|restarted|upgraded|applied)\s+(.+?)\s*[.!]+\s*$`)
	// What a bare participle's sentence may end with: when, and to what.
	adverbRe = regexp.MustCompile(`(?i)\s+(now|again|shortly|immediately|right\s+away)$`)
	targetRe = regexp.MustCompile(`(?i)\s+(to|onto)\s+(the\s+)?(official\s+)?[\w./:@-]*\d[\w./:@-]*(\s+(image|release|version|build))?$`)
	// The sentence ends on "now", "right away" or "immediately".
	trailingAdverbRe = regexp.MustCompile(`(?i)\s+(now|immediately|right\s+away)\s*[.!]*\s*$`)
	// The act claimed as in progress, with its subject: "I'm rolling",
	// "it is now restarting". A bare gerund ("Rolling back to 3.3.0 takes
	// ...") is how a caution opens, and is not this.
	claimUnderWay = regexp.MustCompile(`(?i)\b(i am|i'm|we are|we're|it is|it's|is|are)\s+(now\s+)?(rolling|restarting|upgrading|applying)\b`)
	// Approval or the act itself, claimed as done.
	claimHas = regexp.MustCompile(`(?i)\b(has|have)\s+been\s+approved\b|\b(the\s+)?(rollback|restart|upgrade|change|it)\s+has\s+(been\s+)?(approved|started)\b`)
	// One sentence, with what ends it and the space after. It ends at
	// punctuation followed by a space or the end of the line, so a version
	// such as 3.4.1 stays inside its sentence.
	sentenceRe = regexp.MustCompile(`.+?(?:[.!?]+(?:\s+|$)|$)`)
	// What may sit in front of a sentence on its line: indentation, a list
	// marker, a quote marker.
	linePrefixRe = regexp.MustCompile(`^(\s*(?:#{1,6}\s+|[-*>]\s+)?)`)
)

// claimsPrematurely says whether one sentence claims the act approved or
// under way. The label and acknowledgement in front of it are looked past.
func claimsPrematurely(t string) bool {
	if claimUnderWay.MatchString(t) || claimHas.MatchString(t) || claimWillAct.MatchString(t) ||
		claimActApproved.MatchString(t) || claimDoneWord.MatchString(t) {
		return true
	}
	rest := t
	labelled := false
	for i := 0; i < 2; i++ {
		if loc := labelRe.FindStringIndex(rest); loc != nil && loc[1] < len(rest) {
			if conditionalLabelRe.MatchString(rest[:loc[1]]) {
				// What follows approval is described, not claimed: the act
				// as a participle is a caution here. But "Approved" itself
				// right after the label is still the claim.
				after := strings.TrimLeft(rest[loc[1]:], "*_ ")
				// "now", "right away" and "immediately" make it the act under
				// way and not a description of what follows approval.
				return claimDoneAfterLabel.MatchString(after) || claimActApproved.MatchString(after) ||
					(trailingAdverbRe.MatchString(after) && bareParticipleClaim(after))
			}
			rest, labelled = rest[loc[1]:], true
		}
		if loc := ackRe.FindStringIndex(rest); loc != nil && loc[1] < len(rest) {
			rest = rest[loc[1]:]
		}
	}
	rest = strings.TrimLeft(rest, "*_ ")
	if claimActApproved.MatchString(rest) || claimWillAct.MatchString(rest) {
		return true
	}
	if labelled {
		return claimDoneAfterLabel.MatchString(rest) || bareParticipleClaim(rest)
	}
	return claimDone.MatchString(rest) || bareParticipleClaim(rest)
}

// bareParticipleClaim reads a sentence that is the act as a participle and
// nothing else: "Rolling validator1 back to 3.4.1 now.", "Restarting
// validator1 now.", "Upgrading validator1 to 3.4.2.". It is closed. What
// stands between the participle and the stop is, in this order, an optional
// "now"-style adverb, an optional "to <version or image>", and then either
// nothing, or the thing acted on (the node, it, or one word), with or
// without "back" on either side of it. Any other word, a verb above all,
// makes the sentence a caution or a heading and not this: "Rolling back to
// 3.3.0 takes the node off the network", "Restarting now would land inside
// a rotation". The sentence must stop with a . or a !.
func bareParticipleClaim(sent string) bool {
	m := participleRe.FindStringSubmatch(sent)
	if m == nil {
		return false
	}
	rest := " " + strings.TrimSpace(m[2])
	adverb, target := false, false
	if loc := adverbRe.FindStringIndex(rest); loc != nil {
		rest, adverb = rest[:loc[0]], true
	}
	if loc := targetRe.FindStringIndex(rest); loc != nil {
		rest, target = rest[:loc[0]], true
	}
	words := strings.Fields(strings.ToLower(rest))
	isThing := func(ws []string) bool {
		// "the node", "the validator", "the rollback", "with the restart"
		if len(ws) > 0 && ws[0] == "with" {
			ws = ws[1:]
		}
		if len(ws) == 2 && (ws[0] == "the" || ws[0] == "a") {
			return true
		}
		return len(ws) == 1 && ws[0] != "back" && ws[0] != "to" && ws[0] != "onto"
	}
	// "Starting the rollback.", "Proceeding with the restart.", "Rolled
	// validator1 back to 3.4.1.": the opener and the past tense are the act
	// begun or done, whatever else the closed shape holds.
	switch strings.ToLower(m[1]) {
	case "starting", "proceeding", "initiating", "rolled", "restarted", "upgraded", "applied":
		if len(words) == 1 && words[0] == "back" {
			return true
		}
		if len(words) == 0 {
			return adverb
		}
		if isThing(words) || (words[len(words)-1] == "back" && isThing(words[:len(words)-1])) ||
			(words[0] == "back" && isThing(words[1:])) {
			return true
		}
		return false
	}
	switch {
	case len(words) == 0, len(words) == 1 && words[0] == "back":
		// "Restarting now." and "Rolling back now." claim; "Rolling back
		// to 3.3.0." is a heading for a caution, and without a stop word or
		// a thing acted on it is left alone.
		return adverb
	case isThing(words):
		return adverb || target
	case words[len(words)-1] == "back" && isThing(words[:len(words)-1]):
		return true
	case words[0] == "back" && isThing(words[1:]):
		return true
	}
	return false
}

// correctPrematureClaims rewrites a gate-carrying reply's claim that the act
// is approved or under way, and reports whether it did. The first claiming
// sentence becomes yesTurnCorrection; any later one is dropped, so the
// correction is said once.
func correctPrematureClaims(reply string) (string, bool) {
	lines := strings.Split(reply, "\n")
	changed, said := false, false
	for i, ln := range lines {
		prefix := linePrefixRe.FindString(ln)
		body := ln[len(prefix):]
		var b strings.Builder
		lineChanged := false
		for _, sent := range sentenceRe.FindAllString(body, -1) {
			t := strings.TrimSpace(strings.TrimLeft(sent, "*_ "))
			if claimsPrematurely(t) {
				lineChanged = true
				if !said {
					b.WriteString(yesTurnCorrection)
					if strings.TrimRight(sent, " \t") != sent {
						b.WriteString(" ")
					}
					said = true
				}
				continue
			}
			b.WriteString(sent)
		}
		if lineChanged {
			lines[i] = strings.TrimRight(prefix+b.String(), " ")
			changed = true
		}
	}
	if !changed {
		return reply, false
	}
	return strings.Join(lines, "\n"), true
}
