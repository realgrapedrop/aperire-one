package main

import (
	"regexp"
	"strings"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/memory"
	"aperire-advisor/internal/rollback"
)

// Recalled notes, re-tested against the node before the model reads them
// (#1012).
//
// A note the Advisor wrote is its own earlier guess, and the RECALLED header
// says so. That did not hold on a lab validator (17bc, 2026-10-11): after a
// refusal caused by its own block, the Advisor wrote "a same-version
// image-source change is not a rollback" (memory 2091535e9ea4), and a fresh
// session recalled it and refused the rollback outright, while the node's own
// derivation named the target the whole time. The note was wrong, and nothing
// beside it said so.
//
// So where the service holds a live answer to the question a note is about,
// it stamps that answer under the note. Today that is the rollback: whether
// this node derives a target, and which. The reading is taken once per ask,
// and only when a recalled note mentions a rollback, so a conversation with
// no such note pays nothing for it.

// rollbackMentionRe finds a note about rolling the node back, in the words
// the Advisor and an operator use for it: roll back and rollback, revert,
// downgrade, go back, and the previous version or release. Wide on purpose
// (#1012 review, L1): a wrong note worded "no downgrade target; do not
// propose a revert" missed the first, narrower pattern and came back with no
// live answer under it. A false match costs one stamped line of fact.
var rollbackMentionRe = regexp.MustCompile(`(?i)\broll[\s-]?backs?\b` +
	`|\broll(?:ed|ing|s)?\s+(?:\S+\s+){0,3}back\b` +
	`|\brevert(?:s|ed|ing)?\b` +
	`|\bdowngrad(?:e|es|ed|ing)\b` +
	`|\b(?:go|goes|going|gone|went)\s+(?:\S+\s+){0,2}back\b` +
	`|\b(?:previous|prior|older|earlier)\s+(?:version|release|build|image)\b`)

// rollbackDenialRe finds a note that says there is no rollback here: no
// target, not a rollback, nothing to go back to, cannot be proposed. Only
// such a note is told it is wrong when the node derives a target (#1012
// review, L2). A note recording a rollback that happened is history, and the
// live derivation sits under it as a fact without calling it wrong.
var rollbackDenialRe = regexp.MustCompile(`(?i)\bnot\s+(?:a|an)\s+(?:roll[\s-]?back|revert|downgrade)\b` +
	`|\bno\s+(?:\S+\s+){0,2}target\b` +
	`|\bnothing\s+to\s+(?:roll|revert|downgrade|go)\b` +
	`|\b(?:cannot|can't|can not|won't|will not|do not|don't|never)\s+(?:be\s+)?(?:roll|revert|downgrad|propos)`)

// recallCheck returns the check memory.RenderChecked stamps notes with, for
// the State this ask already read. nil State, nil check: there is nothing
// live to compare with, and saying so under every note would read as a
// finding.
func (s *server) recallCheck(st *host.State) func(memory.Entry) string {
	if st == nil {
		return nil
	}
	var d rollback.Derivation
	var derr error
	var done bool
	return func(e memory.Entry) string {
		text := e.Title + "\n" + e.Body
		if !rollbackMentionRe.MatchString(text) {
			return ""
		}
		if !done {
			d, derr = s.deriveRollback(st)
			done = true
		}
		return liveRollbackLine(d, derr, rollbackDenialRe.MatchString(text))
	}
}

// liveRollbackLine is the node's present answer to "can this node be rolled
// back, and to what", in one line. denies says the note claims there is no
// rollback here; only then does a derived target make the note wrong.
func liveRollbackLine(d rollback.Derivation, err error, denies bool) string {
	if err != nil {
		return "the rollback derivation could not be read just now (" + err.Error() +
			"), so this note has not been re-tested; read rollback_assessment before relying on it"
	}
	if d.Refusal != "" {
		return "this node derives no rollback target right now: " + strings.TrimSpace(d.Detail)
	}
	line := "this node derives a rollback from " + d.Running + " to " + d.Target + " right now"
	if d.SourceRollback {
		line = "this node derives a rollback to " + d.Target + " right now, a source rollback in " +
			"which the release does not move, and it IS a rollback the service accepts"
	}
	if denies {
		line += ". This entry says there is no rollback here, and that is wrong"
	}
	return line
}
