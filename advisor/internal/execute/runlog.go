package execute

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RunLog is a live, line-by-line record of one run, written as it happens.
//
// Distinct from the ledger on purpose. The ledger is the audit: append-only,
// hash-chained, one entry per decision, and it is written at step boundaries
// because that is what an auditor needs. Someone watching a change to their
// validator needs something else — every line as it arrives, including the
// wrapper's own output, including the seconds where nothing has finished yet.
//
// A run log is transcript, not evidence. It is not chained, it can be deleted,
// and nothing is authorised on the strength of it. Keeping the two separate
// means neither has to compromise: the ledger stays sparse and verifiable, and
// this can be as chatty as watching requires.
//
// NDJSON appended to a file, tailed by byte offset — the same shape the
// operator's other project uses for its developer console, which is a good
// reason to keep it: a resumable byte offset survives a dropped connection and
// a page reload without the server holding per-client state.
type RunLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
	// scope is the run id's last segment: the stage or compound scope this
	// transcript is filed under. It decides whether a success verdict here
	// is a claim about the node (#769).
	scope string
}

// Line is one entry in the transcript.
type Line struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // start | step | out | ok | fail | halt | done | note | pending | handoff
	Text string    `json:"text"`
	Step string    `json:"step,omitempty"`
	// Proof is the post-state verifier's judged reading (verify.go), carried
	// by every verdict line about a node operation. The page renders a
	// success claim only from a line that has one.
	Proof map[string]any `json:"proof,omitempty"`
	// Stopped says where a halted run stopped when that is the whole point:
	// "before-apply" is a run that ended before its interrupting step, so
	// nothing was restarted by it.
	Stopped string `json:"stopped,omitempty"`
	// Staged, on a stop before the restart, is the release the run had
	// already set the node to start on next (Executor.Staged). The page
	// says so rather than "not touched".
	Staged string `json:"staged,omitempty"`
	// Refused, on a halt written because the run's preconditions refuse, is
	// the failing checks, one "name — detail" entry each: the same strings
	// the 409 answer carries (#1169). A reader finds the reason by this key
	// and not by the sentence in Text, so it survives a reload, a second
	// window, an aggregator's view of the peer, and an hour.
	Refused []string `json:"refused,omitempty"`
}

// StoppedBeforeApply marks a halt that came before the run's interrupting
// step, so the node was not restarted by this run.
const StoppedBeforeApply = "before-apply"

// InterruptingScope reports whether a transcript filed under this scope is
// about an act that takes the node off the network. A success verdict in
// one of these is a claim about the node, and needs the node's proof.
//
// prepare, config and prepare-cancel are the reversible halves: their done
// says a stage finished, which the steps themselves are evidence of.
// Anything not named here is treated as interrupting, so a scope added
// later has to be declared reversible on purpose to escape the rule.
func InterruptingScope(scope string) bool {
	switch scope {
	case StagePrepare, StageConfig, "prepare-cancel":
		return false
	}
	return true
}

// "handoff" marks the one line in a merged upgrade transcript where prepare's
// work ends and cutover's begins under the same approval, with no operator
// act in between. Distinct from "note" — an existing kind already used for
// lower-stakes asides like an unconfirmed step's continuation — because this
// line names something happening TO the node, not a remark about a step: the
// dashboard renders it with its own rule-bounded, amber treatment rather than
// folding it into an ordinary transcript line.

// RunID names the file for a plan and stage. Stable, so a reload finds the
// same stream.
func RunID(planID, stage string) string {
	safe := func(s string) string {
		return strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				return r
			}
			return '-'
		}, s)
	}
	return safe(planID) + "." + safe(stage)
}

func OpenRunLog(dir, runID string) (*RunLog, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, runID+".ndjson")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	scope := runID
	if i := strings.LastIndex(runID, "."); i >= 0 {
		scope = runID[i+1:]
	}
	return &RunLog{f: f, path: p, scope: scope}, nil
}

// Write appends one line and flushes it.
//
// Synced on every line, which is not free — but a transcript that is watched
// live and buffered is a transcript that arrives after the thing it describes,
// and the whole point is that someone is watching now.
//
// A success verdict ("done", or "pending", which says the node restarted
// onto the right build) in a transcript about a node operation cannot be
// written through here: it has no proof, and it is exactly the line #769's
// page read as "back in full sync". It is recorded as a stop instead, with
// the words that were attempted kept, so a future caller that forgets the
// verifier produces a loud halt rather than a quiet false success.
func (r *RunLog) Write(kind, step, text string) {
	if r == nil {
		return
	}
	if (kind == "done" || kind == "pending") && InterruptingScope(r.scope) {
		r.refuseUnproven(step, text)
		return
	}
	r.put(Line{Kind: kind, Step: step, Text: text})
}

// refuseUnproven is the backstop's one line: the words that were attempted,
// recorded as a stop.
func (r *RunLog) refuseUnproven(step, text string) {
	r.put(Line{Kind: "halt", Step: step, Text: "this run reported an outcome the node did not " +
		"prove, so it is recorded as stopped rather than finished: " + text})
}

// StageDone ends a run whose scope is a reversible stage on its own (a
// prepare, a config edit). The stage finishing is its steps' own evidence;
// what the page says about the NODE beside it ("still on the old version",
// "takes effect at the next restart") is a claim, so the line carries the
// node's reading (Executor.Reading) and the page says it from that (#769).
// In a transcript about a node operation it is the same refusal Write
// makes, because there it would read as the operation finishing.
func (r *RunLog) StageDone(p *Proof, text string) {
	if r == nil {
		return
	}
	if InterruptingScope(r.scope) {
		r.refuseUnproven("", text)
		return
	}
	r.put(Line{Kind: "done", Text: text, Proof: p.Wire()})
}

// Complete writes the one line that may call a node operation finished. It
// takes the verifier's proof and nothing else can stand in for it: a proof
// that is not Verified is written as the halt it is.
func (r *RunLog) Complete(p *Proof, text string) {
	if r == nil {
		return
	}
	if p.State() != Verified {
		r.put(Line{Kind: "halt", Text: "not confirmed: " + NotRestartedNote(p), Proof: p.Wire()})
		return
	}
	r.put(Line{Kind: "done", Text: text, Proof: p.Wire()})
}

// Pending writes "restarted onto the right build, not yet in sync". Same
// rule as Complete: only from a reading that proves the first two.
func (r *RunLog) Pending(p *Proof, text string) {
	if r == nil {
		return
	}
	if p.State() != CatchingUp {
		r.put(Line{Kind: "halt", Text: "not confirmed: " + NotRestartedNote(p), Proof: p.Wire()})
		return
	}
	r.put(Line{Kind: "pending", Text: text, Proof: p.Wire()})
}

// Halt writes a stop that a reading explains, carrying the reading.
func (r *RunLog) Halt(p *Proof, text string) {
	if r == nil {
		return
	}
	r.put(Line{Kind: "halt", Text: text, Proof: p.Wire()})
}

// StoppedAbandoned marks a halt written because the service stopped under
// a run it could not finish watching. Nothing is known about the node.
const StoppedAbandoned = "abandoned"

// Abandon writes the stop of a run this service was shut down under. A stop,
// not a pending: pending says the node restarted onto the right build, and
// a service leaving mid-run knows no such thing.
func (r *RunLog) Abandon(text string) {
	if r == nil {
		return
	}
	r.put(Line{Kind: "halt", Text: text, Stopped: StoppedAbandoned})
}

// Refuse writes the stop of a run whose preconditions refused before
// anything was done, and keeps the failing checks on the line itself. The
// reason used to live in the 409 answer alone, so it existed only in the
// browser tab that made the request (#1169).
func (r *RunLog) Refuse(text string, failed []string) {
	if r == nil {
		return
	}
	r.put(Line{Kind: "halt", Text: text, Refused: failed})
}

// StopBeforeApply writes the stop of a run that ended before its
// interrupting step. The page reads the marker and says the node was not
// restarted, and no way back is printed, because there is nothing to undo.
func (r *RunLog) StopBeforeApply(text, staged string, p *Proof) {
	if r == nil {
		return
	}
	r.put(Line{Kind: "halt", Text: text, Stopped: StoppedBeforeApply, Staged: staged, Proof: p.Wire()})
}

// HaltWith writes a halt that carries what the run had staged and the
// node's reading when it stopped.
func (r *RunLog) HaltWith(text, staged string, p *Proof) {
	if r == nil {
		return
	}
	r.put(Line{Kind: "halt", Text: text, Staged: staged, Proof: p.Wire()})
}

func (r *RunLog) put(l Line) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l.At = time.Now().UTC()
	b, err := json.Marshal(l)
	if err != nil {
		return
	}
	r.f.Write(append(b, '\n'))
	r.f.Sync()
}

func (r *RunLog) Printf(kind, step, format string, args ...any) {
	r.Write(kind, step, fmt.Sprintf(format, args...))
}

func (r *RunLog) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

func (r *RunLog) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}
