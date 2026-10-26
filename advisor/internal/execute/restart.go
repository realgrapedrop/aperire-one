package execute

import (
	"fmt"
	"time"

	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/runbook"
)

// The restart's own confirmation — ADR 0016 §5.
//
// It is not a wrapper around AwaitHealthy, and that is the point. AwaitHealthy
// runs its whole window before returning and writes run.unconfirmed itself on
// the way out, so a node that came back on a DIFFERENT build — visible on the
// very first poll — would be reported as "still catching up" for fifteen
// minutes, told the operator that was normal, and left a false entry on the
// ledger for a node that was up and answering. A mismatch is a finding, and a
// finding has to halt on the reading that shows it.
//
// It lives here rather than beside either caller because there are two of
// them — the web run and the command line — and a confirmation that differs
// between them is two different products. The web path had this loop and the
// CLI still called AwaitHealthy, which is exactly the divergence this
// placement prevents.

// NodeReader is what a restart is confirmed from: one whole reading of the
// node at a time (#769). An interface, so the loop can be exercised against
// a scripted node instead of a real one.
type NodeReader interface {
	Observe() (runbook.Observation, error)
}

// RestartVerdict is what one confirmation window concluded.
type RestartVerdict int

const (
	// RestartBack: a process newer than the restart step reports the build
	// it was running before and is back in full sync. Proven, by the node.
	RestartBack RestartVerdict = iota
	// RestartVersionChanged: it came back on something else. Not a slow
	// sync — a restart that changed the running build is a finding, and
	// nothing about waiting longer makes it less of one.
	RestartVersionChanged
	// RestartStillCatchingUp: the window closed on a process newer than the
	// restart step, on the expected build, not yet in full sync. The
	// restart happened and was seen; this is not a failure.
	RestartStillCatchingUp
	// RestartNotObserved: the window closed without one reading from a
	// process newer than the restart step (#769). The old process kept
	// answering, or nothing did, or the step never ran. Nothing proves the
	// node restarted, so nothing may say it did.
	RestartNotObserved
)

// PollRestart is the loop. Pure of clocks, ledgers and transcripts so the
// decision — which reading ends the wait, and with what verdict — can be
// tested directly.
//
// appliedAt is when the run's restart step began; every reading is judged
// against it. It returns the verdict, the version it stopped on (the one
// actually found, for a mismatch) and the judged reading that decided it.
func PollRestart(read NodeReader, expected string, appliedAt time.Time, window time.Duration,
	now func() time.Time, sleep func(time.Duration), tick func(version, detail string)) (RestartVerdict, string, *Proof) {

	deadline := now().Add(window)
	var last *Proof
	for {
		obs, err := read.Observe()
		p := Judge(obs, err, appliedAt, now(), expected)
		last = p
		if tick != nil {
			if err != nil {
				tick("?", err.Error())
			} else {
				tick(obs.Version, obs.Detail)
			}
		}
		switch p.State() {
		case NotApplied:
			return RestartNotObserved, "", p
		case Verified:
			return RestartBack, p.Version(), p
		}
		// A node that is not answering yet is the ordinary case: it is
		// restarting. Only a version it actually REPORTED can contradict the
		// one it was running, and for a restart that is true of the old
		// process as much as a new one: nothing here moves the build.
		if err == nil && obs.Version != "" && obs.Version != expected {
			return RestartVersionChanged, obs.Version, p
		}
		if !now().Before(deadline) {
			break
		}
		sleep(5 * time.Second)
	}
	if last.State() == CatchingUp {
		return RestartStillCatchingUp, expected, last
	}
	return RestartNotObserved, last.Version(), last
}

// AwaitRestart polls and records. The verdict comes back for the caller to
// render — a transcript line on the web, a printed one on the command line —
// and the ledger entry is written here, once, so both paths leave the same
// record of the same fact.
func (e *Executor) AwaitRestart(expected string, window time.Duration,
	tick func(version, detail string)) (RestartVerdict, string, *Proof) {

	verdict, found, p := PollRestart(e.State, expected, e.appliedAt, window, e.now, e.sleep, tick)
	data := p.Wire()
	switch verdict {
	case RestartBack:
		data["detail"] = p.Detail()
		e.record(ledger.KindRunCompleted,
			LedgerSynced(OpRestart, p, ""), data)
	case RestartVersionChanged:
		// run.halted, not executor.refused. The executor did not decline to
		// act — it acted, and what came back is wrong. A refusal entry here
		// would put a run that ran into the list an auditor filters for runs
		// that did not.
		data["expected"], data["found"] = expected, found
		e.record(ledger.KindRunHalted,
			"restart halted: the node came back on a different version", data)
	case RestartStillCatchingUp:
		data["timeout"] = window.String()
		e.record(ledger.KindRunUnconfirmed,
			fmt.Sprintf("node restarted and had not returned to full sync within %s", window), data)
	case RestartNotObserved:
		e.record(ledger.KindRunHalted, NotRestartedNote(p), data)
	}
	return verdict, found, p
}

// RestartVersionChangedNote is what an operator is told when the node comes
// back on another build. Both versions in the sentence itself: "it came back
// on a different version" without saying which two is something nobody can
// act on. Shared by both callers so the CLI and the transcript say the same
// thing.
func RestartVersionChangedNote(expected, found string) string {
	return "the node came back running " + found + ", not the " + expected +
		" it was running before this restart. Nothing here changed the version, so something " +
		"else did: the deployment file, a pulled tag, or a hand-run command. This run is halted " +
		"rather than reported as slow, because waiting longer does not make it the same build."
}
