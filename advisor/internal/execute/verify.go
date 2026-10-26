package execute

import (
	"fmt"
	"time"

	"aperire-advisor/internal/runbook"
)

// The post-state verifier — #769.
//
// A run that takes the node off the network is finished when the node says
// so, and only then. Not when the steps returned, not when a grant was
// checked, not when a wrapper printed "running": when one reading, taken from
// the node itself, shows all three of
//
//   - a process that started AFTER this run's interrupting step began, so
//     the node answering is the one that came back and not the one that was
//     there all along;
//   - the build this run expected, read off that same process;
//   - full sync, read off that same process.
//
// On the lab the page said "Restart complete. Your node is running the new
// version and back in full sync with the network" over a node whose process
// had been up for twelve days: the run stopped after prepare, wrote `done`,
// and the done was read as the whole upgrade. Nothing had observed anything.
//
// So the proof is a type only this file can build. A run log accepts a
// success verdict for a node operation only with one (RunLog.Complete), and
// the sentences that claim it ("back in full sync") are composed here and
// nowhere else. A caller that wants to say the node is back has to have
// asked the node.

// PostState is what one reading proves about the node after a run's
// interrupting step.
type PostState int

const (
	// NotApplied: this run never reached its interrupting step, so there is
	// nothing whose outcome could be observed. Nothing was restarted by it.
	NotApplied PostState = iota
	// Unread: the node did not answer, or answered without an uptime. A
	// restarting node is unread for a while; that is ordinary. It is never
	// evidence of anything.
	Unread
	// NotRestarted: the node answering has been up since before the
	// interrupting step began. It is the process that was already there.
	NotRestarted
	// WrongVersion: a process that started after the step, on a build other
	// than the one this run expected.
	WrongVersion
	// CatchingUp: a process that started after the step, on the expected
	// build, not yet in full sync.
	CatchingUp
	// Verified: a process that started after the step, on the expected
	// build, in full sync. The only state a run may be called complete on.
	Verified
)

func (p PostState) String() string {
	switch p {
	case NotApplied:
		return "not-applied"
	case Unread:
		return "unread"
	case NotRestarted:
		return "not-restarted"
	case WrongVersion:
		return "wrong-version"
	case CatchingUp:
		return "catching-up"
	case Verified:
		return "verified"
	}
	return "unknown"
}

// Proof is one judged reading. Every field is unexported: a Proof is made by
// Judge from what the node answered, or not at all.
type Proof struct {
	state      PostState
	expected   string
	version    string
	serverSt   string
	detail     string
	uptimeSec  int
	hasUptime  bool
	startedAt  time.Time
	appliedAt  time.Time
	observedAt time.Time
	readErr    string
}

// State is what this reading proves.
func (p *Proof) State() PostState {
	if p == nil {
		return NotApplied
	}
	return p.state
}

// Version is the build the node reported in this reading, empty if it did
// not answer.
func (p *Proof) Version() string {
	if p == nil {
		return ""
	}
	return p.version
}

// Detail is the node's own sync description from this reading.
func (p *Proof) Detail() string {
	if p == nil {
		return ""
	}
	return p.detail
}

// ServerState is the node's own state word in this reading.
func (p *Proof) ServerState() string {
	if p == nil {
		return ""
	}
	return p.serverSt
}

// ReadError is why a reading is Unread, when it is.
func (p *Proof) ReadError() string {
	if p == nil {
		return "nothing asked the node"
	}
	if p.readErr == "" && p.state == Unread {
		return "it did not answer"
	}
	return p.readErr
}

// Restarted reports whether this reading came from a process that started
// after the run's interrupting step.
func (p *Proof) Restarted() bool {
	s := p.State()
	return s == WrongVersion || s == CatchingUp || s == Verified
}

// Wire is the proof as the transcript and the ledger carry it. The page
// renders a success claim only from a verdict line that carries this, and
// reads the version it names from here rather than from a sentence.
func (p *Proof) Wire() map[string]any {
	if p == nil {
		return nil
	}
	m := map[string]any{
		"post_state":   p.state.String(),
		"expected":     p.expected,
		"version":      p.version,
		"server_state": p.serverSt,
		"in_sync":      p.state == Verified,
		"restarted":    p.Restarted(),
		"observed_at":  p.observedAt.UTC().Format(time.RFC3339Nano),
	}
	if !p.appliedAt.IsZero() {
		m["applied_at"] = p.appliedAt.UTC().Format(time.RFC3339Nano)
	}
	if p.hasUptime {
		m["uptime_sec"] = p.uptimeSec
		m["started_at"] = p.startedAt.UTC().Format(time.RFC3339Nano)
	}
	if p.readErr != "" {
		m["read_error"] = p.readErr
	}
	return m
}

// Judge decides what one reading proves. appliedAt is when this run's
// interrupting step began (zero if it never did); now is when the reading
// was taken.
//
// The restart test is "the process started at or after the step began",
// with the start estimated as now minus the node's own uptime. uptime is
// whole seconds, rounded down, so the estimate can be up to a second LATER
// than the true start: a process that started less than a second before the
// step would pass. Nothing this run did can have started it, and accepting
// that sliver is what keeps a genuine sub-second recreate from reading as
// "not restarted" on every poll.
func Judge(obs runbook.Observation, readErr error, appliedAt, now time.Time, expected string) *Proof {
	p := &Proof{expected: expected, appliedAt: appliedAt, observedAt: now}
	if appliedAt.IsZero() {
		p.state = NotApplied
		return p
	}
	if readErr != nil {
		p.state, p.readErr = Unread, readErr.Error()
		return p
	}
	p.version, p.serverSt, p.detail = obs.Version, obs.ServerState, obs.Detail
	if obs.UptimeSec == nil || *obs.UptimeSec < 0 || obs.Version == "" {
		p.state = Unread
		if obs.UptimeSec == nil {
			p.readErr = "the node did not report its uptime, so a restart cannot be seen"
		} else if obs.Version == "" {
			p.readErr = "the node did not report its build"
		}
		return p
	}
	p.hasUptime, p.uptimeSec = true, *obs.UptimeSec
	p.startedAt = now.Add(-time.Duration(p.uptimeSec) * time.Second)
	switch {
	case p.startedAt.Before(appliedAt):
		p.state = NotRestarted
	case obs.Version != expected:
		p.state = WrongVersion
	case !obs.Healthy:
		p.state = CatchingUp
	default:
		p.state = Verified
	}
	return p
}

// NotRestartedNote is what an operator is told when the window closed and
// no reading ever came from a process newer than the run's interrupting
// step. Said from the last reading, because "the node did not answer" and
// "the node answering is the old one" are different things to go and check.
func NotRestartedNote(p *Proof) string {
	switch p.State() {
	case NotApplied:
		return "this run never reached the step that restarts the node, so nothing was restarted by it"
	case NotRestarted:
		return fmt.Sprintf("the node was not seen restarting: the process answering has been up "+
			"since %s, before this run's restart step began at %s, and it reports %s. Check the "+
			"node's current version and sync state before deciding anything",
			p.startedAt.UTC().Format(time.RFC3339), p.appliedAt.UTC().Format(time.RFC3339), p.version)
	case Unread:
		why := p.readErr
		if why == "" {
			why = "it did not answer"
		}
		return "the node's restart could not be confirmed: " + why + ". Check the node's " +
			"current version and sync state before deciding anything"
	}
	return "the node's restart could not be confirmed from its own readings"
}

// What a verdict line says, by operation. These are the only sentences in
// the Advisor that claim a node is back in full sync, and each is built from
// the proof it is written beside.
const (
	OpUpgrade   = "upgrade"
	OpRestart   = "restart"
	OpNormalise = "normalise"
	OpRollback  = "rollback"
)

// SyncedLine is the done line for a Verified proof. late marks a
// confirmation that arrived after the window closed.
func SyncedLine(op string, p *Proof, late bool) string {
	v := p.Version()
	var s string
	switch op {
	case OpRestart:
		s = "node is back in full sync with the network, still running " + v
	case OpNormalise:
		s = "the deployment change is in and the node is back in full sync, still running " + v
	default: // upgrade and rollback say the version it is now on
		s = "node is running " + v + " and back in full sync with the network"
	}
	if late {
		s += " (confirmed after the window closed)"
	}
	return s
}

// LedgerSynced is the ledger summary for a Verified proof, lateBy set for a
// confirmation after the window closed. The version is the one the node
// reported, from the proof.
func LedgerSynced(op string, p *Proof, lateBy string) string {
	var s string
	switch op {
	case OpRestart:
		s = "node restarted and is back in full sync on " + p.Version()
	case OpRollback:
		s = "node rolled back to " + p.Version() + " and is back in full sync"
	default:
		s = "node reports " + p.Version() + " and is back in full sync"
	}
	if lateBy != "" {
		s += ", " + lateBy + " after the window closed"
	}
	return s
}

// CatchingUpLine is the pending line for a CatchingUp proof: restarted, on
// the expected build, not yet in sync.
func CatchingUpLine(op string, p *Proof) string {
	switch op {
	case OpRestart:
		return "your node restarted and has not returned to full sync yet"
	case OpNormalise:
		return "the deployment change is in and the node has not returned to full sync yet"
	}
	return "your node is running " + p.Version() + ", and has not returned to full sync yet"
}
