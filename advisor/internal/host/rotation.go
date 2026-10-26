package host

import (
	"fmt"
	"strings"
)

// Is the node's ledger store mid-rotation? — issue #80.
//
// The wrapper already refuses to stop a node while a NuDB rotation is in
// flight, because an interrupted rotation is what emptied a store on
// 2026-08-25. That refusal is the backstop and stays the backstop. What this
// read is for is asking the SAME question earlier, at assessment time, so a
// restart the wrapper would refuse is never offered to the operator as a gate
// — and so the passkey approval, which is spent on the attempt rather than on
// the success, is never spent on one that was doomed before it was offered.
//
// It goes through the wrapper's read-only `rotation-state` verb, which is the
// same reading `rotation_guard` performs, published on its own so the Advisor
// can answer "can I restart yet" without attempting a restart to find out.

// rotationInFlight is the ONE state word from the wrapper that means a
// rotation is happening right now. The wrapper prints four — rotating, stale,
// idle, unknown — and refuses a restart on this one alone; the other three
// print and continue. Matching that exactly is the point: a reading here that
// blocked on "stale" or "unknown" would refuse restarts the wrapper would
// have allowed, which turns a containment guard into an outage.
const rotationInFlight = "rotating"

// RotationInFlight reports whether a store rotation is under way, with the
// wrapper's own one-line explanation beside it.
//
// It FAILS OPEN, deliberately. No wrapper configured, the wrapper erroring,
// the log unreadable: all of them answer "not in flight" rather than refusing.
// This check is an early warning that saves a ceremony, not a safety boundary
// — the boundary is the wrapper's own exit-64 refusal, which runs on the
// privileged side and cannot be talked out of it. A read that failed CLOSED
// would let one broken docker call lock an operator out of restarting their
// own node, which is the failure mode a recovery path must never have.
//
// The detail is returned rather than re-derived because the wrapper's line
// carries the elapsed minutes, and the operator's next question after "a
// rotation is running" is "for how long". A second call to learn that would
// be a second reading of a state that moves.
func (s *State) RotationInFlight() (bool, string, error) {
	state, detail, err := s.RotationStateNow()
	return state == rotationInFlight, detail, err
}

// RotationInFlightWait is RotationInFlight with no time limit on the log
// read: `rotation-state --wait`, the read the wrapper's own stop guard takes.
// It is the one the spend guard (execute.Executor.RotationInFlight) is
// handed. That guard exists so an approval is never spent on a stop the
// wrapper will refuse, and a bounded read that ran out on a slow log would
// answer "unknown", fail open, and spend it anyway (PR #1049 review, #1043).
// Everything that only offers or renders keeps the bounded read: it sits
// inside the Advisor's 90-second check.
func (s *State) RotationInFlightWait() (bool, string, error) {
	state, detail, err := s.rotationState("--wait")
	return state == rotationInFlight, detail, err
}

// RotationStateNow is the wrapper's state word itself, "rotating", "stale",
// "idle" or "unknown", with its detail. The rotation precondition needs the
// word, not the bool: only "idle" is a reading that no rotation is running,
// and "unknown" (a read that ran out, a log that could not be read) is not
// one (#833, PR #1049 review).
func (s *State) RotationStateNow() (state, detail string, err error) {
	return s.rotationState()
}

func (s *State) rotationState(extra ...string) (state, detail string, err error) {
	if s.Wrapper == "" {
		// No privileged read is available. Unlike artefactHashes there is no
		// direct fallback to fall back TO: the verb reads the node's container
		// log, and the account this service runs as is deliberately denied
		// docker (see the wrapper's `inspect` verb). Reading it here directly
		// would undo the arrangement the wrapper exists to create.
		return "", "", nil
	}
	name := s.Wrapper
	rest := append([]string{"rotation-state"}, extra...)
	out, rerr := s.Runner.Run(s.context(), name, rest...)
	if rerr != nil {
		return "", "", fmt.Errorf("reading the store-rotation state through the wrapper: %w", rerr)
	}
	state, detail = parseRotationState(string(out))
	return state, detail, nil
}

// parseRotationState reads the wrapper's "<state><TAB><detail>" line.
//
// The first non-empty line, not the first line: the verb prints exactly one,
// but a leading blank or a stray line from the docker call underneath it
// would otherwise be compared against the state words and match none of them,
// which fails open silently rather than reading the answer that is there.
func parseRotationState(out string) (state, detail string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		state, detail, _ = strings.Cut(line, "\t")
		return strings.TrimSpace(state), strings.TrimSpace(detail)
	}
	return "", ""
}
