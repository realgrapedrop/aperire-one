package host

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// StoreSize is one reading of the node's ledger store, taken on the
// privileged side.
//
// Why the privileged side (#427). On a host running the node from its
// vendor's package, the state directory is 0750 and owned by the account the
// node runs as. The dashboard runs as a different account and cannot open
// it, and it should not be given the group: the account that serves a web
// page does not need read access to the whole ledger store. The wrapper
// already runs as root for the verbs that need it and already answers
// `disk`, so one more number costs no new access anywhere.
//
// Exactly one of Bytes and Reason is set. A store that could not be measured
// says why, in the words of whatever refused, and never comes back as zero:
// that is the same rule the dashboard's own walk now follows, and the two
// readings meet on the page.
type StoreSize struct {
	// Path is the directory that was measured, as the wrapper resolved it
	// from its own configuration. Published so the page names the store it
	// is reporting on rather than the one the dashboard was pointed at,
	// which on a moved node are not the same directory.
	Path string `json:"path"`
	// Bytes is the size, or nil when it could not be taken. A pointer, not a
	// zero: this whole file exists because a reading nobody took was being
	// rendered as a number.
	Bytes      *int64    `json:"bytes"`
	Reason     string    `json:"reason,omitempty"`
	MeasuredAt time.Time `json:"measured_at"`
}

// Measured reports whether this reading has a size behind it.
func (r StoreSize) Measured() bool { return r.Bytes != nil }

// StoreSize asks the wrapper's store-size verb how large the node's ledger
// store is right now.
//
// The verb answers in the wrapper's own AperireX=Y lines, the same shape
// `inspect` speaks and read by the same AperireFacts, on both node shapes:
//
//	AperireStorePath=/var/lib/xrpld/db/nudb
//	AperireStoreBytes=7193382912
//
// or, when it could not be taken,
//
//	AperireStorePath=/var/lib/xrpld/db/nudb
//	AperireStoreBytes=unknown
//	AperireStoreReason=the store directory does not exist
//
// and it exits 0 either way, because "I could not measure it" is an answer
// and a non-zero exit would arrive here as a failure of the call instead.
//
// There is one case where the verb does NOT reach that promise, and it is the
// ordinary one. A configuration with no DATA_PATH in it never gets as far as
// measuring anything: require_conf refuses, exit 64, a sentence on stderr and
// not one Aperire line on stdout, which is exactly how `disk` behaves on the
// same configuration. So this reads a refusal as what it is, a store that was
// not measured and the wrapper's own words for why, rather than as a failure
// of the read that would arrive at the page as a Go error with the reason
// buried in it. Every path but one comes back as a reading.
//
// The exception is a host with no wrapper grant at all. Nothing was asked
// there, so there is nothing to report as an answer.
func (s *State) StoreSize() (StoreSize, error) {
	if s.Wrapper == "" {
		return StoreSize{}, fmt.Errorf("no privilege wrapper is configured, so the node's store was not measured")
	}
	name := s.Wrapper
	args := []string{"store-size"}
	r := StoreSize{MeasuredAt: time.Now().UTC()}
	out, err := s.Runner.Run(s.context(), name, args...)
	if err != nil {
		// The wrapper refused, or could not be run. Either way the operator
		// needs the sentence, so it becomes the reason and the reading has
		// no size.
		r.Reason = wrapperReason(err)
		return r, nil
	}
	facts := AperireFacts(out)
	r.Path = facts["AperireStorePath"]
	raw, ok := facts["AperireStoreBytes"]
	if !ok {
		// An answer with no AperireStoreBytes line in it. A verb that printed
		// something else, or nothing, has not told us the store is empty.
		r.Reason = "the wrapper's store-size answer carries no size: " + excerpt(string(out))
		return r, nil
	}
	if raw == "unknown" {
		r.Reason = facts["AperireStoreReason"]
		if r.Reason == "" {
			// The verb promises a reason beside an unknown. Missing is a
			// wrapper that needs fixing, not a store that is fine.
			r.Reason = "the wrapper reported the size as unknown and gave no reason"
		}
		return r, nil
	}
	n, perr := strconv.ParseInt(raw, 10, 64)
	if perr != nil || n < 0 {
		r.Reason = fmt.Sprintf("the wrapper's store-size answer is not a byte count: %q", raw)
		return r, nil
	}
	r.Bytes = &n
	return r, nil
}

// wrapperReason pulls the wrapper's own sentence out of a failed call.
//
// ExecRunner wraps a non-zero exit as "<command>: exit status 64: wrapper:
// <sentence>", because the wrapper's die() writes "wrapper: ..." as its own
// stderr line. The sentence is the part an operator can act on; the rest
// names a path and a number they cannot.
//
// Matched only where the wrapper could actually be speaking: at the start of
// the message, at the start of a line, or after the ": " ExecRunner joins
// stderr on with. A bare search would find the marker inside a PATH, and
// "fork/exec /wrapper: permission denied" would come back as "permission
// denied" with nothing left to say which program refused.
func wrapperReason(err error) string {
	msg := strings.TrimSpace(err.Error())
	for _, marker := range []string{": wrapper: ", "\nwrapper: "} {
		if i := strings.LastIndex(msg, marker); i >= 0 {
			if tail := strings.TrimSpace(msg[i+len(marker):]); tail != "" {
				return tail
			}
		}
	}
	if tail, ok := strings.CutPrefix(msg, "wrapper: "); ok && strings.TrimSpace(tail) != "" {
		return strings.TrimSpace(tail)
	}
	return msg
}
