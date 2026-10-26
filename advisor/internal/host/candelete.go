package host

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Is the daily ledger-store rotation window installed and running on this
// host?, issue #106.
//
// The gap this closes: asked to set advisory_delete back to 1, the Advisor
// argued that "nothing recorded on this node shows any such process
// existing" to authorise a rotation, when the aperire-can-delete.timer
// service (#79) was installed on the host the whole time, arming one rotation
// a day. The Advisor had no host systemd units in its context and reasoned
// correctly from an incomplete picture; the fix is not a smarter guess, it is
// a read.
//
// Per the operator's ruling on #106, advisory_delete=0 (rippled rotates on
// its own) and advisory_delete=1 with this window installed are BOTH
// legitimate, operator-chosen configurations. This read exists so the
// Advisor can say which one is actually running here, not to argue for
// either, CanDeleteTimerDisabled is the ordinary, healthy state on a
// free-running node, never a fault to fix.

// The four states the wrapper's can-delete-timer verb prints, mirroring the
// shape rotation-state and config-readable already use.
const (
	// CanDeleteTimerAbsent means the unit was never installed on this host,
	// the normal state for a node that has not run
	// scripts/install-can-delete-timer.sh.
	CanDeleteTimerAbsent = "absent"
	// CanDeleteTimerEnabled means the timer is installed and enabled: this
	// host authorises one rotation a day through the window.
	CanDeleteTimerEnabled = "enabled"
	// CanDeleteTimerDisabled means the timer is installed but not enabled,
	// the ordinary state install-can-delete-timer.sh leaves a node in when
	// advisory_delete is still off, so rippled keeps rotating on its own.
	CanDeleteTimerDisabled = "disabled"
	// CanDeleteTimerUnknown means this could not be measured. Never treated
	// as absent: a host where systemctl would not answer has told this
	// process nothing about whether the window exists.
	CanDeleteTimerUnknown = "unknown"
)

// CanDeleteWindow reports whether the daily rotation window is installed and
// enabled on this host, and the wrapper's own detail beside it, including,
// when it can be read, when the window last ran.
//
// Unlike RotationInFlight this never fails open into a specific answer: no
// wrapper, a wrapper error, or an unrecognised word all come back as
// CanDeleteTimerUnknown, because nothing here gates an action the way the
// rotation guard does. There is no safety property to preserve by guessing,
// so an unread fact is reported as unread rather than defaulted to "absent",
// which would be a different, false claim about the host.
func (s *State) CanDeleteWindow() (state, detail string) {
	if s.Wrapper == "" {
		return CanDeleteTimerUnknown,
			"no privilege wrapper is configured, so whether the daily rotation window is installed was not asked"
	}
	name := s.Wrapper
	rest := []string{"can-delete-timer"}
	out, err := s.Runner.Run(s.context(), name, rest...)
	if err != nil {
		return CanDeleteTimerUnknown,
			fmt.Sprintf("the wrapper's can-delete-timer verb did not answer: %v", err)
	}
	// The same "<state><TAB><detail>" line rotation-state prints, and the
	// same first-non-empty-line parser: reused rather than duplicated, since
	// nothing about it is specific to rotation-state's own verb.
	got, d := parseRotationState(string(out))
	switch got {
	case CanDeleteTimerAbsent, CanDeleteTimerEnabled, CanDeleteTimerDisabled, CanDeleteTimerUnknown:
		return got, d
	default:
		return CanDeleteTimerUnknown,
			fmt.Sprintf("the wrapper reported an unrecognised state %q for the rotation window", got)
	}
}

// The node's own answer about advisory delete, from its running process
// (review of #1101). The config file can say advisory_delete=1 while the
// running node still rotates on its own: scripts/enable-advisory-delete.sh
// edits the file and does not restart the node. `can_delete` with no
// parameter is a read, and answers a number only when the running node has
// advisory delete enabled.
const (
	// AdvisoryLiveEnabled: the running node reports advisory delete enabled.
	AdvisoryLiveEnabled = "enabled"
	// AdvisoryLiveNotEnabled: the running node reports it is not enabled, so
	// it rotates on its own whatever its file says.
	AdvisoryLiveNotEnabled = "not-enabled"
	// AdvisoryLiveUnknown: not read, or an answer this does not recognise.
	AdvisoryLiveUnknown = "unknown"
)

// canDeleteReadBody is the request, with no parameter. It is a READ only
// because it has none: `can_delete` with a parameter writes ("now" arms one
// rotation, "always" and a number arm more), so the body is a constant and a
// row pins it byte for byte.
const canDeleteReadBody = `{"method":"can_delete","params":[{}]}`

// AdvisoryDeleteLive asks the running node whether advisory delete is on.
func (s *State) AdvisoryDeleteLive() (state, detail string) {
	if s.Profile.AdminRPC == "" || s.HTTP == nil {
		return AdvisoryLiveUnknown, "no admin endpoint is configured, so the node's own advisory delete state was not asked"
	}
	req, err := http.NewRequestWithContext(s.context(), http.MethodPost, s.Profile.AdminRPC,
		strings.NewReader(canDeleteReadBody))
	if err != nil {
		return AdvisoryLiveUnknown, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return AdvisoryLiveUnknown, fmt.Sprintf("the node did not answer can_delete: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return AdvisoryLiveUnknown, fmt.Sprintf("the node's can_delete answer could not be read: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return AdvisoryLiveUnknown, fmt.Sprintf("the node's admin rpc returned %s for can_delete", resp.Status)
	}
	var out struct {
		Result struct {
			Status    string          `json:"status"`
			Error     string          `json:"error"`
			CanDelete json.RawMessage `json:"can_delete"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return AdvisoryLiveUnknown, fmt.Sprintf("the node's can_delete answer was not readable: %v", err)
	}
	switch {
	case out.Result.Error == "notEnabled":
		return AdvisoryLiveNotEnabled, "the node reports advisory delete is not enabled"
	case out.Result.Error != "":
		return AdvisoryLiveUnknown, fmt.Sprintf("the node refused can_delete: %s", out.Result.Error)
	case len(out.Result.CanDelete) > 0 && out.Result.Status == "success":
		return AdvisoryLiveEnabled, "the node reports advisory delete is enabled"
	}
	return AdvisoryLiveUnknown, "the node's can_delete answer named neither a value nor an error"
}
