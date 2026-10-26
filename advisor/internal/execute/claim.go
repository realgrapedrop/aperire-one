package execute

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/ledger"
)

// ── The run's claim on its approval (#1063) ─────────────────────────────
//
// An approval is consent to one change, used by one run, spent once. The
// spend has to wait for the end of the run: the per-step check (#1047) asks
// before every step whether the approval still stands, and a grant spent at
// the top would read as withdrawn at the first step. So the run claims the
// grant first, before its first step that changes the host, and the claim
// is what a second run finds: the command-line executor and the service
// share no lock in memory, and before this both could act on one grant.

// ErrClaimLost is a run whose approval stopped being its own mid-run: held
// by another run, or written again since this run claimed it.
var ErrClaimLost = errors.New("the approval is no longer this run's")

// How a stage leaves the grant it claimed, carried out on every return.
type settleMode int

const (
	// settleRelease gives the claim back, spending nothing: only the
	// rotation refusal, which comes before any step and tells the operator
	// their approval was not used.
	settleRelease settleMode = iota
	// settleKeep holds the claim for the next stage of the same run, or for
	// the caller's Finish, when the stage finished. A stop spends it.
	settleKeep
	// settleSpend spends it, win or lose.
	settleSpend
)

// spendClaimed is approval.SpendClaimed, a variable so a test can make the
// spend fail the way a grant this account can neither remove nor rewrite
// does.
var spendClaimed = approval.SpendClaimed

// ClaimRun is this run's claim value, made the first time it is needed and
// kept for the life of the Executor, so the stages of one merged run hold
// one claim between them.
func (e *Executor) ClaimRun() string {
	e.claimMu.Lock()
	defer e.claimMu.Unlock()
	return e.claimRunLocked()
}

func (e *Executor) claimRunLocked() string {
	if e.claimRun == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			e.claimRun = fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
		} else {
			e.claimRun = hex.EncodeToString(b[:])
		}
	}
	return e.claimRun
}

func (e *Executor) processLabel() string {
	name := e.ClaimedBy
	if name == "" {
		name = filepath.Base(os.Args[0])
	}
	return fmt.Sprintf("%s (pid %d)", name, os.Getpid())
}

// claimGrant makes the grant RunStage just verified this run's, or refuses
// the stage and says who holds it. Nothing has been done when it refuses,
// and the grant is left as it was: it is not this run's to spend.
func (e *Executor) claimGrant(stage string, a approval.Approval) error {
	c := approval.Claim{Run: e.ClaimRun(), Process: e.processLabel(), At: e.now().UTC()}
	if _, err := approval.ClaimGrant(e.ApprovalDir, e.PlanID, a.Stage, c, e.now()); err != nil {
		data := map[string]any{"stage": stage, "granted_scope": a.Stage, "error": err.Error(),
			"reason": "claim_failed"}
		var held *approval.ClaimedError
		if errors.As(err, &held) {
			data["reason"] = "approval_held"
			data["held_by"] = held.Holder.Process
			data["held_since"] = held.Holder.At
		}
		e.Ledger.AppendAs(ledger.KindRefusal, e.PlanID,
			"executor refused: stage "+stage+" did not run: "+err.Error(), data, actorFromApproval(a))
		return fmt.Errorf("stage %s: %w; nothing was done", stage, err)
	}
	e.claimMu.Lock()
	if e.claims == nil {
		e.claims = map[string]bool{}
	}
	e.claims[a.Stage] = true
	e.claimMu.Unlock()
	return nil
}

// takeClaim hands one claimed scope to whoever settles it, once: the stage
// on its way out, Finish, or Interrupt from a signal, whichever comes first.
func (e *Executor) takeClaim(scope string) (run string, ok bool) {
	e.claimMu.Lock()
	defer e.claimMu.Unlock()
	if !e.claims[scope] {
		return "", false
	}
	delete(e.claims, scope)
	return e.claimRunLocked(), true
}

// atStep records the step this stage is at, for the note a stop leaves on
// the approval it used.
func (e *Executor) atStep(name string) {
	e.claimMu.Lock()
	e.lastStep = name
	e.claimMu.Unlock()
}

// usedNote is what a stopped run leaves on the approval it spent (#1074
// review): the retry's refusal quotes it.
func (e *Executor) usedNote() string {
	e.claimMu.Lock()
	step := e.lastStep
	e.claimMu.Unlock()
	if step == "" {
		return "this approval was used by a run that stopped before its first step; approve again to retry"
	}
	return fmt.Sprintf("this approval was used by the run that stopped at %q; approve again to retry", step)
}

// stillHeld is the per-step half of the claim: the grant that answered the
// check is the one this run claimed.
func (e *Executor) stillHeld(a approval.Approval) error {
	switch {
	case a.Claim != nil && e.claimRun != "" && a.Claim.Run == e.claimRun:
		return nil
	case a.Claim != nil:
		return fmt.Errorf("%w: %w", ErrClaimLost, &approval.ClaimedError{Holder: *a.Claim})
	}
	return fmt.Errorf("%w: it carries no claim, so it was written again after this run claimed it", ErrClaimLost)
}

// settleGrant carries out how a stage leaves its grant, on its way out of
// RunStage, and joins anything that did not go as designed to what the
// stage returns.
func (e *Executor) settleGrant(stage, scope string, how settleMode, runErr error) error {
	switch {
	case how == settleRelease:
		run, ok := e.takeClaim(scope)
		if !ok {
			return runErr
		}
		if err := approval.ReleaseClaim(e.ApprovalDir, e.PlanID, scope, run); err != nil {
			// Still this run's claim, and it lapses with the approval's own
			// window. Said, because the operator was told it was not used.
			e.Log.Write("note", "", "this run's claim on the approval could not be given back ("+
				err.Error()+"), so it cannot be used again until it lapses")
		}
		return runErr
	case runErr != nil:
		// A stop. The approval is used, and the retry is told where.
		// Not over a lapse: that approval had already expired or been
		// withdrawn, and the stop says which.
		note := e.usedNote()
		var lapse *ConsentLapsedError
		if errors.As(runErr, &lapse) {
			note = ""
		}
		if err := e.spendOwn(stage, scope, note); err != nil {
			return errors.Join(runErr, err)
		}
		if note != "" {
			return fmt.Errorf("%w; %s", runErr, note)
		}
	case how == settleSpend:
		if err := e.spendOwn(stage, scope, ""); err != nil {
			return err
		}
	}
	return runErr
}

// spendOwn spends one grant this run claimed, and says so when the spend
// did not go as designed (#1061). A grant voided in place authorises
// nothing more, and that is a note. A grant that could be neither removed
// nor voided still authorises what it was granted for: that is a ledger row
// and an error the caller has to stop on, naming when it lapses.
func (e *Executor) spendOwn(stage, scope, note string) error {
	run, ok := e.takeClaim(scope)
	if !ok {
		return nil
	}
	e.claimMu.Lock()
	e.used = true
	e.claimMu.Unlock()
	err := spendClaimed(e.ApprovalDir, e.PlanID, scope, run, note)
	if err == nil {
		return nil
	}
	if !errors.Is(err, approval.ErrStillLive) {
		e.Log.Write("note", "", "the approval could not be removed, so it was voided in place and "+
			"authorises nothing more: "+err.Error())
		return nil
	}
	until := "it expires"
	if a, found, perr := approval.Peek(e.ApprovalDir, e.PlanID, scope); perr == nil && found {
		until = a.ExpiresAt.UTC().Format("15:04 MST")
	}
	e.record(ledger.KindRefusal, "the approval could not be spent and stays live until "+until,
		map[string]any{"stage": stage, "granted_scope": scope, "reason": "spend_failed",
			"error": err.Error()})
	// Named by what the grant was given for, not by the stage that failed to
	// spend it: a compound grant that a stopped prepare could not spend still
	// pays for the cutover, and "do not run another prepare" would say the
	// wrong thing about what it is still good for.
	return fmt.Errorf("the approval for this %s could not be spent, and it stays live until %s: "+
		"do not run another %s of this node before then (%w)", scope, until, scope, err)
}

// Finish spends every grant this run claimed and has not spent. A caller
// whose run stops between the stages of a merged run calls it before it
// writes the stop: the run is over, and the grant was consent to it alone.
// Idempotent, and a no-op for a run whose last stage already spent its
// grant.
func (e *Executor) Finish() error {
	e.claimMu.Lock()
	scopes := make([]string, 0, len(e.claims))
	for s := range e.claims {
		scopes = append(scopes, s)
	}
	e.claimMu.Unlock()
	sort.Strings(scopes)
	note := e.usedNote()
	var errs []error
	for _, s := range scopes {
		if err := e.spendOwn(s, s, note); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Interrupt settles the run's approval when the process is told to stop
// (#1074 review, L3): Ctrl-C at a confirm prompt or during a build used to
// leave the claim, and the next approval of the plan was refused naming a
// dead process until the claim lapsed. A run interrupted is a run that
// stopped, so its approval is spent, with the note, and the sentence says
// so. Safe to call from a signal handler while the run is still going: each
// claim is settled once, by whichever gets to it first.
//
// When a step had changed the deployment, the way back is printed with it
// (#1074 review): an interrupt after the deployment was pointed at a new
// image leaves it staged, and the operator needs the restore in front of
// them, not only in a transcript.
func (e *Executor) Interrupt() string {
	e.claimMu.Lock()
	held, used := len(e.claims) > 0, e.used
	e.claimMu.Unlock()
	var said string
	switch {
	case held:
		if err := e.Finish(); err != nil {
			said = "Interrupted. " + err.Error()
		} else {
			said = "Interrupted. " + strings.ToUpper(e.usedNote()[:1]) + e.usedNote()[1:] + "."
		}
	case used:
		// The stage already spent it, a restart's wait after the cutover
		// say: it was used, by this run, before the interrupt.
		said = "Interrupted. This run had already used its approval; approve again for another run."
	default:
		said = "Interrupted. This run held no approval, so nothing was used."
	}
	if h := e.RollbackHint(); h != "" {
		said += "\n\nThis run changed the deployment before it stopped. The way back:\n" + h
	}
	return said
}
