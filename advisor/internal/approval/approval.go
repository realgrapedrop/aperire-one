// Package approval is the per-action consent — ADR 0007 §6, scoped and
// expiring.
//
// An approval binds to one plan on one node and dies on a clock. That is the
// difference between "yes, upgrade this node to 3.2.1 now" and "yes, upgrade
// things". A standing yes is what turns an assistant into an unsupervised
// process, and the scoping here is what stops an approval granted for a
// blocked upgrade from being spent on a different one an hour later.
//
// The binding is to the plan's FINGERPRINT, not its identifier. Two plans with
// the same ID and different parameters are different plans, and an approval
// that survived a parameter change would approve something nobody read.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aperire-advisor/internal/webauthn"
)

// Approval is one operator consent.
type Approval struct {
	PlanID      string `json:"plan_id"`
	Fingerprint string `json:"fingerprint"`
	RunbookID   string `json:"runbook_id"`
	Node        string `json:"node"`
	GrantedBy   string `json:"granted_by"`
	// GrantedByRole is what GrantedBy was allowed to do at the moment of the
	// ceremony, as the granting service recorded it. A claim, not a proof —
	// the assertion signs a challenge, not this file's contents — and the
	// ledger labels it as one. Kept because role is ENFORCED everywhere and
	// RECORDED nowhere, so a demotion afterwards makes the past
	// unreconstructable: "was the person who restarted this node an admin at
	// the time" has no answer without it.
	GrantedByRole string    `json:"granted_by_role,omitempty"`
	GrantedAt     time.Time `json:"granted_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	// Stage lets a single plan be approved in parts. The reversible steps of an
	// upgrade and the restart that interrupts validation are different
	// decisions, and collapsing them into one yes is how an operator ends up
	// having authorised an outage they were not thinking about.
	Stage string `json:"stage"`
	// Reason is the operator's own words. Optional, and the ledger keeps it.
	Reason string `json:"reason,omitempty"`

	// Assertion is the passkey signature that produced this approval.
	//
	// An approval used to be authorised by existing: anything that could write
	// the file, or reach the service that writes it, produced one. Carrying
	// the assertion means the authority is a physical touch rather than a file
	// on disk, so neither a stolen service token nor a direct write is enough.
	// Verified by the executor against a credential list it holds itself —
	// see internal/webauthn.
	Assertion *webauthn.Assertion `json:"assertion,omitempty"`
	// Challenge the assertion was signed over, so the verifier does not have
	// to be told it by the caller.
	Challenge string `json:"challenge,omitempty"`
	// Origin the ceremony ran on, recorded for the ledger.
	Origin string `json:"origin,omitempty"`

	// Source and Digest are where the approved plan's image came from and
	// the digest it was pinned to, copied from its bound parameters when
	// the grant is written (#1033). Both are node-derived, never asked of
	// the operator, so a run that derives them again can find they moved.
	// They name what was approved in that refusal, and nothing else: a run
	// takes them as the approved plan's only after recomputing Fingerprint
	// with them, which a hand-edited value does not survive.
	Source string `json:"source,omitempty"`
	Digest string `json:"digest,omitempty"`

	// SpentAt is set when a spend could not remove the file and voided it
	// in place instead (#781). A voided grant authorises nothing.
	SpentAt *time.Time `json:"spent_at,omitempty"`
	// SpentNote says what used it, when a run that stopped spent it: the
	// refusal of a retry quotes it, so the operator reads "used by the run
	// that stopped at <step>" rather than a bare "not approved".
	SpentNote string `json:"spent_note,omitempty"`

	// Claim is the run this grant belongs to (#1063), set before that run's
	// first step that changes the host. See ClaimGrant.
	Claim *Claim `json:"claim,omitempty"`
}

// Claim marks a grant as belonging to one run. An approval is consent to one
// change, used by one run, and the spend that retires it comes at the end of
// that run. The claim is what makes the grant that run's before it acts: a
// second run, in this process or another, finds it and refuses.
//
// Run is a random value the run makes for itself, never its transcript id:
// that id is the plan and the stage, so the command-line tool and the
// service would compute the same one for the same grant. Process and At are
// for the refusal a second run gives, so it can say who holds the grant.
type Claim struct {
	Run     string    `json:"run"`
	Process string    `json:"process"`
	At      time.Time `json:"at"`
}

// claimLapsed is a claim older than the approval's own window. The run that
// made it did not settle it (it was killed, or its host went down), and
// nothing else may: it counts as spent. Because a claim is never made before
// the grant was, a lapsed claim is always on an expired grant as well, so
// this changes which refusal is given, never whether one is.
func (a Approval) claimLapsed(now time.Time) bool {
	if a.Claim == nil {
		return false
	}
	return now.After(a.Claim.At.Add(a.ExpiresAt.Sub(a.GrantedAt)))
}

// ClaimedError is a grant another run holds, and when that claim lapses.
//
// The refusal says both, and the way out (#1074 review, L3): a run killed
// mid-stage (Ctrl-C at the command line, a host that went down) leaves its
// claim, and an operator told only "approve again once that run has
// finished" would wait on a process that no longer exists.
type ClaimedError struct {
	Holder Claim
	Lapses time.Time
}

func claimedBy(a Approval) *ClaimedError {
	return &ClaimedError{Holder: *a.Claim, Lapses: a.Claim.At.Add(a.ExpiresAt.Sub(a.GrantedAt))}
}

func (e *ClaimedError) Error() string {
	msg := fmt.Sprintf("%v: %s claimed it at %s", ErrClaimed, e.Holder.Process,
		e.Holder.At.UTC().Format("15:04:05 MST"))
	if !e.Lapses.IsZero() {
		msg += fmt.Sprintf(". That claim lapses at %s; if that run is no longer going, withdraw the approval "+
			"in the Advisor tab and approve again", e.Lapses.UTC().Format("15:04:05 MST"))
	}
	return msg
}

func (e *ClaimedError) Unwrap() error { return ErrClaimed }

// Stages.
const (
	StagePrepare = "prepare" // everything reversible, no interruption
	StageCutover = "cutover" // the step that restarts the node

	// StageInvestigate is break glass — plan-interrogative-loop §11.3. It
	// authorises READING, not acting: opening a bounded window in which the
	// interrogative loop runs at raised ceilings. This is the whole change
	// this design makes to the approval package — Check, Grant, Spend and
	// NonceStore are already parameterised by stage and need none.
	StageInvestigate = "investigate"

	// StageUpgrade is the one-approval scope for the upgrade runbook's web
	// path: one ceremony, naming "upgrade" as what it signs over, that
	// authorises prepare and then cutover in sequence — see Covers.
	//
	// This is a distinct SCOPE, not a shorthand for calling Grant twice from
	// one ceremony. Two grants from one prepare-bound assertion would leave
	// the cutover file carrying a Challenge that was minted for "prepare" —
	// byte-indistinguishable from the exact forgery nonce.go's binding
	// exists to stop ("a captured 'I approve prepare' could be resubmitted
	// as 'I approve the cutover' and it verified"). A compound grant instead
	// asks the operator to sign over "upgrade" itself: the nonce is issued
	// and consumed for that scope, so what was actually signed names what
	// was actually granted.
	StageUpgrade = "upgrade"

	// StageConfig is RB-003's first stage — ADR 0018. The edit itself:
	// a dated backup the wrapper cannot be told to skip, one allow-listed
	// key rewritten, the result verified. Reversible, and the node keeps
	// validating throughout.
	StageConfig = "config"

	// StageConfigRestart is RB-003's compound scope, mirroring StageUpgrade
	// exactly and for the same reason — see Covers.
	//
	// One ceremony that names "config-restart" as what it signs over, and
	// covers the edit and then the restart in sequence. Two grants minted
	// from one assertion would leave the restart's file carrying a challenge
	// issued for "config", which is byte-indistinguishable from the forgery
	// nonce.go exists to stop.
	//
	// It is compound because the two halves are one decision. Every key on
	// the allow-list is read by the node at startup, so an edit approved on
	// its own leaves the node running one configuration and holding another,
	// and asking for a second passkey in that gap is asking the operator to
	// authorise the half that does nothing and then the half that does.
	StageConfigRestart = "config-restart"

	// StageRestart is RB-002's single stage — ADR 0016. One stage over two,
	// because a restart has no reversible half to separate from the outage.
	//
	// Covers is deliberately NOT extended for it. A restart approval covers a
	// restart and nothing else: the compound "upgrade" scope covers prepare
	// and cutover because they are one sequence one ceremony authorised, and
	// a restart is not part of that sequence. The fingerprint hashes the
	// runbook ID as well, so a restart approval and a cutover approval can
	// never collide even before Covers is consulted — two independent locks,
	// which is why reusing "cutover" for this was rejected.
	StageRestart = "restart"

	// StageRollback is RB-004's single stage — ADR 0019. One stage for the
	// reason the restart has one: the rollback IS the restart, and a
	// reversible half split off it would leave the deployment naming one
	// version while the node runs another.
	//
	// It appears in no compound scope and covers nothing but itself. A
	// rollback changes the running version, which is the same class of act an
	// upgrade's cutover is — and that is exactly why it must not be reachable
	// from an upgrade's grant: an operator who approved going to 3.3.0 did not
	// approve going back to 3.2.0, and the two are separate ceremonies with
	// separate confirm codes. The fingerprint hashes the runbook ID as well,
	// so the two are different plans before Covers is ever consulted.
	StageRollback = "rollback"
)

// compoundScopes maps each compound grant to the concrete stages it covers,
// in the order it runs them.
//
// A table rather than a chain of ORs, because Check needs the same knowledge
// in reverse — "which compound grant might satisfy this request" — and two
// hand-written directions of one relation is how they end up disagreeing.
// Membership here is what makes a scope compound; nothing else keys off it.
var compoundScopes = map[string][]string{
	StageUpgrade:       {StagePrepare, StageCutover},
	StageConfigRestart: {StageConfig, StageRestart},
}

// Covers reports whether an approval granted for scope `granted` authorises
// acting under `requested`. Equal scopes always cover each other. A compound
// grant additionally covers each of the concrete stages it runs in sequence —
// that is its entire purpose. Nothing else covers anything else: a prepare
// grant does not cover cutover, on purpose, for the reason StageUpgrade's own
// doc states, and a config-restart grant does not cover a cutover because
// cutover is not one of the stages it names.
//
// Note what the table does NOT do: StageRestart appears under
// StageConfigRestart and is also RB-002's whole stage, so a config-restart
// grant covers "restart" by name. It cannot be spent on an RB-002 restart
// anyway — Check compares the fingerprint, and the fingerprint hashes the
// runbook ID, so the two are different plans with different plan_ids before
// Covers is ever consulted. Two independent locks, and the tests assert both.
func Covers(granted, requested string) bool {
	if granted == requested {
		return true
	}
	for _, stage := range compoundScopes[granted] {
		if stage == requested {
			return true
		}
	}
	return false
}

// compoundFor lists the compound scopes that could satisfy a request for one
// concrete stage. Empty when the stage is itself compound: a compound grant
// is never satisfied by another compound grant, and looking for one would be
// the beginning of a scope hierarchy nobody decided to have.
func compoundFor(stage string) []string {
	if _, itself := compoundScopes[stage]; itself {
		return nil
	}
	var out []string
	for scope, covered := range compoundScopes {
		for _, c := range covered {
			if c == stage {
				out = append(out, scope)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Fingerprint identifies a plan by what it would do, not by what it is called.
func Fingerprint(runbookID, node string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|", runbookID, node)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s;", k, params[k])
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// InvestigationFingerprint wraps Fingerprint for break glass —
// plan-interrogative-loop §11.3. "investigate" plays the role a runbook ID
// plays elsewhere; there is no runbook, because nothing here performs an
// action.
//
// scope is always "window" in v1 (§11.3a) but is carried as a real parameter
// rather than hardcoded into the hash, so a hypothetical narrower or wider
// grant in a later version produces a DIFFERENT confirm code from this one —
// an operator can never be shown one and handed the other.
//
// trigger_sha256 NAMES the break; it does not constrain it (§11.3). A
// follow-up asked inside an already-open window is not fingerprinted against
// this value at all — /v1/investigate/continue re-checks the window's four
// bounds, never the trigger hash. Recomputing this fingerprint for a
// follow-up would silently turn the naming field into a constraint field,
// which is exactly the misreading §11.3 warns about twice.
func InvestigationFingerprint(offerID, question, node string) string {
	return Fingerprint("investigate", node, map[string]string{
		"scope":          "window",
		"offer_id":       offerID,
		"trigger_sha256": normaliseQuestionHash(question),
	})
}

// normaliseQuestionHash is deliberately simple — trim and lower-case before
// hashing — because this hash NAMES the trigger for cross-checking, it does
// not need to be a canonical semantic fingerprint of the question. See
// InvestigationFingerprint.
func normaliseQuestionHash(q string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(q))))
	return hex.EncodeToString(h[:])
}

var (
	ErrNone      = fmt.Errorf("no approval")
	ErrExpired   = fmt.Errorf("approval expired")
	ErrMismatch  = fmt.Errorf("approval is for a different plan")
	ErrWrongNode = fmt.Errorf("approval is for a different node")
	ErrUnsigned  = fmt.Errorf("approval carries no passkey assertion")
	ErrBadProof  = fmt.Errorf("approval's passkey assertion does not verify")
	// ErrSpent is a grant a spend voided in place because the file could
	// not be removed (#781).
	ErrSpent = fmt.Errorf("approval was already spent")
	// ErrSpendFailed is a spend that could not remove the grant. Whether
	// it was voided in place is in the message, and Check says the rest.
	ErrSpendFailed = fmt.Errorf("the approval could not be spent")
	// ErrStillLive is the part of a failed spend that matters most: the
	// grant could be neither removed nor voided, so it still authorises
	// what it was granted for until it expires.
	ErrStillLive = fmt.Errorf("it stays live until it expires")
	// ErrClaimed is a grant another run holds (#1063).
	ErrClaimed = fmt.Errorf("the approval is held by another run")
	// ErrClaimFailed is a claim that could not be written. The run does
	// not act on a grant it could not mark as its own.
	ErrClaimFailed = fmt.Errorf("the approval could not be claimed for this run")
)

// Verifier checks an assertion against credentials it holds itself.
//
// An interface, so the credentials come from the Advisor's own state rather
// than from whoever is presenting the approval — a verifier that accepts the
// public key alongside the signature is checking that the attacker can do
// arithmetic. The real one is in internal/host; webauthn_test exercises the
// crypto against a genuine signature.
type Verifier interface {
	Verify(a webauthn.Assertion, challenge string) error
}

// readGrant reads one approval file by its own literal scope name — the
// exact string an approval was Grant-ed under, never a fallback. Kept
// separate from Check so the fallback in Check reads as what it is: a second
// lookup, not a different meaning for the first one.
func readGrant(dir, planID, scope string) (Approval, error) {
	return readFile(grantPath(dir, planID, scope))
}

// Check returns the approval for this stage, or an error explaining the
// refusal. Every failure mode is distinct, because "you never approved this"
// and "your approval ran out four minutes ago" call for different responses
// from the operator reading it.
//
// It looks first for a grant made exactly for stage, then — for a concrete
// stage only, never when stage is itself a compound scope — falls back to
// each compound grant that names stage among what it covers. The fallback is
// a second file lookup, not a looser equality: Covers still decides, and a
// grant for one stage never satisfies a request for another.
func Check(dir, planID, fingerprint, node, stage string, now time.Time) (Approval, error) {
	defer readLock(dir)()
	a, err := readGrant(dir, planID, stage)
	if err != nil {
		if !os.IsNotExist(err) {
			return Approval{}, err
		}
		found := false
		for _, scope := range compoundFor(stage) {
			a, err = readGrant(dir, planID, scope)
			if err == nil {
				found = true
				break
			}
			if !os.IsNotExist(err) {
				return Approval{}, err
			}
		}
		if !found {
			return Approval{}, fmt.Errorf("%w for plan %s stage %s", ErrNone, planID, stage)
		}
	}
	if a.SpentAt != nil {
		if a.SpentNote != "" {
			return Approval{}, fmt.Errorf("%w: %s", ErrSpent, a.SpentNote)
		}
		return Approval{}, fmt.Errorf("%w at %s for plan %s", ErrSpent, a.SpentAt.Format(time.RFC3339), planID)
	}
	if a.Node != node {
		return Approval{}, fmt.Errorf("%w: granted for %q, running against %q", ErrWrongNode, a.Node, node)
	}
	if a.Fingerprint != fingerprint {
		return Approval{}, fmt.Errorf("%w: the plan's parameters changed after it was approved", ErrMismatch)
	}
	if !Covers(a.Stage, stage) {
		return Approval{}, fmt.Errorf("%w: approval is for stage %q, not %q", ErrMismatch, a.Stage, stage)
	}
	if now.After(a.ExpiresAt) {
		return Approval{}, fmt.Errorf("%w: granted %s, expired %s ago",
			ErrExpired, a.GrantedAt.Format(time.RFC3339), now.Sub(a.ExpiresAt).Round(time.Second))
	}
	// After expiry, on purpose: a claim is never older than its grant, so a
	// lapsed one is on an expired grant, and "expired" is the refusal the
	// run holding it should read. This one is for a file whose times were
	// written by hand.
	if a.claimLapsed(now) {
		return Approval{}, fmt.Errorf("%w: %s claimed it at %s and never finished, and a claim older "+
			"than the approval's own window counts as spent", ErrSpent, a.Claim.Process,
			a.Claim.At.UTC().Format(time.RFC3339))
	}
	return a, nil
}

// CheckSigned is Check plus proof. Use this wherever an approval is about to
// authorise something: it is the difference between "a file says you approved"
// and "a passkey was touched".
//
// A nil Verifier is refused rather than skipped. An unverifiable approval and
// an unverified one look the same from the outside, and defaulting to trust
// would make every deployment without a credential store silently weaker than
// it reads.
func CheckSigned(dir, planID, fingerprint, node, stage string, now time.Time, v Verifier) (Approval, error) {
	a, err := Check(dir, planID, fingerprint, node, stage, now)
	if err != nil {
		return Approval{}, err
	}
	if v == nil {
		return Approval{}, fmt.Errorf("%w: no credential store to check it against", ErrBadProof)
	}
	if a.Assertion == nil || a.Challenge == "" {
		return Approval{}, fmt.Errorf("%w", ErrUnsigned)
	}
	if err := v.Verify(*a.Assertion, a.Challenge); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrBadProof, err)
	}
	return a, nil
}

// Grant writes an approval.
//
// Never over a grant a run holds (#1063). Two ceremonies for one plan and
// stage write one file, and a second grant written over the first while a
// run is acting on it would hand that run's approval to whoever runs next,
// and have that run's spend retire a grant it never claimed.
func Grant(dir string, a Approval) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	unlock, err := writeLock(dir)
	if err != nil {
		return "", err
	}
	defer unlock()
	path := grantPath(dir, a.PlanID, a.Stage)
	if old, rerr := readFile(path); rerr == nil && old.SpentAt == nil && old.Claim != nil &&
		!old.claimLapsed(time.Now()) {
		return "", claimedBy(old)
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, append(b, '\n'), 0o640)
}

// Spend removes an approval once it has been acted on, so a second run cannot
// reuse it. Expiry alone is not enough: an approval granted for fifteen
// minutes would otherwise authorise two cutovers inside that window.
//
// A spend that cannot remove the file does not leave the grant live (#781).
// It voids the file in place, so Check refuses it, and still returns an
// error wrapping ErrSpendFailed: the caller decides what a spend that did
// not go as designed means for the act it was paying for. Removing needs
// the directory writable and voiding needs only the file, so one can work
// where the other did not. When neither does, the error wraps ErrStillLive
// as well.
//
// Whoever holds it: this is the spend a cancel or an adoption makes. A run
// retires its own grant with SpendClaimed.
func Spend(dir, planID, stage string) error {
	unlock := lockOrNot(dir)
	defer unlock()
	_, err := spendFile(grantPath(dir, planID, stage))
	return err
}

// SpendClaimed retires a grant the run holding claim run made its own, and
// nothing else (#1063). A grant that is gone, or that no longer carries
// this run's claim, is not this run's to spend, and is left alone: it was
// cancelled, or it is a new grant written after this run's claim lapsed.
//
// note is for a run that stopped: the grant is voided in place with it, so a
// retry's refusal says what used the approval. Removed only when it cannot
// be rewritten. An empty note spends it the way Spend does.
func SpendClaimed(dir, planID, stage, run, note string) error {
	unlock := lockOrNot(dir)
	defer unlock()
	path := grantPath(dir, planID, stage)
	a, err := readFile(path)
	if err != nil || a.SpentAt != nil || a.Claim == nil || a.Claim.Run != run {
		return nil
	}
	if note != "" {
		now := time.Now().UTC()
		a.SpentAt, a.SpentNote = &now, note
		if rewrite(path, a) == nil {
			return nil
		}
	}
	_, err = spendFile(path)
	return err
}

// spendFile is Spend's own logic, for a caller already holding the lock.
// live is true only when the grant could be neither removed nor voided.
func spendFile(path string) (live bool, err error) {
	rerr := removeFile(path)
	if rerr == nil || os.IsNotExist(rerr) {
		return false, nil
	}
	if verr := voidWrite(path); verr != nil {
		return true, fmt.Errorf("%w: %s could not be removed (%v) or voided in place (%v); %w",
			ErrSpendFailed, filepath.Base(path), rerr, verr, ErrStillLive)
	}
	return false, fmt.Errorf("%w: %s could not be removed (%v); it was voided in place and "+
		"authorises nothing", ErrSpendFailed, filepath.Base(path), rerr)
}

// removeFile is os.Remove, a variable so a test can make a spend fail the
// way a read-only directory does, as root as well.
var removeFile = os.Remove

// Void marks one grant spent in place, without removing it: Check refuses
// it from then on. Spend falls back to it; a caller that has to make a grant
// unusable when it cannot be removed can call it directly.
func Void(dir, planID, stage string) error {
	unlock := lockOrNot(dir)
	defer unlock()
	return voidFile(grantPath(dir, planID, stage))
}

// voidFile rewrites a grant in place with SpentAt set. Truncating the
// existing file, never creating one: a spend of a grant that is not there
// has nothing to void.
func voidFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var a Approval
	if err := json.Unmarshal(raw, &a); err != nil {
		// Unreadable as an approval already refuses in Check. Emptying it
		// keeps it that way whatever it held.
		return writeInPlace(path, nil)
	}
	now := time.Now().UTC()
	a.SpentAt = &now
	return rewrite(path, a)
}

// voidWrite is voidFile, a variable so a test can make the fallback fail
// too, the way a grant file this account cannot write does.
var voidWrite = voidFile

// Peek reads an approval without removing it — a look, not a spend. Cancel
// uses this to report what it actually cleared rather than a bare "ok", and
// to tell "there was nothing to cancel" from "cancelled" honestly.
func Peek(dir, planID, stage string) (Approval, bool, error) {
	defer readLock(dir)()
	a, err := readFile(grantPath(dir, planID, stage))
	if os.IsNotExist(err) {
		return Approval{}, false, nil
	}
	if err != nil {
		return Approval{}, false, err
	}
	return a, true, nil
}

// Withdraw is a cancel of one grant: look, and if it still authorises
// anything, retire it, as one act under the lock (#1061). Two cancels of one
// grant at the same moment used to both find it with Peek and both write a
// ledger row for one withdrawal. Only the call that withdrew it is told so.
//
// withdrew is true when this call left the grant authorising nothing, by
// removing it or voiding it in place; err says how, when it was not a plain
// removal. A grant still live afterwards is withdrew false with an error
// wrapping ErrStillLive. A grant a run holds is withdrawn all the same: a
// cancel is what stops that run at its next step.
func Withdraw(dir, planID, stage string, now time.Time) (a Approval, withdrew bool, err error) {
	unlock := lockOrNot(dir)
	defer unlock()
	path := grantPath(dir, planID, stage)
	a, err = readFile(path)
	if os.IsNotExist(err) {
		return Approval{}, false, nil
	}
	if err != nil {
		return Approval{}, false, err
	}
	if a.SpentAt != nil || a.claimLapsed(now) {
		return a, false, nil
	}
	live, err := spendFile(path)
	return a, !live, err
}

// StillLiveError names the grants a cancel could neither remove nor void.
type StillLiveError struct{ Grants []Approval }

func (e *StillLiveError) Error() string {
	var names []string
	for _, a := range e.Grants {
		names = append(names, fmt.Sprintf("%s stage %s (until %s)", a.PlanID, a.Stage,
			a.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	return fmt.Sprintf("%v: %d approval%s could not be removed or voided and still authorise what they "+
		"were granted for: %s", ErrStillLive, len(e.Grants), plural(len(e.Grants)), strings.Join(names, "; "))
}

func (e *StillLiveError) Unwrap() []error { return []error{ErrSpendFailed, ErrStillLive} }

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// CancelAllByUser withdraws every approval one operator granted that still
// authorises anything, across every plan and stage: the shape logout needs,
// since the operator signing out may not remember which stage they last
// approved, and a standing approval left behind is a standing approval
// regardless of what page granted it.
//
// Each is withdrawn the way Withdraw withdraws one (#1061): removed, voided
// in place when it cannot be removed, and returned in the error when it can
// be neither, so the caller never reports a logout as having cleared a grant
// that is still live. One unreadable file does not stop the rest. Grants
// already spent are skipped, so a cancel never records a withdrawal twice.
func CancelAllByUser(dir, grantedBy string) ([]Approval, error) {
	unlock := lockOrNot(dir)
	defer unlock()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out, live []Approval
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		a, err := readFile(path)
		if err != nil || a.GrantedBy != grantedBy || a.SpentAt != nil || a.claimLapsed(now) {
			continue
		}
		if still, _ := spendFile(path); still {
			live = append(live, a)
			continue
		}
		out = append(out, a)
	}
	if len(live) > 0 {
		return out, &StillLiveError{Grants: live}
	}
	return out, nil
}

// LiveFor lists the unexpired approvals for one runbook on one node that
// cover a stage, whatever plan they were granted for. A look, never a spend.
//
// The question it answers is the run's (#1029): there is no approval for the
// plan this node derives now, so did the operator approve ANOTHER plan for
// the same act? If so the node's answer moved between the approval and the
// run, and that is what the refusal has to say. "You never approved this"
// would send the operator to approve something they already approved.
//
// Unreadable files are skipped: this only chooses which refusal to give, and
// the run is refused either way.
func LiveFor(dir, runbookID, node, stage string, now time.Time) []Approval {
	defer readLock(dir)()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Approval
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		a, err := readFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if a.RunbookID != runbookID || a.Node != node || !Covers(a.Stage, stage) || now.After(a.ExpiresAt) ||
			a.SpentAt != nil || a.claimLapsed(now) {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantedAt.After(out[j].GrantedAt) })
	return out
}
