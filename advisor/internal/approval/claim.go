package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ── One run per grant, and one lock for every change to a grant (#1063) ──
//
// The service and the command-line executor both act on the grants in one
// directory, and nothing used to make them take turns: the service's run
// lock lives in its own memory. So every change to a grant file is made
// under one lock file in the approvals directory, held with flock, which
// two processes, or two opens in one process, cannot both hold for writing.
//
// A separate file, never the grant itself. A spend removes the grant, and a
// waiter holding the removed file's lock would wake up holding nothing,
// read the grant as it stood before the claim it was waiting behind, and
// claim it too.
//
// Grants are rewritten in place, never replaced with a new file: the
// command-line tool runs as the service's account by design, and a file
// replaced by any other account would stop being one the service can void.

const lockName = ".lock"

func grantPath(dir, planID, stage string) string {
	return filepath.Join(dir, planID+"."+stage+".json")
}

// lockFile takes the grants lock, shared for a read and exclusive for a
// change.
//
// Never as root (#1074 review, L1). Approvals are the service account's, and
// both programs run as it; a root process making or chowning a file at a
// name that account controls is how a link planted there becomes the
// account's own copy of a root file. The name is opened without following a
// link, and has to be a regular file with one name before anything else.
// Owner-only, set on the open file every time: a lock any other account can
// open is a lock that account can hold against every approval (L2).
//
// The wait is bounded (L2). A lock held past lockWait is refused, never
// waited out: a stuck holder must not freeze the per-step check of a run in
// flight, the command-line recovery path, or logout's cancel.
func lockFile(dir string, exclusive bool) (func(), error) {
	if geteuid() == 0 {
		return nil, ErrRoot
	}
	f, err := os.OpenFile(filepath.Join(dir, lockName),
		os.O_RDONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("%s is not a plain file with one name, so it is not used as the approvals lock", lockName)
	}
	if fi.Mode().Perm() != 0o600 {
		_ = f.Chmod(0o600)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	deadline := time.Now().Add(lockWait)
	for {
		err = syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrLockHeld
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// lockWait is how long a caller waits for the grants lock before it is
// refused. A variable so a test can shorten it.
var lockWait = 5 * time.Second

// geteuid is os.Geteuid, a variable so a test can stand in for root.
var geteuid = os.Geteuid

var (
	// ErrLockHeld is the grants lock held past lockWait.
	ErrLockHeld = fmt.Errorf("another run holds the approvals lock and did not let it go; nothing was " +
		"changed, try again in a moment")
	// ErrRoot is a change to an approval asked of root. Approvals belong to
	// the Advisor's own account; run the command-line tool as that account.
	ErrRoot = fmt.Errorf("approvals are handled by the Advisor's own account, never root: run this as that " +
		"account (sudo -u <advisor account>)")
)

// writeLock is the lock a claim and a grant need. Neither goes ahead
// without it.
func writeLock(dir string) (func(), error) { return lockFile(dir, true) }

// lockOrNot is the lock a spend or a cancel takes. Neither waits on a
// directory that cannot hold a lock file: a spend that runs anyway is the
// one that leaves nothing live, and that matters more than the order of
// two cancels.
func lockOrNot(dir string) func() {
	if unlock, err := lockFile(dir, true); err == nil {
		return unlock
	}
	return func() {}
}

// readLock is a reader's lock, so a read never sees a grant half rewritten.
// A read that cannot take it reads anyway: a half-written file fails to
// parse, and a grant that fails to parse authorises nothing.
func readLock(dir string) func() {
	if unlock, err := lockFile(dir, false); err == nil {
		return unlock
	}
	return func() {}
}

func readFile(path string) (Approval, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Approval{}, err
	}
	var a Approval
	if err := json.Unmarshal(raw, &a); err != nil {
		return Approval{}, fmt.Errorf("approval %s: %w", path, err)
	}
	return a, nil
}

// rewrite writes a grant back over itself.
func rewrite(path string, a Approval) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writeInPlace(path, append(b, '\n'))
}

// writeInPlace truncates the existing file and writes it, never creating
// one: the file keeps its owner and its mode.
func writeInPlace(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ClaimGrant makes the grant filed under scope this run's, before the run's
// first step that changes the host (#1063).
//
// One run per grant: a grant another run holds is refused with a
// ClaimedError naming that run's process and when it claimed. The same run
// asking again (the second stage of a merged run) is answered with the grant
// and nothing is written. A claim older than the grant's own window counts
// as spent, and so does a voided grant. A claim that cannot be written is
// refused: a run does not act on a grant it could not mark as its own.
//
// The caller has already checked the grant. This only decides who has it.
func ClaimGrant(dir, planID, scope string, c Claim, now time.Time) (Approval, error) {
	if geteuid() == 0 {
		return Approval{}, fmt.Errorf("%w: %w", ErrClaimFailed, ErrRoot)
	}
	unlock, err := writeLock(dir)
	if err != nil {
		return Approval{}, fmt.Errorf("%w: %w", ErrClaimFailed, err)
	}
	defer unlock()
	path := grantPath(dir, planID, scope)
	a, err := readFile(path)
	switch {
	case os.IsNotExist(err):
		return Approval{}, fmt.Errorf("%w for plan %s stage %s", ErrNone, planID, scope)
	case err != nil:
		return Approval{}, err
	case a.SpentAt != nil:
		return Approval{}, fmt.Errorf("%w at %s for plan %s", ErrSpent, a.SpentAt.Format(time.RFC3339), planID)
	case a.claimLapsed(now):
		return Approval{}, fmt.Errorf("%w: %s claimed it at %s and never finished, and a claim older "+
			"than the approval's own window counts as spent", ErrSpent, a.Claim.Process,
			a.Claim.At.UTC().Format(time.RFC3339))
	case a.Claim != nil && a.Claim.Run == c.Run:
		return a, nil
	case a.Claim != nil:
		return Approval{}, &ClaimedError{Holder: *a.Claim}
	}
	claimPause()
	a.Claim = &c
	if err := rewrite(path, a); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrClaimFailed, err)
	}
	return a, nil
}

// claimPause runs between a claim's read and its write. A test widens that
// gap with it, so two claimers that do not exclude each other both get
// through it, and a test that should refuse one of them fails.
var claimPause = func() {}

// ReleaseClaim gives a grant back unspent: the one stop that promises the
// operator their approval was not used, a run refused before its first step
// because the ledger store is rotating (#93). Only the run holding the claim
// can release it.
func ReleaseClaim(dir, planID, scope, run string) error {
	unlock, err := writeLock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	path := grantPath(dir, planID, scope)
	a, err := readFile(path)
	if err != nil || a.SpentAt != nil || a.Claim == nil || a.Claim.Run != run {
		return nil
	}
	a.Claim = nil
	return rewrite(path, a)
}

// HeldAny is HeldBy for every grant of one plan, whatever its stage: what
// a cancel of the plan asks, since any run of it could be the one a
// restored deployment file lands under.
func HeldAny(dir, planID string, now time.Time) (*ClaimedError, bool) {
	defer readLock(dir)()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, planID+".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		a, err := readFile(filepath.Join(dir, name))
		if err == nil && a.SpentAt == nil && a.Claim != nil && !a.claimLapsed(now) {
			return claimedBy(a), true
		}
	}
	return nil, false
}

// HeldAnywhere is HeldAny for every plan in the directory: is any grant held
// by a run right now. What a ledger repair asks, since a run in flight is
// the writer that would be moving under it.
func HeldAnywhere(dir string, now time.Time) (*ClaimedError, bool) {
	defer readLock(dir)()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		a, err := readFile(filepath.Join(dir, name))
		if err == nil && a.SpentAt == nil && a.Claim != nil && !a.claimLapsed(now) {
			return claimedBy(a), true
		}
	}
	return nil, false
}

// HeldBy says which run holds the grant that would answer a Check for this
// stage, if one does. A door asks it before it opens a transcript, so a run
// that is going to be refused does not write into the live transcript of
// the run that holds the grant: the two share a transcript name.
func HeldBy(dir, planID, stage string, now time.Time) (*ClaimedError, bool) {
	defer readLock(dir)()
	for _, scope := range append([]string{stage}, compoundFor(stage)...) {
		a, err := readFile(grantPath(dir, planID, scope))
		if err != nil {
			continue
		}
		if a.SpentAt == nil && a.Claim != nil && !a.claimLapsed(now) {
			return claimedBy(a), true
		}
		// The exact grant answers Check whenever it is there, so a
		// compound one behind it is not the one this stage would use.
		return nil, false
	}
	return nil, false
}
