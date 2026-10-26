package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// A ledger that forked (#1091): two rows both claim to follow the same row,
// because two programs appended without seeing each other. Open refuses such
// a file, and with it the node's Advisor stops working, so there has to be a
// way out. It has to be a narrow one. A repair that re-hashed whatever it
// found would turn a tamper-evident record into one anyone could launder, so
// this accepts exactly one shape and refuses every other break:
//
//   - every row hashes correctly on its own content, so nothing was altered;
//   - every row's predecessor is a row that is in the file and earlier in it,
//     with the seq one below, so nothing was removed;
//   - what is wrong is only that more than one row follows the same
//     predecessor.
//
// At each such fork the row written FIRST stays, and so does everything that
// chains from it. That is the prefix of the file that read as intact, the
// only branch the dashboard's witness or the aggregator's mirror can ever
// have accepted, so a repair never changes a row someone else already holds.
// It does not depend on how long the fork sat, or on which branch has since
// grown longer, so the same file gives the same answer whenever it is run.
//
// The other rows are not thrown away. Each is carried whole, data included,
// inside the one new ledger.repaired row, which is chained after the kept
// rows, and is also moved unedited into a sidecar file beside a full copy of
// the file as it was.

// ErrNothingToRepair is a ledger whose chain already verifies.
var ErrNothingToRepair = errors.New("the ledger chain is intact; there is nothing to repair")

// NotAForkError is a break that is not a fork: an altered row, a removed one,
// or a file that does not parse. It is never repaired. The reason names the
// entry.
type NotAForkError struct{ Reason string }

func (e *NotAForkError) Error() string {
	return "this break is not a fork, so it is not repaired: " + e.Reason
}

// TooLargeError is a fork whose moved rows, carried whole in the repair row,
// would make that row longer than a ledger row may be. Nothing is changed;
// the file stays as it is, and the break is left for a person to read.
type TooLargeError struct{ Bytes int }

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("the rows to move would make one ledger row of %d bytes, more than the %d a row may hold, "+
		"so the repair would leave a ledger that cannot be opened", e.Bytes, maxRow)
}

// Fork describes a repairable fork: the rows that would stay and the rows
// that would be moved out.
type Fork struct {
	// Kept is how many rows stay, in their original order.
	Kept int
	// Moved are the rows taken out, in file order, exactly as written.
	Moved []Entry
	// After is the seq of the row both branches follow.
	After int
}

// forkPlan is the analysis: which lines of the file stay and which move.
type forkPlan struct {
	lines [][]byte
	rows  []Entry
	keep  []bool
}

// Diagnose reads the ledger and says whether its break is a repairable fork.
// It returns ErrNothingToRepair for an intact chain and a *NotAForkError for
// any other break. It changes nothing.
func Diagnose(path string) (Fork, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Fork{}, err
	}
	p, err := analyse(raw)
	if err != nil {
		return Fork{}, err
	}
	return p.fork(), nil
}

func (p *forkPlan) fork() Fork {
	f := Fork{}
	for i, k := range p.keep {
		if k {
			f.Kept++
		} else {
			f.Moved = append(f.Moved, p.rows[i])
		}
	}
	if len(f.Moved) > 0 {
		// The row both branches follow is the earliest moved row's
		// predecessor.
		f.After = f.Moved[0].Seq - 1
	}
	return f
}

func splitRows(raw []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(raw, []byte("\n")) {
		if t := bytes.TrimSpace(l); len(t) > 0 {
			out = append(out, t)
		}
	}
	return out
}

func analyse(raw []byte) (*forkPlan, error) {
	lines := splitRows(raw)
	p := &forkPlan{lines: lines, rows: make([]Entry, len(lines)), keep: make([]bool, len(lines))}
	byHash := map[string]int{}
	parent := make([]int, len(lines))
	depth := make([]int, len(lines))

	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, &NotAForkError{fmt.Sprintf("row %d does not parse (%v)", i+1, err)}
		}
		want, err := e.computeHash()
		if err != nil {
			return nil, err
		}
		if e.Hash != want {
			return nil, &NotAForkError{fmt.Sprintf("entry %d (row %d of the file) has been altered", e.Seq, i+1)}
		}
		p.rows[i] = e
		if e.PrevHash == "" {
			parent[i], depth[i] = -1, 1
		} else {
			j, ok := byHash[e.PrevHash]
			if !ok {
				return nil, &NotAForkError{fmt.Sprintf(
					"entry %d (row %d of the file) follows a row that is not earlier in the file, so a row was removed or the file is damaged", e.Seq, i+1)}
			}
			parent[i], depth[i] = j, depth[j]+1
		}
		if e.Seq != depth[i] {
			return nil, &NotAForkError{fmt.Sprintf(
				"entry %d (row %d of the file) is numbered %d where its place in the chain is %d", e.Seq, i+1, e.Seq, depth[i])}
		}
		byHash[e.Hash] = i
	}

	// The row written first at each fork stays, with whatever chains from a
	// row that stays. A row whose predecessor moved moves with it.
	first := map[int]int{}
	for i := range lines {
		pr := parent[i]
		f, seen := first[pr]
		if !seen {
			first[pr] = i
			f = i
		}
		p.keep[i] = f == i && (pr == -1 || p.keep[pr])
	}
	return p, nil
}

// RepairReport is what a repair did.
type RepairReport struct {
	Fork Fork
	// Backup holds the whole file as it was before the repair; ForkFile holds
	// the moved rows. Both beside the ledger.
	Backup, ForkFile string
	// Entry is the row the repair appended to the ledger.
	Entry Entry
}

// Repair moves a fork out of the ledger at path. It takes the same lock every
// append takes, so a writer in another process waits and then follows the
// repaired chain. Nothing is changed unless the break is a pure fork, and the
// original file is kept before anything is replaced.
//
// Must run as the account that owns the ledger. A rewritten file owned by
// root is one the Advisor's service can no longer append to.
//
// refuseIf, when it is not nil, is asked once the ledger lock is held and
// before anything is read for the repair; an error from it stops the repair
// with nothing changed. It is how the caller says "not while a run holds an
// approval", which this package cannot know.
func Repair(path string, by Actor, now time.Time, refuseIf func() error) (RepairReport, error) {
	f, unlock, err := openLocked(path)
	if err != nil {
		return RepairReport{}, err
	}
	defer f.Close()
	defer unlock()
	if refuseIf != nil {
		if err := refuseIf(); err != nil {
			return RepairReport{}, err
		}
	}

	// Whose file this is and who can read it. The dashboard reads the ledger
	// through a group on some hosts, so what the repair writes keeps the
	// original's owner, group and mode (#1091), and a repair that cannot give
	// them refuses with everything in place.
	own, err := ownershipOf(f)
	if err != nil {
		return RepairReport{}, fmt.Errorf("could not read who owns the ledger, so nothing was changed: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return RepairReport{}, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return RepairReport{}, err
	}
	p, err := analyse(raw)
	if err != nil {
		return RepairReport{}, err
	}
	fork := p.fork()
	if len(fork.Moved) == 0 {
		return RepairReport{}, ErrNothingToRepair
	}

	stamp := now.UTC().Format("20060102T150405Z")
	rep := RepairReport{Fork: fork,
		Backup:   path + ".pre-repair-" + stamp,
		ForkFile: path + ".fork-" + stamp}

	var kept bytes.Buffer
	var last Entry
	for i, k := range p.keep {
		if k {
			kept.Write(p.lines[i])
			kept.WriteByte('\n')
			last = p.rows[i]
		}
	}
	// The moved rows ride in the repair row whole, data included, so the
	// ledger itself still says what happened in them (a step that restarted
	// the node, a run that completed) and not only that they moved.
	e := Entry{
		Seq: last.Seq + 1, At: now.UTC(), Kind: KindLedgerRepaired,
		Summary: fmt.Sprintf("repaired a forked ledger: %d row(s) after entry %d moved to %s, and carried here",
			len(fork.Moved), fork.After, filepath.Base(rep.ForkFile)),
		Data: Stamp(map[string]any{
			"moved": fork.Moved, "kept": fork.Kept, "after": fork.After,
			"fork_file": filepath.Base(rep.ForkFile), "backup": filepath.Base(rep.Backup),
		}, by),
		PrevHash: last.Hash,
	}
	h, err := e.computeHash()
	if err != nil {
		return RepairReport{}, err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return RepairReport{}, err
	}
	// A row longer than the readers take makes the ledger unopenable, which
	// is the failure this command exists to end.
	if len(line) > maxRow {
		return RepairReport{}, &TooLargeError{Bytes: len(line)}
	}
	kept.Write(line)
	kept.WriteByte('\n')

	// Evidence first. Both are created exclusively, so a second repair in the
	// same second refuses rather than overwrite the first one's evidence.
	// Everything created before the swap is removed again if a later step
	// fails, so a refusal leaves the directory as it found it.
	var made []string
	undo := func() {
		for _, m := range made {
			os.Remove(m)
		}
	}
	if err := writeNew(rep.Backup, raw, own); err != nil {
		undo()
		return RepairReport{}, fmt.Errorf("could not keep a copy of the ledger first: %w", err)
	}
	made = append(made, rep.Backup)
	var moved bytes.Buffer
	for i, k := range p.keep {
		if !k {
			moved.Write(p.lines[i])
			moved.WriteByte('\n')
		}
	}
	if err := writeNew(rep.ForkFile, moved.Bytes(), own); err != nil {
		undo()
		return RepairReport{}, fmt.Errorf("could not keep the moved rows: %w", err)
	}
	made = append(made, rep.ForkFile)

	// The replacement is checked before it replaces anything.
	tmp := path + ".repair-tmp"
	_ = os.Remove(tmp)
	if err := writeNew(tmp, kept.Bytes(), own); err != nil {
		undo()
		return RepairReport{}, err
	}
	made = append(made, tmp)
	if _, err := Entries(tmp); err != nil {
		undo()
		return RepairReport{}, fmt.Errorf("the repaired ledger did not verify, so nothing was replaced: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		undo()
		return RepairReport{}, err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	rep.Entry = e
	return rep, nil
}

// ownership is the owner, group and permission bits of the ledger a repair
// replaces, which every file the repair creates is given.
type ownership struct {
	uid, gid int
	mode     os.FileMode
}

func ownershipOf(f *os.File) (ownership, error) {
	fi, err := f.Stat()
	if err != nil {
		return ownership{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ownership{}, errors.New("this platform does not say who owns a file")
	}
	return ownership{uid: int(st.Uid), gid: int(st.Gid), mode: fi.Mode().Perm()}, nil
}

// fchown is (*os.File).Chown, a variable so a test can stand in for an
// account that is not a member of the ledger's group, as root as well.
var fchown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// writeNew creates a file that must not exist, with the owner, group and mode
// given, and syncs it. The mode is set on the descriptor, so the process's
// umask does not narrow it. A file whose owner or group cannot be set is
// removed again and the error returned: a repaired ledger the dashboard can
// no longer read is the failure the repair must not cause.
func writeNew(path string, data []byte, own ownership) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := fchown(f, own.uid, own.gid); err != nil {
		return fail(fmt.Errorf("could not give %s the ledger's owner and group (%d:%d): %w",
			filepath.Base(path), own.uid, own.gid, err))
	}
	if err := f.Chmod(own.mode); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	return f.Close()
}

// WithCarried returns entries with the rows a repair carried inside each
// ledger.repaired row put back in place, directly after it, so a reader that
// asks "did a run complete on this version" still sees a run whose rows the
// repair moved off the chain. The carried rows are returned exactly as they
// were written, their original seq and hashes included, which is why this is
// for readers that filter on kind and data and not for anything that
// verifies the chain: Entries has already done that.
//
// A carried row is data inside a row, and anything able to append a row could
// write one that says whatever it likes, so each is held to the repair's own
// rules before it is believed: it hashes correctly on its own content, its
// predecessor is a row that is earlier (in the chain or already carried), and
// its seq is that row's plus one. A row that fails is left out, and the reason
// comes back naming it, for the caller to say; it is never dropped quietly.
func WithCarried(entries []Entry) (all []Entry, dropped []string) {
	all = make([]Entry, 0, len(entries))
	known := map[string]int{"": 0} // hash of an earlier row -> its seq
	for _, e := range entries {
		all = append(all, e)
		if e.Kind == KindLedgerRepaired {
			raw, err := json.Marshal(e.Data["moved"])
			var moved []Entry
			if err == nil {
				err = json.Unmarshal(raw, &moved)
			}
			if err != nil {
				dropped = append(dropped, fmt.Sprintf("the rows carried by entry %d could not be read (%v)", e.Seq, err))
			}
			for _, m := range moved {
				if why := carriedFault(m, known); why != "" {
					dropped = append(dropped, fmt.Sprintf("a row carried by entry %d (seq %d, %s) was not used: %s",
						e.Seq, m.Seq, m.Kind, why))
					continue
				}
				known[m.Hash] = m.Seq
				all = append(all, m)
			}
		}
		known[e.Hash] = e.Seq
	}
	return all, dropped
}

// carriedFault is why a carried row is not believed, or "" when it is.
func carriedFault(m Entry, known map[string]int) string {
	want, err := m.computeHash()
	if err != nil || m.Hash != want {
		return "it does not hash to what it says"
	}
	prevSeq, ok := known[m.PrevHash]
	if !ok {
		return "the row it follows is not earlier in the ledger"
	}
	if m.Seq != prevSeq+1 {
		return fmt.Sprintf("it is numbered %d where the row it follows puts it at %d", m.Seq, prevSeq+1)
	}
	return ""
}
