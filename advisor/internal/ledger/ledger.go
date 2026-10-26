// Package ledger is the append-only record of everything the executor did.
//
// Three properties matter, and they are the reason this is a package rather
// than a log line:
//
//   - It is written by the EXECUTOR, from its own observations. Never from
//     what a plan claimed, never from what the model said happened. The plan
//     is recorded as an input; the outcomes are recorded as measurements.
//
//   - It is append-only and hash-chained. Each entry commits to the one before
//     it, so an entry cannot be altered or removed without breaking every
//     entry after it. That does not make the file tamper-proof — anyone who
//     can write it can rewrite the whole chain — it makes tampering visible,
//     which is the property an operator actually needs when reconstructing an
//     incident.
//
//   - It records refusals as carefully as actions. "The executor declined to
//     restart because consensus looked unhealthy" is the entry that explains
//     the outage that did not happen, and it is worth as much as the ones that
//     explain the outages that did.
package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Kind is what an entry records. The set is closed: an executor that wants to
// record something new declares it here, which keeps the ledger readable by
// someone who has never seen the code.
type Kind string

const (
	KindCompactAccepted Kind = "compact.accepted"
	KindPlanCreated     Kind = "plan.created"
	KindApprovalGranted Kind = "approval.granted"
	KindApprovalRefused Kind = "approval.refused"
	// Revoked before it was spent — the operator's own second thought, or the
	// dashboard clearing it on logout. Distinct from a refusal (the Advisor
	// said no) and from a spend (RunStage used it): here nothing was ever
	// wrong with the approval, it just should not stand any more.
	KindApprovalCancelled Kind = "approval.cancelled"
	KindPreconditions     Kind = "preconditions.evaluated"
	KindStepStarted       Kind = "step.started"
	KindStepSucceeded     Kind = "step.succeeded"
	KindStepFailed        Kind = "step.failed"
	KindRunCompleted      Kind = "run.completed"
	KindRunHalted         Kind = "run.halted"
	// A node that was restarted onto the target and has not rejoined
	// consensus within the window is neither of the two above. Recording it
	// as halted says the operation failed, which sends an operator towards a
	// rollback of a node that is merely still syncing.
	KindRunUnconfirmed Kind = "run.unconfirmed"
	// The node that was unconfirmed above did return to full sync on the
	// target, after the window. Recorded as its own kind rather than a late
	// run.completed so the record keeps saying the window was missed AND
	// that the node made it: the first was proven live on a resync that took
	// fifteen minutes against a fifteen-minute window (2026-08-18), and the
	// ledger ended on the clock's verdict instead of the node's.
	KindRunConfirmedLate Kind = "run.confirmed_late"
	KindRunCancelled     Kind = "run.cancelled"
	KindRefusal          Kind = "executor.refused"

	// Break glass — plan-interrogative-loop §11.10. Four additions and one
	// deliberate reuse (KindApprovalGranted/KindApprovalRefused above cover
	// an investigation's approval identically to an upgrade's — "what have
	// I approved on this node" has one answer shape, stage tells them apart).
	//
	// KindInvestigateOffered is written when the service renders an offer,
	// whether or not the operator ever acts on it — the ledger's record of
	// "this was offered" does not depend on acceptance.
	KindInvestigateOffered Kind = "investigate.offered"
	// KindActionProposed is written when the Advisor proposes an act to the
	// operator and the service lets that proposal reach them as a gate —
	// ADR 0016, amended 2026-08-19. Deliberately a sibling of
	// KindInvestigateOffered rather than of approval.granted: it authorises
	// nothing and spends nothing, and a proposal the operator walks away
	// from should stay in the record AS a proposal nobody acted on. The
	// actor is whoever asked, not the service — the Advisor proposes on a
	// person's behalf, and an anonymous row here would lose which admin was
	// standing in front of the gate.
	KindActionProposed Kind = "action.proposed"
	// KindActionRefused is written when the model emitted an action tag the
	// service could not accept — mangled markup, an unknown kind, a value
	// off its fixed list. Nothing was staged and nothing could have run; the
	// entry exists because the alternative is silence, and silence here is
	// what cost validator1's operator a turn on 2026-08-21: a reply that
	// said Confirmed, no gate, and no record anywhere that a proposal had
	// been made and refused. The actor is whoever asked, as with
	// KindActionProposed — the refusal happened in front of a person.
	KindActionRefused Kind = "action.refused"
	// KindBreakglassOpened is written once, when the approval is spent and
	// the window opens (spend-on-open, §11.3).
	KindBreakglassOpened Kind = "breakglass.opened"
	// KindInvestigateStarted is one gated question beginning inside an open
	// window.
	KindInvestigateStarted Kind = "investigate.started"
	// KindInvestigateRead is one entry PER PRIVILEGED READ during a gated
	// session — deliberately more granular than every other Kind in this
	// package, because break glass is the one surface where "what did it
	// actually touch" has to be reconstructable read by read. Ordinary
	// ungated reads are NOT ledgered (§11.10: "the action ledger records
	// what has been done TO this node"); this Kind exists only for reads
	// that ran through the root-owned wrapper as another identity.
	KindInvestigateRead Kind = "investigate.read"
	// KindInvestigateEnded is one gated question ending — answered, hit a
	// ceiling, or failed.
	KindInvestigateEnded Kind = "investigate.ended"
	// KindBreakglassClosed is the summary line an auditor actually reads:
	// which of the window's four bounds ended it (or that the operator
	// closed it early), and what the window cost in total.
	KindBreakglassClosed Kind = "breakglass.closed"

	// KindInboxNoteWritten records that the Advisor wrote a proposal to
	// internal/inbox — D3, decided 2026-08-08. It carries only metadata
	// (the note's id, title, node and byte count), never the body: the
	// note itself lives at its own path, unpromoted, and the ledger's job
	// here is auditability of "this was written and when", not a second
	// copy of content that is not yet Documented.
	KindInboxNoteWritten Kind = "inbox.note_written"

	// KindMemoryRetracted records that a person withdrew a note the Advisor
	// wrote to its memory, from the command line (#1012). It carries the
	// note's id, node and the reason given, never the note's text: the note
	// stays in the memory file with its retraction beside it, and this entry
	// is what puts who did it and when into the hash-chained record.
	KindMemoryRetracted Kind = "memory.retracted"

	// KindTrustBundleInstalled records that a signed trust bundle from the
	// aggregator was accepted — ADR 0014 decision 4. It carries the issuer,
	// the credential-set serial, whether this was the first (pinning) install
	// or a later credential-only update, and the counts, never the keys
	// themselves. A credential appearing in the store without a matching
	// entry here is visible in the node's own hash-chained record, which the
	// aggregator cannot rewrite — the property that keeps a pushed bundle
	// auditable on the node it changed.
	KindTrustBundleInstalled Kind = "trust.bundle_installed"

	// KindEvidenceCaptured records that a diagnostic snapshot was written into
	// the Advisor's state. Not ceremony-gated — it reads the node and saves
	// the result, it does not change anything — but "not ceremony-gated" was
	// never a reason to be unrecorded, and it was the only admin-gated write
	// on the service that left no trace at all.
	KindEvidenceCaptured Kind = "evidence.captured"

	// KindTrustStoreChanged records that the set of passkeys allowed to
	// approve on this node CHANGED — the privileged action that decides who
	// may perform every other privileged action, and the one that used to
	// leave no record on either side of the system.
	//
	// Written by advisord from what it OBSERVED, never by the shell script
	// that performs the change. That is the whole design: a caller able to
	// append arbitrary entries to a tamper-evident record is exactly the shape
	// this exists to avoid, and observing the change also catches a store
	// rewritten by a path nobody sanctioned. It carries fingerprints and
	// counts, never key material.
	KindTrustStoreChanged Kind = "trust.store_changed"

	// KindModelConfigured records which language model this Advisor is
	// pointed at, and every later change to that choice: the provider, the
	// model, the credential it reads and the sealer's hint for which key
	// that is. Never the key.
	//
	// Written by advisord from what it OBSERVED in its own configuration,
	// on the same reasoning as KindTrustStoreChanged above — the sealer
	// that performs the change does not get to write the record of it, and
	// observing catches a config rewritten by a path nobody sanctioned as
	// readily as one that came through the sealer.
	//
	// It earns its place beside the actions because every answer an
	// operator acted on was written by whatever model was configured at the
	// time. Without this entry the trail can say what was decided and not
	// what decided it.
	KindModelConfigured Kind = "model.configured"

	// KindKnowledgeUpdated records that a signed knowledge bundle from the
	// aggregator was applied — ADR 0017 decision 3. It carries the sequence,
	// the archive's hash, who pushed it and how many files were added,
	// changed and removed.
	//
	// Written for the same reason the trust bundle's entry is: knowledge
	// arriving from off the box shapes every answer this Advisor gives
	// afterwards, and "what is this node telling me, and where did that come
	// from" has to be answerable on the node itself, from a record the
	// aggregator cannot rewrite. It grants nothing — no bundle can widen a
	// read or touch a ceremony — which is exactly why the record needs to
	// show a bundle changing advice and nothing else.
	KindKnowledgeUpdated Kind = "knowledge.updated"

	// KindProposalPromoted and KindProposalRejected record the operator's
	// decision on a proposal this node's Advisor wrote — ADR 0017 decision 4.
	// The decision is made at the aggregator's review card and sent back to
	// the node that proposed, so the node's own record answers "what happened
	// to what I proposed" without anyone having to read the aggregator's.
	//
	// Promotion carries the file the note became, under knowledge-fleet/;
	// rejection carries the reason when one was given. Both carry the person,
	// from the dashboard session, never from the request body. The knowledge
	// itself arrives separately and later, as a signed bundle with its own
	// knowledge.updated entry — these two say a human decided, not that any
	// content changed here.
	KindProposalPromoted Kind = "proposal.promoted"
	KindProposalRejected Kind = "proposal.rejected"

	// KindProposalRevised records that an operator verified a proposal
	// against this node and kept the result — the trust model's Part B.
	//
	// It is on the record for the same reason a decision is, and for one
	// more: this is the only entry point that raises a note's grade after it
	// was written. What the entry carries is what the grade was computed
	// from — the investigation whose record the service read back, how many
	// distinct measured reads it held, and the provenance and rank before and
	// after. A rank that went up with nothing behind it is then a thing
	// somebody can find, in a chain nobody here can quietly edit.
	KindProposalRevised Kind = "proposal.revised"

	// KindFleetLinkRevoked and KindFleetNodeKeyRepinned record an act the
	// aggregator's dashboard performed ON this node rather than through it
	// (#455): its link closed, and the node key the fleet pins for it
	// replaced. Both carry the operator, the node and the key or keys.
	//
	// They are the only two entries in this file that arrive from off the
	// box, and the only two an operator could ask why they are trusted. The
	// answer is the same one the trust bundle and the knowledge bundle give:
	// advisord verifies a detached Ed25519 signature against the aggregator
	// key this node already holds before it writes anything, the set of
	// kinds it will accept is closed, and the summary is composed here from
	// the fields rather than taken off the wire. See internal/fleetrecord.
	//
	// Worth their place beside the acts this service performs itself,
	// because what they record is otherwise invisible from the node. A
	// revoke reaches the nodes that REMAIN as a new passkey bundle, which
	// each of them records honestly as a trust set that changed and cannot
	// say what changed it; the node it happened to saw nothing at all.
	KindFleetLinkRevoked     Kind = "fleet.link_revoked"
	KindFleetNodeKeyRepinned Kind = "fleet.node_key_repinned"

	// KindFleetAdvisorAttached and KindFleetAdvisorDetached record the other
	// two acts an aggregator performs ON this node rather than through it
	// (#641): the aggregator was given this node's own Advisor credential and
	// now reaches its Advisor, and that reach taken away again. Both carry the
	// operator, the node and the key the fleet pins for it, exactly as a
	// revoke does, and both arrive under the same closed set, the same
	// signature check and the same composed-here summary as the two above.
	//
	// Worth their place for the same reason: an attach is what makes this
	// node's Advisor reachable from somewhere else and makes it eligible for
	// the fleet's model key, and from the node itself neither act is visible
	// at all. Before this the node's own record of how that happened was a
	// credential read that simply started working.
	KindFleetAdvisorAttached Kind = "fleet.advisor_attached"
	KindFleetAdvisorDetached Kind = "fleet.advisor_detached"

	// KindLedgerRepaired records that a forked ledger was repaired from the
	// command line (#1091): which rows were taken out of the chain, where
	// they were kept, and who did it. The rows themselves are not copied
	// here; they stay verbatim in the sidecar the entry names.
	KindLedgerRepaired Kind = "ledger.repaired"
)

// IsFleetRecordKind is the closed set of kinds that arrive from OFF this box,
// signed by the aggregator, rather than being written by this service about
// its own work.
//
// It exists so the set has ONE declaration. Every place that has to ask "is
// this one of the aggregator's records" (the replay scan that answers whether
// a record_id has already been written here is the one that matters) must ask
// here rather than naming the members again, because a kind added to the set
// and not to such a list is a kind with no replay guard, which is the one
// failure mode this whole surface is built to prevent.
func IsFleetRecordKind(k Kind) bool {
	switch k {
	case KindFleetLinkRevoked, KindFleetNodeKeyRepinned,
		KindFleetAdvisorAttached, KindFleetAdvisorDetached:
		return true
	}
	return false
}

// Entry is one record. Hash covers every other field including PrevHash, which
// is what chains them.
type Entry struct {
	Seq      int            `json:"seq"`
	At       time.Time      `json:"at"`
	Kind     Kind           `json:"kind"`
	PlanID   string         `json:"plan_id,omitempty"`
	Summary  string         `json:"summary"`
	Data     map[string]any `json:"data,omitempty"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Ledger appends to a JSONL file.
//
// The position — next seq and previous hash — is NOT held on this struct. It
// lives in a per-path registry shared by every Ledger open on the same file in
// this process, guarded by a mutex taken for the whole of Append.
//
// That indirection is load-bearing. Callers here open a ledger, append, and
// drop it, and one of them (a gated break-glass session) holds its handle open
// across a ten-minute question while other requests open their own. With the
// position cached per handle, two handles both believe they are at seq N, both
// write N+1, and the next Open fails its `entry N claims seq N-1` check and
// REFUSES THE WHOLE FILE — so advisord could never append on that host again.
// A duplicated sequence number is not a cosmetic flaw in an append-only record;
// it is indistinguishable from tampering, which is exactly what Open is right
// to refuse.
//
// Across processes the same guarantee comes from a lock on the file itself,
// not from the cache (#1091). advisord and a hand-run `aperire-executor` are
// two processes, and the cache in each is only a hint: every append takes an
// exclusive flock on the ledger, reads the last row's seq and hash from the
// file, and writes after that row. A second writer, whichever program it is,
// therefore follows the last row on disk and cannot fork the chain. The lock
// is advisory, so a program that appends without taking it can still fork the
// file; Open and the CLI's `ledger --repair` are how that is found and kept
// as evidence.
type Ledger struct {
	path string
	st   *position
}

// position is the authoritative append point for one path.
type position struct {
	mu   sync.Mutex
	seq  int
	last string
}

var registry = struct {
	mu sync.Mutex
	m  map[string]*position
}{m: map[string]*position{}}

func positionFor(path string) *position {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	p, ok := registry.m[abs]
	if !ok {
		p = &position{}
		registry.m[abs] = p
	}
	return p
}

// Open reads an existing ledger, verifies its chain, and positions for append.
// A ledger that does not verify is not opened: continuing to append to a chain
// that has already been broken would bury the evidence of the break under
// entries that look fine.
func Open(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	l := &Ledger{path: path, st: positionFor(path)}
	// Held across the scan as well as the assignment: another handle appending
	// while this one is reading would make the position it computes stale
	// before it is stored.
	l.st.mu.Lock()
	defer l.st.mu.Unlock()

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		l.st.seq, l.st.last = 0, ""
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// A reader's lock, so the scan never sees a row another process is in the
	// middle of writing. Not taking it is not fatal: a torn last row fails to
	// parse and the open is refused, which is the safe direction.
	if unlock, lerr := lockFile(f, false); lerr == nil {
		defer unlock()
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	prev := ""
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("ledger %s entry %d: %w", path, n+1, err)
		}
		n++
		if e.Seq != n {
			return nil, fmt.Errorf("ledger %s: entry %d claims seq %d", path, n, e.Seq)
		}
		if e.PrevHash != prev {
			return nil, fmt.Errorf("ledger %s: entry %d does not follow entry %d", path, e.Seq, e.Seq-1)
		}
		want, err := e.computeHash()
		if err != nil {
			return nil, err
		}
		if e.Hash != want {
			return nil, fmt.Errorf("ledger %s: entry %d has been altered", path, e.Seq)
		}
		prev = e.Hash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	l.st.seq, l.st.last = n, prev
	return l, nil
}

// Append writes one entry and returns it as written.
//
// The entry follows the last row IN THE FILE, read under an exclusive lock on
// it, never the position this process last saw (#1091). That is what keeps a
// second program's row, written between two appends of a held handle, from
// being forked over.
func (l *Ledger) Append(kind Kind, planID, summary string, data map[string]any) (Entry, error) {
	l.st.mu.Lock()
	defer l.st.mu.Unlock()

	// O_APPEND so a writer outside the lock cannot overwrite, and 0640
	// because this records what was done to a validator and is not
	// world-readable. Read as well as write, for the last row.
	f, unlock, err := openLocked(l.path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	defer unlock()

	seq, last, err := tail(f)
	if err != nil {
		return Entry{}, fmt.Errorf("ledger %s: %w; not appending to it", l.path, err)
	}

	e := Entry{
		Seq:      seq + 1,
		At:       time.Now().UTC(),
		Kind:     kind,
		PlanID:   planID,
		Summary:  summary,
		Data:     data,
		PrevHash: last,
	}
	h, err := e.computeHash()
	if err != nil {
		return Entry{}, err
	}
	e.Hash = h

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	// Durability matters more than throughput here: an entry that was in a
	// buffer when the host lost power records nothing.
	if err := f.Sync(); err != nil {
		return Entry{}, err
	}

	l.st.seq = e.Seq
	l.st.last = e.Hash
	return e, nil
}

// lockWait is how long a writer waits for the ledger lock before giving up.
// An append holds it for one small write and a sync, so a wait this long
// means a holder that is stuck, and refusing is better than freezing a run.
// A variable so a test can shorten it.
var lockWait = 30 * time.Second

// lockFile takes the lock on an open ledger, bounded by lockWait. flock is
// per open file description, so it excludes another process and another
// handle in this one alike.
func lockFile(f *os.File, exclusive bool) (func(), error) {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another program holds the ledger lock and did not let it go")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// openLocked opens the ledger for append and takes the exclusive lock on it.
// A repair replaces the file by rename, so a writer that was waiting on the
// old file gets the lock on a file that is no longer the ledger; the path is
// checked against the locked file and the open is repeated until they are the
// same.
func openLocked(path string) (*os.File, func(), error) {
	for tries := 0; tries < 8; tries++ {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|syscall.O_CLOEXEC, 0o640)
		if err != nil {
			return nil, nil, err
		}
		unlock, err := lockFile(f, true)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		held, herr := f.Stat()
		now, nerr := os.Stat(path)
		if herr == nil && nerr == nil && os.SameFile(held, now) {
			return f, unlock, nil
		}
		unlock()
		f.Close()
	}
	return nil, nil, fmt.Errorf("the ledger at %s kept being replaced while waiting for its lock", path)
}

// maxRow is the longest row tail will read, the same ceiling the scanners use.
const maxRow = 4 * 1024 * 1024

// tail reads the file's last non-empty row and returns its seq and hash. An
// empty file is seq 0 and no hash. The row must verify on its own content:
// chaining a new row to an altered one would bury the alteration under a row
// that looks fine, the reason Open refuses such a file.
func tail(f *os.File) (seq int, hash string, err error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	line, err := lastLine(f, fi.Size())
	if err != nil {
		return 0, "", err
	}
	if line == nil {
		return 0, "", nil
	}
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return 0, "", fmt.Errorf("the last row does not parse: %w", err)
	}
	want, err := e.computeHash()
	if err != nil {
		return 0, "", err
	}
	if e.Hash != want {
		return 0, "", fmt.Errorf("the last row (entry %d) has been altered", e.Seq)
	}
	return e.Seq, e.Hash, nil
}

// lastLine returns the last non-blank line of the first size bytes of f, read
// backwards from the end so a long ledger costs one short read.
func lastLine(f *os.File, size int64) ([]byte, error) {
	end := size
	one := make([]byte, 1)
	for end > 0 {
		if _, err := f.ReadAt(one, end-1); err != nil {
			return nil, err
		}
		if c := one[0]; c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			break
		}
		end--
	}
	if end == 0 {
		return nil, nil
	}
	start := end
	const chunk = 8192
	for start > 0 {
		n := int64(chunk)
		if n > start {
			n = start
		}
		b := make([]byte, n)
		if _, err := f.ReadAt(b, start-n); err != nil {
			return nil, err
		}
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			start = start - n + int64(i) + 1
			break
		}
		start -= n
		if end-start > maxRow {
			return nil, fmt.Errorf("the last row is longer than %d bytes", maxRow)
		}
	}
	if end-start > maxRow {
		return nil, fmt.Errorf("the last row is longer than %d bytes", maxRow)
	}
	out := make([]byte, end-start)
	if _, err := f.ReadAt(out, start); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out), nil
}

// computeHashCalls counts every call to computeHash. It exists for tests
// that need to prove EntriesSince verifies only what changed rather than
// rehashing a file that has not grown, the reason it exists at all, ADR
// 0021 build step 1, and it is a plain package-level counter rather than a
// build-tagged hook because the tests that read it live in this package.
// Harmless everywhere else: an atomic increment nobody outside a test reads.
var computeHashCalls int64

// computeHash digests the entry's content with its predecessor's hash. Keys
// are sorted so the digest does not depend on Go's map iteration order.
func (e Entry) computeHash() (string, error) {
	atomic.AddInt64(&computeHashCalls, 1)
	payload := struct {
		Seq      int       `json:"seq"`
		At       time.Time `json:"at"`
		Kind     Kind      `json:"kind"`
		PlanID   string    `json:"plan_id"`
		Summary  string    `json:"summary"`
		Data     string    `json:"data"`
		PrevHash string    `json:"prev_hash"`
	}{e.Seq, e.At, e.Kind, e.PlanID, e.Summary, canonical(e.Data), e.PrevHash}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// canonical renders Data to a form that survives a write and a read.
//
// The subtlety that broke verification: Go marshals a struct in field order
// and a map in key order, so an entry written with a struct in Data hashed
// differently once read back as a map — and the chain "broke" on data nobody
// had touched. Round-tripping through a generic value first normalises both to
// the same shape, so the digest depends on the content and not on which Go
// type happened to hold it.
func canonical(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s;", k, normalise(m[k]))
	}
	return b.String()
}

func normalise(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(generic)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// Entries reads the whole ledger back, verifying as it goes.
func Entries(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	prev := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		want, err := e.computeHash()
		if err != nil {
			return nil, err
		}
		if e.Hash != want || e.PrevHash != prev {
			return out, fmt.Errorf("ledger %s: chain breaks at entry %d", path, e.Seq)
		}
		prev = e.Hash
		out = append(out, e)
	}
	return out, sc.Err()
}

// Head is the hash of the last entry — the value that commits to the whole
// chain. Worth printing at the end of a run: an operator who records it
// somewhere else can later prove the ledger has not been rewritten.
//
// Read from the file, so a row another program appended is part of it; the
// position this process last wrote is the answer only when the file cannot be
// read.
func (l *Ledger) Head() string {
	l.st.mu.Lock()
	defer l.st.mu.Unlock()
	if f, err := os.Open(l.path); err == nil {
		defer f.Close()
		if _, h, terr := tail(f); terr == nil && h != "" {
			return h
		}
	}
	return l.st.last
}

// ErrCachedPointStale is what EntriesSince returns when the chain point a
// caller trusted no longer describes this file: the file now has fewer
// entries than the point named, or the entry AT that position no longer
// hashes to what was trusted. Either way the position is not safe to verify
// forward from, the file is a different chain now, whether from a
// reinstall that started numbering over or from a rewrite under the cached
// point, and the caller's one honest move is to read the whole file again
// (EntriesSince with the zero ChainPoint, or Entries) as if nothing had ever
// been cached.
var ErrCachedPointStale = errors.New("ledger: the cached chain point no longer matches this file")

// ChainPoint names a position in a chain a caller has already verified: how
// many entries it had read up to, and the hash of the last one. The zero
// value names the position before any entry, and matches an empty or absent
// file.
type ChainPoint struct {
	Seq  int
	Hash string
}

// EntriesSince is Entries with one more thing a caller can bring: a chain
// point it already trusts, established by an earlier Entries or an earlier
// EntriesSince. Nothing at or before trusted.Seq is re-hashed, that is the
// whole reason this exists (aperire-advisord's ledger route, ADR 0021 build
// step 1: a poll against a file that has not grown used to recompute a
// SHA-256 chain hundreds of entries deep to report that nothing changed).
//
// since is independent of trusted and controls only what comes back in
// tail: entries at a position greater than since. A caller with nothing
// cached passes the zero ChainPoint and since 0, which verifies and returns
// the whole file, the same work Entries does, because trusted.Seq is 0 and
// every entry falls past it.
//
// The trusted point is checked, not assumed. If the file now has fewer
// entries than trusted.Seq, or the entry at that position no longer hashes
// to trusted.Hash, this returns ErrCachedPointStale rather than verifying
// forward from a position that no longer means what the caller thinks.
//
// What it deliberately does NOT do: catch an entry mutated AT OR BEFORE
// trusted.Seq without touching that entry's own recorded hash. Entry 3's
// summary can be rewritten by hand, leaving its Hash field exactly as it
// was, and a request trusting a point at entry 10 will not notice, the
// check at the trusted position passes because entry 10's hash was never
// touched. That gap is the trade this function makes for not re-hashing the
// whole file, and Entries is what closes it: a full read verifies every
// entry against its own content from position one, and finds it. That is
// why the ledger route still calls Entries whenever since_seq is absent,
// the periodic full read is what a truncated cache trusts to catch tampering
// that happened underneath it.
func EntriesSince(path string, trusted ChainPoint, since int) (tail []Entry, count int, head string, err error) {
	tail = make([]Entry, 0)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		if trusted.Seq > 0 {
			return nil, 0, "", ErrCachedPointStale
		}
		return tail, 0, "", nil
	}
	if err != nil {
		return nil, 0, "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	prev := ""
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, 0, "", err
		}
		n++
		if n <= trusted.Seq {
			// Trusted by the caller. Checked only where it can be checked
			// without hashing anything, at the position it names, so a
			// file rewritten under a stale point is still refused rather
			// than verified forward from a hash that no longer applies.
			if n == trusted.Seq && e.Hash != trusted.Hash {
				return nil, 0, "", ErrCachedPointStale
			}
			prev, head = e.Hash, e.Hash
			// Trusted governs what gets RE-HASHED, never what comes back.
			// This entry was verified when it was first read, so it is not
			// hashed again, but a caller that asked for everything after
			// `since` still asked for it. Leaving it out made every tail
			// read answer an empty list once the cache reached the head,
			// with the right count beside it, and the fleet mirror sat
			// still for as long as that lasted without recording a single
			// error (#405).
			if n > since {
				tail = append(tail, e)
			}
			continue
		}
		if e.PrevHash != prev {
			return nil, 0, "", fmt.Errorf("ledger %s: chain breaks at entry %d", path, e.Seq)
		}
		want, err := e.computeHash()
		if err != nil {
			return nil, 0, "", err
		}
		if e.Hash != want {
			return nil, 0, "", fmt.Errorf("ledger %s: chain breaks at entry %d", path, e.Seq)
		}
		prev, head = e.Hash, e.Hash
		if n > since {
			tail = append(tail, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, "", err
	}
	if n < trusted.Seq {
		return nil, 0, "", ErrCachedPointStale
	}
	return tail, n, head, nil
}
