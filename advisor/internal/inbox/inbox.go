// Package inbox is the Advisor's write side of the knowledge boundary — D3,
// decided 2026-08-08 (advisor-enhancement/decisions.md). It writes
// structured notes the model proposes to a directory that sits
// structurally outside every knowledge loader's root and is never read
// back by any reasoning path: nothing model-authored gains the Documented
// tier's citation weight by writing to this package.
//
// The first (and, for this slice, only) writer is the <propose> block: the
// <remember>-adjacent sibling of cmd/aperire-advisord's own <remember>
// extraction. Where <remember> writes a low-stakes, tiered memory entry
// that CAN be read back as evidence (internal/memory), a <propose> block
// writes a note that categorically cannot, until a person moves it.
//
// ADR 0017 phase 2 changed two of this package's original claims, and both
// changes are narrower than they look:
//
//   - It has a reader now (List). The claim it was protecting was never "no
//     code reads this directory" but "no REASONING path reads it": the
//     knowledge loaders still cannot see it, and List exists for the
//     operator's review card, which is a person looking at a queue. A note
//     stays outside every prompt until a human promotes it into
//     knowledge-fleet/local/, which is a different directory written by a
//     different process.
//   - A note can be edited, by exactly one writer (Mark) and in exactly one
//     way: its decision fields. The body a model wrote is never rewritten
//     here — promotion copies it out, and what stays behind is the record
//     that someone decided, who they were, and when. Without that a
//     promoted proposal would sit in the queue forever, and the second
//     reviewer would have no way to see the first one's answer.
//
// The trust model's Part B adds a SECOND body writer, Revise, and it is
// narrower than it sounds too. It rewrites one pending note's body and the
// grade that goes with it, after an operator verified the note against the
// node it came from, and it records who did that on the note itself. Three
// things keep it from being "the model can edit its own grade": it refuses
// any note that is no longer pending, it never computes the grade (the caller
// does, from an investigation record the service wrote), and the file keeps
// revised_by/revised_at so a reviewer can see the body is no longer the one
// the Advisor proposed.
package inbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The three statuses a note can hold. Pending is the only one Write
// produces; the other two are terminal and are written by Mark.
const (
	StatusPending  = "pending"
	StatusPromoted = "promoted"
	StatusRejected = "rejected"
)

// The two provenance values, and the whole of the vocabulary: a note either
// rests on at least one successful measured read the service performed for
// the question that produced it, or it does not.
//
// Neither value is ever taken from the model. Both are computed by the
// service from the investigation's own record (internal/proposalrank) — a
// model that grades its own note would have rated the 2026-08-13 "this
// aggregator has no swap" proposal highly, and that note was never measured
// at all.
const (
	ProvenanceMeasured = "measured"
	ProvenanceInferred = "inferred"
)

// RankMin is what an unranked note is worth, and RankMax is the ceiling on
// what any note can claim. A note whose rank cannot be read — a phase 1
// file, a peer running an older Advisor, a hand-edited header — reads as
// RankMin, never as a high one: the failure mode of a trust score must be
// distrust.
const (
	RankMin = 1
	RankMax = 5
)

const (
	// maxNoteBytes bounds one note when reading it back. A note is written
	// by this package from a capped <propose> block, so this only ever
	// bites on a file somebody put here by hand.
	maxNoteBytes = 256 << 10
	// maxList bounds one List call. Nothing prunes this directory, so an
	// Advisor that has proposed for a year should not cost the review card
	// an unbounded read.
	maxList = 500
	// maxQuestionBytes bounds the question stored as provenance. The
	// question is context for the reviewer, not the note.
	maxQuestionBytes = 400
)

// idRe is what a caller's id must look like before it is joined to a path.
// Write mints exactly this shape (unix nanos, a dash, eight hex); anything
// else is refused before it can name a file.
var idRe = regexp.MustCompile(`^[0-9]{1,20}-[0-9a-f]{8}$`)

// ErrNoSuchNote is returned by Mark when this inbox holds no note with that
// id. It is also the guard that keeps one node's decision from landing on
// another's inbox: ids are minted per node and never collide, so a mark
// aimed at the wrong node finds nothing rather than marking something.
var ErrNoSuchNote = fmt.Errorf("no such proposal in this inbox")

// ErrNotPending is returned by Revise for a note somebody has already decided.
// A promoted note's body has been copied into the corpus and a rejected one is
// the record of a "no"; rewriting either would edit history, and the operator
// would be looking at a queue entry whose body no longer matches the file that
// shipped.
var ErrNotPending = fmt.Errorf("that proposal has already been decided")

// Note is one proposal, written as exactly one file.
type Note struct {
	ID    string
	Title string
	Body  string
	Node  string
	// Question is the operator question whose answer produced this note —
	// provenance for the reviewer, who is being asked to accept a claim and
	// deserves to see what prompted it. Empty on notes written before ADR
	// 0017 phase 2, and absent rather than empty in the file.
	Question  string
	Source    string // "advisor" — mirrors memory.Entry.Source
	CreatedAt time.Time
	Path      string

	// Provenance and Rank are the service's own grading of this note, set
	// once at Write from the investigation record and never edited
	// afterwards. See the ProvenanceMeasured/RankMin block above for why
	// neither is a value the model has any say in.
	//
	// Absent on notes written before this existed, and they come back
	// inferred at RankMin — the reviewer is told the Advisor did not verify
	// this, which for a note whose record no longer exists is the truth.
	Provenance string // measured | inferred
	Rank       int    // 1..5, higher is better grounded

	// RevisedBy and RevisedAt are set by Revise, and they are why the file
	// keeps them rather than leaving the revision to the ledger alone: the
	// note is a human-readable artifact, and a body an operator replaced
	// after verifying it should not read as one the Advisor wrote. Empty on
	// a note nobody has revised, which is most of them.
	RevisedBy string
	RevisedAt time.Time

	// DedupKey is the identity of the recommendation this note carries (node,
	// subject, direction), computed by DedupKey at Write and written into the
	// file so a reviewer can see WHY a later proposal was refused without
	// re-running the derivation in their head.
	//
	// Empty on a note whose recommendation could not be identified, and that
	// is not a fault: an empty key matches nothing and blocks nothing.
	//
	// Notes written before this field existed carry no line for it, and parse
	// re-derives one from the title and body they do have. That is worth
	// being precise about rather than claiming too much for it: prompt.go
	// only started mandating the "## Recommendation" heading on 2026-08-20
	// (640d0a4), so an older note falls back to its title alone, and a title
	// that names a metric without naming what to do about it derives no key
	// and blocks nothing. The re-derivation is what lets the guard work
	// against an existing queue at all, without rewriting a single file in
	// it. It is not a promise that every note already in one is covered.
	DedupKey string

	// Set once, by Mark.
	Status    string // pending | promoted | rejected
	DecidedBy string
	DecidedAt time.Time
	// Reason carries a rejection's optional why. A re-proposal can then say
	// "rejected before, because…" instead of arriving as if it were new.
	Reason string
	// File is where a promotion put the note, relative to knowledge-fleet/.
	File string
}

// NewNote is everything a caller supplies for one proposal. A struct rather
// than eight positional strings, and the two graded fields sit in it beside
// the rest on purpose: a caller that forgets them writes an inferred note at
// RankMin, which is the safe end of the scale.
type NewNote struct {
	Title    string
	Body     string
	Node     string
	Source   string
	Question string
	// Provenance and Rank come from internal/proposalrank, never from
	// anything the model said about its own note.
	Provenance string
	Rank       int
}

// Write creates one note file under dir (state/inbox by convention — a
// sibling of state/runs, per D3 §2.4, and of the knowledge/ loader root,
// never a child of it). dir is created at 0750 if absent, matching every
// other writer under state/. The file itself lands at 0640, the same mode
// tightenState already narrows the rest of state/ to on every start.
//
// It refuses one thing, and the refusal is the whole of issue #115: a
// recommendation a PENDING note already carries is not written a second time.
// The guard lives here rather than in the caller because "the inbox does not
// hold two copies of the same waiting recommendation" is a property of the
// inbox, and a guard one caller performs is a guard the next caller forgets.
// See dedup.go for the key, for why the model does not author it, and for why
// a superseding proposal is refused rather than written over the pending one.
func Write(dir string, in NewNote) (Note, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Note{}, err
	}
	key := DedupKey(in.Node, in.Title, in.Body)
	if key != "" {
		// A read failure here is not a refusal. If the queue cannot be read
		// the honest outcome is the note on disk, not a proposal dropped over
		// an unrelated fault: List already returns an empty list and no error
		// for the ordinary case of a node that has never proposed anything,
		// so reaching this branch means a real I/O problem, and the answer to
		// one of those is never to throw away the evidence in hand.
		if prior, err := List(dir); err == nil {
			for _, p := range prior {
				if p.Status == StatusPending && p.DedupKey == key {
					return Note{}, &DuplicatePendingError{Key: key, Existing: p}
				}
			}
		}
	}
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return Note{}, err
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("%d-%s", now.UnixNano(), hex.EncodeToString(r[:]))
	n := Note{
		ID: id, Title: oneLine(in.Title, 200), Body: strings.TrimSpace(in.Body),
		Node: in.Node, Source: in.Source, CreatedAt: now,
		Question:   oneLine(in.Question, maxQuestionBytes),
		Status:     StatusPending,
		Provenance: normalizeProvenance(in.Provenance),
		Rank:       clampRank(in.Rank),
		DedupKey:   key,
	}
	p := filepath.Join(dir, id+".md")
	if err := os.WriteFile(p, []byte(render(n)), 0o640); err != nil {
		return Note{}, err
	}
	n.Path = p
	return n, nil
}

// List reads every note in dir, newest first. A file that cannot be parsed
// is skipped rather than failing the whole read: one malformed note must not
// hide the rest of the queue from the person reviewing it. A missing
// directory is an empty list and no error — a node whose Advisor has never
// proposed anything is the ordinary case, not a fault.
func List(dir string) ([]Note, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		names = append(names, e.Name())
	}
	// The id is unix nanos first, so the name sorts by age. Newest first,
	// then capped, so a long-lived inbox costs the card the newest maxList
	// rather than an arbitrary maxList.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > maxList {
		names = names[:maxList]
	}
	out := make([]Note, 0, len(names))
	for _, name := range names {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxNoteBytes {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		n, ok := parse(string(b))
		if !ok {
			continue
		}
		n.Path = p
		if n.ID == "" {
			n.ID = strings.TrimSuffix(name, ".md")
		}
		out = append(out, n)
	}
	return out, nil
}

// Get reads one note by id, without reading the rest of the directory. The
// same guards List applies to every file it reads apply here: an id that is
// not the shape Write mints never names a path, and a file too large to be
// one of ours is not read.
//
// Exists because the caller that revises a note has to grade it FIRST, from
// the title on disk rather than from anything the request carried, and Listing
// five hundred files to find one of them is not the read that deserves.
func Get(dir, id string) (Note, error) {
	if !idRe.MatchString(id) {
		return Note{}, ErrNoSuchNote
	}
	p := filepath.Join(dir, id+".md")
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Note{}, ErrNoSuchNote
		}
		return Note{}, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxNoteBytes {
		return Note{}, ErrNoSuchNote
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return Note{}, err
	}
	n, ok := parse(string(b))
	if !ok {
		return Note{}, fmt.Errorf("the note on disk could not be read: %s", p)
	}
	n.ID = id
	n.Path = p
	return n, nil
}

// Mark records a decision on one note: promoted, with the file the promotion
// wrote, or rejected, with an optional reason. The body is carried through
// untouched — this edits the frontmatter only.
//
// Written to a temp file and renamed INSIDE dir, so a decision is either
// fully recorded or not recorded at all, and so the rename never crosses out
// of a directory the unit is allowed to write.
func Mark(dir, id, status, by, reason, file string) (Note, error) {
	if status != StatusPromoted && status != StatusRejected {
		return Note{}, fmt.Errorf("a proposal is marked promoted or rejected, not %q", status)
	}
	n, err := Get(dir, id)
	if err != nil {
		return Note{}, err
	}
	n.Status = status
	n.DecidedBy = oneLine(by, 200)
	n.DecidedAt = time.Now().UTC()
	n.Reason = oneLine(reason, 400)
	n.File = oneLine(file, 400)
	if err := writeInPlace(dir, n); err != nil {
		return Note{}, err
	}
	return n, nil
}

// Revision is what Revise writes onto a pending note. Provenance and Rank are
// NOT computed here and never derived from Body: they come from
// internal/proposalrank, which grades the investigation record the service
// itself wrote. This package's job is to refuse the notes that may not be
// revised and to put the result on disk atomically.
type Revision struct {
	// Body replaces the note's body. Required: a revision that emptied the
	// note would leave the operator deciding on nothing.
	Body string
	// By is the operator who verified it, recorded on the note.
	By string
	// Provenance and Rank are the caller's re-grading of the revised note.
	Provenance string
	Rank       int
}

// Revise rewrites one PENDING note's body and grade.
//
// Two refusals, and the order matters: an id this inbox does not hold is
// ErrNoSuchNote (which is also what keeps one node's revision from landing on
// another's inbox — ids are minted per node and never collide), and a note
// somebody has already decided is ErrNotPending. A promoted note's body is
// already in the fleet corpus; rewriting the queue entry afterwards would
// leave the two saying different things with no sign that they should.
func Revise(dir, id string, rev Revision) (Note, error) {
	body := strings.TrimSpace(rev.Body)
	if body == "" {
		return Note{}, fmt.Errorf("a revision needs a body")
	}
	n, err := Get(dir, id)
	if err != nil {
		return Note{}, err
	}
	if n.Status != StatusPending {
		return Note{}, ErrNotPending
	}
	n.Body = body
	// The key describes the body, so it is re-derived with it. Without this
	// the note keeps the key parse read off the old file: an operator who
	// verifies "raise the crit" and rewrites it as "lower the warn tier"
	// would leave a note recommending down while still holding an up key, and
	// the next honest proposal to raise it would be refused against a note
	// that no longer says that. Re-deriving can also empty the key, which
	// unblocks everything, which is the right direction to fail in.
	n.DedupKey = DedupKey(n.Node, n.Title, body)
	n.RevisedBy = oneLine(rev.By, 200)
	n.RevisedAt = time.Now().UTC()
	n.Provenance = normalizeProvenance(rev.Provenance)
	n.Rank = clampRank(rev.Rank)
	if err := writeInPlace(dir, n); err != nil {
		return Note{}, err
	}
	return n, nil
}

// writeInPlace renders n over its own file through a temp file and a rename
// INSIDE dir. One copy of that sequence for both editors: an edit is either
// fully recorded or not recorded at all, and the rename never crosses out of a
// directory the unit is allowed to write (a cross-directory rename is EROFS on
// a hardened host, which the bundle apply hit once already).
func writeInPlace(dir string, n Note) error {
	tmp, err := os.CreateTemp(dir, ".mark-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := tmp.WriteString(render(n)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return err
	}
	return os.Rename(tmpName, n.Path)
}

// render is deliberately plain markdown with a small frontmatter block, not
// strict YAML — every value it writes is forced onto one line first, so a
// title with a newline in it cannot invent a field. A person reading it
// later (a text editor, an Obsidian-style vault) is a first-class consumer
// of this format, alongside parse below.
func render(n Note) string {
	var b strings.Builder
	fmt.Fprintf(&b, "---\n")
	fmt.Fprintf(&b, "id: %s\n", n.ID)
	fmt.Fprintf(&b, "title: %s\n", n.Title)
	if n.Node != "" {
		fmt.Fprintf(&b, "node: %s\n", n.Node)
	}
	fmt.Fprintf(&b, "source: %s\n", n.Source)
	fmt.Fprintf(&b, "created_at: %s\n", n.CreatedAt.Format(time.RFC3339))
	if n.Question != "" {
		fmt.Fprintf(&b, "question: %s\n", n.Question)
	}
	// Always written, both of them, even at their defaults: a reviewer
	// opening the file in an editor should read the grade the card shows,
	// and "no line" is how a note from before this existed is recognised.
	fmt.Fprintf(&b, "provenance: %s\n", normalizeProvenance(n.Provenance))
	fmt.Fprintf(&b, "rank: %d\n", clampRank(n.Rank))
	// Written only when there is one, so its absence keeps meaning what it
	// has always meant: this note's recommendation was not identifiable, and
	// nothing is being deduplicated against it.
	if n.DedupKey != "" {
		fmt.Fprintf(&b, "dedup_key: %s\n", n.DedupKey)
	}
	// Only on a note somebody revised, which is why they are written
	// conditionally: their ABSENCE is how a reader knows the body below is
	// the one the Advisor proposed.
	if n.RevisedBy != "" {
		fmt.Fprintf(&b, "revised_by: %s\n", n.RevisedBy)
	}
	if !n.RevisedAt.IsZero() {
		fmt.Fprintf(&b, "revised_at: %s\n", n.RevisedAt.Format(time.RFC3339))
	}
	status := n.Status
	if status == "" {
		status = StatusPending
	}
	fmt.Fprintf(&b, "status: %s\n", status)
	if n.DecidedBy != "" {
		fmt.Fprintf(&b, "decided_by: %s\n", n.DecidedBy)
	}
	if !n.DecidedAt.IsZero() {
		fmt.Fprintf(&b, "decided_at: %s\n", n.DecidedAt.Format(time.RFC3339))
	}
	if n.Reason != "" {
		fmt.Fprintf(&b, "reason: %s\n", n.Reason)
	}
	if n.File != "" {
		fmt.Fprintf(&b, "file: %s\n", n.File)
	}
	b.WriteString("---\n\n")
	b.WriteString(n.Body)
	b.WriteString("\n")
	return b.String()
}

// parse is render's inverse, and deliberately forgiving in one direction
// only: a field it does not know is ignored, and a field that is absent
// stays at its zero value. Notes written before phase 2 carry no question
// and no decision fields, and they come back as pending with an empty
// question — which is what they are, not a parse failure.
func parse(s string) (Note, bool) {
	if !strings.HasPrefix(s, "---\n") {
		return Note{}, false
	}
	rest := s[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return Note{}, false
	}
	head, body := rest[:end], rest[end+len("\n---\n"):]
	// The defaults live HERE, in the initializer, so every path that reads a
	// note gets them: List, and Mark's read-modify-write. A note that lost
	// its grade in the file must not come back as a zero rank the card
	// renders as a blank chip, or worse, as a high one.
	n := Note{
		Status: StatusPending, Body: strings.TrimSpace(body),
		Provenance: ProvenanceInferred, Rank: RankMin,
	}
	for _, line := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			// A bare "key:" is an empty value and a line with no colon at
			// all is not a field. Both leave the zero value in place.
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "id":
			n.ID = v
		case "title":
			n.Title = v
		case "node":
			n.Node = v
		case "source":
			n.Source = v
		case "question":
			n.Question = v
		case "provenance":
			n.Provenance = normalizeProvenance(v)
		case "rank":
			// A value that is not a number leaves RankMin in place. Same
			// direction as everything else here: unreadable is untrusted.
			if r, err := strconv.Atoi(v); err == nil {
				n.Rank = clampRank(r)
			}
		case "dedup_key":
			n.DedupKey = v
		case "status":
			n.Status = v
		case "decided_by":
			n.DecidedBy = v
		case "revised_by":
			// Read back for the same reason provenance is: Mark's
			// read-modify-write re-renders the whole file, and a field parse
			// does not fill is erased the moment anybody decides the note.
			n.RevisedBy = v
		case "reason":
			n.Reason = v
		case "file":
			n.File = v
		case "created_at":
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				n.CreatedAt = t
			}
		case "decided_at":
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				n.DecidedAt = t
			}
		case "revised_at":
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				n.RevisedAt = t
			}
		}
	}
	// Re-derived when the file carries no line for it, which is every note
	// written before the guard existed. Without this an inbox that already
	// holds duplicates would go on collecting them, and the guard would only
	// begin working on a queue somebody had cleared by hand first. What it
	// recovers depends on what the old note says: see Note.DedupKey for the
	// limit. It costs one derivation per note per read, over a directory
	// capped at 500.
	if n.DedupKey == "" {
		n.DedupKey = DedupKey(n.Node, n.Title, n.Body)
	}
	return n, true
}

// normalizeProvenance admits exactly one word. Everything else — an empty
// field, a typo, a value a hand edit invented — is inferred, because the
// claim "this was measured" is the one worth being strict about.
func normalizeProvenance(s string) string {
	if strings.TrimSpace(strings.ToLower(s)) == ProvenanceMeasured {
		return ProvenanceMeasured
	}
	return ProvenanceInferred
}

// clampRank holds the scale closed at both ends. A rank of 0 (a caller that
// did not grade) and a rank of 9 (a hand-edited file) both become something
// the card can render honestly.
func clampRank(r int) int {
	if r < RankMin {
		return RankMin
	}
	if r > RankMax {
		return RankMax
	}
	return r
}

// oneLine collapses every run of whitespace to a single space and caps the
// result. Everything written into the frontmatter goes through it: a title
// or a question carrying a newline would otherwise write a line the parser
// reads as another field, which is how a model gets to author metadata.
func oneLine(s string, max int) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) > max {
		s = strings.TrimSpace(s[:max])
	}
	return s
}
