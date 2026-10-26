package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"aperire-advisor/internal/inbox"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/proposalrank"
)

// The proposal inbox, over HTTP — ADR 0017 decision 4.
//
// Three endpoints, and the split between them is the ADR's: this node writes
// proposals and records decisions, the aggregator's review card is where a
// person decides, and the knowledge itself travels back as a signed bundle
// on a separate path. Nothing here promotes anything: a promoted note is
// written into the aggregator's knowledge-fleet/local/ and reaches this node
// as content it verifies, not as a claim it takes on trust from this call.
//
// All three are gated by the service token like every other endpoint. GET is
// read-only and rides `readOnly`; the mark is a POST because it writes, and
// what it writes is one note's decision fields plus a ledger entry. The
// revise is the trust model's Part B and is described where it is defined.

// GET /v1/proposals — this node's inbox.
//
// Pending notes in full (the reviewer needs the body to decide), decided
// ones as a count only. A decided note is not deleted: it stays on disk with
// who decided it and when, which is what lets a later re-proposal be told
// that this was rejected before.
func (s *server) proposals(_ http.ResponseWriter, _ *http.Request) (any, int) {
	dir := filepath.Join(s.stateDir, "inbox")
	notes, err := inbox.List(dir)
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	pending := make([]map[string]any, 0, len(notes))
	decided := 0
	for _, n := range notes {
		if n.Status != inbox.StatusPending {
			decided++
			continue
		}
		pending = append(pending, map[string]any{
			"id":         n.ID,
			"node":       n.Node,
			"created_at": n.CreatedAt,
			"question":   n.Question,
			"title":      n.Title,
			"body":       n.Body,
			"status":     n.Status,
			// The grade the service computed when the note was written
			// (internal/proposalrank). Always present, because inbox.List
			// defaults a note that carries none to inferred at RankMin —
			// the card must never have to guess, and a missing grade is
			// not a neutral one.
			"provenance": n.Provenance,
			"rank":       n.Rank,
		})
	}
	return map[string]any{
		"proposals": pending,
		"pending":   len(pending),
		"decided":   decided,
	}, http.StatusOK
}

// POST /v1/proposals/mark — record what the operator decided.
//
// body: {id, decision: "promoted"|"rejected", reason?, file?, operator, role}
//
// operator and role are injected by the dashboard proxy from the session
// cookie, exactly as they are for evidence, ask and the break-glass writes.
// A body that carried its own would be an audit trail the browser fills in.
//
// A mark aimed at the wrong node finds no such id and is refused with 404.
// That is the whole node guard: ids are minted per node from unix nanos plus
// four random bytes and never collide, so there is nothing here for a
// misrouted decision to land on.
func (s *server) proposalMark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}
	var req struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		File     string `json:"file"`
		Operator string `json:"operator"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}
	if req.Decision != inbox.StatusPromoted && req.Decision != inbox.StatusRejected {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "decision must be promoted or rejected",
		})
		return
	}
	actor := sessionActor(req.Operator, req.Role)
	by := req.Operator
	if by == "" {
		by = "an operator at the aggregator"
	}
	n, err := inbox.Mark(filepath.Join(s.stateDir, "inbox"), req.ID, req.Decision, by, req.Reason, req.File)
	if err == inbox.ErrNoSuchNote {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "no such proposal in this node's inbox",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	kind := ledger.KindProposalPromoted
	summary := fmt.Sprintf("proposal promoted to fleet knowledge by %s: %s", by, n.Title)
	data := map[string]any{"note_id": n.ID, "title": n.Title, "by": by}
	if n.File != "" {
		data["file"] = n.File
		summary += " (" + n.File + ")"
	}
	if req.Decision == inbox.StatusRejected {
		kind = ledger.KindProposalRejected
		summary = fmt.Sprintf("proposal rejected by %s: %s", by, n.Title)
		delete(data, "file")
		if n.Reason != "" {
			data["reason"] = n.Reason
			summary += " — " + n.Reason
		}
	}
	if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
		l.AppendAs(kind, "", summary, data, actor)
	}
	log.Printf("[inbox] proposal %s marked %s by %s", n.ID, n.Status, by)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": n.ID, "status": n.Status,
		"decided_by": n.DecidedBy, "decided_at": n.DecidedAt,
	})
}

// maxReviseBody bounds the note a revision may write.
//
// Well under inbox's own maxNoteBytes (256 KB) on purpose, and that gap is the
// whole reason for the number: inbox.List SKIPS a file larger than its cap, so
// a note revised past it would not be refused anywhere — it would simply stop
// appearing in the queue, with the operator's verified body on disk and the
// card showing one proposal fewer. Refused here, loudly, at a size no answer
// worth folding into a note ever reaches.
const maxReviseBody = 64 << 10

// POST /v1/proposals/revise — the operator verified a proposal against this
// node, and this is what came of it. The trust model's Part B (#49).
//
// body: {id, body, ask_id, operator, role}
//
// THERE IS NO "verified" FLAG IN THAT BODY, and its absence is the design.
// Part A's whole promise is that provenance is computed by the service from
// what an investigation did, never asserted by anything upstream of it — a
// browser (or anything holding the service token) that could post
// verified:true would be able to mint a Measured, top-ranked note over a claim
// nobody ever read. So the request carries the ask_id of the investigation
// instead, and this handler reads that investigation's OWN record back out of
// the progress store and grades it exactly as extractProposal grades a fresh
// proposal. The operator's contribution is the act, not the grade:
// OperatorVerified is what lets a measured note reach rank 5, and it lifts
// nothing at all when the record holds no measured reads.
//
// Five refusals, all of them honest and none of them writing anything:
//
//   - an id this inbox does not hold: 404, the same guard that keeps one
//     node's revision off another's inbox
//   - a note already promoted or rejected: 409, because its body is either in
//     the corpus already or is the record of a "no"
//   - an ask_id that is malformed, unknown, or still running: 409. The
//     progress store holds five minutes and thirty-two ids, so an operator
//     who reads an answer for a long while and then clicks IS refused, and
//     told to ask again. That is the correct outcome: without the record
//     there is nothing to compute a grade from, and a fallback that trusted
//     the click instead would be the hole this endpoint was built to avoid.
//   - an investigation that made no measured reads: 409, nothing written. A
//     verification against readings that do not exist verifies nothing, and
//     the alternative — writing the body and quietly grading it inferred —
//     would let a client's "verify" button silently downgrade a note the
//     operator was not asked about. The card offers the plain revision for
//     this case, which never reaches this endpoint at all.
//   - a body over maxReviseBody, or empty
func (s *server) proposalRevise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}
	var req struct {
		ID       string `json:"id"`
		Body     string `json:"body"`
		AskID    string `json:"ask_id"`
		Operator string `json:"operator"`
		Role     string `json:"role"`
	}
	// The limit is on the READ, so an oversized body is refused by the
	// decoder rather than measured after it is already in memory. A little
	// headroom over maxReviseBody for the JSON envelope and the escaping.
	if err := json.NewDecoder(io.LimitReader(r.Body, maxReviseBody+(8<<10))).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "the revision could not be read — it may be over the " +
				"64 KB a note can hold",
		})
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "a revision needs a body"})
		return
	}
	if len(body) > maxReviseBody {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "that revision is over 64 KB — a note the queue can still show is smaller than that",
		})
		return
	}

	dir := filepath.Join(s.stateDir, "inbox")
	// Read the note FIRST. Its title is what the rejected-before cap matches
	// on, and the title on disk is the one the operator has been reading — a
	// title taken from the request would let a caller pick which prior
	// rejections apply to it.
	n, err := inbox.Get(dir, req.ID)
	if err == inbox.ErrNoSuchNote {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "no such proposal in this node's inbox",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if n.Status != inbox.StatusPending {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "that proposal was already " + n.Status + ", so its body is no longer the queue's to change",
		})
		return
	}

	// The investigation's own record, read back from where the service wrote
	// it. Not from the request, and not from the answer text.
	if !askIDValidRe.MatchString(req.AskID) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "that verification carried no investigation to check it against, so nothing was changed",
		})
		return
	}
	snap, known := s.progress.snapshotFull(req.AskID)
	steps := snap.Steps
	if !known || snap.State != "answered" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this Advisor no longer holds the record of that investigation, so it cannot say what " +
				"it measured. Ask it again and use the fresh answer — nothing was changed.",
		})
		return
	}

	prior, lerr := inbox.List(dir)
	if lerr != nil {
		log.Printf("[inbox] prior notes unreadable, grading %q without them: %v", n.Title, lerr)
	}
	v := proposalrank.Score(proposalrank.Input{
		Steps: steps, Title: n.Title, Prior: prior, OperatorVerified: true,
	})
	if v.Reads == 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "that investigation made no measured reads, so there is nothing for it to verify. " +
				"The note is unchanged.",
			"measured_reads": 0,
		})
		return
	}

	by := req.Operator
	if by == "" {
		by = "an operator at the aggregator"
	}
	wasProvenance, wasRank := n.Provenance, n.Rank
	revised, err := inbox.Revise(dir, req.ID, inbox.Revision{
		Body: body, By: by, Provenance: v.Provenance, Rank: v.Rank,
	})
	if err == inbox.ErrNoSuchNote {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "no such proposal in this node's inbox",
		})
		return
	}
	if err == inbox.ErrNotPending {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "that proposal was decided while you were verifying it, so nothing was changed",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
		l.AppendAs(ledger.KindProposalRevised, "",
			fmt.Sprintf("proposal verified against this node by %s: %s", by, revised.Title),
			map[string]any{
				"note_id": revised.ID, "title": revised.Title, "by": by,
				"ask_id":          req.AskID,
				"measured_reads":  v.Reads,
				"provenance_was":  wasProvenance,
				"rank_was":        wasRank,
				"provenance":      revised.Provenance,
				"rank":            revised.Rank,
				"rejected_before": v.RejectedBefore,
			},
			sessionActor(req.Operator, req.Role))
	}
	log.Printf("[inbox] proposal %s verified by %s: %s rank %d → %s rank %d, from %d measured read(s)",
		revised.ID, by, wasProvenance, wasRank, revised.Provenance, revised.Rank, v.Reads)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": revised.ID,
		"title": revised.Title, "body": revised.Body,
		"provenance": revised.Provenance, "rank": revised.Rank,
		"provenance_was": wasProvenance, "rank_was": wasRank,
		"measured_reads": v.Reads, "rejected_before": v.RejectedBefore,
		"revised_by": revised.RevisedBy, "revised_at": revised.RevisedAt,
	})
}
