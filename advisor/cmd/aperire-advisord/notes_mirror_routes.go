package main

import (
	"net/http"
	"path/filepath"
	"time"

	"aperire-advisor/internal/inbox"
	"aperire-advisor/internal/memory"
)

// The two reads ADR 0021 build step 5 adds, the aggregator's mirror feed
// for what this node's Advisor remembers and what it has proposed. Both are
// gated exactly like /v1/ledger: readOnly, so GET only and behind the
// service's bearer token. Neither answer is scoped to a validator or
// filtered to what a review card needs; the mirror wants everything the
// node holds, because a mirror that drops rows on the way in cannot be
// rebuilt whole from the node later.
//
// Distinct from GET /v1/proposals on purpose. That route is the operator's
// live review queue: pending notes in full, decided ones as a count, this
// node only, and the review card and promoteProposal both depend on that
// exact shape. This route answers every note, decided ones included, with
// their body and who decided them, the aggregator's mirror needs the full
// history, not the queue.

// rfc3339OrEmpty formats a time.Time the way this file's JSON answers do:
// RFC3339 when it is set, and an empty string rather than the zero value's
// "0001-01-01T00:00:00Z" when it is not. A caller reading this as a date
// should see "no such date" as absence, not as a year the ledger cannot
// have entries in.
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// GET /v1/memory, every entry this node's Advisor has recorded, oldest
// first, as memory.Store dedupes and orders them (a later line for the same
// id wins, and anything superseded drops out). A retracted entry stays, with
// superseded_by "retracted" and who withdrew it (#1012 review, L3): the
// aggregator's mirror upserts and never deletes, so a retraction it could not
// see would leave the note standing there.
func (s *server) memory(_ http.ResponseWriter, _ *http.Request) (any, int) {
	store, err := memory.Open(filepath.Join(s.stateDir, "memory.jsonl"))
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	entries, err := store.AllWithRetracted()
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		tags := e.Tags
		if tags == nil {
			tags = []string{}
		}
		confirmedAt := ""
		if e.ConfirmedAt != nil {
			confirmedAt = rfc3339OrEmpty(*e.ConfirmedAt)
		}
		out = append(out, map[string]any{
			"id":            e.ID,
			"at":            rfc3339OrEmpty(e.At),
			"kind":          string(e.Kind),
			"title":         e.Title,
			"body":          e.Body,
			"node":          e.Node,
			"tags":          tags,
			"source":        e.Source,
			"confirmed_by":  e.ConfirmedBy,
			"confirmed_at":  confirmedAt,
			"superseded_by": e.Superseded,
		})
		if e.Superseded == memory.Retracted {
			row := out[len(out)-1]
			row["retracted"] = true
			row["retracted_by"] = e.RetractedBy
			if e.RetractedAt != nil {
				row["retracted_at"] = rfc3339OrEmpty(*e.RetractedAt)
			}
			row["retracted_why"] = e.RetractedWhy
		}
	}
	return map[string]any{"entries": out, "count": len(out)}, http.StatusOK
}

// GET /v1/inbox, every note in this node's inbox, newest first (internal/
// inbox.List's own order), pending and decided alike, in full.
func (s *server) inboxAll(_ http.ResponseWriter, _ *http.Request) (any, int) {
	dir := filepath.Join(s.stateDir, "inbox")
	notes, err := inbox.List(dir)
	if err != nil {
		return map[string]any{"error": err.Error()}, http.StatusServiceUnavailable
	}
	out := make([]map[string]any, 0, len(notes))
	for _, n := range notes {
		out = append(out, map[string]any{
			"id":         n.ID,
			"title":      n.Title,
			"body":       n.Body,
			"node":       n.Node,
			"question":   n.Question,
			"source":     n.Source,
			"created_at": rfc3339OrEmpty(n.CreatedAt),
			"provenance": n.Provenance,
			"rank":       n.Rank,
			"status":     n.Status,
			"decided_by": n.DecidedBy,
			"decided_at": rfc3339OrEmpty(n.DecidedAt),
			"reason":     n.Reason,
			"file":       n.File,
		})
	}
	return map[string]any{"notes": out, "count": len(out)}, http.StatusOK
}
