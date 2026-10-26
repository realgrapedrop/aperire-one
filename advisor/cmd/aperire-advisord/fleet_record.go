package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/fleet"
	"aperire-advisor/internal/fleetrecord"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/ledger"
)

// POST /v1/fleet/record, the append surface for an act done TO this node
// (#455).
//
// The door, and only the door: internal/fleetrecord holds every rule that
// decides whether a record is accepted, unit-tested against a real keypair.
// What lives here is the wiring, and it is the same wiring the trust bundle
// and the knowledge bundle already have, deliberately:
//
//  1. POST only.
//  2. The service token, the gate on every advisord write.
//  3. The issuer's public key, resolved from THIS node's fleet-trust.yaml by
//     the label the record declares. A record claiming an issuer this node
//     does not trust fails closed before anything else is read. One label is
//     not a peer at all: the literal "self" resolves out of this node's own
//     signing seed (host.OwnPubKey) and is checked before peers is ever
//     consulted, so a peers entry named "self" can never be read as it
//     (#477). This is what lets an aggregator hold a second copy of its own
//     act, appended to its own advisord over loopback under that label.
//  4. The detached Ed25519 signature over the canonical bytes.
//  5. Shape: a closed set of kinds, per-kind fields, a freshness window.
//  6. Replay: a record_id already on this ledger is answered as the append
//     it was, and appended once.
//
// What is deliberately NOT here: any way for the caller to choose the
// summary, the time, the sequence or the actor's `verified`. The record says
// what happened and who the aggregator's session named; this service writes
// the sentence, stamps its own clock and says exactly what it proved.
func (s *server) fleetRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	want, err := s.approveToken()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
		return
	}

	var req struct {
		Record    fleetrecord.Record `json:"record"`
		Signature string             `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, fleetrecord.MaxBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	rec := req.Record
	if strings.TrimSpace(rec.IssuerLabel) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the record carries no issuer_label"})
		return
	}
	// The literal "self" is checked FIRST and resolved out of THIS node's own
	// signing seed, never out of peers, and never as a fallback from a peers
	// lookup that came up empty (#477). This is the aggregator's own copy of
	// an act it did to another node: the aggregator has no peers.aggregator
	// entry for itself, and a peer that happened to be labelled "self" must
	// never be usable as a way to escalate to this node's own key. Because
	// this branch never calls AggregatorPubKey, a peers.self entry is never
	// read at all, on any request, whether it verifies or not.
	selfIssuer := rec.IssuerLabel == "self"
	// A narrower guard than "must be an aggregator", and deliberately so
	// (#477 security review). self.role is operator-declared, set only by
	// running scripts/aperire-advisor-fleet-sync.sh --self-label <label> by
	// hand, and "never inferred" by the fleet package's own rule. Most
	// aggregators in the estate today have never run it, and hard-refusing
	// self whenever the role is merely UNKNOWN would silently take the
	// feature away from exactly the hosts it is for. What this DOES refuse,
	// with no new coupling (fleetReg is already loaded at start for the
	// cross-node ask feature): a host whose registry DEFINITELY names it
	// something other than an aggregator. That is the one case a private_key
	// left over from some other purpose (or copied) is not enough on its own
	// to mint a self-issued entry. The residual gap, a host with a
	// private_key and an UNLABELLED self block, is recorded rather than
	// papered over, in the maintainer's design notes.
	if selfIssuer {
		if self := s.fleetNow().reg.SelfIdentity(); self.Role != "" && self.Role != fleet.RoleAggregator {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": fmt.Sprintf("this host's own fleet registry names it a %s, not an aggregator, "+
					"so it may not record a self-issued fleet entry", self.Role),
			})
			return
		}
	}
	var aggKey string
	if selfIssuer {
		aggKey, err = host.OwnPubKey(s.fleetTrust)
	} else {
		aggKey, err = host.AggregatorPubKey(s.fleetTrust, rec.IssuerLabel)
	}
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	if err := rec.VerifySignature(req.Signature, aggKey); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	// Shape AFTER the signature, so a malformed record is only ever read
	// from the aggregator this node trusts. 422 and not 400: the request was
	// understood, and it was this record that could not be recorded.
	if err := rec.Validate(time.Now()); err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, fleetrecord.ErrUnknownKind) {
			// Its own status, because its own remedy: a kind this build does
			// not know is an aggregator running ahead of this node, and what
			// the operator does about it is update the node.
			status = http.StatusNotImplemented
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	kind, ok := fleetrecord.LedgerKind(rec.Kind)
	if !ok {
		// Unreachable: Validate asks the same question first. Kept because
		// the alternative to an impossible branch here is an empty Kind
		// reaching Append, and a ledger entry with no kind is worse than a
		// line of dead code.
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": fleetrecord.ErrUnknownKind.Error()})
		return
	}

	// One at a time from here: the replay guard is a question about the
	// ledger, and the answer has to still be true when the append lands.
	s.fleetRecordMu.Lock()
	defer s.fleetRecordMu.Unlock()

	if held, err := fleetRecordEntry(s.ledgerPath(), rec.RecordID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "this node cannot read its own ledger, so it cannot tell a repeat from a first delivery: " + err.Error(),
		})
		return
	} else if held != nil {
		// Idempotent rather than refused. The aggregator retries a push that
		// died in transit, and a second copy of a record already written is
		// that retry, not an attack: answering it with the entry that exists
		// is what stops a dashboard writing the same act twice.
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "duplicate": true, "seq": held.Seq, "hash": held.Hash, "kind": string(held.Kind),
		})
		return
	}

	l, err := ledger.Open(s.ledgerPath())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "this node's ledger could not be opened for append: " + err.Error(),
		})
		return
	}
	store, _ := host.LoadCredentials(filepath.Join(s.stateDir, "credentials.json"))
	entry, err := l.AppendAs(kind, "", rec.Summary(selfIssuer), rec.Data(),
		fleetRecordActor(store, &rec))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "this node could not append to its ledger: " + err.Error(),
		})
		return
	}
	log.Printf("[fleet-record] %s recorded for %q by %q (issuer %s, seq %d)",
		rec.Kind, rec.Node, rec.Operator, rec.IssuerLabel, entry.Seq)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "seq": entry.Seq, "hash": entry.Hash, "kind": string(entry.Kind),
	})
}

// fleetRecordEntry answers "has this record_id already been written here",
// from the ledger itself rather than from a side file.
//
// The ledger is the thing the guard is protecting, so it is also the honest
// place to ask: a separate nonce store can be lost, pruned or restored out of
// step with the record it is supposed to be guarding, and then the guard
// reads clean for an id that is plainly in the file. These appends happen a
// handful of times in a fleet's life, so reading the file to answer is free.
//
// Only the kinds that ARRIVE FROM OFF THIS BOX are considered, so a
// record_id can never collide with an unrelated entry that happens to carry
// the same member.
//
// That set is asked for by name rather than listed here (#691). It used to
// be spelled out as two explicit comparisons, and when #641 added two more
// kinds this line was not one of the files in scope: the new kinds were
// accepted, written, and then skipped by this scan, so a captured attach or
// detach record could be appended a second time inside its freshness
// window. A duplicated entry in an append-only record of what was done to
// this node is indistinguishable from tampering, which is the one thing
// this file exists to prevent.
//
// ledger.IsFleetRecordKind is the single declaration of that set, and
// fleetrecord's own TestLedgerKindIsClosed fails if a kind is ever added to
// the wire set and not to it. So the next kind cannot reopen this.
func fleetRecordEntry(path, recordID string) (*ledger.Entry, error) {
	entries, err := ledger.Entries(path)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		e := entries[i]
		if !ledger.IsFleetRecordKind(e.Kind) {
			continue
		}
		if id, _ := e.Data["record_id"].(string); id == recordID {
			return &e, nil
		}
	}
	return nil, nil
}
