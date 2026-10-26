package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/knowledge"
	"aperire-advisor/internal/ledger"
)

// POST /v1/knowledge/bundle — ADR 0017 decision 3.
//
// The aggregator pushes its knowledge-fleet/ to every node over the same
// loopback forward the trust bundle already uses: no new port, no new
// credential, no inbound path. Everything that decides whether a bundle is
// accepted is in internal/knowledge, unit-tested against a real keypair and
// against every way a tar can lie. This file is the door: the same bearer
// gate the trust bundle has, the same issuer-to-key resolution, and the two
// records a push leaves behind (the ledger entry and the receipt).
//
// It reuses the trust bundle's KEY, deliberately, and not its PIN. The pin
// there is rp_id plus origins — the set of places a passkey may be created —
// which has no meaning for a corpus of notes. A second pin file would be a
// second thing to get out of step; what makes a knowledge bundle safe is that
// its content grants nothing, so the question worth answering at the door is
// only "did the aggregator this node already trusts sign this, and is it
// newer than what I have".

// knowledgeBundleMaxBody bounds the JSON envelope. The archive inside is
// capped at knowledge.MaxBundleBytes; base64 costs a third more, and the
// manifest of a 2,000-file corpus is a few hundred kilobytes.
const knowledgeBundleMaxBody = 8 << 20

func (s *server) knowledgeBundle(w http.ResponseWriter, r *http.Request) {
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
		Bundle    string             `json:"bundle"` // base64 of the tar.gz
		Manifest  knowledge.Manifest `json:"manifest"`
		Signature string             `json:"sig"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, knowledgeBundleMaxBody)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	if req.Manifest.IssuerLabel == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": knowledge.ErrNoIssuer.Error()})
		return
	}
	gz, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Bundle))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the bundle is not valid base64"})
		return
	}
	if len(gz) > knowledge.MaxBundleBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": fmt.Sprintf("%v: %d bytes", knowledge.ErrTooLarge, len(gz))})
		return
	}

	// The aggregator's public key, by the label the manifest declares — the
	// same lookup and the same file the trust bundle uses. A manifest naming
	// an issuer this node does not trust fails closed here.
	aggKey, err := host.AggregatorPubKey(s.fleetTrust, req.Manifest.IssuerLabel)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	if err := req.Manifest.VerifySignature(req.Signature, aggKey); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	// One push at a time. Two pushes racing the directory swap would leave
	// the receipt describing one bundle and the corpus holding the other.
	s.knowledgeMu.Lock()
	defer s.knowledgeMu.Unlock()

	statePath := s.knowledgeStatePath()
	applied, err := knowledge.LoadApplied(statePath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "cannot read the applied-bundle record: " + err.Error()})
		return
	}
	if err := req.Manifest.CheckSequence(knowledge.AppliedSeq(applied)); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}

	stats, err := knowledge.Install(s.knowledgeFleet, gz, &req.Manifest)
	if err != nil {
		// Fail closed, with the named reason. Nothing was applied: Install
		// verifies into a staging directory beside the corpus and only then
		// swaps, so a refusal here leaves the running corpus exactly as it
		// was.
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, knowledge.ErrTooLarge):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, knowledge.ErrPath), errors.Is(err, knowledge.ErrHash),
			errors.Is(err, knowledge.ErrManifest), errors.Is(err, knowledge.ErrArchive),
			errors.Is(err, knowledge.ErrEmptyBundle):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
		log.Printf("[knowledge] bundle seq %d from %q refused: %v", req.Manifest.Seq, req.Manifest.IssuerLabel, err)
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}

	sum := sha256.Sum256(gz)
	digest := hex.EncodeToString(sum[:])
	// The receipt is written AFTER the swap, so it can never claim a corpus
	// that is not on disk. A failure to write it is logged and not fatal: the
	// files ARE in place, and refusing the push at this point would report
	// the opposite of what happened. The cost of losing it is one replay of
	// this same sequence, which applies the same content again.
	if err := knowledge.SaveApplied(statePath, &knowledge.Applied{
		Seq:       req.Manifest.Seq,
		SHA256:    digest,
		PushedBy:  req.Manifest.PushedBy,
		Issuer:    req.Manifest.IssuerLabel,
		AppliedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		log.Printf("[knowledge] bundle applied but the receipt could not be written: %v", err)
	}

	if l, lerr := ledger.Open(s.ledgerPath()); lerr == nil && l != nil {
		l.AppendAs(ledger.KindKnowledgeUpdated, "",
			fmt.Sprintf("fleet knowledge bundle %d applied: %d added, %d changed, %d removed (%d files)",
				req.Manifest.Seq, stats.Added, stats.Changed, stats.Removed, stats.Files),
			map[string]any{
				"seq":       req.Manifest.Seq,
				"sha256":    digest,
				"pushed_by": req.Manifest.PushedBy,
				"issuer":    req.Manifest.IssuerLabel,
				"added":     stats.Added,
				"changed":   stats.Changed,
				"removed":   stats.Removed,
				"files":     stats.Files,
			},
			serviceActor(aggregatorActorName(req.Manifest.IssuerLabel)))
	}
	log.Printf("[knowledge] bundle seq %d from %q applied: %d added, %d changed, %d removed",
		req.Manifest.Seq, req.Manifest.IssuerLabel, stats.Added, stats.Changed, stats.Removed)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"seq":     req.Manifest.Seq,
		"added":   stats.Added,
		"changed": stats.Changed,
		"removed": stats.Removed,
		"files":   stats.Files,
		"sha256":  digest,
	})
}

// knowledgeStatePath is where the receipt lives: in the state directory,
// beside the trust bundle's own receipt, not inside knowledge-fleet/ — a
// record of what was applied must not be inside the thing a later push
// replaces wholesale.
func (s *server) knowledgeStatePath() string {
	return filepath.Join(s.stateDir, "knowledge-bundle.json")
}

// knowledgeStatus is the /v1/status "knowledge" block: which fleet bundle
// this node is running, and when it took it. nil when none has ever been
// applied — never pushed and pushed-with-sequence-zero are different facts,
// and the aggregator renders them differently.
func (s *server) knowledgeStatus() map[string]any {
	a, err := knowledge.LoadApplied(s.knowledgeStatePath())
	if err != nil || a == nil {
		return nil
	}
	out := map[string]any{"seq": a.Seq, "applied_at": a.AppliedAt}
	if a.PushedBy != "" {
		out["pushed_by"] = a.PushedBy
	}
	if a.Issuer != "" {
		out["issuer"] = a.Issuer
	}
	return out
}
