// Break glass — plan-interrogative-loop §11. Four endpoints (§11.8) and the
// gated session runner (§11.3a's window, §11.1's raised ceilings) that they
// spend. Deliberately does NOT take s.runMu, execute's per-node run lock
// (§11.8: "It mirrors execute's shape but must NOT take execute's run
// lock" — reading is not acting, and a 600-second read holding that lock
// would block a real upgrade behind an investigation).
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aperire-advisor/internal/approval"
	"aperire-advisor/internal/breakglass"
	"aperire-advisor/internal/compact"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/interrogate"
	"aperire-advisor/internal/ledger"
	"aperire-advisor/internal/model"
	"aperire-advisor/internal/runbook"
	"aperire-advisor/internal/webauthn"
)

// afterApprovalRow runs between the approval's ledger row and everything that
// follows it. A seam for one test: it lets the ledger fail on the NEXT row,
// which is the only way to pin that the window's row is written before the
// window opens.
var afterApprovalRow = func() {}

// withdrawUnrecorded retires a grant the ledger could not record and says what
// became of it, as a clause for the answer the operator reads. A grant that
// could be neither removed nor voided is still live, and the clause says so
// and until when (#1091): saying "withdrawn" over a live approval is worse
// than saying nothing.
func (s *server) withdrawUnrecorded(planID, stage string, cause error) string {
	a, withdrew, err := approval.Withdraw(filepath.Join(s.stateDir, "approvals"), planID, stage, time.Now())
	log.Printf("[approve] the ledger could not record the grant for %s stage %s (%v); withdrawn: %v (%v)",
		planID, stage, cause, withdrew, err)
	if err != nil && errors.Is(err, approval.ErrStillLive) {
		return fmt.Sprintf("it could not be withdrawn and is still live until %s; withdraw it in the Advisor tab",
			a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return "it was withdrawn"
}

func (s *server) ledgerPath() string { return filepath.Join(s.stateDir, "ledger.jsonl") }

// hasTierRefusal reports whether any step in the answer was refused for
// tier — the condition the break-glass offer anchors to. main.go's ask
// handler uses it to add the end-of-loop "cap spent" refusal only when the
// loop has not already recorded one.
func hasTierRefusal(steps []interrogate.Step) bool {
	for _, st := range steps {
		if st.RefusedBecause == interrogate.RefusedTier {
			return true
		}
	}
	return false
}

// considerOffer applies §11.4's six gating conditions (condition 1 — "a
// model is configured and the reply is a final answer" — already holds by
// construction: this is only ever called from ask() after loop.Run
// returned successfully) and, if they all hold, mints the offer: an
// offer_id, a fingerprint, a confirm code, and an entry in the offer store
// so investigate/begin can find the transcript later. Returns nil when the
// offer is suppressed — ask()'s caller must render nothing in that case,
// not an empty offer block.
// preResolved, when non-nil, is a would_read list the SERVICE already
// authored (SynthesizeOffer); a model-authored offer passes nil and is
// resolved against the host-verb registry as before.
func (s *server) considerOffer(o interrogate.OfferRequest, preResolved []string, steps []interrogate.Step, node, question string, messages []interrogate.Message) map[string]any {
	resolved := preResolved
	if resolved == nil {
		resolved = interrogate.ResolveWouldRead(o.WouldRead)
	}

	hasTierRefusal := false
	for _, st := range steps {
		if st.RefusedBecause == interrogate.RefusedTier {
			hasTierRefusal = true
			break
		}
	}

	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	_, windowOpen := s.breakglass.OpenForNode(node, time.Now())

	cond := interrogate.OfferConditions{
		CompactPermitsInvestigate:  accErr == nil && acc.Permits(runbook.ClassInvestigate),
		WrapperPresent:             s.wrapper != "",
		TierRefusalOrCeilingChange: hasTierRefusal,
		WindowOpen:                 windowOpen,
	}
	if !interrogate.ShouldOffer(resolved, cond) {
		return nil
	}

	offerID, err := mintOfferID()
	if err != nil {
		log.Printf("[investigate] could not mint an offer id: %v", err)
		return nil
	}
	s.offers.put(offerID, &offerRecord{
		Node: node, Question: question, Messages: messages, Why: o.Why, WouldRead: resolved,
	})

	fp := approval.InvestigationFingerprint(offerID, question, node)
	confirmCode := approval.ConfirmCode(fp)

	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		// The offer is an act the Advisor took on its own initiative — attribute
		// it to the service so the trail has no anonymous rows.
		l.AppendAs(ledger.KindInvestigateOffered, "", "an investigation offer was made",
			map[string]any{
				"offer_id": offerID, "trigger_sha256": sha256Hex(question),
				"why": o.Why, "would_read": resolved, "confirm_code": confirmCode,
			}, serviceActor("the Advisor"))
	}

	return map[string]any{
		"offer_id": offerID, "why": o.Why, "would_read": resolved, "confirm_code": confirmCode,
	}
}

// checkBearerToken is the same constant-time compare approveBegin/approve/
// execute already use, factored out once four callers needed it instead of
// copy-pasted a fifth time.
func (s *server) checkBearerToken(r *http.Request) (int, string) {
	want, err := s.approveToken()
	if err != nil {
		return http.StatusServiceUnavailable, err.Error()
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return http.StatusUnauthorized, "bad token"
	}
	return 0, ""
}

// ── POST /v1/investigate/offer ──────────────────────────────────────────

// investigateOffer mints an OPERATOR-INITIATED offer: no question, no
// refusal, no transcript to resume — the admin decided, from the panel's
// header, that the next questions should run at the gated tier (operator
// ruling 2026-08-19: "they can just click it and then the Advisor gets the
// okay to do deeper investigations with a timeout window"). Everything
// downstream is unchanged: the same offer store, the same fingerprint, the
// same confirm code, the same begin/finish ceremony against this service's
// credential store, the same window and bounds. The only conditions waived
// are the ones about a question that does not exist (tier refusal); the
// ones about the HOST hold as before — compact permits investigate, wrapper
// present, no window already open.
func (s *server) investigateOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}
	var who struct {
		Operator string `json:"operator"`
		Role     string `json:"role"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&who)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, node, err := s.profileKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if s.wrapper == "" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "no privilege wrapper is installed on this host, so a window would let the Advisor read nothing more"})
		return
	}
	acc, accErr := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	if accErr != nil || !acc.Permits(runbook.ClassInvestigate) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "the compact on this host does not permit the investigate class; accept it with " +
				"--classes=upgrade,investigate,restart,config"})
		return
	}
	if _, open := s.breakglass.OpenForNode(node, time.Now()); open {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "a break-glass window is already open on this node"})
		return
	}

	offerID, err := mintOfferID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	const trigger = "operator-initiated investigation from the Advisor panel"
	why := "Opened by the operator, ahead of any question."
	wouldRead := []string{"configuration, logs and resource state of this host, as the questions call for them"}
	s.offers.put(offerID, &offerRecord{
		Node: node, Question: trigger, Messages: nil, Why: why, WouldRead: wouldRead,
	})
	fp := approval.InvestigationFingerprint(offerID, trigger, node)
	confirmCode := approval.ConfirmCode(fp)
	if l, err := ledger.Open(s.ledgerPath()); err == nil && l != nil {
		// Attributed to the operator who asked for it, as a claim (the
		// ceremony that follows is what proves an identity).
		l.AppendAs(ledger.KindInvestigateOffered, "", "an investigation offer was requested by the operator",
			map[string]any{
				"offer_id": offerID, "trigger_sha256": sha256Hex(trigger),
				"why": why, "would_read": wouldRead, "confirm_code": confirmCode,
				"operator_initiated": true,
			}, sessionActor(who.Operator, who.Role))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"offer_id": offerID, "why": why, "would_read": wouldRead, "confirm_code": confirmCode,
	})
}

// ── POST /v1/investigate/begin ──────────────────────────────────────────

type investigateBeginRequest struct {
	OfferID string `json:"offer_id"`
}

// investigateBegin mirrors approveBegin: issue the challenge for one
// ceremony, bound to a fingerprint this service computes itself from a
// record IT holds (the offer), never from anything the caller asserts.
func (s *server) investigateBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}

	var req investigateBeginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil || req.OfferID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request, or no offer_id"})
		return
	}
	rec, ok := s.offers.get(req.OfferID)
	if !ok {
		writeJSON(w, http.StatusGone, map[string]any{
			"error": "that investigation offer has expired; ask the question again"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, node, err := s.profileKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if node != rec.Node {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "the offer was made for a different node than this service now runs"})
		return
	}
	// Condition 6, re-checked here too: offering (or ceremonially entering)
	// a second window while one is open would make "one at a time" a rule
	// only the offer-render path enforces.
	if _, open := s.breakglass.OpenForNode(node, time.Now()); open {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "a break-glass window is already open on this node"})
		return
	}

	fp := approval.InvestigationFingerprint(req.OfferID, rec.Question, node)
	// Two minutes: the same ceremony budget approveBegin gives the upgrade
	// gate — long enough for a passkey prompt and a retry, short enough
	// that a captured value is stale before it is useful.
	n, err := s.nonces.Issue(fp, approval.StageInvestigate, 2*time.Minute)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":    n.Value,
		"fingerprint":  fp,
		"stage":        approval.StageInvestigate,
		"confirm_code": approval.ConfirmCode(fp),
		"expires_in":   int(time.Until(n.Expires).Seconds()),
		"plan_id":      "inv-" + fp[:12],
		"would_read":   rec.WouldRead,
		"why":          rec.Why,
	})
}

// ── POST /v1/investigate ────────────────────────────────────────────────

type investigateRequest struct {
	OfferID      string `json:"offer_id"`
	GrantedBy    string `json:"granted_by"`
	TTLSeconds   int    `json:"ttl_seconds"`
	Reason       string `json:"reason"`
	CredentialID string `json:"credential_id"`
	SessionUser  string `json:"session_user"`
	// GrantedByRole is the dashboard's claim about this operator's role. Same
	// standing as GrantedBy: derived server-side from the session, not proved
	// here, and labelled as a claim on the entry.
	GrantedByRole string `json:"granted_by_role"`
	Origin        string `json:"origin"`

	Assertion *webauthn.Assertion `json:"assertion"`
	Challenge string              `json:"challenge"`
}

// investigate mirrors approve (verify, spend) then execute (start the
// work) — but what it starts is a read, opening the break-glass window
// rather than running a runbook stage. Spend-on-open (§11.3): the approval
// file is consumed the moment the window opens, not when the first
// question completes.
func (s *server) investigate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}

	var req investigateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	if req.CredentialID == "" || req.Assertion == nil || req.Challenge == "" {
		writeJSON(w, http.StatusBadRequest,
			map[string]any{"error": "no passkey assertion; an approval without a ceremony is not one"})
		return
	}
	rec, ok := s.offers.get(req.OfferID)
	if !ok {
		writeJSON(w, http.StatusGone, map[string]any{
			"error": "that investigation offer has expired; ask the question again"})
		return
	}

	l, lerr := ledger.Open(s.ledgerPath())
	// A refused break-glass ceremony used to record a credential id and
	// nothing else. It now names whoever the dashboard says was trying, as a
	// claim — verified:"none", because the refusal is precisely the fact that
	// nothing was proved.
	refusedBy := refusedActor(req.CredentialID, req.GrantedBy, req.GrantedByRole, req.Origin)
	// Two details, not one. The ledger keeps the bare cause — a tamper-evident
	// record of refusals is not the place for instruction text, and the same
	// sentence repeated on every entry buries the causes that differ. The HTTP
	// body is where the operator is actually reading, and the page renders it
	// verbatim, so that is where a remedy belongs.
	refuseDetailed := func(status int, reason, ledgerDetail, httpDetail string) {
		if l != nil {
			l.AppendAs(ledger.KindApprovalRefused, "", reason,
				map[string]any{"stage": approval.StageInvestigate, "detail": ledgerDetail,
					"credential_id": req.CredentialID}, refusedBy)
		}
		writeJSON(w, status, map[string]any{"error": httpDetail})
	}
	refuse := func(status int, reason, detail string) {
		refuseDetailed(status, reason, detail, detail)
	}

	// Verified here, against keys this service holds — independent of
	// whatever the dashboard already checked (§11.11's "independent
	// validation" row).
	store, err := host.LoadCredentials(filepath.Join(s.stateDir, "credentials.json"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := store.Verify(*req.Assertion, req.Challenge); err != nil {
		refuseDetailed(http.StatusForbidden, "approval refused: the passkey assertion did not verify",
			err.Error(), s.enrollmentRemedy(err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, node, err := s.profileKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if node != rec.Node {
		refuse(http.StatusConflict, "approval refused: the node changed since the offer", "node mismatch")
		return
	}

	// Recomputed here, never trusted from the caller — the same discipline
	// approve applies to a runbook's fingerprint.
	fp := approval.InvestigationFingerprint(req.OfferID, rec.Question, node)

	if err := s.nonces.Consume(req.Challenge, fp, approval.StageInvestigate); err != nil {
		refuse(http.StatusForbidden, "approval refused: the challenge does not belong to this act", err.Error())
		return
	}

	acc, err := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	if err != nil || !acc.Permits(runbook.ClassInvestigate) {
		detail := "the compact does not permit the investigate class"
		if err != nil {
			detail = err.Error()
		}
		refuse(http.StatusForbidden, "approval refused: compact does not permit investigate", detail)
		return
	}

	if _, open := s.breakglass.OpenForNode(node, time.Now()); open {
		refuse(http.StatusConflict, "approval refused: a break-glass window is already open", "window already open")
		return
	}

	planID := "inv-" + fp[:12]
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > 5*time.Minute {
		// §11.3: five minutes to USE the approval — an operator should not
		// outlive the thing they are authorising by much, and this is the
		// moment they are sitting in front of the drawer having just
		// clicked yes.
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	// The store verified this assertion above, so the attribution can now be
	// built from BOTH sources — what the store says this key belongs to, and
	// what the dashboard claimed — with any disagreement recorded.
	openedBy := ceremonyActor(store, req.CredentialID, req.GrantedBy, req.GrantedByRole, req.Origin)
	ap := approval.Approval{
		PlanID: planID, Fingerprint: fp, RunbookID: "investigate", Node: node,
		GrantedBy: req.GrantedBy, GrantedByRole: openedBy.Role,
		GrantedAt: now, ExpiresAt: now.Add(ttl), Stage: approval.StageInvestigate,
		Reason: req.Reason, Assertion: req.Assertion, Challenge: req.Challenge, Origin: req.Origin,
	}
	// The ledger is checked BEFORE the approval is written (#1091). It used
	// to be checked after, so a ledger that could not be opened left a live
	// approval with no record of it anywhere. An approval that cannot be
	// recorded is not granted.
	if lerr != nil || l == nil {
		log.Printf("[investigate] not granting %s: the ledger could not be opened: %v", planID, lerr)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "ledger unavailable"})
		return
	}
	if _, err := approval.Grant(filepath.Join(s.stateDir, "approvals"), ap); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if _, err := l.AppendAs(ledger.KindApprovalGranted, planID,
		fmt.Sprintf("%s approved break glass by passkey, expires %s", ap.GrantedBy, ap.ExpiresAt.Format(time.RFC3339)),
		map[string]any{
			"stage": approval.StageInvestigate, "fingerprint": fp, "expires_at": ap.ExpiresAt,
			"reason": req.Reason,
			"ceremony": map[string]any{
				"credential_id": req.CredentialID, "session_user": req.SessionUser, "origin": req.Origin,
			},
		}, openedBy); err != nil {
		// Before the spend and before any window exists (#1091): an approval
		// the ledger has no row for opens nothing.
		fate := s.withdrawUnrecorded(planID, approval.StageInvestigate, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "the ledger could not record this approval (" + err.Error() + "), " + fate + ", and no window was opened"})
		return
	}

	afterApprovalRow()

	// Spend-on-open (§11.3): consumed now, before the window or the first
	// read exists, so a captured approval cannot open a second window.
	if err := approval.Spend(filepath.Join(s.stateDir, "approvals"), planID, approval.StageInvestigate); err != nil {
		log.Printf("[investigate] spend failed for %s: %v", planID, err)
	}

	winID := planID + "-" + now.Format("150405")
	// The window carries the opener's whole identity, not just their name.
	// Every privileged read this window authorises is stamped from it — that
	// is the line that turns break glass from the surface with the most
	// privilege and the least attribution into one entry per read, each
	// naming a person.
	// Opened under the identity key, which is the value every reader of this
	// store looks a window up by (#398). The write and those reads are one
	// pair: a window opened under a name nobody searches for is a window the
	// operator paid a passkey for and the service never finds.
	win := breakglass.OpenAs(winID, node, identityOf(openedBy), now)
	// Recorded before the window is put in the store (#1091): a window the
	// ledger has no row for is a window nobody can account for. The approval
	// is already spent, so a failure here costs the operator a new ceremony
	// and nothing else.
	if _, err := l.AppendAs(ledger.KindBreakglassOpened, planID,
		fmt.Sprintf("break glass opened by %s, window %s", ap.GrantedBy, winID),
		map[string]any{
			"window_id": winID, "opened_by": ap.GrantedBy, "expires_at": win.ExpiresAt,
			"bounds": map[string]any{
				"duration_minutes": int(breakglass.Duration.Minutes()),
				"questions":        breakglass.MaxQuestions,
				"privileged_reads": breakglass.MaxPrivilegedReads,
				"spend_tokens":     breakglass.MaxSpendTokens,
			},
		}, openedBy); err != nil {
		log.Printf("[investigate] window %s not opened: the ledger could not record it: %v", winID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "the ledger could not record the window, so none was opened: " + err.Error()})
		return
	}
	s.breakglass.Open(win)
	// Whoever is standing here is plainly not waiting to be told that the
	// last window ended.
	s.clearWindowEnded()

	// An operator-initiated offer (investigateOffer) has no question to
	// resume: the window is open, and every /v1/ask on this node runs at the
	// gated tier until it closes. Nothing is started here.
	if len(rec.Messages) == 0 {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"started": true, "window_id": winID, "session_id": "",
			"plan_id": planID, "expires_at": win.ExpiresAt,
		})
		return
	}
	cfg, cfgErr := model.LoadConfig(s.modelPath)
	if cfgErr != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": cfgErr.Error()})
		return
	}
	if ok, reason := win.StartQuestion(time.Now()); !ok {
		writeJSON(w, http.StatusConflict, map[string]any{"error": reason})
		return
	}
	sessionID := planID + "-q1"
	resumePrompt := "The operator approved a deeper investigation (break glass). " +
		"You may now read more of this host at raised limits for this question. " +
		"Continue investigating the same question using your raised privileges, " +
		"and use a <lookup> block if there is more you would read."
	// rec.Messages already carries whatever CacheBoundary marker ask()
	// set on its own last seed message; this resume turn is now the new
	// stable tail for the gated rounds that follow it, so it gets its own.
	seed := append(append([]interrogate.Message{}, rec.Messages...),
		interrogate.Message{Role: "user", Content: resumePrompt, CacheBoundary: true})
	// Counted HERE, before the goroutine starts and before the 202 below —
	// punch #24. Incrementing inside the goroutine would leave a window
	// where this handler has already answered "started" and the counter
	// still reads zero, which is exactly when a deploy's quiet-check would
	// conclude it was safe to stop the service.
	gdone := s.askStart()
	go func() {
		defer gdone()
		s.runGatedQuestion(win, sessionID, node, seed, rec.Question, cfg, l)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"started": true, "window_id": winID, "session_id": sessionID,
		"plan_id": planID, "expires_at": win.ExpiresAt,
	})
}

// ── POST /v1/investigate/continue ───────────────────────────────────────

type investigateContinueRequest struct {
	Question string       `json:"question"`
	Focus    string       `json:"focus"`
	Target   string       `json:"target"`
	History  []model.Turn `json:"history"`
	// Operator and Role are the CONTINUING operator, forwarded from the
	// dashboard session by the proxy exactly as granted_by is on the approve
	// path — never typed by the browser.
	//
	// This endpoint used to take no identity at all, and that was a real
	// mis-attribution rather than a missing nicety: admin B could ask the
	// second, third and fourth gated question inside a window admin A opened,
	// and every privileged read those questions performed resolved — by the
	// only join available, window_id → breakglass.opened → opened_by — to A.
	// The record named the wrong person, confidently.
	Operator string `json:"operator"`
	Role     string `json:"role"`
	// Node is which node the CALLER believes it is acting on. Checked against
	// this service's own resolution and refused by name on disagreement — see
	// refuseWrongNode.
	Node string `json:"node"`
}

// investigateContinue is the endpoint the window exists to make possible
// (§11.8): no ceremony, just the window's own four bounds re-checked.
func (s *server) investigateContinue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}

	var req investigateContinueRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unreadable request"})
		return
	}
	if strings.TrimSpace(req.Question) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the question is empty"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, node, err := s.profileKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}

	if refuseWrongNode(w, req.Node, node) {
		return
	}

	win, open := s.breakglass.OpenForNode(node, time.Now())
	if !open {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "no break-glass window is open; break glass again to continue"})
		return
	}
	run, sessionID, status, msg := s.prepareGatedQuestion(ctx, win, node, gatedAsk{
		Question: req.Question, Focus: req.Focus, Target: req.Target, History: req.History,
		Operator: req.Operator, Role: req.Role,
	}, "")
	if status != 0 {
		writeJSON(w, status, gatedRefusalBody(req.Role, msg))
		return
	}
	// Counted before the goroutine and before the 202, for the reason given
	// on the same pattern in investigateBegin above.
	cdone := s.askStart()
	go func() {
		defer cdone()
		run()
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"started": true, "session_id": sessionID, "window_id": win.ID,
	})
}

// gatedRefusalBody is the JSON a refused gated question answers with. The
// role case carries refused_because so the page can render it as the plain
// sentence it is — the drawer's generic error branch labels anything with an
// `error` key as a provider error, and "the model provider failed" is the
// wrong thing to tell someone whose role simply does not reach this tier.
func gatedRefusalBody(role, msg string) map[string]any {
	out := map[string]any{"error": msg}
	if role == roleMonitor {
		out["refused_because"] = string(interrogate.RefusedRole)
	}
	return out
}

// gatedAsk is what a question inside a window needs from its caller —
// the same fields whether it arrives on /v1/investigate/continue or, with
// a window open, on /v1/ask.
type gatedAsk struct {
	Question, Focus, Target string
	History                 []model.Turn
	Operator, Role          string
	// RendersActions says this caller has a surface an act's confirm gate
	// can appear on, so the runner should answer the reply's action block
	// and record it where a recovery poll will find it.
	//
	// It is the caller's fact to state, not something this file can infer.
	// /v1/ask sets it: the drawer renders the gate under the turn, and when
	// that POST dies at the gateway's ~100s cap the page recovers it from
	// the progress store instead (#56). /v1/investigate/continue does not:
	// it answers 202 and its session is rendered by bgResumeSession, which
	// has never drawn a gate — turning one on there would be a new surface,
	// not a fix to this one.
	RendersActions bool
}

// gatedResult is everything one gated question produced. A struct because
// the runner now carries the act's confirm gate as well as the answer, and
// a fifth positional return on a closure two handlers share is how the
// wrong one gets read.
//
// Action and Blocked follow answerAction's contract exactly: at most one is
// ever non-nil, and both are nil for a reply that proposed nothing — which
// is nearly every reply.
type gatedResult struct {
	Outcome interrogate.Outcome
	Steps   []interrogate.Step
	Signal  replySignal
	Action  map[string]any
	Blocked map[string]any
}

// prepareGatedQuestion runs every check a gated question must pass and
// assembles its seed, then hands back a runner. It charges one of the
// window's questions only once every check has passed (see the LoadConfig
// note inside). sessionID is the progress-store key: continue lets the
// service mint it; ask passes its own ask_id so the page's existing
// progress poll finds the trace. status != 0 is an HTTP refusal.
func (s *server) prepareGatedQuestion(ctx context.Context, win *breakglass.Window, node string, g gatedAsk, sessionID string) (run func() (gatedResult, error), sid string, status int, msg string) {
	// A monitor never runs at the gated tier — advisor/knowledge/role-policy.md,
	// "anything inside a break-glass window: no". They cannot open one, and a
	// window an admin opened does not elevate everyone else who is signed in.
	//
	// Defence in depth: the dashboard proxy already refuses a monitor on
	// /investigate-continue by name (ADVISOR_ADMIN_PATHS), and /ask carries no
	// such list because it is a read — so this is the check that holds when
	// the question arrives on the ask path with a window open. Refused here,
	// once, rather than in each of the two callers.
	//
	// The cost is stated rather than hidden: while an admin holds a window on
	// this node, a monitor's ordinary questions are refused too, for the
	// fifteen minutes it lasts. The reason says so, and says when they resume.
	if g.Role == roleMonitor {
		return nil, "", http.StatusForbidden,
			"an admin has a break-glass window open on this node, and a monitor does not ask questions inside one; ordinary questions resume when it closes"
	}
	// Re-checked on every call (§11.8): the compact class can be withdrawn
	// mid-window, and this path trusts nothing it was told.
	acc, err := compact.Load(filepath.Join(s.stateDir, "compact.json"), node)
	if err != nil || !acc.Permits(runbook.ClassInvestigate) {
		return nil, "", http.StatusForbidden, "the compact no longer permits the investigate class"
	}
	// LoadConfig BEFORE StartQuestion: StartQuestion charges one of the
	// window's five questions and marks it in flight the moment it
	// succeeds. A failure discovered after that point with no way back —
	// no EndQuestion call, no goroutine to run one — would burn a question
	// for nothing and leave InFlight incremented forever, which also
	// permanently poisons the chip's "closing — finishing N" reading.
	cfg, cfgErr := model.LoadConfig(s.modelPath)
	if cfgErr != nil {
		return nil, "", http.StatusServiceUnavailable, cfgErr.Error()
	}
	if ok, reason := win.StartQuestion(time.Now()); !ok {
		return nil, "", http.StatusConflict, reason
	}

	mc, knowTarget := s.baseContext(ctx, g.Focus, g.Target)
	// Who is asking and what they may do here — ADR 0016 as amended
	// 2026-08-19. Inside a window this block says the window IS open, which
	// is what lets the model go straight to the assessment instead of
	// telling an admin to break glass they have already broken.
	mc.Session = s.sessionContext(g.Role, node, time.Now())
	personaBody, perr := os.ReadFile(s.persona)
	if perr != nil && !os.IsNotExist(perr) {
		log.Printf("[persona] %s unreadable: %v", s.persona, perr)
	}
	hostBudget := host.NewBudget(interrogate.NewGatedBudget().MaxHostReadsPerQuestion)
	// The record that turn one happened — issue #72, restart_confirm.go.
	//
	// A restart's turn one is "read restart_assessment, then show the
	// operator what you would restart", and this is the only server-side
	// point at which that turn is observable as itself: the read is
	// performed HERE, by this service, and the plan it returns says whether
	// the restart is proposable. Set from the loop's goroutine inside
	// loop.Run and read by the runner below after it returns, so there is
	// one write and one read, ordered by the call itself.
	//
	// Wired on this path only. It is the path every drawer question takes
	// while a window is open, and a restart cannot be proposed without one.
	// The window's own first question (runGatedQuestion) resumes an offered
	// investigation, draws no gate, and carries no session identity to key a
	// proposal on, so arming one there would be a proposal nobody could
	// confirm.
	var proposed *pendingRestart
	fv := s.fleetNow()
	menu := &liveMenu{
		restartAssess: func(actx context.Context) interrogate.Result {
			plan, res := s.restartAssessmentPlan(actx)
			// Last proposable assessment in the turn wins. A second read that
			// fails does not un-propose what a first one showed the operator.
			if p := proposalFromAssessment(plan, res, time.Now()); p != nil {
				proposed = p
			}
			return res
		},
		upgradeAssess:  s.upgradeAssessmentResult,
		configAssess:   s.configAssessmentResult,
		rollbackAssess: s.rollbackAssessmentResult,
		selfContainer:  s.container,
		dash:           s.dashRead, httpClient: s.client, stateDir: s.stateDir,
		runner: s.runner, wrapper: s.wrapper,
		hostBudget: hostBudget, resultClampBytes: 12 * 1024, peers: fv.clients, fleetReg: fv.reg,
		roster: s.roster(context.Background()),
		role:   g.Role,
	}
	// Same discipline as ask() — computed once, from the operator's own
	// question text, before this gated session's first round. node is
	// mc.Node, this service's own resolution (P2-003), never anything the
	// model's own tool calls could name.
	knowledge := model.SelectKnowledgeFor(s.loadKnowledge(), g.Question, mc.Node, knowTarget)
	knowledgeSteps := knowledgeRefusalSteps(knowledge.Refusals)
	system := model.BuildSystemPrompt(string(personaBody), s.loadRolePolicy(), menu.Describe(),
		model.RenderKnowledge(knowledge.Selected))
	turns := defangedTurns(g.History)
	turns = append(turns, model.Turn{Role: "user",
		Content: "OPERATOR ASKS (break glass — gated session)\n" + g.Question +
			"\n\n--- reference material below, reassembled every turn; not the subject ---\n\n" +
			mc.String() + "\n\n--- end of reference material ---\n\nOPERATOR ASKS\n" + g.Question})
	seed := []interrogate.Message{{Role: "system", Content: system}}
	for _, t := range turns {
		seed = append(seed, interrogate.Message{Role: t.Role, Content: t.Content})
	}
	// Cache breakpoint 2, same reasoning as ask() — the last seed message
	// is fixed for the rest of this gated session's rounds.
	if n := len(seed); n > 0 {
		seed[n-1].CacheBoundary = true
	}

	l, _ := ledger.Open(s.ledgerPath())
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s-q%d", win.ID, win.Questions)
	}
	// A: opened the window. B: asked THIS question. The record says both —
	// actor is whoever is asking now, window_opened_by stays beside it.
	asker := sessionActor(g.Operator, g.Role)
	if asker.Empty() {
		// No identity forwarded (an older dashboard, or a caller that is not
		// the proxy). Fall back to the window's opener rather than to nobody,
		// and do not pretend the session was proved.
		asker = actorOf(win.Opener)
		asker.Verified = ledger.VerifiedSession
	}
	question := g.Question
	// The act's confirm gate, answered INSIDE the runner rather than by the
	// handler that returns — see runGatedQuestionWithHostBudget for why the
	// ordering against finish() is the whole point. Bound here because this
	// is where the asker's role and identity are already resolved; nil when
	// the caller has no surface to draw a gate on.
	//
	// Bound once, called once. The handler used to call answerAction itself
	// on the returned signal, and computing it in both places would evaluate
	// one plan twice — two host reads, two ledger action.proposed entries
	// for one proposal, and two derivations of a confirm code that must
	// agree (planIdentity's own doc comment says what a disagreement costs).
	var answer func(replySignal) (map[string]any, map[string]any)
	if g.RendersActions {
		role := g.Role
		answer = func(sig replySignal) (map[string]any, map[string]any) {
			// context.Background(), not the caller's: this runs after the
			// loop, on a goroutine that outlives the POST by design (punch
			// #24), and a gate abandoned because the operator's request had
			// already died at the gateway is the exact failure being fixed.
			actx, acancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer acancel()
			return s.answerAction(actx, sig, role, asker)
		}
	}
	operator := g.Operator
	run = func() (gatedResult, error) {
		res, err := s.runGatedQuestionWithHostBudget(win, sessionID, node, seed, question, cfg, l, hostBudget, menu, knowledgeSteps, asker, answer)
		res.Steps = append(append([]interrogate.Step{}, knowledgeSteps...), res.Outcome.Steps...)
		// Keep the proposal this question raised, or clear whatever the last
		// one left. Either way the store ends this turn saying exactly what
		// the operator was last shown — see settlePendingRestart.
		s.settlePendingRestart(node, operator, proposed, res, err)
		return res, err
	}
	return run, sessionID, 0, ""
}

// ── POST /v1/breakglass/close ───────────────────────────────────────────

func (s *server) breakglassClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	if code, msg := s.checkBearerToken(r); code != 0 {
		writeJSON(w, code, map[string]any{"error": msg})
		return
	}
	// Who clicked Close — forwarded from the dashboard session by the proxy,
	// like the continue path. Not necessarily the person who opened it: an
	// admin can close a colleague's window, and "the operator closed it
	// early" should say which operator.
	var who struct {
		Operator string `json:"operator"`
		Role     string `json:"role"`
		Node     string `json:"node"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&who)

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	_, node, err := s.profileKeyed(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
		return
	}
	if refuseWrongNode(w, who.Node, node) {
		return
	}
	win, open := s.breakglass.OpenForNode(node, time.Now())
	if !open {
		// Idempotent (§11.8): closing a closed window is a no-op that
		// returns the same summary, not an error.
		writeJSON(w, http.StatusOK, map[string]any{"closed": true, "already_closed": true})
		return
	}
	sm := s.closeWindowEarly(win, time.Now(), sessionActor(who.Operator, who.Role))
	writeJSON(w, http.StatusOK, map[string]any{"closed": true, "summary": sm})
}

// closeWindowEarly is the operator's Close, minus the HTTP around it. A
// separate function for one reason: it is the exact sequence that used to
// write the closing entry a second time, and a test can drive it while it
// cannot easily drive the handler (which needs a token, a request and a live
// docker profile). Anything added here that appends to the ledger will fail
// TestOnlyTheCloseNoticeWritesTheClosedEntry.
func (s *server) closeWindowEarly(win *breakglass.Window, now time.Time, by ledger.Actor) breakglass.Summary {
	// The ledger entry is written by the close notice this window carries
	// (breakglass.Window.onClose, wired at boot to recordWindowClosed), not
	// here. Writing it here as well — which is what this path used to do —
	// would put two breakglass.closed entries in a hash-chained record for one
	// ending, and a duplicate there reads exactly like tampering.
	win.CloseEarlyBy(now, identityOf(by))
	return win.Summary(now)
}

// recordWindowClosed is the close notice every window in the Store carries.
// It runs once per window, at the moment it ends, whichever of the five
// endings ended it — see breakglass.Window.onClose for why this is now the
// only place a live window's closing entry is written.
//
// Called with the Store's mutex held on the poll paths, so it does two small
// things and no more: remember the ending for the status surface, and append
// one entry.
func (s *server) recordWindowClosed(win *breakglass.Window, now time.Time) {
	s.noteWindowEnded(windowEnded{
		WindowID: win.ID, Node: win.Node, OpenedBy: win.OpenedBy,
		Reason: win.ClosedBy, At: now,
	})
	// A window closed by one of its bounds was closed by nobody, and the entry
	// carries no actor rather than borrowing the opener's name for an act they
	// did not perform.
	s.appendBreakglassClosed(win.Summary(now), actorOf(win.Closer), "", nil)
}

// appendBreakglassClosed writes breakglass.closed from a Summary. Both the
// live path (a window that just ended) and the boot scan (a window
// reconstructed from the ledger, whose process is gone) go through here, so
// the two record the same shape and an auditor reads one format.
//
// note and extra are how a reconstructed close says it is one — see
// closeOrphanWindows. Both are empty on the live path.
func (s *server) appendBreakglassClosed(sm breakglass.Summary, actor ledger.Actor, note string, extra map[string]any) {
	l, err := ledger.Open(s.ledgerPath())
	if err != nil || l == nil {
		log.Printf("[breakglass] could not record the close of window %s: %v", sm.WindowID, err)
		return
	}
	// closed_because holds the BOUND that ended it; closed_by holds a person,
	// and only when a person actually closed it. They used to be one field
	// with a bound in it, sitting directly beside opened_by, which holds a
	// person — an auditor reading the pair would misread it every time.
	data := map[string]any{
		"window_id": sm.WindowID, "closed_because": sm.ClosedBecause,
		"closed_by": sm.ClosedByOperator, "opened_by": sm.OpenedBy,
		"questions": sm.Questions, "privileged_reads": sm.PrivilegedReads,
		"prompt_tokens": sm.PromptTokens, "completion_tokens": sm.CompletionTokens,
		"cached_prompt_tokens":  sm.CachedPromptTokens,
		"duration_held_seconds": int(sm.DurationHeld.Seconds()),
	}
	for k, v := range extra {
		data[k] = v
	}
	summary := fmt.Sprintf(
		"break glass opened by %s, %d investigation(s), %d privileged read(s), closed (%s) after %s",
		sm.OpenedBy, sm.Questions, sm.PrivilegedReads, sm.ClosedBecause, sm.DurationHeld.Round(time.Second))
	if note != "" {
		summary += ". " + note
	}
	l.AppendAs(ledger.KindBreakglassClosed, "", summary, data, actor)
}

// ── the gated session runner ────────────────────────────────────────────

// runGatedQuestion is investigate's entry point — its own host.Budget is
// built here because it is the FIRST question of the window. Its seed is a
// RESUMED conversation (rec.Messages from the ask() that made the offer),
// not a fresh SelectKnowledge call, so there is no new knowledge selection
// here and nothing to report — the system prompt in seed already carries
// whatever ask() selected, refusals included.
func (s *server) runGatedQuestion(win *breakglass.Window, sessionID, node string, seed []interrogate.Message, question string, cfg model.Config, l *ledger.Ledger) {
	hostBudget := host.NewBudget(interrogate.NewGatedBudget().MaxHostReadsPerQuestion)
	// role is left empty on purpose, and empty is an admin. This path runs
	// the window's FIRST question, whose asker is the person who just
	// presented a passkey to open the window — a monitor cannot reach it at
	// all, because opening a window is an admin act the dashboard proxy and
	// the credential store both gate. There is no request here to stamp a
	// role from, and inventing one would be a second, weaker answer to a
	// question a passkey already answered.
	fv := s.fleetNow()
	menu := &liveMenu{
		restartAssess: s.restartAssessmentResult, upgradeAssess: s.upgradeAssessmentResult,
		configAssess:   s.configAssessmentResult,
		rollbackAssess: s.rollbackAssessmentResult,
		selfContainer:  s.container,
		dash:           s.dashRead, httpClient: s.client, stateDir: s.stateDir,
		runner: s.runner, wrapper: s.wrapper,
		hostBudget: hostBudget, resultClampBytes: 12 * 1024, peers: fv.clients, fleetReg: fv.reg,
		roster: s.roster(context.Background()),
	}
	// The window's first question is asked by whoever just broke the glass.
	// The signal is discarded here on purpose: this path has no HTTP
	// response to attach a gate to, and a proposal nobody can be shown is
	// not a proposal. The block is still stripped from the stored reply.
	s.runGatedQuestionWithHostBudget(win, sessionID, node, seed, question, cfg, l, hostBudget, menu, nil, actorOf(win.Opener), nil)
}

// runGatedQuestionWithHostBudget is the shared body: run the loop at the
// gated ceilings, ledger every privileged read (§11.10: "one entry PER
// PRIVILEGED READ" — the one place this project ledgers reads at all,
// because these run through the root-owned wrapper as another identity),
// then fold the question's cost into the window and record its end.
//
// knowledgeSteps carries any knowledge cap refusal from a caller that just
// ran a fresh model.SelectKnowledge (investigateContinue) — nil from a
// caller resuming an already-selected conversation (runGatedQuestion).
// Recorded into progress right after beginGated, because beginGated
// replaces whatever entry preceded it; appending any earlier would be lost
// the moment this runs.
//
// answer, when set, turns the stripped reply's signal into the act's
// confirm gate. It runs HERE, between stripReplySignalsGiven and finish, and the
// order is the fix for #72: the page's recovery poll settles on the FIRST
// snapshot reporting state "answered", so a gate recorded after that call
// is a gate the operator never sees. A restart always runs at this tier — a
// window makes every question gated, and a restart needs one — so this is
// the only path a restart gate can survive a dead POST on, and until now
// this path recorded no gate at all.
//
// Runs in its own goroutine, on its own 600-second budget (§11.1) — NOT
// s.runMu, which execute holds for the whole run. Two gated sessions on the
// same node are bounded by the window's own four bounds and by the
// approval being single-spend, never by a lock a real upgrade could be
// waiting behind.
func (s *server) runGatedQuestionWithHostBudget(win *breakglass.Window, sessionID, node string, seed []interrogate.Message, question string, cfg model.Config, l *ledger.Ledger, hostBudget *host.Budget, menu *liveMenu, knowledgeSteps []interrogate.Step, asker ledger.Actor, answer func(replySignal) (map[string]any, map[string]any)) (gatedResult, error) {
	s.progress.beginGated(sessionID)
	for _, st := range knowledgeSteps {
		s.progress.append(sessionID, st)
	}
	if l != nil {
		l.AppendAs(ledger.KindInvestigateStarted, win.ID,
			fmt.Sprintf("gated question started, window %s", win.ID),
			map[string]any{"session_id": sessionID, "window_id": win.ID,
				"question_sha256": sha256Hex(question), "window_opened_by": win.OpenedBy}, asker)
	}

	gatedBudget := interrogate.NewGatedBudget()
	gatedBudget.ChargeSeedHostReads(hostBudget.Used())

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	loop := &interrogate.Loop{
		Caller: &modelCaller{client: model.New(cfg)},
		Menu:   menu,
		Budget: gatedBudget,
		Nodes:  nodesOf(menu.fleetReg),
		// The same roster the menu described, so what the prompt NAMES and
		// what a lookup RESOLVES against are one reading (#59).
		Roster: menu.roster,
		// Every completed model call, into the same store the steps go to.
		// A gated question may spend eight of them and several can perform
		// no read at all, so without this the page has minutes of silence to
		// interpret and reads it as a dropped connection (#72).
		OnRound: func(round int) { s.progress.setRound(sessionID, round) },
		OnStep: func(st interrogate.Step) {
			s.progress.append(sessionID, st)
			if st.Read == interrogate.ReadHost && l != nil {
				verb, arg := parseHostReadParams(st.Params)
				// ONE ENTRY PER PRIVILEGED READ, each naming a person. This is
				// the highest-value line of the attribution work: break glass
				// is the surface with the most privilege — a root-owned
				// wrapper running as another identity — and until now every
				// one of these entries was anonymous.
				l.AppendAs(ledger.KindInvestigateRead, win.ID, "privileged read: "+verb,
					map[string]any{
						"session_id": sessionID, "window_id": win.ID, "verb": verb, "arg": arg,
						"status": st.Status, "bytes": len(st.Body), "ms": st.Ms, "redactions": st.Redactions,
						"window_opened_by": win.OpenedBy,
					}, asker)
			}
		},
	}

	started := time.Now()
	var sig replySignal
	var actionBlock, actionRefused map[string]any
	outcome, err := loop.Run(ctx, seed, question)
	now := time.Now()
	outlived := win.EndQuestion(now, hostBudget.Used(), outcome.Spend.PromptTokens,
		outcome.Spend.CachedPromptTokens, outcome.Spend.CompletionTokens)

	if err != nil {
		s.progress.finish(sessionID, "ended", "", "failed: "+err.Error())
	} else {
		// The same treatment ask() gives a final reply: the <remember> and
		// proposal blocks are the model talking to its own notes, and the
		// gated path handed them to the operator verbatim — a reply ending
		// in a raw "</remember>" (2026-08-19). Stored the same way too.
		reply, _ := s.extractMemory(outcome.FinalReply, node)
		reply = s.extractProposal(reply, node, question, outcome.Steps)
		// And the action protocol's own blocks — stripped HERE, beside the
		// progress store's write, not in the handler that returns. The page
		// recovers a dead POST by polling this store, and bgResumeSession
		// renders its answer directly, so a strip that happened only on the
		// HTTP path would hand the operator raw markup on both.
		reply, sig = stripReplySignalsGiven(reply, injectedText(outcome.Messages))
		outcome.FinalReply = reply
		// The act the reply proposed, answered and recorded BEFORE the
		// terminal state. A page recovering a dead POST settles on the first
		// snapshot that says "answered", so the order here is the difference
		// between an operator being handed a gate to approve and being handed
		// a paragraph saying a restart is ready with nothing to press (#72).
		if answer != nil {
			actionBlock, actionRefused = answer(sig)
			if actionBlock != nil {
				s.progress.setAction(sessionID, actionBlock)
				// A reply that came back with a gate claims nothing the
				// gate has not been given yet (#1044).
				if fixed, ok := correctPrematureClaims(reply); ok {
					log.Printf("[ask] the reply claimed its act was approved or under way before the gate was; corrected (#1044)")
					reply = fixed
					outcome.FinalReply = reply
				}
			}
		}
		s.progress.finish(sessionID, "answered", reply, "")
	}

	if l != nil {
		reason := "answered"
		if err != nil {
			reason = "failed"
		}
		data := map[string]any{
			"session_id": sessionID, "window_id": win.ID, "rounds": outcome.Spend.Rounds,
			"reads": outcome.Spend.Reads, "privileged_reads": hostBudget.Used(),
			"prompt_tokens": outcome.Spend.PromptTokens, "completion_tokens": outcome.Spend.CompletionTokens,
			"cached_prompt_tokens": outcome.Spend.CachedPromptTokens,
		}
		if outlived {
			data["outlived_window"] = true
		}
		data["window_opened_by"] = win.OpenedBy
		l.AppendAs(ledger.KindInvestigateEnded, win.ID,
			fmt.Sprintf("gated question ended (%s), %s", reason, time.Since(started).Round(time.Millisecond)),
			data, asker)
	}

	// The window may have just crossed a bound as a result of this
	// question's cost — closing it now (rather than waiting for the next
	// Touch/StartQuestion) makes the ledger's breakglass.closed land close
	// to when it actually happened. The entry itself is written by the
	// window's own close notice, not from here: this used to append a second
	// copy of it.
	win.Touch(now)
	return gatedResult{
		Outcome: outcome, Steps: outcome.Steps, Signal: sig,
		Action: actionBlock, Blocked: actionRefused,
	}, err
}

// parseHostReadParams recovers the distinct verb (and, for node-log/journal,
// the line count) from Request.Params()'s rendered form ("verb=node-log
// lines=80") — §11.10 wants investigate.read to carry `verb` as its own
// field, not folded into a string an auditor would have to parse a second
// time by hand.
func parseHostReadParams(params string) (verb, arg string) {
	for _, part := range strings.Fields(params) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "verb":
			verb = v
		case "lines":
			arg = v
		}
	}
	return verb, arg
}

// sha256Hex is investigate.started's question_sha256 (§11.10) — deliberately
// distinct from trigger_sha256 (approval.InvestigationFingerprint's own
// hash of the offer's trigger question): "one break, several subjects, all
// recorded" — a follow-up asked inside a window has a DIFFERENT
// question_sha256 from the trigger that opened it, and collapsing the two
// would make a window look like it only ever investigated its trigger.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
	return hex.EncodeToString(h[:])
}

// refuseWrongNode is the guard that keeps a break-glass action addressed to
// the host that holds the window.
//
// The hazard it closes is structural rather than a bug in any one line. On a
// fleet view the operator is looking at a PEER: the question went to that
// node's advisord, the offer came back from that node's advisord, and the
// answer is that node's. But continue and close carry no node and there is no
// peer route for them — the aggregator's own advisord is the only thing they
// can reach. So a break-glass action meant for a peer would land here, on this
// host, against whatever window this host happens to have open.
//
// Refuse rather than route, deliberately. Routing it would mean the peer's
// advisord acting on an identity the AGGREGATOR's dashboard verified, and the
// peer cannot verify that assertion itself until the trust bundle reaches it
// (ADR 0014 slice 3). Until then the honest answer is that this cannot be done
// from here, said in those words.
//
// An empty want is permitted: an older page that does not send the field is
// talking to its own host, which is what it always did. Nothing is weakened —
// the caller was already reaching this host and only this host.
func refuseWrongNode(w http.ResponseWriter, want, have string) bool {
	if want == "" || want == have {
		return false
	}
	log.Printf("[breakglass] REFUSED an action addressed to %q; this service runs %q", want, have)
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "this Advisor runs " + have + ", not " + want,
		"detail": "A break-glass window belongs to the host that opened it. Acting on " + want +
			"'s window has to happen on " + want + "'s own dashboard — its advisord is the only " +
			"service that can verify a passkey for it.",
		"node": have,
	})
	return true
}
