package main

import (
	"log"
	"strings"

	"aperire-advisor/internal/breakglass"
	"aperire-advisor/internal/fleetrecord"
	"aperire-advisor/internal/host"
	"aperire-advisor/internal/ledger"
)

// This file is the one place advisord turns "someone did something" into an
// attribution for the ledger. Everything that appends goes through it, so the
// rules below are stated once instead of re-decided per handler.
//
// The seam it exists to be honest about: at the Advisor's trust boundary,
// verifying an assertion proves that A KEY IN ITS STORE SIGNED THIS CHALLENGE
// and nothing more. Whether that key belongs to the person the dashboard
// named is a separate question, and until the store carried user/role the
// Advisor had no way to ask it. Now it does — so the ledger records BOTH the
// name the store gives and the name the dashboard claimed, and says whether
// they agreed. That is strictly more than picking one and is what makes a
// compromised dashboard visible in the record rather than authoritative over
// it.

// ceremonyActor attributes an act authorised by a passkey ceremony.
//
// credentialID is the key that just verified against this service's own
// store. claimedOperator and claimedRole are the dashboard's server-side
// derivation from its session — not attacker-supplied, but not proved here
// either.
//
// The store's own answer wins where it has one, and the dashboard's claim is
// kept alongside it. Where the store has no answer (a credential synced
// before user/role existed, or pushed by an older aggregator) the claim is
// all there is, and `verified` drops to "session" so the record does not
// promise a proof that was never made.
func ceremonyActor(store *host.CredentialStore, credentialID, claimedOperator, claimedRole, origin string) ledger.Actor {
	a := ledger.Actor{
		CredentialID: credentialID,
		Source:       ledger.SourceWeb,
		Origin:       origin,
		ClaimedBy:    "dashboard",
	}
	known := storeIdentity(store, credentialID)
	switch {
	case known.User != "":
		a.Operator = known.User
		a.Role = firstNonEmpty(known.Role, claimedRole)
		a.Verified = ledger.VerifiedCredential
		if claimedOperator != "" && claimedOperator != known.User {
			// Two parties that should agree, made to say so — the same shape
			// trust_sync and ledger_witness already use. Recorded on the entry
			// AND logged, because an operator reading the ledger later and an
			// operator watching the service now are different people.
			a.ClaimedOperator = claimedOperator
			a.IdentityMismatch = true
			log.Printf("[actor] IDENTITY DISAGREEMENT: credential %s is enrolled to %q, "+
				"the dashboard named %q — recorded on the ledger entry",
				abbrevID(credentialID), known.User, claimedOperator)
		}
	default:
		a.Operator = claimedOperator
		a.Role = claimedRole
		a.Verified = ledger.VerifiedSession
	}
	return a
}

// refusedActor attributes a ceremony that did NOT verify.
//
// Nothing was proved — that is the situation being recorded — so the name is
// carried as a claim with verified:"none". Before this, a failed passkey
// attempt recorded a credential id and nothing else, and "someone tried to
// approve a cutover and failed three times" could not be resolved to a person
// even though the session behind it was authenticated.
func refusedActor(credentialID, claimedOperator, claimedRole, origin string) ledger.Actor {
	return ledger.Actor{
		ClaimedOperator: claimedOperator,
		Role:            claimedRole,
		CredentialID:    credentialID,
		Source:          ledger.SourceWeb,
		Origin:          origin,
		Verified:        ledger.VerifiedNone,
		ClaimedBy:       "dashboard",
	}
}

// sessionActor attributes an act the dashboard gates by role but that carries
// no ceremony of its own — break-glass continue and close, and evidence
// capture. The dashboard derives the name server-side from its session; this
// service can neither confirm nor improve on it, so it records it as what it
// is.
func sessionActor(operator, role string) ledger.Actor {
	if operator == "" {
		return ledger.Actor{}
	}
	return ledger.Actor{
		Operator:  operator,
		Role:      role,
		Source:    ledger.SourceWeb,
		Verified:  ledger.VerifiedSession,
		ClaimedBy: "dashboard",
	}
}

// serviceActor attributes an act the Advisor performed on its own behalf —
// an inbox note it wrote, a trust bundle an aggregator pushed. Named so the
// three attribution classes (operator, OS account, service) stay
// distinguishable in the record instead of blurring into "unattributed".
func serviceActor(who string) ledger.Actor {
	return ledger.Actor{
		Operator: who,
		Source:   ledger.SourceService,
		Verified: ledger.VerifiedNone,
	}
}

// aggregatorActorName names the aggregator that pushed a trust bundle, for
// the service actor on the installed entry. "aggregator <label>" reads well
// for a label like "home-one"; when the aggregator's own label is the word
// aggregator (the common case, and the lab's) it read "aggregator
// aggregator", so the role is only prefixed when the label adds something.
//
// The literal "self" (#477) is its own case, checked first: an aggregator's
// second copy of its own act, appended to its own advisord, is not "aggregator
// self" (which reads as a label nobody chose) but "this aggregator" (which
// reads correctly on the exact chain this claimant ever appears on).
func aggregatorActorName(label string) string {
	l := strings.TrimSpace(label)
	if l == "self" {
		return "this aggregator"
	}
	if l == "" || strings.EqualFold(l, "aggregator") {
		return "aggregator"
	}
	return "aggregator " + l
}

// fleetRecordActor attributes an act the AGGREGATOR performed on this node
// and told it about afterwards: a revoked link, or a re-pinned node key
// (#455).
//
// What this service proved is the SENDER. The record's signature verified
// against the aggregator key in fleet-trust.yaml, so "the aggregator said
// this" is a fact; "an admin approved it at a passkey" is that aggregator's
// word, and the ceremony it names ran on a machine whose challenge this node
// never saw. So the attribution is `verified: session` with the aggregator
// named as the claimant, which is the same honesty sessionActor keeps for the
// dashboard's own claims, one machine further out.
//
// One thing is worth checking even so, and it is free: this node holds the
// aggregator's pushed passkey bundle, so it usually knows who that credential
// id belongs to. Where the store's name and the claimed name disagree, both
// go on the entry with identity_mismatch set, exactly as ceremonyActor does.
// The claim is NOT upgraded when they agree: agreement between two things the
// same aggregator told this node is not a proof, and calling it one would be
// the dressing-up this file exists to refuse.
func fleetRecordActor(store *host.CredentialStore, rec *fleetrecord.Record) ledger.Actor {
	a := ledger.Actor{
		Operator:     rec.Operator,
		Role:         rec.Role,
		CredentialID: rec.CredentialID,
		Source:       ledger.SourceWeb,
		Origin:       rec.Origin,
		Verified:     ledger.VerifiedSession,
		ClaimedBy:    aggregatorActorName(rec.IssuerLabel),
	}
	known := storeIdentity(store, rec.CredentialID)
	if known.User != "" && rec.Operator != "" && known.User != rec.Operator {
		a.ClaimedOperator = known.User
		a.IdentityMismatch = true
		log.Printf("[fleet-record] IDENTITY DISAGREEMENT: credential %s is enrolled to %q, "+
			"the aggregator named %q, recorded on the ledger entry",
			abbrevID(rec.CredentialID), known.User, rec.Operator)
	}
	return a
}

// identityOf and actorOf translate between the ledger's Actor and the
// breakglass package's dependency-free Identity. Two small functions are the
// whole price of keeping internal/breakglass importing nothing but time.
func identityOf(a ledger.Actor) breakglass.Identity {
	return breakglass.Identity{
		Operator: a.Operator, Role: a.Role, CredentialID: a.CredentialID,
		Origin: a.Origin, Verified: a.Verified,
	}
}

func actorOf(i breakglass.Identity) ledger.Actor {
	if i.Operator == "" {
		return ledger.Actor{}
	}
	return ledger.Actor{
		Operator: i.Operator, Role: i.Role, CredentialID: i.CredentialID,
		Origin: i.Origin, Verified: i.Verified,
		Source: ledger.SourceWeb, ClaimedBy: "dashboard",
	}
}

type identity struct{ User, Role string }

func storeIdentity(store *host.CredentialStore, credentialID string) identity {
	if store == nil || credentialID == "" {
		return identity{}
	}
	for _, c := range store.Credentials {
		if c.ID == credentialID {
			return identity{User: c.User, Role: c.Role}
		}
	}
	return identity{}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func abbrevID(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
