package ledger

// Actor names who performed the act an entry records.
//
// It lives INSIDE Entry.Data, under the reserved key "actor", and that
// placement is the whole reason this file is a small one rather than a schema
// migration. computeHash digests canonical(e.Data), so a key inside Data is
// covered by the entry hash for free — the attribution cannot be edited
// afterwards without breaking the chain, which is the property the record
// exists to have.
//
// A new top-level field on Entry would have been more self-describing and is
// not available: computeHash's payload struct lists the fields it digests, so
// adding one changes the hash of every entry ever written. Open refuses a
// ledger that does not verify, on purpose, so the first advisord to start
// after that change could no longer append to any existing host's record. A
// top-level field left OUT of the payload would be worse still — an actor an
// attacker could rewrite without breaking the chain is not attribution.
//
// The cost, stated plainly: `data` is a map, so nothing but this file's
// discipline stops a caller putting something else under "actor". Every writer
// goes through Stamp.
type Actor struct {
	// Operator is the person, as best the recording component can name them.
	Operator string `json:"operator,omitempty"`
	// Role is what they were allowed to do AT THE TIME. Recorded because a
	// demotion later makes the past unreconstructable otherwise.
	Role string `json:"role,omitempty"`
	// CredentialID is the passkey that signed, where one did.
	CredentialID string `json:"credential_id,omitempty"`
	// Source distinguishes a web ceremony from a shell invocation from the
	// service acting on its own.
	Source string `json:"source,omitempty"`
	// Origin is the web origin a ceremony ran on.
	Origin string `json:"origin,omitempty"`
	// Verified names what the recording component PROVED, not what it was
	// told. This is the field that keeps the record honest: an auditor can
	// tell a cryptographically-backed attribution from a service's word for
	// it, and both are worth recording as long as they are distinguishable.
	Verified string `json:"verified,omitempty"`
	// ClaimedBy names who asserted Operator when it was not proved here.
	ClaimedBy string `json:"claimed_by,omitempty"`
	// ClaimedOperator is a second, unproved name for the same act. Present
	// only when there are two sources and they were both recorded.
	ClaimedOperator string `json:"claimed_operator,omitempty"`
	// IdentityMismatch is set when two sources that should agree did not.
	// A real alarm, in the same shape trust_sync and ledger_witness use.
	IdentityMismatch bool `json:"identity_mismatch,omitempty"`
}

// What Verified may say. Ordered strongest to weakest.
const (
	// VerifiedCredential — an enrolled passkey signed this act's challenge,
	// checked here against keys this service holds.
	VerifiedCredential = "credential"
	// VerifiedApproval — read out of a signed approval file this service
	// verified before acting on it.
	VerifiedApproval = "approval"
	// VerifiedOS — the operating-system account that ran the command.
	VerifiedOS = "os"
	// VerifiedSession — the dashboard's claim about its logged-in operator,
	// and nothing more. Recorded, never dressed up as proof.
	VerifiedSession = "session"
	// VerifiedNone — nothing was proved. Used where an act was REFUSED
	// precisely because no identity could be established: the claim that
	// failed is worth keeping, and calling it anything else would lie.
	VerifiedNone = "none"
)

// Where an act came from.
const (
	SourceWeb     = "web"
	SourceCLI     = "cli"
	SourceService = "service"
)

// ActorKey is the reserved key inside Entry.Data.
const ActorKey = "actor"

// Empty reports whether this actor names nobody at all.
//
// The distinction matters more than it looks. A zero Actor rendered into Data
// as an empty object is NOT the same digest as no key at all, so an entry
// deliberately left unattributed — preconditions.evaluated, which is a
// measurement rather than an act — would silently start carrying an empty
// actor and every "is this stamped?" check would pass on a technicality.
// Stamp is a no-op on an empty actor for exactly this reason.
func (a Actor) Empty() bool {
	return a.Operator == "" && a.ClaimedOperator == "" && a.CredentialID == ""
}

// Map renders the actor for Data. Empty fields are omitted so the digest
// depends on what is actually known, not on the struct's shape.
//
// A map rather than the struct itself: canonical() round-trips Data through a
// generic value precisely because a struct in Data once hashed differently
// after being read back as a map. Writing a map here means the value written
// and the value read back are the same Go type to begin with.
func (a Actor) Map() map[string]any {
	m := map[string]any{}
	put := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	put("operator", a.Operator)
	put("role", a.Role)
	put("credential_id", a.CredentialID)
	put("source", a.Source)
	put("origin", a.Origin)
	put("verified", a.Verified)
	put("claimed_by", a.ClaimedBy)
	put("claimed_operator", a.ClaimedOperator)
	if a.IdentityMismatch {
		m["identity_mismatch"] = true
	}
	return m
}

// Stamp merges an actor into an entry's data under the reserved key.
//
// Returns data unchanged when the actor names nobody — see Empty. Never
// overwrites an actor already present: the first writer to attribute an act
// is the one closest to the identity, and a later merge that clobbered it
// would replace a proof with a claim.
func Stamp(data map[string]any, a Actor) map[string]any {
	if a.Empty() {
		return data
	}
	if data == nil {
		data = map[string]any{}
	}
	if _, exists := data[ActorKey]; exists {
		return data
	}
	data[ActorKey] = a.Map()
	return data
}

// AppendAs is Append with an actor stamped into the data.
func (l *Ledger) AppendAs(kind Kind, planID, summary string, data map[string]any, a Actor) (Entry, error) {
	return l.Append(kind, planID, summary, Stamp(data, a))
}

// ActorOf reads the attribution back off an entry, for callers that verify
// the record rather than write it. Deliberately not a json-tagged field on
// Entry: a field would have to be excluded from the hash payload by hand, and
// the next person to add a field to that struct would not know why.
func ActorOf(e Entry) (Actor, bool) {
	raw, ok := e.Data[ActorKey].(map[string]any)
	if !ok {
		return Actor{}, false
	}
	s := func(k string) string {
		v, _ := raw[k].(string)
		return v
	}
	b, _ := raw["identity_mismatch"].(bool)
	return Actor{
		Operator:         s("operator"),
		Role:             s("role"),
		CredentialID:     s("credential_id"),
		Source:           s("source"),
		Origin:           s("origin"),
		Verified:         s("verified"),
		ClaimedBy:        s("claimed_by"),
		ClaimedOperator:  s("claimed_operator"),
		IdentityMismatch: b,
	}, true
}
