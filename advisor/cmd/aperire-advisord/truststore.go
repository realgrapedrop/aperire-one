package main

import (
	"errors"
	"log"
	"os/user"
	"path/filepath"
	"time"

	"aperire-advisor/internal/host"
	"aperire-advisor/internal/ledger"
)

// Watching the set of passkeys that may approve anything on this node.
//
// This closes the largest hole in the record. `aperire-auth set-role` and
// `advisor-sync` rewrite advisor/state/credentials.json — the list of keys
// that can authorise an upgrade — and neither left a trace on either side of
// the system. The privileged action that decides who may perform every other
// privileged action was the one with no audit at all.
//
// Two rules shape how it is closed.
//
// The shell script does NOT write the ledger. A caller able to append
// arbitrary entries to a tamper-evident record is exactly the shape the whole
// design exists to avoid, and it would only ever record the SANCTIONED path.
// advisord already owns the file and the fingerprint, so it records the change
// as OBSERVED — which catches a store rewritten by any path, not just the one
// with a CLI command attached to it.
//
// And a watcher alone misses the case it exists for: stop the service, swap
// the store, start it. So the check runs at startup too, against the last
// fingerprint this service ledgered, and says plainly that it is reporting
// something it noticed rather than something it saw happen.

// trustCheckInterval is how often the store is re-read. Comfortably faster
// than a person can change a role and act on it, cheap enough to be
// invisible: one small file read.
const trustCheckInterval = 30 * time.Second

// lastLedgeredFingerprint walks the ledger backwards for the most recent
// fingerprint this service recorded for the trust store.
//
// The ledger IS the durable baseline — deliberately, rather than a state file
// beside it. A marker in its own mutable file would sit outside the
// tamper-evident record and could be edited to make a swap look like no
// change at all, which is precisely the alarm it would be there to raise.
func lastLedgeredFingerprint(path string) string {
	es, err := ledger.Entries(path)
	if err != nil && len(es) == 0 {
		return ""
	}
	for i := len(es) - 1; i >= 0; i-- {
		switch es[i].Kind {
		case ledger.KindTrustStoreChanged, ledger.KindTrustBundleInstalled:
			if fp, ok := es[i].Data["fingerprint_after"].(string); ok && fp != "" {
				return fp
			}
		}
	}
	return ""
}

// fingerprintOf is Fingerprint with a nil-safe front, so a store that could
// not be read records "unreadable" rather than silently reading as "empty" —
// a store that vanished and a store with no credentials are different facts.
func fingerprintOf(s *host.CredentialStore) string {
	if s == nil {
		return "unreadable"
	}
	return s.Fingerprint()
}

// trustSummary is what an entry says about a change, and it never says it with
// key material: counts, a fingerprint pair, and the labels of the people the
// store now trusts.
func trustSummary(prev, cur *host.CredentialStore) map[string]any {
	prevIDs := map[string]bool{}
	if prev != nil {
		for _, c := range prev.Credentials {
			prevIDs[c.ID] = true
		}
	}
	curIDs := map[string]bool{}
	added := 0
	var operators []string
	if cur != nil {
		for _, c := range cur.Credentials {
			curIDs[c.ID] = true
			if !prevIDs[c.ID] {
				added++
			}
			if c.User != "" {
				operators = append(operators, c.User)
			}
		}
	}
	removed := 0
	for id := range prevIDs {
		if !curIDs[id] {
			removed++
		}
	}
	d := map[string]any{
		"fingerprint_before": fingerprintOf(prev),
		"fingerprint_after":  fingerprintOf(cur),
		"added":              added,
		"removed":            removed,
		"trusted":            len(curIDs),
	}
	if len(operators) > 0 {
		d["operators"] = operators
	}
	return d
}

// osOwner names the account this service runs as. The change was made by
// something with write access to a directory this account owns, so recording
// the account is recording the strongest thing available — and verified:"os"
// on the entry says exactly how strong that is.
func osOwner() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

// watchTrustStore records the store's state at startup and on every observed
// change afterwards. Runs for the life of the process.
func (s *server) watchTrustStore() {
	credPath := filepath.Join(s.stateDir, "credentials.json")
	lPath := s.ledgerPath()

	cur, err := host.LoadCredentials(credPath)
	if err != nil {
		log.Printf("[trust] cannot read the credential store: %v", err)
	}
	known := fingerprintOf(cur)
	baseline := lastLedgeredFingerprint(lPath)

	// The startup case, and the honest wording for it. This service was not
	// running when the change happened, so it cannot say when it happened —
	// only that the store no longer matches what it last recorded.
	if baseline != "" && baseline != known {
		d := trustSummary(nil, cur)
		d["fingerprint_before"] = baseline
		d["observed"] = "at startup"
		if l, lerr := ledger.Open(lPath); lerr == nil && l != nil {
			l.AppendAs(ledger.KindTrustStoreChanged, "",
				"the set of passkeys allowed to approve changed while this service was not running "+
					"— observed at startup; it changed at some point since the previous entry",
				d, ledger.Actor{Operator: osOwner(), Source: ledger.SourceService, Verified: ledger.VerifiedOS})
			log.Printf("[trust] store changed while stopped: %s → %s", abbrevID(baseline), abbrevID(known))
		}
	} else if baseline == "" && cur != nil && len(cur.Credentials) > 0 {
		// Nothing recorded yet, and a store already exists. Record the
		// baseline so the FIRST later change has something to be a change
		// FROM, and label it as a baseline rather than as a change.
		d := trustSummary(nil, cur)
		d["observed"] = "first observation"
		if l, lerr := ledger.Open(lPath); lerr == nil && l != nil {
			l.AppendAs(ledger.KindTrustStoreChanged, "",
				"first record of which passkeys may approve on this node",
				d, ledger.Actor{Operator: osOwner(), Source: ledger.SourceService, Verified: ledger.VerifiedOS})
		}
	}

	for range time.Tick(trustCheckInterval) {
		next, nerr := host.LoadCredentials(credPath)
		if nerr != nil {
			continue // a partial write mid-sync; the next tick sees the finished file
		}
		fp := fingerprintOf(next)
		if fp == known {
			continue
		}
		d := trustSummary(cur, next)
		d["observed"] = "while running"
		if l, lerr := ledger.Open(lPath); lerr == nil && l != nil {
			l.AppendAs(ledger.KindTrustStoreChanged, "",
				"the set of passkeys allowed to approve on this node changed",
				d, ledger.Actor{Operator: osOwner(), Source: ledger.SourceService, Verified: ledger.VerifiedOS})
			log.Printf("[trust] store changed: %d trusted (%s → %s)",
				len(next.Credentials), abbrevID(known), abbrevID(fp))
		}
		cur, known = next, fp
	}
}

// acceptedBundlePath is where the receipt for the last accepted trust bundle
// lives — beside the store it describes, so a state directory restored from a
// backup carries the two together or neither.
func (s *server) acceptedBundlePath() string {
	return filepath.Join(s.stateDir, "trust-bundle.json")
}

// enrollmentRemedy turns "your passkey did not verify" into something the
// operator can act on.
//
// The refusal that cost a live ceremony (2026-08-19, an admin enrolled at the
// aggregator, refused on a fleet node) was technically correct and
// operationally useless: it named the credential and said it was not
// enrolled, which reads as "your passkey is broken" to the person holding a
// working passkey. The actual fault was one hop away — this node had never
// been sent the trust bundle carrying that credential — and the command that
// fixes it is one line.
//
// Only ErrNotEnrolled gets the extra sentence. A signature that genuinely
// fails to verify is a different fact and must not be dressed up as a missing
// push; appending the remedy to every failure would train the operator to run
// a push at the sight of any refusal.
//
// The label comes from this node's own fleet self identity, which is the only
// place on this host that knows what the aggregator calls it. When that is
// unknown the command is still correct without --node (it pushes to every
// registered node), so the sentence is printed either way rather than
// withheld for want of a name.
func (s *server) enrollmentRemedy(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if !errors.Is(err, host.ErrNotEnrolled) {
		return msg
	}
	// The in-tree form runs on every install; a bare aperire-auth is only
	// on PATH where the optional CLI installer ran (the lab aggregator, 2026-08-20).
	cmd := "bash scripts/aperire-auth.sh fleet-trust-push"
	if label := s.fleetNow().reg.SelfIdentity().Label; label != "" {
		cmd += " --node " + label
	}
	return msg + ". Push trust to this node from the dashboard host: " + cmd
}

// trustStatus is the /v1/status "trust" block: what this service will
// actually accept as an approver, and where that set came from.
//
// Two claims, deliberately separate. `fingerprint` is what the store hashes
// to right now — it moves for a local advisor-sync or a hand edit as readily
// as for a pushed bundle, which is what makes it the right thing to compare
// against the dashboard's own admin set. `bundle` is the receipt: which
// issuer last handed this node a credential set, which serial, and when. An
// aggregator can compare its current serial against that and see a node that
// never took the last push — before a ceremony fails on it — instead of the
// operator discovering it as a passkey that "doesn't work" on one node.
//
// nil when the store cannot be read at all, so the caller omits the key
// rather than publishing an empty trust block that reads like "nothing is
// trusted". `bundle` is likewise absent, never zeroed, on a node that has
// never been pushed to: never pushed and pushed-with-an-empty-serial are
// different facts and the dashboard renders them differently.
func (s *server) trustStatus() map[string]any {
	store, err := host.LoadCredentials(filepath.Join(s.stateDir, "credentials.json"))
	if err != nil {
		return nil
	}
	t := map[string]any{
		"fingerprint": store.Fingerprint(),
		"credentials": len(store.Credentials),
		"updated_at":  store.UpdatedAt,
	}
	if ab, aerr := host.LoadAcceptedBundle(s.acceptedBundlePath()); aerr == nil && ab != nil {
		t["bundle"] = map[string]any{
			"serial":      ab.Serial,
			"issuer":      ab.Issuer,
			"accepted_at": ab.AcceptedAt,
		}
	}
	return t
}
