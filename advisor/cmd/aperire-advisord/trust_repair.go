package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"aperire-advisor/internal/host"
)

// A re-pairing resets the trust binding (#991).
//
// This node's Advisor pins the rp_id and origins of the first trust bundle it
// accepts, and refuses every later bundle that carries different ones. That
// pin is what keeps a pushed bundle from moving the node's trust to another
// host name. It also meant a node re-paired to an aggregator on a different
// name (one moved to a new host, which keeps its fleet trust key through the
// backup) refused that aggregator's bundles forever, until someone removed
// trust-binding.json by hand.
//
// The pin may move only on an act the operator approved: a pairing. The
// node's root pair command writes fleetPairedRecord to /etc/aperire after the
// aggregator's signed answer and the operator's fingerprint paste have both
// checked out, and after the aggregator approved that pairing under passkey.
// Only root can write there. A bundle alone never moves the pin. It moves when
// all of this holds:
//
//   - the bundle verified against the trust key in fleet-trust.yaml, as every
//     bundle must;
//   - a pairing record is in place, owned by root, not writable by anyone else;
//   - the record names that same trust key, so a record from an earlier
//     pairing cannot be spent on a trust file edited since;
//   - the binding was not pinned under that record already, so one
//     pairing resets the pin at most once;
//   - and the bundle is one for that pairing: on the host the record names,
//     and issued no earlier than the pairing (rePairingBundleRefusal).
//
// The reset is recorded on the ledger with the binding it replaced. Every
// accepted bundle also notes the record it was accepted under, so a pairing
// to the same aggregator and the same name spends its record without a reset
// and without a ledger line of its own.

// defaultFleetPairedPath is where the node's pair command leaves the record.
const defaultFleetPairedPath = "/etc/aperire/fleet-paired.json"

// fleetPairedRecord is what the pair command writes. Only these fields are
// read; anything else in the file is ignored.
type fleetPairedRecord struct {
	Pairing    string `json:"pairing"`
	PairedAt   string `json:"paired_at"`
	TrustPub   string `json:"trust_pub"`
	Aggregator string `json:"aggregator"`
	Label      string `json:"label"`
}

var pairingIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (s *server) fleetPairedPath() string {
	if s.fleetPaired != "" {
		return s.fleetPaired
	}
	return defaultFleetPairedPath
}

// loadFleetPairedRecord reads the record. No file is nil and no error. A file
// that is not a plain file, is a link, belongs to anyone but root (or this
// process, which is what a test or a non-root install runs as), or that its
// group or others could write, is an error and is never used: a record any
// other account could write would let that account move the pin.
func loadFleetPairedRecord(path string) (*fleetPairedRecord, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a plain file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s can be written by its group or by anyone (mode %#o)", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: cannot read its owner", path)
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s belongs to uid %d, not root", path, st.Uid)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, err
	}
	var r fleetPairedRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s is not a pairing record: %w", path, err)
	}
	if !pairingIDRe.MatchString(r.Pairing) || r.TrustPub == "" {
		return nil, fmt.Errorf("%s is not a pairing record: no pairing id or trust key", path)
	}
	return &r, nil
}

// pairedUnder is the record a bundle verified against aggKey is accepted
// under, or nil. A record for another trust key is no record for this bundle.
// An unreadable record is nil too, with the reason logged by the caller.
func pairedUnder(rec *fleetPairedRecord, aggKey string) *fleetPairedRecord {
	if rec == nil || rec.TrustPub != aggKey {
		return nil
	}
	return rec
}

// rePairingResets says whether this re-pairing may replace the pinned binding:
// a record for this bundle's trust key, which the pin was not taken under.
func rePairingResets(pinned *host.Binding, rec *fleetPairedRecord) bool {
	return pinned != nil && rec != nil && pinned.PairedUnder != rec.Pairing
}

// rePairingBundleRefusal says why b may not be the bundle a re-pairing resets
// the pin to, or "" when it may (#991 review, L1). A record alone would let
// the next bundle its trust key ever signed become the pin and the passkey
// list, at any age and under any name, so the reset is held to the pairing
// itself:
//
//   - one of the bundle's origins is on the host the node paired with, as
//     the record names it, so a bundle for some other name is not spent on
//     this pairing;
//   - it was issued no earlier than the pairing, less the clock skew the
//     order check already allows, so a list signed before the pairing (one
//     from before a revoke) cannot come back through it. The aggregator's
//     push waits for the node's link, and the link comes up at the reload
//     after the record is written, so a real push is never older.
//
// The receipt still orders the bundle as it always does. Only the issuer
// comparison is skipped on a reset.
func rePairingBundleRefusal(rec *fleetPairedRecord, b *host.Bundle) string {
	want := hostOf(rec.Aggregator)
	if want == "" {
		return "the pairing record names no aggregator host"
	}
	onHost := false
	for _, o := range b.Origins {
		if strings.EqualFold(hostOf(o), want) {
			onHost = true
			break
		}
	}
	if !onHost {
		return fmt.Sprintf("this node was paired with %s, and the bundle carries no origin on that host", want)
	}
	pairedAt, err := time.Parse(time.RFC3339, rec.PairedAt)
	if err != nil {
		return "the pairing record carries no time it was paired"
	}
	issued, err := time.Parse(time.RFC3339, b.IssuedAt)
	if err != nil {
		return "the bundle carries no issued_at to compare with the pairing"
	}
	if issued.Before(pairedAt.Add(-maxBundleFutureSkew)) {
		return fmt.Sprintf("the bundle was issued %s, before this node was paired at %s", b.IssuedAt, rec.PairedAt)
	}
	return ""
}

// hostOf is the lower-case host name of a URL, without its port, or "".
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
