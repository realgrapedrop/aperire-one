package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"aperire-advisor/internal/host"
)

// The order of trust bundles (#987 review, L4).
//
// A node took any bundle its aggregator signed, whatever its age. Two pushes
// from one aggregator can cross: an attach's push reads the passkey list just
// before a revoke and lands just after the revoke's own push, and the node
// then trusts the removed passkey again while both pushes report success.
//
// Every bundle carries issued_at inside its signature, so the node can tell
// which of two bundles is the older. It keeps the issued_at of the bundle it
// installed with its receipt, and a bundle from the same issuer that is
// strictly older is not installed. That is not a failure: the node already
// holds a newer list, and it says so. A bundle with the same issued_at is
// installed as before, so the same bundle again is idempotent.
//
// issued_at has one-second resolution and is minted when the bundle is
// signed, not when the list was read, so this alone cannot order two pushes
// in the same second, or two whose reads and signatures interleave. The
// aggregator's push (scripts/aperire-auth.sh fleet-trust-push) also takes
// one lock around its read and its sends, so its pushes cannot cross; this
// check is what holds when they come from anything else, a replay of an old
// signed bundle among them.

// maxBundleFutureSkew is how far past this node's own clock a bundle's
// signed issued_at may be and still be installed. The age check above trusts
// issued_at, so one bundle dated in the future (an aggregator whose clock ran
// ahead and was then corrected) would otherwise make every later bundle from
// it "older", a revoke's included, and the node would keep a removed passkey
// while each push read as ok. Five minutes covers clocks that NTP keeps
// honest and the time a push spends on the wire; a bundle past it is refused
// by name, and the pusher reports that refusal as a failure.
const maxBundleFutureSkew = 5 * time.Minute

// bundleIssuedInFuture says whether b's issued_at is more than
// maxBundleFutureSkew past now, and by how much it is ahead. An issued_at
// that does not parse is not judged here.
func bundleIssuedInFuture(b *host.Bundle, now time.Time) (bool, time.Duration) {
	at, err := time.Parse(time.RFC3339, b.IssuedAt)
	if err != nil {
		return false, 0
	}
	ahead := at.Sub(now)
	return ahead > maxBundleFutureSkew, ahead
}

// trustBundleReceipt is the receipt host.AcceptedBundle reads, with the
// bundle's own issued_at added. Written here rather than through
// host.SaveAcceptedBundle so the extra field rides along; host's reader
// ignores it, so the trust-sync status keeps reading this file as before.
type trustBundleReceipt struct {
	Serial     string `json:"serial"`
	Issuer     string `json:"issuer"`
	AcceptedAt string `json:"accepted_at"`
	IssuedAt   string `json:"issued_at,omitempty"`
}

// loadTrustBundleReceipt reads the receipt. No file is nil and no error: the
// node has never been pushed to.
func loadTrustBundleReceipt(path string) (*trustBundleReceipt, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r trustBundleReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// saveTrustBundleReceipt writes it the way host.SaveAcceptedBundle does.
func saveTrustBundleReceipt(path string, r *trustBundleReceipt) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o640)
}

// bundleOlderThanHeld says whether b is strictly older than the bundle the
// receipt describes, whatever issuer either names: an issuer label is not a
// way around the order (#987 re-review, N2), and a bundle from an issuer
// other than the held one is refused before this is asked (heldIssuerDiffers).
// Anything it cannot compare (no receipt, a receipt from before issued_at was
// kept, a time that does not parse) is not older: the bundle goes through the
// checks it always went through, and nothing else.
//
// A held bundle that is itself dated past the window (installed by a build
// from before the window existed) orders nothing either: trusting it would
// keep the very lock-out the window exists to prevent.
func bundleOlderThanHeld(held *trustBundleReceipt, b *host.Bundle, now time.Time) bool {
	if held == nil || held.IssuedAt == "" {
		return false
	}
	heldAt, err := time.Parse(time.RFC3339, held.IssuedAt)
	if err != nil || heldAt.Sub(now) > maxBundleFutureSkew {
		return false
	}
	at, err := time.Parse(time.RFC3339, b.IssuedAt)
	if err != nil {
		return false
	}
	return at.Before(heldAt)
}

// heldIssuerDiffers says whether the node's last bundle came from an issuer
// other than the one b names. Only "aggregator" signs bundles today, so a
// different label is one this node does not know to order against, and the
// handler refuses it by name rather than install it unordered.
func heldIssuerDiffers(held *trustBundleReceipt, b *host.Bundle) bool {
	return held != nil && held.Issuer != "" && held.Issuer != b.IssuerLabel
}
