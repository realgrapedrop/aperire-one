package approval

import (
	"crypto/sha256"
	"strings"
)

// confirmCodeAlphabet is Crockford base32 without I, L, O, U, further reduced
// after a real reported code (QB0V-W3S4) was misread on a phone: S sat
// beside a 4 and read as a 5, and 0 sat beside a V and read as one of the
// O-shapes it was already meant to exclude. Also dropped: 1 (with I already
// gone, keeping 1 invites the same confusion the reduction exists to
// prevent), B (reads as 8 at small sizes), and 8 itself. What is left, 26
// characters, has no pair that is commonly confused for one another at a
// glance. `% len(confirmCodeAlphabet)` over a uniformly-distributed hash byte
// is not perfectly uniform (26 does not divide 256), but this code
// identifies a plan; it does not authorise one — see ConfirmCode's own
// comment — so a few characters landing very slightly more often than others
// is not a property anything depends on. A package-level const, not local to
// ConfirmCode, so the test that guards it against a re-added ambiguous
// character reads the same value this function actually uses.
const confirmCodeAlphabet = "234679ACDEFGHJKMNPQRTVWXYZ"

// ConfirmCode is the XXXX-XXXX the operator types to approve.
//
// Derived from the plan fingerprint, not random, and that is the whole point.
// A random code shown in a browser and typed back into the same browser proves
// only that a human was involved — a script with DOM access reads it and
// submits it. A derived code has an independent source of truth: the same
// eight characters appear in `aperire-executor check`, in /v1/check, and in
// every ledger entry for the plan. An operator who cross-checks anywhere at
// all catches a page that displayed one plan while requesting approval for
// another, which is exactly the gap WebAuthn's missing transaction display
// leaves open.
//
// It is not a secret. It identifies a plan; it does not authorise one. The
// passkey authorises. Publishing it in the ledger is deliberate.
func ConfirmCode(fingerprint string) string {
	// Hash again with a domain separator so the code cannot be walked back to
	// the fingerprint, and so a future change to fingerprinting does not
	// silently change every code.
	sum := sha256.Sum256([]byte("aperire-advisor/confirm-code/v1\x00" + fingerprint))

	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(confirmCodeAlphabet[int(sum[i])%len(confirmCodeAlphabet)])
	}
	return b.String()
}

// CodeMatches compares what the operator typed against the plan's code,
// forgivingly about the things that are not the operator's fault: case, the
// separator, and surrounding whitespace.
func CodeMatches(typed, fingerprint string) bool {
	norm := func(s string) string {
		s = strings.ToUpper(strings.TrimSpace(s))
		return strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), " ", "")
	}
	return norm(typed) != "" && norm(typed) == norm(ConfirmCode(fingerprint))
}
