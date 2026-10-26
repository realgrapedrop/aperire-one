import { createHash } from 'node:crypto';

/**
 * A digest of "who may approve an Advisor action".
 *
 * The Advisor verifies every approval against its own replica of the
 * dashboard's admin passkeys, refreshed by `aperire-auth advisor-sync` — a
 * command someone has to remember to run. When the replica falls behind, the
 * failure is silent and points the wrong way: a passkey enrolled since the
 * last sync is rejected at the approval prompt with an error that reads like
 * the passkey is broken, while an operator whose admin role was revoked keeps
 * approving actions on the node. Comparing digests turns both into something
 * the Advisor tab can say out loud, before either one bites.
 *
 * This lives in a module of its own, with no database and no I/O, because it
 * has a twin: CredentialStore.Fingerprint() in advisor/internal/host. The two
 * are written in different languages and must produce the same bytes for the
 * same credentials — a digest that is merely almost the same reports drift
 * that never goes away, and a permanent warning is one the operator learns to
 * scroll past. Both are pinned to the shared vector in the tests beside them;
 * change one and the other's test fails.
 */
export function credentialDigest(
  rows: Array<{ credential_id: string; public_key: string }>,
): string {
  // Nothing enrolled is a real state, not a hash of nothing — it means no
  // action can be approved at all, and it should read differently from a
  // store that merely differs.
  if (rows.length === 0) return 'empty';
  // Hex per field, not the raw values around a separator. Concatenating
  // `id + ":" + key` looks fine and is not: a public key containing ":" and a
  // newline makes one row hash identically to two real ones, so a store with
  // an extra credential can be made to match a store without it — precisely
  // the drift being watched for. Hex is [0-9a-f] only, so no value can carry
  // a delimiter.
  const hex = (s: string) => Buffer.from(s, 'utf8').toString('hex');
  // Sorted because the two sides read different databases with different
  // natural orderings, and row order says nothing about who may approve.
  // Labels and timestamps are excluded for the same reason: renaming a device
  // does not change trust, and warning about it would be crying wolf.
  const lines = rows.map(r => `${hex(r.credential_id)}:${hex(r.public_key)}`).sort();
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}
