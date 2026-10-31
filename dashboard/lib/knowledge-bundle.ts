/**
 * The aggregator half of ADR 0017 decision 3: the canonical bytes of a
 * knowledge-bundle manifest, and its signature.
 *
 * The ONE thing that must be exactly right is `signingBytes` — it must be
 * byte-identical to the Go twin, `Manifest.SigningBytes()` in
 * advisor/internal/knowledge/bundle.go, or the push is refused on every node
 * with a signature error. Both sides are pinned to the same vector in their
 * tests. Do not "tidy" the serialization without changing both and
 * re-checking the vector.
 *
 * Signing itself reuses the trust bundle's key handling (signWithSeed) rather
 * than repeating it: one aggregator key, one place that knows how a stored
 * seed becomes a signer.
 */
import { signWithSeed } from './trust-bundle.js';

export interface ManifestFile {
  path: string;   // relative to knowledge-fleet/, e.g. "local/xrpl/validations.md"
  sha256: string; // lowercase hex of the file's bytes
}

export interface KnowledgeManifest {
  seq: number;
  files: ManifestFile[];
  created_at: string;   // RFC3339 UTC
  issuer_label: string; // which peers.<label> key on the node verifies this
  pushed_by: string;    // the operator account that built it
}

/**
 * The canonical bytes both sides sign and verify. Mirrors the Go twin:
 *   - fixed key order: seq, files, created_at, issuer_label, pushed_by
 *   - files sorted by path ascending, each {path, sha256} in that order
 *   - JSON.stringify (compact, no HTML escaping — Go uses SetEscapeHTML(false))
 *   - no files at all (an empty corpus, #1219) signs as "files":null, which is
 *     what every released node computes for an empty list; [] would fail the
 *     signature there, before the node could say why it refuses the bundle
 *
 * issuer_label and pushed_by are INSIDE the signature deliberately: the first
 * decides which key verifies the push, and the second is written into the
 * node's ledger as the actor. A field the wire could rewrite would be an
 * audit trail that records whatever the pusher felt like claiming.
 */
export function signingBytes(m: KnowledgeManifest): string {
  const files = [...m.files]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((f) => ({ path: f.path, sha256: f.sha256 }));
  return JSON.stringify({
    seq: m.seq,
    files: files.length ? files : null,
    created_at: m.created_at,
    issuer_label: m.issuer_label,
    pushed_by: m.pushed_by,
  });
}

/** Detached signature over signingBytes, base64url, as the node decodes it. */
export function signManifest(m: KnowledgeManifest, privateKeySeedB64url: string): string {
  return signWithSeed(signingBytes(m), privateKeySeedB64url);
}
