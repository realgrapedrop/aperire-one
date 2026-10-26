/**
 * The aggregator side of ADR 0014 decision 4: build and sign the trust
 * bundle that `aperire-auth fleet-trust-push` sends to each node's advisord.
 *
 * The node verifies this against the aggregator's public key it already
 * holds (fleet-trust.yaml peers.<issuer_label>). The ONE thing that must be
 * exactly right is `signingBytes` — it must be byte-identical to the Go
 * twin, `Bundle.SigningBytes()` in advisor/internal/host/trustbundle.go, or
 * the signature will not verify and the failure reads as a broken passkey.
 * Both are pinned to the same shared vector in their tests. Do not "tidy"
 * the serialization without changing both and re-checking the vector.
 */
import { sign, verify, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

export interface BundleCred {
  credential_id: string;
  public_key: string;
  label: string;
  /**
   * Who this passkey belongs to, and what they were allowed to do when the
   * bundle was built. Carried so a fleet node can attribute an approval to a
   * person from its own store rather than from the claim in the request — the
   * node has no other way to answer "which operator is credential X".
   *
   * Both are INSIDE the signature and both are OMITTED when absent. Omitting
   * is what keeps a bundle without them byte-identical to what this function
   * used to produce, so a node upgraded ahead of its aggregator still
   * verifies. A role the wire could rewrite would be worse than no role, so
   * moving these outside the signature is not the shortcut it looks like.
   */
  user?: string;
  role?: string;
}

export interface TrustBundle {
  rp_id: string;
  origins: string[];
  credentials: BundleCred[];
  serial: string;       // credentialDigest() of the credentials
  issued_at: string;    // RFC3339
  issuer_label: string; // which peers.<label> key on the node verifies this
}

/**
 * The canonical bytes both sides sign/verify. Mirrors the Go twin exactly:
 *   - fixed key order: rp_id, origins, credentials, serial, issued_at, issuer_label
 *   - origins sorted ascending
 *   - credentials sorted by credential_id ascending, each
 *     {credential_id, public_key, label} plus user and role WHEN PRESENT, in
 *     that order — Go's `omitempty` drops an empty string entirely, so this
 *     side must drop it too or the two serializations part company on any
 *     credential that has no user
 *   - JSON.stringify (no spaces, no HTML escaping) — Go uses SetEscapeHTML(false) to match
 */
export function signingBytes(b: TrustBundle): string {
  const origins = [...b.origins].sort();
  const credentials = [...b.credentials]
    .sort((x, y) => (x.credential_id < y.credential_id ? -1 : x.credential_id > y.credential_id ? 1 : 0))
    .map((c) => ({
      credential_id: c.credential_id,
      public_key: c.public_key,
      label: c.label,
      ...(c.user ? { user: c.user } : {}),
      ...(c.role ? { role: c.role } : {}),
    }));
  // Object literal key order is the insertion order for string keys — this
  // is the load-bearing order. JSON.stringify emits compact, unescaped.
  return JSON.stringify({
    rp_id: b.rp_id,
    origins,
    credentials,
    serial: b.serial,
    issued_at: b.issued_at,
    issuer_label: b.issuer_label,
  });
}

/** base64url without padding, matching aperire-fleet-add.sh's key encoding. */
function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s: string): Buffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

/**
 * Sign the bundle with the aggregator's Ed25519 private key (the raw 32-byte
 * seed, base64url — exactly the form aperire-fleet-add.sh stores as
 * `private_key:` in fleet-trust.yaml). Returns the detached signature as
 * base64url, the form the Go verifier decodes.
 */
export function signBundle(b: TrustBundle, privateKeySeedB64url: string): string {
  return signWithSeed(signingBytes(b), privateKeySeedB64url);
}

/**
 * Detached Ed25519 signature over arbitrary canonical bytes, from the raw
 * 32-byte seed as `fleet-trust.yaml` stores it. Extracted from signBundle so
 * the knowledge bundle (ADR 0017) signs with the SAME key handling rather
 * than a second copy of the PKCS8 prefix: one place that knows how this
 * project turns a stored seed into a signer.
 *
 * No key material is logged or persisted here.
 */
export function signWithSeed(message: string, privateKeySeedB64url: string): string {
  const seed = fromB64url(privateKeySeedB64url);
  if (seed.length !== 32) {
    throw new Error(`aggregator private key seed is ${seed.length} bytes, expected 32`);
  }
  // Node's Ed25519 signer wants a KeyObject; build one from the raw seed via
  // the fixed PKCS8 DER prefix (the same prefix aperire-fleet-add.sh uses to
  // derive the public half).
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return b64url(sign(null, Buffer.from(message, 'utf8'), key));
}

/**
 * Verify a detached Ed25519 signature against a peer's public key as
 * fleet-trust.yaml stores it: the raw 32 bytes, base64url, no padding.
 *
 * The mirror of signWithSeed above, and written beside it on purpose. The
 * two halves of one scheme drifting apart is the failure this project has
 * already met once (a signature that will not verify reads to an operator
 * like a broken passkey), so the seed prefix and the SPKI prefix live in the
 * same file and are exercised by the same round-trip test.
 *
 * Never throws. Every way a signature can fail to verify is the same answer
 * to the caller: a malformed key, a wrong-length signature, a value that is
 * not base64url at all, and a good signature over different bytes are all
 * `false`. A gate that has to catch an exception to refuse is a gate one
 * missing try/catch away from admitting.
 */
export function verifyWithPeerKey(
  message: string, signatureB64url: string, publicKeyB64url: string,
): boolean {
  try {
    const raw = fromB64url(publicKeyB64url);
    if (raw.length !== 32) return false;
    const sig = fromB64url(signatureB64url);
    if (sig.length !== 64) return false;
    // Node's Ed25519 verifier wants a KeyObject, and there is no raw-public
    // constructor: build the SPKI DER by hand from the one fixed prefix an
    // Ed25519 public key has (302a300506032b6570032100 + the 32 bytes), the
    // same trick signWithSeed uses on the private side.
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return verify(null, Buffer.from(message, 'utf8'), key, sig);
  } catch {
    return false;
  }
}

/**
 * What public key does peers.<label> hold in this node's fleet-trust.yaml?
 *
 * The TypeScript twin of advisord's AggregatorPubKey
 * (advisor/internal/host/fleettrust.go:63), and strict for the same reason:
 * this file decides which machine may hand this host a key to seal, and a
 * lenient parser that guesses at an exotic hand edit is a parser that can
 * guess wrong. It reads exactly the block aperire-fleet-add.sh writes
 * (python yaml.safe_dump, block style):
 *
 *   private_key: <b64url>        # this node's own key; not read here
 *   peers:
 *     aggregator: <b64url>       # the key we want
 *
 * Two-space indent under `peers:`, one `label: value` per line, bare tokens.
 * A top-level key ends the block. Anything it does not recognise is skipped,
 * and a missing label is a plain null, never a guess. An EMPTY value is null
 * too, not the empty string: the Go side calls that an error, and the one
 * thing both sides must agree on is that it is not a key.
 *
 * No YAML library, deliberately. advisord parses this file with zero
 * dependencies, and a second parser with different opinions about the same
 * bytes is exactly how two services come to disagree about who is trusted.
 */
export function readPeerPubKey(fleetTrustPath: string, label: string): string | null {
  let text: string;
  try {
    text = readFileSync(fleetTrustPath, 'utf8');
  } catch {
    // Absent, or unreadable by this account. Both mean this host cannot say
    // who its aggregator is, which the caller renders as "no aggregator
    // pinned" rather than as a broken file: on a node that never joined a
    // fleet, absent is the ordinary state.
    return null;
  }
  let inPeers = false;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    // A top-level key (no leading whitespace) ends the peers block.
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      inPeers = trimmed.replace(/:$/, '').trim() === 'peers';
      continue;
    }
    if (!inPeers) continue;
    const idx = trimmed.indexOf(':');
    if (idx < 0) continue;
    const k = trimmed.slice(0, idx).trim();
    if (k !== label) continue;
    // Tolerate the quotes yaml.safe_dump would add for some values, the same
    // tolerance the Go reader has. It will not add them for bare base64url.
    const v = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
    return v === '' ? null : v;
  }
  return null;
}

/**
 * This host's OWN signing seed from fleet-trust.yaml, or null.
 *
 * The same one line the CLI reads (`awk -F': *' '/^private_key:/{print $2}'`
 * in scripts/aperire-auth.sh), in the module that already knows this file's
 * shape, so there is one parser rather than one per caller.
 *
 * An honest note about where this leaves the key, because lib/trust-push-hook.ts
 * makes a point of the opposite. That hook spawns the CLI so the seed is never
 * in the web process's heap. The fleet seal cannot: it signs one job per node
 * inside a request, so the seed IS read here. It is the same account and the
 * same readable file either way, so this is not new capability, only a new
 * place the bytes sit for the length of a job. It is read per job, never
 * cached, never logged and never returned to a browser.
 */
export function readOwnPrivateKey(fleetTrustPath: string): string | null {
  let text: string;
  try {
    text = readFileSync(fleetTrustPath, 'utf8');
  } catch {
    return null;
  }
  for (const line of text.split('\n')) {
    // Top level only. A `private_key:` indented under peers: is not this
    // host's key, and reading one would sign with something else's name.
    if (!line.startsWith('private_key:')) continue;
    const v = line.slice('private_key:'.length).trim().replace(/^["']|["']$/g, '');
    return v === '' ? null : v;
  }
  return null;
}

/**
 * This host's own fleet trust PUBLIC key, derived from the seed it holds.
 *
 * Needed in two places phase 3 adds, and neither can be served from the
 * private half: the pairing welcome carries this key (a node that has never
 * met this aggregator has no other anchor for it), and the Settings page
 * shows its fingerprint so the operator holds both halves of the comparison
 * the node asks them to make.
 *
 * Derived rather than stored, so it cannot disagree with what actually
 * signs. Null on a host with no key, a key that is not 32 bytes, or a line
 * that is not base64url at all: every way this can fail is the same answer,
 * because a caller that gets a key here is about to hand it to another
 * machine as this aggregator's identity.
 */
export function readOwnPublicKey(fleetTrustPath: string): string | null {
  const seed = readOwnPrivateKey(fleetTrustPath);
  if (!seed) return null;
  try {
    const raw = fromB64url(seed);
    if (raw.length !== 32) return null;
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), raw]);
    const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    const spki = createPublicKey(key).export({ format: 'der', type: 'spki' });
    return b64url(spki.subarray(-32));
  } catch {
    return null;
  }
}

export { b64url, fromB64url };
