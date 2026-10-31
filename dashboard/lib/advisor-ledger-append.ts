/**
 * The aggregator's side of the Advisor append surface (#455).
 *
 * Two acts on the Settings page are done TO a node rather than through it:
 * its link is revoked (#444), and the node key this fleet pins for it is
 * replaced (#422). Both already write a `fleet_pairing` row to the operator
 * audit here. This module is the other half of the record: a copy on the
 * node's own hash-chained Advisor ledger, so an operator reading the Advisor
 * tab's Audit trail on that node finds what was done to it, named and
 * attributed, instead of a trust set that changed with nothing to say why.
 *
 * WHAT IS LOAD-BEARING HERE: `fleetRecordSigningBytes` must be byte-identical
 * to the Go twin, `Record.SigningBytes()` in advisor/internal/fleetrecord/
 * record.go, or the signature will not verify on the node and the failure
 * reads as a broken passkey. Both sides are pinned to the same two shared
 * vectors, in the tests beside them.
 *
 * NOT A NEW SIGNING SCHEME, deliberately. The record is signed with the same
 * key, the same encoding and the same helper the trust bundle and the
 * knowledge bundle are signed with: this host's Ed25519 seed from
 * fleet-trust.yaml, through `signWithSeed`. A node verifies it against the
 * key it already holds for this aggregator under `peers.<issuer_label>`, so
 * nothing new had to be distributed for this to work, and there is one
 * scheme to get right rather than two.
 *
 * THE SUMMARY IS NOT HERE. advisord composes the ledger's sentence from the
 * kind and the fields. This module cannot write prose into a node's record,
 * and that is the property the whole surface exists to have.
 */
import { randomBytes } from 'node:crypto';
import { readOwnPrivateKey, signWithSeed } from './trust-bundle.js';
import { appendPeerFleetRecord } from './peer-advisor-proxy.js';
import type { FleetNodeConfig } from './fleet-registry.js';
import type { AdvisorPresenceState } from './advisor-presence.js';

/** The label a node looks up in ITS fleet-trust.yaml `peers:` block to find
 *  the key that signed this. The same literal every push from this
 *  aggregator already stamps, and the same reason it is a literal rather
 *  than this host's fleet label: it has to match what the trust push wrote. */
export const FLEET_RECORD_ISSUER_LABEL = 'aggregator';

/** The literal label a node's own advisord checks FIRST and resolves out of
 *  ITS OWN signing seed, never out of peers (#477): the aggregator's second
 *  copy of an act it did to a node, appended to its own advisord over
 *  loopback rather than to that node's. */
export const FLEET_RECORD_ISSUER_SELF = 'self';

/** The closed set. A new kind is a change to the Go twin first. */
export type FleetRecordKind =
  | 'fleet.link_revoked' | 'fleet.node_key_repinned'
  | 'fleet.advisor_attached' | 'fleet.advisor_detached';

/** The kinds that carry ONE key rather than the pair a re-pin carries.
 *  Named once, because buildFleetRecord's branch and the Go twin's
 *  validateFields branch are the same rule stated in two languages. */
const SINGLE_KEY_KINDS: ReadonlySet<string> = new Set<FleetRecordKind>([
  'fleet.link_revoked', 'fleet.advisor_attached', 'fleet.advisor_detached',
]);

/** What a revoke carries in place of a node key when the row pinned none.
 *  The same word the Go side accepts, and a word rather than a key by
 *  construction, so it can never be read back as a key that was pinned. */
export const RECORD_UNPINNED = 'unpinned';

/**
 * One record, exactly as it goes on the wire.
 *
 * Field ORDER is the signature's order. Optional members are omitted rather
 * than sent empty, because Go's omitempty drops them entirely and a
 * `"role":""` on this side signs to different bytes than the node computes.
 */
export interface FleetRecord {
  kind: FleetRecordKind;
  node: string;
  operator: string;
  role?: string;
  credential_id?: string;
  origin?: string;
  /** The single-key kinds: fleet.link_revoked, fleet.advisor_attached and
   *  fleet.advisor_detached. */
  pubkey_node?: string;
  /** fleet.node_key_repinned only. */
  was_pubkey_node?: string;
  now_pubkey_node?: string;
  record_id: string;
  issued_at: string;
  issuer_label: string;
}

/**
 * The canonical bytes both sides sign and verify.
 *
 * A hand-built object in declaration order (V8 preserves string-key
 * insertion order, which is what makes JSON.stringify deterministic here),
 * with every absent member left out rather than set to undefined. The Go
 * twin marshals the same order with SetEscapeHTML(false) so the two agree on
 * an origin carrying &, < or >.
 */
export function fleetRecordSigningBytes(r: FleetRecord): string {
  const ordered: Record<string, string> = { kind: r.kind, node: r.node, operator: r.operator };
  const put = (k: string, v: string | undefined): void => { if (v) ordered[k] = v; };
  put('role', r.role);
  put('credential_id', r.credential_id);
  put('origin', r.origin);
  put('pubkey_node', r.pubkey_node);
  put('was_pubkey_node', r.was_pubkey_node);
  put('now_pubkey_node', r.now_pubkey_node);
  ordered.record_id = r.record_id;
  ordered.issued_at = r.issued_at;
  ordered.issuer_label = r.issuer_label;
  return JSON.stringify(ordered);
}

/** A record id, and the node's replay guard. Random rather than derived from
 *  the label: two revokes of the same node months apart are two acts, and an
 *  id that collided would make the second one read as a retry of the first
 *  and go unrecorded. */
export function mintRecordId(): string {
  return randomBytes(16).toString('base64url');
}

export interface FleetRecordFacts {
  node: string;
  operator: string;
  role?: string;
  credentialId?: string;
  origin?: string;
  /** The key a revoke took with it, null on a row that pinned none. */
  pubkeyNode?: string | null;
  /** The pair a re-pin replaced. */
  wasPubkeyNode?: string;
  nowPubkeyNode?: string;
}

/** Builds the record for one act. The time and the id are minted here, so a
 *  caller cannot choose either. */
export function buildFleetRecord(
  kind: FleetRecordKind, facts: FleetRecordFacts, now: Date = new Date(),
): FleetRecord {
  const base = {
    kind,
    node: facts.node,
    operator: facts.operator,
    ...(facts.role ? { role: facts.role } : {}),
    ...(facts.credentialId ? { credential_id: facts.credentialId } : {}),
    ...(facts.origin ? { origin: facts.origin } : {}),
  };
  const tail = {
    record_id: mintRecordId(),
    issued_at: now.toISOString().replace(/\.\d+Z$/, 'Z'),
    issuer_label: FLEET_RECORD_ISSUER_LABEL,
  };
  if (SINGLE_KEY_KINDS.has(kind)) {
    // `unpinned` is the fallback for a revoke and a detach, both of which
    // are reachable on a row that pins nothing. An attach is not: the route
    // refuses an unpinned row before it asks the node anything, so a
    // `pubkeyNode` missing here would be a bug, and the Go twin refuses the
    // record rather than writing that word into a node's permanent chain.
    return { ...base, pubkey_node: facts.pubkeyNode || RECORD_UNPINNED, ...tail } as FleetRecord;
  }
  return {
    ...base,
    was_pubkey_node: facts.wasPubkeyNode ?? '',
    now_pubkey_node: facts.nowPubkeyNode ?? '',
    ...tail,
  } as FleetRecord;
}

/**
 * Why an append did not happen, in the three shapes that mean different
 * things to an operator.
 *
 * `no_advisor` is ADR 0016's observation carried to a peer: the node's
 * registry row names no advisor_origin, so there is no Advisor on that host
 * to hold a copy, and saying anything else would be this dashboard reporting
 * a fact it never observed. `unreachable` is an Advisor that exists and did
 * not answer. `pin_mismatch` is the node reporting a key this fleet does not
 * pin, which is not exotic on a revoke: a rebuilt node is the common reason
 * to revoke one.
 */
export type FleetRecordFailure =
  | 'no_advisor' | 'not_an_aggregator' | 'pin_mismatch' | 'unreachable' | 'refused' | 'too_old';

export type FleetRecordOutcome =
  | { ok: true; seq: number; hash: string; duplicate: boolean }
  | { ok: false; reason: FleetRecordFailure; detail: string };

export interface AppendFleetRecordOpts {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  now?: Date;
  /** Read per call, never cached, never logged, never returned to a browser,
   *  exactly as lib/fleet-seal.ts reads it for a seal job. Injectable so a
   *  test signs with a key it generated rather than with a host's. */
  readSeed?: (fleetTrustPath: string) => string | null;
  /**
   * A record already built for this act, reused rather than building a new
   * one here (and therefore minting a new record_id).
   *
   * Exists for exactly one caller: the aggregator's own copy of an act it did
   * to a node (#477) has to carry the SAME record_id as the copy sent to that
   * node, because it is one act told twice, not two acts. Every other caller
   * leaves this absent and a record is built here as before, from kind,
   * facts and now. appendOwnFleetRecord below takes the built record
   * directly rather than kind/facts at all, so there is no id-shaped
   * parameter anywhere a caller of THAT function could set. The property
   * this module exists to keep is on the function that only ever derives a
   * self copy, not on this shared option.
   */
  record?: FleetRecord;
}

/**
 * Sign one record and append it to one node's Advisor ledger.
 *
 * NEVER THROWS, and that is the contract the callers depend on: the ledger
 * copy is a step that may fail without undoing the act it describes. The
 * operator audit row is the record of the act; this is a copy on the node.
 */
export async function appendFleetRecord(
  node: FleetNodeConfig,
  fleetTrustPath: string,
  kind: FleetRecordKind,
  facts: FleetRecordFacts,
  opts: AppendFleetRecordOpts = {},
): Promise<FleetRecordOutcome> {
  if (!node.advisor_origin || !node.advisor_token_path) {
    return {
      ok: false, reason: 'no_advisor',
      detail: `“${node.label}” has no Advisor for this dashboard to write to, so nothing was recorded there.`,
    };
  }
  const seed = (opts.readSeed ?? readOwnPrivateKey)(fleetTrustPath);
  if (!seed) {
    return {
      ok: false, reason: 'not_an_aggregator',
      detail: 'this host holds no fleet signing key, so a node would refuse an entry it sent.',
    };
  }
  let record: FleetRecord;
  let signature: string;
  try {
    record = opts.record ?? buildFleetRecord(kind, facts, opts.now);
    signature = signWithSeed(fleetRecordSigningBytes(record), seed);
  } catch (err) {
    return {
      ok: false, reason: 'not_an_aggregator',
      detail: `this host could not sign the entry (${(err as Error).name}).`,
    };
  }
  const answer = await appendPeerFleetRecord(node, { record, signature }, {
    fetchImpl: opts.fetchImpl, timeoutMs: opts.timeoutMs,
  });
  if (answer.ok) {
    const body = (answer.body ?? {}) as Record<string, unknown>;
    return {
      ok: true,
      seq: Number(body.seq ?? 0),
      hash: typeof body.hash === 'string' ? body.hash : '',
      duplicate: body.duplicate === true,
    };
  }
  if (answer.error === 'advisor_not_configured') {
    return {
      ok: false, reason: 'no_advisor',
      detail: `“${node.label}” has no Advisor for this dashboard to write to, so nothing was recorded there.`,
    };
  }
  if (answer.error === 'peer_integrity_mismatch') {
    return {
      ok: false, reason: 'pin_mismatch',
      detail: `“${node.label}” reports a node key this fleet does not pin, so this dashboard would not talk `
        + 'to its Advisor and nothing was recorded there.',
    };
  }
  if (answer.error === 'advisor_not_found') {
    // The node's Advisor answered and has no such route: it runs a build
    // from before this surface existed. Named rather than folded into
    // "unreachable", because the thing to do about it is update that node.
    return {
      ok: false, reason: 'too_old',
      detail: `“${node.label}” runs an Advisor from before this was recorded on the node, so it has no `
        + 'place to keep a copy. Update that node to record acts like this one on it.',
    };
  }
  if (answer.error === 'advisor_refused') {
    return {
      ok: false, reason: 'refused',
      detail: `“${node.label}” refused the entry: ${answer.detail ?? 'it gave no reason'}`,
    };
  }
  return {
    ok: false, reason: 'unreachable',
    // #1209: a token this host could not read is not a node that did not
    // answer; the proxy's sentence names the file and what was not sent.
    detail: answer.error === 'token_unreadable' && answer.detail
      ? `${answer.detail.replace(/[.\s]+$/, '')}, so its Advisor has no copy of this.`
      : `“${node.label}” did not answer, so its Advisor has no copy of this.`,
  };
}

/** This host's own advisord, over loopback, at the same 10s budget a peer
 *  read gets. Not exported: the one caller is appendOwnFleetRecord below. */
const OWN_ADVISOR_TIMEOUT_MS = 10_000;

/** The `error` string out of advisord's own reply, when it sent one. The twin
 *  of peer-advisor-proxy.ts's peerWords, kept here rather than imported so
 *  this module never has to import a peer-shaped type for its one caller
 *  that is not a peer at all. */
function ownAdvisorWords(text: string): string {
  try {
    const parsed = JSON.parse(text) as { error?: unknown };
    return typeof parsed.error === 'string' ? parsed.error : '';
  } catch {
    return '';
  }
}

/**
 * The aggregator's OWN copy of an act it did to a node (#477): the SAME
 * signed record, re-signed with `issuer_label` overridden to "self", posted
 * to THIS host's own co-located advisord over loopback rather than to a
 * peer's.
 *
 * NOT a peer call: there is no FleetNodeConfig here, no pin to verify (the
 * loopback origin IS this host, not a tunnel to somewhere else), and no
 * PEER_ADVISOR_* allow-list involved. It is the same trust boundary
 * settings-api.ts's trust-sync read-back already crosses with
 * deps.advisorUrl / deps.advisorToken, used the same way here.
 *
 * `record` is the FULL record already built and sent to the node, not
 * facts and not a kind: this function has no id-shaped parameter at all, so
 * there is nothing here a caller could set to give the two copies of one act
 * different record_ids. The only field this function changes is
 * issuer_label, and it re-signs because issuer_label is inside the signature.
 *
 * NEVER THROWS, exactly like appendFleetRecord: this is a copy that may fail
 * without undoing the act it describes, attempted whether or not the node's
 * own copy landed.
 *
 * `presence` is ADR 0016's observation, carried in rather than probed here:
 * `absent` means no Advisor was ever installed on this host, which is not an
 * error and is reported as `no_advisor` (ADR 0016 §"one observed fact"); a
 * host that has one but did not just answer is `unreachable`, the same as a
 * peer that did not answer. The two are different facts and this module
 * does not blur them, which is the exact bug class ADR 0016 exists to close
 * (#113). But `presence` is a POLLER's memory, sampled on its own cycle, and
 * it starts at `absent` before that cycle has ever run, so a call made right
 * after a restart could read a genuinely-installed Advisor as never having
 * existed: #113 again, one layer out. `advisorToken` is read fresh from the
 * file on every call with no poller in between, so `absent` is trusted only
 * when the token is ALSO unreadable; a readable token overrides a stale
 * `absent` and this proceeds to attempt the write.
 */
export async function appendOwnFleetRecord(
  fleetTrustPath: string,
  record: FleetRecord,
  presence: AdvisorPresenceState,
  advisorUrl: string | null,
  advisorToken: string | null,
  opts: AppendFleetRecordOpts = {},
): Promise<FleetRecordOutcome> {
  // presence is the POLLER's memory, sampled on its own cycle, and a caller
  // may ask right after a restart, before the first cycle has run: server.ts
  // starts that memory at 'absent' before anything is observed. Reporting
  // 'absent' on that alone would be #113 moved one layer out, an Advisor
  // that is genuinely there read as never having existed. advisorToken is
  // read fresh from the file on every call, with no poller in between, so
  // when it IS readable that is the file-level fact overriding a stale
  // memory that has not caught up yet, and this falls through to attempt
  // the write rather than refusing on a snapshot already known to be wrong.
  if (presence === 'absent' && !advisorToken) {
    return {
      ok: false, reason: 'no_advisor',
      detail: 'this aggregator has no Advisor of its own, so there is no second copy for it to hold.',
    };
  }
  if (!advisorUrl || !advisorToken) {
    return {
      ok: false, reason: 'unreachable',
      detail: 'this aggregator’s own Advisor did not answer, so it holds no copy of this.',
    };
  }
  const seed = (opts.readSeed ?? readOwnPrivateKey)(fleetTrustPath);
  if (!seed) {
    return {
      ok: false, reason: 'not_an_aggregator',
      detail: 'this host holds no fleet signing key, so its own Advisor would refuse an entry it sent itself.',
    };
  }
  const selfRecord: FleetRecord = { ...record, issuer_label: FLEET_RECORD_ISSUER_SELF };
  let signature: string;
  try {
    signature = signWithSeed(fleetRecordSigningBytes(selfRecord), seed);
  } catch (err) {
    return {
      ok: false, reason: 'not_an_aggregator',
      detail: `this host could not sign its own copy (${(err as Error).name}).`,
    };
  }
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? OWN_ADVISOR_TIMEOUT_MS;
  try {
    const r = await doFetch(`${advisorUrl.replace(/\/+$/, '')}/v1/fleet/record`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${advisorToken}` },
      body: JSON.stringify({ record: selfRecord, signature }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await r.text();
    // 401 is the ONE cause that is really "rejected its token": the bearer
    // gate at the door, checked before anything about the record is read.
    // 403 is everything #477 added to the self path: no private_key in
    // fleet-trust.yaml, one that is empty, not base64url or the wrong
    // length, or a signature that does not verify. Folding those into "bad
    // token" sent an operator with a truncated seed to the one file that was
    // fine. advisord's own words on a 403 name the real cause, and they
    // carry only a byte count or a path, never key material, so reading them
    // back here adds nothing that was not already safe to log.
    if (r.status === 401) {
      return {
        ok: false, reason: 'refused',
        detail: `this aggregator’s own Advisor rejected its token (HTTP ${r.status}).`,
      };
    }
    if (r.status === 403) {
      const words = ownAdvisorWords(text);
      return {
        ok: false, reason: 'refused',
        detail: words || `this aggregator’s own Advisor refused the entry (HTTP ${r.status}).`,
      };
    }
    if (r.status === 404) {
      return {
        ok: false, reason: 'too_old',
        detail: 'this aggregator runs an Advisor from before this was recorded on it. Update it to keep '
          + 'a copy of acts like this one.',
      };
    }
    if ((r.status >= 400 && r.status < 500) || r.status === 501) {
      const words = ownAdvisorWords(text);
      return {
        ok: false, reason: 'refused',
        detail: words || `this aggregator’s own Advisor refused the entry (HTTP ${r.status}).`,
      };
    }
    if (!r.ok) {
      return {
        ok: false, reason: 'unreachable',
        detail: 'this aggregator’s own Advisor did not answer, so it holds no copy of this.',
      };
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    return {
      ok: true,
      seq: Number(body.seq ?? 0),
      hash: typeof body.hash === 'string' ? body.hash : '',
      duplicate: body.duplicate === true,
    };
  } catch {
    return {
      ok: false, reason: 'unreachable',
      detail: 'this aggregator’s own Advisor did not answer, so it holds no copy of this.',
    };
  }
}

/** One line for the answer the page renders, and for the audit detail. */
export function describeFleetRecord(outcome: FleetRecordOutcome): string {
  if (outcome.ok) {
    return outcome.duplicate
      ? 'its Advisor already held this entry'
      : `recorded on its Advisor ledger at entry ${outcome.seq}`;
  }
  return outcome.detail;
}
