/**
 * The fleet-write gate, the node's side of a seal.
 *
 * A node dashboard serves two routes under /fleet/v1/ so the operator's own
 * aggregator can change this host's Advisor model key without anyone opening
 * this host's dashboard. Everything about the ordering below is the security
 * property, exactly as lib/read-api.ts says of its own, so it is here as pure
 * decision logic and each step is asserted in test/unit/fleet-write-api.ts:
 * every gate refuses BEFORE the next one runs, and every one of them refuses
 * before the sealer is called at all.
 *
 * A COPY of read-api.ts's shape, deliberately not a share of it. The two
 * surfaces must stay separate sets: one is read, gated by a token; the other
 * writes a credential to a root program, gated by that token AND by a
 * signature from a machine this node has pinned AND by a root arming window
 * no dashboard can open. Sharing the gate would mean one edit could widen
 * both, and a "small" widening of the read surface is not the same act as a
 * small widening of this one.
 *
 * One deliberate divergence from read-api.ts's order, and it is the reverse
 * of what a tidy-up would do. There, the bearer token is checked LAST, after
 * the route is known, because an unauthenticated reader learning that
 * /read/v1/agreement exists tells them nothing. Here the token is checked
 * BEFORE the path is looked at: this surface's route names are the names of
 * things that write, and a caller who cannot present the node's read token
 * gets 401 whatever they asked for. The test pins that with the one case
 * that can tell the two orders apart (a bad token on an unknown path is 401,
 * not 404), because otherwise a later "make it match read-api" passes.
 *
 * What is NOT gated here, and must not be: the arm token. The dashboard does
 * not verify it, cannot mint one, and holds no key that could. It carries an
 * opaque blob from root on the aggregator to root on this host, which is the
 * whole reason arming survives a compromised dashboard on either end.
 */

import { timingSafeEqual, createHash } from 'node:crypto';
import { readBody } from './read-body.js';
import { readFileSync, writeFileSync, renameSync, mkdirSync, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
import type { IncomingMessage } from 'node:http';
import {
  FLEET_WRITE_PROTOCOL_VERSION, FLEET_WRITE_ROUTE_NAMES, FLEET_WRITE_ROUTE_METHODS,
  FLEET_WRITE_FRESHNESS_S, FLEET_WRITE_NONCE_TTL_S, FLEET_WRITE_NONCE_CAP, FLEET_WRITE_MAX_BODY_BYTES,
  FLEET_WRITE_ISSUER_LABEL,
  sealJobSigningBytes, sealKeyHash, updateJobSigningBytes, advisorRevealJobSigningBytes,
  type FleetWriteRouteName, type FleetWriteErrorBody, type SealJob, type SealShape,
  type ArmSealResponse, type UpdateJob, type UpdateApplyJob, type UpdateRestartJob,
  type AdvisorRevealJob, type AdvisorRevealResponse, type AdvisorStateResponse,
} from '../types/fleet-write-contract.js';
import { verifyWithPeerKey } from './trust-bundle.js';
import { SEAL_FIELD_RULES } from './model-seal.js';
import { UPDATE_FIELD_RULES } from './update-apply.js';

const ROUTE_SET: ReadonlySet<string> = new Set(FLEET_WRITE_ROUTE_NAMES);

/** /fleet/v<N>/<noun>/<verb>. Two segments, both closed character classes,
 *  so nothing shaped like a traversal or a URL reaches the membership test. */
const FLEET_WRITE_PATH_RE = /^\/fleet\/v(\d{1,3})\/([a-z]{1,20}\/[a-z]{1,20})$/;

export function isFleetWritePath(pathname: string): boolean {
  return pathname === '/fleet' || pathname.startsWith('/fleet/');
}

function isLoopback(remoteAddress: string | undefined): boolean {
  if (!remoteAddress) return false;
  return remoteAddress === '127.0.0.1'
      || remoteAddress === '::1'
      || remoteAddress === '::ffff:127.0.0.1';
}

/** Constant-time equality over hashes, so unequal lengths leak nothing.
 *  The same comparison read-api.ts makes, and the same reason. */
function tokenMatches(presented: string, expected: string): boolean {
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export type FleetWriteGateDecision =
  | { ok: true; route: FleetWriteRouteName; method: string }
  | { ok: false; status: number; body: FleetWriteErrorBody };

export interface FleetWriteGateInput {
  method: string;
  pathname: string;
  remoteAddress: string | undefined;
  /** The Authorization header, verbatim (or undefined). */
  authorization: string | undefined;
  /** The node's OWN read token as read from disk for this request, null when
   *  the file is absent or unreadable. Same token /read/v1/* takes, read the
   *  same way, per request, so a rotation needs no restart. */
  expectedToken: string | null;
}

/** Gates 1 to 3: the transport. Everything about WHO is asking and WHAT they
 *  asked for, and nothing about the job itself. */
export function gateFleetWrite(input: FleetWriteGateInput): FleetWriteGateDecision {
  const err = (status: number, body: FleetWriteErrorBody): FleetWriteGateDecision =>
    ({ ok: false, status, body });

  // 1. The socket first. A header is forgeable; the remote address of the
  //    accepted connection is not. A caller who is not on this host has
  //    nothing evaluated for them, including whether their token was good.
  if (!isLoopback(input.remoteAddress)) {
    return err(403, { error: 'not_loopback' });
  }

  // 2. No token on disk means the read surface is off, and this surface
  //    rides on it. Named as disabled rather than as wrong credentials: a
  //    host in that state needs its install looked at, not its token.
  if (input.expectedToken === null || input.expectedToken.length < 32) {
    return err(403, {
      error: 'fleet_write_disabled',
      detail: 'this node has no read token, so it accepts nothing from a fleet aggregator',
    });
  }
  const presented = (input.authorization ?? '').replace(/^Bearer\s+/i, '');
  if (!presented || !tokenMatches(presented, input.expectedToken)) {
    return err(401, { error: 'bad_token' });
  }

  // 3. The method, the path and the version. The method is checked against
  //    the union first so a PUT is 405 rather than 404, and against the
  //    route's own row last, once there is a route to ask about.
  if (input.method !== 'POST' && input.method !== 'GET') {
    return err(405, { error: 'method_not_allowed' });
  }
  const m = FLEET_WRITE_PATH_RE.exec(input.pathname);
  if (!m) {
    return err(404, { error: 'unknown_fleet_write_path' });
  }
  const version = Number(m[1]);
  if (version !== FLEET_WRITE_PROTOCOL_VERSION) {
    // Named, never silent, the same divergence from the relay contract that
    // ADR 0008 decision 4 chose for the read surface.
    return err(400, {
      error: 'protocol_version_unsupported',
      server_version: FLEET_WRITE_PROTOCOL_VERSION,
      requested_version: version,
    });
  }
  const route = m[2];
  if (!ROUTE_SET.has(route)) {
    return err(404, { error: 'unknown_fleet_write_path' });
  }
  const named = route as FleetWriteRouteName;
  if (!FLEET_WRITE_ROUTE_METHODS[named].includes(input.method)) {
    return err(405, { error: 'method_not_allowed' });
  }
  return { ok: true, route: named, method: input.method };
}

// ── Which work an admitted request causes ────────────────────────────────
//
// The gate above answers "may this request be served". This answers "by
// what", and it is a separate question with a separate failure mode.
//
// It exists because the mount block used to answer it by falling through
// (#319): `model/arm` had two explicit branches and everything else reached
// the seal, so a route name added to FLEET_WRITE_ROUTE_NAMES without a
// branch would have been handled as a model seal — the most privileged verb
// on this surface. A route arriving with no work is a refusal here, by name.
//
// The lookup is PARTIAL on purpose. Typed as a total Record the compiler
// would catch a missing name, the refusal below would be dead code, and no
// test could drive it; the contract and the build that serves it are
// deployed together but they are not the same artefact, and a node running
// an older build than the aggregator's contract is exactly the case this
// answers. Exhaustiveness belongs on the other side of the pair: the mount
// block switches over FleetWriteWork, so a work token with no branch is a
// compile error there.

/** What a served fleet-write request makes this node do. One token per
 *  distinct act, never per route, because `model/arm` is two acts. */
export type FleetWriteWork =
  | 'arm-state' | 'arm-token' | 'model-seal'
  | 'update-state' | 'update-apply' | 'update-restart'
  | 'advisor-state' | 'advisor-reveal';

const FLEET_WRITE_WORK: Partial<Record<FleetWriteRouteName, Partial<Record<string, FleetWriteWork>>>> = {
  'model/arm': { GET: 'arm-state', POST: 'arm-token' },
  'model/seal': { POST: 'model-seal' },
  'update/state': { GET: 'update-state' },
  'update/apply': { POST: 'update-apply' },
  'update/restart': { POST: 'update-restart' },
  'advisor/state': { GET: 'advisor-state' },
  'advisor/reveal': { POST: 'advisor-reveal' },
};

export type FleetWriteWorkDecision =
  | { ok: true; work: FleetWriteWork }
  | { ok: false; status: number; body: FleetWriteErrorBody };

/**
 * The work, or a named refusal.
 *
 * 500 and not 404: the caller asked for a route this contract names, so the
 * fault is on this side. The detail is written to be rendered — the
 * aggregator prints a peer's `detail` verbatim (lib/fleet-seal.ts's refusal
 * branch), so this sentence is the one an operator reads, and it names the
 * thing to act on rather than describing a dispatch table.
 */
export function fleetWriteWork(route: FleetWriteRouteName, method: string): FleetWriteWorkDecision {
  const work = FLEET_WRITE_WORK[route]?.[method];
  if (!work) {
    return {
      ok: false,
      status: 500,
      body: {
        error: 'no_handler',
        detail: `that node's dashboard names ${route} but serves nothing for it; it runs a build older than that route`,
      },
    };
  }
  return { ok: true, work };
}

// ── The nonce store, gate 7's half of it ─────────────────────────────────
//
// A signed job is a bearer instrument for as long as it is fresh: whoever
// holds the bytes can replay them. Freshness bounds that to five minutes and
// the nonce closes it entirely, but only if the claim is atomic. Two copies
// of the same job arriving together must not both find the nonce unseen, so
// the check and the record are ONE call, made synchronously, before anything
// touches the sealer.

export type NonceClaim = 'fresh' | 'replay' | 'unreadable' | 'full';

export interface NonceStore {
  /** Record this nonce if it has not been seen, and say which happened.
   *  `unreadable` is a refusal, never an admission: a store this host cannot
   *  read is a host that cannot tell a replay from a first delivery, and a
   *  seal spends an arming window and writes a credential. */
  claim(nonce: string, nowMs: number): NonceClaim;
}

/** Drop everything older than the TTL. Pure, so the pruning rule is testable
 *  without a filesystem. Twice the freshness window, so nothing can age out
 *  of the record while it is still fresh enough to be accepted. */
export function pruneNonces(seen: Record<string, number>, nowS: number): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [nonce, at] of Object.entries(seen)) {
    if (typeof at === 'number' && Number.isFinite(at) && nowS - at <= FLEET_WRITE_NONCE_TTL_S) {
      out[nonce] = at;
    }
  }
  return out;
}

/** The claim itself, pure: the answer plus the record to write back. A full
 *  record refuses rather than evicting: dropping the oldest entry would
 *  reopen the replay window for a job still fresh enough to be accepted, and
 *  the pruned record is written back so the cost stays bounded either way. */
export function claimNonce(
  seen: Record<string, number>, nonce: string, nowS: number,
): { claim: 'fresh' | 'replay' | 'full'; next: Record<string, number> } {
  const pruned = pruneNonces(seen, nowS);
  if (Object.prototype.hasOwnProperty.call(pruned, nonce)) {
    return { claim: 'replay', next: pruned };
  }
  if (Object.keys(pruned).length >= FLEET_WRITE_NONCE_CAP) {
    return { claim: 'full', next: pruned };
  }
  return { claim: 'fresh', next: { ...pruned, [nonce]: nowS } };
}

/**
 * The store on disk, under data/ because that is the one directory this
 * account may write. Written temp-then-rename: a truncated file would read
 * as an empty record on the next request, which would reopen the replay
 * window for every job already spent.
 */
export function fileNonceStore(path: string): NonceStore {
  return {
    claim(nonce: string, nowMs: number): NonceClaim {
      const nowS = Math.floor(nowMs / 1000);
      let seen: Record<string, number> = {};
      try {
        const raw = readFileSync(path, 'utf8');
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'unreadable';
        seen = parsed as Record<string, number>;
      } catch (err) {
        // Absent is the ordinary first-ever state and means nothing has been
        // seen. Anything else (unreadable, corrupt, not an object) refuses.
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') return 'unreadable';
      }
      const { claim, next } = claimNonce(seen, nonce, nowS);
      if (claim === 'replay') return 'replay';
      try {
        mkdirSync(dirname(path), { recursive: true });
        const tmp = `${path}.tmp`;
        writeFileSync(tmp, JSON.stringify(next), { mode: 0o600 });
        renameSync(tmp, path);
      } catch {
        // Could not record it, so it cannot be refused next time either.
        // Refusing here is the only honest answer: admitting a job this host
        // will not remember is admitting the same job forever.
        return 'unreadable';
      }
      // Written back even when full, so the record on disk is the pruned one
      // and the next request pays for the entries still alive, not for
      // everything that was ever sent.
      return claim;
    },
  };
}

// ── Gates 4 to 8: the job ────────────────────────────────────────────────

export type JobDecision<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; body: FleetWriteErrorBody };

const NONCE_RE = /^[0-9a-f]{32}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

export interface SealJobCheckInput {
  /** The raw request body, already bounded by the caller. */
  body: string;
  /** This node's own pubkey_node, the value /read/v1/identity serves. Null
   *  when rippled has not answered yet, which refuses every job rather than
   *  matching one: a node that cannot say who it is cannot be told. */
  thisPubkeyNode: string | null;
  /** peers.<label> from THIS node's fleet-trust.yaml, or null. */
  peerKey: (issuerLabel: string) => string | null;
  nowMs: number;
  nonces: NonceStore;
}

/**
 * Gates 4 to 8, in order, each refusing before the next runs.
 *
 * Nothing here logs, throws or returns anything derived from the key except
 * the key itself to its one caller. The error paths are the dangerous ones:
 * an exception carrying the payload it failed on is how a secret ends up in
 * a log nobody meant to write, so a body that will not parse is refused with
 * a fixed sentence and the body is never named.
 */
export function checkSealJob(input: SealJobCheckInput): JobDecision<{ job: SealJob; key: string }> {
  const err = (status: number, body: FleetWriteErrorBody): JobDecision<never> =>
    ({ ok: false, status, body });
  const badJob = (detail: string) => err(400, { error: 'bad_job', detail });

  // 4. The body, and that it is the shape this route serves.
  if (Buffer.byteLength(input.body, 'utf8') > FLEET_WRITE_MAX_BODY_BYTES) {
    return badJob('the job is larger than this route accepts');
  }
  let parsed: { job?: unknown; signature?: unknown; key?: unknown };
  try {
    parsed = JSON.parse(input.body || '{}') as typeof parsed;
  } catch {
    return badJob('the job did not parse');
  }
  const job = parsed?.job as SealJob | undefined;
  const signature = typeof parsed?.signature === 'string' ? parsed.signature : '';
  // Stripped here, once, so this side hashes exactly what the aggregator
  // hashed and exactly what the sealer will receive.
  const key = typeof parsed?.key === 'string' ? parsed.key.replace(/\s/g, '') : '';
  if (!job || typeof job !== 'object') return badJob('the job is missing');
  if (job.v !== FLEET_WRITE_PROTOCOL_VERSION) return badJob('the job carries no supported version');
  if (job.kind !== 'model.seal') return badJob('that job is not a model seal');
  if (typeof job.issuer_label !== 'string' || !job.issuer_label) return badJob('the job names no issuer');
  if (typeof job.target_pubkey_node !== 'string' || !job.target_pubkey_node) return badJob('the job names no target node');
  if (typeof job.nonce !== 'string' || !NONCE_RE.test(job.nonce)) return badJob('the job carries no usable nonce');
  if (typeof job.issued_at !== 'number' || !Number.isFinite(job.issued_at)) return badJob('the job carries no issue time');
  if (typeof job.key_sha256 !== 'string' || !SHA256_RE.test(job.key_sha256)) return badJob('the job carries no usable key hash');
  if (job.shape !== 'openai' && job.shape !== 'anthropic') return badJob('the job names no known provider shape');
  for (const field of ['base_url', 'model', 'credential_name', 'granted_by', 'credential_id'] as const) {
    if (typeof job[field] !== 'string' || job[field] === '') return badJob(`the job carries no ${field}`);
  }
  // The same rules the aggregator applied before signing, applied again
  // here: this node frames the sealer's payload from these three, and it
  // does not take the frame on trust from the signer (#179).
  if (!SEAL_FIELD_RULES.baseUrl(job.base_url)) return badJob('the job\'s base_url is not an address the sealer takes');
  if (!SEAL_FIELD_RULES.model(job.model)) return badJob('the job\'s model is not a plain model identifier');
  if (!SEAL_FIELD_RULES.credentialName(job.credential_name)) return badJob('the job\'s credential_name is not a bare name');
  if (!signature) return badJob('the job carries no signature');
  if (!key) return badJob('the job carries no key');

  // 5. The right host. The aggregator holds one key and every node trusts
  //    it, so a good signature is not on its own an answer to "the right
  //    node": a fleet.yaml row pointing at the wrong forward would otherwise
  //    seal one node's key onto another.
  if (!input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: null,
      detail: 'this node cannot say what its own node key is yet, so it accepts no job addressed to one',
    });
  }
  if (job.target_pubkey_node !== input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: input.thisPubkeyNode,
      detail: 'that job is addressed to a different node',
    });
  }

  // 6. The pinned aggregator, then the signature over the contract's bytes.
  //    Pinned to FLEET_WRITE_ISSUER_LABEL itself, never to whatever label the
  //    job claims: today no writer of fleet-trust.yaml ever populates a
  //    second peers.<label> entry, so input.peerKey(job.issuer_label) and
  //    input.peerKey(FLEET_WRITE_ISSUER_LABEL) resolve the same either way,
  //    but that guarantee should not rest solely on every future writer of
  //    that file continuing to respect the one-label convention.
  if (job.issuer_label !== FLEET_WRITE_ISSUER_LABEL) {
    // expected_issuer and detail name the label this node looked for, never
    // the job's own claim: an unpinned label is untrusted input, and a
    // refusal is not the place to echo it back.
    return err(409, {
      error: 'no_aggregator_pinned', expected_issuer: FLEET_WRITE_ISSUER_LABEL,
      detail: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to change its model key`,
    });
  }
  const pub = input.peerKey(FLEET_WRITE_ISSUER_LABEL);
  if (!pub) {
    return err(409, {
      error: 'no_aggregator_pinned', expected_issuer: FLEET_WRITE_ISSUER_LABEL,
      detail: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to change its model key`,
    });
  }
  if (!verifyWithPeerKey(sealJobSigningBytes(job), signature, pub)) {
    return err(401, { error: 'bad_signature' });
  }

  // 7. Fresh, then unseen. Freshness first because it is free, and because a
  //    stale job should not consume a nonce slot.
  const skewS = Math.abs(Math.floor(input.nowMs / 1000) - job.issued_at);
  if (skewS > FLEET_WRITE_FRESHNESS_S) {
    return err(409, {
      error: 'stale_job',
      detail: `that job was issued ${skewS}s from this node's clock, and this node accepts ${FLEET_WRITE_FRESHNESS_S}s`,
    });
  }
  const claim = input.nonces.claim(job.nonce, input.nowMs);
  if (claim === 'replay') return err(409, { error: 'replayed_job' });
  if (claim === 'unreadable') {
    return err(409, {
      error: 'nonce_store_unreadable',
      detail: 'this node cannot read its own replay record, and will not seal a job it could not refuse a second time',
    });
  }
  if (claim === 'full') {
    return err(503, {
      error: 'nonce_store_full',
      detail: `this node is holding ${FLEET_WRITE_NONCE_CAP} recent job nonces and will not take another until some age out`,
    });
  }

  // 8. The key is the key that was signed for. Last, so a job that fails any
  //    of the above never had its key hashed at all.
  if (sealKeyHash(key) !== job.key_sha256) {
    return err(400, {
      error: 'key_hash_mismatch',
      detail: 'the key does not match the one this job was signed for',
    });
  }

  return { ok: true, value: { job, key } };
}

// ── Gates 4 to 7 for an update job ───────────────────────────────────────
//
// The same order as the seal's, minus gate 8: there is no key here, so there
// is no key hash to bind. That absence is the point rather than a
// simplification — an update job has no secret to leak at a boundary.
//
// A SEPARATE function from checkSealJob rather than a shared gate. The two
// surfaces authorise different acts (a credential reaching a root sealer,
// and a release reaching a root updater), and sharing the gate would mean
// one edit could widen both. The same reason lib/fleet-write-api.ts is a
// copy of read-api.ts's shape rather than a share of it.

const RUN_ID_RE = /^[0-9a-f]{8,64}$/;

export interface UpdateJobCheckInput {
  /** The raw request body, already bounded by the caller. */
  body: string;
  /** Which kind this ROUTE serves. A job of the other kind is refused here,
   *  so an apply can never arrive on the restart route and be verified as
   *  one: `kind` is inside the signature, and this makes the route agree
   *  with it rather than taking the body's word for what it is. */
  kind: UpdateJob['kind'];
  /** This node's own pubkey_node, the value /read/v1/identity serves. */
  thisPubkeyNode: string | null;
  /** peers.<label> from THIS node's fleet-trust.yaml, or null. */
  peerKey: (issuerLabel: string) => string | null;
  nowMs: number;
  nonces: NonceStore;
}

export function checkUpdateJob(input: UpdateJobCheckInput): JobDecision<{ job: UpdateJob }> {
  const err = (status: number, body: FleetWriteErrorBody): JobDecision<never> =>
    ({ ok: false, status, body });
  const badJob = (detail: string) => err(400, { error: 'bad_job', detail });

  // 4. The body, and that it is the shape this route serves.
  if (Buffer.byteLength(input.body, 'utf8') > FLEET_WRITE_MAX_BODY_BYTES) {
    return badJob('the job is larger than this route accepts');
  }
  let parsed: { job?: unknown; signature?: unknown };
  try {
    parsed = JSON.parse(input.body || '{}') as typeof parsed;
  } catch {
    return badJob('the job did not parse');
  }
  const job = parsed?.job as UpdateJob | undefined;
  const signature = typeof parsed?.signature === 'string' ? parsed.signature : '';
  if (!job || typeof job !== 'object') return badJob('the job is missing');
  if (job.v !== FLEET_WRITE_PROTOCOL_VERSION) return badJob('the job carries no supported version');
  if (job.kind !== input.kind) return badJob(`that job is not an ${input.kind.replace('update.', '')}`);
  if (typeof job.issuer_label !== 'string' || !job.issuer_label) return badJob('the job names no issuer');
  if (typeof job.target_pubkey_node !== 'string' || !job.target_pubkey_node) return badJob('the job names no target node');
  if (typeof job.nonce !== 'string' || !NONCE_RE.test(job.nonce)) return badJob('the job carries no usable nonce');
  if (typeof job.issued_at !== 'number' || !Number.isFinite(job.issued_at)) return badJob('the job carries no issue time');
  for (const field of ['granted_by', 'credential_id'] as const) {
    if (typeof job[field] !== 'string' || job[field] === '') return badJob(`the job carries no ${field}`);
  }
  if (job.kind === 'update.apply') {
    // The SAME three rules this node applies to a release its own page
    // offers. The frame for root's one line is built on this side and is
    // never taken on trust from the signer (#179): a value carrying
    // whitespace would be a second field nobody approved.
    const a = job as UpdateApplyJob;
    if (typeof a.tag !== 'string' || !UPDATE_FIELD_RULES.tag(a.tag)) return badJob('that does not look like a release tag');
    if (typeof a.commit !== 'string' || !UPDATE_FIELD_RULES.commit(a.commit)) return badJob('that does not look like a commit id');
    if (typeof a.sha256 !== 'string' || !UPDATE_FIELD_RULES.sha256(a.sha256)) return badJob('that does not look like a sha256');
  } else {
    const r = job as UpdateRestartJob;
    if (typeof r.run_id !== 'string' || !RUN_ID_RE.test(r.run_id)) return badJob('the job names no usable run');
  }
  if (!signature) return badJob('the job carries no signature');

  // 5. The right host. A fleet.yaml row pointing at the wrong forward would
  //    otherwise apply one node's release on another.
  if (!input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: null,
      detail: 'this node cannot say what its own node key is yet, so it accepts no job addressed to one',
    });
  }
  if (job.target_pubkey_node !== input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: input.thisPubkeyNode,
      detail: 'that job is addressed to a different node',
    });
  }

  // 6. The pinned aggregator, then the signature over the contract's bytes.
  //    Pinned to FLEET_WRITE_ISSUER_LABEL itself, never to whatever label the
  //    job claims; see checkSealJob's own gate 6 for why.
  if (job.issuer_label !== FLEET_WRITE_ISSUER_LABEL) {
    // expected_issuer and detail name the label this node looked for, never
    // the job's own claim; see checkSealJob's own gate 6 for why.
    return err(409, {
      error: 'no_aggregator_pinned', expected_issuer: FLEET_WRITE_ISSUER_LABEL,
      detail: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to update it`,
    });
  }
  const pub = input.peerKey(FLEET_WRITE_ISSUER_LABEL);
  if (!pub) {
    return err(409, {
      error: 'no_aggregator_pinned', expected_issuer: FLEET_WRITE_ISSUER_LABEL,
      detail: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to update it`,
    });
  }
  if (!verifyWithPeerKey(updateJobSigningBytes(job), signature, pub)) {
    return err(401, { error: 'bad_signature' });
  }

  // 7. Fresh, then unseen. Freshness first because it is free, and because a
  //    stale job should not consume a nonce slot.
  const skewS = Math.abs(Math.floor(input.nowMs / 1000) - job.issued_at);
  if (skewS > FLEET_WRITE_FRESHNESS_S) {
    return err(409, {
      error: 'stale_job',
      detail: `that job was issued ${skewS}s from this node's clock, and this node accepts ${FLEET_WRITE_FRESHNESS_S}s`,
    });
  }
  const claim = input.nonces.claim(job.nonce, input.nowMs);
  if (claim === 'replay') return err(409, { error: 'replayed_job' });
  if (claim === 'unreadable') {
    return err(409, {
      error: 'nonce_store_unreadable',
      detail: 'this node cannot read its own replay record, and will not start a run it could not refuse a second time',
    });
  }
  if (claim === 'full') {
    return err(503, {
      error: 'nonce_store_full',
      detail: `this node is holding ${FLEET_WRITE_NONCE_CAP} recent job nonces and will not take another until some age out`,
    });
  }

  return { ok: true, value: { job } };
}

// ── Gates 4 to 7 for an advisor reveal job ───────────────────────────────
//
// The same order and the same absence of gate 8 as an update job's: there is
// no key here either, so there is nothing to bind a hash against. This is
// its OWN function, not a shared gate with checkUpdateJob, for the same
// reason that one is not shared with checkSealJob: the three surfaces
// authorise different acts, and a shared gate is one edit away from
// widening all three at once.
//
// This function alone is never the whole answer for a reveal. It proves the
// job came from an aggregator this node already trusts; it says nothing
// about whether this node's own reveal window is open, which is checked
// separately (and only once this function has already said yes) by
// advisorRevealWindowOpen below, on facts this process reads for itself.

export interface AdvisorRevealJobCheckInput {
  /** The raw request body, already bounded by the caller. */
  body: string;
  /** This node's own pubkey_node, the value /read/v1/identity serves. */
  thisPubkeyNode: string | null;
  /** peers.<label> from THIS node's fleet-trust.yaml, or null. */
  peerKey: (issuerLabel: string) => string | null;
  nowMs: number;
  nonces: NonceStore;
}

export function checkAdvisorRevealJob(
  input: AdvisorRevealJobCheckInput,
): JobDecision<{ job: AdvisorRevealJob }> {
  const err = (status: number, body: FleetWriteErrorBody): JobDecision<never> =>
    ({ ok: false, status, body });
  const badJob = (detail: string) => err(400, { error: 'bad_job', detail });

  // 4. The body, and that it is the shape this route serves.
  if (Buffer.byteLength(input.body, 'utf8') > FLEET_WRITE_MAX_BODY_BYTES) {
    return badJob('the job is larger than this route accepts');
  }
  let parsed: { job?: unknown; signature?: unknown };
  try {
    parsed = JSON.parse(input.body || '{}') as typeof parsed;
  } catch {
    return badJob('the job did not parse');
  }
  const job = parsed?.job as AdvisorRevealJob | undefined;
  const signature = typeof parsed?.signature === 'string' ? parsed.signature : '';
  if (!job || typeof job !== 'object') return badJob('the job is missing');
  if (job.v !== FLEET_WRITE_PROTOCOL_VERSION) return badJob('the job carries no supported version');
  if (job.kind !== 'advisor.reveal') return badJob('that job is not an advisor reveal');
  if (typeof job.issuer_label !== 'string' || !job.issuer_label) return badJob('the job names no issuer');
  if (typeof job.target_pubkey_node !== 'string' || !job.target_pubkey_node) return badJob('the job names no target node');
  if (typeof job.nonce !== 'string' || !NONCE_RE.test(job.nonce)) return badJob('the job carries no usable nonce');
  if (typeof job.issued_at !== 'number' || !Number.isFinite(job.issued_at)) return badJob('the job carries no issue time');
  if (!signature) return badJob('the job carries no signature');

  // 5. The right host. A fleet.yaml row pointing at the wrong forward would
  //    otherwise reveal one node's token onto another's aggregator link.
  if (!input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: null,
      detail: 'this node cannot say what its own node key is yet, so it accepts no job addressed to one',
    });
  }
  if (job.target_pubkey_node !== input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: input.thisPubkeyNode,
      detail: 'that job is addressed to a different node',
    });
  }

  // 6. The pinned aggregator, then the signature over the contract's bytes.
  //    Pinned to FLEET_WRITE_ISSUER_LABEL itself, never to whatever label the
  //    job claims; see checkSealJob's own gate 6 for why.
  if (job.issuer_label !== FLEET_WRITE_ISSUER_LABEL) {
    // expected_issuer and detail name the label this node looked for, never
    // the job's own claim; see checkSealJob's own gate 6 for why.
    return err(409, {
      error: 'no_aggregator_pinned', expected_issuer: FLEET_WRITE_ISSUER_LABEL,
      detail: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to reveal its Advisor token`,
    });
  }
  const pub = input.peerKey(FLEET_WRITE_ISSUER_LABEL);
  if (!pub) {
    return err(409, {
      error: 'no_aggregator_pinned', expected_issuer: FLEET_WRITE_ISSUER_LABEL,
      detail: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to reveal its Advisor token`,
    });
  }
  if (!verifyWithPeerKey(advisorRevealJobSigningBytes(job), signature, pub)) {
    return err(401, { error: 'bad_signature' });
  }

  // 7. Fresh, then unseen. Freshness first because it is free, and because a
  //    stale job should not consume a nonce slot.
  const skewS = Math.abs(Math.floor(input.nowMs / 1000) - job.issued_at);
  if (skewS > FLEET_WRITE_FRESHNESS_S) {
    return err(409, {
      error: 'stale_job',
      detail: `that job was issued ${skewS}s from this node's clock, and this node accepts ${FLEET_WRITE_FRESHNESS_S}s`,
    });
  }
  const claim = input.nonces.claim(job.nonce, input.nowMs);
  if (claim === 'replay') return err(409, { error: 'replayed_job' });
  if (claim === 'unreadable') {
    return err(409, {
      error: 'nonce_store_unreadable',
      detail: 'this node cannot read its own replay record, and will not reveal a token it could not refuse a second time',
    });
  }
  if (claim === 'full') {
    return err(503, {
      error: 'nonce_store_full',
      detail: `this node is holding ${FLEET_WRITE_NONCE_CAP} recent job nonces and will not take another until some age out`,
    });
  }

  return { ok: true, value: { job } };
}

// ── The reveal window: a second, independent gate ────────────────────────
//
// A signed job proves an aggregator this node already trusts asked. It does
// not prove a human recently stood at THIS box with real sudo. A
// compromised aggregator can build and sign a job for any node it holds a
// live link to, since it legitimately holds the fleet-trust seed for other
// purposes. The window closes that gap the same way the aggregator's own
// arm window closes the matching one on the seal path: a program the
// dashboard could run to open its own window would be the same as no window
// at all, so root plants this marker (scripts/install-advisord.sh, under
// its existing sudo block) and this process only ever reads it.
//
// Read exactly as the broker's arm_guard reads its own marker: owned by
// root (never this account, and never the account the Advisor itself runs
// as), not group- or world-writable, and younger than its lifetime. A
// marker dated in the future is a clock that moved, and "I cannot tell how
// old this is" reads as too old, same as arm_guard's own comment says.
//
// One divergence from arm_guard worth naming rather than assuming away:
// arm_guard's own marker sits under /etc/aperire, root-owned end to end,
// where this one sits under advisor/state, a directory the account this
// window exists to keep out CAN write to. That account already reads
// approve.token directly, so a symlink swap here widens nothing it did not
// already have, but it could otherwise point reveal.window at some other
// root-owned, non-group-writable, constantly touched file and hold this
// check open indefinitely. Closed (#649) with a single lstatSync (never a
// stat that follows the link) plus an isRegularFile fact, checked before
// ownership or mode are asked at all: a symlink reads as 'not_a_file'
// regardless of what it points to, exactly the way arm_guard's own marker
// never needs this check in the first place, since /etc/aperire is not
// writable by anything this design does not already trust with root.
//
// A symlink is not the only way that account can alias this path to a file
// it does not own. A HARD link needs no symlink at all: `ln` (not `ln -s`)
// to some other regular file it already has one name for, root-owned or
// not, makes reveal.window and that other name the SAME inode. lstat on a
// hard link is indistinguishable from lstat on the file itself, so it
// reports that file's real uid, mode and mtime, exactly the facts a
// legitimate marker would carry; isRegularFile passes too, since a hard
// link is an ordinary regular file. Only nlink, the count of names pointing
// at that inode, differs: a marker install-advisord.sh planted has exactly
// one, its own. Closed with singleLinked, checked in the same lstatSync
// call, right alongside isRegularFile and before ownership or mode are
// asked, the same precondition this codebase already applies to a set
// member during a restore (scripts/aperire-restore.sh's validate_set
// refuses anything with `stat -c '%h' > 1`, for the identical reason: an
// account that can plant a name cannot forge how many names an inode has).
//
// The facts are read by readAdvisorRevealWindowFacts below, one lstatSync
// call, no separate stat: a second call would reopen the exact
// check-then-act race the single-call form avoids. advisorRevealWindowOpen
// stays pure over those facts, so the refusals and the one way it does not
// refuse are each a row over a fixed input, not a stat a test has to fake a
// filesystem for. server.ts's own call is a one-line wrapper around
// readAdvisorRevealWindowFacts, the same shape armState's marker read and
// advisorUnitInstalled already use for their own impure stats.

/** How long a planted reveal window stays open, seconds. The same fifteen
 *  minutes this codebase already reviewed and shipped for the aggregator's
 *  own model-key arm window (ARM_WINDOW_SEC, lib/model-arm.ts). */
export const ADVISOR_REVEAL_WINDOW_LIFETIME_S = 900;

export interface AdvisorRevealWindowFacts {
  /** Does the marker exist at all, under lstat (a dangling symlink still
   *  counts as existing here; it is refused on isRegularFile below, not
   *  folded into a missing marker, so the two causes are never confused in
   *  a test or in the wire detail). */
  exists: boolean;
  /** Is it an ordinary file, per lstat rather than stat. False for a
   *  symlink of any kind, dangling or not, and for anything else that is
   *  not a regular file. Checked before ownership or mode are asked at
   *  all (#649): the account this window exists to keep out can write
   *  advisor/state, so it could otherwise point reveal.window at some
   *  other root-owned, non-group-writable, constantly touched file and
   *  read as armed on facts that were never its own. */
  isRegularFile: boolean;
  /** Does it have exactly one name (lstat's nlink === 1). False for a file
   *  this account hard-linked reveal.window TO from some other root-owned,
   *  non-group-writable, recently-touched file elsewhere on the same
   *  filesystem: a hard link IS the target inode, so lstat reports the
   *  SAME uid, mode and mtime a legitimate marker would, and isRegularFile
   *  passes too, since a hard link is an ordinary regular file. nlink is
   *  the one fact that differs, because the account this window exists to
   *  keep out does not already own a second name for whatever root file it
   *  picked. Checked alongside isRegularFile, before ownership or mode are
   *  asked at all, the same discipline aperire-restore.sh's validate_set
   *  already applies to a set member for the identical reason (refuses
   *  anything with `stat -c '%h' > 1`). */
  singleLinked: boolean;
  /** Is it owned by uid 0. False for a marker this account (or the
   *  Advisor's own account) could have created itself, which is exactly
   *  the case this gate must refuse: a program either of them runs is not
   *  root planting a window. */
  ownedByRoot: boolean;
  /** Does its mode carry a group- or world-write bit (mode & 0o022). A
   *  marker anyone but root can write is not an arming either: something
   *  else could then hold this window open indefinitely. */
  groupOrWorldWritable: boolean;
  /** Seconds since the marker's own mtime, or null when the caller could not
   *  read it at all (folded into `exists: false` in practice; kept as its
   *  own case here so a negative age, a clock that moved, is its own named
   *  refusal rather than the caller having to invent one). */
  ageS: number | null;
}

export type AdvisorRevealWindowRefusalReason =
  'missing' | 'not_a_file' | 'hardlinked' | 'wrong_owner' | 'writable' | 'expired' | 'future';

export type AdvisorRevealWindowDecision =
  | { ok: true }
  | { ok: false; reason: AdvisorRevealWindowRefusalReason };

/** The refusals in the order that matches arm_guard's own bash (exists, then
 *  owner, then mode, then age), with two refusals ahead of all of them that
 *  arm_guard never needs: is this even a plain file, not a symlink (#649),
 *  and does it have only the one name a legitimate marker would (the
 *  hardlink bypass a symlink check alone does not close, see singleLinked's
 *  own comment). Each refuses before the next is asked, same discipline as
 *  every other gate in this file. */
export function advisorRevealWindowOpen(
  facts: AdvisorRevealWindowFacts,
  lifetimeS: number = ADVISOR_REVEAL_WINDOW_LIFETIME_S,
): AdvisorRevealWindowDecision {
  if (!facts.exists) return { ok: false, reason: 'missing' };
  if (!facts.isRegularFile) return { ok: false, reason: 'not_a_file' };
  if (!facts.singleLinked) return { ok: false, reason: 'hardlinked' };
  if (!facts.ownedByRoot) return { ok: false, reason: 'wrong_owner' };
  if (facts.groupOrWorldWritable) return { ok: false, reason: 'writable' };
  if (facts.ageS === null) return { ok: false, reason: 'missing' };
  if (facts.ageS < 0) return { ok: false, reason: 'future' };
  if (facts.ageS > lifetimeS) return { ok: false, reason: 'expired' };
  return { ok: true };
}

/** The one place this process touches the filesystem for the reveal window:
 *  a single lstatSync, never followed by a stat, so a symlink swapped in
 *  after this call cannot make a second call see a different file than the
 *  one isRegularFile already judged (#649: two calls would reopen the exact
 *  check-then-act race a single one avoids). Everything server.ts's own
 *  wrapper needs is this plus the path and the clock. */
export function readAdvisorRevealWindowFacts(path: string, nowMs: number): AdvisorRevealWindowFacts {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return {
      exists: false, isRegularFile: false, singleLinked: false,
      ownedByRoot: false, groupOrWorldWritable: false, ageS: null,
    };
  }
  return {
    exists: true,
    isRegularFile: st.isFile(),
    singleLinked: st.nlink === 1,
    ownedByRoot: st.uid === 0,
    groupOrWorldWritable: (st.mode & 0o022) !== 0,
    ageS: Math.floor((nowMs - st.mtimeMs) / 1000),
  };
}

/** One sentence per refusal reason, written for the row the design puts in
 *  front of the operator: "the window on <label> has closed" plus the exact
 *  re-run command. The reason is still carried on the wire (FleetWriteErrorBody
 *  has no room for it as a separate field without widening the closed error
 *  set for a fact only this one route produces), so it lives in the
 *  sentence rather than a new field. */
export function advisorRevealWindowRefusalDetail(reason: AdvisorRevealWindowRefusalReason): string {
  switch (reason) {
    case 'missing':
      return 'this node has no reveal window open, so it revealed nothing. Run the Advisor install command on it again to open one.';
    case 'not_a_file':
      return 'this node\'s reveal window is not an ordinary file, so it is not a window this gate will honor. Run the Advisor install command on it again to open a fresh one: curl -fsSL https://get.aperire.one/advisor | bash';
    case 'hardlinked':
      return 'this node\'s reveal window is not the only name for its file, so it is not a window this gate will honor. Run the Advisor install command on it again to open a fresh one: curl -fsSL https://get.aperire.one/advisor | bash';
    case 'wrong_owner':
      return 'this node\'s reveal window is not owned by root, so it is not a window this gate will honor. Nothing was revealed.';
    case 'writable':
      return 'this node\'s reveal window is writable by more than root, so it is not a window this gate will honor. Nothing was revealed.';
    case 'expired':
    case 'future':
      return 'this node\'s reveal window has closed. Run the Advisor install command on it again to open a fresh one: curl -fsSL https://get.aperire.one/advisor | bash';
    default: {
      const unreachable: never = reason;
      return `this node's reveal window is closed (${String(unreachable)}).`;
    }
  }
}

// ── The reveal decision: both gates, in one pure function ────────────────
//
// The route in server.ts is a thin wire-up of this: read the body, call
// this, send what it says. Everything that decides whether a token crosses
// is here, where a test can drive it without a real socket, a real clock or
// a real file. Two properties matter enough to name:
//
//   1. A job that fails checkAdvisorRevealJob never causes `windowFacts` to
//      be called at all. A forged job must learn nothing about whether this
//      host's window is open, and a lazy thunk (rather than a value the
//      caller has already computed) is what makes that true regardless of
//      what server.ts does around this call.
//   2. `advisor_token` is a key on the wire ONLY on the 200 branch. Every
//      refusal body is built from FleetWriteErrorBody, which has no such
//      field, so there is no branch a token could leak from by omission.

export interface AdvisorRevealDecideInput {
  /** The already-verified job, or the refusal it failed on. */
  check: JobDecision<{ job: AdvisorRevealJob }>;
  /** Called ONLY when `check.ok`. A thunk, not a value, so the caller cannot
   *  accidentally stat the window before the job is known good. */
  windowFacts: () => AdvisorRevealWindowFacts;
  /** Called ONLY once the window is confirmed open. This node's own
   *  approve.token, read fresh, or null when this host has none. */
  token: () => string | null;
  /** This node's own build ref, already run through this codebase's one
   *  sanitizer for the fact (an unstamped build reads as null, same as
   *  everywhere else it is read). Not decided here; carried through. */
  version: string | null;
  lifetimeS?: number;
}

export type AdvisorRevealDecision =
  | { status: 200; body: AdvisorRevealResponse }
  | { status: number; body: FleetWriteErrorBody };

export function decideAdvisorReveal(input: AdvisorRevealDecideInput): AdvisorRevealDecision {
  if (!input.check.ok) return { status: input.check.status, body: input.check.body };

  const window = advisorRevealWindowOpen(input.windowFacts(), input.lifetimeS);
  if (!window.ok) {
    return {
      status: 409,
      body: { error: 'advisor_reveal_window_closed', detail: advisorRevealWindowRefusalDetail(window.reason) },
    };
  }

  const tok = input.token();
  if (!tok) {
    return {
      status: 409,
      body: {
        error: 'advisor_reveal_unavailable',
        detail: 'this node has no Advisor approve.token to reveal; its install may not have finished',
      },
    };
  }

  return { status: 200, body: { advisor_token: tok, advisord_version: input.version } };
}

/** GET /fleet/v1/advisor/state's whole body, as a pure builder so a test can
 *  assert its key set carries no token by construction, not by review. */
export function buildAdvisorStateResponse(input: {
  state: AdvisorStateResponse['state'];
  lastAnsweredMs: number | null;
  detail: string;
  version: string | null;
}): AdvisorStateResponse {
  return {
    state: input.state,
    last_answered_ms: input.lastAnsweredMs,
    detail: input.detail,
    version: input.version,
  };
}

// ── The arm token: carried, never judged ─────────────────────────────────

export interface ArmTokenCheckInput {
  body: string;
  thisPubkeyNode: string | null;
  nowMs: number;
  nonces: NonceStore;
}

/** One `key=value` line at a time, the shape root writes and root parses.
 *  A repeated key takes the FIRST value: a token with two `target=` lines is
 *  ambiguous, and reading the last one would let a suffix override what the
 *  first line said. */
export function parseArmToken(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const i = line.indexOf('=');
    if (i <= 0) continue;
    const k = line.slice(0, i).trim();
    if (k === '' || Object.prototype.hasOwnProperty.call(out, k)) continue;
    out[k] = line.slice(i + 1).trim();
  }
  return out;
}

/**
 * Gates 4, 5 and 7 for the arm route. Gate 6 is deliberately absent: the
 * signature is verified by ROOT on this host, against a public key root
 * placed and this account cannot read. Checking it here as well would be a
 * second opinion the sealer does not consult, and it would suggest this
 * process holds something it does not.
 *
 * The `target` check below is the BELT, not the buckle (#184). The sealer
 * makes the same comparison against a node key root stamped in
 * /etc/aperire/node-key, and that is the one that decides. This one saves a
 * root invocation and gives the caller a named refusal a moment earlier; it
 * must never be the only place the address is read, because this process is
 * exactly the process the design says must not be able to arm, and a
 * dashboard couriering tokens for other nodes (#176) holds tokens addressed
 * elsewhere.
 */
export function checkArmToken(input: ArmTokenCheckInput): JobDecision<{ token: string; signature: string }> {
  const err = (status: number, body: FleetWriteErrorBody): JobDecision<never> =>
    ({ ok: false, status, body });
  const badJob = (detail: string) => err(400, { error: 'bad_job', detail });

  if (Buffer.byteLength(input.body, 'utf8') > FLEET_WRITE_MAX_BODY_BYTES) {
    return badJob('the arm request is larger than this route accepts');
  }
  let parsed: { token?: unknown; signature?: unknown };
  try {
    parsed = JSON.parse(input.body || '{}') as typeof parsed;
  } catch {
    return badJob('the arm request did not parse');
  }
  const token = typeof parsed?.token === 'string' ? parsed.token : '';
  const signature = typeof parsed?.signature === 'string' ? parsed.signature : '';
  if (!token) return badJob('the arm request carries no token');
  if (!signature) return badJob('the arm request carries no signature');
  const fields = parseArmToken(token);
  if (fields.v !== String(FLEET_WRITE_PROTOCOL_VERSION)) return badJob('the arm token carries no supported version');
  const nonce = fields.nonce ?? '';
  if (!NONCE_RE.test(nonce)) return badJob('the arm token carries no usable nonce');
  const issuedAt = Number(fields.issued_at);
  if (!Number.isFinite(issuedAt)) return badJob('the arm token carries no issue time');

  if (!input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: null,
      detail: 'this node cannot say what its own node key is yet, so it accepts no token addressed to one',
    });
  }
  if ((fields.target ?? '') !== input.thisPubkeyNode) {
    return err(409, {
      error: 'wrong_node', this_node: input.thisPubkeyNode,
      detail: 'that arm token is addressed to a different node',
    });
  }

  const skewS = Math.abs(Math.floor(input.nowMs / 1000) - issuedAt);
  if (skewS > FLEET_WRITE_FRESHNESS_S) {
    return err(409, {
      error: 'stale_job',
      detail: `that token was issued ${skewS}s from this node's clock, and this node accepts ${FLEET_WRITE_FRESHNESS_S}s`,
    });
  }
  // The dashboard's own replay record, which is NOT the sealer's: root keeps
  // /etc/aperire/fleet-arm.seen and is the authority. This one stops a replay
  // costing a socket connection and a root invocation, and the sealer stops
  // it counting for anything.
  const claim = input.nonces.claim(nonce, input.nowMs);
  if (claim === 'replay') return err(409, { error: 'replayed_job' });
  if (claim === 'unreadable') {
    return err(409, {
      error: 'nonce_store_unreadable',
      detail: 'this node cannot read its own replay record, and will not forward a token it could not refuse a second time',
    });
  }
  if (claim === 'full') {
    return err(503, {
      error: 'nonce_store_full',
      detail: `this node is holding ${FLEET_WRITE_NONCE_CAP} recent job nonces and will not take another until some age out`,
    });
  }

  return { ok: true, value: { token, signature } };
}

/**
 * The three lines the sealer reads for an arm, then a half-close.
 *
 * The five-line seal payload is unchanged byte for byte; the sealer branches
 * on whether the first line is exactly `arm`, which a base_url can never be.
 * The token is base64 so its own newlines cannot be mistaken for the frame's.
 */
export function armPayload(token: string, signatureB64: string): string {
  return `arm\n${Buffer.from(token, 'utf8').toString('base64')}\n${signatureB64}\n`;
}

/**
 * What the sealer reported about an arm, read back from its own output
 * rather than assumed from an exit code. Same discipline as sealModelKey.
 *
 * The sealer prints `armed=1`, `window_s=<n>` and `issuer=<label>` on the
 * stream and refuses with one `refused: ...` line, so `armed=1` is the fact
 * and the exit code is corroboration. Note that a SUCCESSFUL arm also writes
 * a human line to stderr (the journal sentence), which is why success is
 * judged on the field and never on stderr being empty.
 */
export function armOutcome(out: { code: number; stdout: string; stderr: string }): ArmSealResponse {
  const fields = new Map<string, string>();
  for (const line of out.stdout.split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) fields.set(line.slice(0, i).trim(), line.slice(i + 1).trim());
  }
  const armed = fields.get('armed') === '1';
  const windowS = Number(fields.get('window_s'));
  if (armed) {
    return {
      ok: true, armed: true,
      window_s: Number.isFinite(windowS) ? windowS : null,
      issuer: fields.get('issuer') ?? null,
      detail: 'This node is armed, and the next seal it accepts spends the window.',
    };
  }
  // The sealer's own last line. It is written to be read by an operator and
  // is never given anything secret to put in it.
  const said = out.stderr.split('\n').map((l) => l.trim()).filter(Boolean).pop() ?? '';
  return {
    ok: false, armed: false, window_s: null, issuer: null, error: 'refused',
    detail: said.replace(/^refused:\s*/, '') || 'This node refused to arm, and said nothing about why.',
  };
}

/**
 * The body, bounded. Resolves null when the caller sent more than the route
 * accepts, so the refusal is the gate's named one rather than a socket the
 * server destroyed mid-sentence.
 */
export function readFleetWriteBody(
  req: IncomingMessage, maxBytes = FLEET_WRITE_MAX_BODY_BYTES,
): Promise<string | null> {
  return readBody(req, maxBytes).then(out => (out.ok ? out.body : null));
}

export type { SealShape };
