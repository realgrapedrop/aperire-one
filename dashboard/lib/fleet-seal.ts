/**
 * The aggregator's half of a fleet seal: one passkey, one key, every node.
 *
 * An operator on the Settings page picks some nodes, types a provider key,
 * and approves once. What follows can take minutes: each node's sealer
 * restarts that node's Advisor and waits for it to come back. So the browser
 * is answered at once with a job id, and this module runs the work behind it
 * and reports per node.
 *
 * Three rules hold this file together, and each is a way the key could leak
 * or a node could be told something untrue.
 *
 * ONE: the key lives in the running job and nowhere else. It is never a
 * field of the status object, never in a log line, never in an audit detail,
 * and not even its hash is published (a hash of a short secret is a secret).
 * It is overwritten when the last target settles, so a job whose status is
 * still readable for thirty minutes holds nothing to read.
 *
 * TWO: a peer's answer is reported as the peer's answer. A node that refuses
 * because it has no aggregator pinned, a node whose arming window lapsed and
 * a node that never answered are three different states with three different
 * next actions, and this module keeps them apart rather than collapsing them
 * into "failed". `unreachable` is only ever a transport failure, and it names
 * the class of failure, never the exception's own message: an error carrying
 * the request it failed on is how a key ends up in a log nobody meant to
 * write, and the request body here IS the key.
 *
 * THREE: the job outlives the response that started it. Nothing here is tied
 * to an IncomingMessage, and no AbortSignal is derived from a response
 * lifecycle. A browser that navigates away mid-seal must not cancel a key
 * that is already crossing to a root program.
 */

import { randomBytes } from 'node:crypto';
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFresh } from './fleet-health.js';
import { verifyPeerPin } from './peer-read-proxy.js';
import { signWithSeed } from './trust-bundle.js';
import { sealModelKey, type SealRunner, type SealOutcome } from './model-seal.js';
import { buildFleetModelRecord, sealKeyDigest, sealKeyHint, type FleetModelRecord } from './fleet-model-record.js';
import {
  sealJobSigningBytes, sealKeyHash, FLEET_WRITE_ISSUER_LABEL, FLEET_WRITE_PROTOCOL_VERSION,
  type SealJob, type SealShape, type SealJobResponse, type FleetWriteErrorBody,
  type ArmStateResponse,
} from '../types/fleet-write-contract.js';

type FetchImpl = typeof fetch;

/** The two answers a dashboard built before the fleet write API gives that
 *  API's routes: 404 from a build that serves nothing there, 302 from one
 *  that sends every unknown path to its login page. Both mean "update that
 *  node's install first", which is what aperire-fleet-arm.sh says for the
 *  same two codes. */
export function predatesFleetWrite(status: number): boolean {
  return status === 404 || status === 302;
}

/** What a row says for such a node. One sentence, shared by the arm read
 *  and the seal so the page never says two things about the same fact. */
export const NO_FLEET_WRITE_DETAIL =
  'That node’s dashboard has no fleet write API; it runs a build older than this feature. '
  + 'Update its install, then bring it up to date from here.';

/** The label that means this host, in a targets array. Never a legal fleet
 *  label (fleet-registry.ts's alphabet allows it, but resolveFleet excludes
 *  the self row from the peers array, so a peer named "self" is not
 *  reachable through the peer path and cannot be confused with this one). */
export const SELF_TARGET = 'self';

/**
 * Where one node's seal has got to.
 *
 * `refused` is the node's own decision, reached and answered. `unreachable`
 * is this side failing to get an answer at all. The operator's next action
 * differs: the first is a thing to fix on that node, the second is a thing
 * to fix on the road to it.
 */
export type SealTargetState = 'queued' | 'sealing' | 'sealed' | 'refused' | 'unreachable';

export interface SealTargetStatus {
  label: string;
  state: SealTargetState;
  /** Machine-readable, for the page to choose words from. The node's own
   *  reason where there is one, this side's error class where there is not. */
  reason?: string;
  /** One sentence, safe to render. Never carries a key. */
  detail?: string;
  /** Three-valued on a sealed node, exactly as the per-node seal reports it. */
  model_configured?: boolean | null;
  service?: string;
  credential?: string;
  config?: string;
}

export interface SealJobStatus {
  job_id: string;
  done: boolean;
  /**
   * Whether this run put a DIFFERENT key behind the fleet model than the one
   * the fleet held when it started, three ways.
   *
   * `false`: the digest of the key being sealed equals the held one. The
   * operator typed the key the fleet already runs, there is no old key, and
   * the page must not say there is. `true`: the digests differ, or the held
   * digest is unknown and the hints already differ (different hints are
   * different keys). `null`: this host cannot tell (no record, a record from
   * before digests, an unreadable one), so the page says it conditionally.
   * Never `true` on a guess: the revoke advice cuts the fleet off its model
   * when it is wrong.
   */
  key_changed: boolean | null;
  targets: SealTargetStatus[];
}

export interface SealJobParams {
  baseUrl: string;
  shape: SealShape;
  model: string;
  credentialName: string;
  /** The human who touched the passkey here, carried so each node's own
   *  audit trail names a person. */
  grantedBy: string;
  /** Their role at the moment they approved. Recorded, never checked here:
   *  the check happened before this job existed. */
  grantedRole: string;
  /** Which passkey they touched. */
  credentialId: string;
  /** 'self' and/or peer labels. Validated by the caller against the fleet
   *  registry before it gets here. */
  targets: string[];
}

/**
 * The whole fleet model setting, key included, for the root store.
 *
 * Every field the node's own sealer needs, because that is what a later
 * catch-up will hand it: a plaintext descriptor sitting beside a sealed key
 * would be two files that drift, so the store holds one object and this is
 * its shape on the way in.
 *
 * `keyHint` is computed on THIS side with sealKeyHint() and travels verbatim.
 * There are already two declarations of that string (TypeScript and the
 * node sealer's bash); a third in the root broker would be the one that
 * drifts, and a hint that differs by one character reads as "that node is
 * behind" forever with no other symptom.
 */
export interface FleetModelDescriptor {
  baseUrl: string;
  shape: SealShape;
  model: string;
  credentialName: string;
  keyHint: string;
  sealedBy: string;
  /** The secret. Alive for the length of the call and no longer: the caller
   *  clears the job's copy on the next line. */
  key: string;
}

export interface FleetSealDeps {
  /** The local sealer socket, injected so a test needs no socket. */
  runSealer: SealRunner;
  /** The local read-back: does this host's Advisor report a model now? */
  readBack: () => Promise<boolean | null>;
  /** A RESOLVED peer by label, or null. Never trusted from the browser
   *  beyond being a lookup key. */
  peerByLabel: (label: string) => FleetNodeConfig | null;
  /** This aggregator's fleet-trust signing seed, read per job. Null when the
   *  host holds none, which refuses every peer target by name rather than
   *  sending an unsigned job that each node would refuse one at a time. */
  signingSeed: () => string | null;
  fetchImpl?: FetchImpl;
  nowMs?: () => number;
  log?: (line: string) => void;
  /**
   * The digest and hint of the key the fleet model holds right now, read when
   * a job starts and before anything is written, or null when none is
   * recorded. Compared with the key being sealed to decide `key_changed`.
   * Never the key.
   */
  heldKey?: () => { digest: string; hint: string } | null;
  /**
   * Called once per node as it settles, so the AGGREGATOR's audit trail
   * carries one line per node and not only "a fleet seal was started".
   *
   * Each node writes its own line on its own record too, and that one is
   * authoritative because the host that actually sealed wrote it. This one
   * exists because an operator asking "what did I change last Tuesday" asks
   * it here, on the dashboard they used, and a node that was unreachable
   * that day has no line anywhere else.
   *
   * Never given the key, and the status it is given never holds one.
   */
  recordOutcome?: (params: SealJobParams, target: SealTargetStatus) => void;
  /**
   * Called once when the job finishes, with the fleet's new model setting,
   * and only when at least one node sealed. The aggregator writes it down:
   * the ruling of 2026-09-04 is that provider, model and key are ONE fleet
   * setting, so there has to be a record of what it is or a node that missed
   * a seal cannot be told from one that never needed it.
   *
   * The record carries the key HINT, computed here while the key is still
   * in hand, and never the key.
   */
  recordFleetModel?: (record: FleetModelRecord) => void;
  /**
   * Called once, beside `recordFleetModel` and on the same condition, with
   * the fleet's whole model descriptor INCLUDING the key.
   *
   * This is the other half of the ruling of 2026-09-04. The record is what
   * the page renders; the store is what a LATER push sends, so a node paired
   * next week inherits today's setting with nothing pasted (ADR 0019 phase 4,
   * #168). Neither can do the other's job: the record holds no secret by
   * design, and the store is a root-owned blob this process cannot open.
   *
   * It runs here for the same reason the record does, and it is the reason
   * both are in this block: the key is about to be gone, and the line after
   * these two clears it.
   *
   * A store write that fails is logged and does not fail the seal, exactly as
   * the record's does. The seal already did what the operator asked for; what
   * is lost is the catch-up for a node that was down, which the next seal
   * restores.
   *
   * The `void` return is deliberate: this hands off to a root socket that can
   * take seconds, and the caller fires it rather than awaiting it, so nothing
   * here holds the key alive past this block.
   */
  storeFleetModel?: (descriptor: FleetModelDescriptor) => void;
  /**
   * Called once when a job is over, after the record is written and the key
   * is gone. What a job changes is what the Settings overview reports (each
   * node's model, the fleet's record), and that overview is served from a
   * five-second cache. The page reads it the moment it sees the job done,
   * and got the body from before the seal: the setting block kept saying
   * "taken from this dashboard's own Advisor" over a record that was on
   * disk (the lab aggregator, 2026-09-04). The cache must go when the job ends.
   */
  onJobDone?: (job: SealJobStatus) => void;
  /** How many nodes are sealed at once. Three: enough that thirty nodes do
   *  not take an hour, few enough that thirty Advisors do not restart at the
   *  same moment. */
  concurrency?: number;
  /**
   * How long to wait for a node's answer. It has to clear that node's own
   * worst case, and the arithmetic is the whole reason the number is what it
   * is: its sealer is bounded at 180 s, and the model read-back after it is
   * up to five tries with a 5 s probe each and 2 s between them, so about
   * 213 s before it can answer at all. A bound below that turns a node that
   * SEALED into a row reading "no answer", which is the kept-versus-observed
   * failure this project keeps meeting: the reading is wrong, not missing.
   */
  peerTimeoutMs?: number;
  /** How long a finished job stays readable. */
  expiryMs?: number;
}

const DEFAULT_CONCURRENCY = 3;
// 240 s: the node's ~213 s worst case (180 s sealer + up to 33 s read-back)
// plus slack for the hop. See peerTimeoutMs above.
const DEFAULT_PEER_TIMEOUT_MS = 240_000;
const DEFAULT_EXPIRY_MS = 30 * 60 * 1000;
/** The pin check's own bound, well short of the seal's: an identity read is
 *  one small GET, and a node that cannot answer it in ten seconds is not a
 *  node to hand a key to. */
const PIN_TIMEOUT_MS = 10_000;

interface RunningJob {
  id: string;
  created: number;
  done: boolean;
  doneAt: number | null;
  targets: SealTargetStatus[];
  /** See SealJobStatus.key_changed. Decided at start, while the key is in
   *  hand and before the record is rewritten. */
  keyChanged: boolean | null;
  /** The secret, for as long as a target still needs it. Overwritten when
   *  the last one settles. Not readable through any exported function. */
  key: string;
}

/**
 * The jobs this process is running or has recently run.
 *
 * In memory, deliberately: a seal is a thing an operator is watching happen,
 * and a job that survived a restart would be a job nobody is running. A
 * restart mid-seal loses the status, not the seal, which is already on its
 * way to a root program that will finish it either way.
 */
export class FleetSealJobs {
  private jobs = new Map<string, RunningJob>();
  private deps: Required<Pick<FleetSealDeps, 'concurrency' | 'peerTimeoutMs' | 'expiryMs'>> & FleetSealDeps;

  constructor(deps: FleetSealDeps) {
    this.deps = {
      concurrency: deps.concurrency ?? DEFAULT_CONCURRENCY,
      peerTimeoutMs: deps.peerTimeoutMs ?? DEFAULT_PEER_TIMEOUT_MS,
      expiryMs: deps.expiryMs ?? DEFAULT_EXPIRY_MS,
      ...deps,
    };
  }

  private now(): number { return (this.deps.nowMs ?? Date.now)(); }
  private log(line: string): void { (this.deps.log ?? console.log)(line); }

  /**
   * Start a job and return its id at once. The key is handed in here and is
   * the caller's last reference to it: the caller clears its own copy and
   * this object owns the only remaining one until the last target settles.
   */
  start(params: SealJobParams, key: string): SealJobStatus {
    this.expire();
    const job: RunningJob = {
      id: randomBytes(12).toString('base64url'),
      created: this.now(),
      done: false,
      doneAt: null,
      targets: params.targets.map((label) => ({ label, state: 'queued' as const })),
      keyChanged: this.keyChangedBy(key),
      key,
    };
    this.jobs.set(job.id, job);
    // The snapshot is taken BEFORE the work starts, so the 202 an operator
    // gets back reads `queued` for every node they picked rather than
    // `sealing` for the first three by accident of scheduling.
    const started = this.status(job);
    // Detached on purpose. The response to the browser is sent from the
    // return value above, and nothing about this work is bound to the request
    // that asked for it: a browser that navigates away mid-seal must not
    // cancel a key that is already crossing to a root program.
    void this.run(job, params);
    return started;
  }

  /** Whether sealing `key` changes the key the fleet holds. See
   *  SealJobStatus.key_changed for the three answers. */
  private keyChangedBy(key: string): boolean | null {
    let held: { digest: string; hint: string } | null;
    try { held = this.deps.heldKey ? this.deps.heldKey() : null; } catch { held = null; }
    if (!held) return null;
    const next = sealKeyDigest(key);
    if (held.digest && next) return held.digest !== next;
    // No digest on the record (it predates them). Two hints that differ are
    // two keys; anything else proves nothing either way.
    const nextHint = sealKeyHint(key);
    if (held.hint && nextHint && held.hint !== nextHint) return true;
    return null;
  }

  /** The status, or null when there is no such job (or it has expired). */
  get(jobId: string): SealJobStatus | null {
    this.expire();
    const job = this.jobs.get(jobId);
    return job ? this.status(job) : null;
  }

  /** What the browser sees. Built field by field rather than by copying the
   *  job, so a field added to RunningJob is never published by accident: the
   *  one that matters is `key`. */
  private status(job: RunningJob): SealJobStatus {
    return {
      job_id: job.id,
      done: job.done,
      key_changed: job.keyChanged,
      targets: job.targets.map((t) => ({ ...t })),
    };
  }

  private expire(): void {
    const now = this.now();
    for (const [id, job] of this.jobs) {
      if (job.done && job.doneAt !== null && now - job.doneAt > this.deps.expiryMs) {
        this.jobs.delete(id);
      }
    }
  }

  /** Bounded concurrency over the target list, in the order the operator
   *  chose them. A worker takes the next queued target until there are none. */
  private async run(job: RunningJob, params: SealJobParams): Promise<void> {
    let next = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        const i = next++;
        if (i >= job.targets.length) return;
        const target = job.targets[i];
        target.state = 'sealing';
        try {
          const result = target.label === SELF_TARGET
            ? await this.sealSelf(params, job.key)
            : await this.sealPeer(target.label, params, job.key);
          Object.assign(target, result);
        } catch (err) {
          // A throw from a seal path is a bug, not an outcome, and it must
          // not take the job down or leave a target reading `sealing`
          // forever. The class only: an exception's message is the one place
          // a payload could ride out of here.
          this.log(`[fleet-seal] ${target.label}: unexpected ${(err as Error).name}`);
          target.state = 'unreachable';
          target.reason = 'internal_error';
          target.detail = 'This node was not reached, and the failure was on this side.';
        }
        // After the state is final, and never able to change it: a recorder
        // that throws must not leave the next node unsealed.
        try { this.deps.recordOutcome?.(params, { ...target }); } catch { /* the record is not the work */ }
      }
    };
    const workers = Array.from(
      { length: Math.min(this.deps.concurrency, job.targets.length) },
      () => worker(),
    );
    await Promise.all(workers);
    // Before the key is cleared, not after: the record carries the hint the
    // node's own sealer wrote, and that is derived from the key. Written the
    // wrong way round it ships an empty hint, which reads as every node
    // being behind, with no error anywhere to say why.
    if (this.deps.recordFleetModel) {
      try {
        const record = buildFleetModelRecord({
          baseUrl: params.baseUrl,
          model: params.model,
          key: job.key,
          sealedBy: params.grantedBy,
          targets: job.targets.map((t) => ({ label: t.label, state: t.state, reason: t.reason ?? null })),
          // When the operator approved, not when the last node finished. A
          // job over a wide fleet runs for a long time, and dating the
          // record at the end makes every node it sealed look older than
          // the setting it is running.
          nowMs: job.created,
        });
        // Null when nothing sealed. A run every node refused did not change
        // the fleet's setting, so it must not replace the one that is
        // actually running.
        if (record) this.deps.recordFleetModel(record);
      } catch (err) {
        // The record is not the work. A dashboard that cannot write it shows
        // an older setting, which is a worse page, not a failed seal.
        this.log(`[fleet-seal] the fleet model record was not written (${(err as Error).name})`);
      }
    }
    // The store, on the same condition and in the same block, and for the
    // same reason: the key is cleared on the line below. A node paired next
    // week inherits this without an operator pasting anything (#168).
    if (this.deps.storeFleetModel && job.targets.some((t) => t.state === 'sealed')) {
      try {
        this.deps.storeFleetModel({
          baseUrl: params.baseUrl,
          shape: params.shape,
          model: params.model,
          credentialName: params.credentialName,
          // Derived here, while the key is still in hand, and never in the
          // root broker: one more declaration of this string is one more
          // place it can drift from the node sealer's.
          keyHint: sealKeyHint(job.key),
          sealedBy: params.grantedBy,
          key: job.key,
        });
      } catch (err) {
        // Logged, never fatal. The seal already did what the operator asked;
        // what is lost is the catch-up for a node that was down, and the next
        // seal puts it back. The error's CLASS only: this call's argument is
        // the key.
        this.log(`[fleet-seal] the fleet model was not sealed at rest (${(err as Error).name})`);
      }
    }
    // The last thing that happens, and the reason the key was held at all.
    job.key = '';
    job.done = true;
    job.doneAt = this.now();
    if (this.deps.onJobDone) {
      try { this.deps.onJobDone(this.status(job)); } catch (err) {
        this.log(`[fleet-seal] the job-done hook failed (${(err as Error).name})`);
      }
    }
  }

  /** This host: the local sealer over its own socket, then the read-back the
   *  per-node seal does. Exactly what the Advisor tab's own seal does, so a
   *  single-node install reaches the same code by the same road. */
  private async sealSelf(params: SealJobParams, key: string): Promise<SealTargetStatus> {
    const outcome = await sealModelKey({
      baseUrl: params.baseUrl,
      shape: params.shape,
      model: params.model,
      credentialName: params.credentialName,
      key,
    }, this.deps.runSealer);
    let modelConfigured: boolean | null = null;
    if (outcome.ok) {
      for (let attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 2_000));
        try { modelConfigured = await this.deps.readBack(); } catch { modelConfigured = null; }
        if (modelConfigured !== null) break;
      }
    }
    return outcomeToTarget(SELF_TARGET, outcome, modelConfigured);
  }

  /**
   * A peer: pin it, sign the job for it by name, and POST the job with its
   * own read token.
   *
   * The order is the point. The pin runs BEFORE the key is anywhere near the
   * wire, because a row whose forward now lands on a different host is
   * exactly the case where the key must not travel, and it is the same
   * verifyPeerPin every other peer path uses rather than a lenient variant.
   * The job then names that node's own pubkey_node, so even a correct
   * signature cannot seal onto a host it was not written for.
   */
  private async sealPeer(label: string, params: SealJobParams, key: string): Promise<SealTargetStatus> {
    const node = this.deps.peerByLabel(label);
    if (!node) {
      return {
        label, state: 'refused', reason: 'unknown_node',
        detail: 'This dashboard has no such node in its fleet registry.',
      };
    }
    const readToken = readTokenFresh(node.token_path);
    if (!readToken) {
      return {
        label, state: 'unreachable', reason: 'token_unreadable',
        detail: 'This dashboard cannot read the read token for that node, so it did not send anything.',
      };
    }
    const doFetch = this.deps.fetchImpl ?? fetch;
    const pinned = await verifyPeerPin(node, readToken, PIN_TIMEOUT_MS, doFetch);
    if (!pinned.ok) {
      return {
        label, state: 'unreachable', reason: pinned.error,
        detail: pinned.error === 'peer_integrity_mismatch'
          ? 'That node did not prove it is the node this row is pinned to, so nothing was sent to it.'
          : 'That node did not answer its identity check, so nothing was sent to it.',
      };
    }
    if (!node.expected_pubkey_node) {
      // Unpinned rows are a supported fleet shape for reads, but not for
      // this: the job is addressed to a node key, and without one there is
      // no address to write. Named, so the fix (pin the row) is obvious.
      return {
        label, state: 'refused', reason: 'row_not_pinned',
        detail: 'That node has no expected_pubkey_node in fleet.yaml, so no job can be addressed to it.',
      };
    }
    const seed = this.deps.signingSeed();
    if (!seed) {
      return {
        label, state: 'refused', reason: 'no_signing_key',
        detail: 'This dashboard holds no fleet-trust private key, so it cannot sign a job for any node.',
      };
    }

    const job: SealJob = {
      v: FLEET_WRITE_PROTOCOL_VERSION,
      kind: 'model.seal',
      issuer_label: FLEET_WRITE_ISSUER_LABEL,
      target_pubkey_node: node.expected_pubkey_node,
      nonce: randomBytes(16).toString('hex'),
      issued_at: Math.floor(this.now() / 1000),
      base_url: params.baseUrl,
      shape: params.shape,
      model: params.model,
      credential_name: params.credentialName,
      key_sha256: sealKeyHash(key),
      granted_by: params.grantedBy,
      credential_id: params.credentialId,
    };
    let signature: string;
    try {
      signature = signWithSeed(sealJobSigningBytes(job), seed);
    } catch {
      // The seed's own error can name its length. Not passed through.
      return {
        label, state: 'refused', reason: 'no_signing_key',
        detail: 'The fleet-trust private key on this dashboard is not a usable signing key.',
      };
    }

    let res: Response;
    try {
      res = await doFetch(`${node.read_origin}/fleet/v1/model/seal`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${readToken}` },
        body: JSON.stringify({ job, signature, key }),
        signal: AbortSignal.timeout(this.deps.peerTimeoutMs),
        // Never followed: a redirect here is an older node sending the key
        // to its login page, and a POST must not be replayed anywhere.
        redirect: 'manual',
      });
    } catch (err) {
      // The class, never the message: this request's body is the key, and a
      // fetch error can carry the request it failed on.
      const cls = (err as Error).name || 'Error';
      this.log(`[fleet-seal] ${label}: no answer (${cls})`);
      return {
        label, state: 'unreachable', reason: 'no_answer',
        detail: cls === 'TimeoutError'
          ? 'That node did not answer in time. Its own sealer may still be finishing; check its Advisor.'
          : 'That node could not be reached.',
      };
    }

    const text = await res.text().catch(() => '');
    let body: (SealJobResponse & FleetWriteErrorBody) | null;
    try { body = JSON.parse(text) as SealJobResponse & FleetWriteErrorBody; } catch { body = null; }
    if (!body && predatesFleetWrite(res.status)) {
      return {
        label, state: 'refused', reason: 'no_fleet_write_surface',
        detail: NO_FLEET_WRITE_DETAIL,
      };
    }
    if (!body) {
      return {
        label, state: 'unreachable', reason: 'bad_answer',
        detail: `That node answered ${res.status} with something this dashboard could not read.`,
      };
    }
    if (res.ok && body.ok) {
      return {
        label, state: 'sealed', reason: body.reason,
        detail: body.detail,
        model_configured: body.model_configured ?? null,
        ...(body.service ? { service: body.service } : {}),
        ...(body.credential ? { credential: body.credential } : {}),
        ...(body.config ? { config: body.config } : {}),
      };
    }
    // A refusal, and it is the NODE's refusal: its own reason and its own
    // words, rendered as it wrote them. A node's gate refusal (`error`) and
    // its sealer's refusal (`reason`) are both refusals to an operator, and
    // both name what to do next.
    return {
      label, state: 'refused',
      reason: body.error ?? body.reason ?? `http_${res.status}`,
      detail: body.detail ?? `That node refused with ${res.status}.`,
      ...(body.service ? { service: body.service } : {}),
    };
  }
}

/** The local sealer's outcome as a target row. Shared so the self path and
 *  a node's own answer render the same way. */
export function outcomeToTarget(
  label: string, outcome: SealOutcome, modelConfigured: boolean | null,
): SealTargetStatus {
  return {
    label,
    state: outcome.ok ? 'sealed' : (outcome.reason === 'unavailable' ? 'unreachable' : 'refused'),
    reason: outcome.reason,
    detail: outcome.detail,
    ...(outcome.ok ? { model_configured: modelConfigured } : {}),
    ...(outcome.service ? { service: outcome.service } : {}),
    ...(outcome.credential ? { credential: outcome.credential } : {}),
    ...(outcome.config ? { config: outcome.config } : {}),
  };
}

/**
 * The read half of the same client: what is that node's arm state?
 *
 * A stat of a marker, made by the node's own dashboard and forwarded here,
 * so Settings can enable Seal only for the nodes where pressing it could
 * work. Pinned first for the same reason every other peer read is: an arm
 * state read off a host this row no longer points at is a fact about the
 * wrong machine.
 *
 * Never throws. A peer that does not answer is `null` with a reason, which
 * the overview renders as a row, because a fleet page that fails because one
 * node is down is a fleet page that stops working exactly when it is needed.
 */
export async function fetchPeerArmState(
  node: FleetNodeConfig,
  opts: { timeoutMs?: number; fetchImpl?: FetchImpl } = {},
): Promise<{ ok: true; state: ArmStateResponse } | { ok: false; reason: string }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? PIN_TIMEOUT_MS;
  const token = readTokenFresh(node.token_path);
  if (!token) return { ok: false, reason: 'token_unreadable' };
  const pinned = await verifyPeerPin(node, token, timeoutMs, doFetch);
  if (!pinned.ok) return { ok: false, reason: pinned.error };
  try {
    const res = await doFetch(`${node.read_origin}/fleet/v1/model/arm`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(timeoutMs),
      // Never followed. An older node answers an unknown path with a
      // redirect to its login page, and following it turned that into a
      // page of HTML this reader could not parse, which rendered as "did
      // not answer" and asked again forever (the lab aggregator, 2026-09-04,
      // validator1 on the build before this feature).
      redirect: 'manual',
    });
    const text = await res.text();
    if (!res.ok) {
      // An older node that predates this surface answers 404, or 302 to its
      // login page. That is "this node cannot tell me", not "this node is
      // not armed", and the two must not render the same way. The same rule
      // aperire-fleet-arm.sh applies when it refuses that node.
      return { ok: false, reason: predatesFleetWrite(res.status) ? 'no_fleet_write_surface' : `http_${res.status}` };
    }
    try {
      return { ok: true, state: JSON.parse(text) as ArmStateResponse };
    } catch {
      return { ok: false, reason: 'bad_answer' };
    }
  } catch (err) {
    return { ok: false, reason: (err as Error).name === 'TimeoutError' ? 'timeout' : 'no_answer' };
  }
}
