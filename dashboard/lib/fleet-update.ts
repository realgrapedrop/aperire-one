/**
 * The aggregator's half of a fleet update: one passkey, one node, its own
 * updater.
 *
 * An operator on Settings & Updates presses Apply on a row that is behind.
 * What follows takes minutes on the far box (`npm ci` plus two Go builds),
 * so the browser is answered at once with a job id and this module runs the
 * work behind it, polling that node's own account of what it is doing.
 *
 * Three rules hold this file together, and each is a way a fleet table could
 * say something nobody measured.
 *
 * ONE: the job never writes a node's Release or Status cell. Those come from
 * the fleet poller re-reading that node's own stamp, and nothing in this
 * file can reach them. A job knows an apply returned 0; a job does not know
 * what the node is now running, and it says so ("applied, waiting for that
 * node to report") until a read says otherwise. That is this project's
 * characteristic bug, and the structure is what prevents it rather than a
 * promise to be careful.
 *
 * TWO: a peer's answer is reported as the peer's answer. `refused` is the
 * node deciding and answering; `unreachable` is this side failing to get an
 * answer at all. An operator acts on the two differently, and a run that
 * stopped answering mid-apply is never rendered as "failed" and never as
 * "applied".
 *
 * THREE: the job outlives the response that started it. Nothing here is tied
 * to an IncomingMessage and no AbortSignal is derived from a response
 * lifecycle: a browser that navigates away mid-apply must not cancel a run
 * that is already under way on another machine.
 *
 * Nothing here carries a secret. An update job names a tag, a commit and a
 * sha256, and the node reads its endpoint from its own root-owned config, so
 * there is no key at any boundary in this file.
 */

import { randomBytes } from 'node:crypto';
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFresh } from './fleet-health.js';
import { verifyPeerPin } from './peer-read-proxy.js';
import { signWithSeed } from './trust-bundle.js';
import { predatesFleetWrite, NO_FLEET_WRITE_DETAIL } from './fleet-seal.js';
import { sameCommit } from './update-check.js';
// The SAME check the restart route makes before it takes a passkey. Imported
// rather than restated, because what a row offers and what a press is given
// must be decided by one reader (#362).
import { unitListRefusal } from './update-apply.js';
import {
  updateJobSigningBytes, FLEET_WRITE_ISSUER_LABEL, FLEET_WRITE_PROTOCOL_VERSION,
  UPDATE_RESTART_UNIT_WAIT_S, UPDATE_RESTART_MAX_UNITS,
  UPDATE_SAY_MAX_CHARS, UPDATE_STEP_MAX_CHARS, UPDATE_UNIT_MAX_CHARS,
  UPDATE_MAX_UNITS, UPDATE_STATE_MAX_BYTES,
  type UpdateApplyJob, type UpdateRestartJob, type UpdateJob,
  type UpdateStateResponse, type UpdateStateRun, type UpdateStateReleaseKey, type FleetWriteErrorBody,
} from '../types/fleet-write-contract.js';
import { FLEET_LINK_BACKOFF_MAX_MS } from '../types/fleet-link-contract.js';

type FetchImpl = typeof fetch;

/**
 * Where one node's update has got to, on this aggregator's record.
 *
 * `applied` is deliberately not `current`. It means the node's own run ended
 * with code 0, which is a fact about a run and not about what the node is
 * running: the table turns green when the poller reads that node's stamp,
 * and for no other reason.
 */
export type UpdateTargetState =
  | 'queued' | 'applying' | 'applied'
  | 'restarting' | 'restarted'
  | 'refused' | 'unreachable';

export interface UpdateTargetStatus {
  label: string;
  state: UpdateTargetState;
  /** Machine-readable, for the page to choose words from. The node's own
   *  reason where there is one, this side's error class where there is not. */
  reason?: string;
  /** One sentence, safe to render. */
  detail?: string;
  /** That node's own run id, once it has one. What a restart is approved
   *  against. */
  run_id?: string;
  /** The step the node's program last announced, for the working line. */
  step?: string;
  /** The node's own last human line, for the working line's second half. */
  say?: string;
  /** What that node's finished run said needs restarting. Its discovery,
   *  carried for DISPLAY: no unit name travels in the other direction. */
  needs_restart?: string[];
  /**
   * A handful of that node's own last output lines, for the row's Details
   * fold (#333). Present only once a run has actually printed something: a
   * refusal reached before the update program started (an endpoint clash, an
   * unpaired node) has nothing to tail, and the fold is omitted rather than
   * shown empty.
   *
   * Carried through the same `carried()` road every other one of a node's
   * sentences is: control characters stripped, each line clamped, and only
   * the last few kept. This is display only and never grows the job's own
   * `run.lines`, which is where the record actually lives.
   */
  tail?: string[];
  /** When this side last got an answer out of that node, so a row that has
   *  gone quiet can say since when rather than freeze on its last reading. */
  answered_at?: number;
}

export interface UpdateJobStatus {
  job_id: string;
  action: 'apply' | 'restart';
  done: boolean;
  targets: UpdateTargetStatus[];
}

export interface UpdateJobParams {
  action: 'apply' | 'restart';
  /** Peer labels. Validated by the caller against the fleet registry before
   *  it gets here. A list from day one, so a later card-level "update every
   *  behind node" is one caller and not a rewrite. */
  targets: string[];
  /** The release the operator approved. Present on an apply, and it can only
   *  NARROW: each node compares it against what its own check names. */
  release?: { tag: string; commit: string; sha256: string };
  /** The run each target must be holding, on a restart. Keyed by label,
   *  because the approval was taken against what THAT run said needed
   *  restarting. */
  runIds?: Record<string, string>;
  /** The human who touched the passkey here, carried so each node's own
   *  audit trail names a person. */
  grantedBy: string;
  /** Their role at the moment they approved. Recorded, never checked here:
   *  the check happened before this job existed. */
  grantedRole: string;
  /** Which passkey they touched. */
  credentialId: string;
}

export interface FleetUpdateDeps {
  /** A RESOLVED peer by label, or null. Never trusted from the browser
   *  beyond being a lookup key. */
  peerByLabel: (label: string) => FleetNodeConfig | null;
  /** This aggregator's fleet-trust signing seed, read per job. */
  signingSeed: () => string | null;
  fetchImpl?: FetchImpl;
  nowMs?: () => number;
  log?: (line: string) => void;
  /** Called once per node as it settles, so the AGGREGATOR's own audit trail
   *  carries a line per node. The node writes its own line too, and that one
   *  is authoritative because the host whose code changed wrote it. */
  recordOutcome?: (params: UpdateJobParams, target: UpdateTargetStatus) => void;
  /** One node at a time. Not for CPU — each node builds on its own box — but
   *  because a fleet-wide apply of a bad release should reach one host and
   *  not six before an operator can stop it. The knob exists for the day a
   *  card-level "update every behind node" is ruled on. */
  concurrency?: number;
  /** How often the aggregator asks a running node what it is doing. The same
   *  cadence the local card tails its own run at. */
  pollMs?: number;
  /** How long one node's whole apply may take before this side gives up
   *  ASKING. It never cancels the run: the run is a root program on another
   *  machine and it finishes either way. Past this the row reads "no
   *  answer", which is honest, where "failed" would not be. */
  applyTimeoutMs?: number;
  /** The same bound for a RESTART, and it is a different number for a
   *  reason (#323). An apply's 45 minutes made a successful restart read as
   *  a failure for three quarters of an hour, and held the only fleet-job
   *  slot for the whole of it. This one is derived from what a restart
   *  actually costs, below. */
  restartTimeoutMs?: number;
  /** The bound on one state or job POST. Short: these are small requests and
   *  a link that cannot carry one in half a minute is a link to report on. */
  peerTimeoutMs?: number;
  /** How long a finished job stays readable. */
  expiryMs?: number;
}

const DEFAULT_CONCURRENCY = 1;
const DEFAULT_POLL_MS = 2_000;
/** 45 minutes, the same bound the local apply has on its own socket. */
const DEFAULT_APPLY_TIMEOUT_MS = 45 * 60_000;
/**
 * A restart's own bound, DERIVED rather than borrowed (#323).
 *
 * The node's root program waits UPDATE_RESTART_UNIT_WAIT_S per unit for it to
 * come back, and will only ever act on UPDATE_RESTART_MAX_UNITS of them. On
 * top of that, a node whose dashboard unit restarted is not reachable again
 * until its link is, which the ADR 0019 backoff caps at
 * FLEET_LINK_BACKOFF_MAX_MS. Double the whole of it for slack, because being
 * a minute early here is a success reported as a failure.
 *
 * Reusing the apply's 45 minutes was the bug. Reusing the node's own 120 s
 * socket bound would be the opposite mistake: that bound is on one socket
 * conversation, not on the reconnect that follows it.
 */
const DEFAULT_RESTART_TIMEOUT_MS =
  2 * (UPDATE_RESTART_MAX_UNITS * UPDATE_RESTART_UNIT_WAIT_S * 1000 + FLEET_LINK_BACKOFF_MAX_MS);
const DEFAULT_PEER_TIMEOUT_MS = 30_000;
const DEFAULT_EXPIRY_MS = 30 * 60 * 1000;
/** The pin check's own bound. An identity read is one small GET, and a node
 *  that cannot answer it in ten seconds is not a node to start a root
 *  program on. */
const PIN_TIMEOUT_MS = 10_000;
/**
 * The completeness read's bound (#331), and it is SHORT on purpose.
 *
 * This read is what a Check now waits on before it paints the table. Every
 * node is asked at once, so the cost of a fleet with three dead boxes is one
 * of these, not three. Six seconds is long enough for a link round trip to a
 * node that is alive and short enough that a node that is not never holds an
 * operator at a spinner. A node that does not answer in it reads as a node
 * that did not answer, which is a fact, and the next check asks again.
 */
const DEFAULT_COMPLETENESS_TIMEOUT_MS = 6_000;

interface RunningJob {
  id: string;
  action: 'apply' | 'restart';
  created: number;
  done: boolean;
  doneAt: number | null;
  targets: UpdateTargetStatus[];
  /** Set when an operator presses Stop waiting, or when the reaper gives up
   *  on a job nobody can end (#325). It stops THIS side's waiting and
   *  nothing else: the run is a root program on another machine and it
   *  finishes either way, which is why the row says so rather than claiming
   *  an outcome. */
  cancelled: 'operator' | 'abandoned' | null;
}

/**
 * Read a peer's answer, and STOP at the cap (#324).
 *
 * The tail this route serves is bounded by the node that serves it and,
 * before this, by nothing on the side that reads it. That asymmetry is the
 * finding: a node whose dashboard is compromised is in ADR 0019's threat
 * model and its named capability is "it can lie down the link", and without
 * a bound here that lie lands in the aggregator's job record and in the
 * operator's browser every two seconds. The link's own 4 MiB response cap is
 * four million times the size of the answer this route was designed to give,
 * and a peer reached directly at its read_origin has no cap at all.
 *
 * Stopped rather than measured afterwards: reading the whole of something in
 * order to refuse it is paying the cost anyway. Returns null past the cap,
 * which the caller renders as its own named refusal.
 */
async function readBounded(res: Response, maxBytes: number): Promise<string | null> {
  const body = res.body;
  if (!body) {
    const text = await res.text().catch(() => '');
    return Buffer.byteLength(text, 'utf8') > maxBytes ? null : text;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch { /* already gone */ }
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/**
 * One of a node's own sentences, made safe to print and clamped to what a
 * cell holds.
 *
 * TWO things happen here and the order matters.
 *
 * The strip first. A sentence off the wire is authored by whatever answered,
 * and a control character in it repaints whatever renders it: the install
 * review's P3-071 reproduced a refusal whose detail erased its own line and
 * repainted it green, so the one line an operator's eye goes to said the
 * opposite of the paragraph around it. The browser is not a terminal, but
 * this same text reaches an audit record, a log line and a test transcript,
 * and none of those is a place for a `\r`. Runs of whitespace collapse for
 * the same reason: a hundred newlines is a cell that pushes the table off
 * the page.
 *
 * The clamp second, so the ellipsis arithmetic is over the string that will
 * actually be printed rather than over one with invisible bytes in it.
 * Truncation is SAID rather than done silently: a sentence that stops
 * mid-word with no mark is a sentence an operator reads as the whole of what
 * the node said. The ellipsis is the mark, and the caller's own sentence
 * carries the rest.
 */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;
function carried(value: unknown, maxChars: number): string | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  const clean = value.replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim();
  if (clean === '') return undefined;
  if (clean.length <= maxChars) return clean;
  return `${clean.slice(0, maxChars - 1)}\u2026`;
}

/** The same clamp, for values that are not sentences (a unit name, a step
 *  name). One road, so a new caller cannot pick the unsanitised one. */
function clamp(value: unknown, maxChars: number): string | undefined {
  return carried(value, maxChars);
}

/** How many of a node's own last lines the fleet row's Details fold keeps
 *  (#333). A tail of a tail: the node's own `update/state` already bounds
 *  itself to UPDATE_STATE_TAIL_LINES, and this keeps only enough of that for
 *  a closed fold in a table cell, not a second copy of the record. */
const FLEET_TAIL_LINES = 6;

/** A node's own last few output lines, sanitised the same road every other
 *  carried sentence takes and bounded regardless of how many the node sent:
 *  the count is capped here, at the point of ingestion, whatever
 *  UPDATE_STATE_MAX_BYTES let through. */
function carriedTail(lines: unknown): string[] {
  if (!Array.isArray(lines)) return [];
  return lines
    .slice(-FLEET_TAIL_LINES)
    .map((l) => carried(String(l), UPDATE_SAY_MAX_CHARS))
    .filter((l): l is string => typeof l === 'string');
}

/** The units a node says need restarting, bounded the way the node's own
 *  unitListRefusal already bounds them. Carried for DISPLAY only. */
function clampUnits(units: unknown): string[] {
  if (!Array.isArray(units)) return [];
  return units
    .slice(0, UPDATE_MAX_UNITS)
    .map((u) => clamp(String(u), UPDATE_UNIT_MAX_CHARS))
    .filter((u): u is string => typeof u === 'string');
}

// ── One component, built from an older tree than its release, #266 ─────
//
// A release rebuilds every component a host has. The bug this exists to
// catch is the one that left no trace: fleet-update synced Advisor sources
// to three nodes on 2026-09-08 without rebuilding the daemon, and nothing on
// the page said so. So this is one amber note, never a column, the
// operator's own ruling on the re-scope, 2026-09-09.
//
// The rule that makes it safe rather than noisy: a component this dashboard
// has no reading for is DROPPED here, not compared. `componentDrift` below
// only ever looks at what `sanitizeComponents` kept, and a key that never
// arrives, or arrived as `dev` because nothing has stamped it yet, is a
// component nobody measured, not a component that agrees, and not one that
// disagrees. Read that as a bug and this note would fire on every fleet
// today, for components that report nothing at all.

/** A component's own build ref, shaped like a commit and nothing else. The
 *  same floor `sameCommit` already holds abbreviations to: shorter than this
 *  and two different builds could share it by accident. `relay_version`
 *  reads the literal string `dev` on every relay a release has not yet
 *  stamped (ADR 0022's own context), and that string fails this shape on
 *  purpose, it is a real field with nothing measurable in it yet, and this
 *  is where that distinction is made rather than three call sites making it
 *  three different ways. */
const COMPONENT_COMMIT_SHAPE = /^[0-9a-f]{7,40}$/i;

/** How many components one host may report, and the only names this
 *  dashboard will ever write into an amber note. A key not listed here is
 *  dropped rather than shown under whatever a peer chose to call it, the
 *  same reason a fleet row never restarts a unit name nothing here would
 *  recognise. */
const COMPONENT_LABELS: Record<string, string> = {
  relay: 'the relay',
  advisord: 'the Advisor daemon',
};
const MAX_COMPONENT_ENTRIES = Object.keys(COMPONENT_LABELS).length;

/**
 * A host's own `components` reading, checked before any of it is compared.
 *
 * The same two-step `carried()` uses and for the same reason: this is
 * node-authored, off the wire, and it reaches a comparison and a rendered
 * sentence. An unknown key, a non-string value, or a value that is not
 * shaped like a commit is dropped rather than coerced, dropping is what
 * keeps `dev` and an absent component reading the same way, "not measured".
 */
export function sanitizeComponents(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (Object.keys(out).length >= MAX_COMPONENT_ENTRIES) break;
    if (!Object.prototype.hasOwnProperty.call(COMPONENT_LABELS, key)) continue;
    if (typeof value !== 'string') continue;
    const v = value.trim().toLowerCase();
    if (!COMPONENT_COMMIT_SHAPE.test(v)) continue;
    out[key] = v;
  }
  return out;
}

/**
 * Which of a host's own measured components disagree with the release it
 * says it is on.
 *
 * `releaseCommit` null yields no verdict at all, a host with no comparable
 * release (a deploy ref, or no stamp) has nothing for a component to agree
 * or disagree with, and an empty list here must not be read as "everything
 * matches" when nothing was actually checked. An empty or absent
 * `components` is the same empty list for a different reason: nobody has
 * measured anything yet. Both callers render nothing either way, which is
 * the point, the two must never be told apart by inventing a verdict for
 * the second one.
 */
export function componentDrift(
  releaseCommit: string | null,
  components: Record<string, string> | null | undefined,
): string[] {
  if (!releaseCommit || !components) return [];
  const out: string[] = [];
  for (const [key, commit] of Object.entries(components)) {
    if (!sameCommit(commit, releaseCommit)) out.push(key);
  }
  return out;
}

/**
 * One amber sentence for a host whose own components disagree with its
 * release, never one line per component, and never at all when nothing
 * measured a mismatch. Null is "say nothing", the same reading `componentDrift`
 * returning `[]` already carries; this is the last step before that reading
 * becomes words on the page.
 */
export function describeComponentDrift(label: string, drifted: string[]): string | null {
  if (drifted.length === 0) return null;
  const names = drifted.map((k) => COMPONENT_LABELS[k] ?? k);
  const joined = names.length === 1
    ? names[0]
    : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
  const verb = names.length === 1 ? 'was' : 'were';
  return `${joined} on ${label} ${verb} built from an older tree than its release; run the update again.`;
}

/** Reaching one of a peer's three update routes: pinned first, its own read token,
 *  redirects never followed. One road, because two would drift and this one
 *  is walked every two seconds. */
async function peerUpdateFetch(
  node: FleetNodeConfig,
  path: string,
  init: { method: 'GET' | 'POST'; body?: string; timeoutMs: number; fetchImpl: FetchImpl; pin: boolean },
): Promise<
  | { ok: true; status: number; text: string }
  | { ok: false; reason: string; detail: string }
> {
  const token = readTokenFresh(node.token_path);
  if (!token) {
    return {
      ok: false, reason: 'token_unreadable',
      detail: 'This dashboard cannot read the read token for that node, so it did not send anything.',
    };
  }
  if (init.pin) {
    // BEFORE anything is sent, and it is the same verifyPeerPin every other
    // peer path uses rather than a lenient variant. A row whose forward now
    // lands on a different host is exactly the case where a job must not
    // travel.
    const pinned = await verifyPeerPin(node, token, PIN_TIMEOUT_MS, init.fetchImpl);
    if (!pinned.ok) {
      return {
        ok: false, reason: pinned.error,
        detail: pinned.error === 'peer_integrity_mismatch'
          ? 'That node did not prove it is the node this row is pinned to, so nothing was sent to it.'
          : 'That node did not answer its identity check, so nothing was sent to it.',
      };
    }
  }
  try {
    const res = await init.fetchImpl(`${node.read_origin}${path}`, {
      method: init.method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(init.body ? { 'content-type': 'application/json' } : {}),
      },
      ...(init.body ? { body: init.body } : {}),
      signal: AbortSignal.timeout(init.timeoutMs),
      // Never followed: a redirect here is an older node sending this to its
      // login page, and a POST must not be replayed anywhere.
      redirect: 'manual',
    });
    const text = await readBounded(res, UPDATE_STATE_MAX_BYTES);
    if (text === null) {
      return {
        ok: false, reason: 'answer_too_large',
        detail: 'That node answered with more than this dashboard reads from that route, so nothing of it was kept.',
      };
    }
    return { ok: true, status: res.status, text };
  } catch (err) {
    const cls = (err as Error).name || 'Error';
    return {
      ok: false,
      reason: cls === 'TimeoutError' ? 'timeout' : 'no_answer',
      detail: cls === 'TimeoutError'
        ? 'That node did not answer in time.'
        : 'That node could not be reached.',
    };
  }
}

/**
 * What one read of a node's update state came back with.
 *
 * `refused` is the distinction this module's rule two is about, moved onto
 * the read as well as onto the job: the node DECIDED and answered, which is
 * a different fact from this side failing to get an answer at all. A caller
 * that prints "did not answer" over a node that answered a refusal is
 * telling the operator to go and look at a box that is up.
 */
export type PeerUpdateStateResult =
  | { ok: true; state: UpdateStateResponse }
  | { ok: false; reason: string; detail: string; refused?: boolean };

/**
 * One node's own account of itself, read over the link.
 *
 * Never throws. A peer that does not answer is a reason, not an exception,
 * because a fleet page that fails because one node is down is a fleet page
 * that stops working exactly when it is needed.
 */
export async function fetchPeerUpdateState(
  node: FleetNodeConfig,
  opts: { timeoutMs?: number; fetchImpl?: FetchImpl; pin?: boolean } = {},
): Promise<PeerUpdateStateResult> {
  const got = await peerUpdateFetch(node, '/fleet/v1/update/state', {
    method: 'GET',
    timeoutMs: opts.timeoutMs ?? PIN_TIMEOUT_MS,
    fetchImpl: opts.fetchImpl ?? fetch,
    // The poll does not re-pin on every tick: the job pinned before it sent
    // anything, and re-reading an identity every two seconds for the length
    // of a build is cost with no new answer.
    pin: opts.pin ?? true,
  });
  if (!got.ok) return got;
  if (got.status !== 200) {
    // 404-family FIRST, and it stays first: a build that predates this
    // surface answers a 404 with a body that means nothing, and reading that
    // body would turn a node that is simply older into a node that said
    // something.
    if (predatesFleetWrite(got.status)) {
      return { ok: false, reason: 'no_fleet_write_surface', detail: NO_FLEET_WRITE_DETAIL };
    }
    // The node's OWN words, where it wrote any (#331). Every refusal this
    // surface produces is `{error, detail}` (lib/fleet-write-api.ts), and
    // `That node answered 409.` threw all of it away — including the one
    // sentence an operator can act on, "this node holds no key for
    // peers.aggregator". Sanitised on the way in, never on the way out: what
    // is kept here is re-served and re-rendered, so it is made safe once at
    // the point of ingestion.
    let body: FleetWriteErrorBody | null;
    try { body = JSON.parse(got.text) as FleetWriteErrorBody; } catch { body = null; }
    const reason = carried(body?.error, UPDATE_STEP_MAX_CHARS);
    const detail = carried(body?.detail, UPDATE_SAY_MAX_CHARS);
    return {
      ok: false,
      // A body that does not parse, or one with no `error` in it, keeps the
      // old classification. It is still true and it is all this side has.
      reason: reason ?? `http_${got.status}`,
      detail: detail ?? `That node answered ${got.status}.`,
      // Whether the node DECIDED or this side failed to reach it. A caller
      // rendering "did not answer" over a node that answered a refusal is
      // the sentence #331 is about.
      refused: true,
    };
  }
  try {
    return { ok: true, state: JSON.parse(got.text) as UpdateStateResponse };
  } catch {
    return { ok: false, reason: 'bad_answer', detail: 'That node answered with something this dashboard could not read.' };
  }
}

// ── Is that node a complete member of this fleet? — #331 ─────────────────
//
// Four things make a node one this fleet can act on: the update grant, a
// release stamp, an update endpoint, and this aggregator's key pinned under
// peers.aggregator on that box. The one-command install-and-join produces
// all four by construction; a node deployed by hand, or one whose operator
// removed the grant on purpose (which the hardening guide documents as
// supported), can be missing any of them.
//
// Before this the table found out by pressing Apply and being refused. Now
// it asks, once, when the fleet is graded — and it reports EXACTLY what the
// node answered. Nothing here fills a gap in with what a pairing usually
// leaves behind: a node that did not answer reads as a node that did not
// answer, and a member the node omitted is `undefined`, never false.

/** What one node said about its own completeness, or why it said nothing.
 *  Every present member is that node's own measurement. */
export interface NodeCompleteness {
  /** When this aggregator got (or gave up waiting for) this answer, ms. */
  read_at: number;
  answered: boolean;
  /** That node's own updater probe. Omitted when it did not say — a build
   *  that predates the member, or a probe that got no answer out of the
   *  socket. Absent is not false. */
  updater?: boolean;
  /** That node's own reading of its own fleet-trust file. Omitted by an
   *  older build. */
  pin?: 'pinned' | 'none' | 'unreadable';
  /** Where root on that node installs from, as root reported it. */
  endpoint?: string;
  /** What that endpoint publishes, as root reported it. */
  published_tag?: string;
  /**
   * That node's own finished apply, as that node is holding it right now
   * (#362).
   *
   * An apply installs a tree; it does not put the tree in service. Until the
   * units named by that run are restarted the node is running the old code,
   * and the only record of that anywhere was the aggregator job held by the
   * browser session that pressed Apply. A second session had no job, so it
   * offered Apply again on a node that had already applied — a passkey spent
   * on a press root would refuse.
   *
   * Every member here is the node's own answer, read off its own
   * `update/state`. Present ONLY while that node is still holding the run: a
   * `run: null` with a `last_run` marker is a node whose own dashboard has
   * since restarted, and the marker says nothing about the other units
   * (#323). Absent is not "nothing to restart"; absent is "the node did not
   * say".
   */
  applied?: {
    /** The run a restart would be approved against, as that node named it. */
    run_id: string;
    /** The release that run installed, off the run's own record. */
    tag?: string;
    /**
     * What that run said is still on the old code, present ONLY when the
     * list is one the restart route would accept. `unitListRefusal` is the
     * gate `/api/update/fleet/restart/begin` makes before it takes a
     * passkey, so a list it would refuse yields no units here and the row
     * offers no button: an offer and a refusal derived from two readers is
     * how a doomed control gets shipped.
     */
    units?: string[];
  };
  /** That node's own build refs, one per component it could measure (#266).
   *  Sanitised the same way every other node-authored value here is; a
   *  component it did not report is simply not a key. Present only when at
   *  least one survived the check. */
  components?: Record<string, string>;
  /** Which of `components` disagree with `installed`'s commit, off THIS
   *  node's own reading of both, never recomputed from a release this
   *  aggregator believes rather than the one that node just named. Absent
   *  or empty means nothing measured a mismatch, which is the ordinary
   *  reading before a release is drifted OR before relay and advisord are
   *  built to say what they measured; the two are the same reading on
   *  purpose (#266). */
  component_drift?: string[];
  /** The release key that node's updater checks against, as that node read
   *  it (#784). Omitted by an older build, and by one whose answer did not
   *  pass the shape check below: absent is "did not say", never a mismatch. */
  release_key?: UpdateStateReleaseKey;
  /** Present only when `answered` is false: why. */
  reason?: string;
  detail?: string;
  /** The node answered a refusal rather than falling silent. */
  refused?: boolean;
}

/** An endpoint URL is a node-authored string and it is rendered on a page,
 *  so it is bounded here the way every other carried value is. Generous
 *  enough for a real URL and far short of a cell-breaking one. */
const ENDPOINT_MAX_CHARS = 200;
/** A run id is sixteen hex characters on every build that writes one. Bounded
 *  anyway: it is node-authored, it rides back to this dashboard on the next
 *  restart press, and nothing node-authored is kept unbounded. */
const RUN_ID_MAX_CHARS = 64;

/**
 * A finished apply the node is STILL HOLDING, and what it said needs
 * restarting (#362).
 *
 * Three refusals, and each is a thing this must not claim.
 *
 *  - `run: null` yields nothing. A node whose own dashboard restarted keeps
 *    a marker rather than a run (#323), and that marker's `restarted_after`
 *    is this node's measurement of ITS OWN process and says nothing about
 *    the relay or the Advisor. Reading a restart of everything out of it
 *    would be the inference #323 exists to refuse — and the restart route
 *    would refuse the press anyway, because it reads `run` too.
 *  - A run still running yields nothing. A snapshot taken mid-apply is not a
 *    result.
 *  - A run whose verdict is not the node's own `ok` yields nothing. That is
 *    a refusal, and it has its own words elsewhere.
 *
 * The units are carried only when `unitListRefusal` passes, which is the
 * gate the restart route makes before it takes a passkey. So the row can
 * offer a Restart exactly where the press would be accepted, and says
 * "applied, waiting for that node to report" everywhere else.
 */
function appliedNotRestarted(run: UpdateStateRun | null): NodeCompleteness['applied'] {
  if (!run || run.running !== false || run.action !== 'apply') return undefined;
  if (run.verdict?.ok !== true) return undefined;
  const runId = carried(run.run_id, RUN_ID_MAX_CHARS);
  if (!runId) return undefined;
  // The gate runs on the list AS THE NODE SENT IT, and the clamp is only for
  // what gets displayed. The other order looks equivalent and is not: a run
  // naming nine units is one the restart route refuses, while `clampUnits`
  // would quietly cut it to the eight the route accepts and the row would
  // offer a button for a press that 409s after the passkey. Caught by the
  // unit row that drives exactly that list.
  const raw = Array.isArray(run.needs_restart) ? run.needs_restart.map((u) => String(u)) : [];
  const tag = carried(run.release?.tag, UPDATE_STEP_MAX_CHARS);
  return {
    run_id: runId,
    ...(tag ? { tag } : {}),
    ...(unitListRefusal(raw) === null ? { units: clampUnits(raw) } : {}),
  };
}

/** An OpenSSH SHA-256 fingerprint: the prefix and 43 base64 characters. */
const SSH_FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

/**
 * A node's release key answer, kept only when it is the shape a node's own
 * reader produces (#784). It is node-authored and lands on a page, so it is
 * checked whole: a known state, at most two fingerprints of the one shape,
 * none unless the state is `ok`, and `lab` only as a literal true. Anything
 * else is dropped entirely, which reads as "did not say".
 */
export function carriedReleaseKey(value: unknown): UpdateStateReleaseKey | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const v = value as { state?: unknown; fingerprints?: unknown; lab?: unknown };
  if (v.state !== 'ok' && v.state !== 'none' && v.state !== 'unreadable') return undefined;
  if (!Array.isArray(v.fingerprints)) return undefined;
  const fps = v.fingerprints;
  if (v.state === 'ok') {
    if (fps.length < 1 || fps.length > 2) return undefined;
    if (!fps.every((f) => typeof f === 'string' && SSH_FINGERPRINT_RE.test(f))) return undefined;
    if (new Set(fps).size !== fps.length) return undefined;
  } else if (fps.length !== 0) {
    return undefined;
  }
  return { state: v.state, fingerprints: fps.map(String), ...(v.lab === true ? { lab: true as const } : {}) };
}

/**
 * Ask one node what it holds. Never throws, never re-pins.
 *
 * `pin: false` is deliberate and it is a display decision. `peerUpdateFetch`
 * spends PIN_TIMEOUT_MS on verifyPeerPin before it sends anything, which
 * would make a display-only read cost sixteen seconds against a dead box.
 * The poller already grades a rebuilt node `not_verified` off its own pinned
 * identity read and the caller excludes those rows, and the Apply press
 * re-pins before any job travels. So nothing acts on this read; it only
 * says what the operator should run.
 */
export async function readNodeCompleteness(
  node: FleetNodeConfig,
  opts: { timeoutMs?: number; fetchImpl?: FetchImpl; nowMs?: () => number } = {},
): Promise<NodeCompleteness> {
  const now = opts.nowMs ?? Date.now;
  const got = await fetchPeerUpdateState(node, {
    timeoutMs: opts.timeoutMs ?? DEFAULT_COMPLETENESS_TIMEOUT_MS,
    fetchImpl: opts.fetchImpl,
    pin: false,
  });
  if (!got.ok) {
    return {
      read_at: now(),
      answered: false,
      reason: got.reason,
      detail: got.detail,
      ...(got.refused ? { refused: true } : {}),
    };
  }
  const s = got.state;
  // `updater` is taken only when the node ALSO said its probe got an answer.
  // A node whose socket accepted a connection and said nothing reports
  // `updater: false` with `updater_answered: false`, and a row that turned
  // that into "install the update grant" would send an operator to run a
  // root command on a host that already holds it (review P3-070). A build
  // older than `updater_answered` omits it, and an omission is read as the
  // definite answer it was before the member existed.
  const said = s.updater_answered !== false;
  const applied = appliedNotRestarted(s.run);
  return {
    read_at: now(),
    answered: true,
    ...(said && typeof s.updater === 'boolean' ? { updater: s.updater } : {}),
    ...(s.aggregator_pin ? { pin: s.aggregator_pin } : {}),
    ...(carried(s.endpoint, ENDPOINT_MAX_CHARS) ? { endpoint: carried(s.endpoint, ENDPOINT_MAX_CHARS) } : {}),
    ...(carried(s.published?.tag, UPDATE_STEP_MAX_CHARS)
      ? { published_tag: carried(s.published?.tag, UPDATE_STEP_MAX_CHARS) }
      : {}),
    // The one fact a fresh session had no way to learn (#362): this node has
    // applied and its units are still on the old code. Off the node's own
    // run record, never off a job this dashboard happens to be holding.
    ...(applied ? { applied } : {}),
    // The release key that node trusts (#784), off its own root-owned file.
    ...(() => {
      const key = carriedReleaseKey(s.release_key);
      return key ? { release_key: key } : {};
    })(),
    // Component drift (#266), off this node's OWN two readings of itself:
    // what it measured, and what it says it is installed at. Never the
    // release this aggregator believes, a node graded `behind` by the
    // aggregator but not yet re-checked by itself would otherwise flag every
    // component as drifted against a release it has not applied yet.
    ...(() => {
      const components = sanitizeComponents(s.components);
      if (Object.keys(components).length === 0) return {};
      const installedCommit = typeof s.installed?.commit === 'string' ? s.installed.commit : null;
      const drift = componentDrift(installedCommit, components);
      return { components, ...(drift.length ? { component_drift: drift } : {}) };
    })(),
  };
}

/**
 * Every addressable peer, asked at once.
 *
 * In parallel and bounded, because the whole point is that one slow node
 * never holds up the table: the cost of this read is one timeout however
 * many nodes are down, not one timeout each. `allSettled` rather than `all`
 * for the same reason, and every path inside already answers rather than
 * throwing, so a rejection here would be a bug and is recorded as one.
 */
export async function readFleetCompleteness(
  nodes: FleetNodeConfig[],
  opts: { timeoutMs?: number; fetchImpl?: FetchImpl; nowMs?: () => number } = {},
): Promise<Record<string, NodeCompleteness>> {
  const now = opts.nowMs ?? Date.now;
  const settled = await Promise.allSettled(
    nodes.map((n) => readNodeCompleteness(n, opts)),
  );
  const out: Record<string, NodeCompleteness> = {};
  settled.forEach((r, i) => {
    out[nodes[i].label] = r.status === 'fulfilled' ? r.value : {
      read_at: now(),
      answered: false,
      reason: 'internal_error',
      detail: 'This node was not asked, and the failure was on this side.',
    };
  });
  return out;
}

/**
 * The jobs this process is running or has recently run.
 *
 * In memory, deliberately: an update is a thing an operator is watching
 * happen, and a job that survived a restart would be a job nobody is
 * running. A restart mid-apply loses the status, not the work, which is
 * already under way on another machine and will finish either way. What the
 * operator sees afterwards is the table, re-graded from each node's own
 * stamp, which is the only terminal truth in this design.
 */
export class FleetUpdateJobs {
  private jobs = new Map<string, RunningJob>();
  private deps: Required<Pick<FleetUpdateDeps,
    'concurrency' | 'pollMs' | 'applyTimeoutMs' | 'restartTimeoutMs' | 'peerTimeoutMs' | 'expiryMs'>> & FleetUpdateDeps;

  constructor(deps: FleetUpdateDeps) {
    // The defaults go AFTER the spread, not before it. Spread last, a caller
    // passing an explicit `undefined` for a key gets undefined rather than
    // the default, and `Math.min(undefined, n)` is NaN: a job that completes
    // with every target still queued. Named in the review's residuals.
    this.deps = {
      ...deps,
      concurrency: deps.concurrency ?? DEFAULT_CONCURRENCY,
      pollMs: deps.pollMs ?? DEFAULT_POLL_MS,
      applyTimeoutMs: deps.applyTimeoutMs ?? DEFAULT_APPLY_TIMEOUT_MS,
      restartTimeoutMs: deps.restartTimeoutMs ?? DEFAULT_RESTART_TIMEOUT_MS,
      peerTimeoutMs: deps.peerTimeoutMs ?? DEFAULT_PEER_TIMEOUT_MS,
      expiryMs: deps.expiryMs ?? DEFAULT_EXPIRY_MS,
    };
  }

  private now(): number { return (this.deps.nowMs ?? Date.now)(); }
  private log(line: string): void { (this.deps.log ?? console.log)(line); }

  /** Is any job still running? One fleet job at a time on this side, the way
   *  one update run at a time already works on a host. Both bounds, because
   *  either alone leaves a way to hammer a node with refused connections. */
  busy(): boolean {
    this.expire();
    for (const job of this.jobs.values()) if (!job.done) return true;
    return false;
  }

  /** Start a job and return its id at once. */
  start(params: UpdateJobParams): UpdateJobStatus {
    this.expire();
    const job: RunningJob = {
      id: randomBytes(12).toString('base64url'),
      action: params.action,
      created: this.now(),
      done: false,
      doneAt: null,
      targets: params.targets.map((label) => ({ label, state: 'queued' as const })),
      cancelled: null,
    };
    this.jobs.set(job.id, job);
    // Taken BEFORE the work starts, so the 202 reads `queued` for every node
    // rather than `applying` for the first by accident of scheduling.
    const started = this.status(job);
    // Detached on purpose: nothing about this work is bound to the request
    // that asked for it.
    void this.run(job, params);
    return started;
  }

  /** The status, or null when there is no such job (or it has expired). */
  get(jobId: string): UpdateJobStatus | null {
    this.expire();
    const job = this.jobs.get(jobId);
    return job ? this.status(job) : null;
  }

  /** What the browser sees. Built field by field rather than by copying the
   *  job, so a field added to RunningJob is never published by accident —
   *  and so that no member of this object is one the Release column reads. */
  private status(job: RunningJob): UpdateJobStatus {
    return {
      job_id: job.id,
      action: job.action,
      done: job.done,
      targets: job.targets.map((t) => ({ ...t })),
    };
  }

  private expire(): void {
    const now = this.now();
    for (const [id, job] of this.jobs) {
      if (job.done && job.doneAt !== null && now - job.doneAt > this.deps.expiryMs) {
        this.jobs.delete(id);
        continue;
      }
      // A job that is NOT done and is older than anything it could honestly
      // still be waiting for (#325). Without this, `busy()` is true forever
      // and the fleet's update page is gone until the aggregator restarts —
      // which is the host the operator was in the middle of managing. It
      // gives up WAITING; it claims nothing about what the node did.
      if (!job.done && now - job.created > this.abandonMs()) {
        this.log(`[fleet-update] job ${job.id} was abandoned after ${Math.round((now - job.created) / 1000)}s`);
        this.stopWaiting(job, 'abandoned');
      }
    }
  }

  /** How long a job may exist before it is abandoned: the longest thing it
   *  could honestly still be waiting for, plus a margin. Derived from the
   *  same two deadlines follow() uses, so raising one raises this. */
  private abandonMs(): number {
    return Math.max(this.deps.applyTimeoutMs, this.deps.restartTimeoutMs) + 5 * 60_000;
  }

  /**
   * Stop waiting on a job, and say so in every row that had not settled.
   *
   * It does NOT abort the run on the far box, and the sentence says as much:
   * the module's own rule three is that a job outlives the request that
   * started it, and a node's root program is not this side's to stop. What
   * is being cancelled is this dashboard's patience.
   */
  private stopWaiting(job: RunningJob, by: 'operator' | 'abandoned'): void {
    job.cancelled = by;
    for (const t of job.targets) {
      if (t.state === 'applied' || t.state === 'restarted' || t.state === 'refused' || t.state === 'unreachable') continue;
      t.state = 'unreachable';
      t.reason = by === 'operator' ? 'stopped_waiting' : 'abandoned';
      t.detail = by === 'operator'
        ? 'This dashboard stopped waiting. Whatever that node started is still running there, and its own page has the rest.'
        : 'This dashboard waited as long as it can and stopped. That node\u2019s own page has what happened.';
    }
    job.done = true;
    job.doneAt = this.now();
  }

  /**
   * The operator's own way out. Answers whether there was a job to stop, so
   * the page can say "already finished" rather than pretending it did
   * something.
   */
  cancel(jobId: string): { ok: boolean; status: UpdateJobStatus | null } {
    this.expire();
    const job = this.jobs.get(jobId);
    if (!job) return { ok: false, status: null };
    if (job.done) return { ok: false, status: this.status(job) };
    this.log(`[fleet-update] job ${job.id} cancelled by the operator`);
    this.stopWaiting(job, 'operator');
    return { ok: true, status: this.status(job) };
  }

  private async run(job: RunningJob, params: UpdateJobParams): Promise<void> {
    let next = 0;
    const worker = async (): Promise<void> => {
      for (;;) {
        const i = next++;
        if (i >= job.targets.length) return;
        const target = job.targets[i];
        // A cancelled job takes no more targets. The queued rows already
        // carry stopWaiting's sentence.
        if (job.cancelled) return;
        try {
          await this.driveOne(job, target, params);
        } catch (err) {
          // A throw is a bug, not an outcome, and it must not take the job
          // down or leave a target reading `applying` forever. The class
          // only: an exception's message can carry the request it failed on.
          this.log(`[fleet-update] ${target.label}: unexpected ${(err as Error).name}`);
          target.state = 'unreachable';
          target.reason = 'internal_error';
          target.detail = 'This node was not reached, and the failure was on this side.';
        }
        if (job.cancelled) return;
        try { this.deps.recordOutcome?.(params, { ...target }); } catch { /* the record is not the work */ }
      }
    };
    const workers = Array.from(
      { length: Math.min(this.deps.concurrency, job.targets.length) },
      () => worker(),
    );
    await Promise.all(workers);
    // A job stopWaiting already ended keeps the moment it ended and the
    // sentences it wrote; the workers finishing afterwards must not
    // overwrite either.
    if (!job.done) {
      job.done = true;
      job.doneAt = this.now();
    }
  }

  /** Sign a job for one node, or say why this dashboard cannot. */
  private buildJob(
    node: FleetNodeConfig, params: UpdateJobParams, label: string,
  ): { ok: true; job: UpdateJob; signature: string } | { ok: false; status: UpdateTargetStatus } {
    if (!node.expected_pubkey_node) {
      // Unpinned rows are a supported fleet shape for reads, but not for
      // this: the job is addressed to a node key, and without one there is
      // no address to write.
      return { ok: false, status: {
        label, state: 'refused', reason: 'row_not_pinned',
        detail: 'That node has no expected_pubkey_node in fleet.yaml, so no job can be addressed to it.',
      } };
    }
    const seed = this.deps.signingSeed();
    if (!seed) {
      return { ok: false, status: {
        label, state: 'refused', reason: 'no_signing_key',
        detail: 'This dashboard holds no fleet-trust private key, so it cannot sign a job for any node.',
      } };
    }
    const common = {
      v: FLEET_WRITE_PROTOCOL_VERSION as typeof FLEET_WRITE_PROTOCOL_VERSION,
      issuer_label: FLEET_WRITE_ISSUER_LABEL,
      target_pubkey_node: node.expected_pubkey_node,
      nonce: randomBytes(16).toString('hex'),
      issued_at: Math.floor(this.now() / 1000),
      granted_by: params.grantedBy,
      credential_id: params.credentialId,
    };
    let built: UpdateJob;
    if (params.action === 'apply') {
      if (!params.release) {
        return { ok: false, status: {
          label, state: 'refused', reason: 'no_release',
          detail: 'That approval carried no release.',
        } };
      }
      built = {
        ...common, kind: 'update.apply',
        tag: params.release.tag, commit: params.release.commit, sha256: params.release.sha256,
      } satisfies UpdateApplyJob;
    } else {
      const runId = params.runIds?.[label] ?? '';
      if (!runId) {
        return { ok: false, status: {
          label, state: 'refused', reason: 'wrong_run',
          detail: 'That approval named no run on this node, so there is nothing to restart against.',
        } };
      }
      built = { ...common, kind: 'update.restart', run_id: runId } satisfies UpdateRestartJob;
    }
    try {
      return { ok: true, job: built, signature: signWithSeed(updateJobSigningBytes(built), seed) };
    } catch {
      // The seed's own error can name its length. Not passed through.
      return { ok: false, status: {
        label, state: 'refused', reason: 'no_signing_key',
        detail: 'The fleet-trust private key on this dashboard is not a usable signing key.',
      } };
    }
  }

  /** One node, start to settled. */
  private async driveOne(job: RunningJob, target: UpdateTargetStatus, params: UpdateJobParams): Promise<void> {
    const label = target.label;
    const node = this.deps.peerByLabel(label);
    if (!node) {
      Object.assign(target, {
        state: 'refused', reason: 'unknown_node',
        detail: 'This dashboard has no such node in its fleet registry.',
      });
      return;
    }
    const built = this.buildJob(node, params, label);
    if (!built.ok) { Object.assign(target, built.status); return; }

    target.state = params.action === 'apply' ? 'applying' : 'restarting';
    const doFetch = this.deps.fetchImpl ?? fetch;
    const path = params.action === 'apply' ? '/fleet/v1/update/apply' : '/fleet/v1/update/restart';
    const sent = await peerUpdateFetch(node, path, {
      method: 'POST',
      body: JSON.stringify({ job: built.job, signature: built.signature }),
      timeoutMs: this.deps.peerTimeoutMs,
      fetchImpl: doFetch,
      pin: true,
    });
    if (!sent.ok) {
      Object.assign(target, { state: 'unreachable', reason: sent.reason, detail: sent.detail });
      return;
    }
    if (sent.status !== 202) {
      // The NODE's own refusal, in the node's own words, or the honest
      // reading of a build that predates this surface.
      if (predatesFleetWrite(sent.status)) {
        Object.assign(target, {
          state: 'refused', reason: 'no_fleet_write_surface', detail: NO_FLEET_WRITE_DETAIL,
        });
        return;
      }
      let body: FleetWriteErrorBody | null;
      try { body = JSON.parse(sent.text) as FleetWriteErrorBody; } catch { body = null; }
      Object.assign(target, {
        state: 'refused',
        reason: carried(body?.error, UPDATE_STEP_MAX_CHARS) ?? `http_${sent.status}`,
        detail: carried(body?.detail, UPDATE_SAY_MAX_CHARS) ?? `That node refused with ${sent.status}.`,
      });
      return;
    }
    let accepted: { run_id?: string };
    try { accepted = JSON.parse(sent.text) as typeof accepted; } catch { accepted = {}; }
    target.run_id = typeof accepted.run_id === 'string' ? accepted.run_id : undefined;
    target.answered_at = this.now();
    await this.follow(job, node, target, params.action);
  }

  /**
   * Poll that node's own account until its run ends.
   *
   * Started and polled, never held. One link request has 310 s and an apply
   * has 45 minutes; a held request would be killed by the transport with the
   * run still going, and this side would then have a timeout where the node
   * has a success.
   */
  private async follow(
    job: RunningJob, node: FleetNodeConfig, target: UpdateTargetStatus, action: 'apply' | 'restart',
  ): Promise<void> {
    const deadline = this.now()
      + (action === 'restart' ? this.deps.restartTimeoutMs : this.deps.applyTimeoutMs);
    const doFetch = this.deps.fetchImpl ?? fetch;
    for (;;) {
      await new Promise((r) => setTimeout(r, this.deps.pollMs));
      // Checked first, so a cancelled job stops asking rather than finishing
      // its current poll and then noticing. stopWaiting has already written
      // this row's sentence; nothing here may overwrite it.
      if (job.cancelled) return;
      const got = await fetchPeerUpdateState(node, {
        timeoutMs: this.deps.peerTimeoutMs, fetchImpl: doFetch, pin: false,
      });
      if (!got.ok) {
        // A node that stopped answering mid-run. NOT failed, and NOT
        // applied: this side has no answer at all, which is a different fact
        // from the node deciding anything, and the row says since when. A
        // restart is EXPECTED to drop the link, so the deadline is what ends
        // this rather than the first missed poll.
        if (this.now() >= deadline) {
          Object.assign(target, {
            state: 'unreachable', reason: got.reason,
            detail: action === 'restart'
              ? 'That node has not answered since its restart began.'
              : 'That node stopped answering while its update was running. What it did is on that node.',
          });
          return;
        }
        continue;
      }
      target.answered_at = this.now();
      const run = got.state.run;
      if (!run || (target.run_id && run.run_id !== target.run_id)) {
        // The node is not holding the run this dashboard started. On a
        // restart that took away the node's own dashboard unit, which is the
        // ORDINARY case after an apply that changed it, that is exactly what
        // is expected: the record lived in the process the restart killed.
        //
        // What is read here is the node's OWN durable marker, and only the
        // one measurement on it (#323). `restarted_after` means that node's
        // dashboard process started after that run began, measured on that
        // node against its own clock. It is not an inference from an
        // absence, and it does not become one here: `run: null` alone is
        // never read as success, because a node whose dashboard came back
        // while its relay did not answers `run: null` in exactly the same
        // way. So the sentence says what was measured and what was not.
        const kept = got.state.last_run;
        if (action === 'restart' && kept && kept.run_id === target.run_id && kept.restarted_after) {
          target.state = 'restarted';
          target.reason = 'restarted_after';
          target.detail = 'That node\u2019s dashboard came back after the restart began. '
            + 'What its other units did is on that node\u2019s own page.';
          if (kept.units.length) target.needs_restart = clampUnits(kept.units);
          return;
        }
        if (this.now() >= deadline) {
          Object.assign(target, {
            state: 'unreachable',
            reason: 'run_replaced',
            detail: action === 'restart'
              ? 'That node did not come back saying it restarted. Its own page has what happened.'
              : 'That node is no longer holding the run this dashboard started.',
          });
          return;
        }
        continue;
      }
      // Clamped at the point of INGESTION, not at the point of rendering:
      // what is kept here is re-served to the browser on every job poll.
      target.step = clamp(run.steps[run.steps.length - 1], UPDATE_STEP_MAX_CHARS);
      target.say = clamp(run.verdict?.say ?? run.lines[run.lines.length - 1], UPDATE_SAY_MAX_CHARS);
      // Kept live through the poll, not only stapled on at the end, so a
      // cancelled or timed-out wait still leaves something in the fold.
      const tail = carriedTail(run.lines);
      if (tail.length) target.tail = tail;
      if (run.running) {
        if (this.now() >= deadline) {
          // Still working, and this side has stopped waiting. NOT a failure
          // and not a success: the run is a root program on another machine
          // and it finishes either way.
          Object.assign(target, {
            state: 'unreachable', reason: 'still_running',
            detail: 'That node is still working and this dashboard has stopped waiting. Its own page has the rest.',
          });
          return;
        }
        continue;
      }
      // The run ended, and the node's own verdict is the word for it.
      const ok = run.verdict?.ok === true;
      target.reason = clamp(run.verdict?.reason, UPDATE_STEP_MAX_CHARS)
        ?? (run.code === 0 ? 'done' : 'refused');
      target.detail = clamp(run.verdict?.say ?? run.verdict?.detail, UPDATE_SAY_MAX_CHARS);
      if (!ok) { target.state = 'refused'; return; }
      if (action === 'restart') { target.state = 'restarted'; return; }
      target.needs_restart = clampUnits(run.needs_restart);
      // `applied`, never `current`. What this node is RUNNING is a question
      // only its own stamp answers, and the fleet poller is the only thing
      // that reads it.
      target.state = 'applied';
      return;
    }
  }
}
