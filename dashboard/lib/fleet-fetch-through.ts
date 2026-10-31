/**
 * Fleet fetch-through — the browser-facing peer overview aggregator
 * (D8 slice 2, advisor-enhancement/d8-aggregator-build-plan.md,
 * security-review-d8-fetchthrough.md).
 *
 * This module never runs in the browser: the peer's token lives here and
 * nowhere else, read fresh from `token_path` per fetch — same discipline as
 * fleet-health.ts, and it reuses that module's `readTokenFresh` rather than
 * re-implementing it. It is a SIBLING of fleet-health.ts, not a
 * reimplementation: fleet-health.ts polls every peer for a cheap health dot
 * on a fixed cadence; this module fetches ONE peer's full Overview on
 * demand, only while a browser is actually viewing it.
 *
 * The caller (server.ts) hands this module an already-RESOLVED
 * FleetNodeConfig row — never a label string. That is the SSRF containment
 * (P1-026): the label-to-row lookup happens once, in server.ts, against the
 * exact-match resolved peers array, and everything downstream of that
 * lookup only ever sees a row whose `read_origin` fleet-registry.ts has
 * already proven is a bare loopback origin. Nothing here builds a URL, a
 * header, or a file path from caller input.
 *
 * Pin verification (P1-029) happens on the SERVE path, not the health-dot
 * path, so it is stricter than fleet-health.ts's `checkIdentityPin`: a
 * pinned row's `node-status` response must carry a non-empty
 * `pubkey_node` that MATCHES `expected_pubkey_node`, or the whole overview
 * is refused. `checkIdentityPin`'s "couldn't check, don't hold it against
 * the peer" leniency exists for a TRANSPORT-level "couldn't ask" (an
 * older peer 404ing a route that didn't used to exist) — that case is
 * already covered here by node-status's own fetch failing outright. A
 * peer that answers 200 with `pubkey_node` missing or empty is a
 * different fact: an impostor that simply omits the field would pass a
 * lenient check for free, and this path serves a peer's ENTIRE Overview
 * under a trusted label, not a single-bit health dot. So here, "couldn't
 * confirm" and "confirmed wrong" both refuse to serve.
 */
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFileExplained, tokenUnreadableDetail, tokenUnreadableLog, isRefusedStatus } from './fleet-health.js';
import type { NodeStatusResponse, PeersResponse, ValidationSummaryResponse } from '../types/read-contract.js';

type FetchImpl = typeof fetch;
type AnyObj = Record<string, unknown>;

// ── Route/lookup — pure, unit-testable without an HTTP server ───────────
// Separated out for the same reason lib/read-api.ts's gateRead is separate
// from server.ts: "so the ordering guarantees can be asserted by unit
// tests" rather than only exercised through a live request.

const NODE_OVERVIEW_PATH_RE = /^\/api\/node\/([a-z0-9-]{1,32})\/overview$/;

/** Pure extraction of the :label segment from the fetch-through route's
 *  path, or null if the path doesn't match at all (P1-026). Deliberately a
 *  CLOSED character class — the same shape fleet-registry.ts's own
 *  LABEL_RE enforces at parse time — rather than "everything between the
 *  two slashes": a label shaped like a URL, a path-traversal segment, or
 *  anything containing '/', ':', '.', '%', or an uppercase letter simply
 *  never matches this regex, so it can never even reach the exact-match
 *  lookup below, let alone build a URL from it. */
export function parseNodeOverviewLabel(pathname: string): string | null {
  const m = NODE_OVERVIEW_PATH_RE.exec(pathname);
  return m ? m[1] : null;
}

/** Exact-match lookup against an ALREADY-RESOLVED peers array. Callers must
 *  pass the RESOLVED peers list (resolveFleet's `.peers`, never the raw
 *  parsed nodes) — that is what makes a self row 404 here rather than
 *  serving its own data through a path meant for peers: resolveFleet
 *  already excludes self from `.peers` (fleet-health.test.ts pins this),
 *  so self is simply never a candidate this function can return. */
export function resolvePeerByLabel(peers: FleetNodeConfig[], label: string): FleetNodeConfig | null {
  return peers.find((p) => p.label === label) ?? null;
}

// A closed set (P2-033), plus one addition beyond the review's literal
// four-item list: `peer_integrity_mismatch`. The review's list names the
// TRANSPORT failure modes; a pin mismatch is not a transport failure — the
// peer answered fine — and folding it into `peer_bad_response` would erase
// exactly the distinction fleet-health.ts's `critical` verdict exists to
// make (see that module's comment on why 'critical' is deliberately
// distinct from 'unreachable'). Never any upstream text, dial error,
// token, or peer address in a value of this type.
export type PeerOverviewErrorCode =
  | 'peer_unreachable'
  | 'peer_timeout'
  | 'peer_bad_response'
  // A second addition beyond the review's four, on the same reasoning as
  // `peer_integrity_mismatch` above: a peer that answers 401/403 is not a
  // transport failure either. It read the request, understood it, and
  // rejected the credential — which is what a wiped-and-reinstalled node
  // does to a registry holding its old token (#268). Folded into
  // `peer_bad_response` (and from there into the browser's UNREACHABLE) it
  // sent an operator to check a network path that was fine.
  | 'peer_refused'
  | 'peer_integrity_mismatch'
  // A third (#1305): this host could not read the token it needs, so nothing
  // was sent to the peer at all. It is a fact about a file on THIS box, which
  // is why it may carry a `detail` (below) where no other code here does: the
  // sentence names that file and says what was not sent, and never holds the
  // token, an upstream's text or a peer's address.
  | 'token_unreadable';

export interface PeerOverviewError {
  ok: false;
  error: PeerOverviewErrorCode;
  /** Only on `token_unreadable`: this host's own sentence about its own file
   *  (tokenUnreadableDetail). Never an upstream's words. */
  detail?: string;
}

/** peers/validation-summary are PER-GROUP (P2-031: "return PARTIAL data
 *  with per-group ages rather than failing the whole Overview") — one
 *  group failing (a slow peer_count RPC, say) must not blank a peer's
 *  entire center panel. node-status is NOT optional: it carries the pin
 *  and both staleness ages (P1-030), so its own failure IS a whole-overview
 *  failure — there is nothing honest to render without it. */
export type PeerGroup<T> =
  | { ok: true; data: T }
  | { ok: false; error: PeerOverviewErrorCode };

export interface PeerOverviewOk {
  ok: true;
  label: string;
  /** Dash's own fetch timestamp — one of the two ages the browser must
   *  compare (R1). The other is `node_status.server_info_age_ms` plus
   *  `node_status.node_reach`, carried through unchanged from the peer's
   *  own `node-status` response. The browser renders the WORSE of the two. */
  fetched_at_ms: number;
  node_status: Omit<NodeStatusResponse, 'protocol_version'>;
  peers: PeerGroup<Omit<PeersResponse, 'protocol_version'>>;
  validation_summary: PeerGroup<Omit<ValidationSummaryResponse, 'protocol_version'>>;
}

export type PeerOverviewResult = PeerOverviewOk | PeerOverviewError;

export const DEFAULT_TIMEOUT_MS = 4_000; // same bound every read route already keeps (fleet-health.ts precedent)
// "at least one cadence interval" (P2-031) — the poller's own cadence,
// FleetHealthPoller's default intervalMs, is the named precedent.
const DEFAULT_NEGATIVE_TTL_MS = 20_000;
// #831: a failure that says nothing about whether the node is there (see
// isTransientFailure) is held for less than the Overview's 2 s peer poll, so
// the very next poll asks again. Single-flight still coalesces the askers.
export const TRANSIENT_NEGATIVE_TTL_MS = 1_500;
// Short: this is the fastest of the fuller plan's per-group cadences
// (state/identity ~5s), kept conservative here since slice 2 bundles all
// three reads into one fetch rather than sub-grouping by cadence.
const DEFAULT_POSITIVE_TTL_MS = 1_500;
// Hard cap on bytes read from any one upstream route response. Generous
// headroom over any of these three computed bodies (peers with a large
// ring is the biggest, still low KBs) — this exists to bound a garbage or
// compromised peer's stream, not to fit a legitimate response tightly.
// Exported: the generic peer-read proxy (lib/peer-read-proxy.ts, D8 slice 3
// backend, security-review-peer-read-proxy.md P2-038) reuses this as its
// DEFAULT, then overrides it per-route for the two routes it names as too
// small at this bound (agreement, alerts) — never widens it for the three
// routes this module itself serves.
export const DEFAULT_MAX_BODY_BYTES = 262_144;

export type RouteReason = 'unreachable' | 'timeout' | 'bad_response' | 'refused';
export type RouteOutcome =
  | { ok: true; body: unknown }
  | {
    ok: false;
    reason: RouteReason;
    /** The upstream HTTP status, when there was one (#831). For the log and
     *  for the negative-cache decision only. Never sent to a browser. */
    status?: number;
    /** The upstream body's own `error` code, when it named one in the
     *  closed shape below (#831). A link answers its refusals this way
     *  (`concurrency_cap`, `link_not_ready`, `upstream_timeout`), and
     *  before this every one of them was logged as a bare bad_response. */
    code?: string;
  };

/** What an upstream error code may look like before it is written to the
 *  journal. The node may be the hostile party, so anything else is dropped
 *  rather than echoed. */
const UPSTREAM_CODE_RE = /^[a-z_]{1,40}$/;
/** The most of an error body read to find its code. A refusal is one line. */
const ERROR_BODY_BYTES = 4_096;

/** The one log detail for a failed route: the reason, then the status and
 *  the upstream code when there were any. `bad_response (503
 *  concurrency_cap)` names the link's cap; `bad_response` alone named
 *  nothing. */
export function describeOutcome(o: { reason: RouteReason; status?: number; code?: string }): string {
  if (o.status === undefined) return o.reason;
  return `${o.reason} (${o.status}${o.code ? ` ${o.code}` : ''})`;
}

/**
 * Is this failure one that says nothing about whether the node is there
 * (#831)? A link that is up and ready answered, just not in time or not with
 * room: the hub's or the node's concurrency cap, a hub-side timeout, or the
 * proxy's own timeout on a link row. Those are cached for one poll, not for
 * twenty seconds, so one slow moment cannot paint a healthy node UNREACHABLE
 * for half a minute.
 *
 * NOT transient: a refused connection (the listener is gone, so the link is
 * down), `link_not_ready`, a 401/403, a pin mismatch, or a timeout on a
 * tunnel row, where the old window stays exactly as it was.
 */
export function isTransientFailure(
  o: { reason: RouteReason; status?: number; code?: string },
  transport: FleetNodeConfig['transport'],
): boolean {
  // Link rows only, whatever the code says. A tunnel has no hub to send
  // these, and anything shaped like them on a tunnel row came from the far
  // end, which does not get to shorten its own unreachable window.
  if (transport !== 'link') return false;
  if (o.code === 'concurrency_cap') return true;
  if (o.status === 504 && o.code === 'upstream_timeout') return true;
  return o.reason === 'timeout';
}

export function reasonToCode(reason: RouteReason): PeerOverviewErrorCode {
  if (reason === 'timeout') return 'peer_timeout';
  if (reason === 'unreachable') return 'peer_unreachable';
  if (reason === 'refused') return 'peer_refused';
  return 'peer_bad_response';
}

/** Reads a fetch Response's body with a hard byte cap, counted on the wire
 *  (not string length — `.length` on a UTF-16 string is not a byte count).
 *  Cancels the underlying stream the moment the cap is exceeded rather than
 *  buffering an unbounded body to measure it after the fact — this is what
 *  makes the bound real rather than cosmetic (P2-031: "do not await
 *  res.json() on an unbounded stream"). Exported for lib/peer-read-proxy.ts —
 *  a SIBLING reuse, not a reimplementation, same discipline this module's own
 *  doc comment holds itself to against fleet-health.ts. */
export async function readBoundedBody(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    // No streaming body on this response (some fetch implementations omit
    // it for very small or empty bodies). Still bound it — just after
    // materializing, since there is no stream to cancel mid-read.
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('response too large');
    return text;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => { /* best effort */ });
        throw new Error('response too large');
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/**
 * Fetch one `/read/v1/<route>` body from a peer. `route` and `query` are
 * BOTH exported-caller-trusted here — this function builds the upstream URL
 * from them directly, exactly the "build the upstream path from the matched
 * name only" instruction security-review-peer-read-proxy.md gives the
 * generic proxy. Every caller of this function (fetchFromPeer below,
 * peer-read-proxy.ts) validates `route` against a named allowlist BEFORE
 * calling it — this function itself does not re-validate, the same
 * separation gateRead's own callers rely on in lib/read-api.ts.
 */
export async function fetchOneRoute(
  origin: string,
  token: string,
  route: string,
  timeoutMs: number,
  maxBodyBytes: number,
  doFetch: FetchImpl,
  query?: URLSearchParams,
): Promise<RouteOutcome> {
  try {
    // URLSearchParams.toString() on an empty instance is '' — no stray '?'
    // on the three-argument callers (fetchFromPeer) that never pass one.
    const qs = query && query.size > 0 ? `?${query.toString()}` : '';
    const res = await doFetch(`${origin}/read/v1/${route}${qs}`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    // 401/403 is the peer answering that this dashboard's token is not one
    // it accepts — a fact of its own, carried all the way to the browser
    // rather than flattened into "bad response" (#268). Every other non-200
    // stays bad_response, unchanged.
    if (!res.ok) {
      const reason: RouteReason = isRefusedStatus(res.status) ? 'refused' : 'bad_response';
      return { ok: false, reason, status: res.status, ...(await upstreamCode(res)) };
    }
    let text: string;
    try {
      text = await readBoundedBody(res, maxBodyBytes);
    } catch (err) {
      // #831: the timeout can fire after the headers, during the body. That
      // is a slow node, and calling it bad_response sent the reader of the
      // log looking for a malformed answer that never existed.
      if (err instanceof Error && err.name === 'TimeoutError') return { ok: false, reason: 'timeout' };
      return { ok: false, reason: 'bad_response' };
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return { ok: false, reason: 'bad_response' };
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return { ok: false, reason: 'bad_response' };
    return { ok: true, body };
  } catch (err) {
    // AbortSignal.timeout aborts with a DOMException/Error named
    // 'TimeoutError' — the same WHATWG shape the read routes and
    // fleet-health.ts already rely on.
    if (err instanceof Error && err.name === 'TimeoutError') return { ok: false, reason: 'timeout' };
    return { ok: false, reason: 'unreachable' };
  }
}

/** The `error` code out of a failed upstream answer, or nothing. Bounded,
 *  never throws, and a code outside UPSTREAM_CODE_RE is dropped. */
async function upstreamCode(res: Response): Promise<{ code?: string }> {
  try {
    const parsed = JSON.parse(await readBoundedBody(res, ERROR_BODY_BYTES)) as { error?: unknown };
    return typeof parsed?.error === 'string' && UPSTREAM_CODE_RE.test(parsed.error) ? { code: parsed.error } : {};
  } catch {
    return {};
  }
}

/** Server-log-only detail (P2-033: "upstream detail to the server log
 *  only"). Never the token, never anything that reaches the browser —
 *  callers of this module only ever see the typed PeerOverviewResult. */
function logUpstreamFailure(label: string, route: string, detail: string): void {
  throttledPeerWarn('fleet-fetch-through', label, route, detail);
}

/** #831: one line per (source, node, failure) this often. A node that is
 *  slow for a minute under a page polling every 2 s used to write a line per
 *  poll per route. */
export const PEER_LOG_EVERY_MS = 10_000;
/** The throttle's keys include a code the node supplied (shape-checked, but
 *  still the node's choice), so the map is capped and simply starts over. */
const PEER_LOG_MAX_KEYS = 512;
const peerLogAt = new Map<string, { at: number; quiet: number }>();
let peerLogNow: () => number = Date.now;

/**
 * Write a proxy's failure line, at most once per PEER_LOG_EVERY_MS for each
 * (source, node, detail), carrying how many were not written. The route is
 * in the line but not the key: twelve routes failing the same way at once
 * are one fact about the node, not twelve.
 */
export function throttledPeerWarn(source: string, label: string, route: string, detail: string): void {
  const key = `${source}|${label}|${detail}`;
  const t = peerLogNow();
  const prev = peerLogAt.get(key);
  if (prev && t - prev.at < PEER_LOG_EVERY_MS) { prev.quiet += 1; return; }
  if (!prev && peerLogAt.size >= PEER_LOG_MAX_KEYS) peerLogAt.clear();
  const more = prev && prev.quiet ? ` (${prev.quiet} more like it since the last line)` : '';
  peerLogAt.set(key, { at: t, quiet: 0 });
  console.warn(`[${source}] ${label} ${route}: ${detail}${more}`);
}

/** Tests only: forget the throttle and, optionally, drive its clock. */
export function resetPeerLogThrottle(now: () => number = Date.now): void {
  peerLogAt.clear();
  peerLogNow = now;
}

export interface FetchFromPeerOpts {
  timeoutMs: number;
  maxBodyBytes: number;
  fetchImpl?: FetchImpl;
}

/** One fetch attempt against one peer — node-status first (it carries the
 *  pin), then peers + validation-summary in parallel only once node-status
 *  has succeeded and, if pinned, confirmed. Never throws: every failure
 *  mode collapses to a typed PeerOverviewResult. */
export async function fetchFromPeer(node: FleetNodeConfig, opts: FetchFromPeerOpts): Promise<PeerOverviewResult> {
  return (await fetchFromPeerDetailed(node, opts)).result;
}

/** fetchFromPeer, plus whether a failure was transient (#831). The flag
 *  stays on this side: the result object is what server.ts serialises to the
 *  browser, and its error set is closed (P2-033). */
async function fetchFromPeerDetailed(
  node: FleetNodeConfig, opts: FetchFromPeerOpts,
): Promise<{ result: PeerOverviewResult; transient: boolean }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const tokenRead = readTokenFileExplained(node.token_path);
  if (!tokenRead.ok) {
    logUpstreamFailure(node.label, 'node-status', `token unreadable: ${tokenUnreadableLog(tokenRead)}`);
    // Its own answer (#1305), never peer_unreachable: nothing was sent. A
    // local file read costs nothing, so the failure is not held, and the
    // next ask sees a file the operator has just fixed.
    return {
      result: { ok: false, error: 'token_unreadable', detail: tokenUnreadableDetail(node.label, 'read', tokenRead) },
      transient: true,
    };
  }
  const token = tokenRead.token;

  const statusOutcome = await fetchOneRoute(node.read_origin, token, 'node-status', opts.timeoutMs, opts.maxBodyBytes, doFetch);
  if (!statusOutcome.ok) {
    logUpstreamFailure(node.label, 'node-status', describeOutcome(statusOutcome));
    return {
      result: { ok: false, error: reasonToCode(statusOutcome.reason) },
      transient: isTransientFailure(statusOutcome, node.transport),
    };
  }
  const statusBody = statusOutcome.body as AnyObj;

  // P1-029, serve-path pin check — fail closed on anything short of an
  // affirmative match. See the module doc comment for why this is
  // stricter than fleet-health.ts's checkIdentityPin.
  if (node.expected_pubkey_node) {
    const observed = typeof statusBody.pubkey_node === 'string' ? statusBody.pubkey_node : '';
    if (!observed || observed !== node.expected_pubkey_node) {
      logUpstreamFailure(node.label, 'node-status', 'pin mismatch or unconfirmed on the serve path');
      return { result: { ok: false, error: 'peer_integrity_mismatch' }, transient: false };
    }
  }

  const [peersOutcome, valOutcome] = await Promise.all([
    fetchOneRoute(node.read_origin, token, 'peers', opts.timeoutMs, opts.maxBodyBytes, doFetch),
    fetchOneRoute(node.read_origin, token, 'validation-summary', opts.timeoutMs, opts.maxBodyBytes, doFetch),
  ]);
  if (!peersOutcome.ok) logUpstreamFailure(node.label, 'peers', describeOutcome(peersOutcome));
  if (!valOutcome.ok) logUpstreamFailure(node.label, 'validation-summary', describeOutcome(valOutcome));

  return { transient: false, result: {
    ok: true,
    label: node.label,
    fetched_at_ms: Date.now(),
    node_status: statusBody as unknown as Omit<NodeStatusResponse, 'protocol_version'>,
    peers: peersOutcome.ok
      ? { ok: true, data: peersOutcome.body as Omit<PeersResponse, 'protocol_version'> }
      : { ok: false, error: reasonToCode(peersOutcome.reason) },
    validation_summary: valOutcome.ok
      ? { ok: true, data: valOutcome.body as Omit<ValidationSummaryResponse, 'protocol_version'> }
      : { ok: false, error: reasonToCode(valOutcome.reason) },
  } };
}

export interface FleetFetchThroughOpts {
  timeoutMs?: number;
  maxBodyBytes?: number;
  positiveTtlMs?: number;
  negativeTtlMs?: number;
  /** How long a TRANSIENT failure is cached (#831, isTransientFailure). One
   *  peer poll at most, so the next poll asks again. */
  transientTtlMs?: number;
  fetchImpl?: FetchImpl;
  /** Injected clock — real Date.now by default. Tests use this to control
   *  TTL expiry deterministically, and it is what stamps expiry at
   *  RESOLUTION time rather than call time (see getOverview's comment). */
  now?: () => number;
}

/**
 * Per-label cache + single-flight coalescing (P2-031) in front of
 * `fetchFromPeer`. One instance's cache is keyed by label ALONE — safe
 * because `parseFleetYaml` already rejects a duplicate label, and because
 * this instance's own label→row mapping never changes after construction
 * (server.ts builds a brand-new instance on every `loadFleetConfig()`
 * reload, discarding the old one along with its cache — the same
 * "restart, not diff" discipline FleetHealthPoller already uses for the
 * identical reason: a fresh instance cannot possibly answer a renamed
 * label with a stale entry, which is the whole of P2-032's requirement).
 */
export class FleetFetchThrough {
  private readonly cache = new Map<string, { result: PeerOverviewResult; expiresAtMs: number }>();
  private readonly inflight = new Map<string, Promise<PeerOverviewResult>>();
  private readonly timeoutMs: number;
  private readonly maxBodyBytes: number;
  private readonly positiveTtlMs: number;
  private readonly negativeTtlMs: number;
  private readonly transientTtlMs: number;
  private readonly fetchImpl?: FetchImpl;
  private readonly now: () => number;

  constructor(opts: FleetFetchThroughOpts = {}) {
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    this.positiveTtlMs = opts.positiveTtlMs ?? DEFAULT_POSITIVE_TTL_MS;
    this.negativeTtlMs = opts.negativeTtlMs ?? DEFAULT_NEGATIVE_TTL_MS;
    this.transientTtlMs = opts.transientTtlMs ?? TRANSIENT_NEGATIVE_TTL_MS;
    this.fetchImpl = opts.fetchImpl;
    this.now = opts.now ?? Date.now;
  }

  async getOverview(node: FleetNodeConfig): Promise<PeerOverviewResult> {
    const cached = this.cache.get(node.label);
    if (cached && cached.expiresAtMs > this.now()) return cached.result;

    const existing = this.inflight.get(node.label);
    if (existing) return existing;

    const promise = fetchFromPeerDetailed(node, { timeoutMs: this.timeoutMs, maxBodyBytes: this.maxBodyBytes, fetchImpl: this.fetchImpl })
      .then(({ result, transient }) => {
        // Stamped at RESOLUTION, not at the moment getOverview was called —
        // a fetch that takes the full timeout to fail must still get a full
        // negative-cache window from the moment we actually learned it
        // failed, not a window shortened by however long the timeout took.
        const ttl = result.ok ? this.positiveTtlMs : transient ? this.transientTtlMs : this.negativeTtlMs;
        this.cache.set(node.label, { result, expiresAtMs: this.now() + ttl });
        return result;
      })
      .finally(() => { this.inflight.delete(node.label); });

    this.inflight.set(node.label, promise);
    return promise;
  }
}
