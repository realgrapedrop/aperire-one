/**
 * The generic peer-read proxy — D8 slice 3 backend
 * (advisor-enhancement/security-review-peer-read-proxy.md, numbering 035+).
 * Extends slice 2's fetch-through (lib/fleet-fetch-through.ts) from three
 * hardcoded routes to any route named in READ_ROUTE_NAMES, so a browser
 * viewing a fleet peer can reach every HTTP-served read route that peer
 * exposes, not just the three the Overview aggregator bundles.
 *
 * A SIBLING of fleet-fetch-through.ts, not a reimplementation: this module
 * imports and reuses its token-read discipline (readTokenFresh, via
 * fleet-health.ts), its bounded-body reader (readBoundedBody), its single
 * upstream-fetch primitive (fetchOneRoute), and its closed error-code set
 * (PeerOverviewErrorCode / reasonToCode). Nothing here builds a URL, a
 * header, or a file path from caller input that fleet-fetch-through.ts
 * doesn't already build the identical way for its own three routes.
 *
 * The security review's two new conditions this module exists to satisfy:
 *
 *   P1-035 — `:route` is validated against the IMPORTED READ_ROUTE_NAMES set
 *   for exact membership BEFORE any outbound fetch. This is why the
 *   allowlist check (isAllowedRoute) is a separate, first-called function:
 *   server.ts calls it and 404s an unknown route before this module's own
 *   entry point (fetchPeerRoute) is ever invoked, so an unrecognized name
 *   never reaches a network call at all — not "reaches it and gets
 *   refused downstream", never reaches it.
 *
 *   P1-036 — the pin (P1-029's serve-path check, generalized) breaks for a
 *   route with no `pubkey_node` field of its own. For a pinned row, EVERY
 *   request first fetches `identity` on the same origin+token and demands
 *   an affirmative `pubkey_node === expected_pubkey_node` match before the
 *   originally-requested route is fetched at all — including when the
 *   originally-requested route IS `identity`: this module does not special-
 *   case that route to skip its own check, because a special case is
 *   exactly the kind of "this one path is different" reasoning that a later
 *   change can silently break. The extra round trip on that one route name
 *   is the cost of having only one code path instead of two.
 *
 *   #831 narrows "every request" for the READ paths only: a confirmed pin is
 *   reused for a few seconds on the same link generation (PeerPinCache
 *   below), so a burst of reads costs one identity check and not one each.
 *   Every write path still pins on the request itself.
 *
 * P2-037 (param forwarding) and P2-038 (per-route body cap) live in this
 * module's own tables (PARAM_ALLOWLIST, ROUTE_MAX_BODY_BYTES) rather than in
 * fleet-fetch-through.ts, because neither concept exists for that module's
 * three fixed, parameterless routes. P2-039 (bounded cache) is
 * PeerReadProxy below, the sibling of FleetFetchThrough — same "restart, not
 * diff" reload discipline (P2-032), plus an entry cap this slice adds
 * because the cache key now includes caller-controlled params.
 */
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFresh } from './fleet-health.js';
import {
  DEFAULT_TIMEOUT_MS, DEFAULT_MAX_BODY_BYTES, TRANSIENT_NEGATIVE_TTL_MS, fetchOneRoute, reasonToCode,
  describeOutcome, isTransientFailure, throttledPeerWarn, type PeerOverviewErrorCode,
} from './fleet-fetch-through.js';
import {
  READ_ROUTE_NAMES, READ_STREAM_CHANNELS,
  type ReadRouteName, type ReadStreamChannel,
} from '../types/read-contract.js';

type FetchImpl = typeof fetch;
type AnyObj = Record<string, unknown>;

// ── Route parsing + allowlisting (P1-035) ────────────────────────────────

const NODE_READ_PATH_RE = /^\/api\/node\/([a-z0-9-]{1,32})\/read\/([a-z-]{1,40})$/;

export interface NodeReadPath {
  label: string;
  route: string;
}

/** Pure extraction of `:label` and `:route` from
 *  `/api/node/:label/read/:route`, or null if the path doesn't match at
 *  all. Both segments use a CLOSED character class — the same discipline
 *  parseNodeOverviewLabel (fleet-fetch-through.ts) already applies to
 *  `:label`, extended here to `:route` for the identical reason: a segment
 *  shaped like a URL, a traversal (`../admin`), or anything containing '/',
 *  ':', '.', '%', or an uppercase letter simply never matches this regex, so
 *  it can never reach isAllowedRoute below, let alone build an upstream URL.
 *  server.ts's own decodeURIComponent(url.pathname) runs BEFORE this
 *  function sees the path — a percent-encoded traversal segment is already
 *  decoded by the time it gets here, and the regex still rejects it. */
export function parseNodeReadPath(pathname: string): NodeReadPath | null {
  const m = NODE_READ_PATH_RE.exec(pathname);
  return m ? { label: m[1], route: m[2] } : null;
}

const ROUTE_SET: ReadonlySet<string> = new Set(READ_ROUTE_NAMES);

/** [P1-035] Exact-set membership against the IMPORTED READ_ROUTE_NAMES —
 *  never a regex, never a denylist, never a hand-copied list. Every JSON
 *  route server.ts and lib/read-api.ts serve, and no others: a route added to
 *  the contract becomes reachable here automatically, and nothing can be
 *  reachable here that isn't in the contract.
 *
 *  P3-040's standing rule, restated with the precision ADR 0013 gives it:
 *  **every JSON route in the contract is reachable through this proxy, and
 *  nothing else is.** The read contract's one streaming member is
 *  deliberately outside that set and has no route name — this function
 *  therefore returns false for 'stream', and must keep doing so. Everything
 *  below this line is a JSON reader: fetchOneRoute → readBoundedBody →
 *  JSON.parse never sees `done` on an event stream, so it would hold the
 *  connection for the full AbortSignal.timeout, return `peer_timeout`, and
 *  negative-cache the peer for twenty seconds. The browser reaches a peer's
 *  stream through /api/node/:label/stream instead, which NODE_READ_PATH_RE's
 *  required `/read/` segment structurally cannot match. */
export function isAllowedRoute(route: string): route is ReadRouteName {
  return ROUTE_SET.has(route);
}

// ── The streaming member: its own path, its own allowlist (ADR 0013) ──────

const NODE_STREAM_PATH_RE = /^\/api\/node\/([a-z0-9-]{1,32})\/stream$/;

const CHANNEL_SET: ReadonlySet<string> = new Set(READ_STREAM_CHANNELS);

/** Pure extraction of `:label` from `/api/node/:label/stream` — one segment
 *  SHORTER than the JSON proxy's path, and shorter on purpose: the JSON
 *  proxy is structurally never in this request's path rather than being told
 *  to skip it. Same closed character class for the label. */
export function parseNodeStreamLabel(pathname: string): string | null {
  const m = NODE_STREAM_PATH_RE.exec(pathname);
  return m ? m[1] : null;
}

/** The requested channels, or null when any of them is not a contract
 *  channel. Exact-set membership against the IMPORTED READ_STREAM_CHANNELS,
 *  the same discipline isAllowedRoute applies to route names — the peer's own
 *  gate validates them again, and this one exists so an unknown channel never
 *  costs an outbound connection. */
export function parseStreamChannels(raw: string | null): ReadStreamChannel[] | null {
  const requested = (raw ?? '').split(',').map((c) => c.trim()).filter((c) => c !== '');
  if (requested.length === 0) return null;
  for (const c of requested) if (!CHANNEL_SET.has(c)) return null;
  return [...new Set(requested)] as ReadStreamChannel[];
}

// ── Param forwarding (P2-037) ────────────────────────────────────────────

// The exact key set the review's Q2 names, confirmed against every route's
// own parameters in server.ts's /read/v1 switch: history (metric, range,
// agg), recent (metric, limit), ledgers (limit, OR around + span),
// agreement (since_ms), missed-ledgers (limit), alerts (since_ms, limit),
// digests (since_ms, limit), bandwidth (limit). Structured via
// URLSearchParams below, never string concatenation — and the token stays
// an Authorization header, never a query param, so nothing forwarded here
// can become or shadow it.
const PARAM_ALLOWLIST = ['metric', 'limit', 'range', 'agg', 'since_ms', 'around', 'span'] as const;

/** Builds the forwarded query from an incoming request's own
 *  URLSearchParams, keeping only the allowlisted keys and dropping
 *  everything else — the peer's own /read/v1 dispatch remains the VALUE
 *  validator (VALID_METRICS, VALID_RANGES, num()'s clamping); this is a key
 *  allowlist, not a value one. */
export function forwardableParams(incoming: URLSearchParams): URLSearchParams {
  const out = new URLSearchParams();
  for (const key of PARAM_ALLOWLIST) {
    const v = incoming.get(key);
    if (v !== null) out.set(key, v);
  }
  return out;
}

/** Stable string form of an already-forwardable param set, sorted by key so
 *  `?limit=5&since_ms=1` and `?since_ms=1&limit=5` collapse to the same
 *  cache key rather than forking two entries for one logical request
 *  (PeerReadProxy's cache key, P2-039). */
function sortedParamKey(params: URLSearchParams): string {
  return [...params.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('&');
}

// ── Per-route body cap (P2-038) ───────────────────────────────────────────

// DEFAULT_MAX_BODY_BYTES (fleet-fetch-through.ts, 262_144) was sized for
// three small, computed bodies. Two routes this proxy newly exposes
// legitimately exceed it:
//   agreement?since_ms — up to the 2-day retention the route itself states
//   (server.ts's RETAINED_MS), roughly 25,000-50,000 rows of
//   { ledger_index, our_voted, ts } at a ~3.5s close time — low single-digit
//   megabytes. 8 MiB is generous headroom over that, sized to bound a
//   garbage/compromised peer's stream, not to fit the legitimate body
//   tightly (same intent DEFAULT_MAX_BODY_BYTES itself states).
//   alerts?limit=500 — up to 500 rows each carrying a delivery/channels
//   object, materially larger per-row than the other bounded routes. 2 MiB
//   is generous headroom over that.
// A route not listed here keeps the slice-2 default — none of the others
// (recent/500 points, ledgers/500 rows, missed-ledgers/500 rows,
// digests/200 rows, bandwidth/24 rows, identity/node-status/peers/
// validation-summary) approach it.
const ROUTE_MAX_BODY_BYTES: Partial<Record<ReadRouteName, number>> = {
  agreement: 8 * 1024 * 1024,
  alerts: 2 * 1024 * 1024,
};

export function maxBodyBytesFor(route: ReadRouteName): number {
  return ROUTE_MAX_BODY_BYTES[route] ?? DEFAULT_MAX_BODY_BYTES;
}

// ── The fetch itself: companion pin check (P1-036) + the requested route ──

export type PeerReadErrorCode = PeerOverviewErrorCode; // same closed set — see fleet-fetch-through.ts

export interface PeerReadOk {
  ok: true;
  body: unknown;
}
export interface PeerReadError {
  ok: false;
  error: PeerReadErrorCode;
}
export type PeerReadResult = PeerReadOk | PeerReadError;

function logUpstreamFailure(label: string, route: string, detail: string): void {
  throttledPeerWarn('peer-read-proxy', label, route, detail);
}

/**
 * [P1-036] The pin, on its own, so there is exactly ONE of it. For a pinned
 * row every request first fetches `identity` on the same origin+token and
 * demands an affirmative `pubkey_node === expected_pubkey_node` match; fail
 * closed on anything short of that — unreachable, timed out, bad response, or
 * a present-but-wrong/absent pubkey_node are all a named error, never a
 * served body.
 *
 * Extracted from fetchPeerRoute so the streaming path (ADR 0013, decision 2)
 * runs the SAME rule rather than a lenient variant of it before it opens an
 * upstream stream. A stream gets one pin check at connect where a poll gets
 * one every two seconds, which is exactly why the node closes a stream after
 * a bounded lifetime: the reconnect re-runs this function, so pin
 * re-verification has a floor rather than depending on something going wrong.
 */
export async function verifyPeerPin(
  node: FleetNodeConfig,
  token: string,
  timeoutMs: number,
  doFetch: FetchImpl,
): Promise<{ ok: true } | PeerReadError> {
  const v = await verifyPeerPinDetailed(node, token, timeoutMs, doFetch);
  return v.ok ? v : { ok: false, error: v.error };
}

type PinVerdict = { ok: true } | { ok: false; error: PeerReadErrorCode; transient: boolean };

async function verifyPeerPinDetailed(
  node: FleetNodeConfig,
  token: string,
  timeoutMs: number,
  doFetch: FetchImpl,
): Promise<PinVerdict> {
  if (!node.expected_pubkey_node) return { ok: true };
  const idOutcome = await fetchOneRoute(node.read_origin, token, 'identity', timeoutMs, DEFAULT_MAX_BODY_BYTES, doFetch);
  if (!idOutcome.ok) {
    logUpstreamFailure(node.label, 'identity', describeOutcome(idOutcome));
    return { ok: false, error: reasonToCode(idOutcome.reason), transient: isTransientFailure(idOutcome, node.transport) };
  }
  const idBody = idOutcome.body as AnyObj;
  const observed = typeof idBody.pubkey_node === 'string' ? idBody.pubkey_node : '';
  if (!observed || observed !== node.expected_pubkey_node) {
    logUpstreamFailure(node.label, 'identity', 'pin mismatch or unconfirmed on the serve path');
    return { ok: false, error: 'peer_integrity_mismatch', transient: false };
  }
  return { ok: true };
}

// ── The pin, remembered for a few seconds (#831) ──────────────────────────

export interface PeerPinCacheOpts {
  /** How long a CONFIRMED pin is reused. Short on purpose: it bounds how long
   *  a loopback origin that started answering for a different host could go
   *  unnoticed, on a transport the hub cannot see (a tunnel). */
  ttlMs?: number;
  /** Entry cap. One per pinned row in practice; a safety valve. */
  maxEntries?: number;
  /** The fleet link's generation for a label (the hub bumps it whenever a
   *  link comes up or goes down). A confirmation made under one generation
   *  is never reused under another, so a reconnect always pins again. A
   *  tunnel row has no link and reads a constant. */
  generation?: (label: string) => number;
  now?: () => number;
}

export const DEFAULT_PIN_TTL_MS = 5_000;
const DEFAULT_PIN_MAX_ENTRIES = 256;

/**
 * A confirmed P1-036 pin, reused for a few seconds by the READ paths only.
 *
 * Before this, every proxied read was two link round trips in sequence: the
 * identity check, then the route. The Advisor tab's first view is thirteen
 * of those at once, and on a lab aggregator that doubled the load on the one
 * link that then stalled (#831). The rule itself does not change: a read is
 * served only after this origin affirmatively answered with the pinned key,
 * now "within the last few seconds, on this link generation" rather than
 * "on this exact request".
 *
 * What does NOT use it: the writes (seal, update, attach, proposal marks,
 * fleet records, an ask) and the stream. Each of those runs verifyPeerPin
 * fresh, because what it sends is not something to send on the strength of
 * an answer from five seconds ago.
 *
 * Only a success is kept, and any failed check drops the label's entry at
 * once. Inside the window there is no check to fail, so the callers drop the
 * entry themselves on any failed read through it (a different host on a
 * re-pointed tunnel answers this dashboard's token with a 401). That, and
 * the few seconds, is the invalidation a tunnel gets; the hub's generation
 * covers a link.
 */
export class PeerPinCache {
  private readonly entries = new Map<string, { at: number; generation: number }>();
  /** One check in flight per (row, generation): the Advisor tab's first view
   *  is thirteen reads at once, and without this all thirteen race to pin
   *  before the first confirmation lands. */
  private readonly checking = new Map<string, Promise<PinVerdict>>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly generation: (label: string) => number;
  private readonly now: () => number;

  constructor(opts: PeerPinCacheOpts = {}) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_PIN_TTL_MS;
    this.maxEntries = opts.maxEntries ?? DEFAULT_PIN_MAX_ENTRIES;
    this.generation = opts.generation ?? (() => 0);
    this.now = opts.now ?? Date.now;
  }

  private key(node: FleetNodeConfig): string {
    return `${node.label}\n${node.read_origin}\n${node.expected_pubkey_node ?? ''}`;
  }

  async verify(node: FleetNodeConfig, token: string, timeoutMs: number, doFetch: FetchImpl): Promise<PinVerdict> {
    if (!node.expected_pubkey_node) return { ok: true };
    const key = this.key(node);
    // Captured BEFORE the check, and stored under this value: a check that
    // straddles a reconnect must not vouch for the link that came up after
    // it started.
    const generation = this.generation(node.label);
    const hit = this.entries.get(key);
    if (hit && hit.generation === generation && this.now() - hit.at < this.ttlMs) return { ok: true };
    // The timeout is part of the key: the Advisor pins with 10 s and the
    // read proxy with 4 s, and a read that joined an Advisor's check would
    // wait past its own bound in exactly the slow-node case this is for.
    const flightKey = `${key}\n${generation}\n${timeoutMs}`;
    const running = this.checking.get(flightKey);
    if (running) return running;
    const check = verifyPeerPinDetailed(node, token, timeoutMs, doFetch)
      .finally(() => { this.checking.delete(flightKey); });
    this.checking.set(flightKey, check);
    const verdict = await check;
    if (!verdict.ok) {
      this.invalidate(node.label);
      return verdict;
    }
    this.entries.delete(key);
    this.entries.set(key, { at: this.now(), generation });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    return verdict;
  }

  /** Forget every confirmation held for this label. */
  invalidate(label: string): void {
    for (const k of [...this.entries.keys()]) if (k.startsWith(`${label}\n`)) this.entries.delete(k);
  }

  size(): number { return this.entries.size; }
}

export interface FetchPeerRouteOpts {
  timeoutMs: number;
  maxBodyBytes: number;
  fetchImpl?: FetchImpl;
  /** Reuse a recent confirmed pin (#831). Absent: pin on this request. */
  pinCache?: PeerPinCache;
}

/**
 * One fetch attempt for one (route, params) pair against one peer. `route`
 * MUST already be a validated ReadRouteName — this function trusts its
 * caller (server.ts, via isAllowedRoute) exactly the way fetchFromPeer
 * trusts its own hardcoded route literals; it does not re-check the
 * allowlist itself.
 *
 * [P1-036] For a pinned row, the identity companion check happens on every
 * call, regardless of which route was actually requested, see this
 * module's doc comment for why no route is special-cased to skip it. With
 * `pinCache` (#831) that check may be answered by a confirmation from the
 * last few seconds on the same link generation instead of a new fetch. Fail
 * closed on anything short of an affirmative match: unreachable, timed out,
 * bad response, or a present-but-wrong/absent pubkey_node are all
 * `peer_integrity_mismatch` or a transport code, never a served body.
 */
export async function fetchPeerRoute(
  node: FleetNodeConfig,
  route: ReadRouteName,
  params: URLSearchParams,
  opts: FetchPeerRouteOpts,
): Promise<PeerReadResult> {
  return (await fetchPeerRouteDetailed(node, route, params, opts)).result;
}

/** fetchPeerRoute plus whether a failure was transient (#831), kept off the
 *  result object for the same reason as fleet-fetch-through.ts's copy. */
async function fetchPeerRouteDetailed(
  node: FleetNodeConfig,
  route: ReadRouteName,
  params: URLSearchParams,
  opts: FetchPeerRouteOpts,
): Promise<{ result: PeerReadResult; transient: boolean }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const token = readTokenFresh(node.token_path);
  if (!token) {
    logUpstreamFailure(node.label, route, 'token unreadable');
    return { result: { ok: false, error: 'peer_unreachable' }, transient: false };
  }

  const pinned = opts.pinCache
    ? await opts.pinCache.verify(node, token, opts.timeoutMs, doFetch)
    : await verifyPeerPinDetailed(node, token, opts.timeoutMs, doFetch);
  if (!pinned.ok) return { result: { ok: false, error: pinned.error }, transient: pinned.transient };

  const outcome = await fetchOneRoute(node.read_origin, token, route, opts.timeoutMs, opts.maxBodyBytes, doFetch, params);
  if (!outcome.ok) {
    // See PeerPinCache: a confirmation is not reused past a failed read.
    opts.pinCache?.invalidate(node.label);
    logUpstreamFailure(node.label, route, describeOutcome(outcome));
    return {
      result: { ok: false, error: reasonToCode(outcome.reason) },
      transient: isTransientFailure(outcome, node.transport),
    };
  }
  return { result: { ok: true, body: outcome.body }, transient: false };
}

// ── PeerReadProxy: bounded cache + single-flight (P2-039) ────────────────

export interface PeerReadProxyOpts {
  timeoutMs?: number;
  positiveTtlMs?: number;
  negativeTtlMs?: number;
  /** A transient failure's window (#831): one peer poll at most. */
  transientTtlMs?: number;
  /** Shared with the Advisor read proxy, so one confirmation serves both. */
  pinCache?: PeerPinCache;
  fetchImpl?: FetchImpl;
  /** Hard cap on distinct (label, route, params) cache entries — bounds the
   *  now caller-controlled key space (P2-039: a caller varying `since_ms`/
   *  `around` must not grow the cache without limit). FIFO eviction by
   *  insertion order (a plain Map's own iteration order), not true LRU —
   *  sufficient to bound growth; this is a safety valve, not a hit-rate
   *  optimization. */
  maxEntries?: number;
  now?: () => number;
}

const DEFAULT_NEGATIVE_TTL_MS = 20_000; // same as FleetFetchThrough — one poll cadence
const DEFAULT_POSITIVE_TTL_MS = 3_000;  // same as FleetFetchThrough
const DEFAULT_MAX_ENTRIES = 500;

/**
 * Per-(resolved row, route, params) cache + single-flight coalescing, the
 * generalization of FleetFetchThrough for an arbitrary route. Keyed by the
 * RESOLVED FleetNodeConfig's label (never a raw string from the request —
 * server.ts looks `:label` up against the resolved peers array exactly as
 * slice 2 does before this class ever sees it, P2-032 unchanged) plus the
 * route name plus the SORTED forwarded params, so `?since_ms=1&limit=5` and
 * `?limit=5&since_ms=1` share one entry rather than forking two.
 *
 * A fresh instance on every fleet reload (server.ts's loadFleetConfig,
 * same "restart, not diff" discipline FleetFetchThrough and
 * FleetHealthPoller already use) — never reused or diffed, so a renamed
 * label can never find a stale entry from a previous instance.
 */
export class PeerReadProxy {
  private readonly cache = new Map<string, { result: PeerReadResult; expiresAtMs: number }>();
  private readonly inflight = new Map<string, Promise<PeerReadResult>>();
  private readonly timeoutMs: number;
  private readonly positiveTtlMs: number;
  private readonly negativeTtlMs: number;
  private readonly transientTtlMs: number;
  private readonly pinCache?: PeerPinCache;
  private readonly maxEntries: number;
  private readonly fetchImpl?: FetchImpl;
  private readonly now: () => number;

  constructor(opts: PeerReadProxyOpts = {}) {
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.positiveTtlMs = opts.positiveTtlMs ?? DEFAULT_POSITIVE_TTL_MS;
    this.negativeTtlMs = opts.negativeTtlMs ?? DEFAULT_NEGATIVE_TTL_MS;
    this.transientTtlMs = opts.transientTtlMs ?? TRANSIENT_NEGATIVE_TTL_MS;
    this.pinCache = opts.pinCache;
    this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.fetchImpl = opts.fetchImpl;
    this.now = opts.now ?? Date.now;
  }

  private key(label: string, route: string, params: URLSearchParams): string {
    return `${label} ${route} ${sortedParamKey(params)}`;
  }

  async get(node: FleetNodeConfig, route: ReadRouteName, params: URLSearchParams): Promise<PeerReadResult> {
    const key = this.key(node.label, route, params);

    const cached = this.cache.get(key);
    if (cached && cached.expiresAtMs > this.now()) return cached.result;

    // Single-flight is keyed identically to the cache (label + route +
    // params) — NOT by label alone. Coalescing two DIFFERENT routes (or the
    // same route with different params) for one peer into a single shared
    // promise would hand one caller another caller's answer.
    const existing = this.inflight.get(key);
    if (existing) return existing;

    const promise = fetchPeerRouteDetailed(node, route, params, {
      timeoutMs: this.timeoutMs,
      maxBodyBytes: maxBodyBytesFor(route),
      fetchImpl: this.fetchImpl,
      pinCache: this.pinCache,
    }).then(({ result, transient }) => {
      // Stamped at RESOLUTION, not at call time — same reasoning as
      // FleetFetchThrough.getOverview: a slow failure must get a full
      // negative-cache window measured from when it actually failed.
      const ttl = result.ok ? this.positiveTtlMs : transient ? this.transientTtlMs : this.negativeTtlMs;
      this.cache.set(key, { result, expiresAtMs: this.now() + ttl });
      this.evictIfNeeded();
      return result;
    }).finally(() => { this.inflight.delete(key); });

    this.inflight.set(key, promise);
    return promise;
  }

  private evictIfNeeded(): void {
    // Map iteration order is insertion order; re-setting an EXISTING key
    // (a cache refresh) does not move it — approximate FIFO, not LRU, which
    // is sufficient for a safety valve rather than a hit-rate optimization.
    while (this.cache.size > this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey === undefined) break;
      this.cache.delete(oldestKey);
    }
  }
}
