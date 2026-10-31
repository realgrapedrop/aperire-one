/**
 * The aggregator's leg of the read API's one streaming channel — ADR 0013,
 * decision 2. A byte forward, nothing more: the browser asks this box for a
 * peer's stream, this box pins the peer, opens the peer's own
 * /read/v1/stream through the tunnel with the per-peer token, and relays what
 * comes back untouched. It never generates a tick, never interpolates a
 * missing one, and never smooths — if nothing arrives, nothing is painted.
 *
 * A SIBLING of lib/peer-read-proxy.ts, not part of it, and deliberately not
 * built on fetchOneRoute/readBoundedBody: those are the JSON reader, and a
 * JSON reader on an event stream never sees `done`. It would hold the
 * connection for the full AbortSignal.timeout(4000), report `peer_timeout`,
 * and negative-cache the peer for twenty seconds. The pin check IS shared
 * (verifyPeerPin), because that rule must have exactly one implementation.
 *
 * The connect deadline is on the HEADERS only. Once the peer has answered
 * 200, there is no total timeout by design — a stream that lasts is the
 * point. Three things end it: the browser disconnecting (the caller's
 * AbortSignal), the peer's own lifetime cap closing it (which is what forces
 * the reconnect that re-runs the pin check), and a transport failure.
 */
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFileExplained, tokenUnreadableDetail, tokenUnreadableLog, isRefusedStatus } from './fleet-health.js';
import { DEFAULT_TIMEOUT_MS, readBoundedBody } from './fleet-fetch-through.js';
import { verifyPeerPin, type PeerReadErrorCode } from './peer-read-proxy.js';
import { READ_STREAM_PATH, type ReadStreamChannel } from '../types/read-contract.js';
import { FLEET_LINK_STREAM_REFUSAL } from '../types/fleet-link-contract.js';

type FetchImpl = typeof fetch;

export interface PeerStreamOpenOk {
  ok: true;
  /** The upstream event-stream body, to be pumped by relayPeerStream. */
  body: ReadableStream<Uint8Array>;
}
export interface PeerStreamOpenError {
  ok: false;
  error: PeerReadErrorCode;
  /** Only on `token_unreadable`: this host's sentence about its own file. */
  detail?: string;
  /** The peer's own status when it answered but refused (its stream
   *  concurrency cap, say) — carried so the browser is told which end said
   *  no, rather than a generic "bad response". */
  upstreamStatus?: number;
  /** The peer is reached by a transport that does not carry the stream at
   *  all: the fleet link answers 501 FLEET_LINK_STREAM_REFUSAL by design
   *  (#831). A capability, not a failure, so the browser is told so in its
   *  own words and stops asking, rather than reading a 502 and retrying
   *  every few seconds for as long as the view is open. */
  notSupported?: boolean;
}
export type PeerStreamOpenResult = PeerStreamOpenOk | PeerStreamOpenError;

export interface OpenPeerStreamOpts {
  /** Aborted when the BROWSER goes away. Propagated to the upstream fetch so
   *  a closed tab releases the peer's connection slot immediately rather
   *  than at its lifetime cap. */
  signal: AbortSignal;
  connectTimeoutMs?: number;
  fetchImpl?: FetchImpl;
  /** Injected clock for the capability cache's TTL. */
  now?: () => number;
}

/** How long a peer's "this transport carries no stream" answer is believed
 *  without asking again (#831). Within it every open for that peer answers
 *  from here, with no pin check and no upstream request, so N tabs (or one
 *  tab's probe beside its EventSource) cost the link nothing after the
 *  first answer. Short, so a node moved off the link is streamed again
 *  within one window. Keyed by label AND origin: a fleet reload that points
 *  a label somewhere else is a different key. Entries are bounded by the
 *  fleet registry's rows, and expired ones are dropped on read. */
export const STREAM_NOT_SUPPORTED_TTL_MS = 30_000;
const notSupportedUntil = new Map<string, number>();
const capabilityKey = (node: FleetNodeConfig) => `${node.label}\u0000${node.read_origin}`;
/** Test seam: forget every remembered capability answer. */
export function resetStreamCapabilityCache(): void { notSupportedUntil.clear(); }

/** The 501's body is read for its code, and both the read and the caller's
 *  disconnect are on a clock: a peer that sends the headers and then drips
 *  (or never ends) the body must not hold this request open. */
const NOT_SUPPORTED_BODY_MAX = 4096;

export async function openPeerStream(
  node: FleetNodeConfig,
  channels: readonly ReadStreamChannel[],
  opts: OpenPeerStreamOpts,
): Promise<PeerStreamOpenResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const connectTimeoutMs = opts.connectTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = opts.now ?? Date.now;

  const known = notSupportedUntil.get(capabilityKey(node));
  if (known !== undefined) {
    if (known > now()) return { ok: false, error: 'peer_bad_response', upstreamStatus: 501, notSupported: true };
    notSupportedUntil.delete(capabilityKey(node));
  }

  const tokenRead = readTokenFileExplained(node.token_path);
  if (!tokenRead.ok) {
    console.warn(`[peer-stream-proxy] ${node.label}: token unreadable: ${tokenUnreadableLog(tokenRead)}`);
    // #1305: its own answer, not peer_unreachable. Nothing was sent.
    return { ok: false, error: 'token_unreadable', detail: tokenUnreadableDetail(node.label, 'read', tokenRead) };
  }
  const token = tokenRead.token;

  // The pin BEFORE the stream opens, and the same rule the JSON proxy runs
  // on every single request — not a lenient variant of it.
  const pinned = await verifyPeerPin(node, token, connectTimeoutMs, doFetch);
  if (!pinned.ok) return { ok: false, error: pinned.error };

  const controller = new AbortController();
  const onCallerAbort = () => controller.abort();
  if (opts.signal.aborted) return { ok: false, error: 'peer_unreachable' };
  opts.signal.addEventListener('abort', onCallerAbort, { once: true });

  // Headers-only deadline: cleared the moment the peer answers, so the
  // stream itself is never on a clock.
  let connectTimer: NodeJS.Timeout | null = setTimeout(() => controller.abort(), connectTimeoutMs);
  const clearConnectTimer = () => {
    if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
  };

  const url = `${node.read_origin}${READ_STREAM_PATH}?channels=${encodeURIComponent(channels.join(','))}`;
  let res: Response;
  try {
    res = await doFetch(url, {
      method: 'GET',
      headers: { authorization: `Bearer ${token}`, accept: 'text/event-stream' },
      signal: controller.signal,
    });
  } catch (err) {
    clearConnectTimer();
    opts.signal.removeEventListener('abort', onCallerAbort);
    const timedOut = (err as Error)?.name === 'AbortError' && !opts.signal.aborted;
    console.warn(`[peer-stream-proxy] ${node.label}: ${timedOut ? 'connect timeout' : 'unreachable'}`);
    return { ok: false, error: timedOut ? 'peer_timeout' : 'peer_unreachable' };
  }
  clearConnectTimer();

  if (res.status === 501) {
    // Read the one small JSON answer rather than cancelling it: its error
    // code is what tells a transport without the stream apart from a peer
    // that broke. Bounded, because a peer can answer 501 with anything.
    // The caller's abort stays wired through this read, and the read has the
    // same deadline the headers had.
    const bodyTimer = setTimeout(() => controller.abort(), connectTimeoutMs);
    let code = '';
    try {
      const text = await readBoundedBody(res, NOT_SUPPORTED_BODY_MAX);
      const body = JSON.parse(text) as { error?: unknown };
      code = typeof body.error === 'string' ? body.error : '';
    } catch {
      /* not the hub's answer, too slow, or the browser left; an ordinary refusal */
      try { await res.body?.cancel(); } catch { /* already gone */ }
    } finally {
      clearTimeout(bodyTimer);
      opts.signal.removeEventListener('abort', onCallerAbort);
    }
    if (code === FLEET_LINK_STREAM_REFUSAL) {
      notSupportedUntil.set(capabilityKey(node), now() + STREAM_NOT_SUPPORTED_TTL_MS);
      console.log(`[peer-stream-proxy] ${node.label}: the fleet link does not carry the event stream; the browser polls instead`);
      return { ok: false, error: 'peer_bad_response', upstreamStatus: 501, notSupported: true };
    }
    console.warn(`[peer-stream-proxy] ${node.label}: upstream stream refused (501)`);
    return { ok: false, error: 'peer_bad_response', upstreamStatus: 501 };
  }
  if (!res.ok || !res.body) {
    opts.signal.removeEventListener('abort', onCallerAbort);
    try { await res.body?.cancel(); } catch { /* already gone */ }
    console.warn(`[peer-stream-proxy] ${node.label}: upstream stream refused (${res.status})`);
    // 401/403 is the peer rejecting this dashboard's read token, the same
    // fact the poller and the JSON proxy now carry as its own (#268). A
    // stream that will not open because the credential is stale is not the
    // peer being broken, and the browser's own fallback reads the code.
    return {
      ok: false,
      error: isRefusedStatus(res.status) ? 'peer_refused' : 'peer_bad_response',
      upstreamStatus: res.status,
    };
  }
  const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
  if (!ctype.includes('text/event-stream')) {
    // An un-upgraded peer answers 404 JSON here, which the !res.ok branch
    // already caught; this catches the stranger case of a 200 that is not a
    // stream at all. Refused rather than pumped into an EventSource that
    // would silently never fire an event.
    opts.signal.removeEventListener('abort', onCallerAbort);
    try { await res.body.cancel(); } catch { /* already gone */ }
    console.warn(`[peer-stream-proxy] ${node.label}: upstream answered 200 but not an event stream (${ctype || 'no content-type'})`);
    return { ok: false, error: 'peer_bad_response', upstreamStatus: res.status };
  }

  return { ok: true, body: res.body };
}

export interface RelaySink {
  write(chunk: Uint8Array): boolean;
  end(): void;
}

/**
 * Pumps upstream bytes to the browser verbatim until either end closes.
 * Resolves when the relay is over, for any reason — the caller ends its own
 * response, so a peer that closes at its lifetime cap becomes a closed
 * browser connection, which becomes an EventSource reconnect, which becomes
 * a fresh pin check. That chain is the design, not a fallback.
 */
export async function relayPeerStream(body: ReadableStream<Uint8Array>, sink: RelaySink): Promise<void> {
  const reader = body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) sink.write(value);
    }
  } catch {
    // A read that throws is the tunnel or the peer going away mid-stream;
    // ending the browser's response is the honest report of it, and the
    // client's own missed-tick deadline has already stopped trusting the
    // bar by the time this lands.
  } finally {
    // cancel() REJECTS, it does not throw, so the old `try/catch` around it
    // never saw anything (#334). On the ordinary browser-disconnect path the
    // caller's abort has already ERRORED this stream, and cancelling an
    // errored stream hands back a promise rejected with the error it stored
    // — the AbortError the disconnect raised. Nothing owned that promise, so
    // Node logged an unhandled rejection on every navigation away from a
    // streaming page. This is the one place that owns it: a caller abort is
    // the normal end of a stream, not a failure, and it is swallowed here
    // the same way a mid-stream read failure already is. The cancel is
    // awaited AFTER sink.end() so the browser's response still ends at the
    // same moment it always did.
    const released = reader.cancel().catch(() => { /* caller gone, or the peer already hung up */ });
    sink.end();
    await released;
  }
}
