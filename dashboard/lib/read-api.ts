/**
 * The read-surface gate — ADR 0008, decision 3.
 *
 * Pure decision logic for requests under /read/, separated from the server so
 * the ordering guarantees can be asserted by unit tests. The ordering is
 * load-bearing and a later refactor can undo it without any behaviour test
 * noticing, so the three assertions the ADR names live in
 * test/unit/read-api.test.ts:
 *
 *   1. a no-cookie, no-token request to a read endpoint gets 401;
 *   2. a no-cookie, valid-token request from a non-loopback address is
 *      rejected — the socket check runs before the token is even considered;
 *   3. a valid token satisfies nothing outside /read/ — the routes are an
 *      exact set, and /api/advisor/ledger-witness is not in it. That route is
 *      the operator's, and the token must not widen into it.
 *
 * ADR 0013 adds one streaming member (/read/v1/stream) to this same gate
 * rather than a gateReadStream() beside it, for the reason above: the
 * ordering IS the security property, and a second copy of it is the drift
 * this comment warns about. gateRead therefore returns a discriminated
 * decision — 'route' or 'stream' — and only the final membership test forks.
 *
 * The token check sits BEFORE the session auth gate in server.ts and is
 * scoped to these routes only. It must never become a general "valid token
 * satisfies the auth gate" bypass, and these paths must never be added to
 * isPublicPath — that would open them to the internet rather than to
 * loopback plus a valid token.
 */

import { timingSafeEqual, createHash } from 'node:crypto';
import {
  READ_PROTOCOL_VERSION, READ_ROUTE_NAMES, READ_STREAM_CHANNELS,
  type ReadRouteName, type ReadStreamChannel, type ReadErrorBody,
} from '../types/read-contract.js';

const ROUTE_SET: ReadonlySet<string> = new Set(READ_ROUTE_NAMES);
const CHANNEL_SET: ReadonlySet<string> = new Set(READ_STREAM_CHANNELS);

/** The one path under /read/ that is NOT a route name (ADR 0013, decision
 *  1). Matched by READ_PATH_RE's own [a-z-] class like any other segment —
 *  the version check and everything before it therefore apply to the stream
 *  unchanged, and only the final membership test forks. */
const STREAM_SEGMENT = 'stream';

/** /read/v<N>/<route> — anything else under /read/ is unknown_read_path. */
const READ_PATH_RE = /^\/read\/v(\d{1,3})\/([a-z-]{1,40})$/;

export function isReadPath(pathname: string): boolean {
  return pathname === '/read' || pathname.startsWith('/read/');
}

function isLoopback(remoteAddress: string | undefined): boolean {
  if (!remoteAddress) return false;
  return remoteAddress === '127.0.0.1'
      || remoteAddress === '::1'
      || remoteAddress === '::ffff:127.0.0.1';
}

/** Constant-time equality over hashes, so unequal lengths leak nothing. */
function tokenMatches(presented: string, expected: string): boolean {
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

export type ReadGateDecision =
  | { ok: true; kind: 'route'; route: ReadRouteName }
  | { ok: true; kind: 'stream'; channels: ReadStreamChannel[] }
  | { ok: false; status: number; body: ReadErrorBody };

export interface ReadGateInput {
  method: string;
  pathname: string;
  remoteAddress: string | undefined;
  /** The Authorization header, verbatim (or undefined). */
  authorization: string | undefined;
  /**
   * The expected token as read from disk for THIS request — null when the
   * token file is absent or unreadable, which disables the surface. Read per
   * request, never cached, so rotation needs no restart.
   */
  expectedToken: string | null;
  /**
   * The raw `?channels=` value for a stream request (comma-separated), or
   * undefined. Optional so every existing caller and every existing test
   * case constructs this input unchanged — a JSON route never reads it.
   */
  channels?: string | undefined;
}

export function gateRead(input: ReadGateInput): ReadGateDecision {
  const err = (status: number, body: ReadErrorBody): ReadGateDecision => ({ ok: false, status, body });

  // The socket first. A header is forgeable; the remote address of the
  // accepted connection is not. Nothing else is evaluated for a caller that
  // is not on this host — including whether its token would have been valid.
  if (!isLoopback(input.remoteAddress)) {
    return err(403, { error: 'not_loopback' });
  }

  // No token on disk means the operator (or an installer) removed it:
  // the surface is off. Distinct from 401 so a misconfigured host reads as
  // "disabled", not as "wrong credentials".
  if (input.expectedToken === null || input.expectedToken.length < 32) {
    return err(403, { error: 'read_surface_disabled' });
  }

  if (input.method !== 'GET') {
    return err(405, { error: 'method_not_allowed' });
  }

  const m = READ_PATH_RE.exec(input.pathname);
  if (!m) {
    return err(404, { error: 'unknown_read_path' });
  }
  const version = Number(m[1]);
  if (version !== READ_PROTOCOL_VERSION) {
    // Named, never silent — the divergence from the relay contract's
    // behaviour is deliberate (ADR 0008, decision 4).
    return err(400, {
      error: 'protocol_version_unsupported',
      server_version: READ_PROTOCOL_VERSION,
      requested_version: version,
    });
  }
  const route = m[2];

  // The one fork (ADR 0013, decision 3). Everything above is the ordering
  // this module's doc comment calls load-bearing, and the stream inherits it
  // unchanged rather than getting a second copy of it: a non-loopback caller
  // is still refused on its socket, a missing token file still reads as
  // "disabled", a POST is still 405, and /read/v2/stream still gets the
  // named protocol_version_unsupported BEFORE a socket is ever held open.
  if (route === STREAM_SEGMENT) {
    const requested = (input.channels ?? '').split(',').map((c) => c.trim()).filter((c) => c !== '');
    if (requested.length === 0) {
      return err(400, { error: 'bad_request', detail: 'stream requires ?channels=' });
    }
    // Named, per channel — never a connection that opens and then delivers
    // nothing, which is the silent-drop failure ADR 0008 decision 4 refused.
    // Checked in the slot the route-membership test occupies for a JSON
    // route, so an unknown channel answers the same way an unknown route
    // does: before the token is considered.
    for (const c of requested) {
      if (!CHANNEL_SET.has(c)) {
        return err(400, { error: 'bad_request', detail: 'unknown stream channel: ' + c });
      }
    }
    const presentedForStream = (input.authorization ?? '').replace(/^Bearer\s+/i, '');
    if (!presentedForStream || !tokenMatches(presentedForStream, input.expectedToken)) {
      return err(401, { error: 'unauthorized' });
    }
    // De-duplicated, so ?channels=a,a subscribes once.
    return { ok: true, kind: 'stream', channels: [...new Set(requested)] as ReadStreamChannel[] };
  }

  if (!ROUTE_SET.has(route)) {
    return err(404, { error: 'unknown_read_path' });
  }

  const presented = (input.authorization ?? '').replace(/^Bearer\s+/i, '');
  if (!presented || !tokenMatches(presented, input.expectedToken)) {
    return err(401, { error: 'unauthorized' });
  }

  return { ok: true, kind: 'route', route: route as ReadRouteName };
}
