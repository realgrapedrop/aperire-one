/**
 * What the aggregator answers the browser when a peer Advisor read failed
 * (#560, #1117, #1134).
 *
 * Lifted out of server.ts so the route and the walks that stand in for it
 * share one mapping: a walk that wrote its own status and body would test its
 * own guess, and the incident behind #1117 was exactly a status the edge
 * rewrote. In front of the aggregator, Cloudflare replaces an origin 502 or
 * 504 with its own HTML page, so neither the node's reason nor the
 * aggregator's own timeout reached the page. A 4xx is left alone, so a failure
 * that carries a reason travels on one, and the page decides by the body's
 * keys (`error`, `detail`, `upstream_status`), never by the status alone.
 */
import type { PeerAdvisorResult } from './peer-advisor-proxy.js';

export type PeerAdvisorFailure = Extract<PeerAdvisorResult, { ok: false }>;

export interface BrowserAnswer {
  status: number;
  body: Record<string, unknown>;
}

/**
 * The status an answer carries when the node's Advisor replied with an error
 * of its own (`advisor_failed`). 424 Failed Dependency: the request failed
 * because the thing it depended on, the node's host read, failed. Any 4xx
 * would pass the edge; this one says what happened.
 */
export const PEER_ADVISOR_FAILED_STATUS = 424;

/**
 * The status every peer failure that is not an answer travels on (#1134): a
 * peer read that timed out, a node that could not be reached, an identity
 * pin the browser cannot act on. These were 504 and 502, and the edge in
 * front of an aggregator replaces both with its own page, so the page read
 * "HTTP 504, an HTML page, not the dashboard" and could not tell a slow node
 * from a wall. 424 is the same Failed Dependency status the node's own
 * reason already rides (above): the request failed because the node it
 * depends on did not answer. The body's `error` says which, and the page
 * decides by that key, never by this status.
 */
export const PEER_NO_ANSWER_STATUS = PEER_ADVISOR_FAILED_STATUS;

/**
 * The one place a peer route turns a peer failure code into a status. The
 * Advisor routes (peerAdvisorFailureAnswer below) and the overview, read and
 * stream routes in server.ts all call it, so no route can drift back onto a
 * status the edge rewrites. A pin mismatch is the one answer with a status of
 * its own: the node answered, as somebody else (409).
 */
export function peerFailureStatus(error: string): number {
  return error === 'peer_integrity_mismatch' ? 409 : PEER_NO_ANSWER_STATUS;
}

/**
 * Who is asking, for the one answer that names a file on this host. The
 * `token_unreadable` sentence carries the token file's path, its owner and its
 * mode (#1209). That is the administrator's to act on and nobody else's: any
 * signed-in session, a monitor included, can read the overview, read, stream
 * and Advisor routes, and a file path is a fact about this host they have no
 * use for. So the rule is here, once, and every route that can answer
 * `token_unreadable` passes who is asking: an administrator gets the full
 * sentence, anyone else gets the code and a general one with no path, owner or
 * mode. The full sentence always goes to the server log, where the failure is
 * written (peer-advisor-proxy.ts, peer-read-proxy.ts and the others log the
 * path, owner and mode as they refuse).
 */
export interface Viewer {
  admin: boolean;
  /** The node the answer is about, for the general sentence. */
  label: string;
}

/** The sentence a session that is not an administrator gets. No path, no
 *  owner, no mode, and the way out: ask the one who can read the file. */
export function tokenUnreadableGeneral(label: string): string {
  return `This dashboard cannot read its token for ${label}, so nothing was sent to it. Ask an administrator.`;
}

/** The one place the rule is applied. `full` is the lib's sentence. */
export function tokenUnreadableFor(viewer: Viewer | undefined, full: string | undefined): string {
  if (viewer?.admin && full) return full;
  return tokenUnreadableGeneral(viewer?.label ?? 'this node');
}

/**
 * What the overview, read and stream routes answer the browser when a peer
 * read failed (#1305). The status is the one mapping above, and the body is
 * the code, plus the two things that may ride with it: `detail`, only on
 * `token_unreadable`, this host's own sentence about its own file (nothing
 * was sent to the node, so it is not an upstream's text), and the peer's
 * `upstream_status` on a stream the node refused. These routes sent
 * `{ error }` alone, so the sentence a fixed file needed never reached the
 * page and an unreadable token read as "unreachable" there.
 */
export function peerReadFailureAnswer(
  failure: { error: string; detail?: string; upstreamStatus?: number },
  viewer: Viewer,
): BrowserAnswer {
  const detail = failure.error === 'token_unreadable' ? tokenUnreadableFor(viewer, failure.detail) : failure.detail;
  return {
    status: peerFailureStatus(failure.error),
    body: {
      error: failure.error,
      ...(detail ? { detail } : {}),
      ...(failure.upstreamStatus !== undefined ? { upstream_status: failure.upstreamStatus } : {}),
    },
  };
}

/** What the edge in front of an aggregator replaces with a page of its own. */
export const EDGE_REWRITTEN_STATUSES: ReadonlySet<number> =
  new Set([502, 504, 520, 521, 522, 523, 524, 525, 526, 527]);

/** A status the browser can read: the edge's own set becomes the no-answer
 *  status, anything else is untouched. For a route that has the status and
 *  writes its own body. */
export function edgeSafeStatus(status: number): number {
  return EDGE_REWRITTEN_STATUSES.has(status) ? PEER_NO_ANSWER_STATUS : status;
}

/**
 * A response relayed from a node's Advisor, made safe for the edge (#1134). A
 * 4xx or a 2xx goes through byte for byte. A 5xx the edge would replace goes
 * as the no-answer status with its body kept and the node's own status beside
 * it in `upstream_status`, so the reason the node gave still reaches the page
 * and the page decides by the body's keys. A body that is not a JSON object
 * is not passed on: there is nothing in it the page can read, and `error`
 * says what happened.
 */
export function edgeSafeRelay(status: number, text: string): { status: number; body: string } {
  if (!EDGE_REWRITTEN_STATUSES.has(status)) return { status, body: text };
  let said: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) said = parsed as Record<string, unknown>;
  } catch { /* not JSON: the status is all there is to say */ }
  if (typeof said.error !== 'string' || !said.error) said.error = 'the Advisor answered HTTP ' + status;
  // An answer that says the Advisor failed is never a run that started or an
  // approval that was granted, whatever the body said before it failed.
  if ('started' in said) said.started = false;
  if ('granted' in said) said.granted = false;
  return { status: PEER_NO_ANSWER_STATUS, body: JSON.stringify({ ...said, upstream_status: status }) };
}

export function peerAdvisorFailureAnswer(result: PeerAdvisorFailure, viewer?: Viewer): BrowserAnswer {
  // advisor_not_configured is a SUPPORTED state, not a failure: 200 with the
  // code, so the tab renders the honest degrade without treating it as
  // transport noise worth retry and backoff.
  if (result.error === 'advisor_not_configured') {
    return { status: 200, body: { ok: false, error: result.error } };
  }
  // A 404 travels as a 404 (notFoundIsAnswer): ask-progress and runs/:id are
  // facts about a named record, not about the transport. What a runs/:id 404
  // does NOT say is that a transcript was removed (#478): a run whose first
  // line is milliseconds away answers the same 404 as a deleted one, and the
  // page decides between them against the node's ledger. advisor_refused
  // carries the peer's own status only on the carried-4xx branch (#560); the
  // fixed-status token rejection never sets one and takes the no-answer
  // status with the rest (#1134). Nothing here is a 502 or a 504: the edge
  // replaces those with a page of its own.
  const status = result.error === 'advisor_not_found' ? 404
    : result.error === 'advisor_refused' && result.status ? result.status
    : peerFailureStatus(result.error);
  return {
    status,
    body: {
      ok: false,
      error: result.error,
      // The peer's own words, when it had any (#268, #1117). A token this host
      // could not read is this host's, and names a file: for an administrator
      // only (tokenUnreadableFor), and a caller that says nothing about who is
      // asking is not one.
      ...(result.error === 'token_unreadable'
        ? { detail: tokenUnreadableFor(viewer, result.detail) }
        : result.detail ? { detail: result.detail } : {}),
      // What the node itself answered, for the page to say beside its reason.
      ...(result.error === 'advisor_failed' && result.status ? { upstream_status: result.status } : {}),
    },
  };
}
