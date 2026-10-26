/**
 * The per-node advisor read proxy — ADR 0014 slice 1.
 *
 * Extends the tab's node-binding below the strip: run history, the audit
 * trail, the plan, the checks and the service status the operator sees are
 * the SELECTED node's, fetched live from that node's own advisord, held
 * nowhere (decision 2: the aggregator caches nothing durable from a node's
 * advisor surface — this module has no cache at all).
 *
 * A sibling of peer-read-proxy.ts, holding to its two security conditions
 * with more force, because the credential behind this surface is the peer's
 * approve token (the ADR's slice-1 ruling: advisord gates its whole /v1
 * with one token; there is no read-scoped credential for advisord — yet):
 *
 *   - The EXACT-PATH allow-list (PEER_ADVISOR_READ_PATHS) is the only thing
 *     standing between a session at the aggregator and /v1/execute on N
 *     hosts. Never a prefix rewrite; an endpoint absent from this table is
 *     404'd by the parser before any label resolves or any fetch happens.
 *     Excluded BY NAME so the list is a decision and not an oversight:
 *     ask, ask-progress, evidence, execute, approve/*, investigate/*,
 *     breakglass/*, runs/:id/stream, and trust/bundle (never reachable
 *     from a browser at all, in any slice).
 *
 *   - The pin runs first, every request (P1-036's rule, shared code; on
 *     the two READ entry points it may be a confirmation from the last few
 *     seconds on the same link generation, #831, and never on a write): a
 *     companion identity read on the peer's READ API must affirmatively
 *     match expected_pubkey_node before the advisor origin is contacted.
 *     The advisor origin is a loopback port on a tunnel; the only thing
 *     that says which node sits behind it is the node key its dashboard
 *     reports.
 */
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFresh } from './fleet-health.js';
import { verifyPeerPin, type PeerPinCache, type PeerReadError } from './peer-read-proxy.js';

type FetchImpl = typeof fetch;

const RUN_ID_RE = /^[A-Za-z0-9._-]{1,120}$/;
const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 4 * 1024 * 1024; // a whole transcript is static JSON, but bounded
/** The longest sentence of a node's own that is carried to the browser (#1117). */
const MAX_FAILURE_WORDS = 400;

/** Browser endpoint → advisord path. The whole slice-1 list. */
const PEER_ADVISOR_READ_PATHS: Record<string, string> = {
  status: '/v1/status',
  check: '/v1/check',
  plan: '/v1/plan',
  ledger: '/v1/ledger',
  runs: '/v1/runs',
  // ADR 0017 decision 4: this node's proposal inbox, for the aggregator's
  // review card. A read like every other entry here — and admin-gated at
  // server.ts, unlike every other entry here, because an unpromoted queue of
  // model-authored notes is not something a monitor session should be able
  // to curl. The DECISION that follows it is not in this table: see
  // markPeerProposal at the bottom of this file.
  proposals: '/v1/proposals',
  // ADR 0021 build step 5: the aggregator mirror's own reads, called by the
  // poller in server.ts rather than typed by a browser, but this table is
  // also parseNodeAdvisorPath's allow-list, so both become reachable at
  // /api/node/:label/advisor/{memory,inbox} the moment they are added here.
  // Admin-gated at server.ts alongside `proposals`, for the same reason:
  // model-authored memory and a node's full inbox (decided notes included,
  // unlike `proposals` above) are not a monitor session's to curl either.
  // Distinct from `proposals`, which stays the review card's own queue.
  memory: '/v1/memory',
  inbox: '/v1/inbox',
};

/** Slice 2's two verbs — parsed by the same parser so there is exactly one
 *  allow-list, but dispatched by name in server.ts (ask is a POST with a
 *  csrf gate; progress forwards its one allow-listed param).
 *
 *  The break-glass verbs are NOT here, and the test beside this file names
 *  them explicitly so the omission is a decision someone can point at. They
 *  are not missing: they ride the slice-3 ceremony block in server.ts
 *  (/api/node/:label/advisor/investigate-begin, investigate,
 *  investigate-continue, breakglass-close), beside approve/begin and
 *  approve/finish, because they are ceremonies and forwarded writes rather
 *  than reads. That block hands them the peer's origin and token, so the
 *  advisord that issued the offer is the one that binds the challenge and
 *  verifies the assertion — the trust bundle is what makes its credential
 *  store hold the admin's key. Routed through THIS table they would be
 *  proxied blind, without the ceremony; routed to the LOCAL /api/advisor
 *  route they would be bound by one advisord and refused by another, which
 *  the operator sees as a broken passkey. The advisord-side guard
 *  (refuseWrongNode) stands behind both. */
const PEER_ADVISOR_VERBS: ReadonlySet<string> = new Set(['ask', 'ask-progress']);

export interface PeerAdvisorPath {
  label: string;
  endpoint: string;
  /** Present only for runs/:id — validated against RUN_ID_RE before this
   *  object exists. */
  runId?: string;
}

/**
 * Parses /api/node/:label/advisor/:endpoint[/:id]. Returns null for
 * anything else — including a valid-looking id on any endpoint but `runs`,
 * and any endpoint not in the allow-list — so server.ts 404s before a
 * label lookup or an outbound fetch is ever attempted. Both
 * browser-controlled segments are validated here and neither is
 * interpolated into a URL before both pass (the ADR's runs/:id guard).
 */
export function parseNodeAdvisorPath(pathname: string): PeerAdvisorPath | null {
  const m = /^\/api\/node\/([^/]+)\/advisor\/([^/]+)(?:\/([^/]+))?$/.exec(pathname);
  if (!m) return null;
  const [, label, endpoint, id] = m;
  if (!LABEL_RE.test(label)) return null;
  if (!Object.prototype.hasOwnProperty.call(PEER_ADVISOR_READ_PATHS, endpoint) &&
      !PEER_ADVISOR_VERBS.has(endpoint)) return null;
  if (PEER_ADVISOR_VERBS.has(endpoint)) {
    return id === undefined ? { label, endpoint } : null;
  }
  if (id !== undefined) {
    if (endpoint !== 'runs') return null;
    if (!RUN_ID_RE.test(id)) return null;
    return { label, endpoint, runId: id };
  }
  return { label, endpoint };
}

export type PeerAdvisorResult =
  | { ok: true; body: unknown }
  | {
      ok: false;
      error: 'advisor_not_configured' | 'advisor_not_found' | 'advisor_unreachable' | 'advisor_refused' | 'advisor_failed' | PeerReadError['error'];
      /** The peer advisord's OWN words, on the two errors that are answers:
       *  advisor_refused and advisor_not_found. A node that refuses a write
       *  knows why ("that investigation measured nothing", "that proposal
       *  was already promoted"), and folding those into advisor_unreachable
       *  told the operator the node was down when it had answered them
       *  clearly. On advisor_not_found it is the node's "no such run", which
       *  is a statement about this instant and nothing more (#478). */
      detail?: string;
      /** The peer's own HTTP status, carried through ONLY on the carried-4xx
       *  branch below (#560), and on `advisor_failed` (#1117) where it is the
       *  node's 5xx. Never on the fixed-status 401/403 token rejection a few
       *  lines above it, which server.ts still answers 502 for, unchanged.
       *  Lets a caller relay a plan refusal with the peer's actual status
       *  rather than the blanket 502 a genuine transport failure gets. */
      status?: number;
    };

export interface FetchPeerAdvisorOpts {
  timeoutMs?: number;
  fetchImpl?: FetchImpl;
  /**
   * An already-rebuilt query string, leading `?` included, or absent for
   * none. ADR 0016: /v1/check and /v1/plan answer about the runbook they are
   * ASKED about, and an absent `runbook` means the upgrade — so a restart
   * plan fetched without one comes back as the upgrade's plan, with a 200
   * and no error anywhere.
   *
   * Built by advisorForwardQuery at the call site, from the operator's params
   * and never from their raw query — the same discipline the local proxy and
   * the ask-progress branch already follow. This module does not build it,
   * so it cannot widen it.
   */
  query?: string;
  /** Reuse a recent confirmed pin (#831). Taken by the two read entry points
   *  only (fetchPeerAdvisor, fetchPeerAdvisorAskProgress); every write pins
   *  on the request. */
  pinCache?: PeerPinCache;
}

/**
 * One live fetch of one allow-listed advisor read on one RESOLVED peer row.
 * `path` must come from parseNodeAdvisorPath — this function trusts its
 * caller the same way fetchPeerRoute trusts isAllowedRoute. GET only, by
 * construction: nothing in this module can express another method.
 */
export async function fetchPeerAdvisor(
  node: FleetNodeConfig,
  path: PeerAdvisorPath,
  opts: FetchPeerAdvisorOpts = {},
): Promise<PeerAdvisorResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  // Degrade without a reference, pin before the advisor origin is
  // contacted, token read fresh — the shared preamble below is the one
  // copy of that sequence for every entry point in this module.
  const pre = await advisorPreamble(node, timeoutMs, doFetch, opts.pinCache);
  if (!pre.ok) return pre;
  const upstream = PEER_ADVISOR_READ_PATHS[path.endpoint] +
    (path.runId !== undefined ? `/${encodeURIComponent(path.runId)}` : '') +
    (opts.query ?? '');
  // runs/:id is the second read where a 404 is an ANSWER (#261), for the same
  // reason ask-progress is: the id names one record, and the node saying it
  // does not have that record is a fact about the record, not about the
  // transport. Folded into advisor_unreachable it reached the browser as a
  // 502, which the terminal's tail reads as transient and re-asks every 2.5
  // seconds for the life of the tab — one line in this dashboard's log per
  // poll. `runs` WITHOUT an id is the index and keeps the old treatment: a
  // 404 there really is the wrong shape of advisord.
  //
  // What that answer says, exactly, and what it does not (#478): the node
  // has no transcript under that id AT THIS INSTANT. advisord serves both
  // /v1/runs and /v1/runs/:id from the same directory listing, so a
  // transcript nobody has written yet and a transcript somebody deleted are
  // the same 404 and no read on this node can tell them apart. The earlier
  // wording here, "a transcript that is never coming back", was the
  // reading the terminal then rendered for eleven minutes of a live restart.
  // So this carries the node's own words through as `detail` and leaves the
  // reading to the page, which has the one record that survives a deleted
  // transcript: the hash-chained ledger, where a run that started has its
  // step entries whatever became of the .ndjson.
  const notFoundIsAnswer = path.endpoint === 'runs' && path.runId !== undefined;
  // #560. /check and /plan answer about a NAMED plan, and the file's own
  // rule for a write applies to them too: a 4xx here is the node ANSWERING
  // ("rollback-node needs a target version"), not transport trouble. Every
  // other read through this function keeps the old rule: a non-2xx on
  // /v1/status, /v1/ledger, /v1/runs (the index), /v1/proposals, /v1/memory
  // or /v1/inbox means the advisord answering is not the shape expected,
  // which IS trouble. A 404 on /check or /plan rides the same branch as a
  // 400 or a 501 (an older advisord answering a runbook it does not
  // implement is the node naming its own build gap, the same reading 501
  // already gets); notFoundIsAnswer stays false here, so this is a decision
  // and not an accident of ordering.
  const carryRefusal = path.endpoint === 'check' || path.endpoint === 'plan';
  // #1117. The same two reads carry a node's 5xx sentence too: an Advisor that
  // cannot read its host answers 503 with the reason, and that reason is the
  // answer to the question asked.
  const carryFailure = carryRefusal;
  const result = await advisorFetch(node, upstream, {
    method: 'GET', token: pre.token, timeoutMs, doFetch, notFoundIsAnswer, carryRefusal, carryFailure,
  });
  // #831: a confirmed pin is not reused past a read that failed.
  if (!result.ok) opts.pinCache?.invalidate(node.label);
  return result;
}

// ── ADR 0014 slice 2: ask and ask-progress, per node ─────────────────────
// The question travels to the SUBJECT node's advisord, which answers with
// its own sealed model key, its own host reads, its own redaction rules,
// and writes its own ledger — the aggregator carries the question and the
// answer, never the reasoning's inputs. Same preamble as every read above:
// degrade without a reference, pin before the advisor origin is contacted,
// token read fresh per request and never surfaced.

/** Shared guarded preamble: not-configured degrade → pin → token. */
async function advisorPreamble(
  node: FleetNodeConfig,
  timeoutMs: number,
  doFetch: FetchImpl,
  pinCache?: PeerPinCache,
): Promise<{ ok: true; token: string } | PeerAdvisorResult & { ok: false }> {
  if (!node.advisor_origin || !node.advisor_token_path) {
    return { ok: false, error: 'advisor_not_configured' };
  }
  const readToken = readTokenFresh(node.token_path);
  if (!readToken) {
    console.warn(`[peer-advisor-proxy] ${node.label}: read token unreadable (pin cannot run)`);
    return { ok: false, error: 'peer_unreachable' };
  }
  const pinned = pinCache
    ? await pinCache.verify(node, readToken, timeoutMs, doFetch)
    : await verifyPeerPin(node, readToken, timeoutMs, doFetch);
  if (!pinned.ok) return { ok: false, error: pinned.error };
  const advisorToken = readTokenFresh(node.advisor_token_path);
  if (!advisorToken) {
    console.warn(`[peer-advisor-proxy] ${node.label}: advisor token unreadable`);
    return { ok: false, error: 'advisor_unreachable' };
  }
  return { ok: true, token: advisorToken };
}

/** The `error` string out of an advisord reply, when it sent one. Anything
 *  that is not JSON with a string `error` yields '' and the caller sends the
 *  code alone. */
function peerWords(text: string): string {
  try {
    const parsed = JSON.parse(text) as { error?: unknown };
    return typeof parsed.error === 'string' ? parsed.error : '';
  } catch {
    return '';
  }
}

async function advisorFetch(
  node: FleetNodeConfig,
  upstream: string,
  o: {
    method: 'GET' | 'POST'; token: string; timeoutMs: number; doFetch: FetchImpl; payload?: string;
    /** Report an upstream 404 as `advisor_not_found` rather than folding it
     *  into `advisor_unreachable`. Opt-in per call site: on every read in
     *  this module a 404 means the peer's advisord is not the shape we
     *  expect, which IS transport trouble. On ask-progress alone it is an
     *  answer — see fetchPeerAdvisorAskProgress. */
    notFoundIsAnswer?: boolean;
    /** Carry a 4xx back as the peer's own refusal rather than as transport
     *  trouble. Opt-in, and only the proposal writes use it: on a read a 4xx
     *  means the peer's advisord is not the shape we expect, which IS
     *  trouble, but a refused write is an ANSWER — the node read the request,
     *  understood it, and said no for a reason the operator needs. */
    carryRefusal?: boolean;
    /** Carry a node's own 5xx sentence back as `advisor_failed` rather than
     *  folding it into `advisor_unreachable` (#1117). The node answered: its
     *  Advisor could not read its host, and said so with a reason, which is
     *  the thing the operator needs and is not "look at the network". Opt-in
     *  for the two reads that ask about a named plan (check, plan). A 5xx
     *  with no sentence in it (an HTML page from a tunnel, an empty body, a
     *  bare code) is still transport trouble. */
    carryFailure?: boolean;
  },
): Promise<PeerAdvisorResult> {
  try {
    const r = await o.doFetch(`${node.advisor_origin}${upstream}`, {
      method: o.method,
      headers: o.method === 'POST'
        ? { 'content-type': 'application/json', authorization: `Bearer ${o.token}` }
        : { authorization: `Bearer ${o.token}` },
      body: o.payload,
      signal: AbortSignal.timeout(o.timeoutMs),
    });
    const text = await r.text();
    if (text.length > MAX_BODY_BYTES) {
      console.warn(`[peer-advisor-proxy] ${node.label} ${upstream}: body over cap (${text.length}b)`);
      return { ok: false, error: 'advisor_unreachable' };
    }
    if (r.status === 404 && o.notFoundIsAnswer) {
      // The peer advisord's own sentence ("no such run"), carried rather
      // than dropped, so the surface that renders this can quote the node
      // instead of a code. It is a fact about this instant and the caller is
      // told only that much. See the note at the notFoundIsAnswer call site.
      const words = peerWords(text);
      return { ok: false, error: 'advisor_not_found', ...(words ? { detail: words } : {}) };
    }
    // The peer's advisord rejected THIS DASHBOARD'S advisor token (#268 on
    // the read side, the same shape here). It answered — the box is up and
    // the tunnel is fine — so it is never `advisor_unreachable`, which sends
    // an operator to look for a service that is running. A different token
    // from the read one, so it names which: a node re-keyed by a reinstall
    // usually needs both copied over.
    if (r.status === 401 || r.status === 403) {
      console.warn(`[peer-advisor-proxy] ${node.label} ${upstream}: token rejected (${r.status})`);
      return {
        ok: false,
        error: 'advisor_refused',
        detail: `${node.label} rejected this dashboard's Advisor token (HTTP ${r.status}) — ` +
          'if its install was wiped or re-keyed, copy its new advisor token into this dashboard',
      };
    }
    // 501 rides with the 4xx (#455): a peer that names the route and does not
    // implement what was asked ANSWERED, and it is running a build behind
    // this one. What an operator does about it is update that node, which is
    // not what "it did not respond" points at.
    if (o.carryRefusal && ((r.status >= 400 && r.status < 500) || r.status === 501)) {
      const detail = peerWords(text);
      console.warn(`[peer-advisor-proxy] ${node.label} ${upstream}: refused ${r.status}`);
      return {
        ok: false, error: 'advisor_refused', status: r.status,
        detail: detail || `the node refused it (HTTP ${r.status})`,
      };
    }
    if (!r.ok && o.carryFailure && r.status >= 500 && r.status <= 599) {
      // #1117. The node's Advisor answered with an error and its reason: an
      // unreadable host is a 503 that says so (#1017). Carried, with its
      // status, for the caller to relay on a status the edge leaves alone.
      // Only a sentence travels: a bare code (a link's own concurrency_cap)
      // reads as itself in the journal below, and anything else the node
      // sent is not shown. The node may be the hostile party, so the
      // sentence is capped and the page escapes it.
      const words = peerWords(text);
      if (words && !/^[a-z_]{1,40}$/.test(words)) {
        console.warn(`[peer-advisor-proxy] ${node.label} ${upstream}: upstream ${r.status}, reason carried`);
        return {
          ok: false, error: 'advisor_failed', status: r.status,
          detail: words.length > MAX_FAILURE_WORDS ? words.slice(0, MAX_FAILURE_WORDS - 1) + '\u2026' : words,
        };
      }
    }
    if (!r.ok) {
      // #831: the code as well as the status, so a link's own 503
      // (concurrency_cap, link_not_ready) reads as itself in the journal.
      // Restricted to a plain code shape: the node may be the hostile party.
      const code = peerWords(text);
      const shown = /^[a-z_]{1,40}$/.test(code) ? ` ${code}` : '';
      console.warn(`[peer-advisor-proxy] ${node.label} ${upstream}: upstream ${r.status}${shown}`);
      return { ok: false, error: 'advisor_unreachable' };
    }
    return { ok: true, body: JSON.parse(text) };
  } catch (err) {
    console.warn(`[peer-advisor-proxy] ${node.label} ${upstream}: ${(err as Error).message}`);
    // A wait that ran out is not a node that could not be reached (#1134): the
    // card says which, and "could not reach" sends an operator to a network
    // that may be fine while the node is only slow. fetch raises the timeout
    // from AbortSignal.timeout as a TimeoutError.
    const name = (err as { name?: string } | null)?.name;
    if (name === 'TimeoutError' || name === 'AbortError') return { ok: false, error: 'peer_timeout' };
    return { ok: false, error: 'advisor_unreachable' };
  }
}

/** A model call is slower than a host read — same 300s budget the local
 *  ask proxy carries, matched to the interrogative loop's own ceiling. */
const ASK_TIMEOUT_MS = 300_000;

export async function fetchPeerAdvisorAsk(
  node: FleetNodeConfig,
  payload: string,
  opts: FetchPeerAdvisorOpts = {},
): Promise<PeerAdvisorResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const pre = await advisorPreamble(node, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, doFetch);
  if (!pre.ok) return pre;
  return advisorFetch(node, '/v1/ask', {
    method: 'POST', token: pre.token, timeoutMs: ASK_TIMEOUT_MS, doFetch, payload,
  });
}

/**
 * The two proposal writes that travel to the node that proposed — ADR 0017
 * decision 4, and the trust model's Part B (#49).
 *
 * Deliberately NOT entries in PEER_ADVISOR_READ_PATHS, and deliberately NOT in
 * PEER_ADVISOR_VERBS either. Both of those tables are reached by a URL the
 * browser types; these two are writes, they are called only by the server's
 * own curation handler after an admin check, and their bodies are built there
 * rather than forwarded. Put in the verbs table, `revise` would become
 * /api/node/:label/advisor/revise — a route around the admin gate that
 * handleKnowledgeAdmin applies, for an endpoint whose whole job is raising a
 * note's trust. Same preamble as every other call in this module, so the pin
 * still runs before the advisor origin is contacted.
 *
 * The node refuses an id it does not hold, which is what keeps either write
 * from landing on the wrong node's inbox.
 */
const PEER_PROPOSAL_WRITES = {
  mark: '/v1/proposals/mark',
  revise: '/v1/proposals/revise',
} as const;

export type PeerProposalWrite = keyof typeof PEER_PROPOSAL_WRITES;

async function postPeerProposal(
  node: FleetNodeConfig,
  write: PeerProposalWrite,
  payload: Record<string, unknown>,
  opts: FetchPeerAdvisorOpts,
): Promise<PeerAdvisorResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pre = await advisorPreamble(node, timeoutMs, doFetch);
  if (!pre.ok) return pre;
  return advisorFetch(node, PEER_PROPOSAL_WRITES[write], {
    method: 'POST', token: pre.token, timeoutMs, doFetch,
    payload: JSON.stringify(payload), carryRefusal: true,
  });
}

export function markPeerProposal(
  node: FleetNodeConfig,
  payload: { id: string; decision: 'promoted' | 'rejected'; reason?: string; file?: string; operator: string; role: string },
  opts: FetchPeerAdvisorOpts = {},
): Promise<PeerAdvisorResult> {
  return postPeerProposal(node, 'mark', payload, opts);
}

/**
 * The verification, travelling to the node the operator just investigated.
 *
 * ask_id rather than a verdict: the peer's advisord holds the record of that
 * investigation and grades the note from it itself. Nothing this aggregator
 * sends can tell a node that something was measured — which is the point, and
 * the reason there is no `verified` field to forward.
 */
export function revisePeerProposal(
  node: FleetNodeConfig,
  payload: { id: string; body: string; ask_id: string; operator: string; role: string },
  opts: FetchPeerAdvisorOpts = {},
): Promise<PeerAdvisorResult> {
  return postPeerProposal(node, 'revise', payload, opts);
}

/**
 * `qs` must come from advisorForwardQuery — already rebuilt from scratch
 * against the ask-progress allow-list; this function never sees the raw
 * browser query.
 *
 * This is the recovery path. A CDN edge kills any single request past ~100s,
 * so a long investigation's POST dies in transit and the drawer recovers the
 * answer by polling here for the ask_id it minted — which is why the peer
 * advisord keys its progress store on that id rather than one of its own.
 *
 * notFoundIsAnswer is what makes the recovery read the same on a peer as it
 * does locally. advisord answers 404 for an id it never registered ("it may
 * have finished and aged out, or never existed"), and the drawer has a branch
 * for exactly that: it settles in a couple of seconds with "that request did
 * not reach the Advisor, so nothing ran". Folded into advisor_unreachable the
 * status reaching the browser was 502, that branch was unreachable on a peer,
 * and the drawer sat on its stall timer for two minutes before saying
 * something less true. The 404 is a fact about the question, not about the
 * transport, and it travels as one.
 */
export async function fetchPeerAdvisorAskProgress(
  node: FleetNodeConfig,
  qs: string,
  opts: FetchPeerAdvisorOpts = {},
): Promise<PeerAdvisorResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pre = await advisorPreamble(node, timeoutMs, doFetch, opts.pinCache);
  if (!pre.ok) return pre;
  const result = await advisorFetch(node, `/v1/ask/progress${qs}`, {
    method: 'GET', token: pre.token, timeoutMs, doFetch, notFoundIsAnswer: true,
  });
  if (!result.ok) opts.pinCache?.invalidate(node.label);
  return result;
}

/**
 * The third server-side write, and the one that records an act done TO that
 * node rather than through it: the aggregator revoked its link, or accepted a
 * node key that changed (#455).
 *
 * In neither allow-list table, for the same reason the two proposal writes
 * are in neither. It is called by the Settings routes after the real ceremony
 * has verified, its body is built server-side by
 * lib/advisor-ledger-append.ts, and put in PEER_ADVISOR_VERBS it would become
 * /api/node/:label/advisor/record: a URL a browser could type, at an endpoint
 * whose whole job is writing to a node's audit trail.
 *
 * Same preamble as everything else in this module, so the pin still runs
 * before the advisor origin is contacted. That matters more here than on a
 * read: the credential this carries is the peer's approve token, and a node
 * answering on a key the fleet does not pin is exactly the case a revoke is
 * most likely to meet.
 *
 * carryRefusal and notFoundIsAnswer, because both are the node ANSWERING. Its
 * advisord refuses an unknown kind, a malformed record and a stale one by
 * name, and a node with no such route at all is one running a build from
 * before this existed. Folding either into "unreachable" would send an
 * operator to look for a service that is running.
 */
export async function appendPeerFleetRecord(
  node: FleetNodeConfig,
  payload: { record: unknown; signature: string },
  opts: FetchPeerAdvisorOpts = {},
): Promise<PeerAdvisorResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pre = await advisorPreamble(node, timeoutMs, doFetch);
  if (!pre.ok) return pre;
  return advisorFetch(node, '/v1/fleet/record', {
    method: 'POST', token: pre.token, timeoutMs, doFetch,
    payload: JSON.stringify(payload),
    carryRefusal: true, notFoundIsAnswer: true,
  });
}

/**
 * Stamps the asking operator onto a question's body on its way to a peer.
 *
 * Lives here rather than inline at the call site because of what it must NOT
 * do: the body the page sent is forwarded whole, and ask_id is the field that
 * matters. The page mints it, the peer's advisord keys its progress store on
 * it, and the drawer polls ask-progress for it when the POST dies at the CDN
 * edge — three hops that only line up if this merge leaves it alone. A rebuild
 * that named the fields it kept would drop it, the ask would still answer, and
 * the only visible symptom would be an answer nobody could recover. There is a
 * test beside this file pinning exactly that.
 *
 * The actor is assigned LAST so a body that carried these keys cannot win.
 * That ordering is the whole guarantee; an unparseable body becomes just the
 * actor, because a question this proxy cannot read is the Advisor's to refuse
 * rather than this proxy's to invent.
 */
export function attachActor(rawBody: string, actor: { operator: string; role: string }): string {
  let base: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(rawBody || '{}') as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      base = parsed as Record<string, unknown>;
    }
  } catch { base = {}; }
  return JSON.stringify({ ...base, ...actor });
}
