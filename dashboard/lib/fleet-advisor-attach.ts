/**
 * The aggregator's half of attaching an Advisor to an already-paired node
 * (#641): the watch read, the signed reveal, and every operator-facing
 * sentence either one produces.
 *
 * WHY A MODULE AND NOT TWO FUNCTIONS IN settings-api.ts. Both calls leave
 * this host and both carry a credential, so both want the one road every
 * other peer call in this codebase already takes: the node's own read token,
 * the pin verified before anything is sent, redirects never followed, a
 * bounded body, and a node's own refusal carried through in the node's own
 * words rather than flattened into "that node answered 409". fleet-update.ts
 * built that road for update/state and update/apply; this file is the same
 * road for advisor/state and advisor/reveal, close enough to read side by
 * side and separate enough that neither grows a branch for the other.
 *
 * WHAT IS DELIBERATELY NOT HERE. No passkey, no ceremony, no broker call: the
 * decision and the write are settings-api.ts's, and this file only reaches
 * the node. That split is what lets a test drive every refusal below without
 * an authenticator, a socket or a root service.
 *
 * THE TOKEN IS NEVER LOGGED, NEVER CACHED, NEVER RETURNED TWICE. It appears in
 * exactly one place, the success return of revealPeerAdvisorToken, and its
 * caller hands it to the broker and drops it. Every error path here carries
 * an exception's CLASS and never its message, the same rule fleet-seal.ts
 * follows for the model key: a fetch error can carry the request it failed
 * on, and the request that failed here is the one holding a bearer token.
 */
import { randomBytes } from 'node:crypto';
import type { FleetNodeConfig } from './fleet-registry.js';
import { readTokenFresh } from './fleet-health.js';
import { verifyPeerPin } from './peer-read-proxy.js';
import { signWithSeed } from './trust-bundle.js';
import { predatesFleetWrite, NO_FLEET_WRITE_DETAIL } from './fleet-seal.js';
import {
  FLEET_WRITE_PROTOCOL_VERSION, FLEET_WRITE_ISSUER_LABEL,
  advisorRevealJobSigningBytes,
  type AdvisorRevealJob, type AdvisorRevealResponse,
  type AdvisorStateResponse, type FleetWriteErrorBody,
} from '../types/fleet-write-contract.js';
import { FLEET_PAIR_MAX_TOKEN_CHARS } from '../types/fleet-link-contract.js';

/** How long one call to a node's advisor surface may take. The watch runs
 *  while an operator is looking at the row, so it is short; the reveal is
 *  one request behind a passkey touch and gets the same budget, because the
 *  node does no work for it beyond a stat and a file read. */
export const ADVISOR_PEER_TIMEOUT_MS = 5_000;

/** The pin check's own budget, ahead of either call. Same value
 *  fleet-update.ts uses for the same check. */
const PIN_TIMEOUT_MS = 5_000;

/** Neither answer is large: a state body is four fields and a reveal body is
 *  two. Anything past this is a node saying something this route does not
 *  serve, and none of it is kept. */
const ADVISOR_ANSWER_MAX_BYTES = 8 * 1024;

/** How much of a node's own refusal sentence is carried onto this page. */
const ADVISOR_SAY_MAX_CHARS = 400;

/** The one command an operator runs on the node, in both the "no Advisor
 *  yet" case and the "the window closed" one. One constant, because the
 *  whole point of the re-arm copy box is that it is the SAME line: the
 *  installer's token block is a no-op on a token that already exists, and
 *  only the reveal window is replanted. add-advisor.js carries its own copy
 *  of this string for the step-1 command block; this is the server's, for
 *  the sentences it writes. */
export const ADVISOR_INSTALL_CMD = 'curl -fsSL https://get.aperire.one/advisor | bash';

// ── Every operator-facing sentence this lane emits ───────────────────────
//
// ONE PLACE, and the UI quotes it rather than re-writing it. The mockup and
// then the page both render what the backend actually says, so a copy change
// is one edit and a drift between the two is impossible rather than merely
// unlikely. Each one is what THIS PAGE OBSERVED, never a claim about the box:
// "this page has not seen an Advisor answer there" is true whatever is
// running on that host, and "that node has no Advisor" is not a fact this
// side can hold.
export const ADVISOR_WATCH_COPY = {
  /** The node answered and reports no Advisor there yet. ATTRIBUTED, not
   *  asserted: this is that node's own report about its own box, and the
   *  sentence says so. */
  waiting: 'That node reports no Advisor answering there yet. This page asks it every few seconds and '
    + 'moves on by itself the moment it does.',
  /** The node answered and its Advisor is up. */
  ready: 'Advisor found, ready to attach.',
  /** The node answered, and reports an Advisor installed there and silent.
   *  Distinct from waiting: the operator has something to look at on that
   *  box rather than something to wait for. */
  down: 'That node reports an Advisor installed there and not answering. Attaching would give this '
    + 'aggregator an address that answers nothing, so check it on that box first.',
  /** The node is on a build with no advisor/state route. Never "absent":
   *  an old build that does not know the route has told us nothing. */
  old_build: 'Update this node first. Its dashboard is on a build that has no way to answer this, so '
    + 'this page cannot see an Advisor arrive there until it is updated.',
  /** This page could not reach the node at all. Honestly distinct from
   *  waiting, which is a node that answered. */
  unreachable: 'This page could not read that node just now, so it has seen nothing either way.',
} as const;

/**
 * The same read, on a row this aggregator ALREADY reaches an Advisor on.
 *
 * This is the distinction #641 step 9 asks the Advisor tab to draw, and it
 * is a different question from the watch above. The watch asks "is there
 * one to attach"; this asks "the one we hold, is it still there". Only the
 * node's own advisor/state route can tell those apart: a peer's Advisor is
 * DECLARED on this side (ADR 0016 decision 7), so an address that does not
 * answer reads as `installed-but-down` forever whether the Advisor was
 * uninstalled on that box or is merely down. Reading the node's own
 * presence is what separates them, and it is why the watch route does not
 * short-circuit an attached row.
 */
export const ADVISOR_ATTACHED_COPY = {
  /** The address this aggregator holds answers, and the node agrees. */
  answering: 'That node’s Advisor answers here.',
  /** The address is still recorded here and the node reports no Advisor
   *  there at all. The honest reading of an Advisor uninstalled on that box
   *  after it was attached. */
  removed: 'That node reports no Advisor there any more, and this aggregator still holds an address and '
    + 'a credential for one. Nothing here was changed by that. Remove this Advisor to take them out.',
  /** The node reports one installed and silent. NOT removed: there is
   *  something on that box to look at. */
  not_answering: 'That node reports an Advisor installed there and not answering. Nothing here has been '
    + 'removed: the address, the credential and the model setting are all still in place.',
  /** A build too old to answer the question. Says nothing either way about
   *  what is on that box. */
  old_build: 'That node’s dashboard is on a build that cannot answer this, so nothing here can tell an '
    + 'Advisor that was removed from one that is down.',
  /** This page could not read the node. Same rule. */
  unread: 'This page could not read that node just now, so it cannot tell an Advisor that was removed '
    + 'from one that is down.',
} as const;

/** What the row says when the reveal window on the node has closed. The
 *  command is the SAME one step 1 printed; running it again replants the
 *  window and leaves the token file exactly as it is. */
export const ADVISOR_WINDOW_CLOSED_COPY =
  'The window on that node has closed, so it revealed nothing and nothing here changed. Run the same '
  + 'command on that box again to open a fresh one, then press Attach.';

/** What Remove says it does, and what it honestly does not. */
export const ADVISOR_DETACH_COPY =
  'This aggregator stops reaching that node’s Advisor. The Advisor itself keeps running there and its '
  + 'own token is untouched: nothing here can revoke a credential this host has already held, so rotate '
  + 'it on that box if that is what you need.';

/** A row this aggregator holds no Advisor address for. Reached with no
 *  network call at all, which is the whole reason it can be said this
 *  plainly: it is a fact about this registry, not about that box. */
export const ADVISOR_NOT_ATTACHED_COPY =
  'No Advisor is attached to this node here. Nothing was read from that box to decide that: this '
  + 'aggregator holds no address for an Advisor there.';

// ── The watch read: GET /fleet/v1/advisor/state ──────────────────────────

/** Why a watch read produced nothing, in this page's own terms. `refused`
 *  says the node DECIDED and answered, which is a different fact from this
 *  side failing to reach it, and the row prints two different sentences. */
export type PeerAdvisorStateResult =
  | { ok: true; state: AdvisorStateResponse }
  | {
    ok: false; reason: string;
    /** THIS SIDE's sentence. Always present, always ours. */
    detail: string;
    /** THAT NODE's sentence, and only ever that. Absent whenever the node
     *  sent none, which is every timeout, every unreachable host, and every
     *  404-family answer whose body means nothing.
     *
     *  Two fields rather than one because a page renders them differently:
     *  `detail` is what this dashboard concluded and `said` is a quotation.
     *  Folding this side's own sentence into `said` is how a row ends up
     *  printing "that node said: that node could not be reached", which
     *  attributes this host's failure to the box it failed to reach. */
    said?: string;
    refused?: boolean; old_build?: boolean;
  };

/** The three-state watch row, decided here rather than on the page: the
 *  comparison is between what a node answered and what this side can do
 *  with it, and both live on this side. */
export type AdvisorWatchState = 'waiting' | 'ready' | 'down' | 'old_build' | 'unreachable';

/** The same read on a row that is already attached. */
export type AdvisorAttachedReading = 'answering' | 'removed' | 'not_answering' | 'old_build' | 'unread';

/** What a node's own presence means for an Advisor this aggregator already
 *  holds an address for. Pure, so the removed-versus-down call is tested
 *  without a socket and no page re-derives it. */
export function advisorAttachedReading(result: PeerAdvisorStateResult): AdvisorAttachedReading {
  if (!result.ok) return result.old_build ? 'old_build' : 'unread';
  if (result.state.state === 'present') return 'answering';
  if (result.state.state === 'installed-but-down') return 'not_answering';
  return 'removed';
}

/** The node's own words out of one read, or undefined. One road, so the
 *  attribution rule above has a single implementation. */
export function advisorStateSaid(result: PeerAdvisorStateResult): string | undefined {
  return result.ok ? (result.state.detail || undefined) : result.said;
}

/**
 * One node's own account of its Advisor, read over the already-live read
 * listener.
 *
 * Never throws. A peer that does not answer is a reason, not an exception,
 * for the same reason fetchPeerUpdateState gives: a fleet page that fails
 * because one node is down is a page that stops working exactly when it is
 * needed.
 *
 * NO PIN CHECK ON THIS ONE, by decision. The body carries no secret and
 * nothing is written from it, so the worst a wrong host can do is make a row
 * say "Advisor found" about a box that is not this node. The pin IS checked,
 * unskippably, before the reveal below, which is the call where being wrong
 * about the host costs something. Re-pinning every few seconds for the
 * length of an install is cost with no new answer, the same reasoning
 * fetchPeerUpdateState's own poll already records.
 */
export async function fetchPeerAdvisorState(
  node: FleetNodeConfig,
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<PeerAdvisorStateResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const token = readTokenFresh(node.token_path);
  if (!token) {
    return {
      ok: false, reason: 'token_unreadable',
      detail: 'This dashboard cannot read the read token for that node, so it asked it nothing.',
    };
  }
  let res: Response;
  try {
    res = await fetchImpl(`${node.read_origin}/fleet/v1/advisor/state`, {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(opts.timeoutMs ?? ADVISOR_PEER_TIMEOUT_MS),
      redirect: 'manual',
    });
  } catch (err) {
    const cls = (err as Error).name || 'Error';
    return {
      ok: false,
      reason: cls === 'TimeoutError' ? 'timeout' : 'no_answer',
      detail: cls === 'TimeoutError' ? 'That node did not answer in time.' : 'That node could not be reached.',
    };
  }
  const text = await readBoundedText(res, ADVISOR_ANSWER_MAX_BYTES);
  if (text === null) {
    return {
      ok: false, reason: 'answer_too_large',
      detail: 'That node answered with more than this dashboard reads from that route, so nothing of it was kept.',
    };
  }
  if (res.status !== 200) {
    // 404-family FIRST, and it stays first: a build that predates this
    // surface answers a 404 with a body that means nothing, and reading that
    // body would turn a node that is simply older into a node that said
    // something. This is the single most important branch on this route,
    // because the alternative reading is "absent", which would put "no
    // Advisor there" over a box nobody asked.
    if (predatesFleetWrite(res.status)) {
      return { ok: false, reason: 'no_fleet_write_surface', detail: NO_FLEET_WRITE_DETAIL, old_build: true };
    }
    let body: FleetWriteErrorBody | null;
    try { body = JSON.parse(text) as FleetWriteErrorBody; } catch { body = null; }
    // The other shape an old build takes: a dashboard new enough to have the
    // fleet-write gate and old enough not to know this path answers a real
    // JSON refusal naming it. Both readings land on the same row.
    const old = body?.error === 'unknown_fleet_write_path' || body?.error === 'no_handler';
    const said = carried(body?.detail);
    return {
      ok: false,
      reason: carried(body?.error) ?? `http_${res.status}`,
      detail: `That node refused with ${res.status}.`,
      ...(said ? { said } : {}),
      refused: true,
      ...(old ? { old_build: true } : {}),
    };
  }
  let parsed: AdvisorStateResponse;
  try { parsed = JSON.parse(text) as AdvisorStateResponse; } catch {
    return { ok: false, reason: 'bad_answer', detail: 'That node answered with something this dashboard could not read.' };
  }
  const state = parsed?.state;
  if (state !== 'absent' && state !== 'present' && state !== 'installed-but-down') {
    return { ok: false, reason: 'bad_answer', detail: 'That node answered with a presence this dashboard does not know.' };
  }
  return {
    ok: true,
    state: {
      state,
      last_answered_ms: typeof parsed.last_answered_ms === 'number' ? parsed.last_answered_ms : null,
      detail: carried(parsed.detail) ?? '',
      version: carried(parsed.version, 64) ?? null,
    },
  };
}

/** The watch row, from one read. Pure, so the three-state decision is
 *  tested without a socket and the page never re-derives it. */
export function advisorWatchState(result: PeerAdvisorStateResult): AdvisorWatchState {
  if (!result.ok) return result.old_build ? 'old_build' : 'unreachable';
  if (result.state.state === 'present') return 'ready';
  if (result.state.state === 'installed-but-down') return 'down';
  return 'waiting';
}

// ── The token a node reveals, checked before it goes anywhere ────────────

/** Why a revealed token was refused before it reached the broker. */
export type RevealedTokenRefusal = 'empty' | 'too_long' | 'bad_shape';

/**
 * Is what that node handed back a bearer token this fleet would ever write?
 *
 * BOUNDED HERE AS WELL AS IN THE BROKER, deliberately, and this is the hop
 * the #641 security review asked for by name. The node bounds it only from
 * below (it must never truncate a credential silently), the broker refuses
 * an oversized one with `token_too_wide`, and this is the middle: a response
 * from a node that is longer or oddly shaped than any token this project
 * mints is already a signal to refuse on, not to forward. An honest token is
 * install-advisord.sh's own `head -c 48 /dev/urandom | base64`, 64 characters
 * of base64, so the shape below is base64's alphabet plus the URL-safe
 * variant and padding, and nothing else: no space, no newline, no control
 * character, nothing that could mean something to the line protocol on the
 * broker socket.
 *
 * The lower bound is 32 rather than 64: a shorter token is still a credential
 * an operator may have placed by hand, and refusing one that works would be
 * this check costing more than it is worth. Anything under 32 characters is
 * not a bearer token at all.
 */
const REVEALED_TOKEN_SHAPE = /^[A-Za-z0-9+/=_-]+$/;
export const REVEALED_TOKEN_MIN_CHARS = 32;

export function checkRevealedToken(raw: unknown): { ok: true; token: string } | { ok: false; reason: RevealedTokenRefusal; detail: string } {
  if (typeof raw !== 'string' || raw === '') {
    return {
      ok: false, reason: 'empty',
      detail: 'That node answered without a token, so there was nothing to attach and nothing was written here.',
    };
  }
  if (raw.length > FLEET_PAIR_MAX_TOKEN_CHARS) {
    return {
      ok: false, reason: 'too_long',
      detail: `That node answered with a token longer than any bearer token this fleet writes (${FLEET_PAIR_MAX_TOKEN_CHARS} characters), so it was refused here and nothing was written.`,
    };
  }
  if (raw.length < REVEALED_TOKEN_MIN_CHARS || !REVEALED_TOKEN_SHAPE.test(raw)) {
    return {
      ok: false, reason: 'bad_shape',
      detail: 'That node answered with something that is not shaped like a bearer token, so it was refused here and nothing was written.',
    };
  }
  return { ok: true, token: raw };
}

// ── The reveal: POST /fleet/v1/advisor/reveal ────────────────────────────

export type PeerAdvisorRevealResult =
  | { ok: true; token: string; advisord_version: string | null }
  | {
    ok: false; reason: string;
    /** THIS SIDE's sentence. */
    detail: string;
    /** THAT NODE's, and only ever that. Same rule, same reason as the watch
     *  result above. */
    said?: string;
    refused?: boolean; window_closed?: boolean; old_build?: boolean;
  };

/**
 * Ask one node for its own approve.token, under a signed job.
 *
 * THE ORDER IS THE SECURITY ARGUMENT and it is not rearrangeable:
 *
 *   1. The row must be pinned. A job is addressed to a node key, and an
 *      unpinned row has no address to write. Refused by name so the fix
 *      (pin the row) is the obvious one.
 *   2. This host must hold a signing seed. No seed, no job, and it says so
 *      rather than sending an unsigned one.
 *   3. verifyPeerPin, BEFORE anything is sent. A row whose forward now lands
 *      on a different host is exactly the case where a request that returns
 *      a credential must not travel.
 *   4. A fresh nonce per call. Never derived from the label, never reused:
 *      the node's own replay ledger is what makes a captured request useless,
 *      and it can only do that if this side never sends the same one twice.
 *
 * The node then applies its own two gates (the signature, and a root-planted
 * window this side cannot forge), and a refusal from either comes back in the
 * node's own words.
 */
export async function revealPeerAdvisorToken(
  node: FleetNodeConfig,
  opts: {
    /** This host's fleet-trust private seed, base64url. Read by the caller,
     *  which already reads it for the trust fingerprint. */
    seed: string | null;
    timeoutMs?: number;
    fetchImpl?: typeof fetch;
    /** Injected only so a test can assert two calls mint two nonces without
     *  reaching into node:crypto. Production passes nothing. */
    nonce?: () => string;
    nowMs?: () => number;
  },
): Promise<PeerAdvisorRevealResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  if (!node.expected_pubkey_node) {
    return {
      ok: false, reason: 'row_not_pinned',
      detail: 'That node’s registry row pins no node key, so no job can be addressed to it. Re-pair that '
        + 'node, or accept its key on its own row first.',
    };
  }
  if (!opts.seed) {
    return {
      ok: false, reason: 'no_signing_key',
      detail: 'This dashboard holds no fleet-trust private key, so it cannot sign a job for any node.',
    };
  }
  const token = readTokenFresh(node.token_path);
  if (!token) {
    return {
      ok: false, reason: 'token_unreadable',
      detail: 'This dashboard cannot read the read token for that node, so it asked it nothing.',
    };
  }
  const pinned = await verifyPeerPin(node, token, PIN_TIMEOUT_MS, fetchImpl);
  if (!pinned.ok) {
    return {
      ok: false, reason: pinned.error,
      detail: pinned.error === 'peer_integrity_mismatch'
        ? 'That node did not prove it is the node this row is pinned to, so nothing was asked of it.'
        : 'That node did not answer its identity check, so nothing was asked of it.',
    };
  }
  const job: AdvisorRevealJob = {
    v: FLEET_WRITE_PROTOCOL_VERSION,
    kind: 'advisor.reveal',
    issuer_label: FLEET_WRITE_ISSUER_LABEL,
    target_pubkey_node: node.expected_pubkey_node,
    nonce: (opts.nonce ?? (() => randomBytes(16).toString('hex')))(),
    issued_at: Math.floor((opts.nowMs ?? Date.now)() / 1000),
  };
  let signature: string;
  try {
    signature = signWithSeed(advisorRevealJobSigningBytes(job), opts.seed);
  } catch {
    // The seed's own error can name its length. Not passed through.
    return {
      ok: false, reason: 'no_signing_key',
      detail: 'The fleet-trust private key on this dashboard is not a usable signing key.',
    };
  }

  let res: Response;
  try {
    res = await fetchImpl(`${node.read_origin}/fleet/v1/advisor/reveal`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ job, signature }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? ADVISOR_PEER_TIMEOUT_MS),
      // Never followed: a redirect here is an older node sending this to its
      // login page, and a request whose ANSWER is a credential must not be
      // replayed anywhere.
      redirect: 'manual',
    });
  } catch (err) {
    // The class, never the message: this request carries a bearer token in a
    // header and a fetch error can carry the request it failed on.
    const cls = (err as Error).name || 'Error';
    return {
      ok: false,
      reason: cls === 'TimeoutError' ? 'timeout' : 'no_answer',
      detail: cls === 'TimeoutError'
        ? 'That node did not answer in time, so nothing was attached.'
        : 'That node could not be reached, so nothing was attached.',
    };
  }
  const text = await readBoundedText(res, ADVISOR_ANSWER_MAX_BYTES);
  if (text === null) {
    return {
      ok: false, reason: 'answer_too_large',
      detail: 'That node answered with more than this dashboard reads from that route, so nothing of it was kept.',
    };
  }
  if (res.status !== 200) {
    if (predatesFleetWrite(res.status)) {
      return { ok: false, reason: 'no_fleet_write_surface', detail: NO_FLEET_WRITE_DETAIL, old_build: true };
    }
    let body: FleetWriteErrorBody | null;
    try { body = JSON.parse(text) as FleetWriteErrorBody; } catch { body = null; }
    const code = body?.error;
    const said = carried(body?.detail);
    if (code === 'advisor_reveal_window_closed') {
      // The one refusal with a way out on the page: the operator re-runs the
      // same command and presses Attach again. The node's own sentence says
      // WHICH of the six window facts failed and it is carried separately,
      // never merged into this side's own line.
      return {
        ok: false, reason: code, window_closed: true, refused: true,
        detail: ADVISOR_WINDOW_CLOSED_COPY,
        ...(said ? { said } : {}),
      };
    }
    const old = code === 'unknown_fleet_write_path' || code === 'no_handler';
    return {
      ok: false,
      reason: carried(code) ?? `http_${res.status}`,
      detail: `That node refused with ${res.status}, so nothing was attached.`,
      ...(said ? { said } : {}),
      refused: true,
      ...(old ? { old_build: true } : {}),
    };
  }
  let parsed: AdvisorRevealResponse;
  try { parsed = JSON.parse(text) as AdvisorRevealResponse; } catch {
    return { ok: false, reason: 'bad_answer', detail: 'That node answered with something this dashboard could not read.' };
  }
  const checked = checkRevealedToken(parsed?.advisor_token);
  if (!checked.ok) return { ok: false, reason: `bad_token_${checked.reason}`, detail: checked.detail };
  return {
    ok: true,
    token: checked.token,
    // The peer's own string, sanitised on the way IN: it is re-served to the
    // page and rendered there, so it is made safe once at ingestion rather
    // than at every render.
    advisord_version: carried(parsed.advisord_version, 64) ?? null,
  };
}

// ── Two small readers, kept here rather than exported from fleet-update ──

/**
 * Read at most maxBytes of a response, or null if it is longer.
 *
 * STOPPED RATHER THAN MEASURED AFTERWARDS (review finding, 2026-09-27).
 * The first version of this read the whole body with arrayBuffer() and then
 * compared its length, which pays the entire cost of a hostile answer in
 * order to refuse it: a node that answers with a gigabyte is a node this
 * process buffers a gigabyte from before deciding it was too big. The cap
 * is 8 KiB and these two routes answer in a few hundred bytes, so anything
 * approaching it is already not one of these answers.
 *
 * The same shape fleet-update.ts's own reader uses, and a copy rather than
 * an import because that one is private to its module: widening it would
 * couple two surfaces that have no other reason to be coupled, and the
 * function is twenty lines.
 */
async function readBoundedText(res: Response, maxBytes: number): Promise<string | null> {
  const body = res.body;
  if (!body) {
    // No stream to read: a stub, or a runtime that does not give one. The
    // cap still applies, it just cannot be enforced early.
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
        // Cancelled, so the sender stops rather than going on filling a
        // buffer nobody will read.
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

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;
/** A peer's own string, made safe once, at ingestion. Same shape (and same
 *  reason) as fleet-update.ts's `carried`. */
function carried(value: unknown, maxChars: number = ADVISOR_SAY_MAX_CHARS): string | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  const clean = value.replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim();
  if (clean === '') return undefined;
  if (clean.length <= maxChars) return clean;
  return `${clean.slice(0, maxChars - 1)}…`;
}
