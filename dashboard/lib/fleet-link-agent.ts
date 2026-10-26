/**
 * The node's half of the fleet link — ADR 0019 decision 1, phases 1 and 2.
 *
 * Runs inside a NODE's dashboard process when dashboard/config/fleet-link.json
 * exists, and does nothing at all when it does not. That absence is the
 * single-node guarantee: no file, no dial, no listener, no timer, and a
 * single-node install is unaffected byte for byte.
 *
 * It dials the aggregator, presents its credential, verifies that the
 * aggregator can sign with the fleet trust key this node has pinned, and then
 * serves framed requests by dialling its OWN loopback.
 *
 * THE ALLOW-LIST IS THE POINT (ADR 0019 decision 2). The node holds it, not
 * the aggregator. Every request is parsed to a (target, method, route name)
 * that must be a member of an exact set built from the contracts the
 * aggregator's own proxies already import, and the outbound URL is REBUILT
 * from the resolved route name. Nothing that came off the wire is ever dialled
 * as a string. That is what makes this an allow-list rather than a filter, and
 * it is checked before any local dial rather than refused downstream, which is
 * the condition lib/peer-read-proxy.ts records as P1-035.
 *
 * A compromised aggregator therefore gets the node's read surface, a seal it
 * cannot sign, a trust bundle this node will only install if it verifies
 * against the fleet key this node already pinned, and nothing else. It cannot
 * reach /api/*, cannot reach the auth routes, cannot reach advisord's
 * /v1/evidence, and cannot open a socket to any port but the two this file
 * names.
 */
import {
  readFileSync, statSync, openSync, closeSync, writeSync, fsyncSync, fstatSync, readSync,
  renameSync, unlinkSync, constants as fsConstants,
} from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { READ_ROUTE_NAMES, READ_STREAM_PATH } from '../types/read-contract.js';
import {
  FLEET_WRITE_ROUTE_NAMES, FLEET_WRITE_ROUTE_METHODS, FLEET_WRITE_ISSUER_LABEL,
  type FleetWriteRouteName,
} from '../types/fleet-write-contract.js';
import {
  FLEET_LINK_PROTOCOL_VERSION, FLEET_LINK_BACKOFF_MIN_MS, FLEET_LINK_BACKOFF_MAX_MS,
  FLEET_LINK_BACKOFF_JITTER, FLEET_LINK_MAX_RESPONSE_BYTES,
  FLEET_LINK_MAX_BUNDLE_BYTES, linkRequestCap, isLinkBundleRequest,
  FLEET_LINK_MAX_INFLIGHT, FLEET_LINK_ADVISOR_MAX_INFLIGHT, FLEET_LINK_FATAL_REFUSALS, LINK_LABEL_RE, FLEET_LINK_REPROBE_MS,
  FLEET_LINK_PROBE_SHORT_RETRIES, FLEET_LINK_NO_REPROBE, FLEET_LINK_PIN_WATCH_MS,
  linkChallengeSigningBytes, parseLinkFrame, encodeLinkFrame, refusal, normaliseHeaders,
  linkTombstoneSigningBytes, parseLinkTombstone,
  type LinkRequest, type LinkRefusalCode, type LinkTarget, type LinkFrame, type LinkTombstone,
} from '../types/fleet-link-contract.js';
import { verifyWithPeerKey } from './trust-bundle.js';

// ── The allow-list ───────────────────────────────────────────────────────

/**
 * The advisord paths the AGGREGATOR dials on a peer, gathered from the three
 * places that dial them rather than invented here:
 *
 *   - lib/peer-advisor-proxy.ts: PEER_ADVISOR_READ_PATHS, PEER_ADVISOR_VERBS
 *     (/v1/ask, /v1/ask/progress) and PEER_PROPOSAL_WRITES.
 *   - server.ts's peer ceremony block (the /api/node/:label/advisor/... regex)
 *     and the handlers it calls in auth.ts, which dial /v1/approve/begin,
 *     /v1/approve, /v1/approve/cancel, /v1/investigate/begin and
 *     /v1/investigate.
 *   - the same block's four forwarded writes: /v1/execute,
 *     /v1/investigate/continue, /v1/investigate/offer, /v1/breakglass/close.
 *
 * Named here by hand ON PURPOSE, and this is the one place in the build where
 * a copy is the right answer. Importing peer-advisor-proxy.ts would pull the
 * aggregator's fetch code into every node's process, and deriving the set
 * from the aggregator would mean the aggregator decides what the node allows,
 * which is precisely the thing this list exists to stop. The test beside this
 * file asserts the members against the source tables so a route added there
 * and not here is a red test rather than a silent 404 in the lab.
 *
 * POST /v1/trust/bundle is a member (#288). It was excluded in the first cut
 * for the reason lib/peer-advisor-proxy.ts:21 excludes it, which is right
 * THERE and wrong here: that proxy carries a browser session, and no browser
 * ever asks for the trust push. This list carries the aggregator's own
 * processes, and the aggregator IS the caller — lib/fleet-trust-push.mjs:61
 * POSTs the signed admin bundle to every node's advisord, and ADR 0019
 * decision 2 step 6 puts it among what pairing delivers over the link. A node
 * that never receives it falls behind on passkeys and revocations, and the
 * arm and seal ceremonies (ADR 0018) then refuse on that node. Carrying it
 * adds no trust: advisord verifies the bundle's signature against the fleet
 * key this node pinned at join, and a bundle the aggregator forged fails
 * there, over the link exactly as over a tunnel.
 *
 * Excluded by name, so the omission is a decision someone can point at:
 *   /v1/evidence      — the raw evidence snapshot, never proxied today either
 *   GET /v1/trust/bundle — reading a node's trust store is not something the
 *                       aggregator does; only the push travels
 *   /v1/runs/:id/stream — an event stream, refused for the shape reason below
 *
 * POST /v1/knowledge/bundle is a member too, and it is the one route with a
 * cap of its own (#289, ruled 2026-09-11). advisord takes 8 MiB of a bundle
 * and a framed request is otherwise capped at 256 KiB, so carrying it at the
 * general cap would have meant a link that takes 3% of what the same node
 * takes on a tunnel. The bound is the node's own instead — see
 * linkRequestCap — everything else stays at 256 KiB, and one bundle travels
 * at a time so the worst case is one large frame per linked node.
 */
const ADVISOR_GET_PATHS: ReadonlySet<string> = new Set([
  '/v1/status', '/v1/check', '/v1/plan', '/v1/ledger', '/v1/runs',
  '/v1/proposals', '/v1/ask/progress',
  // ADR 0021 build step 5: the aggregator mirror's own reads.
  '/v1/memory', '/v1/inbox',
]);

const ADVISOR_POST_PATHS: ReadonlySet<string> = new Set([
  '/v1/ask',
  '/v1/trust/bundle',
  '/v1/knowledge/bundle',
  // POST /v1/fleet/record is a member for the same reason the trust bundle
  // is, and it is the one route on this list whose whole purpose needs the
  // link to be UP (#455). It carries the record of an act the aggregator
  // performed on this node: its link revoked, or the node key the fleet pins
  // for it replaced. The revoke closes this very link, so the aggregator
  // sends the entry first and closes afterwards; a node that did not carry
  // this route would be the one node with no record of what happened to it.
  // It adds no trust, on the same argument: advisord verifies the record
  // against the fleet key this node pinned at join, refuses any kind outside
  // its own closed set, and writes the sentence itself.
  '/v1/fleet/record',
  '/v1/proposals/mark', '/v1/proposals/revise',
  '/v1/approve/begin', '/v1/approve', '/v1/approve/cancel',
  '/v1/investigate/begin', '/v1/investigate', '/v1/investigate/continue',
  '/v1/investigate/offer',
  '/v1/breakglass/close',
  '/v1/execute',
]);

/** The one parameterised advisord path. Same shape peer-advisor-proxy.ts's
 *  RUN_ID_RE validates before it interpolates one. */
const RUN_ID_RE = /^[A-Za-z0-9._-]{1,120}$/;

const READ_ROUTE_SET: ReadonlySet<string> = new Set(READ_ROUTE_NAMES);
const FLEET_ROUTE_SET: ReadonlySet<string> = new Set(FLEET_WRITE_ROUTE_NAMES);

/** Query strings are carried through (the read routes take ?metric&range and
 *  the advisor routes take ?runbook), rebuilt from URLSearchParams rather than
 *  spliced, and bounded. A route name is what is allow-listed; a parameter is
 *  an argument to a route this node already serves to a holder of its own read
 *  token, so widening it buys an attacker nothing they did not already have. */
const MAX_QUERY_BYTES = 2048;

/**
 * A pathname fit to store in an audit row: printable ASCII only, 64
 * characters, nothing else.
 *
 * A path off the wire is attacker-controlled and must never land in a ledger
 * verbatim, which is why the coarse route was all that was recorded. The
 * answer to that is a sanitiser, not a blank. This is a second pass over an
 * already-narrow value: parseLinkFrame bounds the path at 2048 and refuses a
 * path that does not start with a slash, so nothing here is the only thing
 * standing between the wire and the row.
 */
export function auditPath(pathname: string): string {
  const clean = pathname.replace(/[^\u0020-\u007e]/g, '?');
  return clean.length > 64 ? `${clean.slice(0, 63)}~` : clean;
}

/**
 * The only headers a framed request may carry into a local dial.
 *
 * The hub sends these three and nothing else, and the node checks rather than
 * trusts: a compromised aggregator holding a valid credential can put any
 * header name it likes in a frame, and handing an arbitrary set to fetch()
 * means handing it `host`, `content-length` and whatever else the runtime
 * happens to honour. Three names cover every request the fleet actually
 * makes, so the set is closed and anything else is dropped silently rather
 * than refused: a dropped header is not a decision the operator needs to
 * read about, and an aggregator that added one learns nothing from the reply.
 */
const FORWARDED_HEADERS: readonly string[] = ['authorization', 'content-type', 'accept'];

/** The forwarded subset of what arrived, lower-cased by the parser already. */
export function forwardableHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of FORWARDED_HEADERS) {
    const v = headers[name];
    if (typeof v === 'string') out[name] = v;
  }
  return out;
}

export interface LinkAllowOk {
  ok: true;
  /** The absolute URL to dial, rebuilt from the resolved route. */
  url: string;
  method: string;
  /** target:route, the name a refusal and an audit row are counted under. */
  route: string;
}
export interface LinkAllowNo {
  ok: false;
  code: LinkRefusalCode;
  detail: string;
  /** What was asked for, coarsely. The COALESCING key for the audit row, so
   *  the write amplification the ledger's window exists to stop is unchanged. */
  route: string;
  /** The pathname that was actually asked for, sanitised and capped (#286).
   *  The coarse route alone made a probe of /api/auth/login, a typo and an
   *  old build's stream request write the identical row, which is the one
   *  question the row exists to answer. Never the query: a query carries
   *  operator data and answers nothing about what was refused. */
  path: string;
}
export type LinkAllowDecision = LinkAllowOk | LinkAllowNo;

export interface LinkOrigins {
  /** This node's own dashboard, bare loopback origin. */
  dashboard: string;
  /** This node's own advisord, bare loopback origin, or null when it has
   *  none. A request for an absent advisord is refused, never dialled at a
   *  guessed port. */
  advisor: string | null;
}

/**
 * The gate. Pure: no socket, no clock, no filesystem, so every refusal path
 * is asserted without a network in test/unit/fleet-link-agent.test.ts.
 */
export function decideLinkRequest(req: LinkRequest, origins: LinkOrigins): LinkAllowDecision {
  const coarse = `${req.target}:?`;
  // Computed once, from the RAW frame path, so a request that could not even
  // be parsed to a pathname still says what arrived.
  const asked = auditPath(req.path.split('?')[0]);
  const no = (code: LinkRefusalCode, detail: string, route = coarse): LinkAllowNo =>
    ({ ok: false, code, detail, route, path: asked });

  // Split path from query WITHOUT ever building a URL from the raw string:
  // the base is a fixed literal, and only the parsed parts are used below.
  let pathname: string;
  let query: string;
  try {
    const u = new URL(req.path, 'http://link.invalid');
    pathname = u.pathname;
    query = u.searchParams.toString();
  } catch {
    return no('not_allowed', 'that path is not one this node serves');
  }
  if (query.length > MAX_QUERY_BYTES) {
    return no('body_too_large', 'that request carries more query than the link takes');
  }
  const qs = query ? `?${query}` : '';

  // The body cap, AFTER the pathname is known, because one route has a cap of
  // its own (#289) and a cap cannot be applied to a route nobody has resolved
  // yet. 256 KiB everywhere else, and that is not a number picked here: it is
  // what advisord's own handlers read (io.LimitReader(r.Body, 256<<10) at
  // main.go:2159 and :4875, the second being the trust push #288 put on this
  // list). A tighter bound on this side would refuse a body the node itself
  // would have taken, which is a push that works down a tunnel and fails over
  // the link — the silent divergence the fleet-write version note below
  // refuses for the same reason.
  const cap = linkRequestCap(req.target, req.method, pathname);
  if (req.body !== null && Buffer.byteLength(req.body, 'utf8') > cap) {
    return no('body_too_large',
      cap === FLEET_LINK_MAX_BUNDLE_BYTES
        ? 'that bundle is larger than this node accepts on any transport'
        : 'that request is larger than the link carries');
  }

  // The stream, refused by name on this side too. The hub already answers it
  // without framing it; this is the second half of the same decision, so a
  // hub that ever stops doing so does not turn into an undefined behaviour
  // here. lib/peer-stream-proxy.ts reports the failure and overview.html
  // keeps painting the quorum bar from the 2s poll it never stopped.
  if (pathname === READ_STREAM_PATH) {
    return no('stream_not_supported', 'this link does not carry the event stream in this version', 'read:stream');
  }

  if (req.target === 'read') {
    const m = /^\/read\/v1\/([a-z-]{1,40})$/.exec(pathname);
    if (!m || !READ_ROUTE_SET.has(m[1])) {
      return no('not_allowed', 'that is not a read route this node serves');
    }
    if (req.method !== 'GET') {
      return no('not_allowed', 'the read API answers GET only', `read:${m[1]}`);
    }
    return { ok: true, url: `${origins.dashboard}/read/v1/${m[1]}${qs}`, method: 'GET', route: `read:${m[1]}` };
  }

  if (req.target === 'fleet') {
    const m = /^\/fleet\/v(\d{1,3})\/([a-z]{1,20}\/[a-z]{1,20})$/.exec(pathname);
    if (!m || !FLEET_ROUTE_SET.has(m[2])) {
      return no('not_allowed', 'that is not a fleet-write route this node serves');
    }
    const route = m[2] as FleetWriteRouteName;
    if (!FLEET_WRITE_ROUTE_METHODS[route].includes(req.method)) {
      return no('not_allowed', `${route} does not answer ${req.method}`, `fleet:${route}`);
    }
    // The version segment is carried through rather than rebuilt from this
    // side's constant: the node's OWN fleet-write gate answers a version
    // mismatch with a named error, and swapping in the local version here
    // would hide a genuine skew behind a link that quietly fixed it.
    return {
      ok: true,
      url: `${origins.dashboard}/fleet/v${m[1]}/${route}${qs}`,
      method: req.method,
      route: `fleet:${route}`,
    };
  }

  // advisor
  if (!origins.advisor) {
    return no('upstream_unreachable', 'this node runs no Advisor', 'advisor:?');
  }
  const runs = /^\/v1\/runs\/([^/]+)$/.exec(pathname);
  if (runs) {
    if (!RUN_ID_RE.test(runs[1])) {
      return no('not_allowed', 'that is not a run id', 'advisor:/v1/runs/:id');
    }
    if (req.method !== 'GET') {
      return no('not_allowed', 'a run transcript answers GET only', 'advisor:/v1/runs/:id');
    }
    return {
      ok: true,
      url: `${origins.advisor}/v1/runs/${encodeURIComponent(runs[1])}${qs}`,
      method: 'GET',
      route: 'advisor:/v1/runs/:id',
    };
  }
  if (ADVISOR_GET_PATHS.has(pathname)) {
    if (req.method !== 'GET') {
      return no('not_allowed', `${pathname} answers GET only`, `advisor:${pathname}`);
    }
    return { ok: true, url: `${origins.advisor}${pathname}${qs}`, method: 'GET', route: `advisor:${pathname}` };
  }
  if (ADVISOR_POST_PATHS.has(pathname)) {
    if (req.method !== 'POST') {
      return no('not_allowed', `${pathname} answers POST only`, `advisor:${pathname}`);
    }
    return { ok: true, url: `${origins.advisor}${pathname}${qs}`, method: 'POST', route: `advisor:${pathname}` };
  }
  return no('not_allowed', 'that is not an Advisor route this node serves over the link', 'advisor:?');
}

/** The allow-list as data, for the test that pins it against its sources. */
export const LINK_ALLOWED_ADVISOR_PATHS = {
  get: ADVISOR_GET_PATHS,
  post: ADVISOR_POST_PATHS,
} as const;

// ── The audit row ────────────────────────────────────────────────────────

export interface LinkRefusalRow {
  route: string;
  code: LinkRefusalCode;
  /** How many refusals this row stands for. 1 for the first in a window. */
  count: number;
  first_at_ms: number;
  last_at_ms: number;
  /** Up to REFUSAL_PATH_SAMPLE distinct sanitised pathnames seen under this
   *  (route, code) in this window (#286). A sample rather than all of them,
   *  because an aggregator that can drive one refusal per frame could
   *  otherwise grow one row without end. */
  paths: string[];
}

/**
 * Refusals into the node's audit ledger, coalesced.
 *
 * The ledger is auth_events (db.ts), because it is the only audit table this
 * process can write and because the rule for it is already "record the
 * DECISION at the moment it is made". Worth naming plainly: the Advisor's own
 * action ledger is a different record on a different service, and a refusal
 * the dashboard made never reaches it.
 *
 * Coalesced because recordAuthEvent is a synchronous SQLite insert into an
 * append-only table, and a compromised aggregator holding a valid credential
 * can drive one refusal per frame for as long as it likes. Uncoalesced, the
 * audit trail is a write amplifier pointed at the node's own disk. One row
 * per (route, code) at the first refusal so an operator sees it immediately,
 * then at most one more per window carrying the count. Bounded either way.
 */
export interface RefusalLedgerDeps {
  write: (row: LinkRefusalRow) => void;
  now?: () => number;
  windowMs?: number;
  /** How many distinct (route, code) pairs are tracked at once. Past it the
   *  oldest window is flushed and dropped: the map is memory an aggregator
   *  can grow, so it is bounded like everything else here. */
  maxKeys?: number;
}

export interface RefusalLedger {
  note: (route: string, code: LinkRefusalCode, path?: string) => void;
  flush: () => void;
}

/** How many distinct pathnames one row carries. Enough to tell a probe from
 *  a typo, small enough that a row is a row and not a log. */
export const REFUSAL_PATH_SAMPLE = 5;

export function createRefusalLedger(deps: RefusalLedgerDeps): RefusalLedger {
  const now = deps.now ?? (() => Date.now());
  const windowMs = deps.windowMs ?? 60_000;
  const maxKeys = deps.maxKeys ?? 64;
  interface Open {
    route: string; code: LinkRefusalCode; count: number;
    firstMs: number; lastMs: number; paths: Set<string>;
  }
  const pending = new Map<string, Open>();

  const emit = (e: Open) => {
    if (e.count <= 0) return;
    deps.write({
      route: e.route, code: e.code, count: e.count,
      first_at_ms: e.firstMs, last_at_ms: e.lastMs,
      paths: [...e.paths],
    });
  };

  return {
    note(route: string, code: LinkRefusalCode, path?: string) {
      const at = now();
      const key = `${route}\u0000${code}`;
      const sample = path ? [path] : [];
      const open = pending.get(key);
      if (!open) {
        if (pending.size >= maxKeys) {
          // Flush and drop the oldest window rather than growing without end.
          let oldestKey: string | null = null;
          let oldestAt = Infinity;
          for (const [k, v] of pending) if (v.firstMs < oldestAt) { oldestAt = v.firstMs; oldestKey = k; }
          if (oldestKey !== null) {
            const dropped = pending.get(oldestKey)!;
            emit(dropped);
            pending.delete(oldestKey);
          }
        }
        // The first one is written NOW, not at the end of the window: an
        // operator watching a node reject an aggregator should not wait a
        // minute to be told.
        emit({ route, code, count: 1, firstMs: at, lastMs: at, paths: new Set(sample) });
        pending.set(key, { route, code, count: 0, firstMs: at, lastMs: at, paths: new Set() });
        return;
      }
      if (at - open.firstMs >= windowMs) {
        emit(open);
        emit({ route, code, count: 1, firstMs: at, lastMs: at, paths: new Set(sample) });
        pending.set(key, { route, code, count: 0, firstMs: at, lastMs: at, paths: new Set() });
        return;
      }
      open.count += 1;
      open.lastMs = at;
      // Bounded: past the sample the row keeps counting and stops collecting.
      if (path && open.paths.size < REFUSAL_PATH_SAMPLE) open.paths.add(path);
    },
    flush() {
      for (const e of pending.values()) emit(e);
      pending.clear();
    },
  };
}

// ── The config file ──────────────────────────────────────────────────────

export interface LinkConfig {
  aggregator_url: string;
  credential: string;
  label: string;
}

export type LinkConfigLoad =
  | { ok: true; config: LinkConfig }
  | { ok: false; absent: boolean; reason: string };

const REQUIRED_CONFIG_KEYS = ['aggregator_url', 'credential', 'label'] as const;

/**
 * Read and validate config/fleet-link.json.
 *
 * Three refusals worth their own sentences:
 *
 * 1. **Mode.** A credential readable by another account on the node is a
 *    credential. Refused rather than warned about, with the chmod in the
 *    line, because a warning in a journal is not a control.
 *
 * 2. **Plaintext.** The credential crosses on the dial, and decideIngest at
 *    the far end CANNOT see whether it did: the aggregator binds loopback and
 *    terminates TLS in a proxy, so its policy reads `loopback-bind` or
 *    `loopback-peer` for an internet request either way. The only place that
 *    knows whether this hop is encrypted is this one, holding the URL. So
 *    `wss://` is required for a remote aggregator, and `ws://` is accepted
 *    only for a loopback host, which is a test rig or a co-located pair.
 *
 * 3. **Unknown keys** fail the file closed, the fleet-registry.ts rule: a
 *    typo'd key in a credential file must not read as a default.
 */
export function parseLinkConfig(text: string, mode: number | null): LinkConfigLoad {
  const no = (reason: string): LinkConfigLoad => ({ ok: false, absent: false, reason });
  if (mode !== null && (mode & 0o077) !== 0) {
    return no('config/fleet-link.json is readable by other accounts on this host: run `chmod 600` on it and restart');
  }
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return no('config/fleet-link.json is not valid JSON');
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return no('config/fleet-link.json must be an object');
  }
  const obj = doc as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!(REQUIRED_CONFIG_KEYS as readonly string[]).includes(k)) {
      return no(`config/fleet-link.json has an unknown key "${k}"`);
    }
  }
  for (const k of REQUIRED_CONFIG_KEYS) {
    if (typeof obj[k] !== 'string' || (obj[k] as string).length === 0) {
      return no(`config/fleet-link.json is missing or has an empty "${k}"`);
    }
  }
  const label = obj.label as string;
  if (!LINK_LABEL_RE.test(label)) {
    return no(`config/fleet-link.json label "${label}" must match [a-z0-9-]{1,32}`);
  }
  const credential = obj.credential as string;
  if (credential.length < 32) {
    return no('config/fleet-link.json credential is shorter than a minted one, so this node will not present it');
  }
  const raw = obj.aggregator_url as string;
  let u: URL;
  try { u = new URL(raw); } catch { return no('config/fleet-link.json aggregator_url is not a URL'); }
  if (u.protocol !== 'wss:' && u.protocol !== 'ws:') {
    return no('config/fleet-link.json aggregator_url must be a wss:// URL');
  }
  const host = u.hostname.toLowerCase();
  const loopback = host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
  if (u.protocol === 'ws:' && !loopback) {
    return no('config/fleet-link.json aggregator_url is ws:// to a remote host: the link credential would cross '
      + 'the network readable. Use wss:// (the aggregator terminates TLS in front of its dashboard)');
  }
  if (u.username || u.password) {
    return no('config/fleet-link.json aggregator_url must carry no credentials in the URL');
  }
  return { ok: true, config: { aggregator_url: raw, credential, label } };
}

export function loadLinkConfig(path: string): LinkConfigLoad {
  let text: string;
  let mode: number;
  try {
    mode = statSync(path).mode & 0o777;
    text = readFileSync(path, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      // The single-node state. Not an error, and never logged as one.
      return { ok: false, absent: true, reason: 'no fleet link is configured on this node' };
    }
    return { ok: false, absent: false, reason: `config/fleet-link.json could not be read: ${(err as Error).message}` };
  }
  return parseLinkConfig(text, mode);
}

// ── Reconciling the agent to the file on disk (#316) ──────────────────────
//
// The agent used to start once at boot and never again, so a node that was
// paired while it ran held no link until it was restarted by hand: pairing
// writes config/fleet-link.json and runs `systemctl reload`, and that reload
// re-read only the aggregator-side registry. These three pieces let the
// dashboard's SIGHUP handler bring the agent in line with the file every time,
// and let a gate prove it does. The dashboard owns the agent-building (its
// dial, ledger and identity are all dashboard state); this owns the decision.

/**
 * A fingerprint of the config the running agent was built from. Compared on
 * reload so an unrelated SIGHUP (an insights or fleet.yaml edit sends the same
 * signal, and Node runs every SIGHUP handler) does not tear down and re-dial a
 * live link. The credential is folded in so a re-mint is seen as a change, but
 * only the hash is ever kept or compared, never the credential itself.
 */
export function fleetLinkConfigFp(cfg: LinkConfig): string {
  return createHash('sha256')
    .update(`${cfg.aggregator_url}\n${cfg.label}\n${cfg.credential}`)
    .digest('hex');
}

export type LinkReconcileAction = 'none' | 'start' | 'stop' | 'restart';

export interface LinkReconcileDecision {
  action: LinkReconcileAction;
  /** The fingerprint to record once the action is applied, or null. */
  fp: string | null;
  /** A line to log at warn level, or null. */
  warn: string | null;
}

/**
 * Decide what to do with the agent given the config as it is on disk right now
 * and the fingerprint of what is running. Pure, so the matrix is a gate.
 *
 *   - absent + running  -> stop  (the undo path rm's the file then reloads)
 *   - absent + none     -> none  (the single-node state, silent)
 *   - unreadable/parse  -> none, warn: a transient breakage (a mid-chmod
 *                          EACCES, a bad edit) must NOT take down a live link;
 *                          leave the running agent and name the reason
 *   - present + none     -> start (the pairing case #316 exists for)
 *   - present + same fp  -> none  (already live; do not churn on a reload)
 *   - present + other fp -> restart (a re-mint under a running agent)
 */
export function decideLinkReconcile(
  loaded: LinkConfigLoad,
  running: { fp: string } | null,
): LinkReconcileDecision {
  if (!loaded.ok) {
    if (loaded.absent) return { action: running ? 'stop' : 'none', fp: null, warn: null };
    return { action: 'none', fp: running?.fp ?? null, warn: loaded.reason };
  }
  const fp = fleetLinkConfigFp(loaded.config);
  if (running && running.fp === fp) return { action: 'none', fp, warn: null };
  return { action: running ? 'restart' : 'start', fp, warn: null };
}

/** The dashboard's slot for its one agent and the fingerprint behind it. */
export interface LinkAgentSlot {
  agent: FleetLinkAgent | null;
  fp: string | null;
}

export interface LinkReconcileDeps {
  load: () => LinkConfigLoad;
  /** Build (but do not start) an agent for a validated config. */
  make: (config: LinkConfig) => FleetLinkAgent;
  trigger: 'startup' | 'reload';
  log?: (msg: string) => void;
  warn?: (msg: string) => void;
}

/**
 * Bring `slot` in line with the config on disk. Mutates the slot. The dashboard
 * calls this at startup and on every SIGHUP; the fake-agent test drives it
 * directly, which is where the #316 guard lives (a config appearing must make
 * an agent, and an unchanged one must not build a second).
 */
export function reconcileLinkAgent(slot: LinkAgentSlot, deps: LinkReconcileDeps): void {
  const loaded = deps.load();
  const decision = decideLinkReconcile(loaded, slot.agent ? { fp: slot.fp ?? '' } : null);
  if (decision.warn) deps.warn?.(decision.warn);
  if (decision.action === 'none') return;
  if (decision.action === 'stop') {
    slot.agent?.stop();
    slot.agent = null;
    slot.fp = null;
    deps.log?.('fleet-link.json is gone, this node stopped dialling');
    return;
  }
  // start or restart. loaded is ok in both (decideLinkReconcile only returns
  // them for an ok load); the guard narrows the type and cannot fire.
  if (!loaded.ok) return;
  if (decision.action === 'restart') {
    slot.agent?.stop();
    slot.agent = null;
    slot.fp = null;
  }
  slot.agent = deps.make(loaded.config);
  slot.agent.start();
  slot.fp = decision.fp;
  if (deps.trigger === 'reload') {
    deps.log?.(`fleet-link.json is present, this node is opening its link as "${loaded.config.label}"`);
  }
}

// ── Backoff ──────────────────────────────────────────────────────────────

/** Exponential with jitter, capped at a minute. `rand` is injected so the
 *  test asserts the bounds rather than sampling them. */
export function nextBackoffMs(attempt: number, rand: () => number = Math.random): number {
  const base = Math.min(FLEET_LINK_BACKOFF_MAX_MS, FLEET_LINK_BACKOFF_MIN_MS * 2 ** Math.max(0, attempt));
  const jitter = base * FLEET_LINK_BACKOFF_JITTER * (rand() * 2 - 1);
  return Math.max(FLEET_LINK_BACKOFF_MIN_MS, Math.min(FLEET_LINK_BACKOFF_MAX_MS, Math.round(base + jitter)));
}

// ── The running agent ────────────────────────────────────────────────────

/** The minimum a WebSocket has to do for this module. `ws`'s client
 *  satisfies it; the test's fake satisfies it in twenty lines.
 *
 *  `unexpected-response` is in the list because of #280 and is the whole of
 *  that fix's plumbing. Every refusal the hub decides at the upgrade is an
 *  HTTP STATUS and not a frame: there is no WebSocket yet, so `unauthenticated`
 *  and `revoked` can never arrive as the named refusals this module is built
 *  to stop on. `ws` turns the 401 into a plain `error` event, which reads as
 *  transient, and a de-provisioned node then dials a public endpoint forever
 *  while its own page says "dialling". */
export interface LinkSocket {
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
  on: (
    event: 'open' | 'message' | 'close' | 'error' | 'unexpected-response',
    handler: (arg?: unknown, arg2?: unknown) => void,
  ) => void;
}

/**
 * What an upgrade-time HTTP status means to the node.
 *
 * 401 and 403 are the hub saying this credential is not one it serves: unknown,
 * revoked, or registered under another label. Fatal, which since #688 means
 * the backoff stops and the node asks again once an hour, because retrying at
 * backoff speed cannot change the answer and the endpoint is on the public
 * internet. A node holding a tombstone for this credential stops for good.
 *
 * 429 is the rate limit, and it is deliberately NOT fatal: it is the one
 * refusal that clears on its own, and a node that stopped for good on it
 * would need a human to bring back a link the aggregator was only asking to
 * slow down.
 *
 * Anything else (a 502 from a proxy, a 404 from an aggregator whose registry
 * has not been placed yet, a 500) is transient: the far end may be mid-deploy.
 */
export function refusalForStatus(status: number): LinkRefusalCode | null {
  if (status === 401 || status === 403) return 'unauthenticated';
  return null;
}

export type LinkPhase = 'off' | 'dialing' | 'ready' | 'stopped';

export interface LinkAgentState {
  phase: LinkPhase;
  label: string | null;
  /** Why it is where it is, in one sentence an operator reads on the node's
   *  own Settings page. */
  reason: string | null;
  since_ms: number;
  last_ready_ms: number | null;
  /** Set only in 'stopped': the refusal by name this node is holding to. */
  refused: LinkRefusalCode | null;
  /** In 'stopped': when this node asks the aggregator again (#688). Null when
   *  it will not ask again, which is only ever because it holds a tombstone
   *  the aggregator signed for this credential. */
  next_probe_ms?: number | null;
  /** In 'stopped': when the aggregator signed the revocation this node holds,
   *  or null for a refusal it did not sign. */
  revoked_signed_at_ms?: number | null;
}

// ── The tombstone (#688) ─────────────────────────────────────────────────

/** Where the node keeps the one tombstone it may hold. Injected, so the test
 *  drives the decision without a disk; the dashboard hands it the file store
 *  below. `read` answers the parsed JSON or null, and never throws. */
export interface LinkTombstoneStore {
  read: () => unknown;
  write: (t: LinkTombstone) => void;
  remove: () => void;
}

export type TombstoneVerdict = { ok: true; tombstone: LinkTombstone } | { ok: false; why: string };

/**
 * Is this a revocation the aggregator this node pinned signed, for THIS
 * credential on THIS label? Pure and offline: the key is the node's own pin
 * (see LinkTombstone for why that pin is enough for a tombstone and not for
 * an arm key), the credential is the node's own, and nothing is fetched.
 */
export function verifyLinkTombstone(
  raw: unknown,
  ctx: { key: string | null; label: string; credential: string },
): TombstoneVerdict {
  const t = parseLinkTombstone(raw);
  if (!t) return { ok: false, why: 'it is not shaped like a tombstone' };
  if (!ctx.key) return { ok: false, why: `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}` };
  if (t.issuer_label !== FLEET_WRITE_ISSUER_LABEL) return { ok: false, why: 'it names another issuer' };
  if (t.label !== ctx.label) return { ok: false, why: 'it is for another label' };
  const mine = createHash('sha256').update(ctx.credential, 'utf8').digest('hex');
  if (t.credential_sha256 !== mine) return { ok: false, why: 'it is for another credential' };
  const body = {
    v: t.v, issuer_label: t.issuer_label, label: t.label,
    credential_sha256: t.credential_sha256, issued_at: t.issued_at,
  };
  if (!verifyWithPeerKey(linkTombstoneSigningBytes(body), t.signature, ctx.key)) {
    return { ok: false, why: 'it is not signed by the aggregator this node pinned' };
  }
  return { ok: true, tombstone: t };
}

/** A tombstone is a few hundred bytes. Anything past this is not one. */
const TOMBSTONE_MAX_BYTES = 4096;

/**
 * The file store, written the way a file this account's own dashboard trusts
 * should be: on descriptors, never by a name checked and then reopened.
 *
 *   write   a fresh temp name opened O_CREAT|O_EXCL|O_NOFOLLOW at 0600, so
 *           nothing already at that name (a link planted beside it) is
 *           followed or reused; written, fsynced, closed, then renamed over
 *           the real name, which replaces a link rather than writing
 *           through one.
 *   read    O_NOFOLLOW|O_NONBLOCK, then checked on the descriptor: a
 *           regular file, owned by this account, nobody else may write it,
 *           bounded. Anything else reads as no tombstone, which costs this
 *           node an hourly probe and nothing more.
 *   remove  unlink; absent is fine.
 */
export function createTombstoneFileStore(path: string): LinkTombstoneStore {
  return {
    read() {
      let fd: number;
      try {
        fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
      } catch {
        return null;
      }
      try {
        const st = fstatSync(fd);
        if (!st.isFile()) return null;
        if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return null;
        if (st.mode & 0o022) return null;
        if (st.size > TOMBSTONE_MAX_BYTES) return null;
        const buf = Buffer.alloc(TOMBSTONE_MAX_BYTES + 1);
        let len = 0;
        for (;;) {
          const n = readSync(fd, buf, len, buf.length - len, null);
          if (n <= 0) break;
          len += n;
          if (len > TOMBSTONE_MAX_BYTES) return null;
        }
        return JSON.parse(buf.subarray(0, len).toString('utf8'));
      } catch {
        return null;
      } finally {
        try { closeSync(fd); } catch { /* already closed */ }
      }
    },
    write(t) {
      const tmp = `${path}.tmp.${randomBytes(8).toString('hex')}`;
      const fd = openSync(
        tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600,
      );
      try {
        writeSync(fd, `${JSON.stringify(t)}\n`);
        fsyncSync(fd);
      } catch (err) {
        try { closeSync(fd); } catch { /* ignore */ }
        try { unlinkSync(tmp); } catch { /* ignore */ }
        throw err;
      }
      closeSync(fd);
      try {
        renameSync(tmp, path);
      } catch (err) {
        try { unlinkSync(tmp); } catch { /* ignore */ }
        throw err;
      }
    },
    remove() {
      try { unlinkSync(path); } catch { /* absent is the goal */ }
    },
  };
}

export interface LinkAgentDeps {
  config: LinkConfig;
  origins: LinkOrigins;
  /** peers.aggregator from THIS node's fleet-trust.yaml, read per connection
   *  so a re-pinned key needs no restart. Null when the node pinned nobody,
   *  which refuses the link rather than trusting the first signer. */
  aggregatorKey: () => string | null;
  /** True when the trust file is on this host and this dashboard's account is
   *  refused reading it (#1183). That is a different thing from a file with no
   *  key in it: the key may be there, and the wait below cannot clear it by
   *  itself if the fix was a group a running process does not pick up. Absent,
   *  the node says only that it holds no key. */
  pinUnreadable?: () => boolean;
  /** This node's own pubkey_node and dashboard version for the hello. */
  identity: () => { pubkey_node: string | null; dashboard_version: string | null };
  /** Opens one WebSocket to the aggregator with the credential in an
   *  Authorization header. Injected so the test drives the protocol without
   *  a socket. */
  dial: (url: string, headers: Record<string, string>) => LinkSocket;
  fetchImpl?: typeof fetch;
  ledger: RefusalLedger;
  log?: (line: string) => void;
  now?: () => number;
  random?: () => number;
  /** Where a signed revocation is kept between refusals (#688). Absent means
   *  none is ever kept, which only costs a revoked node its hourly probe. */
  tombstone?: LinkTombstoneStore;
  /** Schedules the reconnect. Injected so a test drives it synchronously. */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

export interface FleetLinkAgent {
  start: () => void;
  stop: () => void;
  state: () => LinkAgentState;
  /** Test seam: hand one raw frame to the agent as if it arrived. */
  onFrame: (raw: string) => Promise<void>;
}

export function createFleetLinkAgent(deps: LinkAgentDeps): FleetLinkAgent {
  const now = deps.now ?? (() => Date.now());
  const log = deps.log ?? ((line: string) => console.warn(line));
  const doFetch = deps.fetchImpl ?? fetch;
  const setTimer = deps.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
  const clearTimer = deps.clearTimer ?? ((h: unknown) => clearTimeout(h as NodeJS.Timeout));

  let sock: LinkSocket | null = null;
  let verified = false;
  let nonce = '';
  /**
   * The pubkey_node this session's hello actually carried (#291).
   *
   * NOT re-read when the welcome arrives. `deps.identity()` is sourced from
   * the bridge's server_info and is null until the bridge has reached
   * rippled, so a dashboard that dials in its first second sends null,
   * learns its key a moment later, and then refuses the aggregator's honest
   * echo of the null it was sent. On the lab that cost one session per
   * restart and printed a line blaming the aggregator's key for it.
   *
   * The echo is a check that the welcome answers THIS hello. A hello is a
   * thing that was sent, not a thing that is currently true, so the value it
   * is checked against has to be the one that was sent.
   */
  let helloPubkey: string | null = null;
  let attempt = 0;
  /**
   * Requests this node is serving right now, by id (#831). The size IS the
   * in-flight count, and an entry leaves only when its local fetch has
   * settled on its own: an answer, an error, or the 300 s bound.
   *
   * A cancel from the hub does NOT abort the fetch. Aborting rejects the
   * fetch at once while the local handler keeps running (advisord's ask
   * detaches from its caller on purpose and has no cap of its own), so an
   * abort would free this slot for work that is still going, and a hostile
   * aggregator looping request-then-cancel got 64 handlers running against
   * a cap of 16. A cancel only marks the entry: its answer is not sent, and
   * the slot is held until the work is really done. The hub frees its own
   * slot at once, which is all the stall needed. The cap is the bound that
   * survives a compromised aggregator, so nothing the hub sends may shorten
   * it.
   *
   * Before this the count was a number reset to 0 on every drop while the
   * old fetches were still running, and each of them then took one off as
   * it finished, so after a reconnect the count could go below zero and the
   * cap admit more than sixteen.
   */
  const serving = new Map<string, { cancelled: boolean; target: LinkRequest['target'] }>();
  /** One knowledge bundle at a time (#289). The general in-flight cap is 16,
   *  and sixteen 8 MiB bodies is 128 MiB of a node's memory on the word of an
   *  aggregator that may be the compromised party. One is enough: the pusher
   *  sends one bundle per node and waits for the answer. */
  let bundleInflight = false;
  let timer: unknown = null;
  /** Not dialling on backoff: refused by name (and waiting out the hour), or
   *  shut down. */
  let stopped = false;
  /** stop() was called. Nothing dials again until start(). */
  let shutdown = false;
  /** This dial is the hourly question a refused node asks (#688). Its
   *  outcome is either a welcome or the hour again: nothing in between moves
   *  the page off the refusal it is still holding. */
  let probing = false;
  let state: LinkAgentState = {
    phase: 'off', label: deps.config.label, reason: null,
    since_ms: now(), last_ready_ms: null, refused: null,
    next_probe_ms: null, revoked_signed_at_ms: null,
  };

  const setState = (patch: Partial<LinkAgentState>) => {
    state = { ...state, ...patch, since_ms: patch.phase && patch.phase !== state.phase ? now() : state.since_ms };
  };

  const send = (frame: LinkFrame) => {
    if (!sock) return;
    try { sock.send(encodeLinkFrame(frame)); } catch { /* the close handler settles it */ }
  };

  /** Short retries left to the current probe (#688 review, L1). */
  let probeRetries = 0;
  /**
   * Arm the next probe and say when it is due. The hour is jittered by the
   * backoff's own fraction (#688 review, L1): every node told `revoked` by
   * one bad reload was told it in the same second, and an unjittered hour
   * brings them all back in the same second too, against a hub that admits
   * eight handshakes at a time.
   */
  const scheduleProbe = (ms?: number): number => {
    if (timer !== null) clearTimer(timer);
    const rand = deps.random ?? Math.random;
    const wait = ms ?? Math.round(FLEET_LINK_REPROBE_MS * (1 + FLEET_LINK_BACKOFF_JITTER * (rand() * 2 - 1)));
    timer = setTimer(() => {
      timer = null;
      if (shutdown) return;
      probing = true;
      stopped = false;
      connect();
    }, wait);
    return now() + wait;
  };

  /**
   * Wait for the pin by reading the local trust file, and dial the moment it
   * holds a key (#1183). Nothing leaves this host while it waits: the credential
   * goes to the aggregator only once there is a key to verify the aggregator
   * with, which is the point of L4 below.
   */
  const watchForPin = () => {
    if (timer !== null) clearTimer(timer);
    timer = setTimer(() => {
      timer = null;
      if (shutdown) return;
      if (!deps.aggregatorKey()) { watchForPin(); return; }
      log(`[fleet-link] ${deps.config.label}: the trust file now holds a key for `
        + `peers.${FLEET_WRITE_ISSUER_LABEL}; dialling the aggregator`);
      stopped = false;
      probing = false;
      attempt = 0;
      // The refusal it was holding is over: the page must not say "no key"
      // while the node is dialling with one.
      setState({ refused: null, reason: null });
      connect();
    }, FLEET_LINK_PIN_WATCH_MS);
  };

  /** The tombstone this node may act on right now, or null. Read and verified
   *  at the moment of use, against the pin as it is on disk now. */
  const heldTombstone = (): LinkTombstone | null => {
    if (!deps.tombstone) return null;
    const raw = deps.tombstone.read();
    if (raw === null || raw === undefined) return null;
    const verdict = verifyLinkTombstone(raw, {
      key: deps.aggregatorKey(), label: deps.config.label, credential: deps.config.credential,
    });
    return verdict.ok ? verdict.tombstone : null;
  };

  /** A tombstone that arrived on a refusal: kept only if it verifies. */
  const takeTombstone = (raw: unknown) => {
    if (!deps.tombstone) return;
    const verdict = verifyLinkTombstone(raw, {
      key: deps.aggregatorKey(), label: deps.config.label, credential: deps.config.credential,
    });
    if (!verdict.ok) {
      log(`[fleet-link] ${deps.config.label}: the revocation carried a tombstone this node did not keep: ${verdict.why}`);
      return;
    }
    try {
      deps.tombstone.write(verdict.tombstone);
    } catch (err) {
      log(`[fleet-link] ${deps.config.label}: the aggregator's signed revocation could not be kept `
        + `(${(err as Error).message}); this node will ask again in an hour instead`);
    }
  };

  const dropLink = (reason: string, fatal: LinkRefusalCode | null, tombstone?: unknown) => {
    const s = sock;
    sock = null;
    verified = false;
    // Nobody can be waiting on these answers any more: the hub settled every
    // one of them when the link closed. Their answers are suppressed, and
    // their slots stay counted until the local work has finished, for the
    // reason `serving` gives. A reconnect does not reset the count.
    for (const s of serving.values()) s.cancelled = true;
    bundleInflight = false;
    try { s?.close(); } catch { /* already gone */ }
    if (shutdown) return;
    if (fatal) {
      stopped = true;
      probing = false;
      // #688. A refusal that says the credential is dead is final only when
      // the aggregator signed it. Kept first, then read back through the same
      // check a later refusal uses, so the two can never disagree.
      if (fatal === 'revoked' || fatal === 'unauthenticated') {
        if (tombstone !== undefined) takeTombstone(tombstone);
        const held = heldTombstone();
        if (held) {
          if (timer !== null) { clearTimer(timer); timer = null; }
          const at = new Date(held.issued_at).toISOString();
          setState({
            phase: 'stopped', refused: fatal, next_probe_ms: null, revoked_signed_at_ms: held.issued_at,
            reason: `an operator revoked this node on the aggregator at ${at}, and the aggregator signed `
              + 'that revocation, so this node will not dial it again. Pair it again to rejoin the fleet',
          });
          log(`[fleet-link] ${deps.config.label}: the aggregator revoked this link and signed it (${at}). `
            + 'Not dialling again; pair this node again to rejoin');
          return;
        }
      }
      probeRetries = 0;
      // #688 review, L4: a node that cannot verify any aggregator does not
      // send its credential to one every hour. It waits for its pin, and
      // since #1183 it waits by reading its own trust file, not by waiting for
      // a restart: a reinstalled node starts its dashboard before the pin is
      // readable, and a latch that only a restart cleared left the link down
      // on a host that was otherwise right, with the symptom on the aggregator.
      // The read is local and sends nothing, so it is what L4 allows.
      if (FLEET_LINK_NO_REPROBE.has(fatal)) {
        watchForPin();
        const secs = Math.round(FLEET_LINK_PIN_WATCH_MS / 1000);
        let said: string;
        let logged: string;
        if (deps.pinUnreadable?.() === true) {
          // The file is there and this account is refused. Saying "place the
          // key" would send the operator to a file that already holds it, and
          // "nothing needs restarting" is not promised: a group this account
          // joined after it started does not count until it is restarted.
          said = `${reason}, because fleet-trust.yaml is on this host and this dashboard's account `
            + 'cannot read it. Fix its owner, group or mode so that account can. This node reads it again every '
            + `${secs} seconds and links once it can. A group this account joined after it started does not count `
            + 'until this dashboard is restarted';
          logged = `[fleet-link] ${deps.config.label}: stopped (${fatal}). fleet-trust.yaml is here but this `
            + `account cannot read it. Reading it again every ${secs} seconds; a group joined after this `
            + 'dashboard started needs a restart to count';
        } else {
          said = `${reason}. Place the aggregator's key under peers.aggregator in fleet-trust.yaml `
            + `(pairing does this). This node reads that file again every ${secs} seconds and links `
            + 'on its own once the key is there; nothing needs restarting';
          logged = `[fleet-link] ${deps.config.label}: stopped (${fatal}). ${reason}. `
            + `Reading the trust file again every ${secs} seconds, and dialling once it holds the key`;
        }
        setState({
          phase: 'stopped', refused: fatal, next_probe_ms: null, revoked_signed_at_ms: null, reason: said,
        });
        log(logged);
        return;
      }
      const next = scheduleProbe();
      setState({
        phase: 'stopped', refused: fatal, next_probe_ms: next, revoked_signed_at_ms: null,
        reason: `${reason}. This node asks again once an hour and relinks on its own if the aggregator `
          + 'takes it back; nothing needs restarting',
      });
      log(`[fleet-link] ${deps.config.label}: the aggregator refused this link (${fatal}). ${reason}. `
        + 'Asking again in an hour');
      return;
    }
    if (probing) {
      // The probe got no welcome and no fresh refusal: a dead socket, a 429,
      // a 503, a crossed echo. Nothing new was learned about this credential,
      // so the page keeps the refusal it was holding. A few short retries
      // first (#688 review, L1): a busy hub answering the whole fleet's
      // probes at once is exactly when a full hour's wait costs the most.
      // Then back to the hour, never into the open-ended backoff.
      probing = false;
      stopped = true;
      let next: number;
      if (probeRetries < FLEET_LINK_PROBE_SHORT_RETRIES) {
        next = scheduleProbe(nextBackoffMs(probeRetries, deps.random));
        probeRetries += 1;
      } else {
        probeRetries = 0;
        next = scheduleProbe();
      }
      setState({ phase: 'stopped', next_probe_ms: next });
      return;
    }
    if (stopped) return;
    setState({ phase: 'dialing', reason });
    const wait = nextBackoffMs(attempt, deps.random);
    attempt += 1;
    timer = setTimer(() => { timer = null; connect(); }, wait);
  };

  async function serve(req: LinkRequest): Promise<void> {
    // The concurrency cap is enforced on the NODE as well as the hub. The hub
    // enforcing it is a courtesy to itself; this is the enforcement that
    // survives a compromised aggregator.
    if (serving.size >= FLEET_LINK_MAX_INFLIGHT) {
      deps.ledger.note(`${req.target}:?`, 'concurrency_cap', auditPath(req.path.split('?')[0]));
      send(refusal('concurrency_cap', 'this node is already serving as many link requests as it takes', req.id));
      return;
    }
    // #831: the node's half of the Advisor share. Counted over everything
    // still running, cancelled work included, so abandoned asks piling up on
    // a slow advisord can never take the slots a read needs.
    if (req.target === 'advisor') {
      let advisor = 0;
      for (const s of serving.values()) if (s.target === 'advisor') advisor += 1;
      if (advisor >= FLEET_LINK_ADVISOR_MAX_INFLIGHT) {
        deps.ledger.note(`${req.target}:?`, 'concurrency_cap', auditPath(req.path.split('?')[0]));
        send(refusal('concurrency_cap', 'this node is already running as much Advisor work as it takes', req.id));
        return;
      }
    }
    const bundle = isLinkBundleRequest(req.target, req.method, req.path.split('?')[0]);
    if (bundle && bundleInflight) {
      deps.ledger.note(`${req.target}:?`, 'concurrency_cap', auditPath(req.path.split('?')[0]));
      send(refusal('concurrency_cap', 'this node is already taking a knowledge bundle', req.id));
      return;
    }
    const verdict = decideLinkRequest(req, deps.origins);
    if (!verdict.ok) {
      // The audit row and the refusal frame, together, always. ADR 0019
      // decision 2: "a test, not a comment".
      deps.ledger.note(verdict.route, verdict.code, verdict.path);
      send(refusal(verdict.code, verdict.detail, req.id));
      return;
    }
    // A duplicate id is a hub bug or a hostile one. Refused rather than
    // served, so one entry in `serving` always means one local fetch.
    if (serving.has(req.id)) {
      send(refusal('bad_frame', 'that request id is already in flight on this link', req.id));
      return;
    }
    const slot = { cancelled: false, target: req.target };
    serving.set(req.id, slot);
    if (bundle) bundleInflight = true;
    try {
      const res = await doFetch(verdict.url, {
        method: verdict.method,
        headers: forwardableHeaders(req.headers),
        body: req.method === 'GET' || req.method === 'HEAD' ? undefined : (req.body ?? undefined),
        signal: AbortSignal.timeout(300_000),
      });
      const text = await res.text();
      if (slot.cancelled) return;
      if (Buffer.byteLength(text, 'utf8') > FLEET_LINK_MAX_RESPONSE_BYTES) {
        send(refusal('body_too_large', 'that answer is larger than the link carries', req.id));
        return;
      }
      const headers: Record<string, string> = {};
      const ct = res.headers.get('content-type');
      if (ct) headers['content-type'] = ct;
      const clean = normaliseHeaders(headers) ?? {};
      send({ t: 'res', v: FLEET_LINK_PROTOCOL_VERSION, id: req.id, status: res.status, headers: clean, body: text });
    } catch (err) {
      // A cancelled request gets no answer: the hub has already forgotten
      // the id and would drop one anyway.
      if (slot.cancelled) return;
      const message = (err as Error).name === 'TimeoutError' ? 'upstream_timeout' : 'upstream_unreachable';
      send(refusal(message as LinkRefusalCode, 'this node could not reach its own service for that request', req.id));
    } finally {
      serving.delete(req.id);
      if (bundle) bundleInflight = false;
    }
  }

  async function onFrame(raw: string): Promise<void> {
    // An identity that changes under a live link is a reason to say hello
    // again, not a reason to refuse the aggregator (#291). The welcome this
    // session holds is signed over the key the hello carried; once this node
    // answers to a different one, that statement is about a key this node no
    // longer has, and the honest move is a new hello carrying the new one.
    // Checked on an arriving frame rather than on a timer of its own: the
    // aggregator polls, so frames arrive, and a timer that exists only to
    // notice a thing that almost never happens is a timer to get wrong.
    if (verified && (deps.identity().pubkey_node ?? null) !== helloPubkey) {
      attempt = 0;
      dropLink("this node's identity changed after it said hello, so it is saying hello again", null);
      return;
    }
    const parsed = parseLinkFrame(raw);
    if (!parsed.ok) {
      send(refusal(parsed.code, parsed.detail));
      dropLink(parsed.detail, parsed.code === 'protocol_version_unsupported' ? 'protocol_version_unsupported' : null);
      return;
    }
    const frame = parsed.frame;
    if (frame.t === 'refuse') {
      const fatal = FLEET_LINK_FATAL_REFUSALS.has(frame.code) ? frame.code : null;
      if (frame.id) return; // a per-request refusal from the hub is not a link event
      // #687: `registry_held` is the one refusal where the fix is on the
      // OTHER box, so it gets a line of its own. Every other non-fatal drop
      // lands on the node's Settings page and in the reason field; this one
      // has to say, in the journal an operator greps during an outage, that
      // nothing on this node is wrong and nothing on this node has to be
      // restarted. The retry is the plain backoff, unchanged.
      if (frame.code === 'registry_held') {
        log(`[fleet-link] ${deps.config.label}: the aggregator is holding this node's row and is not `
          + `linking it: ${frame.detail ?? 'no reason given'}. Fix that on the aggregator and reload it; `
          + 'this node keeps retrying and needs no restart');
      }
      // #687 review, F2: the aggregator closed a link it means to take back
      // at once, because the row's ports moved and its loopback listener is
      // bound at the handshake. Said apart from a hold, which needs an
      // operator, and from a drop, which needs nobody: this one resolves on
      // the very next dial.
      if (frame.code === 'rebinding') {
        log(`[fleet-link] ${deps.config.label}: the aggregator is rebinding this link `
          + `(${frame.detail ?? 'its row changed'}); redialling`);
      }
      dropLink(frame.detail ?? `the aggregator refused: ${frame.code}`, fatal, frame.tombstone);
      return;
    }
    if (frame.t === 'welcome') {
      if (verified) return;
      const key = deps.aggregatorKey();
      if (!key) {
        send(refusal('no_aggregator_pinned',
          `this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}, so it trusts no aggregator to reach it`));
        dropLink(`this node holds no key for peers.${FLEET_WRITE_ISSUER_LABEL}`, 'no_aggregator_pinned');
        return;
      }
      // The echo, against what THIS session's hello carried (#291), and
      // said apart from the signature. They are two different findings and
      // an operator reading a log during an incident has to be able to tell
      // them apart: an echo that does not match is a conversation that got
      // crossed, and a signature that does not verify is the aggregator
      // failing to prove who it is. Blaming the pinned key for the first was
      // pointing at the wrong end of the link.
      const echoOk = frame.nonce === nonce
        && frame.label === deps.config.label
        && (frame.pubkey_node ?? null) === helloPubkey;
      if (!echoOk) {
        send(refusal('bad_frame', 'the welcome did not echo this node\'s hello'));
        dropLink('the welcome did not echo this node\'s hello', null);
        return;
      }
      const signed = linkChallengeSigningBytes({
        v: FLEET_LINK_PROTOCOL_VERSION,
        issuer_label: frame.issuer_label,
        nonce: frame.nonce,
        label: frame.label,
        pubkey_node: frame.pubkey_node ?? null,
        issued_at: frame.issued_at,
      });
      if (frame.issuer_label !== FLEET_WRITE_ISSUER_LABEL || !verifyWithPeerKey(signed, frame.signature, key)) {
        // A wrong issuer and a bad signature ARE the same fact: this is not
        // the aggregator this node pinned. Not fatal: the aggregator may be
        // mid-rotation, and a node that stopped dialling forever on one bad
        // frame would need a manual restart to come back.
        send(refusal('bad_signature', 'that welcome was not signed by the aggregator this node pinned'));
        dropLink('the aggregator did not prove it holds the pinned fleet trust key', null);
        return;
      }
      verified = true;
      attempt = 0;
      const wasRefused = probing ? state.refused : null;
      probing = false;
      probeRetries = 0;
      stopped = false;
      setState({
        phase: 'ready', reason: null, last_ready_ms: now(), refused: null,
        next_probe_ms: null, revoked_signed_at_ms: null,
      });
      // #688: a welcome is the aggregator taking this node back, so whatever
      // it signed before is about a relationship that exists again.
      deps.tombstone?.remove();
      // #831: this agent honours a cancel frame. A hub older than that
      // drops the list unread (see LinkReady.caps).
      send({ t: 'ready', v: FLEET_LINK_PROTOCOL_VERSION, caps: ['cancel'] });
      log(`[fleet-link] ${deps.config.label}: linked to ${deps.config.aggregator_url}`
        + (wasRefused ? ` (it had refused this node: ${wasRefused}; relinked with no restart)` : ''));
      return;
    }
    if (frame.t === 'cancel') {
      // An id this node is not serving (already answered, or never seen) is
      // ignored: the race between an answer and a cancel is ordinary.
      if (!verified) return;
      const slot = serving.get(frame.id);
      // Marked, not aborted: see `serving`.
      if (slot) slot.cancelled = true;
      return;
    }
    if (frame.t === 'req') {
      if (!verified) {
        // Requests before the aggregator has proved itself are refused
        // rather than served. This is the gate that makes the pin mean
        // anything at all.
        send(refusal('link_not_ready', 'this node has not verified the aggregator yet', frame.id));
        return;
      }
      await serve(frame);
      return;
    }
    // hello / ready / res travel the other way. A node receiving one is
    // talking to something that is not a hub.
    send(refusal('bad_frame', 'that frame travels the other way on this link'));
    dropLink('the far end sent a frame a node never receives', null);
  }

  function connect(): void {
    if (stopped || shutdown) return;
    // A probe keeps the page on the refusal it is asking about (#688): the
    // node has not been taken back until a welcome says so.
    if (!probing) setState({ phase: 'dialing', reason: state.reason });
    nonce = randomBytes(16).toString('hex');
    let s: LinkSocket;
    try {
      s = deps.dial(deps.config.aggregator_url, { authorization: `Bearer ${deps.config.credential}` });
    } catch (err) {
      dropLink(`the aggregator could not be dialled: ${(err as Error).message}`, null);
      return;
    }
    sock = s;
    verified = false;
    s.on('open', () => {
      // Read HERE, at the moment the hello is built, and remembered. The
      // dial and the open are two different moments and the bridge may have
      // reached rippled between them.
      const id = deps.identity();
      helloPubkey = id.pubkey_node ?? null;
      send({
        t: 'hello', v: FLEET_LINK_PROTOCOL_VERSION,
        label: deps.config.label,
        pubkey_node: helloPubkey,
        dashboard_version: id.dashboard_version,
        challenge_nonce: nonce,
      });
    });
    s.on('message', (data?: unknown) => {
      void onFrame(String(data));
    });
    s.on('close', () => {
      if (sock !== s) return;
      dropLink('the link to the aggregator closed', null);
    });
    // The upgrade was refused with a status rather than accepted. `ws` emits
    // this before `error`, and it is the only place a node can learn that the
    // aggregator has refused it BY NAME (#280): there is no WebSocket, so
    // there is no refusal frame to receive.
    s.on('unexpected-response', (_req?: unknown, res?: unknown) => {
      if (sock !== s) return;
      const status = Number((res as { statusCode?: unknown } | undefined)?.statusCode ?? 0);
      const fatal = refusalForStatus(status);
      if (fatal) {
        dropLink(
          `the aggregator refused this node's credential (HTTP ${status}): it is unknown to that `
          + 'aggregator, or it was revoked',
          fatal,
        );
        return;
      }
      // #688: a 503 is this aggregator saying it cannot judge a credential
      // right now, because its own link registry is missing or unreadable.
      // Transient by construction, so the backoff is the whole answer, and
      // the line says which box to look at.
      if (status === 503) {
        // Said out loud, because dropLink only logs a FATAL refusal and this
        // one is the opposite: the node is fine, the aggregator is not
        // serving, and an operator reading this node's journal during an
        // outage needs to be sent to the other box.
        // Not said on an hourly probe: that node is not retrying, it is going
        // back to the hour, and dropLink keeps the refusal it already holds.
        if (!probing) {
          log(`[fleet-link] ${deps.config.label}: the aggregator is not accepting links right now `
            + '(HTTP 503, which it answers while it cannot read its own link registry). Retrying');
        }
        dropLink(
          'the aggregator is not accepting links right now (it answered 503, which it sends while it '
          + 'cannot read its own link registry). This node keeps retrying and needs no restart',
          null,
        );
        return;
      }
      dropLink(`the aggregator answered the link with HTTP ${status || 'no status'}`, null);
    });
    s.on('error', (err?: unknown) => {
      // A refusal already settled this socket: ws emits `error` after
      // `unexpected-response` for the same rejection, and dropLink clears
      // `sock`, so this guard is what stops the second event turning a fatal
      // stop back into a retry.
      if (sock !== s) return;
      dropLink(`the link to the aggregator failed: ${(err as Error | undefined)?.message ?? 'no reason given'}`, null);
    });
  }

  return {
    start() {
      stopped = false;
      shutdown = false;
      probing = false;
      probeRetries = 0;
      attempt = 0;
      connect();
    },
    stop() {
      stopped = true;
      shutdown = true;
      probing = false;
      if (timer !== null) { clearTimer(timer); timer = null; }
      const s = sock;
      sock = null;
      verified = false;
      try { s?.close(); } catch { /* already gone */ }
      deps.ledger.flush();
      setState({
        phase: 'off', reason: 'this dashboard is shutting down', refused: null,
        next_probe_ms: null, revoked_signed_at_ms: null,
      });
    },
    state: () => state,
    onFrame,
  };
}

/** The sentence the node's own Settings page prints. One line, and it never
 *  says "linked" for a link that is not carrying anything. */
export function linkFactLine(state: LinkAgentState | null): string | null {
  if (!state || state.phase === 'off') return null;
  if (state.phase === 'ready') return `linked to the aggregator as ${state.label}`;
  if (state.phase === 'stopped') {
    return `refused by the aggregator (${state.refused}): ${state.reason ?? 'no reason given'}`;
  }
  return `dialling the aggregator${state.reason ? `: ${state.reason}` : ''}`;
}

export type { LinkTarget };
