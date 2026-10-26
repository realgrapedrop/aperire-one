/**
 * The aggregator's half of the fleet link — ADR 0019 decisions 1 and 2.
 *
 * A node dials `/fleet/v1/link` and holds it. This module accepts that
 * connection, proves to the node that it holds the fleet trust key, and then
 * binds ONE LOOPBACK LISTENER per registered origin for that node: the read
 * origin always, the advisor origin when the row has one. Those are the same
 * `790x` / `781x` ports the SSH forwards landed on, so
 * `lib/fleet-health.ts`, `lib/fleet-fetch-through.ts`, `lib/peer-read-proxy.ts`,
 * `lib/peer-advisor-proxy.ts` and `lib/fleet-write-api.ts` keep dialling what
 * they already dial and none of them changes.
 *
 * Everything the hub can do to a node is bounded by what the NODE allows
 * (lib/fleet-link-agent.ts). This side is a courier.
 *
 * The node list is dashboard/config/fleet-links.json, and the root broker
 * writes it at a passkey-approved pairing (phase 3, the second half of this
 * file). An operator may still place a row by hand for a node they cannot run
 * a command on, which is why both parsers still fail the whole file closed and
 * why the cross-check below exists.
 */

/*
 * SECURITY REVIEW — ADR 0019 decision 4, row by row, against what phases 1
 * and 2 actually built. Written when the code was, not afterwards from
 * memory, and it says where a row is only PARTLY true today.
 *
 * The ADR's own consequences make this mandatory: "/fleet/v1/link is
 * reachable from the internet by design. It must rate-limit by address,
 * refuse an unknown credential without saying which part was wrong, cap
 * concurrent links and unauthenticated handshakes, and refuse plaintext. It
 * gets its own security review before it ships, like /fleet/v1/ did."
 *
 * 1. AGGREGATOR DASHBOARD PROCESS COMPROMISED
 *    Gets: every node's read surface, and it can send seal and arm requests.
 *    Held: it cannot reach anything outside the node-side allow-list. That
 *    is lib/fleet-link-agent.ts's decideLinkRequest, which parses a request
 *    to a (target, method, route name) and REBUILDS the URL from the name,
 *    so no string off the wire is ever dialled. It cannot open an arm window
 *    (root does that, ADR 0018 decision 4), cannot open the fleet's sealed
 *    model at /etc/aperire/fleet-model.cred (root's, and no verb on the root
 *    broker returns the key), and cannot sign a seal job: a job
 *    carrying this hub's own signature still has to verify against the key
 *    the NODE pinned, which this process can read but a job it forged
 *    without the seed cannot satisfy.
 *    Honest gap: the seed IS readable by this account (readOwnPrivateKey),
 *    so a compromised aggregator CAN sign both a seal job and a link
 *    challenge. That is not new with this lane, it is ADR 0018's accepted
 *    trade-off, and the arm window is what stands behind it.
 *    Also held: a signing key it cannot use is a named refusal and not an
 *    exception (#281); an unguarded throw inside a message handler was a
 *    crash loop driven by an ordinary node reconnecting.
 *    Widened since the first review, twice, and bounded both times. The
 *    allow-list carries POST /v1/knowledge/bundle (#289) at advisord's own
 *    8 MiB rather than the link's 256 KiB, which is the only route with a
 *    cap of its own; a compromised aggregator can therefore make a node
 *    hold 8 MiB, ONE at a time per link, on either side, and the node
 *    refuses a second by name rather than queueing it. It buys nothing but
 *    memory: the node applies a bundle only if its manifest verifies
 *    against the fleet key it pinned. Chunking was refused for the same
 *    reason this cap is a number: a reassembly buffer is a place to spend
 *    memory that has no bound written next to it.
 *    Also held: only three headers cross into a node's local dial
 *    (forwardableHeaders), so this side cannot hand a node's fetch a `host`
 *    or a `content-length` of its choosing.
 *    Widened since the first review: the allow-list carries POST
 *    /v1/trust/bundle (#288), so this process can push an admin trust bundle
 *    to a node. It buys a compromised aggregator nothing. advisord verifies
 *    the bundle's signature against the fleet key the NODE pinned at join
 *    before it installs a single credential, which is the same wall as the
 *    seal job in the paragraph above and fails in the same place. The
 *    honest gap is also the same one: this account can read the seed, so it
 *    can sign a bundle as well as a job. That is ADR 0018's accepted
 *    trade-off, not a new one this route opened.
 *
 * 2. NODE DASHBOARD PROCESS COMPROMISED
 *    Gets: that node's own data, and it can lie down the link.
 *    Held: the link is outbound and answers only allow-listed local
 *    requests. This hub treats every frame from a node as untrusted input:
 *    parseLinkFrame validates the shape and the version before any field is
 *    read, a response is matched to an id THIS hub issued (an unmatched id
 *    is dropped, never acted on), a status must be 100..599, a body is
 *    capped at FLEET_LINK_MAX_RESPONSE_BYTES, and a header value carrying a
 *    control character is refused rather than sanitised, which is what stops
 *    a lying node splitting the HTTP response this hub writes back onto its
 *    loopback listener.
 *    A node cannot reach another node: it holds one link, and this hub sends
 *    requests down that link and never accepts one.
 *
 * 3. LINK CREDENTIAL STOLEN
 *    Gets: nothing on its own.
 *    Cannot impersonate the aggregator: the node demands a signature by the
 *    pinned fleet key on EVERY connection, over a nonce the NODE minted, so
 *    a recorded (challenge, signature) pair from an earlier session is
 *    worthless. Test: "a replayed signature from an earlier session does not
 *    verify".
 *    Cannot impersonate another node: the credential resolves exactly one
 *    row (resolveCredential), the hello's label must match that row
 *    (`label_mismatch`), and the peer is served under that row's
 *    expected_pubkey_node, which fleet-fetch-through and every proxy check
 *    against the node's own /read/v1/identity.
 *    A node refused at the upgrade hears it: the refusal is an HTTP status
 *    with no WebSocket behind it, so the agent reads the status off
 *    `unexpected-response` and stops on 401/403 rather than dialling a
 *    public endpoint forever (#280).
 *    Revocation is one row deleted plus a reload, and it closes the link
 *    that is ALREADY up rather than only the next dial: reconcile() sends a
 *    `revoked` refusal and tears the listener down, because a connected node
 *    has no reason to redial and would otherwise keep serving on a
 *    credential the operator just took away. Re-minting a credential counts
 *    as a revocation of the old one, by the same path. The agent stops
 *    retrying on the name and says so on the node's own page.
 *
 * 4. PAIRING CODE STOLEN
 *    Gets: a PENDING ROW, inside fifteen minutes, and this aggregator's two
 *    PUBLIC keys, and (#626, below) whether a node key it names is one this
 *    aggregator watches over a tunnel. Nothing else.
 *    Precisely: one WebSocket held open here in a pool of four, one row in
 *    Settings with a label, a node key and an address all chosen by the
 *    thief, and one line in this journal. No listener is bound (a `ready`
 *    frame on a pairing session is refused by name and binds nothing), no
 *    file is written, no token crosses and nothing is served.
 *    Pairing v2: a hello carrying `keys_first` also gets `pair_keys`, the
 *    fleet trust and fleet arm PUBLIC keys, so the thief can compute the
 *    pairing fingerprint. Every node already paired here holds both keys
 *    (peers.aggregator in its fleet-trust.yaml, and its fleet-arm.pub), so
 *    this tells nobody anything a paired node could not. They go only to a
 *    socket that presented a live code, which is spent by then, and never
 *    on a dial that presented none: an unauthenticated caller can neither
 *    reach root's broker through this hub nor link two hostnames to one
 *    aggregator by its keys. The keys are read from a cache an
 *    administrator's mint filled, so a code holder's dial asks root for
 *    nothing. And the thief's `pair_checked {matched: true}` is a signal
 *    with no weight: it unlocks Approve on the thief's own row, which an
 *    administrator still has to compare by node key and approve under a
 *    passkey, exactly as before.
 *    To become a node the thief needs an administrator to compare their
 *    fingerprint against what the real node printed and press Approve under
 *    a passkey. That is the anchor, and it is the same anchor every join in
 *    this product has used.
 *    #626, A KNOWN NODE'S MOVE. A thief who also presents the node key of a
 *    node this fleet reads over an SSH tunnel used to get a row offering
 *    "Approve and move", and that key is public (every peer the node
 *    connects to sees it). Now the move is offered only on `tunnel_proof`
 *    in `pair_checked`: a MAC under the read token this aggregator already
 *    reads that node with, checked in constant time against the tunnel
 *    row's own token_path copy (fleetKnownNodeProof in the contract). The
 *    thief holds the code and the key, not the token, so the row is refused
 *    before approval and no passkey is spent on it. Held against:
 *      - a proof over a nonce the node chose: the hub checks against the
 *        hub_nonce it KEPT when it sent pair_keys, and never reads one off
 *        the frame (the parser drops any);
 *      - a proof replayed from an earlier pairing: a fresh hub_nonce each
 *        time;
 *      - a proof relayed to another aggregator: the trust key is bound in;
 *      - an older node, or a hub that sent no keys: no proof can come back,
 *        so the move is refused at call-in, and approve() and the settings
 *        route refuse `move_unverified` behind that.
 *    NOT held against: a copy of the node's disk, which holds the token.
 *    The row says so.
 *    Held against, at the human step too (#626 review, L2): a refused
 *    proof's note never tells the administrator to replace the row's token
 *    while this aggregator's own tunnel read still works with the one it
 *    holds. A thief refused for a junk proof who then says "I reinstalled,
 *    here is my new token" would otherwise get the row by asking. Reinstall
 *    advice appears only when the tunnel itself is refused 401/403, and
 *    then behind "confirm it on the node's own console first". The root
 *    socket never sees the proof and need not: this account can read the
 *    tunnel token already, so the proof is no wall between it and root.
 *    Accepted, and named: a code holder now learns ONE BIT it did not
 *    before, whether this aggregator watches a given node key over a
 *    tunnel. A known key is refused (at call-in, or right after its check)
 *    where a new key waits. Each probe costs a code an administrator minted,
 *    one use, fifteen minutes, and the clash refusal (#620) already tells a
 *    code holder as much about a key that is live on the link. The token never crosses before approval and is in no
 *    frame, row, response or journal line; the node computes the MAC only
 *    after its operator's paste matched, so it goes only to an aggregator
 *    root vouched for.
 *    What bounds the code itself: 100 bits (guessing is not a threat at any
 *    rate limit), one use, fifteen minutes, and a mint that is admin-gated,
 *    so a code exists only because an administrator made one. The
 *    presentation guard is a SEPARATE bucket from the link guard, so a
 *    stranger spraying garbage codes cannot deny the fleet its transport —
 *    which is the exact mistake #279 was.
 *    Accepted, and named rather than mitigated: an operator who approves
 *    without comparing gets what they approved. There is no technical
 *    control behind that one.
 *
 * 5. TLS INTERCEPTION AT THE AGGREGATOR
 *    The ADR's control is "decideIngest's plaintext refusal". It is reused
 *    here and it is WEAKER than that line reads, so this is the row to be
 *    exact about. The dashboard speaks node:http and binds 127.0.0.1 by
 *    default (server.ts's HOST), with TLS terminated by a proxy in front. So
 *    decideIngest answers `loopback-bind` for an internet request exactly as
 *    it does for a local one: it cannot see whether the hop was encrypted,
 *    and it never will from this side. It still earns its place, because the
 *    one arrangement it CAN see (a dashboard bound to a LAN address, dialled
 *    directly in plain ws) is refused before the credential is compared.
 *    The load-bearing refusal is on the NODE, in parseLinkConfig: the
 *    aggregator_url must be wss:// unless its host is loopback. The node is
 *    the only party holding the URL, so it is the only party that knows.
 *    Both halves are tested; neither is claimed to be the other.
 *
 * 6. SEAL JOB REPLAYED
 *    Unchanged, and deliberately: the link is a courier. A seal arrives at
 *    the node's own /fleet/v1/model/seal through the node's own loopback and
 *    meets ADR 0018 decision 3's gates 5, 7 and 8 (target node, freshness,
 *    nonce) exactly as it did behind a tunnel. The link adds no replay
 *    window because it adds no acceptance.
 *
 * 7. ROGUE NODE CLAIMS A LABEL
 *    Gets: refused at the upgrade. A label is a name the caller chose; a
 *    credential is not, so the row is resolved from the credential and a
 *    hello claiming a different label is `label_mismatch`. A node that
 *    reconnects REPLACES its own link and no other: the map is keyed by the
 *    label the credential resolved.
 *
 * WHAT THIS ENDPOINT COSTS A STRANGER, and the four controls the ADR named:
 *   - plaintext:  refused for the arrangement decideIngest can see, and by
 *                 the node for the hop that matters (row 5).
 *   - unknown credential: one 401 and one sentence, "unknown credential",
 *                 for no header, a bad header, a revoked credential and a
 *                 credential for a node not in the file. It names no label
 *                 and no port. Constant-time comparison, and the loop does
 *                 not break on a hit, so the timing does not say how far
 *                 down the file a match sits.
 *   - rate limit: per CALLER, windowed, and checked AFTER the credential
 *                 (#279). Both halves of that are the fix. Keyed on the
 *                 first hop of x-forwarded-for when the peer is the local
 *                 TLS proxy and on the socket address otherwise, because on
 *                 a real aggregator the socket address is the proxy's for
 *                 every caller: one bucket for the internet and the whole
 *                 fleet. And checked after the credential, so a bucket a
 *                 stranger filled can never refuse a node holding a valid
 *                 one, which is what turned this control into the denial it
 *                 was written to prevent. The failure map is bounded and
 *                 evicted oldest-first, and IPv6 collapses to its /64.
 *   - caps:       two on the link path, both GLOBAL and neither reachable by
 *                 a stranger. Half-open links awaiting a hello: each already
 *                 presented a valid credential (the counter is incremented
 *                 inside the upgrade callback, which only a resolved row
 *                 reaches) and holds its slot for
 *                 FLEET_LINK_HELLO_TIMEOUT_MS and no longer. Then
 *                 established links, in-flight requests per link, request
 *                 and response bytes, header count and header bytes.
 *
 *                 PHASE 3 CORRECTS THE SENTENCE THAT WAS HERE. The first
 *                 review of this file said "an UNAUTHENTICATED caller never
 *                 occupies a slot at all", and called that stronger than the
 *                 ADR asked for. It is no longer true, by exactly four
 *                 sockets: a pairing session presents no credential and
 *                 holds a slot from the upgrade until its hello. What keeps
 *                 the correction bounded is that those four slots are a
 *                 SEPARATE counter with a separate cap
 *                 (FLEET_LINK_MAX_PAIRINGS), so `pendingHandshakes` still
 *                 counts only credentialled sockets and the link path's
 *                 property is untouched. The new surface is four sockets for
 *                 ten seconds, and the same counter bounds the Pending rows
 *                 that survive a hello, so nothing here grows without a
 *                 number written next to it.
 *
 * ONE THING THIS DOES NOT CHANGE, said plainly because it is easy to read
 * the loopback listener as new exposure: anything running on the aggregator
 * that can reach 127.0.0.1:790x could already reach the SSH forward on the
 * same port, and still needs that node's read token to get an answer. The
 * listener is bound to 127.0.0.1 by the bind itself rather than by a check
 * inside the handler, and a bind that fails closes the link by name instead
 * of serving beside whatever already holds the port.
 */
import { createHash, timingSafeEqual, randomUUID, randomBytes } from 'node:crypto';
import { readBody, type BodyOutcome } from './read-body.js';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { decideIngest, isLoopbackHost } from './ingest-policy.js';
import { READ_STREAM_PATH } from '../types/read-contract.js';
import { FLEET_WRITE_ISSUER_LABEL } from '../types/fleet-write-contract.js';
import { classifyPairKey } from './fleet-pair-classify.js';
import type { FleetNodeConfig } from './fleet-registry.js';
import type { TunnelAuth } from './fleet-health.js';
import {
  FLEET_LINK_PROTOCOL_VERSION, FLEET_LINK_PATH, FLEET_LINK_MAX_INFLIGHT, FLEET_LINK_ADVISOR_MAX_INFLIGHT,
  FLEET_LINK_MAX_RESPONSE_BYTES, FLEET_LINK_REQUEST_TIMEOUT_MS,
  linkRequestCap, isLinkBundleRequest,
  FLEET_LINK_HELLO_TIMEOUT_MS, LINK_LABEL_RE,
  FLEET_LINK_MAX_PAIRINGS, FLEET_PAIR_HEADER, FLEET_PAIR_KEEPALIVE_MS, FLEET_PAIR_MAX_PER_KEY,
  FLEET_PAIR_MAX_WINDOW_MS,
  pairSettledSigningBytes,
  linkChallengeSigningBytes, pairChallengeSigningBytes, linkTombstoneSigningBytes,
  isFleetArmPubkey, fleetKnownNodeProofMatches,
  parseLinkFrame, encodeLinkFrame, refusal, normaliseHeaders, pairDashboardUrl,
  type LinkRefusalCode, type LinkTarget, type LinkFrame, type LinkTombstone,
} from '../types/fleet-link-contract.js';

// ── The registry file ────────────────────────────────────────────────────

export interface LinkRegistryRow {
  label: string;
  /** SHA-256 of that node's credential, hex. The aggregator never holds the
   *  credential itself: a file it can read is a file a compromised dashboard
   *  can read, and a hash is not a credential. */
  credential_sha256: string;
  /** The loopback port this node's read origin binds at, the `790x` the
   *  fleet.yaml row already names as read_origin. */
  read_port: number;
  /** The `781x`, when this node runs an Advisor. */
  advisor_port?: number;
}

export interface LinkRegistryParse {
  links: LinkRegistryRow[];
  /** Set only when the file existed and failed to validate. */
  error: string | null;
}

const SHA256_RE = /^[0-9a-f]{64}$/;
const ROW_KEYS = ['label', 'credential_sha256', 'read_port', 'advisor_port'] as const;

/**
 * Fail-closed, the lib/fleet-registry.ts rule and for the same reason: one
 * malformed row drops the WHOLE file rather than serving a partial fleet. A
 * file that binds three of four nodes and says nothing is worse than one that
 * binds none and says why.
 */
export function parseLinkRegistry(text: string): LinkRegistryParse {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch (err) {
    return { links: [], error: `fleet-links.json is not valid JSON: ${(err as Error).message}` };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { links: [], error: 'fleet-links.json must be an object with a "links" list' };
  }
  const list = (doc as Record<string, unknown>).links;
  if (list === undefined) return { links: [], error: null };
  if (!Array.isArray(list)) return { links: [], error: 'fleet-links.json "links" must be a list' };

  const rows: LinkRegistryRow[] = [];
  const labels = new Set<string>();
  const ports = new Set<number>();
  for (let i = 0; i < list.length; i++) {
    const raw = list[i];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { links: [], error: `links[${i}] is not an object` };
    }
    const obj = raw as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      if (!(ROW_KEYS as readonly string[]).includes(k)) {
        return { links: [], error: `links[${i}] has an unknown key "${k}"` };
      }
    }
    const label = obj.label;
    if (typeof label !== 'string' || !LINK_LABEL_RE.test(label)) {
      return { links: [], error: `links[${i}] label must match [a-z0-9-]{1,32}` };
    }
    if (labels.has(label)) return { links: [], error: `fleet-links.json has a duplicate label "${label}"` };
    labels.add(label);
    const hash = obj.credential_sha256;
    if (typeof hash !== 'string' || !SHA256_RE.test(hash)) {
      return { links: [], error: `links[${i}] credential_sha256 must be 64 hex characters` };
    }
    const readPort = obj.read_port;
    if (typeof readPort !== 'number' || !Number.isInteger(readPort) || readPort < 1024 || readPort > 65535) {
      return { links: [], error: `link "${label}" read_port must be an integer between 1024 and 65535` };
    }
    if (ports.has(readPort)) return { links: [], error: `fleet-links.json binds port ${readPort} twice` };
    ports.add(readPort);
    let advisorPort: number | undefined;
    if (Object.prototype.hasOwnProperty.call(obj, 'advisor_port')) {
      const p = obj.advisor_port;
      if (typeof p !== 'number' || !Number.isInteger(p) || p < 1024 || p > 65535) {
        return { links: [], error: `link "${label}" advisor_port must be an integer between 1024 and 65535` };
      }
      if (ports.has(p)) return { links: [], error: `fleet-links.json binds port ${p} twice` };
      ports.add(p);
      advisorPort = p;
    }
    rows.push({ label, credential_sha256: hash, read_port: readPort, ...(advisorPort ? { advisor_port: advisorPort } : {}) });
  }
  return { links: rows, error: null };
}

/**
 * The two files must agree, or neither serves (#282).
 *
 * A pairing writes both at once and validates them together, so the case this
 * guards is the OTHER one: `fleet-links.json` on the aggregator and
 * `fleet.yaml` beside it, edited by hand for a node nobody could run a command
 * on, and until this check nothing compared them. One transposed digit bound node1's link on node2's origin: every
 * poll, fetch-through, read proxy and seal aimed at node2 reached node1,
 * node2's own link could then never bind and was refused `bind_failed` for as
 * long as the file said so, and node1's row dialled a port with nothing on
 * it. A double outage whose only symptom names a port rather than a conflict.
 *
 * Two things stood behind it and neither is a check. The per-node read token
 * usually turns the swap into a 401 rather than wrong data, and
 * `expected_pubkey_node` would catch the identity swap, and it is OPTIONAL,
 * so a hand-placed row without one has nothing left. Two nodes sharing a read
 * token (a copied install, a restored backup) plus an unpinned row is
 * silently wrong fleet data under the wrong label, which is the class this
 * project keeps paying for.
 *
 * Three refusals, each naming the file to fix:
 *
 *   1. a link row for a label `fleet.yaml` does not name at all
 *   2. a link row whose port is not the port that label's origin names
 *   3. a link row whose `fleet.yaml` entry does not say `transport: link`
 *
 * The third makes intent and binding agree by construction rather than by an
 * operator's care: a row that binds a port the fleet believes is a tunnel is
 * a disagreement even when the numbers match.
 *
 * ONE ROW, ONE REFUSAL (#687). This used to fail the whole file closed, and
 * on koi one hand-edited row took every link on the fleet down with it: three
 * rows, one of them inconsistent, and all three nodes were told `revoked`.
 * A row is now held on its own. Every consistent row keeps serving, the held
 * row is named with both files in the sentence, and the node holding that row
 * is refused `registry_held`, which it retries.
 *
 * ONE CLASS STILL TAKES ITS NEIGHBOURS WITH IT, and it has to. fleet.yaml
 * does not refuse two peers naming the same loopback port (parseFleetYaml
 * checks duplicate LABELS and nothing else, fleet-registry.ts:342-353), so
 * two peers can both read on 127.0.0.1:7902 while fleet-links.json binds
 * 7901 and 7902 to two different labels. The per-row check passes for the row
 * that owns 7902, and binding it would serve that node's data to every poll
 * aimed at the other one: #282's wrong-binding outcome, arrived at from the
 * other side. So a serving row whose port is ALSO named by a different
 * fleet.yaml peer is held too, and nothing binds that port at all. An
 * unreachable peer is a fact on the page; a peer reading another node's
 * ledger under its own label is the bug this project keeps paying for.
 */
export interface LinkPeerOrigin {
  label: string;
  read_origin: string;
  advisor_origin?: string;
  transport?: string;
}

/**
 * What a node is told when its row is withheld, and nothing else (#687
 * review).
 *
 * The aggregator's own sentence names the file, the errno, the absolute path
 * it tried, and the other rows a port collides with. All of that is the
 * aggregator's business, and the node is the one machine on the fleet that
 * must not be handed a map of it: a node is a smaller blast radius than the
 * aggregator, and a compromised one reading "EACCES on
 * /home/<operator>/aperire-one/dashboard/config/fleet-links.json" or
 * "fleet.yaml also reads \"validator1\" on that port" has learned the
 * aggregator's layout for free. So the wire gets one of two fixed sentences
 * and the journal keeps the detail.
 */
export const HOLD_WIRE_UNREADABLE =
  'the aggregator cannot read its link registry right now';
export const HOLD_WIRE_CONFLICT =
  'this row conflicts with another row on the aggregator; the operator has to fix fleet.yaml '
  + 'or fleet-links.json there';

/** A row that will not be served, why (the aggregator's journal), and the
 *  fixed sentence the node is told (`wire`). */
export interface WithheldLinkRow {
  row: LinkRegistryRow;
  reason: string;
  wire: string;
}

export interface LinkRowSplit {
  /** Rows this aggregator may bind and serve. */
  serving: LinkRegistryRow[];
  /** Rows whose credential is still good and whose binding is not. */
  withheld: WithheldLinkRow[];
}

function originPort(origin: string | undefined): number | null {
  if (!origin) return null;
  try {
    const u = new URL(origin);
    // A bare origin with no explicit port is the protocol's default, which
    // fleet-registry.ts's loopback rule already refuses for anything real.
    return u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
  } catch { return null; }
}

/** Why this one row disagrees with fleet.yaml, or null. */
export function checkLinkRow(
  row: LinkRegistryRow,
  peers: readonly LinkPeerOrigin[],
): string | null {
  const peer = peers.find((p) => p.label === row.label);
  if (!peer) {
    return `fleet-links.json has a link for "${row.label}", and fleet.yaml has no peer by that name`;
  }
  if (peer.transport !== 'link') {
    return `fleet-links.json has a link for "${row.label}", and its fleet.yaml row does not say `
      + 'transport: link, so the fleet would still read that node as a tunnel';
  }
  const readPort = originPort(peer.read_origin);
  if (readPort !== row.read_port) {
    return `link "${row.label}" binds read_port ${row.read_port} and fleet.yaml reads it on `
      + `${peer.read_origin}: one of the two files has the wrong port`;
  }
  const advisorPort = originPort(peer.advisor_origin);
  if ((row.advisor_port ?? null) !== advisorPort) {
    return `link "${row.label}" ${row.advisor_port ? `binds advisor_port ${row.advisor_port}` : 'binds no advisor port'}`
      + ` and fleet.yaml ${peer.advisor_origin ? `reads its Advisor on ${peer.advisor_origin}` : 'gives it no advisor_origin'}`
      + ': one of the two files has to change';
  }
  return null;
}

/**
 * The root broker's pre-write gate: would the pair it is about to place leave
 * ANY row inconsistent?
 *
 * Imported by name from `scripts/aperire-fleet-broker.sh`, which runs it as
 * the dashboard account against the two candidate files before either is
 * renamed into place, and refuses `cross_check` on a non-null answer. Deleting
 * it in #687's first pass turned every broker write into
 * `candidate_refused`: approve, revoke, attach, detach, convert, all of them,
 * with nothing written. Keep the export and the shape.
 *
 * Whole-file here on purpose, and it is the opposite of #687 rather than a
 * leftover of it. A reload is asked "what may serve right now", and one bad
 * row must not answer for the others. A WRITE is asked "is this pair worth
 * placing", and a write that would hold one of its own rows is a write to fix
 * before it lands, not after.
 */
export function crossCheckLinkRows(
  rows: readonly LinkRegistryRow[],
  peers: readonly LinkPeerOrigin[],
): string | null {
  return splitLinkRows(rows, peers).withheld[0]?.reason ?? null;
}

/** Split fleet-links.json into what may serve and what is withheld, per row. */
export function splitLinkRows(
  rows: readonly LinkRegistryRow[],
  peers: readonly LinkPeerOrigin[],
): LinkRowSplit {
  const serving: LinkRegistryRow[] = [];
  const withheld: WithheldLinkRow[] = [];
  for (const row of rows) {
    const reason = checkLinkRow(row, peers);
    if (reason) withheld.push({ row, reason, wire: HOLD_WIRE_CONFLICT });
    else serving.push(row);
  }

  // The cross-peer pass. Every port any fleet.yaml peer names, whatever its
  // transport: a tunnel row on 7901 is still something this fleet polls on
  // 7901, and binding a link listener there would answer it.
  const claims = new Map<number, Set<string>>();
  for (const peer of peers) {
    for (const port of [originPort(peer.read_origin), originPort(peer.advisor_origin)]) {
      if (port === null) continue;
      const labels = claims.get(port) ?? new Set<string>();
      labels.add(peer.label);
      claims.set(port, labels);
    }
  }
  const collided: WithheldLinkRow[] = [];
  const kept: LinkRegistryRow[] = [];
  for (const row of serving) {
    const ports = [row.read_port, ...(row.advisor_port ? [row.advisor_port] : [])];
    const clash = ports
      .map((port) => ({ port, labels: [...(claims.get(port) ?? [])].filter((l) => l !== row.label) }))
      .find((c) => c.labels.length > 0);
    if (clash) {
      collided.push({
        row,
        wire: HOLD_WIRE_CONFLICT,
        reason: `link "${row.label}" binds port ${clash.port} and fleet.yaml also reads `
          + `${clash.labels.map((l) => `"${l}"`).join(', ')} on that port: no node may bind a port `
          + 'two rows claim, or one node would answer for another',
      });
    } else {
      kept.push(row);
    }
  }
  return { serving: kept, withheld: [...withheld, ...collided] };
}

/**
 * What a reload of fleet-links.json decides, as a value (#687).
 *
 * server.ts reads two files and owns the logging; every JUDGEMENT it used to
 * make inline lives here instead, because each of the degraded branches was
 * its own way to take the fleet down and none of them could be tested where
 * they were.
 *
 * The rule that shapes all of it: a registry this aggregator cannot read
 * right now is not a registry that says anything. So a missing, unreadable or
 * unparseable file WITHHOLDS the last-good rows (a new dial is answered
 * `registry_held`, which the node retries) and leaves the live links alone.
 * Tearing a live link down because a file went missing for a moment is the
 * #687 outage with a different first step, and the node's own agent has held
 * this line for longer: `decideLinkReconcile` keeps a live link on an
 * unreadable config and only warns.
 *
 * A file that PARSES is the opposite case: it is this aggregator's own word
 * on who may link, so its verdict is applied to the live links too.
 */
export type LinkRegistryFile =
  | { kind: 'absent' }
  | { kind: 'unreadable'; detail: string }
  | { kind: 'text'; text: string };

export interface LinkReloadInput {
  file: LinkRegistryFile;
  /** fleet.yaml's peers, as loadFleetConfig() left them. Empty means either a
   *  single-node install or a fleet.yaml that failed to load, and the two are
   *  told apart by whether there are link rows to check at all. */
  peers: readonly LinkPeerOrigin[];
  previous: { serving: readonly LinkRegistryRow[]; withheld: readonly WithheldLinkRow[] };
}

export interface LinkReloadPlan {
  serving: LinkRegistryRow[];
  withheld: WithheldLinkRow[];
  /** Re-judge the LIVE links against this plan. False only when the registry
   *  could not be read, where the plan is a guess and a live link is a fact. */
  reconcile: boolean;
  /**
   * Live links to judge even when `reconcile` is false (#687 review, F1).
   *
   * A registry this aggregator cannot read leaves every live link alone, and
   * that is right for the registry. It is NOT right for fleet.yaml: the same
   * SIGHUP may have re-pointed a peer's `read_origin` at a port another
   * node's listener already holds, and that listener keeps answering, so the
   * poll for the re-pointed peer reaches the wrong node and hands it that
   * peer's bearer token. Any live link whose row no longer agrees with the
   * fleet.yaml in front of us is dropped, by label, and nothing else is.
   */
  dropLive: string[];
  /**
   * Can this aggregator say that a credential is UNKNOWN?
   *
   * Only when the registry parsed. Absent, unreadable and unparseable all
   * mean it holds no opinion, and a 401 in that state is a lie the node
   * treats as final (`refusalForStatus`). #688's second door: an aggregator
   * restarted while the file was missing, with a pairing code armed, built a
   * hub with no rows and answered every node a final 401.
   */
  judgeable: boolean;
  /** Lines for the journal, in the order they should be written. */
  warnings: string[];
}

export function planLinkReload(input: LinkReloadInput): LinkReloadPlan {
  const lastGood = (): LinkRegistryRow[] => [
    ...input.previous.serving,
    ...input.previous.withheld.map((w) => w.row),
  ];
  const keepHolding = (reason: string, warning: string): LinkReloadPlan => {
    const rows = lastGood();
    // F1: the registry says nothing, and fleet.yaml still speaks. A live link
    // whose row disagrees with the peers we just loaded is dropped by name;
    // every other live link is left exactly as it is. Skipped when fleet.yaml
    // loaded no peers, because then neither file is saying anything and
    // dropping every link on that would be #687 again.
    const dropLive = input.peers.length
      ? splitLinkRows(rows, input.peers).withheld.map((w) => w.row.label)
      : [];
    const warnings = [warning];
    for (const label of dropLive) {
      warnings.push(`[fleet-link] "${label}" is dropped as well: fleet.yaml no longer agrees with the `
        + 'row this link came up on, and a listener on a port fleet.yaml now gives another peer would '
        + "answer that peer's polls");
    }
    return {
      serving: [],
      withheld: rows.map((row) => ({ row, reason, wire: HOLD_WIRE_UNREADABLE })),
      reconcile: false,
      dropLive,
      judgeable: false,
      warnings,
    };
  };

  if (input.file.kind === 'absent') {
    // Nothing ever placed it: the documented single-node state, and there is
    // nothing to hold. Something took it away: held, never revoked. No
    // shipped writer deletes this file (the broker's own revoke leaves
    // `{"links": []}` behind for the last row), so its absence after it was
    // there is an accident, not an instruction.
    // Nothing in memory either: from this process's side an absent file and
    // a file that was taken away look identical after a restart, so it still
    // holds no opinion about a credential (judgeable: false).
    if (!lastGood().length) {
      return { serving: [], withheld: [], reconcile: false, dropLive: [], judgeable: false, warnings: [] };
    }
    return keepHolding(
      'this aggregator cannot find its own fleet-links.json right now',
      '[fleet-link] fleet-links.json is gone, and it was there. Every node is held, not revoked, '
      + 'and links already up are left alone',
    );
  }

  if (input.file.kind === 'unreadable') {
    return keepHolding(
      `this aggregator cannot read its own fleet-links.json right now (${input.file.detail})`,
      `[fleet-link] fleet-links.json could not be read: ${input.file.detail}. Every node is held, `
      + 'not revoked, and links already up are left alone',
    );
  }

  const parsed = parseLinkRegistry(input.file.text);
  if (parsed.error) {
    // Fail closed and say so once, the fleet.yaml rule: a file that binds
    // some nodes and swallows the rest is worse than one that binds none.
    // Held rather than emptied, because a half-typed file is a state an
    // operator is one keystroke from leaving.
    return keepHolding(
      `fleet-links.json does not parse: ${parsed.error}`,
      `[fleet-link] ${parsed.error}, so no new node may link`,
    );
  }

  // "fleet.yaml did not load" and "that label is not in fleet.yaml" are two
  // different problems with one symptom: loadFleetConfig() leaves the peer
  // list EMPTY on a parse or resolve failure, and the cross-check would then
  // blame fleet-links.json for a row that is perfectly good. Named apart, so
  // the operator opens the file that is actually wrong.
  if (parsed.links.length && input.peers.length === 0) {
    const reason = 'fleet.yaml loaded no peers (see the [fleet] line above), so no link row can be '
      + 'checked against it';
    return {
      serving: [],
      withheld: parsed.links.map((row) => ({ row, reason, wire: HOLD_WIRE_CONFLICT })),
      // This file parsed. It is fleet.yaml that is missing, and the pair of
      // them is what says a row may be served, so the live links are judged.
      reconcile: true,
      dropLive: [],
      // This file parsed, so an unknown credential is genuinely unknown.
      judgeable: true,
      warnings: [`[fleet-link] ${reason}`],
    };
  }

  const split = splitLinkRows(parsed.links, input.peers);
  return {
    serving: split.serving,
    withheld: split.withheld,
    reconcile: true,
    dropLive: [],
    judgeable: true,
    warnings: split.withheld.map(
      (w) => `[fleet-link] "${w.row.label}" is held and will not link: ${w.reason}`,
    ),
  };
}

// ── Who the rate limit is talking to ─────────────────────────────────────

/**
 * The key the handshake guard counts failures under (#279).
 *
 * `req.socket.remoteAddress` is the honest answer on a directly-dialled
 * dashboard and the WRONG one on a real aggregator: it terminates TLS in a
 * proxy on the same box and binds loopback, so that address is the proxy's
 * for every caller, every node in the fleet and every stranger on the
 * internet in one bucket.
 *
 * So the header is read, and ONLY from a peer that cannot be a stranger:
 *
 *   - peer is loopback  → this is the local TLS proxy, and the first hop of
 *     `x-forwarded-for` is the caller it is speaking for. No proxy, no
 *     header, and the key falls back to a named shared bucket.
 *   - peer is anything else → the header is a caller choosing its own
 *     bucket, which is the whole reason a rate limit keyed on a forgeable
 *     value is not a rate limit. Ignored, and the socket address is used.
 *
 * `auth.ts`'s clientIp() trusts the header from ANY peer; do not reuse it
 * here, and do not "unify" the two later without moving that one first.
 *
 * IPv6 collapses to its /64. An attacker is handed a /64 by their provider,
 * so a per-address bucket on IPv6 is 18 quintillion buckets and no limit at
 * all.
 */
export function linkRateKey(
  remoteAddress: string | undefined | null,
  forwardedFor: string | string[] | undefined,
): string {
  const peer = String(remoteAddress ?? '').trim();
  if (isLoopbackHost(peer)) {
    const raw = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    const first = typeof raw === 'string' ? raw.split(',')[0].trim() : '';
    // A proxy that forwards nothing leaves one shared bucket, and that is
    // now survivable: a valid credential is never refused by this bucket
    // (see gateLinkUpgrade), so the worst it can do is turn one stranger's
    // 401 into another stranger's 429.
    if (!first) return 'proxy:no-forwarded-for';
    return `fwd:${normaliseRateKey(first)}`;
  }
  return `peer:${normaliseRateKey(peer || 'unknown')}`;
}

/** Lower-cased, de-bracketed, de-zoned, IPv4-mapped unwrapped, and IPv6
 *  collapsed to its /64. Bounded, because it becomes a map key. */
export function normaliseRateKey(raw: string): string {
  let a = raw.trim().toLowerCase().slice(0, 64);
  if (a.startsWith('[')) a = a.slice(1);
  if (a.endsWith(']')) a = a.slice(0, -1);
  const zone = a.indexOf('%');
  if (zone !== -1) a = a.slice(0, zone);
  if (a.startsWith('::ffff:') && a.includes('.')) a = a.slice('::ffff:'.length);
  if (!a.includes(':')) return a;
  const prefix = ipv6Prefix64(a);
  return prefix ?? a;
}

/** The first four hextets of an IPv6 address, `::` expanded, or null when it
 *  is not an address this can read (which keys on the raw string instead:
 *  a key that is wrong is still a key, and a throw here would be a gate). */
function ipv6Prefix64(addr: string): string | null {
  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  let parts: string[];
  if (halves.length === 1) {
    parts = head;
  } else {
    const tail = halves[1] ? halves[1].split(':') : [];
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    parts = [...head, ...Array<string>(fill).fill('0'), ...tail];
  }
  if (parts.length !== 8) return null;
  const four: string[] = [];
  for (const part of parts.slice(0, 4)) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    four.push(parseInt(part, 16).toString(16));
  }
  return `${four.join(':')}::/64`;
}

// ── The handshake guard ──────────────────────────────────────────────────

export interface HandshakeGuardOpts {
  now?: () => number;
  /** Failed handshakes remembered per address, and for how long. */
  windowMs?: number;
  maxFailuresPerWindow?: number;
  /** Sockets upgraded but not yet through the handshake, across all
   *  addresses. An endpoint on the public internet must not let a stranger
   *  hold an unbounded number of half-open links. */
  maxPending?: number;
  /** Established links. One per registered node is the real ceiling; this is
   *  the belt. */
  maxLinks?: number;
  /** How many addresses are remembered at once. The map is memory a stranger
   *  can grow one IP at a time, so it is bounded and evicted oldest-first. */
  maxAddresses?: number;
}

export interface HandshakeGuard {
  /** The two GLOBAL caps, which no stranger can flip: `pending` counts only
   *  sockets that already presented a valid credential, and `links` counts
   *  established ones. Checked before the credential, because they are about
   *  what this process is already carrying and not about who is calling. */
  caps: (pending: number, links: number) => { ok: true } | { ok: false; code: LinkRefusalCode; detail: string };
  /** Has this key already failed too often in the window? Checked AFTER the
   *  credential (#279), so it can never refuse a caller who turns out to
   *  hold a valid one. */
  overLimit: (key: string) => boolean;
  /** Record a refused handshake under this key. */
  fail: (key: string) => void;
  /** Record a completed one, which clears the key. */
  succeed: (key: string) => void;
}

export function createHandshakeGuard(opts: HandshakeGuardOpts = {}): HandshakeGuard {
  const now = opts.now ?? (() => Date.now());
  const windowMs = opts.windowMs ?? 60_000;
  const maxFailures = opts.maxFailuresPerWindow ?? 10;
  const maxPending = opts.maxPending ?? 8;
  const maxLinks = opts.maxLinks ?? 64;
  const maxAddresses = opts.maxAddresses ?? 1024;
  const failures = new Map<string, { count: number; firstMs: number }>();

  return {
    caps(pending, links) {
      if (links >= maxLinks) {
        return { ok: false, code: 'too_many_links', detail: 'this aggregator is holding as many links as it takes' };
      }
      if (pending >= maxPending) {
        return { ok: false, code: 'rate_limited', detail: 'this aggregator is already mid-handshake with as many callers as it takes' };
      }
      return { ok: true };
    },
    overLimit(key) {
      const rec = failures.get(key);
      return Boolean(rec && now() - rec.firstMs < windowMs && rec.count >= maxFailures);
    },
    fail(address) {
      const at = now();
      const rec = failures.get(address);
      if (!rec || at - rec.firstMs >= windowMs) {
        if (failures.size >= maxAddresses) {
          let oldest: string | null = null;
          let oldestAt = Infinity;
          for (const [k, v] of failures) if (v.firstMs < oldestAt) { oldestAt = v.firstMs; oldest = k; }
          if (oldest !== null) failures.delete(oldest);
        }
        failures.set(address, { count: 1, firstMs: at });
        return;
      }
      rec.count += 1;
    },
    succeed(address) { failures.delete(address); },
  };
}

// ── The credential check ─────────────────────────────────────────────────

export function credentialHash(credential: string): string {
  return createHash('sha256').update(credential, 'utf8').digest('hex');
}

/**
 * Which row does this credential belong to, if any.
 *
 * Constant-time in two senses. Each comparison is timingSafeEqual over the
 * 32 raw bytes (the same shape lib/fleet-write-api.ts's tokenMatches uses; it
 * is not exported, so this is a deliberate second copy rather than a shared
 * one, and both are one line). And the loop does not break on a hit, so the
 * time it takes does not say how far down the file a matching label sits.
 *
 * Returns null for an unknown credential and says nothing else. ADR 0019's
 * consequences: "refuse an unknown credential without saying which part was
 * wrong."
 */
export function resolveCredential(rows: readonly LinkRegistryRow[], presented: string): LinkRegistryRow | null {
  const digest = createHash('sha256').update(presented, 'utf8').digest();
  let hit: LinkRegistryRow | null = null;
  for (const row of rows) {
    let expected: Buffer;
    try { expected = Buffer.from(row.credential_sha256, 'hex'); } catch { continue; }
    if (expected.length !== digest.length) continue;
    if (timingSafeEqual(expected, digest)) hit = row;
  }
  return hit;
}

// ── The upgrade gate ─────────────────────────────────────────────────────

export interface LinkUpgradeInput {
  pathname: string;
  bindHost: string;
  remoteAddress: string | undefined;
  authorization: string | undefined;
  allowPlaintext: boolean;
  rows: readonly LinkRegistryRow[];
  /** #687: the rows this aggregator holds but will not serve. Consulted only
   *  when `rows` did not resolve the credential, so a held credential is
   *  answered with the truth instead of the 401 a stranger gets. */
  withheldRows?: readonly WithheldLinkRow[];
  /** #688's second door: can this aggregator say a credential is UNKNOWN?
   *  False while its registry is absent, unreadable or unparseable, where a
   *  401 would be a final refusal built on no reading at all. Defaults to
   *  true, so a caller that does not pass it behaves exactly as before. */
  registryJudgeable?: boolean;
  pending: number;
  links: number;
  guard: HandshakeGuard;
  /** What the rate limit counts this caller under, from linkRateKey(). Not
   *  derived here: the header it may read is only trustworthy from a loopback
   *  peer, and that judgement belongs in one place. */
  rateKey: string;
  /** Did the caller send `X-Aperire-Pairing: 1`? A pairing session carries no
   *  credential, so the discriminator has to be an explicit header rather
   *  than the ABSENCE of one: a dialer sending neither is a scanner, and a
   *  scanner must get the 401 it gets today rather than a pairing slot. */
  pairing: boolean;
  /** Pairing sockets and Pending rows this hub is already carrying. Its own
   *  count, never folded into `pending`: that counter's property is "only a
   *  credentialled socket holds a slot". */
  pairings: number;
  /** The pairing guard, separate from `guard` on purpose: a stranger
   *  spraying pairing garbage must not fill the bucket that refuses link
   *  handshakes. Consulted in the pairing arm BEFORE a slot is granted,
   *  which is the one place a caller with no code can be refused at all
   *  (P2-054). */
  pairGuard: HandshakeGuard;
  /** Pre-hello pairing sockets and Pending rows THIS rate key is already
   *  holding. The four-slot cap bounds the aggregator; this bounds one
   *  caller, so no single address can deny the rest. */
  pairingsFromKey: number;
}

export type LinkUpgradeDecision =
  | { ok: true; kind: 'link'; row: LinkRegistryRow }
  /** #687: a credential this aggregator knows, on a row it will not serve.
   *  The upgrade completes so the node can be told which two files disagree
   *  in words; nothing is bound and no Live is created. */
  | { ok: true; kind: 'held'; row: LinkRegistryRow; reason: string; wire: string }
  | { ok: true; kind: 'pair' }
  | { ok: false; status: number; code: LinkRefusalCode; message: string; countAsFailure: boolean };

/**
 * Everything decided BEFORE the WebSocket state machine sees anything, in the
 * order /ingest already uses in server.ts's upgrade handler.
 *
 * The transport policy runs FIRST here, which is the reverse of /ingest's
 * order and deliberate. There, the token is on the wire in the upgrade request
 * either way, so gating transport first would protect no secret. Here it is
 * the same fact and the opposite conclusion: this endpoint is on the public
 * internet by design, so refusing a plaintext dial before the credential is
 * ever compared is the cheaper refusal for a scanner and the honest one for a
 * misconfigured node.
 *
 * An honest note on what decideIngest can and cannot prove, because the
 * security review below turns on it: the dashboard speaks node:http, and the
 * aggregator binds loopback with TLS terminated by a proxy in front. So
 * decideIngest returns `loopback-bind` for an internet request just as it does
 * for a local one, and it CANNOT tell this hub whether the hop that carried
 * the credential was encrypted. It is reused because it is the right refusal
 * for the one arrangement it can see (a dashboard bound to a LAN address,
 * dialled directly in the clear), and the load-bearing plaintext refusal for
 * this link lives on the NODE, in parseLinkConfig, which is the only side
 * holding the URL that says whether the hop was wss://.
 */
export function gateLinkUpgrade(input: LinkUpgradeInput): LinkUpgradeDecision {
  const address = input.remoteAddress ?? 'unknown';

  if (input.pathname !== FLEET_LINK_PATH) {
    return { ok: false, status: 404, code: 'unauthenticated', message: 'no such endpoint', countAsFailure: false };
  }

  const verdict = decideIngest({
    bindHost: input.bindHost,
    remoteAddress: input.remoteAddress,
    allowPlaintext: input.allowPlaintext,
  });
  if (!verdict.allow) {
    return {
      ok: false, status: 403, code: 'unauthenticated',
      message: `[security] REFUSED ${FLEET_LINK_PATH} from ${address}: ${verdict.message}`,
      countAsFailure: true,
    };
  }

  // A request carrying BOTH a credential and the pairing header is
  // ambiguous, and an ambiguous request is refused rather than resolved by
  // whichever branch happens to be first in the file. Nothing legitimate
  // sends both: the pair command sends no Authorization header at all.
  if (input.pairing && (input.authorization ?? '').trim()) {
    return {
      ok: false, status: 401, code: 'unauthenticated',
      message: `[fleet-link] refused a link from ${address}: unknown credential`,
      countAsFailure: true,
    };
  }

  // A pairing session, which is decided here and goes no further through
  // the link path: it has no credential to resolve, so `resolveCredential`
  // below would refuse it, and it must not touch the link caps or the link
  // rate bucket. Its own cap is the only thing standing in front of it, and
  // its own guard is consulted at the HELLO, after the code resolves, which
  // is #279's ordering applied to the new surface.
  if (input.pairing) {
    // #279's ordering does not apply here and it is worth saying why. That
    // ruling is "a valid credential is never refused by a bucket somebody
    // else filled", and it works because the credential resolves first. A
    // pairing caller presents nothing at the upgrade, so there is no such
    // thing as a caller this bucket might be wronging: the bucket is the
    // only thing there is, and a code that arrives later is checked against
    // its own bucket with the same ordering as before.
    if (input.pairGuard.overLimit(input.rateKey)) {
      return {
        ok: false, status: 429, code: 'rate_limited',
        message: `[fleet-link] refused a pairing from ${address}: too many refused pairings from there`,
        countAsFailure: false,
      };
    }
    // Before the global cap, deliberately. Checked the other way round, a
    // caller holding its two would be refused by the four-slot message,
    // which names the aggregator's condition instead of the caller's.
    if (input.pairingsFromKey >= FLEET_PAIR_MAX_PER_KEY) {
      return {
        ok: false, status: 429, code: 'rate_limited',
        message: `[fleet-link] refused a pairing from ${address}: that caller is already holding `
          + `${input.pairingsFromKey} of this aggregator's pairing slots`,
        countAsFailure: false,
      };
    }
    if (input.pairings >= FLEET_LINK_MAX_PAIRINGS) {
      return {
        ok: false, status: 429, code: 'rate_limited',
        message: `[fleet-link] refused a pairing from ${address}: this aggregator is already holding as many pairings as it takes`,
        countAsFailure: false,
      };
    }
    return { ok: true, kind: 'pair' };
  }

  // The two GLOBAL caps. Neither can be flipped by a stranger: `pending`
  // counts only sockets that already presented a valid credential, and
  // `links` counts established ones.
  const caps = input.guard.caps(input.pending, input.links);
  if (!caps.ok) {
    return {
      ok: false, status: 429, code: caps.code,
      message: `[fleet-link] refused a link from ${address}: ${caps.detail}`,
      countAsFailure: false,
    };
  }

  // The credential, BEFORE the per-caller rate limit, and that order is
  // the fix for #279 rather than an optimisation.
  //
  // With the limit first, ten refused handshakes a minute from anyone at all
  // refused every legitimate node too, and guard.succeed() could never clear
  // the bucket because no node got far enough to succeed. On an aggregator
  // that is one shared bucket for the whole internet AND the whole fleet, so
  // the control became the denial: an unauthenticated stranger, needing no
  // credential, held the fleet's entire transport down for as long as they
  // cared to. It compounded with a node whose credential was revoked, which
  // dialled forever and spent the same bucket with no attacker at all.
  //
  // Checking the credential first costs one SHA-256 per registered row for a
  // stranger, against a TCP accept and an HTTP header parse they have
  // already made this process do. What it buys is that a valid credential is
  // never refused by a bucket somebody else filled.
  const presented = (input.authorization ?? '').replace(/^Bearer\s+/i, '').trim();
  const row = presented ? resolveCredential(input.rows, presented) : null;
  if (row) return { ok: true, kind: 'link', row };

  // #687: the same credential check over the held rows, before the 401. A
  // node whose row is held is not a stranger and must not be answered like
  // one: 401 is fatal on the node (refusalForStatus), so the fleet-wide
  // fail-closed used to stop every node dialling until somebody restarted
  // each dashboard by hand. This path is reached only when `rows` did not
  // match, so a serving node never pays for it, and a stranger still learns
  // nothing: the refusal it gets is the same 401 as before.
  const withheldRows = input.withheldRows ?? [];
  const withheldHit = presented && withheldRows.length
    ? resolveCredential(withheldRows.map((h) => h.row), presented)
    : null;
  if (withheldHit) {
    const hit = withheldRows.find((h) => h.row.label === withheldHit.label);
    return {
      ok: true, kind: 'held', row: withheldHit,
      // What the node hears: fixed, and never the aggregator's own paths,
      // errnos or other rows' labels (#687 review, F3).
      wire: hit?.wire ?? HOLD_WIRE_CONFLICT,
      // What the journal hears, on the aggregator, where it belongs.
      reason: hit?.reason ?? 'this aggregator is holding that row until its two registry files agree',
    };
  }

  // This aggregator cannot say the credential is unknown, because it has not
  // read a registry (#688's second door). One aggregator restart while
  // fleet-links.json was missing, with a pairing code armed to build the hub,
  // answered every node on the fleet a 401, and 401 is final: they all needed
  // a restart of their own. So the answer is a 503, which is transient on the
  // node, and it is the SAME answer for every caller: a stranger learns that
  // this endpoint is not serving links right now, which is true, and nothing
  // about any credential. No socket is upgraded and no bucket is spent.
  if (input.registryJudgeable === false) {
    return {
      ok: false, status: 503, code: 'registry_held',
      message: `[fleet-link] a link dial from ${address} met a registry this aggregator cannot read, `
        + 'so it was held rather than refused',
      countAsFailure: false,
    };
  }

  // Unknown. One sentence for every way this fails: no header, a header that
  // is not a credential, a credential that was revoked, a credential for a
  // node that is not in this file. A caller learns that it is not linked, and
  // nothing about why, which is the whole of the refusal's job.
  //
  // The rate limit now decides only which refusal a repeat caller gets, and
  // it is still worth having: it names the abuse in the journal, and it stops
  // this endpoint answering a scanner at line rate.
  if (input.guard.overLimit(input.rateKey)) {
    return {
      ok: false, status: 429, code: 'rate_limited',
      message: `[fleet-link] refused a link from ${address} (${input.rateKey}): too many refused handshakes`,
      countAsFailure: true,
    };
  }
  return {
    ok: false, status: 401, code: 'unauthenticated',
    message: `[fleet-link] refused a link from ${address}: unknown credential`,
    countAsFailure: true,
  };
}

// ── The running hub ──────────────────────────────────────────────────────

export interface LinkHubSocket {
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
  on: (event: 'message' | 'close' | 'error' | 'pong', handler: (arg?: unknown) => void) => void;
  /** A protocol-level ping, for a pairing session that has to stay open
   *  across a human decision. Optional because only that one path sends
   *  one, and a caller's stand-in socket should not have to implement a
   *  method it never receives. `ws` provides it, and answers a peer's ping
   *  with a pong; the 'pong' event above is how this hub hears the node's
   *  answer to ITS ping. */
  ping?: () => void;
}

export interface LinkHubDeps {
  /** The parsed fleet-links.json, re-read by the caller on SIGHUP. Rows this
   *  aggregator may actually serve, never a held one. */
  rows: () => readonly LinkRegistryRow[];
  /** #687: rows whose credential this aggregator still holds and whose
   *  binding it will not serve until the two registry files agree. A node
   *  presenting one of these is refused `registry_held` and told which two
   *  files disagree, rather than `revoked` (final) or 401 (also final).
   *  Optional: a caller that never holds anything passes nothing. */
  withheldRows?: () => readonly WithheldLinkRow[];
  /** #688: false while this host's registry is absent, unreadable or
   *  unparseable. A dial it cannot judge is held (503), never refused 401,
   *  which is final on the node. */
  registryJudgeable?: () => boolean;
  /** Sign the challenge with this host's fleet trust seed. Null when this
   *  host holds no signing key, which refuses every link: an aggregator that
   *  cannot prove who it is has nothing to offer a node that pinned it. */
  sign: (message: string) => string | null;
  bindHost: string;
  allowPlaintext: boolean;
  /** Completes the WebSocket upgrade. server.ts passes ws's handleUpgrade. */
  upgrade: (req: IncomingMessage, socket: Duplex, head: Buffer, done: (ws: LinkHubSocket) => void) => void;
  /** Completes the upgrade for a PAIRING session, from a listener with a
   *  small maxPayload. Separate from `upgrade` because the link's cap is
   *  10 MiB for a knowledge bundle and a pairing caller is
   *  unauthenticated (P2-054). Falls back to `upgrade` when absent, so a
   *  test rig with one fake listener still works. */
  upgradePairing?: (req: IncomingMessage, socket: Duplex, head: Buffer, done: (ws: LinkHubSocket) => void) => void;
  /** Injected so the e2e test can watch a bind. Defaults to node:http. */
  makeServer?: () => Server;
  guard?: HandshakeGuard;
  /** How often a waiting pairing socket is pinged. Injected so a test can
   *  watch the pings without waiting 25 seconds for one. */
  pairKeepaliveMs?: number;
  /** A SECOND guard, for pairing presentations. Separate on purpose: a
   *  stranger spraying garbage codes must not be able to fill the bucket
   *  that refuses link handshakes, and a node whose credential was revoked
   *  must not be able to fill the one that refuses pairings. */
  pairGuard?: HandshakeGuard;
  /** Resolve and CLAIM a pairing code, or say why not. Injected rather than
   *  imported, so this module holds no database handle and the e2e can drive
   *  the exchange with no SQLite at all. Absent means this host takes no
   *  pairings, which is how it behaved before phase 3. */
  consumeCode?: (raw: string, rateKey: string) => PairCodeVerdict;
  /** This aggregator's own fleet trust PUBLIC key, base64url. Carried in the
   *  welcome because a new node has no prior anchor for it. Null on a host
   *  that holds no fleet trust key, which refuses every pairing: an
   *  aggregator that cannot prove who it is has nothing to offer. */
  fleetTrustPubKey?: () => string | null;
  /**
   * Pairing v2: this aggregator's fleet ARM public key, plain base64, as
   * root's broker last reported it, or null when nothing has asked yet.
   *
   * A CACHE, held by the caller for the whole process, and written by the
   * mint's preflight and by every approval's fresh `arm-key` answer. Read
   * here because a `pair_hello` handler must stay synchronous and must never
   * make a code holder's dial reach root: the broker is asked by an
   * administrator's mint, never by a node. A miss (the dashboard restarted
   * between the mint and the dial) sends no `pair_keys`, and the row falls
   * back to the check after approval. The arm key is one value for the
   * whole fleet, so it is not stored per code.
   */
  cachedArmPubKey?: () => string | null;
  /** Every row THIS fleet's own fleet.yaml holds, self excluded. #620.
   *  Read fresh through the closure, the same reload idiom as `rows`, so a
   *  SIGHUP takes effect on the very next `pair_hello`. Absent reads as no
   *  rows, which is the ordinary single-node install: every presented key
   *  is new. */
  fleetNodes?: () => readonly FleetNodeConfig[];
  /** #626: read one tunnel row's token_path, trimmed, or null when it cannot
   *  be read. The token a known node's move proof is checked against: the
   *  copy this aggregator already reads that node with. Injected so a test
   *  can hold the token in memory; server.ts passes readTokenFresh. Absent
   *  reads every token as unreadable, so no known-node move is offered. The
   *  value is never logged, stored on a row or sent anywhere. */
  readTokenFile?: (path: string) => string | null;
  /** #626 review, L2: what this aggregator's own tunnel read of a row shows
   *  right now (fleet-health's tunnelAuthOf). Picks the sentence a refused
   *  move proof gets, so reinstall advice is only given where the tunnel
   *  itself says the token changed. Absent reads as unknown. */
  tunnelAuth?: (label: string) => TunnelAuth;
  log?: (line: string) => void;
  now?: () => number;
}

/** What `deps.consumeCode` answers. `why` is for the journal and never for
 *  the wire: bad, reused and expired are three facts about a code and one
 *  fact about the caller. */
export type PairCodeVerdict =
  /** The code resolved and is now spent. `expires_at_ms` is the CODE's own
   *  expiry, which is what the Pending row expires with. `name` (#635) is
   *  the name an admin typed into "Name this node" before minting it, or
   *  null/absent when none was given -- optional so the many existing
   *  stubs of this shape (in tests) go on compiling unchanged. */
  | { ok: true; expires_at_ms: number; name?: string | null }
  | { ok: false; why: string };

/**
 * How far along one pairing is. The page shows the phrase beside it, so
 * every value here has to be a truthful thing to say about a row an operator
 * is looking at.
 */
export type PairingStage = 'waiting' | 'approved' | 'settling' | 'done' | 'refused';

/**
 * How a `done` row finished, as a value the page can branch on (#632).
 * `done` only says the broker wrote the node's row. Whether the NODE then
 * finished is a separate fact, and it used to live only in the note's
 * wording, which the follow-on's annotate() replaces a minute later. The
 * page painted a green "registered" and "Paired as" for all of them.
 *
 *   waiting        the signed answer went out, and the node has not yet said
 *                  whether it wrote its credential
 *   ok             the node said it wrote its credential
 *   no_credential  the node said it could not write its credential
 *   link_closed    the answer never reached the node: its link closed first
 *   unconfirmed    the node's link closed after the answer went out, before
 *                  it said whether it wrote its credential
 *
 * Null on every row that is not `done`. `ok` is still the node's word, not
 * an observation: the follow-on's own wait for the link is what observes.
 */
export type PairingSettled = 'waiting' | 'ok' | 'no_credential' | 'link_closed' | 'unconfirmed';

/**
 * Pairing v2: where the node's fingerprint check stands for one row. The
 * page renders the row by this (lane D), so each value is a truthful thing
 * to say to the operator deciding whether to approve.
 *
 *   waiting_at_node  `pair_keys` went out; the node has not answered. No
 *                    Approve: approve() refuses `not_checked`.
 *   matched          the node said its operator's paste matches these keys.
 *                    A signal from the node, never trust: it unlocks Approve
 *                    on this row and nothing else.
 *   mismatch         the node said it did not match. The row is refused and
 *                    nothing is registered.
 *   after_approval   no `pair_keys` went out (an older node, or a cache miss
 *                    after a restart), so the node checks the signed welcome
 *                    after approval, the way it always has.
 */
export type PairingCheck = 'waiting_at_node' | 'matched' | 'mismatch' | 'after_approval';

/** One Pending row, as Settings renders it. No socket, no token, no code. */
export interface PairingRow {
  id: string;
  label: string;
  pubkey_node: string;
  /** Null when this fleet does not know where that node's dashboard is
   *  (#339): the node said so, or the address it sent was one only that box
   *  could open. The row is registered either way. */
  dashboard_url: string | null;
  advisor: boolean;
  dashboard_version: string | null;
  advisord_version: string | null;
  node_version: string | null;
  /** linkRateKey()'s answer for the socket this arrived on. SHOWN, never
   *  acted on: it is what an operator compares against where they think the
   *  node is, and it is not a credential. */
  dialed_from: string;
  first_seen_ms: number;
  /** The CODE's expiry, not the hello's: a Pending row expires with the
   *  window the operator agreed to when they minted it. */
  expires_at_ms: number;
  stage: PairingStage;
  /** One truthful sentence about what this row is doing right now. */
  note: string;
  /** The one optional next step `note` may carry (#635) -- today, only the
   *  follow-on's `arm_closed` outcome has one (fleet-broker.ts's
   *  PairFollowOnNext, mirrored here by shape rather than imported, so this
   *  module holds no dependency on that one). Carried apart from `note` so
   *  the page can render it as its own block, sentence then a command in its
   *  own copy box, rather than folding a root command into running prose --
   *  which is how the missing-period bug and the un-copyable command in the
   *  old Paired note both happened. Null whenever there is no next step. */
  note_next: { sentence: string; command: string } | null;
  /** What the node reported writing, once it has. */
  wrote: string[];
  /** #620: set when the presented node key already pins exactly one row in
   *  this fleet's own fleet.yaml that is not yet a link (a tunnel row this
   *  fleet already watches). Approving renders as "Approve and move" and
   *  carries this label, never the one the node proposed. `label` above
   *  stays what the node sent, so the Pending row can still say the
   *  proposed name is being ignored. */
  known_label: string | null;
  /** #624: set when the presented node key already pins exactly one LINK row
   *  that no link is held under right now: that node, back after being
   *  offline or rebuilt with its identity kept. Approving reconnects it
   *  under this label, never the one the node proposed, and needs no move
   *  proof (there is no tunnel read token to prove). `label` above stays
   *  what was proposed, so the row can still say it is being set aside. */
  reconnect_label: string | null;
  /** #620: set when the key is not simply new or known-but-tunnel: it is
   *  pinned by a row that is already a link and currently live, by more
   *  than one row, or the proposed label already names a different row
   *  under a different key. Refused here, before Approve ever renders; the
   *  broker's own pin_taken/label_taken checks are the last-line guard for
   *  anything this classification missed. */
  clash_reason: string | null;
  /** Pairing v2: see PairingCheck. The two keys `pair_keys` carried are NOT
   *  here, deliberately: the pairing fingerprint is a function of them, and
   *  nothing this dashboard serves may let a page compute it (#741). */
  check: PairingCheck;
  /** Pairing v2: the hello carried `keys_first`, so the node took its
   *  operator's paste before it dialled and will not ask again, whether or
   *  not it got `pair_keys`. A public flag, no key material. */
  node_asked_first: boolean;
  /** #626: `verified` once a known row's node proved it holds the read token
   *  this aggregator already reads it with. Null otherwise, and always null
   *  on a row that is not a known node's move. A known row is approvable
   *  only once this says `verified`; a known row that cannot reach it is
   *  refused before approval. Neither the proof nor the token is here. */
  move_proof: 'verified' | null;
  /** #632: how a `done` row finished. Null until then. */
  settled: PairingSettled | null;
  /** #632: the failure's own reason when `settled` is not `ok` or `waiting`,
   *  kept apart from `note` so the follow-on's sentence cannot replace it. */
  settled_reason: string | null;
}

/** What the caller hands back from the settle callback: the broker's answer.
 *  The hub never calls a broker itself — it owns the socket and the frames,
 *  and settings-api.ts owns the privileged program. */
export type PairSettlement =
  | {
    ok: true; label: string; credential: string;
    fleet_arm_pubkey: string | null; read_port: number; advisor_port: number | null;
    /** #1057: the broker wrote the node's row but could not write this
     *  aggregator's own, and said which row to add by hand. Carried on the
     *  pairing row's note from here on; absent when nothing was missing. */
    self_row_note?: string | null;
    /** #1079: the broker's sentence about the Advisor attachment a rejoin
     *  cleared, or kept because it could not be rewritten safely. Rides the
     *  row's finish line the way self_row_note does. */
    advisor_note?: string | null;
  }
  | { ok: false; error: string; detail: string };

export type PairApproveOutcome =
  | { ok: true }
  | { ok: false; error: string; detail: string };

/** #687 review, F1: judge only these live links, and bind nothing. */
export interface ReconcileOpts {
  onlyLabels?: readonly string[];
}

export interface LinkStatus {
  /** Is this node's link up AND are its listeners bound right now? */
  held: boolean;
  /** When it last was. Observed, never derived from the config: a row that
   *  SAYS link and never held one reads as never. */
  last_held_ms: number | null;
  reason: string | null;
}

export interface FleetLinkHub {
  handleUpgrade: (req: IncomingMessage, socket: Duplex, head: Buffer) => void;
  status: (label: string) => LinkStatus | null;
  /** How many requests this hub is counting against the label's link right
   *  now, or null with no live link. For tests and for a log line. */
  inflight: (label: string) => number | null;
  /** Bumped every time the label's link comes up or goes down (#831). A pin
   *  confirmed under one generation is never reused under another. */
  generation: (label: string) => number;
  /** Close any live link whose row has gone from fleet-links.json, or whose
   *  credential has been re-minted. Called after the file is re-read. */
  reconcile: (opts?: ReconcileOpts) => Promise<void>;
  /** Every pairing this hub is holding, for the Settings page. */
  pending: () => PairingRow[];
  /**
   * Send the signed welcome and start the settlement.
   *
   * Returns as soon as the welcome is away, NOT when the node has finished.
   * The node pauses on that frame for an operator to compare a fingerprint,
   * and blocking an HTTP response on a second human at another keyboard is a
   * spinner nobody can read. The row carries the stage instead, and the page
   * polls the one body it already polls.
   */
  approve: (
    id: string, finalLabel: string,
    settle: (tokens: { read_token: string; advisor_token: string | null }) => Promise<PairSettlement>,
    /** #741: this aggregator's fleet ARM public key, plain base64, as root's
     *  broker reported it a moment ago. It goes in the SIGNED welcome, so the
     *  pairing fingerprint the operator pastes at the node covers it before a
     *  token leaves that node. What this process says it is proves nothing;
     *  the paste against root's own output is what does. */
    fleetArmPubkey: string | null,
  ) => PairApproveOutcome;
  /** Drop a Pending row and close its socket, by name. Refusing grants
   *  nothing, so this needs no passkey. */
  refuse: (id: string) => boolean;
  /**
   * Put a sentence on a finished row, and give it another linger.
   *
   * The follow-on (§3.6) runs after this hub's part is over — it waits for
   * the link, pushes the trust bundle, and says whether the node still needs
   * a model — and the row is where the operator is looking. The hub owns the
   * row, so the caller hands it words rather than reaching into it.
   *
   * `next` (#635) rides beside the sentence: the one optional next step
   * `note` may carry, so the page can render it as its own block -- a
   * sentence, then a command in its own copy box -- instead of the note
   * carrying a command inline.
   */
  annotate: (id: string, note: string, next?: { sentence: string; command: string } | null) => boolean;
  /**
   * Say that an operator has just asked, at a passkey, for this node's link
   * to be revoked (#688). The next reconcile that finds that row gone from
   * fleet-links.json, with the live link still holding the credential that
   * row had when this was called, sends the `revoked` refusal with a
   * tombstone this host signed. Nothing else ever does.
   *
   * Returns the undo: the caller runs it when the broker refuses or cannot
   * be reached, so a revoke that did not happen leaves nothing signed
   * behind. Unused expectations lapse on their own after
   * LINK_REVOKE_EXPECT_MS, so one can never attach itself to a row that
   * leaves the file for some other reason later.
   */
  expectRevoke: (label: string) => () => void;
  close: () => Promise<void>;
}

/** How long an expected revoke may wait for the reload that carries it out.
 *  The broker's revoke rewrites the file and reloads this dashboard in the
 *  same call, so this is seconds in practice; two minutes is a ceiling. */
export const LINK_REVOKE_EXPECT_MS = 120_000;

/** One bound loopback listener, tagged by which origin it serves. #641: a
 *  positional array could not tell an additive advisor bind apart from the
 *  read listener it must never touch, so every entry now says which one it
 *  is. `port` rides beside it: a presence-only check (an entry exists, a row
 *  names a port) cannot tell a genuine match apart from a row whose port
 *  changed value directly, old to new, with no reload in between where it
 *  read as absent. Comparing the actual bound port is what tells those two
 *  apart. */
interface ServerEntry {
  kind: 'read' | 'advisor';
  port: number;
  server: Server;
  /** Set synchronously, the first thing unbindAdvisor does, before it
   *  enumerates or settles a single pending request. A request already
   *  accepted and reading its own body when a detach starts is not IN
   *  live.pending yet (it only lands there once its body finishes), so
   *  unbindAdvisor's own enumeration can never see it. serveLoopback checks
   *  this flag itself, on the very entry its request arrived through,
   *  immediately after that body finishes reading and before the request
   *  would otherwise be queued and forwarded to a node this hub has already
   *  stopped serving. */
  closing: boolean;
  /** Cancellers for every request on this entry currently reading its own
   *  body, keyed by the function each one adds just before its own readBody
   *  call and removes the moment that call settles, either way. `closing`
   *  above only answers a request whose body has ALREADY finished reading by
   *  the time a detach starts; one still mid-read is not there yet, and used
   *  to sit on this socket at whatever pace the CLIENT chose to send it,
   *  while closeAllConnections() in unbindAdvisor destroyed that socket
   *  regardless, a hard reset, not the clean refusal this whole mechanism
   *  exists to hand back. Firing every canceller here resolves each one's
   *  own race with that same refusal at once, rather than waiting on the
   *  client. */
  readingBodies: Set<() => void>;
}

interface Live {
  label: string;
  ws: LinkHubSocket;
  /** #624: the address this link dialed from (the rate key the Pending row
   *  shows as `dialed_from`), for the "last linked" sentence on a reconnect
   *  row. Recorded beside lastHeld, never before the link was held. */
  from: string;
  ready: boolean;
  /** The credential hash this link was admitted on. Re-minting a node's
   *  credential is a revocation of the old one, so a live link holding the
   *  previous hash is closed exactly like a deleted row. */
  credentialHash: string;
  servers: ServerEntry[];
  /** #641: `kind` rides beside each in-flight request so an advisor-only
   *  detach can answer exactly the requests it orphaned and leave every read
   *  request travelling the same link alone. */
  pending: Map<string, { settle: (frame: LinkFrame) => void; timer: NodeJS.Timeout; kind: 'read' | 'advisor' }>;
  /** The tear-down in flight, or null. Set the moment tearDown starts.
   *
   *  Two callers reach tearDown for the same link: live.ws.close() fires the
   *  socket's own 'close' handler INSIDE the await on the listeners, and a
   *  real ws emits 'error' and then 'close' on an abnormal termination. The
   *  link is still in the map for that whole window, so both guards pass and
   *  the second tear-down overwrites the reason with whichever event fired
   *  last and says so again in the journal (#290).
   *
   *  A promise and not a flag, because the second caller must WAIT. The
   *  reconnect path calls tearDown on the old link and binds when it settles;
   *  a flag would hand it an immediate return while the old listener was
   *  still closing, and the rebind would hit EADDRINUSE against this hub's
   *  own dead socket — the exact failure closeAllConnections is here to stop
   *  and the one runbook step 9 checks for. */
  tearing: Promise<void> | null;
  /** A knowledge bundle is on this link right now (#289). One at a time, so
   *  the worst case is one 8 MiB frame per linked node and never sixteen. */
  bundleInflight: boolean;
  /** The node's ready frame listed `cancel` (#831). Only then does this hub
   *  send one: an older agent meets an unknown frame with bad_frame and
   *  drops the link. */
  canCancel: boolean;
}

/** One live pairing. Held in memory beside `links`, and deliberately not
 *  persisted: a socket cannot survive a restart, so a row that did would be
 *  a Pending row nobody can approve — which is the kept-versus-observed bug
 *  this project keeps paying for. The CODE survives, hashed, so the operator
 *  runs the same command again. */
interface Pairing {
  id: string;
  label: string;
  pubkey_node: string;
  /** pairDashboardUrl()'s answer, never the raw field (#339). */
  dashboard_url: string | null;
  advisor: boolean;
  dashboard_version: string | null;
  advisord_version: string | null;
  node_version: string | null;
  rate_key: string;
  first_seen_ms: number;
  expires_at_ms: number;
  /** The nonce the NODE minted, remembered so the welcome echoes what was
   *  SENT rather than anything read later (#291's lesson). */
  nonce: string;
  ws: LinkHubSocket;
  stage: PairingStage;
  note: string;
  /** #635: see PairingRow's own doc comment. This is that field's home. */
  note_next: { sentence: string; command: string } | null;
  wrote: string[];
  /** #620: see PairingRow's own doc comment. This is that field's home. */
  known_label: string | null;
  /** #624: see PairingRow's own doc comment. This is that field's home. */
  reconnect_label: string | null;
  /** #624: the address a link came up from under the reconnect label while
   *  the broker call was in flight, or null. Turned into `cut_note` only if
   *  the broker then wrote, since a failed rejoin cuts nothing. */
  cut_from: string | null;
  /** #624: appended to every later note on the row, so the sentence that
   *  follows "registered" does not hide a cut link. */
  cut_note: string;
  /** #1057: the same job for the broker's "this aggregator has no row of its
   *  own" sentence. Empty, or a leading space and the sentence. Without it the
   *  note was written once at settle and overwritten by `pair_done` and by
   *  the follow-on, and the operator never read why the node was held. */
  self_row_tail: string;
  /** #620: see PairingRow's own doc comment. This is that field's home. */
  clash_reason: string | null;
  /** #632: see PairingRow's own doc comments. These are those fields' home. */
  settled: PairingSettled | null;
  settled_reason: string | null;
  settle: ((tokens: { read_token: string; advisor_token: string | null }) => Promise<PairSettlement>) | null;
  /** #741: the arm key the welcome carried, so the settlement can be held to
   *  it. Null until approved. */
  arm_pub: string | null;
  /** Pairing v2: the hello carried `keys_first: true`. */
  keys_first: boolean;
  /** Pairing v2: the two keys `pair_keys` carried, or null when none went
   *  out. approve() refuses a welcome whose keys differ from these, because
   *  the node's check covered these and would refuse anything else. Kept
   *  off PairingRow (see its `check`). */
  sent_trust: string | null;
  sent_arm: string | null;
  check: PairingCheck;
  /** #626: the hub_nonce `pair_keys` carried, KEPT here when it was sent.
   *  The known-node proof is checked against this copy and never against
   *  anything the node sends back. Off PairingRow: it is no secret, but it
   *  is nobody's business but this check's. */
  hub_nonce: string | null;
  /** #626: see PairingRow's own doc comment. This is that field's home. */
  move_proof: 'verified' | null;
  /** #635: the sentence a known row's note ends on, naming whose proposed
   *  name is set aside, kept so the note can be rebuilt when the proof
   *  lands. Empty on every other row. */
  known_aside: string;
  closed: boolean;
  timer: NodeJS.Timeout | null;
  /** Separate from `timer`: that one is the code's expiry, fires once, and
   *  ends the row. This one repeats and ends with the socket. */
  keepalive: NodeJS.Timeout | null;
  /** Answered the last keepalive ping. A ping to a node that has gone does
   *  NOT throw: it writes into a half-open socket the kernel will not reset
   *  for minutes, so `close` never fires and the row would sit "waiting,
   *  Approve" until the code expired (#315). The keepalive marks this false
   *  before each ping and the node's pong sets it true; a ping that finds it
   *  still false means the previous one went unanswered and the node is
   *  gone. */
  alive: boolean;
}

/** #831: at most one journal line per (link, refusal code) this often. */
export const LINK_REFUSAL_LOG_EVERY_MS = 10_000;

/** #831: the Advisor's share of a link. Defined in the contract because the
 *  node enforces it too; re-exported here for this file's readers. The hub's
 *  half: a slow advisord answering inside the proxy's 10 s timeout holds its
 *  requests without anything being abandoned, so cancelling does not help,
 *  and with no share of their own the Overview's reads met a full link. */
export { FLEET_LINK_ADVISOR_MAX_INFLIGHT };

/** Codes noteLink writes by name. Anything else a node sends is written as
 *  `other`, which keeps the throttle's map bounded and keeps a hostile
 *  node's words out of this journal. */
const LOGGED_REFUSAL_CODES: ReadonlySet<string> = new Set([
  'link_not_ready', 'concurrency_cap', 'upstream_timeout', 'upstream_unreachable',
  'not_allowed', 'body_too_large', 'bad_frame', 'stream_not_supported',
  'cancelled', 'abandoned',
]);

export function createFleetLinkHub(deps: LinkHubDeps): FleetLinkHub {
  const log = deps.log ?? ((line: string) => console.warn(line));
  const now = deps.now ?? (() => Date.now());
  const guard = deps.guard ?? createHandshakeGuard({ now });
  const makeServer = deps.makeServer ?? (() => createServer());
  const links = new Map<string, Live>();
  /** The port this link's READ listener is actually bound to, or null before
   *  onReady has bound one. Observed, never taken from the row: the whole
   *  point of F2 is that the row can move and the listener cannot follow it
   *  on its own. */
  const readPortOf = (live: Live): number | null =>
    live.servers.find((s) => s.kind === 'read')?.port ?? null;
  const lastHeld = new Map<string, number>();
  /** #624: where each label's link last dialed from (the rate key the row
   *  shows as `dialed_from`), so a reconnect row can be read against it.
   *  In memory only, like lastHeld. */
  const lastDialedFrom = new Map<string, string>();
  const lastReason = new Map<string, string>();
  /** #831: see FleetLinkHub.generation. */
  const generations = new Map<string, number>();
  const bumpGeneration = (label: string) => { generations.set(label, (generations.get(label) ?? 0) + 1); };
  /** #831: the last time each (label, code) refusal was written, and how many
   *  went unwritten since. Keyed on a closed code set, so the map is bounded
   *  by the registry. */
  const refusalLog = new Map<string, { at: number; quiet: number }>();
  /**
   * One journal line per kind of refusal per link, at most every
   * LINK_REFUSAL_LOG_EVERY_MS, carrying how many were not written (#831).
   *
   * Before this the hub's own 503s (link_not_ready, concurrency_cap) were
   * sent with no line at all and the proxies wrote them as `bad_response`,
   * so the one log that could have said "the link was full" said nothing,
   * and an absence of `concurrency_cap` lines was read as proof it had not
   * happened.
   */
  /** Advisor requests in flight on this link. Sixteen entries at most, so a
   *  walk is cheaper than a second count to keep in step. */
  function advisorInflight(live: Live): number {
    let n = 0;
    for (const p of live.pending.values()) if (p.kind === 'advisor') n += 1;
    return n;
  }

  function noteLink(live: Live, kind: 'read' | 'advisor', code: string, by: 'hub' | 'node'): void {
    const known = LOGGED_REFUSAL_CODES.has(code) ? code : 'other';
    const key = `${live.label}|${known}`;
    const t = now();
    const prev = refusalLog.get(key);
    if (prev && t - prev.at < LINK_REFUSAL_LOG_EVERY_MS) { prev.quiet += 1; return; }
    const more = prev && prev.quiet ? `; ${prev.quiet} more like it since the last line` : '';
    refusalLog.set(key, { at: t, quiet: 0 });
    const load = `${live.pending.size} of ${FLEET_LINK_MAX_INFLIGHT} in flight`;
    const what = known === 'cancelled'
      ? `cancelled a ${kind} request its caller gave up on`
      : known === 'abandoned'
        ? `a caller gave up on a ${kind} request; the node takes no cancel, so it holds the slot until it answers`
        : `${by === 'hub' ? 'this hub' : 'the node'} refused a ${kind} request: ${known}`;
    log(`[fleet-link] ${live.label}: ${what} (${load})${more}`);
  }
  let pendingHandshakes = 0;
  const pairGuard = deps.pairGuard ?? createHandshakeGuard({ now });
  const pairings = new Map<string, Pairing>();
  /** Upgraded, pre-hello pairing sockets. Counted apart from the rows so the
   *  cap covers both: the sum is the memory an unauthenticated caller can
   *  make this hub hold. */
  let pairingSockets = 0;
  /** #688: revokes an operator approved at a passkey and the broker has not
   *  yet carried out, by label. Bound to the credential the row held when
   *  the operator asked, so a re-pair racing the revoke gets nothing. */
  const expectedRevokes = new Map<string, { credentialHash: string; until: number; token: symbol }>();

  /** The signed tombstone for one live link, or null. Only called from the
   *  "row gone from both lists" branch of runReconcile, and only after an
   *  expectRevoke for that label and that credential. */
  const tombstoneFor = (live: Live): LinkTombstone | null => {
    const exp = expectedRevokes.get(live.label);
    if (!exp) return null;
    expectedRevokes.delete(live.label);
    if (exp.until < now() || exp.credentialHash !== live.credentialHash) return null;
    const body = {
      v: FLEET_LINK_PROTOCOL_VERSION, issuer_label: FLEET_WRITE_ISSUER_LABEL,
      label: live.label, credential_sha256: live.credentialHash, issued_at: now(),
    };
    let signature: string | null;
    try { signature = deps.sign(linkTombstoneSigningBytes(body)); } catch { signature = null; }
    if (!signature) {
      log(`[fleet-link] ${live.label}: revoked, but this host could not sign a tombstone, so that node will `
        + 'ask again once an hour and be refused each time');
      return null;
    }
    return { ...body, signature };
  };

  /** One sentence for every way a code fails to resolve. Bad, reused and
   *  expired are not linked facts about the caller, and the journal names
   *  which of the three it was. */
  const CODE_REFUSAL = 'that pairing code is not one this aggregator is waiting for';
  // Pairing v2: the row's sentence for each check state (design 1.8).
  const PAIR_NOTE_WAITING_AT_NODE = 'Called in. Waiting for the fingerprint check at the node.';
  // The node's word, unsigned, so said as the node's word (#850 review).
  const PAIR_NOTE_MATCHED = 'The node reports that the fingerprint pasted there matches this aggregator\u2019s keys. '
    + 'Compare the node key, then approve.';
  // Two causes besides a miscopy, named in the order they are likely: the
  // keys sent were cached at the mint, so a restore or a grant reinstall
  // since then sends stale ones (#850 review, L3); and a node that dialled
  // some other address.
  const PAIR_NOTE_MISMATCH = 'Refused at the node: the pasted fingerprint doesn\u2019t match the keys this aggregator sent. '
    + 'Nothing was registered. If the paste was exactly what sudo aperire-fleet-arm --fingerprint prints here, '
    + 'this aggregator\u2019s keys may have changed since the code was minted: mint a fresh code and pair again. '
    + 'If it still doesn\u2019t match, stop and check which address the node dialled.';
  const PAIR_NOTE_MISMATCH_KEYS_CHANGED = 'Refused at the node: this aggregator\u2019s fleet trust key changed after '
    + 'the code was minted, so the keys the node was sent are not the ones root prints now. Nothing was registered. '
    + 'Mint a fresh code and pair again.';

  // #626: a known node's move. The row says what is and is not proved, by
  // state, and the refusals each name their one fix.
  const knownLead = (l: string) => `This node key is already pinned to ${l}, read over an SSH tunnel.`;
  /** Waiting for the node's check, which carries the proof. */
  const knownNoteWaiting = (l: string, aside: string) => `${knownLead(l)} Before a move is offered, the node `
    + `has to prove it holds the read token this aggregator reads ${l} with.${aside}`;
  /** Proved. Still says what a copy of the disk could do, because it could. */
  const knownNoteVerified = (l: string, aside: string) => `${knownLead(l)} The node proved it holds the read `
    + `token this aggregator reads ${l} with, so it is not just someone presenting ${l}'s public key. A copy of `
    + `that box's disk holds the token too, so check the key on the node's own terminal and where it dialed from `
    + `before you approve. Approving moves ${l} to the fleet link. It keeps the name ${l} and its history.${aside}`;
  // #624: a link row's node coming back. No proof is asked of it: the link
  // credential is what proves a node to this aggregator after it is paired,
  // and the key match alone is an unsigned claim, so the note says only what
  // was matched, when the link was last seen, and sends the operator to the
  // two things a copy cannot fake. `last` is this process's own memory of the
  // link (empty after a restart), never a stored fact.
  const reconnectNote = (l: string, last: string, aside: string) => `Its node key matches ${l}'s link row, so `
    + `this may be ${l}, back after being offline. No link is held under that name right now.${last} Approving `
    + `reconnects ${l} under the same name with a new credential. It keeps its name and history. The key alone does `
    + `not prove a machine, so check the key on the node's own terminal and where it dialed from before you approve.${aside}`;
  const lastLinkedSentence = (label: string): string => {
    const at = lastHeld.get(label);
    const from = lastDialedFrom.get(label);
    if (at === undefined) {
      return ' This dashboard has not seen it linked since it started. A node may not have dialed back yet; wait a minute before you approve.';
    }
    const when = new Date(at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    return ` Last linked ${when}${from ? ` from ${from}` : ''}.`;
  };
  const reconnectLive = (l: string) => `${l} is linked again from somewhere right now, so this pairing is refused. `
    + 'If that is the same machine, it needs no pairing. If it is a second machine holding the same node key, '
    + 'that is a copied install: give the copy its own node identity, then mint a new code.';
  const knownRefused = (l: string, why: string) => `Refused before approval. ${knownLead(l)} A move needs proof `
    + `that the node holds the read token this aggregator reads ${l} with, and ${why} Nothing was registered.`;
  /** The node's terminal gets one generic sentence, never which part failed:
   *  whoever holds the code is not yet anyone this aggregator trusts. */
  const KNOWN_WIRE_REFUSAL = 'This aggregator refused the pairing before approval. Its administrator can see why '
    + 'on the Settings page.';

  /** How long a finished row stays on the page. Long enough for an operator
   *  who pressed Approve to read what happened. */
  const PAIRING_LINGER_MS = 60_000;
  /** Pre-hello pairing sockets, by rate key. Bounded by construction: a key
   *  is deleted the moment its count reaches zero, and no key can exceed
   *  FLEET_PAIR_MAX_PER_KEY, so the map cannot grow past the four-slot cap
   *  and a stranger cannot grow it one address at a time (#279's lesson
   *  about the failure map, applied to this one). */
  const pairingSocketsByKey = new Map<string, number>();
  const holdPairingSocket = (key: string): void => {
    pairingSocketsByKey.set(key, (pairingSocketsByKey.get(key) ?? 0) + 1);
  };
  const releasePairingSocket = (key: string): void => {
    const left = (pairingSocketsByKey.get(key) ?? 1) - 1;
    if (left <= 0) pairingSocketsByKey.delete(key);
    else pairingSocketsByKey.set(key, left);
  };
  /** Pre-hello sockets plus held rows for one key: what the gate bounds. */
  const pairingsFromKey = (key: string): number => {
    let rows = 0;
    for (const p of pairings.values()) if (p.rate_key === key) rows += 1;
    return (pairingSocketsByKey.get(key) ?? 0) + rows;
  };

  const refuseSocket = (socket: Duplex, status: number, text: string) => {
    try {
      socket.write(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\n\r\n`);
    } catch { /* the peer already left */ }
    socket.destroy();
  };

  /** Close a live link and everything it holds. Awaited on replacement so a
   *  reconnect never meets its own dead listener (EADDRINUSE). */
  function tearDown(live: Live, reason: string): Promise<void> {
    if (live.tearing) return live.tearing;
    // One line per close, wherever the close came from (#290). ADR 0019's
    // trade-off row says a link outage must be tellable from a tunnel
    // outage: the Settings row does that on the page, and the journal has to
    // do it too, because the journal is where an operator looks when the
    // page is what is broken. Before this, only a revoke wrote a line, so
    // the one close nobody caused was the one close nobody could see: a
    // node's restart left two "linked, serving" lines and nothing between.
    // Above the latch, so it is written once even though the body below runs
    // once: the first reason is the true one, and the caller that arrives
    // second gets the same promise rather than a second sentence.
    log(`[fleet-link] ${live.label}: link closed, ${reason}`);
    live.tearing = (async () => {
    // The age on the row is "when did this last WORK", so it is stamped as
    // the link goes away, not only as it arrives. Stamped at bind alone, a
    // link that held for three hours and dropped a minute ago reported three
    // hours, which inflates the outage on the one field the row's whole job
    // rests on.
    if (live.ready) { lastHeld.set(live.label, now()); lastDialedFrom.set(live.label, live.from); bumpGeneration(live.label); }
    for (const p of live.pending.values()) {
      clearTimeout(p.timer);
      p.settle(refusal('upstream_unreachable', 'the link to that node closed while this request was in flight'));
    }
    live.pending.clear();
    try { live.ws.close(); } catch { /* already gone */ }
    await Promise.all(live.servers.map(({ server }) => new Promise<void>((done) => {
      // closeAllConnections FIRST. close() alone stops accepting and then
      // waits on live sockets, and the fleet poll holds keep-alives open, so
      // the callback would not fire before the node reconnects and the
      // rebind would hit EADDRINUSE against this hub's own dead listener.
      try { server.closeAllConnections(); } catch { /* older server, or already closed */ }
      server.close(() => done());
      // A server that was never listening never calls back.
      if (!server.listening) done();
    })));
    live.servers.length = 0;
    live.ready = false;
    lastReason.set(live.label, reason);
    if (links.get(live.label) === live) links.delete(live.label);
    })();
    return live.tearing;
  }

  /**
   * Binds one loopback listener for a link, tagged by which origin it
   * serves.
   *
   * Resolves `false`, never throwing, when this Live was torn down or
   * replaced (the node's own socket closing, a credential re-mint, a
   * reconnect, or another reconcile() pass finishing first) while listen()
   * was still in flight: whatever was just bound is closed and dropped at
   * once, rather than left served for a link this hub no longer considers
   * live. #641 Low: this guard used to be written once, inline, only at
   * reconcile()'s own additive-bind call site; onReady's initial bind had no
   * equivalent guard at all. Moved in here so every caller, onReady and
   * reconcile alike, gets it for free.
   */
  function bindOne(live: Live, port: number, kind: 'read' | 'advisor'): Promise<boolean> {
    return new Promise((done, fail) => {
      const server = makeServer();
      // Captured once, up front, so serveLoopback can check THIS entry's own
      // `closing` flag even after unbindAdvisor has spliced it out of
      // live.servers (a lookup by kind alone would find nothing once that
      // splice has already run, #641 Medium).
      const entry: ServerEntry = { kind, port, server, closing: false, readingBodies: new Set() };
      server.on('request', (req: IncomingMessage, res: ServerResponse) => {
        void serveLoopback(live, entry, req, res);
      });
      server.once('error', (err: Error) => fail(err));
      // 127.0.0.1 only. The listener answers with a node's whole read
      // surface behind that node's own bearer token, so it must not be
      // reachable from anywhere but this box, and the bind is what enforces
      // that rather than a check inside the handler.
      server.listen(port, '127.0.0.1', () => {
        live.servers.push(entry);
        if (live.tearing || links.get(live.label) !== live) {
          const idx = live.servers.indexOf(entry);
          if (idx !== -1) live.servers.splice(idx, 1);
          try { server.closeAllConnections(); } catch { /* already gone */ }
          server.close(() => { /* nothing waits on this */ });
          done(false);
          return;
        }
        done(true);
      });
    });
  }

  /**
   * #641: the subtractive half of the additive advisor bind below. Closes
   * exactly the advisor listener on an otherwise-live link, the same way
   * `tearDown` closes every listener, but scoped to one `ServerEntry` and
   * never touching `live.ws` or the read listener beside it.
   *
   * Any request already forwarded to the node from THIS listener is sitting
   * in `live.pending`, tagged `kind: 'advisor'` from the moment
   * `serveLoopback` sent it. Those are answered here, at once, with the same
   * `upstream_unreachable` shape `tearDown` already uses for a request
   * orphaned by a full link drop: a clear refusal, rather than a hang until
   * `FLEET_LINK_REQUEST_TIMEOUT_MS` or a node reply for a route the
   * aggregator no longer trusts. A read-kind request on the very same link
   * is untouched, since it is a different key in the same map and this loop
   * never looks at it.
   *
   * `settle()` only resolves the promise `serveLoopback` is awaiting; the
   * write that actually answers the caller (`res.writeHead`/`res.end`) is
   * that promise's OWN continuation, a microtask, not something this
   * function runs directly. Closing the listener's sockets in the same
   * synchronous turn as `settle()` would race that microtask: a real
   * `closeAllConnections()` destroys the socket outright, so a caller could
   * see a reset connection instead of the very refusal it was just handed.
   * The `setImmediate` below is a deliberate yield, giving every settled
   * continuation a full turn to finish writing before the socket goes.
   */
  async function unbindAdvisor(live: Live, entry: ServerEntry): Promise<void> {
    // #641 Medium: set FIRST, synchronously, before anything else below
    // runs. serveLoopback checks this on the very entry a request arrived
    // through, right after that request's own body finishes reading. That is
    // the one case this function's own live.pending enumeration cannot see,
    // because a request still reading its body is not in live.pending yet.
    entry.closing = true;
    // Stop new accepts next, still before touching a single pending
    // request. The previous order (settle every orphan, yield one turn,
    // THEN stop accepting) left this listener open across both of those
    // steps: a keep-alive connection could land a brand-new advisor request
    // in that window, which got forwarded as an ordinary in-flight request
    // and then had its own socket hard-reset moments later by
    // closeAllConnections(), the exact "reset instead of the answer"
    // failure this function exists to prevent, just for a request that
    // slipped in one step later.
    const closed = new Promise<void>((done) => {
      entry.server.close(() => done());
      if (!entry.server.listening) done();
    });

    const orphaned: Array<[string, { settle: (frame: LinkFrame) => void; timer: NodeJS.Timeout }]> = [];
    for (const [id, p] of live.pending) {
      if (p.kind !== 'advisor') continue;
      orphaned.push([id, p]);
    }
    for (const [id, p] of orphaned) {
      clearTimeout(p.timer);
      live.pending.delete(id);
      p.settle(refusal(
        'upstream_unreachable',
        `the Advisor was detached from ${live.label} while this request was in flight`,
        id,
      ));
    }

    // #641 review: a request already accepted and reading its own body when
    // this detach started is not in live.pending yet, it only lands there
    // once its body finishes, so the enumeration above can never see it.
    // Left alone, it used to sit on this listener's socket until the CLIENT
    // finished sending it (or never, for a slow or silent one), while
    // closeAllConnections() below destroyed that socket regardless: a hard
    // reset, not the clean refusal this function exists to hand back. Every
    // such request registered its own canceller on this entry the moment it
    // started reading (serveLoopback, just before its own readBody call);
    // firing them now resolves each one's own race at once, with the same
    // refusal shape the orphaned loop above just used, rather than this
    // function waiting on however long the client takes.
    const inFlight = Array.from(entry.readingBodies);
    for (const cancel of inFlight) cancel();

    if (orphaned.length || inFlight.length) await new Promise<void>((r) => setImmediate(r));
    try { entry.server.closeAllConnections(); } catch { /* older server, or already closed */ }
    await closed;
    const idx = live.servers.indexOf(entry);
    if (idx !== -1) live.servers.splice(idx, 1);
    log(`[fleet-link] ${live.label}: advisor detached`);
  }

  async function serveLoopback(live: Live, entry: ServerEntry, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const kind = entry.kind;
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    const pathname = (req.url ?? '/').split('?')[0];
    if (!live.ready) {
      noteLink(live, kind, 'link_not_ready', 'hub');
      send(503, { error: 'link_not_ready', detail: `the link to ${live.label} is not carrying requests` });
      return;
    }
    // The event stream, answered here rather than framed. See
    // FLEET_LINK_STREAM_REFUSAL: peer-stream-proxy.ts reports the failure and
    // overview.html paints the quorum bar from the poll it never stopped.
    if (kind === 'read' && pathname === READ_STREAM_PATH) {
      send(501, {
        error: 'stream_not_supported',
        detail: 'this node is reached over the fleet link, which does not carry the event stream yet',
      });
      return;
    }
    if (live.pending.size >= FLEET_LINK_MAX_INFLIGHT) {
      noteLink(live, kind, 'concurrency_cap', 'hub');
      send(503, { error: 'concurrency_cap', detail: `the link to ${live.label} is already carrying as much as it takes` });
      return;
    }
    // Counted by kind, not by occupancy: reads in flight must not shrink the
    // Advisor's own share, only the Advisor must not take the reads'.
    if (kind === 'advisor' && advisorInflight(live) >= FLEET_LINK_ADVISOR_MAX_INFLIGHT) {
      noteLink(live, kind, 'concurrency_cap', 'hub');
      send(503, {
        error: 'concurrency_cap',
        detail: `the Advisor's share of the link to ${live.label} is full; the rest is kept for reads`,
      });
      return;
    }

    // The knowledge push is the one route that may be large (#289), and one
    // of them travels at a time. Refused BEFORE the body is read, so a second
    // pusher does not first cost this process 8 MiB to be told no. The node
    // holds the same rule; this is the aggregator declining to buffer what it
    // knows the node will refuse.
    const method = req.method ?? 'GET';
    const bundle = isLinkBundleRequest(kind, method, pathname);
    if (bundle && live.bundleInflight) {
      noteLink(live, kind, 'concurrency_cap', 'hub');
      send(503, {
        error: 'concurrency_cap',
        detail: `the link to ${live.label} is already carrying a knowledge bundle`,
      });
      return;
    }

    const cap = linkRequestCap(kind, method, pathname);
    let body = '';
    let tooBig = false;
    let cancelled = false;
    if (bundle) live.bundleInflight = true;
    // #641 review: `cancel` is registered on THIS entry before the read
    // starts and removed the instant it settles, either way, so
    // unbindAdvisor can resolve this request's own race the moment a detach
    // lands, rather than however long the client takes to finish sending
    // it. The promise executor below runs synchronously, so `cancel` is
    // always assigned before this function can be suspended by the `await`.
    let cancel: (() => void) | null = null;
    try {
      const outcome = await new Promise<BodyOutcome | 'cancelled'>((resolve) => {
        cancel = () => resolve('cancelled');
        entry.readingBodies.add(cancel);
        readBody(req, cap).then(resolve);
      });
      if (cancel) entry.readingBodies.delete(cancel);
      if (outcome === 'cancelled') cancelled = true;
      else if (outcome.ok) body = outcome.body;
      else if (outcome.reason === 'too_large') tooBig = true;
      else throw new Error('request stream failed');
    } catch (err) {
      if (cancel) entry.readingBodies.delete(cancel);
      if (bundle) live.bundleInflight = false;
      throw err;
    }
    if (cancelled) {
      if (bundle) live.bundleInflight = false;
      send(502, {
        error: 'upstream_unreachable',
        detail: `the Advisor was detached from ${live.label} while this request was in flight`,
      });
      return;
    }
    if (tooBig) {
      if (bundle) live.bundleInflight = false;
      send(413, {
        error: 'body_too_large',
        detail: bundle
          ? 'that bundle is larger than a node accepts on any transport'
          : 'that request is larger than the fleet link carries',
      });
      return;
    }

    // #641 Medium: this request's own body has just finished reading, which
    // is exactly the case unbindAdvisor's own live.pending enumeration can
    // never see: a request that was still reading its body when a detach
    // started is not queued yet, so it is not among the requests that
    // enumeration settles. Checked on THIS entry, captured once at bind
    // time in bindOne, so it still answers correctly even once
    // unbindAdvisor has already spliced the entry out of live.servers.
    if (entry.closing) {
      if (bundle) live.bundleInflight = false;
      send(502, {
        error: 'upstream_unreachable',
        detail: `the Advisor was detached from ${live.label} while this request was in flight`,
      });
      return;
    }

    const headers: Record<string, string> = {};
    for (const name of ['authorization', 'content-type', 'accept']) {
      const v = req.headers[name];
      if (typeof v === 'string') headers[name] = v;
    }
    const clean = normaliseHeaders(headers);
    if (clean === null) {
      send(400, { error: 'bad_frame', detail: 'that request carries headers the fleet link does not take' });
      return;
    }
    // #831: the caller went away while its body was being read. Nothing is
    // framed for an answer nobody will read.
    if (res.destroyed) {
      if (bundle) live.bundleInflight = false;
      return;
    }
    const target: LinkTarget = kind === 'advisor' ? 'advisor' : (pathname.startsWith('/fleet/') ? 'fleet' : 'read');
    const id = randomUUID();
    const sendCancel = () => {
      if (!live.canCancel) return;
      try { live.ws.send(encodeLinkFrame({ t: 'cancel', v: FLEET_LINK_PROTOCOL_VERSION, id })); } catch { /* going away */ }
    };
    const answer = await new Promise<LinkFrame | null>((settle) => {
      const timer = setTimeout(() => {
        live.pending.delete(id);
        sendCancel();
        noteLink(live, kind, 'upstream_timeout', 'hub');
        settle(refusal('upstream_timeout', `${live.label} did not answer over the link in time`, id));
      }, FLEET_LINK_REQUEST_TIMEOUT_MS);
      live.pending.set(id, { settle, timer, kind });
      // #831: the caller giving up frees the slot NOW, not when the node
      // answers or 310 s pass. `close` also fires after a normal finish;
      // by then every path that answers has already taken the id out of
      // `pending` (onFrame, the timer, tearDown, unbindAdvisor), so the
      // lookup below is what tells an abandon from a finish.
      res.on('close', () => {
        const waiting = live.pending.get(id);
        if (!waiting) return;
        if (!live.canCancel) {
          // An older node cannot be told. Its slot stays counted, because
          // the node is still spending it, and the late answer is written to
          // a socket that is gone, exactly as before.
          noteLink(live, kind, 'abandoned', 'hub');
          return;
        }
        clearTimeout(waiting.timer);
        live.pending.delete(id);
        sendCancel();
        noteLink(live, kind, 'cancelled', 'hub');
        settle(null);
      });
      try {
        live.ws.send(encodeLinkFrame({
          t: 'req', v: FLEET_LINK_PROTOCOL_VERSION, id, target,
          method: req.method ?? 'GET', path: req.url ?? '/', headers: clean,
          body: body.length ? body : null,
        }));
      } catch (err) {
        clearTimeout(timer);
        live.pending.delete(id);
        settle(refusal('upstream_unreachable', `the link to ${live.label} would not carry that request: ${(err as Error).message}`, id));
      }
    });
    if (bundle) live.bundleInflight = false;
    if (answer === null || res.destroyed) return;

    if (answer.t === 'res') {
      const out: Record<string, string> = { 'cache-control': 'no-store' };
      const ct = answer.headers['content-type'];
      if (ct) out['content-type'] = ct;
      res.writeHead(answer.status, out);
      res.end(answer.body ?? '');
      return;
    }
    const code = answer.t === 'refuse' ? answer.code : 'bad_frame';
    const detail = answer.t === 'refuse' ? (answer.detail ?? '') : 'that node answered with a frame this hub does not take';
    // A node's refusal is carried as a status the aggregator's own proxies
    // already read: 403 for a route the node does not allow (which is a
    // decision, not an outage), 502 for anything transport-shaped, so a
    // fleet row goes unreachable exactly as it does behind a dead tunnel.
    const status = code === 'not_allowed' ? 403
      : code === 'stream_not_supported' ? 501
      : code === 'body_too_large' ? 413
      : code === 'concurrency_cap' ? 503
      : code === 'upstream_timeout' ? 504
      : 502;
    send(status, { error: code, detail });
  }

  async function onReady(live: Live): Promise<void> {
    const row = deps.rows().find((r) => r.label === live.label);
    if (!row) {
      await tearDown(live, 'that node is no longer in fleet-links.json');
      return;
    }
    try {
      // #641 Low: bindOne resolves false, rather than throwing, when this
      // Live was torn down or replaced while listen() was in flight. Nothing
      // is left half-served in that case, since bindOne already closed and
      // dropped whatever it just bound, so onReady has nothing further to
      // do: no log line, no `ready` flip, no second bind attempt.
      if (!(await bindOne(live, row.read_port, 'read'))) return;
      if (row.advisor_port) {
        if (!(await bindOne(live, row.advisor_port, 'advisor'))) return;
      }
    } catch (err) {
      // A bind that fails means requests would still be going somewhere ELSE
      // (a leftover SSH forward on the same port, most likely). Serving in
      // that state would put `link` on a row whose reads are travelling down
      // a tunnel, which is this project's kept-vs-observed bug wearing a new
      // hat. So: refuse by name, close the link, and say which port.
      const detail = `this aggregator could not bind ${live.label}'s loopback ports: ${(err as Error).message}`;
      try { live.ws.send(encodeLinkFrame(refusal('bind_failed', detail))); } catch { /* going away anyway */ }
      // No log here: tearDown writes this reason as the close line.
      await tearDown(live, detail);
      return;
    }
    // #641 High (residual, from review): `row` above is a snapshot, read
    // once, before either bind, and an attach or detach can land in the
    // awaited gap inside bindOne. The fix that shipped for this finding
    // queued reconcile() AFTER `ready` flipped true, which left a narrower
    // window open: the stale-port listener was already eligible to serve
    // requests for however long that queued call took to actually run.
    // Re-read the row HERE instead, with nothing awaited between this line
    // and the read, and correct the advisor bind directly against what it
    // says now, before `ready` (and the requests it invites) exists at all.
    // The same comparison runReconcile's own phase 1/2 split uses, run once,
    // inline, for this one link. This is a single corrective pass, not a
    // loop: the row can still move again during the unbind/bind below, and a
    // change that lands in THAT gap is caught by the queued reconcile() a
    // few lines down, the same way runReconcile itself never loops until
    // stable either.
    const freshRow = deps.rows().find((r) => r.label === live.label);
    if (!freshRow) {
      await tearDown(live, 'that node is no longer in fleet-links.json');
      return;
    }
    const advisorEntry = live.servers.find((s) => s.kind === 'advisor');
    if (advisorEntry && (!freshRow.advisor_port || advisorEntry.port !== freshRow.advisor_port)) {
      await unbindAdvisor(live, advisorEntry);
    }
    if (freshRow.advisor_port && !live.servers.some((s) => s.kind === 'advisor')) {
      try {
        if (!(await bindOne(live, freshRow.advisor_port, 'advisor'))) return;
        log(`[fleet-link] ${live.label}: advisor attached, serving 127.0.0.1:${freshRow.advisor_port}`);
      } catch (err) {
        const detail = `this aggregator could not bind ${live.label}'s advisor loopback port: ${(err as Error).message}`;
        try { live.ws.send(encodeLinkFrame(refusal('bind_failed', detail))); } catch { /* going away anyway */ }
        await tearDown(live, detail);
        return;
      }
    }
    // unbindAdvisor and bindOne above both await, and a full teardown (the
    // node's own socket closing, a credential re-mint) can finish in that
    // gap the same way it already can inside bindOne itself; bindOne's own
    // listen() callback guards against that for its own case, but this
    // corrective pass adds an unbindAdvisor call bindOne's guard does not
    // cover, and a torn-down link must never be reported as having come up
    // (the property the existing "onReady's own advisor bind is dropped ...
    // if the link tears down" test already holds bindOne to).
    if (live.tearing || links.get(live.label) !== live) return;

    live.ready = true;
    bumpGeneration(live.label);
    lastHeld.set(live.label, now());
    lastDialedFrom.set(live.label, live.from);
    lastReason.delete(live.label);
    // #641 Low (rereview): build this line from what live.servers actually
    // holds, not from freshRow. freshRow is only ever re-verified against the
    // ADVISOR bind above; read_port is bound once, from the original `row`
    // snapshot, and never re-corrected here. Printing freshRow.read_port
    // would report a value the hub may not actually be serving if read_port
    // itself changed between the two reads, the same kept-vs-observed
    // mismatch this file's own comments warn about elsewhere, just moved
    // into a log line. The bound ServerEntry is the one thing that cannot
    // drift from what is actually listening.
    // boundRead cannot actually be missing here: the read bind above either
    // returned true, which pushes a 'read' entry onto live.servers before
    // resolving, or this function already returned. Nothing between there and
    // here ever removes a 'read' entry (unbindAdvisor only ever splices an
    // 'advisor' one). The `row.read_port` fallback is only to keep this a
    // plain read rather than a non-null assertion; it should never fire.
    const boundRead = live.servers.find((s) => s.kind === 'read');
    const boundAdvisor = live.servers.find((s) => s.kind === 'advisor');
    log(`[fleet-link] ${live.label}: linked, serving 127.0.0.1:${boundRead?.port ?? row.read_port}`
      + (boundAdvisor ? ` and 127.0.0.1:${boundAdvisor.port}` : ''));
    // Queued anyway: runReconcile still owes this link its ordinary
    // doomed/credential-mint check, and a row that has not moved again since
    // the re-read above costs one no-op pass.
    void reconcile();
  }

  function onFrame(live: Live, raw: string): void {
    const parsed = parseLinkFrame(raw);
    if (!parsed.ok) {
      try { live.ws.send(encodeLinkFrame(refusal(parsed.code, parsed.detail))); } catch { /* going away */ }
      void tearDown(live, parsed.detail);
      return;
    }
    const frame = parsed.frame;
    if (frame.t === 'ready') {
      if (live.ready || live.servers.length) return;
      live.canCancel = Boolean(frame.caps?.includes('cancel'));
      void onReady(live);
      return;
    }
    if (frame.t === 'res' || frame.t === 'refuse') {
      // Requests travel ONE direction on a link. A frame that is not the
      // answer to something this hub is waiting for is dropped, not acted
      // on: an id the hub never issued is a node trying to write into a
      // conversation it was not part of.
      const id = frame.id;
      if (!id) {
        if (frame.t === 'refuse') void tearDown(live, frame.detail ?? `that node refused the link: ${frame.code}`);
        return;
      }
      const waiting = live.pending.get(id);
      if (!waiting) return;
      live.pending.delete(id);
      clearTimeout(waiting.timer);
      if (frame.t === 'refuse') noteLink(live, waiting.kind, frame.code, 'node');
      if (frame.t === 'res' && frame.body !== null
          && Buffer.byteLength(frame.body, 'utf8') > FLEET_LINK_MAX_RESPONSE_BYTES) {
        waiting.settle(refusal('body_too_large', `${live.label} answered with more than the link carries`, id));
        return;
      }
      waiting.settle(frame);
      return;
    }
    // hello arrives once, before this handler is installed; welcome and req
    // travel the other way.
    try { live.ws.send(encodeLinkFrame(refusal('bad_frame', 'that frame travels the other way on this link'))); } catch { /* going away */ }
    void tearDown(live, 'that node sent a frame a hub never receives');
  }

  // ── Pairing ────────────────────────────────────────────────────────────
  //
  // A pairing session is not a link session and shares nothing with one but
  // the endpoint. It binds no listener, carries no request, and holds one
  // row in memory until it is approved, refused, or its code runs out.

  function stopPairKeepalive(p: Pairing): void {
    if (p.keepalive) { clearInterval(p.keepalive); p.keepalive = null; }
  }

  /** Hold the socket open across the operator's decision. See
   *  FLEET_PAIR_KEEPALIVE_MS for why a pairing needs this and a link does
   *  not. Every exit from a pairing runs through dropPairing or
   *  lingerPairing, and both stop it. */
  function armPairKeepalive(p: Pairing): void {
    if (!p.ws.ping) return;
    p.alive = true;
    p.keepalive = setInterval(() => {
      if (p.closed) { stopPairKeepalive(p); return; }
      // The prior ping went unanswered, so the node is gone (#315). A ping
      // does not throw on a half-open socket, so this liveness check is the
      // only thing that ends a row whose node vanished without a clean
      // close; without it the row sat "waiting, Approve" until the code ran
      // out. The same shape server.ts uses for the browser WS: ping, and
      // terminate if the previous one was not ponged.
      if (p.alive === false) {
        lingerPairing(p, 'refused', 'the node stopped answering, so it has gone; nothing was registered');
        return;
      }
      p.alive = false;
      try { p.ws.ping?.(); } catch {
        lingerPairing(p, 'refused', 'the node went away before it was approved, so nothing was registered');
      }
    }, deps.pairKeepaliveMs ?? FLEET_PAIR_KEEPALIVE_MS);
    p.keepalive.unref?.();
  }

  function dropPairing(p: Pairing, reason: string, stage?: PairingStage): void {
    if (p.timer) { clearTimeout(p.timer); p.timer = null; }
    stopPairKeepalive(p);
    if (stage) { p.stage = stage; p.note = reason; }
    p.closed = true;
    try { p.ws.close(); } catch { /* already gone */ }
    pairings.delete(p.id);
    log(`[fleet-link] pairing ${p.label}: ${reason}`);
  }

  /** Keep a finished row on the page for a moment, then forget it. The
   *  socket goes now; only the row lingers. */
  function lingerPairing(p: Pairing, stage: PairingStage, note: string): void {
    if (p.timer) { clearTimeout(p.timer); p.timer = null; }
    stopPairKeepalive(p);
    p.stage = stage;
    p.note = note + p.cut_note + p.self_row_tail;
    try { p.ws.close(); } catch { /* already gone */ }
    p.timer = setTimeout(() => { pairings.delete(p.id); }, PAIRING_LINGER_MS);
    p.timer.unref?.();
  }

  function armPairingExpiry(p: Pairing): void {
    const left = p.expires_at_ms - now();
    p.timer = setTimeout(() => {
      if (p.closed) return;
      // Expires with its CODE. A code presented at minute fourteen gets a
      // one-minute row, which is the ADR's "a Pending row expires with its
      // code" read literally and the right reading: the window the operator
      // agreed to is the one they started.
      try {
        p.ws.send(encodeLinkFrame(refusal('unauthenticated', 'that pairing code has run out')));
      } catch { /* going anyway */ }
      dropPairing(p, 'the code ran out before an administrator approved it', 'refused');
    }, Math.max(1_000, left));
    p.timer.unref?.();
  }

  /**
   * #626: why a known node's move cannot be offered, or null when its proof
   * verifies. Re-finds the tunnel row in a FRESH fleet.yaml read (a reload
   * since the hello is judged now, not then), reads that row's token copy,
   * and checks the MAC over the hub_nonce this hub kept, the node's own
   * challenge nonce from the hello, the node key and the trust key this hub
   * sent. Constant time. The token is held for the length of this call and
   * goes nowhere else.
   */
  function knownMoveRefusal(p: Pairing, label: string, proof: string | undefined): string | null {
    if (proof === undefined) {
      return 'this node sent none: its Aperire is older than that proof. Update Aperire on that node, then mint '
        + 'a new code and pair again.';
    }
    const pinned = (deps.fleetNodes?.() ?? []).filter(
      (n) => n.role !== 'aggregator' && n.expected_pubkey_node === p.pubkey_node,
    );
    const row = pinned.length === 1 && pinned[0].label === label && pinned[0].transport !== 'link' ? pinned[0] : null;
    if (!row) {
      return `this aggregator's fleet.yaml changed while the row waited, so ${label} is no longer the one tunnel `
        + 'row with that node key. Mint a new code and pair again.';
    }
    if (!p.hub_nonce || !p.sent_trust) {
      return 'this aggregator kept nothing to check the proof against. Mint a new code and pair again.';
    }
    const token = deps.readTokenFile?.(row.token_path) ?? null;
    if (!token) {
      return `this aggregator could not read its own copy of that token (the token_path on ${label}'s row in `
        + 'fleet.yaml), so it had nothing to check the proof against. That is this host to fix, then pair again.';
    }
    const ok = fleetKnownNodeProofMatches({
      readToken: token, hubNonce: p.hub_nonce, challengeNonce: p.nonce,
      pubkeyNode: p.pubkey_node, fleetTrustPubkey: p.sent_trust,
    }, proof);
    if (ok) return null;
    // #626 review, L2: the sentence is chosen by what this aggregator's own
    // tunnel read shows, never by anything the caller says. Advice to
    // replace a token is given only where the tunnel itself refuses the one
    // held: a code holder with a public key and a junk proof must not be
    // able to talk an administrator into installing a token they choose.
    const tunnel = deps.tunnelAuth?.(label) ?? { kind: 'unknown' as const };
    if (tunnel.kind === 'answering') {
      return `the proof this node sent does not match, and ${label} is answering this aggregator over its tunnel `
        + `with the token held for it right now. So the node calling in does not hold ${label}'s token: it is not `
        + `${label}. Don't change any token because of this request.`;
    }
    if (tunnel.kind === 'refused') {
      return `the proof this node sent does not match, and ${label} is also refusing this aggregator's token over `
        + `its tunnel (HTTP ${tunnel.status}), which is what a reinstall looks like. Confirm the reinstall on `
        + `${label}'s own console before you replace anything. Only then put its new read token where ${label}'s `
        + 'row points, and pair again.';
    }
    return `the proof this node sent does not match, and this aggregator can't read ${label} over its tunnel right `
      + `now, so it can't tell a reinstall from a different machine. Get the tunnel answering, then pair again. `
      + "Don't replace any token on the caller's word.";
  }

  function onPairFrame(p: Pairing, raw: string): void {
    if (p.closed) return;
    const parsed = parseLinkFrame(raw);
    if (!parsed.ok) {
      try { p.ws.send(encodeLinkFrame(refusal(parsed.code, parsed.detail))); } catch { /* going */ }
      dropPairing(p, parsed.detail, 'refused');
      return;
    }
    const frame = parsed.frame;

    if (frame.t === 'pair_checked') {
      // Only as the answer to keys this hub sent, once, before approval.
      // Anything else is a frame this pairing never asked for, and it costs
      // the sender its own row and nothing else.
      if (p.sent_arm === null || p.check !== 'waiting_at_node' || p.stage !== 'waiting') {
        try {
          p.ws.send(encodeLinkFrame(refusal('bad_frame', 'this pairing asked for no fingerprint check')));
        } catch { /* going */ }
        dropPairing(p, `that node sent a fingerprint check this aggregator did not ask for (check ${p.check}, stage ${p.stage})`, 'refused');
        return;
      }
      if (frame.matched) {
        // A signal, never trust (see PairChecked). It unlocks Approve on
        // THIS row only; the operator still compares the node key, and the
        // node still refuses a welcome whose keys are not the ones it
        // checked.
        p.check = 'matched';
        log(`[fleet-link] pairing ${p.label}: the node says its operator's fingerprint matches this aggregator's keys`);
        if (!p.known_label) {
          // #624: a reconnect row keeps its own sentence, as a known row does.
          if (!p.reconnect_label) p.note = PAIR_NOTE_MATCHED;
          return;
        }
        // #626: a known node's move is offered only on a proof. Checked here,
        // once, against what THIS hub kept and read: never the token, never
        // a nonce, from the frame.
        const why = knownMoveRefusal(p, p.known_label, frame.tunnel_proof);
        if (why) {
          try { p.ws.send(encodeLinkFrame(refusal('unauthenticated', KNOWN_WIRE_REFUSAL))); } catch { /* going */ }
          log(`[fleet-link] pairing ${p.label}: refused the move of "${p.known_label}", `
            + `${frame.tunnel_proof === undefined ? 'the node sent no tunnel proof' : 'its tunnel proof did not verify'} (#626)`);
          lingerPairing(p, 'refused', knownRefused(p.known_label, why));
          return;
        }
        p.move_proof = 'verified';
        p.note = knownNoteVerified(p.known_label, p.known_aside);
        log(`[fleet-link] pairing ${p.label}: the node proved it holds the read token "${p.known_label}" is read with (#626)`);
        return;
      }
      p.check = 'mismatch';
      // #850 review, L3: the trust key can be read fresh here (the arm key
      // cannot without root). When it moved since pair_keys went out, that
      // is the cause, and the operator is told so rather than sent to look
      // for an impostor.
      const trustNow = deps.fleetTrustPubKey?.() ?? null;
      const keysChanged = trustNow !== p.sent_trust;
      log(`[fleet-link] pairing ${p.label}: refused at the node, the pasted fingerprint does not match this aggregator's keys`
        + (keysChanged ? ' (its fleet trust key changed since the keys were sent)' : ''));
      lingerPairing(p, 'refused', keysChanged ? PAIR_NOTE_MISMATCH_KEYS_CHANGED : PAIR_NOTE_MISMATCH);
      return;
    }

    if (frame.t === 'pair_tokens') {
      if (p.stage !== 'approved' || !p.settle) {
        try {
          p.ws.send(encodeLinkFrame(refusal('bad_frame', 'this pairing has not been approved')));
        } catch { /* going */ }
        dropPairing(p, 'that node sent its tokens before this pairing was approved', 'refused');
        return;
      }
      // #624: the last line before the broker. A link that came up under this
      // name after the approval refuses the row where it connects, and this
      // holds if that ever missed one: a rejoin re-mints the credential, and
      // the reconcile then drops the live link as revoked.
      if (p.reconnect_label && links.has(p.reconnect_label)) {
        const detail = reconnectLive(p.reconnect_label);
        p.settle = null;
        try {
          p.ws.send(encodeLinkFrame({
            t: 'pair_settled', v: FLEET_LINK_PROTOCOL_VERSION, ok: false, error: 'pair_clash', detail,
          }));
        } catch { /* going */ }
        log(`[fleet-link] pairing ${p.label}: refused before registering, "${p.reconnect_label}" is linked (#624)`);
        lingerPairing(p, 'refused', `Refused before registering. ${detail} Nothing was registered.`);
        return;
      }
      const settle = p.settle;
      p.settle = null;
      p.stage = 'settling';
      p.note = 'registering the node';
      void (async () => {
        let outcome: PairSettlement;
        try {
          outcome = await settle({ read_token: frame.read_token, advisor_token: frame.advisor_token });
        } catch (err) {
          // A throw out of the broker call is a failure of THIS host, and it
          // is answered as one rather than escaping a message handler and
          // taking the process with it (#281's lesson, in the new place).
          outcome = {
            ok: false, error: 'broker_failed',
            detail: `this aggregator could not register the node: ${(err as Error).message}`,
          };
        }
        if (p.closed) return;
        if (!outcome.ok) {
          try {
            p.ws.send(encodeLinkFrame({
              t: 'pair_settled', v: FLEET_LINK_PROTOCOL_VERSION, ok: false,
              error: outcome.error, detail: outcome.detail,
            }));
          } catch { /* going */ }
          lingerPairing(p, 'refused', outcome.detail);
          return;
        }
        // #624: the broker wrote. A link that came up under this name while
        // it was in flight is dropped by the re-mint; say so on the row.
        if (p.cut_from) {
          p.cut_note = ` ${p.reconnect_label ?? 'The node'} linked from ${p.cut_from} while this was registering. `
            + 'The new credential replaced its old one, so that link was dropped and that machine has to pair again.';
        }
        // #1057: the broker wrote the node's row and could not write this
        // aggregator's own, so the dashboard holds every link. Said on the
        // row for as long as it lives, and in the log, where it was in none.
        if (outcome.self_row_note) {
          p.self_row_tail = ` ${outcome.self_row_note}`;
          log(`[fleet-link] pairing ${outcome.label}: registered, but ${outcome.self_row_note}`);
        }
        // #1079: the Advisor attachment a rejoin cleared (or could not), said
        // on the same finish line, so the operator sees why Add an Advisor
        // offers the node again, and in the log.
        if (outcome.advisor_note) {
          p.self_row_tail += ` ${outcome.advisor_note}`;
          log(`[fleet-link] pairing ${outcome.label}: ${outcome.advisor_note}`);
        }
        // #741: the arm key this settles with is the one the welcome carried
        // and the operator's paste covered. Root made or read it between the
        // two (a rotation, a restore); signing the new one would hand the node
        // a key nobody compared. Refused here, before anything is signed; the
        // node would refuse it too. The broker has written its row by now, so
        // the sentence says what the recovery is.
        if (outcome.fleet_arm_pubkey !== p.arm_pub) {
          try {
            p.ws.send(encodeLinkFrame({
              t: 'pair_settled', v: FLEET_LINK_PROTOCOL_VERSION, ok: false,
              error: 'arm_key_changed',
              detail: 'this aggregator\u2019s fleet arm key changed between the approval and the registration, '
                + 'so the fingerprint you pasted no longer covers it. Nothing was written on the node. '
                + 'Run the pair command again with a fresh code.',
            }));
          } catch { /* going */ }
          lingerPairing(p, 'refused',
            'registered, but the fleet arm key changed after the approval, so the node installed nothing. Pair it again.');
          return;
        }
        p.label = outcome.label;
        // Signed under the same key as the welcome, one frame ago, which is
        // the key the operator's fingerprint comparison covered (P2-056).
        // The nonce and the node key are in the signed set, so this
        // signature is bound to THIS pairing and cannot be replayed onto
        // another one.
        let settleSig: string | null;
        try {
          settleSig = deps.sign(pairSettledSigningBytes({
            nonce: p.nonce,
            label: outcome.label,
            pubkey_node: p.pubkey_node,
            credential_sha256: createHash('sha256').update(outcome.credential).digest('hex'),
            fleet_arm_pubkey: outcome.fleet_arm_pubkey,
            read_port: outcome.read_port,
            advisor_port: outcome.advisor_port,
          }));
        } catch (err) {
          log(`[fleet-link] pairing ${p.label}: this aggregator could not sign the settlement `
            + `(${(err as Error).message.replace(/\d+/g, 'n')})`);
          settleSig = null;
        }
        if (!settleSig) {
          // The node IS registered at this point: the broker has written.
          // So this is not a rollback, it is a node that must be told to
          // run again rather than handed an artefact it cannot verify.
          try {
            p.ws.send(encodeLinkFrame({
              t: 'pair_settled', v: FLEET_LINK_PROTOCOL_VERSION, ok: false,
              error: 'no_fleet_trust_key',
              detail: 'this aggregator registered the node but cannot sign the answer, '
                + 'so the node has nothing it can verify. Run the pair command again with a fresh code.',
            }));
          } catch { /* going */ }
          lingerPairing(p, 'refused',
            'registered, but this aggregator could not sign the answer, so the node installed nothing');
          return;
        }
        try {
          p.ws.send(encodeLinkFrame({
            t: 'pair_settled', v: FLEET_LINK_PROTOCOL_VERSION, ok: true,
            label: outcome.label, credential: outcome.credential,
            fleet_arm_pubkey: outcome.fleet_arm_pubkey,
            read_port: outcome.read_port, advisor_port: outcome.advisor_port,
            signature: settleSig,
          }));
        } catch (err) {
          // Written, and the node did not hear. Named, because the recovery
          // is the rejoin path and not a rollback.
          p.settled = 'link_closed';
          p.settled_reason = `the node's link closed before it heard: ${(err as Error).message}`;
          lingerPairing(p, 'done',
            `registered, and the node's link closed before it heard: ${(err as Error).message}. `
            + 'Run the pair command again with a fresh code');
          return;
        }
        p.stage = 'done';
        p.settled = 'waiting';
        p.note = 'registered; waiting for the node to write its credential' + p.cut_note + p.self_row_tail;
      })();
      return;
    }

    if (frame.t === 'pair_done') {
      // Only from a pairing this aggregator actually settled (P2-055).
      //
      // This frame's whole job is to put a sentence on the Settings page,
      // and the sentence begins "registered". Accepted at any stage, a
      // caller holding nothing but a valid code could send it straight
      // after the hello and make the row read "registered, and the node
      // wrote its credential", with its own chosen list of files, when this
      // aggregator had written nothing and no administrator had approved
      // anything. approve() then answered `already_started`, so the row
      // could not even be approved afterwards: the operator lost the code
      // and kept a row that lied.
      //
      // `settling` as well as `done` because the socket may deliver this
      // while the broker's answer is still in flight.
      if (p.stage !== 'settling' && p.stage !== 'done') {
        try {
          p.ws.send(encodeLinkFrame(refusal('bad_frame', 'a pairing session serves nothing')));
        } catch { /* going */ }
        dropPairing(p, `that node reported finishing a pairing this aggregator has not settled (stage ${p.stage})`, 'refused');
        return;
      }
      // For the RECORD and for the row's sentence. Nothing this hub does
      // next is decided by it: §3.6's follow-on waits on this hub's own
      // observation that the link is held, so a node that lies here buys a
      // timeout and a row that reads `link` with `never held`.
      //
      // Bounded here as well as in the parser: this is the one node-chosen
      // list that reaches an operator's screen, and a row is not a place to
      // render sixteen 512-character strings.
      p.wrote = frame.wrote.slice(0, 8).map((w) => w.slice(0, 200));
      // #632: the node's own word, as a value. A second pair_done on a row
      // already settled restates it and changes nothing else.
      p.settled = frame.ok ? 'ok' : 'no_credential';
      p.settled_reason = frame.ok ? null : 'the node could not write its credential';
      lingerPairing(p, 'done', frame.ok
        ? 'registered, and the node wrote its credential'
        : 'registered, and the node could not write its credential');
      return;
    }

    // A `ready`, a `hello`, a `req`, a `res` or a second `pair_hello`. A
    // pairing session serves nothing, so there is no frame here that could
    // ask it to: nothing is bound, which is why nothing can be reached.
    try {
      p.ws.send(encodeLinkFrame(refusal('bad_frame', 'a pairing session serves nothing')));
    } catch { /* going */ }
    dropPairing(p, `that node sent a ${frame.t} on a pairing session`, 'refused');
  }

  /**
   * Pairing v2: hand a keys-first node this aggregator's two public keys, so
   * it can compare its operator's paste before anyone approves.
   *
   * Synchronous, and it asks root for nothing. The arm key comes from the
   * process-wide cache the mint filled (an administrator's act), never from
   * the broker on a code holder's dial. A miss sends nothing: the row reads
   * `after_approval` and the node compares at the welcome instead, as an
   * older aggregator would have it do. Neither key is logged: together they
   * are the fingerprint's whole input (#741).
   *
   * What a code holder gets here is two public keys every paired node
   * already holds, and only after presenting a live code that is now spent.
   * See threat row 4 at the top of this file.
   */
  function sendPairKeys(p: Pairing): void {
    const trust = deps.fleetTrustPubKey?.() ?? null;
    const arm = deps.cachedArmPubKey?.() ?? null;
    if (!trust || !isFleetArmPubkey(arm)) {
      log(`[fleet-link] pairing ${p.label}: sent no keys before approval (`
        + `${!trust ? 'this host holds no fleet trust key' : 'no arm key cached since this dashboard started'}`
        + '), so that node checks the fingerprint after approval');
      return;
    }
    // #626: KEPT before it goes out. The known-node proof is checked against
    // this copy, never against a value the node sends back.
    const hubNonce = randomBytes(16).toString('hex');
    p.hub_nonce = hubNonce;
    try {
      p.ws.send(encodeLinkFrame({
        t: 'pair_keys', v: FLEET_LINK_PROTOCOL_VERSION, nonce: p.nonce,
        fleet_trust_pubkey: trust, fleet_arm_pubkey: arm,
        hub_nonce: hubNonce,
      }));
    } catch {
      lingerPairing(p, 'refused', 'the node went away before it was approved, so nothing was registered');
      return;
    }
    p.sent_trust = trust;
    p.sent_arm = arm;
    p.check = 'waiting_at_node';
    // A known row keeps its own note: it is the warning an operator must
    // read before a move, and the check state rides beside it.
    if (!p.known_label && !p.reconnect_label) p.note = PAIR_NOTE_WAITING_AT_NODE;
  }

  function acceptPairing(
    req: IncomingMessage, socket: Duplex, head: Buffer, rateKey: string, address: string,
  ): void {
    let settled = false;
    const upgrade = deps.upgradePairing ?? deps.upgrade;
    upgrade(req, socket, head, (ws) => {
      // Counted HERE, inside the callback, for the reason the link path
      // gives: ws aborts a malformed handshake without ever invoking this,
      // and a counter incremented outside would leak one slot per aborted
      // socket until the cap refused every pairing until a restart.
      pairingSockets += 1;
      holdPairingSocket(rateKey);
      const helloTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        pairingSockets -= 1;
        releasePairingSocket(rateKey);
        // Counted as a failure so a caller that keeps parking silent
        // sockets fills its own bucket and is refused at the upgrade by
        // overLimit above, rather than being free to re-dial every ten
        // seconds forever (P2-054).
        pairGuard.fail(rateKey);
        log(`[fleet-link] no pairing hello from ${address} within ${FLEET_LINK_HELLO_TIMEOUT_MS}ms, dropping`);
        try { ws.close(); } catch { /* already gone */ }
      }, FLEET_LINK_HELLO_TIMEOUT_MS);

      ws.on('message', (data?: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(helloTimer);
        pairingSockets -= 1;
        // The pre-hello hold goes here; from this point the ROW is what
        // pairingsFromKey counts for this caller, and it carries the same
        // rate key.
        releasePairingSocket(rateKey);

        const parsed = parseLinkFrame(String(data));
        if (!parsed.ok || parsed.frame.t !== 'pair_hello') {
          // A node key this hub cannot pin is refused HERE, by the parser,
          // and the code is NOT spent: `bad_frame` names the node's own
          // problem and the operator fixes it on the node. Separate from the
          // code refusals on purpose.
          const detail = parsed.ok
            ? 'the first frame on a pairing session is a pairing hello'
            : parsed.detail;
          try { ws.send(encodeLinkFrame(refusal(parsed.ok ? 'bad_frame' : parsed.code, detail))); } catch { /* going */ }
          try { ws.close(); } catch { /* already gone */ }
          log(`[fleet-link] refused a pairing from ${address}: ${detail}`);
          return;
        }
        const hello = parsed.frame;

        if (!deps.consumeCode) {
          try { ws.send(encodeLinkFrame(refusal('unauthenticated', CODE_REFUSAL))); } catch { /* going */ }
          try { ws.close(); } catch { /* already gone */ }
          log(`[fleet-link] refused a pairing from ${address}: this host takes no pairings`);
          return;
        }

        // The code resolves BEFORE the bucket is consulted, which is #279's
        // ruling applied to the new surface: a valid code is never refused
        // by a bucket somebody else filled. The bucket then decides only
        // WHICH refusal a repeat caller gets.
        const verdict = deps.consumeCode(hello.code, rateKey);
        if (!verdict.ok) {
          const limited = pairGuard.overLimit(rateKey);
          pairGuard.fail(rateKey);
          log(`[fleet-link] refused a pairing from ${address} (${rateKey}): the code was ${verdict.why}`);
          try {
            ws.send(encodeLinkFrame(limited
              ? refusal('rate_limited', 'too many refused pairings from there')
              : refusal('unauthenticated', CODE_REFUSAL)));
          } catch { /* going */ }
          try { ws.close(); } catch { /* already gone */ }
          return;
        }
        pairGuard.succeed(rateKey);

        // One more bound, at the row rather than at the socket: four is the
        // number of pairings this hub holds, however they got here.
        if (pairings.size >= FLEET_LINK_MAX_PAIRINGS) {
          try {
            ws.send(encodeLinkFrame(refusal('rate_limited',
              'this aggregator is already holding as many pairings as it takes')));
          } catch { /* going */ }
          try { ws.close(); } catch { /* already gone */ }
          log(`[fleet-link] refused a pairing from ${address}: ${pairings.size} already held`);
          return;
        }

        // #635: what this row proposes as its name, before #620's own
        // classification ever runs. Three sources, in order -- an operator's
        // typed name (stored with the code at mint, never trusted from the
        // node), then the node's own hello, and #620's "known" answer below
        // still wins over both of them, because a known key's row is never
        // the caller's to rename. `verdict.name` was already validated
        // against LABEL_RE at mint time (settings-api.ts's mintPairing). It
        // may name an existing row (#976): the classification below decides
        // that by the key presented now, which the mint could not.
        // #635 review: kept apart from `proposedLabel` on purpose. The note
        // below has to say WHOSE word is being set aside when a known row
        // wins, and "the name it proposed" is a true sentence about the
        // node's own hello and a false one about a name the operator typed
        // into this dashboard themselves.
        const proposedByOperator = Boolean(verdict.name && verdict.name.length > 0);
        const proposedLabel = proposedByOperator ? (verdict.name as string) : hello.label;

        // #620: judged the moment the code presents, before Approve ever
        // renders. Pure and synchronous, off fleet.yaml alone, plus this
        // hub's own observation of which labels are live right now.
        const classification = classifyPairKey({
          pubkeyNode: hello.pubkey_node,
          proposedLabel,
          fleetNodes: deps.fleetNodes?.() ?? [],
          // #624: held, not only ready. A link that has authenticated and not
          // yet said ready is already this label's link, and a reconnect
          // judged against it would cut it off after a spent passkey.
          isLive: (label) => links.has(label),
          // #624: a link row the registry has let go cannot be rejoined (the
          // broker refuses it after the passkey), so it is a clash up front.
          linkRegistered: (label) => deps.rows().some((r) => r.label === label),
          // #624: a held row never enters the link map, so a node that keeps
          // dialing and being told registry_held reads as offline.
          linkWithheld: (label) => (deps.withheldRows?.() ?? []).some((h) => h.row.label === label),
          proposedByOperator,
        });
        // #635 review: nothing left to say when the name that is set aside
        // already matches the row it moves to -- an operator who typed the
        // known row's own name did not lose anything.
        const knownAside = (classification.kind !== 'known' && classification.kind !== 'reconnect')
          || proposedLabel === classification.label
          ? ''
          : proposedByOperator
            ? ` The name you gave it (${proposedLabel}) is not used.`
            : ` The name it proposed (${proposedLabel}) is ignored.`;
        const p: Pairing = {
          id: randomUUID(),
          label: proposedLabel,
          pubkey_node: hello.pubkey_node,
          // Normalised at the EARLIEST point this aggregator holds the
          // value (#339). A node that does not know its own public address
          // sends no field, and an older node sends one built from its own
          // host name — `https://ubuntu-22.localhost/overview.html` — which
          // is an address only that box can open. Both become null here, so
          // no later step has to know the difference and nothing refuses
          // after a code and a passkey have been spent.
          dashboard_url: pairDashboardUrl(hello.dashboard_url),
          advisor: hello.advisor,
          dashboard_version: hello.dashboard_version,
          advisord_version: hello.advisord_version,
          node_version: hello.node_version,
          rate_key: rateKey,
          first_seen_ms: now(),
          // The code's own window, handed back by the store, clamped to the
          // ceiling this hub can state for itself: a row must not outlive
          // the window the operator agreed to, and a store that answers with
          // a date in 2039 must not be able to park a socket here.
          expires_at_ms: Math.min(verdict.expires_at_ms, now() + FLEET_PAIR_MAX_WINDOW_MS),
          nonce: hello.challenge_nonce,
          ws,
          stage: 'waiting',
          // #620 review (118): the match here is the node KEY, and that key
          // arrives on `pair_hello` unsigned -- a copy of the disk this key
          // came from would present it identically. This note says so and
          // sends the operator to the two things a copy cannot also fake
          // (the node's own terminal, and where the dial came from), rather
          // than asserting the identity this row cannot itself prove.
          // #626: a known row's note says the move is not offered until the
          // node proves it holds the read token this aggregator reads it
          // with. The node KEY arrives unsigned and is public besides (its
          // peers see it, /crawl lists it), so the key match alone is never
          // presented as the node's identity (#620 review, 118).
          note: classification.kind === 'known'
            ? knownNoteWaiting(classification.label, knownAside)
            : classification.kind === 'reconnect'
              ? reconnectNote(classification.label, lastLinkedSentence(classification.label), knownAside)
            : classification.kind === 'clash'
              ? `Refused before approval. ${classification.reason}`
              : 'waiting for an administrator to compare its node key and approve it',
          note_next: null,
          wrote: [],
          known_label: classification.kind === 'known' ? classification.label : null,
          reconnect_label: classification.kind === 'reconnect' ? classification.label : null,
          cut_from: null,
          cut_note: '',
          self_row_tail: '',
          clash_reason: classification.kind === 'clash' ? classification.reason : null,
          settled: null,
          settled_reason: null,
          settle: null,
          arm_pub: null,
          // Exactly `true`: a stranger's `"yes"` or `1` is an older node's
          // hello, never a refusal (F4).
          keys_first: (hello as { keys_first?: unknown }).keys_first === true,
          sent_trust: null,
          sent_arm: null,
          check: 'after_approval',
          hub_nonce: null,
          move_proof: null,
          known_aside: knownAside,
          closed: false,
          timer: null,
          keepalive: null,
          alive: true,
        };
        pairings.set(p.id, p);
        // A clash is refused below, immediately: no code window to hold open
        // and no keepalive to ping a socket about to close.
        if (classification.kind !== 'clash') {
          armPairingExpiry(p);
          armPairKeepalive(p);
        }
        // One line, with the two things an operator needs to recognise it:
        // never the code, which is spent and was never ours to print.
        log(`[fleet-link] a node asked to pair as "${p.label}" from ${rateKey}, node key ${p.pubkey_node}`
          + (classification.kind === 'known' ? `, already known as "${classification.label}"` : '')
          + (classification.kind === 'reconnect' ? `, reconnecting as "${classification.label}" (#624)` : '')
          + (classification.kind === 'clash' ? ', refused at call-in (#620)' : ''));

        ws.on('message', (d?: unknown) => onPairFrame(p, String(d)));
        ws.on('pong', () => { p.alive = true; });
        ws.on('close', () => {
          if (p.closed || pairings.get(p.id) !== p) return;
          // The socket IS the row (ruling, 2026-09-12), refined by #315: a
          // row whose node has gone goes with it, but it LINGERS a moment
          // first, saying so, rather than vanishing under an operator who
          // was mid-decision. Approve is gone the instant the stage is not
          // 'waiting'; the note is what they read. Except once it is
          // finished, where the row is the outcome the operator is reading
          // and the node closes on purpose.
          // #632: registered, the answer went out, and the node closed
          // without saying whether it wrote its credential. Not a failure
          // this hub saw, and not a success either: the pill says neither.
          if (p.stage === 'done' && p.settled === 'waiting') {
            p.settled = 'unconfirmed';
            p.settled_reason = 'the node\u2019s link closed before it said whether it wrote its credential';
            return;
          }
          if (p.stage === 'done' || p.stage === 'refused') return;
          lingerPairing(p, 'refused', 'the node went away before it was approved, so nothing was registered');
        });
        ws.on('error', () => {
          if (p.closed || pairings.get(p.id) !== p) return;
          if (p.stage === 'done' || p.stage === 'refused') return;
          lingerPairing(p, 'refused', 'the node went away before it was approved, so nothing was registered');
        });

        // #620: a clash is refused HERE, at call-in, before an operator ever
        // sees an Approve control for it. The row stays on the page for the
        // same linger every other finished row gets, so "refused, and here
        // is why" is not a row that vanished out from under whoever was
        // reading it.
        //
        // #620 review (122): the wire frame does NOT carry classification's
        // own reason. That text can name another row's label (the C(c) case:
        // "srv12345 is already a row in this fleet...") to whoever is
        // holding the code that reached this refusal, and a code is not an
        // administrator -- it is exactly the kind of caller this reason
        // should not be handed to. The node's terminal gets one generic
        // sentence; the full reason is for the Pending row only, which only
        // an authenticated administrator ever reads.
        if (classification.kind === 'clash') {
          try {
            ws.send(encodeLinkFrame(refusal(
              'label_mismatch',
              'This aggregator refused the pairing before approval. Its administrator can see why on the Settings page.',
            )));
          } catch { /* going */ }
          // The wire refusal is the bare reason, for a terminal that frames
          // it itself; the row's own note carries the same "Refused before
          // approval." prefix it was built with. lingerPairing sets p.note,
          // so it is handed that prefixed text again here rather than the
          // bare reason, or this would overwrite it with an unprefixed copy.
          lingerPairing(p, 'refused', p.note);
        } else {
          // Pairing v2. Never to a clash, which is refused above before it
          // could be handed anything.
          if (p.keys_first) sendPairKeys(p);
          // #626: a known node's move needs the proof, and the proof rides
          // on the answer to `pair_keys`. No keys went out (an older node
          // that never asked, or this aggregator had none to send), so no
          // proof can come back: refused now, before Approve ever renders,
          // the way a clash is. A new node is unaffected.
          if (p.known_label && p.stage === 'waiting' && p.sent_arm === null) {
            const why = p.keys_first
              ? 'this aggregator sent the node no keys to answer with one (it holds no fleet trust key, or this '
                + 'dashboard restarted after the code was minted). Mint a new code and pair again.'
              : 'this node is too old to send one. Update Aperire on that node, then mint a new code and pair again.';
            try { ws.send(encodeLinkFrame(refusal('unauthenticated', KNOWN_WIRE_REFUSAL))); } catch { /* going */ }
            log(`[fleet-link] pairing ${p.label}: refused the move of "${p.known_label}" at call-in, no proof can come `
              + `back (${p.keys_first ? 'no keys were sent' : 'the node did not ask for keys first'}) (#626)`);
            lingerPairing(p, 'refused', knownRefused(p.known_label, why));
          }
        }
      });

      ws.on('close', () => {
        if (settled) return;
        settled = true;
        clearTimeout(helloTimer);
        pairingSockets -= 1;
      });
      ws.on('error', () => {
        if (settled) return;
        settled = true;
        clearTimeout(helloTimer);
        pairingSockets -= 1;
      });
    });
  }

  function handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    // A FIXED base, never the Host header (#287). Only the pathname is read,
    // and a Host value Node accepted but URL refuses would throw here, inside
    // an event handler, and take the process with it. server.ts's upgrade
    // handler carries the same fix and the same reason.
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      refuseSocket(socket, 400, 'Bad Request');
      return;
    }
    const address = req.socket.remoteAddress ?? 'unknown';
    const rateKey = linkRateKey(req.socket.remoteAddress, req.headers['x-forwarded-for']);
    const pairing = req.headers[FLEET_PAIR_HEADER] === '1';
    const decision = gateLinkUpgrade({
      pathname: url.pathname,
      bindHost: deps.bindHost,
      remoteAddress: req.socket.remoteAddress,
      authorization: typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined,
      allowPlaintext: deps.allowPlaintext,
      rows: deps.rows(),
      withheldRows: deps.withheldRows?.() ?? [],
      registryJudgeable: deps.registryJudgeable?.() ?? true,
      pending: pendingHandshakes,
      links: links.size,
      guard,
      rateKey,
      pairing,
      pairings: pairingSockets + pairings.size,
      pairGuard,
      pairingsFromKey: pairingsFromKey(rateKey),
    });
    if (!decision.ok) {
      // Which bucket a refusal is counted in follows which path it was on,
      // so a stranger's refused pairings can never deny the fleet its links.
      if (decision.countAsFailure) (pairing ? pairGuard : guard).fail(rateKey);
      log(decision.message);
      refuseSocket(socket, decision.status, decision.status === 401 ? 'Unauthorized'
        : decision.status === 429 ? 'Too Many Requests'
        : decision.status === 404 ? 'Not Found'
        : decision.status === 503 ? 'Service Unavailable' : 'Forbidden');
      return;
    }

    if (decision.kind === 'pair') {
      acceptPairing(req, socket, head, rateKey, address);
      return;
    }

    const row = decision.row;
    const heldReason = decision.kind === 'held' ? decision.reason : null;
    const heldWire = decision.kind === 'held' ? decision.wire : '';
    let settled = false;
    deps.upgrade(req, socket, head, (ws) => {
      // Counted HERE and not before the upgrade call: ws aborts a malformed
      // handshake without ever invoking this callback, and a counter
      // incremented outside it would leak one per aborted socket until the
      // cap refused every link on the fleet until a restart.
      pendingHandshakes += 1;
      // Nothing is bound and nothing is served until the node has sent a
      // hello this hub can sign for and a ready confirming it verified the
      // signature. The socket holds a pending slot for that long and no
      // longer.
      const helloTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        pendingHandshakes -= 1;
        guard.fail(rateKey);
        log(`[fleet-link] ${row.label}: no hello within ${FLEET_LINK_HELLO_TIMEOUT_MS}ms, dropping`);
        try { ws.close(); } catch { /* already gone */ }
      }, FLEET_LINK_HELLO_TIMEOUT_MS);

      ws.on('message', (data?: unknown) => {
        if (!settled) {
          const parsed = parseLinkFrame(String(data));
          if (!parsed.ok || parsed.frame.t !== 'hello') {
            settled = true;
            clearTimeout(helloTimer);
            pendingHandshakes -= 1;
            guard.fail(rateKey);
            try { ws.send(encodeLinkFrame(refusal('bad_frame', 'the first frame on a link is a hello'))); } catch { /* going */ }
            try { ws.close(); } catch { /* already gone */ }
            return;
          }
          const hello = parsed.frame;
          settled = true;
          clearTimeout(helloTimer);
          pendingHandshakes -= 1;
          if (hello.label !== row.label) {
            // The credential resolved a row; the hello claimed another label.
            // Named separately from `unauthenticated` because it is a
            // MISCONFIGURATION an operator fixes in one file, not an attack:
            // the node's fleet-link.json and the aggregator's fleet-links.json
            // disagree about what this node is called.
            guard.fail(rateKey);
            log(`[fleet-link] refused a link from ${address}: the credential is ${row.label}'s and the hello said ${hello.label}`);
            try { ws.send(encodeLinkFrame(refusal('label_mismatch', 'that credential is registered under a different label'))); } catch { /* going */ }
            try { ws.close(); } catch { /* already gone */ }
            return;
          }
          // #687: a held row goes no further. The credential resolved and the
          // hello named the right label, so this is the node the row is for,
          // and it gets the sentence naming both files instead of silence.
          // guard.succeed() first: the credential was good, and a node
          // retrying a hold it cannot fix must not fill the bucket that
          // refuses everyone else. Nothing is bound and no Live is created,
          // so this socket leaves no trace beyond the log line.
          if (heldReason) {
            guard.succeed(rateKey);
            log(`[fleet-link] ${row.label}: held, not linked. ${heldReason}`);
            // The journal above got the whole reason; the node gets the fixed
            // sentence (#687 review, F3).
            try { ws.send(encodeLinkFrame(refusal('registry_held', heldWire))); } catch { /* going */ }
            try { ws.close(); } catch { /* already gone */ }
            return;
          }
          const challenge = {
            v: FLEET_LINK_PROTOCOL_VERSION,
            issuer_label: FLEET_WRITE_ISSUER_LABEL,
            nonce: hello.challenge_nonce,
            label: row.label,
            pubkey_node: hello.pubkey_node ?? null,
            issued_at: Math.floor(now() / 1000),
          };
          // Guarded, the way lib/fleet-seal.ts:450-459 guards the same call
          // on the same key (#281). signWithSeed THROWS when the stored seed
          // is not 32 bytes (a truncated paste, a wrapped line, a key from
          // another format), and this is inside a WebSocket message handler:
          // the throw escapes it, reaches process.on('uncaughtException') and
          // exits the dashboard. systemd restarts, the node reconnects on
          // backoff, and it exits again. An ordinary node doing an ordinary
          // thing drives a crash loop out of one bad line in a config file.
          //
          // The guard lives HERE and not only in the closure server.ts
          // passes, because a `sign` dependency that throws must never be
          // able to take the process down whoever wrote it. The null path
          // below already refuses by name and closes.
          let signature: string | null;
          try {
            signature = deps.sign(linkChallengeSigningBytes(challenge));
          } catch (err) {
            // The seed's own error can name its length. Not passed on.
            log(`[fleet-link] ${row.label}: this aggregator's fleet trust key is not a usable signing key `
              + `(${(err as Error).message.replace(/\d+/g, 'n')})`);
            signature = null;
          }
          if (!signature) {
            log(`[fleet-link] ${row.label}: this aggregator cannot sign with its fleet trust key, so it cannot prove who it is`);
            try { ws.send(encodeLinkFrame(refusal('bad_signature', 'this aggregator holds no fleet trust signing key'))); } catch { /* going */ }
            try { ws.close(); } catch { /* already gone */ }
            return;
          }
          guard.succeed(rateKey);

          const live: Live = {
            label: row.label, ws, from: rateKey, ready: false, credentialHash: row.credential_sha256,
            servers: [], pending: new Map(), tearing: null, bundleInflight: false, canCancel: false,
          };
          // A node that reconnects REPLACES its link, and the old listeners
          // are torn down and awaited before the new ones bind.
          const existing = links.get(row.label);
          links.set(row.label, live);
          // #624: a pairing waiting (or already approved, its tokens not yet
          // sent) to reconnect this very label was judged "not live" before
          // this link came up. It is refused now, so no further passkey is
          // spent on a rejoin that would cut this link off. A pairing already
          // settling is past recall: its broker call is in flight.
          for (const w of [...pairings.values()]) {
            if (w.reconnect_label === row.label && (w.stage === 'waiting' || w.stage === 'approved')) {
              try { w.ws.send(encodeLinkFrame(refusal('unauthenticated', KNOWN_WIRE_REFUSAL))); } catch { /* going */ }
              log(`[fleet-link] pairing ${w.label}: refused, "${row.label}" linked again while it waited (#624)`);
              lingerPairing(w, 'refused',
                `Refused before ${w.stage === 'approved' ? 'registering' : 'approval'}. ${reconnectLive(row.label)} Nothing was registered.`);
            } else if (w.reconnect_label === row.label && w.stage === 'settling') {
              // Past recall: the broker call is in flight, and its re-mint
              // will drop this link as revoked. Remembered, so the row says so.
              w.cut_from = rateKey;
              log(`[fleet-link] pairing ${w.label}: "${row.label}" linked from ${rateKey} while its reconnect was registering (#624)`);
            }
          }
          const begin = existing
            ? tearDown(existing, 'that node reconnected').then(() => { links.set(row.label, live); })
            : Promise.resolve();
          void begin.then(() => {
            if (links.get(row.label) !== live) return;
            ws.send(encodeLinkFrame({ t: 'welcome', ...challenge, signature }));
          });
          ws.on('message', (d?: unknown) => onFrame(live, String(d)));
          ws.on('close', () => { if (links.get(row.label) === live) void tearDown(live, 'that node closed its link'); });
          ws.on('error', (e?: unknown) => {
            if (links.get(row.label) !== live) return;
            void tearDown(live, `that node's link failed: ${(e as Error | undefined)?.message ?? 'no reason given'}`);
          });
          return;
        }
      });
      ws.on('close', () => {
        if (settled) return;
        settled = true;
        clearTimeout(helloTimer);
        pendingHandshakes -= 1;
      });
      ws.on('error', () => {
        if (settled) return;
        settled = true;
        clearTimeout(helloTimer);
        pendingHandshakes -= 1;
      });
    });
  }

  /**
   * Revocation, and the reason it has to be a verb rather than a state.
   *
   * Deleting a row stops the NEXT dial and nothing else: a node that is
   * already connected has no reason to redial, so without this the credential
   * an operator just revoked keeps serving that node's whole read surface
   * indefinitely. The guide and the runbook both promise otherwise, and a
   * promised control that does not run is worse than one nobody claimed.
   *
   * The refusal is sent by name so the node's agent stops retrying and says
   * so on its own Settings page, rather than dialling a hub that will refuse
   * it every time.
   */
  async function runReconcile(opts: ReconcileOpts = {}): Promise<void> {
    const rows = deps.rows();
    const withheldRows = deps.withheldRows?.() ?? [];
    // #687 review, F1: a pass over NAMED links only. The caller uses it when
    // the registry could not be read and fleet.yaml moved underneath a live
    // link: those links must go, and every other one must be left exactly
    // where it is, because an unreadable registry is not evidence about them.
    const only = opts.onlyLabels ? new Set(opts.onlyLabels) : null;
    // #687: three outcomes, and the CODE is the difference between an
    // operator editing one file and an operator with a shell on every node.
    //   gone from both lists      → revoked, and the node stops for good.
    //   credential re-minted      → revoked, same, and the same as it was.
    //   held                      → registry_held, and the node retries.
    // The row was told `revoked` for all three, which is how one bad row on
    // koi ended twelve minutes of blindness with three manual restarts.
    //
    // The order of the first two matters: a re-mint beats a hold. A row can
    // be held AND carry a new credential (the file was rewritten and the
    // cross-check now fails), and the link in front of this one is holding
    // the OLD credential, which is revoked whatever else is true of its row.
    const doomed: Array<{
      live: Live; reason: string; code: LinkRefusalCode; wire?: string; tombstone?: LinkTombstone | null;
    }> = [];
    for (const live of links.values()) {
      if (only && !only.has(live.label)) continue;
      const row = rows.find((r) => r.label === live.label);
      const withheldRow = withheldRows.find((h) => h.row.label === live.label);
      if (!row && withheldRow && withheldRow.row.credential_sha256 !== live.credentialHash) {
        doomed.push({ live, reason: "that node's link credential was re-minted", code: 'revoked' });
      } else if (!row && withheldRow) {
        doomed.push({ live, reason: withheldRow.reason, code: 'registry_held', wire: withheldRow.wire });
      } else if (!row) {
        // #688: the one branch a tombstone may ride, and only when an
        // operator asked for exactly this at a passkey (expectRevoke). A row
        // that vanished for any other reason is told `revoked` with nothing
        // signed, and that node asks again in an hour.
        doomed.push({
          live, reason: 'that node is no longer in fleet-links.json', code: 'revoked', tombstone: tombstoneFor(live),
        });
      } else if (row.credential_sha256 !== live.credentialHash) {
        doomed.push({ live, reason: "that node's link credential was re-minted", code: 'revoked' });
      } else if (live.ready && readPortOf(live) !== null && readPortOf(live) !== row.read_port) {
        // #687 review, F2: the read listener is bound ONCE, by onReady, and
        // nothing ever moved it. So a row whose read_port changed under the
        // same credential left the old listener serving that node on a port
        // fleet.yaml no longer gives it, and the next row to take that port
        // could never bind it: every poll aimed at the new owner reached the
        // old node, with the new owner's bearer token. Treated like a
        // re-mint, with one difference that is the whole point: the code is
        // NOT final, so the node redials at once and the listener is rebuilt
        // on the port the file now names.
        doomed.push({
          live,
          reason: `that node's read_port moved from ${readPortOf(live)} to ${row.read_port} in `
            + 'fleet-links.json, so its link is being rebound',
          code: 'rebinding',
          wire: 'the aggregator is rebinding this node\'s link because its row changed',
        });
      }
    }
    for (const { live, reason, code, wire, tombstone } of doomed) {
      // `reason` is the journal's, `wire` the node's (#687 review, F3). A
      // revocation has nothing to hide: its sentence says the row is gone,
      // which the node is entitled to know and which names nothing else.
      const frame = { ...refusal(code, wire ?? reason), ...(tombstone ? { tombstone } : {}) };
      if (tombstone) log(`[fleet-link] ${live.label}: revoked at a passkey; sent a signed tombstone with it`);
      try { live.ws.send(encodeLinkFrame(frame)); } catch { /* going away anyway */ }
    }
    await Promise.all(doomed.map(({ live, reason }) => tearDown(live, reason)));

    // #641: a row already carrying a live, ready link can gain or lose an
    // Advisor with no redial at all. Attach and detach both write
    // fleet-links.json in place, the same file this pass already reloaded
    // above. This binds or drops exactly the one advisor-kind listener the
    // fresh row now names, additive or subtractive, and never calls
    // tearDown, never touches the read listener, never touches `live.ws`.
    //
    // A link just queued for tearDown above is skipped: it has no current
    // row to compare against (or one that no longer names its credential),
    // and it is going away regardless. A link whose `ready` frame has not
    // landed yet is skipped too: onReady queues its own reconcile() the
    // instant `ready` flips (#641 High), so there is nothing here for this
    // pass to race it on.
    // A named pass is a surgical drop and nothing else: with no readable
    // registry behind it, this pass must not bind or unbind anything.
    if (only) return;

    const doomedSet = new Set(doomed.map((d) => d.live));
    const candidates: Array<{ live: Live; row: LinkRegistryRow }> = [];
    for (const live of links.values()) {
      if (doomedSet.has(live) || !live.ready) continue;
      const row = rows.find((r) => r.label === live.label);
      if (!row) continue; // paired 1:1 with the doomed check above.
      candidates.push({ live, row });
    }

    // Phase 1: unbind. An entry is dropped when the row no longer names a
    // port at all, OR when it names a DIFFERENT one than what is actually
    // bound. #641 High: checking presence alone (an entry exists, a row
    // names a port) cannot tell a genuine match apart from a port that
    // changed value directly, old to new, with no reload in between where
    // it read as absent; that used to read as "already matching, no rebind
    // churn" and leave the stale port bound forever. Treated exactly like
    // a detach: unbind first, in this phase, before phase 2 below binds
    // anything.
    for (const { live, row } of candidates) {
      const advisorEntry = live.servers.find((s) => s.kind === 'advisor');
      if (advisorEntry && (!row.advisor_port || advisorEntry.port !== row.advisor_port)) {
        await unbindAdvisor(live, advisorEntry);
      }
    }

    // Phase 2: bind. Runs only after EVERY unbind above has finished, so a
    // port that moved from one row to another in this same reload (one node
    // releases it, another takes it) is never a race between "does the new
    // claimant bind first" and "has the old one let go yet": a
    // single interleaved pass would fail the new claimant's bind on
    // EADDRINUSE against the old row's still-live listener and tear that
    // whole (otherwise healthy) link down, paying for another row's rename.
    for (const { live, row } of candidates) {
      if (!row.advisor_port) continue;
      if (live.servers.some((s) => s.kind === 'advisor')) continue; // already matches; phase 1 left it alone.
      try {
        if (!(await bindOne(live, row.advisor_port, 'advisor'))) continue; // stray: bindOne already cleaned it up.
        log(`[fleet-link] ${live.label}: advisor attached, serving 127.0.0.1:${row.advisor_port}`);
      } catch (err) {
        // Same hazard onReady's own bind guards against: a bind failing
        // means something else is already listening on that port, and
        // serving in that state would hand a bearer token to whatever
        // that is. Refused by name so the node's own agent keeps
        // retrying rather than giving up for good (`bind_failed` is not
        // in FLEET_LINK_FATAL_REFUSALS), and the whole link is torn down
        // rather than left half-served.
        const detail = `this aggregator could not bind ${live.label}'s advisor loopback port: ${(err as Error).message}`;
        try { live.ws.send(encodeLinkFrame(refusal('bind_failed', detail))); } catch { /* going away anyway */ }
        await tearDown(live, detail);
      }
    }
    // Row unchanged, or already matching what is bound: no rebind churn.
  }

  // #641: two SIGHUPs close together (an attach followed at once by another
  // verb, or any other double reload) each call reconcile(). Unserialized,
  // both readings can see the same row missing its advisor listener, both
  // start a bind, and the loser hits EADDRINUSE on its own sibling: a
  // failure this module already treats as "something else is on that port"
  // and answers by tearing the whole link down. That is not a hazard the
  // additive bind is supposed to carry, so every call is chained behind
  // whichever one is already running, fulfilled or rejected, rather than
  // let two runs touch the same Live objects at once.
  let reconcileChain: Promise<void> = Promise.resolve();
  function reconcile(opts: ReconcileOpts = {}): Promise<void> {
    const run = reconcileChain.then(() => runReconcile(opts), () => runReconcile(opts));
    // A run that throws must not poison every reconcile() after it: the
    // chain variable always holds a settled-or-pending promise a NEXT call
    // can attach behind, never a rejection nobody is about to catch.
    reconcileChain = run.catch(() => undefined);
    return run;
  }

  return {
    handleUpgrade,
    reconcile,
    expectRevoke(label: string): () => void {
      const row = deps.rows().find((r) => r.label === label)
        ?? deps.withheldRows?.().find((h) => h.row.label === label)?.row;
      if (!row) return () => {};
      const token = Symbol(label);
      expectedRevokes.set(label, { credentialHash: row.credential_sha256, until: now() + LINK_REVOKE_EXPECT_MS, token });
      return () => {
        if (expectedRevokes.get(label)?.token === token) expectedRevokes.delete(label);
      };
    },
    pending(): PairingRow[] {
      return [...pairings.values()]
        .map((p) => ({
          id: p.id,
          label: p.label,
          pubkey_node: p.pubkey_node,
          dashboard_url: p.dashboard_url,
          advisor: p.advisor,
          dashboard_version: p.dashboard_version,
          advisord_version: p.advisord_version,
          node_version: p.node_version,
          dialed_from: p.rate_key,
          first_seen_ms: p.first_seen_ms,
          expires_at_ms: p.expires_at_ms,
          stage: p.stage,
          note: p.note,
          note_next: p.note_next,
          wrote: p.wrote,
          known_label: p.known_label,
          reconnect_label: p.reconnect_label,
          clash_reason: p.clash_reason,
          check: p.check,
          node_asked_first: p.keys_first,
          move_proof: p.move_proof,
          settled: p.settled,
          settled_reason: p.settled_reason,
        }))
        .sort((a, b) => a.first_seen_ms - b.first_seen_ms);
    },
    approve(id, finalLabel, settle, fleetArmPubkey): PairApproveOutcome {
      const p = pairings.get(id);
      if (!p || p.closed) {
        return {
          ok: false, error: 'no_such_pending',
          detail: 'that pairing is not one this dashboard is holding. It expired, it was refused, '
            + 'or this dashboard restarted: a pairing socket cannot survive a restart, so the node runs the command again.',
        };
      }
      if (p.stage !== 'waiting') {
        return { ok: false, error: 'already_started', detail: `that pairing is already ${p.stage}` };
      }
      if (now() >= p.expires_at_ms) {
        dropPairing(p, 'the code ran out before an administrator approved it', 'refused');
        return { ok: false, error: 'expired', detail: 'that pairing code ran out. Mint another and run the command again.' };
      }
      if (!LINK_LABEL_RE.test(finalLabel)) {
        return { ok: false, error: 'bad_label', detail: 'a label must match [a-z0-9-]{1,32}, the same rule fleet.yaml uses' };
      }
      // Pairing v2: keys went out, so the node checks them before anyone
      // approves. Until it says they matched, an approval would spend a
      // passkey on a row its own operator may be about to refuse. Keyed on
      // keys having been SENT, not on the hello's flag: a keys-first node
      // that met a cache miss got none, and checks after approval instead.
      if (p.sent_arm !== null && p.check !== 'matched') {
        return {
          ok: false, error: 'not_checked',
          detail: 'that node has not confirmed this aggregator\u2019s pairing fingerprint yet. Wait for its row to say it matched.',
        };
      }
      // #626: a known node's move only on a verified proof. The row is
      // refused before it could get here in every path that lacks one; this
      // is the line that holds if one of those is ever missed.
      if (p.known_label && p.move_proof !== 'verified') {
        return {
          ok: false, error: 'move_unverified',
          detail: `this node has not proved it holds the read token this aggregator reads ${p.known_label} with, `
            + 'so it is not moved. Nothing was sent.',
        };
      }
      // #620: a known row's label is never the caller's to pick. The browser
      // may only say it approved the move; this checks the move was approved
      // under the label this hub itself found the row at, never one typed
      // or forged into the request.
      if (p.known_label && finalLabel !== p.known_label) {
        return {
          ok: false, error: 'known_label_mismatch',
          detail: `this pairing's node key is already this fleet's "${p.known_label}"; it can only be approved under that name.`,
        };
      }
      // #624: a reconnect row's label is the row's own too, and the broker's
      // rejoin is what it asks for. Under any other name the key is pinned
      // to a different row and the broker refuses it, after the passkey.
      if (p.reconnect_label && finalLabel !== p.reconnect_label) {
        return {
          ok: false, error: 'reconnect_label_mismatch',
          detail: `this pairing's node key is already this fleet's "${p.reconnect_label}"; it can only be reconnected under that name.`,
        };
      }
      const pub = deps.fleetTrustPubKey?.() ?? null;
      if (!pub) {
        return {
          ok: false, error: 'no_fleet_trust_key',
          detail: 'this aggregator holds no fleet trust key, so it cannot prove who it is to a node that has never met it.',
        };
      }
      // #741: no arm key, no welcome. The node now refuses a welcome that
      // carries none, so sending one would spend the operator's passkey on a
      // pairing that can only fail at the other keyboard. Checked through
      // the contract's one rule for what an arm key is, which is the rule the
      // node's fingerprint applies to it.
      if (!isFleetArmPubkey(fleetArmPubkey)) {
        return {
          ok: false, error: 'no_fleet_arm_key',
          detail: 'this aggregator has no usable fleet arm key, so a node has nothing to compare its pairing '
            + 'fingerprint against. Run sudo aperire-fleet-arm --fingerprint here to see why.',
        };
      }
      // Pairing v2: the welcome must carry the keys the node already checked.
      // `fleetArmPubkey` is root's answer from a moment ago and `pub` is read
      // fresh, so a rotation or a restore since `pair_keys` went out shows
      // here. The node would refuse such a welcome after the passkey was
      // spent; this refuses before. The row is finished either way: the
      // paste it holds covers keys this aggregator no longer has.
      if (p.sent_arm !== null && (fleetArmPubkey !== p.sent_arm || pub !== p.sent_trust)) {
        try {
          p.ws.send(encodeLinkFrame(refusal('unauthenticated',
            'this aggregator\u2019s keys changed after this node checked them. Print the fingerprint on the '
              + 'aggregator again and run the pair command with a fresh code.')));
        } catch { /* going anyway */ }
        lingerPairing(p, 'refused',
          'Refused before approval: this aggregator\u2019s keys changed after the node checked them. Nothing was '
            + 'registered. Run the pair command on the node again with a fresh code.');
        return {
          ok: false, error: 'arm_key_changed',
          detail: 'this aggregator\u2019s fleet keys changed after the node checked its fingerprint, so a welcome now '
            + 'would carry keys nobody compared. Nothing was sent. Run the pair command on the node again with a fresh code.',
        };
      }
      const challenge = {
        v: FLEET_LINK_PROTOCOL_VERSION,
        issuer_label: FLEET_WRITE_ISSUER_LABEL,
        // The nonce the hello SENT, remembered on the row. Not re-read from
        // anywhere: an echo is checked against what was sent (#291).
        nonce: p.nonce,
        label: finalLabel,
        pubkey_node: p.pubkey_node,
        fleet_trust_pubkey: pub,
        fleet_arm_pubkey: fleetArmPubkey,
        issued_at: Math.floor(now() / 1000),
      };
      // Guarded exactly as the link challenge is (#281): signWithSeed throws
      // on a seed that is not 32 bytes, and this is reached from a request
      // handler.
      let signature: string | null;
      try {
        signature = deps.sign(pairChallengeSigningBytes(challenge));
      } catch (err) {
        log(`[fleet-link] pairing ${p.label}: this aggregator's fleet trust key is not a usable signing key `
          + `(${(err as Error).message.replace(/\d+/g, 'n')})`);
        signature = null;
      }
      if (!signature) {
        return {
          ok: false, error: 'no_fleet_trust_key',
          detail: 'this aggregator cannot sign with its fleet trust key, so it cannot prove who it is.',
        };
      }
      p.label = finalLabel;
      p.settle = settle;
      p.arm_pub = fleetArmPubkey;
      p.stage = 'approved';
      // #635: the exact sentence the page paints green under the row, and
      // the moment the fingerprint box appears beside it -- the node has
      // just been sent the welcome it is about to print and ask about, so
      // "is now asking" is true the instant this note is written, not a
      // moment later.
      p.note = p.check === 'matched'
        // Pairing v2: the node checked before approval and will not ask
        // again. It holds its tokens until this welcome carries the same
        // keys, which the guard above has just made sure of.
        ? 'Approved. The node checked this aggregator\u2019s keys before approval and is registering now.'
        // A keys-first node that got no keys (a cache miss) took the paste
        // before it dialled, so it compares now without asking anything.
        : p.keys_first
          ? 'Approved. The node is comparing this aggregator\u2019s keys with the fingerprint pasted there before it called in.'
          : 'Approved. The node is now asking you to paste this aggregator\u2019s pairing fingerprint.';
      try {
        p.ws.send(encodeLinkFrame({ t: 'pair_welcome', ...challenge, signature }));
      } catch (err) {
        dropPairing(p, `that node's pairing closed before the answer reached it: ${(err as Error).message}`, 'refused');
        return { ok: false, error: 'node_gone', detail: 'that node is no longer holding its pairing. Run the command again with a fresh code.' };
      }
      log(`[fleet-link] pairing "${finalLabel}": approved, waiting for the node to accept this aggregator's key`);
      return { ok: true };
    },
    annotate(id: string, note: string, next?: { sentence: string; command: string } | null): boolean {
      const p = pairings.get(id);
      if (!p) return false;
      p.note = note + p.cut_note + p.self_row_tail;
      p.note_next = next ?? null;
      // Another linger, so a row does not disappear halfway through the
      // sentence an operator started reading.
      if (p.timer) { clearTimeout(p.timer); p.timer = null; }
      p.timer = setTimeout(() => { pairings.delete(p.id); }, PAIRING_LINGER_MS);
      p.timer.unref?.();
      return true;
    },
    refuse(id: string): boolean {
      const p = pairings.get(id);
      if (!p) return false;
      try {
        p.ws.send(encodeLinkFrame(refusal('unauthenticated',
          'an administrator refused this pairing on the aggregator')));
      } catch { /* going anyway */ }
      dropPairing(p, 'an administrator refused it', 'refused');
      return true;
    },
    inflight(label: string): number | null {
      const live = links.get(label);
      return live ? live.pending.size : null;
    },
    generation(label: string): number {
      return generations.get(label) ?? 0;
    },
    status(label: string): LinkStatus | null {
      const live = links.get(label);
      const held = Boolean(live?.ready);
      const last = lastHeld.get(label) ?? null;
      if (!held && last === null && !lastReason.has(label)) return null;
      return { held, last_held_ms: held ? now() : last, reason: held ? null : (lastReason.get(label) ?? null) };
    },
    async close(): Promise<void> {
      for (const p of [...pairings.values()]) {
        dropPairing(p, 'this aggregator is shutting down', 'refused');
      }
      await Promise.all([...links.values()].map((l) => tearDown(l, 'this aggregator is shutting down')));
    },
  };
}
