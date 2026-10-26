/**
 * The fleet link's wire format — ADR 0019 decision 1.
 *
 * A node's dashboard dials the aggregator's public HTTPS URL, holds one
 * WebSocket, and serves framed requests back down it. The aggregator binds a
 * loopback listener per registered origin at its end, exactly where the SSH
 * forward used to land, so `fleet-registry.ts`'s bare-loopback rule,
 * `fleet-health.ts`, `fleet-fetch-through.ts`, `peer-read-proxy.ts`,
 * `peer-advisor-proxy.ts` and `fleet-write-api.ts` all keep dialling what they
 * already dial. Nothing downstream of the listener knows a link exists.
 *
 * This file is the ONE definition of what crosses. The hub imports it, the
 * agent imports it, and neither holds a private copy of a field name.
 *
 * Versioning follows types/relay-contract.ts's shape (every frame carries a
 * version) and types/read-contract.ts's behaviour on mismatch: a version this
 * side does not speak gets a NAMED refusal frame and never a silent drop. A
 * link is between two dashboards that an operator upgrades separately, so a
 * mismatch is an ordinary state and has to say what it is.
 *
 * What is deliberately NOT here:
 *   - the credential. It rides the upgrade request's `Authorization: Bearer`
 *     header, not a frame, so the aggregator can refuse an unknown one BEFORE
 *     the WebSocket state machine sees anything, the way /ingest already
 *     refuses a bad relay token. A frame-borne credential would mean every
 *     unauthenticated dialer gets an upgraded socket first.
 *   - any route table. The node's allow-list is built in the agent from
 *     READ_ROUTE_NAMES, FLEET_WRITE_ROUTE_NAMES and the advisord paths the
 *     aggregator's own proxies dial. Duplicating them here would create a
 *     second set to drift.
 *   - the event stream. See FLEET_LINK_STREAM_REFUSAL below.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const FLEET_LINK_PROTOCOL_VERSION = 1;

/** The endpoint on the AGGREGATOR. Versioned in the path like /fleet/v1/. */
export const FLEET_LINK_PATH = '/fleet/v1/link';

/** The node-side config file, 0600, that turns the agent on. Absent on a
 *  single-node install, which is why one is unaffected byte for byte. */
export const FLEET_LINK_CONFIG_BASENAME = 'fleet-link.json';

/** The node-side record of a revocation the aggregator signed (#688), 0600,
 *  in the dashboard's data/ directory (the one its unit may write; config/
 *  is read-only under ProtectSystem=strict). Written only by the node's own
 *  agent after the signature verifies; deleted by a welcome, by a re-pair
 *  and by a re-placed credential. See LinkTombstone. */
export const FLEET_LINK_TOMBSTONE_BASENAME = 'fleet-link.tombstone.json';

/** The aggregator-side file naming which nodes may link and where their
 *  loopback listeners bind. Written by ADR 0019 decision 2's root broker at
 *  an approval; hand-placed only for a node nobody can run a command on. */
export const FLEET_LINK_REGISTRY_BASENAME = 'fleet-links.json';

// ── Bounds ───────────────────────────────────────────────────────────────
//
// Every one of these is a cap on what ONE side can make the other spend. The
// aggregator is the party that can be compromised and still hold a valid
// credential (ADR 0019 decision 4, row 1), so the agent enforces all of them
// on what it receives and does not take the hub's word for any of them.

/** Requests in flight on one link. Past it the hub refuses locally rather
 *  than queueing: a queue is an unbounded buffer with a friendlier name. */
export const FLEET_LINK_MAX_INFLIGHT = 16;

/**
 * The most of those sixteen the Advisor may hold, on either end (#831). The
 * rest stay for reads, so a slow advisord cannot take a node's Overview down
 * with it. The hub counts what it is waiting on; the node counts what it is
 * still running, cancelled work included, because a cancelled ask keeps
 * running on the node until it finishes. Both are needed: the hub frees an
 * abandoned slot at once, so only the node knows how much Advisor work is
 * really still going.
 */
export const FLEET_LINK_ADVISOR_MAX_INFLIGHT = 12;

/** The largest request body the agent will forward to a local dial. The
 *  biggest real one is a seal job (FLEET_WRITE_MAX_BODY_BYTES, 16 KiB) and
 *  the next is a question typed by a human. */
export const FLEET_LINK_MAX_REQUEST_BYTES = 256 * 1024;

/** The largest response body the agent will send back. A whole advisord
 *  transcript is static JSON, and peer-advisor-proxy.ts already caps its own
 *  read at the same 4 MiB. */
export const FLEET_LINK_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/**
 * The one route with a cap of its own — the fleet knowledge push (#289).
 *
 * A knowledge bundle is a base64 tar.gz of the corpus, and advisord takes
 * 8 MiB of it (advisor/cmd/aperire-advisord/knowledge_bundle.go:44). Capping
 * it at 256 KiB here would make the link carry 3% of what the node accepts on
 * a tunnel, which is a link that is not sufficient for a fleet node — and a
 * fleet node that still needs a per-node login is the thing ADR 0019 exists
 * to remove.
 *
 * So the bound is the node's own, and it is a bound, not an absence of one.
 * Everything else stays at 256 KiB, because widening the general cap for one
 * route would hand every other route thirty-two times the memory it needs.
 *
 * CHUNKING WAS REFUSED. Splitting a bundle across frames needs a reassembly
 * buffer on the receiving side, which is a new place for a compromised
 * aggregator to spend a node's memory, for a route whose payload changes
 * a few times a year.
 */
export const FLEET_LINK_MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
export const FLEET_LINK_BUNDLE_PATH = '/v1/knowledge/bundle';

/**
 * The largest WebSocket message either end accepts.
 *
 * One bundle frame, with room for the framing. The body rides as a JSON
 * string INSIDE a JSON frame, so every quote in it is escaped a second time;
 * the bundle is base64 and escapes almost nothing, and the manifest's file
 * list is the part that does, at roughly four quotes per file. 2 MiB of
 * headroom covers a corpus of tens of thousands of files and is still a
 * number a single frame can be allowed to reach.
 */
export const FLEET_LINK_MAX_FRAME_BYTES = FLEET_LINK_MAX_BUNDLE_BYTES + 2 * 1024 * 1024;

/**
 * How large a body this exact request may carry.
 *
 * A function and not a table lookup at the call site, because BOTH ends
 * enforce it — the hub before it frames a body and the node before it
 * forwards one — and two copies of the same `if` is how they drift apart.
 */
export function linkRequestCap(target: LinkTarget, method: string, pathname: string): number {
  if (target === 'advisor' && method === 'POST' && pathname === FLEET_LINK_BUNDLE_PATH) {
    return FLEET_LINK_MAX_BUNDLE_BYTES;
  }
  return FLEET_LINK_MAX_REQUEST_BYTES;
}

/** Is this the one route that may be large? The in-flight guard is keyed on
 *  it: one bundle per link at a time, on either side, so the worst case is
 *  one 8 MiB frame per linked node and never two. */
export function isLinkBundleRequest(target: LinkTarget, method: string, pathname: string): boolean {
  return target === 'advisor' && method === 'POST' && pathname === FLEET_LINK_BUNDLE_PATH;
}

/** Headers carried in either direction: count and total bytes. Small on
 *  purpose. What actually crosses is an authorization header, a content-type
 *  and a content-length. */
export const FLEET_LINK_MAX_HEADERS = 24;
export const FLEET_LINK_MAX_HEADER_BYTES = 8 * 1024;

/** The longest a hub will wait for one response frame before it answers its
 *  own loopback caller with a gateway timeout. Above ASK_TIMEOUT_MS (300s in
 *  peer-advisor-proxy.ts) on purpose: a question that the aggregator is still
 *  waiting on must not be killed by the transport underneath it. */
export const FLEET_LINK_REQUEST_TIMEOUT_MS = 310_000;

/** Reconnect backoff on the node: first delay, cap, and the jitter fraction.
 *  Capped at a minute by ADR 0019 decision 1's Reconnect row. */
export const FLEET_LINK_BACKOFF_MIN_MS = 1_000;
export const FLEET_LINK_BACKOFF_MAX_MS = 60_000;
export const FLEET_LINK_BACKOFF_JITTER = 0.25;

/**
 * How long a refused node waits before it asks again (#688, ruled
 * 2026-09-29, option A).
 *
 * A refusal by name used to be the end: the agent set itself stopped and
 * nothing but a restart of that node's dashboard cleared it. Every node on
 * the lab needed exactly that on 2026-09-27, after an aggregator bug told
 * healthy nodes `revoked`. Now a refused node dials once an hour. The
 * aggregator still decides: a node it really revoked is answered 401 again
 * and goes back to the hour, and one it refused in error relinks on its own.
 *
 * One dial an hour is not the tight retry loop against a public endpoint
 * that the Reconnect row was written to stop, and a node holding a signed
 * tombstone (LinkTombstone) does not dial at all once it is refused again.
 */
export const FLEET_LINK_REPROBE_MS = 60 * 60 * 1000;

/** After a probe that met a transient answer (a 429, a 503, a refused
 *  connection), how many short backoff retries before going back to the
 *  hour. The hub admits eight handshakes at a time, so a fleet-wide false
 *  refusal met by every node's probe at once would otherwise drain at eight
 *  nodes an hour; a few seconds' retry lets the rest in within minutes. */
export const FLEET_LINK_PROBE_SHORT_RETRIES = 4;

/** How often a node stopped on `no_aggregator_pinned` reads its own trust file
 *  to see whether the pin has arrived (#1183). A local read: no connection is
 *  made and nothing is sent while the file holds no key. */
export const FLEET_LINK_PIN_WATCH_MS = 15_000;

/** The one fatal code a node does not re-probe (#688 review, L4). */
export const FLEET_LINK_NO_REPROBE: ReadonlySet<LinkRefusalCode> = new Set<LinkRefusalCode>([
  'no_aggregator_pinned',
]);

/** How long the hub waits for a hello after an upgrade before it drops the
 *  socket. An unauthenticated handshake holds a slot, so it holds it briefly. */
export const FLEET_LINK_HELLO_TIMEOUT_MS = 10_000;

// ── The handshake ────────────────────────────────────────────────────────

/**
 * First frame, node → aggregator, immediately after the upgrade.
 *
 * `challenge_nonce` is minted by the NODE, not the aggregator, and that is
 * the whole anti-replay property: the node names bytes nobody has signed yet,
 * so a captured (challenge, signature) pair from an earlier session proves
 * nothing on this one. An aggregator-chosen nonce would be replayable by
 * anyone who recorded one session.
 */
export interface LinkHello {
  t: 'hello';
  v: number;
  /** The label this node believes it is registered under. Advisory: the hub
   *  resolves the row from the CREDENTIAL, and refuses when the two disagree,
   *  because a label is a name the caller chose and a credential is not. */
  label: string;
  /** This node's own pubkey_node, as its /read/v1/identity reports it. The
   *  hub echoes it into the signed challenge so the signature is bound to
   *  the host that asked, and the node checks the echo. */
  pubkey_node: string | null;
  /** The node dashboard's version, for the row and for a skew line in a log. */
  dashboard_version: string | null;
  /** 32 hex characters, fresh per connection. */
  challenge_nonce: string;
}

/**
 * Second frame, aggregator → node. The aggregator's answer, signed with the
 * fleet trust key the node has pinned at `peers.aggregator` in its own
 * fleet-trust.yaml (FLEET_WRITE_ISSUER_LABEL).
 *
 * Same key and same algorithm as a seal job: Ed25519 over UTF-8 bytes,
 * signWithSeed / verifyWithPeerKey in lib/trust-bundle.ts. A second scheme
 * here would be a second thing to get wrong, and the node already has to hold
 * this key to accept a seal at all.
 */
export interface LinkWelcome {
  t: 'welcome';
  v: number;
  /** Which peers.<label> on the node verifies this. Always the literal
   *  FLEET_WRITE_ISSUER_LABEL today; carried so a refusal can name it. */
  issuer_label: string;
  /** The nonce from the hello, echoed. */
  nonce: string;
  /** The label the hub resolved from the credential. */
  label: string;
  /** The pubkey_node from the hello, echoed. */
  pubkey_node: string | null;
  /** Unix seconds at the hub. */
  issued_at: number;
  /** base64url Ed25519 over linkChallengeSigningBytes(). */
  signature: string;
}

/**
 * Third frame, node → aggregator: the signature verified, the node will now
 * serve. The hub binds its loopback listeners on THIS frame and not on the
 * welcome, so a listener never exists for a node that refused the aggregator.
 */
export interface LinkReady {
  t: 'ready';
  v: number;
  /**
   * What this node's agent can do beyond v1's floor (#831). Optional, and
   * the whole compatibility story rides on that:
   *   - an older HUB rebuilds a ready frame from `t` and `v` alone (the
   *     parser's `case 'ready'` before #831), so it never sees this and
   *     never sends anything the node would have to understand;
   *   - an older NODE sends no list, so a newer hub reads "nothing extra"
   *     and sends it nothing new. It must not: an agent meets a frame type
   *     it does not know with bad_frame and drops the link.
   * A malformed list, or a name this side does not know, is dropped and
   * never a bad frame, the way a tombstone that does not parse is. A newer
   * agent advertising more must not cost it the link.
   */
  caps?: LinkCapability[];
}

/** Capabilities a node may advertise in its ready frame. A closed set on
 *  the receiving side: names outside it are dropped at parse. */
export type LinkCapability = 'cancel';
export const LINK_CAPABILITIES: readonly LinkCapability[] = ['cancel'];

/**
 * Aggregator to node: stop working on this request, nobody is waiting for
 * the answer any more (#831).
 *
 * Sent only to a node whose ready frame listed `cancel`. The hub's own
 * caller (a proxy that timed out, a browser that went away) has gone, and
 * before this the request kept its link slot until the node answered or 310
 * seconds passed, so a few seconds of a slow node while the browser kept
 * retrying filled all sixteen slots and every read after that was refused.
 *
 * What it asks of the node: send nothing back for that id. What it does
 * NOT do: stop the local work or free the node's own slot early. The node
 * counts a request until its local fetch has settled on its own, because
 * the cap is the bound that survives a compromised aggregator, and a
 * request-then-cancel loop must not buy unbounded local work. Aborting the
 * fetch would not stop a handler that ignores its caller going away; it
 * would only hide that handler from the count.
 *
 * No version bump, for the reason the pairing frames were added at v1 (plan
 * D3): a bump refuses every established link the instant one side updates.
 */
export interface LinkCancel {
  t: 'cancel';
  v: number;
  id: string;
}


// ── Pairing (ADR 0019 phase 3) ───────────────────────────────────────────
//
// A node that is not registered yet dials the SAME endpoint and holds it for
// one exchange. It carries no credential, because it has none: it carries a
// one-time code an admin minted on the aggregator, and what the exchange
// buys it is a row an operator has to approve under a passkey.
//
// Five new frame types at v1 rather than a version bump, and that is a
// deliberate trade (plan D3). A bump would refuse every established link at
// the instant the aggregator updates, which is a fleet outage for a feature
// nobody has used yet. Nothing here changes LINK_CHALLENGE_SIGNED_FIELDS, so
// the bytes an existing link signs are untouched. What it costs is that a
// pair command meeting an OLD hub gets `bad_frame` ("the first frame on a
// link is a hello") rather than a sentence naming the skew — so the command
// prints that mapping itself.
//
// Pairing v2 adds two more the same way, and gates both so neither side ever
// meets one it would refuse: `pair_keys` goes only to a hello that carried
// `keys_first`, and `pair_checked` comes only from a node that received
// `pair_keys`.

/** The header that says which kind of session this is, BEFORE anything is
 *  decided. A dialer sending neither this nor an Authorization header is a
 *  scanner and gets the 401 it gets today, not a pairing slot: keying the
 *  discriminator on the ABSENCE of a credential would put every bare probe
 *  on the pairing path. Lower-cased, the way node:http delivers it. */
export const FLEET_PAIR_HEADER = 'x-aperire-pairing';

/** Concurrent pairing sessions, across all callers. Its own counter and its
 *  own small cap, kept out of the link path's `pending` on purpose: that
 *  counter's property is "only a credentialled socket holds a slot", and a
 *  pairing session has no credential. Four sockets for ten seconds is the
 *  whole of the new surface. */
export const FLEET_LINK_MAX_PAIRINGS = 4;

/** The longest a Pending row may live, whatever the code store says. The row
 *  expires with its CODE, which is fifteen minutes from the MINT and not
 *  from the hello — so a code presented at minute fourteen gets a
 *  one-minute row. This is the ceiling the hub clamps to, so a store that
 *  hands back a date in 2039 cannot park a socket here forever. */
export const FLEET_PAIR_MAX_WINDOW_MS = 15 * 60 * 1000;

/** The most pre-hello pairing sockets one rate key may hold at once.
 *
 *  The four-slot cap is a bound on what this aggregator carries; it is not a
 *  bound on any one caller, and before this a single address could hold all
 *  four by opening sockets and sending nothing, re-dialling every ten
 *  seconds for the cost of four TCP connections (P2-054). An operator trying
 *  to add a node during that window could not, and the sentence they got
 *  named a condition rather than a cause.
 *
 *  Two, not one: an operator re-running the pair command after a refusal
 *  should not meet their own previous socket, and a node behind the same NAT
 *  as another is a real arrangement. */
export const FLEET_PAIR_MAX_PER_KEY = 2;

/** The most a pairing frame may be, and the reason it is its own number.
 *
 *  The pairing socket used to be served by the same WebSocketServer as the
 *  link, whose maxPayload is FLEET_LINK_MAX_FRAME_BYTES (10 MiB) because a
 *  link carries knowledge bundles. That let an UNAUTHENTICATED caller buffer
 *  10 MiB and make this process JSON.parse it, four at a time. Every pairing
 *  frame is bounded by the five caps below and fits in single-digit KiB;
 *  64 KiB is room for a protocol that grows without being a lever. */
export const FLEET_PAIR_MAX_FRAME_BYTES = 64 * 1024;

/** How often the aggregator pings a pairing socket that is waiting.
 *
 *  A pairing session carries NOTHING on the wire between the hello and the
 *  welcome: the operator is walking to another machine, comparing a
 *  fingerprint and touching a passkey, which is minutes. A steady-state link
 *  never idles (the fleet poll crosses it every couple of seconds) so it has
 *  never needed one of these, but a pairing can sit silent for the whole
 *  fifteen. Anything between the two hosts that ages an idle connection
 *  therefore closes it: a reverse proxy's read timeout defaults to 60s in
 *  nginx, and a stateful firewall drops an idle flow on its own schedule.
 *  The node would print "the aggregator closed the connection without
 *  finishing the exchange" and the operator would have no way to know it was
 *  a timer rather than a refusal.
 *
 *  25s because it has to be under the shortest of those defaults with room
 *  to lose one. The ping travels from the aggregator, which is the direction
 *  a proxy's read timeout watches, and the node's library answers it with a
 *  pong that resets the other direction. */
export const FLEET_PAIR_KEEPALIVE_MS = 25_000;

/** Bounds on what a pairing frame may carry. Each is a cap on what an
 *  UNAUTHENTICATED caller can make the aggregator hold. */
export const FLEET_PAIR_MAX_CODE_CHARS = 64;
export const FLEET_PAIR_MAX_URL_CHARS = 512;
export const FLEET_PAIR_MAX_KEY_CHARS = 128;
export const FLEET_PAIR_MAX_TOKEN_CHARS = 512;
export const FLEET_PAIR_MAX_VERSION_CHARS = 64;

/** A node key, base58 starting with `n`. The same shape
 *  lib/fleet-registry.ts's NODE_KEY_RE holds, re-declared here because this
 *  file is the wire and depends on nothing — and both are one line. The
 *  broker declares it a third time in bash, and §3.7's test drives one
 *  near-miss set through all of them. */
export const PAIR_NODE_KEY_RE = /^n[1-9A-HJ-NP-Za-km-z]{20,60}$/;
/** Crockford base32 and the dashes the page prints. The aggregator
 *  normalises what arrives; this only refuses what could never be a code. */
export const PAIR_CODE_RE = /^[0-9A-Za-z-]{1,64}$/;

/**
 * First frame, node → aggregator, on a pairing session.
 *
 * The code rides HERE and not in the upgrade header, which is the one
 * asymmetry with a link session and the reason is worth keeping: a code is
 * one-time and it is shown to a human. Consuming it before the upgrade
 * completes would spend it on a connection that may never send a frame, and
 * a code burnt by a dropped TCP connection is an operator running the whole
 * thing again with nothing anywhere saying why.
 *
 * `pubkey_node` is NOT nullable here, unlike LinkHello. A row with no node
 * key cannot be pinned, lib/fleet-seal.ts refuses an unpinned node by name,
 * and lib/fleet-registry.ts fails the whole file closed on a malformed pin —
 * so a Pending row with no key is a row nobody can approve into anything
 * useful. The primary refusal is on the NODE, in the pair command, which can
 * say "this node's rippled has not answered yet" before a byte crosses.
 */
export interface PairHello {
  t: 'pair_hello';
  v: number;
  /** As the operator typed it. Normalised on the aggregator. */
  code: string;
  /** Proposed, never authoritative: the aggregator refuses a collision and
   *  the node prints what it was actually given. */
  label: string;
  pubkey_node: string;
  /** Where an operator reaches THIS node's own dashboard, and the one field
   *  in this frame the node may not know (#339).
   *
   *  Absent when the node's `public_url` is still the shipped default, or
   *  names a loopback address, or resolves to a `.localhost` name. A fresh
   *  box is exactly that box: the install asks for `public_url` as its
   *  closing step, so at pairing time the value is the default, and this
   *  used to be built from the host's own FQDN instead. That produced rows
   *  reading `https://ubuntu-22.localhost/overview.html`, an address nobody
   *  anywhere can open. Saying nothing is the honest answer; a node that
   *  later sets a real `public_url` re-pairs and sends it then.
   *
   *  Optional on the WIRE, not merely nullable: a node still running the
   *  old build sends the field, and pairing has to keep working for it —
   *  the aggregator normalises the value it gets with pairDashboardUrl()
   *  rather than refusing the frame. */
  dashboard_url?: string;
  /** Does this node run an advisord? Decides whether the row gets an
   *  advisor_origin at all, and both halves of that pair are written
   *  together or not at all (fleet-registry fails closed on half of one). */
  advisor: boolean;
  dashboard_version: string | null;
  advisord_version: string | null;
  /** The xrpld build, for the row and for a skew line. */
  node_version: string | null;
  /** 32 hex, minted by the NODE. Same anti-replay property as a link
   *  hello's: the node names bytes nobody has signed yet. */
  challenge_nonce: string;
  /**
   * Pairing v2: this node holds the operator's pasted fingerprint already
   * and can check the aggregator's keys before anyone approves, so send
   * `pair_keys` first.
   *
   * Optional, and that is the whole compatibility story, the same shape as
   * LinkReady.caps (#831):
   *   - an older HUB never reads it. Its parser hands a pair_hello through
   *     with every field it carried, so the flag reaches it harmlessly and it
   *     answers the way it always has, with the welcome after approval;
   *   - an older NODE never sends it, so a newer hub never sends it
   *     `pair_keys`, a frame its parser would refuse as unknown.
   * A hub honours it only when it is exactly `true`, and never refuses a
   * hello over it. No version bump: a bump would refuse every older node.
   */
  keys_first?: true;
}

/**
 * Pairing v2, aggregator → node, right after the code was consumed and only
 * to a hello that carried `keys_first: true`. The aggregator's two public
 * keys, so the node can compare the fingerprint its operator pasted BEFORE
 * an administrator spends a passkey on the row.
 *
 * Unsigned on purpose. Both keys are public, and every node already paired
 * to this aggregator holds both. What proves possession is unchanged: the
 * signed welcome must carry these same two keys, byte for byte, and verify
 * under this trust key, or the node sends no token. A forged frame gains
 * nothing: either the paste does not match it, or the welcome does not.
 *
 * Sent only to a socket that presented a live code, which is already spent.
 * Never before the code: an unauthenticated caller must not make the
 * dashboard reach root's broker, or link two hostnames to one aggregator by
 * its keys.
 */
export interface PairKeys {
  t: 'pair_keys';
  v: number;
  /** The hello's challenge nonce, echoed. */
  nonce: string;
  /** base64url, the welcome's encoding and the welcome's parse rules. */
  fleet_trust_pubkey: string;
  /** Plain base64, the welcome's encoding and the welcome's parse rules. */
  fleet_arm_pubkey: string;
  /** 32 hex the hub minted, fresh for this frame. The known-node proof
   *  (#626) is a MAC over it, and the hub checks that MAC against the copy
   *  it KEPT when it sent this frame, never against anything the node sends
   *  back. A proof from an earlier pairing carries an earlier nonce. */
  hub_nonce: string;
}

/**
 * Pairing v2, node → aggregator, the answer to `pair_keys`. Sent only by a
 * node that received one, so an older hub never sees it.
 *
 * A SIGNAL, never trust. A hostile code holder can send `matched: true`
 * without checking anything, and all it unlocks is Approve on its own row,
 * which the operator still compares by node key. The comparison that
 * matters runs on the node, and the node holds its tokens until the signed
 * welcome carries the keys it checked.
 */
export interface PairChecked {
  t: 'pair_checked';
  v: number;
  matched: boolean;
  /**
   * #626: fleetKnownNodeProof() below, 64 lowercase hex. The node holds the
   * read token this aggregator already reads it with, if it is a node this
   * aggregator already watches over an SSH tunnel.
   *
   * Sent only with `matched: true`, and computed only after the match: the
   * MAC goes only to an aggregator whose keys root vouched for. Never the
   * token itself. Optional on the wire, and that is the compatibility:
   *   - a node older than #626 sends none. A hub that needs one (a known
   *     node's move) refuses the move by name; any other row is unaffected;
   *   - a hub older than #626 rebuilds this frame field by field and drops
   *     it, so a newer node costs it nothing.
   */
  tunnel_proof?: string;
}

/**
 * Second frame, aggregator → node, sent only after an admin has approved.
 *
 * This is the TOFU moment, and it is the reason `fleet_trust_pubkey` is in
 * the frame: the node has no prior anchor for this aggregator, so it
 * verifies the signature against the key carried BESIDE it. That proves
 * possession of the private half and nothing about identity. What supplies
 * the identity is the operator, standing at both ends, comparing the
 * fingerprint the command prints against the one Settings shows.
 */
export interface PairWelcome {
  t: 'pair_welcome';
  v: number;
  issuer_label: string;
  /** Echoed from the hello. */
  nonce: string;
  /** The label the operator settled on, which may not be the one proposed. */
  label: string;
  /** Echoed from the hello. */
  pubkey_node: string;
  /** The aggregator's fleet trust PUBLIC key. Not a secret.
   *
   *  base64URL, because that is how fleet-trust.yaml stores a key and what
   *  lib/trust-bundle.ts's verifyWithPeerKey takes. The fleet ARM key in
   *  `pair_settled` below is plain base64, because that is what
   *  install-model-key-sealer.sh --trust-arm-key accepts. Two keys, two
   *  encodings, and the difference is named here because nothing about
   *  either field's name says which. */
  fleet_trust_pubkey: string;
  /** The aggregator's fleet ARM public key, plain base64 of the raw 32
   *  bytes, the encoding install-model-key-sealer.sh --trust-arm-key takes
   *  (#741). In the WELCOME, and signed there, so the operator's one
   *  comparison covers it before this node sends a token: the pairing
   *  fingerprint (fleetPairingFingerprint below) is over this key AND the
   *  trust key, and its only reference is printed by root on the aggregator.
   *  The settlement carries the same key again and the node refuses one that
   *  differs. Required: a node that would be handed no arm key is refused. */
  fleet_arm_pubkey: string;
  issued_at: number;
  /** base64url Ed25519 over pairChallengeSigningBytes(). */
  signature: string;
}

/**
 * Third frame, node → aggregator: the signature verified against the key it
 * carried, and the operator accepted the fingerprint.
 *
 * The two tokens are the only secrets that travel node → aggregator in this
 * whole phase, and they travel inside TLS on a channel the aggregator has
 * just proved it holds the fleet key for.
 */
export interface PairTokens {
  t: 'pair_tokens';
  v: number;
  read_token: string;
  advisor_token: string | null;
}

/**
 * Fourth frame, aggregator → node: what the broker wrote, or why it refused.
 *
 * One frame with an `ok` discriminator rather than a settled frame and a
 * refusal frame, because a refusal HERE is not a refusal of the link: the
 * socket stays up long enough for the node to print the reason, and the
 * reason is one the operator acts on (a label that collides, a pin that
 * collides, a port pool with nothing free).
 */
export type PairSettled =
  | {
    t: 'pair_settled';
    v: number;
    ok: true;
    /** The label the row was actually written under. */
    label: string;
    /** The link credential, minted by the aggregator, 32 random bytes. The
     *  aggregator keeps only its SHA-256, so this plaintext exists on the
     *  aggregator for the length of one frame and on the node in a 0600
     *  file. It never reaches the broker. */
    credential: string;
    /** The aggregator's fleet ARM public key, plain base64 of the raw 32
     *  bytes, exactly what install-model-key-sealer.sh --trust-arm-key takes.
     *  Public. Null when the aggregator has no arm key yet: making one is
     *  aperire-fleet-arm.sh's job and never an approval's, so the node skips
     *  that artefact and says so rather than being handed something invented. */
    fleet_arm_pubkey: string | null;
    read_port: number;
    advisor_port: number | null;
    /** Signed by the SAME fleet trust key that signed the welcome, over
     *  pairSettledSigningBytes. The operator compared that key's fingerprint
     *  one frame ago; without this, the comparison covers the welcome and
     *  not the frame carrying the two artefacts the node installs as root
     *  (P2-056). */
    signature: string;
  }
  | { t: 'pair_settled'; v: number; ok: false; error: string; detail: string };

/** Fifth frame, node → aggregator: the artefacts are on disk. What it
 *  reports is for the RECORD and for the page's sentence; nothing the
 *  aggregator does next is decided by it (§3.6 waits on its own observation
 *  of the link instead, because a node that lies here must not be able to
 *  drive a trust push). */
export interface PairDone {
  t: 'pair_done';
  v: number;
  ok: boolean;
  wrote: string[];
}

// ── The multiplexed request ──────────────────────────────────────────────

/**
 * Which local service the node dials. Three names because the aggregator
 * already has three proxies, not because the node has three ports: `read`
 * and `fleet` are both this node's own dashboard, `advisor` is its advisord.
 * The agent maps a target to a port; nothing off the wire ever names a port.
 */
export type LinkTarget = 'read' | 'advisor' | 'fleet';

export const LINK_TARGETS: readonly LinkTarget[] = ['read', 'advisor', 'fleet'];

/** Aggregator → node. One request, one id, one response. */
export interface LinkRequest {
  t: 'req';
  v: number;
  /** Unique on this link for as long as the request is in flight. */
  id: string;
  target: LinkTarget;
  method: string;
  /** Path and query, as the aggregator's own proxy built it. The agent parses
   *  it to a ROUTE NAME and rebuilds the URL from the name; it never dials a
   *  string that came off the wire. */
  path: string;
  headers: Record<string, string>;
  /** UTF-8. Null for a request with no body. */
  body: string | null;
}

/** Node → aggregator. */
export interface LinkResponse {
  t: 'res';
  v: number;
  id: string;
  status: number;
  headers: Record<string, string>;
  body: string | null;
}

// ── Refusals ─────────────────────────────────────────────────────────────

/**
 * Every way either end says no, named. A closed set for the same reason
 * FleetWriteErrorCode is one: "your credential is unknown" and "this node
 * does not serve that route" send an operator to two different files.
 */
export type LinkRefusalCode =
  // Handshake, aggregator → node.
  | 'protocol_version_unsupported'
  | 'unauthenticated'   // the credential is not one this aggregator knows
  | 'revoked'           // it was, and is not any more
  | 'registry_held'     // the credential is still good; this row is held (#687)
  | 'rebinding'         // the row's ports moved; redial and they are rebound (#687)
  | 'label_mismatch'    // the credential's row is not the label that was claimed
  | 'rate_limited'
  | 'too_many_links'
  | 'bind_failed'       // the loopback listener could not be bound
  // Handshake, node → aggregator.
  | 'bad_signature'     // the welcome was not signed by the pinned key
  | 'no_aggregator_pinned'
  // Per request, node → aggregator.
  | 'not_allowed'       // outside the node's allow-list. The audit row's reason
  | 'stream_not_supported'
  | 'body_too_large'
  | 'concurrency_cap'
  | 'upstream_unreachable'
  | 'upstream_timeout'
  // Either end, any time.
  | 'bad_frame'
  | 'link_not_ready';

export interface LinkRefusal {
  t: 'refuse';
  v: number;
  /** Present when this refuses one request; absent when it refuses the link. */
  id?: string;
  code: LinkRefusalCode;
  /** One sentence for an operator. Never a credential, never a token, and
   *  never which HALF of a credential check failed. */
  detail?: string;
  /** Only on a `revoked` that an operator asked for at a passkey (#688).
   *  An older node ignores the member, which is the whole of the
   *  compatibility story: it stops exactly as it did before. */
  tombstone?: LinkTombstone;
}

/**
 * A revocation the aggregator signed, so a node can tell a real one from a
 * mistaken one without asking anybody (#688).
 *
 * WHY IT EXISTS. After option A a refused node re-probes hourly. That is the
 * right answer to a false `revoked` and a waste on a true one: a node an
 * operator removed on purpose would dial a public endpoint once an hour
 * forever. The tombstone is how the aggregator says "this one was meant",
 * and a node that holds a valid one stops for good.
 *
 * WHO MAKES ONE. In the code, only the passkey-gated Revoke on the Settings
 * page, and only for the link whose credential it is revoking. A reload, a
 * reconcile, a re-minted credential or a held row never produce one, because
 * those are exactly the paths #687's false `revoked` came from: a tombstone
 * minted there would turn the next bug of that kind from an hour's outage
 * into a permanent one.
 *
 * That is a property of the code path, not of the cryptography. The signing
 * seed is read by the aggregator's dashboard account (server.ts's `sign`),
 * so an attacker holding that account can sign a tombstone for any node it
 * has a credential hash for, with no passkey. What that buys is every node
 * stopped for good until it is paired again. Before this existed the same
 * attacker could already stop every node with a bare `revoked` (final on the
 * node, needing a restart there); the difference is a re-pair rather than a
 * restart. Worth knowing, not a new capability.
 *
 * WHAT IT BINDS. The label and the SHA-256 of the link credential, so it is
 * about one credential on one node and nothing else. A re-pair mints a new
 * credential, and a tombstone for the old one no longer matches: it is inert
 * on its own, and the pair command deletes the file besides.
 *
 * WHAT VERIFIES IT. The fleet trust key this node pinned at pairing
 * (`peers.aggregator` in its fleet-trust.yaml), read at the moment of use,
 * offline. Only a holder of the fleet trust seed can sign one: the key
 * that signs every welcome, whose private half is on the aggregator and is
 * readable by its dashboard account (see above).
 *
 * WHY A PIN IN A DASHBOARD-OWNED FILE IS ENOUGH HERE, when #726 refused the
 * same pin as the anchor for an arm key. A tombstone can only make this node
 * STOP dialling. The dashboard account can already do that by deleting
 * fleet-link.json, so whoever can swap the pin gains nothing a forged
 * tombstone would give them. An arm key is the opposite kind of artefact: it
 * grants a capability, so its anchor must be one the dashboard cannot
 * rewrite.
 *
 * HONOURED ONLY BESIDE A FRESH REFUSAL. A node never reads its tombstone to
 * decide whether to dial. It dials at start, and whenever a reload finds
 * fleet-link.json changed (a SIGHUP with the file unchanged does nothing),
 * and only when the aggregator refuses it again does a valid tombstone turn
 * the hourly re-probe into a full stop; a welcome deletes it. What it cannot
 * undo on its own: a node that has stopped for good never asks again, so a
 * revoke later reversed by hand without a re-pair (the row put back into
 * fleet-links.json with the old credential hash; the backup set does not
 * carry that file, so a restore does not do this) leaves that node down until
 * its dashboard is restarted, when it dials once and is welcomed.
 */
export interface LinkTombstone {
  v: number;
  issuer_label: string;
  label: string;
  /** Hex SHA-256 of the link credential, never the credential itself. */
  credential_sha256: string;
  /** Milliseconds since the epoch, on the aggregator's clock. */
  issued_at: number;
  /** Ed25519 over linkTombstoneSigningBytes, base64url. */
  signature: string;
}

/** The signed set, and the order IS the contract. Do not reorder. */
export const LINK_TOMBSTONE_SIGNED_FIELDS = [
  'v', 'issuer_label', 'label', 'credential_sha256', 'issued_at',
] as const;

export type LinkTombstoneBody = Omit<LinkTombstone, 'signature'>;

/**
 * The bytes a tombstone's signature covers.
 *
 * The construction every signed frame on this link uses (hex per field,
 * newline separated), under a domain prefix of its own. The welcome, the
 * pairing welcome, the settlement and the fleet records are all signed with
 * the SAME key, so the prefix is what stops a signature made for one of
 * them verifying as a tombstone, and the reverse. A test holds each pair.
 */
export function linkTombstoneSigningBytes(t: LinkTombstoneBody): string {
  const lines = LINK_TOMBSTONE_SIGNED_FIELDS.map((name) => {
    const value = t[name] === null || t[name] === undefined ? '' : String(t[name]);
    return `${name}=${Buffer.from(value, 'utf8').toString('hex')}`;
  });
  return `aperire-fleet-tombstone/${FLEET_LINK_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

const TOMBSTONE_HASH_RE = /^[0-9a-f]{64}$/;
const TOMBSTONE_SIG_RE = /^[A-Za-z0-9_-]{1,200}$/;
const TOMBSTONE_LABEL_RE = /^[a-z0-9-]{1,32}$/;

/**
 * A tombstone's SHAPE, or null. Never throws. The signature is not checked
 * here: that needs the pinned key, and belongs to the node.
 */
export function parseLinkTombstone(raw: unknown): LinkTombstone | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const t = raw as Record<string, unknown>;
  if (t.v !== FLEET_LINK_PROTOCOL_VERSION) return null;
  if (typeof t.issuer_label !== 'string' || !TOMBSTONE_LABEL_RE.test(t.issuer_label)) return null;
  if (typeof t.label !== 'string' || !TOMBSTONE_LABEL_RE.test(t.label)) return null;
  if (typeof t.credential_sha256 !== 'string' || !TOMBSTONE_HASH_RE.test(t.credential_sha256)) return null;
  if (typeof t.issued_at !== 'number' || !Number.isSafeInteger(t.issued_at) || t.issued_at < 0) return null;
  if (typeof t.signature !== 'string' || !TOMBSTONE_SIG_RE.test(t.signature)) return null;
  return {
    v: t.v, issuer_label: t.issuer_label, label: t.label,
    credential_sha256: t.credential_sha256, issued_at: t.issued_at, signature: t.signature,
  };
}

/**
 * The refusals a node must stop retrying on.
 *
 * ADR 0019 decision 1's Reconnect row: a link refused BY NAME stops dialling
 * and says so on the node's own page, rather than hammering an endpoint that
 * is reachable from the internet. Everything else (a hub restarting, a rate
 * limit, a full link table) is transient and keeps its backoff.
 *
 * `registry_held` and `rebinding` are deliberately NOT in this set (#687).
 * The second says the aggregator is closing a link it intends to accept again
 * a second later, because the row's read port moved and the listener is bound
 * at handshake time; a node that stopped on it would have to be restarted to
 * come back to an aggregator that is waiting for it. It says the
 * aggregator still holds this node's credential and is refusing to serve the
 * row until its two registry files agree, which is a condition the operator
 * clears on the aggregator alone. A node that stopped for good on it needed a
 * shell on every box to come back, and that is exactly the outage this code
 * exists to end. An older node that does not know the name reaches the same
 * answer: parseLinkFrame takes any string as a code, the set below does not
 * hold it, so the link drops and retries on backoff. *
 * "Stops" means SLOWS, since #688 (ruled 2026-09-29). A node refused by a
 * code in this set stops its backoff and asks again about once every
 * FLEET_LINK_REPROBE_MS (jittered), and its page keeps the refusal and its
 * reason until a dial is actually welcomed. It stops for good only on a
 * `revoked` or a 401/403 while it holds a tombstone the aggregator signed
 * for this very credential (LinkTombstone). `unauthenticated`,
 * `label_mismatch` and `protocol_version_unsupported` get the hour as well:
 * each can be cleared on the other box (an aggregator upgraded past a
 * protocol version, a row put right) and none should need a shell on the
 * node. `no_aggregator_pinned` does NOT (FLEET_LINK_NO_REPROBE): a node that
 * cannot verify any aggregator must not send its bearer credential to one
 * every hour, so it stays stopped until its pin is placed, and reads its own trust file
 * every FLEET_LINK_PIN_WATCH_MS to notice (#1183), which needs no restart.
 */
export const FLEET_LINK_FATAL_REFUSALS: ReadonlySet<LinkRefusalCode> = new Set<LinkRefusalCode>([
  'unauthenticated',
  'revoked',
  'label_mismatch',
  'protocol_version_unsupported',
  'no_aggregator_pinned',
]);

/**
 * The event stream is refused on a link, by name, and the poll keeps the
 * surface alive.
 *
 * ADR 0013's channel is an SSE body that never ends, and this frame format is
 * one request to one response. Chunked frames would need their own ordering,
 * their own cancel and their own accounting, which is a phase of its own.
 * Refusing is safe here and nowhere else in this file, because the ONLY
 * consumer (lib/peer-stream-proxy.ts) reports an open failure to the browser,
 * and overview.html's handlePeerValidationsTickResponse then paints the quorum
 * bar off the 2s poll it never stopped running. The bar steps instead of
 * streaming. Nothing goes blank and nothing lies.
 *
 * Both ends refuse it: the hub's listener answers the path without framing it,
 * and the agent's allow-list refuses it again if a frame ever arrives.
 */
export const FLEET_LINK_STREAM_REFUSAL = 'stream_not_supported' as const;

export type LinkFrame =
  | LinkHello | LinkWelcome | LinkReady | LinkCancel | LinkRequest | LinkResponse | LinkRefusal
  | PairHello | PairKeys | PairChecked | PairWelcome | PairTokens | PairSettled | PairDone;

// ── The signed bytes ─────────────────────────────────────────────────────

/**
 * The exact bytes the aggregator signs and the node verifies.
 *
 * Hex-encoded UTF-8 per field, newline separated, with a domain-separating
 * first line — the same construction sealJobSigningBytes() uses, and for the
 * same two reasons. Hex shares no character with the separator, so no value
 * can forge a field boundary; and the prefix names the domain, so a signature
 * made for a seal job can never verify as a link challenge or the reverse.
 * The two schemes share one key, which is exactly when domain separation
 * stops being cosmetic.
 *
 * The field order IS the contract. Do not reorder, and do not add a field
 * without moving FLEET_LINK_PROTOCOL_VERSION.
 */
export const LINK_CHALLENGE_SIGNED_FIELDS = [
  'v', 'issuer_label', 'nonce', 'label', 'pubkey_node', 'issued_at',
] as const;

export interface LinkChallenge {
  v: number;
  issuer_label: string;
  nonce: string;
  label: string;
  pubkey_node: string | null;
  issued_at: number;
}

export function linkChallengeSigningBytes(c: LinkChallenge): string {
  const lines = LINK_CHALLENGE_SIGNED_FIELDS.map((name) => {
    // `pubkey_node` is the one nullable field. An absent key signs as the
    // empty string rather than as the four letters "null", so a node that
    // cannot yet say what its key is cannot be confused with one that calls
    // itself null.
    const value = c[name] === null || c[name] === undefined ? '' : String(c[name]);
    return `${name}=${Buffer.from(value, 'utf8').toString('hex')}`;
  });
  return `aperire-fleet-link/${FLEET_LINK_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

/**
 * The pairing welcome's signed bytes.
 *
 * A DIFFERENT domain prefix from a link challenge, for exactly the reason
 * the link challenge has one: the two share one key, and that is precisely
 * when domain separation stops being cosmetic. A signature made over a
 * pairing welcome must never verify as a link challenge, a seal job or the
 * reverse — and a pairing welcome is the one frame a node verifies with no
 * prior anchor, so it is the one that must be hardest to substitute.
 *
 * `fleet_trust_pubkey` is IN the signed set. The signature already fails if
 * the key is swapped (a swapped key cannot verify a signature it did not
 * make), so this binds it explicitly rather than relying on that: the frame
 * says "this key, these bytes", both under one signature.
 *
 * The field order IS the contract. Do not reorder.
 */
export const PAIR_CHALLENGE_SIGNED_FIELDS = [
  'v', 'issuer_label', 'nonce', 'label', 'pubkey_node', 'fleet_trust_pubkey', 'fleet_arm_pubkey', 'issued_at',
] as const;

export interface PairChallenge {
  v: number;
  issuer_label: string;
  nonce: string;
  label: string;
  pubkey_node: string;
  fleet_trust_pubkey: string;
  /** #741: signed with the trust key, so the pairing fingerprint the
   *  operator pastes covers both keys before a token leaves the node. */
  fleet_arm_pubkey: string;
  issued_at: number;
}

export function pairChallengeSigningBytes(c: PairChallenge): string {
  const lines = PAIR_CHALLENGE_SIGNED_FIELDS.map((name) => {
    const value = c[name] === null || c[name] === undefined ? '' : String(c[name]);
    return `${name}=${Buffer.from(value, 'utf8').toString('hex')}`;
  });
  return `aperire-fleet-pair/${FLEET_LINK_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

/**
 * The settlement's signed set, and the order IS the contract. Do not
 * reorder.
 *
 * Why this exists: the welcome is signed and the settlement was not, so an
 * interceptor who forwarded the honest welcome unchanged (and so passed the
 * operator's fingerprint comparison, because it IS the aggregator's key)
 * could rewrite the frame after it. The node installs `fleet_arm_pubkey` as
 * root, and whoever can rewrite that file can arm the host at will, so the
 * one artefact whose substitution is a durable privileged foothold was the
 * one the ceremony did not cover (P2-056).
 *
 * Two deliberate differences from PAIR_CHALLENGE_SIGNED_FIELDS:
 *
 *   - No `v` and no `issuer_label`. The node bound both in the welcome it
 *     already verified, on the same socket, under the same key. Repeating
 *     them here would sign them twice and prove nothing new.
 *   - `credential_sha256`, not the credential. The signed bytes are written
 *     to no log and no file, but they are still bytes two programs build,
 *     and there is no reason for a permanent secret to be one of them. Both
 *     ends hold the plaintext and hash it.
 *
 * The null collapsing is the challenge helper's rule, reused rather than
 * reinvented: `fleet_arm_pubkey` and `advisor_port` are both nullable, and
 * an aggregator with no arm key must sign bytes the node can rebuild.
 */
export const PAIR_SETTLED_SIGNED_FIELDS = [
  'nonce', 'label', 'pubkey_node', 'credential_sha256', 'fleet_arm_pubkey', 'read_port', 'advisor_port',
] as const;

export interface PairSettledSigned {
  nonce: string;
  label: string;
  pubkey_node: string;
  credential_sha256: string;
  fleet_arm_pubkey: string | null;
  read_port: number;
  advisor_port: number | null;
}

export function pairSettledSigningBytes(s: PairSettledSigned): string {
  const lines = PAIR_SETTLED_SIGNED_FIELDS.map((name) => {
    const value = s[name] === null || s[name] === undefined ? '' : String(s[name]);
    return `${name}=${Buffer.from(value, 'utf8').toString('hex')}`;
  });
  return `aperire-fleet-settle/${FLEET_LINK_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

// ── The pairing fingerprint (#741) ───────────────────────────────────────
//
// ONE value over the two keys a node takes from a pairing: the fleet trust
// key (which signs everything the aggregator sends it) and the fleet arm key
// (which opens a sealing window on it). The operator pastes it at the node,
// and the node compares it exactly against what it computes from the signed
// welcome. Its only reference is printed by ROOT on the aggregator
// (aperire-fleet-arm --fingerprint, and the install's closing summary),
// never by a dashboard: the aggregator's dashboard account is exactly what
// could substitute the arm key, so a value it showed could be substituted
// with it.
//
// Pasted, not read aloud, so it can afford to be long: the whole sha256, 64
// hex. Not 32: the trust half of root's reference is read from
// dashboard/config/fleet-trust.yaml, which the dashboard account can write, so
// a compromised account controls BOTH inputs and needs only a collision
// between two (trust, arm) pairs of its own, and 128 bits of output is a
// 64-bit birthday search (#741 review, L1). 256 bits puts that at 128. A
// typed prefix or a y/N would let a crafted key that matches the first few
// characters through; the whole value is compared, and a prefix is refused.
//
// The bash twin is in scripts/aperire-fleet-arm.sh (fleet_pairing_fingerprint)
// and the two are held together by FLEET_PAIRING_FINGERPRINT_VECTOR, which the
// unit test and scripts/test-seal-model-key.sh both assert.

/** Domain separation: these bytes can never be a hash of anything else this
 *  product hashes, and a v2 can change the construction without ambiguity. */
export const FLEET_PAIRING_FINGERPRINT_DOMAIN = 'aperire-fleet-pairing-fingerprint/2\n';
/** Hex characters of sha256 kept: all of them. /2 in the domain is the
 *  64-character form; /1 was a 32-character prefix and is retired. */
export const FLEET_PAIRING_FINGERPRINT_HEX = 64;

/** One fixed input and its output, asserted by BOTH implementations. The
 *  trust key is 32 bytes of 0x01 (base64url), the arm key 32 bytes of 0x02
 *  (plain base64). Change the construction and this changes with it. */
export const FLEET_PAIRING_FINGERPRINT_VECTOR = {
  trust_b64url: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
  arm_b64: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
  fingerprint: '9dcd79f46b004f208447547884255de43fb4cc32b1fa91c92767b13cc2e13fc7',
} as const;

/** The raw 32 bytes of a key, or null. CANONICAL encodings only: Node's
 *  decoder skips characters it does not know, so "the same key with junk in
 *  it" would decode to the same bytes and a node would then write the junk.
 *  A round trip that does not reproduce the input is refused. */
function rawKey(s: string, enc: 'base64' | 'base64url'): Buffer | null {
  if (typeof s !== 'string' || !s) return null;
  const raw = Buffer.from(s, enc);
  if (raw.length !== 32) return null;
  if (raw.toString(enc) !== s) return null;
  return raw;
}

/** Whether a string is a fleet arm public key a node could take: the
 *  canonical plain base64 of 32 raw bytes. */
export function isFleetArmPubkey(s: unknown): s is string {
  return typeof s === 'string' && rawKey(s, 'base64') !== null;
}

/**
 * The pairing fingerprint: sha256 over the domain, the raw trust key and the
 * raw arm key, all 64 hex. Null when either is not a canonical 32-byte key,
 * which a node treats as a refusal: there is nothing honest to compare.
 */
export function fleetPairingFingerprint(trustB64url: string, armB64: string): string | null {
  const trust = rawKey(trustB64url, 'base64url');
  const arm = rawKey(armB64, 'base64');
  if (!trust || !arm) return null;
  return createHash('sha256')
    .update(Buffer.from(FLEET_PAIRING_FINGERPRINT_DOMAIN, 'utf8'))
    .update(trust)
    .update(arm)
    .digest('hex')
    .slice(0, FLEET_PAIRING_FINGERPRINT_HEX);
}

/**
 * What an operator pasted, compared with what the node computed. Whitespace
 * anywhere and letter case are the only things forgiven, because those are
 * what a terminal copy adds. Root prints the value bare (64 lowercase hex on
 * one line); an aggregator older than that printed it in groups of four, and
 * both spellings match, in either direction of a rolling update. Nothing
 * else: a prefix, a suffix, a label copied with it, or an empty line is a
 * mismatch. Exact equality of the whole value, never startsWith.
 */
export function pairingFingerprintMatches(pasted: string, expected: string | null): boolean {
  if (!expected || !/^[0-9a-f]+$/.test(expected) || expected.length !== FLEET_PAIRING_FINGERPRINT_HEX) return false;
  if (typeof pasted !== 'string') return false;
  const norm = pasted.replace(/\s+/g, '').toLowerCase();
  return norm.length === expected.length && norm === expected;
}

// ── The known-node proof (#626) ──────────────────────────────────────────
//
// A node key matching a tunnel row proves nothing on its own: `pubkey_node`
// is the validator's public key, its peers see it and /crawl lists it. So a
// node that asks to move from its SSH tunnel to the fleet link also proves
// it holds the read token the aggregator already reads it with. The
// aggregator holds a copy of that token (the tunnel row's token_path), so it
// can check the MAC without the token ever crossing.
//
// What it proves: "holds this node's read token". That beats a code holder
// presenting a public node key. It does not beat a copy of the node's disk,
// because the read token is on that disk.
//
// THE BYTES, pinned, because two programs compute them:
//   key      the read token as UTF-8, with every ASCII whitespace character
//            removed (the node's file is read with `tr -d '[:space:]'`; the
//            aggregator's copy with a trim). Empty is refused.
//   message  UTF-8 of the domain line below, then four fields, each the
//            exact string the wire carried, each followed by one "\n":
//              hub_nonce           32 lowercase hex, from pair_keys
//              challenge_nonce     32 lowercase hex, the node's, from pair_hello
//              pubkey_node         as pair_hello carried it
//              fleet_trust_pubkey  base64url, as pair_keys carried it
//            None of the four can hold a "\n" (each is held to its own rule
//            first), so the separator is unambiguous.
//   output   HMAC-SHA256, 64 lowercase hex.
// Binding fleet_trust_pubkey stops a proof meant for this aggregator being
// relayed to another; the two nonces stop a replay; pubkey_node names the
// row it moves.

export const FLEET_KNOWN_PROOF_DOMAIN = 'aperire-fleet-known-proof/1\n';

/** One fixed input and its output. Asserted by the TypeScript test AND by an
 *  independent python3 hmac in scripts/test-fleet-pair.sh, so the two ends
 *  cannot drift together. Change the construction and this changes too. */
export const FLEET_KNOWN_PROOF_VECTOR = {
  read_token: '5f'.repeat(32),
  hub_nonce: 'a1'.repeat(16),
  challenge_nonce: 'b2'.repeat(16),
  pubkey_node: 'n9KVJNZtQZmJ5yxqvxvJbQPEqvhqPxpVMBZTmJxmFhQxTVVVVVVV',
  fleet_trust_pubkey: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
  proof: '07688703b67f9e7b564bdef01aa963db3520e131dc4d39167c8ed2be5e00368f',
} as const;

export const FLEET_KNOWN_PROOF_RE = /^[0-9a-f]{64}$/;

export interface FleetKnownProofInput {
  readToken: string;
  hubNonce: string;
  challengeNonce: string;
  pubkeyNode: string;
  fleetTrustPubkey: string;
}

/**
 * The proof, or null when any input is not what its own rule allows. Null is
 * a refusal on both ends: the node sends nothing, the hub accepts nothing.
 * The token is never returned, logged or thrown.
 */
export function fleetKnownNodeProof(input: FleetKnownProofInput): string | null {
  if (typeof input.readToken !== 'string') return null;
  const key = input.readToken.replace(/[\t\n\v\f\r ]/g, '');
  if (!key || key.length > FLEET_PAIR_MAX_TOKEN_CHARS) return null;
  if (typeof input.hubNonce !== 'string' || !/^[0-9a-f]{32}$/.test(input.hubNonce)) return null;
  if (typeof input.challengeNonce !== 'string' || !/^[0-9a-f]{32}$/.test(input.challengeNonce)) return null;
  if (typeof input.pubkeyNode !== 'string' || !PAIR_NODE_KEY_RE.test(input.pubkeyNode)) return null;
  if (rawKey(input.fleetTrustPubkey, 'base64url') === null) return null;
  return createHmac('sha256', Buffer.from(key, 'utf8'))
    .update(Buffer.from(FLEET_KNOWN_PROOF_DOMAIN, 'utf8'))
    .update(Buffer.from(`${input.hubNonce}\n${input.challengeNonce}\n${input.pubkeyNode}\n${input.fleetTrustPubkey}\n`, 'utf8'))
    .digest('hex');
}

/**
 * Does a presented proof match the one these inputs give? Constant time over
 * the 32 bytes once both are the right shape. False for a missing, malformed
 * or wrong proof, and for inputs fleetKnownNodeProof refuses: there is no
 * way to answer true without the token.
 */
export function fleetKnownNodeProofMatches(input: FleetKnownProofInput, presented: unknown): boolean {
  if (typeof presented !== 'string' || !FLEET_KNOWN_PROOF_RE.test(presented)) return false;
  const expected = fleetKnownNodeProof(input);
  if (!expected) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(presented, 'hex'));
}

/** Four characters at a time: the spelling an older aggregator printed.
 *  Nothing prints it now; the unit test uses it to prove such a paste still
 *  matches. */
export function groupFingerprint(fp: string): string {
  return fp.replace(/(.{4})(?!$)/g, '$1 ');
}

// ── Parsing ──────────────────────────────────────────────────────────────

const NONCE_RE = /^[0-9a-f]{32}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const LINK_LABEL_RE = /^[a-z0-9-]{1,32}$/;

/**
 * Turn one received text frame into a typed one, or name why not.
 *
 * Never throws, for the reason verifyWithPeerKey() gives: a gate that has to
 * catch an exception to refuse is one missing try/catch away from admitting.
 * A frame that fails here is refused before anything looks at its contents.
 */
export type FrameParse =
  | { ok: true; frame: LinkFrame }
  | { ok: false; code: LinkRefusalCode; detail: string };

/** http(s), bounded, and no credentials in it. A dashboard_url is what a
 *  fleet chip click navigates to, so it is rendered into the page: a
 *  `javascript:` or a `data:` here would be this aggregator's own page
 *  opening whatever a stranger with a code chose. */
/** The characters a registry row cannot hold, refused on the RAW string
 *  before it is parsed (P3-062).
 *
 *  WHATWG `new URL` strips tabs and newlines while parsing and the raw
 *  string is what gets stored, so
 *  `isPairUrl('https://node.example/x\n    role: aggregator')` used to
 *  return true. Nothing was written: the broker's own glob refuses the same
 *  characters at the last step. But the ORDER of the refusal was wrong. A
 *  hello carrying a newline became a Pending row, an administrator spent a
 *  passkey approving it, and the broker refused at the end, spending the
 *  code and the approval for a string this parser should never have taken.
 *
 *  The set is the broker's set exactly, which is what makes the two agree:
 *  any whitespace, either quote, and any control character. A literal
 *  equality against `new URL(raw).href` would have been wrong here for a
 *  different reason: it appends a trailing slash to a bare origin, so it
 *  would refuse `https://node.example.internal`, which is legitimate. */
const PAIR_URL_FORBIDDEN = /[\s"']/;

/** Any C0 control or DEL. Written as a code-point test rather than as a
 *  regular expression class: a class holding literal control characters is
 *  the thing `no-control-regex` exists to catch, and a disable comment there
 *  would read as though the characters were an accident. */
function hasControlChar(raw: string): boolean {
  for (let i = 0; i < raw.length; i += 1) {
    const c = raw.charCodeAt(i);
    if (c <= 0x1f || c === 0x7f) return true;
  }
  return false;
}

export function isPairUrl(raw: string): boolean {
  if (raw.length > FLEET_PAIR_MAX_URL_CHARS) return false;
  if (PAIR_URL_FORBIDDEN.test(raw) || hasControlChar(raw)) return false;
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.username || u.password) return false;
  return true;
}

/**
 * An address only the node itself could open — #339.
 *
 * The host, PARSED, never a prefix glob: `http://127.0.0.1.evil.example` is
 * not loopback and `https://localhost.evil.example` is not a `.localhost`
 * name, and a glob says both are (P3-059, which is the same mistake one
 * layer down). `new URL().hostname` has already done the work of deciding
 * where the host ends, so this compares the host and nothing else.
 *
 * The `.localhost` suffix is here because that is what this bug WAS: a box
 * whose FQDN is `ubuntu-22.localhost` produced a row nobody could click.
 * RFC 6761 reserves the whole tree for loopback, so no `.localhost` name is
 * ever an address another machine reaches.
 *
 * Over-matching costs a link an operator has to fix by re-pairing;
 * under-matching leaves the row that started this. Over-matching is
 * cheaper, so `0.0.0.0` and all of 127/8 are in.
 */
export function isLocalOnlyHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === '::1' || h === '0.0.0.0' || h === '::') return true;
  // All of 127/8, not 127.0.0.1 alone: a dashboard bound to 127.0.0.2 is
  // just as unreachable from the aggregator.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

/**
 * The dashboard address a registry row may carry, or null when there is
 * none worth carrying — #339.
 *
 * Null for three different facts and deliberately ONE answer: the node sent
 * no field (a current node that knows it does not know), the node sent
 * something this parser cannot read, or the node sent an address only it
 * could open (an older node, still deriving one from its own host name).
 * All three mean the same thing to a row: this fleet does not know where
 * that node's dashboard is.
 *
 * Never a refusal. The refusal would land on the AGGREGATOR at ingest,
 * which is the one place in this handshake a refusal must not land late:
 * PAIR_URL_FORBIDDEN above records what that costs, and an old node's
 * `.localhost` value would spend a code and an administrator's passkey
 * before anything said why.
 */
export function pairDashboardUrl(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw === '') return null;
  if (!isPairUrl(raw)) return null;
  let u: URL;
  try { u = new URL(raw); } catch { return null; }
  return isLocalOnlyHost(u.hostname) ? null : raw;
}

/** A port the broker could have assigned. The registry parser holds the same
 *  bound; this one refuses a float and a negative before either is printed. */
function isPairPort(raw: unknown): boolean {
  return typeof raw === 'number' && Number.isInteger(raw) && raw >= 1024 && raw <= 65535;
}

/** A public key as a pairing frame may carry it: a bounded, non-empty
 *  string. The welcome and `pair_keys` share this rule, so a key the node
 *  checked early is one the welcome could carry. */
function isPairKeyField(raw: unknown): raw is string {
  return typeof raw === 'string' && raw.length > 0 && raw.length <= FLEET_PAIR_MAX_KEY_CHARS;
}

export function parseLinkFrame(raw: string): FrameParse {
  const bad = (detail: string): FrameParse => ({ ok: false, code: 'bad_frame', detail });
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return bad('that frame did not parse');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return bad('that frame is not an object');
  const f = parsed as Record<string, unknown>;
  if (typeof f.t !== 'string') return bad('that frame names no type');
  if (typeof f.v !== 'number' || !Number.isFinite(f.v)) return bad('that frame carries no version');
  if (f.v !== FLEET_LINK_PROTOCOL_VERSION) {
    return {
      ok: false,
      code: 'protocol_version_unsupported',
      detail: `this side speaks fleet link v${FLEET_LINK_PROTOCOL_VERSION} and that frame is v${f.v}`,
    };
  }
  switch (f.t) {
    case 'hello': {
      if (typeof f.label !== 'string' || !LINK_LABEL_RE.test(f.label)) return bad('the hello names no usable label');
      if (typeof f.challenge_nonce !== 'string' || !NONCE_RE.test(f.challenge_nonce)) {
        return bad('the hello carries no usable challenge nonce');
      }
      if (f.pubkey_node !== null && typeof f.pubkey_node !== 'string') return bad('the hello carries no usable node key');
      if (f.dashboard_version !== null && typeof f.dashboard_version !== 'string') {
        return bad('the hello carries no usable version');
      }
      return { ok: true, frame: f as unknown as LinkHello };
    }
    case 'welcome': {
      if (typeof f.issuer_label !== 'string' || !f.issuer_label) return bad('the welcome names no issuer');
      if (typeof f.nonce !== 'string' || !NONCE_RE.test(f.nonce)) return bad('the welcome echoes no usable nonce');
      if (typeof f.label !== 'string' || !LINK_LABEL_RE.test(f.label)) return bad('the welcome names no usable label');
      if (f.pubkey_node !== null && typeof f.pubkey_node !== 'string') return bad('the welcome carries no usable node key');
      if (typeof f.issued_at !== 'number' || !Number.isFinite(f.issued_at)) return bad('the welcome carries no issue time');
      if (typeof f.signature !== 'string' || !f.signature) return bad('the welcome carries no signature');
      return { ok: true, frame: f as unknown as LinkWelcome };
    }
    case 'ready': {
      // #831: keep only capability names this side knows. Anything else
      // (absent, not an array, a long list, a stranger's name) reads as no
      // capability rather than a bad frame. See LinkReady.caps.
      const caps = Array.isArray(f.caps) && f.caps.length <= 16
        ? LINK_CAPABILITIES.filter((c) => (f.caps as unknown[]).includes(c))
        : [];
      return {
        ok: true,
        frame: { t: 'ready', v: FLEET_LINK_PROTOCOL_VERSION, ...(caps.length ? { caps } : {}) },
      };
    }
    case 'cancel': {
      if (typeof f.id !== 'string' || !ID_RE.test(f.id)) return bad('the cancel carries no usable id');
      return { ok: true, frame: { t: 'cancel', v: FLEET_LINK_PROTOCOL_VERSION, id: f.id } };
    }
    case 'req': {
      if (typeof f.id !== 'string' || !ID_RE.test(f.id)) return bad('the request carries no usable id');
      if (typeof f.target !== 'string' || !LINK_TARGETS.includes(f.target as LinkTarget)) {
        return bad('the request names no known target');
      }
      if (typeof f.method !== 'string' || !/^[A-Z]{3,7}$/.test(f.method)) return bad('the request names no usable method');
      if (typeof f.path !== 'string' || !f.path.startsWith('/') || f.path.length > 2048) {
        return bad('the request carries no usable path');
      }
      const headers = normaliseHeaders(f.headers);
      if (headers === null) return bad('the request carries headers this link does not take');
      if (f.body !== null && typeof f.body !== 'string') return bad('the request carries no usable body');
      return { ok: true, frame: { ...(f as unknown as LinkRequest), headers } };
    }
    case 'res': {
      if (typeof f.id !== 'string' || !ID_RE.test(f.id)) return bad('the response carries no usable id');
      if (typeof f.status !== 'number' || f.status < 100 || f.status > 599) return bad('the response carries no usable status');
      const headers = normaliseHeaders(f.headers);
      if (headers === null) return bad('the response carries headers this link does not take');
      if (f.body !== null && typeof f.body !== 'string') return bad('the response carries no usable body');
      return { ok: true, frame: { ...(f as unknown as LinkResponse), headers } };
    }
    case 'refuse': {
      if (typeof f.code !== 'string') return bad('the refusal names no code');
      if (f.id !== undefined && (typeof f.id !== 'string' || !ID_RE.test(f.id))) return bad('the refusal carries no usable id');
      if (f.detail !== undefined && typeof f.detail !== 'string') return bad('the refusal carries no usable detail');
      // #688: a tombstone that does not parse is DROPPED, never a bad frame.
      // The refusal it rode on is still a refusal and must still be acted on;
      // losing the tombstone only costs this node an hourly re-probe.
      const { tombstone: rawTombstone, ...rest } = f;
      const tombstone = rawTombstone === undefined ? null : parseLinkTombstone(rawTombstone);
      return { ok: true, frame: { ...(rest as unknown as LinkRefusal), ...(tombstone ? { tombstone } : {}) } };
    }
    case 'pair_hello': {
      if (typeof f.code !== 'string' || !PAIR_CODE_RE.test(f.code)) return bad('the pairing hello carries no usable code');
      if (typeof f.label !== 'string' || !LINK_LABEL_RE.test(f.label)) return bad('the pairing hello names no usable label');
      // Not nullable, unlike a link hello's. A node that cannot say what its
      // node key is cannot be pinned, and an unpinned node cannot be sealed.
      if (typeof f.pubkey_node !== 'string' || !PAIR_NODE_KEY_RE.test(f.pubkey_node)) {
        return bad('the pairing hello carries no usable node key');
      }
      // Optional (#339). Absent is a node saying it does not know its own
      // public address, which is a fact and not a fault. Present has to be
      // a URL this side would be willing to hold; whether it is one anybody
      // can OPEN is pairDashboardUrl()'s question, asked at ingest, and its
      // answer is a value rather than a refusal.
      if (f.dashboard_url !== undefined
          && (typeof f.dashboard_url !== 'string' || !isPairUrl(f.dashboard_url))) {
        return bad('the pairing hello carries no usable dashboard address');
      }
      if (typeof f.advisor !== 'boolean') return bad('the pairing hello does not say whether it runs an Advisor');
      for (const k of ['dashboard_version', 'advisord_version', 'node_version'] as const) {
        if (f[k] !== null && (typeof f[k] !== 'string' || (f[k] as string).length > FLEET_PAIR_MAX_VERSION_CHARS)) {
          return bad('the pairing hello carries no usable version');
        }
      }
      if (typeof f.challenge_nonce !== 'string' || !NONCE_RE.test(f.challenge_nonce)) {
        return bad('the pairing hello carries no usable challenge nonce');
      }
      return { ok: true, frame: f as unknown as PairHello };
    }
    case 'pair_welcome': {
      if (typeof f.issuer_label !== 'string' || !f.issuer_label) return bad('the pairing welcome names no issuer');
      if (typeof f.nonce !== 'string' || !NONCE_RE.test(f.nonce)) return bad('the pairing welcome echoes no usable nonce');
      if (typeof f.label !== 'string' || !LINK_LABEL_RE.test(f.label)) return bad('the pairing welcome names no usable label');
      if (typeof f.pubkey_node !== 'string' || !PAIR_NODE_KEY_RE.test(f.pubkey_node)) {
        return bad('the pairing welcome echoes no usable node key');
      }
      if (!isPairKeyField(f.fleet_trust_pubkey)) {
        return bad('the pairing welcome carries no usable fleet trust key');
      }
      // #741. Absent is an aggregator older than the pairing fingerprint, and
      // a welcome without it is refused here rather than paired with half a
      // comparison: the fingerprint the operator pastes covers this key.
      if (!isPairKeyField(f.fleet_arm_pubkey)) {
        return bad('the pairing welcome carries no fleet arm key. That aggregator is older than this node: '
          + 'update it, then pair again');
      }
      if (typeof f.issued_at !== 'number' || !Number.isFinite(f.issued_at)) return bad('the pairing welcome carries no issue time');
      if (typeof f.signature !== 'string' || !f.signature) return bad('the pairing welcome carries no signature');
      return { ok: true, frame: f as unknown as PairWelcome };
    }
    case 'pair_keys': {
      // Pairing v2. The two keys are held to the welcome's own rules, so a
      // value the node checks here is one a welcome could carry. Whether
      // each is a canonical 32-byte key is fleetPairingFingerprint's
      // question, asked by the node before it compares anything.
      if (typeof f.nonce !== 'string' || !NONCE_RE.test(f.nonce)) return bad('the pairing keys echo no usable nonce');
      if (!isPairKeyField(f.fleet_trust_pubkey)) return bad('the pairing keys carry no usable fleet trust key');
      if (!isPairKeyField(f.fleet_arm_pubkey)) return bad('the pairing keys carry no usable fleet arm key');
      if (typeof f.hub_nonce !== 'string' || !NONCE_RE.test(f.hub_nonce)) return bad('the pairing keys carry no usable hub nonce');
      return {
        ok: true,
        frame: {
          t: 'pair_keys', v: FLEET_LINK_PROTOCOL_VERSION, nonce: f.nonce,
          fleet_trust_pubkey: f.fleet_trust_pubkey, fleet_arm_pubkey: f.fleet_arm_pubkey, hub_nonce: f.hub_nonce,
        },
      };
    }
    case 'pair_checked': {
      if (typeof f.matched !== 'boolean') return bad('the pairing check does not say whether it matched');
      // #626. Absent is a node older than the proof, which is a fact and not
      // a fault. Present has to be the shape, and only beside a match: the
      // node computes it only after its operator's paste matched.
      if (f.tunnel_proof !== undefined) {
        if (typeof f.tunnel_proof !== 'string' || !FLEET_KNOWN_PROOF_RE.test(f.tunnel_proof)) {
          return bad('the pairing check carries no usable tunnel proof');
        }
        if (f.matched !== true) return bad('the pairing check carries a tunnel proof without a match');
      }
      // Rebuilt from the fields this side knows, the way a ready frame is
      // (#831): a later node adding a field must not cost it this hub, and
      // nothing it adds reaches anything here. That includes any nonce a
      // node might echo: the proof is checked against the hub's own copy.
      return {
        ok: true,
        frame: {
          t: 'pair_checked', v: FLEET_LINK_PROTOCOL_VERSION, matched: f.matched,
          ...(typeof f.tunnel_proof === 'string' ? { tunnel_proof: f.tunnel_proof } : {}),
        },
      };
    }
    case 'pair_tokens': {
      if (typeof f.read_token !== 'string' || !f.read_token
          || f.read_token.length > FLEET_PAIR_MAX_TOKEN_CHARS) {
        return bad('that frame carries no usable read token');
      }
      if (f.advisor_token !== null && (typeof f.advisor_token !== 'string' || !f.advisor_token
          || (f.advisor_token as string).length > FLEET_PAIR_MAX_TOKEN_CHARS)) {
        return bad('that frame carries no usable advisor token');
      }
      return { ok: true, frame: f as unknown as PairTokens };
    }
    case 'pair_settled': {
      if (typeof f.ok !== 'boolean') return bad('the pairing answer does not say whether it settled');
      if (f.ok === false) {
        if (typeof f.error !== 'string' || !f.error) return bad('the pairing refusal names no error');
        if (typeof f.detail !== 'string') return bad('the pairing refusal carries no usable detail');
        return { ok: true, frame: f as unknown as PairSettled };
      }
      if (typeof f.label !== 'string' || !LINK_LABEL_RE.test(f.label)) return bad('the pairing answer names no usable label');
      if (typeof f.credential !== 'string' || !f.credential
          || f.credential.length > FLEET_PAIR_MAX_TOKEN_CHARS) {
        return bad('the pairing answer carries no usable credential');
      }
      if (f.fleet_arm_pubkey !== null && (typeof f.fleet_arm_pubkey !== 'string'
          || (f.fleet_arm_pubkey as string).length > FLEET_PAIR_MAX_KEY_CHARS)) {
        return bad('the pairing answer carries no usable fleet arm key');
      }
      if (!isPairPort(f.read_port)) return bad('the pairing answer names no usable read port');
      if (f.advisor_port !== null && !isPairPort(f.advisor_port)) {
        return bad('the pairing answer names no usable advisor port');
      }
      // Refused here rather than at the verify: an unsigned settlement is
      // not a settlement this protocol has, and a node that accepted one
      // would be a node an interceptor could strip the signature from.
      if (typeof f.signature !== 'string' || !f.signature
          || (f.signature as string).length > FLEET_PAIR_MAX_KEY_CHARS) {
        return bad('the pairing answer is not signed');
      }
      return { ok: true, frame: f as unknown as PairSettled };
    }
    case 'pair_done': {
      if (typeof f.ok !== 'boolean') return bad('that frame does not say whether it finished');
      if (!Array.isArray(f.wrote) || f.wrote.length > FLEET_LINK_MAX_HEADERS
          || f.wrote.some((w) => typeof w !== 'string' || w.length > FLEET_PAIR_MAX_URL_CHARS)) {
        return bad('that frame carries no usable list of what it wrote');
      }
      return { ok: true, frame: f as unknown as PairDone };
    }
    default:
      return bad(`this side has no frame called "${String(f.t).slice(0, 24)}"`);
  }
}

/**
 * Headers, lower-cased, bounded and stringly typed, or null when they are not
 * headers this link takes. Arrays are refused rather than joined: a header
 * that arrived twice is ambiguous, and the ambiguity is the caller's to
 * resolve before it reaches a gate that reads one of them.
 */
export function normaliseHeaders(raw: unknown): Record<string, string> | null {
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out: Record<string, string> = {};
  let bytes = 0;
  let count = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v !== 'string') return null;
    if (!/^[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(k)) return null;
    // No control characters, which is what stops a header value splitting a
    // response when the hub writes it back onto a real HTTP socket. A SPACE
    // is fine and has to be: `application/json; charset=utf-8` carries one.
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(v)) return null;
    count += 1;
    bytes += k.length + v.length;
    if (count > FLEET_LINK_MAX_HEADERS || bytes > FLEET_LINK_MAX_HEADER_BYTES) return null;
    out[k.toLowerCase()] = v;
  }
  return out;
}

export function encodeLinkFrame(frame: LinkFrame): string {
  return JSON.stringify(frame);
}

export function refusal(code: LinkRefusalCode, detail?: string, id?: string): LinkRefusal {
  return { t: 'refuse', v: FLEET_LINK_PROTOCOL_VERSION, code, ...(detail ? { detail } : {}), ...(id ? { id } : {}) };
}
