/**
 * The dashboard's read contract — ADR 0008.
 *
 * The Advisor reads dashboard data through these routes and never opens the
 * SQLite file. The Go mirror is advisor/internal/dashread/contract.go; the
 * two carry one wire shape and one protocol_version and must be edited
 * together; a mismatch is a named error, never a silent drop. Exactly like
 * relay-contract.ts and relay/contract.go.
 *
 * Versioning follows the relay contract's shape — every response body carries
 * `protocol_version` — but deliberately not its behaviour on mismatch: a
 * version this server does not serve gets a named error body
 * ({ error: "protocol_version_unsupported", server_version, requested_version })
 * rather than a silent drop. A version mismatch between two services on one
 * host is an install problem with an obvious fix, and the operator should be
 * told it in words that name the fix.
 *
 * What is deliberately NOT here, and never will be by v1's rules:
 *   - auth_users / auth_credentials / auth_sessions / auth_magic_links —
 *     ADR 0003's hard exclusion, enforced by the absence of a route.
 *   - ledger_witness / ledger_alarms — the dashboard's independent witness to
 *     the Advisor's action ledger. Withheld for lag, not secrecy: the gap
 *     between the last witnessed count and the ledger's current length is
 *     exactly the window in which a truncation goes undetected, and a reader
 *     of the witness learns precisely how many entries can be cut without
 *     contradiction. (`/api/advisor/ledger-witness` serves this to the
 *     OPERATOR, behind the session gate; the read token must never satisfy
 *     that route.)
 *   - auth_events — who changed who may do what: role changes, credential
 *     enrolment and removal, magic-link issuance, trust-store syncs. Excluded
 *     for the same reason as the auth_* tables it describes, and by the same
 *     mechanism: no route names it. A reader of this table learns which
 *     accounts hold the role that can approve a change to the validator,
 *     which is a map of who to attack.
 *
 * NOTE for anyone adding a table to that list: the list is a COMMENT, and
 * adding to it is not a contract change. READ_PROTOCOL_VERSION moves when the
 * SERVED shape moves — a route added, removed, or altered. Naming something
 * that is deliberately not served alters nothing on the wire, so the Go mirror
 * (advisor/internal/dashread/contract.go) does not change with it.
 */

export const READ_PROTOCOL_VERSION = 1;

/**
 * The route names under /read/v1/. An exact set, not a prefix — a route is
 * served because it is named here, never inherited.
 */
export const READ_ROUTE_NAMES = [
  'history',        // ?metric&range&agg     — bucketed series, same shape as /history
  'recent',         // ?metric&limit         — last raw samples
  'ledgers',        // ?limit  |  ?around&span — recent rows newest-first, or the window centred on an index (ascending)
  'agreement',      // ?since_ms             — per-ledger our_voted (2-day retention, stated in the response)
  'missed-ledgers', // ?limit                — every miss on record with its context
  'alerts',         // ?since_ms&limit       — alert transitions with value/threshold/delivery
  'firing',         //                       — what is firing right now
  'digests',        // ?since_ms&limit       — digest send history
  'bandwidth',      // ?limit                — monthly bandwidth rows, newest first
  'identity',       //                       — this node's identity (pubkey_node, build_version, network)
  'node-status',    //                       — the server_info-derived snapshot, D8 first slice
  'peers',          //                       — the peer-ring summary, D8 first slice
  'validation-summary', //                   — computeAgreementStats() output verbatim, D8 first slice
  'consensus-snapshot', //                   — the Consensus tab's 14 live-value cards, for a peer
  'amendment-ballot',   //                   — the Governance tab's per-amendment ballot table, for a peer
  'governance',         //                   — the rest of the Governance tab: vote stance, publishers, for a peer
  'system',             //                   — the SYSTEM card's CPU/RAM/SWAP/DISK gauges, for a peer
  'net-stats',          //                   — BANDWIDTH LIVE + ERRORS & BUDGET, for a peer
  'validations-tick',   //                   — Overview's "Validations received / quorum" row, for a peer
  'fleet',              //, the fleet roster this dashboard holds, with each node's last answer (#59)
  'node-config',        //, the four allow-listed rippled.cfg settings this host runs (#59)
] as const;

export type ReadRouteName = typeof READ_ROUTE_NAMES[number];

/**
 * The streaming channel — ADR 0013, decision 1.
 *
 * The rule the route array carries, restated here because this is the first
 * member deliberately outside it: **every JSON route in the contract is
 * reachable through the peer-read proxy, and nothing else is.** The stream is
 * a member of the contract and NOT of READ_ROUTE_NAMES, so it gets its own
 * constants rather than a row in that array — lib/peer-read-proxy.ts derives
 * its allowlist from the imported READ_ROUTE_NAMES, and the string 'stream'
 * added there would, with no other edit anywhere, route an event stream
 * through a JSON reader that never sees `done`: a held socket, a
 * `peer_timeout`, and a 20s negative cache on the peer. A silent, wrong,
 * self-inflicted outage that arrives for free the moment the name is added.
 * The reason for the carve-out is a shape mismatch, not a privilege one.
 *
 * Served under the same gate as every JSON route (loopback socket first, then
 * the token, then GET-only, then path shape and protocol_version) — only the
 * final membership test forks, validating the requested channels against
 * READ_STREAM_CHANNELS instead of the route set. An unknown channel is a
 * named 400, never a connection that opens and delivers nothing.
 *
 * Adding this endpoint does not bump protocol_version (the additive-member
 * rule below): a server that does not know the path answers exactly as it
 * always did, `404 unknown_read_path`. The `hello` event carries the version
 * so a client can still assert what it is talking to.
 */
export const READ_STREAM_PATH = '/read/v1/stream';

/**
 * The channels a caller may subscribe to. One, deliberately (ADR 0013,
 * decision 8): stream a channel only when the source changes faster than the
 * poll AND the change itself carries the meaning. `validations_tick` keeps
 * the WS event's UNDERSCORE — the same name the local page already switches
 * on — while the JSON route keeps its hyphen (`validations-tick`). Two
 * transports of one object, each keeping the naming its own side already
 * uses.
 */
export const READ_STREAM_CHANNELS = ['validations_tick'] as const;

export type ReadStreamChannel = typeof READ_STREAM_CHANNELS[number];

/**
 * The `hello` event's data, sent once at connect. An event stream has no
 * response body to extend ReadEnvelope, so this is the envelope's stand-in:
 * a client that does not see `hello` first treats the connection as failed.
 */
export interface ReadStreamHello extends ReadEnvelope {
  channels: ReadStreamChannel[];
}

/**
 * The `validations_tick` event's data — ValidationsTickResponse minus
 * protocol_version, byte-identical to what /read/v1/validations-tick already
 * serves from the same builder (lib/read-payloads.ts's
 * buildValidationsTickFields). Deliberately NOT the nested WS broadcast
 * shape, which carries no quorum: sourcing quorum from a different route on a
 * different cadence would reintroduce, inside this fix, precisely the
 * cross-cadence skew ADR 0013 exists to remove. One object, one moment.
 *
 * No `id:` field on this channel, so the browser never sends Last-Event-ID
 * and the server never replays. A replayed round-progress tick is a stale
 * reading rendered as current.
 */
export type ValidationsTickEvent = Omit<ValidationsTickResponse, 'protocol_version'>;

/**
 * The contract-evolution rule, set by the `ledgers` window (Phase A of the
 * interrogative-loop plan) and applying to every later addition: an OPTIONAL
 * parameter added to an existing route does NOT bump protocol_version,
 * PROVIDED the response echoes it and the client asserts the echo's
 * PRESENCE (never equality — a clamped `span` echoes the applied value, and
 * a clamp is correct behaviour). A missing echo is a named per-read failure
 * on the client ("this dashboard does not serve windowed ledger reads"),
 * never a silently narrower answer. A version bump would darken the whole
 * read surface on a half-upgraded host; the echo rule scopes the failure to
 * the one read that needs the new parameter.
 *
 * `ledgers?around=<index>&span=<n>`: the window
 * [around - floor(span/2), around + floor(span/2)] by ledger_index,
 * ascending. span defaults 21, clamps to 61; the APPLIED span is echoed.
 * Rows exist only for observed ledgers, so `returned` can be smaller than
 * `requested` — the gap is a fact about the record, not an absence of
 * ledgers, and consumers must surface it rather than reason over a window
 * with silent holes.
 */
export interface LedgerWindowResponse extends ReadEnvelope {
  around: number;
  span: number;       // as applied, after clamping
  requested: number;  // == span
  returned: number;   // rows actually present in the window
  ledgers: ReadLedgerRow[];
}

/** One row of the `ledgers` route, both forms. Mirrors db.ts's LedgerRow. */
export interface ReadLedgerRow {
  ledger_index: number;
  close_ts: number;      // rippled epoch seconds (since 2000-01-01)
  close_time: number;    // seconds between this close and the previous
  txn_count: number;
  fam_money: number;
  fam_market: number;
  fam_nft: number;
  fam_accts: number;
}

/**
 * `ledgers?limit`: the OTHER form of the route, pre-dating around/span —
 * newest-first, no window centred on an index. No echo assertion applies
 * here: the server's own cap (500) is the only thing that can narrow the
 * reply, so a shorter-than-asked answer is a legitimate result, not a
 * defect a client must catch by name (contrast LedgerWindowResponse above).
 * Declared for the same reason as the routes below: no served byte change,
 * this is writing down a shape the route already serves.
 */
export interface ReadLedgersLatestResponse extends ReadEnvelope {
  limit: number;
  ledgers: ReadLedgerRow[];
}

/**
 * The remaining routes the interrogative loop's read menu consumes
 * (plan-interrogative-loop §4.1). No served byte changes here — these
 * mirror shapes db.ts and server.ts were already serving; this is writing
 * the shape down on both sides, which is the rule for every mirrored contract
 * here: both sides change together, and a mismatch is a named error.
 */

/** One ledger's local agreement record. Mirrors AgreementRow in db.ts. */
export interface ReadAgreementRow {
  ledger_index: number;
  our_voted: number; // 0 or 1
  ts: number;         // ms
}

/** `agreement?since_ms`. The dashboard prunes this table at two days, so
 *  the response states its own retention rather than the caller assuming
 *  it — a 30-day-old since_ms legitimately comes back with two days of
 *  rows, and that is the table behaving correctly, not a shorter answer. */
export interface AgreementResponse extends ReadEnvelope {
  retention_days: number;
  since_ms: number;
  rows: ReadAgreementRow[];
}

/** One recorded miss, with the node's own context at the moment of the
 *  miss. Mirrors MissedLedgerRow in db.ts. */
export interface ReadMissedLedgerRow {
  ledger_index: number;
  ts: number; // ms
  validations_seen: number | null;
  trusted_unl: number | null;
  peer_count: number | null;
  server_state: string | null;
}

/** `missed-ledgers?limit`. */
export interface MissedLedgersResponse extends ReadEnvelope {
  limit: number;
  missed: ReadMissedLedgerRow[];
}

/** One alert lifecycle transition. Mirrors AlertEvent in db.ts. */
export interface ReadAlertEvent {
  id: number;
  ts: number; // ms
  metric: string;
  severity: 'warn' | 'critical' | 'page';
  state: 'firing' | 'resolved';
  value: number | null;
  threshold_op: string | null;
  threshold_value: number | null;
  duration_s: number | null;
  dedup_key: string;
  channels: string[];
  delivery: Record<string, string>;
  acked_at: number | null;
  muted_until: number | null;
  context: string | null;
}

/** `alerts?since_ms&limit`. */
export interface AlertsResponse extends ReadEnvelope {
  since_ms: number;
  limit: number;
  alerts: ReadAlertEvent[];
}

/** One currently-firing alert. Mirrors FiringStateRow in db.ts — the live
 *  set, not history, which is why the route takes no since_ms. */
export interface ReadFiringStateRow {
  dedup_key: string;
  metric: string;
  severity: 'warn' | 'critical' | 'page';
  triggered_ts: number;
  fired_ts: number;
  last_value: number | null;
  last_seen_ts: number | null;
  threshold_op: string | null;
  threshold_value: number | null;
  duration_s: number | null;
  channels: string[];
  acked_at: number | null;
  muted_until: number | null;
  last_paged_ts: number | null;
}

/** `firing` — no parameters. */
export interface FiringResponse extends ReadEnvelope {
  firing: ReadFiringStateRow[];
}

/**
 * `identity` — no parameters. This node's identity as this dashboard's own
 * snapshot knows it — enough for a fleet peer to detect it is answering for
 * the wrong node (decisions.md D6 addendum, the pubkey-pinning proposal:
 * fleet.yaml's optional `expected_pubkey_node`, checked by fleet-health.ts on
 * every poll of a pinned peer). Values are carried through unchanged from
 * `snapshot.server_info`, not normalised for display — same convention as
 * ReadLedgerRow/AgreementRow above ("the source table's own convention...
 * rather than normalised here"). In particular `build_version` is NOT
 * stripped of its `rippled-` prefix (overview.html strips it client-side for
 * display; server.ts's own version comparisons at line ~3863 compare the raw
 * string, and a normalised contract field would disagree with those), and
 * `network` is the raw `network_id` rippled reports, not the Mainnet/
 * Testnet/Devnet label overview.html derives from it — the label map already
 * exists twice in that file and a third copy inside the contract is exactly
 * the cross-tab-disagreement shape this project keeps re-finding.
 *
 * Adding this ROUTE does not bump protocol_version. Two independent reasons:
 * a server that does not know this route already answers a caller with the
 * named `unknown_read_path` error (never a silent drop, never a differently
 * shaped 200) — ADR 0008's per-read failure contract already covers "this
 * dashboard is older than the client expects" without a version field; and
 * ADR 0010's own follow-ups name the first change that WOULD justify
 * protocol_version 2 as a response-SHAPE change to an EXISTING route (a
 * `node_ledgers` time window), which this is not — a wholly additive route
 * is strictly weaker than the optional-parameter case that rule already
 * covers.
 */
export interface IdentityResponse extends ReadEnvelope {
  pubkey_node: string | null;
  build_version: string | null;
  /**
   * The raw `network_id`, and the one place this contract states what an
   * ABSENT one means — so no consumer reads `null` as "hasn't arrived yet"
   * and codes a retry for a value that will never arrive.
   *
   * rippled emits `network_id` in server_info only when the operator
   * configured one: `if (auto const netid = app_.overlay().networkID())` in
   * NetworkOPs::getServerInfo, where `networkID()` returns
   * `std::optional<std::uint32_t>` seated only from a `[network_id]` stanza
   * (OverlayImpl's setup_Overlay, which also accepts the words `main` /
   * `testnet` / `devnet` for 0 / 1 / 2). So:
   *
   *   - `null` means the field was ABSENT, which means unconfigured, which
   *     is rippled's own default — Mainnet. A permanent per-install fact,
   *     not a transient pre-first-poll gap. (Measured on the lab fleet:
   *     `'network_id' in server_info.result.info === false` on all three
   *     mainnet nodes.)
   *   - `0` means the operator wrote the mainnet id out explicitly. Same
   *     network, different config; both label "Mainnet".
   *   - `1` / `2` are Testnet / Devnet.
   *   - Any OTHER number is a private or parallel network with no name this
   *     dashboard is entitled to invent — render the number. Never fall
   *     back to "Mainnet" for an unrecognised id: only ABSENCE carries
   *     rippled's mainnet default, and calling a private network "Mainnet"
   *     is the exact mistake the NETWORK row exists to catch.
   *
   * The label map itself stays in the client (overview.html's
   * `networkLabelFor`), not here — see this interface's doc comment above
   * on why a third copy of it inside the contract is the wrong shape.
   */
  network: number | null;
}

/**
 * D8 first slice (advisor-enhancement/d8-aggregator-build-plan.md, "the
 * three additive read routes"): the three routes that let a peer node's
 * Overview render from the read API. All additive, all read-only; none
 * bumps protocol_version — the same two reasons IdentityResponse's doc
 * comment gives (an older server answers with the named unknown_read_path
 * error, never a differently-shaped 200; ADR 0010 reserves v2 for a
 * response-SHAPE change to an EXISTING route, which none of these are).
 *
 * `unl_total` and `is_validator` appear on both NodeStatusResponse and
 * ValidationSummaryResponse. They're sourced from the same in-process
 * expressions on the server (snapshot.trusted_unl.size, isValidatorNode()),
 * so within one request they cannot disagree — but a consumer that polls
 * the two routes on separate cadences (the build plan's §"data flow" table:
 * node-status ~5s, validation-summary bundled with it) can observe skew of
 * up to one cadence between them. Treat both as "as of this route's own
 * fetch", never as jointly atomic.
 */

/** Shared by `node-status` and `peers` — whether the node/peer data below
 *  is a live observation or the last one seen before the node stopped
 *  answering (server.ts's nodeReachState(), unchanged shape). */
export interface NodeReachState {
  ok: boolean;
  misses: number;
  last_ok_ms: number;
  unreachable_for_s: number;
}

/** Mirrors the `amendments` broadcast's computed summary (server.ts's
 *  pollFeature, `lastAmendmentsBroadcast`). Absent (null) before the node
 *  has reached a validated ledger even once this process's life — counting
 *  amendments against an unsynced position undercounts pending by ~90 and
 *  corrects itself minutes later with no explanation (see pollFeature's own
 *  comment), so this route withholds the field entirely rather than publish
 *  a count already known to be wrong. */
export interface AmendmentCounts {
  enabled: number;
  supported: number;
  vetoed: number;
  pending: number;
  /** null on a node that reports no per-amendment vote tally at all — the
   *  same distinction ReadAmendmentBallotRow.count carries, applied to the
   *  aggregate. A tracking node cannot tell how close anything is to
   *  threshold, and "0 approaching" is a claim it has no basis to make.
   *  Widened without a protocol_version bump for the same reason: an older
   *  client's `fmtInt(null)` already renders the dash it would want. */
  approaching: number | null;
}

/**
 * What release an Aperire install IS, three-valued (ADR 0022 decision 1).
 *
 *   `release`    — `.release` at the install root: the tag, the commit, the
 *                  archive's sha256 and when it was published.
 *   `deploy_ref` — no `.release`, a `.deploy-ref`: deployed from a commit,
 *                  not from a published release.
 *   `unknown`    — neither file. Said out loud, never guessed, and never
 *                  read as "the same as mine".
 *
 * The sum is what a consumer compares, and it compares for EQUALITY. These
 * are not ordered against each other anywhere: an aggregator asks "is this
 * host on the release the endpoint publishes", which one comparison answers
 * and a version ordering could only get wrong.
 *
 * `source_url` is deliberately absent: which endpoint a host asks is that
 * host's own business and no peer grades it.
 */
export type ReleaseIdentityWire =
  | { kind: 'release'; tag: string; commit: string; sha256: string; published_at: string }
  | { kind: 'deploy_ref'; sha: string }
  | { kind: 'unknown' };

/**
 * `node-status` — the server_info-derived snapshot the center identity
 * panel, state pill, and Health card need. Raw values, not
 * display-normalised (same convention as IdentityResponse: `network` is the
 * raw network_id, not a Mainnet/Testnet/Devnet label; `pubkey_validator` may
 * be rippled's literal string "none" on a stock node, not filtered — use
 * `is_validator` for the filtered fact). `base_fee_xrp` (not `base_fee`):
 * server_info's `validated_ledger.base_fee_xrp` and the `fee` RPC's
 * `base_fee` share a name-stem across two different units (XRP vs drops) —
 * overview.html reads both, at different call sites — and a field named
 * `base_fee` sourced from the XRP one would invite a 10^6 error in a later
 * slice that assumes drops.
 *
 * The two ages (risk R1, "kept vs observed" — the project's characteristic
 * bug): `server_info_age_ms` is how old THIS node's own cached server_info
 * is (null only if this process has never once completed a server_info
 * poll — never coerced to 0, which would read as "instantly fresh" while
 * every other field is null), and `node_reach` is this node's own
 * reachability state. A caller aggregating a PEER's node-status must show
 * the worse of {its own fetch age, this route's server_info_age_ms}.
 */
export interface NodeStatusResponse extends ReadEnvelope {
  server_state: string | null;
  validated_ledger_index: number | null; // "Total Ledgers" — validated_ledger.seq
  complete_ledgers: string | null;
  uptime_s: number | null;               // server_info's own uptime, resets on rippled restart
  build_version: string | null;
  base_fee_xrp: number | null;
  load_factor: number | null;
  peer_count: number | null;
  /** Raw network_id. Absent (null) is NOT "unknown" — it is rippled's
   *  unconfigured default, i.e. Mainnet. The full rule, with the rippled
   *  source it comes from, is on IdentityResponse.network above; it is
   *  written down once and both routes point at it. */
  network: number | null;
  pubkey_validator: string | null;       // raw string, may be "none" — see is_validator
  pubkey_node: string | null;
  /**
   * This node's OS hostname (`os.hostname()`), so a fleet aggregator's
   * Overview can name the host of the node it is displaying instead of its
   * own serving host — the page's `location.hostname` is a fact about the
   * BROWSER's origin, which under a peer view belongs to a different
   * machine entirely.
   *
   * Deliberately the OS hostname and not a configured public URL: a public
   * URL can be shared across a fleet (or absent), while `system`'s
   * `host.meta.hostname` already ships this same `os.hostname()` expression
   * on a route the Overview peer poll already fetches. One expression means
   * the two routes cannot disagree about what host this is; sourcing one of
   * them from `APERIRE_PUBLIC_URL` or `APERIRE_HOSTNAME` would give one
   * page two answers to the same question.
   *
   * Pointer-typed in the Go mirror, and null rather than '' when the host
   * reports no name: absent is not empty (the Governance lesson — a `?? ''`
   * here would render a blank row that looks like a measured emptiness).
   * A consumer that receives no `host_name` at all is talking to a server
   * older than this field and must render its own dash, never a claim like
   * "not available for a peer" — the peer will serve it the moment it is
   * upgraded.
   *
   * No protocol_version bump: an older server simply omits the key (a new
   * client sees absent and falls back), and an older client ignores it.
   * Strictly weaker than the optional-parameter case ADR 0010's follow-ups
   * already cover, and not a shape change to an existing field.
   */
  host_name: string | null;
  /**
   * rippled's own `hostid` from server_info — the node process's
   * self-identifier, NOT the machine `host_name` above, and the two
   * routinely differ: under Docker it is the container id (measured on the
   * lab fleet: `4ad2597b5262` / `ac7e56056e8b` / `3e2fbd6e8f3f`, against
   * host names `srv12345` / `srv12346` / `srv12347`), on a native
   * install it is usually the machine's hostname.
   *
   * Carried raw, like every other field on this route. Worth knowing when
   * reading one: on a NON-admin connection rippled substitutes a masked
   * two-word pseudonym rather than the real value. Every Aperire dashboard
   * polls its own node over an admin connection, so what this route serves
   * is the real identifier — but a value that looks like two English words
   * is that mask, not a host, and must not be read as one.
   *
   * Null when rippled reported none. No protocol_version bump, for the same
   * reason `host_name` above gives.
   */
  hostid: string | null;
  domain: string | null;
  unl_total: number;
  is_validator: boolean;
  amendments: AmendmentCounts | null;
  time_drift_ms: number | null;          // null when the relay hasn't reported a clock reading yet
  ntp_synced: boolean | null;            // paired with time_drift_ms — a drift number is meaningless
                                          // without knowing whether the clock reporting it is synced
  server_info_age_ms: number | null;
  node_reach: NodeReachState;
  /**
   * The commit this HOST's Aperire install was last deployed from — the
   * first line of `.deploy-ref` at the install root, which the fleet update
   * stamps after it rsyncs (issue #128 rung 2).
   *
   * A fact about the dashboard's own install, not about rippled, and it
   * rides here for the same reason `host_name` above does: this is the route
   * every fleet poll already reads on every cycle for every peer, so the
   * comparison costs no extra read and no extra route. `identity` was the
   * other candidate and is the wrong one — it is fetched only for a peer
   * carrying `expected_pubkey_node`, which would make noticing an old deploy
   * depend on whether that peer happened to be pinned.
   *
   * Null means this host reported no ref, and that is ALL it means: no
   * `.deploy-ref` (never deployed to by the fleet tool, which is the normal
   * single-node install), or a file this process could not read. An absent
   * key means the peer is older than this field. Both are "unknown", and a
   * consumer must never read either as "same as mine" — the whole point of
   * the field is to tell a host that is behind from a host that cannot say.
   *
   * Opaque to every consumer: compared for equality, never parsed, never
   * ordered. Two refs that differ say the hosts are not running the same
   * deploy; neither says which one is newer.
   *
   * No protocol_version bump — an additive member, the same rule `host_name`
   * and `hostid` above were added under.
   */
  deploy_ref: string | null;
  /**
   * What release this HOST's Aperire install IS — `.release` at the install
   * root when the bootstrap wrote one, its `.deploy-ref` when only that
   * exists, and `unknown` when neither does (ADR 0022 decision 1).
   *
   * Three-valued and the third value is the point. `deploy_ref` above says
   * which commit a FLEET UPDATE put on the box; it is null on every host
   * installed from the published bootstrap, which is now most of them. This
   * says which published release the host is on, so an aggregator can grade
   * a fleet against one `release.json` it fetched once instead of comparing
   * hosts to each other and learning only that they differ.
   *
   * `unknown` is never current and never behind. A host that cannot say what
   * it runs gets its own bucket at both ends: counting it as agreeing is the
   * kept-vs-observed failure, and nagging it is a claim nobody measured.
   *
   * Optional, and no protocol_version bump — an additive member, the same
   * rule `host_name`, `hostid` and `deploy_ref` above were added under. A
   * consumer older than this field sees nothing new; a consumer newer than a
   * peer reads the absent key as `unknown`, which is exactly what it is.
   * Nothing on the Go side (advisor/internal/dashread/contract.go) has to
   * change for it: that decoder names the fields it wants and ignores the
   * rest.
   */
  release?: ReleaseIdentityWire;
}

/** One row of the `peers` route. Carries the fields the ring, legend, and
 *  tooltip already render client-side (overview.html's applyPeers/
 *  showPeerTooltip) — `has_issue`/`issue_reasons` mirror applyPeers' own
 *  derivation exactly (sanity !== 'sane', or latency > 1000ms) so a peer
 *  Overview built from this route computes the identical verdict a local
 *  Overview does, not a second implementation that can drift from it. */
export interface ReadPeerRow {
  address: string | null;
  host: string | null;    // PTR hostname when resolved, otherwise same as address
  country: string | null;
  inbound: boolean;
  latency_ms: number | null;
  version: string | null;
  uptime_s: number | null;
  sanity: string | null;
  has_issue: boolean;
  issue_reasons: string[];
}

/**
 * `peers` — the peer-ring summary: the full enriched peer array plus the
 * legend's derived counts (total, out, in, issue, p90), matching the
 * table's "full peer array + counts" finding. This is the first read route
 * to carry node network addresses across the tunnel (risk R5) — parked
 * under the same loopback + token protection every read route already has;
 * the transport-level question (should this leave loopback unencrypted) is
 * D1's open item, not this slice's.
 *
 * `node_reach` rides along for the same reason `node-status` carries it:
 * `pollPeers` swallows every rippled error and leaves `snapshot.peers`
 * un-cleared, so a peer list served while the node itself is unreachable is
 * the LAST list, not a current one (the exact case overview.html's
 * applyPeers refuses to render for the local node). A consumer of this
 * route must apply that same refusal rather than trust `peers` alone.
 */
export interface PeersResponse extends ReadEnvelope {
  peers: ReadPeerRow[];
  total: number;
  out: number;
  in: number;
  issue: number;
  latency_p90_ms: number | null;
  node_reach: NodeReachState;
}

/**
 * `validation-summary` — computeAgreementStats()'s output, field for field,
 * never raw agreement rows: 24h at a ~3.5s close time is ~25,000 rows per
 * fetch to render four integers, and `computeAgreementStats()` already
 * computes exactly this on the server for the live Validations card.
 */
export interface ValidationSummaryResponse extends ReadEnvelope {
  agreement_1h: number;
  missed_1h: number;
  agreement_24h: number;
  missed_24h: number;
  unl_active_1h: number;
  unl_total: number;
  is_validator: boolean;
}

/**
 * `consensus-snapshot` — the fourteen live-value cards on the Consensus tab
 * (Rippled State / Ledger Progression / Validation Activity / Fee & Load)
 * that, before this route existed, read "n/a for a peer": they are fed
 * locally by the WS `server_info`/`fee`/`ledger:close` broadcasts and the
 * server's own 1Hz validation tally, none of which a peer's browser session
 * holds — but the PEER's own dashboard process already computes every one
 * of them from ITS OWN rippled connection, the same way it already serves
 * `node-status`. This route exposes that existing computation; it starts
 * no new polling.
 *
 * Explicitly OUT of scope: the per-round quorum bar (received/target/UNL
 * ticks) is fed by `validations_tick`'s `current_round` counters, which
 * reset on every ledger close and are meaningful only as a live push — a
 * 5s-polled snapshot of "how many of the CURRENT round's validations have
 * landed so far" would show a bar that visibly regresses every poll tick
 * rather than climbing smoothly, a worse answer than the honest
 * "n/a for a peer" the bar already shows. `quorum_req` (the target) is a
 * single stable number from `server_info` and is served here; the bar
 * itself is not.
 *
 * Raw values, not display-normalised — same convention as every other
 * route in this file (`fee_escalation`/`job_overflow` in particular carry
 * rippled's literal null/absent value, not the local page's "1.0"/"0"
 * fallback text; a consumer applies that fallback the same way
 * applyServerInfo already does for the local reading).
 *
 * Three independent staleness clocks, all exposed rather than baked into
 * a single number (risk R1, kept-vs-observed): `server_info_age_ms` covers
 * the `server_info`-derived fields (proposers, quorum_req, converge_time_s,
 * ledger_age_s, fee_escalation, job_overflow), `fee_age_ms` covers the
 * `fee`-derived fields (open_ledger_fee_drops, queue_size), and
 * `last_close_age_ms` covers the three fields sourced from the peer's own
 * WS ledger-close stream (close_delta_s, tx_last_ledger, tps_1m) — a stream
 * that can die independently of the poll-based fields above it and, unlike
 * `ledgers_per_min` (which self-heals to 0 as its 60s window empties),
 * would otherwise freeze at the last real ledger and render a stalled peer
 * as still producing ledgers. `validation_rate_per_min` carries no age of
 * its own: it is recomputed from a 60s sliding window every second
 * regardless of poll success, so it already self-heals to 0 the same way
 * `ledgers_per_min` does.
 *
 * A real, expected shape — not a defect — confirmed against a genuinely
 * desynced peer (node2, 2026-08-11, rippled reporting `complete_ledgers:
 * "empty"` and no `validated_ledger`): `proposers`, `quorum_req`,
 * `converge_time_s`, `validation_rate_per_min`, and `job_overflow` all
 * populate normally (they come from `server_info` fields and the
 * `validationReceived` stream, neither of which needs a validated ledger),
 * while EVERY ledger-close/fee-derived field on this response
 * (`avg_close_1h_s`, `ledger_age_s`, `close_delta_s`, `tx_last_ledger`,
 * `tps_1m`, `open_ledger_fee_drops`, `queue_size`, `fee_age_ms`,
 * `last_close_age_ms`) is null at once, because `fee` RPC and the
 * `ledgerClosed` stream both depend on a synced node. A consumer must not
 * treat "most of this response is null" as evidence the route itself is
 * broken — it is the correct, honest shape for that specific peer's state.
 */
export interface ConsensusSnapshotResponse extends ReadEnvelope {
  avg_close_1h_s: number | null;      // null until at least one close_time sample lands inside the 1h window
  proposers: number | null;
  quorum_req: number | null;
  converge_time_s: number | null;
  ledger_age_s: number | null;        // validated_ledger.age AT THE LAST server_info POLL — add server_info_age_ms for the true current age
  close_delta_s: number | null;       // the most recent ledger close's own delta; null before this process has seen one
  ledgers_per_min: number;            // a count over a real 60s window — 0 is a fact (no ledgers closed), never null
  tx_last_ledger: number | null;
  tps_1m: number | null;              // null when close_delta_s is unknown or zero, not a divide-by-zero Infinity
  validation_rate_per_min: number;    // self-healing 60s sliding window — see the age-clocks note above
  fee_escalation: number | null;      // null exactly when rippled's load_factor_fee_escalation is null; see doc note re display fallback
  open_ledger_fee_drops: number | null;
  queue_size: number | null;
  job_overflow: number | null;        // null exactly when rippled omits the field; see doc note re display fallback
  server_info_age_ms: number | null;
  fee_age_ms: number | null;
  last_close_age_ms: number | null;
  node_reach: NodeReachState;
}

/**
 * `amendment-ballot` — the Governance tab's per-amendment ballot table, for
 * a peer. Server.ts's sampleGovernance() already builds this exact row
 * shape for the local page's `amendments.pending` array
 * (lib/amendments.ts's buildAmendmentBallotRows, the "one definition"
 * shared by both); this route exposes it unchanged, no new polling —
 * `snapshot.feature` is already maintained by the existing pollFeature()
 * poller.
 *
 * Real peer data, not something to blank: amendments differ per node
 * (a fork's build recognizes a different set; `our_vote`/`supported` are
 * this SPECIFIC node's own choice and build, not a network-wide fact).
 * `count`/`threshold`/`validations`/`support_pct`/`progress_state`/
 * `needed_count` ARE network-wide facts and will typically agree across
 * nodes sharing a UNL — served per-peer anyway, since a fork lagging the
 * network's current feature vote is exactly the case worth being able to
 * see directly on that fork's own row.
 *
 * The rest of the tab — vote stance, publishers, amendment-blocked — is the
 * sibling `governance` route below; the two are fetched on one poll tick and
 * this one keeps the table because the table is the one part that is a LIST.
 *
 * The tally fields are `number | null`, and that widening does NOT bump
 * protocol_version. rippled fills `count`/`threshold`/`validations` only on a
 * node that runs the flag-ledger amendment vote — a stock node reports none
 * of them, and this route used to filter every such row out, emptying the
 * whole ballot on a tracking node (see lib/amendments.ts's
 * `reportsNoSupport` for the measured evidence). An older client against
 * this server reads `Number(null) || 0` → 0, exactly what it renders for
 * those same amendments today; a newer client against an older server never
 * sees a null, because that server filtered those rows away. Neither
 * direction changes meaning, so this stays inside the additive rule
 * IdentityResponse's own doc comment states, and does not spend a version
 * bump that would darken every route on a half-upgraded host.
 *
 * `majority_at_ms` and `support_state` are additive for the same reason. An
 * older client ignores both and renders what it always rendered; a newer
 * client against an older server sees them missing and falls back to the
 * tally fields, which is the same decision `support_state` names.
 *
 * `support_state: 'counted'` and `counted` are additive again. A client
 * older than the value sees a state it does not name and renders its
 * "Not reported" note, which is what that client showed for the same node
 * before the dashboard learned to count; `count`/`validations` stay null on
 * such a row on purpose, so no client can mistake the dashboard's count for
 * the node's own tally. A client older than `support_state` altogether
 * renders `support_pct`, which on a counted row is the counted share.
 *
 * That fallback recomputes the percentage rather than trusting the one on
 * the wire. A server older than these fields also computed `support_pct` the
 * old way (count/threshold, which reads above 100% past the bar) and its row
 * still carries `count` and `validations`, so the client derives the share
 * itself. Otherwise a fleet halfway through an upgrade shows one node at
 * 103.6% beside another at 80.6% for the same amendment on the same network.
 *
 * `library_age_ms` is additive (#542): how old the amendment knowledge
 * library behind every row's `description`/`xls_url` is, read from the
 * library file's own recorded refresh moment, not filesystem mtime (a
 * deploy overwrites the file with the tree's shipped copy, which would make
 * mtime read as freshly refreshed the moment it is actually stalest). null
 * before this node has ever refreshed the library. An older client ignores
 * it and renders exactly what it always rendered.
 */
export interface AmendmentBallotResponse extends ReadEnvelope {
  rows: ReadAmendmentBallotRow[];
  feature_age_ms: number | null;
  library_age_ms: number | null;
  node_reach: NodeReachState;
}

/** One row of the `amendment-ballot` route. Mirrors AmendmentBallotRow in
 *  lib/amendments.ts (whose doc comment carries the full field-by-field
 *  reasoning) field for field. */
export interface ReadAmendmentBallotRow {
  hash: string;
  name: string;
  xls: string | null;
  description: string | null;
  xls_url: string | null;
  /** null exactly when this node reports no vote tally for the amendment —
   *  a tracking node never reports one. Never collapse to 0: "nobody is
   *  signalling yes" and "this node cannot tell" are different facts, and
   *  the second one rendered as the first is what emptied this table. */
  count: number | null;
  threshold: number | null;
  validations: number | null;
  /** `count / validations`, the share xrpscan publishes, not `count /
   *  threshold` (which reads above 100% past the bar). */
  support_pct: number | null;
  progress_state: 'pending' | 'needs' | null;
  needed_count: number | null;
  /** When this amendment reached the network's majority, ms since the Unix
   *  epoch, converted from rippled's ripple-epoch `majority` field. Reported
   *  by a tracking node too, so it is often the only support fact such a
   *  node has. null when the amendment does not hold the majority. */
  majority_at_ms: number | null;
  /** Which support fact the row carries: the node's own tally, a count the
   *  dashboard made from the trusted validations stream, a majority-only
   *  reading, or nothing at all. Named on the wire so a peer's page renders
   *  the same states as the local one instead of inferring them from
   *  nulls. Additive, and an older client that ignores it renders exactly
   *  what it rendered before. */
  support_state: 'tallied' | 'counted' | 'majority' | 'unreported';
  /** The dashboard's own count, present exactly when `support_state` is
   *  'counted': how many trusted validators listed this amendment on the
   *  last voting ledger (`count`), how many trusted validators validated
   *  that ledger (`validations`), rippled's bar for that round
   *  (`threshold`), and which ledger and moment it was read from. null on
   *  every other row. */
  counted: ReadCountedAmendmentSupport | null;
  our_vote: 'yes' | 'no' | 'default' | 'obsolete';
  supported: boolean;
}

/** Mirrors CountedAmendmentSupportRow in lib/amendments.ts. */
export interface ReadCountedAmendmentSupport {
  ledger_index: number;
  at_ms: number;
  count: number;
  validations: number;
  threshold: number;
}

/**
 * `governance` — everything the Governance tab renders that is not the
 * ballot table: the AMENDMENT STATUS card's blocked pill and threshold
 * count, the OUR VOTE STANCE card, and the PUBLISHER HEALTH card plus its
 * PUBLISHERS table. Every value here is genuinely per-node — a validator's
 * voting posture is its operator's own choice, and which validator-list
 * publishers a node follows is its own configuration — so serving this
 * node's numbers under a peer's label would be the wrong answer, not a
 * harmless approximation.
 *
 * One route rather than three (vote stance / publishers / diagnostics),
 * because server.ts computes all of it inside one function at one moment:
 * three routes would give three age clocks to values that share a single
 * one, the cross-cadence skew ADR 0013 exists to remove. It mirrors that
 * local structure field for field rather than inventing a shape.
 *
 * Two staleness clocks, because there genuinely are two pollers behind it:
 * `feature_age_ms` for the amendment aggregates (pollFeature, 5 min) and
 * `sites_age_ms` for the publisher block (pollValidatorListSites). A
 * consumer that wants one number for the whole body takes the worse of the
 * two.
 *
 * Additive route: no protocol_version bump, for the two reasons
 * IdentityResponse's doc comment gives.
 *
 * What is NOT here, deliberately: the tab's "Network Majority Version",
 * "Manifest Rotations 24h", "UNL Churn 7d" and "Signalling Match" fields.
 * They have no producer anywhere in this dashboard — the local page reads
 * them off payload keys server.ts has never written, and renders the same
 * dash a peer now does. Adding null contract fields for four values nothing
 * computes would dress a missing feature up as a served one.
 */
export interface GovernanceResponse extends ReadEnvelope {
  amendment_blocked: boolean;
  /** null when this node reports no vote tally at all — see
   *  ReadAmendmentBallotRow.count. */
  threshold_met_count: number | null;
  approaching_threshold_count: number | null;
  our_votes: { yes: number; no: number; default: number };
  next_activation_status: 'pending' | 'gathering' | 'none';
  next_activation_name: string | null;
  publishers: ReadPublisherSummary;
  feature_age_ms: number | null;
  sites_age_ms: number | null;
  node_reach: NodeReachState;
}

/** Mirrors PublisherSummary in lib/publishers.ts field for field. */
export interface ReadPublisherSummary {
  site_count: number;
  refresh_status: string;
  refresh_age_s: number | null;
  list_expiry_days: number | null;
  cert_expiry_days: number | null;
  sites: ReadPublisherSiteRow[];
}

/** One row of the PUBLISHERS table. `list_expiry_days`, `cert_expiry_days`
 *  and `sequence` are null on builds that omit those fields from
 *  `validator_list_sites` — measured absent on the lab fleet — and render as
 *  the same dash the local view shows, never a confident zero. */
export interface ReadPublisherSiteRow {
  site: string;
  status: string;
  refresh_age_s: number | null;
  list_expiry_days: number | null;
  cert_expiry_days: number | null;
  sequence: number | null;
}

/**
 * `system` — the full host snapshot both Overview's SYSTEM card
 * (overview.html's applySystem, cpu/memory/swap/disk only) and the System
 * tab's own cards + accordions (system.html's applySystem, the whole shape
 * below) render, for a peer. Deliberately the ONE route in this file with no
 * `node_reach` field: every other peer route above is derived from rippled
 * (server_info, fee, peers, feature) and can go stale or absent when that
 * node's rippled process is unreachable, but every field here — including
 * `get_counts`/`get_counts_canonical`, which ARE rippled RPC results — comes
 * from a read this same dashboard process performs directly (`/proc`,
 * `statfs`, `timedatectl`/`chronyc`, `pgrep`, or its own `get_counts`/
 * `crawl_shards` RPC calls), independent of the WS/peer machinery that
 * `node_reach` tracks. Carrying rippled's reachability next to readings that
 * do not depend on it would attach a signal that can read `ok: false` while
 * the numbers underneath it are perfectly current, the wrong semantics for
 * this route.
 *
 * Two independent kinds of "no data" here, and they must not collapse into
 * one:
 *   - Before this process's first `pushSystem()` tick completes, the ENTIRE
 *     broadcast is `null` and this route serves every field as null — never
 *     a zeroed "idle host" reading (0% CPU / 0% RAM / 0% disk is a
 *     plausible-looking lie, the project's characteristic "kept vs observed"
 *     bug), an honest absence instead. A consumer must treat an all-null
 *     body the same as a failed fetch.
 *   - Several sections are ALSO independently nullable even once
 *     `pushSystem()` is ticking normally, because the underlying fact is a
 *     per-host CONFIGURATION or TIMING gap, not a missing tick:
 *     `node_db_cfg` is null when that host has no `RIPPLED_CFG_PATH`
 *     configured at all (a permanent per-install fact, not "wait and it'll
 *     appear") — collapsing this to `{ online_delete: null }` would render
 *     the specific, wrong claim "online_delete: off" instead of leaving the
 *     row dim; `get_counts`/`get_counts_canonical` are null until this
 *     process's own periodic `get_counts` RPC has completed at least once;
 *     `disk_io` is null when `/proc/diskstats` itself is unreadable. Each of
 *     these stays an object-level `| null`, never flattened to an object of
 *     all-null fields, so a consumer can tell "this peer doesn't have this"
 *     apart from "this peer hasn't reported yet."
 *   - `pressure.*` and `oom_kills` are the opposite case: their OWN readers
 *     (`readPressureSome`, `readOomKills`) already default to `0` rather
 *     than null when PSI/vmstat are unavailable on that kernel — passed
 *     through faithfully as `number`, not reinterpreted as `number | null`,
 *     so a peer's card reads identically to a local one built from the same
 *     source function. Same for the numeric fields inside `disk_io` once
 *     the object itself is non-null (each defaults to 0 before a second
 *     sample interval has elapsed, never null).
 *   - `rippled.cpu_pct` is `number` (defaults to 0, never null) for the same
 *     reason; `rippled.pid` stays nullable and is the actual "was a rippled
 *     process found at all" signal system.html's own applySystem gates on
 *     — a peer where rippled isn't discoverable must read as "no rippled
 *     process," not "0% CPU."
 *   - `shard_count` is passed through as the exact three-state union
 *     rippled's `crawl_shards` already produces (`number | 'not_sharded' |
 *     null`) — coercing it through a numeric parser would turn the string
 *     literal `'not_sharded'` (the common, correct answer for most
 *     validators) into `null` via `Number('not_sharded') → NaN`.
 *
 * No new polling anywhere in this route — `pushSystem()`, the `get_counts`
 * poller, and `crawl_shards` all already run on their own existing
 * intervals, independent of any peer view. This route exposes their
 * existing output verbatim; only the fields either page's own applySystem
 * actually reads are named here (not `host.host_uptime_s`, which
 * system.html reads defensively but `pushSystem` has never actually
 * emitted — dead on the wire today).
 */
export interface SystemResponse extends ReadEnvelope {
  cpu: {
    busy_pct: number | null;
    iowait_pct: number | null;
    steal_pct: number | null;
    cores: number | null;
    load_1m: number | null;
    load_5m: number | null;
    load_15m: number | null;
  } | null;
  memory: {
    used_pct: number | null;
    used_bytes: number | null;
    total_bytes: number | null;
    /** #198. Reclaimable file cache — MemAvailable − MemFree — as a
     *  percentage of RAM and in bytes. Used + cache + free is the whole of
     *  RAM by construction, since used is total − MemAvailable.
     *
     *  Null when the reading was not made: a relay older than the fields
     *  feeding this dashboard, or a peer on a build that predates them.
     *  Never 0, which is a box with nothing cached and a different fact. */
    cache_pct: number | null;
    cache_bytes: number | null;
  } | null;
  swap: {
    used_pct: number | null;
    used_bytes: number | null;
    total_bytes: number | null;
  } | null;
  disk: {
    used_pct: number | null;
    used_bytes: number | null;
    total_bytes: number | null;
  } | null;
  /** PSI "some avg10" per resource, 0-100. Each already defaults to 0 (never
   *  null) at the source when PSI is unavailable on that kernel — see the
   *  doc comment above. */
  pressure: {
    cpu: number;
    memory: number;
    io: number;
  } | null;
  /** Cumulative OOM-kill count from /proc/vmstat. 0 (never null) when the
   *  counter is missing on that kernel — same "0 is a real reading" rule
   *  as `pressure`. */
  oom_kills: number | null;
  /** #198. What the node store did over the last `get_counts` interval, as
   *  opposed to since the process started. Null when no usable pair of
   *  samples exists yet — the first poll after a start, or a pair that
   *  spanned a rippled restart, whose difference is not a rate of anything.
   *  `read_hit_pct` is separately null when nothing was read in the
   *  interval: a quiet store is not a 0% hit rate. */
  nodestore: {
    read_hit_pct: number | null;
    reads_per_s: number | null;
    writes_per_s: number | null;
    read_bps: number | null;
    written_bps: number | null;
  } | null;
  nudb_size_bytes: number | null;
  /** Who took the reading `nudb_size_bytes` carries, when it was not the
   *  node's own dashboard.
   *
   *  Null on every host that walked its own store, which is the ordinary
   *  case, and null again where nobody measured it at all: `nudb_size_bytes`
   *  is then null too and `nudb_walk_error` says why. Non-null only on a host
   *  whose dashboard account cannot open the store (a node installed from its
   *  vendor's package keeps its state directory 0750, owned by the account
   *  the node runs as) and whose own Advisor measured it on the privileged
   *  side instead. `at` is when the Advisor took the reading, not when this
   *  dashboard relayed it, because that is what the page prints.
   *
   *  Additive and nullable: a peer on an older build omits the field, which a
   *  consumer must read as "this dashboard measured it itself", the same way
   *  every host behaved before the field existed. */
  nudb_measured_by: { source: 'advisor'; at: string } | null;
  nudb_peak_bytes_24h: number | null;
  mount_free_days_est: number | null;
  /** #199. The mount-free-days estimate with its reasoning attached, fitted
   *  from the DAILY PEAKS of `nudb_size` over the retained window rather than
   *  first-vs-last over 24 hours — the only slope that means anything on a
   *  store running online_delete. `days` repeats `mount_free_days_est` and is
   *  null unless `status` is `ok`; the two never disagree.
   *
   *  Null when this host has no `RIPPLED_DATA_PATH` configured at all — the
   *  same "there is no store here to measure" fact `nudb_size_bytes` already
   *  carries, not a startup gap. A peer on an older build omits the field
   *  entirely, which a consumer must read as null rather than as "not
   *  growing". */
  nudb_growth: {
    status: 'ok' | 'not_growing' | 'needs_history';
    days: number | null;
    peak_growth_bytes_per_day: number | null;
    peak_7d_bytes: number | null;
    last_rotation: { ts: number; drop_bytes: number } | null;
  } | null;
  /** The directory the node store is measured from (`RIPPLED_DATA_PATH` on
   *  the node's dashboard), or null when it is not set. system.html reads it
   *  to name the state: an unset path is "not set", with the script that
   *  sets it, rather than the same dash a store still being walked shows.
   *  A peer on an older build omits the field; a consumer must read that as
   *  "unknown", not as "not set". */
  rippled_data_path: string | null;
  /** The last store walk's failure message, or null while walks succeed or
   *  no path is set. A path that is set and cannot be read is its own
   *  state on the page ("unreadable"), distinct from unset. */
  nudb_walk_error: string | null;
  clock: {
    ntp_synced: boolean | null;
    time_drift_ms: number | null;
  } | null;
  rippled: {
    /** The "was a rippled process found at all" signal — see the doc
     *  comment above. Never coerced to 0; a consumer must gate rendering
     *  the whole rippled-process block on this being non-null, exactly as
     *  system.html's own applySystem already does locally. */
    pid: number | null;
    /** Defaults to 0, never null, when no process was found — matches
     *  readRippledProcess's own return shape. Meaningless without also
     *  checking `pid`. */
    cpu_pct: number;
    rss_bytes: number | null;
    threads: number | null;
  } | null;
  disk_io: {
    read_iops: number;
    write_iops: number;
    read_bps: number;
    write_bps: number;
    util_pct: number;
  } | null;
  host: {
    uptime_s: number | null;
    entropy_avail: number | null;
    inode_usage_pct: number | null;
    rippled_uptime_s: number | null;
    meta: {
      hostname: string;
      os_name: string;
      kernel: string;
      architecture: string;
    } | null;
  } | null;
  /** The subset of rippled's raw `get_counts` RPC result system.html's
   *  rippled-Internals accordion reads. Independently nullable from the
   *  rest of this response — see the doc comment above. */
  get_counts: {
    AL_hit_rate: number | null;
    AL_size: number | null;
    SLE_hit_rate: number | null;
    node_reads_total: number | null;
    node_reads_hit: number | null;
    node_writes: number | null;
    write_load: number | null;
    treenode_cache_size: number | null;
  } | null;
  /** ADR 0002's fork-namespace-resolved object counters — additive sibling
   *  of `get_counts`, same nullability rule. */
  get_counts_canonical: {
    SHAMapAccountStateLeafNode: number | null;
    SHAMapInnerNode: number | null;
    SHAMapItem: number | null;
    STLedgerEntry: number | null;
  } | null;
  /** rippled.cfg's [node_db] section, parsed by this dashboard process.
   *  `null` means no `RIPPLED_CFG_PATH` is configured on that host at all
   *  (a permanent per-install fact) — NOT the same as `{ online_delete:
   *  null }`, which is a configured cfg with online_delete unset ("off").
   *  Collapsing the two would render a specific, wrong operational claim;
   *  see the doc comment above. */
  node_db_cfg: {
    online_delete: number | null;
    advisory_delete: boolean | null;
  } | null;
  /** rippled's `crawl_shards` RPC result — see the three-state note above.
   *  `null` here means this process has never completed that poll, distinct
   *  from `'not_sharded'` (polled, and the node genuinely has none). */
  shard_count: number | 'not_sharded' | null;
}

/**
 * `net-stats` — the Network tab's BANDWIDTH LIVE and ERRORS & BUDGET cards
 * (network.html's `applyNetStats`), for a peer. Unlike `system`, this data
 * genuinely depends on something outside this dashboard process: an
 * aperire-relay running on that peer's host and reaching this dashboard's
 * `/ingest` (server.ts's `handleRelayPush`, which maintains
 * `lastNetStatsBroadcast`). A peer with no relay configured never populates
 * that broadcast at all, and this route serves the all-null envelope
 * forever for that peer — a permanent absence, not the transient
 * pre-first-tick gap `system` also has. A caller cannot distinguish "this
 * peer has never had a relay" from "this peer's relay is mid-outage" from
 * this route alone, and must not try to: network.html's own peer-view
 * module treats both the same way `system`'s pre-tick null already is
 * treated — as "not served," never as the peer itself being unreachable
 * (the rest of the peer's fields, e.g. `peers`/`node-status`, keep working
 * independently).
 *
 * Every field is `number | null` (`string | null` for the two interface
 * identifiers), never defaulted to 0 or `''` — the same "kept vs observed"
 * rule `system`'s doc comment states: `rx_bps: 0` on a genuinely idle
 * interface is a real reading, so an all-null body is the only honest way
 * to say "not reporting" without inventing a plausible-looking idle host.
 *
 * No new polling — this route exposes `handleRelayPush`'s own outbound
 * object verbatim, field for field; only the fields `applyNetStats` itself
 * reads are named here. Notably absent: `node_label` (server-internal,
 * never rendered), `socket_count`/`tcp_resets_per_sec` (no card reads
 * them yet), and `peer_connections` — deliberately fed to `applyPeers` from
 * rippled's own peer data instead, per `applyNetStats`'s own comment on why
 * (correct even when the node runs in a container, where the relay's
 * host-side port scan reports 0).
 */
export interface NetStatsResponse extends ReadEnvelope {
  interface: string | null;
  interface_source: string | null;
  rx_bps: number | null;
  tx_bps: number | null;
  rx_pps: number | null;
  tx_pps: number | null;
  tcp_established: number | null;
  tcp_retrans_per_sec: number | null;
  rx_errors: number | null;
  tx_errors: number | null;
  rx_drops: number | null;
  tx_drops: number | null;
  tcp_time_wait: number | null;
  monthly_used_bytes: number | null;
  monthly_cap_bytes: number | null;
  monthly_pct: number | null;
  http_rpc_connections: number | null;
  admin_ws_connections: number | null;
  ws_public_connections: number | null;
}

/**
 * `validations-tick` — Overview's "Validations received / quorum" row
 * (overview.html's `renderQuorumBar`), for a peer. Unlike `system`/
 * `net-stats`, there is no cached broadcast object behind this route: the
 * server rebuilds the SAME object the browser's own 1Hz `validations_tick`
 * WS push builds (server.ts, the `setInterval` just above
 * `sampleSystemHistoryMetrics`), from the live in-memory round counters, on
 * every request — the same "no new polling, read what's already tracked"
 * discipline `identity` uses for `snapshot.server_info` directly.
 *
 * `quorum` is `snapshot.server_info.validation_quorum`, not a field of the
 * WS tick itself — carried here because a peer's quorum bar needs both. A
 * node that has just restarted reports `validation_quorum` as rippled's
 * unsigned -1 sentinel (`4294967295`) until its UNL has loaded
 * (`renderQuorumBar`'s own comment, overview.html); this route serves that
 * honestly as `null`, never the literal number, so a peer mid-restart
 * doesn't try to draw a domain no real network can have.
 *
 * Every count field (`received`, `unl_received`, `unl_size`) is a real `0`
 * when a round has genuinely seen no validations yet or the UNL is
 * genuinely empty — never coerced to `null` for a zero — the same "kept vs
 * observed" rule the rest of this file's doc comments state; only
 * `ledger_index` (before this process has ever tracked a round) and
 * `quorum` (the sentinel case above) are legitimately `null`. There is no
 * permanent "this peer doesn't track validations" state the way `net-stats`
 * has for a peer with no relay — this route is served by every dashboard
 * process, always; a caller only ever sees the transient pre-first-tick gap.
 */
export interface ValidationsTickResponse extends ReadEnvelope {
  ledger_index: number | null;
  received: number | null;
  unl_received: number | null;
  unl_size: number | null;
  quorum: number | null;
  our_validated: boolean | null;
  rate_per_min: number | null;
  rate_per_sec: number | null;
}

/**
 * `fleet`, no parameters. The roster THIS dashboard holds, and what it last
 * observed of each member. Added for #59.
 *
 * The problem it exists to solve is a distinction nothing else could draw.
 * The Advisor's own peer table (`advisor/state/fleet.json`) is generated from
 * this dashboard's `fleet.yaml`, and a row with no readable token path is
 * deliberately LEFT OUT of it rather than guessed at (lib/advisor-registry-gen.ts).
 * So a node that is in the fleet but whose credential this Advisor does not
 * hold was, to the Advisor, indistinguishable from a node nobody ever
 * registered, and both came back as "no such fleet peer". One of those is a
 * name that does not exist; the other is a host that exists and cannot be
 * reached from here. They need different sentences, and only the dashboard
 * knows which is which.
 *
 * Every field here is something this dashboard already computes for its own
 * FLEET card (lib/fleet-health.ts's FleetPeerPublic). No new polling and no new
 * outbound call.
 *
 * It widens nothing, and that is checked rather than assumed: `/api/fleet`
 * serves the same assembly to the browser behind the session gate with no
 * `isAdmin` check, so every signed-in session already reads these labels,
 * verdicts and last-seen times for its own fleet. Reaching a PEER's copy
 * through the peer-read proxy therefore hands a monitor what a monitor can
 * already read there. Worth stating because route-set membership is not the
 * whole gate story in this codebase: peer-advisor-proxy.ts has entries that
 * server.ts admin-gates on top of the allow-list, and a new route has to be
 * compared against its own local surface rather than against a neighbour.
 *
 * A dashboard with no `fleet.yaml` is not an error and not an empty fleet: it
 * is a single-node install, and it says so with `registered: false` and a
 * roster holding only this host.
 */
export interface FleetRosterResponse extends ReadEnvelope {
  /** False when this host has no fleet registry at all (no `fleet.yaml`, or
   *  one that could not identify this host). `nodes` then holds exactly one
   *  row, this host, and a caller must say "this host knows only itself"
   *  rather than "the fleet is empty", the second is a claim about a fleet,
   *  and a host with no registry has no standing to make one. */
  registered: boolean;
  /** This host's own label in the roster. Always the label of the one row
   *  whose `self` is true. */
  self_label: string;
  /** The server's clock when this body was built. Ages are computed by the
   *  caller against this, never pre-formatted here: a server-formatted "4m
   *  ago" freezes the moment it is serialised, which is this project's
   *  characteristic kept-versus-observed bug. */
  now_ms: number;
  nodes: ReadFleetNode[];
}

export interface ReadFleetNode {
  label: string;
  /** 'aggregator' | 'node' | 'validator' | 'relay', or '' when the row does
   *  not say. Never inferred, fleet-registry.ts's own rule. */
  role: string;
  self: boolean;
  /** The FLEET card's rollup verdict for this row, verbatim: 'ok' | 'warn' |
   *  'unreachable' | 'refused' | 'critical'. */
  verdict: string;
  /** '' when the verdict is ok; the card's own short reason otherwise. */
  detail: string;
  /** Epoch ms of the last poll of this node that ANSWERED, or null when it
   *  has never answered since this process started. This is the "last time it
   *  was reachable" a caller needs in order to say how old a negative is. It
   *  never advances on a failed poll, and never on an answer that came back
   *  from the wrong node. */
  last_answered_ms: number | null;
}

/**
 * `node-config`, no parameters. The four rippled settings the Advisor's
 * config runbook (ADR 0018) is allowed to change, as this host's own
 * `rippled.cfg` has them right now. Added for #59.
 *
 * It is here because "what is node_size on that node" was the question that
 * opened the issue, and no route served it. `system` carries `node_db_cfg`,
 * which is the two key=value settings under `[node_db]`; rippled writes the
 * other two as bare stanzas (`[node_size]` on one line, `huge` on the next).
 * Serving those under `node_db_cfg` would have put settings in an object
 * named for a section they are not in.
 *
 * What this widens, stated precisely rather than waved at. `online_delete`
 * and `advisory_delete` are already served by `system` to any holder of the
 * read token and the System tab renders both, so those two are unchanged.
 * `node_size` and `ledger_history` are NOT rendered anywhere today: the
 * System tab only mentions `node_size` in help text. A session could already
 * get all four for its OWN host through the Advisor's config assessment,
 * which is available at both tiers, so the widening is zero in kind and
 * non-zero in reach: the same class of fact, now for a peer as well as for
 * here. That is the trade this route is for. No key material, no path, no
 * credential, and no other stanza.
 *
 * `cfg_read` false means this host has no `RIPPLED_CFG_PATH` configured, or
 * the file could not be read, a permanent per-install fact, and NOT the same
 * as four nulls under a cfg that was read and has those keys unset.
 * Collapsing the two would render "node_size is unset" about a file nobody
 * ever opened.
 */
export interface NodeConfigResponse extends ReadEnvelope {
  cfg_read: boolean;
  /** When this dashboard last parsed that file, epoch ms, or null when it
   *  never has. The file is read once at startup, so this value can be days
   *  old while the response itself is a millisecond old, and a caller that
   *  reports the request's own freshness would be reporting the wrong
   *  clock. Every reader must date the answer by THIS, not by when it asked. */
  parsed_at_ms: number | null;
  /** rippled's `[node_size]` stanza, 'tiny' | 'small' | 'medium' | 'large' |
   *  'huge' as the file spells it, carried through unchanged. Null when the
   *  stanza is absent, which is rippled's own default of `tiny`; the absence
   *  is the fact, and a caller that wants to name the default says so itself
   *  rather than being handed a value the file does not contain. */
  node_size: string | null;
  /** rippled's `[ledger_history]` stanza, a count, or the word `full`, as
   *  written. Null when absent. */
  ledger_history: string | null;
  /** `[node_db]`'s `online_delete`, the same value `system` already serves. */
  online_delete: number | null;
  /** `[node_db]`'s `advisory_delete`, the same value `system` already serves. */
  advisory_delete: boolean | null;
}

/** Every read response body extends this. */
export interface ReadEnvelope {
  protocol_version: number;
}

export interface ReadErrorBody {
  error: 'not_loopback' | 'read_surface_disabled' | 'method_not_allowed'
       | 'protocol_version_unsupported' | 'unknown_read_path' | 'unauthorized'
       | 'bad_request'
       // The stream's concurrency cap (ADR 0013, decision 6). A read that
       // occupies a socket for minutes is not self-limiting the way a
       // request/response read is, so the newest connection over the cap is
       // refused BY NAME rather than queued — a queued stream is a stream
       // that delivers nothing and says nothing about why.
       | 'stream_capacity_reached';
  /** Present on protocol_version_unsupported. */
  server_version?: number;
  requested_version?: number;
  detail?: string;
}
