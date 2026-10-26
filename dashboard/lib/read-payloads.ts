/**
 * Pure response builders for the D8 first slice's three read routes
 * (advisor-enhancement/d8-aggregator-build-plan.md) — `node-status`,
 * `peers`, `validation-summary`. server.ts's read-surface switch calls
 * these with values it already has in `snapshot`; nothing here polls or
 * mutates anything, which is what makes the field mapping unit-testable
 * without a network (the same split as fleet-health.ts's `deriveVerdict`
 * vs `FleetHealthPoller` — pure derivation, thin untested shell around it).
 *
 * Every field is constructed explicitly rather than spread from a wider
 * object. A spread (`{ ...computeAgreementStats() }`) would serialize
 * whatever that function returns today AND whatever field it grows
 * tomorrow — TypeScript's excess-property check only applies to object
 * literals, not to a variable assigned from a call, so a widened source
 * object would silently widen the read surface. ADR 0008's exclusions are
 * "enforced by absence"; that guarantee only holds if every route names
 * exactly the fields it serves.
 */
import type {
  AmendmentBallotResponse,
  AmendmentCounts,
  ConsensusSnapshotResponse,
  GovernanceResponse,
  NetStatsResponse,
  NodeReachState,
  NodeStatusResponse,
  PeersResponse,
  ReadPeerRow,
  ReleaseIdentityWire,
  SystemResponse,
  ValidationSummaryResponse,
  ValidationsTickResponse,
  FleetRosterResponse,
  NodeConfigResponse,
} from '../types/read-contract.js';
import {
  buildAmendmentBallotRows,
  buildAmendmentVoteSummary,
  nextActivationFromRows,
  type AmendmentFeatureEntry,
  type AmendmentExtInfo,
  type AmendmentDescInfo,
} from './amendments.js';
import type { CountedAmendmentSupport } from './amendment-votes.js';
import { buildPublisherSummary, type ValidatorListSiteEntry } from './publishers.js';

type AnyObj = Record<string, unknown>;

// ── node-status ────────────────────────────────────────────────────────

export interface NodeStatusInput {
  /** snapshot.server_info ?? null — raw rippled server_info.result.info. */
  info: AnyObj | null;
  /** snapshot.domain_status?.domain ?? null */
  domain: string | null;
  /** `os.hostname()` from the call site, not read here — `node:os` stays
   *  out of lib/ so this builder remains a pure function of its input (the
   *  same reason `nowMs` and `clock` are passed in rather than sampled). */
  hostName: string | null;
  /** snapshot.trusted_unl?.size ?? 0 */
  unlTotal: number;
  /** isValidatorNode() */
  isValidator: boolean;
  /** lastAmendmentsBroadcast — typed `unknown` at the call site; validated
   *  here rather than trusted, since it's populated by a background poller
   *  this function has no control over. */
  amendments: unknown;
  /** lastSystemBroadcast's `.clock` field, or null before the relay has
   *  reported one. */
  clock: { ntp_synced?: boolean | null; time_drift_ms?: number | null } | null;
  /** nodeReachState() */
  nodeReach: NodeReachState;
  /** The timestamp `snapshot.server_info` was last successfully written,
   *  or null if this process has never completed a server_info poll.
   *  Deliberately its OWN tracked value rather than derived from
   *  nodeReach.last_ok_ms: nodeReach's "last ok" is coupled today to
   *  pollServerInfo's own success path, but coupling the age of one field
   *  to the reachability bookkeeping of a different concern is exactly the
   *  kind of implicit dependency that breaks quietly the day a second
   *  caller marks the node reachable for an unrelated reason. */
  serverInfoAtMs: number | null;
  /** Injected so this function has no direct Date.now() call — the two-ages
   *  test asserts an exact null-before-first-poll case and an exact
   *  computed-age case, both of which need a fixed "now". */
  nowMs: number;
  /** The install's `.deploy-ref`, already normalised by the caller's reader
   *  (lib/deploy-ref.ts). Null when this host has none or could not read it
   *  — passed in rather than read here for the same reason `hostName` is:
   *  this builder stays a pure function of its input, with no filesystem of
   *  its own. Optional so every existing call site keeps compiling and gets
   *  the honest null. */
  deployRef?: string | null;
  /** What release this install IS, already resolved by the caller's reader
   *  (lib/release-stamp.ts): the stamp, the deploy ref, or unknown. Passed in
   *  for the same reason `deployRef` is, this builder reads no files. Omitted
   *  by a call site that has no reader, and an omitted member is `unknown` to
   *  whoever reads it, which is exactly what it is. */
  release?: ReleaseIdentityWire;
}

// Number(), not a typeof==='number' guard — matches the project's own
// fork-drift convention (server.ts's jq_trans_overflow handling, and
// identity's `network` field): some rippled builds expose a numeric field
// as a stringified counter, and coercing the JS TYPE isn't normalising the
// VALUE. But `typeof v === 'object'` (true for arrays, plain objects, AND
// null) is excluded first — Number([]) is 0 and Number([21]) is 21, both
// finite, and info.peers vs snapshot.peers is one keystroke apart on the
// call side. A rejected non-scalar reads as "not reported", not as a
// silently wrong number.
function numOrNull(v: unknown): number | null {
  if (typeof v === 'object') return null;
  const n = Number(v);
  return v != null && Number.isFinite(n) ? n : null;
}

// For fields the wire contract declares as a Go int/int64 (peer_count,
// network, validated_ledger_index, and the two uptime_s fields) — the
// source is not guaranteed to be a whole number (a fork could report a
// fractional value; nothing here would catch it before it reached JSON),
// and json.Unmarshal into a Go int field fails outright on a fractional
// JSON number. Rounding here is the guarantee the Go struct's type
// declares but cannot itself enforce — the exact class of shape drift the
// parity test does not check.
function intOrNull(v: unknown): number | null {
  const n = numOrNull(v);
  return n === null ? null : Math.round(n);
}

function strOrNull(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function coerceAmendmentCounts(v: unknown): AmendmentCounts | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  // `approaching` is deliberately NOT in this required-number list: it is
  // null on a node that reports no vote tally (AmendmentCounts' own doc
  // comment), and requiring a number there would discard the entire
  // amendments block on exactly the tracking nodes this fix exists for.
  const fields = ['enabled', 'supported', 'vetoed', 'pending'] as const;
  for (const f of fields) {
    if (typeof o[f] !== 'number') return null;
  }
  return {
    enabled: o.enabled as number,
    supported: o.supported as number,
    vetoed: o.vetoed as number,
    pending: o.pending as number,
    approaching: typeof o.approaching === 'number' ? o.approaching : null,
  };
}

export function buildNodeStatusFields(input: NodeStatusInput): Omit<NodeStatusResponse, 'protocol_version'> {
  const info = input.info ?? {};
  const validatedLedger = (info.validated_ledger ?? null) as AnyObj | null;
  const clock = input.clock ?? {};
  return {
    server_state: strOrNull(info.server_state),
    validated_ledger_index: validatedLedger ? intOrNull(validatedLedger.seq) : null,
    complete_ledgers: strOrNull(info.complete_ledgers),
    uptime_s: intOrNull(info.uptime),
    build_version: strOrNull(info.build_version),
    base_fee_xrp: validatedLedger ? numOrNull(validatedLedger.base_fee_xrp) : null,
    load_factor: numOrNull(info.load_factor),
    peer_count: intOrNull(info.peers),
    // intOrNull already keeps the two facts apart the way the contract
    // needs: an ABSENT network_id (rippled's unconfigured default, i.e.
    // Mainnet) becomes null, while a configured `network_id = 0` survives
    // as 0. Nothing to collapse here — see IdentityResponse.network in
    // read-contract.ts for why those are different config, same network.
    network: intOrNull(info.network_id),
    pubkey_validator: strOrNull(info.pubkey_validator),
    pubkey_node: strOrNull(info.pubkey_node),
    host_name: strOrNull(input.hostName),
    // rippled's self-identifier, from server_info — a different fact from
    // host_name just above (container id vs machine name under Docker), and
    // sourced from the node rather than from this process for that reason.
    hostid: strOrNull(info.hostid),
    domain: input.domain,
    unl_total: input.unlTotal,
    is_validator: input.isValidator,
    amendments: coerceAmendmentCounts(input.amendments),
    time_drift_ms: typeof clock.time_drift_ms === 'number' ? clock.time_drift_ms : null,
    ntp_synced: typeof clock.ntp_synced === 'boolean' ? clock.ntp_synced : null,
    server_info_age_ms: input.serverInfoAtMs == null ? null : Math.max(0, input.nowMs - input.serverInfoAtMs),
    node_reach: input.nodeReach,
    // `?? null`, never `?? ''` and never a fabricated placeholder: an
    // install with no `.deploy-ref` reports none, and a reader downstream
    // must be able to tell that from a ref that is merely different.
    deploy_ref: input.deployRef ?? null,
    // ADR 0022 decision 6: the release identity rides the route every fleet
    // poll already reads, so an aggregator grades a whole fleet against one
    // release.json without a second route or a second read. Omitted rather
    // than sent as `unknown` when the caller has no reader: absent and
    // unknown mean the same thing to a consumer, and only one of them adds
    // bytes to every poll on hosts that never wired it.
    ...(input.release ? { release: input.release } : {}),
  };
}

// ── peers ─────────────────────────────────────────────────────────────

/** The subset of the enriched PeerRow (server.ts's enrichPeers output) this
 *  route needs. Declared locally rather than imported from server.ts —
 *  server.ts is the entrypoint script and imports FROM lib/, never the
 *  reverse (same discipline fleet-health.ts's own inline body types
 *  follow). */
export interface PeerLike {
  address?: string;
  inbound?: boolean;
  latency?: number;
  version?: string;
  uptime?: number;
  country?: string;
  host?: string;
  sanity?: string;
}

const LATENCY_ISSUE_MS = 1000;

/** Mirrors overview.html's applyPeers() issue derivation exactly (sanity
 *  !== 'sane', or latency over 1000ms) — a peer Overview built from this
 *  route must compute the identical verdict a local Overview does. */
function deriveIssue(p: PeerLike): { hasIssue: boolean; reasons: string[] } {
  const lat = typeof p.latency === 'number' ? p.latency : 0;
  const sanity = p.sanity || 'sane';
  const reasons: string[] = [];
  if (sanity !== 'sane') reasons.push('rippled marked sanity: ' + sanity);
  if (lat > LATENCY_ISSUE_MS) reasons.push('high latency: ' + lat + ' ms');
  return { hasIssue: reasons.length > 0, reasons };
}

export function buildPeersFields(
  peers: PeerLike[],
  nodeReach: NodeReachState,
): Omit<PeersResponse, 'protocol_version'> {
  const rows: ReadPeerRow[] = peers.map((p) => {
    const { hasIssue, reasons } = deriveIssue(p);
    return {
      address: p.address ?? null,
      host: p.host ?? p.address ?? null,
      country: p.country ?? null,
      inbound: !!p.inbound,
      // Rounded, not passed through raw: the Go mirror declares these ints
      // (LatencyMs, UptimeS *int/*int64), and json.Unmarshal into an int
      // field fails outright on a fractional JSON number. Nothing upstream
      // guarantees rippled reports a whole millisecond or a whole second.
      latency_ms: typeof p.latency === 'number' && Number.isFinite(p.latency) ? Math.round(p.latency) : null,
      version: p.version ?? null,
      uptime_s: typeof p.uptime === 'number' && Number.isFinite(p.uptime) ? Math.round(p.uptime) : null,
      sanity: p.sanity ?? null,
      has_issue: hasIssue,
      issue_reasons: reasons,
    };
  });
  const out = rows.filter((r) => !r.inbound).length;
  const inCount = rows.filter((r) => r.inbound).length;
  const issue = rows.filter((r) => r.has_issue).length;
  const lats = rows.map((r) => r.latency_ms).filter((n): n is number => typeof n === 'number' && n > 0).sort((a, b) => a - b);
  const latency_p90_ms = lats.length ? lats[Math.min(lats.length - 1, Math.floor(lats.length * 0.9))] : null;
  return {
    peers: rows,
    total: out + inCount,
    out,
    in: inCount,
    issue,
    latency_p90_ms,
    node_reach: nodeReach,
  };
}

// ── validation-summary ───────────────────────────────────────────────

export interface AgreementStatsLike {
  agreement_1h: number;
  missed_1h: number;
  agreement_24h: number;
  missed_24h: number;
  unl_active_1h: number;
  unl_total: number;
  is_validator: boolean;
}

/** Re-emits computeAgreementStats()'s output field by field — "verbatim"
 *  (build-plan wording) means the same VALUES, not the same object
 *  identity. A field computeAgreementStats() grows later does not
 *  automatically join this route; it has to be named here too. */
export function buildValidationSummaryFields(stats: AgreementStatsLike): Omit<ValidationSummaryResponse, 'protocol_version'> {
  return {
    agreement_1h: stats.agreement_1h,
    missed_1h: stats.missed_1h,
    agreement_24h: stats.agreement_24h,
    missed_24h: stats.missed_24h,
    unl_active_1h: stats.unl_active_1h,
    unl_total: stats.unl_total,
    is_validator: stats.is_validator,
  };
}

// ── consensus-snapshot ──────────────────────────────────────────────────

/** One raw metrics-table sample, the same shape db.ts's queryRecent already
 *  returns ({ ts (ms), value }) — passed straight through from server.ts
 *  rather than re-typed, so this function has no db.ts import of its own. */
export interface SnapshotMetricSample { ts: number; value: number; }

/** The most recent ledger close this process has observed, cached at the
 *  exact same call site server.ts's own `broadcast('ledger:close', ...)`
 *  reads from — closeDeltaS and txnCount together, so the two can never
 *  skew against each other the way separately-updated caches could. Null
 *  before this process has seen a single ledgerClosed event. */
export interface LastCloseSummary {
  closeDeltaS: number | null; // null when the delta was sanity-clipped or this is the first close after a restart
  txnCount: number;
  atMs: number;
}

export interface ConsensusSnapshotInput {
  /** snapshot.server_info ?? null */
  info: AnyObj | null;
  /** snapshot.fee ?? null */
  fee: AnyObj | null;
  /** validationTsLog.length at call time — the identical rolling-60s count
   *  the `validations_tick` broadcast already carries as rate_per_min. Not
   *  scoped to the trusted UNL: a stock node sees every network validation,
   *  not just its own, so this fills for a non-validator peer too. */
  validationRatePerMin: number;
  /** queryRecent('close_time', N) — oldest first. Only ever contains
   *  non-clipped deltas (server.ts skips the write when the sanity check at
   *  the ledgerClosed handler fails), which is exactly what the 1h average
   *  should skip too. */
  closeTimeSamples: SnapshotMetricSample[];
  /** queryRecent('txn_count', N) — oldest first. Written unconditionally on
   *  every ledgerClosed regardless of the close_time sanity check, so this
   *  is the more reliable series for "how many ledgers actually closed in
   *  the last 60s" than closeTimeSamples would be. */
  txnCountSamples: SnapshotMetricSample[];
  lastClose: LastCloseSummary | null;
  /** server.ts's own serverInfoAtMs — identical value node-status already
   *  uses for its own server_info_age_ms. */
  serverInfoAtMs: number | null;
  /** The `fee` RPC's own poll timestamp — a second, independent staleness
   *  clock from server_info's (pollFee runs on its own 10s interval). */
  feeAtMs: number | null;
  nodeReach: NodeReachState;
  nowMs: number;
}

function convergeTimeS(lastClose: AnyObj): number | null {
  if (typeof lastClose.converge_time_s === 'number') return lastClose.converge_time_s;
  if (typeof lastClose.converge_time === 'number') return lastClose.converge_time / 1000;
  return null;
}

function ageMs(atMs: number | null, nowMs: number): number | null {
  return atMs == null ? null : Math.max(0, nowMs - atMs);
}

export function buildConsensusSnapshotFields(input: ConsensusSnapshotInput): Omit<ConsensusSnapshotResponse, 'protocol_version'> {
  const info = input.info ?? {};
  const fee = input.fee ?? {};
  const drops = (fee.drops ?? {}) as AnyObj;
  const lastCloseInfo = (info.last_close ?? {}) as AnyObj;
  const validatedLedger = (info.validated_ledger ?? null) as AnyObj | null;

  // 1h rolling average — filter by timestamp, not sample count, so a quiet
  // period doesn't poison the average with data from before it (identical
  // rule to consensus.html's own client-side avgClose1h computation).
  const cutoff1h = input.nowMs - 3_600_000;
  const within1h = input.closeTimeSamples.filter((s) => s.ts >= cutoff1h);
  const avgClose1hS = within1h.length > 0
    ? within1h.reduce((a, s) => a + s.value, 0) / within1h.length
    : null;

  // Ledgers/min — count of ledger closes observed in the last 60s. 0 is a
  // real fact (nothing closed), so this is never null.
  const cutoff60s = input.nowMs - 60_000;
  const ledgersPerMin = input.txnCountSamples.filter((s) => s.ts >= cutoff60s).length;

  const closeDeltaS = input.lastClose?.closeDeltaS ?? null;
  const txnCount = input.lastClose ? input.lastClose.txnCount : null;
  const tps1m = (closeDeltaS != null && closeDeltaS > 0 && txnCount != null)
    ? Math.round(txnCount / closeDeltaS)
    : null;

  return {
    avg_close_1h_s: avgClose1hS,
    proposers: intOrNull(lastCloseInfo.proposers),
    quorum_req: intOrNull(info.validation_quorum),
    converge_time_s: convergeTimeS(lastCloseInfo),
    ledger_age_s: validatedLedger ? intOrNull(validatedLedger.age) : null,
    close_delta_s: closeDeltaS,
    ledgers_per_min: ledgersPerMin,
    tx_last_ledger: txnCount,
    tps_1m: tps1m,
    validation_rate_per_min: input.validationRatePerMin,
    fee_escalation: numOrNull(info.load_factor_fee_escalation),
    open_ledger_fee_drops: intOrNull(drops.open_ledger_fee),
    queue_size: intOrNull(fee.current_queue_size),
    job_overflow: intOrNull(info.jq_trans_overflow),
    server_info_age_ms: ageMs(input.serverInfoAtMs, input.nowMs),
    fee_age_ms: ageMs(input.feeAtMs, input.nowMs),
    last_close_age_ms: input.lastClose ? ageMs(input.lastClose.atMs, input.nowMs) : null,
    node_reach: input.nodeReach,
  };
}

// ── amendment-ballot ─────────────────────────────────────────────────────

export interface AmendmentBallotInput {
  /** snapshot.feature ?? {} */
  features: Record<string, AmendmentFeatureEntry>;
  /** snapshot.xrpscan_amendments */
  ext: Record<string, AmendmentExtInfo> | undefined;
  /** snapshot.amendment_descriptions */
  desc: Record<string, AmendmentDescInfo> | undefined;
  /** The dashboard's own count from the trusted validations stream
   *  (lib/amendment-votes.ts), null before the first voting ledger since
   *  start. Consulted only for rows the node reports no tally on. */
  counted: CountedAmendmentSupport | null;
  /** When pollFeature() last successfully wrote snapshot.feature — null
   *  before this process's first successful poll (same convention as
   *  serverInfoAtMs/feeAtMs). */
  featureAtMs: number | null;
  /** When the amendment knowledge library (the source of `desc` above) was
   *  last genuinely refreshed from xrpl.org. Read out of the file's own
   *  `refreshed_at` line, not the file's mtime (#542: a deploy overwrites
   *  the file with the tree's shipped copy, which would make mtime read as
   *  "just refreshed" the moment it is actually the stalest it will ever
   *  be). null before any refresh this process or a prior one recorded. */
  libraryAtMs: number | null;
  nodeReach: NodeReachState;
  nowMs: number;
}

/** Thin wire wrapper around buildAmendmentBallotRows (lib/amendments.ts) —
 *  the row computation itself lives there, shared with server.ts's own
 *  local-page builder; this just adds the route's envelope fields. */
export function buildAmendmentBallotFields(input: AmendmentBallotInput): Omit<AmendmentBallotResponse, 'protocol_version'> {
  return {
    rows: buildAmendmentBallotRows(input.features, input.ext, input.desc, input.counted),
    feature_age_ms: ageMs(input.featureAtMs, input.nowMs),
    library_age_ms: ageMs(input.libraryAtMs, input.nowMs),
    node_reach: input.nodeReach,
  };
}

// ── governance ───────────────────────────────────────────────────────────

export interface GovernanceInput {
  /** snapshot.feature ?? {} */
  features: Record<string, AmendmentFeatureEntry>;
  /** snapshot.xrpscan_amendments — only reached for next-activation's NAME,
   *  which falls back to the hash the same way the ballot table does. */
  ext: Record<string, AmendmentExtInfo> | undefined;
  /** The dashboard's own count, as for the ballot route; the card's
   *  threshold-met and approaching figures measure on it when the node
   *  reports no tally, the same precedence as the rows. */
  counted: CountedAmendmentSupport | null;
  /** snapshot.validator_list_sites ?? [] */
  sites: ValidatorListSiteEntry[];
  /** snapshot.server_info ?? null — read for `amendment_blocked` only. */
  info: Record<string, unknown> | null;
  /** When pollFeature() last successfully wrote snapshot.feature. */
  featureAtMs: number | null;
  /** When pollValidatorListSites() last successfully wrote
   *  snapshot.validator_list_sites — its own clock, its own poller. */
  sitesAtMs: number | null;
  nodeReach: NodeReachState;
  nowMs: number;
}

/** The Governance tab minus its ballot table, for a peer. Every aggregate
 *  comes from the same two shared builders the local page uses
 *  (lib/amendments.ts, lib/publishers.ts), so the two views of one node can
 *  never disagree about the same rippled response. */
export function buildGovernanceFields(input: GovernanceInput): Omit<GovernanceResponse, 'protocol_version'> {
  const summary = buildAmendmentVoteSummary(input.features, input.counted);
  const next = nextActivationFromRows(buildAmendmentBallotRows(input.features, input.ext, undefined, input.counted));
  const pubs = buildPublisherSummary(input.sites, input.nowMs);
  return {
    amendment_blocked: Boolean(input.info?.amendment_blocked),
    threshold_met_count: summary.threshold_met,
    approaching_threshold_count: summary.approaching,
    our_votes: {
      yes: summary.our_votes.yes,
      no: summary.our_votes.no,
      default: summary.our_votes.default,
    },
    next_activation_status: next.status,
    next_activation_name: next.name,
    publishers: {
      site_count: pubs.site_count,
      refresh_status: pubs.refresh_status,
      refresh_age_s: pubs.refresh_age_s,
      list_expiry_days: pubs.list_expiry_days,
      cert_expiry_days: pubs.cert_expiry_days,
      sites: pubs.sites.map((s) => ({
        site: s.site,
        status: s.status,
        refresh_age_s: s.refresh_age_s,
        list_expiry_days: s.list_expiry_days,
        cert_expiry_days: s.cert_expiry_days,
        sequence: s.sequence,
      })),
    },
    feature_age_ms: ageMs(input.featureAtMs, input.nowMs),
    sites_age_ms: ageMs(input.sitesAtMs, input.nowMs),
    node_reach: input.nodeReach,
  };
}

// ── system ────────────────────────────────────────────────────────────

type SystemFields = Omit<SystemResponse, 'protocol_version'>;

interface SystemMeterFields { used_pct: number | null; used_bytes: number | null; total_bytes: number | null; }

/** Memory has two fields swap and disk do not, so it gets its own coercer
 *  rather than widening the shared one — cache on a swap block would be a
 *  field with nothing behind it. Absent (an older relay, or a peer on an
 *  older build) stays null: never 0, which is a real reading of a box with
 *  nothing cached. */
function coerceMemorySection(v: unknown): SystemFields['memory'] {
  const o = (v && typeof v === 'object') ? v as AnyObj : {};
  return {
    used_pct: numOrNull(o.used_pct),
    used_bytes: numOrNull(o.used_bytes),
    total_bytes: numOrNull(o.total_bytes),
    cache_pct: numOrNull(o.cache_pct),
    cache_bytes: numOrNull(o.cache_bytes),
  };
}

/** Object-level nullable: null means no usable pair of get_counts samples
 *  exists yet on that host. `read_hit_pct` is nullable inside a present
 *  object as well — an interval with no reads is not a 0% hit rate. */
function coerceNodeStore(v: unknown): SystemFields['nodestore'] {
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    read_hit_pct: numOrNull(o.read_hit_pct),
    reads_per_s: numOrNull(o.reads_per_s),
    writes_per_s: numOrNull(o.writes_per_s),
    read_bps: numOrNull(o.read_bps),
    written_bps: numOrNull(o.written_bps),
  };
}

function coerceMeterSection(v: unknown): SystemMeterFields {
  const o = (v && typeof v === 'object') ? v as AnyObj : {};
  return {
    used_pct: numOrNull(o.used_pct),
    used_bytes: numOrNull(o.used_bytes),
    total_bytes: numOrNull(o.total_bytes),
  };
}

// Not shared with node-status's inline check — that one destructures a
// single field off an object already known non-null; this one has to guard
// the object itself too, since `clock`/`node_db_cfg` can each be absent.
function boolOrNull(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}

/** The all-null envelope served before this process's first `pushSystem()`
 *  tick — see SystemResponse's doc comment in read-contract.ts. Every
 *  section-level field is null uniformly, rather than some sections being
 *  `null` and others being an object of all-null fields; a consumer checking
 *  `body.cpu &&` (the "has this process ticked at all" signal every peer-view
 *  call site uses) gets a consistent answer regardless of which section it
 *  happens to check first. */
const ALL_NULL_SYSTEM_FIELDS: SystemFields = {
  cpu: null, memory: null, swap: null, disk: null, pressure: null,
  oom_kills: null, nodestore: null, nudb_size_bytes: null, nudb_measured_by: null, nudb_peak_bytes_24h: null,
  mount_free_days_est: null, nudb_growth: null, rippled_data_path: null, nudb_walk_error: null,
  clock: null, rippled: null, disk_io: null,
  host: null, get_counts: null, get_counts_canonical: null,
  node_db_cfg: null, shard_count: null,
};

function coercePressure(v: unknown): { cpu: number; memory: number; io: number } {
  // readPressureSome/readOomKills already default to 0 (never null) when PSI
  // or vmstat is unavailable on that kernel — numOrNull would turn a missing
  // key into null, silently changing "0, a real reading" into "not reported"
  // for a peer relative to what the same object reads locally. `?? 0`, not
  // numOrNull, preserves that.
  const o = (v && typeof v === 'object') ? v as AnyObj : {};
  return {
    cpu: numOrNull(o.cpu) ?? 0,
    memory: numOrNull(o.memory) ?? 0,
    io: numOrNull(o.io) ?? 0,
  };
}

function coerceDiskIo(v: unknown): SystemFields['disk_io'] {
  // Genuinely object-level nullable (readDiskIo() returns null outright when
  // /proc/diskstats is unreadable) — unlike pressure, a missing object here
  // stays null rather than becoming an object of zeros.
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    read_iops: numOrNull(o.read_iops) ?? 0,
    write_iops: numOrNull(o.write_iops) ?? 0,
    read_bps: numOrNull(o.read_bps) ?? 0,
    write_bps: numOrNull(o.write_bps) ?? 0,
    util_pct: numOrNull(o.util_pct) ?? 0,
  };
}

function coerceHostMeta(v: unknown): { hostname: string; os_name: string; kernel: string; architecture: string } | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    hostname: strOrNull(o.hostname) ?? '',
    os_name: strOrNull(o.os_name) ?? '',
    kernel: strOrNull(o.kernel) ?? '',
    architecture: strOrNull(o.architecture) ?? '',
  };
}

function coerceHost(v: unknown): SystemFields['host'] {
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    uptime_s: numOrNull(o.uptime_s),
    entropy_avail: numOrNull(o.entropy_avail),
    inode_usage_pct: numOrNull(o.inode_usage_pct),
    rippled_uptime_s: numOrNull(o.rippled_uptime_s),
    meta: coerceHostMeta(o.meta),
  };
}

function coerceGetCounts(v: unknown): SystemFields['get_counts'] {
  // Object-level nullable: snapshot.get_counts is null until this process's
  // own periodic get_counts RPC has completed at least once, independent of
  // pushSystem's own tick.
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    AL_hit_rate: numOrNull(o.AL_hit_rate),
    AL_size: numOrNull(o.AL_size),
    SLE_hit_rate: numOrNull(o.SLE_hit_rate),
    node_reads_total: numOrNull(o.node_reads_total),
    node_reads_hit: numOrNull(o.node_reads_hit),
    node_writes: numOrNull(o.node_writes),
    write_load: numOrNull(o.write_load),
    treenode_cache_size: numOrNull(o.treenode_cache_size),
  };
}

function coerceGetCountsCanonical(v: unknown): SystemFields['get_counts_canonical'] {
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    SHAMapAccountStateLeafNode: numOrNull(o.SHAMapAccountStateLeafNode),
    SHAMapInnerNode: numOrNull(o.SHAMapInnerNode),
    SHAMapItem: numOrNull(o.SHAMapItem),
    STLedgerEntry: numOrNull(o.STLedgerEntry),
  };
}

/** Who measured the peer's store, when it was not that peer's own dashboard.
 *  Both fields or nothing: a provenance with no timestamp cannot be rendered
 *  as "measured by the Advisor at ...", and half of it would read as a
 *  reading this dashboard took. */
function coerceMeasuredBy(v: unknown): SystemFields['nudb_measured_by'] {
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  if (o.source !== 'advisor' || typeof o.at !== 'string' || o.at === '') return null;
  return { source: 'advisor', at: o.at };
}

function coerceNudbGrowth(v: unknown): SystemFields['nudb_growth'] {
  // Object-level nullable: null means this host has no RIPPLED_DATA_PATH, so
  // there is no store here to measure — the same permanent per-install fact
  // nudb_size_bytes already carries. The status is passed through only when
  // it is one of the three the contract names; anything else is a peer
  // speaking a shape this build does not know, and is read as absent rather
  // than forwarded verbatim.
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  const status = o.status;
  if (status !== 'ok' && status !== 'not_growing' && status !== 'needs_history') return null;
  const rot = (o.last_rotation && typeof o.last_rotation === 'object') ? o.last_rotation as AnyObj : null;
  const rotTs = rot ? numOrNull(rot.ts) : null;
  const rotDrop = rot ? numOrNull(rot.drop_bytes) : null;
  return {
    status,
    days: numOrNull(o.days),
    peak_growth_bytes_per_day: numOrNull(o.peak_growth_bytes_per_day),
    peak_7d_bytes: numOrNull(o.peak_7d_bytes),
    last_rotation: (rotTs !== null && rotDrop !== null) ? { ts: rotTs, drop_bytes: rotDrop } : null,
  };
}

function coerceNodeDbCfg(v: unknown): SystemFields['node_db_cfg'] {
  // Object-level nullable: null means no RIPPLED_CFG_PATH is configured on
  // this host at all (permanent per-install fact) — see SystemResponse's
  // doc comment on why this must not collapse to { online_delete: null }.
  if (!v || typeof v !== 'object') return null;
  const o = v as AnyObj;
  return {
    online_delete: numOrNull(o.online_delete),
    advisory_delete: boolOrNull(o.advisory_delete),
  };
}

function coerceShardCount(v: unknown): SystemFields['shard_count'] {
  // The one field in this route that is NOT run through numOrNull — see the
  // doc comment in read-contract.ts: Number('not_sharded') is NaN, and
  // numOrNull would turn the common, correct answer into null.
  if (v === 'not_sharded') return 'not_sharded';
  return numOrNull(v);
}

/** `system` — server.ts's `lastSystemBroadcast`, typed `unknown` at the call
 *  site (`let lastSystemBroadcast: unknown = null`) since it's populated by
 *  `pushSystem()`'s own 5s poller (plus the independent get_counts/
 *  crawl_shards pollers for two of its fields), not this function. Passing
 *  `null` (before the first tick completes) yields the all-null envelope,
 *  never a zeroed reading — see SystemResponse's doc comment in
 *  read-contract.ts for why that distinction matters, and why several
 *  sections stay independently nullable even once ticking normally. Every
 *  field named explicitly; a spread of the wider broadcast object would
 *  widen the read surface every time pushSystem grows a field, exactly what
 *  this file's own header comment warns against. */
export function buildSystemFields(broadcast: unknown): SystemFields {
  if (!broadcast || typeof broadcast !== 'object') return ALL_NULL_SYSTEM_FIELDS;
  const b = broadcast as AnyObj;
  const cpu = (b.cpu && typeof b.cpu === 'object') ? b.cpu as AnyObj : {};
  return {
    cpu: {
      busy_pct: numOrNull(cpu.busy_pct),
      iowait_pct: numOrNull(cpu.iowait_pct),
      steal_pct: numOrNull(cpu.steal_pct),
      cores: numOrNull(cpu.cores),
      load_1m: numOrNull(cpu.load_1m),
      load_5m: numOrNull(cpu.load_5m),
      load_15m: numOrNull(cpu.load_15m),
    },
    memory: coerceMemorySection(b.memory),
    swap: coerceMeterSection(b.swap),
    disk: coerceMeterSection(b.disk),
    pressure: coercePressure(b.pressure),
    oom_kills: numOrNull(b.oom_kills),
    nodestore: coerceNodeStore(b.nodestore),
    nudb_size_bytes: numOrNull(b.nudb_size_bytes),
    nudb_measured_by: coerceMeasuredBy(b.nudb_measured_by),
    nudb_peak_bytes_24h: numOrNull(b.nudb_peak_bytes_24h),
    mount_free_days_est: numOrNull(b.mount_free_days_est),
    nudb_growth: coerceNudbGrowth(b.nudb_growth),
    // The two facts system.html names the store's state from: where it is
    // measured, and whether the last walk read it. Absent (an older build)
    // is null here, and the ALL_NULL envelope above is gated out by the page
    // on `cpu`, so null only ever reaches a reader from a host that ticked.
    rippled_data_path: strOrNull(b.rippled_data_path),
    nudb_walk_error: strOrNull(b.nudb_walk_error),
    clock: {
      ntp_synced: boolOrNull((b.clock as AnyObj | undefined)?.ntp_synced),
      time_drift_ms: numOrNull((b.clock as AnyObj | undefined)?.time_drift_ms),
    },
    rippled: {
      pid: numOrNull((b.rippled as AnyObj | undefined)?.pid),
      cpu_pct: numOrNull((b.rippled as AnyObj | undefined)?.cpu_pct) ?? 0,
      rss_bytes: numOrNull((b.rippled as AnyObj | undefined)?.rss_bytes),
      threads: numOrNull((b.rippled as AnyObj | undefined)?.threads),
    },
    disk_io: coerceDiskIo(b.disk_io),
    host: coerceHost(b.host),
    get_counts: coerceGetCounts(b.get_counts),
    get_counts_canonical: coerceGetCountsCanonical(b.get_counts_canonical),
    node_db_cfg: coerceNodeDbCfg(b.node_db_cfg),
    shard_count: coerceShardCount(b.shard_count),
  };
}

// ── net-stats ─────────────────────────────────────────────────────────

type NetStatsFields = Omit<NetStatsResponse, 'protocol_version'>;

/** The all-null envelope served when `lastNetStatsBroadcast` is still
 *  `null` — either this process has never received a relay push for this
 *  node, or (for a peer) that node has no relay configured at all. See
 *  NetStatsResponse's doc comment in read-contract.ts. */
const ALL_NULL_NET_STATS_FIELDS: NetStatsFields = {
  interface: null, interface_source: null,
  rx_bps: null, tx_bps: null, rx_pps: null, tx_pps: null,
  tcp_established: null, tcp_retrans_per_sec: null,
  rx_errors: null, tx_errors: null, rx_drops: null, tx_drops: null,
  tcp_time_wait: null,
  monthly_used_bytes: null, monthly_cap_bytes: null, monthly_pct: null,
  http_rpc_connections: null, admin_ws_connections: null, ws_public_connections: null,
};

/** `net-stats` — server.ts's `lastNetStatsBroadcast`, typed `unknown` at the
 *  call site (`let lastNetStatsBroadcast: unknown = null`) since it's
 *  populated by `handleRelayPush` on every relay push, not this function.
 *  Passing `null` (no relay push ever received for this node — a permanent
 *  state for a peer with no relay, not just a startup gap) yields the
 *  all-null envelope, never a zeroed "idle interface" reading — see
 *  NetStatsResponse's doc comment in read-contract.ts. Every field named
 *  explicitly; a spread of the wider broadcast object would widen the read
 *  surface every time handleRelayPush grows a field, exactly what this
 *  file's own header comment warns against. */
export function buildNetStatsFields(broadcast: unknown): NetStatsFields {
  if (!broadcast || typeof broadcast !== 'object') return ALL_NULL_NET_STATS_FIELDS;
  const b = broadcast as AnyObj;
  return {
    interface: strOrNull(b.interface),
    interface_source: strOrNull(b.interface_source),
    rx_bps: numOrNull(b.rx_bps),
    tx_bps: numOrNull(b.tx_bps),
    rx_pps: numOrNull(b.rx_pps),
    tx_pps: numOrNull(b.tx_pps),
    tcp_established: numOrNull(b.tcp_established),
    tcp_retrans_per_sec: numOrNull(b.tcp_retrans_per_sec),
    rx_errors: numOrNull(b.rx_errors),
    tx_errors: numOrNull(b.tx_errors),
    rx_drops: numOrNull(b.rx_drops),
    tx_drops: numOrNull(b.tx_drops),
    tcp_time_wait: numOrNull(b.tcp_time_wait),
    monthly_used_bytes: numOrNull(b.monthly_used_bytes),
    monthly_cap_bytes: numOrNull(b.monthly_cap_bytes),
    monthly_pct: numOrNull(b.monthly_pct),
    http_rpc_connections: numOrNull(b.http_rpc_connections),
    admin_ws_connections: numOrNull(b.admin_ws_connections),
    ws_public_connections: numOrNull(b.ws_public_connections),
  };
}

// ── validations-tick ─────────────────────────────────────────────────────

type ValidationsTickFields = Omit<ValidationsTickResponse, 'protocol_version'>;

/** Server has never tracked a validation round for this process — the
 *  transient state before the first `current_round` exists (module load, or
 *  a request that somehow lands before the 1Hz interval's first tick). No
 *  permanent all-null state exists otherwise: unlike `net-stats`, every
 *  dashboard process serves this route from its own in-memory round
 *  counters, with no dependency on an external relay ever being installed. */
const ALL_NULL_VALIDATIONS_TICK_FIELDS: ValidationsTickFields = {
  ledger_index: null, received: null, unl_received: null, unl_size: null,
  quorum: null, our_validated: null, rate_per_min: null, rate_per_sec: null,
};

/** rippled's unsigned -1 sentinel for `validation_quorum`, reported until a
 *  freshly-restarted node's UNL has loaded (renderQuorumBar's own comment,
 *  overview.html ~line 3214). A domain no real network can have — served as
 *  `null`, never as the literal number. */
const QUORUM_UNKNOWN_SENTINEL = 4294967295;

function coerceQuorum(v: unknown): number | null {
  const n = numOrNull(v);
  return n === null || n === QUORUM_UNKNOWN_SENTINEL ? null : n;
}

/** `validations-tick` — Overview's "Validations received / quorum" row, for
 *  a peer. `input` is the same shape server.ts's own `validations_tick` WS
 *  broadcast builds (`current_round`, `rate_per_min`, `rate_per_sec`), plus
 *  `quorum_raw` (`snapshot.server_info.validation_quorum`) carried alongside
 *  it — the WS tick itself never includes quorum, but the quorum bar needs
 *  both. Typed `unknown` at the call site since it's assembled fresh from
 *  live module-scope vars on every request, not trusted wholesale. */
export function buildValidationsTickFields(input: unknown): ValidationsTickFields {
  if (!input || typeof input !== 'object') return ALL_NULL_VALIDATIONS_TICK_FIELDS;
  const b = input as AnyObj;
  const cr = (b.current_round && typeof b.current_round === 'object') ? b.current_round as AnyObj : null;
  if (!cr) return ALL_NULL_VALIDATIONS_TICK_FIELDS;
  return {
    ledger_index: numOrNull(cr.ledger_index),
    received: numOrNull(cr.received),
    unl_received: numOrNull(cr.unl_received),
    unl_size: numOrNull(cr.unl_size),
    quorum: coerceQuorum(b.quorum_raw),
    our_validated: typeof cr.our_validated === 'boolean' ? cr.our_validated : null,
    rate_per_min: numOrNull(b.rate_per_min),
    rate_per_sec: numOrNull(b.rate_per_sec),
  };
}

// ── #59, the fleet roster, and this host's node config ────────────────

type FleetRosterFields = Omit<FleetRosterResponse, 'protocol_version'>;
type NodeConfigFields = Omit<NodeConfigResponse, 'protocol_version'>;

/** One input row: FleetPeerPublic's own fields, narrowed to what this route
 *  serves. Typed structurally rather than importing FleetPeerPublic so the
 *  route cannot grow a field just because that card did, the same
 *  name-every-field discipline the header comment above sets out. */
export interface FleetRosterInputNode {
  label: string;
  self: boolean;
  verdict: string;
  detail: string;
  last_seen_ms: number | null;
  role?: string;
}

/**
 * `fleet`, the roster this dashboard holds, and what it last observed of
 * each member (#59).
 *
 * `rows` is fleetView()'s nodes, or null on a host with no fleet registry.
 * Null is NOT an error and NOT an empty fleet: it is a single-node install,
 * and it answers with `registered: false` and one row for this host, so a
 * caller says "this host knows only itself" rather than "the fleet is
 * empty". A host with no registry has no standing to make a claim about a
 * fleet.
 *
 * `selfLabel` is what this host calls itself when there is no registry to
 * name it (deriveSelfLabel's answer, which falls back to the hostname). When
 * there IS a registry the roster's own self row wins, because the label a
 * fleet knows a host by is the one every other surface in that fleet uses.
 */
export function buildFleetRosterFields(
  rows: FleetRosterInputNode[] | null,
  selfLabel: string,
  nowMs: number,
): FleetRosterFields {
  if (!rows || rows.length === 0) {
    return {
      registered: false,
      self_label: selfLabel,
      now_ms: nowMs,
      nodes: [{
        label: selfLabel,
        role: '',
        self: true,
        verdict: 'ok',
        detail: '',
        // This host answering about itself is not a poll that succeeded at
        // some past moment; it is the moment. Anything else would date this
        // host's own reading to a poll it never makes of itself.
        last_answered_ms: nowMs,
      }],
    };
  }
  const selfRow = rows.find((r) => r.self);
  return {
    registered: true,
    self_label: selfRow?.label ?? selfLabel,
    now_ms: nowMs,
    nodes: rows.map((r) => ({
      label: r.label,
      role: typeof r.role === 'string' ? r.role : '',
      self: r.self,
      verdict: r.verdict,
      detail: r.detail,
      // The self row's own last_seen_ms is already "now" while it exists
      // (fleet-health.ts's buildSelfPeer), so it needs no special case.
      last_answered_ms: r.last_seen_ms,
    })),
  };
}

/** The shape server.ts's rippled.cfg parser keeps. Declared here so the
 *  builder is testable without importing the server. */
export interface NodeCfgInput {
  /** Epoch ms of the parse that produced these four values. */
  parsed_at_ms: number;
  node_size: string | null;
  ledger_history: string | null;
  online_delete: number | null;
  advisory_delete: boolean | null;
}

/**
 * `node-config`, the four allow-listed rippled settings this host runs
 * (#59). `cfg` null means no `RIPPLED_CFG_PATH` was configured, or the file
 * could not be read: a permanent per-install fact, served as `cfg_read:
 * false` beside four nulls and never as four nulls alone.
 */
export function buildNodeConfigFields(cfg: NodeCfgInput | null): NodeConfigFields {
  if (!cfg) {
    return {
      cfg_read: false,
      parsed_at_ms: null,
      node_size: null, ledger_history: null,
      online_delete: null, advisory_delete: null,
    };
  }
  return {
    cfg_read: true,
    parsed_at_ms: cfg.parsed_at_ms,
    node_size: cfg.node_size,
    ledger_history: cfg.ledger_history,
    online_delete: cfg.online_delete,
    advisory_delete: cfg.advisory_delete,
  };
}
