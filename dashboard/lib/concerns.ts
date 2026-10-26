/**
 * The concern layer, ranking and routing for signals that already exist.
 *
 * The one sentence that constrains this whole file
 * (from the concern-cards design, section 1):
 *
 *   **It ranks and routes signals that already exist. It does not invent
 *   thresholds, and it does not decide what is wrong.**
 *
 * Thresholds live in exactly two places and stay there: `config/rules.yaml`
 * (the rules engine) and `lib/fleet-health.ts` (`deriveVerdict`,
 * `checkIdentityPin`, `STALE_AFTER_MS`). A third copy here would drift from
 * both, and the first symptom of that drift is a card that disagrees with the
 * Insights tab about whether an alert is firing. Nothing below declares a
 * number a signal is compared against, the one comparison this module makes
 * (staleness) reads its boundary from `input.staleAfterMs`, which the poller
 * supplies from its own constant.
 *
 * Pure: no I/O, no clock, no module-level mutable state. `nowMs` arrives in
 * the input. The three behaviours that are genuinely cross-cycle, a concern
 * surviving a failed read, a stable `first_seen_ms`, and resolution, are
 * properties of the INPUT (retained poller rows, the `firstSeen` map), which
 * is what lets the resolution rule be written as what it actually is: a fact
 * is gone only when the source that raised it was read successfully and did
 * not return it. Never a TTL. Never a timeout.
 */
import type { FleetVerdict, PeerUnreachableReason } from './fleet-health.js';
import type { ReadFiringStateRow, NodeReachState } from '../types/read-contract.js';

// ─── Shapes ────────────────────────────────────────────────────────────

export type ConcernClass =
  | 'integrity' | 'reachability' | 'alert' | 'staleness'
  | 'drift' | 'observability';   // last two: slice 2, appended client tier

export type ConcernSeverity = 'page' | 'critical' | 'warn';

/** Where the arrow points. `params` is structured context for the composer,
 *  never a pre-built sentence: the tab composes the question per class so the
 *  voice matches the composers already on that page. */
export interface ConcernLink {
  kind: 'alert' | 'fleet' | 'none';
  params: Record<string, string>;
}

export interface Concern {
  id: string;                  // dedup key, stable across cycles
  node: string;                // fleet label; the self node's OWN label, never "this node"
  self: boolean;
  class: ConcernClass;
  severity: ConcernSeverity;

  title: string;               // short phrase, sentence case
  evidence: string;            // the one line the card renders

  /** When the fact was measured at its source. Null when the source measured
   *  nothing, a peer that did not answer measured nothing by definition. */
  measured_at_ms: number | null;
  /** When THIS dashboard last confirmed it. For a peer that is the poll or
   *  read that produced the fact, up to one poll interval old, never "now". */
  observed_at_ms: number;
  /** The worse of the two, computed here, rendered as-is. A number, never a
   *  formatted string: a server-formatted age freezes between polls, which is
   *  the same defect `FleetPeerPublic.last_seen_ms` already avoids. */
  evidence_age_ms: number;

  /** 1–10, 10 most critical. THE ordering key (§4.1 as amended): the strip is
   *  read left to right, so the leftmost card is the most important thing this
   *  dashboard can see. Computed by `scoreConcern` from the concern's own
   *  fields, never supplied by a caller, never recomputed by the client. */
  score: number;

  first_seen_ms: number;
  /** True only for the alert class, whose `triggered_ts` survives a restart
   *  in `firing_state`. False everywhere else, and the card says so in those
   *  words ("since this dashboard started") rather than implying a history
   *  this process cannot have. */
  first_seen_persisted: boolean;
  escalated_from: ConcernSeverity | null;
  escalated_at_ms: number | null;
  acked_at: number | null;     // alert class only; null everywhere else in v1

  /** Always false since the scored-strip amendment. It marked the one concern
   *  §4.3 promoted into slot four past four chronic criticals; strict score
   *  order supersedes that promotion, so no ordering exception is made and
   *  there is nothing to explain. The field stays because the shape is a
   *  contract the client already renders and an always-false flag renders as
   *  nothing, whereas a removed field is a `undefined` read on every card
   *  served by a host that upgraded before the page did. */
  newest: boolean;

  link: ConcernLink;
}

export type UncheckedReason = 'not_yet_polled' | 'token_unreadable' | 'refused';

/** The whole body of `GET /api/concerns`. */
export interface ConcernsResponse {
  generated_at_ms: number;
  scope: 'fleet' | 'node';          // 'node' when fleetView() yields no peers
  /** This host's own node label, the same one `/api/fleet` uses. The page
   *  needs it to badge a calm card describing this host's own measurements:
   *  every other card carries a label, and one card reading "this node" beside
   *  three reading `node2` would be the same node named two ways. */
  self_label: string;
  checked: {
    nodes_total: number;
    nodes_checked: number;
    signals_checked: number;        // source checks that RETURNED a usable answer
  };
  unchecked: Array<{ label: string; reason: UncheckedReason }>;
  concerns: Concern[];              // COMPLETE and in final display order
  display_max: 4;                   // the client slices, the server does not
  /** The scoring vocabulary, served so the page holds no metric table and no
   *  threshold of its own. The client rates its calm fill cards and its
   *  change-point observations with the SAME numbers this module ranked the
   *  concerns by, one table, one ranker, and a card's position means the
   *  same thing wherever the card came from.
   *
   *  Served rather than duplicated in the page: a copy in JavaScript would
   *  drift from this one, and the first symptom of that drift is a calm card
   *  sitting left of a concern. There is no cross-host contract risk in
   *  serving it, the browser only ever reads this from the same host that
   *  built the cards it is ordering. */
  scoring: {
    metric_importance: Record<string, number>;
    default_importance: number;
    fill_max: number;
    observation: number;
    /** Cell metric → the rule metrics that cover it. See CELL_METRIC_RULES. */
    cell_metrics: Record<string, string[]>;
  };
}

/**
 * One peer, as the concern layer sees it. Built field by field by
 * `FleetHealthPoller.peersConcernInput()`, never a spread of poller state,
 * so a `read_origin` or a `token_path` can never arrive here by accident.
 */
export interface PeerConcernInput {
  label: string;
  verdict: FleetVerdict;             // deriveVerdict's output, unchanged
  detail: string;
  /** Structured, never inferred from `detail`'s prose. 'not_yet_polled' is
   *  the constructor's initial state and emits no concern; 'token_unreadable'
   *  emits a warn; 'no_answer' is a real unreachable; 'refused' is a peer
   *  that answered 401/403. null when the peer answered. */
  unreachable_reason: PeerUnreachableReason;
  /** The status behind a 'refused' reason, 401 or 403. Null for every other
   *  reason — this is evidence, and evidence nobody measured is not zero. */
  refused_status: number | null;
  last_seen_ms: number | null;       // last successful poll of the REGISTERED node
  sample_age_ms: number | null;      // AS OF sample_read_at_ms; null when it had no samples
  sample_read_at_ms: number | null;
  /** The last rows a SUCCESSFUL firing read returned, with the timestamp of
   *  that read. Never cleared by a failed read. Both null until the first
   *  successful firing read for this peer. */
  firing: ReadFiringStateRow[] | null;
  firing_read_at_ms: number | null;
  pinned: boolean;
  pin_mismatch: boolean;             // true only when checked AND not matched
  /** When this dashboard last ATTEMPTED this peer, whatever the outcome.
   *  Added beyond the design's named shape: a peer whose only fact is a
   *  negative one (it did not answer) has no other honest `observed_at_ms`,
   *  and dating a failed poll to "now" would claim a 20-second-old absence
   *  was confirmed this instant. */
  last_poll_at_ms: number | null;
  /** Source checks that returned a usable answer in the peer's LAST COMPLETED
   *  cycle. Added beyond the design's named shape because §6.3 forbids
   *  inflating `signals_checked`, and it cannot be derived here: a non-null
   *  read timestamp means "succeeded at some point", not "read this cycle". */
  signals_checked: number;
}

export interface ConcernInput {
  nowMs: number;
  scope: 'fleet' | 'node';
  selfLabel: string;
  /** `queryFiringState()`, read in the same tick that serves the request,
   *  which is why every self concern's `observed_at_ms` is now. Typed as the
   *  contract row rather than db.ts's `FiringStateRow` (structurally
   *  identical) so this module never imports the database. */
  selfFiring: ReadFiringStateRow[];
  selfReach: NodeReachState;         // server.ts's nodeReachState()
  /** True when this dashboard is a fleet aggregator rather than a node's own
   *  dashboard, `isAggregatorSelf` in fleet-health.ts, which is the same rule
   *  the header chip uses to drop this host from the roster. Suppresses the
   *  self REACHABILITY concern only: an aggregator has no node of its own to
   *  lose, and claiming it does would contradict the chip on the same screen.
   *  Its firing alerts are still concerns, those are real rules firing on a
   *  real host, and the Insights tab lists them. */
  selfIsAggregator: boolean;
  peers: PeerConcernInput[];
  /** Non-alert classes only, owned by server.ts beside the poller. Read here,
   *  reconciled by the caller through `reconcileFirstSeen`. In memory, so it
   *  resets on restart, which is exactly what `first_seen_persisted: false`
   *  tells the operator on the card. */
  firstSeen: Map<string, number>;
  /** The poller's own staleness boundary (`STALE_AFTER_MS`), passed in rather
   *  than redeclared, so this module holds no threshold of its own. */
  staleAfterMs: number;
}

// ─── Constants ─────────────────────────────────────────────────────────

/** The strip renders four. Served rather than hard-coded in the page so the
 *  carousel slice can raise it in one place. */
export const DISPLAY_MAX = 4;

// ─── Scoring ───────────────────────────────────────────────────────────
//
// One number, 1–10, on every card, and the strip is ordered by it descending:
// people read left to right, so the leftmost card is the most important thing
// this dashboard can see. Everything else about the order is a tie-break.
//
// The whole table is deliberately small, explicit and commented. A score an
// operator cannot predict is worse than no score at all, they would learn to
// distrust the position rather than read it, so nothing here is derived from
// a formula with tuning constants in it. Every value below is a stated
// judgement about what matters on a validator, in one place, changeable in one
// place.
//
// It invents no thresholds: it never decides WHETHER something is wrong (the
// rules engine and `deriveVerdict` do that, unchanged), only how far left a
// thing that is already wrong should sit.

/**
 * How much each metric matters on a validator, 1–10. Used twice: to shade an
 * alert's score inside its severity band, and to rate a HEALTHY metric for a
 * calm fill card. Two uses, one table, so a metric cannot be important when it
 * is broken and unimportant when it is fine.
 *
 * The names are the RAW metric names from `config/rules.yaml` and
 * `knowledge/metric-alerts.yaml`, the same strings the Insights tab's
 * Currently Firing rows print, which is what keeps the two surfaces
 * comparable. `test/unit/concerns.test.ts` reads both YAML files and fails if
 * any rule metric is missing an entry here, because a lookup miss is silent:
 * it returns the default and nothing complains. That test exists because the
 * names drift (the page's Agreement cell is `agreement_pct`; the rule behind
 * it is `agreement_pct_1h`).
 */
export const METRIC_IMPORTANCE: Record<string, number> = {
  // 10, the validator's purpose. Agreement is the measure that decides
  // whether it is doing its job at all, and missed validations is the same
  // fact counted the other way. Nothing on a validator outranks these.
  agreement_pct_1h: 10,
  missed_validations_1h: 10,
  // The Advisor tab's Agreement cell measures the same thing over its own
  // window and carries the cell's name, not the rule's. Rated identically and
  // deliberately: the same fact must not change importance depending on which
  // surface noticed it.
  agreement_pct: 10,

  // 9, reachability and connectivity: whether the node is participating.
  // A validator the network cannot see is not validating, whatever its own
  // numbers say, and a validator with no peers is signing in the dark. The
  // node being wholly unreachable is the extreme of this, no reading at all,
  // so it sits at the top of the band.
  node_unreachable_s: 9,
  peer_count: 9,
  validator_registry_seen: 9,
  validator_last_seen_age_s: 9,

  // 7, the freshness of the feeds this dashboard judges everything else by,
  // and the node being actively dropped by its peers. A stale relay feed is
  // this product's characteristic failure in one metric: every host number on
  // every page becomes a kept reading rendered as a current one.
  relay_feed_age_s: 7,
  peer_shed_signal: 7,

  // 6, close and queue timing: the node keeping up with the network's pace.
  // Below connectivity because it is usually the symptom, above host resources
  // because it is measured on the thing we actually care about.
  load_factor: 6,
  jq_trans_overflow: 6,

  // 5, host resources. They matter through their effect on everything above,
  // and everything above is measured directly, so a busy CPU is a lead rather
  // than a verdict.
  cpu_busy_pct: 5,
  mem_used_pct: 5,
  swap_used_pct: 5,
  // Real and worth acting on, but on a timescale of days. It never belongs
  // left of a fact about this minute.
  validator_version_drift: 5,
  // The data mount filling. Rated with the host resources for the same
  // reason and with the same caveat: when it fires the node still validates
  // normally, and the runway is measured in weeks. It is a capacity fact,
  // not a fact about this ledger, and the strip should say so by where it
  // puts it.
  nudb_mount_free_days: 5,
  // An amendment this build does not support, already at the network's
  // majority. Same band and the same reasoning as the mount running out:
  // real, the node still validates normally right up to the moment it
  // doesn't, and the runway is measured in days to weeks rather than this
  // minute — time to plan an upgrade deliberately, not an emergency yet.
  unsupported_amendment_days_to_block: 5,
  // The host verifier's own findings, and whether it is still running at all.
  // Rated here rather than higher on purpose: what it reports is real (a
  // service down, a config left open), but every one of those facts has a
  // metric of its own further up this table that says it sooner and in its own
  // words. This is the backstop, and a backstop does not outrank the thing it
  // backs. Deliberately not in the 7 band either: that band is for the feeds
  // the pages are drawn from, and a stale verify report blinds no page.
  verify_failed_checks: 5,
  verify_report_age_s: 4,
  // No report at all on a host that installs the verifier. Same band as the
  // age: both say nobody is checking this box, which is not a fault in the
  // node and is not nothing either.
  verify_report_missing: 4,

  // 4, network quality. Rising latency precedes missed validations, which is
  // exactly why it ranks under the thing it precedes: when the consequence
  // arrives it has its own card at 10.
  peer_latency_p50: 4,
  tcp_retrans_per_sec: 4,
  // A host in the fleet running an older deploy of this dashboard. Real, and
  // a human has to fix it, but it is a fact about the monitoring rather than
  // about the node: the box on the old commit still watches its validator.
  // The bottom of the concern band on purpose, since every rating above it
  // describes something the network can feel.
  fleet_deploy_divergent: 4,
  // Aperire itself is not on the release the endpoint publishes. Rated with
  // the deploy divergence above it, and for the same reason: it is a fact
  // about the monitoring, not about the node, and a box on last month's
  // release still watches its validator. Never confused with
  // node_version_behind, which is rippled's version and sits in another band
  // entirely.
  update_available: 4,

  // 3, traffic. No rule covers it; it is here because the Advisor tab's
  // Outgoing traffic cell can become a calm fill card and must be rated by the
  // same table as everything else.
  tx_bps: 3,
};

/** An unknown metric sits in the middle, never at either extreme: a rule
 *  added today must not silently outrank agreement, and must not silently
 *  fall below traffic either. The totality test makes this unreachable for
 *  any metric a shipped rule names. */
export const DEFAULT_METRIC_IMPORTANCE = 5;

/** The ceiling for a calm fill card. Strictly below the floor of every real
 *  concern (4), so a healthy metric can never outrank something that is
 *  actually wrong, the invariant a test pins directly. */
export const FILL_MAX_SCORE = 3;

/** The client's observation tier: a change-point the tab detected in a
 *  metric's own 30-day series. Above every calm card because it is worth
 *  attention, below every rule-backed concern because `changePoint()` is, in
 *  its own words, deliberately crude, it points at a date, it does not prove
 *  anything, and weaker evidence must not outrank stronger (§5.3). */
export const OBSERVATION_SCORE = 4;

/**
 * Which rule metrics cover each of the tab's four measurement cells.
 *
 * The cell names and the rule names are different vocabularies that happen to
 * overlap, and the page must not guess between them. Served rather than
 * duplicated in the page so the page holds no metric table of its own: it
 * decides a cell's severity by asking whether any of these metrics has an
 * alert concern on the node being measured, instead of comparing the value to
 * a threshold it keeps privately. A cell whose list is empty is covered by no
 * rule, and keeps whatever local band it has (there is one such cell today,
 * `tx_bps`, and it has no band).
 */
export const CELL_METRIC_RULES: Record<string, string[]> = {
  peer_count: ['peer_count'],
  peer_latency_p50: ['peer_latency_p50'],
  // Both directions of the same fact, either of which makes the Agreement
  // cell a concern rather than a calm card.
  agreement_pct: ['agreement_pct_1h', 'missed_validations_1h'],
  tx_bps: [],
};

/** The fields `scoreConcern` actually reads. Named so an emitter can be
 *  scored before it is a Concern, a concern is built unscored and scored
 *  exactly once, on the way out of `buildConcerns`, which is what makes
 *  "every concern carries a score" a property of the code path rather than a
 *  thing every emitter has to remember. */
export type ScorableConcern =
  Pick<Concern, 'class' | 'severity' | 'link' | 'measured_at_ms' | 'observed_at_ms'>;

export function metricImportance(metric: string): number {
  const v = METRIC_IMPORTANCE[metric];
  return v === undefined ? DEFAULT_METRIC_IMPORTANCE : v;
}

/**
 * The score, 1–10, as a pure function of the concern's own fields.
 *
 * Every band is stated here in one place:
 *
 *   10  integrity, a node answering as a different node. Every other reading
 *       from that label is about an unknown machine, which is why the poller
 *       refuses them outright. Nothing can be more important than not knowing
 *       whose numbers you are looking at.
 *    9  a node not answering at all, and the `page` alert tier. Both mean the
 *       same thing operationally: someone has to look now. A node that is
 *       silent is not a node that is fine, and its last-good readings are on
 *       the page beside this.
 *  7–8  the `critical` alert tier, shaded by the metric's own importance:
 *       8 for a metric that matters directly (importance ≥ 7), 7 otherwise.
 *       A critical CPU rule and a critical agreement rule are not the same
 *       news, and the strip is where that difference has to show.
 *  5–6  the `warn` alert tier, shaded the same way.
 *    6  a read token this dashboard cannot read. It sits at the top of the
 *       unknown band rather than in the alert bands because nothing about
 *       that node has been checked at all, the maximum unknown, and a fault
 *       on this box that the operator can fix.
 *  4–6  staleness, by how stale: 6 when the source stores nothing at all or
 *       is more than ten times past its freshness limit, 5 past three times,
 *       4 otherwise. A feed that just crossed the line and a feed that
 *       stopped an hour ago are different facts.
 *    4  the client tiers (`drift`, `observability`), see OBSERVATION_SCORE.
 *
 * The floor over the whole type is 4, which is what keeps every real concern
 * above every calm fill card.
 *
 * `staleAfterMs` is the poller's own boundary, passed in exactly as
 * `buildConcerns` receives it, so this function still declares no threshold.
 */
export function scoreConcern(c: ScorableConcern, staleAfterMs: number): number {
  if (c.class === 'integrity') return 10;

  if (c.class === 'reachability') {
    // Two ids at two severities, and the severity is the whole difference:
    // critical is "it did not answer", warn is "we could not ask".
    return c.severity === 'warn' ? 6 : 9;
  }

  if (c.class === 'alert') {
    if (c.severity === 'page') return 9;
    const imp = metricImportance(c.link.params.alert ?? '');
    const high = imp >= 7;
    return c.severity === 'critical' ? (high ? 8 : 7) : (high ? 6 : 5);
  }

  if (c.class === 'staleness') {
    // Nothing stored at all: there is no reading to be stale, which is the
    // worst version of this rather than the mildest.
    if (c.measured_at_ms === null) return 6;
    // How stale it was AS OF THE READ, `observed_at_ms - measured_at_ms` is
    // the peer's own `sample_age_ms`, the same number the emitter compared,
    // and not a clock that keeps running after the node went quiet.
    const ratio = staleAfterMs > 0
      ? (c.observed_at_ms - c.measured_at_ms) / staleAfterMs
      : 0;
    if (ratio >= 10) return 6;
    if (ratio >= 3) return 5;
    return 4;
  }

  // drift / observability: emitted by the client tier, never by this module,
  // and scored here only so the function is total over the type.
  return OBSERVATION_SCORE;
}

// ─── Formatting helpers ────────────────────────────────────────────────

/** Coarse, human, and monotone in the value, used inside evidence strings
 *  only. Live ages on the card are formatted by the browser from
 *  `evidence_age_ms`, never here. */
export function fmtDuration(ms: number): string {
  const safe = Number.isFinite(ms) && ms > 0 ? ms : 0;
  const s = Math.round(safe / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  if (h < 24) return rm ? `${h}h ${rm}m` : `${h}h`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d}d ${rh}h` : `${d}d`;
}

function fmtValue(v: number): string {
  if (!Number.isFinite(v)) return 'an unreadable value';
  const abs = Math.abs(v);
  if (abs >= 1000) return Math.round(v).toLocaleString('en-US');
  if (Number.isInteger(v)) return String(v);
  return String(Number(v.toFixed(abs < 1 ? 3 : 2)));
}

// ─── Emitters, one per class ───────────────────────────────────────────

/** The worse of the two ages, §3.5. A peer that answers instantly from a ten
 *  minute old reading shows ten minutes, not zero. */
function evidenceAge(nowMs: number, measuredAtMs: number | null, observedAtMs: number): number {
  const older = measuredAtMs === null ? observedAtMs : Math.min(measuredAtMs, observedAtMs);
  return Math.max(0, nowMs - older);
}

/**
 * Every concern's title and evidence for the alert class come from the row
 * itself. The metric name is carried through RAW and unabbreviated, which is
 * the same string the Insights tab's Currently Firing row prints, the two
 * surfaces are then literally comparable, which is the property this feature
 * has to hold above all others.
 */
function alertConcern(args: {
  nowMs: number;
  node: string;
  self: boolean;
  row: ReadFiringStateRow;
  observedAtMs: number;
}): Omit<Concern, 'score'> {
  const { nowMs, node, self, row, observedAtMs } = args;

  // `firing_state` keeps epoch SECONDS, db.ts's schema says so on the column
  // ("epoch s") and the writer floors milliseconds to get there, while every
  // timestamp on a Concern is epoch milliseconds, because that is what the
  // browser formats ages from everywhere else in this product. Converting in
  // this one place, on the way in, is what stops the two units meeting: read
  // live, an unconverted `triggered_ts` produced an evidence age of fifty-six
  // years and an elapsed time of "0s", and both were rendered without
  // complaint because a number is a number.
  const secToMs = (v: number | null): number | null =>
    v === null || v === 0 ? null : Math.round(v * 1000);
  const measuredAtMs = secToMs(row.last_seen_ts);
  const triggeredAtMs = secToMs(row.triggered_ts);

  // How long it has been that way, on ONE clock. `last_seen_ts` and
  // `triggered_ts` are both the source node's own clock, so their difference
  // is meaningful across a fleet in a way that (our now − their triggered_ts)
  // would not be.
  const firingForMs = (measuredAtMs ?? nowMs) - (triggeredAtMs ?? nowMs);

  const measured = row.last_value === null
    ? 'no value recorded'
    : `measured ${fmtValue(row.last_value)}`;
  const against = (row.threshold_op && row.threshold_value !== null)
    ? `against ${row.threshold_op} ${fmtValue(row.threshold_value)}`
    : 'no threshold recorded';
  const forHow = triggeredAtMs !== null
    ? `firing for ${fmtDuration(firingForMs)}`
    : 'no start time recorded';

  const direction = row.threshold_op === null ? 'alert'
    : row.threshold_op.startsWith('<') ? 'under its threshold'
      : row.threshold_op.startsWith('>') ? 'over its threshold'
        : 'at its threshold';

  const params: Record<string, string> = { alert: row.metric, sev: row.severity, node };
  if (row.last_value !== null) params.value = String(row.last_value);
  if (row.threshold_op) params.op = row.threshold_op;
  if (row.threshold_value !== null) params.threshold = String(row.threshold_value);
  if (triggeredAtMs !== null) {
    params.at = String(triggeredAtMs);
    params.dur = fmtDuration(firingForMs);
  }

  return {
    id: `${node}:alert:${row.dedup_key}`,
    node,
    self,
    class: 'alert',
    severity: row.severity,
    title: `${row.metric} ${direction}`,
    evidence: `${measured}, ${against}, ${forHow}`,
    measured_at_ms: measuredAtMs,
    observed_at_ms: observedAtMs,
    evidence_age_ms: evidenceAge(nowMs, measuredAtMs, observedAtMs),
    // Free and persisted: firing_state.triggered_ts survives a restart, and a
    // peer's own firing rows carry the same field over the read API.
    first_seen_ms: triggeredAtMs ?? nowMs,
    first_seen_persisted: triggeredAtMs !== null,
    escalated_from: null,
    escalated_at_ms: null,
    acked_at: secToMs(row.acked_at),
    newest: false,
    link: { kind: 'alert', params },
  };
}

// ─── buildConcerns ─────────────────────────────────────────────────────

/**
 * One cycle's concerns, unranked. `rankConcerns` puts them in display order.
 *
 * Note what is deliberately absent: escalation. `escalated_from` and
 * `escalated_at_ms` are in the shape and are always null in slice 1, because
 * no slice-1 concern id can change severity. Every id pins its own severity
 * through its class and subject, integrity is always critical, staleness
 * always warn, the two reachability ids are separate ids at separate
 * severities (`:reachability:token` warn, `:reachability:dashboard` critical),
 * and an alert's severity is a property of the rule its `dedup_key` names.
 * Carrying a prior-severity map to record a transition that cannot occur
 * would be state nothing reads. The fields stay so the class that can change
 * severity has somewhere to put it.
 */
export function buildConcerns(input: ConcernInput): Concern[] {
  const { nowMs, selfLabel, selfFiring, selfReach, peers, firstSeen, staleAfterMs } = input;
  const selfIsAggregator = input.selfIsAggregator;
  // Unscored while it is being built, scored once at the return below. An
  // emitter that had to remember to score itself would eventually forget, and
  // a concern with a missing score sorts as `undefined`, which in JavaScript
  // is neither greater nor less than anything, so it would land wherever the
  // sort happened to leave it.
  const out: Array<Omit<Concern, 'score'>> = [];

  const firstSeenFor = (id: string): number => firstSeen.get(id) ?? nowMs;

  // ── self ──
  // Both self signals are in-process and read in the tick that serves this
  // request, so `observed_at_ms` is genuinely now for them, the one place in
  // this module where that is true.
  // An aggregator's self row is unreachable permanently and by construction,
  // there is no rippled on that box and there never was. Emitting it would put
  // a chronic critical on the strip forever, about a node that does not exist,
  // while the header chip on the same page has already excluded this host from
  // the fleet. Its own firing alerts below are unaffected.
  if (!selfReach.ok && !selfIsAggregator) {
    const id = `${selfLabel}:reachability:node`;
    out.push({
      id,
      node: selfLabel,
      self: true,
      class: 'reachability',
      severity: 'critical',
      title: 'This node is not answering',
      evidence: `no answer for ${fmtDuration(selfReach.unreachable_for_s * 1000)} ` +
        `across ${selfReach.misses} missed poll${selfReach.misses === 1 ? '' : 's'}; ` +
        `last reached ${fmtDuration(Math.max(0, nowMs - selfReach.last_ok_ms))} ago`,
      // The fact being asserted is a negative one, and this process
      // re-establishes it every five seconds, so it is current. `last_ok_ms`
      // is in the evidence line as what it is: when contact was last made.
      measured_at_ms: nowMs,
      observed_at_ms: nowMs,
      evidence_age_ms: 0,
      first_seen_ms: firstSeenFor(id),
      first_seen_persisted: false,
      escalated_from: null,
      escalated_at_ms: null,
      acked_at: null,
      newest: false,
      link: {
        kind: 'none',
        params: {
          concern: 'reachability_self',
          unreachable_for_s: String(selfReach.unreachable_for_s),
          misses: String(selfReach.misses),
          node: selfLabel,
        },
      },
    });
  }

  for (const row of selfFiring) {
    out.push(alertConcern({ nowMs, node: selfLabel, self: true, row, observedAtMs: nowMs }));
  }

  // ── peers ──
  for (const p of peers) {
    // Absence of evidence. Never a concern, and never counted as clear
    // either, it is named in the response's `unchecked` array instead.
    if (p.unreachable_reason === 'not_yet_polled') continue;

    const observedAtMs = p.last_poll_at_ms ?? nowMs;

    // Integrity suppresses everything else for this node. This is already the
    // poller's own behaviour, on a pin mismatch it refuses the wrong node's
    // health signals outright, and the concern layer inherits that refusal
    // rather than restating it. The readings behind an alert or a staleness
    // card for this label came from a node that is not the one it names.
    if (p.pin_mismatch) {
      const id = `${p.label}:integrity:pubkey_node`;
      out.push({
        id,
        node: p.label,
        self: false,
        class: 'integrity',
        severity: 'critical',
        title: 'Node identity mismatch',
        evidence: p.detail,
        measured_at_ms: null,
        observed_at_ms: observedAtMs,
        evidence_age_ms: evidenceAge(nowMs, null, observedAtMs),
        first_seen_ms: firstSeenFor(id),
        first_seen_persisted: false,
        escalated_from: null,
        escalated_at_ms: null,
        acked_at: null,
        newest: false,
        link: { kind: 'fleet', params: { fleet: p.label, state: p.verdict, detail: p.detail } },
      });
      continue;
    }

    if (p.unreachable_reason === 'token_unreadable') {
      // A fault on THIS box that the operator can fix, so it is a concern
      // rather than a silence. No path in the evidence: §8.3, labels and
      // numbers only, never a file path.
      const id = `${p.label}:reachability:token`;
      out.push({
        id,
        node: p.label,
        self: false,
        class: 'reachability',
        severity: 'warn',
        title: 'Its read token cannot be read',
        evidence: 'this dashboard could not read the token it needs to poll this node, ' +
          'so nothing about it has been checked' +
          (p.last_seen_ms === null ? '' : `; last reached ${fmtDuration(Math.max(0, nowMs - p.last_seen_ms))} ago`),
        measured_at_ms: null,
        observed_at_ms: observedAtMs,
        evidence_age_ms: evidenceAge(nowMs, null, observedAtMs),
        first_seen_ms: firstSeenFor(id),
        first_seen_persisted: false,
        escalated_from: null,
        escalated_at_ms: null,
        acked_at: null,
        newest: false,
        link: { kind: 'fleet', params: { fleet: p.label, state: p.verdict, detail: p.detail } },
      });
    } else if (p.unreachable_reason === 'refused') {
      // The node is up and answered; it does not accept this dashboard's
      // read token (#268). A separate id and a separate title from
      // :reachability:dashboard on purpose — calling this "not answering"
      // sends the operator to the network, and the network is fine.
      const id = `${p.label}:reachability:token-rejected`;
      out.push({
        id,
        node: p.label,
        self: false,
        class: 'reachability',
        severity: 'critical',
        title: 'It rejects this dashboard\'s read token',
        evidence: `it answered with HTTP ${p.refused_status ?? 401}, so nothing about it has been checked` +
          (p.last_seen_ms === null ? '' : `; last read ${fmtDuration(Math.max(0, nowMs - p.last_seen_ms))} ago`) +
          '. A wipe-and-reinstall mints a new token: copy it into this dashboard and reload the registry',
        // Nothing was measured; the refusal itself was observed at the poll.
        measured_at_ms: null,
        observed_at_ms: observedAtMs,
        evidence_age_ms: evidenceAge(nowMs, null, observedAtMs),
        first_seen_ms: firstSeenFor(id),
        first_seen_persisted: false,
        escalated_from: null,
        escalated_at_ms: null,
        acked_at: null,
        newest: false,
        link: { kind: 'fleet', params: { fleet: p.label, state: p.verdict, detail: p.detail } },
      });
    } else if (p.unreachable_reason === 'no_answer') {
      const id = `${p.label}:reachability:dashboard`;
      out.push({
        id,
        node: p.label,
        self: false,
        class: 'reachability',
        severity: 'critical',
        title: 'Not answering its dashboard',
        evidence: p.last_seen_ms === null
          ? 'it has not answered once since this dashboard started'
          : `no answer to its read API; last reached ${fmtDuration(Math.max(0, nowMs - p.last_seen_ms))} ago`,
        // Nothing was measured, it did not answer. The absence itself was
        // observed at the poll, up to one interval ago, and the card says so.
        measured_at_ms: null,
        observed_at_ms: observedAtMs,
        evidence_age_ms: evidenceAge(nowMs, null, observedAtMs),
        first_seen_ms: firstSeenFor(id),
        first_seen_persisted: false,
        escalated_from: null,
        escalated_at_ms: null,
        acked_at: null,
        newest: false,
        link: {
          kind: 'fleet',
          params: {
            fleet: p.label,
            state: p.verdict,
            detail: p.detail,
            ...(p.last_seen_ms === null ? {} : { last_seen_ms: String(p.last_seen_ms) }),
          },
        },
      });
    }

    // Retained alert rows, whatever the peer's reachability. A peer that has
    // gone silent does NOT lose the alerts that were true last time it answered,
    // they persist with a growing age beside the reachability card. Two cards,
    // two facts, neither invented (§3.7). The `N alerts firing` verdict never
    // emits anything of its own: the rows are the specific source and the
    // verdict is the general one, so one fact makes one card (§4.2).
    if (p.firing) {
      for (const row of p.firing) {
        out.push(alertConcern({
          nowMs,
          node: p.label,
          self: false,
          row,
          observedAtMs: p.firing_read_at_ms ?? observedAtMs,
        }));
      }
    }

    // Staleness is judged on the value AS OF THE READ, never on a clock that
    // keeps running. A peer that was fresh when it last answered and then went
    // silent is unreachable, not stale, it gets one card, the true one. A
    // peer that was already stale keeps its staleness card, with the age on it
    // growing, because that fact was observed and has not been contradicted.
    const staleByRead = p.sample_age_ms !== null && p.sample_age_ms > staleAfterMs;
    const noSamplesEver = p.sample_age_ms === null && p.sample_read_at_ms !== null;
    if (staleByRead || noSamplesEver) {
      const id = `${p.label}:staleness:samples`;
      const sampleTs = (p.sample_read_at_ms !== null && p.sample_age_ms !== null)
        ? p.sample_read_at_ms - p.sample_age_ms
        : null;
      const observed = p.sample_read_at_ms ?? observedAtMs;
      out.push({
        id,
        node: p.label,
        self: false,
        class: 'staleness',
        severity: 'warn',
        title: noSamplesEver ? 'Answering, but storing nothing' : 'Its samples have stopped',
        evidence: noSamplesEver
          ? 'it answers, but has stored no samples at all, so every number on its ' +
            'pages is unbacked'
          : `its most recent stored sample is ${fmtDuration(Math.max(0, nowMs - (sampleTs ?? nowMs)))} old, ` +
            `against a freshness limit of ${fmtDuration(staleAfterMs)}; the numbers on ` +
            'its pages are kept readings, not current ones',
        measured_at_ms: sampleTs,
        observed_at_ms: observed,
        evidence_age_ms: evidenceAge(nowMs, sampleTs, observed),
        first_seen_ms: firstSeenFor(id),
        first_seen_persisted: false,
        escalated_from: null,
        escalated_at_ms: null,
        acked_at: null,
        newest: false,
        link: {
          kind: 'fleet',
          params: {
            fleet: p.label,
            state: p.verdict,
            detail: p.detail,
            ...(sampleTs === null ? {} : { sample_age: fmtDuration(Math.max(0, nowMs - sampleTs)) }),
            stale_after: fmtDuration(staleAfterMs),
          },
        },
      });
    }
  }

  return out.map((c) => ({ ...c, score: scoreConcern(c, staleAfterMs) }));
}

// ─── Ranking ───────────────────────────────────────────────────────────

const CLASS_RANK: Record<ConcernClass, number> = {
  integrity: 0, reachability: 1, alert: 2, staleness: 3,
  // Never reached from the server list, the appended client tier (slice 2)
  // is placed after it and never sorted into it. Ranked here anyway so the
  // comparator is total over the whole type rather than over a subset.
  drift: 4, observability: 5,
};

/** The clock a concern is "new" by: max(first_seen, escalated_at), so a
 *  concern that got worse counts as new again from the moment it did. Now a
 *  tie-break rather than the slot-four rule it was written for. */
export function newnessMs(c: Concern): number {
  return Math.max(c.first_seen_ms, c.escalated_at_ms ?? 0);
}

/**
 * Total order, no ties possible, deterministic across cycles. Two dashboards
 * with the same state show the same strip, and two cycles with identical
 * inputs produce identical output.
 *
 * Score first, descending, the strip is read left to right and the leftmost
 * card is the most important thing this dashboard can see. Severity is not a
 * separate step any more because it is an INPUT to the score: a critical rule
 * on agreement and a critical rule on CPU are not the same news, and a chain
 * that compared severity before anything else could not say so.
 *
 * Class next, because within one score a node answering as the wrong node is
 * a different kind of fact from a node with a hot CPU. Recency inside that,
 * because among equally scored alerts the one that started two minutes ago is
 * the one the operator has not seen yet. Label before id at the end, because
 * cross-node ties broken by registry order would be unpredictable to a reader
 *, a four-slot strip is not a roster.
 */
export function compareConcerns(a: Concern, b: Concern): number {
  const byScore = b.score - a.score;                 // highest first
  if (byScore !== 0) return byScore;
  const byClass = CLASS_RANK[a.class] - CLASS_RANK[b.class];
  if (byClass !== 0) return byClass;
  const byNewest = newnessMs(b) - newnessMs(a);      // newest first
  if (byNewest !== 0) return byNewest;
  if (a.node !== b.node) return a.node < b.node ? -1 : 1;
  if (a.id !== b.id) return a.id < b.id ? -1 : 1;
  return 0;
}

/**
 * Display order: the comparator, and nothing else.
 *
 * The slot-four promotion §4.3 described is GONE, deliberately. It existed so
 * four chronic criticals could not hold the strip forever against a fresh
 * warn, and it bought that by breaking, once per cycle, the one ordering rule
 * the operator could otherwise predict. Strict score order is the stronger
 * answer to the same problem: a fresh critical scores high on its own merits
 * and needs no exception to be seen, and a fresh warn that scores below four
 * chronic criticals is genuinely the fifth most important thing on the page,
 * putting it fourth would be the strip lying about its own order.
 *
 * Freshness survives as a tie-break inside a score, which is where it was
 * always doing honest work.
 *
 * `nowMs` is gone from the signature with it: the fifteen-minute window was
 * the only reason a pure ranking function needed the present.
 */
export function rankConcerns(list: Concern[]): Concern[] {
  return list.slice().sort(compareConcerns);
}

// ─── The response ──────────────────────────────────────────────────────

/**
 * The whole `GET /api/concerns` body, so the route handler holds no ranking
 * logic and no thresholds, it assembles inputs and serialises this.
 *
 * The server never truncates. The overflow line needs the severity counts of
 * the concerns beyond the fourth and the future carousel needs the rest of
 * them, so truncating here would have to be undone twice.
 */
export function buildConcernsResponse(input: ConcernInput): ConcernsResponse {
  const concerns = rankConcerns(buildConcerns(input));

  const unchecked: Array<{ label: string; reason: UncheckedReason }> = [];
  // Self is always checked: both its signals are in-process reads that
  // cannot fail without the process being gone.
  let nodesChecked = 1;
  let signalsChecked = 2;             // the firing query and the node reach state
  for (const p of input.peers) {
    if (p.unreachable_reason === 'not_yet_polled') {
      unchecked.push({ label: p.label, reason: 'not_yet_polled' });
    } else if (p.unreachable_reason === 'token_unreadable') {
      // In `unchecked` AS WELL as emitting a concern, so the counts stay
      // honest: quietly not checking a node is precisely the failure this
      // feature exists to prevent.
      unchecked.push({ label: p.label, reason: 'token_unreadable' });
    } else if (p.unreachable_reason === 'refused') {
      // Same rule, same reason. The node is present and locked, which is
      // NOT checked — counting it as checked would put a node nobody read
      // behind an "everything looked at" number.
      unchecked.push({ label: p.label, reason: 'refused' });
    } else if (p.unreachable_reason === null) {
      nodesChecked++;
    }
    signalsChecked += p.signals_checked;
  }

  return {
    generated_at_ms: input.nowMs,
    scope: input.scope,
    self_label: input.selfLabel,
    checked: {
      nodes_total: input.scope === 'fleet' ? input.peers.length + 1 : 1,
      nodes_checked: nodesChecked,
      signals_checked: signalsChecked,
    },
    unchecked,
    concerns,
    display_max: DISPLAY_MAX,
    scoring: {
      metric_importance: METRIC_IMPORTANCE,
      default_importance: DEFAULT_METRIC_IMPORTANCE,
      fill_max: FILL_MAX_SCORE,
      observation: OBSERVATION_SCORE,
      cell_metrics: CELL_METRIC_RULES,
    },
  };
}

/**
 * The caller's half of the `firstSeen` contract (§3.8): the function reads the
 * map, and the caller writes in the ids it observed and deletes the ones that
 * did not appear. Deleting is what makes a resolved-then-recurring concern
 * honestly new the second time instead of claiming a first sighting from
 * before it resolved.
 */
export function reconcileFirstSeen(firstSeen: Map<string, number>, concerns: Concern[]): void {
  const live = new Set<string>();
  for (const c of concerns) {
    if (c.first_seen_persisted) continue;   // the alert class owns its own, in the database
    live.add(c.id);
    if (!firstSeen.has(c.id)) firstSeen.set(c.id, c.first_seen_ms);
  }
  for (const id of firstSeen.keys()) {
    if (!live.has(id)) firstSeen.delete(id);
  }
}
