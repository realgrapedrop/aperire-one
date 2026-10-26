// One definition of "pending", shared by the Overview card and the Governance
// ballot.
//
// They had one each. Overview counted supported-and-not-enabled; Governance
// counted not-enabled-and-not-obsolete. The two differ by exactly the
// amendments rippled has removed from its build, so Overview reported 5
// pending directly above a ballot listing 4, and nothing on either page said
// which was right.
//
// The ballot's rule is the correct one. rippled reports `vetoed: "Obsolete"`
// for an amendment it used to define and no longer does — it is not on the
// ballot, it cannot activate, and no operator action changes that. Counting it
// as pending counts something that will never happen.

import { amendmentVoteThreshold, type CountedAmendmentSupport } from './amendment-votes.js';

/** The shape this rule needs from one rippled `feature` entry. */
export interface FeatureEntry {
  enabled?: unknown;
  /** `true` for an operator veto, the string `"Obsolete"` when rippled dropped it. */
  vetoed?: unknown;
  supported?: unknown;
}

/** True when an amendment is genuinely awaiting the network's decision. */
export function onTheBallot(f: FeatureEntry): boolean {
  return !f.enabled && f.vetoed !== 'Obsolete';
}

/** How many amendments are pending — the number both tabs must show. */
export function pendingCount(features: Record<string, FeatureEntry>): number {
  return Object.values(features).filter(onTheBallot).length;
}

/**
 * rippled's per-amendment vote tally, or null when this node does not report
 * one at all.
 *
 * The distinction is the whole point. `count`, `threshold` and `validations`
 * appear in a `feature` response only on a node that has run the flag-ledger
 * amendment vote; a node that only tracks the network never fills them in.
 * Measured on the lab fleet, same rippled build, same moment:
 *
 *   validator  → {"count":13,"threshold":28,"validations":36,…}
 *   stock node → {"enabled":false,"name":"LendingProtocol","supported":true,…}
 *
 * Reading the second as "zero validators support this" is a plausible-looking
 * lie about the network, in exactly the way the `system` route's own doc
 * comment describes for a zeroed CPU reading — the node has no opinion to
 * report, which is not the same fact as an opinion of zero.
 */
export function amendmentTally(v: unknown): number | null {
  if (v === undefined || v === null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * D8 #4 (advisor-enhancement/d8-frontend-tab-audit.md) added a second filter
 * to the ballot table — `count > 0`, "at least one validator is currently
 * signalling yes" — to keep amendments with no momentum out of it. That
 * filter is **gone**, and this comment is what remains of it, because it was
 * wrong twice over:
 *
 *   - It could not distinguish a reported zero from an absent tally, and
 *     rippled reports no tally at all on a node that does not run the
 *     flag-ledger vote. Every row disappeared on every tracking node — the
 *     table read "no amendments currently on the ballot" directly beneath a
 *     card counting four.
 *   - Even fixed to test only a reported zero, it left the ballot able to
 *     list fewer amendments than the PENDING card counts, which is the
 *     cross-card disagreement `onTheBallot` was extracted to end. The noise
 *     it was aimed at is already excluded by `onTheBallot` itself: an
 *     enabled amendment is gone, and one rippled has dropped from the build
 *     is gone. What is left is exactly the set xrpscan shows — four, today.
 *
 * A genuinely zero-support amendment now appears with an honest "0.0%" and
 * "Needs N", which says more than hiding it did. One rule, one list:
 * `onTheBallot` decides membership for the card and the table alike.
 */

// ── The ballot table row shape — shared by the local Governance page and ──
// the `amendment-ballot` read route (D8, second Consensus follow-up pass).
// Same "one definition" discipline as onTheBallot/pendingCount above,
// applied one level deeper: server.ts's sampleGovernance() builds this
// exact shape inline for the local page; a peer's browser session needs
// the identical computation run against the PEER's own `snapshot.feature`,
// so it lives here as its own pure, unit-tested function rather than a
// second hand-copied loop server.ts's read-surface switch would otherwise
// need. Amendments genuinely differ per node (a fork's build recognizes a
// different set, an operator votes differently, network momentum on any
// one amendment is the same everywhere but THIS node's `our_vote` and
// `supported` are not) — this is real peer data, not something to blank.

/** The subset of one rippled `feature` entry this row needs, beyond
 *  FeatureEntry's own three fields. */
export interface AmendmentFeatureEntry extends FeatureEntry {
  name?: unknown;
  count?: unknown;
  threshold?: unknown;
  validations?: unknown;
  /** Ripple-epoch seconds at which this amendment reached, and has since
   *  held, the network's majority. Present on a tracking node too, which is
   *  the only support fact such a node reports at all, see
   *  `rippleEpochToMs` and AmendmentBallotRow.support_state. */
  majority?: unknown;
}

/** rippled counts time from 2000-01-01T00:00:00Z, not from the Unix epoch.
 *  Converted here, at the source, so no page does epoch arithmetic of its
 *  own and gets it wrong by 30 years. */
const RIPPLE_EPOCH_OFFSET_S = 946684800;

/** One `majority` field as milliseconds since the Unix epoch, or null when
 *  the amendment does not hold the majority (rippled omits the field, and
 *  clears it again if support falls back below the bar). */
export function rippleEpochToMs(v: unknown): number | null {
  const secs = amendmentTally(v);
  if (secs === null || secs <= 0) return null;
  return (secs + RIPPLE_EPOCH_OFFSET_S) * 1000;
}

/** xrpscan's own enrichment for one amendment hash (name/xls tag) — mirrors
 *  snapshot.xrpscan_amendments's per-hash value in server.ts. */
export interface AmendmentExtInfo {
  name?: string;
  xls?: string | null;
}

/** The known-amendments description scrape's per-hash value — mirrors
 *  snapshot.amendment_descriptions in server.ts. */
export interface AmendmentDescInfo {
  description?: string | null;
  xls_url?: string | null;
}

export interface AmendmentBallotRow {
  hash: string;
  name: string;
  xls: string | null;
  description: string | null;
  xls_url: string | null;
  /** null on a node that reports no vote tally at all — see amendmentTally. */
  count: number | null;
  threshold: number | null;
  validations: number | null;
  /** Share of the trusted validations this node saw that voted yes:
   *  `count / validations`, the same ratio xrpscan publishes. null when
   *  either side is unknown, never a 0% that reads as "no support" when
   *  the truth is "this node cannot tell".
   *
   *  It used to be `count / threshold`, which is a different quantity: the
   *  threshold is the 80%-of-validations bar, so an amendment past the bar
   *  rendered above 100% under a header reading SUPPORT % (measured on the
   *  lab validator, 2026-09-02: fixCleanup3_3_0 count 29, threshold 28,
   *  validations 36, the table said 103.6%, xrpscan said 82.86%). How far
   *  the tally is from the bar is what `progress_state` and `needed_count`
   *  carry, and they still measure against `threshold`. */
  support_pct: number | null;
  progress_state: 'pending' | 'needs' | null;
  needed_count: number | null;
  /** When the amendment reached the network's majority (ms, Unix epoch), or
   *  null when it does not hold it. rippled reports this on every node,
   *  including one that reports no tally. */
  majority_at_ms: number | null;
  /**
   * Which support fact this row actually has, named rather than left for a
   * page to infer from a pile of nulls:
   *
   *   'tallied'     this node ran the flag-ledger vote and counted the
   *                  validations, so `support_pct` is a real measurement.
   *   'majority'    no tally, but the node reports the amendment holds the
   *                  network's majority (`majority_at_ms`). Honest partial
   *                  knowledge, and more than a blank.
   *   'unreported'  this node has no support fact for the amendment at all.
   *                  Not "no support": no reading. The page must say so.
   *
   *   'counted'     no tally from the node, but this dashboard counted the
   *                  votes itself from the trusted validations it saw on the
   *                  last voting ledger (lib/amendment-votes.ts). The figure
   *                  lives in `counted`, never in `count`/`validations`, so
   *                  the node's own reading and the dashboard's can never be
   *                  mistaken for each other. Ranks below 'tallied': a node
   *                  that reports its own tally is believed over our count.
   *
   * Measured on two hosts running xrpld 3.3.0 at the same moment
   * (2026-09-02): the validator's `feature` entries carry
   * count/threshold/validations, the tracking node's carry only
   * enabled/name/supported/vetoed plus `majority` on the one amendment past
   * the bar. rippled fills the tally from its last flag-ledger vote, and a
   * node that does not validate never runs one.
   */
  support_state: 'tallied' | 'counted' | 'majority' | 'unreported';
  /** The dashboard's own count for this amendment, present exactly when
   *  `support_state` is 'counted'. Its `count` and `validations` are what
   *  `support_pct` was made from on such a row; `ledger_index` and `at_ms`
   *  say which voting ledger, so the page can say where the figure came
   *  from and an operator can compare it against a validator or xrpscan for
   *  the same moment. */
  counted: CountedAmendmentSupportRow | null;
  our_vote: 'yes' | 'no' | 'default' | 'obsolete';
  supported: boolean;
}

/** One row's slice of a CountedAmendmentSupport tally. */
export interface CountedAmendmentSupportRow {
  ledger_index: number;
  at_ms: number;
  count: number;
  validations: number;
  threshold: number;
}

/** The tally figures a row is measured on: the node's own when it reports
 *  one, otherwise the dashboard's count, otherwise nothing. One place
 *  decides the precedence so the ballot rows, the vote summary and the
 *  next-activation ranking cannot disagree about it. */
function rowTally(
  f: AmendmentFeatureEntry, hash: string, counted: CountedAmendmentSupport | null | undefined,
): { count: number | null; threshold: number | null; validations: number | null; from: 'node' | 'counted' | null } {
  const count       = amendmentTally(f.count);
  const validations = amendmentTally(f.validations);
  const threshold   = amendmentTally(f.threshold);
  if (count !== null && validations !== null && validations > 0) {
    return { count, threshold, validations, from: 'node' };
  }
  if (counted && counted.validations > 0) {
    return {
      count: counted.counts[hash.toUpperCase()] ?? 0,
      threshold: counted.threshold ?? amendmentVoteThreshold(counted.validations),
      validations: counted.validations,
      from: 'counted',
    };
  }
  return { count, threshold, validations, from: null };
}

/**
 * Every amendment genuinely on the ballot — `onTheBallot`, the same rule and
 * therefore the same count as the PENDING card — sorted by name; field for
 * field the same shape server.ts's
 * sampleGovernance() builds for the local page's `amendments.pending` array,
 * which now calls this function rather than keeping its own copy of the
 * loop. `ext`/`desc` are optional: a hash absent from either map falls back
 * exactly the way the local page does (the hash's own first 8 characters as
 * a name, null description).
 */
export function buildAmendmentBallotRows(
  features: Record<string, AmendmentFeatureEntry>,
  ext: Record<string, AmendmentExtInfo> | undefined,
  desc: Record<string, AmendmentDescInfo> | undefined,
  counted?: CountedAmendmentSupport | null,
): AmendmentBallotRow[] {
  const rows: AmendmentBallotRow[] = [];
  for (const hash of Object.keys(features)) {
    const f = features[hash];
    if (!onTheBallot(f)) continue;

    const tally       = rowTally(f, hash, counted);
    const { count, validations, threshold } = tally;
    const majorityAt  = rippleEpochToMs(f.majority);
    // A ratio needs both halves to mean anything. Missing either one leaves
    // the figure null rather than a 0 the table would render as a red "0.0%"
    // bar under a node that never claimed it.
    const measured    = count !== null && validations !== null && validations > 0;
    const supportPct  = measured ? (count / validations) * 100 : null;
    // Distance to the bar is its own question, and its own denominator.
    const rated       = count !== null && threshold !== null && threshold > 0;
    const needed      = rated ? Math.max(0, threshold - count) : null;
    const atThreshold = rated && count >= threshold;
    const progressState: 'pending' | 'needs' | null =
      !f.enabled && rated ? (atThreshold ? 'pending' : 'needs') : null;
    const supportState: AmendmentBallotRow['support_state'] =
      supportPct === null ? (majorityAt !== null ? 'majority' : 'unreported')
        : tally.from === 'counted' ? 'counted' : 'tallied';
    // The node's own fields stay the node's own: on a counted row they are
    // null on the wire, and the dashboard's figures travel under `counted`.
    const countedRow: CountedAmendmentSupportRow | null =
      supportState === 'counted' && counted
        ? { ledger_index: counted.ledger_index, at_ms: counted.at_ms,
            count: count as number, validations: validations as number, threshold: threshold as number }
        : null;
    const own = tally.from === 'node';

    let ourVote: 'yes' | 'no' | 'default' | 'obsolete';
    if (f.vetoed === 'Obsolete')  ourVote = 'obsolete';
    else if (f.vetoed === true)   ourVote = 'no';
    else if (f.supported)         ourVote = 'yes';
    else                          ourVote = 'default';

    const entry = ext?.[hash.toUpperCase()];
    const amendmentName = (typeof f.name === 'string' && f.name) || entry?.name || (hash.slice(0, 8) + '…');
    const description = desc?.[hash.toUpperCase()];

    rows.push({
      hash,
      name: amendmentName,
      xls: entry?.xls ?? null,
      description: description?.description ?? null,
      xls_url: description?.xls_url ?? null,
      count:       own ? count       : amendmentTally(f.count),
      threshold:   own ? threshold   : amendmentTally(f.threshold),
      validations: own ? validations : amendmentTally(f.validations),
      support_pct: supportPct,
      progress_state: progressState,
      needed_count: needed,
      majority_at_ms: majorityAt,
      support_state: supportState,
      counted: countedRow,
      our_vote: ourVote,
      supported: Boolean(f.supported),
    });
  }
  rows.sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { sensitivity: 'base' }));
  return rows;
}

// ── The aggregate counts the Governance card and the `governance` read ──
// route both publish. One definition, for the same reason the row builder
// above is one: server.ts had this loop twice (sampleGovernance's own and
// pollFeature's summary), and the two disagreed about "approaching" — one
// compared `count` against 75% of threshold, the other `validations`
// against 80%. Nothing on either page said which number it was showing.

export interface AmendmentVoteSummary {
  enabled: number;
  supported: number;
  vetoed: number;
  /** supported-and-not-enabled. Kept beside the ballot's own `pendingCount`
   *  (onTheBallot) because the Governance card still exposes both. */
  supported_pending: number;
  /** null on a node that reports no vote tally at all — "cannot tell", not
   *  "none". See amendmentTally. */
  approaching: number | null;
  threshold_met: number | null;
  our_votes: { yes: number; no: number; default: number };
}

/** Every aggregate the Governance tab's AMENDMENT STATUS / OUR VOTE STANCE
 *  cards render, computed once over one `feature` response. */
export function buildAmendmentVoteSummary(
  features: Record<string, AmendmentFeatureEntry>,
  counted?: CountedAmendmentSupport | null,
): AmendmentVoteSummary {
  let enabled = 0, supported = 0, vetoed = 0, supportedPending = 0;
  let approaching = 0, thresholdMet = 0;
  let yes = 0, no = 0, def = 0;
  let anyTally = false;

  for (const hash of Object.keys(features)) {
    const f = features[hash];
    if (f.enabled)   enabled++;
    if (f.supported) supported++;
    if (f.vetoed)    vetoed++;

    const isPending = Boolean(f.supported) && !f.enabled;
    if (isPending) supportedPending++;

    // The same precedence as the ballot rows: the node's own tally, else
    // the dashboard's count, so the card above the table and the rows in it
    // measure the same thing.
    const { count, threshold } = rowTally(f, hash, counted);
    const rated     = count !== null && threshold !== null && threshold > 0;
    if (rated) anyTally = true;
    const atThreshold = rated && count >= threshold;
    if (atThreshold && !f.enabled) thresholdMet++;
    if (isPending && rated && !atThreshold && count >= threshold * 0.75) approaching++;

    if (!f.enabled) {
      if (f.vetoed === 'Obsolete')    def++;      // not a choice the operator made
      else if (f.vetoed === true)     no++;
      else if (f.supported)           yes++;
      else                            def++;
    }
  }

  return {
    enabled, supported, vetoed,
    supported_pending: supportedPending,
    approaching:   anyTally ? approaching  : null,
    threshold_met: anyTally ? thresholdMet : null,
    our_votes: { yes, no, default: def },
  };
}

/**
 * Which amendment is closest to activating, read off the ballot rows rather
 * than a second pass over `features` — the duplicate loop is what let the
 * ballot and the card disagree in the first place.
 *
 * Scoped to *supported* rows, as it always was: an unsupported amendment
 * crossing threshold means this node is about to be amendment-blocked, which
 * the Amendment Blocked pill already reports on its own.
 *
 * Two ways to rank, in order. A tally ranks first and by `count`, which is
 * comparable across the rows of one node whatever its denominator. Failing
 * that, a row HOLDING THE MAJORITY is still a fact this node reported, and
 * ranking on it is what keeps the card from dashing directly above a ballot
 * row reading "Majority", the same page holding a fact in one place and
 * denying it in another, which is the defect the support column was just
 * fixed for. Longest-held majority wins: it is the one closest to the end of
 * its window. Only when neither exists is the answer 'none', which on a
 * tracking node with nothing at majority is the honest answer.
 */
export function nextActivationFromRows(
  rows: AmendmentBallotRow[],
): { status: 'pending' | 'gathering' | 'none'; name: string | null } {
  // `count` is the node's own; a counted row carries its figure under
  // `counted`. Either is a tally this node can rank on.
  const tallied = (r: AmendmentBallotRow): number | null => r.count ?? r.counted?.count ?? null;
  let best: AmendmentBallotRow | null = null;
  for (const r of rows) {
    const c = tallied(r);
    if (!r.supported || c === null) continue;
    if (best === null || c > (tallied(best) as number)) best = r;
  }
  if (best !== null) {
    return {
      status: best.progress_state === 'pending' ? 'pending' : 'gathering',
      name: best.name,
    };
  }

  let heldLongest: AmendmentBallotRow | null = null;
  for (const r of rows) {
    if (!r.supported || r.majority_at_ms === null) continue;
    if (heldLongest === null || r.majority_at_ms < (heldLongest.majority_at_ms as number)) heldLongest = r;
  }
  if (heldLongest === null) return { status: 'none', name: null };
  return { status: 'pending', name: heldLongest.name };
}

// ── #654: an amendment THIS BUILD does not support, holding majority ────
//
// `nextActivationFromRows` above is scoped to *supported* rows by design,
// with its own comment saying why: an unsupported row crossing the bar
// means this node is about to be amendment-blocked, a different fact from
// "which amendment is this node's own vote closest to passing". Nothing
// upstream of the Amendment Blocked pill said so ahead of time — that pill
// reports rippled's own `amendment_blocked`, which only turns true once
// blocking has already happened. This is the earlier warning: the pill's
// fact, days before it is true.

/** rippled's own amendment activation delay: two weeks from the moment an
 *  amendment first holds (and keeps) the network's 80% majority. Source:
 *  XRPLF/rippled `Amendments.h`, `defaultAmendmentMajorityTime` /
 *  xrpl.org's amendment lifecycle docs — every majority amendment activates
 *  exactly this long after `majority` is set, absent an operator veto that
 *  removes support before then. Measured against the prod validator's own
 *  `feature` reading, 2026-09-26: majority since 2026-09-25 ~14:12 UTC,
 *  activation named as "about 2026-10-09 14:12 UTC" in this issue — 14 days,
 *  to the reported minute. */
export const AMENDMENT_MAJORITY_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

/** One amendment this build's own vote cannot stop: unsupported, and already
 *  holding the network's majority. `block_at_ms` is when it activates absent
 *  an intervening upgrade; `days_left` is how far away that is right now,
 *  and goes negative once the window has closed (which reads the same as
 *  `amendment_blocked` — this node just has not polled `server_info` since,
 *  or the block already happened and this fact is now historical). */
export interface UnsupportedMajorityAmendment {
  hash: string;
  name: string;
  majority_at_ms: number;
  block_at_ms: number;
  days_left: number;
}

/** No unsupported amendment holds majority right now — the metric's healthy
 *  reading. Large and constant, the same convention `nudb_mount_free_days`
 *  uses for "not filling": a rule threshold of `<= 14` or `<= 3` can never
 *  mistake it for a real countdown, and it is one fixed number rather than
 *  a magic 9999 repeated at every call site. */
export const NO_UNSUPPORTED_MAJORITY_DAYS = 99999;

/**
 * The unsupported-and-at-majority amendment closest to activating, or null.
 *
 * Ranked by `majority_at_ms` (earliest wins): the one that has held the
 * network's majority longest is the one closest to the end of its window,
 * same ranking rule `nextActivationFromRows` uses for a supported row.
 * `vetoed === 'Obsolete'` is excluded via the same `onTheBallot` gate every
 * other reader of `features` goes through — an amendment rippled has
 * dropped from its own build cannot activate against this node either.
 */
export function nextUnsupportedMajority(
  features: Record<string, AmendmentFeatureEntry>,
  ext?: Record<string, AmendmentExtInfo>,
  nowMs: number = Date.now(),
): UnsupportedMajorityAmendment | null {
  let best: { hash: string; f: AmendmentFeatureEntry; majorityAt: number } | null = null;
  for (const hash of Object.keys(features)) {
    const f = features[hash];
    if (!onTheBallot(f) || f.supported) continue;
    const majorityAt = rippleEpochToMs(f.majority);
    if (majorityAt === null) continue;
    if (best === null || majorityAt < best.majorityAt) best = { hash, f, majorityAt };
  }
  if (best === null) return null;
  const entry = ext?.[best.hash.toUpperCase()];
  const name = (typeof best.f.name === 'string' && best.f.name) || entry?.name || (best.hash.slice(0, 8) + '…');
  const blockAt = best.majorityAt + AMENDMENT_MAJORITY_WINDOW_MS;
  return {
    hash: best.hash,
    name,
    majority_at_ms: best.majorityAt,
    block_at_ms: blockAt,
    days_left: (blockAt - nowMs) / (24 * 60 * 60 * 1000),
  };
}

/**
 * The Insights metric this fact is written as: days until this node is
 * amendment-blocked by something it does not support, or the healthy
 * constant when nothing is at majority.
 *
 * Written UNCONDITIONALLY whenever this node can answer the question at
 * all (the same "always write, healthy value when clear" rule
 * `nudb_mount_free_days` follows) rather than only while an amendment is at
 * majority: a metric that stops being written the moment its own condition
 * clears leaves the alert rule holding whatever it last saw forever,
 * because `evaluateRulesForMetric` only re-checks a rule on a new sample.
 * Support returning, an operator's own veto, or an upgrade landing before
 * the window closes all have to read back as healthy, and only a written
 * sample can say that.
 */
export function unsupportedMajorityDaysMetric(
  features: Record<string, AmendmentFeatureEntry>,
  ext?: Record<string, AmendmentExtInfo>,
  nowMs: number = Date.now(),
): number {
  const next = nextUnsupportedMajority(features, ext, nowMs);
  return next === null ? NO_UNSUPPORTED_MAJORITY_DAYS : next.days_left;
}
