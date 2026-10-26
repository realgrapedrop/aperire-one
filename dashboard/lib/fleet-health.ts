/**
 * Fleet health — server-side polling of peer read-APIs (task step B).
 *
 * This module never runs in the browser: the peer's token lives here and
 * nowhere else. Tokens are read from `token_path` per poll (same pattern as
 * READ_TOKEN_PATH in server.ts — rotation needs no restart), and the public
 * view built by `toPublicPeer` deliberately drops `read_origin`/`token_path`
 * so a spread can never leak them to the browser.
 *
 * Verdict derivation is pure (`deriveVerdict`) so the fresh/stale/firing/
 * silent cases are unit-testable without a network. The poller itself
 * (`FleetHealthPoller`) is the thin, mostly-untested shell around it: two
 * reads per peer per cycle (`recent?metric=peer_count&limit=1` for
 * reachability + freshness — the same read the fleet guide already tells
 * operators to verify with — and `firing` for degraded-but-reachable), each
 * bounded by AbortSignal.timeout so one hung peer cannot pin the cycle.
 *
 * This node's own row is never polled through here — "never poll yourself
 * through the loopback like a stranger" (task B). `isSelf` identifies it by
 * comparing a peer's read_origin against this process's own bound port; the
 * caller (server.ts) computes that row's verdict from state it already has
 * (node reachability, firing alerts) and merges it in via `mergeSelf`.
 */
import { readFileSync } from 'node:fs';
import type { FleetNodeConfig } from './fleet-registry.js';
import type { ReadFiringStateRow, ReleaseIdentityWire } from '../types/read-contract.js';
import { parseIdentityWire } from './release-stamp.js';
import { gradeWithFloor, releaseFloor, type UpdateLatest } from './update-check.js';
import type { PeerConcernInput } from './concerns.js';
import { compareVersions, readVersion } from './version-compare.js';
import { parseDeployRef, compareDeployRefs, type DeployRefState, type DeployComparison } from './deploy-ref.js';

// 'critical' is the fourth verdict both sortFleetForDisplay's VERDICT_RANK
// (below) and fleet-chip.js's own comment already reserved a slot for ("in
// case a future verdict adds one") — this pin-mismatch integrity failure is
// that future verdict. Deliberately distinct from 'unreachable': a peer that
// ANSWERS but is the wrong node is a different fact than a peer that does not
// answer at all, and conflating the two would hide the one signal this slice
// exists to surface — see stateWord()'s fixed detail text in fleet-chip.js,
// which 'unreachable' never shows (it always renders "UNREACHABLE · last
// known Xm ago" regardless of detail).
// 'refused' is the fifth verdict, and the distinction it draws is the whole
// of issue #268: a peer that ANSWERS the read API with 401 or 403 said no,
// which is not the same fact as a peer that did not answer at all. On
// 2026-09-09 a wiped-and-reinstalled node minted a fresh read token, this
// dashboard's registry still held the old one, and the fleet showed the box
// as UNREACHABLE — sending the operator to check a network path that was
// fine. Reachability and authorisation are two facts. Red on both, because
// both need attention; different words, because they need different work.
export type FleetVerdict = 'ok' | 'warn' | 'unreachable' | 'refused' | 'critical';

// The exact wording, decisions.md D6 addendum / fleet-build-punchlist.md.
export const PIN_MISMATCH_DETAIL =
  'answers, but its node key is not the one registered — if this node was rebuilt, re-pin it (see the fleet guide)';

/** The two statuses that mean "I heard you, and no". Everything else a peer
 *  can answer with (500, 502, a malformed body) is trouble on its side, not
 *  a decision about this dashboard's credential, and stays unreachable. */
export function isRefusedStatus(status: number): boolean {
  return status === 401 || status === 403;
}

/** The refusal, as a verdict: the status code and the route that carried it,
 *  because "401 on recent" is what an operator greps a log for. The prose
 *  that tells them what to DO about it is composed by the browser (one copy,
 *  fleet-chip.js's refusedTip) — a fixed sentence naming a label has no
 *  business being repeated on the wire for every row. */
export function refusedVerdict(status: number, route: string | null): VerdictResult {
  return {
    verdict: 'refused',
    detail: `read token rejected (HTTP ${status}${route ? ` on ${route}` : ''})`,
  };
}

/** The three canaries when a peer refused. All three say the same thing the
 *  overall verdict does — nothing was read, and the reason is not silence. */
function refusedTriple(status: number, route: string | null): {
  stateVerdict: VerdictResult; healthVerdict: VerdictResult; alertsVerdict: VerdictResult;
} {
  const v = refusedVerdict(status, route);
  return { stateVerdict: v, healthVerdict: v, alertsVerdict: v };
}

/** What the browser is allowed to see. No read_origin, no token_path. */
export interface FleetPeerPublic {
  label: string;
  /** Optional — absent when this fleet does not know where that node's own
   *  dashboard is (#339). Nothing in the browser navigates to it today (D8
   *  slice 3 moved node picking to a label in the shell's hash), so this is
   *  a record of what the row holds; absent renders as "not set" wherever
   *  one is added, and never as a `.localhost` link nobody can open. */
  dashboard_url?: string;
  self: boolean;
  verdict: FleetVerdict;
  detail: string;             // '' when ok; a short reason otherwise
  // The three canaries the FLEET card renders as S / H / A. `verdict` above is
  // their rollup (the chip's single dot). Optional so an older cache or the
  // self row (which sets them from the overall) can omit them; the card falls
  // back to the overall verdict when a component is absent.
  state_verdict?: FleetVerdict;
  state_detail?: string;
  health_verdict?: FleetVerdict;
  health_detail?: string;
  alerts_verdict?: FleetVerdict;
  alerts_detail?: string;
  /** R — the release canary, the leftmost of the four badges. Its two halves
   *  are carried as separate fields rather than only inside `release_detail`
   *  because the card renders them separately: the running version in the
   *  tooltip's body, the newer one beside it in amber. A browser that had to
   *  split the detail prose back apart would break the moment the wording
   *  changed. `latest_available` is what this row was actually COMPARED
   *  against — null on a row that was never graded (unreachable, or the wrong
   *  node answered) — and never a promise that an upgrade exists. */
  release_verdict?: FleetVerdict;
  release_detail?: string;
  build_version?: string | null;
  latest_available?: string | null;
  /** The machine the node runs on: its OS hostname as its own dashboard
   *  reports it. Gated like build_version (null when unreachable or when the
   *  wrong node answered), and null for a host that never said. */
  host_name?: string | null;
  /** Epoch ms of the last successful poll (or, for the self row, always
   *  "now" while the row exists). Null only if this peer has never once
   *  answered since this process started. The browser formats "Xm ago" from
   *  this at render time — never a server-formatted string, which would
   *  freeze between broadcasts (the project's kept-vs-observed shape).
   *  Means "last successful poll of the REGISTERED node" — a mismatched
   *  answer never advances this, even though the wrong node did respond. */
  last_seen_ms: number | null;
  /** Only meaningful for a PINNED row (fleet.yaml's expected_pubkey_node).
   *  undefined — this row is unpinned; the concept doesn't apply and never
   *  will for it. true — the peer's own /read/v1/identity was read this
   *  cycle (or the last cycle it answered) and its pubkey_node matched.
   *  false — pinned, but not currently confirmed: either the keys disagree
   *  (verdict is 'critical') or the identity route itself couldn't be read
   *  (an older, un-upgraded peer 404s it — see checkIdentityPin). */
  verified?: boolean;
  /** The commit this host's install was last deployed from, and where it
   *  sits relative to the rest of the fleet (issue #128 rung 2). Both are
   *  optional and both are absent together on a row that was never graded.
   *
   *  `deploy_ref` null means the host reported none — no stamp, an older
   *  peer that does not carry the field, or a peer that did not answer.
   *  `deploy_state` says what that is worth once the fleet is looked at as
   *  a whole: 'shared' (on the ref the largest group is on), 'divergent'
   *  (reported a different one), 'unknown' (reported none, and therefore
   *  neither). Set at assembly (server.ts's fleetView), not by the poller,
   *  because a host's state is a fact about the SET and no single poll can
   *  know it. */
  deploy_ref?: string | null;
  deploy_state?: DeployRefState;
  /** Which Aperire RELEASE this host's install is, and where that sits
   *  against the release the endpoint currently publishes (ADR 0022
   *  decision 6). Distinct from the two fields above in what it answers:
   *  `deploy_state` compares hosts to each other and can only say they
   *  differ, this compares every host to one `release.json` the aggregator
   *  fetched once and can say which of them is behind.
   *
   *  `aperire_release` is what the host said about itself, already parsed;
   *  `unknown` covers a peer that did not answer, one older than the field,
   *  and one carrying no stamp. `aperire_release_state` is 'current',
   *  'behind' or 'unknown', and unknown is never either of the other two.
   *  'older' is a host whose release was published AFTER the one the endpoint
   *  serves: the endpoint is replaying an older signed release (#1073),
   *  which is nothing to do and never 'behind'.
   *  Both are set at assembly, not by the poller, because grading needs the
   *  published release and no single poll has it. */
  aperire_release?: ReleaseIdentityWire;
  aperire_release_state?: 'current' | 'behind' | 'unknown' | 'not_verified' | 'older';
  /** The status the peer refused this dashboard's read token with — 401 or
   *  403 — present only on a row whose verdict is 'refused', absent on every
   *  other row. Additive, and the only new member this state puts on the
   *  wire: the sentence that tells an operator what to do about it is
   *  composed in the browser from the label it already has. */
  refused_status?: number;
  /** The identity verdict, named. Present together, and only on a row whose
   *  pinned key was READ this cycle and disagreed (#273) — never on a row
   *  that merely could not be checked, and never on one that has since gone
   *  dark. Both are node public keys, which are public by construction: they
   *  are already served by /read/v1/identity and printed on the Overview.
   *
   *  They are what turns "can't compare" into a sentence an operator can
   *  act on, and they are also the discriminator every consumer keys on —
   *  `verdict: 'critical'` is not, because a firing critical alert produces
   *  the same verdict and has nothing to do with identity. */
  pin_expected?: string;
  pin_reported?: string;
  /**
   * The SELF row's pin verdict (#488), and the reason this member exists at
   * all: on a peer the two keys above are the whole story, and on this host
   * they are not.
   *
   * A peer's mismatch means the wrong node answered, so everything it said is
   * refused. This host's mismatch means the REGISTRY IS STALE: the dashboard
   * reads its own node directly, nothing it reported is in doubt, and the file
   * that disagrees with it is the one on this disk. The two need different
   * words, so they need different discriminators, and every consumer that
   * reads "the wrong node answered" out of `pin_expected`/`pin_reported`
   * excludes `self` rows rather than being handed keys it would mis-describe.
   *
   *   'ok'           the registry pins this node's own key.
   *   'changed'      it pins another, and both keys are on the row.
   *   'unconfirmed'  pinned, and this node has not said what its key is
   *                  (rippled unreachable, or a snapshot with no pubkey_node).
   *                  Never rendered as a mismatch: "could not read my own key"
   *                  is not "the registry is wrong", the same rule
   *                  checkIdentityPin already holds for a peer.
   *
   * Absent on an unpinned row, which fleet-registry.ts documents as
   * first-class, and absent on every peer row.
   */
  pin_state?: 'ok' | 'changed' | 'unconfirmed';
}

/** The self row's pin, compared. `expected` is the registry row's
 *  `expected_pubkey_node`, `reported` is what this node's own snapshot says
 *  its `pubkey_node` is (the value /read/v1/identity serves, read from the
 *  same snapshot and never from a fresh poll).
 *
 *  Pure, and null on an unpinned row: a fleet.yaml that names no key for this
 *  host is the ordinary single-node shape, not a lesser mode.
 *
 *  The keys come back only when a real comparison was made, the same
 *  discipline checkIdentityPin holds for a peer: a key nobody read is not a
 *  key, and an unread key must never render as a changed one. */
export interface SelfPinFacts {
  state: 'ok' | 'changed' | 'unconfirmed';
  expected: string;
  /** Only on 'ok' and 'changed'. Null when nothing was read. */
  reported: string | null;
}

export function selfPinFacts(
  expected: string | null | undefined,
  reported: string | null | undefined,
): SelfPinFacts | null {
  const pinned = typeof expected === 'string' && expected ? expected : null;
  if (!pinned) return null;
  const own = typeof reported === 'string' && reported ? reported : null;
  if (!own) return { state: 'unconfirmed', expected: pinned, reported: null };
  if (own === pinned) return { state: 'ok', expected: pinned, reported: own };
  return { state: 'changed', expected: pinned, reported: own };
}

/** The states in which a node is actually doing its job on the network: fully
 *  synced (`full`), or a validator taking part (`proposing`/`validating`).
 *  Anything else it reports — `connected`, `syncing`, `tracking`,
 *  `disconnected` — is not-yet-there, and a node that is not there is not
 *  healthy-green however fresh its metrics are. */
const SYNCED_STATES = new Set(['full', 'proposing', 'validating']);

export interface VerdictResult { verdict: FleetVerdict; detail: string }

// ── The canaries (ADR: FLEET card R / S / H / A, one meaning each) ─────────
// Each grades ONE thing, so the badges never double-count and the chip's
// single dot is their rollup (below). R = the node's release posture; S = the
// node's own sync state; H = whether this reading can be trusted (reachable,
// fresh, identity-pinned); A = the Insights alerts firing on this node, by
// severity.

/** S — the node's own sync state. */
export function deriveStateVerdict(input: { reachable: boolean; serverState?: string | null }): VerdictResult {
  if (!input.reachable) return { verdict: 'unreachable', detail: 'no answer' };
  // Reachable but state not read (an older peer that does not serve
  // node-status, or a hiccup) — "couldn't check" is not "not synced", so it is
  // not penalised here; H carries the reachability/freshness story.
  if (!input.serverState) return { verdict: 'ok', detail: '' };
  if (SYNCED_STATES.has(input.serverState)) return { verdict: 'ok', detail: input.serverState };
  return { verdict: 'warn', detail: `not fully synced (${input.serverState})` };
}

/** S for the SELF row. The exact same not-fully-synced comparison above,
 *  plus one rule a peer never needs (#505). A peer's missing `server_state`
 *  can be an older dashboard that has never served `node-status` at all, a
 *  structural and permanent gap `deriveStateVerdict` rightly waves through
 *  as "couldn't check, not penalised". This row is the node reporting on
 *  ITSELF, so "reachable" alone is not the same claim as "I have read my own
 *  state". At cold start, before the first `server_info` poll has landed,
 *  reachability is only the optimistic default this process boots with, and
 *  a missing reading there must read the same as no answer at all, never
 *  fine. `everObserved` is the fact that tells the two apart: once this
 *  process has read its own `server_info` at least once, a later reply that
 *  drops the field (a fork renaming it) falls back to the ordinary
 *  "couldn't check" every peer gets, rather than manufacturing a second
 *  reading of a fact this process plainly has other evidence for. */
export function deriveSelfStateVerdict(input: {
  reachable: boolean;
  serverState?: string | null;
  everObserved: boolean;
}): VerdictResult {
  if (input.reachable && !input.serverState && !input.everObserved) {
    return { verdict: 'unreachable', detail: 'no answer' };
  }
  return deriveStateVerdict(input);
}

/** H — can this reading be trusted? Reachability, freshness, identity — and
 *  NOT alerts or sync state, which are A's and S's jobs. */
export function deriveHealthVerdict(input: {
  reachable: boolean; sampleAgeMs: number | null; staleAfterMs: number; pinMismatch?: boolean;
}): VerdictResult {
  if (!input.reachable) return { verdict: 'unreachable', detail: 'no answer' };
  if (input.pinMismatch) return { verdict: 'critical', detail: PIN_MISMATCH_DETAIL };
  if (input.sampleAgeMs === null) return { verdict: 'warn', detail: 'no data yet' };
  if (input.sampleAgeMs > input.staleAfterMs) return { verdict: 'warn', detail: 'stale data' };
  return { verdict: 'ok', detail: '' };
}

/** A — Insights alerts firing on this node, graded by their worst severity. */
export function deriveAlertsVerdict(input: { reachable: boolean; firing: ReadFiringStateRow[] | null }): VerdictResult {
  if (!input.reachable) return { verdict: 'unreachable', detail: 'no answer' };
  const rows = input.firing || [];
  if (!rows.length) return { verdict: 'ok', detail: '' };
  const label = `${rows.length} alert${rows.length === 1 ? '' : 's'} firing`;
  if (rows.some((r) => r.severity === 'critical' || r.severity === 'page')) return { verdict: 'critical', detail: label };
  if (rows.some((r) => r.severity === 'warn')) return { verdict: 'warn', detail: label };
  return { verdict: 'ok', detail: '' };
}

/** R — the node's release posture: is it running something current, is it
 *  behind, or has it fallen off the network entirely?
 *
 *  Red is reserved for amendment-blocked, which is not "an upgrade is
 *  available" but "this node stopped following the ledger because an
 *  amendment activated past its build". Amber is merely behind. Green
 *  includes every case where there is nothing to compare — an unknown
 *  build_version, or an aggregator that has not managed to read the upstream
 *  release lists — because missing data is not a fault and a badge that
 *  ambers on ignorance is a badge operators learn to ignore. */
export function deriveReleaseVerdict(input: {
  reachable: boolean;
  buildVersion?: string | null;
  latestRelease?: string | null;
  amendmentBlocked?: boolean | null;
}): VerdictResult {
  if (!input.reachable) return { verdict: 'unreachable', detail: 'no answer' };
  // Strictly `=== true`: null is "the governance route did not answer", which
  // is a different fact from "it answered and said no", and only the second
  // could ever clear this. Neither reds the badge on a guess.
  if (input.amendmentBlocked === true) return { verdict: 'critical', detail: 'amendment blocked' };
  if (!input.buildVersion || !input.latestRelease) {
    return { verdict: 'ok', detail: input.buildVersion ? input.buildVersion : '' };
  }
  // One comparator for every surface (#667): the version pill, the
  // node_version_behind metric and this badge all ask lib/version-compare.ts,
  // so a node on 3.4.1-rc1 with 3.4.1 released reads as behind on all three
  // and ambers together. A version nobody can read stays quiet, as it always
  // did: no number, no claim.
  const running = readVersion(input.buildVersion);
  const latest = readVersion(input.latestRelease);
  if (running && latest && compareVersions(running, latest) < 0) {
    return { verdict: 'warn', detail: `${input.buildVersion} — ${input.latestRelease} available` };
  }
  return { verdict: 'ok', detail: input.buildVersion };
}

/** What R contributes to the OVERALL dot — and it is deliberately not what R
 *  itself shows. A node that is amendment-blocked is off the network, so that
 *  reddens the row; a node that is merely a release behind does NOT amber it.
 *
 *  The asymmetry is the point. Plenty of operators sit a release behind on
 *  purpose (waiting out a point release, staging an upgrade across a fleet),
 *  and a fleet whose dots all go amber the day a version ships would train
 *  everyone to stop reading the dots — which is the one thing they exist for.
 *  The [R] badge still shows the full green/amber/red, so "behind" is visible
 *  to anyone looking at the node; it just is not an alarm. */
export function releaseEscalation(release: VerdictResult): VerdictResult {
  return release.verdict === 'critical' ? release : { verdict: 'ok', detail: '' };
}

/** The single dot the chip shows — the worst of the parts, so it can never
 *  disagree with the badges. critical > refused > unreachable > warn > ok.
 *  Refused sits above unreachable because it is the more specific fact: a
 *  peer that answered and said no has told us something a silent one has
 *  not, and a rollup must never lose it. */
const SEVERITY: Record<FleetVerdict, number> = { ok: 0, warn: 1, unreachable: 2, refused: 3, critical: 4 };
export function rollupVerdict(...parts: VerdictResult[]): VerdictResult {
  return parts.reduce<VerdictResult>(
    (worst, p) => (SEVERITY[p.verdict] > SEVERITY[worst.verdict] ? p : worst),
    { verdict: 'ok', detail: '' },
  );
}

/** The three canaries when nothing was read — a peer that did not answer, or
 *  whose token could not be read. All three say the same "no answer" the
 *  overall verdict does, so no badge claims to know a state we never got. */
const UNREACHABLE_TRIPLE: {
  stateVerdict: VerdictResult; healthVerdict: VerdictResult; alertsVerdict: VerdictResult;
} = {
  stateVerdict: { verdict: 'unreachable', detail: 'no answer' },
  healthVerdict: { verdict: 'unreachable', detail: 'no answer' },
  alertsVerdict: { verdict: 'unreachable', detail: 'no answer' },
};

export interface VerdictInput {
  reachable: boolean;
  /** Age of the most recent sample in ms, or null if the peer answered but
   *  returned no samples at all (a fresh install with nothing written yet). */
  sampleAgeMs: number | null;
  staleAfterMs: number;
  firingCount: number;
  /** The peer's server_state, when it could be read. null = not read. */
  serverState?: string | null;
  /** Set when the peer answered a read with 401/403. Outranks everything
   *  else here: nothing below it was read, and the reason is a decision the
   *  peer made, not silence. */
  refusedStatus?: number | null;
  refusedRoute?: string | null;
}

/** The overall verdict — the rollup of state, health and alerts — kept as the
 *  single value the chip dot and /api/fleet's `verdict` carry, so the dot is
 *  always the worst of the three badges. Alerts here come coarsely from the
 *  firing COUNT (the rich, severity-aware A verdict uses the rows). */
export function deriveVerdict(input: VerdictInput): VerdictResult {
  // A refusal is an answer, and it is the only thing this poll learned.
  // Checked before reachability so it can never be flattened into it.
  if (input.refusedStatus) return refusedVerdict(input.refusedStatus, input.refusedRoute ?? null);
  const alerts: VerdictResult = input.firingCount > 0
    ? { verdict: 'warn', detail: `${input.firingCount} alert${input.firingCount === 1 ? '' : 's'} firing` }
    : { verdict: 'ok', detail: '' };
  return rollupVerdict(
    deriveStateVerdict({ reachable: input.reachable, serverState: input.serverState }),
    deriveHealthVerdict({ reachable: input.reachable, sampleAgeMs: input.sampleAgeMs, staleAfterMs: input.staleAfterMs }),
    alerts,
  );
}

export interface PeerPollResult {
  reachable: boolean;
  sampleAgeMs: number | null;
  firingCount: number;
  /** The ROWS behind `firingCount`, retained rather than discarded — the
   *  concern layer cites each firing alert individually (which metric, what
   *  it measured, against what) and cannot do that from a count.
   *
   *  `null` means the firing read itself did not produce a usable answer
   *  this poll; `[]` means it did and there was nothing firing. The
   *  distinction is the whole of the resolution rule (concern-cards design
   *  3.7): rows are cleared only by a SUCCESSFUL read that returned none,
   *  never by a failed one, so a peer whose firing route hiccups does not
   *  read as "the alerts cleared".
   *
   *  `firingCount` deliberately stays 0 in the null case, exactly as it was
   *  before this field existed: `deriveVerdict` is untouched, so a failed
   *  firing read still does not degrade the fleet verdict and /api/fleet's
   *  dot is byte-identical to what it was. */
  firing: ReadFiringStateRow[] | null;
  /** The peer's server_state (full / proposing / connected / syncing / …),
   *  or null if the state read did not answer. Feeds deriveVerdict's
   *  not-fully-synced check. */
  serverState: string | null;
  /** The peer's build_version, from the SAME node-status body serverState
   *  comes from — one read, two facts. Null when the read did not answer, or
   *  when what it returned was not version-shaped (see versionStr). */
  buildVersion: string | null;
  /** The peer's amendment_blocked, from its governance route. Three states,
   *  and the third is load-bearing: true (it said yes), false (it said no),
   *  null (nobody said). Only true reds [R]; null never does. */
  amendmentBlocked: boolean | null;
  /** The peer's `.deploy-ref` — which commit that HOST's install was last
   *  deployed from — off the same node-status body as serverState and
   *  buildVersion (issue #128 rung 2). Null covers three different things
   *  and is deliberately not split: the read did not answer, the peer is
   *  older than the field, or the peer has no stamp. All three are
   *  "unknown", and unknown is never counted as agreeing with anyone. */
  deployRef: string | null;
  /** The peer's OS hostname, its `host_name` off the same node-status body
   *  (the read contract's own words: the machine, never the browser's
   *  origin and never a public URL). Null when the read did not answer, the
   *  peer predates the field, or the host reports no name; all three are
   *  "not said", and the page prints a dash for them. */
  hostName: string | null;
  /** The peer's release identity, off the SAME node-status body deployRef
   *  comes from. `{kind:'unknown'}` when the read did not answer, the peer
   *  is older than the field, or the host carries no stamp. All three are
   *  the same nothing, and none of them is ever graded as current. */
  release: ReleaseIdentityWire;
  /** The status the peer refused the gate read with (401 or 403), and which
   *  route carried it. Null on every other outcome, including a 500 — a peer
   *  in trouble is not a peer that rejected a credential. `reachable` stays
   *  false alongside these: nothing WAS read. The two are not the same fact
   *  and every consumer checks the refusal first. */
  refusedStatus: number | null;
  refusedRoute: string | null;
}

type FetchImpl = typeof fetch;

interface RecentBody { points?: Array<{ ts: number; value: number }> }
interface FiringBody { firing?: unknown[] }

/** Peer firing rows now reach the browser as card evidence rather than dying
 *  as a `.length`, so they are re-typed here field by field rather than cast.
 *  A peer is a trusted-but-separate box: its rows arrive over the network and
 *  a malformed (or oversized) one must not become a concern's title. Anything
 *  that is not the expected shape is dropped; strings are clamped. */
const MAX_FIRING_ROWS = 50;
const MAX_FIELD_CHARS = 120;
function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v.slice(0, MAX_FIELD_CHARS) : null;
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
/** A peer's build_version is validated at ingest for the same reason the
 *  firing rows above are, and it matters more: it reaches the browser inside
 *  the [R] badge's tooltip, which the FLEET card sets as innerHTML. Version
 *  characters only (digits, letters, and the separators forks actually use —
 *  `2.2.0`, `2.3.0-rc1`, `1.12.0+DEBUG`), clamped. Anything else is dropped
 *  to null, which [R] already reads as "nothing to compare against" rather
 *  than as a fault. */
const VERSION_RE = /^[0-9A-Za-z._+-]{1,32}$/;
export function versionStr(v: unknown): string | null {
  return typeof v === 'string' && VERSION_RE.test(v) ? v : null;
}

export function sanitiseFiringRows(raw: unknown): ReadFiringStateRow[] {
  if (!Array.isArray(raw)) return [];
  const out: ReadFiringStateRow[] = [];
  for (const item of raw.slice(0, MAX_FIRING_ROWS)) {
    if (typeof item !== 'object' || item === null) continue;
    const r = item as Record<string, unknown>;
    const dedupKey = str(r.dedup_key);
    const metric = str(r.metric);
    const severity = str(r.severity);
    if (!dedupKey || !metric) continue;
    if (severity !== 'warn' && severity !== 'critical' && severity !== 'page') continue;
    out.push({
      dedup_key: dedupKey,
      metric,
      severity,
      triggered_ts: num(r.triggered_ts) ?? 0,
      fired_ts: num(r.fired_ts) ?? 0,
      last_value: num(r.last_value),
      last_seen_ts: num(r.last_seen_ts),
      threshold_op: str(r.threshold_op),
      threshold_value: num(r.threshold_value),
      duration_s: num(r.duration_s),
      channels: [],          // never rendered by the concern layer; not carried
      acked_at: num(r.acked_at),
      muted_until: num(r.muted_until),
      last_paged_ts: num(r.last_paged_ts),
    });
  }
  return out;
}

/** Nothing was read. Written once so no failure branch below can invent a
 *  different shape of "we learned nothing" as fields are added to the result. */
const UNREACHABLE_POLL: PeerPollResult = {
  reachable: false, sampleAgeMs: null, firingCount: 0, firing: null,
  serverState: null, buildVersion: null, amendmentBlocked: null, deployRef: null, release: { kind: 'unknown' }, hostName: null,
  refusedStatus: null, refusedRoute: null,
};

/** One poll cycle against one peer. Never throws — every failure mode
 *  (network error, timeout, non-200, malformed body) collapses to
 *  `reachable: false`, which `deriveVerdict` reads as unreachable. */
export async function pollOnePeer(
  node: FleetNodeConfig,
  token: string,
  opts: { timeoutMs: number; fetchImpl?: FetchImpl },
): Promise<PeerPollResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const headers = { authorization: `Bearer ${token}` };
  try {
    const recentRes = await doFetch(
      `${node.read_origin}/read/v1/recent?metric=peer_count&limit=1`,
      { headers, signal: AbortSignal.timeout(opts.timeoutMs) },
    );
    // The gate read. A 401/403 here is the node answering that this
    // dashboard's token is not one it accepts — the fresh-install case
    // (#268) — and it stops the poll: every route below shares the same
    // credential, so re-asking four more times would learn the same no four
    // more times. Any other non-200 stays unreachable.
    if (!recentRes.ok) {
      return isRefusedStatus(recentRes.status)
        ? { ...UNREACHABLE_POLL, refusedStatus: recentRes.status, refusedRoute: 'recent' }
        : UNREACHABLE_POLL;
    }
    const recentBody = await recentRes.json() as RecentBody;
    const points = Array.isArray(recentBody.points) ? recentBody.points : [];
    const last = points.length ? points[points.length - 1] : null;
    const sampleAgeMs = last ? Math.max(0, Date.now() - Number(last.ts)) : null;

    let firingCount = 0;
    let firing: ReadFiringStateRow[] | null = null;
    try {
      const firingRes = await doFetch(
        `${node.read_origin}/read/v1/firing`,
        { headers, signal: AbortSignal.timeout(opts.timeoutMs) },
      );
      if (firingRes.ok) {
        const firingBody = await firingRes.json() as FiringBody;
        firing = sanitiseFiringRows(firingBody.firing);
        // Counted from the RAW array, not the sanitised one, so this number
        // means exactly what it meant before the rows were retained: how
        // many alerts the peer said were firing. A row this process could
        // not re-type would otherwise silently lower the fleet verdict.
        firingCount = Array.isArray(firingBody.firing) ? firingBody.firing.length : 0;
      }
    } catch { /* the peer already answered `recent`; a firing-read hiccup doesn't downgrade reachability */ }

    // The node's own sync state and its release posture, read last so they
    // never reorder the recent→firing sequence. Both are non-fatal, exactly
    // like firing: the peer already answered `recent`, so a hiccup on either
    // route (or an older peer that 404s one of them) leaves that value null
    // rather than downgrading reachability. deriveVerdict and
    // deriveReleaseVerdict both treat null as "not checked".
    //
    // The two are read as a PAIR rather than one after the other — neither
    // depends on the other, and four sequential 4s-bounded reads per peer
    // would put a slow fleet's worst-case cycle at the poll interval itself.
    // The "read last" rule above is about the recent→firing order, which is
    // untouched.
    const readJson = async (path: string): Promise<Record<string, unknown> | null> => {
      try {
        const res = await doFetch(
          `${node.read_origin}${path}`,
          { headers, signal: AbortSignal.timeout(opts.timeoutMs) },
        );
        if (!res.ok) return null;
        return await res.json() as Record<string, unknown>;
      } catch { return null; }
    };
    const [nsBody, govBody] = await Promise.all([
      readJson('/read/v1/node-status'),
      readJson('/read/v1/governance'),
    ]);
    const serverState = typeof nsBody?.server_state === 'string' ? nsBody.server_state : null;
    // build_version rides along on the node-status body that was already
    // being fetched for the state — the release canary costs no extra read.
    const buildVersion = versionStr(nsBody?.build_version);
    // Same body again, third fact: which deploy this peer's HOST is running.
    // Re-normalised through parseDeployRef rather than trusted as a string —
    // it came off the network, and a peer that sent something unref-shaped
    // reports nothing rather than putting it in a browser payload. A peer
    // too old to carry the key leaves this null, which is `unknown`, never
    // an assumed match (the version-skew rule: an un-upgraded peer must not
    // break the comparison or silently drop out of it).
    const deployRef = parseDeployRef(
      typeof nsBody?.deploy_ref === 'string' ? nsBody.deploy_ref : null,
    );
    // Only a governance route that ANSWERED can say a node is not blocked.
    // An older peer that predates the route 404s it and leaves this null, and
    // a staged fleet rollout must not red-flag every un-upgraded peer as
    // amendment-blocked — the same "couldn't check is not checked-and-wrong"
    // rule the identity pin follows.
    const amendmentBlocked = typeof govBody?.amendment_blocked === 'boolean'
      ? govBody.amendment_blocked : null;
    // Fifth fact off the same node-status body: which published release this
    // peer's install IS (ADR 0022). Re-parsed rather than trusted as an
    // object for the same reason deployRef is re-normalised above: it came
    // off the network. A peer too old to carry the key parses to `unknown`,
    // which is never graded as current and never as behind.
    const release = parseIdentityWire(nsBody?.release);
    // Fourth fact off the node-status body: the machine's own name. An
    // empty string is a host that reports no name, which is the same
    // absence as a peer too old to send the key.
    const hostName = typeof nsBody?.host_name === 'string' && nsBody.host_name !== '' ? nsBody.host_name : null;

    return {
      reachable: true, sampleAgeMs, firingCount, firing, serverState, buildVersion,
      amendmentBlocked, deployRef, release, hostName, refusedStatus: null, refusedRoute: null,
    };
  } catch {
    return UNREACHABLE_POLL;
  }
}

interface IdentityBody { pubkey_node?: string | null }

export interface IdentityPinResult {
  /** True only when the peer's /read/v1/identity answered with a 200 and a
   *  usable body. False for a network error, a timeout, a non-200 — which
   *  includes an older, un-upgraded peer's 404 unknown_read_path, since this
   *  route did not exist on every dashboard before this slice. A staged
   *  fleet rollout must not red-flag every peer that simply hasn't been
   *  upgraded yet as an integrity failure; "couldn't check" and "checked and
   *  it's wrong" are different facts and only the second is a mismatch. */
  checked: boolean;
  /** Meaningful only when checked is true. */
  matched: boolean;
  /** The two keys the comparison was made from, so the surfaces that report
   *  a mismatch can NAME it rather than assert one in the abstract (#273:
   *  "expected n9MVyn…, it reports n94fDo…"). Both null on every path where
   *  `checked` is false — an unpinned row, a 404 from an older peer, a
   *  timeout, a body with no key in it. A key nobody read is not a key. */
  expected: string | null;
  reported: string | null;
}

/** Reads a pinned peer's own identity and compares it against the row's
 *  expected_pubkey_node. Called from the SAME poll cycle as pollOnePeer —
 *  no second timer — and only when the base poll already found the peer
 *  reachable (nothing to confirm about an identity nobody answered). */
export async function checkIdentityPin(
  node: FleetNodeConfig,
  token: string,
  opts: { timeoutMs: number; fetchImpl?: FetchImpl },
): Promise<IdentityPinResult> {
  const expected = node.expected_pubkey_node;
  const unchecked = { checked: false, matched: false, expected: expected ?? null, reported: null };
  if (!expected) return { checked: false, matched: false, expected: null, reported: null };
  const doFetch = opts.fetchImpl ?? fetch;
  try {
    const res = await doFetch(
      `${node.read_origin}/read/v1/identity`,
      { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(opts.timeoutMs) },
    );
    if (!res.ok) return unchecked;
    const body = await res.json() as IdentityBody;
    if (typeof body.pubkey_node !== 'string' || !body.pubkey_node) return unchecked;
    return { checked: true, matched: body.pubkey_node === expected, expected, reported: body.pubkey_node };
  } catch {
    return unchecked;
  }
}

// Exported so fleet-fetch-through.ts (the demand-driven overview
// fetch-through, D8 slice 2) reuses this rather than re-implementing the
// "read the token fresh from disk on every fetch, never cache it" rule —
// the same reason that module is a sibling of this one, not a copy of it.
export function readTokenFresh(tokenPath: string): string | null {
  try {
    const t = readFileSync(tokenPath, 'utf8').trim();
    return t.length > 0 ? t : null;
  } catch { return null; }
}

/** True when a peer's read_origin is this process's own loopback bind — the
 *  case a copied-across-the-fleet fleet.yaml produces for the row that
 *  describes the node it's running on. */
export function isSelf(node: FleetNodeConfig, ownPort: number): boolean {
  let u: URL;
  try { u = new URL(node.read_origin); } catch { return false; }
  const host = u.hostname.toLowerCase();
  const isLoopbackHost = host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
  const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
  return isLoopbackHost && port === ownPort;
}

export interface ResolvedFleet {
  selfNode: FleetNodeConfig | null;
  peers: FleetNodeConfig[];
  /** Set when the registry had entries but none identified this node — the
   *  caller logs this once and falls back to single-node behaviour, the
   *  same fail-closed posture the parser itself uses for a bad file. An
   *  operator who copies fleet.yaml to a peer without updating which row is
   *  "this one" gets a named reason, not two dashboards silently polling
   *  each other as strangers. */
  error: string | null;
}

/** Splits a parsed registry into "this node" and "the rest", by matching
 *  read_origin's port against this process's own (see `isSelf`). An empty
 *  registry resolves to nothing, same as no file — not an error. */
export function resolveFleet(nodes: FleetNodeConfig[], ownPort: number): ResolvedFleet {
  if (nodes.length === 0) return { selfNode: null, peers: [], error: null };
  const selfNode = nodes.find((n) => isSelf(n, ownPort)) ?? null;
  if (!selfNode) {
    return {
      selfNode: null,
      peers: [],
      error: `fleet.yaml has ${nodes.length} entr${nodes.length === 1 ? 'y' : 'ies'} but none identifies ` +
        `this node (no read_origin matches this server's own port ${ownPort}) — treating as single-node until fixed`,
    };
  }
  return { selfNode, peers: nodes.filter((n) => n !== selfNode), error: null };
}

/** 5 minutes — well above every metric's own write cadence. Exported because
 *  the concern layer's staleness class is defined as "the poller called it
 *  stale", and it must read that boundary from here rather than keep a second
 *  copy of the number (concern-cards design §1: the concern layer ranks
 *  signals, it never defines a threshold). */
export const STALE_AFTER_MS = 5 * 60 * 1000;

/** Why a peer is not currently a usable source, structured so no consumer
 *  ever has to discriminate on `detail`'s prose.
 *
 *  `not_yet_polled` is the constructor's initial state — absence of evidence.
 *  It must never emit a concern and must never be counted as clear either;
 *  it is named in the response's `unchecked` array instead.
 *  `token_unreadable` is a fault on THIS box the operator can fix, so it does
 *  emit (a warn), and is named in `unchecked` too so the counts stay honest.
 *  `no_answer` is a real unreachable peer.
 *  `refused` is a peer that ANSWERED with 401/403: the box is up, the network
 *  path is fine, and it does not accept this dashboard's read token. It emits
 *  its own concern (never the no-answer one, which would be a lie) and is
 *  named in `unchecked` too — nothing about that node was read.
 *  `null` means the peer answered. */
export type PeerUnreachableReason = 'not_yet_polled' | 'token_unreadable' | 'no_answer' | 'refused' | null;

/** Everything the poller retains per peer between ticks. The four fields
 *  below the verdict exist so a LATER failed read cannot erase an EARLIER
 *  successful one: every branch of `tick()` that cannot refresh a value
 *  carries the previous one forward unchanged, and the read timestamp beside
 *  it is what makes the resulting card say "last confirmed 6m ago" instead of
 *  quietly presenting an old fact as a new one. */
interface PeerHealthState {
  verdict: FleetVerdict;
  detail: string;
  // The canaries behind the overall `verdict` (which is their rollup):
  // S (sync state), H (trust of the reading), A (Insights alerts). The FLEET
  // card renders one badge from each; the chip's dot stays the rollup.
  stateVerdict: VerdictResult;
  healthVerdict: VerdictResult;
  alertsVerdict: VerdictResult;
  // R's two INPUTS rather than its verdict, because R is the one canary that
  // needs a fleet-wide fact the poller does not have: the newest installable
  // release, which is the same number for every peer and belongs to the
  // process, not to a poll. It is threaded in at assembly instead
  // (peersPublic), so these two are what the tick retains.
  //
  // Neither is in `retained` above, deliberately. They follow serverState:
  // null means "not read this cycle", which every consumer already treats as
  // "not checked" rather than as a fault — so carrying a stale version
  // forward would buy nothing and would let a node keep claiming a build it
  // may no longer be running.
  buildVersion: string | null;
  amendmentBlocked: boolean | null;
  /** Follows buildVersion exactly, and for the same reason: not retained.
   *  Null means "not read this cycle", which every consumer treats as
   *  unknown — and carrying a stale ref forward would let a host keep
   *  claiming a deploy it may no longer be running, which is the one claim
   *  this feature exists to catch. */
  deployRef: string | null;
  /** Which published release this peer's install is, off the same body.
   *  Follows deployRef exactly: not retained, refused on a pin mismatch, and
   *  `{kind:'unknown'}` for every kind of nothing. A release nobody
   *  confirmed this cycle is not a release. */
  release: ReleaseIdentityWire;
  /** Follows deployRef: not retained, refused on a pin mismatch. A name
   *  nobody confirmed this cycle is not a name. */
  hostName: string | null;
  lastSeenMs: number | null;
  verified?: boolean;
  unreachableReason: PeerUnreachableReason;
  /** Follows buildVersion: not retained. A refusal is re-established by
   *  every poll that gets one, and a peer that answers 200 next cycle
   *  clears it with everything else. */
  refusedStatus: number | null;
  refusedRoute: string | null;
  sampleAgeMs: number | null;
  sampleReadAtMs: number | null;
  firing: ReadFiringStateRow[] | null;
  firingReadAtMs: number | null;
  /** True only when the identity route was READ and the key disagreed —
   *  never for "could not check" (see IdentityPinResult). */
  pinMismatch: boolean;
  /** The two keys that disagreed, retained with `pinMismatch` itself and
   *  only ever set together with it. They are what lets a surface NAME the
   *  mismatch ("expected n9MVyn…, it reports n94fDo…") instead of asserting
   *  one in the abstract, and keeping them beside the boolean is what stops
   *  a row from claiming a mismatch it cannot describe. */
  pinExpected: string | null;
  pinReported: string | null;
  /** When this dashboard last ATTEMPTED this peer, set by every branch of
   *  the tick including the ones that read nothing. This is the "observed"
   *  half of the two-age rule for a peer whose only fact is a negative one
   *  (it did not answer): without it the card would have to date a failed
   *  poll to "now" and claim a 20-second-old absence was confirmed this
   *  instant. Null only before the first tick. */
  lastPollAtMs: number | null;
  /** Source checks that returned a usable answer in the LAST COMPLETED
   *  cycle, never a running total and never derived from "has a timestamp"
   *  (which only means "succeeded at some point"). Reset every tick. */
  signalsChecked: number;
  /** Consecutive polls this peer has not answered. Zero after any answer.
   *  See MISSES_BEFORE_UNREACHABLE. */
  missStreak: number;
}

/**
 * How many polls in a row a peer that WAS answering may miss before it reads
 * as unreachable. One is a sample, not a state: on the lab aggregator (2026-09-06) a
 * single 4 s timeout on a 20 s cycle, through an ssh forward between two
 * cheap VPS boxes, flipped a healthy node to a critical "Not answering its
 * dashboard" card for the twenty seconds until the next poll answered, and
 * the operator saw that "relatively often". Two misses is forty seconds of
 * silence, which is a state worth a red card. The first miss keeps the last
 * verdict; last_seen_ms does not advance (it never does without an answer),
 * so the row's age keeps telling the truth meanwhile. A peer that has never
 * answered has nothing to keep and reads unreachable on its first miss.
 */
export const MISSES_BEFORE_UNREACHABLE = 2;

/**
 * Polls every non-self peer on an interval and keeps the last-known verdict
 * per label so a transient failure between ticks still has something to
 * show. `last_seen_ms` only advances on a SUCCESSFUL poll — this is what
 * lets the browser render "last known Xm ago" honestly.
 */
/**
 * #626 review, L2: what this aggregator's own tunnel read of a peer shows
 * right now, for the pairing hub to choose its sentence by when a known
 * node's move proof does not match.
 *
 *   answering  the last poll read the peer with the token this aggregator
 *              holds, and the pinned key (if any) agreed. Whoever holds a
 *              different token is not that node.
 *   refused    the peer answered the last poll with 401 or 403: it no
 *              longer takes the token this aggregator holds, which is what
 *              a reinstall looks like.
 *   unknown    never polled, unreachable, or a pin mismatch. Nothing to
 *              tell a reinstall from a different machine by.
 */
export type TunnelAuth =
  | { kind: 'answering' }
  | { kind: 'refused'; status: number }
  | { kind: 'unknown' };

export function tunnelAuthOf(
  s: { refusedStatus: number | null; unreachableReason: unknown; pinMismatch: boolean } | undefined,
): TunnelAuth {
  if (!s) return { kind: 'unknown' };
  if (s.refusedStatus && isRefusedStatus(s.refusedStatus)) return { kind: 'refused', status: s.refusedStatus };
  if (s.unreachableReason === null && !s.pinMismatch) return { kind: 'answering' };
  return { kind: 'unknown' };
}

export class FleetHealthPoller {
  private readonly peers: FleetNodeConfig[];
  private readonly ownPort: number;
  private readonly intervalMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl?: FetchImpl;
  private readonly state = new Map<string, PeerHealthState>();
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(peers: FleetNodeConfig[], opts: {
    ownPort: number;
    intervalMs?: number;
    timeoutMs?: number;
    fetchImpl?: FetchImpl;
    /** The poller this one replaces on a reload (#994). See `carryFrom`. */
    carryFrom?: FleetHealthPoller | null;
  }) {
    this.peers = peers.filter((p) => !isSelf(p, opts.ownPort));
    this.ownPort = opts.ownPort;
    this.intervalMs = opts.intervalMs ?? 20_000;
    this.timeoutMs = opts.timeoutMs ?? 4_000;
    this.fetchImpl = opts.fetchImpl;
    for (const p of this.peers) {
      this.state.set(p.label, {
        verdict: 'unreachable', detail: 'not yet polled', ...UNREACHABLE_TRIPLE, lastSeenMs: null,
        unreachableReason: 'not_yet_polled',
        sampleAgeMs: null, sampleReadAtMs: null,
        firing: null, firingReadAtMs: null,
        // Nothing has been read, so R has nothing to grade — and because
        // these are the poller's only un-retained fields, every branch that
        // reads nothing has to say so explicitly rather than inherit it.
        buildVersion: null, amendmentBlocked: null, deployRef: null, release: { kind: 'unknown' }, hostName: null,
        refusedStatus: null, refusedRoute: null,
        pinMismatch: false, pinExpected: null, pinReported: null,
        lastPollAtMs: null, signalsChecked: 0, missStreak: 0,
      });
      // A reload builds a new poller from scratch (a rename must never find
      // the old row's state, P2-032), and the state it is born with says
      // `not yet polled`, which the Settings overview reads as a node that is
      // down. An Attach reloads this dashboard, so for the first poll after it
      // every node read unreachable while its reads still answered (#994).
      // The last observation of a peer whose row did not change is what this
      // poller starts from instead, so it keeps its own last_seen_ms and
      // miss streak: a node that really went dark during the reload still
      // flips on the poll that misses it, and a stale reading still dates
      // itself as stale.
      const kept = opts.carryFrom?.stateIfSameRead(p);
      if (kept) this.state.set(p.label, kept);
    }
  }

  /** This poller's last observation of `node`, copied, but only when the row
   *  it was read through is the same one: the same label, read origin, token
   *  file, pinned key and transport. Anything else is a different peer wearing
   *  the old name, and gets no history (#994). Fields the poll never uses
   *  (the Advisor address an Attach adds, the role, the dashboard URL) do not
   *  count, because they are why the reload happened. */
  stateIfSameRead(node: FleetNodeConfig): PeerHealthState | null {
    const had = this.peers.find((p) => p.label === node.label);
    const s = this.state.get(node.label);
    if (!had || !s) return null;
    const same = had.read_origin === node.read_origin
      && had.token_path === node.token_path
      && (had.expected_pubkey_node ?? null) === (node.expected_pubkey_node ?? null)
      && (had.transport ?? 'loopback') === (node.transport ?? 'loopback');
    return same ? { ...s } : null;
  }

  start(): void {
    if (this.timer || this.peers.length === 0) return;
    void this.tick();
    this.timer = setInterval(() => { void this.tick(); }, this.intervalMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  private async tick(): Promise<void> {
    await Promise.all(this.peers.map(async (node) => {
      const prevToken = this.state.get(node.label);
      // Everything a failed branch must carry forward untouched. Written once
      // here so no branch below can forget one: a retained fact is only ever
      // replaced by a fact that was actually read, never by a blank.
      const retained = {
        lastSeenMs: prevToken?.lastSeenMs ?? null,
        sampleAgeMs: prevToken?.sampleAgeMs ?? null,
        sampleReadAtMs: prevToken?.sampleReadAtMs ?? null,
        firing: prevToken?.firing ?? null,
        firingReadAtMs: prevToken?.firingReadAtMs ?? null,
        pinMismatch: prevToken?.pinMismatch ?? false,
        // Retained WITH the boolean above, never apart from it: a row that
        // still says its pin failed must still be able to say which two keys
        // failed it.
        pinExpected: prevToken?.pinExpected ?? null,
        pinReported: prevToken?.pinReported ?? null,
      };
      const token = readTokenFresh(node.token_path);
      if (!token) {
        this.state.set(node.label, {
          verdict: 'unreachable', detail: 'token unreadable', ...UNREACHABLE_TRIPLE,
          ...retained,
          buildVersion: null, amendmentBlocked: null, deployRef: null, release: { kind: 'unknown' }, hostName: null,
          refusedStatus: null, refusedRoute: null,
          unreachableReason: 'token_unreadable',
          lastPollAtMs: Date.now(),
          signalsChecked: 0,
          missStreak: (prevToken?.missStreak ?? 0) + 1,
        });
        return;
      }
      const poll = await pollOnePeer(node, token, { timeoutMs: this.timeoutMs, fetchImpl: this.fetchImpl });
      const { verdict, detail } = deriveVerdict({ ...poll, staleAfterMs: STALE_AFTER_MS });
      const prev = this.state.get(node.label);
      const readAtMs = Date.now();
      // The peer answered and said no (#268). Checked BEFORE the unreachable
      // branch below, and deliberately outside the miss-streak hold: that
      // hold exists because one timeout is a sample rather than a state, and
      // a 401 is neither — it is a decision, and it will be the same decision
      // next cycle. Holding the previous OK verdict over it would leave a
      // locked-out node reading healthy for another twenty seconds.
      //
      // `missStreak` is reset, not incremented: the box answered. Nothing is
      // retried out of band either — the poller keeps its cadence, so a fleet
      // full of refusals costs exactly the reads a healthy one does.
      if (poll.refusedStatus) {
        this.state.set(node.label, {
          verdict, detail,
          ...refusedTriple(poll.refusedStatus, poll.refusedRoute),
          ...retained,
          buildVersion: null, amendmentBlocked: null, deployRef: null, release: { kind: 'unknown' }, hostName: null,
          // Dropped exactly as the unreachable branch drops it: a token this
          // node rejects cannot confirm an identity either.
          verified: undefined,
          unreachableReason: 'refused',
          refusedStatus: poll.refusedStatus,
          refusedRoute: poll.refusedRoute,
          lastPollAtMs: readAtMs,
          signalsChecked: 0,
          missStreak: 0,
        });
        return;
      }
      if (!poll.reachable) {
        const missStreak = (prev?.missStreak ?? 0) + 1;
        // A peer that answered last cycle keeps its verdict through the first
        // miss (MISSES_BEFORE_UNREACHABLE). The attempt is still recorded,
        // nothing is read (signalsChecked 0), and lastSeenMs stays where the
        // last answer left it.
        if (prev && prev.unreachableReason === null && missStreak < MISSES_BEFORE_UNREACHABLE) {
          this.state.set(node.label, { ...prev, lastPollAtMs: readAtMs, signalsChecked: 0, missStreak });
          return;
        }
        this.state.set(node.label, {
          verdict, detail, ...UNREACHABLE_TRIPLE,
          ...retained,
          buildVersion: null, amendmentBlocked: null, deployRef: null, release: { kind: 'unknown' }, hostName: null,
          refusedStatus: null, refusedRoute: null,
          // Deliberately NOT carried forward: an unreachable poll has always
          // dropped `verified` from the public row, and /api/fleet's shape is
          // not this feature's to change.
          verified: undefined,
          unreachableReason: 'no_answer',
          lastPollAtMs: readAtMs,
          signalsChecked: 0,
          missStreak,
        });
        return;
      }

      // Pin verification — same cycle, no second timer. Only attempted for a
      // row that both names an expected key AND answered the base poll;
      // nothing to confirm about an identity nobody answered.
      let finalVerdict: FleetVerdict = verdict;
      let finalDetail = detail;
      let verified: boolean | undefined;
      // True from here down — the unreachable case returned above — until a
      // pin mismatch takes it back, which is the one way a peer can answer
      // without that counting as reaching the REGISTERED node.
      let refreshLastSeen: boolean = true;
      let pinMismatch = false;
      let pinExpected: string | null = null;
      let pinReported: string | null = null;
      // The recent read answered (we are past the !reachable return); the
      // firing read answered only if it produced rows. Counted per cycle,
      // never inferred from "there is a timestamp on file".
      let signalsChecked = 1 + (poll.firing !== null ? 1 : 0);
      if (node.expected_pubkey_node && poll.reachable) {
        const pin = await checkIdentityPin(node, token, { timeoutMs: this.timeoutMs, fetchImpl: this.fetchImpl });
        if (pin.checked) signalsChecked++;
        if (pin.checked && !pin.matched) {
          // The wrong node answered. Its health signals (sampleAgeMs,
          // firingCount — already folded into `verdict`/`detail` above) are
          // REFUSED: the row carries only the integrity failure, never a
          // metric the wrong node reported. last_seen keeps meaning "last
          // successful poll of the REGISTERED node" — this wasn't one.
          finalVerdict = 'critical';
          finalDetail = PIN_MISMATCH_DETAIL;
          verified = false;
          refreshLastSeen = false;
          pinMismatch = true;
          // Both keys, from the comparison that just failed — the row is
          // about to refuse everything else this answer carried, and these
          // two are the only part of it that describes the failure rather
          // than the impostor.
          pinExpected = pin.expected;
          pinReported = pin.reported;
          // Only the pin check produced a usable answer. The recent and
          // firing reads DID answer, but as the wrong node, and this row
          // refuses their readings rather than counting them as checked.
          signalsChecked = 1;
        } else if (pin.checked && pin.matched) {
          verified = true;
        } else {
          // Identity route unreadable (network hiccup, or an older peer that
          // predates this route and 404s it) — pin unconfirmed this cycle,
          // but not treated as a mismatch. Normal verdict/detail stand.
          verified = false;
        }
      }

      // The three canaries. On a pin mismatch the impostor's state and alerts
      // are refused exactly as its metrics are — all three read the critical
      // integrity failure, not the wrong node's numbers.
      const stateV: VerdictResult = pinMismatch
        ? { verdict: 'critical', detail: PIN_MISMATCH_DETAIL }
        : deriveStateVerdict({ reachable: poll.reachable, serverState: poll.serverState });
      const healthV: VerdictResult = deriveHealthVerdict({
        reachable: poll.reachable, sampleAgeMs: poll.sampleAgeMs, staleAfterMs: STALE_AFTER_MS, pinMismatch,
      });
      const alertsV: VerdictResult = pinMismatch
        ? { verdict: 'critical', detail: PIN_MISMATCH_DETAIL }
        : deriveAlertsVerdict({ reachable: poll.reachable, firing: poll.firing });
      // R's contribution to the dot, and ONLY its red one — a node that is
      // amendment-blocked has fallen off the network and reddens the row; a
      // node that is merely a release behind does not amber it (see
      // releaseEscalation for why that asymmetry is deliberate). No
      // latestRelease is needed here: the red case is decided by
      // amendment_blocked alone, and the amber case is not an escalation.
      // On a pin mismatch the impostor's governance answer is refused with
      // everything else it said — the row is already critical for the
      // integrity failure, and that is the reason it should name.
      const releaseGate = pinMismatch
        ? { verdict: 'ok' as FleetVerdict, detail: '' }
        : releaseEscalation(deriveReleaseVerdict({
          reachable: true, amendmentBlocked: poll.amendmentBlocked,
        }));
      // The dot is the worst of the parts. finalVerdict already folded in the
      // COARSE (count-based) alert signal as warn; roll the rich, severity-aware
      // alerts verdict in so a CRITICAL alert reddens the dot, not just ambers
      // it — the dot can never be less severe than the A badge.
      const dot = rollupVerdict({ verdict: finalVerdict, detail: finalDetail }, alertsV, releaseGate);

      this.state.set(node.label, {
        verdict: dot.verdict,
        detail: dot.detail,
        stateVerdict: stateV,
        healthVerdict: healthV,
        alertsVerdict: alertsV,
        // R's inputs, refused on a pin mismatch exactly as the metrics above
        // are: the version and the amendment status that came back belong to
        // whichever node answered, and this label does not name that node.
        // Nulled rather than retained, so [R] reads "nothing to compare
        // against" instead of showing a build the registered node may never
        // have run.
        buildVersion: pinMismatch ? null : poll.buildVersion,
        amendmentBlocked: pinMismatch ? null : poll.amendmentBlocked,
        // Refused on a pin mismatch with everything else the impostor said:
        // the ref that came back describes whichever host answered, and this
        // label does not name that host.
        deployRef: pinMismatch ? null : poll.deployRef,
        release: pinMismatch ? { kind: 'unknown' as const } : poll.release,
        hostName: pinMismatch ? null : poll.hostName,
        lastSeenMs: refreshLastSeen ? Date.now() : (prev?.lastSeenMs ?? null),
        verified,
        // A peer that answered is not unreachable for ANY reason, including
        // the one it had last cycle — this is where a recovered peer clears.
        // A re-keyed node whose new token has been copied in reads its real
        // state on the very next poll, with no restart and no second tick.
        unreachableReason: null,
        refusedStatus: null,
        refusedRoute: null,
        missStreak: 0,
        // On a pin mismatch every reading below came from a node that is not
        // the one this label names, so the previous cycle's values stand and
        // their read timestamps do not advance. The card then says "last
        // confirmed Xm ago" about the REGISTERED node, which is true, rather
        // than presenting an impostor's numbers as fresh.
        sampleAgeMs: pinMismatch ? retained.sampleAgeMs : poll.sampleAgeMs,
        sampleReadAtMs: pinMismatch ? retained.sampleReadAtMs : readAtMs,
        // null means the firing read did not answer this cycle: keep the last
        // rows that WERE read, and keep their timestamp, so nothing reads as
        // "the alerts cleared" (concern-cards design 3.7 / 4.2).
        firing: (pinMismatch || poll.firing === null) ? retained.firing : poll.firing,
        firingReadAtMs: (pinMismatch || poll.firing === null) ? retained.firingReadAtMs : readAtMs,
        pinMismatch,
        pinExpected,
        pinReported,
        lastPollAtMs: readAtMs,
        signalsChecked,
      });
    }));
  }

  /** Non-self peers only, in registry order. `mergeSelf` adds the current
   *  node's own row (see server.ts) so the two never disagree about how a
   *  row not covered here is computed.
   *
   *  `latestRelease` is the newest installable release this process knows
   *  about — one fleet-wide number, the same for every peer, owned by
   *  server.ts's upstream release poll. It arrives HERE rather than in the
   *  poller on purpose: the poller's job is to read each peer, and a value
   *  that is identical for all of them and refreshed on a six-hour clock of
   *  its own has no business being copied into per-peer state. Null (no
   *  argument, or the release check is off / has not answered yet) means
   *  there is nothing to compare against, which [R] reads as green. */
  peersPublic(latestRelease: string | null = null): FleetPeerPublic[] {
    return this.peers.map((p) => {
      const s = this.state.get(p.label);
      // "Did this peer answer?" — the state holds the structured reason
      // rather than a boolean, and null is the value that means it did (see
      // PeerUnreachableReason). A missing state entry is a peer that has
      // never been polled, which is not an answer either.
      const reachable = !!s && s.unreachableReason === null;
      // On a pin mismatch R says what S and A say: the integrity failure,
      // never a reading taken from the node that answered.
      //
      // Gated on `reachable` and not on pinMismatch alone. pinMismatch is a
      // RETAINED field, so a peer that mismatched its pin and then went dark
      // still carries it — and S/H/A on that row read 'unreachable' (they
      // apply their own override inside the tick, after the unreachable
      // branch has already returned). Without this gate R would be the one
      // badge saying critical while the other three and the dot said
      // unreachable, which breaks both invariants at once: the badges agree
      // with each other, and none of them is ever more severe than the dot.
      const pinRefused = reachable && !!s && s.pinMismatch;
      const releaseV: VerdictResult = pinRefused
        ? { verdict: 'critical', detail: PIN_MISMATCH_DETAIL }
        : deriveReleaseVerdict({
          reachable,
          buildVersion: s?.buildVersion ?? null,
          latestRelease,
          amendmentBlocked: s?.amendmentBlocked ?? null,
        });
      return {
        label: p.label,
        ...(p.dashboard_url ? { dashboard_url: p.dashboard_url } : {}),
        self: false,
        verdict: s?.verdict ?? 'unreachable',
        detail: s?.detail ?? 'not yet polled',
        state_verdict: s?.stateVerdict.verdict ?? 'unreachable',
        state_detail: s?.stateVerdict.detail ?? '',
        health_verdict: s?.healthVerdict.verdict ?? 'unreachable',
        health_detail: s?.healthVerdict.detail ?? '',
        alerts_verdict: s?.alertsVerdict.verdict ?? 'unreachable',
        alerts_detail: s?.alertsVerdict.detail ?? '',
        release_verdict: releaseV.verdict,
        release_detail: releaseV.detail,
        // The tooltip's two halves, carried separately so the card never has
        // to parse them back out of the detail prose. Both are null on a row
        // that was not graded at all — an unreachable peer, or one whose
        // answer came from the wrong node — rather than a version nobody
        // confirmed sitting beside a release it was never compared to.
        build_version: pinRefused ? null : (reachable ? (s?.buildVersion ?? null) : null),
        latest_available: (reachable && !pinRefused) ? latestRelease : null,
        // Gated exactly like build_version above: a peer that did not answer,
        // or whose answer came from the wrong node, reports no ref rather
        // than one nobody confirmed. `deploy_state` is added later, at
        // assembly, once every row in the fleet is on the table.
        deploy_ref: (reachable && !pinRefused) ? (s?.deployRef ?? null) : null,
        // Gated the same way, and for the same reason: a peer that did not
        // answer, or whose answer came from the wrong node, reports unknown
        // rather than a release nobody confirmed. Omitted rather than sent as
        // `unknown`, which is what read-payloads does with the same fact:
        // absent and unknown are the same reading, and only one of them adds
        // a key to every row on a fleet where nothing carries a stamp yet.
        ...(releasePublic(reachable && !pinRefused ? s?.release : null)),
        host_name: (reachable && !pinRefused) ? (s?.hostName ?? null) : null,
        last_seen_ms: s?.lastSeenMs ?? null,
        // Present only on a refused row. `reachable` above is already false
        // for one, so every graded field (build_version, deploy_ref,
        // host_name, aperire_release) is null or absent without a second
        // gate: a node that will not let this dashboard read it publishes no
        // release, and unknown is the honest grade.
        ...(s?.refusedStatus ? { refused_status: s.refusedStatus } : {}),
        // Behind the SAME gate the refused fields above are behind, and the
        // same gate every graded field on this row is behind: `pinRefused`,
        // which is reachable AND mismatched. A row that mismatched and then
        // went dark reads unreachable everywhere else on this object, and
        // publishing the keys on it would leave one member describing an
        // identity failure while the other twelve describe silence.
        ...(pinRefused && s?.pinExpected && s?.pinReported
          ? { pin_expected: s.pinExpected, pin_reported: s.pinReported }
          : {}),
        ...(s?.verified !== undefined ? { verified: s.verified } : {}),
      };
    });
  }

  /**
   * The concern layer's view of the same peers — the retained signals above,
   * named one by one.
   *
   * Every field is written out explicitly and this is NEVER a spread of the
   * state object, for the same reason `toPublicPeer` is not: a spread carries
   * whatever the state gains next, and the state is one field away from
   * holding something (a read_origin, a token path) that must not cross into
   * a browser response. Adding a field here has to be a decision, not a
   * consequence.
   */
  /** #626 review, L2: see tunnelAuthOf. */
  tunnelAuth(label: string): TunnelAuth {
    return tunnelAuthOf(this.state.get(label));
  }

  peersConcernInput(): PeerConcernInput[] {
    return this.peers.map((p) => {
      const s = this.state.get(p.label);
      return {
        label: p.label,
        verdict: s?.verdict ?? 'unreachable',
        detail: s?.detail ?? 'not yet polled',
        // NOT `?? 'not_yet_polled'`: null is this field's most common VALUE
        // (the peer answered), not an absence, and nullish-coalescing it
        // turned every healthy peer into a never-checked one — which is the
        // exact failure this feature exists to prevent, arriving through the
        // back door. Absence is the missing state entry, and only that.
        unreachable_reason: s ? s.unreachableReason : 'not_yet_polled',
        last_seen_ms: s?.lastSeenMs ?? null,
        sample_age_ms: s?.sampleAgeMs ?? null,
        sample_read_at_ms: s?.sampleReadAtMs ?? null,
        firing: s?.firing ?? null,
        firing_read_at_ms: s?.firingReadAtMs ?? null,
        refused_status: s?.refusedStatus ?? null,
        pinned: Boolean(p.expected_pubkey_node),
        pin_mismatch: s?.pinMismatch ?? false,
        last_poll_at_ms: s?.lastPollAtMs ?? null,
        signals_checked: s?.signalsChecked ?? 0,
      };
    });
  }
}

/**
 * Aggregator mode: this dashboard hosts no local node of its own — its self
 * row is unreachable (there is no local rippled) while it federates real peer
 * nodes. The aggregator is the vantage point, not a monitored node.
 *
 * This is the server-side twin of `isAggregatorSelf` in `fleet-chip.js`, and
 * the condition is deliberately identical. The header chip already drops this
 * host from the roster, the count and the picker; anything else on the page
 * that treats it as a node instead will contradict the chip on the same
 * screen — a strip reading "this node is not answering" beside a chip that
 * says three nodes are healthy. Same rule, two renderers, one meaning.
 *
 * The peers requirement is what keeps a genuine single-node dashboard honest:
 * a lone node whose rippled has died is unreachable with no peers, and that
 * must stay visible rather than being mistaken for an aggregator.
 */
export function isAggregatorSelf(self: { verdict: FleetVerdict } | null, peerCount: number): boolean {
  return !!self && self.verdict === 'unreachable' && peerCount >= 1;
}

/** Builds the self row's public view from state the caller already has
 *  (node reachability, firing alerts) — never from a poll. `last_seen_ms` is
 *  always "now": the page IS the node, so its own freshness is definitionally
 *  current, not a value that can go stale between broadcasts.
 *
 *  `release` is optional because this row's release facts come from a place
 *  this pure function cannot see — this process's own server_info snapshot
 *  and its upstream release poll — so server.ts hands them in rather than
 *  this reaching for them. Omitted, the row's [R] is green with nothing to
 *  say, which is what it was before this canary existed. */
export function buildSelfPeer(
  node: FleetNodeConfig,
  verdict: FleetVerdict,
  detail: string,
  release?: { buildVersion: string | null; latestRelease: string | null; amendmentBlocked: boolean | null },
  deployRef?: string | null,
  hostName?: string | null,
  aperireRelease?: ReleaseIdentityWire,
  /** `selfPinFacts(node.expected_pubkey_node, <this node's own pubkey_node>)`,
   *  computed by the caller because the key lives in the caller's snapshot
   *  and this function reaches for nothing. Omitted leaves the row exactly as
   *  it was before #488: no pin members at all. */
  selfPin?: SelfPinFacts | null,
  /** The S/H/A canaries, computed by the caller through the exact same
   *  `deriveStateVerdict` / `deriveHealthVerdict` / `deriveAlertsVerdict` a
   *  peer row's badges go through (#505), never a second copy of "not fully
   *  synced" written for this row alone. Omitted, the three badges fall back
   *  to a copy of the rolled verdict passed in above: the aggregator's
   *  nodeless self row has no server_state to ask about, and that fallback is
   *  exactly what every caller before #505 already got. */
  canaries?: { state: VerdictResult; health: VerdictResult; alerts: VerdictResult },
): FleetPeerPublic {
  const reachable = verdict !== 'unreachable';
  const releaseV = deriveReleaseVerdict({
    reachable,
    buildVersion: release?.buildVersion ?? null,
    latestRelease: release?.latestRelease ?? null,
    amendmentBlocked: release?.amendmentBlocked ?? null,
  });
  const stateV = canaries?.state ?? { verdict, detail };
  const healthV = canaries?.health ?? { verdict, detail };
  const alertsV = canaries?.alerts ?? { verdict, detail };
  // The DOT is the rolled verdict passed in (already the rollup of state,
  // health and the coarse alert count, for a real node: see selfFleetPeer)
  // with R's red folded in, the same amendment-blocked escalation every peer
  // row gets, so this node is not the one place on the fleet where falling
  // off the network leaves a green dot. Only red escalates (releaseEscalation),
  // so an aggregator's unreachable self row still reads unreachable and
  // isAggregatorSelf keeps working.
  const dot = rollupVerdict({ verdict, detail }, releaseEscalation(releaseV));
  return {
    label: node.label, ...(node.dashboard_url ? { dashboard_url: node.dashboard_url } : {}), self: true,
    verdict: dot.verdict, detail: dot.detail,
    state_verdict: stateV.verdict, state_detail: stateV.detail,
    health_verdict: healthV.verdict, health_detail: healthV.detail,
    alerts_verdict: alertsV.verdict, alerts_detail: alertsV.detail,
    release_verdict: releaseV.verdict,
    release_detail: releaseV.detail,
    build_version: release?.buildVersion ?? null,
    latest_available: release?.latestRelease ?? null,
    last_seen_ms: Date.now(),
    // This host's own ref, read from its own disk rather than polled. Null
    // when it has no stamp, which is the ordinary single-node install.
    deploy_ref: deployRef ?? null,
    // Likewise this host's own name, from its own OS rather than a poll.
    host_name: hostName ?? null,
    // And this host's own release, read off its own disk. Omitted when there
    // is none, exactly as a peer's is.
    ...(releasePublic(aperireRelease)),
    // The registry's own row for this host, compared against what this node
    // says it is (#488). Absent on an unpinned row, so a single-node install
    // sends exactly what it sent before. The two keys ride along only on
    // 'changed', which is the one state that is a comparison rather than the
    // absence of one, and every consumer that reads them as "the wrong node
    // answered" excludes self rows.
    ...(selfPin ? { pin_state: selfPin.state } : {}),
    ...(selfPin && selfPin.state === 'changed' && selfPin.reported
      ? { pin_expected: selfPin.expected, pin_reported: selfPin.reported }
      : {}),
  };
}

/** A release identity as it appears on a public row: present when the host
 *  actually said something, absent otherwise. One helper so a peer's row and
 *  this host's own row cannot disagree about what "nothing" looks like. */
function releasePublic(r: ReleaseIdentityWire | null | undefined): { aperire_release?: ReleaseIdentityWire } {
  return r && r.kind !== 'unknown' ? { aperire_release: r } : {};
}

/**
 * Grades every row in a fleet against the others by deploy ref — issue #128
 * rung 2, the noticing half.
 *
 * Takes the assembled fleet (this host's own row plus every peer's) and
 * returns the same rows carrying `deploy_state`, alongside the comparison
 * the metric is written from. One call site, one derivation: the number the
 * alert fires on and the state each row renders cannot disagree, because
 * they are the same computation.
 *
 * The self row's ref is the tie-break preference, which changes no count —
 * on a fleet split evenly between two refs, `reference` is described from
 * the box the operator is reading.
 */
export function gradeFleetDeploy(nodes: FleetPeerPublic[]): {
  nodes: FleetPeerPublic[];
  comparison: DeployComparison;
} {
  const selfRef = nodes.find((n) => n.self)?.deploy_ref ?? null;
  const comparison = compareDeployRefs(
    nodes.map((n) => ({ label: n.label, ref: n.deploy_ref ?? null })),
    { preferRef: selfRef },
  );
  const stateByLabel = new Map(comparison.hosts.map((h) => [h.label, h.state]));
  return {
    nodes: nodes.map((n) => ({ ...n, deploy_state: stateByLabel.get(n.label) ?? 'unknown' })),
    comparison,
  };
}

/**
 * Grades every row in a fleet against ONE published release — ADR 0022
 * decision 6, the fleet half of the check.
 *
 * `latest` is a value, not a fetch. That is what makes "the aggregator asks
 * the endpoint once for a fleet of six" structural rather than a promise in a
 * comment: this function cannot make an outbound call, so nobody can add a
 * per-peer one to it later without changing its shape.
 *
 * Four states, and the last two are load-bearing in both directions. A host
 * whose stamp matches the published sum is `current`. A host with a stamp
 * that does not match is `behind` — equality, never an ordering, so a fleet
 * is never told which of two releases is newer, only which one the endpoint
 * publishes. Everything else is `unknown`: a peer that did not answer, a peer
 * older than the field, a peer deployed by the fleet tool rather than
 * installed from a release, and every host when the endpoint said nothing.
 * Unknown is never counted as up to date and never marked behind.
 *
 * `not_verified` is the fourth, and it is not a weaker unknown — it is a
 * different fact and a worse one (#273). The node answered, it named a key,
 * and the key is not the one this fleet pinned: nothing it said about itself
 * is worth grading, because this dashboard cannot establish that the thing
 * which answered is the node the row names. Folding it into unknown told an
 * operator their node had "no release stamp" when the node has one and the
 * aggregator declined to trust it — the same class of lie as #268's 401 read
 * as unreachable, and the same rule applies: a verdict is never folded into
 * a weaker one.
 *
 * Keyed on the two pinned keys the row carries, never on `verdict`: a node
 * with a firing critical alert is also 'critical' and its release grades
 * perfectly well.
 *
 * `selfLatest` is the release THIS host's own row is graded against, and it
 * defaults to the fleet's. It exists because the self row is the one row that
 * appears twice on the Updates card: once here, and once in the facts grid
 * above the table, which on a host with an updater is graded from root's
 * reading rather than from this process's (#293). Two readings of ONE
 * endpoint taken a day apart put two words on one host — "behind" in the
 * grid, "current" in the row (#365) — so the caller that has both hands the
 * grid's release in here and the row grades from the same reading. Still a
 * value, still no fetch: the whole fleet costs one outbound call either way,
 * and every other row is graded against `latest` because a peer is not
 * graded by this host's /etc/aperire/update.conf.
 */
export function gradeFleetRelease(
  nodes: FleetPeerPublic[],
  latest: UpdateLatest | null,
  selfLatest: UpdateLatest | null = latest,
  /** The high-water mark of THIS host's release store, when its account can
   *  read it (#1073). Part of the floor for the self row only: a peer's mark
   *  is that peer's own, and its stamp is the floor this dashboard can see. */
  selfHighWaterAt: string | null = null,
): {
  nodes: FleetPeerPublic[];
  /** The labels the fleet view marks. Empty when nothing is behind, and
   *  empty when nothing could be graded — those are different facts, and
   *  `graded` is what tells them apart. */
  behind: string[];
  current: number;
  unknown: number;
  /** The labels whose pinned identity failed. Named rather than counted, the
   *  same as `behind`: a caller that says "1 not verified" has to be able to
   *  say WHICH, and these rows are the ones an operator acts on. Never also
   *  counted in `unknown` — that is the fold this exists to undo. */
  not_verified: string[];
  /** The labels already on a release published after the one the endpoint
   *  serves (#1073). Named like `behind`, and never inside it or inside
   *  `current`: the endpoint is replaying an older signed release, which is
   *  neither news nor an update. */
  older: string[];
  /** False when the endpoint did not answer. Nothing was measured, so a
   *  caller writes no metric and the view marks nobody.
   *
   *  Read off `latest` alone, never off `selfLatest`: a table whose every
   *  peer reads "can't compare" beside one graded self row is a worse thing
   *  to render than no table, and the card hides on this. */
  graded: boolean;
} {
  const behind: string[] = [];
  const notVerified: string[] = [];
  const older: string[] = [];
  let current = 0, unknown = 0;
  const graded = nodes.map((n) => {
    // Ahead of the comparison, not after it: there is nothing to compare.
    // The row's release was already refused upstream (peersPublic nulls
    // everything a mismatched answer carried), so gradeAgainstLatest would
    // return 'unknown' here — which is exactly the wrong word.
    //
    // Never on the SELF row (#488), which carries the same two keys for a
    // different fact: this dashboard read its own node directly, so its
    // release IS known and IS gradeable, and the stale thing is the registry
    // file. Grading it 'not_verified' would put "1 not verified" on the
    // Updates card about the host the operator is reading it on.
    if (!n.self && n.pin_expected && n.pin_reported) {
      notVerified.push(n.label);
      return { ...n, aperire_release_state: 'not_verified' as const };
    }
    // This host's own row against the reading its caller graded the card
    // from, every other row against the one the fleet was fetched with. The
    // two are the same value unless a caller said otherwise (#365).
    //
    // The floor is the row's own (#1073): a release published no later than
    // the one THAT host runs is a replay, whichever host the endpoint was
    // read from. A peer's floor is its stamp's date, which crossed the wire
    // with its identity; this host's also holds its high-water mark.
    const id = n.aperire_release ?? null;
    const state = gradeWithFloor(id, n.self ? selfLatest : latest,
      releaseFloor(id, n.self ? selfHighWaterAt : null));
    if (state === 'behind') behind.push(n.label);
    else if (state === 'current') current++;
    else if (state === 'older') older.push(n.label);
    else unknown++;
    return { ...n, aperire_release_state: state };
  });
  return {
    nodes: graded, behind, current, unknown, not_verified: notVerified, older,
    graded: latest !== null,
  };
}

/** Sort order the mock fixes: critical, refused, warning, unreachable, healthy.
 *  'critical' is the pin-mismatch integrity failure (fleet-health.ts,
 *  pubkey pinning) — the slot this ranking always reserved ahead of warn
 *  is now occupied, not merely reserved. Ties keep registry order (a stable
 *  sort), never alphabetical — re-ordering a fleet by name would separate a
 *  node from the neighbours its operator listed it beside. */
// 'refused' sits second, above warn: a node that will not accept this
// dashboard's credential is showing nothing at all, and the fix is a file
// copy the operator can do in a minute.
const VERDICT_RANK: Record<FleetVerdict, number> = { critical: 1, refused: 2, warn: 3, unreachable: 4, ok: 5 };
export function sortFleetForDisplay(peers: FleetPeerPublic[]): FleetPeerPublic[] {
  return peers
    .map((p, i) => ({ p, i }))
    .sort((a, b) => (VERDICT_RANK[a.p.verdict] - VERDICT_RANK[b.p.verdict]) || (a.i - b.i))
    .map((x) => x.p);
}
