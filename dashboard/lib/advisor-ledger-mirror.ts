/**
 * The aggregator's poller and re-verify for the fleet Advisor ledger
 * mirror, ADR 0021 build step 3.
 *
 * This module decides three things db.ts is never asked to decide on its
 * own: how far to ask a node for (since_seq), whether an answer is a clean
 * append or a chain that no longer agrees with what is held, and, when it
 * disagrees, whether that is a reinstalled node starting a new run or a
 * genuine rewrite. db.ts only ever stores what this module hands it.
 *
 * Two providers feed one poller. This host's own advisord answers over the
 * loopback ADVISOR_URL, exactly as witnessAdvisorLedger already reads it in
 * server.ts; every peer answers through fetchPeerAdvisor's exact-path
 * allow-list, which already lists `ledger` and already carries the pin and
 * the token. Both are folded into one `fetchLedger` closure per node before
 * they reach this file, so nothing here knows or cares which is which.
 */
import {
  mirrorState, mirrorRecordAttempt, mirrorAppendEntries, mirrorRowAt,
  mirrorMarkBreak, mirrorClearBreak, mirrorRunsForNode, witnessHeadAt,
  type LedgerEntryIn,
} from '../db.js';

/** One ledger entry as a node's /v1/ledger answers it, advisor/internal/
 *  ledger's Entry, unreshaped. */
export type MirrorLedgerEntry = LedgerEntryIn;

export type LedgerFetchResult =
  | { ok: true; chainIntact: boolean; count: number; head: string; entries: MirrorLedgerEntry[] }
  | {
    ok: false;
    detail: string;
    /** Set when the failure means "there is no Advisor to ask" (a
     *  dashboard-alone install's own advisord, an unsealed advisord that
     *  refuses every token) rather than "an Advisor exists and could not be
     *  reached". The distinction matters: recording the first as a failed
     *  attempt, forever, on a poll cadence, is this project's named
     *  kept-versus-observed mistake pointed at a fact that was never kept in
     *  the first place. pollMirrorNode skips recording anything at all when
     *  this is set, so a node with no Advisor leaves no state row rather
     *  than an ever-growing pile of identical failures. */
    absent?: boolean;
  };

/** Asks one node for its ledger. `sinceSeq` null means the whole file: the
 *  first read of a node this mirror has never held a position for, and the
 *  disambiguating re-read this module reaches for on its own when a tail
 *  answer does not chain onto what is held. */
export type FetchLedger = (sinceSeq: number | null) => Promise<LedgerFetchResult>;

export interface MirrorTarget {
  node: string;
  fetchLedger: FetchLedger;
}

export interface ChainBreak {
  seq: number;
  expected: string;
  got: string;
}

/** Records a fetch failure as an attempt, unless the target says there was
 *  never anything there to attempt (see LedgerFetchResult.absent). */
function recordFetchFailure(node: string, res: { detail: string; absent?: boolean }): void {
  if (res.absent) return;
  mirrorRecordAttempt(node, false, res.detail);
}

/**
 * Compares entries against an INDEPENDENT source before they are trusted
 * onto the mirror: the dashboard's own hourly witness of that node's ledger
 * (ledger_witness, read via witnessHeadAt), where one exists.
 *
 * This is the half a chain-linkage check alone cannot provide. Two entries
 * can chain onto each other perfectly, prev_hash to hash all the way down,
 * and still both belong to a chain that was rewritten from entry 1 before
 * this mirror ever synced it: nothing in the mirror's own held rows would
 * catch that, because the mirror never held the original. The witness can,
 * for exactly the counts it happened to observe.
 */
function checkWitness(node: string, entries: MirrorLedgerEntry[]): ChainBreak | null {
  for (const e of entries) {
    const witnessed = witnessHeadAt(node, e.seq);
    if (witnessed !== null && witnessed !== e.hash) {
      return { seq: e.seq, expected: witnessed, got: e.hash };
    }
  }
  return null;
}

/**
 * The one path that commits entries to the mirror. Every caller in this
 * file that is about to append routes through here, so the witness check
 * runs exactly once, in exactly one place, rather than once per call site
 * with the usual risk that a new call site forgets it.
 */
function appendVerified(node: string, run: string, entries: MirrorLedgerEntry[]): void {
  if (entries.length === 0) { mirrorRecordAttempt(node, true, null); return; }
  const brk = checkWitness(node, entries);
  if (brk) { mirrorMarkBreak(node, brk.seq, brk.expected, brk.got); return; }
  mirrorAppendEntries(node, run, entries);
}

/**
 * The front-of-chain comparison a suspected reinstall or rewrite needs: for
 * every entry this full read carries, is there already a mirrored row at
 * that exact (node, run, seq), and if so does it agree? The first
 * disagreement is the break; later ones are downstream of it and not
 * separately interesting.
 */
function findBreak(node: string, run: string, entries: MirrorLedgerEntry[]): ChainBreak | null {
  for (const e of entries) {
    const held = mirrorRowAt(node, run, e.seq);
    if (held && held.hash !== e.hash) {
      return { seq: e.seq, expected: held.hash, got: e.hash };
    }
  }
  return null;
}

/**
 * A full read came back with a genesis (`entries[0].hash`) this mirror has
 * not seen before on this node: a reinstalled Advisor, or the very first
 * sync. Opens the new run wholesale. The old run's rows, if any, are left
 * exactly where they are, which is the "two runs, never merged" outcome.
 */
function openNewRun(node: string, entries: MirrorLedgerEntry[]): void {
  if (entries.length === 0) { mirrorRecordAttempt(node, true, null); return; }
  appendVerified(node, entries[0].hash, entries);
}

/**
 * The tail did not chain cleanly onto what is held (a count that went
 * backwards, or a first tail entry whose prev_hash disagrees with the last
 * hash this mirror trusts). One full read is the disambiguator, the same
 * escape hatch the ledger route itself falls back to on a stale cached
 * point: if the full read's genesis still matches the run this mirror
 * holds, it is a rewrite somewhere inside that run and findBreak locates
 * it; a different genesis is a reinstall, and the new run opens clean.
 */
async function resyncFromScratch(target: MirrorTarget, prior: { run: string | null; last_seq: number }): Promise<void> {
  const full = await target.fetchLedger(null);
  if (!full.ok) { recordFetchFailure(target.node, full); return; }
  if (!full.chainIntact) {
    mirrorRecordAttempt(target.node, false, 'the node reports its own chain is broken');
    return;
  }
  if (full.entries.length === 0) {
    // The ledger is empty, wiped or never written. Nothing to open as a
    // run yet; the next poll tries again.
    mirrorRecordAttempt(target.node, true, null);
    return;
  }
  const newGenesis = full.entries[0].hash;
  if (prior.run !== null && newGenesis === prior.run) {
    // Same chain. Whatever looked like a break from the tail alone is
    // either a genuine rewrite inside it, found by comparing the whole
    // thing against what is held and against the witness, or nothing at
    // all (an out-of-order network hiccup that answered a stale count
    // once).
    const wBrk = checkWitness(target.node, full.entries);
    if (wBrk) { mirrorMarkBreak(target.node, wBrk.seq, wBrk.expected, wBrk.got); return; }
    const brk = findBreak(target.node, prior.run, full.entries);
    if (brk) { mirrorMarkBreak(target.node, brk.seq, brk.expected, brk.got); return; }
    const fresh = full.entries.filter(e => e.seq > prior.last_seq);
    appendVerified(target.node, prior.run, fresh);
    return;
  }
  // A different genesis: this node's Advisor was reinstalled. The prior
  // run's rows are untouched; this is a second run starting at its own
  // seq 1.
  openNewRun(target.node, full.entries);
}

/**
 * One poll of one node. Skips entirely when the mirror has stopped on this
 * node (a break awaiting an operator's re-verify); that stop is the whole
 * point of recording it durably.
 */
export async function pollMirrorNode(target: MirrorTarget): Promise<void> {
  const state = mirrorState(target.node);
  if (state?.broken) return;

  const hasRun = !!(state && state.run);
  const since = hasRun ? state!.last_seq : null;
  const res = await target.fetchLedger(since);
  if (!res.ok) { recordFetchFailure(target.node, res); return; }
  if (!res.chainIntact) {
    mirrorRecordAttempt(target.node, false, 'the node reports its own chain is broken');
    return;
  }

  // Count went backwards from what this mirror already holds: a clean
  // reinstall (or wipe) signal, the same one the tab's own mergeLedgerTail
  // reads client-side.
  if (hasRun && res.count < state!.last_seq) {
    await resyncFromScratch(target, state!);
    return;
  }

  if (res.entries.length === 0) {
    // An empty tail is only honest when the node agrees there is nothing
    // after `since`. A node that says it holds MORE than this mirror does,
    // and then hands over none of it, is not reporting "nothing new": it is
    // contradicting itself, and the mirror must not read that as a healthy
    // poll (#405, where a daemon answered every tail read with an empty
    // list once its head cache was seeded, and three nodes' mirrors sat
    // still for as long as it lasted with last_error empty and broken 0).
    //
    // Recorded as a failed attempt rather than repaired here on purpose. A
    // full read would paper over it every twenty seconds, at the whole-file
    // cost this route exists to avoid, and hide the very condition an
    // operator needs to see. The card reads behind, which it is, and the
    // reason says why.
    if (hasRun && res.count > state!.last_seq) {
      mirrorRecordAttempt(
        target.node, false,
        `the node reports ${res.count} entries but answered none after ${state!.last_seq}`,
      );
      return;
    }
    // The node answered and confirmed the position; nothing new.
    mirrorRecordAttempt(target.node, true, null);
    return;
  }

  if (!hasRun) {
    // First sight of this node. `since` was null, so this answer is the
    // whole file and entries[0] is genuinely seq 1.
    openNewRun(target.node, res.entries);
    return;
  }

  const first = res.entries[0];
  if (first.prev_hash !== state!.last_hash) {
    // The tail does not chain onto what is held, and count did not go
    // backwards, so this is not the easy reinstall case above. One full
    // read tells the rest.
    await resyncFromScratch(target, state!);
    return;
  }
  appendVerified(target.node, state!.run!, res.entries);
}

/**
 * Polls every target once, each isolated from the others' failures.
 * FleetHealthPoller's own shape: `Promise.all` over a per-node try/catch, so
 * one node's timeout never delays or drops another's tick.
 */
export async function pollMirrorTargets(targets: MirrorTarget[]): Promise<void> {
  await Promise.all(targets.map(async (t) => {
    try {
      await pollMirrorNode(t);
    } catch (err) {
      mirrorRecordAttempt(t.node, false, (err as Error).message);
    }
  }));
}

/**
 * Runs targets on an interval, guarded against overlapping itself: a first
 * full read, or a re-verify's full read running at the same moment, can
 * take longer than peer-advisor-proxy's own 10s default timeout, and a
 * fleet's worth of those stacking on a 20s cadence is worse than one poll
 * arriving a little late.
 */
export class AdvisorLedgerMirror {
  private readonly targets: MirrorTarget[];
  private readonly intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private inFlight = false;

  constructor(targets: MirrorTarget[], opts: { intervalMs?: number } = {}) {
    this.targets = targets;
    this.intervalMs = opts.intervalMs ?? 20_000;
  }

  start(): void {
    if (this.timer || this.targets.length === 0) return;
    void this.tick();
    this.timer = setInterval(() => { void this.tick(); }, this.intervalMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  private async tick(): Promise<void> {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      await pollMirrorTargets(this.targets);
    } finally {
      this.inFlight = false;
    }
  }
}

export interface ReverifyMismatch {
  seq: number;
  mirror_hash: string;
  node_hash: string;
}

export interface ReverifyResult {
  node: string;
  ok: boolean;
  /** What made this not ok, when it was not: a fetch that failed, or the
   *  node reporting its own chain broken. Absent when ok. */
  error?: string;
  runs_compared: string[];
  mismatches: ReverifyMismatch[];
  /** True when this call lifted a prior break. False both when there was
   *  nothing to lift and when mismatches were found and the stop stands. */
  cleared: boolean;
}

/**
 * Re-reads a node's WHOLE ledger and compares it against every row this
 * mirror already holds for its current run. Reports every disagreement
 * rather than assuming the first one explains the rest: an operator staring
 * at a broken mirror wants the full extent of it, not one example.
 *
 * Clears a break only when the comparison finds nothing wrong: the full
 * read agrees, entry for entry, with every position the mirror already
 * holds for that run. That is deliberately the ONLY way a break clears;
 * this function never rewrites a disagreeing row to match the node, because
 * a mirror that fixes itself by copying whatever the node says now is not a
 * check on the node, it is an assumption that the node is currently
 * correct.
 */
export async function reverifyMirrorNode(node: string, fetchLedger: FetchLedger): Promise<ReverifyResult> {
  const full = await fetchLedger(null);
  if (!full.ok) {
    return { node, ok: false, error: full.detail, runs_compared: [], mismatches: [], cleared: false };
  }
  if (!full.chainIntact) {
    return {
      node, ok: false, error: 'the node reports its own chain is broken',
      runs_compared: [], mismatches: [], cleared: false,
    };
  }

  const runs = mirrorRunsForNode(node);
  const currentRun = full.entries.length > 0 ? full.entries[0].hash : null;
  // Compare the current run against the full read directly. Any OTHER run
  // this mirror holds belongs to a chain the node no longer carries (an
  // earlier reinstall), and there is nothing on the node left to compare it
  // against: it stands as history, unverifiable further, exactly as ADR
  // 0021 says a removed Advisor's mirrored past should read.
  const mismatches: ReverifyMismatch[] = [];
  if (currentRun !== null) {
    for (const e of full.entries) {
      const held = mirrorRowAt(node, currentRun, e.seq);
      if (held && held.hash !== e.hash) {
        mismatches.push({ seq: e.seq, mirror_hash: held.hash, node_hash: e.hash });
      }
    }
  }

  if (mismatches.length > 0) {
    // Leave the row exactly as mirrorMarkBreak already found it, or place
    // the stop now if this is how the disagreement was first noticed.
    const first = mismatches[0];
    mirrorMarkBreak(node, first.seq, first.mirror_hash, first.node_hash);
    return { node, ok: true, runs_compared: runs, mismatches, cleared: false };
  }

  // Clean. Bring the mirror fully current for this run (a break can leave
  // it short of the node's actual head) and lift the stop.
  if (currentRun !== null) {
    const state = mirrorState(node);
    const from = state && state.run === currentRun ? state.last_seq : 0;
    const fresh = full.entries.filter(e => e.seq > from);
    if (fresh.length) mirrorAppendEntries(node, currentRun, fresh);
    else mirrorRecordAttempt(node, true, null);
  } else {
    mirrorRecordAttempt(node, true, null);
  }
  mirrorClearBreak(node);
  return { node, ok: true, runs_compared: runs, mismatches: [], cleared: true };
}
