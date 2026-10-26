/**
 * What the node store did over the last interval, from get_counts.
 *
 * rippled reports `node_reads_total`, `node_reads_hit`, `node_writes`,
 * `node_read_bytes` and `node_written_bytes` cumulatively since the process
 * started. So does the hit rate it derives for its own caches:
 * `TaggedCache::getHitRate` is hits over hits+misses since start, which
 * flattens within hours of a start and barely moves when the cache begins
 * missing today. A validator that has been up for weeks reports a hit rate
 * that is a fact about last month.
 *
 * The difference between two samples is what an operator can act on, and it
 * is the series the System tab charts. The cumulative pair stays on the
 * Internals card, labelled as since-start, because it is a different
 * question and both are worth having.
 *
 * Two of the five counters are 32-bit in rippled (`Database.h`:
 * `std::atomic<std::uint32_t> fetchHitCount_` and `fetchSz_`, reported as
 * `node_reads_hit` and `node_read_bytes`; the other three are 64-bit).
 * `node_read_bytes` wraps at 4 GiB, which a node fetching 7 MB/s from its
 * store does every ten minutes, so a pair of samples routinely sees it go
 * backwards on a process that never restarted. Those two take a modular
 * delta; only the 64-bit three are the restart tell (#215).
 *
 * Pure: two samples in, an answer out. The caller owns the polling, the
 * previous sample, and the metric writes.
 */

/** The width of rippled's `fetchHitCount_` and `fetchSz_`. */
const U32 = 2 ** 32;

/**
 * The advance of a 32-bit counter between two samples. One wrap is
 * recovered exactly; a true delta of 2^32 or more within one interval
 * aliases, so the poll interval sets the ceiling this reads correctly to:
 * 2^32 / interval bytes per second.
 */
function u32Delta(prev: number, cur: number): number {
  return cur >= prev ? cur - prev : cur + U32 - prev;
}

export interface NodeStoreSample {
  /** Unix milliseconds the counters were read at. */
  ts: number;
  reads: number;
  hits: number;
  writes: number;
  readBytes: number;
  writtenBytes: number;
}

export interface NodeStoreRates {
  /** Hits over reads IN THE INTERVAL, or null when the store was not read at
   *  all. A quiet interval is not a 0% hit rate. */
  read_hit_pct: number | null;
  reads_per_s: number;
  writes_per_s: number;
  read_bps: number;
  written_bps: number;
}

/** Below this the deltas are small enough that the poller's own jitter shows
 *  up as a rate. get_counts polls every minute, so in practice this is a
 *  floor nothing waits on. */
export const NODESTORE_MIN_INTERVAL_S = 30;

/**
 * The counters out of a raw `get_counts` result, or null when any of them is
 * missing or unparseable.
 *
 * `Number()` on every field rather than a typeof check: current builds
 * serialise the 64-bit counters as decimal STRINGS ("2157246990"), and a
 * `typeof v === 'number'` guard would have read every one of them as absent.
 */
export function nodeStoreSample(result: Record<string, unknown>, ts: number): NodeStoreSample | null {
  const n = (v: unknown): number | null => {
    if (v === null || v === undefined || typeof v === 'object' || typeof v === 'boolean') return null;
    const x = Number(v);
    return Number.isFinite(x) ? x : null;
  };
  const reads = n(result.node_reads_total);
  const hits = n(result.node_reads_hit);
  const writes = n(result.node_writes);
  const readBytes = n(result.node_read_bytes);
  const writtenBytes = n(result.node_written_bytes);
  if (reads === null || hits === null || writes === null || readBytes === null || writtenBytes === null) {
    return null;
  }
  return { ts, reads, hits, writes, readBytes, writtenBytes };
}

/**
 * Null when the pair cannot be used: too close together to measure, or
 * spanning a rippled restart.
 *
 * A 64-bit counter that went backwards is the restart tell. The pair then
 * spans two processes and its difference is not a rate of anything, so it is
 * dropped rather than clamped to zero — a clamped restart would render as a
 * store that suddenly went idle. The two 32-bit counters go backwards on a
 * healthy process whenever they wrap, so they are never the tell; a restart
 * resets all five, and the 64-bit three catch it.
 */
export function nodeStoreRatesBetween(prev: NodeStoreSample, cur: NodeStoreSample): NodeStoreRates | null {
  const dt = (cur.ts - prev.ts) / 1000;
  if (!(dt >= NODESTORE_MIN_INTERVAL_S)) return null;
  if (cur.reads < prev.reads || cur.writes < prev.writes || cur.writtenBytes < prev.writtenBytes) {
    return null;
  }
  const dReads = cur.reads - prev.reads;
  const dHits = u32Delta(prev.hits, cur.hits);
  return {
    read_hit_pct: dReads > 0 ? (dHits / dReads) * 100 : null,
    reads_per_s: dReads / dt,
    writes_per_s: (cur.writes - prev.writes) / dt,
    read_bps: u32Delta(prev.readBytes, cur.readBytes) / dt,
    written_bps: (cur.writtenBytes - prev.writtenBytes) / dt,
  };
}
