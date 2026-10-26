/**
 * The read API's history answers, cached for half a bucket (#119), and
 * computed without holding the event loop (#831).
 *
 * `queryHistory` is a GROUP BY aggregation over the metrics table. At 30d
 * that is roughly 2.6M rows on this process's single thread: measured on a
 * busy node at up to ~600ms per call, 21 calls costing 2617ms inside one
 * 15-second window. Every consumer of the read API pays it, and there is more
 * than one. This node's own Advisor assembles four 30-day concern cards per
 * question (it now caches its own four, server-side), and an aggregator's
 * peer views pull chart series through the same route for every client
 * watching this node. This bounds everyone.
 *
 * The TTL is half the bucket the query itself will use, which is the only
 * honest number available here: a 30d range buckets at 4h, so its newest
 * bucket is filled over four hours and a two-hour reuse cannot skip a point.
 * A 1h range buckets at 30s and gets 15 seconds, below every chart's own
 * refresh. The cache can never be staler than the resolution of the answer it
 * is holding, at any range, which is what makes one rule safe for all six.
 *
 * #831: a miss used to run the whole aggregation in one synchronous call.
 * better-sqlite3 has no async API, so for about a second nothing else on the
 * node ran, the fleet link agent included, and every request the aggregator
 * had in flight to this node waited behind it. A miss now runs as a series of
 * bucket-aligned slices, each its own small statement, with a yield to the
 * event loop between them. Each bucket falls wholly inside one slice, so the
 * answer is exactly the one-statement answer; only the longest single block
 * changes, from the whole range to one slice. Concurrent misses on one key
 * share one fill.
 *
 * Lives here rather than inside server.ts so it can be driven by a test with
 * a counting query. A cache asserted by reading it is a cache nobody measured.
 */

export interface HistoryCacheDeps<T> {
  /** The aggregation over `fromS <= ts < toS` (Unix seconds), bucketed at
   *  `bucketS`. Called only on a miss, once per slice. */
  queryRange: (metric: string, fromS: number, toS: number, bucketS: number, agg: string) => T[];
  /** Bucket width in SECONDS for a range, the same function the query uses.
   *  Injected rather than imported so the two can never drift apart in a
   *  test that thinks it is measuring the real thing. */
  bucketForRange: (rangeMs: number) => number;
  /** Overridable for tests; defaults to Date.now. */
  now?: () => number;
  /** The longest span one slice may cover, in seconds. Rounded down to a
   *  whole number of buckets, never below one bucket. */
  sliceSpanS?: number;
  /** Lets the event loop run between slices. Defaults to setImmediate. */
  yieldToLoop?: () => Promise<void>;
}

export interface HistoryCache<T> {
  get(metric: string, range: string, rangeMs: number, agg: string): Promise<T[]>;
  /** Entries currently held. Exposed for the test that pins the key space. */
  size(): number;
}

/** Six hours of rows per slice. At one sample a second that is about 21,600
 *  rows on the index, a few milliseconds of work. */
export const DEFAULT_SLICE_SPAN_S = 6 * 3600;

/** The end of the last slice: everything from its start onward. */
const OPEN_END_S = Number.MAX_SAFE_INTEGER;

/**
 * The slices for one query, as [fromS, toS) pairs. Every edge but the first
 * is a multiple of `bucketS`, so a bucket is never split between two slices
 * and each slice's per-bucket aggregate is the whole bucket's. The first
 * slice starts at `fromS` exactly, as the one-statement query does, so the
 * oldest, partial bucket is cut at the same row.
 */
export function historySlices(fromS: number, nowS: number, bucketS: number, sliceSpanS: number): Array<[number, number]> {
  const span = Math.max(1, Math.floor(sliceSpanS / bucketS)) * bucketS;
  const out: Array<[number, number]> = [];
  let start = fromS;
  let edge = fromS - (fromS % bucketS) + span;
  // Closed slices up to now; the last one is open-ended, so a row written
  // while the fill is yielding still lands in exactly one slice.
  while (edge <= nowS) {
    out.push([start, edge]);
    start = edge;
    edge += span;
  }
  out.push([start, OPEN_END_S]);
  return out;
}

export function createHistoryCache<T>(deps: HistoryCacheDeps<T>): HistoryCache<T> {
  const now = deps.now ?? Date.now;
  const sliceSpanS = deps.sliceSpanS ?? DEFAULT_SLICE_SPAN_S;
  const yieldToLoop = deps.yieldToLoop ?? (() => new Promise<void>((done) => setImmediate(done)));
  const entries = new Map<string, { at: number; points: T[] }>();
  const filling = new Map<string, Promise<T[]>>();

  async function fill(metric: string, rangeMs: number, agg: string): Promise<T[]> {
    const bucketS = deps.bucketForRange(rangeMs);
    const t = now();
    const fromS = Math.floor((t - rangeMs) / 1000);
    const points: T[] = [];
    for (const [a, b] of historySlices(fromS, Math.floor(t / 1000), bucketS, sliceSpanS)) {
      points.push(...deps.queryRange(metric, a, b, bucketS, agg));
      await yieldToLoop();
    }
    return points;
  }

  return {
    async get(metric, range, rangeMs, agg) {
      // Keyed on the RANGE NAME as well as its ms width. They are 1:1 today,
      // and keying on both means a future range that shares a width with an
      // existing one cannot silently serve the other's answer.
      const key = `${metric}|${range}|${agg}`;
      const ttlMs = deps.bucketForRange(rangeMs) * 500;
      const hit = entries.get(key);
      if (hit && now() - hit.at < ttlMs) return hit.points;
      const running = filling.get(key);
      if (running) return running;
      // Stamped at the START of the fill: the newest bucket is read last and
      // is at least as fresh as this, so the TTL never overstates freshness.
      const at = now();
      const p = fill(metric, rangeMs, agg)
        .then((points) => { entries.set(key, { at, points }); return points; })
        .finally(() => { filling.delete(key); });
      filling.set(key, p);
      return p;
    },
    size() { return entries.size; },
  };
}
