/**
 * How fast the node store is growing, on a store that rotates.
 *
 * The estimate this replaces fitted the first and last `nudb_size` sample of
 * a 24-hour window. That works on a store that only ever grows. It does not
 * work on one running online_delete: the size walks a sawtooth, each
 * rotation drops it by a large step, and the last sample sits wherever the
 * tooth happens to be. Two readings taken either side of a rotation gave a
 * negative slope (rendered as a dash, so the row read "not measured" on a
 * perfectly healthy node), and two taken either side of the regrowth gave a
 * number with no meaning at all — prod read 82 days from one such pair.
 *
 * The only slope that means anything on a rotating store is peak to peak.
 * A rotation removes the ledgers below the retention floor; the floor moves
 * forward with the chain, so the top of each tooth is the store's real
 * high-water mark for that day. Fit those and the sawtooth cancels out,
 * PROVIDED the tooth is a calendar day wide, which is the assumption
 * `dailyPeaks` below makes and #79's gated rotation breaks.
 *
 * #101. A node with `advisory_delete=1` only rotates when the daily
 * can-delete window (#79) finds a rotation due, so its true cadence is
 * whatever its own threshold and that once-a-day window agree on together,
 * sometimes a bit over 24h, sometimes closer to 48h. A calendar-day peak
 * fit reads that as real growth for however long the deferred cycle runs
 * past midnight, warns, clears when the deferred rotation finally lands,
 * and repeats on the next cycle, a chronic re-fire on a store that is
 * pruning exactly as designed. The fix is not to detect gating; it is to
 * stop assuming the tooth is a day wide at all. Once the store has
 * completed two rotations, `cyclePeaks` fits ITS OWN peak-to-peak cadence,
 * whatever that is, and the calendar never enters the calculation. Below
 * two rotations, the store's first cycle, or one that never rotates,
 * there is no cycle to fit yet, and the daily-peak fit is what it has
 * instead, unchanged from before. A store that never rotates has zero
 * drops to find, forever, so it stays on the daily fit for good, which is
 * exactly the case #79's safety net (a rotation that stopped running) has
 * to keep catching.
 *
 * Everything here is pure: samples in, an answer out. The caller decides
 * where the samples come from and how often to ask.
 */

export interface NudbSample {
  /** Unix milliseconds. */
  ts: number;
  /** Store size in bytes. */
  value: number;
}

/** The most recent sample-to-sample drop large enough to be a rotation
 *  rather than noise, timed to the sample that first read lower. */
export interface NudbRotation {
  ts: number;
  drop_bytes: number;
}

export interface NudbGrowth {
  /**
   *  - `needs_history` — fewer than two daily peaks are on record. The store
   *    may well be growing; nothing here can say at what rate yet.
   *  - `not_growing`   — two or more peaks, and the fitted slope is flat or
   *    falling. This is the normal state of a pruned validator and is a
   *    measurement, not a failure to measure.
   *  - `ok`            — the peaks are rising, and `peak_growth_bytes_per_day`
   *    says how fast.
   */
  status: 'ok' | 'not_growing' | 'needs_history';
  /** Days until the mount fills at the peak growth rate. Null unless the
   *  status is `ok` AND the caller supplied free space to divide into. */
  days: number | null;
  /** The fitted slope, bytes per day. Fitted from the store's own rotation
   *  cycles once two have completed (#101), or from calendar-day peaks
   *  before that or on a store that never rotates. Null only when there
   *  were not two points to fit. Negative when the peaks are falling, a
   *  real reading, not an error. */
  peak_growth_bytes_per_day: number | null;
  /** The largest size seen in the last 7 days. Null when no sample falls in
   *  that window. */
  peak_7d_bytes: number | null;
  last_rotation: NudbRotation | null;
}

const DAY_MS = 86_400_000;

/** A drop of at least this fraction of the preceding reading is a rotation.
 *  Well above the noise floor of a directory walk (files appear and vanish
 *  between walks) and well below the step online_delete takes. */
export const ROTATION_DROP_FRACTION = 0.10;

/** Two peaks is the minimum a line can be fitted through; the page says so
 *  in exactly these words. */
export const MIN_DAILY_PEAKS = 2;

interface DailyPeak {
  /** Whole UTC days since the epoch. */
  day: number;
  peak: number;
}

/**
 * The largest reading in each UTC day.
 *
 * Today is a partial day: its peak is whatever has been seen so far, which
 * is by construction lower than it will be by midnight. Including it drags
 * the fit down and can turn a growing store into a flat one every morning.
 * So today is dropped — UNLESS it has already passed every earlier day's
 * peak, in which case it is a completed fact about the store's high-water
 * mark and dropping it would discard the newest thing known.
 */
export function dailyPeaks(points: readonly NudbSample[], now: number): DailyPeak[] {
  const byDay = new Map<number, number>();
  for (const p of points) {
    if (!p || !Number.isFinite(p.ts) || !Number.isFinite(p.value)) continue;
    const day = Math.floor(p.ts / DAY_MS);
    const cur = byDay.get(day);
    if (cur === undefined || p.value > cur) byDay.set(day, p.value);
  }
  const peaks = [...byDay.entries()]
    .map(([day, peak]) => ({ day, peak }))
    .sort((a, b) => a.day - b.day);
  if (peaks.length === 0) return peaks;

  const today = Math.floor(now / DAY_MS);
  const last = peaks[peaks.length - 1];
  if (last.day !== today) return peaks;
  const earlier = peaks.slice(0, -1);
  if (earlier.length === 0) return peaks;
  const highestEarlier = earlier.reduce((m, p) => (p.peak > m ? p.peak : m), earlier[0].peak);
  return last.peak > highestEarlier ? peaks : earlier;
}

/** Least-squares slope of peak against day, in bytes per day. Null when
 *  fewer than two distinct days are on record. */
function peakSlopeBytesPerDay(peaks: readonly DailyPeak[]): number | null {
  if (peaks.length < MIN_DAILY_PEAKS) return null;
  let sx = 0, sy = 0;
  for (const p of peaks) { sx += p.day; sy += p.peak; }
  const mx = sx / peaks.length, my = sy / peaks.length;
  let num = 0, den = 0;
  for (const p of peaks) {
    const dx = p.day - mx;
    num += dx * (p.peak - my);
    den += dx * dx;
  }
  if (!(den > 0)) return null;   // every sample landed in one day
  return num / den;
}

/**
 * The index of every sample that reads a drop of more than
 * ROTATION_DROP_FRACTION from the one before it, every rotation the series
 * shows, in order, oldest first.
 *
 * The resolution is the resolution of the series handed in. Over a 30-day
 * window the caller's samples are 4-hour buckets, so a rotation is timed to
 * the bucket it landed in, and one that both dropped and fully regrew
 * inside a single bucket is invisible. Both are stated on the row rather
 * than smoothed over.
 */
function rotationIndices(points: readonly NudbSample[]): number[] {
  const idxs: number[] = [];
  for (let i = 1; i < points.length; i++) {
    const prev = points[i - 1], cur = points[i];
    if (!prev || !cur || !Number.isFinite(prev.value) || !Number.isFinite(cur.value)) continue;
    const drop = prev.value - cur.value;
    if (prev.value > 0 && drop > prev.value * ROTATION_DROP_FRACTION) idxs.push(i);
  }
  return idxs;
}

/** The most recent rotation, for display. Everything that decides `status`
 *  scans the full list (`rotationIndices`, `cyclePeaks`) instead, this is
 *  the one entry point that only wants the last one. */
export function lastRotation(points: readonly NudbSample[]): NudbRotation | null {
  const idxs = rotationIndices(points);
  if (idxs.length === 0) return null;
  const i = idxs[idxs.length - 1];
  return { ts: points[i].ts, drop_bytes: points[i - 1].value - points[i].value };
}

/** Two completed rotations is the minimum a cycle-to-cycle line can be
 *  fitted through, the same reasoning `MIN_DAILY_PEAKS` states for
 *  calendar days. Below this the store is on its first cycle, or has none,
 *  and `dailyPeaks` is what it is fitted from instead. */
export const MIN_CYCLE_ROTATIONS = 2;

interface CyclePeak {
  ts: number;
  peak: number;
}

/**
 * The high-water mark of each rotation cycle the series completed, plus the
 * cycle in progress since the last one IF it has already grown past the
 * last completed cycle's peak, the same rule `dailyPeaks` applies to an
 * unfinished calendar day, applied here to an unfinished cycle instead.
 *
 * No calendar enters this at all. A cycle is whatever span the store's own
 * rotations mark out, so a free-running store rotating every 32 hours and
 * one gated to a daily window that only lets it through every 48-56 hours
 * both fit correctly, without either shape needing to be told apart first.
 */
function cyclePeaks(points: readonly NudbSample[], idxs: readonly number[]): CyclePeak[] {
  const peaks: CyclePeak[] = [];
  let segStart = 0;
  for (const idx of idxs) {
    let peak = -Infinity, peakTs: number | null = null;
    for (let i = segStart; i < idx; i++) {
      const p = points[i];
      if (p && Number.isFinite(p.value) && p.value > peak) { peak = p.value; peakTs = p.ts; }
    }
    if (peakTs !== null) peaks.push({ ts: peakTs, peak });
    segStart = idx;
  }
  let pendingPeak = -Infinity, pendingTs: number | null = null;
  for (let i = segStart; i < points.length; i++) {
    const p = points[i];
    if (p && Number.isFinite(p.value) && p.value > pendingPeak) { pendingPeak = p.value; pendingTs = p.ts; }
  }
  if (pendingTs !== null && (peaks.length === 0 || pendingPeak > peaks[peaks.length - 1].peak)) {
    peaks.push({ ts: pendingTs, peak: pendingPeak });
  }
  return peaks;
}

/** Least-squares slope of peak against time, in bytes per day. Null when
 *  fewer than two cycles are on record. */
function cycleSlopeBytesPerDay(peaks: readonly CyclePeak[]): number | null {
  if (peaks.length < MIN_CYCLE_ROTATIONS) return null;
  let sx = 0, sy = 0;
  for (const p of peaks) { sx += p.ts / DAY_MS; sy += p.peak; }
  const n = peaks.length;
  const mx = sx / n, my = sy / n;
  let num = 0, den = 0;
  for (const p of peaks) {
    const dx = (p.ts / DAY_MS) - mx;
    num += dx * (p.peak - my);
    den += dx * dx;
  }
  if (!(den > 0)) return null;   // every cycle landed at the same instant
  return num / den;
}

/**
 * @param points        `nudb_size` over the retained window, oldest first.
 * @param diskFreeBytes free space on the mount, or null when unknown.
 */
export function estimateNudbGrowth(
  points: readonly NudbSample[],
  diskFreeBytes: number | null,
  now: number = Date.now(),
): NudbGrowth {
  const peaks = dailyPeaks(points, now);

  let peak7d: number | null = null;
  const from7d = now - 7 * DAY_MS;
  for (const p of points) {
    if (!p || !Number.isFinite(p.value) || p.ts < from7d) continue;
    if (peak7d === null || p.value > peak7d) peak7d = p.value;
  }

  const rotation = lastRotation(points);

  // Two DAILY peaks is still the gate for "there is nothing to fit yet",
  // unchanged from before #101, and what the page's "needs 2 days" text
  // still means. What changes is which fit runs once past that gate.
  if (peaks.length < MIN_DAILY_PEAKS) {
    return {
      status: 'needs_history',
      days: null,
      peak_growth_bytes_per_day: null,
      peak_7d_bytes: peak7d,
      last_rotation: rotation,
    };
  }

  // #101. Two or more completed rotations and the fit is the store's own
  // cycles, whatever cadence those actually ran on; below that there is no
  // cycle yet, and the calendar-day fit is what there is instead.
  const idxs = rotationIndices(points);
  const slope = idxs.length >= MIN_CYCLE_ROTATIONS
    ? cycleSlopeBytesPerDay(cyclePeaks(points, idxs))
    : peakSlopeBytesPerDay(peaks);

  if (slope === null || slope <= 0) {
    return {
      status: 'not_growing',
      days: null,
      peak_growth_bytes_per_day: slope,
      peak_7d_bytes: peak7d,
      last_rotation: rotation,
    };
  }
  const days = (diskFreeBytes !== null && Number.isFinite(diskFreeBytes) && diskFreeBytes > 0)
    ? diskFreeBytes / slope
    : null;
  return {
    status: 'ok',
    days,
    peak_growth_bytes_per_day: slope,
    peak_7d_bytes: peak7d,
    last_rotation: rotation,
  };
}
