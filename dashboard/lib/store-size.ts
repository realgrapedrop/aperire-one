/**
 * Measuring the node's ledger store, and deciding what may be derived from
 * the measurement.
 *
 * The bug this exists to close (#427): the directory walk swallowed a failure
 * at every level, including at its own root, and returned 0. So on a host
 * where the dashboard account cannot open the store at all, the System tab
 * showed NUDB SIZE 0 B and MOUNT FREE DAYS "not growing" for a 6.7 GB store
 * that was filling, beside a 24-hour peak of 42.70 GB left over from the node
 * that used to live there. Three rows on one card, two of them inventions,
 * and the card said none of it was in doubt.
 *
 * A reading that could not be taken is not a reading of zero. The rule is the
 * project's own kept-versus-observed rule: the page never claims a state it
 * did not observe. Everything here follows from that.
 *
 * Deeper entries are still skipped. A single file that vanished between the
 * listing and the stat, a symlink pointing nowhere, a subdirectory the node
 * has locked for a moment: those make the total approximate, which is what a
 * directory size is. The ROOT is different in kind. If the store's own
 * directory cannot be opened, nothing was measured at all.
 */

import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { estimateNudbGrowth, type NudbGrowth, type NudbSample } from './nudb-growth.js';

/** One attempt at measuring the store.
 *
 *  Exactly one of the two is set. `bytes` is a size that was walked;
 *  `error` is the reason the walk could not be taken, in the words the
 *  operating system used (`EACCES: permission denied, scandir '...'`,
 *  `ENOENT: no such file or directory, scandir '...'`), so the page can name
 *  a permission problem and a missing path as the different things they are
 *  without this module inventing a vocabulary for them. */
export interface StoreReading {
  bytes: number | null;
  error: string | null;
}

/** Is this a reading, or the absence of one? The one place that decides, so
 *  the broadcast, the derivations and the page cannot come to disagree. */
export function storeMeasured(r: StoreReading): boolean {
  return r.error === null && r.bytes !== null;
}

/** The filesystem calls this walk makes, injectable so a test can drive a
 *  root that refuses without needing a root-owned directory to refuse from. */
export interface StoreFs {
  readdir: typeof readdir;
  stat: typeof stat;
}

const REAL_FS: StoreFs = { readdir, stat };

/**
 * Sum every regular file under `path`.
 *
 * Throws when the root cannot be listed, and only then. The caller turns that
 * into a reading that was not taken; it must never turn it into a zero.
 */
export async function dirSize(path: string, fs: StoreFs = REAL_FS): Promise<number> {
  let total = 0;
  async function walk(p: string, root: boolean): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(p, { withFileTypes: true });
    } catch (err) {
      // The whole difference. A directory deeper in is skipped, which makes
      // the total approximate. The root is the measurement itself.
      if (root) throw err;
      return;
    }
    for (const e of entries) {
      const full = join(p, e.name);
      if (e.isDirectory()) await walk(full, false);
      else if (e.isFile()) {
        try { total += (await fs.stat(full)).size; } catch { /* skip */ }
      }
    }
  }
  await walk(path, true);
  return total;
}

/**
 * Measure the store, and never fail: the failure is the answer.
 *
 * An empty path is "there is no store configured here", which the page
 * already names separately from a store it could not read, so it comes back
 * with neither a size nor an error.
 */
export async function measureStore(path: string, fs: StoreFs = REAL_FS): Promise<StoreReading> {
  if (!path) return { bytes: null, error: null };
  try {
    return { bytes: await dirSize(path, fs), error: null };
  } catch (err) {
    return { bytes: null, error: (err as Error).message };
  }
}

/** Everything the System tab shows about the store beyond its current size.
 *  Each is null when it could not be derived, never a filler value. */
export interface StoreDerivations {
  peak_bytes_24h: number | null;
  growth: NudbGrowth | null;
  free_days_est: number | null;
  /** The same free-days answer as a metric an alert rule watches, or null to
   *  write nothing at all this tick. */
  free_days_metric: number | null;
}

const NOTHING: StoreDerivations = {
  peak_bytes_24h: null, growth: null, free_days_est: null, free_days_metric: null,
};

/**
 * What may be derived from the store's history, given the reading taken now.
 *
 * Nothing, when there is no reading. The peak, the growth fit and the
 * free-days estimate are all about a store this host is writing, and the
 * samples behind them can outlive the store that produced them: a node
 * replaced on the same box leaves a month of a different store's sizes in the
 * series. Deriving from those while the current store cannot be read is how
 * one card came to say 0 B and 42.70 GB in adjacent rows.
 *
 * `notGrowingDays` is the large number written to the free-days METRIC on a
 * store that is not growing, so an alert rule that is watching it can resolve
 * rather than stay firing on a series that stopped. That substitution holds
 * only for a store somebody measured and found flat. Not measured is not not
 * growing, and writing ten years of headroom for a store nobody could read
 * would be the same invention this function exists to stop, in the one place
 * where it also silences an alert. A rule left firing because its input went
 * quiet is the better failure: it is visible, and it is true that the input
 * went quiet.
 */
export function deriveFromStore(
  reading: StoreReading,
  samples: { peak24h: number | null; window30d: readonly NudbSample[] },
  diskFreeBytes: number | null,
  notGrowingDays: number,
): StoreDerivations {
  if (!storeMeasured(reading)) return { ...NOTHING };
  const growth = estimateNudbGrowth(samples.window30d, diskFreeBytes);
  let metric: number | null = null;
  if (growth.days !== null) {
    metric = Math.min(growth.days, notGrowingDays);
  } else if (growth.status === 'not_growing' && diskFreeBytes !== null && diskFreeBytes > 0) {
    metric = notGrowingDays;
  }
  return {
    peak_bytes_24h: samples.peak24h,
    growth,
    free_days_est: growth.days,
    free_days_metric: metric,
  };
}

// ── a reading taken somewhere else ──────────────────────────────────────

/**
 * The store block this host's own Advisor publishes on /v1/status.
 *
 * #427, second half. On a host running the node from its vendor's package
 * the dashboard account cannot open the store at all, and the answer is not
 * to give it the group: the account that serves a web page does not need
 * read access to the whole ledger store. The privilege wrapper already runs
 * as root for the verbs that need it, the Advisor already holds the grant to
 * call it, and the dashboard already fetches the Advisor's /v1/status for the
 * component versions. So the number comes back along a path that exists.
 *
 * `measured_at` is the Advisor's own timestamp, not this process's clock.
 * The page prints it, so it has to be when the reading was taken rather than
 * when it was relayed.
 */
export interface AdvisorStoreReading {
  path: string;
  bytes: number | null;
  reason: string;
  measured_at: string;
}

/** Read the Advisor's store block, or nothing. Every field is checked: an
 *  Advisor too old to publish this, a proxy's error body and a truncated
 *  answer all arrive as an object, and treating one as a reading would put a
 *  number on the page that nobody measured. */
export function parseAdvisorStore(raw: unknown): AdvisorStoreReading | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const at = typeof o.measured_at === 'string' ? o.measured_at : '';
  if (!at || Number.isNaN(Date.parse(at))) return null;
  const bytes = typeof o.bytes === 'number' && Number.isFinite(o.bytes) && o.bytes >= 0 ? o.bytes : null;
  return {
    path: typeof o.path === 'string' ? o.path : '',
    bytes,
    reason: typeof o.reason === 'string' ? o.reason : '',
    measured_at: at,
  };
}

/** How old an Advisor reading may be and still stand for the store as it is
 *  now. The Advisor serves one reading for up to a minute and this process
 *  asks once a minute, so a healthy reading is under two minutes old when it
 *  arrives. Three minutes allows one missed ask and no more: past that the
 *  Advisor has stopped refreshing it, and a number nobody has taken lately is
 *  not what the store weighs. */
export const ADVISOR_READING_MAX_AGE_MS = 3 * 60_000;

/** A reading stamped further ahead than this is a clock that disagrees, and
 *  a reading from the future is not one to trust either. */
const ADVISOR_READING_SKEW_MS = 60_000;

/** Is this Advisor reading a size, taken recently enough to be the store's
 *  size now? The one place that decides, so the page, the derivations and
 *  the series cannot come to disagree about which readings count. */
export function advisorReadingCurrent(
  r: AdvisorStoreReading | null, now: number,
): r is AdvisorStoreReading & { bytes: number } {
  if (!r || r.bytes === null) return false;
  const age = now - Date.parse(r.measured_at);
  return Number.isFinite(age) && age >= -ADVISOR_READING_SKEW_MS && age <= ADVISOR_READING_MAX_AGE_MS;
}

/** The same directory, ignoring a trailing slash. The Advisor names the path
 *  its wrapper measured and the dashboard names the one its env file holds;
 *  two detectors, so a difference in the string is a difference in the store
 *  until shown otherwise. An empty path matches nothing. */
export function storePathsMatch(a: string, b: string): boolean {
  const norm = (p: string) => p.replace(/\/+$/, '');
  return norm(a) !== '' && norm(a) === norm(b);
}

/** A current Advisor reading of THIS dashboard's store. The Advisor
 *  publishes the path it measured, and on a moved node that is not the
 *  directory the dashboard was pointed at: a size is still worth showing,
 *  labelled, but it is not a sample of this store's series. */
export function advisorReadingOfThisStore(
  r: AdvisorStoreReading | null, now: number, storePath: string,
): r is AdvisorStoreReading & { bytes: number } {
  return advisorReadingCurrent(r, now) && storePathsMatch(r.path, storePath);
}

/** What the System tab is told about the store's size, and who took the
 *  reading behind it. */
export interface StoreForThePage {
  bytes: number | null;
  measured_by: { source: 'advisor'; at: string } | null;
}

/**
 * Choose between this dashboard's own walk and the Advisor's.
 *
 * Own first, always: it is this process's own observation and it needs no
 * second service to be running. The Advisor's reading is used only where
 * there is no reading of our own, and then it is LABELLED, because a number
 * measured by another program at another moment is not the same fact as one
 * this process took, and a page that shows the two identically is claiming a
 * reading it did not take. And only while it is current: an Advisor reading
 * that has stopped being refreshed is no longer the store's size.
 */
export function storeForThePage(
  own: StoreReading,
  viaAdvisor: AdvisorStoreReading | null,
  now: number = Date.now(),
): StoreForThePage {
  if (storeMeasured(own)) return { bytes: own.bytes, measured_by: null };
  if (advisorReadingCurrent(viaAdvisor, now)) {
    return { bytes: viaAdvisor.bytes, measured_by: { source: 'advisor', at: viaAdvisor.measured_at } };
  }
  return { bytes: null, measured_by: null };
}

/** Which series of sizes a derivation is fitted from. 'own' is the
 *  dashboard's series of its own walks; 'advisor' is the series of the
 *  Advisor's readings of this store, which is kept apart from it (see
 *  storeToDeriveFrom). */
export type StoreSeries = 'own' | 'advisor';

/**
 * The reading the store's history is derived from, and the series it is
 * derived over (#1245).
 *
 * #427 kept the peaks, the growth fit and the free-days estimate off the page
 * whenever this process could not walk the store, because the series they are
 * read from can outlive the store that filled it: a node replaced on the same
 * box leaves a month of a different store's sizes behind, and a fit over both
 * says the new store is not growing because the old one never moved. That is
 * still the rule. What changes is who may have measured the store: a current
 * reading from this host's own Advisor, of this dashboard's store, is a
 * measurement, taken by the one program with the access to take it.
 *
 * It is NOT fitted over the dashboard's own series, which is where the old
 * store's sizes are. The Advisor's readings are recorded into a series of
 * their own (makeAdvisorSampleRecorder below), and a derivation from them
 * reads only that, so on the day a host starts being measured this way the
 * fit starts with nothing from before. With neither an own walk nor a
 * current Advisor reading of this store there is no series and nothing is
 * derived.
 */
export function storeToDeriveFrom(
  own: StoreReading,
  viaAdvisor: AdvisorStoreReading | null,
  now: number,
  storePath: string,
): { reading: StoreReading; series: StoreSeries | null } {
  if (storeMeasured(own)) return { reading: own, series: 'own' };
  if (advisorReadingOfThisStore(viaAdvisor, now, storePath)) {
    return { reading: { bytes: viaAdvisor.bytes, error: null }, series: 'advisor' };
  }
  return { reading: own, series: null };
}

/**
 * Records the Advisor's readings into the dashboard's own series (the caller
 * says which: the chart's, and the Advisor-only one a derivation reads), and
 * only the ones that are a size, are current, are new and are of this
 * store.
 *
 *   - Stamped with when the Advisor took the reading, not when it arrived. A
 *     reading that is two minutes old is a point two minutes back on the
 *     chart; it is never written as though it were taken now.
 *   - Not recorded past ADVISOR_READING_MAX_AGE_MS. A stale reading is
 *     dropped, so a stopped Advisor leaves a gap in the series, the same way
 *     a failed walk does, and does not hold the line flat.
 *   - Not recorded twice. The Advisor serves one reading for a minute and the
 *     ask is once a minute, so the same reading can arrive twice; a repeat is
 *     one observation, not two.
 *   - Only a size. A reading that carries a reason instead of bytes records
 *     nothing, never a zero.
 *   - Only of this dashboard's store: the reading's path has to be the one
 *     the dashboard is configured with.
 *
 * Returns whether this call wrote a sample.
 */
export function makeAdvisorSampleRecorder(
  write: (bytes: number, ts: number) => void,
  storePath: string,
): (r: AdvisorStoreReading | null, now: number) => boolean {
  let lastTs = 0;
  return (r, now) => {
    if (!advisorReadingOfThisStore(r, now, storePath)) return false;
    const ts = Date.parse(r.measured_at);
    if (ts <= lastTs) return false;
    write(r.bytes, ts);
    lastTs = ts;
    return true;
  };
}
