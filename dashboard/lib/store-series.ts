/**
 * Where the current store's size series begins (#1251).
 *
 * The `nudb_size` series is one line per host, and the host's store can be
 * replaced under it: a container node moved to the vendor's package, a store
 * restored from a snapshot, a disk swapped. Everything fitted over the series
 * afterwards then mixes two stores. Peak 24h and peak 7d carry the old store's
 * size, the growth fit reads the drop as a rotation, and a flat old store
 * beside a growing new one fits "not growing", which is written to the
 * `nudb_mount_free_days` alert metric as ten years of headroom.
 *
 * This module decides where the current store's series starts. Everything
 * that is derived, and the chart, reads from there. The samples before it
 * stay in the database, so a cut that turns out to be wrong loses nothing.
 *
 * Two facts say a store was replaced, and no third:
 *
 *   - Its path changed. The dashboard records the path its series was taken
 *     for. A different path at the next start is a different store.
 *   - Its size collapsed. Two readings in a row below a small fraction of the
 *     last day's peak. An ordinary online_delete rotation keeps the retained
 *     ledgers and the state, so the store does not fall to a tenth of itself.
 *
 * Nothing here touches the node's files. Both facts come from what the
 * dashboard already records: the path it is configured with, and the sizes it
 * writes.
 *
 * Pure: the database, the clock and the log are passed in.
 */

import { storePathsMatch } from './store-size.js';

/** What the database holds about the series: the store it was recorded for,
 *  and where the current store's samples begin (epoch seconds, 0 for "the
 *  whole series"). */
export interface SeriesMark {
  path: string;
  cut_s: number;
}

/** A reading below this fraction of the previous day's peak counts toward a
 *  replaced store. Deliberately far below any rotation step: online_delete
 *  removes the older of two backends and keeps the retained ledgers and the
 *  state, and a gated rotation (#79, #101) that waited an extra day removes
 *  more, but nothing close to nine tenths. A cut that is too eager costs the
 *  peaks two days of refilling; one that is too shy keeps the old figures. */
export const REPLACED_BELOW_FRACTION = 0.10;

/** How many readings in a row must be that low. One is a walk that skipped a
 *  directory for a moment (the walk is approximate by design, see
 *  lib/store-size.ts); two a minute apart is a store that is not there. */
export const REPLACED_CONSECUTIVE = 2;

/** How far back the peak a reading is compared with is taken. */
export const PEAK_LOOKBACK_S = 24 * 3600;

export type StartupDecision =
  | { kind: 'adopted'; mark: SeriesMark }    // first record: the history stands
  | { kind: 'same'; mark: SeriesMark }       // same store as last time
  | { kind: 'path_changed'; mark: SeriesMark };  // a different store

/**
 * Compare the store this process is configured for with the one the series
 * was recorded for.
 *
 * A database that has never recorded a path ADOPTS the current one and keeps
 * its whole history. It cannot be told apart from an upgrade of a host that
 * has run one store all along, which is every host that exists today, and
 * cutting there would blank every operator's peaks for two days on update.
 */
export function decideAtStartup(saved: SeriesMark | null, storePath: string, nowS: number): StartupDecision {
  if (saved === null) return { kind: 'adopted', mark: { path: storePath, cut_s: 0 } };
  if (storePathsMatch(saved.path, storePath)) return { kind: 'same', mark: saved };
  return { kind: 'path_changed', mark: { path: storePath, cut_s: nowS } };
}

export interface StoreSeriesDeps {
  /** Persist the mark. */
  save: (mark: SeriesMark) => void;
  /** The largest `nudb_size` reading at or after `fromS` (epoch seconds), or
   *  null when there is none. */
  peakSince: (fromS: number) => number | null;
  log?: (line: string) => void;
}

export class SeriesStart {
  private mark: SeriesMark;
  private lowRun: number[] = [];

  constructor(
    saved: SeriesMark | null,
    private readonly storePath: string,
    nowS: number,
    private readonly deps: StoreSeriesDeps,
  ) {
    const d = decideAtStartup(saved, storePath, nowS);
    this.mark = d.mark;
    if (d.kind !== 'same') deps.save(d.mark);
    if (d.kind === 'path_changed') {
      deps.log?.(`[nudb] the store is now ${JSON.stringify(storePath)}, not ${JSON.stringify(saved?.path)}; its size series starts here and nothing before this is fitted`);
    }
  }

  /** Where the current store's series begins, epoch seconds. Samples before
   *  it belong to a store that was replaced. */
  cutS(): number { return this.mark.cut_s; }

  /**
   * Note a reading that is about to be recorded. Returns true when it makes
   * the series start over, at the first of the low readings.
   *
   * Call it BEFORE the reading is written: the comparison is against the
   * peak of what is already on record.
   */
  observe(bytes: number, tsS: number): boolean {
    if (!Number.isFinite(bytes) || bytes < 0) return false;
    const peak = this.deps.peakSince(Math.max(this.mark.cut_s, tsS - PEAK_LOOKBACK_S));
    if (peak === null || !(peak > 0) || !(bytes < peak * REPLACED_BELOW_FRACTION)) {
      this.lowRun = [];
      return false;
    }
    this.lowRun.push(tsS);
    if (this.lowRun.length < REPLACED_CONSECUTIVE) return false;
    const cutS = this.lowRun[0];
    this.lowRun = [];
    this.mark = { path: this.storePath, cut_s: cutS };
    this.deps.save(this.mark);
    this.deps.log?.(`[nudb] the store fell to ${bytes} bytes from a day's peak of ${peak}; it was replaced, so its size series starts over at ${cutS}`);
    return true;
  }
}
