/**
 * The release feed: which xrpld release is out, which one a node can actually
 * install, and what this dashboard hands a browser about both (#658).
 *
 * Three public readings go in:
 *   - the official package index, the signed DEB repository the install
 *     guide configures. From 3.4.x on, a release ships as a signed package
 *     first, and sometimes only as one: 3.4.1 exists at packages.xrplf.org
 *     and has no GitHub release at all. A package there installs with apt on
 *     a native host.
 *   - the GitHub release feed, which used to be the only "released" source.
 *   - the official container image, asked one narrow question about one
 *     tag rather than walked as a list (#682).
 *
 * Released and installable are two different questions, so they are answered
 * from two different sets. A release EXISTS if any of the three carries it.
 * A release is INSTALLABLE if the package index or a published image carries
 * it; a GitHub tag on its own installs nothing. When the first is ahead of
 * the second the feed says so with a `note`, which is what puts the amber
 * "soon" pill on the page, and the poller drops to the short clock until the
 * two agree.
 *
 * The note is written only once the package index has been read at least
 * once. Without it, "GitHub has 3.4.0, the image has 3.3.0" is not evidence
 * that nothing installs 3.4.0: the signed package may well be sitting in the
 * repository (it was, for the whole of 3.4.x), and an amber "nothing to do
 * yet" would be wrong on a native host in exactly the case that matters.
 * Fail soft, say less.
 *
 * Every reading is cached with the time it was taken, and only a successful
 * read moves it. One GitHub blip must not retract a release the page has
 * already announced, and a failed index read must not re-stamp the age the
 * page prints beside it.
 *
 * Kept pure, no fetch of its own and no clock, so the whole table of cases is
 * a unit test.
 */

import {
  computeReleasePosture, type ReleaseFact, type ReleasePosture,
} from './release-posture.js';
import { compareVersions, readVersion } from './version-compare.js';

/** The Packages index of the repository the install guide configures:
 *  `deb [signed-by=...] https://packages.xrplf.org/repository/deb-stable any main`.
 *  The repository is a Nexus apt host with no directory listing; its Release
 *  file names exactly this path (and only amd64). */
export const PACKAGES_INDEX_URL =
  'https://packages.xrplf.org/repository/deb-stable/dists/any/main/binary-amd64/Packages';

/** The label a release fact carries downstream, naming the feed the number
 *  actually came from. `PACKAGES_SOURCE` is distinct from an Advisor's own
 *  `target_source` ('package repository'), which is a different read, of a
 *  different thing, on a different clock. */
export const PACKAGES_SOURCE = 'packages.xrplf.org';
export const GITHUB_SOURCE = 'github release feed';
export const IMAGE_SOURCE = 'the published container image';

/** The repository the XRPL release process publishes to, announced
 *  2026-09-19; WietseWind/docker-xrpld#31 retires xrpllabsofficial/xrpld in
 *  its favour. A constant rather than a setting, for the reason the
 *  Advisor's own `OfficialImageRepo` is one: what comes back from a
 *  registry is what a node runs, and a configurable name is a name an
 *  operator's own configuration could point anywhere. */
export const OFFICIAL_IMAGE_REPO = 'rippleci/xrpld';

/** An index well past any real size. The real one is under 4 KB. */
export const PACKAGES_INDEX_MAX_BYTES = 1_000_000;

const RELEASE_RE = /^[0-9]+(\.[0-9]+)*$/;

/** The newest of any number of versions, ignoring the absent ones. */
export function newestOf(...vs: Array<string | null | undefined>): string | undefined {
  let best: string | undefined;
  for (const v of vs) {
    if (typeof v !== 'string' || !v) continue;
    if (best === undefined || compareVersions(v, best) > 0) best = v;
  }
  return best;
}

/**
 * A Debian version (`[epoch:]upstream[-revision]`) to the release it
 * packages, or null when that is not a plain dotted release. `3.4.1-1` is
 * 3.4.1. A pre-release (`3.5.0~rc1-1`) is null, the same way the GitHub read
 * skips pre-releases: an operator is never nudged toward one.
 */
export function releaseFromDebVersion(debVersion: string): string | null {
  let v = debVersion.trim();
  const colon = v.indexOf(':');
  if (colon >= 0) v = v.slice(colon + 1);
  const dash = v.lastIndexOf('-');
  if (dash > 0) v = v.slice(0, dash);
  return RELEASE_RE.test(v) ? v : null;
}

/**
 * Every release of `xrpld` in a Debian Packages index, oldest first, no
 * repeats. Only a stanza whose own `Package:` is exactly `xrpld` counts:
 * `xrpld-assert` (which `Provides: xrpld`), and the `-dbgsym` packages carry
 * the same version numbers but are not the release an operator installs.
 * Anything unparseable is skipped, never thrown.
 */
export function parseDebPackagesIndex(text: string, pkg = 'xrpld'): string[] {
  const seen = new Set<string>();
  for (const stanza of text.replace(/\r\n/g, '\n').split(/\n[ \t]*\n/)) {
    const name = /^Package:[ \t]*(\S+)[ \t]*$/m.exec(stanza)?.[1];
    if (name !== pkg) continue;
    const ver = /^Version:[ \t]*(\S+)[ \t]*$/m.exec(stanza)?.[1];
    const rel = ver ? releaseFromDebVersion(ver) : null;
    if (rel) seen.add(rel);
  }
  return [...seen].sort(compareVersions);
}

/**
 * Read a response body as text with a running cap, aborting the transfer the
 * moment it goes past. The old version read the whole body first and checked
 * its length afterwards, which is a bound on nothing: a hostile or broken
 * endpoint (or a Nexus error page behind a proxy) could hand this process a
 * gigabyte and the cap would fire after it was all in memory. `content-length`
 * is the ENCODED size, so it is only worth an early reject; the cap that
 * matters counts the bytes `fetch` has already decompressed.
 *
 * Returns null when the cap is passed, or when there is no body at all.
 */
export async function readCappedText(res: Response, maxBytes: number): Promise<string | null> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) {
    try { await res.body?.cancel(); } catch { /* already gone */ }
    return null;
  }
  if (!res.body) return null;
  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let seen = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    seen += value.byteLength;
    if (seen > maxBytes) {
      try { await reader.cancel(); } catch { /* already gone */ }
      return null;
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}

// ── The cached readings ────────────────────────────────────────────────

/** One source's newest release and when that reading was taken. */
export interface SourceReading {
  version: string;
  /** Epoch ms of the last SUCCESSFUL read of this source. */
  read_at: number;
}

export interface FeedCache {
  github?: SourceReading;
  packages?: SourceReading;
  image?: SourceReading;
}

/**
 * Fold one poll's readings into the cache. A source that answered replaces
 * its entry, with the time it answered; a source that failed, timed out or
 * parsed to nothing keeps whatever it last said, at the time it said it.
 *
 * One bad poll must never make a released version vanish, which would flip
 * every node's pill and the fleet's [R] badge on a network blip, and it must
 * never make a stale number look freshly read.
 */
export function nextFeedCache(
  prev: FeedCache,
  reads: { github?: string; packages?: string; image?: string },
  now: number,
): FeedCache {
  const fold = (was: SourceReading | undefined, got: string | undefined): SourceReading | undefined =>
    (typeof got === 'string' && got) ? { version: got, read_at: now } : was;
  return {
    github: fold(prev.github, reads.github),
    packages: fold(prev.packages, reads.packages),
    image: fold(prev.image, reads.image),
  };
}

export interface ReconciledFeed {
  latest_release?: string;
  latest_installable?: string;
  /** Which feed `latest_release` came from, carried into the posture's
   *  upstream fact so nothing downstream has to guess. */
  release_source?: string;
  /** Which feed `latest_installable` came from. The page says "releases ship
   *  as signed packages" only when this is the package index. */
  installable_source?: string;
  /** Epoch ms `release_source` was last read successfully. This is the age
   *  the page prints; a poll where that source failed does not move it. */
  release_read_at?: number;
  /** Epoch ms `installable_source` was last read successfully. */
  installable_read_at?: number;
  /** Set when a release exists that nothing can install yet, and the package
   *  index has been read at least once (so "nothing installs it" is a
   *  reading, not a guess). This is what puts the amber "soon" pill up. */
  note?: string | null;
  /** False while the picture is incomplete: the index has never been read,
   *  or something is released that nothing installs yet. The poller rechecks
   *  on the short clock while this is false. */
  settled: boolean;
}

type Candidate = { source: string; reading: SourceReading };

/** Newest wins; on a tie the earlier candidate wins, and the arrays below are
 *  ordered so that is the package index, then GitHub, then the image. The
 *  index is the source an operator installs from, so when two sources carry
 *  the same release it is the honest label for it. */
function newest(cands: Array<Candidate | null>): Candidate | undefined {
  let best: Candidate | undefined;
  for (const c of cands) {
    if (!c) continue;
    if (!best || compareVersions(c.reading.version, best.reading.version) > 0) best = c;
  }
  return best;
}

export function reconcileReleaseFeed(cache: FeedCache): ReconciledFeed {
  const pkg = cache.packages ? { source: PACKAGES_SOURCE, reading: cache.packages } : null;
  const gh = cache.github ? { source: GITHUB_SOURCE, reading: cache.github } : null;
  const img = cache.image ? { source: IMAGE_SOURCE, reading: cache.image } : null;

  // Released: any of the three. Installable: only the two that produce an
  // artifact. A GitHub tag installs nothing.
  const released = newest([pkg, gh, img]);
  const installable = newest([pkg, img]);

  const ahead = !!released &&
    (!installable || compareVersions(released.reading.version, installable.reading.version) > 0);

  return {
    latest_release: released?.reading.version,
    latest_installable: installable?.reading.version,
    release_source: released?.source,
    installable_source: installable?.source,
    release_read_at: released?.reading.read_at,
    installable_read_at: installable?.reading.read_at,
    note: (ahead && pkg)
      ? `${released.reading.version} is released; nothing installable carries it yet`
      : undefined,
    settled: !!pkg && !ahead,
  };
}

// ── What a browser is handed ───────────────────────────────────────────

export type ReleaseInfo = {
  /** Newest release any source carries. */
  latest_release?: string;
  /** Newest release something can actually install. */
  latest_installable?: string;
  /** Which feed `latest_release` came from. */
  release_source?: string;
  /** Which feed `latest_installable` came from. */
  installable_source?: string;
  /** Epoch ms `release_source` was last read successfully. */
  release_read_at?: number;
  /** This node's own build is older than `latest_installable`. False where
   *  there is no local node, or where its version is not version-shaped. */
  behind?: boolean;
  /** Epoch ms the poll last RAN. Not the age of any reading: a poll where
   *  every source failed still moves this and moves nothing else. */
  checked_at?: number;
  /** Released, and nothing installable carries it yet. `null`, never absent,
   *  once a poll has run: overview.html MERGES each release_info frame over
   *  the one before it (a deliberate backstop against a narrower frame
   *  erasing a field), and JSON drops an undefined key, so a note that was
   *  true an hour ago survived the frame that retracted it. The tab then
   *  read "3.5.0 is published and installable" directly above "nothing can
   *  install it yet", until reload. An explicit null is what retracts it. */
  note?: string | null;
};

/** The release picture this process holds, from the reconciled feed and the
 *  running build. Pure: the poll supplies the clock. */
export function releaseInfoFromFeed(
  feed: ReconciledFeed,
  running: string | null | undefined,
  now: number,
): ReleaseInfo {
  const installable = feed.latest_installable ?? feed.latest_release;
  const run = readVersion(running);
  return {
    latest_release: feed.latest_release,
    latest_installable: feed.latest_installable,
    release_source: feed.release_source,
    installable_source: feed.installable_source,
    release_read_at: feed.release_read_at,
    behind: (run && installable) ? compareVersions(run, installable) < 0 : false,
    checked_at: now,
    // Explicit, never absent: see the field's own note above.
    note: feed.note ?? null,
  };
}

/** The upstream fact both posture callers judge against. Dated by the read
 *  that produced it, never by the poll that failed to. No read time, no
 *  fact: the page would otherwise print "checked moments ago" beside a
 *  number nobody has managed to read since the process started. */
export function upstreamFactFromInfo(info: ReleaseInfo): ReleaseFact | null {
  return (info.latest_release && info.release_read_at)
    ? {
      version: info.latest_release,
      source: info.release_source ?? GITHUB_SOURCE,
      checked_at: info.release_read_at,
    }
    : null;
}

export type SelfReleasePayload = ReleaseInfo & {
  self_installable: ReleaseFact | null;
  self_release_posture: ReleasePosture;
};

/**
 * The one release-info payload every surface serves: the /release-info
 * route, the WS snapshot, and both `release_info` broadcasts. Built fresh on
 * every call from whatever the process currently holds, so the posture is
 * always judged against the latest running version and Advisor reading
 * rather than whatever they were when the feed last changed (#550).
 */
export function selfReleasePayload(
  info: ReleaseInfo,
  selfInstallable: ReleaseFact | null,
  running: string | null,
): SelfReleasePayload {
  return {
    ...info,
    self_installable: selfInstallable,
    self_release_posture: computeReleasePosture(upstreamFactFromInfo(info), selfInstallable, running),
  };
}
