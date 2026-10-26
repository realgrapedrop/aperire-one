/**
 * The one fact both surfaces read about whether a newer rippled release is
 * actually installable (#550).
 *
 * Two honest sources, two different questions:
 *   - upstream: a release EXISTS (the release feed server.ts already polls
 *     for the Overview chip; the official package index when it has been
 *     read, see release-feed.ts).
 *   - installable: the newest version the Advisor's own registry (or, on a
 *     native host, package-repository) check says it can actually pull.
 *     This is the same read it would use to build an upgrade plan.
 *
 * They can disagree for hours after a release, and sometimes for good: the
 * 3.4.x releases ship as signed packages and no vendor image ever followed,
 * so a registry check that still reads the vendor image stays behind until
 * the Advisor reads the package instead. A page that reads only the first
 * says "upgrade available" when nothing can be installed yet; a page that
 * reads only the second says nothing at all about a release the operator
 * has already heard about. Before this, Overview read only the first and the
 * Advisor tab's own card read only the second, with nothing between them
 * saying the two could disagree. An operator who saw both pages at once had
 * no way to tell "the Advisor is behind" from "nothing is wrong, the image
 * just is not out yet".
 *
 * This function is pure on purpose: no fetch, no clock, no node label. The
 * caller supplies both readings (each already dated and sourced) and gets
 * back the one classification everything downstream renders from. Computed
 * once, per caller, from whichever two readings that caller actually has.
 * Never two independent judgements of the same two numbers.
 */

import { compareVersions as cmpVersion, readVersion } from './version-compare.js';

/** One version reading, with where it came from and when. */
export interface ReleaseFact {
  version: string;
  /** e.g. 'github release feed', 'image registry', 'package repository'. */
  source: string;
  /** Epoch ms this reading was taken. */
  checked_at: number;
}

export type ReleasePostureState =
  /** Nothing upstream is newer than what is already installable (or
   *  running, when installable is not known). Nothing to say. */
  | 'current'
  /** Something newer exists upstream, and the Advisor's own check already
   *  covers it. This is the ordinary "an upgrade is available" case,
   *  unchanged from before this issue. */
  | 'installable'
  /** Something newer exists upstream and nothing can install it yet.
   *  This is the gap this issue is about. */
  | 'gap';

export interface ReleasePosture {
  state: ReleasePostureState;
  upstream: ReleaseFact | null;
  installable: ReleaseFact | null;
}

/**
 * Classifies the gap between what is released upstream and what can be
 * installed right now.
 *
 * A known `running` at or past upstream is always 'current', whatever the
 * installable reading says (#658: a node on 3.4.1 whose Advisor's registry
 * check still answered 3.3.0 was shown "3.4.0 soon"). Every caller that can
 * know the running version passes it; the peer route reads it off the fleet
 * poll.
 *
 * `running` is optional: when it is not known (an aggregator with no node of
 * its own, or a page that has not read it yet), "is upstream newer at all"
 * falls back to comparing upstream against `installable`, which is the best
 * available stand-in (a running node is never ahead of what it could
 * install). A `running` string with no version in it counts as not known,
 * never as a version; one that carries a build prefix (`rippled-3.3.0`) is
 * read through it, the same way the page has always rendered it.
 *
 * Something installable that is newer than what the node runs is always
 * 'installable', even when upstream is newer still. The feed can carry a
 * release nothing installs yet (a GitHub tag ahead of the package index)
 * while the node is behind a release it CAN install: 3.5.0 tagged, 3.4.1 in
 * the package index, the node on 3.3.0. Classing that as 'gap' told the
 * operator "3.5.0 soon, nothing to offer yet" and swallowed the upgrade to
 * 3.4.1 that was sitting right there. The pending release is still said, in
 * the tip, beside the call to action.
 */
export function computeReleasePosture(
  upstream: ReleaseFact | null,
  installable: ReleaseFact | null,
  running?: string | null,
): ReleasePosture {
  if (!upstream) return { state: 'current', upstream, installable };

  const runningVersion = readVersion(running);
  const baseline = runningVersion ?? installable?.version ?? null;
  const upstreamIsNewer = baseline ? cmpVersion(upstream.version, baseline) > 0 : true;
  if (!upstreamIsNewer) return { state: 'current', upstream, installable };

  const installableBeatsRunning =
    !!installable && !!runningVersion && cmpVersion(installable.version, runningVersion) > 0;
  const installableCoversUpstream =
    !!installable && cmpVersion(installable.version, upstream.version) >= 0;
  return {
    state: (installableBeatsRunning || installableCoversUpstream) ? 'installable' : 'gap',
    upstream,
    installable,
  };
}

/** One peer's entry in the opportunistic installable cache: either an
 *  Advisor answered a check for it, or this dashboard asked and there is no
 *  Advisor there. No entry at all is a third fact, 'unknown'. */
export type PeerAdvisorEntry =
  | { state: 'present'; fact: ReleaseFact }
  | { state: 'absent' };

export interface PeerReleasePostureBody {
  advisor: 'present' | 'absent' | 'unknown';
  installable: ReleaseFact | null;
  release_posture: ReleasePosture | null;
}

/**
 * The body /api/node/<label>/release-posture serves, from readings the
 * dashboard already holds. Pure, so the whole table of cases is a unit test
 * rather than a regex over server.ts.
 *
 * `release_posture` is null when the peer's own running version could not be
 * read (unreachable, or refused by the fleet pin). Without it the posture
 * would be judged against the peer's installable reading alone, and a peer
 * already running the release came out as a gap, which is #658 itself: the
 * Advisor tab's peer card then says "3.4.0 is out, the Advisor cannot offer
 * it yet" about a node running 3.4.1. No version read, no claim.
 */
export function peerReleasePostureBody(
  upstream: ReleaseFact | null,
  entry: PeerAdvisorEntry | undefined,
  peerRunning: string | null,
): PeerReleasePostureBody {
  const advisor: 'present' | 'absent' | 'unknown' = entry ? entry.state : 'unknown';
  const installable = entry && entry.state === 'present' ? entry.fact : null;
  const running = readVersion(peerRunning);
  return {
    advisor,
    installable,
    release_posture: running ? computeReleasePosture(upstream, installable, running) : null,
  };
}

/**
 * The one reading server.ts pulls off a `/v1/check` body to learn what an
 * Advisor believes is newest and installable. Shared so the self poll
 * (pollSelfAdvisorInstallable) and the peer cache (#550's peer half,
 * notePeerAdvisorInstallable) can never parse the same shape two different
 * ways. `target_source` is published only beside a DERIVED target
 * (advisord's main.go); a caller who supplied their own target gets none,
 * which this guards against the same way a body that answers something a
 * no-target call did not expect would be guarded against either way.
 */
export function parseAdvisorCheckInstallable(body: {
  target?: unknown; target_source?: unknown; target_source_read_at?: unknown;
}): ReleaseFact | null {
  const version = typeof body.target === 'string' ? body.target : '';
  const source = typeof body.target_source === 'string' ? body.target_source : '';
  if (!version || !source) return null;
  const readAt = typeof body.target_source_read_at === 'string'
    ? Date.parse(body.target_source_read_at) : NaN;
  return { version, source, checked_at: Number.isFinite(readAt) ? readAt : Date.now() };
}
