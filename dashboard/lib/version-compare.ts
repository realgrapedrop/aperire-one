/**
 * One rule for "is this version older than that one", for every surface that
 * decides what the version pill says (#658).
 *
 * Before this there were four copies of the compare and they did not agree.
 * The server's own copies read a segment with `parseInt`, so `3.4.1-rc1`
 * parsed as `3.4.1` and a release candidate counted as the release itself.
 * overview.html's copy read it with `Number`, so the same segment came out
 * `NaN`, fell to 0, and `3.4.1-rc1` counted as `3.4.0`. It also compared
 * three segments only. Two surfaces reading the same two numbers and
 * answering differently is the failure class #550 and #658 are both about,
 * so the rule is written once here and mirrored, character for character, in
 * overview.html's `vcmp` (version-compare.test.ts runs this table through
 * both, so the mirror cannot drift silently).
 *
 * The rule:
 *   - Numeric segments compare left to right, numerically. 3.10.0 > 3.9.0.
 *   - A missing segment is 0, so 3.4 and 3.4.0 are the same release.
 *   - A pre-release sorts BEFORE its release: 3.4.1-rc1 < 3.4.1, and
 *     2.5.0-b1 < 2.5.0. Two pre-releases of the same release compare by
 *     their tail (b1 < rc1, rc1 < rc2).
 *   - Build metadata after `+` is ignored, and a leading `v` is ignored.
 *   - Anything that does not start with a number sorts below everything that
 *     does, rather than throwing. Callers that must not make a claim about an
 *     unreadable version ask `isReadableVersion` first; this function stays
 *     quiet either way.
 *
 * The fleet card's [R] badge (`fleet-health.ts`) asks this function too
 * (#667), so the pill, the badge and `node_version_behind` cannot disagree
 * about a node on a release candidate: it reads as behind the final release
 * on all three, and they amber together.
 */

/** The version text a surface is allowed to make a claim about. Mirrors
 *  overview.html's `runningKnown`: two numeric segments, at least. A node
 *  whose version has not been read renders as `—` or an empty string, and no
 *  pill, badge or card may say anything about it. */
export function isReadableVersion(v: unknown): boolean {
  return typeof v === 'string' && /^v?[0-9]+\.[0-9]+/i.test(v.trim());
}

/**
 * A node's reported `build_version` to the version inside it, or null when
 * there is no version in it at all.
 *
 * Most builds report a bare `3.3.0`, but some report `rippled-3.3.0`.
 * overview.html has stripped that prefix at every render site for as long as
 * the version has been on the page; the server stripped it nowhere, so the
 * same node read as "no version" to `behind`, to `node_version_behind` and
 * to the posture, and a node a release behind rendered healthy with no pill
 * at all. Every server-side reading of a running version goes through here.
 */
export function readVersion(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const stripped = v.trim().replace(/^(rippled|xrpld)-/i, '');
  return isReadableVersion(stripped) ? stripped : null;
}

function parseVersion(v: string): { nums: number[]; pre: string } {
  let s = String(v).trim().toLowerCase();
  const plus = s.indexOf('+');
  if (plus >= 0) s = s.slice(0, plus);
  const m = /^v?([0-9]+(?:\.[0-9]+)*)(.*)$/.exec(s);
  if (!m) return { nums: [], pre: s };
  return {
    nums: m[1].split('.').map((n) => parseInt(n, 10)),
    pre: m[2].replace(/^[-~.]/, ''),
  };
}

/** b1 < rc1 < rc2. Digit runs compare numerically, letter runs compare as
 *  text, and the shorter tail sorts first when one is a prefix of the other. */
function comparePre(a: string, b: string): number {
  const ta = a.match(/[0-9]+|[^0-9]+/g) ?? [];
  const tb = b.match(/[0-9]+|[^0-9]+/g) ?? [];
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i], y = tb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^[0-9]+$/.test(x), ny = /^[0-9]+$/.test(y);
    if (nx && ny) { const d = parseInt(x, 10) - parseInt(y, 10); if (d) return d < 0 ? -1 : 1; continue; }
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Compare two versions. Negative when `a` is older, 0 when they are the same
 *  release, positive when `a` is newer. */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a), pb = parseVersion(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const x = pa.nums[i] ?? 0, y = pb.nums[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === '') return 1;
  if (pb.pre === '') return -1;
  return comparePre(pa.pre, pb.pre);
}
