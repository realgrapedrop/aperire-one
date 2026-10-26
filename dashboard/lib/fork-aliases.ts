// Fork-naming capability detection, factored out of server.ts so
// the resolution logic can be unit tested directly.
//
// The validator node software ships under diverging names across forks — the
// XRPL Foundation's `rippled`, xrpl-labs' `xrpld`, and Xahau's `xahaud` — and
// renames have twice silently blanked dashboard fields: the process binary
// (rippled→xrpld) and the get_counts C++ object-counter namespace
// (ripple::→xrpl::). We resolve through a known-alias table rather than gating
// on build_version, because the three forks version independently and a single
// version threshold can't track per-fork symbol names (and a patched build
// would defeat it). When an expected counter resolves under NO known alias we
// surface it in the logs, so the next rename announces itself instead of
// reaching a user as a blank cell.

// Ordered alias prefixes for get_counts object counters, first match wins.
// Newer rippled/xrpld builds use `xrpl::`; older rippled used `ripple::`.
// Add a new prefix here when a fork introduces one.
export const COUNTER_PREFIXES = ['xrpl::', 'ripple::'] as const;

// Ordered process-binary basenames, used by findRippledPid in server.ts so the
// pgrep fast-path and the /proc fallback share one authoritative default list.
export const BINARY_NAMES = ['rippled', 'xrpld', 'xahaud'] as const;

// The class counters every supported build must expose. These map to the four
// RIPPLED INTERNALS rows (SLE Size, AccountState, LedgerNode, NodeObject Count)
// that broke on the namespace rename. If one of these resolves to null, that's
// the signal a rename happened and we warn.
export const REQUIRED_COUNTERS = [
  'STLedgerEntry',
  'SHAMapAccountStateLeafNode',
  'SHAMapInnerNode',
  'SHAMapItem',
] as const;

// Resolve a single class counter by trying each known namespace prefix in
// order. Returns the numeric count for the first prefix present, or null if no
// known alias is found. A value of 0 is a valid count, not a miss.
export function resolveCounter(raw: Record<string, unknown>, canonicalName: string): number | null {
  for (const prefix of COUNTER_PREFIXES) {
    const v = raw[prefix + canonicalName];
    if (v !== undefined && v !== null) {
      const n = Number(v);
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

// Resolve every REQUIRED_COUNTERS entry into a flat canonical object. These
// canonical keys are broadcast alongside the raw get_counts so clients can read
// stable names regardless of which fork's namespace the node uses.
export function resolveAllCounters(raw: Record<string, unknown>): Record<string, number | null> {
  const out: Record<string, number | null> = {};
  for (const name of REQUIRED_COUNTERS) out[name] = resolveCounter(raw, name);
  return out;
}

// Names whose value is null — a total alias miss after trying every prefix.
export function findMissingRequired(canonical: Record<string, number | null>): string[] {
  return REQUIRED_COUNTERS.filter((name) => canonical[name] == null);
}

// A miss has two very different meanings, and the warner used to conflate
// them — observed live on a 3.3.0 node mid-sync, which was reported as "the
// next rename" when it was a node with no state tree yet:
//
//   renamed — the counter EXISTS in get_counts under a prefix this table
//             does not know (`foo::SHAMapItem`). That is the rename signal
//             this module exists to announce, and the found key names the
//             prefix to add.
//   absent  — no key with this counter's suffix exists at all. A node that
//             has not built its state tree reports no SHAMap counters, so
//             absence is a node state, not a naming change. It still logs
//             once (a counter absent on a HEALTHY node would matter) but as
//             what it is, never as a rename.
export function classifyMiss(
  raw: Record<string, unknown>,
  canonicalName: string,
): { kind: 'renamed'; foundAs: string } | { kind: 'absent' } {
  for (const key of Object.keys(raw)) {
    if (key === canonicalName || key.endsWith('::' + canonicalName)) {
      return { kind: 'renamed', foundAs: key };
    }
  }
  return { kind: 'absent' };
}

// Build a warner that logs each unresolved required field once per
// (field, build_version), so a poll loop doesn't spam and an upgrade that
// changes the version re-announces any still-missing field exactly once.
// `raw` is the same get_counts body the resolver saw, so a miss can be
// classified rather than guessed at.
export function createMissWarner(
  logFn: (msg: string) => void,
): (missing: string[], buildVersion: string | null, raw: Record<string, unknown>) => void {
  const seen = new Set<string>();
  return (missing, buildVersion, raw) => {
    const version = buildVersion ?? 'unknown';
    for (const field of missing) {
      const kindNow = classifyMiss(raw, field);
      // Absence and a rename dedupe separately: a node that was absent
      // while syncing must still announce a genuine rename discovered
      // after it arrives.
      const key = `${field}@${version}@${kindNow.kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (kindNow.kind === 'renamed') {
        const tried = COUNTER_PREFIXES.map((p) => p + field).join(', ');
        logFn(`required counter RENAMED: ${field} found as "${kindNow.foundAs}" ` +
          `(build: ${version}, tried: ${tried}) — add its prefix to COUNTER_PREFIXES`);
      } else {
        logFn(`required counter absent from get_counts: ${field} (build: ${version}) — ` +
          `normal while the node has no state tree; a rename would show the counter ` +
          `under an unknown prefix instead`);
      }
    }
  };
}
