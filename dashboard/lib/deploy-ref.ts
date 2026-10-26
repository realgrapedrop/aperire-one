/**
 * The deployed ref, and what a fleet's refs say when compared — issue #128
 * rung 2 (detection: automate the noticing, never the fixing).
 *
 * `.deploy-ref` sits at the install root and holds the commit the last fleet
 * update rsynced onto this host (tools/fleet-update.sh writes it after the
 * transfer). A host has no `.git` — the deploy excludes it — so this file is
 * the only thing on the box that knows what it is running, and reading it
 * needs no network and no credentials. Comparison, not interrogation: the
 * aggregator holds several hosts' answers and looks at them side by side.
 *
 * Two rules the whole module exists to keep:
 *
 *   - **Absent file means absent field.** No stamp is not a version, and it
 *     is never turned into one. A single-node install has no `.deploy-ref`
 *     and must be indistinguishable from one that was never deployed to.
 *   - **Unknown is never current.** A host whose ref could not be read is
 *     counted in its own bucket and is neither on the shared ref nor off it.
 *     Assuming "no answer means the same as me" is exactly the kept-vs-observed
 *     failure this project keeps meeting.
 */

/** The longest ref this will carry. A git SHA is 40; the slack is for a tag
 *  or a short branch name a future deploy might stamp instead. Anything
 *  longer is not a ref, it is a file that happens to sit at that path. */
const MAX_REF_LEN = 64;

/** Printable ASCII, no spaces. Deliberately NOT a hex/SHA test: the
 *  comparison is string equality over an opaque token and never parses it,
 *  so a stricter alphabet could only ever mark a truthful host `unknown` —
 *  the one direction this feature must not fail in. This rejects shape
 *  (a log file, a YAML document, a stray binary), not content. */
const REF_SHAPE = /^[\x21-\x7e]{1,64}$/;

/**
 * Normalises the raw file body to a ref, or null.
 *
 * First line only: `echo "$SHA" >` leaves a trailing newline, and a file that
 * grew a second line is a file this cannot vouch for.
 */
export function parseDeployRef(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const first = raw.split('\n', 1)[0].trim();
  if (first.length === 0 || first.length > MAX_REF_LEN) return null;
  return REF_SHAPE.test(first) ? first : null;
}

export interface DeployRefReader {
  /** The ref as of at most `ttlMs` ago, re-reading the file when that has
   *  elapsed. */
  current(): string | null;
}

export interface DeployRefReaderOptions {
  path: string;
  /** How long a read is trusted before the file is looked at again.
   *  Default 60s. */
  ttlMs?: number;
  now?: () => number;
  /** Injected for tests; production passes node:fs readFileSync. Throws are
   *  handled here, exactly as the real one does. */
  readFile: (path: string) => string;
  /** Called once per distinct failure reason, for the journal. Never called
   *  for a missing file: not having been deployed to is not a fault. */
  onError?: (message: string) => void;
}

/**
 * A ref reader that re-reads on demand rather than on a timer.
 *
 * The deploy rewrites `.deploy-ref` without restarting the dashboard (a
 * frontend-only sync restarts nothing), so a value read once at startup and
 * cached for the life of the process would go quietly wrong the first time
 * that happened. A TTL rather than a `setInterval` because there is nothing
 * to do with a fresh read except answer the next caller with it — a timer
 * would add a process-lifetime handle and buy nothing.
 *
 * ENOENT and EACCES are the same on the wire (no field either way) and
 * different in the journal: a host that HAS a ref and cannot read its own
 * file is an operator-fixable fault, not an undeployed box. Logged once per
 * reason so a permissions accident is visible rather than reading as absence
 * (the shape of #113).
 */
export function createDeployRefReader(opts: DeployRefReaderOptions): DeployRefReader {
  const ttlMs = opts.ttlMs ?? 60_000;
  const now = opts.now ?? Date.now;
  const reported = new Set<string>();
  let value: string | null = null;
  let readAt = 0;
  let everRead = false;

  const reread = (): void => {
    readAt = now();
    everRead = true;
    let raw: string;
    try {
      raw = opts.readFile(opts.path);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException)?.code ?? 'UNKNOWN';
      if (code !== 'ENOENT' && !reported.has(code)) {
        reported.add(code);
        opts.onError?.(`cannot read ${opts.path} (${code}) — this host reports no deploy ref until that is fixed`);
      }
      value = null;
      return;
    }
    const parsed = parseDeployRef(raw);
    if (parsed === null && !reported.has('SHAPE')) {
      reported.add('SHAPE');
      opts.onError?.(`${opts.path} does not contain a deploy ref — reporting none`);
    }
    value = parsed;
  };

  return {
    current(): string | null {
      if (!everRead || now() - readAt >= ttlMs) reread();
      return value;
    },
  };
}

// ── Comparison ────────────────────────────────────────────────────────────

/** Where one host sits relative to the rest.
 *  `shared` — its ref is the one the largest group of hosts is on.
 *  `divergent` — it reported a ref, and it is not that one.
 *  `unknown` — it reported no ref (did not answer, answered without the
 *  field, or carries no stamp). Never folded into either of the other two. */
export type DeployRefState = 'shared' | 'divergent' | 'unknown';

export interface DeployHostInput {
  label: string;
  /** null when this host reported no ref, for any reason. */
  ref: string | null;
}

export interface DeployHostResult extends DeployHostInput {
  state: DeployRefState;
}

export interface DeployComparison {
  hosts: DeployHostResult[];
  /** The ref the largest group is on — what `shared` means for this result.
   *  Null when no host reported one. Never a promise that it is the NEWEST
   *  ref: this compares hosts to each other, it does not ask anyone what the
   *  current release is. */
  reference: string | null;
  known: number;
  shared: number;
  /** Hosts that reported a ref other than `reference`. This is the metric. */
  divergent: number;
  unknown: number;
  /** False when there is nothing to compare — fewer than two hosts, or no
   *  host reported a ref at all. The caller writes no metric in that case; a
   *  `0` there would be a claim of agreement nobody observed. */
  comparable: boolean;
}

/**
 * Compares hosts by ref and counts the odd ones out.
 *
 * `divergent = (hosts with a known ref) − (size of the largest group)`. Not
 * "hosts that differ from mine": during a staged roll the box doing the
 * comparing is as likely to be the one still behind, and grading against
 * itself would report a whole fleet as divergent when one host is the odd one
 * out. Counting against the largest group is symmetric — every host computes
 * the same number from the same answers — and stays honest on a tie (2 v 2
 * gives 2, which is what "these hosts do not agree" is worth).
 *
 * `preferRef` only breaks a tie for the LABEL of `reference` (and so for
 * which side reads `shared`); it cannot change any count. Passing the local
 * host's own ref means an evenly split fleet is described from the box the
 * operator is on rather than from registry order.
 */
export function compareDeployRefs(
  hosts: DeployHostInput[],
  opts: { preferRef?: string | null } = {},
): DeployComparison {
  const groups = new Map<string, number>();
  for (const h of hosts) {
    if (h.ref === null) continue;
    groups.set(h.ref, (groups.get(h.ref) ?? 0) + 1);
  }
  const known = [...groups.values()].reduce((a, b) => a + b, 0);
  let reference: string | null = null;
  let largest = 0;
  for (const [ref, count] of groups) {
    if (count > largest) { reference = ref; largest = count; }
  }
  // Tie-break, counts untouched: prefer the caller's own ref when it is one
  // of the joint-largest groups.
  if (reference !== null && opts.preferRef && groups.get(opts.preferRef) === largest) {
    reference = opts.preferRef;
  }
  const hostResults: DeployHostResult[] = hosts.map((h) => ({
    ...h,
    state: h.ref === null ? 'unknown' : (h.ref === reference ? 'shared' : 'divergent'),
  }));
  return {
    hosts: hostResults,
    reference,
    known,
    shared: largest,
    divergent: known - largest,
    unknown: hosts.length - known,
    comparable: hosts.length >= 2 && known >= 1,
  };
}
