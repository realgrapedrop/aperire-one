/**
 * What this install IS — ADR 0022 decision 1, the precondition for every
 * other half of the update check.
 *
 * Nothing on an installed host recorded which release it was running.
 * `package.json` says 0.4.0 and has not moved in any release, so it is not a
 * release identity and is never consulted here. Two files at the install
 * root are, in this order:
 *
 *   1. `.release` — one JSON object the bootstrap writes at the end of a
 *      successful install or reinstall (tag, commit, sha256, published_at,
 *      source_url, installed_at).
 *   2. `.deploy-ref` — the commit the fleet update last rsynced onto this
 *      host, which is all a fleet-updated box has ever had.
 *
 * The identity is three-valued and the third value is said out loud:
 *
 *   | On the host                          | kind         |
 *   |--------------------------------------|--------------|
 *   | `.release` present and parseable     | `release`    |
 *   | no `.release`, `.deploy-ref` present | `deploy_ref` |
 *   | neither                              | `unknown`    |
 *
 * The two rules `deploy-ref.ts` exists to keep hold here too, and one is
 * added:
 *
 *   - **Absent file means absent field.** No stamp is not a version.
 *   - **Unknown is never current**, and (ADR 0022 decision 2) unknown is
 *     never behind either. A host that cannot say what it is running gets
 *     its own bucket at both ends.
 *   - **A present `.release` settles it, whatever it turned out to say.** The
 *     bootstrap removes `.deploy-ref` when it writes the stamp, precisely so
 *     one file claims identity rather than two, so a host carrying a stamp
 *     and a stale ref would otherwise be answered from the file nobody stands
 *     behind. A stamp that names a release is that release; one that names
 *     only a commit (which is what the bootstrap writes when the copy that
 *     ran carries no stamp of its own) is that commit, in the same words a
 *     deploy ref gets; one that names neither is unknown. Only a file that is
 *     not JSON at all is a fault, and that one is said in the journal.
 *
 * Nothing here trusts the stamp for anything but display and for deciding
 * whether to check: the dashboard account can write its own `.release`, and
 * an apply re-verifies the archive against the publisher's sha256 before it
 * unpacks anything. A lying stamp can cause a needless check, never a wrong
 * install.
 */
import { parseDeployRef } from './deploy-ref.js';
import type { ReleaseIdentityWire } from '../types/read-contract.js';

/** A sha256 as `sha256sum` prints it. Compared for equality, lower-cased
 *  first, and never ordered: releases are not version-numbered against each
 *  other anywhere in this feature. */
const SHA256_SHAPE = /^[0-9a-f]{64}$/i;
/** Printable ASCII, no spaces, bounded. Same reasoning as REF_SHAPE in
 *  deploy-ref.ts: this rejects shape (a log line, a YAML document), not
 *  content, because a stricter alphabet could only ever mark a truthful host
 *  unknown. */
const TOKEN_SHAPE = /^[\x21-\x7e]{1,128}$/;
/** The whole file. A stamp is six short fields; anything past this is not
 *  the file the bootstrap wrote. */
const MAX_STAMP_BYTES = 8 * 1024;

/** The object `.release` holds, once it has been checked. */
export interface ReleaseStamp {
  tag: string;
  commit: string;
  sha256: string;
  published_at: string;
  /** Where the archive came from, e.g.
   *  `https://get.aperire.one/release.tar.gz`. The endpoint the check asks
   *  is derived from this, so a host installed from a mirror asks its own
   *  mirror. Null when the stamp did not carry a usable one. */
  source_url: string | null;
  installed_at: string | null;
}

/** The three-valued identity, as ADR 0022's table gives it. `unknown` is a
 *  member of this union and not an absence, because the page has words for
 *  it: "unknown, older than 2026-09-08". */
export type ReleaseIdentity =
  | {
    kind: 'release';
    tag: string;
    commit: string;
    sha256: string;
    published_at: string;
    /** Local only. This never crosses onto the read API: which endpoint a
     *  host asks is that host's own business and no peer grades it. */
    source_url: string | null;
    /** Local only, like source_url: when the bootstrap wrote the stamp. */
    installed_at: string | null;
  }
  | { kind: 'deploy_ref'; sha: string }
  | { kind: 'unknown' };

/** The identity as it travels: the same union without `source_url`, and it
 *  lives in the read contract because that is where it is published. What a
 *  peer says about itself, and what an aggregator grades. */
export type { ReleaseIdentityWire };

export const UNKNOWN_IDENTITY: ReleaseIdentity = { kind: 'unknown' };

function str(v: unknown): string | null {
  return typeof v === 'string' && TOKEN_SHAPE.test(v.trim()) ? v.trim() : null;
}

/**
 * The raw file body to a stamp, or null.
 *
 * Every required field has to be there and has to be shaped: a half-written
 * stamp is not a release identity, and reading one would put a tag on the
 * page beside a sum that names nothing. `published_at` is checked for shape
 * only (a non-empty token that parses as a date), never re-formatted, so
 * whatever the publisher wrote is what the page prints.
 */
export function parseReleaseStamp(raw: string | null | undefined): ReleaseStamp | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_STAMP_BYTES) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    return null;
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const o = obj as Record<string, unknown>;
  const tag = str(o.tag);
  const commit = str(o.commit);
  const sha256 = str(o.sha256);
  const publishedAt = str(o.published_at);
  if (!tag || !commit || !sha256 || !publishedAt) return null;
  if (!SHA256_SHAPE.test(sha256)) return null;
  if (!Number.isFinite(Date.parse(publishedAt))) return null;
  const sourceUrl = str(o.source_url);
  return {
    tag,
    commit,
    sha256: sha256.toLowerCase(),
    published_at: publishedAt,
    // https only, and this is not decoration. The stamp is a file the
    // dashboard account can write, so the one field in it that steers an
    // outbound request is the one field worth refusing: a plain-http or
    // file: source would downgrade the only integrity this phase has.
    source_url: sourceUrl && /^https:\/\/[^\s]+$/i.test(sourceUrl) ? sourceUrl : null,
    installed_at: str(o.installed_at),
  };
}

/**
 * What a `.release` file amounts to: a whole release, a bare commit, or
 * neither.
 *
 * The bootstrap writes this file even when the copy of itself that ran
 * carries no stamp, and then it writes empty strings rather than a guess
 * (`get-aperire.sh`'s own words: "no tag, no date, and a commit only when it
 * can read one back"). That file is not corrupt, it is a host saying it was
 * not installed from a published release. Since the bootstrap also removes
 * `.deploy-ref` when it writes the stamp, reading that as corrupt would take
 * the last thing such a host could say about itself.
 *
 * So three outcomes, and `malformed` is only the first:
 *
 *   - not JSON, or not an object — nothing wrote this on purpose, and it is
 *     worth a line in the journal.
 *   - every release field whole — a release.
 *   - a commit and no usable release — deployed from a commit, said in the
 *     same words a `.deploy-ref` gets, because it is the same fact.
 */
export function readReleaseFile(raw: string | null | undefined): {
  stamp: ReleaseStamp | null;
  commit: string | null;
  malformed: boolean;
} {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_STAMP_BYTES) {
    return { stamp: null, commit: null, malformed: true };
  }
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    return { stamp: null, commit: null, malformed: true };
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return { stamp: null, commit: null, malformed: true };
  }
  const stamp = parseReleaseStamp(raw);
  if (stamp) return { stamp, commit: null, malformed: false };
  // Not a release. A commit is still an identity, and the same one a
  // fleet-deployed host has, so it is normalised through the same parser.
  const commit = parseDeployRef((obj as Record<string, unknown>).commit as string | undefined);
  return { stamp: null, commit, malformed: false };
}

/** The stamp and the ref, resolved to one identity. Pure, so the precedence
 *  is a test rather than a deploy. */
export function identityFrom(
  stamp: ReleaseStamp | null,
  deployRef: string | null,
): ReleaseIdentity {
  if (stamp) {
    return {
      kind: 'release',
      tag: stamp.tag,
      commit: stamp.commit,
      sha256: stamp.sha256,
      published_at: stamp.published_at,
      source_url: stamp.source_url,
      installed_at: stamp.installed_at,
    };
  }
  if (deployRef) return { kind: 'deploy_ref', sha: deployRef };
  return { kind: 'unknown' };
}

/** Strips the host-only field. One function, so a future member added to
 *  the local identity has to be published deliberately rather than by
 *  spread. */
export function identityForWire(id: ReleaseIdentity): ReleaseIdentityWire {
  if (id.kind === 'release') {
    const { tag, commit, sha256, published_at } = id;
    return { kind: 'release', tag, commit, sha256, published_at };
  }
  if (id.kind === 'deploy_ref') return { kind: 'deploy_ref', sha: id.sha };
  return { kind: 'unknown' };
}

/** A peer's `release` member, checked before it is graded. Anything that is
 *  not one of the three shapes is `unknown`, which is the one reading that
 *  can never be wrong about a peer this process cannot see. */
export function parseIdentityWire(v: unknown): ReleaseIdentityWire {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return { kind: 'unknown' };
  const o = v as Record<string, unknown>;
  if (o.kind === 'release') {
    const tag = str(o.tag), commit = str(o.commit), sha256 = str(o.sha256), published = str(o.published_at);
    if (!tag || !commit || !sha256 || !published || !SHA256_SHAPE.test(sha256)) return { kind: 'unknown' };
    return { kind: 'release', tag, commit, sha256: sha256.toLowerCase(), published_at: published };
  }
  if (o.kind === 'deploy_ref') {
    const sha = parseDeployRef(typeof o.sha === 'string' ? o.sha : null);
    return sha ? { kind: 'deploy_ref', sha } : { kind: 'unknown' };
  }
  return { kind: 'unknown' };
}

/** The words the page and the fleet view use for an identity. One
 *  derivation, so a host describing itself and an aggregator describing that
 *  host cannot say two different things. */
export function describeIdentity(id: ReleaseIdentityWire | ReleaseIdentity): string {
  // The operator's words, not the system's (2026-09-09: "deployed from
  // 4182c53b65, not a published release" read as a warning and meant
  // nothing to them). Three readings, each saying where the code came from.
  if (id.kind === 'release') {
    const when = 'installed_at' in id && id.installed_at ? `, installed ${String(id.installed_at).slice(0, 10)}` : '';
    return `${id.tag} (commit ${id.commit})${when}`;
  }
  if (id.kind === 'deploy_ref') return `commit ${id.sha.slice(0, 7)}, by a fleet update (no release name)`;
  return 'unknown (this install predates release stamps)';
}

export interface ReleaseIdentityReader {
  /** The identity as of at most `ttlMs` ago, re-reading both files when that
   *  has elapsed. */
  current(): ReleaseIdentity;
}

export interface ReleaseIdentityReaderOptions {
  releasePath: string;
  deployRefPath: string;
  /** How long a read is trusted before the files are looked at again.
   *  Default 60s, matching the deploy-ref reader. */
  ttlMs?: number;
  now?: () => number;
  readFile: (path: string) => string;
  /** One line per distinct failure, for the journal. Never called for a
   *  missing file: not having a stamp is not a fault. */
  onError?: (message: string) => void;
}

/**
 * A reader that re-reads on demand rather than at boot.
 *
 * A TTL and not a value cached for the life of the process, because an apply
 * deliberately does not restart anything (ADR 0022 decision 3): between the
 * swap and the operator pressing restart, `.release` on disk names the new
 * release while this process is still the old one. A boot-time read would go
 * quietly wrong in exactly the window the feature creates.
 */
export function createReleaseIdentityReader(
  opts: ReleaseIdentityReaderOptions,
): ReleaseIdentityReader {
  const ttlMs = opts.ttlMs ?? 60_000;
  const now = opts.now ?? Date.now;
  const reported = new Set<string>();
  let value: ReleaseIdentity = UNKNOWN_IDENTITY;
  let readAt = 0;
  let everRead = false;

  const read = (path: string, what: string): string | null => {
    try {
      return opts.readFile(path);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException)?.code ?? 'UNKNOWN';
      // ENOENT and everything else are the same on the wire (no claim either
      // way) and different in the journal. A host that HAS a stamp and
      // cannot read its own file is an operator-fixable fault; reading as
      // absence is #113's shape.
      const key = `${what}:${code}`;
      if (code !== 'ENOENT' && !reported.has(key)) {
        reported.add(key);
        opts.onError?.(`cannot read ${path} (${code}) — this host reports no release until that is fixed`);
      }
      return null;
    }
  };

  const reread = (): void => {
    readAt = now();
    everRead = true;
    const rawStamp = read(opts.releasePath, 'release');
    if (rawStamp !== null) {
      const file = readReleaseFile(rawStamp);
      if (file.malformed && !reported.has('release:SHAPE')) {
        reported.add('release:SHAPE');
        opts.onError?.(`${opts.releasePath} is not a release stamp — this host reports its release as unknown`);
      }
      // Whatever it turned out to be, the deploy ref is not consulted: this
      // file exists, so the bootstrap has been here and removed the other
      // one. A stamp naming nothing is a host saying it was not installed
      // from a published release, which is an answer, not a gap.
      value = identityFrom(file.stamp, file.commit);
      return;
    }
    const rawRef = read(opts.deployRefPath, 'deploy-ref');
    value = identityFrom(null, parseDeployRef(rawRef));
  };

  return {
    current(): ReleaseIdentity {
      if (!everRead || now() - readAt >= ttlMs) reread();
      return value;
    },
  };
}
