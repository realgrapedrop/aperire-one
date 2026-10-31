/**
 * Is a newer Aperire release published? ADR 0022 decision 2, phase 1.
 *
 * Two files are fetched from the release endpoint and both are required:
 *
 *   - `release.json`  — `{ tag, commit, sha256, published_at }`, the only
 *     file that names a RELEASE. A publisher could edit it by hand.
 *   - `release.tar.gz.sha256` — `sha256sum release.tar.gz` output, written by
 *     a machine beside the archive. It names bytes, not a release: no tag, no
 *     commit, no date.
 *
 * They have to agree on the sum. A disagreement is `mid_publish` and never an
 * update: the publish ordering renames the archive, then its sum, then the
 * bootstrap, then `release.json` last, so a fetch that lands mid-rename sees
 * a `release.json` describing an archive that is not there yet. Offering that
 * as an update means offering one the apply would refuse.
 *
 * Neither of those two is believed for anything but WHICH archive (#761).
 * What that archive is (its tag, commit, date and notes) is read from the
 * signed document for it, `release-<sha256>.json`, fetched under the name
 * that never changes with its `.sig` beside it, and only after the signature
 * verifies against the signer set this host trusts. The same order root's
 * updater follows (scripts/aperire-update.sh, verify_published), and for the
 * same reason: a publish renames release.json and its signature one after
 * the other, so a machine never pairs those two. A release that is not
 * signed, or not signed by a key this host trusts, shows nothing from the
 * file at all: no "behind", no metric, no notes.
 *
 * Everything here is pure over an injected fetch. The module makes no
 * decision about WHEN to ask (the server owns the click and the daily timer)
 * and writes nothing.
 *
 * **This is a phone-home and it is treated as one.** The upstream rippled
 * poll reads two public lists and tells them nothing; a request to
 * get.aperire.one tells my own endpoint this host's IP and that it runs
 * Aperire. So it gets its own switch, `APERIRE_UPDATE_CHECK=off`, and its own
 * metric, `update_available`. One metric cannot mean two things: a rule
 * written for "the node is behind" would fire for "Aperire is behind" and the
 * alert text would be wrong.
 *
 * Comparison is EQUALITY of the sha256, never an ordering. Releases here are
 * not version-numbered against each other: the feature does not downgrade and
 * does not let anyone pin a chosen version, so "is what the endpoint publishes
 * the thing I have" is the whole question. Same rule `deploy-ref.ts` states
 * for refs: compared for equality, never parsed, never ordered.
 */
import type { ReleaseIdentity, ReleaseIdentityWire } from './release-stamp.js';
import type { ReleaseVerifier } from './release-signature.js';

/** Where a host asks when its stamp does not say. */
export const DEFAULT_UPDATE_ENDPOINT = 'https://get.aperire.one';

/**
 * Five readings, and the last three are all "no verdict" for different
 * reasons the page has different words for.
 *
 *   `current`     — the endpoint publishes what this host has installed.
 *   `behind`      — it publishes something else, and this host knows what it
 *                   is running. Never derived from an ordering.
 *   `unknown`     — the endpoint answered and this host cannot say what it
 *                   is running (no stamp, or a deploy ref). Never current,
 *                   never behind: ADR 0022 decision 2 in both directions.
 *   `mid_publish` — the two files disagree on the sum. Try again in a minute.
 *   `unreachable` — no answer, a malformed answer, a release refused on its
 *                   signature, a signed release published no later than the
 *                   one this host runs (a replay), or checks are switched off.
 *                   `reason` tells those apart without inventing a sixth
 *                   state: a new state would fall through every switch that
 *                   already reads these five (#268), and each of these offers
 *                   nothing to apply.
 */
export type UpdateState = 'current' | 'behind' | 'unknown' | 'mid_publish' | 'unreachable';

/** Why a non-verdict is a non-verdict. Kept out of `state` because the page
 *  phrases from the state and only annotates from this. */
export type UpdateReason =
  | 'disabled'            // APERIRE_UPDATE_CHECK=off, nothing left this box
  | 'network'             // no answer, a timeout, or an HTTP error
  | 'endpoint_malformed'  // an answer that is not a release.json or not a sum
  | 'sum_disagreement'    // the two files name different archives
  | 'no_identity'         // this host has no stamp to compare with
  // The endpoint answered and its release is not shown (#761, #760). Never
  // "could not reach": it did answer, with something nobody can show was
  // signed by the release key.
  | 'signature_missing'   // no signed release-<sha>.json or no .sig beside it
  | 'signature_refused'   // a signature that does not verify against this host's key set
  | 'signature_unchecked' // this host cannot check one: no key set, or no ssh-keygen
  // The endpoint answered with a validly signed release that was published no
  // later than the one this host runs (#1073). A replay, not a newer release
  // and not a silence: root's `check` refuses it the same way
  // (`published_older=yes`) and an apply of it exits 7. Never "could not
  // reach", and never "behind".
  | 'published_older';

/**
 * What a release brings, in the words the changelog already used.
 *
 * Written by the publisher out of the changelog diff between the previous
 * published snapshot and this one, grouped by the heading each line was
 * added under. It is DISPLAY TEXT and nothing else: the page prints it, and
 * every decision about a release is still made from the tag, the commit and
 * the sha256 above it. A publisher who wrote nonsense here changes what an
 * operator reads and nothing a host does.
 *
 * Absent when the endpoint published none, which is the normal answer for
 * the first release ever and for a republish nobody wrote a changelog line
 * for. Absent and empty are the same reading here and both are `undefined`:
 * a member that is always present has broken someone's deepEqual on this
 * payload before.
 */
export interface UpdateNotes {
  added: string[];
  changed: string[];
  fixed: string[];
  security: string[];
  removed: string[];
  /** How many lines the publisher cut for space. A list that quietly
   *  stopped at eight would read as a complete one. */
  more: number;
  /** The release these were measured against. */
  since: string | null;
}

/** What the endpoint currently publishes. */
export interface UpdateLatest {
  tag: string;
  commit: string;
  sha256: string;
  published_at: string;
  notes?: UpdateNotes;
  /** Where this release's changelog is, when the publisher knows the tag is
   *  on the public repository (#299). DISPLAY ONLY, like the notes: the page
   *  prints a link from it and only after checking it against the one
   *  public address it knows. Absent is the normal answer, and the page
   *  then links the file on the default branch. */
  changelog_url?: string;
}

export interface UpdateCheckResult {
  state: UpdateState;
  /** What the endpoint published, when it answered with something whole.
   *  Present on `current`, `behind` and `unknown` — an unknown host still
   *  gets to see what the current release IS, it just gets no verdict about
   *  itself. Null on the three no-answer paths. */
  latest: UpdateLatest | null;
  reason: UpdateReason | null;
  /** When this answer was produced. Not when the release was published. */
  checked_at: number;
  endpoint: string;
}

const SHA256_SHAPE = /^[0-9a-f]{64}$/i;
const TOKEN_SHAPE = /^[\x21-\x7e]{1,128}$/;
/** Neither file is large. A body past this is not the file that was asked
 *  for, and reading it into memory is the wrong way to find that out. */
const MAX_BODY_BYTES = 64 * 1024;

/** `APERIRE_UPDATE_CHECK=off` disables every outbound call this module makes.
 *  Its own switch, deliberately not `APERIRE_RELEASE_CHECK`: that one governs
 *  reading two public lists about rippled, which tells nobody anything. */
export function updateChecksEnabled(value: string | undefined): boolean {
  return (value ?? '').trim().toLowerCase() !== 'off';
}

/**
 * Which endpoint to ask, in precedence order:
 *
 *   1. `APERIRE_UPDATE_ENDPOINT`, for a test rig and for a host pointed at a
 *      mirror by its operator.
 *   2. The `source_url` in this host's own stamp, with the file name
 *      stripped, so a host installed from a mirror asks that mirror.
 *   3. `https://get.aperire.one`.
 *
 * The stamp is https only. It is writable by the account this process runs
 * as, so following a plain-http URL out of it would hand the one integrity
 * this phase has to whoever could write that file. The environment variable
 * is allowed http as well, because it is set by whoever writes the unit
 * file and a loopback test rig has no certificate.
 */
export function updateEndpoint(opts: { env?: string | null; sourceUrl?: string | null }): string {
  // The env override may be plain http and the stamp may not. They are not
  // the same kind of input: the environment is set by whoever writes the
  // unit file, which is root, while `.release` is written by the account this
  // process runs as. A rig standing in for get.aperire.one on loopback needs
  // http; a stamp asking for it is a downgrade nobody chose.
  const fromEnv = normaliseEndpoint(opts.env, { allowHttp: true });
  if (fromEnv) return fromEnv;
  const fromStamp = normaliseEndpoint(opts.sourceUrl);
  if (fromStamp) return fromStamp;
  return DEFAULT_UPDATE_ENDPOINT;
}

/** A URL to the directory the release files sit in: the file name stripped,
 *  no trailing slash, query and fragment discarded. */
function normaliseEndpoint(
  raw: string | null | undefined,
  opts: { allowHttp?: boolean } = {},
): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  const ok = u.protocol === 'https:' || (opts.allowHttp === true && u.protocol === 'http:');
  if (!ok) return null;
  // `/release.tar.gz` -> ``; `/snapshots/release.tar.gz` -> `/snapshots`;
  // `/` and `` -> ``. A path already naming a directory keeps every segment.
  const segs = u.pathname.split('/').filter(Boolean);
  if (segs.length && segs[segs.length - 1].includes('.')) segs.pop();
  const path = segs.length ? `/${segs.join('/')}` : '';
  return `${u.protocol}//${u.host}${path}`;
}

/** The five headings a changelog entry can sit under, in the order a card
 *  reads them: what is new first, then what was repaired, then what moved. */
const NOTE_GROUPS = ['added', 'fixed', 'changed', 'security', 'removed'] as const;
/** Bounds on text nobody here wrote. The publisher already cuts at 140 and
 *  eight to a group; these are the bounds this end enforces anyway, because
 *  the file comes off the network. */
const MAX_NOTE_CHARS = 240;
const MAX_NOTES_PER_GROUP = 40;

/**
 * The optional `notes` member, and it is optional in both directions: a
 * release.json without one is whole, and a release.json with a broken one is
 * still whole. Bad notes drop the notes, NEVER the release — turning a
 * publisher's typo into `endpoint_malformed` would stop the update check on
 * every host in the fleet over a line of prose.
 */
function parseNotes(value: unknown): UpdateNotes | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const out: UpdateNotes = { added: [], changed: [], fixed: [], security: [], removed: [], more: 0, since: null };
  let any = false;
  for (const group of NOTE_GROUPS) {
    const raw = o[group];
    if (!Array.isArray(raw)) continue;
    for (const item of raw.slice(0, MAX_NOTES_PER_GROUP)) {
      if (typeof item !== 'string') continue;
      // Control characters out rather than the whole line dropped: what
      // arrives is prose, and a stray tab is not a reason to lose a note.
      // eslint-disable-next-line no-control-regex
      const text = item.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, MAX_NOTE_CHARS);
      if (text === '') continue;
      out[group].push(text);
      any = true;
    }
  }
  if (!any) return null;
  const more = typeof o.more === 'number' && Number.isFinite(o.more) && o.more > 0
    ? Math.min(Math.floor(o.more), 9999) : 0;
  out.more = more;
  out.since = typeof o.since === 'string' && TOKEN_SHAPE.test(o.since.trim()) ? o.since.trim() : null;
  return out;
}

/** `release.json`, checked before it is believed. Same field rules as the
 *  local stamp: a half-written release is not a release. */
export function parseReleaseJson(raw: string | null | undefined): UpdateLatest | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_BODY_BYTES) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    return null;
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const o = obj as Record<string, unknown>;
  const s = (v: unknown) => (typeof v === 'string' && TOKEN_SHAPE.test(v.trim()) ? v.trim() : null);
  const tag = s(o.tag), commit = s(o.commit), sha256 = s(o.sha256), published = s(o.published_at);
  if (!tag || !commit || !sha256 || !published) return null;
  if (!SHA256_SHAPE.test(sha256)) return null;
  if (!Number.isFinite(Date.parse(published))) return null;
  const out: UpdateLatest = { tag, commit, sha256: sha256.toLowerCase(), published_at: published };
  const notes = parseNotes(o.notes);
  if (notes) out.notes = notes;
  // Like the notes, a bad link drops the link and never the release.
  const cl = typeof o.changelog_url === 'string' ? o.changelog_url.trim() : '';
  if (cl.length > 0 && cl.length <= 300 && /^https:\/\/[^\s"'<>\\]+$/.test(cl)) out.changelog_url = cl;
  return out;
}

/** The first field of `sha256sum release.tar.gz`. The second field is the
 *  served name and is not checked: a publisher who renames the archive has
 *  broken more than this check, and refusing on it would turn a working
 *  endpoint into a permanent "try again in a minute". */
export function parseSumFile(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_BODY_BYTES) return null;
  const first = raw.split('\n', 1)[0].trim();
  const token = first.split(/\s+/, 1)[0];
  return SHA256_SHAPE.test(token) ? token.toLowerCase() : null;
}

/**
 * Where this host sits against a release the endpoint published.
 *
 * The only comparison in the feature, and it is equality. A host that cannot
 * name its own release is `unknown` at both ends: not current (it may be old)
 * and not behind (nobody measured that), which is the reading a nag must
 * never be built on.
 */
export function gradeAgainstLatest(
  identity: ReleaseIdentity | ReleaseIdentityWire | null | undefined,
  latest: UpdateLatest | null,
): 'current' | 'behind' | 'unknown' {
  if (!latest || !identity) return 'unknown';
  if (identity.kind === 'release') {
    // The sum says the same archive; the commit says the same code. Two
    // archives of one commit differ only by their tar timestamps (a lab
    // build of the commit the endpoint went on to publish, 2026-09-10), and
    // a host on the published commit is current whichever bytes it came
    // from.
    if (identity.sha256.toLowerCase() === latest.sha256.toLowerCase()) return 'current';
    return sameCommit(identity.commit, latest.commit) ? 'current' : 'behind';
  }
  // A deploy ref names a commit, and release.json names the commit the
  // archive was built from. The same commit is the same code, so that host
  // is current, and the first live check (the lab aggregator, 2026-09-08) had exactly
  // this: deployed from the commit the endpoint had just published and
  // passing no verdict. A DIFFERENT commit stays unknown: a fleet tool can
  // deploy a commit newer than any release, and "behind" would be a lie.
  if (identity.kind === 'deploy_ref') {
    return sameCommit(identity.sha, latest.commit) ? 'current' : 'unknown';
  }
  return 'unknown';
}

/** Two git commit ids name the same commit when one is a prefix of the
 *  other, and the shorter is long enough to mean anything (7 hex, git's own
 *  floor for an abbreviation). */
export function sameCommit(a: string, b: string): boolean {
  const x = a.trim().toLowerCase(), y = b.trim().toLowerCase();
  if (!/^[0-9a-f]{7,40}$/.test(x) || !/^[0-9a-f]{7,40}$/.test(y)) return false;
  return x.startsWith(y) || y.startsWith(x);
}

// ── The floor an update never goes below (#1073) ─────────────────────────
//
// A replayed older release is still a validly signed one, so its signature
// cannot tell it from a newer one. Its publish date can, and root's `check`
// and its apply both refuse a release published no later than the newest this
// host has: the later of the release it runs (the kept, signed copy) and the
// high-water mark the bootstrap keeps beside the store (scripts/aperire-update.sh,
// floor_published_at). The page applies the same floor, so the daily metric,
// the fleet table and the card can no longer be flipped to "behind" by an
// endpoint replaying an old signed release.
//
// What this process can read of root's floor is this host's own stamp (the
// release it runs, which the kept copy is the signed twin of) and the
// high-water file when the account can read it. Both are dates the bootstrap
// wrote from a signed release.json; neither is the endpoint's say.

/** The shape root accepts for a floor date: one UTC second-resolution stamp,
 *  and nothing else. A floor read from anywhere is held to it. */
const FLOOR_DATE_SHAPE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** A floor date as a number, or null when it is not one root would accept. */
function floorMs(v: string | null | undefined): number | null {
  if (typeof v !== 'string' || !FLOOR_DATE_SHAPE.test(v)) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * The date a release on offer has to be newer than: the later of the release
 * this host runs and the high-water mark. Null when neither is known (a host
 * installed before signed releases, or from a clone), and then nothing is
 * refused on its date, exactly as root does.
 *
 * The identity is read for its own `published_at` only when it is a release
 * stamp; a deploy ref and an unknown host carry none.
 */
export function releaseFloor(
  identity: ReleaseIdentity | ReleaseIdentityWire | null | undefined,
  highWaterAt?: string | null,
): string | null {
  const own = identity && identity.kind === 'release' ? identity.published_at : null;
  const a = floorMs(own), b = floorMs(highWaterAt);
  if (a === null && b === null) return null;
  if (a === null) return highWaterAt as string;
  if (b === null) return own as string;
  return b > a ? (highWaterAt as string) : (own as string);
}

/**
 * `gradeAgainstLatest`, with the floor applied the way root applies it: the
 * same archive or commit is current first, then a release published no later
 * than the floor is `older` (a replay, nothing to do), and only then is a
 * different archive `behind`.
 *
 * `older` is not a member of `UpdateState`. A caller turns it into the
 * reading that fits its surface: the page's own check reports it as
 * `unreachable` with reason `published_older`, and the fleet table gives the
 * row its own word.
 */
export function gradeWithFloor(
  identity: ReleaseIdentity | ReleaseIdentityWire | null | undefined,
  latest: UpdateLatest | null,
  floorAt: string | null,
): 'current' | 'behind' | 'unknown' | 'older' {
  const g = gradeAgainstLatest(identity, latest);
  if (g !== 'behind' || !latest) return g;
  const floor = floorMs(floorAt);
  // A release whose own date cannot be read is not judged on it: root would
  // not have offered it either, and the page does not invent a verdict.
  const at = Date.parse(latest.published_at);
  if (floor === null || !Number.isFinite(at)) return g;
  return at > floor ? 'behind' : 'older';
}

/**
 * The release the PEERS in the Updates card's fleet table are graded against:
 * the one this process's own reading of the endpoint named, and nothing older.
 *
 * The card used to grade the fleet against the last answer this process ever
 * got, whatever its latest reading said. An endpoint that stopped answering
 * (or whose answer was not shown) therefore printed "The endpoint did not
 * answer" beside "4 nodes behind", the count coming from a release the check
 * had just stopped naming, possibly one a stand-in endpoint served days
 * before (#863). A kept reading is not an observation: with no release in
 * this reading there is nothing to compare, and the count is unknown rather
 * than a number.
 *
 * `own` is this process's reading, never the updater's: a peer is not graded
 * by this host's update.conf (#293), which is why the caller hands in `result`
 * and not the reading the facts grid shows.
 *
 * The one exception is the replay (`published_older`, #1073). The endpoint
 * DID answer, with a signed release no newer than what this host runs, and
 * the fleet keeps grading against the last real release from that same
 * endpoint so a replayed old file cannot flip every row. Keyed on the
 * reason, never on the words the page prints, and on the endpoint, so a
 * reading kept from a different one (a lab stand-in) is not borrowed.
 */
export function fleetGradingReading(
  own: Pick<UpdateCheckResult, 'latest' | 'reason' | 'endpoint'> | null | undefined,
  kept: Pick<UpdateCheckResult, 'latest' | 'endpoint'> | null | undefined,
): UpdateLatest | null {
  if (!own) return null;
  if (own.latest) return own.latest;
  if (own.reason === 'published_older' && kept?.latest && kept.endpoint === own.endpoint) return kept.latest;
  return null;
}

export interface UpdateCheckOptions {
  /** Injected, always. Production passes the global fetch. */
  fetchImpl: typeof fetch;
  endpoint: string;
  identity: ReleaseIdentity | ReleaseIdentityWire | null;
  /** Checks the signed release.json against the keys this host trusts.
   *  Absent means nothing can be checked, so nothing is believed: every
   *  answer is `signature_unchecked`. */
  verify?: ReleaseVerifier;
  /** The high-water mark root keeps beside the release store, when this
   *  account can read it. Part of the floor (#1073); absent means the floor
   *  is the stamp's own date alone. */
  highWaterAt?: string | null;
  /** False when `APERIRE_UPDATE_CHECK=off`. Checked HERE rather than at the
   *  call sites, so there is one place a switched-off host can be proven to
   *  make no outbound call. */
  enabled?: boolean;
  now?: () => number;
  timeoutMs?: number;
}

/**
 * One check: two fetches, one cross-check, one comparison.
 *
 * Both files are fetched together. They are two small objects from the same
 * origin, and asking for them in series would double the window in which a
 * publish can land between them, which is the exact race the cross-check
 * exists to catch.
 */
export async function checkForUpdate(opts: UpdateCheckOptions): Promise<UpdateCheckResult> {
  const now = opts.now ?? Date.now;
  const base = { latest: null, checked_at: now(), endpoint: opts.endpoint } as const;

  if (opts.enabled === false) {
    // Nothing leaves the box. Reported as unreachable with a reason rather
    // than as a sixth state: the page says checks are switched off, and no
    // nag either way.
    return { ...base, state: 'unreachable', reason: 'disabled', checked_at: now() };
  }

  // Three outcomes per file, not two: a file the endpoint says it does not
  // have (404, 410) is a fact about the release, while a fetch that failed
  // is a fact about the network. Only the signed pair tells them apart; for
  // the first two files either one is "could not reach", as before.
  type Got = { kind: 'ok'; body: Buffer } | { kind: 'missing' } | { kind: 'failed' };
  const get = async (name: string): Promise<Got> => {
    try {
      const r = await opts.fetchImpl(`${opts.endpoint}/${name}`, {
        // undici will not cancel an outbound fetch on its own, so the
        // deadline is explicit or a hung endpoint holds this forever.
        signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
        headers: { accept: '*/*' },
        redirect: 'follow',
      });
      if (!r.ok) return r.status === 404 || r.status === 410 ? { kind: 'missing' } : { kind: 'failed' };
      // Bytes, not text: the signed file is checked as it was signed, and a
      // decode and re-encode is not guaranteed to give the same bytes back.
      const body = Buffer.from(await r.arrayBuffer());
      return body.length > MAX_BODY_BYTES ? { kind: 'failed' } : { kind: 'ok', body };
    } catch {
      return { kind: 'failed' };
    }
  };
  const text = (g: Got): string | null => (g.kind === 'ok' ? g.body.toString('utf8') : null);

  const [jsonGot, sumGot] = await Promise.all([get('release.json'), get('release.tar.gz.sha256')]);
  const jsonRaw = text(jsonGot), sumRaw = text(sumGot);

  if (jsonRaw === null || sumRaw === null) {
    return { ...base, state: 'unreachable', reason: 'network', checked_at: now() };
  }

  // Read for the sum only. Every other field in this file is unsigned.
  const pointer = parseReleaseJson(jsonRaw);
  const sum = parseSumFile(sumRaw);
  if (!pointer || !sum) {
    // A body that is not the file that was asked for. Deliberately NOT
    // mid_publish: "try again in a minute" is false for a file that is
    // permanently broken, and a publisher who left one that way should see a
    // reading that does not resolve itself.
    return { ...base, state: 'unreachable', reason: 'endpoint_malformed', checked_at: now() };
  }

  if (pointer.sha256 !== sum) {
    // The one file a publisher could edit by hand disagrees with the one a
    // machine wrote. Never an update.
    return { ...base, state: 'mid_publish', reason: 'sum_disagreement', checked_at: now() };
  }

  // The signed document for that archive, under the names that never change.
  const [signedGot, sigGot] = await Promise.all([
    get(`release-${pointer.sha256}.json`), get(`release-${pointer.sha256}.json.sig`),
  ]);
  if (signedGot.kind === 'failed' || sigGot.kind === 'failed') {
    return { ...base, state: 'unreachable', reason: 'network', checked_at: now() };
  }
  if (signedGot.kind === 'missing' || sigGot.kind === 'missing') {
    return { ...base, state: 'unreachable', reason: 'signature_missing', checked_at: now() };
  }
  if (!opts.verify) {
    return { ...base, state: 'unreachable', reason: 'signature_unchecked', checked_at: now() };
  }
  const v = await opts.verify(signedGot.body, sigGot.body);
  if (v.verdict !== 'ok') {
    return {
      ...base, state: 'unreachable', checked_at: now(),
      reason: v.verdict === 'unchecked' ? 'signature_unchecked' : 'signature_refused',
    };
  }
  // Verified first, then read, from the same bytes.
  const latest = parseReleaseJson(signedGot.body.toString('utf8'));
  if (!latest) {
    return { ...base, state: 'unreachable', reason: 'endpoint_malformed', checked_at: now() };
  }
  if (latest.sha256 !== pointer.sha256) {
    // Signed, and for a different archive than the one release.json points
    // at. Root refuses this in the same words; so does this.
    return { ...base, state: 'unreachable', reason: 'signature_refused', checked_at: now() };
  }

  const verdict = gradeWithFloor(opts.identity, latest, releaseFloor(opts.identity, opts.highWaterAt));
  if (verdict === 'older') {
    // Signed, whole, and published no later than what this host already
    // runs: a replay. Reported the way root reports it, as a release that
    // offers nothing, with no `latest` so no surface names it as the release
    // to be on (the metric writes nothing, nothing is stored, no notes are
    // carried) and the fleet keeps grading against the last real answer.
    return { ...base, state: 'unreachable', reason: 'published_older', checked_at: now() };
  }
  return {
    state: verdict,
    latest,
    reason: verdict === 'unknown' ? 'no_identity' : null,
    checked_at: now(),
    endpoint: opts.endpoint,
  };
}

/** The one reading that goes to the metric, and only when there is one.
 *  `unknown`, `mid_publish` and `unreachable` write NOTHING: a 0 there is a
 *  measurement nobody made, and the alert built on it would resolve on
 *  evidence that was never collected. */
export function updateAvailableMetric(state: UpdateState): 0 | 1 | null {
  if (state === 'current') return 0;
  if (state === 'behind') return 1;
  return null;
}

// ── What the updater on this host says ───────────────────────────────────
//
// A host with the update grant (ADR 0022 phase 2) has a root program that
// reads its own endpoint out of /etc/aperire/update.conf, which this account
// cannot read or write. That endpoint is the one an apply would install
// from, and it is not always the one this process asks: an operator can
// point a host at a mirror, and a lab stand-in has pointed one at loopback
// (#293). Two readings of "what is published" on one card is how a page ends
// up offering a release its own host would refuse.
//
// So where there is an updater, its answer is the one the card grades from,
// and this dashboard's own fetch is kept only to notice that the two
// disagree. The metric and the fleet table stay on the dashboard's own
// fetch: the daily reading is about this process, and a peer is not graded
// by this host's updater.

/** The check verb's answer, as facts off the wire. Every field optional:
 *  an older program on a host mid-update publishes fewer of them, and a
 *  missing field is a reading nobody took rather than a zero. */
export interface UpdaterReading {
  /** Where root fetches from. Absent on a program older than this one. */
  endpoint: string | null;
  /** What that endpoint publishes, when root got a whole answer out of it. */
  latest: UpdateLatest | null;
  /** What root read out of this host's stamp. */
  installed: { tag: string; commit: string; sha256: string } | null;
  /** Root's own word for where this host stands. */
  verdict: 'current' | 'behind' | 'mid_publish' | 'unreachable' | null;
  /** `refused` when root's `unreachable` is a release it refused on its
   *  signature (`signature=refused`, #736), which is not a network fault and
   *  must not be said as one (#760). Present only then: absent on every
   *  other reading and on an older program, so a payload nobody refused
   *  reads exactly as it did. */
  signature?: 'refused';
  /** True when root's `unreachable` is a validly signed release published no
   *  later than what this host already has (`published_older=yes`, the floor
   *  check, #1073). The endpoint answered; the card says it is serving an
   *  older release than this host has, not that it did not answer. Present
   *  only then, for the same reason `signature` is. */
  publishedOlder?: true;
}

const UPDATER_VERDICTS = ['current', 'behind', 'mid_publish', 'unreachable'] as const;

/** One `key=value` fact, checked before it is believed. Everything here came
 *  off a socket, and the same field rules apply as to a release.json. */
function fact(facts: Record<string, string>, name: string): string | null {
  const v = facts[name];
  return typeof v === 'string' && v.trim() !== '' && TOKEN_SHAPE.test(v.trim()) ? v.trim() : null;
}

export function readUpdaterCheck(facts: Record<string, string> | null | undefined): UpdaterReading | null {
  if (!facts || typeof facts !== 'object') return null;
  const verdictRaw = fact(facts, 'verdict');
  const verdict = verdictRaw && (UPDATER_VERDICTS as readonly string[]).includes(verdictRaw)
    ? verdictRaw as UpdaterReading['verdict'] : null;
  const endpointRaw = fact(facts, 'endpoint');
  // http is allowed here and nowhere else in this file: the value came from
  // a root-owned file that this account cannot write, and a mirror on a
  // private network is a thing an operator may legitimately run.
  const endpoint = endpointRaw && /^https?:\/\/[^\s"\\]+$/.test(endpointRaw) ? endpointRaw : null;
  const tag = fact(facts, 'published_tag');
  const commit = fact(facts, 'published_commit');
  const sha256 = fact(facts, 'published_sha256');
  // The publish date gets the same check release.json's does: it is printed
  // as a day on the card, and a value nothing could parse would be rendered
  // as one. Absent rather than wrong — the release is still whole without it.
  const at = fact(facts, 'published_at');
  const published_at = at && Number.isFinite(Date.parse(at)) ? at : '';
  // Root names what the endpoint publishes from the UNSIGNED release.json
  // before it reaches its signature check, and on mid_publish it stops there
  // (scripts/aperire-update.sh, verb_check). Those facts are a tag the
  // endpoint chose, so they name no release here: not on the card, not in a
  // disagreement or a lag sentence, not in a peer's state. Every verdict root
  // reaches past its check is read as before, published_older included.
  const latest: UpdateLatest | null = verdict !== 'mid_publish'
    && tag && commit && sha256 && SHA256_SHAPE.test(sha256)
    ? { tag, commit, sha256: sha256.toLowerCase(), published_at }
    : null;
  const iTag = fact(facts, 'installed_tag');
  const iCommit = fact(facts, 'installed_commit');
  const iSha = fact(facts, 'installed_sha256');
  const installed = iSha && SHA256_SHAPE.test(iSha)
    ? { tag: iTag ?? '', commit: iCommit ?? '', sha256: iSha.toLowerCase() }
    : null;
  const refused = fact(facts, 'signature') === 'refused';
  const older = fact(facts, 'published_older') === 'yes';
  if (!verdict && !endpoint && !latest && !installed) return null;
  return {
    endpoint, latest, installed, verdict,
    ...(refused ? { signature: 'refused' as const } : {}),
    ...(older ? { publishedOlder: true as const } : {}),
  };
}

/**
 * The card's answer, taken from the updater's.
 *
 * `null` means this reading says nothing the card can grade from, and the
 * caller falls back to the dashboard's own fetch — a program too old to
 * report an endpoint, a probe that collided with a run, a socket that
 * answered nothing. Absent is not a verdict.
 *
 * The comparison is this file's own, not root's: root compares two sha256s
 * and stops, while `gradeAgainstLatest` also reads two builds of one commit
 * as the same code. Root's WORD is taken for the readings that are not a
 * comparison at all (an endpoint that did not answer, one mid-publish),
 * because only root knows what happened when it asked.
 */
export function gradeFromUpdater(
  reading: UpdaterReading | null,
  identity: ReleaseIdentity | ReleaseIdentityWire | null,
  now: () => number = Date.now,
  /** False when this host cannot check a signature at all: root's key set
   *  (the constant path) is missing or not a set, or this process's own
   *  verifier said `signature_unchecked`. Root says `signature=refused` for
   *  those too, and that refusal is the host's, not the endpoint's. */
  hostCanCheck = true,
  /** The high-water mark, when this account can read it (#1073). */
  highWaterAt: string | null = null,
): UpdateCheckResult | null {
  if (!reading || !reading.verdict || !reading.endpoint) return null;
  const base = { checked_at: now(), endpoint: reading.endpoint };
  if (reading.verdict === 'unreachable') {
    // Root refused a signed release for its date, not for its signature and
    // not for lack of an answer (`published_older=yes`). The endpoint
    // answered, with an older release than this host has.
    if (reading.publishedOlder) {
      return { ...base, state: 'unreachable', latest: null, reason: 'published_older' };
    }
    // Root answers `unreachable` for a release it refused on its signature,
    // on purpose (the one reading that offers nothing to apply), and says
    // which in a fact of its own. The card says which too, and whose fault:
    // a host with no key or no ssh-keygen refuses every release, and telling
    // its operator not to install from the endpoint blames the wrong party.
    const reason: UpdateReason = reading.signature !== 'refused' ? 'network'
      : hostCanCheck ? 'signature_refused' : 'signature_unchecked';
    return { ...base, state: 'unreachable', latest: null, reason };
  }
  if (reading.verdict === 'mid_publish') {
    return { ...base, state: 'mid_publish', reason: 'sum_disagreement', latest: null };
  }
  if (!reading.latest) return null;
  // Root's own stamp reading is preferred over this process's: they read the
  // same file, and root read it now while this one holds a read for up to a
  // minute — which is exactly the window an apply creates.
  const from: ReleaseIdentity | ReleaseIdentityWire | null = reading.installed
    ? {
      kind: 'release', tag: reading.installed.tag, commit: reading.installed.commit,
      sha256: reading.installed.sha256, published_at: '', source_url: null, installed_at: null,
    }
    : identity;
  // Root's own `behind` already passed its floor; this is for a program too
  // old to say `published_older`, and for the dashboard's own copy of the
  // dates. The stamp this process holds is the floor's release half, since
  // root's installed facts carry no date.
  const verdict = gradeWithFloor(from, reading.latest, releaseFloor(identity, highWaterAt));
  if (verdict === 'older') {
    return { ...base, state: 'unreachable', latest: null, reason: 'published_older' };
  }
  return {
    ...base,
    state: verdict,
    latest: reading.latest,
    reason: verdict === 'unknown' ? 'no_identity' : null,
  };
}

// ── The last answered check, kept across a restart ──────────────────────
//
// A read without `check=now` answers from what this host last learned and
// makes no outbound call. That memory lived in the process, so every restart
// forgot it, and the restart an apply ends with is the one read that
// matters: the page comes back seven seconds later, the updater names the
// release with no notes to carry, and the fold hides (#295, the live
// observation of 2026-09-12). What was learned is written beside the
// database and read back at boot, checked before it is believed: it is this
// process's own file, and still a file.
const STORED_STATES: readonly UpdateState[] = ['current', 'behind', 'unknown', 'mid_publish', 'unreachable'];
const STORED_REASONS: readonly UpdateReason[] = [
  'disabled', 'network', 'endpoint_malformed', 'sum_disagreement', 'no_identity',
  'signature_missing', 'signature_refused', 'signature_unchecked', 'published_older',
];
/** Marks a stored check written by code that verified the release it holds.
 *  A file without it was written before the dashboard checked signatures
 *  (#761), holds an unverified release and its notes, and is not read back:
 *  the next check replaces it. */
const STORED_SIGNED = 'release-key';

export function serializeStoredCheck(result: UpdateCheckResult): string {
  return JSON.stringify({
    state: result.state, reason: result.reason, checked_at: result.checked_at,
    endpoint: result.endpoint, latest: result.latest, verified_by: STORED_SIGNED,
  });
}

export function parseStoredCheck(raw: string | null | undefined): UpdateCheckResult | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_BODY_BYTES) return null;
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { return null; }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const o = obj as Record<string, unknown>;
  if (o.verified_by !== STORED_SIGNED) return null;
  if (typeof o.state !== 'string' || !(STORED_STATES as readonly string[]).includes(o.state)) return null;
  const reason = o.reason === null ? null
    : typeof o.reason === 'string' && (STORED_REASONS as readonly string[]).includes(o.reason) ? o.reason as UpdateReason
    : undefined;
  if (reason === undefined) return null;
  if (typeof o.checked_at !== 'number' || !Number.isFinite(o.checked_at) || o.checked_at <= 0) return null;
  if (typeof o.endpoint !== 'string' || !/^https?:\/\/[^\s"\\]+$/.test(o.endpoint)) return null;
  // The release goes through the same reader release.json does, so a stored
  // release is held to exactly what a fetched one is.
  const latest = o.latest === null ? null : parseReleaseJson(JSON.stringify(o.latest));
  if (o.latest !== null && !latest) return null;
  return { state: o.state as UpdateState, reason, checked_at: o.checked_at, endpoint: o.endpoint, latest };
}

/**
 * The notes belong to the archive, and the updater cannot carry them.
 *
 * Root's `check` verb answers in `key=value` facts, one line each, and a
 * changelog is a list. So a card graded from the updater names a release
 * with no notes, and the fold that says what it brings hides (#295). This
 * process fetched the same release.json on its own read, notes included.
 * When both readings name the same archive, those notes are this release's
 * notes and travel with it, and so does the changelog link (#299), which is
 * published beside them. When they name different archives (#293), they
 * describe a release this host would refuse to install, and stay off.
 */
export function carryNotes(
  graded: UpdateCheckResult | null,
  own: UpdateCheckResult | null | undefined,
): UpdateCheckResult | null {
  if (!graded || !graded.latest) return graded;
  const notes = graded.latest.notes ? undefined : own?.latest?.notes;
  const url = graded.latest.changelog_url ? undefined : own?.latest?.changelog_url;
  if (!notes && !url) return graded;
  const a = graded.latest, b = own!.latest!;
  const same = a.sha256 === b.sha256 || (a.tag === b.tag && sameCommit(a.commit, b.commit));
  if (!same) return graded;
  return { ...graded, latest: { ...a, ...(notes ? { notes } : {}), ...(url ? { changelog_url: url } : {}) } };
}

/** Two endpoints, two answers, one host. */
export interface EndpointDisagreement {
  /** Where root installs from, and what it publishes. */
  updater_endpoint: string;
  updater_tag: string;
  /** Where this process asked, and what that published. */
  page_endpoint: string;
  page_tag: string;
}

/** One endpoint, two readings of it taken at different moments. */
export interface ReadingLag {
  /** The endpoint both sides named, as this process spells it. */
  endpoint: string;
  /** What the updater's reading names. */
  updater_tag: string;
  /** What the older, page-side reading names. */
  page_tag: string;
}

/**
 * Two readings, one host: what they actually disagree about.
 *
 * Three answers, and the order they are decided in is load-bearing:
 *
 *   1. `null` — the same archive, or a side that produced no reading at all.
 *      A comparison needs BOTH sides to have produced a sha256: one endpoint
 *      that did not answer is a missing reading, and calling that a
 *      disagreement would put a red line on a card over a flaky network.
 *      Compared on the sum, reported by tag, because a tag is what an
 *      operator acts on. Two DIFFERENT endpoints publishing one archive land
 *      here too, and that is deliberate: there is nothing to warn about when
 *      root would install the same bytes either way.
 *   2. `endpoints` — the endpoint strings differ. This is the misconfigured
 *      host (#293): root installs from somewhere this page never read, so
 *      nothing is applied from here until the file that decides is fixed.
 *   3. `lag` — one endpoint, two readings, different archives. The endpoint
 *      published between the two reads. Nothing is misconfigured, and a
 *      sentence naming `/etc/aperire/update.conf` here blames a root-owned
 *      file for a clock (#342).
 *
 * Deciding (2) on the sums rather than on the endpoint strings is what made
 * (3) indistinguishable from it for the whole life of this guard.
 */
function compareReadings(
  page: UpdateCheckResult | null,
  reading: UpdaterReading | null,
): { kind: 'endpoints'; clash: EndpointDisagreement } | { kind: 'lag'; lag: ReadingLag } | null {
  if (!page || !page.latest || !reading || !reading.latest || !reading.endpoint) return null;
  if (page.latest.sha256.toLowerCase() === reading.latest.sha256.toLowerCase()) return null;
  if (sameEndpoint(page.endpoint, reading.endpoint)) {
    return { kind: 'lag', lag: { endpoint: page.endpoint, updater_tag: reading.latest.tag, page_tag: page.latest.tag } };
  }
  return {
    kind: 'endpoints',
    clash: {
      updater_endpoint: reading.endpoint,
      updater_tag: reading.latest.tag,
      page_endpoint: page.endpoint,
      page_tag: page.latest.tag,
    },
  };
}

/**
 * The same endpoint, written two ways?
 *
 * This process's own endpoint comes out of `updateEndpoint()` already
 * normalised; the updater's comes off root's `check` verb as whatever is in
 * `/etc/aperire/update.conf`, which nothing here normalised. So they are put
 * through the same reader before being compared, http allowed, because a
 * trailing slash is not a misconfiguration and telling an operator to go fix
 * one would be the same wrong sentence in a smaller hat.
 *
 * A side the reader rejects falls back to its raw text. Two strings nobody
 * could parse that are the same string are still the same endpoint.
 */
function sameEndpoint(a: string, b: string): boolean {
  const na = normaliseEndpoint(a, { allowHttp: true });
  const nb = normaliseEndpoint(b, { allowHttp: true });
  if (na && nb) return na === nb;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Do the two readings name two different endpoints, publishing different
 * archives? The one refusal on this comparison: what it reports cannot be
 * resolved from this page, and what it names is the file that decides.
 *
 * Same endpoint, different archives is NOT this. That is
 * `pageReadingOlderThanUpdater` below, and it is not a refusal.
 */
export function updaterEndpointDisagreement(
  page: UpdateCheckResult | null,
  reading: UpdaterReading | null,
): EndpointDisagreement | null {
  const out = compareReadings(page, reading);
  return out && out.kind === 'endpoints' ? out.clash : null;
}

/**
 * One endpoint, and this process's reading of it is OLDER than the updater's.
 *
 * Never both this and a disagreement: they are the two branches of one
 * comparison. What an operator does about it is press Check now, which
 * refreshes this side in the same request.
 *
 * `updaterAt` is when the updater's facts were read, which is not when they
 * were asked for: a cached probe is up to five minutes old. The clocks are
 * compared here, inside the function whose answer is a sentence about which
 * reading is older, rather than by the caller: the daily check CAN land
 * inside those five minutes and leave this process holding the newer of the
 * two, and a sentence naming the wrong one is the defect this exists to fix,
 * in a narrower window. Where the page's reading is not the older one, or
 * there is no clock for the other side, this is null and the card says
 * nothing: there is nothing misconfigured to report, and the probe refreshes
 * itself within five minutes.
 */
export function pageReadingOlderThanUpdater(
  page: UpdateCheckResult | null,
  reading: UpdaterReading | null,
  updaterAt: number | null,
): ReadingLag | null {
  if (updaterAt === null || !page || page.checked_at > updaterAt) return null;
  const out = compareReadings(page, reading);
  return out && out.kind === 'lag' ? out.lag : null;
}
