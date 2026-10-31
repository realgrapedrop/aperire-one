/**
 * Three facts a fleet node says about its own install, read back off the wire
 * (#593, #615): the relay's build, the directory the dashboard is installed in,
 * and the account the dashboard runs as.
 *
 * They arrive on the `node-status` read route, the one every fleet poll
 * already fetches, and they are node-authored. Two of them are shown beside
 * commands an operator copies and runs under sudo (the trust-file fix, the
 * update-grant reinstall), as what the node said and never inside a command:
 * a path the node chose is not something root should act on. They are still
 * whitelisted here, so a hostile or broken peer cannot put a shell word into
 * a sentence next to one. Every parser is a whitelist: a value that is not
 * exactly the shape of the thing it names is dropped to null, and null is
 * "this node did not say", which the pages answer with their own default and
 * no note, never with a guess.
 *
 * Kept in its own module, and not in fleet-health.ts, so a page-facing
 * builder (settings-api.ts, server.ts) can reuse the same check without
 * importing the poller.
 */

/** The longest directory this will carry. PATH_MAX is 4096, and no install
 *  sits anywhere near it; a longer string is not an install directory. */
const MAX_DIR_LEN = 200;

/** Letters, digits, dot, underscore, hyphen and the separator. Nothing a
 *  shell treats as syntax, no space, no quote, no `$`, no `~`. A directory
 *  with a character outside this set is a real directory this page then
 *  falls back on rather than printing: a wrong default costs the operator a
 *  sentence's worth of editing, a quoted-wrong one costs a root command. */
const DIR_SHAPE = /^\/[A-Za-z0-9._\-/]*$/;

/**
 * The install directory a peer reported, or null.
 *
 * Absolute only, no `.` or `..` segment, no empty segment, and a trailing
 * slash is dropped rather than refused (`/srv/aperire-one/` and
 * `/srv/aperire-one` are one directory). The root itself is not an install.
 */
export function parseInstallDir(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  let s = raw.trim();
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  if (s.length < 2 || s.length > MAX_DIR_LEN) return null;
  if (!DIR_SHAPE.test(s)) return null;
  const segments = s.slice(1).split('/');
  for (const seg of segments) {
    if (seg === '' || seg === '.' || seg === '..') return null;
    // A segment that starts with a hyphen is an option to whatever the path
    // is handed to, if the path is ever quoted off the front of a command.
    if (seg.startsWith('-')) return null;
  }
  return s;
}

/** The account name a POSIX system accepts, plus the dots and capitals some
 *  directory-backed accounts carry. A hyphen never leads, so the name cannot
 *  be read as an option. */
const ACCOUNT_SHAPE = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;

/** The account a peer's dashboard runs as, or null. */
export function parseRunAs(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  return ACCOUNT_SHAPE.test(s) ? s : null;
}

/** A relay's own build ref, shaped like a commit and nothing else. The same
 *  rule `sanitizeComponents` (lib/fleet-update.ts) holds the `components`
 *  reading to: a relay no release has stamped reads the literal `dev`, which
 *  fails this on purpose and so reads "not reported" here exactly as it does
 *  on the local System tab. fleet-update.ts imports fleet-health.ts, which uses this module, so
 *  the shape is repeated rather than imported; the unit test holds the two
 *  functions to the same answers. */
const RELAY_BUILD_SHAPE = /^[0-9a-f]{7,40}$/;

/** The relay build a peer reported, lower-cased, or null. */
export function parseRelayBuild(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const v = raw.trim().toLowerCase();
  return RELAY_BUILD_SHAPE.test(v) ? v : null;
}

/** The three facts as the poller keeps them for one peer. */
export interface PeerInstallFacts {
  relayVersion: string | null;
  installDir: string | null;
  runAs: string | null;
}

/** Nothing was said. One frozen value so no failure branch invents its own
 *  shape of "we learned nothing". */
export const NO_INSTALL_FACTS: PeerInstallFacts = Object.freeze({
  relayVersion: null, installDir: null, runAs: null,
});

/** The two members of a peer's node-status body that are for an administrator
 *  only (#615): where its dashboard is installed and the account it runs as.
 *  `relay_version` is a build ref and is not on this list. */
export const ADMIN_ONLY_INSTALL_KEYS = ['install_dir', 'run_as'] as const;

/**
 * A peer's node-status body as a session of this role may read it. The
 * proxied routes forward a peer's JSON as it arrived, to any signed-in role,
 * so this is where the two administrator-only members come out for everyone
 * else. A copy, never an edit in place: the proxy and the overview cache hold
 * one body and serve it to every role.
 */
export function nodeStatusForRole<T>(body: T, isAdminSession: boolean): T {
  if (isAdminSession || !body || typeof body !== 'object' || Array.isArray(body)) return body;
  const out = { ...(body as Record<string, unknown>) };
  for (const k of ADMIN_ONLY_INSTALL_KEYS) delete out[k];
  return out as T;
}
