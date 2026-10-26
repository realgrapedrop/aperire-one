/**
 * The high-water mark root keeps beside the release store (#1073).
 *
 * `get-aperire.sh` writes the publish date of the newest release this host
 * has ever installed to `<store>/high-water`, root-owned and 0644, in a store
 * that is 0755, so the dashboard's account can read it. Root's own update
 * check refuses any release published no later than the later of that date
 * and the release the host runs. The page applies the same floor, which means
 * reading the same file the way root reads it: believed only when it is a
 * regular file (never a link), owned by root, writable by nobody else, and
 * one date. Anything else reads as no mark, which leaves the floor at the
 * stamp's own date alone, never at a date somebody else could have planted.
 *
 * `scripts/aperire-update.sh` (`high_water_at`) is the other copy of these
 * rules. The two read one file, so they are kept to one shape.
 */
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';

export const RELEASE_STORE_DEFAULT = '/var/lib/aperire/release';

/** One UTC second-resolution date, the only shape root keeps. */
const DATE_LINE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * The mark in `file`, or null.
 *
 * `trustedUid` is the owner the file has to have. Root's is 0. A test that
 * writes its own store passes its own uid, the way the shell copy takes the
 * run's own account when it is not root.
 */
export function readHighWater(file: string, trustedUid = 0): string | null {
  let fd: number | null = null;
  try {
    // O_NOFOLLOW: a link planted at the name is refused, not read through.
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    // Judged on the descriptor the bytes come from, not on the name.
    const st = fstatSync(fd);
    if (!st.isFile() || st.uid !== trustedUid || (st.mode & 0o022) !== 0) return null;
    const buf = Buffer.alloc(64);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const first = buf.subarray(0, n).toString('utf8').split('\n', 1)[0];
    return DATE_LINE.test(first) ? first : null;
  } catch {
    return null;
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* nothing to do */ } }
  }
}

/**
 * This host's mark, from the store `APERIRE_RELEASE_STORE` names or the
 * installed one. A store named by the environment is a test's own, so its
 * owner is trusted to be the account running the test, as the shell copy
 * does; the installed store's file has to be root's.
 */
export function readReleaseHighWater(env: NodeJS.ProcessEnv = process.env): string | null {
  const named = env.APERIRE_RELEASE_STORE;
  if (named && named.startsWith('/')) {
    return readHighWater(join(named, 'high-water'), process.getuid ? process.getuid() : 0);
  }
  return readHighWater(join(RELEASE_STORE_DEFAULT, 'high-water'), 0);
}
