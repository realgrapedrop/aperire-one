/**
 * A small JSON file this dashboard's own account writes and trusts, read and
 * written on descriptors, never by a name checked and then reopened.
 *
 *   write   a fresh temp name opened O_CREAT|O_EXCL|O_NOFOLLOW at 0600, so
 *           nothing already at that name (a link planted beside it) is
 *           followed or reused; written, fsynced, closed, then renamed over
 *           the real name, which replaces a link rather than writing
 *           through one.
 *   read    O_NOFOLLOW|O_NONBLOCK, then checked on the descriptor: a
 *           regular file, owned by this account, nobody else may write it,
 *           no larger than the caller's bound. Anything else reads as null.
 *
 * Two files use it: the tombstone a node keeps (#688) and the tombstones an
 * aggregator signed (#738). Lifted out of the first so the second is not a
 * copy of it.
 */
import {
  openSync, closeSync, fstatSync, readSync, writeSync, fsyncSync, renameSync, unlinkSync,
  constants as fsConstants,
} from 'node:fs';
import { randomBytes } from 'node:crypto';

/** The parsed JSON at `path`, or null for anything that is not a file this
 *  account owns, nobody else can write, and at most `maxBytes` long. Never
 *  throws. */
export function readOwnedJson(path: string, maxBytes: number): unknown {
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return null;
    if (st.mode & 0o022) return null;
    if (st.size > maxBytes) return null;
    const buf = Buffer.alloc(maxBytes + 1);
    let len = 0;
    for (;;) {
      const n = readSync(fd, buf, len, buf.length - len, null);
      if (n <= 0) break;
      len += n;
      if (len > maxBytes) return null;
    }
    return JSON.parse(buf.subarray(0, len).toString('utf8'));
  } catch {
    return null;
  } finally {
    try { closeSync(fd); } catch { /* already closed */ }
  }
}

/** Write `value` as one line of JSON at `path`, replacing whatever is there.
 *  Throws when it could not, leaving no temp file behind. */
export function writeOwnedJson(path: string, value: unknown): void {
  const tmp = `${path}.tmp.${randomBytes(8).toString('hex')}`;
  const fd = openSync(
    tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600,
  );
  try {
    writeSync(fd, `${JSON.stringify(value)}\n`);
    fsyncSync(fd);
  } catch (err) {
    try { closeSync(fd); } catch { /* ignore */ }
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw err;
  }
  closeSync(fd);
  try {
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw err;
  }
}
