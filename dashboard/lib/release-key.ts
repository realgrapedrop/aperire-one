/**
 * The release key this host trusts, as the operator compares it (#736).
 *
 * Every update is checked against /usr/local/lib/aperire/release-signers,
 * the root-owned copy the install and each signed update put there. Settings
 * & Updates shows the fingerprint of each key in that file, the same
 * `SHA256:<base64>` that `ssh-keygen -l` prints and the public guide
 * publishes, so an operator can put the two side by side.
 *
 * Two rules:
 *
 *   - **Only a root-owned copy.** The tree's scripts/release-signers is
 *     writable by the account this process runs as, so a fingerprint read from
 *     it could be made to show whatever an attacker liked. There is no
 *     fallback to it. The one other path is `APERIRE_RELEASE_SIGNERS`, and
 *     only root can set it: it reaches this process from the unit file or
 *     /etc/aperire/aperire.env (root:dashboard 0640), the same two places
 *     `APERIRE_UPDATE_ENDPOINT` comes from. The walks use it to stand a test
 *     key in for the release key (#761); a host never has it set. It moves
 *     only this process's verifier. The Release key row keeps showing the
 *     constant, root's key, and names the test key beside it, never in its
 *     place (releaseKeyWire).
 *   - **What is shown is what is used.** The dashboard's own update check
 *     verifies release.json against the keys read here (#761), with the same
 *     parser. Without the override that is the same file the card shows; with
 *     it, the card shows both and says which one this page checks against.
 *   - **Absent is said, never guessed.** No file is "no release key
 *     installed", and a file that is not a signer set is "unreadable". Neither
 *     is ever shown as a fingerprint.
 *
 * Read-only. Nothing here changes which key the host trusts; that only ever
 * happens through a signed release.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const RELEASE_SIGNERS_PATH = '/usr/local/lib/aperire/release-signers';

/** The signer set this process trusts: the root-owned constant, or the path
 *  root named in `APERIRE_RELEASE_SIGNERS`. Absolute paths only; anything else
 *  in the variable is ignored rather than resolved against a working
 *  directory this account owns. */
export function releaseSignersPath(env: string | undefined = process.env.APERIRE_RELEASE_SIGNERS): string {
  const v = (env ?? '').trim();
  return v.startsWith('/') ? v : RELEASE_SIGNERS_PATH;
}

/** The one principal and namespace a signer line may carry
 *  (scripts/release-verify-lib.sh). */
const PRINCIPAL = 'aperire-release-key';
const NAMESPACES = 'namespaces="aperire-release"';
/** One key normally, two only while the key is rotated. */
const MAX_KEYS = 2;

/** The signer set itself, for the one caller that checks a signature with
 *  it. Kept off ReleaseKeyView, which is sent to the page as it is. */
export interface ReleaseSignerSet {
  state: ReleaseKeyView['state'];
  /** The set rebuilt from the four checked fields of each accepted line, one
   *  line per key and nothing else, which is what `ssh-keygen -Y verify` is
   *  handed: no comment, no carriage return, nothing the check did not read.
   *  Empty unless `state` is `ok`. */
  text: string;
  fingerprints: string[];
  path: string;
}

export interface ReleaseKeyView {
  /** ok: fingerprints below. none: no file. unreadable: a file that is not
   *  a signer set this host's updater would accept. */
  state: 'ok' | 'none' | 'unreadable';
  /** `SHA256:<base64, no padding>`, one per key, in file order. */
  fingerprints: string[];
  /** Where it was read from, so the page can name the file. */
  path: string;
}

/** OpenSSH's fingerprint of a public key blob: SHA-256 over the decoded key,
 *  base64 without the trailing `=`. */
export function sshFingerprint(base64Key: string): string {
  const blob = Buffer.from(base64Key, 'base64');
  return 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
}

/** Parse an allowed_signers file the way the updater's shape check does:
 *  every non-comment line is `aperire-release-key namespaces="aperire-release"
 *  ssh-ed25519 <base64> [comment]`, one or two of them. Anything else is
 *  `unreadable`, never a partial answer. */
export function parseReleaseSigners(text: string, path = RELEASE_SIGNERS_PATH): ReleaseKeyView {
  const { state, fingerprints } = checkReleaseSigners(text, path);
  return { state, fingerprints, path };
}

function checkReleaseSigners(text: string, path: string): ReleaseSignerSet {
  const fingerprints: string[] = [];
  const lines: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    // The same split bash's `read -r principal opts type key rest` makes:
    // four fields on spaces and tabs, the rest of the line (trailing blanks
    // dropped) as the comment, held to the same characters the updater's
    // check allows. Any line it would refuse makes the whole set unreadable.
    const m = /^([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)(?:[ \t]+(.*?))?[ \t]*$/.exec(line);
    if (line !== line.trimStart() || !m || m[1] !== PRINCIPAL || m[2] !== NAMESPACES
        || m[3] !== 'ssh-ed25519' || !/^[A-Za-z0-9+/]{40,}={0,2}$/.test(m[4])
        || (m[5] !== undefined && m[5] !== '' && !/^[A-Za-z0-9._@:+ -]+$/.test(m[5]))) {
      return { state: 'unreadable', text: '', fingerprints: [], path };
    }
    fingerprints.push(sshFingerprint(m[4]));
    lines.push(`${PRINCIPAL} ${NAMESPACES} ssh-ed25519 ${m[4]}\n`);
  }
  if (fingerprints.length === 0 || fingerprints.length > MAX_KEYS
      || new Set(fingerprints).size !== fingerprints.length) {
    return { state: 'unreadable', text: '', fingerprints: [], path };
  }
  return { state: 'ok', text: lines.join(''), fingerprints, path };
}

/** What the card's Release key row carries: always root's own set, at the
 *  constant path, because that is the key root's updater checks every
 *  install against. When APERIRE_RELEASE_SIGNERS points this process's
 *  verifier somewhere else, the key it uses rides beside it as `test_key`,
 *  so the page says so instead of silently showing one key and checking
 *  against another. */
export interface ReleaseKeyWire extends ReleaseKeyView {
  test_key?: ReleaseKeyView;
}

export function releaseKeyWire(
  read: (p: string) => string = (p) => readFileSync(p, 'utf8'),
  override: string = releaseSignersPath(),
): ReleaseKeyWire {
  const own = readReleaseKey(read, RELEASE_SIGNERS_PATH);
  if (override === RELEASE_SIGNERS_PATH) return own;
  return { ...own, test_key: readReleaseKey(read, override) };
}

/** Read a signer set. `read` is injectable for tests only. The path is the
 *  root-owned one unless the caller names another: the Release key row
 *  always reads the constant (releaseKeyWire), the verifier reads
 *  releaseSignersPath(). */
export function readReleaseKey(
  read: (p: string) => string = (p) => readFileSync(p, 'utf8'),
  path: string = releaseSignersPath(),
): ReleaseKeyView {
  const { state, fingerprints } = readReleaseSigners(read, path);
  return { state, fingerprints, path };
}

/** The same read, keeping the checked bytes for a signature check. */
export function readReleaseSigners(
  read: (p: string) => string = (p) => readFileSync(p, 'utf8'),
  path: string = releaseSignersPath(),
): ReleaseSignerSet {
  let text: string;
  try {
    text = read(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    return { state: code === 'ENOENT' ? 'none' : 'unreadable', text: '', fingerprints: [], path };
  }
  return checkReleaseSigners(text, path);
}
