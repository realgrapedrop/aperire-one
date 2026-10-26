/**
 * Was this release.json signed by a key this host trusts? (#761)
 *
 * The dashboard's own update check reads release.json for the metric, the
 * fleet table and the release notes on Settings & Updates. Root already holds
 * every release to the release key (ADR 0024, scripts/release-verify-lib.sh);
 * this is the same check for what the page reads, so a taken-over endpoint
 * can neither flip the metric fleet-wide nor put text of its choosing on
 * every Settings page.
 *
 * Same verifier as root, not a second one: `ssh-keygen -Y verify`, with the
 * principal and namespace fixed here exactly as the shell library fixes them,
 * against the signer set root installed (lib/release-key.ts reads it and
 * holds it to the same shape check). Run with execFile, no shell, the message
 * on stdin, a deadline, and the two files it needs in a directory only this
 * account can read, removed afterwards.
 *
 * Three answers, and none of them is "could not reach":
 *
 *   ok         a key in the set signed exactly these bytes
 *   refused    a signature is there and does not verify against the set:
 *              a changed file, a different key, a different namespace
 *   unchecked  this host cannot check at all: no signer set, one that is
 *              not a set, or no ssh-keygen. Nothing from the file is used.
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readReleaseSigners, type ReleaseSignerSet } from './release-key.js';

/** Fixed, never read from anywhere (scripts/release-verify-lib.sh). */
const PRINCIPAL = 'aperire-release-key';
const NAMESPACE = 'aperire-release';
const VERIFY_TIMEOUT_MS = 10_000;

export type SignatureVerdict =
  | { verdict: 'ok' }
  | { verdict: 'refused' | 'unchecked'; why: string };

/** Checks `message` against `signature`. Injected into the update check so
 *  that module stays pure over its inputs. */
export type ReleaseVerifier = (message: Buffer, signature: Buffer) => Promise<SignatureVerdict>;

/** Run one program, stdin from `input`, and say how it ended. */
export type RunVerify = (
  file: string, args: string[], input: Buffer, timeoutMs: number,
) => Promise<{ code: number | null; output: string; missing: boolean }>;

const runSpawn: RunVerify = (file, args, input, timeoutMs) => new Promise((resolve) => {
  let output = '';
  let done = false;
  const finish = (r: { code: number | null; output: string; missing: boolean }) => {
    if (done) return;
    done = true;
    resolve(r);
  };
  const child = spawn(file, args, { stdio: ['pipe', 'pipe', 'pipe'], timeout: timeoutMs, env: { PATH: process.env.PATH ?? '/usr/bin:/bin' } });
  child.stdout.on('data', (d: Buffer) => { if (output.length < 4096) output += d.toString('utf8'); });
  child.stderr.on('data', (d: Buffer) => { if (output.length < 4096) output += d.toString('utf8'); });
  child.on('error', (e: NodeJS.ErrnoException) => finish({ code: null, output: e.message, missing: e.code === 'ENOENT' }));
  child.on('close', (code) => finish({ code, output, missing: false }));
  child.stdin.on('error', () => {});
  child.stdin.end(input);
});

/**
 * The verifier the server uses. The signer set is read on every call, so a
 * rotation that lands under a running process is used from the next check,
 * and the card's fingerprint (read through the same function) never names a
 * key other than the one in use.
 */
export function sshKeygenVerifier(opts: {
  signers?: () => ReleaseSignerSet;
  run?: RunVerify;
  keygen?: string;
} = {}): ReleaseVerifier {
  const signers = opts.signers ?? (() => readReleaseSigners());
  const run = opts.run ?? runSpawn;
  const keygen = opts.keygen ?? 'ssh-keygen';
  return async (message, signature) => {
    const set = signers();
    if (set.state === 'none') {
      return { verdict: 'unchecked', why: `this host has no release key at ${set.path}, so no release can be checked` };
    }
    if (set.state !== 'ok' || set.text === '') {
      return { verdict: 'unchecked', why: `${set.path} is not a release key set this host accepts, so no release can be checked` };
    }
    if (signature.length === 0) {
      return { verdict: 'refused', why: 'the signature is empty' };
    }
    const dir = mkdtempSync(join(tmpdir(), 'aperire-release-verify-'));
    try {
      const allowed = join(dir, 'allowed_signers');
      const sig = join(dir, 'release.json.sig');
      writeFileSync(allowed, set.text, { mode: 0o600 });
      writeFileSync(sig, signature, { mode: 0o600 });
      const r = await run(keygen, [
        '-Y', 'verify', '-f', allowed, '-I', PRINCIPAL, '-n', NAMESPACE, '-s', sig,
      ], message, VERIFY_TIMEOUT_MS);
      if (r.missing) {
        return { verdict: 'unchecked', why: 'this host has no ssh-keygen (openssh-client), so no release can be checked' };
      }
      if (r.code === 0) return { verdict: 'ok' };
      if (r.code === null) {
        return { verdict: 'unchecked', why: 'ssh-keygen did not finish checking the signature' };
      }
      // Too old to know -Y is a different sentence from a bad signature, the
      // same split the shell library makes.
      if (/illegal option|unknown option|invalid option/i.test(r.output)) {
        return { verdict: 'unchecked', why: 'this host’s ssh-keygen is too old to check a release signature (it needs OpenSSH 8.2 or newer)' };
      }
      const said = r.output.replace(/\s+/g, ' ').trim().slice(0, 200);
      return { verdict: 'refused', why: said ? `the signature does not verify against the release key: ${said}` : 'the signature does not verify against the release key' };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}
