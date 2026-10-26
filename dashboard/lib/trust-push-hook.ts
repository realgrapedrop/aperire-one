/**
 * Push the trust bundle to the fleet when a passkey enrollment changed who
 * may approve.
 *
 * The gap this closes. `aperire-auth` pushes on every credential change it
 * makes, but it cannot see a passkey being enrolled in a browser — that
 * happens here, in the web process, and until now it reached the fleet only
 * when someone remembered to run the push by hand. On 2026-08-19 nobody did:
 * an admin enrolled at the aggregator, walked to a ceremony on stock-node2,
 * and was told their credential was not enrolled with the Advisor.
 *
 * Three rules shape how it is closed, and all three are about not making the
 * web process more powerful than it was.
 *
 * ONE: it runs only when the SERIAL MOVED. The bundle carries admin
 * credentials only, so a monitor's new passkey does not change it and nothing
 * is pushed. That is a property of the digest rather than a role check kept in
 * step by hand — if the credential set the next push would carry is byte-for-
 * byte what the last one carried, there is nothing to send.
 *
 * TWO: it never touches key material. It spawns the same `aperire-auth
 * fleet-trust-push` an operator runs, rather than reimplementing signing in
 * the request path. That does NOT reduce privilege — same uid, same readable
 * fleet-trust.yaml — and pretending otherwise would be the dishonest version
 * of this comment. What it does buy is one implementation of "build, sign,
 * push", already covered by scripts/test-fleet-trust-perms.sh, with the
 * private key nowhere in this process's heap. Actually separating the signing
 * account from the server account is the change that would reduce capability,
 * and it is a bigger job than this.
 *
 * THREE: it can never affect the enrollment. The credential is already
 * written and the operator has already touched their passkey by the time this
 * runs; a failure here is logged and recorded, never returned. The caller
 * sends its response first and calls this after.
 *
 * What the operator sees when a push fails: nothing here, deliberately. The
 * result of a failed push is a node whose trust set is behind, and that is
 * already surfaced — the Advisor tab compares each node's reported serial
 * against this dashboard's and shows the stale banner with the fix command
 * (lib/trust-sync.ts). Reporting the ATTEMPT would add a second, weaker claim
 * that has to be kept in step with the observed one, and it would miss every
 * cause that does not involve a push at all: a node reinstalled, a node that
 * was down at push time and stayed down, a node joined after the last change.
 * The observation catches all of them; the attempt catches one.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export interface TrustPushSpawn {
  (cmd: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number }):
    Promise<{ code: number; output: string }>;
}

export interface TrustPushDeps {
  /** Repository root — the parent of dashboard/. */
  repoDir: string;
  /** The database the CLI must open: the same one this process opened. */
  dbPath: string;
  spawn: TrustPushSpawn;
  log: (line: string) => void;
  /** Test seam only; defaults to existsSync. */
  exists?: (p: string) => boolean;
}

export type TrustPushOutcome =
  | { ran: false; reason: 'serial_unchanged' | 'not_an_aggregator' | 'no_signing_key' | 'no_cli' | 'disabled' }
  | { ran: true; ok: boolean; output: string };

/**
 * The whole decision, so it can be read in one place and tested without a
 * filesystem. Returns the reason it did nothing rather than a bare boolean:
 * "did not push" has four different meanings here and only one of them is
 * interesting.
 */
export function trustPushDecision(
  before: string, after: string, repoDir: string, exists: (p: string) => boolean,
): Exclude<TrustPushOutcome, { ran: true }> | { ran: true } {
  if (process.env.APERIRE_NO_TRUST_PUSH === '1') return { ran: false, reason: 'disabled' };
  // The guard that makes this safe by construction. A monitor's passkey, a
  // re-enrollment of the same key, a device rename — none of them move the
  // serial, and none of them are pushed.
  if (before === after) return { ran: false, reason: 'serial_unchanged' };
  if (!exists(join(repoDir, 'dashboard', 'config', 'fleet.yaml'))) {
    return { ran: false, reason: 'not_an_aggregator' };
  }
  if (!exists(join(repoDir, 'dashboard', 'config', 'fleet-trust.yaml'))) {
    return { ran: false, reason: 'no_signing_key' };
  }
  if (!exists(join(repoDir, 'scripts', 'aperire-auth.sh'))) {
    return { ran: false, reason: 'no_cli' };
  }
  return { ran: true };
}

/**
 * Run it. Never throws: every failure path returns, and the caller has
 * already answered the browser.
 */
export async function pushTrustAfterEnrollment(
  before: string, after: string, deps: TrustPushDeps,
): Promise<TrustPushOutcome> {
  const exists = deps.exists ?? existsSync;
  const decision = trustPushDecision(before, after, deps.repoDir, exists);
  if (!decision.ran) {
    if (decision.reason !== 'not_an_aggregator' && decision.reason !== 'serial_unchanged') {
      deps.log(`[trust-push] the admin key set changed but nothing was pushed: ${decision.reason}`);
    }
    return decision;
  }
  deps.log(`[trust-push] admin key set changed (${before.slice(0, 12)}… → ${after.slice(0, 12)}…) — pushing to the fleet`);
  try {
    const r = await deps.spawn('bash', [join(deps.repoDir, 'scripts', 'aperire-auth.sh'), 'fleet-trust-push'], {
      cwd: deps.repoDir,
      // The CLI resolves its own repository from its path; the one thing it
      // must be told is which database, or it would push the admin set of a
      // different install on a host running two.
      // APERIRE_TRUST_PUSH_AS_DASHBOARD: this process IS the dashboard's
      // account, so the CLI must not try to resolve or switch to it (#872,
      // #873 review L6). A unit it could not parse would otherwise fail a
      // push the page has always been able to make.
      env: { ...process.env, APERIRE_DB_PATH: deps.dbPath, APERIRE_TRUST_PUSH_AS_DASHBOARD: '1' },
      // Long enough for every node's own 10s timeout plus the signing, short
      // enough that a hung tunnel does not leave a child around for an hour.
      timeoutMs: 60_000,
    });
    // Per node, not summarised: which node refused, and what it said, is the
    // whole value of the log line. The CLI already prints one line each.
    for (const line of r.output.split('\n')) {
      if (line.trim()) deps.log(`[trust-push] ${line.trimEnd()}`);
    }
    if (r.code !== 0) {
      deps.log('[trust-push] AT LEAST ONE NODE DID NOT TAKE THE NEW TRUST SET. ' +
        'It will refuse a passkey enrolled since its last accepted bundle, and the ' +
        'Advisor tab shows it as stale with the command to fix it.');
    }
    return { ran: true, ok: r.code === 0, output: r.output };
  } catch (err) {
    deps.log(`[trust-push] the push could not be started: ${(err as Error).message}`);
    return { ran: true, ok: false, output: (err as Error).message };
  }
}
