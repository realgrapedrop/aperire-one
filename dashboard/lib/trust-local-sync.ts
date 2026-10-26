/**
 * Hand a passkey enrolled in the browser to the Advisor on this host.
 *
 * The gap this closes. The Advisor checks passkey approvals against its OWN
 * copy of the admins' public keys, advisor/state/credentials.json. Every CLI
 * command that changes who may approve re-syncs that copy on its way out. A
 * passkey enrolled in a BROWSER is the one change the CLI never sees, so on
 * every host, every time, an enrollment after the Advisor install left the
 * store stale until an operator noticed the banner on the Advisor tab and ran
 * `aperire-auth advisor-sync` on the box. That was the whole root cause of
 * "Trust store is stale" being the normal state of a fresh install (#160).
 * The fleet had already been fixed for the same gap (trust-push-hook.ts);
 * the co-located Advisor had not.
 *
 * How it is closed without making this process more powerful. The dashboard
 * never writes the store: it cannot, the state directory belongs to the
 * Advisor's account, and a dashboard that could write it could grant itself
 * approving keys. What it does is ASK, through a socket systemd owns
 * (scripts/install-trust-sync-grant.sh), and the root program behind that
 * socket rebuilds the store from the dashboard's database on disk. Nothing
 * sent over the socket goes into the store: the payload is the origin and the
 * rp_id, and the program refuses either when it differs from what the store
 * already holds. So the most a compromised dashboard could do through this is
 * bring the Advisor level with a database it already owns outright.
 *
 * Same three rules as the fleet push. It runs only when the admin serial
 * MOVED (a monitor's passkey changes nothing and asks for nothing). It never
 * touches key material. And it can never affect the enrollment: the caller
 * has answered the browser before this runs, and every failure here is a log
 * line and an audit row, never a response.
 *
 * What the operator sees when it fails: nothing from here, and that is
 * deliberate for the same reason as the fleet hook. The Advisor tab already
 * compares the Advisor's reported fingerprint with this dashboard's and shows
 * the stale banner with the command (lib/trust-sync.ts). The observation is
 * the claim; this hook only makes it true more often. What this DOES read
 * back, for the log, is that observation: /v1/status after the sync, so the
 * journal says whether the Advisor now agrees rather than that a program
 * exited zero.
 */
import { isSocketUnreachable } from './model-seal.js';
import type { ProgramAnswer } from './socket-program.js';

/** Where systemd listens for a sync. Under /run and outside the checkout,
 *  because the dashboard account owns the checkout and anything it could
 *  rewrite is not a privilege boundary. */
export const TRUST_SYNC_SOCKET = '/run/aperire/trust-sync.sock';

export interface TrustLocalSyncDeps {
  /** The origin approvals may come from: authn.yaml's public_url, first
   *  entry, exactly what `aperire-auth advisor-sync` sends. */
  origin: string;
  /** authn.yaml's rp_id, or empty to let the program derive it from the
   *  origin the same way the CLI does. */
  rpId: string;
  /** The socket client; server.ts hands in askSocketProgram bound to the
   *  path. Tests hand in a function. */
  ask: (payload: string) => Promise<ProgramAnswer>;
  /** advisord's /v1/status trust fingerprint, or null when it could not be
   *  read. What the log line is built from. */
  readBack: () => Promise<string | null>;
  /** This dashboard's fingerprint now, for the comparison. */
  mine: () => string;
  log: (line: string) => void;
  /** The audit row. Best effort; a throw here is caught. */
  record: (detail: Record<string, unknown>) => void;
  /** What moved the admin key set, as the audit row names it. Defaults to
   *  the browser enrollment; a Settings change names itself. */
  trigger?: string;
}

export const TRUST_SYNC_TRIGGER_ENROLLMENT = 'auto after a browser enrollment';

export type TrustLocalSyncOutcome =
  | { ran: false; reason: 'serial_unchanged' | 'disabled' | 'no_origin' }
  | { ran: true; ok: false; reason: 'no_grant' | 'refused' | 'failed'; detail: string }
  | { ran: true; ok: true; trusted: number | null; advisorAgrees: boolean | null };

/**
 * The decision, on its own so it can be read in one place. Returns why it did
 * nothing rather than a bare boolean.
 */
export function trustLocalSyncDecision(
  before: string, after: string, origin: string,
): Exclude<TrustLocalSyncOutcome, { ran: true }> | { ran: true } {
  // The same switch as the fleet push: a host that must never have the web
  // process ask for a trust change turns both off together.
  if (process.env.APERIRE_NO_TRUST_PUSH === '1') return { ran: false, reason: 'disabled' };
  // A monitor's passkey, a re-enrollment of the same key, a rename: none of
  // them move the admin serial, and none of them are synced.
  if (before === after) return { ran: false, reason: 'serial_unchanged' };
  // No configured origin is a host that has not been told where approvals
  // come from; guessing would be the CLI's refusal restated as a default.
  if (!origin) return { ran: false, reason: 'no_origin' };
  return { ran: true };
}

/** The two lines the program reads, in order. The rp_id may be empty. */
export function trustSyncPayload(origin: string, rpId: string): string {
  return `${origin}\n${rpId}\n`;
}

/** Never throws, never carries anything but counts and words. */
export async function syncLocalTrustAfterEnrollment(
  before: string, after: string, deps: TrustLocalSyncDeps,
): Promise<TrustLocalSyncOutcome> {
  const decision = trustLocalSyncDecision(before, after, deps.origin);
  if (!decision.ran) {
    if (decision.reason !== 'serial_unchanged') {
      deps.log(`[trust-sync] the admin key set changed but the Advisor was not asked to sync: ${decision.reason}`);
    }
    return decision;
  }
  deps.log(`[trust-sync] admin key set changed (${before.slice(0, 12)} to ${after.slice(0, 12)}), asking the Advisor to sync`);
  const trigger = deps.trigger ?? TRUST_SYNC_TRIGGER_ENROLLMENT;

  let answer: ProgramAnswer;
  try {
    answer = await deps.ask(trustSyncPayload(deps.origin, deps.rpId));
  } catch (err) {
    if (isSocketUnreachable(err)) {
      // The ordinary case on a host installed before the grant existed, or
      // one whose Advisor was set up by hand. Named, with the one-command
      // remedy, because the banner on the tab is about to say the same thing
      // without saying why.
      deps.log('[trust-sync] this host has no trust-sync socket, so the enrollment did not reach the Advisor. ' +
        'Add the grant with: curl -fsSL https://get.aperire.one | bash -s -- --run trust-sync-grant (the Advisor install command runs it). ' +
        'Until then: bash scripts/aperire-auth.sh advisor-sync');
      safeRecord(deps, { trigger, outcome: 'no_grant' });
      return { ran: true, ok: false, reason: 'no_grant', detail: 'no trust-sync socket on this host' };
    }
    deps.log(`[trust-sync] the sync could not be asked for: ${(err as Error).message}`);
    safeRecord(deps, { trigger, outcome: 'failed' });
    return { ran: true, ok: false, reason: 'failed', detail: (err as Error).message };
  }

  // What the program said to a person, line by line, under this tag.
  for (const line of answer.stderr.split('\n')) {
    if (line.trim()) deps.log(`[trust-sync] ${line.trimEnd()}`);
  }
  if (answer.code !== 0) {
    // 3 is the program's own refusal code for a request that tried to move
    // the relying party or widen the origins; anything else is a store it
    // could not write. Both are already in the journal in its words.
    const reason = answer.code === 3 ? 'refused' : 'failed';
    safeRecord(deps, { trigger, outcome: reason, code: answer.code });
    return { ran: true, ok: false, reason, detail: answer.stderr.trim() };
  }

  const fields = parseFields(answer.stdout);
  const trusted = fields.trusted !== undefined ? Number(fields.trusted) : null;

  // The claim that matters is the Advisor's, not the program's exit code:
  // read its fingerprint back and say whether it now equals ours. A mismatch
  // here is what the tab will show as the stale banner, so the journal names
  // it first.
  let advisorAgrees: boolean | null = null;
  let theirs: string | null;
  try { theirs = await deps.readBack(); } catch { theirs = null; }
  if (theirs !== null) {
    advisorAgrees = theirs === deps.mine();
    deps.log(advisorAgrees
      ? `[trust-sync] the Advisor now trusts ${trusted ?? '?'} passkey(s), and its fingerprint matches this dashboard's`
      : `[trust-sync] the store was written (${trusted ?? '?'} trusted) but the Advisor reports a different fingerprint; ` +
        'it re-reads the file on the next approval, so check the tab, and if the banner stays: bash scripts/aperire-auth.sh advisor-sync');
  } else {
    deps.log(`[trust-sync] the store was written (${trusted ?? '?'} trusted); the Advisor could not be read back to confirm`);
  }
  safeRecord(deps, {
    trigger, outcome: 'synced',
    trusted, advisor_agrees: advisorAgrees,
  });
  return { ran: true, ok: true, trusted: Number.isFinite(trusted as number) ? trusted : null, advisorAgrees };
}

function parseFields(stdout: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of stdout.split('\n')) {
    const m = /^([a-z_]+)=(.*)$/.exec(line);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

function safeRecord(deps: TrustLocalSyncDeps, detail: Record<string, unknown>): void {
  try { deps.record(detail); } catch (err) {
    deps.log(`[trust-sync] the audit row could not be written: ${(err as Error).message}`);
  }
}
