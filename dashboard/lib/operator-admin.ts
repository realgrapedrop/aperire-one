/**
 * Operator management, the part that decides.
 *
 * Everything the Settings page does TO an account lives here: who exists,
 * who may approve, which passkeys are registered, and what a change to any
 * of those does to the fleet's trust set. The routes in settings-api.ts
 * carry the HTTP; this file carries the rules.
 *
 * Written with every side effect injected, for one reason: these are the
 * refusals that hold when the page is not the thing making the request. A
 * guard that needs a database, a socket and a signing key to exercise is a
 * guard nobody exercises, and the four that matter here (you cannot remove
 * yourself, you cannot demote yourself, you cannot remove the last admin,
 * you cannot promote anyone without your passkey) are exactly the ones a
 * later refactor can drop without a single behaviour test noticing.
 *
 * Two rules run through all of it.
 *
 * ONE: the page refuses what the CLI only warns about. `aperire-auth` warns
 * when a command leaves nobody able to approve, because whoever ran it has a
 * root shell and can put it back. A browser session cannot. So self-removal,
 * self-demotion, removing the last admin and demoting the last admin are
 * refusals here, not warnings.
 *
 * TWO: the raw magic-link token exists in exactly one place, the JSON
 * response to the request that minted it. It is not in an audit row, not in
 * a log line, and not in an error. What is recorded is who was invited and
 * whether the email went out.
 */
import type { AuthEventKind } from '../db.js';
import type { TrustPushOutcome } from './trust-push-hook.js';
import type { TrustLocalSyncOutcome } from './trust-local-sync.js';

/** The two roles the product has. Anything else is refused before it can be
 *  written: isAdmin() is `role === 'admin'`, so a row holding 'Admin' would
 *  display as an administrator and be able to approve nothing. */
export type OperatorRole = 'admin' | 'monitor';

/** What one write endpoint answers with, before the HTTP layer sends it. */
export interface OperatorResult { status: number; body: Record<string, unknown>; }

// ── The rows this module reads ─────────────────────────────────────────

export interface AccountUserRow {
  id: number;
  username: string;
  email: string | null;
  /** The RAW database value, not normalised. Legacy rows created by
   *  createUser() hold 'operator', and comparing a normalised value would
   *  make such a row impossible to regularise: asked to become a monitor it
   *  would read as already being one. */
  role: string;
  created_at: number;
  last_login_at: number | null;
}

export interface AccountCredentialRow {
  id: number;
  /** The WebAuthn handle, base64url. auth_sessions.credential_id stores
   *  this, not the row id, which is why a revoke has to read it before the
   *  row is deleted. */
  credential_id: string;
  name: string | null;
  created_at: number;
  last_used_at: number | null;
}

export interface PendingLinkRow { purpose: string; created_at: number; expires_at: number; }

/** The acting operator, off the session and never off a request body. */
export interface ActingSession {
  userId: number;
  username: string;
  role: string;
  /** The WebAuthn handle this session was opened with, or null on a session
   *  minted before that was recorded. It is the one passkey a revoke must
   *  leave alone: dropping it ends the very session doing the dropping, and
   *  on a box with one admin and no email channel nothing can sign in again. */
  credentialId?: string | null;
}

// ── What the page is handed ────────────────────────────────────────────

export interface AccountPasskeyView {
  id: number;
  device: string;
  /** True on the passkey the asking session signed in with. The page does
   *  not offer to revoke it; the server refuses if asked anyway. */
  signed_in: boolean;
  enrolled_at: string | null;
  last_used_at: string | null;
}

export interface AccountView {
  email: string;
  role: OperatorRole;
  is_self: boolean;
  created_at: string | null;
  last_login_at: string | null;
  passkeys: AccountPasskeyView[];
  sessions: number;
  pending_link: null | { purpose: 'enroll' | 'recover'; issued_at: string; expires_at: string };
}

export interface TrustEnvelope {
  serial_before: string;
  serial_after: string;
  pushed: boolean;
  nodes: Array<{ label: string; ok: boolean; what: string }>;
}

export interface AdvisorSyncEnvelope { attempted: boolean; ok: boolean | null; what: string; }

// ── The ceremony, verified elsewhere ───────────────────────────────────

/**
 * A passkey assertion that has been checked, and WHAT it authorised.
 *
 * The action, the email and the role all come off the record written at
 * begin. Nothing here is read from the finishing request: an assertion
 * proves the operator approved adding THIS person as THIS role, and a value
 * the browser could change between the two halves would let one signature be
 * spent on a different grant entirely.
 */
export interface VerifiedGrant {
  action: 'add' | 'role';
  email: string;
  role: OperatorRole;
  operator: string;
  operatorRole: string;
  credentialId: string;
}

export type GrantOutcome =
  | { ok: true; grant: VerifiedGrant }
  | { ok: false; status: number; error: string };

/** Verify the assertion on this request, if one was presented. */
export type GrantVerifier = () => Promise<GrantOutcome>;

/** Issue a challenge for a grant that is about to be asked for. */
export type GrantBeginner = (grant: { action: 'add' | 'role'; email: string; role: OperatorRole })
  => Promise<OperatorResult>;

// ── Injected effects ───────────────────────────────────────────────────

export interface OperatorAdminDeps {
  users(): AccountUserRow[];
  credentials(userId: number): AccountCredentialRow[];
  /** Sessions still usable: not revoked, not expired, not idle past the timeout. */
  liveSessions(userId: number): number;
  /** The newest unused, unexpired magic link, or null. */
  pendingLink(userId: number): PendingLinkRow | null;

  createOperator(email: string, role: OperatorRole): AccountUserRow;
  setRole(userId: number, role: OperatorRole): void;
  /** One transaction: credentials, sessions, links, then the row. Returns
   *  what it removed, for the audit line. */
  removeOperator(userId: number): { passkeys: number; sessions: number; links: number };
  revokeCredential(credId: number, actor: { username: string; role: string | null }): void;
  endSessionsForUser(userId: number): number;
  endSessionsForCredential(handle: string): number;

  /** Mint a link. The raw token comes back here and goes into the response;
   *  it is never handed to record() or log(). */
  issueLink(userId: number, purpose: 'enroll' | 'recover'): { url: string; expiresAt: number };
  /** Email it, when there is a channel and an address. `emailed:false` with
   *  no error is "there was nowhere to send it", which is the ordinary state
   *  of a box with no email channel. */
  sendLink(to: string, url: string): Promise<{ emailed: boolean; error?: string }>;

  /** The serial the next push would carry: this host's admin key digest. */
  fingerprint(): string;
  push(before: string, after: string): Promise<TrustPushOutcome>;
  sync(before: string, after: string): Promise<TrustLocalSyncOutcome>;

  record(e: {
    actor: string; actorRole: string | null; event: AuthEventKind;
    target: string | null; detail: Record<string, unknown> | null;
  }): void;
  log(line: string): void;
}

// ── Small shared helpers ───────────────────────────────────────────────

function iso(secs: number | null | undefined): string | null {
  if (typeof secs !== 'number' || !Number.isFinite(secs)) return null;
  return new Date(secs * 1000).toISOString();
}

function refuse(status: number, error: string, detail?: string): OperatorResult {
  return { status, body: detail ? { error, detail } : { error } };
}

/**
 * The identity, normalised.
 *
 * Email IS the account here (auth_users.username holds it), so the shape has
 * to be settled before anything is written. Lower-cased because a person who
 * types their address with a capital and then without it is one person, and
 * the column is UNIQUE but case-sensitive.
 */
export function normalizeEmail(raw: unknown): string {
  return String(raw ?? '').trim().toLowerCase();
}

/** Loose on purpose, the same latitude the CLI takes: deliverability is
 *  settled when the link is actually sent, not by a regular expression. */
export function emailLooksRight(email: string): boolean {
  if (!email || email.length > 254) return false;
  if (/\s/.test(email)) return false;
  return /^[^@]+@[^@]+\.[^@]+$/.test(email);
}

export function parseRole(raw: unknown): OperatorRole | null {
  return raw === 'admin' || raw === 'monitor' ? raw : null;
}

/** What the page shows a role as. A legacy 'operator' row can approve
 *  nothing, which is what a monitor is, so it reads as one. The RAW value is
 *  what every comparison below uses. */
export function displayRole(role: string): OperatorRole {
  return role === 'admin' ? 'admin' : 'monitor';
}

/**
 * Find an account by the email the page sent.
 *
 * Exact first, then case-insensitively: an account added from the CLI with a
 * capital in it is a real account, and it has to be manageable from the page
 * rather than reading as unknown. The email column is checked last, for rows
 * whose username and email differ.
 */
export function findAccount(users: AccountUserRow[], email: string): AccountUserRow | null {
  return users.find((u) => u.username === email)
    ?? users.find((u) => u.username.toLowerCase() === email)
    ?? users.find((u) => (u.email ?? '').toLowerCase() === email)
    ?? null;
}

/** Does any row already claim this identity, in any casing, on either
 *  column? What the duplicate refusal is built on. */
export function accountExists(users: AccountUserRow[], email: string): boolean {
  return users.some((u) => u.username.toLowerCase() === email || (u.email ?? '').toLowerCase() === email);
}

function adminCount(users: AccountUserRow[]): number {
  return users.filter((u) => u.role === 'admin').length;
}

// ── The accounts section of the overview ───────────────────────────────

/**
 * Every account, with what is true of it.
 *
 * Built from the user rows, NOT from the credential join: an account with no
 * passkey yet is exactly the account this page just created, and a join
 * would drop it on the one screen that has to show it.
 *
 * Sorted self first, then admins, then monitors, each group by email. Self
 * is resolved by user id and never by comparing the email string, because
 * the same comparison decides whether a removal is refused.
 */
export function buildAccounts(deps: OperatorAdminDeps, selfUserId: number | null, selfHandle: string | null = null): AccountView[] {
  const views = deps.users().map((u) => accountView(deps, u, selfUserId, selfHandle));
  const rank = (a: AccountView) => (a.is_self ? 0 : a.role === 'admin' ? 1 : 2);
  return views.sort((a, b) => rank(a) - rank(b) || a.email.localeCompare(b.email));
}

function accountView(deps: OperatorAdminDeps, u: AccountUserRow, selfUserId: number | null, selfHandle: string | null): AccountView {
  const link = deps.pendingLink(u.id);
  return {
    email: u.username,
    role: displayRole(u.role),
    is_self: selfUserId !== null && u.id === selfUserId,
    created_at: iso(u.created_at),
    last_login_at: iso(u.last_login_at),
    passkeys: deps.credentials(u.id).map((c) => ({
      id: c.id,
      device: c.name && c.name.trim() ? c.name : 'unnamed',
      signed_in: selfHandle !== null && c.credential_id === selfHandle,
      enrolled_at: iso(c.created_at),
      last_used_at: iso(c.last_used_at),
    })),
    sessions: deps.liveSessions(u.id),
    pending_link: link && (link.purpose === 'enroll' || link.purpose === 'recover')
      ? { purpose: link.purpose, issued_at: iso(link.created_at)!, expires_at: iso(link.expires_at)! }
      : null,
  };
}

/** One account by id, after a change, for the response envelope. */
function viewById(deps: OperatorAdminDeps, userId: number, sess: ActingSession): AccountView | null {
  const row = deps.users().find((u) => u.id === userId);
  return row ? accountView(deps, row, sess.userId, sess.credentialId ?? null) : null;
}

// ── The audit read ─────────────────────────────────────────────────────

/** 1..500, defaulting to 100. A page cannot ask for the whole table. */
export function clampAuditLimit(raw: string | null | undefined): number {
  // An absent limit is not a limit of zero. Number(null) is 0, which would
  // clamp to 1 and answer a page that asked for nothing with one row.
  if (raw === null || raw === undefined || raw.trim() === '') return 100;
  const n = Number(raw);
  if (!Number.isFinite(n)) return 100;
  return Math.min(500, Math.max(1, Math.floor(n)));
}

export interface AuditRow {
  id: number; at: number; actor: string; actor_role: string | null;
  event: string; target: string | null; detail: string | null;
}

/**
 * The rows as the page reads them. `detail` is parsed rather than passed
 * through as text: the page renders fields, and a row whose JSON did not
 * parse reads as no detail rather than as a string that looks like one.
 * Nothing is added here, because the recorder's rule (no key material, no
 * tokens) is what makes the table safe to serve at all.
 */
export function mapAuditEvents(rows: AuditRow[]): Array<Record<string, unknown>> {
  return rows.map((r) => {
    let detail: unknown = null;
    if (r.detail) {
      try { detail = JSON.parse(r.detail); } catch { detail = null; }
    }
    return {
      id: r.id,
      at: new Date(r.at * 1000).toISOString(),
      actor: r.actor,
      actor_role: r.actor_role,
      event: r.event,
      target: r.target,
      detail: detail && typeof detail === 'object' ? detail : null,
    };
  });
}

// ── The trust settlement ───────────────────────────────────────────────

/**
 * The CLI's per-node lines.
 *
 * `aperire-auth fleet-trust-push` prints one indented line per node and a
 * summary after them. Its words are what the page shows: replacing them with
 * a house sentence would lose the HTTP status a node refused with, which is
 * the only thing that tells an operator whether a node is unreachable or
 * simply not taking this aggregator's bundle.
 *
 * A line counts as a failure when it says failed, unreachable or refused.
 * That is the CLI's whole vocabulary for a bad outcome, and a line this
 * cannot classify is reported as a failure carrying its own text, never as a
 * success.
 */
export function parseTrustNodes(output: string): Array<{ label: string; ok: boolean; what: string }> {
  const nodes: Array<{ label: string; ok: boolean; what: string }> = [];
  for (const line of output.split('\n')) {
    const m = /^\s{1,4}([a-z0-9-]{1,32}):\s+(\S.*)$/.exec(line.replace(/\s+$/, ''));
    if (!m) continue;
    const what = m[2].trim();
    nodes.push({ label: m[1], ok: !/(failed|unreachable|refused)/i.test(what), what });
  }
  // A label printed twice is not a clean outcome whichever line says ok: one
  // of the two did not come from that node's own result (#1099).
  const counts = new Map<string, number>();
  for (const n of nodes) counts.set(n.label, (counts.get(n.label) ?? 0) + 1);
  for (const n of nodes) if ((counts.get(n.label) ?? 0) > 1) n.ok = false;
  return nodes;
}

function advisorSyncEnvelope(outcome: TrustLocalSyncOutcome): AdvisorSyncEnvelope {
  if (!outcome.ran) {
    const what = outcome.reason === 'serial_unchanged'
      ? 'the set of admin passkeys did not change, so the Advisor had nothing to take'
      : outcome.reason === 'disabled'
        ? 'trust changes from the dashboard are turned off on this host'
        : 'this host has no public_url, so the Advisor could not be told where approvals come from';
    return { attempted: false, ok: null, what };
  }
  if (!outcome.ok) {
    const what = outcome.reason === 'no_grant'
      ? 'this host has no trust-sync socket, so the Advisor did not take the change'
      : outcome.reason === 'refused'
        ? 'the Advisor refused the sync'
        : 'the sync did not complete';
    return { attempted: true, ok: false, what };
  }
  const trusted = outcome.trusted ?? null;
  const count = trusted === null ? 'the admin passkeys' : `${trusted} passkey${trusted === 1 ? '' : 's'}`;
  const what = outcome.advisorAgrees === false
    ? `the store was written (${count}) but the Advisor still reports a different fingerprint`
    : outcome.advisorAgrees === null
      ? `the store was written (${count}); the Advisor could not be read back to confirm`
      : `the Advisor now trusts ${count}`;
  return { attempted: true, ok: true, what };
}

/**
 * What a change to who may approve did to the fleet and to this host's own
 * Advisor.
 *
 * `before` is read by the caller BEFORE its write. That ordering is the
 * whole mechanism: both hooks short-circuit when the serial did not move, so
 * a serial read after the write would make every push a no-op that reported
 * itself as one.
 *
 * The two run in parallel because they touch different things (the fleet
 * over HTTP, the local Advisor over a socket) and each carries its own
 * timeout. Serialising them would put the endpoint's budget at the sum of
 * two 60 second bounds.
 */
export async function settleTrustChange(
  before: string, deps: OperatorAdminDeps,
): Promise<{ trust: TrustEnvelope; advisor_sync: AdvisorSyncEnvelope }> {
  const after = deps.fingerprint();
  const [pushed, synced] = await Promise.allSettled([deps.push(before, after), deps.sync(before, after)]);

  let trust: TrustEnvelope = { serial_before: before, serial_after: after, pushed: false, nodes: [] };
  if (pushed.status === 'fulfilled') {
    const out = pushed.value;
    trust = {
      serial_before: before,
      serial_after: after,
      pushed: out.ran === true && out.ok,
      // Kept on a failed push too. A run with two nodes that took it and one
      // that did not is precisely the case an operator opened this page for,
      // and dropping the rows when the exit code is nonzero would hide it.
      nodes: out.ran === true ? parseTrustNodes(out.output) : [],
    };
  } else {
    deps.log(`[operators] the trust push could not be run: ${(pushed.reason as Error).message}`);
  }

  const advisor_sync: AdvisorSyncEnvelope = synced.status === 'fulfilled'
    ? advisorSyncEnvelope(synced.value)
    : { attempted: true, ok: false, what: 'the sync could not be run' };
  if (synced.status === 'rejected') {
    deps.log(`[operators] the Advisor sync could not be run: ${(synced.reason as Error).message}`);
  }

  return { trust, advisor_sync };
}

// ── The guards ─────────────────────────────────────────────────────────

export type Validation<T> = { ok: true; value: T } | { ok: false; result: OperatorResult };

/**
 * May this email be added, as this role?
 *
 * Run at begin, before a passkey is spent, and again after the assertion
 * verifies: the window between the two halves is long enough for the same
 * account to be created from the CLI or from another browser.
 */
export function validateAdd(
  deps: OperatorAdminDeps, rawEmail: unknown, rawRole: unknown,
): Validation<{ email: string; role: OperatorRole }> {
  const email = normalizeEmail(rawEmail);
  if (!emailLooksRight(email)) {
    return { ok: false, result: refuse(400, 'that does not look like an email address') };
  }
  const role = parseRole(rawRole);
  if (!role) return { ok: false, result: refuse(400, 'role must be admin or monitor') };
  if (accountExists(deps.users(), email)) {
    return { ok: false, result: refuse(409, 'that operator already exists') };
  }
  return { ok: true, value: { email, role } };
}

/**
 * May this account's role be changed to this one?
 *
 * The order is the contract's: unknown, then already-that-role, then self,
 * then the last admin. Self is by user id. The role comparison is against
 * the RAW stored value, so a legacy 'operator' row can still be set to
 * 'monitor' explicitly.
 */
export function validateRoleChange(
  deps: OperatorAdminDeps, sess: ActingSession, rawEmail: unknown, rawRole: unknown,
): Validation<{ user: AccountUserRow; role: OperatorRole }> {
  const email = normalizeEmail(rawEmail);
  if (!emailLooksRight(email)) {
    return { ok: false, result: refuse(400, 'that does not look like an email address') };
  }
  const role = parseRole(rawRole);
  if (!role) return { ok: false, result: refuse(400, 'role must be admin or monitor') };
  const users = deps.users();
  const user = findAccount(users, email);
  if (!user) return { ok: false, result: refuse(404, 'no operator with that email') };
  if (user.role === role) return { ok: false, result: refuse(409, 'already that role') };
  if (user.id === sess.userId) {
    return { ok: false, result: refuse(403, 'you cannot change your own role') };
  }
  if (user.role === 'admin' && role === 'monitor' && adminCount(users) === 1) {
    return { ok: false, result: refuse(409, 'that is the last admin', 'Promote another operator first.') };
  }
  return { ok: true, value: { user, role } };
}

export function validateRemove(
  deps: OperatorAdminDeps, sess: ActingSession, rawEmail: unknown,
): Validation<AccountUserRow> {
  const email = normalizeEmail(rawEmail);
  if (!emailLooksRight(email)) {
    return { ok: false, result: refuse(400, 'that does not look like an email address') };
  }
  const users = deps.users();
  const user = findAccount(users, email);
  if (!user) return { ok: false, result: refuse(404, 'no operator with that email') };
  if (user.id === sess.userId) {
    return { ok: false, result: refuse(403, 'you cannot remove yourself') };
  }
  if (user.role === 'admin' && adminCount(users) === 1) {
    return { ok: false, result: refuse(409, 'that is the last admin', 'Add another admin first.') };
  }
  return { ok: true, value: user };
}

// ── The routes ─────────────────────────────────────────────────────────

export type OperatorRoute = 'add/begin' | 'add' | 'link' | 'role/begin' | 'role' | 'revoke' | 'remove';

export interface OperatorContext {
  session: ActingSession | null;
  payload: Record<string, unknown>;
  /** Verifies the assertion carried by THIS request. Called only when a
   *  challenge id was presented. */
  verify: GrantVerifier;
  /** Issues the challenge for a grant. */
  beginGrant: GrantBeginner;
  deps: OperatorAdminDeps;
}

/**
 * The one way in.
 *
 * The admin check here is deliberately a second copy of the dispatcher's.
 * settings-api.ts refuses a monitor before this file is reached, and if that
 * gate were ever moved, reordered or given a new route that skipped it, this
 * would still refuse. Nothing is read, written or spawned above it.
 */
export async function handleOperatorRoute(
  route: OperatorRoute, ctx: OperatorContext,
): Promise<OperatorResult> {
  const sess = ctx.session;
  if (!sess) return refuse(401, 'unauthenticated');
  if (sess.role !== 'admin') {
    return refuse(403, 'this operator may not change settings',
      `Role is ${sess.role}. Managing operators decides who can approve changes to the node, and that is an admin's to do.`);
  }
  switch (route) {
    case 'add/begin':  return beginAdd(ctx, sess);
    case 'add':        return applyAdd(ctx, sess);
    case 'link':       return applyLink(ctx, sess);
    case 'role/begin': return beginRole(ctx, sess);
    case 'role':       return applyRole(ctx, sess);
    case 'revoke':     return applyRevoke(ctx, sess);
    case 'remove':     return applyRemove(ctx, sess);
  }
}

async function beginAdd(ctx: OperatorContext, _sess: ActingSession): Promise<OperatorResult> {
  const v = validateAdd(ctx.deps, ctx.payload.email, ctx.payload.role);
  if (!v.ok) return v.result;
  return ctx.beginGrant({ action: 'add', email: v.value.email, role: v.value.role });
}

async function beginRole(ctx: OperatorContext, sess: ActingSession): Promise<OperatorResult> {
  const v = validateRoleChange(ctx.deps, sess, ctx.payload.email, ctx.payload.role);
  if (!v.ok) return v.result;
  return ctx.beginGrant({ action: 'role', email: v.value.user.username, role: v.value.role });
}

/** Was a ceremony presented, and did it authorise THIS action? Everything
 *  the grant carries comes from the record written at begin. */
async function grantFor(
  ctx: OperatorContext, action: 'add' | 'role',
): Promise<{ presented: false } | { presented: true; result: OperatorResult } | { presented: true; grant: VerifiedGrant }> {
  const chalId = typeof ctx.payload.challenge_id === 'string' ? ctx.payload.challenge_id.trim() : '';
  if (!chalId) return { presented: false };
  const verified = await ctx.verify();
  if (!verified.ok) return { presented: true, result: refuse(verified.status, verified.error) };
  if (verified.grant.action !== action) {
    // One signature, one grant. An assertion collected for an add is not
    // spendable on a role change, and the record says which it was.
    return { presented: true, result: refuse(403, 'that approval was for a different action') };
  }
  return { presented: true, grant: verified.grant };
}

async function applyAdd(ctx: OperatorContext, sess: ActingSession): Promise<OperatorResult> {
  const { deps } = ctx;
  const g = await grantFor(ctx, 'add');
  if ('result' in g) return g.result;

  let email: string;
  let role: OperatorRole;
  const passkeyChecked = 'grant' in g;
  if ('grant' in g) {
    email = g.grant.email;
    role = g.grant.role;
  } else {
    const v = validateAdd(deps, ctx.payload.email, ctx.payload.role ?? 'monitor');
    if (!v.ok) return v.result;
    if (v.value.role === 'admin') {
      // The privilege grant. An admin added without an assertion would mean
      // a stolen session could mint itself a second administrator, and the
      // session cookie alone is not the claim this needs.
      return refuse(403, 'adding an admin needs your passkey');
    }
    email = v.value.email;
    role = v.value.role;
  }

  // Again, after the ceremony: the same account can be created from the CLI
  // or another browser in the seconds a passkey touch takes.
  const recheck = validateAdd(deps, email, role);
  if (!recheck.ok) return recheck.result;

  const serialBefore = deps.fingerprint();
  const user = deps.createOperator(email, role);
  const link = deps.issueLink(user.id, 'enroll');
  const sent = await deps.sendLink(email, link.url);
  if (sent.error) deps.log(`[operators] the enrollment email for the new operator did not send: ${sent.error}`);

  // The token is in `link.url` and goes into the response below. Neither row
  // here carries it, or the address it was sent to.
  deps.record({
    actor: sess.username, actorRole: sess.role, event: 'magic_link_issued',
    target: email, detail: { purpose: 'enroll', emailed: sent.emailed },
  });
  deps.record({
    actor: sess.username, actorRole: sess.role, event: 'operator_added',
    target: email, detail: { role, via: 'settings', passkey_checked: passkeyChecked },
  });

  // A brand new account holds no passkey, so the admin key set cannot have
  // moved. Settled anyway, through the same helper as every other write, so
  // the page reads one shape and the "nothing to push" case is the hooks'
  // own answer rather than a value written here.
  const settled = await settleTrustChange(serialBefore, deps);
  return {
    status: 200,
    body: {
      ok: true,
      account: viewById(deps, user.id, sess),
      link: {
        url: link.url, purpose: 'enroll',
        expires_at: new Date(link.expiresAt * 1000).toISOString(),
        emailed: sent.emailed,
      },
      ...settled,
    },
  };
}

async function applyLink(ctx: OperatorContext, sess: ActingSession): Promise<OperatorResult> {
  const { deps } = ctx;
  const email = normalizeEmail(ctx.payload.email);
  if (!emailLooksRight(email)) return refuse(400, 'that does not look like an email address');
  const purpose = ctx.payload.purpose === 'recover' ? 'recover'
    : ctx.payload.purpose === 'enroll' || ctx.payload.purpose === undefined ? 'enroll' : null;
  if (!purpose) return refuse(400, 'purpose must be enroll or recover');
  const user = findAccount(deps.users(), email);
  if (!user) return refuse(404, 'no operator with that email');

  const serialBefore = deps.fingerprint();
  const link = deps.issueLink(user.id, purpose);
  const sent = await deps.sendLink(user.email ?? user.username, link.url);
  if (sent.error) deps.log(`[operators] the enrollment email did not send: ${sent.error}`);
  deps.record({
    actor: sess.username, actorRole: sess.role, event: 'magic_link_issued',
    target: user.username, detail: { purpose, emailed: sent.emailed },
  });

  const settled = await settleTrustChange(serialBefore, deps);
  return {
    status: 200,
    body: {
      ok: true,
      account: viewById(deps, user.id, sess),
      link: {
        url: link.url, purpose,
        expires_at: new Date(link.expiresAt * 1000).toISOString(),
        emailed: sent.emailed,
      },
      ...settled,
    },
  };
}

async function applyRole(ctx: OperatorContext, sess: ActingSession): Promise<OperatorResult> {
  const { deps } = ctx;
  const g = await grantFor(ctx, 'role');
  if ('result' in g) return g.result;

  const rawEmail = 'grant' in g ? g.grant.email : ctx.payload.email;
  const rawRole = 'grant' in g ? g.grant.role : ctx.payload.role;

  // Every guard, and for a ceremony every guard AGAIN: a demotion elsewhere
  // can have made this operator the last admin while the passkey was being
  // touched.
  const v = validateRoleChange(deps, sess, rawEmail, rawRole);
  if (!v.ok) return v.result;
  const { user, role } = v.value;
  if (!('grant' in g) && role === 'admin') {
    // After the guards, so an operator asking for something impossible is
    // told what is wrong with it rather than being sent to their
    // authenticator for a change that would be refused afterwards.
    return refuse(403, 'promoting to admin needs your passkey');
  }

  // Read BEFORE the write. Both are: the serial, because the hooks short
  // circuit when it did not move and reading it afterwards would make every
  // push a no-op; the role, because it is the `from` of the audit row and
  // the write is what destroys it.
  const serialBefore = deps.fingerprint();
  const previousRole = user.role;
  deps.setRole(user.id, role);
  deps.record({
    actor: sess.username, actorRole: sess.role, event: 'role_change',
    target: user.username, detail: { from: previousRole, to: role, via: 'settings' },
  });

  if (role === 'monitor') {
    // A live session carries what its holder may do. Demotion that left the
    // open tabs alone would mean the operator keeps approving until they
    // sign out.
    const sessionsEnded = deps.endSessionsForUser(user.id);
    if (sessionsEnded > 0) {
      deps.log(`[operators] ${user.username} was demoted; ${sessionsEnded} live session(s) ended`);
    }
  }

  const settled = await settleTrustChange(serialBefore, deps);
  return {
    status: 200,
    body: { ok: true, account: viewById(deps, user.id, sess), ...settled },
  };
}

async function applyRevoke(ctx: OperatorContext, sess: ActingSession): Promise<OperatorResult> {
  const { deps } = ctx;
  const rawId = ctx.payload.credential_id;
  const users = deps.users();

  let owner: AccountUserRow | null = null;
  let targets: AccountCredentialRow[] = [];

  if (rawId !== undefined && rawId !== null) {
    const credId = Number(rawId);
    if (!Number.isInteger(credId) || credId <= 0) return refuse(400, 'that is not a passkey id');
    for (const u of users) {
      const found = deps.credentials(u.id).find((c) => c.id === credId);
      if (found) { owner = u; targets = [found]; break; }
    }
    if (!owner) return refuse(404, 'no passkey with that id');
  } else if (ctx.payload.email !== undefined) {
    const email = normalizeEmail(ctx.payload.email);
    if (!emailLooksRight(email)) return refuse(400, 'that does not look like an email address');
    owner = findAccount(users, email);
    if (!owner) return refuse(404, 'no operator with that email');
    targets = deps.credentials(owner.id);
    if (targets.length === 0) return refuse(404, 'that operator has no passkeys');
  } else {
    return refuse(400, 'name a passkey id or an operator');
  }

  // The passkey this session signed in with stays. Revoking it ends the
  // session doing the revoking, and with one admin and no email channel
  // there is then nothing left that can sign in. Both forms hit this: the
  // id of that passkey, and "every passkey" of the account that holds it.
  if (sess.credentialId && targets.some((c) => c.credential_id === sess.credentialId)) {
    return refuse(403, 'that is the passkey you are signed in with', 'Sign in with another passkey to revoke this one.');
  }

  const serialBefore = deps.fingerprint();
  // The handles are read here, while the rows still exist: a session is
  // bound to the WebAuthn handle, not to the row id, and after the delete
  // there is nothing left to match a session against.
  const handles = targets.map((c) => c.credential_id);
  for (const cred of targets) deps.revokeCredential(cred.id, { username: sess.username, role: sess.role });
  let sessionsEnded = 0;
  for (const handle of handles) sessionsEnded += deps.endSessionsForCredential(handle);
  if (sessionsEnded > 0) {
    deps.log(`[operators] ${targets.length} passkey(s) revoked for ${owner.username}; ${sessionsEnded} session(s) ended`);
  }

  const settled = await settleTrustChange(serialBefore, deps);
  return {
    status: 200,
    body: {
      ok: true,
      account: viewById(deps, owner.id, sess),
      revoked: targets.length,
      ...settled,
    },
  };
}

async function applyRemove(ctx: OperatorContext, sess: ActingSession): Promise<OperatorResult> {
  const { deps } = ctx;
  const v = validateRemove(deps, sess, ctx.payload.email);
  if (!v.ok) return v.result;
  const user = v.value;

  const serialBefore = deps.fingerprint();
  const previousRole = user.role;
  const removed = deps.removeOperator(user.id);
  deps.record({
    actor: sess.username, actorRole: sess.role, event: 'operator_removed',
    target: user.username,
    detail: {
      role: previousRole, passkeys: removed.passkeys, sessions: removed.sessions,
      links: removed.links, via: 'settings',
    },
  });
  deps.log(`[operators] ${user.username} was removed by ${sess.username}`);

  const settled = await settleTrustChange(serialBefore, deps);
  // No account: there is no longer one to describe.
  return { status: 200, body: { ok: true, removed, ...settled } };
}
