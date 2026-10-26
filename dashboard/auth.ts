// Aperire — operator authentication via WebAuthn / passkeys (Phase A1).
//
// Self-contained: no external IdP, no third-party SDK at runtime apart
// from @simplewebauthn/server for the cryptographic ceremony. Sessions
// live in sqlite (auth_sessions); the cookie carries a 256-bit random
// session id and nothing else. The DB stores only the SHA-256 of that
// id (auth_sessions.id) — the raw id never hits disk, and readSession
// hashes the incoming cookie before lookup, so a DB read yields nothing
// replayable. Magic-link tokens follow the same pattern (raw in the URL,
// hash in auth_magic_links.token). Operator records are bootstrapped via
// the SSH CLI (scripts/aperire-auth.sh) — no web-side user creation.
//
// This module exposes:
//   - the request handler dispatcher (handleAuthRequest)
//   - the requireAuth(req) check used by server.ts middleware in A2
//   - small DB helpers for the SSH CLI
//
// Phase boundaries:
//   A1 — schema + endpoints + CLI (this file). Routes are live but
//        nothing enforces them yet.
//   A2 — wires requireAuth into server.ts so unauth requests bounce.
//   A3 — idle timeout + auth.yaml config.
//   A4 — top-right auth pill + docs.
//
// Cookie shape: `apr_sess=<sessionId>; HttpOnly; SameSite=Lax;
// Path=/; Max-Age=<absolute cap>` plus `Secure` by default in
// production. Secure is NOT decided by the inbound x-forwarded-proto
// header (an attacker could strip it) — it is on unless this is a
// genuine local-dev loopback request. APERIRE_FORCE_SECURE_COOKIES=true
// forces it on unconditionally.

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
  type AuthenticatorTransportFuture,
} from '@simplewebauthn/server';
import { createHash, randomBytes } from 'node:crypto';
import { sealModelKey, SEAL_FIELD_RULES, type SealRunner } from './lib/model-seal.js';
import { readFileSync } from 'node:fs';
import { deviceLabel } from './lib/device-label.js';
import { credentialDigest } from './lib/trust-fingerprint.js';
import { pushTrustAfterEnrollment, type TrustPushOutcome } from './lib/trust-push-hook.js';
import { syncLocalTrustAfterEnrollment, TRUST_SYNC_SOCKET, type TrustLocalSyncOutcome } from './lib/trust-local-sync.js';
import { askSocketProgram } from './lib/socket-program.js';
import {
  windowStateFor, checkOperatorName, setupStateFor,
  type SetupState, type WindowClosure,
} from './lib/bootstrap-window.js';
import type { OperatorRole, OperatorResult, VerifiedGrant, GrantOutcome } from './lib/operator-admin.js';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import type { IncomingMessage, ServerResponse } from 'node:http';
import yaml from 'js-yaml';

import { db, hashToken, recordAuthEvent } from './db.js';
import { sendDigestEmail } from './email.js';
import { readBodyOrThrow } from './lib/read-body.js';
import { postAdvisorApprove, postAdvisorCancel } from './lib/advisor-approve-call.js';
import { edgeSafeStatus, edgeSafeRelay } from './lib/peer-advisor-answer.js';

// ── Configuration ──────────────────────────────────────────────────
// Source-of-truth precedence (highest first):
//   1. Env var (APERIRE_RP_ID etc.) — escape hatch for ad-hoc testing
//   2. authn.yaml at mockup/config/authn.yaml — operator-edited
//   3. Hardcoded localhost defaults
//
// rpID is the eTLD+1 of the dashboard URL — must match exactly what
// the browser sees in window.location, otherwise WebAuthn refuses to
// issue / verify credentials. Origin is the full URL.
//
// rp_id and public_url accept comma-separated lists so a single deploy
// can authenticate over multiple origins (e.g. localhost + the public
// Cloudflare URL during a migration window).
interface AuthnYaml {
  db_path?: string;
  public_url?: string;
  rp_id?:    string;
  rp_name?:  string;
  session?:  { idle_timeout_minutes?: number; idle_warning_seconds?: number };
  magic_link?: { ttl_minutes?: number; send_via_email?: boolean; email_subject?: string };
}
let authnConfigCache: AuthnYaml | null = null;
function loadAuthnConfig(): AuthnYaml {
  if (authnConfigCache) return authnConfigCache;
  const path = process.env.APERIRE_AUTHN_YAML
    ?? join(import.meta.dirname, 'config', 'authn.yaml');
  try {
    const text = readFileSync(path, 'utf8');
    authnConfigCache = (yaml.load(text) as AuthnYaml) || {};
    console.log(`[authn] loaded ${path}`);
  } catch (err) {
    authnConfigCache = {};
    console.warn(`[authn] ${path} not loaded (${(err as Error).message}) — using env / defaults`);
  }
  return authnConfigCache;
}

function rpName(): string {
  return process.env.APERIRE_RP_NAME || loadAuthnConfig().rp_name || 'Aperire';
}

// Session policy — idle timeout + warning window. 0 disables idle
// timeout (cookie max-age remains the only boundary; not recommended
// in prod).
function idleTimeoutMs(): number {
  const min = loadAuthnConfig().session?.idle_timeout_minutes ?? 30;
  return min > 0 ? min * 60 * 1000 : 0;
}
function idleWarningMs(): number {
  const sec = loadAuthnConfig().session?.idle_warning_seconds ?? 60;
  return Math.max(0, sec) * 1000;
}
function rpIDs(): string[] {
  const raw = process.env.APERIRE_RP_ID || loadAuthnConfig().rp_id || 'localhost';
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}
/**
 * The origins WebAuthn will accept a ceremony from.
 *
 * The configured public_url is the answer, plus one defensive addition: the
 * loopback origin on the port this process is ACTUALLY listening on.
 *
 * That addition exists because of a real failure. authn.yaml.example ships
 * `public_url: http://localhost:7800`, the installer copied it verbatim, and
 * an install made with `--port 7900` therefore told SimpleWebAuthn to expect
 * localhost:7800 while the browser was on localhost:7900. expectedOrigin
 * mismatched and EVERY enrollment failed, with nothing on the page naming a
 * port. The installer now writes the real port, but a config can also be
 * hand-copied between hosts or survive a port change, and a stale one must
 * not be able to lock an operator out of the box over the loopback tunnel
 * they are already trusted to be inside.
 *
 * Why this is not a widening of trust: an origin is only ever compared
 * against what the browser reports for a ceremony this server itself issued
 * a challenge for, and reaching http://localhost:<our port> already means
 * being on this host or inside an authenticated tunnel to it. It adds the
 * address the operator is demonstrably already using. It does NOT add a
 * public hostname, a wildcard, or anything derived from a request header.
 */
function origins(): string[] {
  const raw = process.env.APERIRE_RP_ORIGIN || loadAuthnConfig().public_url || 'http://localhost:7800';
  const configured = raw.split(',').map(s => s.trim()).filter(Boolean);
  // Same default as server.ts's own PORT, read from the same env.
  const port = Number(process.env.PORT ?? 7800);
  const loopback = `http://localhost:${port}`;
  const norm = (u: string) => u.replace(/\/+$/, '');
  return configured.some(o => norm(o) === loopback) ? configured : [...configured, loopback];
}

// Exported so the WS upgrade handler (server.ts) can enforce the same
// expected-origin set WebAuthn pins credentials to — the configured
// public_url(s), not anything derived from request headers. Returned
// with trailing slashes stripped so a browser's `Origin` header (never
// has a trailing slash) compares cleanly. This is the single source of
// truth for "which origins are allowed to open a same-origin socket."
// Which node this dashboard is, for the lock screen's manual-enrollment
// hint. On a host running more than one instance, the CLI shim resolves to
// ONE install and mints links for it alone — the operator followed this
// page's own instruction and got a link for the wrong node (D6 §4.7). The
// label is operator-chosen and already public in the fleet chip, so
// disclosing it pre-auth reveals nothing a filesystem path would; it is
// set from the fleet registry's self row after load (and reload), null on
// a single-node install where the ambiguity cannot exist.
let instanceLabel: string | null = null;
export function setInstanceLabel(label: string | null): void { instanceLabel = label; }

/**
 * What this dashboard IS, for the Settings page's last section: the rp_id
 * passkeys are bound to, the origins a ceremony is accepted from, and the
 * public URL an operator reaches it at.
 *
 * From authn.yaml, the same first-entry reading `aperire-auth advisor-sync`
 * does, plus the origins() set WebAuthn actually verifies against. A page
 * that showed something derived from a request header would be showing the
 * browser's opinion of this host rather than this host's own (the Overview
 * HOST field already made that mistake once).
 */
export function dashboardIdentity(): { rp_id: string; origins: string[]; public_url: string | null } {
  const cfg = loadAuthnConfig();
  const first = (v: string | undefined) => (v ?? '').split(',')[0].trim();
  return {
    rp_id: rpIDs()[0] ?? '',
    origins: expectedOrigins(),
    public_url: first(cfg.public_url).replace(/\/+$/, '') || null,
  };
}

export function expectedOrigins(): string[] {
  return origins().map(o => o.replace(/\/$/, ''));
}

// True when no origin is explicitly configured — i.e. we fell back to
// the localhost default with no env/yaml override. In that mode the WS
// handler treats loopback origins leniently for local dev instead of
// hard-failing, but still never trusts an arbitrary public Host/Origin.
export function originExplicitlyConfigured(): boolean {
  return !!(process.env.APERIRE_RP_ORIGIN || loadAuthnConfig().public_url);
}

// Cookie names. apr_sess survives across visits; apr_chal is short-
// lived and only present during a registration / authentication
// ceremony so the /finish endpoint can find the matching challenge.
// Instance-scoped: cookies are host-scoped and PORT-BLIND, so two instances
// of this dashboard behind one hostname — the central-viewing-host topology,
// or a lab box running a sibling on another port — shared one cookie jar.
// Signing into the second overwrote apr_sess for the first, which then read
// a hash absent from its own database and silently showed the lock screen,
// indistinguishable from an expired session (D6 §4.2, observed live). The
// port is the natural instance discriminator on a shared host; the default
// port keeps the bare historical names so every existing single-node
// install keeps its sessions across this change.
const INSTANCE_PORT = Number(process.env.PORT ?? 7800);
const COOKIE_SUFFIX = INSTANCE_PORT === 7800 ? '' : `_${INSTANCE_PORT}`;
const SESSION_COOKIE   = 'apr_sess' + COOKIE_SUFFIX;
const CHALLENGE_COOKIE = 'apr_chal' + COOKIE_SUFFIX;
// Absolute session lifetime (MED-03). A session is invalid once it is
// older than created_at + this cap, REGARDLESS of idle activity — so
// /auth/touch can keep a session alive against the idle timeout but can
// never push it past the absolute boundary. The idle timeout (A3,
// idleTimeoutMs) is the shorter, sliding boundary; this is the hard
// ceiling. Cookie Max-Age is aligned to the same value so the browser
// drops the cookie at the same moment the server stops honoring it.
const SESSION_ABSOLUTE_TTL_S = 7 * 24 * 60 * 60;     // 7 days — hard ceiling
const SESSION_MAX_AGE_S      = SESSION_ABSOLUTE_TTL_S;
const CHALLENGE_TTL_MS    = 5 * 60 * 1000;           // 5 min
// Bound on the in-memory challenge map (MED-04). Each /login/begin or
// /register/begin allocates one entry; without a ceiling a flood of
// begins is an unbounded-memory DoS. When full we evict the oldest
// entry (a stale in-flight ceremony) to make room — legitimate
// ceremonies complete in seconds, so eviction only ever sheds abuse or
// abandoned attempts.
const MAX_PENDING_CHALLENGES = 4000;

// ── DB statements (auth-only — table DDL lives in db.ts) ────────────
const insertUser = db.prepare(`
  INSERT INTO auth_users (username, email, role, created_at)
  VALUES (?, ?, 'operator', ?)
`);
const findUserByUsername = db.prepare(`
  SELECT id, username, email, role, created_at, last_login_at
    FROM auth_users WHERE username = ?
`);
const findUserById = db.prepare(`
  SELECT id, username, email, role, created_at, last_login_at
    FROM auth_users WHERE id = ?
`);
const listUsers = db.prepare(`
  SELECT id, username, email, role, created_at, last_login_at
    FROM auth_users ORDER BY id ASC
`);
const updateUserLastLogin = db.prepare(`
  UPDATE auth_users SET last_login_at = ? WHERE id = ?
`);

// ── The bootstrap window (#135 Step 1) ──────────────────────────────
//
// See lib/bootstrap-window.ts for what the window IS and why it keys on a
// user row rather than on a passkey. These are the two statements that
// read and close it.
const countUsers = db.prepare(`SELECT COUNT(*) AS n FROM auth_users`);

// When this box was claimed, read off the same table the count is read off.
// Kept for the one caller that wants the operator rows' own answer; the
// window's date comes off the durable record below, because that is the one
// that still answers after every operator row has been deleted.
const firstUserCreatedAt = db.prepare(`SELECT MIN(created_at) AS at FROM auth_users`);

// The durable close (#135). The EARLIEST of the two rows that can record this
// box being owned, so re-running either never moves the date, and so a box
// that was observed as owned and then claimed through the window still reads
// back the first thing that happened to it.
//
// auth_events rather than a column on auth_users, deliberately:
// `aperire-auth del` deletes operator rows and this table is untouched by it,
// nothing in this product updates or deletes a row here, and a restore that
// brought back only the audit still knows this box has an owner. See
// lib/bootstrap-window.ts.
const findWindowClosure = db.prepare(`
  SELECT at, event FROM auth_events
   WHERE event IN ('first_admin_created', 'setup_window_closed')
   ORDER BY at ASC, id ASC LIMIT 1
`);

// The close, as ONE statement.
//
// A count-then-insert would be a race with a window between the two reads:
// two browsers on a fresh box both see zero and both create an admin, and
// the box has two owners neither of whom chose the other. The WHERE NOT
// EXISTS makes the check part of the write, so SQLite's write lock settles
// it: exactly one INSERT reports changes() === 1 and every other reports 0.
//
// The role is the literal 'admin' HERE, in the statement, and is never read
// from the request body. The first operator on a box has to be able to
// approve things or the box cannot be administered at all, and a role that
// arrived over the wire during the one unauthenticated write this product
// has would be a role an attacker chose.
//
// The second NOT EXISTS is the 2026-09-17 ruling, kept inside the write
// rather than in front of it. A box that has been owned once has a row on the
// audit that says so, and deleting every operator does not remove it, so an
// emptied box fails this statement for the same reason an owned one does.
// Putting it here rather than only in the handler means the durable fact is
// checked in the same statement that writes, with no gap of any size, exactly
// as the count is.
const insertFirstAdmin = db.prepare(`
  INSERT INTO auth_users (username, email, role, created_at)
  SELECT ?, ?, 'admin', ?
   WHERE NOT EXISTS (SELECT 1 FROM auth_users)
     AND NOT EXISTS (
       SELECT 1 FROM auth_events
        WHERE event IN ('first_admin_created', 'setup_window_closed')
     )
`);

const insertCredential = db.prepare(`
  INSERT INTO auth_credentials
    (user_id, credential_id, public_key, sign_count, transports, name, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const findCredentialById = db.prepare(`
  SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at
    FROM auth_credentials WHERE credential_id = ?
`);
// The credentials the Advisor should be trusting: every admin's, and nothing
// else. Digested the same way the Advisor digests its own store, so the two
// can be compared without either handing the other its contents.
const adminCredentialsStmt = db.prepare(`
  SELECT c.credential_id, c.public_key
    FROM auth_credentials c JOIN auth_users u ON u.id = c.user_id
   WHERE u.role = 'admin'
`);

/**
 * Every enrolled passkey, with the account it belongs to and that account's
 * role. What `aperire-auth list-credentials` shows, for the Settings page's
 * Operators section, from the same tables.
 *
 * No key material and no credential handle. The public key is not a secret,
 * but it is also not a fact an operator reads a page for, and a payload that
 * carries it is a payload that ends up in a browser cache and a screenshot.
 * What is here is who, on what device, since when.
 */
const operatorPasskeysStmt = db.prepare(`
  SELECT c.id AS id, COALESCE(c.name, '') AS device, u.username AS user,
         u.role AS role, c.created_at AS enrolled_at, c.last_used_at AS last_used_at
    FROM auth_credentials c JOIN auth_users u ON u.id = c.user_id
   ORDER BY u.username ASC, c.id ASC
`);

export interface OperatorPasskey {
  id: number;
  device: string;
  user: string;
  role: string;
  /** Unix seconds, as the table stores them. Formatted by the page, never
   *  here: a server-formatted time freezes between requests. */
  enrolled_at: number;
  last_used_at: number | null;
}

export function listOperatorPasskeys(): OperatorPasskey[] {
  return operatorPasskeysStmt.all() as OperatorPasskey[];
}

/**
 * Fingerprint of who may approve, read from the dashboard's own tables.
 *
 * The digest itself lives in lib/trust-fingerprint.ts, where it has no
 * database to reach and can be pinned against the Advisor's Go twin. This is
 * only the query that feeds it.
 */
export function trustFingerprint(): { fingerprint: string; credentials: number } {
  const rows = adminCredentialsStmt.all() as Array<{ credential_id: string; public_key: string }>;
  return { fingerprint: credentialDigest(rows), credentials: rows.length };
}

// Where the CLI lives, and which database it must open. Resolved the same way
// db.ts resolves its own path, from this file's location rather than from the
// working directory — a service started by systemd has no useful cwd, and a
// dev instance pointed at its own database with APERIRE_DB_PATH must not push
// the admin set of the production one.
const REPO_DIR = resolve(import.meta.dirname, '..');
const DB_PATH = process.env.APERIRE_DB_PATH
  ? resolve(process.env.APERIRE_DB_PATH)
  : resolve(import.meta.dirname, '..', 'data', 'aperire.db');

/** execFile as the hook wants it: never rejects on a nonzero exit, because a
 *  nonzero exit is the answer rather than an error. */
function runTrustPush(
  cmd: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number },
): Promise<{ code: number; output: string }> {
  return new Promise((res) => {
    execFile(cmd, args, {
      cwd: opts.cwd, env: opts.env, timeout: opts.timeoutMs, maxBuffer: 1 << 20,
    }, (err, stdout, stderr) => {
      const output = `${stdout ?? ''}${stderr ?? ''}`;
      const code = err ? ((err as NodeJS.ErrnoException & { code?: number }).code ?? 1) : 0;
      res({ code: typeof code === 'number' ? code : 1, output });
    });
  });
}

const listCredentialsForUser = db.prepare(`
  SELECT id, user_id, credential_id, public_key, sign_count, transports, name, created_at, last_used_at
    FROM auth_credentials WHERE user_id = ? ORDER BY id ASC
`);
const updateCredentialCounter = db.prepare(`
  UPDATE auth_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?
`);
const deleteCredential = db.prepare(`
  DELETE FROM auth_credentials WHERE id = ?
`);

// credential_id records WHICH passkey opened the session, so an Advisor
// approval can be pinned to that authenticator rather than to any key
// registered against the account. NULL for a registration-issued session,
// where no assertion has happened yet.
const insertSession = db.prepare(`
  INSERT INTO auth_sessions
    (id, user_id, created_at, last_activity_at, expires_at, user_agent, ip, credential_id)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
const findSessionById = db.prepare(`
  SELECT s.id, s.user_id, s.created_at, s.last_activity_at, s.expires_at,
         s.revoked_at, s.user_agent, s.ip, s.credential_id,
         u.username, u.email, u.role
    FROM auth_sessions s
    JOIN auth_users u ON u.id = s.user_id
   WHERE s.id = ?
`);
const touchSession = db.prepare(`
  UPDATE auth_sessions SET last_activity_at = ? WHERE id = ?
`);
const revokeSession = db.prepare(`
  UPDATE auth_sessions SET revoked_at = ? WHERE id = ?
`);

// What "live" means for a session row, written once. It is the test
// readSession puts to a presented cookie: not revoked, inside the 7-day cap
// (by expires_at, and by created_at for a row minted under the old 1-year
// policy), and, when an idle timeout is set, active within it. The count the
// Settings page shows uses LIVE_SESSION, and the sweep below ends exactly the
// rows IDLE_SESSION names, which are the live rows that fail only the idle
// test. Neither can drift from readSession's rule or from the other.
// Bound by liveBounds().
const OPEN_SESSION = `revoked_at IS NULL AND expires_at >= ? AND created_at >= ?`;
const LIVE_SESSION = `${OPEN_SESSION} AND last_activity_at >= ?`;
const IDLE_SESSION = `${OPEN_SESSION} AND last_activity_at < ?`;
function liveBounds(nowMs: number): [number, number, number] {
  const nowS = Math.floor(nowMs / 1000);
  const timeoutMs = idleTimeoutMs();
  return [
    nowS,
    nowS - SESSION_ABSOLUTE_TTL_S,
    // readSession kills a session idle for MORE than the timeout; 0 turns
    // the idle timeout off, and then no row is idle.
    timeoutMs > 0 ? (nowMs - timeoutMs) / 1000 : Number.MIN_SAFE_INTEGER,
  ];
}
const endIdleSessionsStmt = db.prepare(`UPDATE auth_sessions SET revoked_at = ? WHERE ${IDLE_SESSION}`);
// Past the cap is dead whatever any setting says, so this one needs no
// config. Everything younger stays, revoked or not: its user agent, address,
// credential and times are the only record of who signed in.
const deleteOldSessionsStmt = db.prepare(`DELETE FROM auth_sessions WHERE created_at < ?`);

/**
 * Keep the table honest and bounded. Ends the sessions that went idle (marks
 * them revoked, which is what readSession does the next time their cookie is
 * presented, so nothing observable changes except that a cookie nobody
 * presents again no longer reads as open), then deletes rows created more
 * than the cap ago. Returns how many of each.
 */
export function sweepSessions(nowMs: number = Date.now()): { ended: number; deleted: number } {
  const bounds = liveBounds(nowMs);
  const ended = endIdleSessionsStmt.run(bounds[0], ...bounds).changes;
  const deleted = deleteOldSessionsStmt.run(bounds[1]).changes;
  return { ended, deleted };
}

/**
 * The session for a sign-in that has just been proven; returns the raw id
 * for the cookie. Both sign-in paths end here (a passkey assertion, and a
 * passkey just enrolled), so this is where the table is kept bounded: a
 * session is only ever added at a sign-in, and each sign-in first sweeps, so
 * the table holds at most one cap's worth of sign-ins.
 *
 * Raw id goes in the cookie; the DB stores only its SHA-256 (see
 * readSession, which hashes the presented cookie before lookup).
 */
export function issueSession(
  req: IncomingMessage, userId: number, credentialId: string | null, ts: number,
): string {
  try {
    const { ended, deleted } = sweepSessions();
    if (ended > 0 || deleted > 0) {
      console.log(`[authn] sessions swept: ${ended} idle ended, ${deleted} past the cap deleted`);
    }
  } catch (err) {
    // Housekeeping only: the operator just proved a passkey, and old rows
    // that could not be swept must not cost them the session.
    console.warn('[authn] session sweep failed:', (err as Error).message);
  }
  const sid = randomBytes(32).toString('base64url');
  const ua = String(req.headers['user-agent'] ?? '').slice(0, 200);
  const ip = String(req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '').slice(0, 64);
  insertSession.run(hashToken(sid), userId, ts, ts, ts + SESSION_MAX_AGE_S, ua, ip, credentialId);
  return sid;
}

const insertMagicLink = db.prepare(`
  INSERT INTO auth_magic_links (token, user_id, purpose, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?)
`);
const findMagicLink = db.prepare(`
  SELECT id, token, user_id, purpose, created_at, expires_at, consumed_at
    FROM auth_magic_links WHERE token = ?
`);
const consumeMagicLink = db.prepare(`
  UPDATE auth_magic_links SET consumed_at = ? WHERE id = ?
`);

// ── Public DB helpers (used by SSH CLI) ────────────────────────────
export interface AuthUser {
  id: number; username: string; email: string | null;
  role: string; created_at: number; last_login_at: number | null;
}
export interface AuthCredential {
  id: number; user_id: number; credential_id: string; public_key: string;
  sign_count: number; transports: string | null; name: string | null;
  created_at: number; last_used_at: number | null;
}

export function createUser(username: string, email: string | null): AuthUser {
  const ts = Math.floor(Date.now() / 1000);
  const result = insertUser.run(username, email, ts);
  return {
    id: Number(result.lastInsertRowid),
    username, email,
    role: 'operator',
    created_at: ts, last_login_at: null,
  };
}
export function getUserByUsername(username: string): AuthUser | null {
  return (findUserByUsername.get(username) as AuthUser | undefined) ?? null;
}
/** How many operators this box has. The bootstrap window is open at 0. */
export function operatorCount(): number {
  return (countUsers.get() as { n: number }).n;
}

/**
 * The durable close, read once and then remembered.
 *
 * Memoised in one direction only. A window that is shut can never open, so
 * once a row has been seen there is nothing to re-read and the gate stops
 * querying on every request. While it is still open there is no memo, so the
 * query runs, which is correct: that box's answer can still change, and on a
 * box in that state the audit table is a handful of rows.
 */
let windowClosureMemo: WindowClosure | null = null;

function readWindowClosure(): WindowClosure | null {
  if (windowClosureMemo) return windowClosureMemo;
  const row = findWindowClosure.get() as { at: number; event: string } | undefined;
  if (!row) return null;
  windowClosureMemo = {
    at: row.at,
    why: row.event === 'first_admin_created' ? 'first_admin_created' : 'observed_operator',
  };
  return windowClosureMemo;
}

/**
 * Record that this box is owned, if it is and nothing says so yet.
 *
 * The other half of the close, for every operator this window did not create:
 * `aperire-auth add`, an admin adding a colleague, or a box that was already
 * owned before this record existed. Written once, and from then on the row is
 * what keeps the window shut when the operator rows go away.
 *
 * Called from the read below rather than from the CLI, because the CLI is a
 * bash script writing SQLite directly and a rule enforced in two languages is
 * a rule that will disagree with itself. This process notices instead.
 */
function sealWindowIfOwned(count: number): WindowClosure | null {
  if (count <= 0) return null;
  const seen = readWindowClosure();
  if (seen) return seen;
  recordAuthEvent({
    actor: 'setup', event: 'setup_window_closed',
    target: null,
    detail: {
      via: 'observed an operator this window did not create',
      operators: count,
      note: 'first-run setup cannot reopen on this box, whatever happens to these operators',
    },
  });
  return readWindowClosure();
}

/** True while the browser may create the first administrator. */
export function bootstrapWindowOpen(): boolean {
  const count = operatorCount();
  const closure = readWindowClosure() ?? sealWindowIfOwned(count);
  return windowStateFor({ operatorCount: count, closure }) === 'open';
}

/** When this box was recorded as owned, and by which of the two routes. */
export function windowClosure(): WindowClosure | null {
  const closure = readWindowClosure();
  if (closure) return closure;
  return sealWindowIfOwned(operatorCount());
}

/** When the first operator on this box was created, or null for none. */
export function firstOperatorCreatedAt(): number | null {
  const row = firstUserCreatedAt.get() as { at: number | null } | undefined;
  return row?.at ?? null;
}

/**
 * The window as the browser is allowed to see it.
 *
 * One read, taken now, at the moment of the ask. Everything about which
 * fields come back lives in lib/bootstrap-window.ts; this only supplies the
 * two facts and says whether the asker is signed in.
 */
export function setupState(authed: boolean): SetupState {
  return setupStateFor({
    operatorCount: operatorCount(),
    closure: windowClosure(),
    authed,
  });
}

/**
 * Create the first administrator, or lose the race.
 *
 * Returns the new user on success and null when somebody else got there
 * first. Null is not an error to log loudly: on a fresh box being set up by
 * two people, or one person with two tabs, exactly one of them is supposed
 * to see it.
 */
export function createFirstAdmin(username: string, source?: string): AuthUser | null {
  const info = insertFirstAdmin.run(username, username, Math.floor(Date.now() / 1000));
  if (info.changes !== 1) return null;
  const user = getUserByUsername(username);
  if (user) {
    // Recorded because it is the single most privileged thing this product
    // ever does without a signed-in operator: it decides who owns the box.
    //
    // `from` is where the request came from. Every other row in this table
    // names an operator, because every other write has a session behind it;
    // this one has an address and nothing else, and an address is what an
    // operator has to compare against where they were sitting when they
    // claimed the box. Absent when the caller did not supply one, which is
    // the CLI path, where the actor is a root shell on the host itself.
    recordAuthEvent({
      actor: 'setup', event: 'first_admin_created',
      target: username,
      detail: {
        role: 'admin', via: 'bootstrap window', note: 'closes the window',
        ...(source ? { from: source } : {}),
      },
    });
  }
  return user;
}

export function getUserById(id: number): AuthUser | null {
  return (findUserById.get(id) as AuthUser | undefined) ?? null;
}
export function getAllUsers(): AuthUser[] {
  return listUsers.all() as AuthUser[];
}
export function getCredentialsForUser(userId: number): AuthCredential[] {
  return listCredentialsForUser.all(userId) as AuthCredential[];
}
// The exact lookup handleLoginFinish runs against the returned assertion's
// credential id: the full auth_credentials table, not any user's narrowed
// list. Exported so a test can prove that lookup succeeds for a credential
// that was never sent to the browser in allowCredentials, the same way
// production code proves it every time a login completes.
export function getCredentialByCredentialId(credentialId: string): AuthCredential | undefined {
  return findCredentialById.get(credentialId) as AuthCredential | undefined;
}

// Chromium (and every other client built to the same limit) refuses to open
// navigator.credentials.create() at all once excludeCredentials carries more
// than 64 entries: "The excludeCredentials attribute exceeds the maximum
// allowed size (64)". Found on a real host with 67 enrolled passkeys, where
// it meant a 68th could never be added. excludeCredentials only tells the
// authenticator "you already hold one of these, don't write a duplicate",
// it is a client-side nicety, not a security boundary. The boundary is
// auth_credentials.credential_id TEXT NOT NULL UNIQUE: a duplicate
// registration is rejected by the database on the FULL set of credentials
// regardless of what shipped in this list, so cutting the list down here
// costs nothing but the (rare) chance of a same-authenticator re-registration
// going unblocked client-side for a credential outside the cut.
export const MAX_EXCLUDE_CREDENTIALS = 64;

/**
 * Build the excludeCredentials list for a WebAuthn registration ceremony,
 * capped at the size a browser will accept.
 *
 * ONE call site for both registration paths (operator enrolment and the
 * shared setup/magic-link ceremony) so a future third site can't reintroduce
 * the unbounded list by copying the map() inline instead of calling here.
 *
 * Ordered newest-first by last use, falling back to creation date for a
 * credential that has never been used, the credentials most likely to
 * still be the one plugged in are the ones that make the cut.
 */
export function buildExcludeCredentials(
  credentials: AuthCredential[],
): { id: string; transports?: AuthenticatorTransportFuture[] }[] {
  return [...credentials]
    .sort((a, b) => {
      const aKey = a.last_used_at ?? 0;
      const bKey = b.last_used_at ?? 0;
      if (aKey !== bKey) return bKey - aKey;
      return b.created_at - a.created_at;
    })
    .slice(0, MAX_EXCLUDE_CREDENTIALS)
    .map(c => ({
      id: c.credential_id,
      transports: c.transports
        ? c.transports.split(',').filter(Boolean) as AuthenticatorTransportFuture[]
        : undefined,
    }));
}

// Same Chromium list-size check, the other side of the ceremony (#389):
// generateAuthenticationOptions()'s allowCredentials hits the identical
// 64-entry ceiling that excludeCredentials does. One name kept for the two
// so nothing has to explain twice that they are the same browser limit.
export const MAX_ALLOW_CREDENTIALS = MAX_EXCLUDE_CREDENTIALS;

/**
 * Build the allowCredentials hint for a WebAuthn authentication ceremony.
 *
 * Below the cap this is every one of the operator's passkeys, same as
 * before: the hint lets a platform authenticator narrow straight to the
 * right one instead of asking the operator to pick.
 *
 * Past the cap there is no safe truncation the way there is on the
 * excludeCredentials side. That list is advisory: dropping an entry from
 * it costs nothing because the database's uniqueness check runs on the full
 * set regardless. allowCredentials is also advisory, but truncating it here
 * risks hinting away the one device the operator actually has in hand right
 * now, which is a real lockout, not a nicety lost. So past the cap the hint
 * is dropped entirely rather than cut down: this is the SAME discoverable-
 * credential request already sent when no username is given at all.
 *
 * Two separate facts, not one. handleLoginFinish looks the returned
 * credential up by its id in the full auth_credentials table and checks it
 * belongs to the signed-in-for user, a check that has never read this hint
 * either way, so the SERVER accepts any of the account's credentials
 * regardless of what was hinted. Whether the BROWSER actually offers an
 * unhinted credential to assert with is a separate question this function
 * cannot answer: a discoverable (resident) credential can be, which is what
 * this project asks authenticators for (`residentKey: 'preferred'` at
 * registration), but 'preferred' is not 'required', so a passkey an
 * authenticator declined to make resident is only ever assertable while its
 * id is in this list. An operator past the cap whose in-hand device holds a
 * non-resident credential would still be locked out; a truncated hint would
 * have hit the same operator differently, and no truncation order beats
 * dropping the hint for the more likely case of a discoverable one.
 */
export function buildAllowCredentials(
  credentials: AuthCredential[],
): { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined {
  if (credentials.length > MAX_ALLOW_CREDENTIALS) return undefined;
  return credentials.map(c => ({
    id: c.credential_id,
    transports: c.transports
      ? c.transports.split(',').filter(Boolean) as AuthenticatorTransportFuture[]
      : undefined,
  }));
}

/**
 * Remove one passkey.
 *
 * `actor` names who did it. It defaults to the CLI's own account name, which
 * is what every caller before the Settings page was: a command run by
 * somebody with a shell, where the shell is the record. A change made from
 * the page has a signed-in operator behind it, and an audit row that said
 * 'dashboard' for both would lose the only fact worth keeping.
 */
export function revokeCredentialById(
  credId: number, actor?: { username: string; role: string | null },
): void {
  const cred = db.prepare(
    'SELECT c.credential_id, u.username FROM auth_credentials c ' +
    'JOIN auth_users u ON u.id = c.user_id WHERE c.id = ?',
  ).get(credId) as { credential_id: string; username: string } | undefined;
  deleteCredential.run(credId);
  // Removing a passkey removes an operator's ability to approve with it.
  // That is a change to who can act on the node, so it is recorded here as
  // well as taking effect — the same reason a role change is.
  recordAuthEvent({
    actor: actor?.username ?? 'dashboard',
    actorRole: actor?.role ?? null,
    event: 'credential_removed',
    target: cred?.username ?? `credential:${credId}`,
    detail: { credential_id: cred?.credential_id ?? null },
  });
}
export function issueMagicLink(
  userId: number, purpose: 'enroll' | 'recover', ttlMin: number,
  opts?: {
    /** Who asked for it. Defaults to the CLI's account name, as before. */
    actor?: { username: string; role: string | null };
    /** Set false when the caller records its own row. The Settings page
     *  does: it knows whether the mail actually went out, and that is the
     *  fact an operator reads this row for. Two rows for one link would be
     *  worse than a row written a moment later. */
    record?: boolean;
  },
): string {
  // The raw token rides in the emailed URL; the DB stores only its
  // SHA-256 so a DB read can't reconstruct a redeemable link. Redemption
  // (handleMagic) hashes the presented token before lookup.
  const token = randomBytes(32).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  insertMagicLink.run(hashToken(token), userId, purpose, now, now + ttlMin * 60);
  // The link is a route to enrolling a passkey on this account, so issuing one
  // is a privileged act even though nothing has been granted yet. Neither the
  // token nor its hash is recorded: the audit answers who was invited and
  // when, never how to redeem it.
  if (opts?.record !== false) {
    recordAuthEvent({
      actor: opts?.actor?.username ?? 'dashboard',
      actorRole: opts?.actor?.role ?? null,
      event: 'magic_link_issued',
      target: getUserById(userId)?.username ?? `user:${userId}`,
      detail: { purpose, ttl_minutes: ttlMin },
    });
  }
  return token;
}

// ── Operator management (#216) ──────────────────────────────────────
//
// The statements the Settings page's operator section reads and writes.
// Everything that DECIDES lives in lib/operator-admin.ts; what is here is
// the SQL, and the one rule the SQL carries: a role is a literal in this
// file, never a value that arrived over the wire.

const insertOperator = db.prepare(`
  INSERT INTO auth_users (username, email, role, created_at) VALUES (?, ?, ?, ?)
`);
const updateUserRole = db.prepare(`UPDATE auth_users SET role = ? WHERE id = ?`);
const countLiveSessionsStmt = db.prepare(`
  SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id = ? AND ${LIVE_SESSION}
`);
const latestPendingLinkStmt = db.prepare(`
  SELECT purpose, created_at, expires_at FROM auth_magic_links
   WHERE user_id = ? AND consumed_at IS NULL AND expires_at > ?
   ORDER BY id DESC LIMIT 1
`);
const revokeSessionsForUser = db.prepare(`
  UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL
`);
const revokeSessionsForCredential = db.prepare(`
  UPDATE auth_sessions SET revoked_at = ? WHERE credential_id = ? AND revoked_at IS NULL
`);
const countCredentialsStmt = db.prepare(`SELECT COUNT(*) AS n FROM auth_credentials WHERE user_id = ?`);
const countSessionsStmt = db.prepare(`SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id = ?`);
const countLinksStmt = db.prepare(`SELECT COUNT(*) AS n FROM auth_magic_links WHERE user_id = ?`);
const deleteCredentialsForUser = db.prepare(`DELETE FROM auth_credentials WHERE user_id = ?`);
const deleteSessionsForUser = db.prepare(`DELETE FROM auth_sessions WHERE user_id = ?`);
const deleteLinksForUser = db.prepare(`DELETE FROM auth_magic_links WHERE user_id = ?`);
const deleteUserRow = db.prepare(`DELETE FROM auth_users WHERE id = ?`);

/**
 * Create an operator with a role.
 *
 * createUser() above cannot: it writes the literal 'operator', which is the
 * legacy value and approves nothing. The role here is checked against the
 * two the product has even though every caller validates first, because this
 * is the last place before the write and 'Admin' with a capital would be an
 * account that displays as an administrator and can approve nothing.
 */
export function createOperator(email: string, role: 'admin' | 'monitor'): AuthUser {
  if (role !== 'admin' && role !== 'monitor') throw new Error('role must be admin or monitor');
  const ts = Math.floor(Date.now() / 1000);
  const result = insertOperator.run(email, email, role, ts);
  return { id: Number(result.lastInsertRowid), username: email, email, role, created_at: ts, last_login_at: null };
}

/** Change a role. Same literal check, same reason. */
export function setUserRole(userId: number, role: 'admin' | 'monitor'): boolean {
  if (role !== 'admin' && role !== 'monitor') throw new Error('role must be admin or monitor');
  return updateUserRole.run(role, userId).changes === 1;
}

/** Sessions this operator could still use: the ones readSession would accept. */
export function liveSessionCount(userId: number, nowMs: number = Date.now()): number {
  return (countLiveSessionsStmt.get(userId, ...liveBounds(nowMs)) as { n: number }).n;
}

/** The newest link still worth showing: unused and unexpired. */
export function latestPendingLink(
  userId: number,
): { purpose: string; created_at: number; expires_at: number } | null {
  return (latestPendingLinkStmt.get(userId, Math.floor(Date.now() / 1000)) as
    { purpose: string; created_at: number; expires_at: number } | undefined) ?? null;
}

/** End every session this operator holds. What a demotion does, because a
 *  live session carries the role its holder had when it opened. */
export function endSessionsForUser(userId: number): number {
  return revokeSessionsForUser.run(Math.floor(Date.now() / 1000), userId).changes;
}

/** End every session opened with one passkey. The column stores the
 *  WebAuthn handle, so this takes the handle and not the row id. */
export function endSessionsForCredential(credentialHandle: string): number {
  return revokeSessionsForCredential.run(Math.floor(Date.now() / 1000), credentialHandle).changes;
}

/**
 * Delete an operator and everything that belongs to them, in one
 * transaction.
 *
 * The same four statements the CLI's `del` runs, in the same order and for
 * the same reason: the sqlite3 client does not honour REFERENCES without
 * PRAGMA foreign_keys, so the cascade is written out, and a partial failure
 * must not leave rows pointing at a user that is gone.
 */
export const deleteOperator = db.transaction((userId: number): {
  passkeys: number; sessions: number; links: number;
} => {
  const counts = {
    passkeys: (countCredentialsStmt.get(userId) as { n: number }).n,
    sessions: (countSessionsStmt.get(userId) as { n: number }).n,
    links: (countLinksStmt.get(userId) as { n: number }).n,
  };
  deleteCredentialsForUser.run(userId);
  deleteSessionsForUser.run(userId);
  deleteLinksForUser.run(userId);
  deleteUserRow.run(userId);
  return counts;
});

// ── In-memory challenge store ──────────────────────────────────────
// WebAuthn ceremony is two-step: /begin issues the challenge, /finish
// verifies the assertion against it. We keep the challenge here keyed
// by an opaque per-ceremony id (apr_chal cookie). 5-min TTL; janitor
// runs every minute. A server restart drops in-flight ceremonies,
// which is fine — the user just retries.
interface ChallengeRecord {
  challenge: string;
  type: 'register' | 'login' | 'approve' | 'investigate' | 'seal' | 'grant' | 'update' | 'pair' | 'catchup';
  username?: string;
  userId?: number;
  createdAt: number;
  /**
   * Approval ceremonies only. The plan this assertion authorises, computed by
   * the Advisor from what it actually evaluated and never supplied by the
   * client. Without this binding an assertion would prove "the operator is
   * present", which is not the same claim as "the operator approved THIS" —
   * and a page that could get one signature could spend it on any plan.
   */
  approve?: {
    planId: string;
    fingerprint: string;
    stage: string;
    target: string;
    /**
     * ADR 0016. Both are bound INTO the fingerprint the Advisor issued this
     * challenge against, so they have to survive the ceremony and be sent
     * back verbatim at /v1/approve. Carried here, on the server's own
     * record, rather than re-read from the finishing request: a value the
     * browser could change between the two halves would recompute a
     * different fingerprint and fail the grant AFTER the passkey touch.
     */
    runbook: string;
    intent: string;
    /** RB-003's two, carried for exactly the same reason. */
    key: string;
    value: string;
    /**
     * RB-005's two (ADR 0023) and the upgrade's source override (#682),
     * carried for the same reason again. `source` is how an operator asks
     * to build here when an official image also exists; the digest that
     * pins an official pull is NOT here, because the Advisor resolves it
     * on its own side and a browser must not be able to name the image an
     * approval installs.
     */
    change: string;
    user: string;
    source: string;
    sessionId: string;
    credentialId: string;
  };
  /**
   * Sealing a model key. WHAT is about to be sealed, recorded here at begin
   * so the finishing half cannot seal something else. The browser sends the
   * key with the assertion, and nothing else: the provider, the shape, the
   * model and the credential name all come off this record.
   *
   * Without that binding an assertion would prove "the operator is present",
   * which is not the same claim as "the operator approved sealing a key for
   * THIS provider under THIS credential name". A page that could get one
   * signature could spend it on any of them.
   *
   * The key itself is deliberately NOT here. A challenge record lives in a
   * map for five minutes and is swept by a janitor; a secret does not belong
   * in one.
   */
  seal?: {
    baseUrl: string;
    shape: 'openai' | 'anthropic';
    model: string;
    credentialName: string;
    /**
     * WHICH nodes this approval covers: 'self' and/or fleet labels, resolved
     * at begin against the registry. Bound here for exactly the reason every
     * other field is: an assertion proves the operator approved sealing THIS
     * key for THIS provider on THESE nodes. A targets array read from the
     * finishing request would let a page get one signature and spend it on
     * the whole fleet.
     */
    targets: string[];
    sessionId: string;
    credentialId: string;
  };
  /**
   * Granting a privilege to an operator: adding one, or changing what one
   * may do (#216). WHO and WHAT, written here at begin.
   *
   * The binding is the whole point. An assertion proves the admin was
   * present; it does not say what they were present FOR. Without this
   * record the finishing half would have to read the email and the role off
   * the request that carries the signature, and one collected signature
   * could then mint an administrator nobody approved. `action` is bound for
   * the same reason: an approval taken for an add is not spendable on a
   * role change.
   */
  grant?: {
    action: 'add' | 'role';
    email: string;
    role: OperatorRole;
    sessionId: string;
    credentialId: string;
  };
  /**
   * Approving a node into the fleet (ADR 0019 phase 3). WHICH node, under
   * WHAT name, written here at begin.
   *
   * `pubkeyNode` is the load-bearing field and the reason this is not just a
   * pairing id: the id is a value the page holds, and a touch captured while
   * one Pending row was on screen must not be spendable on another. The
   * finishing half reads the key back off the LIVE row and refuses if the two
   * disagree, so an approval covers the node whose fingerprint the operator
   * was looking at and no other.
   *
   * `label` is bound because the operator may rename the node before
   * approving, and the name they approved is the name that gets written. A
   * label read off the finishing request would let one signature register a
   * node under any name.
   *
   * The honest limit, stated here as auth.ts already states it elsewhere:
   * WebAuthn has no trusted transaction display, so the touch proves
   * possession and freshness and not intent toward this node. This record is
   * what makes a captured touch un-replayable against a different row; it is
   * not a claim that the authenticator showed anybody a fingerprint.
   */
  pair?: {
    pairingId: string;
    label: string;
    pubkeyNode: string;
    sessionId: string;
    credentialId: string;
    /** #620: bound in beside label and pubkeyNode, for the same reason
     *  those are: a captured touch must not be replayable as the OTHER
     *  decision against the same row. A plain approval taken here can never
     *  finish as a known-node move, and a move approval can never finish as
     *  a plain one. */
    convertTunnel: boolean;
  };
  /**
   * Bringing nodes up to date on the fleet's sealed model (ADR 0019 phase 4,
   * #168). WHICH nodes, and WHAT they are about to be sent, written here at
   * begin.
   *
   * This is a seal. The one thing that makes it a different ceremony is that
   * the operator does not type the key: it is already sealed on this host,
   * and the root broker is what opens it. So the same binding rule applies
   * for the same reason, and `targets` is the field that carries it. A
   * targets array read off the finishing request would let one signature,
   * taken to catch up one node that was down, be spent on the whole fleet.
   *
   * The three descriptor fields are bound as well, and they are not
   * decoration. An operator approving a catch-up is approving a setting they
   * did not type this time, so the page shows them the model, the base URL's
   * HOST and the credential name first, read from the store's own head. What
   * they were shown is written here, and the finishing half refuses if the
   * head has changed underneath it: `base_url` is the one field of that store
   * a compromised dashboard can rewrite without root, and this is where a
   * rewrite between the two halves of the ceremony is caught.
   */
  catchup?: {
    targets: string[];
    baseUrlHost: string;
    /** The WHOLE address, which is what the comparison at finish uses. The
     *  host beside it is what the page prints. Binding the host alone would
     *  leave the port and the path free to change between the two halves of
     *  the ceremony (security review, finding F9). */
    baseUrl: string;
    model: string;
    credentialName: string;
    sessionId: string;
    credentialId: string;
  };
  /**
   * Applying an update, restarting into it, or rolling it back (ADR 0022
   * phase 2, #62). WHAT is about to be run, written here at begin.
   *
   * The binding is the whole point, and for an apply it is the release: an
   * assertion proves the admin was present, not that they approved THIS
   * release. Without the record, the finishing half would take the tag, the
   * commit and the sha256 off the request that carries the signature, and
   * one collected signature could then install anything the endpoint
   * happens to be serving later. The ceremony covers that release and
   * nothing else.
   *
   * `action` is bound for the reason `grant.action` is: an approval taken
   * for an apply is not spendable on a rollback.
   *
   * For a restart, `units` comes off the finished run's own `needs_restart=`
   * line, server-side, and never off the request. The dashboard never sends
   * a unit name it chose (ADR 0022 decision 5) — a fixed list of three
   * would refuse the restart on two hosts I run today, and a list the page
   * supplied would be a unit name root took from a browser.
   */
  update?: {
    action: UpdateAction;
    release?: { tag: string; commit: string; sha256: string };
    units?: string[];
    /** The fleet halves: which nodes, and which run on each. Written here at
     *  begin for the same reason the release is, and never read off the
     *  request that carries the signature. */
    targets?: string[];
    runIds?: Record<string, string>;
    sessionId: string;
    credentialId: string;
  };
  /**
   * Break glass (plan-interrogative-loop §11.8). Same binding shape as
   * approve above, for the same reason — the Advisor computes fingerprint
   * from the offer record IT holds, never from anything the client sends.
   */
  investigate?: {
    offerId: string;
    fingerprint: string;
    sessionId: string;
    credentialId: string;
  };
}
const pendingChallenges = new Map<string, ChallengeRecord>();
setInterval(() => {
  const cutoff = Date.now() - CHALLENGE_TTL_MS;
  for (const [id, rec] of pendingChallenges.entries()) {
    if (rec.createdAt < cutoff) pendingChallenges.delete(id);
  }
}, 60_000).unref();

// Insert a challenge, evicting the oldest entries first if we're at the
// MAX_PENDING_CHALLENGES ceiling (MED-04). Map iteration order is
// insertion order, so the first key is the oldest. This caps memory
// growth from a /begin flood without rejecting a legitimate operator's
// ceremony (which would be the newest entry).
function putPendingChallenge(id: string, rec: ChallengeRecord): void {
  while (pendingChallenges.size >= MAX_PENDING_CHALLENGES) {
    const oldest = pendingChallenges.keys().next().value;
    if (oldest === undefined) break;
    pendingChallenges.delete(oldest);
  }
  pendingChallenges.set(id, rec);
}

// ── Login rate limiter (MED-04) ────────────────────────────────────
// Sliding-window limiter for /login/begin + /login/finish, keyed by
// client IP (and, when a username is supplied, an additional
// per-username bucket). Mirrors enrollRateOk's shape. The window is
// generous enough that a real operator fumbling a passkey a few times
// never trips it, but a scripted enumeration/probing run does. Lost on
// restart (in-memory), which is acceptable — an attacker gains nothing
// from a restart they can't trigger. Tunables:
//   LOGIN_RATE_LIMIT     attempts per window per key
//   LOGIN_RATE_WINDOW_MS the sliding window
const LOGIN_RATE_LIMIT     = 20;
const LOGIN_RATE_WINDOW_MS = 5 * 60 * 1000;   // 20 attempts / 5 min / key
const loginAttempts = new Map<string, number[]>();
// Bound the limiter map itself so distinct attacker IPs can't grow it
// without limit (the same DoS class as the challenge map).
const MAX_LOGIN_RATE_KEYS = 10_000;
function loginRateOk(key: string): { ok: boolean; resetTs: number | null } {
  const now = Date.now();
  const cutoff = now - LOGIN_RATE_WINDOW_MS;
  const bucket = (loginAttempts.get(key) ?? []).filter(t => t >= cutoff);
  if (bucket.length >= LOGIN_RATE_LIMIT) {
    loginAttempts.set(key, bucket);
    return { ok: false, resetTs: bucket[0] + LOGIN_RATE_WINDOW_MS };
  }
  bucket.push(now);
  if (loginAttempts.size >= MAX_LOGIN_RATE_KEYS && !loginAttempts.has(key)) {
    const oldest = loginAttempts.keys().next().value;
    if (oldest !== undefined) loginAttempts.delete(oldest);
  }
  loginAttempts.set(key, bucket);
  return { ok: true, resetTs: null };
}

// Best-effort client IP for rate-limiting. Behind the Cloudflare tunnel
// the real client is in x-forwarded-for (first hop); fall back to the
// socket address for direct/LAN connections. Used only as a rate-limit
// key — never for an authz decision — so a spoofed XFF at worst lets an
// attacker spread their own attempts across buckets (each still capped).
function clientIp(req: IncomingMessage): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim().slice(0, 64);
  }
  return String(req.socket.remoteAddress ?? 'unknown').slice(0, 64);
}

// Apply the login limiter to a request, by IP and (if present) username.
// Returns the 429 payload to send, or null when the request may proceed.
function checkLoginRate(req: IncomingMessage, username?: string): { resetTs: number | null } | null {
  const ipRate = loginRateOk(`ip:${clientIp(req)}`);
  if (!ipRate.ok) return { resetTs: ipRate.resetTs };
  if (username) {
    const userRate = loginRateOk(`lu:${username}`);
    if (!userRate.ok) return { resetTs: userRate.resetTs };
  }
  return null;
}

// ── Cookie helpers ─────────────────────────────────────────────────
function parseCookies(req: IncomingMessage): Record<string, string> {
  const header = req.headers.cookie;
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

// Decide whether the session/challenge cookie gets the `Secure` flag.
// MED-06: this must NOT be driven by the inbound x-forwarded-proto
// header — an attacker on a non-tunnel path (Shape B, the LAN split) could send
// `x-forwarded-proto: http` to strip Secure and force the cookie over
// cleartext. Instead Secure is ON by default and only suppressed for a
// genuine local-dev request (loopback peer, not running in production).
//
// Precedence:
//   1. APERIRE_FORCE_SECURE_COOKIES=true → always Secure (explicit opt-in).
//   2. NODE_ENV=production               → always Secure (the unit ships this).
//   3. loopback remote address + not prod → local dev over plain HTTP, no Secure.
//   4. anything else                      → Secure (fail safe).
// Production behind the Cloudflare tunnel always lands on (2).
function shouldUseSecureCookie(req: IncomingMessage): boolean {
  if (process.env.APERIRE_FORCE_SECURE_COOKIES === 'true') return true;
  if (process.env.NODE_ENV === 'production') return true;
  // Local dev only: the connecting peer is loopback. We look at the
  // socket's own remote address (not a forgeable header) so a remote
  // client can never claim loopback to strip Secure.
  const remote = req.socket.remoteAddress ?? '';
  const isLoopback = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
  if (isLoopback) return false;
  // Direct HTTPS to the dashboard process — keep Secure on.
  return true;
}

// maxAgeS <= 0 emits a BROWSER-SESSION cookie (no Max-Age / no Expires): it
// is discarded when the browser session ends, so closing the browser signs
// the operator out. The server still enforces the real lifetime (absolute
// TTL + idle timeout) against its own session record, so a session cookie
// is a convenience floor, never the security ceiling. (A browser with
// "continue where you left off" / session restore may preserve even a
// session cookie across a restart — the idle timeout is the reliable
// backstop there.)
function setCookie(req: IncomingMessage, res: ServerResponse, name: string, value: string, maxAgeS: number): void {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (maxAgeS > 0) parts.push(`Max-Age=${maxAgeS}`);
  if (shouldUseSecureCookie(req)) parts.push('Secure');
  appendSetCookie(res, parts.join('; '));
}

function clearCookie(req: IncomingMessage, res: ServerResponse, name: string): void {
  const parts = [
    `${name}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (shouldUseSecureCookie(req)) parts.push('Secure');
  appendSetCookie(res, parts.join('; '));
}

function appendSetCookie(res: ServerResponse, header: string): void {
  // res.setHeader replaces; we may need multiple Set-Cookie headers in
  // a single response (e.g. clearing apr_chal + setting apr_sess on
  // /auth/login/finish), so coalesce as an array.
  const existing = res.getHeader('set-cookie');
  if (Array.isArray(existing)) {
    res.setHeader('set-cookie', [...existing, header]);
  } else if (typeof existing === 'string') {
    res.setHeader('set-cookie', [existing, header]);
  } else {
    res.setHeader('set-cookie', header);
  }
}

// ── CSRF check ─────────────────────────────────────────────────────
// State-changing endpoints that aren't passkey assertions (/auth/touch,
// /auth/lock) require an `X-Aperire-CSRF: 1` header. Browsers refuse
// to add custom headers on cross-site requests without explicit CORS
// preflight, so this rejects CSRF without a token store.
/**
 * A header a cross-site request cannot set.
 *
 * The cookie is SameSite=Lax, which stops a cross-site form POST but not every
 * shape of request. A custom header does: a form cannot add one at all, and a
 * cross-origin fetch that tries is held behind a preflight this server never
 * answers. It is cheap and it composes with the cookie rather than replacing
 * it.
 *
 * Exported because the Advisor's write endpoints live in server.ts and were
 * the only authenticated writes in the app skipping this.
 */
export function csrfOk(req: IncomingMessage): boolean {
  return req.headers['x-aperire-csrf'] === '1';
}

// ── JSON helpers ───────────────────────────────────────────────────
/**
 * Every route on this page reads its body through here, and throws on a body
 * over the cap. The reading itself is lib/read-body.ts, shared with the rest
 * of the server; what stays local is the default cap and the throw, which the
 * routes below are written around.
 */
async function readBody(req: IncomingMessage, maxBytes = 8192): Promise<string> {
  return readBodyOrThrow(req, maxBytes);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(payload));
}

// ── Public auth check + middleware (A2) ────────────────────────────
/**
 * Who may authorise an Advisor action.
 *
 * Only two, and only one of them can approve. A role hierarchy with five tiers
 * is a thing nobody can hold in their head at the moment they need to, and the
 * question here is binary: can this person restart the validator or not.
 */
export type Role = 'admin' | 'monitor';
export function isAdmin(role: string): boolean { return role === 'admin'; }



export interface AuthSessionInfo {
  sessionId: string;
  userId: number;
  username: string;
  email: string | null;
  role: string;
  lastActivityAt: number;
  expiresAt: number;
  /**
   * The passkey that opened this session, base64url. NULL on sessions minted
   * before the column existed — those read normally and are asked to
   * re-authenticate before approving anything.
   */
  credentialId: string | null;
}

// Paths that always serve regardless of session state. Everything
// else routes through requireAuthGate. Keep this set tight — every
// public path is a potential information leak. The lock-screen
// (/login.html) and its critical-path assets (vendored WebAuthn
// browser bundle, brand image, favicon) are the floor.
//
// The rule, learned the hard way: a page served before authentication
// needs its WHOLE asset closure served before authentication. The theme
// stylesheet was added to every page including this one and left out of
// here, so an operator with no session got a 302 for it and the sign-in
// page rendered with no tokens at all: no palette, no font stack, the
// card in the browser's default serif and the passkey button as bare
// text. It returned 200 and looked broken.
//
// test/unit/login-asset-closure.test.ts derives that closure from
// login.html's own link/script tags and asserts every one of them clears
// this gate, so the next asset added to the sign-in page cannot repeat it.
//
// These two are safe to publish: theme.css is colour and radius tokens,
// theme-toggle.js reads one localStorage key and flips an attribute.
// Neither reads a session, reaches an API, or carries anything an
// unauthenticated visitor could not already infer from the login page.
const PUBLIC_PATH_EXACT = new Set<string>([
  '/login.html',
  '/favicon.ico',
  // Referenced by login.html since long before the theme work and never
  // in this set, so it has always 302'd for a visitor with no session.
  // Silent because a browser that cannot fetch the SVG icon quietly falls
  // back to the .ico below it. Found by the derived closure check, not by
  // anyone noticing.
  '/favicon.svg',
  '/aperire-logo.gif',
  // The brand mark. It has always been gated, which login.html works around
  // by inlining its own copy (see the comment beside celebrateThenGo), and
  // the first pre-auth page to reference it with <img> got a broken image on
  // a live install. It is a logo: publishing it leaks nothing that the page
  // it sits on does not already say.
  '/aperire-mark.svg',
  '/theme.css',
  '/theme-toggle.js',
]);
function isPublicPath(pathname: string): boolean {
  if (PUBLIC_PATH_EXACT.has(pathname)) return true;
  if (pathname.startsWith('/vendor/')) return true;       // simplewebauthn bundle
  return false;
}

/**
 * A2 middleware. Returns true if the response was sent (request handled,
 * caller should `return`); false to continue normal routing.
 *
 * Decision tree:
 *   - public path → return false (let static-file routing serve it)
 *   - valid session → return false (authed; carry on)
 *   - no session + /api/* or /history → 401 JSON, signal frontend to lock
 *   - no session + anything else → 302 to /login.html?next=<encoded path>
 *
 * `/auth/*` requests never reach here — they're dispatched by
 * handleAuthRequest before the gate runs.
 */
/** The first-run page. One constant, because three places name it. */
export const SETUP_PATH = '/setup.html';

export function requireAuthGate(req: IncomingMessage, res: ServerResponse, pathname: string): boolean {
  // ── The bootstrap window (#135 Step 1) ──────────────────────────────
  //
  // A box with zero operators has exactly one thing worth showing, so every
  // navigation lands on it, the sign-in page included: there is nobody to
  // sign in AS, and a lock screen that cannot be unlocked is a dead end
  // dressed up as a door. See lib/bootstrap-window.ts for what the window
  // is and why deleting every operator reopens it.
  //
  // This runs BEFORE isPublicPath on purpose. /login.html is public, so
  // leaving it above would serve the dead end rather than redirect past it.
  if (bootstrapWindowOpen()) {
    if (pathname === SETUP_PATH) return false;
    if (pathname === '/login.html') {
      res.writeHead(302, { Location: SETUP_PATH, 'cache-control': 'no-store' });
      res.end();
      return true;
    }
    // The setup page's own assets, and everything else already public.
    if (isPublicPath(pathname)) return false;
    // An API call on an unowned box is answered the same way it is on a
    // locked one, so a stale tab locks rather than silently half-works.
    if (pathname.startsWith('/api/') || pathname === '/history') {
      res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ error: 'unauthenticated', redirect: SETUP_PATH }));
      return true;
    }
    res.writeHead(302, { Location: SETUP_PATH, 'cache-control': 'no-store' });
    res.end();
    return true;
  }

  // Window closed. This page stops being a way to claim the box, and it is
  // no longer a way to add a node either (#585, operator's ruling
  // 2026-09-21): that moved into Settings & Updates, which is the one place
  // fleet configuration lives. So a closed window has exactly one thing this
  // path can mean for any caller: send them to where adding a node actually
  // happens now.
  //
  // An administrator holds a session that can reach it, so they are handed
  // straight there. A caller with no session, or a monitor (who could never
  // reach Settings & Updates either, that page's own gate says so), is sent
  // to sign in first; ?next carries them back to this same redirect once
  // they have. Either way the refusal is still SERVER-side: this route
  // serves no markup at all on a closed box, so there is nothing here for a
  // stranger to read even for a moment.
  if (pathname === SETUP_PATH) {
    const sess = readSession(req);
    if (sess && isAdmin(sess.role)) {
      res.writeHead(302, { Location: '/settings.html#add-node', 'cache-control': 'no-store' });
      res.end();
      return true;
    }
    res.writeHead(302, {
      Location: `/login.html?next=${encodeURIComponent(SETUP_PATH)}`,
      'cache-control': 'no-store',
    });
    res.end();
    return true;
  }

  if (isPublicPath(pathname)) return false;
  if (readSession(req)) return false;

  // API + history: machine-readable 401 so the frontend can detect
  // session loss and overlay the lock-screen without navigating away.
  // The Location-style hint in the body makes manual debugging easy.
  if (pathname.startsWith('/api/') || pathname === '/history') {
    res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ error: 'unauthenticated', redirect: '/login.html' }));
    return true;
  }

  // Browser navigation: redirect to the lock-screen with the original
  // path as ?next= so we land them where they were aiming after sign-in.
  const original = req.url ?? '/';
  const next = encodeURIComponent(original);
  res.writeHead(302, { Location: `/login.html?next=${next}`, 'cache-control': 'no-store' });
  res.end();
  return true;
}

export function readSession(req: IncomingMessage): AuthSessionInfo | null {
  const cookies = parseCookies(req);
  const sid = cookies[SESSION_COOKIE];
  if (!sid) return null;
  // The cookie carries the raw session id; the DB row is keyed by its
  // SHA-256. Hash before lookup so the raw id never has to be compared
  // against disk. A cookie whose hash isn't present returns null.
  const row = findSessionById.get(hashToken(sid)) as {
    id: string; user_id: number; created_at: number; last_activity_at: number;
    expires_at: number; revoked_at: number | null; user_agent: string | null; ip: string | null;
    credential_id: string | null;
    username: string; email: string | null; role: string;
  } | undefined;
  if (!row) return null;
  if (row.revoked_at != null) return null;
  const nowS = Math.floor(Date.now() / 1000);
  if (row.expires_at < nowS) return null;

  // Absolute lifetime cap (MED-03). Independent of idle activity: once a
  // session is older than created_at + SESSION_ABSOLUTE_TTL_S it is dead
  // no matter how recently /auth/touch ran. Revoke on read so the row
  // stops being honored and the next /auth/session poll flips the lock
  // screen. expires_at is normally aligned to this same cap (set at
  // mint time), so this is belt-and-suspenders for any session whose
  // expires_at was set under the old 1-year policy.
  if (row.created_at + SESSION_ABSOLUTE_TTL_S < nowS) {
    revokeSession.run(nowS, row.id);
    return null;
  }

  // Idle timeout (A3). When configured, sessions whose last_activity_at
  // is older than idle_timeout_minutes get revoked here so subsequent
  // requests fail without re-checking the time gap, and the lock-screen
  // overlay flips on the next /auth/session poll.
  const timeoutMs = idleTimeoutMs();
  if (timeoutMs > 0 && (Date.now() - row.last_activity_at * 1000) > timeoutMs) {
    revokeSession.run(Math.floor(Date.now() / 1000), row.id);
    return null;
  }

  return {
    // The stored hash, not the raw cookie value. Only ever used to key
    // touch/revoke UPDATEs (which match on the same id column) — never
    // sent to the client.
    sessionId: row.id,
    userId: row.user_id,
    username: row.username,
    email: row.email,
    role: row.role,
    lastActivityAt: row.last_activity_at,
    expiresAt: row.expires_at,
    credentialId: row.credential_id,
  };
}

// ── Handlers ───────────────────────────────────────────────────────

// POST /auth/register/begin  body: { username }
// Issues registration options to add ANOTHER passkey to an account.
// MED-02: this route is an enumeration oracle if it answers for any
// username (404 unknown vs 200 known), so it now requires a valid
// session — only an already-authenticated operator can add a credential
// this way, and they may only add credentials to their OWN account.
// First-device / unauthenticated enrollment does NOT use this route: it
// flows through /auth/magic (single-use link) which issues options
// inline. So gating this behind a session does not affect the
// magic-link enrollment path.
async function handleRegisterBegin(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'authentication required' }); return; }
  const body = await readBody(req);
  let payload: { username?: string };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }
  // The authenticated operator may only enroll a credential for
  // themselves. If a username is supplied it must match the session;
  // otherwise default to the session's own account. Either way the
  // response is identical whether or not some OTHER username exists, so
  // there is no enumeration signal.
  if (payload.username && payload.username !== sess.username) {
    sendJson(res, 403, { error: 'cannot enroll a credential for another operator' });
    return;
  }
  const user = getUserById(sess.userId);
  if (!user) {
    sendJson(res, 401, { error: 'authentication required' });
    return;
  }
  const existing = getCredentialsForUser(user.id);
  const opts = await generateRegistrationOptions({
    rpName: rpName(),
    rpID:   rpIDs()[0],
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    excludeCredentials: buildExcludeCredentials(existing),
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'register',
    username: user.username,
    userId: user.id,
    createdAt: Date.now(),
  });
  setCookie(req, res, CHALLENGE_COOKIE, chalId, Math.floor(CHALLENGE_TTL_MS / 1000));
  sendJson(res, 200, opts);
}

// POST /auth/register/finish  body: { response, name? }
async function handleRegisterFinish(
  req: IncomingMessage, res: ServerResponse, advisorUrl?: string, advisorToken?: string | null,
): Promise<void> {
  const body = await readBody(req, 16_384);
  let payload: { response?: unknown; name?: string };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }
  if (!payload.response) { sendJson(res, 400, { error: 'response required' }); return; }
  const cookies = parseCookies(req);
  const chalId = cookies[CHALLENGE_COOKIE];
  if (!chalId) { sendJson(res, 400, { error: 'no pending challenge — restart registration' }); return; }
  const rec = pendingChallenges.get(chalId);
  pendingChallenges.delete(chalId);
  if (!rec || rec.type !== 'register' || !rec.userId) {
    sendJson(res, 400, { error: 'no matching challenge' }); return;
  }
  let result: VerifiedRegistrationResponse;
  try {
    result = await verifyRegistrationResponse({
      response: payload.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      requireUserVerification: true,
    });
  } catch (err) {
    // LOW-04: keep the detailed WebAuthn failure reason server-side only.
    // The verbatim message can disclose ceremony internals; the browser
    // gets a generic string.
    console.warn('[authn] register verify failed:', (err as Error).message);
    sendJson(res, 400, { error: 'registration verification failed' });
    return;
  }
  if (!result.verified || !result.registrationInfo) {
    sendJson(res, 400, { error: 'registration not verified' });
    return;
  }
  const info = result.registrationInfo;
  const ts = Math.floor(Date.now() / 1000);
  // Read BEFORE the insert. This is the serial the fleet last had a chance to
  // take; comparing it to the serial after the insert is what decides whether
  // anything needs pushing at all. A monitor's passkey does not appear in the
  // bundle, so it does not move this — which is why there is no role check
  // here to fall out of step with the bundle query.
  const serialBefore = trustFingerprint().fingerprint;
  insertCredential.run(
    rec.userId,
    info.credential.id,
    info.credential.publicKey instanceof Uint8Array
      ? Buffer.from(info.credential.publicKey).toString('base64url')
      : String(info.credential.publicKey),
    info.credential.counter ?? 0,
    Array.isArray(info.credential.transports) ? info.credential.transports.join(',') : null,
    deviceLabel(payload.name),
    ts,
  );
  // A new passkey on an admin account is a new key that can approve a change
  // to the validator. Recorded with the device label the operator chose and
  // the credential handle — never the public key, which the trust store
  // already holds and the audit has no use for.
  recordAuthEvent({
    actor: getUserById(rec.userId)?.username ?? `user:${rec.userId}`,
    actorRole: getUserById(rec.userId)?.role ?? null,
    event: 'credential_enrolled',
    target: getUserById(rec.userId)?.username ?? `user:${rec.userId}`,
    detail: { credential_id: info.credential.id, label: deviceLabel(payload.name) },
  });

  // Successful enrollment is itself proof of possession — treat it as a
  // sign-in too. Without this the operator would be prompted for
  // biometric a second time immediately after enrollment to "really"
  // sign in. Issue a session right here so the frontend can land them
  // on the dashboard with one tap.
  // A registration flow proves possession of a new credential, and the
  // credential it just created is the one this session is bound to.
  const sid = issueSession(req, rec.userId, info.credential.id, ts);
  updateUserLastLogin.run(ts, rec.userId);
  setCookie(req, res, SESSION_COOKIE, sid, 0); // browser-session cookie — closes-out on browser exit; server enforces expiresAt
  clearCookie(req, res, CHALLENGE_COOKIE);
  const user = getUserById(rec.userId);
  sendJson(res, 200, { ok: true, signed_in: true, username: user?.username ?? null });

  // AFTER the response, and never able to change it. The credential is
  // written and the operator has already touched their passkey; a fleet node
  // being unreachable must not cost them the session they just earned, and
  // waiting on N nodes would make enrollment slower the larger the fleet is.
  //
  // Until this existed, a passkey enrolled here reached the fleet only when
  // somebody remembered to push it by hand — which is exactly how an admin
  // came to be refused on stock-node2 on 2026-08-19 with an error naming
  // their passkey.
  const serialAfter = trustFingerprint().fingerprint;
  void pushTrustAfterEnrollment(serialBefore, serialAfter, {
    repoDir: REPO_DIR, dbPath: DB_PATH, spawn: runTrustPush,
    log: (line) => console.log(line),
  });
  // And the Advisor on THIS host, which the fleet push does not reach. Until
  // this existed every browser enrollment after the Advisor install left its
  // trust store stale until somebody ran advisor-sync on the box (#160).
  void syncLocalTrustAfterEnrollment(serialBefore, serialAfter, {
    ...trustSyncTarget(),
    ask: (payload) => askSocketProgram(TRUST_SYNC_SOCKET_PATH, payload, 60_000, 'the trust sync'),
    readBack: () => readAdvisorTrustFingerprint(advisorUrl, advisorToken ?? null),
    mine: () => trustFingerprint().fingerprint,
    log: (line) => console.log(line),
    record: (detail) => recordAuthEvent({
      actor: user?.username ?? 'unknown', actorRole: user?.role ?? null,
      event: 'trust_synced', target: 'advisor', detail,
    }),
  });
}

// Where systemd listens for a trust sync. Overridable so a walk can drive a
// stub on a temporary path; the constant is what every real host uses.
const TRUST_SYNC_SOCKET_PATH = process.env.APERIRE_TRUST_SYNC_SOCKET || TRUST_SYNC_SOCKET;

/** The origin and rp_id the sync is asked for: the SAME values
 *  `aperire-auth advisor-sync` reads out of authn.yaml, first entry of each,
 *  so the two paths cannot disagree about what the store is bound to. Not
 *  origins(): that adds the loopback address this process listens on, which
 *  is a WebAuthn convenience for the operator on the box and not a place the
 *  Advisor should be told approvals come from. The rp_id may be empty, in
 *  which case the program derives it from the origin as the CLI does. */
function trustSyncTarget(): { origin: string; rpId: string } {
  const cfg = loadAuthnConfig();
  const first = (v: string | undefined) => (v ?? '').split(',')[0].trim();
  return { origin: first(cfg.public_url).replace(/\/+$/, ''), rpId: first(cfg.rp_id) };
}

/** advisord's own trust fingerprint, from /v1/status, or null when it could
 *  not be read. The read-back after a sync: the log says whether the Advisor
 *  agrees, not whether a program exited zero. */
async function readAdvisorTrustFingerprint(advisorUrl?: string, advisorToken?: string | null): Promise<string | null> {
  if (!advisorUrl || !advisorToken) return null;
  try {
    const r = await fetch(`${advisorUrl}/v1/status`, {
      headers: { authorization: `Bearer ${advisorToken}` },
      signal: AbortSignal.timeout(5_000),
    });
    if (!r.ok) return null;
    const j = await r.json() as { trust?: { fingerprint?: unknown } };
    return typeof j.trust?.fingerprint === 'string' ? j.trust.fingerprint : null;
  } catch {
    return null;
  }
}

// POST /auth/login/begin  body: { username? }
// If username is provided, narrow allowCredentials to that user's
// passkeys (dropped past #389's cap, see buildAllowCredentials).
// Otherwise issue a discoverable-credential challenge so the
// browser/OS can surface any matching passkey.
async function handleLoginBegin(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  let payload: { username?: string };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }
  // MED-04: throttle by IP (+username when supplied) before doing any
  // DB work or allocating a challenge, so a probing run is cheap to
  // reject and can't enumerate or exhaust memory.
  const rl = checkLoginRate(req, payload.username);
  if (rl) { sendJson(res, 429, { error: 'too many login attempts — try again shortly', reset_at: rl.resetTs }); return; }
  let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined;
  let userId: number | undefined;
  if (payload.username) {
    const user = getUserByUsername(payload.username);
    if (!user) {
      // Unknown operator. Return the SAME 412 shape as a known operator
      // with no enrolled passkey so login/begin can't be used to probe
      // which usernames (emails) exist. enrollment_available=false +
      // null email_hint route the client to the generic manual-enroll
      // hint, identical to a known-but-uninvitable operator.
      sendJson(res, 412, {
        error: 'no passkey enrolled for this operator on any device yet',
        enrollment_available: false,
        email_hint: null,
        // Same shape as the known-operator branch below, instance
        // included — a differing field set would be the enumeration
        // signal this branch exists to avoid.
        instance: instanceLabel,
      });
      return;
    }
    userId = user.id;
    const creds = getCredentialsForUser(user.id);
    if (creds.length === 0) {
      // No passkey enrolled yet for this user. Reject the sign-in
      // attempt with structured info the lock-screen uses to render a
      // self-serve enrollment flow: if the user has email + we can
      // send via Resend, the screen surfaces a "Send enrollment link"
      // button; otherwise it falls back to the CLI hint. 412 status
      // is "Precondition Failed" — semantically right.
      const enrollment_available = canEmailEnrollLink(user);
      sendJson(res, 412, {
        error: 'no passkey enrolled for this operator on any device yet',
        enrollment_available,
        email_hint: user.email ? maskEmail(user.email) : null,
        instance: instanceLabel,
      });
      return;
    }
    allowCredentials = buildAllowCredentials(creds);
  }
  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    allowCredentials,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'login',
    username: payload.username,
    userId,
    createdAt: Date.now(),
  });
  setCookie(req, res, CHALLENGE_COOKIE, chalId, Math.floor(CHALLENGE_TTL_MS / 1000));
  sendJson(res, 200, opts);
}

/**
 * The asserted credential has to belong to the operator the challenge was
 * minted for. Without this, a challenge issued for user A could be completed
 * with user B's credential, and the session would be cut for B.
 *
 * A challenge with no userId is the discoverable-credential (usernameless)
 * flow, where login/begin was never told who is signing in. There the
 * credential itself is the only identity claim, so there is nothing to
 * cross-check and the answer is yes.
 *
 * Exported on its own because the route around it needs a browser, a
 * challenge cookie and a real assertion to reach, and none of those are what
 * would silently regress here.
 */
export function credentialBindingOk(
  challengeUserId: number | null | undefined,
  credentialUserId: number,
): boolean {
  if (challengeUserId == null) return true;
  return credentialUserId === challengeUserId;
}

// POST /auth/login/finish  body: { response }
async function handleLoginFinish(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req, 16_384);
  let payload: { response?: { id?: string; rawId?: string } };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }
  if (!payload.response?.id) { sendJson(res, 400, { error: 'response.id required' }); return; }
  // MED-04: same IP limiter as login/begin (no username on finish, so
  // IP-keyed only). Shares the bucket with begin so a begin+finish pair
  // counts as the two attempts it is.
  const rl = checkLoginRate(req);
  if (rl) { sendJson(res, 429, { error: 'too many login attempts — try again shortly', reset_at: rl.resetTs }); return; }
  const cookies = parseCookies(req);
  const chalId = cookies[CHALLENGE_COOKIE];
  if (!chalId) { sendJson(res, 400, { error: 'no pending challenge — restart login' }); return; }
  const rec = pendingChallenges.get(chalId);
  pendingChallenges.delete(chalId);
  if (!rec || rec.type !== 'login') {
    sendJson(res, 400, { error: 'no matching challenge' }); return;
  }
  // Look up the credential by the id the browser returned.
  const cred = findCredentialById.get(payload.response.id) as AuthCredential | undefined;
  if (!cred) { sendJson(res, 401, { error: 'unknown credential' }); return; }
  if (!credentialBindingOk(rec.userId, cred.user_id)) {
    console.warn(`[authn] login/finish credential/user mismatch: challenge user ${rec.userId}, credential user ${cred.user_id}`);
    sendJson(res, 401, { error: 'authentication failed' }); return;
  }
  let result: VerifiedAuthenticationResponse;
  try {
    result = await verifyAuthenticationResponse({
      response: payload.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
        transports: cred.transports ? cred.transports.split(',').filter(Boolean) as never : undefined,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    // LOW-04: detailed reason to the server log only; generic to client.
    console.warn('[authn] login verify failed:', (err as Error).message);
    sendJson(res, 401, { error: 'authentication failed' });
    return;
  }
  if (!result.verified) { sendJson(res, 401, { error: 'authentication not verified' }); return; }
  // Roll the counter forward.
  const ts = Math.floor(Date.now() / 1000);
  updateCredentialCounter.run(result.authenticationInfo.newCounter, ts, cred.id);
  // Issue a session.
  const sid = issueSession(req, cred.user_id, cred.credential_id, ts);
  updateUserLastLogin.run(ts, cred.user_id);
  setCookie(req, res, SESSION_COOKIE, sid, 0); // browser-session cookie — closes-out on browser exit; server enforces expiresAt
  clearCookie(req, res, CHALLENGE_COOKIE);
  const user = getUserById(cred.user_id);
  sendJson(res, 200, { ok: true, username: user?.username ?? null });
}

// GET /auth/session — current session status. Drives the shell's
// idle-tracker poll: when within the warning window the response
// includes idle_warning + secs_remaining so the client can show the
// "Stay signed in" toast. Calling /auth/session does not bump
// last_activity_at — only /auth/touch does, which is gated to real
// operator input events client-side.
function handleSession(req: IncomingMessage, res: ServerResponse): void {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 200, { authed: false }); return; }
  const timeoutMs = idleTimeoutMs();
  const warningMs = idleWarningMs();
  let idleWarning = false;
  let secsRemaining: number | null = null;
  if (timeoutMs > 0) {
    const elapsedMs = Date.now() - sess.lastActivityAt * 1000;
    const remainingMs = Math.max(0, timeoutMs - elapsedMs);
    secsRemaining = Math.floor(remainingMs / 1000);
    idleWarning = remainingMs > 0 && remainingMs <= warningMs;
  }
  sendJson(res, 200, {
    authed: true,
    username: sess.username,
    email: sess.email,
    // Added for break glass (plan-interrogative-loop §9.6, §11.7): the
    // drawer needs to know monitor from admin BEFORE it decides whether to
    // render a ceremony or a note, and this is the one place a page already
    // asks who it is talking to. A rendering hint only — the refusal lives
    // in server.ts's ADVISOR_ADMIN_PATHS gate, not here.
    role: sess.role,
    // A stable name for "this sign-in", so a page can keep something across
    // navigations and drop it the moment the session is not the same one.
    // The Advisor tab uses it to keep a conversation alive while you visit
    // Consensus for a ledger number, and to make sure the next operator at
    // this browser never sees it.
    //
    // Derived, not the session id: sess.sessionId is already the stored hash
    // of the cookie, and this hashes that again and keeps 16 characters. It
    // identifies the session to code that already holds the cookie and is
    // useless to anything that does not.
    scope: createHash('sha256').update('advisor-scope:' + sess.sessionId).digest('hex').slice(0, 16),
    last_activity_at: sess.lastActivityAt,
    idle_timeout_seconds: timeoutMs > 0 ? Math.floor(timeoutMs / 1000) : null,
    idle_warning: idleWarning,
    secs_remaining: secsRemaining,
  });
}

// POST /auth/touch — bump last_activity_at; called on real input
function handleTouch(req: IncomingMessage, res: ServerResponse): void {
  if (!csrfOk(req)) { sendJson(res, 403, { error: 'csrf' }); return; }
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'no session' }); return; }
  touchSession.run(Math.floor(Date.now() / 1000), sess.sessionId);
  sendJson(res, 200, { ok: true });
}

// POST /auth/lock — manual lock; revoke session, clear cookie
//
// advisorUrl/advisorToken are optional so every other caller of this file's
// exported dispatcher (tests included) is unaffected — when present, logout
// also clears whatever unspent Advisor approvals this operator was holding.
// See revokeApprovalsOnLogout for why that call is fire-and-forget.
function handleLock(
  req: IncomingMessage, res: ServerResponse, advisorUrl?: string, advisorToken?: string | null,
  logoutTargets?: () => LogoutCancelTarget[],
): void {
  if (!csrfOk(req)) { sendJson(res, 403, { error: 'csrf' }); return; }
  const sess = readSession(req);
  if (sess) {
    revokeSession.run(Math.floor(Date.now() / 1000), sess.sessionId);
    if (advisorUrl) {
      let peers: LogoutCancelTarget[];
      // A throw from the fleet side must not stop the logout it rides on.
      try { peers = logoutTargets ? logoutTargets() : []; } catch { peers = []; }
      revokeApprovalsOnLogout(sess.username, advisorUrl, advisorToken ?? null, peers);
    }
  }
  clearCookie(req, res, SESSION_COOKIE);
  sendJson(res, 200, { ok: true });
}

// POST /auth/magic  body: { token }
// Redeems a single-use enrollment token issued via the SSH CLI.
// Returns registration options + sets the apr_chal cookie so the
// browser can immediately POST /auth/register/finish to enroll a
// passkey for the named user.
async function handleMagic(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  let payload: { token?: string };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }
  if (!payload.token) { sendJson(res, 400, { error: 'token required' }); return; }
  // The DB stores SHA-256(token); hash the presented raw token before
  // lookup. Single-use (consumed_at) + TTL are enforced below, unchanged.
  const link = findMagicLink.get(hashToken(payload.token)) as {
    id: number; token: string; user_id: number; purpose: string;
    created_at: number; expires_at: number; consumed_at: number | null;
  } | undefined;
  if (!link) { sendJson(res, 404, { error: 'invalid token' }); return; }
  if (link.consumed_at != null) { sendJson(res, 410, { error: 'token already used' }); return; }
  if (link.expires_at < Math.floor(Date.now() / 1000)) {
    sendJson(res, 410, { error: 'token expired' }); return;
  }
  const user = getUserById(link.user_id);
  if (!user) { sendJson(res, 404, { error: 'user gone' }); return; }
  consumeMagicLink.run(Math.floor(Date.now() / 1000), link.id);
  await issueRegistrationCeremony(req, res, user);
}

/**
 * Issue WebAuthn registration options for a user and arm the challenge.
 *
 * ONE owner for the first-device enrollment ceremony. Two routes authorize
 * their way here and then do exactly the same thing:
 *
 *   /auth/magic        a single-use link proves the operator was invited
 *   /auth/setup/begin  a box with zero operators proves nobody owns it yet
 *
 * The authorization differs; the ceremony must not. Keeping it here is what
 * stops the bootstrap path drifting into a second registration
 * implementation with its own challenge shape or its own cookie TTL, and it
 * is why /auth/register/finish needed no change to serve either: the state
 * it reads is identical whichever route armed it.
 */
async function issueRegistrationCeremony(
  req: IncomingMessage, res: ServerResponse, user: AuthUser,
): Promise<void> {
  const existing = getCredentialsForUser(user.id);
  const opts = await generateRegistrationOptions({
    rpName: rpName(),
    rpID:   rpIDs()[0],
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    excludeCredentials: buildExcludeCredentials(existing),
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'register',
    username: user.username,
    userId: user.id,
    createdAt: Date.now(),
  });
  setCookie(req, res, CHALLENGE_COOKIE, chalId, Math.floor(CHALLENGE_TTL_MS / 1000));
  sendJson(res, 200, { username: user.username, options: opts });
}

// POST /auth/setup/begin  body: { username }
//
// #135 Step 1. Claim an unowned box: create the first administrator and
// hand back registration options so the browser can enroll their passkey.
//
// This is the only write in the product that runs with no session behind
// it, so what authorizes it is stated plainly: the box has zero operators,
// which means there is nobody to ask for permission and nobody whose
// permission is being bypassed. See lib/bootstrap-window.ts for why that
// is keyed on a user row and why deleting every operator reopens it.
//
// Three things are deliberately NOT taken from the request:
//   - the role, which is the literal 'admin' inside insertFirstAdmin
//   - whether the window is open, which is re-decided by that same statement
//   - who wins a race, which SQLite's write lock decides, not this handler
async function handleSetupBegin(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  let payload: { username?: unknown };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }

  // Cheap refusal first, so a closed window costs nothing and says the same
  // thing whatever was posted. The authoritative check is the INSERT below;
  // this one only saves work and gives a better message.
  if (!bootstrapWindowOpen()) {
    sendJson(res, 409, {
      error: 'already_owned',
      message: 'An administrator already exists on this dashboard. Sign in instead.',
    });
    return;
  }

  const name = checkOperatorName(payload.username);
  if (!name.ok) { sendJson(res, 400, { error: 'invalid_name', message: name.reason }); return; }

  // clientIp's caveat holds here too: an x-forwarded-for can be anything the
  // caller wrote. It is recorded, never acted on, and the row it lands in is
  // an account of what the open window was used for, not an authorization.
  const user = createFirstAdmin(name.value!, clientIp(req));
  if (!user) {
    // Lost the race. Another browser created the first administrator between
    // the check above and this INSERT, which is exactly what the single
    // statement exists to make survivable. Same message as the closed window:
    // from here they are the same situation.
    sendJson(res, 409, {
      error: 'already_owned',
      message: 'An administrator already exists on this dashboard. Sign in instead.',
    });
    return;
  }

  await issueRegistrationCeremony(req, res, user);
}

// GET /auth/setup/state
//
// The one place the wizard learns whether the window is open. It asks on
// every step rather than remembering the answer it got when the page loaded:
// the window can close under a page that is still on screen (another tab,
// another operator, `aperire-auth add` in an SSH session), and a wizard that
// went on offering to claim the box would be describing a door that is
// already shut. Kept versus observed, on the one fact this page exists for.
//
// GET, so no CSRF header, and read-only: it creates nothing, changes
// nothing, and the write it describes is refused by its own statement.
function handleSetupState(req: IncomingMessage, res: ServerResponse): void {
  sendJson(res, 200, setupState(readSession(req) !== null));
}

// ── Self-serve enrollment helpers (A2.1) ────────────────────────────
// Mask local-part of an email so the lock-screen can hint at where the
// enrollment URL would go without echoing the full address publicly.
//   operator@example.com → "o••••••r@example.com"
//   ab@example.org       → "a•@example.org"
function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at < 1) return email;
  const local  = email.slice(0, at);
  const domain = email.slice(at);
  if (local.length <= 2) return local[0] + '•' + domain;
  return local[0] + '•'.repeat(Math.max(3, local.length - 2)) + local[local.length - 1] + domain;
}

// Build the HTML body for an enrollment-link email. Mirrors
// auth-send-magic.mjs but inline so the server doesn't need to spawn
// a subprocess. Keep prose short — the operator usually wants the
// link, not a brochure.
function buildEnrollmentEmailHtml(url: string): string {
  const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]!));
  return `<!doctype html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1f2328;background:#fff;margin:0;padding:24px;">
  <div style="max-width:520px;margin:0 auto;">
    <h2 style="margin:0 0 16px;font-size:20px;">Enroll your Aperire passkey</h2>
    <p style="margin:0 0 16px;color:#555;line-height:1.5;">
      Click the link below to enroll a passkey on this device. Your browser
      will prompt for biometric verification (Touch ID, Face ID, Windows
      Hello, or a security key).
    </p>
    <p style="margin:24px 0;text-align:center;">
      <a href="${esc(url)}" style="display:inline-block;padding:12px 24px;background:#0969da;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">
        Enroll passkey
      </a>
    </p>
    <p style="margin:16px 0 0;color:#656d76;font-size:13px;line-height:1.5;">
      Or paste this URL into your browser:<br>
      <code style="display:inline-block;margin-top:6px;padding:6px 8px;background:#f6f8fa;border-radius:3px;font-size:12px;word-break:break-all;">${esc(url)}</code>
    </p>
    <hr style="border:0;border-top:1px solid #d1d9e0;margin:24px 0 12px;">
    <p style="margin:0;color:#8b949e;font-size:12px;">
      Single-use link. If you didn't request this, ignore this email — the
      URL becomes invalid as soon as it's used or after its expiry window.
    </p>
  </div>
</body></html>`;
}

// Read channels.yaml on demand for the email channel's API key + sender.
// Same shape as auth-send-magic.mjs's loader — keeps the logic next to
// where it's used without coupling auth.ts to server.ts's parse cache.
function loadEmailChannelForEnrollment(): { apiKey: string; sender: string } | null {
  try {
    const channelsPath = join(import.meta.dirname, 'config', 'channels.yaml');
    const text = readFileSync(channelsPath, 'utf8');
    type AnyObj = Record<string, unknown>;
    const doc = (yaml.load(text) as AnyObj) || {};
    const channels = (doc.channels as AnyObj) || {};
    const e = (channels.email as AnyObj) || {};
    if (e.provider !== 'resend') return null;
    const apiKeyEnv = typeof e.api_key_env === 'string' ? e.api_key_env : 'RESEND_API_KEY';
    const apiKey = process.env[apiKeyEnv];
    if (!apiKey) return null;
    const sender = typeof e.sender === 'string' ? e.sender : '';
    if (!sender) return null;
    return { apiKey, sender };
  } catch { return null; }
}

// True iff we could plausibly email `user`. Drives the
// enrollment_available flag returned by /auth/login/begin.
function canEmailEnrollLink(user: AuthUser): boolean {
  if (!user.email) return false;
  return !!loadEmailChannelForEnrollment();
}

// In-memory rate limiter for self-serve enrollment requests. Keyed
// by `u:<user_id>` for known operators and `n:<username>` for
// unknown handles — separate namespaces. Tying the bucket to user_id
// (not the public-facing handle) means a `delete + add` of an
// operator gives them a fresh bucket: the new row has a new id, even
// if the username is reused. 3 attempts per hour is generous for
// legitimate retry, useless for abuse. Lost on restart.
const ENROLL_RATE_LIMIT     = 3;
const ENROLL_RATE_WINDOW_MS = 60 * 60 * 1000;
const enrollAttempts = new Map<string, number[]>();
function enrollRateOk(key: string): { ok: boolean; resetTs: number | null } {
  const now = Date.now();
  const cutoff = now - ENROLL_RATE_WINDOW_MS;
  const bucket = (enrollAttempts.get(key) ?? []).filter(t => t >= cutoff);
  enrollAttempts.set(key, bucket);
  if (bucket.length >= ENROLL_RATE_LIMIT) {
    return { ok: false, resetTs: bucket[0] + ENROLL_RATE_WINDOW_MS };
  }
  bucket.push(now);
  return { ok: true, resetTs: null };
}

// The three facts an enrollment link is built from. One home each: the
// lock-screen's self-serve request and the Settings page both send this mail
// now, and two copies of the base URL is how one of them ends up pointing at
// the wrong origin.
function enrollmentTtlMinutes(): number {
  return loadAuthnConfig().magic_link?.ttl_minutes ?? 15;
}
function enrollmentSubject(): string {
  return loadAuthnConfig().magic_link?.email_subject ?? 'Aperire — enroll your passkey';
}
function enrollmentBaseUrl(): string {
  return (loadAuthnConfig().public_url || 'http://localhost:7800')
    .split(',')[0].trim().replace(/\/$/, '');
}

/**
 * Mint a link, and hand the caller the URL.
 *
 * The raw token is in the returned URL and nowhere else. No audit row is
 * written here (`record: false`): the caller knows whether the mail went
 * out, which is the fact the row exists to carry, and it writes one row with
 * that in it rather than this writing a second without.
 */
export function issueEnrollmentLink(
  userId: number, purpose: 'enroll' | 'recover',
): { url: string; expiresAt: number } {
  const ttlMin = enrollmentTtlMinutes();
  // Read before the insert, so the expiry reported is never later than the
  // one stored. A link that says it expires a second early is harmless; one
  // that says it is still good after the row says otherwise is not.
  const issuedAt = Math.floor(Date.now() / 1000);
  const token = issueMagicLink(userId, purpose, ttlMin, { record: false });
  return { url: `${enrollmentBaseUrl()}/login.html?token=${token}`, expiresAt: issuedAt + ttlMin * 60 };
}

/**
 * Send it, when there is somewhere to send it.
 *
 * `emailed:false` with no error is the ordinary state of a box with no email
 * channel configured, or an account with no address: nothing failed, there
 * was nowhere to send. The log line carries a masked address and never the
 * URL, which holds the token.
 */
export async function emailEnrollmentLink(
  to: string | null, url: string,
): Promise<{ emailed: boolean; error?: string }> {
  if (!to) return { emailed: false };
  const channel = loadEmailChannelForEnrollment();
  if (!channel) return { emailed: false };
  try {
    const r = await sendDigestEmail(
      { apiKey: channel.apiKey, sender: channel.sender, recipients: [to] },
      enrollmentSubject(), buildEnrollmentEmailHtml(url),
    );
    if (r.ok) {
      console.log(`[authn] enrollment email sent to ${maskEmail(to)} (id ${r.messageId ?? '?'})`);
      return { emailed: true };
    }
    console.warn(`[authn] enrollment email failed for ${maskEmail(to)}: ${r.error}`);
    return { emailed: false, error: r.error };
  } catch (err) {
    console.warn(`[authn] enrollment email threw for ${maskEmail(to)}:`, (err as Error).message);
    return { emailed: false, error: (err as Error).message };
  }
}

// ── /auth/enroll/request ─────────────────────────────────────────
// POST { username }
// Issues a magic-link for `username`, emails it via the configured
// Resend channel. CSRF-protected and rate-limited per-username.
// Always-200 on path-finding errors (unknown user, no email, etc.) to
// avoid leaking which usernames exist; the rate-limit is the only
// outwardly distinguishable signal.
async function handleEnrollRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!csrfOk(req)) { sendJson(res, 403, { error: 'csrf' }); return; }
  const body = await readBody(req);
  let payload: { username?: string };
  try { payload = JSON.parse(body || '{}'); } catch { sendJson(res, 400, { error: 'bad json' }); return; }
  if (!payload.username) { sendJson(res, 400, { error: 'username required' }); return; }
  const username = payload.username;

  // Look up the user FIRST so we can rate-limit by user_id (stable
  // across delete+re-add — a fresh row gets a fresh bucket). Unknown
  // usernames fall back to a name-keyed bucket so an attacker can't
  // probe for accounts by burning unrelated user_id slots.
  const user = getUserByUsername(username);
  const rateKey = user ? `u:${user.id}` : `n:${username}`;
  const rate = enrollRateOk(rateKey);
  if (!rate.ok) {
    sendJson(res, 429, {
      error: 'too many enrollment requests for this operator — try again later',
      reset_at: rate.resetTs,
    });
    return;
  }

  // Below this point the response is always 200 to avoid revealing
  // whether the username exists or has an email on file. Enumeration
  // through the lock-screen is therefore no easier than the basic
  // "username unknown" path of /auth/login/begin.
  const okResponse = (hint: string | null) => sendJson(res, 200, {
    ok: true,
    email_hint: hint,
  });

  if (!user || !user.email) { okResponse(null); return; }
  const channelCfg = loadEmailChannelForEnrollment();
  if (!channelCfg) { okResponse(null); return; }

  const ttlMin = enrollmentTtlMinutes();
  const subject = enrollmentSubject();
  const baseUrl = enrollmentBaseUrl();
  const token = issueMagicLink(user.id, 'enroll', ttlMin);
  const url = `${baseUrl}/login.html?token=${token}`;
  const html = buildEnrollmentEmailHtml(url);

  // Fire-and-forget the send; we already promised 200. Logging the
  // outcome lets the operator diagnose Resend issues from the server
  // log without surfacing them to whoever clicked the button.
  sendDigestEmail({ apiKey: channelCfg.apiKey, sender: channelCfg.sender, recipients: [user.email] }, subject, html)
    .then(r => {
      if (r.ok) console.log(`[authn] enrollment email sent to ${maskEmail(user.email!)} (id ${r.messageId ?? '?'})`);
      else      console.warn(`[authn] enrollment email failed for ${username}: ${r.error}`);
    })
    .catch(err => console.warn(`[authn] enrollment email threw for ${username}:`, (err as Error).message));

  okResponse(maskEmail(user.email));
}

// ── Dispatcher ─────────────────────────────────────────────────────
// Returns true if the request was handled, false to fall through to
// the rest of server.ts. Wired in A1; the requireAuth middleware that
// gates /api/* lives in A2.
export async function handleAuthRequest(
  req: IncomingMessage, res: ServerResponse, pathname: string,
  advisorUrl?: string, advisorToken?: string | null,
  logoutTargets?: () => LogoutCancelTarget[],
): Promise<boolean> {
  if (!pathname.startsWith('/auth/')) return false;
  // CSRF: every state-changing /auth route (all non-GET) requires the
  // X-Aperire-CSRF header. Cross-site JS cannot set a custom header without
  // a preflight the browser will block, and the session cookie is only
  // SameSite=Lax — so this is the defense for the session-minting routes
  // (login/finish, register/finish, magic) as well as touch/lock/enroll.
  // GET /auth/session is read-only and stays exempt.
  if (req.method !== 'GET' && !csrfOk(req)) { sendJson(res, 403, { error: 'csrf' }); return true; }
  try {
    if (pathname === '/auth/register/begin'  && req.method === 'POST') { await handleRegisterBegin(req, res);  return true; }
    if (pathname === '/auth/register/finish' && req.method === 'POST') { await handleRegisterFinish(req, res, advisorUrl, advisorToken); return true; }
    if (pathname === '/auth/login/begin'     && req.method === 'POST') { await handleLoginBegin(req, res);    return true; }
    if (pathname === '/auth/login/finish'    && req.method === 'POST') { await handleLoginFinish(req, res);   return true; }
    if (pathname === '/auth/session'         && req.method === 'GET')  { handleSession(req, res); return true; }
    if (pathname === '/auth/touch'           && req.method === 'POST') { handleTouch(req, res);   return true; }
    if (pathname === '/auth/lock'            && req.method === 'POST') { handleLock(req, res, advisorUrl, advisorToken, logoutTargets); return true; }
    if (pathname === '/auth/magic'           && req.method === 'POST') { await handleMagic(req, res); return true; }
    if (pathname === '/auth/enroll/request'  && req.method === 'POST') { await handleEnrollRequest(req, res); return true; }
    if (pathname === '/auth/setup/begin'     && req.method === 'POST') { await handleSetupBegin(req, res); return true; }
    if (pathname === '/auth/setup/state'     && req.method === 'GET')  { handleSetupState(req, res); return true; }
    sendJson(res, 405, { error: 'method not allowed' });
    return true;
  } catch (err) {
    // LOW-04: log the real error; never echo its message to the client.
    console.error('[auth] handler threw:', err);
    if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
    return true;
  }
}

// ── Advisor approval ceremony ──────────────────────────────────────────
//
// A passkey assertion, bound to one plan and one stage, signed by the
// credential that opened this session.
//
// Three bindings, and all three are enforced server-side:
//
//   1. The CHALLENGE is derived from a plan the Advisor computed. The client
//      names a target version; it never supplies a fingerprint. An assertion
//      for plan A is therefore worthless for plan B.
//
//   2. The CREDENTIAL must be the one that opened this session. allowCredentials
//      is only a hint — a malicious page can ignore it and sign with any
//      registered key — so the returned credential is compared against the
//      session's after verification. That is the enforcement; the hint is only
//      so the browser does not show a picker.
//
//   3. The USER must be the session's user.
//
// What this does NOT defend against, stated plainly because it matters:
// WebAuthn has no trusted transaction display. The authenticator prompt names
// the site, not the action. A compromised dashboard page could show one plan
// while requesting a challenge for another, and a real fingerprint would
// approve the wrong thing. The extension meant to fix that, txAuthSimple, was
// never implemented by browsers. What carries the rest is the executor
// re-measuring preconditions after approval, the stage split, and a ledger
// entry recording the fingerprint that was actually signed.

/** The shape the browser's WebAuthn response arrives in. */
interface AssertionResponse {
  id?: string;
  response?: { authenticatorData?: string; clientDataJSON?: string; signature?: string };
}

interface AdvisorPlanRef {
  planId: string;
  fingerprint: string;
  blocked: boolean;
  /** Per stage, because a check an earlier stage satisfies cannot forbid it. */
  blockedFor: Record<string, boolean>;
  failures: string[];
  /** Failures that stop the named stage specifically. */
  failuresFor(stage: string): string[];
}

// ── ADR 0016: two runbooks, one ceremony ────────────────────────────────
//
// A table rather than a branch. `if (runbook === 'restart-node') … else …`
// reads identically and carries an unstated else: a third runbook falls into
// the upgrade's arm and is handed its stage list, its version regex and its
// gate stage, none of which it declares. Everything a ceremony is allowed to
// name for a runbook is here, in one place, keyed by the runbook's own id.
//
// This mirrors the Advisor's own rules (internal/runbook) rather than
// replacing them: advisord validates all of this again from the runbook
// definition itself, and that check is the one that decides. This one exists
// so a wrong value is refused BEFORE the operator touches their passkey —
// `intent` in particular is bound into the fingerprint, so a bad one comes
// back as a 409 from /v1/approve after the ceremony, not before it.

interface CeremonyRules {
  /** Grant scopes this runbook's ceremony may sign over — its GrantScopes. */
  readonly stages: readonly string[];
  /** True when the runbook declares a version parameter. */
  readonly wantsTarget: boolean;
  /** The enum this runbook binds, or null when it binds none. */
  readonly intents: readonly string[] | null;
  /**
   * The configuration keys this runbook may name, or null when it names
   * none. RB-003's `key` and `value` are inside the fingerprint exactly as
   * `intent` is, so a ceremony begun without them is a ceremony for a
   * different plan — and a key outside this list is refused here, before the
   * operator touches a passkey, rather than as a 409 afterwards.
   *
   * The band a value has to satisfy is deliberately NOT here. It is a
   * function of the key, it lives in the privilege wrapper and is mirrored
   * once in the Advisor's own table, and a third copy in the dashboard would
   * be the one that rots. This checks the shape; advisord checks the band.
   */
  readonly configKeys: readonly string[] | null;
  /**
   * RB-005's `change` enum (ADR 0023), or null when the runbook binds none.
   * Inside the fingerprint exactly as `intent` is. The order matters and is
   * enforced on the Advisor's side, against the deployment it reads; this
   * list only refuses a value that is not one of the three.
   */
  readonly changes: readonly string[] | null;
  /**
   * True when this runbook takes #682's source override. Only the upgrade
   * does. 'build' is the one value a caller may send: 'official' is what
   * the Advisor decides for itself from the registry, and a browser naming
   * it would be a browser choosing where an image comes from.
   */
  readonly wantsSource: boolean;
  /** Which stage's blocked_for decides whether this grant may be issued. */
  gateStage(stage: string): string;
}

const DEFAULT_RUNBOOK = 'upgrade-xrpld';

const CEREMONY_RULES: Record<string, CeremonyRules> = {
  // 'upgrade' is the one-approval compound scope: a real thing to sign over,
  // covering prepare and then cutover in sequence (Covers, in
  // internal/approval). It is gated exactly as prepare is — cutover's own
  // preconditions are re-measured at the handoff, on the host.
  [DEFAULT_RUNBOOK]: {
    stages: ['prepare', 'cutover', 'upgrade'],
    wantsTarget: true,
    intents: null,
    configKeys: null,
    changes: null,
    wantsSource: true,
    gateStage: (stage) => (stage === 'upgrade' ? 'prepare' : stage),
  },
  // One stage, and it is the whole runbook. There is no reversible half, so
  // there is no earlier stage whose own checks could be deferred: the gate
  // stage is the stage.
  'restart-node': {
    stages: ['restart'],
    wantsTarget: false,
    intents: ['apply-config', 'resource-pressure', 'planned-maintenance', 'operator-judgement'],
    configKeys: null,
    changes: null,
    wantsSource: false,
    gateStage: (stage) => stage,
  },
  // ADR 0018. 'config-restart' is the compound scope: one ceremony covering
  // the edit and then the restart that makes it take effect. It is gated as
  // the EDIT is — the restart's own preconditions, the container-can-read
  // check among them, are re-measured at the handoff, on the host. Gating
  // the grant on them here would refuse the first change on exactly the host
  // that needs one.
  'config-change': {
    stages: ['config', 'restart', 'config-restart'],
    wantsTarget: false,
    intents: null,
    configKeys: ['online_delete', 'advisory_delete', 'node_size', 'ledger_history'],
    changes: null,
    wantsSource: false,
    gateStage: (stage) => (stage === 'config-restart' ? 'config' : stage),
  },
  // ADR 0019. One stage and one scope: the rollback IS the restart, so there
  // is no reversible half whose checks could be deferred, and no compound
  // scope to sign over. The gate stage is the stage.
  //
  // It wants a target, and that target is NOT the newest release: the Advisor
  // derives it from the node's own dated deployment copies and run history,
  // and refuses any other. The shape check here is the same one the upgrade
  // gets, because the fingerprint is computed from whatever arrives.
  'rollback-node': {
    stages: ['rollback'],
    wantsTarget: true,
    intents: ['planned-rollback', 'regression-suspected', 'operator-judgement'],
    configKeys: null,
    changes: null,
    wantsSource: false,
    gateStage: (stage) => stage,
  },
  // ADR 0023. One change to the deployment file, one stage, one scope. The
  // gate stage is the stage: there is no reversible half, the reversal is
  // restoring the dated copy the wrapper takes before it writes.
  'normalise-deployment': {
    stages: ['normalise'],
    wantsTarget: false,
    intents: null,
    configKeys: null,
    changes: ['runtime-user', 'config-mount', 'node-args'],
    wantsSource: false,
    gateStage: (stage) => stage,
  },
};

interface Ceremony {
  runbook: string;
  stage: string;
  target: string;
  intent: string;
  key: string;
  value: string;
  change: string;
  user: string;
  source: string;
  rules: CeremonyRules;
}

/**
 * Validates one ceremony's runbook, stage, target and intent together, since
 * none of the four means anything on its own. Returns the normalised set or
 * the one sentence that says what was wrong with it.
 *
 * An absent runbook is the upgrade, which is what every caller written
 * before RB-002 sends — the same default advisord applies, named in both
 * places rather than inferred in one.
 */
// Exported for its own test. The same reason origins() is: this is the one
// place that says which combinations of runbook, stage, target, intent, key,
// change, user and source are a plan at all, and a refusal it gets wrong is
// a 409 the operator meets AFTER touching their passkey.
export function resolveCeremony(
  runbookRaw: unknown, stageRaw: unknown, targetRaw: unknown, intentRaw: unknown,
  keyRaw: unknown = undefined, valueRaw: unknown = undefined,
  changeRaw: unknown = undefined, userRaw: unknown = undefined,
  sourceRaw: unknown = undefined,
): { ok: true; ceremony: Ceremony } | { ok: false; error: string } {
  const runbook = String(runbookRaw ?? '') || DEFAULT_RUNBOOK;
  const rules = Object.prototype.hasOwnProperty.call(CEREMONY_RULES, runbook)
    ? CEREMONY_RULES[runbook] : undefined;
  if (!rules) return { ok: false, error: 'bad runbook' };

  const stage = String(stageRaw ?? '');
  if (!rules.stages.includes(stage)) return { ok: false, error: 'bad stage' };

  const target = String(targetRaw ?? '');
  if (rules.wantsTarget) {
    if (!/^[0-9]+(\.[0-9]+)*$/.test(target)) return { ok: false, error: 'bad target' };
  } else if (target !== '') {
    // Not merely ignored. A version sent for a runbook that binds none is a
    // caller that believes it is approving something else, and the
    // fingerprint it would get back is not the one it is about to display.
    return { ok: false, error: 'this runbook takes no target version' };
  }

  const intent = String(intentRaw ?? '');
  if (rules.intents) {
    if (!rules.intents.includes(intent)) return { ok: false, error: 'bad intent' };
  } else if (intent !== '') {
    return { ok: false, error: 'this runbook takes no intent' };
  }

  const key = String(keyRaw ?? '');
  const value = String(valueRaw ?? '');
  if (rules.configKeys) {
    if (!rules.configKeys.includes(key)) return { ok: false, error: 'bad configuration key' };
    // Shape only — the band belongs to the wrapper and the Advisor's mirror
    // of it. What this refuses is anything that is not a short token, which
    // is the same bound the model's own parser applies.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(value)) {
      return { ok: false, error: 'bad configuration value' };
    }
  } else if (key !== '' || value !== '') {
    // Not merely ignored, for the reason a stray target is not: a caller
    // sending a key to a runbook that binds none believes it is approving
    // something else, and the fingerprint it gets back is not the one it is
    // about to display.
    return { ok: false, error: 'this runbook takes no configuration key' };
  }

  const change = String(changeRaw ?? '');
  const user = String(userRaw ?? '');
  if (rules.changes) {
    if (!rules.changes.includes(change)) return { ok: false, error: 'bad deployment change' };
    // The one change that takes a value, in the one shape the wrapper
    // accepts: numeric, because a name resolves differently inside the
    // container than on the host, and the whole point of writing the line
    // is that the node comes back as the account it went down as.
    if (change === 'runtime-user') {
      if (!/^[0-9]{1,10}:[0-9]{1,10}$/.test(user)) return { ok: false, error: 'bad runtime user' };
    } else if (user !== '') {
      return { ok: false, error: 'this change takes no user' };
    }
  } else if (change !== '' || user !== '') {
    // Not merely ignored, for the reason a stray key is not: a caller
    // sending a change to a runbook that binds none believes it is
    // approving something else.
    return { ok: false, error: 'this runbook takes no deployment change' };
  }

  const source = String(sourceRaw ?? '');
  if (rules.wantsSource) {
    // 'build' or nothing. Naming the official image is the Advisor's
    // decision, taken from the registry and pinned to a digest on its own
    // side; a browser that could name it could choose what gets installed.
    if (source !== '' && source !== 'build') return { ok: false, error: 'bad image source' };
  } else if (source !== '') {
    return { ok: false, error: 'this runbook takes no image source' };
  }

  return { ok: true, ceremony: { runbook, stage, target, intent, key, value, change, user, source, rules } };
}

/** Asks the Advisor to compute the plan. The client never supplies these. */
async function advisorPlan(
  advisorUrl: string, target: string, token: string | null,
  runbook = DEFAULT_RUNBOOK, intent = '', key = '', value = '',
  change = '', user = '', source = '',
): Promise<AdvisorPlanRef> {
  // The plan the fingerprint is computed from has to be the plan the
  // ceremony is about. Both parameters travel here for that reason: an
  // absent runbook means the upgrade upstream, so a restart plan fetched
  // without one comes back as the upgrade's — same plan_id shape, different
  // plan — and `intent` is inside the fingerprint, so a check run without it
  // disagrees with /v1/approve/begin about what was evaluated.
  const q = new URLSearchParams();
  if (target) q.set('target', target);
  if (runbook !== DEFAULT_RUNBOOK) q.set('runbook', runbook);
  if (intent) q.set('intent', intent);
  // Both, or neither. They are bound into the fingerprint together, and a
  // check run with one of them is a check of a plan that cannot exist.
  if (key) { q.set('key', key); q.set('value', value); }
  // RB-005's two and #682's one, for the reason key and value travel: all
  // three are inside the fingerprint, so a check run without them is a
  // check of a different plan than the one about to be approved.
  if (change) { q.set('change', change); if (user) q.set('user', user); }
  if (source) q.set('source', source);
  const r = await fetch(`${advisorUrl}/v1/check?${q.toString()}`, {
    headers: { authorization: `Bearer ${token ?? ''}` },
    signal: AbortSignal.timeout(30_000),
  });
  if (!r.ok) throw new Error(`the Advisor could not evaluate this plan (${r.status})`);
  const b = await r.json() as {
    plan_id?: string; fingerprint?: string; blocked?: boolean;
    blocked_for?: Record<string, boolean>;
    verdicts?: Array<{ name: string; passed: boolean; detail: string; gates?: string }>;
  };
  if (!b.fingerprint || !b.plan_id) throw new Error('the Advisor returned no plan identity');
  const verdicts = b.verdicts ?? [];
  return {
    planId: b.plan_id,
    fingerprint: b.fingerprint,
    blocked: !!b.blocked,
    blockedFor: b.blocked_for ?? {},
    failures: verdicts.filter(v => !v.passed).map(v => `${v.name} — ${v.detail}`),
    failuresFor(stage: string): string[] {
      return verdicts
        .filter(v => !v.passed && (!v.gates || v.gates === stage))
        .map(v => `${v.name} — ${v.detail}`);
    },
  };
}

export async function handleAdvisorApproveBegin(
  req: IncomingMessage, res: ServerResponse, advisorUrl: string, advisorToken: string | null,
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, {
      error: 'this operator may not approve Advisor actions',
      detail: `Role is ${sess.role}. An admin can change it on the dashboard host: bash scripts/aperire-auth.sh set-role <email> admin`,
    });
    return;
  }
  if (!sess.credentialId) {
    sendJson(res, 409, {
      error: 'this session predates passkey-bound approval',
      detail: 'Sign out and back in, so the session records which passkey opened it.',
    });
    return;
  }

  const payload = JSON.parse((await readBody(req)) || '{}') as
    { target?: string; stage?: string; runbook?: string; intent?: string; key?: string; value?: string;
      change?: string; user?: string; source?: string };
  // Runbook, stage, target and intent are validated together — none of the
  // four means anything on its own, and the combination is what the
  // fingerprint is computed from. See CEREMONY_RULES above.
  const resolved = resolveCeremony(
    payload?.runbook, payload?.stage, payload?.target, payload?.intent, payload?.key, payload?.value,
    payload?.change, payload?.user, payload?.source);
  if (!resolved.ok) { sendJson(res, 400, { error: resolved.error }); return; }
  const { runbook, stage, target, intent, key, value, change, user: runAs, source, rules } = resolved.ceremony;

  let plan: AdvisorPlanRef;
  try {
    plan = await advisorPlan(advisorUrl, target, advisorToken, runbook, intent, key, value,
      change, runAs, source);
  } catch (err) {
    sendJson(res, 503, { error: (err as Error).message });
    return;
  }
  // Refuse per stage, not per plan. A precondition that an EARLIER stage
  // satisfies cannot also forbid approving that stage: the two backup checks
  // are taken by prepare, so gating prepare's approval on them meant a host
  // that had never been upgraded could never approve the step that would
  // have unblocked it. The stage that interrupts validation still refuses
  // until its own checks pass, which is the protection that matters.
  //
  // A compound 'upgrade' grant is gated exactly as prepare is — cutover's
  // own preconditions are re-measured at the handoff between stages, on the
  // host, never inferred here. Gating the grant itself on them would
  // resurrect the same "unapprovable on a first upgrade" bug this comment
  // already describes, in a new shape.
  const gateStage = rules.gateStage(stage);
  const stageBlocked = typeof plan.blockedFor[gateStage] === 'boolean'
    ? plan.blockedFor[gateStage]
    : plan.blocked;
  if (stageBlocked) {
    sendJson(res, 409, {
      error: `the Advisor refuses the ${stage} stage right now`,
      failures: plan.failuresFor(gateStage),
    });
    return;
  }

  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    sendJson(res, 409, { error: 'the passkey that opened this session is no longer registered' });
    return;
  }

  // The challenge comes from the Advisor, bound there to this plan and this
  // stage. The dashboard used to generate its own, which named neither — so a
  // captured prepare ceremony could be replayed as a cutover and the Advisor's
  // independent check could not tell. Fail closed: no challenge, no ceremony.
  let advisorChallenge: string;
  try {
    const tok = advisorToken;
    if (!tok) {
      sendJson(res, 503, { error: 'no approval token installed; web approval is disabled on this host' });
      return;
    }
    const br = await fetch(`${advisorUrl}/v1/approve/begin`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${tok}` },
      // Both new fields travel as their own keys. `intent` is deliberately
      // NOT the free-text reason sent at finish: this one is an enum and is
      // inside the fingerprint, that one is prose and is outside it, and one
      // field carrying both is how a plan gets approved that nobody read.
      body: JSON.stringify({ target, stage, runbook, intent, key, value, change, user: runAs, source }),
      signal: AbortSignal.timeout(30_000),
    });
    const bj = await br.json() as { challenge?: string; fingerprint?: string; error?: string };
    if (!br.ok || !bj.challenge) {
      // Never a 502 (#1134): the edge in front of an aggregator replaces it with
      // its own page, and the Advisor's sentence goes with it.
      sendJson(res, edgeSafeStatus(502), { error: bj.error ?? 'the Advisor would not issue a challenge' });
      return;
    }
    // The Advisor computes the fingerprint from the plan it would actually
    // run. If it disagrees with the one this ceremony is about to display,
    // stop — the operator would be approving a different thing than they see.
    if (bj.fingerprint && bj.fingerprint !== plan.fingerprint) {
      sendJson(res, 409, { error: 'the plan changed while the ceremony was starting; nothing was approved' });
      return;
    }
    advisorChallenge = bj.challenge;
  } catch (err) {
    sendJson(res, 503, { error: `the Advisor did not answer: ${(err as Error).message}` });
    return;
  }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    // Passed as bytes, not as a string: the library UTF-8-encodes a string
    // before base64url-ing it, which would make what the browser signs differ
    // from what the Advisor issued. Decoding first keeps them byte-identical.
    challenge: new Uint8Array(Buffer.from(advisorChallenge, 'base64url')),
    // A hint, not the enforcement. See the note above.
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'approve',
    userId: sess.userId,
    createdAt: Date.now(),
    approve: {
      planId: plan.planId, fingerprint: plan.fingerprint, stage,
      target, runbook, intent, key, value, change, user: runAs, source,
      sessionId: sess.sessionId, credentialId: cred.credential_id,
    },
  });

  sendJson(res, 200, {
    challenge_id: chalId,
    options: opts,
    plan: { plan_id: plan.planId, fingerprint: plan.fingerprint, stage, target, runbook, intent, key, value,
      change, user: runAs, source },
  });
}

export async function handleAdvisorApproveFinish(
  req: IncomingMessage, res: ServerResponse, advisorUrl: string, advisorToken: string | null,
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  // Checked again here, not only at begin. A role can be revoked between the
  // two halves of a ceremony, and the half that authorises is this one.
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, { error: 'this operator may not approve Advisor actions' });
    return;
  }

  const payload = JSON.parse((await readBody(req, 64 * 1024)) || '{}') as
    { challenge_id?: string; response?: unknown; ttl_seconds?: number; reason?: string };
  const chalId = String(payload?.challenge_id ?? '');
  const rec = pendingChallenges.get(chalId);
  // Single use, whatever happens next.
  pendingChallenges.delete(chalId);

  if (!rec || rec.type !== 'approve' || !rec.approve) {
    sendJson(res, 400, { error: 'no such ceremony, or it has already been used' });
    return;
  }
  if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
    sendJson(res, 408, { error: 'the ceremony expired; start it again' });
    return;
  }
  if (rec.approve.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
    sendJson(res, 403, { error: 'this ceremony belongs to a different session' });
    return;
  }

  const cred = findCredentialById.get(rec.approve.credentialId) as AuthCredential | undefined;
  if (!cred) { sendJson(res, 409, { error: 'the credential is no longer registered' }); return; }

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: payload?.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
      },
      requireUserVerification: true,
    });
  } catch {
    sendJson(res, 400, { error: 'the passkey did not verify' });
    return;
  }
  if (!result.verified) { sendJson(res, 400, { error: 'the passkey did not verify' }); return; }

  // THE enforcement. allowCredentials is advisory; this is not.
  const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
  if (usedId !== rec.approve.credentialId || usedId !== sess.credentialId) {
    sendJson(res, 403, {
      error: 'that is not the passkey that opened this session',
      detail: 'Approvals must be signed by the authenticator holding the session.',
    });
    return;
  }

  const ts = Math.floor(Date.now() / 1000);
  updateCredentialCounter.run(result.authenticationInfo.newCounter, ts, cred.id);

  if (!advisorToken) {
    sendJson(res, 503, { error: 'no approval token installed; web approval is disabled on this host' });
    return;
  }
  const user = getUserById(sess.userId);
  // The Advisor's answer, or a 504/502 that says it gave none (#1051). A slow
  // answer used to abort out of here as an uncaught throw, which the outer
  // handler turned into a bare `internal_error` while the Advisor went on to
  // refuse the approval with its reasons in the ledger.
  const answer = await postAdvisorApprove(advisorUrl, advisorToken, {
      plan_id: rec.approve.planId,
      fingerprint: rec.approve.fingerprint,
      stage: rec.approve.stage,
      target: rec.approve.target,
      // Verbatim from the record this server wrote at begin, never from the
      // finishing request. The Advisor recomputes the fingerprint from these,
      // and a value the browser could change between the two halves of one
      // ceremony would fail the grant after the passkey had already been
      // touched — ADR 0016.
      runbook: rec.approve.runbook,
      intent: rec.approve.intent,
      key: rec.approve.key,
      value: rec.approve.value,
      change: rec.approve.change,
      user: rec.approve.user,
      source: rec.approve.source,
      granted_by: user?.username ?? `user:${sess.userId}`,
      // The role this operator held AT THE MOMENT of the ceremony. Derived
      // here from the session, exactly like granted_by and for the same
      // reason — never sent by the browser. Role is enforced everywhere in
      // this system and, until now, recorded nowhere: a demotion afterwards
      // left "was the person who restarted this node an admin at the time"
      // with no answer at all.
      granted_by_role: sess.role ?? '',
      ttl_seconds: Math.min(Math.max(Number(payload?.ttl_seconds ?? 600), 60), 1800),
      reason: String(payload?.reason ?? '').slice(0, 300),
      credential_id: cred.credential_id,
      session_user: user?.username ?? '',
      origin: origins()[0] ?? '',
      // The raw assertion, carried through so the Advisor can verify it
      // independently against keys it holds itself. Without this the Advisor
      // is trusting that the dashboard checked — and an approval that only a
      // service vouches for is one that a stolen service token can forge.
      assertion: {
        credential_id: cred.credential_id,
        authenticator_data: (payload?.response as AssertionResponse)?.response?.authenticatorData ?? '',
        client_data_json: (payload?.response as AssertionResponse)?.response?.clientDataJSON ?? '',
        signature: (payload?.response as AssertionResponse)?.response?.signature ?? '',
      },
      challenge: rec.challenge,
  });
  res.writeHead(answer.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(answer.body);
}

// POST /api/advisor/cancel-approval — revoke an approval before it runs.
//
// Same gate as granting one: an admin session, checked here rather than
// trusted from the proxy allow-list, because revoking is still an act on the
// node's behalf even though it undoes rather than does. No passkey ceremony
// — undoing consent does not need consent re-proven, and requiring one would
// make "I changed my mind" cost exactly as much as the mistake it is meant to
// let the operator back out of.
export async function handleAdvisorApproveCancel(
  req: IncomingMessage, res: ServerResponse, advisorUrl: string, advisorToken: string | null,
  // For the test that drives a slow Advisor without waiting thirty seconds.
  // Production callers pass nothing and get the ceiling.
  opts: { timeoutMs?: number } = {},
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, { error: 'this operator may not cancel Advisor approvals' });
    return;
  }
  if (!csrfOk(req)) { sendJson(res, 403, { error: 'csrf' }); return; }

  const payload = JSON.parse((await readBody(req, 8 * 1024)) || '{}') as
    { plan_id?: string; stage?: string; reason?: string; runbook?: string };
  const planId = String(payload?.plan_id ?? '');
  const stage = String(payload?.stage ?? '');
  // ADR 0016's eighth dashboard edit, beyond the seven the ADR tables: the
  // Advisor validates a named stage against the runbook it belongs to, so a
  // cancel that does not say which runbook cancels a restart as if it were an
  // upgrade stage and is refused there. An absent runbook is the upgrade,
  // which is what every caller written before RB-002 sends.
  const runbook = String(payload?.runbook ?? '') || DEFAULT_RUNBOOK;
  const rules = Object.prototype.hasOwnProperty.call(CEREMONY_RULES, runbook)
    ? CEREMONY_RULES[runbook] : undefined;
  if (!rules) { sendJson(res, 400, { error: 'bad runbook' }); return; }
  // No stage is the logout sweep: clear every unspent approval this operator
  // holds, wherever it is. It names no stage, so there is none to validate.
  if (stage && !rules.stages.includes(stage)) {
    sendJson(res, 400, { error: 'bad stage' }); return;
  }
  if (stage && !planId) { sendJson(res, 400, { error: 'plan_id is required with a stage' }); return; }

  if (!advisorToken) {
    sendJson(res, 503, { error: 'no approval token installed; web approval is disabled on this host' });
    return;
  }
  const user = getUserById(sess.userId);
  // #1096: a slow Advisor is a 504 with a reason, not an uncaught abort.
  const answer = await postAdvisorCancel(advisorUrl, advisorToken, {
    plan_id: planId, stage, runbook,
    granted_by: user?.username ?? `user:${sess.userId}`,
    granted_by_role: sess.role ?? '',
    reason: String(payload?.reason ?? '').slice(0, 300),
  }, opts);
  res.writeHead(answer.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(answer.body);
}

// POST /api/advisor/investigate-begin — break glass's own ceremony start
// (plan-interrogative-loop §11.8). Mirrors handleAdvisorApproveBegin: the
// Advisor computes the fingerprint from an offer record IT holds (never
// from anything this request supplies) and issues a challenge bound to it,
// which this ceremony then asks the browser's passkey to sign.
export async function handleAdvisorInvestigateBegin(
  req: IncomingMessage, res: ServerResponse, advisorUrl: string, advisorToken: string | null,
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  // §11.7: a monitor sees the offer as information, with no control. This
  // is the boundary — the drawer's rendering choice is a courtesy on top
  // of it, not instead of it.
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, {
      error: 'this operator may not break glass',
      detail: `Role is ${sess.role}. An admin can change it on the dashboard host: bash scripts/aperire-auth.sh set-role <email> admin`,
    });
    return;
  }
  if (!sess.credentialId) {
    sendJson(res, 409, {
      error: 'this session predates passkey-bound approval',
      detail: 'Sign out and back in, so the session records which passkey opened it.',
    });
    return;
  }

  const payload = JSON.parse((await readBody(req)) || '{}') as { offer_id?: string };
  const offerId = String(payload?.offer_id ?? '');
  if (!offerId) { sendJson(res, 400, { error: 'no offer_id' }); return; }

  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    sendJson(res, 409, { error: 'the passkey that opened this session is no longer registered' });
    return;
  }

  if (!advisorToken) {
    sendJson(res, 503, { error: 'no approval token installed; web approval is disabled on this host' });
    return;
  }
  let advisorChallenge: string;
  let fingerprint: string;
  let confirmCode: string;
  let why: string;
  let wouldRead: string[];
  try {
    const br = await fetch(`${advisorUrl}/v1/investigate/begin`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${advisorToken}` },
      body: JSON.stringify({ offer_id: offerId }),
      signal: AbortSignal.timeout(30_000),
    });
    const bj = await br.json() as {
      challenge?: string; fingerprint?: string; confirm_code?: string;
      why?: string; would_read?: string[]; error?: string;
    };
    if (!br.ok || !bj.challenge || !bj.fingerprint) {
      sendJson(res, edgeSafeStatus(br.status && br.status !== 200 ? br.status : 502),
        { error: bj.error ?? 'the Advisor would not issue a challenge' });
      return;
    }
    advisorChallenge = bj.challenge;
    fingerprint = bj.fingerprint;
    confirmCode = bj.confirm_code ?? '';
    why = bj.why ?? '';
    wouldRead = bj.would_read ?? [];
  } catch (err) {
    sendJson(res, 503, { error: `the Advisor did not answer: ${(err as Error).message}` });
    return;
  }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    challenge: new Uint8Array(Buffer.from(advisorChallenge, 'base64url')),
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'investigate',
    userId: sess.userId,
    createdAt: Date.now(),
    investigate: {
      offerId, fingerprint, sessionId: sess.sessionId, credentialId: cred.credential_id,
    },
  });

  sendJson(res, 200, {
    challenge_id: chalId,
    options: opts,
    offer: { offer_id: offerId, fingerprint, confirm_code: confirmCode, why, would_read: wouldRead },
  });
}

// POST /api/advisor/investigate — the finish half. Verifies the assertion,
// enforces "this is the passkey that opened the session" exactly as
// handleAdvisorApproveFinish does, then hands the Advisor the assertion so
// IT can verify independently and open the window.
export async function handleAdvisorInvestigateFinish(
  req: IncomingMessage, res: ServerResponse, advisorUrl: string, advisorToken: string | null,
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, { error: 'this operator may not break glass' });
    return;
  }

  const payload = JSON.parse((await readBody(req, 64 * 1024)) || '{}') as
    { challenge_id?: string; response?: unknown; ttl_seconds?: number; reason?: string };
  const chalId = String(payload?.challenge_id ?? '');
  const rec = pendingChallenges.get(chalId);
  pendingChallenges.delete(chalId);

  if (!rec || rec.type !== 'investigate' || !rec.investigate) {
    sendJson(res, 400, { error: 'no such ceremony, or it has already been used' });
    return;
  }
  if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
    sendJson(res, 408, { error: 'the ceremony expired; start it again' });
    return;
  }
  if (rec.investigate.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
    sendJson(res, 403, { error: 'this ceremony belongs to a different session' });
    return;
  }

  const cred = findCredentialById.get(rec.investigate.credentialId) as AuthCredential | undefined;
  if (!cred) { sendJson(res, 409, { error: 'the credential is no longer registered' }); return; }

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: payload?.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
      },
      requireUserVerification: true,
    });
  } catch {
    sendJson(res, 400, { error: 'the passkey did not verify' });
    return;
  }
  if (!result.verified) { sendJson(res, 400, { error: 'the passkey did not verify' }); return; }

  const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
  if (usedId !== rec.investigate.credentialId || usedId !== sess.credentialId) {
    sendJson(res, 403, {
      error: 'that is not the passkey that opened this session',
      detail: 'Approvals must be signed by the authenticator holding the session.',
    });
    return;
  }

  const ts = Math.floor(Date.now() / 1000);
  updateCredentialCounter.run(result.authenticationInfo.newCounter, ts, cred.id);

  if (!advisorToken) {
    sendJson(res, 503, { error: 'no approval token installed; web approval is disabled on this host' });
    return;
  }
  const user = getUserById(sess.userId);
  const r = await fetch(`${advisorUrl}/v1/investigate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${advisorToken}` },
    body: JSON.stringify({
      offer_id: rec.investigate.offerId,
      granted_by: user?.username ?? `user:${sess.userId}`,
      granted_by_role: sess.role ?? '',
      ttl_seconds: Math.min(Math.max(Number(payload?.ttl_seconds ?? 300), 60), 300),
      reason: String(payload?.reason ?? '').slice(0, 300),
      credential_id: cred.credential_id,
      session_user: user?.username ?? '',
      origin: origins()[0] ?? '',
      assertion: {
        credential_id: cred.credential_id,
        authenticator_data: (payload?.response as AssertionResponse)?.response?.authenticatorData ?? '',
        client_data_json: (payload?.response as AssertionResponse)?.response?.clientDataJSON ?? '',
        signature: (payload?.response as AssertionResponse)?.response?.signature ?? '',
      },
      challenge: rec.challenge,
    }),
    signal: AbortSignal.timeout(30_000),
  });
  // The Advisor's answer as it came, except a 5xx the edge would replace with a
  // page: that goes on a status it leaves alone, with the node's beside it (#1134).
  const relayed = edgeSafeRelay(r.status, await r.text());
  res.writeHead(relayed.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(relayed.body);
}

/** An Advisor a logout must also reach: a linked node's, on an aggregator. */
export interface LogoutCancelTarget {
  /** The node's fleet label, for the server log. */
  label: string;
  /** Its Advisor's origin on this host (the link's loopback port). */
  url: string;
  /** Its approve token, read fresh at the moment of logout. Null when it
   *  cannot be read on this host. */
  token: string | null;
}

// Best-effort revoke of one operator's unspent approvals, called from
// /auth/lock (logout) before the session itself is destroyed. Fire-and-forget
// on purpose: the Advisor being briefly unreachable must never be a reason a
// logout hangs or fails, and a standing approval left behind by a downed
// Advisor is no worse than the one that was already there before logout
// existed. `reason: 'logout'` is what tells this apart from the tab's own
// "revoke this approval" in the ledger.
//
// On an aggregator it is every Advisor the operator could have approved on
// (#1094): an approval made from the aggregator's Actions card travels the
// link and lives on the NODE's Advisor, so cancelling only on this host's own
// left it live there, for its remaining minutes, after the operator had signed
// out. One request per Advisor, all at once, each logged by name, and a node
// that cannot be reached is named in the log and nothing else: it neither
// delays nor fails the logout.
function revokeApprovalsOnLogout(
  username: string, advisorUrl: string, advisorToken: string | null, peers: LogoutCancelTarget[] = [],
): void {
  const targets: LogoutCancelTarget[] = [];
  if (advisorToken) targets.push({ label: 'this host', url: advisorUrl, token: advisorToken });
  for (const p of peers) {
    // The same Advisor twice would only cancel nothing the second time and
    // log it twice.
    if (targets.some((t) => t.url === p.url)) continue;
    if (!p.token) {
      console.warn(`[logout] approvals for ${username} were not cancelled on ${p.label}: its Advisor token cannot be read on this host`);
      recordLogoutCancelFailure(username, p.label, 'no_token');
      continue;
    }
    targets.push(p);
  }
  for (const t of targets) void cancelOnOneAdvisor(username, t);
}

async function cancelOnOneAdvisor(username: string, t: LogoutCancelTarget): Promise<void> {
  try {
    const r = await fetch(`${t.url}/v1/approve/cancel`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${t.token}` },
      body: JSON.stringify({ granted_by: username, reason: 'logout' }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!r.ok) {
      console.warn(`[logout] approvals for ${username} were not cancelled on ${t.label}: its Advisor answered ${r.status}`);
      recordLogoutCancelFailure(username, t.label, 'refused', r.status);
      return;
    }
    let cancelled: unknown;
    try { cancelled = (JSON.parse(await r.text()) as { cancelled?: unknown }).cancelled; } catch { /* the cancel itself succeeded */ }
    console.log(`[logout] cancelled ${typeof cancelled === 'number' ? cancelled : 'any'} unspent approval(s) for ${username} on ${t.label}`);
  } catch (err) {
    console.warn(`[logout] approvals for ${username} were not cancelled on ${t.label}: could not reach its Advisor (${(err as Error).message})`);
    recordLogoutCancelFailure(username, t.label, 'unreachable');
  }
}

/** The audit row for a cancel that did not land (#1094). Never throws: the
 *  logout it rides on has already happened. */
function recordLogoutCancelFailure(
  username: string, node: string, reason: 'unreachable' | 'refused' | 'no_token', status?: number,
): void {
  try {
    recordAuthEvent({
      actor: username, event: 'logout_cancel_failed', target: node,
      detail: {
        reason, ...(status !== undefined ? { status } : {}),
        note: 'this operator signed out, but an unspent approval of theirs may still be live on that Advisor until it expires',
      },
    });
  } catch (err) {
    console.warn(`[logout] could not record the failed cancel on ${node}: ${(err as Error).message}`);
  }
}

// ── The model key: test it, then seal it ────────────────────────────
//
// Three endpoints, and the order matters. The test touches nothing on this
// host and needs no passkey, because asking a provider whether a key works is
// not a change to anything. Sealing IS a change, to a root-owned credential
// store and to a running service, so it takes a passkey bound to what is
// about to be sealed.
//
// The key travels in two requests and is held in this process for the length
// of each. Nothing on either path logs a request body, and every variable
// holding it is cleared in a finally, because the failure that matters is an
// error handler that reports the payload it choked on.

/** Whether a shape is one this product knows how to speak. */
function sealShape(v: unknown): 'openai' | 'anthropic' | null {
  return v === 'openai' || v === 'anthropic' ? v : null;
}

/** The same rules the sealer applies, applied here so a refusal arrives before
 *  a passkey is spent rather than after. One definition, in model-seal.ts. */
const sealBaseUrlOk = SEAL_FIELD_RULES.baseUrl;

/**
 * POST /api/advisor/model/test
 *
 * Ask the provider which models this key reaches. Server-side, not from the
 * browser: the provider APIs do not answer a cross-origin request, and the
 * answer is also how the operator finds out the key works before spending a
 * passkey on it.
 *
 * Changes nothing anywhere. Stores nothing. The key exists in this function
 * and in one outbound Authorization header, and in no log on either side of
 * it.
 */
export async function handleAdvisorModelTest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, { error: 'this operator may not configure the Advisor model' });
    return;
  }

  // eslint-disable-next-line no-useless-assignment -- cleared in the finally below, on purpose
  let key = '';
  try {
    const body = JSON.parse((await readBody(req, 16 * 1024)) || '{}') as
      { base_url?: string; shape?: string; key?: string };
    const baseUrl = String(body?.base_url ?? '').trim();
    const shape = sealShape(body?.shape);
    key = String(body?.key ?? '').replace(/[\s]/g, '');

    if (!shape) { sendJson(res, 400, { error: 'shape must be openai or anthropic' }); return; }
    if (!sealBaseUrlOk(baseUrl)) {
      sendJson(res, 400, { error: 'the provider address must be https, or loopback for a local runner' });
      return;
    }
    if (!key) { sendJson(res, 400, { error: 'no key' }); return; }

    // Asking Anthropic the OpenAI question gets a 404 and no list, which
    // reads to an operator as "your key is bad". Different header, different
    // path, told apart by the shape they chose.
    const url = shape === 'anthropic' ? `${baseUrl}/v1/models` : `${baseUrl}/models`;
    const headers: Record<string, string> = shape === 'anthropic'
      ? { 'x-api-key': key, 'anthropic-version': '2023-06-01' }
      : { authorization: `Bearer ${key}` };

    const started = Date.now();
    let r: Response;
    try {
      r = await fetch(url, { headers, signal: AbortSignal.timeout(20_000) });
    } catch (err) {
      // The provider's own failure, not ours, and named as such. The error is
      // summarised rather than passed through: a fetch error can carry the
      // request it failed on.
      sendJson(res, 200, {
        ok: false, latency_ms: Date.now() - started,
        error: `could not reach ${baseUrl}: ${(err as Error).name}`,
      });
      return;
    }
    const latency = Date.now() - started;
    const text = await r.text();

    if (!r.ok) {
      // The provider's own words, capped. This is the one place an operator
      // learns that a key was rejected rather than mistyped, so it is passed
      // through rather than replaced with a house sentence.
      sendJson(res, 200, {
        ok: false, latency_ms: latency, status: r.status,
        error: r.status === 401 || r.status === 403
          ? 'the provider rejected that key'
          : `the provider answered ${r.status}`,
        provider_said: text.slice(0, 200),
      });
      return;
    }

    let models: string[] = [];
    try {
      const j = JSON.parse(text) as { data?: { id?: unknown }[] };
      models = (j?.data ?? [])
        .map((m) => (typeof m?.id === 'string' ? m.id : ''))
        .filter(Boolean)
        // Text models only. An image or video model in this list is a wrong
        // turn waiting to happen, and the Advisor cannot use one.
        .filter((m) => !/imagine|image|video|embed|whisper|tts|audio/i.test(m))
        .sort();
    } catch { models = []; }

    sendJson(res, 200, { ok: true, latency_ms: latency, models });
  } catch {
    sendJson(res, 400, { error: 'could not read the request' });
  } finally {
    // Not because the garbage collector needs help, but because every path out
    // of this function, including the thrown ones, should leave nothing behind
    // that a later error handler could serialise. The linter reads this as a
    // value nobody uses, which is exactly what it is meant to be.
    // eslint-disable-next-line no-useless-assignment
    key = '';
  }
}

/**
 * Which nodes an approval covers, resolved before the passkey is spent.
 *
 * Injected rather than read here so auth.ts keeps no opinion about the fleet
 * registry: server.ts owns the resolved peer list, and this file owns the
 * ceremony. A refusal comes back as a sentence the operator can act on, and
 * it arrives BEFORE the authenticator is touched.
 */
export interface SealTargetResolver {
  (raw: unknown): { ok: true; targets: string[] } | { ok: false; error: string };
}

/** The default for the per-node route: this host, and nothing else. The raw
 *  value is ignored, so the old endpoint cannot be widened by sending it a
 *  targets array it never took. */
const SELF_ONLY: SealTargetResolver = () => ({ ok: true, targets: ['self'] });

/**
 * The begin half, shared by /api/advisor/model/seal/begin and
 * /api/settings/model/seal/begin.
 *
 * ONE implementation on purpose. The two routes differ in exactly one thing,
 * which nodes the approval covers, and everything else about them is the
 * same check in the same order: admin, a session bound to a passkey, a
 * credential that is still registered, then every field validated before a
 * challenge is issued. An operator who is going to be refused should be
 * refused before they touch their authenticator, and a second copy of that
 * list is a second place for one of the checks to go missing.
 */
async function modelSealBegin(
  req: IncomingMessage, res: ServerResponse, resolveTargets: SealTargetResolver,
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, {
      error: 'this operator may not configure the Advisor model',
      detail: `Role is ${sess.role}. An admin can change it on the dashboard host: bash scripts/aperire-auth.sh set-role <email> admin`,
    });
    return;
  }
  if (!sess.credentialId) {
    sendJson(res, 409, {
      error: 'this session predates passkey-bound approval',
      detail: 'Sign out and back in, so the session records which passkey opened it.',
    });
    return;
  }
  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    sendJson(res, 409, { error: 'the passkey that opened this session is no longer registered' });
    return;
  }

  // The body, refused rather than thrown. A bare parse here reached the
  // server's outer catch, which answered a plain-text 500 to a route whose
  // caller parses JSON (#218) — so an operator with a truncated request got a
  // console parse error instead of a refusal. readBody throws on an oversized
  // body too, and that is the same answer: this route could not read it.
  //
  // Placed after the role and session checks, not before them: the order of
  // refusals on this page is a security property (see settings-gate.test.ts),
  // and a monitor must be told about their role rather than about their body.
  type SealBody = { base_url?: string; shape?: string; model?: string; credential_name?: string; targets?: unknown };
  let body: SealBody;
  try {
    body = JSON.parse((await readBody(req, 16 * 1024)) || '{}') as SealBody;
  } catch {
    sendJson(res, 400, { error: 'could not read the request' });
    return;
  }
  const baseUrl = String(body?.base_url ?? '').trim();
  const shape = sealShape(body?.shape);
  const model = String(body?.model ?? '').trim();
  const credentialName = String(body?.credential_name ?? '').trim();

  // Every one of these is checked here, before a passkey is spent, and again
  // by the sealer as root. An operator who is going to be refused should be
  // refused before they touch their authenticator.
  if (!shape) { sendJson(res, 400, { error: 'shape must be openai or anthropic' }); return; }
  if (!sealBaseUrlOk(baseUrl)) {
    sendJson(res, 400, { error: 'the provider address must be https, or loopback for a local runner' });
    return;
  }
  if (!SEAL_FIELD_RULES.model(model)) {
    sendJson(res, 400, { error: 'that does not look like a model identifier' });
    return;
  }
  if (!SEAL_FIELD_RULES.credentialName(credentialName)) {
    sendJson(res, 400, { error: 'the credential name must be a bare name' });
    return;
  }
  const resolved = resolveTargets(body?.targets);
  if (!resolved.ok) { sendJson(res, 400, { error: resolved.error }); return; }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'seal',
    userId: sess.userId,
    createdAt: Date.now(),
    seal: {
      baseUrl, shape, model, credentialName,
      targets: resolved.targets,
      sessionId: sess.sessionId, credentialId: cred.credential_id,
    },
  });

  sendJson(res, 200, { challenge_id: chalId, options: opts, targets: resolved.targets });
}

/**
 * POST /api/advisor/model/seal/begin
 *
 * Issue a passkey challenge for sealing a key under a named credential for a
 * named model. No key here: what is being approved is the action, and the
 * secret follows the approval. This host only; the Settings route covers a
 * fleet.
 */
export async function handleAdvisorModelSealBegin(req: IncomingMessage, res: ServerResponse): Promise<void> {
  await modelSealBegin(req, res, SELF_ONLY);
}

/**
 * POST /api/settings/model/seal/begin
 *
 * The same ceremony over one, some or all nodes. The resolver comes from
 * server.ts, which holds the fleet registry.
 */
export async function handleSettingsSealBegin(
  req: IncomingMessage, res: ServerResponse, resolveTargets: SealTargetResolver,
): Promise<void> {
  await modelSealBegin(req, res, resolveTargets);
}

/** After a seal, the fact the operator is actually waiting on. The sealer
 *  reads back that the SERVICE is active; this reads back that the Advisor
 *  reports a MODEL. They are different facts, and the first browser seal on
 *  a real host proved it: service active, key sealed, "no model is
 *  configured". Resolves true/false from the Advisor's own status, or null
 *  when it did not answer in time. */
export type ModelReadBack = () => Promise<boolean | null>;

/** What a verified ceremony hands its completion step. Everything but the
 *  key comes off the record written at begin. */
export interface VerifiedSeal {
  baseUrl: string;
  shape: 'openai' | 'anthropic';
  model: string;
  credentialName: string;
  targets: string[];
  /** The secret, alive for the length of the completion callback and cleared
   *  by the caller of that callback, not by the callback. */
  key: string;
  /** Who approved, and with which passkey, from the SESSION and the record,
   *  never from the request body. */
  operator: string;
  role: string;
  credentialId: string;
}

/** The one step that needs an authenticator, factored out so a test can
 *  stand in for it. Same shape as verifyAuthenticationResponse itself, so
 *  production's default is that function unchanged and a stub here still
 *  meets every check around it (challenge, session, credential id) the way
 *  verifyPairGrant's callers do for the pairing ceremony. */
export type SealVerifier = typeof verifyAuthenticationResponse;

/**
 * Verify a seal assertion, then hand what it authorised to one completion
 * step.
 *
 * Written as a wrapper rather than as a function returning the key, so the
 * `finally` that clears the key has exactly one home no matter how many
 * routes finish a seal. The completion callback writes the response; every
 * refusal below writes its own and the callback never runs.
 *
 * The ordering here is the ceremony. Its load-bearing line is the credential
 * comparison: allowCredentials is advisory, so the passkey that was actually
 * used has to be the one the record named AND the one this session was
 * opened with, or an operator with any registered key could finish a
 * ceremony another operator began.
 */
async function withVerifiedSeal(
  req: IncomingMessage, res: ServerResponse,
  complete: (seal: VerifiedSeal) => Promise<void>,
  verify: SealVerifier = verifyAuthenticationResponse,
): Promise<void> {
  const sess = readSession(req);
  if (!sess) { sendJson(res, 401, { error: 'unauthenticated' }); return; }
  // Checked again here, not only at begin. A role can be revoked between the
  // two halves of a ceremony, and the half that authorises is this one.
  if (!isAdmin(sess.role)) {
    sendJson(res, 403, { error: 'this operator may not configure the Advisor model' });
    return;
  }

  // eslint-disable-next-line no-useless-assignment -- cleared in the finally below, on purpose
  let key = '';
  try {
    const payload = JSON.parse((await readBody(req, 16 * 1024)) || '{}') as
      { challenge_id?: string; response?: unknown; key?: string };
    const chalId = String(payload?.challenge_id ?? '');
    const rec = pendingChallenges.get(chalId);
    // Single use, whatever happens next.
    pendingChallenges.delete(chalId);
    key = String(payload?.key ?? '').replace(/[\s]/g, '');

    if (!rec || rec.type !== 'seal' || !rec.seal) {
      sendJson(res, 400, { error: 'no such ceremony, or it has already been used' });
      return;
    }
    if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
      sendJson(res, 408, { error: 'the ceremony expired; start it again' });
      return;
    }
    if (rec.seal.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
      sendJson(res, 403, { error: 'this ceremony belongs to a different session' });
      return;
    }
    if (!key) { sendJson(res, 400, { error: 'no key' }); return; }

    const cred = findCredentialById.get(rec.seal.credentialId) as AuthCredential | undefined;
    if (!cred) { sendJson(res, 409, { error: 'the credential is no longer registered' }); return; }

    let result;
    try {
      result = await verify({
        response: payload?.response as never,
        expectedChallenge: rec.challenge,
        expectedOrigin: origins(),
        expectedRPID: rpIDs(),
        credential: {
          id: cred.credential_id,
          publicKey: Buffer.from(cred.public_key, 'base64url'),
          counter: cred.sign_count,
        },
        requireUserVerification: true,
      });
    } catch {
      sendJson(res, 400, { error: 'the passkey did not verify' });
      return;
    }
    if (!result.verified) { sendJson(res, 400, { error: 'the passkey did not verify' }); return; }

    // THE enforcement, as everywhere else here: allowCredentials is advisory.
    const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
    if (usedId !== rec.seal.credentialId || usedId !== sess.credentialId) {
      sendJson(res, 403, { error: 'that is not the passkey this session was opened with' });
      return;
    }
    updateCredentialCounter.run(result.authenticationInfo.newCounter, Math.floor(Date.now() / 1000), cred.id);

    // Everything but the key comes off the record written at begin, TARGETS
    // included. A value the browser could change between the two halves would
    // mean the operator approved one thing and this sealed another, and for
    // targets that difference is one node against a fleet.
    await complete({
      baseUrl: rec.seal.baseUrl,
      shape: rec.seal.shape,
      model: rec.seal.model,
      credentialName: rec.seal.credentialName,
      targets: rec.seal.targets,
      key,
      operator: sess.username,
      role: sess.role,
      credentialId: rec.seal.credentialId,
    });
  } catch {
    sendJson(res, 400, { error: 'could not read the request' });
  } finally {
    // As above: the assignment nobody reads is the one that matters.
    // eslint-disable-next-line no-useless-assignment
    key = '';
  }
}

/**
 * POST /api/advisor/model/seal
 *
 * Verify the assertion, then hand the key to the one program allowed to seal
 * it on THIS host. What comes back is what that program read back about the
 * service, not what it was asked to do.
 */
export async function handleAdvisorModelSealFinish(
  req: IncomingMessage, res: ServerResponse, run: SealRunner, readBack?: ModelReadBack,
): Promise<void> {
  await withVerifiedSeal(req, res, async (seal) => {
    const outcome = await sealModelKey({
      baseUrl: seal.baseUrl,
      shape: seal.shape,
      model: seal.model,
      credentialName: seal.credentialName,
      key: seal.key,
    }, run);

    // What the Advisor itself says afterwards, not what the sealer said about
    // the service. Asked a few times: the service was just restarted and its
    // listener can be a second or two behind `is-active`. Only a real boolean
    // ends the wait; null after the last try is reported as null, never
    // upgraded to a guess.
    let modelConfigured: boolean | null = null;
    if (outcome.ok && readBack) {
      for (let attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 2_000));
        try { modelConfigured = await readBack(); } catch { modelConfigured = null; }
        if (modelConfigured !== null) break;
      }
    }

    // On the record here, not only on the host. The sealer writes a journal
    // line for every invocation, but a seal that never reached it (no socket,
    // no window, a refusal on the way) left nothing on this side at all, and
    // the only way to find out what happened was to go and read the host's
    // journal. What is written is the decision and its outcome: never the key,
    // and never anything read back that could carry one.
    recordAuthEvent({
      actor: seal.operator,
      actorRole: seal.role,
      event: 'model_key_sealed',
      target: seal.credentialName,
      detail: {
        outcome: outcome.ok ? 'sealed' : 'refused',
        reason: outcome.reason,
        model: seal.model,
        base_url: seal.baseUrl,
        ...(outcome.service ? { service: outcome.service } : {}),
        ...(outcome.config ? { config: outcome.config } : {}),
        ...(outcome.ok ? { model_configured: modelConfigured } : {}),
      },
    });

    sendJson(res, outcome.ok ? 200 : 409, {
      ok: outcome.ok,
      reason: outcome.reason,
      detail: outcome.detail,
      ...(outcome.service ? { service: outcome.service } : {}),
      ...(outcome.credential ? { credential: outcome.credential } : {}),
      ...(outcome.config ? { config: outcome.config } : {}),
      model: seal.model,
      // Present on every success, and three-valued: true and false are the
      // Advisor's own word, null is "it had not answered yet". The page
      // builds its sentence from this and from nothing else.
      ...(outcome.ok ? { model_configured: modelConfigured } : {}),
    });
  });
}

/**
 * POST /api/settings/model/seal
 *
 * The same verification, then a JOB rather than a seal: the nodes the
 * operator approved are sealed behind a job id and the browser is answered
 * at once. A node's sealer restarts its Advisor and waits for it, and thirty
 * of those is not a request an operator should be holding a page open for.
 *
 * The key is handed to the job and this function keeps none: the `finally`
 * in withVerifiedSeal clears its copy the moment this returns, and the job
 * clears its own when the last node settles.
 *
 * `verify` is injected for the same one reason verifyPairGrant is on the
 * pairing routes: so a test can drive this through the REAL session lookup,
 * the real pending-record comparison and the real single-use challenge,
 * standing in only for the step that needs an authenticator. Production
 * passes nothing and gets withVerifiedSeal's own default.
 */
export async function handleSettingsSealFinish(
  req: IncomingMessage, res: ServerResponse,
  startJob: (seal: VerifiedSeal) => { job_id: string; targets: { label: string }[] },
  verify?: SealVerifier,
): Promise<void> {
  await withVerifiedSeal(req, res, async (seal) => {
    const started = startJob(seal);
    // Recorded here, once, as the DECISION. Each node writes its own outcome
    // to its own audit trail, and the aggregator's job status carries the
    // per-node result; what belongs on this record is that this operator
    // approved this change for these nodes.
    recordAuthEvent({
      actor: seal.operator,
      actorRole: seal.role,
      event: 'model_key_sealed',
      target: seal.credentialName,
      detail: {
        outcome: 'started',
        model: seal.model,
        base_url: seal.baseUrl,
        targets: seal.targets,
        job_id: started.job_id,
      },
    });
    sendJson(res, 202, started);
  }, verify);
}


// ── The operator grant ceremony (#216) ─────────────────────────────────
//
// Adding an administrator, and promoting one, are the two acts that widen
// who may approve a change to the validator. Both ask for the acting admin's
// passkey at the moment of the click, exactly as sealing a model key does,
// and for the same reason: a session cookie proves a browser was signed in
// at some point, and that is not the claim "this administrator, at this
// keyboard, right now, grants this" needs to be.
//
// Two halves, and the binding between them is the record. Everything the
// grant authorises (the action, the email, the role) is written at begin and
// read back from that record at finish. Nothing is taken from the finishing
// request but the assertion itself.

/**
 * Issue the challenge.
 *
 * The refusals here all land BEFORE the authenticator is touched. An
 * operator who is going to be told no should be told before they put their
 * finger on a sensor, and the validation of who is being granted what has
 * already happened in lib/operator-admin.ts by the time this is called.
 */
export async function beginOperatorGrant(
  req: IncomingMessage, grant: { action: 'add' | 'role'; email: string; role: OperatorRole },
): Promise<OperatorResult> {
  const sess = readSession(req);
  if (!sess) return { status: 401, body: { error: 'unauthenticated' } };
  if (!isAdmin(sess.role)) return { status: 403, body: { error: 'this operator may not change settings' } };
  if (grant.action !== 'add' && grant.action !== 'role') {
    return { status: 400, body: { error: 'unknown grant' } };
  }
  if (grant.role !== 'admin' && grant.role !== 'monitor') {
    return { status: 400, body: { error: 'role must be admin or monitor' } };
  }
  if (!sess.credentialId) {
    return {
      status: 409,
      body: {
        error: 'this session predates passkey-bound approval',
        detail: 'Sign out and back in, so the session records which passkey opened it.',
      },
    };
  }
  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { status: 409, body: { error: 'the passkey that opened this session is no longer registered' } };
  }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'grant',
    userId: sess.userId,
    createdAt: Date.now(),
    grant: {
      action: grant.action, email: grant.email, role: grant.role,
      sessionId: sess.sessionId, credentialId: cred.credential_id,
    },
  });
  return { status: 200, body: { challenge_id: chalId, options: opts } };
}

/**
 * Verify one.
 *
 * The ordering below is the ceremony, and it is the same ordering
 * withVerifiedSeal uses. Its load-bearing line is the credential comparison:
 * allowCredentials is advisory, a page can sign with any registered key, so
 * the key that was actually used has to be the one the record named AND the
 * one this session was opened with. Without it, any operator holding any
 * enrolled passkey could finish a ceremony another operator began.
 *
 * The admin check is here as well as at begin because a role can be revoked
 * between the two halves, and the half that authorises is this one.
 */
export async function verifyOperatorGrant(
  req: IncomingMessage, payload: { challenge_id?: unknown; response?: unknown },
): Promise<GrantOutcome> {
  const sess = readSession(req);
  if (!sess) return { ok: false, status: 401, error: 'unauthenticated' };
  if (!isAdmin(sess.role)) return { ok: false, status: 403, error: 'this operator may not change settings' };

  const chalId = String(payload?.challenge_id ?? '');
  const rec = pendingChallenges.get(chalId);
  // Single use, whatever happens next.
  pendingChallenges.delete(chalId);

  if (!rec || rec.type !== 'grant' || !rec.grant) {
    return { ok: false, status: 400, error: 'no such ceremony, or it has already been used' };
  }
  if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
    return { ok: false, status: 408, error: 'the ceremony expired; start it again' };
  }
  if (rec.grant.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
    return { ok: false, status: 403, error: 'this ceremony belongs to a different session' };
  }
  const cred = findCredentialById.get(rec.grant.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { ok: false, status: 409, error: 'the credential is no longer registered' };
  }

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: payload?.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    // LOW-04 again: the reason stays server-side.
    console.warn('[authn] grant assertion failed:', (err as Error).message);
    return { ok: false, status: 400, error: 'the passkey did not verify' };
  }
  if (!result.verified) return { ok: false, status: 400, error: 'the passkey did not verify' };

  const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
  if (usedId !== rec.grant.credentialId || usedId !== sess.credentialId) {
    return { ok: false, status: 403, error: 'that is not the passkey this session was opened with' };
  }
  updateCredentialCounter.run(result.authenticationInfo.newCounter, Math.floor(Date.now() / 1000), cred.id);

  const grant: VerifiedGrant = {
    action: rec.grant.action,
    email: rec.grant.email,
    role: rec.grant.role,
    // Who approved, from the SESSION, never from the request body.
    operator: sess.username,
    operatorRole: sess.role,
    credentialId: rec.grant.credentialId,
  };
  return { ok: true, grant };
}

// ── The pairing approval ceremony (ADR 0019 phase 3) ───────────────────
//
// Beside the operator grant rather than beside withVerifiedSeal, because an
// approval carries no secret from the browser: what crosses is an assertion
// and a choice of label. The grant pair is the one that fits.

export interface PairGrantRequest {
  pairingId: string;
  label: string;
  pubkeyNode: string;
  /** #620: true only when this row's own classification named it a known
   *  node (settings-api.ts re-derives this from the row, never trusts a
   *  caller's say-so). The one explicit decision label_not_a_link asks
   *  for. Defaults false, so every ordinary approval is unaffected. */
  convertTunnel?: boolean;
}

export interface VerifiedPairGrant {
  pairingId: string;
  label: string;
  pubkeyNode: string;
  /** Who approved, from the SESSION and never from the request body. */
  operator: string;
  operatorRole: string;
  credentialId: string;
  /** #620: see PairGrantRequest's own doc comment. */
  convertTunnel: boolean;
}

export type PairGrantOutcome =
  | { ok: true; grant: VerifiedPairGrant }
  | { ok: false; status: number; error: string; detail?: string };

/**
 * Issue the challenge for one pairing approval.
 *
 * Every refusal here lands BEFORE the authenticator is touched: an operator
 * who is going to be told no should be told before they put a finger on a
 * sensor.
 */
export async function beginPairGrant(
  req: IncomingMessage, grant: PairGrantRequest,
): Promise<OperatorResult> {
  const sess = readSession(req);
  if (!sess) return { status: 401, body: { error: 'unauthenticated' } };
  if (!isAdmin(sess.role)) return { status: 403, body: { error: 'this operator may not change settings' } };
  if (!grant.pairingId || !grant.label || !grant.pubkeyNode) {
    return { status: 400, body: { error: 'that pairing is not one this dashboard is holding' } };
  }
  if (!sess.credentialId) {
    return {
      status: 409,
      body: {
        error: 'this session predates passkey-bound approval',
        detail: 'Sign out and back in, so the session records which passkey opened it.',
      },
    };
  }
  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { status: 409, body: { error: 'the passkey that opened this session is no longer registered' } };
  }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'pair',
    userId: sess.userId,
    createdAt: Date.now(),
    pair: {
      pairingId: grant.pairingId, label: grant.label, pubkeyNode: grant.pubkeyNode,
      sessionId: sess.sessionId, credentialId: cred.credential_id,
      convertTunnel: grant.convertTunnel === true,
    },
  });
  return { status: 200, body: { challenge_id: chalId, options: opts } };
}

/**
 * Verify one.
 *
 * The same ordering verifyOperatorGrant uses, and the same load-bearing
 * line: allowCredentials is advisory, a page can sign with any registered
 * key, so the key actually used has to be the one the record named AND the
 * one this session was opened with. The admin check runs again here because
 * a role can be revoked between the two halves, and this is the half that
 * authorises.
 */
export async function verifyPairGrant(
  req: IncomingMessage, payload: { challenge_id?: unknown; response?: unknown },
): Promise<PairGrantOutcome> {
  const sess = readSession(req);
  if (!sess) return { ok: false, status: 401, error: 'unauthenticated' };
  if (!isAdmin(sess.role)) return { ok: false, status: 403, error: 'this operator may not change settings' };

  const chalId = String(payload?.challenge_id ?? '');
  const rec = pendingChallenges.get(chalId);
  // Single use, whatever happens next.
  pendingChallenges.delete(chalId);

  if (!rec || rec.type !== 'pair' || !rec.pair) {
    return { ok: false, status: 400, error: 'no such ceremony, or it has already been used' };
  }
  if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
    return { ok: false, status: 408, error: 'the ceremony expired; start it again' };
  }
  if (rec.pair.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
    return { ok: false, status: 403, error: 'this ceremony belongs to a different session' };
  }
  const cred = findCredentialById.get(rec.pair.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { ok: false, status: 409, error: 'the credential is no longer registered' };
  }

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: payload?.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    console.warn('[authn] pairing assertion failed:', (err as Error).message);
    return { ok: false, status: 400, error: 'the passkey did not verify' };
  }
  if (!result.verified) return { ok: false, status: 400, error: 'the passkey did not verify' };

  const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
  if (usedId !== rec.pair.credentialId || usedId !== sess.credentialId) {
    return { ok: false, status: 403, error: 'that is not the passkey this session was opened with' };
  }
  updateCredentialCounter.run(result.authenticationInfo.newCounter, Math.floor(Date.now() / 1000), cred.id);

  return {
    ok: true,
    grant: {
      pairingId: rec.pair.pairingId,
      label: rec.pair.label,
      pubkeyNode: rec.pair.pubkeyNode,
      operator: sess.username,
      operatorRole: sess.role,
      credentialId: rec.pair.credentialId,
      convertTunnel: rec.pair.convertTunnel,
    },
  };
}

// ── The catch-up ceremony (ADR 0019 phase 4, #168) ─────────────────────
//
// A seal with no key field. The fleet's model is already sealed on this host
// and the root broker opens it; what an operator approves here is sending
// that setting to nodes that are behind.
//
// It is a passkey ceremony rather than a plain button for the reason every
// other one on this page is: the act reaches a root program that writes a
// credential on another machine, and a session cookie proves a browser was
// signed in at some point, which is not the claim "this administrator, at
// this keyboard, right now" needs to be.

export interface CatchupGrantRequest {
  /** 'self' and/or fleet labels, resolved against the registry BEFORE this
   *  is called, exactly as the seal's targets are. */
  targets: string[];
  /** What the store says it holds, read from the broker's own head, so the
   *  page can show an operator the setting they did not type this time. The
   *  HOST of the base URL, never the provider brand: that field is the one a
   *  compromised dashboard can persist without root. */
  baseUrlHost: string;
  /** The whole address, bound but not printed. What is rendered is the host,
   *  because that is the readable part and the part a poisoned base gives
   *  away; what is COMPARED at finish is this, so a port or a path rewritten
   *  between the two halves is caught as well (F9). */
  baseUrl: string;
  model: string;
  credentialName: string;
}

export interface VerifiedCatchupGrant extends CatchupGrantRequest {
  operator: string;
  operatorRole: string;
  credentialId: string;
}

export type CatchupGrantOutcome =
  | { ok: true; grant: VerifiedCatchupGrant }
  | { ok: false; status: number; error: string; detail?: string };

/**
 * Issue the challenge, with what is about to be sent bound into the record
 * and echoed back so the page can print it.
 *
 * Every refusal lands BEFORE the authenticator is touched.
 */
export async function beginCatchupGrant(
  req: IncomingMessage, grant: CatchupGrantRequest,
): Promise<OperatorResult> {
  const sess = readSession(req);
  if (!sess) return { status: 401, body: { error: 'unauthenticated' } };
  if (!isAdmin(sess.role)) return { status: 403, body: { error: 'this operator may not change settings' } };
  if (!grant.targets.length) {
    return { status: 400, body: { error: 'name at least one node to bring up to date' } };
  }
  if (!grant.model || !grant.credentialName) {
    return {
      status: 409,
      body: {
        error: 'no_sealed_model',
        detail: 'this aggregator holds no sealed fleet model, so there is nothing to send. '
          + 'Seal the fleet model from here with the key.',
      },
    };
  }
  if (!sess.credentialId) {
    return {
      status: 409,
      body: {
        error: 'this session predates passkey-bound approval',
        detail: 'Sign out and back in, so the session records which passkey opened it.',
      },
    };
  }
  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { status: 409, body: { error: 'the passkey that opened this session is no longer registered' } };
  }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'catchup',
    userId: sess.userId,
    createdAt: Date.now(),
    catchup: {
      targets: grant.targets,
      baseUrlHost: grant.baseUrlHost,
      baseUrl: grant.baseUrl,
      model: grant.model,
      credentialName: grant.credentialName,
      sessionId: sess.sessionId, credentialId: cred.credential_id,
    },
  });
  // Read back from the record's own fields, so the page can only print what
  // was actually bound. An operator approving a setting they did not type
  // has to see it, and seeing the page's own last fetch instead would be
  // showing them something the signature does not cover.
  return {
    status: 200,
    body: {
      challenge_id: chalId,
      options: opts,
      targets: grant.targets,
      model: grant.model,
      base_url_host: grant.baseUrlHost,
      credential_name: grant.credentialName,
    },
  };
}

/**
 * Verify one.
 *
 * The same ordering verifyPairGrant uses, and the same load-bearing line:
 * allowCredentials is advisory, so the key actually used has to be the one
 * the record named AND the one this session was opened with. The admin check
 * runs again because a role can be revoked between the two halves, and this
 * is the half that authorises.
 */
export async function verifyCatchupGrant(
  req: IncomingMessage, payload: { challenge_id?: unknown; response?: unknown },
): Promise<CatchupGrantOutcome> {
  const sess = readSession(req);
  if (!sess) return { ok: false, status: 401, error: 'unauthenticated' };
  if (!isAdmin(sess.role)) return { ok: false, status: 403, error: 'this operator may not change settings' };

  const chalId = String(payload?.challenge_id ?? '');
  const rec = pendingChallenges.get(chalId);
  // Single use, whatever happens next.
  pendingChallenges.delete(chalId);

  if (!rec || rec.type !== 'catchup' || !rec.catchup) {
    return { ok: false, status: 400, error: 'no such ceremony, or it has already been used' };
  }
  if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
    return { ok: false, status: 408, error: 'the ceremony expired; start it again' };
  }
  if (rec.catchup.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
    return { ok: false, status: 403, error: 'this ceremony belongs to a different session' };
  }
  const cred = findCredentialById.get(rec.catchup.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { ok: false, status: 409, error: 'the credential is no longer registered' };
  }

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: payload?.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    console.warn('[authn] catch-up assertion failed:', (err as Error).message);
    return { ok: false, status: 400, error: 'the passkey did not verify' };
  }
  if (!result.verified) return { ok: false, status: 400, error: 'the passkey did not verify' };

  const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
  if (usedId !== rec.catchup.credentialId || usedId !== sess.credentialId) {
    return { ok: false, status: 403, error: 'that is not the passkey this session was opened with' };
  }
  updateCredentialCounter.run(result.authenticationInfo.newCounter, Math.floor(Date.now() / 1000), cred.id);

  return {
    ok: true,
    grant: {
      targets: rec.catchup.targets,
      baseUrlHost: rec.catchup.baseUrlHost,
      baseUrl: rec.catchup.baseUrl,
      model: rec.catchup.model,
      credentialName: rec.catchup.credentialName,
      operator: sess.username,
      operatorRole: sess.role,
      credentialId: rec.catchup.credentialId,
    },
  };
}

/**
 * The two hooks a change to who may approve has to run, wired to this
 * host's real fleet CLI and its real trust-sync socket.
 *
 * The same deps the enrollment path uses, handed out rather than copied, so
 * a change made from the Settings page and a passkey enrolled in a browser
 * reach the fleet by exactly one code path. The difference is only in who
 * waits: enrollment fires these and answers, this returns them so the caller
 * can await and report per node.
 */
export function trustChangeRunners(
  actor: { username: string; role: string | null },
  advisor?: { url?: string; token?: string | null },
  trigger?: string,
): {
  fingerprint: () => string;
  push: (before: string, after: string) => Promise<TrustPushOutcome>;
  sync: (before: string, after: string) => Promise<TrustLocalSyncOutcome>;
} {
  return {
    fingerprint: () => trustFingerprint().fingerprint,
    push: (before, after) => pushTrustAfterEnrollment(before, after, {
      repoDir: REPO_DIR, dbPath: DB_PATH, spawn: runTrustPush,
      log: (line) => console.log(line),
    }),
    sync: (before, after) => syncLocalTrustAfterEnrollment(before, after, {
      ...trustSyncTarget(),
      ask: (p) => askSocketProgram(TRUST_SYNC_SOCKET_PATH, p, 60_000, 'the trust sync'),
      readBack: () => readAdvisorTrustFingerprint(advisor?.url, advisor?.token ?? null),
      mine: () => trustFingerprint().fingerprint,
      log: (line) => console.log(line),
      record: (detail) => recordAuthEvent({
        actor: actor.username, actorRole: actor.role,
        event: 'trust_synced', target: 'advisor', detail,
      }),
      trigger,
    }),
  };
}


// ── The update ceremony (#62, ADR 0022 phase 2) ────────────────────────
//
// Applying a release, restarting into it and rolling it back are three acts
// that change what code this host runs. Each asks for the acting admin's
// passkey at the moment of the click, exactly as sealing a model key does,
// and for the same reason: a session cookie proves a browser was signed in
// at some point, and that is not the claim "this administrator, at this
// keyboard, right now, approves installing snapshot-2026-09-20" needs to be.
//
// The operator ruled no arm window here (2026-09-08, #62): the admin passkey
// is the gate and the restart is a second click. Break glass is not it
// either — that exists because the actor is a model. Here the actor is an
// admin in a browser pressing a button on their own host.
//
// Two halves, and the binding between them is the record. Everything the
// approval authorises is written at begin and read back from that record at
// finish. Nothing is taken from the finishing request but the assertion.

/** What one ceremony covers. Discriminated, because an approval taken for an
 *  apply is not spendable on a rollback. */
export type UpdateCeremony =
  | { action: 'apply'; release: { tag: string; commit: string; sha256: string } }
  | { action: 'restart'; units: string[] }
  | { action: 'rollback' }
  // The fleet halves (#275). Separate actions rather than a flag on the two
  // above, and the discriminant IS the security property: verifyUpdateCeremony
  // takes the expected action as an argument, so an approval taken to apply
  // on THIS host cannot be spent to apply on another, or the reverse.
  | { action: 'fleet_apply'; targets: string[]; release: { tag: string; commit: string; sha256: string } }
  | { action: 'fleet_restart'; targets: string[]; runIds: Record<string, string>; units: string[] };

export type UpdateAction = UpdateCeremony['action'];

/**
 * What goes on the pending record for this act, and nothing else.
 *
 * Pure, and separate from beginUpdateCeremony, because it is the half worth
 * asserting on its own: a fleet action that forgot to write `targets` would
 * mint an approval covering no node, and the finishing half reads the
 * targets from HERE rather than from the request that carries the signature.
 * A test drives every action through it.
 */
export function updateCeremonyBinding(what: UpdateCeremony): {
  release?: { tag: string; commit: string; sha256: string };
  units?: string[];
  targets?: string[];
  runIds?: Record<string, string>;
} {
  switch (what.action) {
    case 'apply': return { release: what.release };
    case 'restart': return { units: what.units };
    case 'rollback': return {};
    case 'fleet_apply': return { release: what.release, targets: what.targets };
    case 'fleet_restart': return { units: what.units, targets: what.targets, runIds: what.runIds };
  }
}

/**
 * Is this approval spendable on this act?
 *
 * One line, and it is the security property of the whole ceremony: an
 * approval taken for one action is not spendable on another. It matters more
 * now than it did with three actions, because two of the five start a root
 * program on a DIFFERENT machine — an `apply` approval for this host must
 * not become a `fleet_apply` against a node, and the reverse.
 *
 * Pure and exported so a test can drive the whole cross-product rather than
 * whichever pair a walk happens to exercise.
 */
export function updateApprovalMismatch(recorded: UpdateAction, expected: UpdateAction): string | null {
  if (recorded === expected) return null;
  return `that approval was taken for ${recorded}, not ${expected}`;
}

export type UpdateCeremonyOutcome =
  | { ok: true; approved: VerifiedUpdate }
  | { ok: false; status: number; error: string; detail?: string };

/** What a verified ceremony hands the run. Who approved comes off the
 *  SESSION, never off the request body. */
export interface VerifiedUpdate {
  action: UpdateAction;
  release?: { tag: string; commit: string; sha256: string };
  units?: string[];
  /** Which nodes the approval covers, on a fleet action. Read back from the
   *  record written at begin: a label the finishing request could change
   *  would mean the operator approved one node and this updated another. */
  targets?: string[];
  /** The run each target must still be holding, on a fleet restart. Bound
   *  for the same reason `units` is on the local one: the approval was taken
   *  against what THAT run said needed restarting. */
  runIds?: Record<string, string>;
  operator: string;
  operatorRole: string;
  credentialId: string;
}

/**
 * Issue the challenge.
 *
 * Every refusal here lands BEFORE the authenticator is touched. An operator
 * who is going to be told no should be told before they put their finger on
 * a sensor. Whether there is anything to apply, and whether this host has an
 * updater at all, is settled by the caller in server.ts, which holds the
 * release reading and the socket.
 */
export async function beginUpdateCeremony(
  req: IncomingMessage, what: UpdateCeremony,
): Promise<OperatorResult> {
  const sess = readSession(req);
  if (!sess) return { status: 401, body: { error: 'unauthenticated' } };
  if (!isAdmin(sess.role)) return { status: 403, body: { error: 'this operator may not update this host' } };
  if (!sess.credentialId) {
    return {
      status: 409,
      body: {
        error: 'this session predates passkey-bound approval',
        detail: 'Sign out and back in, so the session records which passkey opened it.',
      },
    };
  }
  const cred = findCredentialById.get(sess.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { status: 409, body: { error: 'the passkey that opened this session is no longer registered' } };
  }

  const opts = await generateAuthenticationOptions({
    rpID: rpIDs()[0],
    userVerification: 'required',
    allowCredentials: [{ id: cred.credential_id }] as never,
  });
  const chalId = randomBytes(24).toString('base64url');
  putPendingChallenge(chalId, {
    challenge: opts.challenge,
    type: 'update',
    userId: sess.userId,
    createdAt: Date.now(),
    update: {
      action: what.action,
      ...updateCeremonyBinding(what),
      sessionId: sess.sessionId, credentialId: cred.credential_id,
    },
  });
  // What was bound goes back with the challenge, so the page can print the
  // release it is about to install and the units it is about to restart, and
  // an operator reads what they are signing rather than what the page last
  // fetched.
  return {
    status: 200,
    body: {
      challenge_id: chalId,
      options: opts,
      action: what.action,
      // What was bound, read back from the SAME function that wrote the
      // record, so the page can only print what the record actually holds.
      // `runIds` is deliberately not published: it is a bound value, not a
      // thing an operator reads.
      ...(({ runIds: _unused, ...shown }) => shown)(updateCeremonyBinding(what)),
    },
  };
}

/**
 * Verify one.
 *
 * The ordering below is the ceremony, and it is the ordering
 * verifyOperatorGrant uses. Its load-bearing line is the credential
 * comparison: allowCredentials is advisory, a page can sign with any
 * registered key, so the key that was actually used has to be the one the
 * record named AND the one this session was opened with.
 *
 * The admin check is here as well as at begin because a role can be revoked
 * between the two halves, and the half that authorises is this one.
 */
export async function verifyUpdateCeremony(
  req: IncomingMessage, payload: { challenge_id?: unknown; response?: unknown },
  expect: UpdateAction,
): Promise<UpdateCeremonyOutcome> {
  const sess = readSession(req);
  if (!sess) return { ok: false, status: 401, error: 'unauthenticated' };
  if (!isAdmin(sess.role)) return { ok: false, status: 403, error: 'this operator may not update this host' };

  const chalId = String(payload?.challenge_id ?? '');
  const rec = pendingChallenges.get(chalId);
  // Single use, whatever happens next.
  pendingChallenges.delete(chalId);

  if (!rec || rec.type !== 'update' || !rec.update) {
    return { ok: false, status: 400, error: 'no such ceremony, or it has already been used' };
  }
  // An approval taken for one act is not spendable on another. Checked
  // against the ROUTE that is finishing, not against anything in the body.
  const mismatch = updateApprovalMismatch(rec.update.action, expect);
  if (mismatch) {
    return { ok: false, status: 403, error: mismatch };
  }
  if (Date.now() - rec.createdAt > CHALLENGE_TTL_MS) {
    return { ok: false, status: 408, error: 'the ceremony expired; start it again' };
  }
  if (rec.update.sessionId !== sess.sessionId || rec.userId !== sess.userId) {
    return { ok: false, status: 403, error: 'this ceremony belongs to a different session' };
  }
  const cred = findCredentialById.get(rec.update.credentialId) as AuthCredential | undefined;
  if (!cred || cred.user_id !== sess.userId) {
    return { ok: false, status: 409, error: 'the credential is no longer registered' };
  }

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: payload?.response as never,
      expectedChallenge: rec.challenge,
      expectedOrigin: origins(),
      expectedRPID: rpIDs(),
      credential: {
        id: cred.credential_id,
        publicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.sign_count,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    // LOW-04: the reason stays server-side.
    console.warn('[authn] update assertion failed:', (err as Error).message);
    return { ok: false, status: 400, error: 'the passkey did not verify' };
  }
  if (!result.verified) return { ok: false, status: 400, error: 'the passkey did not verify' };

  const usedId = (payload?.response as { id?: string } | undefined)?.id ?? '';
  if (usedId !== rec.update.credentialId || usedId !== sess.credentialId) {
    return { ok: false, status: 403, error: 'that is not the passkey this session was opened with' };
  }
  updateCredentialCounter.run(result.authenticationInfo.newCounter, Math.floor(Date.now() / 1000), cred.id);

  return {
    ok: true,
    approved: {
      action: rec.update.action,
      release: rec.update.release,
      units: rec.update.units,
      targets: rec.update.targets,
      runIds: rec.update.runIds,
      operator: sess.username,
      operatorRole: sess.role,
      credentialId: rec.update.credentialId,
    },
  };
}
