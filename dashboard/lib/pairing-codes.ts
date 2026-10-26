/**
 * The pairing code — ADR 0019 decision 2, phase 3.
 *
 * An admin mints one on the Settings page, reads it to the node (or pastes
 * the whole command), and the node presents it once in its `pair_hello`. The
 * code is what gets a node a PENDING ROW and nothing else: no listener is
 * bound, no file is written, no token crosses. Approval is a passkey and a
 * fingerprint an operator compares, and that is the trust decision.
 *
 * Four properties, and each one is a line of code rather than a promise:
 *
 *   100 bits      20 Crockford base32 characters from randomBytes. Guessing
 *                 is not a threat at any rate limit, which is what makes the
 *                 presentation guard a nuisance-bound rather than a control.
 *   hashed at rest  only the SHA-256 hex is stored, the shape
 *                 auth_magic_links already uses. A read of the database
 *                 yields nothing presentable.
 *   15 minutes    expires_at is created_at + 900, and a PENDING row expires
 *                 with its CODE rather than with its hello: the window the
 *                 operator agreed to is the one they started.
 *   one use       a single UPDATE ... WHERE consumed_at IS NULL claims it,
 *                 and `changes === 1` is the claim. Two simultaneous
 *                 presentations of one code therefore resolve exactly once,
 *                 with no lock and no read-then-write.
 *
 * The table lives in the auth_* family, which is deliberately outside the
 * ADR 0008 read contract, so a read token can never enumerate it.
 *
 * WHY THE STORE IS SQLITE AND NOT A MAP (D1): a dashboard restart between
 * the mint and the run would invalidate a code the operator is holding on a
 * second machine, and the symptom is "the code did not work" with the reason
 * nowhere. The honest residual is that the dashboard account owns the
 * database and can rewrite the row — and that account can already mint a
 * code through its own route, so the row is not what stands behind pairing.
 */
import { createHash, randomBytes } from 'node:crypto';
import { db } from '../db.js';

/** Crockford base32: no I, L, O or U, so a code can be read aloud. 32
 *  characters exactly, and 256 is a multiple of 32, so `byte % 32` over
 *  randomBytes is uniform and needs no rejection loop. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** 20 characters, 100 bits. */
export const PAIRING_CODE_LENGTH = 20;
/** The window the operator agrees to when they press Mint. */
export const PAIRING_CODE_TTL_MS = 15 * 60 * 1000;
/** How long a spent or expired row is kept before the sweep drops it. Long
 *  enough that "that code is already used" is still answerable for an hour
 *  after the fact in the journal, short enough that the table stays small. */
const PAIRING_CODE_KEEP_MS = 60 * 60 * 1000;

/** Mint ceilings. A bound on accident, not on an attacker: mint is behind
 *  settingsGate, so the caller is already an authenticated admin. Both are
 *  in memory and a restart clears them, which is said out loud because a
 *  control a restart can flip is not one to believe in. */
const MINT_WINDOW_MS = 60 * 60 * 1000;
const MINT_PER_ADMIN = 10;
const MINT_PER_HOST = 30;

const insertCode = db.prepare(`
  INSERT INTO fleet_pairing_codes
    (code_sha256, issued_by, issued_credential_id, created_at, expires_at, operator_label)
  VALUES (?, ?, ?, ?, ?, ?)
`);
const claimCode = db.prepare(`
  UPDATE fleet_pairing_codes SET consumed_at = ?, consumed_from = ?
  WHERE code_sha256 = ? AND consumed_at IS NULL AND expires_at > ?
`);
const cancelOwnCode = db.prepare(`
  UPDATE fleet_pairing_codes SET consumed_at = ?, consumed_from = ?
  WHERE code_sha256 = ? AND issued_by = ? AND consumed_at IS NULL AND expires_at > ?
`);
const readCode = db.prepare(`
  SELECT id, issued_by, created_at, expires_at, consumed_at, operator_label
  FROM fleet_pairing_codes WHERE code_sha256 = ?
`);
const dropOld = db.prepare(`DELETE FROM fleet_pairing_codes WHERE expires_at < ?`);
const latestLive = db.prepare(`
  SELECT MAX(expires_at) AS latest FROM fleet_pairing_codes
  WHERE consumed_at IS NULL AND expires_at > ?
`);

/**
 * The rule a typed code goes through before anything looks it up.
 *
 * Upper-cased, `O` folded to `0` and `I`/`L` folded to `1`, then every
 * character outside the alphabet dropped: the dashes the page prints, the
 * spaces a paste picks up. The `APR` prefix is handled separately, because
 * its three letters are all IN the alphabet and the filter keeps them.
 * Exactly 20 characters after all that, or null.
 *
 * Normalisation happens BEFORE the lookup and never as a retry, because
 * rejecting a mistyped code and rejecting a stolen one have to be the same
 * refusal. A "try it again without the dashes" path would be a second answer
 * that says the first one was about the formatting.
 */
export function normalisePairingCode(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  // Bounded before any per-character work: this runs on an unauthenticated
  // frame, and a megabyte of "O" is not a code.
  if (raw.length > 256) return null;
  const upper = raw.trim().toUpperCase();
  // `APR` is three Crockford characters, so the prefix the page prints does
  // NOT fall out of the filter below — it survives it and makes every typed
  // code 23 characters long. Both readings are tried, and only one of them
  // can ever be 20 characters because they differ by exactly three: the
  // whole string first, so a bare code that happens to begin with A, P, R
  // is read as itself, then the string with a leading APR removed.
  const whole = fold(upper);
  if (whole.length === PAIRING_CODE_LENGTH) return whole;
  if (upper.startsWith('APR')) {
    const body = fold(upper.slice(3));
    if (body.length === PAIRING_CODE_LENGTH) return body;
  }
  return null;
}

/** Upper-cased already. `O` to `0`, `I` and `L` to `1`, everything outside
 *  the alphabet dropped: the dashes, the spaces, a stray quote from a paste. */
function fold(upper: string): string {
  let out = '';
  for (const ch of upper) {
    const folded = ch === 'O' ? '0' : (ch === 'I' || ch === 'L') ? '1' : ch;
    if (ALPHABET.includes(folded)) out += folded;
  }
  return out;
}

/** `APR-XXXXX-XXXXX-XXXXX-XXXXX`, the form the page prints and the command
 *  takes. Normalisation undoes it, so nothing downstream depends on it. */
export function formatPairingCode(normalised: string): string {
  const groups: string[] = [];
  for (let i = 0; i < normalised.length; i += 5) groups.push(normalised.slice(i, i + 5));
  return `APR-${groups.join('-')}`;
}

export function pairingCodeHash(normalised: string): string {
  return createHash('sha256').update(normalised, 'utf8').digest('hex');
}

// ── The mint limit ───────────────────────────────────────────────────────

const mints: Array<{ issuer: string; at: number }> = [];

export interface MintLimitVerdict { ok: boolean; detail?: string }

/** Asked before a mint, and it does not record one: recordMint() does, so a
 *  refusal further down (a database error) does not spend a slot. */
export function mintLimit(issuer: string, nowMs: number): MintLimitVerdict {
  while (mints.length && nowMs - mints[0].at >= MINT_WINDOW_MS) mints.shift();
  if (mints.length >= MINT_PER_HOST) {
    return { ok: false, detail: `this dashboard has minted ${MINT_PER_HOST} pairing codes in the last hour. Wait, or approve the rows you already have.` };
  }
  const mine = mints.filter((m) => m.issuer === issuer).length;
  if (mine >= MINT_PER_ADMIN) {
    return { ok: false, detail: `you have minted ${MINT_PER_ADMIN} pairing codes in the last hour. Wait, or approve the rows you already have.` };
  }
  return { ok: true };
}

function recordMint(issuer: string, nowMs: number): void {
  mints.push({ issuer, at: nowMs });
}

/** Test seam. A fresh process starts with an empty window, and one test's
 *  mints must not refuse the next test's. */
export function clearMintLimit(): void { mints.length = 0; }

// ── Mint ─────────────────────────────────────────────────────────────────

export interface MintedCode {
  /** The plaintext, returned exactly once and stored nowhere. */
  code: string;
  /** Unix seconds, the value the page counts down to. */
  expires_at: number;
}

/**
 * Insert one row and hand back the plaintext once.
 *
 * `issuer` and `credentialId` come from the SESSION at the call site, never
 * from a request body: the row is the record of which admin made a code and
 * which passkey opened the session that did it.
 *
 * `operatorLabel` (#635) is the name an admin typed into "Name this node"
 * before minting, already validated against the same rule fleet.yaml uses
 * and already checked for a collision by the caller (settings-api.ts's
 * mintPairing) -- this function only stores what it is handed. Null or
 * omitted is the ordinary case: no name was given, and the node's own
 * proposal stands, exactly as it always has.
 */
export function mintPairingCode(
  issuer: string, credentialId: string, nowMs: number, operatorLabel?: string | null,
): MintedCode {
  const bytes = randomBytes(PAIRING_CODE_LENGTH);
  let normalised = '';
  for (const b of bytes) normalised += ALPHABET[b % ALPHABET.length];
  const createdAt = Math.floor(nowMs / 1000);
  const expiresAt = Math.floor((nowMs + PAIRING_CODE_TTL_MS) / 1000);
  insertCode.run(pairingCodeHash(normalised), issuer, credentialId, createdAt, expiresAt, operatorLabel ?? null);
  recordMint(issuer, nowMs);
  // The endpoint is armed from this instant, not from the memo's next pass:
  // an operator who mints and runs the node's command inside ten seconds is
  // the ordinary case, not an edge one.
  armedUntilMs = Math.max(armedUntilMs, expiresAt * 1000);
  return { code: formatPairingCode(normalised), expires_at: expiresAt };
}

// ── Consume ──────────────────────────────────────────────────────────────

/**
 * What a presentation resolved to.
 *
 * `why` is for the JOURNAL and never for the wire. Bad, reused and expired
 * are three facts about a code and one fact about the caller: an operator
 * reading the aggregator's log needs them apart, and the node on the far end
 * gets one sentence for all three.
 */
export type CodeVerdict =
  | {
    ok: true; id: number; issued_by: string; expires_at: number;
    /** The name an admin typed into "Name this node" before minting this
     *  code (#635), or null when none was given. Read once, here, by the
     *  hello that spends the code -- the same one-shot shape the code
     *  itself has, so a name never outlives the code that carried it. */
    name: string | null;
  }
  | { ok: false; why: 'malformed' | 'unknown' | 'reused' | 'expired' };

export function consumePairingCode(raw: unknown, rateKey: string, nowMs: number): CodeVerdict {
  const normalised = normalisePairingCode(raw);
  if (!normalised) return { ok: false, why: 'malformed' };
  const hash = pairingCodeHash(normalised);
  const nowSec = Math.floor(nowMs / 1000);
  // ONE statement, and the claim is `changes === 1`. Not a SELECT then an
  // UPDATE: two presentations of the same code in the same instant both pass
  // a read and both would win.
  const claimed = claimCode.run(nowSec, rateKey.slice(0, 128), hash, nowSec);
  if (claimed.changes === 1) {
    const row = readCode.get(hash) as
      { id: number; issued_by: string; expires_at: number; operator_label: string | null } | undefined;
    // The UPDATE matched, so the row is there. Answered defensively anyway:
    // this is the one place a missing row would mean the database changed
    // under a claim, and admitting a pairing on a guess is not the move.
    if (!row) return { ok: false, why: 'unknown' };
    return {
      ok: true, id: row.id, issued_by: row.issued_by, expires_at: row.expires_at,
      name: row.operator_label ?? null,
    };
  }
  // It did not match. Say which of the three for the journal.
  const row = readCode.get(hash) as
    { consumed_at: number | null; expires_at: number } | undefined;
  if (!row) return { ok: false, why: 'unknown' };
  if (row.consumed_at !== null) return { ok: false, why: 'reused' };
  return { ok: false, why: 'expired' };
}

/**
 * Consume the CALLER'S OWN still-live code, by its hash, the replace path
 * behind "Mint a new code?" in step 3. One UPDATE, `changes === 1` is the
 * claim, the same shape a presentation uses in consumePairingCode() above,
 * scoped to `issuer` so a replace can never reach another admin's row,
 * whatever hash the request carries.
 *
 * This is not the silent case the D1 comment near the top of this file
 * warns against. That one is a restart invalidating a code the operator may
 * be holding somewhere else, with the reason nowhere. This one is asked, on
 * the same screen, about the code that screen is showing, and the question
 * states the consequence before the operator confirms it: "the one shown
 * stops working." A confirmed, visible trade is not the hazard line 29
 * describes.
 *
 * Returns false, without error, for a hash that is malformed, unknown,
 * already consumed, expired, or issued by somebody else. The caller mints
 * the new code regardless; this only decides whether the old one stops.
 */
export function cancelPairingCodeByHash(hash: unknown, issuer: string, nowMs: number): boolean {
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) return false;
  const nowSec = Math.floor(nowMs / 1000);
  const result = cancelOwnCode.run(nowSec, 'replaced from the page', hash, issuer, nowSec);
  return result.changes === 1;
}

const liveCodeWithName = db.prepare(`
  SELECT 1 FROM fleet_pairing_codes
  WHERE operator_label = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1
`);

/**
 * Does a still-live, unspent code already carry this name (#635 review)?
 *
 * A WARNING, never a refusal: an operator minting a second code for a name
 * they already minted one for is unusual, not wrong -- the first code may
 * simply have been for a run that failed partway, and the fix is telling
 * them so at the moment it is cheapest to notice, not blocking the mint
 * they came here to do. Checked against the table, the same store
 * `pairingArmed` reads, so a restart between the two mints is answered the
 * same honest way that function already settled on.
 */
export function liveCodeNamed(name: string, nowMs: number): boolean {
  const nowSec = Math.floor(nowMs / 1000);
  return Boolean(liveCodeWithName.get(name, nowSec));
}

/**
 * Is any code live right now?
 *
 * The one question the fleet-link endpoint has to answer before it will
 * accept a pairing dial at all, and it is asked on an internet-facing
 * upgrade, so it is memoised: a scanner cannot drive one query per dial.
 *
 * Read from the TABLE rather than from a flag a mint sets, because a code
 * survives a restart (D1) and the operator may run the node's command after
 * one. A flag would be armed only in the process that minted.
 */
let armedUntilMs = 0;
let armedCheckedMs = 0;
const ARMED_MEMO_MS = 10_000;

export function pairingArmed(nowMs: number): boolean {
  if (nowMs < armedUntilMs) return true;
  if (nowMs - armedCheckedMs < ARMED_MEMO_MS) return false;
  armedCheckedMs = nowMs;
  const row = latestLive.get(Math.floor(nowMs / 1000)) as { latest: number | null } | undefined;
  armedUntilMs = row?.latest ? row.latest * 1000 : 0;
  return nowMs < armedUntilMs;
}

/** Test seam, and the same one a mint uses: a code minted a millisecond ago
 *  must arm the endpoint without waiting out the memo. */
export function clearPairingArmedMemo(): void { armedUntilMs = 0; armedCheckedMs = 0; }

/** Rows past their expiry plus an hour. Returns how many went. */
export function sweepPairingCodes(nowMs: number): number {
  const cutoff = Math.floor((nowMs - PAIRING_CODE_KEEP_MS) / 1000);
  return dropOld.run(cutoff).changes;
}

// The same shape auth.ts's challenge sweep uses, and unref'd for the same
// reason: a timer must never be what keeps this process alive.
setInterval(() => {
  try { sweepPairingCodes(Date.now()); } catch { /* the next pass */ }
}, 5 * 60_000).unref();
