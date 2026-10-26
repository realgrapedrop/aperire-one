/**
 * The fleet's model setting, written down.
 *
 * Ruling 2026-09-04: the Advisor's provider, model and key are ONE setting
 * for the whole fleet. There is no per-node picking. So there has to be a
 * record of what that setting IS, or the page can only show what each node
 * happens to report and cannot say which of them is behind.
 *
 * The record is written by the aggregator when a fleet seal finishes, and it
 * is written whenever ANY node sealed: the change happened on the fleet even
 * if one node was down for it. That node is then behind, which is the whole
 * point of keeping the record.
 *
 * What is NOT in it: the key. What is derived from it is the same hint the
 * node's own sealer writes into its config, and one SHA-256 of the whole key
 * (`key_digest`) kept for a single question: is the key being sealed now the
 * one the fleet already holds (#1114)? The hint cannot answer it (ten shown
 * characters, none at all for a short key). The digest never leaves this
 * record: publicFleetModel() drops it from everything the page is sent. A
 * digest of a LOW-entropy key can be guessed by whoever can read this file,
 * which is the dashboard's own account, so it is as strong as the key.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/** How each node ended, kept per label so the page can name the one that
 *  missed the change. `reason` is the code; the sentence is the node's and
 *  belongs to the live job, not to a record read back days later. */
export interface FleetModelTarget {
  label: string;
  state: string;
  reason: string | null;
}

export interface FleetModelRecord {
  /** The record's own shape, so a later field can be added without a file
   *  written by an older build reading as something it is not. */
  v: 1;
  base_url: string;
  provider: string;
  model: string;
  /** The same hint the node's sealer writes, so a node's own report can be
   *  compared with it character for character. Empty when the key was too
   *  short or too odd for the sealer to have made one. */
  key_hint: string;
  /** SHA-256 of the whole key, hex. Empty or absent on a record written
   *  before it existed. Never sent to the page: see publicFleetModel(). */
  key_digest?: string;
  sealed_at: string;
  /** The operator who touched the passkey, as the audit event records them.
   *  Null on a record that was not written by a seal from this page. */
  sealed_by: string | null;
  targets: FleetModelTarget[];
}

/**
 * The hint, exactly as scripts/aperire-seal-model-key.sh computes it:
 *
 *     KEY_HINT="${KEY:0:6}…${KEY: -4}"
 *
 * behind the same two guards, a length floor and a character class. Both
 * matter. The floor is why ten shown characters give nothing away, and the
 * class keeps the key ASCII, which is what makes bash's `${#KEY}` and this
 * `length` the same number.
 *
 * A hint that differs from the node's by one character reads as "that node
 * is behind" forever, with no other symptom, so this mirrors the sealer's
 * string rather than approximating it: the separator is U+2026, one
 * character, and never three dots.
 */
export function sealKeyHint(key: string): string {
  const k = String(key ?? '');
  if (k.length < 24) return '';
  if (!/^[A-Za-z0-9._-]+$/.test(k)) return '';
  return `${k.slice(0, 6)}…${k.slice(-4)}`;
}

/**
 * SHA-256 of the whole key, hex, or '' for an empty one. Computed where the
 * key is in hand, and compared only with another digest. Unlike the hint it
 * tells two keys apart whatever their length or characters, so a short or
 * base64-style key (local and OpenAI-compatible endpoints) is not mistaken
 * for a different one, and two keys from one provider that happen to share
 * their last four characters are not mistaken for the same one.
 */
export function sealKeyDigest(key: string): string {
  const k = String(key ?? '');
  return k ? createHash('sha256').update(k, 'utf8').digest('hex') : '';
}

/** The record as the page may see it: everything but the digest. */
export function publicFleetModel(record: FleetModelRecord | null): Omit<FleetModelRecord, 'key_digest'> | null {
  if (!record) return null;
  const { key_digest: _digest, ...rest } = record;
  return rest;
}

/** The brand behind a base URL, for display. The same three the form offers,
 *  and a base this table does not know falls back to its host, which is true
 *  if plain. The page prefers its own lookup and uses this when it has none. */
export function providerNameFor(baseUrl: string): string {
  switch (String(baseUrl || '')) {
    case 'https://api.anthropic.com': return 'Anthropic';
    case 'https://api.openai.com/v1': return 'OpenAI';
    case 'https://api.x.ai/v1': return 'xAI';
    default:
      try { return new URL(String(baseUrl)).host; } catch { return 'unknown'; }
  }
}

/**
 * What the root broker's `model-store-head` answers: the fleet's sealed
 * descriptor, minus the key.
 *
 * A different thing from the record above, and the difference is the whole
 * reason both exist. The RECORD is what the page renders and what every
 * node's verdict is computed against; it holds no secret and the dashboard
 * writes it. This is a HEAD of the sealed store, which only root can open,
 * and it answers one question the record cannot: would a node paired right
 * now inherit a model at all?
 *
 * Declared here beside the record so the two shapes are read together, and
 * so nothing has to import the broker client to know what a head looks like.
 */
export interface FleetModelStoreHead {
  base_url: string;
  shape: string;
  model: string;
  credential_name: string;
  /** The same hint the record holds and the node's sealer writes. */
  key_hint: string;
  sealed_at: string;
  sealed_by: string;
  /**
   * How the store is kept on this aggregator (#711): `sealed` is a
   * systemd-creds blob bound to the machine, `plain` a root-only 0600 file
   * on a host with no systemd-creds (Ubuntu 22.04 and its systemd 249).
   * Empty from a broker older than the field, which only ever sealed.
   */
  method: string;
  /**
   * The form this host would write TODAY. Differs from `method` only on an
   * aggregator whose OS moved under its store: a 22.04 host upgraded in
   * place still holds `plain` until the fleet model is sealed again.
   */
  host_method: string;
  /**
   * The path of the OTHER form, when both are on disk (a put that died
   * between writing one and removing the other). Empty when there is one.
   * On a sealing host that leftover is a plaintext key nothing else names,
   * so the page says where it is and how to remove it.
   */
  other_form_at: string;
}

/**
 * The host of a base URL, for the one line that renders the store.
 *
 * NOT providerNameFor(). `base_url` is the one field of the store a
 * compromised dashboard can rewrite with no root involved and no operator
 * present (ADR 0019 phase 4, §7), so the page prints where the Advisor would
 * actually send every question's context rather than the brand that address
 * is supposed to belong to. A poisoned base reads as `evil.example` beside
 * the model name instead of as "Anthropic".
 */
export function baseUrlHost(baseUrl: string): string {
  try {
    return new URL(String(baseUrl)).host || String(baseUrl);
  } catch {
    return String(baseUrl || 'unknown');
  }
}

export interface FleetModelSeal {
  baseUrl: string;
  model: string;
  key: string;
  sealedBy: string | null;
  targets: FleetModelTarget[];
  nowMs?: number;
}

/**
 * The record a finished job leaves, or null when the job changed nothing.
 *
 * Null when no target sealed. A run where every node refused did not change
 * the fleet's setting, and writing it would make every node read "behind" a
 * setting that is not running anywhere.
 */
export function buildFleetModelRecord(seal: FleetModelSeal): FleetModelRecord | null {
  const sealed = seal.targets.filter((t) => t.state === 'sealed');
  if (sealed.length === 0) return null;
  return {
    v: 1,
    base_url: seal.baseUrl,
    provider: providerNameFor(seal.baseUrl),
    model: seal.model,
    key_hint: sealKeyHint(seal.key),
    key_digest: sealKeyDigest(seal.key),
    sealed_at: new Date(seal.nowMs ?? Date.now()).toISOString(),
    sealed_by: seal.sealedBy,
    targets: seal.targets.map((t) => ({ label: t.label, state: t.state, reason: t.reason ?? null })),
  };
}

/**
 * Written temp-then-rename, the same way the nonce store is: a truncated
 * file would read as "no fleet setting" on the next page load, and every
 * node would go from IN SYNC to UNKNOWN with nothing wrong on any of them.
 */
export function writeFleetModelRecord(path: string, record: FleetModelRecord): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, path);
}

/**
 * The record, or null.
 *
 * Absent is the ordinary state on a dashboard that has never sealed from
 * this page, and it is not an error. Corrupt is also null, and says so in
 * the log: the page's own answer for "no record" is "the setting is this
 * dashboard's own Advisor", which is a safe place to land.
 */
export function readFleetModelRecord(
  path: string, log: (line: string) => void = console.warn,
): FleetModelRecord | null {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      log(`[fleet-model] ${path}: ${(err as Error).name}`);
    }
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<FleetModelRecord>;
    if (!parsed || typeof parsed !== 'object') return null;
    if (typeof parsed.base_url !== 'string' || typeof parsed.model !== 'string') return null;
    return {
      v: 1,
      base_url: parsed.base_url,
      provider: typeof parsed.provider === 'string' ? parsed.provider : providerNameFor(parsed.base_url),
      model: parsed.model,
      key_hint: typeof parsed.key_hint === 'string' ? parsed.key_hint : '',
      key_digest: typeof parsed.key_digest === 'string' && /^[0-9a-f]{64}$/.test(parsed.key_digest)
        ? parsed.key_digest : '',
      sealed_at: typeof parsed.sealed_at === 'string' ? parsed.sealed_at : '',
      sealed_by: typeof parsed.sealed_by === 'string' ? parsed.sealed_by : null,
      targets: Array.isArray(parsed.targets)
        ? parsed.targets.filter((t): t is FleetModelTarget => !!t && typeof t.label === 'string')
          .map((t) => ({ label: t.label, state: String(t.state ?? ''), reason: t.reason ?? null }))
        : [],
    };
  } catch {
    log(`[fleet-model] ${path}: not readable as a record`);
    return null;
  }
}

// ── Is this node on the fleet's setting? ─────────────────────────────────

/** What a node's Advisor reports about its model, as much of it as the
 *  comparison uses. Every field optional: a node running an older build
 *  reports fewer of them, and "not reported" is not "reported empty". */
export interface NodeModelReport {
  base_url?: unknown;
  name?: unknown;
  key_hint?: unknown;
  configured?: unknown;
  configured_at?: unknown;
  /** Whether the credential a validated config names is actually on this
   *  host, distinct from whether a model is chosen at all (#516: a config
   *  restored from a backup with no sealed key behind it). Absent on a node
   *  running a build that predates the field, and absent means unknown, the
   *  same rule as every other field here: never read as false. */
  credential_present?: unknown;
}

export type NodeSync =
  | 'in_sync' | 'behind' | 'no_model' | 'no_credential' | 'unread' | 'no_advisor' | 'unknown';

/**
 * How much later than the fleet's own timestamp a node may be sealed and
 * still count as current.
 *
 * Two clocks meet here and neither is authoritative. `configured_at` is
 * written by the node's own sealer at the moment it sealed; `sealed_at` is
 * this dashboard's, at the moment the operator approved. Every node a job
 * seals therefore carries a timestamp at or after the record's, and this
 * allowance only has to absorb a host that is off on NTP. The identity triple (base URL, model, key hint) is the
 * real evidence that a node holds the fleet's setting; the timestamp only
 * catches "the same key was sealed again and this node missed it", where
 * the node's own config is functionally identical anyway. So the allowance
 * is generous on purpose: a wrong BEHIND is worse than a late one.
 */
export const SEALED_AT_ALLOWANCE_MS = 60 * 60 * 1000;

export interface SyncInput {
  /** Whether that node's Advisor answered, said nothing, or is not there.
   *  Three states, never two: a node whose dashboard blipped has not told
   *  us it has no Advisor. */
  presence: 'present' | 'absent' | 'unread';
  model: NodeModelReport | null;
  fleet: FleetModelRecord | null;
  /**
   * Where the setting came from, because the timestamp means something in
   * only one of the two cases.
   *
   * On a 'record' the `sealed_at` is when an operator approved a change for
   * the fleet, so a node whose own seal predates it by a lot did not take
   * that change. On a 'self' setting it is one machine's own seal date and
   * says nothing about any other machine: a peer sealed a week earlier from
   * the Advisor tab, on the same provider, model and key, is behind
   * nothing. Under 'self' the identity triple is the whole evidence.
   */
  source?: 'record' | 'self' | 'none';
}

/**
 * One node's verdict against the fleet's setting.
 *
 * Order matters. Presence first, because a node that did not answer has
 * said nothing at all about its model. Then the node's own unconditional
 * fact (it reports no model, or a model it cannot reach), because that is
 * true whether or not this dashboard knows what the fleet's setting is.
 * Only then the comparison, which needs a setting to compare against.
 */
export function computeNodeSync(input: SyncInput): NodeSync {
  if (input.presence === 'absent') return 'no_advisor';
  if (input.presence === 'unread') return 'unread';
  const m = input.model;
  if (!m || m.configured === false) {
    // A model is chosen but the credential behind it is not on this host.
    // A config restored from a backup with no sealed key is the shape this
    // exists for (#516), and it is exactly the node a catch-up push should
    // be offered for, the same as `no_model`. Kept apart from `no_model`
    // because the row can still name the model, and the operator should not
    // be told there is nothing sealed when there is.
    //
    // `credential_present` is read strictly: only an explicit `false`
    // alongside a named model reaches this branch. A node running a build
    // that predates the field reports neither, and it must fall through to
    // `no_model` exactly as it always has: an absent field is unknown,
    // never a claim of its own.
    if (m && m.credential_present === false && typeof m.name === 'string' && m.name) {
      return 'no_credential';
    }
    return 'no_model';
  }
  const fleet = input.fleet;
  // No setting recorded and nothing to take one from: the node reports a
  // model and there is nothing to hold it against. Not in sync, not behind.
  if (!fleet) return 'unknown';
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');
  if (str(m.base_url) !== fleet.base_url) return 'behind';
  if (str(m.name) !== fleet.model) return 'behind';
  if (str(m.key_hint) !== fleet.key_hint) return 'behind';
  if ((input.source ?? 'record') === 'record') {
    const nodeAt = Date.parse(str(m.configured_at));
    const fleetAt = Date.parse(fleet.sealed_at);
    if (isFinite(nodeAt) && isFinite(fleetAt) && nodeAt < fleetAt - SEALED_AT_ALLOWANCE_MS) return 'behind';
  }
  return 'in_sync';
}
