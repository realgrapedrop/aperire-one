// Lightweight SQLite-backed time-series store for Aperire historical metrics.
// One file (aperire.db) under the repo's data/ dir, outside the source tree
// so the systemd unit's ReadWritePaths can grant write access to data/ only,
// never dashboard/. Single table, append-only writes, bucketed reads. 30-day
// retention; daily prune.
//
// Why SQLite: matches Koi's pattern (better-sqlite3), no daemon to install,
// embedded, fast enough that we don't care about query performance at this
// scale (~215k rows for 5 metrics × 30 days at 1-min granularity).

import Database from 'better-sqlite3';
import { existsSync, renameSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

// Default path = <repo>/data/aperire.db (data/ sits one level up from
// dashboard/, alongside the logs the unit writes). Keeping the DB out of the
// source tree lets the systemd unit's ReadWritePaths exclude dashboard/.
// Override APERIRE_DB_PATH lets a parallel dev instance use its own sqlite
// file without colliding with the prod systemd unit's DB.
const DEFAULT_DB_PATH = resolve(import.meta.dirname, '..', 'data', 'aperire.db');
const DB_PATH = process.env.APERIRE_DB_PATH
  ? resolve(process.env.APERIRE_DB_PATH)
  : DEFAULT_DB_PATH;
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;        // 30 days

/** The directory the database lives in: the one place under the install the
 *  dashboard's own unit may write (ReadWritePaths=@REPO@/data, with
 *  ProtectSystem=strict making dashboard/config read-only). A file the
 *  running dashboard has to create for itself goes here. */
export const DB_DIR = dirname(DB_PATH);

/**
 * Seconds between the Unix epoch and the Ripple epoch (2000-01-01 UTC).
 *
 * `ledgers.close_ts` holds rippled's own `ledger_time`, which counts from the
 * Ripple epoch, so its values are ~946 million lower than a Unix timestamp
 * for the same instant. Anything comparing that column against `Date.now()`
 * has to cross this offset explicitly, and the one place that forgot deleted
 * the entire ledger history on every prune: every stored value looked like
 * 1996 to a Unix-epoch cutoff.
 */
export const RIPPLE_EPOCH_S = 946_684_800;

// Ensure the parent dir exists before opening, the default data/ dir is
// created by the installer at 0750, but a fresh dev checkout (or a custom
// APERIRE_DB_PATH) may point at a dir that doesn't exist yet.
mkdirSync(dirname(DB_PATH), { recursive: true });

// One-shot migration of any in-tree DB to the new out-of-tree location.
// Two legacy locations are moved into DB_PATH (preserving all previously
// collected metrics + the WAL/SHM sidecars): the old in-source aperire.db
// (pre-data-dir layout) and the even-older pharos.db (project rebrand).
// No-op once the destination already exists or when APERIRE_DB_PATH is set.
(function migrateLegacyDb() {
  if (process.env.APERIRE_DB_PATH || existsSync(DB_PATH)) return;
  for (const legacyName of ['aperire.db', 'pharos.db']) {
    const legacyMain = resolve(import.meta.dirname, legacyName);
    if (!existsSync(legacyMain)) continue;
    // Best-effort. Under the systemd unit dashboard/ is read-only
    // (ProtectSystem=strict), so a rename out of the source tree can fail
    // with EROFS, the installer relocates the DB with root before the
    // service starts, so don't crash startup here; just point at the fix.
    try {
      renameSync(legacyMain, DB_PATH);
      for (const suffix of ['-wal', '-shm']) {
        const from = legacyMain + suffix;
        const to = DB_PATH + suffix;
        if (existsSync(from) && !existsSync(to)) renameSync(from, to);
      }
      console.log(`[db] migrated ${legacyName} → data/aperire.db (preserving history)`);
    } catch (err) {
      console.warn(
        `[db] found legacy ${legacyName} in the source tree but could not move it ` +
        `to ${DB_PATH} (${(err as Error).message}). Re-run install-aperire-service.sh, ` +
        `which relocates it with root before the service starts.`,
      );
    }
    return;
  }
})();

export type MetricName =
  | 'close_time'
  | 'converge_time'
  | 'txn_count'
  | 'load_factor'
  | 'validation_rate'
  | 'agreement_pct'
  // Consensus alert-rule inputs (rules.yaml). 1h-windowed agreement and
  // missed-validation counts written from the 60s aggregate tick, plus the
  // rippled job-queue transaction-overflow counter from server_info. Named
  // to match the keys the alert rules and knowledge/metric-alerts.yaml use.
  | 'agreement_pct_1h'
  | 'missed_validations_1h'
  | 'jq_trans_overflow'
  // amendment_blocked as 1/0 from server_info. rippled omits the field
  // entirely when false, so absence is written as 0 rather than skipped,
  // a metric that only ever appears while blocked gives an operator no way
  // to tell "not blocked" from "not being watched". This is the one
  // condition the field guide calls drop-everything: a blocked server stops
  // participating in consensus altogether.
  | 'amendment_blocked'
  // #654: days until this node is amendment-blocked by something it does
  // NOT support, holding the network's majority right now — the warning
  // ahead of amendment_blocked's own fact. Written every pollFeature() tick
  // at a large constant (see NO_UNSUPPORTED_MAJORITY_DAYS in
  // lib/amendments.ts) when nothing qualifies, so the alert rule always has
  // a fresh sample to resolve against rather than being stuck on the last
  // real countdown it saw.
  | 'unsupported_amendment_days_to_block'
  // Is a newer node release available. 1 when the running build is behind
  // the latest published release, 0 when current, absent when the check has
  // not succeeded yet. RB-001's primary trigger in the Advisor's runbook
  // inventory is "build_version behind current release", and until this
  // existed the dashboard had no idea what the current release was, a
  // trigger with nothing to fire it.
  | 'node_version_behind'
  // Is a newer APERIRE release published. 1 when the endpoint publishes a
  // release this install is not on, 0 when it publishes the one it is on,
  // and absent for every other reading: a host with no stamp, an endpoint
  // caught mid-publish, a box with no egress. Deliberately not folded into
  // node_version_behind above — that one is rippled's version, this one is
  // the dashboard's own, and a rule written for either would say the wrong
  // thing about the other (ADR 0022 decision 2).
  | 'update_available'
  // Network-tab history series, sampled once per minute from the live
  // peers poll and the most recent net_stats relay broadcast.
  | 'peer_count'
  | 'peers_inbound'
  | 'peers_outbound'
  | 'peers_insane'
  | 'peer_latency_p50'
  | 'peer_latency_p90'
  | 'rx_bps'
  | 'tx_bps'
  | 'rx_pps'
  | 'tx_pps'
  | 'tcp_retrans_per_sec'
  | 'tcp_established'
  // A derived verdict, not a measurement: which way a peer loss is pointing.
  // 0 nothing unusual · 1 the network shed us · 2 our own box. Written from
  // series already collected, so it costs one derivation per sample and no
  // new collection. See classifyPeerShed in server.ts for what the numbers
  // mean and why they mean it.
  | 'peer_shed_signal'
  // How the network sees this validator, from the public registry. A node
  // cannot establish either of these about itself: one that has gone invisible
  // to every peer still reports itself healthy.
  | 'validator_registry_seen'      // 1 when the registry lists our key, else 0
  | 'validator_last_seen_age_s'    // seconds since the network last saw us sign
  | 'validator_version_drift'      // 1 when the registry's version != ours
  // Relay connection counts (net_stats broadcast): rippled HTTP-RPC,
  // admin-WS, public-WS, and peer connection tallies. Written from the
  // 10s network sample whenever the relay supplies them.
  | 'http_rpc_conn'
  | 'admin_ws_conn'
  | 'ws_public_conn'
  | 'peer_conn'
  // Relay-feed freshness, seconds since the last net_stats push. Written
  // EVERY network sample tick (not gated on the relay being up), so it climbs
  // when the relay is silent and drives the relay_feed_age_s alert + the
  // Network-tab stale-feed banner.
  | 'relay_feed_age_s'
  // Node reachability, seconds the node itself has been unreachable, written
  // EVERY network sample tick (0 while reachable). Climbs during a restart or
  // outage so it can trip the node_unreachable_s alert, instead of the node
  // reading healthy off a kept last-good peer count (#54).
  | 'node_unreachable_s'
  // How many hosts in this fleet are not on the deploy ref the largest group
  // is on (issue #128). Written once a minute by the aggregator only, and
  // only when at least one host reported a ref — a single-node install never
  // writes it, and "nobody could say" is never recorded as agreement. Hosts
  // that report no ref are not counted here at all; they carry `unknown` on
  // their own row instead.
  | 'fleet_deploy_divergent'
  // System-tab: rippled data-dir size sampled once per minute. 24h growth
  // + mount-free-days estimates derive from this timeseries.
  | 'nudb_size'
  // The same sizes, but only the ones this host's Advisor measured (#1245),
  // so a fit over them cannot reach back into a different store's samples in
  // nudb_size. Written beside nudb_size, never charted on its own.
  | 'nudb_size_advisor'
  // How long the data mount lasts at the growth measured over the last 24
  // hours. The safety net behind the scheduled rotation window (#79): a node
  // that is pruning reads 3650 here, because its store sawtooths and 24-hour
  // growth is flat. Only a node that has stopped pruning makes this fall.
  | 'nudb_mount_free_days'
  // The host verifier's last run (scripts/verify-after-restart.sh on
  // aperire-verify.timer), read out of data/verify-report.json once a minute.
  // How many of its checks failed, and how long ago the run was, from the
  // report's own stamp rather than the file's mtime. Neither is ever written
  // from an absent or unparseable report: a zero here would be a claim that a
  // run happened and found nothing wrong.
  | 'verify_failed_checks'
  | 'verify_report_age_s'
  // And whether there is a report at all. 1 means this host installs the
  // verifier and has none, 0 means one was read. Written only where the timer
  // unit exists, so a box with no verifier is silent here rather than
  // permanently alarmed about an installer it never ran (#143).
  | 'verify_report_missing'
  // System-tab history series, sampled once per minute from the pushSystem
  // cache so the history card below the top-row cards has data to draw.
  | 'cpu_busy_pct'
  | 'cpu_iowait_pct'
  | 'mem_used_pct'
  // Page cache as % of RAM (MemAvailable − MemFree). Charted beside memory
  // and swap: on a validator this is mostly node-store pages, and a cache
  // that collapses is the reads about to go to disk.
  | 'mem_cache_pct'
  | 'swap_used_pct'
  | 'pressure_cpu'
  | 'pressure_memory'
  | 'pressure_io'
  | 'rippled_cpu_pct'
  | 'rippled_rss_pct'
  // Node-store activity, from per-interval deltas of get_counts'
  // node_reads_total / node_reads_hit / node_writes. Deliberately NOT the
  // cumulative AL_hit_rate / SLE_hit_rate rippled reports: those are hits
  // over hits+misses since the process started, so they flatten after the
  // first hours and a cache going bad barely moves them. A delta says what
  // the store did in the last interval.
  | 'nodestore_read_hit_pct'
  | 'nodestore_reads_per_s'
  | 'nodestore_writes_per_s';

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

// Defense-in-depth: lock the on-disk DB down to the service user only.
// The DB holds session/magic-link hashes (no longer plaintext, see the
// hashing below) plus bandwidth/alert history; even hashed, a world-
// readable DB is needless exposure. Best-effort: a chmod failure (e.g.
// the file lives on a filesystem that ignores POSIX modes) is logged but
// not fatal, the WAL-mode open already succeeded and the install script
// is the primary enforcement path.
//
// The DB file (+ WAL/SHM) is always squeezed to 0600. The parent dir is left
// alone for the two managed cases, the default data/ dir (install-aperire-
// service.sh owns it at 0750 <operator>:<operator>) and a dev checkout, and is
// only tightened to 0700 when the operator has pointed APERIRE_DB_PATH at a
// dedicated dir of their own, where clamping is the safe default. We never
// chmod the source tree, and we don't fight the installer's 0750 on data/.
(function restrictDbPermissions() {
  const targets = [DB_PATH, DB_PATH + '-wal', DB_PATH + '-shm'];
  for (const f of targets) {
    if (!existsSync(f)) continue;
    try { chmodSync(f, 0o600); }
    catch (err) { console.warn(`[db] could not chmod ${f} to 0600: ${(err as Error).message}`); }
  }
  // Only clamp the dir when the operator pointed APERIRE_DB_PATH somewhere of
  // their own choosing, the default data/ dir is the installer's to manage.
  if (process.env.APERIRE_DB_PATH) {
    const dbDir = dirname(DB_PATH);
    try { chmodSync(dbDir, 0o700); }
    catch (err) { console.warn(`[db] could not chmod data dir to 0700: ${(err as Error).message}`); }
  }
})();

// SHA-256 (hex) of an opaque high-entropy token. Used to store session
// ids and magic-link tokens as hashes: the raw value lives only in the
// cookie / emailed URL, the DB keeps the digest, and every lookup hashes
// the presented value first. These tokens are already 256-bit CSPRNG
// output, so plain SHA-256 (no salt/PBKDF) is the correct API-key-style
// hashing, fast, deterministic, and not brute-forceable at this entropy.
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}
db.exec(`
  CREATE TABLE IF NOT EXISTS metrics (
    ts INTEGER NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL,
    PRIMARY KEY (ts, metric)
  );
  CREATE INDEX IF NOT EXISTS idx_metric_ts ON metrics(metric, ts);

  CREATE TABLE IF NOT EXISTS ledgers (
    ledger_index INTEGER PRIMARY KEY,
    close_ts     INTEGER NOT NULL,        -- epoch seconds (rippled ledger_time)
    close_time   REAL    NOT NULL,        -- delta seconds
    txn_count    INTEGER NOT NULL,
    fam_money    INTEGER NOT NULL,
    fam_market   INTEGER NOT NULL,
    fam_nft      INTEGER NOT NULL,
    fam_accts    INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_ledgers_close_ts ON ledgers(close_ts);

  -- Per-ledger agreement record (did OUR validator sign this ledger). Persisted
  -- so a dashboard restart doesn't wipe the rolling 1h/24h agreement windows
  -- (otherwise the panel resets to a tiny sample and reads as a false drop).
  -- ts is epoch MILLISECONDS to match the in-memory agreementHistory window math.
  CREATE TABLE IF NOT EXISTS agreement (
    ledger_index INTEGER PRIMARY KEY,
    our_voted    INTEGER NOT NULL,        -- 0 | 1
    ts           INTEGER NOT NULL          -- epoch ms
  );
  CREATE INDEX IF NOT EXISTS idx_agreement_ts ON agreement(ts);

  -- Missed ledgers, the identities, kept. The agreement table above records
  -- every ledger for the rolling windows and is pruned after two days; this
  -- table keeps only the misses, permanently, with the node's context captured
  -- at the moment of the miss, because that context is the one thing that
  -- cannot be reconstructed later. Misses are near zero in normal operation,
  -- so this stays small forever. No prune, deliberately.
  CREATE TABLE IF NOT EXISTS missed_ledgers (
    ledger_index     INTEGER PRIMARY KEY,
    ts               INTEGER NOT NULL,     -- epoch ms
    validations_seen INTEGER,              -- validations observed for this ledger
    trusted_unl      INTEGER,              -- UNL size at the time
    peer_count       INTEGER,
    server_state     TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_missed_ledgers_ts ON missed_ledgers(ts);

  -- Insights tab, alert lifecycle events. One row per state transition
  -- (firing, resolved). The dedup_key uniquely identifies a single firing
  -- instance, joining the firing event row with its later resolved row.
  CREATE TABLE IF NOT EXISTS alerts_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,    -- epoch seconds of the transition
    metric          TEXT NOT NULL,
    severity        TEXT NOT NULL,       -- warn | critical | page
    state           TEXT NOT NULL,       -- firing | resolved
    value           REAL,
    threshold_op    TEXT,
    threshold_value REAL,
    duration_s      INTEGER,             -- threshold-hold required (firing) or held (resolved)
    dedup_key       TEXT NOT NULL,
    channels        TEXT,                -- JSON array of channel ids
    delivery        TEXT,                -- JSON map { channelId: 'pending'|'delivered'|'failed:<reason>' }
    acked_at        INTEGER,
    muted_until     INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts_history(ts);
  CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts_history(dedup_key);

  -- Currently firing alerts. One row per active firing instance, removed
  -- when the alert resolves. Survives restart so the dashboard recovers
  -- its state machine from disk on boot.
  CREATE TABLE IF NOT EXISTS firing_state (
    dedup_key     TEXT PRIMARY KEY,
    metric        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    triggered_ts  INTEGER NOT NULL,    -- when threshold first crossed (epoch s)
    fired_ts      INTEGER NOT NULL,    -- when state went OK→firing (epoch s)
    last_value    REAL,
    last_seen_ts  INTEGER,
    threshold_op    TEXT,
    threshold_value REAL,
    duration_s      INTEGER,
    channels      TEXT,                  -- JSON array
    acked_at      INTEGER,
    muted_until   INTEGER,
    last_paged_ts INTEGER                 -- for Page-tier 15-min re-fire (Phase 9)
  );

  -- Insights tab, scheduled digest delivery record. Phase 6 starts
  -- writing here when real digests send.
  CREATE TABLE IF NOT EXISTS digest_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               INTEGER NOT NULL,    -- send timestamp (epoch seconds)
    channel          TEXT NOT NULL,       -- email | ntfy | webhook
    state            TEXT NOT NULL,       -- sent | retried | failed
    subject          TEXT,
    recipient_count  INTEGER NOT NULL,
    message_id       TEXT,                -- provider message id (Resend, etc.)
    retry_count      INTEGER NOT NULL DEFAULT 0,
    error            TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_digest_ts ON digest_runs(ts);

  -- ── Auth (Phase A1) ────────────────────────────────────────────────
  -- WebAuthn / passkey-based operator authentication. Operator records
  -- are kept here so the SSH CLI can manage users without touching the
  -- running dashboard process. All accessor functions live in auth.ts.

  -- One row per operator. The operator's email is the unique identity:
  -- the username column stores the same value (kept for code-compat;
  -- accessors read by username, which is now an email). Email is also
  -- mirrored in its own column + carries a UNIQUE index for collision
  -- safety against case differences or future drift.
  --
  -- role is 'admin' or 'monitor'. It decides one thing: whether this operator
  -- may authorise an Advisor action against the validator. Both roles see the
  -- same dashboard, hiding read-only data from a colleague is not a security
  -- property, and pretending otherwise makes people share the admin login.
  -- Approving a change to a validator is a different question, and that is the
  -- one the role answers.
  -- Independent witness to the Advisor's action ledger.
  --
  -- That ledger is hash-chained, which makes an ALTERED entry visible: every
  -- entry commits to the one before it. What it cannot do is notice its own
  -- tail being cut off, verification walks forward from the first entry, so
  -- a file with the last N entries removed verifies perfectly, or a
  -- consistent rewrite by anyone who can write the file, since they can
  -- recompute every hash.
  --
  -- Both gaps close the same way: something outside the file has to remember
  -- what it saw. The dashboard records (count, head) as it observes them, so
  -- a shorter ledger than one already seen, or a different head at a count
  -- already seen, is a contradiction rather than a clean chain.
  -- Keyed by (node, entry_count), not entry_count alone.
  --
  -- The node column is what makes this usable for a fleet at all. Without it,
  -- pointing the witness at peers cross-contaminates: node2's 40 entries at a
  -- different head than node1's 40 entries reads as "rewritten", and a false
  -- tamper alarm is worse than no alarm, an operator who learns to dismiss
  -- one will dismiss the real one. Rows written before this column existed
  -- are this host's own, and migrate to the LOCAL_NODE sentinel.
  CREATE TABLE IF NOT EXISTS ledger_witness (
    node        TEXT    NOT NULL,      -- which node's ledger this observation is of
    entry_count INTEGER NOT NULL,      -- entries in the ledger at observation
    head        TEXT    NOT NULL,      -- hash of the last entry at that count
    first_seen  INTEGER NOT NULL,      -- epoch seconds
    PRIMARY KEY (node, entry_count)
  );

  -- Contradictions, kept. An alarm that clears itself when the ledger is put
  -- back is not an alarm.
  CREATE TABLE IF NOT EXISTS ledger_alarms (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     INTEGER NOT NULL,
    kind   TEXT    NOT NULL,           -- truncated | rewritten | unreadable
    detail TEXT    NOT NULL
  );

  -- Has an Advisor ever answered on this host? ADR 0016.
  --
  -- Modelled on ledger_witness above, and for the same reason: a fact that
  -- has to survive a restart to stay true. The Advisor is optional, and a
  -- dashboard installed without one must not nag about a service nobody
  -- asked for. The readable token file is what says an Advisor is installed;
  -- this row is only the memory that keeps a PERMISSIONS ACCIDENT from
  -- silently hiding one. advisord's own ensureToken() records that accident
  -- happening once already, at 0600.
  --
  -- Epoch SECONDS, matching ledger_witness.first_seen. The browser payload
  -- carries milliseconds, and lastAdvisorAnsweredMs() below is the single
  -- place the two units meet.
  --
  -- Only the self row (LOCAL_NODE) is written today. The node column is here
  -- for symmetry, and so that peer liveness, if it is ever polled, has a
  -- place to land without a table rebuild.
  CREATE TABLE IF NOT EXISTS advisor_presence (
    node          TEXT PRIMARY KEY,
    first_seen    INTEGER NOT NULL,
    last_answered INTEGER NOT NULL
  );

  -- Which store the nudb_size series describes (#1251). One row. 'path' is
  -- the store directory the series was recorded for; 'cut_s' (epoch SECONDS,
  -- like the metrics table's ts) is where the current store's series begins, 0 when the
  -- whole of it is one store. Nothing before cut_s is read for the peaks, the
  -- growth fit, the free-days estimate or the chart: they belong to a store
  -- that was replaced. The samples themselves are kept, so a cut that was a
  -- false alarm loses nothing.
  CREATE TABLE IF NOT EXISTS store_series (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    path  TEXT NOT NULL,
    cut_s INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS auth_users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT,
    role            TEXT NOT NULL DEFAULT 'operator',
    created_at      INTEGER NOT NULL,        -- epoch seconds
    last_login_at   INTEGER
  );

  -- One row per registered passkey. credential_id is the WebAuthn-returned
  -- handle (base64url) and must be unique across the whole table, the
  -- browser sends it back at login time and we look up by it. public_key
  -- is the COSE-encoded public key (base64url). sign_count is rolled
  -- forward on every successful assertion to detect cloned authenticators.
  CREATE TABLE IF NOT EXISTS auth_credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL UNIQUE,    -- base64url
    public_key      TEXT NOT NULL,           -- base64url COSE
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      TEXT,                    -- CSV: usb,ble,nfc,internal,hybrid
    name            TEXT,                    -- operator-chosen label, e.g. "primary-laptop"
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_auth_credentials_user ON auth_credentials(user_id);

  -- One row per active session. id stores the SHA-256 (hex) of the
  -- random 256-bit token the cookie carries, the raw token never hits
  -- disk, so a DB read yields nothing replayable. Every lookup hashes
  -- the presented cookie value first (see auth.ts hashToken). last_activity_at
  -- drives idle-timeout; A3 reads auth.yaml for the threshold. revoked_at
  -- is set when the session is locked / killed; queries filter on it so
  -- revoked rows aren't valid.
  CREATE TABLE IF NOT EXISTS auth_sessions (
    id                TEXT PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    created_at        INTEGER NOT NULL,
    last_activity_at  INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,        -- absolute lifetime cap: created_at + SESSION_ABSOLUTE_TTL_S (7 days, MED-03); cookie Max-Age aligned
    revoked_at        INTEGER,                 -- non-null = invalid
    user_agent        TEXT,
    ip                TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);

  -- One-time tokens for magic-link new-device enrollment. Issued by the
  -- SSH CLI or by an authenticated operator inviting a new device, sent
  -- via Resend. The token column stores the SHA-256 (hex) of the 256-bit
  -- raw token; the raw token rides only in the emailed URL and redemption
  -- hashes the presented token before lookup, a DB read can't yield a
  -- usable link. Single-use: consumed_at is set on first redemption and
  -- the token can never be replayed. ttl_minutes from auth.yaml governs
  -- expiry.
  CREATE TABLE IF NOT EXISTS auth_magic_links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT NOT NULL UNIQUE,    -- SHA-256 hex of a 256-bit raw token
    user_id         INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    purpose         TEXT NOT NULL,           -- 'enroll' | 'recover'
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    consumed_at     INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_auth_magic_user ON auth_magic_links(user_id);

  -- Who changed who may do what.
  --
  -- This closes the largest hole in the audit story, and the least defensible
  -- one: the privileged action that decides who may perform every other
  -- privileged action left no record on either side of the system. A role
  -- change rewrites the Advisor's trust store as a side effect, so one
  -- command silently changes the set of passkeys that can authorise an
  -- upgrade, and afterwards nothing anywhere said it had happened. The
  -- Advisor now observes its own store changing; this is the dashboard's half,
  -- recording the DECISION rather than its downstream effect.
  --
  -- Append-only by convention (nothing updates or deletes a row) and
  -- deliberately outside the ADR 0008 read contract, with ledger_witness, for
  -- the same reason the auth_* tables are: a read token must never be able to
  -- enumerate who holds which role.
  CREATE TABLE IF NOT EXISTS auth_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,      -- epoch seconds
    actor       TEXT    NOT NULL,      -- who performed it; an operator, or a named CLI account
    actor_role  TEXT,                  -- what they were allowed to do at the time
    event       TEXT    NOT NULL,      -- role_change | credential_enrolled | credential_removed | magic_link_issued | trust_synced
    target      TEXT,                  -- who or what it was done TO
    detail      TEXT                   -- JSON; the before/after of the change, never key material
  );
  CREATE INDEX IF NOT EXISTS idx_auth_events_at ON auth_events(at DESC);

  -- One-time codes a node presents to join the fleet (ADR 0019 phase 3).
  --
  -- Shaped on auth_magic_links above, and for the same three reasons. The
  -- code column holds the SHA-256 (hex) of the printed code, normalised, so
  -- a read of this table yields nothing presentable. consumed_at makes it
  -- single-use, and the claim is one UPDATE ... WHERE consumed_at IS NULL,
  -- so two simultaneous presentations of one code resolve exactly once.
  -- expires_at is the mint plus fifteen minutes, and a PENDING row expires
  -- with its code rather than with its hello: the window the operator
  -- agreed to is the one they started.
  --
  -- In the auth_* family on purpose, which is outside the ADR 0008 read
  -- contract, so a read token can never enumerate codes in flight.
  CREATE TABLE IF NOT EXISTS fleet_pairing_codes (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    code_sha256          TEXT NOT NULL UNIQUE,  -- SHA-256 hex of the normalised code
    issued_by            TEXT NOT NULL,         -- the session's username, never a request body
    issued_credential_id TEXT NOT NULL,         -- which passkey opened that session
    created_at           INTEGER NOT NULL,      -- epoch seconds
    expires_at           INTEGER NOT NULL,      -- created_at + 900
    consumed_at          INTEGER,               -- set when a hello resolves it
    consumed_from        TEXT                   -- the rate key it was presented from
  );
  CREATE INDEX IF NOT EXISTS idx_fleet_pairing_expires ON fleet_pairing_codes(expires_at);

  -- The fleet-wide Advisor ledger mirror. ADR 0021 build step 3.
  --
  -- One row per node's ledger entry, fed through the peer advisor proxy (or
  -- read directly for this host's own advisord) from GET /v1/ledger's
  -- since_seq tail. This table is a copy, never a source: every row carries
  -- the hash and prev_hash the node itself computed, which is what lets a
  -- run of rows be re-verified against that node at any time. The
  -- aggregator never appends an entry of its own.
  --
  -- Keyed by (node, run, seq), not (node, seq) alone. run is the genesis
  -- identity of the chain a row belongs to: the hash the node's own entry 1
  -- carries. A reinstalled node's Advisor starts a fresh chain numbering
  -- from seq 1 again, and without run its first new entry would collide
  -- with the old chain's entry 1 at the same primary key, which is exactly
  -- the silently-overwritten outcome the ADR rules out. Two runs for one
  -- node are two sets of rows under two different run values, never merged
  -- and never compared against each other.
  CREATE TABLE IF NOT EXISTS advisor_ledger (
    node        TEXT    NOT NULL,
    run         TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    at          TEXT    NOT NULL,   -- the node's own RFC3339 string, kept as sent
    kind        TEXT    NOT NULL,
    plan_id     TEXT,
    summary     TEXT    NOT NULL,
    data        TEXT    NOT NULL,   -- JSON text, the node's own fields
    prev_hash   TEXT    NOT NULL,
    hash        TEXT    NOT NULL,
    verified_at INTEGER NOT NULL,   -- epoch seconds this row was mirrored
    PRIMARY KEY (node, run, seq)
  );

  -- One row per node, tracking where its mirror stands and whether it is
  -- allowed to keep growing.
  --
  -- as_of is the "kept versus observed" boundary this whole surface exists
  -- to respect: it advances only on a poll that actually reached the node,
  -- never on an attempt that failed, so a row can never be shown as current
  -- off the back of a timeout. last_attempt_at is separate and advances on
  -- every attempt, success or not, so a node gone quiet can say since when.
  --
  -- broken and the three break_* columns are the durable half of "stops
  -- mirroring that node until an operator re-verify": a flag that only
  -- lived in memory would clear itself on the next restart, which is not a
  -- re-verify, it is silence mistaken for repair.
  CREATE TABLE IF NOT EXISTS advisor_ledger_mirror_state (
    node            TEXT PRIMARY KEY,
    run             TEXT,             -- the current run's genesis hash; absent before the first sync
    last_seq        INTEGER NOT NULL DEFAULT 0,
    last_hash       TEXT,
    as_of           INTEGER,          -- epoch seconds of the last successful poll
    last_attempt_at INTEGER,          -- epoch seconds of the last attempt, success or not
    last_error      TEXT,
    broken          INTEGER NOT NULL DEFAULT 0,
    break_seq       INTEGER,
    break_expected  TEXT,
    break_got       TEXT
  );

  -- ADR 0021 build step 5: the fleet mirror of what each node's Advisor
  -- remembers and has been told, alongside the ledger mirror above.
  --
  -- Neither table has a hash chain to verify, so neither needs the ledger
  -- mirror's run/seq machinery: a node's memory and inbox are re-read
  -- WHOLE on every poll (there is no since_seq on /v1/memory or /v1/inbox),
  -- and every row that comes back is upserted by its own stable id, never
  -- deleted. A node whose state/ was wiped, or an Advisor that was
  -- reinstalled, answers a full read that is empty or smaller than before;
  -- the rows this mirror already holds for it stay exactly where they are.
  -- That is the same direction ADR 0021 rules the ledger mirror to fail in
  -- ("removing every Advisor from a fleet leaves the aggregator with a
  -- mirror of what they recorded while they existed") and it is a plainer
  -- one here, because there is no chain to say a rewrite happened, an
  -- upsert-only mirror simply cannot lose history on a bad read.
  CREATE TABLE IF NOT EXISTS advisor_memory_mirror (
    node          TEXT    NOT NULL,
    id            TEXT    NOT NULL,   -- memory.Entry.ID, the node's own sha256-derived id
    at            TEXT    NOT NULL,   -- the node's own RFC3339 string, kept as sent
    kind          TEXT    NOT NULL,   -- observed | concluded | confirmed
    title         TEXT    NOT NULL,
    body          TEXT    NOT NULL,
    tags          TEXT    NOT NULL DEFAULT '[]', -- JSON array text
    source        TEXT,
    confirmed_by  TEXT,
    confirmed_at  TEXT,
    superseded_by TEXT,
    last_seen_at  INTEGER NOT NULL,   -- epoch seconds of the poll that last saw this row
    -- Set once, only by a Settings admin action (never by the poller): the
    -- entry has been copied into fleet knowledge as an operator-authored
    -- note. Nullable, because most rows never are.
    promoted_at   INTEGER,
    promoted_by   TEXT,
    promoted_file TEXT,
    PRIMARY KEY (node, id)
  );

  CREATE TABLE IF NOT EXISTS advisor_inbox_mirror (
    node          TEXT    NOT NULL,
    id            TEXT    NOT NULL,   -- inbox.Note.ID, minted per node, never colliding
    title         TEXT    NOT NULL,
    body          TEXT    NOT NULL,
    question      TEXT,
    source        TEXT,
    created_at    TEXT    NOT NULL,
    provenance    TEXT,
    rank          INTEGER,
    status        TEXT    NOT NULL,   -- pending | promoted | rejected
    decided_by    TEXT,
    decided_at    TEXT,
    reason        TEXT,
    file          TEXT,
    last_seen_at  INTEGER NOT NULL,
    PRIMARY KEY (node, id)
  );

  -- One row per (node, kind) tracking the "kept versus observed" boundary
  -- for the memory and inbox mirrors, the same rule advisor_ledger_mirror_state
  -- keeps for the ledger: as_of only moves on a poll that reached the node,
  -- last_attempt_at moves on every attempt.
  CREATE TABLE IF NOT EXISTS advisor_notes_mirror_state (
    node            TEXT NOT NULL,
    kind            TEXT NOT NULL,    -- 'memory' | 'inbox'
    as_of           INTEGER,
    last_attempt_at INTEGER,
    last_error      TEXT,
    PRIMARY KEY (node, kind)
  );
`);

// Full-text search over the mirror, ADR 0021 build step 3 (#231 is the
// surface that reads it; nothing does yet). A plain FTS5 table rather than
// an external-content one: rows in advisor_ledger are never updated after
// they are written, so there is no later edit for a sync trigger to catch
// that this file's own insert does not already cover. Its rowid is left to
// SQLite's default, and the search side joins back to advisor_ledger by that
// same hidden rowid, and the two tables are populated together, row for row,
// in mirrorAppendEntries below.
//
// Wrapped: a build of better-sqlite3 without the FTS5 extension must not
// take the whole dashboard down at import over an index nothing has read
// yet (the exact failure the alerts_history.context migration comment above
// warns about, for a different column). Search degrades to answering nothing
// rather than the process refusing to start.
export let advisorLedgerFtsAvailable = true;
try {
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS advisor_ledger_fts USING fts5(
      summary, data, kind, plan_id
    );
  `);
} catch (err) {
  advisorLedgerFtsAvailable = false;
  console.warn(
    '[db] advisor_ledger_fts unavailable (no FTS5 in this sqlite build); fleet Advisor search will read empty:',
    (err as Error).message,
  );
}

// Migrations, add columns to existing tables when the schema evolves.
// SQLite has no IF NOT EXISTS for ALTER TABLE ADD COLUMN, so we probe
// the table_info catalog and only add what's missing.
function ensureColumn(table: string, column: string, def: string): void {
  type Col = { name: string };
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Col[];
  if (cols.some(c => c.name === column)) return;
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`);
  console.log(`[db] migrated: added ${table}.${column}`);
}
ensureColumn('alerts_history', 'delivery', 'TEXT');
// #1019. A note a person retracted on its node. The node still serves it, with
// superseded_by "retracted" and who withdrew it, precisely because this mirror
// never deletes: the retraction has to arrive as a fact on the row, or the
// note stays standing here and can be promoted into every Advisor's corpus.
ensureColumn('advisor_memory_mirror', 'retracted_by', 'TEXT');
ensureColumn('advisor_memory_mirror', 'retracted_at', 'TEXT');
ensureColumn('advisor_memory_mirror', 'retracted_why', 'TEXT');
// What was happening when an alert fired, JSON, written once at the
// transition and never updated. An alert says a number crossed a line; it does
// not say what else was true at that moment, and by the time anyone reads it
// that moment is gone. Missed validations have carried their context since
// they shipped, for exactly this reason; alerts did not.
//
// It must be added HERE, with the other migrations, and not beside the code
// that uses it: every db.prepare() below runs at import, and a statement
// naming a column that does not exist yet takes the whole process down before
// it serves a request. That is not hypothetical, it is how this landed.
ensureColumn('alerts_history', 'context', 'TEXT');

// Which passkey opened this session, not merely which person.
//
// The session already records user_id, which is what puts the operator's name
// in the header. That is the person. An operator can register several passkeys
//, a laptop, a phone, a hardware key kept as recovery, and user_id cannot
// tell them apart. Binding an Advisor approval to the credential that opened
// the session narrows "someone with a registered passkey for this account" to
// "the authenticator in the room", which is the claim an approval to restart a
// validator should actually be making.
//
// Nullable on purpose: sessions minted before this column existed carry NULL.
// They stay valid for reading, and are told to re-authenticate if they try to
// approve, rather than failing somewhere obscure.
ensureColumn('auth_sessions', 'credential_id', 'TEXT');

// The name an operator gave a node BEFORE it ever dialled in (#635). Set only
// when the operator typed one into the "Name this node" field ahead of Mint;
// NULL is the ordinary case, and reads as "let the node propose its own"
// exactly as it always has. Never trusted from the node's own hello -- this
// column is written once, from the mint route, by an already-authenticated
// admin, and nothing on the pairing socket can touch it afterwards.
ensureColumn('fleet_pairing_codes', 'operator_label', 'TEXT');

/**
 * The node name this host's OWN advisord is witnessed under.
 *
 * A sentinel rather than the host's fleet label, deliberately. A label is
 * configuration: it can be renamed, and a rename would orphan every
 * observation taken before it, the witness would see a ledger it had never
 * met, at a count it had, and stay silent about exactly the contradiction it
 * exists to catch. Fleet labels are `[a-z0-9-]{1,32}` (peer-advisor-proxy's
 * LABEL_RE), so the `@` here cannot collide with one.
 */
export const LOCAL_NODE = '@local';

// ledger_witness gains a node column, and this one is NOT an ensureColumn.
//
// The primary key changes from (entry_count) to (node, entry_count), and
// SQLite cannot alter a primary key in place. CREATE TABLE IF NOT EXISTS above
// is a no-op against a database that already has the old table, so without
// this every existing install would keep the single-column key and the first
// fleet observation would collide with a local row at the same count, the
// exact false `rewritten` alarm the column exists to prevent.
//
// Rebuild-and-copy, in a transaction. Existing rows are the LOCAL node's, by
// definition: that is the only ledger this ever witnessed.
(function migrateLedgerWitnessNode(): void {
  type Col = { name: string };
  const cols = db.prepare('PRAGMA table_info(ledger_witness)').all() as Col[];
  if (cols.length === 0 || cols.some(c => c.name === 'node')) return;
  const local = LOCAL_NODE;
  db.exec('BEGIN');
  try {
    db.exec(`
      CREATE TABLE ledger_witness_new (
        node        TEXT    NOT NULL,
        entry_count INTEGER NOT NULL,
        head        TEXT    NOT NULL,
        first_seen  INTEGER NOT NULL,
        PRIMARY KEY (node, entry_count)
      );
    `);
    db.prepare(
      'INSERT INTO ledger_witness_new (node, entry_count, head, first_seen) ' +
      'SELECT ?, entry_count, head, first_seen FROM ledger_witness',
    ).run(local);
    db.exec('DROP TABLE ledger_witness');
    db.exec('ALTER TABLE ledger_witness_new RENAME TO ledger_witness');
    db.exec('COMMIT');
    console.log(`[db] migrated: ledger_witness keyed by (node, entry_count); existing rows are '${local}'`);
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
})();

// A row whose role is neither 'admin' nor 'monitor' (the pre-roles value
// 'operator') stays powerless until someone runs set-role. It must never be
// auto-promoted here: a stale CLI copy elsewhere can still INSERT 'operator'
// rows, and a startup promotion would mint admins out of them on the next
// restart, new accounts get their rights at creation (first account admin,
// the rest monitor) or from an admin's explicit set-role, nowhere else.

// One-time migration: collapse the legacy username + email split into
// email-as-identity. For any existing operator whose username doesn't
// already match their email, copy email into username so future lookups
// (which still go through the username column) find them by their
// email. Idempotent, re-running is a no-op once values match.
(function migrateUsernameToEmail() {
  type Row = { id: number; username: string; email: string | null };
  const rows = db.prepare(
    `SELECT id, username, email FROM auth_users WHERE email IS NOT NULL AND email != '' AND username != email`
  ).all() as Row[];
  if (rows.length === 0) return;
  const update = db.prepare('UPDATE auth_users SET username = ? WHERE id = ?');
  const tx = db.transaction((batch: Row[]) => {
    for (const r of batch) update.run(r.email, r.id);
  });
  tx(rows);
  console.log(`[db] migrated: collapsed ${rows.length} auth_users row(s) to email-as-identity`);
})();

// Add a UNIQUE index on auth_users.email so the email column carries
// the same collision-safety the username column already enforced. The
// `IF NOT EXISTS` makes this safe to re-run.
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email)`);

const insertStmt = db.prepare(
  'INSERT OR REPLACE INTO metrics (ts, metric, value) VALUES (?, ?, ?)'
);

// Observer hook for the rule evaluator. Synchronous so that a metric
// write and the alert lifecycle update are atomic from the caller's
// perspective. Observers should be cheap; the rule evaluator does an
// O(rules-for-metric) scan, typically 1-2 rules per metric.
type MetricObserver = (metric: MetricName, value: number, ts: number) => void;
const metricObservers = new Set<MetricObserver>();
export function addMetricObserver(fn: MetricObserver): void { metricObservers.add(fn); }

/** Write one data point. ts is epoch ms (we store seconds for compactness). */
export function writeMetric(metric: MetricName, value: number, ts: number = Date.now()): void {
  if (!Number.isFinite(value)) return;
  insertStmt.run(Math.floor(ts / 1000), metric, value);
  for (const obs of metricObservers) {
    try { obs(metric, value, ts); } catch (err) { console.warn('[db] metric observer threw:', (err as Error).message); }
  }
}

/** Bucket size in seconds, picked by total range. Returns ~30-120 points per chart. */
// Exported for the read API's history cache (#119): a cache whose TTL is
// derived from the bucket has to read the same bucket the query will use, or
// the two drift the first time a boundary moves.
export function bucketForRange(rangeMs: number): number {
  if (rangeMs <=  1 * 3600_000)  return    30;   // 1h  → 30s buckets, ~120 pts
  if (rangeMs <=  6 * 3600_000)  return   180;   // 6h  → 3min buckets, ~120 pts
  if (rangeMs <= 12 * 3600_000)  return   300;   // 12h → 5min buckets, ~144 pts
  if (rangeMs <= 24 * 3600_000)  return   600;   // 24h → 10min buckets, ~144 pts
  if (rangeMs <=  7 * 86_400_000) return 3600;   // 7d  → 1h buckets, 168 pts
  return 14_400;                                 // 30d → 4h buckets, 180 pts
}

// Modulo-based bucket flooring. Earlier version used `(ts / ?) * ?` but
// better-sqlite3 binds JS numbers as REAL, which made the division a float
// division, multiplying back returned the original ts and no grouping
// happened at all (each row was its own "bucket"). Modulo avoids the type
// issue entirely: ts - (ts % bucketS) cleanly floors to the bucket boundary
// regardless of how the parameter is bound.
// Three pre-prepared aggregations cover the common cases. AVG is the
// historical default and works well for level-style metrics (counts,
// percentages, throughput). MAX surfaces peaks for incident-detection
// metrics (close_time, load_factor) where a single bad sample inside
// a bucket is the signal we care about. MIN is for floors (e.g.
// rx_bps drop detection).
const queryStmtAvg = db.prepare(`
  SELECT (ts - ts % ?) AS bucket_s, AVG(value) AS v
  FROM metrics WHERE metric = ? AND ts >= ?
  GROUP BY bucket_s ORDER BY bucket_s
`);
const queryStmtMax = db.prepare(`
  SELECT (ts - ts % ?) AS bucket_s, MAX(value) AS v
  FROM metrics WHERE metric = ? AND ts >= ?
  GROUP BY bucket_s ORDER BY bucket_s
`);
const queryStmtMin = db.prepare(`
  SELECT (ts - ts % ?) AS bucket_s, MIN(value) AS v
  FROM metrics WHERE metric = ? AND ts >= ?
  GROUP BY bucket_s ORDER BY bucket_s
`);

export interface HistoryPoint { ts: number; value: number; }
export type AggMode = 'avg' | 'max' | 'min';

/** Returns aggregated time-series for a metric over the given range. */
export function queryHistory(metric: MetricName, rangeMs: number, agg: AggMode = 'avg', notBeforeS = 0): HistoryPoint[] {
  // notBeforeS is a lower bound in the SQL, not a filter on the buckets that
  // come back: a bucket that straddles it carries only the rows after it,
  // where a bucket dropped afterwards would carry the rows before it (#1251).
  const fromS = Math.max(Math.floor((Date.now() - rangeMs) / 1000), notBeforeS);
  const bucketS = bucketForRange(rangeMs);
  const stmt = agg === 'max' ? queryStmtMax : agg === 'min' ? queryStmtMin : queryStmtAvg;
  const rows = stmt.all(bucketS, metric, fromS) as Array<{ bucket_s: number; v: number }>;
  return rows.map(r => ({ ts: r.bucket_s * 1000, value: r.v }));
}

// #831: the same three aggregations over a closed-open slice of time, so
// lib/history-cache.ts can fill a long range a bucket-aligned slice at a
// time and yield between slices instead of holding the event loop for the
// whole range.
const rangeStmt = (fn: 'AVG' | 'MAX' | 'MIN') => db.prepare(`
  SELECT (ts - ts % ?) AS bucket_s, ${fn}(value) AS v
  FROM metrics WHERE metric = ? AND ts >= ? AND ts < ?
  GROUP BY bucket_s ORDER BY bucket_s
`);
const rangeStmtAvg = rangeStmt('AVG');
const rangeStmtMax = rangeStmt('MAX');
const rangeStmtMin = rangeStmt('MIN');

/** queryHistory over `fromS <= ts < toS` (Unix seconds) at an explicit bucket
 *  width. Every bucket that lies wholly inside the slice comes out exactly as
 *  queryHistory computes it. */
export function queryHistoryRange(metric: MetricName, fromS: number, toS: number, bucketS: number, agg: AggMode = 'avg'): HistoryPoint[] {
  const stmt = agg === 'max' ? rangeStmtMax : agg === 'min' ? rangeStmtMin : rangeStmtAvg;
  const rows = stmt.all(bucketS, metric, fromS, toS) as Array<{ bucket_s: number; v: number }>;
  return rows.map(r => ({ ts: r.bucket_s * 1000, value: r.v }));
}

const recentStmt = db.prepare(`
  SELECT ts, value FROM metrics
  WHERE metric = ? ORDER BY ts DESC LIMIT ?
`);

/** Returns the last N raw samples for a metric, oldest first. */
export function queryRecent(metric: MetricName, limit: number): HistoryPoint[] {
  const rows = recentStmt.all(metric, limit) as Array<{ ts: number; value: number }>;
  return rows.reverse().map(r => ({ ts: r.ts * 1000, value: r.value }));
}

const peakSinceStmt = db.prepare('SELECT MAX(value) AS v FROM metrics WHERE metric = ? AND ts >= ?');
/** The largest raw sample of a metric at or after `fromS` (epoch seconds), or
 *  null when there is none. */
export function peakMetricSince(metric: MetricName, fromS: number): number | null {
  const r = peakSinceStmt.get(metric, fromS) as { v: number | null } | undefined;
  return r && r.v !== null && Number.isFinite(r.v) ? r.v : null;
}

const loadStoreSeriesStmt = db.prepare('SELECT path, cut_s FROM store_series WHERE id = 1');
const saveStoreSeriesStmt = db.prepare(
  'INSERT INTO store_series (id, path, cut_s) VALUES (1, ?, ?) ' +
  'ON CONFLICT(id) DO UPDATE SET path = excluded.path, cut_s = excluded.cut_s');
/** Which store the nudb_size series describes, or null on a database that
 *  has never recorded one (#1251). */
export function loadStoreSeries(): { path: string; cut_s: number } | null {
  const r = loadStoreSeriesStmt.get() as { path: string; cut_s: number } | undefined;
  return r ?? null;
}
export function saveStoreSeries(path: string, cutS: number): void {
  saveStoreSeriesStmt.run(path, cutS);
}

const pruneStmt = db.prepare('DELETE FROM metrics WHERE ts < ?');
const pruneLedgersStmt = db.prepare('DELETE FROM ledgers WHERE close_ts < ?');
// Agreement rows feed only the 24h rolling window; keep a 2-day buffer (ms).
const pruneAgreementStmt = db.prepare('DELETE FROM agreement WHERE ts < ?');
function prune(): void {
  const cutoffS = Math.floor((Date.now() - RETENTION_MS) / 1000);
  const m = pruneStmt.run(cutoffS);
  // ledgers.close_ts is Ripple-epoch, so the cutoff has to be too. Comparing
  // it against the Unix cutoff above matched every row ever written and wiped
  // the table on every run, at startup and daily, which is why ledger
  // history never survived a restart.
  const l = pruneLedgersStmt.run(cutoffS - RIPPLE_EPOCH_S);
  const a = pruneAgreementStmt.run(Date.now() - 2 * 24 * 60 * 60 * 1000);
  if (m.changes > 0 || l.changes > 0 || a.changes > 0) {
    console.log(`[db] pruned ${m.changes} metric rows, ${l.changes} ledgers older than 30d, ${a.changes} agreement rows older than 2d`);
  }
}
prune();
// Daily, and unref'd: background maintenance must never be the reason a
// process refuses to exit. The server keeps its own listener open so the timer
// still fires there; a test or a one-shot script that imports this module gets
// its schema and its queries without inheriting a 24-hour handle.
setInterval(prune, 24 * 60 * 60 * 1000).unref();

// ─── Per-ledger ticker history ────────────────────────────────────────
// Persisted by the bridge after the family-settlement re-emit so each row
// carries the authoritative txn_count + family breakdown. Ticker on the
// Overview page seeds from this table on page load and pans through it.

export interface LedgerRow {
  ledger_index: number;
  close_ts: number;       // epoch seconds
  close_time: number;     // delta seconds
  txn_count: number;
  fam_money: number;
  fam_market: number;
  fam_nft: number;
  fam_accts: number;
}

const writeLedgerStmt = db.prepare(`
  INSERT OR REPLACE INTO ledgers
    (ledger_index, close_ts, close_time, txn_count, fam_money, fam_market, fam_nft, fam_accts)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

export function writeLedger(r: LedgerRow): void {
  writeLedgerStmt.run(
    r.ledger_index, r.close_ts, r.close_time, r.txn_count,
    r.fam_money, r.fam_market, r.fam_nft, r.fam_accts,
  );
}

const recentLedgersStmt = db.prepare(`
  SELECT ledger_index, close_ts, close_time, txn_count,
         fam_money, fam_market, fam_nft, fam_accts
  FROM ledgers ORDER BY ledger_index DESC LIMIT ?
`);

/** Returns the last N ledger rows, newest first. */
export function queryRecentLedgers(limit: number): LedgerRow[] {
  return recentLedgersStmt.all(limit) as LedgerRow[];
}

// The window centred on a named index, what "was this ledger slow compared
// to its neighbours" reads. Ascending, because a window is read as a
// timeline; the latest-N form stays descending because it is read as news.
// Rows exist only for ledgers the dashboard observed, so a window can
// legitimately come back with holes, the caller reports requested vs
// returned rather than papering over the gap.
const ledgerWindowStmt = db.prepare(`
  SELECT ledger_index, close_ts, close_time, txn_count,
         fam_money, fam_market, fam_nft, fam_accts
  FROM ledgers WHERE ledger_index BETWEEN ? AND ?
  ORDER BY ledger_index ASC LIMIT 61
`);
export function queryLedgerWindow(fromIndex: number, toIndex: number): LedgerRow[] {
  return ledgerWindowStmt.all(fromIndex, toIndex) as LedgerRow[];
}

// ─── Agreement record persistence ─────────────────────────────────────
export interface AgreementRow { ledger_index: number; our_voted: number; ts: number; }
const writeAgreementStmt = db.prepare(
  `INSERT OR REPLACE INTO agreement (ledger_index, our_voted, ts) VALUES (?, ?, ?)`,
);
export function writeAgreement(ledgerIndex: number, ourVoted: boolean, ts: number): void {
  writeAgreementStmt.run(ledgerIndex, ourVoted ? 1 : 0, ts);
}

export interface MissedLedgerRow {
  ledger_index: number; ts: number;
  validations_seen: number | null; trusted_unl: number | null;
  peer_count: number | null; server_state: string | null;
}
const writeMissedLedgerStmt = db.prepare(
  `INSERT OR REPLACE INTO missed_ledgers
     (ledger_index, ts, validations_seen, trusted_unl, peer_count, server_state)
   VALUES (?, ?, ?, ?, ?, ?)`,
);
export function writeMissedLedger(r: MissedLedgerRow): void {
  writeMissedLedgerStmt.run(r.ledger_index, r.ts, r.validations_seen,
    r.trusted_unl, r.peer_count, r.server_state);
}
const missedLedgersStmt = db.prepare(
  `SELECT ledger_index, ts, validations_seen, trusted_unl, peer_count, server_state
   FROM missed_ledgers ORDER BY ledger_index DESC LIMIT ?`,
);
/** Newest first. The table is tiny by design, but the limit keeps it honest. */
export function queryMissedLedgers(limit: number): MissedLedgerRow[] {
  return missedLedgersStmt.all(limit) as MissedLedgerRow[];
}
const agreementSinceStmt = db.prepare(
  `SELECT ledger_index, our_voted, ts FROM agreement WHERE ts >= ? ORDER BY ts ASC`,
);
/** Returns persisted agreement records with ts at or after `sinceMs`, oldest first. */
export function queryAgreementSince(sinceMs: number): AgreementRow[] {
  return agreementSinceStmt.all(sinceMs) as AgreementRow[];
}

// ─── Bandwidth accumulators (fed by the relay's /ingest pushes) ───────
// `bandwidth_monthly` partitions by YYYY-MM so month rollover is automatic,
// a new partition starts accumulating once the UTC month ticks. Old months
// stay on disk (pruning rolls them out after retention, if we want).
// `bandwidth_last_snapshot` persists the most recent cumulative counter
// per node so monthly totals keep accumulating across dashboard restarts.
db.exec(`
  CREATE TABLE IF NOT EXISTS bandwidth_monthly (
    node_label TEXT NOT NULL,
    year_month TEXT NOT NULL,       -- 'YYYY-MM' (UTC)
    rx_bytes   INTEGER NOT NULL,
    tx_bytes   INTEGER NOT NULL,
    updated_ts INTEGER NOT NULL,
    PRIMARY KEY (node_label, year_month)
  );
  CREATE TABLE IF NOT EXISTS bandwidth_last_snapshot (
    node_label TEXT PRIMARY KEY,
    rx_bytes   INTEGER NOT NULL,
    tx_bytes   INTEGER NOT NULL,
    updated_ts INTEGER NOT NULL
  );
`);

const monthlyUpsertStmt = db.prepare(`
  INSERT INTO bandwidth_monthly (node_label, year_month, rx_bytes, tx_bytes, updated_ts)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(node_label, year_month) DO UPDATE SET
    rx_bytes = rx_bytes + excluded.rx_bytes,
    tx_bytes = tx_bytes + excluded.tx_bytes,
    updated_ts = excluded.updated_ts
`);

const monthlyQueryStmt = db.prepare(`
  SELECT rx_bytes, tx_bytes FROM bandwidth_monthly
  WHERE node_label = ? AND year_month = ?
`);

const lastSnapQueryStmt = db.prepare(`
  SELECT rx_bytes, tx_bytes FROM bandwidth_last_snapshot WHERE node_label = ?
`);

const lastSnapUpsertStmt = db.prepare(`
  INSERT INTO bandwidth_last_snapshot (node_label, rx_bytes, tx_bytes, updated_ts)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(node_label) DO UPDATE SET
    rx_bytes = excluded.rx_bytes,
    tx_bytes = excluded.tx_bytes,
    updated_ts = excluded.updated_ts
`);

export function addMonthlyBandwidthDelta(nodeLabel: string, yearMonth: string, dRx: number, dTx: number): void {
  monthlyUpsertStmt.run(nodeLabel, yearMonth, dRx, dTx, Date.now());
}
export function getMonthlyBandwidth(nodeLabel: string, yearMonth: string): { rx_bytes: number; tx_bytes: number } {
  const row = monthlyQueryStmt.get(nodeLabel, yearMonth) as { rx_bytes: number; tx_bytes: number } | undefined;
  return row ?? { rx_bytes: 0, tx_bytes: 0 };
}
export function getLastSnapshot(nodeLabel: string): { rx_bytes: number; tx_bytes: number } | null {
  const row = lastSnapQueryStmt.get(nodeLabel) as { rx_bytes: number; tx_bytes: number } | undefined;
  return row ?? null;
}
export function setLastSnapshot(nodeLabel: string, rx: number, tx: number): void {
  lastSnapUpsertStmt.run(nodeLabel, rx, tx, Date.now());
}

const bandwidthMonthsStmt = db.prepare(`
  SELECT node_label, year_month, rx_bytes, tx_bytes, updated_ts
  FROM bandwidth_monthly ORDER BY year_month DESC, node_label LIMIT ?
`);

/** Recent monthly bandwidth rows, newest month first, the read API's view. */
export function queryBandwidthMonths(limit: number): Array<{
  node_label: string; year_month: string; rx_bytes: number; tx_bytes: number; updated_ts: number;
}> {
  return bandwidthMonthsStmt.all(limit) as Array<{
    node_label: string; year_month: string; rx_bytes: number; tx_bytes: number; updated_ts: number;
  }>;
}

// ─── Insights tab, alert + digest persistence ────────────────────────

export type DeliveryStatus = 'pending' | 'delivered' | string;  // 'failed:<reason>' allowed
export type DeliveryMap = Record<string, DeliveryStatus>;

export interface AlertEvent {
  id?: number;
  ts: number;                    // epoch seconds
  metric: string;
  severity: 'warn' | 'critical' | 'page';
  state: 'firing' | 'resolved';
  value: number | null;
  threshold_op: string | null;
  threshold_value: number | null;
  duration_s: number | null;
  dedup_key: string;
  channels: string[];            // serialized to/from TEXT
  delivery?: DeliveryMap;        // per-channel delivery status, populated post-send
  acked_at?: number | null;
  muted_until?: number | null;
  /** What else was true when this fired. JSON, set once at the transition. */
  context?: string | null;
}

export interface FiringStateRow {
  dedup_key: string;
  metric: string;
  severity: 'warn' | 'critical' | 'page';
  triggered_ts: number;
  fired_ts: number;
  last_value: number | null;
  last_seen_ts: number | null;
  threshold_op: string | null;
  threshold_value: number | null;
  duration_s: number | null;
  channels: string[];
  acked_at: number | null;
  muted_until: number | null;
  last_paged_ts: number | null;
}

export interface DigestRun {
  id?: number;
  ts: number;
  channel: 'email' | 'ntfy' | 'webhook';
  state: 'sent' | 'retried' | 'failed';
  subject: string | null;
  recipient_count: number;
  message_id: string | null;
  retry_count: number;
  error: string | null;
}

const writeAlertEventStmt = db.prepare(`
  INSERT INTO alerts_history
    (ts, metric, severity, state, value, threshold_op, threshold_value,
     duration_s, dedup_key, channels, delivery, acked_at, muted_until, context)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
/** Insert an alert lifecycle event. Returns the new row id so callers
    can attach delivery status as channels resolve their sends. */
export function writeAlertEvent(e: AlertEvent): number {
  const initialDelivery: DeliveryMap = e.delivery ?? Object.fromEntries(e.channels.map(c => [c, 'pending']));
  const result = writeAlertEventStmt.run(
    e.ts, e.metric, e.severity, e.state,
    e.value, e.threshold_op, e.threshold_value,
    e.duration_s, e.dedup_key, JSON.stringify(e.channels),
    JSON.stringify(initialDelivery),
    e.acked_at ?? null, e.muted_until ?? null,
    e.context ?? null,
  );
  return Number(result.lastInsertRowid);
}

const updateAlertDeliveryStmt = db.prepare(`
  UPDATE alerts_history SET delivery = ? WHERE id = ?
`);
const readAlertDeliveryStmt = db.prepare(`
  SELECT delivery FROM alerts_history WHERE id = ?
`);
/** Patch one channel's delivery status on an existing alerts_history row.
    Reads + merges + writes so concurrent updates from multiple channels
    don't clobber each other. */
export function updateAlertDelivery(eventId: number, channelId: string, status: DeliveryStatus): void {
  const row = readAlertDeliveryStmt.get(eventId) as { delivery: string | null } | undefined;
  if (!row) return;
  const map: DeliveryMap = row.delivery ? JSON.parse(row.delivery) : {};
  map[channelId] = status;
  updateAlertDeliveryStmt.run(JSON.stringify(map), eventId);
}

const queryAlertHistoryStmt = db.prepare(`
  SELECT id, ts, metric, severity, state, value, threshold_op, threshold_value,
         duration_s, dedup_key, channels, delivery, acked_at, muted_until, context
  FROM alerts_history
  WHERE ts >= ?
  ORDER BY ts DESC
  LIMIT ?
`);
export function queryAlertHistory(sinceMs: number, limit = 200): AlertEvent[] {
  const fromS = Math.floor(sinceMs / 1000);
  const rows = queryAlertHistoryStmt.all(fromS, limit) as Array<{
    id: number; ts: number; metric: string; severity: string; state: string;
    value: number | null; threshold_op: string | null; threshold_value: number | null;
    duration_s: number | null; dedup_key: string; channels: string; delivery: string | null;
    acked_at: number | null; muted_until: number | null; context: string | null;
  }>;
  return rows.map(r => ({
    id: r.id,
    ts: r.ts * 1000,
    metric: r.metric,
    severity: r.severity as AlertEvent['severity'],
    state: r.state as AlertEvent['state'],
    value: r.value,
    threshold_op: r.threshold_op,
    threshold_value: r.threshold_value,
    duration_s: r.duration_s,
    dedup_key: r.dedup_key,
    channels: r.channels ? JSON.parse(r.channels) : [],
    delivery: r.delivery ? JSON.parse(r.delivery) : {},
    acked_at: r.acked_at,
    muted_until: r.muted_until,
    context: r.context,
  }));
}

const upsertFiringStateStmt = db.prepare(`
  INSERT INTO firing_state
    (dedup_key, metric, severity, triggered_ts, fired_ts, last_value, last_seen_ts,
     threshold_op, threshold_value, duration_s, channels, acked_at, muted_until, last_paged_ts)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(dedup_key) DO UPDATE SET
    last_value = excluded.last_value,
    last_seen_ts = excluded.last_seen_ts,
    acked_at = excluded.acked_at,
    muted_until = excluded.muted_until,
    last_paged_ts = excluded.last_paged_ts
`);
export function upsertFiringState(s: FiringStateRow): void {
  upsertFiringStateStmt.run(
    s.dedup_key, s.metric, s.severity, s.triggered_ts, s.fired_ts,
    s.last_value, s.last_seen_ts, s.threshold_op, s.threshold_value, s.duration_s,
    JSON.stringify(s.channels), s.acked_at, s.muted_until, s.last_paged_ts,
  );
}

const clearFiringStateStmt = db.prepare('DELETE FROM firing_state WHERE dedup_key = ?');
export function clearFiringState(dedupKey: string): void {
  clearFiringStateStmt.run(dedupKey);
}

const queryFiringStateStmt = db.prepare(`
  SELECT dedup_key, metric, severity, triggered_ts, fired_ts, last_value, last_seen_ts,
         threshold_op, threshold_value, duration_s, channels, acked_at, muted_until, last_paged_ts
  FROM firing_state
  ORDER BY fired_ts DESC
`);
export function queryFiringState(): FiringStateRow[] {
  const rows = queryFiringStateStmt.all() as Array<{
    dedup_key: string; metric: string; severity: string; triggered_ts: number; fired_ts: number;
    last_value: number | null; last_seen_ts: number | null;
    threshold_op: string | null; threshold_value: number | null; duration_s: number | null;
    channels: string; acked_at: number | null; muted_until: number | null; last_paged_ts: number | null;
  }>;
  return rows.map(r => ({
    dedup_key: r.dedup_key,
    metric: r.metric,
    severity: r.severity as FiringStateRow['severity'],
    triggered_ts: r.triggered_ts,
    fired_ts: r.fired_ts,
    last_value: r.last_value,
    last_seen_ts: r.last_seen_ts,
    threshold_op: r.threshold_op,
    threshold_value: r.threshold_value,
    duration_s: r.duration_s,
    channels: r.channels ? JSON.parse(r.channels) : [],
    acked_at: r.acked_at,
    muted_until: r.muted_until,
    last_paged_ts: r.last_paged_ts,
  }));
}

const writeDigestRunStmt = db.prepare(`
  INSERT INTO digest_runs (ts, channel, state, subject, recipient_count, message_id, retry_count, error)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
export function writeDigestRun(d: DigestRun): void {
  writeDigestRunStmt.run(
    d.ts, d.channel, d.state, d.subject, d.recipient_count,
    d.message_id, d.retry_count, d.error,
  );
}

const queryDigestRunsStmt = db.prepare(`
  SELECT id, ts, channel, state, subject, recipient_count, message_id, retry_count, error
  FROM digest_runs WHERE ts >= ? ORDER BY ts DESC LIMIT ?
`);
export function queryDigestRuns(sinceMs: number, limit = 50): DigestRun[] {
  const fromS = Math.floor(sinceMs / 1000);
  const rows = queryDigestRunsStmt.all(fromS, limit) as Array<{
    id: number; ts: number; channel: string; state: string; subject: string | null;
    recipient_count: number; message_id: string | null; retry_count: number; error: string | null;
  }>;
  return rows.map(r => ({
    id: r.id,
    ts: r.ts * 1000,
    channel: r.channel as DigestRun['channel'],
    state: r.state as DigestRun['state'],
    subject: r.subject,
    recipient_count: r.recipient_count,
    message_id: r.message_id,
    retry_count: r.retry_count,
    error: r.error,
  }));
}

export { db };


// ─── Advisor ledger witness ───────────────────────────────────────────
export interface LedgerWitnessVerdict {
  ok: boolean;
  kind?: 'truncated' | 'rewritten';
  detail?: string;
}
const witnessAtStmt = db.prepare('SELECT head FROM ledger_witness WHERE node = ? AND entry_count = ?');
const witnessMaxStmt = db.prepare('SELECT MAX(entry_count) AS n FROM ledger_witness WHERE node = ?');
const witnessPutStmt = db.prepare(
  'INSERT OR IGNORE INTO ledger_witness (node, entry_count, head, first_seen) VALUES (?, ?, ?, ?)',
);
const alarmPutStmt = db.prepare(
  'INSERT INTO ledger_alarms (at, kind, detail) VALUES (?, ?, ?)',
);
const alarmsStmt = db.prepare(
  'SELECT id, at, kind, detail FROM ledger_alarms ORDER BY id DESC LIMIT ?',
);

/**
 * Record one observation of the Advisor's ledger and report whether it
 * contradicts anything already seen.
 *
 * Two contradictions matter. A count lower than one already witnessed means
 * entries were removed. A different head at a count already witnessed means
 * the chain was rebuilt. Neither is visible from inside the ledger file.
 *
 * Scoped to one node. Every comparison here, the head at a count, and the
 * highest count seen, is per node, because two nodes' ledgers are unrelated
 * files that happen to be counted the same way. Comparing across them
 * manufactures contradictions out of nothing.
 */
export function witnessLedger(
  count: number,
  head: string,
  ts = Math.floor(Date.now() / 1000),
  node: string = LOCAL_NODE,
): LedgerWitnessVerdict {
  if (!Number.isFinite(count) || count < 0 || !head || !node) return { ok: true };
  const seen = witnessAtStmt.get(node, count) as { head: string } | undefined;
  if (seen && seen.head !== head) {
    const detail = `${node}: at ${count} entries the ledger head was ${seen.head.slice(0, 16)}…, now ${head.slice(0, 16)}…`;
    alarmPutStmt.run(ts, 'rewritten', detail);
    return { ok: false, kind: 'rewritten', detail };
  }
  const max = (witnessMaxStmt.get(node) as { n: number | null }).n ?? 0;
  if (count < max) {
    const detail = `${node}: the ledger held ${max} entries and now holds ${count}`;
    alarmPutStmt.run(ts, 'truncated', detail);
    return { ok: false, kind: 'truncated', detail };
  }
  if (!seen) witnessPutStmt.run(node, count, head, ts);
  return { ok: true };
}

export function queryLedgerAlarms(limit = 20): Array<{ id: number; at: number; kind: string; detail: string }> {
  return alarmsStmt.all(limit) as Array<{ id: number; at: number; kind: string; detail: string }>;
}

export function highestWitnessed(node: string = LOCAL_NODE): { entry_count: number; head: string; first_seen: number } | null {
  return (db.prepare(
    'SELECT entry_count, head, first_seen FROM ledger_witness WHERE node = ? ORDER BY entry_count DESC LIMIT 1',
  ).get(node) as { entry_count: number; head: string; first_seen: number } | undefined) ?? null;
}

/** The witnessed head at one exact entry count, or null when this node was
 *  never independently observed at that count. Read by the fleet Advisor
 *  ledger mirror (ADR 0021 build step 3), which verifies each newly synced
 *  entry against the witness where one exists, on top of the linkage
 *  against its own previously mirrored hash: two entries can chain onto
 *  each other perfectly and still both be a rewrite of a chain the witness
 *  saw differently before this mirror ever synced. Only ledger_witness rows
 *  for LOCAL_NODE exist today (witnessAdvisorLedger only reads this host's
 *  own advisord), so this answers null for every peer until fleet
 *  witnessing exists, which is the "where one exists" the mirror honours
 *  rather than assumes. */
export function witnessHeadAt(node: string, count: number): string | null {
  const row = witnessAtStmt.get(node, count) as { head: string } | undefined;
  return row ? row.head : null;
}

// ─── Advisor presence, ADR 0016 ───────────────────────────────────────
//
// Two functions and one unit conversion. The table stores epoch SECONDS, like
// ledger_witness; every caller above this line works in milliseconds. These
// two functions are the only place the two meet, which is the whole reason
// they exist rather than the callers holding a prepared statement each.

const advisorAnsweredPutStmt = db.prepare(
  'INSERT INTO advisor_presence (node, first_seen, last_answered) VALUES (?, ?, ?) ' +
  // first_seen is never overwritten: it is when an Advisor was FIRST seen on
  // this host, and a second answer is not a new install.
  'ON CONFLICT(node) DO UPDATE SET last_answered = excluded.last_answered',
);
const advisorAnsweredGetStmt = db.prepare(
  'SELECT last_answered FROM advisor_presence WHERE node = ?',
);

/** Record that an Advisor answered on this host, at `atMs`. Called only on a
 *  200 from /v1/status, never on a probe that failed and never on a probe
 *  that was skipped. */
export function recordAdvisorAnswered(atMs: number, node: string = LOCAL_NODE): void {
  const secs = Math.floor(atMs / 1000);
  advisorAnsweredPutStmt.run(node, secs, secs);
}

/** Epoch ms of the last answer, or null if one has never been seen here.
 *  Null is the honest "never observed" and is what makes `absent` reachable —
 *  it must never be coerced to 0, which would read as 1970 and put every
 *  fresh install permanently past the grace window. */
export function lastAdvisorAnsweredMs(node: string = LOCAL_NODE): number | null {
  const row = advisorAnsweredGetStmt.get(node) as { last_answered: number } | undefined;
  return row ? row.last_answered * 1000 : null;
}

// ─── The auth audit ───────────────────────────────────────────────────
//
// See the auth_events table comment for why this exists. The rule for callers
// is short: record the DECISION at the moment it is made, name the person who
// made it, and never put key material or a token in `detail`.

export type AuthEventKind =
  | 'role_change'
  | 'credential_enrolled'
  | 'credential_removed'
  | 'magic_link_issued'
  | 'trust_synced'
  // #135 Step 1. The browser creating the first administrator, which is the
  // one privileged write this product accepts without a signed-in operator.
  // It happens at most once per box, and it decides who owns it.
  | 'first_admin_created'
  // #135. The other way that window shuts: this dashboard observing that the
  // box already has an operator it did not create, which is every box claimed
  // with `aperire-auth add` and every box that was owned before this row
  // existed. Written once, and then it is the record that keeps the window
  // shut through a DELETE of every operator row. See lib/bootstrap-window.ts
  // for why the record lives in this table and not beside the operators.
  | 'setup_window_closed'
  // A key handed to the one root program the dashboard can reach. Recorded on
  // every attempt, including the refusals: a failed seal used to leave no
  // trace on this side at all, so the only record of it was a journal on the
  // host, which is a bad place to have to go looking first.
  | 'model_key_sealed'
  // #216. An account created or deleted from the Settings page. The CLI
  // records a deletion as a credential_removed with a reason, which reads as
  // a passkey being taken away rather than as an operator ceasing to exist,
  // and there was no event at all for the creation. Both are decisions about
  // who may reach this box, so both get their own name.
  | 'operator_added'
  | 'operator_removed'
  // #62, ADR 0022 phase 2. An apply, a restart into it, or a rollback: the
  // three acts that change what code this host runs. One kind rather than
  // three, with the act in the detail, because a refused rollback and a
  // refused apply are the same class of fact and the record is read by
  // searching it.
  | 'update_run'
  // ADR 0019 decision 2. A request the aggregator sent down the fleet link
  // that this node's allow-list refused. On a node, never on an aggregator.
  // The row names the route and the reason, and carries a COUNT: refusals
  // are coalesced per window before they get here, because an aggregator
  // that can drive one per frame would otherwise be a write amplifier
  // pointed at this table.
  | 'fleet_link_refused'
  // ADR 0019 phase 3. The pairing lifecycle, on the aggregator: a code
  // minted, a code presented, a node approved into the fleet, a pending row
  // refused. One kind with the act in the detail, the `update_run` shape, so
  // the whole join of one node reads as one search. The code itself is never
  // in a row: what identifies the act is the label and the node key.
  | 'fleet_pairing'
  // #1094. A logout could not cancel this operator's unspent approvals on one
  // Advisor (a linked node's, or this host's own): unreachable, refused, or no
  // token readable here. The approval may stay live there until it expires, and
  // any administrator session can spend it, so the failure is a record, named
  // by node, and not only a line in the server log.
  | 'logout_cancel_failed';

const authEventPutStmt = db.prepare(
  'INSERT INTO auth_events (at, actor, actor_role, event, target, detail) VALUES (?, ?, ?, ?, ?, ?)',
);

export function recordAuthEvent(e: {
  actor: string;
  actorRole?: string | null;
  event: AuthEventKind;
  target?: string | null;
  detail?: Record<string, unknown> | null;
  at?: number;
}): void {
  authEventPutStmt.run(
    e.at ?? Math.floor(Date.now() / 1000),
    e.actor,
    e.actorRole ?? null,
    e.event,
    e.target ?? null,
    e.detail ? JSON.stringify(e.detail) : null,
  );
}

export function queryAuthEvents(limit = 100): Array<{
  id: number; at: number; actor: string; actor_role: string | null;
  event: string; target: string | null; detail: string | null;
}> {
  return db.prepare(
    'SELECT id, at, actor, actor_role, event, target, detail FROM auth_events ORDER BY id DESC LIMIT ?',
  ).all(limit) as Array<{
    id: number; at: number; actor: string; actor_role: string | null;
    event: string; target: string | null; detail: string | null;
  }>;
}

// ─── Advisor ledger mirror, ADR 0021 build step 3 ──────────────────────
//
// Everything below is data access only. What decides WHEN to poll a node,
// how to tell a reinstall from a rewrite, and what a re-verify compares is
// lib/advisor-ledger-mirror.ts. This file only ever stores what that
// module hands it and answers what it asks back.

/** One mirrored ledger entry, shaped exactly like advisor/internal/ledger's
 *  Entry (seq, at, kind, plan_id, summary, data, prev_hash, hash), the
 *  wire shape the node's /v1/ledger already answers, so nothing here
 *  reshapes it on the way in. */
export interface AdvisorMirrorEntry {
  seq: number;
  at: string;
  kind: string;
  plan_id: string | null;
  summary: string;
  data: string;   // JSON text
  prev_hash: string;
  hash: string;
  verified_at: number;
}

export interface AdvisorMirrorState {
  node: string;
  run: string | null;
  last_seq: number;
  last_hash: string | null;
  as_of: number | null;
  last_attempt_at: number | null;
  last_error: string | null;
  broken: boolean;
  break_seq: number | null;
  break_expected: string | null;
  break_got: string | null;
}

type MirrorStateRow = Omit<AdvisorMirrorState, 'broken'> & { broken: number };

function nowS(): number { return Math.floor(Date.now() / 1000); }

const mirrorStateGetStmt = db.prepare(
  'SELECT node, run, last_seq, last_hash, as_of, last_attempt_at, last_error, ' +
  'broken, break_seq, break_expected, break_got FROM advisor_ledger_mirror_state WHERE node = ?',
);
function rowToState(row: MirrorStateRow): AdvisorMirrorState {
  return { ...row, broken: row.broken === 1 };
}

/** The mirror's own record of one node's position, or null before this node
 *  has ever been polled once. */
export function mirrorState(node: string): AdvisorMirrorState | null {
  const row = mirrorStateGetStmt.get(node) as MirrorStateRow | undefined;
  return row ? rowToState(row) : null;
}

const mirrorStateEnsureStmt = db.prepare(
  'INSERT OR IGNORE INTO advisor_ledger_mirror_state (node, last_seq) VALUES (?, 0)',
);
const mirrorAttemptOkStmt = db.prepare(
  'UPDATE advisor_ledger_mirror_state SET as_of = ?, last_attempt_at = ?, last_error = NULL WHERE node = ?',
);
const mirrorAttemptFailStmt = db.prepare(
  'UPDATE advisor_ledger_mirror_state SET last_attempt_at = ?, last_error = ? WHERE node = ?',
);

/**
 * Record one poll attempt against `node`. `as_of` (the "kept versus
 * observed" timestamp) only ever moves on `ok`. `last_attempt_at` moves on
 * every call, so a node that has gone quiet can say since when rather than
 * freeze on the age of its last good reading. Never touches `broken`: only
 * mirrorMarkBreak sets it and only mirrorClearBreak clears it.
 */
export function mirrorRecordAttempt(node: string, ok: boolean, detail: string | null, ts = nowS()): void {
  mirrorStateEnsureStmt.run(node);
  if (ok) {
    mirrorAttemptOkStmt.run(ts, ts, node);
  } else {
    mirrorAttemptFailStmt.run(ts, detail, node);
  }
}

const mirrorInsertRowStmt = db.prepare(
  'INSERT INTO advisor_ledger (node, run, seq, at, kind, plan_id, summary, data, prev_hash, hash, verified_at) ' +
  'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
);
const mirrorInsertFtsStmt = db.prepare(
  'INSERT INTO advisor_ledger_fts (rowid, summary, data, kind, plan_id) VALUES (?, ?, ?, ?, ?)',
);

/** One entry as read off a node's /v1/ledger, the shape mirrorAppendEntries
 *  accepts, never the stored row shape, which carries verified_at and a
 *  serialised `data`. */
export interface LedgerEntryIn {
  seq: number;
  at: string;
  kind: string;
  plan_id?: string | null;
  summary: string;
  data?: unknown;
  prev_hash: string;
  hash: string;
}

const mirrorAppendStateStmt = db.prepare(
  'UPDATE advisor_ledger_mirror_state SET run = ?, last_seq = ?, last_hash = ?, ' +
  'as_of = ?, last_attempt_at = ?, last_error = NULL WHERE node = ?',
);

/**
 * Append entries this dashboard has just verified belong to `run` on `node`,
 * in order, and record that the poll succeeded. Never called with entries
 * this mirror has not already decided chain cleanly onto what it holds:
 * that decision is lib/advisor-ledger-mirror.ts's, this only writes it down.
 *
 * Advances the state row's run/last_seq/last_hash to the tail of what was
 * just appended, so the next poll asks for since_seq at exactly that point.
 */
export function mirrorAppendEntries(node: string, run: string, entries: LedgerEntryIn[], ts = nowS()): void {
  if (entries.length === 0) { mirrorRecordAttempt(node, true, null, ts); return; }
  mirrorStateEnsureStmt.run(node);
  const insert = db.transaction((rows: LedgerEntryIn[]) => {
    let lastHash = '';
    for (const e of rows) {
      const dataText = JSON.stringify(e.data ?? {});
      const info = mirrorInsertRowStmt.run(
        node, run, e.seq, e.at, e.kind, e.plan_id ?? null, e.summary, dataText, e.prev_hash, e.hash, ts,
      );
      if (advisorLedgerFtsAvailable) {
        mirrorInsertFtsStmt.run(info.lastInsertRowid, e.summary, dataText, e.kind, e.plan_id ?? null);
      }
      lastHash = e.hash;
    }
    return lastHash;
  });
  const lastHash = insert(entries);
  mirrorAppendStateStmt.run(run, entries[entries.length - 1].seq, lastHash, ts, ts, node);
}

const mirrorRowAtStmt = db.prepare(
  'SELECT seq, at, kind, plan_id, summary, data, prev_hash, hash, verified_at FROM advisor_ledger ' +
  'WHERE node = ? AND run = ? AND seq = ?',
);

/** The mirrored row at one exact position, or null when this mirror has
 *  never held a row there, which is not a mismatch, only a gap this mirror
 *  has not read yet. */
export function mirrorRowAt(node: string, run: string, seq: number): AdvisorMirrorEntry | null {
  return (mirrorRowAtStmt.get(node, run, seq) as AdvisorMirrorEntry | undefined) ?? null;
}

const mirrorRunsStmt = db.prepare(
  'SELECT run FROM advisor_ledger WHERE node = ? GROUP BY run ORDER BY MIN(verified_at)',
);

/** Every run this mirror has ever held rows for, oldest genesis first.
 *  Never fewer than one once a node has synced at all, and more than one is
 *  exactly the "two runs, never merged" outcome of a reinstall. */
export function mirrorRunsForNode(node: string): string[] {
  return (mirrorRunsStmt.all(node) as Array<{ run: string }>).map(r => r.run);
}

const mirrorRowCountStmt = db.prepare('SELECT COUNT(*) AS n FROM advisor_ledger WHERE node = ? AND run = ?');

export function mirrorRowCount(node: string, run: string): number {
  return (mirrorRowCountStmt.get(node, run) as { n: number }).n;
}

const mirrorBreakStmt = db.prepare(
  'UPDATE advisor_ledger_mirror_state SET broken = 1, break_seq = ?, break_expected = ?, break_got = ?, ' +
  'last_attempt_at = ?, last_error = ? WHERE node = ?',
);
const alarmInsertStmt = db.prepare('INSERT INTO ledger_alarms (at, kind, detail) VALUES (?, ?, ?)');

/**
 * A chain break: the node's own account of a position this mirror already
 * held no longer agrees with it. Stops the poller from touching this node
 * again (mirrorState(node).broken) until mirrorClearBreak runs, which only
 * a re-verify does. Also kept in ledger_alarms, the one table this
 * dashboard already reads as "contradictions, kept": a fleet mirror break
 * is the same class of fact as a local rewrite, just with a node named in
 * the sentence instead of assumed to be this host's own.
 */
export function mirrorMarkBreak(node: string, seq: number, expected: string, got: string, ts = nowS()): void {
  mirrorStateEnsureStmt.run(node);
  mirrorBreakStmt.run(
    seq, expected, got, ts,
    `chain break at entry ${seq}: mirror held ${expected.slice(0, 16)}…, node now reports ${got.slice(0, 16)}…`,
    node,
  );
  alarmInsertStmt.run(
    ts, 'rewritten',
    `${node}: mirror entry ${seq} was ${expected.slice(0, 16)}…, the node now reports ${got.slice(0, 16)}…`,
  );
}

const mirrorClearBreakStmt = db.prepare(
  'UPDATE advisor_ledger_mirror_state SET broken = 0, break_seq = NULL, break_expected = NULL, break_got = NULL ' +
  'WHERE node = ?',
);

/** Lifts the stop a break placed on `node`. Only mirrorMarkBreak sets what
 *  this clears: nothing else may resume a node's polling once it has
 *  stopped, which is the durable half of "until an operator re-verify". */
export function mirrorClearBreak(node: string): void {
  mirrorClearBreakStmt.run(node);
}

export interface MirrorSummaryRow {
  node: string;
  run: string | null;
  count: number;
  head: string | null;
  as_of: number | null;
  last_attempt_at: number | null;
  last_error: string | null;
  broken: boolean;
  break_seq: number | null;
  break_expected: string | null;
  break_got: string | null;
}

/** One row per node this dashboard has ever polled, for the read route
 *  #231 will build on. `count`/`head` come from the state row's own
 *  last_seq/last_hash rather than a fresh COUNT(*), because entries are
 *  appended in order with no gaps within a run, so the two agree; a test
 *  that wants the raw row count reads advisor_ledger directly, as
 *  mirrorRowCount does. */
export function mirrorSummary(): MirrorSummaryRow[] {
  const rows = db.prepare(
    'SELECT node, run, last_seq, last_hash, as_of, last_attempt_at, last_error, ' +
    'broken, break_seq, break_expected, break_got FROM advisor_ledger_mirror_state ORDER BY node',
  ).all() as MirrorStateRow[];
  return rows.map(r => ({
    node: r.node, run: r.run, count: r.last_seq, head: r.last_hash,
    as_of: r.as_of, last_attempt_at: r.last_attempt_at, last_error: r.last_error,
    broken: r.broken === 1, break_seq: r.break_seq, break_expected: r.break_expected, break_got: r.break_got,
  }));
}

export interface MirrorSearchHit {
  node: string;
  run: string;
  seq: number;
  at: string;
  kind: string;
  plan_id: string | null;
  summary: string;
}

/** A fleet-wide full-text search over the mirror, #231's read. Empty
 *  (never an error) when this build's sqlite has no FTS5, or when the
 *  query matches nothing.
 *
 * The operator's text is always sent to FTS5 as one quoted phrase, never as
 * bare words. FTS5's query grammar, not its tokenizer, is what an unquoted
 * "ops@example.org" fails on ("syntax error near \"@\""): a bareword may
 * only hold characters the grammar accepts outside a string, and an email
 * address, a hyphenated flag or a plan id are exactly the operator inputs
 * this search exists to find. Quoting turns every one of those into a
 * literal phrase match instead of parsed query syntax, which is also the
 * more useful default for a first cut with no query language exposed in
 * any UI (#231): searching for text finds that text. */
export function mirrorSearch(query: string, opts: { node?: string; limit?: number } = {}): MirrorSearchHit[] {
  if (!advisorLedgerFtsAvailable || !query.trim()) return [];
  // Number.isFinite before the clamp: an unparsed query param (?limit=foo)
  // arrives as NaN, and better-sqlite3 refuses to bind NaN as an integer
  // parameter ("datatype mismatch") rather than coercing it. This route's
  // one caller-supplied number gets sanitised here so a malformed limit
  // reads as the default rather than 500ing the read.
  const rawLimit = opts.limit;
  const limit = Math.min(Math.max(Number.isFinite(rawLimit) ? (rawLimit as number) : 50, 1), 500);
  const phrase = `"${query.trim().replace(/"/g, '""')}"`;
  const params: unknown[] = [phrase];
  let nodeFilter = '';
  if (opts.node) { nodeFilter = 'AND l.node = ?'; params.push(opts.node); }
  params.push(limit);
  try {
    // MATCH against the virtual table's own name, not its join alias `f`:
    // `f MATCH ?` inside this JOIN raises "no such column: f" on this
    // better-sqlite3 build, where `advisor_ledger_fts MATCH ?` does not.
    // The alias shorthand SQLite documents for a bare fts5 table does not
    // extend to one side of a join.
    return db.prepare(
      `SELECT l.node AS node, l.run AS run, l.seq AS seq, l.at AS at, l.kind AS kind, l.plan_id AS plan_id, l.summary AS summary
       FROM advisor_ledger_fts f
       JOIN advisor_ledger l ON l.rowid = f.rowid
       WHERE advisor_ledger_fts MATCH ? ${nodeFilter}
       ORDER BY l.verified_at DESC LIMIT ?`,
    ).all(...params) as MirrorSearchHit[];
  } catch {
    // FTS5's MATCH syntax rejects some plain text an operator might type
    // (an unbalanced quote, a bare "-"). A search that cannot parse its own
    // query answers nothing rather than 500ing a read route.
    return [];
  }
}

// ── The memory and inbox mirrors, ADR 0021 build step 5 ─────────────────
//
// Simpler than the ledger mirror above on purpose: neither source carries a
// hash chain, so there is nothing here to verify against a witness or a
// prior run, only to record. lib/advisor-notes-mirror.ts decides WHEN to
// poll and what a fetch answered; every function below only ever upserts
// what it is handed, by (node, id), and never deletes a row this mirror has
// already kept.

function notesMirrorNow(): number { return Math.floor(Date.now() / 1000); }

export interface NotesMirrorState {
  node: string;
  kind: 'memory' | 'inbox';
  as_of: number | null;
  last_attempt_at: number | null;
  last_error: string | null;
}

const notesMirrorStateEnsureStmt = db.prepare(
  'INSERT OR IGNORE INTO advisor_notes_mirror_state (node, kind) VALUES (?, ?)',
);
const notesMirrorStateGetStmt = db.prepare(
  'SELECT node, kind, as_of, last_attempt_at, last_error FROM advisor_notes_mirror_state WHERE node = ? AND kind = ?',
);
const notesMirrorAttemptOkStmt = db.prepare(
  'UPDATE advisor_notes_mirror_state SET as_of = ?, last_attempt_at = ?, last_error = NULL WHERE node = ? AND kind = ?',
);
const notesMirrorAttemptFailStmt = db.prepare(
  'UPDATE advisor_notes_mirror_state SET last_attempt_at = ?, last_error = ? WHERE node = ? AND kind = ?',
);

/** This mirror's own record of one node's last poll for `kind`, or null
 *  before that (node, kind) pair has ever been attempted. */
export function notesMirrorState(node: string, kind: 'memory' | 'inbox'): NotesMirrorState | null {
  return (notesMirrorStateGetStmt.get(node, kind) as NotesMirrorState | undefined) ?? null;
}

const notesMirrorStateAllStmt = db.prepare(
  'SELECT node, kind, as_of, last_attempt_at, last_error FROM advisor_notes_mirror_state WHERE kind = ? ORDER BY node',
);

/**
 * Every node's poll state for one `kind`, the fleet-wide version of
 * `notesMirrorState` above. Issue #232's memory list needs this and
 * `inboxMirrorSummary` (which already carries the same two facts for
 * `kind = 'inbox'`) does not need it duplicated: `as_of` only moves on a
 * poll that reached the node, `last_error` is set on a poll that did not,
 * and a row this mirror has never attempted is simply absent, the same
 * "kept versus observed" rule the ledger mirror holds to. A memory entry's
 * own `last_seen_at` is not a substitute for this: it is the last poll
 * that still SAW that particular row, which conflates a row the node's
 * file dropped with a poll that failed outright, exactly the confusion
 * this table exists to keep apart.
 */
export function notesMirrorStateAll(kind: 'memory' | 'inbox'): NotesMirrorState[] {
  return notesMirrorStateAllStmt.all(kind) as NotesMirrorState[];
}

/**
 * Records one poll attempt for (node, kind). `as_of` only moves on `ok`,
 * the same kept-versus-observed rule mirrorRecordAttempt already keeps for
 * the ledger. Never called for a target the poller has already decided is
 * absent (no Advisor to ask at all): see AdvisorNotesMirror's own doc
 * comment for why an absent Advisor leaves no state row rather than a pile
 * of identical failed attempts.
 */
export function notesMirrorRecordAttempt(
  node: string, kind: 'memory' | 'inbox', ok: boolean, detail: string | null, ts = notesMirrorNow(),
): void {
  notesMirrorStateEnsureStmt.run(node, kind);
  if (ok) notesMirrorAttemptOkStmt.run(ts, ts, node, kind);
  else notesMirrorAttemptFailStmt.run(ts, detail, node, kind);
}

/** One memory entry as a node's /v1/memory answers it. */
export interface MemoryMirrorEntryIn {
  id: string;
  at: string;
  kind: string;
  title: string;
  body: string;
  node?: string;
  tags?: string[];
  source?: string;
  confirmed_by?: string;
  confirmed_at?: string;
  superseded_by?: string;
  /** Set by a node on a note a person withdrew (#1012, #1019). */
  retracted?: boolean;
  retracted_by?: string;
  retracted_at?: string;
  retracted_why?: string;
}

/** The Superseded value a node gives a note a person withdrew; the same word
 *  advisor/internal/memory uses (memory.Retracted). */
export const MEMORY_RETRACTED = 'retracted';

export interface MemoryMirrorRow {
  node: string;
  id: string;
  at: string;
  kind: string;
  title: string;
  body: string;
  tags: string; // JSON array text, as stored
  source: string | null;
  confirmed_by: string | null;
  confirmed_at: string | null;
  superseded_by: string | null;
  last_seen_at: number;
  promoted_at: number | null;
  promoted_by: string | null;
  promoted_file: string | null;
  /** Who withdrew the note on its node, when, and why (#1019). Null on a note
   *  nobody retracted. */
  retracted_by: string | null;
  retracted_at: string | null;
  retracted_why: string | null;
}

/** True for a note its node says a person retracted. Read off superseded_by,
 *  the field every node build that can retract already sends. */
export function memoryRowRetracted(row: { superseded_by: string | null }): boolean {
  return row.superseded_by === MEMORY_RETRACTED;
}

const memoryMirrorUpsertStmt = db.prepare(`
  INSERT INTO advisor_memory_mirror
    (node, id, at, kind, title, body, tags, source, confirmed_by, confirmed_at, superseded_by,
     retracted_by, retracted_at, retracted_why, last_seen_at)
  VALUES (@node, @id, @at, @kind, @title, @body, @tags, @source, @confirmed_by, @confirmed_at, @superseded_by,
     @retracted_by, @retracted_at, @retracted_why, @last_seen_at)
  ON CONFLICT (node, id) DO UPDATE SET
    at = excluded.at, kind = excluded.kind, title = excluded.title, body = excluded.body,
    tags = excluded.tags, source = excluded.source, confirmed_by = excluded.confirmed_by,
    confirmed_at = excluded.confirmed_at, superseded_by = excluded.superseded_by,
    retracted_by = excluded.retracted_by, retracted_at = excluded.retracted_at,
    retracted_why = excluded.retracted_why,
    last_seen_at = excluded.last_seen_at
`);

/**
 * Upserts every entry a full /v1/memory read answered, by (node, id), and
 * records the poll as a success. Never deletes: an entry this mirror
 * already holds that a later read no longer mentions (a node wiped, an
 * Advisor reinstalled with a fresh state/) stays exactly where it is,
 * the mirror's job is to keep what it was shown, not to agree with the
 * node's CURRENT file about what still exists.
 */
export function memoryMirrorUpsert(node: string, entries: MemoryMirrorEntryIn[], ts = notesMirrorNow()): void {
  const upsert = db.transaction((rows: MemoryMirrorEntryIn[]) => {
    for (const e of rows) {
      memoryMirrorUpsertStmt.run({
        node, id: e.id, at: e.at, kind: e.kind, title: e.title, body: e.body,
        tags: JSON.stringify(e.tags ?? []),
        source: e.source ?? null, confirmed_by: e.confirmed_by ?? null,
        confirmed_at: e.confirmed_at ?? null, superseded_by: e.superseded_by ?? null,
        retracted_by: e.retracted_by ?? null, retracted_at: e.retracted_at ?? null,
        retracted_why: e.retracted_why ?? null,
        last_seen_at: ts,
      });
    }
  });
  upsert(entries);
  notesMirrorRecordAttempt(node, 'memory', true, null, ts);
}

const memoryMirrorForNodeStmt = db.prepare(
  'SELECT * FROM advisor_memory_mirror WHERE node = ? ORDER BY at ASC',
);

/** Every mirrored memory entry for one node, oldest first. */
export function memoryMirrorForNode(node: string): MemoryMirrorRow[] {
  return memoryMirrorForNodeStmt.all(node) as MemoryMirrorRow[];
}

const memoryMirrorRowStmt = db.prepare(
  'SELECT * FROM advisor_memory_mirror WHERE node = ? AND id = ?',
);

/** One mirrored memory entry by (node, id), or null. What the promote
 *  route reads before it will write anything into fleet knowledge. */
export function memoryMirrorRow(node: string, id: string): MemoryMirrorRow | null {
  return (memoryMirrorRowStmt.get(node, id) as MemoryMirrorRow | undefined) ?? null;
}

/** Every mirrored memory entry across the fleet, newest first, capped,
 *  the Advisor tab's read-only list. */
export function memoryMirrorFleet(limit = 200): MemoryMirrorRow[] {
  const n = Math.min(Math.max(Number.isFinite(limit) ? limit : 200, 1), 1000);
  return db.prepare('SELECT * FROM advisor_memory_mirror ORDER BY at DESC LIMIT ?').all(n) as MemoryMirrorRow[];
}

const memoryMirrorPromoteStmt = db.prepare(
  'UPDATE advisor_memory_mirror SET promoted_at = ?, promoted_by = ?, promoted_file = ? WHERE node = ? AND id = ?',
);

/**
 * Records that a mirrored memory entry was promoted into fleet knowledge,
 * never set by the poller, only by the Settings promote route, after the
 * write into knowledge-fleet/local/ and the push both succeeded. A row
 * already carrying this is not refused a second promotion (an operator may
 * legitimately re-promote a corrected version), it is only ever informative:
 * the mirror is a record of what was seen, and this is one more fact about
 * one row, not a lock.
 */
export function memoryMirrorMarkPromoted(node: string, id: string, by: string, file: string, ts = notesMirrorNow()): void {
  memoryMirrorPromoteStmt.run(ts, by, file, node, id);
}

/** One inbox note as a node's /v1/inbox answers it. */
export interface InboxMirrorNoteIn {
  id: string;
  title: string;
  body: string;
  node?: string;
  question?: string;
  source?: string;
  created_at: string;
  provenance?: string;
  rank?: number;
  status: string;
  decided_by?: string;
  decided_at?: string;
  reason?: string;
  file?: string;
}

export interface InboxMirrorRow {
  node: string;
  id: string;
  title: string;
  body: string;
  question: string | null;
  source: string | null;
  created_at: string;
  provenance: string | null;
  rank: number | null;
  status: string;
  decided_by: string | null;
  decided_at: string | null;
  reason: string | null;
  file: string | null;
  last_seen_at: number;
}

const inboxMirrorUpsertStmt = db.prepare(`
  INSERT INTO advisor_inbox_mirror
    (node, id, title, body, question, source, created_at, provenance, rank, status, decided_by, decided_at, reason, file, last_seen_at)
  VALUES (@node, @id, @title, @body, @question, @source, @created_at, @provenance, @rank, @status, @decided_by, @decided_at, @reason, @file, @last_seen_at)
  ON CONFLICT (node, id) DO UPDATE SET
    title = excluded.title, body = excluded.body, question = excluded.question, source = excluded.source,
    created_at = excluded.created_at, provenance = excluded.provenance, rank = excluded.rank,
    status = excluded.status, decided_by = excluded.decided_by, decided_at = excluded.decided_at,
    reason = excluded.reason, file = excluded.file, last_seen_at = excluded.last_seen_at
`);

/** Upserts every note a full /v1/inbox read answered, by (node, id), and
 *  records the poll as a success. Same never-delete rule as the memory
 *  mirror, for the same reason. */
export function inboxMirrorUpsert(node: string, notes: InboxMirrorNoteIn[], ts = notesMirrorNow()): void {
  const upsert = db.transaction((rows: InboxMirrorNoteIn[]) => {
    for (const n of rows) {
      inboxMirrorUpsertStmt.run({
        node, id: n.id, title: n.title, body: n.body,
        question: n.question ?? null, source: n.source ?? null, created_at: n.created_at,
        provenance: n.provenance ?? null, rank: n.rank ?? null, status: n.status,
        decided_by: n.decided_by ?? null, decided_at: n.decided_at ?? null,
        reason: n.reason ?? null, file: n.file ?? null, last_seen_at: ts,
      });
    }
  });
  upsert(notes);
  notesMirrorRecordAttempt(node, 'inbox', true, null, ts);
}

export interface InboxMirrorNodeSummary {
  node: string;
  pending: number;
  total: number;
  as_of: number | null;
}

/** One row per node this mirror has ever polled for its inbox: how many
 *  notes are still pending, how many exist in all, and when this mirror
 *  last actually reached that node, the Advisor tab's fleet inbox count. */
export function inboxMirrorSummary(): InboxMirrorNodeSummary[] {
  const rows = db.prepare(`
    SELECT s.node AS node, s.as_of AS as_of,
      COALESCE(SUM(CASE WHEN m.status = 'pending' THEN 1 ELSE 0 END), 0) AS pending,
      COUNT(m.id) AS total
    FROM advisor_notes_mirror_state s
    LEFT JOIN advisor_inbox_mirror m ON m.node = s.node
    WHERE s.kind = 'inbox'
    GROUP BY s.node
    ORDER BY s.node
  `).all() as InboxMirrorNodeSummary[];
  return rows;
}
