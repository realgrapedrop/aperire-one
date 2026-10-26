/**
 * The dashboard's fleet-write contract.
 *
 * One operator, on the aggregator's dashboard, changes the Advisor's model
 * key on every node they run. The key has to reach each node's own root
 * sealer, and the sealer's header forbids giving advisord a path to it, so
 * the job travels the road the read API already built: loopback to that
 * node's dashboard, which hands it to the socket systemd holds for it.
 *
 * This file is the ONE definition of what crosses. Both sides import it: the
 * aggregator builds and signs a job here, the node parses and verifies one
 * here, and neither has a private copy of the field order. It carries no
 * runtime import beyond node built-ins for that reason.
 *
 * Versioning follows types/read-contract.ts exactly, including its divergence
 * from the relay contract: a version this server does not serve gets a named
 * error body ({ error: "protocol_version_unsupported", server_version,
 * requested_version }) and never a silent drop.
 *
 * What is deliberately NOT here:
 *   - any read. This surface writes, and a caller with a read token can
 *     already read; putting a read here would mean two route sets serving
 *     the same fact and one of them drifting.
 *   - anything that arms a host. The dashboard cannot arm anything, on this
 *     node or any other: the arm token is minted by root on the aggregator
 *     and verified by root on the node. What crosses here is an opaque token
 *     this process cannot forge and does not check.
 */

import { createHash } from 'node:crypto';

export const FLEET_WRITE_PROTOCOL_VERSION = 1;

/**
 * The route names under /fleet/v1/. An exact set, never a prefix, for the
 * same reason READ_ROUTE_NAMES is one: a route is served because it is named
 * here. Two segments rather than one because both members are about the
 * model and a third subject will want its own noun.
 */
export const FLEET_WRITE_ROUTE_NAMES = [
  'model/seal',     // POST      the signed job plus the key, once
  'model/arm',      // POST/GET  the root arm token, and the arm state
  'update/state',   // GET       what this node's own updater says about it
  'update/apply',   // POST      the signed job that starts this node's apply
  'update/restart', // POST      the signed job that restarts what its run named
  'advisor/state',  // GET       this node's own Advisor presence, plus its build stamp
  'advisor/reveal', // POST      the signed job that reveals this node's own approve.token,
                     //           gated a second way by a root-planted, time-bounded window
] as const;

export type FleetWriteRouteName = (typeof FLEET_WRITE_ROUTE_NAMES)[number];

/**
 * Which methods each route answers, as DATA rather than as a branch.
 *
 * `model/arm` answers GET as well as POST: the aggregator's Settings page
 * shows per-node arm state, and a stat of a marker it cannot read is the
 * whole of that answer. Written here beside the route set so the carve-out
 * is a lookup one line away from the names it applies to, rather than an
 * `if (route === ...)` somewhere in the gate that a later tidy-up deletes.
 */
export const FLEET_WRITE_ROUTE_METHODS: Record<FleetWriteRouteName, readonly string[]> = {
  'model/seal': ['POST'],
  'model/arm': ['POST', 'GET'],
  // A GET behind the read token alone, the carve-out model/arm already has
  // and for the same reason: it changes nothing, and a caller holding this
  // node's read token can already read this node's whole read surface. What
  // it adds over the stamp is the endpoint root installs from and a bounded
  // tail of the current run. Both are deliberate (#275), not a consequence
  // of the stamp precedent.
  'update/state': ['GET'],
  'update/apply': ['POST'],
  'update/restart': ['POST'],
  // advisor/state is a free GET, same carve-out and same reason: it changes
  // nothing, and a caller holding this node's read token can already read
  // this node's whole read surface. advisor/reveal is the one route on this
  // whole contract that hands back a secret, so it stays a signed POST, the
  // same as model/seal.
  'advisor/state': ['GET'],
  'advisor/reveal': ['POST'],
};

/**
 * The label a node looks up in ITS fleet-trust.yaml `peers:` block to find
 * the key that signs a job.
 *
 * A literal, and not this dashboard's own fleet label, because it has to
 * match what the trust push already wrote: dashboard/lib/fleet-trust-job.py
 * and scripts/aperire-knowledge-push.sh both stamp `issuer_label:
 * "aggregator"` into the bundles they sign, and advisord looks the key up by
 * that string. Using the aggregator's fleet label here would mean asking a
 * node for `peers.the lab aggregator`, which no push has ever written, on every node
 * in the fleet.
 */
export const FLEET_WRITE_ISSUER_LABEL = 'aggregator';

/** How far a job's `issued_at` may be from the node's clock, either way. */
export const FLEET_WRITE_FRESHNESS_S = 300;

/** How long a spent nonce is remembered. Twice the freshness window, so a
 *  job can never age out of the replay record while it is still fresh
 *  enough to be accepted. */
export const FLEET_WRITE_NONCE_TTL_S = 600;

/** How many nonces a node remembers at once. The record is read and written
 *  whole on every job, so its size is the per-request cost; a caller holding
 *  a read token could otherwise grow it without end and stall the process
 *  (#180). Past the cap a node refuses, by name, until entries age out: a few
 *  thousand is more arms and seals than a fleet performs in ten minutes. */
export const FLEET_WRITE_NONCE_CAP = 4096;

/** The largest body either route accepts. A key and a signature; anything
 *  larger is not one of these. */
export const FLEET_WRITE_MAX_BODY_BYTES = 16 * 1024;

/** The provider API shapes the sealer knows. Same two words the per-node
 *  seal takes, and the same two the sealer branches on. */
export type SealShape = 'openai' | 'anthropic';

/**
 * The signed half of a seal. Every field is inside the signature, and the
 * key is not a field: it rides beside the job in the request body and is
 * bound to it by `key_sha256`, so a job that arrives with a different key
 * than the one it was signed for is refused before the sealer is called.
 */
export interface SealJob {
  v: typeof FLEET_WRITE_PROTOCOL_VERSION;
  kind: 'model.seal';
  /** Which peers.<label> key on the node verifies this. */
  issuer_label: string;
  /** The node this job is FOR, as that node's own /read/v1/identity reports
   *  it. A job delivered to the wrong node is refused rather than sealed:
   *  the aggregator holds one key and every node trusts it, so "the right
   *  signature" is not on its own an answer to "the right host". */
  target_pubkey_node: string;
  /** 32 hex characters, once. */
  nonce: string;
  /** Unix seconds. */
  issued_at: number;
  base_url: string;
  shape: SealShape;
  model: string;
  credential_name: string;
  /** sha256 of the key, hex, over the key with whitespace already stripped
   *  (the same stripping the per-node seal does before it sends one). */
  key_sha256: string;
  /** The human who touched the passkey on the aggregator, so the node's own
   *  audit trail names a person rather than a machine. */
  granted_by: string;
  /** Which passkey they touched. Recorded for the same reason. */
  credential_id: string;
}

/** The wire body of POST /fleet/v1/model/seal. */
export interface SealJobRequest {
  job: SealJob;
  /** base64url Ed25519 over sealJobSigningBytes(job). */
  signature: string;
  /** The secret. Present only here, on one loopback hop, and never in a
   *  response, a log, a job status or an audit detail. */
  key: string;
}

/** The wire body of POST /fleet/v1/model/arm. Opaque to the dashboard on
 *  both ends: root mints it and root verifies it. */
export interface ArmRequest {
  /** Plain `key=value` lines, bash-parseable, signed exactly as they are. */
  token: string;
  /** base64 (standard, padded) Ed25519 over the token bytes. */
  signature: string;
}

/**
 * What a node answers a seal with: the per-node seal's response shape, field
 * for field, so the aggregator renders one node's answer the same way the
 * Advisor tab renders its own host's.
 */
export interface SealJobResponse {
  ok: boolean;
  reason: 'sealed' | 'expired' | 'unarmed' | 'refused' | 'unavailable';
  detail: string;
  service?: string;
  credential?: string;
  config?: string;
  model: string;
  /** Three-valued on success: the Advisor's own word, or null when it had
   *  not answered yet. Absent on a refusal. */
  model_configured?: boolean | null;
}

/** What a node answers POST /fleet/v1/model/arm with. The sealer is the
 *  authority; this is its own report, read back rather than assumed. */
export interface ArmSealResponse {
  ok: boolean;
  armed: boolean;
  /** The window the node's sealer opened, in seconds. Null when it refused
   *  and therefore opened none. */
  window_s: number | null;
  /** Which aggregator the node's ROOT sealer read out of the token it
   *  verified. Read back rather than echoed from the request: this side
   *  never checked that signature, and the only trustworthy answer to "who
   *  armed this node" is the one from the program that verified it. */
  issuer: string | null;
  /** Present only on a failure, and it separates the two the operator acts
   *  on differently: `refused` is the node's sealer deciding, `unavailable`
   *  is no sealer to ask. Same two words the seal path uses. */
  error?: 'refused' | 'unavailable';
  detail: string;
}

/** What a node answers GET /fleet/v1/model/arm with: lib/model-arm.ts's
 *  ArmState, plus the two constants that make it readable. */
export interface ArmStateResponse {
  armed: boolean;
  remaining_s: number;
  reason?: 'no-marker' | 'expired' | 'future';
  window_s: number;
  marker: string;
}

// ── The update jobs, #275's half of this surface ─────────────────────────
//
// The aggregator cannot open a node's /run/aperire/update.sock: it is 0600
// and owned by that node's own dashboard account, and nothing on another box
// should be able to. So an update travels the road a seal travels — the
// aggregator asks the node's DASHBOARD, and that dashboard asks its own root
// updater, on its own facts.
//
// What crosses carries no source. Not a URL, not a path, not a program, not
// an argument, and on the restart job not even a unit name: root on the node
// reads its endpoint from its own /etc/aperire/update.conf and refuses a
// payload that disagrees with what that endpoint publishes. The aggregator
// can narrow what a node installs and can never widen it, which is the
// property the whole feature's safety argument rests on.
//
// These jobs carry NO SECRET, which is a real difference from the seal. A
// seal carries a provider key on one loopback hop; there is nothing here to
// leak at a boundary.

/** The signed half of a fleet apply. */
export interface UpdateApplyJob {
  v: typeof FLEET_WRITE_PROTOCOL_VERSION;
  kind: 'update.apply';
  /** Which peers.<label> key on the node verifies this. */
  issuer_label: string;
  /** The node this job is FOR, as that node's own /read/v1/identity reports
   *  it. Same reason the seal carries one: the aggregator holds one key and
   *  every node trusts it, so a good signature is not an answer to "the
   *  right host". */
  target_pubkey_node: string;
  /** 32 hex characters, once. */
  nonce: string;
  /** Unix seconds. */
  issued_at: number;
  /** What the operator was shown and approved. NARROWING only: the node
   *  compares these three against what its OWN check names and refuses a
   *  disagreement, and root compares them again against what its own
   *  endpoint publishes. */
  tag: string;
  commit: string;
  sha256: string;
  /** The human who touched the passkey on the aggregator, so the node's own
   *  audit trail names a person rather than a machine. */
  granted_by: string;
  /** Which passkey they touched. Recorded for the same reason. */
  credential_id: string;
}

/**
 * The signed half of a fleet restart.
 *
 * It names a RUN, never a unit. The unit list comes from that node's own
 * finished run (`needs_restart=`, discovered by root on that box), which is
 * ADR 0022 decision 5 held across the link: the set differs by host, so the
 * program discovers it and nobody sends it. The operator still sees the
 * names before the passkey, because update/state reports them and the
 * aggregator renders them — node to aggregator for display, never
 * aggregator to node as an instruction.
 */
export interface UpdateRestartJob {
  v: typeof FLEET_WRITE_PROTOCOL_VERSION;
  kind: 'update.restart';
  issuer_label: string;
  target_pubkey_node: string;
  nonce: string;
  issued_at: number;
  /** The node's own run id, as update/state reported it. A node whose
   *  finished run is not this one refuses: the approval was taken against
   *  what that run said needed restarting. */
  run_id: string;
  granted_by: string;
  credential_id: string;
}

export type UpdateJob = UpdateApplyJob | UpdateRestartJob;

/** The wire body of POST /fleet/v1/update/apply and /fleet/v1/update/restart.
 *  No third member: there is no key here and there never will be. */
export interface UpdateJobRequest {
  job: UpdateJob;
  /** base64url Ed25519 over updateJobSigningBytes(job). */
  signature: string;
}

/** The field order for each kind, and it is the contract. Same rules as
 *  SEAL_JOB_SIGNED_FIELDS: do not reorder, do not add a field without moving
 *  FLEET_WRITE_PROTOCOL_VERSION, and do not tidy the serialisation. */
export const UPDATE_APPLY_JOB_SIGNED_FIELDS = [
  'v', 'kind', 'issuer_label', 'target_pubkey_node', 'nonce', 'issued_at',
  'tag', 'commit', 'sha256', 'granted_by', 'credential_id',
] as const satisfies readonly (keyof UpdateApplyJob)[];

export const UPDATE_RESTART_JOB_SIGNED_FIELDS = [
  'v', 'kind', 'issuer_label', 'target_pubkey_node', 'nonce', 'issued_at',
  'run_id', 'granted_by', 'credential_id',
] as const satisfies readonly (keyof UpdateRestartJob)[];

/**
 * The exact byte order both sides sign and verify, per kind.
 *
 * The prefix line is `aperire-fleet-update/<v>`, NOT the seal's
 * `aperire-fleet-write/<v>`. `kind` is inside the signature already, so
 * cross-kind confusion is impossible either way; a distinct prefix costs
 * nothing and removes the question entirely. #303's lesson from the pairing
 * review is to be strict about what sits under a signature.
 */
export function updateJobSigningBytes(job: UpdateJob): string {
  const fields = job.kind === 'update.apply'
    ? UPDATE_APPLY_JOB_SIGNED_FIELDS
    : UPDATE_RESTART_JOB_SIGNED_FIELDS;
  const lines = (fields as readonly string[]).map((name) => {
    const value = (job as unknown as Record<string, unknown>)[name];
    const hex = Buffer.from(String(value), 'utf8').toString('hex');
    return `${name}=${hex}`;
  });
  return `aperire-fleet-update/${FLEET_WRITE_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

/** How many lines of a run's own output update/state carries. A TAIL, not
 *  the record: the whole 400-line record stays on the node where its own
 *  page reads all of it, and every link answer stays far inside
 *  FLEET_LINK_MAX_RESPONSE_BYTES rather than resting on an estimate of how
 *  noisy a build is. */
export const UPDATE_STATE_TAIL_LINES = 40;

/**
 * What a restart on a node costs, in the numbers the node's own root program
 * uses, so the aggregator's patience is DERIVED rather than borrowed (#323).
 *
 * `scripts/aperire-update.sh` waits RESTART_WAIT seconds per unit for it to
 * come back (`:101`, `:644`), and it will only ever act on the four units in
 * its own UNITS_ALLOWED (`:109`). Those two are the whole of the node's side
 * of the window; the aggregator adds the link's reconnect backoff on top,
 * because a node whose dashboard unit restarted is not reachable again until
 * its link is.
 *
 * Reusing the apply's 45 minutes here is what made a successful restart read
 * as a failure for three quarters of an hour, and reusing the node's own
 * 120 s socket bound would be too tight, because that bound is on one
 * socket conversation and not on the reconnect that follows it.
 */
export const UPDATE_RESTART_UNIT_WAIT_S = 60;
export const UPDATE_RESTART_MAX_UNITS = 4;

/**
 * How many bytes of one of a node's own sentences the aggregator will keep.
 *
 * The tail is bounded by the node that SERVES it and, until #324, by nothing
 * on the side that reads it. That asymmetry is the whole finding: a node's
 * dashboard being compromised is in ADR 0019's threat model, its named
 * capability is "it can lie down the link", and without a bound here that lie
 * lands in the aggregator's job record and in the operator's browser every
 * two seconds.
 *
 * A sentence an operator reads, a step name, and the eight units
 * `unitListRefusal` already allows. Both ends read these numbers.
 */
export const UPDATE_SAY_MAX_CHARS = 240;
export const UPDATE_STEP_MAX_CHARS = 32;
export const UPDATE_UNIT_MAX_CHARS = 64;
export const UPDATE_MAX_UNITS = 8;

/**
 * The largest answer the aggregator will read from a node's update/state.
 *
 * Derived from what the route can honestly produce: 40 tail lines at the
 * sentence cap, the steps, the units, the two verdict sentences and the host
 * facts, with room to spare. Far below the link's own 4 MiB response cap,
 * which is four million times the size of the answer this route was designed
 * to give.
 */
export const UPDATE_STATE_MAX_BYTES = 64 * 1024;

/** A node's own account of where it stands and what it is doing. Every
 *  member is that node's own measurement; nothing here is the aggregator's
 *  opinion carried back. */
export interface UpdateStateResponse {
  /** Is there an updater on that host at all. False means no root grant,
   *  which is a different sentence from a refusal. */
  updater: boolean;
  /**
   * Did that host's probe get an answer at all (#331).
   *
   * `updater` alone folds two readings into one word: there is no grant, and
   * the socket accepted a connection and said nothing. The second is the
   * residual the fleet-apply review named P3-070, and five minutes of it
   * would have a row telling an operator to run a root command on a host
   * that already holds the grant.
   *
   * OPTIONAL: a node on an older build omits it, and a reader takes the
   * absence as "did not say" rather than as false. Absent and false are
   * different readings and this is the member that exists to keep them apart.
   */
  updater_answered?: boolean;
  /**
   * Does that node hold this fleet's aggregator key, by its own reading of
   * its own `config/fleet-trust.yaml` (#331).
   *
   * The SAME `readPeerPubKey(FLEET_TRUST_PATH, FLEET_WRITE_ISSUER_LABEL)`
   * call gate 6 of `checkUpdateJob` makes, so the fact a row displays and the
   * refusal a press would actually get come from one reader and cannot
   * drift. It is reported here because the state route runs no job gate:
   * `no_aggregator_pinned` is only ever reached on the two signed POST
   * routes, so a read can never carry it.
   *
   * Three-valued, and the third value is the point. A trust file that exists
   * and this account cannot open reads identically to one that was never
   * written, and #331 records exactly that accident costing an afternoon on a
   * key that was there all along. `unreadable` is a mode bit to fix;
   * `none` is a pairing to run.
   *
   * OPTIONAL, same rule as above.
   */
  aggregator_pin?: 'pinned' | 'none' | 'unreadable';
  /** Where root on that node fetches from, as root reported it. Null when
   *  there is no updater, or when its program is older than that fact. */
  endpoint: string | null;
  /** What root says that endpoint publishes. */
  published: { tag: string; commit: string; sha256: string } | null;
  /** What root read out of that node's stamp. */
  installed: { tag: string; commit: string; sha256: string } | null;
  /** Root's own word for where that host stands. Null when it did not say. */
  verdict: 'current' | 'behind' | 'mid_publish' | 'unreachable' | null;
  /** What that node's own dashboard would do if its own Apply were pressed,
   *  and why not when it would refuse. Read back rather than re-derived on
   *  the aggregator: one function decides it, on the box that knows. */
  can_apply: boolean;
  /** The refusal's own sentence, present exactly when can_apply is false. */
  cannot_apply_detail?: string;
  /** That node's current or last run. Null when it has never run one, and
   *  null again after a restart that took away the process holding it. */
  run: UpdateStateRun | null;
  /**
   * What each of that node's own components measured about its own build,
   * where it could measure one (#266).
   *
   * A release rebuilds every component the host has; the accident this
   * exists to catch is the one that did not happen, fleet-update synced
   * Advisor sources to three nodes on 2026-09-08 without rebuilding the
   * daemon, and nothing said so. Keyed by component name (`relay`,
   * `advisord`), each value that node's own build ref for that piece.
   *
   * OPTIONAL, and so is every key inside it: a component this build cannot
   * yet measure, or one that has never reported a build ref of its own
   * (`relay_version` reads `dev` until a release stamps it), is OMITTED
   * rather than guessed. Absent is "not measured", never drift, the
   * comparison this member feeds must never read a missing key as a
   * mismatch. */
  components?: Record<string, string>;
  /**
   * What that node KEPT about its last run, across the process that held it
   * (#323).
   *
   * The run record lives in memory, and a restart verb restarts the
   * dashboard's own unit last and deliberately, which takes that process
   * away. Without this the node comes back saying `run: null` and the only
   * honest reading on the other side is "I cannot say", for a restart that
   * in fact succeeded.
   *
   * Every member is that node's own record or that node's own measurement.
   * Nothing here is inferred by the reader.
   */
  last_run: UpdateStateLastRun | null;
}

export interface UpdateStateLastRun {
  run_id: string;
  action: 'apply' | 'restart' | 'rollback';
  started_at: number;
  /** When the node last wrote this marker, which on a self-restart is the
   *  last moment the old process was alive. */
  written_at: number;
  /** The exit code, if the program reached its own last line before the
   *  process went away. Null is the ordinary reading after a restart that
   *  included this dashboard's unit, and it is NOT a failure. */
  code: number | null;
  steps: string[];
  /** What that run asked to be restarted, off the run's own record. */
  units: string[];
  /**
   * Did the process answering this request start AFTER that run began?
   *
   * The node's own measurement, from its own process start time against the
   * marker it wrote. It is the fact that makes a self-restart readable: the
   * process holding that run is gone and this one came up after the run
   * started. It says nothing about the other units — that is what the node's
   * own page is for — and a reader must not turn it into one.
   */
  restarted_after: boolean;
}

export interface UpdateStateRun {
  run_id: string;
  action: 'apply' | 'restart' | 'rollback';
  running: boolean;
  started_at: number;
  finished_at: number | null;
  /** The steps the program announced, in order. */
  steps: string[];
  /** The exit code, null while it is still running. A snapshot taken
   *  mid-apply must not be readable as a result. */
  code: number | null;
  /** The verdict's two sentences, as that node computed them. */
  verdict: { ok: boolean; reason: string; detail: string; say: string } | null;
  /** The last UPDATE_STATE_TAIL_LINES of the program's own words, and the
   *  cursor the next poll passes back as ?since=<n>. */
  lines: string[];
  /** How many lines that node's own record holds, so a reader can tell a
   *  tail from the whole. NOT a total: the record itself caps at 400 lines
   *  and drops the oldest, so "how many has this run produced" is a number
   *  nobody on either side has. Deliberately not a cursor either — an index
   *  into a record that drops its oldest line means something different on
   *  the next poll, and the row renders the last line anyway. */
  line_count: number;
  /** The units that run said are running older code than the tree now holds.
   *  That node's own discovery, for the aggregator to DISPLAY. */
  needs_restart: string[];
  /** What the run was applying, when it was an apply. */
  release: { tag: string; commit: string; sha256: string } | null;
}

// ── The advisor jobs, #641's half of this surface ────────────────────────
//
// Attaching an Advisor to an already-paired node is a PULL, not a push, and
// this is the pull's signed half. The aggregator asks a node it already
// holds a live link to for that node's own approve.token, and the node
// answers only when TWO independent things are both true: this job checks
// out (an aggregator this node already trusts, freshly, once), and a
// root-planted, time-bounded window is open on the node's own box (checked
// separately, outside this contract, by a stat this process cannot forge).
// Neither alone is sufficient, which is the whole security argument.
//
// The job carries no secret and no grant fields (no key, unlike SealJob; no
// granted_by/credential_id, unlike every other job here): it does not widen
// anything on this node, it only asks this node to hand back a token it
// already holds, and the human who approved THAT (the operator's passkey
// touch on the aggregator) is recorded on the aggregator's own side, where
// the ceremony runs. Its own `kind` discriminator keeps a captured seal or
// update signature from ever replaying as a reveal, the same domain
// separation checkSealJob and checkUpdateJob already keep as separate
// functions rather than a shared gate.

/** The signed half of an advisor reveal. */
export interface AdvisorRevealJob {
  v: typeof FLEET_WRITE_PROTOCOL_VERSION;
  kind: 'advisor.reveal';
  /** Which peers.<label> key on the node verifies this. */
  issuer_label: string;
  /** The node this job is FOR, as that node's own /read/v1/identity reports
   *  it. Same reason every other job here carries one: a good signature is
   *  not on its own an answer to "the right host". */
  target_pubkey_node: string;
  /** 32 hex characters, once. */
  nonce: string;
  /** Unix seconds. */
  issued_at: number;
}

/** The wire body of POST /fleet/v1/advisor/reveal. No third member: there
 *  is no key here, and the token it asks for is never a member of the job
 *  itself. */
export interface AdvisorRevealRequest {
  job: AdvisorRevealJob;
  /** base64url Ed25519 over advisorRevealJobSigningBytes(job). */
  signature: string;
}

/** What a node answers a successful reveal with. Nothing else: no token,
 *  no build stamp, ever rides the free GET below. */
export interface AdvisorRevealResponse {
  /** advisor/state/approve.token, read fresh. Bounded by
   *  FLEET_PAIR_MAX_TOKEN_CHARS the same way a pairing token already is
   *  (fleet-link-contract.ts:299), on the caller's side: this response is
   *  never truncated here, since truncating a credential silently is worse
   *  than sending it whole. */
  advisor_token: string;
  /** The Advisor binary's own build ref, same field advisor/state serves,
   *  read back here too so a successful attach can render a build stamp on
   *  its very first row without a second round trip. Null exactly when
   *  advisor/state's own version is null. */
  advisord_version: string | null;
}

export const ADVISOR_REVEAL_JOB_SIGNED_FIELDS = [
  'v', 'kind', 'issuer_label', 'target_pubkey_node', 'nonce', 'issued_at',
] as const satisfies readonly (keyof AdvisorRevealJob)[];

/**
 * The exact byte order both sides sign and verify.
 *
 * The prefix line is `aperire-fleet-advisor/<v>`, distinct from both the
 * seal's `aperire-fleet-write/<v>` and the update jobs'
 * `aperire-fleet-update/<v>`. `kind` already sits inside the signature, so
 * cross-kind confusion is impossible either way; a distinct prefix per kind
 * costs nothing and removes the question entirely (#303's lesson from the
 * pairing review: be strict about what sits under a signature).
 */
export function advisorRevealJobSigningBytes(job: AdvisorRevealJob): string {
  const lines = ADVISOR_REVEAL_JOB_SIGNED_FIELDS.map((name) => {
    const value = job[name];
    const hex = Buffer.from(String(value), 'utf8').toString('hex');
    return `${name}=${hex}`;
  });
  return `aperire-fleet-advisor/${FLEET_WRITE_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

/**
 * What GET /fleet/v1/advisor/state answers: this node's own Advisor
 * presence, the same three facts `self` already carries in
 * buildAdvisorPresenceResponse (lib/advisor-presence.ts), namely `state`,
 * `last_answered_ms` and `detail`, plus the one field that shape has never
 * carried: the build stamp GET /v1/status already serves (advisord's own
 * `version`) and this route now forwards. No token, no secret, ever, in
 * this response; that is the whole reason a reveal needs its own signed,
 * window-gated route rather than riding this free one.
 *
 * A literal union rather than an import of AdvisorPresenceState: this file
 * carries no runtime import beyond node built-ins, by its own header rule,
 * and the three states are stable enough that restating them here once is
 * cheaper than a cross-file type coupling.
 */
export interface AdvisorStateResponse {
  state: 'absent' | 'present' | 'installed-but-down';
  last_answered_ms: number | null;
  detail: string;
  /** Null when this node has no Advisor answering yet, its Advisor predates
   *  the field, or its Advisor answered with the literal build ref "dev"
   *  (an unstamped build, e.g. a fresh install whose own build step never
   *  passed -ldflags -X main.version=...; #650). Never remembered across
   *  cycles: the same non-memory rule `modelConfigured` already follows in
   *  advisor-presence.ts, and for the same reason: a stale build stamp is
   *  a claim nobody measured this cycle. */
  version: string | null;
}

/**
 * Every refusal this surface can make, named. A closed set because the
 * aggregator chooses words from it: "that node has no aggregator pinned" and
 * "that node refused the signature" send an operator to two different files,
 * and collapsing them into one 401 would send them to neither.
 */
export type FleetWriteErrorCode =
  | 'not_loopback'
  | 'fleet_write_disabled'
  | 'bad_token'
  | 'method_not_allowed'
  | 'unknown_fleet_write_path'
  | 'protocol_version_unsupported'
  | 'bad_job'
  | 'wrong_node'
  | 'no_aggregator_pinned'
  | 'bad_signature'
  | 'stale_job'
  | 'replayed_job'
  | 'nonce_store_unreadable'
  | 'nonce_store_full'
  | 'key_hash_mismatch'
  // The node's own check does not say it is behind, so there is nothing for
  // it to apply. Its own Apply button refuses on the same fact; this is that
  // refusal reached from the aggregator.
  | 'not_behind'
  // A restart job naming a run that is not the run this node finished. The
  // approval was taken against what THAT run said needed restarting.
  | 'wrong_run'
  // A route this contract names and the build serving it has no work for.
  // Not the same fact as `unknown_fleet_write_path`, which says the path is
  // not a route at all: this one says the path IS a route and this build
  // does nothing for it, which sends an operator to the node's version
  // rather than to their own spelling.
  | 'no_handler'
  // The reveal job checked out, but this node's own reveal window did not:
  // absent, wrongly owned, group- or world-writable, or older than its
  // lifetime. One code for all four, since the operator-facing sentence is
  // the same either way ("the window on this node has closed, run the
  // installer again"); `detail` says which.
  | 'advisor_reveal_window_closed'
  // The reveal job checked out and the window was open, but this node holds
  // no approve.token to hand back: an install that has not finished, or
  // one whose Advisor was removed since. Named apart from `bad_job`,
  // because nothing about the request was wrong.
  | 'advisor_reveal_unavailable';

export interface FleetWriteErrorBody {
  error: FleetWriteErrorCode;
  /** One sentence for an operator, when the code alone does not say enough
   *  to act on. Never carries a key, and never a hash of one. */
  detail?: string;
  server_version?: number;
  requested_version?: number;
  /** On wrong_node: what this node calls itself, so the aggregator can say
   *  which row is stale rather than "somewhere in your fleet". */
  this_node?: string | null;
  /** On no_aggregator_pinned: the label that was looked for. A fleet whose
   *  trust exchange wrote a different one is then one log line to diagnose
   *  instead of a lab mystery. */
  expected_issuer?: string;
}

/**
 * The exact byte order both sides sign and verify.
 *
 * Every value is hex-encoded UTF-8 because two of them are typed by an
 * operator: `base_url` and `model` can hold any character a keyboard makes,
 * including the newline this format separates fields with. Hex has no
 * character in common with the separator or the `=`, so no value can be
 * split into a field boundary and no two different jobs can serialise the
 * same way. That is worth more here than readability: the thing being
 * authorised is a key reaching a root program.
 *
 * The field order is the contract. Do not reorder, do not add a field
 * without moving FLEET_WRITE_PROTOCOL_VERSION, and do not "tidy" the
 * serialisation: the aggregator and the node import THIS function, so a
 * change lands on both sides at once only if both are deployed together.
 */
export const SEAL_JOB_SIGNED_FIELDS = [
  'v', 'kind', 'issuer_label', 'target_pubkey_node', 'nonce', 'issued_at',
  'base_url', 'shape', 'model', 'credential_name', 'key_sha256',
  'granted_by', 'credential_id',
] as const satisfies readonly (keyof SealJob)[];

export function sealJobSigningBytes(job: SealJob): string {
  const lines = SEAL_JOB_SIGNED_FIELDS.map((name) => {
    const value = job[name];
    const hex = Buffer.from(String(value), 'utf8').toString('hex');
    return `${name}=${hex}`;
  });
  return `aperire-fleet-write/${FLEET_WRITE_PROTOCOL_VERSION}\n${lines.join('\n')}`;
}

/**
 * The key's hash, over the key as the sealer will receive it.
 *
 * Whitespace is stripped FIRST, the same strip the per-node seal handler
 * applies before it writes a key to the socket. A key pasted with a trailing
 * newline would otherwise hash on the aggregator and hash differently on the
 * node, and the operator would be told their key did not match itself.
 */
export function sealKeyHash(key: string): string {
  return createHash('sha256').update(key.replace(/\s/g, ''), 'utf8').digest('hex');
}
