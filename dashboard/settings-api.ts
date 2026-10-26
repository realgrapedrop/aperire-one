/**
 * The Settings page's routes: everything an operator does TO a node, done
 * from the one dashboard they already have open.
 *
 * Admin only, all of them:
 *
 *   GET  /api/settings/overview            every node, and what is true of it
 *   GET  /api/settings/audit               who changed who may do what
 *   POST /api/settings/model/test          ask the provider whether a key works
 *   POST /api/settings/model/seal/begin    one challenge, bound to the nodes picked
 *   POST /api/settings/model/seal          202 with a job id; the work runs behind it
 *   GET  /api/settings/model/seal/job/:id  per-node state, polled
 *   POST /api/settings/trust/push          push the admin passkeys to one or all nodes
 *   POST /api/settings/operators/add/begin one challenge, bound to the grant
 *   POST /api/settings/operators/add       create an account and invite it
 *   POST /api/settings/operators/link      a fresh enrollment link for one
 *   POST /api/settings/operators/role/begin  the same challenge, for a promotion
 *   POST /api/settings/operators/role      promote or demote
 *   POST /api/settings/operators/revoke    one passkey, or all of an account's
 *   POST /api/settings/operators/remove    delete the account outright
 *
 * Written as a dispatcher with injected dependencies, the shape
 * knowledge-admin.ts already uses, so server.ts hands over what it owns (the
 * fleet registry, the local sealer, the Advisor presence probe) and this file
 * owns the decision to use them.
 *
 * Two rules run through all six.
 *
 * ONE: a peer that does not answer is a ROW, never a thrown page. The whole
 * point of this page is the fleet, and a fleet page that fails because one
 * node is down fails exactly when an operator opened it to find out which
 * node is down. Every fan-out below is settled, not raced, and every failure
 * is a named reason on that node's row.
 *
 * TWO: the key is never on this side of the wire except in the request that
 * carries it. It is not in a response, not in a job status, not in a log
 * line, and not in an audit detail. The seal ceremony hands it straight to
 * the job, which owns it until the last node settles.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  readSession, isAdmin, csrfOk, trustFingerprint, listOperatorPasskeys,
  handleAdvisorModelTest, handleSettingsSealBegin, handleSettingsSealFinish,
  getAllUsers, getCredentialsForUser, liveSessionCount, latestPendingLink,
  createOperator, setUserRole, deleteOperator, revokeCredentialById,
  endSessionsForUser, endSessionsForCredential, issueEnrollmentLink,
  emailEnrollmentLink, beginOperatorGrant, verifyOperatorGrant, trustChangeRunners,
  beginPairGrant, verifyPairGrant, beginCatchupGrant, verifyCatchupGrant, getUserById,
  type SealTargetResolver, type AuthSessionInfo, type VerifiedCatchupGrant, type SealVerifier,
} from './auth.js';
import { queryAuthEvents, recordAuthEvent, memoryMirrorRow, memoryMirrorMarkPromoted } from './db.js';
import { promoteMemoryNote, knowledgePaths } from './knowledge-admin.js';
import { readBodyOrThrow } from './lib/read-body.js';
import { isSocketUnreachable } from './lib/model-seal.js';
import { mintPairingCode, mintLimit, cancelPairingCodeByHash, liveCodeNamed } from './lib/pairing-codes.js';
import {
  brokerApprovePayload, brokerRevokePayload, brokerRevokeOutcome, brokerRepinPayload, brokerRepinOutcome, brokerAnswerOf, brokerOutcome, BROKER_NO_ANSWER, armKeyRemintNote,
  brokerArmKeyPayload, brokerArmKeyOutcome, PAIRING_FINGERPRINT_COMMAND, fleetArmCommand,
  brokerArmKeyCheckPayload, brokerArmKeyCheckOutcome, restoreSentence, trustKeyLostDetail,
  BROKER_BUSY_DETAIL, armSelfSentence, armSelfCommand, catchupNodeLine, storeWriteLine, grantInstallSentence, grantStepCommand,
  brokerAttachAdvisorPayload, brokerAttachAdvisorOutcome,
  brokerDetachAdvisorPayload, brokerDetachAdvisorOutcome,
  brokerOutcomeUnknown, brokerUnknownDetail, inheritFleetModel, attachModelSentence,
  type AttachModelState, type InheritOutcome, type BrokerStoreHeadOutcome, type BrokerPushOutcome, type BrokerPushGrant, type StoreWriteNote,
} from './lib/fleet-broker.js';
import {
  fetchPeerAdvisorState, revealPeerAdvisorToken, advisorWatchState,
  advisorAttachedReading, advisorStateSaid,
  ADVISOR_WATCH_COPY, ADVISOR_ATTACHED_COPY, ADVISOR_DETACH_COPY, ADVISOR_INSTALL_CMD,
} from './lib/fleet-advisor-attach.js';
import type { PairingRow, PairApproveOutcome, PairSettlement } from './lib/fleet-link-hub.js';
import {
  buildAccounts, clampAuditLimit, mapAuditEvents, handleOperatorRoute,
  type OperatorAdminDeps, type OperatorRoute, type OperatorResult,
} from './lib/operator-admin.js';
import { type FleetNodeConfig } from './lib/fleet-registry.js';
import { fleetRowNamed, mintNameVerdict } from './lib/fleet-pair-classify.js';
import type { FleetPeerPublic } from './lib/fleet-health.js';
import { fetchPeerAdvisor } from './lib/peer-advisor-proxy.js';
import { FleetSealJobs, fetchPeerArmState, SELF_TARGET } from './lib/fleet-seal.js';
import { readOwnPrivateKey } from './lib/trust-bundle.js';
import {
  appendFleetRecord, appendOwnFleetRecord, buildFleetRecord, describeFleetRecord,
} from './lib/advisor-ledger-append.js';
import {
  computeNodeSync, providerNameFor, baseUrlHost, publicFleetModel,
  type FleetModelRecord, type NodeModelReport, type NodeSync,
} from './lib/fleet-model-record.js';
import type { ArmStateResponse } from './types/fleet-write-contract.js';
import { trustSyncRemedy } from './lib/trust-sync.js';
import {
  trustPushRows, annotatePushFailures, pushResultsByNode, pushFailureLine, pushCauseLine, pushFailedLine,
  PUSH_SUMMARY_RE, lastLine, type PushRow, type PushReason,
} from './lib/trust-push-rows.js';
export { pushResultsByNode, pushFailureLine, pushCauseLine, pushFailedLine, PUSH_SUMMARY_RE };
export type { PushRow, PushReason };

/** The grant command a broker's refusal names, in the one root form it
 *  prints (#929): the bootstrap's step, with this install's directory and the
 *  installer's flag when it names one. A sentence from an older root-held
 *  broker, which still names the tree's installer, does not match, and the
 *  page offers the grant step instead, never the tree path. */
const GRANT_STEP_IN_DETAIL = /curl -fsSL https:\/\/get\.aperire\.one \| bash -s -- --dir \S+ --run fleet-broker-grant(?: --(?:refresh-nodes|new-fleet-keys|remove)\b)?/;

/** advisord's /v1/status, as much of it as this page reads. Every field
 *  optional: a node running a build that predates one of them reports
 *  nothing, and "not reported" is a different fact from "reported empty". */
interface AdvisorStatusDoc {
  version?: string;
  model?: unknown;
  trust?: unknown;
}

export interface NodeAdvisorSettings {
  /** Did this node's Advisor answer at all, this pass? Never a memory: an
   *  Advisor that did not answer is reported as not answering. */
  present: boolean;
  /**
   * Three states, because `present` only has two and the two questions an
   * operator asks are different ones.
   *
   *   present  it answered.
   *   absent   this dashboard knows there is no Advisor there: the node's
   *            registry row carries no Advisor at all, or this host's own
   *            presence observation says none is installed.
   *   unread   there may well be one; it did not answer this pass.
   *
   * A node whose dashboard blipped for a second is `unread`, and must never
   * be shown, or refused, as a node with no Advisor.
   */
  presence: 'present' | 'absent' | 'unread';
  version: string | null;
  /** advisord's own model block, verbatim. Null when it did not answer, or
   *  answered without one. */
  model: unknown;
  /** advisord's own trust block, verbatim. */
  trust: unknown;
  /** Why there is nothing here, when there is nothing here. */
  reason?: string;
}

export interface NodeSettings {
  label: string;
  role: string | null;
  is_self: boolean;
  reachable: boolean;
  /** How this dashboard reaches that node. 'self' is this process. 'link' is
   *  the node's own outbound fleet link (ADR 0019), terminating in a loopback
   *  listener this process binds. 'loopback' is everything else: this host, or
   *  the near end of a forward.
   *
   *  It is the row's INTENT, read off fleet.yaml, and it is not evidence that
   *  anything is working. link_last_held_ms beside it is the observed half. */
  transport: 'self' | 'loopback' | 'link';
  /** When this node's link was last up AND its loopback listeners bound, or
   *  null for never. Observed, never derived from the config: a row that says
   *  `link` and has never held one reads as never, which is what tells an
   *  operator that a link outage is a link outage and not a dead node. Null
   *  on every row that is not on the link. */
  link_last_held_ms: number | null;
  /** The machine the node runs on: its OS hostname as its own dashboard
   *  reports it (this host's from its own OS; a peer's off the fleet poll,
   *  which reads it from the same node-status body as the build version).
   *  Null is "not said": unreachable, a peer older than the field, or a
   *  host with no name. The page prints a dash, never a guess. */
  host_name: string | null;
  pubkey_node: string | null;
  /** Only meaningful for a pinned row: true when that node proved its
   *  identity, false when it is pinned and did not, null when unpinned. */
  pin_ok: boolean | null;
  /**
   * Which of the four things "did not prove it" means (#422).
   *
   *   null          the row pins nothing, so there is nothing to prove.
   *   'ok'          it answered with the pinned key.
   *   'changed'     it answered with a DIFFERENT key, and both are here.
   *     That node's reads are refused until an administrator accepts the
   *     new one, which is the only state on this list an operator acts on.
   *   'unconfirmed' pinned, and this dashboard has not read its key this
   *     cycle. Never rendered as a mismatch: "could not check" and "checked
   *     and it is wrong" are different facts and only the second is one.
   */
  pin_state: 'ok' | 'changed' | 'unconfirmed' | null;
  /** The key that node reported, when it reported one that did not match.
   *  Null everywhere else: a key nobody read is not a key. */
  pin_reported: string | null;
  /** The key the REGISTRY pins, when it is not the one that node reported.
   *  Null everywhere else, on the same rule as pin_reported.
   *
   *  It exists because `pubkey_node` above does not mean one thing on every
   *  row and this note needs the pinned key by name: a peer's column holds
   *  what the registry pins, and this host's own holds what its node reports
   *  (there was never a comparison on a self row to hold the other). Reading
   *  the pinned key out of a column that means two things is how a note ends
   *  up printing "pinned X" where X is the very key that disagrees. */
  pin_expected: string | null;
  last_seen_ms: number | null;
  advisor: NodeAdvisorSettings;
  /** #641. Does this aggregator hold an address for that node's Advisor, off
   *  the registry row itself. A different question from `advisor.presence`,
   *  which is what that node answered: an attached Advisor that is down is
   *  `true` here and not `present` there, and an Advisor running on a node
   *  nobody attached is the other way round. False on the self row, which is
   *  not attached from anywhere. */
  advisor_attached?: boolean;
  arm: ArmStateResponse | null;
  /** Why there is no arm state. Null when there is one. An older node with
   *  no fleet-write surface reads as 'no_fleet_write_surface', which is "this
   *  node cannot tell me" and not "this node is not armed". */
  arm_reason: string | null;
  /** The bundle that node last accepted, off its own trust block. */
  bundle: { serial: string | null; accepted_at: string | null } | null;
  /** Is this node on the fleet's model setting? Computed here, never on the
   *  page: the comparison is between what the node reports and what the
   *  fleet's record says, and both live on this side. */
  sync: NodeSync;
  /** The serial the next push from THIS dashboard would carry. The same
   *  value on every row (it is a fact about this host's admin set, not about
   *  the node), carried per row so the page can compare without arithmetic.
   *  Null on a host that holds no signing key and therefore pushes nothing. */
  current_serial: string | null;
}

export interface SettingsAdminDeps {
  /** dashboard/config/fleet-trust.yaml, resolved by server.ts from the same
   *  base as fleet.yaml. */
  fleetTrustPath: string;
  /** Repository root, the parent of dashboard/. Same value knowledge-admin.ts
   *  is handed, and used the same way: knowledgePaths(repoDir) for the
   *  memory-promotion route, ADR 0021 build step 5. */
  repoDir: string;
  /** The resolved peers, and this node's own registry row. */
  peers: () => FleetNodeConfig[];
  selfNode: () => FleetNodeConfig | null;
  /** #1057: the registry rows this dashboard read and could not use, because
   *  none of them is this host (resolveFleet's fail-closed answer). Empty
   *  whenever the registry resolved. They are not peers: nothing polls them
   *  and no link is bound for them. They are listed so a node that paired
   *  into that state can still be revoked from Settings. Optional: a host
   *  that never holds a row back passes nothing. */
  held?: () => { nodes: FleetNodeConfig[]; reason: string | null };
  /** The rendered fleet, for reachability and last-seen. Null on a
   *  single-node install, which is the ordinary state and not an error. */
  fleetView: () => { nodes: FleetPeerPublic[] } | null;
  /** This host's own advisord status, or null when it has none / did not
   *  answer. Fetched by server.ts, which owns the token. */
  selfAdvisorStatus: () => Promise<AdvisorStatusDoc | null>;
  /** This host's own pubkey_node, the value /read/v1/identity serves. */
  selfPubkeyNode: () => string | null;
  /** This host's own OS hostname, the value node-status serves as
   *  host_name. Sampled by server.ts, which owns node:os. */
  selfHostName: () => string | null;
  /** This host's own arm state, from lib/model-arm.ts. */
  selfArmState: () => ArmStateResponse;
  /** What the fleet link hub observes about one node, or null when this
   *  dashboard holds no link for it. Optional: an aggregator with no
   *  fleet-links.json passes nothing and every row reads as it did. */
  linkStatus?: (label: string) => { held: boolean; last_held_ms: number | null } | null;
  /**
   * Tell the link hub an operator has approved revoking this node at a
   * passkey (#688), so the `revoked` it sends when the row leaves
   * fleet-links.json carries a tombstone this host signed. Returns the undo,
   * run when the broker refuses. Optional: a host with no hub passes
   * nothing, and a revoked node there simply asks again once an hour.
   */
  expectRevoke?: (label: string) => () => void;
  /** Facts about this dashboard itself, for the page's last section. */
  thisDashboard: () => Record<string, unknown>;
  /** The fleet's model setting as last recorded, or null when this
   *  dashboard has never sealed one from here. */
  fleetModel: () => FleetModelRecord | null;
  /**
   * What the root broker says it holds SEALED (ADR 0019 phase 4, #168).
   *
   * A different question from `fleetModel` above, and the page asks both. The
   * record says what the fleet's setting IS and drives every node's verdict;
   * this says whether a node paired right now would inherit it, which neither
   * the record nor any node's status can answer.
   *
   * Optional: an aggregator with no broker holds no store, and the page then
   * says so rather than growing a fact about a feature this host does not
   * have. Never throws: five states in, and four of them are not "there is no
   * store".
   */
  storeHead?: () => Promise<BrokerStoreHeadOutcome>;
  /** The same read, but one that waits its turn on the socket rather than
   *  answering `unread` while a push holds it. For an operator-started
   *  one-shot (an attach's inherit, #1037), where a busy broker is a wait and
   *  not an answer. Absent, `storeHead` is used. */
  storeHeadQueued?: () => Promise<BrokerStoreHeadOutcome>;
  /** Push the sealed fleet model to one node, or to 'self'. One call per
   *  node, serially: the broker socket takes one connection at a time and a
   *  push runs for minutes. */
  modelPush?: (label: string, grant: BrokerPushGrant) => Promise<BrokerPushOutcome>;
  /** Is the fleet broker grant's arm program on this host, root-owned at
   *  its fixed name (#812)? A stat, never thrown: absent, unreadable and
   *  not root's all answer false, and the page then prints the update first. */
  fleetArmInstalled?: () => boolean;
  /** Is the fleet broker itself here, root-owned at its fixed name? The update
   *  places the arm program only where it is, so a host without it is told to
   *  install the grant instead of being sent to an update that changes nothing.
   *  Not supplied (a caller with no observation) reads as present. */
  fleetBrokerInstalled?: () => boolean;
  /** This host's own Advisor presence, the ADR 0016 observation. Used only
   *  to tell "there is no Advisor here" from "it did not answer just now". */
  selfAdvisorPresence: () => 'absent' | 'present' | 'installed-but-down';
  /** The seal job runner. */
  jobs: FleetSealJobs;
  /** Run the trust push for one node (or all, when label is null), and
   *  report what the CLI said. Spawned by server.ts, which already owns the
   *  spawn helper the enrollment hook uses. */
  pushTrust: (label: string | null) => Promise<{ ok: boolean; output: string }>;
  /** Pairings this dashboard is holding right now (ADR 0019 phase 3), and
   *  the two verbs on one. Optional: a host with no hub holds none, and the
   *  page then renders no Pending block at all rather than an empty one. */
  pairings?: () => PairingRow[];
  pairApprove?: (
    id: string, label: string,
    settle: (tokens: { read_token: string; advisor_token: string | null }) => Promise<PairSettlement>,
    /** #741: the fleet arm public key root's broker reported a moment ago,
     *  for the signed welcome. */
    fleetArmPubkey: string | null,
  ) => PairApproveOutcome;
  pairRefuse?: (id: string) => boolean;
  /** Ask the root broker to register a node. Injected so this file holds no
   *  socket path of its own and a test can answer without one. */
  broker?: (payload: string) => Promise<{ code: number; stdout: string; stderr: string; reported?: boolean; timedOut?: boolean }>;
  /** Pairing v2: keep the fleet arm public key root's broker just reported,
   *  in the process-wide cache the link hub reads when a keys-first node
   *  calls in (LinkHubDeps.cachedArmPubKey). Written by the mint's preflight
   *  and by every approval's fresh answer. Optional: a host with no hub has
   *  nowhere to keep it. */
  rememberArmPubKey?: (pub: string) => void;
  /** Is root's broker already working on something (a model push after the
   *  last pairing, a catch-up)? A mint asks this before it queues behind
   *  that work, and answers busy at once rather than waiting minutes for a
   *  ten-millisecond answer (#850 review, L2). Optional: absent reads idle. */
  brokerBusy?: () => boolean;
  /** This aggregator's own fleet trust PUBLIC key, base64url. Shown beside
   *  the Pending rows so the operator holds both halves of the comparison
   *  the node's command asks them to make (ruling, 2026-09-12). */
  fleetTrustPubKey?: () => string | null;
  /** Start the follow-on for a node that has just been registered (§3.6):
   *  wait for its link to be HELD, push the passkey list, and put the
   *  outcome on its row. Fire and forget from here — the approval has
   *  already been answered, and this takes up to a minute and a half. */
  pairFollowOn?: (input: {
    pairingId: string; label: string; advisor: boolean; grant: BrokerPushGrant;
    /** #743 review, L2: a sentence to lead the row's note with, when this
     *  pairing made a new arm key that nodes paired earlier do not trust. */
    armKeyNote?: string | null;
  }) => void;
  /** 32 random bytes as hex, for one link credential. Injected rather than
   *  imported so a test can make it deterministic; node:crypto in server.ts
   *  is the only production source. */
  mintCredential?: () => string;
  /*
   * #859: this process writes nothing in dashboard/config. On a hardened unit
   * it cannot (the directory is not in ReadWritePaths), and the revoke and
   * Accept new key edits it used to make are root's fleet broker's now, as
   * `revoke` and `repin`. There is no registry file handle here on purpose.
   */
  /** Re-read the registry in this process, the way a SIGHUP does. Called
   *  after a registry write so the page repaints from the file that is now
   *  on disk rather than from the one this process read at start-up. */
  reloadFleet?: () => void;
  /**
   * What this host's LAST attempt to seal the fleet model at rest reported
   * (#443).
   *
   * Kept by the caller that made the call, never derived from a later read
   * of the store: a broker with no store verbs answers the write and the
   * read the same way, and a store that was fine before a failed write would
   * otherwise read as proof the write landed.
   */
  lastStoreWrite?: () => StoreWriteNote | null;
  /**
   * Write one entry to a node's own Advisor ledger (#455).
   *
   * Injected for the same reason verifyPairGrant below is: so a test can
   * drive the two node controls through the real gate and the real ceremony
   * while standing in for the one step that leaves this host. Production
   * passes nothing and gets lib/advisor-ledger-append.ts's own, which signs
   * with this host's fleet key and posts over the peer's advisor origin.
   *
   * Never a way to make the act depend on it: both callers treat a failure
   * as a copy that did not land, and say so.
   */
  appendAdvisorLedger?: typeof appendFleetRecord;
  /**
   * The aggregator's OWN second copy of the same entry (#477): the same
   * record appendAdvisorLedger above was given, re-signed with issuer_label
   * "self" and posted to this host's own co-located advisord over loopback.
   *
   * Injected for the same reason appendAdvisorLedger is: a test drives both
   * calls in order without leaving this process. Production passes nothing
   * and gets lib/advisor-ledger-append.ts's own, called with this host's own
   * advisorUrl/advisorToken/selfAdvisorPresence below.
   *
   * Never a way to make either act depend on it: attempted whether or not
   * the node's own copy landed, and a failure here never undoes anything.
   */
  appendOwnAdvisorLedger?: typeof appendOwnFleetRecord;
  /** The passkey check on an approval. Injected for ONE reason: so a test
   *  can drive these four routes through the REAL settingsGate, the real
   *  session lookup and the real record comparison while standing in for
   *  the one step that needs an authenticator (P3-061). Production passes
   *  nothing and gets auth.ts's own. Never a way to weaken the gate: a
   *  stub here still meets every check around it. */
  verifyPairGrant?: typeof verifyPairGrant;
  /** The passkey check on a catch-up, injected for exactly the reason
   *  verifyPairGrant above is: so a test can drive the route through the real
   *  gate, the real session lookup and the real record comparison while
   *  standing in for the one step that needs an authenticator. */
  verifyCatchupGrant?: typeof verifyCatchupGrant;
  /** The passkey check on a model seal. Same reason as verifyPairGrant: a
   *  test can drive /api/settings/model/seal through the REAL settingsGate,
   *  the real session lookup and the real pending-record comparison while
   *  standing in for the one step that needs an authenticator. Production
   *  passes nothing and gets auth.ts's own. */
  verifySeal?: SealVerifier;
  /** This host's own advisord, for the trust sync's read-back. Optional:
   *  without it a sync reports that the Advisor could not be read back,
   *  which is honest, rather than claiming agreement it did not observe. */
  advisorUrl?: string;
  advisorToken?: () => string | null;
  log?: (line: string) => void;
  /** Re-reads one node's whole ledger and reports every mismatch against
   *  what this dashboard has mirrored, ADR 0021 build step 3. Null return
   *  means the node named is not one this dashboard mirrors at all: a
   *  peer without an Advisor stack, a typo, or LOCAL_NODE on a
   *  dashboard-alone install. Optional: a build that has not wired the
   *  mirror in server.ts answers 501 rather than throwing. */
  reverifyAdvisorMirror?: (node: string) => Promise<Record<string, unknown> | null>;
  /**
   * The two calls attaching an Advisor makes to a node (#641), injected for
   * exactly the reason appendAdvisorLedger above is: so a test can drive the
   * whole ceremony, the real gate and the real broker payload while standing
   * in for the one step that leaves this host. Production passes neither and
   * gets lib/fleet-advisor-attach.ts's own.
   *
   * Never a way to weaken anything: the pin check, the signature and the
   * node's own reveal window all live inside the real implementations, and a
   * stub here still meets every check around them on this side.
   */
  peerAdvisorState?: typeof fetchPeerAdvisorState;
  revealAdvisorToken?: typeof revealPeerAdvisorToken;
  /** One node's Advisor status, read after an attach to learn whether it
   *  already has a model (#1037). The real read is fetchPeerAdvisor's, over
   *  the row the attach just wrote; a test stands in for the node. */
  peerAdvisorStatus?: (node: FleetNodeConfig) => ReturnType<typeof fetchPeerAdvisor>;
  /** The wait between an attach's ledger-copy attempts (#641), injected so a
   *  test can drive all four without spending nine seconds of wall clock on
   *  it. Production passes nothing and gets a real timer. Never a way to
   *  change how many attempts there are, or which outcomes retry: both of
   *  those are the module's, where they can be read. */
  sleep?: (ms: number) => Promise<void>;
}

const OVERVIEW_PATH = '/api/settings/overview';
const AUDIT_PATH = '/api/settings/audit';
/** #216. One table rather than seven string comparisons, so a route cannot
 *  be added below the gate by accident. */
export const OPERATOR_ROUTES: Record<string, OperatorRoute> = {
  '/api/settings/operators/add/begin': 'add/begin',
  '/api/settings/operators/add': 'add',
  '/api/settings/operators/link': 'link',
  '/api/settings/operators/role/begin': 'role/begin',
  '/api/settings/operators/role': 'role',
  '/api/settings/operators/revoke': 'revoke',
  '/api/settings/operators/remove': 'remove',
};
/**
 * Pairing (ADR 0019 phase 3). One table, the OPERATOR_ROUTES shape, so a
 * route cannot be added below the gate by accident.
 */
export const PAIR_ROUTES = {
  '/api/settings/pair/ready': 'ready',
  '/api/settings/pair/mint': 'mint',
  '/api/settings/pair/approve/begin': 'approve/begin',
  '/api/settings/pair/approve': 'approve',
  '/api/settings/pair/refuse': 'refuse',
} as const;
/**
 * Bringing a node up to date on the fleet's sealed model (ADR 0019 phase 4,
 * #168). The PAIR_ROUTES shape, beside it, so a route cannot be added below
 * the gate by accident.
 *
 * Two halves of one ceremony, and the binding between them is the challenge
 * record: the targets and the descriptor an operator was shown are written at
 * begin and read back from that record at finish, never from the request that
 * carries the signature.
 */
export const MODEL_ROUTES = {
  '/api/settings/model/catchup/begin': 'catchup/begin',
  '/api/settings/model/catchup': 'catchup',
} as const;
const JOB_PATH_RE = /^\/api\/settings\/model\/seal\/job\/([A-Za-z0-9_-]{1,64})$/;
const CATCHUP_JOB_PATH_RE = /^\/api\/settings\/model\/catchup\/job\/([A-Za-z0-9_-]{1,64})$/;
const LABEL_RE = /^[a-z0-9-]{1,32}$/;
/** No more nodes in one approval than a fleet could plausibly hold. A bound
 *  rather than a limit anybody will meet: an unbounded targets array is an
 *  unbounded fan-out started by one request. */
const MAX_TARGETS = 64;

/**
 * The overview is assembled from four loopback reads per peer, and a page
 * left open must not be able to drive that rate. Five seconds is short
 * enough that an operator who has just armed a host and refreshed sees it,
 * and long enough that a poll cannot become a storm (the shape issues #93,
 * #105 and #119 all shared).
 */
const OVERVIEW_CACHE_MS = 5_000;

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

/** As in auth.ts: the shared read, with this page's default cap and a throw. */
async function readBody(req: IncomingMessage, maxBytes = 16 * 1024): Promise<string> {
  return readBodyOrThrow(req, maxBytes);
}

let overviewCache: { at: number; body: Record<string, unknown> } | null = null;

/**
 * What each node's Advisor was last OBSERVED to be, by target label.
 *
 * The seal resolver needs to refuse a node that has no Advisor, and the only
 * honest source for that is an observation. A live probe at /seal/begin
 * would put a fan-out between the operator's click and their authenticator
 * prompt, and it would fold "slow" into "absent", which is the one
 * distinction this whole panel keeps apart. So the overview, which the page
 * has always just read, leaves its observation here and the resolver refuses
 * only on a POSITIVE `absent`. Anything else it lets through, and the node's
 * own gate refuses it by name if it must.
 */
const advisorSeen = new Map<string, 'present' | 'absent' | 'unread'>();

/**
 * What each node's model verdict was last OBSERVED to be, by target label.
 *
 * The catch-up resolver needs to refuse a node that needs nothing, and the
 * only honest source for that is the same observation the page renders. Kept
 * beside advisorSeen, written in the same place, and read the same way: only
 * a POSITIVE `in_sync` refuses. A node this dashboard has not looked at is
 * let through, because refusing on silence would leave a node behind forever.
 */
const syncSeen = new Map<string, NodeSync>();

/** Test seam: a fresh process starts with no cache, and a test that drives
 *  two overviews in a row should not be answered by the first. */
export function clearSettingsOverviewCache(): void { overviewCache = null; }

/** Test seam, separate from the cache on purpose: clearing the cache after a
 *  seal must not also forget which nodes have an Advisor. */
export function clearSettingsAdvisorMemory(): void { advisorSeen.clear(); syncSeen.clear(); }

/**
 * The dispatcher. Returns true when it answered, false when the path is not
 * one of its own, exactly as handleKnowledgeAdmin does, so server.ts calls it
 * once and falls through otherwise.
 */
/**
 * Signed in, an admin, and carrying the CSRF header on anything that is not
 * a read. In that order, and as a value rather than three returns inside the
 * dispatcher, so the ORDER itself can be asserted: a monitor posting without
 * the header has to be told about their role, because a csrf answer would
 * tell an unprivileged caller that their role was never the problem.
 *
 * Returns the refusal, or null when the request may proceed.
 */
export function settingsGate(input: {
  session: { role: string } | null; method: string; csrf: boolean;
}): { status: number; body: Record<string, unknown> } | null {
  if (!input.session) return { status: 401, body: { error: 'unauthenticated' } };
  if (!isAdmin(input.session.role)) {
    return {
      status: 403,
      body: {
        error: 'this operator may not change settings',
        detail: `Role is ${input.session.role}. Settings changes what every node runs, and that is an admin's to do.`,
      },
    };
  }
  if (input.method !== 'GET' && !input.csrf) return { status: 403, body: { error: 'csrf' } };
  return null;
}

export async function handleSettingsAdmin(
  req: IncomingMessage, res: ServerResponse, pathname: string, deps: SettingsAdminDeps,
): Promise<boolean> {
  if (!pathname.startsWith('/api/settings/')) return false;

  // Admin, then CSRF on anything that is not a read. Both here rather than
  // per route: a route added below inherits the gate rather than remembering
  // to ask for it, which is the way one of them eventually would not.
  const sess = readSession(req);
  const refusal = settingsGate({ session: sess, method: req.method ?? 'GET', csrf: csrfOk(req) });
  if (refusal) { send(res, refusal.status, refusal.body); return true; }
  // settingsGate refuses a null session first, so this is not an assumption.
  const session = sess as AuthSessionInfo;
  const isGet = req.method === 'GET';

  if (pathname === OVERVIEW_PATH) {
    if (!isGet) { send(res, 405, { error: 'method_not_allowed' }); return true; }
    const now = Date.now();
    let body: Record<string, unknown>;
    if (overviewCache && now - overviewCache.at < OVERVIEW_CACHE_MS) {
      body = overviewCache.body;
    } else {
      body = await buildOverview(deps);
      overviewCache = { at: now, body };
    }
    // Outside the cache, deliberately. Every other field here is a fact
    // about the fleet and is the same for whoever asked; `accounts` carries
    // is_self, which is a fact about the ASKER. Cached with the rest, the
    // second admin to open the page would be shown the first one's row as
    // their own, and the guards that refuse self-removal would disagree
    // with the page that offered it. These are local reads.
    body = { ...body, accounts: buildAccounts(operatorDeps(deps, session), session.userId, session.credentialId) };
    send(res, 200, body);
    return true;
  }

  /**
   * The auth audit, newest first.
   *
   * Read straight out of auth_events with nothing added. The recorder's rule
   * is what makes this safe to serve: no key material and no tokens go into
   * a row, so there is nothing here to filter on the way out. Admin only,
   * like everything else on this page, because the table names who holds
   * which role.
   */
  if (pathname === AUDIT_PATH) {
    if (!isGet) { send(res, 405, { error: 'method_not_allowed' }); return true; }
    const q = new URL(req.url ?? '', 'http://dashboard.invalid').searchParams;
    send(res, 200, { events: mapAuditEvents(queryAuthEvents(clampAuditLimit(q.get('limit')))) });
    return true;
  }

  // The operator section (#216). The gate above has already run; what is
  // here is the body, and the decisions live in lib/operator-admin.ts.
  const operatorRoute = OPERATOR_ROUTES[pathname];
  if (operatorRoute) {
    if (req.method !== 'POST') { send(res, 405, { error: 'method_not_allowed' }); return true; }
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse((await readBody(req)) || '{}');
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch { send(res, 400, { error: 'could not read the request' }); return true; }

    let result: OperatorResult;
    try {
      result = await handleOperatorRoute(operatorRoute, {
        session: { userId: session.userId, username: session.username, role: session.role, credentialId: session.credentialId },
        payload,
        // Called only when a challenge id was presented, and it verifies the
        // assertion on THIS request against the record written at begin.
        verify: () => verifyOperatorGrant(req, payload),
        beginGrant: (grant) => beginOperatorGrant(req, grant),
        deps: operatorDeps(deps, session),
      });
    } catch (err) {
      result = operatorFailure(err);
      if (result.status === 500) console.error('[settings] the operator change failed:', err);
    }
    // Any of these changes what the page shows about an account, and one of
    // them changes what every node reports about its trust set.
    clearSettingsOverviewCache();
    send(res, result.status, result.body);
    return true;
  }

  if (pathname === '/api/settings/model/test' && req.method === 'POST') {
    // The existing handler, unchanged and unwrapped: it does its own admin
    // check, holds the key for one outbound request and clears it in a
    // finally. There is nothing this file could add to it but a second copy.
    await handleAdvisorModelTest(req, res);
    return true;
  }

  if (pathname === '/api/settings/model/seal/begin' && req.method === 'POST') {
    await handleSettingsSealBegin(req, res, targetResolver(deps));
    return true;
  }

  if (pathname === '/api/settings/model/seal' && req.method === 'POST') {
    await handleSettingsSealFinish(req, res, (seal) => deps.jobs.start({
      baseUrl: seal.baseUrl,
      shape: seal.shape,
      model: seal.model,
      credentialName: seal.credentialName,
      grantedBy: seal.operator,
      grantedRole: seal.role,
      credentialId: seal.credentialId,
      targets: seal.targets,
    }, seal.key), deps.verifySeal);
    // A seal changes what every targeted node is about to report, so the
    // page's next overview must not be answered from before it.
    clearSettingsOverviewCache();
    return true;
  }

  const catchupJobMatch = CATCHUP_JOB_PATH_RE.exec(pathname);
  if (catchupJobMatch) {
    if (!isGet) { send(res, 405, { error: 'method_not_allowed' }); return true; }
    const job = catchupJobs.get(catchupJobMatch[1]);
    if (!job) {
      send(res, 404, {
        error: 'no_such_job',
        detail: 'That catch-up has finished and its record has expired, or it was never started here.',
      });
      return true;
    }
    send(res, 200, job);
    return true;
  }

  const jobMatch = JOB_PATH_RE.exec(pathname);
  if (jobMatch) {
    if (!isGet) { send(res, 405, { error: 'method_not_allowed' }); return true; }
    const status = deps.jobs.get(jobMatch[1]);
    if (!status) {
      send(res, 404, {
        error: 'no_such_job',
        detail: 'That seal has finished and its record has expired, or it was never started here.',
      });
      return true;
    }
    send(res, 200, status);
    return true;
  }

  if (pathname === '/api/settings/trust/push' && req.method === 'POST') {
    await handleTrustPush(req, res, deps);
    return true;
  }

  const modelRoute = MODEL_ROUTES[pathname as keyof typeof MODEL_ROUTES];
  if (modelRoute) {
    if (req.method !== 'POST') { send(res, 405, { error: 'method_not_allowed' }); return true; }
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse((await readBody(req)) || '{}');
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch { send(res, 400, { error: 'could not read the request' }); return true; }
    const answer = await handleCatchupRoute(modelRoute, req, payload, deps);
    // A catch-up changes what every node it touched is about to report, so
    // the page's next overview must not be answered from before it.
    clearSettingsOverviewCache();
    send(res, answer.status, answer.body);
    return true;
  }

  // The Add an Advisor watch (#641). ONE node, named in the query, read
  // live off that node's own dashboard.
  //
  // WHY IT IS NOT ON THE OVERVIEW. "One read builds the page"
  // (settings-walk.mjs) is a rule about the page's ten-second poll, and this
  // is not that: it fires only while an operator has a node picked on the
  // Add an Advisor card, for that node alone, and stops the moment the row
  // folds or they navigate away. Folding it into the overview would make
  // every dashboard poll a fan-out across the whole fleet, forever, to
  // answer a question almost nobody is asking at any given moment.
  //
  // IT CHANGES NOTHING AND CARRIES NO SECRET, on either side: the node's own
  // advisor/state route is a free GET behind the read token, and this
  // forwards its three facts plus a build stamp. The reveal, which is the
  // one call that returns a credential, is a separate signed POST behind a
  // passkey and a window on the node.
  if (pathname === ADVISOR_WATCH_PATH) {
    if (!isGet) { send(res, 405, { error: 'method_not_allowed' }); return true; }
    const label = new URL(req.url ?? '', 'http://127.0.0.1').searchParams.get('node') ?? '';
    // nodeTarget's own rules, reached with a query value rather than a body:
    // a bad label is a 400, this host's own row is a 409, an unknown label
    // is a 404. Never a fan-out, and never a probe of a node nobody named.
    const target = nodeTarget(deps, { label });
    if (!target.ok) { send(res, target.status, target.body); return true; }
    const node = target.node;
    const attached = Boolean(node.advisor_origin);
    // AN ATTACHED ROW IS READ TOO, and this is deliberate rather than an
    // oversight worth short-circuiting. A peer's Advisor is DECLARED on this
    // side, never probed (ADR 0016 decision 7), so an address that stops
    // answering reads as `installed-but-down` whether the Advisor was
    // uninstalled on that box or is merely down. The node's own presence is
    // the only thing that tells those apart, and telling them apart is what
    // #641 asks the Advisor tab to do. One read, the same read, either way.
    const got = await (deps.peerAdvisorState ?? fetchPeerAdvisorState)(node);
    const watch = advisorWatchState(got);
    const reading = advisorAttachedReading(got);
    const said = advisorStateSaid(got);
    send(res, 200, {
      label: node.label,
      attached,
      /** Which of the two questions this row is answering. An unattached row
       *  carries `watch` (is there one to attach) and an attached one
       *  carries `reading` (the one we hold, is it still there). Both are
       *  decided here, where the registry is, never on the page. */
      ...(attached ? { reading } : { watch }),
      /** Only an unattached, pinned row whose node answered present may
       *  attach. */
      can_attach: !attached && watch === 'ready' && Boolean(node.expected_pubkey_node),
      pinned: Boolean(node.expected_pubkey_node),
      version: got.ok ? got.state.version : null,
      last_answered_ms: got.ok ? got.state.last_answered_ms : null,
      /** THIS SIDE's sentence. */
      detail: attached ? ADVISOR_ATTACHED_COPY[reading] : ADVISOR_WATCH_COPY[watch],
      /** THAT NODE's, and only ever that: null whenever the node sent none,
       *  which is every timeout and every answer whose body means nothing.
       *  Never this side's own sentence under a "that node said" label. */
      said: said ?? null,
      /** Why the read produced nothing, in this side's words, where the
       *  state copy above is about what the row now means. These are two
       *  sentences and not one: "update this node first" is the state, and
       *  "that node's dashboard has no fleet write API" is how this host
       *  found out. Null on a read that worked. */
      why: got.ok ? null : got.detail,
      reason: got.ok ? null : got.reason,
      install_command: ADVISOR_INSTALL_CMD,
    });
    return true;
  }

  // The controls on a registered node's row (#444, #422, #641). The same
  // table shape as PAIR_ROUTES and MODEL_ROUTES above, so a route cannot be
  // added below the gate by accident.
  const nodeRoute = NODE_ROUTES[pathname as keyof typeof NODE_ROUTES];
  if (nodeRoute) {
    if (req.method !== 'POST') { send(res, 405, { error: 'method_not_allowed' }); return true; }
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse((await readBody(req)) || '{}');
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch { send(res, 400, { error: 'could not read the request' }); return true; }
    const answer = await handleNodeRoute(nodeRoute, req, payload, deps, session);
    // A revoke drops a row and a re-pin changes one, so the page's next
    // overview must not be answered from before it.
    clearSettingsOverviewCache();
    send(res, answer.status, answer.body);
    return true;
  }

  const pairRoute = PAIR_ROUTES[pathname as keyof typeof PAIR_ROUTES];
  if (pairRoute) {
    if (req.method !== 'POST') { send(res, 405, { error: 'method_not_allowed' }); return true; }
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse((await readBody(req)) || '{}');
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch { send(res, 400, { error: 'could not read the request' }); return true; }
    if (pairRoute === 'ready') {
      // Changes no pairing state, so the overview cache is left alone.
      const ready = await pairReadiness(deps);
      send(res, ready.status, ready.body);
      return true;
    }
    if (pairRoute === 'mint') {
      // `replaces` is the hash of a code minted earlier from the same step
      // (#607): the page sends it only after the operator confirmed "Mint a
      // new code?", never on the click that mints the first one.
      // `name` (#635) is what the operator typed into "Name this node"
      // before minting, optional and validated inside mintPairing.
      const minted = await mintPairing(deps, session, Date.now(), payload.replaces, payload.name);
      send(res, minted.status, minted.body);
      return true;
    }
    const answer = await handlePairRoute(pairRoute, req, payload, deps, session);
    // The Pending block rides the overview body, so an approval or a refusal
    // must not be answered from a cache taken before it.
    clearSettingsOverviewCache();
    send(res, answer.status, answer.body);
    return true;
  }

  // The Advisor ledger mirror's re-verify, ADR 0021 build step 3. A chain
  // break stops the poller on that node until this runs, admin-gated like
  // every other write on this page, because it is what decides a node's
  // mirror is trustworthy again.
  if (pathname === '/api/settings/advisor-mirror/reverify' && req.method === 'POST') {
    if (!deps.reverifyAdvisorMirror) {
      send(res, 501, { error: 'not_available', detail: 'this dashboard has no mirror to re-verify' });
      return true;
    }
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse((await readBody(req)) || '{}');
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch { send(res, 400, { error: 'could not read the request' }); return true; }
    const node = typeof payload.node === 'string' ? payload.node : '';
    if (!node) { send(res, 400, { error: 'a node is required' }); return true; }
    const result = await deps.reverifyAdvisorMirror(node);
    if (!result) {
      send(res, 404, { error: 'no_such_node', detail: `"${node}" is not a node this dashboard mirrors` });
      return true;
    }
    send(res, 200, result);
    return true;
  }

  // Promoting a mirrored memory entry into fleet knowledge, ADR 0021 build
  // step 5, issue #232. Settings-side by decision (ADR 0021 §5's "Settings
  // is the one place for fleet config"), and never automatic: this route
  // exists to be clicked, once, by an admin who read the entry in the
  // Advisor tab's read-only mirror list and decided it belonged in fleet
  // knowledge. The write itself, the lint, the rollback and the push are
  // knowledge-admin.ts's promoteMemoryNote, the same machinery
  // promoteProposal already runs, so there is exactly one implementation of
  // "write a knowledge file and push it" in this codebase.
  if (pathname === '/api/settings/memory/promote' && req.method === 'POST') {
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse((await readBody(req)) || '{}');
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch { send(res, 400, { error: 'could not read the request' }); return true; }
    const user = getUserById(session.userId);
    const out = await promoteMemoryNote(payload, {
      paths: knowledgePaths(deps.repoDir),
      repoDir: deps.repoDir,
      operator: user?.username ?? `user:${session.userId}`,
      role: session.role,
      selfLabel: deps.selfNode()?.label ?? null,
      log: deps.log ?? ((line: string) => console.log(line)),
      lookup: memoryMirrorRow,
      stamp: memoryMirrorMarkPromoted,
    });
    send(res, out.status, out.body);
    return true;
  }

  send(res, 404, { error: 'unknown_settings_path' });
  return true;
}

/**
 * What a throw out of the operator section means to the caller.
 *
 * One case is not a bug: the duplicate check is a read followed by a write,
 * and two admins adding the same address in the same instant both pass it.
 * The second one's INSERT hits the UNIQUE index on auth_users.username and
 * throws. That is the same refusal the check would have made a moment
 * earlier, so it is answered the same way and the race is invisible to the
 * page. Nothing else here inserts into a unique column: the magic-link token
 * is 256 random bits, and no credential is created on any of these routes.
 *
 * Anything else is answered as a failure in the page's own shape, because
 * the server's outer handler answers a plain-text 500 and the page is
 * reading JSON. The message never carries the error's own text.
 */
export function operatorFailure(err: unknown): OperatorResult {
  const code = String((err as { code?: unknown })?.code ?? '');
  if (code.startsWith('SQLITE_CONSTRAINT')) {
    return { status: 409, body: { error: 'that operator already exists' } };
  }
  return { status: 500, body: { error: 'that change could not be completed' } };
}

/**
 * The operator section's effects, wired to this host's real tables, real CLI
 * and real socket.
 *
 * Built per request because two of them are bound to the acting operator:
 * every audit row this writes names the session's account, and the trust
 * sync's own row does too. A module-level singleton would have to be told
 * who was asking on every call, which is the same argument written less
 * obviously.
 */
function operatorDeps(deps: SettingsAdminDeps, sess: AuthSessionInfo): OperatorAdminDeps {
  // Built on first use, not here. Wiring the runners reads the Advisor's
  // token off disk, and the overview asks for these deps on every poll to
  // render `accounts` while touching none of the three. A synchronous file
  // read on a polled route is the shape of #93, #105 and #119.
  let runners: ReturnType<typeof trustChangeRunners> | null = null;
  const trust = (): ReturnType<typeof trustChangeRunners> => (runners ??= trustChangeRunners(
    { username: sess.username, role: sess.role },
    { url: deps.advisorUrl, token: deps.advisorToken ? deps.advisorToken() : null },
    'auto after a Settings change',
  ));
  const log = deps.log ?? ((line: string) => console.log(line));
  return {
    users: () => getAllUsers(),
    credentials: (userId) => getCredentialsForUser(userId).map((c) => ({
      id: c.id, credential_id: c.credential_id, name: c.name,
      created_at: c.created_at, last_used_at: c.last_used_at,
    })),
    liveSessions: (userId) => liveSessionCount(userId),
    pendingLink: (userId) => latestPendingLink(userId),
    createOperator: (email, role) => createOperator(email, role),
    setRole: (userId, role) => { setUserRole(userId, role); },
    removeOperator: (userId) => deleteOperator(userId),
    revokeCredential: (credId, actor) => revokeCredentialById(credId, actor),
    endSessionsForUser: (userId) => endSessionsForUser(userId),
    endSessionsForCredential: (handle) => endSessionsForCredential(handle),
    issueLink: (userId, purpose) => issueEnrollmentLink(userId, purpose),
    sendLink: (to, url) => emailEnrollmentLink(to, url),
    fingerprint: () => trust().fingerprint(),
    push: (before, after) => trust().push(before, after),
    sync: (before, after) => trust().sync(before, after),
    record: (e) => recordAuthEvent(e),
    log,
  };
}

/**
 * Which nodes an approval may cover, resolved against the registry BEFORE
 * the passkey is spent. 'self' is this host; every other entry must be a
 * label this dashboard already knows, so a targets array cannot name a host
 * this process was never told about.
 */
function targetResolver(deps: SettingsAdminDeps): SealTargetResolver {
  return (raw: unknown) => resolveSealTargets(raw, {
    known: new Set(deps.peers().map((p) => p.label)),
    seen: (label) => advisorSeen.get(label) ?? null,
  });
}

/**
 * The resolution itself, with its two inputs handed in.
 *
 * Separated from the factory so it can be exercised without a fleet: the
 * gate it carries (a node observed to have no Advisor is refused before the
 * passkey is touched) is the only one on this route, and a gate nothing
 * asserts is a comment.
 */
export function resolveSealTargets(
  raw: unknown,
  ctx: { known: Set<string>; seen: (label: string) => 'present' | 'absent' | 'unread' | null },
): { ok: true; targets: string[] } | { ok: false; error: string } {
  if (!Array.isArray(raw) || raw.length === 0) {
    return { ok: false, error: 'name at least one node to seal on' };
  }
  if (raw.length > MAX_TARGETS) {
    return { ok: false, error: `that is more than ${MAX_TARGETS} nodes in one approval` };
  }
  const targets: string[] = [];
  for (const entry of raw) {
    const label = String(entry);
    if (label === SELF_TARGET) {
      // Only a POSITIVE observation refuses. A node this dashboard has not
      // looked at, or looked at and could not read, is let through and the
      // node's own gate refuses it by name if it must. Refusing on silence
      // would turn a blip into "you have no Advisor".
      if (ctx.seen(SELF_TARGET) === 'absent') {
        return { ok: false, error: 'this dashboard has no Advisor, so there is nothing on it to configure' };
      }
      if (!targets.includes(SELF_TARGET)) targets.push(SELF_TARGET);
      continue;
    }
    if (!LABEL_RE.test(label) || !ctx.known.has(label)) {
      return { ok: false, error: `this dashboard has no node called "${label}"` };
    }
    if (ctx.seen(label) === 'absent') {
      // What this dashboard knows is that it holds no Advisor address for
      // that node, which is a fact about its own registry row. Said that
      // way rather than as a claim about the far side.
      return {
        ok: false,
        error: `this dashboard holds no Advisor address for "${label}", so it has nothing there to configure`,
      };
    }
    if (!targets.includes(label)) targets.push(label);
  }
  return { ok: true, targets };
}


/** One node's Advisor facts from a status document, or the reason there are
 *  none. Shared by the self row and every peer row so the two cannot render
 *  differently for the same state. */
function advisorFrom(
  doc: AdvisorStatusDoc | null,
  presence: 'present' | 'absent' | 'unread',
  reason?: string,
): NodeAdvisorSettings {
  if (!doc) {
    return {
      present: false, presence: presence === 'present' ? 'unread' : presence,
      version: null, model: null, trust: null, ...(reason ? { reason } : {}),
    };
  }
  return {
    present: true,
    presence: 'present',
    version: typeof doc.version === 'string' ? doc.version : null,
    model: doc.model ?? null,
    trust: doc.trust ?? null,
  };
}

/**
 * A peer that did not answer: is that node without an Advisor, or is it a
 * node whose Advisor this dashboard could not reach?
 *
 * `advisor_not_configured` is the one answer of the first kind. It is not a
 * failed request at all: the node's own registry row carries no Advisor
 * origin, so this dashboard has been told there is nothing there. Every
 * other code is a request that did not land, and a request that did not land
 * says nothing about what is installed on the far side.
 */
function presenceFromError(error: string | undefined): 'absent' | 'unread' {
  return error === 'advisor_not_configured' ? 'absent' : 'unread';
}

/** The model block a node reports, if it reported one. */
function modelOf(advisor: NodeAdvisorSettings): NodeModelReport | null {
  const m = advisor.model;
  return m && typeof m === 'object' ? (m as NodeModelReport) : null;
}

/**
 * The fleet's setting, and where it came from.
 *
 * 'record'  a fleet seal from this page wrote it down.
 * 'self'    there is no record, and this dashboard's own Advisor has a model.
 *           A fresh install sealed from the Advisor tab before Settings
 *           existed is exactly this case, and taking its model as the fleet's
 *           is better than telling an operator with a working Advisor that
 *           the fleet has no model. The first change made from Settings
 *           writes the record and the source becomes 'record'.
 * 'none'    neither. Nothing to hold any node against.
 */
function fleetSetting(
  record: FleetModelRecord | null, selfAdvisor: NodeAdvisorSettings,
): { model: FleetModelRecord | null; source: 'record' | 'self' | 'none' } {
  if (record) return { model: record, source: 'record' };
  const m = modelOf(selfAdvisor);
  const baseUrl = typeof m?.base_url === 'string' ? m.base_url : '';
  const name = typeof m?.name === 'string' ? m.name : '';
  if (!m || m.configured === false || !baseUrl || !name) return { model: null, source: 'none' };
  return {
    source: 'self',
    model: {
      v: 1,
      base_url: baseUrl,
      provider: providerNameFor(baseUrl),
      model: name,
      key_hint: typeof m.key_hint === 'string' ? m.key_hint : '',
      // This host's own seal time, which is the only time anybody wrote it.
      sealed_at: typeof m.configured_at === 'string' ? m.configured_at : '',
      // Nobody approved this AS a fleet setting, so there is no operator to
      // name. The page prints the when and leaves the by-whom off.
      sealed_by: null,
      targets: [],
    },
  };
}

async function buildOverview(deps: SettingsAdminDeps): Promise<Record<string, unknown>> {
  const view = deps.fleetView();
  const rows = view?.nodes ?? [];
  const rowFor = (label: string): FleetPeerPublic | undefined => rows.find((n) => n.label === label);
  // The serial the next push would carry, and null when this host cannot
  // push at all. trustFingerprint() is the same digest the bundle's `serial`
  // is, so there is no second derivation here (lib/trust-sync.ts settles
  // that question in its own comment).
  const currentSerial = readOwnPrivateKey(deps.fleetTrustPath) ? trustFingerprint().fingerprint : null;

  const selfNode = deps.selfNode();
  const selfLabel = selfNode?.label ?? 'this node';
  const selfRow = rowFor(selfLabel);
  let selfStatus: AdvisorStatusDoc | null = null;
  let selfReason: string | undefined;
  try {
    selfStatus = await deps.selfAdvisorStatus();
    if (!selfStatus) selfReason = 'advisor_not_answering';
  } catch {
    selfReason = 'advisor_not_answering';
  }
  // This host: it answered, or the ADR 0016 observation says whether there
  // is an Advisor here at all. 'installed-but-down' is an Advisor, down, so
  // it reads unread rather than absent.
  const selfPresence: 'present' | 'absent' | 'unread' = selfStatus
    ? 'present'
    : (deps.selfAdvisorPresence() === 'absent' ? 'absent' : 'unread');
  const selfAdvisor = advisorFrom(selfStatus, selfPresence, selfReason);
  const record = deps.fleetModel();
  const fleet = fleetSetting(record, selfAdvisor);

  // Read once: the key this node reports, and the registry's verdict on it as
  // the fleet assembly already judged it.
  const selfKey = deps.selfPubkeyNode();
  const selfPin = selfPinFactsFor(selfRow);

  const self: NodeSettings = {
    label: selfLabel,
    role: selfNode?.role ?? null,
    is_self: true,
    // This process is answering the request, so it is reachable by
    // definition. Its node's health is a different question and the fleet
    // card already answers it.
    reachable: true,
    transport: 'self',
    link_last_held_ms: null,
    host_name: deps.selfHostName(),
    // On a peer this column holds what the registry PINS; here it holds what
    // this node reports, because this row had no comparison to show until
    // #488 and the key an operator wants beside "this one" is the node's own.
    // The note under the row reads the pinned key out of pin_expected rather
    // than out of here, so the two meanings never cross.
    pubkey_node: selfKey,
    // There is no pin between this process and itself. There IS one between
    // the registry file on this disk and the node this process reads: a row
    // that pins a key this node does not have is dead config here and
    // fail-closed on every other host that reads this node through it, and
    // nothing said so (#488).
    // Mapped exactly as a peer's is on the line below: null when the row pins
    // nothing, true when the pin was proved, false for both ways it was not.
    // One field, one meaning, on every row.
    pin_ok: selfPin.pin_state === null ? null : selfPin.pin_state === 'ok',
    ...selfPin,
    last_seen_ms: selfRow?.last_seen_ms ?? Date.now(),
    advisor: selfAdvisor,
    sync: computeNodeSync({
      presence: selfPresence, model: modelOf(selfAdvisor), fleet: fleet.model, source: fleet.source,
    }),
    arm: deps.selfArmState(),
    arm_reason: null,
    bundle: bundleFrom(selfStatus),
    current_serial: currentSerial,
  };

  // Settled, never raced, and bounded by each call's own timeout. One slow
  // node delays this response; it never removes another node's row.
  const peers = await Promise.all(deps.peers().map(async (node): Promise<NodeSettings> => {
    const row = rowFor(node.label);
    const [statusResult, armResult] = await Promise.all([
      fetchPeerAdvisor(node, { label: node.label, endpoint: 'status' }),
      fetchPeerArmState(node),
    ]);
    const link = node.transport === 'link' ? (deps.linkStatus?.(node.label) ?? null) : null;
    const status = statusResult.ok ? (statusResult.body as AdvisorStatusDoc) : null;
    const presence = status ? 'present' as const : presenceFromError(statusResult.ok ? undefined : statusResult.error);
    const advisor = advisorFrom(status, presence, statusResult.ok ? undefined : statusResult.error);
    return {
      label: node.label,
      role: node.role ?? null,
      is_self: false,
      // Unchanged, and deliberately: reachability is what the fleet poll
      // observed on this node's read origin, whatever carried it. A link that
      // is up says nothing about whether the node behind it answered.
      reachable: row ? row.verdict !== 'unreachable' : statusResult.ok,
      transport: node.transport === 'link' ? 'link' : 'loopback',
      link_last_held_ms: link ? link.last_held_ms : null,
      host_name: row?.host_name ?? null,
      pubkey_node: node.expected_pubkey_node ?? null,
      pin_ok: node.expected_pubkey_node ? (row?.verified ?? false) : null,
      ...pinFacts(node, row),
      last_seen_ms: row?.last_seen_ms ?? null,
      advisor,
      // #641. The REGISTRY's own fact, and not the presence reading above:
      // does this aggregator hold an address for that node's Advisor. The
      // two answer different questions and the page needs both. An Advisor
      // that is merely down is still one this fleet holds an address for and
      // can still be removed; a node that answers `present` on its own box
      // but has never been attached is not one this page can remove
      // anything from. Reading it off the row is also free and cannot fail.
      advisor_attached: Boolean(node.advisor_origin),
      sync: computeNodeSync({ presence, model: modelOf(advisor), fleet: fleet.model, source: fleet.source }),
      arm: armResult.ok ? armResult.state : null,
      arm_reason: armResult.ok ? null : armResult.reason,
      bundle: bundleFrom(status),
      current_serial: currentSerial,
    };
  }));

  // What the resolver reads at /seal/begin. Written here because this is the
  // one place that observes every node, and the page cannot start a seal
  // without having read this route first.
  advisorSeen.set(SELF_TARGET, self.advisor.presence);
  syncSeen.set(SELF_TARGET, self.sync);
  for (const p of peers) {
    advisorSeen.set(p.label, p.advisor.presence);
    syncSeen.set(p.label, p.sync);
  }

  // The pairings this dashboard is holding, on the body the page already
  // polls rather than on a route of its own: the five-second cache then
  // bounds the rate, and a Pending row appears on the same refresh that
  // repaints the registry it is about to join.
  const pending = deps.pairings?.() ?? [];
  // One broker call per overview, and the five-second cache above is what
  // bounds its rate. Never throws: a host with no broker passes no dep and
  // the page prints no sealed-copy line at all, rather than an empty one.
  let storeHead: BrokerStoreHeadOutcome | null = null;
  if (deps.storeHead) {
    try {
      storeHead = await deps.storeHead();
    } catch {
      // Not `none`. A dep that threw says nothing about what the store holds,
      // and the sentence for `none` instructs a re-paste of a live key.
      storeHead = { state: 'unread', reason: 'no_answer', detail: BROKER_BUSY_DETAIL };
    }
  }
  const fleetTrustKey = deps.fleetTrustPubKey?.() ?? null;
  const thisDash = deps.thisDashboard();
  let storeWrite: StoreWriteNote | null;
  try { storeWrite = deps.lastStoreWrite?.() ?? null; } catch { storeWrite = null; }

  // #1057: the rows this dashboard holds back. One short object each, never
  // a fan-out: nothing about a held node is read.
  const heldFleet = deps.held?.() ?? { nodes: [], reason: null };
  return {
    self,
    peers,
    held: heldFleet.nodes.map((n) => ({
      label: n.label,
      role: n.role ?? null,
      transport: n.transport === 'link' ? 'link' : 'loopback',
      pubkey_node: n.expected_pubkey_node ?? null,
      reason: heldFleet.reason,
    })),
    pending,
    /**
     * Where the pairing fingerprint comes from, and never the fingerprint
     * (#741, ruling 2026-09-30).
     *
     * A node asks the operator to paste one value over this aggregator's
     * fleet trust key and its fleet arm key. This page used to show the trust
     * key's fingerprint for the comparison, and this page is served by the
     * one account that could put a different arm key in front of a node: a
     * value it showed could be substituted with it. So the only reference is
     * root's own output, and what the page carries is the fixed, root-owned
     * command that prints it: the same words the node's prompt uses, never a
     * path this process chose. Null on a host that signs for no fleet.
     */
    pairing_fingerprint: fleetTrustKey ? { command: PAIRING_FINGERPRINT_COMMAND } : null,
    /**
     * The line that arms, with no flags (#812). `installed` is whether the
     * fleet broker grant put its root-owned copy on root's PATH here; when
     * it did, the command is that fixed name and never a path. The page adds
     * --self-only or --node <label> and composes nothing else.
     * `broker` is whether the fleet broker is here at all. Without it there
     * is nothing to arm and nothing for an update to place: the line is the
     * grant install, and the page adds no flag to it.
     */
    fleet_arm: (() => {
      const installed = armInstalledOf(deps);
      const broker = brokerInstalledOf(deps);
      return {
        installed, broker,
        command: installed || broker ? fleetArmCommand(installed) : grantInstallSentence(installDirOf(deps)),
      };
    })(),
    /**
     * The command that opens THIS aggregator's sealing window for a catch-up
     * (#1182), exactly the one the `arm_closed` refusal prints, built by the
     * same function so the two cannot drift. Null where there is no fleet
     * broker here and nothing to place, which is the case `fleet_arm.command`
     * answers with the grant install instead.
     */
    arm_self_command: (() => {
      const installed = armInstalledOf(deps);
      return installed || brokerInstalledOf(deps) ? armSelfCommand(installed) : null;
    })(),
    // Without the key digest: that one is for the seal's own comparison.
    fleet_model: publicFleetModel(fleet.model),
    fleet_model_source: fleet.source,
    /**
     * Whether a node paired right now would inherit a model, and what it
     * would inherit (ADR 0019 phase 4, #168).
     *
     * The honest answer to a question neither the record nor any node's
     * status can give. Five states, and only `none` means "there is no
     * store": the sentence the page prints for that one tells an operator to
     * seal the fleet model again with the key, so a busy socket, a blob this
     * host cannot open and a broker older than the feature each keep their
     * own answer.
     *
     * The HOST of `base_url` is what goes on the line, not the provider
     * brand. That is the one field of the store a compromised dashboard can
     * rewrite with no root involved and no operator present (§7), and the
     * page is where it shows: a poisoned base renders as `evil.example`
     * beside the model name rather than as "Anthropic".
     */
    fleet_model_store: storeHead === null ? null : {
      state: storeHead.state,
      ...(storeHead.state === 'held' ? {
        model: storeHead.head.model,
        base_url_host: baseUrlHost(storeHead.head.base_url),
        credential_name: storeHead.head.credential_name,
        key_hint: storeHead.head.key_hint,
        sealed_at: storeHead.head.sealed_at,
        sealed_by: storeHead.head.sealed_by,
        method: storeHead.head.method,
        host_method: storeHead.head.host_method,
        other_form_at: storeHead.head.other_form_at,
      } : {}),
      ...('detail' in storeHead ? { detail: storeHead.detail } : {}),
    },
    /**
     * Whether the LAST attempt to seal the fleet model at rest landed (#443).
     *
     * A seal whose per-node rows all read `sealed` and whose store write
     * failed is the exact case the sealed copy exists to close: a node
     * paired next week inherits nothing, and Catch up has nothing to send.
     * On the lab aggregator the only place that said so was a log line, and the page
     * read as clean.
     *
     * The write's OWN outcome, kept by the host that made the call, and not
     * a later read of the store: a root service with no store verbs answers
     * both the same way, and a store that was fine before a failed write
     * would otherwise read as proof the write landed.
     *
     * Null on a host that has not tried one since it started, which is not
     * a failure and prints nothing.
     */
    fleet_model_store_write: storeWrite === null ? null : {
      ok: storeWrite.ok,
      at: storeWrite.at,
      ...(storeWrite.error ? { error: storeWrite.error } : {}),
      ...(storeWrite.detail ? { detail: storeWrite.detail } : {}),
      // Composed here, off this host's own measurement, so the page never
      // chooses these words a second time.
      ...(storeWriteLine(storeWrite) ? { line: storeWriteLine(storeWrite) } : {}),
    },
    operators: listOperatorPasskeys(),
    // The install line a fresh box runs to join THIS fleet, built here rather
    // than in the browser so it comes from the same origin rule the mint
    // command uses. It carries no code, cannot expire and cannot be spent, so
    // it rides the body the page already polls instead of a route.
    this_dashboard: {
      ...thisDash,
      install_join_command: installJoinCommandLine(thisDash.public_url),
      // What a relay on the node's own box must dial to reach this
      // dashboard (#135). Built here, beside the join line, so both come
      // off the same origin rule rather than off a browser's location bar.
      relay_ingest_url: relayIngestUrl(thisDash.public_url),
    },
  };
}

/**
 * What this dashboard knows about one row's pin, in the three states an
 * operator acts on differently (#422).
 *
 * Read off the fleet poll's own row, which reads the node's own identity
 * route in the same cycle it polls it. The two keys are only there when the
 * comparison actually failed: `checkIdentityPin` reports them on a mismatch
 * and nulls them on every path where it could not check, so a row that says
 * `changed` says it because a key was read and did not match, never because
 * one was missing.
 */
function pinFacts(
  node: FleetNodeConfig, row: FleetPeerPublic | undefined,
): { pin_state: NodeSettings['pin_state']; pin_reported: string | null; pin_expected: string | null } {
  if (!node.expected_pubkey_node) return { pin_state: null, pin_reported: null, pin_expected: null };
  if (row?.verified === true) return { pin_state: 'ok', pin_reported: null, pin_expected: null };
  const reported = typeof row?.pin_reported === 'string' ? row.pin_reported : null;
  const expected = typeof row?.pin_expected === 'string' ? row.pin_expected : null;
  // Both keys, from the comparison that failed, and the pinned one has to be
  // the one the registry holds NOW: a poll taken before an accept would
  // otherwise keep the row reading `changed` against a key nobody pins.
  if (reported && expected === node.expected_pubkey_node && reported !== expected) {
    return { pin_state: 'changed', pin_reported: reported, pin_expected: expected };
  }
  return { pin_state: 'unconfirmed', pin_reported: null, pin_expected: null };
}

/**
 * The same three states for THIS host's own row (#488), read off the row the
 * fleet view already carries rather than compared a second time here.
 *
 * That is the whole point of taking it from there. The comparison needs the
 * key this node reported AND whether this node answered at all, and only the
 * fleet assembly holds the second half: `selfPubkeyNode()` serves the last
 * snapshot, which on a node that has gone dark is a reading nobody took this
 * cycle. Comparing against it here would have Settings say "changed" off a
 * kept value while the Fleet card, which gates on reachability, says nothing.
 * One computation, one answer, on both surfaces.
 */
function selfPinFactsFor(
  row: FleetPeerPublic | undefined,
): { pin_state: NodeSettings['pin_state']; pin_reported: string | null; pin_expected: string | null } {
  const state = row?.pin_state ?? null;
  if (state === null) return { pin_state: null, pin_reported: null, pin_expected: null };
  if (state === 'changed' && row?.pin_expected && row?.pin_reported) {
    return { pin_state: 'changed', pin_reported: row.pin_reported, pin_expected: row.pin_expected };
  }
  // 'ok', 'unconfirmed', and the shape that cannot happen: `changed` without
  // its keys. A state that claims a comparison and cannot name it is read as
  // the absence of one, never as a mismatch.
  return { pin_state: state === 'changed' ? 'unconfirmed' : state, pin_reported: null, pin_expected: null };
}

/** The receipt for the last bundle a node accepted, off its own trust block.
 *  Null on a node that has never been pushed to, which is a different fact
 *  from a node whose serial does not match. */
function bundleFrom(doc: AdvisorStatusDoc | null): { serial: string | null; accepted_at: string | null } | null {
  const trust = (doc?.trust ?? null) as { bundle?: { serial?: unknown; accepted_at?: unknown } } | null;
  const b = trust?.bundle;
  if (!b) return null;
  return {
    serial: typeof b.serial === 'string' ? b.serial : null,
    accepted_at: typeof b.accepted_at === 'string' ? b.accepted_at : null,
  };
}

// ── Pairing: the mint ────────────────────────────────────────────────────

/**
 * The one line the operator carries to the node.
 *
 * This dashboard cannot know the other machine's install path, and a line
 * that named one as a placeholder (`sudo bash <node-install-dir>/...`) failed
 * as typed the moment it was copied (#611). So it prints the bootstrap
 * instead: get-aperire.sh, given both --fleet-aggregator and --code on a box
 * that is already installed, finds the checkout itself and hands the code
 * straight to aperire-fleet-pair.sh. No path in the line, no placeholder to
 * replace.
 *
 * The aggregator's own URL comes from THIS dashboard's identity, never from
 * a request header: the command tells a node where to dial, and a Host
 * header is the caller's choice of destination.
 */
export function pairCommandLine(publicUrl: unknown, code: string): string {
  return 'curl -fsSL https://get.aperire.one | bash -s -- \\\n'
    + `  --fleet-aggregator ${aggregatorOrigin(publicUrl)} \\\n`
    + `  --code ${code}`;
}

/**
 * The same rule `scripts/fleet-origin.sh` holds, in TypeScript: scheme, then
 * either a bracketed IPv6 literal or a host name, then an optional port, and
 * nothing else.
 *
 * This is the third copy of one grammar and the one that had `\S+` (P3-075).
 * `\S+` accepts a quote, a backtick, a `;` and a `$(...)`, and both lines
 * below are printed with a copy button beside them for an operator to paste
 * into a ROOT shell on another machine. A `public_url` of
 * `https://dash.example;id` rendered a line that ran `id` there before either
 * installer ever saw the origin. The shell copies are byte-compared by
 * scripts/test-fleet-origin.sh; this one is held by the unit test beside it.
 */
const FLEET_ORIGIN_RE = /^https?:\/\/(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._~-]+)(:[0-9]{1,5})?$/;

/**
 * This aggregator's own origin, for a command that names it.
 *
 * Never the Host header. The command tells a node where to dial, and a Host
 * header is the caller's choice of destination. A malformed or missing
 * `public_url` becomes a placeholder the operator has to fill in, which is the
 * honest answer: this dashboard does not know its own address until somebody
 * tells it, and a placeholder they have to replace beats a command that looks
 * complete and is not.
 */
function aggregatorOrigin(publicUrl: unknown): string {
  if (typeof publicUrl !== 'string') return '<this-aggregator-url>';
  // The trailing slash a copied browser address carries comes off first, and
  // once, the way both installers take it off, so what is checked is what is
  // printed.
  const trimmed = publicUrl.replace(/\/+$/, '');
  return FLEET_ORIGIN_RE.test(trimmed) ? trimmed : '<this-aggregator-url>';
}

/**
 * The line an operator runs on a box that has nothing on it yet, which
 * installs Aperire and then joins it to THIS fleet.
 *
 * It carries no code, deliberately, and that is the whole difference from
 * `pairCommandLine` above. A code is good for fifteen minutes from the mint
 * and a fresh-box install has no bounded duration: apt, a Node download, an
 * npm install and two Go builds, plus a container image pull when the box is
 * getting a node too. A code on this line races a clock nobody controls. So
 * the install asks for one at the end, on the terminal, and the operator mints
 * it then.
 *
 * Being code-free is also what lets this be rendered as a constant: it cannot
 * expire, it cannot be spent, and it needs no route and no state.
 */
export function installJoinCommandLine(publicUrl: unknown): string {
  return 'curl -fsSL https://get.aperire.one | bash -s -- \\\n'
    + `  --fleet-aggregator ${aggregatorOrigin(publicUrl)}`;
}

/**
 * The `dashboard_url` a relay on ANOTHER box has to be given (#135 step 2).
 *
 * The same origin rule as everything else on this page, and for the same
 * reason: this value is printed for an operator to paste into a root-owned
 * config on a different machine. `https` becomes `wss` and `http` becomes
 * `ws`, which is the pairing scripts/aperire-setup.sh already prints and the
 * one the relay's own config comments use.
 *
 * A `public_url` this dashboard cannot vouch for becomes a placeholder the
 * operator has to fill in. That is the honest answer: a dashboard does not
 * know its own address until somebody tells it, and a line that looks
 * complete and is not costs an hour on the other box.
 */
export function relayIngestUrl(publicUrl: unknown): string {
  if (typeof publicUrl !== 'string') return '<dashboard-url>/ingest';
  const trimmed = publicUrl.replace(/\/+$/, '');
  if (!FLEET_ORIGIN_RE.test(trimmed)) return '<dashboard-url>/ingest';
  return `${trimmed.replace(/^http/, 'ws')}/ingest`;
}

/**
 * Mint one code, and answer with it exactly once.
 *
 * The code is in the response body and nowhere else: not in the audit row,
 * not in a log line, not in the overview. What the audit row records is that
 * an admin minted one and when it expires, which is the fact an operator
 * needs when a Pending row they did not expect turns up.
 *
 * `replaces`, when the page sends it, is the hash of a code minted earlier
 * from the SAME step -- the "Mint a new code?" confirmation (#607, the
 * Opus review of PR #610). The step holds one code: the operator was asked,
 * on screen, before the one they were looking at stopped working, so this is
 * not the silent restart case lib/pairing-codes.ts warns against. It is the
 * caller's own code or nothing is touched -- `cancelPairingCodeByHash`
 * refuses a hash issued by anybody else -- and the mint below happens either
 * way, so a hash that no longer resolves (already spent, already expired)
 * never blocks a fresh code. `replaced` in the response is the only source
 * of truth the page has for whether to say "the old one no longer works":
 * it must never say that on a guess.
 *
 * `name` (#635) is what the operator typed into "Name this node" before
 * clicking Mint. Optional -- empty or absent means the node's own proposal
 * stands, exactly as it always has. When given, it is validated against the
 * SAME rule fleet.yaml uses (LABEL_RE below). A name that is this
 * aggregator's own is refused, and nothing is minted, and so is a peer row
 * that pins no node key, which no presented key could ever match. A name that
 * is a pinned peer row's is minted, with a warning that says so (#976): which
 * node that is cannot be known before a key is presented, and classifyPairKey
 * answers it at hello time, by key, with the same lookup (`fleetRowNamed`).
 */
export async function mintPairing(
  deps: SettingsAdminDeps, session: AuthSessionInfo, nowMs: number, replaces?: unknown, name?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!session.credentialId) {
    return {
      status: 409,
      body: {
        error: 'this session predates passkey-bound approval',
        detail: 'Sign out and back in, so the session records which passkey opened it.',
      },
    };
  }
  let operatorLabel: string | null = null;
  if (name !== undefined && name !== null && name !== '') {
    if (typeof name !== 'string') {
      return { status: 400, body: { error: 'bad_name', detail: 'A name must be text.' } };
    }
    const trimmed = name.trim();
    if (trimmed !== '') {
      if (!LABEL_RE.test(trimmed)) {
        return {
          status: 400,
          body: {
            error: 'bad_name',
            // The page's own client-side sentence, in the server's own
            // refusal too (#635 review): plain English, not the regex an
            // operator typing a name has no reason to parse.
            detail: 'A name is lower case letters, digits and dashes, up to 32 of them.',
          },
        };
      }
      // The aggregator's own row is never one of `deps.peers()` (#635
      // review): checked apart, the same split `nodeTarget` above already
      // draws between "no such peer" and "that is this host".
      const self = deps.selfNode();
      if (self && self.label === trimmed) {
        return {
          status: 409,
          body: {
            error: 'name_taken',
            detail: `${trimmed} already names this aggregator. Give the node a different name.`,
          },
        };
      }
      // A peer row under this name is NOT refused (#976) when it pins a key.
      // No key exists yet, so the mint cannot say whether the node that uses
      // this code is that row coming back or another machine; the hello
      // decides, by key, and the mint's answer says so. A row that pins no
      // key can never be matched, so that one name is refused. See
      // mintNameVerdict.
      const row = fleetRowNamed(trimmed, deps.peers());
      const verdict = row ? mintNameVerdict(trimmed, row) : null;
      if (verdict && 'refuse' in verdict) {
        return { status: 409, body: { error: 'name_taken', detail: verdict.refuse } };
      }
      operatorLabel = trimmed;
    }
  }

  // One mint at a time, from the limit check to the record (#850 review, L1).
  // The preflight below awaits root's broker, and the mint is recorded only
  // after it: checked outside this queue, forty concurrent mints from one
  // admin all passed a limit of ten, and two mints replacing one code both
  // cancelled it. The broker takes one call at a time anyway, so queueing
  // the mints adds no wait of its own.
  const credentialId = session.credentialId;
  return serialMint(() => mintPairingSerial(deps, session, credentialId, nowMs, replaces, operatorLabel));
}

let mintQueue: Promise<unknown> = Promise.resolve();
function serialMint<T>(fn: () => Promise<T>): Promise<T> {
  const run = mintQueue.then(fn, fn);
  mintQueue = run.catch(() => undefined);
  return run;
}

async function mintPairingSerial(
  deps: SettingsAdminDeps, session: AuthSessionInfo, credentialId: string, nowMs: number, replaces: unknown,
  operatorLabel: string | null,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const limit = mintLimit(session.username, nowMs);
  if (!limit.ok) return { status: 429, body: { error: 'too_many_pairing_codes', detail: limit.detail } };

  // Pairing v2 (design 1.6): root's arm key before any code exists. A code
  // this host cannot finish pairing with (a moved install, no grant, no
  // fingerprint command) would cost the operator the walk to the node and a
  // paste for nothing. Before the replace below, so a refused mint leaves the
  // operator's live code where it was. The key goes into the cache a
  // keys-first node's hello reads, so that hello never reaches root itself.
  const preflight = await armKeyPreflight(deps);
  if (!preflight.ok) {
    return {
      status: 409,
      body: { error: preflight.error, detail: preflight.detail, command: preflight.command },
    };
  }
  // #743 review, L2, at the mint now: the broker made a new arm key on a
  // fleet that already had nodes. Said here, at the first moment it is true.
  const armKeyNote = armKeyRemintNote(preflight.fleet_arm_key, preflight.fleet_arm_key_orphaned);

  // #635 review (optional, item 7): a WARNING, never a refusal -- an
  // unspent code or a Pending row already carrying this name is unusual,
  // not wrong, and the fix is saying so at the cheapest moment rather than
  // blocking the mint the operator came here to do.
  let warning: string | null = null;
  if (operatorLabel) {
    const warnings: string[] = [];
    // #976: a row by this name is the real state, said without a key claim.
    const row = fleetRowNamed(operatorLabel, deps.peers());
    const verdict = row ? mintNameVerdict(operatorLabel, row) : null;
    if (verdict && 'warn' in verdict) warnings.push(verdict.warn);
    const liveCode = liveCodeNamed(operatorLabel, nowMs);
    const pendingRow = deps.pairings?.().some((p) => p.label === operatorLabel) ?? false;
    if (liveCode || pendingRow) {
      warnings.push(`${operatorLabel} is already on an unspent code or a Pending row. This mints a second one under `
        + 'the same name; the first is untouched.');
    }
    warning = warnings.length ? warnings.join(' ') : null;
  }

  const replaced = replaces !== undefined && replaces !== null
    ? cancelPairingCodeByHash(replaces, session.username, nowMs)
    : false;

  const minted = mintPairingCode(session.username, credentialId, nowMs, operatorLabel);
  let publicUrl: unknown;
  try { publicUrl = (deps.thisDashboard() as Record<string, unknown>).public_url; } catch { publicUrl = null; }
  recordAuthEvent({
    actor: session.username,
    actorRole: session.role,
    event: 'fleet_pairing',
    target: null,
    detail: {
      act: 'code_minted', expires_at: minted.expires_at, replaced: replaced, name: operatorLabel,
      ...(warning ? { name_warning: warning } : {}),
      // Which arm key state the mint found, never the key: the two public
      // keys together are the pairing fingerprint's input (#741).
      fleet_arm_key: preflight.fleet_arm_key ?? 'present',
      ...(armKeyNote ? { arm_key_lost_for: preflight.fleet_arm_key_orphaned.join(', ') || 'unknown' } : {}),
    },
  });
  return {
    status: 200,
    body: {
      code: minted.code,
      expires_at: minted.expires_at,
      command: pairCommandLine(publicUrl, minted.code),
      replaced: replaced,
      name: operatorLabel,
      warning: warning,
      arm_key_note: armKeyNote,
    },
  };
}

/**
 * Pairing v2: ask root's broker for the fleet arm key before a code is
 * minted, and keep the answer for the link hub (design 1.6).
 *
 * `arm-key`, not the read-only `arm-key-check` the readiness step asks: the
 * hub needs the public key itself, and a mint is an administrator's act,
 * like an approval, which has always asked the same verb. When that verb has
 * to make a key on a fleet that already has nodes it says so, and the mint
 * carries that sentence (armKeyRemintNote).
 *
 * Every refusal names the one command that fixes it, the way readiness
 * does: the broker's own command when its sentence carries one, the full
 * grant install otherwise. A busy broker is said as busy, with nothing to
 * run.
 */
const MINT_BUSY_DETAIL = 'This aggregator is still finishing the last pairing (its root broker is busy, most likely '
  + 'sending the fleet model to that node). Nothing was minted. Try again in a minute.';

async function armKeyPreflight(deps: SettingsAdminDeps): Promise<
  | { ok: true; fleet_arm_pubkey: string; fleet_arm_key: string | null; fleet_arm_key_orphaned: string[] }
  | { ok: false; error: string; detail: string; command: string | null }
> {
  const grant = grantInstallSentence(installDirOf(deps));
  const noGrant = { ok: false as const, error: 'no_grant',
    detail: `This host isn't set up to pair nodes yet. Install the pairing grant first: ${grant}`, command: grant };
  if (!deps.broker) return noGrant;
  // #850 review, L2: a broker already at work is most likely pushing the
  // fleet model to the node paired a moment ago, which can take minutes. A
  // mint queued behind it would hold the operator's click for all of that.
  if (deps.brokerBusy?.()) return { ok: false, error: 'broker_busy', detail: MINT_BUSY_DETAIL, command: null };
  let outcome: ReturnType<typeof brokerArmKeyOutcome>;
  try {
    const answer = await deps.broker(brokerArmKeyPayload());
    outcome = brokerArmKeyOutcome(brokerAnswerOf(answer),
      installDirOf(deps));
  } catch (err) {
    if (isSocketUnreachable(err)) return noGrant;
    if (brokerOutcomeUnknown(err)) return { ok: false, error: 'broker_busy', detail: BROKER_BUSY_DETAIL, command: null };
    return { ok: false, error: 'no_broker',
      detail: `this host's fleet broker could not be reached: ${(err as Error).message}`, command: grant };
  }
  if (!outcome.ok) {
    if (outcome.error === 'no_answer') return { ok: false, error: 'broker_busy', detail: outcome.detail, command: null };
    // A broker that closed the connection with no exit line: its own word,
    // with nothing to run. The grant is not what is wrong (#848).
    if (outcome.error === BROKER_NO_ANSWER) return { ok: false, error: BROKER_NO_ANSWER, detail: outcome.detail, command: null };
    // fleet_arm_key_lost (#851) carries its own command, the restore, and the
    // same mapping readiness and approval use: the grant install named in its
    // sentence is the deliberate re-key, never the button.
    if (outcome.command) return { ok: false, error: outcome.error, detail: outcome.detail, command: outcome.command };
    const named = GRANT_STEP_IN_DETAIL.exec(outcome.detail);
    return { ok: false, error: outcome.error, detail: outcome.detail, command: named ? named[0] : grant };
  }
  deps.rememberArmPubKey?.(outcome.fleet_arm_pubkey);
  return {
    ok: true, fleet_arm_pubkey: outcome.fleet_arm_pubkey,
    fleet_arm_key: outcome.fleet_arm_key, fleet_arm_key_orphaned: outcome.fleet_arm_key_orphaned,
  };
}

/**
 * The two halves of a catch-up (ADR 0019 phase 4, #168).
 *
 * It is a seal, and it is the same ceremony with one field missing: the
 * operator does not type the key, because the fleet's model is already sealed
 * on this host and only the root broker can open it.
 *
 * Which means an operator is approving a setting they did not type this time,
 * so `begin` shows them what is about to be pushed, read from the store's own
 * head, and `finish` refuses if that head has changed underneath them.
 * `base_url` is the one field of the store a compromised dashboard can
 * rewrite with no root involved (ADR 0019 phase 4 §7), and its HOST is what
 * both halves render.
 */
async function handleCatchupRoute(
  route: 'catchup/begin' | 'catchup',
  req: IncomingMessage,
  payload: Record<string, unknown>,
  deps: SettingsAdminDeps,
): Promise<{ status: number; body: Record<string, unknown> }> {
  // No `session` parameter, deliberately. Everything this route records about
  // WHO comes off the verified grant, which reads it from the session at the
  // moment the passkey was checked. A second source for the same fact is a
  // second place for the two to disagree.
  if (!deps.storeHead || !deps.modelPush) {
    return {
      status: 501,
      body: {
        error: 'no_broker',
        detail: `this host has no fleet broker installed, so it holds no sealed fleet model and `
          + `cannot push one. Install the grant: ${grantInstallSentence(installDirOf(deps))}`,
      },
    };
  }

  if (route === 'catchup/begin') {
    const resolved = resolveCatchupTargets(payload.targets, {
      known: new Set(deps.peers().map((p) => p.label)),
      seen: (label) => advisorSeen.get(label) ?? null,
      sync: (label) => syncSeen.get(label) ?? null,
    });
    if (!resolved.ok) return { status: 400, body: { error: resolved.error } };
    const head = await deps.storeHead();
    const refusal = storeHeadRefusal(head);
    if (refusal) return refusal;
    if (head.state !== 'held') throw new Error('unreachable');
    // THIS aggregator's own window, read before the authenticator is touched.
    // A push moves the key only while root has one open here, so an operator
    // whose window is shut should be told at the button rather than after
    // spending a passkey on a ceremony that refuses per node.
    const armed = deps.selfArmState();
    if (!armed.armed) {
      return {
        status: 409,
        body: {
          error: 'arm_closed',
          detail: 'this aggregator has no sealing window open, so it can move no key. '
            + `${armSelfSentence(armInstalledOf(deps))}, then Catch up.`,
        },
      };
    }
    const begun = await beginCatchupGrant(req, {
      targets: resolved.targets,
      baseUrlHost: baseUrlHost(head.head.base_url),
      baseUrl: head.head.base_url,
      model: head.head.model,
      credentialName: head.head.credential_name,
    });
    // What is left of the window, so the confirmation can say it. The push
    // happens inside it and it lapses on its own, which is the fact an
    // operator is agreeing to along with the model and the address.
    return {
      status: begun.status,
      body: begun.status === 200
        ? { ...begun.body, arm_remaining_s: armed.remaining_s }
        : begun.body,
    };
  }

  const verified = await (deps.verifyCatchupGrant ?? verifyCatchupGrant)(req, payload);
  if (!verified.ok) {
    return { status: verified.status, body: { error: verified.error, ...(verified.detail ? { detail: verified.detail } : {}) } };
  }
  // The store, read AGAIN and compared with what the operator was shown. The
  // dashboard account can call model-store-put without root and without an
  // operator present, so a descriptor that changed between the two halves of
  // this ceremony is a change nobody approved.
  const head = await deps.storeHead();
  const refusal = storeHeadRefusal(head);
  if (refusal) return refusal;
  if (head.state !== 'held') throw new Error('unreachable');
  // The WHOLE address, not its host: a store rewritten from
  // https://api.example.com/v1 to https://api.example.com/v1-of-mine keeps
  // its host and is a different endpoint (F9). The host is what the page
  // prints; this is what the approval covers.
  if (head.head.base_url !== verified.grant.baseUrl
    || baseUrlHost(head.head.base_url) !== verified.grant.baseUrlHost
    || head.head.model !== verified.grant.model
    || head.head.credential_name !== verified.grant.credentialName) {
    return {
      status: 409,
      body: {
        error: 'store_changed',
        detail: 'the sealed fleet model changed between the moment this was shown to you and the '
          + 'moment you approved it. Read the sealed-copy line again and approve once more.',
      },
    };
  }

  // 202 and a job, not one long response. One push runs for up to 270 s and a
  // catch-up is serial, so a wide one would hold this request open for the
  // best part of twenty minutes: longer than any proxy in front of this
  // dashboard will hold a socket, and the answer would be lost with the work
  // still running. The seal answers the same way for the same reason, and §5
  // calls a catch-up "a seal with no key field".
  const job = startCatchup(deps, verified.grant);
  return {
    status: 202,
    body: {
      ok: true, job_id: job.id, model: job.model, targets: job.targets,
      detail: 'Approved. The sealed model is going out to each node in turn.',
    },
  };
}

/** One catch-up, as the page polls it. Every field is what was approved or
 *  what a node answered; nothing derived from the key is here, and the key
 *  itself never reaches this process on this path at all. */
export interface CatchupJobStatus {
  id: string;
  model: string;
  base_url_host: string;
  credential_name: string;
  targets: string[];
  /** Always false. A catch-up pushes the key the store already holds and
   *  writes no store, so it can never put a new key behind the fleet model.
   *  The page reads this, by key, to decide whether to tell the operator to
   *  revoke an old key: there is none after a catch-up (#1114). */
  key_changed: false;
  /** One row per node, appended as that node settles, so the page can say
   *  "two of five" while the third is still going. */
  results: Array<Record<string, unknown>>;
  done: boolean;
  started_at: number;
  finished_at: number | null;
}

/** Catch-ups this process has run, for the page to poll. Held for half an
 *  hour after they finish: long enough for an operator who walked away, short
 *  enough that a dashboard left up for months is not accumulating them. */
const catchupJobs = new Map<string, CatchupJobStatus>();
const CATCHUP_JOB_TTL_MS = 30 * 60_000;

/**
 * Start the pushes and hand back the record the page will poll.
 *
 * Serially, one node per broker call. The socket is MaxConnections=1 and a
 * push takes minutes; the gap between two of them is where a waiting approval
 * gets in, which is the one thing that makes a wide catch-up survivable on a
 * busy aggregator.
 */
function startCatchup(
  deps: SettingsAdminDeps, grant: VerifiedCatchupGrant,
): CatchupJobStatus {
  const now = Date.now();
  for (const [id, old] of catchupJobs) {
    if (old.finished_at !== null && now - old.finished_at > CATCHUP_JOB_TTL_MS) catchupJobs.delete(id);
  }
  const job: CatchupJobStatus = {
    id: randomBytes(9).toString('base64url'),
    model: grant.model,
    base_url_host: grant.baseUrlHost,
    credential_name: grant.credentialName,
    // This host LAST. Its own sealer spends the arming window (one arming is
    // one seal, on the host the key lands on), and the broker reads that same
    // window before every push. Sealed first, it would shut the window on
    // every node behind it in the same catch-up.
    targets: [...grant.targets].sort((a, b) => Number(a === SELF_TARGET) - Number(b === SELF_TARGET)),
    key_changed: false,
    results: [],
    done: false,
    started_at: now,
    finished_at: null,
  };
  catchupJobs.set(job.id, job);
  // THE APPROVAL, on the record now, before any node has answered. The same
  // reason the pairing approval writes one here: a catch-up that was approved
  // and then interrupted still happened, and an operator asking what spent
  // that passkey must find the answer. The per-node rows below are the
  // outcomes; this is the act.
  recordAuthEvent({
    actor: grant.operator, actorRole: grant.operatorRole,
    event: 'model_key_sealed', target: grant.credentialName,
    detail: {
      act: 'catchup_approved', model: grant.model, base_url_host: grant.baseUrlHost,
      nodes: job.targets.join(','), credential_id: grant.credentialId,
    },
  });
  void (async (): Promise<void> => {
    // `finally`, so a throw anywhere in here still ends the job. Without it a
    // failed audit write would leave done=false forever: the page would poll
    // every two seconds with no end, and the sweep below never collects a job
    // that has not finished.
    try {
      for (const label of job.targets) {
        let outcome;
        try {
          outcome = await deps.modelPush!(label, {
            grantedBy: grant.operator, credentialId: grant.credentialId,
          });
        } catch (err) {
          // The CLASS, never the message: this call's payload, on the far side
          // of the socket, is the key.
          outcome = {
            pushed: false, state: 'unreachable' as const, reason: 'no_broker',
            detail: `this host's fleet broker could not be reached (${(err as Error).name}).`,
            model_configured: null,
          };
        }
        job.results.push({
          label,
          pushed: outcome.pushed,
          state: outcome.state,
          reason: outcome.reason,
          detail: outcome.detail,
          model_configured: outcome.model_configured,
          // The sentence an operator reads for this node, composed here so
          // the page never chooses the words a second time (#448). A node
          // that answered and said no is quoted; "could not be reached"
          // belongs to the state where nothing answered.
          line: catchupNodeLine(label, outcome, armInstalledOf(deps)),
        });
        // That node is about to report something different from what the last
        // overview said about it.
        clearSettingsOverviewCache();
        // One row per node, as it settles, exactly as a seal records one. An
        // operator asking "what did I change, and which nodes took it" asks it
        // here, on the dashboard they used.
        recordAuthEvent({
          actor: grant.operator,
          actorRole: grant.operatorRole,
          event: 'model_key_sealed',
          target: `${label}:${grant.credentialName}`,
          detail: {
            act: 'catchup',
            outcome: outcome.state,
            reason: outcome.reason,
            model: grant.model,
            base_url_host: grant.baseUrlHost,
            node: label,
            model_configured: outcome.model_configured,
            credential_id: grant.credentialId,
          },
        });
      }
    } finally {
      job.done = true;
      job.finished_at = Date.now();
    }
  })();
  return job;
}

/** What a head that is not `held` means to the two catch-up routes.
 *
 *  Five states in, four refusals out, and none of them says "there is no
 *  store" unless the broker positively said so. A busy socket answered as
 *  `none` would tell an operator to paste a live provider key over a store
 *  that was fine. */
function storeHeadRefusal(
  head: BrokerStoreHeadOutcome,
): { status: number; body: Record<string, unknown> } | null {
  switch (head.state) {
    case 'held': return null;
    case 'none': return {
      status: 409,
      body: {
        error: 'no_sealed_model',
        detail: 'this aggregator holds no sealed fleet model, so there is nothing to send. Seal the '
          + 'fleet model from here with the key.',
      },
    };
    case 'unreadable': return {
      status: 409,
      body: {
        error: 'store_unreadable',
        detail: `${head.detail} Seal the fleet model from here again with the key.`,
      },
    };
    case 'predates': return { status: 501, body: { error: 'broker_predates_store', detail: head.detail } };
    default: return { status: 503, body: { error: 'broker_busy', detail: head.detail } };
  }
}

/**
 * Which nodes a catch-up may cover.
 *
 * The seal's resolver, plus one more gate. The design's rule is that targets
 * are the labels the overview reads `behind` or `no_model`, and this is where
 * that is enforced rather than on the page: a targets array is a value the
 * browser holds.
 *
 * Only a POSITIVE `in_sync` refuses, the same discipline the Advisor
 * observation uses. A node this dashboard has not looked at, or looked at and
 * could not read, is let through: refusing on silence would make a blip into
 * "that node needs nothing", which is the reading that leaves a node behind
 * forever.
 */
export function resolveCatchupTargets(
  raw: unknown,
  ctx: {
    known: Set<string>;
    seen: (label: string) => 'present' | 'absent' | 'unread' | null;
    sync: (label: string) => NodeSync | null;
  },
): { ok: true; targets: string[] } | { ok: false; error: string } {
  const resolved = resolveSealTargets(raw, ctx);
  if (!resolved.ok) return resolved;
  const targets = resolved.targets.filter((label) => ctx.sync(label) !== 'in_sync');
  if (targets.length === 0) {
    return {
      ok: false,
      error: 'every node named there already reports the fleet’s model, so there is nothing to send',
    };
  }
  return { ok: true, targets };
}

/**
 * The two controls on a registered node's row: revoke it (#444), and accept
 * a node key that changed (#422).
 *
 * BOTH SIT BEHIND THE PAIRING APPROVAL'S OWN CEREMONY, and deliberately the
 * same one. A pairing approval is an administrator deciding, at a passkey,
 * that a label and a node key belong together on this fleet. Revoking is
 * that decision withdrawn and re-pinning is it taken a second time about the
 * same label, so neither may cost less than the first one did. The operator's
 * ruling on #422, 2026-09-17: an explicit, passkey-gated re-pin, and nothing
 * accepts a new key on its own.
 *
 * WHY THE PAIRING GRANT AND NOT A THIRD ONE. `beginPairGrant` already binds
 * three values into the challenge record (an id, a label and a node key) and
 * reads them back at finish from the record rather than from the request
 * carrying the signature, which is exactly the binding these two need. What
 * makes the reuse safe rather than convenient is the ID: a real pairing's id
 * is 18 random bytes, and these two mint theirs as `revoke:<label>` and
 * `repin:<label>`, checked at finish. So a grant taken for one of these
 * cannot be spent on a pairing approval (no Pending row has that id, and the
 * route answers 404 before it verifies anything), and a pairing grant cannot
 * be spent here (its id does not carry the prefix). Both directions have a
 * row.
 *
 * WHAT EACH ONE WRITES, and the ORDER, which is load-bearing:
 *
 *   revoke  the broker's own `revoke` FIRST, which closes the live link and
 *           prunes root's push-destination record. Then the registry row.
 *           The other way round leaves a moment where fleet-links.json names
 *           a label fleet.yaml does not, which holds that row (#687: that
 *           row alone, not the file), so a reload landing in that moment
 *           drops the link it is about to revoke anyway.
 *   repin   the registry row alone. Root's `fleet-nodes.conf` is not this
 *           dashboard's to write and still pins the old key, so the answer
 *           says so and names the one command that rebuilds it.
 */
export const NODE_ROUTES = {
  '/api/settings/node/revoke/begin': 'revoke/begin',
  '/api/settings/node/revoke': 'revoke',
  '/api/settings/node/repin/begin': 'repin/begin',
  '/api/settings/node/repin': 'repin',
  // #641. The same table, the same gate, the same ceremony shape: attaching
  // an Advisor to an already-registered node, and removing one. Not the
  // approve/convertTunnel shape, which needed an extra bound boolean only
  // because Approve reuses one route for two different decisions.
  '/api/settings/node/attach/begin': 'attach/begin',
  '/api/settings/node/attach': 'attach',
  '/api/settings/node/detach/begin': 'detach/begin',
  '/api/settings/node/detach': 'detach',
} as const;

/** The scoped watch (#641). ONE node, named in the query, and only while an
 *  operator has that node picked on the Add an Advisor card. A GET because
 *  it reads and changes nothing here, admin-gated like every other route on
 *  this page because what it reads is a fleet fact. */
export const ADVISOR_WATCH_PATH = '/api/settings/advisor-watch';

/** The pin a row carries when it carries none. Never a node key: the shape
 *  rule is `n` plus at least twenty base58 characters, and this is neither.
 *  It exists so an unpinned node can still be revoked under a ceremony whose
 *  record binds three values, rather than 400ing at `begin` on an empty one. */
export const NO_PIN = 'unpinned';

/**
 * The web origin this ceremony ran on, for the node's copy of the record, or
 * undefined.
 *
 * Read from the request and therefore checked here rather than trusted: a
 * node refuses a whole record whose origin is not origin-shaped, and losing
 * the audit copy because a client sent an odd header would be this field
 * costing more than it is worth. Anything that does not match is dropped, and
 * the entry is written without it.
 */
function requestOrigin(req: IncomingMessage): string | undefined {
  const raw = req.headers.origin;
  if (typeof raw !== 'string') return undefined;
  return /^https?:\/\/[A-Za-z0-9.:-]{1,120}$/.test(raw) ? raw : undefined;
}

/**
 * How long the node's copy of the record may take, per act.
 *
 * Shorter than the module default, because an operator is waiting on the act
 * and this is not the act. Two requests are made, the pin read and the
 * append, so a node that is simply gone costs six seconds before the revoke
 * that is meant to remove it is even asked for. Long enough for a loopback
 * forward and an advisord that answers, which is every node that is going to
 * keep a copy at all.
 */
const ADVISOR_LEDGER_TIMEOUT_MS = 3_000;

/**
 * How an attach's own ledger copy waits out the listener it travels over
 * (#641).
 *
 * The bind is what makes this necessary. `attach-advisor` writes the port
 * into `fleet-links.json`, this process re-reads it, and the hub opens the
 * listener behind that port on its next reconcile. Between those two there
 * is a real gap where the registry names an address and nothing answers on
 * it, and an entry written into that gap is an entry the node never gets.
 *
 * FOUR ATTEMPTS, and the waits are 0, 1s, 3s and 5s: nine seconds of
 * wall clock at the outside, spent only while the answer is "this did not
 * get there". An operator is waiting on this request, so the ceiling is
 * chosen to be shorter than the point where a page would look stuck rather
 * than to be generous. The first attempt is immediate, because the ordinary
 * case is that the listener is already up.
 */
const ADVISOR_LEDGER_RETRY_WAITS_MS = [1_000, 3_000, 5_000];

/** The one reason that is a race rather than a decision. A refusal, a pin
 *  mismatch, a node with no Advisor and a record called too old are all
 *  answers; asking again cannot change any of them. */
function ledgerCopyMayLandLater(outcome: Awaited<ReturnType<typeof appendFleetRecord>>): boolean {
  return !outcome.ok && outcome.reason === 'unreachable';
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms).unref?.(); });
}

/**
 * Call `attempt` until it lands or until the waits run out, retrying only
 * while the outcome is one that could land later.
 *
 * Returns the LAST outcome either way, so a copy that never lands is
 * reported exactly as it was before this existed: `unreachable`, with the
 * node's own reason, and the answer says the entry did not land. Nothing
 * here can make an attach fail, and nothing here invents a success.
 */
async function retryWhileUnreachable(
  attempt: () => Promise<Awaited<ReturnType<typeof appendFleetRecord>>>,
  sleep: (ms: number) => Promise<void>,
): Promise<Awaited<ReturnType<typeof appendFleetRecord>>> {
  let outcome = await attempt();
  for (const wait of ADVISOR_LEDGER_RETRY_WAITS_MS) {
    if (!ledgerCopyMayLandLater(outcome)) return outcome;
    await sleep(wait);
    outcome = await attempt();
  }
  return outcome;
}

/**
 * The second sentence for the aggregator's own copy of an entry (#477),
 * appended to the confirmation's `detail` beside the existing sentence about
 * the node's copy. Never the whole story on its own: `advisor_ledger_self`,
 * `advisor_ledger_self_ok` and `advisor_ledger_self_reason` on the response
 * carry the same fact for a caller that wants it structured rather than read
 * out of a sentence.
 *
 * `no_advisor` gets its OWN wording, worded as a fact rather than a failure
 * (security review, #477): this aggregator simply has no Advisor installed,
 * which is an ordinary and documented shape (the fleet guide says as much),
 * not something that went wrong on an attempt that was made. Folding it into
 * "kept no copy of its own" read as a failed write on a host that never had
 * anywhere to write to.
 */
const TOKEN_DIR = '/etc/aperire/fleet-tokens';

/** True when `p` is a direct child of the fleet token directory -- the
 *  convention path approve/revoke both use. Anything else (a tunnel node's
 *  own path, or a hand-edited row) is a path the broker's revoke never
 *  touches by name, only by that exact convention (#854 security review,
 *  L2). */
function underTokenDir(p: string): boolean {
  const prefix = `${TOKEN_DIR}/`;
  return p.startsWith(prefix) && !p.slice(prefix.length).includes('/');
}

/** The revoke's confirmation: one line per step that ran, and for a step
 *  that did not finish, the step and its one fix (#854, #704, and the
 *  #854 security review's L1/L2). */
export function revokeConfirmation(input: {
  label: string;
  node: { token_path: string; advisor_token_path?: string };
  outcome: Extract<ReturnType<typeof brokerRevokeOutcome>, { ok: true }>;
  advisorLedger: { ok: boolean };
  pushOk: boolean;
  pushed: string;
  installDir: string;
}): { lead: string; done: string[]; needsRoot: { why: string; command: string } | null } {
  const { label, node, outcome, pushOk, pushed, installDir } = input;
  const done: string[] = [];
  let needsRoot: { why: string; command: string } | null = null;
  const tokenDir = TOKEN_DIR;
  // Every path this row itself names, in its own words -- a tunnel node's
  // custom token_path, or a hand-edited advisor_token_path, as well as the
  // ordinary <label>.token / <label>.approve.token pair.
  const rowPaths = [node.token_path, node.advisor_token_path].filter(
    (p): p is string => typeof p === 'string' && p.length > 0,
  );
  const customPaths = rowPaths.filter((p) => !underTokenDir(p));

  done.push(outcome.had_link
    ? `Link closed, and the node was told${input.advisorLedger.ok ? ' (an entry is on its own Advisor ledger)' : ''}.`
    : 'There was no link to close for this node.');
  // #859: the registry half is the broker's second phase.
  const fleetYaml = `${installDir}/dashboard/config/fleet.yaml`;
  if (outcome.fleet_row === 'removed') {
    done.push('Registry row removed.');
  } else if (outcome.fleet_row === 'absent' || outcome.already_gone) {
    done.push('Registry row: already gone.');
  } else if (outcome.fleet_row === 'left') {
    const command = `sudoedit ${fleetYaml}`;
    done.push(`Registry row not removed: ${outcome.registry_left_detail ?? 'the broker could not take it out'} `
      + `${outcome.had_link ? 'The link is already closed, so this node can no longer reach this fleet. ' : ''}`
      + `Press Revoke again once that is fixed, or take its row out by hand with ${command}`);
    needsRoot = {
      why: outcome.had_link
        ? 'this node’s registry row is still here, although its link is closed'
        : 'this node’s registry row is still here',
      command,
    };
  } else {
    // A broker older than #859 never takes the row out.
    const command = grantStepCommand(installDir);
    done.push(`Registry row not removed: this host’s root broker is older than this dashboard and does `
      + `not take it out. The link is closed. Run ${command}, then press Revoke again to finish.`);
    needsRoot = { why: 'this host’s fleet broker is older than this dashboard', command };
  }
  if (outcome.advisor_peer === 'removed') {
    done.push('Taken out of this aggregator’s Advisor fleet map. The Advisor reads it again on its own, '
      + 'with no restart.');
  } else if (outcome.advisor_peer === 'absent') {
    done.push('Advisor fleet map: it was not there.');
  } else if (outcome.advisor_peer === 'left') {
    done.push('Advisor fleet map: left as it was, together with the registry row.');
  }

  if (outcome.root_record === 'pruned') {
    done.push('Root record removed: this aggregator may no longer send it a model key.');
  } else if (outcome.root_record === 'absent') {
    done.push('Root record: there was none for this node.');
  } else if (outcome.already_gone) {
    done.push('Root record: already gone.');
  } else if (outcome.root_record === null && !outcome.had_link) {
    // no_row (#854 security review, L2 by the same reasoning as the token
    // section below): the broker refuses before it ever reaches root's own
    // record, so there is nothing to call a failure. The registry row this
    // request just dropped is also the row --refresh-nodes would have read
    // to rebuild that record, so naming that command here would send the
    // operator to run something that can no longer find this node either.
    done.push('Root record: not checked, because there was no link to close.');
  } else if (outcome.root_record === null) {
    const command = grantStepCommand(installDir);
    done.push(`Root record not checked: this host’s root broker did not report it. Run ${command}`);
    needsRoot = { why: 'this host’s fleet broker did not say whether root’s record was pruned', command };
  } else {
    const command = grantStepCommand(installDir, '--refresh-nodes');
    done.push(`Root record not removed: the rewrite failed. Run ${command}`);
    needsRoot = { why: 'root’s record of where a model key may be sent still names this node', command };
  }

  if (outcome.already_gone) {
    done.push('Token files: already gone.');
  } else if (outcome.tokens_removed === null && !outcome.had_link) {
    // no_row: the broker never reaches the cleanup step at all (a tunnel
    // node, or a link row it never held). Nothing was deleted, so this
    // row's own paths -- wherever they point -- are named rather than
    // left for the operator to go find (#854 security review, L2).
    if (rowPaths.length) {
      const command = `sudo rm -f ${rowPaths.join(' ')}`;
      done.push(`Token files not removed: there was no link to close, so the broker never reached that `
        + `step. This node’s row names: ${rowPaths.join(', ')}. Run ${command}`);
      needsRoot ??= { why: 'this node’s own token files may still be on this host', command };
    } else {
      done.push('Token files: this node’s row names none.');
    }
  } else if (outcome.tokens_removed === null) {
    const command = `sudo rm -f ${tokenDir}/${label}.token ${tokenDir}/${label}.approve.token`;
    done.push(`Token files not checked: this host’s root broker did not report them. Run ${command}`);
    needsRoot ??= { why: 'this node’s token files may still be on this host', command };
  } else if (outcome.tokens_dir_refused) {
    // L1: the DIRECTORY was refused (a symlink there, a too-wide mode),
    // never tried against either file by name. Naming the file would send
    // an operator to `ls` the wrong thing.
    const lookCommand = `sudo ls -ld ${tokenDir}`;
    const rmCommand = `sudo rm -f ${tokenDir}/${label}.token ${tokenDir}/${label}.approve.token`;
    done.push(`Token files not removed: ${tokenDir} itself was refused (not a plain directory, a symlink, `
      + `or wider than it should be), before either file was tried by name. Look at it with ${lookCommand}, `
      + `fix it, then remove this node’s token files by hand: ${rmCommand}`);
    needsRoot ??= { why: `${tokenDir} is not a directory this broker will walk into`, command: lookCommand };
  } else if (outcome.tokens_failed.length) {
    const names = outcome.tokens_failed.map((t) => `${tokenDir}/${t}`).join(' ');
    const command = `sudo ls -l ${names}`;
    done.push(`Token files removed (${outcome.tokens_removed}). Not removed, because it is not a plain file: `
      + `${names}. Look at it with ${command}, then remove it by hand.`);
    needsRoot ??= { why: 'something other than a token file is at this node’s token name', command };
  } else {
    done.push(`Token files removed (${outcome.tokens_removed}).`);
    if (customPaths.length) {
      // L2: cleanup succeeded for the convention pair, but this row also
      // names a path outside the fleet token directory -- a tunnel node's
      // own token, or a hand-edited advisor_token_path -- which the broker
      // never touches by name, only by that exact convention.
      const command = `sudo rm -f ${customPaths.join(' ')}`;
      done.push(`This node’s row also names a token path the broker never touches by convention: `
        + `${customPaths.join(', ')}. Run ${command}`);
      needsRoot ??= { why: 'a token path this row names sits outside the fleet token directory', command };
    }
  }

  done.push(pushOk
    ? `Passkey list pushed to the remaining nodes (${pushed}).`
    : `Passkey list not pushed (${pushed}). Press Push on the Fleet trust enrollment card to send it again.`);
  done.push('Backup sets taken before now still include this node; take a fresh one.');

  // #859: a registry row that stayed is not "off this fleet" on the page's
  // first line; the link is closed, and that is what the lead says.
  const registryLeft = !outcome.already_gone && (outcome.fleet_row === 'left' || outcome.fleet_row === null);
  const lead = registryLeft
    ? `“${label}” can no longer reach this fleet${outcome.had_link ? ': its link is closed' : ''}. Its registry `
      + 'row is still here, and the list below says how to finish.'
    : `“${label}” is off this fleet. The node itself is untouched and can pair again.`;
  return { lead, done, needsRoot };
}

function selfLedgerSentence(outcome: Awaited<ReturnType<typeof appendOwnFleetRecord>>): string {
  if (outcome.ok) {
    return `This aggregator kept its own copy of that entry too (${describeFleetRecord(outcome)}).`;
  }
  if (outcome.reason === 'no_advisor') {
    return 'This aggregator runs no Advisor, so there is no ledger here to hold a copy.';
  }
  return `This aggregator kept no copy of its own: ${outcome.detail}`;
}

/** `ok`, or the outcome's own failure reason. What `advisor_ledger_self_reason`
 *  and the matching audit field carry, so a caller that wants the fact
 *  structured (rather than read out of `advisor_ledger_self`'s sentence) does
 *  not have to parse one. */
function fleetRecordReason(outcome: Awaited<ReturnType<typeof appendOwnFleetRecord>>): string {
  return outcome.ok ? 'ok' : outcome.reason;
}

/**
 * What is TRUE to say after a broker refusal on an act whose ledger copy
 * went first (review finding, 2026-09-27).
 *
 * Revoke and detach both write the node's copy BEFORE the broker, because
 * the broker is the thing that takes away the address the copy travels
 * over. That ordering is right and it stays. What was wrong is the sentence
 * afterwards: a refused broker answered "Nothing was changed" or "The
 * registry row was left alone", on a request that had already put a
 * permanent, signed entry in that node's own append-only record. Press it
 * twice on a row the broker refuses and there are two entries with two
 * record_ids, each saying an act happened that did not.
 *
 * The entry cannot be taken back, so the answer names it. An operator who
 * reads "nothing was changed" and later finds an entry for an act that
 * never happened has been told two things that cannot both be true, and the
 * one they were told first is the false one.
 */
function refusalAfterLedgerCopies(
  label: string,
  nodeCopy: Awaited<ReturnType<typeof appendFleetRecord>> | null,
  selfCopy: Awaited<ReturnType<typeof appendOwnFleetRecord>> | null,
  nothingElse: string,
): string {
  const landed: string[] = [];
  if (nodeCopy?.ok) landed.push(`“${label}”’s own Audit trail`);
  if (selfCopy?.ok) landed.push('this aggregator’s own');
  if (landed.length === 0) return nothingElse;
  return `${nothingElse.replace(/\s*$/, '')} One thing did happen and cannot be taken back: an entry for `
    + `this was already written to ${landed.join(' and ')}, before the refusal. Read it as an attempt `
    + 'rather than as the act.';
}

/**
 * What an attach's answer says about the copy on the NODE (#641).
 *
 * Revoke and re-pin say nothing here, and they can afford to: their copies
 * are written while the node is plainly reachable, and the structured
 * `advisor_ledger*` fields carry the fact for anyone who wants it. An
 * attach's copy travels over a listener that comes up a beat after the row
 * does, so "it landed" is a claim worth making out loud in both directions.
 *
 * One sentence, and it never reads as a failure of the attach: the Advisor
 * IS attached either way, and what is missing is a line in that node's own
 * record of the act.
 */
/**
 * The fleet's model, for a node whose Advisor was just attached (#1037).
 *
 * Read first, pushed second, and pushed only on a POSITIVE reading that the
 * node's Advisor has no model: its sealer replaces whatever it holds, so a
 * node already on a model is left on it (Catch up is how an operator moves
 * one), and a node whose model could not be read is not overwritten blind.
 *
 * This aggregator's own window is asked before anything is sent. The broker
 * refuses a push while it is shut, and saying so now, with the root line,
 * beats spending a push to be told. The node's own window is its Advisor
 * install's: that install opens one, and the attach follows it.
 *
 * The push itself runs AFTER the answer, as the pairing follow-on's does. It
 * waits on the far node's sealer, which can take minutes, and the attach has
 * already done what the operator approved. What it came to goes on the
 * record, in the journal, and on that node's row at the next refresh.
 *
 * Null when this host has no store to read or no broker to push through.
 */
async function startAttachModel(
  deps: SettingsAdminDeps,
  row: FleetNodeConfig,
  grant: BrokerPushGrant,
  actor: { username: string; role: string },
): Promise<AttachModelState | null> {
  // The queued read, not the polled one: this runs once, for an operator who
  // approved it, and a catch-up holding the socket is a reason to wait, not
  // a reason to tell that node there was nothing to send.
  const storeHead = deps.storeHeadQueued ?? deps.storeHead;
  const push = deps.modelPush;
  if (!storeHead || !push) return null;
  let status: Awaited<ReturnType<typeof fetchPeerAdvisor>>;
  try {
    status = await (deps.peerAdvisorStatus
      ?? ((n: FleetNodeConfig) => fetchPeerAdvisor(n, { label: n.label, endpoint: 'status' })))(row);
  } catch {
    status = { ok: false, error: 'advisor_unreachable' };
  }
  // Any failure to read is `unread` here, `advisor_not_configured` included:
  // the row this reads was written a moment ago, and a row this process has
  // not re-read yet is not a node without an Advisor.
  const presence = status.ok ? 'present' as const : 'unread' as const;
  const advisor = advisorFrom(status.ok ? (status.body as AdvisorStatusDoc) : null, presence);
  const sync = computeNodeSync({ presence, model: modelOf(advisor), fleet: null });
  if (sync !== 'no_model' && sync !== 'no_credential') {
    return sync === 'unread' || sync === 'no_advisor' ? 'unread' : 'kept';
  }
  if (!deps.selfArmState().armed) return 'arm_closed';
  void (async (): Promise<void> => {
    let outcome: InheritOutcome;
    try {
      outcome = await inheritFleetModel(row.label, true, grant, { storeHead, push });
    } catch (err) {
      // The CLASS, never the message: the payload behind this call is the key.
      outcome = { state: 'unreachable', reason: (err as Error).name };
    }
    // That node is about to report something different from what the last
    // overview said about it.
    clearSettingsOverviewCache();
    try {
      recordAuthEvent({
        actor: actor.username, actorRole: actor.role, event: 'fleet_pairing',
        target: row.label,
        detail: {
          act: 'attach_model', model: outcome.state,
          ...(outcome.reason ? { model_reason: outcome.reason } : {}),
          credential_id: grant.credentialId,
        },
      });
    } catch (err) {
      console.warn(`[fleet-link] attach "${row.label}": the model outcome could not be recorded: ${(err as Error).message}`);
    }
    console.log(`[fleet-link] attach "${row.label}": fleet model ${outcome.state}`
      + (outcome.detail ? `: ${outcome.detail}` : ''));
  })();
  return 'started';
}

function nodeLedgerSentence(label: string, outcome: Awaited<ReturnType<typeof appendFleetRecord>>): string {
  if (outcome.ok) {
    return `“${label}” recorded it in its own Audit trail (${describeFleetRecord(outcome)}). `;
  }
  if (outcome.reason === 'unreachable') {
    return `“${label}” did not take a copy for its own Audit trail: its Advisor did not answer while `
      + 'this was written. The Advisor is attached; the entry is what is missing. ';
  }
  return `“${label}” did not take a copy for its own Audit trail: ${outcome.detail} The Advisor is `
    + 'attached; the entry is what is missing. ';
}

/** The ceremony ids these two routes mint. A real pairing id is random
 *  bytes, so no Pending row can ever carry one of these. */
function revokeCeremonyId(label: string): string { return `revoke:${label}`; }
function repinCeremonyId(label: string): string { return `repin:${label}`; }
/** #641's two, on the same rule and checked the same way at finish. Four
 *  distinct prefixes now, so no grant taken for any one of these four acts
 *  can be spent on another: attach reveals a credential and detach forgets
 *  one, and neither may be reachable with the other's approval. */
function attachCeremonyId(label: string): string { return `attach:${label}`; }
function detachCeremonyId(label: string): string { return `detach:${label}`; }

/** This host's own install directory, for the commands these answers print.
 *  `deps.thisDashboard()` always resolves one in practice (server.ts builds
 *  it from `import.meta.dirname`, never from anything a request carries),
 *  so the fallback below is for the shape TypeScript still makes this
 *  function account for, not a path this project has ever observed missing
 *  (#630 review). A command with a hole in it is still better than one
 *  wearing another box's path, so it stays a string an operator can read
 *  in the printed command -- but it says what actually happened rather
 *  than reusing `<install-dir>`, the exact placeholder pattern #629 fixed
 *  elsewhere for failing silently as typed. */
function armInstalledOf(deps: SettingsAdminDeps): boolean {
  try { return deps.fleetArmInstalled?.() === true; } catch { return false; }
}
function brokerInstalledOf(deps: SettingsAdminDeps): boolean {
  try { return deps.fleetBrokerInstalled ? deps.fleetBrokerInstalled() !== false : true; } catch { return false; }
}

function installDirOf(deps: SettingsAdminDeps): string {
  try {
    const dir = (deps.thisDashboard() as Record<string, unknown>).install_dir;
    if (typeof dir === 'string' && dir.trim()) return dir.trim();
  } catch { /* falls through to the same honest marker below */ }
  return '<this dashboard could not determine its own install directory>';
}

/** The peer this route is about, or the refusal. Never the self row: the
 *  aggregator is not one of its own peers, and `deps.peers()` excludes it,
 *  so a request naming this host finds nothing here. The page hides the
 *  controls on that row too, and this is the half that does not depend on
 *  the page. */
function nodeTarget(
  deps: SettingsAdminDeps, payload: Record<string, unknown>, allowHeld = false,
): { ok: true; node: FleetNodeConfig } | { ok: false; status: number; body: Record<string, unknown> } {
  const label = typeof payload.label === 'string' ? payload.label : '';
  if (!LABEL_RE.test(label)) {
    return { ok: false, status: 400, body: { error: 'bad_label', detail: 'a label must match [a-z0-9-]{1,32}, the same rule fleet.yaml uses.' } };
  }
  const self = deps.selfNode();
  if (self && self.label === label) {
    return {
      ok: false, status: 409,
      body: {
        error: 'not_a_peer',
        detail: 'that is the host serving this page. A dashboard is not one of its own peers, so it '
          + 'cannot revoke, re-pin, attach or detach itself; do it from the aggregator that holds it. '
          + 'This host’s own Advisor is installed on the box, not attached from here.',
      },
    };
  }
  const node = deps.peers().find((p) => p.label === label);
  if (!node) {
    // #1057: a row this dashboard read and could not use. Revoke reaches it,
    // because taking a node off the fleet needs only its label; everything
    // else needs a bound link, a read or an Advisor address, and a held row
    // has none of the three, so those are answered as what they are.
    const held = deps.held?.().nodes.find((p) => p.label === label);
    if (held && allowHeld) return { ok: true, node: held };
    if (held) {
      return {
        ok: false, status: 409,
        body: {
          error: 'node_held',
          detail: `“${label}” is held: fleet.yaml has no row for this host, so this dashboard reads no `
            + 'node and binds no link. Revoke is the only act available on it until that row is added.',
        },
      };
    }
    return { ok: false, status: 404, body: { error: 'no_such_node', detail: `this dashboard has no node called “${label}”.` } };
  }
  return { ok: true, node };
}

async function handleNodeRoute(
  route: 'revoke/begin' | 'revoke' | 'repin/begin' | 'repin'
    | 'attach/begin' | 'attach' | 'detach/begin' | 'detach',
  req: IncomingMessage,
  payload: Record<string, unknown>,
  deps: SettingsAdminDeps,
  session: AuthSessionInfo,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const target = nodeTarget(deps, payload, route === 'revoke/begin' || route === 'revoke');
  if (!target.ok) return { status: target.status, body: target.body };
  const node = target.node;
  const pinned = node.expected_pubkey_node ?? null;
  const row = deps.fleetView()?.nodes.find((n) => n.label === node.label);

  // ── revoke ─────────────────────────────────────────────────────────
  if (route === 'revoke/begin') {
    const begun = await beginPairGrant(req, {
      pairingId: revokeCeremonyId(node.label),
      label: node.label,
      pubkeyNode: pinned ?? NO_PIN,
    });
    // What the operator is agreeing to, beside the challenge, so the
    // confirmation names the node, its key and what stops working rather
    // than asking for a passkey over the word "revoke".
    return {
      status: begun.status,
      body: begun.status === 200
        ? {
          ...begun.body,
          label: node.label,
          pubkey_node: pinned,
          transport: node.transport ?? 'loopback',
          has_advisor: Boolean(node.advisor_origin),
        }
        : begun.body,
    };
  }

  if (route === 'revoke') {
    const verified = await (deps.verifyPairGrant ?? verifyPairGrant)(req, payload);
    if (!verified.ok) {
      return { status: verified.status, body: { error: verified.error, ...(verified.detail ? { detail: verified.detail } : {}) } };
    }
    // The prefix, and the label it names. This is what stops a pairing
    // approval being spent here: its id is random bytes and carries neither.
    if (verified.grant.pairingId !== revokeCeremonyId(verified.grant.label)
      || verified.grant.label !== node.label) {
      return {
        status: 409,
        body: {
          error: 'wrong_ceremony',
          detail: 'that approval was taken for something other than revoking this node, so nothing was changed.',
        },
      };
    }
    // The record's key against the registry's NOW. A row re-pinned between
    // the two halves is a different node from the one that was approved.
    if (verified.grant.pubkeyNode !== (pinned ?? NO_PIN)) {
      return {
        status: 409,
        body: {
          error: 'node_changed',
          detail: 'that approval was taken for a different node key than this row now pins. Read the row '
            + 'again and approve once more.',
        },
      };
    }
    if (!deps.broker) {
      return {
        status: 501,
        body: {
          error: 'no_broker',
          detail: 'this host has no fleet broker installed, so it cannot close a node’s link. Install the '
            + `grant: ${grantStepCommand(installDirOf(deps))}`,
        },
      };
    }

    // THE APPROVAL, on the record before any of the work, exactly as the
    // pairing approval writes one: a revoke that was approved and then
    // interrupted still happened, and an operator asking what spent that
    // passkey must find the answer.
    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: {
        act: 'revoke_approved', pubkey_node: pinned,
        transport: node.transport ?? 'loopback', credential_id: verified.grant.credentialId,
      },
    });

    // THE COPY ON THE NODE, AND IT GOES BEFORE THE BROKER (#455).
    //
    // This is the ordering decision the whole step turns on. A revoke closes
    // the node's link, and for a `transport: link` row that link IS the path
    // to its Advisor: the loopback advisor_origin in the registry is a port
    // this dashboard's hub serves while the node's outbound connection is
    // held. After the broker's revoke there is nothing behind that port, so
    // an entry written afterwards would reach nobody on exactly the nodes
    // this entry is most about. Written here the node is still reachable,
    // its registry row still resolves, and the approval above is already on
    // the operator audit.
    //
    // It writes no file this dashboard owns, so it cannot leave the registry
    // and the link file disagreeing, which is the hazard that fixes the
    // broker-before-registry order below.
    //
    // A FAILURE HERE DOES NOT UNDO THE ACT, and never asks. The operator
    // audit row is the record of the revoke; this is a copy on the node, and
    // a node with no Advisor, one that is down, or one answering on a key
    // this fleet does not pin gets no copy and the answer says which.
    const revokeFacts = {
      node: node.label,
      operator: session.username,
      role: session.role,
      credentialId: verified.grant.credentialId,
      origin: requestOrigin(req),
      pubkeyNode: pinned,
    };
    const revokeRecord = buildFleetRecord('fleet.link_revoked', revokeFacts);
    const advisorLedger = await (deps.appendAdvisorLedger ?? appendFleetRecord)(
      node, deps.fleetTrustPath, 'fleet.link_revoked', revokeFacts,
      { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS, record: revokeRecord },
    );

    // #688: THE ONE PLACE A TOMBSTONE IS ASKED FOR. The operator has just
    // approved this at a passkey, and the broker below is what removes the
    // row. Registered before the broker because the broker's own reload may
    // reconcile the hub before its answer reaches this line; withdrawn on
    // every path where the revoke did not happen.
    const withdrawTombstone = deps.expectRevoke?.(node.label) ?? (() => {});

    // The broker FIRST: the live link closes and root stops holding this
    // label as a place a key may be sent. See this block's own comment for
    // why the registry row cannot go first.
    let answer: { code: number; stdout: string; stderr: string; reported?: boolean; timedOut?: boolean };
    try {
      answer = await deps.broker(brokerRevokePayload(node.label));
    } catch (err) {
      withdrawTombstone();
      return {
        status: 502,
        body: {
          error: 'no_broker',
          detail: refusalAfterLedgerCopies(node.label, advisorLedger, null,
            brokerOutcomeUnknown(err)
              ? brokerUnknownDetail('revoke')
              : `this host’s fleet broker could not be reached (${(err as Error).name}), so that node is `
                + 'still on this fleet.'),
          advisor_ledger: describeFleetRecord(advisorLedger),
          advisor_ledger_ok: advisorLedger.ok,
        },
      };
    }
    const outcome = brokerRevokeOutcome(brokerAnswerOf(answer), installDirOf(deps), node.label);
    if (!outcome.ok && outcome.phase1) {
      // #870 review, L1: the broker's credential half ran (root's record and
      // the token files) and only the link registry could not be read or
      // written back. That is a partial revoke: the tombstone stays, the
      // audit row carries what root did, and the page says the link may
      // still be up, never that nothing happened.
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: {
          act: 'revoke_partial', pubkey_node: pinned, error: outcome.error, link_removed: 'unknown',
          root_record: outcome.phase1.root_record, tokens_removed: outcome.phase1.tokens_removed,
          tokens_failed: outcome.phase1.tokens_failed, tokens_dir_refused: outcome.phase1.tokens_dir_refused,
          advisor_ledger: describeFleetRecord(advisorLedger),
        },
      });
      return {
        status: 409,
        body: {
          error: outcome.error,
          // A cut-off answer has not said anything about the registry row, so
          // the sentence about it belongs to the registry refusal alone.
          detail: outcome.error === 'no_answer'
            ? outcome.detail
            : `${outcome.detail} Its registry row is still here. Press Revoke again once the link `
              + 'registry is fixed.',
          root_record: outcome.phase1.root_record,
          tokens_removed: outcome.phase1.tokens_removed,
          tokens_failed: outcome.phase1.tokens_failed,
          tokens_dir_refused: outcome.phase1.tokens_dir_refused,
          advisor_ledger: describeFleetRecord(advisorLedger),
          advisor_ledger_ok: advisorLedger.ok,
        },
      };
    }
    if (!outcome.ok) {
      // Not when this host stopped waiting: the broker may still be carrying
      // the revoke out (its unit runs longer than this host waits), and the
      // tombstone is what lets the node be told it was revoked when the link
      // closes (#688).
      if (!(answer.timedOut === true && outcome.error === 'no_answer')) withdrawTombstone();
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: {
          act: 'revoke_failed', pubkey_node: pinned, error: outcome.error, detail: outcome.detail,
          advisor_ledger: describeFleetRecord(advisorLedger),
        },
      });
      return {
        status: 409,
        body: {
          error: outcome.error,
          detail: refusalAfterLedgerCopies(node.label, advisorLedger, null,
            // A broker that gave no answer has not said the row was left
            // alone (#848): its own sentence says it cannot tell.
            outcome.error === 'no_answer' ? outcome.detail : `${outcome.detail} The registry row was left alone.`),
          advisor_ledger: describeFleetRecord(advisorLedger),
          advisor_ledger_ok: advisorLedger.ok,
        },
      };
    }

    // THE AGGREGATOR'S OWN COPY OF THE SAME ENTRY (#477), and it is AFTER
    // the broker (review finding, 2026-09-27). The node's copy has to go
    // first: the broker's revoke closes the link its address rides on. This
    // one goes to this host's own Advisor over loopback, which no broker
    // refusal can take away, so writing it before the broker only bought a
    // second permanent entry for an act that might be refused a line later.
    // Same record and same record_id, so the two copies of one act still
    // cannot disagree about which act they are.
    const advisorLedgerSelf = await (deps.appendOwnAdvisorLedger ?? appendOwnFleetRecord)(
      deps.fleetTrustPath, revokeRecord, deps.selfAdvisorPresence(),
      deps.advisorUrl ?? null, deps.advisorToken ? deps.advisorToken() : null,
      { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS },
    );

    // #859: the registry row went in the broker's own revoke, in its second
    // phase. When that phase could not finish (registry_left) or the broker
    // is older than #859 and never takes the row out (fleet_row null), the
    // link is still closed and the credential half done: that is said, the
    // act is still a revoke, and the confirmation names the one step left.
    const registryLeft = !outcome.already_gone
      && (outcome.fleet_row === 'left' || outcome.fleet_row === null);

    // The passkey list, to the nodes that are left. A revoked node must not
    // be on the next bundle, and the nodes that stay should hold one that
    // agrees with the fleet they are now in.
    let pushed: string;
    let pushOk = false;
    try {
      const r = await deps.pushTrust(null);
      pushOk = r.ok;
      pushed = r.ok ? (lastLine(r.output) || 'pushed')
        : pushFailedLine(r.output, null, new Set(deps.peers().map((p) => p.label)));
    } catch (err) {
      pushed = `the push could not be started (${(err as Error).name})`;
    }

    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: {
        act: registryLeft ? 'revoke_partial' : 'revoked', pubkey_node: pinned, had_link: outcome.had_link,
        fleet_row: outcome.fleet_row, advisor_peer: outcome.advisor_peer,
        ...(outcome.registry_left_reason ? { registry_left_reason: outcome.registry_left_reason } : {}),
        nodes_pruned: outcome.nodes_pruned, root_record: outcome.root_record,
        tokens_removed: outcome.tokens_removed, tokens_failed: outcome.tokens_failed,
        tokens_dir_refused: outcome.tokens_dir_refused,
        reloaded: outcome.reloaded, trust_push: pushed, credential_id: verified.grant.credentialId,
        // Whether the node kept a copy, on the row that IS the record of the
        // act. An auditor reading this one line can tell "there is an entry
        // on that node too" from "there is not, and here is why".
        advisor_ledger: describeFleetRecord(advisorLedger),
        // And whether THIS aggregator kept its own second copy of the same
        // entry (#477), the record the operator reads from the box they are
        // sitting at without having to open the node that was removed.
        advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
        advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
      },
    });
    clearSettingsOverviewCache();
    // What the answer may claim is what the broker said it did (#854, #704).
    // One line per step, in the order they ran. A step that did not finish
    // says so and names its one fix; nothing else asks the operator for
    // anything. Root's record has three states and only a failed rewrite
    // (or a broker that did not say) needs --refresh-nodes: a label root
    // never held had nothing to take out.
    const confirmation = revokeConfirmation({
      label: node.label, node, outcome, advisorLedger, pushOk, pushed, installDir: installDirOf(deps),
    });
    return {
      status: 200,
      body: {
        ok: true,
        label: node.label,
        pubkey_node: pinned,
        had_link: outcome.had_link,
        nodes_pruned: outcome.nodes_pruned,
        root_record: outcome.root_record,
        tokens_removed: outcome.tokens_removed,
        tokens_failed: outcome.tokens_failed,
        tokens_dir_refused: outcome.tokens_dir_refused,
        trust_push: pushed,
        advisor_ledger: describeFleetRecord(advisorLedger),
        advisor_ledger_ok: advisorLedger.ok,
        advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
        advisor_ledger_self_ok: advisorLedgerSelf.ok,
        advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
        lead: confirmation.lead,
        done: confirmation.done,
        detail: `${confirmation.lead} ${confirmation.done.join(' ')} ${selfLedgerSentence(advisorLedgerSelf)}`,
        ...(confirmation.needsRoot ? { needs_root: confirmation.needsRoot } : {}),
      },
    };
  }

  // ── attach an Advisor to an already-paired node (#641) ─────────────
  //
  // THE SHAPE, and why the order below is not rearrangeable.
  //
  // Attach is a PULL. This host does not send the node a credential; it asks
  // the node for the node's OWN approve.token, and the node answers only
  // when two independent things are both true: the job checks out (a signed
  // job from an aggregator that node already trusts, fresh, once) and a
  // root-planted, time-bounded window is open on that node's own box. This
  // process can satisfy the first at will, which is the point: it cannot
  // satisfy the second, and the second is what a compromised aggregator runs
  // into.
  //
  // So everything this side can refuse on is refused BEFORE the node is
  // contacted at all. A reveal is a window spent, and a window is fifteen
  // minutes of someone's afternoon on another box: it is not spent to find
  // out that the row is a tunnel row, or that it already has an Advisor, or
  // that this host has no broker to write the answer with.
  if (route === 'attach/begin' || route === 'attach') {
    if ((node.transport ?? 'loopback') !== 'link') {
      return {
        status: 409,
        body: {
          error: 'not_a_link',
          detail: `“${node.label}” is not reached over a fleet link, so an Advisor cannot be attached to it `
            + 'this way. Pair that node from Settings first, then attach.',
        },
      };
    }
    if (node.advisor_origin) {
      // #854 security review, L4: this is what a revoke-then-rejoin leaves
      // an operator looking at. Revoke deletes the node's Advisor token
      // file; a rejoin restores advisor_port on the link row but never
      // that file, and this check still reads advisor_origin as set, so
      // Attach refuses here with the token gone and no obvious way back.
      // The broker's own refresh-advisor-token verb rebuilds the token
      // file's content on a row already attached, without touching
      // anything else, so it is named here rather than only "remove it
      // first", which asks for a whole new attach when the row might
      // already be fine.
      return {
        status: 409,
        body: {
          error: 'already_attached',
          detail: `“${node.label}” already has an Advisor attached here. If its Advisor tab is refusing `
            + '(for example after a revoke followed by pairing again, which removes the token file but '
            + 'leaves this row attached), this host’s fleet broker has a refresh-advisor-token verb that '
            + 'rebuilds that file without touching anything else; someone with root on this host can run '
            + 'it. Otherwise, Detach it first if you mean to attach a different Advisor.',
        },
      };
    }
    // ATTACH DOES NOT ACCEPT AN UNPINNED ROW, and this is the one place the
    // four node controls differ on that. Revoke takes NO_PIN because closing
    // a link needs no address; attach cannot, because the reveal job is
    // ADDRESSED to a node key and the broker checks that same key against
    // both fleet.yaml and root's own record. There is no spelling of "I do
    // not know which node this is" that is also an address.
    if (!pinned) {
      return {
        status: 409,
        body: {
          error: 'not_pinned',
          detail: `“${node.label}” pins no node key, so there is no node this request could be addressed `
            + 'to. Pin that row first, then attach.',
        },
      };
    }
  }

  if (route === 'attach/begin') {
    const begun = await beginPairGrant(req, {
      pairingId: attachCeremonyId(node.label),
      label: node.label,
      pubkeyNode: pinned!,
    });
    // What the operator is agreeing to, beside the challenge: the node, its
    // key, and the one thing this act actually grants, which is this
    // aggregator holding that node's Advisor credential from now on.
    return {
      status: begun.status,
      body: begun.status === 200
        ? {
          ...begun.body,
          label: node.label,
          pubkey_node: pinned,
          grants: 'this aggregator will hold that node’s Advisor credential and may push the fleet’s '
            + 'model to it',
        }
        : begun.body,
    };
  }

  if (route === 'attach') {
    const verified = await (deps.verifyPairGrant ?? verifyPairGrant)(req, payload);
    if (!verified.ok) {
      return { status: verified.status, body: { error: verified.error, ...(verified.detail ? { detail: verified.detail } : {}) } };
    }
    if (verified.grant.pairingId !== attachCeremonyId(verified.grant.label)
      || verified.grant.label !== node.label) {
      return {
        status: 409,
        body: {
          error: 'wrong_ceremony',
          detail: 'that approval was taken for something other than attaching an Advisor to this node, so '
            + 'nothing was changed and nothing was asked of that node.',
        },
      };
    }
    if (verified.grant.pubkeyNode !== pinned) {
      return {
        status: 409,
        body: {
          error: 'node_changed',
          detail: 'that approval was taken for a different node key than this row now pins. Read the row '
            + 'again and approve once more.',
        },
      };
    }
    if (!deps.broker) {
      return {
        status: 501,
        body: {
          error: 'no_broker',
          detail: 'this host has no fleet broker installed, so it cannot record an Advisor against a node. '
            + `Install the grant: ${grantStepCommand(installDirOf(deps))}`,
        },
      };
    }

    // THE APPROVAL, on the record before any of the work, exactly as revoke
    // writes one: an attach that was approved and then interrupted still
    // spent a passkey touch, and an operator asking what spent it must find
    // the answer.
    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: { act: 'attach_approved', pubkey_node: pinned, credential_id: verified.grant.credentialId },
    });

    // THE REVEAL. The pin is checked inside, before anything is sent.
    const revealed = await (deps.revealAdvisorToken ?? revealPeerAdvisorToken)(node, {
      seed: readOwnPrivateKey(deps.fleetTrustPath),
    });
    if (!revealed.ok) {
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: { act: 'attach_failed', pubkey_node: pinned, error: revealed.reason, stage: 'reveal' },
      });
      return {
        status: revealed.window_closed ? 409 : 502,
        body: {
          error: revealed.reason,
          // This side's sentence, and that node's underneath it as a
          // separate field. Never one string: "that node said" over this
          // host's own conclusion attributes a failure to the box that
          // failed to answer.
          detail: revealed.window_closed
            ? revealed.detail
            : `${revealed.detail} Nothing was changed here.`,
          said: revealed.said ?? null,
          ...(revealed.window_closed ? { rearm_command: ADVISOR_INSTALL_CMD } : {}),
          ...(revealed.old_build ? { old_build: true } : {}),
        },
      };
    }

    // THE BROKER, and it is the only writer. The token goes down the socket
    // and is never held past this call: not in the response, not in the
    // audit row, not in a log line.
    let answer: { code: number; stdout: string; stderr: string; reported?: boolean; timedOut?: boolean };
    try {
      answer = await deps.broker(brokerAttachAdvisorPayload({
        label: node.label, pubkey_node: pinned!, advisor_token: revealed.token,
      }));
    } catch (err) {
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: { act: 'attach_failed', pubkey_node: pinned, error: 'no_broker', stage: 'broker' },
      });
      return {
        status: 502,
        body: {
          error: 'no_broker',
          // The attach's own copies are both written AFTER the broker, so a
          // refusal here really did leave the ledgers alone. What it cannot
          // say is that nothing was changed, on the one path where the call
          // is still queued and may land later.
          detail: brokerOutcomeUnknown(err)
            ? brokerUnknownDetail('attach')
            : `this host’s fleet broker could not be reached (${(err as Error).name}), so nothing was changed.`,
        },
      };
    }
    const outcome = brokerAttachAdvisorOutcome(
      brokerAnswerOf(answer), installDirOf(deps),
    );
    if (!outcome.ok) {
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: { act: 'attach_failed', pubkey_node: pinned, error: outcome.error, stage: 'broker' },
      });
      // A broker that gave no answer (#848) has not said nothing changed, and
      // its own sentence says it cannot tell. Adding "Nothing was changed"
      // under it would contradict the line above it.
      return {
        status: 409,
        body: { error: outcome.error, detail: outcome.error === 'no_answer' ? outcome.detail : `${outcome.detail} Nothing was changed.` },
      };
    }

    // THE LEDGER COPY GOES AFTER THE BROKER, AND THIS IS THE ONE ORDERING ON
    // THIS PAGE THAT IS THE OPPOSITE OF REVOKE'S.
    //
    // A revoke writes its copy first because the broker's revoke closes the
    // link the copy travels over. An attach is the mirror: before the broker
    // there is no advisor_origin on this row at all, so appendFleetRecord's
    // own first gate would answer `no_advisor` and skip the write, honestly
    // and uselessly. The address exists only after the broker has written
    // fleet.yaml and this process has re-read it.
    //
    // So the row is RE-READ rather than reused. `node` is the object this
    // request started with and it is bare by definition; the row that now
    // carries an Advisor is the one deps.peers() returns after the reload.
    // A reload that did not land leaves the copy unwritten and says so,
    // which is the same honest failure every other ledger copy can have.
    //
    // The broker SIGHUPs this process itself, and this is the fallback for a
    // host where that did not land. It runs BEFORE the re-read, not after
    // the answer, because the re-read is the thing that needs it.
    if (!outcome.reloaded) { try { deps.reloadFleet?.(); } catch { /* a stale page, never a lost write */ } }
    let attachedRow = deps.peers().find((p) => p.label === node.label) ?? node;
    if (!attachedRow.advisor_origin) {
      // One more re-read, once, after asking for the reload the broker said
      // it had already done. A row still bare here is a registry this
      // process has not picked up, and the answer says the copy did not land
      // rather than pretending it did.
      try { deps.reloadFleet?.(); } catch { /* same */ }
      attachedRow = deps.peers().find((p) => p.label === node.label) ?? node;
    }
    const attachFacts = {
      node: node.label,
      operator: session.username,
      role: session.role,
      credentialId: verified.grant.credentialId,
      origin: requestOrigin(req),
      pubkeyNode: pinned,
    };
    const attachRecord = buildFleetRecord('fleet.advisor_attached', attachFacts);
    // RETRIED, AND ONLY ON `unreachable`. The address this copy travels over
    // is a loopback port the hub binds on its next reconcile, and that bind
    // is asynchronous: the row exists the moment the broker writes it, and
    // the listener behind it comes up a beat later. So the first attempt can
    // land in a real gap where the port is in the registry and nothing is
    // answering on it, and the node's own record of the act would be missing
    // for good over a race that resolves itself in under a second.
    //
    // ONE reason retries, deliberately. `unreachable` is "this did not get
    // there", which is the only shape a bind race can take. A refusal, a
    // pin mismatch, a node with no Advisor and a record the node called too
    // old are all DECISIONS, and asking again cannot change any of them.
    // Retrying a decision would turn one honest refusal into four.
    //
    // The SAME record every time, so a retry that races a first attempt
    // which actually landed is answered as the duplicate it is, by the
    // node's own replay guard, rather than written twice (#691).
    const advisorLedger = await retryWhileUnreachable(
      () => (deps.appendAdvisorLedger ?? appendFleetRecord)(
        attachedRow, deps.fleetTrustPath, 'fleet.advisor_attached', attachFacts,
        { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS, record: attachRecord },
      ),
      deps.sleep ?? sleepMs,
    );
    // The aggregator's own copy of the same act (#477), same record id,
    // attempted whether or not the node's landed.
    const advisorLedgerSelf = await (deps.appendOwnAdvisorLedger ?? appendOwnFleetRecord)(
      deps.fleetTrustPath, attachRecord, deps.selfAdvisorPresence(),
      deps.advisorUrl ?? null, deps.advisorToken ? deps.advisorToken() : null,
      { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS },
    );

    // THE PASSKEY LIST, to that node's Advisor, the push pairing makes after
    // its link is held (#983). Without it the Advisor just attached checks
    // every approval against the set it held before, which for one that never
    // had a bundle is none at all, and nobody can approve an action there
    // until a command is run on this aggregator. AFTER the ledger copy,
    // because the push travels over the same listener and the copy's retry
    // is what waits out its bind. Never a reason to fail the attach: the
    // attach stands, and a push that did not land is said with its command.
    let pushed: string;
    let pushOk = false;
    try {
      const r = await deps.pushTrust(node.label);
      pushOk = r.ok;
      pushed = r.ok ? (lastLine(r.output) || 'pushed')
        : pushFailedLine(r.output, node.label, new Set(deps.peers().map((p) => p.label)));
    } catch (err) {
      pushed = `the push could not be started (${(err as Error).name})`;
    }
    const pushSentence = pushOk
      ? 'It holds the current passkey list. '
      : `The passkey list did not reach it (${pushed}), so its Advisor checks approvals against the set it `
        + `held before. Push it from this aggregator, in ${installDirOf(deps)}: `
        + `${trustSyncRemedy(node.label).remedy} `;

    // THE FLEET'S MODEL, the inherit a pairing makes (#1037). Ruling
    // 2026-09-04: provider, model and key are one fleet setting, inherited at
    // registration. A node whose Advisor arrives AFTER it paired has nothing
    // to inherit at its pairing, so attach is where it registers that Advisor
    // and where it inherits. The same decision and the same broker push the
    // follow-on uses, under the passkey this attach was approved with, whose
    // confirmation already says the fleet's model may be pushed to it. The
    // key goes root to root; this process never holds it.
    const modelState = await startAttachModel(deps, attachedRow, {
      grantedBy: verified.grant.operator, credentialId: verified.grant.credentialId,
    }, { username: session.username, role: session.role });
    // The sentence goes LAST, after the ledger lines, because one of them
    // ends in a root command an operator copies.
    const modelSentence = modelState ? attachModelSentence(modelState, armInstalledOf(deps)) : '';

    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: {
        act: 'attached', pubkey_node: pinned, advisor_port: outcome.advisor_port,
        advisord_version: revealed.advisord_version, credential_id: verified.grant.credentialId,
        trust_push: pushed, model: modelState ?? 'not_attempted',
        advisor_ledger: describeFleetRecord(advisorLedger),
        advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
        advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
      },
    });
    clearSettingsOverviewCache();
    return {
      status: 200,
      body: {
        ok: true,
        label: node.label,
        advisor_port: outcome.advisor_port,
        advisord_version: revealed.advisord_version,
        reloaded: outcome.reloaded,
        advisor_ledger: describeFleetRecord(advisorLedger),
        advisor_ledger_ok: advisorLedger.ok,
        advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
        advisor_ledger_self_ok: advisorLedgerSelf.ok,
        advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
        trust_push: pushed,
        trust_push_ok: pushOk,
        model: modelState ?? 'not_attempted',
        detail: `“${node.label}” has an Advisor attached${revealed.advisord_version ? `, build ${revealed.advisord_version}` : ''}. `
          + 'Its Advisor tab answers from here now. '
          + pushSentence
          // A host with no store to read and no broker to push through says
          // what it always said: that is still a separate step there.
          + (modelState ? '' : 'Giving it the fleet’s model is a separate step. ')
          // SAID EITHER WAY, because the CHANGELOG promises this entry and a
          // promise that is silently sometimes true is worse than one that
          // is qualified. The copy is retried while it is unreachable; if it
          // still did not land, the answer names that rather than leaving an
          // operator to find a gap in that node's own record later.
          + nodeLedgerSentence(node.label, advisorLedger)
          + selfLedgerSentence(advisorLedgerSelf)
          + (modelSentence ? ` ${modelSentence}` : ''),
      },
    };
  }

  // ── remove an Advisor from a node (#641) ───────────────────────────
  //
  // Passkey-gated like revoke, and for the same reason: it touches root's
  // own record and the operator audit. NO NODE CONTACT AT ALL, which is both
  // the scope and the honest limit. This forgets an address; it does not
  // uninstall anything, and it cannot invalidate a bearer token this host
  // has already held. That sentence is on the confirmation, not buried.
  if (route === 'detach/begin' || route === 'detach') {
    if (!node.advisor_origin) {
      return {
        status: 409,
        body: {
          error: 'not_attached',
          detail: `“${node.label}” has no Advisor attached here, so there is nothing to remove.`,
        },
      };
    }
    // THE SAME TRANSPORT CHECK ATTACH MAKES, and it was missing here
    // (review finding, 2026-09-27). A row reached down a tunnel CAN carry an
    // `advisor_origin`: that is a documented, supported fleet shape, older
    // than links. The broker's `detach-advisor` refuses one by name
    // (`label_not_a_link`), and an older installed broker refuses the verb
    // outright, so the whole request was only ever going to end in a
    // refusal. Refusing it HERE is what keeps it from spending a passkey
    // touch and writing a permanent ledger entry on the way to finding that
    // out. `#620`'s convert is the path for such a row, and it is named.
    if ((node.transport ?? 'loopback') !== 'link') {
      return {
        status: 409,
        body: {
          error: 'not_a_link',
          detail: `“${node.label}” is not reached over a fleet link, so its Advisor cannot be removed this `
            + 'way. Convert that row to a link first, from its Pending row, and then remove it.',
        },
      };
    }
  }

  if (route === 'detach/begin') {
    const begun = await beginPairGrant(req, {
      pairingId: detachCeremonyId(node.label),
      label: node.label,
      pubkeyNode: pinned ?? NO_PIN,
    });
    return {
      status: begun.status,
      body: begun.status === 200
        ? { ...begun.body, label: node.label, pubkey_node: pinned, limit: ADVISOR_DETACH_COPY }
        : begun.body,
    };
  }

  if (route === 'detach') {
    const verified = await (deps.verifyPairGrant ?? verifyPairGrant)(req, payload);
    if (!verified.ok) {
      return { status: verified.status, body: { error: verified.error, ...(verified.detail ? { detail: verified.detail } : {}) } };
    }
    if (verified.grant.pairingId !== detachCeremonyId(verified.grant.label)
      || verified.grant.label !== node.label) {
      return {
        status: 409,
        body: {
          error: 'wrong_ceremony',
          detail: 'that approval was taken for something other than removing this node’s Advisor, so '
            + 'nothing was changed.',
        },
      };
    }
    if (verified.grant.pubkeyNode !== (pinned ?? NO_PIN)) {
      return {
        status: 409,
        body: {
          error: 'node_changed',
          detail: 'that approval was taken for a different node key than this row now pins. Read the row '
            + 'again and approve once more.',
        },
      };
    }
    if (!deps.broker) {
      return {
        status: 501,
        body: {
          error: 'no_broker',
          detail: 'this host has no fleet broker installed, so it cannot take an Advisor off a node’s '
            + `record. Install the grant: ${grantStepCommand(installDirOf(deps))}`,
        },
      };
    }

    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: { act: 'detach_approved', pubkey_node: pinned, credential_id: verified.grant.credentialId },
    });

    // THE COPY ON THE NODE GOES FIRST, exactly as a revoke's does and for
    // exactly the same reason: the broker's detach takes `advisor_origin`
    // out of the row, and that address IS the path this copy travels over.
    // Written afterwards it would reach nobody, on the one node the entry is
    // most about. Written here the address still resolves and the approval
    // above is already on the operator audit.
    //
    // A failure here does not undo the act and never asks. The operator
    // audit row is the record of the detach; this is a copy on the node.
    const detachFacts = {
      node: node.label,
      operator: session.username,
      role: session.role,
      credentialId: verified.grant.credentialId,
      origin: requestOrigin(req),
      pubkeyNode: pinned,
    };
    const detachRecord = buildFleetRecord('fleet.advisor_detached', detachFacts);
    const advisorLedger = await (deps.appendAdvisorLedger ?? appendFleetRecord)(
      node, deps.fleetTrustPath, 'fleet.advisor_detached', detachFacts,
      { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS, record: detachRecord },
    );

    let answer: { code: number; stdout: string; stderr: string; reported?: boolean; timedOut?: boolean };
    try {
      answer = await deps.broker(brokerDetachAdvisorPayload(node.label));
    } catch (err) {
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: { act: 'detach_failed', pubkey_node: pinned, error: 'no_broker' },
      });
      return {
        status: 502,
        body: {
          error: 'no_broker',
          detail: refusalAfterLedgerCopies(node.label, advisorLedger, null,
            brokerOutcomeUnknown(err)
              ? brokerUnknownDetail('removal')
              : `this host’s fleet broker could not be reached (${(err as Error).name}), so the Advisor is `
                + 'still attached here.'),
          advisor_ledger: describeFleetRecord(advisorLedger),
          advisor_ledger_ok: advisorLedger.ok,
        },
      };
    }
    const outcome = brokerDetachAdvisorOutcome(
      brokerAnswerOf(answer), installDirOf(deps),
    );
    if (!outcome.ok) {
      recordAuthEvent({
        actor: session.username, actorRole: session.role, event: 'fleet_pairing',
        target: node.label,
        detail: {
          act: 'detach_failed', pubkey_node: pinned, error: outcome.error,
          advisor_ledger: describeFleetRecord(advisorLedger),
        },
      });
      return {
        status: 409,
        body: {
          error: outcome.error,
          detail: refusalAfterLedgerCopies(node.label, advisorLedger, null,
            outcome.error === 'no_answer' ? outcome.detail : `${outcome.detail} The Advisor is still attached here.`),
          advisor_ledger: describeFleetRecord(advisorLedger),
          advisor_ledger_ok: advisorLedger.ok,
        },
      };
    }

    // THE AGGREGATOR'S OWN COPY, and it is AFTER the broker on purpose
    // (review finding, 2026-09-27). The node's copy has to go first, because
    // the broker is what takes away the address it travels over. This one
    // has no such constraint: it goes to this host's own Advisor over
    // loopback, which the broker cannot take away, so writing it before the
    // broker only bought a second permanent entry for an act that might not
    // happen. Same record and same record_id either way, so the two copies
    // of one act still cannot disagree about which act they are.
    const advisorLedgerSelf = await (deps.appendOwnAdvisorLedger ?? appendOwnFleetRecord)(
      deps.fleetTrustPath, detachRecord, deps.selfAdvisorPresence(),
      deps.advisorUrl ?? null, deps.advisorToken ? deps.advisorToken() : null,
      { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS },
    );

    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: {
        act: 'detached', pubkey_node: pinned, nodes_updated: outcome.nodes_updated,
        credential_id: verified.grant.credentialId,
        advisor_ledger: describeFleetRecord(advisorLedger),
        advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
        advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
      },
    });
    if (!outcome.reloaded) { try { deps.reloadFleet?.(); } catch { /* a stale page, never a lost write */ } }
    clearSettingsOverviewCache();
    return {
      status: 200,
      body: {
        ok: true,
        label: node.label,
        nodes_updated: outcome.nodes_updated,
        reloaded: outcome.reloaded,
        advisor_ledger: describeFleetRecord(advisorLedger),
        advisor_ledger_ok: advisorLedger.ok,
        advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
        advisor_ledger_self_ok: advisorLedgerSelf.ok,
        advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
        detail: `The Advisor is off “${node.label}” here. ${ADVISOR_DETACH_COPY} `
          + selfLedgerSentence(advisorLedgerSelf),
      },
    };
  }

  // ── accept a changed node key (#422) ───────────────────────────────
  //
  // Never on the node's say-so and never on a label match alone. What the
  // operator compares is the key this dashboard pinned against the key that
  // node answered with, and the approval carries both.
  const observed = typeof row?.pin_reported === 'string' ? row.pin_reported : null;
  const observedAgainst = typeof row?.pin_expected === 'string' ? row.pin_expected : null;
  if (!pinned) {
    return {
      status: 409,
      body: { error: 'not_pinned', detail: `“${node.label}” pins no node key, so there is nothing to re-pin.` },
    };
  }
  if (!observed || observedAgainst !== pinned || observed === pinned) {
    return {
      status: 409,
      body: {
        error: 'no_mismatch',
        detail: `this dashboard has not read a different node key from “${node.label}”. A key it could not `
          + 'read is not a key that changed, so there is nothing to accept.',
      },
    };
  }

  if (route === 'repin/begin') {
    const begun = await beginPairGrant(req, {
      pairingId: repinCeremonyId(node.label),
      label: node.label,
      pubkeyNode: observed,
    });
    return {
      status: begun.status,
      body: begun.status === 200
        ? { ...begun.body, label: node.label, pinned_pubkey_node: pinned, observed_pubkey_node: observed }
        : begun.body,
    };
  }

  const verified = await (deps.verifyPairGrant ?? verifyPairGrant)(req, payload);
  if (!verified.ok) {
    return { status: verified.status, body: { error: verified.error, ...(verified.detail ? { detail: verified.detail } : {}) } };
  }
  if (verified.grant.pairingId !== repinCeremonyId(verified.grant.label)
    || verified.grant.label !== node.label) {
    return {
      status: 409,
      body: {
        error: 'wrong_ceremony',
        detail: 'that approval was taken for something other than accepting this node’s new key, so nothing '
          + 'was changed.',
      },
    };
  }
  // The key that was SHOWN against the key that node answers with now. A
  // third key arriving between the two halves is a third decision, and this
  // approval is not it.
  if (verified.grant.pubkeyNode !== observed) {
    return {
      status: 409,
      body: {
        error: 'node_changed',
        detail: 'that node is now reporting a different key again from the one you were shown. Compare the '
          + 'two keys on the row once more and approve it again.',
      },
    };
  }
  if (!deps.broker) {
    return {
      status: 501,
      body: {
        error: 'no_broker',
        detail: 'this host has no fleet broker installed, and accepting a new key is root’s to write. Install '
          + `the grant: ${grantStepCommand(installDirOf(deps))}`,
      },
    };
  }

  recordAuthEvent({
    actor: session.username, actorRole: session.role, event: 'fleet_pairing',
    target: node.label,
    detail: {
      act: 'repin_approved', pinned_pubkey_node: pinned, observed_pubkey_node: observed,
      credential_id: verified.grant.credentialId,
    },
  });

  // #859: root's broker writes the row, never this process. `pinned` is the
  // key the operator was shown, so a row moved again since refuses there.
  let repinAnswer: { code: number; stdout: string; stderr: string };
  let repinError: { error: string; detail: string } | null = null;
  try {
    repinAnswer = await deps.broker(brokerRepinPayload(node.label, pinned, observed));
    const r = brokerRepinOutcome(brokerAnswerOf(repinAnswer), installDirOf(deps));
    if (!r.ok) repinError = { error: r.error, detail: r.detail };
  } catch (err) {
    repinError = brokerOutcomeUnknown(err)
      ? { error: 'no_answer', detail: brokerUnknownDetail('repin') }
      : { error: 'no_broker', detail: `this host’s fleet broker could not be reached (${(err as Error).name}), so the row was not re-pinned.` };
  }
  if (repinError) {
    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      target: node.label,
      detail: {
        act: 'repin_failed', pinned_pubkey_node: pinned, observed_pubkey_node: observed,
        error: repinError.error,
      },
    });
    return { status: repinError.error === 'no_broker' ? 502 : 409, body: repinError };
  }

  // THE COPY ON THE NODE, AND HERE IT GOES AFTER THE WRITE (#455), which is
  // the opposite of the revoke above and for the same reason: the entry has
  // to be able to reach the node.
  //
  // Every call this dashboard makes to a peer's Advisor verifies the pin
  // first, and the pin is exactly what was wrong until the line above ran.
  // So the row is re-pinned first, and the node object this append carries
  // is the row as it now stands. `observed` is not a value from the request:
  // it is the key this dashboard read from that node and the operator
  // approved at a passkey one step ago, which is what the check about to run
  // against the node will find it still reporting.
  //
  // As on the revoke, a failure here does not undo the re-pin. The act is
  // the registry row, already written; this is the node's own copy.
  const repinFacts = {
    node: node.label,
    operator: session.username,
    role: session.role,
    credentialId: verified.grant.credentialId,
    origin: requestOrigin(req),
    wasPubkeyNode: pinned,
    nowPubkeyNode: observed,
  };
  const repinRecordBuilt = buildFleetRecord('fleet.node_key_repinned', repinFacts);
  const advisorLedger = await (deps.appendAdvisorLedger ?? appendFleetRecord)(
    { ...node, expected_pubkey_node: observed }, deps.fleetTrustPath, 'fleet.node_key_repinned',
    repinFacts, { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS, record: repinRecordBuilt },
  );

  // THE AGGREGATOR'S OWN COPY (#477), right beside the node's above and not
  // gated on whether that one landed. See the matching comment on the
  // revoke path.
  const advisorLedgerSelf = await (deps.appendOwnAdvisorLedger ?? appendOwnFleetRecord)(
    deps.fleetTrustPath, repinRecordBuilt, deps.selfAdvisorPresence(),
    deps.advisorUrl ?? null, deps.advisorToken ? deps.advisorToken() : null,
    { timeoutMs: ADVISOR_LEDGER_TIMEOUT_MS },
  );

  recordAuthEvent({
    actor: session.username, actorRole: session.role, event: 'fleet_pairing',
    target: node.label,
    detail: {
      act: 'repinned', was_pubkey_node: pinned, now_pubkey_node: observed,
      credential_id: verified.grant.credentialId,
      advisor_ledger: describeFleetRecord(advisorLedger),
      advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
      advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
    },
  });
  clearSettingsOverviewCache();
  // The honest half. Root's own push-destination record still names the old
  // key, and this dashboard does not write that file: `model-push` resolves
  // a label there and nowhere else, so a catch-up to this node refuses until
  // root has been asked to vouch for the registry as it stands now.
  return {
    status: 200,
    body: {
      ok: true,
      label: node.label,
      was_pubkey_node: pinned,
      now_pubkey_node: observed,
      advisor_ledger: describeFleetRecord(advisorLedger),
      advisor_ledger_ok: advisorLedger.ok,
      advisor_ledger_self: describeFleetRecord(advisorLedgerSelf),
      advisor_ledger_self_ok: advisorLedgerSelf.ok,
      advisor_ledger_self_reason: fleetRecordReason(advisorLedgerSelf),
      detail: `“${node.label}” is pinned to the key it reports, and its reads work again. One thing is `
        + 'left, and it needs root: this host’s own record of where a model key may be sent still names '
        + 'the old key, so run '
        + `${grantStepCommand(installDirOf(deps), '--refresh-nodes')} `
        + 'before the next catch-up to this node. It prints the old and the new key before it writes: '
        + `compare the new one with pubkey_node in ${node.label}’s own server_info before you confirm, `
        + 'because it reads the key this page just wrote. '
        + selfLedgerSentence(advisorLedgerSelf),
      needs_root: {
        why: 'the fleet model may not be sent to this node until root vouches for its new key',
        command: `${grantStepCommand(installDirOf(deps), '--refresh-nodes')}`,
      },
    },
  };
}

/**
 * The three verbs on a Pending row.
 *
 * `approve/begin` and `approve` are two halves of one ceremony and the
 * binding between them is the challenge record: the label and the node key
 * are written at begin and read back from the record at finish, never from
 * the request that carries the signature. `refuse` needs no passkey, because
 * refusing grants nothing.
 */
/**
 * Is this host ready to pair a node? (Pairing v2, lane B.)
 *
 * The question the Add a node page asks before it shows the fingerprint
 * step: can root here print a pairing fingerprint, and does an approval have
 * the keys it needs? It asks the broker's `arm-key-check`, which reports
 * whether the fleet arm key is there and NEVER makes one (#846 review, L5),
 * then reads whether this dashboard holds a fleet trust key.
 *
 * It makes nothing on purpose, and on a fleet whose key was lost neither
 * does anything else (#851): the broker answers fleet_arm_key_lost, and this
 * offers the restore command, naming the grant's --new-fleet-keys only as
 * the deliberate alternative.
 *
 * Asked once per visit to the step, never polled: the broker's socket takes
 * one connection at a time (MaxConnections=1), so a polled check would make
 * an approval answer busy. Nothing is cached either: the answer is about
 * this moment.
 *
 * A POST, because it reaches root's broker and the settings gate requires
 * CSRF on anything that does. One answer: `{ ok: true }`, or
 * `{ ok: false, error, detail, command }` for the first thing in the way,
 * with the sentence an operator reads and the one command that fixes it.
 * Every failure here is fixed by the full grant install, which also makes
 * both keys.
 */
export async function pairReadiness(
  deps: SettingsAdminDeps,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const grant = grantInstallSentence(installDirOf(deps));
  const notReady = (error: string, detail: string, command: string | null) => ({
    status: 200, body: { ok: false, error, detail, command },
  });
  const noGrant = () => notReady('no_grant',
    `This host isn't set up to pair nodes yet. Install the pairing grant first: ${grant}`, grant);

  if (!deps.broker) return noGrant();
  let check: ReturnType<typeof brokerArmKeyCheckOutcome>;
  try {
    const answer = await deps.broker(brokerArmKeyCheckPayload());
    check = brokerArmKeyCheckOutcome(brokerAnswerOf(answer),
      installDirOf(deps));
  } catch (err) {
    if (isSocketUnreachable(err)) return noGrant();
    if (brokerOutcomeUnknown(err)) return notReady('broker_busy', BROKER_BUSY_DETAIL, null);
    return notReady('no_broker', `this host's fleet broker could not be reached: ${(err as Error).message}`, grant);
  }
  if (!check.ok) {
    if (check.error === 'no_answer') return notReady('broker_busy', check.detail, null);
    if (check.error === BROKER_NO_ANSWER) return notReady(BROKER_NO_ANSWER, check.detail, null);
    // fleet_arm_key_lost (#851) carries its own command, the restore: the
    // grant install would refuse on that host, and the re-key it names is
    // never the button. install_moved (#828), no_fleet_arm_key and the rest:
    // the broker's own sentence, which names its own command. That command
    // is the one offered when it is there; the grant install otherwise.
    if (check.command) return notReady(check.error, check.detail, check.command);
    const named = GRANT_STEP_IN_DETAIL.exec(check.detail);
    return notReady(check.error, check.detail, named ? named[0] : grant);
  }
  // The command step 3 tells the operator to run, at its fixed name. A
  // broker that answers is not proof of it (#812): a grant older than the
  // installed name has the socket and not the command.
  if (!armInstalledOf(deps)) {
    return notReady('no_fingerprint_command',
      'This host\u2019s pairing grant predates the command that prints the pairing fingerprint '
        + `(${PAIRING_FINGERPRINT_COMMAND}). Run the grant installer again to install it: ${grant}`, grant);
  }
  // After the broker, deliberately: a host with no grant is told to install
  // the grant, which makes this key too, rather than about the key first.
  if (!(deps.fleetTrustPubKey?.() ?? null)) {
    // #851 review L4a: with peers in this dashboard's own registry the key
    // was lost, and the grant install refuses (exit 4) rather than make one.
    // The restore is the command, the re-key only named, as for the arm key.
    // Optional-called: a caller holding a partial deps (the pairing walk) has
    // no registry, which is the first-aggregator answer.
    const paired = (deps.peers?.() ?? []).map((p) => p.label);
    if (paired.length) return notReady('fleet_trust_key_lost', trustKeyLostDetail(installDirOf(deps), paired), restoreSentence(installDirOf(deps)));
    return notReady('no_fleet_trust_key',
      'This aggregator has no fleet trust key, so there is no pairing fingerprint to print. Its pairing '
        + 'grant predates the grant making that key, and an update does not make it. Run the grant '
        + `installer again: ${grant}`, grant);
  }
  return { status: 200, body: { ok: true } };
}

/**
 * The name an approval is bound to. A known row's and a reconnect row's are
 * the fleet's own and never the caller's to pick (#620, #624); every other
 * row keeps what the operator typed, else its own proposal. A reconnect is
 * NOT a convert (convertTunnel stays false): the broker takes the rejoin it
 * already makes for a node reconnecting under its own label, where any other
 * name would be refused pin_taken after the passkey.
 */
export function pairApprovalLabel(
  row: Pick<PairingRow, 'known_label' | 'reconnect_label' | 'label'>, typed: unknown,
): string {
  return row.known_label ?? row.reconnect_label ?? (typeof typed === 'string' && typed ? typed : row.label);
}

async function handlePairRoute(
  route: 'approve/begin' | 'approve' | 'refuse',
  req: IncomingMessage,
  payload: Record<string, unknown>,
  deps: SettingsAdminDeps,
  session: AuthSessionInfo,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const rows = deps.pairings?.() ?? [];
  const id = typeof payload.pairing_id === 'string' ? payload.pairing_id : '';
  const row = rows.find((r) => r.id === id) ?? null;

  if (route === 'refuse') {
    if (!deps.pairRefuse || !row) {
      return { status: 404, body: { error: 'no_such_pending', detail: 'that pairing is not one this dashboard is holding.' } };
    }
    deps.pairRefuse(id);
    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing',
      // #635 review: a known row's own name, when there is one -- row.label
      // is whatever was proposed (the node's hello, or now an operator's
      // typed name), and a known row's proposal is never the identity this
      // journal should record against.
      target: row.known_label ?? row.reconnect_label ?? row.label, detail: { act: 'refused', pubkey_node: row.pubkey_node },
    });
    return { status: 200, body: { ok: true } };
  }

  if (!row) {
    return {
      status: 404,
      body: {
        error: 'no_such_pending',
        detail: 'that pairing is not one this dashboard is holding. It expired, it was refused, or this '
          + 'dashboard restarted: a pairing socket cannot survive a restart, so run the command on the node again.',
      },
    };
  }
  // #620: a clash refuses here too, defense in depth. The page offers no
  // Approve control for one of these, so reaching this is either a stale
  // tab or a request that did not come from the page at all -- neither
  // gets a passkey ceremony spent on a row that can only ever be refused.
  if (row.clash_reason) {
    return { status: 409, body: { error: 'pair_clash', detail: row.clash_reason } };
  }
  // Pairing v2: a row whose node has not confirmed the fingerprint (or said
  // it did not match) gets no passkey ceremony at all, on either half. The
  // page shows no Approve for it, so this is a stale tab or a request that
  // did not come from the page. The hub's own `not_checked` is the last line.
  if (row.check === 'waiting_at_node' || row.check === 'mismatch') {
    return {
      status: 409,
      body: {
        error: 'not_checked',
        detail: row.check === 'mismatch'
          ? 'that node refused this aggregator\u2019s keys: the fingerprint pasted there does not match. Nothing was registered.'
          : 'that node has not confirmed this aggregator\u2019s pairing fingerprint yet. Wait for its row to say it matched.',
      },
    };
  }
  // #626: a known node's move gets no passkey ceremony until its node proved
  // it holds the read token this aggregator reads it with. The hub refuses
  // such a row before Approve renders, and refuses `move_unverified` at
  // approve; this keeps a stale tab or a hand-made request from spending a
  // touch first.
  if (row.known_label !== null && row.move_proof !== 'verified') {
    return {
      status: 409,
      body: {
        error: 'move_unverified',
        detail: `that node has not proved it holds the read token this aggregator reads ${row.known_label} with, so it is not moved.`,
      },
    };
  }
  // The label the operator settled on. For a known node this is NEVER the
  // caller's to pick -- it is the row's own classification, re-derived from
  // fleet.yaml a moment ago, and the name the node itself proposed is
  // ignored on purpose (#620). Every other row keeps today's rule: what the
  // operator typed, or the row's own label, validated here and again in the
  // hub, and bound into the challenge record so the name that was approved
  // is the name that gets written.
  const convertTunnel = row.known_label !== null;
  const label = pairApprovalLabel(row, payload.label);
  if (!LABEL_RE.test(label)) {
    return { status: 400, body: { error: 'bad_label', detail: 'a label must match [a-z0-9-]{1,32}, the same rule fleet.yaml uses.' } };
  }

  if (route === 'approve/begin') {
    const begun = await beginPairGrant(req, { pairingId: id, label, pubkeyNode: row.pubkey_node, convertTunnel });
    return { status: begun.status, body: begun.body };
  }

  const verified = await (deps.verifyPairGrant ?? verifyPairGrant)(req, payload);
  if (!verified.ok) {
    return { status: verified.status, body: { error: verified.error, ...(verified.detail ? { detail: verified.detail } : {}) } };
  }
  // #620 review (123): the signed record's own pairing id against the one
  // this route is finishing. beginPairGrant binds pairingId in beside the
  // key, and this had never been read back: a touch taken for one Pending
  // row could otherwise finish against another id whose pubkey_node just
  // happened to still agree (two rows sharing a key, #315's own shape).
  if (verified.grant.pairingId !== id) {
    return {
      status: 409,
      body: {
        error: 'pending_changed',
        detail: 'that approval was taken for a different pairing than the row now holds. Compare the '
          + 'fingerprint again and approve it once more.',
      },
    };
  }
  // The record's key against the LIVE row's. A touch captured while one
  // Pending row was on screen must not be spendable on another, and the id
  // alone is a value the page holds.
  if (verified.grant.pubkeyNode !== row.pubkey_node) {
    return {
      status: 409,
      body: {
        error: 'pending_changed',
        detail: 'that approval was taken for a different node key than the row now holds. Compare the '
          + 'fingerprint again and approve it once more.',
      },
    };
  }
  // #620: the SIGNED record of which decision this was, against what the
  // row says now. A row cannot flip from known to new or back between begin
  // and finish (it is judged once, at call-in), so a disagreement here means
  // the touch was for a different row than the one now behind this id.
  if (verified.grant.convertTunnel !== convertTunnel) {
    return {
      status: 409,
      body: {
        error: 'pending_changed',
        detail: 'that approval does not match what this row is now. Compare the row again and approve once more.',
      },
    };
  }
  if (!deps.pairApprove || !deps.broker) {
    return {
      status: 501,
      body: {
        error: 'no_broker',
        detail: 'this host has no fleet broker installed, so it cannot register a node. Install the grant: '
          + grantInstallSentence(installDirOf(deps)),
      },
    };
  }

  // #741: the fleet arm key, from root, BEFORE the welcome. The welcome
  // carries it, signed, so the pairing fingerprint the operator pastes at the
  // node covers it before a token leaves that node. On a fresh aggregator this
  // is where the key is made. Refused here rather than sent without one: the
  // node refuses a welcome with no arm key, after the operator has walked to
  // it, and this row stays approvable.
  let armKey: ReturnType<typeof brokerArmKeyOutcome>;
  try {
    const armAnswer = await deps.broker(brokerArmKeyPayload());
    armKey = brokerArmKeyOutcome(brokerAnswerOf(armAnswer),
      installDirOf(deps));
  } catch (err) {
    armKey = {
      ok: false, error: 'no_broker',
      detail: `this host's fleet broker could not be reached: ${(err as Error).message}`,
    };
  }
  if (!armKey.ok) {
    return {
      status: 409,
      body: { error: armKey.error, detail: armKey.detail, ...(armKey.command ? { command: armKey.command } : {}) },
    };
  }
  const armKeyAtApproval = armKey;
  // The freshest word on the key, for the next keys-first node. The hub
  // compares this same answer with what it sent this row (arm_key_changed).
  deps.rememberArmPubKey?.(armKeyAtApproval.fleet_arm_pubkey);

  // The approval is on the record NOW, before the node has answered. An
  // approval whose node never comes back still happened, and a record that
  // waited for the settlement would have nothing to show for it.
  recordAuthEvent({
    actor: session.username, actorRole: session.role, event: 'fleet_pairing',
    target: verified.grant.label,
    detail: {
      act: 'approved', pubkey_node: row.pubkey_node, dialed_from: row.dialed_from,
      credential_id: verified.grant.credentialId,
      // #741: which arm key the welcome carried, and whether this approval
      // is what made it.
      fleet_arm_key: armKeyAtApproval.fleet_arm_key ?? 'present',
    },
  });

  const outcome = deps.pairApprove(id, verified.grant.label, (tokens) => settlePairing({
    deps, session, label: verified.grant.label, row, tokens,
    // Who approved THIS pairing, carried through to the model inherit: the
    // node's own ledger names the operator whose passkey let the key reach
    // it, and this ceremony is the one that did.
    grant: { grantedBy: verified.grant.operator, credentialId: verified.grant.credentialId },
    convertTunnel: verified.grant.convertTunnel,
    armKeyAtApproval,
  }), armKeyAtApproval.fleet_arm_pubkey);
  if (!outcome.ok) {
    return { status: 409, body: { error: outcome.error, detail: outcome.detail } };
  }
  // 202, not 200: what happens next needs the node, and the node is waiting
  // for an operator to compare a fingerprint at the other keyboard. The row
  // carries the stage and the page polls the body it already polls, rather
  // than holding a request open on a second human.
  return {
    status: 202,
    body: {
      ok: true, pairing_id: id, label: verified.grant.label,
      // #635: the page's own click verdict is deliberately neutral now
      // ("Passkey accepted") -- the row's own note is where "Approved" is
      // said, once, so this detail matches rather than restating it.
      detail: 'Passkey accepted. The node is being asked to accept this aggregator&rsquo;s key.',
    },
  };
}

/**
 * The settlement: mint a credential, ask the root broker to register the
 * node, and hand the answer back to the hub to send down the pinned socket.
 *
 * The credential is minted HERE and only its SHA-256 crosses to the broker.
 * The plaintext goes down the pairing socket, which the aggregator has just
 * proved it owns by signature, and is never written on this side.
 */
async function settlePairing(input: {
  deps: SettingsAdminDeps;
  session: AuthSessionInfo;
  label: string;
  row: PairingRow;
  tokens: { read_token: string; advisor_token: string | null };
  grant: BrokerPushGrant;
  /** #620: true only for a known-node move, and only ever set from the
   *  row's own classification, never from anything the browser sent. */
  convertTunnel: boolean;
  /** #741: what `arm-key` said before the welcome. Where the key was made
   *  (and a lost one remade) is now there, not in the approve. */
  armKeyAtApproval: { fleet_arm_pubkey: string; fleet_arm_key: string | null; fleet_arm_key_orphaned: string[] };
}): Promise<PairSettlement> {
  const { deps, session, label, row, tokens, grant, convertTunnel, armKeyAtApproval } = input;
  const credential = deps.mintCredential?.() ?? '';
  if (!credential) {
    return { ok: false, error: 'no_credential', detail: 'this dashboard could not mint a link credential.' };
  }
  // The hello said an Advisor is here, and the tokens that followed carry none
  // for it (#1108 review, L1). Sent on, the broker would read that as a node
  // with no Advisor and clear the attachment the operator, looking at a row
  // that says "present", thought they were keeping. Refused here, before any
  // write, naming the cause; the node runs its pair command again.
  if (row.advisor && tokens.advisor_token === null) {
    const detail = 'the node said it has an Advisor but sent no token for it, so nothing was written. '
      + 'Run the pair command on it again; if it keeps saying so, check that its Advisor token is readable there.';
    recordAuthEvent({
      actor: session.username, actorRole: session.role, event: 'fleet_pairing', target: label,
      detail: { act: 'register_failed', pubkey_node: row.pubkey_node, error: 'advisor_token_missing', detail },
    });
    return { ok: false, error: 'advisor_token_missing', detail };
  }
  const payload = brokerApprovePayload({
    label,
    pubkey_node: row.pubkey_node,
    dashboard_url: row.dashboard_url,
    role: 'node',
    advisor: row.advisor && tokens.advisor_token !== null,
    credential_sha256: createHash('sha256').update(credential, 'utf8').digest('hex'),
    read_token: tokens.read_token,
    advisor_token: row.advisor ? tokens.advisor_token : null,
    ...(convertTunnel ? { convert_tunnel: true as const } : {}),
    // #741 review, L2: held to the key on disk by root before any write.
    fleet_arm_pubkey: armKeyAtApproval.fleet_arm_pubkey,
  });
  let answer: { code: number; stdout: string; stderr: string; reported?: boolean; timedOut?: boolean };
  try {
    answer = await (deps.broker as NonNullable<SettingsAdminDeps['broker']>)(payload);
  } catch (err) {
    return {
      ok: false, error: 'no_broker',
      detail: `this host's fleet broker could not be reached: ${(err as Error).message}`,
    };
  }
  // The socket layer (askSocketProgram -> splitSealerStream) already read
  // the exit code off the stream and consumed its line; passing answer.code
  // through means this second parse does not look for an exit= that is no
  // longer there and read its absence as "the broker said nothing" (#311).
  const parsed = brokerAnswerOf(answer);
  const outcome = brokerOutcome(parsed);
  recordAuthEvent({
    actor: session.username, actorRole: session.role, event: 'fleet_pairing',
    target: label,
    detail: outcome.ok
      ? {
        act: 'registered', pubkey_node: row.pubkey_node,
        read_port: outcome.read_port, advisor_port: outcome.advisor_port,
        rejoined: outcome.rejoined, reloaded: outcome.reloaded,
        // #1079: the Advisor attachment this rejoin cleared, because the node
        // said it has none. The one row that says a link row lost its Advisor.
        ...(outcome.advisor_lowered ? { advisor_lowered: true } : {}),
        ...(outcome.converted_from ? { converted_from: outcome.converted_from } : {}),
        // #1057: the aggregator's own fleet.yaml row, written or not. When it
        // is `missing` the sentence rides beside it, so an operator reading
        // this row alone can tell a held node from a linked one.
        ...(outcome.self_row ? { self_row: outcome.self_row } : {}),
        ...(outcome.self_row_note ? { self_row_note: outcome.self_row_note } : {}),
        // #723: whether the node was handed an arm key, and if not, why. The
        // one place on this host that says a pairing settled without one.
        fleet_arm_key: outcome.fleet_arm_key ?? (outcome.fleet_arm_pubkey ? 'present' : 'none'),
        ...(outcome.fleet_arm_key_orphaned.length
          ? { arm_key_lost_for: outcome.fleet_arm_key_orphaned.join(', ') } : {}),
      }
      : { act: 'register_failed', pubkey_node: row.pubkey_node, error: outcome.error, detail: outcome.detail },
  });
  if (!outcome.ok) return { ok: false, error: outcome.error, detail: outcome.detail };
  // The row is written and the node is about to be told. What happens next
  // (the link coming up, the passkey list reaching it) is this aggregator's
  // own observation and takes up to a minute and a half, so it runs behind
  // the answer and reports on the row.
  deps.pairFollowOn?.({
    pairingId: row.id, label, advisor: row.advisor, grant,
    armKeyNote: armKeyRemintNote(outcome.fleet_arm_key, outcome.fleet_arm_key_orphaned)
      ?? armKeyRemintNote(armKeyAtApproval.fleet_arm_key, armKeyAtApproval.fleet_arm_key_orphaned),
  });
  return {
    ok: true,
    label,
    credential,
    fleet_arm_pubkey: outcome.fleet_arm_pubkey,
    read_port: outcome.read_port,
    advisor_port: outcome.advisor_port,
    ...(outcome.self_row_note ? { self_row_note: outcome.self_row_note } : {}),
    ...(outcome.advisor_note ? { advisor_note: outcome.advisor_note } : {}),
  };
}

/**
 * Push the admin passkeys to one node, some, or all.
 *
 * No passkey. The enrollment hook (lib/trust-push-hook.ts) already pushes
 * after every credential change without one, and this is the same act asked
 * for by hand: it sends PUBLIC keys the node is already meant to hold. What
 * it is not is a substitute for that hook, which is why it is a button an
 * operator reaches for when a node was down at push time.
 *
 * Sequential, one node at a time. The CLI signs the same bundle for each,
 * and the operator wants to read which node took it in the order they picked.
 */
async function handleTrustPush(
  req: IncomingMessage, res: ServerResponse, deps: SettingsAdminDeps,
): Promise<void> {
  let raw: string;
  try { raw = await readBody(req); } catch { send(res, 400, { error: 'could not read the request' }); return; }
  let parsed: { targets?: unknown };
  try { parsed = JSON.parse(raw || '{}') as typeof parsed; } catch {
    send(res, 400, { error: 'could not read the request' });
    return;
  }
  const requested = Array.isArray(parsed?.targets) ? parsed.targets.map(String) : [];
  if (requested.length === 0) { send(res, 400, { error: 'pick at least one node to push to' }); return; }
  if (requested.length > MAX_TARGETS) { send(res, 400, { error: `that is more than ${MAX_TARGETS} nodes` }); return; }

  const known = new Set(deps.peers().map((p) => p.label));
  const results: PushRow[] = [];
  // "all" is the CLI's own unscoped push, which reaches every node in
  // fleet.yaml in one run: one signature, one pass, and the CLI's own honest
  // per-node lines. Never a loop over labels, which would sign N times and
  // could report a fleet as pushed when the registry had changed under it.
  const labels = requested.includes('all') ? [null] : requested;
  for (const entry of labels) {
    if (entry !== null && (!LABEL_RE.test(entry) || !known.has(entry))) {
      results.push({ label: entry, ok: false, detail: 'this dashboard has no node with that label' });
      continue;
    }
    try {
      results.push(...trustPushRows(entry, await deps.pushTrust(entry), known));
    } catch (err) {
      results.push({
        label: entry ?? 'all', ok: false, reason: 'not_started',
        detail: `the push could not be started (${(err as Error).name})`,
      });
    }
  }
  // What this aggregator's own link to each failed node said when it was
  // asked, just now (#1184). Read here, at the moment of the failure, from
  // the hub and never from the overview the page polled earlier.
  annotatePushFailures(results, new Map(deps.peers().map((p) => [p.label, p])), deps.linkStatus);
  // A push changes what every node reports about its trust set.
  clearSettingsOverviewCache();
  send(res, 200, { results });
}

