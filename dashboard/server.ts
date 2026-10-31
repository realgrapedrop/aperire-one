import { createServer } from 'node:http';
import { readFile, readdir, statfs, writeFile } from 'node:fs/promises';
import { accessSync, constants as fsConstants, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { cpus, hostname as osHostname, arch as osArch, release as osRelease, type as osType, homedir as osHomedir, userInfo as osUserInfo } from 'node:os';
import { promises as dns } from 'node:dns';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { WebSocket, WebSocketServer } from 'ws';
import yaml from 'js-yaml';

const execFileAsync = promisify(execFile);
// @ts-expect-error, geoip-lite has its own type shape; we only need lookup()
import geoip from 'geoip-lite';
import { pendingCount, buildAmendmentBallotRows, buildAmendmentVoteSummary, nextActivationFromRows, nextUnsupportedMajority, unsupportedMajorityDaysMetric, type AmendmentFeatureEntry } from './lib/amendments.js';
import { refreshAmendmentsLibrary, parseAmendmentsLibraryDoc, pickAmendmentsLibrary, type AmendmentsLibraryFile } from './lib/xrpl-org-amendments.js';
import { digestValue } from './lib/digest-value.js';
import { releaseKeyWire, readReleaseSigners, RELEASE_SIGNERS_PATH } from './lib/release-key.js';
import { readReleaseHighWater } from './lib/release-floor.js';
import { sshKeygenVerifier } from './lib/release-signature.js';
import { buildPublisherSummary, type ValidatorListSiteEntry } from './lib/publishers.js';
import { AmendmentVoteCounter } from './lib/amendment-votes.js';
import {
  writeMetric, queryHistory, queryHistoryRange, queryRecent, writeLedger, queryRecentLedgers, queryLedgerWindow,
  writeAgreement, queryAgreementSince, RIPPLE_EPOCH_S,
  writeMissedLedger, queryMissedLedgers,
  witnessLedger, queryLedgerAlarms, highestWitnessed,
  addMonthlyBandwidthDelta, getMonthlyBandwidth, getLastSnapshot, setLastSnapshot,
  queryBandwidthMonths,
  type MetricName,
  peakMetricSince, loadStoreSeries, saveStoreSeries,
  addMetricObserver, writeAlertEvent, queryAlertHistory, updateAlertDelivery,
  upsertFiringState, clearFiringState, queryFiringState, type FiringStateRow,
  queryDigestRuns, writeDigestRun,
  recordAdvisorAnswered, lastAdvisorAnsweredMs,
  bucketForRange,
  recordAuthEvent,
  LOCAL_NODE, DB_DIR,
  mirrorSummary, mirrorSearch,
  memoryMirrorFleet, inboxMirrorSummary, notesMirrorStateAll,
  type HistoryPoint,
  type MemoryMirrorEntryIn, type InboxMirrorNoteIn,
} from './db.js';
import {
  AdvisorLedgerMirror, reverifyMirrorNode,
  type MirrorTarget, type FetchLedger, type MirrorLedgerEntry,
} from './lib/advisor-ledger-mirror.js';
import {
  AdvisorNotesMirror,
  type NotesMirrorTarget, type FetchMemory, type FetchInbox,
} from './lib/advisor-notes-mirror.js';
import { buildDigestText, formatDigestTs, type DigestSummary } from './lib/mail-text.js';
import { sendAlertEmail, sendDigestEmail, buildSubject, type EmailChannelConfig, type AlertEmailContext } from './email.js';
import {
  parseRuleActionField, RULE_ACTION_MAX, RULE_ACTION_COMMAND_MAX,
  type RuleActionWarning,
} from './lib/rule-action.js';
import {
  mergeRuleFiles, describeRulesLoad, LOCAL_RULES_FILENAME,
} from './lib/rules-merge.js';
import { sendAlertNtfy, type NtfyChannelConfig } from './ntfy.js';
import { sendAlertWebhook, type WebhookChannelConfig, type WebhookFormat } from './webhook.js';
import { randomBytes } from 'node:crypto';
import { SEALER_SOCKET, sealModelKey, type SealRunner } from './lib/model-seal.js';
import {
  runUpdateVerb, checkPayload, applyPayload, restartPayload, rollbackPayload,
  updateFieldRefusal, unitListRefusal, needsRestart, brokerGrantReading, decideLocalApply, updaterAnswered, UPDATE_SOCKET,
  type UpdateAsk, type UpdateSnapshot, type UpdateVerdict,
} from './lib/update-apply.js';
import { armState, ARM_MARKER, ARM_WINDOW_SEC } from './lib/model-arm.js';
import { askSocketProgram } from './lib/socket-program.js';
import { beginUpdateCeremony, verifyUpdateCeremony } from './auth.js';
import { handleAdvisorModelTest, handleAdvisorModelSealBegin, handleAdvisorModelSealFinish,
  handleAuthRequest, requireAuthGate, readSession, expectedOrigins, originExplicitlyConfigured,
  dashboardIdentity,
         handleAdvisorApproveBegin, handleAdvisorApproveFinish, handleAdvisorApproveCancel, isAdmin,
         handleAdvisorInvestigateBegin, handleAdvisorInvestigateFinish,
         trustFingerprint, csrfOk, setInstanceLabel, getUserById } from './auth.js';
import { isSafePublicDomain, nextTomlHop, TOML_MAX_REDIRECTS } from './lib/url-policy.js';
import { readBody } from './lib/read-body.js';
import { internalErrorResponse } from './lib/error-response.js';
import { applySecurityHeaders } from './lib/security-headers.js';
import { decideIngest, plaintextOverrideEnabled, startupIngestWarning, isLoopbackHost, relayTokenAccepted, PLAINTEXT_OVERRIDE_ENV } from './lib/ingest-policy.js';
import { isReadPath, gateRead } from './lib/read-api.js';
import {
  isFleetWritePath, gateFleetWrite, fleetWriteWork, checkSealJob, checkArmToken,
  checkUpdateJob, fileNonceStore, armPayload, armOutcome, readFleetWriteBody,
  checkAdvisorRevealJob, decideAdvisorReveal, buildAdvisorStateResponse,
  readAdvisorRevealWindowFacts, type AdvisorRevealWindowFacts,
} from './lib/fleet-write-api.js';
import { nodeStatusForRole } from './lib/peer-install-facts.js';
import { buildNodeStatusFields, buildPeersFields, buildValidationSummaryFields, buildConsensusSnapshotFields, buildAmendmentBallotFields, buildGovernanceFields, buildSystemFields, buildNetStatsFields, buildValidationsTickFields, buildFleetRosterFields, buildNodeConfigFields, type LastCloseSummary } from './lib/read-payloads.js';
import { parseRippledCfg } from './lib/rippled-cfg.js';
import { advisorForwardQuery, advisorRunbookError } from './lib/advisor-proxy-query.js';
import { handleKnowledgeAdmin } from './knowledge-admin.js';
import { handleSettingsAdmin, clearSettingsOverviewCache, pairCommandLine } from './settings-api.js';
import { FleetSealJobs, type FleetModelDescriptor } from './lib/fleet-seal.js';
import {
  FleetUpdateJobs, fetchPeerUpdateState, readFleetCompleteness,
  sanitizeComponents, componentDrift, describeComponentDrift,
  type NodeCompleteness,
} from './lib/fleet-update.js';
import { readFleetModelRecord, writeFleetModelRecord } from './lib/fleet-model-record.js';
import { READ_PROTOCOL_VERSION } from './types/read-contract.js';
import { ReadStreamRegistry, formatSseEvent, type StreamSink } from './lib/read-stream.js';
import { loadFleetRegistry, type FleetNodeConfig } from './lib/fleet-registry.js';
import { pushFailedLine } from './lib/trust-push-rows.js';
import {
  createFleetLinkHub, planLinkReload, createIssuedTombstoneFileStore, FLEET_LINK_ISSUED_TOMBSTONES_BASENAME,
  pruneIssuedTombstones,
  type FleetLinkHub, type LinkRegistryRow, type WithheldLinkRow, type LinkRegistryFile,
} from './lib/fleet-link-hub.js';
import {
  createFleetLinkAgent, createRefusalLedger, loadLinkConfig, linkFactLine,
  reconcileLinkAgent, createTombstoneFileStore,
  type FleetLinkAgent, type LinkSocket, type LinkConfig, type LinkAgentSlot,
} from './lib/fleet-link-agent.js';
import {
  FLEET_LINK_PATH, FLEET_LINK_CONFIG_BASENAME, FLEET_LINK_REGISTRY_BASENAME, FLEET_LINK_TOMBSTONE_BASENAME,
  FLEET_LINK_HELLO_TIMEOUT_MS, FLEET_LINK_MAX_FRAME_BYTES, FLEET_PAIR_MAX_FRAME_BYTES,
} from './types/fleet-link-contract.js';
import { buildNodeIdentity, resolveNodeHostname, resolveNodeLabel, resolveNodeName, safeRead } from './lib/alert-identity.js';
import { logoutCancelTargets } from './lib/logout-targets.js';
import { createHistoryCache } from './lib/history-cache.js';
import { readVerifyReport, verifyReportMissing } from './lib/verify-report.js';
import {
  observeAdvisorPresence, buildAdvisorPresenceResponse, DEFAULT_FORGET_AFTER_MS, advisorUnitPath, createPresenceReader,
  type AdvisorPresenceResult,
} from './lib/advisor-presence.js';
import { FleetHealthPoller, resolveFleet, buildSelfPeer, selfPinFacts, sortFleetForDisplay, deriveSelfStateVerdict, deriveHealthVerdict, deriveAlertsVerdict, rollupVerdict, isAggregatorSelf, gradeFleetDeploy, gradeFleetRelease, STALE_AFTER_MS, type FleetPeerPublic } from './lib/fleet-health.js';
import { createDeployRefReader, type DeployComparison } from './lib/deploy-ref.js';
import { createReleaseIdentityReader, identityForWire, describeIdentity } from './lib/release-stamp.js';
import {
  checkForUpdate, updateChecksEnabled, updateEndpoint, updateAvailableMetric,
  readUpdaterCheck, gradeFromUpdater, updaterEndpointDisagreement, pageReadingOlderThanUpdater,
  type UpdateCheckResult, type UpdaterReading, type UpdateLatest, fleetGradingReading,
  carryNotes, serializeStoredCheck, parseStoredCheck,
} from './lib/update-check.js';
import { buildConcernsResponse, reconcileFirstSeen } from './lib/concerns.js';
import { FleetFetchThrough, parseNodeOverviewLabel, resolvePeerByLabel } from './lib/fleet-fetch-through.js';
import { readTokenFresh } from './lib/fleet-health.js';
import { PeerReadProxy, PeerPinCache, parseNodeReadPath, isAllowedRoute, forwardableParams, parseNodeStreamLabel, parseStreamChannels } from './lib/peer-read-proxy.js';
import { openPeerStream, relayPeerStream } from './lib/peer-stream-proxy.js';
import { parseNodeAdvisorPath, fetchPeerAdvisor, fetchPeerAdvisorAsk, fetchPeerAdvisorAskProgress, attachActor, readPeerAdvisorToken, type PeerAdvisorResult } from './lib/peer-advisor-proxy.js';
import { peerAdvisorFailureAnswer, peerFailureStatus, peerReadFailureAnswer, edgeSafeRelay, type Viewer } from './lib/peer-advisor-answer.js';
import { notesMirrorAnswer, type RegistryLabels } from './lib/notes-mirror-answer.js';

/** The peer advisor reads that stay admin-only on this dashboard: a queue of
 *  model-authored notes (proposals, ADR 0017 decision 4) and, since ADR
 *  0021 build step 5, the mirror feed's own reads (memory, a node's full
 *  inbox including decided notes), the same reasoning both times. Every
 *  other entry in PEER_ADVISOR_READ_PATHS a monitor session may watch. */
const ADMIN_ONLY_ADVISOR_READS: ReadonlySet<string> = new Set(['proposals', 'memory', 'inbox']);
import { annotateTrustSync } from './lib/trust-sync.js';
import { readPeerPubKey, readOwnPrivateKey, readOwnPublicKey, signWithSeed } from './lib/trust-bundle.js';
import { consumePairingCode, pairingArmed } from './lib/pairing-codes.js';
import {
  FLEET_BROKER_SOCKET, FLEET_BROKER_TIMEOUT_MS, FLEET_BROKER_PUSH_TIMEOUT_MS, FLEET_ARM_PROGRAM, FLEET_BROKER_PROGRAM, rootProgramInstalled, grantStepCommand,
  PAIR_FOLLOWON_POLL_MS, PAIR_FOLLOWON_MAX_MS, pairFollowOnNote,
  brokerModelStorePutPayload, brokerModelStoreHeadPayload, brokerModelPushPayload,
  brokerStoreOutcome, brokerStoreHeadOutcome, brokerPushOutcome, serializeBrokerCalls,
  brokerAnswerOf, BROKER_BUSY_DETAIL, askWithCeiling, inheritFleetModel,
  type BrokerAnswer, type BrokerStoreHeadOutcome, type BrokerPushOutcome,
  type BrokerPushGrant, type StoreWriteNote, type InheritOutcome,
} from './lib/fleet-broker.js';
import {
  FLEET_WRITE_ISSUER_LABEL, UPDATE_STATE_TAIL_LINES,
  type UpdateStateResponse, type UpdateStateLastRun,
  type UpdateApplyJob, type UpdateRestartJob,
} from './types/fleet-write-contract.js';
import { asksInFlight, trackAsk } from './lib/ask-gauge.js';
import { healthzVerdict, installRoleFromEnv, isDashboardHost } from './lib/healthz-verdict.js';
import { peerShedVerdict, baseline } from './lib/peer-shed.js';
import { isAgreementWindowReconciled, observedWindowStartMs, type AgreementReconcileInput } from './lib/agreement-reconcile.js';
import { BINARY_NAMES, resolveAllCounters, findMissingRequired, createMissWarner } from './lib/fork-aliases.js';
import type { RelayPush } from './types/relay-contract.js';
import { hostMetricsSource, type LastRelaySystem } from './lib/host-metrics-source.js';
import { type NudbGrowth } from './lib/nudb-growth.js';
import { SeriesStart } from './lib/store-series.js';
import {
  parseAdvisorCheckInstallable, peerReleasePostureBody, type ReleaseFact,
} from './lib/release-posture.js';
import {
  PACKAGES_INDEX_URL, PACKAGES_INDEX_MAX_BYTES,
  parseDebPackagesIndex, reconcileReleaseFeed, nextFeedCache, releaseInfoFromFeed,
  readCappedText, selfReleasePayload, upstreamFactFromInfo, OFFICIAL_IMAGE_REPO,
  type FeedCache, type ReleaseInfo, type SelfReleasePayload,
} from './lib/release-feed.js';
import { compareVersions as cmpVersion, readVersion } from './lib/version-compare.js';
import {
  measureStore, storeMeasured, deriveFromStore, parseAdvisorStore, storeForThePage,
  storeToDeriveFrom, makeAdvisorSampleRecorder, storePathsMatch,
  type StoreReading, type AdvisorStoreReading, type StoreSeries,
} from './lib/store-size.js';
import {
  nodeStoreSample, nodeStoreRatesBetween, NODESTORE_MIN_INTERVAL_S,
  type NodeStoreSample, type NodeStoreRates,
} from './lib/nodestore-rates.js';
import { exitWithParent } from './lib/exit-with-parent.js';

// A scratch dashboard that a test or a walk started goes when that process
// does (#1084). Off unless APERIRE_EXIT_WITH_PARENT is set, which nothing an
// operator installs ever sets.
exitWithParent();

// A monitoring dashboard must not die because one socket did. Undici throws
// "TypeError: terminated" from its own internals when a proxied upstream
// (the advisor's SSE stream, mid-read) closes at the wrong moment, a race
// that no request-level try/catch can reach, and one that killed this
// process six times in a single day. Every crash severed every operator's
// session at once; one of them cut an operator off in the middle of a
// supervised upgrade. Log it, name it, keep serving. systemd's
// Restart=always remains the backstop for anything that still exits.
process.on('unhandledRejection', (reason) => {
  const r = reason instanceof Error ? reason.stack ?? reason.message : String(reason);
  console.warn(`[unhandled rejection] ${r}`);
});
process.on('uncaughtException', (err) => {
  // Log, then leave. This handler exists because an undici socket race was
  // killing the process six times a day and taking every operator's session
  // with it, but "keep running" was the wrong half of that fix. After an
  // uncaught exception Node's own documentation says the process state is
  // undefined: a request may never be ended, a better-sqlite3 transaction may
  // be left open, and the result is a quietly degraded server still serving an
  // authenticated dashboard. A crash is honest and systemd restarts it in
  // three seconds; a zombie that answers wrongly is neither.
  //
  // The exit is deferred a moment so the log line reaches disk and in-flight
  // responses have a chance to finish, and forced if that grace is not enough.
  console.error(`[uncaught exception] ${err.stack ?? err.message}`);
  console.error('[uncaught exception] exiting; systemd will restart this process');
  try {
    httpServer.close();
    // The fleet link holds one loopback listener per node and one outbound
    // socket, none of which httpServer knows about.
    void fleetLinkHub?.close();
    fleetLinkSlot.agent?.stop();
  } catch { /* the server may not be listening yet */ }
  setTimeout(() => process.exit(1), 500).unref();
  // If something is holding the loop open, do not wait forever to die.
  setTimeout(() => process.abort(), 5_000).unref();
});

const PORT = Number(process.env.PORT ?? 7800);
// The Advisor's read-only service. Loopback by construction, it refuses to
// bind anything else, so this is not a value that can point somewhere
// interesting by accident.
const ADVISOR_URL = process.env.ADVISOR_URL ?? 'http://127.0.0.1:7810';
// Shared secret proving the caller is a service that can read a file at 0600.
// Read per call, not cached, so rotating it does not need a dashboard restart.
// Absent means web approval is disabled, which is the right default for a
// host where nobody has deliberately turned it on.
const ADVISOR_TOKEN_PATH = process.env.ADVISOR_TOKEN_PATH
  ?? resolve(import.meta.dirname, '..', 'advisor', 'state', 'approve.token');
function advisorApproveToken(): string | null {
  try {
    const t = readFileSync(ADVISOR_TOKEN_PATH, 'utf8').trim();
    return t.length >= 32 ? t : null;
  } catch { return null; }
}
// The read-surface token, ADR 0008. A second secret, deliberately not
// approve.token: one token in both directions would mean compromising either
// service yields both, and the two directions have very different blast
// radii. advisord generates it beside approve.token with the same ownership
// (0640, the shared service group), and this side reads it per request so
// rotation needs no restart. Absent or short means the read surface is
// disabled, never open.
const READ_TOKEN_PATH = process.env.APERIRE_READ_TOKEN_PATH
  ?? resolve(import.meta.dirname, '..', 'advisor', 'state', 'read.token');
function readSurfaceToken(): string | null {
  try {
    const t = readFileSync(READ_TOKEN_PATH, 'utf8').trim();
    return t.length >= 32 ? t : null;
  } catch { return null; }
}
// Loopback-only by default, defense-in-depth behind the Cloudflare tunnel.
// Binding off-loopback exposes /ingest to the LAN, which is a posture the
// startup line and the ingest gate below both have something to say about.
// Prefer a tunnel that keeps a remote relay's hop on loopback at both ends.
const HOST = process.env.HOST ?? '127.0.0.1';
// MED-07. A relay on another machine dialling a LAN-bound dashboard sends its
// bearer token and telemetry in the clear. Refused by default; see
// lib/ingest-policy.ts for the rule and the two sanctioned ways around it.
// Read once at startup, not per connection: this is a deployment posture, and
// a value that could change under a running process would make the startup
// line a lie.
const INGEST_ALLOW_PLAINTEXT = plaintextOverrideEnabled(process.env[PLAINTEXT_OVERRIDE_ENV]);
const RIPPLED_URL = process.env.RIPPLED_URL ?? 'ws://127.0.0.1:6006';
// What the installer was told this host is (#808). A dashboard-role host has
// no node of its own: it must not open the rippled bridge, and /healthz must
// not wait for one. A RIPPLED_URL set by hand is the operator pointing this
// dashboard at a node on purpose, so that wins and the host reads as a node.
const DASHBOARD_HOST = isDashboardHost(
  installRoleFromEnv(process.env.APERIRE_INSTALL_ROLE),
  !!process.env.RIPPLED_URL,
);
const DATA_MOUNT = process.env.DATA_MOUNT ?? '/';
// Root of rippled's data directory. Used for NuDB size + growth reporting
// on the System tab. Empty (default) means "don't report NuDB metrics."
// When the Go relay takes full ownership of validator-host reads, this
// key migrates into relay.conf as `rippled_data_path`, no rename, just
// a venue shift.
const RIPPLED_DATA_PATH = process.env.RIPPLED_DATA_PATH ?? '';
// Path to rippled.cfg on disk. Parsed at startup to surface the
// `[node_db] online_delete` config on the System tab. Empty = skip.
// Like RIPPLED_DATA_PATH, this migrates to the Go relay when Shape B
// deployments appear.
const RIPPLED_CFG_PATH = process.env.RIPPLED_CFG_PATH ?? '';
const PUBLIC_DIR = resolve(import.meta.dirname, 'public');
// Which database this process opened, resolved the way db.ts resolves it.
// The trust-push CLI is told it explicitly: a host running two installs must
// not push the admin set of the other one.
const DB_PATH = process.env.APERIRE_DB_PATH
  ? resolve(process.env.APERIRE_DB_PATH)
  : resolve(import.meta.dirname, '..', 'data', 'aperire.db');

// This install's deploy stamp is the commit the fleet update last rsynced
// onto this host, written to `.deploy-ref` at the install root (issue #128
// rung 2). One directory up from the dashboard, which is where every
// install puts it, and absent on a box that was never deployed to by the
// fleet tool. That is the ordinary single-node case, not a fault, so it is
// not logged.
//
// Re-read rather than cached for the life of the process: a frontend-only
// sync rewrites this file and restarts nothing, so a value read once at
// boot would go stale without a single event to notice it by.
const deployRefReader = createDeployRefReader({
  path: resolve(import.meta.dirname, '..', '.deploy-ref'),
  readFile: (p) => readFileSync(p, 'utf8'),
  onError: (msg) => console.warn(`[deploy] ${msg}`),
});

// What release this install IS (ADR 0022 decision 1). `.release` at the same
// install root, written by the bootstrap; `.deploy-ref` when only that
// exists; unknown when neither does, which is every host installed before
// 2026-09-08 and is said out loud rather than guessed.
//
// Re-read on a TTL for one more reason than the deploy stamp has: an apply
// deliberately restarts nothing, so between the tree swap and the operator
// pressing restart the stamp on disk names the new release while this
// process is still the old one.
// The install root, which is one directory up on every install. Overridable
// only so a test rig can stand up a host whose stamp is not this checkout's:
// the walk needs a `.release` it can write, and writing one into the working
// tree would make every developer's `git status` dirty and every CI run a
// host that claims a release it is not. Unset in production, where this
// resolves exactly as the deploy-ref reader above does.
const INSTALL_ROOT = process.env.APERIRE_INSTALL_ROOT
  ? resolve(process.env.APERIRE_INSTALL_ROOT)
  : resolve(import.meta.dirname, '..');
const releaseReader = createReleaseIdentityReader({
  releasePath: resolve(INSTALL_ROOT, '.release'),
  deployRefPath: resolve(INSTALL_ROOT, '.deploy-ref'),
  readFile: (p) => readFileSync(p, 'utf8'),
  onError: (msg) => console.warn(`[release] ${msg}`),
});

// Insights tab config directory. Production defaults to /etc/aperire so
// systemd EnvironmentFile + the *.yaml files all live in one tree owned
// root:aperire 0640. For dev, we ship a sample tree under mockup/config
// that the operator can copy into /etc/aperire on first deploy.
const INSIGHTS_CONFIG_DIR = process.env.APERIRE_CONFIG_DIR
  ?? resolve(import.meta.dirname, 'config');

// Static shared-secret allow-list for inbound relay connections on /ingest.
// Comma-separated in RELAY_TOKENS. Empty set = ingest effectively disabled
// (no relay will authenticate). Generate per-validator with e.g.
//   openssl rand -hex 32
// and set the same token in the relay's relay.conf `auth_token`.
const RELAY_TOKENS = new Set<string>(
  (process.env.RELAY_TOKENS ?? '').split(',').map(s => s.trim()).filter(Boolean)
);

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.gif': 'image/gif',
};

// MED-09, sanitizeHttpUrl (http(s)-only, factored into lib/ for unit testing)
// guards xls_url before it reaches the governance popover.

// ────────────────────────────────────────────────────────────────────────
// State cache + broadcast fanout
// ────────────────────────────────────────────────────────────────────────

type AnyObj = Record<string, unknown>;

interface PeerRow {
  address?: string;
  inbound?: boolean;
  latency?: number;
  version?: string;
  uptime?: number;
  country?: string;
  host?: string;                        // PTR hostname (cached, may be undefined)
  sanity?: string;
  public_key?: string;
  complete_ledgers?: string;
}

interface Snapshot {
  server_info?: AnyObj;
  // Latest published release and whether the running build is behind it.
  release_info?: ReleaseInfo;
  peers?: PeerRow[];
  _peerKey?: string;
  fee?: AnyObj;
  validator_list_sites?: AnyObj[];
  feature?: AnyObj;
  // Hash → { name, xls } enrichment from xrpscan's public amendments API.
  // Used to (a) surface the XLS-NN tag next to each amendment name and
  // (b) name amendments this rippled build doesn't recognize (e.g. when
  // rippled returns just a hash because the feature isn't in this binary).
  xrpscan_amendments?: Record<string, { name?: string; xls?: string }>;
  // Hash → { description, xls_url } scraped from xrpl.org's known-amendments
  // page. Persisted to data/amendments.yaml so descriptions survive
  // restart and can be hand-edited if the upstream copy is wrong.
  amendment_descriptions?: Record<string, { description: string; xls_url?: string }>;
  validators?: AnyObj[];
  consensus_info?: AnyObj;
  trusted_unl?: Set<string>;          // master_key set, derived from `validators`
  last_ledger?: AnyObj;
  our_pubkey_validator?: string;
  // The public registry's view of this validator, what other operators and
  // explorers see. Null until the first poll answers.
  registry_view?: {
    last_seen: string;
    ledger_index: number | null;
    unl: string[];
    registry_version: string | null;
  };
  get_counts?: AnyObj;                // cached rippled get_counts RPC response
  get_counts_canonical?: Record<string, number | null>; // fork-namespace-resolved counters  // Own validator's manifest domain + toml-verification result. Populated by
  // pollOwnDomain (manifest admin command → .well-known/xrp-ledger.toml).
  // Replayed in the browser snapshot so a reload keeps the ✓.
  domain_status?: { domain: string | null; verified: boolean };
  // #654: the unsupported-and-at-majority amendment closest to activating,
  // or null when none is. Recomputed on every pollFeature() poll from the
  // same `feature` response the amendment cards read; see
  // lib/amendments.ts's nextUnsupportedMajority for the ranking rule.
  unsupported_majority?: import('./lib/amendments.js').UnsupportedMajorityAmendment | null;
}

const snapshot: Snapshot = {};
const browsers = new Set<WebSocket>();

function broadcast(type: string, data: unknown) {
  const payload = JSON.stringify({ type, data });
  for (const ws of browsers) {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(payload); } catch { /* ignore */ }
    }
  }
}

// ────────────────────────────────────────────────────────────────────────
// rippled bridge
// ────────────────────────────────────────────────────────────────────────

let rippled: WebSocket | null = null;
let rippledReqId = 0;
const pendingReqs = new Map<number, (res: AnyObj) => void>();

function rippledReq<T extends AnyObj = AnyObj>(command: string, params: AnyObj = {}): Promise<T> {
  return new Promise((resolvep, reject) => {
    if (!rippled || rippled.readyState !== WebSocket.OPEN) {
      reject(new Error('rippled not connected'));
      return;
    }
    const id = ++rippledReqId;
    pendingReqs.set(id, (r) => resolvep(r as T));
    rippled.send(JSON.stringify({ id, command, ...params }));
    setTimeout(() => {
      if (pendingReqs.has(id)) { pendingReqs.delete(id); reject(new Error(`rippled ${command} timeout`)); }
    }, 15_000);
  });
}

// Amendment support, counted from the trusted validations stream (#161).
// A tracking node's `feature` carries no vote tally, but its validations
// stream carries every trusted validator's vote on each voting ledger; the
// counter (lib/amendment-votes.ts) turns those into the figure the ballot
// shows under "counted". Nothing is published before the first voting
// ledger after start, up to ~15 minutes, and a round short of the quorum is
// logged and dropped rather than shown.
const amendmentVotes = new AmendmentVoteCounter();

// Validation counter, counts received validations for the currently-open ledger
let currentLedgerValidations = 0;

// ─── Historical metric write accumulators ─────────────────────────────
// Bridge writes downsampled metrics to SQLite every minute (load_factor avg,
// validation_rate count) and per-ledger metrics on each close (close_time,
// txn_count, converge_time). Charts on the Consensus tab read these back.

let lastLedgerCloseTs = 0;
let lastConvergeForLedger: number | null = null;
// The `consensus-snapshot` read route's own cache of the most recent close,
// closeDeltaS and txnCount together, updated at the exact same call site
// that computes them for broadcast('ledger:close', ...) below, so a peer's
// "Close"/"TX Last Ledger"/"TPS 1m" cards can never disagree with what this
// box's own ledgerClosed handler just decided about the same ledger.
let lastLedgerClose: LastCloseSummary | null = null;
let perMinLoadFactor: number[] = [];
let perMinValidationCount = 0;

// Consensus / load metrics are 1-minute aggregates by design, load_factor
// averages values seen in the minute, validation_rate counts them. Network
// metrics are instantaneous snapshots and need denser sampling so the Live
// history chart's 5-minute visible window has more than 5 data points.
// 10s cadence gives ~30 points in 5 minutes (enough that the "oldest point
// sliding off the right edge" artifact is imperceptible), with a tolerable
// 6x row-count bump in the metrics table.
setInterval(() => {
  if (perMinLoadFactor.length > 0) {
    const avg = perMinLoadFactor.reduce((a, b) => a + b, 0) / perMinLoadFactor.length;
    writeMetric('load_factor', avg);
    perMinLoadFactor = [];
  }
  writeMetric('validation_rate', perMinValidationCount);
  perMinValidationCount = 0;

  // Agreement % derived from the in-memory rolling 1h window
  const now = Date.now();
  let a1 = 0, m1 = 0;
  for (const r of agreementHistory) {
    if (now - r.ts <= ONE_HOUR_MS) { if (r.our_voted) a1++; else m1++; }
  }
  const total = a1 + m1;
  // Only a validator has agreement to report. These three feed five alert
  // rules and the Advisor's metric strip, and on a stock node they were
  // reporting 0% agreement with 100% of ledgers missed, turning a
  // perfectly healthy host into a permanent critical alert on three tabs.
  // A node that never proposes has nothing to agree with.
  // An unreconciled 1h window is not a reading. After the node restarts the
  // admin WS drops, the ledgers missed during the outage never enter
  // agreementHistory, and the pre-outage records, all "we voted", compute a
  // clean 100% with zero missed. Feeding that to the rule engine would let a
  // node that just came back resolve a firing miss-alert on evidence nobody
  // collected. So we write nothing at all for the window's two metrics and
  // wait for it to settle.
  //
  // Why skipping is safe, and what it costs:
  //   - The rule engine is write-driven end to end. addMetricObserver fans a
  //     write out to evaluateRulesForMetric, which returns immediately when no
  //     rule names the metric; no rule anywhere keys on the ABSENCE of a
  //     sample. The one staleness rule in config/rules.yaml is
  //     relay_feed_age_s, which is a different metric written by the relay
  //     path, so a gap here trips no stale-feed alarm.
  //   - The cost is that a firing missed_validations_1h alert cannot RESOLVE
  //     while the window is unreconciled, and a genuinely bad agreement raises
  //     no new alert during it either. That is bounded: conditions (a) and (c)
  //     in isAgreementWindowReconciled both clear within about an hour of the
  //     node coming back. Staying quiet about a window we did not measure is
  //     the deliberate trade, the alternative is an alert, or an
  //     all-clear, derived from records that were never taken.
  const reconciled1h = agreementWindowReconciled(now);
  if (isValidatorNode() && reconciled1h) {
    if (total > 0) {
      // agreement_pct has no rule behind it, it is the Advisor tab's cell and
      // the Consensus Live sparkline. Skipped on the same condition as the
      // rules' own metric, and consensus.html skips its pushLive of the same
      // name in the same case, so the series reads identically whichever path
      // filled it.
      writeMetric('agreement_pct', (a1 / total) * 100);
      // Alert-rule inputs (rules.yaml consensus rules key on these names).
      // agreement_pct_1h mirrors agreement_pct but is the name the rules and
      // knowledge library expect. Only meaningful when the window has data.
      writeMetric('agreement_pct_1h', (a1 / total) * 100);
    }
    // missed_validations_1h: written even at 0 so the rule state machine can
    // resolve a firing miss-alert once misses clear (a rule only advances or
    // resolves on a fresh write of its metric).
    writeMetric('missed_validations_1h', m1);
  }

  // NuDB size, walk the configured rippled data directory once per
  // minute. The walk takes tens of milliseconds for typical NuDB layouts
  // (10-100 files); cheap enough to piggyback on the 1m tick. Feeds
  // 24h-growth-rate + mount-free-days estimates.
  //
  // And, on a host where that walk cannot be taken, one question to this
  // host's own Advisor at the same cadence (#427). Never faster: this is the
  // rate that outbound call is bounded by.
  void sampleStore();

  // (System-tab history sampling moved to its own 10s interval below,
  // beside sampleNetworkMetrics, at 60s here, a Live chart seeded from
  // stored samples spanned its window with only ~5 points. The NuDB walk
  // and the agreement windows above deliberately stay per-minute.)
}, 60_000);

// 1Hz validations aggregate. Replaces the per-event `broadcast('validation')`
// fanout, at ~400 events/sec × N browsers that was the dashboard's
// dominant CPU cost (renderer JSON.parse + handler runs and GPU compositor
// per-mutation). Browsers consume `validations_tick` and update the quorum
// bar / rate display from the carried fields once per second.
// The read surface's open streams (ADR 0013). One registry per process: the
// read token is one token per node, so "concurrency cap per token" is this
// counter, never a map keyed by the secret itself. Bounds and their
// reasoning live in lib/read-stream.ts.
const readStreams = new ReadStreamRegistry();

// The FLAT contract shape, built from the live in-memory round counters on
// demand, the object /read/v1/validations-tick serves and the object the
// stream emits, from ONE builder (ADR 0013's trade-off: two transports for
// one surface, and they must not drift). Deliberately not the nested WS
// broadcast just below, which carries no quorum: sourcing quorum from a
// different route on a different cadence would reintroduce, inside this fix,
// the cross-cadence skew the stream exists to remove.
function currentValidationsTickFields() {
  const info = (snapshot.server_info ?? {}) as AnyObj;
  return buildValidationsTickFields({
    current_round: {
      ledger_index: currentRoundLedgerIdx,
      received: currentRoundValidations.size,
      unl_received: currentRoundUnlValidations.size,
      unl_size: snapshot.trusted_unl?.size ?? 0,
      our_validated: currentRoundOurValidated,
    },
    rate_per_min: validationTsLog.length,
    rate_per_sec: validationTsLog.length / 60,
    quorum_raw: info.validation_quorum,
  });
}

setInterval(() => {
  const now = Date.now();
  const cutoff60s = now - 60_000;
  while (validationTsLog.length && validationTsLog[0] < cutoff60s) validationTsLog.shift();
  broadcast('validations_tick', {
    ts: now,
    rate_per_min: validationTsLog.length,
    rate_per_sec: validationTsLog.length / 60,
    current_round: {
      ledger_index: currentRoundLedgerIdx,
      received: currentRoundValidations.size,
      unl_received: currentRoundUnlValidations.size,
      // UNL size from the trusted_unl set so the browser can render
      // the quorum bar's domain as the full UNL (not capped at quorum).
      // 0 if the trusted UNL hasn't populated yet (rare, briefly after
      // bridge restart). Browsers fall back to quorum-as-domain.
      unl_size: snapshot.trusted_unl?.size ?? 0,
      our_validated: currentRoundOurValidated,
    },
  });
  // The read surface's stream rides the SAME fanout (ADR 0013): one tick,
  // two transports, so a peer's bar cannot pulse on a different beat from
  // the node's own. sweep() runs here too rather than on a timer of its own
  //, the lifetime cap and the heartbeat are the whole of what a quiet
  // stream still needs, and this interval already exists.
  readStreams.emit('validations_tick', currentValidationsTickFields(), now);
  readStreams.sweep(now);
}, 1000);

function sampleSystemHistoryMetrics(): void {
  const s = lastSystemBroadcast as AnyObj | null;
  if (!s) return;
  const cpu = s.cpu as AnyObj | undefined;
  const mem = s.memory as AnyObj | undefined;
  const swap = s.swap as AnyObj | undefined;
  const pressure = s.pressure as AnyObj | undefined;
  const rippled = s.rippled as AnyObj | undefined;

  if (cpu) {
    if (typeof cpu.busy_pct === 'number')   writeMetric('cpu_busy_pct',   cpu.busy_pct);
    if (typeof cpu.iowait_pct === 'number') writeMetric('cpu_iowait_pct', cpu.iowait_pct);
  }
  if (mem && typeof mem.used_pct === 'number')    writeMetric('mem_used_pct',  mem.used_pct);
  if (mem && typeof mem.cache_pct === 'number')   writeMetric('mem_cache_pct', mem.cache_pct);
  if (swap && typeof swap.used_pct === 'number')  writeMetric('swap_used_pct', swap.used_pct);
  if (pressure) {
    if (typeof pressure.cpu === 'number')    writeMetric('pressure_cpu',    pressure.cpu);
    if (typeof pressure.memory === 'number') writeMetric('pressure_memory', pressure.memory);
    if (typeof pressure.io === 'number')     writeMetric('pressure_io',     pressure.io);
  }
  if (rippled && typeof rippled.cpu_pct === 'number') {
    writeMetric('rippled_cpu_pct', rippled.cpu_pct);
  }
  // rippled RSS as % of host memory, comparable scale to CPU% so the
  // rippled-health chart can overlay both on one Y axis.
  if (rippled && typeof rippled.rss_bytes === 'number'
      && mem && typeof mem.total_bytes === 'number' && mem.total_bytes > 0) {
    writeMetric('rippled_rss_pct', (rippled.rss_bytes / mem.total_bytes) * 100);
  }
}

setInterval(sampleNetworkMetrics, 10_000);
// System host metrics sample at the same 10s cadence as the network set,
// they used to piggyback the 1-minute tick, which left a Live chart seeded
// from stored samples with ~5 points across its window where the network
// charts got ~30. Same writeMetric store, same retention; ~8 extra rows
// per 10s is well inside what the network set already writes.
setInterval(sampleSystemHistoryMetrics, 10_000);

// ── The host verifier's result, as a metric ───────────────────────────────
//
// scripts/verify-after-restart.sh runs from aperire-verify.timer (30 minutes
// after that timer starts, which is 30 minutes after a boot and 30 minutes
// after an install, then daily) and leaves data/verify-report.json behind.
// This is the only thing that reads it, and all it does is turn the last run
// into two numbers a rule can watch:
//
//   verify_failed_checks   how many checks that run failed
//   verify_report_age_s    how long ago the run was, from its own stamp
//
// Both are written on every tick while a report parses, INCLUDING a stale one.
// That is deliberate and matches nudb_mount_free_days: a rule only advances or
// resolves on a fresh write, so a metric that stops being written leaves a
// firing alert firing forever with nothing able to clear it. The age is the
// freshness signal, exactly as relay_feed_age_s is for the relay feed.
//
// No report, an unreadable one, or one that does not parse writes neither of
// those two. Never a zero: `verify_failed_checks: 0` is a claim that a run
// happened and found nothing wrong, and a host where the verifier has never
// run must not be able to make it.
//
// It writes a third metric instead, which is what closes the hole the two
// above left (#143). Silence used to be the whole answer to "no report", so a
// host whose first run never happened was unverified with nothing saying so:
// no report, no metric, no age to grow. verify_report_missing is that fact
// measured. It is only written where it means something, which is a host that
// HAS the verifier installed: the timer unit on disk is the discriminator, and
// a box that never installed the verifier gets no reading rather than a
// permanent alarm about an installer it never ran.
//
//   verify_report_missing  1 the verifier is installed and has left no usable
//                            report, 0 a report was read this tick
const VERIFY_REPORT_PATH = process.env.APERIRE_VERIFY_REPORT
  ?? resolve(import.meta.dirname, '..', 'data', 'verify-report.json');
// Overridable for the same reason the report path is: so a test can put a
// host's shape in a temporary directory.
const VERIFY_TIMER_UNIT = process.env.APERIRE_VERIFY_TIMER_UNIT
  ?? '/etc/systemd/system/aperire-verify.timer';

/** Whether this host installs the verifier at all. A stat, not a systemctl
 *  call: the dashboard cannot run one under its sandbox, and the unit file is
 *  what install-aperire-service.sh puts there. */
function verifierInstalled(): boolean {
  try { return statSync(VERIFY_TIMER_UNIT).isFile(); } catch { return false; }
}

function sampleVerifyReport(): void {
  let text: string | null;
  try { text = readFileSync(VERIFY_REPORT_PATH, 'utf8'); } catch { text = null; }
  const reading = readVerifyReport(text, Date.now());
  const missing = verifyReportMissing(reading, verifierInstalled());
  if (missing !== null) writeMetric('verify_report_missing', missing);
  if (!reading) return;
  writeMetric('verify_failed_checks', reading.failedChecks);
  writeMetric('verify_report_age_s', reading.ageS);
}
// Once a minute. The file changes once a day; this cadence is about the alert
// engine, which measures a rule's duration from writes and needs enough of
// them to hold a threshold. No call at startup: the rule observer is wired
// further down this file, so a write from here before that point would be
// stored and never evaluated.
setInterval(sampleVerifyReport, 60_000);

// ── Witnessing the Advisor's audit ledger ─────────────────────────────
//
// The ledger is hash-chained, so an altered entry is visible from inside it.
// Two things are not: removing entries from the end (verification walks
// forward, so a truncated file verifies perfectly) and a wholesale rewrite by
// anyone who can write the file, since they can recompute every hash. "Chain
// intact" therefore means "this file is internally consistent" and no more.
//
// The missing half is an observer that remembers. The dashboard already reads
// the ledger's summary, so it records what it sees; a ledger shorter than one
// already witnessed, or a different head at a length already witnessed, is a
// contradiction the file cannot talk its way out of.
//
// Deliberately on a server-side timer rather than on browser polling: an
// operator's tab is open at exactly the times nobody is tampering.
async function witnessAdvisorLedger(): Promise<void> {
  const tok = advisorApproveToken();
  if (!tok) return;   // advisord not installed on this host
  try {
    const r = await fetch(`${ADVISOR_URL}/v1/ledger`, {
      headers: { authorization: `Bearer ${tok}` },
      signal: AbortSignal.timeout(20_000),
    });
    if (!r.ok) return;
    const b = await r.json() as { count?: number; head?: string; chain_intact?: boolean };
    if (b.chain_intact === false) {
      console.error('[witness] the Advisor reports its own chain is broken');
      return;
    }
    if (typeof b.count !== 'number' || !b.head) return;
    const v = witnessLedger(b.count, b.head);
    if (!v.ok) {
      console.error(`[witness] ACTION LEDGER ${v.kind?.toUpperCase()}: ${v.detail}`);
    }
  } catch {
    // advisord restarting or absent is ordinary; only contradictions are news.
  }
}
// Once shortly after startup, then hourly. Frequent enough that a rewrite has
// to survive a witness, cheap enough to be invisible.
setTimeout(() => { void witnessAdvisorLedger(); }, 20_000);
setInterval(() => { void witnessAdvisorLedger(); }, 60 * 60 * 1000);

// Where the current store's size series begins (#1251). A store replaced
// under the series (a different path at start, or a size that collapsed) starts
// it over: the peaks, the growth fit, the free-days estimate and the chart read
// from there, so nothing is fitted across two stores. Built before the first
// walk below so the first sample of a new path lands after the cut. Absent
// where no store is configured.
const storeSeries: SeriesStart | null = RIPPLED_DATA_PATH
  ? new SeriesStart(loadStoreSeries(), RIPPLED_DATA_PATH, Math.floor(Date.now() / 1000), {
      save: (m) => saveStoreSeries(m.path, m.cut_s),
      peakSince: (fromS) => peakMetricSince('nudb_size', fromS),
      log: (line) => console.warn(line),
    })
  : null;
/** The one place a store size is recorded into the series: the cut is decided
 *  against what is already on record, then the reading is written. */
function recordStoreSize(bytes: number, ts: number, alsoAdvisor: boolean): void {
  storeSeries?.observe(bytes, Math.floor(ts / 1000));
  writeMetric('nudb_size', bytes, ts);
  if (alsoAdvisor) writeMetric('nudb_size_advisor', bytes, ts);
}

async function sampleNudbSize(): Promise<void> {
  if (!RIPPLED_DATA_PATH) return;
  const reading = await measureStore(RIPPLED_DATA_PATH);
  // The last size is cleared on a failed read, not kept. A store measured
  // ten minutes ago and unreadable now is not the size it was then: the
  // page would go on showing the old number under the same dim styling a
  // live one has, which is the kept-versus-observed shape exactly.
  lastNudbSize = reading.bytes;
  lastNudbWalkError = reading.error;
  if (reading.error !== null) {
    // Kept for the page: a path that is set and cannot be walked is a
    // different fact from one that was never set, and the System tab names
    // each as itself rather than showing the same dash for both.
    console.warn('[nudb] walk failed:', reading.error);
    return;
  }
  if (reading.bytes !== null) recordStoreSize(reading.bytes, Date.now(), false);
}
// The store as this host's own Advisor measured it, when this process could
// not measure it itself. Null the rest of the time, which is every host
// whose own walk works.
let advisorStoreReading: AdvisorStoreReading | null = null;

/**
 * Ask this host's Advisor for the store size, and only when there is a
 * reason to.
 *
 * #427. The node's state directory is 0750 and owned by the account the node
 * runs as on a package install, so this process cannot open it, and giving
 * the account that serves a web page read access to the whole ledger store
 * is the wrong way to fix that. The Advisor already holds the one grant that
 * can read it, and this process already fetches its /v1/status for the
 * component versions, so the number comes back over a path that exists.
 *
 * Three gates, and each one is what keeps this cheap and honest:
 *
 *   - only when this dashboard's own walk did not produce a reading. A host
 *     that can measure its own store never makes this call at all.
 *   - only on the walk's own cadence, once a minute, never on a page load or
 *     a broadcast. A browser poll must not be able to drive an outbound call.
 *   - only when the presence probe says an Advisor is actually here (ADR
 *     0016's one observed fact). `installed-but-down` and `absent` both mean
 *     there is nothing to ask, and the card says so rather than waiting.
 *
 * #1245. What comes back is also recorded (recordAdvisorStoreSample), so the
 * peaks, the growth fit and the free-days estimate fill on a host whose store
 * this account will never be allowed to open. The alternative was a read
 * grant on the node's state directory, and passage through it exposes the
 * node's wallet database (its peer identity key) to the account that serves
 * a web page.
 */
async function refreshAdvisorStoreReading(): Promise<void> {
  if (!RIPPLED_DATA_PATH || storeMeasured(nudbReading())) { advisorStoreReading = null; return; }
  if (advisorPresenceSelf.state !== 'present') { advisorStoreReading = null; return; }
  const status = await fetchSelfAdvisorStatus();
  // The ask took time. A walk that has recovered since it was made is the
  // better reading, and a sample of this one would be the second source of
  // a store this process can now measure itself.
  if (storeMeasured(nudbReading())) { advisorStoreReading = null; return; }
  const reading = parseAdvisorStore(status?.store);
  if (reading === null && advisorStoreReading !== null) {
    console.warn('[nudb] the Advisor stopped reporting the store size');
  }
  advisorStoreReading = reading;
  noteAdvisorStorePath(reading);
  recordAdvisorStoreSample(reading, Date.now());
}
// Whether the Advisor's last size was of the store this dashboard is
// configured for. A reading of another directory is shown, labelled, and is
// neither recorded nor fitted from, and the page cannot say which of the two
// paths differs, so the log does, once, when it starts and when it stops. A
// container node is the ordinary case: the wrapper measures the whole data
// mount and the dashboard is pointed at the store inside it.
let advisorPathMatched: boolean | null = null;
function noteAdvisorStorePath(r: AdvisorStoreReading | null): void {
  if (r === null || r.bytes === null) return;
  const matched = storePathsMatch(r.path, RIPPLED_DATA_PATH);
  if (matched === advisorPathMatched) return;
  advisorPathMatched = matched;
  if (matched) console.log('[nudb] the Advisor now measures the store this dashboard is configured for; its readings are recorded');
  else console.warn(`[nudb] the Advisor measured ${JSON.stringify(r.path)} and this dashboard is configured for ${JSON.stringify(RIPPLED_DATA_PATH)}; its size is shown, labelled, and not recorded or fitted from`);
}
// The Advisor's readings, into this dashboard's own series. Only a reading
// that is a size, is current, is new and is of this dashboard's store is
// written, stamped with when the Advisor took it (lib/store-size.ts says why
// each of those). Twice: into nudb_size, which the chart draws, and into
// nudb_size_advisor, which is all a derivation from the Advisor's readings
// reads, so the sizes of a store that used to be here never enter the fit.
const recordAdvisorStoreSample = makeAdvisorSampleRecorder(
  (bytes, ts) => recordStoreSize(bytes, ts, true),
  RIPPLED_DATA_PATH,
);

async function askAdvisorForStore(): Promise<void> {
  try {
    await refreshAdvisorStoreReading();
  } catch (err) {
    // An Advisor that could not be reached is not a reason to lose the walk's
    // own result, which is already recorded by the walk.
    console.warn('[nudb] could not ask the Advisor for the store size:', (err as Error).message);
    advisorStoreReading = null;
  }
}

/** The walk, then the fallback, in that order: the fallback's own first
 *  question is whether the walk produced a reading. */
async function sampleStore(): Promise<void> {
  await sampleNudbSize();
  await askAdvisorForStore();
}

// Prime once at startup so the System tab has a value on first broadcast.
// An unset path is logged once, here, so the reason for a store that is
// never measured is in the log and not only on the page.
if (RIPPLED_DATA_PATH) void sampleStore();
else console.log('[nudb] RIPPLED_DATA_PATH is not set; the node store is not measured (run the update, which sets it and offers the restart: curl -fsSL https://get.aperire.one | bash -s -- --update --force)');

// ─── rippled.cfg parser (the four changeable settings) ────────────────
// Rippled exposes its retention and sizing config in the file, not on the
// admin RPC surface. Read at startup, cached, and re-read on SIGHUP. Null
// until the first successful read.
//
// The SIGHUP re-read is not housekeeping (#59). The Advisor's own config
// runbook changes exactly these four settings and restarts the node, so this
// process holding a startup parse forever means the next "what is node_size"
// answers with the value the operator just changed away from. The answer
// carries the time of the parse either way, so it is never a lie, but a
// stale-but-dated answer to a question the product itself invalidated is a
// poor one.
interface NodeDbCfg { online_delete: number | null; advisory_delete: boolean | null; }
let lastNodeDbCfg: NodeDbCfg | null = null;
// #59. The other two settings the config runbook (ADR 0018) may change are
// not key=value lines at all: rippled writes them as bare stanzas, the
// section header on one line and the value alone on the next.
//
//   [node_size]
//   huge
//
// Kept beside lastNodeDbCfg rather than folded into it, because that object
// is named for the [node_db] section and these two are not in it. The
// `node-config` read route serves all four together; `system` keeps serving
// node_db_cfg exactly as it always has, so the System tab is untouched.
let lastNodeStanzaCfg: { node_size: string | null; ledger_history: string | null } | null = null;
/** When the parse below last succeeded. The `node-config` read route dates
 *  its answer by this and never by the request, because the file is read once
 *  at startup: a value can be days old inside a response a millisecond old. */
let lastRippledCfgParsedAtMs: number | null = null;
async function readRippledCfg(): Promise<void> {
  if (!RIPPLED_CFG_PATH) return;
  try {
    // The format's two shapes, and the edge cases in telling them apart,
    // live in lib/rippled-cfg.ts so they can be tested without a file.
    const cfg = parseRippledCfg(await readFile(RIPPLED_CFG_PATH, 'utf8'));
    lastNodeDbCfg = { online_delete: cfg.online_delete, advisory_delete: cfg.advisory_delete };
    lastNodeStanzaCfg = { node_size: cfg.node_size, ledger_history: cfg.ledger_history };
    lastRippledCfgParsedAtMs = Date.now();
    console.log(`[cfg] rippled.cfg parsed: online_delete=${cfg.online_delete}, advisory_delete=${cfg.advisory_delete}, `
      + `node_size=${cfg.node_size ?? '(absent)'}, ledger_history=${cfg.ledger_history ?? '(absent)'}`);
  } catch (err) {
    // A failed re-read must not leave the old value looking current: it is
    // left exactly as it was, with lastRippledCfgParsedAtMs still dating the
    // last read that actually succeeded. It is never bumped by an attempt that
    // did not (kept-vs-observed).
    console.warn('[cfg] rippled.cfg read failed:', (err as Error).message);
  }
}
// #546. The lone startup call above is not enough: nothing else re-read this
// file except SIGHUP, so a config the Advisor's own runbook changed (ADR
// 0018) went on answering with the value from before the change for as long
// as this process stayed up. The parsed_at_ms sat true and silently ignored. A
// SIGHUP is not guaranteed for that ceremony: it restarts the NODE, never
// this process.
//
// The fix is a cheap fact this process can always check for itself, on the
// same cadence it already broadcasts the System tab: has the file's mtime
// moved since the last read? statSync costs one syscall, next to nothing
// beside the parse it can trigger, and it needs no cooperation from whatever
// changed the file (the Advisor's runbook, a hand edit, anything).
let lastRippledCfgMtimeMs: number | null = null;
if (RIPPLED_CFG_PATH) {
  readRippledCfg();
  try { lastRippledCfgMtimeMs = statSync(RIPPLED_CFG_PATH).mtimeMs; } catch { /* best effort; the poll below catches it */ }
}
async function refreshRippledCfgIfChanged(): Promise<void> {
  if (!RIPPLED_CFG_PATH) return;
  try {
    const mtimeMs = statSync(RIPPLED_CFG_PATH).mtimeMs;
    if (mtimeMs === lastRippledCfgMtimeMs) return;
    lastRippledCfgMtimeMs = mtimeMs;
    // Awaited, not fired-and-forgotten: the caller (pushSystem) reads
    // lastNodeDbCfg a few lines after this returns, in the same broadcast.
    // A change caught this cycle should answer in this cycle, not the
    // next one.
    await readRippledCfg();
  } catch (err) {
    // Could not even stat() the file this cycle (a transient permission
    // window (#545) or a missing mount). The cached values stand, dated by
    // their own last successful parse; nothing here claims a fresher read
    // that did not happen.
    console.warn('[cfg] rippled.cfg stat failed:', (err as Error).message);
  }
}

// ─── Insights tab config loader (rules / channels / digest) ────────────
// Three YAML files in INSIGHTS_CONFIG_DIR drive everything the Insights
// tab renders. Loaded at startup; reloaded on SIGHUP. Validation is
// permissive, any per-section parse error is captured and surfaced to
// the UI as a red badge on that section, rather than crashing the
// dashboard. The browser never sees the raw secret values; channels with
// secrets show only the env-var name + a masked tail of the resolved key.

type InsightsValidation = { ok: boolean; level: 'ok' | 'warn' | 'alert'; message?: string };

interface ParsedRule {
  metric: string;
  severity: 'warn' | 'critical' | 'page';
  threshold: { op: string; value: number };
  duration: string;          // raw, e.g. "60s"
  durationS: number;         // parsed seconds for evaluator
  channels: string[];
  // #128. Optional operator instruction: what to do about this rule
  // firing, and why it matters. Per-RULE rather than per-metric, because
  // a warn and a critical on one metric usually want different answers.
  // Falls back to the metric knowledge library when absent.
  //
  // Instruction text only. The Insights security model is read, validate
  // and instruct, so nothing here is ever executed and no live value is
  // interpolated into it: the alert row already names the node, the
  // threshold and the reading. A static string is all this can be.
  action?: string;
  action_command?: string;
}

interface MetricKnowledgeEntry {
  description: string;
  recommended_actions: string[];
}

interface InsightsConfigState {
  rules: {
    path: string;
    /** ADR 0020. The operator's overrides, read beside the shipped file. */
    localPath: string;
    validation: InsightsValidation;
    counts: { total: number; page: number; critical: number; warn: number };
    /** What the local file did to the shipped set on the last load. `present`
     *  is false when there is no such file, which is the normal case. */
    local: { present: boolean; overrides: number; added: number; disabled: number };
    full: ParsedRule[];
    lastReloadedAt: number | null;
  };
  knowledge: {
    path: string;
    validation: InsightsValidation;
    metric_alerts: Record<string, MetricKnowledgeEntry>;
  };
  channels: {
    path: string;
    validation: InsightsValidation;
    email: { configured: boolean; senderRaw: string | null; recipients: number; keyMask: string | null; keyPresent: boolean };
    ntfy:  { configured: boolean; baseUrl: string | null; topic: string | null; tokenPresent: boolean };
    webhooks: { count: number };
    activeCount: number;     // 0..3, drives the Channels strip cell
  };
  digest: {
    path: string;
    validation: InsightsValidation;
    enabled: boolean;
    cadence: string | null;
    timeUtc: string | null;
    recipients: number;
    includes: string[];
  };
}

const INSIGHTS_KNOWLEDGE_DIR = process.env.APERIRE_KNOWLEDGE_DIR
  ?? resolve(import.meta.dirname, 'knowledge');

const insightsConfigPaths = {
  rules:     join(INSIGHTS_CONFIG_DIR, 'rules.yaml'),
  rulesLocal: join(INSIGHTS_CONFIG_DIR, LOCAL_RULES_FILENAME),
  channels:  join(INSIGHTS_CONFIG_DIR, 'channels.yaml'),
  digest:    join(INSIGHTS_CONFIG_DIR, 'digest.yaml'),
  knowledge: join(INSIGHTS_KNOWLEDGE_DIR, 'metric-alerts.yaml'),
};

// The amendment library the release ships (read only) and the copy this host
// refreshes at run time. The runtime copy lives in data/, the one directory
// the unit may write (ADR 0024); it used to overwrite the tracked file in
// dashboard/knowledge, which left every checkout dirty and kept the source
// tree writable by the web process. Beside the database, which is in data/
// on every install (and in a test's own directory under a test).
const AMENDMENTS_SHIPPED_PATH = join(INSIGHTS_KNOWLEDGE_DIR, 'amendments.yaml');
const AMENDMENTS_LIBRARY_PATH = process.env.APERIRE_AMENDMENTS_PATH
  ?? join(dirname(DB_PATH), 'amendments.yaml');

// Server-internal email config, not exposed via the API. Populated when
// channels.yaml loads if the email channel is configured AND its API key
// resolves from env. Used by the state-machine evaluator to actually send.
let emailSendConfig: EmailChannelConfig | null = null;

// Phase 7, server-internal ntfy push config. Same pattern as
// emailSendConfig: only exists when the channel is configured AND
// reachable. Bearer token is optional (public topics work without).
let ntfySendConfig: NtfyChannelConfig | null = null;

// Phase 8, server-internal webhook fan-out list. One entry per
// configured target in channels.yaml; rules.yaml refers to the bare
// id 'webhook' and we fan out to every entry whose severity_filter
// admits the alert. Empty array = no webhooks configured.
let webhookSendConfigs: WebhookChannelConfig[] = [];

// Phase 6, server-internal digest send config. Holds the resolved
// recipient list + cadence + content flags + subject template, parallel
// to emailSendConfig. Never exposed via the API; reset on every
// SIGHUP / digest.yaml reload.
interface DigestSendConfig {
  enabled: boolean;
  cadence: 'daily' | 'weekly' | 'hourly';
  timeUtc: string;          // "HH:MM" UTC of the daily/weekly send
  weeklyDays: number[];     // 0=Sun..6=Sat, used when cadence is 'weekly'
  recipients: string[];     // override from digest.yaml, else email channel recipients
  subjectTemplate: string;
  footerTemplate: string;
  include: {
    agreement_summary: boolean;
    top_alerts: boolean;
    digest_window_hours: number;
    network_health: boolean;
    upcoming_amendments: boolean;
  };
}
let digestSendConfig: DigestSendConfig | null = null;

// Phase 5, Test Fire rate limiter. In-memory sliding-window of recent
// test-fire timestamps per channel, capped at TEST_FIRE_LIMIT per
// TEST_FIRE_WINDOW_MS. Keyed by channel id ('email' | 'ntfy' | 'webhook')
// so each channel has its own bucket, flooding email tests doesn't
// burn the ntfy budget. Resets naturally via the sliding window.
const TEST_FIRE_LIMIT = 5;
const TEST_FIRE_WINDOW_MS = 3_600_000;
const testFireBuckets = new Map<string, number[]>();

function testFireRateState(channelId: string): { used: number; limit: number; reset_ts: number | null } {
  const now = Date.now();
  const cutoff = now - TEST_FIRE_WINDOW_MS;
  const bucket = (testFireBuckets.get(channelId) ?? []).filter(t => t >= cutoff);
  testFireBuckets.set(channelId, bucket);
  const reset_ts = bucket.length > 0 ? bucket[0] + TEST_FIRE_WINDOW_MS : null;
  return { used: bucket.length, limit: TEST_FIRE_LIMIT, reset_ts };
}

function testFireConsume(channelId: string): boolean {
  const state = testFireRateState(channelId);
  if (state.used >= state.limit) return false;
  const bucket = testFireBuckets.get(channelId) ?? [];
  bucket.push(Date.now());
  testFireBuckets.set(channelId, bucket);
  return true;
}

// What a Live Test would actually attempt, for the Insights card to name.
// Read from the send configs the executor below checks, not from the
// config summary: channels.yaml can list an email block whose API key env
// var is unset, the summary calls that configured, and the executor then
// answers 'not configured'. The card has to say what the button will do.
function testFireConfigured(): { email: boolean; ntfy: boolean; webhooks: number } {
  return { email: !!emailSendConfig, ntfy: !!ntfySendConfig, webhooks: webhookSendConfigs.length };
}

// Optional second-factor, if APERIRE_TEST_TOKEN is set in env, every
// Test Fire request must carry a matching token. Empty / unset env var
// means open access (still rate-limited). Operators who want stricter
// control set the var; otherwise the rate-limit alone is the gate.
function testFireTokenRequired(): boolean {
  return !!process.env.APERIRE_TEST_TOKEN;
}
function testFireTokenValid(provided: string | null | undefined): boolean {
  const expected = process.env.APERIRE_TEST_TOKEN;
  if (!expected) return true;
  return typeof provided === 'string' && provided === expected;
}

const insightsConfig: InsightsConfigState = {
  rules:    { path: insightsConfigPaths.rules, localPath: insightsConfigPaths.rulesLocal, validation: { ok: false, level: 'alert', message: 'not loaded' }, counts: { total: 0, page: 0, critical: 0, warn: 0 }, local: { present: false, overrides: 0, added: 0, disabled: 0 }, full: [], lastReloadedAt: null },
  knowledge: { path: insightsConfigPaths.knowledge, validation: { ok: false, level: 'alert', message: 'not loaded' }, metric_alerts: {} },
  channels: { path: insightsConfigPaths.channels, validation: { ok: false, level: 'alert', message: 'not loaded' }, email: { configured: false, senderRaw: null, recipients: 0, keyMask: null, keyPresent: false }, ntfy: { configured: false, baseUrl: null, topic: null, tokenPresent: false }, webhooks: { count: 0 }, activeCount: 0 },
  digest:   { path: insightsConfigPaths.digest,   validation: { ok: false, level: 'alert', message: 'not loaded' }, enabled: false, cadence: null, timeUtc: null, recipients: 0, includes: [] },
};

function maskSecret(value: string | undefined): string | null {
  if (!value) return null;
  if (value.length <= 4) return '****';
  return '****' + value.slice(-4);
}

function parseDurationSeconds(s: unknown): number {
  if (typeof s === 'number') return s;
  const m = /^(\d+(?:\.\d+)?)\s*(s|m|h|ms)?$/.exec(String(s ?? '').trim());
  if (!m) return 0;
  const n = Number(m[1]);
  const unit = m[2] || 's';
  if (unit === 'ms') return n / 1000;
  if (unit === 'm')  return n * 60;
  if (unit === 'h')  return n * 3600;
  return n;
}

// ADR 0020. Two files: the shipped rules.yaml, replaced by every update, and
// the operator's rules.local.yaml, which nothing writes and which overrides
// the shipped set by metric + severity. The merge happens on the raw yaml
// entries, so everything below this line sees exactly what it saw when one
// file fed it.
//
// The local file cannot take the alerting down. A file that will not parse,
// or one carrying an entry this cannot key, is a named error with the shipped
// rules loaded and in force: never a silent drop, never zero rules. Only the
// SHIPPED file failing leaves the previous rules alone, exactly as before.
async function loadRulesYaml(): Promise<void> {
  const target = insightsConfig.rules;
  try {
    const text = await readFile(target.path, 'utf8');

    // Absent is the normal case and is not an error. Present-but-unreadable
    // is: a file the operator wrote and this process cannot open must say so
    // rather than run as though the host had no overrides.
    let localText: string | null = null;
    let localReadError: string | null = null;
    try {
      localText = await readFile(target.localPath, 'utf8');
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code !== 'ENOENT') localReadError = `${LOCAL_RULES_FILENAME}: ${e.message}`;
    }

    const merged = mergeRuleFiles(text, localText);
    const localError = localReadError ?? merged.localError;
    const rawRules = merged.rules;

    const counts = { total: 0, page: 0, critical: 0, warn: 0 };
    const full: ParsedRule[] = [];
    const actionWarnings: RuleActionWarning[] = [];
    for (const raw of rawRules) {
      if (!raw || typeof raw !== 'object') continue;
      const r = raw as AnyObj;
      const metric = typeof r.metric === 'string' ? r.metric : '';
      const sev = String(r.severity ?? '').toLowerCase();
      if (!metric || (sev !== 'page' && sev !== 'critical' && sev !== 'warn')) continue;
      const threshold = (r.threshold ?? {}) as AnyObj;
      const op = typeof threshold.op === 'string' ? threshold.op : '>=';
      const tval = typeof threshold.value === 'number' ? threshold.value : Number(threshold.value);
      if (!Number.isFinite(tval)) continue;
      const channels = Array.isArray(r.channels)
        ? r.channels.filter((c: unknown) => typeof c === 'string') as string[]
        : [];
      full.push({
        metric,
        severity: sev as ParsedRule['severity'],
        threshold: { op, value: tval },
        duration: typeof r.duration === 'string' ? r.duration : '0s',
        durationS: parseDurationSeconds(r.duration),
        channels,
        action: parseRuleActionField(r.action, RULE_ACTION_MAX, 'action', metric, actionWarnings),
        action_command: parseRuleActionField(r.action_command, RULE_ACTION_COMMAND_MAX, 'action_command', metric, actionWarnings),
      });
      counts.total++;
      if (sev === 'page') counts.page++;
      else if (sev === 'critical') counts.critical++;
      else if (sev === 'warn') counts.warn++;
    }
    target.counts = counts;
    target.full = full;
    target.local = {
      present: localReadError !== null || merged.localPresent,
      overrides: merged.counts.overrides,
      added: merged.counts.added,
      disabled: merged.counts.disabled,
    };
    // The rules loaded either way, so this is never an alert badge: it is a
    // warn naming the file that was skipped and why.
    target.validation = localError
      ? { ok: true, level: 'warn', message: localError }
      : { ok: true, level: 'ok' };
    target.lastReloadedAt = Date.now();
    rebuildRulesByMetric();
    pruneOrphanedFiringState();
    // A field that was thrown away says so. Silently dropping operator
    // instruction text would look identical to never having written any.
    for (const w of actionWarnings) {
      console.warn(`[insights] rules.yaml: ${w.metric} ${w.field} ignored, ${w.reason}`);
    }
    if (localError) {
      console.warn(`[insights] ${localError}; the shipped rules stand and nothing from that file is applied`);
    }
    console.log(`[insights] ${describeRulesLoad(counts, { ...merged, localError })}`);
  } catch (err) {
    target.validation = { ok: false, level: 'alert', message: (err as Error).message };
    target.counts = { total: 0, page: 0, critical: 0, warn: 0 };
    target.local = { present: false, overrides: 0, added: 0, disabled: 0 };
    target.full = [];
    rebuildRulesByMetric();
    console.warn(`[insights] rules.yaml load failed: ${(err as Error).message}`);
  }
}

async function loadChannelsYaml(): Promise<void> {
  const target = insightsConfig.channels;
  try {
    const text = await readFile(target.path, 'utf8');
    const doc = yaml.load(text) as AnyObj;
    const channels = (doc?.channels ?? {}) as AnyObj;

    // Email
    const e = (channels.email ?? {}) as AnyObj;
    const apiKeyEnv = typeof e.api_key_env === 'string' ? e.api_key_env : '';
    const apiKey = apiKeyEnv ? process.env[apiKeyEnv] : '';
    const recips = Array.isArray(e.recipients) ? e.recipients.filter((r: unknown) => typeof r === 'string') as string[] : [];
    target.email = {
      configured: !!e && !!e.provider && recips.length > 0,
      senderRaw: typeof e.sender === 'string' ? e.sender : null,
      recipients: recips.length,
      keyMask: maskSecret(apiKey),
      keyPresent: !!apiKey,
    };

    // Server-internal email send config, kept separate from the public
    // summary above so the API response never carries the API key or the
    // full recipient list. Only the deliverChannels() path reads this.
    emailSendConfig = (target.email.configured && apiKey) ? {
      apiKey,
      sender: typeof e.sender === 'string' ? e.sender : '',
      recipients: recips,
    } : null;

    // ntfy
    const n = (channels.ntfy ?? {}) as AnyObj;
    const tokenEnv = typeof n.token_env === 'string' ? n.token_env : '';
    const ntfyToken = tokenEnv ? (process.env[tokenEnv] ?? '') : '';
    const tokenPresent = !!ntfyToken;
    target.ntfy = {
      configured: !!n && !!n.provider && !!n.topic,
      baseUrl: typeof n.base_url === 'string' ? n.base_url : null,
      topic:   typeof n.topic === 'string' ? n.topic : null,
      tokenPresent,
    };

    // Server-internal ntfy config, same shape rules as emailSendConfig.
    // Severity-priority map honors what's in the YAML; falls back to a
    // sensible default if the operator omitted it.
    const sevPri = (n.severity_priority ?? {}) as AnyObj;
    ntfySendConfig = (target.ntfy.configured && target.ntfy.baseUrl && target.ntfy.topic) ? {
      baseUrl: target.ntfy.baseUrl,
      topic:   target.ntfy.topic,
      token:   ntfyToken || null,
      severityPriority: {
        warn:     typeof sevPri.warn     === 'string' ? sevPri.warn     : 'default',
        critical: typeof sevPri.critical === 'string' ? sevPri.critical : 'high',
        page:     typeof sevPri.page     === 'string' ? sevPri.page     : 'urgent',
      },
    } : null;

    // Webhooks (Phase 8), list of fan-out targets. Each entry parsed
    // independently; bad entries log a warning and are skipped, so a
    // single typo never disables all delivery.
    const wh = Array.isArray(channels.webhooks) ? channels.webhooks : [];
    const validWebhooks: WebhookChannelConfig[] = [];
    const validSeverities = new Set(['warn', 'critical', 'page']);
    for (let i = 0; i < wh.length; i++) {
      const entry = (wh[i] ?? {}) as AnyObj;
      const id     = typeof entry.id     === 'string' ? entry.id     : `webhook-${i + 1}`;
      const format = typeof entry.format === 'string' ? entry.format : '';
      const url    = typeof entry.url    === 'string' ? entry.url    : '';
      if (format !== 'discord' && format !== 'slack' && format !== 'generic') {
        console.warn(`[insights] webhooks[${i}] '${id}': unknown format '${format}' (expected discord|slack|generic), skipped`);
        continue;
      }
      if (!url) {
        console.warn(`[insights] webhooks[${i}] '${id}': missing url, skipped`);
        continue;
      }
      const authHeaderEnv = typeof entry.auth_header_env === 'string' ? entry.auth_header_env : '';
      const authHeader = authHeaderEnv ? (process.env[authHeaderEnv] ?? '') : '';
      const sevList = Array.isArray(entry.severity_filter) ? entry.severity_filter : null;
      const severityFilter = sevList
        ? (sevList.filter(s => typeof s === 'string' && validSeverities.has(s)) as WebhookChannelConfig['severityFilter'])
        : null;
      validWebhooks.push({
        id,
        format: format as WebhookFormat,
        url,
        authHeader: authHeader || null,
        severityFilter: (severityFilter && severityFilter.length > 0) ? severityFilter : null,
      });
    }
    webhookSendConfigs = validWebhooks;
    target.webhooks = { count: validWebhooks.length };

    target.activeCount = (target.email.configured ? 1 : 0)
                       + (target.ntfy.configured  ? 1 : 0)
                       + (target.webhooks.count > 0 ? 1 : 0);

    target.validation = { ok: true, level: 'ok' };
    if (target.email.configured && !target.email.keyPresent) {
      target.validation = { ok: false, level: 'warn', message: `${apiKeyEnv} env var not set` };
    }
    console.log(`[insights] channels.yaml parsed: ${target.activeCount}/3 active (email=${target.email.configured} ntfy=${target.ntfy.configured} webhooks=${target.webhooks.count})`);
  } catch (err) {
    target.validation = { ok: false, level: 'alert', message: (err as Error).message };
    console.warn(`[insights] channels.yaml load failed: ${(err as Error).message}`);
  }
}

async function loadDigestYaml(): Promise<void> {
  const target = insightsConfig.digest;
  try {
    const text = await readFile(target.path, 'utf8');
    const doc = yaml.load(text) as AnyObj;
    target.enabled = doc.enabled === true;
    target.cadence = typeof doc.cadence === 'string' ? doc.cadence : null;
    target.timeUtc = typeof doc.time_utc === 'string' ? doc.time_utc : null;

    // Recipient list: prefer override_recipients in digest.yaml, else
    // reuse the email channel's recipients. Public summary stores the
    // count; the server-internal digestSendConfig stores the full list.
    const overrideList = Array.isArray(doc.override_recipients)
      ? (doc.override_recipients as unknown[]).filter(r => typeof r === 'string') as string[]
      : [];

    // Look up the resolved email-channel recipients via the channels.yaml
    // round-trip. We don't have direct access to that array on the public
    // insightsConfig blob, so resolve through emailSendConfig (set right
    // before this loader runs by loadChannelsYaml, since loadInsightsConfig
    // calls them in order).
    const fallbackRecips = emailSendConfig?.recipients ?? [];
    const resolvedRecips = overrideList.length > 0 ? overrideList : fallbackRecips;
    target.recipients = resolvedRecips.length;

    const includes = (doc.include ?? {}) as AnyObj;
    const flags: string[] = [];
    if (includes.agreement_summary)   flags.push('agreement');
    if (includes.top_alerts)          flags.push('top alerts');
    if (includes.network_health)      flags.push('network');
    if (includes.upcoming_amendments) flags.push('amendments');
    target.includes = flags;

    // Server-internal config used by the cron + sender. Only built when
    // the digest is enabled AND we have at least one recipient resolved
    // (otherwise there's nothing to send).
    const cadenceRaw = (target.cadence ?? 'daily').toLowerCase();
    const cadence: DigestSendConfig['cadence'] =
      cadenceRaw === 'weekly' ? 'weekly' :
      cadenceRaw === 'hourly' ? 'hourly' : 'daily';
    const weeklyDays = Array.isArray(doc.weekly_days)
      ? (doc.weekly_days as unknown[]).filter(n => typeof n === 'number') as number[]
      : [1];
    digestSendConfig = (target.enabled && resolvedRecips.length > 0)
      ? {
          enabled:  true,
          cadence,
          timeUtc:  target.timeUtc ?? '13:00',
          weeklyDays,
          recipients: resolvedRecips,
          subjectTemplate: typeof doc.subject === 'string'
            ? doc.subject
            : 'Aperire daily report · {host} · {agreement_pct}% agreement',
          footerTemplate:  typeof doc.footer === 'string' ? doc.footer : '',
          include: {
            agreement_summary:   includes.agreement_summary === true,
            top_alerts:          includes.top_alerts === true,
            digest_window_hours: typeof includes.digest_window_hours === 'number' ? includes.digest_window_hours : 24,
            network_health:      includes.network_health === true,
            upcoming_amendments: includes.upcoming_amendments === true,
          },
        }
      : null;

    target.validation = { ok: true, level: 'ok' };
    console.log(`[insights] digest.yaml parsed: ${target.cadence} at ${target.timeUtc} → ${target.recipients} recipients`);
  } catch (err) {
    target.validation = { ok: false, level: 'alert', message: (err as Error).message };
    digestSendConfig = null;
    console.warn(`[insights] digest.yaml load failed: ${(err as Error).message}`);
  }
}

async function loadKnowledgeYaml(): Promise<void> {
  // Loads the metric-alert knowledge library. Indexed by metric name
  // (one entry per metric, severity-agnostic for now). Only the fields
  // the UI consumes are surfaced: description + recommended_actions.
  const target = insightsConfig.knowledge;
  try {
    const text = await readFile(target.path, 'utf8');
    const doc = yaml.load(text);
    const entries = Array.isArray(doc) ? doc : null;
    if (!entries) throw new Error('expected top-level YAML array of entries');

    const map: Record<string, MetricKnowledgeEntry> = {};
    let count = 0;
    for (const raw of entries) {
      if (!raw || typeof raw !== 'object') continue;
      const e = raw as AnyObj;
      const metric = typeof e.metric === 'string' ? e.metric : '';
      if (!metric) continue;
      map[metric] = {
        description: typeof e.description === 'string' ? e.description : '',
        recommended_actions: Array.isArray(e.recommended_actions)
          ? (e.recommended_actions as unknown[]).filter(a => typeof a === 'string') as string[]
          : [],
      };
      count++;
    }
    target.metric_alerts = map;
    target.validation = { ok: true, level: 'ok' };
    console.log(`[insights] metric-alerts.yaml parsed: ${count} entries`);
  } catch (err) {
    target.validation = { ok: false, level: 'warn', message: (err as Error).message };
    target.metric_alerts = {};
    console.warn(`[insights] metric-alerts.yaml load failed: ${(err as Error).message}`);
  }
}

async function loadInsightsConfig(): Promise<void> {
  // Order matters: digest reads channels.email.recipients as fallback.
  await loadRulesYaml();
  await loadChannelsYaml();
  await loadDigestYaml();
  await loadKnowledgeYaml();
  await loadAmendmentsLibrary();
}

loadInsightsConfig();

// SIGHUP triggers a reload, same idiom as `systemctl reload`. Operators
// edit the YAML files, then `systemctl reload aperire-dashboard` (which
// sends SIGHUP under default unit semantics). The state object updates
// in place; the next /api/insights/config request sees the new values.
process.on('SIGHUP', () => {
  console.log('[insights] SIGHUP received, reloading config');
  loadInsightsConfig();
  // And the node's own config, for the reason at readRippledCfg: the
  // Advisor's config runbook changes those four settings, and a startup
  // parse kept forever would answer with what they used to be.
  void readRippledCfg();
});

// ─── Fleet registry + health poller, decisions.md D5, task steps A/B ────
// A small, independent registry (config/fleet.yaml) telling this dashboard
// where every other node in its fleet lives and how to reach a health dot
// for it. Never the Advisor's advisor/state/fleet.json, the dashboard must
// not depend on that optional add-on. Absent file (the default on every
// single-node install) is not logged at all: this is the documented
// single-node regression guarantee, not a degraded state.
const FLEET_CONFIG_PATH = join(INSIGHTS_CONFIG_DIR, 'fleet.yaml');
// The trust file, beside the registry and read from the same base so an
// install that moves its config moves both. This is the file that answers
// "which machine may hand this node a key to seal": peers.<issuer_label>,
// the same block advisord reads with its own zero-dependency parser.
const FLEET_TRUST_PATH = join(INSIGHTS_CONFIG_DIR, 'fleet-trust.yaml');

/**
 * Does this node hold the aggregator's key, and if not, why not (#331).
 *
 * Three values, and the third is the one that cost an afternoon. A trust
 * file this account cannot OPEN reads, through readPeerPubKey, exactly like
 * one that was never written: both come back null. On 2026-09-13 a file was
 * placed root-owned with a group nobody was in, the error was swallowed, and
 * the node reported "no key" for a key that was sitting in it. Same class as
 * #318, and it is why an aggregator's row must be able to say "fix the mode"
 * rather than "pair it again".
 *
 * The key lookup itself is the SAME readPeerPubKey call gate 6 of
 * checkUpdateJob makes, so the fact this reports and the refusal a job would
 * get cannot drift. What is added around it is the one stat that tells the
 * two nulls apart.
 */
function aggregatorPinState(): 'pinned' | 'none' | 'unreadable' {
  if (readPeerPubKey(FLEET_TRUST_PATH, FLEET_WRITE_ISSUER_LABEL)) return 'pinned';
  // No key. Either there is no file (never paired, the ordinary state) or
  // there is one this account cannot read.
  try {
    statSync(FLEET_TRUST_PATH);
  } catch {
    return 'none';
  }
  try {
    readFileSync(FLEET_TRUST_PATH, 'utf8');
  } catch {
    // It exists and will not open: a mode or an ownership to fix, never a
    // pairing to run again.
    return 'unreadable';
  }
  // It exists, it opens, and it carries no peers.aggregator line.
  return 'none';
}
// Spent seal and arm nonces, under the one directory this account may write.
// Read and rewritten per request rather than held in memory: a restart must
// not forget what it has already accepted, or a replay of a still-fresh job
// would seal a second time.
const FLEET_WRITE_NONCE_PATH = process.env.APERIRE_FLEET_NONCE_PATH
  ?? resolve(import.meta.dirname, '..', 'data', 'fleet-write-nonces.json');
const fleetWriteNonces = fileNonceStore(FLEET_WRITE_NONCE_PATH);
// A DEDICATED record for advisor.reveal jobs, not the seal/update ledger
// above. Same claimNonce/fileNonceStore machinery, its own file: a
// coincidental nonce collision across job kinds is then structurally
// impossible rather than merely unlikely, and a reveal's replay record can
// never be grown or exhausted by an unrelated seal or update job landing on
// the same store.
const FLEET_ADVISOR_NONCE_PATH = process.env.APERIRE_FLEET_ADVISOR_NONCE_PATH
  ?? resolve(import.meta.dirname, '..', 'data', 'fleet-advisor-nonces.json');
const fleetAdvisorNonces = fileNonceStore(FLEET_ADVISOR_NONCE_PATH);
// The reveal window root plants (scripts/install-advisord.sh), read here by
// lstat only (readAdvisorRevealWindowFacts, lib/fleet-write-api.ts: one call,
// never followed by a stat, so a symlink swapped in after this call cannot
// make a second call see a different file than the one already judged,
// #649): this process never writes it and never reads its content, only its
// ownership, its mode and its own mtime. Overridable so a walk can stage a
// host with one open, closed, or absent.
const ADVISOR_REVEAL_WINDOW_PATH = process.env.APERIRE_ADVISOR_REVEAL_WINDOW_PATH
  ?? resolve(import.meta.dirname, '..', 'advisor', 'state', 'reveal.window');
function statAdvisorRevealWindow(nowMs: number): AdvisorRevealWindowFacts {
  return readAdvisorRevealWindowFacts(ADVISOR_REVEAL_WINDOW_PATH, nowMs);
}
// The fleet's model setting, beside the nonce store for the same reason:
// data/ is the one directory this account may write. Provider, model and key
// are ONE setting for the whole fleet (ruling 2026-09-04), so this file is
// what the Settings page holds each node against. It never holds the key.
const FLEET_MODEL_PATH = process.env.APERIRE_FLEET_MODEL_PATH
  ?? resolve(import.meta.dirname, '..', 'data', 'fleet-model.json');
let fleetPoller: FleetHealthPoller | null = null;
/** The fleet Advisor ledger mirror poller, ADR 0021 build step 3. Rebuilt on
 *  every loadFleetConfig() reload, same "restart, not diff" discipline as
 *  fleetPoller just above: a label rename across a reload must never leave
 *  a stale timer polling under the old name. */
let advisorMirror: AdvisorLedgerMirror | null = null;
/** The fleet memory and inbox mirror poller, ADR 0021 build step 5. Same
 *  reload discipline as advisorMirror just above. */
let advisorNotesMirror: AdvisorNotesMirror | null = null;

/** This host's own advisord, read the same way witnessAdvisorLedger already
 *  does: loopback ADVISOR_URL, the local approve token, re-read fresh on
 *  every call rather than cached, so an Advisor installed after this
 *  dashboard started is picked up without a restart. A dashboard-alone
 *  install (ADR 0016) still gets a LOCAL_NODE target; its fetchLedger
 *  answers `absent: true` every tick rather than an ordinary failure, so
 *  the poller records nothing at all for a host that has no Advisor to
 *  ask, and the mirror stays truly empty rather than a state row full of
 *  identical failed attempts. */
function localMirrorTarget(): MirrorTarget {
  const fetchLedger: FetchLedger = async (sinceSeq) => {
    const tok = advisorApproveToken();
    if (!tok) return { ok: false, detail: 'advisord not installed on this host', absent: true };
    const qs = sinceSeq !== null ? `?since_seq=${sinceSeq}` : '';
    try {
      const r = await fetch(`${ADVISOR_URL}/v1/ledger${qs}`, {
        headers: { authorization: `Bearer ${tok}` },
        signal: AbortSignal.timeout(20_000),
      });
      if (!r.ok) return { ok: false, detail: `advisord answered HTTP ${r.status}` };
      const b = await r.json() as {
        count?: number; head?: string; chain_intact?: boolean; entries?: MirrorLedgerEntry[];
      };
      if (typeof b.count !== 'number' || typeof b.chain_intact !== 'boolean') {
        return { ok: false, detail: 'advisord answered an unexpected shape' };
      }
      return { ok: true, chainIntact: b.chain_intact, count: b.count, head: b.head ?? '', entries: b.entries ?? [] };
    } catch (err) {
      return { ok: false, detail: (err as Error).message };
    }
  };
  return { node: LOCAL_NODE, fetchLedger };
}

/** One peer target, read through fetchPeerAdvisor's exact-path allow-list,
 *  the same pin-then-token preamble every other peer advisor read already
 *  runs. Only for a peer whose row carries advisor_origin/advisor_token_path;
 *  a peer with no Advisor stack registered is simply not in the list this
 *  builds from. */
function peerMirrorTarget(node: FleetNodeConfig): MirrorTarget {
  const fetchLedger: FetchLedger = async (sinceSeq) => {
    const qs = sinceSeq !== null ? `?since_seq=${sinceSeq}` : '';
    const r = await fetchPeerAdvisor(node, { label: node.label, endpoint: 'ledger' }, qs ? { query: qs, pinCache: peerPinCache } : { pinCache: peerPinCache });
    if (!r.ok) return { ok: false, detail: r.detail ?? r.error };
    const b = r.body as { count?: number; head?: string; chain_intact?: boolean; entries?: unknown[] };
    if (typeof b.count !== 'number' || typeof b.chain_intact !== 'boolean') {
      return { ok: false, detail: `${node.label}: advisord answered an unexpected shape` };
    }
    return {
      ok: true, chainIntact: b.chain_intact, count: b.count, head: b.head ?? '',
      entries: (b.entries ?? []) as MirrorLedgerEntry[],
    };
  };
  return { node: node.label, fetchLedger };
}

/** Resolves one node's mirror target by label, LOCAL_NODE included, for the
 *  re-verify route: the one thing the periodic poller and an
 *  operator-triggered re-verify must agree on completely, so both are built
 *  from this. */
function mirrorTargetByNode(node: string): MirrorTarget | null {
  if (node === LOCAL_NODE) return localMirrorTarget();
  const peer = resolvePeerByLabel(fleetPeerNodes, node);
  if (!peer || !peer.advisor_origin || !peer.advisor_token_path) return null;
  return peerMirrorTarget(peer);
}

function buildMirrorTargets(peers: FleetNodeConfig[]): MirrorTarget[] {
  const targets: MirrorTarget[] = [localMirrorTarget()];
  for (const p of peers) {
    if (p.advisor_origin && p.advisor_token_path) targets.push(peerMirrorTarget(p));
  }
  return targets;
}

/** ADR 0021 build step 5: this host's own advisord, for its memory and its
 *  inbox. Same loopback/local-token shape as localMirrorTarget, and the
 *  same absent-Advisor degrade: a dashboard-alone install answers
 *  `absent: true` on both, so the poller records nothing for a host with
 *  no Advisor to ask. */
function localNotesMirrorTarget(): NotesMirrorTarget {
  const fetchMemory: FetchMemory = async () => {
    const tok = advisorApproveToken();
    if (!tok) return { ok: false, detail: 'advisord not installed on this host', absent: true };
    try {
      const r = await fetch(`${ADVISOR_URL}/v1/memory`, {
        headers: { authorization: `Bearer ${tok}` },
        signal: AbortSignal.timeout(20_000),
      });
      if (!r.ok) return { ok: false, detail: `advisord answered HTTP ${r.status}` };
      const b = await r.json() as { entries?: unknown[] };
      if (!Array.isArray(b.entries)) return { ok: false, detail: 'advisord answered an unexpected shape' };
      return { ok: true, entries: b.entries as MemoryMirrorEntryIn[] };
    } catch (err) {
      return { ok: false, detail: (err as Error).message };
    }
  };
  const fetchInbox: FetchInbox = async () => {
    const tok = advisorApproveToken();
    if (!tok) return { ok: false, detail: 'advisord not installed on this host', absent: true };
    try {
      const r = await fetch(`${ADVISOR_URL}/v1/inbox`, {
        headers: { authorization: `Bearer ${tok}` },
        signal: AbortSignal.timeout(20_000),
      });
      if (!r.ok) return { ok: false, detail: `advisord answered HTTP ${r.status}` };
      const b = await r.json() as { notes?: unknown[] };
      if (!Array.isArray(b.notes)) return { ok: false, detail: 'advisord answered an unexpected shape' };
      return { ok: true, notes: b.notes as InboxMirrorNoteIn[] };
    } catch (err) {
      return { ok: false, detail: (err as Error).message };
    }
  };
  return { node: LOCAL_NODE, fetchMemory, fetchInbox };
}

/** One peer target, through fetchPeerAdvisor's exact-path allow-list,
 *  admin-gated at the browser route (ADMIN_ONLY_ADVISOR_READS above), but
 *  this poller calls it server-side with the peer's own advisor token, the
 *  same way peerMirrorTarget already does for the ledger. */
function peerNotesMirrorTarget(node: FleetNodeConfig): NotesMirrorTarget {
  const fetchMemory: FetchMemory = async () => {
    const r = await fetchPeerAdvisor(node, { label: node.label, endpoint: 'memory' }, { pinCache: peerPinCache });
    if (!r.ok) return { ok: false, detail: r.detail ?? r.error };
    const b = r.body as { entries?: unknown[] };
    if (!Array.isArray(b.entries)) return { ok: false, detail: `${node.label}: advisord answered an unexpected shape` };
    return { ok: true, entries: b.entries as MemoryMirrorEntryIn[] };
  };
  const fetchInbox: FetchInbox = async () => {
    const r = await fetchPeerAdvisor(node, { label: node.label, endpoint: 'inbox' }, { pinCache: peerPinCache });
    if (!r.ok) return { ok: false, detail: r.detail ?? r.error };
    const b = r.body as { notes?: unknown[] };
    if (!Array.isArray(b.notes)) return { ok: false, detail: `${node.label}: advisord answered an unexpected shape` };
    return { ok: true, notes: b.notes as InboxMirrorNoteIn[] };
  };
  return { node: node.label, fetchMemory, fetchInbox };
}

function buildNotesMirrorTargets(peers: FleetNodeConfig[]): NotesMirrorTarget[] {
  const targets: NotesMirrorTarget[] = [localNotesMirrorTarget()];
  for (const p of peers) {
    if (p.advisor_origin && p.advisor_token_path) targets.push(peerNotesMirrorTarget(p));
  }
  return targets;
}
/** Last deploy-divergence count written, so the journal gets a line when the
 *  picture changes and silence while it holds (see checkFleetDeployDrift).
 *  Declared here, with the rest of the fleet state, because loadFleetConfig
 *  clears it and runs before this module is done initialising. */
let lastDeployDivergent: number | null = null;
let fleetSelfNode: FleetNodeConfig | null = null;
// The RESOLVED peers array the browser-facing fetch-through route looks
// `:label` up against (D8 slice 2), never the raw parsed nodes, so a row
// that failed self-resolution (resolveFleet's fail-closed branch) can
// never be reachable through this route either. Empty until loadFleetConfig
// runs at least once, which happens synchronously below before the HTTP
// server starts accepting requests.
let fleetPeerNodes: FleetNodeConfig[] = [];
// #1057: the rows the registry carries when none of them is this host
// (resolveFleet's fail-closed answer). Not peers: nothing polls them, no
// route reaches them, and the fetch-through above never sees them. Settings
// lists them so a node that paired into that state can still be revoked.
let fleetHeldNodes: FleetNodeConfig[] = [];
let fleetHeldReason: string | null = null;
// #1191. The labels fleet.yaml carries right now, every row (this host's, the
// peers', a held row), or null when the file could not be read. The notes
// mirror keeps the rows of a node that was renamed or revoked; this is what
// tells the route which of them are from a node no longer in the fleet. Null
// is "not known", never "empty": an absent or empty file is a real, empty
// fleet, and a parse error is not.
let fleetRegistryLabels: RegistryLabels = null;
// #1191. The nodes the notes mirror is polling right now, which is not the
// registry: a registered node whose Advisor address was removed
// (detach-advisor) is in the registry and is not polled, and so is every peer
// while the registry is held. Null until the first load.
let notesMirrorPolled: ReadonlySet<string> | null = null;
// Rebuilt from scratch on every loadFleetConfig() call/reload, see
// FleetFetchThrough's own doc comment for why a fresh instance (never a
// diff) is what makes P2-032 hold: a label rename across a reload can never
// find a cache entry that remembers the OLD row, because there is no old
// cache left to find.
let fleetFetchThrough: FleetFetchThrough = new FleetFetchThrough();
// The generic peer-read proxy, D8 slice 3 backend
// (advisor-enhancement/security-review-peer-read-proxy.md). Same
// "restart, not diff" reload discipline as fleetFetchThrough just above,
// see PeerReadProxy's own doc comment for why a fresh instance is what
// keeps P2-032 true for this wider route surface too.
// #831: one confirmed pin serves every READ through either proxy for a few
// seconds, so a burst of reads costs one identity round trip over the link
// rather than one each. Rebuilt with the two proxies on every reload (a key
// change arrives as one), and keyed on the link's generation, so a
// reconnect always pins again. Writes never use it.
const newPeerPinCache = () => new PeerPinCache({ generation: (label) => fleetLinkHub?.generation(label) ?? 0 });
let peerPinCache: PeerPinCache = newPeerPinCache();
let peerReadProxy: PeerReadProxy = new PeerReadProxy({ pinCache: peerPinCache });

function loadFleetConfig(): void {
  // Kept to hand to the new poller below (#994): stopped first, so only one
  // of the two ever polls.
  const priorPoller = fleetPoller;
  if (fleetPoller) { fleetPoller.stop(); fleetPoller = null; }
  if (advisorMirror) { advisorMirror.stop(); advisorMirror = null; }
  if (advisorNotesMirror) { advisorNotesMirror.stop(); advisorNotesMirror = null; }
  // The deploy-divergence log line only speaks when the count CHANGES, so
  // the remembered count has to go with the fleet it was counted over. A
  // reload that adds or drops a host and lands on the same number is a
  // different fleet saying the same thing, and the journal should say so.
  lastDeployDivergent = null;
  fleetSelfNode = null;
  fleetPeerNodes = [];
  fleetHeldNodes = [];
  fleetHeldReason = null;
  fleetRegistryLabels = null;
  fleetFetchThrough = new FleetFetchThrough();
  peerPinCache = newPeerPinCache();
  peerReadProxy = new PeerReadProxy({ pinCache: peerPinCache });
  try {
    const parsed = loadFleetRegistry(FLEET_CONFIG_PATH);
    if (parsed.error) {
      console.warn(`[fleet] ${parsed.error}, falling back to single-node`);
      return;
    }
    // What the parser dropped rather than refused: one line per row that lost
    // a field the fleet can carry on without (#339). Warned, not logged as
    // ordinary news, because every one of them is a row an operator meant to
    // say something with and this dashboard could not use.
    for (const note of parsed.notes) console.warn(`[fleet] ${note}`);
    // Read fine, so these are the registry's labels whatever happens to them
    // next (a held registry still names them).
    fleetRegistryLabels = new Set(parsed.nodes.map((n) => n.label));
    if (parsed.nodes.length === 0) return; // absent file, or an intentionally empty list
    const resolved = resolveFleet(parsed.nodes, PORT);
    if (resolved.error) {
      console.warn(`[fleet] ${resolved.error}`);
      fleetHeldNodes = parsed.nodes;
      fleetHeldReason = resolved.error;
      return;
    }
    fleetSelfNode = resolved.selfNode;
    fleetPeerNodes = resolved.peers;
    // The lock screen's manual-enrollment hint names which node this is, so
    // an operator on a multi-instance host runs the CLI against the right
    // install (D6 §4.7, the wrong-node link was minted by following this
    // page's own unqualified instruction).
    setInstanceLabel(resolved.selfNode?.label ?? null);
    fleetPoller = new FleetHealthPoller(resolved.peers, { ownPort: PORT, carryFrom: priorPoller });
    fleetPoller.start();
    console.log(`[fleet] ${resolved.peers.length} peer(s) registered, self="${resolved.selfNode?.label}"`);
  } finally {
    // Built from fleetPeerNodes AFTER every branch above, success or early
    // return: a single-node install with its own Advisor still mirrors
    // LOCAL_NODE, and a parse error must not also silence that.
    const targets = buildMirrorTargets(fleetPeerNodes);
    if (targets.length > 0) {
      advisorMirror = new AdvisorLedgerMirror(targets, { intervalMs: 20_000 });
      advisorMirror.start();
    }
    // ADR 0021 build step 5, same "restart, not diff" reload as the ledger
    // mirror just above and for the same reason: a label rename across a
    // reload must never leave a stale timer polling under the old name.
    const notesTargets = buildNotesMirrorTargets(fleetPeerNodes);
    notesMirrorPolled = new Set(notesTargets.map((t) => t.node));
    if (notesTargets.length > 0) {
      advisorNotesMirror = new AdvisorNotesMirror(notesTargets, { intervalMs: 30_000 });
      advisorNotesMirror.start();
    }
  }
}
loadFleetConfig();
// Same reload idiom as the Insights config above, edit fleet.yaml, then
// `systemctl reload aperire-server`. Restarting the poller on every reload
// (rather than diffing) is deliberate: fleet.yaml changes rarely, and a
// clean restart can't leave a stale peer's interval timer running under an
// old label.
process.on('SIGHUP', () => {
  console.log('[fleet] SIGHUP received, reloading fleet.yaml');
  loadFleetConfig();
});

// ─── The fleet link, ADR 0019 phase 1 ─────────────────────────────────
//
// Two halves, and a host is at most one of them.
//
//   The HUB runs on an aggregator that has a config/fleet-links.json. It
//   accepts a node's outbound WebSocket and binds that node's loopback
//   listeners, which is where the SSH forward used to land.
//
//   The AGENT runs on a node that has a config/fleet-link.json. It dials the
//   aggregator and serves allow-listed requests against its own loopback.
//
// Both files are absent on a single-node install, so neither object is
// constructed, no port is bound, no socket is opened and no timer is armed.
// That is the ADR's "single-node installs are unaffected", enforced by
// there being nothing to run rather than by a flag.
const FLEET_LINKS_PATH = join(INSIGHTS_CONFIG_DIR, FLEET_LINK_REGISTRY_BASENAME);
const FLEET_LINK_CONFIG_PATH = join(INSIGHTS_CONFIG_DIR, FLEET_LINK_CONFIG_BASENAME);
// #688: a revocation the aggregator signed. Written only by the agent, after
// the signature verifies, and so in data/ rather than beside fleet-link.json:
// the dashboard's unit runs ProtectSystem=strict with dashboard/config
// read-only, and data/ is the one directory of the install it may write.
const FLEET_LINK_TOMBSTONE_PATH = join(DB_DIR, FLEET_LINK_TOMBSTONE_BASENAME);
// #738: the revocations this host signed as an aggregator, so a node revoked
// while its link was down is handed its tombstone in the 401 when it dials
// again. In data/ for the same reason as the node's own copy above. Read once
// here; a node install that never revoked anything has no such file.
const fleetLinkIssuedTombstones = createIssuedTombstoneFileStore(join(DB_DIR, FLEET_LINK_ISSUED_TOMBSTONES_BASENAME));
let fleetLinkRows: LinkRegistryRow[] = [];
/**
 * Rows this aggregator holds and will not serve (#687).
 *
 * A withheld row keeps its credential in memory for one purpose: a node
 * dialling with it is told `registry_held` and the sentence that names both
 * files, instead of the 401 a stranger gets. 401 is fatal on the node, so the
 * old "empty the table and fail closed" left every node stopped until somebody
 * ran `systemctl restart aperire-server` on each box. A withheld credential
 * never binds a port and never reaches a Live.
 */
let fleetLinkWithheldRows: WithheldLinkRow[] = [];
/**
 * Can this host say a link credential is UNKNOWN? (#688)
 *
 * False whenever fleet-links.json is absent, unreadable or unparseable, where
 * a 401 would be a final refusal built on no reading at all. Starts false: a
 * process that has not read the file yet is exactly the state that answered
 * every node a 401 after an aggregator restart with the file missing and a
 * pairing code armed.
 */
let fleetLinkRegistryJudgeable = false;
let fleetLinkHub: FleetLinkHub | null = null;
/**
 * Pairing v2: this aggregator's fleet arm PUBLIC key, as root's broker last
 * reported it to a mint or an approval. Module scope rather than on the hub,
 * because the hub is built lazily and a mint can come first. Read by the
 * hub when a keys-first node calls in, so that dial never reaches root. Not
 * persisted: after a restart it is empty until the next mint, and a node
 * that dials in that gap checks after approval instead. Never logged.
 */
let pairArmPubKeyCache: string | null = null;

/** The file, as a value planLinkReload can judge. Reading it is this
 *  function's whole job; every decision about what it means lives in the
 *  hub's planner, where it can be tested (#687). */
function readLinkRegistryFile(): LinkRegistryFile {
  try {
    return { kind: 'text', text: readFileSync(FLEET_LINKS_PATH, 'utf8') };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' };
    return { kind: 'unreadable', detail: (err as Error).message };
  }
}

function loadFleetLinks(): void {
  const plan = planLinkReload({
    file: readLinkRegistryFile(),
    peers: fleetPeerNodes,
    previous: { serving: fleetLinkRows, withheld: fleetLinkWithheldRows },
  });
  fleetLinkRows = plan.serving;
  fleetLinkWithheldRows = plan.withheld;
  fleetLinkRegistryJudgeable = plan.judgeable;
  for (const line of plan.warnings) console.warn(line);
  // #738 review, L1: a row back in the registry (a restore, say) is never
  // answered with the tombstone this host kept for its credential. Only on a
  // reload that read the file: an unreadable one says nothing about rows.
  if (plan.judgeable) {
    try {
      const dropped = pruneIssuedTombstones(fleetLinkIssuedTombstones, plan.serving, plan.withheld);
      if (dropped.length) {
        console.log(`[fleet-link] ${dropped.join(', ')}: back in fleet-links.json, so the revocation kept for `
          + 'that credential was dropped');
      }
    } catch (err) {
      console.warn(`[fleet-link] a kept revocation for a row back in fleet-links.json could not be dropped from `
        + `its file (${(err as Error).message}); it is dropped here until this dashboard restarts`);
    }
  }
  if (fleetLinkRows.length) {
    console.log(`[fleet-link] ${fleetLinkRows.length} node(s) may link to this aggregator`);
  }
  if (fleetLinkWithheldRows.length) {
    console.warn(`[fleet-link] ${fleetLinkWithheldRows.length} row(s) held. Fix the file named above, then `
      + 'reload this dashboard (SIGHUP). A held node relinks on its own; there is nothing to do on it.');
  }
  // A reload that drops a row (or re-mints a credential) closes that node's
  // LIVE link, not just its next dial. Without this the credential an
  // operator just revoked keeps serving until the node happens to reconnect.
  // Skipped when the registry could not be read at all: see planLinkReload.
  // #687 review: when the registry could not be read, the live links are
  // left alone EXCEPT the ones fleet.yaml has just moved out from under. Those
  // are dropped by name, because a listener still answering on a port
  // fleet.yaml now gives another peer answers that peer's polls with the
  // wrong node's data, and hands it that peer's bearer token.
  if (fleetLinkHub) {
    if (plan.reconcile) void fleetLinkHub.reconcile();
    else if (plan.dropLive.length) void fleetLinkHub.reconcile({ onlyLabels: plan.dropLive });
  } else if (fleetLinkRows.length || fleetLinkWithheldRows.length) ensureFleetLinkHub();
}

/**
 * Build the hub, once.
 *
 * Phase 1 built it only when `fleet-links.json` already had rows, which is
 * correct for a link and wrong for a PAIRING: the whole point of pairing is
 * the case where that file is empty, so the first node ever to join would
 * have met a destroyed socket. It is built here when either half is true:
 * a registered node or a live pairing code. A single-node install with
 * neither still constructs nothing, binds no port and arms no timer, which
 * is the ADR's "single-node installs are unaffected" kept as it was.
 */
function ensureFleetLinkHub(): FleetLinkHub {
  if (fleetLinkHub) return fleetLinkHub;
  fleetLinkHub = createFleetLinkHub({
      // Read through the closure, so a SIGHUP that revokes a credential
      // takes effect on the next dial with no restart.
      rows: () => fleetLinkRows,
      // #687: read through the closure too, so the row an operator just
      // un-broke starts serving on the reload rather than on a restart.
      withheldRows: () => fleetLinkWithheldRows,
      // #688: a dial this host cannot judge is held, never refused 401.
      registryJudgeable: () => fleetLinkRegistryJudgeable,
      // #738: what this host signed, for the 401 a revoked node meets.
      issuedTombstones: fleetLinkIssuedTombstones,
      // Guarded like lib/fleet-seal.ts's copy of this call (#281):
      // readOwnPrivateKey validates nothing about the line it read, and
      // signWithSeed throws on a seed that is not 32 bytes. A null is a
      // named refusal on the hub's side; an exception was a crash loop.
      sign: (message) => {
        const seed = readOwnPrivateKey(FLEET_TRUST_PATH);
        if (!seed) return null;
        try {
          return signWithSeed(message, seed);
        } catch {
          return null;
        }
      },
      bindHost: HOST,
      allowPlaintext: INGEST_ALLOW_PLAINTEXT,
      upgrade: (req, socket, head, done) => {
        fleetLinkWss.handleUpgrade(req, socket, head, (ws) => done(ws as unknown as Parameters<typeof done>[0]));
      },
      upgradePairing: (req, socket, head, done) => {
        fleetPairWss.handleUpgrade(req, socket, head, (ws) => done(ws as unknown as Parameters<typeof done>[0]));
      },
      // The pairing half (ADR 0019 phase 3). The hub holds no database
      // handle: it asks for a code to be claimed and is told yes or no.
      consumeCode: (raw, rateKey) => {
        const verdict = consumePairingCode(raw, rateKey, Date.now());
        if (!verdict.ok) return { ok: false, why: verdict.why };
        return { ok: true, expires_at_ms: verdict.expires_at * 1000, name: verdict.name };
      },
      // Derived from the seed this host signs with, so the key a node pins
      // and the key that signed its welcome cannot disagree.
      fleetTrustPubKey: () => readOwnPublicKey(FLEET_TRUST_PATH),
      // Pairing v2: what the last mint or approval heard from root.
      cachedArmPubKey: () => pairArmPubKeyCache,
      // #620: read through the closure, the same reload idiom `rows` above
      // follows, so a fleet.yaml edit + SIGHUP is what a presented key is
      // judged against on the very next pairing hello.
      fleetNodes: () => fleetPeerNodes,
      // #626: the tunnel row's own token copy, the one a known node's move
      // proof is checked against. Read fresh at the check, never cached.
      readTokenFile: readTokenFresh,
      // #626 review, L2: the tunnel's own last read of that row picks the
      // sentence a refused move proof gets.
      tunnelAuth: (label) => fleetPoller?.tunnelAuth(label) ?? { kind: 'unknown' },
    });
  return fleetLinkHub;
}

/**
 * After an approval: wait for the node's link, push the passkey list, and
 * put the outcome on its row (ADR 0019 phase 3, §3.6).
 *
 * Both acts exist already and neither changes. What this adds is WHEN they
 * run and what they wait on, and the one thing it waits on is this hub's own
 * observation: `status(label).held` is true only when the link is up AND its
 * loopback listeners are bound, which is exactly the condition a trust push
 * over the link needs.
 *
 * NOTHING here is decided by the node's `pair_done`. A node that lies in
 * that frame buys itself a timeout and a row reading `link` with `never
 * held`, which is the observed-versus-kept distinction the Settings row was
 * built to show.
 *
 * A timeout is not a failure of the pairing: the row is written, the node is
 * registered, and the page says so.
 */
async function runPairingFollowOn(input: {
  pairingId: string; label: string; advisor: boolean; grant: BrokerPushGrant;
  armKeyNote?: string | null;
}): Promise<void> {
  const { pairingId, label, advisor, grant } = input;
  const deadline = Date.now() + PAIR_FOLLOWON_MAX_MS;
  let held = false;
  while (Date.now() < deadline) {
    if (fleetLinkHub?.status(label)?.held) { held = true; break; }
    await new Promise((r) => setTimeout(r, PAIR_FOLLOWON_POLL_MS));
  }
  let pushed: 'ok' | 'failed' | 'skipped' = 'skipped';
  let pushDetail = '';
  if (held) {
    try {
      const result = await runFleetTrustPush(label);
      pushed = result.ok ? 'ok' : 'failed';
      // This node's own failed line, never the summary that ends the output:
      // that one points at lines above it, and this sentence has none above
      // it to point at (#1184). The helper is the one the Settings route uses.
      if (!result.ok) pushDetail = pushFailedLine(result.output, label, new Set([label]));
    } catch (err) {
      pushed = 'failed';
      pushDetail = (err as Error).message;
    }
  }
  // The fleet's model setting, and whether this node's Advisor is on it.
  const fleetModel = readFleetModelRecord(FLEET_MODEL_PATH, () => {});
  const needsModel = Boolean(advisor && fleetModel);
  // THE INHERIT (ADR 0019 phase 4, #168). The node armed itself, as root, at
  // the end of its own pairing, and this aggregator's push lands well inside
  // that window: the wait above is bounded at ninety seconds and the window
  // is fifteen minutes.
  //
  // Nothing here fails the pairing. The node is registered, its link is up,
  // and the row says what is left to do. That is the whole design of this
  // step: a model that did not land is a sentence, not a rollback.
  const model = await inheritPairedFleetModel(label, advisor, grant);
  const note = pairFollowOnNote({
    held, pushed, pushDetail, needsModel,
    model: model.state, modelDetail: model.detail,
    armInstalled: fleetArmInstalled(),
  });
  // #743 review, L2: a lost-and-remade arm key leads the row, because it is
  // about every OTHER node on the fleet and outranks anything about this one.
  if (input.armKeyNote) {
    note.text = `${input.armKeyNote} ${note.text}`;
    console.warn(`[fleet-link] pairing "${label}": ${input.armKeyNote}`);
  }
  fleetLinkHub?.annotate(pairingId, note.text, note.next);
  console.log(`[fleet-link] pairing "${label}": ${note.text}`
    + (note.next ? ` ${note.next.sentence} (${note.next.command})` : ''));
  recordAuthEvent({
    actor: 'fleet-pairing', actorRole: 'aggregator', event: 'fleet_pairing',
    target: label,
    detail: {
      act: 'follow_up', held, trust_push: pushed, needs_model: needsModel,
      model: model.state, ...(model.reason ? { model_reason: model.reason } : {}),
    },
  });
}

/**
 * Hand a freshly paired node the fleet's sealed model, if there is one. The
 * decision is lib/fleet-broker.ts's, shared with an Advisor's attach (#1037);
 * this supplies the two broker calls, each waiting its turn on the socket.
 */
function inheritPairedFleetModel(
  label: string, advisor: boolean, grant: BrokerPushGrant,
): Promise<InheritOutcome> {
  return inheritFleetModel(label, advisor, grant, {
    storeHead: readFleetModelStoreHead, push: pushFleetModelTo,
  });
}

// ── The node's agent ──────────────────────────────────────────────────
// The dashboard's one slot for the node-side agent and the fingerprint of the
// config it was built from. reconcileLinkAgent (lib/fleet-link-agent.ts) owns
// the start/stop/leave decision and the churn guard; this file owns building
// the agent, whose dial, ledger and identity are all dashboard state.
const fleetLinkSlot: LinkAgentSlot = { agent: null, fp: null };

// Build (but do not start) the node-side agent for a validated config.
function buildFleetLinkAgent(config: LinkConfig): FleetLinkAgent {
  const ledger = createRefusalLedger({
    write: (row) => {
      try {
        recordAuthEvent({
          actor: `fleet-link:${config.label}`,
          actorRole: 'aggregator',
          event: 'fleet_link_refused',
          target: row.route,
          detail: {
            code: row.code, count: row.count,
            first_at_ms: row.first_at_ms, last_at_ms: row.last_at_ms,
            // Sanitised and capped by the agent before it got here (#286),
            // and stored as JSON strings rather than concatenated into a
            // message: an operator whose aggregator has been compromised has
            // to be able to tell a probe from a version skew.
            paths: row.paths,
          },
        });
      } catch (err) {
        console.warn(`[fleet-link] the audit row could not be written: ${(err as Error).message}`);
      }
    },
  });
  return createFleetLinkAgent({
    config,
    origins: {
      dashboard: `http://127.0.0.1:${PORT}`,
      // The Advisor's own origin, only when it is loopback. A remote
      // ADVISOR_URL is not something this link will dial for a stranger.
      advisor: isLoopbackHost(new URL(ADVISOR_URL).hostname) ? ADVISOR_URL.replace(/\/+$/, '') : null,
    },
    aggregatorKey: () => readPeerPubKey(FLEET_TRUST_PATH, FLEET_WRITE_ISSUER_LABEL),
    // A trust file this account is refused is not the same finding as a trust
    // file with no key in it (#1183). EACCES only: a missing file is the
    // ordinary state of a node that never joined a fleet.
    pinUnreadable: () => {
      try { accessSync(FLEET_TRUST_PATH, fsConstants.R_OK); return false; }
      catch (err) { return (err as NodeJS.ErrnoException).code === 'EACCES'; }
    },
    tombstone: createTombstoneFileStore(FLEET_LINK_TOMBSTONE_PATH),
    identity: () => {
      const info = (snapshot.server_info ?? {}) as AnyObj;
      return {
        pubkey_node: typeof info.pubkey_node === 'string' && info.pubkey_node ? info.pubkey_node : null,
        dashboard_version: describeIdentity(identityForWire(releaseReader.current())),
      };
    },
    // handshakeTimeout, because a far end that accepts TCP and never
    // completes the upgrade would otherwise leave the agent in `dialing`
    // with a half-open socket, no retry and no state change, until the OS
    // gave up (#280). Twice the hub's own hello timeout: long enough that a
    // slow link is not mistaken for a dead one, short enough that a black
    // hole is a retry rather than a hang.
    dial: (url, headers) => new WebSocket(url, {
      headers,
      handshakeTimeout: FLEET_LINK_HELLO_TIMEOUT_MS * 2,
      // Set rather than left to ws's 100 MiB default: this end is talking to
      // the party ADR 0019 decision 4 says may be the compromised one, and a
      // frame it accepts is memory it has already spent.
      maxPayload: FLEET_LINK_MAX_FRAME_BYTES,
    }) as unknown as LinkSocket,
    ledger,
  });
}

// Bring the agent in line with config/fleet-link.json as it is on disk right
// now. Called at startup and on SIGHUP. The SIGHUP call is what makes pairing
// take effect without a restart (#316): the pair command writes the file and
// runs `systemctl reload`, and before this reconcile that reload re-read only
// the aggregator-side registry, so a freshly paired node held no link until it
// was restarted by hand.
function reconcileFleetLinkAgent(trigger: 'startup' | 'reload'): void {
  reconcileLinkAgent(fleetLinkSlot, {
    load: () => loadLinkConfig(FLEET_LINK_CONFIG_PATH),
    make: buildFleetLinkAgent,
    trigger,
    log: (m) => console.log(`[fleet-link] ${m}`),
    warn: (m) => console.warn(`[fleet-link] ${m}`),
  });
}

// ─── Advisor presence, ADR 0016 ───────────────────────────────────────
//
// One observed fact: does this host have an Advisor? The Advisor is an
// invited add-on, and a dashboard installed without one used to render a
// permanent "the Advisor service is not answering" (a fact it had never
// observed, painted as current).
//
// The ordering below is the decision, not an optimisation. The token check
// gates the HTTP call, so on a host with no Advisor this timer is one stat()
// every 20 seconds and ZERO network calls. That is what makes "a declined
// Advisor makes no Advisor-shaped request" true server-side as well as in the
// browser, and it is asserted with a counting probe in the unit test rather
// than described here.
const ADVISOR_PRESENCE_POLL_MS = 20_000;
// The operator's number, ratified 2026-08-29, overridable per host. A bad
// value falls back rather than producing a window of NaN, which would make
// every comparison false and pin the state at installed-but-down forever.
const ADVISOR_FORGET_AFTER_MS = (() => {
  const raw = process.env.APERIRE_ADVISOR_FORGET_AFTER_H;
  if (!raw) return DEFAULT_FORGET_AFTER_MS;
  const hours = Number(raw);
  if (!Number.isFinite(hours) || hours <= 0) {
    console.warn(`[advisor-presence] ignoring APERIRE_ADVISOR_FORGET_AFTER_H="${raw}", not a positive number`);
    return DEFAULT_FORGET_AFTER_MS;
  }
  return hours * 3600_000;
})();

// Last observation, served by the route. The route reads this rather than
// probing per request: a browser poll must not be able to drive the outbound
// call rate, and the fact changes on the probe's cadence, not the reader's.
let advisorPresenceSelf: AdvisorPresenceResult = { state: 'absent', detail: '' };

// Where systemd listens for a seal. Overridable so the walk can drive a stub
// on a temporary path; the constant is what every real host uses.
const SEAL_SOCKET_PATH = process.env.APERIRE_SEAL_SOCKET || SEALER_SOCKET;

/** Hand a payload to the model-key sealer over the one socket this account may
 *  open, and wait for what it says.
 *
 *  No child process, and no sudo: this unit sets NoNewPrivileges and an empty
 *  capability bounding set, and nothing spawned under those can gain a
 *  privilege. The privileged side is already running, and what crosses to it
 *  is five lines on a connection. The key is one of them; it is never an
 *  argument, because arguments are world-readable in /proc for as long as a
 *  process runs, and never in the environment, which is inherited by every
 *  child.
 *
 *  Resolves on a refusal rather than rejecting: that is an outcome the
 *  operator needs the words of. It rejects only when the socket could not be
 *  opened at all, which the caller renders as a host that cannot seal. */
const runSealer: SealRunner = (payload) =>
  // Its own work has a bound: it restarts the Advisor and waits up to ten
  // seconds for it, on top of a drain that can take a minute. The unit behind
  // the socket carries the same bound, so this is the second of two.
  askSocketProgram(SEAL_SOCKET_PATH, payload, 180_000, 'the sealer');
let advisorModelConfigured: boolean | null = null;
// The other half of the pair (#516): whether the credential behind that
// model can be read on this host, and the model's own name, both from the
// same cycle that set advisorModelConfigured. Together they are what tells
// the Advisor tab "no model chosen" apart from "chosen, no key here".
let advisorCredentialPresent: boolean | null = null;
let advisorModelName = '';
// This host's own Advisor build ref (#641), same cycle, same non-memory
// rule: /v1/status's own `version` field, read back only from a probe that
// answered THIS cycle, never remembered across one that did not. Served by
// GET /fleet/v1/advisor/state and POST /fleet/v1/advisor/reveal's response,
// both below.
let advisorVersion: string | null = null;

/**
 * This host's own advisord /v1/status, for the Settings overview's self row.
 *
 * One fetch, and only when the overview is actually assembled (which its own
 * five-second cache bounds). Deliberately NOT the presence probe's cached
 * observation: the page needs the model and trust BLOCKS, which that probe
 * reads one boolean out of and throws away. Null on anything short of a
 * readable 200, which the page renders as "this node's Advisor did not
 * answer" rather than as an absent model.
 */
async function fetchSelfAdvisorStatus(): Promise<{ version?: string; model?: unknown; trust?: unknown; store?: unknown } | null> {
  const token = advisorApproveToken();
  if (!token) return null;
  try {
    const r = await fetch(`${ADVISOR_URL}/v1/status`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5_000),
    });
    const text = await r.text();
    if (!r.ok) return null;
    return JSON.parse(text) as { version?: string; model?: unknown; trust?: unknown; store?: unknown };
  } catch { return null; }
}

/**
 * The trust push the Settings page runs, which is the command an operator
 * runs: `scripts/aperire-auth.sh fleet-trust-push [--node <label>]`, the same
 * one lib/trust-push-hook.ts spawns after an enrollment.
 *
 * Spawned rather than reimplemented for the reason that hook already states:
 * one implementation of build, sign and push, already covered by
 * scripts/test-fleet-trust-perms.sh, with the private key nowhere in this
 * process's heap for this path. Never rejects on a non-zero exit, because a
 * non-zero exit is the answer.
 */
function runFleetTrustPush(label: string | null): Promise<{ ok: boolean; output: string }> {
  const repoDir = resolve(import.meta.dirname, '..');
  const args = [join(repoDir, 'scripts', 'aperire-auth.sh'), 'fleet-trust-push'];
  if (label) args.push('--node', label);
  return new Promise((done) => {
    execFile('bash', args, {
      cwd: repoDir,
      // The CLI resolves its own repository from its path; the one thing it
      // must be told is which database, or it would push the admin set of a
      // different install on a host running two.
      env: { ...process.env, APERIRE_DB_PATH: DB_PATH },
      timeout: 60_000,
      maxBuffer: 1 << 20,
    }, (err, stdout, stderr) => {
      done({ ok: !err, output: `${stdout ?? ''}${stderr ?? ''}` });
    });
  });
}

// ─── The Settings page's seal jobs ───────────────────────────────────────
//
// One passkey on this dashboard changes the Advisor's model key on every
// node the operator picked. The work runs behind a job id because a node's
// sealer restarts that node's Advisor and waits for it, and thirty of those
// is not a request to hold a page open for.
//
// Constructed once, at startup, and given readers rather than values: the
// fleet registry reloads on SIGHUP, and a job runner holding a snapshot of
// it would seal against a fleet that no longer exists.
// ─── The root broker, one call at a time ─────────────────────────────────
//
// Every broker call in this process goes through here. The socket is
// `Accept=yes` with `MaxConnections=1`, which is what stops two model pushes
// racing the root-owned node record, and systemd does not queue past it: it
// accepts the second connection and drops it, so an overlapping caller reads
// an empty stream and every parser in lib/fleet-broker.ts calls that
// indeterminate. A push holds the socket for minutes.
//
// This does not make the socket safe against another process on the host. It
// makes THIS process stop competing with itself, which is where all four
// callers live: a pairing approval, the pairing follow-on, a Settings
// catch-up and the overview's store head.
const askFleetBroker = serializeBrokerCalls(
  (payload: string, timeoutMs: number) =>
    askSocketProgram(FLEET_BROKER_SOCKET, payload, timeoutMs, 'the fleet broker'),
);

/** One broker answer, split apart. The socket layer has already read the
 *  exit code off the stream and consumed its line, so it is passed through
 *  rather than looked for again (#311). */
async function askBrokerAnswer(payload: string, timeoutMs: number): Promise<BrokerAnswer> {
  const answer = await askFleetBroker(payload, timeoutMs);
  return brokerAnswerOf(answer);
}

/** What the root store holds, minus the key. Never throws: every way of not
 *  getting an answer is a state, and none of them is "there is no store". */
async function readFleetModelStoreHead(): Promise<BrokerStoreHeadOutcome> {
  try {
    return brokerStoreHeadOutcome(await askBrokerAnswer(
      brokerModelStoreHeadPayload(), FLEET_BROKER_TIMEOUT_MS,
    ), INSTALL_ROOT);
  } catch (err) {
    // A socket that is not there at all. Said as "could not read", never as
    // "there is none": the page's sentence for the second one tells an
    // operator to seal the fleet model again with the key in their hand.
    return {
      state: 'unread', reason: 'no_socket',
      detail: `this host could not reach its fleet broker (${(err as Error).name}).`,
    };
  }
}

/** Send the sealed fleet model to one node. The push's own bound, not the
 *  approval's: the far node's sealer can take minutes. */
async function pushFleetModelTo(label: string, grant: BrokerPushGrant): Promise<BrokerPushOutcome> {
  return brokerPushOutcome(await askBrokerAnswer(
    brokerModelPushPayload(label, grant), FLEET_BROKER_PUSH_TIMEOUT_MS,
  ));
}

/**
 * Seal the fleet's model descriptor at rest, once per fleet seal.
 *
 * Fire and forget from the job, which is why this owns its own catch: the
 * seal has already done what the operator asked for, and a store that was not
 * written costs the catch-up for a node that was down, not the change.
 *
 * The key reaches this function and leaves it on the socket. It is never
 * logged, never in an audit detail, and the audit row below records that a
 * store was written and what is in it apart from the secret.
 */
/** What this host's last attempt to seal the fleet model at rest reported.
 *  Null until one has been made in this process, which is not a failure and
 *  prints nothing. Never carries the key, and never the argument that did. */
let lastFleetModelStoreWrite: StoreWriteNote | null = null;

function storeFleetModelOnHost(d: FleetModelDescriptor, actor: string): void {
  void (async (): Promise<void> => {
    let outcome;
    try {
      outcome = brokerStoreOutcome(await askBrokerAnswer(
        brokerModelStorePutPayload({
          baseUrl: d.baseUrl,
          shape: d.shape,
          model: d.model,
          credentialName: d.credentialName,
          keyHint: d.keyHint,
          sealedBy: d.sealedBy,
          key: d.key,
        }),
        FLEET_BROKER_TIMEOUT_MS,
      ), INSTALL_ROOT);
    } catch (err) {
      // The CLASS only. This call's payload is the key, and an error that
      // carries the request it failed on is how one ends up in a log.
      console.warn(`[fleet-model] the fleet model was not sealed at rest (${(err as Error).name})`);
      outcome = { ok: false as const, error: 'no_broker', detail: 'the fleet broker could not be reached.' };
    }
    if (outcome.ok) {
      console.log(`[fleet-model] sealed at rest on this host at ${outcome.sealed_at}`);
    } else {
      console.warn(`[fleet-model] not sealed at rest: ${outcome.error}`);
    }
    // And on the PAGE, not only in this log (#443). A seal whose per-node
    // rows all read `sealed` and whose store write failed is the case the
    // sealed copy exists to close: the next node to pair inherits nothing.
    lastFleetModelStoreWrite = outcome.ok
      ? { ok: true, at: Date.now() }
      : { ok: false, at: Date.now(), error: outcome.error, detail: outcome.detail };
    // On the record either way. An operator asking why a node paired last
    // week joined with no model needs to find the answer here rather than in
    // a journal on the aggregator.
    recordAuthEvent({
      // The operator who approved the seal this store write belongs to. No
      // role: this call is made by the job, minutes after the ceremony, and
      // the role it would state would be one nothing here observed. The seal's
      // own row, written at the moment of the approval, carries it.
      actor, actorRole: null, event: 'model_key_sealed', target: d.credentialName,
      detail: {
        outcome: outcome.ok ? 'stored' : 'store_failed',
        act: 'fleet_model_store',
        model: d.model,
        base_url: d.baseUrl,
        ...(outcome.ok ? { sealed_at: outcome.sealed_at } : { error: outcome.error }),
      },
    });
  })();
}

const fleetSealJobs = new FleetSealJobs({
  runSealer,
  readBack: () => readBackAdvisorModel(),
  peerByLabel: (label) => resolvePeerByLabel(fleetPeerNodes, label) ?? null,
  signingSeed: () => readOwnPrivateKey(FLEET_TRUST_PATH),
  log: (line) => console.log(line),
  // The digest and hint of the key the fleet holds now, so a seal of the same
  // key is not told to revoke it (#1114).
  heldKey: () => {
    const r = readFleetModelRecord(FLEET_MODEL_PATH, () => {});
    return r ? { digest: r.key_digest ?? '', hint: r.key_hint } : null;
  },
  // One line per node on THIS dashboard's record, as each settles. The node
  // writes its own line too, and that one is authoritative because the host
  // that sealed wrote it; this one is what answers "what did I change, and
  // which nodes took it" on the dashboard the operator actually used.
  // The fleet's setting, written when the job finishes and at least one node
  // took it. A run that changed one node of three still changed the fleet's
  // setting; the other two are behind, which is what the record is for.
  recordFleetModel: (record) => {
    try {
      writeFleetModelRecord(FLEET_MODEL_PATH, record);
      console.log(`[fleet-model] recorded ${record.provider} ${record.model} across ${record.targets.length} node(s)`);
    } catch (err) {
      console.warn(`[fleet-model] could not write ${FLEET_MODEL_PATH}: ${(err as Error).message}`);
    }
  },
  // And the other half of the same ruling: the root store, which is what a
  // node paired next week inherits with nothing pasted (#168). The record is
  // what the page renders; this is what a later push sends.
  storeFleetModel: (d) => storeFleetModelOnHost(d, d.sealedBy),
  // The overview the page reads next must be assembled after the seal, not
  // served from the five seconds before it.
  onJobDone: () => clearSettingsOverviewCache(),
  recordOutcome: (params, target) => recordAuthEvent({
    actor: params.grantedBy,
    actorRole: params.grantedRole,
    event: 'model_key_sealed',
    target: `${target.label}:${params.credentialName}`,
    detail: {
      outcome: target.state,
      reason: target.reason ?? null,
      model: params.model,
      base_url: params.baseUrl,
      node: target.label,
      ...(target.model_configured === undefined ? {} : { model_configured: target.model_configured }),
    },
  }),
});

/**
 * Fleet updates: one node's own updater, driven from here (#275).
 *
 * Beside the seal jobs and deliberately NOT part of them. A seal carries a
 * secret on one loopback hop and spends a root arming window; an update
 * carries a tag and starts a root program that replaces a node's code. The
 * two want different concurrency, different timeouts and different words,
 * and sharing the runner would mean one edit could change both.
 */
/** The shape a fleet label may have, the same alphabet settings-api.ts
 *  admits. A label from a browser is a LOOKUP KEY and nothing more: it is
 *  checked for shape, resolved against the registry, and never joined into a
 *  path, a command or a URL. */
const FLEET_LABEL_RE = /^[a-z0-9-]{1,32}$/;

const fleetUpdateJobs = new FleetUpdateJobs({
  peerByLabel: (label) => resolvePeerByLabel(fleetPeerNodes, label) ?? null,
  signingSeed: () => readOwnPrivateKey(FLEET_TRUST_PATH),
  log: (line) => console.log(line),
  // One line per node on THIS dashboard's record. The node writes its own
  // line too, and that one is authoritative because the host whose code
  // changed wrote it; this one answers "what did I update, and which nodes
  // took it" on the dashboard the operator actually used, including for a
  // node that was unreachable that day and has no line anywhere else.
  recordOutcome: (params, target) => recordAuthEvent({
    actor: params.grantedBy,
    actorRole: params.grantedRole,
    event: 'update_run',
    target: `${target.label}:${params.release?.tag ?? params.action}`,
    detail: {
      action: params.action,
      outcome: target.state,
      reason: target.reason ?? null,
      node: target.label,
      via: 'fleet',
      ...(params.release ? { tag: params.release.tag, commit: params.release.commit } : {}),
      ...(target.run_id ? { run_id: target.run_id } : {}),
    },
  }),
});

// ── What each node holds, on this aggregator's record (#331) ──────────
//
// Four things make a node one this fleet can act on: the update grant, a
// release stamp, an update endpoint, and this aggregator's key pinned on
// that box. Before this the Updates table found out by offering an Apply and
// having it refused, or by grading a stamp-less node `unknown` and leaving
// its action cell blank. Now it asks each node once, when the operator
// presses Check now, and prints what the node said.
//
// Held per label with the moment it was taken, so re-opening the panel (a
// non-live read, which makes no outbound call at all) still shows what was
// last observed rather than going blank. Dropped past the keep window rather
// than shown old: an answer nobody has confirmed in a quarter of an hour is
// one this page stops repeating, and the row falls back to claiming nothing.
//
// Nothing here can reach a Release or a Status cell. Those come from the
// fleet poller re-reading each node's own stamp, which is the one thing that
// can turn a row green.
const fleetCompleteness = new Map<string, NodeCompleteness>();
const COMPLETENESS_KEEP_MS = 15 * 60_000;

/** The peers worth asking. A row this dashboard cannot address, cannot
 *  identify, or that would not let it read at all already has its own
 *  sentence and gets no control at any width, so asking it would be a round
 *  trip for a fact nobody renders. */
function completenessTargets(nodes: FleetPeerPublic[]): FleetNodeConfig[] {
  const out: FleetNodeConfig[] = [];
  for (const n of nodes) {
    if (n.self) continue;
    if (n.aperire_release_state === 'not_verified') continue;
    if (n.verdict === 'refused') continue;
    const peer = resolvePeerByLabel(fleetPeerNodes, n.label);
    if (peer?.expected_pubkey_node) out.push(peer);
  }
  return out;
}

/** That node's last answer, or undefined when there is none worth repeating. */
function completenessFor(label: string, nowMs: number): NodeCompleteness | undefined {
  const got = fleetCompleteness.get(label);
  if (!got) return undefined;
  if (nowMs - got.read_at > COMPLETENESS_KEEP_MS) {
    fleetCompleteness.delete(label);
    return undefined;
  }
  return got;
}

// The Advisor's service unit, the one file an uninstall removes and a
// permissions accident does not. Read, never managed: this unit cannot run
// systemctl, and does not need to. /etc is readable under ProtectSystem=strict.
// Overridable so a walk can stage a host with or without one.
const ADVISOR_UNIT_PATH = advisorUnitPath(process.env);
/** #812: is the fleet broker grant's arm program here? The page prints
 *  `sudo aperire-fleet-arm` only when it is, and otherwise the update first. */
function fleetArmInstalled(): boolean { return rootProgramInstalled(FLEET_ARM_PROGRAM); }
/** Is the fleet broker itself here? Without it the update has no arm program
 *  to place, and the page says so rather than sending an operator to it. */
function fleetBrokerInstalled(): boolean { return rootProgramInstalled(FLEET_BROKER_PROGRAM); }

function advisorUnitInstalled(): boolean | null {
  // Only Linux hosts have a unit to look for. Anywhere else the question has
  // no answer, and `null` leaves the memory in charge.
  if (process.platform !== 'linux') return null;
  try { statSync(ADVISOR_UNIT_PATH); return true; } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ENOENT' ? false : null;
  }
}

async function probeAdvisorPresence(): Promise<void> {
  try {
    const obs = await observeAdvisorPresence({
      // The installed signal and, because /v1/status sits behind advisord's
      // own token check, the probe's credential too. There is no probe to
      // make without it, so the ADR's ordering is also the only one that
      // works.
      readToken: advisorApproveToken,
      probeStatus: async (token) => {
        try {
          const r = await fetch(`${ADVISOR_URL}/v1/status`, {
            headers: { authorization: `Bearer ${token}` },
            signal: AbortSignal.timeout(5_000),
          });
          // The body has to be drained anyway: an unread response body holds
          // the socket open, and this runs every 20 seconds forever. So the
          // model fact is read out of bytes we were going to throw away,
          // rather than bought with a second request for the same document.
          const body = await r.text();
          if (!r.ok) return { answered: false, modelConfigured: null };
          let modelConfigured: boolean | null = null;
          let credentialPresent: boolean | null = null;
          let modelName = '';
          let version: string | null = null;
          try {
            const j = JSON.parse(body) as {
              model?: { configured?: unknown; credential_present?: unknown; name?: unknown };
              version?: unknown;
            };
            // Only a real boolean counts. A body that does not carry the field
            // is an Advisor that predates it, which is not the same as one
            // reporting no model.
            if (typeof j?.model?.configured === 'boolean') modelConfigured = j.model.configured;
            // Same rule for the other half of the pair (#516): absent means
            // this Advisor predates the field, not that the credential is
            // known to be missing.
            if (typeof j?.model?.credential_present === 'boolean') credentialPresent = j.model.credential_present;
            if (typeof j?.model?.name === 'string') modelName = j.model.name;
            // #641: the build ref advisord's own main.go already stamps into
            // /v1/status ("dev" on an unstamped build). This is the one line
            // that had never read it before this route needed to serve it.
            if (typeof j?.version === 'string' && j.version) version = j.version;
          } catch { /* answered, but said nothing readable about a model */ }
          return { answered: true, modelConfigured, credentialPresent, modelName, version };
        } catch { return { answered: false, modelConfigured: null }; }
      },
      lastAnsweredMs: lastAdvisorAnsweredMs(),
      unitInstalled: advisorUnitInstalled,
      nowMs: Date.now(),
      forgetAfterMs: ADVISOR_FORGET_AFTER_MS,
    });
    // Persisted on an answer and on nothing else. A failed probe must never
    // advance the memory. That is the kept-vs-observed shape.
    if (obs.answered === true) recordAdvisorAnswered(Date.now());
    const presenceBefore = advisorPresenceSelf.state;
    if (obs.state !== presenceBefore) {
      console.log(`[advisor-presence] ${presenceBefore} -> ${obs.state}${obs.detail ? `: ${obs.detail}` : ''}`);
    }
    advisorPresenceSelf = { state: obs.state, detail: obs.detail };
    // #1245. The store was walked once at start, before this first probe had
    // answered, and with no Advisor known to be there the question to it was
    // skipped. Waiting for the next minute's tick would leave the card saying
    // "unreadable" for up to a minute after every start of a dashboard whose
    // Advisor is running, and a gap in the series for the same minute. So the
    // Advisor is asked the moment it is first seen, when the walk had failed.
    if (obs.state === 'present' && presenceBefore !== 'present' && RIPPLED_DATA_PATH && lastNudbWalkError !== null) {
      void askAdvisorForStore();
    }
    // Not remembered across cycles, unlike the state. `present` can be reached
    // from a remembered answer with no fresh body, and a stale "it has no
    // model" would put a key field in front of an operator on the strength of
    // a reading nobody took this cycle.
    advisorModelConfigured = obs.modelConfigured;
    advisorCredentialPresent = obs.credentialPresent;
    advisorModelName = obs.modelName;
    // Run through the SAME sanitizer relay_version and componentsNow already
    // use for this exact fact: `dev` (an advisord build the current release
    // never stamped) and anything not shaped like a commit collapse to "not
    // measured" here too, rather than this route inventing a fourth reading
    // of what an unstamped build ref means.
    advisorVersion = sanitizeComponents({ advisord: obs.version ?? '' }).advisord ?? null;
  } catch (e) {
    // Keep the last-known state rather than blanking it. One failed cycle is
    // not evidence that an Advisor was uninstalled.
    console.warn(`[advisor-presence] probe cycle failed: ${(e as Error).message}`);
  }
}
void probeAdvisorPresence();
setInterval(() => { void probeAdvisorPresence(); }, ADVISOR_PRESENCE_POLL_MS).unref();
// What a request is told about this host's Advisor (#995): the cached probe,
// except that a unit which has gone since the last cycle is not left standing
// for the rest of the interval. See createPresenceReader.
const readAdvisorPresence = createPresenceReader({
  current: () => advisorPresenceSelf,
  unitInstalled: advisorUnitInstalled,
  reprobe: probeAdvisorPresence,
  nowMs: () => Date.now(),
});

// #550. What THIS node's own Advisor believes is newest and installable:
// read from the same registry check it would use to build an upgrade plan.
// Never the dashboard's own release-feed poll (releaseInfo, below), which
// only knows a tag EXISTS and was fooled by exactly this: a vendor image
// briefly tagged with a version its binary did not report. Kept apart from
// releaseInfo on purpose. releaseInfo is fleet-wide knowledge, served to any
// browser looking at any node this dashboard can see; this fact is about
// ONE node, this one, and folding it in unnamed would label a peer's chip
// with this host's own reading (the ADR 0014 mislabel class advisor.html's
// own loadRelease comment already names). /release-info names it
// self_installable for the same reason: a caller must be able to tell "this
// dashboard's own node" from "the fleet" without reading this comment.
let selfAdvisorInstallable: { version: string; source: string; checked_at: number } | null = null;
const SELF_ADVISOR_INSTALLABLE_POLL_MS = 5 * 60_000;
async function pollSelfAdvisorInstallable(): Promise<void> {
  // Absence IS the fact here: no Advisor to ask. Every other branch below is
  // a poll that did not land, which is different. This is kept-vs-observed, the
  // same rule probeAdvisorPresence follows just above: one bad cycle must
  // not erase a good reading, or a single timeout would flip a real 'gap'
  // back to whatever the no-Advisor fallback renders, including the exact
  // stale chip this issue is about.
  if (advisorPresenceSelf.state !== 'present') { selfAdvisorInstallable = null; return; }
  const tok = advisorApproveToken();
  if (!tok) return;
  try {
    const r = await fetch(`${ADVISOR_URL}/v1/check?runbook=upgrade-xrpld`, {
      headers: { authorization: `Bearer ${tok}` },
      signal: AbortSignal.timeout(8_000),
    });
    if (!r.ok) return;
    const body = await r.json() as AnyObj;
    const fact = parseAdvisorCheckInstallable(body);
    if (fact) selfAdvisorInstallable = fact;
  } catch {
    // The read failed. Keep the last-known reading rather than erase it.
  }
}
void pollSelfAdvisorInstallable();
setInterval(() => { void pollSelfAdvisorInstallable(); }, SELF_ADVISOR_INSTALLABLE_POLL_MS).unref();

// #550's peer half. What a PEER's own Advisor believes is newest and
// installable, read opportunistically off the SAME check the Advisor tab's
// Operations card already fetches through the proxy for that peer. Never a
// second poll loop hitting nodes nobody is looking at. Keyed by label, so a
// fleet of any size costs nothing extra: an entry exists only for a peer an
// operator has actually opened.
type PeerInstallableEntry =
  | { state: 'present'; fact: { version: string; source: string; checked_at: number } }
  | { state: 'absent' };
const peerAdvisorInstallable = new Map<string, PeerInstallableEntry>();

/**
 * Updates the cache from a check-endpoint result the proxy already fetched
 * for some other reason (the Operations card). Never fetches on its own
 * account, and never called for any endpoint but `check`. /v1/plan and the
 * others do not carry target/target_source at all. Mirrors
 * pollSelfAdvisorInstallable's own discipline (both now share
 * parseAdvisorCheckInstallable): absence of an Advisor is a definite fact
 * (state 'absent'), and a failed or unparseable read leaves whatever this
 * cache already held exactly as it was, a transient hiccup must never
 * erase a real reading.
 */
function notePeerAdvisorInstallable(label: string, endpoint: string, result: PeerAdvisorResult): void {
  if (endpoint !== 'check') return;
  if (!result.ok) {
    if (result.error === 'advisor_not_configured') peerAdvisorInstallable.set(label, { state: 'absent' });
    return;
  }
  const fact = parseAdvisorCheckInstallable(result.body as AnyObj);
  if (fact) peerAdvisorInstallable.set(label, { state: 'present', fact });
}

/** The seal handler's read-back: one presence cycle, now, and the model fact
 *  it carried. Going through the same probe rather than a second fetch keeps
 *  the published fact and the sealer's answer from disagreeing: the page's
 *  next poll sees exactly what the seal response said. */
async function readBackAdvisorModel(): Promise<boolean | null> {
  await probeAdvisorPresence();
  return advisorModelConfigured;
}

/** This node's own row, computed from state the dashboard already has, the
 *  node's own reachability and its own firing alerts, never a self-poll.
 *  The three canaries (S/H/A) go through the exact same
 *  deriveStateVerdict/deriveHealthVerdict/deriveAlertsVerdict a peer's
 *  badges are built from, and the dot is their rollup. Never a second copy
 *  of "not fully synced", and never a copy of one badge standing in for the
 *  other two (#505). Before #505 this row never looked at server_state at
 *  all, so a node mid-resync (connected, complete_ledgers empty) read
 *  healthy on its own Overview while every other box's fleet view called it
 *  warn. */
function selfFleetPeer(node: FleetNodeConfig): FleetPeerPublic {
  const reach = nodeReachState();
  // R's inputs for this row come from the same two places the rest of the
  // dashboard already reads them: server_info for the running build (the same
  // field rejudgeRelease judges the update pill against) and for
  // amendment_blocked (the same Boolean() the governance payload builds), and
  // the release poll's own cached upstream numbers for what is newest. A peer
  // reads the equivalent two over its read API; this node just has them to
  // hand, which is the whole reason it is never polled through the loopback.
  // server_state comes from the same server_info, gated on reach.ok for the
  // same reason: a snapshot left over from before the node went down is not a
  // fact about now, and "I could not read my own state" must never render as
  // "fully synced".
  const info = snapshot.server_info as AnyObj | undefined;
  const running = typeof info?.build_version === 'string' ? info.build_version : null;
  const serverState = reach.ok && typeof info?.server_state === 'string' ? info.server_state : null;
  const firing = queryFiringState();
  // S guards one gap a peer never has: "reachable, but I have never actually
  // read my own server_state", the cold-start case, before the first
  // server_info poll has landed. `serverInfoAtMs` (set only on a successful
  // poll) is what tells that apart from an ordinary "couldn't check" (see
  // deriveSelfStateVerdict).
  const stateV = deriveSelfStateVerdict({ reachable: reach.ok, serverState, everObserved: serverInfoAtMs !== null });
  const healthV = deriveHealthVerdict({ reachable: reach.ok, sampleAgeMs: 0, staleAfterMs: Number.MAX_SAFE_INTEGER });
  const alertsV = deriveAlertsVerdict({ reachable: reach.ok, firing });
  // The dot is the worst of the three. R's escalation is folded in by
  // buildSelfPeer below, exactly as a peer's release gate is.
  const dot = rollupVerdict(stateV, healthV, alertsV);
  // The registry's pin for THIS host against the key this node reports (#488).
  // Gated on `reach.ok` for the same reason amendmentBlocked below is: a
  // snapshot left over from before the node went down is not a fact about now,
  // and "I could not read my own key" must never render as "the registry is
  // wrong". Read out of the snapshot, the same value /read/v1/identity serves,
  // so the pin this dashboard reports about itself and the one a peer reads
  // off it are the same key.
  const ownPubkeyNode = reach.ok && typeof info?.pubkey_node === 'string' && info.pubkey_node
    ? info.pubkey_node
    : null;
  // The host is the node's (#1284): on a split install that is the machine
  // the relay reports, the same answer node-status gives a peer for its row.
  const row = buildSelfPeer(node, dot.verdict, dot.detail, {
    buildVersion: running,
    latestRelease: latestInstallableRelease(),
    // Only meaningful when this node answered at all, an unreachable rippled
    // reports nothing, and a stale snapshot's last-known flag is not a fact
    // about now.
    amendmentBlocked: reach.ok && info ? Boolean(info.amendment_blocked) : null,
  }, deployRefReader.current(), hostnameForAlerts() || null, identityForWire(releaseReader.current()),
  selfPinFacts(node.expected_pubkey_node, ownPubkeyNode),
  { state: stateV, health: healthV, alerts: alertsV });
  // #1284. `label` stays the registry's: the Inbox, Settings and the Advisor
  // deep links match this host by it. What the pages print is display_name,
  // the one name every surface gives this host.
  row.display_name = selfDisplayLabel(node) || node.label;
  return row;
}

// ─── Fleet deploy divergence, issue #128 rung 2 ───────────────────────────
//
// Detection only. Every host stamps `.deploy-ref` when the fleet update
// rsyncs it, every dashboard serves its own on `/read/v1/node-status`, and
// the aggregator already reads that route for every peer on every poll
// cycle. So the noticing costs one comparison and no new read: if the refs
// on the table disagree, some box did not get rolled. What to do about it
// stays a human's decision (rung 3), and nothing here changes any state.
//
// Written HERE and nowhere else, on this host only when it is the fleet's
// aggregator (isAggregatorSelf: no local node of its own, at least one
// peer). Every node in a fleet computes the same divergence number from the
// same answers, so writing it everywhere would mean one deploy gap and four
// identical emails. The confusion rules.yaml's relay_feed_age_s comment is
// a whole paragraph about. The trade is stated in the rule's comment: a
// fleet with no aggregator sees the per-host `deploy_state` on /api/fleet
// but gets no alert.
const FLEET_DEPLOY_CHECK_MS = 60_000;
function checkFleetDeployDrift(): void {
  const graded = fleetGraded();
  // No fleet registry, or one that could not identify this node. A
  // single-host install produces no metric at all, ever. There is nothing
  // to compare it against, and a 0 would be an agreement nobody observed.
  if (!graded) return;
  const self = graded.nodes.find((n) => n.self) ?? null;
  const peerCount = graded.nodes.filter((n) => !n.self).length;
  if (!isAggregatorSelf(self, peerCount)) return;
  const d = graded.deploy;
  // Nobody reported a ref (a fleet of dashboards all older than the field,
  // or none deployed by the fleet tool). Unknown everywhere is not
  // agreement, so nothing is written rather than a reassuring zero.
  if (!d.comparable) return;
  writeMetric('fleet_deploy_divergent', d.divergent);
  if (lastDeployDivergent !== d.divergent) {
    lastDeployDivergent = d.divergent;
    const off = d.hosts.filter((h) => h.state === 'divergent').map((h) => h.label);
    console.log(
      `[deploy] fleet refs: ${d.shared} on ${d.reference?.slice(0, 10) ?? 'none'}, ` +
      `${d.divergent} elsewhere${off.length ? ` (${off.join(', ')})` : ''}, ${d.unknown} unknown`,
    );
  }
}

const fleetDeployTimer = setInterval(checkFleetDeployDrift, FLEET_DEPLOY_CHECK_MS);
if (typeof fleetDeployTimer.unref === 'function') fleetDeployTimer.unref();

/**
 * `first_seen_ms` for the concern classes that have no store, reachability,
 * integrity, staleness. Owned here, beside the poller, rather than inside it,
 * because those three are not all poller-derived (the self reachability
 * concern is computed from this process's own node reach state) and a map
 * that holds two thirds of the concerns is worse than one that holds all of
 * them. The alert class ignores this entirely and uses
 * `firing_state.triggered_ts`, which is already persistent across a restart.
 *
 * In memory, so it resets on restart, which is exactly what the card says
 * when it reads "first seen 4m ago (since this dashboard started)".
 */
const concernFirstSeen = new Map<string, number>();

/** What this dashboard calls ITSELF, on every surface that renders a self
 *  label. The order is the alert identity's, from one helper (lib/
 *  alert-identity.ts), so a node has one name: the name its aggregator knows
 *  it by (fleet-link.json), then the registry row, an aggregator's own row
 *  first; with neither (a fresh install, which is the ordinary state of a
 *  single-node box) it is the node's host name, short form, the same host the
 *  alerts name (#1240). Never the browser's address: see lib/self-label.ts
 *  for why that was the bug (#145).
 *
 *  '' when the host will not say its own name, which each caller renders as
 *  its own kind of absent rather than being handed an invented one.
 *
 *  Takes the row rather than fetching it. Every caller is somewhere that has
 *  already built the fleet view, and fleetView() is the whole assembly
 *  (selfFleetPeer, every peer graded, the deploy comparison, the sort). A
 *  second call inside a browser-polled handler would do all of it twice per
 *  request, on an endpoint whose own comment says it is built from state that
 *  already exists. */
function selfDisplayLabel(selfRow: { label: string } | null): string {
  return resolveNodeName({
    pairedLabel: fleetLinkSlot.agent?.state().label,
    fleetLabel: selfRow?.label,
    aggregator: selfIsFleetAggregator(),
    host: hostnameForAlerts(),
  });
}

/** null means single-node, no registry, or the registry could not identify
 *  this node. The header renders "this node alone" either way. */
function fleetView(): { nodes: FleetPeerPublic[] } | null {
  const graded = fleetGraded();
  return graded ? { nodes: graded.nodes } : null;
}

/** The fleet as rendered, plus the deploy-ref comparison over the same rows.
 *  Both come out of one assembly so the alert's number and the rows' states
 *  are the same computation, never two that can disagree (#128 rung 2).
 *
 *  `selfLatest` is for the ONE caller that also renders a verdict for this
 *  host beside the table: the Updates card, whose facts grid grades from the
 *  updater's reading of the endpoint rather than from this process's (#293).
 *  It hands that reading in so the self row and the grid say one word
 *  (#365). Every other caller omits it and the self row grades with the rest
 *  of the fleet, which is what /api/fleet and the deploy-drift check want:
 *  neither of them renders a release word at all. */
function fleetGraded(selfLatest?: UpdateLatest | null, fleetReading?: UpdateLatest | null): {
  nodes: FleetPeerPublic[];
  deploy: DeployComparison;
  release: ReturnType<typeof gradeFleetRelease>;
} | null {
  if (!fleetSelfNode) return null;
  const self = selfFleetPeer(fleetSelfNode);
  // The upstream release number is the one fact on this row that is not the
  // peer's own, it belongs to this process, is identical for every peer, and
  // is threaded in here at assembly rather than polled per node.
  const peers = fleetPoller ? fleetPoller.peersPublic(latestInstallableRelease()) : [];
  const graded = gradeFleetDeploy([self, ...peers]);
  // The same trick for Aperire's own release (ADR 0022 decision 6): the
  // published release is threaded in from the LAST answer this process got
  // out of get.aperire.one, so a fleet of six is one outbound call. Null
  // until something has answered, and null grades everybody unknown rather
  // than marking anybody.
  //
  // `fleetReading` is the one caller that renders a count (the Updates
  // card). It says which release the peers are held against: this host's own
  // reading of the endpoint for this request, and null when that reading
  // named none, so no row reads behind against a kept answer (#863). Every
  // other caller omits it and keeps the last answer, as they always did;
  // none of them puts a release word on a page.
  const fleetLatest = fleetReading !== undefined ? fleetReading : (lastAnsweredUpdateCheck?.latest ?? null);
  // Nothing passed means the self row grades with the fleet, which is the
  // state every caller but the card is in.
  const release = gradeFleetRelease(graded.nodes, fleetLatest, selfLatest ?? fleetLatest, readReleaseHighWater());
  return { nodes: sortFleetForDisplay(release.nodes), deploy: graded.comparison, release };
}

// ─── Insights tab, alert engine + state machine ──────────────────────
// Every metric write (writeMetric) fans out to a registered observer,
// which scans rules indexed by metric and advances a per-rule state
// machine: OK → pending (threshold held, waiting for duration) →
// firing (alert event written) → resolved (alert event written, state
// cleared). Firing state is mirrored to the firing_state table so a
// dashboard restart recovers without re-firing already-active alerts.

const rulesByMetric = new Map<string, ParsedRule[]>();
function rebuildRulesByMetric(): void {
  rulesByMetric.clear();
  for (const r of insightsConfig.rules.full) {
    const list = rulesByMetric.get(r.metric);
    if (list) list.push(r);
    else rulesByMetric.set(r.metric, [r]);
  }
}

type RuleState = 'OK' | 'pending' | 'firing';
interface RuleInstanceState {
  state: RuleState;
  triggeredAt?: number;          // ms, first time the threshold was crossed
  firedAt?: number;              // ms, pending → firing transition
  dedupKey?: string;
}
const ruleState = new Map<string, RuleInstanceState>();

function ruleFingerprint(metric: string, severity: string): string {
  return `${metric}:${severity}`;
}

/** Retire a firing row that nothing can ever resolve, writing the resolution
 *  to alert history so the record shows how it ended. Notification channels
 *  are deliberately NOT fanned out: nobody wants an email about an alert that
 *  stopped existing because they edited a config file. */
function retireFiringRow(row: FiringStateRow, why: string): void {
  const nowSec = Math.floor(Date.now() / 1000);
  writeAlertEvent({
    ts: nowSec,
    metric: row.metric,
    severity: row.severity,
    state: 'resolved',
    value: row.last_value,
    threshold_op: row.threshold_op,
    threshold_value: row.threshold_value,
    duration_s: Math.max(0, nowSec - row.fired_ts),
    dedup_key: row.dedup_key,
    channels: row.channels,
  });
  clearFiringState(row.dedup_key);
  ruleState.delete(ruleFingerprint(row.metric, row.severity));
  console.log(`[insights] retired firing ${row.metric} ${row.severity}, ${why}`);
}

// An alert only ever resolves inside evaluateRulesForMetric, which is reached
// by a metric write and iterates the rules that currently exist. Delete a rule
// while it is firing and its row in firing_state is never visited again: it
// survives every restart (restoreFiringStateFromDisk puts it straight back),
// keeps appearing in Currently Firing and in /read/v1/firing, and keeps the
// node's fleet badge amber, permanently, with no way for an operator to clear
// it short of editing the database. A firing row is a claim a rule is making;
// once the rule is gone nobody is making it.
//
// Called only from the SUCCESS path of loadRulesYaml. A rules.yaml that fails
// to parse leaves the parsed set empty, and pruning against that would read
// one YAML typo as "every alert on this host just resolved". A rules.local.yaml
// that fails to parse never reaches here either: the merge hands back the
// shipped set whole, so the rules pruned against are the ones in force.
// Disabling a rule locally (ADR 0020) does retire what it left firing, which
// is the same act as deleting the rule and gets the same treatment.
function pruneOrphanedFiringState(): void {
  for (const row of queryFiringState()) {
    const rules = rulesByMetric.get(row.metric);
    if (rules?.some(r => r.severity === row.severity)) continue;
    retireFiringRow(row, 'no rule for it in the merged set (removed from rules.yaml, or disabled in rules.local.yaml)');
  }
}

// Metrics only a validator can have an opinion about. A stock node holds no
// validator key, so asking whether the registry can see it signing is the same
// category error recordOurAgreement already refuses to make.
const VALIDATOR_ONLY_ALERT_METRICS = new Set([
  'agreement_pct_1h',
  'missed_validations_1h',
  'validator_registry_seen',
  'validator_last_seen_age_s',
  'validator_version_drift',
]);
let validatorOnlyFiringCleared = false;

// A box that used to be a validator and is now a stock node keeps whatever was
// firing at the moment its key went away, forever: the pollers that write those
// metrics all return early without a key, so the rules that would resolve them
// are never evaluated again. Observed on a repurposed lab node, a
// validator_registry_seen warning still firing six days after the metric was
// last written, holding the node amber on the fleet roster.
//
// Only called on a POSITIVE observation: a successful server_info poll that
// reports no usable validator key. Never on the absence of one, a dashboard
// that starts while rippled is down knows nothing yet, and "I could not ask"
// must never be recorded as "it is not a validator".
function clearValidatorOnlyFiringState(): void {
  if (validatorOnlyFiringCleared) return;
  validatorOnlyFiringCleared = true;
  for (const row of queryFiringState()) {
    if (!VALIDATOR_ONLY_ALERT_METRICS.has(row.metric)) continue;
    retireFiringRow(row, 'this node holds no validator key, the metric is not written here');
  }
}

// Metrics only a host with a LOCAL node (or its relay) can have an opinion
// about. A fleet aggregator runs no node and no relay of its own, but
// RIPPLED_URL still defaults to loopback, so the sampler measured reachability
// against a rippled that was never there: node_unreachable_s climbed from boot
// and fired a permanent critical, with relay_feed_age_s right behind it
// (operator, 2026-08-23). Same category error, and the same fix, as
// VALIDATOR_ONLY_ALERT_METRICS above: do not write them here, and retire what
// they left firing, because a metric that stops being written never resolves.
const LOCAL_NODE_ONLY_ALERT_METRICS = new Set([
  'node_unreachable_s',
  'relay_feed_age_s',
]);
let localNodeOnlyFiringCleared = false;
// Whether THIS dashboard is a fleet aggregator with no node of its own. Read
// from the fleet self entry's declared role, never inferred: fleet-registry
// makes `role` an explicit field precisely because "a dashboard with no node
// looks exactly as much like an aggregator as like a broken node", and guessing
// between them is the failure that field exists to prevent.
function selfIsFleetAggregator(): boolean {
  return fleetSelfNode?.role === 'aggregator';
}
// Only on the POSITIVE observation that this is an aggregator (its role says
// so). Retires anything the local-node-only rules left firing before the fleet
// resolved, or a previous life on this host left behind; the sampler stops
// writing those metrics, so nothing else would ever resolve them.
function clearLocalNodeOnlyFiringState(): void {
  if (localNodeOnlyFiringCleared) return;
  localNodeOnlyFiringCleared = true;
  for (const row of queryFiringState()) {
    if (!LOCAL_NODE_ONLY_ALERT_METRICS.has(row.metric)) continue;
    retireFiringRow(row, 'this dashboard is a fleet aggregator with no local node, the metric is not written here');
  }
}

// The host an alert names. `APERIRE_HOSTNAME` overrides; then the host the
// node's relay reports, which on a split install (Shape B) is the validator's
// machine and not the one this process runs on (#1232); otherwise the OS
// hostname, so the emails read e.g. `cpu_busy_pct on aperire-prod` instead of
// the bare localhost / Docker container ID. The relay's hostname is kept from
// its last frame whether or not that frame is still fresh: a quiet relay has
// not moved house.
function hostnameSourcesForAlerts(): { hostname: string; hostnameOverride: string | undefined; relayHostname: string | null } {
  return {
    hostname: osHostname(),
    hostnameOverride: process.env.APERIRE_HOSTNAME,
    relayHostname: lastRelaySystem?.payload.hostname ?? null,
  };
}
function hostnameForAlerts(): string {
  return resolveNodeHostname(hostnameSourcesForAlerts());
}

// #1229. Which node an alert is about, for every channel, built in this one
// place and spread into each alert context (firing, resolved, Test Fire), so
// the three cannot drift. This only hands over what the dashboard holds; what
// wins, and what a node that was never read is called, is decided in
// lib/alert-identity.ts. The node's name is the one its aggregator registered
// it under (the running link agent's label, from fleet-link.json), then its
// fleet.yaml self entry, then the hostname: a paired node's fleet.yaml can
// still hold the name it had before it joined. The dashboard address is
// `APERIRE_PUBLIC_URL` when set, then the `public_url` authn.yaml carries, then
// the fleet row's: the old link read only the environment variable, which is
// why an install configured the usual way sent none. There is no host address
// here: the unit's sandbox blocks the netlink socket that read needs, and the
// hostname already says which machine. Never throws: this is on the sync
// metric-write path, and a read that fails (a malformed authn.yaml) must cost
// its own row, not the alert.
function alertNodeFields(): Pick<AlertEmailContext, 'hostname' | 'dashboard_url' | 'identity'> {
  const identity = buildNodeIdentity({
    pairedLabel: fleetLinkSlot.agent?.state().label,
    fleetLabel: fleetSelfNode?.label,
    ...hostnameSourcesForAlerts(),
    aggregator: selfIsFleetAggregator(),
    serverInfo: snapshot.server_info as AnyObj | undefined,
    isValidatorKey: isRealValidatorKey,
    envPublicUrl: process.env.APERIRE_PUBLIC_URL,
    authnPublicUrl: safeRead(() => dashboardIdentity().public_url, null),
    fleetDashboardUrl: fleetSelfNode?.dashboard_url,
  });
  return { hostname: identity.hostname, dashboard_url: identity.url ?? '', identity };
}

// Fan-out to configured delivery channels. Phase 4 implements only
// email; ntfy / webhooks slot in here in Phases 7 / 8 with the same
// shape, fire-and-forget promise, patches alerts_history.delivery
// when the send completes. Errors never propagate up; the metric write
// path stays sync and unblocked.
function deliverChannels(eventId: number, rule: ParsedRule, ctx: AlertEmailContext): void {
  if (rule.channels.includes('email') && emailSendConfig) {
    sendAlertEmail(emailSendConfig, ctx).then(result => {
      if (result.ok) {
        updateAlertDelivery(eventId, 'email', 'delivered');
        console.log(`[alert] email delivered ${ctx.metric} ${ctx.severity} ${ctx.state}` + (result.messageId ? ` (id ${result.messageId})` : ''));
      } else {
        updateAlertDelivery(eventId, 'email', `failed:${result.error || 'unknown'}`);
        console.warn(`[alert] email send failed ${ctx.metric} ${ctx.severity}: ${result.error}`);
      }
    }).catch(err => {
      updateAlertDelivery(eventId, 'email', `failed:${(err as Error).message}`);
      console.warn(`[alert] email threw ${ctx.metric}:`, (err as Error).message);
    });
  }
  if (rule.channels.includes('ntfy') && ntfySendConfig) {
    sendAlertNtfy(ntfySendConfig, ctx).then(result => {
      if (result.ok) {
        updateAlertDelivery(eventId, 'ntfy', 'delivered');
        console.log(`[alert] ntfy delivered ${ctx.metric} ${ctx.severity} ${ctx.state}` + (result.messageId ? ` (id ${result.messageId})` : ''));
      } else {
        updateAlertDelivery(eventId, 'ntfy', `failed:${result.error || 'unknown'}`);
        console.warn(`[alert] ntfy send failed ${ctx.metric} ${ctx.severity}: ${result.error}`);
      }
    }).catch(err => {
      updateAlertDelivery(eventId, 'ntfy', `failed:${(err as Error).message}`);
      console.warn(`[alert] ntfy threw ${ctx.metric}:`, (err as Error).message);
    });
  }
  // Phase 8, webhook fan-out. Single 'webhook' marker in rule.channels
  // expands to every configured target whose severity_filter admits
  // this alert. We Promise.all the targets so the bare 'webhook'
  // delivery key resolves once with a summary status; per-target
  // detail goes to the dashboard log. Failures don't block siblings.
  if (rule.channels.includes('webhook') && webhookSendConfigs.length > 0) {
    const targets = webhookSendConfigs.filter(w =>
      w.severityFilter == null || w.severityFilter.includes(ctx.severity));
    if (targets.length === 0) {
      // Channel listed on the rule but no target accepts this severity.
      // Mark as 'delivered' (no work to do) so the W icon doesn't dim
      // misleadingly. Operator-visible state stays accurate via logs.
      updateAlertDelivery(eventId, 'webhook', 'delivered');
      console.log(`[alert] webhook skipped ${ctx.metric} ${ctx.severity}: no target accepts this severity`);
    } else {
      Promise.all(targets.map(async cfg => {
        try {
          const r = await sendAlertWebhook(cfg, ctx);
          if (r.ok) console.log(`[alert] webhook delivered '${cfg.id}' ${ctx.metric} ${ctx.severity} ${ctx.state}`);
          else      console.warn(`[alert] webhook send failed '${cfg.id}' ${ctx.metric} ${ctx.severity}: ${r.error}`);
          return { id: cfg.id, ok: r.ok, error: r.error };
        } catch (err) {
          const msg = (err as Error).message;
          console.warn(`[alert] webhook threw '${cfg.id}' ${ctx.metric}:`, msg);
          return { id: cfg.id, ok: false, error: msg };
        }
      })).then(results => {
        const failed = results.filter(r => !r.ok);
        if (failed.length === 0) {
          updateAlertDelivery(eventId, 'webhook', 'delivered');
        } else {
          const detail = failed.map(f => `${f.id}:${(f.error || 'err').slice(0, 80)}`).join(' · ');
          updateAlertDelivery(eventId, 'webhook',
            `failed:${failed.length}/${results.length} ${detail}`);
        }
      });
    }
  }
}

function evaluateThreshold(value: number, op: string, threshold: number): boolean {
  switch (op) {
    case '>=': return value >= threshold;
    case '>':  return value >  threshold;
    case '<=': return value <= threshold;
    case '<':  return value <  threshold;
    case '==': return value === threshold;
    default:   return false;
  }
}

function evaluateRulesForMetric(metric: string, value: number, tsMs: number): void {
  const rules = rulesByMetric.get(metric);
  if (!rules || rules.length === 0) return;
  const tsSec = Math.floor(tsMs / 1000);
  for (const rule of rules) {
    const fp = ruleFingerprint(metric, rule.severity);
    let st = ruleState.get(fp) ?? { state: 'OK' as RuleState };
    const triggered = evaluateThreshold(value, rule.threshold.op, rule.threshold.value);

    if (triggered) {
      if (st.state === 'OK') {
        st = { state: 'pending', triggeredAt: tsMs };
      }
      // Fall through, not else-if: a rule with duration 0s must fire on the
      // SAME breach that opened it, not wait for a second sample. The old
      // else-if meant every rule needed two consecutive breaches (an implicit
      // ~10s debounce on top of the configured duration), so node_unreachable_s
      // (duration 0s, a value that IS the outage duration) missed a node that
      // crossed 30s for a single sample during a restart and came back
      // (operator, stock-node2, 2026-08-24, #63). A duration>0 rule is
      // unaffected: heldSec is 0 on this first pass, so it stays pending until
      // a later sample makes heldSec >= its duration, exactly as before.
      if (st.state === 'pending') {
        const heldSec = (tsMs - (st.triggeredAt ?? tsMs)) / 1000;
        if (heldSec >= rule.durationS) {
          // Promote to firing, write event + persist firing_state.
          const triggeredTsSec = Math.floor((st.triggeredAt ?? tsMs) / 1000);
          const dedupKey = `${metric}:${rule.severity}:${triggeredTsSec}`;
          const eventId = writeAlertEvent({
            ts: tsSec,
            metric,
            severity: rule.severity,
            state: 'firing',
            value,
            threshold_op: rule.threshold.op,
            threshold_value: rule.threshold.value,
            duration_s: rule.durationS,
            dedup_key: dedupKey,
            channels: rule.channels,
            context: alertContext(metric),
          });
          deliverChannels(eventId, rule, {
            metric,
            severity: rule.severity,
            state: 'firing',
            value,
            threshold_op: rule.threshold.op,
            threshold_value: rule.threshold.value,
            duration_s: rule.durationS,
            dedup_key: dedupKey,
            triggered_iso: new Date(triggeredTsSec * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'),
            ...alertNodeFields(),
            knowledge: insightsConfig.knowledge.metric_alerts[metric],
            action: rule.action,
            action_command: rule.action_command,
          });
          upsertFiringState({
            dedup_key: dedupKey,
            metric,
            severity: rule.severity,
            triggered_ts: triggeredTsSec,
            fired_ts: tsSec,
            last_value: value,
            last_seen_ts: tsSec,
            threshold_op: rule.threshold.op,
            threshold_value: rule.threshold.value,
            duration_s: rule.durationS,
            channels: rule.channels,
            acked_at: null,
            muted_until: null,
            last_paged_ts: null,
          });
          st = { state: 'firing', triggeredAt: st.triggeredAt, firedAt: tsMs, dedupKey };
          console.log(`[alert] FIRING ${metric} ${rule.severity}: value=${value} threshold=${rule.threshold.op}${rule.threshold.value} held ${heldSec.toFixed(1)}s`);
        }
      } else if (st.state === 'firing' && st.dedupKey) {
        // Update last value/last seen, no new event written.
        upsertFiringState({
          dedup_key: st.dedupKey,
          metric,
          severity: rule.severity,
          triggered_ts: Math.floor((st.triggeredAt ?? tsMs) / 1000),
          fired_ts: Math.floor((st.firedAt ?? tsMs) / 1000),
          last_value: value,
          last_seen_ts: tsSec,
          threshold_op: rule.threshold.op,
          threshold_value: rule.threshold.value,
          duration_s: rule.durationS,
          channels: rule.channels,
          acked_at: null,
          muted_until: null,
          last_paged_ts: null,
        });
      }
    } else {
      if (st.state === 'pending') {
        st = { state: 'OK' };
      } else if (st.state === 'firing' && st.dedupKey) {
        const heldSec = st.firedAt ? Math.floor((tsMs - st.firedAt) / 1000) : 0;
        const eventId = writeAlertEvent({
          ts: tsSec,
          metric,
          severity: rule.severity,
          state: 'resolved',
          value,
          threshold_op: rule.threshold.op,
          threshold_value: rule.threshold.value,
          duration_s: heldSec,
          dedup_key: st.dedupKey,
          channels: rule.channels,
        });
        deliverChannels(eventId, rule, {
          metric,
          severity: rule.severity,
          state: 'resolved',
          value,
          threshold_op: rule.threshold.op,
          threshold_value: rule.threshold.value,
          duration_s: heldSec,
          dedup_key: st.dedupKey,
          triggered_iso: st.firedAt
            ? new Date(st.firedAt).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')
            : '',
          ...alertNodeFields(),
          knowledge: insightsConfig.knowledge.metric_alerts[metric],
          action: rule.action,
          action_command: rule.action_command,
        });
        clearFiringState(st.dedupKey);
        console.log(`[alert] RESOLVED ${metric} ${rule.severity}: held ${heldSec}s`);
        st = { state: 'OK' };
      }
    }

    ruleState.set(fp, st);
  }
}

// Restore in-memory rule state from disk on startup so already-firing
// alerts (e.g., that were firing when the dashboard last shut down)
// keep their dedup_key and don't generate phantom "firing" events when
// the threshold is re-met on the first metric write after boot.
function restoreFiringStateFromDisk(): void {
  const rows = queryFiringState();
  for (const row of rows) {
    const fp = ruleFingerprint(row.metric, row.severity);
    ruleState.set(fp, {
      state: 'firing',
      triggeredAt: row.triggered_ts * 1000,
      firedAt: row.fired_ts * 1000,
      dedupKey: row.dedup_key,
    });
  }
  if (rows.length > 0) console.log(`[insights] restored ${rows.length} firing alert(s) from disk`);
}
restoreFiringStateFromDisk();

addMetricObserver((metric, value, ts) => {
  evaluateRulesForMetric(metric, value, ts);
});

// ─── Phase 6, Scheduled digest ───────────────────────────────────────
// One-shot daily summary email. Cron loop ticks every 60s and fires
// when (a) digest.yaml is enabled, (b) the cadence matches today, and
// (c) we're past the configured time_utc and haven't already sent
// today. Last-sent date persists across restarts via digest_runs,
// the cron seeds digestLastFiredDateUtc from the most recent 'sent'
// row at startup so a 13:01 reboot doesn't re-fire the day's digest.

function gatherDigestSummary(cfg: DigestSendConfig): DigestSummary {
  const now = Date.now();
  const windowMs = cfg.include.digest_window_hours * 3_600_000;
  const cutoff = now - windowMs;

  // Agreement % over the window, count own-voted vs. missed in
  // agreementHistory. Source of truth for the headline metric.
  let total = 0, agreed = 0;
  for (const r of agreementHistory) {
    if (r.ts < cutoff) continue;
    total++;
    if (r.our_voted) agreed++;
  }
  const pct = total > 0 ? (agreed / total) * 100 : null;

  // Alerts in window, counts by tier + most-severe few for the body.
  const events = queryAlertHistory(cutoff, 500);
  const firingEvents = events.filter(e => e.state === 'firing');
  const byTier = { page: 0, critical: 0, warn: 0 };
  for (const e of firingEvents) {
    if (e.severity === 'page')     byTier.page++;
    else if (e.severity === 'critical') byTier.critical++;
    else if (e.severity === 'warn')     byTier.warn++;
  }
  const sevRank: Record<string, number> = { page: 3, critical: 2, warn: 1 };
  const top = firingEvents
    .slice()
    .sort((a, b) => (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0) || b.ts - a.ts)
    .slice(0, 5)
    .map(e => ({ metric: e.metric, severity: e.severity, ts: e.ts, value: e.value }));

  // Approaching amendments, surface the names of any in the snapshot
  // that have an ETA within the next ~7 days. The structure depends on
  // the snapshot.amendments shape; if not populated, return [].
  const approaching: Array<{ name: string; eta?: string }> = [];
  const a = (snapshot as AnyObj).amendments as AnyObj | undefined;
  if (a && Array.isArray(a.approaching)) {
    for (const x of a.approaching as AnyObj[]) {
      if (x && typeof x.name === 'string') approaching.push({ name: x.name, eta: typeof x.eta === 'string' ? x.eta : undefined });
    }
  }

  const info = (snapshot.server_info ?? {}) as AnyObj;
  return {
    ts: now,
    windowHours: cfg.include.digest_window_hours,
    hostname: hostnameForAlerts(),
    pubkey: snapshot.our_pubkey_validator ?? null,
    serverState: typeof info.server_state === 'string' ? info.server_state : null,
    ledgerIndex: (() => {
      const vl = info.validated_ledger as AnyObj | undefined;
      return vl && typeof vl.seq === 'number' ? vl.seq as number : null;
    })(),
    agreement: { pct, total, missed: total - agreed },
    alerts: { total: firingEvents.length, byTier, top },
    network: {
      peerCount:  Array.isArray(snapshot.peers) ? snapshot.peers.length : null,
      trustedUnl: snapshot.trusted_unl?.size ?? 0,
    },
    amendments: approaching,
  };
}

function buildDigestSubject(summary: DigestSummary, cfg: DigestSendConfig): string {
  const tpl = cfg.subjectTemplate;
  return tpl
    .replace('{host}',          summary.hostname)
    .replace('{agreement_pct}', digestValue(summary.agreement.pct != null ? summary.agreement.pct.toFixed(1) : null))
    .replace('{alert_count}',   String(summary.alerts.total))
    .replace('{pubkey_short}',  digestValue(summary.pubkey ? summary.pubkey.slice(0, 12) + '…' : null));
}

function buildDigestHtml(summary: DigestSummary, cfg: DigestSendConfig): string {
  // LOW-08, same rule as the alert email beside it: every interpolated value
  // goes through here, numbers included. The numeric fields are typed, but the
  // type is a claim about the code that fills them rather than about the
  // SQLite column or the node reading they come from.
  const esc = (s: unknown) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
  const pctColor = (pct: number | null) =>
    pct == null ? '#8b949e' :
    pct >= 99   ? '#1a7f37' :
    pct >= 95   ? '#bf8700' :
                  '#cf222e';
  const sevPill = (sev: string) => {
    const col = sev === 'page' ? '#cf222e' : sev === 'critical' ? '#cf222e' : '#bf8700';
    const lbl = sev === 'page' ? 'PAGE' : sev === 'critical' ? 'CRIT' : 'WARN';
    return `<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:${col};color:#fff;font-size:10px;font-weight:700;letter-spacing:0.04em;">${lbl}</span>`;
  };
  const formatTs = formatDigestTs;
  const ag = summary.agreement;
  const agPctStr = esc(digestValue(ag.pct != null ? ag.pct.toFixed(2) + '%' : null));

  const agreementBlock = cfg.include.agreement_summary ? `
    <h3 style="margin:24px 0 8px;font-size:14px;letter-spacing:0.04em;color:#656d76;text-transform:uppercase;">Validator health (last ${summary.windowHours} h)</h3>
    <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;width:100%;">
      <tr><td style="color:#656d76;width:200px;">Agreement</td><td style="font-weight:700;color:${pctColor(ag.pct)};">${agPctStr}</td></tr>
      <tr><td style="color:#656d76;">Total ledgers</td><td>${esc(ag.total)}</td></tr>
      <tr><td style="color:#656d76;">Missed</td><td style="color:${ag.missed > 0 ? '#cf222e' : '#1a7f37'};">${esc(ag.missed)}</td></tr>
      ${summary.serverState ? `<tr><td style="color:#656d76;">Server state</td><td>${esc(summary.serverState)}</td></tr>` : ''}
      ${summary.ledgerIndex != null ? `<tr><td style="color:#656d76;">Last ledger</td><td>${esc(summary.ledgerIndex)}</td></tr>` : ''}
    </table>` : '';

  const alertRows = summary.alerts.top.map(t => `
    <tr>
      <td style="padding:4px 6px;">${sevPill(t.severity)}</td>
      <td style="padding:4px 6px;font-family:monospace;">${esc(t.metric)}</td>
      <td style="padding:4px 6px;color:#656d76;font-family:monospace;">${esc(digestValue(t.value))}</td>
      <td style="padding:4px 6px;color:#8b949e;font-size:12px;">${esc(formatTs(t.ts))}</td>
    </tr>`).join('');
  const alertsBlock = cfg.include.top_alerts ? `
    <h3 style="margin:24px 0 8px;font-size:14px;letter-spacing:0.04em;color:#656d76;text-transform:uppercase;">Alerts (last ${summary.windowHours} h)</h3>
    <p style="margin:0 0 8px;font-size:14px;">
      <strong>${esc(summary.alerts.total)}</strong> total ·
      <span style="color:#cf222e;">${esc(summary.alerts.byTier.page)} page</span> ·
      <span style="color:#cf222e;">${esc(summary.alerts.byTier.critical)} critical</span> ·
      <span style="color:#bf8700;">${esc(summary.alerts.byTier.warn)} warn</span>
    </p>
    ${summary.alerts.total > 0 ? `<table cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px;width:100%;">${alertRows}</table>` : '<p style="color:#1a7f37;font-weight:600;font-size:14px;">No alerts fired in this window.</p>'}` : '';

  const networkBlock = cfg.include.network_health ? `
    <h3 style="margin:24px 0 8px;font-size:14px;letter-spacing:0.04em;color:#656d76;text-transform:uppercase;">Network</h3>
    <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;width:100%;">
      <tr><td style="color:#656d76;width:200px;">Connected peers</td><td>${esc(digestValue(summary.network.peerCount))}</td></tr>
      <tr><td style="color:#656d76;">Trusted UNL</td><td>${esc(summary.network.trustedUnl)}</td></tr>
    </table>` : '';

  const amendmentsBlock = (cfg.include.upcoming_amendments && summary.amendments.length > 0) ? `
    <h3 style="margin:24px 0 8px;font-size:14px;letter-spacing:0.04em;color:#656d76;text-transform:uppercase;">Upcoming amendments</h3>
    <ul style="margin:0;padding-left:20px;font-size:14px;">
      ${summary.amendments.map(a => `<li style="margin:2px 0;">${esc(a.name)}${a.eta ? ` <span style="color:#8b949e;">· ${esc(a.eta)}</span>` : ''}</li>`).join('')}
    </ul>` : '';

  const footer = cfg.footerTemplate ? `
    <hr style="border:0;border-top:1px solid #d1d9e0;margin:24px 0 12px;">
    <div style="color:#8b949e;font-size:12px;white-space:pre-wrap;">${esc(cfg.footerTemplate)}</div>` : '';

  return `<!doctype html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1f2328;background:#fff;margin:0;padding:24px;">
  <div style="max-width:640px;margin:0 auto;">
    <div style="display:inline-block;padding:4px 10px;border-radius:12px;background:#0969da;color:#fff;font-weight:700;font-size:12px;letter-spacing:0.06em;">DAILY DIGEST</div>
    <h2 style="margin:14px 0 4px;font-size:20px;">Aperire · ${esc(summary.hostname)}</h2>
    <p style="color:#656d76;margin:0 0 4px;font-size:13px;">${esc(formatTs(summary.ts))}</p>
    ${summary.pubkey ? `<p style="color:#8b949e;margin:0;font-family:monospace;font-size:11px;">${esc(summary.pubkey)}</p>` : ''}
    ${agreementBlock}
    ${alertsBlock}
    ${networkBlock}
    ${amendmentsBlock}
    <hr style="border:0;border-top:1px solid #d1d9e0;margin:24px 0 12px;">
    <p style="color:#8b949e;font-size:12px;margin:0;">Aperire · XRPL validator dashboard</p>
    ${footer}
  </div>
</body></html>`;
}

let digestLastFiredDateUtc: string | null = null;

// On startup, seed the last-fired date from disk so a quick reboot
// doesn't re-fire today's digest.
function seedDigestLastFiredFromDisk(): void {
  const recent = queryDigestRuns(Date.now() - 7 * 86_400_000, 50);
  for (const r of recent) {
    if (r.state !== 'sent') continue;
    digestLastFiredDateUtc = new Date(r.ts).toISOString().slice(0, 10);
    return;
  }
}
seedDigestLastFiredFromDisk();

function shouldFireDigest(): boolean {
  if (!digestSendConfig?.enabled || !emailSendConfig) return false;
  const cfg = digestSendConfig;
  const now = new Date();
  const todayUtc = now.toISOString().slice(0, 10);
  if (digestLastFiredDateUtc === todayUtc) return false;

  // Cadence, for hourly we don't honor time_utc, just fire once per hour.
  if (cfg.cadence === 'weekly' && !cfg.weeklyDays.includes(now.getUTCDay())) return false;

  if (cfg.cadence === 'hourly') {
    // Hourly: fire if we haven't fired in the last 60 minutes.
    // (Reuses the daily-bucket guard above; for hourly, we'd want a
    // finer key, left as a follow-up since the locked default is daily.)
    return true;
  }

  // Time check (daily / weekly).
  const m = /^(\d+):(\d+)/.exec(cfg.timeUtc);
  if (!m) return false;
  const hh = Number(m[1]);
  const mm = Number(m[2]);
  const target = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hh, mm, 0);
  if (now.getTime() < target) return false;

  return true;
}

async function fireDigestNow(reason = 'scheduled'): Promise<void> {
  if (!digestSendConfig || !emailSendConfig) {
    console.warn(`[digest] cannot fire (${reason}), digest or email not configured`);
    return;
  }
  const summary = gatherDigestSummary(digestSendConfig);
  const subject = buildDigestSubject(summary, digestSendConfig);
  const html    = buildDigestHtml(summary, digestSendConfig);
  const text    = buildDigestText(summary, digestSendConfig);
  const cfgWithRecips: EmailChannelConfig = {
    apiKey: emailSendConfig.apiKey,
    sender: emailSendConfig.sender,
    recipients: digestSendConfig.recipients,
  };

  const result = await sendDigestEmail(cfgWithRecips, subject, html, text);
  writeDigestRun({
    ts: Math.floor(Date.now() / 1000),
    channel: 'email',
    state: result.ok ? 'sent' : 'failed',
    subject,
    recipient_count: digestSendConfig.recipients.length,
    message_id: result.messageId ?? null,
    retry_count: 0,
    error: result.error ?? null,
  });

  digestLastFiredDateUtc = new Date().toISOString().slice(0, 10);
  if (result.ok) console.log(`[digest] sent (${reason}) to ${digestSendConfig.recipients.length} recipients (id ${result.messageId})`);
  else           console.warn(`[digest] failed (${reason}): ${result.error}`);
}

setInterval(() => {
  if (!shouldFireDigest()) return;
  fireDigestNow('scheduled').catch(err => console.warn('[digest] uncaught:', (err as Error).message));
}, 60_000);

// ─── Shard count poller ───────────────────────────────────────────────
// Rippled's `crawl_shards` RPC returns this node's shard inventory. Most
// validators don't shard, in which case the response's `complete_shards`
// is an empty string, we surface "Not sharded" in that case.
let lastShardCount: number | 'not_sharded' | null = null;
async function pollShardCount(): Promise<void> {
  try {
    const res = await rippledReq<AnyObj>('crawl_shards', { public_key: false, limit: 0 });
    const result = (res.result as AnyObj | undefined) ?? {};
    // The local node's shards come back under `complete_shards` as a
    // comma-separated range string (e.g. "1-5,7,10-12"). Empty = no shards.
    const cs = typeof result.complete_shards === 'string' ? result.complete_shards : '';
    if (!cs) { lastShardCount = 'not_sharded'; return; }
    // Expand "1-5,7,10-12" into a count without materializing the range.
    let n = 0;
    for (const part of cs.split(',')) {
      const [a, b] = part.split('-').map(x => Number.parseInt(x, 10));
      n += Number.isFinite(b) ? (b - a + 1) : 1;
    }
    lastShardCount = n;
  } catch {
    // Older rippled builds without shard support reject the RPC, treat as unsharded.
    lastShardCount = 'not_sharded';
  }
}


/**
 * The peer-shed signal, read from series already being collected.
 *
 * The decision lives in lib/peer-shed.ts where it can be tested against both
 * shapes; this is only the part that has to touch the store.
 */
function classifyPeerShed(inbound: number, outbound: number): number {
  const WINDOW_MS = 30 * 60 * 1000;
  const was = (m: Parameters<typeof queryHistory>[0]) =>
    baseline(queryHistory(m, WINDOW_MS, 'avg'));
  const rx = queryRecent('rx_bps', 1), tx = queryRecent('tx_bps', 1);
  const wasRx = was('rx_bps'), wasTx = was('tx_bps');
  return peerShedVerdict({
    inboundNow: inbound,
    outboundNow: outbound,
    inboundWas: was('peers_inbound'),
    outboundWas: was('peers_outbound'),
    trafficNow: rx.length && tx.length ? rx[0].value + tx[0].value : null,
    trafficWas: wasRx === null || wasTx === null ? null : wasRx + wasTx,
  });
}

function sampleNetworkMetrics(): void {
  // Relay-feed freshness, written EVERY tick regardless of whether the relay
  // is pushing, so a dead or absent relay is *observable* (a climbing age)
  // instead of silently missing rows, otherwise a relay that stops simply
  // halts every host-network metric with nothing surfacing why. Drives the
  // `relay_feed_age_s` alert rule and the Network-page stale-feed banner.
  // When the relay has never pushed since this
  // process started, fall back to process uptime so an absent relay still
  // trips the alert once uptime passes the threshold.
  // Local-node signals. An aggregator has no node or relay of its own, so
  // measuring either here reads a rippled that is not present and fires a
  // permanent false alert; skip them and retire anything they left firing (see
  // LOCAL_NODE_ONLY_ALERT_METRICS). Every other host writes them every tick so
  // a dead relay or an unreachable node is observable (a climbing age/duration)
  // rather than silently missing.
  if (selfIsFleetAggregator()) {
    clearLocalNodeOnlyFiringState();
  } else {
    const relayAgeS = lastNetStatsAt > 0
      ? (Date.now() - lastNetStatsAt) / 1000
      : process.uptime();
    writeMetric('relay_feed_age_s', relayAgeS);

    // How long the node itself has been unreachable, the SAME measurement
    // node_reach carries to the browser, written every tick as a metric so an
    // outage is *observable* and can trip a rule (same discipline as
    // relay_feed_age_s above). 0 while reachable. This is the honest signal an
    // unreachable node alerts on, a real duration, never a peer count we did
    // not observe (#54).
    writeMetric('node_unreachable_s', nodeReachState().unreachable_for_s);
  }

  const peers = snapshot.peers ?? [];
  // Only while the node is actually reachable. snapshot.peers is a KEPT
  // last-good list that survives an admin-WS disconnect (it is refreshed by
  // pollPeers, which does not run while disconnected), so writing peer_count
  // from it during a restart stamped a fresh "11 peers" over a node that was
  // down, the kept-vs-observed bug that made a restarting node read healthy
  // and fire no alert (#54). Unreachable: write nothing here and let the
  // samples age out; node_unreachable_s above is what surfaces the outage.
  if (nodeReachable && peers.length > 0) {
    let inbound = 0, outbound = 0, insane = 0;
    const latencies: number[] = [];
    for (const p of peers) {
      if (p.inbound) inbound++; else outbound++;
      if (typeof p.sanity === 'string' && p.sanity !== 'sane') insane++;
      if (typeof p.latency === 'number' && Number.isFinite(p.latency) && p.latency >= 0) {
        latencies.push(p.latency);
      }
    }
    writeMetric('peer_count', peers.length);
    writeMetric('peers_inbound', inbound);
    writeMetric('peers_outbound', outbound);
    writeMetric('peers_insane', insane);
    writeMetric('peer_shed_signal', classifyPeerShed(inbound, outbound));
    // peer_conn (Network "Public Connections" peer series) is sourced from
    // rippled's authoritative peer list, NOT the relay's host-side TCP port
    // scan. The dashboard's admin-RPC link to rippled exists in BOTH deployment
    // shapes (co-located and LAN-split), and it sees the real peer connections
    // even when rippled runs in a container, where the relay, reading only the
    // host network namespace, sees none (the container's peer sockets, mostly
    // outbound + NAT'd, never appear in the host's /proc/net/tcp). So peer_conn
    // is exactly the connected-peer count, correct on every topology.
    writeMetric('peer_conn', peers.length);
    if (latencies.length > 0) {
      latencies.sort((a, b) => a - b);
      const pick = (p: number) => {
        const rank = (latencies.length - 1) * p;
        const lo = Math.floor(rank), hi = Math.ceil(rank);
        return lo === hi ? latencies[lo] : latencies[lo] * (hi - rank) + latencies[hi] * (rank - lo);
      };
      writeMetric('peer_latency_p50', pick(0.50));
      writeMetric('peer_latency_p90', pick(0.90));
    }
  }

  // net_stats are populated once the relay is pushing. Before then these
  // writes are skipped (no point storing zeros that represent "unknown").
  const ns = lastNetStatsBroadcast as Record<string, number> | null;
  if (ns && typeof ns.rx_bps === 'number') {
    writeMetric('rx_bps', ns.rx_bps);
    writeMetric('tx_bps', ns.tx_bps);
    writeMetric('rx_pps', ns.rx_pps);
    writeMetric('tx_pps', ns.tx_pps);
    writeMetric('tcp_retrans_per_sec', ns.tcp_retrans_per_sec);
    writeMetric('tcp_established', ns.tcp_established);
    if (typeof ns.http_rpc_connections  === 'number') writeMetric('http_rpc_conn',  ns.http_rpc_connections);
    if (typeof ns.admin_ws_connections  === 'number') writeMetric('admin_ws_conn',  ns.admin_ws_connections);
    if (typeof ns.ws_public_connections === 'number') writeMetric('ws_public_conn', ns.ws_public_connections);
    // peer_conn is intentionally NOT taken from the relay here, it is sourced
    // from rippled's RPC peer list above, the only source that is authoritative
    // in every deployment (and the only one that works for a containerized node).
  }
}

// ─── Per-ledger transaction family classification (operator-grade accuracy) ──
// We do NOT subscribe to the firehose `transactions` stream: at network tx
// rates it overflows rippled's admin-port send_queue_limit and the node drops
// us as a slow consumer (the reconnect churn then starves agreement tracking).
// Instead, on each ledgerClosed we fetch the just-validated ledger's
// transactions ONCE via the `ledger` RPC, a single response message rather
// than one per tx, and tally them by family. Cross-checked against rippled's
// own `txn_count`. The headline tx count/rate come from ledgerClosed.txn_count
// and are unaffected.
type FamilyKey = 'money' | 'market' | 'nft' | 'accts';
interface FamilyCounts { money: number; market: number; nft: number; accts: number; }
const emptyFamilies = (): FamilyCounts => ({ money: 0, market: 0, nft: 0, accts: 0 });

function classifyTxType(t?: string): FamilyKey {
  if (!t) return 'accts';
  const s = t.toLowerCase();
  if (s.includes('nft')) return 'nft';
  if (s.startsWith('amm') || s === 'offercreate' || s === 'offercancel') return 'market';
  if (s === 'payment' || s.startsWith('check') || s.startsWith('escrow') ||
      s.startsWith('paymentchannel') || s === 'depositpreauth') return 'money';
  return 'accts';
}

// Fetch a (just-validated) ledger's transactions and tally them by family.
// One RPC round-trip = one queued response message, well under the admin
// port's send_queue_limit. Returns ok:false on a transient RPC failure so the
// caller can avoid persisting/flagging a bogus zero count. Handles both the
// api_version 1 (tx fields at top level) and 2 ({tx_json}) response shapes.
async function fetchLedgerFamilies(ledgerIndex: number): Promise<{ families: FamilyCounts; ok: boolean }> {
  try {
    const res = await rippledReq<AnyObj>('ledger', { ledger_index: ledgerIndex, transactions: true, expand: true });
    const led = (res.result as AnyObj | undefined)?.ledger as AnyObj | undefined;
    const txns = (led?.transactions as AnyObj[] | undefined) ?? [];
    const families = emptyFamilies();
    for (const t of txns) {
      const tt = (t.TransactionType ?? (t.tx_json as AnyObj | undefined)?.TransactionType) as string | undefined;
      families[classifyTxType(tt)]++;
    }
    return { families, ok: true };
  } catch {
    return { families: emptyFamilies(), ok: false };
  }
}

// ─── Rolling-window validation tracker ────────────────────────────────
// validationLog: map ledger_index → set of master_keys that validated it.
// agreementHistory: per-ledger record of whether OUR validator signed.
// unlActiveLog: timestamps of trusted validator activity (1h window).
// All in-memory; no persistence yet, counts reset on bridge restart.

const validationLog: Map<number, Set<string>> = new Map();
interface AgreementRecord { ledger_index: number; our_voted: boolean; ts: number; }
const agreementHistory: AgreementRecord[] = [];
interface UnlActiveRecord { master_key: string; ts: number; }
const unlActiveLog: UnlActiveRecord[] = [];

// Validation aggregation, replaces the per-event `broadcast('validation')`
// fanout. Browsers receive a 1Hz `validations_tick` summary instead of
// ~400 events/sec each. validationTsLog is a sliding-window of timestamps
// for rate calculation; the currentRound* fields track per-ledger
// participation for the Consensus quorum bar and Overview agreement view.
const validationTsLog: number[] = [];
let currentRoundLedgerIdx: number | null = null;
let currentRoundValidations:    Set<string> = new Set();
let currentRoundUnlValidations: Set<string> = new Set();
let currentRoundOurValidated = false;

const ONE_HOUR_MS = 3_600_000;
const ONE_DAY_MS  = 86_400_000;

// Seed the rolling agreement window from persisted records so a dashboard
// restart doesn't reset the 1h/24h panels to a misleadingly small sample
// (which reads as a false agreement drop). Records older than 24h are ignored
// here and pruned in the DB layer.
try {
  let seeded = 0;
  for (const r of queryAgreementSince(Date.now() - ONE_DAY_MS)) {
    agreementHistory.push({ ledger_index: r.ledger_index, our_voted: r.our_voted === 1, ts: r.ts });
    seeded++;
  }
  if (seeded) console.log(`[bridge] seeded ${seeded} agreement records from the last 24h`);
} catch (err) { console.error('[bridge] agreement seed failed:', (err as Error).message); }

// Two distinct grace windows that used to share one constant. Validation grace
// covers our own validator's late validation arriving from the rippled stream
// (rare but real, needs to be generous). Family settlement only waits for
// the validated-tx stream to land all txs in the just-closed ledger, which
// usually completes in single-digit seconds, bigger values just delay how
// soon the ticker block flips from "calculating" to settled.
const VALIDATION_GRACE_MS = 30_000;
const FAMILY_GRACE_MS     = 10_000;

// ── Admin-WS disconnect tracking ─────────────────────────────────────
// When our connection to rippled drops, the validations stream stops
// delivering events, including our own validator's validations. If the
// VALIDATION_GRACE_MS check fires during a gap, validationLog is empty
// and we'd record a false MISS even though rippled was healthy and
// signing the whole time. We track gap windows and exclude ledgers that
// closed inside them from the agreement counters.
interface DisconnectWindow { start: number; end: number; }
const disconnectWindows: DisconnectWindow[] = [];
// The process is born disconnected (#165). Until the first open every
// ledger closes unobserved, and the ledgers in flight when we subscribe
// have validations already past us, our own validator's among them, so the
// grace timer recorded a MISS the validator never made (ledger 106713026,
// 2026-09-02, xrpscan 0 missed). Startup is a gap like any other: opened
// here, closed by the first open, padded the same way.
let currentDisconnectStart: number | null = Date.now();
let everConnected = false;
// Pad each window by VALIDATION_GRACE_MS on both sides: ledgers that
// closed just before the disconnect haven't had their grace fire yet,
// and validations for ledgers that closed just after reconnect may
// still be catching up on the stream.
const DISCONNECT_PAD_MS = VALIDATION_GRACE_MS;

function inDisconnectWindow(closedAtMs: number): boolean {
  // Historical (closed) gaps
  for (const w of disconnectWindows) {
    if (closedAtMs >= w.start - DISCONNECT_PAD_MS && closedAtMs <= w.end + DISCONNECT_PAD_MS) {
      return true;
    }
  }
  // Ongoing gap, we're disconnected right now
  if (currentDisconnectStart !== null && closedAtMs >= currentDisconnectStart - DISCONNECT_PAD_MS) {
    return true;
  }
  return false;
}

function pruneTrackers() {
  const now = Date.now();
  while (agreementHistory.length && now - agreementHistory[0].ts > ONE_DAY_MS) agreementHistory.shift();
  while (unlActiveLog.length    && now - unlActiveLog[0].ts    > ONE_HOUR_MS)  unlActiveLog.shift();
  // Keep validationLog bounded, discard ledgers older than the last ~256
  if (validationLog.size > 256) {
    const sorted = Array.from(validationLog.keys()).sort((a, b) => a - b);
    for (let i = 0; i < sorted.length - 256; i++) validationLog.delete(sorted[i]);
  }
}
setInterval(pruneTrackers, 60_000);

function computeAgreementStats() {
  const now = Date.now();
  // The clean stretch this node has actually watched, which after a restart is
  // shorter than the hour the cards are labelled with. Null while there is no
  // current reading at all. Counted in the same pass as the two windows below.
  const obsStart = observedWindowStartMs(agreementReconcileInput(now));
  let a1 = 0, m1 = 0, a24 = 0, m24 = 0, obsA = 0, obsM = 0;
  for (const r of agreementHistory) {
    const age = now - r.ts;
    if (age <= ONE_HOUR_MS) { if (r.our_voted) a1++; else m1++; }
    if (age <= ONE_DAY_MS)  { if (r.our_voted) a24++; else m24++; }
    if (obsStart !== null && r.ts >= obsStart) { if (r.our_voted) obsA++; else obsM++; }
  }
  // UNL active = distinct trusted master_keys seen in the last hour
  const seen = new Set<string>();
  for (const e of unlActiveLog) if (now - e.ts <= ONE_HOUR_MS) seen.add(e.master_key);
  return {
    agreement_1h: a1, missed_1h: m1,
    agreement_24h: a24, missed_24h: m24,
    unl_active_1h: seen.size,
    unl_total:     snapshot.trusted_unl?.size ?? 0,
    // Lets every tab tell "nothing to report yet" apart from "does not
    // apply to this node". Both are zero counts; only one deserves a
    // colour.
    is_validator:  isValidatorNode(),
    // Whether the 1h pair above is a measurement or just what survived in
    // memory. False makes both cards read "measuring…" instead of a green
    // 100% / 0 over a stretch of time nothing was watching. Deliberately not
    // on the ADR-0008 read contract: buildValidationSummaryFields names its
    // fields one by one, so this stays on the WS path and no
    // protocol_version moves.
    reconciled_1h: agreementWindowReconciled(now),
    // The same two counts over the stretch that WAS observed, so a card whose
    // hour is not reconciled can say "22m, 100%, 0 missed" instead of blanking
    // to "measuring…" for the rest of the hour. All three are null together
    // when there is no current reading (admin WS down, or a validator that is
    // not proposing): absent is not zero, and a 0/0 here would render as a
    // confident 100% over nothing. Display-only, and on the WS path only, for
    // the same reason reconciled_1h is: buildValidationSummaryFields names its
    // fields one by one, so no protocol_version moves. The rules' own metrics
    // are untouched and still gated on full reconciliation.
    observed_agreement:  obsStart === null ? null : obsA,
    observed_missed:     obsStart === null ? null : obsM,
    observed_window_ms:  obsStart === null ? null : now - obsStart,
  };
}

/** Everything both agreement-window judgements read, assembled once. They must
 *  be asked the same question about the same instant: a reconciled hour and an
 *  observed window built from different inputs could contradict each other on
 *  screen. */
function agreementReconcileInput(now: number): AgreementReconcileInput {
  return {
    now,
    windowMs: ONE_HOUR_MS,
    padMs: DISCONNECT_PAD_MS,
    currentDisconnectStart,
    disconnectWindows,
    isValidator: isValidatorNode(),
    serverState: snapshot.server_info?.server_state,
    uptimeS: snapshot.server_info?.uptime,
  };
}

/** The 1h window's honesty flag, assembled from this module's disconnect
 *  tracking and the node's own last account of itself. The decision itself
 *  lives in lib/agreement-reconcile.ts so it can be tested without starting
 *  a server. */
function agreementWindowReconciled(now: number): boolean {
  return isAgreementWindowReconciled(agreementReconcileInput(now));
}
function broadcastAgreementStats() {
  broadcast('agreement_stats', computeAgreementStats());
}
// Periodic backstop: even if no new non-GAP ledger triggers a broadcast (e.g.
// a brief disconnect spell), a freshly-loaded tab still receives current stats
// within this interval. The initial page-load snapshot carries them too.
setInterval(broadcastAgreementStats, 10_000);

// A validator public key is base58 and starts with `n`. rippled reports the
// string "none" for a node without a validator token, and some builds report
// an empty string, neither is a key, and treating them as one is what made
// a stock node look like a validator missing every ledger.
function isRealValidatorKey(v: unknown): v is string {
  return typeof v === 'string' && /^n[1-9A-HJ-NP-Za-km-z]{20,}$/.test(v.trim());
}

// Whether this node validates at all. A stock node holds no validator key,
// so asking whether it agreed with the network is a category error, it
// never proposed anything to agree with.
function isValidatorNode(): boolean {
  return isRealValidatorKey(snapshot.our_pubkey_validator);
}
let stockNodeNoticeLogged = false;

function recordOurAgreement(ledger_index: number, closedAtMs: number) {
  // A stock node cannot miss a validation it was never going to make.
  // Recording one anyway produced the worst kind of wrong: every ledger
  // written to the never-pruned missed_ledgers table, agreement pinned at
  // 0% in red on three tabs, and the five consensus alert rules firing
  // permanently on a node that is behaving perfectly.
  if (!isValidatorNode()) {
    if (!stockNodeNoticeLogged) {
      stockNodeNoticeLogged = true;
      console.log('[bridge] no validator key on this node, it is a stock node, ' +
        'so validation agreement is not tracked and not alerted on');
    }
    return;
  }
  // Skip ledgers that closed inside an admin-WS disconnect window, we
  // can't have observed our own validation during the gap, so calling it
  // a MISS would be a false positive. GAP entries don't count toward
  // agreement or missed totals.
  if (inDisconnectWindow(closedAtMs)) {
    const ourPubkey = snapshot.our_pubkey_validator;
    console.log(`[bridge] GAP   ledger=${ledger_index}  our=${ourPubkey ?? ','}  closed during WS disconnect, skipping agreement check`);
    return;
  }
  const set = validationLog.get(ledger_index);
  const ourPubkey = snapshot.our_pubkey_validator;
  const our_voted = !!(ourPubkey && set?.has(ourPubkey));
  if (!our_voted) {
    const seenCount = set?.size ?? 0;
    console.log(`[bridge] MISS  ledger=${ledger_index}  our=${ourPubkey ?? ','}  validations_seen=${seenCount}`);
    // Keep the identity, permanently, with the node's context at the moment
    // of the miss. The agreement table answers "how many"; this answers
    // "which, and what was happening", the part that cannot be
    // reconstructed once the rolling windows prune.
    const info = (snapshot.server_info ?? {}) as AnyObj;
    try {
      writeMissedLedger({
        ledger_index,
        ts: Date.now(),
        validations_seen: seenCount,
        trusted_unl: snapshot.trusted_unl?.size ?? null,
        peer_count: Array.isArray(snapshot.peers) ? snapshot.peers.length : null,
        server_state: typeof info.server_state === 'string' ? info.server_state : null,
      });
    } catch { /* non-fatal, the log line above still records it */ }
  }
  const ts = Date.now();
  agreementHistory.push({ ledger_index, our_voted, ts });
  // Persist so the rolling 1h/24h windows survive a dashboard restart.
  try { writeAgreement(ledger_index, our_voted, ts); } catch { /* non-fatal */ }
  broadcastAgreementStats();
}

// Diagnostic counters so we can see what's flowing
const stats = { validations: 0, ledgers: 0, txs: 0 };
setInterval(() => {
  console.log(`[bridge] stream rates, validations:${stats.validations} ledgers:${stats.ledgers} txs:${stats.txs} browsers:${browsers.size}`);
  stats.validations = 0; stats.ledgers = 0; stats.txs = 0;
}, 10_000);

function onRippledMessage(raw: string) {
  let msg: AnyObj;
  try { msg = JSON.parse(raw); } catch { return; }

  // Response to a command we sent
  if (typeof msg.id === 'number' && pendingReqs.has(msg.id)) {
    const cb = pendingReqs.get(msg.id)!;
    pendingReqs.delete(msg.id);
    cb(msg);
    return;
  }

  // Subscribed stream event
  const type = msg.type as string | undefined;

  if (type === 'ledgerClosed') {
    stats.ledgers++;
    snapshot.last_ledger = msg;
    const closedIdx = Number(msg.ledger_index);
    const expectedCount = Number(msg.txn_count) || 0;
    // Keep the diagnostic tx throughput meaningful now that we no longer count
    // individual `transaction` stream events.
    stats.txs += expectedCount;

    // Persist per-ledger time-series points
    const nowTs = Date.now();
    let closeDeltaS: number | null = null;
    if (lastLedgerCloseTs > 0) {
      const closeTimeS = (nowTs - lastLedgerCloseTs) / 1000;
      // Sanity-clip, ignore implausible deltas (clock skew, missed events,
      // bridge restart). When clipped, broadcast null so the browser knows
      // not to plot a bogus bar instead of inventing a wall-clock fake.
      if (closeTimeS >= 0.5 && closeTimeS <= 30) {
        writeMetric('close_time', closeTimeS, nowTs);
        closeDeltaS = closeTimeS;
      }
    }
    lastLedgerCloseTs = nowTs;
    writeMetric('txn_count', expectedCount, nowTs);
    lastLedgerClose = { closeDeltaS, txnCount: expectedCount, atMs: nowTs };

    // Immediate broadcast, explosion + ticker block fire now, with the
    // best-effort snapshot of the bucket as it stands at close time.
    broadcast('ledger:close', {
      ledger_index: msg.ledger_index,
      txn_count: expectedCount,
      close_time: msg.ledger_time,
      close_time_s: closeDeltaS,             // server-side authoritative delta; null on first-after-restart
      fee_base: msg.fee_base,
      reserve_base: msg.reserve_base,
      reserve_inc: msg.reserve_inc,
      validations_for_this_ledger: currentLedgerValidations,
      families: emptyFamilies(),   // best-effort; the settled families land below
    });
    currentLedgerValidations = 0;

    if (Number.isFinite(closedIdx)) {
      // Agreement check, wait the longer validation grace. Capture the
      // close time in the closure so the grace callback can tell whether
      // this ledger straddled a WS disconnect window.
      const closedAtMs = nowTs;
      setTimeout(() => recordOurAgreement(closedIdx, closedAtMs), VALIDATION_GRACE_MS);

      // Settled family re-emit, by now the ledger is validated, so we fetch
      // its transactions once via RPC and tally families. Frontend updates the
      // ticker block for this ledger in place. Cross-check against txn_count.
      setTimeout(async () => {
        const { families, ok } = await fetchLedgerFamilies(closedIdx);
        const summed = families.money + families.market + families.nft + families.accts;
        const mismatch = ok && expectedCount > 0 && summed !== expectedCount;
        if (mismatch) {
          console.log('[bridge] family count mismatch ledger ' + closedIdx +
                      ' summed=' + summed + ' txn_count=' + expectedCount);
        }
        if (!ok) {
          console.log('[bridge] family fetch failed for ledger ' + closedIdx + ', emitting txn_count only');
        }
        broadcast('ledger:families', {
          ledger_index: closedIdx,
          families,
          txn_count: expectedCount,
          mismatch,
        });
        // Persist this fully-settled ledger to SQLite for ticker history.
        writeLedger({
          ledger_index: closedIdx,
          // Ripple-epoch seconds, both ways. The fallback used to write a
          // Unix timestamp into a Ripple-epoch column, so a ledger that
          // arrived without a ledger_time was recorded thirty years in the
          // future and outlived every prune.
          close_ts:     msg.ledger_time
            ? Number(msg.ledger_time)
            : Math.floor(Date.now() / 1000) - RIPPLE_EPOCH_S,
          close_time:   closeDeltaS ?? 0,
          txn_count:    expectedCount,
          fam_money:    families.money,
          fam_market:   families.market,
          fam_nft:      families.nft,
          fam_accts:    families.accts,
        });
      }, FAMILY_GRACE_MS);
    }
    pollServerInfo().catch(() => {});
    return;
  }

  if (type === 'validationReceived') {
    stats.validations++;
    currentLedgerValidations++;
    perMinValidationCount++;
    const masterKey = msg.master_key as string | undefined;
    // A validator that runs from a bare [validation_seed] publishes no
    // manifest, so the stream omits master_key from its validations
    // entirely and identifies it only by validation_public_key. Keying
    // participation off master_key alone therefore dropped every one of
    // those validators on the floor, including, on such a node, its OWN
    // validation: server_info.pubkey_validator matched nothing in the log,
    // every ledger was recorded as a MISS, and agreement sat at 0% with the
    // consensus rules firing forever on a validator that was proposing
    // normally (observed on a private validator: 52 validations logged per
    // ledger, ours never among them, 929 missed in the 1h window).
    // master_key stays the identity whenever it is published, key rotation
    // is exactly why it exists, and validation_public_key is the fallback
    // for the seed-only case. Trust checks below stay on master_key alone:
    // the UNL is a set of master keys, so a signing key could never be in it.
    const signerKey = masterKey ?? (msg.validation_public_key as string | undefined);
    const ledgerIdx = Number(msg.ledger_index);

    // Record per-ledger participation
    if (signerKey && Number.isFinite(ledgerIdx)) {
      let set = validationLog.get(ledgerIdx);
      if (!set) { set = new Set(); validationLog.set(ledgerIdx, set); }
      set.add(signerKey);
    }
    // Track UNL trusted activity (1h window)
    if (masterKey && snapshot.trusted_unl?.has(masterKey)) {
      unlActiveLog.push({ master_key: masterKey, ts: Date.now() });
      // And its amendment vote, on a voting ledger. Every trusted validation
      // goes in: the ones without an `amendments` field are the denominator,
      // and the ones for later ledgers are what closes a round.
      const outcome = amendmentVotes.record(masterKey, ledgerIdx, msg.amendments, snapshot.trusted_unl.size, Date.now());
      if (outcome?.kind === 'counted') {
        const t = outcome.tally;
        console.log(`[amendments] counted voting ledger ${t.ledger_index}: ${t.validations} trusted validations, threshold ${t.threshold}, ${Object.keys(t.counts).length} amendments voted for`);
        // The ballot rows change on the spot, not on the next minute's sample.
        sampleGovernance();
      } else if (outcome?.kind === 'discarded') {
        const r = outcome.round;
        console.log(`[amendments] voting ledger ${r.ledger_index} not counted: ${r.trusted_validations} trusted validations, quorum is ${r.quorum}`);
      }
    }

    // Per-validation broadcast was removed, at ~400 events/s × 2 browsers
    // it was the dashboard's biggest CPU cost. Browsers now consume the
    // 1Hz `validations_tick` aggregate (see broadcastValidationsTick
    // below) which carries rate, current-round received count, UNL
    // received count, and "did we validate", everything the Consensus
    // and Overview tabs need to render the quorum bar and rate display.
    validationTsLog.push(Date.now());
    if (Number.isFinite(ledgerIdx) && (currentRoundLedgerIdx === null || ledgerIdx > currentRoundLedgerIdx)) {
      // A validation for a newer ledger arrived, round rolled over.
      currentRoundLedgerIdx = ledgerIdx;
      currentRoundValidations = new Set<string>();
      currentRoundUnlValidations = new Set<string>();
      currentRoundOurValidated = false;
    }
    if (ledgerIdx === currentRoundLedgerIdx && signerKey) {
      currentRoundValidations.add(signerKey);
      if (masterKey && snapshot.trusted_unl?.has(masterKey)) currentRoundUnlValidations.add(masterKey);
      if (signerKey === snapshot.our_pubkey_validator) currentRoundOurValidated = true;
    }
    return;
  }

  if (type === 'peerStatusChange') {
    // Peer status changed, schedule a throttled refresh. We don't want to
    // re-poll on every chatty event because that'd make the browser re-render
    // the peer ring and the wander phases would reset, causing visible jitter.
    schedulePeerPoll();
    return;
  }

  if (type === 'serverStatus') {
    broadcast('server_status', { server_status: msg.server_status, load_base: msg.load_base, load_factor: msg.load_factor });
    return;
  }

  if (type === 'manifestReceived') {
    // Trusted validator key rotation, of interest to the governance tab. The
    // manifests stream fires for ANY trusted validator's key rotation, so the
    // domain here belongs to whichever validator rotated, NOT necessarily ours.
    // Only forward a domain hint when this manifest is for OUR master key; the
    // authoritative, toml-verified domain comes from pollOwnDomain regardless.
    // (Note: the stream's `domain` field is not formally documented; treat it
    // as a best-effort hint and never as verified.)
    const isOurs = !!snapshot.our_pubkey_validator && msg.master_key === snapshot.our_pubkey_validator;
    const domain = isOurs && typeof msg.domain === 'string' && msg.domain ? msg.domain : null;
    broadcast('manifest', { master_key: msg.master_key, seq: msg.seq, domain });
    // A fresh manifest for our key may mean the operator just set/changed the
    // domain, re-run verification so the ✓ updates without waiting a full day.
    if (isOurs) void pollOwnDomain();
    return;
  }
}

// When snapshot.server_info was last successfully written, the `node-status`
// read route's server_info_age_ms (R1, kept-vs-observed). Deliberately its
// own tracked value rather than derived from nodeReachState().last_ok_ms:
// that field is coupled today to this function's own success path, but
// coupling the age of one field to a different concern's reachability
// bookkeeping is exactly the kind of implicit dependency that breaks
// quietly the day a second caller starts marking the node reachable. Null
// until the first successful poll, never 0, which would read as
// "instantly fresh" while every other server_info-derived field is still
// null.
let serverInfoAtMs: number | null = null;

async function pollServerInfo() {
  try {
    const res = await rippledReq<AnyObj>('server_info');
    const info = (res.result as AnyObj | undefined)?.info as AnyObj | undefined;
    if (!info) return;
    snapshot.server_info = info;
    serverInfoAtMs = Date.now();
    // An upgrade changes the answer to "are we behind?" immediately. Cheap:
    // compares two strings already in memory and broadcasts only on a change.
    rejudgeRelease();
    // rippled reports pubkey_validator as the literal string "none" on a node
    // with no validator token, it does not omit the field. Stored as-is, the
    // dashboard believed every stock node was a validator whose key simply
    // never appeared in any validation set, so it recorded every ledger as a
    // miss: 100% missed in red on three tabs, rows in the never-pruned
    // missed_ledgers table, and five consensus alert rules firing forever on
    // a node behaving perfectly. A key must look like one to count as one.
    if (!snapshot.our_pubkey_validator && isRealValidatorKey(info.pubkey_validator)) {
      snapshot.our_pubkey_validator = info.pubkey_validator as string;
    } else if (!snapshot.our_pubkey_validator && info.pubkey_validator !== undefined) {
      // rippled answered and named no validator key ("none" on a stock node).
      // That is an observation, not a gap, so it is safe to retire the
      // validator-only alerts a previous life on this box may have left firing.
      clearValidatorOnlyFiringState();
    }

    // Accumulate load_factor per-minute samples for downsampled persistence
    if (typeof info.load_factor === 'number') perMinLoadFactor.push(info.load_factor);

    // Job-queue transaction overflow counter, feeds the jq_trans_overflow
    // alert rule (rules.yaml). Some rippled builds expose this as a string
    // counter, so coerce with Number(); guard on != null to skip builds
    // that omit the field entirely.
    if (info.jq_trans_overflow != null) {
      writeMetric('jq_trans_overflow', Number(info.jq_trans_overflow));
    }

    // amendment_blocked, written every poll as 1/0. rippled omits the field
    // when false, so we coerce absence to 0 instead of skipping the write:
    // a series that only exists while blocked leaves an operator unable to
    // distinguish "healthy" from "not being monitored". Unconditional writes
    // also mean the alert rule always has a current sample to evaluate.
    writeMetric('amendment_blocked', info.amendment_blocked ? 1 : 0);

    // Persist converge_time once per validated ledger (rippled exposes it
    // in last_close; we dedupe by ledger seq so we don't re-write the same
    // value across consecutive 5s polls).
    const lc = info.last_close as AnyObj | undefined;
    const validatedLedger = info.validated_ledger as AnyObj | undefined;
    const seq = validatedLedger?.seq as number | undefined;
    const conv = lc?.converge_time_s as number | undefined;
    if (typeof conv === 'number' && typeof seq === 'number' && seq !== lastConvergeForLedger) {
      writeMetric('converge_time', conv);
      lastConvergeForLedger = seq;
    }

    broadcast('server_info', info);
    noteNodeReachable(true, '');
  } catch (err) {
    // NOT transient, past a point. Swallowing this kept the last good
    // server_info in the snapshot for as long as the node stayed down, so
    // Overview and Consensus went on drawing "full" in green through a
    // restart the operator had just approved, the Advisor tab, which reads
    // the node live, correctly said it could not be reached. A monitoring
    // dashboard showing health it cannot currently observe is the one thing
    // it must never do.
    noteNodeReachable(false, (err as Error)?.message ?? String(err));
  }
}

// Reachability, separate from state. `server_state` is what the node says
// about itself; this is whether it is saying anything at all.
//
// Two consecutive failures, not one: the poll runs every five seconds and a
// single timed-out request is not news about a validator, the same rule the
// Advisor tab's node line already follows. Two is ten seconds, well inside a
// restart and far outside a blip.
const NODE_UNREACHABLE_AFTER = 2;
let nodeMisses = 0;
let nodeReachable = true;
let nodeLastOkMs = Date.now();

function nodeReachState() {
  return {
    ok: nodeReachable,
    misses: nodeMisses,
    last_ok_ms: nodeLastOkMs,
    unreachable_for_s: nodeReachable ? 0 : Math.round((Date.now() - nodeLastOkMs) / 1000),
  };
}

function noteNodeReachable(ok: boolean, detail: string) {
  if (ok) {
    nodeMisses = 0;
    nodeLastOkMs = Date.now();
    if (!nodeReachable) {
      nodeReachable = true;
      console.log('[node] reachable again');
      broadcast('node_reach', { ...nodeReachState(), detail: '' });
    }
    return;
  }
  nodeMisses++;
  if (nodeReachable && nodeMisses >= NODE_UNREACHABLE_AFTER) {
    nodeReachable = false;
    console.warn(`[node] unreachable after ${nodeMisses} attempts: ${detail}`);
  }
  if (!nodeReachable) broadcast('node_reach', { ...nodeReachState(), detail });
}

async function pollPeers() {
  try {
    const res = await rippledReq<AnyObj>('peers');
    const peers = ((res.result as AnyObj | undefined)?.peers as PeerRow[] | undefined) ?? [];
    // enrichPeers awaits any new rDNS lookups (cached after first) and
    // attaches GeoIP country. We always re-run enrichment so cached PTRs
    // surface on later polls.
    const enriched = await enrichPeers(peers);
    const key = enriched.map(p => p.address).sort().join('|');
    if (key !== snapshot._peerKey) {
      snapshot._peerKey = key;
      snapshot.peers = enriched;
      broadcast('peers', enriched);
    } else {
      // Identity unchanged, but enriched data may have new hostnames now,
      // so update the cached snapshot and re-broadcast so the frontend can
      // patch labels in place.
      snapshot.peers = enriched;
      broadcast('peers', enriched);
    }
  } catch (err) { /* transient */ }
}

// Throttle: coalesce many peerStatusChange events into at most one poll per 12s
let peerPollScheduled = false;
function schedulePeerPoll() {
  if (peerPollScheduled) return;
  peerPollScheduled = true;
  setTimeout(() => {
    peerPollScheduled = false;
    pollPeers().catch(() => {});
  }, 12_000);
}

// When snapshot.fee was last successfully written, the `consensus-snapshot`
// read route's fee_age_ms (R1, kept-vs-observed), independent of
// serverInfoAtMs above: pollFee runs on its own 10s interval, so the two
// can legitimately disagree by up to one cadence.
let feeAtMs: number | null = null;

async function pollFee() {
  try {
    const res = await rippledReq<AnyObj>('fee');
    const fee = (res.result as AnyObj | undefined);
    if (fee) {
      snapshot.fee = fee;
      feeAtMs = Date.now();
      broadcast('fee', fee);
    }
  } catch (err) { /* transient */ }
}

async function pollConsensusInfo() {
  try {
    const res = await rippledReq<AnyObj>('consensus_info');
    const info = ((res.result as AnyObj | undefined)?.info) as AnyObj | undefined;
    if (info) {
      snapshot.consensus_info = info;
      // rippled doesn't return a literal `mode` field, derive it from the
      // proposing / validating / synched booleans the way the catalog spec
      // describes.
      let mode = 'tracking';
      if (info.proposing) mode = 'proposing';
      else if (info.validating) mode = 'observing';
      else if (info.synched) mode = 'tracking';
      else mode = 'syncing';
      broadcast('consensus_info', {
        mode,
        phase: info.phase,
        proposers: info.proposers,
      });
    }
  } catch (err) { /* transient */ }
}

// The `amendment-ballot` read route's own staleness clock, when
// snapshot.feature was last successfully written, same convention as
// serverInfoAtMs/feeAtMs above.
let featureAtMs: number | null = null;

async function pollFeature() {
  try {
    const res = await rippledReq<AnyObj>('feature');
    const features = ((res.result as AnyObj | undefined)?.features) as AnyObj | undefined;
    if (!features) return;
    snapshot.feature = features;
    featureAtMs = Date.now();

    // Which amendments are ENABLED is a fact about the validated ledger, so a
    // node that has not caught up yet answers this from an empty position:
    // almost everything reads as supported-but-not-enabled. After a restart
    // that showed as "98 pending" where the real number is about five, and it
    // corrected itself minutes later with no explanation, which looks like
    // ninety-odd amendments appeared and then vanished. Keep the last count
    // that was measured against a validated ledger instead of publishing one
    // known to be wrong; on a cold start there is simply nothing to show yet.
    const st = String((snapshot.server_info as AnyObj | undefined)?.server_state ?? '');
    if (st !== 'full' && st !== 'proposing' && st !== 'validating') return;

    // The dashboard-friendly summary, from the SAME builder the Governance
    // tab's own card uses (lib/amendments.ts). This loop used to be written
    // out here a second time and measured "approaching" differently from
    // sampleGovernance's copy, validations against 80% of threshold here,
    // count against 75% there, so Overview's card and the Governance card
    // could report different numbers for the same node with nothing on
    // either page saying which was which.
    const featureEntries = features as Record<string, AmendmentFeatureEntry>;
    const summary = buildAmendmentVoteSummary(featureEntries);
    // Cache it for the connect snapshot. Without this a freshly loaded tab
    // shows the placeholder until the next periodic broadcast, which reads as
    // "no data" rather than "not yet".
    lastAmendmentsBroadcast = {
      enabled:     summary.enabled,
      supported:   summary.supported,
      vetoed:      summary.vetoed,
      pending:     pendingCount(featureEntries),
      approaching: summary.approaching,
    };
    broadcast('amendments', lastAmendmentsBroadcast);

    // #654: an amendment this build does not support, already at majority.
    // Cached on the snapshot for the governance route (a future UI reads
    // this to name the amendment and its date; the visual callout waits on
    // an approved mockup, RESPONSIVE-STANDARDS.md's own gate). The metric
    // is written on every poll, unconditionally, at the healthy constant
    // when nothing qualifies — see unsupportedMajorityDaysMetric's own
    // comment for why an unwritten metric can never resolve its own alert.
    const ext = (snapshot.xrpscan_amendments ?? {}) as Record<string, { name?: string; xls?: string }>;
    snapshot.unsupported_majority = nextUnsupportedMajority(featureEntries, ext, Date.now());
    writeMetric('unsupported_amendment_days_to_block', unsupportedMajorityDaysMetric(featureEntries, ext, Date.now()));
  } catch (err) { /* transient */ }
}

// Pulls hash → name + XLS-NN from xrpscan so the ballot table can show the
// XLS tag (operators correlate against xrpscan by XLS number) and label
// amendments rippled returns hash-only for. Best-effort: if xrpscan is
// down, the existing rippled names still render.
async function pollXrpscanAmendments() {
  try {
    const res = await fetch('https://api.xrpscan.com/api/v1/amendment', {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return;
    const list = await res.json() as Array<AnyObj>;
    if (!Array.isArray(list)) return;
    const map: Record<string, { name?: string; xls?: string }> = {};
    for (const a of list) {
      const hash = String(a.amendment_id || '').toUpperCase();
      if (!hash) continue;
      map[hash] = {
        name: typeof a.name === 'string' ? a.name : undefined,
        xls:  typeof a.xls  === 'string' ? a.xls  : undefined,
      };
    }
    snapshot.xrpscan_amendments = map;

    // If xrpscan reveals a hash we don't have a description for, refresh
    // xrpl.org opportunistically, beats waiting up to 24h for the daily
    // tick. Triggered only when something genuinely new appears so we
    // don't hammer xrpl.org on every poll cycle.
    const known = snapshot.amendment_descriptions ?? {};
    const missing = Object.keys(map).filter(h => !known[h]);
    if (missing.length > 0) {
      void pollXrplOrgAmendments();
    }
  } catch { /* transient */ }
}

// When the amendment knowledge library (data/amendments.yaml) was last
// genuinely refreshed from xrpl.org, read out of the file's own
// `refreshed_at` line at load, updated to the write moment on every
// successful scrape. Never the file's mtime: a deploy overwrites the file
// with the tree's shipped copy, which would make mtime read as "just
// refreshed" the moment it is actually the stalest it will ever be (#542).
// Served on the Governance tab (both the local broadcast and the peer read
// route) as `library_age_ms`, so an operator can tell a quiet scrape apart
// from a fresh one instead of a file that always looks current.
let amendmentsLibraryAtMs: number | null = null;

// Loads the persisted amendment knowledge library written by
// pollXrplOrgAmendments. Read at startup so descriptions are immediately
// available without waiting on the network.
async function readAmendmentsLibraryFile(path: string): Promise<AmendmentsLibraryFile | null> {
  try {
    return parseAmendmentsLibraryDoc(yaml.load(await readFile(path, 'utf8')));
  } catch (err) {
    if ((err as AnyObj).code !== 'ENOENT') {
      console.warn(`[amendments] knowledge load failed (${path}): ${(err as Error).message}`);
    }
    return null;
  }
}

async function loadAmendmentsLibrary(): Promise<void> {
  const runtime = await readAmendmentsLibraryFile(AMENDMENTS_LIBRARY_PATH);
  const shipped = await readAmendmentsLibraryFile(AMENDMENTS_SHIPPED_PATH);
  const picked = pickAmendmentsLibrary(runtime, shipped);
  if (!picked) return;
  snapshot.amendment_descriptions = picked.entries;
  amendmentsLibraryAtMs = picked.refreshedAtMs;
  const from = picked === runtime ? AMENDMENTS_LIBRARY_PATH : AMENDMENTS_SHIPPED_PATH;
  console.log(`[amendments] knowledge loaded: ${Object.keys(picked.entries).length} entries from ${from}`);
}

// Scrapes hash → description from xrpl.org's known-amendments page and
// writes the result to data/amendments.yaml. The fetch/parse/write/
// stamp logic lives in lib/xrpl-org-amendments.ts (refreshAmendmentsLibrary),
// pure aside from the injected fetch and file-write, so it can be unit
// tested with a fake clock and a fake fetch; this function's own job is
// wiring the real fetch and file-write in and recording the outcome.
async function pollXrplOrgAmendments(): Promise<void> {
  const result = await refreshAmendmentsLibrary({
    fetchImpl: (url) => fetch(url, { signal: AbortSignal.timeout(20_000) }),
    writeImpl: (path, contents) => writeFile(path, contents, 'utf8'),
    path: AMENDMENTS_LIBRARY_PATH,
    nowMs: Date.now(),
  });
  if (!result.ok) {
    // #542: say so rather than leaving the existing file looking current.
    // This used to be a silent early return on both the HTTP-not-ok and the
    // empty-scrape paths.
    console.warn(`[amendments] xrpl.org refresh failed: ${result.reason}`);
    return;
  }
  snapshot.amendment_descriptions = result.entries;
  amendmentsLibraryAtMs = result.refreshedAtMs;
  console.log(`[amendments] refreshed from xrpl.org: ${Object.keys(result.entries).length} entries`);
}

// ── Own-validator domain verification ─────────────────────────────────────
// Establishes the domain→validator half of XRPL domain verification for THIS
// node: (1) read the manifest-claimed domain via the `manifest` admin command
// (server_info / the manifests stream do not reliably expose the own domain;
// the `manifest` command returns details.domain when set), then (2) fetch
// https://<domain>/.well-known/xrp-ledger.toml and confirm a [[VALIDATORS]]
// public_key entry matches our master key. verified=true only when it does.
//
// SECURITY (SSRF): we fetch an operator-controlled, self-asserted domain, low
// risk, but guard anyway: HTTPS only, reject IP-literal / private / loopback /
// link-local / .local hosts before the request, cap the response size, and time
// out. Result is broadcast as { domain, verified } and cached for reload replay.

const TOML_FETCH_TIMEOUT_MS = 10_000;
const TOML_MAX_BYTES = 512 * 1024;        // 512 KiB cap, real toml files are <10 KiB

// Minimal TOML scan for [[VALIDATORS]] public_key entries. We deliberately do
// NOT add a TOML dependency: we only need to know whether our master key is
// listed under a validators table. We scan the [[VALIDATORS]] array tables and
// read each public_key value; a direct substring check of the master key is the
// fallback. Returns true iff our key is present in a [[VALIDATORS]] entry.
function tomlListsValidator(toml: string, masterKey: string): boolean {
  if (!toml || !masterKey) return false;
  // Walk array-of-tables sections; collect those whose header is VALIDATORS.
  // A section runs from its [[header]] (or [header]) line to the next one.
  const lines = toml.split(/\r?\n/);
  let inValidators = false;
  for (const raw of lines) {
    const line = raw.replace(/#.*$/, '').trim();      // strip comments
    if (!line) continue;
    const tableMatch = /^\[\[?\s*([A-Za-z0-9_.-]+)\s*\]?\]$/.exec(line);
    if (tableMatch) {
      inValidators = tableMatch[1].toUpperCase() === 'VALIDATORS';
      continue;
    }
    if (!inValidators) continue;
    const kv = /^public_key\s*=\s*["']?([^"'\s]+)["']?\s*$/i.exec(line);
    if (kv && kv[1] === masterKey) return true;
  }
  // Fallback: some files use inline tables / unusual formatting. A direct
  // presence check of the exact base58 master key is still strong evidence.
  return toml.includes(masterKey);
}

async function pollOwnDomain(): Promise<void> {
  const masterKey = snapshot.our_pubkey_validator;
  if (!masterKey) return;                 // can't verify without our key yet

  let domain: string | null = null;
  try {
    // `manifest` admin command: details.domain carries the manifest-claimed
    // domain (only present when the validator set one). public_key accepts the
    // master OR ephemeral key (rippled maps it to the master internally).
    const res = await rippledReq<AnyObj>('manifest', { public_key: masterKey });
    const details = (res.result as AnyObj | undefined)?.details as AnyObj | undefined;
    const d = details?.domain;
    domain = typeof d === 'string' && d ? d : null;
  } catch { /* rippled transient, leave domain null, retry next cycle */ }

  if (!domain) {
    publishDomainStatus(null, false);
    return;
  }

  // SSRF guard before any outbound request.
  if (!isSafePublicDomain(domain)) {
    console.warn('[domain] rejected unsafe domain for toml fetch');
    publishDomainStatus(domain, false);   // show the claimed domain, unverified
    return;
  }

  let verified = false;
  try {
    // LOW-07. Redirects are followed by hand so the guard above runs on every
    // hop, not just on the name the manifest claimed. `redirect: 'follow'`
    // checked the first host and then let the responding server choose the
    // rest, which is one 302 away from a request to a link-local address.
    // One deadline covers the whole chain, so extra hops buy no extra time.
    const deadline = AbortSignal.timeout(TOML_FETCH_TIMEOUT_MS);
    let url: string | null = `https://${domain}/.well-known/xrp-ledger.toml`;
    let res: Response | null = null;
    for (let hop = 0; hop <= TOML_MAX_REDIRECTS && url; hop++) {
      const r: Response = await fetch(url, {
        signal: deadline,
        redirect: 'manual',
        headers: { accept: 'text/plain, application/toml, */*' },
      });
      if (r.status < 300 || r.status > 399) { res = r; break; }
      const next = nextTomlHop(url, r.headers.get('location'));
      // Nothing reads a redirect's body, and an unread one holds its socket.
      try { await r.body?.cancel(); } catch { /* already closed */ }
      if (!next) {
        console.warn('[domain] toml fetch redirected somewhere the guard refuses, stopping');
        break;
      }
      url = next;
    }
    if (res?.ok) {
      // Read with a hard size cap so a hostile/huge body can't exhaust memory.
      const reader = res.body?.getReader();
      if (reader) {
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            total += value.byteLength;
            if (total > TOML_MAX_BYTES) { try { await reader.cancel(); } catch { /* ignore */ } break; }
            chunks.push(value);
          }
        }
        if (total <= TOML_MAX_BYTES) {
          const toml = Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
          verified = tomlListsValidator(toml, masterKey);
        }
      } else {
        const toml = (await res.text()).slice(0, TOML_MAX_BYTES);
        verified = tomlListsValidator(toml, masterKey);
      }
    }
  } catch { /* fetch failed / timeout / TLS, unverified, never throws up */ }

  publishDomainStatus(domain, verified);
}

// Broadcast + cache the domain status, only re-emitting when it changed so a
// daily re-check doesn't spam idle browsers.
function publishDomainStatus(domain: string | null, verified: boolean): void {
  const prev = snapshot.domain_status;
  if (prev && prev.domain === domain && prev.verified === verified) return;
  snapshot.domain_status = { domain, verified };
  broadcast('domain_status', { domain, verified });
  if (domain) console.log(`[domain] ${domain} verified=${verified}`);
}

// The publisher block's own staleness clock, when snapshot
// .validator_list_sites was last successfully written. Its own poller, so
// its own age, reported separately from feature_age_ms on the `governance`
// read route rather than folded into one number that would be wrong for
// whichever half moved last.
let sitesAtMs: number | null = null;

async function pollValidatorListSites() {
  try {
    const res = await rippledReq<AnyObj>('validator_list_sites');
    const sites = ((res.result as AnyObj | undefined)?.validator_sites) as AnyObj[] | undefined;
    if (!sites) return;
    snapshot.validator_list_sites = sites;
    sitesAtMs = Date.now();

    // Compute soonest expiry across all configured publisher sites.
    let nextExpiryDays: number | null = null;
    let allHealthy = true;
    for (const s of sites) {
      const exp = (s as AnyObj).list_expiration as string | number | undefined;
      const status = (s as AnyObj).last_refresh_status as string | undefined;
      if (status && status !== 'accepted' && status !== 'same_sequence') allHealthy = false;
      if (exp) {
        // rippled returns ISO string or seconds-since-epoch depending on build
        const t = typeof exp === 'string' ? Date.parse(exp) : Number(exp) * 1000;
        if (Number.isFinite(t)) {
          const days = Math.floor((t - Date.now()) / 86_400_000);
          if (nextExpiryDays === null || days < nextExpiryDays) nextExpiryDays = days;
        }
      }
    }
    broadcast('unl_publishers', {
      site_count: sites.length,
      next_expiry_days: nextExpiryDays,
      all_healthy: allHealthy,
    });
  } catch (err) { /* transient */ }
}

// Logs each unresolved required counter once per (field, build_version). A node
// upgrade that renames a counter re-announces it once.
const warnMissingCounters = createMissWarner((msg) => console.warn('[fork]', msg));

// ── Node-store activity, from get_counts deltas ───────────────────────
//
// The arithmetic and the reasoning live in lib/nodestore-rates.ts, which is
// pure and unit-tested; what stays here is the state a poller needs: the
// previous sample, the last computed rates, and the metric writes.
let prevNodeStore: NodeStoreSample | null = null;
let lastNodeStoreRates: NodeStoreRates | null = null;

function updateNodeStoreRates(result: AnyObj, now: number): void {
  const cur = nodeStoreSample(result, now);
  if (!cur) { prevNodeStore = null; lastNodeStoreRates = null; return; }
  const prev = prevNodeStore;
  if (!prev) { prevNodeStore = cur; return; }
  // Too soon: keep the older baseline rather than replacing it, so the next
  // poll measures a wider window instead of an even narrower one.
  if ((cur.ts - prev.ts) / 1000 < NODESTORE_MIN_INTERVAL_S) return;
  const rates = nodeStoreRatesBetween(prev, cur);
  prevNodeStore = cur;
  if (!rates) { lastNodeStoreRates = null; return; }   // a restart, reseeded above
  lastNodeStoreRates = rates;
  if (rates.read_hit_pct !== null) writeMetric('nodestore_read_hit_pct', rates.read_hit_pct);
  writeMetric('nodestore_reads_per_s', rates.reads_per_s);
  writeMetric('nodestore_writes_per_s', rates.writes_per_s);
}

async function pollGetCounts() {
  try {
    const res = await rippledReq<AnyObj>('get_counts');
    const result = res.result as AnyObj | undefined;
    if (result) {
      snapshot.get_counts = result;
      // Resolve the fork-namespaced object counters to canonical keys so the
      // client reads stable names regardless of the node's ripple::/xrpl::
      // namespace, and flag any that no known alias matched (ADR 0002).
      const canonical = resolveAllCounters(result);
      snapshot.get_counts_canonical = canonical;
      updateNodeStoreRates(result, Date.now());
      const buildVersion = (snapshot.server_info?.build_version as string | undefined) ?? null;
      warnMissingCounters(findMissingRequired(canonical), buildVersion, result);
    }
  } catch (err) { /* transient */ }
}

async function pollValidators() {
  try {
    const res = await rippledReq<AnyObj>('validators');
    const result = (res.result as AnyObj | undefined) ?? {};
    // The trusted UNL master keys live under `trusted_validator_keys`,
    // these are the same nH… master keys the `validationReceived` stream
    // tags each validation with, so the Set lookup matches directly.
    const trusted = new Set<string>();
    const keys = result.trusted_validator_keys as string[] | undefined;
    if (Array.isArray(keys)) for (const k of keys) trusted.add(k);
    snapshot.trusted_unl = trusted;
    // Keep the legacy `validators` snapshot field populated if rippled returns it
    // (it doesn't on current builds, but no harm leaving the assignment).
    if (Array.isArray(result.validators)) snapshot.validators = result.validators;
    broadcast('unl_list', { trusted_count: trusted.size });
  } catch (err) { /* transient */ }
}

// Peer address → bare IP (strips port + IPv4-mapped-IPv6 envelope)
function extractIp(addr?: string): string | undefined {
  if (!addr) return undefined;
  let s = addr;
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    s = end > 0 ? s.slice(1, end) : s;
  } else {
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)(?::\d+)?$/i);
    if (mapped) return mapped[1];
    if ((s.match(/:/g) || []).length === 1) s = s.split(':')[0];
  }
  const mapped2 = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped2) return mapped2[1];
  return s;
}

// Reverse DNS cache. PTR records rarely change so a long TTL (6h) keeps
// network noise low while occasional rotation still gets picked up. Race
// each lookup against a 1.5s timeout so a slow resolver never blocks
// the peer broadcast. Pattern ported from Koi's amm-monitor.
const peerHostCache = new Map<string, { host: string | null; fetchedAt: number }>();
const PEER_HOST_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const RDNS_TIMEOUT_MS = 1500;

async function resolvePeerHost(ip: string): Promise<string | null> {
  const cached = peerHostCache.get(ip);
  if (cached && Date.now() - cached.fetchedAt < PEER_HOST_CACHE_TTL_MS) return cached.host;
  try {
    const hosts = await Promise.race<string[]>([
      dns.reverse(ip),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error('timeout')), RDNS_TIMEOUT_MS)),
    ]);
    const host = hosts && hosts.length > 0 ? hosts[0] : null;
    peerHostCache.set(ip, { host, fetchedAt: Date.now() });
    return host;
  } catch {
    peerHostCache.set(ip, { host: null, fetchedAt: Date.now() });
    return null;
  }
}

// Enrich peers with country (GeoIP, sync) and hostname (rDNS, async with
// cache + per-lookup timeout). Country codes are lowercased so the
// frontend's circle-flags CDN URL works out of the box.
async function enrichPeers(peers: PeerRow[]): Promise<PeerRow[]> {
  return Promise.all(peers.map(async (p) => {
    const ip = extractIp(p.address);
    let country: string | undefined;
    let host: string | undefined;
    if (ip) {
      try {
        const lookup = geoip.lookup(ip);
        if (lookup?.country) country = String(lookup.country).toLowerCase();
      } catch { /* ignore */ }
      const rdns = await resolvePeerHost(ip);
      host = rdns ?? undefined;
    }
    return {
      address: p.address,
      inbound: p.inbound,
      latency: p.latency,
      version: p.version,
      uptime: p.uptime,
      sanity: p.sanity,
      public_key: p.public_key,
      complete_ledgers: p.complete_ledgers,
      country,
      host,
    };
  }));
}

function connectRippled() {
  console.log(`[bridge] connecting to rippled ${RIPPLED_URL}`);
  const ws = new WebSocket(RIPPLED_URL);
  rippled = ws;

  ws.on('open', async () => {
    console.log('[bridge] rippled connected');
    // If we were tracking an ongoing disconnect (startup included), close that window and
    // push it into the history so agreement checks can exclude ledgers
    // that closed during the gap. Prune windows older than 24h.
    if (currentDisconnectStart !== null) {
      const w = { start: currentDisconnectStart, end: Date.now() };
      disconnectWindows.push(w);
      currentDisconnectStart = null;
      while (disconnectWindows.length && Date.now() - disconnectWindows[0].end > ONE_DAY_MS) {
        disconnectWindows.shift();
      }
      const gapS = Math.round((w.end - w.start) / 1000);
      console.log(`[bridge] ${everConnected ? 'reconnect' : 'startup'}: ${gapS}s gap recorded, agreement checks for ledgers closed in [${w.start}..${w.end}] will be skipped as GAP`);
      // Nobody is watching a page during startup; the event is for a page
      // that saw the stream drop.
      if (everConnected) broadcast('stream:reconnected', { gap_start_ms: w.start, gap_end_ms: w.end, gap_s: gapS });
    }
    everConnected = true;
    try {
      ws.send(JSON.stringify({
        id: ++rippledReqId,
        command: 'subscribe',
        // No `transactions` stream, see fetchLedgerFamilies: the firehose
        // overflows the admin port's send_queue_limit and gets us dropped.
        streams: ['ledger', 'validations', 'server', 'peer_status', 'manifests'],
      }));
    } catch { /* ignore */ }
    // Initial pulls, get everything once so the snapshot is rich on first
    // connect. Every one of these calls rippled, which is the amendment library.
    // Pulls used to be in this list too, but they call xrpscan/xrpl.org, not
    // rippled, and belong to the startup-once call near connectRippled()
    // below instead (#542: this event never fires on a fleet aggregator,
    // which runs no local rippled to open).
    await Promise.allSettled([
      pollServerInfo(),
      pollPeers(),
      pollFee(),
      pollConsensusInfo(),
      pollFeature(),
      pollValidators(),
      pollValidatorListSites(),
      pollGetCounts(),
      pollShardCount(),
    ]);
    // Prime governance once the upstream snapshots are populated so browsers
    // landing on /governance.html see real data on first paint instead of
    // waiting 60s for the periodic sampler.
    sampleGovernance();
    broadcast('snapshot', snapshotForBrowser());
  });

  ws.on('message', (buf) => onRippledMessage(buf.toString('utf8')));

  ws.on('close', () => {
    console.log('[bridge] rippled disconnected, reconnecting in 3s');
    // Start tracking the gap, finalized when the next connection opens.
    // Guard against double-firing (error + close both trigger close).
    if (currentDisconnectStart === null) currentDisconnectStart = Date.now();
    rippled = null;
    setTimeout(connectRippled, 3_000);
  });

  ws.on('error', (err) => {
    console.error('[bridge] rippled error:', (err as Error).message);
    try { ws.close(); } catch { /* ignore */ }
  });
}

function snapshotForBrowser() {
  return {
    server_info: snapshot.server_info ?? null,
    // A tab opened DURING an outage must not be told the node is fine by the
    // last good reading. Carried in the connect snapshot, not only in the
    // live broadcast, or a reload during a restart looks healthy.
    node_reach: nodeReachState(),
    peers: snapshot.peers ?? [],     // already enriched by pollPeers
    fee: snapshot.fee ?? null,
    last_ledger: snapshot.last_ledger ?? null,
    our_pubkey_validator: snapshot.our_pubkey_validator ?? null,
    domain_status: snapshot.domain_status ?? null,
    net_stats: lastNetStatsBroadcast,
    governance: lastGovernanceBroadcast,
    amendments: lastAmendmentsBroadcast,
    system: lastSystemBroadcast,
    agreement_stats: computeAgreementStats(),   // so a fresh tab isn't blank on load
    // Without this a tab opened between six-hour polls would show no
    // update badge at all, which reads as "you are current". Built through
    // buildReleaseInfoPayload (#550) so this carries self_release_posture
    // exactly like the /release-info route and the two release_info
    // broadcasts below. snapshot.release_info gates presence (no reading
    // yet stays null; a real one, however old, still carries the posture).
    release_info: snapshot.release_info ? buildReleaseInfoPayload() : null,
  };
}

// ── Governance derivation ─────────────────────────────────────────────
// Reads the already-polled feature / validators / validator_list_sites /
// server_info snapshots and the unlActiveLog and produces the payload the
// Governance tab renders. The amendment figures come from
// lib/amendments.ts and the publisher block from lib/publishers.ts, the
// same builders the `amendment-ballot` and `governance` read routes call,
// so this node's own page and a peer's view of it can never disagree.

let lastGovernanceBroadcast: unknown = null;
let lastAmendmentsBroadcast: unknown = null;

// Guarded so a page reloaded repeatedly while the summary is still missing
// asks rippled once, not once per tab.
let featurePollInFlight = false;
function kickFeaturePoll(): void {
  if (featurePollInFlight) return;
  featurePollInFlight = true;
  pollFeature()
    .catch(() => { /* transient, the five-minute schedule still applies */ })
    .finally(() => { featurePollInFlight = false; });
}

/** Who is asking, for the one peer answer that names a file on this host
 *  (lib/peer-advisor-answer.ts, tokenUnreadableFor): an administrator gets the
 *  path, owner and mode, everyone else a general sentence. Read from the
 *  session, never from the request. */
function peerViewer(req: Parameters<typeof readSession>[0], label: string): Viewer {
  const sess = readSession(req);
  return { admin: !!sess && isAdmin(sess.role), label };
}

function sampleGovernance() {
  const info = (snapshot.server_info as AnyObj | undefined) ?? {};
  const features = snapshot.feature as Record<string, AnyObj> | undefined;
  const sites = (snapshot.validator_list_sites as AnyObj[] | undefined) ?? [];
  const unlSize = snapshot.trusted_unl?.size ?? 0;

  const nowMs = Date.now();

  // ── Amendments ────────────────────────────────────────────────────
  // Every figure below comes from lib/amendments.ts, the same three
  // functions the `amendment-ballot` and `governance` read routes call. This
  // block used to be a hand-written loop that duplicated the row builder and
  // the summary; the copies drifted, and a peer's Governance tab could show
  // a different ballot from the node's own. One definition, two views.
  const featureEntries = (features ?? {}) as Record<string, AmendmentFeatureEntry>;
  const counted = amendmentVotes.current();
  const summary = buildAmendmentVoteSummary(featureEntries, counted);
  const pendingList = buildAmendmentBallotRows(
    featureEntries, snapshot.xrpscan_amendments, snapshot.amendment_descriptions, counted,
  );
  const nextActivation = nextActivationFromRows(pendingList);

  // ── UNL activity ──────────────────────────────────────────────────
  const activeKeys = new Set<string>();
  for (const r of unlActiveLog) {
    if (nowMs - r.ts <= ONE_HOUR_MS) activeKeys.add(r.master_key);
  }
  const unlActive1h = activeKeys.size;
  const unlOffline = Math.max(0, unlSize - unlActive1h);
  const expectedQuorum = Math.ceil(unlSize * 0.8);

  // ── Publishers ────────────────────────────────────────────────────
  // lib/publishers.ts, the same builder the `governance` read route calls.
  const pubs = buildPublisherSummary(sites as ValidatorListSiteEntry[], nowMs);

  const payload = {
    amendment_blocked: Boolean(info.amendment_blocked),
    amendments: {
      // Header count mirrors what the table actually shows, every
      // non-enabled non-obsolete amendment, including ones this build
      // can't vote on. supported_pending stays available for any UI
      // that wants the validator's-build-can-vote subset.
      pending_count: pendingList.length,
      supported_pending_count: summary.supported_pending,
      approaching_threshold_count: summary.approaching,
      threshold_met_count: summary.threshold_met,
      enabled_count: summary.enabled,
      supported_count: summary.supported,
      vetoed_count: summary.vetoed,
      our_votes: summary.our_votes,
      next_activation_status: nextActivation.status,
      next_activation_name: nextActivation.name,
      pending: pendingList,
      // #542: the descriptions/xls_url on the rows above come from
      // amendmentsLibraryAtMs's own file, refreshed on its own clock
      // (startup, daily, or opportunistically off an xrpscan diff). Not
      // from this 60s sampler. Served here so the tab can say how old that
      // library is instead of a file that always looks current.
      library_age_ms: amendmentsLibraryAtMs != null ? (nowMs - amendmentsLibraryAtMs) : null,
    },
    unl: {
      size: unlSize,
      active_1h: unlActive1h,
      offline: unlOffline,
      expected_quorum: expectedQuorum,
    },
    publishers: pubs,
    build_version: (info.build_version as string | undefined) ?? null,
  };

  lastGovernanceBroadcast = payload;
  broadcast('governance', payload);
}

setInterval(sampleGovernance, 60_000);

// ────────────────────────────────────────────────────────────────────────
// Local /proc system reader
//
// In Pattern 1 (dashboard on the validator host), the bridge reads /proc
// directly and pushes a `system` message every 5s. The same JSON shape will
// be emitted by the standalone Aperire relay in Patterns 2 and 3, so the
// frontend handler is unchanged.
// ────────────────────────────────────────────────────────────────────────

let prevCpuStat: { idle: number; total: number; iowait: number; steal: number } | null = null;

function parseMeminfoBytes(meminfo: string, key: string): number {
  const re = new RegExp('^' + key + ':\\s+(\\d+)\\s*kB', 'm');
  const m = meminfo.match(re);
  return m ? Number(m[1]) * 1024 : 0;
}

async function readCpu(): Promise<{ busy_pct: number; iowait_pct: number; steal_pct: number; cores: number; load_1m: number; load_5m: number; load_15m: number }> {
  const [statRaw, loadRaw] = await Promise.all([
    readFile('/proc/stat', 'utf-8'),
    readFile('/proc/loadavg', 'utf-8'),
  ]);
  // /proc/stat first line: "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
  const fields  = statRaw.split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
  const iowait  = fields[4] ?? 0;
  const steal   = fields[7] ?? 0;
  const idle    = (fields[3] ?? 0) + iowait;     // fold iowait into idle for busy%
  const total   = fields.reduce((a, b) => a + b, 0);
  let busy_pct = 0, iowait_pct = 0, steal_pct = 0;
  if (prevCpuStat) {
    const idleDelta   = idle   - prevCpuStat.idle;
    const totalDelta  = total  - prevCpuStat.total;
    const iowaitDelta = iowait - prevCpuStat.iowait;
    const stealDelta  = steal  - prevCpuStat.steal;
    if (totalDelta > 0) {
      busy_pct   = (1 - idleDelta   / totalDelta) * 100;
      iowait_pct = (iowaitDelta     / totalDelta) * 100;
      steal_pct  = (stealDelta      / totalDelta) * 100;
    }
  }
  prevCpuStat = { idle, total, iowait, steal };

  const [m1, m5, m15] = loadRaw.trim().split(/\s+/).map(Number);
  return { busy_pct, iowait_pct, steal_pct, cores: cpus().length, load_1m: m1, load_5m: m5, load_15m: m15 };
}

async function readMemAndSwap(): Promise<{ memory: AnyObj; swap: AnyObj }> {
  const m = await readFile('/proc/meminfo', 'utf-8');
  const memTotal = parseMeminfoBytes(m, 'MemTotal');
  const memAvail = parseMeminfoBytes(m, 'MemAvailable');
  const memFree  = parseMeminfoBytes(m, 'MemFree');
  const memUsed  = memTotal - memAvail;
  // Page cache: reclaimable file cache the kernel is holding. MemAvailable
  // already counts it as available, so used + cache + free is the whole of
  // RAM. On a validator it is mostly node-store pages, which is why it is
  // worth its own row and its own series: a cache that collapses is the
  // reads about to go to disk. Clamped at zero (MemAvailable is the
  // kernel's estimate and can sit a hair under MemFree on a box with almost
  // nothing cached).
  const memCache = Math.max(0, memAvail - memFree);
  const swapTotal = parseMeminfoBytes(m, 'SwapTotal');
  const swapFree  = parseMeminfoBytes(m, 'SwapFree');
  const swapUsed  = swapTotal - swapFree;
  return {
    memory: {
      used_pct:    memTotal ? (memUsed / memTotal) * 100 : 0,
      used_bytes:  memUsed,
      total_bytes: memTotal,
      cache_bytes: memCache,
      cache_pct:   memTotal ? (memCache / memTotal) * 100 : 0,
    },
    swap: {
      used_pct:    swapTotal ? (swapUsed / swapTotal) * 100 : 0,
      used_bytes:  swapUsed,
      total_bytes: swapTotal,
    },
  };
}

async function readDisk(mount: string): Promise<AnyObj> {
  const s = await statfs(mount);
  const totalBytes = Number(s.blocks) * Number(s.bsize);
  const freeBytes  = Number(s.bfree)  * Number(s.bsize);
  const usedBytes  = totalBytes - freeBytes;
  return {
    used_pct:    totalBytes ? (usedBytes / totalBytes) * 100 : 0,
    used_bytes:  usedBytes,
    total_bytes: totalBytes,
    mount,
  };
}

// Pressure Stall Information: "some avg10" percentage per resource.
// Returns 0 if the file is missing (kernel < 4.20 or PSI disabled).
async function readPressureSome(path: string): Promise<number> {
  try {
    const raw = await readFile(path, 'utf-8');
    for (const line of raw.split('\n')) {
      if (!line.startsWith('some ')) continue;
      const m = line.match(/avg10=(\d+(?:\.\d+)?)/);
      if (m) return Number(m[1]);
    }
  } catch { /* PSI unavailable, degrade to 0 */ }
  return 0;
}

// Cache the most recently measured NuDB size so the system broadcast can
// include it between 1-minute samples. Null when RIPPLED_DATA_PATH is
// empty, when the first sample hasn't landed yet, and when the last walk
// could not be taken: the three are told apart by the two fields below and
// on the page, never by a number standing in for any of them.
let lastNudbSize: number | null = null;
// The last walk's failure, or null while walks succeed. Read by the page
// beside `rippled_data_path`, so "set but unreadable" has its own name.
//
// #427: this could never fire for the case it was written for. The walk
// swallowed every failure, its own root included, and returned 0, so a
// store the dashboard has no permission to open reported a successful
// sample of zero bytes. The read propagates a root failure now
// (lib/store-size.ts) and this carries the reason.
let lastNudbWalkError: string | null = null;
// The two together, as the one fact the broadcast and the derivations both
// ask about.
function nudbReading(): StoreReading {
  return { bytes: lastNudbSize, error: lastNudbWalkError };
}

// Days-to-full when the store is not growing. The metric needs a number on
// those days so its alert rule can resolve; see the write site in
// pushSystem() for why omitting it would leave an alert stuck firing.
const NOT_GROWING_DAYS = 3650;
let lastFreeDaysWrite = 0;

// The two `nudb_size` reads the system push needs, together, at most once a
// minute (#119's rule: attribute the storm, then cache at the cadence the
// input actually moves). The samples themselves are written once a minute by
// the directory walk, so asking more often than that cannot change the
// answer — and asking on every 5s push meant a 30-day scan twelve times a
// minute, ~43k rows each, for a series whose newest point is a minute old.
//
// The 30-day series is `max` per bucket on purpose: the daily-peak fit and
// the rotation scan both want the top of each tooth, and an average would
// blunt exactly the feature they read. At 30 days the buckets are 4 hours
// wide (bucketForRange), so a rotation is timed to the bucket it landed in.
//
// One cache per series: the dashboard's own walks (`nudb_size`) and the
// Advisor's readings of this store (`nudb_size_advisor`, #1245), which a
// host is derived from one at a time and never both.
type NudbSampleSet = { at: number; cutS: number; peak24h: number | null; window30d: HistoryPoint[] };
const nudbSampleCache: Record<StoreSeries, NudbSampleSet | null> = { own: null, advisor: null };
const NUDB_SAMPLE_METRIC: Record<StoreSeries, MetricName> = { own: 'nudb_size', advisor: 'nudb_size_advisor' };
const NUDB_SAMPLE_TTL_MS = 60_000;
function nudbSamples(series: StoreSeries, now: number): { peak24h: number | null; window30d: HistoryPoint[] } {
  // Both series start at the store's cut (#1251), read in the SQL so a bucket
  // that straddles it holds only the rows after it. A cache from before a cut
  // is not served after one.
  const cutS = storeSeries?.cutS() ?? 0;
  const cached = nudbSampleCache[series];
  if (cached && cached.cutS === cutS && now - cached.at < NUDB_SAMPLE_TTL_MS) return cached;
  const metric = NUDB_SAMPLE_METRIC[series];
  const day = queryHistory(metric, 24 * 3600_000, 'avg', cutS);
  const month = queryHistory(metric, 30 * 86_400_000, 'max', cutS);
  const peak24h = day.length ? day.reduce((m, p) => (p.value > m ? p.value : m), day[0].value) : null;
  const fresh = { at: now, cutS, peak24h, window30d: month };
  nudbSampleCache[series] = fresh;
  return fresh;
}

// ── Clock sync + drift ────────────────────────────────────────────────
// timedatectl is available on every systemd host (which covers virtually
// all modern validator installs). chronyc is available where chrony is
// the active NTP daemon; we fall back to a null drift reading when it's
// missing (operator sees "," rather than a made-up value).
async function readClock(): Promise<{ ntp_synced: boolean | null; time_drift_ms: number | null }> {
  let ntp_synced: boolean | null = null;
  let time_drift_ms: number | null = null;
  try {
    const { stdout } = await execFileAsync('timedatectl', ['show', '--property=NTPSynchronized'], { timeout: 2000 });
    ntp_synced = /NTPSynchronized=yes/i.test(stdout);
  } catch { /* timedatectl not available, leave null */ }
  try {
    const { stdout } = await execFileAsync('chronyc', ['tracking'], { timeout: 2000 });
    // "System time     : 0.000082597 seconds slow of NTP time"
    const m = stdout.match(/System time\s*:\s*([\d.]+)\s*seconds\s*(fast|slow)/i);
    if (m) {
      const sign = m[2].toLowerCase() === 'slow' ? -1 : 1;
      time_drift_ms = Number(m[1]) * 1000 * sign;
    }
  } catch { /* chrony not installed or not active, leave null */ }
  return { ntp_synced, time_drift_ms };
}

// ── rippled process metrics (CPU, RSS, threads, FDs) ──────────────────
// PID discovery order: explicit env var > PID file > `pgrep -x rippled`.
// Docker works because the container's PIDs are still visible in the
// host's /proc; the host-level PID is what pgrep returns.
let cachedRippledPid: number | null = null;
let cachedRippledPidAt = 0;

async function findRippledPid(): Promise<number | null> {
  const now = Date.now();
  // Cache for 5 minutes, rippled restarts are rare and we don't want
  // to pgrep on every broadcast tick.
  if (cachedRippledPid && now - cachedRippledPidAt < 5 * 60_000) return cachedRippledPid;
  if (process.env.RIPPLED_PID) {
    cachedRippledPid = Number(process.env.RIPPLED_PID);
    cachedRippledPidAt = now;
    return cachedRippledPid;
  }
  if (process.env.RIPPLED_PID_FILE) {
    try {
      const data = await readFile(process.env.RIPPLED_PID_FILE, 'utf-8');
      cachedRippledPid = Number(data.trim()) || null;
      cachedRippledPidAt = now;
      return cachedRippledPid;
    } catch { /* fall through to pgrep */ }
  }
  // Fast path: pgrep each known binary name (rippled / xrpld / xahaud). comm is
  // capped at 15 chars and the xrpld image's comm is "xrpld-main", so a hit
  // here isn't guaranteed for every build, the /proc scan below is the
  // catch-all. The name list is the shared BINARY_NAMES registry (ADR 0002).
  //
  // Every name can match more than one process: the xrpld image's `xrpld
  // server_info` CLI (a health check, the advisor's wrapper) is a short-lived
  // process whose comm is exactly "xrpld" while the daemon's is "xrpld-main",
  // so `pgrep -x xrpld` finds the CLI and never the daemon. Whichever way a
  // candidate was found, the daemon is the oldest one: a CLI call lives for
  // a second, the daemon for days. Candidates are gathered from every source
  // and the oldest wins, so a transient never becomes the cached pid (which
  // is what produced the impossible CPU samples #203: the CPU delta of one
  // process measured against the counters of another).
  const candidates = new Set<number>();
  for (const name of BINARY_NAMES) {
    try {
      const { stdout } = await execFileAsync('pgrep', ['-x', name], { timeout: 2000 });
      for (const line of stdout.trim().split('\n')) {
        const pid = Number(line);
        if (pid > 0) candidates.add(pid);
      }
    } catch { /* not running under this name, or pgrep missing, try next */ }
  }
  // Fallback for containerized / renamed rippled. The binary isn't always
  // named "rippled": the xrpllabsofficial/xrpld image ships it as
  // `/usr/bin/xrpld` (comm reads "xrpld-main"), and Xahau ships `xahaud`.
  // `pgrep -x rippled` matches against comm and misses all of these, so we
  // scan /proc for a process whose argv[0] basename is one of the known
  // rippled-family binaries. /proc/<pid>/cmdline is world-readable (unlike
  // /proc/<pid>/exe, which needs ptrace access to another user's process), and
  // matching argv[0] skips the docker-init/tini wrapper whose argv[0] is the
  // init shim. Override the set with RIPPLED_PROC_NAMES (comma-separated).
  const procNames = new Set(
    process.env.RIPPLED_PROC_NAMES
      ? process.env.RIPPLED_PROC_NAMES.split(',').map((s) => s.trim()).filter(Boolean)
      : BINARY_NAMES,
  );
  try {
    for (const name of await readdir('/proc')) {
      if (!/^\d+$/.test(name)) continue;
      let cmdline: string;
      try { cmdline = await readFile(`/proc/${name}/cmdline`, 'utf-8'); }
      catch { continue; }
      const argv0 = cmdline.split('\0')[0];
      const base  = argv0 ? argv0.split('/').pop() : '';
      if (base && procNames.has(base)) candidates.add(Number(name));
    }
  } catch { /* /proc unreadable, keep what pgrep found */ }
  const oldest = await oldestProcess([...candidates]);
  if (oldest !== null) {
    cachedRippledPid = oldest;
    cachedRippledPidAt = now;
    return oldest;
  }
  return null;
}

/** The pid with the smallest start time (/proc/<pid>/stat field 22, in
 *  clock ticks since boot). A pid whose stat can't be read has already
 *  exited and is skipped. */
async function oldestProcess(pids: number[]): Promise<number | null> {
  let best: number | null = null;
  let bestStart = Infinity;
  for (const pid of pids) {
    let statRaw: string;
    try { statRaw = await readFile(`/proc/${pid}/stat`, 'utf-8'); }
    catch { continue; }
    const fields = statRaw.slice(statRaw.lastIndexOf(')') + 2).split(/\s+/).map(Number);
    // After comm removal: 19=starttime (per man 5 proc, field 22 overall).
    const start = fields[19];
    if (!Number.isFinite(start)) continue;
    if (start < bestStart) { bestStart = start; best = pid; }
  }
  return best;
}

// The previous sample is bound to the pid it was read from. A delta between
// two processes (a restart, or a transient CLI that briefly won the pid
// scan) is not a CPU reading: the new process starts its counters at zero,
// so the delta came out as millions of percent, negative or positive, and
// the 7d chart's y-axis followed it off the card (#203). A pid change now
// yields one tick with no delta, exactly like the first tick after startup.
let prevRippledStat: { pid: number; utime: number; stime: number; totalJiffies: number } | null = null;

async function readRippledProcess(): Promise<{ pid: number | null; cpu_pct: number; rss_bytes: number | null; threads: number | null }> {
  const pid = await findRippledPid();
  if (!pid) return { pid: null, cpu_pct: 0, rss_bytes: null, threads: null };
  try {
    const [statRaw, statusRaw, totalStatRaw] = await Promise.all([
      readFile(`/proc/${pid}/stat`, 'utf-8'),
      readFile(`/proc/${pid}/status`, 'utf-8'),
      readFile('/proc/stat', 'utf-8'),
    ]);
    // /proc/<pid>/stat: comm field is wrapped in parens and can contain
    // spaces, so we skip past the last `)` before splitting.
    const afterComm = statRaw.slice(statRaw.lastIndexOf(')') + 2);
    const fields    = afterComm.split(/\s+/).map(Number);
    // After comm removal: 0=state 1=ppid ... 11=utime 12=stime (per man 5 proc)
    const utime = fields[11] || 0;
    const stime = fields[12] || 0;
    const totalFields = totalStatRaw.split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
    const totalJiffies = totalFields.reduce((a, b) => a + b, 0);

    let cpu_pct = 0;
    if (prevRippledStat && prevRippledStat.pid === pid) {
      const procDelta  = (utime - prevRippledStat.utime) + (stime - prevRippledStat.stime);
      const totalDelta = totalJiffies - prevRippledStat.totalJiffies;
      // A process's CPU counters only grow, and it cannot use more than every
      // core for the whole window. Either bound broken means the pid was
      // reused by another process between two reads: no reading this tick.
      const cores = cpus().length;
      if (totalDelta > 0 && procDelta >= 0 && procDelta <= totalDelta) {
        // Multiply by core count so a fully-busy multi-core rippled reads
        // as >100% (industry convention matching top / htop).
        cpu_pct = (procDelta / totalDelta) * 100 * cores;
      }
    }
    prevRippledStat = { pid, utime, stime, totalJiffies };

    const rssMatch     = statusRaw.match(/^VmRSS:\s+(\d+)\s*kB/m);
    const threadsMatch = statusRaw.match(/^Threads:\s+(\d+)/m);
    return {
      pid,
      cpu_pct,
      rss_bytes: rssMatch ? Number(rssMatch[1]) * 1024 : null,
      threads:   threadsMatch ? Number(threadsMatch[1]) : null,
    };
  } catch {
    return { pid: null, cpu_pct: 0, rss_bytes: null, threads: null };
  }
}

// ── Disk I/O stats from /proc/diskstats ─────────────────────────────
// Kernel format (cols, 0-indexed after split):
//   0: major   1: minor   2: name
//   3: reads_completed  5: sectors_read     6: ms_reading
//   7: writes_completed 9: sectors_written 10: ms_writing
//  12: ms_doing_ios (used for util %)
// Sectors are 512 bytes. We sum across "whole-disk" devices (sda, nvme0n1,
// vda, etc.) and skip their partitions + loop/ram/dm-*/sr* noise.
const DISK_WHOLE_RE = /^(sd[a-z]|nvme\d+n\d+|vd[a-z]|xvd[a-z]|hd[a-z])$/;

interface DiskStatSnap {
  reads: number;
  sectorsRead: number;
  writes: number;
  sectorsWritten: number;
  ioTimeMs: number;
}
let prevDiskStats: Map<string, DiskStatSnap> | null = null;
let prevDiskStatsAt = 0;

async function readDiskIo(): Promise<{
  read_iops: number; write_iops: number;
  read_bps:  number; write_bps:  number;
  util_pct:  number;
} | null> {
  let raw: string;
  try { raw = await readFile('/proc/diskstats', 'utf-8'); }
  catch { return null; }
  const now = Date.now();
  const current = new Map<string, DiskStatSnap>();
  for (const line of raw.split('\n')) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 14) continue;
    const name = fields[2];
    if (!DISK_WHOLE_RE.test(name)) continue;
    current.set(name, {
      reads:          Number(fields[3])  || 0,
      sectorsRead:    Number(fields[5])  || 0,
      writes:         Number(fields[7])  || 0,
      sectorsWritten: Number(fields[9])  || 0,
      ioTimeMs:       Number(fields[12]) || 0,
    });
  }

  // Derive rates from the delta between this snapshot and the previous.
  // util_pct is the MAX across all included devices (the "worst disk"
  // signal is what matters for operators watching for I/O Chop). IOPS
  // and Bps aggregate across devices so a validator with split data +
  // log volumes shows its total throughput.
  let read_iops = 0, write_iops = 0, read_bps = 0, write_bps = 0, util_pct = 0;
  if (prevDiskStats && prevDiskStatsAt > 0) {
    const intervalMs  = now - prevDiskStatsAt;
    const intervalSec = intervalMs / 1000;
    if (intervalSec > 0) {
      for (const [name, cur] of current) {
        const prev = prevDiskStats.get(name);
        if (!prev) continue;
        const dReads        = cur.reads          - prev.reads;
        const dWrites       = cur.writes         - prev.writes;
        const dReadSectors  = cur.sectorsRead    - prev.sectorsRead;
        const dWriteSectors = cur.sectorsWritten - prev.sectorsWritten;
        const dIoTime       = cur.ioTimeMs       - prev.ioTimeMs;
        if (dReads        > 0) read_iops  += dReads        / intervalSec;
        if (dWrites       > 0) write_iops += dWrites       / intervalSec;
        if (dReadSectors  > 0) read_bps   += (dReadSectors  * 512) / intervalSec;
        if (dWriteSectors > 0) write_bps  += (dWriteSectors * 512) / intervalSec;
        if (dIoTime       > 0) {
          const u = (dIoTime / intervalMs) * 100;
          if (u > util_pct) util_pct = u;
        }
      }
    }
  }
  prevDiskStats = current;
  prevDiskStatsAt = now;
  // Cap util at 100, a single device can saturate over a short interval
  // and produce a value >100% due to queued requests; that's correct per
  // kernel docs but confusing for operators. Clamp.
  return {
    read_iops, write_iops, read_bps, write_bps,
    util_pct: Math.min(100, util_pct),
  };
}

// ── Host metadata: uptime, entropy, inode usage ─────────────────────
// Static host identity is read once at startup and cached. These values
// don't change between reboots, so there's no point re-reading every tick.
interface HostMeta {
  hostname: string;
  os_name: string;
  kernel: string;
  architecture: string;
}
let hostMeta: HostMeta | null = null;
async function initHostMeta(): Promise<void> {
  let osName = osType();
  try {
    const raw = await readFile('/etc/os-release', 'utf-8');
    const m = raw.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
    if (m) osName = m[1];
  } catch { /* not a systemd host, fall back to os.type() */ }
  hostMeta = {
    hostname:     osHostname(),
    os_name:      osName,
    kernel:       osRelease(),
    architecture: osArch(),
  };
}
initHostMeta();
// The host block as the `system` broadcast carries it. The hostname is read
// when the frame is built, not once at start: the relay's first frame comes
// after startup, and on a split install it is what names the node's machine
// (#1284). Same resolver as the alerts and node-status.
function hostMetaNow(): HostMeta | null {
  return hostMeta ? { ...hostMeta, hostname: hostnameForAlerts() } : null;
}

async function readHostUptime(): Promise<number | null> {
  try {
    const raw = await readFile('/proc/uptime', 'utf-8');
    const n = Number(raw.trim().split(/\s+/)[0]);
    return Number.isFinite(n) ? n : null;
  } catch { return null; }
}

async function readEntropyAvail(): Promise<number | null> {
  try {
    const raw = await readFile('/proc/sys/kernel/random/entropy_avail', 'utf-8');
    const n = Number(raw.trim());
    return Number.isFinite(n) ? n : null;
  } catch { return null; }
}

async function readInodeUsage(mount: string): Promise<number | null> {
  try {
    const s = await statfs(mount);
    const total = Number(s.files) || 0;
    const free  = Number(s.ffree) || 0;
    if (total <= 0) return null;
    return ((total - free) / total) * 100;
  } catch { return null; }
}

// rippled process uptime, derived from /proc/<pid>/stat starttime (clock
// ticks since host boot) combined with /proc/uptime (host uptime in s).
// Assumes CLK_TCK=100, which matches virtually every modern Linux kernel.
async function readRippledUptime(): Promise<number | null> {
  const pid = await findRippledPid();
  if (!pid) return null;
  try {
    const [statRaw, uptimeRaw] = await Promise.all([
      readFile(`/proc/${pid}/stat`, 'utf-8'),
      readFile('/proc/uptime', 'utf-8'),
    ]);
    const afterComm = statRaw.slice(statRaw.lastIndexOf(')') + 2);
    const fields = afterComm.split(/\s+/).map(Number);
    // proc(5) field 22 (starttime) = position 19 after dropping pid + comm.
    const starttime = fields[19] || 0;
    const hostUptime = Number(uptimeRaw.trim().split(/\s+/)[0]) || 0;
    const startedSecondsAgo = hostUptime - (starttime / 100);
    return Math.max(0, startedSecondsAgo);
  } catch { return null; }
}

// Cumulative OOM-kill count from /proc/vmstat. Missing on some kernels.
async function readOomKills(): Promise<number> {
  try {
    const raw = await readFile('/proc/vmstat', 'utf-8');
    for (const line of raw.split('\n')) {
      if (line.startsWith('oom_kill ')) return Number(line.split(/\s+/)[1]) || 0;
    }
  } catch { /* ignore */ }
  return 0;
}

async function pushSystem() {
  try {
    // #546. Cheap next to everything else this function reads: a stat() that
    // catches an approved config change (or a hand edit) on the very next
    // broadcast, rather than leaving the System tab's node_db_cfg answering
    // with whatever this process parsed at startup for as long as it stays up.
    await refreshRippledCfgIfChanged();
    // The local readers always run: they are cheap, and readCpu() keeps its
    // jiffy baseline warm so a fall-back to local never starts from a
    // cold 0%. Whether their values are USED is the source's decision.
    const [localCpu, localMs, localDisk, localPCpu, localPMem, localPIo, localOom, clock, rippled, diskIo,
           hostUptime, entropy, inodeUsage, rippledUptime] = await Promise.all([
      readCpu(),
      readMemAndSwap(),
      readDisk(DATA_MOUNT).catch(() => null),
      readPressureSome('/proc/pressure/cpu'),
      readPressureSome('/proc/pressure/memory'),
      readPressureSome('/proc/pressure/io'),
      readOomKills(),
      readClock(),
      readRippledProcess(),
      readDiskIo(),
      readHostUptime(),
      readEntropyAvail(),
      readInodeUsage(DATA_MOUNT),
      readRippledUptime(),
    ]);

    const src = hostMetricsSource(lastRelaySystem, Date.now(), osHostname());
    let cpu: AnyObj | null, memory: AnyObj | null, swap: AnyObj | null, disk: AnyObj | null;
    let pressure: AnyObj | null, oom: number | null;
    if (src.source === 'relay' && src.fresh) {
      const r = src.sys;
      cpu = {
        busy_pct: r.cpu.busy_pct,
        iowait_pct: typeof r.cpu.iowait_pct === 'number' ? r.cpu.iowait_pct : null,
        steal_pct:  typeof r.cpu.steal_pct  === 'number' ? r.cpu.steal_pct  : null,
        cores: r.cpu.cores, load_1m: r.cpu.load_1m, load_5m: r.cpu.load_5m, load_15m: r.cpu.load_15m,
      };
      // Named field by field rather than passed through, so a relay older
      // than the cache fields reads as "not reported" (null) here instead of
      // arriving as undefined and rendering as a zero cache further down.
      memory = {
        used_pct: r.memory.used_pct,
        used_bytes: r.memory.used_bytes,
        total_bytes: r.memory.total_bytes,
        cache_bytes: typeof r.memory.cache_bytes === 'number' ? r.memory.cache_bytes : null,
        cache_pct: typeof r.memory.cache_pct === 'number' ? r.memory.cache_pct : null,
      };
      swap = r.swap; disk = r.disk;
      pressure = { cpu: r.pressure_cpu_some_pct, memory: r.pressure_memory_some_pct, io: r.pressure_io_some_pct };
      oom = r.oom_kills_total;
    } else if (src.source === 'relay') {
      cpu = null; memory = null; swap = null; disk = null; pressure = null; oom = null;
    } else {
      cpu = localCpu; memory = localMs.memory; swap = localMs.swap; disk = localDisk;
      pressure = { cpu: localPCpu, memory: localPMem, io: localPIo };
      oom = localOom;
    }
    // Derive the NuDB 24h peak (high-water mark) and the remaining-days
    // estimate from the metrics timeseries. The peak is the largest size seen
    // in the window, always >= the current size, never negative, and
    // meaningful even on a pruned validator (it marks the top of the
    // sawtooth). Before any samples exist we broadcast nulls, the honest
    // signal rather than an invented value.
    //
    // #199. The growth half is a fit of the DAILY PEAKS over the retained
    // window, not first-vs-last over 24 hours. See lib/nudb-growth.ts for why
    // the old form could not work on a store running online_delete: it read a
    // healthy node as unmeasurable and read one sample pair straddling a
    // rotation as a confident 82 days.
    // One clock for the whole of it: the page's size and the derivations
    // answer the same question ("is the Advisor's reading current?"), and two
    // calls to Date.now() can answer it differently at the three-minute edge.
    const pushedAt = Date.now();
    let nudbPeakBytes24h: number | null = null;
    let mountFreeDaysEst: number | null = null;
    let nudbGrowth: NudbGrowth | null = null;
    // The same number again, but as a metric an alert rule can watch, which
    // needs one thing the broadcast does not: a value on the days the store
    // is NOT growing. Null there is right for the UI, and wrong for a rule,
    // a rule only advances or resolves on a fresh write, so a metric that
    // stops being written leaves a firing alert firing forever. So "not
    // growing" is written as a large number rather than omitted. It is a
    // measurement, not a filler: at this growth rate the mount does not fill,
    // and ten years says so without pretending to be an estimate of anything.
    let freeDaysMetric: number | null = null;
    // #427. Every one of these is derived from the store's own history, and
    // none of them may be derived while the store itself could not be read.
    // The series outlives the store that filled it: on a host whose node was
    // replaced, the card said NUDB SIZE 0 B and NUDB PEAK 24H 42.70 GB in
    // adjacent rows, one of them a walk that failed and one of them last
    // week's node. deriveFromStore returns nothing at all when the reading
    // was not taken, the free-days metric write included.
    if (RIPPLED_DATA_PATH) {
      const diskFree = (disk && disk.total_bytes != null && disk.used_bytes != null)
        ? (disk.total_bytes as number) - (disk.used_bytes as number)
        : null;
      const basis = storeToDeriveFrom(nudbReading(), advisorStoreReading, pushedAt, RIPPLED_DATA_PATH);
      const derived = deriveFromStore(
        basis.reading,
        basis.series ? nudbSamples(basis.series, pushedAt) : { peak24h: null, window30d: [] },
        diskFree,
        NOT_GROWING_DAYS,
      );
      nudbPeakBytes24h = derived.peak_bytes_24h;
      nudbGrowth = derived.growth;
      mountFreeDaysEst = derived.free_days_est;
      freeDaysMetric = derived.free_days_metric;
    }
    // The size the page shows, and who measured it. Everything above is
    // derived from the series of sizes, which holds this process's own walks
    // and, where it cannot walk the store, the Advisor's readings (#1245);
    // this says which of the two the number on the card is.
    const storeOnThePage = storeForThePage(nudbReading(), advisorStoreReading, pushedAt);
    // Once a minute, not once per 5s push: this is derived from a multi-day
    // window and does not move faster than the walk that feeds it.
    if (freeDaysMetric !== null && Date.now() - lastFreeDaysWrite >= 60_000) {
      lastFreeDaysWrite = Date.now();
      writeMetric('nudb_mount_free_days', freeDaysMetric);
    }
    lastSystemBroadcast = {
      cpu, memory, swap, disk,
      pressure,
      oom_kills: oom,
      // Where the six blocks above came from, so a page can say so. `stale`
      // is only ever true for a relay that went quiet on a split deployment;
      // the blocks are null in that case.
      host_metrics: {
        source: src.source,
        stale: src.source === 'relay' && !src.fresh,
        age_ms: src.source === 'relay' ? src.age_ms : 0,
        hostname: src.hostname,
      },
      // The relay's own build ref (#266's `lastRelayVersion`), run through
      // the same sanitizer the update-state route and the drift check use,
      // so `dev` (unstamped) and a malformed value both collapse to "not
      // measured" here exactly as they do everywhere else this field is
      // read, rather than a fourth definition of that fact living on the
      // System tab alone. This object is `lastSystemBroadcast`, the wider
      // superset read-payloads.ts's buildSystemFields names fields from one
      // at a time rather than spreading (see that file's own header
      // comment). This field is deliberately NOT one of the ones it names,
      // so it never reaches SystemResponse. A peer's page reads it off the
      // `node-status` route instead (#593), the one every fleet poll already
      // fetches, where it is carried as `relay_version`; carrying it on both
      // routes would be two copies of one fact. This copy feeds the local
      // page, off the WS `system` broadcast this object also feeds.
      relay_version: sanitizeComponents({ relay: lastRelayVersion ?? '' }).relay ?? null,
      // #198. Node-store activity over the last get_counts interval, or null
      // when no usable pair exists yet (first poll after a start, or a pair
      // that spanned a rippled restart). Never zeroed into looking idle.
      nodestore: lastNodeStoreRates,
      nudb_size_bytes: storeOnThePage.bytes,
      // Who took the reading above, when it was not this process. Null on
      // every host that measured its own store, which is the ordinary case,
      // and null again where nobody measured it at all. #427: a number the
      // Advisor took a minute ago on the privileged side is not the same
      // fact as one this process walked, and the page names the difference
      // rather than showing them identically.
      nudb_measured_by: storeOnThePage.measured_by,
      nudb_peak_bytes_24h: nudbPeakBytes24h,
      mount_free_days_est: mountFreeDaysEst,
      // #199. The same estimate with its reasoning attached: which of the
      // three answers this is, the peak growth behind it, and when the
      // store last rotated. `mount_free_days_est` stays beside it,
      // unchanged, for anything reading the number alone.
      nudb_growth: nudbGrowth,
      rippled_data_path: RIPPLED_DATA_PATH || null,
      nudb_walk_error: lastNudbWalkError,
      clock,
      rippled,
      disk_io: diskIo,
      host: {
        uptime_s: hostUptime,
        entropy_avail: entropy,
        inode_usage_pct: inodeUsage,
        rippled_uptime_s: rippledUptime,
        meta: hostMetaNow(),
      },
      // Raw rippled get_counts response, client picks out the fields it
      // renders. Poll cadence is 5 min (cache sizes change slowly).
      get_counts: snapshot.get_counts ?? null,
      // Fork-namespace-resolved object counters (ADR 0002). Additive sibling of
      // the raw response so clients can read canonical keys; raw stays for any
      // un-namespaced fields and for the legacy client fallback.
      get_counts_canonical: snapshot.get_counts_canonical ?? null,
      // Data-integrity fields for the Ops & Data Integrity column.
      node_db_cfg: lastNodeDbCfg,
      // #548. The other two settings the config runbook (ADR 0018) may
      // change (node_size and ledger_history) are stanza-shaped rather
      // than key=value, so they live in their own object (see the note on
      // lastNodeStanzaCfg above) and were never sent here at all: the System
      // tab had a row for online_delete and nowhere to show the other three.
      node_stanza_cfg: lastNodeStanzaCfg,
      shard_count: lastShardCount,
    };
    broadcast('system', lastSystemBroadcast);
  } catch (err) {
    console.warn('[system] read error:', (err as Error).message);
  }
}
let lastSystemBroadcast: unknown = null;

setInterval(pushSystem, 5_000);
pushSystem().catch(() => {});

// ── Release awareness ────────────────────────────────────────────────────
// The Field Guide is blunt about this: falling behind is not neutral, because
// when the network activates an amendment your build does not know, the node
// goes amendment blocked and stops participating. It lists the ripple-server
// list and GitHub releases as the channels to watch, and warns that by the
// time rippled's own ">60% of your UNL is newer" message appears, upgrading is
// urgent rather than optional.
//
// Nothing in the dashboard knew what the current release was, so an operator
// running 3.2.0 had no way to learn 3.2.1 existed without going and looking.
//
// Two sources, deliberately, because they answer different questions and can
// disagree for hours:
//   • the source release says a version EXISTS
//   • the image tag says you can actually INSTALL it
// 3.2.1 was tagged on GitHub well before the image was published. A badge fed
// only by the release feed would have said "upgrade" at a point where the
// upgrade could not be performed, and an operator who tried would conclude the
// dashboard was wrong.
//
// #658 added a third source. From 3.4.x on, a release ships as a signed
// package at packages.xrplf.org, and 3.4.1 shipped ONLY there: no GitHub
// release, no vendor image. The feed read GitHub's 3.4.0 as newest and told a
// node already on 3.4.1 that "3.4.0" was coming soon. A package in that index
// is released AND installable (apt on a native host), so lib/release-feed.ts
// reconciles all three: released is the newest of the three, installable is
// the newest of the two that produce an artifact, and a release nothing
// installs yet ships a note.
//
// Opt out with APERIRE_RELEASE_CHECK=off. This is an outbound call, like the
// existing xrpscan and xrpl.org polls, and it sends nothing about this node,
// it reads three public lists.
let releaseInfo: ReleaseInfo = {};
// What each source said at its last GOOD read, with the time it said it. A
// failed read, a non-200, or a body that parses to nothing keeps the entry as
// it was: one bad poll must never make a released version vanish (which would
// flip every node's pill and the fleet's [R] on a network blip), and must
// never re-date a reading nobody managed to take.
let releaseFeedCache: FeedCache = {};
// False while the feed's picture is incomplete (index never read, or
// something released that nothing installs yet). nextReleasePollMs rechecks
// on the short clock while it is.
let releaseFeedSettled = false;

/** The upstream fact both posture callers judge against: the self payload
 *  (buildReleaseInfoPayload) and the peer route (/api/node/<label>/release-
 *  posture). One builder, so the two can never label or date the same
 *  reading differently. */
function upstreamReleaseFact(): ReleaseFact | null {
  return upstreamFactFromInfo(releaseInfo);
}

/**
 * The one release-info payload every surface serves, built fresh from
 * whatever this process currently holds, never cached between calls, so
 * self_release_posture is always judged against the latest server_info and
 * selfAdvisorInstallable readings rather than whatever they were the last
 * time releaseInfo itself changed.
 *
 * #550's remaining half: this dashboard has THREE places that hand
 * release_info to a browser (the /release-info route, the WS snapshot, and
 * the two release_info broadcasts below), and only the route ever called
 * computeReleasePosture. The other two sent the bare releaseInfo object,
 * self_installable and self_release_posture absent, and overview.html
 * assigned each arrival over the one before it wholesale, so a snapshot
 * landing in the same second as the route's own fetch erased the posture
 * the page had just been given, every few seconds, for the life of the tab.
 * Routing every emission site through this one function is the fix at the
 * root: there is no longer a second, narrower shape for any of them to send.
 */
function buildReleaseInfoPayload(): SelfReleasePayload {
  const running = typeof (snapshot.server_info as AnyObj | undefined)?.build_version === 'string'
    ? (snapshot.server_info as AnyObj).build_version as string : null;
  // The shape itself lives in lib/release-feed.ts, where it is executed by
  // its own unit tests. This function is the one line the library cannot
  // write for itself: which running version and which Advisor reading this
  // process currently holds.
  return selfReleasePayload(releaseInfo, selfAdvisorInstallable, running);
}

/** The newest release a node could actually be upgraded to, or null if the
 *  upstream check is off, has not answered yet, or found nothing. One
 *  fleet-wide number, the FLEET card's [R] canary grades every row against
 *  it, so it is read from here at assembly time rather than copied into each
 *  peer's polled state. Installable first, for the same reason the local
 *  update pill prefers it: a release with no published image is not something
 *  an operator can act on, and nudging toward one trains them to ignore the
 *  badge. */
function latestInstallableRelease(): string | null {
  return releaseInfo.latest_installable ?? releaseInfo.latest_release ?? null;
}

const RELEASE_RE = /^[0-9]+(\.[0-9]+)*$/;

// The running version this release check was judged against. What is newest
// upstream changes on the scale of weeks, so asking GitHub and Docker Hub
// every six hours is right, but "are we behind it?" changes the moment an
// upgrade lands, and re-answering it was tied to the same six-hour poll. An
// operator who had just upgraded kept the amber "update to 3.2.1" pill next
// to a node already running 3.2.1, for up to six hours.
let lastJudgedVersion: string | undefined;

// Re-answer "behind?" from the cached upstream numbers, without a fetch.
function rejudgeRelease(): void {
  const running = (snapshot.server_info as AnyObj | undefined)?.build_version;
  if (typeof running !== 'string' || !running || running === lastJudgedVersion) return;
  const installable = releaseInfo.latest_installable ?? releaseInfo.latest_release;
  if (!installable) return;
  lastJudgedVersion = running;
  // A build_version with no version in it is not a version: no claim. One
  // carrying a build prefix (`rippled-3.3.0`) is read through it.
  const run = readVersion(running);
  const behind = !!run && cmpVersion(run, installable) < 0;
  if (behind === releaseInfo.behind) return;
  releaseInfo = { ...releaseInfo, behind };
  snapshot.release_info = releaseInfo;
  writeMetric('node_version_behind', behind ? 1 : 0);
  // #550. Through buildReleaseInfoPayload, same as the route and the WS
  // snapshot, so this broadcast carries self_release_posture too. Before
  // this fix it sent the bare object and overview.html's wholesale
  // assignment erased whatever posture the page already held.
  broadcast('release_info', buildReleaseInfoPayload());
}

async function pollReleases() {
  if ((process.env.APERIRE_RELEASE_CHECK ?? '').toLowerCase() === 'off') return;
  try {
    // The upstream picture is FLEET knowledge, not a local-node privilege:
    // an aggregator running no node of its own is exactly the surface that
    // needs it, its browsers judge each PEER's rendered version against
    // latest_installable client-side. The early return here starved the
    // whole lab of a week-old 3.3.0 (operator catch, 2026-08-14). Poll
    // regardless; `behind` stays a local-node verdict and is simply false
    // where there is no local node to be behind.
    const running = (snapshot.server_info as AnyObj | undefined)?.build_version;

    // Source releases. Pre-releases and drafts are skipped: an operator should
    // not be nudged toward something not generally released.
    let latestRelease: string | undefined;
    try {
      const r = await fetch('https://api.github.com/repos/XRPLF/rippled/releases?per_page=20', {
        headers: { accept: 'application/vnd.github+json' },
        signal: AbortSignal.timeout(10_000),
      });
      if (r.ok) {
        const rows = await r.json() as Array<AnyObj>;
        const tags = (Array.isArray(rows) ? rows : [])
          .filter(x => !x.draft && !x.prerelease)
          .map(x => String(x.tag_name ?? '').replace(/^v/, ''))
          .filter(t => RELEASE_RE.test(t));
        tags.sort(cmpVersion);
        latestRelease = tags[tags.length - 1];
      }
    } catch { /* best effort */ }

    // The official package index (#658). Read as plain text, capped as it
    // streams, and parsed for exactly the `xrpld` package. Only a read that
    // finds at least one xrpld release counts; anything else (timeout,
    // non-200, an HTML error page, a body far too large to be the index)
    // leaves the cached reading and its date exactly as they were.
    let latestPackage: string | undefined;
    try {
      const r = await fetch(PACKAGES_INDEX_URL, { signal: AbortSignal.timeout(10_000) });
      if (r.ok) {
        const text = await readCappedText(r, PACKAGES_INDEX_MAX_BYTES);
        const versions = text ? parseDebPackagesIndex(text) : [];
        if (versions.length) latestPackage = versions[versions.length - 1];
      } else {
        await r.body?.cancel().catch(() => {});
      }
    } catch { /* best effort, the cached reading stands */ }

    // Published images. This is what makes an upgrade actionable for a
    // container deployment.
    //
    // #653/#682. This used to walk xrpllabsofficial/xrpld's tag list, which
    // stops at 3.3.0 and was retired in favour of the release process's own
    // account (WietseWind/docker-xrpld#31). Two things changed with it.
    //
    // The registry is asked about ONE tag, by name, never for a list. The
    // official repository carries hundreds of tags and most of them are not
    // releases: commit hashes, `develop`, release candidates. A walk of that
    // list is a thing to filter correctly forever; a request for one plain
    // version tag cannot be confused by any of them, and a tag that is not
    // there answers 404 rather than being inferred from a page nobody
    // finished reading.
    //
    // And WHICH version is asked about never comes from the registry. It is
    // the newest release the other two sources just named, so "is there an
    // image for it" is the only question a registry gets to answer here.
    let latestImage: string | undefined;
    const askAbout = [latestPackage, latestRelease]
      .filter((v): v is string => !!v && RELEASE_RE.test(v))
      .sort(cmpVersion)
      .pop();
    if (askAbout) {
      try {
        const r = await fetch(
          `https://hub.docker.com/v2/repositories/${OFFICIAL_IMAGE_REPO}/tags/${encodeURIComponent(askAbout)}`,
          { signal: AbortSignal.timeout(10_000) },
        );
        // 200 means an official image carries it; 404 means one does not
        // yet, which is a real answer and not an error. Anything else
        // leaves the cached reading exactly as it was.
        if (r.ok) {
          const body = await r.json() as AnyObj;
          if (String(body.name ?? '') === askAbout) latestImage = askAbout;
        } else {
          await r.body?.cancel().catch(() => {});
        }
      } catch { /* best effort */ }
    }

    // Only a source that answered moves; the rest keep what they last said,
    // dated when they said it.
    releaseFeedCache = nextFeedCache(
      releaseFeedCache,
      { github: latestRelease, packages: latestPackage, image: latestImage },
      Date.now(),
    );
    if (!releaseFeedCache.github && !releaseFeedCache.image && !releaseFeedCache.packages) return;

    const feed = reconcileReleaseFeed(releaseFeedCache);
    releaseFeedSettled = feed.settled;
    // Behind is judged against what can actually be installed, inside the
    // library, with the same comparator every other surface uses.
    releaseInfo = releaseInfoFromFeed(feed, typeof running === 'string' ? running : null, Date.now());
    const behind = releaseInfo.behind === true;
    snapshot.release_info = releaseInfo;
    writeMetric('node_version_behind', behind ? 1 : 0);
    // #550, same reasoning as rejudgeRelease's own broadcast just above.
    broadcast('release_info', buildReleaseInfoPayload());
    if (typeof running === 'string' && running) lastJudgedVersion = running;
  } catch (err) {
    console.warn('[release] check failed:', (err as Error).message);
  }
}

// Six hours matches how often releases happen; it does not match how long a
// release stays uninstallable. The source release and its image tag arrive
// hours apart (3.3.0: tagged on GitHub in the evening, image published the
// next morning), and during that window the one question worth re-asking,
// has the tag appeared yet?, was on the same six-hour clock as everything
// else. While the two sources disagree, ask every thirty minutes. The same
// short clock holds while the feed is unsettled (#658): the package index has
// never answered, or something is released that nothing installs yet. A boot
// that missed the index must not wait six hours to learn what is released.
function nextReleasePollMs(): number {
  return (releaseInfo.note || !releaseFeedSettled) ? 30 * 60_000 : 6 * 60 * 60_000;
}
function scheduleReleasePoll(): void {
  setTimeout(() => {
    pollReleases().catch(() => {}).finally(scheduleReleasePoll);
  }, nextReleasePollMs());
}

// ─── Aperire's own update check — ADR 0022 phase 1 ────────────────────────
//
// Deliberately NOT part of pollReleases above, and this is the record's own
// distinction. That poll reads two public lists about rippled and tells them
// nothing about this host. A request to get.aperire.one tells my own endpoint
// this box's IP and that it runs Aperire, which is a phone-home. So it gets
// its own switch (APERIRE_UPDATE_CHECK=off, not APERIRE_RELEASE_CHECK) and
// its own metric (update_available, not node_version_behind). One metric
// cannot mean two things: a rule written for "the node is behind" would fire
// for "Aperire is behind" and the alert text would be wrong.
//
// Two cadences, both here:
//   • on click, always to the network, because an admin pressing "Check for
//     updates" is asking now;
//   • once every 24 hours in the background, which writes the metric.
// Neither fetches an archive and neither applies anything. Phase 1 reads.
const UPDATE_CHECK_ENABLED = updateChecksEnabled(process.env.APERIRE_UPDATE_CHECK);
const UPDATE_CHECK_EVERY_MS = 24 * 60 * 60_000;

/** The last answer, whatever it was. What the page shows on arrival. */
let lastUpdateCheck: UpdateCheckResult | null = null;
/** The last answer in which the endpoint actually said something. Kept apart
 *  from the one above so "checked: never" can be told from "checked at 09:12
 *  and the endpoint is down now", and so the fleet is graded against a
 *  release somebody published rather than against nothing. */
let lastAnsweredUpdateCheck: UpdateCheckResult | null = null;
// What this host last learned, kept beside the database so a restart does
// not forget it (#295): the restart an apply ends with is followed seven
// seconds later by the page's own read, and that read answers from here.
// Read back through the same checks a fetched answer gets.
const UPDATE_CHECK_STORE = join(dirname(DB_PATH), 'update-check.json');
{
  let raw: string | null;
  try { raw = readFileSync(UPDATE_CHECK_STORE, 'utf8'); } catch { raw = null; }
  const stored = parseStoredCheck(raw);
  if (stored) {
    lastUpdateCheck = stored;
    if (stored.latest) lastAnsweredUpdateCheck = stored;
  } else if (raw !== null) {
    console.warn(`[update-check] ${UPDATE_CHECK_STORE} did not parse; starting with no last check`);
  }
}
function storeUpdateCheck(result: UpdateCheckResult): void {
  // Written whole and renamed into place, so a reader never sees half of it.
  try {
    writeFileSync(`${UPDATE_CHECK_STORE}.tmp`, serializeStoredCheck(result), { mode: 0o600 });
    renameSync(`${UPDATE_CHECK_STORE}.tmp`, UPDATE_CHECK_STORE);
  } catch (e) {
    console.warn(`[update-check] could not keep the last check at ${UPDATE_CHECK_STORE}: ${(e as Error).message}`);
  }
}
const RELEASE_VERIFIER = sshKeygenVerifier();
/** One run at a time. Two admins pressing the button together make one
 *  outbound pair of requests, not four. */
let updateCheckInFlight: Promise<UpdateCheckResult> | null = null;

/** Where this host asks: the test override, then its own stamp's source_url,
 *  then get.aperire.one. Resolved per run rather than at boot, because the
 *  stamp changes under a running process when an apply lands. */
function currentUpdateEndpoint(): string {
  const id = releaseReader.current();
  return updateEndpoint({
    env: process.env.APERIRE_UPDATE_ENDPOINT,
    sourceUrl: id.kind === 'release' ? id.source_url : null,
  });
}

/** Only a real verdict reaches the metric. unknown / mid_publish /
 *  unreachable write nothing at all: a 0 there is a measurement nobody made,
 *  and an alert built on it would resolve on evidence that was never
 *  collected. */
function recordUpdateMetric(result: UpdateCheckResult): UpdateCheckResult {
  const value = updateAvailableMetric(result.state);
  if (value !== null) writeMetric('update_available', value);
  return result;
}

/** `click` is an admin pressing the button, `daily` is the background timer
 *  and the only one that writes the metric, `fleet` is a signed apply job
 *  arriving from the pinned aggregator. The third is there so the rate this
 *  runs at can be read off the call sites: one press each, never a poll. */
function runUpdateCheck(source: 'click' | 'daily' | 'fleet'): Promise<UpdateCheckResult> {
  if (updateCheckInFlight) {
    // A daily run that lands on top of an admin's click shares that click's
    // answer, and still writes the metric from it. Returning the promise bare
    // would cost the day's reading to a coincidence of timing.
    return source === 'daily' ? updateCheckInFlight.then(recordUpdateMetric) : updateCheckInFlight;
  }
  const run = checkForUpdate({
    fetchImpl: fetch,
    endpoint: currentUpdateEndpoint(),
    identity: releaseReader.current(),
    enabled: UPDATE_CHECK_ENABLED,
    // The release is believed only once its signed release.json verifies
    // against the key set this host trusts (#761), the same file the card's
    // Release key row reads. Nothing else in the answer is read before that.
    verify: RELEASE_VERIFIER,
    // The floor root holds an update to (#1073): a signed release published
    // no later than the one this host runs, or than the newest it ever ran,
    // is a replay and never reads "behind". Read per run, because an apply
    // moves the mark.
    highWaterAt: readReleaseHighWater(),
  }).then((result) => {
    lastUpdateCheck = result;
    // `latest` is present exactly when the endpoint answered with two files
    // that agreed, which is the only answer worth remembering as "the last
    // time this worked".
    if (result.latest) lastAnsweredUpdateCheck = result;
    if (result.latest) storeUpdateCheck(result);
    if (source === 'daily') recordUpdateMetric(result);
    return result;
  }).finally(() => { updateCheckInFlight = null; });
  updateCheckInFlight = run;
  return run;
}

// No timer at all when the switch is off, so "off" is a fact about this
// process and not a branch inside a request. The first run is a minute after
// boot rather than at it: an install that has just finished has better things
// to do with its first seconds, and nothing on the page needs this before an
// operator opens the menu.
if (UPDATE_CHECK_ENABLED) {
  const first = setTimeout(() => { runUpdateCheck('daily').catch(() => {}); }, 60_000);
  if (typeof first.unref === 'function') first.unref();
  const daily = setInterval(() => { runUpdateCheck('daily').catch(() => {}); }, UPDATE_CHECK_EVERY_MS);
  if (typeof daily.unref === 'function') daily.unref();
}


// ─── Applying one — ADR 0022 phase 2 ──────────────────────────────────
//
// The dashboard never writes its own tree. It runs under NoNewPrivileges
// with an empty capability set (#153), so the apply, the restart and the
// rollback are verbs of a root program systemd starts behind a socket, in
// the sealer's shape. What is held HERE is the run: one at a time, its lines
// as they arrive, and what it ended as, so the page can tail a thing that
// takes minutes rather than hold a request open for one.
//
// The run log is in memory on purpose. A restart into the new code is the
// last step of an apply, and it kills this process; a half-finished run is
// not a run to resume (ADR 0022 decision 4). What survives a restart is the
// release stamp on disk, which is the fact worth surviving.
const UPDATE_SOCKET_PATH = process.env.APERIRE_UPDATE_SOCKET || UPDATE_SOCKET;

/** Two bounds on every verb, and the unit behind the socket carries its own
 *  RuntimeMaxSec. An apply is `npm ci` plus two Go builds on whatever the
 *  operator is paying for, which on a small VPS is not quick. */
const UPDATE_TIMEOUT_MS = {
  check: 20_000,
  apply: 45 * 60_000,
  restart: 120_000,
  rollback: 15 * 60_000,
} as const;

interface UpdateRunRecord {
  id: string;
  action: 'apply' | 'restart' | 'rollback';
  started_at: number;
  finished_at: number | null;
  running: boolean;
  operator: string;
  release?: { tag: string; commit: string; sha256: string };
  units?: string[];
  snapshot: UpdateSnapshot;
  absent: boolean;
  verdict: UpdateVerdict | null;
}

/** The one run this process will hold. */
let updateRun: UpdateRunRecord | null = null;

// ── The run that outlives the process holding it — #323 ─────────────────
//
// A restart verb restarts this dashboard's own unit LAST and deliberately,
// which takes away the process reading the socket. So the run record above,
// which is memory, is gone exactly when the aggregator most needs to know
// what happened: it asks, this host answers `run: null`, and the only honest
// reading on the other side is "I cannot say" for a restart that succeeded.
//
// This is the small durable thing that closes it. It is the node's own
// record and the node's own measurement, written before the process can be
// taken away and read back by whatever process comes up next. It does NOT
// let a reader assert an outcome nobody measured: what it says is that this
// dashboard process started after that run began, which is a fact about this
// unit and about nothing else on the host.
const UPDATE_LAST_RUN_PATH = process.env.APERIRE_UPDATE_LAST_RUN_PATH
  ?? join(dirname(DB_PATH), 'update-last-run.json');

/** When THIS process started, measured once. The comparison that makes a
 *  self-restart readable, and the only reason it is honest: it is read off
 *  this process's own clock rather than inferred from an absence. */
const PROCESS_STARTED_AT = Date.now() - Math.round(process.uptime() * 1000);

interface UpdateLastRunMarker {
  run_id: string;
  action: 'apply' | 'restart' | 'rollback';
  started_at: number;
  written_at: number;
  code: number | null;
  steps: string[];
  units: string[];
}

let lastUpdateRunMarker: UpdateLastRunMarker | null = (() => {
  try {
    const raw = readFileSync(UPDATE_LAST_RUN_PATH, 'utf8');
    const parsed = JSON.parse(raw) as Partial<UpdateLastRunMarker>;
    if (!parsed || typeof parsed.run_id !== 'string' || !parsed.run_id) return null;
    if (typeof parsed.started_at !== 'number' || !Number.isFinite(parsed.started_at)) return null;
    return {
      run_id: parsed.run_id,
      action: parsed.action === 'restart' || parsed.action === 'rollback' ? parsed.action : 'apply',
      started_at: parsed.started_at,
      written_at: typeof parsed.written_at === 'number' ? parsed.written_at : parsed.started_at,
      code: typeof parsed.code === 'number' ? parsed.code : null,
      steps: Array.isArray(parsed.steps) ? parsed.steps.map(String).slice(-16) : [],
      units: Array.isArray(parsed.units) ? parsed.units.map(String).slice(0, 8) : [],
    };
  } catch {
    // Absent is the ordinary first-ever state, and unreadable is the same
    // answer: this host has nothing it can say about a previous run.
    return null;
  }
})();

/** Written whole and renamed into place, so a reader never sees half of it.
 *  Throttled on the streaming path: a build writes hundreds of lines and the
 *  only thing worth keeping current is which step it reached. */
let lastMarkerWriteAt = 0;
function keepUpdateRun(run: UpdateRunRecord, force: boolean): void {
  const now = Date.now();
  if (!force && now - lastMarkerWriteAt < 2_000) return;
  lastMarkerWriteAt = now;
  const marker: UpdateLastRunMarker = {
    run_id: run.id,
    action: run.action,
    started_at: run.started_at,
    written_at: now,
    code: run.snapshot.code,
    steps: run.snapshot.steps.slice(-16),
    units: (run.units ?? []).slice(0, 8),
  };
  lastUpdateRunMarker = marker;
  try {
    writeFileSync(`${UPDATE_LAST_RUN_PATH}.tmp`, JSON.stringify(marker), { mode: 0o600 });
    renameSync(`${UPDATE_LAST_RUN_PATH}.tmp`, UPDATE_LAST_RUN_PATH);
  } catch (e) {
    // A host that cannot keep this still runs the update. What it loses is
    // the ability to say afterwards what happened, which is worth a line.
    console.warn(`[update] could not keep the last run at ${UPDATE_LAST_RUN_PATH}: ${(e as Error).message}`);
  }
}

/** The marker as the contract publishes it, with the one measurement on it.
 *  `restarted_after` is computed HERE rather than stored, because it is a
 *  fact about the process answering this request and not about the run. */
function lastRunForWire(): UpdateStateLastRun | null {
  const m = lastUpdateRunMarker;
  if (!m) return null;
  return {
    run_id: m.run_id,
    action: m.action,
    started_at: m.started_at,
    written_at: m.written_at,
    code: m.code,
    steps: [...m.steps],
    units: [...m.units],
    restarted_after: PROCESS_STARTED_AT > m.started_at,
  };
}

/** Whether this host has an updater at all, what it last said, and when that
 *  was settled. Cached, because the probe starts a root program: a browser
 *  poll must not drive that rate. Presence changes when someone installs or
 *  removes the grant, so five minutes is generous.
 *
 *  The facts are kept with it because they are the SAME answer: the check
 *  verb reports the endpoint root reads from, what that endpoint publishes
 *  and where this host stands, and throwing all of that away to keep one
 *  boolean is what left the card grading from its own fetch while root
 *  installed from somewhere else (#293). */
let updaterPresence: { present: boolean; at: number; facts: Record<string, string> | null } | null = null;
const UPDATER_PROBE_TTL_MS = 5 * 60_000;

function updateAskFor(timeoutMs: number): UpdateAsk {
  return (payload, onChunk) =>
    askSocketProgram(UPDATE_SOCKET_PATH, payload, timeoutMs, 'the updater', onChunk)
      .then(() => undefined);
}

/**
 * Is there an updater on this host?
 *
 * Answered by asking it something harmless and seeing whether the socket
 * opened at all. `absent` is the only reading taken from it: what the
 * program thinks is published is the page's own question, asked over HTTP by
 * the check that already exists.
 *
 * Never probed while a run is in flight: the socket takes one connection at
 * a time, and a probe that collided with an apply would read as busy and be
 * recorded as a presence answer.
 */
/**
 * The three-valued reading (#331).
 *
 * `answered` is the difference between "there is no grant on this host" and
 * "the socket accepted a connection and said nothing". Both read
 * `present: false`, and only one of them is a reason to tell an operator to
 * install a root program. It is carried on `update/state` so an aggregator's
 * fleet row can tell them apart too.
 */
interface UpdaterProbe {
  present: boolean;
  facts: Record<string, string> | null;
  answered: boolean;
  /** When the FACTS were read off the socket, which on a cache hit is up to
   *  five minutes before this call. The card compares its own reading's age
   *  against this before it says which of the two is older (#342), so a
   *  cached probe and a background check that landed after it are never
   *  reported the wrong way round. */
  at: number;
}
let updaterProbeInFlight: Promise<UpdaterProbe> | null = null;

async function updaterCheck(force: boolean): Promise<UpdaterProbe> {
  // A run in flight IS an updater, and the socket takes one connection at a
  // time. No facts on this path: nothing was asked, and empty facts would be
  // read as a program that said nothing, which is a different claim. It IS a
  // definite answer about presence, which is what `answered` reports.
  if (updateRun?.running) return { present: true, facts: null, answered: true, at: Date.now() };
  const cached = updaterPresence;
  if (!force && cached && Date.now() - cached.at < UPDATER_PROBE_TTL_MS) {
    // Only an ANSWERED reading is ever cached (below), so a cache hit is an
    // answer by construction.
    return { present: cached.present, facts: cached.facts, answered: true, at: cached.at };
  }
  // One probe at a time, whoever asked (#330). The socket unit is
  // `Accept=yes` with `MaxConnections=1`, so two callers arriving after the
  // TTL both miss and both dial, and the second can be accepted and closed
  // with no reply. Sharing one answer removes the collision rather than
  // coping with it, and it costs the far side one root invocation instead of
  // two. Anyone holding this node's read token can drive this since #275.
  if (updaterProbeInFlight) return updaterProbeInFlight;
  updaterProbeInFlight = (async () => {
    const out = await runUpdateVerb(checkPayload(), updateAskFor(UPDATE_TIMEOUT_MS.check));
    const facts = out.absent ? null : out.facts;
    // A program that said NOTHING is not a program that answered, and an
    // empty reading kept for five minutes makes a host that has an updater
    // report as one that does not. Answered readings are cached; a silent
    // one is returned once and forgotten, so the next caller asks again.
    const answered = updaterAnswered(out);
    if (answered) {
      updaterPresence = { present: !out.absent, at: Date.now(), facts };
    } else {
      console.warn('[update] the updater accepted a connection and said nothing; not keeping that as an answer');
    }
    return { present: !out.absent, facts, answered, at: Date.now() };
  })().finally(() => { updaterProbeInFlight = null; });
  return updaterProbeInFlight;
}

async function updaterIsPresent(force: boolean): Promise<boolean> {
  return (await updaterCheck(force)).present;
}

/** The card's answer for THIS host: the updater's when there is one, this
 *  process's own fetch when there is not.
 *
 *  Deliberately not threaded into `writeMetric` or `fleetGraded`. The daily
 *  metric is a reading this process took, and a peer is graded against what
 *  the aggregator fetched — neither is the business of one host's
 *  /etc/aperire/update.conf. */
function updaterView(facts: Record<string, string> | null): {
  reading: UpdaterReading | null; graded: UpdateCheckResult | null;
} {
  const reading = readUpdaterCheck(facts);
  // Root checks against its own key set, the constant path, never the
  // override. When that set is not there, or this process could not check a
  // signature either, root's `signature=refused` is the host's own fault and
  // the card says so rather than blaming the endpoint.
  const hostCanCheck = readReleaseSigners(undefined, RELEASE_SIGNERS_PATH).state === 'ok'
    && lastUpdateCheck?.reason !== 'signature_unchecked';
  return {
    reading,
    graded: gradeFromUpdater(reading, releaseReader.current(), Date.now, hostCanCheck, readReleaseHighWater()),
  };
}

/** What the page tails. The last N lines are already bounded by the reader;
 *  this is the whole record it keeps, plus the two derived facts the card
 *  needs (which units are behind, and what the ending means). */
function updateRunWire(run: UpdateRunRecord | null): Record<string, unknown> {
  if (!run) {
    // Never a 404. The page polls this on arrival and again after a restart
    // it just caused, and "there is no run" is an answer to that question.
    return {
      running: false, run_id: null, action: null, started_at: null,
      lines: [], steps: [], facts: {}, code: null, verdict: null,
      release: null, units: [], needs_restart: [], broker_grant: null,
    };
  }
  return {
    running: run.running,
    run_id: run.id,
    action: run.action,
    started_at: run.started_at,
    finished_at: run.finished_at,
    operator: run.operator,
    lines: run.snapshot.lines,
    steps: run.snapshot.steps,
    facts: run.snapshot.facts,
    code: run.snapshot.code,
    absent: run.absent,
    verdict: run.verdict,
    release: run.release ?? null,
    units: run.units ?? [],
    // What the program itself said is running older code than the tree now
    // holds. The ONLY source the restart verb's unit list may come from.
    needs_restart: needsRestart(run.snapshot.facts),
    // What the update said about the fleet broker's grant, with the command
    // that fixes it when it needs one. Null when the update said nothing
    // (#842): the card makes no claim either way.
    broker_grant: brokerGrantReading(run.snapshot.facts, grantStepCommand(INSTALL_ROOT)),
  };
}

/** Every run and every refusal, on this dashboard's own record. A failed
 *  privileged act that leaves nothing on this side means the only account of
 *  it is a journal on the host, which is a bad place to have to go looking
 *  first — the same lesson the seal learned. Never the endpoint's bytes, and
 *  never anything read back that could carry a secret: what is written is
 *  the decision and its outcome. */
function recordUpdateEvent(
  actor: { operator: string; role: string | null },
  target: string | null,
  detail: Record<string, unknown>,
): void {
  recordAuthEvent({
    actor: actor.operator, actorRole: actor.role,
    event: 'update_run', target, detail,
  });
}

/**
 * A fleet-driven act that did NOT start a run, on THIS node's own record.
 *
 * The local Apply route writes an audit row for every refusal branch. The
 * fleet route used to send a 409 and record nothing here, so only a
 * SUCCESSFUL fleet act left a trace on the node, and a node being repeatedly
 * asked to apply by an aggregator that should not be asking left none at all
 * (#327). The aggregator has its own row, but that is the machine under
 * suspicion.
 *
 * The job is signature-verified by the time any of these branches run, so
 * `granted_by` is as trustworthy here as it is on the success path.
 */
function recordFleetRefusal(
  grantedBy: string,
  action: 'apply' | 'restart',
  target: string | null,
  detail: Record<string, unknown>,
): void {
  recordAuthEvent({
    actor: grantedBy,
    actorRole: null,
    event: 'update_run',
    target,
    detail: { action, ok: false, via: 'fleet', ...detail },
  });
}

/**
 * Start a verb, and answer at once.
 *
 * The response cannot wait for the program: an apply runs for minutes and a
 * held request would time out somewhere between here and the browser. So the
 * run record is created, the socket conversation is started in the
 * background, and the page tails /api/update/run.
 *
 * `running` is cleared in a `finally` and nowhere else. runUpdateVerb does
 * not throw, but a clear on the success path alone would leave this process
 * permanently 409 after one unlucky attempt, with nothing short of a restart
 * to fix it.
 */
function startUpdateRun(
  action: 'apply' | 'restart' | 'rollback',
  payload: string,
  timeoutMs: number,
  who: { operator: string; role: string | null },
  bound: {
    release?: { tag: string; commit: string; sha256: string };
    units?: string[];
    /** Present when an aggregator asked for this over the fleet link. On
     *  THIS node's record, naming the human who touched the passkey on the
     *  aggregator: a node whose code changed should answer "who did that"
     *  from its own trail rather than from someone else's (#275). */
    via?: 'fleet';
  },
): UpdateRunRecord {
  const run: UpdateRunRecord = {
    id: randomBytes(8).toString('hex'),
    action,
    started_at: Date.now(),
    finished_at: null,
    running: true,
    operator: who.operator,
    release: bound.release,
    units: bound.units,
    snapshot: { code: null, steps: [], facts: {}, lines: [] },
    absent: false,
    verdict: null,
  };
  updateRun = run;
  // Written BEFORE the socket, for every verb, and this is the rule rather
  // than a special case for restart. A run that dies between the socket and
  // its own ending — the unit's RuntimeMaxSec, an out-of-memory kill, an
  // operator restarting by hand mid-apply — did privileged work and would
  // otherwise leave nothing on this side at all. That is the trap the seal
  // learned: the only account of it would be a journal on the host, which is
  // a bad place to have to go looking first. Two rows per run, joined by
  // run_id.
  recordUpdateEvent(who, run.release?.tag ?? ((run.units ?? []).join(',') || action), {
    action, outcome: 'started', ok: null, run_id: run.id,
    ...(run.release ? { tag: run.release.tag, commit: run.release.commit } : {}),
    ...(run.units ? { units: run.units } : {}),
    ...(bound.via ? { via: bound.via } : {}),
  });
  // Kept from the first moment, and again as the run streams. On a restart
  // that includes this dashboard's own unit, the last write before the
  // process goes away is what the next process reads back (#323).
  keepUpdateRun(run, true);
  void runUpdateVerb(payload, updateAskFor(timeoutMs), (snap) => {
    run.snapshot = snap;
    keepUpdateRun(run, false);
  })
    .then((out) => {
      run.snapshot = { code: out.code, steps: out.steps, facts: out.facts, lines: out.lines };
      run.absent = out.absent;
      run.verdict = out.verdict;
      recordUpdateEvent(who, run.release?.tag ?? ((run.units ?? []).join(',') || action), {
        action, outcome: out.verdict.reason, ok: out.verdict.ok,
        code: out.code, run_id: run.id,
        ...(run.release ? { tag: run.release.tag, commit: run.release.commit } : {}),
        ...(run.units ? { units: run.units } : {}),
        ...(out.facts.stamp ? { stamp: out.facts.stamp } : {}),
        ...(out.facts.previous ? { previous: out.facts.previous } : {}),
        ...(bound.via ? { via: bound.via } : {}),
      });
      // Nothing to invalidate: the stamp reader holds a read for a minute
      // precisely because an apply changes .release under a live process
      // (ADR 0022 decision 1), so the next read past that minute is the new
      // one on its own.
    })
    .finally(() => {
      run.running = false;
      run.finished_at = Date.now();
      keepUpdateRun(run, true);
    });
  return run;
}

// What else was true when an alert fired.
//
// An alert says a number crossed a line. It does not say what the box was
// doing at that moment, and by the time anyone reads it that moment is gone,
// production log levels rotate, /proc is now, and the metric store keeps
// aggregates rather than the detail. Missed validations have carried their
// context since they shipped, for exactly this reason. Alerts did not.
//
// Deliberately captured at the transition and never continuously. Walking
// every process for swap on each sample would be real cost for something that
// matters a few hours a year.
function alertContext(metric: string): string | null {
  try {
    const ctx: AnyObj = {};
    // The handful of numbers worth having beside any alert.
    for (const m of ['peer_count', 'agreement_pct_1h', 'mem_used_pct',
                     'cpu_busy_pct', 'load_factor'] as const) {
      const pt = queryRecent(m, 1);
      if (pt.length) ctx[m] = Number(pt[0].value.toFixed(2));
    }
    ctx.server_state = snapshot.server_info?.server_state ?? null;

    if (metric === 'swap_used_pct') ctx.swap = swapBreakdown();
    return JSON.stringify(ctx);
  } catch {
    return null;   // context is a nicety; never let it block an alert
  }
}

// Where the swap actually is.
//
// "Swap is in use" is not one condition. Pages belonging to a process that is
// paging are a performance problem worth chasing; shmem and tmpfs pages the
// kernel parked are usually nothing at all, no process owns them and nothing
// waits on them. The totals look identical, and only the split tells them
// apart. On this host today every byte of swap in use is the second kind,
// which is why a rule on the total alone said the wrong thing for weeks.
function swapBreakdown(): AnyObj {
  const meminfo: Record<string, number> = {};
  try {
    for (const line of readFileSync('/proc/meminfo', 'utf8').split('\n')) {
      const m = /^(\w+):\s+(\d+)\s*kB/.exec(line);
      if (m) meminfo[m[1]] = Number(m[2]);
    }
  } catch { /* not Linux, or /proc unavailable */ }

  const used = (meminfo.SwapTotal ?? 0) - (meminfo.SwapFree ?? 0);
  const procs: Array<{ pid: string; name: string; swap_kb: number }> = [];
  let attributed = 0;
  try {
    for (const pid of readdirSync('/proc')) {
      if (!/^\d+$/.test(pid)) continue;
      let name = '', swap = 0;
      try {
        for (const line of readFileSync(`/proc/${pid}/status`, 'utf8').split('\n')) {
          if (line.startsWith('Name:')) name = line.slice(5).trim();
          else if (line.startsWith('VmSwap:')) { swap = parseInt(line.split(/\s+/)[1], 10) || 0; break; }
        }
      } catch { continue; }   // process exited mid-read, or not ours to read
      if (swap > 0) { attributed += swap; procs.push({ pid, name, swap_kb: swap }); }
    }
  } catch { /* /proc unreadable */ }
  procs.sort((a, b) => b.swap_kb - a.swap_kb);

  return {
    total_kb: meminfo.SwapTotal ?? null,
    used_kb: used,
    // What processes account for, versus what they do not. A large gap means
    // shmem or tmpfs, which is a different problem from a process paging.
    process_attributed_kb: attributed,
    unattributed_kb: Math.max(0, used - attributed),
    shmem_kb: meminfo.Shmem ?? null,
    top: procs.slice(0, 8),
  };
}


// How the network sees this validator, from the public registry that other
// operators and explorers read.
//
// This is the one class of fact a node cannot establish about itself. A
// validator that has stopped being seen by everyone else still reports itself
// proposing, with a full peer list and 100% local agreement, because from the
// inside nothing is wrong. The only way to know is to ask someone outside.
//
// Three signals, because they fail independently:
//
//   validator_registry_seen     the registry lists our key at all
//   validator_last_seen_age_s   how long since it observed us sign something
//   validator_version_drift     the version it reports is not the one we run
//
// The third is subtler than it looks. `last_seen` comes from observed
// validations; the version comes from the manifest. So a node can be seen
// signing in real time while the registry still advertises the release it ran
// before its last upgrade, visible, but described wrongly to anyone reading
// the registry to decide whether to trust it.
//
// Best-effort and quiet on failure: the registry being down is not this
// node's problem, and writing a false "not seen" would be worse than writing
// nothing.
async function pollValidatorRegistry() {
  const ourKey = snapshot.our_pubkey_validator;
  if (!ourKey) return;                       // not a validator, or not known yet
  try {
    const res = await fetch('https://api.xrpscan.com/api/v1/validatorregistry', {
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) return;
    const list = await res.json() as Array<AnyObj>;
    // An unreadable or empty listing means we failed to ask, which must not be
    // recorded as "the network cannot see us".
    if (!Array.isArray(list) || list.length === 0) return;

    const row = list.find(r => r && (r as AnyObj).master_key === ourKey);
    writeMetric('validator_registry_seen', row ? 1 : 0);
    if (!row) return;

    const seen = Date.parse(String((row as AnyObj).last_seen ?? ''));
    if (Number.isFinite(seen)) {
      writeMetric('validator_last_seen_age_s', Math.max(0, (Date.now() - seen) / 1000));
    }
    const theirs = String(((row as AnyObj).server_version as AnyObj)?.version ?? '');
    const ours = String(snapshot.server_info?.build_version ?? '');
    if (theirs && ours) writeMetric('validator_version_drift', theirs === ours ? 0 : 1);

    snapshot.registry_view = {
      last_seen: String((row as AnyObj).last_seen ?? ''),
      ledger_index: Number((row as AnyObj).ledger_index ?? 0) || null,
      unl: Array.isArray((row as AnyObj).unl) ? (row as AnyObj).unl as string[] : [],
      registry_version: theirs || null,
    };
  } catch { /* registry unreachable; say nothing rather than something false */ }
}


// Poll schedules
setInterval(() => { pollServerInfo().catch(() => {});         }, 5_000);
// Releases move on the order of weeks; six hours is responsive enough and
// keeps us a negligible caller on two public APIs.
setTimeout(() => { pollReleases().catch(() => {}).finally(scheduleReleasePoll); }, 20_000);
setInterval(() => { pollPeers().catch(() => {});              }, 15_000);
setInterval(() => { pollFee().catch(() => {});                }, 10_000);
setInterval(() => { pollConsensusInfo().catch(() => {});      }, 2_000);
setInterval(() => { pollFeature().catch(() => {});            }, 300_000);   // 5 min
setInterval(() => { pollValidators().catch(() => {});         }, 300_000);   // 5 min
setInterval(() => { pollValidatorListSites().catch(() => {}); }, 600_000);   // 10 min
// 60 s, the catalog's cadence for get_counts. The node-store rates take a
// modular delta on rippled's two 32-bit counters, and the interval sets how
// much they can advance before that aliases: 2^32 / 60 s is 72 MB/s of
// store fetches, against 14 MB/s at five minutes (#215).
setInterval(() => { pollGetCounts().catch(() => {});          }, 60_000);
setInterval(() => { pollShardCount().catch(() => {});         }, 600_000);   // 10 min, rarely changes
setInterval(() => { pollXrpscanAmendments().catch(() => {}); }, 900_000);    // 15 min, amendment metadata barely changes
setInterval(() => { pollXrplOrgAmendments().catch(() => {}); }, 86_400_000); // 24 h, descriptions almost never change
setInterval(() => { pollOwnDomain().catch(() => {});         }, 86_400_000); // 24 h, domain/toml verification, daily cadence
// 10 min. The registry updates as it observes validations, so polling faster
// buys nothing, and this is somebody else's service being asked a question
// about us.
setInterval(() => { pollValidatorRegistry().catch(() => {}); }, 600_000);

// Run the domain verification once at startup, but only after our validator
// master key is known (it comes from the first server_info poll). Poll for the
// key on a short timer, then fire once and stop; the daily interval above keeps
// it fresh thereafter. Bounded so we don't spin forever on a non-validator.
(function bootstrapDomainCheck() {
  let tries = 0;
  const timer = setInterval(() => {
    tries++;
    if (snapshot.our_pubkey_validator) {
      clearInterval(timer);
      pollOwnDomain().catch(() => {});
      // The registry check waits on the same thing, our own key, and needs
      // to run at startup for the same reason. Without it there is a ten
      // minute window after every restart in which nothing knows whether the
      // network can still see this validator, which is exactly the window a
      // restart makes worth checking.
      pollValidatorRegistry().catch(() => {});
    } else if (tries >= 30) {            // ~60s with no validator key → give up
      clearInterval(timer);
    }
  }, 2_000);
})();

// #542: the amendment library pulls (pollXrpscanAmendments, which can itself
// trigger pollXrplOrgAmendments) are network-only: xrpscan and xrpl.org, no
// local rippled involved. So they run once here, unconditionally, at
// process startup. They used to run only inside connectRippled()'s 'open'
// handler, on the theory that "startup" meant "rippled just connected"; that
// is true for every poller ABOVE this comment, which all call rippled, but
// it was never true for these two, and a fleet aggregator (no local rippled
// to open a connection to) never ran them at all. Its amendment
// descriptions sat on whatever the last deploy shipped until the 24h
// interval below happened to catch it. A node gets the same startup
// freshness it always had; this only removes a dependency these two never
// needed.
Promise.allSettled([pollXrpscanAmendments(), pollXrplOrgAmendments()]).catch(() => {});

// A dashboard-role host has no node to bridge to (#808). Opening the bridge
// anyway logged ECONNREFUSED every three seconds for the life of the host.
if (DASHBOARD_HOST) {
  console.log('[bridge] install role is dashboard: no local node, not connecting to rippled');
} else {
  connectRippled();
}

// ────────────────────────────────────────────────────────────────────────
// Relay ingest, accepts outbound pushes from aperire-relay instances,
// diffs counters, accumulates monthly byte totals, rebroadcasts to browsers.
// ────────────────────────────────────────────────────────────────────────

// In-memory last-push snapshot per node_label. Faster than a DB round-trip
// per push; bandwidth_last_snapshot is the persistent backup so monthly
// totals keep accumulating across dashboard restarts.
interface LastPushSnap {
  rx: number; tx: number;
  rx_pkts: number; tx_pkts: number;
  retrans: number; resets: number;
  at_ms: number;                       // 0 = seeded from DB, no timestamp yet
}
const lastPushByNode = new Map<string, LastPushSnap>();

// One dashboard, one relay, ADR 0009. The first label this process sees is
// the one it serves; anything else is refused, once per label, loudly.
let acceptedNodeLabel: string | null = null;
const refusedLabelsLogged = new Set<string>();

// Most recent net_stats broadcast payload, captured so late-joining browsers
// (page reloads between push ticks) get the last-known values in the initial
// snapshot instead of a blank card. Refreshes on every relay push.
let lastNetStatsBroadcast: unknown = null;
let lastNetStatsAt = 0;

// Most recent relay `system` frame. Once a relay has fed this process, its
// host is the host the System tab describes (lib/host-metrics-source.ts).
let lastRelaySystem: LastRelaySystem | null = null;

// The relay's own account of its build, off the one field the wire already
// carries (relay-contract.ts's `relay_version`). Reads the literal string
// `dev` on every relay a release has not yet stamped with a commit, a real
// field with nothing measurable in it yet, which sanitizeComponents (#266)
// is where that distinction is made rather than guessed here.
let lastRelayVersion: string | null = null;
// The Advisor daemon's own build ref, from its /v1/status (#266, #383). The
// update-state route is polled every two seconds, so the daemon is asked at
// most once a minute and the last answer is what the route reports between
// asks; a daemon that has not answered yet, or one built before it carried a
// version, reads as not measured (empty), which sanitizeComponents drops.
let lastAdvisordVersion: string | null = null;
let lastAdvisordVersionAt = 0;
/** The account this process runs as, or null when the OS cannot say (a
 *  container run with a uid that has no passwd entry makes userInfo() throw).
 *  Null is "not reported" to every reader, never a guessed name. */
function dashboardAccountName(): string | null {
  try { return osUserInfo().username || null; } catch { return null; }
}

/** Whether this request carries an administrator's session. Never throws and
 *  never trusts the browser: the role is the session row's own. */
function adminSession(req: Parameters<typeof readSession>[0]): boolean {
  const sess = readSession(req);
  return !!sess && isAdmin(sess.role);
}

function componentsNow(): Record<string, string> {
  const now = Date.now();
  if (now - lastAdvisordVersionAt > 60_000) {
    lastAdvisordVersionAt = now;
    void fetchSelfAdvisorStatus().then((st) => {
      lastAdvisordVersion = st && typeof st.version === 'string' ? st.version : null;
    });
  }
  return sanitizeComponents({ relay: lastRelayVersion ?? '', advisord: lastAdvisordVersion ?? '' });
}

function currentYearMonthUTC(d: Date = new Date()): string {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/** The browser family for the page-load line: enough to tell one device from
 *  another, and nothing an operator would mind seeing in a log. */
const CLIENT_DEBUG = /^(mem)$/.test(process.env.APERIRE_CLIENT_DEBUG ?? '') ? process.env.APERIRE_CLIENT_DEBUG : '';

function browserFamily(ua: string | undefined): string {
  const u = ua ?? '';
  const os = /iPad|Macintosh.*Mobile\//.test(u) ? 'ipad' : /iPhone/.test(u) ? 'iphone' : /Android/.test(u) ? 'android'
    : /Macintosh/.test(u) ? 'mac' : /Windows/.test(u) ? 'windows' : /Linux/.test(u) ? 'linux' : 'other';
  const br = /CriOS/.test(u) ? 'chrome' : /FxiOS/.test(u) ? 'firefox' : /Edg\//.test(u) ? 'edge' : /Chrome\//.test(u) ? 'chrome'
    : /Firefox\//.test(u) ? 'firefox' : /Safari\//.test(u) ? 'safari' : /curl|HeadlessChrome|Playwright/.test(u) ? 'tool' : 'other';
  return `${os}/${br}`;
}

function handleRelayPush(msg: RelayPush): void {
  if (msg?.type !== 'push' || msg.protocol_version !== 1) return;
  const p = msg.payload;
  if (!p || (p.kind !== 'net_stats' && p.kind !== 'system')) return;
  const label = msg.node_label;
  if (!label) return;

  // RELAY_TOKENS is a set and the label is chosen by the relay, so two
  // relays holding valid tokens could both push here. bandwidth_monthly
  // would keep them apart, but everything else lands in `metrics`, which
  // has no node column, their host metrics would interleave silently, and
  // silently is the problem. Under ADR 0009 a second relay is a
  // misconfiguration to refuse, not a capability: one dashboard, one node.
  // A DELIBERATE rename (it has happened, the relay outage cleanup renamed
  // this host's label) is a config edit plus a dashboard restart, which
  // resets this; what cannot happen is two labels alternating in one run,
  // because a rename never alternates.
  if (acceptedNodeLabel === null) {
    acceptedNodeLabel = label;
  } else if (label !== acceptedNodeLabel) {
    if (!refusedLabelsLogged.has(label)) {
      refusedLabelsLogged.add(label);
      console.error(
        `[ingest] REFUSED push labelled ${JSON.stringify(label)}, this dashboard already serves ` +
        `${JSON.stringify(acceptedNodeLabel)}. One dashboard monitors one node (ADR 0009); a second ` +
        `relay needs its own dashboard instance. If this is a deliberate rename, restart the ` +
        `dashboard and it will adopt the new label.`);
    }
    return;
  }

  // Recorded on every accepted push, whichever frame kind carried it, so a
  // relay that never sends a `system` frame (Shape A, no split host) still
  // has its build ref seen.
  if (typeof msg.relay_version === 'string') lastRelayVersion = msg.relay_version;

  // The relay sends two frames per tick. The `system` one is the validator
  // host's compute block; it is kept here and folded into the next
  // pushSystem() tick, which is where the System tab and the read API are
  // fed. Nothing below this line concerns it.
  if (p.kind === 'system') {
    lastRelaySystem = { payload: p, at_ms: Date.now(), label };
    return;
  }

  let prev = lastPushByNode.get(label) ?? null;
  if (!prev) {
    // First push since dashboard start, seed byte baseline from SQLite so
    // we can still credit bytes transferred while the dashboard was down.
    const dbSnap = getLastSnapshot(label);
    if (dbSnap) {
      prev = {
        rx: dbSnap.rx_bytes, tx: dbSnap.tx_bytes,
        rx_pkts: 0, tx_pkts: 0,
        retrans: 0, resets: 0,
        at_ms: 0,
      };
    }
  }

  let rxBps = 0, txBps = 0, rxPps = 0, txPps = 0;
  let retransPerSec = 0, resetsPerSec = 0;
  let dRx = 0, dTx = 0;
  let intervalSec = 0;

  if (prev) {
    const rxDelta = p.rx_bytes - prev.rx;
    const txDelta = p.tx_bytes - prev.tx;
    // Counter decrease = reboot or counter rollover. Drop deltas, reset baseline.
    if (rxDelta < 0 || txDelta < 0) {
      console.log(`[ingest] ${label} counter reset detected, baseline reset`);
    } else {
      dRx = rxDelta;
      dTx = txDelta;
      if (prev.at_ms > 0) {
        intervalSec = Math.max(0.001, (msg.sent_at_ms - prev.at_ms) / 1000);
        rxBps = rxDelta / intervalSec;
        txBps = txDelta / intervalSec;
        rxPps = Math.max(0, p.rx_packets - prev.rx_pkts) / intervalSec;
        txPps = Math.max(0, p.tx_packets - prev.tx_pkts) / intervalSec;
        retransPerSec = Math.max(0, p.tcp_retrans_segs - prev.retrans) / intervalSec;
        resetsPerSec  = Math.max(0, p.tcp_out_resets - prev.resets) / intervalSec;
      }
      // When prev.at_ms === 0 we have a byte baseline from DB but no time
      // reference, so we credit dRx/dTx to the monthly bucket (covers the
      // down-window) without computing a rate for this tick.
    }
  }

  if (dRx > 0 || dTx > 0) {
    addMonthlyBandwidthDelta(label, currentYearMonthUTC(), dRx, dTx);
  }

  lastPushByNode.set(label, {
    rx: p.rx_bytes, tx: p.tx_bytes,
    rx_pkts: p.rx_packets, tx_pkts: p.tx_packets,
    retrans: p.tcp_retrans_segs, resets: p.tcp_out_resets,
    at_ms: msg.sent_at_ms,
  });
  setLastSnapshot(label, p.rx_bytes, p.tx_bytes);

  const monthly = getMonthlyBandwidth(label, currentYearMonthUTC());
  const usedBytes = monthly.rx_bytes + monthly.tx_bytes;
  const capBytes = p.monthly_budget_bytes;
  const monthlyPct = (capBytes && capBytes > 0) ? (usedBytes / capBytes) * 100 : null;

  const outbound = {
    node_label: label,
    interface: p.interface,
    interface_source: p.interface_source,
    rx_bps: rxBps,
    tx_bps: txBps,
    rx_pps: rxPps,
    tx_pps: txPps,
    tcp_retrans_per_sec: retransPerSec,
    tcp_resets_per_sec: resetsPerSec,
    rx_errors: p.rx_errors,
    tx_errors: p.tx_errors,
    rx_drops: p.rx_drops,
    tx_drops: p.tx_drops,
    tcp_established: p.tcp_established,
    tcp_time_wait: p.tcp_time_wait,
    socket_count: p.socket_count,
    http_rpc_connections:  p.http_rpc_connections  ?? null,
    admin_ws_connections:  p.admin_ws_connections  ?? null,
    ws_public_connections: p.ws_public_connections ?? null,
    peer_connections:      p.peer_connections      ?? null,
    monthly_used_bytes: usedBytes,
    monthly_cap_bytes: capBytes,
    monthly_pct: monthlyPct,
    interval_sec: intervalSec,
  };
  lastNetStatsBroadcast = outbound;
  lastNetStatsAt = Date.now();
  broadcast('net_stats', outbound);
}

// ────────────────────────────────────────────────────────────────────────
// HTTP + browser WebSocket
// ────────────────────────────────────────────────────────────────────────

// Which series /history will serve. It has to agree with two other lists it
// has no link to: the metrics the server writes, and the metrics the alert
// rules name. It did not, `agreement_pct_1h` and `missed_validations_1h` are
// written on every ledger and referenced by five rules, and asking /history
// for either returned "bad metric" while 43,000 rows of each sat in the
// database. The rules worked, because they read the store directly; nothing
// could chart the two series behind the alerts that matter most.
//
// test/unit/metric-lists.test.ts asserts the three agree, which is the only
// reason this stays true.
const VALID_METRICS = new Set([
  'close_time', 'converge_time', 'txn_count', 'load_factor', 'validation_rate', 'agreement_pct',
  'agreement_pct_1h', 'missed_validations_1h', 'jq_trans_overflow', 'peer_shed_signal',
  'validator_registry_seen', 'validator_last_seen_age_s', 'validator_version_drift',
  'peer_count', 'peers_inbound', 'peers_outbound', 'peers_insane', 'peer_latency_p50', 'peer_latency_p90',
  'rx_bps', 'tx_bps', 'rx_pps', 'tx_pps', 'tcp_retrans_per_sec', 'tcp_established',
  'http_rpc_conn', 'admin_ws_conn', 'ws_public_conn', 'peer_conn',
  'relay_feed_age_s',
  'node_unreachable_s',
  'update_available',
  'fleet_deploy_divergent',
  'nudb_size', 'nudb_mount_free_days',
  'verify_failed_checks', 'verify_report_age_s', 'verify_report_missing',
  'cpu_busy_pct', 'cpu_iowait_pct', 'mem_used_pct', 'mem_cache_pct', 'swap_used_pct',
  'pressure_cpu', 'pressure_memory', 'pressure_io',
  'rippled_cpu_pct', 'rippled_rss_pct',
  'nodestore_read_hit_pct', 'nodestore_reads_per_s', 'nodestore_writes_per_s',
  'unsupported_amendment_days_to_block',
]);
const VALID_RANGES: Record<string, number> = {
  '1h':  1 * 3600_000,
  '6h':  6 * 3600_000,
  '12h': 12 * 3600_000,
  '24h': 24 * 3600_000,
  '7d':  7 * 86_400_000,
  '30d': 30 * 86_400_000,
};

// #119. See lib/history-cache.ts for why this exists and why the TTL is half
// a bucket. Wired here with the real query and the real bucket function, so
// the cache and the aggregation can never disagree about bucket width.
const historyCache = createHistoryCache<HistoryPoint>({
  // The store's size series starts where the current store's does (#1251):
  // the chart draws nothing from a store that was replaced, and a cut made
  // while an answer was cached cannot be served from it.
  queryRange: (metric, fromS, toS, bucketS, agg) =>
    queryHistoryRange(metric as MetricName, metric === 'nudb_size' ? Math.max(fromS, storeSeries?.cutS() ?? 0) : fromS,
      toS, bucketS, agg as 'avg' | 'max' | 'min'),
  bucketForRange,
  epoch: (metric) => (metric === 'nudb_size' ? storeSeries?.cutS() ?? 0 : 0),
});

const httpServer = createServer(async (req, res) => {
  try {
    // MED-05, emit security headers on every response, and #240: FIRST, before
    // anything that can throw. Parsing and decoding the request URL used to
    // come first, and `curl /api/%zz` threw in the decode, so the catch below
    // answered a 500 carrying none of these. They are set on a response that
    // has not been read yet, which is why nothing here touches the request.
    // setHeader, not writeHead, so the per-route writeHead(code, {...}) calls
    // below merge with, rather than replace, these. The nonce is regenerated
    // per request and injected into the inline <script> of any HTML body
    // served.
    const cspNonce = applySecurityHeaders(res);

    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    let pathname = decodeURIComponent(url.pathname);

    // HTTPS redirect, when the Cloudflare tunnel forwards an HTTP-origin
    // request, cloudflared sets `X-Forwarded-Proto: http`. Bounce those to
    // https so users who typed `http://…` don't end up on plain HTTP. Only
    // acts when the header is present and explicitly http; direct localhost
    // (SSH tunnel, curl --head for ops checks, /healthz probes) pass through.
    const xfp = req.headers['x-forwarded-proto'];
    if (xfp === 'http') {
      res.writeHead(301, { Location: `https://${req.headers.host}${req.url ?? '/'}` });
      res.end();
      return;
    }

    // Health probe, used by systemd / uptime monitors / load balancers.
    // 200 when rippled is connected and ledger stream is moving; 503 when
    // either is stale. Never cached, and unauthenticated.
    //
    // What that means it discloses, restated because asks_in_flight widened
    // it: liveness, how long this process has been up, how fresh its feeds
    // are, and now whether somebody is asking the Advisor at this moment.
    // Accepted deliberately, it is the same kind of fact as uptime_s, it
    // names no operator, no question and no node, and the alternative is an
    // authenticated probe that the deploy check and every uptime monitor
    // would then need a credential for. Nothing about the snapshot, the
    // session store or the fleet belongs here; if that ever changes, this
    // route needs a gate rather than another field.
    if (pathname === '/healthz') {
      const now = Date.now();
      const ledgerAgeMs = lastLedgerCloseTs ? now - lastLedgerCloseTs : null;
      const relayAgeMs  = lastNetStatsAt    ? now - lastNetStatsAt    : null;
      const rippledOk   = !!rippled && rippled.readyState === WebSocket.OPEN;
      const ledgerOk    = ledgerAgeMs != null && ledgerAgeMs < 30_000;
      // An aggregator runs no node of its own, so judging it by a rippled
      // connection it is not supposed to have reported ok:false forever
      // (punch #12; the aggregator sat 503 for its whole life while perfectly healthy).
      // The role comes from the fleet registry: a self entry whose node is
      // never reachable plus registered peers is the same predicate the
      // header chip uses. Its health is what it actually does: serve pages
      // and read peers.
      const peerCount = fleetPoller ? fleetPoller.peersConcernInput().length : 0;
      // The verdict lives in lib/healthz-verdict.ts so it can be tested
      // without booting this file. A dashboard-role install with no node yet
      // is ok and says what to do next (#808).
      const verdict = healthzVerdict({
        rippledOk, ledgerOk, peerCount,
        hasSelfNode: !!fleetSelfNode,
        dashboardHost: DASHBOARD_HOST,
        relayFeeding: relayAgeMs !== null,
      });
      const ok = verdict.ok;
      res.writeHead(ok ? 200 : 503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({
        ok,
        role: verdict.role,
        rippled_connected: verdict.rippledConnected,
        ...(verdict.nodes !== undefined ? { nodes: verdict.nodes } : {}),
        ...(verdict.nextStep ? { next_step: verdict.nextStep } : {}),
        ledger_age_ms: ledgerAgeMs,
        relay_last_push_ms: relayAgeMs,
        // The wall-clock moment of that last push, and the one label this
        // process accepts (ADR 0009). The Add a node watch reads these to
        // judge "has a frame arrived SINCE I started watching", which a
        // relative age cannot say on a box whose own relay never stops
        // pushing (#601): an age of one second is true every second there,
        // and it was read as the new node's first frame. Same class of fact
        // as relay_last_push_ms: freshness, no operator, no question.
        relay_last_push_at: lastNetStatsAt || null,
        relay_label: acceptedNodeLabel,
        uptime_s: Math.round(process.uptime()),
        // How many Advisor questions this process is forwarding right now,
        // punch #24. On the aggregator this is the number that matters
        // before a restart: the middle hop of a peer question is a fetch
        // held open HERE, and killing it hangs up on the advisord that is
        // still answering. fleet-update waits for this to reach zero.
        //
        // Reported alongside `ok` rather than folded into it: a process
        // carrying questions is busy, not unhealthy, and a load balancer
        // must not read it as a reason to take the host out.
        asks_in_flight: asksInFlight(),
      }));
      return;
    }

    // Auth (Phase A1), passkey ceremony + session endpoints. Always
    // unauthenticated; bootstraps a session that the gate below then
    // checks for every other request. The Advisor's coordinates are threaded
    // through so /auth/lock can best-effort revoke this operator's unspent
    // approvals on the way out, see revokeApprovalsOnLogout in auth.ts.
    // The linked nodes' Advisors ride along as a function, read at logout: an
    // approval made from here lives on the node it ran on (#1094).
    if (await handleAuthRequest(req, res, pathname, ADVISOR_URL, advisorApproveToken(),
      () => logoutCancelTargets(fleetPeerNodes, readTokenFresh))) return;

    // ── The read surface, ADR 0008 ──────────────────────────────────
    // The Advisor reads dashboard data through these routes and never opens
    // the SQLite file. Handled BEFORE the session gate below, and scoped to
    // /read/ only: advisord has no cookie, no session and no credential
    // store by design, so it authenticates with a dedicated service token,
    // and that token must satisfy nothing outside this block. In particular
    // it must never satisfy /api/advisor/ledger-witness (the dashboard's
    // independent witness to the Advisor's own ledger, the operator's
    // route), and these paths must never join isPublicPath, which would
    // open them to the internet instead of to loopback plus a token.
    // The route set, the gate ordering and the version behaviour live in
    // lib/read-api.ts; the exclusions are enforced by absence, auth tables
    // and the ledger witness have no route here to serve them.
    if (isReadPath(pathname)) {
      const decision = gateRead({
        method: req.method ?? 'GET',
        pathname,
        remoteAddress: req.socket.remoteAddress,
        authorization: req.headers.authorization,
        expectedToken: readSurfaceToken(),
        channels: url.searchParams.get('channels') ?? undefined,
      });
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      if (!decision.ok) { send(decision.status, decision.body); return; }

      // ── The one streaming member, ADR 0013, decision 4 ────────────────
      // Handled HERE, before okBody exists, and never as a `case` in the
      // switch below: send()/okBody() are one-shot closures that write
      // `content-type: application/json` and call res.end(), and every case
      // under them is built on that assumption. A stream branch inside that
      // switch would be writing an event stream through helpers designed to
      // terminate the response.
      if (decision.kind === 'stream') {
        const admitted = readStreams.add(
          {
            write: (chunk: string) => res.write(chunk),
            end: () => res.end(),
            bufferedBytes: () => res.writableLength,
          } satisfies StreamSink,
          decision.channels,
          Date.now(),
        );
        if (!admitted.ok) {
          // Refused by name, never queued: a queued stream is a stream that
          // delivers nothing and says nothing about why.
          send(503, { error: admitted.error });
          return;
        }
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-store',
          'connection': 'keep-alive',
          // Any reverse proxy in front of this must not buffer the stream
          // into oblivion; harmless where there is none.
          'x-accel-buffering': 'no',
        });
        // The envelope's stand-in, an event stream has no response body to
        // carry protocol_version, and a client that does not see `hello`
        // first treats the connection as failed.
        res.write(formatSseEvent('hello', {
          protocol_version: READ_PROTOCOL_VERSION,
          channels: decision.channels,
        }));
        // First tick immediately, so a reconnect (the lifetime cap fires one
        // every 15 minutes by design) paints from a real reading rather than
        // sitting blank for up to a second.
        if (decision.channels.includes('validations_tick')) {
          res.write(formatSseEvent('validations_tick', currentValidationsTickFields()));
        }
        const drop = () => readStreams.remove(admitted.conn);
        res.on('close', drop);
        res.on('error', drop);
        return;
      }

      const okBody = (payload: object) =>
        send(200, { protocol_version: READ_PROTOCOL_VERSION, ...payload });
      const bad = (detail: string) => send(400, { error: 'bad_request', detail });
      const num = (name: string, dflt: number, max: number) =>
        Math.min(max, Math.max(1, Math.floor(Number(url.searchParams.get(name) ?? dflt) || dflt)));
      switch (decision.route) {
        case 'history': {
          const metric = url.searchParams.get('metric') ?? '';
          const range  = url.searchParams.get('range')  ?? '1h';
          const aggRaw = (url.searchParams.get('agg') ?? 'avg').toLowerCase();
          const agg: 'avg' | 'max' | 'min' = aggRaw === 'max' ? 'max' : aggRaw === 'min' ? 'min' : 'avg';
          if (!VALID_METRICS.has(metric)) { bad('unknown metric: ' + metric); return; }
          const rangeMs = VALID_RANGES[range];
          if (!rangeMs) { bad('unknown range: ' + range); return; }
          okBody({ metric, range, agg, points: await historyCache.get(metric, range, rangeMs, agg) });
          return;
        }
        case 'recent': {
          const metric = url.searchParams.get('metric') ?? '';
          if (!VALID_METRICS.has(metric)) { bad('unknown metric: ' + metric); return; }
          const limit = num('limit', 30, 500);
          okBody({ metric, limit, points: queryRecent(metric as MetricName, limit) });
          return;
        }
        case 'ledgers': {
          // ?around=<index>&span=<n>, the window centred on a named ledger.
          // The table retains 30 days (~650k rows) but the latest-N form
          // reaches ~33 minutes back, so "compare this ledger against its
          // neighbourhood" was unanswerable about anything older, which is
          // most things an operator asks about (plan-interrogative-loop,
          // Phase A).
          //
          // The response ECHOES around and the APPLIED span. Additive
          // optional parameters do not bump protocol_version, provided the
          // response echoes them and the client asserts presence, a server
          // that never echoes is a server that ignored the parameter, and
          // the client must fail that read by name rather than reason over
          // a silently narrower window.
          const aroundRaw = url.searchParams.get('around');
          if (aroundRaw !== null) {
            const around = Math.floor(Number(aroundRaw) || 0);
            if (around <= 0) { bad('around must be a positive ledger index'); return; }
            // Clamped, and the clamped value is what is echoed: a model told
            // 400 and served 61 would reason over a window it does not have.
            const span = num('span', 21, 61);
            const half = Math.floor(span / 2);
            const rows = queryLedgerWindow(around - half, around + half);
            okBody({ around, span, requested: span, returned: rows.length, ledgers: rows });
            return;
          }
          const limit = num('limit', 50, 500);
          okBody({ limit, ledgers: queryRecentLedgers(limit) });
          return;
        }
        case 'agreement': {
          // The store prunes this table at two days. Saying so in every
          // response is the difference between "the API is broken" and "the
          // window is what it is" the first time a 30-day ask returns two
          // days of rows (ADR 0008, trade-offs).
          const RETAINED_MS = 2 * 24 * 60 * 60 * 1000;
          const sinceMs = Math.max(Date.now() - RETAINED_MS, Number(url.searchParams.get('since_ms') ?? 0) || 0);
          okBody({ retention_days: 2, since_ms: sinceMs, rows: queryAgreementSince(sinceMs) });
          return;
        }
        case 'missed-ledgers': {
          const limit = num('limit', 100, 500);
          okBody({ limit, missed: queryMissedLedgers(limit) });
          return;
        }
        case 'alerts': {
          const sinceMs = Number(url.searchParams.get('since_ms') ?? 0) || (Date.now() - 24 * 60 * 60 * 1000);
          const limit = num('limit', 200, 500);
          okBody({ since_ms: sinceMs, limit, alerts: queryAlertHistory(sinceMs, limit) });
          return;
        }
        case 'firing': {
          okBody({ firing: queryFiringState() });
          return;
        }
        case 'digests': {
          const sinceMs = Number(url.searchParams.get('since_ms') ?? 0) || (Date.now() - 7 * 24 * 60 * 60 * 1000);
          const limit = num('limit', 50, 200);
          okBody({ since_ms: sinceMs, limit, digests: queryDigestRuns(sinceMs, limit) });
          return;
        }
        case 'bandwidth': {
          const limit = num('limit', 12, 24);
          okBody({ limit, months: queryBandwidthMonths(limit) });
          return;
        }
        case 'identity': {
          // This node's identity as the snapshot already knows it, no new
          // polling, just exposing pollServerInfo's own fields (server.ts
          // ~2092). Raw values, not display-normalised (see IdentityResponse
          // in read-contract.ts): a fleet peer comparing pubkey_node against
          // fleet.yaml's expected_pubkey_node needs the exact string rippled
          // reports, not the truncated/stripped forms the tab renders.
          const info = (snapshot.server_info ?? {}) as AnyObj;
          const pubkeyNode = typeof info.pubkey_node === 'string' && info.pubkey_node ? info.pubkey_node : null;
          const buildVersion = typeof info.build_version === 'string' && info.build_version ? info.build_version : null;
          // Number(), not a `typeof === 'number'` guard, same convention as
          // jq_trans_overflow just above (server.ts ~2116): "some rippled
          // builds expose this as a string counter". This project's
          // characteristic fork bug is a field blanking because a fork
          // changed its representation, not its meaning; coercing a
          // stringified integer isn't normalising the VALUE (still the raw
          // network_id, no Mainnet/Testnet label), just its JS type.
          const network = info.network_id != null && !Number.isNaN(Number(info.network_id)) ? Number(info.network_id) : null;
          okBody({ pubkey_node: pubkeyNode, build_version: buildVersion, network });
          return;
        }
        case 'node-status': {
          // D8 first slice (advisor-enhancement/d8-aggregator-build-plan.md).
          // No new polling, exposes pollServerInfo's own cache, the same
          // discipline as 'identity' above. buildNodeStatusFields does the
          // field mapping (dashboard/lib/read-payloads.ts) so it's
          // unit-testable without an HTTP round trip.
          const info = (snapshot.server_info ?? null) as AnyObj | null;
          const clockRaw = (lastSystemBroadcast as AnyObj | null)?.clock as AnyObj | undefined;
          okBody(buildNodeStatusFields({
            info,
            // hostnameForAlerts(), the same as the `system` broadcast's
            // host.meta.hostname (hostMetaNow): a fleet Overview cross-checks
            // the two, so they change together or one page gives two answers
            // to "what host is this node on". On a split install both name
            // the machine the relay reports, the one the alerts name (#1284).
            hostName: hostnameForAlerts() || null,
            domain: snapshot.domain_status?.domain ?? null,
            unlTotal: snapshot.trusted_unl?.size ?? 0,
            isValidator: isValidatorNode(),
            amendments: lastAmendmentsBroadcast,
            clock: clockRaw ? { ntp_synced: clockRaw.ntp_synced as boolean | null, time_drift_ms: clockRaw.time_drift_ms as number | null } : null,
            nodeReach: nodeReachState(),
            serverInfoAtMs,
            nowMs: Date.now(),
            // This host's own deploy stamp, so a fleet aggregator can tell
            // whether this box is running the same commit it is (#128). Null
            // when there is no stamp — never fabricated.
            deployRef: deployRefReader.current(),
            // And which published release this install is, so an aggregator
            // can grade a fleet against one release.json rather than asking
            // each host what it thinks of itself (ADR 0022 decision 6).
            release: identityForWire(releaseReader.current()),
            // This host's relay build (#593), read the way the local System
            // tab's Relay row reads it: the last relay push's own
            // `relay_version`, through the commit-shape check that turns an
            // unstamped `dev` into "not measured". Null before any push.
            relayVersion: sanitizeComponents({ relay: lastRelayVersion ?? '' }).relay ?? null,
            // Where this dashboard is installed and who it runs as (#615),
            // so an aggregator's Settings prints this box's real path in
            // the commands it hands an operator. Both are facts about this
            // process, nothing a request carries.
            installDir: resolve(import.meta.dirname, '..'),
            runAs: dashboardAccountName(),
          }));
          return;
        }
        case 'peers': {
          // D8 first slice. Serves snapshot.peers as pollPeers already
          // enriches it (server.ts ~2200), no new polling. node_reach rides
          // along because pollPeers swallows every rippled error and never
          // clears snapshot.peers, so a peer list served while the node
          // itself is unreachable is the LAST list, not a current one (see
          // PeersResponse's doc comment in read-contract.ts).
          okBody(buildPeersFields(snapshot.peers ?? [], nodeReachState()));
          return;
        }
        case 'validation-summary': {
          // D8 first slice. computeAgreementStats()'s output, field for
          // field, never raw agreement rows (the plan's cost accounting:
          // ~25,000 rows per 24h fetch to render four integers).
          okBody(buildValidationSummaryFields(computeAgreementStats()));
          return;
        }
        case 'consensus-snapshot': {
          // The Consensus tab's 14 live-value cards, for a peer. No new
          // polling, reuses snapshot.server_info/snapshot.fee (the same
          // sources 'node-status' and pollFee already maintain),
          // validationTsLog (the same 60s window `validations_tick`
          // already broadcasts), lastLedgerClose (cached at the
          // ledgerClosed handler, server.ts ~1978), and two bounded reads
          // of the metrics table the `history` route already serves from,
          // 1200 close_time samples covers ~1h at typical close cadence
          // (matches consensus.html's own state.closeTimings cap), 60
          // txn_count samples comfortably covers a 60s window even at an
          // implausibly fast close rate.
          okBody(buildConsensusSnapshotFields({
            info: snapshot.server_info ?? null,
            fee: snapshot.fee ?? null,
            validationRatePerMin: validationTsLog.length,
            closeTimeSamples: queryRecent('close_time', 1200),
            txnCountSamples: queryRecent('txn_count', 60),
            lastClose: lastLedgerClose,
            serverInfoAtMs,
            feeAtMs,
            nodeReach: nodeReachState(),
            nowMs: Date.now(),
          }));
          return;
        }
        case 'amendment-ballot': {
          // The Governance tab's per-amendment ballot table, for a peer.
          // No new polling, snapshot.feature is already maintained by
          // pollFeature(); the row computation itself lives in
          // lib/amendments.ts (buildAmendmentBallotRows), shared with this
          // process's own local Governance page so the two can never
          // disagree about the same rippled feature data.
          okBody(buildAmendmentBallotFields({
            features: (snapshot.feature ?? {}) as Record<string, AmendmentFeatureEntry>,
            ext: snapshot.xrpscan_amendments,
            desc: snapshot.amendment_descriptions,
            counted: amendmentVotes.current(),
            featureAtMs,
            libraryAtMs: amendmentsLibraryAtMs,
            nodeReach: nodeReachState(),
            nowMs: Date.now(),
          }));
          return;
        }
        case 'governance': {
          // The rest of the Governance tab, for a peer, the vote stance
          // card, the publisher health card and its table, and the
          // amendment-blocked pill. No new polling: pollFeature() and
          // pollValidatorListSites() already maintain both snapshots, and
          // the aggregates come from the same two library builders this
          // process's own Governance page uses. Each half carries its own
          // poller's age (feature_age_ms / sites_age_ms) rather than one
          // number that would be wrong for whichever moved last.
          okBody(buildGovernanceFields({
            features: (snapshot.feature ?? {}) as Record<string, AmendmentFeatureEntry>,
            ext: snapshot.xrpscan_amendments,
            counted: amendmentVotes.current(),
            sites: (snapshot.validator_list_sites ?? []) as ValidatorListSiteEntry[],
            info: (snapshot.server_info ?? null) as Record<string, unknown> | null,
            featureAtMs,
            sitesAtMs,
            nodeReach: nodeReachState(),
            nowMs: Date.now(),
          }));
          return;
        }
        case 'system': {
          // Overview's SYSTEM card AND the System tab's own cards/
          // accordions, for a peer. No new polling, pushSystem() already
          // runs on its own 5s interval, independent of rippled connectivity
          // (readCpu/readMemAndSwap/readDisk read /proc and statfs on this
          // host directly; get_counts/shard_count are this process's own
          // periodic rippled RPC calls, same discipline). Passing
          // lastSystemBroadcast straight through, buildSystemFields returns
          // the all-null envelope if it's still null (before this process's
          // first tick), never a zeroed "idle host" reading, and keeps
          // several sections (node_db_cfg, get_counts, disk_io)
          // independently nullable per SystemResponse's own doc comment.
          okBody(buildSystemFields(lastSystemBroadcast));
          return;
        }
        case 'fleet': {
          // #59. The roster this dashboard holds, and what it last observed
          // of each member. No new polling: fleetView() is the same assembly
          // the FLEET card and /api/fleet already render from, and every
          // field served here is already on that card in the browser.
          //
          // This is what lets the Advisor tell "no node by that name is
          // registered here" apart from "that node is registered and cannot
          // be reached right now". Its own peer table cannot: a fleet.yaml
          // row whose token path this host has no copy of is left OUT of
          // advisor/state/fleet.json rather than guessed at
          // (lib/advisor-registry-gen.ts), so those two states arrived at
          // the Advisor as one.
          const view = fleetView();
          okBody(buildFleetRosterFields(
            view?.nodes ?? null,
            selfDisplayLabel(view?.nodes.find((n) => n.self) ?? null),
            Date.now(),
          ));
          return;
        }
        case 'node-config': {
          // #59. The four settings ADR 0018's config runbook may change, as
          // this host's own rippled.cfg has them right now, read once at
          // startup by readRippledCfg() above, no new file read per request.
          // Two of them (online_delete, advisory_delete) are already served
          // by `system`; the other two are the reason this route exists, and
          // they are stanza-shaped rather than key=value.
          okBody(buildNodeConfigFields(
            lastRippledCfgParsedAtMs !== null
              ? {
                  parsed_at_ms: lastRippledCfgParsedAtMs,
                  node_size: lastNodeStanzaCfg?.node_size ?? null,
                  ledger_history: lastNodeStanzaCfg?.ledger_history ?? null,
                  online_delete: lastNodeDbCfg?.online_delete ?? null,
                  advisory_delete: lastNodeDbCfg?.advisory_delete ?? null,
                }
              : null,
          ));
          return;
        }
        case 'net-stats': {
          // The Network tab's BANDWIDTH LIVE + ERRORS & BUDGET cards, for a
          // peer. No new polling, handleRelayPush() already refreshes
          // lastNetStatsBroadcast on every relay push; this route exposes it
          // verbatim. buildNetStatsFields returns the all-null envelope both
          // before this node's first relay push AND permanently for a peer
          // that has no relay configured at all, see NetStatsResponse's own
          // doc comment for why a caller must not try to tell those apart.
          okBody(buildNetStatsFields(lastNetStatsBroadcast));
          return;
        }
        case 'validations-tick': {
          // Overview's "Validations received / quorum" row, for a peer. No
          // cached broadcast object to expose here (unlike `system`/
          // `net-stats`), this rebuilds the SAME object the 1Hz
          // `validations_tick` WS push builds (the setInterval just above
          // sampleSystemHistoryMetrics), straight from the live in-memory
          // round counters, on demand: the real current value every time,
          // never a copy that could lag the broadcast. `quorum_raw` reads
          // snapshot.server_info directly, the same discipline the
          // `identity` route already uses, buildValidationsTickFields
          // turns rippled's unsigned -1 "UNL not loaded yet" sentinel into
          // an honest null quorum rather than the literal number.
          //
          // ONE builder, shared with the `validations_tick` stream channel
          // (currentValidationsTickFields, beside the 1Hz fanout), what
          // keeps a peer's streamed bar and its polled fallback from
          // disagreeing during a degradation, the moment the operator is
          // most likely to be looking.
          okBody(currentValidationsTickFields());
          return;
        }
      }
      // Unreachable while the switch covers READ_ROUTE_NAMES; kept so a route
      // added to the contract without a handler fails loudly instead of
      // hanging the request.
      send(500, { error: 'bad_request', detail: 'route has no handler' });
      return;
    }

    // ── The fleet-write surface, the node's side of a Settings seal ─────
    //
    // Two routes, /fleet/v1/model/seal and /fleet/v1/model/arm, mounted HERE:
    // after the read block, before the session gate, and behind the SAME
    // read token. That placement is deliberate on both sides. Before the
    // session gate, because the caller is another dashboard on the far end
    // of a loopback forward and has no cookie to present; behind the read
    // token, because it is the credential that fleet already distributes per
    // node, and a second one would be a second thing to rotate.
    //
    // NO fleet registry precondition. A joined node holds a fleet-trust.yaml
    // with peers.aggregator and typically no fleet.yaml of its own, so
    // fleetSelfNode is null and fleetPeerNodes is empty on exactly the hosts
    // this surface exists for. Whether this node accepts a job is decided by
    // the pinned key and the arming window, never by whether it happens to
    // know about a fleet.
    //
    // The gate ordering, the route set and every named refusal live in
    // lib/fleet-write-api.ts, asserted in its own test. What is here is only
    // the work each admitted request causes.
    if (isFleetWritePath(pathname)) {
      const decision = gateFleetWrite({
        method: req.method ?? 'GET',
        pathname,
        remoteAddress: req.socket.remoteAddress,
        authorization: req.headers.authorization,
        expectedToken: readSurfaceToken(),
      });
      const sendFleet = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      if (!decision.ok) { sendFleet(decision.status, decision.body); return; }

      // The same value /read/v1/identity serves, read the same way: the
      // snapshot rippled already filled, never a fresh poll. A node that
      // cannot say what it is refuses every job addressed to one.
      const ownPubkeyNode = (() => {
        const info = (snapshot.server_info ?? {}) as AnyObj;
        return typeof info.pubkey_node === 'string' && info.pubkey_node ? info.pubkey_node : null;
      })();

      // Which act this route is, as a lookup rather than as a fallthrough
      // (#319). Every branch below is reached by name; a route this contract
      // carries and this build serves no work for is refused here, and is
      // never quietly handled as the seal.
      const work = fleetWriteWork(decision.route, decision.method);
      if (!work.ok) { sendFleet(work.status, work.body); return; }

      if (work.work === 'arm-state') {
        // A stat of a marker this account can neither read nor write, so the
        // aggregator's Settings page can show per-node arm state. Same answer
        // /api/advisor/model/arm gives this host's own operator.
        const state = armState(() => {
          try { return statSync(ARM_MARKER).mtimeMs; } catch { return null; }
        }, Date.now());
        sendFleet(200, { ...state, window_s: ARM_WINDOW_SEC, marker: ARM_MARKER });
        return;
      }

      if (work.work === 'update-state') {
        // What this node's OWN updater says about this node. Every member is
        // this host's measurement: the aggregator renders it and derives
        // nothing from it, which is what keeps a fleet table from ever
        // showing a node as updated on anything but that node's own word.
        //
        // Served from the cached probe, so a two-second poll from an
        // aggregator cannot drive the rate at which this host starts a root
        // program (the same reason the local card reads it that way).
        const probe = await updaterCheck(false);
        const view = updaterView(probe.facts);
        const decision = decideLocalApply({
          probe: { present: probe.present, reading: view.reading, graded: view.graded },
          // A fallback, never a veto (#335). This route is polled, so it
          // cannot take a live HTTP reading of its own, and the one this
          // process keeps is refreshed once a day. Used as the other half of
          // the disagreement test, that day-old memory made every fleet
          // apply refuse from the first publish after a node's last
          // background check until its next one, in words that blamed
          // ENDPOINT in a root-owned file for a clock.
          //
          // So where this host's own updater produced a verdict, that
          // verdict is the answer and the kept reading is not consulted at
          // all. Where it produced nothing to grade from, which is an
          // updater too old to name its endpoint, the kept reading is still
          // better than no answer: it is what this row said before, and
          // withholding the button on that host would be a second bug
          // wearing the first one's clothes. The apply route re-reads both
          // live before it acts either way.
          pageCheck: view.graded ? null : lastUpdateCheck,
        });
        const reading = view.reading;
        const state: UpdateStateResponse = {
          updater: probe.present,
          // Did the probe get an answer at all (#331). `updater: false` on
          // its own folds "no grant here" together with "the socket said
          // nothing", and an aggregator that turned the second into a row
          // saying "install the update grant" would send an operator to run
          // a root command on a host that already holds it.
          updater_answered: probe.answered,
          // Whether this node holds the aggregator's key, by its own reading
          // of its own file (#331). The SAME call gate 6 of checkUpdateJob
          // makes, so what a fleet row displays and what a press would
          // actually be refused with come from one reader.
          //
          // Reported here because this route runs no job gate:
          // `no_aggregator_pinned` is only ever reached on the two signed
          // POST routes, so a read can never carry it.
          aggregator_pin: aggregatorPinState(),
          endpoint: reading?.endpoint ?? null,
          published: reading?.latest
            ? { tag: reading.latest.tag, commit: reading.latest.commit, sha256: reading.latest.sha256 }
            : null,
          installed: reading?.installed ?? null,
          verdict: reading?.verdict ?? null,
          // What this host's own components measure about their own build
          // (#266). The relay's ref rides the pushes this process already
          // receives; the Advisor daemon's is asked for at most once a
          // minute (componentsNow). Omitted entirely when nothing survives
          // the check: no relay connected yet, no daemon answer yet, or a
          // build that was never stamped with a commit.
          ...(() => {
            const components = componentsNow();
            return Object.keys(components).length ? { components } : {};
          })(),
          can_apply: decision.ok,
          ...(decision.ok ? {} : { cannot_apply_detail: decision.refusal.error }),
          run: updateRun ? {
            run_id: updateRun.id,
            action: updateRun.action,
            running: updateRun.running,
            started_at: updateRun.started_at,
            finished_at: updateRun.finished_at,
            steps: [...updateRun.snapshot.steps],
            code: updateRun.snapshot.code,
            verdict: updateRun.verdict,
            // A TAIL. The whole record stays here, where this host's own
            // page reads all of it; what crosses the link is bounded by a
            // constant rather than by an estimate of how noisy a build is.
            lines: updateRun.snapshot.lines.slice(-UPDATE_STATE_TAIL_LINES),
            line_count: updateRun.snapshot.lines.length,
            needs_restart: needsRestart(updateRun.snapshot.facts),
            release: updateRun.release ?? null,
          } : null,
          // What this host kept about its last run, across the process that
          // held it. Null until this host has run one. Its `restarted_after`
          // is this host's own measurement and says nothing about any unit
          // but the one answering this request (#323).
          last_run: lastRunForWire(),
          // The release key root's updater here checks against (#784), the
          // same root-owned read this host's own card makes, and never a test
          // key this process was pointed at. `lab` only when this host's own
          // updater said so, as on that card.
          release_key: (() => {
            const own = releaseKeyWire(undefined, RELEASE_SIGNERS_PATH);
            return {
              state: own.state,
              fingerprints: own.fingerprints,
              ...(probe.facts?.signers === 'lab' ? { lab: true as const } : {}),
            };
          })(),
        };
        sendFleet(200, state);
        return;
      }

      if (work.work === 'advisor-state') {
        // This node's own Advisor presence (#641), served from the same
        // cached probe /api/advisor-presence already reads, plus the one
        // field that route has never carried: the build stamp. Never
        // re-probed per request, for the same reason update-state above is
        // not: a poll from an aggregator's Settings page must not drive the
        // rate this host asks its own Advisor anything.
        //
        // No token, no secret, ever, in this response. That is the whole
        // reason attach needs a SEPARATE signed, window-gated route for the
        // one thing this free GET must never answer. buildAdvisorStateResponse
        // is a pure builder, tested to carry no token key by construction.
        // Read through readAdvisorPresence, not the bare cache (#995): a unit
        // an uninstall just removed must not stay `present` for the rest of
        // the 20 s interval. A stat() when nothing has changed.
        const presenceNow = await readAdvisorPresence();
        sendFleet(200, buildAdvisorStateResponse({
          state: presenceNow.state,
          lastAnsweredMs: lastAdvisorAnsweredMs(),
          detail: presenceNow.detail,
          version: advisorVersion,
        }));
        return;
      }

      const rawBody = await readFleetWriteBody(req);
      if (rawBody === null) {
        sendFleet(400, { error: 'bad_job', detail: 'the request is larger than this route accepts' });
        return;
      }

      switch (work.work) {
        case 'arm-token': {
          const armCheck = checkArmToken({
            body: rawBody,
            thisPubkeyNode: ownPubkeyNode,
            nowMs: Date.now(),
            nonces: fleetWriteNonces,
          });
          if (!armCheck.ok) { sendFleet(armCheck.status, armCheck.body); return; }
          // Carried, not judged. This process holds no key that could verify an
          // arm token and must not look like it does: root on this host is the
          // verifier, against a public key root placed.
          try {
            const out = await askSocketProgram(
              SEAL_SOCKET_PATH,
              armPayload(armCheck.value.token, armCheck.value.signature),
              30_000, 'the sealer',
            );
            const outcome = armOutcome(out);
            sendFleet(outcome.ok ? 200 : 409, outcome);
          } catch {
            // The error's own message is never passed through: it is the one
            // place a payload could ride out of here, and the class of failure
            // is what an operator can act on anyway.
            // The seal path's own `unavailable`, by the same name: no sealer
            // to ask is a different sentence from a sealer that refused, and
            // an operator acts on them differently.
            sendFleet(503, {
              ok: false, armed: false, window_s: null, issuer: null, error: 'unavailable',
              detail: 'This node has no sealing socket. Run the Advisor install command on it again.',
            });
          }
          return;
        }

        case 'model-seal': {
        // Every gate has run before this point and none of them has touched the
        // sealer; what follows is exactly what the per-node seal does, with the
        // job's own fields standing in for the pending record's.
        const check = checkSealJob({
          body: rawBody,
          thisPubkeyNode: ownPubkeyNode,
          peerKey: (label) => readPeerPubKey(FLEET_TRUST_PATH, label),
          nowMs: Date.now(),
          nonces: fleetWriteNonces,
        });
        if (!check.ok) { sendFleet(check.status, check.body); return; }
        const { job } = check.value;
        const outcome = await sealModelKey({
          baseUrl: job.base_url,
          shape: job.shape,
          model: job.model,
          credentialName: job.credential_name,
          key: check.value.key,
        }, runSealer);
        // The fact the operator on the aggregator is actually waiting on: not
        // that the service came back, but that the Advisor reports a MODEL.
        // Same five tries, same three-valued answer as the per-node seal.
        let modelConfigured: boolean | null = null;
        if (outcome.ok) {
          for (let attempt = 0; attempt < 5; attempt++) {
            if (attempt > 0) await new Promise((r) => setTimeout(r, 2_000));
            try { modelConfigured = await readBackAdvisorModel(); } catch { modelConfigured = null; }
            if (modelConfigured !== null) break;
          }
        }
        // On THIS node's record, naming the human who touched the passkey on
        // the aggregator and the machine that carried it. A node whose model
        // key changed should be able to answer "who did that" from its own
        // audit trail rather than from someone else's.
        recordAuthEvent({
          actor: job.granted_by,
          actorRole: null,
          event: 'model_key_sealed',
          target: job.credential_name,
          detail: {
            outcome: outcome.ok ? 'sealed' : 'refused',
            reason: outcome.reason,
            model: job.model,
            base_url: job.base_url,
            issuer_label: job.issuer_label,
            via: 'fleet',
            ...(outcome.service ? { service: outcome.service } : {}),
            ...(outcome.config ? { config: outcome.config } : {}),
            ...(outcome.ok ? { model_configured: modelConfigured } : {}),
          },
        });
        sendFleet(outcome.ok ? 200 : 409, {
          ok: outcome.ok,
          reason: outcome.reason,
          detail: outcome.detail,
          ...(outcome.service ? { service: outcome.service } : {}),
          ...(outcome.credential ? { credential: outcome.credential } : {}),
          ...(outcome.config ? { config: outcome.config } : {}),
          model: job.model,
          ...(outcome.ok ? { model_configured: modelConfigured } : {}),
        });
        return;
        }

        case 'update-apply': {
          // An aggregator asking this node to run its OWN updater (#275).
          //
          // Five things are true here and each is a refusal if it is not.
          // The job is signed by the pinned aggregator, fresh, unseen and
          // addressed to this node (checkUpdateJob). This node's own check
          // says it is behind, its own updater and its own page agree on
          // what is published, and the release the job names is the release
          // this node's own check names (decideLocalApply, with the job's
          // three values as the claim). Root then compares them a third time
          // against what ITS endpoint publishes and refuses a disagreement.
          //
          // Nothing about a source crosses. The job carries a tag, a commit
          // and a sha256, and this node reads its endpoint from its own
          // root-owned config. An aggregator can narrow what this node
          // installs and can never widen it.
          const check = checkUpdateJob({
            body: rawBody,
            kind: 'update.apply',
            thisPubkeyNode: ownPubkeyNode,
            peerKey: (label) => readPeerPubKey(FLEET_TRUST_PATH, label),
            nowMs: Date.now(),
            nonces: fleetWriteNonces,
          });
          if (!check.ok) { sendFleet(check.status, check.body); return; }
          const job = check.value.job as UpdateApplyJob;
          if (updateRun?.running) {
            recordFleetRefusal(job.granted_by, 'apply', job.tag, { outcome: 'busy', run_id: updateRun.id });
            sendFleet(409, {
              error: 'bad_job',
              detail: 'an update is already running on this host',
            });
            return;
          }
          // BOTH of this node's readings, taken now (#335).
          //
          // The local Apply button is preceded by Check now, which refreshes
          // this process's own fetch and forces the probe in one request, so
          // the local path always decides on two readings seconds old. The
          // fleet path had neither: it decided on a probe up to five minutes
          // old and on a page-side reading up to a day old, and a job built
          // from the first of those was then checked against the same cached
          // copy of it, which is a reading validating itself.
          //
          // Refreshed HERE, after checkUpdateJob has passed, so the rate is
          // one press: an unsigned job, a stale one, a replay and one
          // addressed elsewhere are all refused above and drive nothing. In
          // parallel because they are independent (one HTTP, one socket) and
          // the aggregator gives this request 30 seconds; in series their
          // two timeouts add up to exactly that.
          //
          // `updaterCheck(true)` still joins a probe already in flight, so
          // the socket's one-connection-at-a-time rule holds.
          const [pageNow, probe] = await Promise.all([
            UPDATE_CHECK_ENABLED
              ? runUpdateCheck('fleet').catch(() => null)
              : Promise.resolve(null),
            updaterCheck(true),
          ]);
          const view = updaterView(probe.facts);
          const decision = decideLocalApply({
            probe: { present: probe.present, reading: view.reading, graded: view.graded },
            // The reading this request just took, never the kept one. Null
            // when this host's checks are switched off or the endpoint did
            // not answer: one live reading and root's own is what is left,
            // and neither of those is a memory.
            pageCheck: pageNow,
            claimed: { tag: job.tag, commit: job.commit, sha256: job.sha256 },
          });
          if (!decision.ok) {
            // This node's own sentence, in its own words. `not_behind` is
            // the named code for the one refusal an aggregator acts on
            // differently: the node is already current, so the row should
            // stop offering an Apply rather than be retried.
            const r = decision.refusal;
            // The same fields the local route's own row carries per branch,
            // on this node's record, naming the human who approved it on the
            // aggregator and marking where it came from.
            recordFleetRefusal(job.granted_by, 'apply', job.tag, {
              outcome: r.reason,
              ...(r.reason === 'endpoint_disagreement' ? {
                updater_endpoint: r.clash.updater_endpoint, updater_tag: r.clash.updater_tag,
                page_endpoint: r.clash.page_endpoint, page_tag: r.clash.page_tag,
              } : {}),
              ...(r.reason === 'nothing_to_apply' ? { state: r.state } : {}),
              ...(r.reason === 'bad_release' || r.reason === 'stale_page' ? { reason: r.detail } : {}),
              asked_tag: job.tag, asked_commit: job.commit,
            });
            sendFleet(409, {
              error: r.reason === 'nothing_to_apply' ? 'not_behind' : 'bad_job',
              detail: `${r.error}. ${r.detail}`,
            });
            return;
          }
          // Checked again, after the awaits above: the socket takes one
          // connection and root holds a lock, so a second run would be
          // refused there — but it would refuse having overwritten the run
          // the aggregator is watching.
          if (updateRun?.running) {
            recordFleetRefusal(job.granted_by, 'apply', job.tag, { outcome: 'busy', run_id: updateRun.id });
            sendFleet(409, { error: 'bad_job', detail: 'an update is already running on this host' });
            return;
          }
          const run = startUpdateRun(
            'apply', applyPayload(decision.release), UPDATE_TIMEOUT_MS.apply,
            { operator: job.granted_by, role: null },
            { release: decision.release, via: 'fleet' },
          );
          sendFleet(202, { run_id: run.id, started_at: run.started_at, release: decision.release });
          return;
        }

        case 'update-restart': {
          // The job names a RUN, never a unit. The unit list comes off this
          // node's own finished run, which root discovered on this box (ADR
          // 0022 decision 5). The aggregator displays those names, read from
          // update/state, and sends none of them.
          const check = checkUpdateJob({
            body: rawBody,
            kind: 'update.restart',
            thisPubkeyNode: ownPubkeyNode,
            peerKey: (label) => readPeerPubKey(FLEET_TRUST_PATH, label),
            nowMs: Date.now(),
            nonces: fleetWriteNonces,
          });
          if (!check.ok) { sendFleet(check.status, check.body); return; }
          const job = check.value.job as UpdateRestartJob;
          if (updateRun?.running) {
            recordFleetRefusal(job.granted_by, 'restart', job.run_id, { outcome: 'busy', run_id: updateRun.id });
            sendFleet(409, { error: 'bad_job', detail: 'an update is already running on this host' });
            return;
          }
          // The approval was taken against what THAT run said needed
          // restarting. A different run means different units, so the
          // approval does not cover this.
          if (!updateRun || updateRun.id !== job.run_id) {
            recordFleetRefusal(job.granted_by, 'restart', job.run_id, {
              outcome: 'wrong_run', asked_run_id: job.run_id, holding_run_id: updateRun?.id ?? null,
            });
            sendFleet(409, {
              error: 'wrong_run',
              detail: updateRun
                ? 'that job names a run this node has moved on from; read this node\'s state again'
                : 'this node is holding no run, so it has nothing a restart was approved against',
            });
            return;
          }
          const units = needsRestart(updateRun.snapshot.facts);
          const refusal = unitListRefusal(units);
          if (refusal !== null) {
            recordFleetRefusal(job.granted_by, 'restart', job.run_id, {
              outcome: 'nothing_to_restart', reason: refusal, run_id: updateRun.id,
            });
            sendFleet(409, {
              error: 'bad_job',
              detail: 'this node has nothing waiting for a restart. A restart is offered only after an apply says which units are running older code than the tree now holds.',
            });
            return;
          }
          const run = startUpdateRun(
            'restart', restartPayload(units), UPDATE_TIMEOUT_MS.restart,
            { operator: job.granted_by, role: null },
            { units, via: 'fleet' },
          );
          sendFleet(202, { run_id: run.id, started_at: run.started_at, units });
          return;
        }

        case 'advisor-reveal': {
          // Attaching an Advisor to an already-paired node (#641). Two
          // independent gates, neither alone sufficient: the signed job
          // proves an aggregator this node already trusts asked, and the
          // window proves a human recently ran the installer, or a re-arm,
          // on THIS box with real sudo. A compromised aggregator can satisfy
          // the first at will; it cannot satisfy the second. All of that
          // ordering lives in decideAdvisorReveal, a pure function; this is
          // only its wire-up, so a test drives the decision without a real
          // socket, clock or file.
          const check = checkAdvisorRevealJob({
            body: rawBody,
            thisPubkeyNode: ownPubkeyNode,
            peerKey: (label) => readPeerPubKey(FLEET_TRUST_PATH, label),
            nowMs: Date.now(),
            nonces: fleetAdvisorNonces,
          });
          const decision = decideAdvisorReveal({
            check,
            // A thunk: stat'd only when the job above already checked out.
            windowFacts: () => statAdvisorRevealWindow(Date.now()),
            // Called only once the window is confirmed open.
            token: advisorApproveToken,
            version: advisorVersion,
          });
          // Never logged, never cached: this is the one place the token
          // crosses at all, and it crosses once, in a 200 body only.
          sendFleet(decision.status, decision.body);
          return;
        }

        default: {
          // Unreachable while the switch covers FleetWriteWork, and the
          // compiler is what says so: a work token added without a branch
          // fails to build here rather than falling into the seal.
          const unserved: never = work.work;
          sendFleet(500, {
            error: 'no_handler',
            detail: `that node's dashboard admitted ${String(unserved)} and has no branch for it`,
          });
          return;
        }
      }
    }

    // Auth gate (Phase A2), every route past this point requires a
    // valid session, except a small whitelist (/login.html, vendored
    // WebAuthn bundle, brand assets). API requests get 401 JSON so the
    // frontend can lock in place; HTML requests get a 302 to the
    // lock-screen with ?next= preserving the operator's destination.
    if (requireAuthGate(req, res, pathname)) return;

    // History API, bucketed time-series query, returns JSON.
    // Optional `agg` query param picks the aggregation per bucket:
    //   avg (default)  typical/average value, smooths noise
    //   max            peak value, surfaces spikes inside the bucket
    //   min            floor value, surfaces drops inside the bucket
    // Used per-metric so close_time / load_factor / etc. show their
    // peaks instead of getting averaged away over wide bucket windows.
    if (pathname === '/history') {
      const metric = url.searchParams.get('metric') ?? '';
      const range  = url.searchParams.get('range')  ?? '1h';
      const aggRaw = (url.searchParams.get('agg') ?? 'avg').toLowerCase();
      const agg: 'avg' | 'max' | 'min' = aggRaw === 'max' ? 'max' : aggRaw === 'min' ? 'min' : 'avg';
      if (!VALID_METRICS.has(metric)) { res.writeHead(400); res.end('bad metric'); return; }
      const rangeMs = VALID_RANGES[range];
      if (!rangeMs) { res.writeHead(400); res.end('bad range'); return; }
      // #831: the same cache as the read API's history route, so this
      // node's own charts neither block the event loop on a long range nor
      // pay for an aggregation the peer views just paid for.
      const points = await historyCache.get(metric, range, rangeMs, agg);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      // is_validator so a card built from an agreement series can tell a
      // node that is not validating NOW from one that simply has no data.
      // History is real and kept, a node that validated yesterday still
      // has yesterday's numbers, but presenting them as this node's
      // current agreement is how a stock node ended up with a red
      // "Agreement at 0.00%" banner over it.
      res.end(JSON.stringify({ metric, range, agg, points, is_validator: isValidatorNode() }));
      return;
    }

    // What the dashboard has independently witnessed about the Advisor's
    // audit ledger, and any contradiction it has recorded.
    if (pathname === '/api/advisor/ledger-witness') {
      const seen = highestWitnessed();
      const alarms = queryLedgerAlarms(20);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({
        witnessed: seen,
        alarms,
        ok: alarms.length === 0,
      }));
      return;
    }

    // The fleet-wide Advisor ledger mirror, ADR 0021 build step 3. #231 is
    // the search surface that will read this; nothing does yet. Two shapes
    // on one route, chosen by whether `q` is present, so the eventual UI
    // needs only one endpoint to learn: the summary for the Audit trail's
    // per-node header, and a full-text hit list once there is a box to type
    // a query into. Session-gated only, like /api/advisor/ledger itself:
    // this is a copy of the same audit trail every role may already read.
    if (pathname === '/api/advisor-mirror') {
      const q = url.searchParams.get('q');
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      if (q && q.trim()) {
        const node = url.searchParams.get('node') ?? undefined;
        const limit = Number(url.searchParams.get('limit') ?? 50);
        res.end(JSON.stringify({ hits: mirrorSearch(q, { node, limit }) }));
      } else {
        res.end(JSON.stringify({ nodes: mirrorSummary() }));
      }
      return;
    }

    // The fleet memory and inbox mirrors, ADR 0021 build step 5. Admin-only,
    // unlike /api/advisor-mirror just above: that route mirrors the audit
    // ledger, which every role may already read for their own node, but
    // memory and a node's full inbox (decided notes included) carry
    // model-authored content nobody but an admin may read even live, on
    // this node or a peer's (ADMIN_ONLY_ADVISOR_READS above). The mirror
    // must not open a wider door than the thing it mirrors.
    if (pathname === '/api/advisor-notes-mirror') {
      const sess = readSession(req);
      if (!sess) { res.writeHead(401, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'unauthenticated' })); return; }
      if (!isAdmin(sess.role)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'this operator may not read the fleet memory and inbox mirror' }));
        return;
      }
      const rawLimit = Number(url.searchParams.get('limit') ?? 200);
      // The mirror keys this host's own rows under LOCAL_NODE ('@local'), a
      // storage detail (db.ts's own comment on the table says so). Every
      // reader of this route is a person, so `label` carries the name they
      // read everywhere else on this page; `node` stays the raw key,
      // unresolved, because that is what the promote route looks the row up
      // by (knowledge-admin.ts's `promoteMemoryNote`) and a resolved label
      // sent back as `node` would 404 that lookup for every self-row.
      //
      // #1191. Each row also says whether its node is still in the registry
      // (`in_fleet`). The mirror keeps what a renamed or revoked node recorded,
      // and the poller stops asking it, so its last failed poll is not news.
      // The rows are kept; the page marks them and draws no failure for them.
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(notesMirrorAnswer({
        memory: memoryMirrorFleet(rawLimit),
        memory_state: notesMirrorStateAll('memory'),
        inbox: inboxMirrorSummary(),
      }, { localNode: LOCAL_NODE, selfLabel: selfDisplayLabel(fleetSelfNode) || null, registry: fleetRegistryLabels, polled: notesMirrorPolled })));
      return;
    }

    // Every missed validation on record, newest first, with the node's
    // context captured at the moment of each miss. Small by design.
    if (pathname === '/missed-ledgers') {
      const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') ?? 100)));
      const missed = queryMissedLedgers(limit);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      // is_validator so the panel can say "this does not apply here" rather
      // than rendering an empty record as a clean bill of health, or, on a
      // host that ran an older build, rendering rows that never were misses.
      res.end(JSON.stringify({ limit, missed, is_validator: isValidatorNode() }));
      return;
    }

    // Last-N ledger rows for the Overview ticker, newest first
    // The upstream release picture, as this server last saw it. The Advisor
    // tab reads it to say why a release everyone is talking about is not on
    // offer yet, advisord derives its target from the image registry alone,
    // so during the hours between a source release and its image tag the tab
    // would otherwise be silent about a version the operator has already
    // heard of.
    if (pathname === '/release-info') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      // #550. self_installable and self_release_posture are deliberately NOT
      // folded into releaseInfo's own fields (latest_installable, behind,
      // note): those are fleet-wide, read for any node this dashboard can
      // show, and this fact is about this dashboard's own node alone. Named
      // so a caller can tell whose reading it is without reading this
      // comment, and must never apply either to a peer's chip. A peer view
      // keeps releaseInfo's own fields, unchanged.
      //
      // buildReleaseInfoPayload computes the posture ONCE, so the Overview
      // chip and the Advisor tab's Operations card read one classification
      // rather than each judging the same two numbers its own way. Since
      // this fix, so does every other place this dashboard hands
      // release_info to a browser (see that function's own comment).
      res.end(JSON.stringify(buildReleaseInfoPayload()));
      return;
    }

    if (pathname === '/recent-ledgers') {
      const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') ?? 50)));
      const ledgers = queryRecentLedgers(limit);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ limit, ledgers }));
      return;
    }

    // The fleet node picker (header chip + NODES panel), task step B. Both
    // consumers read this SAME endpoint so they cannot disagree. `nodes: []`
    // (a null fleetView() flattened) is the single-node state: absent
    // fleet.yaml, an empty one, or one whose self-identification failed,
    // all three render identically, same as the parser's own absent/invalid
    // equivalence.
    if (pathname === '/api/fleet') {
      const view = fleetView();
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(view ?? { nodes: [] }));
      return;
    }

    // Check for updates — ADR 0022 phase 1, the read half of #62.
    //
    // Admin only, and refused HERE rather than left to the menu that hides
    // the row: the affordance is not the guard (mobile-nav.js injects the
    // row for an admin session the way it injects Settings, and a monitor
    // who calls this by hand still gets a 403). A GET, because it changes
    // nothing on this host: it asks my endpoint what it publishes and
    // compares that with the stamp at the install root.
    //
    // Always to the network, because an admin pressing the button is asking
    // now. The daily background check is the one that writes the metric; this
    // one refreshes what the page shows and what the fleet is graded against.
    if (pathname === '/api/update-check') {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const sess = readSession(req);
      if (!sess) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthenticated' }));
        return;
      }
      if (!isAdmin(sess.role)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'this operator may not check for updates' }));
        return;
      }
      const identity = releaseReader.current();
      // Two readings from one route. Without `check=now` this answers from
      // what the daily background check last learned and makes no outbound
      // call at all, so the panel can paint the release this host is on the
      // instant it opens. With it, the check goes to the network, because an
      // admin who pressed the button is asking now.
      const live = url.searchParams.get('check') === 'now';
      const result = live ? await runUpdateCheck('click') : lastUpdateCheck;
      // The probe rides the same read, cached, and is forced on a live check
      // because an admin who pressed the button is asking about this host
      // now. Never allowed to fail the read: not knowing whether there is an
      // updater is not a reason to withhold the release this host is on.
      let updaterProbe: boolean | null = null;
      let updaterFacts: Record<string, string> | null = null;
      // When those facts were read, which is not when they were asked for:
      // a cache hit is up to five minutes old (#342 below).
      let updaterAt: number | null = null;
      try {
        const probe = await updaterCheck(live);
        updaterProbe = probe.present;
        updaterFacts = probe.facts;
        updaterAt = probe.at;
      } catch { updaterProbe = null; updaterFacts = null; updaterAt = null; }
      // Where there is an updater, ITS answer is the one this card grades
      // from: it reads the endpoint out of /etc/aperire/update.conf, which
      // this account cannot, and that endpoint is the one an apply would
      // install from. A card that offered a release its own host would
      // refuse is the lie one live apply showed (#293).
      const view = updaterView(updaterFacts);
      // The updater names the release and cannot carry its notes; this
      // process's own fetch has them. Same archive, same notes (#295).
      const shown = view.graded ? carryNotes(view.graded, result) : result;
      // Two endpoints, two answers, one host. Reported as a fact rather than
      // resolved quietly: nothing here can tell which of the two the
      // operator meant, and the one that decides is the root-owned file.
      const disagreement = updaterEndpointDisagreement(result, view.reading);
      // One endpoint, two readings of it, and a publish in between (#342).
      // Never both this and the disagreement above: they are the two
      // branches of one comparison.
      //
      // "older" is measured, not assumed, and it is measured inside the
      // function: when the probe's facts were read goes in with the two
      // readings, so this route cannot reach one answer and another caller a
      // different one.
      const readingLag = pageReadingOlderThanUpdater(result, view.reading, updaterAt);
      // The release THIS host's row in the table is graded against, which is
      // the one the facts grid above it was graded from (#365). Undefined
      // means "grade it with the fleet", and there are two of those:
      //
      //   - No updater, so the grid graded from this process's own fetch.
      //     Structurally the same value already: a result carrying a release
      //     IS what `lastAnsweredUpdateCheck` holds, by the line that writes
      //     it.
      //   - The two endpoints disagree (#293). Then the grid's release came
      //     off an endpoint this page never read, and grading the fleet's own
      //     row by it would grade this host against a release the rest of the
      //     table is not being compared with. That split is deliberate, it is
      //     the one the note between the grid and the table names in words,
      //     and the row's tip already says the Apply is not on offer.
      //
      // Withheld too where the updater named no release at all (unreachable,
      // mid-publish): the grid prints no verdict in those states, so there is
      // no word for the row to agree with, and threading null would turn this
      // host "can't compare" over a blip while every peer still grades.
      const selfLatest = view.graded && !disagreement && shown?.latest ? shown.latest : undefined;
      // Graded AFTER the check, so the rows are compared against what this
      // click just learned rather than against yesterday's answer. One
      // fetch, every host: fleetGraded threads the same `latest` into
      // gradeFleetRelease for the whole table.
      //
      // And after the updater probe, which is new (#365): the self row's
      // release is decided above, from the same reading the grid used, so
      // one assembly produces the rows AND the counts the card's title line
      // reads. Re-grading one row afterwards would move the split up a level
      // rather than close it.
      // The peers are graded by THIS process's own reading of the endpoint, not
      // by the updater's (`shown` can be root's, #293): a peer is not graded by
      // this host's update.conf. When that reading named no release, the
      // peers are not graded at all (#863).
      const graded = fleetGraded(selfLatest, fleetGradingReading(result, lastAnsweredUpdateCheck));
      // Every addressable peer, asked what it holds, on the LIVE path only
      // (#331). Taken here and never inside fleetGraded(): that function is
      // also what /api/fleet answers from, which the browser polls, and a
      // link round trip per node on a poll is a cost this card was built to
      // avoid.
      //
      // In parallel, with a short bound, so one node that is down delays the
      // table by one timeout and not by one per node. Never allowed to fail
      // the read: not knowing what a node holds is not a reason to withhold
      // the releases this fleet is on.
      if (live && graded && graded.nodes.length > 1) {
        try {
          const asked = await readFleetCompleteness(completenessTargets(graded.nodes));
          for (const [label, got] of Object.entries(asked)) fleetCompleteness.set(label, got);
        } catch { /* the rows fall back to the last answer, or to none */ }
      }
      const completenessNow = Date.now();
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({
        // Null means nothing has been checked yet on this process, which is
        // neither "up to date" nor "the endpoint did not answer". The page
        // says so by saying nothing about it, and asks.
        state: shown?.state ?? null,
        reason: shown?.reason ?? null,
        latest: shown?.latest ?? null,
        checked_at: shown?.checked_at ?? null,
        endpoint: shown?.endpoint ?? currentUpdateEndpoint(),
        // Which of the two produced the answer above, so the card's (i) can
        // say whose endpoint it is naming. Omitted when there was no
        // updater to ask: absent and 'endpoint' are the same reading, and a
        // member that is always present has broken a deepEqual here before.
        ...(view.graded ? { checked_from: 'updater' as const } : {}),
        // What this host's updater installs from, when the two do not agree
        // on what is published. The card says it in words and offers no
        // Apply: applying would refuse, and applying what root publishes is
        // not what an operator reading this page just asked for.
        ...(disagreement ? { endpoint_disagreement: disagreement } : {}),
        // The other branch: one endpoint, and the reading this page is
        // holding is older than the updater's. Its own member, never the one
        // above: the card withholds Apply on a disagreement, and this is not
        // one. Applying here installs what this host's own updater just
        // named, which is the same thing pressing Check now would offer.
        ...(readingLag ? { page_reading_older: readingLag } : {}),
        // What this host is, in the three-valued form and in the words the
        // page prints. Both, so the page never has to phrase the identity
        // itself and a peer's row and this row cannot say different things
        // about the same fact.
        identity: identityForWire(identity),
        identity_text: describeIdentity(identity),
        // The day this host's release was installed. Local only: the wire
        // identity a peer publishes carries no clock of its own.
        installed_at: identity.kind === 'release' ? identity.installed_at : null,
        // The last time the endpoint actually answered, or null for never.
        // "checked: never" and "checked at 09:12, and it is down now" are
        // different facts and the page says which one it has.
        last_answered_at: lastAnsweredUpdateCheck?.checked_at ?? null,
        // The page applies nothing itself. The way to apply is the
        // published bootstrap run on the box, with --update: it reads the
        // role off that host's units, copies the database out of the tree,
        // carries data, config and Advisor state into the new release and
        // asks before anything restarts. Without the flag the bootstrap
        // answers that the host is already installed and stops, which is
        // what this card used to tell an operator to do.
        apply_command: `curl -fsSL ${shown?.endpoint ?? currentUpdateEndpoint()} | bash -s -- --update`,
        // Is there an updater on this host (ADR 0022 phase 2)? Folded into
        // this read rather than given a route of its own: it is a property of
        // the card's load path, the card already makes exactly one call
        // there, and a second admin round trip on every Settings open for a
        // boolean that only matters when this host is behind is the cost
        // this card was built to avoid.
        //
        // Omitted entirely when it could not be settled. Absent and false are
        // different readings: false means the socket refused, which is a
        // claim, and a member that is always present has broken someone's
        // deepEqual on this payload before.
        ...(updaterProbe === null ? {} : { updater: { present: updaterProbe } }),
        // The release key this host checks every update against, read from
        // the root-owned copy and never from the tree (#736), so the card
        // can show its fingerprint beside the one the public guide prints.
        // `lab` is the updater's own word for a host whose key is not the
        // committed release key, carried only when it said so.
        release_key: {
          // Root's key at the constant path, always; a test key this
          // process checks against instead rides beside it as test_key.
          ...releaseKeyWire(),
          ...(updaterFacts?.signers === 'lab' ? { lab: true } : {}),
        },
        // The fleet half. Null on a single-node install, where there is no
        // fleet to grade and a table of one would be noise.
        fleet: graded && graded.nodes.length > 1 ? {
          graded: graded.release.graded,
          behind: graded.release.behind,
          current: graded.release.current,
          unknown: graded.release.unknown,
          // Its own count, never folded into `unknown` (#273). The card's
          // title line reads this directly: "1 not verified" is a different
          // sentence from "1 node behind" and from saying nothing at all.
          not_verified: graded.release.not_verified,
          // Hosts already on a release published after the one the endpoint
          // serves (#1073). Its own list: the endpoint is replaying an older
          // signed release, which is nothing to do and not "behind".
          older: graded.release.older,
          nodes: graded.nodes.map((n) => ({
            label: n.label, self: Boolean(n.self),
            // #1284. The name the table prints for this host; `label` is the
            // key its Apply and Restart buttons address.
            ...(n.self && n.display_name ? { display_name: n.display_name } : {}),
            state: n.aperire_release_state ?? 'unknown',
            release: n.aperire_release ?? { kind: 'unknown' },
            // Why an ungraded row is ungraded, when the reason is one the
            // operator can fix (#268). A refused node published no release
            // because it would not let this dashboard read one — which is a
            // different sentence from "its dashboard did not answer just
            // now", and the table's (i) says which.
            ...(n.verdict === 'refused' ? { refused: true } : {}),
            // The two keys that disagreed, so the row's (i) names them
            // rather than describing a mismatch in the abstract (#273).
            // Present only on a row already graded `not_verified`. They are
            // what that grade is derived from.
            //
            // Never on the self row (#488). It carries the same two keys for
            // a different fact, a stale registry rather than an impostor, it
            // is never graded `not_verified`, and this table's tip reads them
            // as "every read from it is refused", which is untrue about the
            // host serving the page.
            ...(!n.self && n.pin_expected && n.pin_reported
              ? { pin_expected: n.pin_expected, pin_reported: n.pin_reported }
              : {}),
            // Can this dashboard address a job to that node at all (#275)?
            // Read from the REGISTRY, which this process holds, and never
            // from a cached read of the node: whether that node has an
            // updater, and whether its own check says it is behind, are
            // facts only that node can state, and they are asked for at the
            // moment the operator presses Apply rather than predicted here.
            // A prediction would be exactly the kept reading this card
            // exists to avoid.
            ...(n.self ? {} : {
              can_address: Boolean(resolvePeerByLabel(fleetPeerNodes, n.label)?.expected_pubkey_node),
            }),
            // Where that node's dashboard is installed and who it runs as
            // (#615), off the node-status read the fleet poll already makes,
            // validated when it came off the wire and null behind the same
            // gate as every graded field (an unreachable or mismatched node
            // says nothing). Peers only: this host's own row reads its own
            // directory. Read through installFactsFor and not off the fleet
            // row, which /api/fleet serves to every signed-in role; this
            // route is admin only. The page shows these beside the commands it
            // hands an operator, as what the node said, and never inside one.
            ...(n.self ? {} : (() => {
              const facts = fleetPoller?.installFactsFor(n.label);
              return {
                ...(facts?.installDir ? { install_dir: facts.installDir } : {}),
                ...(facts?.runAs ? { run_as: facts.runAs } : {}),
              };
            })()),
            // What THAT node last said it holds (#331): its update grant, the
            // endpoint root installs from, and whether it pins this
            // aggregator's key. Every member is that node's own answer, and a
            // member it did not answer is absent rather than false. Omitted
            // entirely on a row nothing has ever asked, which is the state
            // before the first Check now and the state after an answer ages
            // out.
            ...(n.self ? {} : (() => {
              // Never on a row this fleet cannot identify, and never on one
              // that refused the read token. Both are rows whose words this
              // dashboard must not repeat: it cannot say which box answered.
              // An answer kept from before a box was rebuilt would otherwise
              // be printed under the new box's name.
              if (n.aperire_release_state === 'not_verified' || n.verdict === 'refused') return {};
              const c = completenessFor(n.label, completenessNow);
              return c ? { completeness: c } : {};
            })()),
            // One amber note when a component measured a build ref that
            // disagrees with the release this row says it is on (#266),
            // never a column, and never for a component nobody measured.
            // Self reads its OWN two facts directly, because a row never
            // asks itself over the fleet link; a peer's drift came off that
            // node's own completeness read above, computed there against
            // THAT node's own installed commit, never recomputed here
            // against a release this aggregator merely believes that node
            // is on.
            ...(() => {
              const releaseCommit = n.aperire_release?.kind === 'release' ? n.aperire_release.commit : null;
              const drift = n.self
                ? componentDrift(releaseCommit, componentsNow())
                : (completenessFor(n.label, completenessNow)?.component_drift ?? []);
              const note = describeComponentDrift(n.label, drift);
              return note ? { drift_note: note } : {};
            })(),
          })),
          // The line that joins a node to this fleet, built HERE rather than
          // in the browser so the aggregator's own origin comes from this
          // dashboard's identity and never from a Host header (the rule
          // pairCommandLine already holds). The code is a placeholder: a
          // real one is minted under Pair a node and is good for fifteen
          // minutes, which is not a thing a table cell can hold.
          pair_command: pairCommandLine(dashboardIdentity().public_url, '<pairing-code>'),
        } : null,
      }));
      return;
    }

    // ── Applying one (ADR 0022 phase 2, the write half of #62) ─────────
    //
    // Four routes, all admin, all CSRF-checked, and the three that change
    // something take a passkey bound to what they are about to do. The
    // operator ruled no arm window (2026-09-08): the admin passkey is the
    // gate, and the restart is a second click.
    //
    // A monitor is refused HERE, by each handler, and the card is not
    // rendered for one either. The affordance is not the guard.
    if (pathname.startsWith('/api/update/')) {
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      const sess = readSession(req);
      if (!sess) { send(401, { error: 'unauthenticated' }); return; }
      if (!isAdmin(sess.role)) {
        send(403, { error: 'this operator may not update this host' });
        return;
      }
      const who = { operator: sess.username, role: sess.role };

      // What the page tails, every two seconds while a run is in flight.
      // Cheap on purpose: it serves the record this process already holds
      // and touches neither the socket nor the endpoint.
      if (pathname === '/api/update/run') {
        if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
        send(200, updateRunWire(updateRun));
        return;
      }

      // What the fleet card tails while a node's update runs. The job's own
      // record and nothing else: no member of it is a field the table's
      // Release or Status cell reads, so a row can only turn green because
      // the poller re-read that node's own stamp (#275).
      if (pathname.startsWith('/api/update/fleet/job/')) {
        if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
        const jobId = pathname.slice('/api/update/fleet/job/'.length);
        const status = fleetUpdateJobs.get(jobId);
        // Never a 404 body the page has to special-case: a job that expired
        // is a job whose outcome is now on the table, read from each node.
        if (!status) { send(404, { error: 'no such update job' }); return; }
        send(200, status);
        return;
      }

      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      // Every one of these changes this host. A page on another origin
      // holding the operator's cookie must reach none of them.
      if (!csrfOk(req)) { send(403, { error: 'csrf' }); return; }

      let body: Record<string, unknown> = {};
      try {
        const read = await readBody(req, 16 * 1024);
        if (!read.ok) {
          if (read.reason === 'too_large') send(413, { error: 'that request is too large' });
          else send(400, { error: 'could not read the request' });
          return;
        }
        const raw = read.body;
        if (raw.trim()) {
          const parsed = JSON.parse(raw) as unknown;
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            body = parsed as Record<string, unknown>;
          }
        }
      } catch {
        send(400, { error: 'could not read the request' });
        return;
      }

      /** One run at a time, and the answer names the one that is running so
       *  the page can go and watch it rather than offer the button again. */
      const busy = (): boolean => Boolean(updateRun?.running);
      const busyBody = () => ({
        error: 'an update is already running on this host',
        detail: 'Watch it finish, then try again.',
        running: true, run_id: updateRun?.id ?? null, action: updateRun?.action ?? null,
      });

      // ── Apply ────────────────────────────────────────────────────
      //
      // The release comes from THIS server's own last check, never from the
      // request. The page may send what it is showing, and a disagreement is
      // refused: a card rendered before a publish would otherwise sign for a
      // release nobody is serving. The payload can narrow, never widen (ADR
      // 0022 decision 3).
      if (pathname === '/api/update/apply/begin') {
        if (busy()) {
          recordUpdateEvent(who, null, { action: 'apply', outcome: 'busy', ok: false });
          send(409, busyBody());
          return;
        }
        // The same answer the card grades from, and for the same reason: on a
        // host with an updater the release that may be applied is the one
        // ITS endpoint publishes, because that is the only one root will
        // install. Probed here rather than trusted from the request.
        //
        // The five guards themselves live in decideLocalApply(), because the
        // fleet route serves the same host and must not reach a different
        // answer (#275). This route keeps what is its own: the audit rows,
        // which carry different fields per refusal.
        const probe = await updaterCheck(false);
        const view = updaterView(probe.facts);
        const decision = decideLocalApply({
          probe: { present: probe.present, reading: view.reading, graded: view.graded },
          pageCheck: lastUpdateCheck,
          claimed: body.release as { tag?: string; commit?: string; sha256?: string } | undefined,
        });
        if (!decision.ok) {
          const r = decision.refusal;
          switch (r.reason) {
            case 'endpoint_disagreement':
              recordUpdateEvent(who, r.clash.updater_tag, {
                action: 'apply', outcome: 'endpoint_disagreement', ok: false,
                updater_endpoint: r.clash.updater_endpoint, updater_tag: r.clash.updater_tag,
                page_endpoint: r.clash.page_endpoint, page_tag: r.clash.page_tag,
              });
              send(409, { error: r.error, detail: r.detail });
              return;
            case 'nothing_to_apply':
              recordUpdateEvent(who, null, { action: 'apply', outcome: 'nothing_to_apply', ok: false, state: r.state });
              send(409, { error: r.error, detail: r.detail });
              return;
            case 'bad_release':
              recordUpdateEvent(who, r.release.tag, { action: 'apply', outcome: 'bad_release', ok: false, reason: r.detail });
              send(409, { error: r.error, detail: r.detail });
              return;
            case 'stale_page':
              // No audit row, and deliberately: nothing was decided about
              // this host. The card is behind this server's own answer.
              send(409, { error: r.error, detail: r.detail, release: r.release });
              return;
            case 'absent':
              recordUpdateEvent(who, null, { action: 'apply', outcome: 'absent', ok: false });
              send(409, { error: r.error, detail: r.detail });
              return;
          }
        }
        const release = decision.release;
        const begun = await beginUpdateCeremony(req, { action: 'apply', release });
        send(begun.status, begun.body);
        return;
      }

      if (pathname === '/api/update/apply/finish') {
        if (busy()) { send(409, busyBody()); return; }
        const v = await verifyUpdateCeremony(req, body, 'apply');
        if (!v.ok) {
          recordUpdateEvent(who, null, { action: 'apply', outcome: 'refused', ok: false, reason: v.error });
          send(v.status, { error: v.error, ...(v.detail ? { detail: v.detail } : {}) });
          return;
        }
        // Off the RECORD written at begin, never off this request. A value
        // the browser could change between the two halves would mean the
        // operator approved one release and this installed another.
        const release = v.approved.release;
        if (!release) { send(400, { error: 'that approval carried no release' }); return; }
        // Checked again, AFTER the ceremony. Verifying an assertion is an
        // await, so two admins finishing their own ceremonies at the same
        // moment can both pass the check at the top of this handler and only
        // one of them own the record. The socket takes one connection and the
        // program holds a lock, so the second would be refused as busy. But
        // it would refuse having overwritten the run the first is watching.
        if (busy()) { send(409, busyBody()); return; }
        const run = startUpdateRun('apply', applyPayload(release), UPDATE_TIMEOUT_MS.apply, who, { release });
        send(202, { run_id: run.id, started_at: run.started_at, release });
        return;
      }

      // ── Restart ──────────────────────────────────────────────────
      //
      // The unit list is read off the finished run's own needs_restart line,
      // server-side, and whatever the page sent is ignored. The dashboard
      // never sends a unit name it chose (ADR 0022 decision 5): the set
      // differs by host (aperire-server here, aperire-read on node2, a pm2
      // process on the aggregator). The program discovers it and this
      // only repeats it back.
      if (pathname === '/api/update/restart/begin') {
        if (busy()) { send(409, busyBody()); return; }
        const units = needsRestart(updateRun?.snapshot.facts ?? {});
        const refusal = unitListRefusal(units);
        if (refusal !== null) {
          send(409, {
            error: 'this host has nothing waiting for a restart',
            detail: 'A restart is offered only after an apply says which units are running older code than the tree now holds.',
          });
          return;
        }
        const begun = await beginUpdateCeremony(req, { action: 'restart', units });
        send(begun.status, begun.body);
        return;
      }

      if (pathname === '/api/update/restart') {
        if (busy()) { send(409, busyBody()); return; }
        const v = await verifyUpdateCeremony(req, body, 'restart');
        if (!v.ok) {
          recordUpdateEvent(who, null, { action: 'restart', outcome: 'refused', ok: false, reason: v.error });
          send(v.status, { error: v.error, ...(v.detail ? { detail: v.detail } : {}) });
          return;
        }
        if (busy()) { send(409, busyBody()); return; }
        const units = v.approved.units ?? [];
        const refusal = unitListRefusal(units);
        if (refusal !== null) { send(409, { error: 'that approval carried no unit to restart', detail: refusal }); return; }
        // The `started` row is startUpdateRun's, written before the socket:
        // one of these units is the process running this line, so a row
        // written afterwards is a row never written.
        const run = startUpdateRun('restart', restartPayload(units), UPDATE_TIMEOUT_MS.restart, who, { units });
        send(202, { run_id: run.id, started_at: run.started_at, units });
        return;
      }

      // ── Roll back ────────────────────────────────────────────────
      //
      // The tree only. What it costs is the operator's to weigh, and the
      // page says so before the passkey: nothing here restores a database.
      if (pathname === '/api/update/rollback/begin') {
        if (busy()) { send(409, busyBody()); return; }
        if (!(await updaterIsPresent(false))) {
          send(409, {
            error: 'no updater is installed on this host',
            detail: 'A rollback is the update program’s own verb, and this host has none.',
          });
          return;
        }
        const begun = await beginUpdateCeremony(req, { action: 'rollback' });
        send(begun.status, begun.body);
        return;
      }

      if (pathname === '/api/update/rollback') {
        if (busy()) { send(409, busyBody()); return; }
        const v = await verifyUpdateCeremony(req, body, 'rollback');
        if (!v.ok) {
          recordUpdateEvent(who, null, { action: 'rollback', outcome: 'refused', ok: false, reason: v.error });
          send(v.status, { error: v.error, ...(v.detail ? { detail: v.detail } : {}) });
          return;
        }
        if (busy()) { send(409, busyBody()); return; }
        const run = startUpdateRun('rollback', rollbackPayload(), UPDATE_TIMEOUT_MS.rollback, who, {});
        send(202, { run_id: run.id, started_at: run.started_at });
        return;
      }

      // ── The fleet half (#275) ────────────────────────────────────
      //
      // Checking and applying never require picking a node (ruling,
      // 2026-09-10): the aggregator does the fleet, and a row's own button
      // is the act rather than a selection. These routes carry a LABEL and
      // resolve it against the registry; it is a lookup key and is never
      // trusted further.
      //
      // No arm window (ruling, 2026-09-08). The admin passkey is the gate,
      // the source is fixed on the far box, and the restart is a second
      // click. What a compromised dashboard gains here is "make a paired,
      // pinned node install the release that node's own endpoint publishes,
      // or nothing", which is the same authority the local Apply button
      // already grants on one host.
      if (pathname === '/api/update/fleet/apply/begin'
        || pathname === '/api/update/fleet/restart/begin') {
        const wantsRestart = pathname.endsWith('/restart/begin');
        if (fleetUpdateJobs.busy()) {
          send(409, {
            error: 'a fleet update is already running',
            detail: 'Watch it finish, then try again.',
          });
          return;
        }
        const label = String(body.label ?? '');
        if (!FLEET_LABEL_RE.test(label)) {
          send(400, { error: 'that is not a node this dashboard knows' });
          return;
        }
        const node = resolvePeerByLabel(fleetPeerNodes, label) ?? null;
        if (!node) { send(404, { error: 'that is not a node this dashboard knows' }); return; }

        // That node's OWN account of itself, read now. Everything the
        // operator is about to approve comes from here rather than from the
        // page: the release it would install and, on a restart, the units
        // its own finished run discovered.
        const peerState = await fetchPeerUpdateState(node, { timeoutMs: 15_000 });
        if (!peerState.ok) {
          // The node DECIDED and answered, or this side never got an answer
          // at all. Two different facts and an operator acts on them
          // differently: one sends them to that box, the other sends them to
          // the link. Saying "did not answer" over a node that answered
          // `no_aggregator_pinned` sent an operator to look at a host that
          // was up and talking (#331).
          send(409, peerState.refused
            ? { error: 'that node refused', detail: peerState.detail, reason: peerState.reason }
            : { error: `that node did not answer (${peerState.reason})`, detail: peerState.detail });
          return;
        }
        if (wantsRestart) {
          const run = peerState.state.run;
          const units = run?.needs_restart ?? [];
          const refusal = unitListRefusal(units);
          if (!run || run.running || refusal !== null) {
            send(409, {
              error: 'that node has nothing waiting for a restart',
              detail: 'A restart is offered only after an apply on that node says which units are running older code than its tree now holds.',
            });
            return;
          }
          // The run the PAGE was looking at, where it named one (#362). A
          // session that never pressed Apply offers the restart off the run
          // that node reported on the last Check now, and minutes can pass
          // before the operator presses it. If the node has since started
          // another run, the units on screen are not the units this would
          // restart, and the operator would approve something they did not
          // read. Compared, never used: the run a job names is still the one
          // the node itself is holding now. Checked only where the page sent
          // one, so the in-session press and an older page are unchanged.
          const claimedRun = typeof body.run_id === 'string' ? body.run_id : '';
          if (claimedRun && claimedRun !== run.run_id) {
            send(409, {
              error: 'this page is showing an older answer',
              detail: 'That node is holding a different run now. Press Check now, then try again.',
            });
            return;
          }
          const begun = await beginUpdateCeremony(req, {
            action: 'fleet_restart',
            targets: [label],
            runIds: { [label]: run.run_id },
            // Shown to the operator, and bound so the page cannot change
            // what they read between the two halves. NOT sent to the node:
            // the job names the run, and the node reads the units off that
            // run itself (ADR 0022 decision 5).
            units,
          });
          send(begun.status, begun.body);
          return;
        }
        // An apply. The release comes from what THAT node's own check names,
        // which is the only one its root updater will install. A `release`
        // in the request is compared and never used: a card rendered before
        // a publish would otherwise sign for something nobody is serving.
        if (!peerState.state.can_apply || !peerState.state.published) {
          send(409, {
            error: 'that node will not apply anything right now',
            detail: peerState.state.cannot_apply_detail
              ?? 'Its own check does not say it is behind. Press Check now, then try again.',
          });
          return;
        }
        const release = peerState.state.published;
        const claimed = body.release as Record<string, unknown> | undefined;
        if (claimed && (String(claimed.tag ?? '') !== release.tag
          || String(claimed.sha256 ?? '') !== release.sha256)) {
          send(409, {
            error: 'this page is showing an older answer',
            detail: 'Check for updates again, then apply what it names.',
            release,
          });
          return;
        }
        const framing = updateFieldRefusal(release);
        if (framing !== null) {
          send(409, { error: 'this dashboard will not name that release to a node', detail: framing });
          return;
        }
        const begun = await beginUpdateCeremony(req, {
          action: 'fleet_apply', targets: [label], release,
        });
        send(begun.status, begun.body);
        return;
      }

      // Stop waiting on a job (#325). NO passkey, and that is the point:
      // this changes nothing on any node. It ends this dashboard's own
      // waiting and frees the single fleet-job slot so the next node can be
      // updated. Whatever a node's root program started carries on there,
      // and the row says so rather than claiming an outcome.
      if (pathname === '/api/update/fleet/cancel') {
        const jobId = String(body.job_id ?? '');
        const out = fleetUpdateJobs.cancel(jobId);
        if (!out.ok && !out.status) { send(404, { error: 'no such update job' }); return; }
        if (!out.ok) { send(409, { error: 'that job has already finished', job: out.status }); return; }
        recordUpdateEvent(who, jobId, { action: 'fleet_cancel', outcome: 'stopped_waiting', ok: null, via: 'fleet' });
        send(200, { ok: true, job: out.status });
        return;
      }

      if (pathname === '/api/update/fleet/apply' || pathname === '/api/update/fleet/restart') {
        const action = pathname.endsWith('/restart') ? 'fleet_restart' as const : 'fleet_apply' as const;
        const v = await verifyUpdateCeremony(req, body, action);
        if (!v.ok) {
          recordUpdateEvent(who, null, { action, outcome: 'refused', ok: false, reason: v.error });
          send(v.status, { error: v.error, ...(v.detail ? { detail: v.detail } : {}) });
          return;
        }
        // Off the RECORD written at begin, never off this request. A label a
        // browser could change between the two halves would mean the
        // operator approved one node and this updated another.
        const targets = v.approved.targets ?? [];
        if (targets.length === 0) { send(400, { error: 'that approval named no node' }); return; }
        // Checked again, AFTER the ceremony: verifying an assertion is an
        // await, so two admins finishing at the same moment can both pass
        // the check at the top and only one of them own the job.
        if (fleetUpdateJobs.busy()) {
          send(409, { error: 'a fleet update is already running', detail: 'Watch it finish, then try again.' });
          return;
        }
        const started = fleetUpdateJobs.start({
          action: action === 'fleet_apply' ? 'apply' : 'restart',
          targets,
          release: v.approved.release,
          runIds: v.approved.runIds,
          grantedBy: v.approved.operator,
          grantedRole: v.approved.operatorRole,
          credentialId: v.approved.credentialId,
        });
        send(202, { job_id: started.job_id, targets: started.targets });
        return;
      }

      send(404, { error: 'no such update route' });
      return;
    }

    // The Advisor tab's concern strip, the ranked, evidenced list of what is
    // wrong anywhere this dashboard can see. Assembled per request from state
    // that already exists (a synchronous firing query, this process's own node
    // reach state, and the fleet poller's retained peer signals): no new
    // poller, no new timer, no new read of any peer.
    //
    // Gated by requireAuthGate above like everything else under /api/, which
    // is why it is under /api/ at all.
    //
    // Deliberately NOT a member of READ_ROUTE_NAMES. The reason differs from
    // the `stream` carve-out's: `stream` is out because its SHAPE breaks the
    // JSON reader, whereas this is out because it is a DERIVED VIEW over
    // routes a peer already serves. Adding it would have every node derive
    // concerns and the aggregator derive concerns over derived concerns,
    // two ranking implementations that can disagree, and a version skew that
    // surfaces as one peer whose cards are subtly different from every other
    // peer's. The aggregator already holds the inputs. Reconsider only if a
    // peer gains a signal that never crosses the wire.
    // Does an Advisor exist, here and on each node this dashboard can route
    // to? ADR 0016. Served from the probe timer's last observation, never
    // probed per request: a browser poll must not drive the outbound call
    // rate, and on an absent host there is no outbound call to drive.
    //
    // Session-gated by requireAuthGate above, which is why it is under /api/.
    //
    // Deliberately NOT a member of READ_ROUTE_NAMES, for the same reason
    // /api/concerns is not: it is a DERIVED VIEW over facts this dashboard
    // already holds. Adding it would have each peer derive presence and the
    // aggregator derive presence over derived answers. Two implementations
    // could disagree about whether a node has an Advisor, and this
    // endpoint's whole job is that no surface decides that for itself.
    //
    // Three fields, not one. `self` is this host; `nodes` is per subject
    // node; `any` is the roll-up and is what navigation keys on. Reading a
    // peer's state under another node's name is the ADR 0014 mislabel this
    // tab has already shipped once.
    if (pathname === '/api/advisor-presence') {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const body = buildAdvisorPresenceResponse({
        self: await readAdvisorPresence(),
        lastAnsweredMs: lastAdvisorAnsweredMs(),
        // From the REGISTRY, not from fleetView(): FleetPeerPublic carries no
        // advisor field, and fleetView() is null on a single-node install,
        // which is precisely the install this record is about.
        peers: fleetPeerNodes.map((p) => ({ label: p.label, advisor_origin: p.advisor_origin })),
        // The repo root, the same directory deployRefReader reads
        // `.deploy-ref` from. The absent-state card prints
        // `bash <this>/aperire-one`, which has to be a real absolute
        // path: the relative form it shipped with failed from anywhere but
        // this directory, which is where nobody's shell starts.
        installDir: resolve(import.meta.dirname, '..'),
        hostName: osHostname() || undefined,
        modelConfigured: advisorModelConfigured,
        credentialPresent: advisorCredentialPresent,
        modelName: advisorModelName,
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
      return;
    }

    if (pathname === '/api/concerns') {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const view = fleetView();
      const selfRow = view?.nodes.find((n) => n.self) ?? null;
      const body = buildConcernsResponse({
        nowMs: Date.now(),
        // A registry that names only this node is not a fleet: with no peers
        // there is nothing a node badge could distinguish, and the quiet line
        // says "on this node" rather than "across 1 node".
        scope: view && view.nodes.length > 1 ? 'fleet' : 'node',
        // The self node's OWN fleet label, taken from the row /api/fleet
        // already builds so the two can never name it differently. With no
        // registry there is no such row, and a fresh install is exactly that
        // state, so the fall-back names the machine (#145) rather than
        // saying 'this node' at an operator who has one node and would like
        // to see it called by its name. 'this node' survives one step
        // further down, for a host that will not say its own name at all,
        // and is only reachable at scope 'node' where §6.2 renders no node
        // badge anyway.
        selfLabel: selfDisplayLabel(selfRow) || 'this node',
        selfFiring: queryFiringState(),
        selfReach: nodeReachState(),
        // Same predicate the header chip uses, so the strip and the chip
        // cannot disagree about whether this host is a node at all.
        selfIsAggregator: isAggregatorSelf(selfRow, view ? view.nodes.length - 1 : 0),
        peers: fleetPoller ? fleetPoller.peersConcernInput() : [],
        firstSeen: concernFirstSeen,
        // The poller's own staleness boundary, passed in rather than
        // redeclared, so the concern layer defines no threshold of its own.
        staleAfterMs: STALE_AFTER_MS,
      });
      // The caller's half of the firstSeen contract: write in the ids that
      // appeared, drop the ones that did not, so a concern that resolves and
      // later recurs is honestly new the second time.
      reconcileFirstSeen(concernFirstSeen, body.concerns);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
      return;
    }

    // The demand-driven fetch-through, D8 slice 2
    // (advisor-enhancement/d8-aggregator-build-plan.md,
    // security-review-d8-fetchthrough.md). Session-gated at the same
    // location as /api/fleet just above (P1-027). The browser hands over
    // exactly one thing, :label, which is an EXACT-MATCH lookup against
    // fleetPeerNodes, the already-RESOLVED peers array: an unknown label
    // (including one shaped like a URL, or the self node's own label,
    // which resolveFleet already excludes from this array) 404s before any
    // outbound fetch is attempted (P1-026). Every other part of every
    // upstream URL is a server-side constant inside fleet-fetch-through.ts;
    // nothing from this request is ever used to build one.
    const nodeOverviewLabel = parseNodeOverviewLabel(pathname);
    if (nodeOverviewLabel !== null) {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      const node = resolvePeerByLabel(fleetPeerNodes, nodeOverviewLabel);
      if (!node) { send(404, { error: 'peer_unknown' }); return; }
      let result;
      try {
        result = await fleetFetchThrough.getOverview(node);
      } catch (err) {
        // An escaped rejection becoming a raw 500 with a stack is exactly
        // the "never a raw error" failure P2-033 forbids, fetchFromPeer
        // itself never throws, but this belt keeps that guarantee even if
        // a future change adds a code path that can.
        console.warn(`[fleet-fetch-through] unexpected error for "${nodeOverviewLabel}": ${(err as Error).message}`);
        send(peerFailureStatus('peer_bad_response'), { error: 'peer_bad_response' });
        return;
      }
      if (!result.ok) {
        // Never a 502 or a 504 (#1134): the edge in front of an aggregator
        // replaces both with its own page. One mapping for every peer route.
        // `detail` rides only on token_unreadable (#1305): this host's own
        // sentence about its own file, never an upstream's words.
        const failed = peerReadFailureAnswer(result, peerViewer(req, node.label));
        send(failed.status, failed.body);
        return;
      }
      send(200, {
        label: result.label,
        fetched_at_ms: result.fetched_at_ms,
        // The same two members come out for a monitor here as on the
        // node-status read route below (#615): this bundle carries the
        // peer's node-status body as it arrived.
        node_status: nodeStatusForRole(result.node_status, adminSession(req)),
        peers: result.peers,
        validation_summary: result.validation_summary,
      });
      return;
    }

    // The generic peer-read proxy, D8 slice 3 backend
    // (advisor-enhancement/security-review-peer-read-proxy.md). Session-
    // gated at the same location as /api/node/:label/overview just above
    // (P1-035/036 assume this runs past requireAuthGate, an unauthenticated
    // caller never reaches here at all). Two browser-controlled segments:
    // `:label` is the same exact-match lookup against the RESOLVED
    // fleetPeerNodes array slice 2 already uses (P1-026, unchanged); `:route`
    // is a membership test against the IMPORTED READ_ROUTE_NAMES set
    // (isAllowedRoute), checked and 404'd BEFORE resolvePeerByLabel or any
    // outbound fetch is attempted, so an unknown route never depends on
    // whether the label happens to be valid too.
    // A peer's streaming channel, ADR 0013, decision 2. Session-gated at
    // the same location as its two JSON neighbours (an unauthenticated
    // caller never reaches this handler at all), the same exact-match
    // resolvePeerByLabel lookup for SSRF containment (P1-026), and the same
    // pin rule before anything is served, verifyPeerPin, shared with the
    // JSON proxy rather than copied. One segment SHORTER than
    // /api/node/:label/read/:route on purpose: parseNodeReadPath's regex
    // requires a literal `/read/` segment, so the JSON proxy, whose reader
    // would buffer an event stream until it timed out and then negative-cache
    // the peer, is structurally never in this request's path.
    //
    // The token stays server-side here exactly as it does for every other
    // peer read; the browser's EventSource carries only the session cookie.
    const nodeStreamLabel = parseNodeStreamLabel(pathname);
    if (nodeStreamLabel !== null) {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const sendJson = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      // Channels first, before the label is even resolved, an unknown
      // channel costs zero outbound connections, the same ordering the JSON
      // proxy gives an unknown route.
      const channels = parseStreamChannels(url.searchParams.get('channels'));
      if (channels === null) { sendJson(400, { error: 'bad_request', detail: 'unknown or missing stream channel' }); return; }
      const streamNode = resolvePeerByLabel(fleetPeerNodes, nodeStreamLabel);
      if (!streamNode) { sendJson(404, { error: 'peer_unknown' }); return; }

      const browserGone = new AbortController();
      res.on('close', () => browserGone.abort());
      let opened;
      try {
        opened = await openPeerStream(streamNode, channels, { signal: browserGone.signal });
      } catch (err) {
        console.warn(`[peer-stream-proxy] unexpected error for "${nodeStreamLabel}": ${(err as Error).message}`);
        sendJson(peerFailureStatus('peer_bad_response'), { error: 'peer_bad_response' });
        return;
      }
      if (!opened.ok && opened.notSupported) {
        // #831. The node is reached over the fleet link, which does not carry
        // the stream. Said as what it is, a 501 with its own code, so the
        // browser stops asking and says the view is polled, instead of
        // reading a 502 and retrying every few seconds.
        if (!res.writableEnded) {
          sendJson(501, { error: 'stream_not_supported',
            detail: `${streamNode.label} is reached over the fleet link, which does not carry the live feed yet` });
        }
        return;
      }
      if (!opened.ok) {
        // A response only if the browser is still there, an aborted request
        // has no one to tell. Same mapping as the other peer routes (#1134).
        if (!res.writableEnded) {
          const failed = peerReadFailureAnswer(opened, peerViewer(req, streamNode.label));
          sendJson(failed.status, failed.body);
        }
        return;
      }
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-store',
        'connection': 'keep-alive',
        'x-accel-buffering': 'no',
      });
      await relayPeerStream(opened.body, {
        write: (chunk: Uint8Array) => res.write(chunk),
        end: () => { if (!res.writableEnded) res.end(); },
      });
      return;
    }

    const nodeReadPath = parseNodeReadPath(pathname);
    if (nodeReadPath !== null) {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      // [P1-035] Route allowlist BEFORE any fetch, before the label is even
      // resolved. `../identity` or any name not in the imported set 404s
      // with zero outbound requests, checkable independent of `:label`.
      if (!isAllowedRoute(nodeReadPath.route)) { send(404, { error: 'unknown_read_path' }); return; }
      const node = resolvePeerByLabel(fleetPeerNodes, nodeReadPath.label);
      if (!node) { send(404, { error: 'peer_unknown' }); return; }
      // [P2-037] Structured, key-allowlisted forwarding, the raw query
      // string is never passed through; only the allowlisted keys, via
      // URLSearchParams, and the token stays an Authorization header inside
      // peer-read-proxy.ts, never a param here.
      const params = forwardableParams(url.searchParams);
      let result;
      try {
        result = await peerReadProxy.get(node, nodeReadPath.route, params);
      } catch (err) {
        // Same belt as the overview route above (P2-033): fetchPeerRoute
        // itself never throws, this guarantees a raw error never escapes as
        // a bare 500 with a stack even if a future change adds a path that
        // can throw.
        console.warn(`[peer-read-proxy] unexpected error for "${nodeReadPath.label}" "${nodeReadPath.route}": ${(err as Error).message}`);
        send(peerFailureStatus('peer_bad_response'), { error: 'peer_bad_response' });
        return;
      }
      if (!result.ok) {
        // Never a 502 or a 504 (#1134): the edge in front of an aggregator
        // replaces both with its own page. One mapping for every peer route.
        // `detail` rides only on token_unreadable (#1305).
        const failed = peerReadFailureAnswer(result, peerViewer(req, node.label));
        send(failed.status, failed.body);
        return;
      }
      // A peer's node-status says where its dashboard is installed and who it
      // runs as (#615). That is for an administrator's commands, so every
      // other role gets the body without those two members. The route name is
      // the allowlisted one (isAllowedRoute above), never browser text.
      send(200, nodeReadPath.route === 'node-status' ? nodeStatusForRole(result.body, adminSession(req)) : result.body);
      return;
    }

    // The per-node advisor read proxy, ADR 0014 slice 1. Session-gated at
    // the same location as its /api/node/:label/* neighbours above (an
    // unauthenticated caller never reaches here). Deliberately outside
    // /read/ so NODE_READ_PATH_RE cannot match it under any label, the
    // JSON read proxy is structurally never in this request's path, the
    // same choice ADR 0013 made for the stream. The parser IS the
    // allow-list: five read endpoints plus runs/:id, both segments
    // validated before any label resolves or any fetch happens; every
    // advisord write verb is absent from the table by name. GET only,
    // a monitor session watches a peer's runs; nothing here can spend
    // anything.
    const nodeAdvisorPath = parseNodeAdvisorPath(pathname);
    if (nodeAdvisorPath !== null) {
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      // Slice 2's two verbs ride the same parser and the same resolved-row
      // discipline. ask is the one POST, a question for the SUBJECT node's
      // advisord, answered with its own sealed key and its own reads, and
      // carries the same csrf gate every authenticated write here does.
      const isPeerAsk = nodeAdvisorPath.endpoint === 'ask';
      const isPeerAskProgress = nodeAdvisorPath.endpoint === 'ask-progress';
      if (isPeerAsk) {
        if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
        if (!csrfOk(req)) { send(403, { error: 'csrf' }); return; }
      } else if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      // Three reads on this table are admin-only: a peer's proposal inbox
      // (ADR 0017 decision 4), and, since ADR 0021 build step 5, its mirror
      // feed reads, its memory and its full inbox, for the same reason.
      // Model-authored content and a decided note's body are not a monitor
      // session's to curl. Everything else here a monitor may watch.
      if (ADMIN_ONLY_ADVISOR_READS.has(nodeAdvisorPath.endpoint)) {
        const sess = readSession(req);
        if (!sess) { send(401, { error: 'unauthenticated' }); return; }
        if (!isAdmin(sess.role)) {
          send(403, { error: 'this operator may not read that Advisor surface' });
          return;
        }
      }
      const advisorNode = resolvePeerByLabel(fleetPeerNodes, nodeAdvisorPath.label);
      if (!advisorNode) { send(404, { error: 'peer_unknown' }); return; }
      // #547. Same rule as the local proxy: a runbook this dashboard does not
      // recognise is refused by name here, rather than dropped and answered
      // by the peer's own /v1/check default (the upgrade).
      const peerRunbookErr = advisorRunbookError(`/api/advisor/${nodeAdvisorPath.endpoint}`, url.searchParams);
      if (peerRunbookErr) { send(400, { error: peerRunbookErr }); return; }
      let result;
      try {
        if (isPeerAsk) {
          const read = await readBody(req, 256 * 1024);
          if (!read.ok) { res.writeHead(413); res.end('question too large'); return; }
          // The actor rides along here for the same reason as on the local
          // proxy: a peer with a break-glass window open answers at the
          // gated tier and records each privileged read against the asker.
          // Assigned last, so a body that carried these keys cannot win.
          let askBody = read.body;
          {
            const sess = readSession(req);
            const user = sess ? getUserById(sess.userId) : null;
            askBody = attachActor(askBody, {
              operator: user?.username ?? (sess ? `user:${sess.userId}` : ''),
              role: sess?.role ?? '',
            });
          }
          // Counted for the whole forward, punch #24. This is THE hop the
          // 2026-08-20 failure ran through: restarting this process while
          // the fetch is open hangs up on a peer advisord that is still
          // answering, and the question dies on a host nobody touched.
          result = await trackAsk(() => fetchPeerAdvisorAsk(advisorNode, askBody));
        } else if (isPeerAskProgress) {
          // Rebuilt from scratch against the same per-path allow-list the
          // local proxy uses, the raw query never crosses.
          const qs = advisorForwardQuery('/api/advisor/ask-progress', url.searchParams);
          result = await fetchPeerAdvisorAskProgress(advisorNode, qs, { pinCache: peerPinCache });
        } else {
          // ADR 0016: /check and /plan answer about a NAMED runbook, and an
          // absent one means the upgrade. Rebuilt from scratch against the
          // same per-path allow-list the local proxy uses, the raw query
          // never crosses, so a peer's Restart card fetches the restart
          // plan rather than the upgrade's under a different title.
          const q = advisorForwardQuery(`/api/advisor/${nodeAdvisorPath.endpoint}`, url.searchParams);
          result = await fetchPeerAdvisor(advisorNode, nodeAdvisorPath, q ? { query: q, pinCache: peerPinCache } : { pinCache: peerPinCache });
        }
      } catch (err) {
        console.warn(`[peer-advisor-proxy] unexpected error for "${nodeAdvisorPath.label}" "${nodeAdvisorPath.endpoint}": ${(err as Error).message}`);
        send(peerFailureStatus('peer_bad_response'), { error: 'peer_bad_response' });
        return;
      }
      // #550's peer half. Opportunistic: this check was already made for the
      // Operations card, and the peer's own installable reading rides along
      // to the cache the new /release-posture route below reads from. No
      // second fetch of any kind.
      notePeerAdvisorInstallable(nodeAdvisorPath.label, nodeAdvisorPath.endpoint, result);
      if (!result.ok) {
        // The mapping lives in lib/peer-advisor-answer.ts, shared with the
        // walks: advisor_not_configured is a supported state answered 200,
        // a 404 travels as a 404 (ask-progress, runs/:id), a carried 4xx
        // keeps the peer's status (#560), and a node's own 5xx sentence
        // (#1117) travels on a 4xx, because the edge in front of this
        // dashboard replaces an origin 502 or 504 with its own page.
        const answer = peerAdvisorFailureAnswer(result, peerViewer(req, nodeAdvisorPath.label));
        send(answer.status, answer.body);
        return;
      }
      // The peer's trust story, which used to be missing entirely: this tab
      // rendered the drift banner for the LOCAL advisord and said nothing
      // about the node actually selected. A node whose trust set is behind
      // refuses the next ceremony with an error that reads like a broken
      // passkey, the 2026-08-19 failure, and the operator had no way to see
      // it coming. The comparison is the same one the local path makes,
      // through the same builder; only the remedy differs, because pushing to
      // the whole fleet to fix one node is wider than what was asked.
      if (nodeAdvisorPath.endpoint === 'status') {
        send(200, annotateTrustSync(result.body, {
          mine: trustFingerprint(), peerLabel: nodeAdvisorPath.label,
        }));
        return;
      }
      send(200, result.body);
      return;
    }

    // #550's peer half. One route the Overview chip and the Advisor tab's
    // release-gap card both read for a PEER, so the two surfaces can never
    // classify the same peer's gap two different ways. Built entirely from
    // readings this dashboard already holds: the fleet-wide upstream fact
    // (releaseInfo) and the peer's own installable reading, cached
    // opportunistically off the check the Operations card already makes
    // (notePeerAdvisorInstallable). Viewing this route costs no outbound
    // call of its own, ever.
    const peerReleasePostureMatch = /^\/api\/node\/([a-z0-9-]{1,32})\/release-posture$/.exec(pathname);
    if (peerReleasePostureMatch) {
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const label = peerReleasePostureMatch[1];
      if (!resolvePeerByLabel(fleetPeerNodes, label)) { send(404, { error: 'peer_unknown' }); return; }
      // 'unknown' (no entry) is a THIRD fact, distinct from both of
      // peerAdvisorInstallable's own states: this dashboard has never
      // proxied a check for this peer yet (nobody has opened its Advisor
      // tab this run), which is different from having asked and been told
      // there is no Advisor there. Both 'unknown' and 'absent' mean the
      // chip keeps today's meaning; naming both lets a caller tell the two
      // apart if it ever needs to.
      const entry = peerAdvisorInstallable.get(label);
      // #658. The peer's running version, gated like the FLEET card's [R].
      // A null here made a peer on 3.4.1 read as a gap ("3.4.0 soon"), and
      // peerReleasePostureBody now refuses to classify at all without it: no
      // version read, no claim about that node. The whole table of cases is
      // executed in release-posture.test.ts; this line is the one thing the
      // library cannot do for itself, read the fleet poll.
      const peerRunning = fleetPoller?.peersPublic().find((p) => p.label === label)?.build_version ?? null;
      send(200, peerReleasePostureBody(upstreamReleaseFact(), entry, peerRunning));
      return;
    }

    // Last-N raw samples, used to seed the bar chart on page load
    if (pathname === '/recent') {
      const metric = url.searchParams.get('metric') ?? '';
      const limit  = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') ?? 30)));
      if (!VALID_METRICS.has(metric)) { res.writeHead(400); res.end('bad metric'); return; }
      const points = queryRecent(metric as MetricName, limit);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ metric, limit, points }));
      return;
    }

    // Insights tab, current parsed config state with secrets masked.
    // Drives the P2 Configuration card and the Channels strip cell.
    // Mutating endpoints intentionally absent, config edits are
    // file-on-disk + SIGHUP (see APERIRE-ROADMAP.md security model).
    // ── Advisor proxy ────────────────────────────────────────────────
    // The Advisor is a separate component and never imports from the
    // dashboard; it answers over its own loopback HTTP surface. The
    // dashboard forwards to it so the tab is same-origin and inherits the
    // session gate above rather than growing an auth story of its own.
    //
    // Deliberately an allow-list of exact paths, not a prefix rewrite. A
    // proxy that forwarded whatever followed /api/advisor/ would hand the
    // Advisor's future write verbs a route the moment they existed, the
    // write path has to be added here on purpose, with its own checks,
    // never inherited.
    // ── ADR 0014 slice 3 (F): the ceremony travels to the node ──────────
    // PEER-DIAL REGION BEGIN (scanned by test/unit/fleet-link-routes.test.ts)
    // Every advisord path this block sends to a peer is extracted from here
    // and checked against the node-side allow-list. Do not move a peer dial
    // out of this region without moving the marker with it; the same test
    // fails if a peer origin is interpolated anywhere else in this file.
    //
    // Per-node approve/execute, routed to the SELECTED node's own advisord.
    // The challenge is issued by that node's advisord, bound to ITS plan,
    // and verified by ITS credential store (the admin keys a trust bundle
    // installed), decision 5. Structurally NO local fallback: an
    // unresolved label 404s, a node without an advisor stack 409s, and
    // neither ever silently reaches this host's ADVISOR_URL. A fallback
    // here would issue a challenge on one advisord and hand the assertion
    // to another to verify, failing as a "broken passkey", the exact trap
    // the ADR names. Additive: the LOCAL /api/advisor/* ceremony below is
    // untouched, so prod (co-located) is unchanged.
    {
      const nc = /^\/api\/node\/([a-z0-9-]{1,32})\/advisor\/(approve\/begin|approve\/finish|cancel-approval|execute|investigate-begin|investigate|investigate-continue|breakglass-close|investigate-offer)$/.exec(pathname);
      if (nc && req.method === 'POST') {
        const [, label, verb] = nc;
        const send = (s: number, b: unknown) => { res.writeHead(s, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(b)); };
        if (!csrfOk(req)) { send(403, { error: 'csrf' }); return; }
        const peer = resolvePeerByLabel(fleetPeerNodes, label);
        if (!peer) { send(404, { error: 'peer_unknown' }); return; }
        if (!peer.advisor_origin || !peer.advisor_token_path) { send(409, { error: 'advisor_not_configured' }); return; }
        // A token this host cannot read is its own answer (#1209, #1305): the
        // code, the sentence naming the file and its owner, and the no-answer
        // status the edge leaves alone. It was a 503 with the sentence in `error`.
        const advisorTok = readPeerAdvisorToken(peer);
        if (!advisorTok.ok) {
          const refused = peerAdvisorFailureAnswer(advisorTok, peerViewer(req, peer.label));
          send(refused.status, refused.body);
          return;
        }
        const peerToken = advisorTok.token;
        // The resolved peer's origin + fresh token, the only values these
        // handlers ever see for this request. handleAdvisorApprove* already
        // take (advisorUrl, advisorToken) as parameters and use them for the
        // plan fetch, the challenge, and the grant, so passing the peer's is
        // the whole of it.
        if (verb === 'approve/begin')   { await handleAdvisorApproveBegin(req, res, peer.advisor_origin, peerToken); return; }
        if (verb === 'approve/finish')  { await handleAdvisorApproveFinish(req, res, peer.advisor_origin, peerToken); return; }
        if (verb === 'cancel-approval') { await handleAdvisorApproveCancel(req, res, peer.advisor_origin, peerToken); return; }
        // Break glass travels the same way (plan-interrogative-loop §11.8).
        // The offer came from the SUBJECT node's advisord, so the challenge
        // is issued by it, bound to ITS offer record, and the assertion is
        // verified by ITS credential store, the trust bundle is what makes
        // that store hold the admin's key. Same handlers as the local route,
        // with the peer's origin and token; the wrong-node guard on the
        // advisord side still stands behind every one of these.
        if (verb === 'investigate-begin') { await handleAdvisorInvestigateBegin(req, res, peer.advisor_origin, peerToken); return; }
        if (verb === 'investigate')       { await handleAdvisorInvestigateFinish(req, res, peer.advisor_origin, peerToken); return; }
        // The three forwarded writes: execute spends an approval already
        // verified twice on the node; investigate-continue and
        // breakglass-close act inside a window the node itself opened. All
        // admin-gated like their local twins, then proxied to the peer's
        // advisord with the peer's token. The break-glass pair carry the
        // actor stamped HERE from the session, never from the body, the
        // same injection the local proxy does, for the same audit reason.
        if (verb === 'execute' || verb === 'investigate-continue' || verb === 'breakglass-close' || verb === 'investigate-offer') {
          const sess = readSession(req);
          if (!sess) { send(401, { error: 'unauthenticated' }); return; }
          if (!isAdmin(sess.role)) { send(403, { error: 'this operator may not run Advisor actions' }); return; }
          const upstream = verb === 'execute' ? '/v1/execute'
            : verb === 'investigate-continue' ? '/v1/investigate/continue'
            : verb === 'investigate-offer' ? '/v1/investigate/offer'
            : '/v1/breakglass/close';
          const limit = verb === 'investigate-continue' ? 256 * 1024 : 64 * 1024;
          const read = await readBody(req, limit);
          if (!read.ok) { send(413, { error: 'too large' }); return; }
          let payload = read.body;
          if (verb !== 'execute') {
            const user = getUserById(sess.userId);
            const actor = { operator: user?.username ?? `user:${sess.userId}`, role: sess.role ?? '' };
            let base: Record<string, unknown> = {};
            try {
              const parsed = JSON.parse(payload || '{}') as unknown;
              if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) base = parsed as Record<string, unknown>;
            } catch { base = {}; }
            payload = JSON.stringify({ ...base, ...actor });
          }
          try {
            const r = await fetch(`${peer.advisor_origin}${upstream}`, {
              method: 'POST',
              headers: { 'content-type': 'application/json', authorization: `Bearer ${peerToken}` },
              body: payload,
              signal: AbortSignal.timeout(verb === 'investigate-continue' ? 120_000 : 30_000),
            });
            // A 5xx from the node, or from the fleet link in front of it, is the
            // edge's to replace with a page: relayed on a status it leaves alone
            // with the node's own status beside the body (#1134).
            const relayed = edgeSafeRelay(r.status, await r.text());
            res.writeHead(relayed.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
            res.end(relayed.body);
          } catch (err) {
            // Edge-safe like every peer failure (#1134): a 502 here never
            // reached the page, which read the edge's HTML in its place.
            // The code is `error`, the words are `detail`: a sentence in the
            // code field is a key the page can never decide by (#1305).
            send(peerFailureStatus('advisor_unreachable'), {
              ok: false, error: 'advisor_unreachable',
              detail: `This dashboard could not reach ${peer.label}\u2019s Advisor: ${(err as Error).message}.`,
            });
          }
          return;
        }
      }
    }
    // PEER-DIAL REGION END

    // The passkey ceremony. Kept out of the proxy allow-list on purpose: these
    // two do not forward a request, they perform a WebAuthn verification the
    // Advisor cannot do, it has no credential store and no session, and only
    // then tell it what was approved.
    // ── The model key ────────────────────────────────────────────
    // Testing a key touches nothing on this host, so it needs no passkey:
    // asking a provider whether a key works is not a change to anything.
    // Sealing IS a change, to a root-owned credential store and to a running
    // service, so it takes a passkey bound to what is about to be sealed.
    //
    // Both sit here, past requireAuthGate and inside the admin checks the
    // handlers make for themselves, and neither is in the read-path
    // allow-list: nothing about a key is a read.
    // Whether root has armed this host for a seal (#168). A stat of the
    // marker, which this account cannot read or write: enough to say "armed,
    // N seconds left" so the model form enables Seal only when a seal could
    // work, and shows the one line to run when it could not. A GET, and a
    // read of nothing secret; still admin-only, because who has armed a host
    // and when is not a fact every signed-in reader needs.
    if (pathname === '/api/advisor/model/arm' && req.method === 'GET') {
      const sess = readSession(req);
      if (!sess) { res.writeHead(401, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'unauthenticated' })); return; }
      if (!isAdmin(sess.role)) { res.writeHead(403, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'this operator may not configure the Advisor model' })); return; }
      const state = armState(() => {
        try { return statSync(ARM_MARKER).mtimeMs; } catch { return null; }
      }, Date.now());
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ ...state, window_s: ARM_WINDOW_SEC, marker: ARM_MARKER }));
      return;
    }
    if (pathname.startsWith('/api/advisor/model/') && req.method === 'POST') {
      // Checked here rather than left to the block further down, which these
      // sit above. All three are writes in the sense that matters: the test
      // spends an operator's session on an outbound request to an address the
      // caller chose, and the other two start and finish a ceremony. A page on
      // another origin holding the operator's cookie must reach none of them.
      if (!csrfOk(req)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'csrf' }));
        return;
      }
      if (pathname === '/api/advisor/model/test') {
        await handleAdvisorModelTest(req, res);
        return;
      }
      if (pathname === '/api/advisor/model/seal/begin') {
        await handleAdvisorModelSealBegin(req, res);
        return;
      }
      if (pathname === '/api/advisor/model/seal') {
        await handleAdvisorModelSealFinish(req, res, runSealer, readBackAdvisorModel);
        return;
      }
    }
    if (pathname === '/api/advisor/approve/begin' && req.method === 'POST') {
      await handleAdvisorApproveBegin(req, res, ADVISOR_URL, advisorApproveToken());
      return;
    }
    if (pathname === '/api/advisor/approve/finish' && req.method === 'POST') {
      await handleAdvisorApproveFinish(req, res, ADVISOR_URL, advisorApproveToken());
      return;
    }
    // Revoking is not a ceremony, but it is still an admin act on the node's
    // behalf, so it sits beside the two above rather than in the read-path
    // allow-list, same reasoning, no ceremony to weaken.
    if (pathname === '/api/advisor/cancel-approval' && req.method === 'POST') {
      await handleAdvisorApproveCancel(req, res, ADVISOR_URL, advisorApproveToken());
      return;
    }
    // Break glass's own ceremony (plan-interrogative-loop §11.8), same
    // reasoning as approve/begin and approve/finish above: a WebAuthn
    // verification the Advisor cannot run itself, kept out of the generic
    // proxy allow-list on purpose.
    if (pathname === '/api/advisor/investigate-begin' && req.method === 'POST') {
      await handleAdvisorInvestigateBegin(req, res, ADVISOR_URL, advisorApproveToken());
      return;
    }
    if (pathname === '/api/advisor/investigate' && req.method === 'POST') {
      await handleAdvisorInvestigateFinish(req, res, ADVISOR_URL, advisorApproveToken());
      return;
    }

    // The run stream is server-sent events, so it is piped rather than
    // buffered, the proxy that reads a whole body before answering would
    // turn a live transcript into a report that arrives when it is over.
    if (pathname.startsWith('/api/advisor/runs/') && pathname.endsWith('/stream')) {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const id = pathname.slice('/api/advisor/runs/'.length, -('/stream'.length));
      if (!/^[A-Za-z0-9._-]{1,120}$/.test(id)) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad run id' }));
        return;
      }
      const off = new URL(req.url ?? '/', 'http://x').searchParams.get('offset') ?? '0';
      // A reconnecting EventSource carries its position in the Last-Event-ID
      // header, not the query string. Dropping it forced every reconnect to
      // replay from zero; forward it so a resume is a resume.
      const lastId = String(req.headers['last-event-id'] ?? '');
      const resume = /^\d+$/.test(lastId) ? lastId : (/^\d+$/.test(off) ? off : '0');
      // Commit to being an event stream BEFORE talking to the advisor. The
      // one response an EventSource treats as fatal, no retry, no error an
      // operator can see, is a non-event-stream content-type. The old code
      // produced exactly that whenever the advisor was briefly unreachable
      // (a restart window), and a page that hit it froze on a stream it
      // believed was live. Whatever happens upstream, the answer is SSE.
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-store',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      try {
        const upstream = await fetch(
          `${ADVISOR_URL}/v1/runs/${encodeURIComponent(id)}/stream?offset=${encodeURIComponent(resume)}`,
          {
            headers: {
              accept: 'text/event-stream',
              authorization: `Bearer ${advisorApproveToken() ?? ''}`,
            },
            signal: AbortSignal.timeout(35 * 60_000),
          },
        );
        if (!upstream.ok || !upstream.body) {
          res.write('retry: 2000\n\n');
          res.end();
          return;
        }
        const reader = upstream.body.getReader();
        req.on('close', () => { try { reader.cancel(); } catch { /* ignore */ } });
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(Buffer.from(value));
        }
        res.end();
      } catch {
        // The advisor going away mid-stream is normal during a restart. End
        // as a well-formed, retryable event stream: the client reconnects
        // with its offset and loses nothing.
        try { res.write('retry: 2000\n\n'); res.end(); } catch { /* ignore */ }
      }
      return;
    }

    // One whole transcript, static, the history view replays what happened,
    // it does not tail. Same id discipline as the stream.
    if (pathname.startsWith('/api/advisor/runs/') && !pathname.endsWith('/stream')) {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }
      const id = pathname.slice('/api/advisor/runs/'.length);
      if (!/^[A-Za-z0-9._-]{1,120}$/.test(id)) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad run id' }));
        return;
      }
      try {
        const r = await fetch(`${ADVISOR_URL}/v1/runs/${encodeURIComponent(id)}`,
          {
            headers: { authorization: `Bearer ${advisorApproveToken() ?? ''}` },
            signal: AbortSignal.timeout(30_000),
          });
        // A 404 is the answer for a run that is not there, so it travels as
        // one; a 5xx the edge would replace with a page goes on a status it
        // leaves alone, with the Advisor's own beside the body (#1134, #1305).
        const relayed = edgeSafeRelay(r.status, await r.text());
        res.writeHead(relayed.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(relayed.body);
      } catch (err) {
        res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ error: 'advisor_unreachable', detail: (err as Error).message }));
      }
      return;
    }

    // The curation routes, ADR 0017 phase 2. Ahead of the proxy block
    // below because that block answers 404 for anything not in its table,
    // and these four are not proxied: they write a file, run the linter,
    // spawn the operator's own push command, and tell the node that
    // proposed what was decided. Admin, CSRF and body limits live in the
    // module, beside the work they gate.
    // The Settings page, ADR 0018. Ahead of the proxy block below for the
    // same reason the curation routes are: none of these is proxied. They
    // read this host's own tables, fan out to every node this dashboard can
    // route to, run a ceremony, and spawn the operator's own push command.
    // Admin, CSRF and the body limits live in the module, beside the work
    // they gate.
    if (await handleSettingsAdmin(req, res, pathname, {
      fleetTrustPath: FLEET_TRUST_PATH,
      repoDir: resolve(import.meta.dirname, '..'),
      peers: () => fleetPeerNodes,
      selfNode: () => fleetSelfNode,
      selfDisplayName: () => selfDisplayLabel(fleetSelfNode),
      held: () => ({ nodes: fleetHeldNodes, reason: fleetHeldReason }),
      fleetView,
      selfAdvisorStatus: fetchSelfAdvisorStatus,
      selfPubkeyNode: () => {
        const info = (snapshot.server_info ?? {}) as AnyObj;
        return typeof info.pubkey_node === 'string' && info.pubkey_node ? info.pubkey_node : null;
      },
      selfHostName: () => osHostname() || null,
      selfRelayVersion: () => sanitizeComponents({ relay: lastRelayVersion ?? '' }).relay ?? null,
      selfArmState: () => {
        const state = armState(() => {
          try { return statSync(ARM_MARKER).mtimeMs; } catch { return null; }
        }, Date.now());
        return { ...state, window_s: ARM_WINDOW_SEC, marker: ARM_MARKER };
      },
      thisDashboard: () => ({
        ...dashboardIdentity(),
        host_name: osHostname() || null,
        install_dir: resolve(import.meta.dirname, '..'),
        label: fleetSelfNode?.label ?? null,
        // #1284. The label this host goes by (pairing, then fleet.yaml), with
        // no host fallback: Settings' Label fact prints only a real label.
        // `label` above stays the registry's, the key.
        display_label: resolveNodeLabel({
          pairedLabel: fleetLinkSlot.agent?.state().label,
          fleetLabel: fleetSelfNode?.label,
          aggregator: selfIsFleetAggregator(),
        }) || null,
        role: fleetSelfNode?.role ?? null,
        // The node's own view of its outbound link, one sentence. Absent on
        // a host that has no fleet-link.json, so the page prints no row for
        // it rather than a row saying "off": a single-node install must not
        // grow a fact about a feature it does not use (ADR 0019).
        fleet_link: linkFactLine(fleetLinkSlot.agent?.state() ?? null),
        // What a relay on ANOTHER box would meet if it dialled /ingest here
        // (MED-07). Decided by the policy module itself, with a placeholder
        // remote peer, so the wizard prints the refusal an operator would
        // actually get rather than a second wording of the same rule that
        // can drift from it. The address is documentation-range and never
        // dials anything; only its non-loopback-ness is read.
        ingest: (() => {
          const verdict = decideIngest({
            bindHost: HOST, remoteAddress: '203.0.113.1',
            allowPlaintext: INGEST_ALLOW_PLAINTEXT,
          });
          return {
            bind_host: HOST,
            remote_relay_allowed: verdict.allow,
            reason: verdict.reason,
            // The refusal, in the policy's own words. Null when a remote
            // relay would be accepted, because there is nothing to warn about.
            detail: verdict.allow ? null : verdict.message,
          };
        })(),
      }),
      // The aggregator's own view of a node's link. Null for every row that
      // is not on the link, and observed rather than configured.
      linkStatus: (label) => fleetLinkHub?.status(label) ?? null,
      // #688: the passkey Revoke asks the hub to sign what it sends.
      expectRevoke: (label) => fleetLinkHub?.expectRevoke(label) ?? (() => {}),
      // Pairing (ADR 0019 phase 3). Every one of these is a pass-through to
      // the hub or to the root broker: this file owns what it holds (the
      // hub, the socket path, node:crypto) and settings-api.ts owns the
      // decision to use it.
      pairings: () => fleetLinkHub?.pending() ?? [],
      pairApprove: (id, label, settle, fleetArmPubkey) => (fleetLinkHub
        ? fleetLinkHub.approve(id, label, settle, fleetArmPubkey)
        : {
          ok: false as const, error: 'no_such_pending',
          detail: 'this dashboard is holding no pairings.',
        }),
      pairRefuse: (id) => fleetLinkHub?.refuse(id) ?? false,
      // Through the serialiser, like every other broker call in this
      // process: the socket takes one connection at a time and a model push
      // holds it for minutes, so an approval must not land on a socket this
      // same process is already using.
      // Bounded, because an operator is waiting on this one. A catch-up in
      // front of it can be 64 nodes at up to 270 s each; past the ceiling
      // this answers as a busy broker rather than holding the approval's
      // request open behind work nobody will wait for (F6). The queued call
      // still runs: what is dropped is the wait, not the connection.
      broker: async (payload) => {
        const answer = await askWithCeiling(
          () => askFleetBroker(payload, FLEET_BROKER_TIMEOUT_MS),
        );
        if (answer) return answer;
        throw new Error(BROKER_BUSY_DETAIL);
      },
      // The sealed fleet model: what this aggregator holds, and sending it to
      // one node (ADR 0019 phase 4, #168).
      // THE POLLED READ, and the only caller that does not join the queue.
      // An open Settings page asks for this every ten seconds and a push holds
      // the socket for minutes: queued, every poll for the length of a
      // catch-up would hang and they would all land at once when it ended.
      // The socket drops an overlapping connection anyway (MaxConnections=1)
      // and the parser calls that `unread`, so this is the same answer without
      // spending the wait.
      //
      // Scoped HERE rather than inside readFleetModelStoreHead, because its
      // other two callers are one-shot and operator-started: the pairing
      // follow-on and the catch-up's own two reads must WAIT their turn.
      // Bailing there would tell an operator a freshly paired node did not
      // answer in time, when the node was fine and this aggregator was busy.
      storeHead: () => (askFleetBroker.busy()
        ? Promise.resolve<BrokerStoreHeadOutcome>({
          state: 'unread', reason: 'broker_busy', detail: BROKER_BUSY_DETAIL,
        })
        : readFleetModelStoreHead()),
      // The same head for an attach's one-shot inherit (#1037), which waits
      // its turn on the socket like the pairing follow-on's does.
      storeHeadQueued: readFleetModelStoreHead,
      modelPush: (label, grant) => pushFleetModelTo(label, grant),
      fleetArmInstalled,
      fleetBrokerInstalled,
      fleetTrustPubKey: () => readOwnPublicKey(FLEET_TRUST_PATH),
      rememberArmPubKey: (pub) => { pairArmPubKeyCache = pub; },
      // #850 review, L2: the same question storeHead asks above. A mint
      // answers busy at once rather than queueing behind a model push.
      brokerBusy: () => askFleetBroker.busy(),
      pairFollowOn: (input) => { void runPairingFollowOn(input); },
      // 32 random bytes as hex, for one link credential. The plaintext goes
      // down the pairing socket and nowhere else; only its SHA-256 reaches
      // the broker, and only that hash is written to fleet-links.json.
      mintCredential: () => randomBytes(32).toString('hex'),
      // #859: no registry file handle. This process writes nothing in
      // dashboard/config (a hardened unit cannot); revoke and Accept new
      // key are the root broker's `revoke` and `repin`.
      // The same signal the root broker sends this process after it writes a
      // registry, so a write made here and a write made there are re-read by
      // one code path rather than two.
      reloadFleet: () => { process.kill(process.pid, 'SIGHUP'); },
      lastStoreWrite: () => lastFleetModelStoreWrite,
      fleetModel: () => readFleetModelRecord(FLEET_MODEL_PATH, (line) => console.warn(line)),
      selfAdvisorPresence: () => advisorPresenceSelf.state,
      jobs: fleetSealJobs,
      pushTrust: runFleetTrustPush,
      advisorUrl: ADVISOR_URL,
      advisorToken: advisorApproveToken,
      reverifyAdvisorMirror: async (node) => {
        const target = mirrorTargetByNode(node);
        if (!target) return null;
        return await reverifyMirrorNode(node, target.fetchLedger) as unknown as Record<string, unknown>;
      },
    })) return;

    if (await handleKnowledgeAdmin(req, res, pathname, {
      repoDir: resolve(import.meta.dirname, '..'),
      advisorUrl: ADVISOR_URL,
      advisorToken: advisorApproveToken,
      peerByLabel: (label) => resolvePeerByLabel(fleetPeerNodes, label) ?? null,
      selfLabel: () => fleetSelfNode?.label ?? null,
      selfName: () => selfDisplayLabel(fleetSelfNode) || null,
    })) return;

    if (pathname.startsWith('/api/advisor/')) {
      const ADVISOR_READ_PATHS: Record<string, string> = {
        '/api/advisor/status': '/v1/status',
        '/api/advisor/check':  '/v1/check',
        '/api/advisor/plan':   '/v1/plan',
        '/api/advisor/ledger': '/v1/ledger',
        '/api/advisor/ask':      '/v1/ask',
        // ADR 0017 decision 4: this host's own proposal inbox, for the
        // review card. Admin-only below, unlike the reads around it.
        '/api/advisor/proposals': '/v1/proposals',
        // The interrogative loop's live step trace for a question still in
        // flight (plan-interrogative-loop §9.5/§10.1). GET, so it inherits
        // the read-only handling below, no new POST surface.
        '/api/advisor/ask-progress': '/v1/ask/progress',
        '/api/advisor/evidence': '/v1/evidence',
        '/api/advisor/execute':  '/v1/execute',
        '/api/advisor/runs':     '/v1/runs',
        // Break glass, plan-interrogative-loop §11.8. Only the two halves
        // with NO ceremony are plain proxy entries here: continue (the
        // window's own authority, already established) and close (undoing
        // consent, which, like cancel-approval, needs no ceremony of its
        // own). investigate-begin and investigate perform a WebAuthn
        // ceremony the Advisor cannot run itself, so they are handled
        // exactly like approve/begin and approve/finish below, kept OUT of
        // this table on purpose.
        '/api/advisor/investigate-continue': '/v1/investigate/continue',
        '/api/advisor/breakglass-close':     '/v1/breakglass/close',
        // The operator-initiated offer (the header's Break glass button):
        // no ceremony of its own either, it only mints the offer the
        // ceremony below then binds to. Admin-gated like the other two.
        '/api/advisor/investigate-offer':    '/v1/investigate/offer',
      };
      const upstream = ADVISOR_READ_PATHS[pathname];
      if (!upstream) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'no such advisor endpoint' }));
        return;
      }

      // Two of these routes change the host. The session gate above proves
      // only that SOMEONE is logged in, and monitor is a real role that is
      // supposed to watch and nothing else, without this, a monitor session
      // could spend an admin's live approval, because the approval lives on
      // the Advisor and the run is just a request. Approving and running are
      // both admin acts; the ceremony has always checked this, and now the
      // route that spends its result does too.
      const ADVISOR_ADMIN_PATHS = new Set([
        '/api/advisor/execute',   // runs a stage against the node
        '/api/advisor/evidence',  // writes a snapshot into the Advisor's state
        // Break glass (§11.7): a monitor sees the offer as information, with
        // no control, enforced here, not just by the page's rendering
        // choice.
        '/api/advisor/investigate-continue',
        '/api/advisor/breakglass-close',
        '/api/advisor/investigate-offer',
        // The one READ in this set (ADR 0017 decision 4). A queue of
        // model-authored notes that no human has accepted yet is not
        // something a monitor session gets to read, and the card hiding it
        // is a rendering choice rather than an enforcement.
        '/api/advisor/proposals',
      ]);
      if (ADVISOR_ADMIN_PATHS.has(pathname)) {
        const sess = readSession(req);
        if (!sess) {
          res.writeHead(401, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'unauthenticated' }));
          return;
        }
        if (!isAdmin(sess.role)) {
          console.warn(`[advisor] refused ${pathname} for ${sess.username} (role ${sess.role})`);
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            error: 'this operator may not run Advisor actions',
            detail: `Role is ${sess.role}. An admin can change it on the dashboard host: bash scripts/aperire-auth.sh set-role <email> admin`,
          }));
          return;
        }
      }
      // /ask is the one POST, and it is listed explicitly rather than by
      // relaxing the rule. It carries a question in its body but changes no
      // host state: the agent holds the model credential, the executor holds
      // the authority to act, and they are deliberately not the same thing.
      const isAsk = pathname === '/api/advisor/ask';
      // Capturing a diagnostic snapshot is a read that saves its output. It
      // changes nothing on the node, so it is not held to the passkey
      // ceremony, but it does need the service token, so it forwards with
      // the same authorisation /v1/approve uses.
      const isEvidence = pathname === '/api/advisor/evidence';
      // The one write that acts on the node. It carries no authority of its
      // own: it spends an approval already verified twice and bound to the
      // plan, and the executor re-measures its preconditions regardless.
      const isExecute = pathname === '/api/advisor/execute';
      // The two break-glass writes with no ceremony of their own, see the
      // note on ADVISOR_READ_PATHS above for why begin/finish are not here.
      const isInvestigateContinue = pathname === '/api/advisor/investigate-continue';
      const isBreakglassClose = pathname === '/api/advisor/breakglass-close';
      const isInvestigateOffer = pathname === '/api/advisor/investigate-offer';
      const isBreakglassWrite = isInvestigateContinue || isBreakglassClose || isInvestigateOffer;
      if (req.method !== 'GET' && !((isAsk || isEvidence || isExecute || isBreakglassWrite) && req.method === 'POST')) {
        res.writeHead(405, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'the advisor proxy is read-only' }));
        return;
      }
      // The same header every other authenticated write in this app requires.
      // These three were the exception, which meant a page on another origin
      // could have spent the model budget or triggered a run using the
      // operator's cookie, the passkey ceremony still stands in front of
      // anything that touches the node, but a run should not be startable
      // from off-site at all.
      if (req.method === 'POST' && !csrfOk(req)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'csrf' }));
        return;
      }
      // Only what's on the per-path allow-list is forwarded, see
      // lib/advisor-proxy-query.ts for the rule and why it must stay
      // per-path rather than global.
      const q = new URL(req.url ?? '/', 'http://localhost').searchParams;
      // #547. A runbook this dashboard does not recognise must be a named
      // refusal here, not a silently-dropped parameter that lets /v1/check
      // answer about its own default (the upgrade) as if that were the
      // answer to the question actually asked.
      const runbookErr = advisorRunbookError(pathname, q);
      if (runbookErr) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: runbookErr }));
        return;
      }
      const qs = advisorForwardQuery(pathname, q);

      const startedAt = Date.now();
      try {
        let payload: string | undefined;
        if (isAsk || isExecute || isBreakglassWrite) {
          const read = await readBody(req, 256 * 1024);
          if (!read.ok) { res.writeHead(413); res.end('question too large'); return; }
          payload = read.body;
        }
        // Who is doing this, stamped HERE, from the session cookie, on the
        // server, never from the browser's body.
        //
        // The two break-glass writes used to carry no identity at all, and
        // that was a real mis-attribution rather than a missing field: with
        // no operator on the request, every privileged read a continued
        // question performed resolved, by the only join available, to
        // whoever opened the window, so a second admin's reads were recorded
        // against the first admin's name. Evidence capture was worse: it was
        // not recorded at all.
        //
        // Injected rather than accepted. If the browser sent the actor, the
        // audit trail would be a field the page fills in, and any operator
        // could write any name into the tamper-evident record. Deriving it
        // from readSession is the same discipline handleAdvisorApproveFinish
        // already applies to granted_by.
        // ask carries the actor too: with a break-glass window open the
        // service runs the question at the gated tier, and every
        // privileged read it performs is recorded against this person.
        if (isBreakglassWrite || isEvidence || isAsk) {
          const sess = readSession(req);            // already proven above for these paths
          const user = sess ? getUserById(sess.userId) : null;
          const actor = {
            operator: user?.username ?? (sess ? `user:${sess.userId}` : ''),
            role: sess?.role ?? '',
          };
          let base: Record<string, unknown> = {};
          if (payload) {
            try {
              const parsed = JSON.parse(payload) as unknown;
              if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                base = parsed as Record<string, unknown>;
              }
            } catch {
              // An unparseable body is the Advisor's to reject. Do not
              // silently replace it with one this proxy invented.
              base = {};
            }
          }
          // Assigned last, so a body that already carried these keys cannot
          // win. That ordering is the whole guarantee.
          payload = JSON.stringify({ ...base, ...actor });
        }
        // Every advisor call now carries the service token, reads included.
        // Loopback is a network boundary, not a user boundary, an
        // unauthenticated read surface on 127.0.0.1 is readable by every
        // account on the host, and what it returns is the audit ledger, the
        // run transcripts and the node's deployment.
        const tok = advisorApproveToken();
        if (!tok) {
          res.writeHead(503, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            error: 'no advisor token readable on this host',
            hint: 'the Advisor generates one at startup; the dashboard must be able to read advisor/state/approve.token',
          }));
          return;
        }
        const isPostUpstream = isAsk || isEvidence || isExecute || isBreakglassWrite;
        const forward = async () => {
          const resp = await fetch(`${ADVISOR_URL}${upstream}${qs}`, {
            method: isPostUpstream ? 'POST' : 'GET',
            headers: isPostUpstream
              ? { 'content-type': 'application/json', authorization: `Bearer ${tok}` }
              : { authorization: `Bearer ${tok}` },
            body: payload,
            // A model call is slower than a host read, so this gets its own
            // budget rather than the read timeout. Widened to match the
            // interrogative loop's own 300s hard ceiling (plan-interrogative-
            // loop §6.1, §9.6), a four-round question with a slow public
            // read can genuinely take longer than the 120s this used to be,
            // and the old value would abort a good answer already in
            // progress on advisord's side.
            // Execute returns as soon as the run is started; progress arrives
            // over the stream, so this is not the run's budget.
            signal: AbortSignal.timeout(isAsk ? 300_000 : 30_000),
          });
          // Read inside the tracked span: the body is the answer, and a
          // process restarted between the response and this read has still
          // lost the question.
          return { resp, text: await resp.text() };
        };
        // Only a question is counted, punch #24. A status poll or a plan
        // read is a second of work and must not make a deploy wait, but an
        // ask can hold this process for minutes and a restart on top of one
        // is what killed an operator's question on 2026-08-20.
        const { resp: r, text: body } = isAsk ? await trackAsk(forward) : await forward();
        // Logged because the failure that prompted this was invisible from
        // here: the browser saw a 502 from the edge while every check from the
        // host said the path was healthy. One line naming the upstream status
        // and the size settles which side actually refused.
        console.log(`[advisor] ${req.method} ${pathname} -> ${upstream} ` +
          `${r.status} ${body.length}b ${Date.now() - startedAt}ms`);
        // Status passes back through here annotated with one thing only the
        // dashboard can know: whether the Advisor's copy of "who may approve"
        // still matches the real one.
        //
        // The Advisor verifies approvals against a replica of these
        // credentials, refreshed by a script someone has to remember to run.
        // When it drifts, the failure is silent and misdirected, a passkey
        // enrolled since the last sync is rejected at the moment of approval
        // with an error that reads like the passkey is broken, and an operator
        // whose admin role was revoked keeps approving. Neither is visible
        // until it matters. Comparing digests makes it visible now.
        let out = body;
        if (pathname === '/api/advisor/status' && r.ok) {
          try {
            // peerLabel null, this is THIS host's advisord, whose remedy is
            // the local sync. The peer path below shares the same builder so
            // the two can never disagree about what "in sync" means.
            //
            // selfIsAggregator: whether THIS host holds its own fleet-trust
            // private key. Only that fact (not role alone, a host can be
            // declared 'aggregator' before its trust key is generated) tells
            // buildTrustSync that a bundle its own advisord holds could only
            // have come from this same dashboard pushing to itself (#178).
            out = JSON.stringify(annotateTrustSync(JSON.parse(body), {
              mine: trustFingerprint(), peerLabel: null,
              selfIsAggregator: readOwnPrivateKey(FLEET_TRUST_PATH) !== null,
              selfLabel: fleetSelfNode?.label ?? null,
            }));
          } catch {
            // A status body we cannot parse is the Advisor's business, not
            // ours. Pass it through untouched rather than turning a readable
            // upstream response into a dashboard error.
          }
        }
        // The Advisor's answer as it came, except a 5xx the edge would replace
        // with a page: that goes on a status it leaves alone, with the
        // Advisor's own beside the body (#1134, #1305).
        const relayed = edgeSafeRelay(r.status, out);
        res.writeHead(relayed.status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(relayed.body);
      } catch (err) {
        console.warn(`[advisor] ${req.method} ${pathname} -> ${upstream} FAILED ` +
          `after ${Date.now() - startedAt}ms: ${(err as Error).message}`);
        // A stopped advisord is a normal state, not an error to bury. The
        // tab says so plainly instead of rendering an empty panel that
        // reads like "nothing to report".
        res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify({
          error: 'advisor_unreachable',
          detail: (err as Error).message,
          hint: `no advisor service answering on ${ADVISOR_URL}`,
        }));
      }
      return;
    }

    if (pathname === '/api/insights/config') {
      // Prettify config-file paths for display: replace the dashboard
      // user's home directory prefix with `~`. Internal callers of
      // readFile() keep using the absolute paths from insightsConfig;
      // this transform only affects the JSON sent to the browser, so
      // the operator sees `~/aperire-one/dashboard/config/rules.yaml`
      // rather than the full path. Paths outside $HOME (e.g.
      // /etc/aperire/relay.conf)
      // pass through unchanged.
      const home = osHomedir();
      const prettify = (p: string): string =>
        (home && p === home) ? '~' :
        (home && p.startsWith(home + '/')) ? '~' + p.slice(home.length) : p;
      const view = {
        ...insightsConfig,
        rules:     { ...insightsConfig.rules,     path: prettify(insightsConfig.rules.path), localPath: prettify(insightsConfig.rules.localPath) },
        knowledge: { ...insightsConfig.knowledge, path: prettify(insightsConfig.knowledge.path) },
        channels:  { ...insightsConfig.channels,  path: prettify(insightsConfig.channels.path) },
        digest:    { ...insightsConfig.digest,    path: prettify(insightsConfig.digest.path) },
      };
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(view));
      return;
    }

    // Currently firing alerts + summary counts. Drives the Currently
    // Firing card and the Firing Now / Last Page strip cells.
    if (pathname === '/api/insights/state') {
      const firing = queryFiringState();
      const counts = { firing_now: firing.length, page: 0, critical: 0, warn: 0 };
      for (const f of firing) {
        if (f.severity === 'page') counts.page++;
        else if (f.severity === 'critical') counts.critical++;
        else if (f.severity === 'warn') counts.warn++;
      }
      // Last Page event (most recent severity=page in alerts_history,
      // any state). Used by the strip cell whether it's firing or
      // resolved, operator wants to know the freshness either way.
      const oneYearAgoMs = Date.now() - 365 * 86_400_000;
      const recentEvents = queryAlertHistory(oneYearAgoMs, 200);
      const lastPage = recentEvents.find(e => e.severity === 'page') ?? null;
      // The last digest that was SENT, not the last run of any kind, and
      // found the same way lastPage above is (#486). A run that failed or is
      // mid-retry is not a send, and one row of any state cannot be told
      // apart from a send by the page: a failed attempt at 13:00 today would
      // have read as today's digest with yesterday's real send hidden behind
      // it. The Digest Log panel still shows every run, failures included.
      const lastDigest = queryDigestRuns(oneYearAgoMs, 200).find(d => d.state === 'sent') ?? null;
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ firing, counts, lastPage, lastDigest }));
      return;
    }

    // Last 24h of alert events. Drives the Alert History table.
    if (pathname === '/api/insights/history') {
      const hours = Math.min(168, Math.max(1, Number(url.searchParams.get('hours') ?? 24)));
      const sinceMs = Date.now() - hours * 3_600_000;
      const events = queryAlertHistory(sinceMs, 500);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ events, since_ms: sinceMs }));
      return;
    }

    // Phase 5, Test Fire status. Returns rate-limit state per channel,
    // which channels a Live Test would reach (`configured`, #1265), and
    // whether APERIRE_TEST_TOKEN gating is active. The browser renders
    // the card from this and decides whether to prompt for a token
    // before POSTing.
    if (pathname === '/api/insights/test_fire' && req.method === 'GET') {
      const state = {
        token_required: testFireTokenRequired(),
        configured: testFireConfigured(),
        channels: {
          email:   testFireRateState('email'),
          ntfy:    testFireRateState('ntfy'),
          webhook: testFireRateState('webhook'),
        },
      };
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(state));
      return;
    }

    // Phase 5, Test Fire executor. Body shape:
    //   { mode: 'dry_run' | 'live', channels?: string[], token?: string }
    // mode=dry_run walks the pipeline without sending; mode=live
    // actually delivers via every requested channel with a [TEST]
    // prefix on the subject. Rate-limited per channel; auth via
    // APERIRE_TEST_TOKEN if set.
    // The page reporting on itself (#259). debug-mem.js sends one small
    // beat on each lifecycle event and every few seconds while its flag is
    // on, and each becomes one log line beside the [page] loads. Session
    // gated like everything under /api/, capped, and it stores nothing:
    // the log IS the record, and it is off unless an operator turned the
    // readout on with ?debug=mem.
    // One shape for "this route will not read that", so a caller gets an
    // answer instead of a reset socket. See lib/read-body.ts.
    const sendJsonRefusal = (r: typeof res, status: number, error: string): void => {
      r.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      r.end(JSON.stringify({ ok: false, error }));
    };

    if (pathname === '/api/client-beat' && req.method === 'POST') {
      void (async () => {
        const read = await readBody(req, 2048);
        if (!read.ok) { res.writeHead(413, { 'cache-control': 'no-store' }); res.end(); return; }
        let b: AnyObj;
        try { b = JSON.parse(read.body || '{}') as AnyObj; } catch (_) { b = {}; }
        const clean = (v: unknown, n: number) => String(v ?? '').replace(/[^\x20-\x7e]/g, '?').slice(0, n);
        console.log(`[beat] ${clean(b.page, 24)} ${clean(b.ev, 24)} ${clean(b.detail, 160)} ${browserFamily(req.headers['user-agent'])}`);
        res.writeHead(204, { 'cache-control': 'no-store' }); res.end();
      })();
      return;
    }

    if (pathname === '/api/insights/test_fire' && req.method === 'POST') {
      void (async () => {
        const read = await readBody(req, 4096);
        if (!read.ok) { sendJsonRefusal(res, 413, 'body_too_large'); return; }
        const body = read.body;
        try {
          let payload: AnyObj;
          try { payload = JSON.parse(body || '{}'); } catch (_) { res.writeHead(400); res.end('bad json'); return; }
          const mode = payload.mode === 'live' ? 'live' : 'dry_run';
          const requestedChannels = Array.isArray(payload.channels)
            ? (payload.channels as unknown[]).filter(c => typeof c === 'string') as string[]
            : ['email', 'ntfy', 'webhook'];
          const token = typeof payload.token === 'string' ? payload.token : null;

          if (mode === 'live' && !testFireTokenValid(token)) {
            res.writeHead(401, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'invalid or missing APERIRE_TEST_TOKEN' }));
            return;
          }

          // Build a synthetic alert context that walks the same path as
          // a real firing event. Subject gets [TEST] via is_test=true.
          const ctx: AlertEmailContext = {
            metric: 'aperire_test_fire',
            severity: 'warn',
            state: 'firing',
            value: 1,
            threshold_op: '>=',
            threshold_value: 1,
            duration_s: 0,
            dedup_key: `aperire_test_fire:${Date.now()}`,
            triggered_iso: new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'),
            ...alertNodeFields(),
            is_test: true,
            // #128. Test Fire is channel-scoped, not rule-scoped: it has
            // no rule behind it to read an action off. A static line
            // keeps a test delivery the same SHAPE as a real one, so an
            // operator sees where the instruction lands before the first
            // real page rather than at 3am.
            action: 'No action needed. This is a delivery test, sent from the Insights tab to prove this channel works.',
          };

          const results: AnyObj[] = [];
          (async () => {
            for (const channelId of requestedChannels) {
              if (channelId === 'email') {
                if (!emailSendConfig) {
                  results.push({ id: 'email', attempted: false, reason: 'not configured' });
                  continue;
                }
                const rateState = testFireRateState('email');
                if (rateState.used >= rateState.limit) {
                  results.push({ id: 'email', attempted: false, reason: 'rate limited', rate: rateState });
                  continue;
                }
                if (mode === 'dry_run') {
                  results.push({
                    id: 'email',
                    attempted: false,
                    mode: 'dry_run',
                    would_send_to: emailSendConfig.recipients,
                    sender: emailSendConfig.sender,
                    subject_preview: buildSubject(ctx),
                  });
                  continue;
                }
                testFireConsume('email');
                const r = await sendAlertEmail(emailSendConfig, ctx);
                results.push({
                  id: 'email',
                  attempted: true,
                  delivered: r.ok,
                  message_id: r.messageId,
                  error: r.error,
                });
                if (r.ok) console.log(`[test-fire] email delivered (id ${r.messageId})`);
                else      console.warn(`[test-fire] email failed: ${r.error}`);
              } else if (channelId === 'ntfy') {
                if (!ntfySendConfig) {
                  results.push({ id: 'ntfy', attempted: false, reason: 'not configured' });
                  continue;
                }
                const rateState = testFireRateState('ntfy');
                if (rateState.used >= rateState.limit) {
                  results.push({ id: 'ntfy', attempted: false, reason: 'rate limited', rate: rateState });
                  continue;
                }
                if (mode === 'dry_run') {
                  results.push({
                    id: 'ntfy',
                    attempted: false,
                    mode: 'dry_run',
                    would_post_to: `${ntfySendConfig.baseUrl}/${ntfySendConfig.topic}`,
                    priority: ntfySendConfig.severityPriority[ctx.severity] ?? 'default',
                  });
                  continue;
                }
                testFireConsume('ntfy');
                const r = await sendAlertNtfy(ntfySendConfig, ctx);
                results.push({
                  id: 'ntfy',
                  attempted: true,
                  delivered: r.ok,
                  message_id: r.messageId,
                  error: r.error,
                });
                if (r.ok) console.log(`[test-fire] ntfy delivered` + (r.messageId ? ` (id ${r.messageId})` : ''));
                else      console.warn(`[test-fire] ntfy failed: ${r.error}`);
              } else if (channelId === 'webhook') {
                if (webhookSendConfigs.length === 0) {
                  results.push({ id: 'webhook', attempted: false, reason: 'not configured' });
                  continue;
                }
                const rateState = testFireRateState('webhook');
                if (rateState.used >= rateState.limit) {
                  results.push({ id: 'webhook', attempted: false, reason: 'rate limited', rate: rateState });
                  continue;
                }
                // Apply each target's severity_filter against the
                // synthetic ctx (defaults to 'warn' here). Targets that
                // don't accept this severity are reported but not
                // counted against the rate-limit bucket.
                const targets = webhookSendConfigs.map(cfg => ({
                  cfg,
                  passes: cfg.severityFilter == null || cfg.severityFilter.includes(ctx.severity),
                }));
                if (mode === 'dry_run') {
                  results.push({
                    id: 'webhook',
                    attempted: false,
                    mode: 'dry_run',
                    targets: targets.map(t => ({
                      id: t.cfg.id,
                      format: t.cfg.format,
                      would_post_to: t.cfg.url,
                      auth_header_set: !!t.cfg.authHeader,
                      severity_passes_filter: t.passes,
                    })),
                  });
                  continue;
                }
                testFireConsume('webhook');
                const sendable = targets.filter(t => t.passes);
                const sendResults = await Promise.all(sendable.map(async t => {
                  const r = await sendAlertWebhook(t.cfg, ctx);
                  if (r.ok) console.log(`[test-fire] webhook delivered '${t.cfg.id}'`);
                  else      console.warn(`[test-fire] webhook failed '${t.cfg.id}': ${r.error}`);
                  return { id: t.cfg.id, format: t.cfg.format, attempted: true, delivered: r.ok, status: r.status, error: r.error };
                }));
                const skipped = targets.filter(t => !t.passes).map(t => ({
                  id: t.cfg.id, format: t.cfg.format, attempted: false, reason: 'severity filter excludes',
                }));
                results.push({
                  id: 'webhook',
                  attempted: true,
                  delivered: sendResults.length > 0 && sendResults.every(r => r.delivered),
                  targets: [...sendResults, ...skipped],
                });
              }
            }
            res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
            res.end(JSON.stringify({
              ok: true,
              mode,
              channels: results,
              configured: testFireConfigured(),
              rate_state: {
                email:   testFireRateState('email'),
                ntfy:    testFireRateState('ntfy'),
                webhook: testFireRateState('webhook'),
              },
            }));
          })().catch(err => {
            res.writeHead(500, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: (err as Error).message }));
          });
        } catch (err) {
          // A body this route could not read is still an /api/ answer: JSON,
          // uncached, and carrying nothing of the thrown error. The message
          // used to go on the wire, which is how a path or a stack line ends
          // up in a browser. It is logged instead.
          res.writeHead(500, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end(JSON.stringify({ ok: false, error: 'internal_error' }));
          console.error(err);
        }
      })();
      return;
    }

    // Phase 6, manually trigger a digest send. Same auth gate as
    // Test Fire (APERIRE_TEST_TOKEN if set) so an operator can verify
    // the digest pipeline before the scheduled hour. Records to
    // digest_runs same as a scheduled send.
    if (pathname === '/api/insights/digest_send' && req.method === 'POST') {
      void (async () => {
        const read = await readBody(req, 1024);
        if (!read.ok) { sendJsonRefusal(res, 413, 'body_too_large'); return; }
        const body = read.body;
        try {
          const payload = body ? JSON.parse(body) as AnyObj : {};
          const token = typeof payload.token === 'string' ? payload.token : null;
          if (!testFireTokenValid(token)) {
            res.writeHead(401, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'invalid or missing APERIRE_TEST_TOKEN' }));
            return;
          }
          if (!digestSendConfig) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'digest disabled or misconfigured' }));
            return;
          }
          fireDigestNow('manual').then(() => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true, mode: 'manual', recipients: digestSendConfig?.recipients.length ?? 0 }));
          }).catch(err => {
            res.writeHead(500, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: (err as Error).message }));
          });
        } catch (err) {
          // A body this route could not read is still an /api/ answer: JSON,
          // uncached, and carrying nothing of the thrown error. The message
          // used to go on the wire, which is how a path or a stack line ends
          // up in a browser. It is logged instead.
          res.writeHead(500, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end(JSON.stringify({ ok: false, error: 'internal_error' }));
          console.error(err);
        }
      })();
      return;
    }

    // Last 7d of digest sends. Drives the Digest Log table. Phase 6
    // populates this table on each scheduled or manual send.
    if (pathname === '/api/insights/digest_log') {
      const days = Math.min(30, Math.max(1, Number(url.searchParams.get('days') ?? 7)));
      const sinceMs = Date.now() - days * 86_400_000;
      const runs = queryDigestRuns(sinceMs, 200);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify({ runs, since_ms: sinceMs }));
      return;
    }

    if (pathname === '/') pathname = '/index.html';

    const filePath = join(PUBLIC_DIR, pathname);
    if (!filePath.startsWith(PUBLIC_DIR)) {
      res.writeHead(403); res.end('Forbidden'); return;
    }

    const ext = extname(filePath);
    const type = MIME[ext] ?? 'application/octet-stream';
    let body = await readFile(filePath);
    if (ext === '.html') {
      // One line per page load, and only for pages: an iPad that came back to
      // a blank tab with its spinner turning (#259, 2026-09-08) left no trace
      // anywhere, because nothing here said whether the reload had even
      // arrived. Pages are a few requests a minute; the browser family is
      // enough to tell that tablet from the desktop next to it.
      console.log(`[page] ${pathname} ${browserFamily(req.headers['user-agent'])} ${req.socket.remoteAddress ?? ''}`);
      // MED-05, stamp the CSP nonce onto the page's inline <script> block so
      // it runs under script-src 'nonce-…'. Bare `<script>` matches only the
      // inline block; external `<script src=…>` (idle-tracker, WebAuthn
      // bundle) is left untouched and already allowed by 'self'.
      body = Buffer.from(body.toString('utf8').replaceAll('<script>', `<script nonce="${cspNonce}">`));
      // APERIRE_CLIENT_DEBUG=mem turns the readout and its beats on for every
      // page this host serves, with nothing to type on the device. The URL
      // flag failed three times on an iPad (#259: a tapped link opens in
      // another app's browser, a typed one gets autocompleted to the bare
      // domain). A lab setting; it is a meta tag debug-mem.js reads.
      if (CLIENT_DEBUG) {
        body = Buffer.from(body.toString('utf8').replace('<head>', `<head><meta name="aperire-debug" content="${CLIENT_DEBUG}">`));
      }
    }
    res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
    res.end(body);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') { res.writeHead(404); res.end('Not found'); return; }
    // The shape of this answer is decided by the raw request URL, because
    // every parsed form of it is out of scope here (both are declared inside
    // the try) and re-parsing inside a catch can throw again. /api/* and
    // /auth/* callers parse the body, so they get JSON; everything else keeps
    // the text it has always had. The error itself is logged, never sent.
    const fail = internalErrorResponse(req.url);
    res.writeHead(fail.status, fail.headers); res.end(fail.body);
    console.error(err);
  }
});

const wss = new WebSocketServer({ noServer: true });
const ingestWss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
// The fleet link. A response frame carries a whole advisord transcript, so
// the cap is the contract's response bound plus room for the framing around
// it, and never unbounded: this endpoint is on the public internet.
// One knowledge bundle frame and no more (#289). The number is the
// contract's, so the two ends and the two caps cannot drift apart.
const fleetLinkWss = new WebSocketServer({ noServer: true, maxPayload: FLEET_LINK_MAX_FRAME_BYTES });
// The PAIRING half of the same endpoint, and its own listener for one
// reason: the cap above is sized for a knowledge bundle on a credentialled
// link, and a pairing caller has presented nothing at all. Serving both from
// one server let an unauthenticated caller buffer 10 MiB and make this
// process parse it, four at a time (P2-054). Every pairing frame fits in
// single-digit KiB.
const fleetPairWss = new WebSocketServer({ noServer: true, maxPayload: FLEET_PAIR_MAX_FRAME_BYTES });

// Heartbeat, without ping/pong, a half-dead WS (cloudflared dropping the
// upstream during a docker network bounce, NAT timeout, etc.) leaves the
// browser frozen until OS TCP keepalive notices, which is hours. Server
// pings every 30s; if the prior ping wasn't ponged we terminate so the
// browser's onclose-driven reconnect (overview.html etc.) fires.
type Liveness = { isAlive?: boolean };
function markAlive(this: WebSocket & Liveness) { this.isAlive = true; }
setInterval(() => {
  for (const client of wss.clients) {
    const w = client as WebSocket & Liveness;
    if (w.isAlive === false) { client.terminate(); continue; }
    w.isAlive = false;
    try { client.ping(); } catch { /* ignore */ }
  }
}, 30_000);

// CSWSH origin gate for the browser /ws feed. Returns true when `origin`
// is allowed to open the socket.
//   - Production (public_url / APERIRE_RP_ORIGIN set): the Origin header
//     MUST exactly match one of the configured origins. A missing Origin
//     (non-browser client, or a browser that withholds it) is rejected,
//     a legitimate browser same-origin upgrade always sends it.
//   - Dev (nothing configured, falls back to localhost default): allow a
//     missing Origin and any loopback origin so local SSH-tunnel / direct
//     access isn't broken, while still rejecting an arbitrary public origin.
function wsOriginAllowed(origin: string | undefined): boolean {
  const allowed = expectedOrigins();
  if (origin && allowed.includes(origin.replace(/\/$/, ''))) return true;

  if (!originExplicitlyConfigured()) {
    // Dev fallback only, never reached once public_url is set.
    if (!origin) return true;
    try {
      const h = new URL(origin).hostname;
      if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]') return true;
    } catch { /* malformed origin → fall through to reject */ }
  }
  return false;
}

httpServer.on('upgrade', (req, socket, head) => {
  // The base is a FIXED literal, not the Host header (#287). Node's HTTP
  // parser accepts a Host value `new URL` refuses (`Host: [` is enough), and
  // this constructor is the first statement of an event handler: the throw
  // escapes it, reaches process.on('uncaughtException') and exits the whole
  // dashboard. One request, no credential, no session, and a loop keeps the
  // box down. The request handler's copy of this line has carried a guard
  // since `curl /api/%zz` threw in its decode; this one never got one.
  //
  // Only `url.pathname` is read below, and a fixed base gives exactly that,
  // which is the form server.ts's other two parses already use. The try/catch
  // is the belt: a path Node accepted and URL will not parse closes the
  // socket with a 400 rather than the process with a signal.
  let url: URL;
  try {
    url = new URL(req.url ?? '/', 'http://localhost');
  } catch {
    console.warn(`[upgrade] refused a malformed request line from ${req.socket.remoteAddress ?? 'unknown'}`);
    try { socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch { /* already gone */ }
    socket.destroy();
    return;
  }

  if (url.pathname === '/ws') {
    // CRIT-01, the browser feed carries the full live telemetry snapshot
    // (raw server_info, enriched peer topology, master pubkey, UNL). It is
    // reachable on the public internet via the Cloudflare tunnel, so we gate
    // the upgrade BEFORE handleUpgrade, mirroring the /ingest bearer reject
    // below: an unauthenticated or cross-origin client never reaches the WS
    // state machine and never sees a snapshot.

    // (1) Session check. readSession() parses the apr_sess cookie and
    // enforces revoked / expired / idle-timeout, the same gate the HTTP
    // requireAuthGate uses. A same-origin browser upgrade carries the
    // cookie automatically, so an authenticated operator still connects.
    if (!readSession(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    // (2) Origin check (CSWSH defense). A cookie alone isn't enough: a
    // malicious page on another origin can open a WebSocket to us and the
    // browser will attach our SameSite=Lax cookie to that cross-site GET
    // upgrade. Pin the Origin to the configured public_url(s), the same
    // origin set WebAuthn credentials are bound to, never to a value
    // derived from the request's own Host header.
    if (!wsOriginAllowed(req.headers.origin)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      browsers.add(ws);
      (ws as WebSocket & Liveness).isAlive = true;
      ws.on('pong', markAlive);
      try { ws.send(JSON.stringify({ type: 'snapshot', data: snapshotForBrowser() })); } catch { /* ignore */ }
      // The amendment summary is only produced by pollFeature, which runs on
      // bridge connect and then every five minutes. If that first run has not
      // happened yet or did not succeed, a tab opening now gets the placeholder
      // and keeps it for up to five minutes, which reads as "no amendments"
      // rather than "not yet". Kick a poll instead of waiting for the schedule;
      // the broadcast it emits reaches this tab and every other one.
      if (lastAmendmentsBroadcast === null) kickFeaturePoll();
      ws.on('close', () => browsers.delete(ws));
      ws.on('error', () => browsers.delete(ws));
    });
    return;
  }

  if (url.pathname === FLEET_LINK_PATH) {
    // ADR 0019 phase 1. Every refusal is decided BEFORE the upgrade, the same
    // order /ingest uses below: transport policy, then the rate limit and the
    // caps, then the credential.
    //
    // This endpoint answers when this host has either a registered node or a
    // live pairing code an administrator minted, and is a destroyed socket
    // otherwise (exactly as it was before the endpoint existed). Pairing is
    // the case where fleet-links.json is EMPTY, so "no rows, no hub" would
    // have refused the first node ever to join a fleet (phase 3). The armed
    // check is a memoised read of the code table, not a query per dial.
    // #738: and when it holds a revocation it signed. A fleet whose last node
    // was revoked while offline has no rows and no code, and a destroyed
    // socket reads as transient on that node, which then dials every minute
    // instead of hourly. The hub answers it the 401 with its tombstone.
    const hub = fleetLinkHub
      ?? (pairingArmed(Date.now()) || fleetLinkIssuedTombstones.size() > 0 ? ensureFleetLinkHub() : null);
    if (!hub) { socket.destroy(); return; }
    hub.handleUpgrade(req, socket, head);
    return;
  }

  if (url.pathname === '/ingest') {
    // Static bearer-token auth. Reject before upgrading so unauthenticated
    // clients never reach the WS state machine.
    const authHeader = String(req.headers.authorization ?? '');
    const m = /^Bearer\s+(.+)$/.exec(authHeader);
    const token = m?.[1]?.trim() ?? '';
    if (!relayTokenAccepted(token, RELAY_TOKENS)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    // Transport policy, MED-07. Runs after the token check on purpose: the
    // token is already on the wire, so gating first would protect nothing and
    // would let any LAN scanner write journal lines. A refusal here means a
    // correctly-authenticated relay was turned away, which is worth reading.
    const verdict = decideIngest({
      bindHost: HOST,
      remoteAddress: req.socket.remoteAddress,
      allowPlaintext: INGEST_ALLOW_PLAINTEXT,
    });
    if (!verdict.allow) {
      console.warn(verdict.message);
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    if (verdict.message) console.warn(verdict.message);

    ingestWss.handleUpgrade(req, socket, head, (ws) => {
      const remote = (req.socket.remoteAddress ?? '?');
      console.log(`[ingest] relay connected from ${remote}`);
      ws.on('message', (raw) => {
        let parsed: unknown;
        try { parsed = JSON.parse(raw.toString()); } catch { return; }
        try { handleRelayPush(parsed as RelayPush); }
        catch (e) { console.error('[ingest] handler error', e); }
      });
      ws.on('close', () => console.log(`[ingest] relay disconnected (${remote})`));
      ws.on('error', (e) => console.warn('[ingest] relay error', e));
    });
    return;
  }

  socket.destroy();
});

// Both halves of the fleet link, started once the WebSocket servers above
// exist. Each is a no-op without its config file.
loadFleetLinks();
reconcileFleetLinkAgent('startup');
// Registered AFTER the fleet.yaml handler above, and the order is the point:
// a reload re-reads fleet.yaml first, so the cross-check below runs against
// the registry the fleet is actually about to use rather than the last one.
// The agent reconcile is here too so a node the pair command just wrote a
// credential for opens its link on that command's own reload, with no restart
// (#316): before this, the reload re-read only the aggregator-side registry.
process.on('SIGHUP', () => {
  console.log('[fleet-link] SIGHUP received, reloading fleet-links.json and reconciling the link');
  loadFleetLinks();
  reconcileFleetLinkAgent('reload');
});

httpServer.listen(PORT, HOST, () => {
  console.log(`Aperire dashboard on http://${HOST}:${PORT}/ (bridge: ${RIPPLED_URL})`);
  // MED-07. Bound off-loopback, the /ingest WebSocket is reachable from the
  // LAN and carries the relay bearer token and telemetry in cleartext unless
  // something terminates TLS in front of it. Say so every time, whether or not
  // any relay token is configured and whether or not the override is on: the
  // fact an operator needs in the journal is that the port is off-box. The
  // loopback default returns null and stays silent.
  const startupWarning = startupIngestWarning({ bindHost: HOST, allowPlaintext: INGEST_ALLOW_PLAINTEXT });
  if (startupWarning) console.warn(startupWarning);
});
