/**
 * What the dashboard says to the root broker, and how it reads the answer —
 * ADR 0019 phase 3, §3.5.
 *
 * The broker is `scripts/aperire-fleet-broker.sh`, installed at
 * `/usr/local/sbin/aperire-fleet-broker` and reached through a
 * systemd socket the dashboard account may open. The dashboard cannot sudo
 * (NoNewPrivileges, empty capability set), so this is the same shape as the
 * model-key sealer, the trust sync and the updater: one verb per connection,
 * the payload on stdin, the answer on one stream with `exit=<code>` last
 * because an exit code does not cross a socket.
 *
 * TWO ENCODING RULES, one per direction, and the asymmetry is deliberate.
 *
 *   out  every value is percent-encoded outside `[A-Za-z0-9._:/-]`, so a
 *        token, a URL or a node key cannot forge a line boundary. What goes
 *        out carries strings a NODE chose, and a node is untrusted input.
 *   in   values are read verbatim to the end of the line. What comes back
 *        carries only values the broker itself produced, and prose an
 *        operator reads (a refusal's detail has spaces in it).
 *
 * WHAT THE PAYLOAD DOES NOT CARRY, and this is the line the security review
 * turns on: no path, no port and no source. The broker derives the token
 * paths from the label inside one fixed directory, and picks the ports from
 * its own pool. So a compromised dashboard calling `approve` can append one
 * row pinned to a node key and write two token files whose names it does not
 * choose — it cannot name a path, cannot change an existing row, cannot
 * remove one and cannot widen a mode.
 *
 * Phase 4 adds three model verbs and narrows that last clause rather than
 * widening the grant. `model-store-head` DOES read a descriptor back, minus
 * the key, because the page has to be able to say whether a node paired now
 * would inherit a model at all. What stays true, and is the claim the
 * security review turns on, is that no verb returns the key.
 *
 * And no credential. The dashboard mints it with randomBytes(32) and sends
 * only its SHA-256: the broker has no reason to hold the plaintext, and a
 * secret that does not cross a boundary cannot leak at it.
 */

import { lstatSync } from 'node:fs';
import type { FleetModelStoreHead } from './fleet-model-record.js';
import { isFleetArmPubkey } from '../types/fleet-link-contract.js';
import { SEALER_NO_REPORT } from './model-seal.js';

/** The socket the grant installs. Named here, beside the payload it takes. */
export const FLEET_BROKER_SOCKET = '/run/aperire/fleet-broker.sock';

/** Long enough for three candidate files, two `tsx` runs and a reload;
 *  shorter than the unit's own RuntimeMaxSec, which is the outer bound. */
export const FLEET_BROKER_TIMEOUT_MS = 45_000;

/**
 * A model push is a different animal and gets its own bound.
 *
 * The far node's own worst case is about 213 s: its sealer is bounded at
 * 180 s and the model read-back after it is up to five tries with a 5 s probe
 * and 2 s between them. 270 s clears that with slack for the hop, and sits
 * under the socket unit's RuntimeMaxSec of 300.
 *
 * Kept apart from the 45 s constant on purpose. One number for both would
 * mean an approval waiting four and a half minutes to report a broker that
 * is not there, or a push cut off at forty-five seconds and reported as no
 * answer when the node had in fact sealed.
 */
export const FLEET_BROKER_PUSH_TIMEOUT_MS = 270_000;

/**
 * The credential name the store is sealed under, declared once on this side
 * and once in the broker.
 *
 * `systemd-creds decrypt` refuses a name that does not match, so these two
 * declarations are a real coupling: change one and the aggregator stops being
 * able to open its own store. It is here rather than in a route so there is
 * one place to read it from.
 */
export const FLEET_MODEL_CREDENTIAL_NAME = 'aperire-fleet-model';

/** Anything outside this set is percent-encoded on the way out. No space, no
 *  newline, no `%` — so an encoded value decodes to exactly one value. */
const SAFE = /^[A-Za-z0-9._:/-]$/;

export function encodeBrokerValue(raw: string): string {
  let out = '';
  for (const byte of Buffer.from(raw, 'utf8')) {
    const ch = String.fromCharCode(byte);
    out += SAFE.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

export interface BrokerApproveInput {
  label: string;
  pubkey_node: string;
  /** Null when this fleet does not know where that node's dashboard is
   *  (#339). The field is then left OUT of the payload rather than sent
   *  empty: the broker's rule is that a value it is given has to be a
   *  dashboard address, and an empty one is not a value. */
  dashboard_url: string | null;
  /** The fleet role for the appended row. 'node' is the only value pairing
   *  writes: an aggregator does not join itself. */
  role: 'node';
  advisor: boolean;
  /** SHA-256 hex of the credential the DASHBOARD minted. The plaintext stays
   *  on this side and goes down the already-pinned pairing socket. */
  credential_sha256: string;
  read_token: string;
  advisor_token: string | null;
  /** #620: the operator's passkey approval of the one explicit decision the
   *  broker will not make on its own -- converting a row this fleet already
   *  holds under `label` from a tunnel to a link, in place. Left out of the
   *  payload (never sent as `0`) on every ordinary approval, so a broker
   *  that predates this field reads exactly the payload it always has. The
   *  broker re-derives which row that is from `label` and `pubkey_node`
   *  against its own fleet.yaml; this flag only says the decision was made. */
  convert_tunnel?: true;
  /** #741 review, L2: the fleet arm public key the signed welcome carried,
   *  which the operator's pasted fingerprint covered. The broker compares it
   *  with the key on disk BEFORE it writes anything and refuses
   *  `arm_key_changed` on a difference, so a rotation between the approval
   *  and the registration leaves no row and no token file behind. */
  fleet_arm_pubkey: string;
}

export function brokerApprovePayload(input: BrokerApproveInput): string {
  const lines = [
    'approve',
    `label=${encodeBrokerValue(input.label)}`,
    `pubkey_node=${encodeBrokerValue(input.pubkey_node)}`,
    `role=${encodeBrokerValue(input.role)}`,
    `advisor=${input.advisor ? '1' : '0'}`,
    `credential_sha256=${encodeBrokerValue(input.credential_sha256)}`,
    `read_token=${encodeBrokerValue(input.read_token)}`,
    `fleet_arm_pubkey=${encodeBrokerValue(input.fleet_arm_pubkey)}`,
  ];
  if (input.convert_tunnel) lines.push('convert_tunnel=1');
  // Absent, not empty, for the same reason the advisor token below is: the
  // broker takes a dashboard_url it is given as a dashboard address, and
  // there is no spelling of "I do not know" that is also an address (#339).
  if (input.dashboard_url) lines.push(`dashboard_url=${encodeBrokerValue(input.dashboard_url)}`);
  // Absent, not empty: the row's advisor_origin and advisor_token_path are
  // written together or not at all, because either half alone fails the whole
  // fleet.yaml closed (fleet-registry.ts).
  if (input.advisor_token) lines.push(`advisor_token=${encodeBrokerValue(input.advisor_token)}`);
  lines.push('end', '');
  return lines.join('\n');
}

export function brokerRevokePayload(label: string): string {
  return ['revoke', `label=${encodeBrokerValue(label)}`, 'end', ''].join('\n');
}

/** Accept new key (#422, #859). `was` is the key the operator was shown as
 *  pinned: the broker refuses `pin_changed` if the row pins anything else by
 *  now, so one approval cannot be spent on a different change. */
export function brokerRepinPayload(label: string, was: string, now: string): string {
  return [
    'repin',
    `label=${encodeBrokerValue(label)}`,
    `was_pubkey_node=${encodeBrokerValue(was)}`,
    `pubkey_node=${encodeBrokerValue(now)}`,
    'end', '',
  ].join('\n');
}

export type BrokerRepinOutcome =
  | { ok: true; advisor_peer_repinned: boolean; reloaded: boolean }
  | { ok: false; error: string; detail: string };

/** What one `repin` meant. Every refusal is fatal: the verb writes fleet.yaml
 *  and the Advisor's fleet.json together or not at all. */
export function brokerRepinOutcome(answer: BrokerAnswer, installDir: string): BrokerRepinOutcome {
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  const said = (answer.facts.error ?? '').trim();
  if (answer.code === null) {
    return {
      ok: false, error: 'no_answer',
      detail: 'the root broker did not print its exit line, so this host cannot tell whether the row was '
        + 're-pinned. Read the row again on the next refresh before pressing Accept new key again.',
    };
  }
  if (said === 'unknown_verb') {
    return {
      ok: false, error: 'unknown_verb',
      detail: `the root service on this host has no repin verb, so it cannot accept a new key. Run the full grant installer here: ${grantInstallSentence(installDir)}`,
    };
  }
  if (answer.code !== 0) {
    return {
      ok: false,
      error: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      detail: detail || 'the root broker refused to re-pin that row and gave no reason.',
    };
  }
  return {
    ok: true,
    advisor_peer_repinned: answer.facts.advisor_peer_repinned === '1',
    reloaded: answer.facts.reloaded === '1',
  };
}

// ── The fleet model store (ADR 0019 phase 4, #168) ───────────────────────

export interface BrokerModelStoreInput {
  baseUrl: string;
  shape: string;
  model: string;
  credentialName: string;
  /** Computed on THIS side with sealKeyHint() and stored verbatim. There are
   *  already two declarations of that string (here and the node sealer's
   *  bash); a third in the broker would be the one that drifts, and a hint
   *  that differs by one character reads as "that node is behind" forever
   *  with no other symptom. A wrong hint from a compromised dashboard is a
   *  wrong verdict on a page, not a leaked key. */
  keyHint: string;
  /** The operator who touched the passkey. Recorded, never checked here. */
  sealedBy: string;
  /** The secret. This is the only payload builder in this file that takes
   *  one, and the value never comes back out of any verb. */
  key: string;
}

export function brokerModelStorePutPayload(input: BrokerModelStoreInput): string {
  return [
    'model-store-put',
    `base_url=${encodeBrokerValue(input.baseUrl)}`,
    `shape=${encodeBrokerValue(input.shape)}`,
    `model=${encodeBrokerValue(input.model)}`,
    `credential_name=${encodeBrokerValue(input.credentialName)}`,
    `key_hint=${encodeBrokerValue(input.keyHint)}`,
    `sealed_by=${encodeBrokerValue(input.sealedBy)}`,
    `key=${encodeBrokerValue(input.key)}`,
    'end', '',
  ].join('\n');
}

/** What an operator does about `arm_closed`, in one sentence, built once.
 *
 *  The window is root's on THIS host and nothing the dashboard can open: that
 *  is what stops a compromised dashboard moving the key on its own schedule.
 *  Every surface that meets the refusal prints this, so the instruction is
 *  the same on the Pending row, on the catch-up and in an audit detail.
 *
 *  `installDir` is THIS host's own directory, the one the command below runs
 *  from, and there is no placeholder branch: a sentence that printed
 *  `<install-dir>` literally failed as typed the moment it was copied
 *  (#629, the #611/#613 class). Both callers already hold the real value --
 *  server.ts's INSTALL_ROOT and this_dashboard.install_dir resolve to the
 *  same path -- so there is nothing to fall back to. */
/** A path an operator can paste straight into a shell, quoted only when it
 *  needs to be: an install directory is ordinarily a plain path with none of
 *  the characters below, and quoting one unconditionally would print a
 *  command that read differently from every other one on this page for no
 *  reason. A path holding a space, a quote, or anything else outside this
 *  set is single-quoted, with an embedded `'` closed, escaped and reopened
 *  the POSIX way (`'\''`), because it is still a path an operator's own
 *  install (their home directory's name, most often) can produce. */
export function shellSafe(path: string): string {
  if (/^[A-Za-z0-9_/.~+@:=-]+$/.test(path)) return path;
  return `'${path.replace(/'/g, "'\\''")}'`;
}

/** Where the fleet broker grant installs the arm program, root-owned, on
 *  root's PATH (#741). server.ts stats this path; nothing here reads it. */
export const FLEET_ARM_PROGRAM = '/usr/local/sbin/aperire-fleet-arm';

/** The installed name, as an operator types it (#812). A constant, the same
 *  words on every aggregator, and never a path a page served by the
 *  dashboard's own account chose. */
export const FLEET_ARM_COMMAND = 'sudo aperire-fleet-arm';

/** The update an operator runs once when this aggregator's grant is older
 *  than the arm program (#812). The update places `aperire-fleet-arm` root-
 *  owned in /usr/local/sbin wherever the fleet broker already is
 *  (refresh_root_programs in get-aperire.sh). `--force` because a host already
 *  on the current release is otherwise told "nothing was touched" before that
 *  step runs (update_stamp_gate), and the program would still not be there.
 *  A constant, like the arm program's own name: a page the dashboard account
 *  serves never chooses it. */
export const FLEET_UPDATE_COMMAND = 'curl -fsSL https://get.aperire.one | bash -s -- --update --force';

/** A root program at its fixed name: a regular file (not a link), owned by
 *  `uid` (root's, 0), and executable. The same test aperire-fleet-broker.sh's
 *  arm_program_installed makes, so the page and the broker never disagree about
 *  "installed" (#812). A stat and nothing more: /usr stays readable under
 *  ProtectSystem=strict, and any failure reads as not installed. */
export function rootProgramInstalled(path: string, uid = 0): boolean {
  try {
    const st = lstatSync(path);
    return st.isFile() && st.uid === uid && (st.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

/** The fixed path of the fleet broker, which the update's refresh of the arm
 *  program is gated on: no broker here, nothing for the update to place. */
export const FLEET_BROKER_PROGRAM = '/usr/local/sbin/aperire-fleet-broker';

/** The line that arms, with no flags (#812). Where the grant put the root-
 *  owned program on root's PATH it is the installed name. Where it did not (a
 *  grant older than #741 runs a broker and has no installed name) it is the
 *  update first, then a check that the program is there now, then the
 *  installed name, as one line that ends in the bare program, so a caller can
 *  add `--self-only` or `--node <label>` either way. The check is what stops
 *  a declined prompt, a failed download or a host the update did not give the
 *  program from running an arm that says "command not found".
 *  It is never a path into this install's tree: root would run a file the
 *  dashboard's own account can write. `installed` is an observation (server.ts
 *  stats FLEET_ARM_PROGRAM), not a guess from the broker answering. */
export function fleetArmCommand(installed: boolean): string {
  return installed ? FLEET_ARM_COMMAND
    : `${FLEET_UPDATE_COMMAND} && test -x ${FLEET_ARM_PROGRAM} && ${FLEET_ARM_COMMAND}`;
}

/** The clause that says why the line starts with the update, or nothing where
 *  the program is installed. Placed in the sentences that carry the line. */
export function fleetArmLeadIn(installed: boolean): string {
  return installed ? '' : ' (this aggregator\'s grant predates the arm program, so the line updates first)';
}

/** Just the command, no lead-in prose (#635): the one thing an operator
 *  actually runs, so a caller building its own sentence around it (or a page
 *  rendering it in a copy box, never inline in running text) does not have
 *  to parse it back out of armSelfSentence()'s own words. */
export function armSelfCommand(installed = false): string {
  return `${fleetArmCommand(installed)} --self-only`;
}

/** #741: the one command that prints this aggregator's pairing fingerprint:
 *  root's, read-only, installed root-owned at a fixed name on root's PATH by
 *  the fleet broker grant. A constant, not built from anything this process
 *  knows: the node's prompt, the install summary and the docs name the same
 *  words, so the page repeats them and is never where the operator gets a
 *  path from. */
export const PAIRING_FINGERPRINT_COMMAND = `${FLEET_ARM_COMMAND} --fingerprint`;

export function armSelfSentence(installed = false): string {
  return `Open one on this aggregator${fleetArmLeadIn(installed)}: ${armSelfCommand(installed)}`;
}

export function brokerModelStoreHeadPayload(): string {
  return ['model-store-head', 'end', ''].join('\n');
}

/** Who approved one push, carried into the job the node verifies.
 *
 *  Not read out of the store. The store names whoever sealed the fleet model,
 *  which may have been months ago and somebody else; the node's ledger has to
 *  name the operator whose passkey authorised the key reaching IT. Both
 *  fields are inside the signature, and a node refuses a job carrying either
 *  of them empty (`checkSealJob`, gate 4). */
export interface BrokerPushGrant {
  /** The approving operator, from the verified grant and never from a body. */
  grantedBy: string;
  /** The passkey that approved it, base64url. */
  credentialId: string;
}

/** One node per call. 'self' is this host, and everything else is a label
 *  the broker resolves in its own root-owned record. */
export function brokerModelPushPayload(label: string, grant: BrokerPushGrant): string {
  return [
    'model-push',
    `label=${encodeBrokerValue(label)}`,
    `granted_by=${encodeBrokerValue(grant.grantedBy)}`,
    `credential_id=${encodeBrokerValue(grant.credentialId)}`,
    'end', '',
  ].join('\n');
}

/**
 * What one `model-store-put` meant.
 *
 * Its failure is never fatal to the seal that triggered it: the store is
 * what a LATER push sends, and a seal that reached every node has already
 * done the thing the operator asked for.
 */
export type BrokerStoreOutcome =
  | { ok: true; sealed_at: string }
  | { ok: false; error: string; detail: string };

export function brokerStoreOutcome(answer: BrokerAnswer, installDir: string): BrokerStoreOutcome {
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  if (answer.code === null) {
    return {
      ok: false, error: 'no_answer',
      detail: 'the root broker did not print its exit line, so this host cannot tell whether the '
        + 'fleet model was sealed. Check whether a node is holding the broker socket, and read '
        + 'the sealed-copy line on Settings for what it actually holds.',
    };
  }
  if (answer.code !== 0 || answer.facts.stored !== '1') {
    const said = (answer.facts.error ?? '').trim();
    return {
      ok: false,
      error: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      // The verb this host does not have is its OWN state, in the same words
      // the head read uses for it (#443). The broker's prose for an unknown
      // verb names the verb, which tells an operator nothing they can act on.
      detail: said === 'unknown_verb'
        ? brokerPredatesStoreDetail(installDir)
        : (detail || 'the root broker did not seal the fleet model, and gave no reason.'),
    };
  }
  return { ok: true, sealed_at: (answer.facts.sealed_at ?? '').trim() };
}

/**
 * What one `model-store-head` meant, in FIVE states and not two.
 *
 * The design's page line has two ("a sealed copy is held" / "there is none"),
 * and the sentence for the second one tells an operator to seal the fleet
 * model from here, with the key. So every way of NOT getting an answer has to
 * be kept apart from `none`, or a busy socket renders as an instruction to
 * re-paste a live provider key over a store that was fine.
 *
 *   held       the broker opened it and reported the descriptor.
 *   none       the broker looked and there is no store. A positive answer.
 *   unreadable there IS one and this host could not open it. Usually a
 *              rebuilt host: the blob is sealed to the machine.
 *   predates   this aggregator's broker has no such verb, so its install is
 *              older than this feature.
 *   unread     no answer at all: the socket is busy, or absent, or the run
 *              was cut off. Says nothing about what the store holds.
 */
export type BrokerStoreHeadOutcome =
  | { state: 'held'; head: FleetModelStoreHead }
  | { state: 'none' }
  | { state: 'unreadable'; reason: string; detail: string }
  | { state: 'predates'; detail: string }
  | { state: 'unread'; reason: string; detail: string };

/** The sentence for a socket somebody else is holding. Named here so the
 *  page and the catchup route say the same thing, and so neither renders it
 *  as a broker failure: a push runs for minutes behind MaxConnections=1, and
 *  "busy" is an ordinary state during one.
 *
 *  A CLAUSE, not a sentence: it opens in lowercase and closes with a full
 *  stop, so it reads after a colon or a comma. Set after a full stop it reads
 *  as a sentence that began in lowercase (#1147), so the page capitalises it
 *  at the join (settings.html's `asSentence`) and the spelling here stays
 *  put: `brokerOutcomeUnknown` matches this exact string, server.ts throws
 *  it, and `brokerUnknownDetail` opens with it. */
export const BROKER_BUSY_DETAIL =
  'the fleet broker is busy finishing a model push; try again in a moment.';

/**
 * Did this broker call fail in a way that leaves the OUTCOME UNKNOWN?
 *
 * askWithCeiling drops the WAIT, not the call: past the ceiling the queued
 * connection is still in the chain and still runs, and its answer is thrown
 * away. That is the honest thing to do with a socket call that may already
 * have changed something, and it makes the caller's sentence a lie if the
 * caller says "nothing was changed" (review finding, 2026-09-27). The write
 * can land minutes later, on a page that has already told an operator it
 * did not.
 *
 * Recognised by the sentence rather than by an error class, because the
 * sentence is this module's own exported constant and server.ts throws
 * exactly it: there is no second spelling to drift from. Every other way a
 * broker call can throw (the socket is not there, the connection is
 * refused, it closed mid-call) really did not get as far as doing anything,
 * and those keep saying so.
 */
export function brokerOutcomeUnknown(err: unknown): boolean {
  return err instanceof Error && err.message === BROKER_BUSY_DETAIL;
}

/**
 * What to say when the outcome is unknown. Never "nothing was changed", and
 * never "it worked": it names what is not known and where the answer will
 * be, which is the row itself on the next refresh.
 */
export function brokerUnknownDetail(act: string): string {
  return `${BROKER_BUSY_DETAIL} This host stopped waiting for it, which is not the same as it not `
    + `happening: the ${act} may still be carried out behind that queue. Nothing here can say which, `
    + 'so read the row again on the next refresh rather than pressing this a second time.';
}

/**
 * The sentence for a root service that has never heard of the sealed store
 * (#443).
 *
 * Its own state, and not "there is no sealed copy": on the lab aggregator the first
 * real fleet seal wrote every node's key, answered `unknown_verb` to the
 * store write, and the page read as clean. Both halves of the store, the
 * write and the read, say this when the verb is not there, because an
 * operator meeting it has one thing to do and it is not re-pasting a key.
 *
 * The installer name is spelled out, and so is the trap the lab fell into:
 * `--refresh-nodes` rebuilds root's node list and does NOT replace the
 * program, so a broker behind the tree stays behind it.
 */
/** THIS host's real install directory, always: both callers hold it
 *  (server.ts's INSTALL_ROOT, settings-api.ts's installDirOf(deps)), so
 *  there is no placeholder branch — the same rule armSelfSentence follows
 *  above, and the one #629 fixed everywhere else this sentence used to
 *  print `<install-dir>` literally and fail as typed the moment it was
 *  copied. */
export function brokerPredatesStoreDetail(installDir: string): string {
  return 'the root service on this host predates the sealed store, so it has no verb for one. Run the full '
    + `grant installer here: ${grantStepCommand(installDir)} `
    + '(not --refresh-nodes, which refreshes the node list and leaves the program as it was).';
}

/** The one root form of the broker grant's installer (#929): the bootstrap's
 *  `--run fleet-broker-grant` step, which holds its argument to a whitelist
 *  and has root run the release's checked copy of the installer, never the
 *  one in the install (ADR 0024). `flag` is the installer's own argument
 *  (`--refresh-nodes`, `--new-fleet-keys`, `--remove`), or none. */
export function grantStepCommand(installDir: string, flag = ''): string {
  return `curl -fsSL https://get.aperire.one | bash -s -- --dir ${shellSafe(installDir)} --run fleet-broker-grant`
    + (flag ? ` ${flag}` : '');
}

/** Same command as brokerPredatesStoreDetail's, spelled out on its own: the
 *  root service predates the grant entirely (no revoke verb, no store verb,
 *  nothing this phase added), and callers of that outcome need the sentence
 *  without the store-specific framing around it. */
export function grantInstallSentence(installDir: string): string {
  return grantStepCommand(installDir);
}

/** The command that puts a lost fleet key back (#851): the backup set's
 *  restore. `<backup set>` is the one thing the page cannot know. */
export function restoreSentence(installDir: string): string {
  return `curl -fsSL https://get.aperire.one | bash -s -- --dir ${shellSafe(installDir)} --restore --from <backup set>`;
}

/** The sentence for a fleet trust key missing on an aggregator whose own
 *  registry already names peers (#851 review L4a). Built here, beside the
 *  arm key's, so the two read alike. */
export function trustKeyLostDetail(installDir: string, paired: readonly string[]): string {
  const names = paired.filter((l) => /^[a-z0-9-]{1,32}$/.test(l)).slice(0, 64).join(', ') || 'in its registry';
  return `This aggregator's fleet trust key is missing, and it already has paired nodes (${names}). They trust `
    + 'the key that is gone, so a new one would cut every one of them off, and the grant installer will not make '
    + `one. Put it back from your backup set: ${restoreSentence(installDir)}. With no backup, make new keys on `
    + `purpose, then pair each node again: ${grantInstallSentence(installDir)} --new-fleet-keys. If a node named `
    + 'here is this host, mark its fleet.yaml row role: aggregator.';
}

/**
 * The one sentence for `fleet_arm_key_lost` (#851), from either arm-key
 * verb: this aggregator's fleet arm key is gone and it already has paired
 * nodes, so root made no new one. The command offered is the restore, never
 * the re-key: `--new-fleet-keys` is named in the sentence as the deliberate
 * alternative, and only root at a keyboard can run it. Built here from the
 * broker's labels rather than passed through from its prose, the same way
 * every other broker reason reaches the page.
 */
export function armKeyLostOutcome(answer: BrokerAnswer, installDir: string): { ok: false; error: 'fleet_arm_key_lost'; detail: string; command: string } {
  const paired = (answer.facts.fleet_arm_key_paired ?? '').split(',')
    .map((l) => l.trim()).filter((l) => /^[a-z0-9-]{1,32}$/.test(l)).slice(0, 64);
  const command = restoreSentence(installDir);
  // No names: root refused on its own record that this host has had a key
  // (#851 review L1), not on any node the registries still list.
  const why = paired.length
    ? `it already has paired nodes (${paired.join(', ')}). They trust`
    : 'it has had one before, so every node paired to it trusts';
  const selfRow = paired.length
    ? ' If a node named here is this host, mark its fleet.yaml row role: aggregator.' : '';
  return {
    ok: false, error: 'fleet_arm_key_lost', command,
    detail: `This aggregator's fleet arm key is missing, and ${why} the key that is gone, so a new one would `
      + 'cut every one of them off, and none was made. Put the key back from your backup set: '
      + `${command}. With no backup, make new keys on purpose, then pair each node again: `
      + `${grantInstallSentence(installDir)} --new-fleet-keys.${selfRow}`,
  };
}

export function brokerStoreHeadOutcome(answer: BrokerAnswer, installDir: string): BrokerStoreHeadOutcome {
  if (answer.code === null) {
    return { state: 'unread', reason: 'no_answer', detail: BROKER_BUSY_DETAIL };
  }
  const said = (answer.facts.error ?? '').trim();
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  if (said === 'unknown_verb') {
    return {
      state: 'predates',
      detail: brokerPredatesStoreDetail(installDir),
    };
  }
  if (answer.code !== 0) {
    return {
      state: 'unreadable',
      reason: said || 'refused',
      detail: detail || 'the root broker refused to read the sealed fleet model and gave no reason.',
    };
  }
  if (answer.facts.stored !== '1') return { state: 'none' };
  const f = (name: string): string => (answer.facts[name] ?? '').trim();
  if (!f('base_url') || !f('model')) {
    // A success with no descriptor in it is this host failing, not a store
    // that is missing: saying `none` here would tell an operator to seal
    // again over a store that may be perfectly good.
    return {
      state: 'unreadable', reason: 'empty_head',
      detail: 'the root broker reported a sealed fleet model without saying what is in it.',
    };
  }
  return {
    state: 'held',
    head: {
      base_url: f('base_url'),
      shape: f('shape'),
      model: f('model'),
      credential_name: f('credential_name'),
      key_hint: f('key_hint'),
      sealed_at: f('sealed_at'),
      sealed_by: f('sealed_by'),
      // A broker older than #711 says neither, and it only ever sealed.
      method: f('method') || 'sealed',
      host_method: f('host_method') || f('method') || 'sealed',
      // Only a path this broker said, and only an absolute one: the page
      // prints it inside an rm command.
      other_form_at: f('other_form') === 'present' && /^\/[A-Za-z0-9._/-]+$/.test(f('other_form_at'))
        ? f('other_form_at') : '',
    },
  };
}

/**
 * What one `model-push` meant.
 *
 * `state` is the node's own, and the three values are the three the seal path
 * already keeps apart (lib/fleet-seal.ts): `sealed` is done, `refused` is
 * that node's decision reached and answered, `unreachable` is this side
 * failing to get an answer at all. The operator's next action differs for
 * each, which is why they are not collapsed.
 */
export type BrokerPushOutcome = {
  /** Did that node take the model? Only ever true on `sealed`. */
  pushed: boolean;
  state: 'sealed' | 'refused' | 'unreachable';
  reason: string;
  detail: string;
  /** Three-valued, as everywhere else: the node's own word, or null when it
   *  had not answered about its model yet. */
  model_configured: boolean | null;
};

export function brokerPushOutcome(answer: BrokerAnswer): BrokerPushOutcome {
  const said = (answer.facts.error ?? '').trim();
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  if (answer.code === null) {
    // Not "that node refused". A no-answer from the socket says nothing about
    // the node, and a push whose answer was cut off may have sealed (#312).
    return {
      pushed: false, state: 'unreachable', reason: BROKER_NO_ANSWER,
      detail: (answer.timed_out
        ? 'this host stopped waiting for the root broker, so it cannot tell whether that node took the model.'
        : 'the root broker did not print its exit line, so this host cannot tell whether that node took the model.')
        + ' Read that node’s own row on the next refresh.',
      model_configured: null,
    };
  }
  if (answer.code !== 0) {
    return {
      pushed: false, state: 'refused',
      reason: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      detail: detail || 'the root broker refused to push the fleet model and gave no reason.',
      model_configured: null,
    };
  }
  const raw = (answer.facts.state ?? '').trim();
  const state: BrokerPushOutcome['state'] = raw === 'sealed' || raw === 'refused' || raw === 'unreachable'
    ? raw
    // A value this build does not know is NOT read as one it does (#268).
    // "That node did not answer me" is the honest reading of an answer this
    // reader cannot interpret.
    : 'unreachable';
  const mc = (answer.facts.model_configured ?? '').trim();
  return {
    pushed: state === 'sealed' && answer.facts.pushed === '1',
    state,
    reason: (answer.facts.reason ?? '').trim() || said || state,
    detail: (answer.facts.detail ?? '').trim() || detail || 'that node gave no reason.',
    model_configured: mc === '1' ? true : mc === '0' ? false : null,
  };
}

/**
 * One broker call at a time, in this process.
 *
 * The socket is `Accept=yes` with `MaxConnections=1`, and that is deliberate:
 * it is what stops two model pushes racing the root-owned node record. A lock
 * inside the broker would be a second mechanism for a property the socket
 * already has.
 *
 * What it costs is here. A push can run for minutes, and systemd does NOT
 * queue past the cap: it accepts the second connection and drops it at once
 * ("Too many incoming connections (1), dropping connection" in the journal,
 * read on a real host 2026-09-15), so the second caller gets a clean close
 * with no bytes. Every parser in this file reads that as `code === null`,
 * which is the indeterminate state, and an approval answered "this host
 * cannot tell whether the node was registered" because an unrelated catchup
 * was running would be a bad page for no reason.
 *
 * So this process takes its own turns. It does not make the socket safe
 * against another process on the same host; it makes THIS process stop
 * competing with itself, which is where every call comes from.
 */
export function serializeBrokerCalls<T, A extends unknown[]>(
  call: (...args: A) => Promise<T>,
): SerializedBrokerCall<T, A> {
  // A chain, not a queue with a bound: the callers are a Settings approval,
  // a pairing follow-on and a catchup, all of which an operator started, and
  // there is no path here that can start an unbounded number of them.
  let tail: Promise<unknown> = Promise.resolve();
  let waiting = 0;
  const serialized = (...args: A): Promise<T> => {
    waiting += 1;
    // The count drops in a `finally` INSIDE the call rather than on the chain
    // behind it, so a caller awaiting this promise sees the flag already
    // clear. On the chain it would clear one microtask late, and the one
    // thing this flag has to be is not stale.
    const run = async (): Promise<T> => {
      try { return await call(...args); } finally { waiting -= 1; }
    };
    const next = tail.then(run);
    // Settled, never rejected onward: one call that throws must not poison
    // every call after it.
    tail = next.catch(() => undefined);
    return next;
  };
  // Whether joining the chain would mean WAITING, for the one caller that
  // must not. A push holds the socket for minutes, and the overview's store
  // head is polled every ten seconds by an open page: queueing it would hang
  // every poll behind the push and leave a hundred calls to fire at once
  // when it finished. That caller asks this first and reports `unread`,
  // which is the same answer it would get from the dropped connection
  // MaxConnections=1 would hand it anyway.
  serialized.busy = (): boolean => waiting > 0;
  return serialized;
}

export type SerializedBrokerCall<T, A extends unknown[]> =
  ((...args: A) => Promise<T>) & { busy(): boolean };

/** How long a caller with an operator waiting on it will hold a place in the
 *  queue. A catch-up can be 64 nodes at up to 270 s each, which is hours, and
 *  a pairing approval behind one would sit on an open request until something
 *  in front of it gave up (security review, finding F6). Two pushes is enough
 *  for the ordinary overlap and short enough that a browser is still there. */
export const BROKER_QUEUE_MAX_MS = 600_000;

/**
 * One call, but not at any price.
 *
 * Resolves to `null` when the wait ran past the ceiling, so the caller can
 * say "the broker is busy" instead of holding a request open behind work that
 * was never going to finish inside a human's patience. The call itself is not
 * cancelled: it is still in the chain and still runs, and its answer is
 * dropped, which is the honest thing to do with a socket call that may
 * already have changed something.
 */
export async function askWithCeiling<T>(
  call: () => Promise<T>, ceilingMs = BROKER_QUEUE_MAX_MS,
): Promise<T | null> {
  let timer: NodeJS.Timeout | undefined;
  const ceiling = new Promise<null>((resolve) => {
    // Cleared in the `finally` below the moment the call answers, so it holds
    // the loop only while a call this process is waiting on is in flight.
    // NOT unref'd: an unref'd ceiling is one the loop can drain out from
    // under, which is the same as no ceiling on a quiet process.
    timer = setTimeout(() => resolve(null), ceilingMs);
  });
  try {
    return await Promise.race([call(), ceiling]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export interface BrokerAnswer {
  facts: Record<string, string>;
  /** Everything that was not `name=value`: the broker talking to a human. */
  lines: string[];
  /** The `exit=` last line, or null when the program never wrote one. */
  code: number | null;
  /** Set with a null `code` when this host stopped waiting rather than the
   *  broker closing the connection (#848). The two are different facts and
   *  say different sentences. */
  timed_out?: boolean;
}

/**
 * Read one answer apart.
 *
 * The field pattern allows digits inside a name, which is #293's lesson:
 * `[a-z_]+` matched none of `installed_sha256`, `published_sha256` or
 * `stamp_sha256`, so three of the updater's own facts were silently read as
 * prose and no consumer ever saw them.
 */
/**
 * The broker's answer, split into facts, prose and an exit code.
 *
 * `socketExitCode` is the code the SOCKET layer already read off the stream.
 * It is authoritative and, when given, this function does not re-derive one
 * (#311).
 *
 * The reason it exists: `askSocketProgram` reads the raw socket through
 * `splitSealerStream`, which CONSUMES the `exit=` line and hands back the
 * code separately as `ProgramAnswer.code`. Passing that answer's `.stdout`
 * back through here to pull the facts out is a SECOND parse of a stream the
 * first already stripped, and the `exit=` line is no longer in it. Without
 * the code passed through, every real approve parsed to `code: null` and was
 * read as "the broker said nothing", while the broker had in fact written
 * the whole answer and registered the node. The aggregator was left with the
 * node and the node was left without its credential. The standalone client
 * the lab used to prove the broker did not double-parse, which is why it saw
 * the full answer and this path did not.
 *
 * A direct caller (a unit test of this parser) passes nothing and the
 * `exit=` line in its own text is read as before.
 */
export function parseBrokerAnswer(raw: string, socketExitCode?: number | null): BrokerAnswer {
  const facts: Record<string, string> = {};
  const lines: string[] = [];
  let code: number | null = socketExitCode ?? null;
  for (const line of raw.split('\n')) {
    const m = /^([a-z][a-z0-9_]*)=(.*)$/.exec(line);
    if (!m) {
      if (line.trim() !== '') lines.push(line.trim());
      continue;
    }
    if (m[1] === 'exit') {
      // Only when no authoritative code was passed. Through askSocketProgram
      // this line was already consumed one layer down (#311); a direct
      // caller still gets it read here. Only a plain number counts, or
      // reading it would invent an outcome.
      if (socketExitCode == null && /^\d+$/.test(m[2].trim())) code = Number(m[2].trim());
      continue;
    }
    facts[m[1]] = m[2].trim();
  }
  return { facts, lines, code };
}

/**
 * The broker's answer off the socket layer, apart (#848).
 *
 * Every caller used to write `parseBrokerAnswer(`${a.stdout}\n${a.stderr}`,
 * a.code)`, and that read an empty stream as exit 1. The socket layer makes
 * the 1 up when no `exit=` line arrives (a dropped connection, a kill, a
 * second connection systemd accepted and closed), so the "no answer" branch
 * every parser here carries (`code === null`, #312) never ran on the real
 * path: an arm-key that got nothing back was read as an arm-key that failed,
 * and an approval told the operator `no_fleet_arm_key` for a broker that was
 * merely busy.
 *
 * `reported: false` is the socket layer saying the code is not the program's.
 * It becomes `code: null` here, which is what BrokerAnswer.code has always
 * documented, and the sentence the socket layer added in its place is dropped
 * so the broker's own last line, if it printed one, is the one quoted.
 * An answer built without the flag (a test double, a direct caller) is read
 * as it always was.
 */
export function brokerAnswerOf(
  answer: { code: number; stdout: string; stderr: string; reported?: boolean; timedOut?: boolean },
): BrokerAnswer {
  const text = `${answer.stdout}\n${answer.stderr}`;
  if (answer.reported !== false) return parseBrokerAnswer(text, answer.code);
  // This side stopped waiting: whatever the broker printed was thrown away
  // with the connection, and the one line on hand is this host's own.
  if (answer.timedOut === true) return { facts: {}, lines: [], code: null, timed_out: true };
  const parsed = parseBrokerAnswer(text, null);
  return { ...parsed, lines: parsed.lines.filter((l) => l !== SEALER_NO_REPORT), code: null };
}

/** The reason an arm-key call gets when the broker produced no answer. Its
 *  own word, so it is never mistaken for the arm key being missing. */
export const BROKER_NO_ANSWER = 'broker_no_answer';

/**
 * The sentence for a broker that closed the connection without an exit line.
 *
 * Says what was observed (no exit code, and the last thing it printed, if
 * anything), what that is not (a missing key), and the two ways forward: try
 * again, which arm-key and arm-key-check both allow because neither changes
 * a key that is already there, and the journal for what the broker did.
 */
export function brokerNoAnswerDetail(answer: BrokerAnswer): string {
  const journal = 'If it repeats, read what the broker did on this host: '
    + 'journalctl -u "aperire-fleet-broker@*" -n 50 --no-pager';
  if (answer.timed_out) {
    // Not "closed the connection": this host gave up. The broker may still be
    // at work behind it, which is why a retry waits a moment.
    return 'This host stopped waiting for the fleet broker, so it has no exit code to read. '
      + 'That is a busy or stuck broker, not a missing arm key. Try again in a minute. ' + journal;
  }
  const last = (answer.lines.length ? answer.lines[answer.lines.length - 1] : '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 160);
  return 'The fleet broker closed the connection without finishing, so it gave no exit code. '
    + (last ? `The last thing it printed was "${last}". ` : 'It printed nothing. ')
    + 'That is a busy or dropped broker, not a missing arm key. Try again in a moment. ' + journal;
}

export type BrokerOutcome =
  | {
    ok: true;
    read_port: number;
    advisor_port: number | null;
    token_path: string;
    advisor_token_path: string | null;
    rejoined: boolean;
    /** A rejoin whose hello said there is no Advisor cleared the attachment
     *  this aggregator had kept (#1079). The broker names the label. */
    advisor_lowered: boolean;
    /** The broker's own sentence about the Advisor attachment on a rejoin:
     *  cleared, or left as it was because the row could not be rewritten
     *  safely. It starts with ADVISOR_NOTE_PREFIX. Null when it said none. */
    advisor_note: string | null;
    reloaded: boolean;
    /** HOW it was reloaded: `systemd:<unit>`, `pm2:<process>`, `none`, or
     *  either with `:failed`. A separate fact from `reloaded` on purpose:
     *  that one is a boolean two versions of this reader agree on, and a
     *  third value in it would have been read as "did not reload" by the
     *  reader that predates the pm2 path (#310, and #268's lesson). */
    reload_via: string;
    /** This aggregator's fleet arm public key, plain base64, or null when the
     *  broker could not make or read one. Since #723 an approval makes the
     *  key when there is none, so a node is never paired without one on a
     *  host that can. */
    fleet_arm_pubkey: string | null;
    /** What the broker did about that key, in one word: `made`, `present`,
     *  `made_fleet_had_nodes` (made, while root's record already named other
     *  nodes: the old key was lost), or why there is none (`no_openssl`,
     *  `make_failed`, `unsafe`, `unusable`). Null from a broker that
     *  predates #723 and says nothing. */
    fleet_arm_key: string | null;
    /** With `made_fleet_had_nodes`: the labels that still trust the lost key
     *  and will refuse every arm until they are paired again. */
    fleet_arm_key_orphaned: string[];
    /** #620: set when this approval converted an existing tunnel row to a
     *  link row under the same label, instead of appending a fresh one or
     *  rejoining. `rejoined` is false on a convert: its ports are new and
     *  its row is a different shape than the one it replaced. */
    converted_from: 'tunnel' | null;
    /** #1057: this aggregator's own fleet.yaml row, as the broker reports it.
     *  `missing` when the approval could not write one (the broker's
     *  `self_row missing` fact), the label it wrote when it did, null from a
     *  broker that predates #1045 or had nothing to say. */
    self_row: string | null;
    /** #1057: the sentence the broker prints when `self_row` is `missing`,
     *  naming the row to add by hand. Without it the dashboard holds every
     *  link and nothing on the page says why. Null on any other answer. */
    self_row_note: string | null;
  }
  | { ok: false; error: string; detail: string };

/** Every sentence the broker's SELF_ROW_NOTE can be starts with this. The
 *  note is told apart from the other plain lines of an approval by it, so a
 *  broker reword that drops the prefix fails a unit test that reads the
 *  broker's own text, rather than silently dropping the note again. */
export const SELF_ROW_NOTE_PREFIX = 'fleet.yaml';
const SELF_ROW_NOTE_MAX = 900;
/** The line the broker starts its sentence about a rejoin's Advisor attachment
 *  with (#1079), the same text scripts/aperire-fleet-broker.sh writes. */
export const ADVISOR_NOTE_PREFIX = 'Advisor attachment: ';
const ADVISOR_NOTE_MAX = 600;
const SELF_ROW_NOTE_FALLBACK = 'fleet.yaml has no row for this host, so the dashboard holds every link. '
  + 'Add this host\u2019s own row by hand and reload.';

/**
 * What one answer means.
 *
 * Exit 3 is a REFUSAL and an outcome an operator acts on: a label that is
 * taken, a pin that collides, a pool with nothing free. Exit 0 with a port
 * missing is a failure of this host and not a refusal, because a broker that
 * says yes without saying where is one nobody can act on.
 */
export function brokerOutcome(answer: BrokerAnswer): BrokerOutcome {
  const said = (answer.facts.error ?? '').trim();
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  if (answer.code === null) {
    // A no-answer cannot assert the negative (#312). The broker prints its
    // exit line last, so a stream that ends without one means it did not
    // reach its own end: it may have written everything and been cut off
    // (RuntimeMaxSec, a kill), or it may never have run. Either is possible,
    // so this says what it does NOT know and names the two ways to find out
    // rather than telling an operator nothing happened when a node might now
    // be registered.
    //
    // The row is NOT a thing to watch afterwards (it used to say so): the
    // approval hands this sentence to the hub, which settles the row as
    // refused and tells the node the pairing did not finish. So the sentence
    // ends where the operator's next move is: look, and pair again.
    return {
      ok: false, error: 'no_answer',
      detail: 'the root broker did not print its exit line, so this host cannot tell whether '
        + 'the node was registered. It may have finished and been cut off, or it may never have '
        + 'run. The node was told this pairing did not finish. Check '
        + '`journalctl -u "aperire-fleet-broker@*"` on this host for what the broker did, then pair '
        + 'the node again with a new code. If it is already in the fleet list, its new request is '
        + 'offered Approve and reconnect, which keeps its name.',
    };
  }
  if (answer.code !== 0) {
    return {
      ok: false,
      error: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      detail: detail || (answer.code === 3
        ? 'the root broker refused to register that node and gave no reason.'
        : 'the root broker could not register that node.'),
    };
  }
  const readPort = Number(answer.facts.read_port);
  if (!Number.isInteger(readPort) || readPort < 1024 || readPort > 65535) {
    return {
      ok: false, error: 'no_port',
      detail: 'the root broker reported success without a read port, so nothing can be bound for that node.',
    };
  }
  const advisorRaw = (answer.facts.advisor_port ?? '').trim();
  const advisorPort = advisorRaw === '' || advisorRaw === '-' ? null : Number(advisorRaw);
  if (advisorPort !== null && (!Number.isInteger(advisorPort) || advisorPort < 1024 || advisorPort > 65535)) {
    return {
      ok: false, error: 'no_port',
      detail: 'the root broker reported an advisor port that is not a port.',
    };
  }
  const armRaw = (answer.facts.fleet_arm_pubkey ?? '').trim();
  // #1057. The fact decides; the sentence is looked for only once it says
  // `missing`. A label in the fact is the row the broker wrote.
  const selfRaw = (answer.facts.self_row ?? '').trim();
  const selfRow = /^[a-z0-9-]{1,32}$/.test(selfRaw) ? selfRaw : null;
  const selfNote = selfRow === 'missing'
    ? (answer.lines.find((l) => l.startsWith(SELF_ROW_NOTE_PREFIX))?.slice(0, SELF_ROW_NOTE_MAX)
      ?? SELF_ROW_NOTE_FALLBACK)
    : null;
  return {
    ok: true,
    read_port: readPort,
    advisor_port: advisorPort,
    token_path: answer.facts.token_path ?? '',
    advisor_token_path: answer.facts.advisor_token_path ? answer.facts.advisor_token_path : null,
    rejoined: answer.facts.rejoined === '1',
    advisor_lowered: /^[a-z0-9-]{1,32}$/.test((answer.facts.advisor_lowered ?? '').trim()),
    advisor_note: answer.lines.find((l) => l.startsWith(ADVISOR_NOTE_PREFIX))?.slice(0, ADVISOR_NOTE_MAX) ?? null,
    converted_from: answer.facts.converted_from === 'tunnel' ? 'tunnel' : null,
    self_row: selfRow,
    self_row_note: selfNote,
    reloaded: answer.facts.reloaded === '1',
    reload_via: (answer.facts.reload_via ?? '').trim() || 'unknown',
    fleet_arm_pubkey: armRaw === '' || armRaw === '-' ? null : armRaw,
    fleet_arm_key: /^[a-z_]{1,32}$/.test((answer.facts.fleet_arm_key ?? '').trim())
      ? (answer.facts.fleet_arm_key ?? '').trim() : null,
    fleet_arm_key_orphaned: (answer.facts.fleet_arm_key_orphaned ?? '').split(',')
      .map((l) => l.trim()).filter((l) => /^[a-z0-9-]{1,32}$/.test(l)).slice(0, 256),
  };
}

// ── arm-key (#741) ───────────────────────────────────────────────────────

/** The `arm-key` verb takes no fields. */
export function brokerArmKeyPayload(): string {
  return ['arm-key', 'end', ''].join('\n');
}

export type BrokerArmKeyOutcome =
  | {
    ok: true;
    /** Plain base64 of the raw 32 bytes, checked to be one. */
    fleet_arm_pubkey: string;
    /** `made` or `present`, as the broker says it. (`made_fleet_had_nodes`
     *  came from brokers before #851, which made a key on a paired fleet.) */
    fleet_arm_key: string | null;
    fleet_arm_key_orphaned: string[];
  }
  | { ok: false; error: string; detail: string; command?: string };

/**
 * What one `arm-key` meant, asked a moment before a welcome is sent (#741).
 *
 * Anything but a canonical 32-byte key is a refusal here, so a welcome is
 * never sent with a key the node would refuse after the operator had walked
 * to it. A broker older than the verb is named with the one command that
 * updates it.
 */
export function brokerArmKeyOutcome(answer: BrokerAnswer, installDir: string): BrokerArmKeyOutcome {
  const said = (answer.facts.error ?? '').trim();
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  if (answer.code === null) {
    return { ok: false, error: BROKER_NO_ANSWER, detail: brokerNoAnswerDetail(answer) };
  }
  if (said === 'unknown_verb') {
    return {
      ok: false, error: 'broker_predates',
      detail: 'this host\u2019s fleet broker is older than the pairing fingerprint, so it cannot hand a node '
        + `the fleet arm key before the welcome. Update it here: ${grantInstallSentence(installDir)}`,
    };
  }
  if (said === 'fleet_arm_key_lost') return armKeyLostOutcome(answer, installDir);
  if (answer.code !== 0) {
    return {
      ok: false, error: said || 'no_fleet_arm_key',
      detail: detail || 'the root broker could not make or read this aggregator\u2019s fleet arm key.',
    };
  }
  const pub = (answer.facts.fleet_arm_pubkey ?? '').trim();
  if (!isFleetArmPubkey(pub)) {
    return {
      ok: false, error: 'no_fleet_arm_key',
      detail: 'the root broker reported a fleet arm key that is not a 32-byte public key.',
    };
  }
  return {
    ok: true,
    fleet_arm_pubkey: pub,
    fleet_arm_key: /^[a-z_]{1,32}$/.test((answer.facts.fleet_arm_key ?? '').trim())
      ? (answer.facts.fleet_arm_key ?? '').trim() : null,
    fleet_arm_key_orphaned: (answer.facts.fleet_arm_key_orphaned ?? '').split(',')
      .map((l) => l.trim()).filter((l) => /^[a-z0-9-]{1,32}$/.test(l)).slice(0, 256),
  };
}

// ── arm-key-check (#846 review, L5) ──────────────────────────────────────

/** The read-only twin of `arm-key`: whether the key is there, never made. */
export function brokerArmKeyCheckPayload(): string {
  return ['arm-key-check', 'end', ''].join('\n');
}

export type BrokerArmKeyCheckOutcome =
  | { ok: true }
  | { ok: false; error: string; detail: string; command?: string };

/**
 * What one `arm-key-check` meant. The pairing readiness check asks this and
 * not `arm-key`, because `arm-key` makes a key that is missing, and on a
 * fleet whose key was lost that would orphan every paired node the moment
 * someone opened Add a node. A broker older than the verb is named with the
 * command that updates it, which also makes it the broker that has the verb.
 */
export function brokerArmKeyCheckOutcome(answer: BrokerAnswer, installDir: string): BrokerArmKeyCheckOutcome {
  const said = (answer.facts.error ?? '').trim();
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  if (answer.code === null) return { ok: false, error: BROKER_NO_ANSWER, detail: brokerNoAnswerDetail(answer) };
  if (said === 'unknown_verb') {
    return {
      ok: false, error: 'broker_predates',
      detail: 'this host\u2019s fleet broker is older than the pairing check, so it cannot say whether the '
        + `fleet arm key is there without making one. Update it here: ${grantInstallSentence(installDir)}`,
    };
  }
  if (said === 'fleet_arm_key_lost') return armKeyLostOutcome(answer, installDir);
  if (answer.code !== 0) {
    return { ok: false, error: said || 'no_fleet_arm_key', detail: detail || 'the root broker could not say whether this aggregator has a fleet arm key.' };
  }
  if ((answer.facts.fleet_arm_key ?? '').trim() !== 'present') {
    return { ok: false, error: 'no_fleet_arm_key', detail: 'the root broker did not report a fleet arm key.' };
  }
  return { ok: true };
}

/**
 * The sentence a pairing's row carries when the broker had to make a NEW arm
 * key while other nodes were already paired (#743 review, L2), or null.
 *
 * Those nodes hold the public half of the key that was lost, and every arm
 * this aggregator sends them from now on is signed by a key they do not
 * trust. Nothing on this host can put the old key back, so the sentence says
 * what happened, names the nodes, and names the one thing that fixes each.
 */
export function armKeyRemintNote(key: string | null, orphaned: readonly string[]): string | null {
  if (key !== 'made_fleet_had_nodes') return null;
  const names = orphaned.length ? orphaned.join(', ') : 'every node paired before this one';
  return 'This aggregator had no fleet arm key, so it made a new one for this pairing. The nodes paired '
    + `before it trust the old key, which is gone: ${names}. They will refuse every arm and every model `
    + 'this aggregator sends until each is paired again, which hands it the new key.';
}

// ── The inherit: one node, the fleet's sealed model (ADR 0019 phase 4) ──

/** What handing one node the fleet's sealed model came to. Seven outcomes,
 *  because they send an operator to four different places: no Advisor on that
 *  node, no store here, a broker here older than the feature, this
 *  aggregator's own window shut, the node's own refusal, and no answer. */
export interface InheritOutcome {
  state: 'sealed' | 'no_advisor' | 'no_store' | 'predates' | 'refused' | 'unreachable' | 'arm_closed';
  detail?: string;
  reason?: string;
}

/**
 * Hand a node the fleet's sealed model, if there is one (#168). The one
 * decision a pairing's follow-on and an Advisor's attach (#1037) both make,
 * so a node gets the model the same way whichever of the two put its Advisor
 * on the fleet. The key never passes through here: the root broker opens the
 * store and sends it, and this reads what came of that.
 *
 * The store is READ first rather than pushed at blindly. A push with no store
 * would refuse anyway, but its refusal would be about this host and would
 * read on the row as though the node had done something wrong.
 */
export async function inheritFleetModel(
  label: string,
  advisor: boolean,
  grant: BrokerPushGrant,
  io: {
    storeHead: () => Promise<BrokerStoreHeadOutcome>;
    push: (label: string, grant: BrokerPushGrant) => Promise<BrokerPushOutcome>;
  },
): Promise<InheritOutcome> {
  if (!advisor) return { state: 'no_advisor' };
  const head = await io.storeHead();
  if (head.state === 'predates') return { state: 'predates' };
  if (head.state === 'none') return { state: 'no_store' };
  if (head.state !== 'held') {
    // Busy, or a blob this host could not open. Neither is "there is none",
    // and neither is that node's fault.
    return { state: 'unreachable', detail: head.detail, reason: head.reason };
  }
  let outcome: BrokerPushOutcome;
  try {
    outcome = await io.push(label, grant);
  } catch (err) {
    // The CLASS, never the message: the payload behind this call is the key.
    return { state: 'unreachable', reason: (err as Error).name };
  }
  if (outcome.state === 'sealed') return { state: 'sealed' };
  // THIS aggregator's window, which is a different sentence from that node's
  // refusal and sends the operator to a different machine.
  if (outcome.reason === 'arm_closed') {
    return { state: 'arm_closed', detail: outcome.detail, reason: outcome.reason };
  }
  if (outcome.state === 'refused') {
    return { state: 'refused', detail: outcome.detail, reason: outcome.reason };
  }
  return { state: 'unreachable', detail: outcome.detail, reason: outcome.reason };
}

/**
 * What an attach did about the fleet's model (#1037), and the sentence for it.
 *
 *   kept         the node already has a model, and it is left on it. Advisor
 *                AI model says whether that is the fleet's; Catch up is how an
 *                operator moves it, never an attach.
 *   unread       whether it has one could not be read, so nothing was sent:
 *                the node's sealer replaces whatever it holds, and a model
 *                nobody saw is not one to overwrite.
 *   arm_closed   this aggregator has no sealing window open, so the broker
 *                would move no key. Said with the one root line, here,
 *                rather than spending a push to be told.
 *   started      it has none, and the push is under way.
 */
export type AttachModelState = 'kept' | 'unread' | 'arm_closed' | 'started';

export function attachModelSentence(state: AttachModelState, armInstalled = false): string {
  switch (state) {
    case 'kept':
      return 'Its Advisor already has a model, so it was left on it. Advisor AI model shows whether that '
        + 'is the fleet’s.';
    case 'unread':
      return 'Whether its Advisor has a model could not be read just now, so the fleet’s was not sent to '
        + 'it. If its row under Advisor AI model shows no model, bring it up to date from there.';
    case 'arm_closed':
      return 'This aggregator had no sealing window open, so it sent that node no model. Advisor AI model '
        + `counts it as out of sync until it has one. Run this on this aggregator${fleetArmLeadIn(armInstalled)}, `
        + `then bring it up to date from Settings: ${armSelfCommand(armInstalled)}`;
    case 'started':
      return 'Its Advisor has no model yet, so the fleet’s is on its way to it now. Its row under Advisor '
        + 'AI model says when it lands.';
  }
}

// ── The follow-on (§3.6) ─────────────────────────────────────────────────

/** How often the follow-on asks whether the node's link is up, and for how
 *  long. `held` is true only when the link is up AND its loopback listeners
 *  are bound, which is exactly the condition a trust push needs. A minute
 *  and a half is generous for a node that has just written its credential
 *  and reloaded; past it the row says what is true and the operator acts. */
export const PAIR_FOLLOWON_POLL_MS = 2_000;
export const PAIR_FOLLOWON_MAX_MS = 90_000;

export interface FollowOnState {
  /** Did this aggregator OBSERVE the node's link come up? Never taken from
   *  the node's own `pair_done`: a node that lies there must not be able to
   *  drive a trust push, so the only input is this hub's own observation. */
  held: boolean;
  /** What the trust push did, when it ran at all. */
  pushed: 'ok' | 'failed' | 'skipped';
  /** The CLI's own words on a failure. Its status codes are the only thing
   *  that tells an unreachable node from one refusing the bundle. */
  pushDetail?: string;
  /** Does the fleet have a model setting this node's Advisor is not on?
   *
   *  Read off this aggregator's own record. Phase 4 acts on it: when the
   *  store holds a sealed model, the follow-on pushes it and `model` below
   *  says what came of that. */
  needsModel: boolean;
  /**
   * What the inherit did (ADR 0019 phase 4, #168).
   *
   * Six outcomes because six things can happen and they send an operator to
   * four different places. NONE of them fails the pairing: the node is
   * registered, its link is up, and the row says what is left to do.
   *
   *   sealed        pushed, and that node's Advisor took it.
   *   no_advisor    that node runs none, so there was nothing to seal.
   *   no_store      this aggregator holds no sealed fleet model.
   *   predates      this aggregator's own broker is older than the feature.
   *   refused       the node's sealer said no. Its own reason, usually that
   *                 nobody armed it or that the window lapsed.
   *   unreachable   no answer in time.
   *   not_attempted nothing was tried, which is what a host with no broker
   *                 dep reports rather than claiming a skip it did not make.
   */
  model?: 'sealed' | 'no_advisor' | 'no_store' | 'predates' | 'refused' | 'unreachable'
  | 'arm_closed' | 'not_attempted';
  /** The node's own words on a refusal, rendered as it wrote them. */
  modelDetail?: string;
  /** Whether FLEET_ARM_PROGRAM is on this host, so the `arm_closed` branch
   *  names the installed command, or the update that places it first (#812).
   *  Never a path into this install's tree. */
  armInstalled?: boolean;
}

/** The one optional next step a follow-on can carry (#635): today, only the
 *  arm-closed outcome. Kept apart from `text` so the Paired card can render
 *  it as its own block -- a sentence, then the command in its own copy box
 *  -- instead of a root command run into the middle of running prose, which
 *  is both the missing-period bug and the un-copyable command the operator's
 *  17v walk caught (S9). */
export interface PairFollowOnNext {
  sentence: string;
  command: string;
}

/** What the Pending row carries once this aggregator's part is over: the
 *  one line every outcome gets (`text` -- "Registered, linked, ..." and
 *  whichever model clause is plain prose), and `next`, present only for the
 *  outcome that names something to run. */
export interface PairFollowOnNote {
  text: string;
  next: PairFollowOnNext | null;
}

/**
 * The sentence (and the one optional next step) the Pending row carries once
 * this aggregator's part is over. Pure, so the words are testable and the
 * timing is not in here.
 */
export function pairFollowOnNote(state: FollowOnState): PairFollowOnNote {
  if (!state.held) {
    return {
      text: 'Registered. Its link has not come up yet, so nothing has been pushed to it: '
        + 'the row above reads link with never held until it does.',
      next: null,
    };
  }
  const head = state.pushed === 'ok'
    ? 'Registered, linked, and it holds the current passkey list.'
    : state.pushed === 'failed'
      ? `Registered and linked. The passkey list did not reach it: ${state.pushDetail || 'no reason given'}. `
        + 'Push it again from Fleet trust enrollment below.'
      : 'Registered and linked.';
  // THIS host's window, not that node's. The distinction is the whole point
  // of the sentence: an operator told to arm the node they just paired would
  // arm the wrong machine and see the same row again. The exact wording
  // below is the one the approved mockup shows in the Paired card's own
  // optional block -- reported verbatim, so keep it in agreement with that
  // card rather than paraphrasing here.
  if (state.model === 'arm_closed') {
    return {
      text: head,
      next: {
        sentence: 'This aggregator had no sealing window open, so it sent the node no model. Advisor AI '
          + `model counts it as out of sync until it has one. Run this on this aggregator${fleetArmLeadIn(state.armInstalled === true)}, `
          + 'then bring the node up to date from Settings:',
        command: armSelfCommand(state.armInstalled === true),
      },
    };
  }
  return { text: `${head}${modelClause(state)}`, next: null };
}

/**
 * The model half of the plain-prose outcomes, one clause per outcome.
 * `arm_closed` is handled above, in `next`, and never reaches here.
 *
 * Each says what happened and, where there is one, what to do next. A
 * pairing is never failed by any of them, so none of these reads as an
 * error: the node is registered and linked, and this is the part that is
 * still outstanding.
 */
function modelClause(state: FollowOnState): string {
  switch (state.model) {
    case 'sealed':
      return ' Its Advisor is on the fleet model.';
    case 'no_advisor':
      return ' There is no Advisor there, so there was nothing to seal.';
    case 'no_store':
      return ' This aggregator holds no sealed fleet model, so it had nothing to hand that node. '
        + 'Seal the fleet model from Settings and that node picks it up.';
    case 'predates':
      return ' This aggregator’s fleet broker is older than this feature, so nothing was handed to '
        + 'that node. Update this host’s install and run its broker grant installer again.';
    case 'refused':
      return ` Its Advisor is not on the fleet model yet: ${state.modelDetail || 'that node refused'}. `
        + 'Arm it and bring it up to date from Settings.';
    case 'unreachable':
      return ' Its Advisor did not answer in time, so whether it took the fleet model is not known '
        + 'here. Bring it up to date from Settings.';
    default:
      // The phase-3 shape, and a host with no broker: nothing was tried, and
      // the row says only what this dashboard actually knows.
      return state.needsModel ? ' Its Advisor has no model yet. Seal one from the row above.' : '';
  }
}

// ── What a per-node push line says (#448) ────────────────────────────────
//
// The lab read this verdict on 2026-09-17: "0 of 1 took
// the model. srv12345: The sealing program could not be reached on
// this host." The node's sealer HAD been reached; its journal has the
// refusal, in words, with the command that fixes it. The page replaced the
// node's answer with a transport failure, and an operator reading that goes
// looking at connectivity for a problem one arm command fixes.
//
// So two rules, and this is the one place either is written.
//
//   1. "could not be reached" belongs to `unreachable` ALONE, which is this
//      side failing to get an answer. A node that answered and said no is
//      quoted, never paraphrased into a transport failure, whatever word its
//      reason carries.
//   2. A refusal about the node's arming window is named as one, with the
//      command and THAT node's label filled in, because the fix is one line
//      on the aggregator and the operator should not have to know it.

/** The arming words a node's sealer uses, and the ones a dashboard in front
 *  of it turns them into. Matched on either, because the node may forward its
 *  sealer's own sentence or its own classification of it, and both mean the
 *  same thing to the operator standing in front of this line. */
const ARM_REFUSAL_RE = /^(unarmed|expired|arm_closed)$/;
const ARM_SENTENCE_RE = /unarmed:|no arming marker|arming window (has )?closed|expired:/i;

/** Is this refusal about the node's window? */
export function isArmRefusal(outcome: { reason?: string; detail?: string }): boolean {
  return ARM_REFUSAL_RE.test((outcome.reason ?? '').trim())
    || ARM_SENTENCE_RE.test(outcome.detail ?? '');
}

/** The one line an operator reads for one node, after one push.
 *
 *  The arm command is run on THIS host: one root line on the aggregator
 *  opens a window on the node it names. `armInstalled` picks the installed
 *  name, or the update that places it first (#812); neither is a path. */
export function catchupNodeLine(
  label: string,
  outcome: Pick<BrokerPushOutcome, 'state' | 'reason' | 'detail'>,
  armInstalled = false,
): string {
  const said = (outcome.detail ?? '').trim();
  if (outcome.state === 'sealed') return `${label}: on the fleet model.`;
  // The broker gave no answer (#848): the silence is the broker's and the
  // node was never asked, or was asked and nobody can say. Never "could not
  // be reached", which is the node's own state and sends the operator to the
  // node.
  if (outcome.reason === BROKER_NO_ANSWER) return `${label}: ${said}`;
  if (outcome.state === 'unreachable') {
    // The only state that may say this, and it says whose silence it is.
    return `${label} could not be reached${said ? `: ${said}` : '.'}`;
  }
  const arm = `${fleetArmCommand(armInstalled)} --node ${label}`;
  if (isArmRefusal(outcome)) {
    return `${label} refused: it has no sealing window open, so nothing may be sealed there from this `
      + `dashboard.${said ? ` It said: ${said}` : ''} Arm it from here${fleetArmLeadIn(armInstalled)}, then Catch up: ${arm}`;
  }
  return `${label} refused${said ? `: ${said}` : ` (${(outcome.reason ?? 'no reason given').trim()}).`}`;
}

// ── What this host's own store write said (#443) ─────────────────────────
//
// A seal whose per-node rows all read `sealed` and whose STORE write failed
// is the exact case the sealed copy exists to close: a node paired next week
// inherits nothing, and the catch-up button has nothing to send. On the lab aggregator
// the only place that said so was a log line, and the page read as clean.
//
// This is the note the page prints beside those rows. It is the store
// write's own outcome, kept by the host that made the call, never derived
// from a later read of the store: a broker with no store verbs answers both
// the same way, and a store that was fine before the failed write would read
// as proof the write landed.

export interface StoreWriteNote {
  /** Did the sealed copy land? */
  ok: boolean;
  /** ms since the epoch, so a page can tell this note from the one before
   *  the seal it is reading. */
  at: number;
  /** The broker's own error code, when it failed. */
  error?: string;
  /** One sentence for the operator. Never carries the key. */
  detail?: string;
}

/** The sentence the verdict carries when the sealed copy did not land.
 *  Null when it did, which is the ordinary case and needs no line. */
export function storeWriteLine(note: StoreWriteNote | null): string | null {
  if (!note || note.ok) return null;
  const why = (note.detail ?? '').trim() || (note.error ?? '').trim() || 'no reason was given';
  return `Not sealed at rest on this host: ${why} Until it is, a node paired from now on inherits no `
    + 'model and Catch up has nothing to send.';
}

// ── What one `revoke` meant (#444) ───────────────────────────────────────
//
// The verb has been in the broker since phase 3 with no caller: an operator
// who wanted a node gone edited two files by hand and re-ran the grant
// installer, which is what the item 4 lab did.
//
// Two of its facts matter to the caller and one of its refusals is not a
// failure. `no_row` means there was no LINK row to close, which is the
// ordinary state for a node this fleet reaches down a tunnel rather than a
// link; the registry row still has to go, so the caller is told "there was
// no link" rather than "the revoke failed". Every other refusal is fatal,
// because root's own destination record is pruned by this verb and a
// registry row dropped without it would leave root vouching for a node the
// fleet no longer knows.
export type BrokerRevokeOutcome =
  | {
    ok: true;
    /** Was there a link row to close? False is not a failure. */
    had_link: boolean;
    /** Did root's own push-destination record lose the row? The broker
     *  reports this separately because its failure is not fatal there
     *  either: a stale row refuses at its own pin check. */
    nodes_pruned: boolean;
    /** The same fact in its three states (#704): the line was taken out,
     *  root's record never held this label, or a line was there and the
     *  rewrite failed. Null when the broker did not say (a no_row answer,
     *  which runs neither step). */
    root_record: 'pruned' | 'absent' | 'failed' | null;
    /** Token files the broker removed (#854). Null when it did not say:
     *  a no_row answer, or a broker older than the step. */
    tokens_removed: number | null;
    /** Token file names the broker refused or could not remove. */
    tokens_failed: string[];
    /** The fleet token directory itself was refused by the broker's own
     *  walk (a symlink there, a too-wide mode, or a fault) before either
     *  token name was even tried (#854 security review, L1). Named apart
     *  from tokens_failed: that is about a LEAF, this is about the
     *  directory both leaves live in. */
    tokens_dir_refused: boolean;
    reloaded: boolean;
    /** The registry half (#859). `removed` or `absent` (already gone) when
     *  it finished, `left` when the broker answered registry_left (the link
     *  is closed and the credential half done, but fleet.yaml's row or the
     *  Advisor's peer could not be taken out), and null when the broker did
     *  not say: one older than #859, which never takes the row out. */
    fleet_row: 'removed' | 'absent' | 'left' | null;
    /** The same, for the peer in the Advisor's fleet.json. */
    advisor_peer: 'removed' | 'absent' | 'left' | null;
    /** registry_left only: the broker's own refusal code and sentence. */
    registry_left_reason: string | null;
    registry_left_detail: string | null;
    /** A new broker's no_row: the label is in none of the five places, so
     *  everything is already gone. Not the same as an older broker's no_row,
     *  which never looked at fleet.yaml. */
    already_gone: boolean;
  }
  | {
    ok: false; error: string; detail: string;
    /** #870 review, L1: the broker refused AFTER its credential half ran
     *  (fleet-links.json could not be read or written back), so root's
     *  record and the token files were acted on and the link may still be
     *  up. These are those facts; absent on a refusal before anything ran. */
    phase1?: ReturnType<typeof revokeCleanupFacts> & { link_removed: 'unknown' };
  };

/** The cleanup facts of a revoke answer, read the same way on every ok path. */
function revokeCleanupFacts(facts: Record<string, string>): {
  nodes_pruned: boolean; root_record: 'pruned' | 'absent' | 'failed' | null;
  tokens_removed: number | null; tokens_failed: string[]; tokens_dir_refused: boolean;
} {
  const np = facts.nodes_pruned;
  const root_record = np === '1' ? 'pruned' : np === 'absent' ? 'absent' : np === '0' ? 'failed' : null;
  const tr = facts.tokens_removed;
  const tokens_removed = tr !== undefined && /^[0-2]$/.test(tr) ? Number(tr) : null;
  const tokens_failed = (facts.tokens_failed ?? '').split(',').map((t) => t.trim())
    .filter((t) => /^[a-z0-9-]{1,32}\.(approve\.)?token$/.test(t));
  const tokens_dir_refused = facts.tokens_dir_refused === '1';
  return { nodes_pruned: root_record === 'pruned', root_record, tokens_removed, tokens_failed, tokens_dir_refused };
}

/** What the credential half of a revoke did, in words, from the facts the
 *  broker had printed. Only what it said: a fact it did not print is not
 *  claimed either way (#848). */
function revokeCleanupSaid(f: ReturnType<typeof revokeCleanupFacts>): string {
  const parts: string[] = [];
  if (f.root_record === 'pruned') parts.push('root’s record of the node was cleared');
  else if (f.root_record === 'failed') parts.push('root’s record of the node could not be cleared');
  else if (f.root_record === 'absent') parts.push('root held no record of the node');
  if (f.tokens_removed !== null) parts.push(`${f.tokens_removed} token file${f.tokens_removed === 1 ? '' : 's'} removed`);
  if (f.tokens_failed.length) parts.push(`${f.tokens_failed.join(', ')} could not be removed`);
  if (f.tokens_dir_refused) parts.push('the token directory was refused');
  return parts.length ? parts.join(', ') : 'it printed nothing about what it cleared';
}
function revokeCleanupClean(f: ReturnType<typeof revokeCleanupFacts>): boolean {
  return f.root_record !== 'failed' && f.tokens_failed.length === 0 && !f.tokens_dir_refused;
}

/** The registry-half facts of a revoke answer (#859). */
function revokeRegistryFacts(facts: Record<string, string>): {
  fleet_row: 'removed' | 'absent' | 'left' | null; advisor_peer: 'removed' | 'absent' | 'left' | null;
} {
  const three = (v: string | undefined) => (v === 'removed' || v === 'absent' || v === 'left' ? v : null);
  return { fleet_row: three(facts.fleet_row), advisor_peer: three(facts.advisor_peer) };
}

/** The answer when an exit code says the revoke ran but the broker did not
 *  say which label it revoked: never a success (#859 security scan). */
const REVOKE_UNVERIFIED = {
  ok: false as const, error: 'revoke_unverified',
  detail: 'the root broker answered without saying it revoked this node, so this host cannot tell whether '
    + 'the link was closed. Treat it as still on this fleet, and read its row again before pressing Revoke again.',
};

export function brokerRevokeOutcome(answer: BrokerAnswer, installDir: string, label?: string): BrokerRevokeOutcome {
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  const said = (answer.facts.error ?? '').trim();
  const registry = revokeRegistryFacts(answer.facts);
  const noLeft = { registry_left_reason: null, registry_left_detail: null };
  if (answer.code === null) {
    // Never "nothing was changed" (#848): the broker prints `revoked=<label>`
    // after its credential half has run, so a stream cut off after that line
    // carries a revoke that already happened (root's record, the token files,
    // usually the link). That is the partial shape the route already keeps
    // its tombstone for. A host that stopped waiting has no stream at all and
    // the broker may still be finishing, which is said as that.
    const ran = label !== undefined && answer.facts.revoked === label;
    const lead = answer.timed_out
      ? 'this host stopped waiting for the root broker, so it cannot tell whether the link was closed, and '
        + 'the broker may still be carrying it out.'
      : 'the root broker did not print its exit line, so this host cannot tell whether the link was closed.';
    const phase1 = ran ? { ...revokeCleanupFacts(answer.facts), link_removed: 'unknown' as const } : null;
    return {
      ok: false, error: 'no_answer',
      detail: phase1
        ? `${lead} Before it was cut off its credential half had run: ${revokeCleanupSaid(phase1)}. `
          + (revokeCleanupClean(phase1)
            ? 'Read the node’s row on the next refresh.'
            : 'Something there did not finish: read the node’s row on the next refresh and press Revoke again if it is still here.')
        : `${lead} Read the node’s row on the next refresh before pressing Revoke again.`,
      ...(phase1 ? { phase1 } : {}),
    };
  }
  if (said === 'unknown_verb') {
    return {
      ok: false, error: 'unknown_verb',
      detail: `the root service on this host has no revoke verb. Run the full grant installer here: ${grantInstallSentence(installDir)}`,
    };
  }
  if (said === 'no_row') {
    // A broker that says fleet_row (#859) means "in none of the five
    // places": everything is already gone. One that does not is older and
    // meant "no link row", having never looked at fleet.yaml; the row is
    // still there, and fleet_row null says so to the caller.
    return {
      ok: true, had_link: false, ...revokeCleanupFacts(answer.facts), reloaded: answer.facts.reloaded === '1',
      ...registry, ...noLeft, already_gone: registry.fleet_row === 'absent',
    };
  }
  // A success, or a partial one, is believed only when the broker named the
  // label it revoked: `revoked=<label>` is printed after phase 1 has run,
  // and an empty, garbled or truncated answer never carries it.
  const verified = (answer.facts.revoked ?? '') !== '' && (label === undefined || answer.facts.revoked === label);
  if (said === 'registry_unreadable' && answer.facts.link_removed === 'unknown') {
    return {
      ok: false, error: 'link_unknown',
      detail: detail || 'the root broker could not read or rewrite this fleet’s link registry, so the link may '
        + 'still be up. Root’s record of the node and its token files were cleared regardless.',
      phase1: { ...revokeCleanupFacts(answer.facts), link_removed: 'unknown' },
    };
  }
  if (said === 'registry_left') {
    if (!verified) return REVOKE_UNVERIFIED;
    // #859 phase 2 refused or failed: the credential half is done and stands
    // (the link is closed, root's record and the token files cleared), and
    // the registry row is still here. Not a failure of the revoke.
    return {
      ok: true,
      had_link: answer.facts.link_removed === '1',
      ...revokeCleanupFacts(answer.facts),
      reloaded: answer.facts.reloaded === '1',
      fleet_row: 'left', advisor_peer: 'left',
      registry_left_reason: (answer.facts.registry_left_reason ?? '').trim() || null,
      registry_left_detail: detail || null,
      already_gone: false,
    };
  }
  if (answer.code !== 0) {
    return {
      ok: false,
      error: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      detail: detail || 'the root broker refused to close that node’s link and gave no reason.',
    };
  }
  if (!verified) return REVOKE_UNVERIFIED;
  return {
    ok: true,
    // #859: a broker that says link_removed is exact; an older one only
    // ever answered 0 when it had removed a link row.
    had_link: answer.facts.link_removed === undefined ? true : answer.facts.link_removed === '1',
    ...revokeCleanupFacts(answer.facts),
    reloaded: answer.facts.reloaded === '1',
    ...registry, ...noLeft, already_gone: false,
  };
}

// ── Attaching and detaching an Advisor on an already-paired node (#641) ──
//
// Two payloads and two outcomes, beside `revoke` above because they are the
// same shape of act: a verb that changes ONE thing about a row this fleet
// already holds, and whose refusals an operator has to be able to act on.
//
// The token is the only value in this file, other than the sealed model
// key's own payload, that is a secret. It is encoded the same way every
// other value is and it never appears in an outcome, on either side: a
// refusal that quoted it back would put a credential in a page, a log and an
// audit row at once.

export interface BrokerAttachAdvisorInput {
  label: string;
  /** The key the row is pinned to. The broker checks it against BOTH
   *  fleet.yaml's row and root's own record, and refuses on either
   *  disagreement: this value is the aggregator saying which node it thinks
   *  it is attaching to, never a value the broker takes as true. */
  pubkey_node: string;
  /** The node's own approve.token, as that node just revealed it. Bounded
   *  and shape-checked one hop earlier (lib/fleet-advisor-attach.ts) before
   *  it ever reaches here, and bounded again by the broker itself. */
  advisor_token: string;
}

export function brokerAttachAdvisorPayload(input: BrokerAttachAdvisorInput): string {
  return [
    'attach-advisor',
    `label=${encodeBrokerValue(input.label)}`,
    `pubkey_node=${encodeBrokerValue(input.pubkey_node)}`,
    `advisor_token=${encodeBrokerValue(input.advisor_token)}`,
    'end', '',
  ].join('\n');
}

export function brokerDetachAdvisorPayload(label: string): string {
  return ['detach-advisor', `label=${encodeBrokerValue(label)}`, 'end', ''].join('\n');
}

export type BrokerAttachAdvisorOutcome =
  | {
    ok: true;
    /** The loopback port the broker allocated for that node's Advisor. The
     *  row's own `advisor_origin` is built from it, and the hub binds a
     *  listener there on its next reconcile. */
    advisor_port: string | null;
    reloaded: boolean;
  }
  | { ok: false; error: string; detail: string };

/**
 * What one `attach-advisor` meant.
 *
 * EVERY REFUSAL IS FATAL, unlike `revoke`'s `no_row`. There is no partial
 * attach worth going on from: the verb writes fleet.yaml, fleet-links.json,
 * the token file and root's own record in one all-or-none candidate set, so
 * either the node has an Advisor attached here or nothing moved. The caller
 * has nothing left to do afterwards.
 *
 * `already_attached` gets its own sentence because it is the one refusal an
 * operator reaches by pressing a button twice, which is not a mistake worth
 * a scary message.
 */
export function brokerAttachAdvisorOutcome(answer: BrokerAnswer, installDir: string): BrokerAttachAdvisorOutcome {
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  const said = (answer.facts.error ?? '').trim();
  if (answer.code === null) {
    return {
      ok: false, error: 'no_answer',
      detail: 'the root broker did not print its exit line, so this host cannot tell whether the Advisor '
        + 'was attached. Read that node’s row on the next refresh before pressing Attach again.',
    };
  }
  if (said === 'unknown_verb') {
    return {
      ok: false, error: 'unknown_verb',
      detail: `the root service on this host has no attach-advisor verb. Run the full grant installer here: ${grantInstallSentence(installDir)}`,
    };
  }
  if (said === 'already_attached') {
    return {
      ok: false, error: 'already_attached',
      // #854 security review, L4: this refusal is also what a rejoin after
      // a revoke leaves behind. Revoke (#854) deletes the node's Advisor
      // token file; a rejoin restores the link row's advisor_port but
      // never that file, because only attach-advisor and
      // refresh-advisor-token write it, and this row already carries
      // advisor_origin so attach-advisor refuses here too. The broker's own
      // refresh-advisor-token verb is the one thing that rebuilds it
      // without widening anything (it can only replace a token file's
      // content on a row already attached). There is no button for it yet,
      // so the fix is named rather than only "refresh the page", which
      // reads like the row will heal on its own and it will not.
      detail: 'that node already has an Advisor attached here. If pressing Attach was meant to replace a '
        + 'missing or stale token (for example after a revoke followed by pairing again), refresh the page '
        + 'to see the row as it stands; if its Advisor tab still refuses, this host’s fleet broker has a '
        + 'refresh-advisor-token verb that rebuilds the token without touching anything else, and someone '
        + 'with root on this host can run it.',
    };
  }
  if (answer.code !== 0) {
    return {
      ok: false,
      error: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      detail: detail || 'the root broker refused to attach that Advisor and gave no reason.',
    };
  }
  return {
    ok: true,
    advisor_port: (answer.facts.advisor_port ?? '').trim() || null,
    reloaded: answer.facts.reloaded === '1',
  };
}

export type BrokerDetachAdvisorOutcome =
  | {
    ok: true;
    /** Did root's own record lose the Advisor bit? The broker reports it
     *  separately because a host with no fleet-nodes.conf line for the label
     *  still detaches: the registry row is what the tab reads, and root's
     *  record is what a model push reads, and the second one refuses on its
     *  own pin check anyway. */
    nodes_updated: boolean;
    reloaded: boolean;
  }
  | { ok: false; error: string; detail: string };

export function brokerDetachAdvisorOutcome(answer: BrokerAnswer, installDir: string): BrokerDetachAdvisorOutcome {
  const detail = answer.lines.length ? answer.lines[answer.lines.length - 1] : '';
  const said = (answer.facts.error ?? '').trim();
  if (answer.code === null) {
    return {
      ok: false, error: 'no_answer',
      detail: 'the root broker did not print its exit line, so this host cannot tell whether the Advisor '
        + 'was detached. Read that node’s row on the next refresh.',
    };
  }
  if (said === 'unknown_verb') {
    return {
      ok: false, error: 'unknown_verb',
      detail: `the root service on this host has no detach-advisor verb. Run the full grant installer here: ${grantInstallSentence(installDir)}`,
    };
  }
  if (said === 'not_attached') {
    return {
      ok: false, error: 'not_attached',
      detail: 'that node has no Advisor attached here, so there was nothing to remove and nothing was changed.',
    };
  }
  if (answer.code !== 0) {
    return {
      ok: false,
      error: said || (answer.code === 3 ? 'refused' : 'broker_failed'),
      detail: detail || 'the root broker refused to remove that Advisor and gave no reason.',
    };
  }
  return {
    ok: true,
    nodes_updated: answer.facts.nodes_updated === '1',
    reloaded: answer.facts.reloaded === '1',
  };
}
