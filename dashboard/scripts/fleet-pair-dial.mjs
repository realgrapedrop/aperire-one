/**
 * The wire half of `scripts/aperire-fleet-pair.sh` — ADR 0019 phase 3, §3.2.
 *
 * Bash cannot speak WebSocket, and the pairing exchange is five frames with
 * an operator's decision in the middle of it. So the shell owns everything
 * privileged (reading the tokens, writing the three artefacts, the reload)
 * and this program owns the socket and nothing else. It writes no file,
 * creates no directory and runs no command.
 *
 * Run through tsx so it imports the CONTRACT rather than holding a private
 * copy of five frame shapes. `types/fleet-link-contract.ts` says in its own
 * header that it is the one definition of what crosses, and a second copy in
 * a tool is exactly how the two ends come to disagree.
 *
 *   node --import tsx scripts/fleet-pair-dial.mjs      (from dashboard/)
 *
 * In dashboard/scripts/ and not dashboard/tools/, because tools/ is test
 * material and the release allowlist does not carry it: a node cannot pair
 * with a helper that did not ship. send-magic.mjs is the same shape and the
 * same reason — a .mjs a shell script runs.
 *
 * THE LINE PROTOCOL, because a single-shot invocation cannot hold a socket
 * across the approval:
 *
 *   stdin  line 1   the job, as JSON. Nothing on argv and nothing in the
 *                   environment: the code and both tokens cross here, and
 *                   argv is world-readable in /proc for the life of the
 *                   process. This is socket-program.ts's own rule, applied
 *                   to the one boundary in this phase that is not a socket.
 *                   It carries `fingerprint`, the operator's paste, which
 *                   the shell took and shape-checked BEFORE it started this
 *                   (pairing v2): the operator's TOFU decision (#741) is
 *                   held from the start and compared here, exactly, against
 *                   what this program computes from the aggregator's keys.
 *   stdout          one JSON event per line, newest last.
 *   stdin  line 2   `{"ok":true,"wrote":[...]}` after the `settled` event,
 *                   once the shell has the artefacts on disk.
 *
 * WHEN the comparison runs depends on the aggregator, and the hello asks for
 * the earlier one (`keys_first`):
 *   - a current aggregator answers with `pair_keys` before anyone approves.
 *     This compares at once and answers `pair_checked`. A mismatch exits 4
 *     before an administrator has spent a passkey. A match waits for the
 *     welcome, which must then carry the SAME two keys, byte for byte, and
 *     verify under that trust key, or nothing is sent.
 *   - an older aggregator never sends `pair_keys`, so its signed welcome is
 *     the first thing that arrives, and the held paste is compared against
 *     it. Either way the operator is asked once, before the dial.
 * The computed value is never emitted before a match, so nothing downstream
 * can print it for the operator to copy back.
 *
 * #626: on a match against early keys, `pair_checked` also carries
 * `tunnel_proof`, a MAC under this node's read token (from the job, never
 * re-read, never printed) that lets an aggregator already reading this node
 * over an SSH tunnel move it to the link. Never computed before the match.
 *
 * Exit codes, the shape every root program in this tree uses:
 *   0  paired
 *   3  refused by name (a bad code, a signature that did not verify, a
 *      broker that would not write the row). An outcome, not a fault.
 *   4  the pasted fingerprint did not match (#741). No token was sent.
 *   1  failed (no socket, a timeout, a frame that makes no sense)
 */
import { WebSocket } from 'ws';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import {
  FLEET_LINK_PROTOCOL_VERSION, FLEET_PAIR_HEADER,
  pairChallengeSigningBytes, pairSettledSigningBytes, parseLinkFrame, encodeLinkFrame,
  fleetPairingFingerprint, pairingFingerprintMatches, fleetKnownNodeProof,
} from '../types/fleet-link-contract.ts';
import { verifyWithPeerKey } from '../lib/trust-bundle.ts';

const V = FLEET_LINK_PROTOCOL_VERSION;

/** One line per event, flushed as it happens: the shell reads this stream
 *  live and prints a truthful step-keyed line for each one. */
function emit(ev) {
  process.stdout.write(`${JSON.stringify(ev)}\n`);
}

const lines = createInterface({ input: process.stdin });
const queue = [];
let waiter = null;
lines.on('line', (line) => {
  if (waiter) { const w = waiter; waiter = null; w(line); return; }
  queue.push(line);
});
let stdinEnded = false;
lines.on('close', () => {
  stdinEnded = true;
  if (waiter) { const w = waiter; waiter = null; w(null); }
});
function nextLine() {
  if (queue.length) return Promise.resolve(queue.shift());
  if (stdinEnded) return Promise.resolve(null);
  return new Promise((resolve) => { waiter = resolve; });
}

function fail(code, message) {
  emit({ ev: 'failed', detail: message });
  process.exitCode = code;
}

const jobLine = await nextLine();
if (!jobLine) { fail(1, 'no job arrived on stdin'); process.exit(); }
let job;
try { job = JSON.parse(jobLine); } catch (err) {
  fail(1, `the job on stdin did not parse: ${err.message}`);
  process.exit();
}

const timeoutMs = Number(job.timeout_ms) || 120_000;

// The operator's paste, held from before the dial. The shell shape-checked
// it already; checked again here so this program never dials holding
// nothing it could compare, whoever started it.
const paste = typeof job.fingerprint === 'string' ? job.fingerprint : '';
if (!/^[0-9a-f]{64}$/.test(paste.replace(/\s+/g, '').toLowerCase())) {
  fail(1, 'the job carries no pairing fingerprint to compare, so nothing was dialled');
  process.exit();
}

/**
 * One dial, one exchange. Resolves with the exit code.
 *
 * Every await is inside one socket's lifetime, so there is no reconnect and
 * no backoff here: a pairing run is an operator standing at a keyboard, and
 * a retry is them running the command again with a fresh code.
 */
const code = await new Promise((resolve) => {
  let settled = false;
  const done = (rc) => { if (!settled) { settled = true; resolve(rc); } };

  emit({ ev: 'dialing', url: job.aggregator_ws });
  let ws;
  try {
    ws = new WebSocket(job.aggregator_ws, {
      headers: { [FLEET_PAIR_HEADER]: '1' },
      handshakeTimeout: 20_000,
      followRedirects: false,
    });
  } catch (err) {
    emit({ ev: 'failed', detail: `could not dial the aggregator: ${err.message}` });
    done(1);
    return;
  }

  const killer = setTimeout(() => {
    emit({ ev: 'failed', detail: `the aggregator did not finish the exchange in ${Math.round(timeoutMs / 1000)}s` });
    try { ws.close(); } catch { /* going */ }
    done(1);
  }, timeoutMs);

  const end = (rc) => { clearTimeout(killer); try { ws.close(); } catch { /* going */ } done(rc); };

  // A refusal decided BEFORE the upgrade is an HTTP status and not a frame
  // (the lesson the link's own agent carries): `ws` turns it into a plain
  // `error`, which reads as transient when it is the opposite.
  ws.on('unexpected-response', (_req, res) => {
    const status = res.statusCode ?? 0;
    res.resume();
    emit({
      ev: 'refused',
      code: status === 401 || status === 403 ? 'unauthenticated' : status === 429 ? 'rate_limited' : 'bad_frame',
      detail: status === 404
        ? 'that aggregator has no /fleet/v1/link endpoint, so it predates the fleet link entirely'
        : `the aggregator refused the connection with HTTP ${status}`,
    });
    end(3);
  });

  // #849: set once `pair_done` has gone out, to the exit code the pairing
  // itself earned. From then on the exchange is finished, and the hub closing
  // the socket (at once, in lingerPairing, often before the beat below runs
  // out) is the end of it rather than a failure. The answer is decided by the
  // shell's report, never by which of the two sides closed first.
  let finished = null;

  ws.on('error', (err) => {
    if (settled) return;
    if (finished !== null) { end(finished); return; }
    emit({ ev: 'failed', detail: `the connection to the aggregator failed: ${err.message}` });
    end(1);
  });

  ws.on('close', () => {
    if (settled) return;
    if (finished !== null) { end(finished); return; }
    emit({ ev: 'failed', detail: 'the aggregator closed the connection without finishing the exchange' });
    end(1);
  });

  ws.on('open', () => {
    emit({ ev: 'hello' });
    ws.send(encodeLinkFrame({
      t: 'pair_hello',
      v: V,
      code: job.code,
      label: job.label,
      pubkey_node: job.pubkey_node,
      // Omitted, never sent as undefined or as an empty string, when the
      // shell could not name an address operators reach this node at (#339).
      // JSON.stringify drops an undefined value, so the two spellings look
      // the same on the wire — but the frame this program builds is also
      // what its own tests read, and a key that is present and empty is a
      // different claim from a key that is absent.
      ...(typeof job.dashboard_url === 'string' && job.dashboard_url
        ? { dashboard_url: job.dashboard_url }
        : {}),
      advisor: Boolean(job.advisor),
      dashboard_version: job.dashboard_version ?? null,
      advisord_version: job.advisord_version ?? null,
      node_version: job.node_version ?? null,
      challenge_nonce: job.challenge_nonce,
      // Pairing v2: this node holds the paste already, so ask for the keys
      // before approval. An older aggregator ignores it and answers with
      // the welcome after approval, which is compared the same way.
      keys_first: true,
    }));
  });

  /** `first` until the aggregator's first answer, `welcome` once the keys it
   *  sent early have matched, `settled` once the tokens are away. */
  let stage = 'first';
  /** Pairing v2: the two keys `pair_keys` carried, once they matched the
   *  paste. The welcome must carry these, byte for byte. Empty when the
   *  aggregator sent none (an older one). */
  let checkedTrustKey = '';
  let checkedArmKey = '';
  /** The fleet trust key carried in the welcome, kept once the operator has
   *  compared its fingerprint. The settlement is verified against it. */
  let comparedTrustKey = '';
  /** #741: the fleet arm key the operator's pasted fingerprint covered. The
   *  settlement must carry this one, byte for byte, or nothing is written. */
  let comparedArmKey = '';
  ws.on('message', (data) => {
    void (async () => {
      const parsed = parseLinkFrame(String(data));
      // #741: a welcome with no fleet arm key is an aggregator older than the
      // pairing fingerprint, or one that could not make its key. Refused by
      // name, as an outcome and not a fault: there is nothing to compare the
      // pasted fingerprint against, and a node that paired anyway would be
      // handed a trust key with no arm key its operator had checked.
      if (!parsed.ok && stage !== 'settled') {
        let raw = null;
        try { raw = JSON.parse(String(data)); } catch { /* not JSON: the generic branch below */ }
        if (raw && raw.t === 'pair_welcome' && (typeof raw.fleet_arm_pubkey !== 'string' || !raw.fleet_arm_pubkey)) {
          emit({
            ev: 'refused',
            code: 'no_fleet_arm_key',
            detail: 'the aggregator sent no fleet arm key, so there is no pairing fingerprint to compare. '
              + 'It is older than this node, or it could not make its key: update the aggregator, then pair '
              + 'again with a fresh code. Nothing was sent.',
          });
          end(3);
          return;
        }
      }
      if (!parsed.ok) {
        // An old aggregator's answer to a frame it has never heard of. The
        // mapping is printed here rather than left to an operator: `bad_frame`
        // on the FIRST frame means that hub predates pairing (its handshake
        // says "the first frame on a link is a hello").
        emit({ ev: 'failed', detail: `the aggregator sent a frame this command cannot read: ${parsed.detail}` });
        end(1);
        return;
      }
      const frame = parsed.frame;

      if (frame.t === 'refuse') {
        emit({ ev: 'refused', code: frame.code, detail: frame.detail ?? 'the aggregator gave no reason' });
        end(3);
        return;
      }

      if (stage === 'first' && frame.t === 'pair_keys') {
        // The echo first, as for the welcome: this node named those bytes and
        // nobody else could have.
        if (frame.nonce !== job.challenge_nonce) {
          emit({ ev: 'refused', code: 'bad_signature', detail: 'the aggregator echoed a challenge this command did not send' });
          end(3);
          return;
        }
        const computed = fleetPairingFingerprint(frame.fleet_trust_pubkey, frame.fleet_arm_pubkey);
        const matched = computed !== null && pairingFingerprintMatches(paste, computed);
        // #626: the known-node proof, a MAC under this node's read token over
        // the aggregator's fresh hub_nonce, this node's OWN challenge nonce and
        // node key (never the frame's echo of them), and the trust key just
        // compared. Computed only now, after the operator's paste matched, so
        // it goes only to an aggregator root vouched for. Sent with every
        // match: this node cannot know whether the aggregator already watches
        // it over a tunnel, and a MAC tells an aggregator that does not
        // nothing about the token. The token itself never leaves here before
        // the signed welcome.
        const proof = matched
          ? fleetKnownNodeProof({
            readToken: job.read_token,
            hubNonce: frame.hub_nonce,
            challengeNonce: job.challenge_nonce,
            pubkeyNode: job.pubkey_node,
            fleetTrustPubkey: frame.fleet_trust_pubkey,
          })
          : null;
        // Answered either way, so the aggregator's row says what happened
        // here. A signal for that row and nothing more: this node's own
        // comparison is the gate, and it holds the tokens.
        try {
          ws.send(encodeLinkFrame({ t: 'pair_checked', v: V, matched, ...(proof ? { tunnel_proof: proof } : {}) }));
        } catch { /* the close says it */ }
        if (computed === null) {
          emit({
            ev: 'refused',
            code: 'bad_signature',
            detail: 'the aggregator sent a fleet trust key or a fleet arm key that is not a 32-byte key, '
              + 'so there is no fingerprint to compare. No token was sent and nothing was written.',
          });
          end(3);
          return;
        }
        if (!matched) {
          emit({
            ev: 'mismatch',
            before_approval: true,
            detail: 'that is not this pairing\u2019s fingerprint. The aggregator\u2019s keys do not match what you '
              + 'pasted, so this node is not paired and nothing was sent or written. Nobody was asked to approve it.',
          });
          end(4);
          return;
        }
        checkedTrustKey = frame.fleet_trust_pubkey;
        checkedArmKey = frame.fleet_arm_pubkey;
        stage = 'welcome';
        emit({ ev: 'keys_matched' });
        return;
      }

      if ((stage === 'first' || stage === 'welcome') && frame.t === 'pair_welcome') {
        // THE ECHOES, checked before the signature is verified and before
        // anything is shown to the operator.
        //
        // The nonce and the node key are checked for equality: the nonce is
        // the anti-replay property (this node named bytes nobody had signed)
        // and the node key is what the row will be pinned to.
        //
        // The LABEL is not. The aggregator resolves a link's row from the
        // credential and refuses a hello claiming any other label, so the
        // label the aggregator settled on is the only one that can ever
        // work; refusing it here would refuse the next dial. It is reported
        // instead, and the pause below names it when it changed.
        if (frame.nonce !== job.challenge_nonce) {
          emit({ ev: 'refused', code: 'bad_signature', detail: 'the aggregator echoed a challenge this command did not send' });
          end(3);
          return;
        }
        if (frame.pubkey_node !== job.pubkey_node) {
          emit({ ev: 'refused', code: 'bad_signature', detail: "the aggregator echoed a different node's key" });
          end(3);
          return;
        }
        const message = pairChallengeSigningBytes({
          v: frame.v,
          issuer_label: frame.issuer_label,
          nonce: frame.nonce,
          label: frame.label,
          pubkey_node: frame.pubkey_node,
          fleet_trust_pubkey: frame.fleet_trust_pubkey,
          fleet_arm_pubkey: frame.fleet_arm_pubkey,
          issued_at: frame.issued_at,
        });
        // Pairing v2: the keys this node already checked, or nothing. A
        // welcome is the aggregator's signed word and pair_keys was not, so
        // the two must be the same keys: an aggregator that showed one pair
        // and signs for another is refused before a token leaves.
        if (checkedTrustKey && (frame.fleet_trust_pubkey !== checkedTrustKey || frame.fleet_arm_pubkey !== checkedArmKey)) {
          emit({
            ev: 'refused',
            code: 'bad_signature',
            detail: 'the aggregator\u2019s signed answer carries different keys from the ones this node checked '
              + 'against your fingerprint, so it is refused. No token was sent and nothing was written.',
          });
          end(3);
          return;
        }
        // Verified against the key carried in the SAME frame. That proves
        // possession of the private half and nothing about identity, which
        // is the whole of what trust-on-first-use is: the operator standing
        // at both ends, comparing the fingerprint, is the anchor.
        if (!verifyWithPeerKey(message, frame.signature, frame.fleet_trust_pubkey)) {
          emit({
            ev: 'refused',
            code: 'bad_signature',
            detail: 'the aggregator did not sign its answer with the key it sent, so it cannot prove it holds the fleet trust key',
          });
          end(3);
          return;
        }
        // #741: the pairing fingerprint, over the two keys this node would
        // take. Computed from the SIGNED welcome and held here: it is not
        // emitted before the operator has pasted theirs, because a value this
        // terminal printed is a value an operator could copy straight back,
        // and then nothing would have been compared at all.
        const expected = fleetPairingFingerprint(frame.fleet_trust_pubkey, frame.fleet_arm_pubkey);
        if (!expected) {
          emit({
            ev: 'refused',
            code: 'bad_signature',
            detail: 'the aggregator sent a fleet trust key or a fleet arm key that is not a 32-byte key, '
              + 'so there is no fingerprint to compare. Nothing was sent.',
          });
          end(3);
          return;
        }
        emit({
          ev: 'welcome',
          issuer_label: frame.issuer_label,
          label: frame.label,
          label_changed: frame.label !== job.label,
          fleet_trust_pubkey: frame.fleet_trust_pubkey,
          fleet_arm_pubkey: frame.fleet_arm_pubkey,
          keys_checked: Boolean(checkedTrustKey),
        });
        // The paste held from before the dial. No second question: the
        // operator answered once, and asking again here is how an answer
        // gets copied from the wrong place under time pressure.
        if (!pairingFingerprintMatches(paste, expected)) {
          emit({
            ev: 'mismatch',
            detail: 'that is not this pairing\u2019s fingerprint. The whole value has to match, and it did not, '
              + 'so this node is not paired and nothing was sent or written.',
          });
          end(4);
          return;
        }
        // Bare, the one spelling root prints it in (aperire-fleet-arm
        // --fingerprint), so the node's closing line reads the same as root's.
        emit({ ev: 'matched', fingerprint: expected });
        stage = 'settled';
        // The key the operator just compared. The settlement is verified
        // against THIS and not against anything the next frame carries: a
        // frame that brought its own key would prove only that whoever sent
        // it holds that key's private half (P2-056).
        comparedTrustKey = frame.fleet_trust_pubkey;
        comparedArmKey = frame.fleet_arm_pubkey;
        ws.send(encodeLinkFrame({
          t: 'pair_tokens',
          v: V,
          read_token: job.read_token,
          advisor_token: job.advisor_token ?? null,
        }));
        return;
      }

      if (stage === 'settled' && frame.t === 'pair_settled') {
        if (frame.ok === false) {
          // A no-answer from the aggregator is INDETERMINATE, not a refusal
          // (#312): the broker may have registered this node and then been
          // cut off before it could say so. The node must not write its
          // credential (it has none: the settlement carries it only on ok),
          // but it must not report a clean refusal either, or an operator
          // reads "it failed" when the aggregator may hold the node. A
          // definite refusal (a taken label, a bad signature) stays a
          // refusal.
          const indeterminate = frame.error === 'no_answer';
          emit({
            ev: indeterminate ? 'settle_unconfirmed' : 'settle_refused',
            error: frame.error, detail: frame.detail,
          });
          end(indeterminate ? 2 : 3);
          return;
        }
        // Before anything is reported, and so before the shell writes a
        // byte: the nonce and this node's own key are inside the signed set,
        // so a settlement lifted from another pairing does not verify here.
        const settleMessage = pairSettledSigningBytes({
          nonce: job.challenge_nonce,
          label: frame.label,
          pubkey_node: job.pubkey_node,
          credential_sha256: createHash('sha256').update(frame.credential).digest('hex'),
          fleet_arm_pubkey: frame.fleet_arm_pubkey,
          read_port: frame.read_port,
          advisor_port: frame.advisor_port,
        });
        if (!verifyWithPeerKey(settleMessage, frame.signature, comparedTrustKey)) {
          emit({
            ev: 'refused',
            code: 'bad_signature',
            detail: 'the aggregator did not sign its settlement with the key this command compared, '
              + 'so the credential, the ports and the fleet arm key in it are not the aggregator\u2019s. '
              + 'Nothing was written.',
          });
          end(3);
          return;
        }
        // #741: the arm key this node installs as root is the one the pasted
        // fingerprint covered, or nothing is. A settlement under the right
        // signature carrying a different key (or none) is refused before the
        // shell writes a byte.
        if (frame.fleet_arm_pubkey !== comparedArmKey) {
          emit({
            ev: 'refused',
            code: 'bad_signature',
            detail: frame.fleet_arm_pubkey
              ? 'the aggregator\u2019s settlement carries a different fleet arm key from the one your fingerprint '
                + 'covered, so it is refused. Nothing was written.'
              : 'the aggregator\u2019s settlement carries no fleet arm key, where the welcome you compared did. '
                + 'Nothing was written.',
          });
          end(3);
          return;
        }
        emit({
          ev: 'settled',
          label: frame.label,
          credential: frame.credential,
          fleet_arm_pubkey: frame.fleet_arm_pubkey,
          read_port: frame.read_port,
          advisor_port: frame.advisor_port,
        });
        stage = 'done';
        const line = await nextLine();
        let report = { ok: false, wrote: [] };
        try { report = JSON.parse(String(line ?? '{}')); } catch { /* the shell died mid-write */ }
        ws.send(encodeLinkFrame({
          t: 'pair_done',
          v: V,
          ok: Boolean(report.ok),
          wrote: Array.isArray(report.wrote) ? report.wrote.slice(0, 16).map(String) : [],
        }));
        finished = report.ok ? 0 : 1;
        emit({ ev: 'closed' });
        // A beat for the frame to leave before the socket goes, and the beat
        // is bounded: nothing after this waits on the aggregator. A hub that
        // closes first ends it sooner, with the same code (#849).
        setTimeout(() => end(finished), 250);
        return;
      }

      emit({ ev: 'failed', detail: `the aggregator sent a ${frame.t} where this command expected the ${stage}` });
      end(1);
    })();
  });
});

process.exitCode = code;
lines.close();
