#!/usr/bin/env node
// The push half of `aperire-auth fleet-trust-push` (ADR 0014 decision 4).
//
// Reads ONE job from stdin as JSON — the bash caller assembles it so the
// admin-credential query stays the exact SQL advisor-sync uses (one source
// of "who is an admin"), and this process never touches the database:
//
//   { rp_id, origins:[...], private_key, issuer_label,
//     rows:[{credential_id, public_key, label, user, role}], // ALL operators; admins filtered here
//     targets:[{label, origin, token}] }                 // nodes with an advisor stack
//
// Builds one signed bundle from the admin rows, then POSTs it to each
// target's advisord /v1/trust/bundle over the (loopback) forward with that
// node's approve token. Public keys only leave here; the private key signs
// and is never logged or forwarded. Prints a per-target result line and
// exits non-zero if any push failed, so the caller can report honestly.
import { signBundle } from './trust-bundle.ts';
import { credentialDigest } from './trust-fingerprint.ts';

const job = JSON.parse(await readStdin());

const admins = (job.rows || []).filter((r) => r.role === 'admin');
// user and role ride WITH the credential, inside the signature.
//
// Without them a fleet node holds a key it can verify a signature against and
// no way to say whose key it is — so every approval on the nodes ADR 0014
// targets would be attributed from the request rather than from anything the
// node itself holds, which is the gap this exists to close. Omitted rather
// than sent empty: the Go verifier's `omitempty` and this side must agree on
// what an absent field looks like or the signature will not verify.
const credentials = admins.map((r) => ({
  credential_id: r.credential_id,
  public_key: r.public_key,
  label: r.label || '',
  ...(r.user ? { user: r.user } : {}),
  ...(r.role ? { role: r.role } : {}),
}));

const bundle = {
  rp_id: job.rp_id,
  origins: job.origins,
  credentials,
  serial: credentialDigest(credentials.map((c) => ({ credential_id: c.credential_id, public_key: c.public_key }))),
  issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  issuer_label: job.issuer_label,
};

let signature;
try {
  signature = signBundle(bundle, job.private_key);
} catch (e) {
  console.error('could not sign the bundle: ' + e.message);
  process.exit(2);
}

const body = JSON.stringify({ bundle, signature });
let anyFail = false;

// One line per node, and it is the only thing a caller reads a node's outcome
// from. Everything a node says rides in these lines (its error text, its
// held list's dates), and a node is not trusted to stay on its own line: an
// answer carrying a newline would print a second line wearing another node's
// label. Control characters never get out of here (#1099), and neither do the
// three that do not split a line but stop a regex's `.` (NEL, LS, PS): a node
// that put one in its own answer would erase its own row from the parsers.
// eslint-disable-next-line no-control-regex
const out = (line) => console.log(String(line).replace(/[\u0000-\u001f\u007f\u0085\u2028\u2029]+/g, ' '));

for (const t of job.targets || []) {
  try {
    const r = await fetch(`${t.origin}/v1/trust/bundle`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${t.token}` },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = { error: text.slice(0, 200) }; }
    if (r.ok && parsed.ok && parsed.superseded) {
      // The node already holds a list signed after this one (#990). That is
      // ok only when it is the SAME list: the serial is the digest of the
      // admin credentials, so an equal serial is the same set of passkeys,
      // and this push had nothing to add. A different serial is a different
      // set, wider or narrower than the one this aggregator holds now, and
      // nothing here can prove it current, so it is a failure that says so.
      if (parsed.held_serial && parsed.held_serial === bundle.serial) {
        out(`  ${t.label}: ok — it already holds this list, from a push signed later ` +
          `(issued ${parsed.held_issued_at}); ${parsed.trusted} trusted`);
      } else {
        anyFail = true;
        out(`  ${t.label}: FAILED — it holds a different list, signed later (issued ` +
          `${parsed.held_issued_at}, serial ${String(parsed.held_serial || 'not reported').slice(0, 12)}…), ` +
          `so this one (issued ${bundle.issued_at}, serial ${bundle.serial.slice(0, 12)}…) was not applied. ` +
          `Push again once any other push is done`);
      }
    } else if (parsed.refusal === 'issued_in_future') {
      // The node refused a list dated past its own clock (#990). A failure:
      // that node keeps the set it had until the clocks agree.
      anyFail = true;
      out(`  ${t.label}: FAILED — refused, this aggregator's clock is ${parsed.skew_seconds}s ahead of ` +
        `that node's. Check the clocks on both, then push again`);
    } else if (r.ok && parsed.ok) {
      out(`  ${t.label}: ok — ${parsed.first_install ? 'first install, pinned' : 'updated'}; ` +
        `${parsed.added} added, ${parsed.removed} removed, ${parsed.trusted} trusted (rp_id ${parsed.rp_id})`);
    } else {
      anyFail = true;
      out(`  ${t.label}: FAILED [HTTP ${r.status}] — ${parsed.error || 'unknown'}`);
    }
  } catch (e) {
    anyFail = true;
    // The kind of failure rides as a code after the word, `[timeout]`, so a
    // reader of this line branches on it and never on the words after it
    // (#1184). A refused connection says so, because "fetch failed" does not.
    const timedOut = e && e.name === 'TimeoutError';
    const code = e && e.cause && e.cause.code ? ` (${e.cause.code})` : '';
    out(`  ${t.label}: unreachable${timedOut ? ' [timeout]' : ''} — ` +
      `${timedOut ? 'no answer within 10 seconds' : e.message}${timedOut ? '' : code} ` +
      '(its trust set keeps its previous value until it can be reached)');
  }
}

console.log(`\n${admins.length} admin credential(s) in the bundle, serial ${bundle.serial.slice(0, 12)}…`);
process.exit(anyFail ? 1 : 0);

function readStdin() {
  return new Promise((resolve) => {
    let d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => resolve(d));
  });
}
