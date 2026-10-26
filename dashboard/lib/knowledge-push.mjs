#!/usr/bin/env node
// The runner half of `aperire-knowledge-push` (ADR 0017 decision 3). Two
// modes, both thin: the logic they call lives in lib/knowledge-push.ts,
// where it has tests.
//
//   node --import tsx lib/knowledge-push.mjs --reserve-seq <bundle-dir> <by>
//       prints the reserved sequence number and exits. Reserved before
//       anything is built, so a number is spent whether or not the push
//       that follows works.
//
//   node --import tsx lib/knowledge-push.mjs   (job JSON on stdin)
//       signs the manifest and pushes.
//
// The job is assembled by the caller so the archive and the manifest are
// built in a single pass over the corpus (they must describe the same set of
// files or every node refuses the bundle), and this process never walks the
// filesystem itself:
//
//   { manifest: {seq, files:[{path, sha256}], created_at, issuer_label, pushed_by},
//     bundle_path: "…/knowledge-7.tar.gz",
//     private_key: "<b64url seed>",
//     replace_fleet_corpus: true | false,
//     targets: [{label, origin, token}] }
//
// The private key signs and is never logged or forwarded. Per-target result
// lines go to stdout for a person; the machine-readable copy is written to
// the file named by APERIRE_PUSH_RESULT, when it is set, so a caller that
// needs the results never has to parse this program's prose.
//
// Exit codes: 0 every node applied it, 1 a node did not, 2 the job could not
// be read or signed, 4 a node had already applied a higher sequence than this
// aggregator's counter, which has been moved past it (#1218), 5 nothing was
// sent because the push could delete notes this host cannot account for
// (#1236), with the one-line form of the refusal written to the result file as
// {refused, seq}. The script builds the bundle again on a 4, once.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { signManifest } from './knowledge-bundle.ts';
import { reserveSeq, raiseSeq, counterBehind, pushGuarded, describePushResult } from './knowledge-push.ts';

const argv = process.argv.slice(2);
if (argv[0] === '--reserve-seq') {
  const dir = argv[1];
  if (!dir) { console.error('--reserve-seq needs the bundle directory'); process.exit(2); }
  try {
    process.stdout.write(String(reserveSeq(dir, argv[2] || 'unknown')) + '\n');
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
  process.exit(0);
}

const job = JSON.parse(await readStdin());
const manifest = job.manifest;

let bundle;
try {
  bundle = readFileSync(job.bundle_path).toString('base64');
} catch (e) {
  console.error('could not read the bundle: ' + e.message);
  process.exit(2);
}

let sig;
try {
  sig = signManifest(manifest, job.private_key);
} catch (e) {
  console.error('could not sign the manifest: ' + e.message);
  process.exit(2);
}

// Each node is asked what it holds before anything is sent (#1236). A push
// replaces a node's whole corpus, so one that could delete notes under local/
// this host has no record of delivering is refused here, whole, unless the
// operator passed --replace-fleet-corpus. Nodes that apply it are written to
// the delivery record, which is what the next push is checked against.
const resultPath = process.env.APERIRE_PUSH_RESULT;
const guarded = await pushGuarded(job.targets || [], JSON.stringify({ bundle, manifest, sig }), {
  seq: manifest.seq,
  paths: manifest.files.map((f) => f.path),
  bundleDir: dirname(job.bundle_path),
  replace: job.replace_fleet_corpus === true,
});
if (guarded.refusal) {
  console.error(guarded.refusal);
  // The caller that shows one line per result (the Promote card) reads this
  // instead of the whole output, which is mostly the build.
  if (resultPath) writeFileSync(resultPath, JSON.stringify({ refused: guarded.summary, seq: manifest.seq }) + '\n', { mode: 0o640 });
  process.exit(5);
}
if (guarded.replaced) console.log(guarded.replaced + '\n');
if (guarded.recordError) {
  console.error(`could not record what was delivered (${guarded.recordError}). The next push will not know ` +
    'what these nodes hold and will ask for --replace-fleet-corpus.');
}
const results = guarded.results;
for (const r of results) console.log(describePushResult(r));

if (resultPath) {
  // Written before the summary line, and to a file rather than to stdout:
  // this program's stdout is prose that a person reads and a shell caller
  // echoes, and a machine-readable channel sharing it would break on the
  // first "Building bundle 4..." somebody adds upstream.
  writeFileSync(resultPath, JSON.stringify({
    seq: manifest.seq, files: manifest.files.length, pushed_by: manifest.pushed_by,
    created_at: manifest.created_at, nodes: results,
  }, null, 2) + '\n', { mode: 0o640 });
}

console.log(`\n${manifest.files.length} file(s) in the bundle, sequence ${manifest.seq}, ` +
  `pushed by ${manifest.pushed_by}.`);

// A node that has applied a higher sequence than the one this aggregator just
// spent means the counter lost its place (#1218): the file is gone after a
// wipe, a restore or a move, and the first number after that is 1. The nodes
// are right to refuse it. The counter moves up to the highest one reported,
// so the next reservation is past every node, and the caller builds again.
const behind = counterBehind(results, manifest.seq);
if (behind) {
  let counter;
  try {
    counter = raiseSeq(dirname(job.bundle_path), behind.applied, manifest.pushed_by, behind.label);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  console.log(`\nThis aggregator's push counter was behind the fleet. ${behind.label} has applied ` +
    `sequence ${behind.applied} and this bundle carried ${manifest.seq}. A wipe, a restore or a move ` +
    `to a new host loses the record of what was pushed. The counter is now at ${counter}, ` +
    `so the next push is sequence ${counter + 1}.`);
  process.exit(4);
}
process.exit(results.some((r) => !r.ok) ? 1 : 0);

function readStdin() {
  return new Promise((resolve) => {
    let d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => resolve(d));
  });
}
