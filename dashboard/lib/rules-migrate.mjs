#!/usr/bin/env node
// The runner half of `scripts/migrate-rules-local.sh` (ADR 0020). Thin: the
// logic it calls lives in lib/rules-merge.ts, where it has tests, and is the
// same code the dashboard loads its rules with.
//
// Three modes, all pure file in / file out. Nothing here decides where a file
// is or writes to the live tree; the wrapper does that, so the destructive
// half is in one program an operator can read.
//
//   node --import tsx lib/rules-migrate.mjs --diff --host H --baseline B --out O
//                                            [--current C] [--out-unpruned U]
//       Writes the local override file that reproduces H on top of B, prints
//       one line per difference. Exit 0 when there are differences, 3 when
//       there are none (nothing to migrate), 1 on a file it cannot read.
//       With --current, every difference the RELEASE now ships is dropped
//       first: the baseline is old, and a field that only repeats what the
//       release carries would pin that value on this host for good. Exit 4
//       when the pruning leaves nothing, which is not the same as 3: this
//       host did tune its rules, and the release has since caught up.
//
//   node --import tsx lib/rules-migrate.mjs --prune --local L --current C --out O
//       The same pruning, on a local file that already exists. Idempotent: a
//       second run finds nothing to drop. Exit 0 when something was dropped,
//       3 when nothing was.
//
//   node --import tsx lib/rules-migrate.mjs --verify-prune --current C --before B --after A
//       Checks that pruning changed nothing about what this host will run
//       once it is on the current release.
//
//   node --import tsx lib/rules-migrate.mjs --verify --host H --baseline B --local L
//       Merges B with L and checks the result is the rule set H holds. This
//       is what makes the migration safe to run: nothing is replaced until
//       the replacement has been shown to reproduce what this host runs.
//
//   node --import tsx lib/rules-migrate.mjs --summarise --shipped S --local L
//       Prints what the local file does to a shipped set: the counts the
//       dashboard's own load line carries.
import { readFileSync, writeFileSync } from 'node:fs';
import yaml from 'js-yaml';
import {
  diffRulesForLocal, pruneAgainstCurrent, mergeRuleFiles, describeMerge, ruleKey,
} from './rules-merge.ts';

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : null;
};
const has = (name) => argv.includes(`--${name}`);

const read = (path, what) => {
  try {
    return readFileSync(path, 'utf8');
  } catch (e) {
    console.error(`cannot read ${what} (${path}): ${e.message}`);
    process.exit(1);
  }
};

/** Every rule a loaded set holds, keyed, with the fields an override carries.
 *  Comments and ordering are not part of what a host RUNS, so they are not
 *  part of what the verification compares. */
const shape = (rules) => {
  const out = new Map();
  for (const r of rules) {
    if (!r || typeof r !== 'object') continue;
    const metric = typeof r.metric === 'string' ? r.metric : '';
    const sev = String(r.severity ?? '').toLowerCase();
    if (!metric || !['warn', 'critical', 'page'].includes(sev)) continue;
    out.set(ruleKey(metric, sev), JSON.stringify({
      threshold: r.threshold ?? null,
      duration: r.duration ?? null,
      channels: r.channels ?? null,
      action: r.action ?? null,
      action_command: r.action_command ?? null,
    }));
  }
  return out;
};

const rulesOf = (text) => {
  const doc = yaml.load(text);
  return Array.isArray(doc?.rules) ? doc.rules : [];
};

/** The local file as it is written: a header saying where it came from, then
 *  the entries. flowLevel 3 puts a threshold and a channel list on one line
 *  each, which is how the shipped file reads and how somebody writes one by
 *  hand. */
const render = (entries, how) => {
  const stamp = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const came = {
    migrate: `from the difference between this host's tuned rules.yaml and the
# shipped file it was tuned from.`,
    'migrate-pruned': `from the difference between this host's tuned rules.yaml and the
# shipped file it was tuned from, with everything the release itself now
# ships dropped: what is left is what this host still says differently.`,
    prune: `by pruning this file against the rules the release now ships. What is
# left is what this host still says differently.`,
  }[how];
  const header = `# Aperire alert rules, yours.
#
# This file overrides config/rules.yaml, the set the product ships, by metric
# and severity. Nothing writes it but you: no install, no update, no fleet
# deploy. Delete an entry and this host runs the shipped rule again.
#
# Written by scripts/migrate-rules-local.sh on ${stamp},
# ${came}
# Read them: an entry here stops this host receiving any later correction to
# that field, which is the price of keeping your own value.
#
# Apply changes without a restart:
#     sudo systemctl reload aperire-server
`;
  return `${header}\n${yaml.dump({ rules: entries }, { lineWidth: 100, noRefs: true, flowLevel: 3 })}`;
};

if (has('diff')) {
  const host = read(flag('host'), "this host's rules.yaml");
  const baseline = read(flag('baseline'), 'the baseline rules.yaml');
  let d;
  try {
    d = diffRulesForLocal(host, baseline);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  for (const line of d.lines) console.log(line);
  console.log(`counts: ${d.counts.overrides} override(s), ${d.counts.added} added, ${d.counts.disabled} disabled`);
  if (d.entries.length === 0) process.exit(3);

  // The unpruned set is written when asked for, because it is what the
  // caller's first guard is measured against: it has to reproduce this host
  // exactly, whatever the pruning then takes out of it.
  const unprunedOut = flag('out-unpruned');
  if (unprunedOut) writeFileSync(unprunedOut, render(d.entries, 'migrate'));

  let entries = d.entries;
  let how = 'migrate';
  const currentPath = flag('current');
  if (currentPath) {
    const current = read(currentPath, 'the current shipped rules');
    const p = pruneAgainstCurrent(entries, current);
    console.log('\n-- of that, what the release already ships:');
    if (p.lines.length === 0) console.log('nothing: every difference above is still this host\'s own');
    for (const line of p.lines) console.log(line);
    console.log(`pruned: ${p.counts.droppedEntries} entr(ies) dropped, `
      + `${p.counts.droppedFields} field(s) dropped, ${p.counts.kept} kept`);
    entries = p.entries;
    how = 'migrate-pruned';
    // Everything this host said differently is what the release now says.
    // Not "nothing to migrate": rules.yaml still has to be replaced.
    if (entries.length === 0) process.exit(4);
  }

  const out = flag('out');
  if (out) writeFileSync(out, render(entries, how));
  else process.stdout.write(`\n${render(entries, how)}`);
  process.exit(0);
}

if (has('prune')) {
  const localPath = flag('local');
  const local = read(localPath, 'the local override file');
  const current = read(flag('current'), 'the current shipped rules');
  const before = rulesOf(local);
  let p;
  try {
    p = pruneAgainstCurrent(before, current);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  for (const line of p.lines) console.log(line);
  console.log(`pruned: ${p.counts.droppedEntries} entr(ies) dropped, `
    + `${p.counts.droppedFields} field(s) dropped, ${p.counts.kept} kept`);
  if (p.counts.droppedEntries === 0 && p.counts.droppedFields === 0) process.exit(3);
  const out = flag('out');
  if (out) writeFileSync(out, render(p.entries, 'prune'));
  else process.stdout.write(`\n${render(p.entries, 'prune')}`);
  process.exit(0);
}

if (has('verify-prune')) {
  // Pruning is only ever allowed to remove what the release itself says. So
  // the test is not "are the files the same" but "does this host run the same
  // rules once it is on the release the pruning was measured against".
  const current = read(flag('current'), 'the current shipped rules');
  const before = read(flag('before'), 'the local file before pruning');
  const after = read(flag('after'), 'the local file after pruning');
  const a = mergeRuleFiles(current, before);
  const b = mergeRuleFiles(current, after);
  for (const [label, m] of [['before', a], ['after', b]]) {
    if (m.localError) {
      console.error(`the ${label} file would not load against the current rules: ${m.localError}`);
      process.exit(1);
    }
  }
  const want = shape(a.rules);
  const got = shape(b.rules);
  const problems = [];
  for (const [key, body] of want) {
    if (!got.has(key)) problems.push(`${key.replace(':', ' ')} would be lost`);
    else if (got.get(key) !== body) problems.push(`${key.replace(':', ' ')} would change`);
  }
  for (const key of got.keys()) {
    if (!want.has(key)) problems.push(`${key.replace(':', ' ')} would appear from nowhere`);
  }
  if (problems.length) {
    console.error('pruning would change what this host runs on the current release:');
    for (const p of problems) console.error(`  ${p}`);
    process.exit(1);
  }
  console.log(`verified: ${want.size} rules, pruning changes nothing this host will run`);
  process.exit(0);
}

if (has('verify')) {
  const host = read(flag('host'), "this host's rules.yaml");
  const baseline = read(flag('baseline'), 'the baseline rules.yaml');
  const local = read(flag('local'), 'the local override file');
  const merged = mergeRuleFiles(baseline, local);
  if (merged.localError) {
    console.error(`the local file would not load: ${merged.localError}`);
    process.exit(1);
  }
  const want = shape(rulesOf(host));
  const got = shape(merged.rules);
  const problems = [];
  for (const [key, body] of want) {
    if (!got.has(key)) problems.push(`${key.replace(':', ' ')} would be lost`);
    else if (got.get(key) !== body) problems.push(`${key.replace(':', ' ')} would change`);
  }
  for (const key of got.keys()) {
    if (!want.has(key)) problems.push(`${key.replace(':', ' ')} would appear from nowhere`);
  }
  if (problems.length) {
    console.error('the migration would not reproduce what this host runs:');
    for (const p of problems) console.error(`  ${p}`);
    process.exit(1);
  }
  console.log(`verified: ${want.size} rules, identical to what this host runs`);
  process.exit(0);
}

if (has('summarise')) {
  const shipped = read(flag('shipped'), 'the shipped rules.yaml');
  const localPath = flag('local');
  let local = null;
  try {
    local = readFileSync(localPath, 'utf8');
  } catch { /* absent is the normal case */ }
  const m = mergeRuleFiles(shipped, local);
  if (m.localError) {
    console.error(m.localError);
    process.exit(1);
  }
  console.log(`${m.rules.length} rules in force; ${describeMerge(m)}`);
  process.exit(0);
}

console.error('one of --diff, --prune, --verify, --verify-prune or --summarise is required');
process.exit(2);
