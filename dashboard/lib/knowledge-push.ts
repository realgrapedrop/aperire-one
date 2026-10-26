/**
 * The shared half of pushing a fleet knowledge bundle — ADR 0017 decision 3.
 *
 * `scripts/aperire-knowledge-push.sh` orchestrates: it lints, builds the
 * archive and the manifest in one pass (lib/knowledge-bundle-job.py, which
 * has to build both together or the node refuses the mismatch), and hands
 * the job to `lib/knowledge-push.mjs`. What lives HERE is everything that is
 * neither shell nor archive: reserving the sequence, and the push loop with
 * its per-target result.
 *
 * Both are here rather than in the runner so they have unit tests and one
 * definition. The sequence in particular used to be an `awk -F'[^0-9]+'`
 * over a JSON file, which is a parser nobody can test and everybody has to
 * trust.
 *
 * The route that promotes a proposal does NOT re-implement any of this. It
 * spawns the same script an operator runs, for the reason lib/
 * trust-push-hook.ts already states about the trust bundle: one
 * implementation of build/sign/push, and the private key stays out of the
 * web process's heap.
 */
import { existsSync, mkdirSync, chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** One node's answer to one push. */
export interface PushResult {
  label: string;
  ok: boolean;
  /** Present when the node applied the bundle. */
  seq?: number;
  files?: number;
  added?: number;
  changed?: number;
  removed?: number;
  /** Present when it did not, in the node's own words. */
  error?: string;
}

export interface PushTarget {
  label: string;
  origin: string;
  token: string;
}

/** What the counter file says, or 0 when there is none. Shared by the two
 *  writers below, so neither can read it differently. */
function readSeq(seqFile: string): number {
  if (!existsSync(seqFile)) return 0;
  try {
    const parsed = JSON.parse(readFileSync(seqFile, 'utf8')) as { seq?: unknown };
    if (typeof parsed.seq === 'number' && Number.isFinite(parsed.seq)) return Math.floor(parsed.seq);
    return 0;
  } catch (err) {
    // A seq file that cannot be read is the one failure this must not
    // paper over: continuing from 0 would mint a number every node has
    // already seen, and every node would refuse the push with a rollback
    // error that names nothing about this file.
    throw new Error(`${seqFile} is unreadable (${(err as Error).message}); ` +
      'the next sequence cannot be chosen without it. Fix or remove the file, ' +
      'knowing that removing it restarts at 1 and every node will refuse that as a replay.',
    { cause: err });
  }
}

function writeSeq(seqFile: string, seq: number, by: string, now: Date, extra: Record<string, unknown> = {}): void {
  writeFileSync(seqFile, JSON.stringify({
    seq, reserved_at: now.toISOString().replace(/\.\d+Z$/, 'Z'), reserved_by: by, ...extra,
  }) + '\n', { mode: 0o640 });
}

/**
 * Reserves the next sequence number, writing it before anything is pushed.
 *
 * Reserved BEFORE the push, never after, and spent whether the push
 * succeeded, failed, or died halfway. A number that reached one node and was
 * then reused for different content would be refused by that node forever —
 * the node's rollback guard cannot tell "the same number twice" from an
 * attacker replaying an older corpus, and it is right not to.
 */
export function reserveSeq(bundleDir: string, by: string, now: Date = new Date()): number {
  mkdirSync(bundleDir, { recursive: true, mode: 0o750 });
  try { chmodSync(bundleDir, 0o750); } catch { /* an existing dir someone else owns is not ours to widen */ }
  const seqFile = join(bundleDir, 'seq.json');
  const seq = readSeq(seqFile) + 1;
  writeSeq(seqFile, seq, by, now);
  return seq;
}

/** The refusal a node gives a sequence it has already passed
 *  (advisor/internal/knowledge/bundle.go, CheckSequence). A unit test holds
 *  the two wordings together. Anchored at both ends: the text is a node's
 *  reply, so an unanchored match backtracks without bound on a long one and
 *  also takes a 409 tag from the middle of some other status's body. */
const SEQ_REFUSAL = /^\[HTTP 409\] .*this node has applied sequence (\d+) and the bundle carries \d+$/;

/** No counter a person reaches: one push a second for thirty years is under
 *  this. A node that claims more is wrong or hostile, and believing it would
 *  move the counter somewhere the numbers stop being exact. */
export const MAX_RECOVERABLE_SEQ = 1_000_000_000;

/**
 * When a node refused the bundle because it had already applied a higher
 * sequence, this aggregator's counter is behind: it lost its record of what it
 * pushed (a wipe, a restore or a move to a new host does that) and started
 * again at 1 while the fleet sits at 44. Returns the highest sequence any node
 * reports, and the node that reported it, or null when no refusal was about
 * the sequence. Refusals for a bad hash or signature, and nodes that could not
 * be reached, say nothing about the counter.
 */
export function counterBehind(results: PushResult[], bundleSeq: number): { applied: number; label: string } | null {
  let best: { applied: number; label: string } | null = null;
  for (const r of results) {
    if (r.ok || !r.error) continue;
    const m = SEQ_REFUSAL.exec(r.error);
    if (!m) continue;
    const applied = Number(m[1]);
    if (applied < bundleSeq || applied > MAX_RECOVERABLE_SEQ) continue;
    if (!best || applied > best.applied) best = { applied, label: r.label };
  }
  return best;
}

/**
 * Moves the counter up to what the fleet has applied, never down. The next
 * reservation is then past every number any node has seen. Raise-only on
 * purpose: a lower number from a node must never pull a counter back to a
 * value another node has already used.
 */
export function raiseSeq(bundleDir: string, atLeast: number, by: string, from: string, now: Date = new Date()): number {
  const seqFile = join(bundleDir, 'seq.json');
  const prev = readSeq(seqFile);
  if (atLeast <= prev) return prev;
  writeSeq(seqFile, atLeast, by, now, { raised_to_match: from });
  return atLeast;
}

/** The pin the field-guide pull keeps, in the same state home as the
 *  sequence: one directory that holds what this aggregator has pushed and
 *  what it pulled to build it (ADR 0017 decision 6 — no git on the boxes, so
 *  these files plus the archived bundles are the history). */
export interface FieldGuidePin {
  repo: string;
  ref: string;
  commit: string;
  pulled_at: string;
  pulled_by: string;
  /** path → content hash, for the next pull's diff. */
  files: Record<string, string>;
}

export function readFieldGuidePin(bundleDir: string): FieldGuidePin | null {
  const p = join(bundleDir, 'field-guide.json');
  if (!existsSync(p)) return null;
  try {
    const parsed = JSON.parse(readFileSync(p, 'utf8')) as FieldGuidePin;
    if (!parsed || typeof parsed.commit !== 'string') return null;
    if (!parsed.files || typeof parsed.files !== 'object') parsed.files = {};
    return parsed;
  } catch {
    // A pin that cannot be read means "never pulled" rather than an error:
    // the worst it costs is a first-pull diff that lists every file, which
    // is honest, and the alternative is a card that cannot be opened.
    return null;
  }
}

export function writeFieldGuidePin(bundleDir: string, pin: FieldGuidePin): void {
  mkdirSync(bundleDir, { recursive: true, mode: 0o750 });
  writeFileSync(join(bundleDir, 'field-guide.json'), JSON.stringify(pin, null, 2) + '\n', { mode: 0o640 });
}

type FetchImpl = typeof fetch;

/**
 * POSTs one already-signed bundle to every target, in order, and reports
 * each node separately.
 *
 * Never throws and never stops early: a fleet where one node is down must
 * still receive the bundle everywhere else, and the caller has to be able to
 * say which node did not take it. A node that refuses keeps the knowledge it
 * had — the bundle is applied whole or not at all on its side.
 */
export async function pushToTargets(
  targets: PushTarget[],
  body: string,
  opts: { fetchImpl?: FetchImpl; timeoutMs?: number } = {},
): Promise<PushResult[]> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const out: PushResult[] = [];
  for (const t of targets) {
    try {
      const r = await doFetch(`${t.origin}/v1/knowledge/bundle`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${t.token}` },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await r.text();
      let parsed: Record<string, unknown>;
      try { parsed = JSON.parse(text) as Record<string, unknown>; } catch { parsed = { error: text.slice(0, 200) }; }
      if (r.ok && parsed.ok === true) {
        out.push({
          label: t.label, ok: true,
          seq: Number(parsed.seq), files: Number(parsed.files),
          added: Number(parsed.added), changed: Number(parsed.changed), removed: Number(parsed.removed),
        });
      } else {
        out.push({ label: t.label, ok: false, error: `[HTTP ${r.status}] ${String(parsed.error ?? 'unknown')}` });
      }
    } catch (err) {
      out.push({
        label: t.label, ok: false,
        error: `unreachable — ${(err as Error).message} (its knowledge keeps its previous value until it can be reached)`,
      });
    }
  }
  return out;
}

/**
 * What a node holds, set against what this push would leave it (#1236).
 *
 * A bundle is the whole corpus: a node applies it by removing every file it
 * does not carry. So an aggregator whose own corpus is smaller than the
 * fleet's (a restore, a move to a new host, a wipe, and nothing brings the
 * corpus back, because the backup set leaves it out on purpose) would delete
 * the difference on every node it reaches, and the notes promoted to local/
 * may exist nowhere else. The node answers "N removed" only after the files
 * are gone.
 *
 * So before anything is sent, each node is asked which bundle it last applied
 * (GET /v1/status, the knowledge block), and this host's DELIVERY RECORD says
 * what it delivered to that node under that sequence. The record is written
 * only when a node answers that it applied a bundle. A manifest in the archive
 * is not evidence: it is written when a bundle is built, before and whether or
 * not any node took it, so a refused run, a dry run or a failed push leaves
 * one describing a corpus no node holds.
 */
export interface HeldCheck {
  label: string;
  /** The sequence the node last applied; null when it never applied one. */
  held: number | null;
  /** Why its status could not be read. Such a node is not pushed to. */
  unreadable?: string;
  /** It holds a bundle this host has no record of delivering to it. */
  unknown?: boolean;
  /** It reports no bundle, but this host delivered this one to it: a receipt
   *  that did not survive, or a node that was wiped. */
  deliveredSeq?: number;
  /** Files in what this host delivered to it that this bundle does not carry. */
  drops: string[];
}

/** What this host delivered to one node: the sequence it applied and the paths. */
export interface Delivery { seq: number; paths: string[]; at: string }
export type DeliveryBook = Record<string, Delivery>;

const DELIVERED_FILE = 'delivered.json';

/** A file that is not there reads as nothing delivered, and so does one that
 *  does not parse: a node that is then found to hold a bundle is unknown, which
 *  refuses. Entries that do not parse are dropped one by one, for the same
 *  reason. A file that is there and cannot be read is different, and throws:
 *  the record exists, so "nothing delivered" would be untrue, and the person
 *  has to hear which file and why (a push run by another account leaves it
 *  theirs). */
export function readDelivered(bundleDir: string): DeliveryBook {
  const file = join(bundleDir, DELIVERED_FILE);
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw new Error(`${file} cannot be read (${(err as Error).message}), so this host cannot tell what it delivered to the nodes`, { cause: err });
  }
  const book: DeliveryBook = {};
  try {
    const raw = JSON.parse(text) as Record<string, unknown>;
    for (const [label, e] of Object.entries(raw ?? {})) {
      const d = e as Partial<Delivery> | null;
      if (!d || typeof d.seq !== 'number' || !Number.isSafeInteger(d.seq) || d.seq < 1) continue;
      if (!Array.isArray(d.paths) || !d.paths.every((p) => typeof p === 'string')) continue;
      book[label] = { seq: d.seq, paths: d.paths as string[], at: String(d.at ?? '') };
    }
  } catch { /* broken: nothing is on record */ }
  return book;
}

/** Writes what nodes just applied, beside the others, by rename. */
export function recordDelivered(bundleDir: string, entries: { label: string; seq: number; paths: string[] }[],
  now: Date = new Date()): void {
  if (!entries.length) return;
  mkdirSync(bundleDir, { recursive: true, mode: 0o750 });
  const book = readDelivered(bundleDir);
  const at = now.toISOString().replace(/\.\d+Z$/, 'Z');
  for (const e of entries) book[e.label] = { seq: e.seq, paths: [...e.paths].sort(), at };
  const file = join(bundleDir, DELIVERED_FILE);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(book, null, 2) + '\n', { mode: 0o640 });
  renameSync(tmp, file);
}

/** The layer a pull can rebuild. A promoted note under local/ has no other copy. */
const REBUILDABLE_LAYER_PREFIX = 'base/';

async function readApplied(t: PushTarget, doFetch: FetchImpl, timeoutMs: number):
Promise<{ held: number | null } | { unreadable: string }> {
  try {
    const r = await doFetch(`${t.origin}/v1/status`, {
      headers: { authorization: `Bearer ${t.token}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await r.text();
    if (!r.ok) return { unreadable: `[HTTP ${r.status}] ${text.slice(0, 120).replace(/\s+/g, ' ')}` };
    const body = JSON.parse(text) as { read_only?: unknown; knowledge?: { seq?: unknown } | null };
    // Only the Advisor's own status counts. A 2xx from anything else (a proxy,
    // an error page that happens to be JSON) says nothing about what is on the
    // node, and "no knowledge block" must not be read out of it.
    if (!body || typeof body !== 'object' || body.read_only !== true) {
      return { unreadable: 'it did not answer with an Advisor status' };
    }
    // No knowledge block is the node saying it has never applied a bundle,
    // which is a fact, and different from a status that could not be read.
    if (body.knowledge === undefined || body.knowledge === null) return { held: null };
    const seq = body.knowledge.seq;
    if (typeof seq === 'number' && Number.isSafeInteger(seq) && seq >= 1) return { held: seq };
    return { unreadable: 'its status has a knowledge block with no usable sequence' };
  } catch (err) {
    return { unreadable: (err as Error).message };
  }
}

/** Asks every target what it holds. `paths` is what the new bundle carries. */
export async function checkNodeHoldings(
  targets: PushTarget[],
  paths: string[],
  book: DeliveryBook,
  opts: { fetchImpl?: FetchImpl; timeoutMs?: number } = {},
): Promise<HeldCheck[]> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const carried = new Set(paths);
  // In parallel: Promote ends the script at 180 s, and a slow node's status
  // read must not be added to every other node's.
  return Promise.all(targets.map(async (t): Promise<HeldCheck> => {
    const a = await readApplied(t, doFetch, timeoutMs);
    if ('unreadable' in a) return { label: t.label, held: null, unreadable: a.unreadable, drops: [] };
    const delivered = Object.hasOwn(book, t.label) ? book[t.label] : undefined;
    // An Advisor with no receipt has never applied a bundle, or has lost the
    // record of it: the advisord logs a failed receipt write and carries on
    // with the files in place. What this host delivered to it is the better
    // guess, and costs a confirmation only when the push drops those files.
    if (a.held === null) {
      return delivered
        ? { label: t.label, held: null, deliveredSeq: delivered.seq, drops: delivered.paths.filter((p) => !carried.has(p)).sort() }
        : { label: t.label, held: null, drops: [] };
    }
    if (!delivered || delivered.seq !== a.held) return { label: t.label, held: a.held, unknown: true, drops: [] };
    return { label: t.label, held: a.held, drops: delivered.paths.filter((p) => !carried.has(p)).sort() };
  }));
}

/** A drop this host cannot take back: not under base/, which a pull rebuilds. */
const unrecoverable = (c: HeldCheck): string[] => c.drops.filter((p) => !p.startsWith(REBUILDABLE_LAYER_PREFIX));

function listSome(paths: string[], n = 5): string {
  const shown = paths.slice(0, n).join(', ');
  return paths.length > n ? `${shown}, and ${paths.length - n} more` : shown;
}

/** The sentence per node that stops a push, or [] when nothing stops it. */
function problemLines(checks: HeldCheck[]): string[] {
  const lines: string[] = [];
  for (const c of checks) {
    if (c.unknown) {
      lines.push(`  ${c.label}: holds bundle ${c.held}, and this host has no record of delivering it, ` +
        'so it cannot say what this push would remove.');
      continue;
    }
    const lost = unrecoverable(c);
    if (lost.length && c.held === null) {
      lines.push(`  ${c.label}: reports no bundle, but this host delivered bundle ${c.deliveredSeq} to it, ` +
        `and this push would delete ${lost.length} file(s) of it, outside base/, that this corpus does not carry: ${listSome(lost)}.`);
      continue;
    }
    if (lost.length) {
      lines.push(`  ${c.label}: holds ${lost.length} file(s) from bundle ${c.held}, outside base/, that this corpus does not carry, ` +
        `and this push would delete them: ${listSome(lost)}.`);
    }
  }
  return lines;
}

/** The refusal, in full, or null when the push may go. */
export function refusalFor(checks: HeldCheck[]): string | null {
  const lines = problemLines(checks);
  if (!lines.length) return null;
  return [
    'Refusing to push. It could delete notes the fleet holds that this host cannot account for. Nothing was sent.',
    '',
    ...lines,
    '',
    'A push replaces a node\'s whole corpus, and the notes under local/ may exist on the nodes only.',
    'If you removed those notes on purpose, confirm it by running the push again with --replace-fleet-corpus added.',
    'If this host lost its corpus (a restore, a move, a wipe), copy it back from a node that has it first. Promote',
    'writes there as the dashboard\'s account, so run the copy as that account:',
    '  sudo -u <dashboard account> rsync -rt <node>:<install dir>/advisor/knowledge-fleet/ <this install dir>/advisor/knowledge-fleet/',
    'If that account cannot reach the node, copy as yourself and give the files the owner, group and modes of the folder.',
    'Then run the push again with --replace-fleet-corpus added. This host keeps a record of what it delivers to each',
    'node, and has none until it has pushed.',
  ].join('\n');
}

/** The same refusal on one line, for a card that shows one line per result. */
export function refusalSummary(checks: HeldCheck[]): string | null {
  const bad = checks.filter((c) => c.unknown || unrecoverable(c).length);
  if (!bad.length) return null;
  const who = bad.map((c) => c.unknown
    ? `${c.label} (holds bundle ${c.held}, no record of delivering it)`
    : `${c.label} (${unrecoverable(c).length} file(s) outside base/)`).join(', ');
  return `Not pushed: it could delete notes the fleet holds that this host cannot account for: ${who}. ` +
    'Nothing was sent. Run aperire-knowledge-push on this host to see how to go on.';
}

export interface GuardedPush {
  /** Set when nothing was sent, with the whole text to show. */
  refusal: string | null;
  /** The same on one line, set with `refusal`. */
  summary: string | null;
  /** Per node, in target order. Empty when refused. */
  results: PushResult[];
  /** Set when `replace` was given and there was something it replaced. */
  replaced: string | null;
  /** Set when a node applied the bundle and the record of it could not be written. */
  recordError: string | null;
}

/**
 * pushToTargets, behind the check above. A node whose status cannot be read
 * is not pushed to, with or without `replace`: what it holds is unknown, and
 * the others still get the bundle. Anything else that would delete what this
 * host cannot account for refuses the whole push, unless `replace` says the
 * operator means it. Every node that applies the bundle is written to the
 * delivery record, which is what the next push is checked against.
 */
export async function pushGuarded(
  targets: PushTarget[],
  body: string,
  o: { seq: number; paths: string[]; bundleDir: string; replace: boolean;
       fetchImpl?: FetchImpl; timeoutMs?: number; statusTimeoutMs?: number },
): Promise<GuardedPush> {
  let book: DeliveryBook = {};
  try {
    book = readDelivered(o.bundleDir);
  } catch (err) {
    // Present and unreadable. A confirmed push goes on without it, as it would
    // without any record; anything else stops here, naming the file.
    if (!o.replace) {
      const text = `Refusing to push. ${(err as Error).message}. Nothing was sent.\n` +
        'Run the push as the account that owns that file, or confirm it by running the push again with --replace-fleet-corpus added.';
      return { refusal: text, summary: `Not pushed: ${(err as Error).message}. Nothing was sent. Run aperire-knowledge-push on this host to see how to go on.`,
        results: [], replaced: null, recordError: null };
    }
  }
  const checks = await checkNodeHoldings(targets, o.paths, book,
    { fetchImpl: o.fetchImpl, timeoutMs: o.statusTimeoutMs });
  const refusal = o.replace ? null : refusalFor(checks);
  if (refusal) return { refusal, summary: refusalSummary(checks), results: [], replaced: null, recordError: null };
  const sent = await pushToTargets(targets.filter((_, i) => !checks[i].unreadable), body,
    { fetchImpl: o.fetchImpl, timeoutMs: o.timeoutMs });
  // By position, never by label: two targets may share one, and a remap by
  // label would show one node's answer as the other's.
  let next = 0;
  const results = targets.map((t, i): PushResult => checks[i].unreadable
    ? {
      label: t.label, ok: false,
      error: `not pushed: what it holds could not be checked (${checks[i].unreadable}). Its knowledge keeps its previous value until it can be reached`,
    }
    : sent[next++]);
  let recordError: string | null = null;
  try {
    recordDelivered(o.bundleDir, results.filter((r) => r.ok && r.seq === o.seq)
      .map((r) => ({ label: r.label, seq: o.seq, paths: o.paths })));
  } catch (err) {
    recordError = (err as Error).message;
  }
  const lines = problemLines(checks);
  const replaced = o.replace && lines.length
    ? ['Replacing what these nodes hold, as asked:', ...lines].join('\n')
    : null;
  return { refusal: null, summary: null, results, replaced, recordError };
}

/** One human line per node, for the CLI and for the server's log. */
export function describePushResult(r: PushResult): string {
  return r.ok
    ? `  ${r.label}: ok — sequence ${r.seq}; ${r.added} added, ${r.changed} changed, ${r.removed} removed (${r.files} files)`
    : `  ${r.label}: FAILED — ${r.error}`;
}
