/**
 * The curation routes — ADR 0017 decisions 4 and 5, the aggregator's side.
 *
 * Five admin-only endpoints behind the Proposals inbox card:
 *
 *   POST /api/advisor/proposals/promote   write a note into the fleet corpus,
 *                                         push it, and tell the origin node
 *   POST /api/advisor/proposals/reject    tell the origin node, and nothing else
 *   POST /api/advisor/proposals/revise    carry a verified body back to the
 *                                         origin node, which re-grades it
 *   GET  /api/advisor/knowledge/state     what is configured and what is pinned
 *   POST /api/advisor/knowledge/pull      step: preview | apply
 *
 * None of them signs anything. The push is `scripts/aperire-knowledge-push.sh`
 * — the same command an operator runs — spawned as a child, for the reason
 * lib/trust-push-hook.ts already states about the trust bundle: one
 * implementation of build/sign/push, covered by its own tests, with the
 * private key never in the web process's heap. What this file owns is the
 * decision to run it, the file it writes first, and the honest report of
 * what each node did with the result.
 *
 * Two orderings are load-bearing:
 *
 *   - The lint binary is checked BEFORE anything is written. The CLI builds
 *     it with `go build` when it is missing; the server must not, because
 *     the server's account should not be writing into advisor/bin — so it
 *     refuses first, with the command to run, which makes the CLI's fallback
 *     unreachable from here.
 *   - The corpus is linted after the write and before the push, and what
 *     failed is taken back out — a promotion restores the file it replaced,
 *     a pull throws its staging away. Left behind, refused files ride the
 *     NEXT push, and they fail every later promotion while naming the note
 *     being promoted for a fault somewhere else entirely.
 *
 * And one honesty rule the card depends on: promoting and reaching the fleet
 * are two different facts. A promotion whose push failed is still promoted —
 * the file is in the corpus and the next push carries it — and the response
 * says both, separately, rather than reporting the first as the second.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readBodyOrThrow } from './lib/read-body.js';
import { accessSync, constants, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, writeFileSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { readSession, isAdmin, csrfOk, getUserById } from './auth.js';
import type { FleetNodeConfig } from './lib/fleet-registry.js';
import { markPeerProposal, revisePeerProposal } from './lib/peer-advisor-proxy.js';
import { edgeSafeStatus } from './lib/peer-advisor-answer.js';
import {
  validateLayerPath, stampFrontmatter, stampPulledFile, splitMarkdownSections,
  summarizePullDiff, describePullDiff, isoDate, oneLine, slug, cleanTokens,
} from './lib/knowledge-curate.js';
import { readFieldGuidePin, writeFieldGuidePin, type PushResult } from './lib/knowledge-push.js';
import { loadFieldGuideConfig, fetchGuide, readTreeAt, hashTree } from './lib/field-guide.js';

export interface KnowledgeAdminDeps {
  /** Repository root — the parent of dashboard/. */
  repoDir: string;
  /** This host's own advisord, for a proposal that came from it. */
  advisorUrl: string;
  advisorToken: () => string | null;
  /** A registered peer by label, or null. Never trusted from the browser
   *  beyond being a lookup key. */
  peerByLabel: (label: string) => FleetNodeConfig | null;
  /** This host's own fleet label, or null when there is no registry. */
  selfLabel: () => string | null;
  log?: (line: string) => void;
}

interface Paths {
  fleetDir: string;      // advisor/knowledge-fleet
  localDir: string;      // …/local
  baseDir: string;       // …/base
  bundleDir: string;     // advisor/knowledge-bundles
  lintBin: string;       // advisor/bin/knowledge-lint
  pushScript: string;    // scripts/aperire-knowledge-push.sh
  configPath: string;    // dashboard/config/knowledge.yaml
  cloneDir: string;      // …/knowledge-bundles/field-guide-src
}

function paths(repoDir: string): Paths {
  // The same two environment overrides the CLI honours, so a lab rig that
  // points one of them somewhere else moves BOTH callers together.
  const fleetDir = process.env.APERIRE_KNOWLEDGE_FLEET || join(repoDir, 'advisor', 'knowledge-fleet');
  const bundleDir = process.env.APERIRE_KNOWLEDGE_BUNDLES || join(repoDir, 'advisor', 'knowledge-bundles');
  return {
    fleetDir,
    localDir: join(fleetDir, 'local'),
    baseDir: join(fleetDir, 'base'),
    bundleDir,
    lintBin: join(repoDir, 'advisor', 'bin', 'knowledge-lint'),
    pushScript: join(repoDir, 'scripts', 'aperire-knowledge-push.sh'),
    configPath: join(repoDir, 'dashboard', 'config', 'knowledge.yaml'),
    cloneDir: join(bundleDir, 'field-guide-src'),
  };
}

/**
 * Whether this account can actually write the corpus, checked before the
 * work rather than discovered by an exception in the middle of it.
 *
 * The case this exists for is real and invisible from the code: on a host
 * where the Advisor runs under its own hardened account,
 * install-advisor-account.sh hands knowledge-fleet/ to that account at 0750,
 * and the dashboard — which shares only the group — can read it and not
 * write it. Without this the operator's first promotion answers EACCES with
 * a path in it and nothing to do about it.
 */
function corpusWritable(dir: string): { ok: boolean; error?: string } {
  const probe = existsSync(dir) ? dir : dirname(dir);
  try {
    accessSync(probe, constants.W_OK | constants.X_OK);
    return { ok: true };
  } catch {
    return {
      ok: false,
      error: `this dashboard cannot write ${dir}. On a host where the Advisor runs under its own ` +
        'account the corpus belongs to that account; re-run scripts/install-aperire-service.sh as ' +
        'root, which makes it group-writable for both services.',
    };
  }
}

/** The 503 for a host with no linter, naming it and the step that installs it
 *  (#1131). The same `--dir` form every other hint in the installer prints, so
 *  the command acts on this install and not whichever one it finds first. */
function noLint(repoDir: string): string {
  const dir = /^[\w./@:+-]+$/.test(repoDir) ? repoDir : `'${repoDir.replace(/'/g, `'\\''`)}'`;
  return 'no knowledge-lint on this host, so nothing can be checked before it reaches every Advisor. ' +
    'The Advisor\u2019s host preparation builds it, and puts Go on the host if it is missing: ' +
    `curl -fsSL https://get.aperire.one | bash -s -- --dir ${dir} --run prepare-host --role dashboard --with-advisor. ` +
    'Or build it by hand where Go is installed: cd advisor && go build -o bin/knowledge-lint ./cmd/knowledge-lint';
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req: IncomingMessage, maxBytes = 256 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBodyOrThrow(req, maxBytes);
  if (!raw.trim()) return {};
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  return parsed as Record<string, unknown>;
}

interface Run { code: number; output: string }

function run(cmd: string, args: string[], opts: { cwd: string; env?: NodeJS.ProcessEnv; timeoutMs: number }): Promise<Run> {
  return new Promise((resolve_) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const cap = (c: Buffer) => { if (output.length < 256 * 1024) output += c.toString('utf8'); };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, opts.timeoutMs);
    child.stdout.on('data', cap);
    child.stderr.on('data', cap);
    child.on('error', (err) => { clearTimeout(timer); resolve_({ code: 127, output: err.message }); });
    child.on('close', (code) => { clearTimeout(timer); resolve_({ code: code ?? 1, output }); });
  });
}

/** The whole corpus, checked with the same binary and the same rules the CLI
 *  uses. Warnings do not block — that is the linter's own decision, read off
 *  its exit status rather than re-derived here. */
async function lintCorpus(p: Paths, repoDir: string): Promise<{ ok: boolean; output: string }> {
  const r = await run(p.lintBin, ['-fleet', p.fleetDir], { cwd: repoDir, timeoutMs: 30_000 });
  return { ok: r.code === 0, output: r.output.trim() };
}

/**
 * One push at a time, across the whole process.
 *
 * The sequence number is reserved by reading a file and writing it back, and
 * two pushes that interleave there would mint the same number for different
 * content — which every node then refuses forever, because a repeated
 * sequence is exactly what its rollback guard exists to catch. On the CLI
 * that needed two operators typing at the same moment; on a card it needs
 * two clicks, so the latch lives here rather than on the punch list.
 */
let pushInFlight = false;

/** Builds, signs and pushes by running the operator's own command. The
 *  machine-readable per-node result comes back through a file rather than
 *  through stdout, which is prose. */
async function pushBundle(p: Paths, repoDir: string, log: (s: string) => void):
Promise<{ ok: boolean; seq?: number; nodes: PushResult[]; output: string }> {
  if (pushInFlight) {
    return {
      ok: false, nodes: [],
      output: 'another push is already running on this dashboard. The corpus has your change; ' +
        'wait for that push to finish and run aperire-knowledge-push, or promote again.',
    };
  }
  pushInFlight = true;
  // try/finally, not a reset before the return: a throw between here and
  // there would leave the latch shut for the life of the process, and every
  // later promotion would be told a push it cannot see is still running.
  try {
    const dir = mkdtempSync(join(tmpdir(), 'aperire-push-'));
    const resultPath = join(dir, 'result.json');
    const r = await run('bash', [p.pushScript], {
      cwd: repoDir,
      env: { ...process.env, APERIRE_PUSH_RESULT: resultPath },
      timeoutMs: 180_000,
    });
    for (const line of r.output.split('\n')) if (line.trim()) log(`[knowledge-push] ${line.trimEnd()}`);
    let seq: number | undefined;
    let nodes: PushResult[] = [];
    let refused: string | undefined;
    try {
      const parsed = JSON.parse(readFileSync(resultPath, 'utf8')) as { seq?: number; nodes?: PushResult[]; refused?: string };
      seq = parsed.seq;
      nodes = parsed.nodes ?? [];
      // A push the script refused before sending anything (#1236): its output
      // is the whole build with the refusal at the end, and the card shows one
      // line, so the line the script wrote for it is what the card gets.
      refused = typeof parsed.refused === 'string' ? parsed.refused : undefined;
    } catch {
      // No result file: the script refused before it pushed (no lint, no key,
      // no fleet.yaml) and its output is the only thing that explains it.
    }
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* a temp dir we made */ }
    return { ok: r.code === 0, seq, nodes, output: refused ?? r.output.trim() };
  } finally {
    pushInFlight = false;
  }
}

/**
 * One proposal write, routed to the node that proposed: this host's own
 * advisord over loopback, or a registered peer through the pinned proxy.
 *
 * The self-or-peer test is the one both writers share, and it is written this
 * way rather than as `label === self` alone because an aggregator with no
 * fleet registry has no self label either — a local proposal decided there
 * carries an empty label and must still reach this host's advisord.
 *
 * The node's own body comes back on success. The decision path ignores it; the
 * verification path needs it, because what the node computed (the provenance
 * and the rank it worked out from its own record) is the whole answer.
 */
async function callOrigin(
  deps: KnowledgeAdminDeps,
  label: string,
  write: 'mark' | 'revise',
  payload: Record<string, unknown>,
): Promise<{ ok: boolean; body?: unknown; error?: string }> {
  const self = deps.selfLabel();
  if (!label || label === self || (!self && !deps.peerByLabel(label))) {
    const token = deps.advisorToken();
    if (!token) return { ok: false, error: 'no advisor token readable on this host' };
    try {
      const r = await fetch(`${deps.advisorUrl}/v1/proposals/${write}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(15_000),
      });
      const text = await r.text();
      if (!r.ok) {
        // The advisord's own words when it has some. It refuses a
        // verification for reasons the operator can act on ("ask again",
        // "that measured nothing"), and "[HTTP 409]" in front of the JSON is
        // not what they should be reading.
        let detail = '';
        try {
          const parsed = JSON.parse(text) as { error?: unknown };
          if (typeof parsed.error === 'string') detail = parsed.error;
        } catch { /* not JSON: the status line below is all there is */ }
        return { ok: false, error: detail || `[HTTP ${r.status}] ${text.slice(0, 200)}` };
      }
      try {
        return { ok: true, body: JSON.parse(text) };
      } catch {
        return { ok: true };
      }
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }
  const peer = deps.peerByLabel(label);
  if (!peer) return { ok: false, error: `no node called "${label}" is registered here` };
  const r = write === 'mark'
    ? await markPeerProposal(peer, payload as Parameters<typeof markPeerProposal>[1])
    : await revisePeerProposal(peer, payload as Parameters<typeof revisePeerProposal>[1]);
  if (r.ok) return { ok: true, body: r.body };
  return { ok: false, error: r.detail || r.error };
}

/** Tells the node that proposed what was decided. Never fails the request:
 *  the promotion happened, and a node that could not be told is a smaller
 *  fact than a decision the operator would have to make twice. */
async function markOrigin(
  deps: KnowledgeAdminDeps,
  label: string,
  payload: { id: string; decision: 'promoted' | 'rejected'; reason?: string; file?: string; operator: string; role: string },
): Promise<{ ok: boolean; error?: string }> {
  const r = await callOrigin(deps, label, 'mark', payload as unknown as Record<string, unknown>);
  return r.ok ? { ok: true } : { ok: false, error: r.error };
}

/**
 * The whole route surface. Returns false when the path is not one of these,
 * so the caller falls through to its own routing.
 */
export async function handleKnowledgeAdmin(
  req: IncomingMessage, res: ServerResponse, pathname: string, deps: KnowledgeAdminDeps,
): Promise<boolean> {
  const ROUTES = new Set([
    '/api/advisor/proposals/promote',
    '/api/advisor/proposals/reject',
    '/api/advisor/proposals/revise',
    '/api/advisor/knowledge/state',
    '/api/advisor/knowledge/pull',
  ]);
  if (!ROUTES.has(pathname)) return false;

  // Admin, on every one of them, the read included. An unpromoted queue of
  // model-authored notes and the pull's diff are not things a monitor
  // session gets to see, and the card hiding them is a rendering choice, not
  // an enforcement.
  const sess = readSession(req);
  if (!sess) { send(res, 401, { error: 'unauthenticated' }); return true; }
  if (!isAdmin(sess.role)) {
    send(res, 403, {
      error: 'this operator may not curate fleet knowledge',
      detail: `Role is ${sess.role}. An admin can change it: aperire-auth set-role <email> admin`,
    });
    return true;
  }
  const isGet = pathname === '/api/advisor/knowledge/state';
  if (isGet ? req.method !== 'GET' : req.method !== 'POST') { send(res, 405, { error: 'method' }); return true; }
  if (!isGet && !csrfOk(req)) { send(res, 403, { error: 'csrf' }); return true; }

  const user = getUserById(sess.userId);
  const operator = user?.username ?? `user:${sess.userId}`;
  const role = sess.role ?? '';
  const log = deps.log ?? ((line: string) => console.log(line));
  const p = paths(deps.repoDir);

  let body: Record<string, unknown> = {};
  if (!isGet) {
    try {
      body = await readJsonBody(req);
    } catch (err) {
      send(res, (err as Error).message === 'too large' ? 413 : 400, { error: 'bad body' });
      return true;
    }
  }

  if (pathname === '/api/advisor/proposals/reject') {
    const id = oneLine(body.id, 120);
    const label = oneLine(body.node_label, 32);
    const reason = oneLine(body.reason, 400);
    if (!id) { send(res, 400, { error: 'which proposal?' }); return true; }
    const marked = await markOrigin(deps, label, { id, decision: 'rejected', reason, operator, role });
    log(`[knowledge] ${operator} rejected proposal ${id} from ${label || 'this host'}` +
      (marked.ok ? '' : ` — the node was not told: ${marked.error}`));
    // The Advisor tab's Inbox calls this. A 502 here is the edge's to replace with
    // a page of its own, and the page then lost the sentence below (#1134).
    send(res, marked.ok ? 200 : edgeSafeStatus(502), {
      ok: marked.ok, id, recorded_on_node: marked.ok, error: marked.error,
    });
    return true;
  }

  // The verification — the trust model's Part B (#49). The operator asked the
  // proposing node's own Advisor to check the claim, read what it measured,
  // and kept the result; this carries the corrected body BACK to that node
  // along with the ask_id of the investigation.
  //
  // What it does NOT carry is a verdict. The node holds the record of that
  // investigation and grades the note from it itself, which is the only reason
  // "Measured" on a card still means something. This route's own job is the
  // same one every route in this file has: prove the caller is an admin, name
  // them from the session, and route the write to the right node.
  if (pathname === '/api/advisor/proposals/revise') {
    const id = oneLine(body.id, 120);
    const label = oneLine(body.node_label, 32);
    const askId = oneLine(body.ask_id, 64);
    const noteBody = String(body.body ?? '').trim();
    if (!id) { send(res, 400, { error: 'which proposal?' }); return true; }
    if (!askId) { send(res, 400, { error: 'a verification names the investigation it rests on' }); return true; }
    if (!noteBody) { send(res, 400, { error: 'a revision needs a body' }); return true; }
    const r = await callOrigin(deps, label, 'revise', {
      id, body: noteBody, ask_id: askId, operator, role,
    });
    const out = (r.body ?? {}) as Record<string, unknown>;
    log(`[knowledge] ${operator} verified proposal ${id} on ${label || 'this host'}` +
      (r.ok
        ? ` — ${String(out.provenance_was)} rank ${String(out.rank_was)} → ${String(out.provenance)} rank ${String(out.rank)}` +
          ` from ${String(out.measured_reads)} measured read(s)`
        : ` — refused: ${r.error}`));
    // The node's answer, forwarded whole. The card renders the grade it
    // computed, not one this host worked out on its behalf.
    send(res, r.ok ? 200 : 409, r.ok ? { ok: true, ...out } : { ok: false, error: r.error });
    return true;
  }

  if (pathname === '/api/advisor/proposals/promote') {
    const out = await promoteProposal(body, {
      paths: p, repoDir: deps.repoDir, operator, role, log,
      selfLabel: deps.selfLabel() ?? null,
      mark: (label, payload) => markOrigin(deps, label, payload),
    });
    send(res, out.status, out.body);
    return true;
  }

  // ── the field-guide pull ────────────────────────────────────────────────
  const cfg = loadFieldGuideConfig(p.configPath);
  const pin = readFieldGuidePin(p.bundleDir);

  if (pathname === '/api/advisor/knowledge/state') {
    send(res, 200, {
      configured: cfg.ok,
      error: cfg.ok ? null : cfg.error,
      repo: cfg.ok ? cfg.config.repo : null,
      ref: cfg.ok ? cfg.config.ref : null,
      lint_available: existsSync(p.lintBin),
      pinned: pin ? {
        commit: pin.commit, short: pin.commit.slice(0, 8), pulled_at: pin.pulled_at,
        pulled_by: pin.pulled_by, files: Object.keys(pin.files).length,
      } : null,
    });
    return true;
  }

  // POST /api/advisor/knowledge/pull
  if (!cfg.ok) { send(res, 409, { error: cfg.error }); return true; }
  if (!existsSync(p.lintBin)) { send(res, 503, { error: noLint(deps.repoDir) }); return true; }
  const step = String(body.step ?? 'preview');
  mkdirSync(p.bundleDir, { recursive: true, mode: 0o750 });

  if (step === 'preview') {
    const fetched = await fetchGuide(p.cloneDir, cfg.config);
    if (!fetched.ok) { send(res, 502, { error: fetched.error }); return true; }
    const after = hashTree(fetched.tree.files);
    const diff = summarizePullDiff(pin?.files ?? {}, after);
    log(`[knowledge] ${operator} previewed ${cfg.config.repo}@${fetched.tree.commit.slice(0, 8)}: ${describePullDiff(diff)}`);
    send(res, 200, {
      ok: true, step: 'preview',
      repo: cfg.config.repo, ref: cfg.config.ref,
      commit: fetched.tree.commit, short: fetched.tree.commit.slice(0, 8),
      from: pin ? { commit: pin.commit, short: pin.commit.slice(0, 8), pulled_at: pin.pulled_at } : null,
      diff, summary: describePullDiff(diff), files: Object.keys(after).length,
    });
    return true;
  }

  if (step !== 'apply') { send(res, 400, { error: 'step is preview or apply' }); return true; }
  const commit = oneLine(body.commit, 40);
  if (!/^[0-9a-f]{7,40}$/.test(commit)) { send(res, 400, { error: 'apply needs the commit the preview showed' }); return true; }
  const writableBase = corpusWritable(p.baseDir);
  if (!writableBase.ok) { send(res, 503, { error: writableBase.error }); return true; }
  const tree = await readTreeAt(p.cloneDir, commit, cfg.config);
  if (!tree.ok) { send(res, 502, { error: tree.error }); return true; }

  // What the operator approved is a tree, not "the tip of the branch when
  // the second click happens". Re-read at the named commit; if the mirror
  // no longer holds it, the pull is refused rather than quietly applying
  // something else.
  const staged = await stagePulledCorpus({
    paths: p, repoDir: deps.repoDir, corpusDir: cfg.config.corpusDir,
    files: tree.tree.files, source: `${cfg.config.repo}@${commit.slice(0, 12)}`,
  });
  if (!staged.ok) {
    send(res, staged.status, {
      error: staged.error, detail: staged.lintOutput || null,
      files: staged.written.length, skipped: staged.skipped,
    });
    return true;
  }
  const { written, skipped, lintOutput } = staged;

  const push = await pushBundle(p, deps.repoDir, log);
  // The pin moves on a successful build even if a node was unreachable: the
  // aggregator HAS this commit, and the next push carries it to whoever
  // missed it. A pin that only moved on a perfect push would re-copy the
  // same tree on every retry and never converge.
  writeFieldGuidePin(p.bundleDir, {
    repo: cfg.config.repo, ref: cfg.config.ref, commit,
    pulled_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    pulled_by: operator,
    files: hashTree(tree.tree.files),
  });
  log(`[knowledge] ${operator} applied ${cfg.config.repo}@${commit.slice(0, 8)}: ` +
    `${written.length} corpus file(s), push ${push.ok ? 'ok' : 'INCOMPLETE'}`);
  send(res, 200, {
    ok: true, step: 'apply', commit, short: commit.slice(0, 8),
    files: written.length, skipped, lint_output: lintOutput || null,
    push: { ok: push.ok, seq: push.seq ?? null, nodes: push.nodes, output: push.nodes.length ? null : push.output || null },
  });
  return true;
}

/** Everything the promote route does once the caller is known to be an
 *  admin. Split out so the ordering that matters — lint after the write,
 *  rollback on refusal, push, then tell the node — has a test that does not
 *  need a session, a browser or a fleet. */
export interface PromoteCtx {
  paths: Paths;
  repoDir: string;
  operator: string;
  role: string;
  selfLabel: string | null;
  log: (line: string) => void;
  mark: (label: string, payload: { id: string; decision: 'promoted' | 'rejected'; reason?: string; file?: string; operator: string; role: string })
    => Promise<{ ok: boolean; error?: string }>;
}

export async function promoteProposal(
  body: Record<string, unknown>, ctx: PromoteCtx,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const p = ctx.paths;
  const reply = (status: number, b: Record<string, unknown>) => ({ status, body: b });
  if (!existsSync(p.lintBin)) { return reply(503, { error: noLint(ctx.repoDir) }); }
  const writable = corpusWritable(p.localDir);
  if (!writable.ok) { return reply(503, { error: writable.error }); }
  const id = oneLine(body.id, 120);
  const label = oneLine(body.node_label, 32);
  const verdict = validateLayerPath(String(body.path ?? ''));
  if (!verdict.ok) { return reply(400, { error: verdict.error }); }
  const title = oneLine(body.title, 200);
  if (!title) { return reply(400, { error: 'a knowledge file needs a title' }); }
  const noteBody = String(body.body ?? '').trim();
  if (!noteBody) { return reply(400, { error: 'a knowledge file needs a body' }); }
  if (Buffer.byteLength(noteBody, 'utf8') > 24 * 1024) {
    return reply(400, { error: 'over 24 KB — that is a quarter of the injection budget in one file; split it' });
  }
  const tags = cleanTokens(body.tags);
  if (!tags.length) { return reply(400, { error: 'a knowledge file needs tags — the ranker has nothing to scope it by' }); }

  const today = isoDate();
  const proposedOn = oneLine(body.created_at, 40).slice(0, 10) || today;
  const question = oneLine(body.question, 200);
  const from = label || ctx.selfLabel || 'this host';
  const file = stampFrontmatter({
    title,
    tags,
    appliesTo: cleanTokens(body.applies_to),
    priority: body.priority === 'high' ? 'high' : 'normal',
    source: question
      ? `${from} Advisor, ${proposedOn}, answering: ${question}`
      : `${from} Advisor, ${proposedOn}`,
    proposedBy: `${from} Advisor, ${proposedOn}`,
    promotedBy: `${ctx.operator}, ${today}`,
    lastReviewed: today,
  }, noteBody);

  // The belt behind validateLayerPath: resolve the destination and prove
  // it is inside the layer before opening anything. A path check and a
  // path use that are not the same expression have drifted before.
  const dest = resolve(p.localDir, verdict.path);
  const rel = relative(p.localDir, dest);
  if (rel.startsWith('..') || rel.includes(`..${sep}`) || resolve(p.localDir, rel) !== dest) {
    return reply(400, { error: 'that path does not land inside the fleet corpus' });
  }
  const replaced = existsSync(dest);
  const previous = replaced ? readFileSync(dest, 'utf8') : null;
  try {
    mkdirSync(dirname(dest), { recursive: true, mode: 0o750 });
    writeFileSync(dest, file, { mode: 0o640 });
  } catch (err) {
    return reply(500, { error: `could not write ${verdict.path}: ${(err as Error).message}` });
  }

  const lint = await lintCorpus(p, ctx.repoDir);
  if (!lint.ok) {
    // Put the corpus back exactly as it was. A refused file left on disk
    // rides the next push, and nobody would connect that to a promotion
    // they were told did not happen.
    try {
      if (previous === null) rmSync(dest, { force: true });
      else writeFileSync(dest, previous, { mode: 0o640 });
    } catch { /* reported below as the lint failure it is */ }
    // The lint covers the whole corpus, so a pre-existing failure elsewhere
    // refuses this promotion too. Saying "this file" would blame the note
    // being promoted for a fault the output names somewhere else.
    return reply(400, {
      error: 'knowledge-lint refused the corpus, so nothing was written or pushed — the detail below names the file',
      detail: lint.output,
    });
  }

  const push = await pushBundle(p, ctx.repoDir, ctx.log);
  const marked = await ctx.mark(label, {
    id, decision: 'promoted', file: `local/${verdict.path}`, operator: ctx.operator, role: ctx.role,
  });
  ctx.log(`[knowledge] ${ctx.operator} promoted ${id || '(no id)'} from ${from} to local/${verdict.path}` +
    ` — push ${push.ok ? 'ok' : 'INCOMPLETE'}, sequence ${push.seq ?? 'none'}`);

  return reply(200, {
    // Promoted is the file being in the corpus. Whether it reached the
    // fleet is the separate fact below, and the card renders them apart.
    ok: true,
    promoted: true,
    replaced,
    file: `local/${verdict.path}`,
    lint_output: lint.output || null,
    push: {
      ok: push.ok,
      seq: push.seq ?? null,
      nodes: push.nodes,
      // Only shown when there is no per-node detail to show instead.
      output: push.nodes.length ? null : push.output || null,
    },
    recorded_on_node: marked.ok,
    mark_error: marked.error ?? null,
  });
}

/**
 * The Settings-side promotion, ADR 0021 build step 5, issue #232.
 *
 * A sibling of promoteProposal above, and deliberately built the same way:
 * write, lint the whole corpus, roll back on a refusal, push. What differs
 * is the source and what happens afterwards. The source is a row this
 * dashboard already mirrored from a node's memory.jsonl (db.ts's
 * memoryMirrorRow), not a proposal a node's Advisor wrote to be reviewed,
 * there is no origin node to tell, because a memory entry is not a queue
 * item with a pending/decided lifecycle. What is stamped on the file is
 * the operator's own act: `source` names the node the fact came from,
 * `promotedBy` names the operator who decided it belonged in fleet
 * knowledge. Nothing here runs on its own; this function exists to be
 * called by one admin-gated, CSRF-checked route, same as every other
 * write in this file.
 *
 * Reachable only through Settings (settings-api.ts), not through
 * handleKnowledgeAdmin's route table above, a different admin surface for
 * a different act, per ADR 0021 §5's "Settings is the one place for fleet
 * config" convention.
 *
 * The mirror read and the promotion stamp are INJECTED (`lookup`, `stamp`)
 * rather than imported from db.js directly, matching the `mark` injection
 * promoteProposal already takes above. This file already reaches db.js
 * transitively (auth.js, imported above for readSession/isAdmin/csrfOk,
 * imports it), so a direct import here would add no new module-load side
 * effect, the reason to keep this a pure function taking its reads and
 * writes as arguments is what it already buys promoteProposal: the write/
 * lint/rollback/push sequence is testable with a plain object, no session,
 * no fleet, and no real database anywhere near it. settings-api.ts already
 * imports db.js for its own reasons and passes the two functions straight
 * through.
 */
export interface MemoryMirrorLookup {
  at: string;
  kind: string;
  title: string;
  body: string;
  /** The node's own marker on the entry. "retracted" is a note a person
   *  withdrew there (#1019); db.ts's MEMORY_RETRACTED is the same word, kept
   *  as a literal here for the reason this file keeps LOCAL_NODE_SENTINEL one. */
  superseded_by?: string | null;
  retracted_by?: string | null;
  retracted_why?: string | null;
}

export interface PromoteMemoryCtx {
  paths: Paths;
  repoDir: string;
  operator: string;
  role: string;
  /** This host's own fleet label, for the source line when the entry being
   *  promoted is this dashboard's OWN Advisor rather than a peer's, see
   *  LOCAL_NODE_SENTINEL below for why that case needs handling at all. */
  selfLabel: string | null;
  log: (line: string) => void;
  lookup: (node: string, id: string) => MemoryMirrorLookup | null;
  stamp: (node: string, id: string, by: string, file: string) => void;
}

/**
 * Mirrors db.ts's LOCAL_NODE exactly (`'@local'`), a sentinel, not a
 * fleet label, that the mirror stores this host's OWN Advisor rows under.
 * Hardcoded rather than imported for the reason PromoteMemoryCtx's own
 * comment gives; test/unit/local-node-sentinel-drift.test.ts pins the two
 * constants against each other so a rename on either side is a red test
 * rather than a signed file quietly carrying `@local` as a node's name.
 *
 * Without this, promoting an entry mirrored from the aggregator's own
 * memory would stamp `source: @local Advisor memory, ...` into a file that
 * is signed and pushed to every node in the fleet, an internal
 * implementation detail written into public knowledge, and a wrong one at
 * that: `@local` names nothing an operator on another node would recognise.
 */
export const LOCAL_NODE_SENTINEL = '@local';

export async function promoteMemoryNote(
  body: Record<string, unknown>, ctx: PromoteMemoryCtx,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const p = ctx.paths;
  const reply = (status: number, b: Record<string, unknown>) => ({ status, body: b });
  if (!existsSync(p.lintBin)) { return reply(503, { error: noLint(ctx.repoDir) }); }
  const writable = corpusWritable(p.localDir);
  if (!writable.ok) { return reply(503, { error: writable.error }); }

  const node = oneLine(body.node, 32);
  const id = oneLine(body.id, 64);
  if (!node || !id) { return reply(400, { error: 'which memory entry, and from which node?' }); }
  // The human-facing name for the node the fact came from. The mirror keys
  // this host's own rows under LOCAL_NODE_SENTINEL, which is a storage
  // detail, not a name, everywhere this promotion SPEAKS about the node
  // (the file it writes, an error an operator reads) uses `from` instead.
  // `node` itself, unchanged, is still what looks the entry up: that is the
  // mirror's own key.
  const from = node === LOCAL_NODE_SENTINEL ? (ctx.selfLabel || 'this host') : node;
  const entry = ctx.lookup(node, id);
  if (!entry) { return reply(404, { error: `no such memory entry mirrored from ${from}` }); }
  // #1019. A note a person withdrew on its node must not reach the corpus every
  // Advisor in the fleet reads: #1012 was a wrong note that made an Advisor
  // refuse a safe operation in every later session. Refused here, on the
  // server, whatever the page shows.
  if (entry.superseded_by === 'retracted') {
    const who = entry.retracted_by ? ` by ${entry.retracted_by}` : '';
    const why = entry.retracted_why ? `: ${entry.retracted_why}` : '';
    return reply(409, { error: `that memory entry was retracted on ${from}${who}${why}. A retracted note is not promoted.` });
  }

  const verdict = validateLayerPath(String(body.path ?? ''));
  if (!verdict.ok) { return reply(400, { error: verdict.error }); }
  const title = oneLine(body.title, 200) || oneLine(entry.title, 200);
  if (!title) { return reply(400, { error: 'a knowledge file needs a title' }); }
  const noteBody = (String(body.body ?? '').trim()) || entry.body.trim();
  if (!noteBody) { return reply(400, { error: 'a knowledge file needs a body' }); }
  if (Buffer.byteLength(noteBody, 'utf8') > 24 * 1024) {
    return reply(400, { error: 'over 24 KB, that is a quarter of the injection budget in one file; split it' });
  }
  const tags = cleanTokens(body.tags);
  if (!tags.length) { return reply(400, { error: 'a knowledge file needs tags, the ranker has nothing to scope it by' }); }

  const today = isoDate();
  // The entry's own date when it has one usable, the promotion's date
  // otherwise, the same fallback promoteProposal's `proposedOn` uses.
  const entryDate = /^\d{4}-\d{2}-\d{2}/.test(entry.at) ? entry.at.slice(0, 10) : today;
  const file = stampFrontmatter({
    title,
    tags,
    appliesTo: cleanTokens(body.applies_to),
    priority: body.priority === 'high' ? 'high' : 'normal',
    source: `${from} Advisor memory, ${entryDate} (${entry.kind})`,
    promotedBy: `${ctx.operator}, ${today}`,
    lastReviewed: today,
  }, noteBody);

  // The same belt-and-suspenders path check promoteProposal applies: resolve
  // the destination and prove it is inside the layer before opening anything.
  const dest = resolve(p.localDir, verdict.path);
  const rel = relative(p.localDir, dest);
  if (rel.startsWith('..') || rel.includes(`..${sep}`) || resolve(p.localDir, rel) !== dest) {
    return reply(400, { error: 'that path does not land inside the fleet corpus' });
  }
  const replaced = existsSync(dest);
  const previous = replaced ? readFileSync(dest, 'utf8') : null;
  try {
    mkdirSync(dirname(dest), { recursive: true, mode: 0o750 });
    writeFileSync(dest, file, { mode: 0o640 });
  } catch (err) {
    return reply(500, { error: `could not write ${verdict.path}: ${(err as Error).message}` });
  }

  const lint = await lintCorpus(p, ctx.repoDir);
  if (!lint.ok) {
    // Put the corpus back exactly as it was, same rollback promoteProposal
    // performs, for the same reason: a refused file left on disk rides the
    // next push and fails every later promotion while naming a different
    // one.
    try {
      if (previous === null) rmSync(dest, { force: true });
      else writeFileSync(dest, previous, { mode: 0o640 });
    } catch { /* reported below as the lint failure it is */ }
    return reply(400, {
      error: 'knowledge-lint refused the corpus, so nothing was written or pushed, the detail below names the file',
      detail: lint.output,
    });
  }

  const push = await pushBundle(p, ctx.repoDir, ctx.log);
  const promotedFile = `local/${verdict.path}`;
  // Recorded on the mirror row only after the write and the lint both
  // succeeded, the same ordering as promoteProposal's mark, so a refused
  // promotion never reads as one that happened.
  ctx.stamp(node, id, ctx.operator, promotedFile);
  ctx.log(`[knowledge] ${ctx.operator} promoted memory entry ${id} from ${from} to ${promotedFile}` +
    `, push ${push.ok ? 'ok' : 'INCOMPLETE'}, sequence ${push.seq ?? 'none'}`);

  return reply(200, {
    ok: true,
    promoted: true,
    replaced,
    file: promotedFile,
    lint_output: lint.output || null,
    push: {
      ok: push.ok,
      seq: push.seq ?? null,
      nodes: push.nodes,
      output: push.nodes.length ? null : push.output || null,
    },
  });
}

/**
 * Writes a pulled tree into `base/<corpusDir>/`, lints it, and swaps it in —
 * staged first, so a corpus the linter refuses costs the live one nothing.
 *
 * Split out from the route for the same reason promoteProposal is: the
 * ordering here is the whole behaviour, and the failure it guards against is
 * silent. A corpus written in place and THEN refused leaves the refused
 * files on disk, where they fail the NEXT promotion — and the promotion is
 * told the lint refused it, naming a note that is not the problem.
 *
 * Every rename stays inside the layer directory. Staging beside it and
 * renaming across is EROFS on a hardened host, which is the trap the node's
 * own bundle apply already hit once.
 */
export interface StageResult {
  ok: boolean;
  status: number;
  error?: string;
  written: string[];
  skipped: string[];
  lintOutput: string;
}

export async function stagePulledCorpus(o: {
  paths: Paths; repoDir: string; corpusDir: string;
  files: Record<string, string>; source: string; today?: string;
}): Promise<StageResult> {
  const p = o.paths;
  const corpusDir = join(p.baseDir, o.corpusDir);
  const stageDir = join(p.baseDir, '.pull-staging');
  const retiredDir = join(p.baseDir, '.pull-retired');
  const pulledOn = o.today ?? isoDate();
  const written: string[] = [];
  const skipped: string[] = [];
  try {
    rmSync(stageDir, { recursive: true, force: true });
    rmSync(retiredDir, { recursive: true, force: true });
    for (const [repoPath, text] of Object.entries(o.files)) {
      const source = `${o.source} ${repoPath}`;
      const docDir = `${o.corpusDir}/${slug(repoPath.split('/').pop()?.replace(/\.md$/i, '') ?? 'document')}`;
      for (const s of splitMarkdownSections(text, { dir: docDir })) {
        const v = validateLayerPath(s.path);
        // A heading that slugs to something unusable, or a path that comes
        // out too long, is skipped — and NAMED. Dropped silently, it leaves
        // the card saying how many files were written and nothing about the
        // section that vanished.
        if (!v.ok) { skipped.push(`${s.title}: ${v.error}`); continue; }
        const dest = resolve(stageDir, v.path);
        const rel = relative(stageDir, dest);
        if (rel.startsWith('..') || resolve(stageDir, rel) !== dest) {
          skipped.push(`${s.title}: the path does not land inside the layer`);
          continue;
        }
        mkdirSync(dirname(dest), { recursive: true, mode: 0o750 });
        writeFileSync(dest, stampPulledFile(s.text, {
          path: s.path, source, pulledOn, tag: o.corpusDir, title: s.title,
        }), { mode: 0o640 });
        written.push(`base/${v.path}`);
      }
    }
  } catch (err) {
    try { rmSync(stageDir, { recursive: true, force: true }); } catch { /* the staging is ours */ }
    return { ok: false, status: 500, error: `could not write the pulled corpus: ${(err as Error).message}`,
      written, skipped, lintOutput: '' };
  }
  if (!written.length) {
    try { rmSync(stageDir, { recursive: true, force: true }); } catch { /* the staging is ours */ }
    return { ok: false, status: 400, error: 'that commit produced no usable corpus files',
      written, skipped, lintOutput: '' };
  }

  // Linted where it stands, so a refusal costs the live corpus nothing.
  const lint = await lintCorpus(p, o.repoDir);
  if (!lint.ok) {
    try { rmSync(stageDir, { recursive: true, force: true }); } catch { /* the staging is ours */ }
    return {
      ok: false, status: 400,
      error: 'knowledge-lint refused the pulled corpus, so nothing was written or pushed',
      written, skipped, lintOutput: lint.output,
    };
  }

  // The swap. The layer is replaced whole: anything the last pull wrote that
  // this commit no longer carries has to leave, or a file deleted upstream
  // would live on in every Advisor's prompt forever.
  try {
    if (existsSync(corpusDir)) renameSync(corpusDir, retiredDir);
    renameSync(join(stageDir, o.corpusDir), corpusDir);
    rmSync(stageDir, { recursive: true, force: true });
    rmSync(retiredDir, { recursive: true, force: true });
  } catch (err) {
    // Put the previous corpus back if the swap died between the two renames.
    try { if (!existsSync(corpusDir) && existsSync(retiredDir)) renameSync(retiredDir, corpusDir); } catch { /* reported below */ }
    try { rmSync(stageDir, { recursive: true, force: true }); } catch { /* the staging is ours */ }
    return { ok: false, status: 500, error: `the pulled corpus could not be swapped in: ${(err as Error).message}`,
      written, skipped, lintOutput: lint.output };
  }
  return { ok: true, status: 200, written, skipped, lintOutput: lint.output };
}

/** Exported for the route table's own test: the paths this module owns. */
export function knowledgeAdminPaths(): string[] {
  return [
    '/api/advisor/proposals/promote',
    '/api/advisor/proposals/reject',
    '/api/advisor/proposals/revise',
    '/api/advisor/knowledge/state',
    '/api/advisor/knowledge/pull',
  ];
}

/** Only used by the state route's file check; exported for tests. */
export function knowledgePaths(repoDir: string): Paths { return paths(repoDir); }
