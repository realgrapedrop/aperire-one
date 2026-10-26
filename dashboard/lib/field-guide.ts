/**
 * The base pull — ADR 0017 decision 5.
 *
 * An admin asks for the public field guide at a pinned commit; this module
 * fetches it, says what would change, and (on a second, separate click)
 * turns it into corpus files. Manual on purpose: auto-ingesting a public
 * repository into every Advisor's prompt is a supply-chain and
 * prompt-injection vector, so nothing here runs on a timer and nothing
 * applies without a person having read the summary first.
 *
 * Three properties hold the security story together:
 *
 *   - The repository comes from `dashboard/config/knowledge.yaml` and from
 *     nowhere else. No browser value reaches git, so there is no request
 *     that can point this at another host. Unconfigured means refused, with
 *     the file to write named in the refusal — never a default that pulls
 *     from somewhere the operator did not choose.
 *   - Only https (or http) URLs are accepted. git's remote helpers make
 *     `ext::sh -c …` a command-execution URL scheme, and an operator pasting
 *     one into a config file should be told no.
 *   - Apply takes the commit the preview showed and refuses if the ref has
 *     moved since. What the operator approved is a specific tree, not "the
 *     tip of main, whenever the second click happens".
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';

export interface FieldGuideConfig {
  repo: string;
  ref: string;
  /** Repository sub-paths to pull, or [] for the whole tree. */
  paths: string[];
  /** Where the pulled files land under knowledge-fleet/base/. */
  corpusDir: string;
}

export type ConfigResult =
  | { ok: true; config: FieldGuideConfig }
  | { ok: false; error: string };

const CORPUS_DIR_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;

/**
 * Reads the source config. Absent, empty or malformed all resolve to the
 * same honest answer: this aggregator has no field guide configured, and
 * here is the file to write.
 */
export function loadFieldGuideConfig(path: string): ConfigResult {
  const missing = `no field guide is configured: write ${path} with a repo, a ref and the paths to pull ` +
    '(see config/knowledge.yaml.example)';
  if (!existsSync(path)) return { ok: false, error: missing };
  let doc: unknown;
  try {
    doc = yaml.load(readFileSync(path, 'utf8'));
  } catch (err) {
    return { ok: false, error: `${path} is not valid YAML: ${(err as Error).message}` };
  }
  const src = (doc as { field_guide?: Record<string, unknown> } | null)?.field_guide;
  if (!src || typeof src !== 'object') return { ok: false, error: missing };
  const repo = String(src.repo ?? '').trim();
  if (!repo) return { ok: false, error: missing };
  if (!/^https?:\/\/[a-z0-9]/i.test(repo)) {
    return {
      ok: false,
      error: `the repo in ${path} must be an http(s) URL — git's other URL schemes can run commands, ` +
        'and a knowledge source is a document, not a program',
    };
  }
  const ref = String(src.ref ?? 'main').trim() || 'main';
  if (!/^[A-Za-z0-9._/-]{1,100}$/.test(ref)) {
    return { ok: false, error: `the ref in ${path} is not a usable branch, tag or commit name` };
  }
  const rawPaths = Array.isArray(src.paths) ? src.paths : [];
  const paths: string[] = [];
  for (const p of rawPaths) {
    const s = String(p ?? '').trim().replace(/^\/+|\/+$/g, '');
    if (!s) continue;
    if (s.includes('..') || s.startsWith('-')) {
      return { ok: false, error: `"${s}" is not a usable path in ${path}` };
    }
    paths.push(s);
  }
  const corpusDir = String(src.corpus_dir ?? 'field-guide').trim();
  if (!CORPUS_DIR_RE.test(corpusDir)) {
    return { ok: false, error: `corpus_dir in ${path} must be a simple lowercase name` };
  }
  return { ok: true, config: { repo, ref, paths, corpusDir } };
}

export interface GitRun {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * One git invocation. Arguments only — never a shell string, so nothing in a
 * path or a ref can become another command. The environment is narrowed so a
 * repository that wants credentials fails fast instead of hanging on a
 * prompt no operator can see.
 */
export function git(args: string[], opts: { cwd?: string; timeoutMs?: number } = {}): Promise<GitRun> {
  return new Promise((resolve) => {
    const child = spawn('git', args, {
      cwd: opts.cwd,
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_ASKPASS: '/bin/false',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_ALLOW_PROTOCOL: 'http:https:',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already gone */ } },
      opts.timeoutMs ?? 120_000);
    child.stdout.on('data', (c: Buffer) => { if (stdout.length < 8 << 20) stdout += c.toString('utf8'); });
    child.stderr.on('data', (c: Buffer) => { if (stderr.length < 64 << 10) stderr += c.toString('utf8'); });
    child.on('error', (err) => { clearTimeout(timer); resolve({ code: 127, stdout, stderr: err.message }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code: code ?? 1, stdout, stderr }); });
  });
}

export interface FetchedTree {
  commit: string;
  /** repo-relative path → file bytes as text. Markdown only. */
  files: Record<string, string>;
}

export type FetchResult = { ok: true; tree: FetchedTree } | { ok: false; error: string };

/**
 * Clones or updates the local mirror and reads one commit's markdown.
 *
 * The mirror is kept (not a fresh clone each time) so a diff can be taken
 * against the commit that was pinned last time — that object has to still be
 * reachable, which rules out a shallow clone.
 */
export async function fetchGuide(cloneDir: string, cfg: FieldGuideConfig): Promise<FetchResult> {
  if (!existsSync(join(cloneDir, '.git'))) {
    const r = await git(['clone', '--quiet', cfg.repo, cloneDir]);
    if (r.code !== 0) return { ok: false, error: `git clone failed: ${r.stderr.trim() || r.code}` };
  } else {
    // A configured repo that no longer matches the mirror is refused rather
    // than silently re-pointed: the pinned commit in the state file belongs
    // to the OLD repository, and a diff across two repositories is not a
    // diff at all.
    const origin = await git(['remote', 'get-url', 'origin'], { cwd: cloneDir });
    if (origin.code === 0 && origin.stdout.trim() !== cfg.repo) {
      return {
        ok: false,
        error: `${cloneDir} is a mirror of ${origin.stdout.trim()}, and the config now names ${cfg.repo}. ` +
          'Remove the mirror directory to start a fresh history against the new repository.',
      };
    }
    const r = await git(['fetch', '--quiet', 'origin', cfg.ref], { cwd: cloneDir });
    if (r.code !== 0) return { ok: false, error: `git fetch failed: ${r.stderr.trim() || r.code}` };
  }
  const head = await git(['rev-parse', existsSync(join(cloneDir, '.git', 'FETCH_HEAD')) ? 'FETCH_HEAD' : 'HEAD'],
    { cwd: cloneDir });
  if (head.code !== 0) return { ok: false, error: `git rev-parse failed: ${head.stderr.trim() || head.code}` };
  const commit = head.stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) return { ok: false, error: `git named no commit for ${cfg.ref}` };
  return readTreeAt(cloneDir, commit, cfg);
}

/** Reads the markdown of one commit out of the mirror. Exported so a caller
 *  applying a commit the preview named can re-read exactly that tree. */
export async function readTreeAt(cloneDir: string, commit: string, cfg: FieldGuideConfig): Promise<FetchResult> {
  if (!/^[0-9a-f]{7,40}$/.test(commit)) return { ok: false, error: 'that is not a commit' };
  const args = ['ls-tree', '-r', '--name-only', commit];
  if (cfg.paths.length) args.push('--', ...cfg.paths);
  const ls = await git(args, { cwd: cloneDir });
  if (ls.code !== 0) return { ok: false, error: `git ls-tree failed: ${ls.stderr.trim() || ls.code}` };
  const names = ls.stdout.split('\n').map((s) => s.trim()).filter((s) => s.endsWith('.md'));
  if (!names.length) {
    return { ok: false, error: `${commit.slice(0, 8)} carries no markdown under ${cfg.paths.join(', ') || 'the repository root'}` };
  }
  if (names.length > 200) return { ok: false, error: `${names.length} markdown files is more than a knowledge pull carries` };
  const files: Record<string, string> = {};
  for (const name of names) {
    const show = await git(['show', `${commit}:${name}`], { cwd: cloneDir });
    if (show.code !== 0) return { ok: false, error: `could not read ${name}: ${show.stderr.trim()}` };
    files[name] = show.stdout;
  }
  return { ok: true, tree: { commit, files } };
}

/** path → content hash, the shape the pin stores and the diff compares. */
export function hashTree(files: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [p, text] of Object.entries(files)) {
    out[p] = createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 32);
  }
  return out;
}
