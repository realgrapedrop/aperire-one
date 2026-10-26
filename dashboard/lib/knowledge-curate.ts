/**
 * Curating fleet knowledge — ADR 0017 decisions 4 and 5, the pure half.
 *
 * Two acts put a file into `advisor/knowledge-fleet/`: promoting a proposal
 * one node's Advisor wrote, and pulling the public field guide at a pinned
 * commit. Both end in the same place — a markdown file with frontmatter that
 * `knowledge-lint` accepts — so both build it here, in functions with no
 * filesystem, no network and no clock of their own.
 *
 * The rules this file encodes are the linter's (advisor/internal/knowledge/
 * lint.go) and the bundle door's (bundle.go). It does not replace either:
 * the route lints the corpus after writing, and every node re-checks the
 * paths at its door. What this module buys is being told before the write
 * rather than after — and the path rules being unit-tested at the aggregator,
 * where the write happens.
 */

/** Frontmatter the promotion stamps. Every field is written, none inferred
 *  at read time — a file whose provenance depends on where it happens to sit
 *  loses it the moment it moves. */
export interface PromoteFrontmatter {
  title: string;
  tags: string[];
  appliesTo: string[];
  /** Only `high` is read by the ranker; `normal` is the honest default. */
  priority: 'high' | 'normal';
  /** Where this came from. For a promotion: the node, its Advisor, and the
   *  question. For a pull: the repository and commit. */
  source: string;
  proposedBy?: string;
  promotedBy?: string;
  /** YYYY-MM-DD. The linter fails a file without it. */
  lastReviewed: string;
}

export interface PathVerdict {
  ok: boolean;
  /** Normalised, layer-relative, forward slashes: "xrpl/consensus/x.md". */
  path: string;
  error?: string;
}

/** One path segment: lowercase, digits, dash, underscore, dot. Deliberately
 *  narrow — this string becomes a directory name on every node in the fleet,
 *  written by a service running under a hardened unit.
 *
 *  A leading underscore is allowed because the corpus convention uses
 *  `_index.md` for a map (ADR 0017 decision 2, and knowledge-lint skips that
 *  name by hand). A leading DOT is not: dot-prefixed names are how this code
 *  stages and retires a pulled corpus, and nothing a document produces
 *  should be able to name one. */
const SEGMENT_RE = /^[a-z0-9_][a-z0-9._-]*$/;
const MAX_DEPTH = 4;
const MAX_PATH_LEN = 160;

/**
 * Validates a taxonomy path typed at the review card, relative to the layer
 * (so `xrpl/consensus/validations.md`, never `local/…` and never a leading
 * slash).
 *
 * Refuses, in this order, everything that would make the file something
 * other than one note in one layer: an absolute path, a traversal, a name
 * that is not markdown, the `nodes` segment (that word belongs to the
 * per-node namespace a bundle may not touch), and `role-policy.md` (which
 * states what each role may do, ships with the release, and is refused at
 * the loader, the linter and the bundle door as well — this is the fourth
 * refusal and the earliest one).
 */
export function validateLayerPath(raw: string): PathVerdict {
  const p = String(raw ?? '').trim().replace(/\\/g, '/');
  if (!p) return { ok: false, path: '', error: 'a proposal needs a path before it can be promoted' };
  if (p.length > MAX_PATH_LEN) {
    return { ok: false, path: p, error: `the path is longer than ${MAX_PATH_LEN} characters` };
  }
  if (p.startsWith('/')) return { ok: false, path: p, error: 'the path is relative to the layer, so it does not start with /' };
  const segs = p.split('/');
  if (segs.length > MAX_DEPTH) {
    return { ok: false, path: p, error: `at most ${MAX_DEPTH} path segments — the taxonomy is a shelf, not a filesystem` };
  }
  for (const s of segs) {
    if (s === '.' || s === '..' || s === '') {
      return { ok: false, path: p, error: 'the path may not contain an empty segment or a traversal' };
    }
    if (!SEGMENT_RE.test(s)) {
      return { ok: false, path: p, error: `"${s}" is not a usable name: lowercase letters, digits, dot, dash and underscore` };
    }
    if (s === 'nodes') {
      return { ok: false, path: p, error: 'nodes/ belongs to per-node knowledge written on the node itself' };
    }
  }
  const name = segs[segs.length - 1];
  if (!name.endsWith('.md')) return { ok: false, path: p, error: 'a knowledge file is markdown and ends in .md' };
  if (name === 'role-policy.md') {
    return { ok: false, path: p, error: 'role-policy.md states what each role may do; it ships with the release and is never pushed' };
  }
  if (name === '.md') return { ok: false, path: p, error: 'the file needs a name, not just an extension' };
  return { ok: true, path: p };
}

/** One line, collapsed and capped. Everything that lands in frontmatter goes
 *  through it: a title with a newline in it would otherwise write a field
 *  nobody authored — the same rule internal/inbox applies on the node. */
export function oneLine(s: unknown, max = 200): string {
  const out = String(s ?? '').split(/\s+/).filter(Boolean).join(' ');
  return out.length > max ? out.slice(0, max).trim() : out;
}

/** A tag or an applies_to token. Lowercased, punctuation stripped to the
 *  characters the ranker compares on, empty ones dropped. */
export function cleanTokens(list: unknown, max = 12): string[] {
  const raw = Array.isArray(list) ? list : String(list ?? '').split(',');
  const out: string[] = [];
  for (const item of raw) {
    const t = String(item ?? '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
    if (t && !out.includes(t)) out.push(t.slice(0, 40));
    if (out.length >= max) break;
  }
  return out;
}

/** YYYY-MM-DD in UTC — the only date shape the linter accepts. */
export function isoDate(at: Date = new Date()): string {
  return at.toISOString().slice(0, 10);
}

/** Drops a frontmatter block the body already carried. The promotion authors
 *  the header itself, and a body that kept its own would produce a file with
 *  two, of which the loader reads the first — so the operator's edits to the
 *  fields would silently not be the ones that count. */
export function stripFrontmatter(body: string): string {
  const s = String(body ?? '').replace(/^\uFEFF/, '');
  if (!s.startsWith('---\n')) return s.trim();
  const end = s.indexOf('\n---\n', 3);
  if (end < 0) return s.trim();
  return s.slice(end + 5).trim();
}

/**
 * The file as it is written. Field order is the corpus convention (title,
 * tags, applies_to, priority, last_reviewed, source, then the two
 * attributions), and every value is a single line.
 */
export function stampFrontmatter(fm: PromoteFrontmatter, body: string): string {
  const lines = ['---'];
  lines.push(`title: ${oneLine(fm.title)}`);
  lines.push(`tags: [${cleanTokens(fm.tags).join(', ')}]`);
  const applies = cleanTokens(fm.appliesTo);
  if (applies.length) lines.push(`applies_to: [${applies.join(', ')}]`);
  lines.push(`priority: ${fm.priority === 'high' ? 'high' : 'normal'}`);
  lines.push(`last_reviewed: ${oneLine(fm.lastReviewed, 10)}`);
  lines.push(`source: ${oneLine(fm.source, 300)}`);
  if (fm.proposedBy) lines.push(`proposed_by: ${oneLine(fm.proposedBy, 200)}`);
  if (fm.promotedBy) lines.push(`promoted_by: ${oneLine(fm.promotedBy, 200)}`);
  lines.push('---', '');
  return `${lines.join('\n')}\n${stripFrontmatter(body)}\n`;
}

/**
 * A pulled file, given minimal frontmatter only when it has none. The guide
 * is somebody else's document and is copied as it is written; what is added
 * is the two things a corpus file must carry and a public markdown file has
 * no reason to — where it came from, and when it was last looked at.
 *
 * The title is the document's own H1 when it has one, and the file's name
 * otherwise. Guessing a tag list would be inventing metadata, so pulled
 * files carry one honest tag: the source.
 */
export function stampPulledFile(
  text: string, opts: { path: string; source: string; pulledOn: string; tag?: string; title?: string },
): string {
  const s = String(text ?? '').replace(/^\uFEFF/, '');
  if (s.startsWith('---\n') && s.indexOf('\n---\n', 3) > 0) return s;
  // A caller that split the document already knows each piece's heading;
  // only fall back to reading one out of the text when it does not.
  const h1 = /^#\s+(.+)$/m.exec(s);
  const base = opts.path.split('/').pop() ?? opts.path;
  const title = oneLine(opts.title || (h1 ? h1[1] : base.replace(/\.md$/, '').replace(/[-_]+/g, ' ')));
  const tag = cleanTokens([opts.tag ?? 'field-guide'])[0] ?? 'field-guide';
  return [
    '---',
    `title: ${title}`,
    `tags: [${tag}]`,
    'priority: normal',
    `last_reviewed: ${opts.pulledOn}`,
    `source: ${oneLine(opts.source, 300)}`,
    '---',
    '',
  ].join('\n') + `\n${s.trim()}\n`;
}

/** A file name made from a heading: lowercase, words joined by dashes. */
export function slug(s: string, max = 60): string {
  const out = String(s ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return (out || 'section').slice(0, max).replace(/-+$/, '');
}

export interface GuideSection {
  /** Layer-relative, under the caller's corpus directory. */
  path: string;
  title: string;
  text: string;
}

/**
 * Splits one pulled document into single-topic files.
 *
 * The field guide is one 138 KB markdown file with 24 H2 sections. Copied
 * whole it is refused by knowledge-lint (a file over 24 KB is a quarter of
 * the injection budget in one file) and useless to the ranker, which would
 * either send all of it or none of it. Its H2 sections are 1–15 KB each and
 * are the natural citation units, so that is the cut.
 *
 * A section that is still too big is cut again at H3, into a directory named
 * for the section. Nothing is dropped: the text above the first heading
 * becomes `_index.md`, which the corpus convention already uses for a map.
 */
export function splitMarkdownSections(
  text: string, opts: { dir: string; maxBytes?: number },
): GuideSection[] {
  const maxBytes = opts.maxBytes ?? 24 * 1024;
  const src = String(text ?? '').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const out: GuideSection[] = [];
  const lines = src.split('\n');

  // Cut at a heading of the given level, returning the preamble and the
  // sections in document order.
  const cut = (body: string[], marker: string) => {
    const pre: string[] = [];
    const sections: { title: string; lines: string[] }[] = [];
    for (const line of body) {
      if (line.startsWith(marker) && line.charAt(marker.length) !== '#') {
        sections.push({ title: line.slice(marker.length).trim(), lines: [line] });
      } else if (sections.length) {
        sections[sections.length - 1].lines.push(line);
      } else {
        pre.push(line);
      }
    }
    return { pre, sections };
  };

  const top = cut(lines, '## ');
  const h1 = /^#\s+(.+)$/m.exec(src);
  const indexBody = top.pre.join('\n').trim();
  if (indexBody) {
    out.push({
      path: `${opts.dir}/_index.md`,
      title: h1 ? h1[1].trim() : opts.dir,
      text: indexBody + '\n',
    });
  }
  for (const s of top.sections) {
    const body = s.lines.join('\n').trim() + '\n';
    const name = slug(s.title);
    if (Buffer.byteLength(body, 'utf8') <= maxBytes) {
      out.push({ path: `${opts.dir}/${name}.md`, title: s.title, text: body });
      continue;
    }
    // Too long for one note. Cut again at H3, under a directory named for
    // the section, and keep whatever came before the first H3 as its map.
    const inner = cut(s.lines, '### ');
    const innerPre = inner.pre.join('\n').trim();
    if (innerPre) {
      out.push({ path: `${opts.dir}/${name}/_index.md`, title: s.title, text: innerPre + '\n' });
    }
    if (!inner.sections.length && !innerPre) {
      out.push({ path: `${opts.dir}/${name}.md`, title: s.title, text: body });
    }
    for (const sub of inner.sections) {
      out.push({
        path: `${opts.dir}/${name}/${slug(sub.title)}.md`,
        title: `${s.title} — ${sub.title}`,
        text: sub.lines.join('\n').trim() + '\n',
      });
    }
  }
  if (!out.length) {
    out.push({ path: `${opts.dir}/_index.md`, title: h1 ? h1[1].trim() : opts.dir, text: src.trim() + '\n' });
  }
  return out;
}

export interface PullDiff {
  added: string[];
  changed: string[];
  removed: string[];
  unchanged: number;
  /** True when nothing about the corpus would change. */
  same: boolean;
}

/**
 * What a pull would change, from two maps of path → content hash. Kept as a
 * pure comparison of two file lists rather than a `git diff` parse: the
 * question the card asks is "what changes in the CORPUS", and the corpus is
 * the subset of the repository that was copied, not the repository's own
 * commit range. A file renamed upstream shows as one removed and one added,
 * which is what it is on a node.
 *
 * An empty `before` (never pulled) makes every file an addition, which is
 * the honest first-pull summary.
 */
export function summarizePullDiff(
  before: Record<string, string>, after: Record<string, string>,
): PullDiff {
  const added: string[] = [], changed: string[] = [], removed: string[] = [];
  let unchanged = 0;
  for (const [p, h] of Object.entries(after)) {
    if (!(p in before)) added.push(p);
    else if (before[p] !== h) changed.push(p);
    else unchanged += 1;
  }
  for (const p of Object.keys(before)) if (!(p in after)) removed.push(p);
  added.sort(); changed.sort(); removed.sort();
  return { added, changed, removed, unchanged, same: !added.length && !changed.length && !removed.length };
}

/** The one-line summary the card leads with. Counts first, because that is
 *  the decision; the names are underneath it in the card itself. */
export function describePullDiff(d: PullDiff): string {
  if (d.same) return 'nothing has changed since the last pull';
  const parts: string[] = [];
  if (d.added.length) parts.push(`${d.added.length} added`);
  if (d.changed.length) parts.push(`${d.changed.length} changed`);
  if (d.removed.length) parts.push(`${d.removed.length} removed`);
  return parts.join(', ');
}
