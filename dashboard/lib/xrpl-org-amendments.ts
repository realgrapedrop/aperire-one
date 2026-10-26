// Parses xrpl.org's "known amendments" page into hash → description +
// xls_url. Pulled out of server.ts's pollXrplOrgAmendments so the scrape
// can be exercised against a real page fixture with no network call, see
// test/unit/xrpl-org-amendments.test.ts.
//
// Page structure has been stable for years: each amendment renders its
// hash inside a <td>, then a <p> description follows the metadata table's
// close. Tolerant to layout drift, silently skips any block it can't parse.
//
// #502: several descriptions open with a lead-in sentence ending in a
// colon and a <ul> (or, on the MPT amendment, several labelled sub-lists)
// that carries the actual substance ("Fixes two bugs in AMM transaction
// processing:" with the two bugs named in the list below it). The old
// scrape kept only the paragraph, so the colon promised a list that never
// showed up. When that shape appears, the list is folded into the
// description as plain text so the sentence completes.

import { sanitizeHttpUrl } from './url-policy.js';

export const AMENDMENT_DESCRIPTION_CAP = 1500;

export interface AmendmentDescriptionEntry {
  description: string;
  xls_url?: string;
}

/** Same entity set the old inline copy handled, moved here unchanged. */
export function decodeHtmlEntities(s: string): string {
  return s
    .replace(/&#x27;/gi, "'")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ');
}

function stripTags(fragment: string): string {
  return decodeHtmlEntities(fragment.replace(/<[^>]+>/g, '')).trim();
}

/**
 * Folds a <ul>/<ol>'s items into `leadText` (which already ends in a
 * colon) as one readable sentence: items joined with "; ", a full stop at
 * the end. When the joined result would run past `cap`, cuts at an item
 * boundary rather than truncating mid-sentence, and names how many items
 * were left off rather than silently dropping the whole entry.
 */
export function foldListIntoDescription(
  leadText: string,
  items: string[],
  cap: number = AMENDMENT_DESCRIPTION_CAP,
): string {
  // Each <li> already ends in its own full stop on the real page; strip it
  // so joining with "; " doesn't read as two sentence-ends back to back.
  const cleanItems = items.map(item => item.replace(/\.+\s*$/, '')).filter(Boolean);
  if (cleanItems.length === 0) return leadText;

  const full = `${leadText} ${cleanItems.join('; ')}.`;
  if (full.length <= cap) return full;

  for (let k = cleanItems.length - 1; k >= 0; k--) {
    const remaining = cleanItems.length - k;
    const candidate = k > 0
      ? `${leadText} ${cleanItems.slice(0, k).join('; ')} (and ${remaining} more)`
      : `${leadText} (and ${remaining} more)`;
    if (candidate.length <= cap) return candidate;
  }
  // The lead sentence alone is already at (or past) the cap on its own:
  // nothing fits alongside it. Caller's own cap check drops the entry.
  return leadText;
}

/**
 * Walks the HTML immediately after the lead paragraph collecting every
 * <li> from every <ul>/<ol> that belongs to the run the colon introduced.
 * Most entries are one list straight after the paragraph ("Fixes two
 * bugs...:" then a <ul>). One shape on the real page (the MPT amendment)
 * introduces several labelled sub-lists instead of one: a short
 * <p>...label:</p> naming what follows, then the <ul> for it, repeated.
 * Both read as one list for this purpose, the label paragraphs are the
 * only thing allowed to sit between list blocks, and only when they
 * themselves end in a colon (a genuine label, not the description
 * resuming as prose). The first tag that is neither one ends the run.
 */
function collectFollowingListItems(rest: string): string[] {
  const items: string[] = [];
  const tagRe = /^\s*<(p|ul|ol)[^>]*>([\s\S]*?)<\/\1>/i;
  let cursor = rest;
  for (;;) {
    const m = tagRe.exec(cursor);
    if (!m) break;
    const tag = m[1].toLowerCase();
    if (tag === 'ul' || tag === 'ol') {
      items.push(
        ...[...m[2].matchAll(/<li[^>]*>([\s\S]*?)<\/li>/gi)]
          .map(li => stripTags(li[1]))
          .filter(Boolean),
      );
    } else {
      // A <p>: only a sub-heading (itself ending in a colon) keeps the
      // run going. A plain paragraph means the description resumes as
      // prose, and the run of lists is over.
      if (!stripTags(m[2]).endsWith(':')) break;
    }
    cursor = cursor.slice(m[0].length);
  }
  return items;
}

/** One amendment's hash → description block: the metadata table's close,
 *  the description paragraph, and (when present) the list(s) it introduces
 *  and the Specification link. */
function parseBlock(afterTable: string, cap: number): AmendmentDescriptionEntry | null {
  const pMatch = /<p[^>]*>([\s\S]*?)<\/p>/i.exec(afterTable);
  if (!pMatch) return null;

  const leadText = stripTags(pMatch[1]);
  if (!leadText) return null;

  let description = leadText;
  if (leadText.endsWith(':')) {
    const rest = afterTable.slice((pMatch.index ?? 0) + pMatch[0].length);
    const items = collectFollowingListItems(rest);
    if (items.length > 0) description = foldListIntoDescription(leadText, items, cap);
    // A colon with no list after it (or an empty one) keeps the plain
    // paragraph, same as before #502.
  }

  if (description.length > cap) return null;

  const linkMatch = /<a[^>]+href="([^"]*XLS-[^"]*)"/i.exec(afterTable);
  return {
    description,
    xls_url: linkMatch ? sanitizeHttpUrl(linkMatch[1]) : undefined,
  };
}

/**
 * Scrapes hash → description + xls_url out of the known-amendments page's
 * raw HTML. Pure and network-free so it can run against a fixture cut from
 * the real page. server.ts's pollXrplOrgAmendments fetches the page and
 * hands the text straight to this function, then persists the result.
 */
export function parseKnownAmendmentsPage(
  html: string,
  cap: number = AMENDMENT_DESCRIPTION_CAP,
): Record<string, AmendmentDescriptionEntry> {
  const map: Record<string, AmendmentDescriptionEntry> = {};
  // Capture: hash, then content up to the next <h1/2/3 (next amendment
  // section), the description <p> and Specification <a> live in there.
  const blockRe = /<td[^>]*>([0-9A-F]{64})<\/td>([\s\S]*?)(?=<h[123]\s|$)/gi;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(html)) !== null) {
    const hash = m[1].toUpperCase();
    const tail = m[2] || '';
    // First <p> after the table is the description. Anything before
    // </table> is still inside the metadata table, skip past it.
    const afterTable = tail.split(/<\/table>/i).slice(1).join('</table>');
    const entry = parseBlock(afterTable, cap);
    if (entry) map[hash] = entry;
  }
  return map;
}

// ── On-disk library (knowledge/amendments.yaml) ─────────────────────────
// #542: the file used to carry no timestamp of its own, so its age was
// whatever the filesystem's mtime said, which after a deploy is the
// moment the tree's shipped copy was written, not the moment anyone
// scraped xrpl.org. An operator reading "just refreshed" off mtime right
// after a deploy would be reading the deploy, not a refresh. `refreshed_at`
// is a top-level ISO timestamp inside the file itself, so the age survives
// both a deploy and a restart honestly.

/** Result of reading the on-disk library back: the entries, keyed and
 *  validated the same way loadAmendmentsLibrary always has, plus the
 *  refresh moment recorded in the file (null for a file with none, an old
 *  format or a hand edit with no cadence marker). Never guessed. */
export interface AmendmentsLibraryFile {
  refreshedAtMs: number | null;
  entries: Record<string, AmendmentDescriptionEntry>;
}

/** Serializes hash → entry into the deterministic, hash-sorted YAML the
 *  dashboard reads back at startup, with `refreshed_at` as a top-level key
 *  ahead of the entries. `parseAmendmentsLibraryDoc` skips it in the entry
 *  loop the same way it always skipped any non-object value. */
export function renderAmendmentsLibraryYaml(
  map: Record<string, AmendmentDescriptionEntry>,
  nowMs: number,
): string {
  const sortedKeys = Object.keys(map).sort();
  const lines: string[] = [
    '# Aperire amendments knowledge library',
    '#',
    '# Auto-generated from https://xrpl.org/resources/known-amendments',
    '# Refreshed daily, on demand when xrpscan reveals a new amendment hash',
    '# with no description yet, and once at process startup regardless of',
    '# whether this host runs a local node. Hand-edits are overwritten on',
    '# next refresh, fork the URL or remove the cron if you need to',
    '# maintain custom copy.',
    '',
    `refreshed_at: ${JSON.stringify(new Date(nowMs).toISOString())}`,
    '',
  ];
  for (const hash of sortedKeys) {
    const e = map[hash];
    lines.push(`${hash}:`);
    lines.push(`  description: ${JSON.stringify(e.description)}`);
    if (e.xls_url) lines.push(`  xls_url: ${JSON.stringify(e.xls_url)}`);
    lines.push('');
  }
  return lines.join('\n');
}

/** Reads a `yaml.load()`-parsed library document back into entries plus its
 *  refresh moment. Pulled out of server.ts's loadAmendmentsLibrary so the
 *  parse can be exercised without touching the filesystem; MED-09
 *  re-validates xls_url on load too, since the file is hand-editable. */
export function parseAmendmentsLibraryDoc(doc: unknown): AmendmentsLibraryFile {
  const entries: Record<string, AmendmentDescriptionEntry> = {};
  let refreshedAtMs: number | null = null;
  if (doc && typeof doc === 'object') {
    for (const [key, raw] of Object.entries(doc as Record<string, unknown>)) {
      if (key === 'refreshed_at') {
        if (typeof raw === 'string') {
          const t = Date.parse(raw);
          if (Number.isFinite(t)) refreshedAtMs = t;
        }
        continue;
      }
      if (!raw || typeof raw !== 'object') continue;
      const v = raw as Record<string, unknown>;
      const description = typeof v.description === 'string' ? v.description : '';
      if (!description) continue;
      entries[key.toUpperCase()] = {
        description,
        xls_url: typeof v.xls_url === 'string' ? sanitizeHttpUrl(v.xls_url) : undefined,
      };
    }
  }
  return { refreshedAtMs, entries };
}

/** Which of the two on-disk libraries the dashboard loads at startup.
 *
 *  The runtime copy lives in data/ (ADR 0024: the unit may write data/ and
 *  nothing else in the tree). The tracked dashboard/knowledge/amendments.yaml
 *  is the copy the release ships, read only. A host that has never scraped
 *  has only the shipped one; a host whose scrapes have been failing may hold
 *  a runtime copy OLDER than what the last update shipped. So the newer of
 *  the two by its own `refreshed_at` wins, and on a tie, or when neither
 *  says, the runtime copy, because it is this host's own. A copy with no
 *  entries never wins over one that has some. */
export function pickAmendmentsLibrary(
  runtime: AmendmentsLibraryFile | null,
  shipped: AmendmentsLibraryFile | null,
): AmendmentsLibraryFile | null {
  const usable = (f: AmendmentsLibraryFile | null) =>
    f !== null && Object.keys(f.entries).length > 0;
  if (!usable(runtime)) return usable(shipped) ? shipped : runtime ?? shipped;
  if (!usable(shipped)) return runtime;
  const r = runtime!.refreshedAtMs ?? -Infinity;
  const s = shipped!.refreshedAtMs ?? -Infinity;
  return s > r ? shipped : runtime;
}

/** What a fetch call needs to look like for refreshAmendmentsLibrary: the
 *  same shape the global `fetch` satisfies, narrowed to what this function
 *  reads, so a test can hand in a fake without constructing a real
 *  Response. */
export interface AmendmentsFetchResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
}

export interface RefreshAmendmentsLibraryDeps {
  fetchImpl: (url: string) => Promise<AmendmentsFetchResponse>;
  writeImpl: (path: string, contents: string) => Promise<void>;
  path: string;
  nowMs: number;
}

export interface RefreshAmendmentsLibraryResult {
  ok: boolean;
  entries: Record<string, AmendmentDescriptionEntry>;
  /** Set only on success, to `deps.nowMs`, the moment recorded in the file
   *  and the moment the caller should adopt as this library's new age. */
  refreshedAtMs: number | null;
  /** Set only on failure, so the caller can say why rather than leaving a
   *  stale file looking current (#542). */
  reason?: string;
}

/** Fetches the known-amendments page, parses it, and writes the library
 *  file. The fetch/parse/write/stamp body of server.ts's
 *  pollXrplOrgAmendments, pulled out so the scheduling decision around it
 *  (call this once at startup with no rippled connection required, #542)
 *  can be driven by a fake clock and a fake fetch with no real network
 *  call and no filesystem write. Every failure path returns `ok: false`
 *  with a reason instead of throwing, matching the caller's existing
 *  "log it, don't crash the poll loop" contract. */
export async function refreshAmendmentsLibrary(
  deps: RefreshAmendmentsLibraryDeps,
): Promise<RefreshAmendmentsLibraryResult> {
  try {
    const res = await deps.fetchImpl('https://xrpl.org/resources/known-amendments');
    if (!res.ok) return { ok: false, entries: {}, refreshedAtMs: null, reason: `HTTP ${res.status}` };
    const html = await res.text();
    const map = parseKnownAmendmentsPage(html);
    if (Object.keys(map).length === 0) {
      return { ok: false, entries: {}, refreshedAtMs: null, reason: 'no amendment blocks found on the page' };
    }
    await deps.writeImpl(deps.path, renderAmendmentsLibraryYaml(map, deps.nowMs));
    return { ok: true, entries: map, refreshedAtMs: deps.nowMs };
  } catch (err) {
    return { ok: false, entries: {}, refreshedAtMs: null, reason: (err as Error).message };
  }
}
