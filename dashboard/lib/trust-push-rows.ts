/**
 * What a trust push's output becomes on the Settings page: one row per node,
 * each failed row with a reason key and the words that say it (#1184).
 *
 * Kept apart from settings-api.ts, which opens the database on import, so the
 * browser walk can run the REAL composition over the REAL push program's
 * output instead of a stub's idea of it.
 */

/** The hub's reading of one node's fleet link: held, and when it last was. */
export type LinkStatus = (label: string) => { held: boolean; last_held_ms: number | null } | null;

/** One row of a trust push's answer.
 *
 *  `reason` is the key the page branches on, and the only thing that does:
 *  never the words in `detail`.
 *    link_down    the node's fleet link to this aggregator was not up when the
 *                 push failed, so the push had no road to it
 *    unreachable  the push got no connection to it
 *    timeout      it was reached and did not answer in time
 *    refused      it answered, and would not take the list
 *    error        it answered a server error
 *    not_pushed   the push never sent to it (its token could not be read)
 *    not_started  the push itself did not run
 *    no_line      the push printed nothing for this node
 *  `link` is the hub's reading of that node's link at `read_at_ms`. */
export type PushReason =
  'link_down' | 'unreachable' | 'timeout' | 'refused' | 'error' | 'not_pushed' | 'not_started' | 'no_line';
export interface PushRow {
  label: string; ok: boolean; detail: string;
  reason?: PushReason;
  link?: { held: boolean; last_held_ms: number | null; read_at_ms: number };
}

/** The CLI's own last line, when it is only a summary. `aperire-auth.sh`
 *  prints exactly these two after the per-node lines; a drift row reads the
 *  script and fails if either stops matching. A line that is only a summary
 *  names no cause, and quoting "(see above)" back at the reader sent them to
 *  a line the page had dropped (#1184). */
export const PUSH_SUMMARY_RE = /^(All pushes succeeded\.|One or more pushes did not succeed \(see above\)\.?)/;

/** The line of a trust push's output that carries a cause when no per-node
 *  line does: the program's own `error:` line, the job's stderr line, the
 *  last line that is not a count of credentials or a summary. Never the
 *  summary. Null when the push printed nothing but those. */
export function pushCauseLine(output: string): string | null {
  const lines = output.split('\n').map((l) => l.trim()).filter(Boolean);
  const err = lines.find((l) => l.startsWith('error:'));
  if (err) return err;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (PUSH_SUMMARY_RE.test(lines[i])) continue;
    if (/^\d+ admin credential\(s\) in the bundle/.test(lines[i])) continue;
    if (/^Pushing trust to fleet nodes/.test(lines[i])) continue;
    return lines[i];
  }
  return null;
}

/** The line a failed push leaves in a sentence or an audit detail where there
 *  is no row to hold the per-node one: that node's own failed line when a
 *  label is asked for, the first failed node's otherwise, then the cause
 *  line. Never the summary that points above itself (#1184). */
export function pushFailedLine(output: string, label: string | null, known: Set<string>): string {
  const rows = pushResultsByNode(output, known).filter((n) => !n.ok);
  const mine = label === null ? rows[0] : rows.find((n) => n.label === label);
  if (mine) return `${mine.label}: ${mine.detail}`;
  return pushCauseLine(output) ?? 'the push reported nothing';
}

const when = (ms: number): string => new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

/** Give every failed row of a push its reason, and say it in words. */
export function annotatePushFailures(
  results: PushRow[],
  registry: Map<string, { transport?: string }>,
  linkStatus?: LinkStatus,
  now: number = Date.now(),
): void {
  for (const row of results) {
    if (row.ok) continue;
    const node = registry.get(row.label);
    let link: PushRow['link'];
    if (node?.transport === 'link' && linkStatus) {
      let st: ReturnType<LinkStatus>;
      try { st = linkStatus(row.label); } catch { st = null; }
      if (st) link = { held: st.held, last_held_ms: st.last_held_ms, read_at_ms: now };
    }
    const base = row.reason;
    // A push that never reached a node whose link is down is a link that is
    // down. A node answering a refusal or an error did get a road, so those
    // keep their own reason whatever the link says now.
    const reason: PushReason | undefined = link && !link.held && (base === 'unreachable' || base === 'timeout')
      ? 'link_down' : base;
    if (reason) row.reason = reason;
    if (link) row.link = link;
    row.detail = pushRowWords(row, link);
  }
}

/** The row's sentence. The program's own line stays in it, in quotes, so
 *  nothing it said is lost, and what this aggregator knew about the node's
 *  link leads. */
function pushRowWords(row: PushRow, link: PushRow['link']): string {
  const said = row.detail;
  const linkLine = !link ? ''
    : link.held ? ` Its fleet link to this aggregator was up when this was read (${when(link.read_at_ms)}).`
      : link.last_held_ms
        ? ` Its fleet link to this aggregator is down (last held ${when(link.last_held_ms)}, read ${when(link.read_at_ms)}).`
        : ` Its fleet link to this aggregator is down, and this aggregator has no record of it holding one (read ${when(link.read_at_ms)}).`;
  switch (row.reason) {
    case 'link_down':
      return `Not reached. ${linkLine.trim()} The push had nothing to travel over, so it still holds the passkey list it had. The program said: ${said}`;
    case 'unreachable':
      return `Not reached.${linkLine} The program said: ${said}`;
    case 'timeout':
      return `It did not answer in time.${linkLine} The program said: ${said}`;
    case 'refused':
      return `It answered, and would not take the list. The program said: ${said}`;
    case 'error':
      return `It answered with an error. The program said: ${said}`;
    case 'not_pushed':
      return `Nothing was sent to it. The program said: ${said}`;
    case 'no_line':
      return said
        ? `The push gave no result for this node. It said: ${said}`
        : 'The push gave no result for this node and printed nothing else.';
    default:
      return said;
  }
}

/** The per-node lines of an unscoped trust push: `  <label>: ok - ...`,
 *  `  <label>: FAILED ...`, `  <label>: unreachable - ...`, and the job's own
 *  `  <label>: failed, not pushed: ...`. Only a label this dashboard knows is
 *  taken, so a prose line that happens to start with a word and a colon is
 *  never a node. Each node once, in the order the CLI printed it. */
export function pushResultsByNode(
  output: string, known: Set<string>,
): PushRow[] {
  const out: PushRow[] = [];
  const at = new Map<string, number>();
  for (const line of output.split('\n')) {
    const m = /^\s{2}([a-z0-9][a-z0-9-]{0,31}): (ok|FAILED|failed|unreachable)\b(.*)$/.exec(line.trimEnd());
    if (!m || !known.has(m[1])) continue;
    const detail = `${m[2]}${m[3]}`.trim();
    const prior = at.get(m[1]);
    if (prior !== undefined) {
      // A label printed twice is never a clean outcome, whichever line says
      // ok: the program prints one line per node, so the second is not that
      // node's own result (#1099).
      out[prior].ok = false;
      out[prior].detail = `${out[prior].detail} (this node was listed twice in the push's output)`;
      out[prior].reason = out[prior].reason ?? 'no_line';
      continue;
    }
    at.set(m[1], out.length);
    const row: PushRow = { label: m[1], ok: m[2] === 'ok', detail };
    const reason = pushReasonOf(m[2], m[3]);
    if (reason) row.reason = reason;
    out.push(row);
  }
  return out;
}

/** The reason a per-node line carries, read from the program's own tokens and
 *  never from its prose: the word that leads the line, the `[HTTP n]` or
 *  `[timeout]` code the program prints after it. Null on an ok line. */
function pushReasonOf(token: string, rest: string): PushReason | null {
  if (token === 'ok') return null;
  if (token === 'unreachable') return /^\s*\[timeout\]/.test(rest) ? 'timeout' : 'unreachable';
  if (token === 'failed') return 'not_pushed';
  const http = /^\s*\[HTTP (\d{3})\]/.exec(rest);
  if (http && Number(http[1]) >= 500) return 'error';
  return 'refused';
}

/** The line of a failed unscoped push that no known node's row carries: a
 *  self row, a node the registry no longer names, a token that could not be
 *  read. Its own words, so the page can say what failed rather than quoting
 *  the summary's "(see above)" with nothing above it. Null when there is none. */
export function pushFailureLine(output: string, known: Set<string>): string | null {
  for (const line of output.split('\n')) {
    const m = /^\s{2}([a-z0-9][a-z0-9-]{0,31}): (FAILED|failed|unreachable)\b/.exec(line.trimEnd());
    if (m && !known.has(m[1])) return line.trim();
  }
  return null;
}

export function lastLine(output: string): string {
  return output.split('\n').map((l) => l.trim()).filter(Boolean).pop() ?? '';
}

/** The rows one entry of a trust push becomes. `entry` is a node label, or
 *  null for the unscoped push that reaches every node in one run. */
export function trustPushRows(
  entry: string | null, r: { ok: boolean; output: string }, known: Set<string>,
): PushRow[] {
  const perNode = pushResultsByNode(r.output, known);
  // "all" is one run, but it is not one result (#1099): the CLI prints a
  // line per node, and a page that counted the one aggregate entry said
  // "All 1 accepted" over a three-node fleet and, on a refusal, could not
  // name the node. One result per node it named, in its own words.
  if (entry === null) {
    if (perNode.length > 0) {
      const rows = [...perNode];
      // Every named node took it and the run still failed (a node it
      // could not name, a summary that says so): never lose that.
      if (!r.ok && perNode.every((n) => n.ok)) {
        rows.push({
          label: 'all', ok: false,
          detail: pushFailureLine(r.output, known) || pushCauseLine(r.output) || 'the push reported a failure',
        });
      }
      return rows;
    }
  } else if (!r.ok) {
    // One node asked for by name. Its own line is above the summary, and
    // the summary only says to look there (#1184): the row carries the
    // line, never the pointer to it.
    const own = perNode.find((n) => n.label === entry && !n.ok);
    if (own) return [own];
  }
  return [{
    label: entry ?? 'all',
    ok: r.ok,
    // The CLI's LAST line when it worked: it prints one per node and ends
    // with the summary, and that is the sentence an operator needs. Its words.
    detail: r.ok ? (lastLine(r.output) || 'pushed') : (pushCauseLine(r.output) ?? ''),
    ...(r.ok ? {} : { reason: 'no_line' as const }),
  }];
}
