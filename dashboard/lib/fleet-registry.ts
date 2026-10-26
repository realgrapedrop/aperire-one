/**
 * Dashboard-side fleet registry — decisions.md D5.
 *
 * A small, independent registry the dashboard's own header chip and NODES
 * panel read to build the node switcher. NEVER the advisor's
 * `advisor/state/fleet.json` — the dashboard must not depend on the optional
 * add-on. Same spirit as that registry (D1/D2), same fail-closed discipline,
 * but its own file and its own four fields, because the two consumers need
 * different things: the Advisor's row is evidence (an origin + a token), the
 * dashboard's row is a place to send the browser (a label, a navigation
 * target, and — separately — the loopback origin its own server polls for a
 * health dot).
 *
 * Fail-closed: any invalid entry, duplicate label, or unknown key drops the
 * WHOLE file to an empty fleet — never a partial list — logged once by the
 * caller with the one reason `error` names. One field is deliberately outside
 * that rule: an unusable `dashboard_url` is dropped from its row and reported
 * in `notes`, because it is the one field nothing on this dashboard renders or
 * dials, and a typo in a hand-edited address must not cost an operator their
 * fleet (#339). A file that is simply absent is
 * not an error: it is the documented single-node regression guarantee, and
 * returns the identical empty-fleet shape with `error: null` so a caller
 * cannot tell the two apart from the parse result alone (see
 * config/fleet.yaml.example and the "invalid vs absent render identically"
 * unit test — only the log line differs, and only loadFleetRegistry, which
 * knows whether a file existed, writes one).
 */
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { sanitizeHttpUrl } from './url-policy.js';
import { isLocalOnlyHost } from '../types/fleet-link-contract.js';

export interface FleetNodeConfig {
  label: string;
  /** Optional. Sanitized http(s) URL — the literal address of this node's
   *  own dashboard. Never appended to; an operator's subpath or trailing
   *  slash is theirs to get right.
   *
   *  Absent means this fleet does not know where that node's dashboard is
   *  (#339), which is an ordinary state and never an error: a node whose
   *  `public_url` is still the shipped default pairs without sending one.
   *  A row that carries a `.localhost` name or a loopback address is read
   *  the same way — the value is DROPPED rather than failing the file
   *  closed, because rows written before this change carry exactly that and
   *  a fleet that renders empty is a worse answer than a row with one field
   *  missing. */
  dashboard_url?: string;
  /** A bare loopback origin (http://127.0.0.1:<port> or http://localhost:<port>),
   *  no path/query/fragment/credentials. This is what the health poller
   *  fetches from THIS server process — never the browser. The fleet guide's
   *  tunnel section is why "loopback" reaches nodes on other machines: an
   *  SSH -L (or equivalent) that lands as loopback on this end. */
  read_origin: string;
  token_path: string;
  /** Optional. Pins this row's peer to a specific node public key
   *  (decisions.md D6 addendum). Absent — the field's own key is simply not
   *  in the entry — is unpinned: today's behaviour, byte for byte, and never
   *  logged or flagged as a lesser mode. Present but not shaped like a real
   *  node key (base58 starting with `n`, same shape server.ts's
   *  isRealValidatorKey and overview.html's realKey already check for a
   *  validator key) fails the WHOLE file closed, same as any other malformed
   *  entry — a typo'd pin is worse silently ignored than loudly refused.
   *  Checked at poll time by fleet-health.ts against the peer's own
   *  `/read/v1/identity`, never at parse time (this module has no network
   *  access and shouldn't grow any). */
  expected_pubkey_node?: string;
  /** Optional — ADR 0014 slice 1. A bare loopback origin where this node's
   *  OWN advisord lands on this host (the `781x` forward beside the read
   *  forward's `780x`; the remote port is whatever that host's advisord was
   *  given as --addr, discovered at join time — never assumed). Absent =
   *  no advisor stack registered for this node, which decision 6's honest
   *  degrade renders as exactly that. Same loopback rule as read_origin. */
  advisor_origin?: string;
  /** Optional — ADR 0014 slice 1. Path to this peer's advisord
   *  approve.token, read fresh per request server-side and never sent to
   *  the browser (advisord gates its whole /v1 with the one token; the
   *  exact-path allow-list in peer-advisor-proxy.ts is what keeps slice 1
   *  read-only, not the credential). Must be present iff advisor_origin
   *  is — half a reference is a misconfiguration, refused at parse. */
  advisor_token_path?: string;
  /** Optional — ADR 0019 decision 1. How this dashboard reaches that node:
   *  `loopback` (a forward, or this host) or `link` (the node's own outbound
   *  fleet link, terminating in a loopback listener this process binds).
   *  Absent means `loopback`, which is every row written before the link
   *  existed, so an untouched fleet.yaml parses byte for byte as it did.
   *
   *  It changes NOTHING about how a peer is read. read_origin is still a
   *  bare loopback origin and every fleet surface still dials it; the key
   *  exists so a row can say which kind of outage it is having, which ADR
   *  0019's consequences call out as the difference between diagnosing a
   *  fleet incident once and diagnosing it twice. A closed set, like `role`,
   *  because it is rendered and a typo must not read as a third transport. */
  transport?: FleetTransport;
  /** Optional. What this node IS in the fleet — one of ROLES below. The
   *  dashboard itself does not act on it; it is carried here because
   *  fleet.yaml is the one file in the estate that holds a rich per-node
   *  record, and the Advisor's own registry is GENERATED from it rather
   *  than hand-edited a second time (two files holding the same fleet is
   *  how a node ended up pointing at a host that no longer existed).
   *
   *  Absent means UNSPECIFIED and is never inferred: a dashboard with no
   *  node and no container looks exactly as much like an aggregator as it
   *  does like a broken node, and guessing between them is the failure this
   *  field exists to prevent. Present but not a known role fails the WHOLE
   *  file closed, same as any other malformed field. */
  role?: FleetRole;
}

/** The roles a fleet member may declare. A closed set, mirrored in Go at
 *  advisor/internal/fleet (RoleAggregator … RoleRelay) — same words, checked
 *  independently on each side, because the dashboard and advisord do not
 *  import from one another. */
export const ROLES = ['aggregator', 'node', 'validator', 'relay'] as const;
export type FleetRole = (typeof ROLES)[number];

/** The transports a fleet row may declare. Absent is `loopback`. */
export const TRANSPORTS = ['loopback', 'link'] as const;
export type FleetTransport = (typeof TRANSPORTS)[number];

/** A validator/node public key is base58 and starts with `n`. Mirrors
 *  server.ts's isRealValidatorKey and overview.html's realKey — same shape,
 *  independently re-declared here because this module has no dependency on
 *  server.ts and shouldn't grow one for one regex. */
const NODE_KEY_RE = /^n[1-9A-HJ-NP-Za-km-z]{20,}$/;

export interface FleetParseResult {
  nodes: FleetNodeConfig[];
  /** Set only when the file existed but failed to parse or validate. */
  error: string | null;
  /** Things this parser dropped rather than refused, one sentence each, for
   *  the caller's journal. Never a reason to fail the file: a note is what a
   *  row lost, and the row is still here. Empty on a clean parse and on a
   *  refusal both, so a caller can log them unconditionally.
   *
   *  Nothing reads a note but a log line. It never carries a raw value that
   *  could hold a scheme this dashboard would not follow — the shape is what
   *  the operator needs and the value is what they already have in the file. */
  notes: string[];
}

const LABEL_RE = /^[a-z0-9-]{1,32}$/;
const REQUIRED_KEYS = ['label', 'read_origin', 'token_path'] as const;
// OPTIONAL keys an entry may carry. Allowed at the unknown-key check below
// but never required, so their absence stays exactly today's parse.
// advisor_origin + advisor_token_path are ADR 0014 slice 1: the reference —
// an origin and a token path — that makes the aggregator a vantage point
// onto a node's own advisord. Absence of BOTH is the supported "no advisor
// stack on this node" state decision 6's degrade reads.
const ALLOWED_KEY_SET: ReadonlySet<string> = new Set([
  // `dashboard_url` is named HERE and no longer in REQUIRED_KEYS (#339).
  // This set is built from that list, so taking the key out of it without
  // putting it back here would make every already-written row carry an
  // unknown key and fail the whole file closed — an empty fleet on every
  // paired aggregator.
  ...REQUIRED_KEYS, 'dashboard_url', 'expected_pubkey_node', 'advisor_origin', 'advisor_token_path', 'role',
  // ADR 0019 decision 1 says this in as many words: the parser fails the
  // whole file closed on an unknown key, so if a row is to declare its
  // transport the parser learns the key in the same commit or the fleet
  // renders empty.
  'transport',
]);
const ROLE_SET: ReadonlySet<string> = new Set(ROLES);
const TRANSPORT_SET: ReadonlySet<string> = new Set(TRANSPORTS);

function isLoopbackOrigin(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.pathname !== '/' && u.pathname !== '') return false;
  if (u.search || u.hash || u.username || u.password) return false;
  const host = u.hostname.toLowerCase();
  return host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]';
}

/** The registry's half of the #339 rule, asked of a value already known to
 *  be an http(s) URL. The PREDICATE is the wire's — one owner, imported,
 *  for the reason scripts/fleet-origin.sh is one file: a second hand-written
 *  copy of a host rule is a second chance to get it wrong (P3-059). */
function isLocalOnlyDashboardUrl(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return true; }
  return isLocalOnlyHost(u.hostname);
}

function validateEntry(raw: unknown, index: number, notes: string[]): FleetNodeConfig | string {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return `fleet[${index}] is not a mapping`;
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!ALLOWED_KEY_SET.has(k)) return `fleet[${index}] has an unknown key "${k}"`;
  }
  for (const k of REQUIRED_KEYS) {
    const v = obj[k];
    if (typeof v !== 'string' || v.length === 0) {
      return `fleet[${index}] is missing or has an empty "${k}"`;
    }
  }
  const label = obj.label as string;
  if (!LABEL_RE.test(label)) {
    return `fleet[${index}] label "${label}" must match [a-z0-9-]{1,32}`;
  }
  // Optional since #339, and never a reason to fail the file. Every value
  // this row cannot use is DROPPED, the row is kept, and one sentence goes
  // to the caller's journal:
  //
  //   absent           not set, and not worth a line. A node whose public_url
  //                    is still the shipped default pairs without sending
  //                    one, and a fleet that does not know where a dashboard
  //                    lives says so.
  //   a local-only URL not set, with a line. Rows written before #339 carry
  //                    `https://ubuntu-22.localhost/...`, built from the
  //                    host's own FQDN: well-formed, and openable only on
  //                    that box.
  //   anything else    not set, with a line. A typo in a hand-edited address
  //                    must not cost the operator their fleet, and this field
  //                    is the one field on a row that nothing renders and
  //                    nothing dials. Fail-closed stays where it earns its
  //                    keep: the label, the loopback origin, the pin, the
  //                    role, the transport and the advisor pair, each of
  //                    which decides what this dashboard READS.
  //
  // The explicit scheme test is not redundant with sanitizeHttpUrl: that one
  // resolves against a base, so `overview.html` and even an empty string come
  // back as a URL on somebody else's host. A row's dashboard address is
  // absolute or it is nothing.
  //
  // The note names the row and the SHAPE, never the value. `javascript:...`
  // is the case that matters: this string is the literal target of a link,
  // and a journal an operator greps is not the place to reproduce one.
  let dashboardUrl: string | undefined;
  if (Object.prototype.hasOwnProperty.call(obj, 'dashboard_url')) {
    const rawUrl = obj.dashboard_url;
    const clean = typeof rawUrl === 'string' && /^https?:\/\//i.test(rawUrl)
      ? sanitizeHttpUrl(rawUrl) : undefined;
    if (!clean) {
      notes.push(`fleet entry "${label}" has a dashboard_url that is not an absolute http(s) URL, `
        + `so that row carries no dashboard address`);
    } else if (isLocalOnlyDashboardUrl(clean)) {
      notes.push(`fleet entry "${label}" has a dashboard_url naming only that node itself `
        + `(${new URL(clean).hostname}), which no other machine can open, so that row carries `
        + `no dashboard address`);
    } else {
      dashboardUrl = clean;
    }
  }
  const readOriginRaw = obj.read_origin as string;
  if (!isLoopbackOrigin(readOriginRaw)) {
    return `fleet entry "${label}" read_origin must be a bare loopback origin ` +
      `(http://127.0.0.1:<port> or http://localhost:<port>, no path)`;
  }
  // Optional. Absent entirely = unpinned, today's behaviour byte for byte —
  // this branch never runs for an entry that doesn't carry the key. Present
  // but not shaped like a plausible node key fails the WHOLE file closed,
  // same rule as every other malformed field here.
  let expectedPubkeyNode: string | undefined;
  if (Object.prototype.hasOwnProperty.call(obj, 'expected_pubkey_node')) {
    const raw = obj.expected_pubkey_node;
    if (typeof raw !== 'string' || !NODE_KEY_RE.test(raw)) {
      return `fleet entry "${label}" expected_pubkey_node is not shaped like a node public key ` +
        `(base58, starting with "n")`;
    }
    expectedPubkeyNode = raw;
  }
  // ADR 0014 slice 1: both or neither. An origin with no token can only
  // produce auth failures that read as a broken advisord; a token with no
  // origin is a secret path nothing will ever read. Either half alone is a
  // misconfiguration and fails the WHOLE file closed, same rule as every
  // other malformed field here.
  // Optional, and a closed set. A mistyped role is refused rather than
  // carried — it is generated onward into the Advisor's registry and from
  // there into a prompt, and free text is not something either should be
  // able to grow by a typo.
  let role: FleetRole | undefined;
  if (Object.prototype.hasOwnProperty.call(obj, 'role')) {
    const rawRole = obj.role;
    if (typeof rawRole !== 'string' || !ROLE_SET.has(rawRole)) {
      return `fleet entry "${label}" role must be one of ${ROLES.join(', ')}`;
    }
    role = rawRole as FleetRole;
  }
  let transport: FleetTransport | undefined;
  if (Object.prototype.hasOwnProperty.call(obj, 'transport')) {
    const rawTransport = obj.transport;
    if (typeof rawTransport !== 'string' || !TRANSPORT_SET.has(rawTransport)) {
      return `fleet entry "${label}" transport must be one of ${TRANSPORTS.join(', ')}`;
    }
    transport = rawTransport as FleetTransport;
  }
  const hasAdvisorOrigin = Object.prototype.hasOwnProperty.call(obj, 'advisor_origin');
  const hasAdvisorToken = Object.prototype.hasOwnProperty.call(obj, 'advisor_token_path');
  if (hasAdvisorOrigin !== hasAdvisorToken) {
    return `fleet entry "${label}" must carry advisor_origin and advisor_token_path together or not at all`;
  }
  let advisorOrigin: string | undefined;
  let advisorTokenPath: string | undefined;
  if (hasAdvisorOrigin) {
    const rawOrigin = obj.advisor_origin;
    if (typeof rawOrigin !== 'string' || !isLoopbackOrigin(rawOrigin)) {
      return `fleet entry "${label}" advisor_origin must be a bare loopback origin ` +
        `(http://127.0.0.1:<port> or http://localhost:<port>, no path)`;
    }
    const rawToken = obj.advisor_token_path;
    if (typeof rawToken !== 'string' || rawToken.length === 0) {
      return `fleet entry "${label}" advisor_token_path must be a non-empty path`;
    }
    advisorOrigin = rawOrigin.replace(/\/+$/, '');
    advisorTokenPath = rawToken;
  }
  return {
    label,
    ...(dashboardUrl ? { dashboard_url: dashboardUrl } : {}),
    read_origin: readOriginRaw.replace(/\/+$/, ''),
    token_path: obj.token_path as string,
    ...(expectedPubkeyNode ? { expected_pubkey_node: expectedPubkeyNode } : {}),
    ...(role ? { role } : {}),
    ...(transport ? { transport } : {}),
    ...(advisorOrigin ? { advisor_origin: advisorOrigin, advisor_token_path: advisorTokenPath } : {}),
  };
}

/** Parses and validates fleet.yaml text. Never throws — any failure returns
 *  an empty fleet with `error` naming the one reason, so the caller can log
 *  once and keep serving single-node behaviour rather than crash. */
export function parseFleetYaml(text: string): FleetParseResult {
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch (err) {
    return { nodes: [], error: `fleet.yaml is not valid YAML: ${(err as Error).message}`, notes: [] };
  }
  if (doc === null || doc === undefined) return { nodes: [], error: null, notes: [] };
  if (typeof doc !== 'object' || Array.isArray(doc)) {
    return { nodes: [], error: 'fleet.yaml must be a mapping with a top-level "fleet:" list', notes: [] };
  }
  const list = (doc as Record<string, unknown>).fleet;
  if (list === undefined) return { nodes: [], error: null, notes: [] };
  if (!Array.isArray(list)) return { nodes: [], error: 'fleet.yaml "fleet:" must be a list', notes: [] };

  const nodes: FleetNodeConfig[] = [];
  const notes: string[] = [];
  const seenLabels = new Set<string>();
  for (let i = 0; i < list.length; i++) {
    const result = validateEntry(list[i], i, notes);
    // A refusal takes the notes with it. The file is empty either way, and a
    // line about a row inside a file nobody kept would send an operator to
    // the wrong line of it.
    if (typeof result === 'string') return { nodes: [], error: result, notes: [] };
    if (seenLabels.has(result.label)) {
      return { nodes: [], error: `fleet.yaml has a duplicate label "${result.label}"`, notes: [] };
    }
    seenLabels.add(result.label);
    nodes.push(result);
  }
  return { nodes, error: null, notes };
}

/** Reads fleet.yaml from disk and parses it. A missing file is the
 *  documented single-node state, not an error — identical shape to a file
 *  that parses to an empty list, `error: null` either way. Any other read
 *  failure (permissions, a directory in its place, …) fails closed the same
 *  way a bad parse does. */
export function loadFleetRegistry(path: string): FleetParseResult {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { nodes: [], error: null, notes: [] };
    return { nodes: [], error: `fleet.yaml could not be read: ${(err as Error).message}`, notes: [] };
  }
  return parseFleetYaml(text);
}

// ── Editing the registry in place (#444, #422) ───────────────────────────
//
// Two edits, and both are TEXT edits on the lines of one row. Never a
// load-then-dump cycle: `config/fleet.yaml.example` ships a commented-out
// `expected_pubkey_node` and a commented-out `transport: link`, and a round
// trip through a YAML dumper deletes both invisibly. The root broker's
// `approve` appends as text for exactly that reason, and these two are its
// mirror image, so a hand-written row survives a revoke of the row beside it.
//
// A comment written INSIDE the row being removed goes with it, because it is
// inside the row. A comment written ABOVE the row stays where it is: that is
// the operator's prose rather than the row, and this edit never deletes an
// operator's writing. A stale note is visible; a deleted one is not.
//
// Every edit is validated before it is offered back: the candidate is parsed
// by this file's own parser, the row that was meant to change is checked, and
// every other row is compared field for field against the original. The
// caller writes nothing a parse did not agree with, which is the same
// discipline the broker's three-candidate rule follows.

/** What one edit produced, or the one reason there is nothing to write. */
export type FleetEditResult =
  | { ok: true; text: string }
  | { ok: false; error: string; detail: string };

interface RowBlock {
  label: string | null;
  /** Line indices, [from, to), into the array the block was cut from. */
  from: number;
  to: number;
  indent: number;
}

/** The `- ` items of the top-level list, as line ranges.
 *
 *  An item starts on a line whose first non-space character is `-` and runs
 *  until the next item at the same indentation, or until a line indented no
 *  further than it (which is the end of the list). Blank lines and comments
 *  between rows belong to the row above, which is what keeps a note an
 *  operator left under a row with that row. */
function rowBlocks(lines: string[]): RowBlock[] {
  const blocks: RowBlock[] = [];
  let current: RowBlock | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const item = /^(\s*)-\s/.exec(line);
    const bare = line.trim();
    if (item) {
      const indent = item[1].length;
      if (current && indent <= current.indent) {
        current.to = i;
        blocks.push(current);
        current = null;
      }
      if (!current) { current = { label: null, from: i, to: lines.length, indent }; continue; }
    }
    if (!current) continue;
    // A line that is neither blank, nor a comment, nor indented past the
    // item's dash has left the list: `fleet:` ended and something else began.
    if (bare !== '' && !bare.startsWith('#') && !item) {
      const indent = (/^(\s*)/.exec(line) ?? ['', ''])[1].length;
      if (indent <= current.indent) {
        current.to = i;
        blocks.push(current);
        current = null;
      }
    }
  }
  if (current) blocks.push(current);
  for (const b of blocks) {
    for (let i = b.from; i < b.to; i++) {
      const m = /^\s*(?:-\s+)?label:\s*(.+?)\s*$/.exec(lines[i]);
      // The first `label:` in the block, with any quoting the operator used
      // taken off. A second one fails the whole file closed at the parser.
      if (m) { b.label = m[1].replace(/^['"]|['"]$/g, ''); break; }
    }
  }
  return blocks;
}

/** The rows a parse produced, keyed by label, for the "nothing else moved"
 *  comparison every edit below makes. */
function rowsByLabel(nodes: FleetNodeConfig[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of nodes) out.set(n.label, JSON.stringify(n));
  return out;
}

/** Everything a candidate has to prove before a caller may write it: it
 *  parses, and every row other than the one named is field for field what it
 *  was. Null when the candidate is good. */
function untouchedElsewhere(
  before: FleetNodeConfig[], candidate: string, label: string,
): { error: string; detail: string } | null {
  const parsed = parseFleetYaml(candidate);
  if (parsed.error) {
    return {
      error: 'candidate_unreadable',
      detail: `this dashboard’s own parser refused the registry it was about to write (${parsed.error}), `
        + 'so nothing was written.',
    };
  }
  const was = rowsByLabel(before);
  const now = rowsByLabel(parsed.nodes);
  for (const [other, shape] of was) {
    if (other === label) continue;
    if (!now.has(other)) {
      return { error: 'row_lost', detail: `the registry this would have written had lost the row “${other}”, so nothing was written.` };
    }
    if (now.get(other) !== shape) {
      return { error: 'row_changed', detail: `the registry this would have written had changed the row “${other}”, so nothing was written.` };
    }
  }
  for (const other of now.keys()) {
    if (other !== label && !was.has(other)) {
      return { error: 'row_added', detail: `the registry this would have written had grown a row “${other}”, so nothing was written.` };
    }
  }
  return null;
}

/**
 * Take one node's row out of the registry text (#444).
 *
 * The caller's ORDER matters and is not this function's to enforce: the
 * broker's `revoke` closes the link row first, and only then is the
 * `fleet.yaml` row dropped. The other way round leaves a moment where
 * `fleet-links.json` names a label `fleet.yaml` does not, which holds THAT
 * row (#687 made the hold per row; it used to fail the whole file closed and
 * tear down every live link on the fleet).
 */
export function dropFleetRow(text: string, label: string): FleetEditResult {
  const before = parseFleetYaml(text);
  if (before.error) {
    return {
      ok: false, error: 'registry_unreadable',
      detail: `this dashboard cannot read its own registry (${before.error}), so it will not rewrite it.`,
    };
  }
  if (!before.nodes.some((n) => n.label === label)) {
    return { ok: false, error: 'no_such_row', detail: `the registry has no row called “${label}”, so there is nothing to drop.` };
  }
  const lines = text.split('\n');
  const block = rowBlocks(lines).find((b) => b.label === label);
  if (!block) {
    return {
      ok: false, error: 'row_not_a_block',
      detail: `the row for “${label}” is not written as its own list item, so this dashboard will not `
        + 'edit it. Take it out of the registry by hand.',
    };
  }
  const keep = [...lines.slice(0, block.from), ...lines.slice(block.to)];
  // THE LAST ROW takes the `fleet:` key with it. A mapping key with nothing
  // under it loads as null, which this file's own parser refuses as "fleet:
  // must be a list" and fails the whole registry closed: revoking the only
  // node would have left an aggregator that could not read its own registry
  // at all. The guide's hand instruction for the same case has always been
  // "delete its row, or the whole file, to return to single-node", and this
  // is that, one line rather than the file, so an operator's comments stay.
  if (before.nodes.length === 1) {
    for (let i = keep.length - 1; i >= 0; i--) {
      if (/^\s*fleet:\s*$/.test(keep[i])) { keep.splice(i, 1); break; }
    }
  }
  const candidate = keep.join('\n');
  const parsed = parseFleetYaml(candidate);
  if (!parsed.error && parsed.nodes.some((n) => n.label === label)) {
    return {
      ok: false, error: 'row_survived',
      detail: `the row for “${label}” was still in the registry this would have written, so nothing was written.`,
    };
  }
  const wrong = untouchedElsewhere(before.nodes, candidate, label);
  if (wrong) return { ok: false, ...wrong };
  return { ok: true, text: candidate };
}

/**
 * Replace one row's pinned node key (#422).
 *
 * Only ever called behind the passkey ceremony that showed an operator both
 * keys. This function makes no judgement about whether the new key is the
 * right one: that judgement is the operator's, and it is the whole ceremony.
 * What it does refuse is a key another row already pins, which is the
 * copied-install hazard `approve` refuses under the same name.
 */
export function repinFleetRow(text: string, label: string, pubkeyNode: string): FleetEditResult {
  const before = parseFleetYaml(text);
  if (before.error) {
    return {
      ok: false, error: 'registry_unreadable',
      detail: `this dashboard cannot read its own registry (${before.error}), so it will not rewrite it.`,
    };
  }
  if (!before.nodes.some((n) => n.label === label)) {
    return { ok: false, error: 'no_such_row', detail: `the registry has no row called “${label}”, so there is nothing to re-pin.` };
  }
  if (!NODE_KEY_RE.test(pubkeyNode)) {
    return { ok: false, error: 'bad_key', detail: 'that is not the shape of a node key, so nothing was written.' };
  }
  const taken = before.nodes.find((n) => n.label !== label && n.expected_pubkey_node === pubkeyNode);
  if (taken) {
    return {
      ok: false, error: 'pin_taken',
      detail: `the registry already pins that node key to the row “${taken.label}”. Two labels on one node `
        + 'key is a copied install, and it reads as wrong fleet data under the wrong name.',
    };
  }
  const lines = text.split('\n');
  const block = rowBlocks(lines).find((b) => b.label === label);
  if (!block) {
    return {
      ok: false, error: 'row_not_a_block',
      detail: `the row for “${label}” is not written as its own list item, so this dashboard will not `
        + 'edit it. Change its pinned key by hand.',
    };
  }
  const next = [...lines];
  let replaced = false;
  for (let i = block.from; i < block.to; i++) {
    const m = /^(\s*(?:-\s+)?)expected_pubkey_node:\s*.*$/.exec(next[i]);
    if (!m) continue;
    // The dash stays where it is: a key written as the item's first line
    // carries the `- `, and rewriting it without one takes the row out of
    // the list.
    next[i] = `${m[1]}expected_pubkey_node: ${pubkeyNode}`;
    replaced = true;
    break;
  }
  if (!replaced) {
    // An unpinned row gains a pin, at the indentation of its own fields.
    const dash = /^(\s*)-\s+/.exec(lines[block.from]);
    const pad = dash ? ' '.repeat(dash[1].length + 2) : '    ';
    next.splice(block.from + 1, 0, `${pad}expected_pubkey_node: ${pubkeyNode}`);
  }
  const candidate = next.join('\n');
  const parsed = parseFleetYaml(candidate);
  if (parsed.error) {
    return {
      ok: false, error: 'candidate_unreadable',
      detail: `this dashboard’s own parser refused the registry it was about to write (${parsed.error}), so nothing was written.`,
    };
  }
  const after = parsed.nodes.find((n) => n.label === label);
  if (!after || after.expected_pubkey_node !== pubkeyNode) {
    return {
      ok: false, error: 'pin_not_written',
      detail: `the row for “${label}” did not come back pinned to that key, so nothing was written.`,
    };
  }
  const wrong = untouchedElsewhere(before.nodes, candidate, label);
  if (wrong) return { ok: false, ...wrong };
  return { ok: true, text: candidate };
}
