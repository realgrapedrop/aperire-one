/**
 * Asking the update program to do something, and reading what it says while
 * it does it.
 *
 * ADR 0022 phase 2. The dashboard never writes its own tree: it runs under
 * NoNewPrivileges with an empty capability set (#153), so the apply, the
 * restart and the rollback are verbs of a root program systemd starts behind
 * /run/aperire/update.sock. This file is the client for that conversation,
 * and it is the only place that knows the program's grammar.
 *
 * Three rules hold it together.
 *
 *  1. **The payload carries no source.** It names a tag, a commit and a
 *     sha256 the page believes is current, and the program compares those
 *     with what it fetched for itself from its own root-owned config. A
 *     payload can narrow what is installed, never widen it: the worst a
 *     compromised web session does with this socket is install the release
 *     the publisher published, or nothing. That is ADR 0022 decision 3, and
 *     `updateFieldRefusal` is the frame that keeps it true — the program
 *     reads `key=value` off one line, so a value carrying whitespace or a
 *     line break would smuggle a second field past it.
 *  2. **The answer is read as it arrives, not when it ends.** An apply takes
 *     minutes (`npm ci` and two Go builds are inside it) and the operator is
 *     watching. `createUpdateRun()` is fed socket chunks and can be asked
 *     what it knows at any moment, so the page tails a run rather than
 *     waiting for one.
 *  3. **A socket that will not open is not a refusal.** ENOENT means no
 *     updater is installed on this host, which is a different sentence from
 *     the program saying no, and an operator acts on the two differently.
 *
 * The stream itself is the sealer's shape (`splitSealerStream`, and the same
 * reason: an exit code does not cross a socket, so `exit=<code>` is the last
 * line). What is added here is that the fact lines in the middle are
 * progress rather than a result.
 */
import { isSocketUnreachable } from './model-seal.js';
import {
  updaterEndpointDisagreement,
  type UpdateCheckResult, type UpdaterReading, type EndpointDisagreement,
} from './update-check.js';

/** Where systemd listens on this host. Root owns the program behind it;
 *  this account owns the socket and may open it, which is the whole grant.
 *  A host without the grant has no socket here, and the connection is
 *  refused rather than answered. */
export const UPDATE_SOCKET = '/run/aperire/update.sock';

/** The steps the program announces, in the order an apply runs them. `done`
 *  and `failed` are steps too: a run ends by saying which. */
export const UPDATE_STEPS = ['snapshot', 'fetch', 'carry', 'install', 'done', 'failed'] as const;
export type UpdateStep = typeof UPDATE_STEPS[number];

/** What the program has said so far. `code` is null until `exit=` lands,
 *  which is exactly "still running": a snapshot taken mid-apply must not be
 *  readable as a result. */
export interface UpdateSnapshot {
  code: number | null;
  steps: UpdateStep[];
  facts: Record<string, string>;
  /** The program's own words, for the operator. Fact lines are not in here:
   *  they are machine grammar and reading them aloud is not a progress
   *  story. Capped, oldest dropped first. */
  lines: string[];
}

/** How many of the program's own lines are kept. An apply's build chain is
 *  noisy and the page shows a tail; keeping the whole of it in memory for a
 *  run nobody is watching is cost with no reader. */
const DEFAULT_MAX_LINES = 400;

export interface UpdateRunReader {
  /** One socket chunk. Chunk boundaries are not line boundaries. */
  feed(chunk: string): void;
  /** The connection closed. Flushes a trailing line with no newline after
   *  it, and settles the code. */
  end(): void;
  snapshot(): UpdateSnapshot;
}

/**
 * A reader that can be fed a socket a piece at a time.
 *
 * The buffering is the load-bearing part. A read can split `step=install`
 * into `step=inst` and `all`, and a parser that splits each chunk on its own
 * would record two lines, neither of them a step. So a partial trailing line
 * is held back until the newline that ends it arrives.
 */
export function createUpdateRun(opts: { maxLines?: number } = {}): UpdateRunReader {
  const maxLines = opts.maxLines ?? DEFAULT_MAX_LINES;
  const steps: UpdateStep[] = [];
  const facts: Record<string, string> = {};
  const lines: string[] = [];
  let code: number | null = null;
  let pending = '';
  let closed = false;

  const isStep = (v: string): v is UpdateStep => (UPDATE_STEPS as readonly string[]).includes(v);

  const takeLine = (line: string): void => {
    // Digits are part of a field name. `installed_sha256`, `published_sha256`
    // and `stamp_sha256` are three of the program's own facts, and a pattern
    // of `[a-z_]+` matched none of them: they were dropped into the human
    // lines and no reader ever saw them (#293).
    const field = /^([a-z][a-z0-9_]*)=(.*)$/.exec(line);
    if (!field) {
      // Anything that is not `name=value` is the program talking to a human.
      if (line.trim() !== '') {
        lines.push(line);
        while (lines.length > maxLines) lines.shift();
      }
      return;
    }
    const name = field[1];
    const value = field[2].trim();
    if (name === 'exit') {
      // Only a plain number counts. Anything else is not the program's own
      // last line, and reading it as one would invent an outcome.
      if (/^\d+$/.test(value)) code = Number(value);
      return;
    }
    if (name === 'step' && isStep(value)) {
      // Consecutive repeats are one step. A program that says it is still
      // installing has not started a second install.
      if (steps[steps.length - 1] !== value) steps.push(value);
    }
    facts[name] = value;
  };

  return {
    feed(chunk: string): void {
      if (closed) return;
      pending += chunk;
      const parts = pending.split('\n');
      pending = parts.pop() ?? '';
      for (const line of parts) takeLine(line);
    },
    end(): void {
      if (closed) return;
      closed = true;
      if (pending !== '') { takeLine(pending); pending = ''; }
      if (code === null) {
        // No last line means the program never reached its own exit handler:
        // it was killed, or it never started. Not a refusal, and not a
        // success. Same reading splitSealerStream takes, and for the same
        // reason.
        lines.push('the updater ended without reporting');
        while (lines.length > maxLines) lines.shift();
        code = 1;
        if (steps[steps.length - 1] !== 'failed') steps.push('failed');
      }
    },
    snapshot(): UpdateSnapshot {
      return { code, steps: [...steps], facts: { ...facts }, lines: [...lines] };
    },
  };
}

/** The whole stream at once, for a caller that was not watching. One
 *  implementation with the incremental path: a run fed byte by byte and the
 *  same bytes fed whole must read identically. */
export function parseUpdateStream(raw: string): UpdateSnapshot {
  const run = createUpdateRun();
  run.feed(raw);
  run.end();
  return run.snapshot();
}

// ── The verbs ────────────────────────────────────────────────────────────
//
// One line each, `verb` then `key=value` fields separated by single spaces.
// The program reads it positionally-by-name off one line, which is why every
// field below is checked for whitespace before it is joined: a value holding
// a space is a second field the operator never approved.

export interface ApplyRelease { tag: string; commit: string; sha256: string }

/** What each field may hold, anchored at both ends. Deliberately narrower
 *  than what a publisher could theoretically emit: these three come off a
 *  release the page read, and a release whose tag has a space in it is one
 *  this dashboard refuses to name to root rather than one it passes on. */
export const UPDATE_FIELD_RULES = {
  tag: (t: string): boolean => /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(t) && !t.includes('..'),
  commit: (c: string): boolean => /^[0-9a-f]{7,40}$/.test(c),
  sha256: (s: string): boolean => /^[0-9a-f]{64}$/.test(s),
  /** A systemd unit name, or a pm2 process name on the aggregator. Never a
   *  path, never an option: the program restarts what it found itself and
   *  this list only narrows that set. */
  unit: (u: string): boolean => /^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}$/.test(u),
} as const;

/** The first field that breaks its rule, named the way an operator reads it,
 *  or null when the request would frame cleanly. */
export function updateFieldRefusal(r: ApplyRelease): string | null {
  if (!UPDATE_FIELD_RULES.tag(r.tag)) return 'that does not look like a release tag';
  if (!UPDATE_FIELD_RULES.commit(r.commit)) return 'that does not look like a commit id';
  if (!UPDATE_FIELD_RULES.sha256(r.sha256)) return 'that does not look like a sha256';
  return null;
}

/** The first unit that breaks its rule, or null. An empty list is its own
 *  refusal: a restart of nothing is a request nobody meant to make. */
export function unitListRefusal(units: string[]): string | null {
  if (!Array.isArray(units) || units.length === 0) return 'no unit to restart';
  if (units.length > 8) return 'that is more units than this host runs';
  for (const u of units) {
    if (!UPDATE_FIELD_RULES.unit(String(u))) return `that does not look like a unit name: ${String(u).slice(0, 40)}`;
  }
  return null;
}

/** Ask what the program itself thinks is published. The probe: a host with
 *  no updater refuses the connection and never reaches this. */
export function checkPayload(): string { return 'check\n'; }

/** Only ever called on a release `updateFieldRefusal` passed: that is the
 *  frame. */
export function applyPayload(r: ApplyRelease): string {
  return `apply tag=${r.tag} commit=${r.commit} sha256=${r.sha256}\n`;
}

/** Only ever called on a list `unitListRefusal` passed. */
export function restartPayload(units: string[]): string {
  return `restart units=${units.join(',')}\n`;
}

export function rollbackPayload(): string { return 'rollback\n'; }

/**
 * What the update said about the fleet broker's grant, as the Settings card
 * shows it (#842).
 *
 * After an update the grant has to record the tree that is installed now, or
 * the broker refuses every pairing approval as `install_moved`. The updater
 * prints `broker_grant=<state>` as a fact when it ran with its output piped,
 * which is how this card runs it:
 *
 *   rerecorded      the grant now records the new tree
 *   already_current it already did
 *   stale           it still records the old tree; the full installer fixes it
 *   too_old         the installed broker cannot re-record; the installer fixes it
 *   absent          this host has no broker grant, so there is nothing to say
 *
 * `command` is set only for the two states that need the operator, and is
 * handed in because the right command depends on where this install lives.
 *
 * A fact that is missing, or a value this dashboard does not know, is NOT a
 * state. A manual update at a terminal sends no key, an older bootstrap sends
 * none, and an update that swapped nothing (a git checkout updated in place)
 * has nothing to re-record. Reading any of those as 'already current' would
 * be the card calling a grant healthy that nobody looked at, so the answer
 * is null and the card says nothing either way.
 */
export type BrokerGrantState = 'rerecorded' | 'already_current' | 'stale' | 'too_old' | 'absent';
const BROKER_GRANT_STATES: readonly string[] = ['rerecorded', 'already_current', 'stale', 'too_old', 'absent'];

export function brokerGrantReading(
  facts: Record<string, string>, command: string,
): { state: BrokerGrantState; command: string | null } | null {
  const raw = (facts.broker_grant ?? '').trim();
  if (!BROKER_GRANT_STATES.includes(raw)) return null;
  const state = raw as BrokerGrantState;
  return { state, command: state === 'stale' || state === 'too_old' ? command : null };
}

/** The units the program said are running older code than the tree now
 *  holds, off the finished run's own facts. Space-separated on the wire.
 *  This is the ONLY source the restart verb's unit list may come from: the
 *  dashboard never sends a unit name it chose (ADR 0022 decision 5). */
export function needsRestart(facts: Record<string, string>): string[] {
  const raw = facts.needs_restart ?? '';
  return raw.split(/[\s,]+/).map((u) => u.trim()).filter(Boolean);
}

/**
 * Did the program actually answer, or did the connection simply end?
 *
 * A program that said nothing is not a program that answered (#330). The
 * socket unit is `Accept=yes` with `MaxConnections=1`, so a second concurrent
 * connection can be accepted and closed with no reply; a clean close is not
 * one of the codes `isSocketUnreachable` recognises, so the run reads as
 * `absent: false` with EMPTY facts. Cached, that empty reading makes a host
 * that HAS an updater report as one that does not, for the whole of the
 * cache's life, and the fleet route then refuses an apply that would have
 * worked.
 *
 * Pure and exported so the rule can be driven directly, because the caller
 * that uses it is a module-level cache in server.ts.
 *
 * BOTH HALVES ARE OBSERVED. A connection that is accepted and closed with
 * no bytes produces exactly this outcome, and there is a test that stands up
 * a real unix socket and shows it. And systemd's own behaviour past
 * MaxConnections was read on a real host (stock-node3, 2026-09-15): it
 * accepts the second connection and drops it at once, "Too many incoming
 * connections (1), dropping connection" in the journal, the client's send
 * reset and its read a clean close with no bytes. Not a queue. So the
 * second reader always sees precisely the empty reading this rule refuses
 * to cache, which is why the rule is here.
 */
export function updaterAnswered(out: Pick<UpdateOutcome, 'absent' | 'facts'>): boolean {
  if (out.absent) return true;   // a definite answer: there is no program here
  return Object.keys(out.facts).length > 0;
}

// ── Whether this host may apply, at all ──────────────────────────────────
//
// One function, because there are now two callers. The operator's own Apply
// button on this host asks it, and so does the fleet route when an
// aggregator asks this node to apply (#275). Two copies of these five
// guards would drift, and the way they would drift is that one of them
// stops refusing something.
//
// Every guard is decided on THIS host's own facts: its own probe, its own
// updater's reading, its own graded verdict. Nothing an aggregator sends is
// an input to the decision — a job's release is compared against what this
// host's own check names, and a disagreement is refused here, before the
// socket, and refused again by root if it ever got past.

export interface LocalApplyProbe {
  /** Is there an updater on this host at all. */
  present: boolean;
  /** What this host's own updater said about where it fetches from and what
   *  is published there. Null when there was none to ask. */
  reading: UpdaterReading | null;
  /** This host graded from its own updater's reading, when that was whole. */
  graded: UpdateCheckResult | null;
}

export interface LocalApplyInput {
  probe: LocalApplyProbe;
  /**
   * This process's own reading of the same endpoint, over HTTP. The fallback
   * when the updater did not grade, and always the other half of the
   * disagreement test.
   *
   * A reading taken FOR this decision, or null. Not the one this process
   * keeps: that is refreshed once a day, and a day-old memory compared
   * against a live reading is a disagreement about the clock, which guard 1
   * then reports as a disagreement about the endpoint (#335). A caller that
   * cannot afford a live fetch passes null, and the decision rests on the
   * updater's own reading, which root checks a third time.
   *
   * The local Apply route still passes the kept reading, because the page in
   * front of it refreshes both readings in one request when an admin presses
   * Check now. A kept reading that is merely older than the updater's no
   * longer refuses anything (#342): guard 1 decides on the endpoints, and
   * the release that gets applied is the updater's either way.
   */
  pageCheck: UpdateCheckResult | null;
  /** What the caller says it is showing. A page that is older than this
   *  server's answer, or an aggregator holding a release this node's own
   *  check does not name, is refused rather than obeyed. */
  claimed?: { tag?: string; commit?: string; sha256?: string } | null;
}

/** Why this host will not apply, in the words it already used. `reason` is
 *  what the caller keys its audit row on; `error` and `detail` are the two
 *  sentences it renders. */
export type LocalApplyRefusal =
  | { reason: 'endpoint_disagreement'; error: string; detail: string; clash: EndpointDisagreement }
  | { reason: 'nothing_to_apply'; error: string; detail: string; state: string | null }
  | { reason: 'bad_release'; error: string; detail: string; release: ApplyRelease }
  | { reason: 'stale_page'; error: string; detail: string; release: ApplyRelease }
  | { reason: 'absent'; error: string; detail: string };

export type LocalApplyDecision =
  | { ok: true; release: ApplyRelease }
  | { ok: false; refusal: LocalApplyRefusal };

/**
 * The five guards, in the order they have always run.
 *
 * The order is deliberate and is preserved exactly as the route ran it. The
 * presence check is LAST: a host with no updater whose page is also showing
 * a stale answer is told about the stale answer first, because that is the
 * one the operator can act on from where they are standing.
 */
export function decideLocalApply(input: LocalApplyInput): LocalApplyDecision {
  const no = (refusal: LocalApplyRefusal): LocalApplyDecision => ({ ok: false, refusal });

  // 1. The two readings name the same ENDPOINT. Where they do not, nothing
  //    is applied at all: applying would refuse, and applying what root
  //    publishes is not what the caller just asked for.
  //
  //    One endpoint read twice, with a publish in between, is not this and
  //    never refuses (#342). The reading that decides what is applied is the
  //    updater's, taken below; a page-side memory that is merely older has
  //    nothing to add and no veto.
  const clash = updaterEndpointDisagreement(input.pageCheck, input.probe.reading);
  if (clash) {
    return no({
      reason: 'endpoint_disagreement',
      error: `this host's updater installs from ${clash.updater_endpoint}, which publishes ${clash.updater_tag}`,
      detail: `This page read ${clash.page_endpoint}, which publishes ${clash.page_tag}.`
        + ' Fix ENDPOINT in /etc/aperire/update.conf if that is not where this host should install from.',
      clash,
    });
  }

  // 2. This host's own reading says it is behind. On a host with an updater
  //    that is the updater's verdict, because the release that may be
  //    applied is the one ITS endpoint publishes: the only one root will
  //    install.
  const seen = input.probe.graded ?? input.pageCheck;
  const latest = seen?.latest ?? null;
  if (!seen || seen.state !== 'behind' || !latest) {
    return no({
      reason: 'nothing_to_apply',
      error: 'there is nothing to apply on this host',
      detail: 'Press Check now first. This host applies only a release its own check says it is behind.',
      state: seen?.state ?? null,
    });
  }

  // 3. The three values frame cleanly on one line for root.
  const release: ApplyRelease = { tag: latest.tag, commit: latest.commit, sha256: latest.sha256 };
  const framing = updateFieldRefusal(release);
  if (framing !== null) {
    return no({
      reason: 'bad_release',
      error: 'this dashboard will not name that release to root',
      detail: framing,
      release,
    });
  }

  // 4. The caller's own idea of what it is applying, when it sent one. A
  //    mismatch means the caller is older than this host's answer.
  const claimed = input.claimed;
  if (claimed && (String(claimed.tag ?? '') !== release.tag
    || String(claimed.sha256 ?? '') !== release.sha256)) {
    return no({
      reason: 'stale_page',
      error: 'this page is showing an older answer',
      detail: 'Check for updates again, then apply what it names.',
      release,
    });
  }

  // 5. There is a program to ask.
  if (!input.probe.present) {
    return no({
      reason: 'absent',
      error: 'no updater is installed on this host',
      detail: 'The published one-liner still updates it from the box itself.',
    });
  }

  return { ok: true, release };
}

// ── What an exit code means ──────────────────────────────────────────────

export interface UpdateVerdict {
  ok: boolean;
  /** Machine-readable, for the page to choose words from. */
  reason: 'done' | 'bad_payload' | 'disagreement' | 'busy' | 'unreachable' | 'bootstrap_failed' | 'refused' | 'absent' | 'running';
  /** The program's own sentence, whole and unparaphrased. For the fold: it
   *  is where two sha256s can be put side by side and compared. */
  detail: string;
  /** The one line the card SHOWS. Same sentence as `detail` whenever the
   *  program's own words are readable on a card, and a composed one when
   *  they are not: a refusal that names two 64-character sums and a
   *  host:port is the program talking to itself, and printing it as the
   *  visible sentence is what put 461px of hex inside a 322px card (#293).
   *  Never carries a sum. */
  say: string;
}

/** Is this sentence something to show an operator, or something to file?
 *  A sha256 or a host:port in it means the latter: neither is read, both
 *  are compared, and comparing is what the fold is for. */
export function isSayable(sentence: string): boolean {
  if (!sentence) return false;
  if (/[0-9a-f]{32}/i.test(sentence)) return false;
  if (/https?:\/\//i.test(sentence)) return false;
  if (/[A-Za-z0-9.-]+:\d{2,5}(?!\d)/.test(sentence)) return false;
  return true;
}

/**
 * The program's exit code, read as an outcome.
 *
 * `error=` is preferred over the generic sentence wherever the program left
 * one: it knows what it was doing and this file does not. The generic
 * sentences are what an operator gets when it did not say, and each of them
 * names the state the box is in rather than only that something failed —
 * "update failed" alone is not an outcome.
 */
export function describeUpdateCode(code: number | null, facts: Record<string, string> = {}): UpdateVerdict {
  const said = (facts.error ?? '').trim();
  // The published release, named. Taken from the program's own facts, and
  // never from the sums beside them: a tag is what an operator compares.
  const pub = (facts.published_tag ?? '').trim();
  // One verdict, two sentences: `detail` is the program's own, whole, and
  // `say` is what the card shows. They are the same string whenever the
  // program's words are readable on a card.
  const v = (reason: UpdateVerdict['reason'], short: string, ok = false): UpdateVerdict => {
    const detail = said || short;
    return { ok, reason, detail, say: isSayable(said) ? said : short };
  };
  if (code === null) {
    return { ok: false, reason: 'running', detail: 'The update program is still working.', say: 'The update program is still working.' };
  }
  switch (code) {
    case 0:
      return v('done', 'The update program finished.', true);
    case 2:
      return v('bad_payload', 'The update program did not understand what it was asked to do. Nothing was changed.');
    case 3:
      return v('disagreement', pub
        ? `The endpoint this host installs from publishes ${pub}, which is not the release this page offered. Nothing was downloaded.`
        : 'The release this page named is not the one the endpoint is publishing now, so nothing was downloaded. Check for updates again and re-apply.');
    case 4:
      return v('busy', 'An update is already running on this host. Nothing was started.');
    case 5:
      return v('unreachable', 'The update program could not reach the release endpoint, so nothing was fetched.');
    case 6:
      return v('bootstrap_failed', 'The install stopped part-way. Nothing was restarted; the previous tree is still on this host.');
    default:
      return v('refused', `The update program stopped with code ${code}, and named no reason this dashboard has a word for. Nothing was changed.`);
  }
}

// ── Running one ──────────────────────────────────────────────────────────

/** The transport, injected so a test can watch what root was asked without a
 *  socket anywhere near it. Takes the payload and a sink for what comes back
 *  as it comes back. Rejects only when the connection could not be made. */
export interface UpdateAsk {
  (payload: string, onChunk: (text: string) => void): Promise<void>;
}

export interface UpdateOutcome extends UpdateSnapshot {
  /** The socket would not open: no updater is installed on this host. Its
   *  own field rather than an exit code, because "there is no program here"
   *  and "the program said no" send an operator to different places. */
  absent: boolean;
  verdict: UpdateVerdict;
}

/**
 * Send one verb and read the whole answer, reporting progress on the way.
 *
 * `onProgress` is called after every chunk with what is known at that
 * moment, which is what makes a tail possible: the caller keeps the last
 * snapshot and answers a polling page from it.
 */
export async function runUpdateVerb(
  payload: string, ask: UpdateAsk, onProgress?: (snap: UpdateSnapshot) => void,
): Promise<UpdateOutcome> {
  const run = createUpdateRun();
  try {
    await ask(payload, (chunk) => {
      run.feed(chunk);
      if (onProgress) onProgress(run.snapshot());
    });
  } catch (err) {
    if (isSocketUnreachable(err)) {
      return {
        code: null, steps: [], facts: {}, lines: [], absent: true,
        verdict: {
          ok: false, reason: 'absent',
          detail: 'No updater is installed on this host. The published one-liner still updates it from the box itself.',
          say: 'No updater is installed on this host. The published one-liner still updates it from the box itself.',
        },
      };
    }
    // Deliberately not carrying the error's own message: it is the one place
    // something off the wire could ride out of here. The class of failure is
    // what an operator can act on.
    run.feed('the update program could not be reached on this host\n');
  }
  run.end();
  const snap = run.snapshot();
  if (onProgress) onProgress(snap);
  return { ...snap, absent: false, verdict: describeUpdateCode(snap.code, snap.facts) };
}
