/**
 * Does this host have an Advisor? ADR 0016.
 *
 * The Advisor is an invited add-on. A dashboard installed without one used to
 * render a permanent "the Advisor service is not answering", which is this
 * project's kept-vs-observed shape running backwards: the dashboard held a
 * fact it had never observed ("there is an Advisor here, it is just quiet")
 * and painted it as current. This file is where that fact gets observed
 * instead, once, so that no surface has to decide for itself.
 *
 * Three states, and the middle one is the point:
 *
 *   absent              never answered on this host
 *   present             answering now
 *   installed-but-down  answered before, silent now
 *
 * Hiding an installed-but-down Advisor would be the same bug in different
 * clothes, so the states are three and not two.
 *
 * Derivation is pure (`deriveAdvisorPresence`) exactly as fleet-health.ts's
 * `deriveVerdict` is, and the ordered observation (`observeAdvisorPresence`)
 * takes its dependencies as arguments so a test can count them. That is not
 * decoration: "an absent host makes zero outbound calls" is the load-bearing
 * claim of the whole record, and a claim only a comment makes is a claim
 * nothing checks.
 */

export type AdvisorPresenceState = 'absent' | 'present' | 'installed-but-down';

export interface AdvisorPresenceResult {
  state: AdvisorPresenceState;
  /** '' when there is nothing to explain, a short reason otherwise. Same
   *  convention as VerdictResult.detail. */
  detail: string;
}

/** The default grace window, ADR 0016 decision 2, ratified by the operator on
 *  2026-08-29: long enough that repairing a permissions accident over a
 *  weekday is not a race, short enough that an uninstall does not ghost a
 *  dead tab for a week. */
export const DEFAULT_FORGET_AFTER_MS = 48 * 60 * 60 * 1000;

export interface AdvisorPresenceInput {
  /** advisor/state/approve.token is readable and at least 32 characters —
   *  the same test advisorApproveToken() already applies. advisord writes it
   *  at startup and never removes it, on shutdown or otherwise, so this
   *  survives a stopped service and is a better answer to "is one installed
   *  here" than any probe of the service itself. */
  tokenReadable: boolean;
  /** THIS cycle's probe of GET /v1/status. `null` means NOT PROBED, which is
   *  what the token-unreadable branch always produces, and it is deliberately
   *  not `false`: "we asked and it said no" and "we never asked" are
   *  different measurements, and collapsing them is the absent-is-not-zero
   *  bug this codebase keeps paying for. */
  answered: boolean | null;
  /** The persisted memory — epoch ms of the last 200, or null if this host
   *  has never seen one. Not the same question as `answered`: this is what
   *  keeps a permissions accident from silently hiding an installed Advisor. */
  lastAnsweredMs: number | null;
  /** Whether the Advisor's service unit is on this host. The memory above
   *  cannot tell an uninstall from a permissions accident: both leave the
   *  token unreadable and both happen inside the grace window. The unit can.
   *  Removing the Advisor removes its unit; a chmod does not. `null` means
   *  the question was not asked (a host where the check is not possible),
   *  and falls through to the memory. `false` means it was asked and the unit
   *  is not there, which ends the grace window on the spot.
   *
   *  It reads BOTH ways, and #113 is the second one: with no memory at all,
   *  a unit that is definitely there is the only evidence a fresh install has
   *  that the unreadable token is an accident rather than an absence.
   *
   *  And #995 is the third: a token that is readable but did not answer is
   *  what an Advisor-only `--keep` uninstall leaves. The token stays in
   *  advisor/state on purpose, on the dashboard's own group, so it never goes
   *  unreadable, and only the unit says the Advisor went. */
  unitInstalled: boolean | null;
  nowMs: number;
  forgetAfterMs: number;
}

/** The Advisor's service unit THIS dashboard pairs with (#1023 review, L1).
 *  Instances pair by name: `install.sh --instance=node2` installs
 *  aperire-server-node2 beside aperire-advisord-node2. Reading the
 *  un-suffixed unit for every instance made a stopped node2 Advisor, whose
 *  token stays readable, read as absent whenever the default instance had no
 *  unit. The installer writes APERIRE_ADVISOR_UNIT_PATH into each instance's
 *  env file, and that wins; APERIRE_INSTANCE is the fallback, and with
 *  neither it is the un-suffixed unit, as before. A name that is not an
 *  instance name is ignored rather than spliced into a path. */
export function advisorUnitPath(env: Record<string, string | undefined>): string {
  if (env.APERIRE_ADVISOR_UNIT_PATH) return env.APERIRE_ADVISOR_UNIT_PATH;
  const inst = env.APERIRE_INSTANCE ?? '';
  const suffix = /^[a-z0-9][a-z0-9-]{0,30}$/.test(inst) ? `-${inst}` : '';
  return `/etc/systemd/system/aperire-advisord${suffix}.service`;
}

/** Whole hours, rounded up, or whole minutes under an hour. The operator is
 *  being told when a state clears, not being given a stopwatch. */
function humanLeft(ms: number): string {
  if (ms <= 0) return 'shortly';
  const mins = Math.ceil(ms / 60000);
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'}`;
  const hours = Math.ceil(ms / 3600000);
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

/**
 * The five-row truth table of ADR 0016 decision 2, and nothing else.
 *
 * | token readable | answered                        | unit | state              |
 * |---|---|---|---|
 * | yes | yes                                      | -    | present            |
 * | yes | no                                       | yes/?| installed-but-down |
 * | yes | no                                       | no   | absent             |
 * | no  | never answered                           | yes  | installed-but-down |
 * | no  | never answered                           | no/? | absent             |
 * | no  | answered before, within the grace window | yes/?| installed-but-down |
 * | no  | answered before, within the grace window | no   | absent             |
 * | no  | answered before, past the grace window   | -    | absent             |
 *
 * The grace-window rows are the whole reason a timestamp is persisted at all,
 * and the reason is narrower than "answered before". The token file is what
 * tells installed-but-down from absent. The memory exists so that a
 * PERMISSIONS ACCIDENT cannot silently hide an installed Advisor — not
 * hypothetical here, advisord's own ensureToken() comment records it
 * happening: written at 0600, a regenerated token locked the dashboard out
 * and the tab said "no advisor token readable on this host" with nothing to
 * explain why. Without the memory that accident would now downgrade from a
 * confusing error to a silent disappearance, which is worse.
 *
 * So the held-on-memory-alone detail names BOTH branches and says when it
 * clears. An operator who reads that sentence can act on either one.
 */
export function deriveAdvisorPresence(input: AdvisorPresenceInput): AdvisorPresenceResult {
  if (input.tokenReadable) {
    if (input.answered === true) return { state: 'present', detail: '' };
    // #995. A readable token is not proof the Advisor is still installed: an
    // Advisor-only `--keep` uninstall keeps advisor/state and hands
    // approve.token to the dashboard's own group, so it stays readable for as
    // long as the host lives, and nothing answers it. Read as installed-but-
    // down, the node said "installed, not answering" forever and an
    // aggregator's Add an Advisor watch pointed at a service that was gone.
    // The unit is what an uninstall removes and a stopped or crashed Advisor
    // keeps, so a definite `false` here is absent. `null` (could not check)
    // keeps the old answer.
    if (input.unitInstalled === false) return { state: 'absent', detail: '' };
    // `false` (asked, refused) and `null` (not asked) both land here, and
    // that is correct for THIS branch: neither is evidence of an answer, and
    // with the unit still here (or unknown) neither can make an installed
    // Advisor absent. The distinction between them is load-bearing only
    // below, where there is no token to fall back on.
    return {
      state: 'installed-but-down',
      detail: 'the Advisor is installed on this host, but its service did not answer the last check',
    };
  }

  if (input.lastAnsweredMs === null) {
    // #113. A FRESH install has no memory to be saved by, and that is where
    // the permissions accident actually happens: advisord writes the token at
    // startup, so the very first thing a wrong mode does is happen before this
    // host has ever recorded an answer. Token unreadable plus never answered
    // read as absent, the tab disappeared, and the page offered to install an
    // Advisor that was installed and running.
    //
    // The unit file is the installer's own marker and it is already read
    // below: scripts/install-advisord.sh writes
    // /etc/systemd/system/aperire-advisord.service, an uninstall removes it,
    // and no mode on the Advisor's state directory can touch it. A definite
    // `true` is therefore proof of an install that a token cannot give, and
    // it is the only thing that overrides the no-memory absent. `false` and
    // `null` fall through unchanged, so a host with no Advisor is absent as
    // it was.
    if (input.unitInstalled === true) {
      return {
        state: 'installed-but-down',
        detail:
          'the Advisor is installed on this host (its service unit is here), but the ' +
          "dashboard cannot read advisor/state/approve.token. Check the permissions on " +
          'that file, and that aperire-advisord has started at least once',
      };
    }
    return { state: 'absent', detail: '' };
  }

  // The memory exists to survive a permissions accident, and an accident
  // does not take a systemd unit with it. No unit means the Advisor was
  // removed, and holding a removed Advisor on the menu for two days is the
  // ghost the window was sized to avoid. Only a definite `false` ends it: a
  // host that could not check keeps the memory's answer.
  if (input.unitInstalled === false) return { state: 'absent', detail: '' };

  const elapsed = input.nowMs - input.lastAnsweredMs;
  // `>=` and not `>`: at exactly the window the memory has expired. Pinned by
  // a test on the boundary value itself, because an inequality nobody tested
  // on its own edge is an inequality nobody chose.
  if (elapsed >= input.forgetAfterMs) return { state: 'absent', detail: '' };

  return {
    state: 'installed-but-down',
    detail:
      "the Advisor's token file is not readable. If the Advisor was removed, this clears in " +
      `${humanLeft(input.forgetAfterMs - elapsed)}. If it was not, check the permissions on ` +
      'advisor/state/approve.token',
  };
}

export interface AdvisorPresenceDeps {
  /** The installed signal AND, on this host, the probe's credential:
   *  /v1/status is behind advisord's own authorized() check, so there is no
   *  probe to make without it. The ordering the ADR mandates is therefore
   *  also the only ordering that works. */
  readToken: () => string | null;
  /** Called ONLY when readToken() returned a token. Must not throw: a network
   *  failure is a non-answer, not an exception. */
  probeStatus: (token: string) => Promise<AdvisorProbe>;
  lastAnsweredMs: number | null;
  /** Is the Advisor's service unit on this host. Consulted only when no
   *  answer proved an Advisor: the token is unreadable, or it is readable
   *  and the probe did not answer (#995). One stat(), no network. `null`
   *  when the host cannot say. */
  unitInstalled: () => boolean | null;
  nowMs: number;
  forgetAfterMs: number;
}

/** One probe's result. Two facts, and the second and third are allowed to
 *  be unknown.
 *
 *  `modelConfigured` is `null` whenever this probe did not learn the answer:
 *  the service did not answer, the body did not parse, or the field was not
 *  there because the Advisor predates it. It is NOT `false` in any of those
 *  cases, and that distinction decides which screen an operator gets. `false`
 *  means a running Advisor said it has no model, which is an invitation to set
 *  one up. `null` means nobody said anything, and inviting somebody to paste a
 *  key into a form that cannot possibly seal it is the worse failure.
 *
 *  `credentialPresent` and `modelName` (#516) are read the same tolerant way:
 *  `null`/`''` on a body that predates them, or on one where they do not
 *  apply (no model chosen at all). Together with `modelConfigured === false`
 *  they are what tells "nothing chosen" apart from "chosen, no key on this
 *  host", which the Advisor tab needs to decide how much of itself to hide.
 *
 *  `version` (#641) is read the same tolerant way again: the Advisor's own
 *  build ref, off main.go's `version` field in the same /v1/status body,
 *  null on a body that predates it or did not parse. It is what
 *  GET /fleet/v1/advisor/state forwards to an aggregator attaching this
 *  node, so a first successful attach can render a build stamp without a
 *  second round trip. */
export interface AdvisorProbe {
  answered: boolean;
  modelConfigured: boolean | null;
  /** Optional so every existing probeStatus (real and test) keeps compiling
   *  unchanged; absent reads exactly like null. */
  credentialPresent?: boolean | null;
  modelName?: string;
  version?: string | null;
}

export interface AdvisorPresenceObservation extends AdvisorPresenceResult {
  /** What this cycle's probe measured, or null if no probe was made. The
   *  caller persists a timestamp on `true` and on nothing else. */
  answered: boolean | null;
  /** Whether the Advisor that answered THIS cycle reports a model. Never
   *  remembered across cycles: `present` can be reached from a remembered
   *  answer with no fresh body, and carrying the last known value there would
   *  be exactly the kept-vs-observed shape this file exists to avoid. */
  modelConfigured: boolean | null;
  /** Whether the credential behind that model can be read on this host, this
   *  cycle. Same non-memory rule as modelConfigured, and the same reason. */
  credentialPresent: boolean | null;
  /** The model's name, when the config validates, this cycle. Empty when
   *  there is none to report, never remembered. */
  modelName: string;
  /** The Advisor's own build ref, this cycle. Same non-memory rule as
   *  modelConfigured, and the same reason (#641). */
  version: string | null;
}

/**
 * One observation cycle, ordered so that absent costs nothing.
 *
 * The order is the decision. On a host with no Advisor this function is one
 * stat() and ZERO network calls, because the token check gates the HTTP call.
 * That is what makes "no Advisor-shaped request is ever made" true on the
 * server as well as in the browser, and it is asserted with a counting
 * probeStatus rather than described.
 */
export async function observeAdvisorPresence(
  deps: AdvisorPresenceDeps,
): Promise<AdvisorPresenceObservation> {
  const token = deps.readToken();
  const tokenReadable = token !== null;
  const probe: AdvisorProbe | null = tokenReadable ? await deps.probeStatus(token) : null;
  const answered: boolean | null = probe === null ? null : probe.answered;
  // The unit is asked about only where its answer can change anything: no
  // answer this cycle. An Advisor that answered is proven, so that branch
  // never looks. Without a token the unit decides both directions — an
  // uninstall inside the grace window, and (#113) a fresh install whose token
  // went unreadable before this host ever recorded an answer. With a token
  // and no answer it tells a stopped Advisor from one an Advisor-only
  // `--keep` uninstall removed, which leaves the token readable (#995).
  //
  // This is what the ADR's cost claim actually buys, and it is worth being
  // exact about: an absent host now costs TWO stat()s per cycle, the token
  // and the unit, and still ZERO network calls. The network claim is the one
  // that makes "a declined Advisor makes no Advisor-shaped request" true, and
  // it is untouched. There is no way to tell a host with no Advisor from a
  // host whose token is unreadable without a second local signal.
  const unitInstalled = answered === true ? null : deps.unitInstalled();
  return {
    ...deriveAdvisorPresence({
      tokenReadable,
      answered,
      lastAnsweredMs: deps.lastAnsweredMs,
      unitInstalled,
      nowMs: deps.nowMs,
      forgetAfterMs: deps.forgetAfterMs,
    }),
    answered,
    // Only from a probe that answered. A failed probe has no opinion about a
    // model, and neither has a cycle that made no probe at all.
    modelConfigured: probe !== null && probe.answered ? probe.modelConfigured : null,
    credentialPresent: probe !== null && probe.answered ? (probe.credentialPresent ?? null) : null,
    modelName: probe !== null && probe.answered ? (probe.modelName ?? '') : '',
    version: probe !== null && probe.answered ? (probe.version ?? null) : null,
  };
}

/** A peer's Advisor is DECLARED, not probed — ADR 0016 decision 7. The
 *  registry validates advisor_origin and advisor_token_path together or not
 *  at all, so their presence is the whole answer. installed-but-down is
 *  deliberately not computed for a peer: pre-computing it would buy a poll of
 *  every peer's advisord on every cycle to replace an error the code already
 *  returns truthfully and node-named at the moment of use
 *  (`advisor_not_configured`). */
export interface AdvisorPresenceNode {
  label: string;
  state: 'absent' | 'present';
  source: 'declared';
}

export interface AdvisorPresenceResponse {
  protocol: 1;
  /** Where this dashboard is installed, so the absent-state card can print a
   *  command an operator can paste. It used to print a RELATIVE path, which
   *  failed verbatim from anywhere but the repo root, and it named an
   *  internal script, which the one-entry-point rule forbids: the menu is
   *  the interface. Absent on a dashboard older than this field, and the
   *  card then falls back to $HOME phrasing rather than guessing a path.
   *
   *  Session-gated, like the rest of /api/*. It is a directory name shown to
   *  a signed-in operator who is about to be told to run sudo in it. */
  install_dir?: string;
  /** This host's own name, as it reports it (os.hostname()). The page names
   *  it when it sends an operator to sign in here, because location.hostname
   *  is a fact about the browser's origin: "localhost" through a forward,
   *  the public name through a tunnel, and never the machine (#252). Absent
   *  on a dashboard older than this field, and the sentence then names no
   *  machine rather than one it guessed. */
  host_name?: string;
  /** THIS host's own Advisor. Keys the break-glass chip and the local half of
   *  the nav entry. */
  self: {
    state: AdvisorPresenceState;
    last_answered_ms: number | null;
    detail: string;
    /** Whether THIS host's Advisor reported a language model on the last cycle
     *  that got an answer out of it, and `null` when the last cycle did not.
     *
     *  This is what the Advisor tab keys the model setup step on, together
     *  with `state`. `present` plus `false` is the one combination that means
     *  "installed, answering, and has no model": the step is worth showing
     *  and the seal can actually happen. Anything else, `null` included, is
     *  not, because a form that takes a key must not appear in front of an
     *  operator whose Advisor could not receive one. */
    model_configured: boolean | null;
    /** Whether the credential behind that model can be read on this host,
     *  same cycle, same non-memory rule (#516). Additive: absent on a
     *  dashboard older than this field, which the tab reads the same as
     *  `null` and falls back to the plain no-model step, never a claim of
     *  its own. Together with `model_name`, this is what tells "no model
     *  chosen at all" apart from "chosen, no key on this host". */
    credential_present?: boolean | null;
    /** The model's name, when the config validates, same cycle. Omitted
     *  when there is none to report, same rule as the field above. */
    model_name?: string;
  };
  /** One row per subject node this dashboard can route to. Keys per-row Ask
   *  pills and the fleet dropdown's Ask links. */
  nodes: AdvisorPresenceNode[];
  /** The roll-up, and the field NAVIGATION keys on — not `self`. On an
   *  aggregator the Advisor tab routes to the SUBJECT node's advisord, so an
   *  aggregator with no local advisord and one node that has one is a fully
   *  working tab today. Keying the nav entry on `self` would hide it and take
   *  the only route to that node's Advisor with it (decision 5).
   *
   *  `self` and `nodes` stay separate on purpose. One field answering both
   *  questions is a defect this tab has already shipped once: reading a
   *  peer's state under another node's name is the ADR 0014 mislabel. */
  any: boolean;
}

export function buildAdvisorPresenceResponse(input: {
  self: AdvisorPresenceResult;
  lastAnsweredMs: number | null;
  /** From the most recent cycle that got an answer, or null. Omitted by a
   *  caller that does not know, which reads the same as not knowing. */
  modelConfigured?: boolean | null;
  /** Same rule, same cycle (#516): whether that model's credential can be
   *  read on this host. */
  credentialPresent?: boolean | null;
  /** The model's name, same cycle. Empty when there is none to report. */
  modelName?: string;
  peers: { label: string; advisor_origin?: string }[];
  /** This dashboard's install directory. Omitted rather than guessed. */
  installDir?: string;
  /** This host's own name, as os.hostname() reports it. Omitted rather than guessed. */
  hostName?: string;
}): AdvisorPresenceResponse {
  const nodes: AdvisorPresenceNode[] = input.peers.map((p) => ({
    label: p.label,
    state: p.advisor_origin ? 'present' : 'absent',
    source: 'declared',
  }));
  return {
    protocol: 1,
    ...(input.installDir ? { install_dir: input.installDir } : {}),
    ...(input.hostName ? { host_name: input.hostName } : {}),
    self: {
      state: input.self.state,
      last_answered_ms: input.lastAnsweredMs,
      detail: input.self.detail,
      model_configured: input.modelConfigured ?? null,
      credential_present: input.credentialPresent ?? null,
      ...(input.modelName ? { model_name: input.modelName } : {}),
    },
    nodes,
    any: input.self.state !== 'absent' || nodes.some((n) => n.state !== 'absent'),
  };
}

/**
 * What a reader is told about this host's own Advisor RIGHT NOW (#995).
 *
 * The probe above runs every 20 seconds and its answer is cached. An
 * aggregator's Add an Advisor watch reads that cached answer through
 * GET /fleet/v1/advisor/state, so for up to one probe interval after an
 * uninstall removed the unit the node still said `present`, and the page
 * offered an enabled Attach for a service that was gone (lab walk on
 * snapshot-2026-09-17be: 11 to 15 s of `ready` after the unit disappeared).
 *
 * A reader trusts the cache in exactly one case: the last cycle found the
 * Advisor present and answering, and its unit is still installed. In every
 * other case it runs the probe cycle now and reports what that observed:
 *
 *   - the cache says present and the unit is definitely gone (`false`, never
 *     `null`): an uninstall just removed it;
 *   - the cache says installed-but-down or absent: whatever it was, it may
 *     have changed since the last tick, in either direction, and ADR 0016
 *     asks for the fact, not the memory of it.
 *
 * The cycle is the one the timer runs, so there is still one implementation
 * of the rule, and an Advisor that answers with no unit on this host (a
 * hand-run stand-in) stays `present`, because the answer outranks the unit
 * as it does there. An absent host's cycle is two stat()s and no network.
 *
 * What the cache still covers: a healthy Advisor, present and answering with
 * its unit installed. One that dies while its unit stays (a crash, a stop) is
 * noticed by the next timer tick, at most 20 s later, and then every reader
 * re-reads until it is back.
 *
 * Bounded so a polling reader cannot drive the outbound call rate: a cycle
 * already running is shared, and one that finished within `minGapMs` is not
 * repeated.
 *
 * And bounded in time. A hung advisord makes the cycle take its whole 5 s
 * probe timeout, which is also how long an aggregator's watch waits for this
 * node, so a reader that waited it out would flip the watch between "did not
 * answer in time" and down. A reader waits `waitMs` (1.5 s) for the cycle and
 * then serves the cache as it stands; the cycle carries on and the next
 * request sees what it found.
 */
export function createPresenceReader(deps: {
  current: () => AdvisorPresenceResult;
  unitInstalled: () => boolean | null;
  /** One full probe cycle; must update what `current` returns. Never throws. */
  reprobe: () => Promise<void>;
  nowMs: () => number;
  minGapMs?: number;
  /** How long a request waits for a cycle before serving the cache. */
  waitMs?: number;
}): () => Promise<AdvisorPresenceResult> {
  const minGapMs = deps.minGapMs ?? 3_000;
  const waitMs = deps.waitMs ?? 1_500;
  let inFlight: Promise<void> | null = null;
  let lastDoneMs = -Infinity;
  return async () => {
    const cached = deps.current();
    if (cached.state === 'present' && deps.unitInstalled() !== false) return cached;
    if (inFlight === null && deps.nowMs() - lastDoneMs >= minGapMs) {
      inFlight = deps.reprobe()
        .catch(() => { /* a failed cycle keeps the last-known state, as the timer does */ })
        .finally(() => { inFlight = null; lastDoneMs = deps.nowMs(); });
    }
    if (inFlight !== null) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const patience = new Promise<void>((resolve) => { timer = setTimeout(resolve, waitMs); });
      try { await Promise.race([inFlight, patience]); } finally { clearTimeout(timer); }
    }
    return deps.current();
  };
}
