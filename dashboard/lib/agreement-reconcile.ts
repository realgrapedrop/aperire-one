/**
 * Is the rolling 1-hour agreement window a measurement, or just what happened
 * to be left in memory?
 *
 * The bug this exists for: after the node restarts, the admin WS to rippled
 * drops, no `ledgerClosed` events arrive, and the ledgers missed during the
 * outage never enter `agreementHistory` at all. The pre-outage records — all
 * "we voted" — stay put, so the 1h window computes 100% with zero missed and
 * the VALIDATIONS card paints a confident green over a stretch of time it
 * never observed. Roughly thirty seconds later the real misses land in the
 * grace-timer burst and the count jumps. Green, then bad, with nothing in
 * between to warn the operator that the first answer was never measured.
 *
 * This is the same failure the project calls "kept vs observed": a stale
 * reading rendered as a current one. The window is not wrong here, it is
 * unfinished, and the honest thing to say is "measuring", not "100%".
 *
 * Pure and dependency-free on purpose. The state it judges lives in
 * server.ts's module scope, which cannot be imported without starting a
 * server, so the decision is lifted out to where a test can reach it.
 */

/** A closed admin-WS gap, as server.ts records it on reconnect. */
export interface DisconnectWindowLike {
  start: number;
  end: number;
}

export interface AgreementReconcileInput {
  /** Now, in ms. */
  now: number;
  /** Width of the window being judged — ONE_HOUR_MS at the only call site. */
  windowMs: number;
  /** The same slack `inDisconnectWindow` applies to a single ledger's close
   *  time, so this test and that one disagree about no instant. */
  padMs: number;
  /** Non-null while the admin WS is down right now. */
  currentDisconnectStart: number | null;
  /** Historical gaps. server.ts prunes these at 24h, which is far wider than
   *  the window we are judging — hence an overlap test, never a "is the list
   *  empty" test, or one gap yesterday would hold the card at "measuring" for
   *  a full day. */
  disconnectWindows: readonly DisconnectWindowLike[];
  /** Whether this node holds a validator key at all. */
  isValidator: boolean;
  /** `server_info.server_state` as rippled last reported it — `unknown`
   *  because that is genuinely what the caller has: the snapshot is filled
   *  from an untyped RPC reply, and there is no guarantee this field is a
   *  string, or present at all. Anything that is not exactly the string
   *  'proposing' counts as unsettled, which is the safe direction. */
  serverState: unknown;
  /** `server_info.uptime`, in seconds, exactly as rippled reported it. Some
   *  builds report it as a string, and a node that has never answered reports
   *  nothing at all — both are handled here rather than at the call site. */
  uptimeS: unknown;
}

/** How long the node must have been up before its own 1h window can possibly
 *  be a full hour of observation. Below this the window is younger than it
 *  claims to be, whatever the counters say. */
const MIN_UPTIME_S = 3600;

/**
 * A gap shorter than this is not an outage of the node: it is the dashboard
 * restarting (a startup gap is tens of milliseconds), or the admin socket
 * blinking. Ledgers close about every four seconds, so at most two closed
 * inside it, and `inDisconnectWindow` already skips those as GAP rather than
 * counting them as agreed. Nothing in the window is claimed that was not
 * observed, so the hour is not held for it.
 *
 * It was held for it until 2026-09-06: a deploy's restart of the dashboard
 * at 17:10 UTC recorded a 45 ms gap, and the Agreement % series, which the
 * node had earned back at 17:48 after a real outage, stayed blank until the
 * gap left the rolling hour at 18:11. The rule this module exists for is
 * about the NODE being away: the ledgers it missed while down never enter
 * the history, so the survivors compute a false 100%. A node restart takes
 * far longer than this to come back and reproposes, so it is still caught
 * by the gap's length, by condition (b), and by condition (c).
 */
export const SHORT_GAP_MS = 10_000;

/** The gaps that can hide a ledger: every one at least SHORT_GAP_MS long. */
function materialGaps(i: AgreementReconcileInput): DisconnectWindowLike[] {
  return i.disconnectWindows.filter((w) => w.end - w.start >= SHORT_GAP_MS);
}

/**
 * True only when every ledger the window claims to cover could actually have
 * been observed. False is not "bad" — it is "not known yet", and the surfaces
 * that consume it must render it as neither green nor red.
 */
export function isAgreementWindowReconciled(i: AgreementReconcileInput): boolean {
  // (a) The admin WS is down right now. Everything after the drop is missing
  //     from the window by construction.
  if (i.currentDisconnectStart !== null) return false;

  // (a, continued) A closed gap that overlaps the window. This is an interval
  //     test against [now - windowMs, now], not a point test: a gap that sat
  //     entirely inside the hour contains no instant equal to either edge, and
  //     a containment check would wave it through. Each gap is widened by
  //     padMs on both sides for the same reason inDisconnectWindow widens it —
  //     ledgers that closed just before the drop had not had their grace timer
  //     fire yet, and validations for ledgers just after the reconnect are
  //     still catching up on the stream.
  const windowStart = i.now - i.windowMs;
  for (const w of materialGaps(i)) {
    if (w.end + i.padMs >= windowStart && w.start - i.padMs <= i.now) return false;
  }

  // (b) A validator that is not proposing is not validating, so whatever the
  //     window holds is from before it stopped. FULL, CONNECTED, SYNCING and
  //     "we have never polled it" all land here.
  if (i.isValidator && i.serverState !== 'proposing') return false;

  // (c) The node itself has not been up for an hour, so an hour of history
  //     cannot exist. Written as a positive test for a finite number: a
  //     missing or unparseable uptime gives NaN, and `NaN < 3600` is false,
  //     which would have read "no information about the node" as "settled".
  const uptime = Number(i.uptimeS);
  if (!Number.isFinite(uptime) || uptime < MIN_UPTIME_S) return false;

  return true;
}

/**
 * When the window is not a full hour of observation, how much of it IS.
 *
 * Refusing to answer at all is what put the VALIDATIONS 1h pair at
 * "measuring…" for a full hour after every restart. The counts over the clean
 * stretch since the node came back are a real reading, they are just a reading
 * about 22 minutes rather than about an hour, and the surface can say so.
 *
 * Returns the start of the contiguous stretch this node could actually have
 * watched, or null when there is genuinely nothing current to report: the
 * admin WS is down right now, or a validator is not proposing. Everything
 * before the returned instant is excluded, which is the whole point. The
 * ledgers missed during the outage never entered the history, so a start that
 * reached back past the gap would count only the surviving "we voted" records
 * and paint the same false 100% this module exists to refuse.
 *
 * Deliberately built from the SAME input as isAgreementWindowReconciled, and
 * from the same padded interval test over the gaps. Any gap that predicate
 * rejects the window for moves this start strictly forward, so the two can
 * never disagree: "unreconciled" and "a full clean hour observed" is not a
 * reachable pair of answers.
 *
 * A caller must still check that anything was counted inside the returned
 * stretch. A start with no records under it is not a measurement either.
 */
export function observedWindowStartMs(i: AgreementReconcileInput): number | null {
  // The two states where there is no current reading at all, same conditions
  // (a) and (b) as above. A window that is still being written has no settled
  // sub-stretch to offer either.
  if (i.currentDisconnectStart !== null) return null;
  if (i.isValidator && i.serverState !== 'proposing') return null;

  // Never claim more than the window itself. This is also the answer when
  // everything below is satisfied, so a fully reconciled node returns
  // now - windowMs and the observed path converges on the normal one.
  const windowStart = i.now - i.windowMs;
  let start = windowStart;

  // The node cannot have observed anything from before it booted. Written as
  // a positive test for a finite number for the same reason condition (c) is:
  // an unparseable uptime is no information, and arithmetic on NaN would
  // silently poison every comparison after it.
  const uptime = Number(i.uptimeS);
  if (Number.isFinite(uptime)) {
    const bootMs = i.now - uptime * 1000;
    if (bootMs > start) start = bootMs;
  }

  // Any gap overlapping the window truncates the observed stretch to what
  // came after it, padded exactly as the reconciled test pads it. Both the
  // membership test and the candidate use w.end + padMs, so a gap that ended
  // just before the window opened, which condition (a) rejects the hour for,
  // still pushes this start past windowStart rather than being waved through.
  // The same gaps condition (a) judges, so a short gap that does not hold
  // the hour does not shorten the observed stretch either.
  for (const w of materialGaps(i)) {
    if (w.end + i.padMs >= windowStart && w.start - i.padMs <= i.now) {
      const after = w.end + i.padMs;
      if (after > start) start = after;
    }
  }

  // The pad can carry the start past now (a gap that closed seconds ago).
  // That is a zero-length window, not a negative one, and the caller reads it
  // as "too little observed yet".
  return Math.min(start, i.now);
}
