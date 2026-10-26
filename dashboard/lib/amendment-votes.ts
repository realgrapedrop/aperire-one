// Amendment support, counted from the trusted validations stream (#161).
//
// rippled fills `feature`'s count/threshold/validations only from the
// flag-ledger amendment vote, and a node that does not validate never runs
// one, so a tracking node's ballot has no tally of its own. It does see the
// votes go past. On the voting ledger, the one before each flag ledger
// (RCLConsensus.cpp: `isVotingLedger`, `(seq + 1) % 256 == 0`), every
// validator lists the amendments it wants in its validation's `amendments`
// field. Measured on aperire4 (2026-09-02, ~17 minutes on the stream): 53 of
// 30,746 validations carried the field, all on ledger 106703359, the one
// before flag ledger 106703360.
//
// Counting those from the trusted set is the same tally a validator makes
// from the same messages (AmendmentTable.cpp: recordVotes / getVotes), with
// one difference kept on purpose: rippled remembers a validator's last vote
// for 24 hours, so its figure can carry a validator or two that missed this
// particular ledger. This counter never blends ledgers. One voting ledger,
// the trusted validations seen on it, published once the ledger is behind us.
//
// Two things it refuses to publish:
//   - a round with fewer trusted validations than the quorum. rippled itself
//     only votes when it holds a quorum of trusted validations for the voting
//     ledger (RCLConsensus.cpp, `validations.size() >= quorum()`); fewer than
//     that is a partial view of the round (a reconnect mid-ledger, a UNL not
//     yet loaded), not a tally.
//   - anything before the first voting ledger after start. The gap is up to
//     ~15 minutes (256 ledgers), and during it the row says "unreported",
//     never 0.

/** How often a flag ledger comes round: every 256th ledger. */
export const FLAG_LEDGER_INTERVAL = 256;

/** The ledger validators vote on: the one before a flag ledger. */
export function isVotingLedger(seq: number): boolean {
  return (seq + 1) % FLAG_LEDGER_INTERVAL === 0;
}

/**
 * rippled's own bar, as computed in AmendmentTable.cpp `computeThreshold`
 * with fixAmendmentMajorityCalc in force (SystemParameters.h,
 * postFixAmendmentMajorityCalcThreshold = 80/100): at least one, otherwise
 * the integer part of 80% of the trusted validations counted. This is the
 * number a validator's `feature` reports as `threshold` for the same round.
 */
export function amendmentVoteThreshold(trustedValidations: number): number {
  return Math.max(1, Math.floor((trustedValidations * 80) / 100));
}

/** One completed voting ledger's tally, the shape the ballot rows consume. */
export interface CountedAmendmentSupport {
  /** The voting ledger the votes were read from. */
  ledger_index: number;
  /** When the first vote for that ledger reached this dashboard, ms since
   *  the Unix epoch. The ledger closed within a few seconds of it. */
  at_ms: number;
  /** Trusted validators seen validating that ledger, with or without an
   *  `amendments` field: the denominator, rippled's `validations`. */
  validations: number;
  /** amendmentVoteThreshold(validations), rippled's `threshold`. */
  threshold: number;
  /** Upper-case amendment hash -> trusted validators that listed it. A hash
   *  no trusted validator listed is absent, and reads as 0. */
  counts: Record<string, number>;
}

/** The round being collected. Sets, not counters: the stream can carry the
 *  same validator's validation for one ledger more than once (a partial and
 *  then a full), and one validator is one vote. */
interface OpenRound {
  ledger_index: number;
  first_ms: number;
  signers: Set<string>;
  votes: Map<string, Set<string>>;
}

/** A round that closed without becoming a tally, and why. Logged by the
 *  caller so a dashboard that keeps saying "unreported" can be read. */
export interface DiscardedRound {
  ledger_index: number;
  trusted_validations: number;
  quorum: number;
}

export type RoundOutcome =
  | { kind: 'counted'; tally: CountedAmendmentSupport }
  | { kind: 'discarded'; round: DiscardedRound };

/**
 * Feeds on trusted validations as they arrive and hands back a tally when a
 * voting ledger is complete. Holds no knowledge of the stream or the UNL;
 * the caller filters to trusted master keys and supplies the UNL size the
 * quorum is measured against, so this stays a pure, testable piece.
 */
export class AmendmentVoteCounter {
  private round: OpenRound | null = null;
  private last: CountedAmendmentSupport | null = null;

  /** The last completed tally, or null before the first one. */
  current(): CountedAmendmentSupport | null { return this.last; }

  /**
   * One trusted validation. `amendments` is the raw field off the message,
   * present only on a voting ledger and only from a validator that wants
   * something. Returns the round this validation closed, if it closed one.
   *
   * A round closes on the first validation two or more ledgers past it.
   * Stragglers for a ledger arrive within a second or two of its close, and
   * the next ledger's validations are already a few seconds later; two
   * ledgers is ~8 seconds, room for every straggler and still well inside
   * the 15 minutes before the next round. A validation for an older ledger
   * than the open round is a straggler that missed the window and is
   * dropped, never blended into the round that followed.
   */
  record(masterKey: string, ledgerIndex: number, amendments: unknown, unlSize: number, nowMs: number): RoundOutcome | null {
    if (!Number.isFinite(ledgerIndex)) return null;
    let closed: RoundOutcome | null = null;
    if (this.round && ledgerIndex >= this.round.ledger_index + 2) closed = this.close(unlSize);
    if (!isVotingLedger(ledgerIndex)) return closed;
    if (this.round && ledgerIndex < this.round.ledger_index) return closed;
    if (!this.round || this.round.ledger_index !== ledgerIndex) {
      this.round = { ledger_index: ledgerIndex, first_ms: nowMs, signers: new Set(), votes: new Map() };
    }
    this.round.signers.add(masterKey);
    if (Array.isArray(amendments)) {
      for (const h of amendments) {
        if (typeof h !== 'string' || h === '') continue;
        const key = h.toUpperCase();
        let who = this.round.votes.get(key);
        if (!who) { who = new Set(); this.round.votes.set(key, who); }
        who.add(masterKey);
      }
    }
    return closed;
  }

  /** Close the open round against the quorum, keep it if it holds one. */
  private close(unlSize: number): RoundOutcome {
    const r = this.round as OpenRound;
    this.round = null;
    const quorum = Math.ceil(unlSize * 0.8);
    if (unlSize <= 0 || r.signers.size < quorum) {
      return { kind: 'discarded', round: { ledger_index: r.ledger_index, trusted_validations: r.signers.size, quorum } };
    }
    const counts: Record<string, number> = {};
    for (const [hash, who] of r.votes) counts[hash] = who.size;
    this.last = {
      ledger_index: r.ledger_index,
      at_ms: r.first_ms,
      validations: r.signers.size,
      threshold: amendmentVoteThreshold(r.signers.size),
      counts,
    };
    return { kind: 'counted', tally: this.last };
  }
}
