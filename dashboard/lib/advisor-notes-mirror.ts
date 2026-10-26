/**
 * The aggregator's poller for the fleet Advisor memory and inbox mirrors,
 * ADR 0021 build step 5.
 *
 * A much simpler sibling of advisor-ledger-mirror.ts, because neither source
 * carries a hash chain. GET /v1/memory and GET /v1/inbox always answer the
 * whole file, so there is no since_seq, no run genesis to compare, and no
 * "does this chain onto what is held" question at all. Every poll is a full
 * read, and every full read is upserted by (node, id), never diffed against
 * what a prior poll saw and never used to delete anything, db.ts's
 * memoryMirrorUpsert and inboxMirrorUpsert both hold to that on their own,
 * so this module's only job is deciding WHEN to ask and handing the answer
 * straight through.
 *
 * Same two providers as the ledger mirror: this host's own advisord over
 * loopback, or a peer through fetchPeerAdvisor's exact-path allow-list.
 * Folded into one target per node before it reaches this file, exactly as
 * server.ts already does for the ledger.
 */
import {
  memoryMirrorUpsert, inboxMirrorUpsert, notesMirrorRecordAttempt,
  type MemoryMirrorEntryIn, type InboxMirrorNoteIn,
} from '../db.js';

export type MemoryFetchResult =
  | { ok: true; entries: MemoryMirrorEntryIn[] }
  | {
    ok: false;
    detail: string;
    /** Same meaning as advisor-ledger-mirror.ts's LedgerFetchResult.absent:
     *  there is no Advisor on this host to ask at all, so nothing is
     *  recorded, not even a failed attempt, rather than a state row that
     *  grows a pile of identical failures for a host that will never have
     *  one. */
    absent?: boolean;
  };

export type InboxFetchResult =
  | { ok: true; notes: InboxMirrorNoteIn[] }
  | { ok: false; detail: string; absent?: boolean };

export type FetchMemory = () => Promise<MemoryFetchResult>;
export type FetchInbox = () => Promise<InboxFetchResult>;

export interface NotesMirrorTarget {
  node: string;
  fetchMemory: FetchMemory;
  fetchInbox: FetchInbox;
}

/** Polls one node's memory. Never throws: a fetch failure is recorded and
 *  swallowed, the same discipline pollMirrorTargets applies to the ledger,
 *  so one node's trouble never stops another's poll. */
async function pollMemory(target: NotesMirrorTarget): Promise<void> {
  const res = await target.fetchMemory();
  if (!res.ok) {
    if (!res.absent) notesMirrorRecordAttempt(target.node, 'memory', false, res.detail);
    return;
  }
  memoryMirrorUpsert(target.node, res.entries);
}

/** Polls one node's inbox. Same shape as pollMemory, kept separate rather
 *  than parameterised over the two: the two payload shapes and the two
 *  db.ts writers they call are different enough that one generic function
 *  would need a branch inside it anyway, and this way each half reads
 *  straight through. */
async function pollInbox(target: NotesMirrorTarget): Promise<void> {
  const res = await target.fetchInbox();
  if (!res.ok) {
    if (!res.absent) notesMirrorRecordAttempt(target.node, 'inbox', false, res.detail);
    return;
  }
  inboxMirrorUpsert(target.node, res.notes);
}

/** One poll of one node: its memory and its inbox, independently, a fetch
 *  failure on one must not stop the other from being recorded. */
export async function pollNotesMirrorNode(target: NotesMirrorTarget): Promise<void> {
  await Promise.all([pollMemory(target), pollInbox(target)]);
}

/** Polls every target once, each isolated from the others' failures, the
 *  same shape as pollMirrorTargets for the ledger. */
export async function pollNotesMirrorTargets(targets: NotesMirrorTarget[]): Promise<void> {
  await Promise.all(targets.map(async (t) => {
    try {
      await pollNotesMirrorNode(t);
    } catch (err) {
      const detail = (err as Error).message;
      notesMirrorRecordAttempt(t.node, 'memory', false, detail);
      notesMirrorRecordAttempt(t.node, 'inbox', false, detail);
    }
  }));
}

/**
 * Runs targets on an interval, guarded against overlapping itself, the
 * same reason AdvisorLedgerMirror keeps this guard: a fleet's worth of
 * requests stacking on top of a still-running poll is worse than one
 * arriving a little late.
 */
export class AdvisorNotesMirror {
  private readonly targets: NotesMirrorTarget[];
  private readonly intervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private inFlight = false;

  constructor(targets: NotesMirrorTarget[], opts: { intervalMs?: number } = {}) {
    this.targets = targets;
    this.intervalMs = opts.intervalMs ?? 30_000;
  }

  start(): void {
    if (this.timer || this.targets.length === 0) return;
    void this.tick();
    this.timer = setInterval(() => { void this.tick(); }, this.intervalMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  private async tick(): Promise<void> {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      await pollNotesMirrorTargets(this.targets);
    } finally {
      this.inFlight = false;
    }
  }
}
