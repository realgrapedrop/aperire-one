/**
 * The read surface's one long-lived connection — ADR 0013, decisions 4-6.
 *
 * Everything else under /read/ is one-shot JSON: it answers and it ends, so
 * it is self-limiting and needs no accounting. A stream occupies a socket for
 * minutes, and that is the whole of what is new here. The three bounds the
 * ADR names therefore live in this module rather than inline in server.ts,
 * where they would be untestable:
 *
 *   - a concurrency cap per read token — the newest connection over the cap
 *     is refused BY NAME, never queued;
 *   - a maximum stream lifetime, which is a SECURITY control and not
 *     housekeeping: the aggregator re-verifies a peer's expected_pubkey_node
 *     pin on every reconnect, so bounding the lifetime converts "the pin is
 *     re-checked when something goes wrong" into a pin re-check with a floor;
 *   - no backpressure buffering — a consumer that cannot keep up gets the
 *     CURRENT tick and never a backlog. A late tick is a stale reading, and
 *     the honest answer to "you fell behind" is the present value, not the
 *     past ones in order.
 *
 * There are no timers in here. `sweep()` is called from the same 1Hz tick
 * that emits the events, so the whole surface runs on one interval the
 * process already had, and a unit test drives lifetime and heartbeat by
 * passing a clock rather than by faking one.
 */

/**
 * The subset of a Node ServerResponse this module uses. A sink, not a
 * response: the registry never sets a header, never decides a status, and
 * cannot end a request it did not open — server.ts owns all three.
 */
export interface StreamSink {
  /** Returns false when the kernel/stream buffer is full, exactly as
   *  ServerResponse.write does. */
  write(chunk: string): boolean;
  end(): void;
  /** Bytes queued in memory and not yet flushed (ServerResponse's
   *  writableLength). The backpressure signal this module skips ticks on. */
  bufferedBytes(): number;
}

export interface StreamConnection {
  readonly sink: StreamSink;
  readonly channels: readonly string[];
  readonly openedAtMs: number;
  lastWriteAtMs: number;
}

export interface ReadStreamRegistryOpts {
  /** ADR 0013 decision 6's starting point: one aggregator, one operator
   *  browser, and headroom. Deliberately small — this is a bound, not a
   *  capacity plan. */
  maxConcurrent?: number;
  /** The pin-re-verification floor. */
  lifetimeMs?: number;
  /** Idle time before a `: heartbeat` comment line, so a stalled tunnel is
   *  detectable rather than indistinguishable from a quiet node. */
  heartbeatMs?: number;
  /** Above this many buffered bytes a tick is DROPPED for that connection
   *  rather than queued. */
  maxBufferedBytes?: number;
}

// ADR 0013 left this as a starting point of 4, reasoned as "one aggregator,
// one operator browser, headroom" — and asked for it to be settled by
// measurement rather than argument. Measured on the lab: the aggregator does
// NOT multiplex. It relays per browser connection, so one operator with the
// fleet dashboard open on this peer holds one upstream slot (3 of 4 free,
// counted from the node), a second operator or a phone holds another, and a
// directly-opened tab page holds one of its own. Four is therefore two
// operators and no room. Eight costs eight idle sockets and a heartbeat each.
// The real repair — one upstream stream per peer, fanned out to every browser
// watching it — belongs with the ledger-close channel, not here.
export const DEFAULT_MAX_CONCURRENT = 8;
export const DEFAULT_LIFETIME_MS = 15 * 60_000;
export const DEFAULT_HEARTBEAT_MS = 10_000;
export const DEFAULT_MAX_BUFFERED_BYTES = 64 * 1024;

/** SSE framing, in one place so the node side and any test agree on it.
 *  No `id:` line, deliberately (ADR 0013, decision 5): without one the
 *  browser never sends Last-Event-ID and the server never replays, and a
 *  replayed round-progress tick is a stale reading rendered as current. */
export function formatSseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

export type AddResult =
  | { ok: true; conn: StreamConnection }
  | { ok: false; error: 'stream_capacity_reached' };

export class ReadStreamRegistry {
  private readonly conns = new Set<StreamConnection>();
  private readonly maxConcurrent: number;
  private readonly lifetimeMs: number;
  private readonly heartbeatMs: number;
  private readonly maxBufferedBytes: number;

  constructor(opts: ReadStreamRegistryOpts = {}) {
    this.maxConcurrent = opts.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
    this.lifetimeMs = opts.lifetimeMs ?? DEFAULT_LIFETIME_MS;
    this.heartbeatMs = opts.heartbeatMs ?? DEFAULT_HEARTBEAT_MS;
    this.maxBufferedBytes = opts.maxBufferedBytes ?? DEFAULT_MAX_BUFFERED_BYTES;
  }

  get size(): number {
    return this.conns.size;
  }

  /** Admits a connection or refuses it by name. The refusal is the NEWEST
   *  connection's, never an eviction of an established one: an operator's
   *  browser must not be able to knock the aggregator's stream off a node. */
  add(sink: StreamSink, channels: readonly string[], nowMs: number): AddResult {
    if (this.conns.size >= this.maxConcurrent) {
      return { ok: false, error: 'stream_capacity_reached' };
    }
    const conn: StreamConnection = {
      sink,
      channels: [...channels],
      openedAtMs: nowMs,
      lastWriteAtMs: nowMs,
    };
    this.conns.add(conn);
    return { ok: true, conn };
  }

  /** Called from the socket's own close handler. Idempotent — a connection
   *  closed by the lifetime cap is removed here a second time and that is
   *  not an error. */
  remove(conn: StreamConnection): void {
    this.conns.delete(conn);
  }

  /**
   * Writes one event to every connection subscribed to `channel`. A
   * connection whose buffer is already over the cap is SKIPPED for this tick
   * — not queued, not disconnected: it will get the next one, which by then
   * is the current reading.
   */
  emit(channel: string, data: unknown, nowMs: number): void {
    if (this.conns.size === 0) return;
    const frame = formatSseEvent(channel, data);
    for (const conn of [...this.conns]) {
      if (!conn.channels.includes(channel)) continue;
      if (conn.sink.bufferedBytes() > this.maxBufferedBytes) continue;
      if (!this.writeTo(conn, frame, nowMs)) continue;
    }
  }

  /**
   * One pass of the two duration bounds. Runs on the same 1Hz tick that
   * emits, so a stream that has gone quiet still gets both.
   *
   * Order matters: the lifetime cap is evaluated first, so a connection due
   * to close is closed rather than heartbeated one last time.
   */
  sweep(nowMs: number): void {
    for (const conn of [...this.conns]) {
      if (nowMs - conn.openedAtMs >= this.lifetimeMs) {
        this.conns.delete(conn);
        try { conn.sink.end(); } catch { /* the peer is already gone */ }
        continue;
      }
      if (nowMs - conn.lastWriteAtMs >= this.heartbeatMs) {
        this.writeTo(conn, ': heartbeat\n\n', nowMs);
      }
    }
  }

  /** Closes every open stream — server shutdown, or a test's teardown. */
  closeAll(): void {
    for (const conn of [...this.conns]) {
      this.conns.delete(conn);
      try { conn.sink.end(); } catch { /* the peer is already gone */ }
    }
  }

  private writeTo(conn: StreamConnection, chunk: string, nowMs: number): boolean {
    try {
      conn.sink.write(chunk);
      conn.lastWriteAtMs = nowMs;
      return true;
    } catch {
      // A write that throws is a socket that is already gone; drop it here
      // rather than waiting for a close event that may never arrive.
      this.conns.delete(conn);
      return false;
    }
  }
}
