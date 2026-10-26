/**
 * Ask a root program a question through a systemd socket.
 *
 * The dashboard's unit forbids sudo (NoNewPrivileges, empty capability set),
 * so the privileged programs it needs are already running behind sockets
 * that systemd owns: /run/aperire/seal-model-key.sock for the model key
 * sealer, /run/aperire/trust-sync.sock for the trust sync. Each accepts one
 * connection, hands it to one program as its three streams, and closes when
 * the program ends. This is the client for that shape, used by both.
 *
 * What crosses is the payload, written once and half-closed so the program's
 * reads see the end of it. Nothing is an argument (world-readable in /proc)
 * and nothing is in the environment (inherited by every child). What comes
 * back is one stream carrying both standard output and standard error, with
 * `exit=<code>` as the last line because an exit code does not cross a
 * socket; splitSealerStream reads it apart.
 *
 * Resolves on a refusal, which is an outcome an operator needs the words of.
 * Rejects only when the socket could not be opened at all: a host without
 * the grant, which is a different sentence from a refusal.
 *
 * A write that breaks is NOT that case, and telling the two apart is what
 * #454 was. A program behind one of these sockets answers and exits, and one
 * that exits with part of the payload still unread leaves this side holding
 * ECONNRESET or EPIPE: closing a unix socket with data still queued on it
 * sets the error on the peer. The answer is already here when that happens,
 * in full, with its own `exit=` line. Rejecting on the write error threw it
 * away, and a node whose sealer had refused in words reported "the sealing
 * program could not be reached on this host".
 */
import { connect as connectSocket } from 'node:net';
import { splitSealerStream } from './model-seal.js';

export interface ProgramAnswer {
  code: number; stdout: string; stderr: string;
  /** False when the stream ended with no `exit=` line, or this side stopped
   *  waiting: `code` is then 1 because something had to be, and it is not the
   *  program's. Absent on an answer built by hand, which reads as reported. */
  reported?: boolean;
  /** True when this side stopped waiting (the timeout below). Nothing the
   *  program may have written is kept, so `stderr` is this side's own
   *  sentence and is never the program's last line (#848). */
  timedOut?: boolean;
}

/**
 * Watch the answer arrive.
 *
 * The two callers that came first (the sealer, the trust sync) answer in a
 * moment and read the whole thing at the end, so they pass nothing. An
 * update runs for minutes with an operator watching, and a progress file
 * that only exists once the run is over is not progress. Optional, so the
 * shape the other two rely on is unchanged: what is handed over is the raw
 * chunk, exactly as it came off the socket, boundaries and all. Whoever
 * takes it owns the reassembly.
 */
export type ProgramChunk = (text: string) => void;

export function askSocketProgram(
  socketPath: string, payload: string, timeoutMs: number, who: string,
  onChunk?: ProgramChunk,
): Promise<ProgramAnswer> {
  return new Promise((resolveRun, rejectRun) => {
    const sock = connectSocket(socketPath);
    sock.setEncoding('utf8');
    let raw = '';
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(killer);
      fn();
    };
    // A program that never answers would hold this request open forever. The
    // unit behind the socket carries its own RuntimeMaxSec=, so this is the
    // second of two bounds, and the caller sets it to match.
    const killer = setTimeout(() => {
      finish(() => resolveRun({ code: 1, stdout: '', stderr: `${who} did not answer in time`, reported: false, timedOut: true }));
      sock.destroy();
    }, timeoutMs);
    sock.on('connect', () => { sock.end(payload); });
    sock.on('data', (d: string) => {
      raw += d;
      // Never allowed to end the run: a watcher that throws is a bug in the
      // watcher, and the program on the other end is mid-apply.
      if (onChunk) { try { onChunk(d); } catch { /* the watcher's problem */ } }
    });
    // One place this settles, and it is `close`, which always follows `error`
    // on a socket. What came back decides: bytes on the wire are the
    // program's answer whatever happened to the write afterwards, and
    // nothing on the wire with an error is a connection that was never made.
    // That second case is the one every caller's catch reads through
    // isSocketUnreachable (ENOENT, EACCES, ECONNREFUSED), and a connect
    // failure has no bytes, so those are unchanged.
    //
    // A clean close with nothing on it still resolves, as it did before: a
    // program that said nothing is not a program that could not be reached,
    // and splitSealerStream reports that as "ended without reporting" (#330).
    let failed: NodeJS.ErrnoException | null = null;
    sock.on('error', (err: NodeJS.ErrnoException) => { failed = err; });
    sock.on('close', () => {
      finish(() => {
        const broke = failed;
        if (broke !== null && raw === '') { rejectRun(broke); return; }
        resolveRun(splitSealerStream(raw));
      });
    });
  });
}
