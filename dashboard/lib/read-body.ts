// LOW-09, one way to read a request body, with a cap that is real.
//
// Every route that read a body had its own copy of the same loop, and the
// copies did not agree. Four of them counted `body.length`, which is UTF-16
// code units rather than bytes, so a multi-byte body was under-counted against
// a cap expressed in bytes. Three of them, all in server.ts, called
// req.destroy() when the cap was passed, and wrote their response from the
// 'end' handler, which a destroyed request never emits: the caller got a reset
// socket and no answer at all. Measured before this file existed, against that
// exact shape, a 64 KiB POST at a 2 KiB cap: `end fired = false`, and the
// client saw `TypeError: fetch failed`.
//
// So the primitive here never destroys and never throws. It stops reading, and
// it hands the route an outcome the route can answer with, because a refusal
// nobody is told about is not a refusal, it is a hang.
//
// One more thing the copies disagreed on. setEncoding('utf8') has to be called
// BEFORE the 'data' listener is attached, or chunks arrive as Buffers and a
// multi-byte character that straddles a chunk boundary is corrupted by the
// implicit toString. Two copies did it, two did not.

import type { IncomingMessage } from 'node:http';

export type BodyOutcome =
  | { ok: true; body: string }
  /** The caller sent more than this route accepts. */
  | { ok: false; reason: 'too_large' }
  /** The stream failed before the body was complete. */
  | { ok: false; reason: 'stream_error' };

/**
 * Read a request body as UTF-8, up to maxBytes.
 *
 * The cap is counted in bytes, and it is checked as the body grows rather than
 * at the end, so an oversized request is abandoned rather than buffered whole.
 * Passing the cap pauses the stream and resolves immediately: nothing is
 * destroyed, so the route still has a live response to write its refusal on.
 *
 * One measured consequence of not destroying. The refusal goes out while the
 * rest of the body is still unread, and node answers it with Connection:
 * keep-alive, so the socket idles until the keep-alive timeout (5s by default)
 * instead of closing at once. The remaining bytes never reach the parser,
 * because pausing the stream pauses the socket read, so they cannot be
 * mistaken for a second request. An answered request that holds a socket for
 * five seconds is the trade for a refusal the caller can actually read.
 */
export function readBody(req: IncomingMessage, maxBytes: number): Promise<BodyOutcome> {
  return new Promise((resolve) => {
    let body = '';
    let settled = false;
    const settle = (outcome: BodyOutcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
    // Before the listener, always. See the note at the top of this file.
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      if (settled) return;
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > maxBytes) {
        body = '';
        req.pause();
        settle({ ok: false, reason: 'too_large' });
      }
    });
    req.on('end', () => settle({ ok: true, body }));
    req.on('error', () => settle({ ok: false, reason: 'stream_error' }));
  });
}

/** Thrown by readBodyOrThrow when the body is over the route's cap. */
export class BodyTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`body too large (over ${maxBytes} bytes)`);
    this.name = 'BodyTooLargeError';
  }
}

/**
 * The same read, for the call sites that are written around a throw.
 *
 * auth.ts and settings-api.ts each have a dozen routes that call this inside a
 * try, or inside a JSON.parse whose catch already answers. Handing those a
 * result object would mean rewriting every one of them to check it, and a
 * check that is easy to forget is worse than an exception that cannot be.
 */
export async function readBodyOrThrow(req: IncomingMessage, maxBytes: number): Promise<string> {
  const out = await readBody(req, maxBytes);
  if (out.ok) return out.body;
  if (out.reason === 'too_large') throw new BodyTooLargeError(maxBytes);
  throw new Error('request stream failed');
}
