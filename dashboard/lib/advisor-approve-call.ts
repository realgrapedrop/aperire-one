// The dashboard's calls to the Advisor that record an approval, and take one
// back (#1051, #1096).
//
// Once the passkey verifies, the dashboard hands the grant to the Advisor's
// /v1/approve, and the Advisor re-measures every precondition before it
// answers. On a node that has just rejoined, those reads can run long: the
// incident behind #1051 had the Advisor spend about 40 seconds on
// `server_info` and the running version, then refuse the approval. This call
// gave up at 30 seconds. The abort threw out of the handler, the outer
// last-resort handler answered `{error:"internal_error"}`, and the operator,
// who had just touched a passkey, got a word that names no cause. The Advisor
// went on to write `approval.refused` into the ledger with the failing
// checks named, so the reason existed and never reached the page.
//
// Two answers this call must never confuse:
//
//   - the Advisor ANSWERED (any status, including its 409 refusal with
//     `failures`): passed through byte for byte, so the page reads what the
//     Advisor said;
//   - the Advisor did NOT answer in time, or could not be reached: the
//     outcome is UNKNOWN. A timeout is not a refusal. The Advisor may still
//     refuse, or may still grant, after this side has stopped waiting. So the
//     answer says exactly that, with a stable `reason` the page branches on,
//     and the page asks the node's ledger what happened.
//
// Revoking an approval has the same shape and the same failure: a slow Advisor
// reached the page as `internal_error` with no word on whether the approval
// was revoked. It goes through the same wrapper, with its own wording.
//
// The detail strings are fixed text. The thrown error's own message stays in
// the server log, where an operator can read it, and never goes on the wire
// (the same rule lib/error-response.ts states).

/** The ceiling this side waits for the Advisor's answer to an approval. */
export const ADVISOR_APPROVE_TIMEOUT_MS = 30_000;

// What status the browser sees (#1051, #1117).
//
// In front of the aggregator, Cloudflare replaces an origin 502 or 504 with its
// own HTML page. The 504 this file answered for a slow Advisor, and the 502 for
// one that could not be reached, therefore never reached the page: it read
// "an HTML page, not the dashboard", could not tell a timeout from a wall, and
// never asked the node's ledger what the Advisor decided. So an answer that
// says the Advisor gave none travels as a 200 whose body carries the facts
// (`error`, `reason`, `upstream_status`, `granted: false`), and the page
// decides by the body, never by the status alone. An Advisor 5xx of its own is
// wrapped the same way, so a reason it gave is not swapped for an edge page
// either. A 4xx (its 409 refusal, with `failures`) passes through byte for byte.

/** What the handler writes back: the Advisor's own answer, or a 200 whose body
 *  says the Advisor gave none. */
export interface AdvisorApproveAnswer {
  status: number;
  body: string;
}

/** The two ways no answer arrives, as the page reads them in `reason`. */
export type NoAnswerReason = 'advisor_timeout' | 'advisor_unreachable' | 'advisor_error';

/** Which call this was, for the words only. */
type Call = 'approve' | 'cancel';

function noAnswer(call: Call, reason: NoAnswerReason, seconds: number): AdvisorApproveAnswer {
  const timedOut = reason === 'advisor_timeout';
  const unknown = call === 'cancel'
    ? 'Whether it revoked the approval is in its record.'
    : 'Whether it approved or refused is in its record.';
  const nothing = call === 'cancel'
    ? 'Nothing was revoked from here. Check that the Advisor is running on that node.'
    : 'Nothing was approved from here. Check that the Advisor is running on that node.';
  return {
    status: 200,
    body: JSON.stringify({
      // Never `granted: true` here, whatever else the body says: the page
      // reads that key as the approval, and an answer that says the Advisor
      // gave none grants nothing.
      granted: false,
      error: timedOut
        ? 'the Advisor did not answer within ' + seconds + ' seconds'
        : 'the Advisor could not be reached',
      reason,
      // What the status would have been, were it not for the edge.
      upstream_status: timedOut ? 504 : 502,
      detail: timedOut ? 'It may still be working on it. ' + unknown : nothing,
    }),
  };
}

/** An Advisor 5xx of its own, wrapped so its reason reaches the page: the
 *  Advisor's JSON object, if it sent one, with `upstream_status` and no
 *  `granted: true`. Anything that is not a JSON object is not passed on. */
function wrapAdvisorServerError(status: number, text: string): AdvisorApproveAnswer {
  let said: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) said = parsed as Record<string, unknown>;
  } catch { /* not JSON: the status is all there is to say */ }
  if (typeof said.error !== 'string' || !said.error) said.error = 'the Advisor answered HTTP ' + status;
  // `reason: advisor_error` (#1135 review): the Advisor answered with an error,
  // but a 5xx is not a verdict. It may have refused or granted before it failed,
  // and an error with no `internal_error` and no reason of its own read as a
  // plain answer, so the page never asked its record. The reason is what makes
  // the page treat the outcome as unknown and start the ledger watch.
  return { status: 200, body: JSON.stringify({ ...said, granted: false, reason: 'advisor_error', upstream_status: status }) };
}

/** True for the error fetch raises when AbortSignal.timeout fires. */
function isTimeout(err: unknown): boolean {
  const n = (err as { name?: string } | null)?.name;
  return n === 'TimeoutError' || n === 'AbortError';
}

async function postAdvisor(
  call: Call,
  path: string,
  advisorUrl: string,
  advisorToken: string,
  payload: unknown,
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch },
): Promise<AdvisorApproveAnswer> {
  const timeoutMs = opts.timeoutMs ?? ADVISOR_APPROVE_TIMEOUT_MS;
  const doFetch = opts.fetchImpl ?? fetch;
  try {
    const r = await doFetch(`${advisorUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${advisorToken}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    // Reading the body is inside the same deadline: the signal covers it.
    const text = await r.text();
    if (r.status >= 500 && r.status <= 599) return wrapAdvisorServerError(r.status, text);
    return { status: r.status, body: text };
  } catch (err) {
    const timedOut = isTimeout(err);
    console.error('[advisor-' + call + '] no answer from the Advisor (' +
      (timedOut ? 'timeout' : 'unreachable') + '):', (err as Error)?.message ?? err);
    return noAnswer(call, timedOut ? 'advisor_timeout' : 'advisor_unreachable', Math.round(timeoutMs / 1000));
  }
}

type PostOpts = { timeoutMs?: number; fetchImpl?: typeof fetch };

/**
 * POST the grant to the Advisor and return what it answered. Never throws for
 * a failed or slow call: that is an answer too, just not the Advisor's.
 * `fetchImpl` and `timeoutMs` exist for the unit test.
 */
export function postAdvisorApprove(
  advisorUrl: string, advisorToken: string, payload: unknown, opts: PostOpts = {},
): Promise<AdvisorApproveAnswer> {
  return postAdvisor('approve', '/v1/approve', advisorUrl, advisorToken, payload, opts);
}

/** The same for taking an approval back (#1096). */
export function postAdvisorCancel(
  advisorUrl: string, advisorToken: string, payload: unknown, opts: PostOpts = {},
): Promise<AdvisorApproveAnswer> {
  return postAdvisor('cancel', '/v1/approve/cancel', advisorUrl, advisorToken, payload, opts);
}
