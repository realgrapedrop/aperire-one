// How many Advisor questions this dashboard process is currently carrying —
// punch #24.
//
// The dashboard is not just the page that asks. On the aggregator it is the
// PROXY: a question asked about validator1 travels browser → aggregator →
// validator1's advisord, and the middle hop is a fetch held open by this
// process for the length of the answer. Restart it and that connection goes
// away, which hangs up on the advisord, which is how an operator's question
// died on 2026-08-20 with the advisord itself never touched.
//
// So the deploy needs to know when this process is holding one. It publishes
// the count on /healthz, and the fleet update tool waits for zero
// before it restarts the unit — the same arrangement /v1/status carries on the
// advisord side.
//
// Deliberately process-local and in-memory. It is a fact about THIS process's
// open sockets, and there is nothing to persist: a process that is gone is
// holding nothing.

let inFlight = 0;

/** How many Advisor questions this process is forwarding right now. */
export function asksInFlight(): number {
  return inFlight;
}

/**
 * Run `work` with this process counted as carrying one question.
 *
 * A wrapper rather than a matched enter/exit pair, because the exit has to
 * happen on the throw as well: an aborted fetch (the 300s timeout, a peer that
 * went away) leaving the count stuck at one would mean the next deploy waits
 * out its whole 120s window and then restarts anyway, on a process that has
 * been idle the entire time. A gauge that can only go up is worse than no
 * gauge, because it is believed once.
 */
export async function trackAsk<T>(work: () => Promise<T>): Promise<T> {
  inFlight++;
  try {
    return await work();
  } finally {
    inFlight--;
  }
}

/** Test seam. Never called by the server. */
export function resetAsksInFlight(): void {
  inFlight = 0;
}
