/**
 * Which way a peer loss is pointing.
 *
 * On 31 July outbound peers fell while inbound held and traffic rose. That
 * shape means the network shed us: peers we had dialled went away, peers still
 * dialling us did not, and the ones left were carrying more. The other shape —
 * both directions falling with traffic flat — means the problem is local,
 * because nothing outside this host would drop inbound and outbound together
 * while leaving throughput unchanged.
 *
 * Reading the two directions separately is the entire point. `peer_count`
 * alone falls identically in both cases, which is why telling them apart used
 * to mean reading three charts at once and knowing what to look for.
 *
 * Pure, and separate from the query that feeds it, so both shapes can be
 * tested. A classifier of this kind fails silently in the worst way: it
 * returns "nothing unusual" whether it saw nothing unusual or saw nothing at
 * all, and an alert that can never fire looks exactly like an alert that has
 * nothing to report.
 */

/** 0 nothing unusual · 1 the network shed us · 2 our own box. */
export type ShedVerdict = 0 | 1 | 2;

export interface PeerShedInput {
  /** Peers dialling us, and peers we dialled, right now. */
  inboundNow: number;
  outboundNow: number;
  /** The same two, averaged over the earlier part of the window. */
  inboundWas: number | null;
  outboundWas: number | null;
  /** Total throughput now, and averaged over the earlier part of the window. */
  trafficNow: number | null;
  trafficWas: number | null;
}

/** A third of a direction gone. Peers churn constantly; this does not. */
export const DROP = 0.33;

export function peerShedVerdict(i: PeerShedInput): ShedVerdict {
  const { inboundNow, outboundNow, inboundWas, outboundWas, trafficNow, trafficWas } = i;
  // No baseline is not the same as no problem, but it is the same response:
  // say nothing. The caller distinguishes them by logging, not by the verdict.
  if (inboundWas === null || outboundWas === null) return 0;
  if (inboundWas <= 0 || outboundWas <= 0) return 0;

  const inFell = inboundNow < inboundWas * (1 - DROP);
  const outFell = outboundNow < outboundWas * (1 - DROP);
  if (!inFell && !outFell) return 0;

  // Throughput is the only thing that separates the two shapes. Without it
  // there is a peer loss and no way to attribute it, and a guess here would be
  // worse than silence — it would send the operator to the wrong place first.
  if (trafficNow === null || trafficWas === null || trafficWas <= 0) return 0;
  const ratio = trafficNow / trafficWas;

  // Outbound gone, inbound holding, remaining peers busier: the network.
  if (outFell && !inFell && ratio > 1.1) return 1;
  // Both gone, throughput unmoved: nothing outside does that.
  if (outFell && inFell && ratio > 0.9 && ratio < 1.1) return 2;
  // A shape that is neither. Conservative on purpose — a trigger that fires on
  // ordinary churn is one the operator learns to ignore, which costs more than
  // the missed case.
  return 0;
}

/**
 * The earlier half of a series, averaged.
 *
 * Deliberately not the whole window: including the fall in "what it was"
 * dilutes exactly the change being measured, so a large drop reads as a small
 * one. Returns null below three points, because two samples is not a baseline.
 */
export function baseline(points: Array<{ value: number }>): number | null {
  const older = points.slice(0, Math.floor(points.length / 2));
  if (older.length < 3) return null;
  return older.reduce((a, p) => a + p.value, 0) / older.length;
}
