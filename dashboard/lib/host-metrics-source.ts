// Which host the System tab's compute rows (CPU, memory, swap, disk,
// pressure, OOM) describe. Pure so it can be tested; server.ts feeds it the
// last relay `system` frame, the clock, and its own hostname.
//
// No relay has ever pushed: the dashboard's own /proc, as on a single host
// without a relay. A relay has pushed and is current: the relay's block,
// which is the validator host's. That is the whole point of a split
// deployment, where the dashboard runs on a different machine and its own
// /proc describes the wrong box. A relay has pushed but gone quiet: if it
// named the same hostname as this process (co-located), the local reader is
// the same host and stays honest; otherwise the rows go to a dash. A number
// that stopped moving, or the dashboard host's number wearing the
// validator's label, are both worse than a blank.

import type { SystemPayload } from '../types/relay-contract.js';

export interface LastRelaySystem {
  payload: SystemPayload;
  at_ms: number;
  label: string;
}

export type HostMetricsSource =
  | { source: 'local'; hostname: string }
  | { source: 'relay'; fresh: true;  sys: SystemPayload; age_ms: number; hostname: string | null }
  | { source: 'relay'; fresh: false; age_ms: number; hostname: string | null };

// Six relay ticks at the default 5 s cadence. Past this the block is stale
// and the tab shows a dash for it rather than a number that stopped moving.
export const RELAY_SYSTEM_STALE_MS = 30_000;

export function hostMetricsSource(
  last: LastRelaySystem | null,
  nowMs: number,
  localHostname: string,
  staleMs: number = RELAY_SYSTEM_STALE_MS,
): HostMetricsSource {
  if (!last) return { source: 'local', hostname: localHostname };
  const age = nowMs - last.at_ms;
  const relayHost = last.payload.hostname || null;
  if (age <= staleMs) return { source: 'relay', fresh: true, sys: last.payload, age_ms: age, hostname: relayHost };
  if (relayHost && relayHost === localHostname) return { source: 'local', hostname: relayHost };
  return { source: 'relay', fresh: false, age_ms: age, hostname: relayHost };
}
