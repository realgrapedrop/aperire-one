# Metric meanings and thresholds

**Superseded.** The other `metrics-*.md` files carry every metric with its
source line, unit and current alert bands: `metrics-consensus-ledger-timing.md`,
`metrics-consensus-agreement.md`, `metrics-load.md`,
`metrics-validator-registry.md`, `metrics-peers.md`, `metrics-traffic.md`,
`metrics-ports-and-relay-feed.md`, `metrics-host-cpu-and-memory.md`,
`metrics-host-pressure.md` and `metrics-host-process-and-disk.md`. Where this
file and those disagree, they are right and this is stale.

**Three names below are not metric names and never were:** `agreement_1h`,
`missed_validations_24h` and `server_state`. Nothing writes them and no read
route serves them, so do not name them in a lookup. The real names are
`agreement_pct_1h`, `missed_validations_1h`, and — for server state — the
`server_info` field, readable through a host read, not a metric series.

Kept for now because the node-specific baselines further down are still the
best record of this host's normal.

What each measured value means and where its lines are, as the dashboard
draws them. Full detail lives in the repo's METRICS-CATALOG.

## Consensus

- agreement_pct / agreement_1h: share of validated ledgers this validator
  signed, rolling window. Healthy is 100%. Ledgers closed during an admin
  connection gap are excluded — a miss nobody could observe is not a miss.
- missed_validations_1h: 0 is healthy; more than 5 in an hour is critical.
- missed_validations_24h: 0 is healthy; more than 20 in a day is critical.
- Every individual miss is kept permanently with context (validations seen,
  peers, server state at that moment) on the Consensus tab.
- Ledger close time: 3–5s healthy, 5–6s elevated, above 6s consensus is
  taking longer than expected.
- server_state: proposing is the healthy state for this validator. full is
  healthy for a non-validating node. connected/syncing are the normal climb
  after a restart (minutes, not seconds) and only a problem when they persist.

## Network

- peer_count: no fixed band. A healthy count is whatever this node holds flat
  over a normal week, recorded in `node-profile.md`. Watch the
  outbound/inbound split, not just the total.
- peer_latency_p50: no fixed band, and the absolute number says less than the
  shape. Compare against this node's own recorded normal; a step change that
  then holds is the finding, and one that stays unexplained is worth writing
  into `node-profile.md` as the current baseline rather than left as a fault.
- tx_bps outgoing: no fixed band. Sustained multiples of this node's own
  recorded baseline, with peers falling at the same time, is the
  manifest-flood signature.

## Reading changes

The cards judge two things separately: band (is the value outside a safe
range right now) and change (has it moved materially from its own baseline).
A metric can be inside its band and still be the most important thing on the
page — the peer incident was found as a change, not a band violation.
