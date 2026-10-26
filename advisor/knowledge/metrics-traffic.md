---
title: Host network traffic, packet rates and retransmits
tags: [traffic, bandwidth, throughput, packets, retransmits, rx_bps, tx_bps, rx_pps, tx_pps, tcp_retrans_per_sec]
last_reviewed: 2026-08-21
---

# Metric reference — host network traffic, packet rates and retransmits

Host-network throughput, packet rates and TCP retransmits. Every series in
this file originates in the relay on the validator host, arrives over the
ingest WebSocket as a `net_stats` push (`relay/contract.go`,
`NetStatsPayload`), and is turned into a rate by the dashboard before storage.

**The relay sends cumulative counters; the dashboard sends rates.** Bytes,
packets, retransmits and resets are counters since the interface came up.
The dashboard diffs each push against the previous one and divides by the
interval it measures from `sent_at_ms` (`dashboard/server.ts:3930-3948`). A
counter that *decreased* means a reboot or a rollover: the deltas are
dropped, the baseline is reset, and a line is logged. So a gap in these
series after a reboot is correct behaviour, not lost data.

**Written only when the relay has pushed.** `sampleNetworkMetrics` skips this
whole block when no push has arrived (`dashboard/server.ts:1585`), because
storing zeros that mean "unknown" is worse than storing nothing. Every one of
these series therefore goes *silent* when the relay dies, with no other
signal — which is exactly what `relay_feed_age_s` exists to make visible.

`relay_feed_age_s` itself lives in `metrics-ports-and-relay-feed.md`. Read it
first whenever any series here looks wrong or empty: silence from a dead relay
looks identical to a healthy quiet network.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-ports-and-relay-feed.md` (rippled port connection
counts, the relay feed watchdog), `metrics-peers.md`,
`metrics-consensus-ledger-timing.md`, `metrics-consensus-agreement.md`,
`metrics-load.md` and the three `metrics-host-*.md` files.

---

### rx_bps and tx_bps

Receive and transmit throughput on the validator's primary interface.
Unit: bytes per second. Diffed from `rx_bytes` / `tx_bytes`
(`dashboard/server.ts:1587`, `1588`).
Bands: no rules. Outbound settles at whatever this node's peer set costs it,
recorded in `node-profile.md`; sustained multiples of that with peers falling
is the manifest-flood signature (see
`incident-2026-07-31-manifest-flood.md`).
What moves them: peer count and peer appetite, ledger size, a flood of
manifests or other peer-protocol traffic, catch-up after a disconnect.
Rising traffic with *falling* peers is the shape worth reacting to: fewer
connections carrying more each.
Investigate: `metric_history` tx_bps 24h max, then `metric_recent`
peer_count limit 60 over the same window, then `metric_recent`
peer_shed_signal limit 60. The interface these are measured on is chosen by
the relay and reported as `interface_source` — `host_read` verb `resources`
if the reading looks like it is measuring the wrong link.

### rx_pps and tx_pps

Packet rate in each direction.
Unit: packets per second. Diffed from `rx_packets` / `tx_packets`
(`dashboard/server.ts:1589`, `1590`).
Bands: no rules.
What moves them: the same causes as the byte rates, but the *ratio* between
them is the extra information. Bytes flat with packets rising means the
average packet got smaller — chatty small messages rather than bulk ledger
data, which is what a manifest or proposal flood looks like.
Investigate: `metric_history` tx_pps 6h max next to `metric_history` tx_bps
6h max — read them as a pair, neither alone says anything.

### tcp_retrans_per_sec

TCP segments retransmitted per second.
Unit: segments per second. Diffed from the cumulative `tcp_retrans_segs` in
`/proc/net/snmp` (`dashboard/server.ts:1591`).
Band (`dashboard/config/rules.yaml`): 50 or above for 60s warns. This was
raised from 10 in the 2026-04-27 audit because the metric is absolute, not a
share of segments sent, so a busy validator can sit at 10/s on a healthy
path. Under 1/s is unremarkable.
What moves it: packet loss on the local path — NIC fault or driver problem,
a congested upstream link, a bad cable or switch port, or a hypervisor-level
network issue if virtualised. Peers experience it as degraded service and
may disconnect.
Investigate: `metric_history` tcp_retrans_per_sec 24h max, then
`metric_history` peer_latency_p90 24h avg over the same window — path loss
usually shows in both. Then `metric_recent` peer_count limit 60 for whether
peers actually left. `host_read` verb `resources` for interface counters.

---

## Collected, displayed, never stored as a series

The relay sends these and the dashboard broadcasts them to the browser, but
nothing calls `writeMetric` on them. There is no history, and asking for them
through `metric_history` or `metric_recent` fails — the read routes only
serve names in `VALID_METRICS` (`dashboard/server.ts:4018`). Do not name any
of these in an investigation plan.

- `rx_errors`, `tx_errors`, `rx_drops`, `tx_drops` — interface error and
  drop counters, cumulative.
- `tcp_resets_per_sec` — computed as a rate by the dashboard
  (`dashboard/server.ts:3948`) and broadcast, but never written.
- `monthly_used_bytes`, `monthly_cap_bytes`, `monthly_pct` — the monthly
  bandwidth ledger. Kept in its own table and served by the `bandwidth` read
  route, not as a metric series.
- `interface`, `interface_source`, `interval_sec` — context about the
  measurement, not measurements.

To see any of these, read the live values through `host_read` verb
`resources` rather than pretending a series exists.
