# Metric reference — peers

Everything the dashboard records about who this node is connected to. All
eight series are written every 10s by `sampleNetworkMetrics`
(`dashboard/server.ts:403`, `1532`) from `snapshot.peers`, which the admin-RPC
`peers` call refreshes every 15s (`dashboard/server.ts:3809`). The sampler is
faster than its source, so consecutive points can repeat the same reading —
a flat stretch of 10-20 seconds is the poll cadence, not a frozen network.

The whole block is skipped when the peer list is empty, so "no peers" appears
as a gap in these series rather than a run of zeros. `peer_count == 0` in the
data means rippled reported zero peers, which is different from rippled not
answering at all.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: the two `metrics-consensus-*.md` files, `metrics-load.md`,
`metrics-validator-registry.md`, `metrics-traffic.md`,
`metrics-ports-and-relay-feed.md` and the three `metrics-host-*.md` files.

---

### peer_count

Connected peers, inbound plus outbound.
Unit: count. `snapshot.peers.length` (`dashboard/server.ts:1557`), from
rippled's own peer list — not the relay, and not a host port scan.
Bands (`dashboard/config/rules.yaml`): `== 0` for 30s pages, below 5 for 60s
is critical, below 10 for 120s warns. 15-30 is healthy on a node running the
default `peers_max = 21`; more peers waste bandwidth without widening
consensus reach. Do not raise the warn threshold above about 12 — a node at
`peers_max = 21` normally hovers in the mid-teens to low twenties and you
would be alerting on ordinary operation.
What moves it: a link outage or firewall change, `[ips]` / `[ips_fixed]`
edits, a restart (the ring rebuilds over minutes), upstream saturation, or
the network shedding us. A fall here often precedes an agreement fall.
Investigate: `metric_history` peer_count 24h avg for the shape, then
`metric_recent` peers_outbound limit 60 and `metric_recent` peers_inbound
limit 60 — the total falls identically whichever direction went, and the
split is the whole diagnosis. Then `metric_recent` peer_shed_signal limit 60
for the verdict, then `host_read` verb `show-config` to check `[ips_fixed]`,
and `host_read` verb `node-log` lines 200 for disconnect reasons.

### peers_inbound and peers_outbound

The same list split by who dialled whom. `p.inbound` counted true and false
(`dashboard/server.ts:1558`, `1559`).
Unit: count each.
Bands: no rules key on either directly; they feed `peer_shed_signal`, which
does. A healthy node carries both, with outbound roughly matching the
`[ips_fixed]` and seed entries it dials and inbound varying with how
reachable the peer port is from outside.
What moves them, differently: outbound falls when peers we dialled go away
or our egress breaks. Inbound falls when we become unreachable — a firewall
change, a NAT expiry, a peer port that stopped listening. Both falling at
once points at this host.
Investigate: `metric_recent` on both at limit 60, then `metric_recent`
peer_shed_signal, then `host_read` verb `show-config` for the peer port and
`[ips_fixed]`, then `host_read` verb `sysctl-relevant` if the loss looks
like connection-table exhaustion.

### peers_insane

Peers rippled has judged not sane — its own word for a peer whose ledger
view it does not trust.
Unit: count. Every peer whose `sanity` field is a string other than `sane`
(`dashboard/server.ts:1560`).
Band: no rule. 0 is the normal state. A handful transiently during network
stress is ordinary; a persistent count means we are holding connections that
contribute nothing to consensus while occupying peer slots.
What moves it: peers that are behind, forked, or catching up.
Investigate: `metric_history` peers_insane 24h max, then `metric_recent`
peer_count limit 60 over the same window to see whether the sane share fell
while the total held — the total hides this completely.

### peer_shed_signal

Which way a peer loss points, as a verdict rather than a count.
Unit: enum. 0 nothing unusual, 1 the network shed us, 2 our own box.
Written every 10s (`dashboard/server.ts:1561`) by `peerShedVerdict`
(`dashboard/lib/peer-shed.ts:40`), which compares inbound and outbound now
against the average of the earlier half of the window and uses total
throughput (`rx_bps + tx_bps`) as the tie-breaker. A direction counts as
fallen at a third gone (`DROP = 0.33`).
Bands (`dashboard/config/rules.yaml`): 1 or above for 600s warns, 2 or above
for 600s is critical. Ten minutes on both, because the classifier is
deliberately conservative but one sample should still not page anyone.
The exact shapes: **1** needs outbound down, inbound holding, and throughput
up more than 10% — peers we dialled went away, peers dialling us did not,
and the ones left are carrying more. That is the 31 July signature. **2**
needs both directions down with throughput within 10% of baseline, which
nothing outside this host would do.
**0 means "no verdict", not "healthy".** It returns 0 when there is no
baseline, when either prior direction was zero, when fewer than three points
exist in the earlier half, and when the shape matches neither pattern. A
classifier of this kind fails silently in the worst way, so never read a 0
as evidence of health — read `peer_count` for that.
Investigate: `metric_recent` peer_shed_signal limit 60, then `metric_recent`
peers_outbound and peers_inbound at the same limit to see the legs, then
`metric_history` tx_bps 6h avg to confirm the throughput leg the verdict
rests on. If the verdict is 1, the next question is external and local
metrics cannot answer it — `public_ledger` at the current index confirms the
network is advancing without us.

### peer_latency_p50 and peer_latency_p90

Median and 90th-percentile round-trip latency across connected peers.
Unit: milliseconds. Computed by linear interpolation over the sorted
per-peer `latency` values (`dashboard/server.ts:1578`, `1579`), skipping
peers that report no latency or a negative one. Written only when at least
one peer reported a usable value.
Bands: no rules, and no number that is healthy everywhere. Compare p50 against
what this node normally holds, recorded in `node-profile.md`. A step change
that then holds is the finding; a plateau nobody has explained is still worth
recording there as the current baseline rather than read as a fault every
time it is seen.
What moves them: peer set composition (a geographically distant peer set
raises both), upstream congestion, local NIC or virtualisation problems.
p90 rising while p50 holds means a few bad peers; both rising together means
the path or the host.
Investigate: `metric_history` peer_latency_p50 7d avg and
`metric_history` peer_latency_p90 7d avg together — the pair is the signal,
either alone is not. Then `metric_history` tcp_retrans_per_sec 24h max for a
path-loss explanation, then `host_read` verb `resources`.

### peer_conn

Connected peers again, under the name the Network tab's connections panel
uses (`dashboard/server.ts:1570`).
Unit: count. Identical value to `peer_count` and sourced the same way.
The duplication is deliberate and the reason matters: its three siblings in
that panel (`http_rpc_conn`, `admin_ws_conn`, `ws_public_conn`) come from the
relay's host-side scan of `/proc/net/tcp`, and the relay contract has a
`peer_connections` field that would fit here — but it is not used. The
dashboard's admin-RPC link to rippled exists in both deployment shapes and
sees the real peer connections even when rippled runs in a container, where
the relay, reading only the host network namespace, sees none. So this one
series in the panel comes from a different source than its neighbours, on
purpose, because it is the only source correct on every topology.
Band: read `peer_count`'s bands; they are the same number.
Investigate: use `peer_count`. This name exists for the panel.
