---
title: The rippled process and NuDB on disk
tags: [rippled process, nudb, online_delete, disk, rippled_cpu_pct, rippled_rss_pct, nudb_size]
last_reviewed: 2026-08-21
---

# Metric reference — the rippled process and NuDB on disk

The rippled process's own CPU and memory, and the size of the node database
on disk.

**Source correction, because it is easy to get wrong.** These do not come
from the relay and do not come from node_exporter. The dashboard reads
`/proc` and `statfs` directly, in its own process, every 5s
(`pushSystem`, `dashboard/server.ts:3426`, `3509`). The relay's
`SystemPayload` type exists in the contract but is not the source of these
series — note the shape does not even match: the relay declares
`pressure_cpu_some_pct` at the top level while the dashboard writes from a
nested `pressure.cpu` it built itself (`dashboard/server.ts:3475`).

**Cadence mismatch, and it matters.** `pushSystem` refreshes the readings
every 5s, but only one snapshot a minute is persisted, by
`sampleSystemHistoryMetrics` (`dashboard/server.ts:342`, `372`). So each
stored point is an *instant*, not a minute's average — a 20-second spike
between two samples is invisible in this history even though the browser saw
it live. Use `max` on `metric_history` and expect this history to understate
short excursions.

**Whose host.** These describe the machine the *dashboard* runs on. In the
co-located deployment that is the validator host and the readings are what
they appear to be. In a split deployment they describe the monitoring box,
and only `rippled_cpu_pct` / `rippled_rss_pct` would even find a process to
measure. Confirm the topology before drawing a conclusion about the
validator from this file.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-host-cpu-and-memory.md` (CPU, memory, swap),
`metrics-host-pressure.md` (kernel pressure stall),
`metrics-consensus-ledger-timing.md`, `metrics-consensus-agreement.md`,
`metrics-load.md`, `metrics-peers.md`, `metrics-traffic.md` and
`metrics-ports-and-relay-feed.md`.

---

### rippled_cpu_pct

CPU consumed by the rippled process itself.
Unit: percent, and **it can exceed 100** — the figure is multiplied by core
count so a fully busy multi-core rippled reads the way `top` reports it
(`readRippledProcess`, `dashboard/server.ts:3214`, written at
`dashboard/server.ts:393`). On a 4-core host, 400 is fully saturated.
Computed by diffing the process's `utime + stime` against total jiffies
between two 5s reads. Zero when no rippled process is found, which on a
split deployment is the normal case.
Band: no rule.
What moves it: the same load that moves `cpu_busy_pct`, but this attributes
it. The pair is the diagnosis: host CPU high and this low means the
competition is elsewhere on the box.
Investigate: `metric_recent` rippled_cpu_pct limit 60 beside
`metric_recent` cpu_busy_pct limit 60, then `host_read` verb `resources`.

### rippled_rss_pct

rippled's resident memory as a share of host memory.
Unit: percent, 0-100. `VmRSS` from `/proc/<pid>/status` divided by
`MemTotal` (`dashboard/server.ts:397-399`). Expressed as a share rather than
bytes so it can overlay `rippled_cpu_pct` on one axis. Written only when
both the RSS and the memory total are readable.
Band: no rule.
What moves it: peer count, ledger replay, cache configuration, `node_size`.
A steady climb across days with no workload change is the shape of a leak.
Investigate: `metric_history` rippled_rss_pct 7d avg for the trend, then
`metric_history` mem_used_pct 7d avg — if this is flat while host memory
climbs, rippled is not the consumer. Then `host_read` verb `resources`.

### nudb_size

Total bytes of the rippled data directory.
Unit: bytes. Measured by a recursive directory walk once a minute
(`sampleNudbSize`, `dashboard/server.ts:448`, called from the 60s tick at
`dashboard/server.ts:337`), summing every regular file and skipping entries
it cannot stat rather than aborting. Not written at all when
`RIPPLED_DATA_PATH` is unset, and a failed walk logs and leaves a gap.
Where the dashboard's account cannot open the store, the Advisor's own
reading (taken through the wrapper) is recorded instead, stamped with when the
Advisor took it, into this series and into `nudb_size_advisor`, which the
growth and free-days figures on such a host are fitted from. A reading older
than three minutes, or of a different directory, is dropped.
Band: no rule.
What moves it: ledger accumulation, and `online_delete` pruning cutting it
back. On a pruned validator the series is a sawtooth, which is why the
System tab shows a 24-hour *peak* rather than a growth rate — the annualised
rate oscillates around zero on a pruned database and misleads.
The derived figures the dashboard computes from this series
(`nudb_peak_bytes_24h`, `mount_free_days_est`, `dashboard/server.ts:3453`)
are broadcast to the browser but are not metrics; they cannot be charted.
Investigate: `metric_history` nudb_size 7d max for the sawtooth envelope —
a rising floor between troughs means pruning is not keeping up. Then
`host_read` verb `disk` for actual free space, then `host_read` verb
`show-config` for the `[node_db]` `online_delete` and `advisory_delete`
settings.

---

## Collected, displayed, never stored as a series

`pushSystem` gathers considerably more than it persists. These reach the
browser but have no history, and naming them in `metric_history` or
`metric_recent` fails — the read routes serve only names in `VALID_METRICS`
(`dashboard/server.ts:4018`).

- the entire `disk` block: `used_pct`, `used_bytes`, `total_bytes`, `mount`.
  **Disk fullness has no series and no alert rule.** `nudb_size` is the only
  storage series, and it measures the data directory, not the filesystem.
- `oom_kills`, `disk_io`, `clock`
- `host.uptime_s`, `host.entropy_avail`, `host.inode_usage_pct`,
  `host.rippled_uptime_s`
- `get_counts` and `get_counts_canonical` — rippled's object counters
- `node_db_cfg`, `shard_count`

Read the live values with `host_read` verb `resources` or `disk` instead of
implying a history exists.
