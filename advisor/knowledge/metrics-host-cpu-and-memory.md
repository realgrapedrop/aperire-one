---
title: Host CPU, memory and swap
tags: [host cpu, memory, swap, ram, cpu_busy_pct, cpu_iowait_pct, mem_used_pct, swap_used_pct]
last_reviewed: 2026-08-21
---

# Metric reference — host CPU, memory and swap

CPU utilisation, memory and swap on the host the dashboard runs on.

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

Companion files: `metrics-host-pressure.md` (kernel pressure stall),
`metrics-host-process-and-disk.md` (the rippled process, NuDB),
`metrics-consensus-ledger-timing.md`, `metrics-consensus-agreement.md`,
`metrics-load.md`, `metrics-peers.md`,
`metrics-traffic.md` and `metrics-ports-and-relay-feed.md`.

---

### cpu_busy_pct

Share of CPU time not spent idle, across all cores.
Unit: percent, 0-100. Computed by diffing `/proc/stat` between two 5s reads
(`readCpu`, `dashboard/server.ts:3010`) and written once a minute
(`dashboard/server.ts:382`). **iowait is folded into idle** for this figure,
so a host stalled on disk reads as *low* busy here, not high — that case is
what `cpu_iowait_pct` and `pressure_io` are for. Steal time is measured but
never stored.
Bands (`dashboard/config/rules.yaml`): 95 or above for 300s is critical, 85
or above for 120s warns.
What moves it: heavy ledger replay after a disconnect, job-queue drain,
another process competing on a shared host, too few cores for current load.
Sustained saturation means consensus messages are not processed in time and
agreement falls — but tail latency moves first, so this is an early signal
only if you are watching it.
Investigate: `metric_history` cpu_busy_pct 6h max, then `metric_recent`
rippled_cpu_pct limit 60 to confirm rippled is the consumer rather than a
neighbour, then `metric_history` load_factor 6h max, then `host_read` verb
`resources` for the live per-process picture.

### cpu_iowait_pct

Share of CPU time waiting on I/O.
Unit: percent, 0-100. Same `/proc/stat` diff (`dashboard/server.ts:383`).
Band: no rule. Read it as the counterpart to `cpu_busy_pct`: because iowait
is folded into idle above, a disk-bound host shows a low busy figure and a
high figure here, and reading only the first would say the host is fine.
What moves it: NuDB compaction or online delete, a slow or failing disk, a
noisy neighbour on shared storage, ledger replay.
Investigate: `metric_history` cpu_iowait_pct 6h max, then `metric_history`
pressure_io 6h max — pressure is the better signal because it measures
stall, not occupancy. Then `host_read` verb `disk`.

### mem_used_pct

Host memory in use, as `(MemTotal - MemAvailable) / MemTotal`.
Unit: percent, 0-100. From `/proc/meminfo` (`readMemAndSwap`,
`dashboard/server.ts:3039`), written at `dashboard/server.ts:385`.
Using `MemAvailable` rather than `MemFree` is the correct choice — page
cache is not pressure — so this number is already the honest one.
Bands (`dashboard/config/rules.yaml`): 90 or above for 60s is critical, 80
or above for 120s warns.
What moves it: rippled's working set growing with peer count and replay
activity, a leak in a recent build, another process on a shared host,
simply too little RAM for the workload. At sustained 90% the OOM killer is
one spike away from terminating rippled, and recovery costs a restart plus a
ledger reload — minutes of downtime.
Investigate: `metric_recent` rippled_rss_pct limit 60 to confirm rippled is
the consumer, then `metric_history` mem_used_pct 7d avg for whether this is
a slow climb (a leak) or a step (a workload change), then `host_read` verb
`resources`, then `host_read` verb `journal` lines 60 for prior OOM events.

### swap_used_pct

Swap in use, as `(SwapTotal - SwapFree) / SwapTotal`.
Unit: percent, 0-100. Same `/proc/meminfo` read
(`dashboard/server.ts:386`). 0 when the host has no swap configured.
Bands (`dashboard/config/rules.yaml`): 50 or above for 60s is critical, 5 or
above for 600s warns.
**The warn threshold is 5, not 0, and the reason is worth knowing.** It was
`> 0` for 300s, which sounds cautious and is not. Linux parks a little in
swap and never reclaims it — shmem and tmpfs pages nothing is waiting on. On
this host that residue is under a megabyte of sixteen gigabytes, and the rule
fired on it continuously for weeks. A rule that is always firing reports
nothing, and the operator learns to scroll past the one that matters. It also
reported the real event no better: when this host genuinely swapped, climbing
to 47.8% over twenty hours, `> 0` was already firing and said nothing new.
What moves it: memory pressure forcing pages out, a high `vm.swappiness`, a
neighbour consuming RAM. Any *active* swapping on a validator is a problem —
disk is orders of magnitude slower than RAM and rippled's hot path becomes
synchronous with it. A validator in swap misses validations while CPU and
memory headlines still look fine.
Investigate: `metric_history` swap_used_pct 7d max for whether this is
residue or a climb, then `metric_history` mem_used_pct 7d max (it is usually
the driver), then `host_read` verb `sysctl-relevant` for `vm.swappiness`.
Distinguish stale residue from active swapping before acting — the field
guide's swap section covers `swapoff` and the trap in it.

---

## Collected, displayed, never stored as a series

`pushSystem` gathers considerably more than it persists. These reach the
browser but have no history, and naming them in `metric_history` or
`metric_recent` fails — the read routes serve only names in `VALID_METRICS`
(`dashboard/server.ts:4018`).

- `cpu.steal_pct`, `cpu.cores`, `cpu.load_1m`, `cpu.load_5m`, `cpu.load_15m`
- `memory.used_bytes`, `memory.total_bytes`, `swap.used_bytes`,
  `swap.total_bytes` — only the percentages are stored

Read the live values with `host_read` verb `resources` or `disk` instead of
implying a history exists.
