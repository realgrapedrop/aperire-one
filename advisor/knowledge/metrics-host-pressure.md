---
title: Kernel pressure stall on the host
tags: [pressure, psi, stall, contention, pressure_cpu, pressure_memory, pressure_io]
last_reviewed: 2026-08-21
---

# Metric reference — kernel pressure stall on the host

Kernel Pressure Stall Information for CPU, memory and I/O on the host the
dashboard runs on.

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
`metrics-host-process-and-disk.md` (the rippled process, NuDB),
`metrics-consensus-ledger-timing.md`, `metrics-consensus-agreement.md`,
`metrics-load.md`, `metrics-peers.md`,
`metrics-traffic.md` and `metrics-ports-and-relay-feed.md`.

---

### pressure_cpu, pressure_memory, pressure_io

Kernel Pressure Stall Information: the share of the last 10 seconds in which
at least one task was stalled waiting for that resource.
Unit: percent, 0-100. Parsed as the `some avg10` value from
`/proc/pressure/{cpu,memory,io}` (`readPressureSome`,
`dashboard/server.ts:3076`), written at `dashboard/server.ts:388-390`.
**A missing PSI file degrades to 0, silently** — on a kernel older than 4.20
or with PSI disabled, these read a flat 0 that is indistinguishable from a
healthy host. Confirm PSI exists before treating 0 as reassurance.
Bands: no rules on any of the three.
Why they beat the utilisation metrics: utilisation says how busy a resource
was; pressure says whether anything was *waiting*. A host at 70% CPU with
zero CPU pressure is fine. A host at 70% with 40% pressure is not. `pressure_io`
in particular catches disk stalls that `cpu_busy_pct` hides entirely,
because iowait is folded into idle there.
What moves them: the same causes as the matching utilisation metric, but
they move earlier and they move when the bottleneck is contention rather
than volume.
Investigate: `metric_history` pressure_io 6h max alongside
`metric_history` cpu_iowait_pct 6h max; then `metric_history` pressure_cpu
6h max next to `metric_history` cpu_busy_pct 6h max. Where pressure moves
and utilisation does not, the constraint is contention. Then `host_read`
verb `disk` or `resources` as the pair indicates.
