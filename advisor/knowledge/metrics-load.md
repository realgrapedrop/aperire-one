---
title: rippled load, amendment block and version
tags: [rippled load, job queue, fee escalation, amendment, version, load_factor, jq_trans_overflow, amendment_blocked, node_version_behind]
last_reviewed: 2026-08-21
---

# Metric reference — rippled load, amendment block and version

Every series the dashboard writes about how hard rippled is working and
whether the build it is running has fallen behind. Derived by reading the
dashboard source, not from recall. Each entry cites the line that writes it,
so any claim here can be checked.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-consensus-ledger-timing.md` and
`metrics-consensus-agreement.md` (ledger timing, agreement),
`metrics-validator-registry.md` (how the network sees this validator),
`metrics-peers.md`, `metrics-traffic.md`, `metrics-ports-and-relay-feed.md`,
and the three `metrics-host-*.md` files (CPU, memory, swap, pressure,
rippled process, NuDB).

**How to use the citations.** `dashboard/server.ts:325` means the write lives
at that line of that file in this repository. `dashboard/config/rules.yaml`
holds the alert thresholds; those are the operator's own settings and are the
only bands the system acts on. Where a band is stated with no rule behind it,
it is a reading guide, not a trigger, and it is marked as such.

**Two metrics here are written but cannot be charted.** `amendment_blocked`
and `node_version_behind` are stored on every poll but are absent from
`VALID_METRICS` (`dashboard/server.ts:4018`), which is the allow-list for the
`history` and `recent` read routes. Asking for either through `metric_history`
or `metric_recent` returns `bad_request`. This is a boundary, not an outage —
`test/unit/metric-lists.test.ts` checks that everything *served* is written
and that every *alerted* metric is servable, but deliberately not the reverse.
Read those two from `server_info` through a host read instead.

---

## rippled load

### load_factor

rippled's combined local plus network load multiplier.
Unit: multiplier; 1 is idle baseline. `server_info` is polled every 5s and
each `load_factor` seen is pushed into a per-minute accumulator; once a
minute the mean of that minute is written (`dashboard/server.ts:301`). So a
single 5-second spike is visible but diluted — use `max` aggregation on
`metric_history` when hunting spikes, not the default `avg`.
Bands (`dashboard/config/rules.yaml`): 100 or above sustained 300s pages;
100 or above for 180s is critical; 80 or above for 180s warns. 100 is the
point where rippled is in fee escalation and actively shedding work. The
shipped thresholds were tuned against nine days of a production validator's
history, which is where these shapes come from: idle sits at
1 about 97% of the time, single-minute spikes above 30 happen roughly ten
times a day, and sustained three-minute periods above 80 happen about once
every five days.
What moves it: local CPU or I/O saturation forcing rippled to back off, a
network-wide demand surge, job-queue backlog upstream.
Distinguishing the two: if the load is local, host metrics move with it. If
it is network-wide, they do not.
Investigate: `metric_history` load_factor 6h max, then `metric_recent`
cpu_busy_pct limit 60 and `metric_recent` pressure_io limit 60 over the same
window — both flat during the spike means the load came from the network and
there is nothing local to tune. `host_read` verb `resources` gives the live
picture. `alerts` since_ms shows what else crossed a line at the same time.

### jq_trans_overflow

Transactions rippled dropped because its job queue overflowed.
Unit: count, as rippled reports it in `server_info`. The dashboard stores the
raw field on every 5s poll (`dashboard/server.ts:2045`), coercing with
`Number()` because some builds report it as a string, and skipping the write
entirely on builds that omit the field.
Read a *rise between samples*, not the level — rippled reports this as a
running counter, so a non-zero value can be an old event the node has not
been restarted since.
Band (`dashboard/config/rules.yaml`): above 0 with a 0s duration is critical,
meaning it fires on the first sample past zero with no waiting period.
What moves it: sustained `load_factor` beyond queue capacity, rippled pinned
on CPU and unable to drain, disk I/O backpressure.
Investigate: `metric_recent` jq_trans_overflow limit 200 to see whether the
value is rising or a flat historical residue, then `metric_history`
load_factor 6h max across the same window, then `metric_recent`
pressure_io limit 60, then `host_read` verb `resources`.

### amendment_blocked

Whether rippled has refused to operate because an amendment it does not
understand has activated.
Unit: 1 or 0. Written on every 5s `server_info` poll
(`dashboard/server.ts:2053`), coercing an absent field to 0 rather than
skipping the write — rippled omits the field when false, and a series that
exists only while blocked leaves an operator unable to tell "healthy" from
"not being monitored".
**Not chartable.** Absent from `VALID_METRICS`, so `metric_history` and
`metric_recent` both refuse it. See the note at the top of this file.
Band: any 1 is an emergency. A blocked validator signs nothing.
What moves it: an amendment reaching majority and activating while this node
runs a build that predates it. It is the failure mode that an upgrade
deferred too long ends in.
Investigate: `host_read` verb `node-log` lines 200 — the block is announced
in the log in plain words, and one read settles it. Keep the second host read
for `unit-status` only if the log is inconclusive; the ceiling is three host
reads for the whole question, not per round, so spending two here leaves one.

### node_version_behind

Whether the running build is older than the newest installable upstream
release.
Unit: 1 or 0. Written when the six-hourly upstream poll completes
(`dashboard/server.ts:3645`) and again whenever the running build changes,
without a fetch (`dashboard/server.ts:3578`) — that second path exists
because an operator who had just upgraded kept an amber "update available"
badge for up to six hours next to a node already running the new version.
Pre-releases and drafts are excluded from the comparison.
**Not chartable.** Same boundary as `amendment_blocked` above.
Band: 1 is not an incident on its own. It becomes one when the release being
missed contains a fix this node needs, or when enough time passes that
`amendment_blocked` becomes reachable.
What moves it: an upstream release, or an upgrade on this host.
Investigate: `host_read` verb `unit-status` for the running version, then
the release notes in `releases.md` in this corpus.

