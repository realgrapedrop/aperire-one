---
title: Agreement and missed validations
tags: [consensus, agreement, missed validations, signing, agreement_pct, agreement_pct_1h, missed_validations_1h]
last_reviewed: 2026-08-21
---

# Metric reference — agreement and missed validations

Every series the dashboard writes about whether this validator signed with
the network, and what it missed when it did not. Derived by reading the
dashboard source, not from recall. Each entry cites the line that writes it,
so any claim here can be checked.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-consensus-ledger-timing.md` (close time, converge
time, validation rate), `metrics-load.md` (rippled load, amendment block,
version drift), `metrics-validator-registry.md` (how the network sees this
validator), `metrics-peers.md`, `metrics-traffic.md`,
`metrics-ports-and-relay-feed.md` and the three `metrics-host-*.md` files.

**How to use the citations.** `dashboard/server.ts:325` means the write lives
at that line of that file in this repository. `dashboard/config/rules.yaml`
holds the alert thresholds; those are the operator's own settings and are the
only bands the system acts on. Where a band is stated with no rule behind it,
it is a reading guide, not a trigger, and it is marked as such.

---

## Agreement

### agreement_pct

Share of ledgers in the rolling hour this validator signed with the network.
Unit: percent, 0-100. Written once a minute (`dashboard/server.ts:321`) from
the in-memory `agreementHistory` window, and *only* when `isValidatorNode()`
is true and the window has at least one entry. On a stock node the series is
absent by design — a node that never proposes has nothing to agree with, and
writing 0% there turned a healthy host into a permanent critical alert.
Ledgers that closed during an admin-connection gap are excluded: a miss
nobody could observe is not a miss.
Band: healthy is 100. No alert rule keys on this name — the rules use
`agreement_pct_1h`, which is written from the identical computation on the
same line pair. Read either; alert on the other.
What moves it: see `agreement_pct_1h`.
Investigate: prefer `agreement_pct_1h` for anything an alert mentions.

### agreement_pct_1h

The same number as `agreement_pct`, under the name the alert rules and the
knowledge library expect (`dashboard/server.ts:325`). The duplicate exists
because five rules were written against this name while only the other one
was served, and the two lists have no link.
Unit: percent, 0-100.
Bands (`dashboard/config/rules.yaml`): below 95 for 60s pages; below 97 for
60s is critical; below 99 for 120s warns. Healthy is 100 with rare dips.
Below 95 sustained puts UNL inclusion at risk, which is why the page tier
exists here and almost nowhere else.
What moves it: proposals that never arrived (peer connectivity), our votes
arriving late (CPU saturation or job-queue lag), sync lag behind ledger
replay or disk, or disagreeing with the majority on an amendment vote.
It is nearly always downstream of a more specific signal — read this to size
the problem and read something else to locate it.
Investigate: `agreement_window` with `since_ms` for the per-ledger
signed/not-signed record, then `missed_ledgers` limit 50 for each miss with
the peer count and server state captured at that moment, then `alerts` with
`since_ms` covering the window to see what else fired, then `node_ledgers`
around the first miss for close intervals. If the misses cluster in time,
`metric_recent` cpu_busy_pct and `metric_recent` peer_count over the same
window separate "we were busy" from "we were alone".

### missed_validations_1h

Ledgers in the rolling hour this validator did not sign.
Unit: count. Written once a minute (`dashboard/server.ts:330`), and written
*even when zero* — an alert rule only advances or resolves on a fresh sample
of its own metric, so a series that stopped at the last miss would leave the
alert firing forever.
Bands (`dashboard/config/rules.yaml`): 6 or more for 60s is critical, 3 or
more for 120s warns. 0 is healthy.
What moves it: identical causes to `agreement_pct_1h`. The value of the
count over the percentage is that it is concrete in an incident write-up —
"three missed" is actionable where "99.7%" is not.
Investigate: `missed_ledgers` limit 50 first — it carries every miss on
record with `validations_seen`, `trusted_unl`, `peer_count` and
`server_state` as they were at the miss, which is the context the percentage
throws away. Then `agreement_window` since_ms, then `alerts` since_ms.

### A miss that repeats at the same time each day

Measured on a lab validator: one to three ledgers missed together (usually
two), once a day, at the same clock time to within about fifteen minutes,
on seven consecutive days. `validations_seen` on the missed ledgers sat in
the normal 114-115 range (the network validated them, this node did not),
and the bridge's own stream-rate log held steady through the gap, validations
still arriving while no ledger closed and nothing was forwarded. That
combination is the signature of the node itself stalling for a few seconds,
not a stream or bridge problem.

Read `missed_ledgers` across several days before chasing a single miss. A
pattern clustered at the same wall-clock time points at a scheduled
contender on the host, for example log rotation, a backup, a provider-side
snapshot, or the can-delete window described in
`rotation-window-and-advisory-delete.md`, rather than at peer connectivity or
a bug in agreement counting. Confirm with `metric_recent` cpu_busy_pct and
peer_count over the same window: if both read ordinary, the stall is not a
resource story on this host, and the next thing to check is what else is
scheduled at that hour.
