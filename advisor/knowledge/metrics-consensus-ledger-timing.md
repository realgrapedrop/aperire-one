---
title: Ledger timing and consensus cadence
tags: [consensus, ledger timing, validations, close_time, converge_time, txn_count, validation_rate]
last_reviewed: 2026-08-21
---

# Metric reference — ledger timing and consensus cadence

Every series the dashboard writes about ledger timing and consensus cadence:
how long a ledger takes to close, how long rippled says agreeing took, what
was in it, and how many validation messages we saw. Derived by reading the
dashboard source, not from recall. Each entry cites the line that writes it,
so any claim here can be checked.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-consensus-agreement.md` (whether this validator
signed), `metrics-load.md` (rippled load, amendment block, version drift),
`metrics-validator-registry.md` (how the network sees this validator),
`metrics-peers.md`, `metrics-traffic.md`, `metrics-ports-and-relay-feed.md`
and the three `metrics-host-*.md` files.

**How to use the citations.** `dashboard/server.ts:325` means the write lives
at that line of that file in this repository. `dashboard/config/rules.yaml`
holds the alert thresholds; those are the operator's own settings and are the
only bands the system acts on. Where a band is stated with no rule behind it,
it is a reading guide, not a trigger, and it is marked as such.

---

## Ledger timing

### close_time

Wall-clock seconds between one validated ledger closing and the next.
Written on every `ledgerClosed` event (`dashboard/server.ts:1874`) as the
delta between two arrival timestamps the dashboard took itself — it is not
rippled's own reported close time. Samples outside 0.5-30s are discarded
entirely rather than clipped, so clock skew, a missed event or a bridge
restart leaves a *gap* in the series, never a fabricated value.
Band (reading guide, no alert rule): 3-5s is healthy, 5-6s elevated, above
6s means consensus is taking longer than it should.
What moves it: network-wide congestion, a slow or disagreeing UNL member,
local CPU starvation delaying our own proposal, disk latency during replay.
Investigate: `node_ledgers` with `around` the ledger in question and `span`
21 gives per-ledger close intervals and transaction counts straight from
the local record — prefer it over eleven public round-trips. Then
`metric_history` close_time 6h max to see whether the excursion is isolated,
then `metric_history` load_factor 6h max to test the congestion explanation.

### converge_time

How long rippled itself says the last consensus round took.
Unit: seconds. Sourced from `server_info`'s `last_close.converge_time_s`,
written once per validated ledger and de-duplicated by ledger sequence so a
5s poll cadence does not re-record the same round (`dashboard/server.ts:2063`).
Band (reading guide, no alert rule): 2-4s is ordinary. Read it against
`close_time` — converge time is the part of the interval rippled spent
agreeing, so a normal close_time with a rising converge_time means the round
is getting harder while the cadence still holds.
What moves it: disputed transaction sets, a UNL member proposing late,
local job-queue lag delaying our own validation.
Investigate: `metric_history` converge_time 24h max, then `metric_history`
close_time 24h max over the same range, then `node_ledgers` around the peak.

### txn_count

Transactions in one validated ledger, as rippled reported it at close.
Unit: count per ledger. Written on every `ledgerClosed` from `msg.txn_count`
(`dashboard/server.ts:1879`). This is rippled's own headline number, not the
dashboard's per-family tally — the families are counted separately by a
follow-up `ledger` RPC and are cross-checked against this value.
Band: none. There is no healthy or unhealthy transaction count; it is demand.
What moves it: network demand, an NFT mint, an exchange rebalancing, an
attack attempt.
Investigate: `metric_history` txn_count 24h max for the shape, then
`node_ledgers` around a peak for the per-family split of those ledgers,
then `metric_history` load_factor 24h max to see whether demand reached the
fee escalator.

### validation_rate

Validation messages this node observed in the preceding minute.
Unit: count per minute. Written once a minute (`dashboard/server.ts:304`)
from a counter that is reset on each write.
Band: none defined. On a healthy node it tracks UNL size times ledger rate;
a fall with peers holding means messages are not reaching us, and a fall
with peers falling is a connectivity problem, not a consensus one.
What moves it: peer loss, the admin WebSocket dropping us as a slow consumer,
a network-wide stall.
Investigate: `metric_history` validation_rate 6h avg, then `metric_recent`
peer_count limit 60 over the same window, then `metric_recent`
relay_feed_age_s to rule out a monitoring gap being mistaken for a real one.
