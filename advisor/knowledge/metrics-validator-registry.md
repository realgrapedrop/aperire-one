---
title: How the public validator registry sees this validator
tags: [validator registry, xrpscan, propagation, manifest, validator_registry_seen, validator_last_seen_age_s, validator_version_drift]
last_reviewed: 2026-08-21
---

# Metric reference — how the network sees this validator

Every series the dashboard writes from the public validator registry: whether
the network can still see this validator, and what it believes about it.
Derived by reading the dashboard source, not from recall. Each entry cites
the line that writes it, so any claim here can be checked.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-consensus-ledger-timing.md` and
`metrics-consensus-agreement.md` (ledger timing, agreement),
`metrics-load.md` (rippled load, version state), `metrics-peers.md`,
`metrics-traffic.md`, `metrics-ports-and-relay-feed.md`, and the three
`metrics-host-*.md` files (CPU, memory, swap, pressure, rippled process,
NuDB).

**How to use the citations.** `dashboard/server.ts:325` means the write lives
at that line of that file in this repository. `dashboard/config/rules.yaml`
holds the alert thresholds; those are the operator's own settings and are the
only bands the system acts on. Where a band is stated with no rule behind it,
it is a reading guide, not a trigger, and it is marked as such.

---

## How the network sees this validator

The only class of problem a node cannot detect about itself. A validator
that has gone invisible to every other operator still reports itself
proposing, with a full peer list and 100% local agreement, because from the
inside nothing is wrong. These three come from an external registry
(`api.xrpscan.com`), polled every 600s (`dashboard/server.ts:3823`).

An unreadable or empty registry response is discarded without writing
anything (`dashboard/server.ts:3780`) — failing to ask must never be
recorded as "the network cannot see us".

### validator_registry_seen

Whether the public validator registry currently has a record for this
node's master key.
Unit: 1 or 0. Written on each successful registry poll
(`dashboard/server.ts:3783`), and only when this node's validator public key
is known — a stock node writes nothing here.
Band (`dashboard/config/rules.yaml`): below 1 held for 1800s warns.
What moves it: falling out of the registry entirely. Distinct from a stale
record, which is the next metric.
Investigate: `public_validator` with this node's key for the network's own
view, then `metric_recent` validator_last_seen_age_s limit 60, then
`agreement_window` since_ms to check whether we actually stopped signing or
only stopped being listed.

### validator_last_seen_age_s

Seconds since the registry last observed a validation signed by this node.
Unit: seconds. Written from the registry row's `last_seen` timestamp,
floored at 0 (`dashboard/server.ts:3788`).
Band (`dashboard/config/rules.yaml`): above 1800 held for 300s is critical.
A healthy validator is observed continuously, so half an hour is long enough
to ride out a registry hiccup and short enough to matter.
What moves it: we stopped signing; we are signing but our validations are
not propagating; the registry itself is lagging. The first two are the ones
that matter and local agreement cannot tell them apart.
Investigate: `agreement_window` since_ms — if local agreement is 100% while
this climbs, we are signing into a void and the problem is propagation, not
consensus. Then `metric_recent` peers_outbound limit 60, then
`public_validator` with this node's key, then `public_ledger` at the current
index to confirm the network is still advancing.

### validator_version_drift

Whether the version the registry advertises for this node differs from the
version it actually runs.
Unit: 1 or 0. Written when both versions are known
(`dashboard/server.ts:3792`).
Band (`dashboard/config/rules.yaml`): 1 or above held for 86400s warns — a
deliberately long hold at low severity.
What moves it: an upgrade. `last_seen` tracks observed validations while the
advertised version comes from the manifest, so the two legitimately disagree
for a while after a version change. It matters because anyone reading the
registry to decide whether to trust this validator sees the stale one.
Investigate: `public_validator` with this node's key to read what is
advertised, then `host_read` verb `unit-status` for what is running.
