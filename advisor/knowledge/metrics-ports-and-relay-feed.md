---
title: TCP connections, rippled ports and the relay feed
tags: [ports, connections, sockets, relay feed, relay, tcp_established, http_rpc_conn, admin_ws_conn, ws_public_conn, relay_feed_age_s]
last_reviewed: 2026-08-21
---

# Metric reference — TCP connections, rippled ports and the relay feed

TCP connection counts on the host and on each rippled port, plus the watchdog
on the relay feed itself. Every series in this file except `relay_feed_age_s`
originates in the relay on the validator host, arrives over the ingest
WebSocket as a `net_stats` push (`relay/contract.go`, `NetStatsPayload`).

**Written only when the relay has pushed.** `sampleNetworkMetrics` skips this
whole block when no push has arrived (`dashboard/server.ts:1585`), because
storing zeros that mean "unknown" is worse than storing nothing. Every one of
these series therefore goes *silent* when the relay dies, with no other
signal — which is exactly what `relay_feed_age_s` exists to make visible.

**Budget the recipes.** Privileged host reads are capped at **three per
question**, not per round, so a recipe chaining two leaves exactly one for
whatever the answer turns up. Dashboard reads are cheaper: four per round,
twelve per question. Prefer them.

Companion files: `metrics-traffic.md` (throughput, packet rates, TCP
retransmits), `metrics-peers.md`, `metrics-consensus-ledger-timing.md`,
`metrics-consensus-agreement.md`, `metrics-load.md` and the three
`metrics-host-*.md` files.

---

### tcp_established

Open TCP connections on the host right now.
Unit: count, instantaneous (not a rate — this field is a gauge in
`/proc/net/snmp` and is stored as-is, `dashboard/server.ts:1592`).
Band: no rule. It counts every connection on the host, not only rippled's,
so on a co-hosted box it includes everything else running there.
What moves it: peer count, RPC and WebSocket clients, anything else on the
host. A climb with the four port-specific counters flat is something outside
rippled.
Investigate: `metric_history` tcp_established 24h max, then the four port
counters below to attribute it, then `host_read` verb `sysctl-relevant` if
it is approaching a connection-table limit.

### http_rpc_conn, admin_ws_conn, ws_public_conn

Concurrent established connections on each rippled port, counted by the
relay from `/proc/net/tcp` and `/proc/net/tcp6` filtered by local port
(`dashboard/server.ts:1593-1595`). Ports are auto-detected from
`rippled.cfg` at relay startup and can be overridden in `relay.conf`.
Unit: count each, instantaneous. Written only when the field is a number, so
a relay that could not determine a port leaves a gap rather than a zero.
Bands: no rules.
What each means: `http_rpc_conn` is JSON-RPC clients, `admin_ws_conn` is the
admin WebSocket — the dashboard's own bridge is normally one of these, so a
drop to zero there means the dashboard lost its link to rippled —
`ws_public_conn` is public WebSocket subscribers.
**Topology caveat.** These are host-namespace counts. If rippled runs in a
container, the relay reading the host namespace may see none of them. A
reading of zero is therefore ambiguous between "nobody is connected" and
"the relay cannot see this". `peer_conn` exists precisely to avoid that
ambiguity for peers; these three have no such fallback.
Investigate: `metric_recent` admin_ws_conn limit 60 when consensus data
looks stale — a lost admin link explains missing agreement records. Then
`host_read` verb `show-config` to confirm which ports are configured, then
`host_read` verb `unit-status`.

### relay_feed_age_s

Seconds since the relay last delivered host-network telemetry.
Unit: seconds. Written on **every** 10s tick regardless of whether a push
arrived (`dashboard/server.ts:1544`) — that unconditional write is the whole
design. When the relay has never pushed since this process started, the
value falls back to the dashboard's own uptime, so an absent relay still
trips the alert once uptime passes the threshold.
Band (`dashboard/config/rules.yaml`): 60 or above for 60s is critical. The
60s duration on top of the 60s threshold tolerates the relay's reconnect
backoff, which caps at 60s, so a brief dashboard restart does not false-fire.
Critical rather than page on purpose: this is a monitoring-visibility outage,
not a consensus emergency. The relay is read-only and the validator is
unaffected by its death.
What moves it: the relay process not running (crashed, OOM-killed, or never
started), a reboot where the relay was not enabled as a service, the unit
stopped or disabled, an ingest port or token mismatch after a config change,
or a broken network path in a split deployment.
**Read this first whenever any relay-fed series looks wrong or empty:** the
port counters above, and every rate in `metrics-traffic.md`. They all go
silent together when the relay stops, and silence looks identical to a
healthy quiet network.
Investigate: `metric_recent` relay_feed_age_s limit 60 — a sawtooth is
normal, a monotonic climb is the relay being gone. Then `host_read` verb
`unit-status` for the relay unit, then `host_read` verb `journal` lines 60
for why it stopped. The operator-side fixes are
`sudo systemctl status aperire-relay`,
`sudo systemctl enable --now aperire-relay`,
`sudo journalctl -u aperire-relay -n 50 --no-pager`, and confirming
`auth_token` in `relay.conf` matches `RELAY_TOKENS` in the dashboard's
environment file.

**Every one of those runs on the host of the node the metric came from, and
saying which host that is, by name, is part of the advice.** The relay is
co-located with the node it reports on; the operator reading the alert is
often somewhere else — on an aggregator page, or on a peer's view of a
different box. An answer that says only "run `systemctl status
aperire-relay`" gets run wherever that operator is sitting. That happened:
the command went to an aggregator, which has no relay by design, and the
"unit not found" reply read as a second, worse fault. When the subject of the
question is a peer, name the peer's host in the sentence that carries the
command, and say plainly that the box you are being asked from is the wrong
place to run it.

---

## Collected, displayed, never stored as a series

The relay sends these and the dashboard broadcasts them to the browser, but
nothing calls `writeMetric` on them. There is no history, and asking for them
through `metric_history` or `metric_recent` fails — the read routes only
serve names in `VALID_METRICS` (`dashboard/server.ts:4018`). Do not name any
of these in an investigation plan.

- `tcp_time_wait`, `socket_count` — instantaneous socket-table gauges.
- `peer_connections` — the relay's own host-side peer count. Deliberately
  unused; see `peer_conn` in `metrics-peers.md` for why.

To see any of these, read the live values through `host_read` verb
`resources` rather than pretending a series exists.
