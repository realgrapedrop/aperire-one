# Aperire One Architecture Guide

How the system is structured end-to-end: components, data flows, storage, trust boundaries, and the non-obvious design decisions behind them. For the installer's perspective see the [deployment guide](DEPLOYMENT-GUIDE.md). For running state see the [operational guide](OPERATIONAL-GUIDE.md). For what each number on screen means see the [metrics guide](METRICS-GUIDE.md).

Audience: operators evaluating Aperire One, engineers onboarding to the codebase, and auditors reviewing the trust model. The opinions are here. The commands are in the other three guides.

---

## Logical architecture

Outbound-only by construction. Every connection in the diagram originates inside the perimeter and dials outward. Nothing in the stack accepts an inbound connection from the public internet beyond rippled's peer protocol.

<img src="images/aperire-dashboard-architecture.png" alt="Aperire One architecture: browsers reach aperire-server through the Cloudflare tunnel or the LAN; aperire-server reads rippled over the admin WebSocket; aperire-relay pushes host and network metrics to it; the optional Advisor (advisord + executor) sits beside it; other fleet nodes are read over private tunnels" width="100%">

## Components

Aperire One is three programs and a tunnel. Each has one job. None of them reach into another's responsibilities.

| Component | Language | Process | Role |
|-----------|----------|---------|------|
| **aperire-dashboard** (`dashboard/server.ts`) | TypeScript / Node.js 22 | `aperire-server.service` (systemd) | Rippled admin-WS client, relay ingest endpoint, browser WS fanout, SQLite time-series store, HTTP static asset server. |
| **aperire-relay** | Go (single static binary) | `aperire-relay.service` (systemd) | Reads `/proc` on the validator host, pushes cumulative counters to the dashboard's `/ingest` over WebSocket every 5 s. |
| **cloudflared** | Go (Cloudflare binary) | `cloudflared-aperire.service` (systemd) | Outbound-only QUIC tunnel from the dashboard host to the Cloudflare edge. No inbound ports. |
| **rippled** | C++ | operator-managed | The validator or stock node being monitored. Aperire One is a read-only observer of rippled's admin WS + peer protocol. |
| **aperire-advisord** (optional) | Go | `aperire-advisord.service` (systemd) | The Advisor's agent: loopback-only, read-mostly HTTP surface. Measures the node, evaluates plans, answers questions through a configured language model, performs config-gated public XRPL lookups. Its three write verbs (record an approval, capture a snapshot, start a run) are token-gated. |
| **aperire-executor** (optional) | Go | invoked per run | The Advisor's actor: executes a runbook's named operations through a privilege wrapper, verifies each step against the node, writes the hash-chained action ledger. |

Three packages because three trust boundaries:

- **The dashboard** speaks rippled.
- **The relay** speaks `/proc`.
- **The tunnel** speaks the public internet.

None of them overlap. The optional Advisor adds a fourth boundary with the same discipline: **the agent that reasons and the executor that acts are separate identities**. The agent holds no privilege. The executor accepts only named operations behind per-stage passkey approvals. The dashboard proxies between the browser and both. The full model (approval ceremony, audit ledger, hard boundaries, knowledge and lookup configuration) is in the [Advisor guide](ADVISOR-GUIDE.md).

### Privilege model

**None of these processes runs as root.**

`aperire-relay` is the most privilege-sensitive component because it lives on the validator host. The install script creates a dedicated `aperire-relay` system user with:

- no login shell (`/usr/sbin/nologin`)
- no home directory
- no `sudo` entry
- no Linux capabilities

The relay's entire scope is two things:

- read `/proc` (everything it needs is world-readable, no elevation required)
- dial a single outbound WebSocket to the dashboard

systemd locks the unit further with these hardening directives:

- `NoNewPrivileges`
- `ProtectSystem=strict`
- `MemoryDenyWriteExecute`
- empty `CapabilityBoundingSet`
- no `ReadWritePaths`, so `ProtectSystem=strict` leaves the relay nowhere on disk it can write

The full unit is in [`scripts/install-aperire-relay.sh`](../scripts/install-aperire-relay.sh), which comments the non-obvious directives. The [Relay reference](RELAY-REFERENCE.md#hardening) points there too, rather than repeating a table that can fall behind the unit.

`aperire-dashboard` and `cloudflared` follow the same pattern on their host. Both run as non-root system users with comparable systemd hardening. Nothing in the Aperire One stack needs root, can elevate at runtime, or can write outside its sandbox.

## Deployment shapes

The layout I recommend for a validator: the validator host keeps rippled, the relay, a loopback-only `aperire-server` and the optional Advisor, and opens no Aperire One port; the pane of glass on a separate host reads it over an SSH tunnel it dials itself (`:790x` read API, `:791x` Advisor). Every Aperire One port on the validator is loopback; only `:51235` and `:22` are inbound. The Advisor is one per node and self-contained: its own sealed model key (usable only on that host), its own knowledge corpus, memory and ledger, and an outbound-only connection to the LLM provider. The dashboard routes questions and approvals to the node's own Advisor; it never answers for a node.

<img src="images/aperire-dashboard-architecture-shape-b.png" alt="Recommended split: validator host with rippled, relay, loopback-only aperire-server and the optional Advisor; dashboard host with the pane of glass and the tunnel, reading the validator over an SSH tunnel it dials" width="100%">

Topology and shape-selection guidance live in the [Deployment guide: Pick your shape](DEPLOYMENT-GUIDE.md#pick-your-shape), which is also where the letters are defined: Shape A is co-located, Shape B is the LAN split. The diagrams, the "use when" guidance, and the inbound-port profile for each shape are all there.

## Fleet: watching more than one node

A single node needs none of this. Once you run a second node, one dashboard can become an **aggregator**: one place to watch the whole fleet and run an upgrade on any node from it.

Adding a node does two separate things, and keeping them separate is the point:

- **Seeing a node.** The aggregator reads that node's dashboard and shows it here, labelled by node. It reaches the node over a private tunnel that stays on loopback at both ends (the aggregator dials out, the node opens no port to the network). A node registered only to be *seen* can never be *acted on*.
- **Acting on a node.** When you approve an upgrade on the aggregator with your passkey, that approval is carried to the node's own Advisor, which verifies it and does the work. Each node keeps its own audit trail of what it did. The aggregator only records what it saw, so the node that changed is the node that holds the record.

You join a node with one command, `aperire-fleet-add.sh`. It reads the node's identity, wires up both sides, and pins the node so a tunnel quietly re-pointed at the wrong host is caught instead of trusted. The full walkthrough (the `fleet.yaml` fields, the tunnel, the trust setup) is in the **[Fleet guide](FLEET-GUIDE.md)**.

**One safety rule worth knowing:** a node remembers which dashboard may approve on it the first time it's set up, and refuses any silent change to that afterward. That is what stops a compromised aggregator from quietly redirecting a node's trust.

## Data flows

The hot paths are all WebSocket or outbound QUIC streams. The only polling is two infrequent HTTPS GETs to public XRPL metadata sites for amendment context (flow 5).

### 1. rippled → dashboard (admin WS)

The dashboard dials `ws://<rippled-host>:6006` on startup and `subscribe`s to these streams:

| Stream | Carries |
|--------|---------|
| `ledger` | Every validated ledger close (sequence, close time, txn count, fees, reserves) |
| `validations` | Every validation the node sees, including its own (for agreement %) |
| `server` | State transitions (`proposing` / `full` / `tracking` / `syncing`) |
| `peer_status` | Peer connect / disconnect / sanity changes |
| `manifests` | Validator manifest rotations (UNL key hierarchy signals) |

It also calls a handful of admin commands on a schedule for data that isn't pushed: `server_info`, `peers`, `consensus_info`, `feature`, `fee`, `validator_list_sites`, `validators`, `get_counts`, `ledger`. Cadences range from 2 s (`consensus_info`) to 10 min (`validator_list_sites`). Exact cadences are in `dashboard/server.ts`.

The dashboard reconnects automatically on close with a 3 s backoff.

**Admin-RPC allow-list proxy (recommended).** rippled admin auth is all-or-nothing. A read connection can also `stop` the validator or vote on amendments. Production deployments insert `aperire-rippled-proxy` (`dashboard/rippled-admin-proxy.ts`) between the dashboard and rippled. The dashboard's `RIPPLED_URL` points at the proxy (`ws://127.0.0.1:6007`). The proxy forwards only the read commands above (deny-by-default) and rejects the mutating `feature` vote form, so a compromise of the dashboard process can't escalate to validator control. It's transparent to the dashboard: no code path changes, just the connection target. Setup is in the [hardening guide](HARDENING-GUIDE.md#admin-rpc-allow-list-proxy-recommended).

### 2. aperire-relay → dashboard (`/ingest`)

**At startup** the relay reads `rippled.cfg` once to auto-detect rippled's four ports (HTTP RPC, Admin WS, WS Public, Peer). Those four numbers are held in memory for the life of the process; rippled.cfg is never re-parsed. rippled's PID is not cached. It is re-resolved on every push (from `rippled_pid_file`, or a `/proc/*/comm` scan) so a rippled restart gets picked up automatically.

**Every 5 s** (configurable 1 to 300 s) the relay sends two JSON frames over WebSocket (`net_stats`, then `system`) containing cumulative counters + instantaneous snapshots read from `/proc`:

```text
relay                                   dashboard
──────                                  ─────────
[once at startup]
  parse rippled.cfg → HTTP RPC / Admin WS / WS Public / Peer ports

[every tick]
  resolve rippled PID from pid_file or /proc/*/comm
  read /proc/net/dev (rx/tx bytes+pkts)
  read /proc/net/snmp (TCP retrans etc)
  read /proc/<rippled-pid>/net/tcp + tcp6 (per-port ESTABLISHED counts)
  read /proc/stat (CPU jiffies)
  read /proc/meminfo, /proc/pressure/*
  read /proc/vmstat, /proc/loadavg
  statfs(data_mount)
                  ──────WS push ─────►  handleRelayPush():
                                           diff counters vs prev snapshot
                                           compute rates (bps, pps, retr/s)
                                           accumulate monthly byte totals
                                           persist snapshot for continuity
                                           broadcast('net_stats', …)
                                           writeMetric(...) → SQLite
                                         system frame → kept for pushSystem():
                                           replaces the dashboard's own /proc
                                           reading of CPU/mem/swap/disk/PSI/OOM
                                           broadcast('system', …)
```

**Why `/proc/<rippled-pid>/net/tcp` rather than `/proc/net/tcp`.** When rippled runs in Docker its TCP sockets live in a container-local network namespace invisible to the host's `/proc/net/tcp`. Reading through rippled's PID reads its own netns, the authoritative view regardless of container boundary. Native installs get identical data so there's no regression. See [Port connection monitoring](RELAY-REFERENCE.md#port-connection-monitoring) for the full rationale.

**Cumulative counters, not rates** (for bandwidth/packets/retransmits). The relay ships `/proc/net/dev` values as-is (monotonic counters). The dashboard diffs consecutive pushes to derive bytes/sec, packets/sec, retransmits/sec. That means the first card on the Network tab needs *two* pushes (~10 s) to populate. Per-port connection counts are instantaneous and populate on the first push.

**Monthly budget continuity.** The dashboard persists the last counter snapshot per `node_label` in SQLite (`bandwidth_last_snapshot`), so on restart it knows where the relay left off and keeps accumulating monthly totals correctly instead of starting from zero.

**Auth.** Static bearer token in the `Authorization: Bearer …` header on WS upgrade. The dashboard keeps an allow-list of valid tokens in `RELAY_TOKENS` (env var, comma-separated). Non-matching tokens get 401 before any state is allocated.

### 3. dashboard → browsers (WebSocket)

Browsers connect to `wss://aperire.example.com/ws`. On connect the dashboard sends a snapshot:

```json
{ "type": "snapshot", "data": { "server_info": …, "peers": …, "net_stats": …, "consensus_info": … } }
```

Then a stream of delta messages as state changes: `ledger`, `validations`, `peers`, `net_stats`, `server_info`, `consensus_info`. Each browser gets a full fanout, no per-client filtering. The HTTP route that loads `/index.html` is gated by the `requireAuthGate` middleware, so the WebSocket upgrade only happens for browsers whose preceding page load had a valid session cookie. See the [auth guide](AUTH-GUIDE.md) for the full ceremony.

### 4. Browser history queries (HTTP)

The dashboard's History panels query SQLite via three HTTP endpoints, not the WebSocket. WebSocket is for live state. HTTP is for bucketed aggregates.

| Endpoint | Returns |
|----------|---------|
| `GET /history?metric=<name>&range=<1h\|6h\|12h\|24h\|7d\|30d>` | Time-bucketed averages for one metric across the range |
| `GET /recent?metric=<name>&limit=<N>` | Last N raw samples for seeding live charts on page load |
| `GET /recent-ledgers?limit=<N>` | Last N ledger rows (sequence, close time, txn count) for the ticker |
| `GET /healthz` | Liveness probe (see operational guide) |

### 5. dashboard → xrpscan + xrpl.org (HTTPS, infrequent)

The Governance tab's Amendments table is enriched with two pieces of metadata that rippled's `feature` admin command doesn't carry: the **XLS spec number** (XLS-65 etc., used to cross-reference xrpscan and the spec) and a **one-line description** of what each amendment does.

| Source | Endpoint | Cadence | Used for |
|--------|----------|---------|----------|
| xrpscan | `GET https://api.xrpscan.com/api/v1/amendment` | every 15 min | hash → name + XLS-NN tag (also names amendments rippled returns hash-only for) |
| xrpl.org | `GET https://xrpl.org/resources/known-amendments` | once per 24 h | hash → one-line description (HTML-scraped, parser tolerant to layout drift) |

The xrpl.org refresh also fires opportunistically when the xrpscan poll reveals a hash with no known description, so brand-new amendments get summarised within minutes of appearing on the ballot instead of waiting up to 24 h for the daily tick.

The xrpl.org payload is parsed into `dashboard/knowledge/amendments.yaml` (deterministic hash-sorted). The yaml is committed so fresh checkouts have descriptions on first paint without needing connectivity to xrpl.org at install time. Subsequent runs refresh it in place. Hand-edits are overwritten on next refresh. If you need to maintain custom copy, disable the poller (see [air-gap notes](OPERATIONAL-GUIDE.md#air-gapped-installs)).

Both fetches are best-effort: a 10 to 20 s `AbortSignal` timeout per request, silent skip on failure, existing in-memory + on-disk data still serve the UI. The Governance tab degrades gracefully. Rows lose the XLS pill and the hover popover, but the rest of the table is unaffected.

## Storage

**SQLite (`data/aperire.db`) in WAL mode** via `better-sqlite3`. One process, one file, in-process access. No separate daemon to secure or monitor. The DB lives under `data/`, outside the source tree, so the systemd unit can grant write access to `data/` only and keep `dashboard/` read-only.

- **What's persisted:** ~38 time-series metrics at 1-minute granularity; ledger summary rows (`ledgers`: sequence, close time, txn count, transaction families); a per-ledger agreement record (`agreement`, 2-day buffer, feeding the rolling windows); every missed validation with the node's context at that moment (`missed_ledgers`, never pruned, since misses are rare and the context cannot be reconstructed later); alert lifecycle rows; a per-node bandwidth snapshot for monthly-total continuity; and a per-month bandwidth bucket (`bandwidth_monthly`). Auth tables (users, credentials, sessions) live here too. Total storage for 30-day retention is a few tens of MB.
- **One trap worth knowing:** `ledgers.close_ts` holds rippled's own `ledger_time`, which counts from the **Ripple epoch** (2000-01-01), not the Unix epoch. Its values are ~946,684,800 lower for the same instant. Anything comparing that column against wall-clock time has to cross the offset explicitly. `RIPPLE_EPOCH_S` in `db.ts` exists for that.
- **What's not persisted:** peer list (lives in memory only, every browser snapshot pulls current state), validator list, amendment state. These are re-derived on startup from the next rippled poll.
- **Retention:** pruned in `db.ts` to keep ~30 days of 1-minute rows. Older points are dropped before they accumulate.

**Why SQLite instead of VictoriaMetrics (the original plan):** the case for VM was "the full metric catalog × multi-year retention." The implementation reset that target. Most of the 175 catalog rows are surfaced live through in-browser buffers fed by the WebSocket and never need to be queried from history. The set that *is* persisted is small (a few dozen series), the retention is short (30 days), and the query pattern is trivial (time-bucket averages). A TSDB adds a daemon to run and secure, a query language to learn, and a network endpoint to firewall. SQLite covers it with one library import, and it is a pattern I already run in production elsewhere.

If the persistence story expands later (hundreds of distinct series, multi-year retention, complex downsampling), VM becomes the right path. Until then it isn't warranted.

## Security model

Trust boundaries, listed inside-out.

### Validator host

- **Inbound from internet:** `:51235` (rippled peer protocol) only. That's pre-existing. It's what makes rippled a rippled.
- **Inbound from LAN** (Shape B): `:6006` (rippled admin WS), firewalled to the dashboard host's IP, `admin_ip`-whitelisted in `rippled.cfg` so even someone on the LAN can't issue admin commands from a non-dashboard IP.
- **Outbound:** rippled's peer connections, plus the relay's outbound WS to the dashboard. Nothing else. The relay is deliberately quiet.

The relay's sandbox (systemd directives: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectKernelTunables`, `CapabilityBoundingSet=`, empty `ReadWritePaths`, `SystemCallFilter=@system-service`) reduces the blast radius if the binary is ever compromised to "a process that can read `/proc`, read its own config, and open outbound TCP". No kernel access, no filesystem writes, no privilege escalation. Details in the [Relay reference](RELAY-REFERENCE.md).

### Dashboard host

- **Inbound from internet:** none. `cloudflared` opens an outbound QUIC stream to the Cloudflare edge.
- **Inbound from the operator:** SSH (pre-existing administration path).
- **Listening ports:** `:7800` bound to `127.0.0.1` by default. The Cloudflare tunnel is the only thing that reaches it from outside the loopback. Set `HOST=0.0.0.0` (or a LAN IP) only for Shape B, where the relay on a separate host pushes to the dashboard over the LAN.
- **Outbound:** Cloudflare edge (QUIC, `cloudflared`); Resend (`api.resend.com`) and ntfy (`ntfy.sh` or self-hosted) for alert delivery when configured; xrpscan (`api.xrpscan.com`) and xrpl.org for amendment metadata enrichment (see [data flow 5](#5-dashboard--xrpscan--xrplorg-https-infrequent)). All other outbound is the rippled admin WS (Shape A: loopback; Shape B: LAN to validator host).
- **Sandbox:** the dashboard's systemd unit applies `ProtectSystem=strict` + `ProtectHome=read-only` with narrow `ReadWritePaths` for the SQLite dir and the log dir. `MemoryMax=3G` caps the dashboard's cgroup so a runaway can't OOM the host (`MemoryHigh=2G` throttles first; the figures cover the process plus its database's page cache). Full hardening is detailed in the [operational guide](OPERATIONAL-GUIDE.md).

### Relay → dashboard

- **Transport:** WebSocket. Use `wss://` with a real TLS cert for Shape B over LAN. Loopback `ws://` is fine for Shape A.
- **Authentication:** static bearer token, rotated by adding the new token to `RELAY_TOKENS`, updating the relay config, then removing the old one from `RELAY_TOKENS` (zero-downtime).
- **Authorization:** `/ingest` rejects the WebSocket upgrade with 401 before allocating any state if the token is not in the allow-list.

### Browser → dashboard

- **Transport:** HTTPS + WSS terminated at the Cloudflare edge; QUIC tunneled to `cloudflared` on the dashboard host; localhost HTTP/WS to Node.js.
- **Authentication:** passwordless WebAuthn / passkeys (FIDO2). Operators are bootstrapped via the SSH CLI (`aperire-auth add <email> --role <admin|monitor>`; the email is the whole identity, the role is chosen at creation), enroll their first passkey via a one-time magic-link URL, and sign in with biometrics on every subsequent visit. Self-contained: no third-party identity provider, no SSO dependency, all state in sqlite. See [AUTH-GUIDE.md](AUTH-GUIDE.md) for the full operator workflow and threat model.
- **Authorization:** the `requireAuthGate` middleware sits after the `/auth/*` dispatch and before every other route. Whitelist (always public) is `/login.html`, `/favicon.ico`, `/aperire-logo.gif`, and `/vendor/*`. Everything else requires a valid `apr_sess` cookie. HTML requests redirect to `/login.html?next=<path>`. API requests get `401` JSON.
- **Sessions:** server-side row in `auth_sessions`. The cookie carries an opaque 256-bit random id only, never a JWT, never a public key. `HttpOnly` + `SameSite=Lax`; `Secure` auto-detected from `x-forwarded-proto` (Cloudflare tunnel) or `APERIRE_FORCE_SECURE_COOKIES=true`. One-year `Max-Age` is the cookie ceiling. The actual session boundary is the configurable idle timeout from `authn.yaml`.
- **CSRF defense:** `SameSite=Lax` plus an `X-Aperire-CSRF: 1` custom-header check on `/auth/touch` and `/auth/lock` (browsers refuse to attach custom headers on cross-site requests without preflight). Passkey ceremonies (`/auth/login/finish`, `/auth/register/finish`) are naturally CSRF-safe. The assertion *is* the challenge response.

### Secrets

- **`RELAY_TOKENS`**: lives in `/etc/aperire/aperire.env` (root-owned, `0640`), loaded into the dashboard via `EnvironmentFile=` in the systemd unit. Never in the committed unit file, never in logs.
- **`relay.conf` `auth_token`**: `/etc/aperire/relay.conf`, `640`, `root:aperire-relay`. Relay user can read; nobody else.
- **Cloudflare tunnel credentials**: `~/.cloudflared/<tunnel-uuid>.json`, user-read-only. Deleting the file revokes the tunnel.

## Tech stack

| Layer | Choice | Why |
|-------|--------|-----|
| Dashboard runtime | Node.js 22 (LTS) via `nvm` | Native WebSocket support, mature stdlib. |
| Dashboard language | TypeScript, executed via `tsx` | End-to-end TS, no build step in the hot path, `tsx` handles transpilation. |
| DB | `better-sqlite3` | Synchronous in-process access. WAL mode. No daemon. |
| WS server | `ws` | Low-overhead, battle-tested, `noServer` mode so I own the upgrade path for auth. |
| Frontend | Vanilla HTML/CSS/JS, inline SVG charts | No framework, no build step, no bundle watcher. Dark theme default. |
| Relay | Go (single static binary) | ~8 MB, zero runtime deps, matches the `node_exporter` / `cloudflared` operator convention. |
| Tunnel | `cloudflared` | Outbound-only QUIC, no inbound ports, free tier plenty for one dashboard. |
| Supervisor | `systemd` | Native to every supported OS (Ubuntu 22.04 / 24.04 LTS), OOM protection via `OOMScoreAdjust`, cgroup memory caps via `MemoryMax`, sandboxing via `ProtectSystem` + friends. |
| OS | Ubuntu 24.04 LTS / 22.04 LTS | Matches rippled's production recommendation. No other OS is a deployment target. |

## Design decisions, with the reasons

### Why a Go relay instead of reading `/proc` from the dashboard?

Two reasons. First, Shape B: the dashboard host isn't necessarily the validator host, so it has no `/proc` of the validator to read. Something has to run *on* the validator. Second, even in Shape A, separating the `/proc` reader from the Node.js dashboard keeps the dashboard's sandbox tight: the dashboard gets a WS frame it understands, not a syscall into the kernel it doesn't. The relay stays a ~8 MB Go binary with a sub-100-line JSON contract, easy to audit end-to-end.

### Why cumulative counters instead of rates?

Counters are what `/proc` exposes. Shipping deltas would require the relay to hold state across pushes, and rate computation would then double-happen if a push were retried. Shipping cumulatives lets the dashboard own rate derivation and lets `bandwidth_last_snapshot` in SQLite continue the monthly bandwidth accounting across either side's restart.

### Why not Prometheus + Grafana?

Classic (v3) was Python + Grafana. It worked. The v4 rebuild had two goals Prometheus/Grafana wouldn't solve: (1) sub-second real-time updates via rippled's WS streams, without a 15 s scrape lag; (2) a single unified frontend where "live" and "historical" live on the same page with the same design language. Prometheus is a scraper. The dashboard needs a pusher pattern for the push-side data (the relay) and a stream pattern for the rippled-side data. Building a thin Node.js server that handles both and serves its own frontend collapsed three moving parts into one.

Prometheus + Grafana remains the right stack for a multi-validator fleet. Aperire One is for the single-operator case.

### Why Cloudflare Tunnel?

The dashboard host needs no inbound port for the tunnel itself (what each shape does open, and to whom, is in the [Deployment guide](DEPLOYMENT-GUIDE.md#what-listens-and-where)). Alternatives (nginx + Let's Encrypt, Tailscale) work too. I chose Cloudflare Tunnel because it adds edge DDoS + TLS termination + rate-limiting for free, doesn't require any firewall changes, and the outbound QUIC stream works through residential NAT without port forwarding. The tunnel is transport only. User auth happens inside the app (WebAuthn / passkeys; see [AUTH-GUIDE.md](AUTH-GUIDE.md)).

### Why SQLite instead of VictoriaMetrics?

Covered above. Short answer: the persisted surface turned out to be small, and one library import beats one daemon to secure.

### Why self-hosted WebAuthn instead of Firebase / SSO?

The Aperire One threat model is enterprise validator operators where a leaked dashboard is a real risk surface. Secrets indicators, peer state, validator health, and alert configuration are all sensitive. Three reasons to bring auth in-house:

1. **No external identity dependency.** When Google or any third-party IdP is down, Aperire One is still reachable. Operator records, credentials, and sessions all live on the dashboard host. The validator's monitoring isn't gated by a service I don't run.
2. **No web write path.** Aperire One's broader security model (alert rules, channels, sessions, operators) is "edit on disk via SSH; web routes are read-only." Pulling auth in-house keeps that boundary intact. Adding an operator is an SSH CLI invocation, not a Firebase Console click. A compromised dashboard process can never grant access to itself.
3. **Phishing-resistant by construction.** Passkeys are cryptographic credentials bound to the origin. Even if an attacker stands up a perfect look-alike `aperire-spoof.example`, the operator's passkey refuses to sign for it. Passwordless removes the entire credential-replay class of attack without bolting on TOTP.

The same `cloudflared` tunnel is what makes this practical. Outbound-only QUIC means I don't have to expose a sign-in page to the public internet on a port I have to defend myself. The library footprint is small (`@simplewebauthn/server` + browser bundle, ~6 KB combined) and well-maintained. The full auth subsystem is documented in [AUTH-GUIDE.md](AUTH-GUIDE.md).

## File layout

```
aperire-one/
├── dashboard/
│   ├── server.ts                # dashboard entry: http + ws + rippled bridge + relay ingest + auth dispatch
│   ├── db.ts                    # SQLite schema + prepared statements + retention pruner; auth tables included
│   ├── auth.ts                  # WebAuthn ceremony, sessions, requireAuthGate middleware, enrollment endpoints
│   ├── email.ts                 # Resend email send for alerts + digests + magic-links
│   ├── ntfy.ts                  # ntfy push notifications for alerts
│   ├── webhook.ts               # Discord / Slack / generic webhook delivery for alerts
│   ├── config/
│   │   ├── rules.yaml           # alert rules + thresholds, the shipped set (replaced by every update)
│   │   ├── rules.local.yaml     # your overrides of it, by metric + severity (never written by an install)
│   │   ├── channels.yaml        # email / ntfy / webhook delivery channels
│   │   ├── channels.yaml.example  # operator-install template
│   │   ├── digest.yaml          # scheduled digest cadence + recipients + content
│   │   └── authn.yaml           # auth: public_url, rp_id, session policy, magic-link options
│   ├── knowledge/
│   │   ├── amendments.yaml      # XLS-NN tags + descriptions, refreshed from xrpl.org
│   │   └── metric-alerts.yaml   # per-metric runbook entries surfaced in Insights tooltips
│   ├── scripts/
│   │   └── send-magic.mjs       # Node helper that emails magic-link enrollment URLs via Resend
│   ├── public/                  # static assets served to browsers
│   │   ├── index.html           # shell: iframe host + auth pill in top-right
│   │   ├── overview.html        # static validator panel centered in the peer ring + P0 strip
│   │   ├── consensus.html
│   │   ├── network.html
│   │   ├── system.html
│   │   ├── governance.html
│   │   ├── insights.html        # alerts + digest + configuration panels
│   │   ├── login.html           # passkey lock-screen (registration + sign-in + self-serve enrollment)
│   │   └── vendor/              # vendored @simplewebauthn/browser bundle
│   └── package.json
├── scripts/
│   ├── aperire-auth.sh          # operator CLI: add / list / del / magic-link / revoke …
│   ├── install-aperire-cli.sh   # non-root helper: symlinks aperire-auth and the aperire menu
│   ├── install-aperire-service.sh  # idempotent installer for the dashboard systemd unit
│   ├── configure-rippled-paths.sh  # writes RIPPLED_CFG_PATH / RIPPLED_DATA_PATH into the env file (the installer runs it)
│   ├── setup-aperire-tunnel.sh  # Cloudflare tunnel bootstrap
│   ├── aperire-server.service   # committed copy of the unit
│   └── aperire-logrotate.conf
├── data/
│   ├── aperire.db               # live DB (WAL + SHM sidecars alongside), outside the source tree
│   └── logs/                    # server-out.log / server-err.log (rotated daily, 14 days kept)
├── docs/
│   ├── ARCHITECTURE-GUIDE.md  # this doc
│   ├── DEPLOYMENT-GUIDE.md
│   ├── AUTH-GUIDE.md          # passkey auth: operator workflow, threat model, recovery
│   ├── OPERATIONAL-GUIDE.md
│   ├── ALERTING-GUIDE.md      # email + ntfy + webhook alert delivery
│   ├── METRICS-GUIDE.md
│   ├── METRICS-CATALOG.md     # exhaustive metric catalog
```

## Related reading

- [Deployment guide](DEPLOYMENT-GUIDE.md): install from scratch, Shape B or Shape A.
- [Operational guide](OPERATIONAL-GUIDE.md): day-to-day ops, health checks, logs, incidents.
- [Metrics guide](METRICS-GUIDE.md): what each number on screen means.
- [Metrics catalog](METRICS-CATALOG.md): exhaustive 175-row catalog with tiers, sources, alert thresholds.
- [Metrics catalog: Collection mechanics](METRICS-CATALOG.md#appendix-collection-mechanics): per-metric `/proc` paths, NIC auto-discovery, monthly budget accounting, push cadence.
- [Relay reference](RELAY-REFERENCE.md): relay install, hardening, and day-2 commands.
- [Tunnel reference](TUNNEL-REFERENCE.md): tunnel config, DNS, systemd unit, day-2 commands.
