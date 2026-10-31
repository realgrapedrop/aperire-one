# Aperire One Relay Reference

`aperire-relay` is the small Go binary that runs on your validator host, reads system and network stats from `/proc`, and pushes them to the dashboard over one outbound WebSocket. This is the reference for operators who've already installed it.

It covers what the relay reads (and what it can't), its push protocol, port detection, hardening, verification, and troubleshooting. To install the relay in the first place, start with the Deployment Guide's [Wiring each shape](DEPLOYMENT-GUIDE.md#wiring-each-shape), which covers both layouts. Everything here picks up from the running relay.

---

## What the relay reads, and what it doesn't

**Reads** (read-only, no privileges required):

| File | Why |
|------|-----|
| `/proc/net/dev` | Interface byte / packet / error / drop counters |
| `/proc/net/snmp` | TCP state (established / retransmits / resets) |
| `/proc/net/sockstat` | Socket counts and TIME_WAIT bucket |
| `/proc/net/route`, `/proc/net/ipv6_route` | Default-route NIC discovery |
| `/proc/stat` | CPU jiffies for busy% |
| `/proc/meminfo` | RAM and swap totals |
| `/proc/loadavg` | 1/5/15-minute load averages |
| `/proc/pressure/{cpu,memory,io}` | PSI stall percentages |
| `/proc/vmstat` | OOM-kill count |
| `/proc/net/tcp`, `/proc/net/tcp6` | Per-port ESTABLISHED connection counts |
| `/proc/<pid>/comm` | Finding rippled's PID when `rippled_pid_file` is unset |
| `/proc/<rippled-pid>/net/tcp`, `tcp6` | The same connection counts from inside rippled's network namespace (Docker) |
| `statfs(data_mount)` | Disk used/total for the configured path, sent in the System frame and shown as the Disk row |

Every one of these is world-readable on a standard Linux system and contains *counters* or *aggregate percentages*, never file contents, process memory, or network payloads. The same set of files `node_exporter`, `cAdvisor`, and `top(1)` read.

**Does not read:** any file in `/home`, any user-data directory, or rippled's database. No process memory (no `ptrace`, no `/proc/<pid>/mem`). No packet contents. No block devices directly.

Outside `/proc` it opens exactly three things, all of them config:

| File | Why |
|------|-----|
| Its own `relay.conf` | Configuration, read once at startup |
| rippled's config file | The `[port_*]` sections, for port auto-detection. `rippled_cfg_path`, or the first of `/etc/opt/ripple/rippled.cfg`, `/opt/ripple/etc/rippled.cfg`, `/etc/ripple/rippled.cfg` that exists |
| rippled's PID file | Only if you set `rippled_pid_file` (typically under `/var/run`). One integer |

**Does not do:**

- **Open an inbound port.** The relay has no listener. Confirm with `ss -ltnp` after install; you won't find the relay in the output.
- **Shape or cap traffic.** The Monthly Budget row is monitoring. Nothing in the code path can drop, throttle, or redirect packets.
- **Phone home.** The only outbound connection is to the `dashboard_url` you set in `relay.conf`. No telemetry, no update checks.

## Push protocol

The relay dials the dashboard over a WebSocket, authenticates with a `Bearer` token (the `auth_token` from `relay.conf`), and pushes on every interval. Each tick sends two frames:

| Frame | `payload.kind` | Carries |
|---|---|---|
| Network | `net_stats` | Interface counters, TCP state, socket counts, per-port connection counts, monthly budget |
| System | `system` | CPU (busy, iowait, steal, load), memory, swap, disk (`statfs` of `data_mount`), pressure, OOM kills, the relay host's hostname |

Both frames carry `protocol_version` 1, the `node_label`, the relay version, and a send timestamp. The System frame is what the dashboard's System tab and Overview system bars show for CPU, memory, swap, disk, pressure and OOM whenever a relay is feeding the dashboard; without one, the dashboard reads its own `/proc`. If a relay on another host stops reporting for 30 s, those rows show a dash and the System tab says so. The dashboard never substitutes its own host's numbers for a validator on a different machine; it does fall back to its own `/proc` when the relay reported the same hostname as the dashboard, since that is the same box. The dashboard diffs the cumulative fields against the prior push to derive rates. The first frame after a connect reports CPU busy% as 0 (no prior sample to diff); it corrects on the next tick.

On disconnect the relay backs off (1s, 2s, 5s, 30s, then 60s capped) and reconnects forever. A dashboard outage is never fatal to the relay, and a dashboard restart costs a few seconds of stale data, nothing more.

## Securing a remote relay link

The relay authenticates with a bearer token in a header, and the dashboard speaks plain HTTP. Over loopback that is fine: nothing leaves the machine. Over a LAN it is not. A `ws://` push to a dashboard on another host puts your `auth_token` and every telemetry frame on the wire readable, and anyone who can see them can replay the token and push forged telemetry. Losing metrics is the small failure. The large one is a real incident papered over with healthy-looking numbers.

**Recommended: tunnel the hop and keep both ends on loopback.** WireGuard or an SSH forward, whichever the host already runs. The relay dials its own machine, the dashboard is dialled from its own machine, and neither one needs to change what it thinks it is talking to.

```toml
# relay.conf on the validator host, with a tunnel forwarding
# 127.0.0.1:7800 to the dashboard host's 127.0.0.1:7800
dashboard_url = "ws://127.0.0.1:7800/ingest"
```

An SSH forward, as a systemd unit or under `autossh`:

```sh
ssh -N -L 127.0.0.1:7800:127.0.0.1:7800 <operator>@<dashboard-host>
```

The dashboard keeps its default `HOST=127.0.0.1`. It never binds to the LAN at all, so there is no port to firewall and nothing to refuse.

**Alternative: `wss://`, where you terminate TLS.** Put a reverse proxy (nginx, Caddy, cloudflared) in front of the dashboard, let it hold the certificate, and have it forward to the dashboard on loopback. The relay dials the proxy:

```toml
dashboard_url = "wss://dashboard.example.com/ingest"
```

The relay verifies the server certificate against the validator host's system root store. There is no skip-verify option and no custom CA setting, so a private CA has to be installed on the validator host the way any other tool on that box would need it.

**What the dashboard does with a plaintext LAN hop.** If the dashboard is bound off-loopback (`HOST=0.0.0.0` or a LAN address) and an authenticated relay reaches it over plain `ws` from another machine, the upgrade is refused with `403` and the reason is logged. Loopback deployments are unaffected and log nothing new. A dashboard bound off-loopback also says so once at startup, whether or not any relay is configured.

**Last resort: accept the cleartext hop by name.** On a trusted L2 you have reason to accept, set this on the dashboard and restart it:

```sh
APERIRE_INGEST_ALLOW_PLAINTEXT=1
```

The dashboard then accepts the push and logs a line per connection saying the token is crossing the network readable. Prefer either of the two options above. This one exists so an operator who has weighed it can proceed, not as a default.

## Port connection monitoring

The Network tab's Admin Connections and Public Connections charts plot concurrent ESTABLISHED TCP connections on each of rippled's four ports (HTTP RPC, Admin WS, WS Public, Peer). Source: `/proc/net/tcp` + `/proc/net/tcp6`, filtered by local (and for the peer port, remote) port number.

**Port auto-detection.** At startup the relay parses `rippled.cfg` and scans every `[port_*]` section, classifying each by protocol + admin whitelist:

| Classification | Criteria |
|---|---|
| **HTTP RPC** | `admin` non-empty AND `protocol` contains `http` |
| **Admin WS** | `admin` non-empty AND `protocol` contains `ws` |
| **WS Public** | `admin` empty AND `protocol` contains `ws` |
| **Peer** | `protocol` contains `peer` |

The relay logs the resolved port + source on startup (`auto-detected from <path>` / `relay.conf override` / `well-known default`). Check `journalctl -u aperire-relay | head` right after install to confirm it picked the ports you expect.

**A node config the relay can't reach.** A container node keeps its config under the operator's home, which Ubuntu creates 0750, so the relay's account can't pass through it. On that shape the installer reads the config itself and pins the ports it finds in `relay.conf`, between two marker lines:

```toml
# >>> node ports pinned by install-aperire-relay.sh >>>
# ...
admin_ws_port  = 6006
peer_port      = 51235
# <<< node ports pinned by install-aperire-relay.sh <<<
```

Every install and update rewrites that block from the node config. A port you set outside the block is yours: the installer leaves it alone and keeps it out of the block. The relay reads the block when it restarts, so its startup log names those ports as `relay.conf override`.

**Container-namespace aware reads.** When rippled runs in a Docker container, its TCP sockets live in a container-local network namespace, invisible to the host's `/proc/net/tcp`. The relay resolves rippled's PID (via `rippled_pid_file` or a `/proc/*/comm` scan) and reads `/proc/<rippled-pid>/net/tcp` instead, the authoritative view inside rippled's netns. On native installs both paths return identical data.

**Peer port is bidirectional.** Service ports (HTTP RPC, Admin WS, WS Public) only ever have clients dialing in, so counting sockets where `local_port == service_port` is correct. The peer port is different: rippled both accepts inbound peers and dials out to peers, so the relay counts sockets where either end matches the peer port. Counting one side would hide half the connections.

## Native vs Docker rippled

The relay's rippled-integration config is identical across install modes. Only the typical values differ:

| | Native (systemd / package) | Docker |
|---|---|---|
| Typical `data_mount` | `/var/lib/rippled/db` or `/opt/rippled/db` | Host-side path of the volume/bind-mount |
| Typical `rippled_pid_file` | `/var/run/rippled/rippled.pid` | leave blank; `pgrep` finds the process |
| How to identify rippled | `systemctl status rippled` | `docker ps` |
| Stop / start / restart | `sudo systemctl {start,stop,restart} rippled` | `docker {start,stop,restart} <container>` |

`data_mount` is the path the relay runs `statfs()` on. The result rides in the System frame and fills the Disk row on the System tab and Overview. Point it at the filesystem where NuDB lives when that's a separate volume from `/`. With no relay feeding the dashboard, the Disk row falls back to a `statfs()` of the dashboard's own `DATA_MOUNT` env var (default `/`), which describes the dashboard host and not the validator. To find the host-side path for a Docker rippled:

```sh
docker inspect <container-name-or-id> \
  --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'
```

Pick the one that contains `db/nudb/` or similar.

## Hardening

The relay runs as a dedicated user with no shell, no home, no sudo, and no capabilities, under a systemd unit that mounts the system read-only and forbids privilege gain, kernel-module loading, and device access. The unit is written by `scripts/install-aperire-relay.sh`, which comments the directives whose reason isn't obvious from the name (the `setrlimit` carve-out, and `UMask` on a service that writes nothing). Read it there rather than from a table here that can fall behind it.

For the net effect and the trust boundaries it creates, see the [architecture guide](ARCHITECTURE-GUIDE.md#privilege-model).

## Troubleshooting

**Relay sessions end with `... expected handshake response status code 101 but got 401`.** Token mismatch. The full line is `[pusher] session ended after 0s: dial: failed to WebSocket dial: expected handshake response status code 101 but got 401`, so grep for `401`, not for `HTTP 401`. The `auth_token` in `relay.conf` isn't in the dashboard's `RELAY_TOKENS` env var. Fix it on the dashboard side, restart the dashboard, then `sudo systemctl restart aperire-relay`.

**Relay sessions end with `... expected handshake response status code 101 but got 403`.** The token was accepted and the transport was not. The dashboard is bound off-loopback and this relay reached it over plain `ws` from another machine, so it refused the push (see [Securing a remote relay link](#securing-a-remote-relay-link)). The explanation is in the dashboard host's journal, not this one. Fix it on the relay by pointing `dashboard_url` at a tunnel endpoint on loopback or at a `wss://` URL; the dashboard-side override is the last resort, not the first move.

**Nothing arrives and you don't know why.** Ask the relay. It tries `dashboard_url` once with its own handshake, sends no data, and names what's in the way:

```sh
sudo aperire-relay --check-dashboard
```

The first line is `check=` followed by one of `accepted`, `dns`, `refused`, `timeout`, `no_route`, `tls`, `unauthorized` (401), `forbidden` (403), `not_ingest` (404), `http` or `no_url`. The second is a sentence giving the one next step. The exit code is 0 only for `accepted`. It reads `/etc/aperire/relay.conf` (pass `--config` for another file) and never prints the token. The installer runs it once at the end of a remote install.

**Relay logs `dial: connection refused`.** The dashboard isn't running, or `dashboard_url` points to the wrong host/port. Verify with `curl -I http://<dashboard-host>:7800/`.

**Cards populate with the wrong interface name.** Default-route discovery picked a NIC that's not what you expected (common on multi-homed or VPN-first hosts). Hover the Network tab's Monthly Budget card: the tooltip's `NIC` line names the interface the relay resolved and where the name came from (`default_route`, `config`, or `fallback_sum`). That tooltip is the only place the resolved NIC is reported, and it needs `monthly_budget_bytes` set (without a cap the card says so instead). The journal is no help: it echoes the configured value (`interface="auto"`), never the result.

Override in `relay.conf`:

```toml
interface = "eth0"
```

Restart. The tooltip then shows `NIC eth0 (config)`, confirming the override.

**Dashboard shows `Monthly Budget —` instead of a percentage.** `monthly_budget_bytes` is 0 or unset in `relay.conf`. Set it to your plan's cap in bytes and restart. This state is intentional and correct if you want monitoring only, with no percentage.

**The journal carries a `[security] dashboard_url=... is plain ws to another host` line at startup.** Not a failure, a warning, and the relay carries on dialling. It means the configured link would send the token in the clear. See [Securing a remote relay link](#securing-a-remote-relay-link). The classification is done on the URL text alone, with no DNS lookup, so a hostname that happens to resolve to `127.0.0.1` is still reported as remote.

**`systemctl status` shows `Active: activating` then `failed`.** Usually config validation. Check `journalctl -u aperire-relay`. Common causes: `auth_token is required when dashboard_url is set` (a URL with no token, which is half-filled configuration), `node_label is required` (label empty/missing), `interval_seconds must be in [1, 300]` (out-of-range value).

**The journal says `dashboard_url is empty: standing by, pushing nothing`.** Not a failure. That is what a split install looks like before you tell the relay which dashboard collects from this host: the service is enabled and running, it dials nothing, and it holds there. An empty `dashboard_url` is a valid value and means exactly this. Set `dashboard_url` and `auth_token` in `relay.conf`, add the same token to `RELAY_TOKENS` on the dashboard host and restart that dashboard, then `systemctl restart aperire-relay`. A restart, not `enable --now`: the unit is already enabled and already running, so `--now` does nothing and the process keeps the config it started with.

## Day-2 commands

```sh
sudo systemctl start aperire-relay         # start
sudo systemctl stop aperire-relay          # stop
sudo systemctl restart aperire-relay       # restart (picks up relay.conf changes)
sudo systemctl status aperire-relay        # current state + last log lines
sudo systemctl disable aperire-relay       # don't start on boot
sudo systemctl enable aperire-relay        # start on boot

sudo journalctl -u aperire-relay -f        # follow logs
sudo journalctl -u aperire-relay --since "1 hour ago"

sudo ss -ltnp | grep aperire-relay         # confirm no inbound listener (should be empty)
sudo aperire-relay --check-dashboard      # try dashboard_url once and say what is in the way
```

**No SIGHUP reload.** Unlike the dashboard, the relay has no config-reload signal handler. Any change to `relay.conf` or rippled.cfg ports needs a full `systemctl restart aperire-relay`. The restart costs one missed push, so one push interval of stale Network-tab data (5 s on the default cadence); nothing else is affected. The relay writes nothing and holds no state, so there is nothing to lose on the way down.

## When to update

Infrequently. The relay's surface is small and stable. The JSON contract is versioned (`protocol_version` in each frame) and backward-compatible changes add new `payload.kind` values rather than break existing ones. Update when:

- A new metric block is added that you want to see on your dashboard
- A CVE in one of the two dependencies requires a rebuild
- Your dashboard version bumps the protocol version

Routine dashboard updates don't require a relay update.

## Fleet registration sequence (node and aggregator)

The relay's whole shape is *dial out and register*: it holds no inbound port, initiates a single outbound connection, and authenticates with a token the other end already knows. A fleet is the same shape one level up — an **aggregator** dials out to each node, over a tunnel, and reads it. This section is the granular, step-by-step companion to the [Architecture guide — Fleet: watching more than one node](ARCHITECTURE-GUIDE.md#fleet-watching-more-than-one-node); the operator how-to (the exact commands, tunnel units, and pinning) is the [Fleet guide](FLEET-GUIDE.md). Registration has two halves that are wired independently: the **read side** (the aggregator gains eyes on a node) and the **trust side** (the aggregator carries an operator's passkey approval to a node). A node can have the first without the second.

### Part 1 — read-side registration

The outcome: the aggregator can poll a node's `/read/v1/` surface over a loopback-only tunnel, labelled by node, with no inbound port opened on the node.

1. **The node already serves the read API.** Every node runs its own full dashboard, which serves the ADR 0008 read API at `/read/v1/` — loopback-only, token-gated by `advisor/state/read.token`, an exact route allow-list. Nothing new is installed on the node for the read side; it is already listening on loopback.

2. **A loopback-preserving tunnel is stood up from the aggregator to the node.** The reference arrangement is an SSH local forward kept alive by systemd on the aggregator: `ssh -L 7901:127.0.0.1:7800 <user>@<node-host>`. One local `790x` port per peer, plus a matching `791x` port where the aggregator also reads that node's own Advisor (`advisor_origin`). Any transport that lands as loopback on both ends works identically; the node is never network-exposed and no firewall rule opens.

3. **`scripts/aperire-fleet-add.sh` joins the node**, run on the aggregator. In order, before writing anything:
   - validates the inputs. `--read-origin` must be a bare loopback origin and `--token-path` must be readable, and both are required. `--label` and `--dashboard-url` are optional: a given label must fit the charset, and a given dashboard address must be https, because the fleet's origin rule allows plain http only to a loopback name and a registry row drops a loopback name;
   - reads the peer's own `/read/v1/identity` through the tunnel and **refuses the join if that fails** — a node it cannot identify is not a node it registers;
   - runs every duplicate check (a label already in either registry, or a `read_origin` already in `fleet.yaml`) before touching a file or a DNS record; an over-permissioned or unparseable trust file is refused earlier still, before the peer is contacted.

4. **The join helper writes the registry rows.** A row in the aggregator's `dashboard/config/fleet.yaml` — `label`, `read_origin`, `token_path`, the `expected_pubkey_node` **pin filled in from the identity read** (trust-on-first-use), `dashboard_url` if `--dashboard-url` was given, and `role` if `--role` was given — and, if the Advisor is installed on the aggregator, the matching row in `advisor/state/fleet.json`. It then reloads the dashboard in place and prints (does not run) the `aperire-advisord` restart command.

5. **`scripts/aperire-advisor-fleet-sync.sh` keeps the Advisor's registry derived from `fleet.yaml`**, so the two never drift. It **generates** `label`, `origin`, `role` and `expected_pubkey_node` from the shared file and **preserves** the host-local `token_path` and `transport`; a peer with no recorded token path is reported and skipped, never guessed. With `--self-label` it writes the `self` block naming which row is this host; without it, an existing `self` block is preserved rather than dropped. Without `--write` it only prints the plan. advisord reads the registry once at start, so it is restarted to pick up the change.

```text
aggregator                                        node
──────────                                        ────
[read side — the aggregator initiates everything]
  ssh -L 7901:127.0.0.1:7800  ───────tunnel──────►  dashboard on 127.0.0.1:7800
  aperire-fleet-add.sh
    GET /read/v1/identity ─────over tunnel────────►  { pubkey_node, build_version, network }
    ◄──────────────────────identity──────────────
    write fleet.yaml row (read_origin, token_path,
       role, expected_pubkey_node = pubkey_node)
    write advisor/state/fleet.json peer row
       (skipped, and said, if no Advisor is installed here)
  [later: to name this host, or to resync after an edit]
    aperire-advisor-fleet-sync.sh --self-label <label> --write
       → advisor/state/fleet.json (self + peers)
  [thereafter, per poll]
    GET /read/v1/<route>  (Bearer read.token) ────►  loopback + token + GET + path
    ◄────────────────────JSON, labelled by node──   checked; else 401 / refused
```

Failure modes to know: the read API refuses any non-loopback caller even with a valid token; `fleet.yaml` parsing is fail-closed (one bad or unknown key drops the whole file to single-node); and a row pinned with `expected_pubkey_node` whose node later reports a different key renders red rather than as a healthy wrong node.

### Part 2 — trust-side registration

The outcome: an operator can approve an action on the aggregator with their passkey, and the **target node's own Advisor** verifies that approval against keys it holds before its executor runs. This half is the "acting on a node" side described in the [Architecture guide](ARCHITECTURE-GUIDE.md#fleet-watching-more-than-one-node) and requires an advisor stack on each actionable node.

1. **Each actionable node runs its own advisor stack** — `aperire-advisord`, `aperire-executor`, the privilege wrapper — with its own credential store, accepted compact, tokens, and hash-chained ledger. The aggregator reaches each node's advisord over one more loopback forward beside the read forward (`791x` beside `790x`), recorded as `advisor_origin` / `advisor_token_path` in `fleet.yaml`.

2. **Pairwise trust keys are exchanged at join.** Each node has an Ed25519 key at `dashboard/config/fleet-trust.yaml` (a private key for itself, one public key per peer). The join helper ensures the aggregator has its own key and places the **aggregator's public key** into the node's trust file — directional: the node can later accept something signed by the aggregator, never the reverse. For a remote node the helper prints the exact entry to paste on that host, with a fingerprint to eyeball.

3. **The aggregator builds and signs a trust bundle** from its own admin passkeys: `{ rp_id, origins[], credentials[{ credential_id, public_key, label }], serial, issued_at, issuer_label }` — **public keys only, no secret material**. `serial` is a digest over the credentials' `credential_id` + `public_key`. It signs the bundle with its Ed25519 private key. Builder/verifier are `dashboard/lib/trust-bundle.ts` and `advisor/internal/host/trustbundle.go`, byte-identical by a shared test vector.

4. **`aperire-auth fleet-trust-push` pushes the bundle** over the existing forward to each node's `POST /v1/trust/bundle`. The node's advisord:
   - checks the request's service token (as every advisord write is gated), **and** verifies the bundle signature against the aggregator's public key from its own `fleet-trust.yaml` — an unsigned or wrongly-signed bundle is refused before any other logic;
   - enforces the **binding pin**: on first accept it records `rp_id` + `origins`; on every later accept it refuses any change to them, accepting only credential-set changes. The first accept is the one-time migration from a node's earlier self-enrolled store;
   - installs the credential set and writes a `trust.bundle_installed` entry in its own ledger.

5. **The ceremony carries a single approval to the node.** When an operator approves an upgrade on the aggregator:
   - advisord on the **target node** issues the challenge, bound to the plan and stage; the aggregator's dashboard refuses if the node's plan fingerprint disagrees with what the page shows;
   - the browser signs at the aggregator's origin; the dashboard verifies the assertion itself and enforces that the signing credential is the one that opened the session;
   - the dashboard carries the **raw assertion** to the target node's advisord (routed per node through `dashboard/lib/peer-advisor-proxy.ts`, with no fallback to the local advisord);
   - the node's advisord verifies the assertion **independently** against its bundle-installed store, recomputes and consumes the challenge, and only then lets its executor run. The eight-character confirm code is derived by the **target node** from the plan it would run, so it can be cross-checked on that host.

```text
aggregator                                        node advisord
──────────                                        ────────────
[one-time trust setup]
  fleet-trust.yaml: aggregator pubkey ──at join──►  node's fleet-trust.yaml (peers.<agg>)
  build + sign bundle (admin PUBLIC keys only)
  aperire-auth fleet-trust-push ────POST /v1/trust/bundle────►  verify signature (agg pubkey)
                                                                pin rp_id + origins (1st accept)
                                                                install creds · ledger entry
  ◄──────────── first_install: pinned / updated ────────────
[per approval — one passkey touch]
  node advisord issues challenge ◄──begin──────────  bound to (plan fingerprint, stage)
  operator touches passkey @ aggregator origin
  dashboard verifies, carries raw assertion ──────►  verify independently vs bundle store
                                                     derive confirm code from ITS plan
                                                     executor runs; writes ITS ledger
```

Only public keys and a signed assertion cross the wire; no private key material moves. The node's ledger is written by the process that acted, on the machine it acted on — the aggregator renders that record but keeps none of it. Two properties are honestly weaker than a single-host install and are documented as such in the architecture guide: the ceremony's two independent sources collapse to *one credential source, two verifiers*, and revocation becomes eventually consistent, bounded by when a node is next reachable.

### Version compatibility of the trust bundle (forthcoming)

This is the direction the trust side is moving, **not** what ships today. A not-yet-merged audit build adds `user` and `role` **into the signed bundle's credential records**, so each node can attribute an act to a named operator and role from something it verified rather than the dashboard's claim. (Today `role` is used only aggregator-side to select which passkeys enter the bundle; it is not signed. The enrichment widens the signed bytes, but the bundle's `serial` / fingerprint stays over `credential_id` + `public_key` only, so that pinned constant does not move.)

Because the enrichment changes the bytes the signature covers, and a node **verifies fail-closed** — a bundle whose signature does not verify is refused before any pin or credential logic runs, and the node keeps its previous credential set — a new aggregator's enriched bundle would not verify against a node still running the old verifier. The safe rollout order is therefore a general principle:

> **When the signed field set of the trust bundle changes, update every verifier before the signer — nodes before the aggregator.** Otherwise an updated signer talking to an un-updated verifier silently stops distributing trust.

The reverse pairing (an old aggregator pushing to an already-updated node) depends on serialization details of the unshipped build and is not asserted here; treat nodes-before-aggregator as the safe order and confirm the specifics against the build when it lands.

---
