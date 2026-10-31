# Aperire One Operational Guide

Day-to-day operations for running Aperire One in production. Lifecycle commands for each service, the health-check shape, the log layout, incident response for the common failure modes, and the residual risks worth watching. It assumes you already deployed per the [deployment guide](DEPLOYMENT-GUIDE.md).

For component internals or the trust model, see the [architecture guide](ARCHITECTURE-GUIDE.md). For what a given number on the UI means, see the [metrics guide](METRICS-GUIDE.md).

---

## The three services

Aperire One is three systemd units on Ubuntu. Any production setup has all three enabled on boot with `Restart=always`.

| Unit | What it does | Process on the box |
|------|--------------|---------------------|
| `aperire-server.service` | Node.js dashboard (rippled bridge, browser WS, ingest endpoint, SQLite, HTTP) | `node --import tsx server.ts` running as `operator` (throughout these guides, `operator` means the account that ran the installer) |
| `aperire-relay.service` | Reads `/proc`, pushes counters every 5 s | `aperire-relay` running as the unprivileged `aperire-relay` user |
| `cloudflared-aperire.service` | Outbound QUIC tunnel to Cloudflare edge | `cloudflared` running as `operator` |
| `aperire-advisord.service` | The Advisor, if installed. Optional add-on | `aperire-advisord` running as the unprivileged `aperire-advisor` user (your login account if you skipped the dedicated-account step) |

Every lifecycle command below uses one of those unit names.

`aperire-advisord` is present only if you installed the Advisor. It's an optional add-on and nothing else depends on it. Stopping it leaves monitoring, alerting and digests untouched, and the Advisor tab says plainly that the service isn't answering rather than rendering empty. See the [Advisor Setup Guide](ADVISOR-SETUP.md).

### Status

```bash
# One-liner: all three at once
systemctl status aperire-server aperire-relay cloudflared-aperire --no-pager

# Per-service detail
systemctl status aperire-server
systemctl status aperire-relay
systemctl status cloudflared-aperire
```

Healthy output for each has `Active: active (running)` and a recent `since` timestamp.

### Start / stop / restart

```bash
sudo systemctl restart aperire-server
sudo systemctl restart aperire-relay
sudo systemctl restart cloudflared-aperire
```

What each restart costs:

- **Dashboard.** Drops browser WebSocket connections (they auto-reconnect in ~2 s) and takes the relay connection with it (the relay reconnects in 1 to 60 s with exponential backoff).
- **Relay alone.** Invisible to browsers. The dashboard keeps serving; the next Network-tab update is delayed by one push cycle.
- **Tunnel.** Drops browser sessions for a few seconds.
- **Advisor.** Stopping `aperire-advisord` no longer throws away a question it's in the middle of. On `SIGTERM` it stops accepting new work, finishes what's already running for up to 60 seconds, then exits. systemd waits that out either way — its own default stop timeout is 90 seconds, and units written by the current installers set `TimeoutStopSec=75` explicitly so the relationship is on the page rather than inherited. A question that needs longer than 60 seconds is still cut off, and the journal says so by name; a break-glass question is the one worth not interrupting, because its answer is delivered by polling and doesn't survive the restart.

  Both services report what they're carrying before you restart them: `asks_in_flight` on the Advisor's `/v1/status` and on the dashboard's `/healthz`. Check it first if you'd rather not interrupt anything.

Routine config changes (editing `rules.local.yaml`, `channels.yaml`, `digest.yaml`, `knowledge/metric-alerts.yaml`) don't need a full restart. See [Apply config changes](#apply-config-changes) below. Use the restart commands above when you've changed env vars, the dashboard binary, or anything in `relay.conf`.

### Logs

```bash
# Live tail, any unit
journalctl -u aperire-server -f
journalctl -u aperire-relay -f
journalctl -u cloudflared-aperire -f

# Historical
journalctl -u aperire-server --since "1 hour ago"
journalctl -u aperire-server --since yesterday --until today

# Dashboard also writes append-log files for longer retention
# (paths shown relative to the repo root)
tail -f data/logs/server-out.log
tail -f data/logs/server-err.log
```

The dashboard's append logs rotate daily via `/etc/logrotate.d/aperire`. 14 compressed days are kept, then dropped. `copytruncate` means the live append-fd survives rotation, so no restart is needed.

---

## Health checks

### `/healthz`

```bash
curl -s http://127.0.0.1:7800/healthz | jq
```

```json
{
  "ok": true,
  "rippled_connected": true,
  "ledger_age_ms": 3412,
  "relay_last_push_ms": 2077,
  "uptime_s": 14325
}
```

- **HTTP 200** when rippled is connected **and** the last ledger-closed event arrived within 30 s.
- **HTTP 503** otherwise. rippled disconnected, ledger stream stalled, or both.
- **`relay_last_push_ms: null`** on a fresh restart before the first push arrives. If it stays `null` after 10 s, the relay isn't authenticating. See the triage table below.

`/healthz` never touches SQLite or the browser broadcast path. Poll it as often as you like. It's the target for:

- External uptime monitors (UptimeRobot, BetterStack, Pingdom, etc.).
- Cloudflare Load Balancer origin health checks, if you ever put a LB in front.
- A cron that pages if the response is non-200 for two consecutive samples.

### Eyeball checks

- **Public URL loads:** `curl -s -o /dev/null -w "%{http_code}\n" https://aperire.example.com/` should be `200`.
- **HTTP redirects to HTTPS:** `curl -sI http://aperire.example.com/ | head -1` should return `HTTP/1.1 301`. The dashboard's `X-Forwarded-Proto: http` middleware issues the 301 at the origin. It's a second layer behind Cloudflare's own "Always Use HTTPS" toggle.
- **WebSocket handshakes:** the browser console on a loaded tab shows `[ws] live` after connect.
- **Relay heartbeat in the server log:** `journalctl -u aperire-server --since "5 min ago" | grep '\[ingest\]'` should show `relay connected from …` followed by nothing (no disconnect lines).
- **Mobile audio toggle visible:** on phone viewports (≤720 px) the speaker icon sits in the top-right of the tab strip (absolute-positioned, `z-index: 2`). Tap to mute/unmute the ambient stream.
- **System history threshold redlines:** each System-tab history chart draws dashed horizontal lines at the warn/critical bands from [METRICS-CATALOG.md](METRICS-CATALOG.md) (amber = warn, red = critical). A glance at the chart answers "how close to the redline am I?" with no doc lookup.

---

## The dashboard systemd unit

The unit at `/etc/systemd/system/aperire-server.service` is the source of truth for the service's runtime posture. Understand these directives before editing it.

### Recovery

- **`Restart=always`, `RestartSec=3`**: restart on any exit within 3 s.
- **`StartLimitIntervalSec=300`, `StartLimitBurst=10`**: up to 10 restarts per 5 minutes before systemd backs off. Enough tolerance for a flapping dependency without spinning forever on a permanent failure.

### Memory

- **`MemoryHigh=2G`**: soft cap. Above this the kernel throttles the cgroup and reclaims its pages aggressively. The figure covers the process (about 350 MB) plus the page cache of its SQLite store, which the cgroup is charged for and which reaches 0.5 to 1 GB after a month of samples. Set it too low and the store's pages get reclaimed as fast as queries re-read them: the event loop stalls for seconds and every read of this node times out, while CPU stays low. Check with `systemctl show aperire-server -p MemoryCurrent -p MemoryHigh` and `memory.events` in the unit's cgroup; a climbing `high` count is the sign.
- **`MemoryMax=3G`**: hard cap. Exceed it and the cgroup OOM killer terminates *only this unit*, then `Restart=always` brings it back. This is the key mitigation from the April 22 outage. A runaway dashboard can no longer OOM the whole host.
- **`OOMScoreAdjust=-100`**: secondary defense. If system-wide pressure fires the kernel OOM killer before the cgroup cap engages, other processes are picked first.
- **`TasksMax=256`**: hard cap on thread/process count in the cgroup.

### Sandboxing

- **`ProtectSystem=strict`**: the entire filesystem is read-only.
- **`ProtectHome=read-only`**: `/home/*` is read-only. Required because the repo lives under the operator's home directory.
- **`ReadWritePaths=<repo>/data <repo>/dashboard/knowledge`**: the only two writable paths inside that sandbox. `data/` holds the SQLite database and the rotated logs; `dashboard/knowledge/` holds the amendment metadata the dashboard refreshes at runtime. `dashboard/` itself stays read-only. Nothing else is writable.
- **`PrivateTmp=true`**: private `/tmp` + `/var/tmp` namespace.
- **`NoNewPrivileges=true`**: cannot gain additional capabilities via setuid binaries.
- **`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `LockPersonality`, `RestrictRealtime`**: standard systemd sandboxing. The service has no business writing `/proc/sys`, loading modules, or changing its own cgroup. These enforce that.

### Secrets

- **`EnvironmentFile=/etc/aperire/aperire.env`**: `RELAY_TOKENS` and any other secrets live here (`0640 root:<dashboard-user>`). The unit file itself is committable. The secret is not.

Full annotated unit file: `/etc/systemd/system/aperire-server.service` on disk, or [`scripts/aperire-server.service`](../scripts/aperire-server.service) in the repo.

---

## Operational runbook

### Apply config changes

Different files reload through different mechanisms. Get this wrong and one of two things happens: the change silently doesn't apply (you edited but never reloaded), or you take a 5-second outage you didn't need (full restart for a YAML tweak).

| What changed | How to apply | Notes |
|---|---|---|
| Dashboard `rules.local.yaml`, `channels.yaml`, `digest.yaml`, `knowledge/metric-alerts.yaml`, `knowledge/amendments.yaml` | `sudo systemctl reload aperire-server` (or `sudo kill -HUP $(systemctl show -p MainPID --value aperire-server)`) | SIGHUP triggers an in-place reload. Browsers stay connected, no missed metrics. Validation runs on the new config and reports back via `/api/insights/config`. Alert rules are two files and both are re-read: `rules.yaml` is the shipped set, `rules.local.yaml` is yours. |
| Dashboard `.env` (e.g. `RELAY_TOKENS`, `RESEND_API_KEY`, `NTFY_TOKEN`, `APERIRE_TEST_TOKEN`) | `sudo systemctl restart aperire-server` | Env vars are read once at process start. SIGHUP won't pick them up. |
| Relay `relay.conf` (any field: auth_token, dashboard_url, monthly_budget_bytes, interface override, port overrides, interval_seconds) | `sudo systemctl restart aperire-relay` | The relay has no SIGHUP handler. Full restart is the only path. One missed push (one interval, 5 s by default) of stale Network-tab data. The dashboard keeps serving everything else. |
| `rippled.cfg` ports the relay auto-detects from | `sudo systemctl restart aperire-relay` | rippled.cfg is parsed once at relay startup and cached. |
| rippled itself restarts (no config change) | Nothing | The relay re-resolves rippled's PID each push tick and reconnects automatically. |
| rippled binary upgrade | Nothing on the relay side | Same auto-recovery as a restart. |
| Dashboard binary / TypeScript source | `sudo systemctl restart aperire-server` | |
| Cloudflare tunnel config | `sudo systemctl restart cloudflared-aperire` | ~3 s outward outage. |

After a SIGHUP reload, confirm the new config landed. Check `journalctl -u aperire-server --since '30 sec ago'` for the parser log lines, or GET `/api/insights/config` from a browser dev console. The rules line names both files and what yours did to the shipped set:

```
[insights] rules.yaml parsed: 33 rules (4P · 13C · 16W); shipped 33, rules.local.yaml: 2 overrides, 1 added, 1 disabled
```

With no overrides on this host the tail reads `no rules.local.yaml`. If it reads `rules.local.yaml not applied`, your file didn't load and the line above it says why; the shipped rules are what the host is running until you fix it.

### Rotate the relay token

Zero downtime, because `RELAY_TOKENS` accepts a comma-separated allow-list.

1. Generate a new token: `openssl rand -hex 32`.
2. Edit `/etc/aperire/aperire.env`, change `RELAY_TOKENS=<old>` to `RELAY_TOKENS=<old>,<new>` (keep both during the rollover).
3. `sudo systemctl restart aperire-server`. The dashboard now accepts either.
4. On the validator host, edit `/etc/aperire/relay.conf`, set `auth_token = "<new>"`, then `sudo systemctl restart aperire-relay`.
5. Verify in the server log that the relay reconnected with the new token: `journalctl -u aperire-server | grep ingest | tail -5`.
6. Edit `/etc/aperire/aperire.env` again, remove `<old>` so only `<new>` is in `RELAY_TOKENS`.
7. `sudo systemctl restart aperire-server`.

### Rotate Cloudflare tunnel credentials

Not a frequent operation. If the credentials file leaks:

```bash
cloudflared tunnel delete aperire
cloudflared tunnel create aperire
# Update config-aperire.yml credentials-file path to the new UUID
cloudflared tunnel route dns aperire aperire.example.com
sudo systemctl restart cloudflared-aperire
```

### Restart rippled without restarting Aperire One

Aperire One reconnects to rippled automatically with a 3 s backoff on close. Restarting rippled is safe. The dashboard shows `rippled_connected: false` on `/healthz` for the duration and recovers on its own.

During the gap:

- The browser WebSocket stays open. Overview / Consensus / Network cards freeze on last-known values.
- The relay keeps pushing (those metrics are independent of rippled).
- `/healthz` returns 503 while the stream is stale.

If an external uptime monitor pages on 503, silence it before planned rippled maintenance.

### The amber window after a restart

Reconnecting is not instant. On a lab validator running on VPS-class hardware, with too little local ledger history to resume from where it left off, I measured roughly 11 to 12 minutes of `connected` / `complete_ledgers: empty` after a clean restart before the node reached `full` again: the time it took to re-acquire from the current network tip on hardware that constrained. Nothing was lost: the store was untouched on disk, and the complete-ledger range came back larger than before the restart. A node with more established local history to resume from may reconnect faster; I haven't measured that case.

During that window, Overview and Consensus show the node connected with no validated ledger range yet, which reads as amber rather than green. That's not a fault. It's also not wired to page: there's no alert rule keyed on `complete_ledgers`, so the Page-tier line in the [metrics guide](METRICS-GUIDE.md#p1-ledger-and-chain-state) is a reading guide, not a live condition your install will trip. Treat 12 minutes as a starting point, not a deadline; if it's still empty well past that, follow the triage table below.

The one restart that behaves differently is one that lands mid-rotation on a store that prunes on its own schedule (`advisory_delete` unset). That can cost the whole store, not an amber window. See [scheduling store pruning](DEPLOYMENT-GUIDE.md#make-store-pruning-something-you-schedule) to move rotation to an hour you choose and stop restarts from landing inside it.

### Keep the node patched

The dashboard reads your node's version and shows it. It does not patch it, and
it will not nag you. That is your cadence to set, so set one.

What the dashboard gives you to work with:

- **The running version.** `build_version` from `server_info`, shown on Overview
  and on Governance. Read it before and after any node work; it is the only
  honest confirmation an upgrade landed.
- **Amendment-blocked.** Surfaced on Governance and recorded every poll. A node
  that is amendment-blocked has already missed an upgrade it needed, and is no
  longer validating the current ledger rules. Treat it as an incident, not a
  reminder.
- **The Advisor's upgrade ceremony,** if you installed the Advisor. It runs the
  upgrade in two stages behind a passkey approval and refuses to call it done
  until the node reports the target version and is back in consensus. See the
  [Advisor guide](ADVISOR-GUIDE.md#the-upgrade-ceremony).

A cadence that works:

1. **Watch the source.** Subscribe to releases on the repository your fork ships
   from (for rippled, `XRPLF/rippled` on GitHub; the Releases page has an RSS
   feed and GitHub will email you). Security releases are announced there first.
2. **Read the release notes before the version number.** An amendment-carrying
   release has a deadline attached to it, and a patch release usually does not.
   The two want different urgency.
3. **Patch releases: inside a week.** Nothing about a validator makes a known
   bug safer to sit on.
4. **Amendment releases: before the amendment activates,** not after. Governance
   shows the vote; a node still on the old build when an amendment goes live
   goes amendment-blocked at that moment.
5. **Upgrade one node at a time** on a fleet, and confirm the first is back in
   consensus before starting the second.
6. **Confirm with the dashboard, not with the package manager.** `build_version`
   on Overview is what the node is actually running.

The same discipline applies to the host. Unattended security upgrades on the OS
are worth switching on; see the [Hardening guide](HARDENING-GUIDE.md).

### Upgrade the dashboard (in place)

```bash
curl -fsSL https://get.aperire.one | bash -s -- --update
curl -s http://127.0.0.1:7800/healthz | jq      # confirm ok: true
```

The update preserves existing secrets. Upgrading the unit doesn't rotate `RELAY_TOKENS`.

### Upgrade the relay

```bash
cd <repo>
git pull
(cd relay && go build -ldflags "-s -w" -o aperire-relay .)
sudo install -m 755 relay/aperire-relay /usr/local/bin/aperire-relay
sudo systemctl restart aperire-relay
```

The JSON contract is versioned. The dashboard accepts old and new frames.

### Back up what a rebuild cannot recreate

Most of the dashboard comes back on its own. It rebuilds the live picture from the node on the next poll, so a rebuilt host is showing you the truth within seconds of starting. These do not come back on their own, and are what a backup is for. This table is the one list: `scripts/aperire-backup-set.sh` defines it once, `aperire-backup.sh` and `aperire-restore.sh` both read it, and `scripts/test-backup-restore.sh` fails the moment this table and the code disagree.

| What | Where | Required or optional | Owner : group | Mode | Why a rebuild cannot recreate it |
|---|---|---|---|---|---|
| The database | `~/aperire-one/data/aperire.db` | required | the dashboard account | 0600 | Your operators and their passkeys, the alert history, the whole metric and ledger history |
| The dashboard config | `~/aperire-one/dashboard/config/{authn,channels,digest,rules.local}.yaml` | required | the dashboard account | 0640 | Your alert choices, your channels, your sign-in settings |
| The fleet config, if this host belongs to a fleet | `~/aperire-one/dashboard/config/{fleet.yaml,fleet-trust.yaml,fleet-link.json,fleet-links.json}` | optional | the dashboard account | 0600 | Which nodes an aggregator reads and where; the aggregator's public key, without which a pushed model seal is refused as `no_aggregator_pinned`; this node's own dial-out credential, minted once by pairing and never stored anywhere else; and, on an aggregator, the hash of every node's link credential, without which no node can link |
| The dashboard's env file, half of the relay token pair | `/etc/aperire/aperire.env` | required | root, group the dashboard account is in | 0640 | One credential in two files, generated at install |
| The relay's own config, the other half | `/etc/aperire/relay.conf` | optional | root, group the relay account is in | 0640 | Same credential as above; only present when this host also runs the relay |
| The Advisor's state, if this host runs one | `~/aperire-one/advisor/state/` | optional | see [restoring the Advisor](#restore-the-advisor-if-this-host-runs-one): two groups, on purpose | 0750 dir / 0640 files | Its audit ledger, its memory, the read and approve tokens an aggregator reads it with, and which model it is configured for |
| The trusted fleet arm key, if this host is fleet-joined | `/etc/aperire/fleet-arm.pub` | optional | root : root | 0644 | The public key this host checks a pushed model seal against |
| The tokens an aggregator presents to its nodes, if this host is one | `/etc/aperire/fleet-tokens/` | optional | root, group the dashboard and the Advisor share | 0750 dir / 0640 files | A read token per paired node, and an approve token per node with an Advisor, each handed over by that node at pairing and kept nowhere else on this host; without them every node refuses this aggregator's reads |
| The aggregator's private fleet arm key, if this host is one | `/etc/aperire/fleet-arm.key` | optional | root : root | 0600 | Every node paired to this aggregator trusts its public half; a new key means pairing every one of them again |
| Root's pin of the aggregator's fleet trust key, if this host is one | `/etc/aperire/fleet-trust.pub` | optional | root : root | 0644 | The one place root takes the fleet trust key from (#1008); a restore puts it back from here, never from the dashboard's copy of the key |
| The held fleet arm key, if this host was paired before it had an Advisor | `/etc/aperire/fleet-arm.paired.pub` | optional | root : root | 0644 | The key a pairing handed this node (#720), kept until the Advisor install places it; without it, adding the Advisor after a rebuild is the same dead end again, a re-pair or a root line on the node |
| The node's own config | Your node's own `rippled.cfg` and its compose file or unit | yours to place | (yours) | (yours) | Not Aperire's, but a rebuild needs it, and nothing here writes it |

`/etc/aperire/creds`, the sealed model credential, is deliberately not in this list. It is worth reading why before you back anything up: see [restoring the Advisor](#restore-the-advisor-if-this-host-runs-one) below. So is an aggregator's fleet model store (`/etc/aperire/fleet-model.cred`): you seal the fleet model again from Settings on a rebuilt aggregator. And so is `/etc/aperire/fleet-nodes.conf`, root's list of nodes a fleet model may be pushed to: the restore prints the one command that rebuilds it from the restored registry.

`/etc/aperire/fleet-arm.key` **is** in the list. It's the aggregator's private fleet arm key: the key it signs every arm window with, and the one whose public half every paired node trusts. Lose it and every node refuses every arm until you pair it again. Carry it and the set can open an arm window on every one of those nodes. So keep the set where only you can reach it, the same as the tokens it already holds, and never on a share another account can read.

Take the whole set in one command:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --backup
```

Root runs the release's checked copy of the backup program, not the file in your checkout, so nothing a login can change runs as root. Everything after `--backup` is the program's own arguments (`--to <dir>`, `--instance <name>`, `--yes`, `--dry-run`). Add `--dir <install>` before `--backup` if the install is not at `~/aperire-one`.

It discovers what this host has (a dashboard, a co-located relay, an Advisor, a fleet membership, a container or a native node), prints that, prints the plan, takes the database through `VACUUM INTO` (one consistent snapshot while the dashboard keeps writing, never a raw copy of a live WAL database), writes everything else next to it, records what every file's owner, group and mode were (a copy alone loses both), and writes a manifest over the whole set. Then, before it prints success, it reads the set back **as you**, not as root, because a set that only root can read is not a backup:

```
== Aperire One backup
  install: ~/aperire-one
  dashboard: aperire-server (port 7900)
  relay: co-located
  advisor: aperire-advisord
  fleet: aggregator
  node: container (aperire-node) (its config is yours to place, see the README this writes)

== plan
  take  database  (data/aperire.db)
  take  dashboard-config  (dashboard/config/{authn,channels,digest,rules.local}.yaml)
  take  fleet-config  (dashboard/config/{fleet.yaml,fleet-trust.yaml,fleet-link.json,fleet-links.json})
  take  relay-env  (/etc/aperire/aperire.env)
  take  relay-conf  (/etc/aperire/relay.conf)
  take  advisor-state  (advisor/state)
  skip  fleet-arm-key  not present on this host
  take  fleet-tokens  (/etc/aperire/fleet-tokens)
  take  fleet-arm-private-key  (/etc/aperire/fleet-arm.key)
  take  fleet-trust-pin  (/etc/aperire/fleet-trust.pub)
  skip  fleet-arm-held-key  not present on this host
  skip  node-config  (yours to place; see the README)

== copying into ~/aperire-backups/20260919-131144
  ok    database  -> .../aperire.db  (integrity_check: ok)
  ok    dashboard-config  -> .../config/ (4 files)
  ok    fleet-config  -> .../config/ (3 files)
  ok    relay-env  -> .../aperire.env
  ok    relay-conf  -> .../relay.conf
  ok    advisor-state  -> .../advisor-state  (account: aperire-advisord)
  skip  fleet-arm-key  not fleet-joined, or no arm key trusted yet
  skip  fleet-arm-held-key  not fleet-joined, or no key held for a later Advisor
  ok    fleet-tokens  -> .../fleet-tokens (4 files)
  ok    fleet-arm-private-key  -> .../fleet-arm.key  (owner-only; keep this set where only you can reach it)
  ok    fleet-trust-pin  -> .../fleet-trust.pub

== verifying
  MANIFEST.sha256 verifies, read back as aperire

== done: 9 taken, 2 skipped, 0 failed
== set:  ~/aperire-backups/20260919-131144  (41M, owned by aperire, mode 700)
```

Every file in the set is closed to group and other, the database included: this set holds tokens (the relay credential, the Advisor's read and approve tokens, your fleet-link credential if this host has one, and on an aggregator the tokens it reads its nodes with) and, on an aggregator, its private fleet arm key, so it is readable by you and by nobody else. Options:

```
--to DIR       write the set here instead of the default ~/aperire-backups/<UTC stamp>/
--instance     which dashboard/Advisor pairing to back up, on a host running more than one
--yes          skip the confirmation before it starts reading
--dry-run      print the plan, touch nothing
```

Then check the database before you trust it:

```bash
sqlite3 <the set>/aperire.db "PRAGMA integrity_check;"
```

Expect `ok`. Nothing else counts as a backup.

### Restore a host from a backup

This is the rebuild path: the Aperire install is gone, the node is still there or has been rebuilt separately, and you have a set the command above wrote.

This is not the path for an update that went wrong. An update leaves the previous tree and a database snapshot on the box, and going back to those is a different, shorter job: see [rolling back an update](DEPLOYMENT-GUIDE.md#updating).

**1. Install fresh, from the published one-liner, dashboard first and the Advisor after if this host runs one.** If you skip this, the restore command below refuses and names the exact one-liner to run, carrying the port the set recorded. A rebuild that defaults to port 7800 on a host that never used it is how a fleet-joined node goes quietly unreachable while `/healthz` still answers `ok` (#517).

**2. Run the one restore command:**

```bash
curl -fsSL https://get.aperire.one | bash -s -- --restore --from ~/aperire-backups/20260919-131144
```

The restore runs the same way: the release's checked copy, and the state helper it writes every file with is that copy's too. `--yes`, `--overwrite`, `--dry-run`, `--instance <name>`, `--db-path <file>` and `--replace-trust-pin` go after `--restore`. Paths are absolute (a leading `~` is fine, your shell expands it), made of letters, digits and `_ . @ + , : = -`, with no `..`.

Before it touches anything, the whole set is copied into a private, root-owned staging area and validated there: every member is a plain file or a directory nobody else can write, the manifest names everything the set holds and nothing more, and the content matches. `MANIFEST.sha256` verifying only proves the set is complete and unchanged since `aperire-backup.sh` wrote it; it does not prove who wrote it. A set is as trusted as the place it was kept, so keep it somewhere only you can reach, the same as any other file holding your tokens; the directory it sits in is refused if another account on the box could write to it.

Every destination, owner and mode below comes from this host's own install, never from the set: a backup set names content, never a destination. The database's own destination, and the port a closing check tests, are decided from the env file that will actually be in force once the restore lands, never from whatever a plain reinstall happened to write first, and if that file names a database path outside this install's own root, the restore refuses rather than trusting it (exit 8 below); type it yourself with `--db-path` instead, and it is checked the same way any operator input to a privileged script is. An old host's `OWNERSHIP` record is never applied. A recorded mode or owner that disagrees with this host's own table is ignored and reported in one line, for every config file this restores. An account or group the record names that this host doesn't have is reported the same way and never refused: a set taken on a host shaped differently (another operator login, or the Advisor on the other account shape) restores onto this one's own accounts.

It then checks that every account the set names exists on this host (translating the Advisor's own account onto whatever this host's install actually runs it as, never onto the backup's stale name, which is the fix for #515), takes a safety copy of everything it is about to overwrite into a root-owned directory beside the install (printed below, pruned to the last two), stops the services it must, restores the database (written by the dashboard's own account into its own directory, never by root), the config, the relay token pair, the fleet files, the fleet arm key, an aggregator's node tokens and private fleet arm key, and the Advisor's state with the right owner and mode, starts everything back up, and closes with one named check per line. A step that fails after the safety copy stops the restore there: it says what did and did not change, leaves the safety copy in place, and never prints a PASS for a check that did not run.

On an aggregator, three more things come back: `fleet-links.json` (with the fleet config, the dashboard account, 0600), the tokens it reads its nodes with (`/etc/aperire/fleet-tokens/`, root and the group the dashboard and the Advisor share, 0750 and 0640, the group resolved the same way the fleet broker resolves it), and the private fleet arm key (`/etc/aperire/fleet-arm.key`, root : root, 0600). The private key is only ever placed where this host has none. If this host already holds the same key, it's left as it is. If it holds a different one, the restore refuses with exit 9 before anything stops, prints both public halves, and touches nothing: every node paired to the key already here trusts it, and replacing it would cut each of them off. Move it aside yourself only once you're sure it's the wrong one (a pairing approved on the fresh install before the restore makes a new key, for example), and expect to pair any node that trusted it again.

The other way round, an aggregator that lost its arm key but kept its fleet records, the restore is the fix. The fleet broker grant installer refuses to make a missing fleet key on a host that already has paired nodes (exit 4, nothing written), and the page's pairing check refuses to make one too. Both name the restore command. Run the restore, then run the grant installer again: it finds the restored key and keeps it.

Check that the restored key is the right one against a node, not against this host. `aperire-fleet-arm --fingerprint` here reads the same file the restore just placed, so it proves the key is in place, not that it's the key your nodes trust. On any paired node, print the public half it was handed at pairing and compare it with the `public half` line the restore printed:

```bash
sudo openssl pkey -pubin -in /etc/aperire/fleet-arm.pub -outform DER | tail -c 32 | base64 -w0; echo
```

They must match exactly. If they don't, the set held a different key from the one this fleet was paired with: stop, and don't approve a pairing or arm a node until you've found out why.

An aggregator's restore then closes on the thing itself: one of its nodes answering a read. For each node row in the restored `fleet.yaml`, it reads that node's token as the dashboard's account and asks the node's loopback read port for one reading, waiting up to 90 seconds for nodes to redial. One `200` is the PASS, naming the node. None answering is a FAIL with each node's reason, never a PASS. An aggregator with no node but itself gets a SKIP that says so. A node only answers once it has linked again, and a node that dialled this host while it held a links file with no row for that node waits up to an hour before asking again. Restart that node's dashboard and it redials at once.

The fleet arm key comes back in two names when the set carries `fleet-arm.pub`: that content lands at `fleet-arm.paired.pub` too, so the copy an Advisor install would later place cannot be an older, held-over key (#724). A host paired but not yet running an Advisor only ever had the held name to begin with, and that alone comes back; installing the Advisor afterwards places it as `fleet-arm.pub`, the same as it would on a host paired that way for the first time.

```
== Aperire One restore
  install: ~/aperire-one
  from set: ~/aperire-backups/20260919-131144
  dashboard: aperire-server, user aperire, port 7900
  database: ~/aperire-one/data/aperire.db (from this install's own default)
  advisor account: ~/aperire-one/advisor/state goes to 'aperire-advisord' here, this host's own Advisor, not the backup's recorded owner

== safety copy
  ~/aperire-one-restore-safety/20260919T131500Z-4821
  saved: database
  saved: config
  saved: relay-env
  saved: relay-conf
  saved: advisor-state

== stopping services
  stopped: aperire-server, aperire-relay, aperire-advisord

== restoring the database
  ok    database  (integrity_check: ok)

== restoring config
  ok    authn.yaml
  ok    channels.yaml
  ok    digest.yaml
  ok    rules.local.yaml
  ok    fleet.yaml
  ok    fleet-links.json
  ok    aperire.env -> /etc/aperire/aperire.env
  ok    relay.conf -> /etc/aperire/relay.conf
  ok    fleet-tokens  -> /etc/aperire/fleet-tokens (4 files, root : aperire-svc)
  ok    fleet-arm.key  placed, root : root 0600, public half TYFJ423GXw1Q7KUp5ImBfCRRmWOM+LIhSo/hH8nKjvE=

== restoring the Advisor's state
  ok    advisor state, account 'aperire-advisord'

== starting services

== checks
  PASS  units active: aperire-server, aperire-relay, aperire-advisord
  PASS  healthz answers ok
  PASS  the running dashboard has the restored database open, with its content confirmed
  waiting up to 90s for a linked node to answer a read
  PASS  a linked node answers a read from this aggregator: core-two
  PASS  the dashboard's account can read the Advisor's approve.token and read.token
  PASS  the ledger chain verifies (chain_intact)
  model: {"model":{"configured":true,"credential_present":false,...}}

  Next, to bring the model back with no key pasted anywhere (#539), on the
  aggregator, arm both sides and then press
  "Bring up to date" for this host in Settings under your own passkey:

      sudo aperire-fleet-arm --node <this host's label>
      sudo aperire-fleet-arm --self-only

  If aperire-fleet-arm is not found there, that aggregator's fleet broker
  grant predates it: update that aggregator first, then run the same commands:

      curl -fsSL https://get.aperire.one | bash -s -- --update --force

  This restore does not run either command.

  This aggregator's own fleet files are back. Root's record of which nodes
  a fleet model may be pushed to (/etc/aperire/fleet-nodes.conf) is not in
  any set; rebuild it from the restored registry before the next push:

      curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant --refresh-nodes

  This restore never read or wrote your node, its store or its own
  configuration.

== 12 file group(s) restored from ~/aperire-backups/20260919-131144
== safety copy of what changed: ~/aperire-one-restore-safety/20260919T131500Z-4821
```

A second run over a host whose database has not moved on since the set changes nothing and says so: `no files needed to change; this host already matches the set`. A dashboard writes metrics, ledgers and sessions continuously, so this covers the ordinary case of running the command twice in a row with nothing in between, not a host that has actually been used since.

A second run over a host whose database **has** moved on with content of its own is different: an operator enrolled, a passkey registered, something a rebuild cannot regenerate on its own, and not merely a database a fresh reinstall has been polling metrics into for a minute with nobody signed in yet. Overwriting the first kind silently is how a restore rolls a host back without saying so; the second kind is replaced without asking, the same as a fresh install always was. It prints what it is about to overwrite (row counts on both sides, and the newest activity it can find), takes a safety copy first, and then either asks you directly (an interactive run) or refuses with `--overwrite` named as the way past it (`--yes` with no terminal to ask on). Add `--overwrite` once you mean it:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --restore --from ~/aperire-backups/20260919-131144 --yes --overwrite
```

**Refusals.** Each one is a distinct exit code, so a script driving this can tell them apart:

| Exit | Meaning | Remedy |
|---|---|---|
| 2 | Usage error, or the set's `OWNERSHIP` file is not the six-column shape a set from this tool always is | Fix the command line, or take a new set: this one may be hand-edited or from something else |
| 3 | The set itself is the problem: no such directory, no `MANIFEST.sha256`, it does not verify, it holds something other than a plain file or a directory, a path escapes the set, a node token has a name no token has, its `fleet-arm.key` is not an Ed25519 private key, the key in its `fleet-trust.yaml` is not the set's own pin of it, the set is writable by anyone but root and you, or the directory it is kept in is writable by anyone and has no sticky bit | Point `--from` at a real set kept somewhere safe, or take a new one; nothing is touched |
| 4 | This host's own Advisor unit names an account or group that doesn't resolve here; or the Advisor moved to its own account and its unit names no group shared with the dashboard, or names one the dashboard is not actually a member of; or the Advisor's state directory (or something above it) is a symlink, a plain file, or a directory writable by an account that is not its owner; or `/etc/aperire/fleet-tokens` is a symlink or not a directory; or the Advisor and the dashboard share no group to put a node token on; or the database's destination is a symlink, sits in a directory that is a symlink, or is somewhere the dashboard's account can't write; or, on a host where the dashboard runs as its own account, `dashboard/config` belongs to that account or is writable by group or other | Re-run the installer that creates the missing account (the update command printed); re-run `install-advisor-account.sh` if the shared group is missing or wrong; remove or rename a planted symlink; hand the database's directory to the dashboard's account with the `install -d` command printed; re-run `install-aperire-service.sh` to put `dashboard/config` back to the operator; or, if a directory in the chain is too permissive, run the update (`curl -fsSL https://get.aperire.one | bash -s -- --update --force`), which takes group and other write off it from a copy checked against the release, then run this again. Nothing is changed and no service is stopped by any of these |
| 5 | The Advisor cannot be mapped: the set carries one and this host has none, the reverse, or more than one installed Advisor claims the same state directory | Install the Advisor first (the command is printed), remove it if the set was never meant to carry one, or restore each instance from its own set with `--instance` |
| 6 | Aperire is not installed on this host yet | Run the one-liner printed, with the port the set recorded, then run this again |
| 7 | This host's database has content the set does not, and `--yes` was given without `--overwrite` | Read what it printed about what would be overwritten, then re-run with `--overwrite` if that is what you mean, or restore onto a host whose database has not moved on |
| 8 | The set's own env file names a database path that resolves outside this install's own root. A backup set names content, never a destination, and this is refused rather than trusted | Type the destination yourself: `--db-path <abs path>`, checked as any operator input to a privileged script is (absolute, no parent this script would have to invent outside the install, not an existing file that fails to look like a SQLite database) |
| 9 | The set carries an aggregator's private fleet arm key, and this host already holds a fleet arm key the restore can't prove is the same: a different key, something other than a plain file, one `openssl` can't read, or no `openssl` to compare with. Nothing is touched | Compare the two public halves it prints. If the key on this host is the wrong one, move it aside yourself (`sudo mv /etc/aperire/fleet-arm.key /root/fleet-arm.key.replaced`) and run the restore again; any node paired to that key needs pairing again. Install `openssl` if it's missing |
| 9 | The set carries root's pin of the fleet trust key, and this host already pins a different one, or its pin is not a plain file; or the set predates the pin and its key differs from the one pinned here. Nothing is touched | Compare the two keys it prints. Every node paired to this host trusts the key pinned here. If the set carries its own pin and that key is the one you mean this aggregator to use, run the restore again with `--replace-trust-pin`; any node paired to the old key needs pairing again. A set taken before the pin is refused whatever the flag says, because its key came from a file the dashboard account could write: restore from a set taken after this host pinned its key |
| 1 | The restore ran and one or more closing checks FAILed | Read the FAIL line; it names what to check (the database it actually opened, the token pair, the relay's log, the Advisor's unit, or why no linked node answered) |

**What the restore costs you.** Everything written between the backup and the loss. On a host backed up nightly that is a day of history, no operators and no passkeys. The gap shows in the History panel as a flat stretch and nowhere else.

**One thing to fix afterwards.** If your node config sets `advisory_delete`, the rotation timer that goes with it was removed with the old install and reinstalled with the new one. Between the loss and the restore nothing was pruning the node's ledger store. Check the store's size after a restore that took longer than an hour.

### Restore the Advisor, if this host runs one

Skip this whole section on a host with no Advisor: `aperire-restore.sh` needed nothing here, and there is nothing here to put back by hand.

**What the backup carries, and what it deliberately does not.** The command above copies `advisor/state` whole: the audit ledger, memory, the read and approve tokens, and `model.json`, which is configuration (which model, which endpoint, a hint of the key) rather than the key itself. It does not carry `/etc/aperire/creds`, the model API key, even if a wider backup of `/etc/aperire` happens to sweep it up. On a host with systemd 250 or newer that file is sealed with `systemd-creds encrypt` against this specific host's own key in `/var/lib/systemd/credential.secret`, which no backup carries, so it opens only here and only for as long as that key does not change. Putting it back on a rebuilt host, or on any other host, is bytes that will not open, and the failure surfaces as a model that does not answer rather than as a restore that did the wrong thing. On older systemd, Ubuntu 22.04 included, it is the key itself in a root-only file, and a copy would be a working key wherever it landed, which is the stronger reason to leave it out. A rebuilt host is meant to get its model back a different way, see the last step below.

Install the Advisor before you run the restore command, on top of the dashboard you already reinstalled:

```bash
curl -fsSL https://get.aperire.one/advisor | bash -s -- --yes
```

If you forget, the restore command's own refusal names this line for you rather than restoring half of a fleet-joined host.

**Why the ownership needs translating, not copying.** The install lays this directory out in two groups on purpose: the directory itself and the two tokens the dashboard reads (`approve.token`, `read.token`) belong to the shared group the Advisor and the dashboard both sit in, and everything else the Advisor writes for itself (`ledger.jsonl`, `memory.jsonl`, `model.json`, and the rest) belongs to the Advisor's own account. A wipe does not always remove the account the old Advisor ran as, so a plain `chown -R` onto the name the backup recorded can still succeed on the rebuilt host, and it is silent about the damage: every service still starts, and the dashboard reports the Advisor installed-but-down because it can no longer open its token. `aperire-restore.sh` reads the account this host's own Advisor unit actually runs as, and applies it, and this host's own fixed shared group, by name alone: the directory and the two tokens land on the shared group, everything else lands on the account's own group, and the mode and owner the backup's `OWNERSHIP` file happened to record for these paths are never read for this, on purpose, so a set carrying a stale or tampered record cannot widen anything on the rebuilt host. This is the fix for #515 and #537, and it is part of the one restore command above, not a separate step.

**Verify the ledger chain is intact, not merely present.** The restore command's own closing checks include a plain `GET /v1/ledger` with no `since_seq`, which re-verifies the whole file from scratch on every call rather than reading a cached answer: `chain_intact: true`, and `count` matching what you recorded when you took the backup.

**What the aggregator's mirror does.** Nothing you have to drive. On its next poll it reads the same genesis hash it always has for this node, because the ledger file is the same one, restored whole, and resumes appending to the run it already had. It does not open a second run: that only happens when the genesis hash changes, which a restore that put the same file back does not do.

**Bring the model back, with no key pasted anywhere.** A rebuilt host has no sealed credential, whether or not `fleet-arm.pub` came back in the set, and pasting the key again is not the supported path on a fleet-joined node. Two windows have to be open at once, on two different machines: this host's own, so it accepts an incoming push, and the aggregator's own, so it may move the sealed key it is already holding. The restore command's closing checks print both commands and stop there; running them and pressing the button in Settings is the one part of a restore still done by hand:

```bash
sudo aperire-fleet-arm --node <this host's label>
sudo aperire-fleet-arm --self-only
```

Run both on the aggregator. `aperire-fleet-arm` is installed there with the fleet broker grant. If it is not found, that grant predates it: update that aggregator first (`curl -fsSL https://get.aperire.one | bash -s -- --update --force`), then run the same commands.

Then, in the aggregator's Settings page, the Advisor AI model panel, press "Bring up to date" for this host under your own passkey.

Check, on the restored host:

```bash
printf 'authorization: Bearer %s\n' "$({ cat ~/aperire-one/advisor/state/approve.token 2>/dev/null || sudo python3 -I /usr/local/sbin/aperire-state-file read ~/aperire-one/advisor/state/approve.token; } | tr -d '[:space:]')" \
  | curl -fsS -H @- http://127.0.0.1:7810/v1/status
```

The token goes to curl on its standard input (`-H @-`), not as an argument: any account on the host can read a running command's arguments. When the Advisor has its own account, `advisor/state` is `0750` and `approve.token` is `0640` for that account and the shared group. Your login is in neither, so `cat` fails and one `sudo` reads the file through the root-held `aperire-state-file` helper, which opens it without following a link and prints it. Root runs that file, so check it is root's first: `stat -c '%U %a' /usr/local/sbin/aperire-state-file` should print `root` and a mode with no group or other write bit, such as `755`. If it prints anything else, don't run the `sudo`. If the host has no helper, run `curl -fsSL https://get.aperire.one | bash -s -- --update --force` first.

The answer shows `model.configured: true` with the key hint you recorded before the loss. A question answered through the dashboard then gets a real reply rather than "the Advisor has no model."

Three answers to expect if the timing is off, all in the product's own words rather than a bare failure, and none of them means anything was damaged:

- Pressing "Bring up to date" before the first command above answers `reason: unarmed` on this host ("This host is not armed. Arm it first..."). Run the first command and press the button again.
- An arming window on this host left unspent for too long answers `reason: expired` ("The arming window has closed. Arm this host again..."). Same remedy: arm again, press again.
- The first command with no second one answers `reason: arm_closed`, and it comes from the aggregator, not this host: "this aggregator has no sealing window open, so it can move no key. Open one on this aggregator: `sudo aperire-fleet-arm --self-only`, then Catch up." Run the second command on the aggregator and press the button again; re-arming this host does not fix it, because this host was never the one that was shut.

### Move to a new host

Use this when the install moves to a different, long-lived machine: a new VPS, a bigger box, a new provider. I move state, never binaries. The new host gets a fresh install from the published one-liner, then the old host's state goes on top of it.

This section covers only what differs when the target is a different machine. The mechanics are already written, so I link to them instead of repeating them:

- [Back up what a rebuild cannot recreate](#back-up-what-a-rebuild-cannot-recreate): what the set holds and the one backup command.
- [Restore a host from a backup](#restore-a-host-from-a-backup): the restore command, its refusals and its closing checks.
- [Restore the Advisor, if this host runs one](#restore-the-advisor-if-this-host-runs-one): the Advisor's state, and how the model comes back.

**Your node is out of scope.** The backup never touches xrpld, its store or its config, and the restore never reads or writes them. Moving the node itself is a separate job that is yours.

**Size the new host first.**

| What | Size |
|---|---|
| State to move, node host | about 90 MB |
| State to move, aggregator | about 1.3 GB, mostly `data/` |
| A full install: the tree, mostly `dashboard/node_modules` | about 0.4 GB |
| A full install: the Go toolchain and build cache | about 0.4 GB |
| Each update, kept as a previous tree and a database copy until you remove them | about 0.36 GB |

#### The steps

1. **On `<old host>`, take the set.** Leave everything running.

   ```bash
   curl -fsSL https://get.aperire.one | bash -s -- --backup
   sqlite3 <the set>/aperire.db "PRAGMA integrity_check;"
   ```

   Expect `ok`. Note the port on the `dashboard:` line. The new host has to use the same one.

2. **Copy the set to `<new host>`, with its modes intact.** The restore refuses a set that anyone but root and you can write, and a set in a directory that anyone can write.

   ```bash
   ssh <new host> 'mkdir -p -m 700 ~/aperire-backups'
   rsync -a ~/aperire-backups/<stamp>/ <new host>:~/aperire-backups/<stamp>/
   ```

   On an aggregator the set holds the arm key and the node tokens, so treat it like the credentials it is: see [If the aggregator moves](#if-the-aggregator-moves).

3. **On `<new host>`, install fresh, on the same role and the same port.** The one-liner guesses the role from what it finds, and a co-located move whose node is not up yet on `<new host>` would install as `dashboard`. Name it. Use no fleet flags.

   ```bash
   curl -fsSL https://get.aperire.one | bash -s -- --role <co-located|dashboard|relay> --port <port>
   ```

   Do not pass `--fleet-aggregator`. That asks for a new pairing code, and a node that is already paired comes back through the credential the restore puts in place. If `<old host>` ran an Advisor, install it now too, with your node answering on this host:

   ```bash
   curl -fsSL https://get.aperire.one/advisor | bash -s -- --yes
   ```

   The Advisor install asks the node who it is and writes `/etc/aperire/node-key`. If the node was down at that moment, run `curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key` once it answers.

4. **Stop `<old host>`'s services, before the restore.** Two live copies of one install fight over the same identity. See [Two live copies](#two-live-copies-of-one-install) below.

   ```bash
   systemctl list-unit-files 'aperire-*' 'cloudflared-aperire*'
   sudo systemctl disable --now <each unit it lists that this host runs>
   ```

   A split dashboard host has no relay, and a host with no Advisor has no `aperire-advisord`. Name only units that exist. Anything `<old host>` records after the backup is not in the set.

5. **On `<new host>`, restore.**

   ```bash
   curl -fsSL https://get.aperire.one | bash -s -- --restore --from ~/aperire-backups/<stamp>
   ```

   Read its closing checks, as in [the restore section](#restore-a-host-from-a-backup).

6. **On an aggregator, check the arm key.** Run no `aperire-fleet-arm.sh` and approve no pairing on `<new host>` before the restore. Either one makes a new arm key when none exists, and the restore then refuses with exit 9 rather than replace it. After the restore, run the check in [If the aggregator moves](#if-the-aggregator-moves). Skip this step on a node host or a standalone host.

7. **Bring the model back.** On a moved fleet node, run the two arm commands the restore printed and press **Bring up to date** under your passkey. They are the commands in [the Advisor section](#restore-the-advisor-if-this-host-runs-one), unchanged. A different host changes nothing about them: this host's arm key and node key come from the restore and the Advisor install, and the aggregator signs for the node key it has pinned. On a moved aggregator, seal the fleet model again, as [If the aggregator moves](#if-the-aggregator-moves) says. On a host that is not in a fleet, there is nothing to arm. Open **Settings & Updates**, then **Advisor AI model**, paste the key, press **Test**, pick a model and seal it with your passkey. The [Advisor setup guide](ADVISOR-SETUP.md#the-model-in-the-browser) has the four steps.

8. **Repoint the hostname.** The name is yours to move: change the DNS record, or the tunnel route, to point at `<new host>`. The tunnel unit and its credentials are not in the set. Set the tunnel up on `<new host>` with the [tunnel steps](DEPLOYMENT-GUIDE.md#reaching-it-from-the-internet-with-a-cloudflare-tunnel) before you move the route. Then sign in with a passkey, from the new name.

9. **Retire `<old host>`**, once the new one has run a day and you have checked it. Step 4 stopped the services. The uninstall removes them for good: [Uninstalling](DEPLOYMENT-GUIDE.md#uninstalling). What it leaves for you is in [What is still yours to remove](DEPLOYMENT-GUIDE.md#what-is-still-yours-to-remove). Keep the set until then.

#### Passkeys and the hostname

A passkey is bound to the host name the dashboard is reached at, not to the box. `rp_id` and `public_url` in `authn.yaml` set that name, and every ceremony is checked against them. The operators and their passkeys are in the database, and `authn.yaml` is in the set, so both come across with the restore.

| Your hostname | What you do |
|---|---|
| Stays the same | Nothing. Operators sign in with the passkeys they already have. |
| Changes | Set the new `public_url` and `rp_id` in `dashboard/config/authn.yaml`, restart `aperire-server`, and enroll every passkey again. The accounts survive. The old passkeys do not work from the new name. |

To re-enroll, mint a link on the host for each operator: `aperire-auth magic-link <email>`. The [Auth guide](AUTH-GUIDE.md#configuration-reference-dashboardconfigauthnyaml) lists both keys.

**Keep an aggregator's hostname if you can.** Each node's Advisor pins the `rp_id` and origins from the first trust bundle it accepts, and refuses any later bundle that carries different ones. A pushed bundle can never move that pin. A pairing you approve under passkey can, once: the node's pairing command leaves a record in `/etc/aperire/fleet-paired.json`, and the Advisor takes the next passkey list signed by that aggregator under the new name, then notes the change on its own Audit trail. So a new name means pairing every node again once the new name is set, in the order [If the aggregator moves](#if-the-aggregator-moves) gives.

#### The relay

| Install | What happens |
|---|---|
| Co-located | The relay moves with the set. `relay.conf` and the dashboard's env file are both in it. The installer wires the relay to loopback on the dashboard's own port, which is why step 3 uses the same port. Nothing to edit. |
| Co-located set, onto a host with a node and no relay yet | The restore stops before it changes anything, and names the two steps that build the relay and wire it beside the dashboard (`--run prepare-host --role co-located`, then `--run relay-colocated`). Run them, then run the restore again. |
| Co-located set, onto a dashboard-only host | `relay.conf` is left out, with a note. A host with no node has no relay to read it. The dashboard's half of the token pair is in `aperire.env` and is restored as usual. |
| Split, the dashboard moves | The relay lives on the validator host and keeps running. Its token still matches, because `RELAY_TOKENS` is in the restored `aperire.env`. Set `dashboard_url` in the relay's `/etc/aperire/relay.conf` to the new dashboard and run `sudo systemctl restart aperire-relay`. |

On a split install, the dashboard also reaches the node over `RIPPLED_URL` in `aperire.env`, and the node's admin port lists the dashboard host's address. A new dashboard host needs its address in that list, and the firewall rule that goes with it. See [Split: three edits](DEPLOYMENT-GUIDE.md#split-three-edits).

#### The fleet

A fleet node dials the aggregator over the [fleet link](FLEET-GUIDE.md#the-fleet-link). The aggregator holds one record per node: the hash of that node's credential, in `dashboard/config/fleet-links.json`. The node holds the credential, in `dashboard/config/fleet-link.json`, and the aggregator's public key, in `fleet-trust.yaml` under `peers.aggregator`. The aggregator's `fleet.yaml` holds the pin for each node, `expected_pubkey_node`.

**If a node host moves**, the restore puts `fleet-link.json` back, and the node dials the aggregator with the same credential it always had. It does not pair again, and the aggregator needs no change. What the aggregator checks is the node key the pin names, which is the key your xrpld reports.

| Your node's key | What you see |
|---|---|
| The same xrpld, the same key | The row comes back on its own. |
| A different key, because the node was rebuilt too | The row goes red with "its node key is not the one registered". Compare the two keys the page prints, then press **Accept new key** under your passkey. See [Pinning a peer's identity](FLEET-GUIDE.md#pinning-a-peers-identity). After an accept, run `curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant --refresh-nodes` on the aggregator before the node can be caught up on the fleet's model. |

The restored credential is the way back, and it needs no approval. A node that pairs again with a new code under the key a link row already pins shows as a Pending row that says "Its node key matches <name>'s link row, so this may be <name>, back after being offline". One approval reconnects it under that name, with a new credential. See [A node coming back](FLEET-GUIDE.md#a-node-coming-back).

A node the aggregator reaches over an SSH forward instead of a link names the old host in the forward's unit on the aggregator. Point it at `<new host>`: see [An SSH forward](FLEET-GUIDE.md#an-ssh-forward).

##### If the aggregator moves

Each node dials the `aggregator_url` in its own `fleet-link.json`, `wss://<aggregator>/fleet/v1/link`. If the aggregator keeps its hostname, no node changes.

If the name changes, pair each node again, in this order:

1. On `<new host>`, set the new `public_url` and `rp_id` in `dashboard/config/authn.yaml` and restart `aperire-server`.
2. Enroll your passkeys again from the new name, as [Passkeys and the hostname](#passkeys-and-the-hostname) says.
3. Then, for each node, mint a code in **Settings** under the node's own name and run the line it prints on that node. The node's key matches its row, so the Pending row offers **Approve and reconnect**, which keeps the row, its history and its Advisor.

The order matters. The pairing writes the new `aggregator_url`, and it lets that node's Advisor take one passkey list under a new name. If the aggregator still serves the old name when the node pairs, the list that follows the pairing carries the old name, spends that chance, and the node has to be paired once more after the rename. Editing `aggregator_url` by hand links the node, but its Advisor keeps refusing every passkey list the new name sends. See the hostname warning above before you rename an aggregator.

The set carries the fleet config (`fleet.yaml`, `fleet-trust.yaml`, `fleet-links.json`), the tokens the aggregator reads its nodes with, and its private arm key. The restore places them. It places the arm key only where `<new host>` has none, and refuses with exit 9 if one is already there that it cannot prove is the same. See [the restore section](#restore-a-host-from-a-backup).

**Check the arm key against a node.** `aperire-fleet-arm --fingerprint` on `<new host>` reads the file the restore just placed, so it proves nothing about your nodes. On any paired node, print the public half it was handed at pairing and compare it with the `public half` line the restore printed:

```bash
sudo openssl pkey -pubin -in /etc/aperire/fleet-arm.pub -outform DER | tail -c 32 | base64 -w0; echo
```

They must match exactly. If they don't, stop. Approve no pairing and arm no node until you know why.

Three things are still yours:

| Not restored | What you do on `<new host>` |
|---|---|
| The fleet's notes, `advisor/knowledge-fleet` (`local/` and `base/`), and this host's record of what it pushed | The set leaves the notes out on purpose, because a node replaces its copy whole on every push. On an aggregator that copy is the source, and a push from a smaller corpus deletes the difference on every node. So the push asks each node what it holds first, and refuses with nothing sent when it could delete notes under `local/` that this host has no record of delivering. Copy the corpus back from a node as the dashboard's account, because Promote writes there as that account: `sudo -u <dashboard account> rsync -rt <node>:<install dir>/advisor/knowledge-fleet/ <new install dir>/advisor/knowledge-fleet/`. If that account cannot reach the node, copy as yourself and give the files the owner, group and modes of the folder. Then run the push again with `--replace-fleet-corpus` added. The host keeps a record of what it delivers to each node and has none until it has pushed, so after that push Promote and plain pushes work. A node that was down for that push needs the same flag the next time. |
| Root's record of each node and its pinned key, `/etc/aperire/fleet-nodes.conf` | A new host has no fleet broker grant yet, so install it first with `curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant`, then run the same command with `--refresh-nodes`. `--refresh-nodes` on its own refuses on a host with no grant. The restore prints both commands, in order. |
| The fleet's model, sealed on the aggregator, `/etc/aperire/fleet-model.cred` or `fleet-model.cred.plain` | Do not copy it. A sealed copy opens only on the host that made it, and a plain copy is every node's key. Seal the fleet model again from **Settings & Updates**, with the key. |

The set now holds the arm key, which opens a sealing window on every node that trusts it. Move the set between hosts over a channel only you can read, keep it where no other account can, and delete every copy once the new host has run a day.

The nodes did not move, so each one keeps the model it already holds. What is gone is the aggregator's sealed copy of the fleet model, and with it the one-passkey catch-up and what a node paired later inherits. The page shows the arm line the seal needs, and it is the one in step 7.

#### Two live copies of one install

Do not leave both hosts running.

- **A node.** The aggregator keeps one link per node. A second connection with the same credential replaces the first, and the first is closed with "that node reconnected". Two live copies displace each other.
- **An aggregator.** Both copies hold the same signing key and the same registry, and the nodes dial whichever one the name reaches.
- **Pairing.** Approving a pairing while the same node key is live on a link from somewhere else is refused as a copied install: "Two machines holding one node key is a copied install".

Stop the old host's services in step 4, and the old host stops acting for the fleet.

### Prune the SQLite DB

The retention pruner in `db.ts` runs automatically and keeps ~30 days. If the file gets unexpectedly large, inspect:

```bash
# Run from the repo root.
sqlite3 data/aperire.db \
  "SELECT metric, COUNT(*) FROM metrics GROUP BY metric ORDER BY 2 DESC LIMIT 20;"
```

If one metric has far more rows than the others, the writer is running too hot. Most likely a buggy cadence somewhere in `server.ts`. Grep for `writeMetric(` to find it.

### Air-gapped installs

The dashboard makes two infrequent outbound HTTPS calls to public XRPL metadata sites, `api.xrpscan.com` (every 15 min) and `xrpl.org` (once per 24 h), to enrich the Governance tab's Amendments table with XLS-NN tags and one-line descriptions. See [data flow 5](ARCHITECTURE-GUIDE.md#5-dashboard--xrpscan--xrplorg-https-infrequent) for the full details.

If your dashboard host can't make outbound HTTPS (strict egress firewall, dedicated mgmt VLAN, etc.), disable both without touching any other functionality:

1. Edit `dashboard/server.ts`. Comment out the two `setInterval` lines for `pollXrpscanAmendments` and `pollXrplOrgAmendments`, and remove them from the startup `Promise.allSettled([…])` block.
2. Restart the dashboard.

What you lose: the XLS-NN pills next to amendment names and the hover-popover descriptions on the Governance tab. What still works: every other Governance card, the amendment names and hashes themselves (sourced from rippled directly), the Our Vote / Progress / Support % columns, and every other tab on the dashboard.

The pre-shipped `dashboard/knowledge/amendments.yaml` loads at startup regardless of the pollers, so descriptions for amendments known at install time still serve the popover. Only brand-new amendments that appeared after the last network sync go undescribed.

The same comment-out-and-restart pattern applies to the alert delivery channels (Resend, ntfy). They're already opt-in via `dashboard/config/channels.yaml`, so the typical air-gap setup is: leave the channels file empty and comment out the two amendment pollers.

---

## Failure modes and triage

The most common things that break, what they look like, and how to fix them.

| Symptom | Likely cause | Fast diagnostic | Fix |
|---------|--------------|-----------------|-----|
| Tunnel 502 on the public URL | Dashboard process down | `systemctl status aperire-server` | With `Restart=always` it's usually back within 3 s. If it's flapping, check `journalctl -u aperire-server` for the crash reason. |
| `/healthz` returns 503, `rippled_connected: false` | rippled unreachable | `ss -ltnp | grep 6006`; `rippled server_info` | Start rippled. Verify the admin port binding matches `RIPPLED_URL`. |
| `/healthz` returns 503, `rippled_connected: true`, stale `ledger_age_ms` | rippled connected but not streaming (sync stall, admin-only mode) | `rippled server_info | grep state` | Usually resolves on its own as rippled catches up. If state is `disconnected`, investigate the validator's peer connectivity. |
| Network tab Bandwidth / Packets / TCP Retrans blank | Relay not authenticating to `/ingest` | `journalctl -u aperire-server --since '1 min ago' | grep ingest`; `journalctl -u aperire-relay \| tail -5` | Token mismatch. Compare `auth_token` in `/etc/aperire/relay.conf` to `RELAY_TOKENS` in `/etc/aperire/aperire.env`. Restart whichever you change. |
| Network tab populated but `tcp_retrans_per_sec` stuck at 0 | Normal when the network path is clean | none | Not a bug. Zero retransmits is what a healthy path looks like. |
| Bandwidth Live shows `0 B/s` after a long idle | Counter wrap (64-bit on Linux, rare) or recent restart | Check `relay_last_push_ms` on `/healthz` | If the relay just restarted, wait for two pushes (~10 s). The dashboard needs two samples to compute a rate. |
| Repeated OOM restarts in `journalctl` | Dashboard exceeding `MemoryMax=3G` | `systemctl status aperire-server` shows `peak`; `journalctl -u aperire-server -p err` | A stable dashboard process runs under 500 MB; the cgroup total adds the database's page cache. Either a leak or an outsized in-memory history buffer. Investigate before bumping `MemoryMax`. |
| Relay keeps ending sessions with `expected handshake response status code 101 but got 401` | Token mismatch | `grep RELAY_TOKENS /etc/aperire/aperire.env`; `grep auth_token /etc/aperire/relay.conf` | Align the two values. Restart the service whose value changed. |
| Relay keeps logging `connection refused` | Dashboard not listening, or `dashboard_url` points at the wrong host | `curl -I http://<dashboard-host>:7800/` | Start the dashboard. Fix `dashboard_url` in `relay.conf` if wrong. |
| Monthly Budget cell reads `—` | `monthly_budget_bytes` is 0 or unset in `relay.conf` | Hover the card. The tooltip confirms | Set a real cap in bytes and restart the relay. Or leave it unset if you want monitoring-only. |
| Network tab shows wrong interface | Default-route discovery picked an unexpected NIC (common on multi-homed or VPN-first hosts) | Hover the Monthly Budget card. Its `NIC` line is the only place the resolved interface is reported; the journal echoes the configured value, not the result | Override `interface = "eth0"` in `relay.conf`, restart. Hover the card again to confirm it now reads `(config)`. |
| Historical charts empty on 1h / 6h / … but Live works | SQLite write path broken, or the dashboard only started recently | Check `server-err.log`; `sqlite3 aperire.db '.tables'` | Verify the DB file is writable. Check `journalctl` for permission errors. If dashboard uptime is short, wait. The 1h range needs at least an hour of data. |

### A ledger or two missed at the same time every day

I measured this on a lab validator: one to three ledgers missed together (usually two), once a day, at close to the same clock time, on seven consecutive days spread across roughly a fifteen-minute band of that hour rather than one fixed minute. I confirmed the network validated those ledgers fine and this node simply didn't join in, and that the network's own validation traffic never paused across the gap. That rules out a network- or dashboard-side stall: the node itself paused for a few seconds.

On the Consensus tab, this shows as a brief dip in Agreement 1h and the Missed count next to it ticking up by the size of the miss, then recovering within the hour as the window rolls forward. What separates it from a random peer hiccup is that it repeats at close to the same clock time day after day rather than showing up once.

If you see this pattern, look for a daily job on the host that runs around that hour and competes for I/O: log rotation, a backup, a provider-side snapshot, or, if you're running the [scheduled pruning window](DEPLOYMENT-GUIDE.md#make-store-pruning-something-you-schedule), the can-delete timer. Check what's scheduled at that hour before assuming it's the network or the dashboard. I never found the exact cause on the host I measured this on: local timers were ruled out, and the leading theory (a host-level pause outside my control) was never confirmed. If you find the cause on your own host, that's the fix; if you don't, one small miss a day at a fixed time is a much smaller problem than an unexplained one, and worth knowing the shape of rather than chasing further.

### When nothing above fits

1. Grab the last few minutes of logs from all three units: `journalctl -u aperire-server -u aperire-relay -u cloudflared-aperire --since "5 min ago"`.
2. Grab `/healthz`: `curl -s http://127.0.0.1:7800/healthz | jq`.
3. Grab the relay's view: `journalctl -u aperire-relay -n 30`.
4. Check system-wide memory / OOM: `dmesg --since "10 min ago" | grep -iE 'oom|killed'`, `free -g`.

If it's repeatable and you want a second pair of eyes, file an issue with those three blobs.

---

## Residual risks

Things the hardening doesn't catch. Know these even on a well-tuned deployment.

### Host-level memory pressure

`MemoryMax=3G` protects the host from the dashboard. It doesn't protect the dashboard from the host. If the box chronically runs with most of swap in use, any sudden memory demand (cron storms, log batches, `updatedb`) can still trigger system-wide OOM, and the kernel may pick a victim that isn't the dashboard cgroup. Watch swap usage on the System tab. An early outage was driven by exactly this dynamic, before `MemoryMax` was added.

### External alerting

`Restart=always` means a 3-second outage goes unnoticed. A crash loop that restarts every 30 s for 8 hours is also silent without something watching from outside. Point a real uptime monitor at `/healthz` through the tunnel so a crash loop (or a rippled stall) pages someone.

### Secrets hygiene

`/etc/aperire/aperire.env` is `0640 root:<dashboard-user>`. Anyone who can read as `operator` can read the token. That includes any process the `operator` user runs. If you add third-party dependencies to the dashboard node_modules, you're trusting them with that token.

### Amendment-blocked rippled

Aperire One is an observer. If rippled becomes `amendment_blocked`, the dashboard shows it (it's a P0 metric) but can't fix it. The validator stops producing validations until rippled is upgraded. Keep the rippled upgrade process practiced. The Governance tab is your early warning.

Treat rippled patching as a security SLA, not only an availability one. A CVE-affected build is an attack surface, and a build that lags an activating amendment drops you out of consensus. Track releases, upgrade before majority amendments activate, and keep an upgrade dry-run rehearsed. See [OS & rippled patching](HARDENING-GUIDE.md#os--rippled-patching) in the hardening guide for the cadence and the `unattended-upgrades` config.

---

## Related reading

- [Architecture guide](ARCHITECTURE-GUIDE.md): components, data flows, trust boundaries.
- [Deployment guide](DEPLOYMENT-GUIDE.md): full install from scratch.
- [Metrics guide](METRICS-GUIDE.md): what every number on screen means.
- [Relay reference](RELAY-REFERENCE.md): relay-side ops commands, hardening rationale, troubleshooting.
- [Tunnel reference](TUNNEL-REFERENCE.md): Cloudflare tunnel config, DNS, management commands.
