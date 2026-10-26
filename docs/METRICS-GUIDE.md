# Aperire One Metrics Guide

What every panel on the Aperire One dashboard shows: where the number comes from, what a healthy value looks like, and the threshold that trips an alert. Tab by tab, from the operator's seat. This is the doc to hand someone who asks "what does this number mean, and when should I care?"

For the exhaustive metric catalog (every cataloged metric across all domains), see the [metrics catalog](METRICS-CATALOG.md). This guide is the UI-facing subset that's live today. For how metrics are *collected* (the `/proc` paths, the rippled admin commands), see the architecture guide's [data flows section](ARCHITECTURE-GUIDE.md#data-flows).

---

## How to read the dashboard

Aperire One has six tabs. Five carry metrics and are covered here. The sixth, Insights, is the alert and configuration surface.

| Tab | Covers |
|-----|--------|
| Overview | Splash view. "Is anything on fire right now?" |
| Consensus | Is this validator doing its job. |
| Network | Peer topology and the network pipe. |
| System | Compute, memory, disk, process health. |
| Governance | Amendment lifecycle and UNL health. |
| Insights | Alerts and configuration (not covered here). |

Within each non-Overview tab, metrics stack by priority tier, urgent on top:

- **P0**: large cards, always expanded. "Is anything on fire?" at a glance.
- **P1**: medium cards with trend sparklines.
- **P2**: diagnostic detail, collapsed by default.

### Severity convention

Used across this guide and on the dashboard itself.

| Severity | What it means | How the dashboard shows it |
|----------|---------------|----------------------------|
| **Page** | Wake someone up at 3 am. Consensus or node state is actively broken. | Red pill / red value text. |
| **Critical** | Same-day action required. Not yet on fire but trending there. | Orange pill / orange value text. |
| **Warn** | Investigate when convenient. Not normal but not urgent. | Yellow pill / yellow value text. |
| **OK** | Within expected range. | Default color / green pill. |

Thresholds below are defaults. Operators can override per metric.

### Data sources, at a glance

| Source key | Flow |
|------------|------|
| **rippled stream** | `subscribe` streams: `ledger`, `validations`, `server`, `peer_status`, `manifests`. Pushed to the dashboard by rippled. Sub-second cadence. The firehose `transactions` stream is deliberately not subscribed: at network rates it overflows the admin port's send queue and the node drops the dashboard as a slow consumer. |
| **rippled admin RPC** | `server_info`, `peers`, `consensus_info`, `feature`, `fee`, `validator_list_sites`, `validators`, `get_counts`, `ledger`. Polled on cadences from 2 s to 10 min. |
| **aperire-relay** | `/proc/net/*` counters on the validator host, pushed every 5 s. Feeds the **Network** tab (bandwidth, TCP errors, port connections). |
| **dashboard host** | The dashboard reads `/proc`, `/proc/<rippled-pid>`, `statfs()`, and `/proc/diskstats` on its own host every 5 s. Feeds the **System** tab. Accurate only when the dashboard runs alongside rippled (co-located). |
| **derived** | Computed in the dashboard from one or more of the above. Agreement %, monthly bandwidth totals, latency percentiles. |

---

## Overview tab

Splash view. A static validator info panel centered in the peer ring, with one P0 strip beneath it that answers "is anything on fire right now?" No deep diagnostics. Those live on the other four tabs.

### Is-anything-on-fire strip (P0)

| Cell | Shows | Healthy | Fires |
|------|-------|---------|-------|
| **State** | `server_state` from `server_info`: `proposing` / `full` / `tracking` / `syncing` / `connected` / `disconnected`. | `proposing` (validator) or `full` (stock node). | Not-expected for >60 s → **Critical**. `disconnected` >60 s → **Page**. |
| **Ledger** | Latest validated ledger sequence from the `ledger` stream. | Monotonically increasing. | Not advancing for >10 s → **Critical**. >30 s → **Page**. |
| **Ledger Age** | Seconds since last validated ledger. | 0 to 5 s. | >5 s for 30 s → **Warn**. >10 s → **Critical**. |
| **Peer Count** | Total connected peers. | 20 to 100, config-dependent. | <5 → **Critical**. =0 → **Page**. |
| **Upgrade Status** | Derived: `Current` / `Ahead` / `Behind`, from our `build_version` vs. the mode version among connected peers. Combined with `amendment_blocked`. | `Current` or `Ahead`. | `Blocked` → **Page**. `Behind` with >25% of peers ahead → **Warn**. |
| **Amendment Blocked** | `server_info.amendment_blocked`. | `false`. | `true` → **Page** (node is offline until rippled is upgraded past the required amendment). |

### Validator panel + peer ring

A static, role-aware info panel (validator vs stock node) sits at the center of the diagram, with the peer ring around it. The panel shows live server state, current ledger, ledgers since restart, version, network, uptime, base fee, amendments, time drift, UNL active, host, domain (with a verification ✓ when the domain's `xrp-ledger.toml` matches the validator's master key), and the validator + node public keys. Each row has a round `(i)` info-tip and a copy button. Fields a stock node doesn't expose render as `<n/a>`.

The peer ring places every connected peer as a dot around the panel, colored by country. Peer detail (host, location, latency, version, connected time, and any issues) surfaces on a hover/tap tooltip. Motion is GPU-cheap CSS only (a breathing state pill, gently floating peers) and is disabled under `prefers-reduced-motion`. No thresholds. It's a situational-awareness view.

### Sliding ledger ticker

Recent validated ledgers (sequence, close time, txn count) slide left across the bottom. A reassuring signal that the node is keeping up, not a threshold-bearing metric.

---

## Consensus tab

The core of "is this validator doing its job."

### P0: Consensus essentials

| Panel | Shows | Healthy | Fires |
|-------|-------|---------|-------|
| **Close time** | `last_close.converge_time_ms`, time to converge on the last ledger. | 2000 to 4000 ms. | >6000 ms sustained → **Warn**. >10 000 ms → **Critical**. |
| **Agreement 1h** | % of our validations that matched the validated ledger in the last hour, plus absolute counts (agreed / missed). | 100%. | <99% → **Warn**. <97% → **Critical**. <95% → **Page**. |
| **Agreement 24h** | Same as 1h but over 24 hours. Smooths out short dips. | 100%. | <99.5% → **Warn**. <99% → **Critical**. |
| **Validation rate** | Our validator's emitted validations per minute. | 14 to 16/min. | <10/min → **Critical**. Zero for 2 min → **Page**. |
| **Ledgers / min** | Network-wide ledger close rate, 1-min rolling. | ≥9/min. | =8 → **Warn**. <8 → **Critical**. |

### P1: Ledger and chain state

| Panel | Shows | Healthy | Fires |
|-------|-------|---------|-------|
| **Ledger index** | Latest validated ledger sequence. Streaming. | Monotonically increasing. | Not advancing for >10 s → **Critical**. |
| **Complete ledgers** | Local history range string. | One contiguous range. | `"empty"` → **Page**. Any gap → **Critical**. |
| **Txn count** | Transactions in the last validated ledger. | 10 to 500, variable with load. | Informational. |
| **TPS (1m rolling)** | Transactions per second, derived from the ledger stream. | 5 to 50, network-dependent. | Informational. |
| **IO latency** | rippled's internal IO latency estimate. | <5 ms. | >100 ms sustained → **Warn**. >1000 ms → **Critical**. |
| **Base fee / Reserve base / Reserve inc** | Current network fees. | Matches network defaults. | Protocol-driven changes are informational. Fee escalation is a P1 warning. |
| **Load factor** | `server_info.load_factor`. | 1.0. | >1.0 sustained → **Warn**. >10 → **Critical**. |

### P2: Diagnostics (collapsed by default)

- **State accounting:** cumulative microseconds per state (`proposing`, `full`, `tracking`, etc.). Helpful for post-incident reconstruction.
- **Consensus phase:** `open` / `establish` / `accepted`. Cycles normally. Stuck in `establish` >8 s is abnormal.
- **Job-queue internals:** pending job counts per type from `get_counts`. Growing backlogs mean the node is running hot.

### How rates are computed

- **Agreement %**: I subscribe to `validations` (all validators) and `ledger` (validated ledgers). For each validation from our own `pubkey_validator`, I check whether it matched the ledger that closed. An 8-second grace plus a 5-minute reconciliation window keeps a late-arriving validation from counting as missed.
- **TPS**: derived from each closed ledger's own `txn_count`, sampled over a 1-minute rolling window. Spikes show through.
- **Ledgers / min**: count of `ledgerClosed` events over a 1-minute rolling window.

---

## Network tab

Peer topology and the literal network pipe.

### P0: At a glance

| Panel | Shows | Healthy | Fires |
|-------|-------|---------|-------|
| **Peer Overview** | Peer count (Total / Inbound / Outbound), insane-peer count, upgrade-status pill. | 20 to 100 total. 0 to 2 insane. | <5 peers → **Critical**. =0 → **Page**. >5 insane sustained → **Warn**. |
| **Peer Quality** | Upgrade status pill + latency percentiles (p50, p90, p99) + ahead-peer count/%. | p50 <100 ms. p90 <250 ms. | p50 >500 ms → **Warn**. p90 >1000 ms → **Warn**. |
| **Bandwidth Live** | Ingress / egress bytes per second, RX/TX packets per second, TCP Established, TCP Retransmits per second. | Matches traffic envelope. Retransmits near 0. | Sustained >80% of link cap → **Warn**. Retransmits ≥50 segs/s → **Warn**. |
| **Errors & Budget** | RX/TX errors, RX/TX drops, monthly bandwidth % (if cap set), TCP TIME_WAIT. | Errors = 0. Drops = 0. | Non-zero errors → **Critical**. Non-zero drops sustained → **Warn**. Budget ≥95% pre-month-end → **Critical**. |

### Data provenance

Everything on this tab except peer list + latency comes from **aperire-relay**, not rippled.

- **Bandwidth Live / Errors & Budget** → `/proc/net/dev` + `/proc/net/snmp` + `/proc/net/sockstat`, pushed by the relay every 5 s. The dashboard diffs consecutive pushes to compute rates. The **Monthly Budget** tooltip shows `NIC <iface> (<source>)`, where `source` is `auto` (default-route discovery) or `config` (if `interface = "eth0"` overrides it in `relay.conf`).
- **Peer Overview / Peer Quality** → `admin:peers` polled every 30 s. Latency percentiles are computed in the dashboard from `peers[].latency`.
- **Ahead Peers** → derived from comparing our `build_version` against connected peers' versions. A high ahead % signals an upgrade is due.

### History panel (bucketed sparklines)

Eight charts in a 2×4 grid. Range toggle: Live / 1 h / 6 h / 12 h / 24 h / 7 d / 30 d.

- **Row 1, port connections:**
  - **Admin Connections** *(left)* overlays `HTTP RPC` + `WS Admin`. Similar scale (usually 0 to 10 concurrent), shared Y-axis. Each series shows a `PEAK N` pill in the legend with the max count over the selected range.
  - **Public Connections** *(right)* overlays `Peer` + `WS Public`. Similar scale (peer 50 to 200 typical, WS public is operator-configured), shared Y-axis. Same per-series `PEAK N` pill.
- **Row 2, network pipe:** Bandwidth (rx + tx bps) *(left)* | Peer Count (total + inbound + outbound) *(right)*.
- **Row 3, network pipe:** Packets/sec (rx + tx pps) *(left)* | Peer Latency (p50 + p90) *(right)*.
- **Row 4, error signals:** TCP Retransmits (segs/s) *(left)* | Insane Peers (count) *(right)*.

Live mode draws from a 5-minute in-browser rolling buffer fed by the WebSocket. Range modes query the `/history` endpoint, which returns bucketed averages from SQLite. Chart totals differ by metric type:

- **Rate metrics** (bandwidth, packets, retransmits) integrate the series trapezoidally, e.g. "3.2 GB moved in the last hour" on Bandwidth.
- **Count metrics** (port connections, peer count) use `totalMode: 'peak'`, the max value over the visible range. Single-series charts show a single `PEAK` badge. Multi-series charts (Admin / Public Connections) render one `PEAK N` pill per series inline with its legend entry.

Port connection counts come from **aperire-relay**'s `/proc/net/tcp` scanner. Ports are auto-detected from `rippled.cfg` at relay startup. See [Port connection monitoring](RELAY-REFERENCE.md#port-connection-monitoring) for the classification rules and container-namespace handling.

First-boot note: bandwidth / packets / retransmits need **two** relay pushes before they render a rate (cumulative counter minus cumulative counter needs two samples). Expect ~10 s of blank cards after a fresh restart. Connection counts are instantaneous and populate on the first push.

---

## Governance tab

Amendment lifecycle and UNL health.

### P0: Amendments

| Panel | Shows | Healthy | Fires |
|-------|-------|---------|-------|
| **Amendment blocked** | `server_info.amendment_blocked`. | `false`. | `true` → **Page** (emergency upgrade, node is offline). |
| **Approaching-threshold count** | Pending amendments with ≥80% validator support. Triggers the 2-week activation countdown. | 0. | ≥1 needing operator action → **Critical**. |
| **Our build supports / vetoes** | Composite of `feature` output filtered by `supported` + `vetoed` + `enabled`. | Matches operator policy. | Drift from intent → **Warn**. |

### P1: Per-amendment detail

For every pending amendment:

- **Support %**: percentage of trusted validators currently signaling yes. Tracking toward 80% or stalling.
- **Threshold met**: boolean, true when support has been ≥80% for ≥2 weeks.
- **Days to activation est.**: derived from the 2-week window and current support trajectory.
- **Our vote**: `yes` / `no` / `default`, from `admin:feature.vote`.

Layout is one stacked table, not one panel per amendment. The hash list can get long.

### P0: UNL health

| Panel | Shows | Healthy | Fires |
|-------|-------|---------|-------|
| **UNL validator count** | Trusted validators in the effective UNL. | 34 to 35 on mainnet (publisher-dependent). | Unexpected change → **Critical**. |
| **Publisher refresh status** | Per `[validator_list_sites]` entry: last refresh status (`accepted`, `same_sequence`, `invalid`, `stale`, `unknown`). | `accepted` / `same_sequence`. | `invalid` / `stale` / `unknown` → **Critical**. |
| **Publisher list expiry** | Days until the published UNL expires. | >7 days. | <7 → **Critical**. <2 → **Page**. |
| **Active validator count** | Trusted validators we've seen a validation from in the last hour. | ≈ `unl_validator_count`. | <quorum → **Page**. |

### Operator playbooks

Copy-paste-able decision tables on the tab itself. Source tables in the [metrics catalog](METRICS-CATALOG.md).

- New amendment at 50% → add to watchlist.
- New amendment at 80% → 2-week countdown. Verify build support within 48 h.
- Amendment at 80%, build doesn't support → upgrade now or explicit `veto`.
- `amendment_blocked = true` → emergency upgrade, node offline until resolved.
- Publisher list expires in <48 h → switch to secondary publisher or add manual UNL.

---

## System tab

Compute, memory, disk, and process health. Two sources feed this tab:

- **CPU, memory, swap, disk, pressure, OOM kills**: the relay's `system` frame, read on the validator host. When no relay feeds the dashboard, the dashboard's own `/proc` and `statfs()` instead. In a split deployment these rows describe the validator as long as the relay is reporting; if the relay stops, they show a dash rather than the dashboard host's numbers.
- **rippled process stats, clock, disk IO, inode usage, host uptime, entropy, NuDB size**: the dashboard's own host (`/proc/<rippled-pid>`, `/proc/diskstats`, `timedatectl`, `RIPPLED_DATA_PATH`). Accurate when the dashboard runs alongside rippled (Shape A). In a split deployment treat those rows as describing the dashboard host.

### P0: Health headlines

| Panel | Shows | Source | Healthy | Fires |
|-------|-------|--------|---------|-------|
| **CPU busy** | `1 - idle` from `/proc/stat`. | validator host via the relay; the dashboard's own `/proc` when no relay feeds it | <70%. | >85% for 5 min → **Warn**. >95% for 10 min → **Critical**. |
| **CPU iowait** | `iowait` share from `/proc/stat`. | same as CPU busy | <5%. | >15% sustained → **Warn**. >30% → **Critical**. |
| **Memory used %** | 1 − (MemAvailable / MemTotal). | same as CPU busy | <80%. | >90% → **Critical**. |
| **Page cache %** | MemAvailable − MemFree, as a share of MemTotal: the reclaimable file cache the kernel is holding. Used + cache + free is the whole of RAM. On a box running the node it is mostly node-store pages, so a large number is the healthy state and a collapse is the reads about to go to disk. | same as CPU busy | Large, and stable. | Nothing. There is no value at which a page cache is wrong; the shape is the signal. |
| **Swap used %** | SwapUsed / SwapTotal. | same as CPU busy | Steady, unchanging, on any role: a long-running host parks pages in swap and holds them there. | ≥40% for 10 min, and climbing or actively paging (`vmstat 1` si/so above zero) → **Warn**, on every role. ≥50% → **Critical**. Change either rule in `rules.local.yaml`. |
| **Disk used** | `statfs()` of the relay's `data_mount` (the volume rippled's database sits on); `DATA_MOUNT` from the dashboard env when no relay feeds it. | same as CPU busy | <75%. | >85% → **Warn**. >95% → **Page** (data mount). |
| **PSI CPU / Memory / IO** | Pressure Stall Information: tasks waiting on each resource (`/proc/pressure/*`). | same as CPU busy | CPU <5%, Mem <1%, IO <5%. | Varies per-resource. IO >50% → **Critical**. |
| **NTP sync / time drift** | NTP sync state + absolute offset, from `timedatectl` and `chronyc` on the host. Listed as P0 because rippled's consensus tolerates only small clock skew. | dashboard host | synced, \|drift\| <50 ms. | \|drift\| >500 ms → **Critical** (consensus risk). |

### P1: Rippled process

| Panel | Shows | Source | Healthy | Fires |
|-------|-------|--------|---------|-------|
| **rippled CPU %** | Process CPU from `/proc/<pid>/stat`. | dashboard host | Matches load. | Unexpectedly pinned → **Warn**. |
| **rippled RSS** | Resident set size from `/proc/<pid>/status`. | dashboard host | Matches `node_size` config. | Unbounded growth → **Critical**. |
| **rippled open FDs** | `/proc/<pid>/fd/` count. | dashboard host | Well under `ulimit -n`. | >80% of limit → **Warn**. >95% → **Critical**. |
| **rippled uptime** | Time since rippled started, from `/proc/<pid>/stat` `starttime`. | dashboard host | Stable, long. | Unexpected reset → **Warn**. |

### P1: Disk and IO

Sourced by the dashboard from `/proc/diskstats` and a walk of the directory named by `RIPPLED_DATA_PATH` in the dashboard's env file (the installer detects it; the relay plays no part). A dashboard without the setting shows the NuDB rows as "not set" and the NuDB Storage chart names the fix: run the update on that host (`curl -fsSL https://get.aperire.one | bash -s -- --update --force`), which sets it and offers the restart. A path that is set but cannot be read shows as "unreadable" with the error.

On a node installed from its vendor's package the state directory is private to the node, and the dashboard's own account cannot open it. The dashboard does not take access to it: the host's Advisor measures the store through the privilege wrapper, and the dashboard shows that size with an icon beside it that says the Advisor measured it. It records each reading into its own NuDB size series, so the peaks, growth and free days fill from the Advisor's readings. They are fitted from those readings alone, and only readings of the store the dashboard is configured for are recorded. A host with no running Advisor keeps the "unreadable" note, and the rows stay unmeasured.

- **Disk IOPS** (read / write) per device, from `/proc/diskstats`.
- **Disk throughput** (bytes/sec read / write) per device.
- **Disk IO util %**: time the device is busy. >90% sustained → **Warn**. Pegged at 100% → **Critical**.
- **Data mount**: which filesystem every disk figure on this tab describes, from `statfs(path)`.
- **Avg write size**: Disk throughput's write side divided by Write IOPS, from the same sample. Small is NuDB's ordinary random writes; a large jump is bulk sequential writing, such as an `online_delete` rotation or a copy job. Reads a dash while Write IOPS is 0.
- **NuDB size**: directory walk of `RIPPLED_DATA_PATH`, or the host's Advisor reading where the dashboard's account cannot open the store. Flatlining while ledgers keep closing means rippled can't write. Critical symptom.
- **NuDB storage history**: the same walk, charted, with the daily peaks read out beside it (peak 24 h, peak 7 d, peak growth per day, last rotation, and growth per ledger). On a node running `online_delete` the series is a sawtooth; the peaks are the part that carries a trend.
- **NuDB 24h peak**: high-water mark over the last 24 hours.
- **Mount free days**: `(free bytes) / (peak growth per day)`. The growth rate is a least-squares fit of the store's DAILY PEAKS over the retained window, not the difference between two readings. Peak to peak is the only slope that means anything on a node running `online_delete`: the store walks a sawtooth, and two samples either side of a rotation say nothing about the trend. Three answers, and none of them is a dash:
  - **not growing**: the peaks are flat or falling. The normal state of a pruned validator, and green.
  - **needs 2 days**: fewer than two daily peaks of the store are on record yet.
  - a number: >30 days is green, 15-30 → **Warn**, ≤14 → **Critical**.

### P2: rippled internals

From `admin:get_counts`. Diagnostic-grade.

- **Cache hit rates:** AL, SLE, node reads. All should sit >90%. Persistent <70% correlates with IO pressure. These three are cumulative since the process started, and the dashboard labels them so: rippled computes them as hits over hits+misses for the life of the process, which settles within hours of a start and barely moves when a cache begins missing today.
- **Node store history**: the same counters as a rate. The dashboard differences `node_reads_total`, `node_reads_hit`, `node_writes`, `node_read_bytes` and `node_written_bytes` between polls and charts the read hit rate FOR THE INTERVAL, with reads and writes per second and bytes per second beside it. A pair of samples that spans a rippled restart is discarded rather than clamped, so a restart leaves a gap rather than a cliff. Two of those counters, `node_reads_hit` and `node_read_bytes`, are 32-bit in rippled and roll over (at 7 MB/s of store reads, `node_read_bytes` rolls over every ten minutes); the dashboard reads a rollover as the advance it made, and takes the three 64-bit counters as the restart tell. `get_counts` is read every minute, so the rollover is read correctly up to 72 MB/s.
- **Cache sizes:** AL, SLE, NodeObject, LedgerNode, AccountState, TreeNode. Stable is good. Unbounded growth correlates with RSS pressure and can be an early memory-leak signal.
- **Job queue:** from `server_info.load.job_types`, summed across every queue type: Jobs In Progress is the sum of `in_progress`, Job Queue is the sum of `waiting`. rippled omits a counter that is zero, so a missing key counts as 0 and a healthy validator reads 0, not a dash. A growing Job Queue is the tell that rippled is under-provisioned. Both rows sit in the Ops column of rippled Internals next to load factor, peer count and server state, and on a peer they read n/a: `server_info` is not part of the read route.
- **`write_load`:** pending ledger writes. Near-zero most of the time. Sustained >0 means IO can't keep up.

### P2: Data integrity

- **Shard count** (if sharding configured) and per-shard completion %.
- **Ledger walk errors**: scraped from the rippled log (planned).
- **Ledger integrity check status**: from the last `ledger_cleaner` pass.

### Threshold redlines on History charts

The System history charts (CPU & Load, Memory & Swap, Disk IO, rippled Resources, NuDB Storage, Node Store) render dashed horizontal reference lines at each series' warn / critical thresholds. Amber for warn, red for critical. Most come from `METRICS-CATALOG.md` and are the same on every host. The swap line is the exception: it is read from the alert rule the host is actually running, so it moves with your `rules.local.yaml` override of it. The Y-axis auto-expands to keep redlines visible even when data is well below warn, so a glance answers "how much headroom do I have before trouble?"

Current threshold values in use:

| Series | Warn (amber) | Critical (red) |
|---|---|---|
| `cpu_busy_pct` | 85 | 95 |
| `mem_used_pct` | 80 | 90 |
| `swap_used_pct` | this host's own rule | this host's own rule |
| `cpu_iowait_pct` | 15 | 30 |
| `pressure_io` | 25 | 50 |

The swap redline follows the host's own swap rule, so it lands at 40% on every role by default, and at whatever you set if you override it in `rules.local.yaml`. Hover the chart title to see the numbers it is drawing and where they came from.

Three cases draw no swap redline at all, and the hover text names which one you are in:

- The host has no swap rule. Nothing would fire, so nothing is drawn.
- The dashboard could not read the host's rules. That is not the same as there being none, and it is not reported as none.
- You are viewing another node. Alert rules are read on each host, so drawing this box's threshold under another box's numbers would be wrong. Open that node's own dashboard to see its swap redline.

rippled Resources (`rippled_cpu_pct`, `rippled_rss_pct`), NuDB Storage and Node Store carry no redlines. The catalog describes those as "matches load" / "unbounded growth" rather than fixed bands, so anything drawn would be guessing.

The charts are history and nothing else. Every live reading is in the panel above that owns it: the load average, cores in use and CPU steal on the CPU & Load card, disk IOPS, throughput and IO latency in the Disk I/O column of Host Diagnostics, and the node-store rates, write load, job queue, load factor, peers and server state in rippled Internals. The one exception is NuDB Storage, whose readouts (peak 24 h, peak 7 d, growth per day, mount free days, last rotation, per ledger) are each a reading of that chart's own history and sit under it.

### Collection mechanics

Every metric on this tab is read by the dashboard from `/proc/*`, `statfs()`, and `/proc/diskstats` on the host it runs on. No `node_exporter` dependency. Full file-by-file table: [Metrics catalog: Collection mechanics](METRICS-CATALOG.md#appendix-collection-mechanics).

---

## What's visible now vs. what's planned

The architecture covers a larger metric catalog than what's wired to panels today ([metrics catalog](METRICS-CATALOG.md)). Current status:

| Tab | Live cards | Planned |
|-----|-----------|---------|
| Overview | P0 strip, peer ring, ledger ticker | Splash polish, role-aware collapsing for stock nodes |
| Consensus | P0 + P1 wired to live data, history panel live | P2 state-accounting detail cards |
| Network | All P0 + P1 live against real peers + relay | Monthly budget alerting, country-diversity panel |
| Governance | Baseline wired | Per-amendment table, publisher-site detail, cert-expiry probe |
| System | P0 + P1 wired (CPU, mem, swap, PSI, disk, rippled process, NuDB) | `get_counts` panels, log-parsed integrity checks |

Alert delivery (email, ntfy push, and Discord / Slack / generic webhooks) is configured on the Insights tab and in `channels.yaml`. See the [alerting guide](ALERTING-GUIDE.md). External uptime monitors pointed at `/healthz` cover the one thing in-app alerting can't: a dashboard that's itself down.

---

## Related reading

- [Architecture guide](ARCHITECTURE-GUIDE.md): where each metric's data flow actually runs.
- [Operational guide](OPERATIONAL-GUIDE.md): triage when a panel goes blank.
- [Metrics catalog](METRICS-CATALOG.md): the exhaustive metric catalog. Collection mechanics (per-metric paths, NIC discovery, monthly-budget accounting, push cadence) live in the appendix.
