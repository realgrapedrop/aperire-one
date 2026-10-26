# Field Guide — monitoring, database and operational settings

Distilled from The Rippled Field Guide (github.com/realgrapedrop/rippled-field-guide),
the operator's own published guide. Treat as Documented. Full guide at the repo.

The software is xrpld, called rippled until 3.2.0, which renamed the binary,
the config path and the data path (see the releases note). Names and paths below are the
xrpld package's, checked 2026-10-22 against its source at tag 3.4.1. A node older than
3.2.0, or a fork that kept the old names, uses different ones: read the real path from the
node's own config before acting on one written here.

`xrpld <command>` means however the node reaches the binary: `xrpld --conf
/etc/xrpld/xrpld.cfg -q <command>` natively, with `docker exec <container>` in front on a
container deployment.

## Monitoring

You can't fix what you can't see. Monitor:

- **Server state**: Should be `proposing` (validator) or `full` (stock node). Alert on `disconnected`, `connected`, or `syncing`.
- **Agreement percentage**: Your votes vs. consensus outcome.
- **Resource utilization**: CPU, memory, disk I/O, network.
- **Peer connections**: Healthy count, no sudden drops.
- **Ledger sync**: Are you keeping up with the network?

For a turnkey solution, the [XRPL Validator Dashboard](https://github.com/realgrapedrop/xrpl-validator-dashboard) provides full-service monitoring built specifically for validator operators. It tracks 40+ rippled metrics via WebSocket and HTTP APIs *plus* system metrics (CPU, memory, disk I/O, network). Includes pre-configured alerts for critical states and supports Discord, Slack, PagerDuty, and other notification channels. Deploys as a single Docker stack - no libraries or dependencies on your rippled machine. Can run on a separate machine entirely for better security (see [Hardened Architecture](https://github.com/realgrapedrop/xrpl-validator-dashboard/blob/main/docs/HARDENED_ARCHITECTURE.md)).

Prometheus + Grafana is an alternative for system metrics, but you'll need additional tooling to monitor xrpld-specific metrics like server state, agreement percentage, or peer connections.

**Quick Diagnostics**

```bash
# Check server status
xrpld server_info

# Health check (the peer port: 51235 where Aperire installed the node, 2459 on the package default)
curl http://localhost:<peer-port>/health

# Check if amendment blocked
xrpld server_info | grep amendment_blocked
```

### Understanding load_factor

`load_factor` is one of the most-watched and most-misread fields in xrpld's API output. Operators new to xrpld often assume any value above 1 means something is wrong. It doesn't.

**What it is**

`load_factor` is xrpld's internal busyness multiplier. It's the input to the network's fee market. When transaction volume rises, xrpld raises `load_factor` and the open-ledger fee scales with it, throttling spam and prioritizing willing-to-pay transactions. The mechanism *requires* `load_factor` to react quickly to short bursts of activity, so the metric is sensitive by design.

A spike to 30 or 40 for a few seconds is not a problem. The XRPL network is bursty — NFT mints, payment surges, exchange sweeps all cause load to climb briefly across every validator simultaneously, then settle. Treating brief spikes as alerts produces false positives and alert fatigue. Sustained periods (minutes, not seconds) above baseline are the actionable signal.

**`server_info` vs `server_state` — different views of the same number**

xrpld exposes load metrics through two related API methods:

- **`server_info`** returns a normalized form: `load_factor: 1.0` for an idle server. Easier to read at a glance — most monitoring tools display this view.
- **`server_state`** returns the raw form alongside a baseline: `load_factor` and `load_base` as integer fee levels. The actual cost multiplier is `load_factor / load_base`. On an idle server both equal `256`, so the multiplier is `1.0`.

`server_state` also exposes a richer breakdown of where the load is coming from. For day-to-day monitoring, `server_info` is enough. For diagnosing *why* `load_factor` is high, `server_state` is the better entry point.

**Reading the number** (normalized view from `server_info`)

| Range | Interpretation |
|---|---|
| 1 – 5 | Quiet to lightly busy. Normal for most of the day. |
| 5 – 30 | The network is processing real volume. NFT drop, payment surge, exchange activity. Common; lasts a few minutes; settles on its own. |
| 30 – 64 | Sustained busy. If it lasts more than a couple of minutes, something real is happening — could be a network event, could be your host slowing down. |
| 64 – 100 | Real fee pressure. Fees are climbing, the queue is filling. |
| 100+ | xrpld has entered fee escalation. It's actively rejecting RPCs and charging much higher fees. The "I am genuinely overwhelmed" signal. |

**The composition — what `load_factor` is the max of**

Per the `server_info` documentation, `load_factor` is the highest of four components:

```
load_factor = max(
  server's load factor   (load to your host, cluster, and network combined),
  cluster's load factor  (when running clustered nodes),
  open ledger cost       (the fee market bidding cost up),
  network's load factor  (overall network demand)
)
```

`server_state` exposes useful aggregates of these:

- **`load_factor_server`** — composite of host + cluster + network load, *excluding* the open-ledger fee escalation. If this is high, the source is real congestion or local pressure, not just fee bidding.
- **`load_factor_fee_escalation`** — open-ledger fee market multiplier. If this is high but `load_factor_server` is at baseline, the network is fee-bidding but the actual workload is fine.
- **`load_factor_fee_queue`** — multiplier to get into the queue when it's full. Rises during real fee escalation.
- **`load_factor_fee_reference`** — the base cost with no load scaling. Reference value.
- **`load_factor_local`**, **`load_factor_net`**, **`load_factor_cluster`** — fields exist in the schema but typically return `null` on modern builds (3.x) for non-clustered single-host validators. The aggregate `load_factor_server` is what's actually exposed.

The decision tree from a single `server_state` query:

| `load_factor_server` | `load_factor_fee_escalation` | What it means |
|---|---|---|
| at base | at base | Idle, healthy. |
| at base | high | Network is fee-bidding (e.g., NFT mint surge). Not actionable from this host. |
| high | at base | Real load on host or network. Investigate local resources. |
| high | high | Sustained network event with real congestion. Watch and wait; investigate locally if it persists. |

**Diagnostic command — single query**

```bash
xrpld server_state | jq '.result.state | {
  load_base,
  load_factor,
  load_factor_server,
  load_factor_fee_escalation,
  load_factor_fee_queue,
  io_latency_ms,
  peer_disconnects_resources,
  jq_trans_overflow,
  server_state,
  last_close
}'
```

If `load_factor_server` is the high one, drop into `server_info` for the deeper local-resource indicators:

| Field | Local-cause signal |
|---|---|
| `io_latency_ms` | `> 5` means disk is the bottleneck |
| `peer_disconnects_resources` | Rising means the host is shedding peers because it can't keep up |
| `jq_trans_overflow` | `> 0` or rising means the job queue is overflowing, so xrpld is dropping transactions it can't process in time |
| `load.job_types[].peak_time` | `> 10s` on `advanceLedger`, `trustedValidation`, or `transaction` indicates pipeline lag inside xrpld |

If all four of those are clean during a `load_factor_server` spike, the load is network-driven (everyone's `load_factor_server` is up together) and there's nothing local to tune. If any are moving, the host is constrained — usually disk, CPU, or RAM.

**The auto-tune trap**

A common operator instinct when `load_factor` rises is to start manually tuning `[node_db]` parameters: `cache`, `cache_age`, or sections like `[io_threads]` and `[network_threads]`. This is almost always wrong on modern xrpld:

- `cache` and `cache_age` inside `[node_db]` are auto-tuned by `node_size`. Manually setting them on a `huge`-sized validator is more likely to under-tune than help.
- `[io_threads]` and `[network_threads]` as top-level config sections are not valid xrpld keys. xrpld will ignore them or warn at startup.
- Thread-pool sizing for I/O and networking is handled internally based on `node_size` and detected core count.

If `load_factor_server` is consistently the cause of high readings, the lever is `node_size` — see [Node Sizing](#node-sizing). The progression is `small → medium → large → huge`. If you're already at `huge`, the answer is more host (more cores, more RAM, faster NVMe), not config tweaks.

**Brief spikes are normal — alert on sustained windows**

Whatever monitoring stack you build, calibrate the duration filter against your validator's actual behavior, not against the threshold value alone. A reasonable starting point is "alert when `load_factor` stays above N for at least 3 minutes" rather than "alert any time `load_factor` exceeds N." Empirical tuning — pull a week of data, look at how often spikes sustain — beats prescriptive thresholds every time.

Reference: [`server_state` API documentation](https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_state).

---

## Database Management

### online_delete Tuning

**The Bottom Line**

**Set `online_delete` to at least 16384, preferably 32768.** The default value (512) causes I/O storms that hurt validator performance.

| Scenario | online_delete | Rationale |
|----------|---------------|-----------|
| Default (not recommended) | 512-2000 | Causes I/O storms |
| Minimum stable | 8192 | ~8 hours between deletes |
| **Recommended** | **16384-32768** | **14-36 hours between deletes** |
| Conservative | 50000+ | Days between deletes, if disk permits |

**The Problem: I/O Storms**

Even on high-spec hardware (150k IOPS NVMe, 80 cores, 128 GB RAM), validators experience dropped ledgers due to I/O storms triggered by low `online_delete` values. The pattern is distinctive:

**Sawtooth Pattern (Low online_delete = 512):**
```
IOPS
30k ┤        ╭─╮        ╭─╮        ╭─╮        ╭─╮
    │       ╱   ╲       ╱  ╲       ╱  ╲       ╱  ╲    ← Delete storms
15k ┤      ╱     ╲     ╱    ╲     ╱    ╲     ╱    ╲
    │     ╱       ╲   ╱      ╲   ╱      ╲   ╱      ╲
 0k ┼────╱─────────╲─╱────────╲─╱────────╲─╱────────╲──
    └────┴──────────┴──────────┴──────────┴──────────┴────► Time
         ~30min    ~30min    ~30min    ~30min
```

**Smooth Pattern (High online_delete = 16384+):**
```
IOPS
30k ┤
    │
15k ┤
    │  ────────────────────────────────────────────  ← Steady state
 0k ┼
    └──────────────────────────────────────────────────► Time
```

**Why NuDB Makes This Worse**

NuDB (xrpld's ledger database) is optimized for append-mostly workloads:

- **Writes are fast:** Sequential appends are efficient
- **Deletes are expensive:** Requires compaction and reorganization
- **Frequent small deletes = worst case for NuDB**

By increasing `online_delete`, you allow NuDB to operate in its optimal mode (appending) for longer periods before incurring deletion overhead.

**The Rotation Mechanism**

xrpld maintains two NuDB databases simultaneously:
- **"Writable" DB** - receives new/modified nodes
- **"Archive" DB** - the older database being phased out

During rotation, xrpld copies all nodes that **weren't modified** since the last rotation from archive to writable. This copy operation is the expensive step.

**The math:**
- Lower `online_delete` → fewer ledgers between rotations → fewer transactions → fewer modified nodes
- Fewer modified nodes → **more nodes must be copied** during rotation
- More copying → I/O spikes → potential missed consensus rounds

**Extreme example:** If you rotated every ledger and only 6 accounts changed, you'd copy millions of unchanged nodes. With 32,768 ledgers between rotations, far more nodes have been naturally modified, so fewer need copying.

**Impact on Validator Performance**

| Metric | During Delete Storm | Normal Operation |
|--------|---------------------|------------------|
| I/O latency | Spikes to 10-100+ ms | 1-2 ms |
| Consensus participation | May miss rounds | Full participation |
| Agreement % | Drops periodically | Stable |
| server_state | May flicker | Steady proposing |

A validator can have perfect agreement scores most of the time but experience periodic drops during I/O storms.

**The Trade-off**

| online_delete | Disk Space | I/O Pattern | Delete Frequency |
|---------------|------------|-------------|------------------|
| 512 | ~250 MB | Sawtooth (bad) | Every 30 min |
| 2000 | ~1 GB | Spiky | Every 2 hours |
| 16384 | ~8-12 GB | Smooth | Every 14-18 hours |
| 32768 | ~16-24 GB | Very smooth | Every 36 hours |

**The trade-off is minimal:** Even at 16384, you're only using ~8-12 GB more disk space in exchange for dramatically smoother I/O and more stable validation.

**Configuration**

```ini
[node_db]
type=NuDB
path=/var/lib/xrpld/db/nudb
online_delete=32768
advisory_delete=0

[ledger_history]
32768
```

> **Note:** `ledger_history` must be ≤ `online_delete`.

**Verifying the Change**

After changing `online_delete` and restarting xrpld:

1. The first delete cycle will still occur at the previous threshold
2. The smooth I/O pattern becomes visible after ledger count exceeds the new threshold
3. Monitor your disk I/O - the sawtooth pattern should disappear

**Additional Tuning Parameters**

If you still experience issues, these parameters in `[node_db]` may help:
- `age_threshold_seconds` - minimum age before deletion eligible
- `recovery_wait_seconds` - delay before rotation resumes after interruption

**The One Rule**

**Never use low values to "save disk space."** You'll pay for it in I/O storms and degraded validator performance. Disk is cheap; validator reputation isn't.

**Source**

This issue was identified by [@shortthefomo](https://github.com/shortthefomo) and documented in [XRPLF/rippled issue #6202](https://github.com/XRPLF/rippled/issues/6202), with technical explanation from Ripple engineer [@ximinez](https://github.com/ximinez).

### advisory_delete

**The Bottom Line**

**Use `advisory_delete=0` (the default).** Let xrpld manage deletion automatically.

**What It Does**

| Value | Behavior |
|-------|----------|
| 0 | xrpld decides when to delete old ledgers (automatic) |
| 1 | xrpld waits for an external signal before deleting |

**When to Use Each**

- **`0` (recommended)**: Standard deployments. xrpld handles everything.
- **`1`**: Only if you have external tooling that needs to process ledger data before deletion, or you're running a specialized archival integration.

**Configuration**

```ini
[node_db]
type=NuDB
path=/var/lib/xrpld/db/nudb
advisory_delete=0
online_delete=32768
```

---

## Operational Settings

### log_level

**The Bottom Line**

**Run `warning` in production.** Only increase for troubleshooting.

| Level | Verbosity | Disk Impact | Use Case |
|-------|-----------|-------------|----------|
| trace | Extreme | GB/hour | Deep debugging only |
| debug | High | Large | Development, troubleshooting |
| info | Medium | Moderate | Default (too verbose for production) |
| **warning** | **Low** | **Minimal** | **Production recommended** |
| error | Very low | Very low | Only problems |
| fatal | Minimal | Negligible | Almost nothing |

**Configuration**

Set via `[rpc_startup]` to apply at boot:

```ini
[rpc_startup]
{ "command": "log_level", "severity": "warning" }
```

**Runtime Adjustment**

Temporarily increase for debugging without restart:

```bash
xrpld log_level debug
```

Then set back:

```bash
xrpld log_level warning
```

**Why Not `info`?**

The default `info` level logs every ledger close, peer connection, and many routine operations. On a busy validator, this generates significant disk I/O. `warning` logs only things that might need attention.

### ssl_verify

**The Bottom Line**

**Always `1` in production.** Never disable SSL verification.

```ini
[ssl_verify]
1
```

**What It Does**

| Value | Behavior |
|-------|----------|
| 1 | Verify SSL certificates for outbound connections |
| 0 | Skip verification (INSECURE) |

**Why It Matters**

xrpld makes HTTPS connections to validator list publishers (vl.ripple.com, unl.xrplf.org). SSL verification ensures:

- You're actually talking to the real publisher
- No man-in-the-middle can inject a malicious validator list
- Your node won't trust fake validators

**When `0` is Acceptable**

- Local development with self-signed certificates
- Isolated test networks
- Never in production

---

