# Aperire One Metrics Catalog

Every metric Aperire One collects, in one place, for the operator who wants the full picture. 175 metrics across 10 domains, each with a priority tier, source, cadence, healthy range, and alert threshold. This is the source-of-truth reference. The [metrics guide](METRICS-GUIDE.md) covers the subset live on screen today; this catalog covers everything, including metrics not yet surfaced.

Both validators and stock nodes are in scope. The dashboard detects the role (`pubkey_validator` present plus `server_state = proposing`) and hides validator-only rows on a stock node.

---

## How to Read This Document

### Columns

| Column | Meaning |
|--------|---------|
| **Metric** | Canonical name. Prefer XRPL.org field names where one exists (e.g., `server_info.info.load_factor`). Where a metric is derived, name follows the pattern `{domain}_{measure}_{window}`. |
| **Description** | One line, operator-facing. |
| **Tier** | P0 = page me at 3am; P1 = check daily; P2 = nice to have / trend analysis. |
| **V** | ✓ if validator-only. Blank = applies to both validators and stock nodes. |
| **Source** | Where the value comes from. See "Source Keys" below. |
| **Cadence** | Update interval. `stream` = pushed by rippled WebSocket subscription; `Ns` = poll every N seconds; `per-ledger` = once per validated ledger close. |
| **Healthy** | Expected normal range. |
| **Alert** | Condition that triggers. |
| **Sev** | Warn / Critical / Page. Page = wake someone up. Critical = same-day action. Warn = investigate when convenient. |

### Source Keys

| Key | Meaning |
|-----|---------|
| `admin:server_info` | `server_info` admin command (HTTP or WebSocket). |
| `admin:server_state` | Numeric-first variant of `server_info`. |
| `admin:consensus_info` | `consensus_info` admin command. |
| `admin:peers` | `peers` admin command. |
| `admin:get_counts` | `get_counts` admin command. |
| `admin:feature` | `feature` admin command (amendment state). |
| `admin:fee` | `fee` admin command. |
| `admin:validator_list_sites` | `validator_list_sites` admin command. |
| `admin:validators` | `validators` admin command. |
| `admin:manifest` | `manifest` admin command. |
| `admin:ledger` | `ledger` admin command. |
| `ws:validations` | `subscribe streams: ["validations"]`. |
| `ws:ledger` | `subscribe streams: ["ledger"]`. |
| `ws:transactions` | `subscribe streams: ["transactions"]`. |
| `ws:manifests` | `subscribe streams: ["manifests"]`. |
| `ws:server` | `subscribe streams: ["server"]`. |
| `ws:consensus` | `subscribe streams: ["consensus"]`. |
| `ws:peer_status` | `subscribe streams: ["peer_status"]`. |
| `http:/health` | rippled `/health` HTTP endpoint. |
| `node_exporter` | Prometheus node_exporter metric (system/OS). |
| `proc:/proc/{pid}/stat` | Direct read of rippled's procfs entry. |
| `fs:nudb` | Directory size of NuDB data path. |
| `log:debug.log` | Parsed from rippled logs. |
| `derived` | Computed in the dashboard from other sources. |

All `admin:*` endpoints are callable from xrpl.js via `Client.request()`; note that amendment, feature, peer, consensus, and get_counts commands require admin access (local or authenticated WebSocket).

### Alert Severity Policy

| Sev | Delivery (v1) | Example |
|-----|---------------|---------|
| **Warn** | Dashboard indicator only | Peer count dipped below normal band but above floor. |
| **Critical** | Dashboard + email | Agreement dropped below 97% over 1h. |
| **Page** | Dashboard + email + (later) SMS/phone | `amendment_blocked = true`, server_state disconnected > 60s. |

Email, ntfy push, and webhooks (Discord / Slack / generic JSON) are all delivery channels. All alerts include: metric name, value, threshold, duration, link to dashboard panel.

---

## 1. Consensus & Validation

The core of "is this validator doing its job." Most rows here are validator-only; a stock node doesn't propose or validate.

| Tier | Metric | Description | V | Source | Cadence | Healthy | Alert | Sev |
|------|--------|-------------|---|--------|---------|---------|-------|-----|
| P0 | `server_state` | rippled state string (`proposing`, `full`, `tracking`, `syncing`, `connected`, `disconnected`) | | `ws:server`, `admin:server_info` | stream | `proposing` (validator), `full` (stock) | not-expected for >60s | Critical; `disconnected` >60s = Page |
| P0 | `validation_quorum` | Minimum validations required for consensus | | `admin:server_info.validation_quorum` | 30s | Matches UNL-derived expectation (~28-29 on mainnet) | Unexpected change | Critical |
| P0 | `consensus_info.mode` | Local consensus participation mode (`observing`, `proposing`, `wrongLedger`, `switchedLedger`) | ✓ | `admin:consensus_info` | 2s | `proposing` | `wrongLedger`/`switchedLedger` >1 ledger | Page |
| P0 | `validations_sent_total` | This validator's validations emitted | ✓ | `ws:validations` filtered by `pubkey_validator` | stream | Steady ~15/min | Zero for >2 min | Page |
| P0 | `validations_received_per_ledger` | Distinct trusted validations received per ledger | | `ws:validations` | stream | ≥ `validation_quorum` | < quorum | Page |
| P0 | `validation_agreement_pct_1h` | % of this validator's validations matching the validated ledger, 1h window | ✓ | `derived` (`ws:validations` + `ws:ledger`) | 60s | 100% | < 99% | Warn; <97% = Critical; <95% = Page |
| P0 | `quorum_satisfied_ratio_1h` | % of ledgers in last hour where received validations ≥ quorum | | `derived` | 60s | 100% | < 100% | Critical |
| P0 | `amendment_blocked` | rippled refusing to work because network has enabled an amendment this build doesn't support | | `admin:server_info.amendment_blocked` | 30s | absent/false | true | Page |
| P1 | `time_in_current_state_s` | Seconds since last state transition | | `derived` from `admin:server_info.state_accounting` | 5s | Stable in healthy state | flapping (>3 transitions/5min) | Critical |
| P1 | `last_close.proposers` | Proposers in last consensus round | | `admin:server_info.last_close.proposers` | per-ledger | Near UNL size | < quorum | Critical |
| P1 | `last_close.converge_time_ms` | Time to reach consensus on last ledger | | `admin:server_info.last_close.converge_time` | per-ledger | 2000-4000 ms | >6000 ms sustained | Warn; >10s = Critical |
| P1 | `validation_rate_per_min` | This validator's emitted validation rate | ✓ | `derived` | 60s | 14-16/min | < 10/min | Critical |
| P1 | `validation_agreements_1h` | Count of agreed validations, 1h | ✓ | `derived` | 60s | ~900 | unexpected drop | Warn |
| P1 | `validation_missed_1h` | Count of missed validations, 1h | ✓ | `derived` | 60s | 0 | > 5 | Critical |
| P1 | `validation_agreement_pct_24h` | Same as 1h, 24h window | ✓ | `derived` | 5m | 100% | < 99.5% | Warn; <99% = Critical |
| P1 | `validation_agreements_24h` | Count of agreed validations, 24h | ✓ | `derived` | 5m | ~21,600-25,920 | unexpected drop | Warn |
| P1 | `validation_missed_24h` | Count of missed validations, 24h | ✓ | `derived` | 5m | 0 | > 20 | Critical |
| P2 | `state_accounting.{state}.duration_us` | Cumulative microseconds per state | | `admin:server_info.state_accounting` | 30s | Most time in `full`/`proposing` | `disconnected` share rising | Warn |
| P2 | `state_transitions_total.{state}` | Count of transitions into each state | | `admin:server_info.state_accounting` | 30s | Low and stable | Sudden spike | Warn |
| P2 | `consensus_info.phase` | Current consensus phase (`open`, `establish`, `accepted`) | | `admin:consensus_info` | 1s | Cycles normally | Stuck in `establish` >8s | Warn |
| P2 | `full_validation_ratio` | % of validations received with `full: true` | | `derived` (`ws:validations.full`) | 5m | ~100% on trusted UNL | sustained drop | Warn |
| P2 | `pubkey_validator` | This validator's public key (nHU...). Identifies this validator on the network; used in UNL membership and reputation tracking. | ✓ | `admin:server_info.pubkey_validator` | startup | Constant | Unexpected change | Page |
| P2 | `pubkey_node` | This node's public key. Identifies this node to peers. | | `admin:server_info.pubkey_node` | startup | Constant | Unexpected change | Critical |

**Notes.**
- `validation_quorum` on mainnet is roughly 80% of trusted UNL size. Ties to UNL churn (see §5).
- `last_close.converge_time` in `server_info` is in ms (confirm against `consensus_info.close_times` histogram for distribution).
- "Missed" validation = a ledger your validator was running for but didn't sign before the close, measured with an 8s grace period and a 5-minute reconciliation window.
- `wrongLedger`/`switchedLedger` modes are normal briefly during a consensus disagreement; alert only if persistent.

---

## 2. Ledger & Chain State

Is this node keeping up with the network? Is its local history intact?

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `ledger_index` | Latest validated ledger sequence number | P0 | | `ws:ledger`, `admin:server_info.validated_ledger.seq` | stream | Monotonically increasing | Not advancing for >10s | Critical; >30s = Page |
| `ledger_age_s` | Seconds since latest validated ledger close | P0 | | `admin:server_info.validated_ledger.age` | 1s | 0-5s | > 5s for 30s | Warn; > 10s = Critical |
| `ledger_close_time_delta_s` | Time between successive ledger closes | P1 | | `derived` (`ws:ledger`) | per-ledger | 3-5s | > 6s sustained | Warn |
| `txn_count_per_ledger` | Transactions included in the last validated ledger | P1 | | `ws:ledger.txn_count` | per-ledger | Variable 10-500 |, |, |
| `tps_1m` | Transactions per second, 1-min rolling | P1 | | `derived` | 10s | 5-50 network-dependent |, |, |
| `ledgers_per_minute_1m` | Network-wide ledger close rate, 1-min rolling. Typically 15-18/min (one every 3-4s). Compare against this validator's validation rate to monitor participation. | P1 | | `derived` (`ws:ledger`) | 10s | ≥ 9/min | 8/min = Warn; < 8/min = Critical | Warn; Critical |
| `complete_ledgers` | Local history range string (e.g., `81234567-99999999`) | P0 | | `admin:server_info.complete_ledgers` | 30s | One contiguous range of configured depth | `"empty"` or gaps in range | Page if empty; Critical if gaps |
| `complete_ledgers_depth` | Count of ledgers in local history | P1 | | `derived` from `complete_ledgers` | 30s | Matches `online_delete` config | < configured depth - 256 | Warn |
| `missing_ledger_gaps` | Count of gaps inside the history range | P0 | | `derived` from `complete_ledgers` | 30s | 0 | ≥ 1 | Critical |
| `io_latency_ms` | rippled's internal IO latency estimate | P1 | | `admin:server_info.io_latency_ms` | 5s | < 5ms | > 100ms sustained | Warn; > 1000 = Critical |
| `fetch_pack_pending` | Outstanding ledger fetch-pack requests | P2 | | `admin:get_counts` | 30s | Low or zero | High sustained | Warn |
| `network_id` | Network this node is joined to (0=mainnet, 1=testnet, 2=devnet) | P2 | | `admin:server_info.network_id` | 60s | Expected constant | Unexpected change | Page |
| `reporting_mode` | Whether this is a Reporting Mode node | P2 | | `admin:server_info.reporting` | startup | Matches operator intent | Drifts from config | Warn |

**Notes.**
- `complete_ledgers` can be a multi-range string during sync; post-sync should be one contiguous range. Any gap is a data integrity issue: triggers historical shard repair.
- `ledger_age_s` spiking is the single most reliable "network problem" signal, worth prominent placement in the dashboard.
- TPS isn't produced by rippled directly; compute from the transactions stream or from `txn_count` per ledger.

---

## 3. Peer Network

Health of the connection graph. Peer data also drives the animated peer visualization.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `peer_count` | Total connected peers | P0 | | `admin:server_info.peers`, `admin:peers` | 15s | ~21 (rippled default `peers_max`; 15-30 healthy, see rippled field guide §peers_max) | < 10 | Warn; < 5 = Critical; = 0 = Page |
| `peers_inbound` | Incoming connections | P1 | | `admin:peers` | 30s | Matches `peer_private` / inbound port config | Drops to 0 unexpectedly | Warn |
| `peers_outbound` | Outgoing connections | P1 | | `admin:peers` | 30s | ≥ `peers_out_max` target | < 5 | Warn |
| `peers_insane` | Peers flagged by rippled as misbehaving (`sanity != "sane"`) | P1 | | `admin:peers` | 30s | 0-2 | > 5 sustained | Warn |
| `peer_latency_ms_p50` | Median peer latency | P1 | | `derived` (`admin:peers[].latency`) | 60s | < 100ms | > 500ms | Warn |
| `peer_latency_ms_p90` | 90th percentile peer latency | P1 | | `derived` | 60s | < 250ms | > 1000ms | Warn |
| `peer_latency_ms_p99` | 99th percentile | P2 | | `derived` | 60s | < 500ms |, |, |
| `peer_disconnects_total` | Cumulative normal disconnects | P2 | | `admin:server_info.peer_disconnects` | 60s | Low rate | Sudden spike | Warn |
| `peer_disconnects_resources_total` | Disconnects from resource exhaustion (this node pushing back) | P1 | | `admin:server_info.peer_disconnects_resources` | 60s | Near zero | > 10/min | Warn; > 100/min = Critical |
| `peers_higher_version_count` | Peers running a newer rippled than this node | P1 | | `derived` (`admin:peers[].version`) | 5m | 0 | > 50% of peers | Warn (upgrade recommended) |
| `peers_higher_version_pct` | Same as above, percent | P1 | | `derived` | 5m | 0% | > 25% | Warn; > 50% = Critical |
| `upgrade_status` | Composite: 0=Current, 1=Behind, 2=Blocked, 3=Critical | P0 | | `derived` from `peers_higher_version_pct` + `amendment_blocked` | 5m | 0 | ≥ 2 | Critical; = 3 = Page |
| `peer_protocol_version_histogram` | Count of peers per protocol version | P2 | | `derived` | 5m | Clustered | Broad fragmentation | Warn |
| `peer_complete_ledgers_coverage_pct` | % of peers serving this node's needed history range | P2 | | `derived` (`admin:peers[].complete_ledgers`) | 5m | > 80% | < 50% | Warn |
| `peer_country_distribution` | Geographic spread (count per ISO country code) | P2 | | `derived` (GeoIP on `admin:peers[].address`) | 5m | Diverse | Heavily single-country | Warn (resilience concern) |
| `peer_asn_distribution` | Autonomous system number distribution | P2 | | `derived` (ASN lookup) | 5m | Diverse | Single-ASN dominance | Warn |
| `peer_uptime_distribution_h` | Histogram of peer connection ages | P2 | | `derived` (`admin:peers[].uptime`) | 5m | Long-tail | All peers recently connected | Warn (peer churn) |

**Notes.**
- Peer enrichment (reverse DNS + GeoIP) produces `peer_country_distribution` and the peer-tooltip content.
- `peer_disconnects_resources` is the canary for your node running hot: rippled is dropping peers because it can't keep up. Critical threshold is tighter than normal disconnects.
- `peer_complete_ledgers_coverage` matters more for history-serving stock nodes than for validators.

---

## 4. Amendments & Governance

This section covers every amendment lifecycle signal an operator needs.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `amendment_blocked` | Node frozen pending upgrade | P0 | | `admin:server_info.amendment_blocked` | 30s | absent/false | true | Page |
| `amendments_enabled_count` | Number of amendments active on network | P2 | | `admin:feature` | 5m | Matches network | Decreases | Page (indicates fork) |
| `amendments_supported_count` | Amendments this build supports | P2 | | `admin:feature` | 5m | Matches build |, |, |
| `amendments_vetoed_count` | Amendments this validator votes against | P2 | ✓ | `admin:feature` filter `vetoed=true` | 5m | Matches operator policy | Drifts from policy | Warn |
| `amendments_pending_count` | Amendments proposed but not yet enabled | P1 | | `admin:feature` filter `enabled=false, supported=true` | 5m | 0-5 typical |, |, |
| `amendments_approaching_threshold_count` | Pending amendments with ≥ 80% validator support | P0 | | `derived` from `admin:feature.count` / `validations` | 5m | 0 | ≥ 1 needing action | Critical (operator decision) |
| `amendment_{hash}.support_pct` | Per-amendment validator support % | P1 | | `admin:feature` | 5m | Tracks toward 80% or stalls | Crosses 80% | Critical (starts 2-week countdown) |
| `amendment_{hash}.threshold_met` | Boolean: ≥ 80% for ≥ 2 weeks | P0 | | `admin:feature` | 5m | Aligns with this node's `vote` | Activation imminent and this build doesn't support | Page |
| `amendment_{hash}.days_to_activation_est` | Days until activation if threshold holds | P1 | | `derived` | 1h | N/A | < 14 and this build doesn't support | Critical |
| `unsupported_amendment_days_to_block` | Shipped implementation of the row above, one scalar rather than per-hash: days until this build is amendment-blocked by the unsupported amendment closest to activating | P0 | | `derived` from `admin:feature.majority` | 5m | 99999 (nothing unsupported at majority) | ≤ 14 (majority reached); ≤ 3 (imminent) | Warn; Critical (#654) |
| `amendment_{hash}.our_vote` | This node's vote stance (`yes` / `no` / `default`) | P1 | ✓ | `admin:feature.vote` + validator config | 5m | Matches policy | Drifted from intended | Warn |
| `amendment_{hash}.our_signalling` | Whether this validator's validations include this amendment | P2 | ✓ | `derived` (`ws:validations` amendment list) | stream | Matches intended vote | Mismatch | Warn |
| `build_version` | This node's rippled version string | P1 | | `admin:server_info.build_version` | startup | Latest stable | Behind current mainline | Warn |
| `build_version_network_majority` | Most common version across trusted peers | P2 | | `derived` (`admin:peers[].version`) | 1h | Matches this node | Ahead of this node | Warn |

**Operator Playbooks (Amendments)**

| Event | Recommended Action | Timeline |
|-------|---------------------|----------|
| New amendment appears in `feature` (unknown hash) | Review amendment notes. Decide vote stance. | Within 1 week |
| Amendment crosses 50% support | Add to watch list. Review amendment docs if unfamiliar. | Opportunistic |
| Amendment crosses 80% support | 2-week activation countdown begins. Verify this build supports it. If not, upgrade or veto. | Within 48 hours of crossing |
| This build doesn't support an amendment at 80% | Upgrade rippled now. If unable, explicitly `veto` the amendment hash. | Before activation window ends |
| `amendment_blocked = true` | Emergency upgrade. Node is offline until build upgraded past required amendment. | Immediate |
| Network majority on newer version | Schedule upgrade to reduce fork risk. | Within 1-2 weeks |

See the Field Guide's **Amendment Blocking** and **Upgrade Procedures** sections for step-by-step procedures.

---

## 5. UNL & Validator List Health

Also net-new for v4. Tracks the freshness and integrity of the trusted validator set.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `unl_validator_count` | Trusted validators in effective UNL | P0 | | `admin:validators` | 5m | Matches publisher (34-35 on mainnet) | Unexpected change | Critical |
| `unl_expected_quorum` | Derived expected `validation_quorum` | P1 | | `derived` | 5m | Matches `server_info.validation_quorum` | Mismatch | Warn |
| `unl_publisher_site_count` | Number of configured `[validator_list_sites]` entries | P1 | | `admin:validator_list_sites` | 10m | ≥ 1 (matches config) | 0 | Page |
| `unl_publisher_{site}.last_refresh_status` | Per-publisher refresh status (`accepted`, `same_sequence`, `unknown`, `invalid`, `stale`) | P0 | | `admin:validator_list_sites` | 5m | `accepted` or `same_sequence` | `invalid`, `stale`, `unknown` | Critical |
| `unl_publisher_{site}.last_refresh_age_s` | Seconds since last successful fetch | P0 | | `admin:validator_list_sites` | 5m | < `refresh_interval_min * 60 * 2` | > 2x interval | Critical; > 24h = Page |
| `unl_publisher_{site}.list_expiry_days` | Days until the published list expires | P0 | | `admin:validator_list_sites.expiration` | 1h | > 7 days | < 7 | Critical; < 2 = Page |
| `unl_publisher_{site}.cert_expiry_days` | HTTPS cert expiry for publisher site | P1 | | TLS probe of site URL | 6h | > 30 days | < 30 | Warn; < 7 = Critical |
| `unl_publisher_{site}.sequence` | UNL list sequence number | P2 | | `admin:validator_list_sites` | 1h | Monotonically increasing | Regression | Critical |
| `unl_active_validator_count` | Trusted validators seen validating in the last hour | P0 | | `derived` (`ws:validations` + `admin:validators`) | 5m | ≈ `unl_validator_count` | < quorum | Page |
| `unl_offline_validator_count` | Trusted validators silent > 15m | P1 | | `derived` | 5m | 0-2 | > 10% of UNL | Critical |
| `unl_offline_validators[]` | List of silent trusted pubkeys | P2 | | `derived` | 5m |, |, |, |
| `unl_manifest_sequence_{pubkey}` | Current manifest sequence per UNL validator | P2 | | `ws:manifests`, `admin:validators` | stream | Stable or monotonic | Regression | Critical |
| `unl_manifest_rotation_events_24h` | Count of validator key rotations observed in 24h | P2 | | `derived` (`ws:manifests`) | 1h | 0-1 typical | Spike | Warn (investigate) |
| `unl_churn_7d` | Validators added/removed from UNL in last 7 days | P2 | | `derived` | 1h | 0-2 | > 5 | Warn |

**Operator Playbooks (UNL)**

| Event | Recommended Action | Timeline |
|-------|---------------------|----------|
| Publisher site refresh fails for > 2 intervals | Verify site URL is reachable, cert valid. Inspect site manifest. | Same day |
| Publisher list expires in < 7 days | Contact publisher. Prepare fallback publisher if available. | Before 48h to expiry |
| Publisher list expires in < 48h | Switch to secondary publisher (or temporarily add manual UNL). | Emergency |
| Trusted validator silent > 15m | Investigate: check their operator status, amendments, network. Do not drop from UNL unilaterally; publishers manage that. | Same day |
| Manifest sequence jump (key rotation) | Log, confirm rotation is legitimate (publisher-announced). | Informational |
| Publisher cert expires soon | Notify publisher. | Opportunistic |

See the Field Guide's **Validator Keys / Key Hierarchy** and **Token Management** sections for key rotation procedures.

---

## 6. Fees & Load

Fee escalation, load factor, and transaction queue state. Signals network pressure and whether this node is contributing to or suffering from it.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `base_fee_xrp` | Network base transaction fee (drops → XRP) | P1 | | `admin:server_info.validated_ledger.base_fee_xrp` | 30s | 0.00001 XRP | Elevated (fee escalation active) | Warn |
| `reserve_base_xrp` | Account reserve (XRP) | P1 | | `admin:server_info.validated_ledger.reserve_base_xrp` | 60s | 1 XRP (current mainnet) | Protocol-driven change | Informational |
| `reserve_inc_xrp` | Owner reserve increment (XRP) | P1 | | `admin:server_info.validated_ledger.reserve_inc_xrp` | 60s | 0.2 XRP (current mainnet) | Protocol-driven change | Informational |
| `load_factor` | Total local + network load multiplier | P0 | | `admin:server_info.load_factor` | 5s | 1.0 | > 1.0 sustained | Warn; > 10 = Critical |
| `load_factor_local` | Local-only load | P1 | | `admin:server_info.load_factor_local` | 5s | 1.0 | > 1.0 | Warn (this node is strained) |
| `load_factor_net` | Network load | P1 | | `admin:server_info.load_factor_net` | 5s | 1.0 | > 1.0 | Informational |
| `load_factor_cluster` | Cluster load (if `[cluster_nodes]` set) | P2 | | `admin:server_info.load_factor_cluster` | 5s | 1.0 | > 1.0 | Warn |
| `load_factor_fee_escalation` | Open-ledger fee escalation factor | P1 | | `admin:server_info.load_factor_fee_escalation` | 5s | 1 | > 1 sustained | Warn |
| `load_factor_fee_queue` | Fee needed to join the transaction queue | P1 | | `admin:server_info.load_factor_fee_queue` | 5s | 1 | > 1 | Informational |
| `load_factor_server` | This server's load component | P1 | | `admin:server_info.load_factor_server` | 5s | 1 | > 1 | Warn |
| `fee.current_queue_size` | Transactions currently queued | P1 | | `admin:fee` | 10s | < `expected_ledger_size` | > `max_queue_size * 0.8` | Warn; ≥ max = Critical |
| `fee.expected_ledger_size` | Network target ledger size | P2 | | `admin:fee` | 10s | ~55-1000 |, |, |
| `fee.max_queue_size` | Max queued transactions the node will hold | P2 | | `admin:fee` | 10s |, |, |, |
| `fee.drops.minimum_fee` | Minimum fee to submit (drops) | P2 | | `admin:fee.drops.minimum_fee` | 10s | 10 drops | Elevated | Informational |
| `fee.drops.median_fee` | Median fee last ledger (drops) | P2 | | `admin:fee.drops.median_fee` | 10s |, |, |, |
| `fee.drops.open_ledger_fee` | Fee to get into open ledger now | P1 | | `admin:fee.drops.open_ledger_fee` | 10s | 10 drops | Sustained elevation | Warn |
| `jq_trans_overflow` | Jobs dropped because transaction job queue full | P1 | | `admin:server_info.jq_trans_overflow` | 30s | Near zero | Non-zero rate | Warn; rising = Critical |

**Notes.**
- `load_factor_local > load_factor_net` means *your* node is the bottleneck, not the network. Separate those in the dashboard.
- `jq_trans_overflow` rising means the node is dropping transactions it should have queued; correlate with CPU/IO pressure.
- "Drops" = 1,000,000 drops per XRP. Display in XRP for humans, keep drops for math.

---

## 7. System / Compute

CPU, memory, disk, process-level. The dashboard reads these from `/proc`, `/sys`, `statfs()`, and `adjtimex(2)` on its own host as an unprivileged user, the same source files `node_exporter` and `top(1)` read. In a co-located install that host is the validator; in a split deployment these describe the dashboard host, not the validator. No `node_exporter` runs on the host. See the [Source Keys](#source-keys) legend and the [appendix](#appendix-collection-mechanics) for the exact per-metric paths.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `cpu_busy_pct` | Total CPU utilization (1 - idle) | P0 | | `proc:/proc/stat` (`cpu` line) | 15s | < 70% | > 85% for 5m | Warn; > 95% 10m = Critical |
| `cpu_iowait_pct` | CPU waiting on IO | P0 | | `proc:/proc/stat` (`cpu` field 5) | 15s | < 5% | > 15% sustained | Warn; > 30% = Critical |
| `cpu_steal_pct` | CPU stolen by hypervisor (VM only) | P1 | | `proc:/proc/stat` (`cpu` field 8) | 15s | < 2% | > 10% | Critical (noisy neighbor) |
| `load_avg_1m` / `_5m` / `_15m` | System load averages | P1 | | `proc:/proc/loadavg` | 15s | < core_count | > 2x core_count sustained | Warn |
| `cpu_cores` | Logical CPU count | P2 | | `proc:/proc/cpuinfo` | startup | Matches hardware | Changed | Page (hardware change) |
| `memory_total_bytes` | Physical RAM | P2 | | `proc:/proc/meminfo` (`MemTotal`) | startup | Matches hardware | Changed | Page |
| `memory_available_bytes` | Memory available for new allocations | P0 | | `proc:/proc/meminfo` (`MemAvailable`) | 15s | > 20% of total | < 10% | Warn; < 5% = Critical |
| `memory_used_pct` | Derived: 1 - (available / total) | P0 | | `derived` | 15s | < 80% | > 90% | Critical |
| `swap_total_bytes` | Swap configured | P2 | | `proc:/proc/meminfo` (`SwapTotal`) | startup |, |, |, |
| `swap_used_pct` | Swap utilization | P0 | | `derived` | 15s | steady, unchanging | >= 40% for 10m, climbing or paging (`vmstat 1` si/so > 0), same on every role | Warn; >= 50% = Critical |
| `oom_kills_total` | Out-of-memory kill events | P0 | | `proc:/proc/vmstat` (`oom_kill`) | 60s | 0 | ≥ 1 | Page |
| `pressure_cpu_some_pct` | PSI: CPU pressure (tasks waiting on CPU) | P1 | | `proc:/proc/pressure/cpu` (`some avg10`) | 15s | < 5% | > 20% sustained | Warn |
| `pressure_memory_some_pct` | PSI: memory pressure | P1 | | `proc:/proc/pressure/memory` (`some avg10`) | 15s | < 1% | > 10% | Warn |
| `pressure_io_some_pct` | PSI: IO pressure | P0 | | `proc:/proc/pressure/io` (`some avg10`) | 15s | < 5% | > 25% sustained | Warn; > 50% = Critical |
| `disk_used_pct{mount}` | Per-mount filesystem utilization | P0 | | `statfs(mount)` | 60s | < 75% | > 85% | Warn; > 95% = Page (data mount) |
| `disk_available_bytes{mount}` | Free space per mount | P0 | | `statfs(mount)` | 60s | Matches growth budget | Projected exhaustion < 14 days | Critical |
| `disk_inodes_used_pct{mount}` | Inode utilization | P2 | | `statfs(mount)` | 5m | < 70% | > 90% | Critical |
| `disk_read_iops{device}` | Read IOPS per device | P1 | | `proc:/proc/diskstats` | 15s | < device rating | Sustained saturation | Warn |
| `disk_write_iops{device}` | Write IOPS | P1 | | `proc:/proc/diskstats` | 15s | < device rating | Sustained saturation | Warn |
| `disk_read_throughput_bps{device}` | Read bytes/sec | P1 | | `proc:/proc/diskstats` | 15s |, | Sustained > device rating | Warn |
| `disk_write_throughput_bps{device}` | Write bytes/sec | P1 | | `proc:/proc/diskstats` | 15s |, | Sustained > device rating | Warn |
| `disk_io_util_pct{device}` | % time device busy | P0 | | `proc:/proc/diskstats` | 15s | < 70% | > 90% sustained | Warn; 100% = Critical |
| `disk_io_wait_ms{device}` | Weighted IO wait time | P1 | | `proc:/proc/diskstats` | 15s | Low | Rising | Warn |
| `process_rippled_cpu_pct` | CPU% of the rippled process only | P1 | | `proc:/proc/{pid}/stat` | 15s | Matches load | Unexpectedly pinned | Warn |
| `process_rippled_rss_bytes` | rippled resident memory | P1 | | `proc:/proc/{pid}/status` | 15s | Matches `node_size` config | Unbounded growth | Critical |
| `process_rippled_open_fds` | Open file descriptors | P1 | | `proc:/proc/{pid}/fd/` count | 60s | Well under `ulimit -n` | > 80% of limit | Warn; > 95% = Critical |
| `process_rippled_threads` | Thread count | P2 | | `proc:/proc/{pid}/status` | 60s | Config-dependent | Unbounded | Warn |
| `process_rippled_uptime_s` | Time since rippled process last started. Longer uptime is generally better; restarts reset. Frequent restarts suggest crashes or manual intervention. | P2 | | `proc:/proc/{pid}/stat` (`starttime`) or `derived` from `state_accounting` | 60s | Stable, long uptime | Unexpected reset | Warn |
| `system_uptime_s` | Host uptime | P2 | | `proc:/proc/uptime` | 60s | Stable | Unexpected reboot | Critical |
| `time_drift_ms` | NTP offset (absolute ms) | P0 | | `adjtimex(2)` (`offset`) | 60s | \|drift\| < 50ms | \|drift\| > 500ms | Critical (consensus risk) |
| `ntp_synced` | Boolean: clock source in sync | P0 | | `adjtimex(2)` (`status`) | 60s | 1 | 0 | Critical |
| `entropy_available` | Kernel entropy pool | P2 | | `proc:/proc/sys/kernel/random/entropy_avail` | 60s | > 1000 | < 200 | Warn |
| `hwmon_temp_celsius{sensor}` | Temperature sensors | P2 | | `sysfs:/sys/class/hwmon/*/temp*_input` | 60s | < 75°C | > 85°C | Warn; > 95°C = Critical |

**Notes.**
- PSI (`pressure.*`) is more useful than raw CPU% alone; it directly captures "tasks are waiting" rather than "CPU is busy doing useful work."
- `process_rippled_cpu_pct` isolates rippled from kernel and other-process CPU, read from `/proc/<pid>/stat`.
- Time drift is listed as P0 because rippled's consensus tolerates only small clock skew; sustained drift will start missing validations.

---

## 8. Network Bandwidth

Per-interface bandwidth accounting. rippled is a chatty protocol; bandwidth caps are the #1 hosting surprise for new operators.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `net_bytes_in_bps{iface}` | Ingress bytes/sec per interface | P0 | | `proc:/proc/net/dev` (RX bytes) | 15s | Matches traffic envelope | Sustained > link cap * 0.8 | Warn; > 0.95 = Critical |
| `net_bytes_out_bps{iface}` | Egress bytes/sec | P0 | | `proc:/proc/net/dev` (TX bytes) | 15s | Matches | Sustained > link cap * 0.8 | Warn; > 0.95 = Critical |
| `net_bytes_in_total_24h{iface}` | 24h ingress total | P1 | | `derived` | 1h | Within monthly budget | Projected monthly overage | Warn |
| `net_bytes_out_total_24h{iface}` | 24h egress total | P1 | | `derived` | 1h | Within monthly budget | Projected monthly overage | Warn |
| `net_packets_in_pps{iface}` | Ingress packets/sec | P1 | | `proc:/proc/net/dev` (RX packets) | 15s |, |, |, |
| `net_packets_out_pps{iface}` | Egress packets/sec | P1 | | `proc:/proc/net/dev` (TX packets) | 15s |, |, |, |
| `net_errors_in{iface}` | Receive errors | P0 | | `proc:/proc/net/dev` (RX errs) | 60s | 0 | Non-zero rate | Critical |
| `net_errors_out{iface}` | Transmit errors | P0 | | `proc:/proc/net/dev` (TX errs) | 60s | 0 | Non-zero rate | Critical |
| `net_drops_in{iface}` | Dropped incoming packets | P0 | | `proc:/proc/net/dev` (RX drop) | 60s | 0 | Non-zero sustained | Warn; rising = Critical |
| `net_drops_out{iface}` | Dropped outgoing packets | P0 | | `proc:/proc/net/dev` (TX drop) | 60s | 0 | Non-zero sustained | Warn; rising = Critical |
| `tcp_established_count` | TCP sockets in ESTABLISHED | P1 | | `proc:/proc/net/snmp` (`Tcp.CurrEstab`) | 30s | Stable, peer_count + clients | Sudden drop | Warn |
| `tcp_time_wait_count` | TCP sockets in TIME_WAIT | P2 | | `proc:/proc/net/sockstat` (`TCP tw`) | 30s | Low | > 10000 | Warn |
| `tcp_retransmits_per_sec` | TCP retransmits rate | P1 | | `proc:/proc/net/snmp` (`Tcp.RetransSegs`) | 30s | < 0.5 segs/s | ≥ 50 segs/s | Warn |
| `tcp_resets_per_sec` | RST packets per sec | P2 | | `proc:/proc/net/snmp` (`Tcp.OutRsts`) | 60s | Low | Spike | Warn |
| `socket_count_total` | Open sockets, all protocols | P2 | | `proc:/proc/net/sockstat` (`sockets used`) | 60s | Well under limit | Near limit | Critical |
| `bandwidth_budget_used_pct_month` | % of monthly bandwidth budget consumed | P0 | | `derived` (config budget + `net_bytes_*_total_24h`) | 1h | On-track vs. days elapsed | > 100% pre-month-end | Critical; overage = Page |

### Per-port connection counts *(v0.4+)*

Current ESTABLISHED TCP connections on each of rippled's four ports. Source: `aperire-relay` reads `/proc/<rippled-pid>/net/tcp` + `tcp6` on every push tick, in rippled's own network namespace. That namespace is the authoritative view for containerized rippled installs and identical to the host namespace on native installs. Ports are auto-detected from `rippled.cfg` at relay startup; see [Port connection monitoring](RELAY-REFERENCE.md#port-connection-monitoring) for the classification rules.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `http_rpc_conn` | Concurrent ESTABLISHED TCP connections where `local_port == http_rpc_port` (admin HTTP-RPC, default 5005) | P1 | | `proc:/proc/<rippled-pid>/net/tcp` | 5s | 0-10 (a few admin tools) | > 50 sustained | Warn; > 100 = Critical (runaway admin client) |
| `admin_ws_conn` | Concurrent ESTABLISHED on `admin_ws_port` (default 6006). Includes the dashboard's own WebSocket to rippled. | P1 | | `proc:/proc/<rippled-pid>/net/tcp` | 5s | 2-10 | > 50 sustained | Warn; > 100 = Critical |
| `ws_public_conn` | Concurrent ESTABLISHED on `ws_public_port` (default 6005). 0 when rippled.cfg doesn't expose a `[port_ws_public]` section. | P2 | | `proc:/proc/<rippled-pid>/net/tcp` | 5s | Operator-dependent (0 to many) |, |, |
| `peer_conn` | Concurrent ESTABLISHED where either end matches `peer_port` (default 51235). Counts both inbound peers (local = peer port) and outbound peers (remote = peer port). | P1 | | `proc:/proc/<rippled-pid>/net/tcp` | 5s | ≈ `peer_count` from rippled admin (50-200 typical) | < 5 | Critical; = 0 = Page (matches `peer_count` semantics) |

**Notes.**
- Monthly bandwidth is the #1 hidden cost for validator hosting. The budget metric requires an operator-configured cap (e.g., "10 TB/month"); dashboard must accept that as config. See Field Guide **Network Bandwidth** section for sizing.
- Always alarm on `net_errors_*` and `net_drops_*`; both are symptoms of cable/NIC/upstream issues that will bleed into consensus.
- `peer_conn` (from `/proc`) is a cross-check on `peer_count` (from `admin:peers`). If the two diverge persistently, either rippled's admin API is reporting stale peer state or the TCP count is reading the wrong netns. Worth investigating either way.
- `*_conn` metrics are instantaneous (no delta required) so they populate on the first push after a relay restart, unlike bandwidth/packet/retransmit rates which need two samples.

---

## 9. rippled Internals

Process internals exposed by `get_counts` and `server_info.state_accounting`. Diagnostic-grade. Useful for tuning, less useful for surface dashboard display.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `get_counts.AL_hit_rate` | Accepted-ledger cache hit rate | P2 | | `admin:get_counts` | 60s | > 90% | < 70% | Warn |
| `get_counts.AL_size` | Accepted-ledger cache entries | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.AccountState` | Live AccountState cache entries | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.LedgerNode` | Cached ledger nodes | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.NodeObject` | Live NodeObjects | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.SLE_hit_rate` | SHAMap ledger entry cache hit rate | P2 | | `admin:get_counts` | 60s | > 90% | < 70% | Warn |
| `get_counts.SLE_size` | SLE cache size | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.treenode_cache_size` | TreeNode cache size | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.treenode_track_size` | TreeNode track size | P2 | | `admin:get_counts` | 60s | Stable | Unbounded growth | Warn |
| `get_counts.write_load` | Pending ledger writes | P1 | | `admin:get_counts` | 30s | Near zero most of the time | Sustained > 0 | Warn (IO can't keep up) |
| `get_counts.node_writes` | Cumulative node writes to DB | P2 | | `admin:get_counts` | 60s |, | Rate change | Warn |
| `get_counts.node_reads_total` / `node_reads_hit` | DB read cache effectiveness | P2 | | `admin:get_counts` | 60s | hit rate > 90% | < 70% | Warn |
| `get_counts.job_queue.{type}.in_progress` | Active jobs per queue type | P2 | | `admin:get_counts` | 30s | Bounded | Persistent backlog | Warn |
| `get_counts.job_queue.{type}.waiting` | Queued jobs per type | P1 | | `admin:get_counts` | 30s | Near zero | Growing | Warn; persistent = Critical |
| `get_counts.job_queue.{type}.threads` | Thread budget per type | P2 | | `admin:get_counts` | startup | Config-dependent |, |, |
| `initial_sync_duration_s` | Time from process start to `full`/`proposing` | P2 | | `derived` from `state_accounting` | startup | Matches machine class | Excessive | Warn (re-tune `node_size`) |

**Notes.**
- `get_counts` requires admin access. Many fields depend on build; treat the set as discoverable: collect all keys, not just a whitelist.
- Caches trending toward unbounded growth correlate with RSS pressure; `get_counts` is often where you catch a memory leak before it kills the process.

---

## 10. Data Integrity

Disk-resident ledger data. Subtle failures here are the ones that cause rippled to limp for days before dying.

| Metric | Description | Tier | V | Source | Cadence | Healthy | Alert | Sev |
|--------|-------------|------|---|--------|---------|---------|-------|-----|
| `nudb_size_bytes` | Total bytes in the NuDB data directory | P0 | | `fs:nudb` (`du`) | 10m | Matches `online_delete` growth curve | Unexpected plateau (writes stopped) or uncontrolled growth | Critical |
| `nudb_growth_rate_bps_24h` | 24h average growth rate | P1 | | `derived` | 1h | Steady | Sudden change | Warn |
| `nudb_mount_free_days` | Days until the data mount fills, at the growth measured over the last 24h | P0 | | `derived` | 1m | 3650 (the store is pruning, so it does not fill) | ≤ 30 days | Warn; ≤ 14 = Critical |
| `online_delete_configured_ledgers` | Configured history retention (from rippled.cfg) | P2 | | config read | startup | Operator intent | Mismatch with `complete_ledgers` | Warn |
| `advisory_delete_enabled` | Whether `[node_db] advisory_delete=1` is set | P2 | | config read | startup | Matches operator intent |, |, |
| `ledger_walk_errors_24h` | Log-reported NuDB/shard corruption events | P0 | | `log:debug.log` | stream | 0 | ≥ 1 | Page |
| `shard_count` | Number of history shards (if sharding configured) | P2 | | `admin:server_info.shards` / `admin:ledger` | 10m | Matches config |, |, |
| `shard_complete_pct{shard_index}` | Per-shard completion | P2 | | `admin:server_info.shards` | 10m | 100% | < 100% stalled | Warn |
| `ledger_integrity_check_status` | Result of last `ledger_cleaner` or equivalent integrity pass | P2 | | `log:debug.log` | daily | `success` | `errors found` | Critical |

**Notes.**
- `nudb_size` plateauing while ledgers keep closing is a symptom of failed writes. Seen in disk-full and permissions-regression incidents. Watch for divergence from the growth curve.
- `nudb_size_advisor` holds the readings the host's Advisor took of the store when the dashboard's own account cannot open it. Growth and free days on such a host are fitted from this series alone, so the sizes of a store that used to be on the host never reach the fit. Not charted on its own; `nudb_size` carries the same points for the chart.
- The size series starts over when the store is replaced. The dashboard records which store path the series was taken for, and a different path at the next start, or a size below a tenth of the last day's peak for two readings in a row, starts it over. Peak 24h, peak 7d, growth, free days and the chart then read only the current store, and growth and free days read "needs 2 days" until two days of it are on record. An ordinary `online_delete` rotation does not cut the series.
- `nudb_mount_free_days` is the safety net behind scheduled store rotation. A node that prunes reads 3650: the store sawtooths, 24-hour growth is flat or negative, and the mount does not fill. It only falls when growth is real and sustained, which is what a node that has stopped pruning looks like. Written only where the store is measured (`RIPPLED_DATA_PATH` set, and either the dashboard walks it or the host's Advisor measured it in the last three minutes); never written on an aggregator, where its rules simply never fire.
- Log-based metrics (`ledger_walk_errors_24h`, `ledger_integrity_check_status`) need structured log parsing. Keep the regex in a dedicated module; rippled log formats drift across minor versions.
- If the operator uses sharding, treat `shard_complete_pct` as P1. If not, hide the row (dashboard role detection).

---

## Alert Delivery (v1 Scope)

### v1: Email

- Email per alert. Subject: `[Sev] metric_name triggered on {host}`.
- Body: metric, current value, threshold, duration, direct link to dashboard panel, last-known-good timestamp.
- De-duplication: suppress re-send until alert clears or 1h elapses, whichever first.
- Configurable recipient list per severity (Page/Critical/Warn can have different distribution).

### Webhooks

- Discord, Slack, and a generic JSON format (`schema: aperire.alert.v1`) for any HTTP receiver. PagerDuty is reachable through the generic format pointed at its Events API. Same per-alert payload across formats, one adapter per target.

### v2: SMS / Phone

- Reserved for `Page`-severity only. Twilio or equivalent.

### Alert State Machine

```
OK → pending (threshold breached, waiting for duration) → firing → (resolved)
```

- `pending` requires threshold hold for the duration window (e.g., "> 85% for 5m") before it advances to `firing`.
- `firing` loops until condition clears.
- `resolved` is the cleared notification sent when `firing` ends; it is an event, not a held state.
- Alert state persists alongside the metrics in SQLite (`aperire.db`) so a dashboard restart doesn't resend everything.

---

## Role-Based Dashboard Visibility

The dashboard should detect node role at connect time and collapse irrelevant panels:

| Signal | Implies |
|--------|---------|
| `server_info.pubkey_validator` present + `server_state = proposing`/`validating` | Validator |
| `server_info.pubkey_validator` absent, `server_state = full` | Stock node |
| `server_info.reporting = true` | Reporting-mode node (further filtering, e.g., no consensus metrics) |

Metrics marked `V = ✓` above should be hidden for stock nodes. UNL/Amendment sections stay visible for both (operators care either way), but thresholds may differ.

---

## References

- **The Rippled Field Guide:** https://github.com/realgrapedrop/rippled-field-guide. Sections: Monitoring, Amendment Blocking, Validator Keys, Network Bandwidth, Database Management.
- **XRPL.org admin API:** https://xrpl.org/public-api-methods.html and https://xrpl.org/admin-rippled-methods.html for canonical field names (`server_info`, `server_state`, `consensus_info`, `feature`, `fee`, `get_counts`, `peers`, `validators`, `validator_list_sites`, `manifest`).
- **Prometheus node_exporter:** https://github.com/prometheus/node_exporter. Metric reference.
- **Related v4 docs:** [ARCHITECTURE-GUIDE.md](ARCHITECTURE-GUIDE.md) (components, data flows, trust boundaries); [METRICS-GUIDE.md](METRICS-GUIDE.md) (operator-facing tab-by-tab walkthrough).

---

## Appendix: Collection mechanics

How the System and Network metrics in this catalog are produced: the exact `/proc` paths, NIC and budget accounting, push cadence. The Network metrics are collected by the relay on the validator host. The System metrics are read by the dashboard from `/proc` on its own host (the validator when co-located, the dashboard host when split). For systemd hardening directives and day-2 commands see the [Relay reference](RELAY-REFERENCE.md).

### Per-metric `/proc` paths

Every System and Network metric, mapped to the exact source it's read from. Network metrics are read by the relay on the validator host; System metrics by the dashboard on its own host. All read-only, all "real-time as of read," all available to any unprivileged Linux user.

| Metric | Path | Field |
|--------|------|-------|
| CPU busy | `/proc/stat` | first line `cpu` (idle + iowait vs total) |
| CPU iowait | `/proc/stat` | `cpu` field 5 |
| CPU steal | `/proc/stat` | `cpu` field 8 |
| Cores | `/proc/cpuinfo` | count of `processor` lines |
| Load 1m / 5m / 15m | `/proc/loadavg` | first three fields |
| RAM total | `/proc/meminfo` | `MemTotal` |
| RAM available | `/proc/meminfo` | `MemAvailable` |
| Swap total | `/proc/meminfo` | `SwapTotal` |
| Swap free | `/proc/meminfo` | `SwapFree` |
| OOM kills | `/proc/vmstat` | `oom_kill` |
| CPU pressure | `/proc/pressure/cpu` | `some avg10` |
| Memory pressure | `/proc/pressure/memory` | `some avg10` |
| IO pressure | `/proc/pressure/io` | `some avg10` |
| Network bytes | `/proc/net/dev` | per-interface RX/TX bytes (delta over interval) |
| Network packets | `/proc/net/dev` | per-interface RX/TX packets |
| Network errors | `/proc/net/dev` | per-interface RX/TX errs |
| Network drops | `/proc/net/dev` | per-interface RX/TX drop |
| TCP established | `/proc/net/snmp` | `Tcp.CurrEstab` |
| TCP retransmits | `/proc/net/snmp` | `Tcp.RetransSegs` |
| TCP resets | `/proc/net/snmp` | `Tcp.OutRsts` |
| TCP TIME_WAIT | `/proc/net/sockstat` | `TCP: … tw` |
| Socket count | `/proc/net/sockstat` | `sockets: used` |
| NIC default route | `/proc/net/route`, `/proc/net/ipv6_route` | destination `0.0.0.0` / `0::/0` |
| Disk used / free | `statfs(path)` syscall | `(blocks − bfree) × bsize` |
| Disk total | `statfs(path)` syscall | `blocks × bsize` |
| Disk inodes used | `statfs(path)` syscall | `(files − ffree) / files` |
| NuDB size | directory walk of `RIPPLED_DATA_PATH` (dashboard env); the host's Advisor reading where the dashboard cannot open the store | recursive byte sum |
| Time drift | `adjtimex(2)` syscall | `offset` field |
| NTP sync | `adjtimex(2)` syscall | `status` flags |
| rippled CPU | `/proc/<pid>/stat` | `utime + stime` (delta over interval) |
| rippled RSS | `/proc/<pid>/status` | `VmRSS` |
| rippled FDs | `/proc/<pid>/fd` | directory entry count |
| rippled threads | `/proc/<pid>/status` | `Threads` |
| rippled uptime | `/proc/<pid>/stat` | `starttime` (delta from current jiffies) |
| Hardware temps | `/sys/class/hwmon/*/temp*_input` | per-sensor millidegrees |
| Port connections | `/proc/<rippled-pid>/net/tcp` + `tcp6` | per-port ESTABLISHED counts (rippled's netns; see [Port connection monitoring](RELAY-REFERENCE.md#port-connection-monitoring)) |

### NIC auto-discovery

A validator's external-facing interface is whichever one carries the **default route**, by definition what the kernel uses to reach the rest of the network. The relay resolves that on every push tick and reports the resolved name back.

**Resolution order:**

1. **IPv4 default route**: read `/proc/net/route`. Row with destination `00000000` (i.e. `0.0.0.0/0`) gives the interface in its first column. `interface_source` → `"default_route"`.
2. **IPv6 fallback**: if no IPv4 default exists, read `/proc/net/ipv6_route` and find the row with destination `0::/0`. `interface_source` → `"default_route"`.
3. **Aggregate fallback**: if no default route resolves (misconfigured host), sum counters across all non-loopback, non-virtual interfaces. Skip list: `lo`, `docker*`, `veth*`, `br-*`, `virbr*`, `tun*`, `tap*`, `wg*`, `cni*`. `interface_source` → `"fallback_sum"`.
4. **Config override**: if `relay.conf` sets `interface = "eth0"` (or any explicit name), skip auto-discovery entirely. `interface_source` → `"config"`.

Every push carries both `interface` and `interface_source` so the dashboard's Monthly Budget tooltip can display which path resolved. Useful for debugging multi-homed or VPN-first hosts.

**Why default-route discovery, not traffic-based heuristics.** Traffic-based selection ("pick whichever interface has the highest byte rate") looks clever but breaks in common cases: a bridge interface on a Docker host can dominate `/proc/net/dev` while being architecturally irrelevant. The default route is the kernel's own declaration of which NIC matters, and it costs a single file read per tick.

### Monthly bandwidth budget

**Monitoring only.** The relay does not cap, shape, or throttle any traffic. It reports two numbers, the dashboard divides them, the result colors a row on the card.

The Monthly Budget row on the Errors & Budget card shows a percentage:

| Band | Color |
|------|-------|
| `< 80%` | green |
| `80-94%` | amber |
| `≥ 95%` | red |

Hovering reveals `Used / Cap / NIC`.

**Configuration.** The cap is a property of the validator's hosting plan, not a UI preference, so it's configured relay-side in `relay.conf`:

```toml
# Hosting-provider monthly egress cap in bytes. Omit or set to 0 to
# disable the budget row (dashboard shows used total only).
monthly_budget_bytes = 5_000_000_000_000   # 5 TB
```

The relay passes this value through on every push as `monthly_budget_bytes`. It never computes the percentage itself.

**Dashboard-side accumulation.** The dashboard persists two tables in SQLite (`aperire.db`):

| Table | Key | Purpose |
|-------|-----|---------|
| `bandwidth_monthly` | `(node_label, year_month)` | Running per-month total (`rx_bytes`, `tx_bytes`). Partitioned by UTC `YYYY-MM` so rollover is automatic: a new partition starts the moment the UTC month ticks, and old months stay on disk for history. |
| `bandwidth_last_snapshot` | `node_label` | Most recent cumulative counter seen. Lets the dashboard keep accumulating across its own restarts: the first push after a restart diffs against this row, so downtime bytes aren't lost. |

**Reboot detection.** A cumulative counter that *decreases* between two pushes is a kernel reset (reboot, counter wrap, interface re-init). The dashboard drops the delta for that tick, sets the new lower value as the baseline, and the next push diffs normally. One tick of lost accounting per reboot, negligible.

### Cadence and freshness

Every 5 seconds the relay reads the network source files in parallel, builds its frame, and pushes it to the dashboard. End-to-end latency from kernel counter to pixel is well under 50 ms inside the 5-second tick. The System-tab source files are read separately by the dashboard from `/proc` on its own host.

Freshness is **quantized to 5 seconds**, not because of latency but because system and network metrics under 5 s are noisy and unactionable. Sub-5 s windows on byte counters are dominated by TCP burstiness, not by any real change in network state. 5 s matches the Prometheus default scrape interval, Grafana default refresh, and `node_exporter`'s collection interval, so operators coming from those tools won't find it unfamiliar.

The interval is tunable via `interval_seconds` in `relay.conf` (valid range 1-300 s). Raising it to 10-15 s halves the push-stream bandwidth, noticeable only for LAN-split (Shape B) deployments where the push crosses the network instead of loopback.
