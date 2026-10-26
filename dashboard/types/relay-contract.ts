// JSON contract between `aperire-relay` (Go, per validator host) and the
// dashboard's `/ingest` WebSocket endpoint (TypeScript, `mockup/server.ts`).
//
// Authentication: the WS upgrade request carries
//   Authorization: Bearer <token>
// Dashboard matches the token against its allow-list; on mismatch the
// connection is rejected with HTTP 401 before upgrade.
//
// After upgrade the relay pushes one `RelayPush` frame every
// `interval_seconds` (default 5) for as long as the connection stays open.
// Counter-style fields are monotonic cumulative values read from `/proc` —
// the dashboard diffs consecutive pushes to derive Bps / pps / deltas and
// treats a decrease as a reboot (resets baseline, drops that tick).

/** Single frame sent by the relay on every push tick. */
export interface RelayPush {
  type: 'push';
  protocol_version: 1;
  node_label: string;         // operator-chosen, identifies the validator
  relay_version: string;      // semver of the relay binary
  sent_at_ms: number;         // relay wall clock at send (UTC, ms since epoch)
  payload: RelayPayload;
}

/** Discriminated union — one block per metric family. The relay sends one
 *  frame per family every tick: `net_stats` then `system`. */
export type RelayPayload = NetStatsPayload | SystemPayload;

/** Host compute metrics for the validator host, mirroring `SystemPayload` in
 *  relay/contract.go. When a relay is feeding the dashboard these replace the
 *  dashboard's own /proc reading for the System tab's CPU / Memory / Swap /
 *  Disk / Pressure / OOM rows — on Shape B those two hosts differ, and the
 *  tab describes the validator, not the box the dashboard runs on. */
export interface SystemPayload {
  kind: 'system';
  /** The relay host's own hostname. Lets the dashboard tell a co-located
   *  relay from a split deployment. Older relays omit it. */
  hostname?: string;
  cpu: {
    busy_pct: number;
    /** Present from relay builds that report them; older relays omit both. */
    iowait_pct?: number;
    steal_pct?: number;
    cores: number;
    load_1m: number;
    load_5m: number;
    load_15m: number;
  };
  memory: {
    used_pct: number;
    used_bytes: number;
    total_bytes: number;
    /** Reclaimable file cache, MemAvailable − MemFree. Optional: a relay
     *  older than these fields omits both, and the dashboard reads their
     *  absence as "not reported" rather than as zero — the difference
     *  between a box with no cache and a relay that cannot say. Additive,
     *  so `protocol_version` is unchanged. */
    cache_bytes?: number;
    cache_pct?: number;
  };
  swap:   { used_pct: number; used_bytes: number; total_bytes: number };
  disk:   { used_pct: number; used_bytes: number; total_bytes: number; mount: string };
  /** Pressure Stall Information, `some avg10`, 0-100. */
  pressure_cpu_some_pct: number;
  pressure_memory_some_pct: number;
  pressure_io_some_pct: number;
  /** Cumulative since boot, from /proc/vmstat. */
  oom_kills_total: number;
}

/** Snapshot of network counters from `/proc/net/dev`, `/proc/net/snmp`,
 *  and `/proc/net/sockstat`. Fuels the Network tab's Bandwidth Live and
 *  Errors & Budget cards. */
export interface NetStatsPayload {
  kind: 'net_stats';

  /** Resolved primary interface name, e.g. `"eth0"`. */
  interface: string;
  /** How the relay picked the interface — surfaced in the dashboard for
   *  operator debugging of odd topologies. */
  interface_source: 'default_route' | 'config' | 'fallback_sum';

  // ── /proc/net/dev — cumulative since boot (or interface up) ──
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
  rx_drops: number;
  tx_drops: number;

  // ── /proc/net/snmp — TCP block ──
  tcp_established: number;    // Tcp.CurrEstab  (instantaneous)
  tcp_retrans_segs: number;   // Tcp.RetransSegs (cumulative → per-sec)
  tcp_out_resets: number;     // Tcp.OutRsts    (cumulative → per-sec)

  // ── /proc/net/sockstat ──
  tcp_time_wait: number;      // `TW:` line
  socket_count: number;       // `sockets: used` line

  // ── /proc/net/tcp{,6} — current ESTABLISHED by local port ──
  // Auto-detected from rippled.cfg at relay startup, or overridden via
  // http_rpc_port / admin_ws_port / ws_public_port / peer_port in
  // relay.conf. Instantaneous counts.
  http_rpc_connections:  number;
  admin_ws_connections:  number;
  ws_public_connections: number;
  peer_connections:      number;

  /** Hosting-plan monthly egress cap in bytes (e.g. 5 TB → 5_000_000_000_000),
   *  or null when the operator hasn't set one. Pass-through from `relay.conf`;
   *  the relay never computes percentages — the dashboard accumulates deltas
   *  across the month and renders `used / cap`. */
  monthly_budget_bytes: number | null;
}
