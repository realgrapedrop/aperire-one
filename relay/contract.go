// Go mirror of the JSON contract defined in this repo at
// dashboard/types/relay-contract.ts. Changes here must be matched there
// (and vice versa) — the wire format is the integration point.
package main

// RelayPush is one frame on the ingest WebSocket. The relay sends one per
// tick after the connection is authenticated; the dashboard consumes and
// diffs cumulative fields to derive rate metrics.
type RelayPush struct {
	Type            string      `json:"type"`              // always "push"
	ProtocolVersion int         `json:"protocol_version"`  // currently 1
	NodeLabel       string      `json:"node_label"`
	RelayVersion    string      `json:"relay_version"`
	SentAtMs        int64       `json:"sent_at_ms"`        // UTC ms since epoch
	Payload         interface{} `json:"payload"`           // NetStatsPayload | SystemPayload
}

// NetStatsPayload carries /proc/net snapshot data. The dashboard diffs
// cumulative fields against the prior push to get Bps / pps / per-sec rates.
type NetStatsPayload struct {
	Kind             string `json:"kind"`              // "net_stats"
	Interface        string `json:"interface"`
	InterfaceSource  string `json:"interface_source"`  // "default_route" | "config" | "fallback_sum"

	// /proc/net/dev — cumulative since interface up
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDrops   uint64 `json:"rx_drops"`
	TxDrops   uint64 `json:"tx_drops"`

	// /proc/net/snmp Tcp block
	TcpEstablished  uint64 `json:"tcp_established"`   // instantaneous
	TcpRetransSegs  uint64 `json:"tcp_retrans_segs"`  // cumulative
	TcpOutResets    uint64 `json:"tcp_out_resets"`    // cumulative

	// /proc/net/sockstat
	TcpTimeWait uint64 `json:"tcp_time_wait"`         // instantaneous
	SocketCount uint64 `json:"socket_count"`          // instantaneous

	// Current concurrent ESTABLISHED connections on each rippled port
	// (source: /proc/net/tcp + /proc/net/tcp6, filtered by local port).
	// Ports auto-detected from rippled.cfg at startup; overrideable via
	// relay.conf (http_rpc_port / admin_ws_port / ws_public_port / peer_port).
	HttpRpcConnections  uint64 `json:"http_rpc_connections"`
	AdminWsConnections  uint64 `json:"admin_ws_connections"`
	WsPublicConnections uint64 `json:"ws_public_connections"`
	PeerConnections     uint64 `json:"peer_connections"`

	// Pass-through from relay.conf, may be null if unset.
	MonthlyBudgetBytes *uint64 `json:"monthly_budget_bytes"`
}

// SystemPayload carries host-level compute metrics. Shape mirrors the JSON
// contract section of docs/system-metrics-collection.md — see that file for
// field semantics. All bytes fields are absolute; CPU / pressure are
// percentages pre-computed by the relay over a short rolling window.
type SystemPayload struct {
	Kind string `json:"kind"` // "system"

	// The relay host's own name. The dashboard compares it with its own to
	// tell a co-located relay (same box, either source is fine) from a
	// split deployment (the tab must never fall back to the dashboard's
	// host when the relay goes quiet).
	Hostname string `json:"hostname"`

	CPU    CPUBlock    `json:"cpu"`
	Memory MemoryBlock `json:"memory"`
	Swap   SwapBlock   `json:"swap"`
	Disk   DiskBlock   `json:"disk"`

	// Pressure Stall Information, percentages (0-100). avg10s.
	PressureCPU    float64 `json:"pressure_cpu_some_pct"`
	PressureMemory float64 `json:"pressure_memory_some_pct"`
	PressureIO     float64 `json:"pressure_io_some_pct"`

	OOMKills uint64 `json:"oom_kills_total"`
}

type CPUBlock struct {
	BusyPct float64 `json:"busy_pct"`
	// iowait and steal as a share of the same window busy_pct is computed
	// over. The dashboard's own /proc reader has always reported both, so a
	// System tab fed by the relay must not lose them.
	IOWaitPct float64 `json:"iowait_pct"`
	StealPct  float64 `json:"steal_pct"`
	Cores     int     `json:"cores"`
	Load1m    float64 `json:"load_1m"`
	Load5m    float64 `json:"load_5m"`
	Load15m   float64 `json:"load_15m"`
}

type MemoryBlock struct {
	UsedPct    float64 `json:"used_pct"`
	UsedBytes  uint64  `json:"used_bytes"`
	TotalBytes uint64  `json:"total_bytes"`
	// Reclaimable file cache, MemAvailable minus MemFree. Additive: a
	// dashboard older than these fields ignores them, and a dashboard newer
	// than the relay reads their absence as "not reported", never as zero.
	// No protocol_version bump for that reason.
	CacheBytes uint64  `json:"cache_bytes"`
	CachePct   float64 `json:"cache_pct"`
}

type SwapBlock struct {
	UsedPct    float64 `json:"used_pct"`
	UsedBytes  uint64  `json:"used_bytes"`
	TotalBytes uint64  `json:"total_bytes"`
}

type DiskBlock struct {
	UsedPct    float64 `json:"used_pct"`
	UsedBytes  uint64  `json:"used_bytes"`
	TotalBytes uint64  `json:"total_bytes"`
	Mount      string  `json:"mount"`
}
