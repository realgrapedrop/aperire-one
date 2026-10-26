package main

import (
	"log"
	"os"
)

// collectNet builds a NetStatsPayload from one snapshot of all relevant
// /proc/net files. Errors on individual files are logged but don't abort —
// the relay would rather send a partial payload than go dark.
func collectNet(cfg *Config) NetStatsPayload {
	resolved, source := resolveInterface(cfg.Interface)

	rows, err := readNetDev()
	if err != nil {
		log.Printf("[collect] /proc/net/dev: %v", err)
	}
	selected := selectNetDev(rows, resolved, source)
	if source == sourceFallbackSum {
		resolved = selected.Name
	}

	tcp, err := readSnmpTCP()
	if err != nil {
		log.Printf("[collect] /proc/net/snmp: %v", err)
	}

	ss, err := readSockstat()
	if err != nil {
		log.Printf("[collect] /proc/net/sockstat: %v", err)
	}

	// Resolve rippled's PID every tick so a rippled restart is picked up
	// automatically. Using the rippled netns is correct for both Docker
	// and native installs — the native case collapses to the host
	// namespace because /proc/<pid>/net/tcp reads the same data.
	rippledPID := resolveRippledPID(cfg.RippledPIDFile)

	httpRpcConn, err := countEstablishedOnPort(cfg.HttpRpcPort, rippledPID)
	if err != nil {
		log.Printf("[collect] /proc/net/tcp (http_rpc port %d): %v", cfg.HttpRpcPort, err)
	}
	adminWsConn, err := countEstablishedOnPort(cfg.AdminWsPort, rippledPID)
	if err != nil {
		log.Printf("[collect] /proc/net/tcp (admin_ws port %d): %v", cfg.AdminWsPort, err)
	}
	wsPublicConn, err := countEstablishedOnPort(cfg.WsPublicPort, rippledPID)
	if err != nil {
		log.Printf("[collect] /proc/net/tcp (ws_public port %d): %v", cfg.WsPublicPort, err)
	}
	// Peer connections go both directions (we dial out AND peers dial in),
	// so we count matches on either end.
	peerConn, err := countEstablishedOnPortEitherEnd(cfg.PeerPort, rippledPID)
	if err != nil {
		log.Printf("[collect] /proc/net/tcp (peer port %d): %v", cfg.PeerPort, err)
	}

	var budget *uint64
	if cfg.MonthlyBudgetBytes > 0 {
		b := cfg.MonthlyBudgetBytes
		budget = &b
	}

	return NetStatsPayload{
		Kind:               "net_stats",
		Interface:          resolved,
		InterfaceSource:    source,
		RxBytes:            selected.RxBytes,
		TxBytes:            selected.TxBytes,
		RxPackets:          selected.RxPackets,
		TxPackets:          selected.TxPackets,
		RxErrors:           selected.RxErrors,
		TxErrors:           selected.TxErrors,
		RxDrops:            selected.RxDrops,
		TxDrops:            selected.TxDrops,
		TcpEstablished:     tcp.CurrEstab,
		TcpRetransSegs:     tcp.RetransSegs,
		TcpOutResets:       tcp.OutRsts,
		TcpTimeWait:        ss.TCPTimeWait,
		SocketCount:        ss.SocketsUsed,
		HttpRpcConnections:  httpRpcConn,
		AdminWsConnections:  adminWsConn,
		WsPublicConnections: wsPublicConn,
		PeerConnections:     peerConn,
		MonthlyBudgetBytes:  budget,
	}
}

// systemState carries what the system collector needs to hold between ticks:
// the previous CPU jiffy snapshot, since busy% is a delta. Nil means "no
// prior sample" — first tick reports 0% until the second.
type systemState struct {
	prevCPU *cpuJiffies
}

// collectSystem builds a SystemPayload. First call after startup produces
// CPU busy=0 because we have no prior jiffy snapshot to diff against; that
// single 5s window is the cold-start cost and self-corrects on the next tick.
func collectSystem(cfg *Config, state *systemState) SystemPayload {
	out := SystemPayload{Kind: "system"}
	if h, err := os.Hostname(); err == nil {
		out.Hostname = h
	}

	if cur, err := readProcStat(); err != nil {
		log.Printf("[collect] /proc/stat: %v", err)
	} else {
		if state.prevCPU != nil {
			out.CPU.BusyPct, out.CPU.IOWaitPct, out.CPU.StealPct = cpuPcts(*state.prevCPU, cur)
		}
		state.prevCPU = &cur
	}
	out.CPU.Cores = cpuCount()
	if l1, l5, l15, err := readLoadAvg(); err != nil {
		log.Printf("[collect] /proc/loadavg: %v", err)
	} else {
		out.CPU.Load1m = l1
		out.CPU.Load5m = l5
		out.CPU.Load15m = l15
	}

	if mi, err := readMeminfo(); err != nil {
		log.Printf("[collect] /proc/meminfo: %v", err)
	} else {
		totalB := mi.MemTotal * 1024
		usedB := (mi.MemTotal - mi.MemAvailable) * 1024
		out.Memory.TotalBytes = totalB
		out.Memory.UsedBytes = usedB
		// Page cache: what the kernel is holding as reclaimable file cache.
		// MemAvailable already counts it as available, so used + cache + free
		// is the whole of RAM. Clamped at zero because MemAvailable is the
		// kernel's estimate and can sit a hair under MemFree on a box with
		// almost nothing cached.
		var cacheB uint64
		if mi.MemAvailable > mi.MemFree {
			cacheB = (mi.MemAvailable - mi.MemFree) * 1024
		}
		out.Memory.CacheBytes = cacheB
		if totalB > 0 {
			out.Memory.UsedPct = 100.0 * float64(usedB) / float64(totalB)
			out.Memory.CachePct = 100.0 * float64(cacheB) / float64(totalB)
		}
		swapTotalB := mi.SwapTotal * 1024
		swapUsedB := (mi.SwapTotal - mi.SwapFree) * 1024
		out.Swap.TotalBytes = swapTotalB
		out.Swap.UsedBytes = swapUsedB
		if swapTotalB > 0 {
			out.Swap.UsedPct = 100.0 * float64(swapUsedB) / float64(swapTotalB)
		}
	}

	if used, total, err := readStatfs(cfg.DataMount); err != nil {
		log.Printf("[collect] statfs %s: %v", cfg.DataMount, err)
	} else {
		out.Disk.UsedBytes = used
		out.Disk.TotalBytes = total
		out.Disk.Mount = cfg.DataMount
		if total > 0 {
			out.Disk.UsedPct = 100.0 * float64(used) / float64(total)
		}
	}

	out.PressureCPU = readPressureSome("/proc/pressure/cpu")
	out.PressureMemory = readPressureSome("/proc/pressure/memory")
	out.PressureIO = readPressureSome("/proc/pressure/io")
	out.OOMKills = readVmstatOomKills()

	return out
}
