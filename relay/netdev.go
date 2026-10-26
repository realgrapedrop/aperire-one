package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// netDevRow is the per-interface counter snapshot. All fields are cumulative
// since the interface came up; the dashboard derives rates from deltas.
type netDevRow struct {
	Name      string
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	RxDrops   uint64
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	TxDrops   uint64
}

// readNetDev parses /proc/net/dev. Format:
//
//   Inter-|   Receive                                                | Transmit
//    face | bytes packets errs drop fifo frame compressed multicast  | bytes packets errs drop fifo colls carrier compressed
//     eth0:  123   45      0    0    0    0     0          0         | 234   67      0    0    0    0    0       0
//
// Columns after the colon are whitespace-separated; we only pull the subset
// the dashboard actually uses.
func readNetDev() ([]netDevRow, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rows []netDevRow
	sc := bufio.NewScanner(f)
	// Skip the two header lines.
	sc.Scan()
	sc.Scan()
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		row := netDevRow{Name: name}
		get := func(i int) uint64 {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			return v
		}
		row.RxBytes = get(0)
		row.RxPackets = get(1)
		row.RxErrors = get(2)
		row.RxDrops = get(3)
		row.TxBytes = get(8)
		row.TxPackets = get(9)
		row.TxErrors = get(10)
		row.TxDrops = get(11)
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan /proc/net/dev: %w", err)
	}
	return rows, nil
}

// selectNetDev returns the single row the relay should report. If resolved
// is a specific interface name, pick that row. If fallback_sum, sum all
// non-virtual rows into a synthetic row named "aggregate".
func selectNetDev(rows []netDevRow, resolved, source string) netDevRow {
	if source != sourceFallbackSum {
		for _, r := range rows {
			if r.Name == resolved {
				return r
			}
		}
		// resolved name is stale or missing — degrade to sum so we still
		// emit something meaningful.
	}
	agg := netDevRow{Name: "aggregate"}
	for _, r := range rows {
		if isVirtualInterface(r.Name) {
			continue
		}
		agg.RxBytes += r.RxBytes
		agg.RxPackets += r.RxPackets
		agg.RxErrors += r.RxErrors
		agg.RxDrops += r.RxDrops
		agg.TxBytes += r.TxBytes
		agg.TxPackets += r.TxPackets
		agg.TxErrors += r.TxErrors
		agg.TxDrops += r.TxDrops
	}
	return agg
}
