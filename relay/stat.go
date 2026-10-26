package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// cpuJiffies is the aggregate cpu line from /proc/stat, in jiffies since boot.
type cpuJiffies struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

func (c cpuJiffies) total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// readProcStat returns the aggregate (first) cpu line. Per-core lines exist
// but the dashboard only reports the overall busy percentage.
func readProcStat() (cpuJiffies, error) {
	var out cpuJiffies
	f, err := os.Open("/proc/stat")
	if err != nil {
		return out, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return out, fmt.Errorf("empty /proc/stat")
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 9 || fields[0] != "cpu" {
		return out, fmt.Errorf("unexpected /proc/stat first line")
	}
	parts := [8]*uint64{&out.User, &out.Nice, &out.System, &out.Idle, &out.IOWait, &out.IRQ, &out.SoftIRQ, &out.Steal}
	for i := 0; i < 8 && i+1 < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i+1], 10, 64)
		*parts[i] = v
	}
	return out, nil
}

// cpuBusyPct returns the busy percentage between two jiffy snapshots. The
// formula is 100 * (1 - (idle_delta + iowait_delta) / total_delta). We fold
// iowait into idle because a CPU that's idle-waiting-for-IO is not "busy"
// from a scheduler-saturation perspective — the node_exporter / top default.
func cpuBusyPct(prev, cur cpuJiffies) float64 {
	busy, _, _ := cpuPcts(prev, cur)
	return busy
}

// cpuPcts returns busy, iowait and steal percentages over the same window,
// so the three always describe one interval. Returns zeros when the window
// is empty or the counters went backwards (a reboot).
func cpuPcts(prev, cur cpuJiffies) (busy, iowait, steal float64) {
	totalDelta := int64(cur.total()) - int64(prev.total())
	if totalDelta <= 0 {
		return 0, 0, 0
	}
	idleDelta := int64(cur.Idle+cur.IOWait) - int64(prev.Idle+prev.IOWait)
	iowaitDelta := int64(cur.IOWait) - int64(prev.IOWait)
	stealDelta := int64(cur.Steal) - int64(prev.Steal)
	busy = 100.0 * (1.0 - float64(idleDelta)/float64(totalDelta))
	iowait = 100.0 * float64(iowaitDelta) / float64(totalDelta)
	steal = 100.0 * float64(stealDelta) / float64(totalDelta)
	return busy, iowait, steal
}

// cpuCount uses runtime.NumCPU. On Linux this reports the GOMAXPROCS default,
// which matches the visible core count absent cgroup CPU pinning.
func cpuCount() int {
	return runtime.NumCPU()
}
