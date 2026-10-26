package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type meminfo struct {
	MemTotal     uint64 // kB
	MemAvailable uint64 // kB
	MemFree      uint64 // kB
	SwapTotal    uint64 // kB
	SwapFree     uint64 // kB
}

// readMeminfo parses /proc/meminfo. Each line is `Key: N kB`. We stop early
// once all five required keys are seen.
//
// MemFree is read for one derived number: page cache is MemAvailable minus
// MemFree, the memory the kernel is holding as reclaimable file cache. On a
// validator that is mostly node-store pages, and it is what makes "used" and
// "available" add up to the box's RAM on the System tab.
func readMeminfo() (meminfo, error) {
	var out meminfo
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return out, err
	}
	defer f.Close()
	needed := 5
	sc := bufio.NewScanner(f)
	for sc.Scan() && needed > 0 {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 1 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			out.MemTotal = v
			needed--
		case "MemAvailable":
			out.MemAvailable = v
			needed--
		case "MemFree":
			out.MemFree = v
			needed--
		case "SwapTotal":
			out.SwapTotal = v
			needed--
		case "SwapFree":
			out.SwapFree = v
			needed--
		}
	}
	return out, nil
}
