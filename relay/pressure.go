package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// readPressureSome returns the "some avg10" percentage from a /proc/pressure
// file. Format:
//   some avg10=0.10 avg60=0.05 avg300=0.02 total=1234
//   full avg10=0.00 avg60=0.00 avg300=0.00 total=0
//
// "avg10" is the 10-second rolling average percentage (0-100) of time at
// least one task was stalled on the resource. Returns 0 if the kernel
// doesn't have PSI enabled (file absent, pre-4.20, or disabled).
func readPressureSome(path string) float64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, token := range strings.Fields(line[5:]) {
			if strings.HasPrefix(token, "avg10=") {
				v, err := strconv.ParseFloat(token[6:], 64)
				if err != nil {
					return 0
				}
				return v
			}
		}
	}
	return 0
}

// readVmstatOomKills pulls `oom_kill` from /proc/vmstat — the cumulative
// count of OOM-kills since boot. Some kernels don't export this line; we
// return 0 in that case (rather than erroring) so the field degrades
// gracefully.
func readVmstatOomKills() uint64 {
	f, err := os.Open("/proc/vmstat")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == "oom_kill" {
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			return v
		}
	}
	return 0
}
