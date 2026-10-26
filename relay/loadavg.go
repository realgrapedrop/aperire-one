package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readLoadAvg parses /proc/loadavg. Format:
//   0.50 0.70 0.60 1/123 4567
// Returns the three load averages (1m / 5m / 15m).
func readLoadAvg() (l1, l5, l15 float64, err error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("short /proc/loadavg")
	}
	l1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	l5, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return l1, 0, 0, err
	}
	l15, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return l1, l5, 0, err
	}
	return l1, l5, l15, nil
}
