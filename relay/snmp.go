package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// snmpTCP is a subset of the Tcp: line from /proc/net/snmp — only the
// fields the dashboard consumes.
type snmpTCP struct {
	CurrEstab   uint64
	RetransSegs uint64
	OutRsts     uint64
}

// readSnmpTCP parses /proc/net/snmp. The file has paired header/value lines
// per protocol. Both lines start with the protocol tag. The header names
// the fields; the data line gives their values, in the same order.
//
//   Tcp: RtoAlgorithm RtoMin ... CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts ...
//   Tcp: 1            200    ... 245        ...    ...     8900        12     47     ...
//
// Field names occasionally shift across kernel versions, so we look up the
// column indices by name rather than hard-coding offsets.
func readSnmpTCP() (snmpTCP, error) {
	var out snmpTCP
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return out, err
	}
	defer f.Close()

	var header, values []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Tcp:") {
			continue
		}
		fields := strings.Fields(line[4:])
		if header == nil {
			header = fields
			continue
		}
		values = fields
		break
	}
	if header == nil || values == nil || len(header) != len(values) {
		return out, nil
	}
	for i, name := range header {
		v, err := strconv.ParseUint(values[i], 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "CurrEstab":
			out.CurrEstab = v
		case "RetransSegs":
			out.RetransSegs = v
		case "OutRsts":
			out.OutRsts = v
		}
	}
	return out, nil
}
