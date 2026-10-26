package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type sockstat struct {
	SocketsUsed uint64 // "sockets: used N"
	TCPTimeWait uint64 // "TCP: inuse … tw N …"
}

// readSockstat parses /proc/net/sockstat. Format (fixed, short):
//   sockets: used 312
//   TCP: inuse 245 orphan 0 tw 89 alloc 400 mem 12
//   UDP: inuse 4 mem 1
//   UDPLITE: inuse 0
//   RAW: inuse 0
//   FRAG: inuse 0 memory 0
func readSockstat() (sockstat, error) {
	var out sockstat
	f, err := os.Open("/proc/net/sockstat")
	if err != nil {
		return out, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		switch {
		case len(fields) >= 3 && fields[0] == "sockets:" && fields[1] == "used":
			out.SocketsUsed, _ = strconv.ParseUint(fields[2], 10, 64)
		case len(fields) >= 6 && fields[0] == "TCP:":
			// Walk fields looking for "tw" key. Kernel format is stable
			// enough that a linear scan is fine and tolerates reorders.
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "tw" {
					out.TCPTimeWait, _ = strconv.ParseUint(fields[i+1], 10, 64)
					break
				}
			}
		}
	}
	return out, nil
}
