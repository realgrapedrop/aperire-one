package main

// Current concurrent TCP connections per local port.
//
// Linux exposes every TCP socket in /proc/net/tcp (IPv4) and /proc/net/tcp6
// (IPv6). Each row carries the local address as HEX_IP:HEX_PORT and a state
// code — 01 is ESTABLISHED. We count rows whose local port matches the
// target and whose state is ESTABLISHED. Pure read, no side effects; runs
// on the same 5s tick as the rest of collectNet.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// procNetPaths returns the /proc paths to read TCP socket tables from.
// When `pid > 0` we read /proc/<pid>/net/{tcp,tcp6} — the rippled
// process's own network namespace, which is the authoritative view for
// containerized rippled installs (Docker). pid == 0 falls back to the
// host namespace. On native installs the two paths are identical.
func procNetPaths(pid int) []string {
	if pid > 0 {
		base := fmt.Sprintf("/proc/%d/net", pid)
		return []string{base + "/tcp", base + "/tcp6"}
	}
	return []string{"/proc/net/tcp", "/proc/net/tcp6"}
}

// countEstablishedOnPort sums ESTABLISHED connections whose LOCAL port
// matches `port`. Correct semantic for service-provider ports (HTTP RPC,
// Admin WS, WS Public) where clients always dial in. Reads from rippled's
// netns when pid > 0.
func countEstablishedOnPort(port uint16, pid int) (uint64, error) {
	return countEstablished(port, pid, false)
}

// countEstablishedOnPortEitherEnd sums ESTABLISHED connections where
// either the local or remote port matches `port`. Correct semantic for
// the peer protocol port because peer connections go both directions —
// we dial out to some peers (remote port = peer port) and others dial
// in (local port = peer port). Counting only one side hides half.
func countEstablishedOnPortEitherEnd(port uint16, pid int) (uint64, error) {
	return countEstablished(port, pid, true)
}

func countEstablished(port uint16, pid int, eitherEnd bool) (uint64, error) {
	if port == 0 {
		return 0, nil
	}
	paths := procNetPaths(pid)
	// If the rippled-namespace read fails (permission, race, container
	// gone), retry against the host namespace so the relay still reports
	// something rather than going dark. Logged by the caller.
	total, err := sumAcrossFiles(paths, port, eitherEnd)
	if err != nil && pid > 0 {
		return sumAcrossFiles([]string{"/proc/net/tcp", "/proc/net/tcp6"}, port, eitherEnd)
	}
	return total, err
}

func sumAcrossFiles(paths []string, port uint16, eitherEnd bool) (uint64, error) {
	var total uint64
	for _, path := range paths {
		n, err := countEstablishedInFile(path, port, eitherEnd)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		total += n
	}
	return total, nil
}

func countEstablishedInFile(path string, port uint16, eitherEnd bool) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Linux encodes ports as 4 uppercase hex digits after the colon,
	// zero-padded. e.g. port 5005 → :138D, port 22 → :0016.
	portSuffix := fmt.Sprintf(":%04X", port)

	var count uint64
	sc := bufio.NewScanner(f)
	// Line 1 is the header (`sl local_address rem_address st ...`).
	sc.Scan()
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		// fields[1] = local_address, fields[2] = rem_address, fields[3] = state.
		if fields[3] != "01" {
			continue
		}
		matches := strings.HasSuffix(fields[1], portSuffix)
		if !matches && eitherEnd {
			matches = strings.HasSuffix(fields[2], portSuffix)
		}
		if matches {
			count++
		}
	}
	return count, sc.Err()
}
