package main

// rippled PID resolution for network-namespace aware socket reads.
//
// rippled commonly runs in a Docker container, in which case its sockets
// live in a container-local network namespace invisible to the host's
// /proc/net/tcp. The authoritative view is /proc/<rippled-pid>/net/tcp,
// which reads the rippled process's own netns regardless of container
// boundary. For native installs the two paths return identical data.
//
// Resolution priority:
//   1. rippled_pid_file in relay.conf — read one integer from the file.
//   2. A /proc scan for the node process, matched by comm or by the basename
//      of argv[0] in /proc/<pid>/cmdline. Works for containerized nodes too
//      because Docker uses PID namespacing but the host sees all PIDs.
//   3. 0 (unresolved) — caller falls back to host /proc/net/tcp.
//
// Which names count: forks rename the binary. The vendor build ships
// /usr/bin/xrpld whose main thread reads "xrpld-main" in comm (comm is
// capped at 15 chars), and Xahau ships xahaud. The list matches
// BINARY_NAMES in the dashboard's fork-alias registry (ADR 0002) plus the
// xrpld-main comm. A container's init shim (docker-init, tini), a shell and
// the relay itself are never in the list, so they never match.
//
// Several processes can match: the xrpld image's `xrpld server_info` CLI
// is a short-lived process with comm "xrpld". The scan keeps the oldest
// match (smallest start time in /proc/<pid>/stat, lowest PID on a tie),
// because the daemon lives for days and a CLI call for a second. Same rule
// the dashboard uses.

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// resolveRippledPID returns the node (rippled family) PID, or 0 if unresolved.
func resolveRippledPID(pidFile string) int {
	if pidFile != "" {
		if pid, err := readPIDFile(pidFile); err == nil && pid > 0 {
			return pid
		}
	}
	if pid := findNodePID("/proc"); pid > 0 {
		return pid
	}
	return 0
}

func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(bytes.TrimRight(data, "\x00")))
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("pid file %s: %w", path, err)
	}
	return pid, nil
}

// nodeCommNames are the /proc/<pid>/comm values of a node process.
var nodeCommNames = map[string]bool{
	"rippled":    true,
	"xrpld":      true,
	"xahaud":     true,
	"xrpld-main": true,
}

// nodeBinaryNames are the argv[0] basenames of a node process.
var nodeBinaryNames = map[string]bool{
	"rippled": true,
	"xrpld":   true,
	"xahaud":  true,
}

// findNodePID walks procRoot (normally /proc) and returns the PID of the
// node process: comm in nodeCommNames, or argv[0] basename in
// nodeBinaryNames. With several matches the oldest wins (see the header).
// Returns 0 if none.
func findNodePID(procRoot string) int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0
	}
	self := os.Getpid()
	best, bestStart := 0, uint64(0)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		dir := procRoot + "/" + e.Name()
		if !isNodeProcess(dir) {
			continue
		}
		start := procStartTime(dir)
		if best == 0 || start < bestStart || (start == bestStart && pid < best) {
			best, bestStart = pid, start
		}
	}
	return best
}

func isNodeProcess(dir string) bool {
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		if nodeCommNames[strings.TrimSpace(string(b))] {
			return true
		}
	}
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		argv0 := string(b)
		if i := strings.IndexByte(argv0, 0); i >= 0 {
			argv0 = argv0[:i]
		}
		if i := strings.LastIndexByte(argv0, '/'); i >= 0 {
			argv0 = argv0[i+1:]
		}
		return nodeBinaryNames[argv0]
	}
	return false
}

// procStartTime returns field 22 (starttime, clock ticks since boot) of
// <dir>/stat, or 0 if it can't be read. The comm field can hold spaces and
// parentheses, so parsing starts after the last ")".
func procStartTime(dir string) uint64 {
	b, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state), so field 22 is f[19].
	if len(f) < 20 {
		return 0
	}
	v, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}
