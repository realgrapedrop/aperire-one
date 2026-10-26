package main

// rippled.cfg port auto-detection.
//
// rippled's config uses INI-style sections. Admin-accessible ports live in
// `[port_*]` sections that declare `port = N`, `protocol = http|ws|...`, and
// an `admin = <ip-list>` whitelist. The presence of a non-empty `admin` line
// is what distinguishes an admin-reachable section from e.g. the public peer
// port (`[port_peer]`, protocol = peer, no admin).
//
// Auto-detection picks the first admin-enabled section whose protocol field
// contains "http" (→ HTTP RPC admin port) or "ws" (→ Admin WebSocket port),
// in the order they appear in the file. Misses / missing files return zero
// values and the caller falls back to the well-known defaults (5005 / 6006).

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// RippledPorts holds the auto-detected port numbers. Zero means "not found
// — use defaults or config override."
//
// Classification rules:
//   - Peer      → protocol contains "peer"
//   - HttpRpc   → admin whitelist set AND protocol contains "http"
//   - AdminWs   → admin whitelist set AND protocol contains "ws"
//   - WsPublic  → admin whitelist empty AND protocol contains "ws"
type RippledPorts struct {
	HttpRpc  uint16
	AdminWs  uint16
	WsPublic uint16
	Peer     uint16
}

type portSection struct {
	name     string
	port     uint64
	protocol string
	admin    string
}

// readRippledCfg parses rippled.cfg and classifies its admin-enabled
// `[port_*]` sections by protocol. Returns zero RippledPorts if the file
// exists but no admin sections are found; returns error only on I/O failure.
func readRippledCfg(path string) (RippledPorts, error) {
	var out RippledPorts

	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()

	var sections []portSection
	var cur *portSection
	flush := func() {
		if cur != nil {
			sections = append(sections, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(f)
	// rippled.cfg can have long comment lines.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if strings.HasPrefix(name, "port_") {
				cur = &portSection{name: name}
			}
			continue
		}
		if cur == nil {
			continue
		}
		// We only care about `key = value` lines inside port sections.
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "port":
			if p, err := strconv.ParseUint(val, 10, 16); err == nil {
				cur.port = p
			}
		case "protocol":
			cur.protocol = strings.ToLower(val)
		case "admin":
			cur.admin = val
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return out, err
	}

	// Classify each port section. First match per classification wins.
	// Peer (always admin-less by design) is classified before the
	// admin/non-admin split for http/ws.
	for _, s := range sections {
		if s.port == 0 {
			continue
		}
		hasAdmin := s.admin != ""
		switch {
		case strings.Contains(s.protocol, "peer"):
			if out.Peer == 0 {
				out.Peer = uint16(s.port)
			}
		case hasAdmin && strings.Contains(s.protocol, "ws"):
			if out.AdminWs == 0 {
				out.AdminWs = uint16(s.port)
			}
		case hasAdmin && strings.Contains(s.protocol, "http"):
			if out.HttpRpc == 0 {
				out.HttpRpc = uint16(s.port)
			}
		case !hasAdmin && strings.Contains(s.protocol, "ws"):
			if out.WsPublic == 0 {
				out.WsPublic = uint16(s.port)
			}
		}
	}

	return out, nil
}

// defaultRippledCfgPaths lists the well-known install paths to probe when
// the operator didn't set rippled_cfg_path explicitly. First match wins.
var defaultRippledCfgPaths = []string{
	"/etc/opt/ripple/rippled.cfg",
	"/opt/ripple/etc/rippled.cfg",
	"/etc/ripple/rippled.cfg",
}

// resolvePortsFromCfg tries the explicit path first, then the well-known
// defaults. Returns whichever is first readable and what it found.
func resolvePortsFromCfg(explicitPath string) (RippledPorts, string, error) {
	var paths []string
	if explicitPath != "" {
		paths = []string{explicitPath}
	} else {
		paths = defaultRippledCfgPaths
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		ports, err := readRippledCfg(p)
		if err != nil {
			return RippledPorts{}, p, err
		}
		return ports, p, nil
	}
	return RippledPorts{}, "", nil
}
