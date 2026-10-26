package main

// Re-reading the fleet registry when it changes (#859).
//
// Root's fleet broker takes a revoked node out of advisor/state/fleet.json
// (and adds a paired one) while this process runs. Before #859 the file was
// loaded once at start, so a revoked peer stayed in this Advisor's peer table
// until somebody restarted it, which is the restart the operator was promised
// they would never have to make.
//
// Not a signal. A Go process with no SIGHUP handler exits on SIGHUP, so the
// broker signalling this process would be a restart by another name, and a
// handler added here would turn every stray kill -HUP into a reload nobody
// asked for. Instead every fleet use asks fleetNow(), which stats the file
// and reloads it when (device, inode, mtime, size) moved. The broker places
// the file by rename, so a changed file is always a new inode and a reader
// never sees half of one.
//
// Same loading rules as at start (fleet.Load, never a half-registered
// fleet), with one difference the #866 review asked for: a RE-read that
// fails keeps the last good table, where a failed start-up has nothing to
// keep and starts empty. Keeping it is safe because a revoked peer's token
// in /etc/aperire/fleet-tokens is already gone, so a stale peer fails closed;
// emptying it would take every live peer away for one bad write. An absent
// file is not a failure: fleet.Load answers it as an empty registry. The
// registry, its clients and its label set swap together under one lock,
// because the label set gates route suggestions and is not token-gated.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"aperire-advisor/internal/dashread"
	"aperire-advisor/internal/fleet"
)

// fleetStamp is what "the file changed" means here. The zero value is "no
// file", so an absent registry that stays absent never reloads.
type fleetStamp struct {
	present bool
	dev     uint64
	ino     uint64
	mtimeNs int64
	size    int64
}

func statFleetStamp(path string) fleetStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fleetStamp{}
	}
	st := fleetStamp{present: true, mtimeNs: fi.ModTime().UnixNano(), size: fi.Size()}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.dev = uint64(sys.Dev) //nolint:unconvert // Dev is uint64 on linux/amd64, uint32 elsewhere
		st.ino = sys.Ino
	}
	return st
}

// fleetView is one consistent reading of the registry: the registry itself,
// a read client per peer, and the set of peer labels. A request takes ONE view
// and uses it throughout, so the menu it describes and the nodes its loop
// resolves against can never come from two different files.
type fleetView struct {
	reg     *fleet.Registry
	clients map[string]*dashread.Client
	nodes   map[string]bool
}

// fleetDerived builds the clients and the label set from a registry, the
// same way main() always has.
func fleetDerived(reg *fleet.Registry) (map[string]*dashread.Client, map[string]bool) {
	clients := map[string]*dashread.Client{}
	nodes := map[string]bool{}
	if reg == nil {
		return clients, nodes
	}
	for _, p := range reg.Peers {
		nodes[p.Label] = true
		clients[p.Label] = &dashread.Client{
			BaseURL: p.Origin, TokenPath: p.TokenPath,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		}
	}
	return clients, nodes
}

// loadFleetRegistry is the start-up load: the SAME checks as a re-read
// (#870 review, M3), because a file the re-read would refuse must not be
// accepted by the next restart instead. A file that does not pass is an
// empty table, said once in the log; there is no last good table to keep.
func loadFleetRegistry(path string) *fleet.Registry {
	reg, err := reloadFleetRegistry(path)
	if err != nil {
		log.Printf("[fleet] %v; using an empty peer table", err)
		return &fleet.Registry{}
	}
	return reg
}

// fleetNow returns the current view, re-reading the registry first when the
// file has changed since the last read. A server with no fleetPath (a test
// that sets the fields directly) never reloads and answers with its fields.
func (s *server) fleetNow() fleetView {
	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()
	if s.fleetPath != "" {
		// Stat BEFORE the read: if the file moves again between the two, the
		// stamp kept is the older one, so the next call sees a difference and
		// reads again. The other order could keep a stamp for bytes never read.
		st := statFleetStamp(s.fleetPath)
		if st != s.fleetStamp && !(st.present && st == s.fleetRefused) {
			// The whole new state is built off to the side and checked
			// before anything here moves. On any failure NOTHING changes,
			// the stamp included: the in-memory table never claims to match
			// a file it refused. The refused file's stamp is kept apart, so
			// it is read and logged once; a fixed file has a new stamp.
			reg, err := reloadFleetRegistry(s.fleetPath)
			if err != nil {
				// Remembered, so a file that stays refused is logged once
				// and not re-read on every fleet use (#870 review, L2). Any
				// further change gives a new stamp and is read again.
				s.fleetRefused = st
				log.Printf("[fleet] REFUSED a changed registry, keeping the last good peer table (%d peer(s)): %v", len(s.fleetNodes), err)
			} else {
				clients, nodes := fleetDerived(reg)
				// One locked assignment: the registry, its clients and its
				// label set always move together.
				s.fleetReg, s.fleetClients, s.fleetNodes, s.fleetStamp = reg, clients, nodes, st
				log.Printf("[fleet] %s changed; re-read: %d peer(s)%s", s.fleetPath, len(reg.Peers), labelList(reg))
			}
		}
	}
	return fleetView{reg: s.fleetReg, clients: s.fleetClients, nodes: s.fleetNodes}
}

func labelList(reg *fleet.Registry) string {
	if reg == nil || len(reg.Peers) == 0 {
		return ""
	}
	return ": " + strings.Join(reg.Labels(), ", ")
}

// nodesOf is the label set of a registry a caller already holds, for a loop
// built from a menu that took its view earlier in the same request.
func nodesOf(reg *fleet.Registry) map[string]bool {
	_, nodes := fleetDerived(reg)
	return nodes
}

// reloadFleetRegistry is the re-read's own load, and it is stricter than the
// start-up load, never weaker (#859 security scan). A re-read is the moment
// a file that changed under a running process starts steering where that
// process sends a peer's token, so before any peer is accepted:
//
//   - the file is opened by descriptor with O_NOFOLLOW and O_NONBLOCK, and
//     must be a regular file, owned by this process's account or by root
//     (the broker writes it as root, then hands it to this account), and
//     writable by nobody else; the bytes parsed are the bytes checked;
//   - every peer's origin is a bare loopback origin, the product's own rule
//     for a peer address (a tunnel or link port on this host), and its
//     token path is absolute and clean.
//
// Any failure is an error, and fleetNow keeps the last good table on an
// error: a re-read never accepts a peer it could not check, and never
// points a client at an address the checks did not pass. An absent file is
// an empty registry, as at start.
func reloadFleetRegistry(path string) (*fleet.Registry, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &fleet.Registry{}, nil
		}
		return nil, fmt.Errorf("fleet registry %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fleet registry %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("fleet registry %s: not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("fleet registry %s: writable by group or others (%04o)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && int(st.Uid) != os.Getuid() {
			return nil, fmt.Errorf("fleet registry %s: owned by uid %d, neither root nor this account", path, st.Uid)
		}
	}
	// The broker caps what it writes at 1 MiB; anything larger is not a file
	// it wrote.
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("fleet registry %s: %w", path, err)
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("fleet registry %s: larger than 1 MiB", path)
	}
	reg, err := fleet.Parse(path, b)
	if err != nil {
		return nil, err
	}
	for _, p := range reg.Peers {
		if err := loopbackOrigin(p.Origin); err != nil {
			return nil, fmt.Errorf("fleet registry %s: peer %q: %w", path, p.Label, err)
		}
		if !filepath.IsAbs(p.TokenPath) || filepath.Clean(p.TokenPath) != p.TokenPath {
			return nil, fmt.Errorf("fleet registry %s: peer %q: token_path is not an absolute, clean path", path, p.Label)
		}
	}
	return reg, nil
}

// loopbackOrigin accepts http://127.0.0.1:<port>, http://localhost:<port>
// and http://[::1]:<port>, with no path, query, fragment or user info.
func loopbackOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("origin %q does not parse", origin)
	}
	if u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("origin %q is not a bare http origin", origin)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		return fmt.Errorf("origin %q names no port", origin)
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("origin %q is not on this host's loopback", origin)
		}
	}
	return nil
}
