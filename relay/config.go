package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config mirrors /etc/aperire/relay.conf. See relay.conf.example for a
// documented template; keep the two in sync when fields are added.
type Config struct {
	DashboardURL    string `toml:"dashboard_url"`
	AuthToken       string `toml:"auth_token"`
	NodeLabel       string `toml:"node_label"`
	Interface       string `toml:"interface"`          // "auto" or explicit NIC name
	DataMount       string `toml:"data_mount"`         // path to statfs() for the Disk row
	IntervalSeconds int    `toml:"interval_seconds"`   // push cadence

	// Hosting-plan monthly egress cap in bytes. 0 = unset (pass-through
	// null in the JSON contract). Kept unsigned in the wire format so the
	// dashboard can render "no cap configured" distinctly from "0% used."
	MonthlyBudgetBytes uint64 `toml:"monthly_budget_bytes"`

	// ── Port connection counts ─────────────────────────────────────────
	// Path to rippled.cfg. Used to auto-detect the admin HTTP-RPC and
	// Admin WebSocket ports at startup. Empty = probe well-known paths.
	// If detection fails, falls back to the defaults (5005 / 6006) unless
	// the operator pins a port explicitly below.
	RippledCfgPath string `toml:"rippled_cfg_path"`

	// Optional path to rippled's PID file. When set, the relay reads TCP
	// socket state from /proc/<pid>/net/tcp — the authoritative view for
	// containerized rippled installs where the container has its own
	// network namespace. Empty = fall back to `pgrep -x rippled`. If the
	// PID can't be resolved, socket counts are read from the host
	// namespace (/proc/net/tcp), which is correct for native installs but
	// shows only docker-proxy sockets on Docker-hosted rippled.
	RippledPIDFile string `toml:"rippled_pid_file"`

	// Explicit port overrides. Zero = "use auto-detected or default".
	HttpRpcPort  uint16 `toml:"http_rpc_port"`
	AdminWsPort  uint16 `toml:"admin_ws_port"`
	WsPublicPort uint16 `toml:"ws_public_port"`
	PeerPort     uint16 `toml:"peer_port"`
}

// Well-known default ports used when neither rippled.cfg nor explicit
// config overrides supply a value.
const (
	defaultHttpRpcPort  uint16 = 5005
	defaultAdminWsPort  uint16 = 6006
	defaultWsPublicPort uint16 = 6005
	defaultPeerPort     uint16 = 51235
)

// Defaults matching the docs — applied on top of whatever relay.conf sets.
func defaultConfig() Config {
	return Config{
		Interface:       "auto",
		DataMount:       "/",
		IntervalSeconds: 5,
	}
}

// awaitingRegistration reports the "installed, not yet paired with a
// dashboard" state: the config is complete and valid, and it names no
// dashboard to push to.
//
// A split install knows this host but not the dashboard that will collect
// from it, and the installer must leave something on disk either way. The
// two things it must not leave are a placeholder hostname, which the relay
// would dial forever against a name that does not exist, and a config the
// relay rejects, which under Restart=always is a start loop every five
// seconds. An empty dashboard_url is neither: the relay comes up, says once
// that it is standing by, and waits for the operator to fill the file in and
// restart it.
func awaitingRegistration(c *Config) bool {
	return strings.TrimSpace(c.DashboardURL) == ""
}

func loadConfig(path string) (Config, error) {
	c := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := validateConfig(&c); err != nil {
		return c, err
	}
	// Nothing will be dialled, so the node ports nothing will report are not
	// worth probing the filesystem for, and the three "well-known default"
	// lines they would log are noise in front of the one line that matters.
	if !awaitingRegistration(&c) {
		resolvePorts(&c)
	}
	return c, nil
}

// portSource is one resolved port plus where the value came from: an
// explicit override in relay.conf, a value read out of the node's own
// config, or the well-known default nobody set anything for.
type portSource struct {
	value  uint16
	source string // "override", "auto-detected" or "default"
}

// needsNodeConfig reports whether resolving these four ports would open the
// node's config at all: it only does that when at least one of them is not
// already pinned. An explicit "= 0" in relay.conf is indistinguishable from
// "not set" here, on purpose — it is the same value resolvePorts has always
// treated as "use auto-detection", and close-node-config-exposure.sh's own
// shell parse used to count that line as pinned anyway (a grep for
// `key = value`, blind to which value), granting the relay a read it did not
// use.
func needsNodeConfig(c *Config) bool {
	return c.HttpRpcPort == 0 || c.AdminWsPort == 0 || c.WsPublicPort == 0 || c.PeerPort == 0
}

// resolvePortsDetailed does the same two-step resolution resolvePorts always
// has (explicit override, then auto-detected from the node's config, then
// the well-known default), but hands back the source of each value instead
// of only logging it, and the config path it actually opened (empty if it
// opened none). --print-effective-config and the normal startup path share
// this one function so the two can never drift: a second implementation of
// "which file would this open" is exactly the shell re-parse this replaces.
func resolvePortsDetailed(c *Config) (ports [4]portSource, cfgPath string) {
	var detected RippledPorts
	if needsNodeConfig(c) {
		p, path, err := resolvePortsFromCfg(c.RippledCfgPath)
		if err != nil {
			log.Printf("[ports] rippled.cfg parse %s: %v (falling back to defaults)", path, err)
		}
		detected = p
		cfgPath = path
	}

	resolveOne := func(field, fromCfg, def uint16) portSource {
		if field != 0 {
			return portSource{field, "override"}
		}
		if fromCfg != 0 {
			return portSource{fromCfg, "auto-detected"}
		}
		return portSource{def, "default"}
	}

	ports[0] = resolveOne(c.HttpRpcPort, detected.HttpRpc, defaultHttpRpcPort)
	ports[1] = resolveOne(c.AdminWsPort, detected.AdminWs, defaultAdminWsPort)
	ports[2] = resolveOne(c.WsPublicPort, detected.WsPublic, defaultWsPublicPort)
	ports[3] = resolveOne(c.PeerPort, detected.Peer, defaultPeerPort)
	return ports, cfgPath
}

// resolvePorts fills in HttpRpcPort / AdminWsPort on the Config when the
// operator didn't pin them in relay.conf, and logs the source of each one so
// an operator tailing the journal at startup can see exactly where the
// number came from.
func resolvePorts(c *Config) {
	ports, cfgPath := resolvePortsDetailed(c)
	fields := [4]*uint16{&c.HttpRpcPort, &c.AdminWsPort, &c.WsPublicPort, &c.PeerPort}
	names := [4]string{"http_rpc_port", "admin_ws_port", "ws_public_port", "peer_port"}
	for i, p := range ports {
		*fields[i] = p.value
		switch p.source {
		case "override":
			log.Printf("[ports] %s=%d (relay.conf override)", names[i], p.value)
		case "auto-detected":
			log.Printf("[ports] %s=%d (auto-detected from %s)", names[i], p.value, cfgPath)
		default:
			log.Printf("[ports] %s=%d (well-known default)", names[i], p.value)
		}
	}
}

func validateConfig(c *Config) error {
	// node_label first: it identifies this host whether or not a dashboard is
	// named yet, and the installer always writes it.
	if c.NodeLabel == "" {
		return errors.New("node_label is required")
	}
	// An empty dashboard_url is the awaiting-registration state, not a
	// mistake, and a token is meaningless without somewhere to send it. A
	// dashboard_url WITH no token stays an error: that one is half-filled
	// configuration, and dialling with an empty bearer would earn a 401 the
	// operator then has to interpret from the far side.
	if !awaitingRegistration(c) && c.AuthToken == "" {
		return errors.New("auth_token is required when dashboard_url is set")
	}
	if c.IntervalSeconds < 1 || c.IntervalSeconds > 300 {
		return fmt.Errorf("interval_seconds must be in [1, 300], got %d", c.IntervalSeconds)
	}
	return nil
}
