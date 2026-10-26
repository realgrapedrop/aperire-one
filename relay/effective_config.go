package main

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

// printEffectiveConfig answers, from this binary's own parsing and
// resolution logic, one question a shell script cannot reliably ask by
// re-reading relay.conf itself: does this relay open the node's config, and
// if so which file and which ports come from it.
//
// close-node-config-exposure.sh and install-aperire-relay.sh's own section
// 5b used to answer that by grepping relay.conf for
// `key = "value"` and counting `key = N` lines against four. That reparse
// missed what the real TOML parser does not: a single-quoted (literal)
// string is valid TOML and the grep only matched double quotes; a key
// inside an unrelated `[table]` is not the top-level key relay.conf and the
// port-line grep could not tell the two apart; and an explicit `= 0` reads
// as "pinned" to a line-count grep when this relay treats it exactly like
// "not set" (a zero port is not a valid port to pin). Every one of those
// silently granted or withheld a read on a file that can hold
// [validator_token]. This function loads the config the one way that
// cannot drift from what a normal start does, because it uses the same
// loadConfig/resolvePortsDetailed this binary always uses.
//
// Ports are resolved even where the config is in the awaiting-registration
// state (an empty dashboard_url): a split install closes the node config
// before the relay is paired with a dashboard, and the ACL grant that
// question decides must not depend on whether pairing has happened yet.
// loadConfig's own early-return on that state exists for the running
// process's log, not for this report, so this function does its own
// load/validate/resolve rather than calling loadConfig.
//
// Touches no network and no socket. Prints only to stdout, in a stable
// key=value form a shell can parse with sed or awk without a JSON library
// on the host; every diagnostic goes to stderr, on purpose, so a caller
// that pipes stdout into a parser never has to guard against a stray log
// line landing in the middle of it.
func printEffectiveConfig(w io.Writer, cfgPath string) error {
	c := defaultConfig()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfgPath, err)
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return fmt.Errorf("parse %s: %w", cfgPath, err)
	}
	if err := validateConfig(&c); err != nil {
		return fmt.Errorf("invalid config in %s: %w", cfgPath, err)
	}

	ports, nodeCfgPath := resolvePortsDetailed(&c)
	readsNodeConfig := needsNodeConfig(&c) && nodeCfgPath != ""

	names := [4]string{"http_rpc_port", "admin_ws_port", "ws_public_port", "peer_port"}

	fmt.Fprintf(w, "config_file=%s\n", cfgPath)
	fmt.Fprintf(w, "node_config_path=%s\n", nodeCfgPath)
	fmt.Fprintf(w, "reads_node_config=%t\n", readsNodeConfig)
	for i, p := range ports {
		fmt.Fprintf(w, "%s=%d\n", names[i], p.value)
		fmt.Fprintf(w, "%s_source=%s\n", names[i], p.source)
	}
	return nil
}
