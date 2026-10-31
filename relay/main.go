package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// version is stamped at build time via -ldflags; falls back to "dev" for
// `go run` invocations during development.
var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/aperire/relay.conf", "path to relay.conf")
	showVersion := flag.Bool("version", false, "print the stamped build ref and exit")
	printEffective := flag.Bool("print-effective-config", false,
		"load --config exactly as a normal start does, print the node config "+
			"path it would open (if any), whether it reads it, and each port's "+
			"resolved value and source, then exit; touches no network and no socket")
	checkDash := flag.Bool("check-dashboard", false,
		"load --config, try dashboard_url once with the relay's own handshake and say "+
			"which of these it is: the name does not resolve, the connection is refused or "+
			"times out, the TLS handshake fails, the token is refused, or it is accepted; "+
			"sends no frame, then exits (0 only when accepted)")
	flag.Parse()

	// Cheap and side-effect-free on purpose: prepare-host.sh's freshness check
	// (#266) runs this before deciding whether to rebuild, and a probe that
	// touched the config file or the network would make "is this binary
	// current" itself a reason the host is not.
	if *showVersion {
		os.Stdout.WriteString(version + "\n")
		return
	}

	// Read-only and exits before anything below dials or opens a socket. Kept
	// ahead of log.SetFlags on purpose: a script parsing this on stdout must
	// never see a timestamp-prefixed line, and a failure here is reported as
	// a plain, clear message rather than through the timestamped log the
	// running service uses.
	if *printEffective {
		if err := printEffectiveConfig(os.Stdout, *cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Ahead of log.SetFlags for the same reason: a script reads the key line
	// off stdout, and the answer is the exit code.
	if *checkDash {
		os.Exit(runCheckDashboard(os.Stdout, os.Stderr, *cfgPath, nil, checkWithin))
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("aperire-relay %s starting, config=%s", version, *cfgPath)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("node_label=%q dashboard=%q interval=%ds interface=%q",
		cfg.NodeLabel, cfg.DashboardURL, cfg.IntervalSeconds, cfg.Interface)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Installed, not registered. One line, then stand down and wait: no dial,
	// no ticker, no collectors. Blocking rather than exiting is the point —
	// the unit is Restart=always with the start limiter off, so a process that
	// returned here would be respawned every five seconds forever, which is
	// the same journal flood as the placeholder dial it replaces.
	if awaitingRegistration(&cfg) {
		log.Printf("[pusher] dashboard_url is empty: standing by, pushing nothing. "+
			"This host is installed and not yet registered with a dashboard. Set dashboard_url "+
			"and auth_token in %s (auth_token must match RELAY_TOKENS on the dashboard host), "+
			"then: systemctl restart aperire-relay", *cfgPath)
		<-ctx.Done()
		log.Printf("aperire-relay shutdown complete")
		return
	}

	// MED-07. Say what the configured link does with the token before the
	// first dial, not after a 403 nobody can interpret from this host.
	if w := ingestLinkWarning(cfg.DashboardURL); w != "" {
		log.Print(w)
	}

	pushLoop(ctx, &cfg, version)

	log.Printf("aperire-relay shutdown complete")
}
