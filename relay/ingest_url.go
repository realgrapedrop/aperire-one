package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// MED-07 — classify the configured dashboard_url so the relay says at startup
// what it is about to do with the operator's bearer token.
//
// The relay does not enforce anything here. It dials, and the dashboard
// decides: a dashboard bound off-loopback refuses a plaintext push from a
// remote relay unless its operator set APERIRE_INGEST_ALLOW_PLAINTEXT. What
// the relay owes the operator is a line in the journal that names the problem
// on the host where the config lives, because the dashboard's refusal lands in
// a journal on a different machine and reaches this side as a bare 403.
//
// Classification is done on the URL literal alone. No DNS: a name that resolves
// to a LAN address today can resolve elsewhere tomorrow, resolution at startup
// can hang or fail on a host that is still coming up, and a startup warning
// that depends on the network is a warning that goes missing exactly when
// things are broken. A hostname we cannot classify is reported as remote,
// which is the safe reading.

type ingestLinkClass int

const (
	// linkUnknown — the URL did not parse. validateConfig does not parse it
	// either, so this stays a warning; the dial will fail loudly on its own.
	linkUnknown ingestLinkClass = iota
	// linkTLS — wss:// or https://. The hop is encrypted.
	linkTLS
	// linkLoopbackPlain — plaintext, but to this machine. A tunnel endpoint
	// or a co-located dashboard. Nothing leaves the host in the clear.
	linkLoopbackPlain
	// linkRemotePlain — plaintext to another machine. The token and every
	// telemetry frame cross the network readable.
	linkRemotePlain
)

// classifyIngestURL reads the scheme and host of the configured dashboard_url.
//
// Both scheme pairs are handled because the WebSocket dialer accepts them
// both: coder/websocket maps http→ws and https→wss, so an operator who wrote
// "http://dashboard:7800/ingest" gets a working plaintext connection and would
// otherwise get no warning at all.
func classifyIngestURL(raw string) ingestLinkClass {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return linkUnknown
	}
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		return linkTLS
	case "ws", "http":
		// fall through to the host test
	default:
		return linkUnknown
	}
	if isLoopbackTarget(u.Hostname()) {
		return linkLoopbackPlain
	}
	return linkRemotePlain
}

// isLoopbackTarget matches what the dashboard's ingest gate treats as on-box:
// "localhost", ::1, and all of 127.0.0.0/8. Anything that is not a literal IP
// is not loopback here, including a name that happens to resolve to one, since
// we deliberately do not resolve.
func isLoopbackTarget(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// ingestLinkWarning returns the line to log at startup, or "" when the
// configured link needs no comment. The wording matches the dashboard's own
// refusal so an operator reading either journal sees the same two fixes.
func ingestLinkWarning(raw string) string {
	switch classifyIngestURL(raw) {
	case linkRemotePlain:
		return fmt.Sprintf("[security] dashboard_url=%q is plain ws to another host: the auth_token and every "+
			"telemetry frame cross the network readable, and anyone who can see them can push forged telemetry "+
			"(MED-07). A dashboard bound off-loopback REFUSES this by default and the dial fails with 403. "+
			"Two sanctioned fixes: tunnel the hop with WireGuard or SSH and point dashboard_url at "+
			"ws://127.0.0.1:<port>/ingest, or terminate TLS in front of the dashboard and use wss://. "+
			"See docs/RELAY-REFERENCE.md, \"Securing a remote relay link\".", raw)
	case linkUnknown:
		return fmt.Sprintf("[security] dashboard_url=%q could not be read as a URL, so its transport could not be "+
			"checked. Expected ws:// or wss:// with a host, for example wss://dashboard.example/ingest.", raw)
	default:
		return ""
	}
}
