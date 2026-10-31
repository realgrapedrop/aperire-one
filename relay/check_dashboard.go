package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

// --check-dashboard (#586): try the configured dashboard_url once, the way the
// relay would, and say which of a short list of things is in the way.
//
// It is the relay's own handshake and nothing else. The same bearer header,
// the same system root store, the same dial as a normal start, then a normal
// close. No frame is sent, so the dashboard learns no node label and spends no
// slot on this host. It reads relay.conf as the service does and takes no URL
// from anywhere else.
//
// What it prints, on stdout, is two lines:
//
//	check=<key>
//	<one sentence on what happened, and the one next step>
//
// The key is what a script reads (the installer keys on the exit code, and a
// test on the key); the sentence is for the operator and can be reworded
// without breaking either. The exit code carries the same answer. The token
// is never printed: the sentence names the host and port from the URL and
// nothing else out of the config.
const (
	checkAccepted     = "accepted"
	checkDNS          = "dns"
	checkRefused      = "refused"
	checkTimeout      = "timeout"
	checkNoRoute      = "no_route"
	checkTLS          = "tls"
	checkUnauthorized = "unauthorized"
	checkForbidden    = "forbidden"
	checkNotIngest    = "not_ingest"
	checkHTTP         = "http"
	checkOther        = "other"
	checkNoURL        = "no_url"
)

// Exit codes. 0 is the only success. 1 is a config that did not load, as for
// --print-effective-config, and 2 is what the flag package gives an unknown
// flag, which is how the installer tells an older binary from a failed check.
var checkExit = map[string]int{
	checkAccepted:     0,
	checkNoURL:        10,
	checkDNS:          11,
	checkRefused:      12,
	checkTimeout:      13,
	checkNoRoute:      14,
	checkTLS:          15,
	checkUnauthorized: 16,
	checkForbidden:    17,
	checkNotIngest:    18,
	checkHTTP:         19,
	checkOther:        20,
}

// checkWithin is how long the one attempt gets. Shorter than the 10 seconds a
// running relay gives a dial: an operator at a terminal is waiting on this one.
const checkWithin = 5 * time.Second

type checkOutcome struct {
	Key  string
	Line string
}

// runCheckDashboard loads cfgPath as a normal start does, tries the dial once
// and writes the two-line answer to w. It returns the process exit code.
// client is nil in production (system roots); a test passes its own.
func runCheckDashboard(w io.Writer, errw io.Writer, cfgPath string, client *http.Client, within time.Duration) int {
	// loadConfig narrates the ports it resolved through the standard logger.
	// That is the running service's journal, and here it would be timestamped
	// noise between the operator and the one answer they asked for.
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return 1
	}
	if awaitingRegistration(&cfg) {
		o := checkOutcome{checkNoURL, fmt.Sprintf("dashboard_url is empty in %s, so there is nothing to check. "+
			"Set dashboard_url and auth_token there, then run this again.", cfgPath)}
		writeOutcome(w, o)
		return checkExit[o.Key]
	}
	o := checkDashboard(context.Background(), &cfg, client, within)
	writeOutcome(w, o)
	return checkExit[o.Key]
}

func writeOutcome(w io.Writer, o checkOutcome) {
	fmt.Fprintf(w, "check=%s\n%s\n", o.Key, o.Line)
}

// checkDashboard makes the one dial and classifies what came back.
func checkDashboard(ctx context.Context, cfg *Config, client *http.Client, within time.Duration) checkOutcome {
	host, hostport := checkTarget(cfg.DashboardURL)
	conn, resp, err := dialDashboardResp(ctx, cfg, client, within)
	if err == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "check")
		return checkOutcome{checkAccepted, fmt.Sprintf("Reached %s and the dashboard accepted this relay's token. "+
			"If no data shows up, the relay service itself is the next thing to read: journalctl -u aperire-relay -n 30.", hostport)}
	}
	if resp != nil {
		return classifyStatus(resp.StatusCode, host, hostport)
	}
	return classifyDialError(err, host, hostport, within)
}

// classifyStatus reads an HTTP answer where a WebSocket upgrade was expected.
// 401 is the dashboard's token check, and a 403 only comes after it (the
// MED-07 transport refusal in server.ts's upgrade handler), so the two mean
// different fixes on different hosts.
func classifyStatus(code int, host, hostport string) checkOutcome {
	switch code {
	case http.StatusUnauthorized:
		return checkOutcome{checkUnauthorized, fmt.Sprintf("Reached %s, and it refused the token (401). "+
			"The auth_token in relay.conf has to be listed in RELAY_TOKENS on the dashboard's host. "+
			"Add it there, restart that dashboard, then restart this relay.", hostport)}
	case http.StatusForbidden:
		return checkOutcome{checkForbidden, fmt.Sprintf("Reached %s and it refused the connection (403). "+
			"A dashboard does that after it accepts the token when it will not take plain ws:// from another host. "+
			"Point dashboard_url at a tunnel on loopback (ws://127.0.0.1:7800/ingest) or at a wss:// address. "+
			"A proxy in front of the dashboard can send a 403 too.", hostport)}
	case http.StatusNotFound:
		return checkOutcome{checkNotIngest, fmt.Sprintf("Reached %s, but nothing answers the path in dashboard_url (404). "+
			"The path should end in /ingest, and a proxy in front has to pass it through, WebSocket upgrades included.", hostport)}
	}
	return checkOutcome{checkHTTP, fmt.Sprintf("Reached %s and it answered HTTP %d, not a WebSocket upgrade. "+
		"Something answers on that address but is not the dashboard's /ingest. "+
		"A 502, 503 or 504 means a proxy is up and the dashboard behind it is not. Check both.", hostport, code)}
}

// classifyDialError sorts a dial that never produced an HTTP answer. The order
// matters: a DNS failure can also report a timeout, and a TLS failure arrives
// wrapped in the same url.Error as a refused connection.
func classifyDialError(err error, host, hostport string, within time.Duration) checkOutcome {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return checkOutcome{checkDNS, fmt.Sprintf("The name %s does not resolve from this host. "+
			"Check the spelling of the host in dashboard_url, and that this host's DNS can look it up: getent hosts %s",
			host, host)}
	}
	if why, ok := tlsReason(err, host); ok {
		return checkOutcome{checkTLS, fmt.Sprintf("Reached %s, but the TLS handshake failed: %s. "+
			"Fix the certificate on the dashboard side, or use the name it was issued for in dashboard_url.", hostport, why)}
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return checkOutcome{checkRefused, fmt.Sprintf("%s refused the connection. "+
			"Nothing is listening on that port, or a firewall rejected it. "+
			"Check the port in dashboard_url, and that the dashboard's host allows inbound TCP on it.", hostport)}
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return checkOutcome{checkNoRoute, fmt.Sprintf("This host has no route to %s. "+
			"Check the address in dashboard_url, and this host's network and VPN.", hostport)}
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return checkOutcome{checkTimeout, fmt.Sprintf("%s did not answer within %d seconds. "+
			"A firewall is most likely dropping the traffic. Allow inbound TCP on that port at the dashboard's host "+
			"(and at its cloud provider's firewall) from this host's address.", hostport, int(within.Seconds()))}
	}
	return checkOutcome{checkOther, fmt.Sprintf("The dial to %s failed: %s", hostport, bareError(err))}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// tlsReason names a TLS failure in plain words, or reports that err is not one.
func tlsReason(err error, host string) (string, bool) {
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return "the server did not speak TLS (that port serves plain HTTP, so use ws:// or a tunnel, or point at the TLS port)", true
	}
	var unk x509.UnknownAuthorityError
	if errors.As(err, &unk) {
		return "the certificate was signed by an authority this host does not trust", true
	}
	var hn x509.HostnameError
	if errors.As(err, &hn) {
		return fmt.Sprintf("the certificate was not issued for the name %s", host), true
	}
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) {
		if ci.Reason == x509.Expired {
			return "the certificate has expired, or this host's clock is wrong", true
		}
		return "the certificate is not valid", true
	}
	var cv *tls.CertificateVerificationError
	if errors.As(err, &cv) {
		return "the certificate could not be verified", true
	}
	var ae tls.AlertError
	if errors.As(err, &ae) {
		return "the server refused the handshake", true
	}
	var oe *net.OpError
	if errors.As(err, &oe) && strings.Contains(oe.Error(), "tls:") {
		return "the server refused the handshake", true
	}
	return "", false
}

// checkTarget returns the host and host:port the sentences name, with a default
// port filled in. Nothing but those two comes out of the URL: it can carry
// userinfo or a query, and neither belongs on a terminal or in a paste.
func checkTarget(raw string) (host, hostport string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "the dashboard", "the dashboard"
	}
	host = u.Hostname()
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "wss", "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return host, net.JoinHostPort(host, port)
}

// bareError drops the URL a url.Error wraps, so the one fallback line cannot
// repeat anything the URL carried.
func bareError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
