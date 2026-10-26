package dashread

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client reads the dashboard's read API over loopback. The token is read
// from disk on every call — rotation needs no restart, and an operator who
// deletes the file has turned the surface off on both sides at once.
type Client struct {
	// BaseURL is the dashboard's origin, e.g. http://127.0.0.1:7800.
	BaseURL string
	// TokenPath is the read token this service generated beside its approval
	// token. A second secret, deliberately not approve.token: one token in
	// both directions would mean compromising either service yields both.
	TokenPath string
	// HTTPClient defaults to a 5-second-timeout client.
	HTTPClient *http.Client
}

// The states a read can fail in, distinguished because the tab surfaces them
// differently: "unreachable" is an install or service problem, "unauthorized"
// is token drift, a VersionError is a half-upgraded host and names the fix.
var (
	ErrNoToken      = errors.New("read token unreadable")
	ErrUnauthorized = errors.New("read surface refused the token")
	ErrDisabled     = errors.New("read surface is disabled on the dashboard")
)

// VersionError carries both versions so the operator is told the fix, not
// shown an empty panel.
type VersionError struct {
	Server    int
	Requested int
}

func (e *VersionError) Error() string {
	return fmt.Sprintf("read contract version mismatch: dashboard serves v%d, this service speaks v%d — upgrade whichever is behind", e.Server, e.Requested)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.TokenPath)
	if err != nil {
		return "", ErrNoToken
	}
	t := strings.TrimSpace(string(b))
	if len(t) < 32 {
		return "", ErrNoToken
	}
	return t, nil
}

func (c *Client) get(ctx context.Context, route string, query url.Values, out any) error {
	tok, err := c.token()
	if err != nil {
		return err
	}
	u := strings.TrimRight(c.BaseURL, "/") + "/read/v" + fmt.Sprint(ProtocolVersion) + "/" + route
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("read surface unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("read surface unreachable: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var ae apiError
		_ = json.Unmarshal(body, &ae)
		switch ae.Error {
		case "protocol_version_unsupported":
			return &VersionError{Server: ae.ServerVersion, Requested: ProtocolVersion}
		case "unauthorized":
			return ErrUnauthorized
		case "read_surface_disabled":
			return ErrDisabled
		default:
			return fmt.Errorf("read surface: http %d %s %s", resp.StatusCode, ae.Error, ae.Detail)
		}
	}
	return json.Unmarshal(body, out)
}

// History returns the bucketed series for one metric over a named range.
func (c *Client) History(ctx context.Context, metric, rng, agg string) ([]HistoryPoint, error) {
	q := url.Values{"metric": {metric}, "range": {rng}, "agg": {agg}}
	var r historyResponse
	if err := c.get(ctx, "history", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return r.Points, nil
}

// Recent returns the last raw samples for one metric.
func (c *Client) Recent(ctx context.Context, metric string, limit int) ([]HistoryPoint, error) {
	q := url.Values{"metric": {metric}, "limit": {fmt.Sprint(limit)}}
	var r historyResponse
	if err := c.get(ctx, "recent", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return r.Points, nil
}

// LedgerWindow is the window of observed ledgers centred on an index —
// what "was this ledger slow compared to its neighbours" reads.
//
// The returned span is the one the server APPLIED (it clamps to 61), and a
// window can come back with fewer rows than it spans: the ledgers table
// holds only what the dashboard observed, so a restart or an outage leaves
// holes. Callers must surface requested-vs-returned rather than reason over
// a window with silent gaps.
type LedgerWindow struct {
	Around    int64
	Span      int // as applied by the server
	Requested int
	Returned  int
	Ledgers   []LedgerRow
}

func (c *Client) LedgerWindow(ctx context.Context, around int64, span int) (*LedgerWindow, error) {
	q := url.Values{"around": {fmt.Sprint(around)}, "span": {fmt.Sprint(span)}}
	var r ledgerWindowResponse
	if err := c.get(ctx, "ledgers", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	// The echo assertion — presence, never equality. A dashboard from before
	// this parameter existed serves the latest-N form with a 200 and no echo;
	// treating that as a smaller window would hand the model the newest 50
	// ledgers labelled as the neighbourhood of a ledger from last Tuesday.
	// The failure is named so the operator is told the fix.
	if r.Around == nil || r.Span == nil {
		return nil, errors.New("this dashboard does not serve windowed ledger reads — upgrade it (read contract: ledgers?around&span)")
	}
	return &LedgerWindow{
		Around: *r.Around, Span: *r.Span,
		Requested: r.Requested, Returned: r.Returned,
		Ledgers: r.Ledgers,
	}, nil
}

// LatestLedgers returns the most recently observed ledgers, newest first, up
// to limit — the `node_ledgers` menu item's `latest` form (plan-
// interrogative-loop §4.1), and the same plain "newest N" behaviour the
// ledgers route served before around/span existed. Unlike LedgerWindow this
// needs no echo assertion: the server's own cap (500) is the only thing that
// can narrow the answer, and a caller asking for fewer than that gets
// exactly what it asked for.
func (c *Client) LatestLedgers(ctx context.Context, limit int) ([]LedgerRow, error) {
	q := url.Values{"limit": {fmt.Sprint(limit)}}
	var r latestLedgersResponse
	if err := c.get(ctx, "ledgers", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return r.Ledgers, nil
}

// AgreementWindow is this node's own per-ledger agreement record, with the
// retention the server actually applied — the same applied-vs-requested
// shape as LedgerWindow, for the same reason. The server clamps a request
// older than its two-day retention up to the floor and echoes both the
// stated retention and the sinceMs it actually used; a caller that dropped
// those and kept only Rows would have no way to render "2 days" without
// hardcoding it, which is exactly the drift LedgerWindow exists to avoid.
type AgreementWindow struct {
	RetentionDays int
	SinceMs       int64 // as applied by the server
	Rows          []AgreementRow
}

// Agreement returns this node's own per-ledger agreement record since
// sinceMs, and the retention window the server actually served.
func (c *Client) Agreement(ctx context.Context, sinceMs int64) (*AgreementWindow, error) {
	q := url.Values{"since_ms": {fmt.Sprint(sinceMs)}}
	var r agreementResponse
	if err := c.get(ctx, "agreement", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return &AgreementWindow{RetentionDays: r.RetentionDays, SinceMs: r.SinceMs, Rows: r.Rows}, nil
}

// MissedLedgers returns every recorded miss, newest first, up to limit. The
// table is small and never pruned by design, so this is closer to a full
// history than a window.
func (c *Client) MissedLedgers(ctx context.Context, limit int) ([]MissedLedgerRow, error) {
	q := url.Values{"limit": {fmt.Sprint(limit)}}
	var r missedLedgersResponse
	if err := c.get(ctx, "missed-ledgers", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return r.Missed, nil
}

// Alerts returns alert lifecycle transitions (firing and resolved) since
// sinceMs, newest first, up to limit.
func (c *Client) Alerts(ctx context.Context, sinceMs int64, limit int) ([]AlertEvent, error) {
	q := url.Values{"since_ms": {fmt.Sprint(sinceMs)}, "limit": {fmt.Sprint(limit)}}
	var r alertsResponse
	if err := c.get(ctx, "alerts", q, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return r.Alerts, nil
}

// Firing returns what is firing right now — the live set, not history.
func (c *Client) Firing(ctx context.Context) ([]FiringStateRow, error) {
	var r firingResponse
	if err := c.get(ctx, "firing", nil, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return r.Firing, nil
}

// FleetRoster returns the roster this dashboard holds and what it last
// observed of each member (#59). Called against THIS host's own dashboard,
// never a peer's: the roster a question is resolved against is the roster of
// the host the question was asked on.
func (c *Client) FleetRoster(ctx context.Context) (*FleetRoster, error) {
	var r fleetRosterResponse
	if err := c.get(ctx, "fleet", nil, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	return &FleetRoster{
		Registered: r.Registered, SelfLabel: r.SelfLabel,
		NowMs: r.NowMs, Nodes: r.Nodes,
	}, nil
}

// NodeConfig returns the four allow-listed rippled settings the dashboard at
// this client's origin reports for ITS host. Pointed at a peer's client, it
// answers for that peer.
func (c *Client) NodeConfig(ctx context.Context) (*NodeConfig, error) {
	var r nodeConfigResponse
	if err := c.get(ctx, "node-config", nil, &r); err != nil {
		return nil, err
	}
	if r.ProtocolVersion != ProtocolVersion {
		return nil, &VersionError{Server: r.ProtocolVersion, Requested: ProtocolVersion}
	}
	cfg := r.NodeConfig
	return &cfg, nil
}

// Probe reports the surface's state for /v1/status: "ok", or a short reason
// the tab can show — the same treatment advisor_unreachable already gets.
func (c *Client) Probe(ctx context.Context) (ok bool, state string) {
	_, err := c.Recent(ctx, "peer_count", 1)
	switch {
	case err == nil:
		return true, "ok"
	case errors.Is(err, ErrNoToken):
		return false, "token_unreadable"
	case errors.Is(err, ErrUnauthorized):
		return false, "unauthorized"
	case errors.Is(err, ErrDisabled):
		return false, "disabled"
	default:
		var ve *VersionError
		if errors.As(err, &ve) {
			return false, ve.Error()
		}
		return false, "unreachable"
	}
}
