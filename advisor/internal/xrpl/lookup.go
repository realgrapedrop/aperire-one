// Package xrpl is the Advisor's read-only window onto the public ledger.
//
// A validator keeps almost no ledger history, so "what was ledger X" cannot
// be answered by the node that missed it. This package asks a public XRPL
// API instead — strictly read-only, one conventional endpoint from a
// file-based config the operator controls, and nothing here can write
// anywhere. It is the first read tool the model can drive; later read tools
// should reuse this shape: config-gated endpoint, plain summary out.
package xrpl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// rippleEpoch converts XRPL close times (seconds since 2000-01-01 UTC).
const rippleEpoch = 946684800

// LookupConfig is read from state/xrpl-lookup.json. Absent or disabled means
// the Advisor says "lookup not enabled" rather than reaching anywhere — new
// outbound egress is an operator decision, never a default.
type LookupConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	// ValidatorEndpoint is the public validator registry (agreement scores,
	// domains, versions — the network's view of a validator). Optional;
	// empty means validator lookups answer "not enabled".
	ValidatorEndpoint string `json:"validator_endpoint"`
	// Explorer is a public explorer's base URL, used only to COMPOSE links
	// the operator can click ({explorer}/ledger/N, {explorer}/validator/nH…).
	// The Advisor never fetches from it — this is a link for a human, not
	// egress for the agent. Optional; empty means no links are offered.
	Explorer string `json:"explorer"`
}

func LoadLookupConfig(path string) (LookupConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LookupConfig{}, err
	}
	var c LookupConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return LookupConfig{}, err
	}
	if c.Enabled && c.Endpoint == "" {
		return LookupConfig{}, fmt.Errorf("xrpl lookup enabled but no endpoint configured")
	}
	return c, nil
}

// Summary is what an operator (or the model) needs to reason about one
// ledger: when it closed, how much it carried, and how fast it followed its
// predecessor.
type Summary struct {
	LedgerIndex      int64     `json:"ledger_index"`
	LedgerHash       string    `json:"ledger_hash"`
	CloseTime        time.Time `json:"close_time"`
	TxnCount         int       `json:"txn_count"`
	CloseIntervalSec float64   `json:"close_interval_sec"` // vs the previous ledger; 0 when unknown
	Source           string    `json:"source"`
}

// Lookup fetches one ledger's summary, plus its predecessor's close time so
// the close interval — the consensus cadence at that moment — comes with it.
//
// lgrNotFound gets two quiet retries: the cluster is a load-balanced fleet,
// and a ledger that closed moments ago may not have reached the backend that
// answered. An operator asking about the ledger their node just validated is
// the COMMON case, not the edge.
func Lookup(ctx context.Context, client *http.Client, endpoint string, index int64) (Summary, error) {
	cur, err := fetchLedger(ctx, client, endpoint, index)
	for attempt := 0; attempt < 2 && err != nil && strings.Contains(err.Error(), "lgrNotFound"); attempt++ {
		select {
		case <-ctx.Done():
			return Summary{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		cur, err = fetchLedger(ctx, client, endpoint, index)
	}
	if err != nil {
		if strings.Contains(err.Error(), "lgrNotFound") {
			return Summary{}, fmt.Errorf("%w — if this ledger closed moments ago the "+
				"cluster may simply not have it yet; asking again shortly usually works", err)
		}
		return Summary{}, err
	}
	s := Summary{
		LedgerIndex: index,
		LedgerHash:  cur.hash,
		CloseTime:   time.Unix(cur.closeTime+rippleEpoch, 0).UTC(),
		TxnCount:    cur.txnCount,
		Source:      endpoint,
	}
	// Best effort — a summary without the interval is still a summary.
	if prev, err := fetchLedger(ctx, client, endpoint, index-1); err == nil {
		s.CloseIntervalSec = float64(cur.closeTime - prev.closeTime)
	}
	return s, nil
}

type ledgerFacts struct {
	hash      string
	closeTime int64
	txnCount  int
}

func fetchLedger(ctx context.Context, client *http.Client, endpoint string, index int64) (ledgerFacts, error) {
	body, err := json.Marshal(map[string]any{
		"method": "ledger",
		"params": []any{map[string]any{
			"ledger_index": index,
			"transactions": true,
			"expand":       false,
		}},
	})
	if err != nil {
		return ledgerFacts{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ledgerFacts{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aperire-advisor/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return ledgerFacts{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return ledgerFacts{}, fmt.Errorf("%s said %s", endpoint, resp.Status)
	}

	var r struct {
		Result struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Ledger struct {
				Hash         string   `json:"ledger_hash"`
				CloseTime    int64    `json:"close_time"`
				Transactions []string `json:"transactions"`
			} `json:"ledger"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return ledgerFacts{}, fmt.Errorf("unreadable answer from %s: %w", endpoint, err)
	}
	if r.Result.Error != "" {
		return ledgerFacts{}, fmt.Errorf("%s: %s", endpoint, r.Result.Error)
	}
	if r.Result.Ledger.Hash == "" {
		return ledgerFacts{}, fmt.Errorf("%s returned no ledger for index %d", endpoint, index)
	}
	return ledgerFacts{
		hash:      r.Result.Ledger.Hash,
		closeTime: r.Result.Ledger.CloseTime,
		txnCount:  len(r.Result.Ledger.Transactions),
	}, nil
}

// Describe renders a Summary as the plain lines the model context carries.
func (s Summary) Describe() string {
	interval := "unknown"
	if s.CloseIntervalSec > 0 {
		interval = fmt.Sprintf("%.0fs after the previous ledger", s.CloseIntervalSec)
	}
	return fmt.Sprintf(
		"ledger %d closed %s UTC, %d transactions, %s (source: %s)",
		s.LedgerIndex, s.CloseTime.Format("2006-01-02 15:04:05"),
		s.TxnCount, interval, s.Source)
}

// ── validator lookup ──────────────────────────────────────────────────
//
// The other half of every diagnosis: how the NETWORK sees a validator, from
// a public registry's collectors. A validator that is not on a published UNL
// is typically not tracked at all — that answer is returned honestly rather
// than as an error, because "the public registry does not see this key" is
// itself information.

// ValidatorStatus is what a public registry reports about one validator key.
type ValidatorStatus struct {
	Key     string `json:"key"`
	Tracked bool   `json:"tracked"`

	Domain        string `json:"domain,omitempty"`
	DomainOK      bool   `json:"domain_verified"`
	ServerVersion string `json:"server_version,omitempty"`
	Chain         string `json:"chain,omitempty"`
	LedgerIndex   int64  `json:"ledger_index,omitempty"`

	// LastSeen is the point of this lookup. It is when the network last
	// observed this validator sign something — the one fact a node cannot
	// establish about itself, because a validator that has gone invisible to
	// everyone else still looks perfectly healthy from the inside.
	LastSeen time.Time `json:"last_seen,omitempty"`

	// UNL lists the published lists carrying this key. Empty is a normal and
	// common state: 275 of the 310 validators in the registry are on none.
	UNL []string `json:"unl,omitempty"`

	Source string `json:"source"`
}

// registryEntry is one row of the registry listing.
type registryEntry struct {
	MasterKey   string   `json:"master_key"`
	Chain       string   `json:"chain"`
	LastSeen    string   `json:"last_seen"`
	LedgerIndex int64    `json:"ledger_index"`
	Domain      string   `json:"domain"`
	UNL         []string `json:"unl"`
	Meta        struct {
		Verified bool `json:"verified"`
	} `json:"meta"`
	ServerVersion struct {
		Version string `json:"version"`
	} `json:"server_version"`
}

// LookupValidator asks the configured registry about one validator key.
//
// It reads the whole registry listing and finds the key in it, because the
// per-validator route this used to call answers HTTP 200 with the body
// "Error" for every key, tracked or not. The old code read that as "not
// tracked" — so every validator, including ones the registry reports on in
// real time, came back as untracked with a confident explanation attached.
// A tool that answers "no" when it means "I could not ask" is worse than one
// that fails, and this one had been doing it for every lookup.
func LookupValidator(ctx context.Context, client *http.Client, endpoint, key string) (ValidatorStatus, error) {
	url := strings.TrimRight(endpoint, "/") + "/api/v1/validatorregistry"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ValidatorStatus{}, err
	}
	req.Header.Set("User-Agent", "aperire-advisor/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return ValidatorStatus{}, err
	}
	defer resp.Body.Close()
	// The listing is a few hundred kilobytes. The cap is generous enough for
	// growth and still bounded, because this is a response from off-host.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return ValidatorStatus{}, fmt.Errorf("%s said %s", endpoint, resp.Status)
	}

	var rows []registryEntry
	if err := json.Unmarshal(raw, &rows); err != nil {
		// An unparseable body is a failure to ask, and must be reported as
		// one. This is the exact distinction the previous version lost.
		return ValidatorStatus{}, fmt.Errorf("%s returned something that is not a registry listing: %w", endpoint, err)
	}
	if len(rows) == 0 {
		return ValidatorStatus{}, fmt.Errorf("%s returned an empty registry listing", endpoint)
	}

	out := ValidatorStatus{Key: key, Source: endpoint}
	for _, r := range rows {
		if r.MasterKey != key {
			continue
		}
		out.Tracked = true
		out.Domain = r.Domain
		out.DomainOK = r.Meta.Verified
		out.ServerVersion = r.ServerVersion.Version
		out.Chain = r.Chain
		out.LedgerIndex = r.LedgerIndex
		out.UNL = r.UNL
		if t, err := time.Parse(time.RFC3339, r.LastSeen); err == nil {
			out.LastSeen = t
		}
		break
	}
	// Not found in a listing we successfully read is a real answer: this key
	// is genuinely absent from the registry.
	return out, nil
}

// Describe renders the status as the plain lines the model context carries.
func (v ValidatorStatus) Describe() string {
	if !v.Tracked {
		return fmt.Sprintf("validator %s is not tracked by the public registry (%s) — "+
			"normal for a validator not on a published UNL; local measurements are authoritative",
			v.Key, v.Source)
	}
	d := v.Domain
	if d == "" {
		d = "no domain"
	} else if v.DomainOK {
		d += " (verified)"
	}
	seen := "last seen unknown"
	if !v.LastSeen.IsZero() {
		seen = fmt.Sprintf("last seen %s (%s ago)",
			v.LastSeen.UTC().Format(time.RFC3339), time.Since(v.LastSeen).Round(time.Minute))
	}
	unl := "on no published UNL"
	if len(v.UNL) > 0 {
		unl = "on published UNL: " + strings.Join(v.UNL, ", ")
	}
	return fmt.Sprintf("validator %s (%s, registry reports %s, chain %s, at ledger %d) — %s, %s. Source %s. "+
		"Registry version and ledger come from what the network last observed, so they lag a restart; "+
		"local measurements are authoritative for this node's own state.",
		v.Key, d, v.ServerVersion, v.Chain, v.LedgerIndex, seen, unl, v.Source)
}
