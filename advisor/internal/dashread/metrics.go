package dashread

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"
)

// This file is the service-side port of the reduction the Advisor tab
// performs for its four strip cells (advisor.html, loadCards). The page
// keeps its copy for DISPLAY — cards, sparklines, the composed "Check …"
// questions. What moved here is the model's view: ADR 0008 retires the
// page-passing path, so the measurements in the prompt are now assembled by
// the service from its own reads, which makes prompt.go's "own reads"
// invariant true of Metrics rather than merely claimed.
//
// The numbers must agree with what the operator sees on the cards, so the
// thresholds, the median, the change-point detector and the formatting all
// mirror the page exactly. When one side changes, change the other.

// Summary is one metric reduced to what the prompt carries. Field-for-field
// the shape of model.MetricLine; main.go maps between them so this package
// does not import the model.
type Summary struct {
	Label    string
	Now      string
	Baseline string
	Changed  string // "fell 39% around Jul 31", or empty when steady
}

// Card mirrors one CARDS entry on the page: label, formatting, and the
// relative move that counts as a change rather than noise.
type Card struct {
	Metric string
	Label  string
	Fmt    func(float64) string
	Drop   float64 // 0 = no drop threshold
	Rise   float64 // 0 = no rise threshold
}

// Cards returns the four strip metrics, mirroring CARDS in advisor.html.
func Cards() []Card {
	return []Card{
		{
			Metric: "peer_count", Label: "Peers",
			Fmt: func(v float64) string {
				if v >= 10 {
					return fmt.Sprintf("%.0f", v)
				}
				return fmt.Sprintf("%.1f", v)
			},
			Drop: 0.20, // a fifth of the peers gone is a change, not noise
		},
		{
			Metric: "tx_bps", Label: "Outgoing traffic",
			Fmt: func(v float64) string {
				return groupThousands(int64(math.Round(v/1000))) + " kbps"
			},
			Drop: 0.50,
			Rise: 1.00, // a doubling is worth explaining
		},
		{
			Metric: "peer_latency_p50", Label: "Peer latency",
			Fmt:  func(v float64) string { return fmt.Sprintf("%.0f ms", math.Round(v)) },
			Rise: 0.25,
		},
		{
			Metric: "agreement_pct", Label: "Agreement",
			Fmt: func(v float64) string {
				if v >= 99.995 {
					return fmt.Sprintf("%.0f%%", v)
				}
				return fmt.Sprintf("%.2f%%", v)
			},
			Drop: 0.001,
		},
	}
}

// groupThousands renders 533000 as "533,000", matching toLocaleString('en-US').
func groupThousands(n int64) string {
	s := fmt.Sprint(n)
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg, s = true, s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func median(a []float64) float64 {
	if len(a) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), a...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

type changeAt struct {
	index  int
	before float64
	after  float64
}

// changePoint finds the largest step in the series by difference of means
// either side of it. Deliberately crude, exactly as on the page: it points
// at a date, it does not prove anything.
func changePoint(v []float64) *changeAt {
	n := len(v)
	if n < 8 {
		return nil
	}
	pre := make([]float64, n+1)
	for i := 0; i < n; i++ {
		pre[i+1] = pre[i] + v[i]
	}
	best, bestD := -1, 0.0
	edge := int(math.Floor(float64(n) * 0.08))
	if edge < 3 {
		edge = 3
	}
	for k := edge; k < n-edge; k++ {
		before := pre[k] / float64(k)
		after := (pre[n] - pre[k]) / float64(n-k)
		if d := math.Abs(after - before); d > bestD {
			bestD, best = d, k
		}
	}
	if best < 0 {
		return nil
	}
	return &changeAt{
		index:  best,
		before: pre[best] / float64(best),
		after:  (pre[n] - pre[best]) / float64(n-best),
	}
}

func shortDate(tsMs int64) string {
	return time.UnixMilli(tsMs).Format("Jan 2")
}

func finite(pts []HistoryPoint) []float64 {
	out := make([]float64, 0, len(pts))
	for _, p := range pts {
		if !math.IsNaN(p.Value) && !math.IsInf(p.Value, 0) {
			out = append(out, p.Value)
		}
	}
	return out
}

// Summarize reduces one metric's 30-day series plus its last raw samples to
// the line the prompt carries. Returns nil when there is nothing usable —
// the prompt simply omits the metric, as the page omits the card's number.
func Summarize(card Card, hist []HistoryPoint, recent []HistoryPoint) *Summary {
	vals := finite(hist)
	n := len(vals)
	if n == 0 {
		return nil
	}
	live := finite(recent)

	// The card's number must be the node NOW: the bucketed series lags by
	// hours, and after the 3.2.1 upgrade it fed a stale peer count to the
	// model. Same rule here, for the same reason.
	tail := n / 20
	if tail < 1 {
		tail = 1
	}
	now := median(vals[n-tail:])
	if len(live) > 0 {
		now = median(live)
	}

	cp := changePoint(vals)
	var baselineV float64
	if cp != nil {
		baselineV = cp.before
	} else {
		head := int(math.Floor(float64(n) * 0.6))
		if head < 1 {
			head = 1
		}
		baselineV = median(vals[:head])
	}

	rel := 0.0
	if baselineV > 1e-9 {
		rel = (now - baselineV) / baselineV
	}
	moved := ""
	if card.Drop != 0 && rel <= -card.Drop {
		moved = "fell"
	} else if card.Rise != 0 && rel >= card.Rise {
		moved = "rose"
	}

	changed := ""
	if moved != "" {
		when := "an unclear date"
		if cp != nil {
			i := cp.index
			if i > len(hist)-1 {
				i = len(hist) - 1
			}
			when = shortDate(hist[i].TS)
		}
		changed = fmt.Sprintf("%s %d%% around %s", moved, int(math.Abs(math.Round(rel*100))), when)
	}

	return &Summary{
		Label:    card.Label,
		Now:      card.Fmt(now),
		Baseline: card.Fmt(baselineV),
		Changed:  changed,
	}
}

// AssembleMetrics fetches and reduces all four strip metrics. An error means
// the surface itself failed (unreachable, unauthorized, version mismatch) —
// the caller surfaces that as a state rather than answering from nothing.
func AssembleMetrics(ctx context.Context, c *Client) ([]Summary, error) {
	return AssembleMetricsWith(ctx, c, c.History)
}

// HistoryFunc is the History read AssembleMetricsWith takes, so a caller can
// put a cache in front of it. Same signature as Client.History.
type HistoryFunc func(ctx context.Context, metric, rng, agg string) ([]HistoryPoint, error)

// AssembleMetricsWith is AssembleMetrics with the history read injected.
//
// #119: the four 30d reads are the expensive half by three orders of
// magnitude. Each is a 30-day aggregation over ~2.6M rows on the dashboard's
// single-threaded event loop, measured at up to ~600ms; the Recent(5) beside
// it is an indexed LIMIT 5 and measured under 20ms for all four together. So
// the caller caches history and leaves recent alone, and this signature is
// what lets it do that without this package holding state of its own.
func AssembleMetricsWith(ctx context.Context, c *Client, history HistoryFunc) ([]Summary, error) {
	var out []Summary
	for _, card := range Cards() {
		hist, err := history(ctx, card.Metric, "30d", "avg")
		if err != nil {
			return nil, err
		}
		recent, err := c.Recent(ctx, card.Metric, 5)
		if err != nil {
			return nil, err
		}
		if s := Summarize(card, hist, recent); s != nil {
			out = append(out, *s)
		}
	}
	return out, nil
}
