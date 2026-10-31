package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// pushLoop opens a WebSocket to the dashboard and pushes one frame per tick
// for as long as the connection stays up. On disconnect it backs off and
// reconnects forever — dashboard outages aren't fatal.
//
// Backoff: 1s → 2s → 5s → 30s → 60s capped. No jitter — the dashboard can
// handle a thundering herd even if every validator reconnects simultaneously.
//
// The ladder resets after a session that actually worked, and that reset is
// the part that matters. oneSession runs until the connection drops, and a
// dropped connection is an error — so resetting only on a nil return meant
// resetting never. Four disconnects over the life of the process and the relay
// sat at the 60s cap permanently: a dashboard restart that took three seconds
// cost a full minute of host metrics, every time, on a process that had been
// up for weeks.
//
// A session that stayed up is evidence the far side is fine, whatever ended
// it. Treating its end as the first failure of a new outage rather than the
// fifth of an old one is what makes the first retry fast again.
const healthySession = 60 * time.Second

func pushLoop(ctx context.Context, cfg *Config, version string) {
	backoff := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 30 * time.Second, 60 * time.Second}
	attempt := 0
	for {
		started := time.Now()
		err := oneSession(ctx, cfg, version)
		if ctx.Err() != nil {
			return
		}
		lasted := time.Since(started)
		if lasted >= healthySession {
			attempt = 0
		}
		if err == nil {
			attempt = 0
			continue
		}
		wait := backoff[min(attempt, len(backoff)-1)]
		log.Printf("[pusher] session ended after %s: %v (reconnect in %s)",
			lasted.Round(time.Second), err, wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		attempt++
	}
}

// dialDashboard opens the ingest WebSocket to cfg.DashboardURL with the relay's
// bearer token attached.
//
// wss:// works with no extra plumbing: coder/websocket rewrites the scheme to
// https and hands the request to an *http.Client, so TLS is negotiated and the
// server certificate is verified against the host's system root store. There
// is no InsecureSkipVerify anywhere in this path and no custom CA hook, which
// means a dashboard fronted by a private CA needs that CA installed on the
// validator host the same way every other tool on the box needs it.
//
// client is nil in production, which selects http.DefaultClient and therefore
// the system roots. Tests pass their own client to reach a certificate the
// system roots do not know about; that injection is the only reason this is a
// separate function.
func dialDashboard(ctx context.Context, cfg *Config, client *http.Client) (*websocket.Conn, error) {
	conn, _, err := dialDashboardResp(ctx, cfg, client, 10*time.Second)
	return conn, err
}

// dialDashboardResp is dialDashboard with the HTTP answer kept and the time
// allowed chosen by the caller. A refused upgrade comes back as an error AND a
// response, and the status is the only reliable way to tell a refused token
// (401) from a refused transport (403): --check-dashboard reads it from here
// rather than from the error's text.
func dialDashboardResp(ctx context.Context, cfg *Config, client *http.Client, within time.Duration) (*websocket.Conn, *http.Response, error) {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.AuthToken)

	dialCtx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	return websocket.Dial(dialCtx, cfg.DashboardURL, &websocket.DialOptions{
		HTTPHeader: header,
		HTTPClient: client,
	})
}

// oneSession runs until the connection drops or ctx is cancelled. Each call
// to this function represents one successful or unsuccessful dial + push
// tight-loop. Errors are the signal to reconnect.
func oneSession(ctx context.Context, cfg *Config, version string) error {
	conn, err := dialDashboard(ctx, cfg, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Give reads a generous budget — the dashboard doesn't send anything
	// back but we still want a read loop running so close frames land.
	defer conn.Close(websocket.StatusNormalClosure, "relay shutdown")
	log.Printf("[pusher] connected to %s", cfg.DashboardURL)

	// Background reader — drains anything the server sends and surfaces
	// connection closure via ctx cancellation.
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	go func() {
		for {
			_, _, err := conn.Read(sessionCtx)
			if err != nil {
				cancelSession()
				return
			}
		}
	}()

	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sysState := &systemState{}

	// First tick immediately so the dashboard populates without waiting a
	// full interval. System block's CPU busy% will be 0 on this first push
	// (no prior jiffy snapshot); that's expected and corrects next tick.
	for {
		if err := sendTick(sessionCtx, conn, cfg, version, sysState); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		select {
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		case <-ticker.C:
		}
	}
}

// sendTick collects both payload blocks and writes two RelayPush frames on
// the WS connection. We emit each block as its own message so the dashboard
// can route them independently — the discriminated-union envelope pattern
// in the TS contract makes this a natural split.
func sendTick(ctx context.Context, conn *websocket.Conn, cfg *Config, version string, state *systemState) error {
	now := time.Now().UnixMilli()
	netPayload := collectNet(cfg)
	sysPayload := collectSystem(cfg, state)

	frames := []RelayPush{
		{Type: "push", ProtocolVersion: 1, NodeLabel: cfg.NodeLabel, RelayVersion: version, SentAtMs: now, Payload: netPayload},
		{Type: "push", ProtocolVersion: 1, NodeLabel: cfg.NodeLabel, RelayVersion: version, SentAtMs: now, Payload: sysPayload},
	}

	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, f := range frames {
		data, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("marshal %T: %w", f.Payload, err)
		}
		if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
			return err
		}
	}
	return nil
}
