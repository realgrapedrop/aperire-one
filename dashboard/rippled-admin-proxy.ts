// aperire-rippled-proxy — read-only allow-list proxy for the rippled admin WS.
//
// WHY (MED-12). The dashboard needs rippled's *admin* WebSocket for a handful
// of read commands (server_info, peers, feature, …). But rippled admin auth is
// binary: a connection that can read can also `stop` the validator, set
// amendment votes, `connect` to arbitrary peers, or create validation seeds.
// The dashboard's own code is verified read-only — but a compromise of the
// dashboard *process* (e.g. a malicious npm dependency gaining code-exec) would
// inherit a fully-privileged admin connection. rippled has no read-only admin
// role, so we contain rather than scope: this proxy sits between the dashboard
// and rippled, forwards only an explicit allow-list of read commands, and
// rejects everything else — including the mutating form of `feature`.
//
// DEPLOYMENT. Point the dashboard at the proxy and the proxy at rippled:
//   dashboard:  RIPPLED_URL=ws://127.0.0.1:6007
//   proxy:      PROXY_LISTEN=127.0.0.1:6007  RIPPLED_UPSTREAM_URL=ws://127.0.0.1:6006
// For the containment to be meaningful, rippled's admin port should accept
// connections only from the proxy (admin_ip / firewall) so the dashboard
// process cannot bypass the proxy and dial rippled directly. See the
// deployment guide's "Admin-RPC allow-list proxy" section.
//
// The proxy holds no secrets and issues no commands of its own — it only
// forwards or rejects. It is deliberately tiny: one upstream connection per
// client connection, lifecycle tied together, no buffering of state.

import { WebSocket, WebSocketServer } from 'ws';
import { ALLOWED_COMMANDS, rejectReason } from './lib/proxy-policy.js';

// ── Config ────────────────────────────────────────────────────────────────
const LISTEN = process.env.PROXY_LISTEN ?? '127.0.0.1:6007';
const [LISTEN_HOST, LISTEN_PORT_RAW] = LISTEN.split(':');
const LISTEN_PORT = Number(LISTEN_PORT_RAW ?? 6007);
const UPSTREAM_URL = process.env.RIPPLED_UPSTREAM_URL ?? 'ws://127.0.0.1:6006';

// ── Allow-list ──────────────────────────────────────────────────────────────
// The allow-list + decision logic lives in lib/proxy-policy.ts so it can be
// unit tested without opening sockets. ALLOWED_COMMANDS is EXACTLY the read
// commands dashboard/server.ts issues; rejectReason() enforces deny-by-default
// plus the `feature` vote-form guard.

// Build an error frame shaped like a rippled WS response so the dashboard's
// id-keyed request handler resolves the pending promise instead of hanging.
function errorFrame(raw: string, reason: string): string {
  let id: unknown;
  let command: unknown;
  try {
    const msg = JSON.parse(raw) as Record<string, unknown>;
    id = msg.id;
    command = msg.command;
  } catch { /* leave id/command undefined */ }
  return JSON.stringify({
    id,
    status: 'error',
    type: 'response',
    error: 'proxyForbidden',
    error_message: `aperire-rippled-proxy: ${reason}`,
    request: { command },
  });
}

// ── Proxy server ────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ host: LISTEN_HOST, port: LISTEN_PORT });

wss.on('connection', (client, req) => {
  const peer = req.socket.remoteAddress ?? '?';
  // One dedicated upstream connection per client. Tying the lifecycles 1:1
  // keeps the proxy stateless: when the dashboard reconnects, it gets a fresh
  // upstream; when upstream drops, the client is closed so the dashboard's own
  // reconnect loop takes over.
  const upstream = new WebSocket(UPSTREAM_URL);

  // Frames the client sends before upstream is OPEN (the dashboard fires
  // `subscribe` immediately on connect). Queue and flush on open.
  const pending: string[] = [];
  let upstreamOpen = false;

  function passOrReject(data: string): void {
    const reason = rejectReason(data);
    if (reason) {
      console.warn(`[proxy] REJECT from ${peer}: ${reason}`);
      try { client.send(errorFrame(data, reason)); } catch { /* client gone */ }
      return;
    }
    try { upstream.send(data); } catch { /* upstream gone; close handler cleans up */ }
  }

  client.on('message', (buf) => {
    const data = buf.toString('utf8');
    if (upstreamOpen) passOrReject(data);
    else pending.push(data);
  });

  upstream.on('open', () => {
    upstreamOpen = true;
    for (const data of pending.splice(0)) passOrReject(data);
  });

  // rippled → dashboard: relay verbatim. The proxy never inspects responses.
  upstream.on('message', (buf) => {
    try { client.send(buf.toString('utf8')); } catch { /* client gone */ }
  });

  // Lifecycle: any close/error on either side tears down the pair.
  const closeBoth = () => {
    try { client.close(); } catch { /* already closed */ }
    try { upstream.close(); } catch { /* already closed */ }
  };
  client.on('close', closeBoth);
  client.on('error', closeBoth);
  upstream.on('close', closeBoth);
  upstream.on('error', (err) => {
    console.warn(`[proxy] upstream error: ${(err as Error).message}`);
    closeBoth();
  });
});

wss.on('listening', () => {
  console.log(`[proxy] aperire-rippled-proxy on ws://${LISTEN_HOST}:${LISTEN_PORT} → ${UPSTREAM_URL}`);
  console.log(`[proxy] allow-list (${ALLOWED_COMMANDS.size}): ${[...ALLOWED_COMMANDS].join(', ')}`);
});

wss.on('error', (err) => {
  console.error(`[proxy] fatal: ${(err as Error).message}`);
  process.exit(1);
});
