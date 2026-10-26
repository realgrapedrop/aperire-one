// MED-07 — transport policy for the relay's /ingest WebSocket.
//
// The dashboard speaks plain HTTP (node:http). Nothing in this process
// terminates TLS, so every byte that reaches /ingest arrived in the clear on
// the last hop. That is harmless when the last hop never left the machine: a
// co-located relay dialling 127.0.0.1, or a TLS-terminating proxy on the same
// box forwarding to loopback. It is not harmless when the dashboard is bound
// to a LAN address and a relay on a different machine dials it directly,
// because the `Authorization: Bearer <relay token>` header and every telemetry
// frame then cross the LAN readable. Anyone who can see that traffic can
// replay the token and push forged telemetry: false alerts, or worse, a real
// incident papered over with healthy-looking numbers.
//
// So: refuse that one arrangement by default, and name the two sanctioned ways
// out in the log. Loopback deployments — which is every deployed host — are
// completely unaffected; they never reach the refusal branch at all.
//
// This module is pure on purpose. server.ts wires it into the upgrade handler;
// the decisions themselves are testable without a socket.

import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Is this the relay's token?
 *
 * LOW-02. `RELAY_TOKENS.has(token)` answered the same question, and answered
 * it in a time that depends on how much of the token was right, because
 * JavaScript string equality stops at the first byte that differs. On the
 * loopback hop that /ingest is meant for, that leaks to nobody. The gate does
 * not get to assume the hop stayed loopback: an operator who binds HOST to a
 * LAN address and sets the override has an /ingest a LAN peer can time.
 *
 * Constant-time in the two senses lib/fleet-link-hub.ts's resolveCredential
 * uses. Each comparison is timingSafeEqual over a fixed-width SHA-256 digest,
 * so a token of the wrong length is not distinguishable from one of the right
 * length. And the loop does not break on a hit, so the time it takes does not
 * say which configured token matched. It still scales with how many are
 * configured, which is a fact about this host and not about the token.
 */
export function relayTokenAccepted(presented: string, tokens: Iterable<string>): boolean {
  if (!presented) return false;
  const digest = createHash('sha256').update(presented, 'utf8').digest();
  let hit = false;
  for (const token of tokens) {
    if (!token) continue;
    const expected = createHash('sha256').update(token, 'utf8').digest();
    if (timingSafeEqual(expected, digest)) hit = true;
  }
  return hit;
}

/** The env var an operator sets to accept the plaintext LAN hop deliberately. */
export const PLAINTEXT_OVERRIDE_ENV = 'APERIRE_INGEST_ALLOW_PLAINTEXT';

/**
 * True when the operator has deliberately named the override. Deliberately
 * narrow: an empty string, "0", "no" or anything unrecognised is off, because
 * the failure mode of a generous parser here is a silent downgrade.
 */
export function plaintextOverrideEnabled(raw: string | undefined): boolean {
  const v = (raw ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

/**
 * Normalise an address for loopback testing: strip IPv6 brackets, a zone id,
 * and the IPv4-mapped-IPv6 prefix Node hands back for a v4 peer on a
 * dual-stack listener (`::ffff:127.0.0.1`).
 */
function normalizeAddress(raw: string): string {
  let a = raw.trim().toLowerCase();
  if (a.startsWith('[') && a.endsWith(']')) a = a.slice(1, -1);
  const zone = a.indexOf('%');
  if (zone !== -1) a = a.slice(0, zone);
  if (a.startsWith('::ffff:')) a = a.slice('::ffff:'.length);
  return a;
}

/**
 * True for anything that cannot leave the machine: `localhost`, `::1`, and the
 * whole of 127.0.0.0/8 (systemd-resolved sits on 127.0.0.53, and an operator
 * binding 127.0.1.1 is still loopback-only).
 *
 * A wildcard bind (`0.0.0.0`, `::`) is NOT loopback: it covers loopback and
 * every LAN interface, and it is the LAN half that decides the risk.
 */
export function isLoopbackHost(host: string | undefined | null): boolean {
  if (!host) return false;
  const a = normalizeAddress(host);
  if (a === 'localhost') return true;
  if (a === '::1') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
  if (!m) return false;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some(n => n > 255)) return false;
  return octets[0] === 127;
}

/**
 * The peer end of an accepted socket. Same rule as isLoopbackHost, plus one
 * difference that matters: an address we could not read at all is treated as
 * remote. Failing closed on an unknown peer is the whole point of the gate.
 */
export function isLoopbackPeer(remoteAddress: string | undefined | null): boolean {
  if (!remoteAddress) return false;
  return isLoopbackHost(remoteAddress);
}

export type IngestAllowReason =
  | 'loopback-bind'   // the listener cannot be reached from off-box
  | 'loopback-peer'   // the relay (or a local TLS proxy) is on this machine
  | 'encrypted'       // the hop reached us over TLS
  | 'override';       // the operator accepted the plaintext LAN hop by name

export type IngestDecision =
  | { allow: true; reason: IngestAllowReason; message?: string }
  | { allow: false; reason: 'plaintext-remote'; message: string };

export interface IngestPolicyInput {
  /** The address the dashboard's listener is bound to (the HOST env value). */
  bindHost: string;
  /** `req.socket.remoteAddress` for the connecting relay. */
  remoteAddress: string | undefined | null;
  /**
   * True when this socket reached us over TLS. Unreachable today: server.ts
   * builds its listener with node:http, so this is always false. It is here so
   * that a future TLS listener does not have to re-derive the rule, and so the
   * rule reads as "plaintext" rather than "always".
   */
  encrypted?: boolean;
  /** Result of plaintextOverrideEnabled() on the env var. */
  allowPlaintext: boolean;
}

/**
 * Decide whether an authenticated relay may complete its /ingest upgrade.
 *
 * Called AFTER the bearer-token check, not before. The token is on the wire in
 * the upgrade request either way, so checking transport first would protect no
 * secret; it would only mean any LAN scanner that touches the port can write a
 * line into the operator's journal. Ordering it second makes a refusal mean
 * "a real relay was turned away", which is the thing worth logging.
 */
export function decideIngest(input: IngestPolicyInput): IngestDecision {
  if (input.encrypted) return { allow: true, reason: 'encrypted' };
  if (isLoopbackHost(input.bindHost)) return { allow: true, reason: 'loopback-bind' };
  if (isLoopbackPeer(input.remoteAddress)) return { allow: true, reason: 'loopback-peer' };

  const peer = input.remoteAddress ? String(input.remoteAddress) : 'unknown';
  if (input.allowPlaintext) {
    return {
      allow: true,
      reason: 'override',
      message: `[ingest] plaintext push from ${peer} accepted: ${PLAINTEXT_OVERRIDE_ENV} is set. `
        + `The relay bearer token and telemetry cross the network readable on this hop (MED-07).`,
    };
  }
  return {
    allow: false,
    reason: 'plaintext-remote',
    message: `[security] REFUSED /ingest from ${peer}: the dashboard is bound to ${input.bindHost} and this relay `
      + `reached it over plain ws, so the bearer token and telemetry would cross the network readable, `
      + `and anyone who can see them can push forged telemetry (MED-07). `
      + `Two sanctioned fixes: (1) tunnel the hop with WireGuard or SSH so both ends stay loopback and set `
      + `dashboard_url = "ws://127.0.0.1:<port>/ingest" on the relay, or (2) terminate TLS in front of the `
      + `dashboard and set dashboard_url = "wss://.../ingest". `
      + `If this is a trusted L2 you accept the risk on, set ${PLAINTEXT_OVERRIDE_ENV}=1 on the dashboard. `
      + `See docs/RELAY-REFERENCE.md, "Securing a remote relay link".`,
  };
}

/**
 * The startup line. Emitted whenever HOST is non-loopback at all, with or
 * without relay tokens configured and with or without the override, because
 * "the ingest port is reachable from off-box" is the fact an operator needs to
 * see in the journal. Returns null for a loopback bind, which is the default
 * and stays silent.
 */
export function startupIngestWarning(input: { bindHost: string; allowPlaintext: boolean }): string | null {
  if (isLoopbackHost(input.bindHost)) return null;
  const base = `[security] HOST=${input.bindHost} is not loopback: /ingest is reachable off-box and carries the `
    + `relay bearer token and telemetry over plain ws (MED-07).`;
  if (input.allowPlaintext) {
    return `${base} ${PLAINTEXT_OVERRIDE_ENV} is set, so plaintext pushes from remote relays are ACCEPTED. `
      + `Prefer a WireGuard or SSH tunnel that keeps both ends loopback, or terminate TLS in front of the dashboard.`;
  }
  return `${base} Plaintext pushes from remote relays are REFUSED. Tunnel the hop with WireGuard or SSH so both ends `
    + `stay loopback, or terminate TLS in front of the dashboard and point the relay at wss://. `
    + `Set ${PLAINTEXT_OVERRIDE_ENV}=1 only to accept the cleartext hop on a trusted L2. `
    + `See docs/RELAY-REFERENCE.md, "Securing a remote relay link".`;
}
