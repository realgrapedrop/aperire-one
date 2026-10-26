// The security headers every response this process writes must carry, and the
// nonce the page's inline <script> is stamped with.
//
// In lib/ rather than in server.ts because of WHEN they have to be set (#240).
// The outer handler used to parse and decode the request URL first and set
// these afterwards, so a request whose path cannot be decoded — `curl
// /api/%zz` — threw before the first setHeader and was answered by the catch
// with a 500 carrying no Content-Security-Policy and no X-Content-Type-Options.
// Nothing rendered from that body, so nothing was exploitable, but "on every
// response" was not true, and the exception is the response most likely to be
// carrying something a page did not expect. Setting them is now the first
// thing the handler does, before anything that can throw, and this file is
// what a test can call without booting a database, a session store and a
// rippled connection.
//
// setHeader, never writeHead: the per-route `writeHead(code, {...})` calls
// merge with headers already set, and a writeHead that carried these would
// replace them on every route that names its own content type.

import { randomBytes } from 'node:crypto';

/** Just enough of a ServerResponse to set a header on. Kept structural so a
 *  test can pass a real ServerResponse and assert getHeaders() afterwards. */
export interface HeaderSink {
  setHeader(name: string, value: string): unknown;
}

// MED-05, Content-Security-Policy emitted on every response. script-src uses a
// per-response nonce (injected into each page's single inline <script>); there
// are no inline event handlers, so 'unsafe-inline' is never needed for script
// and an injected XSS payload cannot execute. style-src keeps 'unsafe-inline',
// the UI leans on a <style> block plus many style="" attrs, and style injection
// is low risk. External loads are pinned to the exact origins the UI uses: flag
// SVGs (img) from two CDNs and the optional lo-fi audio stream (media).
// Everything else is same-origin, including the /ws and /history connections
// (connect-src 'self' covers same-origin WebSocket).
export function contentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https://hatscripts.github.io https://cdn.jsdelivr.net",
    "media-src 'self' https://stream.nightride.fm",
    "connect-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    // 'self', not 'none', the dashboard shell (index.html) loads each tab
    // into a same-origin <iframe>, so framing by our own origin must be
    // allowed. External origins still can't frame us (clickjacking defense).
    "frame-ancestors 'self'",
  ].join('; ');
}

/**
 * Set the four headers on one response and return the nonce that response's
 * CSP names, for stamping onto an HTML body's inline <script>.
 *
 * Reads nothing off the request on purpose: it takes no request, so there is
 * nothing here that a malformed one can throw on, which is what lets it run
 * before the URL is parsed.
 */
export function applySecurityHeaders(res: HeaderSink): string {
  const nonce = randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy', contentSecurityPolicy(nonce));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // SAMEORIGIN, not DENY, the shell frames its tab pages from the same
  // origin (see frame-ancestors 'self' above). DENY blanks every tab.
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  return nonce;
}
