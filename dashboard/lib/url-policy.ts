// Pure URL-policy helpers, factored out of server.ts so they can be unit
// tested without booting the server.

// MED-09 — accept only http(s) links. xls_url is regex-scraped from xrpl.org
// and amendments.yaml is hand-editable, so a tampered upstream or hostile YAML
// could otherwise smuggle a `javascript:`/`data:` URL that runs when an
// operator clicks the spec link. Parsing against a base also resolves any
// relative href to an absolute one. Returns undefined for anything non-http(s).
export function sanitizeHttpUrl(raw: string): string | undefined {
  try {
    const u = new URL(raw, 'https://xrpl.org');
    return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : undefined;
  } catch { return undefined; }
}

// ── The validator's self-asserted domain ─────────────────────────────────
//
// The domain comes out of the validator's own manifest, so it is operator-set
// rather than attacker-set, and the dashboard fetches one file from it to see
// whether the validator is listed there. That is still an outbound request to
// a name this process was told at runtime, which is the shape SSRF takes.

/**
 * Reject hosts that could point an outbound fetch at internal infrastructure.
 * A bare registrable hostname only: no userinfo, no port, no path, no IP
 * literal, and none of the suffixes that only resolve inside a network.
 */
export function isSafePublicDomain(host: string): boolean {
  if (!host || host.length > 253) return false;
  const h = host.toLowerCase();
  // No userinfo, port, path, or whitespace, a bare hostname only.
  if (/[\s/@:?#\\]/.test(h)) return false;
  // Reject IP literals (v4 and bracketless v6), domain verification is for
  // named hosts; an IP literal is a red flag for SSRF.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;
  if (h.includes(':')) return false;                 // any colon → IPv6/port
  // Must look like a real registrable domain (at least one dot, valid labels).
  if (!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(h)) return false;
  // Reject obviously-internal suffixes / hostnames.
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
      h.endsWith('.internal') || h.endsWith('.lan')) return false;
  return true;
}

/** How many hops the toml fetch will follow before it gives up. */
export const TOML_MAX_REDIRECTS = 3;

/**
 * LOW-07. Where a redirect on the toml fetch is allowed to go.
 *
 * The guard above runs once, on the domain the manifest claimed. With
 * `redirect: 'follow'` that was the only time it ran: whoever controls the
 * response controls every hop after it, and one `302 Location:
 * http://169.254.169.254/latest/meta-data/` walks the request straight past a
 * check that already passed. Following by hand means the same guard runs on
 * every hop, which is the point.
 *
 * Returns the absolute URL to fetch next, or null to stop. Refuses anything
 * that is not https, any host the guard would not have accepted in the first
 * place, and a Location that will not parse.
 */
export function nextTomlHop(from: string, location: string | null): string | null {
  if (!location) return null;
  let next: URL;
  try { next = new URL(location, from); } catch { return null; }
  if (next.protocol !== 'https:') return null;
  if (next.port) return null;
  if (next.username || next.password) return null;
  if (!isSafePublicDomain(next.hostname)) return null;
  return next.href;
}
