/**
 * The Advisors a logout must also cancel approvals on (#1094): every linked
 * node's, read from the registry at the moment of logout.
 *
 * Only a peer with BOTH an advisor_origin and an advisor_token_path has an
 * Advisor this host can speak to. The token is read fresh, the way the
 * forwarded approval routes read it, so a rotated token is the one used, and
 * a token that cannot be read comes back as null for the caller to name.
 */
import type { LogoutCancelTarget } from '../auth.js';

export interface LogoutPeer {
  label: string;
  advisor_origin?: string;
  advisor_token_path?: string;
}

export function logoutCancelTargets(
  peers: readonly LogoutPeer[], readToken: (path: string) => string | null,
): LogoutCancelTarget[] {
  const out: LogoutCancelTarget[] = [];
  for (const p of peers) {
    if (!p.advisor_origin || !p.advisor_token_path) continue;
    out.push({ label: p.label, url: p.advisor_origin, token: readToken(p.advisor_token_path) });
  }
  return out;
}
