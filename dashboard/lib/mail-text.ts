// #1274. The plain-text part of the digest mail and the enrollment (magic-link)
// mail, built from the same facts as their HTML.
//
// Resend derives a text part by stripping the HTML when none is sent, and a
// table strips to cells that touch: `AgreementTotal ledgers99.5%`. A phone
// preview and a text-only reader show exactly that. #1243 fixed the alert mail
// the same way (buildText in email.ts); these two follow it, one `Label: value`
// per line. Nothing in a text part is escaped, because nothing there is parsed
// as markup. The one HTML builder here, the enrollment mail's, escapes the link.
//
// Kept out of server.ts and auth.ts so a test can import the builders without
// starting the dashboard.

import { digestValue } from './digest-value.js';

export interface DigestSummary {
  ts: number;                       // epoch ms when gathered
  windowHours: number;
  hostname: string;
  pubkey: string | null;
  serverState: string | null;
  ledgerIndex: number | null;
  agreement: { pct: number | null; total: number; missed: number };
  alerts: { total: number; byTier: { page: number; critical: number; warn: number }; top: Array<{ metric: string; severity: string; ts: number; value: number | null }> };
  network: { peerCount: number | null; trustedUnl: number };
  amendments: Array<{ name: string; eta?: string }>;
}

/** The slice of the digest config the body depends on. */
export interface DigestBodyConfig {
  footerTemplate: string;
  include: {
    agreement_summary: boolean;
    top_alerts: boolean;
    network_health: boolean;
    upcoming_amendments: boolean;
  };
}

/** `2026-10-23 21:50:07 UTC`, the one timestamp shape both parts print. */
export function formatDigestTs(tsMs: number): string {
  return new Date(tsMs).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

const SEV_WORD: Record<string, string> = { page: 'PAGE', critical: 'CRIT', warn: 'WARN' };

/** The digest's text part: the same blocks as buildDigestHtml, same order. */
export function buildDigestText(summary: DigestSummary, cfg: DigestBodyConfig): string {
  const L: string[] = ['DAILY DIGEST', `Aperire · ${summary.hostname}`, formatDigestTs(summary.ts)];
  if (summary.pubkey) L.push(`Validator key: ${summary.pubkey}`);

  if (cfg.include.agreement_summary) {
    const ag = summary.agreement;
    L.push('', `Validator health (last ${summary.windowHours} h)`);
    L.push(`Agreement: ${digestValue(ag.pct != null ? ag.pct.toFixed(2) + '%' : null)}`);
    L.push(`Total ledgers: ${ag.total}`);
    L.push(`Missed: ${ag.missed}`);
    if (summary.serverState) L.push(`Server state: ${summary.serverState}`);
    if (summary.ledgerIndex != null) L.push(`Last ledger: ${summary.ledgerIndex}`);
  }

  if (cfg.include.top_alerts) {
    L.push('', `Alerts (last ${summary.windowHours} h)`);
    L.push(`Total: ${summary.alerts.total}`);
    L.push(`Page: ${summary.alerts.byTier.page}`);
    L.push(`Critical: ${summary.alerts.byTier.critical}`);
    L.push(`Warn: ${summary.alerts.byTier.warn}`);
    if (summary.alerts.total > 0) {
      for (const t of summary.alerts.top) {
        L.push(`${SEV_WORD[t.severity] ?? t.severity.toUpperCase()} ${t.metric}: ${digestValue(t.value)} (${formatDigestTs(t.ts)})`);
      }
    } else {
      L.push('No alerts fired in this window.');
    }
  }

  if (cfg.include.network_health) {
    L.push('', 'Network');
    L.push(`Connected peers: ${digestValue(summary.network.peerCount)}`);
    L.push(`Trusted UNL: ${summary.network.trustedUnl}`);
  }

  if (cfg.include.upcoming_amendments && summary.amendments.length > 0) {
    L.push('', 'Upcoming amendments');
    for (const a of summary.amendments) L.push(a.eta ? `- ${a.name} (${a.eta})` : `- ${a.name}`);
  }

  L.push('', 'Aperire · XRPL validator dashboard');
  if (cfg.footerTemplate) L.push('', cfg.footerTemplate);
  return L.join('\n');
}

/**
 * The enrollment mail's HTML part, the one both senders use: the dashboard's
 * own sends (auth.ts) and `aperire-auth magic-link` (scripts/send-magic.mjs,
 * #1354). The CLI kept a copy of its own until now, and the copy was the only
 * part of it that ever ran, because the script that held it never started.
 * Keep prose short: the operator usually wants the link, not a brochure.
 */
export function buildEnrollmentHtml(url: string): string {
  const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]!));
  return `<!doctype html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1f2328;background:#fff;margin:0;padding:24px;">
  <div style="max-width:520px;margin:0 auto;">
    <h2 style="margin:0 0 16px;font-size:20px;">Enroll your Aperire passkey</h2>
    <p style="margin:0 0 16px;color:#555;line-height:1.5;">
      Click the link below to enroll a passkey on this device. Your browser
      will prompt for biometric verification (Touch ID, Face ID, Windows
      Hello, or a security key).
    </p>
    <p style="margin:24px 0;text-align:center;">
      <a href="${esc(url)}" style="display:inline-block;padding:12px 24px;background:#0969da;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">
        Enroll passkey
      </a>
    </p>
    <p style="margin:16px 0 0;color:#656d76;font-size:13px;line-height:1.5;">
      Or paste this URL into your browser:<br>
      <code style="display:inline-block;margin-top:6px;padding:6px 8px;background:#f6f8fa;border-radius:3px;font-size:12px;word-break:break-all;">${esc(url)}</code>
    </p>
    <hr style="border:0;border-top:1px solid #d1d9e0;margin:24px 0 12px;">
    <p style="margin:0;color:#8b949e;font-size:12px;">
      Single-use link. If you didn't request this, ignore this email — the
      URL becomes invalid as soon as it's used or after its expiry window.
    </p>
  </div>
</body></html>`;
}

/**
 * The enrollment mail's text part. The link sits on a line of its own, bare, so
 * a text client makes it tappable and nothing is glued to either end of it.
 */
export function buildEnrollmentText(url: string): string {
  return [
    'Enroll your Aperire passkey',
    '',
    'Open the link below to enroll a passkey on this device. Your browser will',
    'prompt for biometric verification (Touch ID, Face ID, Windows Hello, or a',
    'security key).',
    '',
    'Enroll link:',
    url,
    '',
    "Single-use link. If you didn't request this, ignore this email. The URL",
    'becomes invalid as soon as it is used or after its expiry window.',
  ].join('\n');
}
