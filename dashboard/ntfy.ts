// Insights tab — ntfy push delivery (Phase 7).
//
// Mirrors email.ts in shape — one module, one send function, the
// state-machine evaluator fires it as part of deliverChannels(). NTFY
// is a self-hosted REST push service (binwiederhier/ntfy); Koi's
// Flash instance is the same pattern. Public topics need no auth;
// protected topics use Bearer auth via the NTFY_TOKEN env var.
//
// Reuses AlertEmailContext from email.ts since the per-alert payload
// is identical across channels — cheaper than duplicating the type.

import type { AlertEmailContext } from './email.js';
import { identityRows } from './lib/alert-identity.js';

export interface NtfyChannelConfig {
  baseUrl: string;                  // e.g. https://ntfy.your-domain.example
  topic:   string;                  // e.g. aperire-alerts
  token:   string | null;           // optional bearer; null for public topic
  severityPriority: { warn: string; critical: string; page: string };
}

export interface NtfySendResult {
  ok: boolean;
  messageId?: string;
  error?: string;
}

const SEV_LABEL: Record<AlertEmailContext['severity'], string> = {
  warn:     'WARN',
  critical: 'CRITICAL',
  page:     'PAGE',
};

const SEV_TAG: Record<AlertEmailContext['severity'], string> = {
  warn:     'warning',
  critical: 'rotating_light',
  page:     'rotating_light',
};

export function buildTitle(ctx: AlertEmailContext): string {
  const prefix = ctx.is_test ? '[TEST] ' : '';
  const stateLbl = ctx.state === 'firing' ? '' : ' resolved';
  // ASCII-only separator. Title is sent via HTTP header (RFC 7230,
  // US-ASCII only) so a Unicode "·" gets mangled to U+FFFD on the
  // ntfy server end and renders as "�" on phones. The node name is
  // operator-written (a fleet label, or APERIRE_HOSTNAME) and gets the same
  // treatment: it names the node on the lock screen, which is the one place
  // an operator reads before opening anything (#1229).
  const node = ctx.identity.name.replace(/[^\x20-\x7e]/g, '?');
  return `${prefix}${SEV_LABEL[ctx.severity]} - ${ctx.metric}${stateLbl} on ${node}`;
}

export function buildMessage(ctx: AlertEmailContext): string {
  const lines: string[] = [];
  if (ctx.is_test) lines.push('Test Fire from Aperire. No real alert is firing.');
  if (ctx.threshold_op != null && ctx.threshold_value != null) {
    lines.push(`Threshold: ${ctx.threshold_op} ${ctx.threshold_value}` +
               (ctx.duration_s != null && ctx.state === 'firing' ? ` for ${ctx.duration_s}s` : ''));
  }
  if (ctx.value != null) {
    lines.push(`${ctx.state === 'firing' ? 'Current' : 'Final'} value: ${ctx.value}`);
  }
  if (ctx.state === 'resolved' && ctx.duration_s != null) {
    lines.push(`Was firing for ${ctx.duration_s}s`);
  }
  for (const r of identityRows(ctx.identity)) lines.push(`${r.label}: ${r.value}`);
  if (ctx.knowledge?.recommended_actions?.[0] && ctx.state === 'firing') {
    lines.push(`First check: ${ctx.knowledge.recommended_actions[0]}`);
  }
  return lines.join('\n');
}

/**
 * Send a notification through ntfy.
 *
 * POST JSON to the base URL with topic, title, message, priority,
 * tags, click. Bearer auth header added when a token is configured.
 *
 * Returns a result object — never throws. Errors are recorded back
 * to alerts_history.delivery so the operator can see "ntfy failed"
 * in the channel icons.
 */
export async function sendAlertNtfy(
  cfg: NtfyChannelConfig,
  ctx: AlertEmailContext,
): Promise<NtfySendResult> {
  if (!cfg.baseUrl) return { ok: false, error: 'no base_url' };
  if (!cfg.topic)   return { ok: false, error: 'no topic' };

  const priority = cfg.severityPriority[ctx.severity] ?? 'default';
  // Traditional ntfy publish: POST {baseUrl}/{topic} with the message
  // as the request body and metadata in headers. More reliable across
  // ntfy server versions than the JSON-body publish path; matches the
  // documented "Publish via PUT/POST" usage in ntfy.sh docs.
  const url = `${cfg.baseUrl.replace(/\/$/, '')}/${cfg.topic}`;
  const title = buildTitle(ctx);
  const headers: Record<string, string> = {
    'content-type': 'text/plain; charset=utf-8',
    'title':    title,
    'priority': priority,
    'tags':     SEV_TAG[ctx.severity],
  };
  if (cfg.token) headers['authorization'] = `Bearer ${cfg.token}`;
  if (ctx.identity.url) headers['click'] = ctx.identity.url;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: buildMessage(ctx),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, error: `HTTP ${res.status}${text ? ': ' + text.slice(0, 200) : ''}` };
    }
    let messageId: string | undefined;
    try {
      const data = await res.json() as { id?: string };
      messageId = data.id;
    } catch (_) { /* server returned non-JSON; that's fine, just no id */ }
    return { ok: true, messageId };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}
