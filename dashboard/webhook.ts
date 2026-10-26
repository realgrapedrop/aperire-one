// Insights tab — webhook delivery (Phase 8).
//
// Mirrors email.ts / ntfy.ts in shape — one module, one send function,
// the state-machine evaluator fans out via deliverChannels(). Three
// payload formats: Discord (embeds), Slack (attachments), generic
// (flat JSON for any HTTP receiver). Operators add entries to
// channels.yaml; rules.yaml refers to the singular id `webhook` and
// the server fans out to every configured target whose severity_filter
// admits this alert.
//
// Reuses AlertEmailContext from email.ts since the per-alert payload
// is identical across channels — same reasoning as ntfy.ts.
//
// Which node fired comes from the same identity block as email and ntfy
// (#1229, lib/alert-identity.ts): Discord and Slack print its four rows as
// fields, generic carries the identity under `node` (#1259).

import type { AlertEmailContext } from './email.js';
import { identityRows } from './lib/alert-identity.js';

export type WebhookFormat = 'discord' | 'slack' | 'generic';

export interface WebhookChannelConfig {
  id:           string;                 // operator-chosen label, e.g. "discord-ops"
  format:       WebhookFormat;
  url:          string;                 // POST target
  authHeader:   string | null;          // resolved value, not the env-var name
  severityFilter: AlertEmailContext['severity'][] | null;  // null = accept all
}

export interface WebhookSendResult {
  ok: boolean;
  status?: number;
  error?:  string;
}

const SEV_LABEL: Record<AlertEmailContext['severity'], string> = {
  warn:     'WARN',
  critical: 'CRITICAL',
  page:     'PAGE',
};

// Severity colour palette — same intent as the email HTML and the
// dashboard's ok/warn/alert tokens. Webhook receivers display these
// inline, so consistency with the rest of the surface matters.
const SEV_COLOR_HEX: Record<AlertEmailContext['severity'], string> = {
  warn:     '#bf8700',
  critical: '#cf222e',
  page:     '#cf222e',
};
const RESOLVED_COLOR_HEX = '#1a7f37';
// Discord embeds want a decimal int, not "#rrggbb".
function hexToInt(hex: string): number {
  return parseInt(hex.replace('#', ''), 16);
}

function buildTitle(ctx: AlertEmailContext): string {
  const prefix   = ctx.is_test ? '[TEST] ' : '';
  const stateLbl = ctx.state === 'firing' ? '' : ' resolved';
  return `${prefix}[${SEV_LABEL[ctx.severity]}] ${ctx.metric}${stateLbl} on ${ctx.identity.name}`;
}

function buildSummaryLines(ctx: AlertEmailContext): string[] {
  const lines: string[] = [];
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
  if (ctx.knowledge?.recommended_actions?.[0] && ctx.state === 'firing') {
    lines.push(`First check: ${ctx.knowledge.recommended_actions[0]}`);
  }
  return lines;
}

// ── Discord payload ────────────────────────────────────────────────
// https://discord.com/developers/docs/resources/webhook#execute-webhook
// Embeds carry a coloured side-bar that operators read at-a-glance.
function buildDiscordPayload(ctx: AlertEmailContext): unknown {
  const isFiring = ctx.state === 'firing';
  const color = hexToInt(isFiring ? SEV_COLOR_HEX[ctx.severity] : RESOLVED_COLOR_HEX);
  const fields: { name: string; value: string; inline?: boolean }[] = [];
  if (ctx.threshold_op != null && ctx.threshold_value != null) {
    fields.push({ name: 'Threshold', value: `${ctx.threshold_op} ${ctx.threshold_value}`, inline: true });
  }
  if (ctx.value != null) {
    fields.push({ name: isFiring ? 'Current' : 'Final', value: String(ctx.value), inline: true });
  }
  if (ctx.duration_s != null) {
    fields.push({ name: isFiring ? 'Held for' : 'Was firing', value: `${ctx.duration_s}s`, inline: true });
  }
  for (const r of identityRows(ctx.identity)) fields.push({ name: r.label, value: r.value, inline: r.label !== 'Link' });
  if (ctx.knowledge?.recommended_actions?.[0] && isFiring) {
    fields.push({ name: 'First check', value: ctx.knowledge.recommended_actions[0], inline: false });
  }
  return {
    username: 'Aperire',
    embeds: [{
      title:       buildTitle(ctx),
      url:         ctx.dashboard_url || undefined,
      description: ctx.is_test ? 'Test Fire from Aperire. No real alert is firing.' : undefined,
      color,
      fields,
      timestamp:   new Date().toISOString(),
      footer:      { text: 'Aperire · XRPL validator dashboard' },
    }],
  };
}

// ── Slack payload ──────────────────────────────────────────────────
// https://api.slack.com/messaging/webhooks — `attachments[].color`
// drives the side-bar; `fields` render in two columns.
function buildSlackPayload(ctx: AlertEmailContext): unknown {
  const isFiring = ctx.state === 'firing';
  const color    = isFiring ? SEV_COLOR_HEX[ctx.severity] : RESOLVED_COLOR_HEX;
  const fields: { title: string; value: string; short: boolean }[] = [];
  if (ctx.threshold_op != null && ctx.threshold_value != null) {
    fields.push({ title: 'Threshold', value: `${ctx.threshold_op} ${ctx.threshold_value}`, short: true });
  }
  if (ctx.value != null) {
    fields.push({ title: isFiring ? 'Current' : 'Final', value: String(ctx.value), short: true });
  }
  if (ctx.duration_s != null) {
    fields.push({ title: isFiring ? 'Held for' : 'Was firing', value: `${ctx.duration_s}s`, short: true });
  }
  for (const r of identityRows(ctx.identity)) fields.push({ title: r.label, value: r.value, short: r.label !== 'Link' });
  if (ctx.knowledge?.recommended_actions?.[0] && isFiring) {
    fields.push({ title: 'First check', value: ctx.knowledge.recommended_actions[0], short: false });
  }
  return {
    text: buildTitle(ctx),
    attachments: [{
      color,
      title:       buildTitle(ctx),
      title_link:  ctx.dashboard_url || undefined,
      text:        buildSummaryLines(ctx).join('\n'),
      fields,
      footer:      'Aperire',
      ts:          Math.floor(Date.now() / 1000),
    }],
  };
}

// ── Generic payload ────────────────────────────────────────────────
// Stable, documented JSON shape for any HTTP receiver. Keys mirror
// AlertEmailContext so a downstream consumer can map fields without
// guessing. Don't rename keys without a version bump; adding one (`node`,
// #1259) is safe for a receiver that ignores keys it doesn't know.
function buildGenericPayload(ctx: AlertEmailContext): unknown {
  return {
    schema:          'aperire.alert.v1',
    metric:          ctx.metric,
    severity:        ctx.severity,
    state:           ctx.state,
    value:           ctx.value,
    threshold_op:    ctx.threshold_op,
    threshold_value: ctx.threshold_value,
    duration_s:      ctx.duration_s,
    dedup_key:       ctx.dedup_key,
    triggered_iso:   ctx.triggered_iso,
    hostname:        ctx.hostname,
    node: {
      name:     ctx.identity.name,
      role:     ctx.identity.role,
      hostname: ctx.identity.hostname,
      node_key: ctx.identity.node_key,
      url:      ctx.identity.url,
    },
    dashboard_url:   ctx.dashboard_url ?? null,
    is_test:         !!ctx.is_test,
    knowledge:       ctx.knowledge ?? null,
  };
}

export function buildPayload(format: WebhookFormat, ctx: AlertEmailContext): unknown {
  switch (format) {
    case 'discord': return buildDiscordPayload(ctx);
    case 'slack':   return buildSlackPayload(ctx);
    case 'generic': return buildGenericPayload(ctx);
  }
}

/**
 * Send an alert through one webhook target.
 *
 * POST JSON to `cfg.url` with a 10s timeout. Returns a result object
 * — never throws. The fan-out caller in server.ts collates per-target
 * results and patches alerts_history.delivery with a summary status
 * for the row. Failures don't block siblings.
 */
export async function sendAlertWebhook(
  cfg: WebhookChannelConfig,
  ctx: AlertEmailContext,
): Promise<WebhookSendResult> {
  if (!cfg.url) return { ok: false, error: 'no url' };

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'user-agent':   'aperire-dashboard/1.0',
  };
  if (cfg.authHeader) headers['authorization'] = cfg.authHeader;

  const body = JSON.stringify(buildPayload(cfg.format, ctx));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const res = await fetch(cfg.url, {
      method: 'POST',
      headers,
      body,
      signal: controller.signal,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, status: res.status, error: `HTTP ${res.status}${text ? ': ' + text.slice(0, 200) : ''}` };
    }
    return { ok: true, status: res.status };
  } catch (err) {
    const e = err as Error;
    if (e.name === 'AbortError') return { ok: false, error: 'timeout after 10s' };
    return { ok: false, error: e.message };
  } finally {
    clearTimeout(timeout);
  }
}
