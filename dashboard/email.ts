// Insights tab — email delivery via Resend (Phase 4).
//
// One thin module that knows how to send the alert-pipeline emails.
// Configuration comes from `channels.yaml` (parsed by server.ts) plus
// the RESEND_API_KEY env var. We use Resend's transactional Emails API
// rather than Broadcasts — alerts are low-volume, per-recipient, and
// not subject to marketing-list semantics.
//
// The module is intentionally narrow: one function, fire-and-forget
// from the state-machine evaluator. Delivery success/failure is
// reported back via the returned promise so the caller can patch
// `alerts_history.delivery` for the row.

import { Resend } from 'resend';
import { identityRows, type NodeIdentity } from './lib/alert-identity.js';

export interface AlertEmailContext {
  metric: string;
  severity: 'warn' | 'critical' | 'page';
  state:    'firing' | 'resolved';
  value:    number | null;
  threshold_op: string | null;
  threshold_value: number | null;
  duration_s: number | null;          // hold-required for firing, held-for for resolved
  dedup_key: string;
  triggered_iso: string;              // human-readable triggered timestamp
  hostname: string;                   // dashboard host identifier
  dashboard_url?: string;             // optional click-through link
  // #1229. Which node this is about, built once (lib/alert-identity.ts) and
  // rendered by every channel. Required, so a new place that builds a context
  // fails to compile until it says which node the alert is for.
  identity: NodeIdentity;
  knowledge?: { description?: string; recommended_actions?: string[] };
  // #128. The firing rule's own instruction, if it carries one. More
  // specific than the metric knowledge above, since a warn and a
  // critical on one metric usually want different answers, so it is
  // rendered ahead of it. Static operator-authored text: nothing here
  // is executed, and no live value is ever interpolated into it.
  action?: string;
  action_command?: string;
  is_test?: boolean;                  // Phase 5 — Test Fire flag, prefixes subject with [TEST]
}

export interface EmailChannelConfig {
  apiKey: string;
  sender: string;                     // e.g. "Captain <captain@example.com>"
  recipients: string[];
}

export interface EmailSendResult {
  ok: boolean;
  messageId?: string;
  error?: string;
}

const SEV_LABEL: Record<AlertEmailContext['severity'], string> = {
  warn:     'WARN',
  critical: 'CRITICAL',
  page:     'PAGE',
};

function fmtThreshold(ctx: AlertEmailContext): string {
  if (ctx.threshold_op == null || ctx.threshold_value == null) return '—';
  return `${escapeHtml(ctx.threshold_op)} ${escapeHtml(ctx.threshold_value)}`;
}

function fmtDuration(s: number | null): string {
  if (s == null) return '—';
  if (s < 60)   return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

export function buildSubject(ctx: AlertEmailContext): string {
  const verb = ctx.state === 'firing' ? '' : ' resolved';
  const prefix = ctx.is_test ? '[TEST] ' : '';
  return `${prefix}[${SEV_LABEL[ctx.severity]}] ${ctx.metric}${verb} on ${ctx.identity.name}`;
}

// The identity rows as a labelled box under the metric name. The one value
// that can be a link is only made one when it is an http(s) address: the
// builder already guarantees that, and a renderer that took its word would
// turn a future mistake there into a clickable script in someone's inbox.
function identityBlock(ctx: AlertEmailContext): string {
  const rows = identityRows(ctx.identity).map(r => {
    const value = r.href && /^https?:\/\//i.test(r.href)
      ? `<a href="${escapeHtml(r.href)}" style="color:#0969da;word-break:break-all;">${escapeHtml(r.value)}</a>`
      : escapeHtml(r.value);
    return `<tr><td style="color:#656d76;width:140px;"><strong>${escapeHtml(r.label)}</strong></td><td>${value}</td></tr>`;
  }).join('\n      ');
  return `<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;width:100%;margin:8px 0 16px;background:#f6f8fa;border-radius:6px;">
      ${rows}
    </table>`;
}

export function buildHtml(ctx: AlertEmailContext): string {
  const isFiring = ctx.state === 'firing';
  const sevLabel = SEV_LABEL[ctx.severity];
  const sevColor =
    ctx.severity === 'page'     ? '#cf222e' :
    ctx.severity === 'critical' ? '#cf222e' :
                                  '#bf8700';
  const stateColor = isFiring ? sevColor : '#1a7f37';
  const stateLabel = isFiring ? 'FIRING' : 'RESOLVED';

  const valueLine = ctx.value != null
    ? `<tr><td><strong>${isFiring ? 'Current' : 'Final'} value</strong></td><td>${escapeHtml(ctx.value)}</td></tr>`
    : '';

  const durationLine = ctx.duration_s != null
    ? `<tr><td><strong>${isFiring ? 'Held for' : 'Was firing'}</strong></td><td>${fmtDuration(ctx.duration_s)}</td></tr>`
    : '';

  // #128. The rule's own action, ahead of the metric library, and gated on
  // firing for the same reason that block is: a resolved notification is an
  // all-clear, and "treat the node as down" under one would be an
  // instruction about something that already recovered. Test Fire sends
  // state 'firing', so a test delivery still carries it and an operator
  // meets the block before the first real page rather than at 3am.
  const ruleActionBlock = isFiring && (ctx.action || ctx.action_command)
    ? `<div style="margin-top:18px;padding:12px;background:#f6f8fa;border-left:3px solid ${sevColor};border-radius:4px;">` +
      (ctx.action ? `<p style="margin:0 0 4px;font-weight:600;">What to do</p><p style="margin:0;color:#555;">${escapeHtml(ctx.action)}</p>` : '') +
      (ctx.action_command
        ? `<p style="margin:8px 0 0;"><code style="display:block;padding:6px 8px;background:#eaeef2;border-radius:3px;font-size:13px;word-break:break-all;">${escapeHtml(ctx.action_command)}</code></p>`
        : '') +
      `</div>`
    : '';

  let knowledgeBlock = '';
  if (isFiring && ctx.knowledge && (ctx.knowledge.description || (ctx.knowledge.recommended_actions || []).length > 0)) {
    const desc = ctx.knowledge.description ? `<p style="margin:8px 0;color:#555;">${escapeHtml(ctx.knowledge.description)}</p>` : '';
    const actions = (ctx.knowledge.recommended_actions || []).slice(0, 3);
    const actionList = actions.length > 0
      ? `<p style="margin:4px 0 0;font-weight:600;">First checks:</p><ul style="margin:4px 0 0 0;padding-left:20px;">` +
        actions.map(a => `<li style="margin:2px 0;">${escapeHtml(a)}</li>`).join('') +
        `</ul>`
      : '';
    knowledgeBlock = `<div style="margin-top:18px;padding:12px;background:#f6f8fa;border-left:3px solid ${sevColor};border-radius:4px;">${desc}${actionList}</div>`;
  }

  const testBanner = ctx.is_test
    ? `<div style="margin-bottom:16px;padding:10px 14px;background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;color:#7d4e00;font-weight:600;">
         This is a Test Fire email from the Aperire dashboard. No real alert is firing.
       </div>`
    : '';

  return `<!doctype html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1f2328;background:#fff;margin:0;padding:24px;">
  <div style="max-width:560px;margin:0 auto;">
    ${testBanner}
    <div style="display:inline-block;padding:4px 10px;border-radius:12px;background:${stateColor};color:#fff;font-weight:700;font-size:12px;letter-spacing:0.06em;">
      ${sevLabel} · ${stateLabel}
    </div>
    <h2 style="margin:14px 0 0;font-size:20px;">${escapeHtml(ctx.metric)}</h2>
    ${identityBlock(ctx)}
    <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;width:100%;">
      <tr><td style="color:#656d76;width:140px;"><strong>Triggered</strong></td><td>${escapeHtml(ctx.triggered_iso)}</td></tr>
      <tr><td style="color:#656d76;"><strong>Threshold</strong></td><td>${fmtThreshold(ctx)}</td></tr>
      ${valueLine}
      ${durationLine}
      <tr><td style="color:#656d76;"><strong>Dedup key</strong></td><td style="font-family:monospace;font-size:12px;color:#656d76;">${escapeHtml(ctx.dedup_key)}</td></tr>
    </table>
    ${ruleActionBlock}
    ${knowledgeBlock}
    <hr style="border:0;border-top:1px solid #d1d9e0;margin:24px 0 12px;">
    <p style="color:#8b949e;font-size:12px;margin:0;">Aperire · XRPL validator dashboard</p>
  </div>
</body></html>`;
}

/**
 * The plain-text part, #1243. The same facts as buildHtml in the same order,
 * one `Label: value` per line, the identity rows from the same
 * identityRows() every other channel prints.
 *
 * Without it Resend derives a text part by stripping the HTML, and a table
 * strips to cells that touch: `Nodevalidator-1 (validator) Hostsrv1`.
 * That is what a phone preview and a text-only reader show. Nothing here is
 * escaped, because nothing here is parsed as markup.
 */
export function buildText(ctx: AlertEmailContext): string {
  const isFiring = ctx.state === 'firing';
  const lines: string[] = [`${SEV_LABEL[ctx.severity]} · ${isFiring ? 'FIRING' : 'RESOLVED'}`, ctx.metric, ''];
  if (ctx.is_test) lines.push('This is a Test Fire email from the Aperire dashboard. No real alert is firing.', '');
  for (const r of identityRows(ctx.identity)) lines.push(`${r.label}: ${r.value}`);
  lines.push('');
  lines.push(`Triggered: ${ctx.triggered_iso}`);
  lines.push(`Threshold: ${ctx.threshold_op == null || ctx.threshold_value == null ? 'none' : `${ctx.threshold_op} ${ctx.threshold_value}`}`);
  if (ctx.value != null) lines.push(`${isFiring ? 'Current' : 'Final'} value: ${ctx.value}`);
  if (ctx.duration_s != null) lines.push(`${isFiring ? 'Held for' : 'Was firing'}: ${fmtDuration(ctx.duration_s)}`);
  lines.push(`Dedup key: ${ctx.dedup_key}`);
  if (isFiring && (ctx.action || ctx.action_command)) {
    lines.push('');
    if (ctx.action) lines.push(`What to do: ${ctx.action}`);
    if (ctx.action_command) lines.push(`  ${ctx.action_command}`);
  }
  const actions = (ctx.knowledge?.recommended_actions || []).slice(0, 3);
  if (isFiring && (ctx.knowledge?.description || actions.length > 0)) {
    lines.push('');
    if (ctx.knowledge?.description) lines.push(ctx.knowledge.description);
    if (actions.length > 0) lines.push('First checks:', ...actions.map(a => `- ${a}`));
  }
  lines.push('', 'Aperire · XRPL validator dashboard');
  return lines.join('\n');
}

/**
 * LOW-08. Every value the template interpolates goes through here, including
 * the numeric ones. They are typed `number | null`, but the type is a claim
 * about the code that fills them, not about what SQLite hands back: the column
 * is not typed, and a rule file is operator-authored text that reaches the
 * same fields. The cost of escaping a number that was always a number is
 * nothing; the cost of trusting the type on the one row where it is wrong is
 * markup in someone's inbox.
 */
function escapeHtml(s: string | number): string {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]!));
}

let resendClient: Resend | null = null;
function getClient(apiKey: string): Resend {
  if (!resendClient) resendClient = new Resend(apiKey);
  return resendClient;
}

/**
 * Send a pre-rendered digest email through the same Resend client.
 * Caller (Phase 6 cron) builds the HTML separately because digest
 * content has a different shape than alert events, and passes the
 * plain-text part built from the same facts (lib/mail-text.ts). Returns the same
 * result type so the digest_runs writer can record success/failure
 * uniformly.
 */
export async function sendDigestEmail(
  cfg: EmailChannelConfig,
  subject: string,
  html: string,
  text?: string,
): Promise<EmailSendResult> {
  if (!cfg.apiKey) return { ok: false, error: 'no API key' };
  if (!cfg.sender) return { ok: false, error: 'no sender configured' };
  if (cfg.recipients.length === 0) return { ok: false, error: 'no recipients' };

  try {
    const client = getClient(cfg.apiKey);
    const res = await client.emails.send({
      from: cfg.sender,
      to: cfg.recipients,
      subject,
      html,
      // #1274: without a text part Resend strips the HTML, and a table strips
      // to cells that touch. Callers pass one built from the same facts.
      ...(text === undefined ? {} : { text }),
    });
    if (res.error) return { ok: false, error: res.error.message ?? String(res.error) };
    return { ok: true, messageId: res.data?.id };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

/**
 * Send an alert email through Resend.
 *
 * Returns a result object — never throws. Callers (the state-machine
 * evaluator) use the result to patch `alerts_history.delivery` for the
 * row; failures are recorded but never block other channels or cause
 * the metric write to error.
 */
export async function sendAlertEmail(
  cfg: EmailChannelConfig,
  ctx: AlertEmailContext,
): Promise<EmailSendResult> {
  if (!cfg.apiKey) return { ok: false, error: 'no API key' };
  if (!cfg.sender) return { ok: false, error: 'no sender configured' };
  if (cfg.recipients.length === 0) return { ok: false, error: 'no recipients' };

  try {
    const subject = buildSubject(ctx);
    const html    = buildHtml(ctx);
    const text    = buildText(ctx);
    const client  = getClient(cfg.apiKey);
    const res = await client.emails.send({
      from: cfg.sender,
      to: cfg.recipients,
      subject,
      html,
      text,
    });
    if (res.error) return { ok: false, error: res.error.message ?? String(res.error) };
    return { ok: true, messageId: res.data?.id };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}
