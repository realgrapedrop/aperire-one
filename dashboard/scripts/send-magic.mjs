#!/usr/bin/env node
// Aperire — send a magic-link enrollment URL to one operator via the
// email channel configured in channels.yaml. Invoked by the SSH CLI
// (scripts/aperire-auth.sh) when authn.yaml has `magic_link.send_via_email: true`.
//
// Usage: send-magic.mjs <to-email> <subject> <url>
//
// Reuses the dashboard's email.ts so we don't reimplement Resend wiring.
// Reads channels.yaml + RESEND_API_KEY from /etc/aperire/aperire.env or
// the process env. Exits 0 on send-ok, non-zero on any failure (CLI then
// prints a fallback message and the URL itself).

import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

// This file sits at dashboard/scripts/send-magic.mjs — both the email
// module and the config dir live one level up.
import { sendDigestEmail } from '../email.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CHANNELS_PATH = resolve(HERE, '..', 'config', 'channels.yaml');

async function loadEmailChannel() {
  let text;
  try { text = await readFile(CHANNELS_PATH, 'utf8'); }
  catch (err) { throw new Error(`channels.yaml not readable: ${err.message}`, { cause: err }); }
  const doc = yaml.load(text) || {};
  const e = doc?.channels?.email;
  if (!e || e.provider !== 'resend') {
    throw new Error('email channel not configured (or provider is not resend)');
  }
  const keyEnv = e.api_key_env || 'RESEND_API_KEY';
  const apiKey = process.env[keyEnv];
  if (!apiKey) throw new Error(`${keyEnv} not set in env`);
  const sender = e.sender;
  if (!sender) throw new Error('email channel has no sender configured');
  return { apiKey, sender, recipients: [] };  // recipients filled per-call
}

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function buildHtml(url) {
  return `<!doctype html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1f2328;background:#fff;margin:0;padding:24px;">
  <div style="max-width:520px;margin:0 auto;">
    <h2 style="margin:0 0 16px;font-size:20px;">Enroll your Aperire passkey</h2>
    <p style="margin:0 0 16px;color:#555;line-height:1.5;">
      Click the link below to enroll a passkey for the Aperire dashboard.
      Your browser will prompt for biometric verification (Touch ID, Face ID,
      Windows Hello, or a security key) and store the credential locally.
    </p>
    <p style="margin:24px 0;text-align:center;">
      <a href="${escHtml(url)}" style="display:inline-block;padding:12px 24px;background:#0969da;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">
        Enroll passkey
      </a>
    </p>
    <p style="margin:16px 0 0;color:#656d76;font-size:13px;line-height:1.5;">
      Or paste this URL into your browser:<br>
      <code style="display:inline-block;margin-top:6px;padding:6px 8px;background:#f6f8fa;border-radius:3px;font-size:12px;word-break:break-all;">${escHtml(url)}</code>
    </p>
    <hr style="border:0;border-top:1px solid #d1d9e0;margin:24px 0 12px;">
    <p style="margin:0;color:#8b949e;font-size:12px;">
      Single-use link. If you did not request this, ignore this email — the URL becomes
      invalid as soon as it's used or after its expiry window.
    </p>
  </div>
</body></html>`;
}

async function main() {
  const [to, subject, url] = process.argv.slice(2);
  if (!to || !subject || !url) {
    console.error('usage: auth-send-magic.mjs <to-email> <subject> <url>');
    process.exit(2);
  }
  const cfg = await loadEmailChannel();
  cfg.recipients = [to];
  const html = buildHtml(url);
  const result = await sendDigestEmail(cfg, subject, html);
  if (!result.ok) {
    console.error('email send failed:', result.error);
    process.exit(1);
  }
  console.log(result.messageId || 'sent');
  process.exit(0);
}

main().catch(err => {
  console.error('fatal:', err.message);
  process.exit(1);
});
