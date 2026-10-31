#!/usr/bin/env node
// Aperire — send a magic-link enrollment URL to one operator via the
// email channel configured in channels.yaml. Invoked by the SSH CLI
// (scripts/aperire-auth.sh) when authn.yaml has `magic_link.send_via_email: true`.
//
// Usage: send-magic.mjs <to-email> <subject> <url>
//
// Reuses the dashboard's email.ts so we don't reimplement Resend wiring, and
// the enrollment mail's HTML and text parts from lib/mail-text.ts, the ones
// the dashboard's own enrollment sends use (#1354). Reads channels.yaml +
// RESEND_API_KEY from /etc/aperire/aperire.env or the process env.
//
// Run through tsx, the way fleet-pair-dial.mjs is and the dashboard's unit is:
//   node --import tsx scripts/send-magic.mjs ...      (from dashboard/)
// email.ts and lib/ import each other with .js specifiers that name .ts files,
// which tsx resolves and Node's own type stripping does not.
//
// Exits 0 on send-ok, non-zero on any failure (CLI then prints a fallback
// message and the URL itself).

import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

// This file sits at dashboard/scripts/send-magic.mjs. The email module, the
// mail builders and the config dir live one level up.
import { sendDigestEmail } from '../email.js';
import { buildEnrollmentHtml, buildEnrollmentText } from '../lib/mail-text.js';

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

async function main() {
  const [to, subject, url] = process.argv.slice(2);
  if (!to || !subject || !url) {
    console.error('usage: send-magic.mjs <to-email> <subject> <url>');
    process.exit(2);
  }
  const cfg = await loadEmailChannel();
  cfg.recipients = [to];
  const result = await sendDigestEmail(cfg, subject, buildEnrollmentHtml(url), buildEnrollmentText(url));
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
