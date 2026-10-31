// How authn.yaml's two comma-separated keys, public_url and rp_id, are read.
//
// Both are documented as ONE string, comma-separated for several values
// (the header of auth.ts, the env-var table in docs/AUTH-GUIDE.md). The
// natural typo is a YAML list, and auth.ts met it as
// `raw.split is not a function` from whichever caller read the key first: the
// WebAuthn origin set, the Settings page, the add-node pairing command, the
// alert's Link row (#1231).
//
// A list is joined with commas, not refused. `aperire-auth` already reads it
// that way: its value reader ends in `String(v)`, which turns a list into
// `a,b`, so a refusal here would be a stricter reading than the one the same
// file gets from the CLI. (The installer reads the key with a
// same-line `sed`, so for it a list reads as unset. That is why the warning
// below tells the operator to write one string. The pairing script reads a
// list as well, #1275.) And a refusal inside
// loadAuthnConfig lands in its catch, which answers an empty config with a
// warning: rp_id and public_url fall back to the localhost defaults and a
// public deploy cannot sign in. A joined list is the line the operator meant.
//
// Pure on purpose, no database and no module state, so the rows that pin it
// do not need a process of their own.

import { pairDashboardUrl } from '../types/fleet-link-contract.js';

/**
 * One authn.yaml value as the one comma-separated string it is documented to
 * be. A string is returned as it came. A list of strings is joined with
 * commas, and `warn` says so once. Anything else (a mapping, a number) is
 * treated as unset, and `warn` names the key, because a silent default here
 * would be the localhost origin.
 */
export function asCommaString(key: string, v: unknown, warn: (msg: string) => void): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) {
    warn(`${key} is a YAML list, read as the one comma-separated line it takes. Write it as one string, comma-separated: the installer reads only that form`);
    return v.filter((x): x is string => typeof x === 'string').map(s => s.trim()).filter(Boolean).join(',');
  }
  warn(`${key} must be one string, comma-separated for several; ignoring it`);
  return undefined;
}

/**
 * The address this dashboard gives out as its own, out of a comma-separated
 * public_url: the first entry another machine can open, #1233.
 *
 * The first entry alone was wrong when it was `http://localhost:7800` and a
 * later one was public: the alert's Link row and the add-node pairing command
 * got nothing, with a usable address configured. "Can open" is
 * pairDashboardUrl's question, the one the alert and the registry already ask.
 *
 * When no entry qualifies, the first entry is still the answer: a box that
 * has only its localhost default keeps showing it, and every consumer already
 * says what a local-only address means (the pair command prints a
 * placeholder, the alert says no dashboard address is set). Trailing slashes
 * come off, as they do for the origin set.
 */
export function firstUsableUrl(raw: string | undefined): string | null {
  const entries = (raw ?? '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
  return entries.find(e => pairDashboardUrl(e) !== null) ?? entries[0] ?? null;
}
