// Allow-list policy for the rippled admin proxy (MED-12), factored out of
// rippled-admin-proxy.ts so the decision logic can be unit tested directly.

// EXACTLY the read commands dashboard/server.ts issues. Deny-by-default means
// stop / validation_create / validation_seed / connect / ledger_accept /
// can_delete and every other mutating or sensitive admin command is blocked
// without having to enumerate them. KEEP THIS IN SYNC with server.ts — if a new
// rippled command is added there, add it here too or the dashboard will see it
// rejected. (Search server.ts for rippledReq('…') and the subscribe payload.)
export const ALLOWED_COMMANDS = new Set<string>([
  'server_info',
  'peers',
  'fee',
  'consensus_info',
  'feature',              // read form only — the vote form is rejected below
  'manifest',
  'get_counts',
  'validators',
  'validator_list_sites',
  'crawl_shards',
  'subscribe',
]);

// `feature` is dual-purpose: with no arguments (or just a feature id) it reads
// amendment state, but `{command:'feature', feature:'<hash>', vetoed:true}` sets
// this validator's amendment vote. The dashboard only ever calls the read form,
// so reject any `feature` request that carries a `vetoed` field.
export function isMutatingFeatureVote(msg: Record<string, unknown>): boolean {
  return msg.command === 'feature' && Object.prototype.hasOwnProperty.call(msg, 'vetoed');
}

// Decide whether a single client→rippled frame may pass. Returns null when
// allowed, or a short reason string when it must be rejected.
export function rejectReason(raw: string): string | null {
  let msg: Record<string, unknown>;
  try {
    msg = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return 'non-JSON frame';
  }
  const command = typeof msg.command === 'string' ? msg.command : '';
  if (!command) return 'missing command';
  if (!ALLOWED_COMMANDS.has(command)) return `command not permitted: ${command}`;
  if (isMutatingFeatureVote(msg)) return 'feature vote (vetoed) not permitted';
  return null;
}
