// The advisor proxy's query-forwarding allow-list, factored out of
// server.ts so the per-path rule can be unit tested directly rather than
// only exercised through a live request.
//
// server.ts rebuilds the forwarded query string from scratch on every
// /api/advisor/* call rather than passing the operator's query through
// unchanged — an allow-list, not a filter, the same discipline
// lib/proxy-policy.ts applies to the rippled admin proxy. Widening it must
// stay PER-PATH: plan-interrogative-loop §9.6 is explicit that a global
// relaxation is the failure this file exists to prevent — "the query
// filter is the failure that would look like 'polling works but returns
// nothing', with a 200 and no error anywhere."
//
// Every other advisor path keeps the target-only rule it always had.
// ask-progress is the one addition: without `id` surviving this rebuild,
// GET /v1/ask/progress answers about nothing, successfully, forever.
//
// ADR 0016 adds two more, on /check and /plan only. `runbook` decides WHICH
// plan those two endpoints answer about, and an absent one means the upgrade
// — so dropping it does not fail, it answers about the wrong runbook, and the
// tab renders the upgrade's verdicts and confirm code under a card titled
// Restart. `intent` is bound INTO the fingerprint, so dropping that one is
// invisible until /v1/approve recomputes the fingerprint and 409s, after the
// operator has already touched their passkey.
//
// Both are exact-value allow-lists rather than shapes. There are two runbooks
// and four intents; enumerating them here means a value this dashboard does
// not know about is refused by the dashboard rather than forwarded for the
// Advisor to refuse.
//
// ADR 0021 build step 1 adds a third, scoped to /api/advisor/ledger alone:
// since_seq, a plain non-negative integer naming the last entry the caller
// already holds. It is a shape check, not an enum, there is no fixed set of
// valid sequence numbers, so it is validated by pattern like target rather
// than looked up in a set like runbook and intent.

const TARGET_RE = /^[0-9]+(\.[0-9]+)*$/;
const ASK_ID_RE = /^[A-Za-z0-9-]{8,64}$/;
const SINCE_SEQ_RE = /^[0-9]{1,19}$/;
// #547. RB-003 (config-change, ADR 0018) and RB-004 (rollback-node, ADR 0019)
// shipped after this set was written, so a request naming either fell through
// this allow-list, lost its `runbook`, and /v1/check answered about its own
// documented default (the upgrade) with a 200. A caller reading that 200
// has no way to tell "here is the upgrade plan you asked for" from "here is
// the upgrade plan because I do not know config-change". Every runbook id
// this dashboard can ask about must be named here, and advisorRunbookError
// below is what stops the NEXT one that ships from repeating this silently:
// an id that reaches a plan path and is not in this set is refused, not
// dropped.
// Exported so a test can compare this set against the Advisor's own runbook
// registry (advisor/internal/runbook/*.go) rather than trusting the two to
// stay in step on their own (see advisor-runbook-allowlist-drift.test.ts).
export const RUNBOOKS: ReadonlySet<string> = new Set([
  'upgrade-xrpld', 'restart-node', 'config-change', 'rollback-node',
  // ADR 0023 (#682). One change to the deployment file, so a node can run
  // an image that carries no entrypoint of its own.
  'normalise-deployment',
]);
const INTENTS: ReadonlySet<string> = new Set([
  'apply-config', 'resource-pressure', 'planned-maintenance', 'operator-judgement',
]);
/** The two paths that answer about a named plan. Nothing else takes either. */
const PLAN_PATHS: ReadonlySet<string> = new Set(['/api/advisor/check', '/api/advisor/plan']);
/** The one path that answers a ledger tail. Nothing else takes since_seq. */
const LEDGER_PATH = '/api/advisor/ledger';
// RB-003's own two parameters (configkeys.go): which setting, and what to set
// it to. `key` is a small, fixed enum, so it is named exactly like `runbook`
// and `intent` rather than shaped; `value`'s band is a function of the key
// (a number, 0/1, or one of a few words), so it is bounded to the widest
// shape any of those bands take and left to the Advisor's own
// ValidateConfigChange to enforce the actual band.
const CONFIG_KEYS: ReadonlySet<string> = new Set([
  'online_delete', 'advisory_delete', 'node_size', 'ledger_history',
]);
const CONFIG_VALUE_RE = /^[A-Za-z0-9]{1,16}$/;
// RB-005's own two (ADR 0023): which single change to the deployment, and
// the account for the one change that takes a value. Named exactly as the
// config keys are, and for the same reason: a normalise plan is about ONE
// change, and dropping it answers about no particular change at all with a
// 200 the caller cannot tell from the answer it asked for.
const DEPLOYMENT_CHANGES: ReadonlySet<string> = new Set([
  'runtime-user', 'config-mount', 'node-args',
]);
// Numeric uid:gid, the one shape the wrapper accepts. A name resolves
// differently inside the container than on the host.
const RUNTIME_USER_RE = /^[0-9]{1,10}:[0-9]{1,10}$/;
// #682's source override. 'build' is the only value a caller may send:
// 'official' is what the Advisor decides from the registry and pins to a
// digest on its own side, so a browser naming it would be a browser
// choosing where an image comes from.
const IMAGE_SOURCES: ReadonlySet<string> = new Set(['build']);

/**
 * Builds the query string to forward upstream for one advisor proxy path,
 * from the operator's own request params. Returns '' when nothing on this
 * path is allow-listed, or when what was supplied does not match the shape
 * that path expects — never a syntactically-invalid but "close enough"
 * value forwarded through.
 */
export function advisorForwardQuery(pathname: string, params: URLSearchParams): string {
  if (pathname === '/api/advisor/ask-progress') {
    const id = params.get('id') ?? '';
    return ASK_ID_RE.test(id) ? `?id=${encodeURIComponent(id)}` : '';
  }
  const out: string[] = [];
  const target = params.get('target') ?? '';
  if (TARGET_RE.test(target)) out.push(`target=${encodeURIComponent(target)}`);
  if (PLAN_PATHS.has(pathname)) {
    const runbook = params.get('runbook') ?? '';
    if (RUNBOOKS.has(runbook)) out.push(`runbook=${encodeURIComponent(runbook)}`);
    const intent = params.get('intent') ?? '';
    if (INTENTS.has(intent)) out.push(`intent=${encodeURIComponent(intent)}`);
    // #547. Named alongside runbook and intent for the same reason: a
    // config-change plan is about one setting and one proposed value, and
    // dropping either silently answers about no particular change at all.
    // The caller reads 200 and has no way to tell that from an answer about
    // the change it actually named.
    const key = params.get('key') ?? '';
    if (CONFIG_KEYS.has(key)) out.push(`key=${encodeURIComponent(key)}`);
    const value = params.get('value') ?? '';
    if (CONFIG_VALUE_RE.test(value)) out.push(`value=${encodeURIComponent(value)}`);
    const change = params.get('change') ?? '';
    if (DEPLOYMENT_CHANGES.has(change)) out.push(`change=${encodeURIComponent(change)}`);
    const user = params.get('user') ?? '';
    if (RUNTIME_USER_RE.test(user)) out.push(`user=${encodeURIComponent(user)}`);
    const source = params.get('source') ?? '';
    if (IMAGE_SOURCES.has(source)) out.push(`source=${encodeURIComponent(source)}`);
  }
  if (pathname === LEDGER_PATH) {
    const sinceSeq = params.get('since_seq') ?? '';
    if (SINCE_SEQ_RE.test(sinceSeq)) out.push(`since_seq=${encodeURIComponent(sinceSeq)}`);
  }
  return out.length ? `?${out.join('&')}` : '';
}

/**
 * Names the reason a plan request must be refused outright, rather than
 * silently answered about a different runbook (or null when the request is
 * fine, including every path this rule does not apply to, and a request that
 * simply named no runbook at all, which is /v1/check's own documented default
 * of the upgrade).
 *
 * #547. Before this, a `runbook` this allow-list did not recognise was
 * dropped by advisorForwardQuery like any other unlisted parameter, and the
 * request went on to the Advisor with none at all. It answered with the
 * upgrade plan and a 200, precisely as if the caller had asked for that. A
 * caller cannot tell "you asked for the upgrade" from "I do not know the
 * runbook you named" without this: an id that reaches a plan path and is not
 * on the allow-list is a caller (or a shipped runbook this file has not
 * learned about yet) that must be told so, in words, rather than handed an
 * answer to a question it did not ask.
 */
export function advisorRunbookError(pathname: string, params: URLSearchParams): string | null {
  if (!PLAN_PATHS.has(pathname)) return null;
  const runbook = params.get('runbook') ?? '';
  if (runbook === '' || RUNBOOKS.has(runbook)) return null;
  return `unknown runbook ${JSON.stringify(runbook)}. This dashboard knows ${Array.from(RUNBOOKS).join(', ')}`;
}
