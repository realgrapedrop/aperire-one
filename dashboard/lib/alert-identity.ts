/**
 * Which node an alert is about (#1229).
 *
 * An alert used to carry the box's hostname once, unlabelled. With several
 * nodes that does not say which one fired, or whether it is a validator or a
 * stock node. One block says it, built once from what the dashboard already
 * reads, and every channel renders the same rows: a new channel is a new
 * formatter over `identityRows`, never a new set of questions.
 *
 * Pure. server.ts gathers the inputs (the node's pairing, fleet registry and
 * server_info) and hands them here, so every branch is testable without a
 * server or a fleet.
 *
 * There is no host address in the block. The dashboard's unit does not allow
 * the netlink socket Node reads the interface list through, so under it the
 * address could never be read, and the hostname already says which machine.
 */
import { pairDashboardUrl } from '../types/fleet-link-contract.js';
import { deriveSelfLabel } from './self-label.js';

export type NodeRole = 'validator' | 'stock node' | 'aggregator';

export interface NodeIdentity {
  /** The name the node's aggregator knows it by, else its fleet label, else the
   *  machine's short name. */
  name: string;
  /** null when this dashboard has not read its node yet. Never guessed. */
  role: NodeRole | null;
  hostname: string;
  /** The node's own public key in full, null until server_info has answered. */
  node_key: string | null;
  /** A dashboard address another machine can open, null when none is set. */
  url: string | null;
}

/**
 * Everything the identity is read from, as plain data. server.ts hands over
 * what it holds and nothing is decided there: which link wins, what counts
 * as a validator, what a node that was never read is called, all live here,
 * where a row can reach them.
 */
export interface NodeSources {
  /** The label in this node's `fleet-link.json`, the name its aggregator
   *  registered it under. Absent on a node that was never paired. On a node it
   *  wins over `fleetLabel`: a `fleet.yaml` self entry is whatever the node
   *  was called before it joined, and can be months stale. */
  pairedLabel?: string | null;
  /** This host's row in the fleet registry, absent on a single-node install.
   *  An aggregator's own name lives here, and wins over any pairing. */
  fleetLabel?: string | null;
  hostname: string;
  /** This dashboard has no local node (a fleet aggregator). */
  aggregator: boolean;
  /** The last `server_info` this dashboard read from its node. Absent until
   *  the first answer: a restart with the node down is exactly then, and
   *  "stock node" would be a made-up answer. */
  serverInfo?: Record<string, unknown>;
  /** Whether a `pubkey_validator` value is a real key. rippled says "none" on
   *  a stock node, and some builds say "". */
  isValidatorKey: (v: unknown) => boolean;
  /** `APERIRE_PUBLIC_URL`, then `public_url` from authn.yaml, then the fleet
   *  row's `dashboard_url`: the first one another machine could open wins. */
  envPublicUrl?: string | null;
  authnPublicUrl?: string | null;
  fleetDashboardUrl?: string | null;
}

export interface IdentityRow {
  label: string;
  value: string;
  /** Set only on an http(s) address, so a renderer may make it a link. */
  href?: string;
}

export function deriveRole(aggregator: boolean, observedValidator: boolean | null): NodeRole | null {
  if (aggregator) return 'aggregator';
  if (observedValidator === null) return null;
  return observedValidator ? 'validator' : 'stock node';
}

/** `n9KmK…6sWW`: five characters, an ellipsis, four. A key too short to cut
 *  comes back whole. */
export function shortNodeKey(key: string): string {
  return key.length > 12 ? `${key.slice(0, 5)}…${key.slice(-4)}` : key;
}

/**
 * A read that may throw, answered with a fallback instead. server.ts reads
 * authn.yaml through this: an alert is sent from the sync metric-write path,
 * and a source that fails must cost its own row, never the alert.
 */
export function safeRead<T>(read: () => T, fallback: T): T {
  try { return read(); } catch { return fallback; }
}

export function buildNodeIdentity(s: NodeSources): NodeIdentity {
  let url: string | null = null;
  for (const c of [s.envPublicUrl, s.authnPublicUrl, s.fleetDashboardUrl]) {
    const ok = pairDashboardUrl(c);
    // The parsed form: an address written with non-ASCII characters has to
    // reach the ntfy `click` header as ASCII, or the whole push is refused.
    if (ok) { url = new URL(ok).href; break; }
  }
  // An aggregator names itself in its own fleet.yaml. A node is named by its
  // pairing, which can be newer than its fleet.yaml entry.
  const paired = String(s.pairedLabel ?? '').trim();
  const fleet = String(s.fleetLabel ?? '').trim();
  const label = s.aggregator ? fleet || paired : paired || fleet;
  const info = s.serverInfo;
  const validatorKey = info?.pubkey_validator;
  const nodeKey = info?.pubkey_node;
  return {
    name: deriveSelfLabel(label, s.hostname) || s.hostname || 'unnamed node',
    role: deriveRole(s.aggregator, info === undefined || validatorKey === undefined ? null : s.isValidatorKey(validatorKey)),
    hostname: s.hostname,
    node_key: typeof nodeKey === 'string' && nodeKey ? nodeKey : null,
    url,
  };
}

/**
 * The labelled rows every channel prints, in this order. Absent facts say so
 * in words: an empty cell would read as "checked, and there is nothing".
 */
export function identityRows(id: NodeIdentity): IdentityRow[] {
  const host = id.hostname || 'unknown';
  return [
    { label: 'Node', value: `${id.name} (${id.role ?? 'role not read yet'})` },
    { label: 'Host', value: host },
    { label: 'Node key', value: id.node_key ? shortNodeKey(id.node_key) : id.role === 'aggregator' ? 'no local node' : 'not read yet' },
    id.url
      ? { label: 'Link', value: id.url, href: id.url }
      : { label: 'Link', value: 'no dashboard address is set' },
  ];
}
