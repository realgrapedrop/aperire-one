/**
 * "Does that node still agree with this dashboard about who may approve?"
 *
 * The dashboard owns the answer to "who is an admin". Every advisord holds a
 * verified REPLICA of that set, and a replica that has silently fallen behind
 * is worse than no replica: a passkey enrolled since the last push is refused
 * at the moment of approval with an error that reads like the passkey is
 * broken, and an operator whose admin role was revoked keeps approving on that
 * node until someone remembers to push. Both are invisible until they bite.
 *
 * This is the comparison, factored out of server.ts because it now runs on two
 * paths that must not disagree: the LOCAL advisor status, and a PEER's status
 * proxied through /api/node/:label/advisor/status. The peer path was the gap —
 * a node could be behind for days and the tab said nothing, which is how
 * 2026-08-19's ceremony failed on a node nobody had pushed to.
 *
 * The serial question, settled: there is no separate serial to derive. The
 * bundle's `serial` is credentialDigest() over the admin credentials, and the
 * store's `fingerprint` is the Go twin of that same digest over the same
 * fields. So the fingerprint a node reports IS the serial of the bundle it
 * accepted, and `trustFingerprint()` on this side IS the serial the next push
 * would carry. Comparing them needs no new derivation and no new fixture —
 * `trust-sync.test.ts` pins that equality with a vector shared with the Go
 * side rather than restating the digest here.
 */

/** The half of advisord's /v1/status this module reads. Every field optional:
 *  an advisord older than the field reports nothing, and "not reported" is a
 *  different fact from "reported as empty". */
export interface AdvisorTrustBlock {
  fingerprint?: string;
  credentials?: number;
  updated_at?: string;
  /** The receipt, present only on a node that has accepted a pushed bundle. */
  bundle?: { serial?: string; issuer?: string; accepted_at?: string };
}

export interface TrustSync {
  /** True only when the node affirmatively reported a set that matches. An
   *  advisord that reported nothing is NOT in sync — it is unknown, and this
   *  says so by being false with a null count rather than by guessing.
   *
   *  NULL is a third answer, and it is not "unknown": it is "not this
   *  dashboard's question" (#172). See managed_by. */
  in_sync: boolean | null;
  dashboard_credentials: number;
  advisor_credentials: number | null;
  advisor_updated_at: string | null;
  /** The serial of the bundle that node last ACCEPTED, and when. Null on a
   *  node that has never been pushed to, or one running a build that predates
   *  the receipt. Distinct from the fingerprint comparison above: the
   *  fingerprint also moves for a local advisor-sync or a hand edit, so a node
   *  can be in sync with no bundle receipt at all (that is a co-located
   *  install) and out of sync with a recent one. */
  bundle_serial: string | null;
  bundle_accepted_at: string | null;
  /**
   * WHO owns this node's trust store, when it is not this dashboard.
   *
   * #172. A fleet node's own dashboard was comparing the store an AGGREGATOR
   * installed against its own local accounts, and calling the difference
   * drift: an amber banner on every node in the fleet, on a node with one
   * local operator and five pushed admin keys, with a remedy that had to be
   * run on a machine the operator was not looking at. The two sets were never
   * meant to match, so the comparison had no true answer to give.
   *
   * When this node's advisord reports a bundle receipt AND the view is its
   * own (not a peer's), the honest answer is that this store is managed from
   * elsewhere: in_sync is null, there is no remedy here, and this names the
   * issuer that pushed it. Staleness is still judged, on the machine that can
   * judge it: Settings on the aggregator, bundle serial against current.
   *
   * Null on every other row, where in_sync is a real boolean.
   */
  managed_by: string | null;
  /**
   * True when managed_by is null because THIS dashboard is the one that
   * pushed the bundle its own advisord holds (#178), not because the
   * question does not apply here.
   *
   * A co-located aggregator+advisord pushes to itself the same way it
   * pushes to any other node, same signing key, same issuer_label. Read
   * back on its own status, that bundle looks identical to one an aggregator
   * elsewhere installed, and the plain managed_by sentence ("managed by
   * aggregator") reads as if some other box is in charge of a store this
   * very dashboard just wrote. It is not managed from elsewhere: staleness
   * IS answerable here (this dashboard's own fingerprint against the serial
   * its own advisord accepted) and the remedy IS runnable here (push again).
   * Only true when the host holds the fleet-trust private key itself,
   * see TrustSyncInput.selfIsAggregator.
   */
  self_pushed: boolean;
  /** The exact command to run. Peer-scoped when the node is a peer, because
   *  pushing to every node to fix one is a wider act than the operator asked
   *  for. Null when there is nothing to run HERE (see managed_by): a remedy
   *  an operator cannot run on the machine they are looking at is not a
   *  remedy. */
  remedy: string | null;
  /**
   * WHERE to run it, and this is not cosmetic.
   *
   * `advisor-sync` rebuilds a host's credential store from that host's OWN
   * database. On a fleet node whose store was installed by a pushed bundle,
   * that command replaces the aggregator's admin keys with whatever local
   * accounts that node's dashboard happens to have — `fleet-trust-push`'s own
   * comment calls it out as never a substitute on a fleet node. So a node
   * whose status carries a bundle receipt is told to push from the aggregator
   * instead, and the card says which machine that is. Getting this wrong would
   * have the banner recommend the one command that empties the store it is
   * complaining about.
   */
  remedy_on: 'this_host' | 'aggregator' | null;
}

export interface TrustSyncInput {
  /** advisord's `trust` block, or null/undefined when it reported none. */
  advisorTrust: AdvisorTrustBlock | null | undefined;
  /** This dashboard's own admin set — `trustFingerprint()`. */
  mine: { fingerprint: string; credentials: number };
  /** The fleet label when this is a PEER's status; null for the local one. */
  peerLabel: string | null;
  /**
   * True only for a LOCAL view (peerLabel null) of a host that holds its own
   * fleet-trust private key, the one fact that separates "this dashboard
   * pushed to itself" from "some other aggregator pushed here" (#178).
   * Read `readOwnPrivateKey(FLEET_TRUST_PATH) !== null` at the call site;
   * never the seed itself, only whether one exists. Ignored when peerLabel
   * is set, or when the local advisord reports no bundle at all.
   */
  selfIsAggregator?: boolean;
  /** This host's own fleet label, so the self-push remedy is scoped to this
   *  node the same way a peer's remedy is scoped to that peer. Null or an
   *  unregistered label falls back to the unscoped push (every node,
   *  including this one) rather than a mangled command. */
  selfLabel?: string | null;
}

/**
 * A label is interpolated into a shell command an operator will copy, so it is
 * bounded to the fleet registry's own label alphabet before it goes anywhere
 * near one. fleet-registry.ts already refuses anything else at load, so this
 * can only ever fire on a bug — and on a bug the honest output is the unscoped
 * command, which is correct, not a command with a mangled argument.
 */
const LABEL_RE = /^[a-z0-9-]{1,32}$/;

/** What to call an issuer a node did not name. Prose, not a label, and the
 *  only value of managed_by that is not one: the card renders it into a
 *  sentence, and "managed by another dashboard" is true where a made-up
 *  label would not be. */
const UNNAMED_ISSUER = 'another dashboard';

// The command as it runs on EVERY install: the in-tree script, from the
// repo root. A bare `aperire-auth` is only on PATH where the optional CLI
// installer ran, and a remedy the operator has to translate before it works
// is not a remedy (the lab aggregator, 2026-08-20).
function pushCommand(label: string | null | undefined): string {
  return label && LABEL_RE.test(label)
    ? `bash scripts/aperire-auth.sh fleet-trust-push --node ${label}`
    : 'bash scripts/aperire-auth.sh fleet-trust-push';
}

export function trustSyncRemedy(
  peerLabel: string | null,
): { remedy: string; remedy_on: 'this_host' } {
  // A peer: this host IS the aggregator, and the push is scoped to the node
  // the operator is looking at.
  if (peerLabel) return { remedy: pushCommand(peerLabel), remedy_on: 'this_host' };
  // The local advisord on a host that syncs from its own database — a
  // co-located install, and the original case.
  //
  // There used to be a third branch here, for a local advisord whose store an
  // ISSUER installed: it returned the aggregator's push command with
  // remedy_on 'aggregator'. It is gone because buildTrustSync no longer asks
  // that question (#172): a node whose store is managed from elsewhere is not
  // told to fix it, because there is nothing to fix on the machine the
  // operator is looking at, and a remedy for another box is a remedy nobody
  // runs.
  return { remedy: 'bash scripts/aperire-auth.sh advisor-sync', remedy_on: 'this_host' };
}

export function buildTrustSync(input: TrustSyncInput): TrustSync {
  const t = input.advisorTrust ?? null;
  const theirs = typeof t?.fingerprint === 'string' ? t.fingerprint : null;
  const count = typeof t?.credentials === 'number' ? t.credentials : null;
  const serial = typeof t?.bundle?.serial === 'string' ? t.bundle.serial : null;
  const issuer = typeof t?.bundle?.issuer === 'string' ? t.bundle.issuer : null;
  const base = {
    dashboard_credentials: input.mine.credentials,
    advisor_credentials: count,
    advisor_updated_at: typeof t?.updated_at === 'string' ? t.updated_at : null,
    bundle_serial: serial,
    bundle_accepted_at: typeof t?.bundle?.accepted_at === 'string' ? t.bundle.accepted_at : null,
  };
  // #172. This node's own view of a store an aggregator installed. The
  // comparison below would be this dashboard's local accounts against
  // somebody else's admin set, which were never meant to match: there is no
  // true answer, so none is given.
  //
  // #178's carve-out: unless THIS dashboard is the one holding the
  // fleet-trust private key, in which case there is no "somebody else",
  // the only key that could have produced this bundle is the one sitting in
  // this host's own fleet-trust.yaml, so it pushed to itself. The comparison
  // has a true answer here (this dashboard's fingerprint against the serial
  // its own advisord accepted) and the remedy is runnable here (push again).
  if (serial !== null && !input.peerLabel) {
    if (input.selfIsAggregator) {
      return {
        ...base,
        in_sync: theirs !== null && theirs === input.mine.fingerprint,
        managed_by: null,
        self_pushed: true,
        remedy: pushCommand(input.selfLabel ?? null),
        remedy_on: 'this_host',
      };
    }
    // Never null in this branch, and that is a guard rather than a nicety.
    // The card keys on managed_by being set; a null here would fall through
    // to the stale banner, whose own fallback is `advisor-sync` — the one
    // command that empties the store it is complaining about. advisord
    // refuses a bundle that names no issuer, so the only way to reach this
    // is a hand-edited receipt, which is exactly the input a guard is for.
    return {
      ...base, in_sync: null, managed_by: issuer ?? UNNAMED_ISSUER, self_pushed: false,
      remedy: null, remedy_on: null,
    };
  }
  return {
    ...base,
    in_sync: theirs !== null && theirs === input.mine.fingerprint,
    managed_by: null,
    self_pushed: false,
    ...trustSyncRemedy(input.peerLabel),
  };
}

/**
 * Annotate a status document in place-ish (returns a new object) with the
 * comparison. Returns the document untouched when it is not an object — a
 * status body this cannot parse is the Advisor's business, not ours, and
 * turning a readable upstream response into a dashboard error would be the
 * worse failure.
 */
export function annotateTrustSync(doc: unknown, input: Omit<TrustSyncInput, 'advisorTrust'>): unknown {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return doc;
  const d = doc as Record<string, unknown>;
  const advisorTrust = (d.trust ?? null) as AdvisorTrustBlock | null;
  return { ...d, trust_sync: buildTrustSync({ ...input, advisorTrust }) };
}
