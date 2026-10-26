// What /healthz says about this process, as a pure function so it can be
// tested without booting server.ts (#808).
//
// Three kinds of host answer here, and each is judged by what it is for:
//
//   node        reads a local rippled. ok only while the bridge is open AND a
//               ledger closed in the last 30s. A node with rippled down stays
//               503 on purpose: that is the answer an operator needs.
//   aggregator  runs no node of its own and reads peers (punch #12). ok, as
//               long as the fleet registry says it has peers and a self row.
//   dashboard   the install was told `--role dashboard`: there is no local
//               node, there never will be, and the nodes it shows arrive by
//               relay push or by the fleet registry. ok, with the count of
//               nodes it knows and, at zero, the next step.
//
// The install role comes from APERIRE_INSTALL_ROLE in aperire.env, which
// install-aperire-service.sh writes. Before #808 the only evidence was the
// fleet registry, so a fresh dashboard install with no fleet.yaml yet took
// itself for a node, waited for a rippled on 127.0.0.1:6006 that a dashboard
// host never has, and answered 503 until someone added a node. The
// installer's closing check then failed a correct install.

export type HealthzRole = 'node' | 'aggregator' | 'dashboard';

export interface HealthzInput {
  rippledOk: boolean;
  ledgerOk: boolean;
  /** Fleet peers registered (the poller's input length). */
  peerCount: number;
  /** This host has a self row in the fleet registry. */
  hasSelfNode: boolean;
  /** The install recorded `--role dashboard` and no node URL was set by hand. */
  dashboardHost: boolean;
  /** A relay has pushed a frame to this process since it started. */
  relayFeeding: boolean;
}

export interface HealthzVerdict {
  ok: boolean;
  role: HealthzRole;
  /** null where the question does not apply: this host has no node of its own. */
  rippledConnected: boolean | null;
  /** Only for a dashboard-role host. */
  nodes?: number;
  /** Only for a dashboard-role host that knows no node yet. */
  nextStep?: string;
}

export const ADD_A_NODE_STEP =
  'No node is reporting yet. Add one from Settings & Updates, Add a node.';

/**
 * The install role as the server should read it. Only `dashboard` changes
 * anything today; every other value, and a missing one (a host installed
 * before this was recorded), reads as "no claim" and falls back to the
 * evidence the server always used.
 */
export function installRoleFromEnv(raw: string | undefined): string {
  return (raw ?? '').trim().toLowerCase();
}

/**
 * Whether this process is a dashboard-role host that must not look for a
 * node. An operator who set RIPPLED_URL by hand has pointed this dashboard at
 * a node on purpose, and that node's state is then the thing to judge.
 */
export function isDashboardHost(installRole: string, rippledUrlSetByHand: boolean): boolean {
  return installRole === 'dashboard' && !rippledUrlSetByHand;
}

export function healthzVerdict(i: HealthzInput): HealthzVerdict {
  // Unchanged from punch #12: peers plus a self row and no node of our own.
  const aggregator = !i.rippledOk && !i.ledgerOk && i.peerCount >= 1 && i.hasSelfNode;
  if (aggregator) {
    return { ok: true, role: 'aggregator', rippledConnected: null };
  }
  if (i.dashboardHost) {
    const nodes = Math.max(i.peerCount + (i.hasSelfNode ? 1 : 0), i.relayFeeding ? 1 : 0);
    const v: HealthzVerdict = { ok: true, role: 'dashboard', rippledConnected: null, nodes };
    if (nodes === 0) v.nextStep = ADD_A_NODE_STEP;
    return v;
  }
  return { ok: i.rippledOk && i.ledgerOk, role: 'node', rippledConnected: i.rippledOk };
}
