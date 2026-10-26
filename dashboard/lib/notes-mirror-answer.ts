/**
 * What GET /api/advisor-notes-mirror answers, with each row stamped for
 * whether its node is still in the fleet registry (#1191).
 *
 * The mirror is upsert-only (ADR 0021): a node that is renamed or revoked
 * leaves its rows and its poll state behind, and the poller rightly stops
 * asking it. The page then drew the last failed poll as if it were current,
 * "poll failed, peer_unreachable, last confirmed 13d ago", for a node that
 * is not unreachable but gone, and a renamed node's notes twice. The rows stay
 * (a mirror that deleted on a roster change could lose what a node recorded
 * while it existed); what changes is that each carries `in_fleet`, so the page
 * can say a row is from a node no longer in the fleet and draw no poll
 * failure for it.
 *
 * A second fact rides beside it, `polled`: whether this dashboard is polling
 * that node now. A node can be in the registry and not polled (its Advisor
 * address was removed with detach-advisor, or the registry is held), and its
 * last attempt is as stale as a node that left: the poller is not asking it
 * either. `in_fleet` is about the registry, `polled` about the poller, and the
 * page draws a failure line only for a node that is both.
 *
 * Kept out of db.ts and server.ts so the walk that stands in for the route
 * builds its answer with this same function over raw rows, instead of a stub
 * that wrote its own `in_fleet`. It imports nothing: a walk loading it opens
 * no database.
 */

/** The labels the registry carries, or null when it could not be read. */
export type RegistryLabels = ReadonlySet<string> | null;

/** One row of the mirror, as the queries return it. */
export interface MirrorNodeRow { node: string }

export interface NotesMirrorRaw<M extends MirrorNodeRow, S extends MirrorNodeRow, I extends MirrorNodeRow> {
  memory: M[];
  memory_state: S[];
  inbox: I[];
}

export interface NotesMirrorContext {
  /** The key this host's own rows are stored under ('@local'). */
  localNode: string;
  /** What this host is called in the registry, for the label shown. */
  selfLabel: string | null;
  /** Null when the registry file could not be read: membership is then
   *  unknown, and unknown is not "gone". */
  registry: RegistryLabels;
  /** The nodes the notes mirror is polling right now (its target set), or null
   *  when that is not known. Unknown is not "not polled". */
  polled: ReadonlySet<string> | null;
}

/**
 * Whether a mirror key names a node the registry still carries. This host's
 * own rows are always in. With no readable registry nothing is called gone: a
 * parse error on fleet.yaml must not make every node look like it left, and
 * the answer is recomputed on every request, so it corrects itself as soon as
 * the registry reads.
 */
export function nodeInFleet(node: string, ctx: Pick<NotesMirrorContext, 'localNode' | 'registry'>): boolean {
  if (node === ctx.localNode) return true;
  if (ctx.registry === null) return true;
  return ctx.registry.has(node);
}

/** Whether the poller is asking this node now. This host's own rows, and any
 *  answer with no known target set, read as polled. */
export function nodePolled(node: string, ctx: Pick<NotesMirrorContext, 'localNode' | 'polled'>): boolean {
  if (node === ctx.localNode) return true;
  if (ctx.polled === null) return true;
  return ctx.polled.has(node);
}

export function notesMirrorAnswer<M extends MirrorNodeRow, S extends MirrorNodeRow, I extends MirrorNodeRow>(
  raw: NotesMirrorRaw<M, S, I>,
  ctx: NotesMirrorContext,
): {
    memory: Array<M & { label: string; in_fleet: boolean; polled: boolean }>;
    memory_state: Array<S & { label: string; in_fleet: boolean; polled: boolean }>;
    inbox: Array<I & { label: string; in_fleet: boolean; polled: boolean }>;
  } {
  // `node` stays the raw key, unresolved: the promote route looks the row up
  // by it, and a label sent back as `node` would 404 that lookup for every
  // self-row. `label` is the name a person reads.
  const stamp = <T extends MirrorNodeRow>(row: T) => ({
    ...row,
    label: row.node === ctx.localNode ? (ctx.selfLabel ?? 'this host') : row.node,
    in_fleet: nodeInFleet(row.node, ctx),
    polled: nodePolled(row.node, ctx),
  });
  return {
    memory: raw.memory.map(stamp),
    memory_state: raw.memory_state.map(stamp),
    inbox: raw.inbox.map(stamp),
  };
}
