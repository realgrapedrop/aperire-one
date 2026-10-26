/**
 * fleet.yaml -> advisor/state/fleet.json.
 *
 * ONE source of truth for fleet topology, and it is the file the operator
 * already edits. Two files holding the same fleet is exactly how a node
 * ended up with a peer row pointing at a host that had not existed for six
 * days — and, worse, at a loopback port that had since become its OWN
 * dashboard, so a "fixed" token path would have fed that node its own swap
 * and agreement labelled as another node's.
 *
 * Direction is one-way and deliberate. fleet.yaml is authored; fleet.json is
 * derived. advisord does not read YAML — advisor/internal/host/fleettrust.go
 * records the standing decision that a binary verifying signatures against a
 * validator's approval trust carries zero external dependencies, and one
 * lookup is not a reason to link a YAML parser into it.
 *
 * WHAT IS GENERATED, AND WHAT IS THE OPERATOR'S:
 *
 *   generated   label, origin (from read_origin), role, expected_pubkey_node
 *   preserved   token_path, transport — carried through from the existing
 *               fleet.json untouched, because those are host-local facts
 *               (which token file this host can read, which tunnel is
 *               load-bearing) that the shared fleet.yaml cannot know.
 *               The self block is host-local in the same way: which row is
 *               THIS host is the operator's own answer, given once with
 *               --self-label, and a later run without that flag keeps it.
 *
 * A peer that is new to fleet.json has no token_path to preserve, and this
 * module will NOT invent one — the row is reported as needing a token path
 * and left out, because a registry row with a guessed credential path is a
 * read that fails at the worst moment, or worse, succeeds against the wrong
 * file. Naming what was skipped is the whole point: fail closed and VISIBLE.
 *
 * This module is pure — it takes text and an existing registry and returns
 * the bytes to write. Writing them (owner, group, mode 0600, atomic
 * replace) belongs to the installer script that has the privileges for it.
 */
import { parseFleetYaml, ROLES, type FleetNodeConfig, type FleetRole } from './fleet-registry.js';

/** One row of advisord's own registry — advisor/internal/fleet's Peer,
 *  exactly. Any key not in this shape fails advisord's DisallowUnknownFields
 *  load, so this type is a contract with that parser and not a convenience. */
export interface AdvisorPeerRow {
  label: string;
  origin: string;
  token_path: string;
  transport?: string;
  role?: FleetRole;
  expected_pubkey_node?: string;
}

/** advisord's self block — what THIS host is. */
export interface AdvisorSelf {
  label?: string;
  role?: FleetRole;
}

/** The object form of advisor/state/fleet.json. */
export interface AdvisorRegistryFile {
  self?: AdvisorSelf;
  peers: AdvisorPeerRow[];
}

export interface GenerateInput {
  /** fleet.yaml's text — the source of truth. */
  fleetYaml: string;
  /** advisor/state/fleet.json's current text, or '' when there is none. */
  existingJson: string;
  /** Which fleet.yaml row is THIS host. Never inferred: a generator guessing
   *  which row is the local one is the same class of mistake as an Advisor
   *  guessing what kind of host it is on. Omit it and the self block already
   *  in `existingJson` is kept as it stands; with none there, none is
   *  written. */
  selfLabel?: string;
}

export interface GenerateResult {
  /** The file to write, or null when nothing may be written safely. */
  registry: AdvisorRegistryFile | null;
  /** The one reason nothing may be written. */
  error: string | null;
  /** Rows in fleet.yaml that could not be carried into fleet.json, each
   *  with the reason. Never silent, never a partial guess. */
  skipped: { label: string; reason: string }[];
  /** Plain-language notes for the operator — what changed, what stayed. */
  notes: string[];
}

/** Reads the current fleet.json in EITHER accepted shape (a legacy array,
 *  or the object form), mirroring advisord's own version-tolerant Load. A
 *  half-upgraded host must be readable here for the same reason it must be
 *  loadable there: the binary and the config do not land in one step. */
export function parseExistingRegistry(text: string): { file: AdvisorRegistryFile; error: string | null } {
  const trimmed = text.trim();
  if (trimmed === '') return { file: { peers: [] }, error: null };
  let doc: unknown;
  try {
    doc = JSON.parse(trimmed);
  } catch (err) {
    return { file: { peers: [] }, error: `existing fleet.json is not valid JSON: ${(err as Error).message}` };
  }
  if (Array.isArray(doc)) return { file: { peers: doc as AdvisorPeerRow[] }, error: null };
  if (doc !== null && typeof doc === 'object') {
    const obj = doc as Record<string, unknown>;
    const peers = obj.peers === undefined ? [] : obj.peers;
    if (!Array.isArray(peers)) {
      return { file: { peers: [] }, error: 'existing fleet.json has a "peers" that is not a list' };
    }
    const self = obj.self as AdvisorSelf | undefined;
    return { file: { ...(self ? { self } : {}), peers: peers as AdvisorPeerRow[] }, error: null };
  }
  return { file: { peers: [] }, error: 'existing fleet.json is neither a peer array nor a registry object' };
}

/** The label and role of a self block already on disk, rebuilt field by
 *  field. parseExistingRegistry mirrors advisord's version-tolerant load and
 *  takes `self` on trust, so whatever is there could be any shape at all.
 *  Spreading it onward would hand advisord's DisallowUnknownFields loader a
 *  key it refuses — and that fails the WHOLE registry closed at the next
 *  restart, which is the silently-emptied fleet this module exists to
 *  prevent. Anything unrecognised is dropped here instead. */
function priorSelfFields(self: unknown): { label: string; role?: FleetRole } {
  if (typeof self !== 'object' || self === null || Array.isArray(self)) return { label: '' };
  const obj = self as Record<string, unknown>;
  const label = typeof obj.label === 'string' ? obj.label : '';
  const role = typeof obj.role === 'string' && (ROLES as readonly string[]).includes(obj.role)
    ? (obj.role as FleetRole)
    : undefined;
  return { label, ...(role ? { role } : {}) };
}

/**
 * Builds advisord's registry from fleet.yaml plus what is already on this
 * host. Never throws: any failure returns `registry: null` with one reason,
 * so the caller writes nothing and says why — the same fail-closed shape
 * both registries' own parsers use.
 */
export function generateAdvisorRegistry(input: GenerateInput): GenerateResult {
  const parsed = parseFleetYaml(input.fleetYaml);
  if (parsed.error) {
    return { registry: null, error: `fleet.yaml did not parse: ${parsed.error}`, skipped: [], notes: [] };
  }
  const existing = parseExistingRegistry(input.existingJson);
  if (existing.error) {
    return { registry: null, error: existing.error, skipped: [], notes: [] };
  }

  const byLabel = new Map<string, AdvisorPeerRow>();
  for (const row of existing.file.peers) {
    if (row && typeof row.label === 'string') byLabel.set(row.label, row);
  }

  // Which row is THIS host is a host-local fact, the same kind as token_path
  // and transport: the operator answered it once, with --self-label, and a
  // later run that does not repeat the flag must not un-answer it. The
  // documented "remove a peer" flow is a bare re-run, and a host that forgets
  // what it is describes the fleet but not the machine reading it.
  const explicitSelfLabel = input.selfLabel ?? '';
  const priorSelf = priorSelfFields(existing.file.self);
  const selfLabel = explicitSelfLabel || priorSelf.label;
  const selfPreserved = explicitSelfLabel === '' && priorSelf.label !== '';

  // Scoped to an EXPLICIT label on purpose. A preserved label whose row has
  // since left fleet.yaml is handled below, with a note — turning it into a
  // hard error would break a bare re-run that worked yesterday.
  if (explicitSelfLabel && !parsed.nodes.some((n) => n.label === explicitSelfLabel)) {
    return {
      registry: null,
      error: `--self-label "${explicitSelfLabel}" names no row in fleet.yaml — this host must be one of its own fleet's members`,
      skipped: [],
      notes: [],
    };
  }

  const skipped: GenerateResult['skipped'] = [];
  const notes: string[] = [];
  const peers: AdvisorPeerRow[] = [];
  let self: AdvisorSelf | undefined;

  for (const node of parsed.nodes) {
    if (selfLabel && node.label === selfLabel) {
      // This host's own row never becomes a peer of itself. advisord's Load
      // refuses that collision outright, and it is the wrong-node read in
      // its purest form: reading your own dashboard under another node's
      // name.
      self = { label: node.label, ...(node.role ? { role: node.role } : {}) };
      if (!node.role) {
        notes.push(`this host's row ("${node.label}") declares no role — add "role:" to fleet.yaml so the Advisor can say what this host is`);
      }
      continue;
    }
    const prior = byLabel.get(node.label);
    const tokenPath = prior?.token_path;
    if (!tokenPath) {
      skipped.push({
        label: node.label,
        reason: 'no token_path — fleet.yaml cannot know which token file THIS host can read; ' +
          'add the row with scripts/aperire-fleet-add.sh, or set token_path in fleet.json by hand, then re-run',
      });
      continue;
    }
    peers.push({
      label: node.label,
      origin: node.read_origin,
      token_path: tokenPath,
      ...(prior?.transport ? { transport: prior.transport } : {}),
      ...(node.role ? { role: node.role } : {}),
      ...(node.expected_pubkey_node ? { expected_pubkey_node: node.expected_pubkey_node } : {}),
    });
    if (prior && prior.origin !== node.read_origin) {
      // The drift this whole module exists to catch, named rather than
      // applied silently.
      notes.push(`peer "${node.label}" origin ${prior.origin} -> ${node.read_origin} (fleet.yaml is the source of truth)`);
    }
  }

  if (selfPreserved) {
    if (self) {
      notes.push(`kept this host's self block ("${selfLabel}") from the existing fleet.json — pass --self-label to name a different row`);
    } else {
      // The kept label names no fleet.yaml row any more: renamed, or removed.
      // Keeping the block as it stood still beats un-naming the host, and the
      // note is how the operator finds out it drifted.
      self = { label: priorSelf.label, ...(priorSelf.role ? { role: priorSelf.role } : {}) };
      notes.push(`this host's self block ("${priorSelf.label}") names no row in fleet.yaml — kept as it was; add the row back, or re-run with --self-label <label>`);
    }
  }

  // A row in fleet.json that fleet.yaml no longer knows about is a fossil —
  // the aperire1 case exactly. Dropped, and said out loud.
  for (const label of byLabel.keys()) {
    if (label === selfLabel) {
      notes.push(`dropped peer "${label}" — it is THIS host, and a host cannot be its own fleet peer`);
      continue;
    }
    if (!parsed.nodes.some((n) => n.label === label)) {
      notes.push(`dropped peer "${label}" — no longer in fleet.yaml`);
    }
  }

  return {
    registry: { ...(self ? { self } : {}), peers },
    error: null,
    skipped,
    notes,
  };
}

/** Serialises the registry the way the installer writes it — two-space
 *  indent, trailing newline, the same shape aperire-fleet-add.sh produces,
 *  so a generated file and a joined-to file diff cleanly against each other. */
export function renderAdvisorRegistry(file: AdvisorRegistryFile): string {
  return JSON.stringify(file, null, 2) + '\n';
}

/** Exposed for the caller's own reporting. */
export type { FleetNodeConfig };
