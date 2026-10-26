/**
 * What a presented node key already means to this fleet. #620.
 *
 * Judged the moment a node presents its code (`pair_hello`), before a
 * Pending row's Approve control ever renders, off fleet.yaml alone: that
 * file is the one place a node's key is pinned, whether the row reaches it
 * by a tunnel or a link. A pure function on purpose, no socket and no clock
 * beyond what the caller hands in as `isLive`, so the three outcomes are a
 * unit test and not a live pairing.
 *
 * Four answers, and only four:
 *
 *   new        no row pins this key anywhere. The ordinary path.
 *   known      exactly one row pins it, and that row is not yet a link (a
 *              tunnel row this fleet already watches). Approving is the
 *              deliberate decision to move it, under ITS OWN label. The
 *              label the node itself proposed is never used.
 *   reconnect  exactly one row pins it, that row IS a link, and no link is
 *              held under its label right now: a node back after being
 *              offline, or rebuilt with its identity kept (#624).
 *              Approving reconnects it under the row's OWN label, the
 *              move the broker already makes for a node rejoining under
 *              its own name. The proposed label is never used.
 *   clash      anything else: the key is pinned by a row that is already a
 *              link AND currently live (two machines, one key), or by more
 *              than one row, or by a link row the registry no longer
 *              holds or is withholding, or the label the node proposed already names a
 *              different row under a different key. Refused before
 *              Approve ever shows.
 *
 * What this function does NOT decide: it never writes anything and it is
 * never the last word. The broker re-derives the same "known" row from
 * fleet.yaml and the presented key on its own, at approve time, and refuses
 * a request whose label does not match what it finds there. This is the
 * Pending row's own judgement of what to SHOW, not the enforcement.
 */
import type { FleetNodeConfig } from './fleet-registry.js';

export type PairKeyClassification =
  | { kind: 'new' }
  | { kind: 'known'; label: string }
  | { kind: 'reconnect'; label: string }
  | { kind: 'clash'; reason: string };

export interface ClassifyPairKeyInput {
  pubkeyNode: string;
  /** The label the node itself proposed in its `pair_hello`. Only read to
   *  find a label collision (a clash) or to confirm there is none, never
   *  to decide the row a known key moves to, which is always that row's
   *  OWN label. */
  proposedLabel: string;
  /** Every row this fleet's own fleet.yaml holds, self excluded: tunnel
   *  rows and link rows alike, which is the whole reason one function can
   *  answer both "is this a known node" and "is this label taken". */
  fleetNodes: readonly FleetNodeConfig[];
  /** Is a link session currently held under this label? Never guessed at:
   *  the caller answers from its own observation (the hub's live map), the
   *  same distinction the rest of this product draws between kept and
   *  observed state. */
  isLive: (label: string) => boolean;
  /** Does the link registry (fleet-links.json) still hold a row under this
   *  label? A revoke that could not take the fleet.yaml row out leaves a
   *  link row there with nothing behind it, and the broker refuses to
   *  rejoin that after the passkey (rejoin_unanchored). Optional: absent
   *  reads as "held", which is every caller that has no registry to ask. */
  linkRegistered?: (label: string) => boolean;
  /** Is this label's row withheld (its credential still good, its binding
   *  not served until the two registry files agree)? Such a node is not
   *  linked here, but it is not offline either: it keeps dialing and being
   *  told registry_held, and a reconnect would re-mint its credential
   *  under it. Optional: absent reads as "not withheld". */
  linkWithheld?: (label: string) => boolean;
  /** Did `proposedLabel` come from an operator's mint-time name (#635)
   *  rather than the node's own `pair_hello`? Changes only the REMEDY the
   *  C(c) clash names: a node's own `--fleet-label` flag is not what set
   *  this label when the code itself carried a name, so telling an
   *  operator to type a flag on someone else's terminal would be advice
   *  for the wrong machine. Defaults to false, the node's own proposal,
   *  which is every caller before #635. */
  proposedByOperator?: boolean;
}

/**
 * Does `label` already name a row in this fleet, under any node key? The one
 * lookup behind the C(c) clash below, and behind the mint-time name check
 * (#635) -- an operator naming a node before any code even exists is asking
 * exactly the same question a node's own proposed label asks at hello time,
 * only earlier. Pulled out so both callers share one answer rather than two
 * copies of `fleetNodes.find`.
 */
export function fleetRowNamed(
  label: string, fleetNodes: readonly FleetNodeConfig[],
): FleetNodeConfig | undefined {
  return fleetNodes.find((n) => n.label === label);
}

/**
 * What a mint under an existing row's name tells the operator (#976).
 *
 * The mint used to refuse such a name, saying the row was "pinned to a
 * different node key". No node has presented a key at mint time, so that was
 * a claim the mint could not make, and it was wrong in the case that matters
 * most: a node rebuilt with its identity kept, rejoining under its own name.
 * Taking the sentence at its word, an operator revoked the row and lost its
 * history, when Approve and reconnect would have kept it (#624).
 *
 * So the mint goes ahead and says what is true now: a row by that name
 * exists, and the hello decides. classifyPairKey reads the presented key
 * before the label, so the node that holds that row's key gets the row's own
 * move (reconnect for a link row, the proven move for a tunnel row), and any
 * other key is a clash at call-in, before approval, when "a different node
 * key" is finally a fact. Minting under the name reaches nothing that minting
 * under any other name does not: a reconnect already binds by key, whatever
 * name the code carries. The one name still refused is a row that pins no
 * key: no presented key can match it, so its code could only ever clash.
 */
export type MintNameVerdict = { refuse: string } | { warn: string };

export function mintNameVerdict(label: string, row: FleetNodeConfig): MintNameVerdict {
  // A row that pins no node key can never be matched by key at call-in, so
  // every node that used such a code would be the C(c) clash. Minting it
  // would spend a code certain to be refused; refused here instead, with no
  // claim about any key.
  if (!row.expected_pubkey_node) {
    return {
      refuse: `${label} is already a row in this fleet, and it pins no node key, so no node can be matched to it `
        + 'under that name. Give the node a different name.',
    };
  }
  const how = row.transport === 'link'
    ? `If that row isn't linked right now and the node that uses this code holds that row's node key, its Pending `
      + 'row offers Approve and reconnect, which keeps the name, its history and its Advisor.'
    : `If the node that uses this code is that same node, its Pending row offers Approve and move once it proves `
      + 'it holds the read token this aggregator reads it with.';
  return {
    warn: `${label} is already a row in this fleet, ${row.transport === 'link' ? 'on the fleet link' : 'watched over a tunnel'}. `
      + `${how} A node with any other key is refused when it calls in, before approval, and nothing changes.`,
  };
}

export function classifyPairKey(input: ClassifyPairKeyInput): PairKeyClassification {
  const { pubkeyNode, proposedLabel, fleetNodes, isLive, linkRegistered, linkWithheld, proposedByOperator } = input;
  // An aggregator's own row is never a destination a node's key could be
  // pinned to as a peer: excluded here rather than trusted to be absent,
  // because fleetNodes is peers only in the ordinary case but a defensive
  // read should not depend on that holding forever.
  const pinned = fleetNodes.filter(
    (n) => n.role !== 'aggregator' && n.expected_pubkey_node === pubkeyNode,
  );

  if (pinned.length === 0) {
    // Not a known key. Still a clash if the label it proposed is already
    // somebody else's row (the C(c) case): the operator's editable label
    // field means this is not the last refusal, but it is the honest one
    // to show before anybody approves rather than after. Here, unlike at
    // mint (#976), a key HAS been presented and no row pins it, so a row
    // under this label that pins a key pins a different one.
    const labelRow = fleetRowNamed(proposedLabel, fleetNodes);
    if (labelRow) {
      return {
        kind: 'clash',
        reason: `${proposedLabel} is already a row in this fleet`
          + (labelRow.expected_pubkey_node ? ', pinned to a different node key. ' : '. ')
          + (proposedByOperator
            // The code itself carried this name (#635): the node's own
            // --fleet-label had nothing to do with it, and may not even be
            // set, so the fix is a new code, not a flag on the node's line.
            ? 'Mint a new code with a different name.'
            : 'Give it a different name with --fleet-label, then mint a new code and pair again.'),
      };
    }
    return { kind: 'new' };
  }

  if (pinned.length > 1) {
    // Two rows already pin one key. Not this pairing's fault and not this
    // pairing's fix: approving here cannot know which of them it would be
    // replacing, so it refuses rather than guessing.
    const labels = pinned.map((n) => n.label).join(', ');
    return {
      kind: 'clash',
      reason: `This fleet already pins that node key to more than one row (${labels}), so approving it `
        + 'here would not know which one it replaces. Fix the duplicate by hand, then mint a new code and pair again.',
    };
  }

  const row = pinned[0];
  if (row.transport === 'link') {
    if (isLive(row.label)) {
      return {
        kind: 'clash',
        reason: `${row.label} is already on the fleet link with this node key, and it's answering from `
          + 'somewhere else right now. Two machines holding one node key is a copied install. Fix it on the '
          + 'copy (give it its own node identity), then mint a new code.',
      };
    }
    // A link row that is not currently live: a node that was offline, or was
    // rebuilt with its identity kept, presenting a fresh code for the row
    // this fleet still remembers (#624). It is that row coming back, under
    // that row's own label whatever the node proposed.
    if (linkWithheld?.(row.label)) {
      return {
        kind: 'clash',
        reason: `${row.label} is a link row this aggregator holds but is not serving until its two registries agree, `
          + 'so that node may still be dialing it. Fix the registry first (the Settings page names the two files), '
          + 'then mint a new code.',
      };
    }
    if (linkRegistered && !linkRegistered(row.label)) {
      // The row is in fleet.yaml but the link registry has let it go, which
      // is what a revoke that could not finish leaves. The broker refuses a
      // rejoin with nothing to anchor it, after the passkey; say so now.
      return {
        kind: 'clash',
        reason: `${row.label} is still a row in this fleet's list, but its link was revoked and the revoke `
          + 'did not finish. Press Revoke on its row again to finish taking it out, then mint a new code and pair again.',
      };
    }
    return { kind: 'reconnect', label: row.label };
  }

  // Exactly one row, not a link: the known-node case. Its own label is
  // what a move keeps, whatever the node itself proposed.
  return { kind: 'known', label: row.label };
}
