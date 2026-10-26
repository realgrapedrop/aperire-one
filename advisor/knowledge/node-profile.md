# This node's normal

What healthy looks like on THIS node. When a measurement disagrees with this
profile, the disagreement is the finding.

This file ships empty on purpose. It carries no baselines until an operator
fills them in, and "not recorded" below means exactly that: unknown, never
zero and never healthy. Answer a question that turns on a missing number from
the live measurement instead, and say plainly that no baseline is on record
for it.

Where it lives: on a single-node install, edit this file. On a fleet, give
each node its own copy at `knowledge/nodes/<label>/node-profile.md`; a profile
scoped to the node being asked about outranks this one for that node's
questions.

## Baselines

What this node actually does over a normal week, and the deviation worth
investigating. Measure each line before writing it. A guessed baseline is
worse than a missing one, because a guess gets compared against.

- Peers: not recorded. Record the steady count, the inbound/outbound split,
  and the drop that means something on this node.
- Agreement: not recorded. Record the normal percentage and how often a
  validation is missed. Each miss is kept on the Consensus tab with context.
- Peer latency p50: not recorded. Record the usual band, and any step change
  already explained, with its date.
- Traffic: not recorded. Record steady kbps in and out, and what a spike has
  meant here before.
- Ledger close cadence: 3 to 5 seconds is healthy, 5 to 6 elevated, above 6
  means consensus is taking longer than expected. This one is a property of
  the network rather than a measurement of this node, so it holds everywhere.

## Deployment shape

- How the node runs: not recorded. Native or in a container; if a container,
  the compose project, the service name and the image it is pinned to. The
  compose file is the deployment's source of truth, and the wrapper's
  set-image and set-image-local verbs are the only sanctioned ways to edit
  it. Which one applies is the image's origin: a registry tag takes
  set-image, an image built on the host from the signed package takes
  set-image-local, which also writes the pull_policy line that keeps compose
  from reaching for a registry that cannot serve a localhost/ name.
- Config file and data directory: not recorded. Both are detected at install
  and written to the dashboard's environment file, so record here only what
  differs from what was detected.
- UNL and registry: not recorded. Whether the validator is on a published UNL,
  where it is tracked, and the verified domain if it has one. A tracker going
  quiet is a visibility loss, not a participation problem: local agreement is
  the source of truth for whether this node is validating.
- What else runs on this host: not recorded. Anything that must not be
  touched belongs here by name, because a process this file does not mention
  is a process nobody will think to leave alone.

## Operator conventions

- Restarts: not recorded. State how rare a node restart should be here, and
  whether a dashboard restart counts (it is not validator downtime, but it is
  still a restart).
- Backups: config and compose file are copied with a dated suffix beside the
  originals before any change. Backups and pulled images survive a cancel;
  only the deployment edit is rolled back.
- Upgrades follow the two-stage ceremony, prepare then restart, each stage
  approved with a confirm code plus a passkey, everything audited.
