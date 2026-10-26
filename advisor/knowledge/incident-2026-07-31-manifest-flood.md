# Incident — the July 31 manifest flood, resolved by 3.2.1

The reference case for peer-count diagnosis. A documented network-wide event
from late July 2026, kept because its signature is the template for telling
network events apart from local faults.

## What the event looked like

On affected validators, the pattern was consistent:

- Peer count fell from a stable low-20s to bouncing around 9 to 15, starting
  around 2026-07-31 / 2026-08-01.
- Outbound peers roughly halved while inbound barely moved. That asymmetry
  was the tell: peers were shedding load, nothing was wrong locally.
- Outgoing traffic rose sharply (roughly tripling on many nodes) and stayed
  elevated.
- Agreement never moved: 100% throughout, zero missed validations. Consensus
  held the whole time.

## What it was

A network-wide manifest flood. Manifests are the small identity records
validators pass around so nodes know who is who. Nodes were accepting and
rebroadcasting manifests from unknown keys without limit; they piled up and
nodes dropped peers to cope. Not a local fault, and not an attack on any one
node.

## The fix

xrpld 3.2.1 shipped four protections, including a cap on how many manifests
from unknown keys a node will hold. After upgrading to 3.2.1, affected nodes
saw peers rebuild and traffic return to baseline within minutes of the
restart.

## The reusable lesson

When peers drop: check the outbound/inbound split and the traffic level
before suspecting the node. Outbound falling while inbound holds, with
traffic rising, points at the network. Both falling together with traffic
flat points closer to home: connectivity, firewall, or the node itself.
