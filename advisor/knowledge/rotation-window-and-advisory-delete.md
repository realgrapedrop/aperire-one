# The ledger store's rotation, advisory_delete, and the daily window

What `advisory_delete` and `online_delete` actually control, the two ways an
Aperire host runs with them, and why neither one is the "right" answer. Both
are the operator's choice.

## What rippled is doing

`online_delete` sets how many ledgers rippled keeps before it prunes. Pruning
means rotating the NuDB store: copy the current state forward, swap in a fresh
writable backend, delete the old one. Left alone, rippled decides when that
rotation happens, roughly every `online_delete` ledgers (about every 32 to 36 hours
at `online_delete=32768`), at whatever hour that lands on.

`advisory_delete` changes who decides. Set to `0`, rippled rotates on its own,
unannounced. Set to `1`, rippled will not rotate until told to, through the
`can_delete` admin RPC.

## Mode 1: advisory_delete=0, free-running

The default. rippled prunes on its own schedule. This is a completely normal,
supported way to run a validator, and most hosts that have not deliberately
opted into the window run this way. The trade-off: a rotation can start at any
hour, including one an operator picks to restart or stop the node. Stopping
the node while a rotation is in flight is what emptied a store on this
project's own stock-node1 on 2026-08-25, the node came back and rebuilt from
genesis.

## Mode 2: advisory_delete=1, with the daily window

`advisory_delete=1` alone does nothing useful, nobody is calling
`can_delete`, so the store never rotates and grows without bound. What makes
the mode work is `scripts/install-can-delete-timer.sh`, which installs:

- `aperire-can-delete.timer`, fires once a day, 04:00 local, the quietest
  hour on a validator host and far from when anyone restarts one by hand.
- `aperire-can-delete.service`, one run of `aperire-can-delete.sh`: it
  authorises exactly one rotation (`can_delete now`), watches the node's log
  until that rotation finishes or a bound is reached, then disarms
  (`can_delete never`) whether or not one was due. The store is never left
  armed with nobody watching.

With this installed and enabled, rotation still happens roughly every 32
hours, but at a time the operator chose, and `aperire-node-wrapper.sh` will
not stop the node while that window (or an unannounced rotation on the same
host) is in flight, the exact interruption that emptied stock-node1's store.

## The baseline reconnect window

Not every slow-looking restart is a rotation problem. Measured on a lab
validator on VPS-class hardware (2026-08-26): a clean restart, no rotation in
flight, left the node `connected` / `complete_ledgers` empty for about 11 to
12 minutes before it reached `full`. The node had only a few thousand
ledgers of local history at the time, below roughly twice `online_delete`,
so it had no durable complete range to resume from and was still in initial
acquisition since its last resync. It re-acquired from the current network
tip instead, and CPU-limited hardware made that acquisition slow. The store
was intact the whole time, and the complete-ledger range came back
afterward, larger than before the restart.

That 11-12 minute figure is what a node in this state pays on hardware this
constrained. It is not measured on a node with an established, larger
complete range; that may reconnect faster, since it would have more of its
own history to resume from rather than reacquiring from the tip. Don't quote
12 minutes as a universal number, quote it as what was measured on a node
still building its range.

Either way, this is smaller than, and unrelated to, the store loss described
in Mode 1 above: a restart that lands mid-rotation on a free-running store
can cost the whole thing and rebuild from genesis, on an order of magnitude
longer than 12 minutes. Read the state, not the duration alone, to tell which
one happened. `complete_ledgers` climbing back from empty toward its old
range is the baseline window. A fresh, near-empty range with a starting
sequence far below what it was before the restart is store loss.

## What the Advisor can actually see

The wrapper's `can-delete-timer` verb reports whether
`aperire-can-delete.timer` is installed on this host, whether it is enabled,
and when it last ran. Four answers, read the same way every other host fact
is:

- **enabled**, the window is installed and enabled; this host runs mode 2.
- **disabled**, the timer is installed but not enabled. This is the
  ordinary state `install-can-delete-timer.sh` leaves a node in while
  `advisory_delete` is still `0`: nothing to fix, the node is running mode 1
  and has not finished opting into mode 2.
- **absent**, the timer was never installed on this host. Also ordinary:
  most hosts run mode 1 and have no reason to install it.
- **unknown**, this could not be measured (no privilege wrapper configured,
  or it did not answer). Unknown is not evidence the window does not exist;
  it means this was not read.

Answer a question about rotation or `advisory_delete` from this reading, not
from what was said in an earlier conversation or from what seems likely.
Neither mode is a mistake to correct: `advisory_delete=0` and
`advisory_delete=1` with this window enabled are both configurations an
operator can choose and keep. Describe the one this host is actually running,
and if asked to switch, say what the other mode is and what changes, without
arguing for either.
