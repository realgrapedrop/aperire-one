# Node releases — known issues and fixes

What the operator knows about releases of the node software. The Advisor has
no other way to learn what is *in* a release: its release check reports that a
version exists and is pullable, which is not the same as knowing why anyone
would want it.

## xrpld 3.2.1 — released 2026-08-02

Contains a fix for a manifest-flood defect present in 3.2.0.

The defect's signature, as measured on this operator's validator during the
2026-07-31 event: outbound peer connections roughly halved while inbound held,
transaction traffic rose about threefold, and `peers_insane` moved from 0 to
about 3.3. Agreement stayed at 100% and no resource metric moved.

Deliberately no conclusion here about any particular node. This note records
what the defect is and what it looks like; whether a given node's measurements
match that signature is a question to answer against that node's data, not by
assuming.

Source: operator's own dashboard measurements plus the upstream release. The
signature was checked against a month of baseline data, not just the incident
day, which is what separated the real change from ordinary short-window noise
and ruled out a local fault before 3.2.1 was identified as the fix.

## xrpld 3.2.0 — released 2026-06-17

Renamed the binary, the config path and the data path in one release. This is
the reason the environment profile is re-checked before every plan rather than
trusted from setup (ADR 0005).
