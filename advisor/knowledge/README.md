# Advisor knowledge

Notes the Advisor may cite as **Documented**. Application knowledge, not
playbook material — it ships, and the operator maintains it.

This exists because of a boundary the 2026-07-31 retrospective named before
the Advisor was built: local metrics can reach *"not a local fault"* and stop.
Identifying the manifest flood, and identifying 3.2.1 as its fix, required
information that was never in the node's own telemetry. The Advisor asked
about that incident and correctly answered **Unexplained**, because nothing in
its context could take it further.

Files here are loaded verbatim into the model's context and labelled
Documented. So:

- **Write what you know, not what you suspect.** A guess in here comes back
  wearing the Documented label, which is the one that says "this is not a
  guess".
- **Cite the source.** A line an operator cannot trace is a line they cannot
  check.
- **Date entries.** A release note that was true in June is a liability in
  December, and the Advisor cannot tell.
- Lean means one topic per file, not thin. Keep the concrete values in —
  config lines, measured numbers with their window and date — because a note
  that carries them answers the next question without a single new read.
  What gets cut is a second topic, never the evidence.
- Keep it lean. Every question is ranked against a budget, not the whole
  corpus at once — a large or growing collection of notes no longer makes
  every question pay for all of it, but a note that never wins a ranking
  never gets read either, so it is still worth writing for what a question
  will actually ask, not as an archive.

A file placed directly here answers questions about this node regardless of
topic (or, for a file whose name starts `metrics-`, only when the question
names one of its metrics). A file placed under `nodes/<label>/` answers only
for the node called `<label>` — this is for a fleet where each validator has
its own baselines, incidents or tuning notes and a question about one should
not be answered from another's. `<label>` is a directory name, one level
deep; nothing under it is read further down.

If a note does not fit in a question's budget — because the budget is tight,
or because something more specific to the question outranked it — that is
never silent. It shows up in the trace under the drawer as a refused step
naming the file, the same way a read that hit its own limit does.

Nothing here is a substitute for the web search in ADR 0006. It is the half
that works with no network, no key, and no vendor.
