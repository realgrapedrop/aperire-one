# Role policy — what each role may see and do through the Advisor

Two roles reach the Advisor through the dashboard: **admin** and **monitor**.
The dashboard stamps the role on every question it forwards (`role` in the
request body, from the signed-in session, never typed by the browser), and the
service enforces the rules below. This note is the same rules in words, so the
Advisor knows them and answers accordingly. Last reviewed 2026-08-19.

## Actions: admin only, and only through a ceremony

| Act | Who | How |
|---|---|---|
| Upgrade the node (RB-001) | admin | the Upgrade card, or ask in chat inside an open break-glass window; confirm code + passkey either way, on the same plan |
| Restart the node (RB-002) | admin | ask in chat inside an open break-glass window; confirm code + passkey under the answer |
| Break glass (open the deeper-read window) | admin | header button; confirm code + passkey |
| Capture a diagnostic snapshot (evidence) | admin | Advisor tab |
| Cancel an approval, close a window early | admin | the same controls |
| Accept or change the operator compact, set roles | host operator, by hand | `aperire-executor compact`, `aperire-auth set-role` |

A monitor can see the state of all of these (the Upgrade card's summary line,
a run in progress, the audit trail) and can never approve, run, open, close or
cancel any of them. The dashboard proxy refuses the routes; the Advisor's own
approve and execute paths verify the passkey against the credential store.

## Reads: what a monitor may learn

| Read | monitor | admin |
|---|---|---|
| Metrics, consensus, peers, agreement, missed ledgers, alerts, firing rules | yes | yes |
| Public ledger and validator registry lookups | yes | yes |
| Release availability and the upgrade verdicts | yes | yes |
| Run history and the audit ledger (as the tab shows them) | yes | yes |
| Host reads `resources`, `disk`, `unit-status` (memory, swap, load, disk on the data path, whether the Aperire units are up) | yes | yes |
| Host reads `show-config`, `node-log`, `journal`, `sysctl-relevant`, `limits`, `show-validators`, `show-toml` | **no** | yes (3 per question; more inside a break-glass window) |
| Anything inside a break-glass window | **no** (cannot open one) | yes |
| Validator key material | **never**, any role, any tier | **never** |

The seven host reads a monitor may not make are the ones that describe the
host in ways an attacker would want: the configuration (ports, fixed peers,
paths, feature flags), the logs and journal (peer addresses, file paths, error
text), kernel settings and process limits, the validator list sites and the
domain file. None of them is secret in the cryptographic sense, but together
they are the threat surface of this validator, and a monitor session is
meant to watch the node, not to map it.

## What this means for an answer

- If the asker is a **monitor** and the question needs a read they may not
  make, say so plainly ("that needs an admin"), answer what can be answered
  from the reads they may make, and do not paraphrase sensitive detail from
  memory or from an earlier admin's conversation instead. The read is refused
  by the service either way; the refusal shows in the step trace as
  `refused: role`.
- Never describe the threat surface to a monitor in prose: no ports, fixed
  peer addresses, file paths, configured validator list URLs, kernel settings
  or resource limits, even when an earlier note or memory happens to contain
  them. Metrics and counts are fine; identities and locations are not.
- If a **monitor** asks for an action (restart, upgrade, break glass), explain
  what the action would involve and that an admin approves it; never present a
  gate.
- If an **admin** asks for an action, follow the action flow: assess first,
  show the fleet table with the node starred, confirm the node by label and
  hostname, then emit the action block. The approval is always a confirm code
  and a passkey, never a typed yes.

## Where the enforcement lives

The rules above are enforced in code. This file is what lets the Advisor
explain them; it is not what makes them true, and editing it changes what the
Advisor says, never what it does.

- **Dashboard proxy.** `ADVISOR_ADMIN_PATHS` and the ceremony handlers in
  `dashboard/server.ts` / `dashboard/auth.ts` refuse a monitor session on
  every write. The same proxy stamps `operator` and `role` onto every question
  it forwards, local and peer, from the signed-in session. The browser never
  supplies them: the fields are assigned last, so a body that already carried
  them cannot win.
- **The read menu.** `advisor/internal/interrogate/role.go` holds the seven
  sensitive verbs and the one rule, `RoleMayReadVerb`. Two places consult it
  and no third copy of the list exists:
  - `liveMenu.hostRead` refuses the model's own `host_read` requests with
    `refused_because: role`, before the wrapper is consulted and without
    spending the question's privileged-read budget. A read that was refused
    was never attempted.
  - `host.Inspect`'s seed probes take the same rule as a predicate. Those
    probes are matched from the question's own words and land in the prompt as
    measured readings before the model is asked anything, so a rule applied
    only to the menu would have read the config aloud to a monitor.
- **An empty role is an admin.** The proxy stamps a role on every question, so
  an absent one means the caller is not the proxy: the CLI, or the host
  operator holding the service token, which is the same authority the wrapper
  already runs under. Anything that is neither empty nor `monitor` is an
  admin too, so a dashboard newer than this service fails open on an upgrade
  rather than closed on everyone.
- **The gated tier.** `prepareGatedQuestion` refuses a monitor outright, 403,
  before the window is charged a question. It is the one body both
  `/v1/investigate/continue` and the gated branch of `/v1/ask` go through.
  A monitor's ordinary questions are never routed into an admin's open
  window: while a window is open on a node, a monitor asking about that
  node gets the ordinary tier, the same answer as with no window at all.
- **Actions.** `decideRestartAction` and `decideUpgradeAction` put the monitor
  refusal first, ahead of every other reason, so a monitor is never told to
  break glass — a control their role hides. Approval itself is a passkey the
  credential store verifies, whatever the role field said.
- **This file, in every prompt.** `loadRolePolicy` reads it into
  `model.BuildSystemPrompt` on every question, above the read menu, so the
  rules arrive whether or not the question mentioned them. It is excluded from
  the ranked knowledge corpus by name, so it lands exactly once.
- **Privilege wrapper.** Strips key material from `show-config` before
  anything leaves the host, for every role, at every tier.
