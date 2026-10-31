# Advisor: setup and what it can do

The Advisor is the optional assistant that answers questions about your node and can run approved actions on it from the dashboard. This page is for the operator installing it: what it may do, how to install it, and how to confirm it works.

Aperire One monitors your node fully without the Advisor. Turn it on and you get two things, both with hard limits set out below: an expert you can ask about your own node, and a way to run approved actions on it from the dashboard.

---

## Adding it later

The Advisor is off by default. `install.sh` installs the dashboard, the relay
and the node without it unless you pass `--with-advisor`, so a host that only
needs monitoring never gets one.

**Until an Advisor is present, it isn't in the dashboard at all.** There is no
Advisor tab, and no Ask Advisor button on any alert, missed validation or node
row. Not greyed out: not rendered. The one place it is mentioned is a quiet
**Add the Advisor** row at the bottom of the navigation menu, which opens a
single page describing what the Advisor is and the command that installs it.

Adding one to a host that already runs the dashboard is one command:

```bash
curl -fsSL https://get.aperire.one/advisor | bash
```

That is the whole thing. It finds the install this host is running, from the
dashboard service's own record of where it lives, builds what a host installed
without the Advisor never built, and hands over to the same script the
`--with-advisor` flag runs: the service, the two root grants the browser needs,
the move onto a dedicated account that reaches the node wrapper through one root socket, and the Advisor's own copy
of who may approve. It says what needs root before it asks for it, and it reads
the service back as enabled, running and answering before it tells you it
worked.

It is an add-on, so on a host with no Aperire One install it stops and names
the command that installs one, rather than installing something you did not
ask for. On a host that watches other nodes rather than running one, the
account move is skipped with a line saying why: that step reads the node
deployment the privilege wrapper drives, and such a host has none. The flag
path behaves the same way, because it is the same script.

Piping a URL into a shell runs code you have not read, so read it first if you
would rather: `curl -fsSL https://get.aperire.one/advisor -o get-advisor.sh`,
then `less`. Same script.

The steps it runs are set out in full under [Install](#install), for a host
with no network path to the endpoint or an operator who would rather run them
directly. All of them are safe to re-run, and so is this.

Re-running it on a host whose Advisor is already answering changes nothing and
says so, with one exception: if that Advisor has no language model yet, it
opens a fresh fifteen minute window for the browser step below and does nothing
else.

### The model, in the browser

The install ends with the Advisor running and no model, which means it reads,
plans and keeps its ledger but cannot answer a question in your words. The
install command's last act is to open the window the next step needs, and both
install paths close with these same four steps:

1. Refresh the dashboard in your browser.
2. Open the menu (top right) and choose **Settings & Updates**.
3. Open **Advisor AI model**, the last panel. It is there only once an Advisor
   exists somewhere in the fleet, so a dashboard with none never shows it.
4. Choose a provider, paste the key, press **Test**, pick a model, and seal it
   with your passkey.

The key is checked against the provider before anything is written, and the
models offered are the ones that key actually reaches. It is kept where only
root on that host can read it, and neither the dashboard nor the page ever shows
it again. The Advisor restarts to pick it up, which waits for any question
already running, so the last step can take a minute.

Set a monthly spend limit on the provider account the key belongs to. The key
reaches nothing on your node or validator, so all someone could do with a copy
is spend on that account, and the limit caps that. If you ever doubt the
dashboard host, rotate the key (see [Change the model or rotate the key](#change-the-model-or-rotate-the-key)).

**Where the key is kept, by OS.** Two methods, and a host uses whichever one its
systemd supports. The checklist (`--check`) and the Advisor install both print
which one this host will use, before anything is installed.

| Host | Method | What the unit loads it with | TPM used when present |
|---|---|---|---|
| Ubuntu 24.04, Linux Mint 22, Debian 12, anything on systemd 250 or newer | `systemd-creds encrypt`, sealed to the machine | `LoadCredentialEncrypted=` | Yes |
| Ubuntu 22.04, anything on older systemd | a `root:root` 0600 file in `/etc/aperire/creds`, inside a directory that is itself `root:root` 0700 | `LoadCredential=` | **No** |

A fleet aggregator keeps its copy of the fleet model by the same rule: sealed at `/etc/aperire/fleet-model.cred`, or a `root:root` 0600 file at `/etc/aperire/fleet-model.cred.plain` on older systemd. See "The sealed copy" in the [fleet guide](FLEET-GUIDE.md).

`systemd-creds` and `LoadCredentialEncrypted=` first shipped in systemd 250
(systemd NEWS, v250). Ubuntu 22.04 ships 249, so it has neither.
`LoadCredential=` is older and is present on 249, measured on a 22.04 host, so
both paths hand the key to the service the same way: a file on a per-service
ramfs at 0400, under the same credential name, which the Advisor reads without
knowing which method put it there.

**What the second method trades away.** Two things, and the first one is easy
to miss: a 22.04 host **with** a TPM gets no TPM binding at all on this path.
The tool that would use the chip is the one that is not there. If your hardware
has a TPM and you want the key bound to it, that is a reason to run 24.04 or
newer rather than a reason to avoid the Advisor.

The second is what a copy of the file is worth. On the plain path the file is
the key: any root-made copy of `/etc` carries a working key off the machine, and
that includes copies nobody thinks of as backups, an `etckeeper` repository or
an image built without `/var/lib`. `systemd-creds` output is ciphertext bound to
the host key, so the same copy carries nothing usable.

What the second method does **not** trade away is who can read it on the host
itself. Without a TPM, which is the ordinary case on a VPS, `systemd-creds`
encrypts with `/var/lib/systemd/credential.secret`, a `0400 root:root` file
sitting beside the blob: an attacker who can read one can read the other. On
such a host the two methods have the same reader set, root. The difference is
entirely in what leaves the machine.

Neither method puts the key in a config file, an environment, or a log.
Aperire's own backup (`scripts/aperire-backup.sh`) excludes
`/etc/aperire/creds` on both paths and says so in the set's README. That is a
statement about this tool and no other: any backup of `/etc` you run yourself
will take the key unless you exclude that directory.

Until a model is sealed, the Advisor tab shows one card saying so and pointing
at the same panel. It goes away on its own once the Advisor comes back
answering.

**The window.** Sealing needs root, and the dashboard does not run as root. Its
own service hardening goes further than that: it cannot gain a privilege at
all, so it cannot start a root program even with permission to. What it has
instead is one private socket, its account's alone. Behind that socket is one
root program that takes no arguments, reads a key on standard input, and seals
only while a window is open. The install command opens one for fifteen minutes;
sealing closes it, and an unused one closes itself. Nothing the dashboard can
reach opens another. The panel shows whether the window is still open, and if
it has closed by the time you get there, the line that reopens it:

```bash
curl -fsSL https://get.aperire.one/advisor | bash
```

**To remove the browser step entirely**, on a host where you would rather the
dashboard could not do this at all:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --remove
```

That takes back the socket, the program and any open window. Setting the model up
from a terminal is unaffected and is still the right answer when no browser can
reach the host:

```bash
bash scripts/setup-advisor-model.sh
```

### Change the model or rotate the key

The model is one setting for the whole fleet: one provider, one model, one key,
applied to this dashboard and to every node that runs an Advisor. There is no
per-node choice, so there is one place to change it.

Open the menu on any page, choose **Settings & Updates** (administrators only), then
**Advisor AI model**. It states the current setting first: the provider, the
model, a hint for which key is in place (the first and last few characters, the
way a provider console shows it), when it was sealed and by whom. The key
itself is never shown. Under that, one row per node saying whether that node is
on the setting: in sync, behind, no model sealed at all, not read this pass, or
no Advisor to configure. A node that is behind carries its own **Bring up to
date** button.

Under that, one more line: whether a **sealed copy** of the setting is held
here, and so whether a node joining the fleet tomorrow gets the model without
anybody pasting a key. See below.

**Change model or key** opens the form. Paste the key (the same one, or a new
one to rotate to), press Test, choose from the models that key actually
reaches, then approve with your passkey. One approval covers the nodes the
change names and nothing wider: they are recorded with the challenge. A
single-node install is the same form with one row. The key field is always
required here, because a change is a new setting and no dashboard keeps a copy
of the old one.

#### Seal or change the fleet model

The steps, in the page's own order and words:

1. Open the menu (top right) and choose **Settings & Updates**.
2. Open **Advisor AI model** and press **Change model or key**.
3. Under **1. Choose the model and paste its key**: pick the **Provider**, paste the **API key**, press **Test**, then pick the **Model** from the list the key reaches.
4. Under **2. Run this command on the host running this dashboard**: copy the line with its **copy** button and run it over SSH or at the console of the host that runs this dashboard. Where the fleet broker grant is installed, it is:

   ```bash
   sudo aperire-fleet-arm
   ```

   The page adds `--self-only` or `--node <label>` when the change covers one node. The pill turns from **NOT ARMED** to **ARMED** within a few seconds.
5. Under step 3 (**3. Seal all N nodes with your passkey** on a fleet): press **Seal with my passkey** and touch your passkey once.
6. Read the table. Every node should read **IN SYNC**. A node that reads **BEHIND** gets **Bring up to date** on its row, or **Bring N nodes up to date** under the setting for all of them at once.

The window lasts fifteen minutes and one seal spends it. While it is open, step 2 shows only the ARMED pill and how long is left. Once it lapses or is spent, the pill reads NOT ARMED again and the command is back on the page, so arming again is the same copy and paste.

**The sealed copy, and what it saves you.** When a change finishes with at
least one node on the new setting, the aggregator's root service seals the
whole setting, key included, into a credential only that machine can open. The
dashboard cannot read it back: there is no route, and no verb on that service
returns the key. Two things follow, and both mean no second paste.

- A node paired later inherits the setting during its own pairing, and its
  Pending row says what came of it.
- A node that was down for a change is caught up with **Bring up to date**, or
  with **Bring N nodes up to date** under the setting, and there is no key
  field: the confirmation names the model, the address it goes to and the
  credential name, you approve once, and each node answers for itself as it
  settles.

Both need a sealing window open on the aggregator itself, the same kind of
window each node needs before a key lands on it. The sealed copy only moves
while one is open, so nothing on that machine can send it at a time of its own
choosing. One window covers a whole catch-up: a push does not spend it, and
the button names the command if it is shut.

The line under the setting says which of those is possible right now. Four
things it can say, and only one of them means there is nothing held: no sealed
copy, a copy this host could not open (the copy is sealed to the machine that
made it, so a rebuilt host cannot read the old one), or a service too busy to
answer. It names the **host** of the provider address rather than the brand,
because that address is where every question's context would go.

The sealed copy is **not a backup**. It cannot be moved and cannot be read
anywhere but the machine that made it.

**Arming is the one terminal step.** A change seals a key, and sealing works only
inside a window that root opens on the node being sealed. Settings shows each
node's arming state while the form is open and polls it, so **Seal** is dead
until every node in the change is armed, and the line that arms them sits right
above the button with a copy control. On a single host it is:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --arm
```

On a fleet it is one line on the aggregator, `sudo aperire-fleet-arm`, which
arms every node at once; the fleet guide covers what each node needs before it
will honour that. The fleet broker grant installs it root-owned on root's
PATH. On an aggregator whose grant is older than that program, the page prints
the update first, a check that the program is there, and then the same command
(`curl -fsSL https://get.aperire.one | bash -s -- --update --force && test -x /usr/local/sbin/aperire-fleet-arm && sudo aperire-fleet-arm`).
It never prints a path into the install directory. On a host with no fleet
broker grant at all the update has nothing to place, so the page names the grant
install instead.
Run it over SSH or at the console; the state turns to ARMED within
a few seconds and the button comes alive. The window lasts fifteen minutes and
one seal spends it. It stays root-only on purpose: the window is what stops a
compromised dashboard account from pointing the Advisor at an endpoint it
controls, and the passkey cannot cover that, because the dashboard is what
checks the passkey.

After the seal, each node's row reports what its own Advisor came back with and
whether it is now on the fleet's setting, and the change lands in that node's
Audit trail as `model.configured`, with
the provider, the model and the credential.

**Rotation is yours to finish.** Sealing a new key does not revoke the old one.
Until you revoke it at the provider, anything still holding it can spend on
your account. Revoke it there once every node reads IN SYNC, and not before:
revoking first breaks every node that has not taken the change yet. The page
says this next to the Seal button, and again on the verdict of a seal that put a
different key behind the fleet model. When this host can't tell whether a seal
replaced a key (it holds no record of the last one), the verdict says it as an
if: if this replaced a different key, revoke that one once every node reads IN
SYNC. A seal of the key the fleet already runs says nothing, and neither does
Bring up to date, which sends the key the fleet already holds.

The terminal alternative is the operator menu, run as you (it asks for sudo on the steps that need it): `bash <install dir>/aperire-one`,
then **3) Advisor**, **6) Set up / change the model**.

**The dashboard works it out for itself.** It checks whether an Advisor is
installed on this host and whether it is answering, so there is no flag to set,
nothing to reinstall and no page to reload. The dashboard rechecks every twenty
seconds and each open page picks the answer up on its own cycle, so within a
minute of the service answering the Advisor tab and every Ask Advisor button
appear by themselves, including on pages already open.

The reverse is deliberately not symmetric. An Advisor that is installed but
stopped keeps its tab and says plainly that the service is not answering, and
every alert and missed validation stays on screen with its Ask button greyed
rather than removed. A stopped service is news worth telling you, and hiding a
real problem because an optional service is down would make installing that
service a condition of seeing that something is wrong.

---

## What the Advisor can do

- **Read** your metrics, its own records, and a short list of facts about the host: node configuration, disk, memory, kernel settings, logs.
- **Act** on your node only through one script, the root-owned copy at `/usr/local/sbin/aperire-node-wrapper`, and only with one of a fixed set of verbs. It cannot invent a command or name an arbitrary path. A verb that takes an argument accepts only allow-listed values; the script holds every real path itself.

Every action needs your approval first: a typed confirmation code, then your passkey, per stage. Approvals are spent on use and expire.

Everything it does, and everything it refuses to do, is written to a hash-chained ledger you can read in the tab.

---

## What it cannot do

- **Reach Docker.** Its account is not in the docker group. That group is root-equivalent, so an account in it could bypass the wrapper entirely.
- **Read your validator key.** `rippled.cfg` holds `[validator_token]`. The wrapper strips it as root before returning anything, so the key never reaches the Advisor.
- **Run anything else as root.** One root socket, one fixed table of verbs, no wildcard.
- **Edit what constrains it.** The wrapper and its config are root-owned, and its own unit puts the rest of the filesystem out of reach. The audit ledger is different, and worth being precise about: it lives in the Advisor's own state directory, so the Advisor can write it. What protects it is the hash chain. Each entry commits to the one before it, so altering or removing one breaks every entry after it and the ledger refuses to open. That makes tampering visible rather than impossible, which is the property you need when reconstructing an incident.

---

## The two accounts

| Account | Runs | Reaches Docker? |
|---|---|---|
| `aperire-dashboard` | the dashboard | no |
| `aperire-advisor` | the Advisor | no |

Neither is your login. A fresh install runs the dashboard as `aperire-dashboard`, a system account with no login shell and no home directory, in none of the groups that are root on a host by themselves (`docker`, `sudo` and the like). A host that already ran the dashboard as another account keeps that account, and the installer warns about it.

The Advisor runs under its own account so that "it can only act through the wrapper" is enforced by the system, not promised by the code. That account holds no sudo rule. It reaches the wrapper through one root socket, owned by root and the Advisor account's own group, mode 0660. The broker behind the socket admits only that account's uid, takes one verb from a fixed table and runs the wrapper, which root owns and which is a readable list of everything the Advisor can do.

The two accounts share one group, `aperire-svc`, for two files the dashboard has to read: `approve.token`, which it presents when it calls the Advisor, and `read.token`, which a fleet aggregator authenticates against. Both are mode 0640.

The default account name is `aperire-advisor`, chosen so it can't collide with a person. Set `APERIRE_ACCOUNT` to pick another. Either way it's created as a system account with no login shell and no home directory.

An account that looks like somebody's (a login shell, SSH keys in its home, or docker group membership) is refused rather than adopted, so the installer never touches an account a person signs in with.

---

## Install

There is one Advisor install and two ways to reach it. Both run `scripts/install-advisor-stack.sh`, which is the sequence:

1. `install-advisord.sh` builds the Advisor, installs its service, and configures the privilege wrapper from this host's own deployment.
2. `install-model-key-sealer.sh` installs the socket the browser seals a model key through, and opens a fifteen minute window.
3. `install-trust-sync-grant.sh` installs the socket that hands a passkey enrolled in the browser to the Advisor.
4. `install-advisor-account.sh` moves the Advisor onto its own account, which reaches the node wrapper through one root socket.
5. `aperire-auth.sh advisor-sync` gives the Advisor its own copy of who may approve, for anyone who enrolled before it was installed.
6. The read-back: enabled, running, and answering on `/v1/status`, before any of the above is claimed.

Steps 1 and 6 are fatal, because there is no Advisor without them. Steps 2, 3 and 5 are degradations: each one says what was lost and what to run instead, and the install carries on. Step 4 runs on every host, Ubuntu 22.04 and hosts with no node included. If it refuses on a host whose Advisor was already running, it puts the previous arrangement back and the rest still runs. The run then ends with exit 3 and a closing block, the last thing on the screen, saying the Advisor isn't on its own account and which command finishes the move. A first install has no previous arrangement to put back, so the Advisor is installed and not started, and the read-back ends the run with exit 1.

**On a host that already runs Aperire One**, one command:

```bash
curl -fsSL https://get.aperire.one/advisor | bash
```

**While installing Aperire One**, one flag:

```bash
sudo bash install.sh --role=co-located --with-advisor
```

That is for a co-located host: the node runs here, container or native. If your node runs on a different host, use `--role=dashboard`, and the Advisor still gets its own account:

```bash
sudo bash install.sh --role=dashboard --with-advisor
```

Both end where the other ends: with the Advisor answering and the four browser steps above for the model. The [flags](#advisor-flags-and-overrides) below cover the rest.

To run the sequence on its own, on a host installed without the Advisor, run the first command above. Both paths call the same sequence. On a host whose Advisor already answers it says so and changes nothing, so it is not how you repair one; moving a shared-account Advisor onto its own account is the update (`curl -fsSL https://get.aperire.one | bash -s -- --update --force`, at a terminal, answering Y when it offers the move).

### Advisor flags and overrides

Defaults suit a single node. Change them only if you need to.

| Flag or variable | Default | What it does |
|---|---|---|
| `--advisor-shared-account` | off | Retired. Accepted and ignored: the Advisor always gets its own account |
| `--advisor-port=N`, or `APERIRE_ADVISOR_PORT` | `7810` | The loopback port advisord listens on |
| `APERIRE_ACCOUNT` | `aperire-advisor` | The name of the dedicated account |
| `APERIRE_NODE_CONTAINER` | read from the wrapper config, else the one running container | The container this Advisor watches |

The flags are `install.sh`'s. The variables are read by the Advisor scripts either way, so they work when you run those scripts on their own:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --run advisor-account --account my-advisor
```

### What each step does

`install-advisord.sh` builds the Advisor, installs its service, and calls `install-node-wrapper.sh`, which finds your node's deployment and writes those paths to `/etc/aperire/node-wrapper.conf`. That file is root-owned, so the Advisor can't edit its own limits.

This step tries the container path first: a container found by image name (anything matching `rippled`, `xrpld` or `xahaud`). If nothing matches, or more than one does, it stops and asks you to name it:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container-name> [--node-wrapper-rpc <port>]
```

The optional `--node-wrapper-rpc` is the node's admin RPC port (or a loopback `http://127.0.0.1:PORT` URL). Leave it off and the port is read from the container's own published mapping.

**On a natively installed node**, this step's default run finds no container and stops without acting; wire the wrapper for it explicitly instead:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native
```

It detects the running unit (`xrpld.service`, then `rippled.service`, or the one you name with `--node-wrapper-native <unit>`), reads the config it points at for the admin RPC and the data path, and works out which package owns it. If you installed the node with this project's own native installer (see the [Deployment Guide's native section](DEPLOYMENT-GUIDE.md#a-native-node-without-docker)), that install already ran this command as its last step, so there is nothing left to wire here. Either way, until the wrapper names your node, the Advisor still monitors and explains; only the action side needs it.

`install-advisor-account.sh` creates the `aperire-advisor` account and moves the service onto it. It proves the arrangement works before touching the running service:

- the account can reach its binary and write its own state
- on a host with a node, it reaches the wrapper through its root socket and the wrapper answers, but the dashboard's account cannot
- it cannot reach Docker
- it cannot read your node's configuration (and it warns you if that file is still readable by every account on the host)
- it cannot list your home directory
- the wrapper socket, and a writable state directory, both work inside a throwaway copy of the sandbox

If any check fails it tells you which one, and undoes the socket, the ACLs and the state-directory ownership it had set. The service is never stopped, so nothing about the running Advisor changes. The account itself and its group membership stay; they're harmless on their own and re-running the installer reuses them. If the service doesn't come back after the move, it restores the previous setup automatically.

### It also closes your node's configuration

A Docker Compose deployment usually leaves `rippled.cfg` readable by everyone on the host. That's easy to miss, because most validator hosts have no other accounts, until this installer adds one.

So the install closes it. The file becomes readable by you, by your node, and by the relay if the relay needs it to auto-detect the node's ports. Nothing else on the host can read it. Your node keeps working: the file stays readable by the group your node actually reads it as, found by asking the running node rather than assuming. Nothing restarts and your validator doesn't stop.

If your node isn't running, this step is skipped rather than guessed at, and the install tells you. Tightening the file without confirming the node still reads it is how a validator ends up unable to start. Run it yourself once the node is up:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure
```

That reports and changes nothing. Add `--apply` to make the change.

---

## After installing

**Your shell needs a fresh login.** Your account was added to the `aperire-svc` group, and Linux fixes a process's groups when it starts, so a shell opened before the install keeps the old list.

The services aren't affected; systemd starts them fresh. You'll only hit this reading `advisor/state` or `advisor/evidence`, or running `go build ./...` inside `advisor/`.

| Fix | Scope |
|---|---|
| `sg aperire-svc -c '<command>'` | one command |
| `newgrp aperire-svc` | a subshell |
| log out and back in | permanent |

A new tmux or screen pane doesn't help; it inherits from the server process, which is also older than the group.

**A model is separate.** Asking questions needs one configured. `install-advisord.sh` offers to do it at the end when none is set, and answering no is fine. A host whose Advisor is running with no model says so on the Advisor tab and points at **Settings**, **Advisor AI model**, where it is set up (see [The model, in the browser](#the-model-in-the-browser)). Changing one already sealed is the same panel (see [Change the model or rotate the key](#change-the-model-or-rotate-the-key)), or from a terminal:

```bash
./scripts/setup-advisor-model.sh
```

Readiness checks, the plan, and the ledger all work without it.

---

## Running it day to day

Everything about the Advisor's service is behind `aperire-one`, under
**Advisor**: restart, start and stop, its status and recent log, updating its
binary from the tree, the model, and re-running the install, which re-arms the
browser's model window and repairs both root grants and the account move. The
section also names what the dashboard currently observes about this host, so
you can tell an Advisor that is missing from one that is installed and quiet
without leaving the menu. Every entry prints the command it is about to run,
so nothing below is hidden from you, and none of it has to be typed.

The raw commands in the rest of this page still work and are what the menu
runs.

---

## Checking it worked

```bash
systemctl status aperire-advisord      # active, running as aperire-advisor

cd advisor && sudo -u aperire-advisor ./bin/aperire-advisord --wrapper=/usr/local/sbin/aperire-node-wrapper \
  --wrapper-socket=/run/aperire/node-wrapper.sock --wrapper-call inspect
```

The second command should print your node's details, a container's on that shape or a systemd unit's on a native install. If it does, the Advisor can reach your node through the wrapper's root socket and no other way.

In the dashboard, open the Advisor tab. It should name your node and its version.

Three other things it can say, and they mean different faults:

| What you see | What it means |
|---|---|
| "Advisor not running" | The dashboard can read the service token but the Advisor isn't answering. Check `systemctl status aperire-advisord`. |
| The tab is there, and it names `approve.token` and permissions | The dashboard found the Advisor's service unit but can't read the token. The Advisor is installed; the dashboard is locked out of it. |
| No Advisor tab at all, and a page offering to install one | Neither the token nor the service unit is there, so as far as the dashboard can tell no Advisor was ever installed here. |

The second one is almost always the group. `approve.token` is mode 0640 and
owned by the `aperire-svc` group, and the dashboard's own process fixed its
group list when it started, which was before the installer created that group.
Restart it once:

```bash
sudo systemctl restart aperire-server
```

---

## Undoing it

The uninstaller removes it. One command, and it is scoped to the Advisor, so the dashboard, the relay, your operators and the node carry on:

```bash
curl -fsSL https://get.aperire.one/uninstall | bash -s -- --role=advisor --wipe
```

It takes every piece the Advisor arrives in, which is more than the four files that used to be listed here:

- `aperire-advisord.service`, stopped and disabled, and the `.before-account` and `.before-hardening` copies of the unit it replaced
- the model-key sealer: its socket, its root program under `/usr/local/sbin`, the arming marker, and any key an earlier ceremony sealed
- the trust-sync grant: its socket, its template unit and its root program
- the retired sudo rules, each followed by a `visudo -c` on what is left: `/etc/sudoers.d/aperire-model-key`, and `/etc/sudoers.d/aperire-advisor` and `aperire-advisor-<instance>` when they are exactly what an older release wrote (any other file under those names is left and named)
- every access control entry granted to `aperire-advisor`, taken back **before** the account goes: afterwards the entry reads as a bare numeric uid and a removal by name stops matching it
- the `aperire-advisor` account, and the `aperire-svc` group with the memberships in it. On `--keep` the group stays while a file kept in `/etc/aperire` is on it (an aggregator's fleet tokens), so its id can't pass to another group, with every member taken out except a dashboard that stays. An install that later finds the group with anyone else in it refuses and names them
- `/etc/aperire/node-wrapper.conf` and `node-config-perms.before`
- `/var/lib/aperire/verified-images` and `/var/lib/aperire/rollback`, the wrapper's records of images it verified and a package kept for a rollback
- `advisor/bin`, `advisor/evidence`, and `advisor/state` apart from `read.token`, which the dashboard install wrote and the dashboard is still reading

`--keep` instead of `--wipe` still removes the unit, the sockets, the access and the account, because those are privilege rather than data. The sealed key, the wrapper's configuration, its records under `/var/lib/aperire` and the Advisor's own state stay where a reinstall finds them.

The `.before-account` file matters and is why it is on that list. It is the marker that says the dedicated-account installer owns the unit, and `install-advisord.sh` reads it: leave it behind and a later reinstall skips writing the unit entirely, reporting success while the service has no unit to start.

To read back that none of it is left:

```bash
bash scripts/aperire-leftovers.sh
```

The Advisor's sudo rules are in `/etc/sudoers.d`, which your login can't read on Ubuntu. The finder says so on a `not checked` line with the command that reads it (`sudo ls -la /etc/sudoers.d`), and exits 3 rather than calling the host clean.

### Just the account move, not the Advisor

If you want the Advisor back on your own account rather than gone, the installer prints the exact commands when it moves the Advisor and keeps your previous service file at `/etc/systemd/system/aperire-advisord.service.before-account`. In order:

1. Put that file back: `sudo cp -a /etc/systemd/system/aperire-advisord.service.before-account /etc/systemd/system/aperire-advisord.service`
2. On a host with a node wrapper, stop the Advisor's root socket: `sudo systemctl disable --now aperire-node-wrapper.socket`. The installer prints this step only where it applies.
3. Give the three directories back to your account: `curl -fsSL https://get.aperire.one | bash -s -- --run advisor-account --hand-trees-back`. It takes `advisor/state`, `advisor/evidence` and `advisor/knowledge-fleet` and does nothing else.
4. Reload systemd and restart the Advisor: `sudo systemctl daemon-reload && sudo systemctl restart aperire-advisord`

A moved Advisor holds no sudo rule, so there's no sudoers step. The installer removes any rule it finds once the Advisor answers on its socket. On a named instance, add `--instance <name>` to step 3 and use `aperire-node-wrapper-<name>.socket` and `aperire-advisord-<name>` in steps 2 and 4.

Your node is untouched by any of this. The Advisor never changes anything without an approval you gave.

---

## A note on hardening reports

`systemd-analyze security aperire-advisord` reports an exposure score for the unit. The service runs with `NoNewPrivileges=true` and a syscall filter, because it never needs to gain privilege: its only route to your node is a connection to the wrapper's root socket. If `UMask=0027` is flagged, that is deliberate: it makes files group-readable, which is exactly what lets the dashboard read the one file it shares.

The score measures what a process may call. It can't see that the boundary here is a socket that takes one fixed table of verbs and only the Advisor's user id.

---

## See also

- [Advisor guide](ADVISOR-GUIDE.md): what it is, how it thinks, and the approval ceremony in detail.
- [Deployment guide](DEPLOYMENT-GUIDE.md): host shapes and the rest of the install.
