# Aperire One Authentication Guide

How operators sign in to Aperire One, and how you control who can. Aperire One uses passkeys (WebAuthn), no passwords and no identity provider. This guide covers first-time setup, day-to-day sign-in, adding and removing operators, roles, and getting back in after a lost device.

For a screenshot-by-screenshot walkthrough of creating and registering an operator, see the [Enrollment Guide](ENROLLMENT-GUIDE.md). For trust boundaries and the request flow, see the [Architecture Guide](ARCHITECTURE-GUIDE.md). For first-time install, see the [Deployment Guide](DEPLOYMENT-GUIDE.md).

## At a glance

| | |
|---|---|
| Method | Passkeys (WebAuthn): Touch ID, Face ID, Windows Hello, YubiKey |
| Identity | The operator's email address is the username. One field, globally unique. |
| Bootstrap | Open the dashboard in a browser and it walks you through the first admin. Or SSH to the host: `aperire-auth add <email> --role <admin\|monitor>` |
| Sessions | Server-side; the cookie carries an opaque id, capped at 7 days |
| Idle timeout | 30 min default, set in `dashboard/config/authn.yaml` |
| Manual lock | `Cmd/Ctrl+Shift+L`, or the account menu (top-right), then Log out |

The dashboard serves nothing without a valid session. Every tab and every `/api/*` response requires a passkey sign-in first.

## What it protects, and what it doesn't

Passkeys are cryptographic and bound to the origin, so there's no password to phish or steal, and a credential enrolled for one dashboard can't be replayed against another. Session cookies are `HttpOnly` and `SameSite=Lax`, `Secure` over the tunnel, with a custom-header CSRF check on the lock and idle-touch calls.

Two limits worth knowing:

- **Shell access on the dashboard host outranks everything.** `aperire-auth` is the only way to add, remove, or re-role an operator, and it runs on the host. Anyone with a shell as the dashboard's account, or with sudo on the host, can manage operators at will. That's by design: that account owns the database. On a fresh install it's `aperire-dashboard`, which has no login, so managing operators takes your sudo password. Protect the SSH key accordingly.
- **A passkey is only as safe as the device holding it.** If someone can produce the biometric on a stolen, unlocked device, they can sign in. Set device-level protections (PIN, biometric lockout, remote wipe). Aperire One treats one passkey as sufficient and doesn't layer TOTP on top, matching FIDO and NIST guidance for platform-bound credentials.

Deeper mechanics (challenge handling, replay counters, rate-limit internals) live in the Architecture Guide and the ADRs.

---

## First-time setup

### 1. Install the CLI

Run once on the dashboard host as the dashboard user (no root):

```bash
bash <repo>/scripts/install-aperire-cli.sh
```

This drops two symlinks in `~/.local/bin`: `aperire-auth`, the operator CLI this guide covers, and `aperire`, the interactive menu that wraps every script in `scripts/`. Open a new shell (or `hash -r`) and both are on your PATH.

### 2. Set your origin in `authn.yaml`

Edit `dashboard/config/authn.yaml`:

```yaml
public_url: https://your-dashboard.example.com
rp_id:     your-dashboard.example.com
```

`rp_id` is `public_url`'s host: no scheme, no port. They must match, or WebAuthn refuses to issue or use credentials. For local dev, use `http://localhost:7800` with `rp_id: localhost`.

Restart the dashboard to pick up the change:

```bash
sudo systemctl restart aperire-server
```

### 3. Add the first operator

**Open the dashboard in a browser.** A box with no operators has nothing to
sign in to, so it shows you a setup page instead of a lock screen, whichever
address you ask for. Type the email you want to sign in with, enroll a passkey,
and you land on the dashboard already signed in. The first account is always
`admin`, decided by the server and not by anything the browser sends: somebody
has to be able to approve Advisor actions.

Creating that account is the only thing this product ever writes without a
signed-in operator, and the window it happens in is open only while the box has
never had an operator at all. The moment the first one exists, the claim stops
being possible, for you as much as for anyone else: adding a node from here on
is a Settings & Updates job, and this page can never hand the dashboard to
somebody new. Nothing needs to be turned off afterwards.

**Nothing reopens it.** Not a restart, not a config change, and not removing
every operator later: the close is recorded, and the record outlives the
accounts. A box that ends up with nobody on it is recovered from the machine,
with `aperire-auth add` in a shell there, and that is the property this buys. A
dashboard that has been owned once never accepts an unauthenticated write
again, whoever reaches the port.

The page says which of the two states it is in, at the top, every time you open
it: setup is open because this box has never had an operator, or setup closed
on a named day, with the recovery beside it.

Enrolling ends the visit: the moment the account exists you land on the
dashboard, already signed in. Adding a node is a separate step from there, in
**Settings & Updates → Add a node**: where the node runs, the command to run
on that machine, a test that watches for the node's first frame, and the
Advisor if you want it. That sequence is in the
[Deployment Guide](DEPLOYMENT-GUIDE.md) under STEP 3, and it stays in
Settings & Updates for as long as this dashboard exists, not only on the first
visit.

**Or from the shell, if you would rather:**

```bash
aperire-auth add primary@your-org.example --role admin
```

The role is required, chosen at creation. Your first operator wants `admin`.
`add` creates the account and prints the single-use enrollment link right away
(and emails it when an email channel is configured). See the roles table below.

Use the CLI when there is no browser that can reach the box yet, or when you
are scripting an install. Either route produces the same account; the browser
route is one fewer SSH session.

### 4. Enroll your first passkey

`add` already printed an enrollment URL. If it expired before you used it, re-issue one:

```bash
aperire-auth magic-link primary@your-org.example
```

Open the URL on the device you'll use for the dashboard. The lock-screen redeems the token and prompts for a biometric. One Touch ID / Face ID / Windows Hello tap and you're enrolled and signed in.

With `magic_link.send_via_email: true` in `authn.yaml`, the URL is also emailed via the Resend channel from `channels.yaml`. The CLI always prints it to stdout as a fallback.

---

## Day-to-day

### Signing in

1. Visit the dashboard URL.
2. Type your email address in the single field, click **Sign in with passkey**.
3. Approve the biometric prompt.

You land on the dashboard. Sessions are capped at 7 days; in practice the idle timeout is the boundary you'll meet.

### Locking

- Press `Cmd+Shift+L` (macOS) or `Ctrl+Shift+L` (Linux/Windows) to lock immediately.
- Or open the account menu (the pill in the top-right), then click **Log out**.
- Or do nothing: after the idle timeout with no input, the session stops working. It is marked revoked the next time anyone signs in, and its row is deleted at the first sign-in after it is 7 days old. The Settings page counts only sessions that can still sign in. `list-sessions` shows `active` for any session inside the 7-day cap, so read `last_activity` for idleness.

Locking sends you to the lock-screen with a `next` back to where you were; signing in returns you there.

### Adding a passkey on a new device (self-serve)

1. Type your email, click **Sign in with passkey**.
2. The screen flips to enrollment with a "new device" callout.
3. Click **Send enrollment link**, then open the email and click the link.
4. Approve the biometric prompt. One prompt total, and you're in.

The link is single-use, expires in 15 minutes (configurable), and is rate-limited to 3 per hour per operator. If the email doesn't arrive, check the dashboard log for `[authn]` enrollment lines.

### Adding a passkey on a new device (admin-issued)

When email isn't set up, or you want to hand the link over out-of-band:

```bash
aperire-auth magic-link <email>
```

Send the single-use URL over a private channel. The operator pastes it into a browser on the new device and approves the biometric prompt.

---

## Managing operators

Everything below the shell block is also on the dashboard. Open the menu, pick **Settings & Updates**, and the **Operator passkey enrollment** panel lists every operator with their role, their passkeys, when each was last used, and whether a link is out for them. From there an admin can:

| Button | Does | Passkey asked |
|---|---|---|
| **Add operator** | Creates the account with the role you pick and issues their enrollment link. The link is shown once, with Copy, and emailed if the dashboard has an email channel | Yes, when the new operator is an admin |
| **New passkey link** | A fresh single-use link for an existing operator, for a new device or a lost one | No |
| **Change role** | Promote to admin or demote to monitor. A demotion ends that person's open sessions | Yes, when promoting |
| **Revoke** / **Revoke all** | Drops one passkey, or every passkey the operator has. Sessions signed in with a dropped passkey end | No |
| **Remove** | Deletes the operator, their passkeys, sessions and unused links, after a confirm | No |

The page refuses two things the CLI only warns about: removing or demoting yourself, and removing or demoting the last admin. A root shell can always undo a mistake; a page cannot, so it does not offer one. Every change is written to the operator audit (below the table) with the name of the admin who made it, and any change to who may approve pushes the new trust set to every fleet node and to this host's Advisor before the page answers, one result row per node.

The same operations from a shell on the host:

```bash
aperire-auth list                          # all operators
aperire-auth add <email> --role monitor    # add (prints their enrollment URL)
aperire-auth list-credentials <email>      # an operator's enrolled passkeys
aperire-auth revoke <email | credential-id>        # revoke one passkey (e.g. lost device)
aperire-auth fleet-trust-push [--node L]   # re-send the trust set to fleet nodes
aperire-auth list-sessions <email>         # sessions: active, expired or revoked
aperire-auth revoke-session <session-id>   # force sign-out from one device
aperire-auth del <email>                   # remove operator + passkeys + sessions
```

Email is the identity, so there's no rename. To change an address, `del` the operator then `add` the new one; the old passkeys don't carry over (they were bound to the old email).

Adding, removing, or re-roling an operator does **not** need a dashboard restart, the dashboard re-queries the database on every request. Session-policy changes in `authn.yaml` (idle timeout and the like) do need a restart, since the server reads that file at startup. The CLI re-reads it on every invocation.

## Roles

Two roles, one difference: who may approve an Advisor action against the node. Both see the same dashboard. Hiding read-only data from a colleague isn't a security property.

| Role | Dashboard | Advisor actions | Assigned |
|---|---|---|---|
| `admin` | Everything | May approve and run; their passkey is copied into the Advisor's trust store by `advisor-sync` | `add <email> --role admin`, or `set-role <email> admin` later |
| `monitor` | Everything (same UI) | None; their passkey is never trusted for approvals | Any account, via `set-role <email> monitor` |

Change a role in either direction on the host:

```bash
aperire-auth set-role colleague@your-org.example admin     # promote
aperire-auth set-role colleague@your-org.example monitor   # demote
```

What happens right away:

- **The change binds live.** The role is read from the account on every request, so a demotion takes effect on the person's next click, no re-login and no waiting for a session to expire. Their header pill (`name@admin` / `name@monitor`) updates on its next poll.
- **The Advisor's trust follows.** `set-role` re-runs `advisor-sync` itself, dropping a demoted passkey and adding a promoted one. `revoke` and `del` ride the same auto-sync, and a passkey enrolled in the browser asks for the same sync through a private socket the Advisor installer sets up (`scripts/install-trust-sync-grant.sh`; the store is rebuilt from the database, nothing the dashboard sends goes into it). `aperire-auth advisor-trust` shows what the Advisor currently trusts.
- **And so does the fleet.** On a host with a `fleet.yaml`, `add`, `del`, `revoke` and `set-role` also push the new trust set to every registered node, and enrolling a passkey in the browser pushes it too. See "Keeping the fleet's trust current" below for what that means when a node is down.
- **Demoting the last admin is allowed from the shell, with a loud warning, and refused on the page.** It leaves nobody able to approve Advisor actions. Shell access outranks the role system, so the way back is the same command: `set-role <email> admin`. Settings will not offer it: promote somebody else first.

---

## Keeping the fleet's trust current

Skip this if you run one node. It only applies to a host with a `dashboard/config/fleet.yaml`.

Every node's Advisor holds its own copy of the passkeys allowed to approve there. That copy arrives as a signed **trust bundle** pushed from this host. A node that never received the current bundle refuses the ceremony, and the error names the passkey rather than the missing push, which reads as "my passkey is broken" to somebody holding one that works everywhere else.

So the push is automatic now:

| What you did | What is pushed | If a node doesn't take it |
|---|---|---|
| `aperire-auth del` / `revoke` / `set-role` | The new set, to every registered node | The command exits nonzero and names each node that refused |
| `aperire-auth add` | The current set, re-asserted | A warning only. A new operator has no passkey yet, so nothing changed; creating an account never fails because a node is down |
| A passkey enrolled in the browser | The new set, to every registered node | Enrollment still succeeds. The server logs the failure per node, and the Advisor tab shows that node as stale |

Only an admin's passkey is in the bundle, so a monitor enrolling changes nothing and nothing is pushed.

**When a push fails.** Nothing is retried automatically and nothing is rolled back: the change is real on this host, and the nodes that took it are current. The nodes that did not are still enforcing the previous set, which for a revocation means the revoked key still approves there. Fix it with the same command the failure prints:

```bash
aperire-auth fleet-trust-push                 # every node
aperire-auth fleet-trust-push --node <label>  # just one
```

The push reads the signing key, `fleet.yaml` and each node's Advisor token. When the dashboard runs as its own account, those are its files, so the push runs as that account and `sudo` asks for your password once. If it can't run (no sudo, or a file nobody can read), the command says why and exits non-zero: the local change is saved, and every node still trusts the previous set until a push succeeds.

**Seeing it before it bites.** Open the Advisor tab with a node selected. If that node's trust set is behind, the tab says so with the exact command, rather than leaving you to find out at an approval prompt. The same banner names this host when it is the local Advisor that is behind.

**Turning it off.** `--no-push` on any of those commands does the change and skips the push (`APERIRE_NO_TRUST_PUSH=1` for a non-interactive caller). Its one intended use is a fleet where some nodes run a build older than the trust-bundle route: push to those by hand once they are upgraded.

**One permission that has to be right.** Each node's `dashboard/config/fleet-trust.yaml` must be readable by the account its Advisor runs as, at mode `0640`. Otherwise the node answers every push with a 403 naming the path, and you meet the consequence three hops away as a refused passkey. The installers set it; `bash scripts/verify-after-restart.sh` reports it. A file that holds a `private_key:` (an aggregator's) stays `0600` to the dashboard's account instead, and the Advisor reads `fleet-trust.pub.yaml` beside it, which has the public keys only.

---

## Recovery: lost passkey, locked-out operator

If another admin can still sign in, no shell is needed: Settings, **New passkey link** on your row, and the link is shown once and emailed if email is set up. Enroll the new device from it, then **Revoke** the lost passkey from the same row.

Recovery starts with SSH to the dashboard host only when nobody is left who can sign in as an admin. If the only operator lost their only passkey:

1. SSH in as the user that owns `aperire.db` (typically `operator` in a default install).
2. Issue a fresh link: `aperire-auth magic-link <email>`
3. Open the printed URL on a working device and enroll a new passkey.
4. Optionally revoke the lost one:
   ```bash
   aperire-auth list-credentials <email>    # find the lost id
   aperire-auth revoke <id>
   ```

If SSH itself is the problem, that's host-level recovery, outside Aperire One's scope. Treat the dashboard host's SSH key as the ultimate recovery factor and protect it accordingly (hardware key, encrypted backup).

---

## Configuration reference (`dashboard/config/authn.yaml`)

```yaml
public_url: https://your-dashboard.example.com
rp_id:     your-dashboard.example.com         # host of public_url
rp_name:   Aperire                            # shown in OS biometric prompts

session:
  idle_timeout_minutes: 30                    # auto-lock after N minutes of no input
  idle_warning_seconds: 60                    # "Stay signed in" toast this long before lock

magic_link:
  ttl_minutes:    15                          # how long enrollment URLs live
  send_via_email: false                       # if true, CLI also emails the URL via Resend
  email_subject:  "Aperire — enroll your passkey"
```

| Key | Default | Notes |
|---|---|---|
| `public_url` | `http://localhost:7800` | Built into magic-link URLs and pinned as the WebAuthn origin. |
| `rp_id` | `localhost` | Must match `public_url`'s host. Changing it **invalidates all existing passkeys**, so operators re-enroll. |
| `rp_name` | `Aperire One` | Cosmetic, shown in the OS prompt ("Use Touch ID for Aperire One"). |
| `session.idle_timeout_minutes` | `30` | `0` disables the idle timeout (not recommended). |
| `session.idle_warning_seconds` | `60` | One click on the warning toast extends the session another full idle window. |
| `magic_link.ttl_minutes` | `15` | Caps the validity window; links are single-use regardless. |
| `magic_link.send_via_email` | `false` | Needs a working email channel in `channels.yaml`. |
| `magic_link.email_subject` | `"Aperire One — enroll your passkey"` | Subject line when `send_via_email: true`. |

Env-var overrides, handy for dev:

| Env var | Overrides |
|---|---|
| `APERIRE_DB_PATH` | the database path, default `<repo>/data/aperire.db`. Read by the dashboard and the CLI, so both always open the same file. The service installer writes it into `/etc/aperire/aperire.env` |
| `APERIRE_RP_ID` | `rp_id` (comma-separated for multiple origins) |
| `APERIRE_RP_ORIGIN` | `public_url` (comma-separated) |
| `APERIRE_RP_NAME` | `rp_name` |
| `APERIRE_AUTHN_YAML` | path to the `authn.yaml` file itself |
| `APERIRE_FORCE_SECURE_COOKIES` | `true` forces the `Secure` cookie flag regardless of detected protocol |

The database is not set in `authn.yaml`. `APERIRE_DB_PATH` is the single place it is configured, which is what keeps the dashboard and the CLI on the same file: point only one of them somewhere else and an operator you add never appears at the lock-screen. A `db_path` key in `authn.yaml` is ignored, and the CLI warns if it finds one.

---

## Cookies

| Cookie | Purpose | Lifetime |
|---|---|---|
| `apr_sess` | Session id | 7 days (the absolute session cap) |
| `apr_chal` | Per-ceremony challenge | 5 minutes |

Both are `HttpOnly` and `SameSite=Lax`. The `Secure` flag is set automatically when the dashboard sees HTTPS: the Cloudflare tunnel's `x-forwarded-proto`, a direct TLS socket, or `APERIRE_FORCE_SECURE_COOKIES=true`. On plain-HTTP `localhost` it's correctly off, because browsers reject `Secure` cookies over HTTP, which would otherwise break dev sign-in.

A custom `X-Aperire-CSRF: 1` header is required on `/auth/touch` and `/auth/lock`. Browsers won't attach a custom header cross-site without a CORS preflight, so that plus `SameSite=Lax` blocks CSRF with no token store.

---

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register/begin` | Registration options for a known operator |
| POST | `/auth/register/finish` | Verify registration, store credential, issue session |
| POST | `/auth/login/begin` | Authentication options; 412 + `enrollment_available` for a known operator with no passkey |
| POST | `/auth/login/finish` | Verify assertion, issue session |
| GET | `/auth/session` | Current session state |
| POST | `/auth/touch` | Idle-timeout signal (bumps last activity) |
| POST | `/auth/lock` | Revoke the session, clear the cookie |
| POST | `/auth/magic` | Redeem a single-use enrollment URL |
| POST | `/auth/enroll/request` | Self-serve enrollment link by email (rate-limited 3/hr) |

Everything else (`/`, `/insights.html`, `/api/*`, `/history`) is gated: HTML routes redirect to `/login.html?next=<path>`, API routes return `401`, when there's no session.

The Settings page's operator actions are under `/api/settings/operators/` (`add`, `link`, `role`, `revoke`, `remove`, with `add/begin` and `role/begin` issuing the passkey challenge for an admin grant) and the audit under `/api/settings/audit`. They answer `403` to a monitor, need the CSRF header on every write, and never carry a magic-link token anywhere but the one response that issued it.

---

## Troubleshooting

**"No matching passkey on this device."**
The browser has no passkey for this `rp_id`. Either you never enrolled on this device (use self-serve enrollment, or `aperire-auth magic-link <email>`), or you're on a different origin than where you enrolled (check `public_url` / `rp_id`).

**Works on `https://...` but not on `http://localhost:7800`.**
Each origin has its own passkey set. Enroll separately on each; credentials don't transfer.

**"Send enrollment link" button is missing.**
The email channel isn't configured (`channels.yaml` plus `RESEND_API_KEY`). Check the dashboard log for `[authn]` lines on a fresh sign-in attempt.

**429 "too many enrollment requests."**
Three per hour per operator, tracked in memory. Wait, or restart the dashboard to flush the counter. `del` then `add` also resets it, but that revokes the operator's enrolled passkeys along with the row.

**`apr_sess` is set but `/api/*` returns 401.**
The session is revoked or expired. Check `aperire-auth list-sessions <email>` and sign in again.

**Locked out and can't restart the dashboard.**
You don't need a restart to sign in, the session table is read on every request. If the lock-screen itself won't load or `/auth/login/begin` returns 500, check `data/logs/server-out.log`; the usual cause is a syntax error in `authn.yaml` crashing the server at startup.

---

## Implementation references

- Server: `dashboard/auth.ts`
- Tables: `dashboard/db.ts` (`auth_users`, `auth_credentials`, `auth_sessions`, `auth_magic_links`)
- Lock-screen: `dashboard/public/login.html`
- SSH CLI: `scripts/aperire-auth.sh`, `scripts/install-aperire-cli.sh`

For the request flow and trust boundaries, see the [Architecture Guide](ARCHITECTURE-GUIDE.md).
