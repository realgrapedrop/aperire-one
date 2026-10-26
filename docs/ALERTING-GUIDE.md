# Aperire One Alerting Guide

How to wire up alert delivery so the dashboard reaches you when something fires. For a validator operator who wants alerts by email, phone push, or chat. Covers email via Resend, ntfy push (public and self-hosted), webhooks (Discord / Slack / generic), subscribing devices, verifying delivery, and troubleshooting.

The Insights tab evaluates rules and writes alert events regardless of channel configuration. This guide covers getting those events delivered to humans.

---

## Quick reference

| | |
|---|---|
| Config file | `dashboard/config/channels.yaml` |
| Template | `dashboard/config/channels.yaml.example` |
| Secrets | `/etc/aperire/aperire.env` (env vars referenced by name in channels.yaml) |
| Reload after edits | `sudo systemctl reload aperire-server` (SIGHUP) |
| Verify config parsed | `journalctl -u aperire-server --since '30 sec ago' \| grep '\[insights\] channels'` |
| Verify delivery | Test Fire on the Insights tab, or `curl POST /api/insights/test_fire` |

---

## Channels supported today

| Channel | What it does | Status |
|---|---|---|
| `email` | Transactional email via [Resend](https://resend.com) | Shipped |
| `ntfy` | Push notification to phones / desktops via [ntfy](https://ntfy.sh) | Shipped |
| `webhooks` | POST to Discord, Slack, or any generic JSON receiver | Shipped |

Each rule lists the channel ids it should fire on. A rule with `channels: [email]` only sends email; `channels: [email, ntfy]` fans out to both. If a channel id appears in a rule but isn't defined in `channels.yaml`, the dashboard surfaces a validation alert on the Insights tab on next reload.

---

## Editing alert rules: two files

Alert rules live in two files, and only one of them is yours.

| File | Whose | What happens to it |
|---|---|---|
| `dashboard/config/rules.yaml` | The product's | Every install and every update replaces it. Don't edit it: a change here is lost on the next update, and a rule the product corrects reaches you through this file. |
| `dashboard/config/rules.local.yaml` | Yours | Nothing writes it: no install, no update, no fleet deploy. The installer creates it once, as comments, and never touches it again. |

A rule is named by its **metric and its severity**. An entry in your file with
the same pair overrides the shipped rule; a pair the shipped set doesn't have
is a new rule; `enabled: false` switches a shipped rule off. No file at all
means you run the shipped rules exactly.

**Change a threshold.** Only the fields you list move. The `op` is inherited
from the shipped rule, so a rule that warns *below* a number keeps warning
below it:

```yaml
rules:
  - metric: swap_used_pct
    severity: warn
    threshold: { op: ">=", value: 40 }
    duration: 900s
```

**Switch a rule off.** It stops evaluating, and anything it left firing is
retired on the next reload:

```yaml
  - metric: peer_count
    severity: warn
    enabled: false
```

**Add a rule of your own.** A metric and severity the shipped set doesn't have
inherits nothing, so give it the whole threshold, `op` included:

```yaml
  - metric: peer_count
    severity: critical
    threshold: { op: "<", value: 2 }
    duration: 300s
    channels: [email]
    action: This validator peers with a fixed set. Two left means one is gone.
```

Fields an entry may set: `threshold` (`op`, `value`), `duration`, `channels`,
`action`, `action_command`. Everything else about a rule comes from the
shipped one.

Apply both files without a restart:

```bash
sudo systemctl reload aperire-server
```

Then check what is in force. The Rules card on the Insights tab names both
files and how many rules yours changed, added or switched off, and the journal
says the same on every load:

```bash
sudo journalctl -u aperire-server --since '30 sec ago' | grep 'rules.yaml parsed'
# [insights] rules.yaml parsed: 33 rules (4P · 13C · 16W); shipped 33, rules.local.yaml: 2 overrides, 1 added, 1 disabled
```

Your file can never take the alerting down. If it won't parse, or an entry has
no metric, no severity, a pair repeated inside the file, or a new rule with no
threshold, the shipped rules load and stand, the Rules card reads WARN with the
reason, and the journal names the file:

```
[insights] rules.local.yaml: peer_count warn appears twice; the shipped rules stand and nothing from that file is applied
```

**Swap ships at one number for every role.** `swap_used_pct` warns at 40% and
turns critical at 50%, whether the box runs the node or only the dashboard. A
long-running Linux host parks pages in swap and holds them there without
reclaiming, and a steady amount sitting at the same level for weeks is
ordinary, on the node's own box included: what is worth acting on is swap
that keeps climbing, or `vmstat 1` showing active paging (si/so above zero),
not the raw percentage alone.

If you want a stricter number on one box, `scripts/set-alert-role-defaults.sh`
still sets it, written once into `rules.local.yaml` as an override and never
touched again:

```bash
bash scripts/set-alert-role-defaults.sh --role=co-located --swap-warn=15
sudo systemctl reload aperire-server
```

### Coming from a release where you edited rules.yaml

If you tuned `rules.yaml` on this host, move those changes across before the
next update replaces it. Two files go in beside your own: the shipped rules
**your file descends from** (the baseline) and the shipped rules of the
release **you are about to deploy**.

```bash
# dry run: says what it would do, writes nothing
bash scripts/migrate-rules-local.sh --shipped=BASELINE.yaml --current=RELEASE.yaml
# do it, backing up both files first
bash scripts/migrate-rules-local.sh --shipped=BASELINE.yaml --current=RELEASE.yaml --write
sudo systemctl reload aperire-server
```

**The baseline** is what your changes are measured against. It has to be the
version your file descends from, not the newest one: a rule the product added
since would otherwise look like a rule you deleted and be written back as
`enabled: false`. Updates used to skip `rules.yaml` entirely, so on a host that
has been running a while that version is older than its last deploy.

**The release file** is what stops the migration writing down things you no
longer need to say. A difference against a baseline that old is a difference
somebody made on this host, and often the product has since caught up with it:
alert text pasted onto a box by hand in August ships in the release now, and a
rule you added yourself may be a rule everyone gets. Written into
`rules.local.yaml`, each one pins today's value on this host for good and stops
every later correction to it reaching you. With `--current` those are dropped,
each with a line saying which fields went and why, and what is left is what
this host still says differently. A rule you switched off is never dropped:
that is your statement, and no release can make it for you.

It backs up both files, refuses if `rules.local.yaml` already has entries, and
writes nothing until it has shown two things: that the differences reproduce
the rules this host runs, and that the pruning changes nothing this host will
run on the release. Run it twice and the second run finds nothing to do.

Already migrated without `--current`? Take the redundant entries back out, any
time, with the same result:

```bash
bash scripts/migrate-rules-local.sh --prune --current=RELEASE.yaml          # dry run
bash scripts/migrate-rules-local.sh --prune --current=RELEASE.yaml --write
```

That run replaces `rules.yaml` with the release's file as well, and says so
before it does. It has to: what it takes out of your file has to come back
from the shipped one, or a threshold you pinned would simply be gone from your
alerts until the update landed. It is the file the update would put there
anyway.

## Telling an operator what to do about it

An alert says what happened. A rule can also say what to do about it, and why
it matters, with two optional fields:

```yaml
  - metric: node_unreachable_s
    severity: critical
    threshold: { op: ">=", value: 180 }
    duration: 0s
    channels: [email, ntfy]
    action: >-
      Three minutes is longer than any normal restart, so treat the node as
      down rather than busy. Check the service is running on the node's own
      host, then read why it stopped. Every minute here is missed validations.
    action_command: sudo systemctl status rippled && sudo journalctl -u rippled -n 50 --no-pager
```

| Field | What it is | Cap |
|---|---|---|
| `action` | One or two plain sentences: what to do, and why it matters | 400 characters |
| `action_command` | A single command line to copy and run | 200 characters |

Both are optional, and like any other field they are set in your own
`rules.local.yaml` (an entry naming the same metric and severity carries the
text; the rest of the rule stays the shipped one). Where they appear:

- On the alert's row in Insights. Hover the row and the text is under **What to do**, with the command below it. A row whose rule carries an action is marked, so you know there is something to read.
- In the notification itself, so the email or push that wakes you already carries the instruction.
- On a Test Fire delivery, which carries a placeholder line so you see where the instruction lands before the first real page.

They are per-rule, not per-metric, so a warn and a critical on the same metric
can say different things. That is usually the point: at 15 seconds of a node
being unreachable the answer is "wait, it is probably your own restart", and at
three minutes it is "go look now".

A rule with no clear action is better left without one than given filler. When
a rule has no `action`, the metric's entry in `knowledge/metric-alerts.yaml`
answers instead, exactly as it did before, and its first recommendation shows
under **First check**.

Both fields are text and nothing more. Aperire never runs an `action_command`,
and never substitutes a live value into either field, so write them as static
lines. Anything that looks like a template (`{{value}}`, `$HOME`) reaches you
as those literal characters. The alert row already names the node, the
threshold and the reading, so the instruction does not need to repeat them.

A field that is not a string, or is over its cap, is dropped and the reason is
logged. The rule still evaluates: losing the alert because its help text was
malformed would be the wrong trade. Check the journal if an action you wrote
does not appear:

```bash
sudo journalctl -u aperire-server | grep 'rules.yaml'
```

Secrets (Resend API key, ntfy auth token) live in environment variables loaded from `/etc/aperire/aperire.env`. `channels.yaml` references them by name only. Never put a secret directly in the yaml.

---

## Which node an alert is about

Every email, push and webhook carries the same four labelled lines, so you can tell which node fired and what kind of node it is.

| Line | What it says | Where it comes from |
|---|---|---|
| Node | The node's name and its role: `validator-1 (validator)` | The label in the node's `fleet-link.json`, else its `fleet.yaml` label, else the machine's short name. An aggregator uses its own `fleet.yaml` label first. The role is `validator`, `stock node` or `aggregator` |
| Host | The machine's hostname: `srv1` | The hostname. `APERIRE_HOSTNAME` overrides it |
| Node key | The node's public key, shortened: `n9KmK…6sWW` | The key the node reports for itself |
| Link | The address of this node's dashboard | `APERIRE_PUBLIC_URL` when set, else `public_url` in `authn.yaml`, else the fleet row's `dashboard_url` |

The email subject, the push title and the Discord and Slack titles name the node too: `[WARN] load_factor on validator-1` in the email and the webhooks, `WARN - load_factor on validator-1` on the phone. In the email the four lines sit under the metric name. In the push they follow the threshold and value lines. In Discord and Slack they're fields under the threshold and value.

A `generic` webhook carries the same facts as JSON under `node`, beside the existing keys:

```json
"node": {
  "name": "validator-1",
  "role": "validator",
  "hostname": "srv1",
  "node_key": "n9KmKBEvJkZu3m8HqW2X7bTyDhCfN4ePaLsQ5vRjGt1UxA6sWW",
  "url": "https://dash.example.com"
}
```

The key is in full there, and a fact not read yet is `null`, so a receiver can tell it from a missing key.

A fact the dashboard can't read says so in words, never a blank:

- `role not read yet` means the dashboard hasn't heard from its node since it started. It does not mean stock node.
- `no local node` on an aggregator's Node key line: an aggregator has no node of its own to read.
- `no dashboard address is set` means no address another machine could open is configured. A `localhost` or `127.0.0.1` address doesn't count, because a link to it works only on the host itself. Set `public_url` in `authn.yaml` and restart the dashboard, and the next alert carries a link. The dashboard reads that file once, at start.

One limit:

- **In a split install (Shape B) the Host line names the machine the dashboard runs on,** not the validator's host, and so does the Node line when there is no name from pairing or `fleet.yaml`. Set `APERIRE_HOSTNAME` to name the node the way you want it. CPU, memory and disk alerts there still describe the validator's host, which the relay reports.

---

## Email via Resend

[Resend](https://resend.com) is a transactional email provider. Free tier covers 3,000 emails per month, enough for one validator's alert volume even in a noisy week.

### Setup

1. **Create a Resend account** at <https://resend.com>.
2. **Verify your sender domain.** Resend requires DNS records (SPF, DKIM, optionally DMARC). The dashboard DNS UI walks you through them. Typical propagation is ~10 minutes.
3. **Generate an API key.** Use a key with "Sending access" scope only. Don't grant management or billing rights.
4. **Store the key in `aperire.env`:**

   ```
   RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

   The service installer already creates the file `0640 root:<dashboard-user>`, where `<dashboard-user>` is the account the dashboard runs as (the one that ran the installer). Root owns it, the dashboard's group can read it, nobody else can. Confirm rather than reset:

   ```bash
   ls -l /etc/aperire/aperire.env      # -rw-r----- root <dashboard-user>
   ```

   If it looks wrong, name that same account when you repair it. There is no `aperire` group; chowning the file to a group the dashboard is not in locks it out of its own secrets:

   ```bash
   sudo chown root:"$(systemctl show -p User --value aperire-server)" /etc/aperire/aperire.env
   sudo chmod 640 /etc/aperire/aperire.env
   ```

5. **Edit `channels.yaml`:**

   ```yaml
   channels:
     email:
       provider: resend
       api_key_env: RESEND_API_KEY
       sender: "Aperire <alerts@your-domain.example>"
       recipients:
         - on-call@your-domain.example
         - operator-2@your-domain.example
   ```

   The `sender` address must use a domain you verified in step 2. The display name (`Aperire One`) is whatever you want recipients to see in their inbox.

6. **Reload and verify:**

   ```bash
   sudo systemctl reload aperire-server
   journalctl -u aperire-server --since '30 sec ago' | grep '\[insights\] channels'
   # expected: "channels.yaml parsed: 1/3 active (email=true ntfy=false webhooks=0)"
   ```

7. **Test fire.** The Insights tab's **Test Fire** button is the simplest route and needs nothing extra. Every `/api/` route requires a signed-in session, so the `curl` equivalents below only work with a session cookie. See [Calling the API from a shell](#calling-the-api-from-a-shell).

   ```bash
   curl -s -X POST http://127.0.0.1:7800/api/insights/test_fire \
     -b "apr_sess=$APR_SESS" \
     -H 'content-type: application/json' \
     -d '{"mode":"live","channels":["email"]}' | jq
   ```

   A successful response carries `delivered: true` and Resend's `message_id`. Check the recipient inboxes within ~30 seconds.

### Common email issues

- **DKIM/SPF not yet propagated.** Resend's dashboard shows verification status per domain. Wait until all rows show "Verified" before sending. Premature sends can land in spam and dent domain reputation.
- **Recipients in your own domain not receiving.** Many corporate Microsoft 365 / Google Workspace setups quarantine new senders. Check the recipient's quarantine folder first; whitelist the sender if needed.
- **Sender display name truncated.** Some clients drop the display name when it's too long. Keep it under ~30 chars.

---

## ntfy push notifications

[ntfy](https://ntfy.sh) is a publish/subscribe push service. The dashboard publishes alert messages to a topic on a server; subscribed devices receive push notifications in near real-time. Two deployment paths.

### Concepts: server, topic, subscription

- **Server.** The ntfy host (e.g. `https://ntfy.sh` for the public service, or `https://ntfy.your-domain.example` for self-hosted).
- **Topic.** A string identifying the message channel on that server. Messages are isolated per topic; subscribers see only the topic(s) they subscribe to. The topic is the unit of access control.
- **Subscription.** A client (typically the ntfy app on a phone) opens a persistent connection to the server and receives any new messages posted to its subscribed topics.

The server URL and topic name together are the address. `ntfy.sh/foo` is unrelated to `ntfy.example.com/foo`. Completely separate feeds.

### Path A: Public ntfy.sh (zero infrastructure)

Works immediately, no server to host. The trade-off: ntfy.sh topics are publicly readable by anyone who knows the topic name. Treat the topic name itself as a low-grade secret.

1. **Choose a hard-to-guess topic name:**

   ```bash
   # 32 hex chars, prefix it so it's recognizable
   echo aperire-$(openssl rand -hex 16)
   # → aperire-7c8a4f2b1d9e6c3a5b8f2d1e4c9a6b3d
   ```

2. **Edit `channels.yaml`:**

   ```yaml
   channels:
     ntfy:
       provider: ntfy
       base_url: https://ntfy.sh
       topic: aperire-7c8a4f2b1d9e6c3a5b8f2d1e4c9a6b3d
       token_env: NTFY_TOKEN          # leave empty for public ntfy.sh
       severity_priority:
         warn:     default
         critical: high
         page:     urgent
   ```

3. Reload and verify as in the email section.

### Path B: Self-hosted ntfy (recommended for production)

Self-hosting gives you auth, retention, and ACLs. Running an ntfy server, putting TLS in front of it, and creating users and access tokens are ntfy's own operations, documented at [docs.ntfy.sh](https://docs.ntfy.sh/install/) far better than a mirror here could stay. A stale copy of someone else's setup guide is worse than a link.

What Aperire One needs from it is only this: a base URL, a topic, and a token with publish rights on that topic. Put them in `channels.yaml`:

```yaml
channels:
  ntfy:
    provider: ntfy
    base_url: https://ntfy.your-domain.example
    topic: aperire-alerts
    token_env: NTFY_TOKEN          # the token itself lives in the env file
    severity_priority:
      warn:     default
      critical: high
      page:     urgent
```

The token is read from the environment, never from this file. See `config/channels.yaml.example` for the full annotated shape and [Security notes](#security-notes) for where the env file lives.

Devices then subscribe with a token of their own (read rights are enough).

### Subscribing devices

The publish side delivering messages to the server is half the job. The other half is each device maintaining a subscription so push notifications actually arrive.

#### Phone (Android / iOS)

1. Install the ntfy app from your platform's app store.
2. Open the app, tap **+** to add a subscription.
3. **Critically: tap "Use another server"** before entering the topic. The default is `ntfy.sh`. If you self-hosted, you must override this, otherwise the app subscribes to a different server and never receives your messages.
4. Server URL: `https://ntfy.your-domain.example` (or `https://ntfy.sh` if using path A).
5. Topic: the exact topic name from `channels.yaml`. Case-sensitive, hyphens matter.
6. If your server requires auth: open the app's **Settings → Users → Add user** and add the subscriber token (`tk_phone_subscriber_token_here`). Subscriptions automatically use the matching server's user credentials.
7. Save the subscription. The app should immediately show "Connected" or similar.
8. **Grant notification permission** at the OS level (Android / iOS settings → ntfy → Notifications → Allow).

#### Android-only: make notifications actually wake the phone

Android's battery optimization aggressively kills background services. Without these settings, ntfy will receive messages but show them with significant delay or skip them entirely:

- Inside ntfy app: enable **Instant delivery** for the subscription (uses Firebase Cloud Messaging on Android, or a foreground service on F-Droid builds).
- OS Settings → Apps → ntfy → Battery → set to **Unrestricted** (sometimes called "Don't optimize").

#### Desktop (web client)

Visit your ntfy server URL in a browser, e.g. `https://ntfy.your-domain.example/aperire-alerts`. The web UI subscribes via Server-Sent Events. Browser notifications must be granted permission once.

For a desktop persistent client, ntfy also publishes a CLI: `ntfy subscribe aperire-alerts`.

---

## Webhooks: Discord, Slack, generic

Each webhook is one entry under the `webhooks:` list. Three formats:

- **`discord`** posts an embed with a severity-coloured side-bar. The URL comes from a Discord channel's Edit Channel → Integrations → Webhooks → New Webhook → Copy URL.
- **`slack`** posts an attachment with a coloured bar and two-column fields. The URL comes from <https://api.slack.com/apps> → your app → Incoming Webhooks → Add New Webhook to Workspace.
- **`generic`** is a flat JSON POST to any HTTP receiver. Stable schema (`schema: aperire.alert.v1`) carrying every alert field, so a downstream listener (Zapier, n8n, a custom endpoint, a PagerDuty Events API bridge) maps fields without guessing.

PagerDuty has no dedicated format. Reach it through `generic` pointed at its Events API.

### Setup

Add one entry per target to `channels.yaml`:

```yaml
channels:
  webhooks:
    - id: discord-ops
      format: discord
      url: https://discord.com/api/webhooks/ID/TOKEN

    - id: slack-validators
      format: slack
      url: https://hooks.slack.com/services/T00/B00/XXXX
      severity_filter: [critical, page]      # skip warn-tier on Slack

    - id: generic-bridge
      format: generic
      url: https://hooks.example.com/aperire
      auth_header_env: WEBHOOK_BEARER         # optional Authorization header
```

Per-entry keys:

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique label, shown in dashboard logs and each alert's delivery summary. |
| `format` | yes | One of `discord` / `slack` / `generic`. |
| `url` | yes | POST target. For Discord and Slack the URL *is* the credential. |
| `auth_header_env` | no | Env-var name whose value is sent as the `Authorization` header, for generic receivers behind a bearer / API key. |
| `severity_filter` | no | List of severities this target accepts (`warn` / `critical` / `page`). Omit to accept all. Useful for routing only `page` to a paging bridge. |

Rules refer to webhooks with the singular channel id **`webhook`**. `channels: [webhook]` fans out to every entry in the list whose `severity_filter` admits the alert. Secrets for `auth_header_env` live in `aperire.env`, never in the yaml. An empty `webhooks: []` is the correct neutral state; the Channels strip pill on the Insights tab shows "0 webhooks".

Reload and verify as in the email section, then Test Fire to confirm delivery.

---

## Verifying delivery: the Test Fire panel

Once channels are configured, prove the path works before the first real alert.

### Dry run (validates config without sending)

On the Insights tab, click **Test Fire → Dry Run**. Or via API:

```bash
curl -s -X POST http://127.0.0.1:7800/api/insights/test_fire \
  -b "apr_sess=$APR_SESS" \
  -H 'content-type: application/json' \
  -d '{"mode":"dry_run"}' | jq
```

Returns a per-channel preview: who the email would go to, what the ntfy message would look like, what URL it would post to, what priority. No emails sent, no pushes delivered, no rate-limit budget consumed.

Any channel that's misconfigured shows up in the response with `attempted: false, reason: 'not configured'`, a useful sanity check after editing `channels.yaml`.

### Calling the API from a shell

There is no loopback exemption: `/api/` routes are gated on a signed-in session whether the request comes from the internet or from `127.0.0.1`. The examples here assume `APR_SESS` holds a session cookie from a browser you are already signed into. Copy it from devtools (Application → Cookies → `apr_sess`) and export it:

```bash
export APR_SESS='…'
```

If you would rather not, use the Test Fire button on the Insights tab; it does the same thing with the session you already have.

### Live test (actually delivers)

On the Insights tab, click **Test Fire → Live Test**. Or via API:

```bash
# Through every configured channel:
curl -s -X POST http://127.0.0.1:7800/api/insights/test_fire \
  -b "apr_sess=$APR_SESS" \
  -H 'content-type: application/json' \
  -d '{"mode":"live"}' | jq

# Through one channel only, useful when debugging:
curl -s -X POST http://127.0.0.1:7800/api/insights/test_fire \
  -b "apr_sess=$APR_SESS" \
  -H 'content-type: application/json' \
  -d '{"mode":"live","channels":["ntfy"]}' | jq
```

Real deliveries land in the configured destinations, prefixed with `[TEST]` so recipients can immediately tell it's not a real incident.

Live tests are rate-limited to 5 per hour per channel. The response carries `rate_state` showing how many of the 5/hour you've used, and `configured` naming the channels a live test reaches: `email` and `ntfy` as true or false, and `webhooks` as a count. A channel with no working send setup, such as an email block whose API key variable is unset, reads false or 0. The Test Fire card on the Insights tab lists its channels from this.

### Optional: token-protected live tests

If you want to prevent anyone with dashboard access from accidentally spamming on-call recipients, set a second-factor token in `/etc/aperire/aperire.env`:

```
APERIRE_TEST_TOKEN=some-long-random-string
```

The Test Fire UI then prompts for the token before firing live; API callers must include it in the request body:

```bash
curl -s -X POST http://127.0.0.1:7800/api/insights/test_fire \
  -b "apr_sess=$APR_SESS" \
  -H 'content-type: application/json' \
  -d '{"mode":"live","token":"some-long-random-string"}' | jq
```

Dry run is never gated.

---

## Troubleshooting

### Email arrives, ntfy doesn't (or vice versa)

Per-channel issues are independent. Test fire each one in isolation (`channels: ["email"]`, `channels: ["ntfy"]`) to localize the problem. Server-side `delivered: true` means the message reached the channel provider; whether it then reached the human recipient depends on per-channel mechanics below.

### "delivered: true" but no notification on phone (ntfy)

Most common cause: the phone is subscribed to a different server URL than Aperire One publishes to. The two URLs must match exactly, including hyphens and protocol scheme.

Diagnostic: in a phone browser (not the ntfy app), open

```
https://<your-ntfy-server>/<your-topic>/json?poll=1&since=24h
```

If this returns JSON with the test message id, the server is reachable from the phone and the message is on it. The issue is then app config (wrong server, missing token, instant delivery off, or notification permission denied).

If this errors or hangs, the server URL itself is wrong or unreachable from the phone's network.

### "delivered: true" but no email

- Check spam / quarantine folders first.
- Resend dashboard shows per-message logs at <https://resend.com/emails>. The `message_id` from the test fire response should appear there with delivery status.
- If status is "Bounced," the recipient address is invalid. If "Delayed," the recipient's mail server is rate-limiting; usually clears within an hour.

### Title on phone shows replacement characters (`�`)

HTTP headers are ASCII-only, so a non-ASCII character in the title gets mangled in transit. Aperire One sends ASCII-safe titles, so this shouldn't happen on a current build. If you see it, you're on an older build: pull the latest and restart the dashboard.

### Notifications work briefly then stop on Android

Battery optimization killing the ntfy background service. Set the ntfy app to "Unrestricted" battery mode (OS Settings → Apps → ntfy → Battery), and confirm "Instant delivery" is on inside the ntfy app for the subscription.

### Multiple operators: some get notifications, some don't

Each operator's phone needs its own subscription. ntfy isn't a multi-cast service like email. There's no central recipient list. Every operator who wants alerts adds the subscription themselves on their device.

If you want central management of who gets what, use the email channel. For ntfy, document the server URL and topic in your team's runbook so new operators can self-subscribe.

### `[insights] channels.yaml parsed: 0/3 active`

YAML parse error or schema validation failure. Check `journalctl -u aperire-server -p err --since '5 min ago'` for the specific message. Most common: indentation drift, missing required field (`provider`, `api_key_env`).

---

## Security notes

- **Public ntfy.sh topics are world-readable** to anyone who guesses the topic name. The 32 hex characters from `openssl rand -hex 16` make guessing impractical, but the topic *can* leak. Anyone you tell the topic name to gets full access. For sensitive deployments, self-host with auth.
- **Self-hosted ntfy with `auth-default-access: deny-all`** is the secure default. Every topic requires explicit grants. Two-token pattern (publisher write-only, subscriber read-only) means a leaked subscriber token can read messages but can't fake new ones.
- **Secrets only in `aperire.env`,** never in `channels.yaml`. The yaml is committed to source control; the env file isn't.
- **A URL in `channels.yaml` is a URL the dashboard will POST to.** Webhook and ntfy targets are taken as written: no allow-list, no host check, and no refusal for an address on your own network. That is deliberate, because a self-hosted ntfy on `192.168.1.10` is a normal setup and a guard that blocked it would break the common case. It does mean that anyone who can edit that file can make the dashboard send a POST to anything it can reach, your node's admin port included. Treat write access to `channels.yaml` as equivalent to shell access on the dashboard host: root-owned, mode 0644 or tighter, and changed through the same review as any other config.

- **No secrets in alert content.** Aperire One's alert messages contain metric name, threshold, value, and the node's identity (name, role, hostname, shortened node key, dashboard link). No API keys, no tokens, no transaction details. If you author custom rules with sensitive values in the description, they'll appear in delivered alerts.
- **Every alert carries the hostname and the dashboard link.** On a public ntfy.sh topic, anyone who learns the topic name can read them. If a validator's hostname or dashboard address is private, use a self-hosted ntfy with auth, or email only.

---

## What's next

- **Page-tier 15-min re-fire cadence.** Page-severity alerts re-deliver every 15 minutes while still firing, so a missed first notification doesn't leave an unacknowledged page hanging.
