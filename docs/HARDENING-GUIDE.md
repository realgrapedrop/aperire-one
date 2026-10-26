# Aperire One Hardening Guide

Lock down the host Aperire One runs on. This is for the operator taking a validator (or its dashboard) to production, who wants the box around the node treated with the same care as the node itself.

It covers the firewall, SSH, OS and rippled patching, a CIS baseline, the admin-RPC allow-list proxy, and a checklist to confirm it all took.

None of this is required to *run* Aperire. The install works without it. It's here because a validator is a public, always-on service, and the host around it deserves the same care as the node.

**Ordering depends on where the host lives.**

Behind a perimeter firewall, do this after the install ([Deployment Guide](DEPLOYMENT-GUIDE.md) first).

On a host with a public IP (any rented VPS), do the [fresh-host account](#on-a-fresh-cloud-host-the-operator-account-comes-first), [SSH](#ssh-hardening) and [Firewall](#firewall) sections **before** installing anything. The box is exposed from the moment it boots, and nothing in those three sections needs Aperire One to exist. The rest waits for the install.

---

## On a fresh cloud host, the operator account comes first

A cloud image typically boots with **root as the only account**. The SSH hardening below sets `PermitRootLogin no` plus `AllowGroups aperire-admins`, which in that state locks out the only login the host has.

Create the operator account first, prove it works, then harden:

```bash
useradd -m -s /bin/bash <operator>
usermod -aG sudo <operator>
groupadd aperire-admins
usermod -aG aperire-admins <operator>
mkdir -p /home/<operator>/.ssh
cp /root/.ssh/authorized_keys /home/<operator>/.ssh/
chown -R <operator>:<operator> /home/<operator>/.ssh
chmod 700 /home/<operator>/.ssh && chmod 600 /home/<operator>/.ssh/authorized_keys
```

Then, **from a new terminal**, confirm `ssh <operator>@<host>` works and that `sudo whoami` answers `root`. Only after both do you apply the SSH section.

The name `operator` itself may be taken. Some images ship a legacy `operator` group, and `useradd` refuses a username whose group already exists. Pick another name rather than forcing it with `-g`.

---

## Firewall

A fresh Ubuntu host ships UFW inactive, so until you enable it every listening port is reachable from anywhere the host's network allows. Both installers print a warning when no active firewall is detected. This section is the rules to apply.

The model is default-deny inbound, then open only the ports each host actually needs, each scoped to the narrowest source.

Enable UFW from a console or a second SSH session you can recover from. Applying default-deny over a single live SSH session locks you out if the `OpenSSH` rule is wrong.

The dashboard binds `127.0.0.1` by default, so it is never network-exposed regardless of the firewall. The inbound surface is small:

| Port | Host | Purpose | Exposure |
|---|---|---|---|
| SSH (`:22`) | both | Management plane | Key-only, scoped to an admin group |
| `:51235` | `VAL` | rippled peer protocol | Public |
| `:6006` | `VAL` | rippled admin WS | Shape B only. LAN, scoped to `DASH` |
| `:7800` | `DASH` | Relay ingest | Shape B only. LAN, scoped to `VAL` |

In Shape A both `:6006` and `:7800` stay on loopback, so SSH and the peer port are the only inbound surface.

Shape A is the co-located layout and Shape B is the split one, defined once in the deployment guide's [Pick your shape](DEPLOYMENT-GUIDE.md#pick-your-shape). Which one you are running decides which rows above apply to you, so get it right before you write a firewall rule.

**Already behind a perimeter firewall?** If a hardware/network firewall (a UniFi gateway, pfSense, an upstream appliance) already drops unsolicited inbound, a host UFW is defense-in-depth. Accepting the residual and skipping it is a reasonable operator decision. Two caveats:

- A perimeter firewall does **not** stop LAN-lateral attacks. A compromised device on the same LAN can still reach this host's SSH (and, in Shape B, `:7800`/`:6006`). Put the validator and dashboard hosts on their own VLAN/segment with inter-segment rules, scope rippled's admin to the dashboard IP (`admin_ip` in `rippled.cfg`), and keep SSH key-only.
- If rippled (or anything) runs in **Docker** on the host, plain UFW can be bypassed by Docker's own iptables rules. Published container ports aren't filtered unless you use the `DOCKER-USER` chain or `ufw-docker`.

### Validator host (`VAL`)

rippled's peer port is public; its admin WS is LAN-only and scoped to the dashboard host. This mirrors the verify-from-peer / not-from-public check in the [split-shape walkthrough](DEPLOYMENT-GUIDE.md#split-three-edits).

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow 51235/tcp                                  # rippled peer protocol (public)
sudo ufw allow from <DASH-ip> to any port 6006 proto tcp  # rippled admin WS (DASH only)
sudo ufw enable
```

Verify the admin port is reachable from `DASH` but not from a public host:

```bash
# from DASH: should connect:
nc -zv <VAL-ip> 6006
# from any public host: should NOT connect. If it does, fix the rule before going live.
```

### Dashboard host (`DASH`)

The rules depend on the shape:

**Shape B (LAN split).** The dashboard binds `:7800` to the LAN so `VAL`'s relay can push to it. Open that port scoped to `VAL` only (mirroring the `:6006` pattern above), and nothing else inbound but SSH:

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow from <VAL-ip> to any port 7800 proto tcp   # relay ingest (VAL only)
sudo ufw enable
```

Verify `:7800` from `VAL` (should connect) and from a public host (should not):

```bash
# from VAL: should connect:
nc -zv <DASH-ip> 7800
# from any public host: should NOT connect.
```

**Shape A / tunnelled.** The dashboard binds loopback only and reaches the internet through the outbound Cloudflare tunnel, so no inbound port is needed beyond SSH:

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw enable
```

---

## SSH hardening

SSH is the privileged management plane for this deployment. The operator CLI (`aperire-auth`, for passkey enrollment and magic-link minting) runs over it, and on `VAL` it is the path to rippled. Treat the SSH key for each host as the ultimate recovery factor.

Beyond key-only auth, drop a hardening file so the settings survive `sshd_config` upgrades:

```bash
sudo tee /etc/ssh/sshd_config.d/10-aperire.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowGroups aperire-admins
EOF
sudo systemctl reload ssh
```

`AllowGroups aperire-admins` scopes SSH to a dedicated group. Create it and add the operators who need access (`sudo groupadd aperire-admins && sudo usermod -aG aperire-admins <user>`). Adjust the group name to your convention.

Confirm your own account is in the group before reloading, or you lock yourself out.

Add a brute-force throttle:

```bash
sudo apt install fail2ban
sudo systemctl enable --now fail2ban
```

If you run Cloudflare, you can route SSH through [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/use-cases/ssh/) so `:22` need not be internet-facing at all. The same edge that fronts the dashboard fronts SSH, and the firewall can drop public `:22` entirely.

---

## OS & rippled patching

Patching is a security control, not just maintenance. An unpatched OS or an `amendment_blocked`/CVE-affected rippled is both an attack surface and a consensus-availability risk.

**Automatic OS security updates.** Install `unattended-upgrades` and pin it to security origins, with auto-reboot **off**. A validator reboots on the operator's schedule, never unattended:

```bash
sudo apt-get install -y unattended-upgrades
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Drop-in (survives package upgrades; cleaner than editing 50unattended-upgrades):
sudo tee /etc/apt/apt.conf.d/52aperire-unattended.conf >/dev/null <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
// Never auto-reboot a validator. Schedule reboots into a quiet window so a
// kernel update doesn't drop you out of consensus mid-day.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

sudo unattended-upgrade --dry-run --debug | tail   # confirm it parses + see what applies
```

When a security update does need a reboot, `/var/run/reboot-required` appears. Watch for it (the System tab surfaces pending-reboot) and reboot deliberately.

**rippled patching.** `unattended-upgrades` does **not** cover rippled unless it's installed from Ripple's APT repo. A Docker rippled is patched by pulling a pinned image tag and recreating the container. Either way, treat rippled patching as an SLA, not an afterthought:

- Subscribe to rippled release notes / the XRPL validator channels.
- When an amendment reaches majority, make sure your rippled build supports it **before** it activates. The Governance tab is the early warning. A node that goes `amendment_blocked` stops producing validations until upgraded.
- Keep the upgrade practiced (a dry-run on a spare/standby) so an emergency patch is routine, not improvised.

---

## CIS baseline (recommended)

Defense-in-depth aligned to the [CIS Ubuntu 24.04 Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux). Optional, but each item closes a gap the rest of this guide doesn't.

**Tamper-evident audit trail (`auditd`).** Without it there's no forensic record of who touched config or escalated privilege, so the breach-response lane is blind. Watch the files that matter for this deployment:

```bash
sudo apt-get install -y auditd audispd-plugins
sudo tee /etc/audit/rules.d/60-aperire.rules >/dev/null <<'EOF'
-w /etc/aperire/                -p wa -k aperire-config
-w /etc/ssh/sshd_config         -p wa -k sshd-config
-w /etc/ssh/sshd_config.d/      -p wa -k sshd-config
# Use YOUR deployment's real config path. /opt/ripple/etc/rippled.cfg is the
# native-package layout only; a Docker deployment keeps it wherever the
# compose file mounts it from. Read it from the wrapper config:
#   awk -F= '$1=="CONFIG_FILE"{print $2}' /etc/aperire/node-wrapper.conf
-w /opt/ripple/etc/rippled.cfg  -p wa -k rippled-config
-w /etc/systemd/system/aperire-server.service -p wa -k aperire-unit
EOF
sudo augenrules --load
sudo systemctl enable --now auditd
# Read the trail later: sudo ausearch -k aperire-config
```

**Verify the watches actually loaded. This fails silently.** A watch on a file that does not exist yet is *dropped*, and `augenrules --load` buries the error. So on a host hardened before the install, the rippled and unit watches quietly never exist. That's an audit trail with a hole exactly where it matters most.

Count what the kernel holds against what the file says:

```bash
sudo auditctl -l          # every -w line in 60-aperire.rules must appear here
```

If any are missing, the path is wrong for this deployment or does not exist yet. Fix the path, and **re-run `sudo augenrules --load` after the install** creates `/etc/aperire` and the service units.

**Kernel network hardening (`sysctl`).** Anti-spoofing, no ICMP redirects, no source routing:

```bash
sudo tee /etc/sysctl.d/60-aperire-hardening.conf >/dev/null <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
# NOTE: do NOT set net.ipv4.ip_forward = 0 on a host running Docker (e.g. a
# co-located rippled-in-Docker): Docker needs forwarding. Leave it default.
EOF
sudo sysctl --system
```

**Service minimization.** The validator should run rippled, the dashboard/relay, and little else. Audit what's enabled and disable what you don't need:

```bash
systemctl list-unit-files --state=enabled
sudo systemctl disable --now <unit>
```

Desktop leftovers (`cups`, `avahi-daemon`, `ModemManager`) are the classic examples but rarely present on a server image.

What a fresh Ubuntu 24.04 cloud image actually ships that is worth disabling is `lxd-installer.socket`, a trigger that installs the LXD container stack the first time anything touches its socket. A capability nothing here needs, one connection away.

---

## Admin-RPC allow-list proxy (recommended)

The dashboard needs rippled's **admin** WebSocket for a handful of read commands, but rippled admin auth is binary. A connection that can read can also `stop` the validator, set amendment votes, or `connect` to arbitrary peers.

The dashboard's own code is verified read-only. A compromise of the dashboard *process* (say a malicious npm dependency) would still inherit that fully-privileged connection.

rippled has no read-only admin role, so the proxy contains it. `aperire-rippled-proxy` sits between the dashboard and rippled and forwards only an explicit allow-list of read commands (`server_info`, `peers`, `feature`, …), rejecting everything else, including the *mutating* form of `feature` (`vetoed`).

Deny-by-default means `stop`, `validation_create`, `connect`, `ledger_accept` and the rest are blocked without enumerating them.

Install the unit and wire the dashboard through it:

```bash
# 1. The unit ships as a template with @RUN_USER@ / @REPO@ / @NODE_BIN@
#    placeholders. Substitute your install's service user, repo path, and Node
#    bin dir (the same values the other aperire-*.service units use), then
#    install it. A raw copy leaves the placeholders in and the unit won't start.
#    <run-user> is the dashboard's own account, the User= in
#    aperire-server.service (aperire-dashboard on a fresh install). The proxy
#    opens its logs in data/logs as that account, so it has to own them.
sudo sed -e "s#@RUN_USER@#<run-user>#g" \
         -e "s#@REPO@#<repo-path>#g" \
         -e "s#@NODE_BIN@#<node-bin-dir>#g" \
         scripts/aperire-rippled-proxy.service \
  | sudo tee /etc/systemd/system/aperire-rippled-proxy.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now aperire-rippled-proxy

# The proxy writes to its own log files, not the journal.
tail -n 5 <repo-path>/data/logs/proxy-out.log   # "[proxy] … allow-list (11): server_info, …"

# 2. Point the dashboard at the proxy instead of rippled directly.
#    In /etc/aperire/aperire.env (or the dashboard unit env):
#        RIPPLED_URL=ws://127.0.0.1:6007
sudo systemctl restart aperire-server
curl -s http://127.0.0.1:7800/healthz | jq   # rippled_connected: true (now via the proxy)
```

The proxy listens on loopback (`PROXY_LISTEN=127.0.0.1:6007`) and forwards to `RIPPLED_UPSTREAM_URL` (default `ws://127.0.0.1:6006`).

For the containment to hold, **lock rippled's admin port to the proxy only** so the dashboard process can't bypass the proxy and dial rippled directly. That's `admin_ip` in `rippled.cfg` plus a firewall rule. Shape B already scopes `:6006` to the dashboard host; co-located, keep admin on loopback and treat the proxy as the sole client.

The allow-list must track the commands the dashboard issues, so a dashboard version that adds a new rippled command adds it to the allow-list in the same change.

---

## The node config holds the validator token

`rippled.cfg` (or `xrpld.cfg`) carries `[validator_token]` on a validator. That is the key the node signs with: anything that can read the file can sign as your validator. A default node deployment creates it mode `0644` inside a `0755` directory, which is every account on the host.

The node installer closes it, on the install and on every re-run:

| What | Before | After |
|---|---|---|
| the config file | `0644` | `0640`, group the node's own account |
| its directory | `0755` | `0750` |
| any other reader that needs it | world-readable | a named ACL entry, that account only |

The group is the part that matters, and it is measured rather than assumed. A hardened deployment drops every capability, so the node has no `CAP_DAC_OVERRIDE` and the mode bits bind it even when it runs as uid 0. Tighten the file without moving its group and the node reads its config fine until the next restart, then cannot start at all. So the closing step asks the running node which group it reads the file as, grants the relay its read first where that relay parses the config for its ports, and reverts everything if it cannot watch the node open the file afterwards. Nothing restarts and the validator does not stop.

Run it yourself any time. It reports by default and changes nothing:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure           # report only
curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply   # make the change
```

Check the result directly. `sudo` reads it either way, and is the reliable answer:

```bash
# Read the path from the record rather than guessing at the layout
cfg=$(awk -F= '$1=="CONFIG_FILE"{print $2}' /etc/aperire/node.conf)
sudo stat -c '%a %U:%G' "$cfg"     # expect 640, and the node's own group
sudo getfacl -p "$cfg"             # every named entry should be one you can explain
```

The closer grants the dashboard's account a read on the file and passage on its directory the moment it finds the unit. That account is `aperire-dashboard`, which has no login, so read the result with `sudo getfacl -p <file>`: the entry `user:aperire-dashboard:r--` is the grant. On a host installed before the dashboard had its own account, the dashboard runs as your login, and plain `stat` and `getfacl` work from it.

Two things this does not do. It does not hide the file from the accounts that need it. The dashboard reads it directly, for four settings it draws from it (`online_delete`, `advisory_delete`, `node_size`, `ledger_history`), so its account holds a named read entry on it. On a container deployment the file stays yours; on a native install it and its directory are root's. On a host installed before the dashboard had its own account, the dashboard runs as your login and reads the file as its owner. That is a real trade, made on purpose: the dashboard's account can read a file that may carry your validator token, the same way it always could on a container install. The Advisor's account is refused outright, on both shapes; the wrapper's redacted copy is the only view of this file it is meant to have. And this does not replace keeping the token out of backups that leave the host, which is yours to arrange.

## The dashboard's own account

A fresh install runs the dashboard as `aperire-dashboard`, a system account made for it: no login shell, no home, and in none of `docker`, `sudo`, `libvirt`, `lxd` or `adm`. Each of those groups is root on the host by itself, so a web process running as an account in one could reach the validator. The install refuses an `aperire-dashboard` account that has a login shell or any of those groups.

| What | Owner | Why |
|---|---|---|
| The install directory, the `dashboard/config` directory, `advisor/` | You | Nothing root runs or copies can be rewritten by a service account. On an aggregator the fleet files in `dashboard/config` (`fleet.yaml`, `fleet-links.json`, `fleet-trust.yaml`) are the dashboard's, written there by root's broker; it cannot add, rename or remove an entry beside them |
| `data/` (database, logs, the amendment library) | `aperire-dashboard`, `0700` | The one directory the dashboard writes |
| `/etc/aperire/aperire.env` | `root:aperire-dashboard 0640` | The dashboard reads it and cannot change it |
| The root sockets in `/run/aperire` | `aperire-dashboard`, `0600` | Only the dashboard can ask them |

The account reaches the install directory and Node through `--x` access entries on the directories above them, which allow passing through and nothing else. The installer reads back, as that account, that it can run Node and read the server before it writes the unit.

Check it:

```bash
id aperire-dashboard                          # no docker, sudo, libvirt, lxd or adm
systemctl show aperire-server -p User         # User=aperire-dashboard
sudo stat -c '%U %a' <install-dir>/data       # aperire-dashboard 700
stat -c '%U %a' <install-dir>/dashboard/config   # your login, no group or other write
```

Its logs are opened by the service itself, after it has switched to that account, rather than by systemd as root. A log name in `data/logs` that the account turned into a link can only reach a file the account could already write.

A host installed before this keeps running the dashboard as your login. The installer and the update say so and change nothing; moving such a host is a separate step that comes in a later release. The uninstaller removes `aperire-dashboard` with the dashboard, after handing anything it owned back to you.

## The root sockets on a dashboard host

The dashboard runs unprivileged and cannot become root. Its unit sets `NoNewPrivileges=true` with an empty capability set, so `sudo` refuses inside it whatever `/etc/sudoers` says. Anything that genuinely needs root is therefore a separate program that is already running as root, reached over a private socket the dashboard account alone may open (mode `0600`, owned by that account, one connection at a time).

There are three, and a host only has the ones its install put there:

| Socket | Program | What the dashboard may ask for |
|---|---|---|
| `/run/aperire/seal-model-key.sock` | `/usr/local/sbin/aperire-seal-model-key` | Seal one model API key to this host, once per arming window. It cannot open its own window. |
| `/run/aperire/trust-sync.sock` | `/usr/local/sbin/aperire-trust-sync` | Rebuild the Advisor's trust store from the dashboard's own database. Nothing it sends goes into the store. |
| `/run/aperire/update.sock` | `/usr/local/sbin/aperire-update` | Check for a newer release, apply it, restart the units it names, or roll back. |

Two properties are worth checking rather than assuming:

- **Each program is copied out of the checkout.** The checkout is your account's files, so a unit naming a script in the tree would be root for anything running as your account, or as the dashboard on a host where it still runs as your login. All three live in `/usr/local/sbin`, root-owned. Confirm with `stat -c '%U %a' /usr/local/sbin/aperire-*`; each should read `root 755`.
- **The update socket carries no source.** The endpoint the update program fetches from is in `/etc/aperire/update.conf`, which is root-owned and which the dashboard account cannot write. A request over the socket carries the tag, commit and checksum the page believes is current; the program fetches the publisher's own files and refuses anything that disagrees. So the widest thing a compromised web session can do with it is install the release the publisher published. Confirm with `stat -c '%U %a' /etc/aperire/update.conf` (`root 644`) and read the file: it should name the endpoint you expect.
- **The update program checks the release key, not the endpoint.** Every release is signed, and the program verifies the signature against `/usr/local/lib/aperire/release-signers` before it runs anything it fetched. Confirm with `stat -c '%U %a' /usr/local/lib/aperire/release-signers` (`root 644`), then compare its fingerprint, shown on Settings & Updates, with the one published in [Release Signing](RELEASE-SIGNING.md#check-the-release-key-on-your-host).

To take any of them off: `curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --remove`, `curl -fsSL https://get.aperire.one | bash -s -- --run trust-sync-grant --remove`, `curl -fsSL https://get.aperire.one | bash -s -- --run update-grant --remove`. Removing a grant costs the feature and nothing else; the operator can still do each of those things at a shell.

---

## Post-install hardening checklist

Run through this before treating the deployment as production.

- [ ] **OS updates are automatic, reboots are not.** `unattended-upgrades` pinned to security origins with `Automatic-Reboot "false"` on both hosts. See [OS & rippled patching](#os--rippled-patching). Confirm with `sudo unattended-upgrade --dry-run --debug | tail`.
- [ ] **rippled patching is an SLA.** You track rippled releases and can upgrade before an amendment activates, so the node never sits `amendment_blocked`.
- [ ] **SSH is hardened.** Key-only auth, no root login, scoped to an admin group, and `fail2ban` running. See [SSH hardening](#ssh-hardening). Verify with `sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin|allowgroups'`.
- [ ] **CIS baseline applied (recommended).** `auditd` watching config paths, sysctl network hardening, and unneeded services disabled. See [CIS baseline](#cis-baseline-recommended). Verify with `sudo auditctl -l` and `sudo sysctl net.ipv4.conf.all.rp_filter`.
- [ ] **Every audit watch actually loaded.** `sudo auditctl -l` lists every `-w` line from `60-aperire.rules`. A watch on a path that did not exist at load time was dropped silently. If the host was hardened before the install, re-run `sudo augenrules --load` now that the paths exist.
- [ ] **Admin-RPC proxy in front of rippled (recommended).** `aperire-rippled-proxy` running, `RIPPLED_URL` points at it, and rippled's admin port is locked to the proxy. See [Admin-RPC allow-list proxy](#admin-rpc-allow-list-proxy-recommended). Verify `/healthz` shows `rippled_connected: true`.
- [ ] **Firewall is enabled.** UFW active with the per-host rules from [Firewall](#firewall). Verify with `sudo ufw status verbose`. On `VAL`, confirm `:6006` is not reachable from a public host; on `DASH` Shape B, confirm `:7800` is reachable only from `VAL`.
- [ ] **`RELAY_TOKENS` is a real secret** (not `dev-test-token-001`). The install script generates one automatically; verify `/etc/aperire/aperire.env` doesn't contain a dev value if you ever edited it.
- [ ] **Logrotate is installed.** `/etc/logrotate.d/aperire` exists and `sudo logrotate --debug /etc/logrotate.d/aperire` runs clean.
- [ ] **Health check is reachable.** `curl -s https://aperire.example.com/healthz | jq` returns `ok: true` from an external network.
- [ ] **The node config is closed.** `0640` on the file, `0750` on its directory, group the node's own account, and every named ACL entry on it is one you can explain: the relay's read if it auto-detects ports, and the dashboard's account (a read on the file, passage on the directory) if a dashboard is installed on this host. See [The node config holds the validator token](#the-node-config-holds-the-validator-token). The node installer does this on every run; verify with `sudo getfacl -p "$(awk -F= '$1=="CONFIG_FILE"{print $2}' /etc/aperire/node.conf)"` and `sudo stat -c '%a %U:%G' "$(awk -F= '$1=="CONFIG_FILE"{print $2}' /etc/aperire/node.conf)"`.
- [ ] **`relay.conf` is `0640 root:aperire-relay`.** Check with `stat /etc/aperire/relay.conf`.
- [ ] **`aperire.env` is `0640 root:<dashboard-user>`.** Check with `stat /etc/aperire/aperire.env`.
- [ ] **The root sockets are the ones you meant to have.** `ls -l /run/aperire/*.sock` and `stat -c '%U %a' /usr/local/sbin/aperire-*`. Each socket is `0600` owned by the dashboard account, each program is `root 755`. If updating from the dashboard is not something you want on this host, `curl -fsSL https://get.aperire.one | bash -s -- --run update-grant --remove` takes it off. See [The root sockets](#the-root-sockets-on-a-dashboard-host).
- [ ] **Cloudflare tunnel credentials are user-read-only.** Check `~/.cloudflared/*.json` perms.
- [ ] **External uptime monitor points at `/healthz`.** UptimeRobot, BetterStack, Pingdom, anything that pages on 503. Without it a crash loop is invisible.
- [ ] **Backup plan.** `aperire.db` is a single file (with `-wal` / `-shm` sidecars). Copy it to back up; the dashboard will recover missing time-series data from rippled on the next poll, so backups are a nice-to-have, not critical.

---
