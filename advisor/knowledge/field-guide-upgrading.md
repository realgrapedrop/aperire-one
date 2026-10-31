# Field Guide: upgrading xrpld

Distilled from The Rippled Field Guide (github.com/realgrapedrop/rippled-field-guide),
the operator's own published guide. Treat as Documented. Full guide at the repo.

The software is xrpld, called rippled until 3.2.0, which renamed the binary,
the config path and the data path (see the releases note). Names and paths below are the
xrpld package's, checked 2026-10-22 against its source at tag 3.4.1. A node older than
3.2.0, or a fork that kept the old names, uses different ones: read the real path from the
node's own config before acting on one written here.

`xrpld <command>` means however the node reaches the binary: `xrpld --conf
/etc/xrpld/xrpld.cfg -q <command>` natively, with `docker exec <container>` in front on a
container deployment.

## Upgrading xrpld

Keeping xrpld updated is essential. Outdated servers can become amendment blocked and unable to participate in consensus. This section covers notification channels, upgrade procedures, and troubleshooting.

### Two deployment shapes

The commands below are the vendor's own generic procedures, for whichever way a node is deployed. This tool runs an upgrade one of two ways depending on how the node itself is deployed, and the two carry different guarantees rather than the same guarantee reached by a different route.

On a Docker Compose deployment, the image is BUILT on the node's own host from the XRPL Foundation's signed DEB package, named `localhost/xrpld:<release>`, and inspected before anything is touched; then the running container is recreated on it. Building rather than pulling is not a preference: from 3.4.x a release ships as a signed package first and sometimes only as one, so there are releases with no image at any registry, and 3.4.1 is one of them. The build checks the package signing key's fingerprint against the published value and refuses on a mismatch, installs one exact package version through apt's own signature checking, and proves the version and the package the image reports before the tag is kept. What that tag resolves to is recorded before the operator's approval and compared again immediately before the swap, so a tag moved in between stops the upgrade rather than being restarted onto. The deployment carries `pull_policy: never` beside the image, because `localhost/` has no registry behind it and a missing image must fail at once rather than send compose looking for one.

Two things about a container deployment are read before the stop, and each refuses the upgrade rather than being discovered after it. A container that names no user has been running as root, and the built image's own account is uid 997, which on the host is whichever account holds that number: the deployment has to say `user: "0:0"` before the swap, which keeps the behaviour the node already has. A deployment that mounts the node config only at `/config` is refused for a related reason: the image copies that config to `/etc/xrpld/xrpld.cfg` at start and refuses to run on the package's default config when it cannot, so that shape needs either root or a second read-only mount at `/etc/xrpld/xrpld.cfg`, as its own change and never both at once. After the recreate, the container's own first lines are read: `copied` or `already matches` is a node that got its config, and the refusal line stops the run with the rollback in front of it.

On a native package install (the vendor's `xrpld` or `rippled` package, run by systemd), the package manager fetches and installs in one call, the vendor's signature is what is verified, and the version that comes up afterward is compared against what was installed, not against a digest, there is no digest on this path. Both are real guarantees; neither is a weaker version of the other.

Reversibility differs the same way. A container rollback restores a dated compose backup, or points the deployment back at the previous image, and is instant and local as long as that image is still on the host; where it is not, the same recipe builds it again from the same signed package. A native rollback is another `package-install` at the previous version, which only works if that version is still offered by the repository the host trusts, checked before the rollback starts, not discovered partway through it.

Which release is newest is read from the signed package index at packages.xrplf.org on both shapes, never from a container registry. The registry answer is wrong for this software now: the image this tool used to deploy stops at 3.3.0, so a node facing an amendment deadline would be told it was current.

### Staying Notified

**Subscription Options (Use Multiple)**

| Channel | URL | What You Get |
|---------|-----|--------------|
| **ripple-server mailing list** | [groups.google.com/g/ripple-server](https://groups.google.com/g/ripple-server) | Release announcements, urgent upgrade notices, amendment alerts. **Essential.** |
| **GitHub Releases** | [github.com/XRPLF/rippled/releases](https://github.com/XRPLF/rippled/releases) | Detailed release notes, changelogs |
| **GitHub Watch** | Click "Watch" → "Custom" → "Releases" | Email notifications for new releases |
| **RSS Feed** | `github.com/XRPLF/rippled/releases.atom` | For RSS readers |

**Built-in Upgrade Notification**

xrpld itself monitors the network and warns you when most validators are running a newer version. The message, logged at error level and printed to stderr:

```
Check for upgrade: A majority of trusted validators are running a newer version.
```

xrpld checks on every 256th ledger. It prints the first message only when validations have arrived from at least 90% of the validators on your UNL and at least 60% of the xrpld validators among them report a higher version. After that it repeats once a week, until the node restarts. By the time you see it, upgrading is urgent.

**Source:** `LedgerMaster::checkAccept` in [LedgerMaster.cpp at tag 3.4.1](https://github.com/XRPLF/rippled/blob/3.4.1/src/xrpld/app/ledger/detail/LedgerMaster.cpp); the mechanism first shipped in [rippled 1.6.0](https://xrpl.org/blog/2020/rippled-1.6.0)

**Amendment Voting Timeline**

When new amendments are introduced:

1. **Release**: New xrpld version with amendment code is published
2. **Voting begins**: Validators vote for/against (requires 80% support for 2 weeks)
3. **Activation**: Amendment becomes active on the network
4. **Blocking**: Servers without the amendment code become amendment blocked

The window between voting start and activation is typically 2 weeks. Upgrade before activation to avoid being blocked.

**Source:** [XRPL Blog](https://xrpl.org/blog)

### Pre-Upgrade Checklist

Before upgrading:

1. **Check current version**
   ```bash
   xrpld --version
   # or
   xrpld --conf /etc/xrpld/xrpld.cfg -q server_info | grep build_version
   ```

2. **Read the release notes** - [GitHub Releases](https://github.com/XRPLF/rippled/releases)
   - Are there breaking changes?
   - Does this release require a config change?
   - Are there new amendments that will begin voting?

3. **Check the package source** - `apt-cache policy xrpld` must show `packages.xrplf.org`. A host still on `repos.ripple.com` cannot see 3.4.0 or later (see "Package source and key errors" below)

4. **Verify disk space** - Ensure sufficient space for the upgrade

5. **Plan timing** - Upgrade during low-activity periods if possible, though xrpld restarts are fast

### Upgrade Procedures

The package is `xrpld` and the service is `xrpld.service`. The upgrade is always yours to start: from the Advisor tab, or with the package manager as below.

**Method 1: apt (Most Control)**

```bash
# Update package lists
sudo apt update

# Check the available version and which repository it comes from
apt-cache policy xrpld

# Upgrade xrpld
sudo apt install --only-upgrade xrpld

# Reload systemd (picks up any unit file changes)
sudo systemctl daemon-reload

# Restart xrpld
sudo systemctl restart xrpld
```

**Method 2: Stop First, Then Upgrade**

For the smoothest upgrade with fastest re-sync, stop the service cleanly before the package changes:

```bash
# Gracefully stop xrpld and wait for it to exit (can take a minute)
sudo systemctl stop xrpld
while systemctl is-active xrpld >/dev/null 2>&1; do
    sleep 2
done

# Install the new package
sudo apt update && sudo apt install --only-upgrade xrpld

# Reload and start
sudo systemctl daemon-reload
sudo systemctl start xrpld
```

**Package source and key errors**

If `apt update` fails with a GPG error, or names `repos.ripple.com`, the host is on the retired package source. `repos.ripple.com` stops at 3.3.0 and never carries 3.4.0 or later: packages moved to `packages.xrplf.org` on 2026-08-19, under a new signing key. Re-trusting the old repository's key keeps the node on a source that cannot offer the release an activating amendment needs, so do not point an operator back at it.

Move the source with the update. It adds `packages.xrplf.org` and checks the key against the fingerprint below before trusting it. It keeps the installed package for rollback, because the new repository never carries 3.3.0. It retires the old source only after the new one has answered. It installs, upgrades and restarts nothing:

```bash
curl -fsSL https://get.aperire.one | bash -s -- --update --force
```

If the error names `packages.xrplf.org` itself, the key file is missing or wrong. Fetch it to a scratch directory and read its fingerprint before it goes anywhere near apt:

```bash
tmp=$(mktemp -d)
wget -qO "$tmp/xrplf.asc" https://packages.xrplf.org/xrplf.asc
gpg --show-keys --fingerprint "$tmp/xrplf.asc"
```

It must show exactly one key, `XRPLF Packages`, with fingerprint `B655 4167 4122 1F78 0FBC FBC9 AA84 D41A 11D2 9FA9`. If it shows anything else, stop and delete the file. If it matches, install it as the armored file apt reads (no `--dearmor`), make sure the source line is there, and retry:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$tmp/xrplf.asc" /etc/apt/keyrings/xrplf.asc
echo 'deb [signed-by=/etc/apt/keyrings/xrplf.asc] https://packages.xrplf.org/repository/deb-stable any main' \
  | sudo tee /etc/apt/sources.list.d/xrplf.list
sudo apt update
```

**Source:** [XRPLF install guide, packages published from 2026-08-19](https://github.com/XRPLF/rippled/blob/4a4fded2eba11427c48ce3f24d9c1aea5e7a9d17/docs/install.md)

### Post-Upgrade Verification

After upgrading, verify the server is healthy:

```bash
# Check version
xrpld --conf /etc/xrpld/xrpld.cfg -q server_info | grep build_version

# Check server state (should return to proposing/full within minutes)
xrpld --conf /etc/xrpld/xrpld.cfg -q server_info | grep server_state

# Check for amendment blocked status
xrpld --conf /etc/xrpld/xrpld.cfg -q server_info | grep amendment_blocked

# Check health endpoint (on the peer port: 51235 where Aperire installed the node, 2459 on the package default)
curl http://localhost:<peer-port>/health

# Monitor logs for errors
tail -f /var/log/xrpld/debug.log
```

**Expected Behavior**

- Server will sync with the network (5-15 minutes typical)
- `server_state` returns to `full` (stock node) or `proposing` (validator)
- `amendment_blocked` should be `false`
- Health check returns 200 with empty `info` object

### Amendment Blocking

**What It Means**

When the network enables a protocol amendment your server doesn't understand, your server becomes "amendment blocked." This is a safety feature - rather than misinterpret transactions under rules it doesn't know, the server stops processing.

**Symptoms**

- `server_state` shows `connected` instead of `full` or `proposing`
- `amendment_blocked: true` in `server_info`
- Error when submitting transactions: `amendmentBlocked` (error code 14)
- Health check returns critical status

**How to Check**

```bash
# Check if amendment blocked
xrpld --conf /etc/xrpld/xrpld.cfg -q server_info | grep amendment_blocked

# See which features are blocking
xrpld --conf /etc/xrpld/xrpld.cfg -q feature | grep -A1 '"blocked"'
```

**How to Resolve**

Upgrade to the latest xrpld version:

```bash
sudo apt update && sudo apt install --only-upgrade xrpld
sudo systemctl restart xrpld
```

If `apt-cache policy xrpld` shows `repos.ripple.com`, the host cannot see the release it needs: move the source first (see "Package source and key errors" above).

In most cases, upgrading to the latest version resolves the block. Check [Known Amendments](https://xrpl.org/resources/known-amendments) to see which version introduced support for specific amendments.

**Prevention**

- Subscribe to ripple-server mailing list for advance notice
- Upgrade promptly when new versions are released
- Don't wait for the built-in >60% warning - by then you're behind

**Source:** [Server is Amendment Blocked](https://xrpl.org/docs/infrastructure/troubleshooting/server-is-amendment-blocked)

### Which release is current

This note carries no version number: one written here is stale the day the next release ships. Read it where it cannot go stale. The signed package index at packages.xrplf.org says which release is newest (see "Two deployment shapes"). [GitHub Releases](https://github.com/XRPLF/rippled/releases) has the changelog for each release, and the releases note records what the operator knows about specific ones. [Known Amendments](https://xrpl.org/resources/known-amendments) lists the amendments and their status.

---

# Phase 6: Community & Reputation

For validators, building trust takes time. This phase covers community engagement, directory registration, and the long path to UNL inclusion.

---

