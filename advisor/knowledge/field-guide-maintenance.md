# Field Guide: maintaining xrpld

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

## Maintenance

Regular maintenance prevents small issues from becoming big problems. This section covers log management, disk space, database health, backups, and disaster recovery.

### Log Management

**Log File Location**

The package's `xrpld.cfg` sets `[debug_logfile]` to `/var/log/xrpld/debug.log`. The path is whatever that section says on the node in front of you, so read it rather than assuming. The verbosity is controlled by `log_level` in the same config.

**Log Levels**

| Level | Verbosity | Production Use |
|-------|-----------|----------------|
| trace | Extreme | Never |
| debug | High | Troubleshooting only |
| info | Medium | Too verbose |
| **warning** | **Low** | **Recommended** |
| error | Very low | Minimal logging |

Set the log level in `xrpld.cfg`:

```ini
[rpc_startup]
{ "command": "log_level", "severity": "warning" }
```

You can temporarily increase verbosity for debugging without restarting:

```bash
xrpld log_level debug
# ... investigate issue ...
xrpld log_level warning
```

**Log Rotation**

The `xrpld` package installs its own logrotate rule at `/etc/logrotate.d/xrpld`. This is the file the 3.4.1 package ships, copied from the package source:

```
/var/log/xrpld/*.log {
  daily
  minsize 200M
  rotate 7
  nocreate
  missingok
  notifempty
  compress
  compresscmd /usr/bin/gzip
  compressext .gz
  postrotate
    # Only signal the daemon if it's actually running; otherwise the RPC
    # call returns a transport error and logrotate marks the rotation as
    # failed, generating recurring errors on stopped nodes.
    if systemctl is-active --quiet xrpld; then
      /usr/bin/xrpld --conf /etc/xrpld/xrpld.cfg logrotate
    fi
  endscript
}
```

The `postrotate` command tells xrpld to close and reopen its log file, and only runs while the service is active. Read the copy on the host before advising a change, because a host on another release, or a fork, may differ. Adjust `minsize` and `rotate` based on your disk space and retention needs.

> **Note:** Ensure you have only one logrotate configuration for xrpld. Multiple configurations can cause issues.

**Source:** [xrpld.logrotate at tag 3.4.1](https://github.com/XRPLF/rippled/blob/3.4.1/package/shared/xrpld.logrotate) and the install path in [package/README.md at 3.4.1](https://github.com/XRPLF/rippled/blob/3.4.1/package/README.md); [logrotate API reference](https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/logging-and-data-management-methods/logrotate)

### Disk Space Monitoring

**What Consumes Disk**

| Component | Location | Growth Rate | Notes |
|-----------|----------|-------------|-------|
| Ledger database (NuDB) | `/var/lib/xrpld/db/nudb` | ~12 GB/day (full history) | Controlled by `online_delete` |
| SQLite databases | `/var/lib/xrpld/db` | Minimal | wallet.db, transaction.db |
| Logs | `/var/log/xrpld` | Depends on log level | Controlled by logrotate |

**Monitoring Commands**

```bash
# Check xrpld data directory size
du -sh /var/lib/xrpld/db/

# Check log directory size
du -sh /var/log/xrpld/

# Check overall disk usage
df -h /var/lib/xrpld
```

**The online_delete Trade-off**

As covered in [Database Management](#database-management), higher `online_delete` values (16384-32768) use more disk but prevent I/O storms. Monitor your disk usage and adjust accordingly. With `online_delete=32768`, expect 16-24 GB for the ledger database.

### Database Maintenance

**Ledger Cleaner**

xrpld includes an asynchronous maintenance process called the Ledger Cleaner that can find and repair corruption in the ledger database. It is configured with the admin method `ledger_cleaner`:

| Field | What it does |
|---|---|
| `min_ledger`, `max_ledger` | The range of ledger indexes to check. |
| `ledger` | Check and correct that one ledger only. |
| `full` | `true` fixes ledger state objects and transactions in the range. Defaults to `false`. |
| `check_nodes`, `fix_txns` | `true` corrects only ledger state objects, or only transactions. Each overrides `full`. |
| `stop` | `true` disables the cleaner. |

An admin command requiring access to admin ports. A successful call answers `Cleaner configured`.

**Source:** [ledger_cleaner](https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/logging-and-data-management-methods/ledger_cleaner)

**When Database Corruption Occurs**

Corruption can result from:
- Unexpected shutdowns or power loss
- Hardware failures (disk, memory)
- Running out of disk space during writes

**Recovery Options**

**Option 1: Test with fresh database paths**

If you have disk space, change the paths temporarily to test if corruption is the issue:

```ini
[node_db]
path=/var/lib/xrpld/db/nudb_test

[database_path]
/var/lib/xrpld/db_test
```

If the server syncs successfully with fresh paths, corruption was the issue.

**Option 2: Delete and re-download**

It's safe to delete xrpld's databases - the server will re-download ledger history from the network:

```bash
# Stop xrpld first
sudo systemctl stop xrpld

# Remove databases (keep your config!)
sudo rm -rf /var/lib/xrpld/db/nudb/*
sudo rm /var/lib/xrpld/db/*.db

# Restart - server will sync from network
sudo systemctl start xrpld
```

Re-syncing typically takes 5-15 minutes for recent ledger data.

> **Warning:** If you delete `wallet.db`, your node will generate a new identity. For stock nodes this is fine. For validators, your validator identity is in `xrpld.cfg` (the token), not in `wallet.db`, so your validator identity is preserved.

**Source:** [Server Doesn't Sync](https://xrpl.org/docs/infrastructure/troubleshooting/server-doesnt-sync)

### Validator Key Backups

**What to Back Up**

| File | Location | Contains | Backup Frequency |
|------|----------|----------|------------------|
| `validator-keys.json` | Offline storage | Master key, token sequence | After every token generation |
| `xrpld.cfg` | `/etc/xrpld/xrpld.cfg` | Current token, config | After config changes |

**Backup Best Practices**

1. **Store `validator-keys.json` on encrypted, offline media** (USB drive stored in a safe)
2. **Multiple copies in different physical locations** - fire, flood, theft protection
3. **Update backups after every token generation** - the `token_sequence` must always increase
4. **Never store master keys on the validator server**
5. **Test your backup restoration process** periodically

**The Critical Sequence Number Rule**

Each token contains a sequence number. The network only accepts tokens with a sequence number higher than any previously seen. If you:

1. Generate token (sequence 1)
2. Generate token (sequence 2)
3. Restore old backup (sequence 1)
4. Generate token (sequence 2 again)

...the network will ignore that token because it's not higher than sequence 2. **Always update your backup after generating tokens.**

**Source:** [validator-keys-tool guide](https://github.com/ripple/validator-keys-tool/blob/master/doc/validator-keys-tool-guide.md)

### Health Checks

**The Health Check Endpoint**

xrpld provides a health check endpoint on the peer port (51235 where Aperire installed the node, 2459 on the package default):

```bash
curl http://localhost:<peer-port>/health
```

**Response Interpretation**

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Healthy - all metrics normal |
| 503 | Warning - some metrics in warning range |
| 500 | Critical - server has serious issues |

A healthy response returns an empty `info` object:

```json
{
  "info": {}
}
```

An unhealthy response lists the problematic metrics:

```json
{
  "info": {
    "server_state": "syncing",
    "validated_ledger": "too old"
  }
}
```

**Metrics Checked**

- `server_state` - should be `full` or `proposing`
- `validated_ledger` - age of latest validated ledger
- `peers` - number of peer connections
- `amendment_blocked` - whether server is amendment blocked

**Monitoring Best Practices**

- Call the health check frequently (every 30-60 seconds)
- Don't alert on every unhealthy status - metrics can fluctuate briefly
- Escalate only for **severe and consistent** problems
- Allow 15 minutes after startup before expecting healthy status

**Special Cases**

- **Private peers**: Health check warns if peers < 7, but private validators intentionally have few peers. Check for your expected peer count instead.
- **Test networks**: Health check warns if validated ledger is > 7 seconds old, but test networks may have longer gaps between ledgers.

**Source:** [Health Check Interventions](https://xrpl.org/docs/infrastructure/troubleshooting/health-check-interventions)

### Disaster Recovery

**Scenario: Server Hardware Failure**

1. Provision new server meeting [Hardware Requirements](#hardware-requirements)
2. Install xrpld from packages
3. Copy your `xrpld.cfg` from backup (includes validator token)
4. Start xrpld - it will sync from the network
5. Verify `server_state` returns to `proposing` (validator) or `full` (stock node)

**Scenario: Configuration Corruption**

1. Stop xrpld
2. Restore `xrpld.cfg` from backup
3. Verify the account the node runs as can read it (`xrpld` on a native package, whose unit runs as `User=xrpld`), and that it is no wider than 0640, since it holds the validator token. A mode that locks that account out fails at the next restart, not before: the node reads its config once at startup and keeps running, so it looks healthy until then
4. Restart xrpld

**Scenario: Master Key Compromise**

This is the worst case - see [Key Compromise Response](#key-compromise-response) in the Validator Keys section. You must revoke the key and coordinate with UNL publishers.

**Disaster Recovery Checklist**

- [ ] Encrypted backup of `validator-keys.json` in secure offline location
- [ ] Backup of `xrpld.cfg` with current token
- [ ] Documented server provisioning process
- [ ] Tested restoration procedure (at least annually)
- [ ] Contact information for UNL publishers (in case of master key compromise)
