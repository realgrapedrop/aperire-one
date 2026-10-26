#!/usr/bin/env bash
# The account an XRPL node runs as on this host, resolved the same way by
# everything that needs it (#31).
#
# Sourced, never run. scripts/install-aperire-node.sh creates the account on a
# fresh install; scripts/migrate-node-nonroot.sh creates or reads it when it
# moves an existing install onto it. Two writers of one fact is how two hosts
# end up with the same node owned by different uids, so the rules live here
# once.
#
#   node_account_name            the name, `xrpld`
#   node_account_read            print "name<TAB>uid<TAB>gid" if it exists,
#                                return 1 if it does not. Changes nothing
#   node_account_ensure          the same, creating the account if it is not
#                                there. Needs root
#
# ── Why `xrpld`, and why 997 ──────────────────────────────────────────────
#
# The package already ships the account the daemon is meant to run as, and
# every image built from it carries that account. Read out of the image this
# project builds from the signed package (`localhost/xrpld`), where it is
# 997:997; the official rippleci/xrpld image ships the same named account at
# 999:999, which is why a deployment names its user by NUMBER rather than
# inheriting whatever an image happens to use:
#
#   /etc/passwd   xrpld:x:997:997:XRP Ledger daemon:/var/lib/xrpld:/sbin/nologin
#   /var/lib/xrpld and /var/log/xrpld are 0750 and owned by 997:997
#   /lib/systemd/system/xrpld.service carries User=xrpld, Group=xrpld
#
# So this does not invent an identity. It uses the vendor's, by number, and
# names the host account `xrpld` too so `ls -l` on the store reads the same on
# both sides of the mount. That unit is also where the claim "no capability is
# needed" comes from: its CapabilityBoundingSet lines for CAP_NET_BIND_SERVICE
# are commented out, and are only to be uncommented for ports below 1024. The
# three ports this node binds are 2459, 5005 and 6006.
#
# ── When 997 is already taken ─────────────────────────────────────────────
#
# 997 is inside the range a Linux distribution allocates system accounts from,
# downwards from 999, so on a host that installed something else first it can
# belong to an unrelated service. It does on the box this was written on:
# uid 997 is `pcp` and gid 997 is `crontab`. Handing that account write access
# to the ledger store, or that group read access to a config carrying
# [validator_token], is not a trade worth making for a matching number. So the
# number is preferred, never forced: if either half of 997:997 is taken the
# account is created with whatever the system allocates, the run says which
# account held 997, and the uid is recorded in /etc/aperire/node.conf so
# nothing downstream has to guess.
#
# Both shapes are proven to run. A container started as 997:997 resolves the
# image's own passwd entry (HOME=/var/lib/xrpld); one started as a pair with
# no entry in the image runs the same, reaches `healthy` the same, and answers
# server_info the same, with HOME falling back to `/`. xrpld takes every path
# it uses from the config file, so it never reads HOME.

# The name. One string, one place.
node_account_name() { printf 'xrpld\n'; }

# The uid and gid preferred, from the vendor image above.
NODE_ACCOUNT_PREFERRED_ID=997

# Print "name<TAB>uid<TAB>gid" for the account if this host has it.
# Returns 1 and prints nothing if it does not. Reads only.
node_account_read() {
  local name entry uid gid
  name=$(node_account_name)
  entry=$(getent passwd "$name" 2>/dev/null) || return 1
  [[ -n "$entry" ]] || return 1
  uid=$(printf '%s' "$entry" | cut -d: -f3)
  gid=$(printf '%s' "$entry" | cut -d: -f4)
  [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return 1
  printf '%s\t%s\t%s\n' "$name" "$uid" "$gid"
}

# The same, creating the account when it is absent. Root only.
#
# Every note it wants to make goes to stderr, so a caller reading the one line
# on stdout gets the fact and nothing else. Returns non-zero without creating
# anything if the tools are not here, rather than leaving a half-made account.
node_account_ensure() {
  local name uid_free=0 gid_free=0 holder
  name=$(node_account_name)

  if node_account_read; then
    return 0
  fi

  [[ $EUID -eq 0 ]] || { echo "node_account_ensure: creating the ${name} account needs root" >&2; return 1; }
  command -v useradd  >/dev/null 2>&1 || { echo "node_account_ensure: no useradd on this host, so the ${name} account cannot be created" >&2; return 1; }
  command -v groupadd >/dev/null 2>&1 || { echo "node_account_ensure: no groupadd on this host, so the ${name} group cannot be created" >&2; return 1; }

  getent passwd "$NODE_ACCOUNT_PREFERRED_ID" >/dev/null 2>&1 || uid_free=1
  getent group  "$NODE_ACCOUNT_PREFERRED_ID" >/dev/null 2>&1 || gid_free=1

  if (( uid_free && gid_free )); then
    groupadd --system --gid "$NODE_ACCOUNT_PREFERRED_ID" "$name" >&2 \
      || { echo "node_account_ensure: groupadd ${name} failed" >&2; return 1; }
    useradd --system --uid "$NODE_ACCOUNT_PREFERRED_ID" --gid "$name" \
            --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
            --comment "XRP Ledger daemon" "$name" >&2 \
      || { echo "node_account_ensure: useradd ${name} failed" >&2; return 1; }
    echo "created the ${name} account at ${NODE_ACCOUNT_PREFERRED_ID}:${NODE_ACCOUNT_PREFERRED_ID}, the uid and gid the node image itself uses" >&2
  else
    holder=""
    (( uid_free )) || holder="uid ${NODE_ACCOUNT_PREFERRED_ID} belongs to $(getent passwd "$NODE_ACCOUNT_PREFERRED_ID" | cut -d: -f1)"
    if (( ! gid_free )); then
      [[ -n "$holder" ]] && holder="${holder}, "
      holder="${holder}gid ${NODE_ACCOUNT_PREFERRED_ID} belongs to $(getent group "$NODE_ACCOUNT_PREFERRED_ID" | cut -d: -f1)"
    fi
    groupadd --system "$name" >&2 \
      || { echo "node_account_ensure: groupadd ${name} failed" >&2; return 1; }
    useradd --system --gid "$name" \
            --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
            --comment "XRP Ledger daemon" "$name" >&2 \
      || { echo "node_account_ensure: useradd ${name} failed" >&2; return 1; }
    echo "the node image uses ${NODE_ACCOUNT_PREFERRED_ID}:${NODE_ACCOUNT_PREFERRED_ID} and this host cannot: ${holder}." >&2
    echo "created ${name} with the ids this host allocated instead; the node runs as those." >&2
  fi

  node_account_read || { echo "node_account_ensure: the ${name} account is still not resolvable after creating it" >&2; return 1; }
}
