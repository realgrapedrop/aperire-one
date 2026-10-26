#!/usr/bin/env bash
# Put `advisory_delete=1` in a node's [node_db] stanza, issue #79.
#
# Why this exists as its own script. With `online_delete` alone, rippled
# decides when to rotate its NuDB store, so the window arrives unannounced.
# A node stopped inside one came back with an empty store and rebuilt from
# genesis (stock-node1, 2026-08-25). `advisory_delete=1` makes rotation
# something the host asks for, through the `can_delete` admin RPC, which is
# what lets the rotation and the restart be kept apart.
#
# The Advisor's wrapper can already set this key, `set-config
# advisory_delete=1`, but only when the line is already in the file, and on
# a stock deployment it is not. This adds it, and it runs without the Advisor,
# a break-glass window or a passkey, because the fleet rollout is a
# maintenance job and not an approved change to a running node.
#
# It does NOT restart the node. rippled reads its config at startup, so the
# change takes effect on the next restart, and that restart is the operator's
# to schedule (and, on a node that still rotates on its own, to time).
#
# Usage:
#   sudo bash scripts/enable-advisory-delete.sh [/path/to/rippled.cfg]
#
# With no path it reads CONFIG_FILE from /etc/aperire/node-wrapper.conf. It
# does not search: a script that guesses which config a node reads can edit
# the wrong one and report success.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf 'enable-advisory-delete: %s\n' "$*" >&2; exit 1; }

# The ACL-carrying helper this script shares with aperire-node-wrapper.sh's
# set-config, configure-rippled-paths.sh and migrate-node-nonroot.sh (#545).
[[ -r "${SCRIPT_DIR}/config-write-lib.sh" ]] \
  || die "${SCRIPT_DIR}/config-write-lib.sh is missing from this checkout"
# shellcheck source=scripts/config-write-lib.sh
. "${SCRIPT_DIR}/config-write-lib.sh"

CFG="${1:-}"
if [[ -z "$CFG" ]]; then
  WCONF=/etc/aperire/node-wrapper.conf
  [[ -r "$WCONF" ]] || die "no path given and $WCONF is not readable, pass the node's rippled.cfg explicitly"
  CFG=$(sed -n 's/^CONFIG_FILE=//p' "$WCONF" | head -1)
  [[ -n "$CFG" ]] || die "$WCONF names no CONFIG_FILE, pass the node's rippled.cfg explicitly"
  printf 'using %s (from %s)\n' "$CFG" "$WCONF"
fi

[[ "$CFG" == /* ]]        || die "the config path must be absolute, got '$CFG'"
[[ -f "$CFG" ]]           || die "no such file: $CFG"
[[ -w "$CFG" ]]           || die "$CFG is not writable by $(id -un), run with sudo"

hdr=$(grep -cE '^[[:space:]]*\[node_db\][[:space:]]*$' "$CFG" || true)
(( hdr > 0 )) || die "$CFG has no [node_db] stanza, so there is nothing to gate"
(( hdr == 1 )) || die "$CFG has $hdr [node_db] stanzas, which one rippled honours is not something this script can decide; fix that by hand first"

# One key, one value. rippled tolerates duplicate keys and picks one (last
# wins), so a file with two advisory_delete lines can read 1 to this script
# and still start with rotation on. The stock xrpld config ships a commented
# example block (#online_delete=512 with its own advisory_delete=0) that,
# left in, is exactly this second line. Refuse rather than guess which one
# rippled honours, the same call the stanza check above makes.
adc=$(awk '
  /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb = 1; next }
  inb && /^[[:space:]]*\[/               { inb = 0 }
  inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ { n++ }
  END { print n + 0 }
' "$CFG")
(( adc <= 1 )) || die "$CFG has $adc advisory_delete lines in [node_db]; rippled would pick one and this script cannot decide which, remove the extras by hand (the stock #online_delete=512 example block carries a stray one) so exactly one remains, then re-run"

# advisory_delete gates online_delete. Without a delete interval there is no
# rotation to gate, and setting this would look like protection that is not
# doing anything.
od=$(grep -oE '^[[:space:]]*online_delete[[:space:]]*=[[:space:]]*[0-9]+' "$CFG" | tail -1 |
     grep -oE '[0-9]+$' || true)
if [[ -z "$od" || "$od" == 0 ]]; then
  printf 'warning: %s sets no online_delete (or sets it to 0), so this node never rotates and advisory_delete gates nothing.\n' "$CFG"
  printf '         Setting it anyway is harmless, and correct if online_delete is turned on later.\n'
fi

current=$(awk '
  /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb = 1; next }
  inb && /^[[:space:]]*\[/               { inb = 0 }
  inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ {
    sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
  }
' "$CFG")

if [[ "$current" == "1" ]]; then
  printf '%s already has advisory_delete=1 in [node_db]. Nothing to do.\n' "$CFG"
  exit 0
fi

backup="$CFG.$(date +%Y%m%d-%H%M%S).bak"
cp -a "$CFG" "$backup"
cmp -s "$CFG" "$backup" || die "backup does not match the original"
cwl_prune_backups "$CFG" 10

stat -c '%U:%G:%a' "$CFG" >/dev/null || die "could not read the current owner and mode of $CFG"
was_snap=$(cwl_acl_snapshot "$CFG")

tmp=$(mktemp "$CFG.XXXXXX")
if [[ -n "$current" ]]; then
  # Present with the wrong value. Rewrite it in place, inside [node_db] only:
  # the key means nothing outside it, and a blind global rewrite would touch
  # a line this script was never asked about.
  awk '
    /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb = 1; print; next }
    inb && /^[[:space:]]*\[/               { inb = 0 }
    inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ { print "advisory_delete=1"; next }
    { print }
  ' "$CFG" > "$tmp"
  action="changed advisory_delete=$current to advisory_delete=1"
else
  # Absent. Added on the line after the header, where it is easy to find and
  # cannot land in the wrong section.
  awk '
    /^[[:space:]]*\[node_db\][[:space:]]*$/ && !done {
      print; print "advisory_delete=1"; done = 1; next
    }
    { print }
  ' "$CFG" > "$tmp"
  action="added advisory_delete=1"
fi

# Read the written file back the same way the original was read. The rewrite
# is proven by what the file now says, not by awk having exited zero.
now=$(awk '
  /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb = 1; next }
  inb && /^[[:space:]]*\[/               { inb = 0 }
  inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ {
    sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
  }
' "$tmp")
[[ "$now" == "1" ]] || { rm -f "$tmp"; die "the rewrite left advisory_delete reading '$now'; $CFG is untouched"; }

# At most one line changed, and it changed in one direction. diff reports one
# added line for the insert, one removed and one added for the rewrite.
changed=$(diff "$CFG" "$tmp" | grep -c '^[<>]' || true)
(( changed >= 1 && changed <= 2 )) || { rm -f "$tmp"; die "the rewrite moved $changed lines; $CFG is untouched"; }

# The node reads this file through a bind mount as its own account. A rewrite
# that lands correct content under a different owner makes rippled start on
# image defaults, silently (2026-08-19), and one that drops a named ACL entry
# is the same failure a layer further out: the node still owns the file, so
# it never notices, and it is the dashboard's and the relay's read that goes
# missing instead (#545). cwl_carry_permissions carries owner, group, mode
# AND the ACL in one call, so the write and the accounts reading it never
# come apart.
if ! cwl_carry_permissions "$CFG" "$tmp"; then
  rm -f "$tmp"
  die "could not carry $CFG's owner, group, mode and ACL onto the rewrite; $CFG is untouched"
fi
mv "$tmp" "$CFG"

now_own=$(stat -c '%U:%G:%a' "$CFG")
now_snap=$(cwl_acl_snapshot "$CFG")
if [[ "$now_snap" != "$was_snap" ]]; then
  if cwl_restore_from_backup "$backup" "$CFG"; then
    die "the rewrite changed $CFG's $(cwl_snapshot_describe); restored $backup and left the config reading exactly as it did before this ran, investigate before restarting the node"
  else
    die "the rewrite changed $CFG's $(cwl_snapshot_describe), AND restoring $backup failed; the node config's permissions are unproven, fix $CFG by hand from $backup before restarting"
  fi
fi

cat <<EOF
$action in $CFG
owner: $now_own (unchanged)
compared: $(cwl_snapshot_describe)
backup: $backup

Not in effect until the node restarts. Two things before you do that:

  1. This node still rotates on its own until it restarts. Check that one is
     not running right now:
         docker logs --tail 500 <container> | grep -E 'rotating|finished rotation'
     or, on a native install, tail the cfg's own [debug_logfile] instead:
         tail -n 500 <debug_logfile> | grep -E 'rotating|finished rotation'
     If the last line is "rotating" with no "finished rotation" after it,
     wait.
  2. After the restart, install the window that will schedule rotations from
     now on, or the store will grow forever:
         curl -fsSL https://get.aperire.one | bash -s -- --update --force
EOF
