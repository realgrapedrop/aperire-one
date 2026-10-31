#!/usr/bin/env bash
# aperire-backup-set.sh - the one file table, read by aperire-backup.sh,
# aperire-restore.sh and scripts/test-backup-restore.sh. Nobody else names
# this list a second time.
#
# Issue #544: the operational guide's own backup and restore sections were
# about seventy lines of pasted shell, and every drill against them (#514
# #515 #517 #535 #536 #537 #539) found a defect in that shell rather than in
# the idea. This file is the table the guide's own "Back up what a rebuild
# cannot recreate" section prints in prose; scripts/test-backup-restore.sh
# fails the moment the two disagree.
#
# Sourced, never run. Ships with the release (scripts/release-manifest.txt),
# because both aperire-backup.sh and aperire-restore.sh source it, and the
# second one runs on a freshly installed host that has nothing else.
#
#   # shellcheck source=scripts/aperire-backup-set.sh
#   . "$(dirname "${BASH_SOURCE[0]}")/aperire-backup-set.sh"
#
# ---- the table ---------------------------------------------------------
#
# One row per file (or small family of files sharing one rule), six columns,
# pipe-separated:
#
#   key       a short name, used in messages and in the backup set's own
#             directory layout
#   what      the guide's own words for it
#   where     a path. One leading "/" means an absolute path (under
#             /etc/aperire); anything else is relative to the install
#             directory, and may use brace expansion ({a,b,c}) the way a
#             shell would
#   required  "required" (every install has it) or "optional" (only some
#             host shapes do)
#   ownerdoc  what the owner and group ARE, in words. The real owner and
#             group applied on a restore come out of the backup's own
#             OWNERSHIP file, read off the live files at backup time, never
#             out of this column. This column is for the guide and for a
#             human reading a `bkset_print_table` run
#   mode      the mode those files carry
#   why       the guide's own words for why a rebuild cannot recreate it
#
# Five things a rebuild cannot recreate are deliberately NOT rows here, and
# all five stay that way on purpose:
#
#   - /etc/aperire/fleet-model.cred, or fleet-model.cred.plain on a host with
#     no systemd-creds (#711): an aggregator's copy of the fleet model, which
#     is every node's provider key. The sealed form opens only on this host;
#     the plain form is the key in the clear and a working key wherever a copy
#     lands. A rebuilt aggregator seals the fleet model again from Settings.
#
#   - /etc/aperire/creds, the sealed model credential. It is sealed to THIS
#     host's own key in /var/lib/systemd/credential.secret, which no backup
#     carries, so a copy of it is bytes that open nowhere else and, on this
#     same host after a wipe, sometimes open and sometimes don't (#514). A
#     rebuilt host gets its model back through the fleet push instead.
#   - your node's own config (rippled.cfg, its compose file or its unit).
#     Only you know where it lives, and it never contains the sealed
#     credential above but does hold your validator token, which this
#     tooling never reads. It stays a row here, marked "yours to place",
#     so the table is still the one place both scripts and the guide read,
#     and neither script ever touches it.
#   - advisor/evidence, the privilege wrapper's own log of every verb it has
#     been asked to run. It is a log, not state: nothing the Advisor decides
#     reads it back, and the pre-change snapshot a rollback actually checks
#     lives under advisor/state/evidence instead, which the advisor-state
#     row already carries whole. Losing this one on a restore costs history,
#     never a decision.
#   - advisor/knowledge-fleet, the signed corpus an aggregator pushes to
#     every node it fleet-links (ADR 0017). It is replaced whole, by rename,
#     on the next push, the same way the model credential above comes back
#     through the fleet rather than a copy; a copy taken here would also be
#     the wrong shape to trust, since a node verifies it against the
#     aggregator's own key, not against anything a backup could carry.
#     That holds on a node. On an aggregator the corpus is the source, so a
#     restore leaves it empty, and the next push would delete the fleet's
#     notes on every node. The push refuses that until the corpus is copied
#     back from a node and the operator confirms (#1236). Its record of what it
#     delivered to each node (advisor/knowledge-bundles/delivered.json) is not in
#     the set either, which is why the first push after a restore needs that
#     confirmation.
#
# Three things an aggregator holds ARE rows, on purpose, since #791 and #744:
# fleet-links.json (inside the fleet-config row), /etc/aperire/fleet-tokens
# and /etc/aperire/fleet-arm.key. Without them a restored aggregator passed
# every closing check while no node could link, be read or be armed. The arm
# key is a private key, like the trust-bundle signing key an aggregator's
# fleet-trust.yaml already carried in the fleet-config row: it opens an arm
# window on every node that trusts it, which is why the set stays owner-only
# and why the restore never overwrites a different key already on the host.
# /etc/aperire/fleet-nodes.conf stays out: root rebuilds it from fleet.yaml
# with install-fleet-broker-grant.sh --refresh-nodes.
# shellcheck disable=SC2034  # read by aperire-restore.sh, not by this file
BKSET_ADVISOR_SHARED_GROUP=aperire-svc  # install-advisor-account.sh's SHARED
BKSET_TABLE=(
  'database|The database|data/aperire.db|required|the dashboard account|0600|Your operators and their passkeys, the alert history, the whole metric and ledger history'
  'dashboard-config|The dashboard config|dashboard/config/{authn,channels,digest,rules.local}.yaml|required|the dashboard account|0640|Your alert choices, your channels, your sign-in settings'
  'fleet-config|The fleet config, if this host belongs to a fleet|dashboard/config/{fleet.yaml,fleet-trust.yaml,fleet-link.json,fleet-links.json}|optional|the dashboard account|0600|Which nodes an aggregator reads and where; the aggregator'"'"'s public key, without which a pushed model seal is refused as no_aggregator_pinned; this node'"'"'s own dial-out credential, minted once by pairing and never stored anywhere else; and, on an aggregator, the hash of every node'"'"'s link credential, without which no node can link'
  'relay-env|The dashboard'"'"'s env file, half of the relay token pair|/etc/aperire/aperire.env|required|root, group the dashboard account is in|0640|One credential in two files, generated at install'
  'relay-conf|The relay'"'"'s own config, the other half|/etc/aperire/relay.conf|optional|root, group the relay account is in|0640|Same credential as above; only present when this host also runs the relay'
  'advisor-state|The Advisor'"'"'s state, if this host runs one|advisor/state|optional|two groups, on purpose, see the Advisor section|0750 dir / 0640 files|Its audit ledger, its memory, the read and approve tokens an aggregator reads it with, and which model it is configured for'
  'fleet-arm-key|The trusted fleet arm key, if this host is fleet-joined|/etc/aperire/fleet-arm.pub|optional|root : root|0644|The public key this host checks a pushed model seal against'
  'fleet-tokens|The tokens an aggregator presents to its nodes, if this host is one|/etc/aperire/fleet-tokens|optional|root, group the dashboard and the Advisor share|0750 dir / 0640 files|A read token per paired node, and an approve token per node with an Advisor, each handed over by that node at pairing and kept nowhere else on this host; without them every node refuses this aggregator'"'"'s reads'
  'fleet-arm-private-key|The aggregator'"'"'s private fleet arm key, if this host is one|/etc/aperire/fleet-arm.key|optional|root : root|0600|Every node paired to this aggregator trusts its public half; a new key means pairing every one of them again'
  'fleet-trust-pin|Root'"'"'s pin of the aggregator'"'"'s fleet trust key, if this host is one|/etc/aperire/fleet-trust.pub|optional|root : root|0644|The one place root takes the fleet trust key from (#1008); a restore puts it back from here, never from the dashboard'"'"'s copy of the key'
  'fleet-arm-held-key|The held fleet arm key, if this host was paired before it had an Advisor|/etc/aperire/fleet-arm.paired.pub|optional|root : root|0644|The key a pairing handed this node (#720), kept until the Advisor install places it; without it, adding the Advisor after a rebuild is the #720 dead end again, a re-pair or a root line on the node'
  'node-config|The node'"'"'s own config|your rippled.cfg and its compose file or unit|yours to place|(yours)|(yours)|Not Aperire'"'"'s, but a rebuild needs it, and nothing here writes it'
)

bkset_field() {  # <row> <index 1-based>
  local row=$1 idx=$2
  IFS='|' read -r -a _f <<<"$row"
  printf '%s' "${_f[$((idx - 1))]}"
}

bkset_row() {  # <key> -> the pipe row, or nothing
  local key=$1 row
  for row in "${BKSET_TABLE[@]}"; do
    [[ "$(bkset_field "$row" 1)" == "$key" ]] && { printf '%s\n' "$row"; return 0; }
  done
  return 1
}

bkset_keys() { local row; for row in "${BKSET_TABLE[@]}"; do bkset_field "$row" 1; echo; done; }

# ── install layout, discovered from where this file itself lives ────────
# Both scripts run ON the host they act on, from inside the checkout that
# ships them, so there is no ssh round trip and no guessing a home directory:
# the tree containing scripts/ IS the install.
bkset_repo_dir() { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P; }

ETC_APERIRE=/etc/aperire
UNIT_DIR=/etc/systemd/system

# The one reader of the Advisor's account (#809), from the same checkout this
# file sits in, the way aperire-restore.sh already loads it for the Advisor's
# own state. Refused by name when it is missing: both callers source this
# file before they touch anything, so stopping here changes nothing.
if [[ ! -r "$(dirname "${BASH_SOURCE[0]}")/advisor-owner-lib.sh" ]]; then
  echo "error: $(dirname "${BASH_SOURCE[0]}")/advisor-owner-lib.sh is missing from this checkout. Nothing was changed." >&2
  exit 1
fi
# shellcheck source=scripts/advisor-owner-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/advisor-owner-lib.sh"

# instances_of <unit-prefix> -> one line per instance suffix this HOST has
# ("" for the un-suffixed one), same shape as uninstall.sh's own helper.
bkset_instances_of() {
  local prefix=$1 f n
  for f in "$UNIT_DIR/$prefix".service "$UNIT_DIR/$prefix"-*.service; do
    [[ -e "$f" ]] || continue
    n="$(basename "$f" .service)"
    n="${n#"$prefix"}"
    printf '%s\n' "${n#-}"
  done
}

# bkset_this_instance <repo_dir> -> the suffix ("" or "-node2" style name,
# without the leading dash) whose dashboard unit's WorkingDirectory is THIS
# checkout, the same match uninstall.sh's identify_checkout makes. Empty and
# rc=1 when nothing matches (a host with no dashboard unit at all); more than
# one match is rc=2, because a bare invocation on a multi-instance host has
# no way to guess which one you mean; pass --instance.
bkset_this_instance() {
  local repo=$1 here inst unit wd there matches=() f
  here="$(cd "$repo" && pwd -P)"
  for f in "$UNIT_DIR"/aperire-server.service "$UNIT_DIR"/aperire-server-*.service \
           "$UNIT_DIR"/aperire-read.service "$UNIT_DIR"/aperire-read-*.service; do
    [[ -e "$f" ]] || continue
    unit="$(basename "$f" .service)"
    wd="$(sed -n 's/^WorkingDirectory=//p' "$f" | head -1)"
    [[ -n "$wd" ]] || continue
    [[ "$(basename "$wd")" == dashboard ]] || continue
    there="$(cd "$(dirname "$wd")" 2>/dev/null && pwd -P)" || continue
    [[ "$there" == "$here" ]] || continue
    if [[ "$unit" == aperire-server || "$unit" == aperire-read ]]; then inst=""
    else inst="${unit#aperire-server-}"; inst="${inst#aperire-read-}"; fi
    matches+=("$inst")
  done
  if [[ ${#matches[@]} -eq 0 ]]; then return 1; fi
  if [[ ${#matches[@]} -gt 1 ]]; then
    printf '%s\n' "${matches[@]}" | sort -u
    return 2
  fi
  printf '%s\n' "${matches[0]}"
  return 0
}

# The dashboard unit for a suffix: aperire-server first, aperire-read
# second (a fleet member's read-only peer runs the latter), same order
# install-advisor-account.sh already uses.
bkset_dash_unit() {  # <suffix, "" or "node2">
  local suf=$1 s name
  s="${suf:+-$suf}"
  for name in "aperire-server${s}" "aperire-read${s}"; do
    [[ -f "$UNIT_DIR/${name}.service" ]] && { printf '%s\n' "$name"; return 0; }
  done
  return 1
}

bkset_unit_user() { awk -F= '/^User=/{print $2; exit}' "$UNIT_DIR/$1.service" 2>/dev/null; }

# bkset_fleet_token_group <dashboard account> -> the group the token files
# under /etc/aperire/fleet-tokens belong to, resolved exactly the way
# aperire-fleet-broker.sh resolves its own SHARED_GROUP when it writes them:
# the first group of the Advisor's account that the dashboard is also in, or
# the dashboard's own primary group on a host with no Advisor, or with an
# Advisor that runs as root (root reads every file, so there is no second
# account to share a group with). Prints nothing and returns 1 when the
# Advisor has its own account and the two share no group, the case the
# broker refuses too. Returns 3, printing nothing, when the Advisor's unit
# is there but its account cannot be read out of it (advisor_owner_account's
# refusal, the broker's advisor_account_unread): that is never taken as
# root. One answer for both programs, so a restored token lands on the group
# the broker would have chosen.
#
# The account comes from aperire-advisord.service by that exact name, the
# unit the broker reads, never the first match of a glob: that glob found
# the credcheck unit first, read root, and refused every aggregator restore
# (#809).
bkset_fleet_token_group() {
  local dash=$1 adv cand dash_groups
  adv="$(advisor_owner_account "$UNIT_DIR")" || return 3
  if [[ -n "$adv" && "$adv" != root ]] && id -u "$adv" >/dev/null 2>&1; then
    dash_groups=" $(id -nG "$dash" 2>/dev/null) "
    for cand in $(id -nG "$adv" 2>/dev/null); do
      [[ "$dash_groups" == *" $cand "* ]] && { printf '%s\n' "$cand"; return 0; }
    done
    return 1
  fi
  id -gn "$dash" 2>/dev/null || return 1
}

bkset_advisor_unit() {  # <suffix>
  local suf=$1 s name
  s="${suf:+-$suf}"
  name="aperire-advisord${s}"
  [[ -f "$UNIT_DIR/${name}.service" ]] && { printf '%s\n' "$name"; return 0; }
  return 1
}

# The Advisor's --addr and --state, read off its own unit file directly
# (install-advisor-account.sh and install-advisord.sh write both straight
# into ExecStart, never a drop-in, so there is nothing to compose).
bkset_advisor_addr()  { sed -n 's/.*--addr=\([^ ]*\).*/\1/p'  "$UNIT_DIR/$1.service" 2>/dev/null | head -1; }
bkset_advisor_state() { sed -n 's/.*--state=\([^ ]*\).*/\1/p' "$UNIT_DIR/$1.service" 2>/dev/null | head -1; }

bkset_relay_unit() {  # <suffix>
  local suf=$1 s name
  s="${suf:+-$suf}"
  name="aperire-relay${s}"
  [[ -f "$UNIT_DIR/${name}.service" ]] && { printf '%s\n' "$name"; return 0; }
  return 1
}

# aperire<suffix>.env, falling back to the un-suffixed file the way
# install-advisor-account.sh does, so a second instance still finds the
# first one's port rather than defaulting to 7800.
bkset_env_file() {  # <suffix>
  local suf=$1 s f
  s="${suf:+-$suf}"
  for f in "$ETC_APERIRE/aperire${s}.env" "$ETC_APERIRE/aperire.env"; do
    [[ -r "$f" ]] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

bkset_env_key() { awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/,""); print; exit}' "$1" 2>/dev/null; }

# ── canonical, no-fallback instance paths ───────────────────────────────
# bkset_env_file above falls back to the un-suffixed file so a reader can
# still find a port; that fallback is wrong for a backup or a restore, both
# of which have to know exactly which instance's own file they are moving.
# These three never fall back and never check existence: they name where
# THIS instance's file belongs, whether or not it is there yet, so a caller
# can tell "not found" from "found at the wrong place" (#544 finding 098:
# --instance node2 backing up, and later overwriting, instance one's token).
bkset_env_path()        { local s=${1:+-$1}; printf '%s\n' "$ETC_APERIRE/aperire${s}.env"; }
bkset_relay_conf_path() { local s=${1:+-$1}; printf '%s\n' "$ETC_APERIRE/relay${s}.conf"; }

# bkset_db_path_from_env <repo> <suffix> <env-file> -> the database that env
# file's own APERIRE_DB_PATH names, or the suffixed default when it names
# none, or the env file cannot be read at all. install-aperire-service.sh
# writes APERIRE_DB_PATH into the instance's own env file whenever it lays
# one down, and honours it as an override if the operator sets it first, so
# this key is read before falling back to the suffixed default, or a host
# that moved its database with APERIRE_DB_PATH gets backed up and restored
# against the wrong file. Takes the env file as an explicit argument, rather
# than resolving it internally, because a restore has to decide this from
# the env file that will be IN FORCE once it lands, not from whatever is on
# the host before the set's own copy has been put back (#561).
bkset_db_path_from_env() {
  local repo=$1 suf=$2 s=${2:+-$2} envp=$3 fromenv
  fromenv="$(bkset_env_key "$envp" APERIRE_DB_PATH)"
  [[ -n "$fromenv" ]] && { printf '%s\n' "$fromenv"; return 0; }
  printf '%s\n' "$repo/data/aperire${s}.db"
}

# bkset_db_path <repo> <suffix> -> the database THIS instance opens right
# now, read off this host's own live env file. Used by aperire-backup.sh,
# which only ever reads the host as it stands; aperire-restore.sh uses
# bkset_db_path_from_env directly instead, with the env file it has decided
# will be in force once it finishes.
bkset_db_path() {
  local repo=$1 suf=$2
  bkset_db_path_from_env "$repo" "$suf" "$(bkset_env_path "$suf")"
}

# ── OWNERSHIP: the six-column record a copy alone cannot carry ──────────
# "mode uid gid owner group path", path last and absolute so it survives a
# restore onto a different target root or a rehearsal directory. The numbers
# are the record of what the ids were; the names are what a restore applies,
# because a rebuilt host hands its accounts whatever ids are free that day.
bkset_stat_line() {  # <path> -> "mode uid gid owner group path", or nothing
  local p=$1
  [[ -e "$p" ]] || return 1
  stat -c '%a %u %g %U %G %n' "$p" 2>/dev/null
}
