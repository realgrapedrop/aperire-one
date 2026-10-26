#!/usr/bin/env bash
# One rule about dashboard/config/fleet-trust.yaml, in one place.
#
# The rule: the account advisord runs as must be able to READ the public keys
# in this file, and nobody outside that arrangement should be able to. And
# since #868 (ADR 0024 row 19): when the file holds a private_key, the
# Advisor's account must NOT be able to read it. Then the file is 0600 to the
# dashboard account and the Advisor reads fleet-trust.pub.yaml beside it,
# which scripts/fleet-trust-split.sh makes: the same peers, the public half
# of the key, and no private_key.
#
# Why it needs its own file. advisord verifies a pushed trust bundle against
# the aggregator's public key, and it holds that key in exactly one place —
# peers.<issuer> in fleet-trust.yaml. A file it cannot open makes every push
# fail with HTTP 403, and the operator sees it three hops away, at a passkey
# prompt on a node that says their credential is not enrolled. That is what
# happened on 2026-08-19: stock-node2's copy was aperire:aperire 0640 while
# advisord ran as its own account, so the push could never have landed even
# once the aggregator got around to sending it.
#
# The group is deliberately NOT hardcoded. install-advisor-account.sh names
# the shared group (aperire-svc today), install-advisord.sh may leave the
# service on the operator's own group, and at least one node in the fleet was
# set up by hand with a group called `advisord`. All three are correct
# arrangements; what matters is whether THIS host's advisord account can read
# THIS file. So the check resolves the account from the unit and asks which
# groups it is in, rather than asserting a name.
#
# Use it two ways:
#
#   bash scripts/fleet-trust-perms.sh [path]     one-shot check, prints a verdict
#   source scripts/fleet-trust-perms.sh          the functions, for another script
#
# Reads only. Needs no root. Never changes a mode — a signing-key file is
# tightened deliberately, by the installer, never as a side effect of a check.
# ft_target says what a program that CREATES the file gives it, so the
# check and the create cannot disagree about the rule.

# ── the pure part ────────────────────────────────────────────────────────
#
# Everything that decides a verdict takes its inputs as arguments so it can be
# tested without a systemd unit, an advisord account, or a real file. The
# wrappers below are the only part that touches the host.

# ft_verdict <mode> <file_owner> <file_group> <account> <account_groups_csv>
#
# Prints "<state>\t<message>" where state is ok | bad. Returns 0 for ok, 1 for
# bad, so a caller can branch on either.
#
# The mode every tool holds this file to. Exactly this, never "at most": see
# ft_verdict's own note.
FT_TRUST_MODE=640
# The mode a trust file that holds a private_key is held to (#868): its
# owner, the dashboard account, and nobody else.
FT_KEY_MODE=600
# The public half beside it, the file the Advisor reads in its place.
FT_PUB_LEAF=fleet-trust.pub.yaml
# The group install-advisor-account.sh puts the dashboard and the Advisor's
# own account in (its SHARED; aperire-backup-set.sh carries the same name).
# When both accounts are in it, it is THE group for this file: another group
# they happen to share, adm say, also lets in every other member of that
# group (#846 review, L4).
FT_SHARED_GROUP=aperire-svc

# ft_key_target <dashboard-account>
#
# Prints "<owner> <group> <mode>": what a NEW fleet-trust.yaml that holds a
# private_key is created with (install-fleet-broker-grant.sh). The dashboard
# account and its own primary group, 0600. Returns 1 for an account that
# does not exist.
ft_key_target() {
  local dash="$1" primary
  [[ -n "$dash" ]] || return 1
  primary="$(id -gn "$dash" 2>/dev/null)" || return 1
  [[ -n "$primary" ]] || return 1
  printf '%s %s %s\n' "$dash" "$primary" "$FT_KEY_MODE"
}

# ft_key_verdict <mode> <owner> <account> <measured-readable: yes|no|"">
#
# The rule for a trust file that holds a private_key. Prints
# "<state>\t<message>" like ft_verdict. The Advisor's account must not read
# it, and the mode is exactly 0600. One exception: an Advisor that runs as
# the dashboard account itself (a host that never moved it to its own) owns
# the file, and there is no second account to keep it from.
ft_key_verdict() {
  local mode="$1" owner="$2" account="$3" measured="${4:-}"
  if [[ "$owner" != "$account" ]]; then
    if [[ "$measured" == yes ]]; then
      printf 'bad\t%s\n' "measured: $account can read the private key in this file (#868). Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force (it narrows the key once the Advisor runs a build that reads fleet-trust.pub.yaml, and says so when it does not yet)"
      return 1
    fi
  fi
  if [[ "$mode" != "$FT_KEY_MODE" ]]; then
    printf 'bad\t%s\n' "it holds a private_key at mode $mode, expected $FT_KEY_MODE (#868). Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force (it narrows the key once the Advisor runs a build that reads fleet-trust.pub.yaml, and says so when it does not yet)"
    return 1
  fi
  if [[ "$owner" == "$account" ]]; then
    printf 'ok\t%s\n' "the private key is $owner's $FT_KEY_MODE, and the Advisor runs as $owner itself"
    return 0
  fi
  printf 'ok\t%s\n' "the private key is $owner's alone, $FT_KEY_MODE, not readable by $account"
  return 0
}

# ft_target <dashboard-account> [advisor-account] [advisor-groups-csv] [dashboard-groups-csv]
#
# Prints "<owner> <group> <mode>": what a trust file the Advisor has to READ
# is given: fleet-trust.pub.yaml beside a key file, or a node's peers-only
# fleet-trust.yaml. A NEW key file takes ft_key_target instead (#868), and
# #821's koi:koi 0600 is never made for a file the Advisor reads. The owner is the dashboard account, which signs with the key and
# owns the directory the file sits in (install-advisor-account.sh keeps the
# same owner when it re-grants the file). The group is one the Advisor's
# account and the dashboard account are both in, so both can read it; with
# no separate Advisor account, the dashboard account's own primary group.
#
# The third and fourth arguments are the Advisor account's and the dashboard
# account's groups, comma-separated, for a caller that has already looked
# them up; empty means ask `id` here. FT_SHARED_GROUP when both accounts are
# in it; otherwise the first group they share, which is the layouts this
# file's header names (a hand-made `advisord` group, an Advisor left on the
# operator's own group).
# Returns 1, printing nothing, when there is an Advisor account and the two
# share no group: no file made then could be read by both, and making one
# anyway is the 2026-08-19 failure.
ft_target() {
  local dash="$1" adv="${2:-}" adv_groups="${3:-}" dash_groups="${4:-}" g primary
  [[ -n "$dash" ]] || return 1
  if [[ -n "$adv" && "$adv" != root && "$adv" != "$dash" ]]; then
    [[ -n "$adv_groups" ]] || adv_groups="$(ft_account_groups "$adv")"
    [[ -n "$dash_groups" ]] || dash_groups="$(ft_account_groups "$dash")"
    dash_groups=",$dash_groups,"
    if [[ ",$adv_groups," == *",$FT_SHARED_GROUP,"* && "$dash_groups" == *",$FT_SHARED_GROUP,"* ]]; then
      printf '%s %s %s\n' "$dash" "$FT_SHARED_GROUP" "$FT_TRUST_MODE"
      return 0
    fi
    while IFS= read -r g; do
      if [[ -n "$g" && "$dash_groups" == *",$g,"* ]]; then
        printf '%s %s %s\n' "$dash" "$g" "$FT_TRUST_MODE"
        return 0
      fi
    done < <(printf '%s\n' "${adv_groups//,/$'\n'}")
    return 1
  fi
  primary="$(id -gn "$dash" 2>/dev/null)" || return 1
  [[ -n "$primary" ]] || return 1
  printf '%s %s %s\n' "$dash" "$primary" "$FT_TRUST_MODE"
}

ft_verdict() {
  local mode="$1" owner="$2" fgroup="$3" account="$4" groups_csv="$5"
  local readable=0

  if [[ "$owner" == "$account" ]]; then
    readable=1
  else
    local g
    while IFS= read -r g; do
      [[ -n "$g" && "$g" == "$fgroup" ]] && readable=1
    done < <(printf '%s\n' "${groups_csv//,/$'\n'}")
  fi

  if (( ! readable )); then
    printf 'bad\t%s\n' "group '$fgroup' (owner '$owner') is not readable by the advisor account '$account'"
    return 1
  fi
  # Readable through a group, but not the one this file belongs on. When the
  # Advisor's account is in FT_SHARED_GROUP, that is the group both accounts
  # were put in for this, and any other shared group lets its other members
  # read the aggregator's signing key too. Without it (an Advisor running as
  # the operator, a hand-made group) the shared group found above stands.
  if [[ "$owner" != "$account" && "$fgroup" != "$FT_SHARED_GROUP" \
        && ",$groups_csv," == *",$FT_SHARED_GROUP,"* ]]; then
    printf 'bad\t%s\n' "group '$fgroup' is not $FT_SHARED_GROUP, the group '$account' shares with the dashboard for this file; every other member of '$fgroup' can read the signing key"
    return 1
  fi
  # Exactly 0640. Not "at least group-readable": a signing key at 0644 is
  # readable by every account on the box, and this file is the only thing
  # standing between a local account and a forged trust bundle.
  if [[ "$mode" != "$FT_TRUST_MODE" ]]; then
    printf 'bad\t%s\n' "mode is $mode, expected $FT_TRUST_MODE"
    return 1
  fi
  printf 'ok\t%s\n' "$owner:$fgroup $FT_TRUST_MODE, readable by $account"
  return 0
}

# ── the host part ────────────────────────────────────────────────────────

# advisor-owner-lib.sh, sourced if it sits beside this file: the one place
# that walks a unit's effective User= through every drop-in, in the load
# order systemd itself applies (#589 reuses it rather than re-deriving the
# same fact a second way). Optional: a caller that copies this one file
# somewhere without its sibling still gets a working, if less thorough,
# reading further down.
FT_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -r "$FT_SELF_DIR/advisor-owner-lib.sh" ]]; then
  # shellcheck source=scripts/advisor-owner-lib.sh
  # shellcheck disable=SC1091  # resolved at runtime, beside this file
  source "$FT_SELF_DIR/advisor-owner-lib.sh"
fi

# ft_advisor_account [unit-dir] [unit-name] : the account advisord runs as,
# read from EXACTLY ONE unit, named by unit-name (default aperire-advisord),
# never a glob. A glob over "aperire-advisord*.service" used to also match
# aperire-advisord-credcheck.service, the OnFailure= handler
# install-advisor-account.sh writes beside the real unit, which runs
# User=root by design (and '-' sorts before '.' in ASCII, so that file was
# read FIRST), and every host reported "root can read" here, which is true
# of every file on the box and proves nothing about the account that
# actually needs to (#589).
#
# Prints the account name; "root" when the unit's effective User= is root or
# was never assigned anywhere the walk looked (systemd's own default,
# systemd.exec(5)) while the unit DOES exist; or empty when no such unit
# exists on this host at all. Those are three different facts a caller has
# to tell apart, not one "nothing to test" bucket: root proves nothing about
# a file's readability, and a caller that treats it as "no unit" would skip
# a check this host actually needs, silently.
ft_advisor_account() {
  local dir="${1:-/etc/systemd/system}" name="${2:-aperire-advisord}"
  # A separate assignment, not folded into the `local` line above: bash
  # declares every name in a single `local a=.. b="$a"` statement before it
  # assigns any of them, so under `set -u` (this whole file runs under it,
  # sourced into a caller that does) referencing $dir while it is still being
  # declared on the same line reads as unbound, not as the value just given.
  local unit="$dir/${name}.service" eff
  [[ -e "$unit" || -L "$unit" ]] || { printf ''; return 0; }
  [[ -r "$unit" ]] || return 3
  # The one reader every other script uses too (#809), so the three answers
  # are decided in exactly one place.
  # Its exit 3 (a unit with no User= it can read) is handed back as is.
  if declare -F advisor_owner_unit_account >/dev/null 2>&1; then
    advisor_owner_unit_account "$unit"
    return
  fi
  # advisor-owner-lib.sh was not found beside this file: read the one exact
  # unit named above by hand, which alone (never having globbed) already
  # fixes the credcheck-unit mixup; drop-in overrides are simply not seen in
  # this fallback, the one thing the sourced walker adds over it. The same
  # [Service]-only reading, and the same exit 3 for a unit it cannot read a
  # User= out of, rather than root.
  eff="$(awk '
    /^[[:space:]]*\[/ { sec = $0; sub(/^[[:space:]]+/, "", sec); sub(/[[:space:]]+$/, "", sec); next }
    sec == "[Service]" && /^[[:space:]]*User[[:space:]]*=/ {
      v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]\r]+$/, "", v)
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
      u = v; seen = 1
    }
    END { if (!seen) exit 3; print u }' "$unit")" || return 3
  [[ -n "$eff" && "$eff" != 0 ]] || eff=root
  printf '%s' "$eff"
}

# ft_account_groups <account> — every group it can read a file through,
# comma-separated. Empty when the account does not exist on this host.
ft_account_groups() {
  local account="$1"
  [[ -n "$account" ]] || { printf ''; return; }
  id -nG "$account" 2>/dev/null | tr ' ' ','
}

# ft_measure_readable <account> <path>: asks the kernel directly, rather
# than deriving an answer from stat and group membership: those two cannot
# see a restrictive PARENT directory (0750 and tighter) standing between the
# account and a file it would otherwise read through. Prints "yes" or "no"
# and returns 0 when the question could actually be asked; returns 1,
# printing nothing, when it could not (no passwordless sudo, and no root to
# runuser with) so the caller knows to fall back rather than reading silence
# as a "no".
ft_measure_readable() {
  local account="$1" path="$2"
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    if sudo -n -u "$account" test -r "$path" 2>/dev/null; then printf yes; else printf no; fi
    return 0
  fi
  if [[ $EUID -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
    if runuser -u "$account" -- test -r "$path" 2>/dev/null; then printf yes; else printf no; fi
    return 0
  fi
  return 1
}

# ft_check_file <path> [unit-dir] [unit-name] : the whole check against a
# real file. Prints "<state>\t<message>"; state is ok | bad | skip | warn.
# Returns 0 unless bad.
#
# Readability is MEASURED first, through sudo or runuser, whichever this
# caller can actually reach: stat and id -nG is what the account resolves to
# on paper, and a 0750 (or tighter) directory somewhere above $path is
# invisible to both, so a file that reads as reachable by that math can
# still be a 403 the operator only ever meets three hops away, at a passkey
# prompt (2026-08-19). The derived verdict is kept as the fallback for a
# caller with neither sudo nor root, and the message always says which of
# the two produced the answer, so a green line never reads as measured when
# it was only ever a calculation.
ft_check_file() {
  local path="$1" dir="${2:-/etc/systemd/system}" name="${3:-aperire-advisord}" account groups key pub
  if [[ ! -e "$path" ]]; then
    printf 'skip\t%s\n' "no $path on this host (not a fleet member, or not joined yet)"
    return 0
  fi
  if ! account="$(ft_advisor_account "$dir" "$name")"; then
    printf 'bad\t%s\n' "the $name unit is there but names no User= under [Service] this can read (or cannot be read), so which account has to read $path is unknown -- check: systemctl cat $name"
    return 1
  fi
  if [[ -z "$account" ]]; then
    printf 'skip\t%s\n' "no advisord unit on this host, so nothing needs to read $path"
    return 0
  fi
  if [[ "$account" == root ]]; then
    # The unit exists and its effective User= is root (a unit with no User=
    # at all is the reader's refusal above, #809) (#589): testing as root
    # would say "yes" about any file on the box, so
    # that answer would be a green line that proves nothing. Amber, not ok.
    printf 'warn\t%s\n' "the $name unit's effective User= is root, which can read anything; this could not confirm the ACTUAL advisor account can read $path -- check: systemctl show $name -p User --value"
    return 0
  fi
  groups="$(ft_account_groups "$account")"
  if [[ -z "$groups" ]]; then
    printf 'skip\t%s\n' "the unit names account '$account', which does not exist on this host"
    return 0
  fi

  # #868: does this file hold a private_key? Then the Advisor reads the
  # public file beside it, and must not read this one.
  pub="$(dirname -- "$path")/$FT_PUB_LEAF"
  key="$(ft_holds_key "$path")"
  if [[ "$key" == yes || -e "$pub" || -L "$pub" ]] && [[ "$key" != no ]]; then
    ft_check_split "$path" "$pub" "$account" "$groups" "$key"
    return
  fi
  local line state msg
  line="$(ft_check_readable "$path" "$account" "$groups")"
  state="${line%%$'\t'*}" msg="${line#*$'\t'}"
  if [[ "$state" != bad && ( -e "$pub" || -L "$pub" ) ]]; then
    # A peers-only file with a public file still beside it: advisord reads
    # the public file, so it has to say the same.
    if [[ "$(ft_pub_in_sync "$path" "$pub")" == no ]]; then
      printf 'bad\t%s\n' "$pub is beside a trust file with no private_key and does not carry the same peers, and the Advisor reads it in that file's place. Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      return 1
    fi
  fi
  # A peers-only file holds the key the Advisor verifies every push against
  # (peers.aggregator). Root owns it as pairing makes it; an account that is
  # not the tree's owner (the dashboard's own, ADR 0024) owning it could
  # repin that key (#873 review, M2).
  if [[ "$state" != bad && "$key" == no && "$(dirname -- "$path")" == */dashboard/config ]]; then
    local fowner tree_owner
    fowner="$(stat -c '%U' "$path" 2>/dev/null)"
    tree_owner="$(stat -c '%U' "$(dirname -- "$(dirname -- "$(dirname -- "$path")")")" 2>/dev/null)"
    if ft_anchor_owner_bad "$fowner" "$tree_owner"; then
      printf 'bad\t%s\n' "$path holds this host's trust anchor (peers) and is owned by $fowner, which is neither root nor the tree's owner ($tree_owner), so that account could repin the key the Advisor trusts. Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      return 1
    fi
  fi
  # Unknown is never ok (#873 review, L2): with no public file, a file this
  # cannot read may be a key file at 0640 to the Advisor's group, which is
  # #868's own shape.
  if [[ "$state" != bad && "$key" == unknown ]]; then
    state=warn
    msg="$msg (whether it holds a private_key could not be checked: it is not readable here, and there is no passwordless sudo. Run this with sudo to know)"
  fi
  printf '%s\t%s\n' "$state" "$msg"
  [[ "$state" != bad ]]
}

# ft_anchor_owner_bad <file-owner> <tree-owner>: true when a peers-only
# trust file is owned by an account that is neither root nor the tree's
# owner, which could then repin the key the Advisor trusts (M2).
ft_anchor_owner_bad() {
  [[ -n "$1" && "$1" != root && -n "$2" && "$1" != "$2" ]]
}

# ft_holds_key <path>: yes | no | unknown. Does the file have a top-level
# private_key line? Read by this process when it can, else by root through
# sudo -n, never printed. Through sudo it COUNTS the lines (grep -c): a
# refused sudo prints nothing and exits 1, the same status as grep's "no
# match", so the status alone cannot tell "no key" from "not asked" (#873
# review, M1's class). Only a number printed is an answer.
ft_holds_key() {
  local path="$1" rc n
  if [[ -r "$path" ]]; then
    grep -q '^private_key:' -- "$path" 2>/dev/null; rc=$?
  elif [[ $EUID -eq 0 ]]; then
    grep -q '^private_key:' -- "$path" 2>/dev/null; rc=$?
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    n="$(sudo -n grep -c '^private_key:' -- "$path" 2>/dev/null)" || true
    case "$n" in
      0) rc=1 ;;
      [1-9]*) rc=0 ;;
      *) rc=2 ;;
    esac
  else
    printf unknown; return 0
  fi
  case "$rc" in 0) printf yes ;; 1) printf no ;; *) printf unknown ;; esac
}

# ft_pub_in_sync <trust-file> <pub-file>: yes | no | unknown. Does the public
# file carry every line of the trust file but the private_key line, in the
# same order? That is the part the Advisor uses (peers). The public_key line
# and the header comments fleet-trust-split.sh adds are left out of the
# comparison. The trust file is read through `grep -v`, so this process sees
# its public lines only, never the key.
ft_pub_in_sync() {
  local path="$1" pub="$2" want got
  [[ -r "$pub" ]] || { printf unknown; return 0; }
  if [[ -r "$path" || $EUID -eq 0 ]]; then
    want="$(grep -v '^private_key:' -- "$path" 2>/dev/null)" || [[ $? -eq 1 ]] || { printf unknown; return 0; }
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    # A sentinel line from inside the root shell, so a refused sudo (no
    # sentinel) is never read as an empty file (M1's class).
    # shellcheck disable=SC2016  # the root shell's own $1 and $?
    want="$(sudo -n sh -c 'grep -v "^private_key:" -- "$1"; echo "__ft_end:$?"' _ "$path" 2>/dev/null)" || true
    case "$want" in
      *__ft_end:0|*__ft_end:1) want="${want%__ft_end:*}"; want="${want%$'\n'}" ;;
      *) printf unknown; return 0 ;;
    esac
  else
    printf unknown; return 0
  fi
  got="$(grep -v -e '^public_key:' -e '^# ' -- "$pub" 2>/dev/null)" || true
  want="$(grep -v '^# ' <<<"$want")" || true
  if [[ "$want" == "$got" ]]; then printf yes; else printf no; fi
}

# ft_check_split <key-file> <pub-file> <account> <groups> <holds-key>
# The aggregator shape (#868): the key file 0600 and unreadable by the
# Advisor, the public file readable by it, 0640, and in step with the key
# file's peers.
ft_check_split() {
  local path="$1" pub="$2" account="$3" groups="$4" key="$5"
  local kmode kowner measured="" line kstate kmsg pline pstate pmsg sync
  kmode="$(stat -c '%a' "$path" 2>/dev/null)" || { printf 'skip\t%s\n' "could not stat $path"; return 0; }
  kowner="$(stat -c '%U' "$path" 2>/dev/null)"
  measured="$(ft_measure_readable "$account" "$path")" || measured=""
  line="$(ft_key_verdict "$kmode" "$kowner" "$account" "$measured")"
  kstate="${line%%$'\t'*}" kmsg="${line#*$'\t'}"
  if [[ "$kstate" == bad ]]; then
    printf 'bad\t%s\n' "$path: $kmsg"
    return 1
  fi
  if [[ ! -e "$pub" && ! -L "$pub" ]]; then
    printf 'bad\t%s\n' "$path holds a private_key and there is no $FT_PUB_LEAF beside it, so the Advisor has no public key to verify a pushed bundle or a self record with. Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    return 1
  fi
  pline="$(ft_check_readable "$pub" "$account" "$groups")"
  pstate="${pline%%$'\t'*}" pmsg="${pline#*$'\t'}"
  if [[ "$pstate" == bad ]]; then
    printf 'bad\t%s\n' "$pub: $pmsg"
    return 1
  fi
  if [[ "$key" == yes ]] && grep -q '^private_key:' -- "$pub" 2>/dev/null; then
    printf 'bad\t%s\n' "$pub holds a private_key line. It is the file the Advisor reads, and must carry public keys only. Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    return 1
  fi
  sync="$(ft_pub_in_sync "$path" "$pub")"
  if [[ "$sync" == no ]]; then
    printf 'bad\t%s\n' "$pub does not carry the same peers as $path, so the Advisor verifies against a stale copy. Fix: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    return 1
  fi
  local how=measured
  [[ -n "$measured" ]] || how="derived from file mode and owner; could not measure $account directly, no passwordless sudo and not root"
  printf '%s\t%s\n' "$pstate" "$kmsg ($how); public half: $pmsg$([[ "$sync" == unknown ]] && printf '%s' "; whether it is in step with the key file's peers could not be checked here")"
  [[ "$pstate" != bad ]]
}

# ft_check_readable <path> <account> <groups-csv>: the check for a file the
# Advisor has to read. Prints "<state>\t<message>".
#
# Readability is MEASURED first, through sudo or runuser, whichever this
# caller can actually reach: stat and id -nG is what the account resolves to
# on paper, and a 0750 (or tighter) directory somewhere above $path is
# invisible to both, so a file that reads as reachable by that math can
# still be a 403 the operator only ever meets three hops away, at a passkey
# prompt (2026-08-19). The derived verdict is kept as the fallback for a
# caller with neither sudo nor root, and the message always says which of
# the two produced the answer, so a green line never reads as measured when
# it was only ever a calculation.
ft_check_readable() {
  local path="$1" account="$2" groups="$3" mode owner fgroup
  if ! mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    printf 'skip\t%s\n' "could not stat $path"
    return 0
  fi
  owner="$(stat -c '%U' "$path" 2>/dev/null)"
  fgroup="$(stat -c '%G' "$path" 2>/dev/null)"

  local measured
  if measured="$(ft_measure_readable "$account" "$path")"; then
    if [[ "$measured" != yes ]]; then
      printf 'bad\t%s\n' "measured: $account cannot read $path (sudo -n -u $account test -r), owner '$owner' group '$fgroup' mode $mode"
      return 1
    fi
    if [[ "$mode" != "640" ]]; then
      printf 'bad\t%s\n' "mode is $mode, expected 640 (measured: $account can still read $path, which is the other half of the problem)"
      return 1
    fi
    printf 'ok\t%s\n' "$owner:$fgroup 640, measured: $account can read $path (sudo -n -u $account test -r)"
    return 0
  fi

  local derived dstate dmsg
  derived="$(ft_verdict "$mode" "$owner" "$fgroup" "$account" "$groups")"
  dstate="${derived%%$'\t'*}"
  dmsg="${derived#*$'\t'}"
  printf '%s\t%s (derived from file mode and group membership; could not measure %s directly, no passwordless sudo and not root)\n' \
    "$dstate" "$dmsg" "$account"
  [[ "$dstate" != "bad" ]]
}

# Run directly, or be sourced. ${BASH_SOURCE[0]} != $0 when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -uo pipefail
  _repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  _path="${1:-$_repo/dashboard/config/fleet-trust.yaml}"
  _line="$(ft_check_file "$_path")"
  _state="${_line%%$'\t'*}"
  _msg="${_line#*$'\t'}"
  printf '%s: %s\n' "$_state" "$_msg"
  [[ "$_state" == "bad" ]] && exit 1
  exit 0
fi
