#!/usr/bin/env bash
# aperire-leftovers.sh - everything named aperire that is still on this host.
#
#   bash scripts/aperire-leftovers.sh
#   bash scripts/aperire-leftovers.sh --root /tmp/some-tree
#
# It reads. It removes nothing, changes nothing and needs no root for most of
# what it looks at. A place it cannot read as this account (/etc/sudoers.d is
# root's alone on Ubuntu, so is /root) gets a "not checked" line naming it and
# the one root command that reads it by hand, and is never counted as clean,
# because those are different (#1034).
#
# Exit status is the answer: 0 when nothing of ours is here, 1 when something
# is, 3 when nothing was found in the places it could read but at least one
# place could not be read. That is what makes it usable as the last step of an
# uninstall test on a lab box, where the interesting failure is the artefact
# nobody thought of.
#
# --root <dir> looks inside a directory as if it were /. It is how this file
# is tested, and it is also the honest way to check an image or a chroot. The
# host-only reads (systemd, access control entries) are skipped under it and
# said to be skipped.
#
# What counts as a leftover:
#
#   units          /etc/systemd/system/aperire*, and cloudflared-aperire
#   config         /etc/aperire, /etc/sudoers.d/aperire* (the three rules
#                  uninstall.sh removes are ours; any other is listed as
#                  not this install's),
#                  /etc/profile.d/aperire-go.sh, and everything under
#                  /var/lib/aperire: the signed releases, the verified-image
#                  records and a package kept for a rollback (an empty
#                  directory is listed too, since a wipe removes it)
#   programs       /usr/local/sbin/aperire*, /usr/local/bin/aperire*,
#                  /usr/local/lib/aperire*
#   accounts       aperire-advisor, aperire-dashboard, aperire-relay, and the
#                  aperire-svc group
#   commands       ~/.local/bin/aperire*
#   access         an access control entry for aperire-advisor or
#                  aperire-dashboard on a home, a node directory or the
#                  node config
#   the checkout   the directory a dashboard unit read from, and any
#                  aperire-one directory in a home
#   snapshots      aperire-one.previous-*, .rolled-back-* and .db-* beside it:
#                  the trees and database copies every update leaves (#860)
#
# What is NOT a leftover, and is never listed: your node, docker, Go, nvm.
# Those are the box, not the install.

set -uo pipefail

ROOT=""
FOUND=0
CHECKED=0
# Split from FOUND so the closing summary can print a remedy that is
# actually true of each row rather than one blanket claim: WIPE_FOUND is
# what uninstall.sh --wipe removes on the next run, MANUAL_FOUND is a name
# nothing here ever wrote (#518).
WIPE_FOUND=0
MANUAL_FOUND=0
# Update snapshots are the install's own, but uninstall.sh can only take them
# while it can still tell which checkout they belong to, so the remedy differs.
SNAP_FOUND=0
# Places this account could not read, so nothing can be said about them
# either way (#1034). Kept apart from CHECKED: a place that was not read was
# not looked at.
UNCHECKED=0

usage() {
  awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
}

# A name uninstall.sh has no claim on: a hand copy left beside a live file,
# or an internal tool's own backup convention (see fleet-backup.sh's own
# header for the same shape). Matched by the name, not by asking who wrote
# it, since nothing here has that answer. `.before-account` is NOT one of
# these: uninstall.sh globs for that suffix on every aperire-advisord* name,
# whether or not this run detected the instance it belonged to.
is_decorated_copy() {
  case "$1" in
    *.bak-*|*.pre-*) return 0 ;;
    *) return 1 ;;
  esac
}

# One line per thing found, one counter, so the exit status and the output
# cannot disagree. hit() is this install's own, and --wipe removes it on a
# later run; hit_manual() is a name nothing here ever wrote, and no run of
# this uninstaller touches it.
hit() { printf '  LEFT   %s\n' "$*"; FOUND=$((FOUND + 1)); WIPE_FOUND=$((WIPE_FOUND + 1)); }
hit_manual() { printf '  LEFT   %s   (not this install'"'"'s; nothing here removes it)\n' "$*"; FOUND=$((FOUND + 1)); MANUAL_FOUND=$((MANUAL_FOUND + 1)); }
hit_snapshot() { printf '  LEFT   %s   (an update snapshot)\n' "$*"; FOUND=$((FOUND + 1)); SNAP_FOUND=$((SNAP_FOUND + 1)); }
note() { printf '  ....   %s\n' "$*"; }
# $1 = the place, as it would be on a host, $2 = the root command that reads
# it by hand, $3 = what was being looked for there, if the place alone does
# not say. Never this file as root: it can sit in a checkout another account
# can write (#929).
unchecked() { printf '  ????   not checked: %s needs root%s; read it yourself with: %s\n' "$1" "${3:+ (to look for $3)}" "$2"; UNCHECKED=$((UNCHECKED + 1)); }
# A directory this account can list: read and search both. -r alone passes
# on a directory whose entries cannot then be reached.
can_list() { [[ -r "$1" && -x "$1" ]]; }
head_() { printf '\n%s\n' "$*"; }

# Every path this looks at goes through here, so --root is one rule rather
# than a prefix somebody has to remember at each call site.
p() { printf '%s%s' "$ROOT" "$1"; }

look_for_paths() { # $@ = absolute paths or globs, as they would be on a host
  local pattern f rel
  for pattern in "$@"; do
    CHECKED=$((CHECKED + 1))
    for f in $(compgen -G "$(p "$pattern")" || true); do
      rel="${f#"$ROOT"}"
      if is_decorated_copy "$rel"; then hit_manual "$rel"; else hit "$rel"; fi
    done
  done
}

check_units() {
  head_ "systemd units"
  look_for_paths '/etc/systemd/system/aperire*' '/etc/systemd/system/cloudflared-aperire.service'
  if [[ -z "$ROOT" ]] && command -v systemctl >/dev/null 2>&1; then
    local u
    while IFS= read -r u; do
      [[ -n "$u" ]] || continue
      hit "systemd knows unit $u"
    done < <(systemctl list-unit-files 'aperire*' --no-legend 2>/dev/null | awk '{print $1}')
  else
    note "systemd itself not asked (--root, or no systemctl here)"
  fi
}

# The sudo rules uninstall.sh removes, by the names the scripts here write
# them under (#818). The Advisor's retired rules (aperire-advisor and
# aperire-advisor-<name>, #1025) are the install's own only when they are
# exactly what an older release wrote, which is the test uninstall.sh removes
# them by: retired_advisor_rule below is the same function, kept identical by
# scripts/test-uninstall-units.sh. A file this account cannot read is listed
# with that said. Any other aperire* file in sudoers.d is listed, never
# claimed, because "the uninstaller takes it" would be untrue: a hand-placed
# rule (a lab aggregator had an `aperire ALL=(ALL) NOPASSWD:ALL` one, worth a
# look on its own).
OUR_SUDOERS=(aperire-restart aperire-model-key)
# Is this file exactly a sudo rule an older release wrote for the Advisor
# (#1025)? Two shapes shipped: one line, `<account> ALL=(root) NOPASSWD:
# <wrapper>` (the first account move), and later the same line with a comment
# header and two Defaults lines for that same account (trusted-path-lib.sh's
# writer, until ADR 0025). Every command is a node wrapper by path. Comments
# grant nothing; any other line, or a second grant, makes it somebody else's.
retired_advisor_rule() {  # $1 = the file
  [[ -f "$1" && ! -L "$1" ]] || return 1
  awk '
    /^[[:space:]]*(#|$)/ { next }
    !acct && match($0, /^[a-z_][a-z0-9_-]* ALL=\(root\) NOPASSWD: /) {
      acct = substr($0, 1, index($0, " ") - 1)
      n = split(substr($0, RLENGTH + 1), cmds, ", ")
      for (i = 1; i <= n; i++)
        if (cmds[i] !~ /^\/[^ ,]*aperire-node-wrapper(-[a-z0-9-]+)?(\.sh)?$/) bad = 1
      next
    }
    acct && $0 == ("Defaults:" acct " !requiretty") { next }
    acct && index($0, "Defaults:" acct " secure_path=/") == 1 && split($0, w, /[[:space:]]+/) == 2 { next }
    { bad = 1 }
    END { exit (acct && !bad) ? 0 : 1 }
  ' "$1" 2>/dev/null
}

check_sudoers() {
  local f rel name n d
  # root:root 0750 on Ubuntu, so as anyone else the glob below matches
  # nothing at all, and that used to read as a clean directory (#1034).
  d="$(p /etc/sudoers.d)"
  if [[ -d "$d" ]] && ! can_list "$d"; then
    unchecked /etc/sudoers.d "sudo ls -la /etc/sudoers.d"
    return 0
  fi
  CHECKED=$((CHECKED + 1))
  for f in $(compgen -G "$(p '/etc/sudoers.d/aperire*')" || true); do
    rel="${f#"$ROOT"}"; name="${rel##*/}"
    for n in "${OUR_SUDOERS[@]}"; do
      [[ "$name" == "$n" ]] && { hit "$rel"; continue 2; }
    done
    if [[ "$name" == aperire-advisor || "$name" == aperire-advisor-* ]]; then
      if [[ ! -r "$f" ]]; then
        hit "$rel   (could not read it as this account; run as root to tell whether it is a retired rule of ours)"
      elif retired_advisor_rule "$f"; then
        hit "$rel"
      else
        hit_manual "$rel"
      fi
      continue
    fi
    hit_manual "$rel"
  done
}

# /var/lib/aperire (#1005). It used to look at release/ alone, so the node
# wrapper's verified-image markers survived every wipe the lifecycle gate ran
# and nothing said so. Every entry in it is listed, a dotfile included: the
# three this tree writes are the install's own, and a wipe removes them and
# then the directory; anything else is not, and the directory stays for it.
# An empty directory is listed on its own, because a wipe removes that too.
OUR_VAR_LIB=(release verified-images rollback)
check_var_lib() {
  local d f rel name n any=0
  CHECKED=$((CHECKED + 1))
  d="$(p /var/lib/aperire)"
  [[ -e "$d" || -L "$d" ]] || return 0
  # Not a directory (a link, a file, anything else) is listed as itself.
  if [[ -L "$d" || ! -d "$d" ]]; then hit /var/lib/aperire; return 0; fi
  for f in "$d"/* "$d"/.[!.]* "$d"/..?*; do
    [[ -e "$f" || -L "$f" ]] || continue
    any=1
    rel="${f#"$ROOT"}"; name="${rel##*/}"
    for n in "${OUR_VAR_LIB[@]}"; do
      [[ "$name" == "$n" ]] && { hit "$rel"; continue 2; }
    done
    hit_manual "$rel"
  done
  [[ $any -eq 1 ]] || hit /var/lib/aperire
}

check_config() {
  head_ "configuration"
  look_for_paths '/etc/aperire' '/etc/profile.d/aperire-go.sh'
  check_sudoers
  check_var_lib
}

check_programs() {
  head_ "programs"
  look_for_paths '/usr/local/sbin/aperire*' '/usr/local/bin/aperire*' '/usr/local/lib/aperire*'
}

# Read from the passwd and group files rather than through getent, because
# that is the one lookup --root can honestly redirect. On a host with no
# --root the file IS what getent would answer for the local database, and a
# fleet account has never been anything but local.
check_accounts() {
  head_ "accounts and groups"
  local db name
  db="$(p /etc/passwd)"
  for name in aperire-advisor aperire-dashboard aperire-relay; do
    CHECKED=$((CHECKED + 1))
    if [[ -r "$db" ]] && grep -q "^${name}:" "$db" 2>/dev/null; then
      hit "account ${name}"
    fi
  done
  db="$(p /etc/group)"
  for name in aperire-advisor aperire-dashboard aperire-relay aperire-svc; do
    CHECKED=$((CHECKED + 1))
    if [[ -r "$db" ]] && grep -q "^${name}:" "$db" 2>/dev/null; then
      hit "group ${name}"
    fi
  done
}

# The homes to look in. Under --root every home in the tree, because there is
# no session to ask; on a host the invoking operator's, plus the one sudo came
# from, which is the account that owns an install.
operator_homes() {
  if [[ -n "$ROOT" ]]; then
    local d
    for d in "$ROOT"/home/* "$ROOT"/root; do
      [[ -d "$d" ]] && printf '%s\n' "$d"
    done
    return 0
  fi
  [[ -n "${HOME:-}" ]] && printf '%s\n' "$HOME"
  if [[ -n "${SUDO_USER:-}" ]]; then
    getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6
  fi
}

check_commands() {
  head_ "commands on PATH"
  local home f rel
  while IFS= read -r home; do
    [[ -n "$home" ]] || continue
    # A home or a bin this account cannot get into matches nothing below.
    if ! [[ -x "$home" ]] || { [[ -d "$home/.local/bin" ]] && ! can_list "$home/.local/bin"; } \
       || { [[ -d "$home/.local" ]] && ! [[ -x "$home/.local" ]]; }; then
      unchecked "${home#"$ROOT"}/.local/bin" "sudo ls -la ${home#"$ROOT"}/.local/bin" "aperire* commands"
      continue
    fi
    CHECKED=$((CHECKED + 1))
    for f in $(compgen -G "$home/.local/bin/aperire*" || true); do
      rel="${f#"$ROOT"}"
      if is_decorated_copy "$rel"; then hit_manual "$rel"; else hit "$rel"; fi
    done
  done < <(operator_homes | sort -u)
}

# The one class of leftover that is invisible in a directory listing: an
# access control entry granted to an account that has since been removed
# reads back as a bare numeric uid, and the next account created on the box
# inherits it.
check_access() {
  head_ "access control entries"
  if [[ -n "$ROOT" ]] || ! command -v getfacl >/dev/null 2>&1; then
    note "not read (--root, or no getfacl here)"
    return 0
  fi
  local target home acct
  while IFS= read -r home; do
    [[ -n "$home" ]] || continue
    CHECKED=$((CHECKED + 1))
    for acct in aperire-advisor aperire-dashboard; do
      if getfacl -p "$home" 2>/dev/null | grep -q "^user:${acct}:"; then
        hit "${acct} has an access control entry on $home"
      fi
    done
    # The node the dashboard runs sits under nvm in that home, and the
    # dashboard's account is given passage down to it (ADR 0024).
    local d
    for d in "$home/.nvm" "$home/.nvm/versions" "$home/.nvm/versions/node" \
             "$home"/.nvm/versions/node/* "$home"/.nvm/versions/node/*/bin; do
      [[ -d "$d" ]] || continue
      if getfacl -p "$d" 2>/dev/null | grep -q '^user:aperire-dashboard:'; then
        hit "aperire-dashboard has an access control entry on $d"
      fi
    done
  done < <(operator_homes | sort -u)
  # The node directory the privilege wrapper named, when that record is still
  # here. When it is not, the entry cannot be found from this side and saying
  # so is better than reporting clean.
  target="$(p /etc/aperire/node-wrapper.conf)"
  if [[ -r "$target" ]]; then
    local cfg
    cfg="$(awk -F= '$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$target" 2>/dev/null || true)"
    if [[ -n "$cfg" && -e "$cfg" ]]; then
      if getfacl -p "$(dirname "$cfg")" 2>/dev/null | grep -q '^user:aperire-advisor:'; then
        hit "aperire-advisor has an access control entry on $(dirname "$cfg")"
      fi
      # The dashboard's named read (ADR 0024): on the file and its directory.
      for target in "$cfg" "$(dirname "$cfg")"; do
        if getfacl -p "$target" 2>/dev/null | grep -q '^user:aperire-dashboard:'; then
          hit "aperire-dashboard has an access control entry on $target"
        fi
      done
    fi
  elif [[ -e "$target" ]] || { [[ -d "$(p /etc/aperire)" ]] && ! can_list "$(p /etc/aperire)"; }; then
    unchecked /etc/aperire/node-wrapper.conf "sudo cat /etc/aperire/node-wrapper.conf" "the node directory it names, and access control entries on it"
  else
    note "no node-wrapper.conf, so no node directory to check by name"
  fi
}

# What an update leaves beside the checkout. The names are the updater's own
# (scripts/get-aperire.sh, scripts/aperire-update.sh) and the same three
# patterns uninstall.sh matches. A symlink is never reported as a snapshot: it
# is neither a directory nor a file to the find below.
#
# Where it looks is said in the output, not assumed: the invoking account's
# home, the sudo user's, every other account's home from the passwd file, and
# the directory beside the checkout any dashboard unit still reads from. In
# each, the names <base>.previous-*, .rolled-back-* and .db-*, for base
# aperire-one and for the unit's checkout directory name when it is different.
# A checkout that was renamed and whose unit is gone cannot be found by name,
# and the output says so.
snapshot_places() { # prints "parent<TAB>base" lines
  local home wd par
  local -a bases=(aperire-one)
  if [[ -z "$ROOT" ]] && command -v systemctl >/dev/null 2>&1; then
    local u
    while IFS= read -r u; do
      [[ -n "$u" ]] || continue
      wd="$(systemctl show -p WorkingDirectory --value "$u" 2>/dev/null || true)"
      wd="${wd#WorkingDirectory=}"
      [[ -n "$wd" && "$(basename "$wd")" == dashboard ]] || continue
      par="$(dirname "$wd")"
      [[ -d "$par" && "$par" != / ]] || continue
      printf '%s\t%s\n' "$(dirname "$par")" "$(basename "$par")"
    done < <(systemctl list-unit-files 'aperire-server*' --no-legend 2>/dev/null | awk '{print $1}')
  fi
  local pw
  pw="$(p /etc/passwd)"
  {
    operator_homes
    if [[ -n "$ROOT" ]]; then :; elif [[ -r "$pw" ]]; then
      awk -F: '($3>=1000 && $3<65534) || $3==0 {print $6}' "$pw"
    fi
  } | sort -u | while IFS= read -r home; do
    [[ -d "$home" ]] || continue
    printf '%s\t%s\n' "$home" "${bases[0]}"
  done
}

check_snapshots() {
  local parent base f name suffix n=0 seen=""
  while IFS=$'\t' read -r parent base; do
    [[ -n "$parent" ]] || continue
    case "$seen" in *"|$parent/$base|"*) continue ;; esac
    seen="$seen|$parent/$base|"
    # A home this account cannot list hides its snapshots from the find below
    # as completely as an empty one would.
    if ! can_list "$parent"; then
      unchecked "${parent#"$ROOT"}" "sudo ls -a ${parent#"$ROOT"}" "update snapshots, aperire-one.*"
      continue
    fi
    CHECKED=$((CHECKED + 1)); n=$((n + 1))
    while IFS= read -r -d '' f; do
      name="$(basename "$f")"
      [[ "$name" == "$base".* ]] || continue
      suffix="${name#"$base".}"
      if [[ -d "$f" && ! -L "$f" ]]; then
        [[ "$suffix" =~ ^(previous|rolled-back)-[0-9]{8}T[0-9]{6}Z(-[0-9]+)*$ ]] && hit_snapshot "${f#"$ROOT"}"
      elif [[ -f "$f" && ! -L "$f" ]]; then
        [[ "$suffix" =~ ^db-[0-9]{8}T[0-9]{6}Z(-[0-9]+)*(-wal|-shm)?$ ]] && hit_snapshot "${f#"$ROOT"}"
      fi
    done < <(find -P "$parent" -mindepth 1 -maxdepth 1 \( -type d -o -type f \) -print0 2>/dev/null | sort -z)
  done < <(snapshot_places)
  note "update snapshots: looked for aperire-one.* (and a unit's own checkout name) in ${n} home/checkout parent(s); a renamed checkout with no unit left is not found by name"
}

check_checkout() {
  head_ "the checkout"
  local wd home
  if [[ -z "$ROOT" ]] && command -v systemctl >/dev/null 2>&1; then
    wd="$(systemctl show -p WorkingDirectory --value aperire-server.service 2>/dev/null || true)"
    wd="${wd#WorkingDirectory=}"
    if [[ -n "$wd" && -d "$wd" ]]; then
      hit "a dashboard unit still reads from $wd"
    fi
  fi
  while IFS= read -r home; do
    [[ -n "$home" ]] || continue
    if ! [[ -x "$home" ]]; then
      unchecked "${home#"$ROOT"}" "sudo ls -a ${home#"$ROOT"}" "an aperire-one checkout"
      continue
    fi
    CHECKED=$((CHECKED + 1))
    [[ -d "$home/aperire-one" ]] && hit "${home#"$ROOT"}/aperire-one"
  done < <(operator_homes | sort -u)
  check_snapshots
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --root)   ROOT="${2:?--root needs a directory}"; shift 2 ;;
      --root=*) ROOT="${1#*=}"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "unknown argument: $1 (run with --help)" >&2; exit 2 ;;
    esac
  done
  if [[ -n "$ROOT" ]]; then
    [[ -d "$ROOT" ]] || { echo "error: --root $ROOT is not a directory" >&2; exit 2; }
    ROOT="${ROOT%/}"
  fi

  echo
  echo "  ───── what is still here ─────"
  [[ -n "$ROOT" ]] && echo "  looking inside ${ROOT} as if it were /"

  check_units
  check_config
  check_programs
  check_accounts
  check_commands
  check_access
  check_checkout

  echo
  if [[ $FOUND -eq 0 && $UNCHECKED -eq 0 ]]; then
    echo "  nothing of ours is here (${CHECKED} places looked at)."
    echo
    return 0
  fi
  # Never the sentence above when a place went unread: that is the claim a run
  # without root used to make about /etc/sudoers.d without having looked.
  if [[ $FOUND -eq 0 ]]; then
    echo "  incomplete: no leftover in the ${CHECKED} places this account could read,"
    echo "  and ${UNCHECKED} it could not (the \"not checked\" lines above). Read each of those"
    echo "  with the command on its line. Anything there named aperire is a leftover."
    echo
    return 3
  fi
  echo "  ${FOUND} leftover(s), out of ${CHECKED} places looked at."
  if [[ $UNCHECKED -gt 0 ]]; then
    echo "  ${UNCHECKED} more could not be read as this account (the \"not checked\" lines above)."
  fi
  echo
  if [[ $WIPE_FOUND -gt 0 ]]; then
    echo "  ${WIPE_FOUND} of those are the install's own. To take them off, name the"
    echo "  checkout:  curl -fsSL https://get.aperire.one/uninstall | bash -s -- --dir <checkout> --wipe"
  fi
  if [[ $SNAP_FOUND -gt 0 ]]; then
    [[ $WIPE_FOUND -gt 0 ]] && echo
    echo "  ${SNAP_FOUND} of those are update snapshots, and the .db-* ones are copies of the"
    echo "  database, passkeys included. uninstall.sh --wipe takes them only while a"
    echo "  dashboard unit still names the checkout; after a --keep, or once the"
    echo "  checkout is gone, remove them by hand: cd <the directory> && rm -rf -- <name> ..."
  fi
  if [[ $MANUAL_FOUND -gt 0 ]]; then
    [[ $((WIPE_FOUND + SNAP_FOUND)) -gt 0 ]] && echo
    echo "  ${MANUAL_FOUND} of those are not this install's: a copy left beside a live file"
    echo "  (.bak-*, .pre-*), a sudo rule under a name the install does not write, or"
    echo "  an entry in /var/lib/aperire it does not keep. No run of uninstall.sh"
    echo "  takes them off; remove them by hand if you do not want them."
  fi
  echo
  return 1
}

main "$@"
