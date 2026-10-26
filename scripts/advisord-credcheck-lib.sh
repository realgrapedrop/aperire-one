#!/usr/bin/env bash
# advisord-credcheck-lib.sh, the one place that names aperire-advisord's
# failure-recovery unit AND the one place that writes it (P2-093). Sourced,
# never executed, by install-advisord.sh and install-advisor-account.sh:
# the two scripts that rewrite aperire-advisord's own unit and therefore the
# two places OnFailure= gets written.
#
# Before this file existed, install-advisor-account.sh wrote OnFailure=
# naming the recovery unit and said, in a comment, that writing the unit
# itself was "not this script's to write", which meant a host that ran
# install-advisor-account.sh without ever running install-advisord.sh first
# got a unit that names a recovery service that does not exist, and systemd
# ignores an OnFailure= it cannot find. Sourcing this from both places means
# neither can write the reference without the definition coming along with
# it: one function, called wherever the name is used.
#
#   . "$REPO/scripts/advisord-credcheck-lib.sh"
#   CREDCHECK_UNIT_NAME="aperire-advisord-credcheck${SUFFIX}"
#   write_advisord_credcheck_unit "$REPO" "$UNIT_DIR" "$CREDCHECK_UNIT_NAME" "$INSTANCE"
#
# ---- why the program is copied to /usr/local/sbin (P1-090) -----------
#
# The unit this writes used to run scripts/aperire-advisord-credcheck.sh
# straight out of the checkout, as root, on OnFailure=. That is a file the
# dashboard's own unprivileged account owns and can rewrite (it is that
# account's checkout), and the Advisor's account can force the trigger just
# by crashing itself, so a unit shaped that way is root, on demand, for
# either account. Every other root program in this tree is copied out of
# reach of both of them first: install-model-key-sealer.sh says why, and
# does the same copy-compare-refresh dance this function does.
#
# Refreshed on every call, compare-then-install like the sealer: an absent
# or differing copy at the destination is replaced, a matching one is left
# alone so a re-run does not restart anything that does not need it.

# Where the checked-out program ends up. A variable only so a test can point
# it somewhere harmless; nothing here should ever pass anything else.
#
# Honoured only when this shell is not root (#1148): install-advisor-account.sh
# sources this as root, and a variable set in a root shell the login started
# would choose the directory root places the program, its helper and its library
# in. Whose account this is comes from id(1) at a fixed path and never from
# bash's $EUID, which bash imports from the environment (#1109); an id that
# cannot be read is root's answer. install-advisord.sh and the update source it
# as the operator, whose environment is the operator's own: a path from there
# reaches root only as the argument of a sudo the operator then authorises, and
# no uid test can tell that apart from a choice they made, which is why those
# callers are the decision recorded on #1148.
CREDCHECK_RUN_UID="$(/usr/bin/id -u 2>/dev/null)" || CREDCHECK_RUN_UID=0
_credcheck_movable() { [[ "$CREDCHECK_RUN_UID" =~ ^[0-9]+$ && "$CREDCHECK_RUN_UID" != 0 ]]; }
CREDCHECK_SBIN=/usr/local/sbin/aperire-advisord-credcheck
if _credcheck_movable; then CREDCHECK_SBIN="${APERIRE_CREDCHECK_SBIN:-$CREDCHECK_SBIN}"; fi
# The program's own dependency, copied out of the checkout beside it and for
# the same reason (#703): every file it writes under advisor/state goes
# through scripts/state-file.py, and a root program that resolved that helper
# inside a tree the dashboard account can rewrite would be root for that
# account. Shared with the sealer, which installs and removes the same path.
# Defaulted from CREDCHECK_SBIN's own directory rather than spelled out, so a
# test that points the program somewhere harmless points its helper at the
# same place without needing to know a second variable exists. On a real
# host they are installed beside each other for the same reason.
#
# Not read from APERIRE_STATE_TOOL_DEST (#1127): install-advisord.sh runs this
# as the operator and hands the path to sudo, so a variable the login set
# would pick the file root runs. It is checked before every such call, below.
CREDCHECK_STATE_TOOL="${CREDCHECK_SBIN%/*}/aperire-state-file"
# The owner root will accept for it. A plain assignment, so the environment
# cannot set it; a suite that needs another owner assigns it after sourcing.
CREDCHECK_TOOL_UID=0
# Is $1 a helper root may run? A regular file, not a link, owned by
# CREDCHECK_TOOL_UID, writable by neither group nor other.
_credcheck_tool_ok() { # $1 = path
  local meta
  [[ -f "$1" && ! -L "$1" && -r "$1" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$1" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$CREDCHECK_TOOL_UID" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}
# The other helper that travels with it (#708): the one place that says how
# this host keeps a model key and what the directive that loads it reads. The
# credential check judges both forms, so a copy without it refuses to judge
# anything. Same defaulting rule and the same reason as the state tool, and
# the same path install-model-key-sealer.sh places for the sealer.
CREDCHECK_METHOD_LIB="${CREDCHECK_SBIN%/*}/aperire-model-key-method"
if _credcheck_movable; then CREDCHECK_METHOD_LIB="${APERIRE_KEY_METHOD_LIB_DEST:-$CREDCHECK_METHOD_LIB}"; fi

# Runs $* as root: directly when this shell already is, through sudo when it
# is not. install-advisord.sh runs as the operator's own account and sudos
# per privileged line; install-advisor-account.sh requires EUID 0 for its
# whole run. Both call this function, so it has to work either way.
_credcheck_priv() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

# Where root keeps its own copy of the release-digests library, for a caller
# that has none beside this file. A constant as root: nothing in the
# environment may point root at a library to source (#955, L4). An
# unprivileged run may point it somewhere harmless; a test that runs as root
# (fakeroot) rewrites this one line in its copy instead, the way the digests
# library's own fixtures do.
CREDCHECK_ROOT_LIB=/usr/local/lib/aperire
# The environment is honoured on positive evidence of an unprivileged account
# only: the uid comes from id(1), never from bash's $EUID, which bash imports
# from the environment (#1109).
_cc_uid="$(/usr/bin/id -u 2>/dev/null || true)"
if [[ "$_cc_uid" =~ ^[0-9]+$ && "$_cc_uid" != 0 ]]; then
  CREDCHECK_ROOT_LIB="${APERIRE_CREDCHECK_ROOT_LIB:-$CREDCHECK_ROOT_LIB}"
fi
unset _cc_uid

# The release-digests library this shell may source, printed. Never one out of
# the tree being copied from: that file is the login's to change, and this
# runs as root (#952, ADR 0024). Beside this library first, which is the copy
# root staged out of the checked release; else root's own, when it is a
# regular file owned by root that nobody else can write. Resolved here and not
# when this file is sourced, because a caller can load this file's text over a
# pipe, where there is no file name to take a directory from.
_credcheck_rd_lib() {
  local here="" f meta
  [[ -n "${BASH_SOURCE[0]:-}" ]] && here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
  if [[ -n "$here" && -r "$here/release-digests-lib.sh" ]]; then
    printf '%s' "$here/release-digests-lib.sh"
    return 0
  fi
  f="$CREDCHECK_ROOT_LIB/release-digests-lib.sh"
  meta="$(stat -c '%F:%u:%a' -- "$f" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "regular file" ]] || return 1
  [[ "$(cut -d: -f2 <<<"$meta")" == 0 ]] || return 1
  (( (8#${meta##*:} & 8#022) == 0 )) || return 1
  printf '%s' "$f"
}

# One checked copy into a root location, as root. rd_install comes from
# release-digests-lib.sh, which a caller that already defines it (get-aperire.sh
# carries its own copy, so it never sources one out of a tree it is checking)
# does not load twice. The tree in $1 is what is copied FROM, checked against
# the release's digests; it is never where the library that does the checking
# comes from.
_credcheck_place() { # $1 = tree, $2 = path in the release, $3 = destination, $4 = mode
  local out rc=0 rd_lib
  if ! declare -F rd_install >/dev/null; then
    rd_lib="$(_credcheck_rd_lib)" || {
      echo "error: release-digests-lib.sh is not beside this library and $CREDCHECK_ROOT_LIB has no copy of it that root owns, so nothing can be copied as root" >&2
      return 1
    }
    # shellcheck source=scripts/release-digests-lib.sh
    . "$rd_lib" || {
      echo "error: $rd_lib could not be loaded, so nothing can be copied as root" >&2
      return 1
    }
  fi
  out="$(rd_priv rd_install "$1" "$2" "$3" "$4" --kinds)" || rc=$?
  case $rc in
    0) if [[ "$out" == same ]]; then
         echo "   $3  (already matches the release)"
       else
         echo "   $3  (root:root $4, copied from the one read that was checked)"
       fi ;;
    1) if [[ "$out" == refused:accounts ]]; then
         # Status 6, as in rd_install's callers: the account check could not
         # run, which says nothing about the file (#1111).
         echo "error: $3 was not written: the account check could not run (above), so $2 was not judged" >&2
         return 6
       fi
       echo "error: $3 was not written" >&2
       return 1 ;;
    *) echo "error: $3 was not written" >&2
       return 1 ;;
  esac
}

# write_advisord_credcheck_unit $1=REPO $2=UNIT_DIR $3=CREDCHECK_UNIT_NAME $4=INSTANCE
write_advisord_credcheck_unit() {
  local repo="$1" unit_dir="$2" name="$3" instance="$4"
  local src="$repo/scripts/aperire-advisord-credcheck.sh"
  local dest="$CREDCHECK_SBIN"
  local unit="$unit_dir/${name}.service"
  local advisord_unit="aperire-advisord${instance:+-$instance}"
  local dropin_dir="$unit_dir/${advisord_unit}.service.d"
  local env_line="" state_line=""
  [[ -n "$instance" ]] && env_line="Environment=APERIRE_INSTANCE=$instance"
  # The state directory this instance's model.json lives in, so the program
  # can leave a departure note beside it when it quarantines a credential
  # (#541 attribution). Not $REPO itself: the copied program at $dest has no
  # tree of its own to compute this from once it is out of the checkout.
  [[ -n "$repo" ]] && state_line="Environment=APERIRE_ADVISOR_STATE=$repo/advisor/state"

  if [[ ! -f "$src" ]]; then
    echo "error: $src is missing from this checkout" >&2
    return 1
  fi
  # Each copy is checked against the release's digests and made from the one
  # read that was checked (ADR 0024). A copy the release does not vouch for
  # stops here, before the unit that would name it is written.
  _credcheck_place "$repo" scripts/aperire-advisord-credcheck.sh "$dest" 0755 || return $?

  # The helper travels with it, on the same check. A credcheck refreshed
  # without one cannot leave the attribution note it exists to leave.
  if [[ ! -f "$repo/scripts/state-file.py" ]]; then
    echo "error: $repo/scripts/state-file.py is missing from this checkout" >&2
    return 1
  fi
  _credcheck_place "$repo" scripts/state-file.py "$CREDCHECK_STATE_TOOL" 0755 || return $?

  # And the method library (#708), the same way. A credcheck refreshed
  # without it cannot judge either form of credential and says so instead of
  # repairing the host.
  if [[ ! -f "$repo/scripts/model-key-method-lib.sh" ]]; then
    echo "error: $repo/scripts/model-key-method-lib.sh is missing from this checkout" >&2
    return 1
  fi
  _credcheck_place "$repo" scripts/model-key-method-lib.sh "$CREDCHECK_METHOD_LIB" 0644 || return $?

  local tmp
  # Every step is checked by hand: a caller that tests this function in an
  # `if` turns errexit off inside it, so a failed write has to return itself
  # (#898 review, N7).
  tmp="$(mktemp)" || return 1
  cat > "$tmp" <<UNITEOF || { rm -f "$tmp"; return 1; }
# Written by scripts/advisord-credcheck-lib.sh
[Unit]
Description=Aperire Advisor model-credential recovery (fires only when ${advisord_unit}.service fails)

[Service]
Type=oneshot
User=root
${env_line}
${state_line}
ExecStart=$dest
# Only what systemd-creds decrypt, mv, rm and systemctl need. Not the fully
# hardened set aperire-advisord's own unit carries: this runs as root, not
# as an unprivileged account, so there is no capability set to strip without
# risking the one read (systemd-creds decrypt, which needs the host's
# credential secret or the TPM) this program exists to make.
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
# The credential store, the drop-in this program removes, and the state
# directory it leaves the attribution note in, and nothing else.
# Dash-prefixed on all three: on a host with no /etc/aperire yet, a first
# failure with no drop-in ever written, or a state directory not yet
# created, the path this names does not exist, and ReadWritePaths on a path
# that is not there fails the unit at start (226/NAMESPACE) rather than
# letting the script report cleanly that there was nothing to do. The
# drop-in DIRECTORY is named, not its parent (/etc/systemd/system):
# removing the drop-in FILE only needs write on the directory that holds
# it, and rmdir-ing that directory once it is empty already fails silently
# and harmlessly if this program cannot reach the directory's own parent.
# It always has, in the tree this was written against.
ReadWritePaths=-/etc/aperire -$dropin_dir -$repo/advisor/state
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
StandardOutput=journal
StandardError=journal
UNITEOF

  if ! _credcheck_priv install -o root -g root -m 0644 "$tmp" "$unit"; then
    rm -f "$tmp"
    echo "error: $unit was not written" >&2
    return 1
  fi
  rm -f "$tmp"
  echo "   $unit"
}

# advisord_quarantine_path $1=the credential's real path. Prints the path to
# move it to (P3-095): the timestamp alone collides when two quarantines
# land in the same second, for instance a re-run of this installer right
# after aperire-advisord-credcheck.service has already fired on the same
# bad blob, and a second `mv -f` onto an existing quarantine file would
# silently overwrite the first one's evidence. The pid makes each call
# unique without needing to check what is already on disk.
advisord_quarantine_path() {
  printf '%s.unopenable-%s-%s' "$1" "$(date +%s)" "$$"
}

# write_advisord_credential_note $1=state dir $2=via $3=credential name
#
# The one thing the credential check cannot leave silent (#541 attribution).
# When it quarantines a credential, the Advisor's own next start records
# the departure on its ledger from what it observes
# (recordCredentialTransition, P2-081): "the configured language model's
# credential is no longer present on this host", with nothing to say why.
# This is the same note shape aperire-seal-model-key.sh's write_change_file
# leaves beside a change it makes (at/via/credential_name; no by, no
# issuer, because nothing here was an operator's instruction), so the entry
# can add that the credential could not be opened on this host, discovered
# by the credential check, rather than reading as a removal nobody can
# explain.
#
# A failure here is reported, never swallowed: this program's whole point
# is telling a real failure apart from a silent one, and a note that goes
# missing without a word is exactly that shape (root_cause_not_workaround).
# Still non-fatal to the caller (`return 0` either way): a missing note
# means a departure entry with no attribution, which is the behaviour this
# fix started from, not a reason to leave the credential itself quarantined
# and the unit still down.
# The note is PLANTED, never written by name (#703). This function is sourced
# out of the checkout, so it resolves the helper beside itself; the copied
# program at /usr/local/sbin has its own resolution and its own copy.
write_advisord_credential_note() {
  local dir="$1" via="$2" cred="$3" tool err
  if [[ ! -d "$dir" ]]; then
    echo "warning: $dir does not exist; no attribution note left for $cred ($via)" >&2
    return 0
  fi
  tool="$CREDCHECK_STATE_TOOL"
  [[ -f "$tool" ]] || tool="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/state-file.py"
  if [[ ! -r "$tool" ]]; then
    echo "warning: no state-file helper at $tool; no attribution note left for $cred ($via)" >&2
    return 0
  fi
  # Root runs it below, so it has to be a file only root could have written:
  # the tree's copy, when this runs as the operator, is the operator's (#1127).
  if ! _credcheck_tool_ok "$tool"; then
    echo "warning: $tool is not a helper root will run (it must be a regular file owned by root and writable by no one else); no attribution note left for $cred ($via)" >&2
    return 0
  fi
  if ! err="$({
    printf '{\n'
    printf '  "at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "via": "%s",\n' "$via"
    printf '  "credential_name": "%s"\n' "$cred"
    printf '}\n'
  } | _credcheck_priv python3 -I "$tool" plant "$dir/model-change.json" dir dir 0640 --stdin 2>&1)"; then
    echo "warning: could not write an attribution note under $dir for $cred ($via): $err" >&2
    return 0
  fi
}
