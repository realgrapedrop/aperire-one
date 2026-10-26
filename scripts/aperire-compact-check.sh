#!/usr/bin/env bash
# Does the operator compact on this host still name the node this host runs?
#
# The compact is accepted per node, and the node is named by its identity: the
# container's name on a container host, the systemd unit on a native one
# (#398). Change the shape of the node and that name changes under an
# acceptance the operator already made, the Advisor's own load refuses the
# pair, and every privileged class goes with it: no restart, no upgrade, no
# configuration change, no rollback. That refusal is right. What was missing
# is anything saying so at the moment it starts being true, which is a
# conversion run (#466). The first signal was a status block nobody has a
# reason to read.
#
# So this is read by the native install path at the end of its run. It reads
# three files and writes nothing:
#
#   /etc/aperire/node.conf              which node this host runs, KIND+SERVICE
#   /etc/aperire/node-wrapper.conf      the same, where the first is absent
#   <advisor state>/compact.json        which node the acceptance names
#
# It never accepts anything. Accepting terms is the operator's act, and a
# script that re-accepted them on their behalf would be accepting on behalf of
# a person who has not read them. It prints the exact command, carrying the
# privilege and the classes the old acceptance named, and stops there.
#
# Silent when there is nothing to say: no compact, no node, or a compact that
# names the node this host runs. A fresh install has accepted nothing, and
# telling that operator to accept again would be wrong.
#
#   bash scripts/aperire-compact-check.sh
#   bash scripts/aperire-compact-check.sh --node xrpld.service
#   bash scripts/aperire-compact-check.sh --state <install-dir>/advisor/state
#
# Exits 0 whether or not it found a mismatch: this is a notice at the end of a
# run that succeeded, not a gate on it.
set -euo pipefail

NODE=""
STATE="${APERIRE_ADVISOR_STATE:-}"
ETC_APERIRE="${APERIRE_ETC:-/etc/aperire}"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
# Defaulted, not assumed. Piped into bash over ssh (which is how an operator
# checks a host from their own machine) there is no BASH_SOURCE at all, and
# under set -u reading it ends the script before it has said anything.
SELF="${BASH_SOURCE[0]:-$0}"
SCRIPTS_DIR="$(cd "$(dirname "$SELF")" 2>/dev/null && pwd || echo .)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node)  NODE="${2:-}"; shift 2 ;;
    --state) STATE="${2:-}"; shift 2 ;;
    -h|--help) [[ -r "$SELF" ]] && sed -n '2,36p' "$SELF"; exit 0 ;;
    *) echo "aperire-compact-check: unknown argument '$1'" >&2; exit 64 ;;
  esac
done

# One key out of one of the installers' own record files. Read line by line,
# never sourced: these files are records, not shell.
conf_value() { # $1=file $2=key
  [[ -r "$1" ]] || return 0
  awk -F= -v k="$2" '$1==k { sub(/^[^=]*=/, ""); print; exit }' "$1"
}

if [[ -z "$NODE" ]]; then
  NODE="$(conf_value "${ETC_APERIRE}/node.conf" SERVICE)"
  [[ -n "$NODE" ]] || NODE="$(conf_value "${ETC_APERIRE}/node-wrapper.conf" SERVICE)"
fi
# SERVICE=none is the wrapper's own way of saying this host runs no node. It
# is not a node name and must never be compared against one.
[[ "$NODE" == "none" ]] && NODE=""
[[ -n "$NODE" ]] || exit 0

# Where the Advisor keeps its state. The unit is the authority: it was written
# with --state=<dir> by the Advisor's own installer, so it names the directory
# the service actually reads rather than one this script guessed at.
#
# That unit by its exact name, aperire-advisord.service, or the named
# instance's own when the installer that runs this has one (APERIRE_INSTANCE,
# the variable the node installers already carry), never the first match of a
# glob: a glob over aperire-advisord*.service also lists the credcheck unit
# (#541), which sorts first. Read by hand here rather than through
# advisor-owner-lib.sh, because piped over ssh this script has no tree beside
# it to source anything from.
if [[ -z "$STATE" ]]; then
  unit="${UNIT_DIR}/aperire-advisord${APERIRE_INSTANCE:+-${APERIRE_INSTANCE}}.service"
  if [[ -r "$unit" ]]; then
    line="$(grep -m1 '^ExecStart=' "$unit" || true)"
    if [[ "$line" =~ --state=([^[:space:]]+) ]]; then STATE="${BASH_REMATCH[1]}"; fi
  fi
fi
# A tree beside this script, which is where an operator running from a clone
# has one, and then the layout the installers lay down.
if [[ -z "$STATE" ]]; then
  for cand in "${SCRIPTS_DIR}/../advisor/state" /home/*/aperire-one/advisor/state; do
    if [[ -d "$cand" ]]; then STATE="$cand"; break; fi
  done
fi
[[ -n "$STATE" ]] || exit 0

COMPACT="${STATE%/}/compact.json"
[[ -r "$COMPACT" ]] || exit 0

# The three facts the notice needs, out of the acceptance. The file is written
# by the executor with one key per line and one class per line, so classes are
# collected across lines rather than assumed to be on the key's own.
read_compact() {
  awk '
    function qval(line,   s) {
      s = substr(line, index(line, ":") + 1)
      if (match(s, /"[^"]*"/)) return substr(s, RSTART + 1, RLENGTH - 2)
      return ""
    }
    /"node"[[:space:]]*:/       && node == ""      { node = qval($0) }
    /"privilege"[[:space:]]*:/  && privilege == "" { privilege = qval($0) }
    /"classes"[[:space:]]*:/ { inc = 1 }
    inc {
      s = $0
      if (index(s, "\"classes\"")) s = substr(s, index(s, ":") + 1)
      while (match(s, /"[^"]*"/)) {
        classes = classes (classes == "" ? "" : ",") substr(s, RSTART + 1, RLENGTH - 2)
        s = substr(s, RSTART + RLENGTH)
      }
      if (index($0, "]")) inc = 0
    }
    END {
      printf "AperireCompactNode=%s\n", node
      printf "AperireCompactPrivilege=%s\n", privilege
      printf "AperireCompactClasses=%s\n", classes
    }
  ' "$1"
}

FACTS="$(read_compact "$COMPACT")"
fact() { awk -F= -v k="$1" '$1==k { sub(/^[^=]*=/, ""); print; exit }' <<<"$FACTS"; }
ACC_NODE="$(fact AperireCompactNode)"
ACC_PRIV="$(fact AperireCompactPrivilege)"
ACC_CLASSES="$(fact AperireCompactClasses)"

# Nothing to say: no acceptance in the file, or one that names this host's
# node. Both are the ordinary case and both print nothing.
[[ -n "$ACC_NODE" ]] || exit 0
[[ "$ACC_NODE" != "$NODE" ]] || exit 0

# Whose account the command runs as, taken from the state directory itself
# rather than assumed: the acceptance is written there and has to stay
# readable by the service that reads it.
ACCT="$(stat -c '%U' "$STATE" 2>/dev/null || true)"
[[ -n "$ACCT" && "$ACCT" != "UNKNOWN" ]] || ACCT="<the account the Advisor runs as>"
ADVISOR_DIR="$(dirname "${STATE%/}")"

# The arguments are built before anything is printed, so the command is one
# valid line-continuation either way rather than a line that lost its
# backslash in the branch that adds to it.
ARGS="--accept --container=${NODE}"
UNREAD=0
if [[ -n "$ACC_PRIV" && -n "$ACC_CLASSES" ]]; then
  ARGS="${ARGS} --privilege=${ACC_PRIV} --classes=${ACC_CLASSES}"
else
  UNREAD=1
fi

C_BOLD=''; C_OFF=''; C_CYAN=''
if [[ -t 1 ]]; then C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'; C_CYAN=$'\033[36m'; fi

cat <<EOF

  ${C_BOLD}The Advisor on this host cannot act until the compact is accepted again.${C_OFF}

  The operator compact here was accepted for ${C_BOLD}${ACC_NODE}${C_OFF}, and this host now
  runs ${C_BOLD}${NODE}${C_OFF}. An acceptance is per node, so the Advisor refuses every
  privileged class until it names this one: restart, upgrade, configuration
  change and rollback are all refused, and it says so when you ask.

  Nothing here is broken and nothing is lost. Accepting terms is yours to do,
  so this run has not done it, and the terms themselves have not changed.

      ${C_CYAN}cd ${ADVISOR_DIR}
      sudo -u ${ACCT} ./bin/aperire-executor compact \\
        ${ARGS}${C_OFF}

EOF

if (( UNREAD )); then
  cat <<EOF
  ${COMPACT} names a privilege and a class list this could not read. Open it
  and pass the same --privilege and --classes it holds: the command above
  would otherwise accept a narrower compact than the one you had.

EOF
else
  cat <<EOF
  The privilege and the classes above are the ones ${COMPACT}
  already names, so this accepts what this host had, under its new identity.

EOF
fi
exit 0
