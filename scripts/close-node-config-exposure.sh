#!/usr/bin/env bash
# Close read access to the node's configuration file, which holds the
# validator token.
#
# WHY THIS EXISTS
#
# rippled.cfg contains [validator_token] — the key material the validator signs
# with. On a default Docker Compose deployment the file is created mode 0644
# and its directory 0775, so every account on the host can read it. That is
# usually invisible, because a validator host often has no other accounts.
#
# Installing the Advisor changes that. install-advisor-account.sh gives the
# Advisor's account (aperire-advisor by default, resolved below) a traversal
# ACL on the operator's home so it can reach its own state directory:
#
#     setfacl -m "u:aperire-advisor:--x" "$HOME"
#
# That grant is correct and minimal — it passes through without listing. But
# combined with a world-readable rippled.cfg further down the tree, the account
# whose entire purpose is that it cannot see key material can read the token
# directly, and never has to go through the wrapper that redacts it.
#
# The wrapper's redaction is then a convention rather than a boundary. §7 says
# the Advisor never reads validator key material; this makes the filesystem say
# it too.
#
# WHAT IT CHANGES
#
#   rippled.cfg           0644            ->  0640
#   its group             the operator's  ->  the group the node reads it as
#   its directory         0775            ->  0750
#   the Advisor account   refused the config directory outright (ACL)
#   the dashboard account granted a named read on the file and passage on
#                         the directory, where it is not already the owner
#
# THE GROUP IS THE PART THAT MATTERS, AND IT COST A VALIDATOR TO LEARN
#
# The first version of this script tightened the file to 0640 and left its
# group alone, on the reasoning that the container runs as root and root
# ignores file modes. That reasoning is wrong wherever the deployment drops
# capabilities — and a hardened compose file drops all of them:
#
#     cap_drop:
#       - ALL
#
# With an empty capability set there is no CAP_DAC_OVERRIDE, so the container's
# root is an ordinary uid 0 subject to the same permission bits as anyone else.
# It matches neither the owner nor the group, falls through to "other", and
# "other" is exactly what was just closed.
#
# Nothing appeared to break, which is the dangerous part. rippled reads its
# configuration once at startup and had been running for days, so the node
# stayed healthy and kept proposing. The failure was queued for the next
# restart — including the recreate that an Advisor upgrade performs, which is
# the worst possible moment to discover a config the node cannot open.
#
# So the file's group becomes the group the node actually reads it as, and this
# script refuses to finish unless it has watched the container read the file.
#
# WHAT IT DOES NOT CHANGE
#
# The node is not touched. No container is restarted, no service is restarted,
# and the validator does not stop. File permissions are evaluated when a file
# is opened, so a process that already holds the file open is unaffected.
#
# THE RELAY CAVEAT, AND ITS ORDERING
#
# aperire-relay runs as its own account and can parse rippled.cfg at startup to
# auto-detect the four ports the Network tab charts. Tightening the file would
# break that on any host relying on auto-detection. This script checks whether
# your relay needs it and, if so, grants that one account read access by ACL
# rather than leaving the file open to everyone.
#
# That grant cannot be made to an account that does not exist yet, and on a
# greenfield host it does not: install-aperire-node.sh runs first and calls
# this script at the end of its own run (#462), and the get.aperire.one
# one-liner runs second and is what creates aperire-relay. So the first close
# on a fresh host grants the relay nothing, because there is no relay.
#
# Two things carry that ordering. This script counts "the relay needs the file
# and has no entry on it" as work in its own right, so a run on an
# already-closed host still adds the entry rather than answering "nothing to
# do" about a reader it locked out. And install-aperire-relay.sh calls this
# script itself, once, when the relay it just created cannot read the config
# the relay.conf names. A native node ends the greenfield sequence with the
# relay reading its config; a container node, whose config sits under a home
# directory a service account cannot traverse, ends it being told plainly that
# port auto-detection is off and which four ports to pin instead.
#
# "Needs it" is judged by asking the relay's own installed binary, not by
# this script re-parsing relay.conf by hand. A shell reparse cannot tell a
# single-quoted TOML string from an unset value, a key inside an unrelated
# `[table]` from the top-level one relay.conf declares, or an explicit
# `= 0` from a pinned port, and every one of those misreadings decided a
# real ACL grant on a file that can hold [validator_token] (a security
# review, 2026-09-18). The relay binary itself parses its own config once,
# correctly, at real startup; `--print-effective-config` runs that same
# parsing and resolution and prints what it found, touching no network and
# no socket, so this script asks that instead of guessing. The binary is
# found from the installed unit's own ExecStart line (`systemctl cat`), not
# from a path this script assumes, and the file it names is compared to this
# one with `realpath -m` on both sides so a symlinked or relative path reads
# the same as a canonical one. Where the relay cannot be asked at all — no
# unit, an older binary built before this flag existed, a non-zero exit, or
# output this run cannot parse — the grant is left exactly as it already is
# (granted if absent, kept if present): the safe default this script has
# always used when it could not prove otherwise. Only a positive, parsed
# answer removes a named entry that answer says does nothing.
#
# USAGE
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure           # report only
#   curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply   # make the change
#
# Report mode changes nothing. Run it first.

set -euo pipefail

CONF=/etc/aperire/node-wrapper.conf
# The node installer's own record of the node on this host. The wrapper's
# configuration exists only where the Advisor was installed, and this script,
# the one thing that closes a world-readable node config, refused to look at a
# host without one (#437). A node-only box is the fleet's stock shape, and it
# is where that file sits at 0644 with other service accounts beside it.
# Either file names the node; the wrapper's wins where both are there because
# it names more of it. The Advisor-specific parts below stay skipped on a host
# with no Advisor, because they are about an account, not about the node.
NODE_CONF=/etc/aperire/node.conf
# The account the Advisor runs as. Resolved the same way
# install-advisor-account.sh resolves it, because the two scripts have to
# agree about which account they are talking about: an explicit
# APERIRE_ACCOUNT, else the User= of the installed aperire-advisord unit,
# else the installer's default (aperire-advisor). Hardcoded to `aperire`,
# this script once denied the *operator's* own config directory on a host
# whose operator happens to be named `aperire`, then failed its own check
# because the file's owner could still read it. A name is not an identity;
# take it from the same place.
ADVISOR_ACCOUNT=${APERIRE_ACCOUNT:-}
if [[ -z "$ADVISOR_ACCOUNT" ]]; then
  ADVISOR_ACCOUNT=$(systemctl show aperire-advisord -p User --value 2>/dev/null || true)
fi
ADVISOR_ACCOUNT=${ADVISOR_ACCOUNT:-aperire-advisor}
RELAY_ACCOUNT=aperire-relay
# The unit this script asks for the relay's own answer, standalone. Carries
# the same instance suffix install-aperire-relay.sh names its unit with
# (APERIRE_INSTANCE), so a second pairing on one host is asked about its own
# relay rather than the first one's.
RELAY_UNIT_NAME="aperire-relay${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
# The other way in. install-aperire-relay.sh's own section 5b calls this
# script BEFORE that unit exists on disk — the config close happens before
# the systemd unit is written — so asking `systemctl cat` here would find
# nothing on the exact run this grant matters most for. That caller already
# knows the binary it just installed and the config it just wrote, because it
# is the one that installed and wrote them, and hands both over directly
# rather than asking this script to find a unit that is not there yet.
RELAY_BIN_OVERRIDE=${APERIRE_RELAY_BIN:-}
RELAY_CONF_OVERRIDE=${APERIRE_RELAY_CONF:-}

# The dashboard's own run account. On a native install the config directory
# is the vendor package's, 0755 root:root, and passage into it is granted by
# name to the accounts that need it. Without the dashboard among them,
# dashboard/server.ts's own read of this file (the System tab's
# online_delete, advisory_delete, node_size and ledger_history rows) fails
# into a swallowed warning, and a host with a dashboard and no Advisor never
# ran anything that would have caught it (#462).
#
# Resolved from the installed unit, never assumed: aperire-server is the
# plain install, aperire-read is a fleet node's split-role name, and either
# carries an instance suffix (install-aperire-service.sh's SERVICE_NAME) on a
# host running more than one pairing side by side. The suffix is the same
# APERIRE_INSTANCE convention install-advisor-account.sh and aperire.sh both
# already resolve the dashboard unit by (#462 P3-077); a bare, unsuffixed
# enumeration found nothing at all on an instance host, LoadState reading
# not-found for both names even though a dashboard sat right beside them.
#
# LoadState is asked before User=, because is-active alone cannot tell "this
# unit is stopped" from "this unit was never installed" (both print
# inactive/3), and User= on a unit systemd has never heard of comes back
# empty, which would otherwise read as "runs as root" about a host with no
# dashboard at all.
DASH_SUFFIX="${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
DASHBOARD_UNIT=''
DASHBOARD_ACCOUNT=''
for _du in "aperire-server${DASH_SUFFIX}.service" "aperire-read${DASH_SUFFIX}.service"; do
  if [[ "$(systemctl show "$_du" -p LoadState --value 2>/dev/null)" == "loaded" ]]; then
    DASHBOARD_UNIT="$_du"
    DASHBOARD_ACCOUNT="$(systemctl show "$_du" -p User --value 2>/dev/null)"
    DASHBOARD_ACCOUNT="${DASHBOARD_ACCOUNT:-root}"
    break
  fi
done
unset _du
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

die()  { echo "  error: $*" >&2; exit 1; }
say()  { echo; echo "== $*"; }
info() { echo "   $*"; }

[[ $EUID -eq 0 ]] || die "run with sudo, it reads a root-owned config and changes file modes"

# ---------------------------------------------------------------- discover
# Everything is derived. Nothing here knows one operator's paths.

# Read, never sourced: these files decide what the Advisor may touch, so a
# shell metacharacter in one of them stays data.
conf_value() { # $1 = key, $2 = file
  [[ -r "$2" ]] || return 0
  awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$2"
}
SOURCED_FROM=''
CONFIG_FILE=''
SERVICE=''
# container or native (#30). Read because SERVICE means two different things
# depending on it: a container's name on one shape, a systemd unit on the
# other, and the native branch below asks systemd for the node's pid by that
# unit name (#463). Absent on an older wrapper configuration, which is why
# nothing here refuses on it.
KIND=''
for f in "$CONF" "$NODE_CONF"; do
  [[ -f "$f" ]] || continue
  [[ -n "$SOURCED_FROM" ]] && SOURCED_FROM="${SOURCED_FROM} and ${f}" || SOURCED_FROM="$f"
  [[ -n "$CONFIG_FILE" ]] || CONFIG_FILE=$(conf_value CONFIG_FILE "$f")
  [[ -n "$SERVICE" ]]     || SERVICE=$(conf_value SERVICE "$f")
  [[ -n "$KIND" ]]        || KIND=$(conf_value KIND "$f")
done
# Whether the privilege wrapper has a configuration at all, which is a
# different question from which node this host runs. The verify step below
# asks the wrapper to prove the node still reads its config, and on a host
# with no wrapper configuration that question has no answer: asking it anyway
# reads as "the wrapper can no longer read the configuration" and reverts a
# correct close.
WRAPPER_CONFIGURED=0
[[ -f "$CONF" ]] && WRAPPER_CONFIGURED=1

[[ -n "$SOURCED_FROM" ]] \
  || die "neither $CONF nor $NODE_CONF is here, so which node's config to close is not something this script can read. Install the node with scripts/install-aperire-node.sh, or the Advisor's wrapper with scripts/install-node-wrapper.sh, and run this again"
[[ -n "$CONFIG_FILE" ]] || die "CONFIG_FILE is not set in $SOURCED_FROM"
[[ -f "$CONFIG_FILE" ]] || die "CONFIG_FILE points at $CONFIG_FILE, which does not exist"
CONFIG_DIR=$(dirname "$CONFIG_FILE")

# The account must not be the file's owner. An owner reads their own file
# whatever the mode says, so "close the file to its owner" cannot be done,
# and a run that tries it applies, fails its own verify, and reverts: the
# exposure stays open and the output reads like the node was the problem.
# That is exactly what a fresh install did (#154): the account installer
# called this script before it had rewritten the unit, so User= still named
# the operator, who owns the config. The caller now says which account it
# means; this refuses to guess wrong a second time.
CONFIG_OWNER=$(stat -c '%U' "$CONFIG_FILE")
if [[ "$ADVISOR_ACCOUNT" == "$CONFIG_OWNER" ]]; then
  die "the Advisor account resolved to '$ADVISOR_ACCOUNT', which owns $CONFIG_FILE.
   That is the operator, not the Advisor: an owner can always read their own
   file, so there is nothing this script could close. This happens when the
   unit's User= still names the operator, before install-advisor-account.sh
   has rewritten it. Name the account explicitly:
     curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --account aperire-advisor"
fi

# The container shape, where nothing needs granting: the dashboard runs as
# the same account that installed the node under its own home directory, and
# an owner reads their own file whatever the mode says. Cleared here rather
# than refused, because this account not needing help is not the same
# failure as the Advisor owning the file, which means the whole close cannot
# happen at all.
if [[ -n "$DASHBOARD_ACCOUNT" && "$DASHBOARD_ACCOUNT" == "$CONFIG_OWNER" ]]; then
  DASHBOARD_ACCOUNT=''
fi

say "What is being protected"
info "read from   : $SOURCED_FROM"
info "config file : $CONFIG_FILE"
info "directory   : $CONFIG_DIR"
if grep -qE '^\s*\[validator_token\]' "$CONFIG_FILE"; then
  info "contains    : [validator_token], this host signs with this file"
else
  info "contains    : no [validator_token] stanza (stock or non-validating node)"
  info "              tightening it is still correct, but nothing urgent is exposed"
fi

# ---------------------------------------------------------------- diagnose

say "Who can read it today"

mode_file=$(stat -c '%a' "$CONFIG_FILE")
mode_dir=$(stat -c '%a' "$CONFIG_DIR")
info "file mode      : $mode_file  ($(stat -c '%U:%G' "$CONFIG_FILE"))"
info "directory mode : $mode_dir  ($(stat -c '%U:%G' "$CONFIG_DIR"))"

exposed=0
if [[ "${mode_file: -1}" =~ [4567] ]]; then
  info "the file is readable by every account on this host"
  exposed=1
fi

# The direct question, asked directly. An account either can open the file or
# it cannot; the permission arithmetic above is a description, this is a test.
reads_it() {
  id "$1" >/dev/null 2>&1 || return 1
  runuser -u "$1" -- test -r "$CONFIG_FILE" 2>/dev/null
}

if id "$ADVISOR_ACCOUNT" >/dev/null 2>&1; then
  if reads_it "$ADVISOR_ACCOUNT"; then
    info "the '$ADVISOR_ACCOUNT' account CAN read it, this is the finding"
    info "  it reaches the file through the traversal ACL the installer adds,"
    info "  and bypasses the wrapper's redaction entirely"
    exposed=1
  else
    info "the '$ADVISOR_ACCOUNT' account cannot read it, already closed"
  fi
else
  info "no '$ADVISOR_ACCOUNT' account on this host (Advisor not installed)"
fi

# Captured before anything changes, the same reason relay_could_read is: the
# verify below has to tell "my change broke the dashboard" from "the
# dashboard never had access", and a container node under an operator's home
# is the second case (a service account cannot traverse into it whatever
# entry it holds on the file itself).
dashboard_could_read=0
if [[ -n "$DASHBOARD_ACCOUNT" ]]; then
  if reads_it "$DASHBOARD_ACCOUNT"; then
    dashboard_could_read=1
    info "the dashboard account '$DASHBOARD_ACCOUNT' ($DASHBOARD_UNIT) can already read it"
  else
    info "the dashboard account '$DASHBOARD_ACCOUNT' ($DASHBOARD_UNIT) cannot read it yet"
  fi
elif [[ -n "$DASHBOARD_UNIT" ]]; then
  # DASHBOARD_ACCOUNT is empty here for the owner no-op at CONFIG_OWNER above
  # (#531), not for the "no dashboard on this host" reason the branch below
  # states. DASHBOARD_UNIT survives that no-op, so it is what tells the two
  # apart: a unit is loaded, and it happens to run as the account that
  # installed the node, which already reads its own file whatever the mode
  # says. True and worth saying on its own line, not silence and not the
  # "not installed" sentence a host running this unit right now does not
  # deserve.
  info "$DASHBOARD_UNIT runs as $CONFIG_OWNER, which owns $CONFIG_FILE, so it needs nothing granted"
else
  # Said, not left silent (#462 P3-078). On the greenfield native order the
  # node installer runs before any dashboard unit exists, so this run has
  # nothing to grant and nothing to verify; without this line that reads
  # exactly like a host that will never have a dashboard, when it is really
  # a host whose dashboard has not been installed yet.
  info "no aperire-server or aperire-read unit loaded here yet (dashboard not installed), nothing granted for it"
  info "  once it is: curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply"
fi

# ---------------------------------------------------------------- relay

say "Does the relay need to read this file?"

# ONE rule, asked of the relay itself: --print-effective-config loads
# relay.conf exactly as a real start does and prints node_config_path (the
# file it would open, empty if none) and reads_node_config (false once every
# port is pinned by value). No shell re-parse of relay.conf happens here
# anymore — see the header for what that used to get wrong.
#
# RELAY_ASK_NOTE explains a failed ask in one line; RELAY_ANSWER_BIN,
# RELAY_ANSWER_READS and RELAY_ANSWER_NODE_CFG hold a successful one. All are
# globals a function sets rather than returns, because bash function "return"
# is an exit code, not a value, and this needs to hand back several at once.
relay_answer_value() { # $1 = key, $2 = the printed key=value text
  awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' <<<"$2"
}
relay_ask() {
  local bin='' conf='' cat_out execline answer rc reads
  RELAY_ASK_NOTE=''
  RELAY_ANSWER_BIN=''
  RELAY_ANSWER_READS=''
  RELAY_ANSWER_NODE_CFG=''
  if [[ -n "$RELAY_BIN_OVERRIDE" && -n "$RELAY_CONF_OVERRIDE" ]]; then
    bin="$RELAY_BIN_OVERRIDE"; conf="$RELAY_CONF_OVERRIDE"
  else
    # `|| true` on every read here: systemctl, grep and a plain assignment are
    # all simple commands, and under `set -e` a non-zero exit from any one of
    # them — a unit systemd has never heard of, a line that is not there to
    # match — would end the whole script right here instead of reaching the
    # "cannot be asked" refusal this function exists to report.
    cat_out=$(systemctl cat "${RELAY_UNIT_NAME}.service" 2>/dev/null) || true
    if [[ -z "$cat_out" ]]; then
      RELAY_ASK_NOTE="no ${RELAY_UNIT_NAME}.service unit is loaded here"
      return 1
    fi
    # `systemctl cat` prints the unit file verbatim, comments and all; the
    # line this script needs is the literal ExecStart= install-aperire-relay.sh
    # wrote, binary path first, --config second. Not `systemctl show
    # -p ExecStart`, which prints the internal exec-command struct
    # (path=...;argv[]=...;...), a different shape a naive split would
    # misread as the binary's own path with the struct's punctuation stuck to it.
    #
    # The LAST match, not the first: `systemctl cat` concatenates the unit
    # file with every drop-in in load order, and a drop-in that overrides
    # ExecStart= does it the way systemd requires, an empty ExecStart= to
    # clear the old one and then the new value beneath it. systemd runs
    # whichever came last; taking the first would read a stale line off the
    # main unit while a drop-in silently pointed the real relay somewhere
    # else, which is the wrong-config shape this whole change exists to
    # close. No drop-in here sets ExecStart= today (this project's own
    # drop-in only ever sets EnvironmentFile=), so this is not reachable yet,
    # but the read should not depend on that staying true.
    execline=$(grep '^ExecStart=' <<<"$cat_out" | tail -1) || true
    execline=${execline#ExecStart=}
    bin=$(awk '{print $1}' <<<"$execline") || true
    conf=$(sed -nE 's/.*--config[[:space:]]+([^[:space:]]+).*/\1/p' <<<"$execline") || true
    if [[ -z "$bin" || -z "$conf" ]]; then
      RELAY_ASK_NOTE="${RELAY_UNIT_NAME}.service's ExecStart names no --config this run could read"
      return 1
    fi
  fi
  if [[ ! -x "$bin" ]]; then
    RELAY_ASK_NOTE="$bin is not here, or is not executable"
    return 1
  fi
  # `if`, not a bare assignment: this is the one call in this function whose
  # failure is expected and meaningful (an older build predating this flag
  # exits non-zero on an unrecognised option), and a bare
  # `answer=$(cmd); rc=$?` would let `set -e` end the script on that command
  # substitution before the next line ever reads $rc.
  if answer=$(timeout 10 "$bin" --print-effective-config --config "$conf" 2>/dev/null </dev/null); then
    rc=0
  else
    rc=$?
  fi
  if [[ $rc -ne 0 ]]; then
    RELAY_ASK_NOTE="$bin --print-effective-config exited $rc (an older build predating that flag answers the same way)"
    return 1
  fi
  reads=$(relay_answer_value reads_node_config "$answer") || true
  if [[ "$reads" != "true" && "$reads" != "false" ]]; then
    RELAY_ASK_NOTE="$bin printed something this run could not parse"
    return 1
  fi
  RELAY_ANSWER_BIN="$bin"
  RELAY_ANSWER_READS="$reads"
  RELAY_ANSWER_NODE_CFG="$(relay_answer_value node_config_path "$answer" || true)"
  # Whether every port is pinned by value, straight from the four *_source
  # fields the relay prints alongside its own resolved numbers. This is a
  # distinct fact from reads_node_config=false (that is also true whenever
  # auto-detection is needed but nothing is there to auto-detect FROM), and
  # it is worth its own sentence: one is a satisfied configuration, the other
  # is port auto-detection quietly not working.
  RELAY_ANSWER_ALL_PINNED=1
  local k
  for k in http_rpc_port admin_ws_port ws_public_port peer_port; do
    [[ "$(relay_answer_value "${k}_source" "$answer" || true)" == "override" ]] || { RELAY_ANSWER_ALL_PINNED=0; break; }
  done
  return 0
}

relay_needs=0
relay_could_read=0
relay_file_entry=0
relay_dir_entry=0
relay_over_granted=0
if id "$RELAY_ACCOUNT" >/dev/null 2>&1; then
  if relay_ask; then
    if [[ "$RELAY_ANSWER_ALL_PINNED" -eq 1 ]]; then
      info "no, all four ports are set explicitly in relay.conf"
    elif [[ "$RELAY_ANSWER_READS" == "true" ]]; then
      # Compared as realpath -m on both sides, not byte for byte (#085): a
      # symlinked, relative or doubled-slash path the relay opens is the same
      # file this script is closing even though the two strings differ.
      relay_resolved=$(realpath -m -- "$RELAY_ANSWER_NODE_CFG" 2>/dev/null) || true
      config_resolved=$(realpath -m -- "$CONFIG_FILE" 2>/dev/null) || true
      if [[ -n "$relay_resolved" && "$relay_resolved" == "$config_resolved" ]]; then
        info "yes, it auto-detects ports by parsing this file ($RELAY_ANSWER_BIN's own --print-effective-config)"
        info "  it will be granted read access by ACL, so the file closes to"
        info "  everyone else without blanking the connection-count charts"
        relay_needs=1
        # Whether it can read the file *now*, before anything changes. Without
        # this the verify below cannot tell "my change broke the relay" from "the
        # relay never had access", and a stock host is the second case: the
        # config sits under a home directory Ubuntu creates 0750, which a
        # dedicated service account cannot traverse. Blocking the whole close on
        # a condition that predates it is how the exposure stays open.
        if reads_it "$RELAY_ACCOUNT"; then
          relay_could_read=1
          info "  it can read the file today"
        else
          info "  NOTE: it cannot read the file today either, the config sits"
          info "  under a home directory it cannot traverse, so port"
          info "  auto-detection is already not working on this host"
        fi
      else
        info "no, its own configuration resolves to ${RELAY_ANSWER_NODE_CFG}, not this one"
      fi
    else
      info "no, its own configuration resolves to no file it can find"
      info "  rippled_cfg_path is not set in relay.conf, and this host's node config"
      info "  is not one of the three well-known paths it falls back to, so port"
      info "  auto-detection cannot work here no matter what this file grants"
    fi
  else
    # Cannot be asked at all: no unit, an older binary, a non-zero exit, or
    # output this run could not parse. The safe default this script has
    # always used when it could not prove otherwise — grant if absent, keep
    # if present — applies rather than guessing the relay away from a read it
    # may still need. Only a positive, parsed "no" above removes anything.
    info "could not ask: $RELAY_ASK_NOTE"
    info "  the relay could not be asked, so the read is left as the safe default"
    info "  (granted if it did not have one, kept if it did) rather than guessed away"
    relay_needs=1
    reads_it "$RELAY_ACCOUNT" && relay_could_read=1
  fi
  # A named entry left over from before the rule above was the rule, or from
  # a host where relay.conf changed after the grant was made (rippled_cfg_path
  # edited, or the four ports pinned afterwards). Checked here so the report
  # and the "Nothing to do" gate below both see it, and removed inside the
  # same snapshot this run takes of everything else (#532).
  if [[ "$relay_needs" -eq 0 ]]; then
    getfacl -p "$CONFIG_FILE" 2>/dev/null | grep -qE "^user:${RELAY_ACCOUNT}:" && relay_file_entry=1
    getfacl -p "$CONFIG_DIR"  2>/dev/null | grep -qE "^user:${RELAY_ACCOUNT}:" && relay_dir_entry=1
    if [[ "$relay_file_entry" -eq 1 || "$relay_dir_entry" -eq 1 ]]; then
      relay_over_granted=1
      info "  it already holds a named entry here from an earlier run; the rule above"
      info "  says it does not read this file, so this run removes it"
    fi
  fi
else
  info "no '$RELAY_ACCOUNT' account on this host"
fi

# ---------------------------------------------------------------- the node

say "How does the node itself read this file?"

NODE_GID=""      # the group the file must be readable by
NATIVE_USER=""   # set instead of MOUNT_DEST when the node runs natively
MOUNT_DEST=""    # where the container sees it
container_ok=""  # "", "yes" or "no"

# The container's view of the file, resolved rather than assumed. The mount is
# file-level, so the destination path is not derivable from the source name.
container_reads() {
  [[ -n "$MOUNT_DEST" ]] || return 1
  # `sh -c`, not a bare `test`. docker exec runs a binary, and `test` is a shell
  # builtin that most node images do not also ship as /usr/bin/test — so a bare
  # `docker exec ... test -r` reports "cannot read" on a file it can read
  # perfectly well. That false negative is why the first run of this script
  # reported the container check as a soft note instead of a hard failure.
  docker exec "$SERVICE" sh -c "test -r '$MOUNT_DEST'" 2>/dev/null
}

if [[ -n "${SERVICE:-}" ]] && command -v docker >/dev/null 2>&1 \
   && docker inspect "$SERVICE" >/dev/null 2>&1; then
  # One destination per LINE, sorted, then the first of them. The same host
  # file is mounted at two destinations now (#31: /etc/xrpld/xrpld.cfg, which
  # is the path the node opens, and /config/rippled.cfg, which is the path the
  # image's entrypoint and this project's path detection both look for).
  #
  # Two things had to be got right here. Without the newline this template
  # concatenated both destinations into one nonsense path, `test -r` on it
  # failed, and this script reported "the node cannot read its own
  # configuration" about a node reading it perfectly well, then reverted the
  # change it had just applied. And without the sort the answer wobbles:
  # docker does not list mounts in a stable order (measured on 28.3.3, three
  # consecutive inspects of one container gave two different orders), so the
  # path this reports would change between runs. Either destination is the
  # same file; what matters is that one path comes out and it is the same one
  # every time.
  #
  # The blank line is dropped before the sort, and that is not tidiness. The
  # template ends every destination with a newline and docker adds one of its
  # own, so the output carries an empty last line; an empty string sorts
  # before every path, the first line would answer it, and MOUNT_DEST would
  # come out empty. An empty MOUNT_DEST reads as "the node cannot read its
  # config", which is this script reverting a correct change and blaming the
  # node. Found by running this against a live container rather than by
  # reading it.
  #
  # The assignment carries its own failure, and that is #460. When the
  # recorded CONFIG_FILE is not the path this container mounts, the template
  # matches nothing, `grep -v` exits 1 with no lines, pipefail makes that the
  # pipeline's status, and under `set -e` a failing pipeline in an assignment
  # ends the script right here: nothing on either stream, status 1, halfway
  # through a report the operator was told to run. `awk NR==1` rather than
  # `head -1` for the same family of reason: head closes the pipe after the
  # first line, sort takes SIGPIPE, and 141 is a status this assignment would
  # then have to swallow as well.
  MOUNT_DEST=$(docker inspect "$SERVICE" \
    --format "{{range .Mounts}}{{if eq .Source \"$CONFIG_FILE\"}}{{.Destination}}{{\"\\n\"}}{{end}}{{end}}" 2>/dev/null \
    | grep -v '^[[:space:]]*$' | LC_ALL=C sort | awk 'NR==1') || MOUNT_DEST=''

  # And the sentence that replaces the blank terminal. A container that does
  # not mount the recorded file is not a container this script may close a
  # file for: the file it would tighten is not the one the node opens, and the
  # verify below would read the node's untouched config as the node losing it.
  # So both paths are named, from the container's own mount list rather than
  # from anything this script would guess.
  if [[ -z "$MOUNT_DEST" ]]; then
    MOUNT_SOURCES=$(docker inspect "$SERVICE" \
      --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' 2>/dev/null \
      | grep -v '^[[:space:]]*$' | LC_ALL=C sort | sed 's/^/                /') \
      || MOUNT_SOURCES=''
    die "$SERVICE does not mount $CONFIG_FILE, so there is nothing here to close.
   recorded path : $CONFIG_FILE
                   (read from $SOURCED_FROM)
   what $SERVICE mounts:
${MOUNT_SOURCES:-                nothing this run could read}
   The two have to be the same path, byte for byte. A record written by hand
   or restored from a backup, a parent directory that is a symlink, and a
   compose that mounts its config from somewhere else all arrive here. The
   file this would close is not the file the node opens, so nothing was
   changed. Put the mounted path in the record, or have the node measure
   itself again:
     curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt"
  fi
  NODE_UID=$(docker exec "$SERVICE" id -u 2>/dev/null || true)
  NODE_GID=$(docker exec "$SERVICE" id -g 2>/dev/null || true)
  caps=$(docker exec "$SERVICE" sh -c 'grep ^CapEff /proc/1/status' 2>/dev/null | awk '{print $2}')

  info "mounted at  : ${MOUNT_DEST:-<not mounted>}"
  info "runs as     : uid ${NODE_UID:-?}, gid ${NODE_GID:-?}"

  # CAP_DAC_OVERRIDE is bit 1. Without it, uid 0 is an ordinary user for the
  # purposes of file permissions, and the mode bits decide everything.
  if [[ -n "${caps:-}" ]] && [[ $(( 0x$caps >> 1 & 1 )) -eq 1 ]]; then
    info "capabilities: holds CAP_DAC_OVERRIDE, file modes do not restrain it"
  elif [[ -n "${caps:-}" ]]; then
    info "capabilities: none (cap_drop: ALL), the mode bits fully apply to it"
    info "  so the file must be readable by gid ${NODE_GID:-?}, or the node"
    info "  cannot open its own configuration the next time it starts"
  fi

  if container_reads; then container_ok=yes; info "right now   : it can read the file"
  else container_ok=no;    info "right now   : it CANNOT read the file"; fi
else
  # Not a container deployment, or the container is not running. A natively
  # installed node is the same problem with a different way of asking: the
  # process reads the file as some account, and that account's group is what
  # the file must stay readable by. Found from the running process rather than
  # from a unit file, because the process is the ground truth for what it
  # actually runs as.
  info "no running container for '${SERVICE:-<unset>}', looking for a native node"
  NATIVE_PID=''

  # The unit the record names, first (#463). A process-name search cannot find
  # the vendor's node at all: /usr/bin/xrpld names its main thread xrpld-main,
  # so `pgrep -x xrpld` matches nothing on a host where the node has been up
  # for days, and this script refused on aperire2 with the node at `full` and
  # 22 peers. The unit is the fact the record already carries, and systemd
  # knows which pid belongs to it whatever the binary calls itself.
  #
  # Not asked on a host whose record says `container`: there SERVICE is a
  # container name, and a systemd unit that happens to share it is some other
  # program's pid, which would be answered with confidence and be wrong.
  if [[ -n "${SERVICE:-}" && "$KIND" != container ]] && command -v systemctl >/dev/null 2>&1; then
    NATIVE_PID=$(systemctl show "$SERVICE" -p MainPID --value 2>/dev/null || true)
    [[ "$NATIVE_PID" =~ ^[1-9][0-9]*$ ]] || NATIVE_PID=''
    [[ -n "$NATIVE_PID" ]] && info "from record : ${SERVICE} is running, MainPID ${NATIVE_PID}"
  fi

  # The fallback, for a node nothing on this host recorded. Every name the
  # three forks have used, the vendor's -main thread name included, because
  # the whole point of this half is that there is no record to ask.
  #
  # `|| true` because pgrep exits 1 on no match, and under pipefail that
  # status survives `head` and kills the whole script at this assignment,
  # silently, before the deliberate "cannot reach the node" refusal below
  # ever gets to explain itself.
  if [[ -z "$NATIVE_PID" ]]; then
    for p in rippled xrpld xahaud xrpld-main rippled-main xahaud-main; do
      NATIVE_PID=$(pgrep -x "$p" 2>/dev/null | head -1 || true)
      [[ -n "$NATIVE_PID" ]] && { info "found by name: process '$p' pid $NATIVE_PID"; break; }
    done
  fi

  if [[ -n "${NATIVE_PID:-}" ]]; then
    # Guarded for the same reason the pgrep above is: a pid that went away
    # between the two reads makes `ps` exit non-zero, and under `set -e` that
    # would end the run here rather than at the refusal written for it.
    NATIVE_USER=$(ps -o user= -p "$NATIVE_PID" 2>/dev/null | tr -d ' ' || true)
    if [[ -z "$NATIVE_USER" ]]; then
      info "pid $NATIVE_PID is gone, so which account reads the file is not"
      info "  something this run can say"
    else
      NODE_GID=$(id -g "$NATIVE_USER" 2>/dev/null || true)
      info "native node : pid $NATIVE_PID running as '$NATIVE_USER' (gid ${NODE_GID:-?})"
      if reads_it "$NATIVE_USER"; then
        container_ok=yes; info "right now   : it can read the file"
      else
        container_ok=no;  info "right now   : it CANNOT read the file"
      fi
    fi
  else
    info "no running node found either, cannot verify the node's access"
  fi
fi

# ---------------------------------------------------------------- report

# Three independent problems. The file being open to everyone is the one we
# came for; the node being unable to read it is one a previous tightening can
# have caused, and it is the more urgent of the two because it is silent until
# a restart.
broken_node=0
[[ "$container_ok" == "no" ]] && broken_node=1

# And the third: a grant this script would make, that it has not made. The
# `exposed` test above reads the file's mode, and a file already at 0640 reads
# as closed however many readers it has locked out. #462 made that ordering
# ordinary rather than rare: the node installer now closes the config at the
# end of its own run, and on a greenfield host the relay's account does not
# exist yet, so the relay arrives afterwards with no named entry, cannot parse
# the config for the node's ports, and every later run of this script would
# have answered "Nothing to do" about it forever.
#
# Asked as "is the entry there", never as "can that account read the file".
# On a container node the config sits under a home directory the relay cannot
# traverse, so it cannot read the file either way; gating on the read would
# re-apply the whole change on every run of the commonest host shape and fix
# nothing there. Gating on the entry means a host that already has it is still
# a fast no-op, and a host missing it gets one apply and then becomes one.
#
# A host with no getfacl answers no here, which is the pre-#462 behaviour: the
# apply path below needs getfacl for its own revert snapshot and refuses
# without it, so guessing "ungranted" would only ever reach that refusal.
relay_ungranted=0
if [[ "$relay_needs" -eq 1 ]] \
   && ! getfacl -p "$CONFIG_FILE" 2>/dev/null | grep -qE "^user:${RELAY_ACCOUNT}:r"; then
  relay_ungranted=1
fi

# Same question, same reason, for the dashboard's own account (#462 P1-071).
# On native, the vendor's package leaves the directory 0755 root:root and
# nothing there names the dashboard's account at all until this run does.
dashboard_ungranted=0
if [[ -n "$DASHBOARD_ACCOUNT" ]] \
   && ! getfacl -p "$CONFIG_FILE" 2>/dev/null | grep -qE "^user:${DASHBOARD_ACCOUNT}:r"; then
  dashboard_ungranted=1
fi

if [[ "$exposed" -eq 0 && "$broken_node" -eq 0 && "$relay_ungranted" -eq 0 \
      && "$dashboard_ungranted" -eq 0 && "$relay_over_granted" -eq 0 ]]; then
  say "Nothing to do"
  info "the config is closed to other accounts and the node can still read it"
  exit 0
fi

if [[ "$relay_ungranted" -eq 1 && "$exposed" -eq 0 && "$broken_node" -eq 0 ]]; then
  say "The file is closed, and the relay was never granted its read"
  info "this is the ordering a fresh host has: the config is closed while the"
  info "node is installed, and '$RELAY_ACCOUNT' is created after that by the"
  info "dashboard install. Nothing here reopens the file; this run adds the one"
  info "named entry that account needs and leaves everything else as it is."
fi

if [[ "$relay_over_granted" -eq 1 && "$exposed" -eq 0 && "$broken_node" -eq 0 ]]; then
  say "The file is closed, and the relay holds a read it does not use"
  info "its own configuration does not resolve to this file (rippled_cfg_path names"
  info "something else, is unset with the node config off the three well-known"
  info "paths, or all four ports are pinned now). The entry an earlier run made"
  info "does nothing for it; this run removes it and leaves everything else as it is."
fi

if [[ "$dashboard_ungranted" -eq 1 && "$exposed" -eq 0 && "$broken_node" -eq 0 ]]; then
  say "The file is closed, and the dashboard's own account was never granted its read"
  info "this is the ordering a native host has: the vendor's package leaves"
  info "the directory closed to everyone from the start, and '$DASHBOARD_ACCOUNT'"
  info "($DASHBOARD_UNIT) was never named on it. Nothing here reopens the file;"
  info "this run adds the one named entry that account needs and leaves"
  info "everything else as it is."
fi

if [[ "$broken_node" -eq 1 ]]; then
  say "The node cannot read its own configuration"
  info "it is almost certainly still running: rippled reads this file once at"
  info "startup, so a process that started earlier is unaffected and keeps"
  info "proposing. The failure is queued for the next restart, including the"
  info "recreate an upgrade performs."
  info "this run repairs that."
fi

# The group the node reads the file as. Without a running container to ask,
# this cannot be established — and tightening a file when you cannot confirm
# the node still reads it is how the first version of this script queued a
# validator failure. Refuse instead.
mode_group=$(stat -c '%G' "$CONFIG_FILE")
target_group=""
if [[ -n "$NODE_GID" ]]; then
  target_group=$(getent group "$NODE_GID" | cut -d: -f1)
  target_group=${target_group:-$NODE_GID}
elif [[ "$exposed" -eq 1 ]]; then
  die "cannot reach the node, so it is not possible to confirm it
   would still read this file. Start the node and run this again, closing the
   file without that check is what breaks a validator at its next restart."
fi

if [[ "$APPLY" -eq 0 ]]; then
  say "What --apply would do"
  [[ -n "$target_group" && "$target_group" != "$mode_group" ]] && \
    info "chgrp $target_group $CONFIG_FILE   # the group the node reads it as"
  info "chmod 640 $CONFIG_FILE"
  info "chmod 750 $CONFIG_DIR"
  [[ "$relay_needs" -eq 1 ]] && info "setfacl -n -m u:$RELAY_ACCOUNT:r-- $CONFIG_FILE"
  [[ "$relay_file_entry" -eq 1 ]] && info "setfacl -n -x u:$RELAY_ACCOUNT $CONFIG_FILE   # unused, its own config does not read this path"
  [[ "$relay_dir_entry" -eq 1 ]] && info "setfacl -n -x u:$RELAY_ACCOUNT $CONFIG_DIR    # unused passage"
  [[ -n "$DASHBOARD_ACCOUNT" ]] && info "setfacl -n -m u:$DASHBOARD_ACCOUNT:r-- $CONFIG_FILE   # $DASHBOARD_UNIT"
  id "$ADVISOR_ACCOUNT" >/dev/null 2>&1 && \
    info "setfacl -n -m u:$ADVISOR_ACCOUNT:--- $CONFIG_DIR"
  [[ -n "$DASHBOARD_ACCOUNT" ]] && info "setfacl -n -m u:$DASHBOARD_ACCOUNT:--x $CONFIG_DIR"
  echo
  info "then it confirms the node can still read the file, and puts everything"
  info "back if it cannot."
  info "the node is not restarted and does not stop."
  info "re-run with --apply to make the change."
  exit 0
fi

# ---------------------------------------------------------------- apply

say "Applying"

# Recorded so the revert below is this host's real previous state, not an
# assumed default.
#
# Written once and never overwritten. A second run sees whatever the first run
# left behind, so overwriting would replace the original state with an
# already-modified one — and that is not hypothetical: the run that repaired
# the capability mistake recorded the half-applied state as the baseline,
# losing the only record of what the file started as.
#
# But only for the file it is CURRENTLY the backup of (#462 P3-075). A
# container-to-native conversion, or any change of which config this host
# runs, leaves an old backup naming a different path: keeping it means the
# undo this run prints at the end names the wrong file's original mode and
# group. The recorded `file=` line is compared against this run's own
# CONFIG_FILE, and a mismatch rotates the stale backup aside with a
# timestamp rather than either overwriting it silently or trusting it.
BACKUP=/etc/aperire/node-config-perms.before
backup_for=''
if [[ -f "$BACKUP" ]]; then
  backup_for=$(awk -F'file=' '/^file=/{split($2,a," "); print a[1]; exit}' "$BACKUP" 2>/dev/null)
fi
if [[ -n "$backup_for" && "$backup_for" != "$CONFIG_FILE" ]]; then
  stale="${BACKUP}.$(date +%Y%m%d%H%M%S)"
  mv "$BACKUP" "$stale"
  info "the recorded backup was for $backup_for, not $CONFIG_FILE (a container-to-native"
  info "conversion is the usual reason); moved it aside to $stale and starting fresh"
fi
if [[ -f "$BACKUP" ]]; then
  info "original state already recorded in $BACKUP, keeping it:"
  sed 's/^/     /' "$BACKUP"
else
  {
    echo "file=$CONFIG_FILE mode=$mode_file group=$mode_group"
    echo "dir=$CONFIG_DIR mode=$mode_dir"
  } > "$BACKUP"
  chmod 600 "$BACKUP"
  info "original state recorded in $BACKUP"
fi

# What this run found, as a whole: owner, group, mode bits and every ACL
# entry on both paths. The revert restores that snapshot, not a hand-written
# list of the entries this script knows how to add. The list was wrong on a
# second run: it removed the relay's read grant, which the first run had
# made and this run had not, and the connection-count charts went with it.
#
# Cleaned up on every path through one trap rather than a scattered `rm -f`
# at each exit: a failure in the getfacl right below used to leak this file
# into /tmp forever, because the removal lived only at the bottom of a
# script that `die` never reaches (#462 P2-072).
#
# Kept on disk, not removed, on the one path where it is evidence rather than
# litter: a revert that did not fully take (#462 P3-079). SNAPSHOT_KEEP is
# read by the trap below at exit time, not at the time this line runs, so
# setting it inside revert_and_report reaches all the way back here.
SNAPSHOT_DIR=/tmp
SNAPSHOT=$(mktemp "$SNAPSHOT_DIR/node-config-perms.XXXXXX")
SNAPSHOT_KEEP=0
trap '[[ "$SNAPSHOT_KEEP" -eq 1 ]] || rm -f "$SNAPSHOT"' EXIT
getfacl -p "$CONFIG_FILE" "$CONFIG_DIR" > "$SNAPSHOT" 2>/dev/null \
  || die "getfacl could not record the current permissions, so a revert would be a guess; not applying"

# Reverts to the snapshot and says whether the restore actually took, rather
# than assuming a `setfacl --restore` that exited zero put everything back
# (#462 P2-072). Compared byte for byte against the same `getfacl` this run
# took the snapshot with, because a restore that silently fails on one entry
# still exits zero.
revert_and_report() { # $1 = why this run is reverting
  local why="$1" before after
  say "Reverting, $why"
  before="$(cat "$SNAPSHOT" 2>/dev/null)"
  setfacl --restore="$SNAPSHOT" 2>/dev/null || true
  after="$(getfacl -p "$CONFIG_FILE" "$CONFIG_DIR" 2>/dev/null)"
  if [[ "$before" == "$after" ]]; then
    info "previous modes restored. nothing is changed."
    return 0
  fi
  SNAPSHOT_KEEP=1
  info "FAIL  the restore did not take; $CONFIG_FILE and $CONFIG_DIR may not"
  info "      match what they were before this run. The snapshot this run"
  info "      took is kept, not removed, so you have something to compare"
  info "      against: $SNAPSHOT"
  info "        diff <(cat $SNAPSHOT) <(getfacl -p $CONFIG_FILE $CONFIG_DIR)"
  return 1
}

# Every command from here to the end of the apply block is covered: a
# failure in any one of them (a read-only filesystem mid-grant, a setfacl an
# unusual filesystem refuses) must revert exactly the way a failed verify
# does, not exit under `set -e` with the file mutated and nothing put back
# (#462 P2-072). Cleared before the verify section, which has its own
# deliberately non-fatal reads and reports failure through `$fail` instead.
apply_failed() {
  local rc=$?
  trap - ERR INT TERM
  if revert_and_report "an apply step itself failed (exit $rc)"; then
    exit 1
  fi
  exit 2
}
trap apply_failed ERR

# An interrupt is not a failed command, so ERR never sees it, and the EXIT
# trap above only removes a temp file: it does not revert anything (#462
# P3-079). Left untrapped, Ctrl-C between the first chgrp and the last
# setfacl below stopped the script with the file mutated, no revert, and
# nothing said. Both signals run the same revert as a failed apply step, and
# then exit with the code the shell conventionally uses for that signal
# (130, 143) so a caller watching for "this died from a signal" still sees
# exactly that; the printed report, not the exit code, is what says whether
# the revert itself took.
apply_interrupted() {  # $1 = signal name, $2 = the exit code bash uses for it
  trap - ERR INT TERM
  revert_and_report "interrupted by SIG$1 mid-apply"
  exit "$2"
}
trap 'apply_interrupted INT 130' INT
trap 'apply_interrupted TERM 143' TERM

# The node's access goes on before the file closes, so there is no window in
# which it could lose the file. Same reasoning for the relay and the
# dashboard below.
if [[ -n "$target_group" && "$target_group" != "$mode_group" ]]; then
  chgrp "$target_group" "$CONFIG_FILE"
  info "$CONFIG_FILE -> group $target_group, which is how the node reads it"
fi

if [[ "$relay_needs" -eq 1 ]]; then
  setfacl -n -m "u:$RELAY_ACCOUNT:r--" "$CONFIG_FILE"
  info "$RELAY_ACCOUNT: granted read on the config file only"
elif [[ "$relay_file_entry" -eq 1 ]]; then
  # Captured before removal so the undo at the end prints the entry this run
  # actually took away, not the one it would have made had it granted
  # instead (this run's own removal branch never runs the grant branch
  # above, so REMOVED_RELAY_FILE_PERM is the only record of what was here).
  # Cut at the first whitespace, not to end of line: a masked entry prints as
  # `user:aperire-relay:rwx<tab><tab>#effective:r--`, and `(.*)$` would carry
  # the tab and the comment into the undo line below, printing a setfacl
  # argument nothing can run.
  REMOVED_RELAY_FILE_PERM=$(getfacl -p "$CONFIG_FILE" 2>/dev/null \
    | sed -nE "s/^user:${RELAY_ACCOUNT}:([^[:space:]]*).*/\1/p") || true
  setfacl -n -x "u:$RELAY_ACCOUNT" "$CONFIG_FILE"
  info "$RELAY_ACCOUNT: removed its read on the config file (its own configuration does not resolve to this path)"
fi

if [[ -n "$DASHBOARD_ACCOUNT" ]]; then
  setfacl -n -m "u:$DASHBOARD_ACCOUNT:r--" "$CONFIG_FILE"
  info "$DASHBOARD_ACCOUNT: granted read on the config file only ($DASHBOARD_UNIT)"
fi

chmod 640 "$CONFIG_FILE"; info "$CONFIG_FILE -> 640"
chmod 750 "$CONFIG_DIR";  info "$CONFIG_DIR -> 750"

if id "$ADVISOR_ACCOUNT" >/dev/null 2>&1; then
  setfacl -n -m "u:$ADVISOR_ACCOUNT:---" "$CONFIG_DIR"
  info "$ADVISOR_ACCOUNT: refused the config directory outright"
fi

# Passage through the config directory for the accounts that must still
# reach the file through it. At 750, an account that is neither the
# directory's owner nor in its group cannot traverse to a file it can
# otherwise read — a read ACL on the file alone is not enough, and that is
# exactly how the relay lost its port auto-detection on a fresh install even
# though it had been granted the file. Passage only: the advisor grant,
# inverted. Granted after the chmod above, not before it — an ACL added first
# turns that chmod into a mask-only change and the mask recalculation would
# quietly hand the old group bits back.
#
# Every change here passes -n, so the mask is never recomputed. Without it,
# `setfacl -m` and `-x` set the mask to the union of the group entry and every
# named entry left, and a named entry the mask was holding back gets what it
# names: an existing u:<someone>:rwx under a r-x mask became writable (found by
# ADR 0024 lane C). The mask stays the one the chmod above set, 750 here and
# 640 on the file, and every grant this run makes fits inside it.
if [[ -n "$NATIVE_USER" ]]; then
  setfacl -n -m "u:$NATIVE_USER:--x" "$CONFIG_DIR"
  info "$NATIVE_USER: granted passage through the config directory"
fi
if [[ "$relay_needs" -eq 1 ]]; then
  setfacl -n -m "u:$RELAY_ACCOUNT:--x" "$CONFIG_DIR"
  info "$RELAY_ACCOUNT: granted passage through the config directory"
elif [[ "$relay_dir_entry" -eq 1 ]]; then
  # Same reason the file-side removal captures its own perm string first.
  REMOVED_RELAY_DIR_PERM=$(getfacl -p "$CONFIG_DIR" 2>/dev/null \
    | sed -nE "s/^user:${RELAY_ACCOUNT}:([^[:space:]]*).*/\1/p") || true
  setfacl -n -x "u:$RELAY_ACCOUNT" "$CONFIG_DIR"
  info "$RELAY_ACCOUNT: removed its passage through the config directory"
fi
if [[ -n "$DASHBOARD_ACCOUNT" ]]; then
  setfacl -n -m "u:$DASHBOARD_ACCOUNT:--x" "$CONFIG_DIR"
  info "$DASHBOARD_ACCOUNT: granted passage through the config directory"
fi

# ---------------------------------------------------------------- verify
#
# Every claim this script makes, tested. A permissions change that silently
# broke the node would be far worse than the exposure it closes. From here
# on a failed read reports through $fail rather than the ERR/INT/TERM traps
# above: a reader that never had access is a note, not a broken apply step,
# and an interrupt here is the operator's to have, not this script's to
# revert over reads that were never a mutation.
trap - ERR INT TERM

say "Verifying"
fail=0

if id "$ADVISOR_ACCOUNT" >/dev/null 2>&1; then
  if reads_it "$ADVISOR_ACCOUNT"; then
    info "FAIL  $ADVISOR_ACCOUNT can still read the config"
    fail=1
  else
    info "ok    $ADVISOR_ACCOUNT can no longer read the config"
  fi
fi

if [[ -n "$DASHBOARD_ACCOUNT" ]]; then
  if reads_it "$DASHBOARD_ACCOUNT"; then
    info "ok    $DASHBOARD_ACCOUNT ($DASHBOARD_UNIT) can read it, the System tab keeps reading this file"
  elif [[ "$dashboard_could_read" -eq 1 ]]; then
    info "FAIL  $DASHBOARD_ACCOUNT ($DASHBOARD_UNIT) lost access, the System tab would go blank"
    fail=1
  else
    # It could not read the file before this ran either, the same shape as
    # the relay's own note below: a container node under an operator's home
    # blocks traversal above the directory this run just granted passage
    # through, and re-applying this change on every run would fix nothing.
    info "note  $DASHBOARD_ACCOUNT ($DASHBOARD_UNIT) still cannot read the config, as before this ran."
    info "      A directory above $CONFIG_DIR is blocking it, a container node under an"
    info "      operator's home is the usual reason. Grant passage there by hand if you"
    info "      want the System tab reading this file:"
    info "        sudo setfacl -n -m u:$DASHBOARD_ACCOUNT:--x $(dirname "$CONFIG_DIR")"
  fi
elif [[ -n "$DASHBOARD_UNIT" ]]; then
  info "ok    $DASHBOARD_UNIT owns $CONFIG_FILE, it reads it as its own file, nothing was granted"
fi

if [[ "$relay_needs" -eq 1 ]]; then
  if reads_it "$RELAY_ACCOUNT"; then
    info "ok    $RELAY_ACCOUNT can still read it, so port auto-detection works"
  elif [[ "$relay_could_read" -eq 1 ]]; then
    info "FAIL  $RELAY_ACCOUNT lost access, the Network charts would blank"
    fail=1
  else
    # It could not read the file before this ran either, so nothing here took
    # anything away. Said plainly rather than passed over, and without a
    # remedy that widens anything: the relay installer pins the ports it
    # reads from this file as root instead (#1266), so no directory above
    # the config is ever opened to the relay for them.
    info "note  $RELAY_ACCOUNT still cannot read the config, as before this ran."
    info "      A directory above $CONFIG_DIR keeps it out, an operator's home"
    info "      is the usual reason. The relay installer pins the ports it reads"
    info "      from this file in relay.conf instead, and every update refreshes them."
  fi
elif [[ "$relay_file_entry" -eq 1 || "$relay_dir_entry" -eq 1 ]]; then
  # Confirmed against the relay's own answer, asked again, not merely by
  # whether it can still open the file: a failed read alone cannot tell "the
  # removal was correct" from "some unrelated directory above this one blocks
  # this account", which would read as success while proving nothing about
  # what this run actually removed. The answer does not depend on what this
  # run just changed — resolving a path is unaffected by the ACL on it — so
  # asking again here is a real second opinion, not the same read repeated.
  #
  # relay_ask's own success is kept apart from its answer: a failure to ask
  # THIS time (transient, or the same "cannot be asked" shape the removal
  # itself may have been made under) must not silently fall back to judging
  # this "ok" off reads_it alone, the exact thing this whole check exists to
  # not do. Said as what it is below, not folded into a plain "ok".
  relay_reasked=0
  relay_ask && relay_reasked=1
  if [[ "$relay_reasked" -eq 1 && "$RELAY_ANSWER_READS" == "true" ]] \
     && [[ -n "$(realpath -m -- "$RELAY_ANSWER_NODE_CFG" 2>/dev/null)" ]] \
     && [[ "$(realpath -m -- "$RELAY_ANSWER_NODE_CFG" 2>/dev/null)" == "$(realpath -m -- "$CONFIG_FILE" 2>/dev/null)" ]]; then
    info "FAIL  $RELAY_ACCOUNT's own effective config still resolves to this file after its entry was removed"
    fail=1
  elif reads_it "$RELAY_ACCOUNT"; then
    info "FAIL  $RELAY_ACCOUNT can still read the config after its entry was removed"
    fail=1
  elif [[ "$relay_reasked" -eq 0 ]]; then
    info "ok    $RELAY_ACCOUNT no longer reads the config ($RELAY_ASK_NOTE just now,"
    info "      so this is confirmed by its own read, not by a second opinion from the binary)"
  else
    info "ok    $RELAY_ACCOUNT no longer reads the config; its own configuration never named this path"
  fi
fi

# The node itself. Read through the wrapper rather than by opening the file,
# because that is the path that has to keep working.
# The account installer hands over the root-owned copy it placed (ADR 0024),
# so root never runs a wrapper out of the tree here (#779 review, L1). Run on
# its own from a checkout, the sibling is what there is.
WRAPPER="${APERIRE_CLOSER_WRAPPER:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/aperire-node-wrapper.sh}"
if [[ -f "$WRAPPER" && $WRAPPER_CONFIGURED -eq 0 ]]; then
  # Asked only where it can be answered. The wrapper reads its own
  # configuration and refuses without one, so on a node-only host both reads
  # below would fail for a reason that has nothing to do with this change, and
  # the revert at the end would undo a correct close (#437). Said, not skipped
  # in silence: the node's own read two checks down is what gates this run.
  info "note  no $CONF here, so the wrapper was not asked; the node's own read below is the gate"
elif [[ -f "$WRAPPER" ]]; then
  # Through bash, not by its exec bit: a staged copy can sit on a /tmp mounted
  # noexec (#764), and a wrapper that cannot be exec'd must not read as none.
  if bash "$WRAPPER" show-config >/dev/null 2>&1; then
    info "ok    the wrapper still returns the configuration"
  else
    info "FAIL  the wrapper can no longer read the configuration"
    fail=1
  fi
  if bash "$WRAPPER" artefact-hashes node-config >/dev/null 2>&1; then
    info "ok    artefact-hashes still answers (the rollback precondition)"
  else
    info "FAIL  artefact-hashes broke, an upgrade would misjudge its rollback"
    fail=1
  fi
fi

# The node itself, and this one is not advisory. If it cannot open its own
# configuration the node stays up — it read the file at startup — and then
# fails the next time it starts, which may be days later and is very likely to
# be the recreate step of an upgrade. A soft "could not confirm" here is what
# let exactly that through the first time, so it is a hard gate now.
if [[ -n "$MOUNT_DEST" ]]; then
  if container_reads; then
    info "ok    the node still reads its config ($MOUNT_DEST)"
  else
    info "FAIL  the node can NO LONGER read its config"
    info "      it is still running, rippled reads this once at startup, but it"
    info "      would fail to start the next time, including on an upgrade."
    fail=1
  fi
elif [[ -n "$NATIVE_USER" ]]; then
  if reads_it "$NATIVE_USER"; then
    info "ok    '$NATIVE_USER' still reads its config, so the node starts"
  else
    info "FAIL  '$NATIVE_USER' can no longer read the config, the node would"
    info "      fail to start"
    fail=1
  fi
else
  info "FAIL  could not confirm the node still reads its config"
  info "      not proceeding on an assumption about a validator"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  if revert_and_report "something that must keep working stopped working"; then
    exit 1
  fi
  exit 2
fi

say "Done"
info "the validator token is now readable only by its owner and the node itself."
info "the Advisor reads that configuration only as the wrapper's redacted copy."
echo
# From the recorded original, not from what this run happened to find. On a
# second run those are not the same thing, and printing the latter produces an
# "undo" that is a no-op — and silently omits the group, which is the part that
# decides whether the node can start.
orig_mode=$(awk -F'mode=' '/^file=/{split($2,a," "); print a[1]}' "$BACKUP" 2>/dev/null)
orig_grp=$(awk -F'group=' '/^file=/{print $2}' "$BACKUP" 2>/dev/null)
orig_dmode=$(awk -F'mode=' '/^dir=/{print $2}' "$BACKUP" 2>/dev/null)
info "to undo, restoring what was recorded before the first run:"
info "  sudo chgrp ${orig_grp:-<original group>} $CONFIG_FILE"
info "  sudo chmod ${orig_mode:-644} $CONFIG_FILE"
info "  sudo chmod ${orig_dmode:-775} $CONFIG_DIR"
info "  sudo setfacl -n -x u:$ADVISOR_ACCOUNT $CONFIG_DIR"
[[ "$relay_needs" -eq 1 ]] && info "  sudo setfacl -n -x u:$RELAY_ACCOUNT $CONFIG_FILE"
[[ "$relay_needs" -eq 1 ]] && info "  sudo setfacl -n -x u:$RELAY_ACCOUNT $CONFIG_DIR"
# The entry this run actually took away, not the one a fresh grant would have
# made: REMOVED_RELAY_FILE_PERM/REMOVED_RELAY_DIR_PERM are captured at the
# moment of removal above, from getfacl's own text for that entry, so a
# stranger's unusual bits (anything other than the r-- and --x this script
# itself ever grants) come back exactly as they were rather than as a guess.
[[ "$relay_file_entry" -eq 1 ]] && info "  sudo setfacl -n -m u:$RELAY_ACCOUNT:${REMOVED_RELAY_FILE_PERM:-r--} $CONFIG_FILE   # restores the unused read this run removed"
[[ "$relay_dir_entry" -eq 1 ]] && info "  sudo setfacl -n -m u:$RELAY_ACCOUNT:${REMOVED_RELAY_DIR_PERM:---x} $CONFIG_DIR   # restores the unused passage this run removed"
[[ -n "$DASHBOARD_ACCOUNT" ]] && info "  sudo setfacl -n -x u:$DASHBOARD_ACCOUNT $CONFIG_FILE"
[[ -n "$DASHBOARD_ACCOUNT" ]] && info "  sudo setfacl -n -x u:$DASHBOARD_ACCOUNT $CONFIG_DIR"
[[ -n "$NATIVE_USER" ]] && info "  sudo setfacl -n -x u:$NATIVE_USER $CONFIG_DIR"
echo
info "that reopens the file to every account on this host. It is here for the"
info "case where something unexpected broke, not as a routine step."
