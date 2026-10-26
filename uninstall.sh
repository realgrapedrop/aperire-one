#!/bin/bash
# uninstall.sh, the Aperire One uninstaller.
#
#   curl -fsSL https://get.aperire.one/uninstall | bash
#
# or, from a checkout that is still here:
#
#   sudo bash uninstall.sh
#
# It looks at the host, works out what is installed, prints that as a plan,
# and then asks the one question that cannot be guessed:
#
#   1) keep artifacts   the database, the passkeys, /etc/aperire and the
#                       checkout stay. A later install picks them up.
#   2) wipe clean       those go too, and nothing named aperire is left.
#
# There is no default. On a run with no terminal, name the answer with --keep
# or --wipe; --yes alone does not answer it, because it skips a confirmation
# and this is not one.
#
# ---- what it works out for itself -----------------------------------
#
# The role and the instances come from what is on the host: the unit files in
# /etc/systemd/system and the contents of /etc/aperire. --role is still
# accepted and still overrides, for a host where you want one half removed
# and the other left alone.
#
# ---- what it never touches ------------------------------------------
#
#   - your node. The container, its configuration and its ledger store are
#     the box, not this install. Nothing here reads or writes them, and the
#     only thing it changes about them is taking back the access control
#     entries it added for the Advisor account.
#   - docker itself.
#   - Go and nvm, unless you pass --wipe --toolchain.
#
# Flags:
#   --keep              answer 1: keep the database, /etc/aperire and the
#                       checkout
#   --wipe              answer 2: remove them as well
#   --toolchain         with --wipe, also remove /usr/local/go, ~/.nvm, ~/.npm
#                       and the Go module cache this install put there
#   --role=<role>       override the detected role:
#                         dashboard   aperire-server, the verify timer, the
#                                     update and fleet broker grants, the
#                                     tunnel unit and the operator CLI links
#                         validator   the relay and the rotation timer
#                         co-located  both of those
#                         advisor     everything the Advisor installed
#                         cli-only    just the operator CLI links (no sudo)
#
#                       A role that names one half is SCOPED: --wipe then
#                       removes that half's own configuration and state, and
#                       never /etc/aperire, data/ or the checkout, because
#                       the half that is staying still reads them.
#                       co-located is both halves, so it is not scoped.
#   --yes, -y           skip the "proceed?" confirmation. It does NOT answer
#                       the keep/wipe question.
#   --help, -h
#
# The older, finer-grained form of the same answer is still accepted:
# --purge-config removes /etc/aperire, --purge-data removes data/, and
# --purge-all does both. None of the three removes the checkout, which is
# what --wipe adds.
#
# Examples:
#   sudo bash uninstall.sh                       # asks the question
#   sudo bash uninstall.sh --keep --yes
#   sudo bash uninstall.sh --wipe --toolchain --yes
#   bash uninstall.sh --role=cli-only --keep     # no sudo

set -euo pipefail

# Where this program is (UNINSTALL_SELF), and the install it removes (REPO_DIR):
# the same directory from a checkout, two when it is a copy root staged out of
# the release and APERIRE_INSTALL_TREE names the install (#943). Code is run
# from UNINSTALL_SELF only; everything that is "the install" stays on REPO_DIR.
UNINSTALL_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${APERIRE_INSTALL_TREE:-$UNINSTALL_SELF}" 2>/dev/null && pwd)" \
  || { echo "error: the install at ${APERIRE_INSTALL_TREE:-$UNINSTALL_SELF} is not a directory this account can enter" >&2; exit 1; }
# What to type to run this again. A copy the bootstrap staged is gone when the
# run ends, so the line names the bootstrap; a checkout's own copy names itself.
if [[ -n "${APERIRE_INSTALL_TREE:-}" ]]; then
  AGAIN_BARE="curl -fsSL https://get.aperire.one/uninstall | bash"
  AGAIN_CMD="curl -fsSL https://get.aperire.one/uninstall | bash -s --"
else
  AGAIN_BARE="sudo bash $0"
  AGAIN_CMD="sudo bash $0"
fi

# Every absolute location this script writes to, named once. One assignment
# per directory is what lets scripts/test-uninstall.sh point the whole run
# inside a temporary tree and prove that it did: a path spelled out at its
# use site would be rewritten in some places and not others, and the copy
# under test would quietly remove things from the machine running the test.
UNIT_DIR=/etc/systemd/system
ETC_APERIRE=/etc/aperire
SUDOERS_DIR=/etc/sudoers.d
LOGROTATE_DIR=/etc/logrotate.d
PROFILE_DIR=/etc/profile.d
SBIN_DIR=/usr/local/sbin
UBIN_DIR=/usr/local/bin
ULIB_DIR=/usr/local/lib
RELEASE_STORE_DIR=/var/lib/aperire/release
# The directory both of those live in, and the Advisor's node wrapper keeps
# root's own records in (#1005): a marker per image digest it verified, and a
# package it kept for a rollback. install-advisord.sh makes it.
VAR_LIB_DIR=/var/lib/aperire
RUN_DIR=/run/aperire
GO_DIR=/usr/local/go
# The helper the dashboard hand-back plants with: the copy beside this program,
# which from the bootstrap's stage is the checked one, or root's own installed
# copy when this program was fetched and is running alone (#943).
STATE_TOOL="$UNINSTALL_SELF/scripts/state-file.py"
if [[ ! -f "$STATE_TOOL" && -f "$SBIN_DIR/aperire-state-file" && ! -L "$SBIN_DIR/aperire-state-file" ]]; then
  STATE_TOOL="$SBIN_DIR/aperire-state-file"
fi

# The wrapper's two, by the names scripts/aperire-node-wrapper.sh gives them.
VERIFIED_IMAGE_DIR="$VAR_LIB_DIR/verified-images"
PACKAGE_KEEP_DIR="$VAR_LIB_DIR/rollback"

ADVISOR_ACCOUNT=aperire-advisor
DASH_ACCOUNT=aperire-dashboard
RELAY_ACCOUNT=aperire-relay
SHARED_GROUP=aperire-svc

ROLE=""
ANSWER=""
LEGACY_CONFIG=0
LEGACY_DATA=0
RM_CONFIG=0
RM_DATA=0
RM_CHECKOUT=0
RM_TOOLCHAIN=0
ASSUME_YES=0

# ── Argument parsing ────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --role=*)        ROLE="${arg#*=}" ;;
    --keep)          ANSWER="keep" ;;
    --wipe)          ANSWER="wipe" ;;
    --toolchain)     RM_TOOLCHAIN=1 ;;
    --purge-config)  LEGACY_CONFIG=1 ;;
    --purge-data)    LEGACY_DATA=1 ;;
    --purge-all)     LEGACY_CONFIG=1; LEGACY_DATA=1 ;;
    --yes|-y)        ASSUME_YES=1 ;;
    -h|--help)
      awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "$0"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $arg" >&2
      echo "       run with --help for usage" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$ROLE" ]]; then
  case "$ROLE" in
    dashboard|validator|co-located|advisor|cli-only) ;;
    *)
      echo "error: invalid role '$ROLE'" >&2
      exit 2
      ;;
  esac
fi

# The old flags are an answer, just a narrower one: they say which artefacts
# go, and by saying nothing about the checkout they keep it.
if [[ -z "$ANSWER" && ( $LEGACY_CONFIG -eq 1 || $LEGACY_DATA -eq 1 ) ]]; then
  ANSWER="keep"
fi

# ── What is on this host ────────────────────────────────────────────
#
# Read from the unit directory rather than from systemctl, because it is the
# same directory the removals below write to: a unit "known to systemd" here
# is exactly a unit file on disk, so a second run sees what the first left.
# Every installer in this tree writes to /etc/systemd/system; nothing here
# ships a unit under /lib.
have() { [[ -e "$1" ]]; }

# Instance suffixes for a family of units, "" for the un-suffixed one. This is
# how a host running `install.sh --instance=node2` is found without being
# asked: the unit names are the record, and nothing else on the box holds one.
instances_of() {  # $1 = unit prefix, e.g. aperire-server
  local f n
  for f in "$UNIT_DIR/$1".service "$UNIT_DIR/$1"-*.service; do
    [[ -e "$f" ]] || continue
    n="$(basename "$f" .service)"
    n="${n#"$1"}"
    printf '%s\n' "${n#-}"
  done
}

DASH_INSTANCES=()
RELAY_INSTANCES=()
while IFS= read -r line; do DASH_INSTANCES+=("$line"); done < <(instances_of aperire-server)
while IFS= read -r line; do RELAY_INSTANCES+=("$line"); done < <(instances_of aperire-relay)

# A dashboard whose unit is already gone but whose env file is not is still a
# dashboard install: /etc/aperire/aperire.env holds the relay token.
# Whether ANY of this is a unit, a binary, an account or a link, rather than a
# file in /etc/aperire that an earlier `--keep` left behind on purpose. Both
# are evidence of an install and both are detected, but only one of them is a
# thing that runs, and the plan has to say which it saw.
UNIT_EVIDENCE=0

HAS_DASHBOARD=0
if [[ ${#DASH_INSTANCES[@]} -gt 0 ]]; then HAS_DASHBOARD=1; UNIT_EVIDENCE=1; fi
if [[ $HAS_DASHBOARD -eq 0 ]]; then
  for f in "$ETC_APERIRE"/aperire.env "$ETC_APERIRE"/aperire-*.env; do
    have "$f" && HAS_DASHBOARD=1
  done
fi
# The update grant, which is the dashboard's and not the Advisor's: one root
# socket the dashboard account may open to move this host to a newer release.
# Any piece of it present is a dashboard to take off, for the reason the
# Advisor's pieces are: an install interrupted between two of its own steps is
# exactly the host that most needs the rest removed.
for f in "$UNIT_DIR/aperire-update.socket" "$UNIT_DIR/aperire-update@.service" \
         "$SBIN_DIR/aperire-update"; do
  have "$f" && { HAS_DASHBOARD=1; UNIT_EVIDENCE=1; }
done
have "$ETC_APERIRE/update.conf" && HAS_DASHBOARD=1
# The dashboard's own account (ADR 0024), which an interrupted run can leave
# with nothing else beside it.
id "$DASH_ACCOUNT" >/dev/null 2>&1 && HAS_DASHBOARD=1
# The fleet broker grant, which is an aggregator's (#804): the socket the
# dashboard account opens to approve a pairing or hold the fleet's model key,
# the template unit behind it, and the two root programs
# install-fleet-broker-grant.sh places. Also the dashboard's grant, so any
# piece of it is a dashboard to take off. A host where a dashboard step that
# predated this left only these behind is exactly the host that has to be
# found: with nothing else on it, it would otherwise read as "nothing to do"
# while the next install refuses on the units it still has.
for f in "$UNIT_DIR/aperire-fleet-broker.socket" "$UNIT_DIR/aperire-fleet-broker@.service" \
         "$SBIN_DIR/aperire-fleet-broker" "$SBIN_DIR/aperire-fleet-arm"; do
  have "$f" && { HAS_DASHBOARD=1; UNIT_EVIDENCE=1; }
done
# Its configuration, which a --keep leaves on purpose: evidence of an
# install, not of anything that runs.
for f in "$ETC_APERIRE/fleet-broker.conf" "$ETC_APERIRE/fleet-nodes.conf" \
         "$ETC_APERIRE/fleet-arm.key"; do
  have "$f" && HAS_DASHBOARD=1
done
# The one directive this tree writes beside the dashboard's unit rather than
# into it: scripts/enable-relay-colocated.sh puts an EnvironmentFile line in
# <unit>.service.d/relay-env.conf so a dashboard installed without a relay
# token reads /etc/aperire/aperire.env. A directory standing there is a
# dashboard to take off, and it is a unit-shaped one, so the plan may call it
# evidence of something that runs.
have "$UNIT_DIR/aperire-server.service.d" && { HAS_DASHBOARD=1; UNIT_EVIDENCE=1; }
# The two pieces the hardening guide has you place by hand (#818): the rippled
# admin proxy, whose unit runs out of this checkout's dashboard/, and the
# sudo rule allow-aperire-restart.sh writes so aperire-server can be restarted
# without a password. Both are the dashboard's, by exact name.
have "$UNIT_DIR/aperire-rippled-proxy.service" && { HAS_DASHBOARD=1; UNIT_EVIDENCE=1; }
have "$SUDOERS_DIR/aperire-restart" && HAS_DASHBOARD=1

HAS_VERIFY=0
have "$UNIT_DIR/aperire-verify.timer" && { HAS_VERIFY=1; UNIT_EVIDENCE=1; }
have "$UNIT_DIR/aperire-verify.service" && { HAS_VERIFY=1; UNIT_EVIDENCE=1; }
have "$REPO_DIR/data/verify-report.json" && HAS_VERIFY=1

HAS_TUNNEL=0
have "$UNIT_DIR/cloudflared-aperire.service" && { HAS_TUNNEL=1; UNIT_EVIDENCE=1; }

HAS_RELAY=0
if [[ ${#RELAY_INSTANCES[@]} -gt 0 ]]; then HAS_RELAY=1; UNIT_EVIDENCE=1; fi
have "$UBIN_DIR/aperire-relay" && { HAS_RELAY=1; UNIT_EVIDENCE=1; }
id "$RELAY_ACCOUNT" >/dev/null 2>&1 && { HAS_RELAY=1; UNIT_EVIDENCE=1; }

HAS_ROTATION=0
have "$UNIT_DIR/aperire-can-delete.timer" && { HAS_ROTATION=1; UNIT_EVIDENCE=1; }
have "$UNIT_DIR/aperire-can-delete.service" && { HAS_ROTATION=1; UNIT_EVIDENCE=1; }
have "$ULIB_DIR/aperire/aperire-can-delete.sh" && { HAS_ROTATION=1; UNIT_EVIDENCE=1; }

# The xrpld image recipe: what root runs to build a container node's image
# from the XRPL Foundation's signed package. Files only, no unit, so it is
# not UNIT_EVIDENCE, it is a copy of a recipe and nothing runs it unless the
# wrapper is asked to. Left behind it is harmless and confusing in equal
# measure, and a later install would find a recipe from a release nobody
# still has the tree for.
HAS_IMAGE_RECIPE=0
have "$ULIB_DIR/aperire/build-xrpld-image.sh" && HAS_IMAGE_RECIPE=1
# The directory, not one file inside it: a host an earlier, buggy uninstall
# left with only one file in xrpld-image/ (#730 - a run before this fix could
# leave exactly that) still has a recipe to take off, whichever file survived.
have "$ULIB_DIR/aperire/xrpld-image" && HAS_IMAGE_RECIPE=1

# The Advisor, in every piece it arrives in. Any one of them present is an
# Advisor to remove: an install interrupted between two of its own steps is
# exactly the host that most needs the rest taken off.
ADVISORD_UNITS=()
while IFS= read -r line; do ADVISORD_UNITS+=("$line"); done < <(instances_of aperire-advisord)
# "credcheck" can never be a real APERIRE_INSTANCE here (#541): the
# recovery unit's own name, aperire-advisord-credcheck.service, is
# indistinguishable by instances_of's glob from a genuine instance called
# "credcheck". Filtered once, here, rather than carried through every loop
# below as a phantom entry that would make the per-instance credcheck
# removal look for aperire-advisord-credcheck-credcheck.service.
_advisord_units_filtered=()
for _u in "${ADVISORD_UNITS[@]}"; do
  [[ "$_u" == credcheck ]] && continue
  _advisord_units_filtered+=("$_u")
done
ADVISORD_UNITS=(${_advisord_units_filtered[@]+"${_advisord_units_filtered[@]}"})
unset _advisord_units_filtered _u
HAS_ADVISOR=0
if [[ ${#ADVISORD_UNITS[@]} -gt 0 ]]; then HAS_ADVISOR=1; UNIT_EVIDENCE=1; fi
for f in "$UNIT_DIR/aperire-seal-model-key.socket" "$UNIT_DIR/aperire-seal-model-key@.service" \
         "$UNIT_DIR/aperire-trust-sync.socket" "$UNIT_DIR/aperire-trust-sync@.service" \
         "$SBIN_DIR/aperire-seal-model-key" "$SBIN_DIR/aperire-trust-sync" \
         "$SBIN_DIR/aperire-advisord-credcheck" "$SBIN_DIR/aperire-state-file" \
         "$SBIN_DIR/aperire-model-key-method" "$SBIN_DIR/aperire-node-wrapper" \
         "$SBIN_DIR/aperire-wrapper-broker" "$UNIT_DIR/aperire-node-wrapper.socket" \
         "$SUDOERS_DIR/$ADVISOR_ACCOUNT" "$REPO_DIR/advisor/bin" \
         "$UNIT_DIR/aperire-advisord.service.d"; do
  have "$f" && { HAS_ADVISOR=1; UNIT_EVIDENCE=1; }
done
# The failure-recovery unit (#541), one per instance, same as ADVISORD_UNITS
# above; instances_of only sees a unit that still exists, so a bare glob
# catches one whose OWN unit was already removed by an earlier interrupted
# run, the same reasoning as the .before-account marker glob further down.
for f in "$UNIT_DIR"/aperire-advisord-credcheck*.service; do
  [[ -e "$f" ]] || continue
  HAS_ADVISOR=1; UNIT_EVIDENCE=1
done
# Configuration, not something that runs.
for f in "$ETC_APERIRE/node-wrapper.conf" "$ETC_APERIRE/node-config-perms.before" \
         "$ETC_APERIRE/model-key.arm"; do
  have "$f" && HAS_ADVISOR=1
done
# What two opt-in or retired Advisor scripts leave (#818): the copy of the
# unit harden-advisord.sh keeps before it rewrites it, and the sudo rule the
# model-key sealer used before it had a socket. Exact names, both.
for f in "$UNIT_DIR/aperire-advisord.service.before-hardening" "$SUDOERS_DIR/aperire-model-key" \
         "$SUDOERS_DIR/$ADVISOR_ACCOUNT"-*; do
  have "$f" && HAS_ADVISOR=1
done
# The node wrapper's records, which an earlier --keep leaves on purpose.
for f in "$VERIFIED_IMAGE_DIR" "$PACKAGE_KEEP_DIR"; do
  have "$f" && HAS_ADVISOR=1
done
id "$ADVISOR_ACCOUNT" >/dev/null 2>&1 && { HAS_ADVISOR=1; UNIT_EVIDENCE=1; }
# The shared group, on its own. A keep leaves it while a file kept in
# /etc/aperire is on it (#824), so a later run has to find it to take it off.
# Not HAS_ADVISOR: nothing that runs and nothing an Advisor reads is implied
# by a group, and the dashboard's step asks HAS_ADVISOR whether to keep a
# library for an Advisor that stays. It only puts the Advisor's step, which
# owns the group, on the list.
HAS_SHARED_GROUP=0
getent group "$SHARED_GROUP" >/dev/null 2>&1 && HAS_SHARED_GROUP=1

# Whether an Advisor is on this host, read ONLY from what root wrote: its unit
# files and its programs in sbin. HAS_ADVISOR above also counts advisor/bin in
# the checkout, which the dashboard account can create, and this answer
# decides whether root keeps or removes the fleet's read tokens (#804). A
# signal the dashboard account could plant must not keep root files alive.
ADVISOR_ROOT=0
[[ ${#ADVISORD_UNITS[@]} -gt 0 ]] && ADVISOR_ROOT=1
for f in "$UNIT_DIR"/aperire-advisord-credcheck*.service \
         "$UNIT_DIR/aperire-seal-model-key.socket" "$UNIT_DIR/aperire-trust-sync.socket" \
         "$UNIT_DIR/aperire-node-wrapper.socket" \
         "$SBIN_DIR/aperire-seal-model-key" "$SBIN_DIR/aperire-trust-sync" \
         "$SBIN_DIR/aperire-advisord-credcheck" "$SBIN_DIR/aperire-node-wrapper" \
         "$SBIN_DIR/aperire-wrapper-broker"; do
  [[ -e "$f" ]] && ADVISOR_ROOT=1
done

# Whether the fleet broker grant is on this host, by the same rule.
broker_grant_here() {
  local f
  for f in "$UNIT_DIR/aperire-fleet-broker.socket" "$UNIT_DIR/aperire-fleet-broker@.service" \
           "$SBIN_DIR/aperire-fleet-broker" "$SBIN_DIR/aperire-fleet-arm"; do
    [[ -e "$f" ]] && return 0
  done
  return 1
}

# The operator this install belongs to, and their home. Under sudo that is
# the account that invoked it, never root: the checkout, the CLI links and
# the toolchain caches are that account's files.
OP_USER="$(id -un)"
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
  OP_USER="$SUDO_USER"
fi
OP_HOME="${HOME:-}"
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
  OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6)"
fi
[[ -n "$OP_HOME" ]] || OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6)"
[[ -n "$OP_HOME" ]] || OP_HOME="/nonexistent"

CLI_LINKS=()
for f in "$OP_HOME"/.local/bin/aperire*; do
  [[ -L "$f" || -e "$f" ]] && CLI_LINKS+=("$f")
done
HAS_CLI=0
if [[ ${#CLI_LINKS[@]} -gt 0 ]]; then HAS_CLI=1; UNIT_EVIDENCE=1; fi

HAS_GO_PROFILE=0
have "$PROFILE_DIR/aperire-go.sh" && { HAS_GO_PROFILE=1; UNIT_EVIDENCE=1; }

# ── The steps ───────────────────────────────────────────────────────
STEPS=()
# A role naming one half of an install leaves the other half running, and the
# other half reads /etc/aperire, data/ and the checkout. So --wipe under one
# of those means "wipe this half", never "wipe the box".
ROLE_SCOPED=0
[[ -n "$ROLE" && "$ROLE" != "co-located" ]] && ROLE_SCOPED=1
if [[ -n "$ROLE" ]]; then
  # An override is exactly that: the operator has named the half they want
  # gone, so nothing is added to it from what is detected.
  case "$ROLE" in
    dashboard)   STEPS+=("dashboard" "tunnel" "cli") ;;
    validator)   STEPS+=("relay" "rotation" "imagerecipe") ;;
    co-located)  STEPS+=("dashboard" "tunnel" "cli" "relay" "rotation" "imagerecipe") ;;
    advisor)     STEPS+=("advisor") ;;
    cli-only)    STEPS+=("cli") ;;
  esac
else
  [[ $HAS_DASHBOARD -eq 1 || $HAS_VERIFY -eq 1 ]] && STEPS+=("dashboard")
  [[ $HAS_TUNNEL   -eq 1 ]] && STEPS+=("tunnel")
  [[ $HAS_ADVISOR  -eq 1 || $HAS_SHARED_GROUP -eq 1 ]] && STEPS+=("advisor")
  [[ $HAS_RELAY    -eq 1 ]] && STEPS+=("relay")
  [[ $HAS_ROTATION -eq 1 ]] && STEPS+=("rotation")
  [[ $HAS_IMAGE_RECIPE -eq 1 ]] && STEPS+=("imagerecipe")
  [[ $HAS_CLI      -eq 1 ]] && STEPS+=("cli")
  [[ $HAS_GO_PROFILE -eq 1 ]] && STEPS+=("goprofile")
fi

DETECTED=""
if [[ -n "$ROLE" ]]; then
  DETECTED="$ROLE (you named it)"
else
  for s in ${STEPS[@]+"${STEPS[@]}"}; do
    case "$s" in
      dashboard) DETECTED="${DETECTED}dashboard, " ;;
      tunnel)    DETECTED="${DETECTED}tunnel, " ;;
      advisor)   DETECTED="${DETECTED}Advisor, " ;;
      relay)     DETECTED="${DETECTED}relay, " ;;
      rotation)  DETECTED="${DETECTED}rotation timer, " ;;
      imagerecipe) DETECTED="${DETECTED}image recipe, " ;;
      cli)       DETECTED="${DETECTED}operator CLI, " ;;
      goprofile) DETECTED="${DETECTED}Go PATH line, " ;;
    esac
  done
  DETECTED="${DETECTED%, }"
  if [[ $UNIT_EVIDENCE -eq 1 ]]; then
    DETECTED="${DETECTED} (from the units on this host)"
  else
    # An earlier run answered "keep", so what is left is configuration and
    # nothing that runs. Saying "from the units" there would name evidence
    # this host does not have.
    DETECTED="${DETECTED} (configuration in ${ETC_APERIRE}; no units are left)"
  fi
fi

# What this run is about to take off that a reinstall does not put back by
# itself (#1181). Read here, before anything is removed, so the closing text
# says what this run did and not what an earlier one did: a second --keep over
# configuration alone finds no unit, no binary and no account, and claims
# nothing. The Advisor counts only when something of it RUNS here (a unit or
# its account), never on the configuration a keep leaves behind.
KEEP_NAMES_RELAY=0; KEEP_NAMES_ADVISOR=0; KEEP_NAMES_GRANT=0
if [[ ${#STEPS[@]} -gt 0 ]]; then
  [[ $HAS_RELAY -eq 1 ]] && [[ " ${STEPS[*]} " == *" relay "* ]] && KEEP_NAMES_RELAY=1
  if [[ " ${STEPS[*]} " == *" advisor "* ]] \
     && { [[ ${#ADVISORD_UNITS[@]} -gt 0 ]] || id "$ADVISOR_ACCOUNT" >/dev/null 2>&1; }; then
    KEEP_NAMES_ADVISOR=1
  fi
  [[ " ${STEPS[*]} " == *" dashboard "* ]] && broker_grant_here && KEEP_NAMES_GRANT=1
fi

# ── Nothing to do ───────────────────────────────────────────────────
# Answered before the question is asked, and that order is the point: a host
# with nothing on it must not be refused for failing to answer a question
# about artefacts it does not have. This is the second run of a pair, and it
# is the one that has to be quiet.
if [[ ${#STEPS[@]} -eq 0 ]]; then
  echo
  echo "  ───── Aperire One uninstaller ─────"
  echo
  echo "  Nothing to do. This host has no Aperire One units, no ${ETC_APERIRE}"
  echo "  entries of ours, no relay or Advisor account, and no operator CLI"
  echo "  links under ${OP_HOME}/.local/bin."
  echo
  exit 0
fi

# ── Privilege check ─────────────────────────────────────────────────
# NEEDS_ROOT is only ever lowered from here, never raised: the test harness
# rewrites this one line to run the whole script unprivileged in a temporary
# tree, and a later re-assignment would put it back.
NEEDS_ROOT=1
CLI_ONLY=0
# The links under a home directory are the one thing here that belongs to an
# ordinary account and needs no root to remove. Nothing else about the host
# may enter this test: gating it on some unrelated file meant every box where
# the toolchain had ever been installed refused `--role=cli-only` for want of
# a root it did not need.
if [[ ${#STEPS[@]} -eq 1 && "${STEPS[0]}" == "cli" ]]; then
  CLI_ONLY=1
  NEEDS_ROOT=0
fi

if [[ $NEEDS_ROOT -eq 1 && $EUID -ne 0 ]]; then
  echo "error: this removes systemd units, accounts and files under /etc, so it must run as root." >&2
  echo "       ${AGAIN_CMD} $*" >&2
  exit 1
fi
if [[ $CLI_ONLY -eq 1 && "$ROLE" == "cli-only" && $EUID -eq 0 ]]; then
  echo "error: role 'cli-only' must NOT run as root" >&2
  exit 1
fi

# ── The checkout, identified before anything is removed ─────────────
#
# The one directory here that a mistake cannot be undone from, so it is never
# taken on a resemblance. The running dashboard unit says where it reads from
# (WorkingDirectory is <install>/dashboard), and the checkout is removed only
# when that answer is this checkout. A host with no unit to ask gets a line
# naming the directory and no rm at all.
CHECKOUT=""
CHECKOUT_WHY=""
CHECKOUT_PARENT_ID=""
identify_checkout() {
  local inst unit wd here there
  here="$(cd "$REPO_DIR" && pwd -P)"
  for inst in ${DASH_INSTANCES[@]+"${DASH_INSTANCES[@]}"}; do
    unit="aperire-server${inst:+-$inst}.service"
    wd="$(systemctl show -p WorkingDirectory --value "$unit" 2>/dev/null || true)"
    wd="${wd#WorkingDirectory=}"
    [[ -n "$wd" && "$wd" != "/" ]] || continue
    [[ "$(basename "$wd")" == "dashboard" ]] || continue
    there="$(cd "$(dirname "$wd")" 2>/dev/null && pwd -P)" || continue
    [[ "$there" == "$here" ]] || continue
    # Floors, in case a unit ever names something absurd. Each one on its own
    # would be a directory nobody meant to hand to rm -rf.
    [[ "$here" != "/" && "$here" != "$OP_HOME" ]] || return 1
    [[ -f "$here/uninstall.sh" && -d "$here/scripts" ]] || return 1
    CHECKOUT="$here"
    CHECKOUT_PARENT_ID="$(stat -c '%d:%i' -- "$(dirname "$here")" 2>/dev/null || true)"
    CHECKOUT_WHY="the ${unit} unit reads from ${wd}"
    return 0
  done
  return 1
}
if [[ "$ANSWER" == "wipe" ]]; then
  identify_checkout || true
fi

# ── Print the plan ──────────────────────────────────────────────────
echo
echo "  ───── Aperire One uninstaller ─────"
echo
echo "  Install:   ${REPO_DIR}"
echo "  Found:     ${DETECTED}"
if [[ ${#DASH_INSTANCES[@]} -gt 0 ]]; then
  names=""
  for inst in "${DASH_INSTANCES[@]}"; do names="${names}${inst:-<the un-named one>}, "; done
  echo "  Instances: ${names%, }"
fi
echo
echo "  Will remove:"

for step in ${STEPS[@]+"${STEPS[@]}"}; do
  case "$step" in
    dashboard)
      for inst in ${DASH_INSTANCES[@]+"${DASH_INSTANCES[@]}"}; do
        echo "    • stop + disable aperire-server${inst:+-$inst}.service, and remove its unit"
        echo "      and ${UNIT_DIR}/aperire-server${inst:+-$inst}.service.d, the directives beside it"
        echo "    • remove ${LOGROTATE_DIR}/aperire${inst:+-$inst}"
      done
      if [[ ${#DASH_INSTANCES[@]} -eq 0 ]] && have "$UNIT_DIR/aperire-server.service.d"; then
        echo "    • remove ${UNIT_DIR}/aperire-server.service.d, a drop-in directory left"
        echo "      standing where its unit used to be"
      fi
      echo "    • stop + disable aperire-verify.timer"
      if id "$DASH_ACCOUNT" >/dev/null 2>&1; then
        echo "    • hand the ${DASH_ACCOUNT} account's files back to the checkout's owner,"
        echo "      take back its access control entries, then remove the account"
      fi
      echo "    • remove the aperire-verify units and ${REPO_DIR}/data/verify-report.json"
      echo "    • remove the update grant: its socket, its root program, the"
      echo "      file naming where this host fetched releases from, the release"
      echo "      key it checks against, and the signed releases this host kept"
      echo "    • remove the fleet broker grant, on an aggregator: stop its socket"
      echo "      and any broker it started, remove both units, ${SBIN_DIR}/aperire-fleet-broker"
      echo "      and ${SBIN_DIR}/aperire-fleet-arm"
      if have "$UNIT_DIR/aperire-rippled-proxy.service" || have "$SUDOERS_DIR/aperire-restart"; then
        echo "    • remove what the hardening guide placed by hand, where it is here:"
        echo "      aperire-rippled-proxy.service (stopped first) and ${SUDOERS_DIR}/aperire-restart"
      fi
      ;;
    tunnel)
      echo "    • stop + disable cloudflared-aperire.service (if present)"
      echo "    • remove ${UNIT_DIR}/cloudflared-aperire.service"
      ;;
    advisor)
      echo "    • stop + disable aperire-advisord, and remove its unit and the"
      echo "      .before-account and .before-hardening copies of the unit it replaced"
      echo "    • remove the model-key sealer: its socket, its root program and"
      echo "      any arming window that is open"
      echo "    • remove the trust-sync grant: its socket and its root program"
      echo "    • take back the access control entries granted to ${ADVISOR_ACCOUNT}"
      echo "    • remove ${SUDOERS_DIR}/${ADVISOR_ACCOUNT} and the retired ${SUDOERS_DIR}/aperire-model-key,"
      echo "      and check the rest with visudo"
      echo "    • hand every file that account owns under ${REPO_DIR} back to"
      echo "      the checkout's owner, then remove the ${ADVISOR_ACCOUNT} account"
      echo "      and the ${SHARED_GROUP} group, unless a file kept in ${ETC_APERIRE} is on it"
      echo "    • remove ${REPO_DIR}/advisor/bin"
      if have "$VERIFIED_IMAGE_DIR" || have "$PACKAGE_KEEP_DIR"; then
        echo "    • ${VERIFIED_IMAGE_DIR} and ${PACKAGE_KEEP_DIR}, the node wrapper's records"
        echo "      of images it verified and a package kept for a rollback: removed on a wipe,"
        echo "      kept and named otherwise"
      fi
      ;;
    relay)
      for inst in ${RELAY_INSTANCES[@]+"${RELAY_INSTANCES[@]}"}; do
        echo "    • stop + disable aperire-relay${inst:+-$inst}.service, and remove its unit"
      done
      echo "    • remove ${UBIN_DIR}/aperire-relay"
      echo "    • remove the '${RELAY_ACCOUNT}' system user"
      ;;
    rotation)
      echo "    • stop + disable aperire-can-delete.timer"
      echo "    • remove the aperire-can-delete units and ${ULIB_DIR}/aperire/"
      echo "    • NOTE: advisory_delete=1 stays in your node config, so the node"
      echo "      will stop pruning until you remove it or reinstall the timer"
      ;;
    cli)
      for f in ${CLI_LINKS[@]+"${CLI_LINKS[@]}"}; do
        echo "    • remove ${f}"
      done
      [[ ${#CLI_LINKS[@]} -eq 0 ]] && echo "    • remove the operator CLI links from ${OP_HOME}/.local/bin"
      ;;
    goprofile)
      echo "    • ${PROFILE_DIR}/aperire-go.sh, the login PATH line the toolchain"
      echo "      install added. Removed on a wipe, kept otherwise."
      ;;
  esac
done
echo

# ── The question ────────────────────────────────────────────────────
#
# Two answers, no default. Everything above happens either way; this decides
# what is left standing afterwards, and it is the only thing on this run that
# cannot be worked out from the host.
ask_the_question() {
  local reply
  cat <<EOF
  Then one of two endings. There is no default, so pick one:

    1) keep artifacts   ${REPO_DIR}/data (the database: operators, passkeys,
                        alert history), ${ETC_APERIRE} (the relay token, the
                        config, any sealed key) and this checkout all stay.
                        A later install picks them up where they are.

    2) wipe clean       those go too, and nothing named aperire is left on
                        this host.

EOF
  if [[ -n "$ANSWER" ]]; then
    echo "  Answered on the command line: $([[ "$ANSWER" == "wipe" ]] && echo '2, wipe clean' || echo '1, keep artifacts')"
    echo
    return 0
  fi
  # EOF, not a terminal test. A here-string or a file is a legitimate answer
  # and reads as one; a closed stdin, /dev/null or an exhausted pipe fails
  # the read, and that is the case with nobody to ask.
  while true; do
    printf '  1 or 2? '
    if ! IFS= read -r reply; then
      echo
      refuse_no_answer
    fi
    case "$reply" in
      1|keep)  ANSWER="keep"; echo; return 0 ;;
      2|wipe)  ANSWER="wipe"; echo; return 0 ;;
      "")      echo "  There is no default. Answer 1 or 2, or press Ctrl-C to stop." ;;
      *)       echo "  '$reply' is not 1 or 2." ;;
    esac
  done
}

refuse_no_answer() {
  cat >&2 <<EOF

error: there is nobody to answer the question above.

  Name the ending and take the plan exactly as printed:

      ${AGAIN_CMD} --keep --yes    (1, the database and ${ETC_APERIRE} stay)
      ${AGAIN_CMD} --wipe --yes    (2, they go, and so does the checkout)

  --yes on its own is not enough. It skips the "proceed?" confirmation, and
  the question above is not one: nothing on this host says which ending you
  want, so nothing can guess it.

  Or answer it in a terminal:

      ${AGAIN_BARE}
EOF
  exit 2
}

ask_the_question

# WIPE is the ending, and every step above reads it for its OWN artefacts.
# The three below are the shared ones, and they are only taken when the whole
# install is going: a scoped role leaves half of it running against them.
WIPE=0
[[ "$ANSWER" == "wipe" ]] && WIPE=1
if [[ $WIPE -eq 1 && $ROLE_SCOPED -eq 0 ]]; then
  RM_CONFIG=1; RM_DATA=1; RM_CHECKOUT=1
fi
# The older flags say the same thing one directory at a time, and they say it
# whatever the role is, because that is what they have always done.
[[ $LEGACY_CONFIG -eq 1 ]] && RM_CONFIG=1
[[ $LEGACY_DATA   -eq 1 ]] && RM_DATA=1

if [[ $RM_TOOLCHAIN -eq 1 && $WIPE -ne 1 ]]; then
  echo "error: --toolchain only means something with --wipe. Go and nvm are not this" >&2
  echo "       install's to remove on a run that is keeping everything else." >&2
  exit 2
fi
if [[ $RM_TOOLCHAIN -eq 1 && $ROLE_SCOPED -eq 1 ]]; then
  echo "error: --toolchain with --role=${ROLE} would take Go and nvm off a box that is" >&2
  echo "       still running the other half of this install. Drop one of the two." >&2
  exit 2
fi

# The checkout was identified before the plan printed only when --wipe was
# already on the command line. An answer given at the prompt arrives here.
if [[ $RM_CHECKOUT -eq 1 && -z "$CHECKOUT" ]]; then
  identify_checkout || true
fi

# ── The update snapshots, beside the checkout (#860) ────────────────
#
# Every update moves the tree it replaces aside to <checkout>.previous-<stamp>
# and copies the database to <checkout>.db-<stamp>; a rollback leaves
# <checkout>.rolled-back-<stamp>. They sit NEXT to the checkout, not in it, so
# removing the checkout never took them, and the database copies hold the auth
# tables. The names are the updater's own (scripts/get-aperire.sh and
# scripts/aperire-update.sh): a UTC stamp, then an optional -N when two runs
# land in the same second, and for a database copy an optional -wal or -shm.
# Anything else beside the checkout is the operator's and is never matched.
#
# The checkout is the one a dashboard unit reads from (identify_checkout), the
# same proof the checkout's own removal needs. Only snapshots found that way
# are ever deleted (SNAP_PROVEN=1). With no unit left to ask, as after an
# earlier --keep removed them, the same patterns are matched beside this
# script's own directory and only LISTED (SNAP_PROVEN=0), so a later wipe still
# tells the operator where the database copies are. scripts/aperire-leftovers.sh
# holds the same three patterns; a change here changes there.
#
# SNAPS holds bare names. They are only ever used from SNAP_PARENT, pinned by
# remove_pinned below, never as absolute paths.
SNAPS=()
SNAP_PARENT=""
SNAP_PARENT_ID=""
SNAP_PROVEN=0
find_update_snapshots() {
  local dir parent base f name suffix
  SNAPS=(); SNAP_PROVEN=0
  if [[ -z "$CHECKOUT" ]]; then identify_checkout || true; fi
  if [[ -n "$CHECKOUT" ]]; then
    dir="$CHECKOUT"; SNAP_PROVEN=1
  else
    dir="$(cd "$REPO_DIR" && pwd -P)"
  fi
  [[ "$dir" != "/" ]] || return 0
  parent="$(dirname "$dir")"
  base="$(basename "$dir")"
  SNAP_PARENT="$parent"
  SNAP_PARENT_ID="$(stat -c '%d:%i' -- "$parent" 2>/dev/null || true)"
  while IFS= read -r -d '' f; do
    name="$(basename "$f")"
    [[ "$name" == "$base".* ]] || continue
    suffix="${name#"$base".}"
    # find -P with -type d / -type f: a symlink is neither, so one named like a
    # snapshot is skipped at listing time.
    if [[ -d "$f" && ! -L "$f" ]]; then
      [[ "$suffix" =~ ^(previous|rolled-back)-[0-9]{8}T[0-9]{6}Z(-[0-9]+)*$ ]] && SNAPS+=("$name")
    elif [[ -f "$f" && ! -L "$f" ]]; then
      [[ "$suffix" =~ ^db-[0-9]{8}T[0-9]{6}Z(-[0-9]+)*(-wal|-shm)?$ ]] && SNAPS+=("$name")
    fi
  done < <(find -P "$parent" -mindepth 1 -maxdepth 1 \( -type d -o -type f \) -print0 2>/dev/null | sort -z)
  return 0
}
find_update_snapshots

# Delete by bare name from a parent pinned once. The listing was made long
# before the delete (a prompt sits between), and an absolute path is resolved
# again at delete time: if an ancestor of the parent was renamed and a link
# planted in its place, root would delete in the link's target (#865). So cd -P
# into the parent, refuse unless it is the same directory (device:inode) the
# listing saw, and remove each name relative to it. rm never follows a link at
# the name itself.
#   remove_pinned PARENT PARENT_ID NAME...
remove_pinned() {
  local parent="$1" id="$2" n rc=0
  shift 2
  (
    cd -P -- "$parent" 2>/dev/null \
      && [[ -n "$id" && "$(stat -c '%d:%i' -- . 2>/dev/null)" == "$id" ]] \
      || { echo "  !! ${parent} is not the directory it was when this run listed it; nothing was removed from it."; exit 3; }
    for n in "$@"; do
      if rm -rf --one-file-system -- "$n" && [[ ! -e "$n" ]]; then
        echo "  → DELETED ${parent}/${n}"
      else
        echo "  !! could not remove ${parent}/${n}; remove it by hand."
      fi
    done
  ) || rc=$?
  return $rc
}

# What to tell the operator when these stay: a count, the size, how many are
# database copies, and one command with exact names (no glob: a glob would
# take a lookalike such as <checkout>.db-<stamp>.sql). cd plus relative names,
# so a hand run cannot be redirected by an ancestor link.
print_snapshot_remedy() { # $1 = indent
  local ind="$1" n dbn=0 size cmd
  for n in "${SNAPS[@]}"; do [[ "$n" == *.db-* ]] && dbn=$((dbn + 1)); done
  size="$(cd -P -- "$SNAP_PARENT" 2>/dev/null && du -shc -- "${SNAPS[@]}" 2>/dev/null | tail -1 | cut -f1)"
  cmd="cd $(printf '%q' "$SNAP_PARENT") && rm -rf --"
  for n in "${SNAPS[@]}"; do cmd+=" $(printf '%q' "$n")"; done
  echo "${ind}${#SNAPS[@]} update snapshot(s) beside the checkout, about ${size:-?}. ${dbn} of them are"
  echo "${ind}.db-* files, copies of the database, passkeys included. To remove exactly these:"
  echo "${ind}  ${cmd}"
}

# ── The fleet's files, decided once ─────────────────────────────────
#
# What the broker grant leaves in /etc/aperire, and which of it this run
# removes. Decided here, before the plan prints, and the plan and the steps
# both read these two lists, so what the plan says goes is what goes (#804).
# A wipe of the whole install takes all of /etc/aperire and needs neither.
#
# FLEET_DELETE   the broker's own files, on a wipe scoped to the dashboard
# FLEET_TOKENS   "delete", "keep" (an Advisor stays and reads them), or ""
FLEET_DELETE=()
FLEET_TOKENS=""
in_steps() { [[ " ${STEPS[*]} " == *" $1 "* ]]; }
if [[ $WIPE -eq 1 && $RM_CONFIG -eq 0 ]]; then
  if in_steps dashboard; then
    for f in "$ETC_APERIRE/fleet-broker.conf" "$ETC_APERIRE/fleet-nodes.conf" \
             "$ETC_APERIRE/fleet-arm.key" "$ETC_APERIRE/fleet-arm.made" "$ETC_APERIRE/fleet-model.cred" \
             "$ETC_APERIRE/fleet-model.cred.plain" "$ETC_APERIRE"/.fleet-arm.key.??????; do
      [[ -e "$f" || -L "$f" ]] && FLEET_DELETE+=("$f")
    done
    if [[ -e "$ETC_APERIRE/fleet-tokens" ]]; then
      if [[ $ADVISOR_ROOT -eq 1 ]] && ! in_steps advisor; then
        FLEET_TOKENS=keep
      else
        FLEET_TOKENS=delete
      fi
    fi
  elif in_steps advisor && [[ -e "$ETC_APERIRE/fleet-tokens" ]]; then
    # The Advisor's half going after the dashboard's already went: nothing
    # that writes or reads the tokens is left once this step is done, and
    # they are group aperire-svc, which this step deletes. Left, they would
    # carry a dead gid the next group made here inherits.
    if ! broker_grant_here && [[ ${#DASH_INSTANCES[@]} -eq 0 ]]; then
      FLEET_TOKENS=delete
    fi
  fi
fi

# ── The shared group, decided once (#824, #986) ─────────────────────
#
# Deleting a group does not touch its files: each keeps the bare gid, and
# the next group made on this host can be given it and read them. On a lab
# aggregator a keep left every fleet token root:<dead gid> 0640. So a file
# this run keeps under /etc/aperire never stays on a group this run deletes.
#
# For aperire-svc the group stays instead, while a kept file is on it. It is
# the one name both halves of a later install find by name: the Advisor's
# installer adopts it (`getent group || groupadd`) and adds both accounts, and
# the dashboard's adds its own account when kept fleet tokens are on it, so
# every kept file is readable again the moment they rejoin it, with no step
# having to know which files to give back. userdel takes out only the
# accounts it deletes, so every other member (a login a dashboard used to run
# as, before ADR 0024) is taken out here too, and only a dashboard that stays
# is left in it: on a whole keep it has no members and only root reads its
# files, the same as root:root would be. On an Advisor-only removal the dashboard that
# stays is still in it, so it still reads the fleet's tokens after its next
# restart (#986), which a dashboard on a group that was deleted cannot. And
# while it exists its gid cannot be handed to anyone else. A later wipe takes
# it: the group alone puts the Advisor's step on that run's list.
#
# The groups named after one account (the dashboard's, the Advisor's, the
# relay's) cannot stay: each installer makes its account with a group of the
# same name (--user-group, or useradd's own default), and useradd refuses to
# when that group already exists. Their kept files
# go to root's group instead, right before the account goes
# (release_kept_etc_ids, below), and each installer gives its own file back:
# install-aperire-service.sh the env file and an aggregator's fleet tokens,
# install-aperire-relay.sh relay.conf.
#
# What this run deletes from /etc/aperire is not kept, so it does not keep
# the group: a wipe takes all of it, and the fleet's files in FLEET_DELETE
# and FLEET_TOKENS go before the group is decided.
svc_kept_in_etc() {  # prints each kept file on the shared group, one a line
  local gid f d
  [[ $RM_CONFIG -eq 0 && -d "$ETC_APERIRE" ]] || return 0
  gid="$(getent group "$SHARED_GROUP" 2>/dev/null | cut -d: -f3 || true)"
  [[ "$gid" =~ ^[0-9]+$ ]] || return 0
  while IFS= read -r -d '' f; do
    [[ "$FLEET_TOKENS" == delete && ( "$f" == "$ETC_APERIRE/fleet-tokens" || "$f" == "$ETC_APERIRE/fleet-tokens/"* ) ]] && continue
    for d in ${FLEET_DELETE[@]+"${FLEET_DELETE[@]}"}; do [[ "$f" == "$d" ]] && continue 2; done
    printf '%s\n' "$f"
  done < <(find "$ETC_APERIRE" -gid "$gid" -print0 2>/dev/null)
  return 0
}
SVC_KEPT=()
if in_steps advisor; then
  while IFS= read -r line; do [[ -n "$line" ]] && SVC_KEPT+=("$line"); done < <(svc_kept_in_etc)
fi

echo "  Then:"
SCOPE_NOTE=""
[[ $WIPE -eq 1 && $ROLE_SCOPED -eq 1 ]] && SCOPE_NOTE="  (--role=${ROLE} is one half of this install, and the other half reads it)"
if [[ $RM_CONFIG -eq 1 ]]; then
  echo "    • DELETE ${ETC_APERIRE}/  (relay token, authn.yaml, relay.conf, any sealed key)"
  if [[ -e "$ETC_APERIRE/fleet-arm.key" ]]; then
    echo "      This includes fleet-arm.key, the key every paired node pins for this"
    echo "      aggregator. Nothing makes a new one on its own while this host's fleet"
    echo "      records still name a node: the grant installer refuses and names the"
    echo "      restore. Keep a backup set to put it back, or make a new one with"
    echo "      install-fleet-broker-grant.sh --new-fleet-keys and pair every node again."
  fi
else
  echo "    • keep ${ETC_APERIRE}/${SCOPE_NOTE}"
  for f in ${FLEET_DELETE[@]+"${FLEET_DELETE[@]}"}; do
    echo "      except: DELETE ${f}"
  done
  if [[ "$FLEET_TOKENS" == delete ]]; then
    echo "      except: DELETE ${ETC_APERIRE}/fleet-tokens"
  elif [[ "$FLEET_TOKENS" == keep ]]; then
    echo "      and keep ${ETC_APERIRE}/fleet-tokens, which the Advisor staying here reads"
  fi
  if [[ ${#SVC_KEPT[@]} -gt 0 ]]; then
    echo "    • keep the ${SHARED_GROUP} group: ${#SVC_KEPT[@]} file(s) kept in ${ETC_APERIRE} are on it,"
    echo "      so its id is not freed for another group to inherit, and take every member"
    echo "      out of it but a dashboard that stays. A later install reads them through it"
    echo "      again; a wipe removes it"
  fi
  if [[ " ${FLEET_DELETE[*]} " == *" $ETC_APERIRE/fleet-arm.key "* ]]; then
    echo "      fleet-arm.key is the key every paired node pins for this aggregator,"
    echo "      and fleet-arm.made, the record that it was made, goes with it. Without"
    echo "      it, every node paired to this one has to be told to trust a new one"
    echo "      again. Nothing makes that new one on its own while the fleet's records"
    echo "      still name a node: restore it from a backup set, or use the grant"
    echo "      installer's --new-fleet-keys."
  fi
fi
if [[ $RM_DATA -eq 1 ]]; then
  echo "    • DELETE ${REPO_DIR}/data/  (the database and the rotated logs)"
else
  echo "    • keep ${REPO_DIR}/data/${SCOPE_NOTE}"
fi
if [[ $RM_CHECKOUT -eq 1 ]]; then
  if [[ -n "$CHECKOUT" ]]; then
    echo "    • DELETE ${CHECKOUT}/  (${CHECKOUT_WHY})"
  else
    echo "    • KEEP the checkout at ${REPO_DIR}: no dashboard unit on this host"
    echo "      names it, so it is not removed on a resemblance. Remove it yourself."
  fi
fi
if [[ $RM_CHECKOUT -eq 1 && $SNAP_PROVEN -eq 1 && ${#SNAPS[@]} -gt 0 ]]; then
  echo "    • DELETE ${#SNAPS[@]} update snapshot(s) beside the checkout, the database copies"
  echo "      among them (${CHECKOUT}.previous-*, .rolled-back-*, .db-*)"
fi
if [[ $RM_TOOLCHAIN -eq 1 ]]; then
  echo "    • DELETE ${GO_DIR}, ${OP_HOME}/.nvm, ${OP_HOME}/.npm, ${OP_HOME}/go"
fi
echo
echo "  Not touched, on either ending: your node (container, config, ledger"
echo "  store), docker$([[ $RM_TOOLCHAIN -eq 1 ]] || echo ', Go, nvm')."
echo

if [[ $ASSUME_YES -ne 1 ]]; then
  if ! IFS= read -r -p "  Proceed? [y/N] " reply; then
    echo
    echo "error: there is no terminal to confirm on. Add --yes to take the plan exactly as printed." >&2
    exit 2
  fi
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "aborted."; exit 0 ;;
  esac
fi

GO_PROFILE_REMOVED=0

# ── Helpers ─────────────────────────────────────────────────────────
# A unit's "failed" record, cleared once the unit is stopped and never before
# (#1036). A service that exits non-zero on SIGTERM (node under tsx exits 143)
# is left failed by its own stop, an instance of a socket's template can be
# left failed by a run that ended badly, and systemd keeps either record after
# the unit file is gone: a clean uninstall then showed a red unit in
# `systemctl list-units --failed` until a reboot. Patterns are systemd's own,
# for a template's instances. Quiet, because a unit with no record is the
# normal case and says nothing.
clear_failed() {  # $@ = unit names or patterns
  local u
  for u in "$@"; do
    systemctl reset-failed "$u" >/dev/null 2>&1 || true
  done
}

stop_disable_remove() {
  # $1 = unit name (without .service), $2 = unit file path
  local svc="$1" unit="$2"
  if systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q -e "${svc}.service"; then
    systemctl stop "${svc}" 2>/dev/null || true
    systemctl disable "${svc}" 2>/dev/null || true
    echo "  → stopped + disabled ${svc}"
  fi
  # Outside the test above: a record an older uninstall left behind has no
  # unit file to find it by.
  clear_failed "${svc}.service"
  if [[ -f "$unit" ]]; then
    rm -f "$unit"
    echo "  → removed ${unit}"
  fi
}

remove_if_present() {
  local p
  for p in "$@"; do
    if [[ -L "$p" || -e "$p" ]]; then
      rm -rf "$p"
      echo "  → removed ${p}"
    fi
  done
}

# One access control entry, taken back only where it is actually there. An
# unconditional setfacl -x exits 0 on a path that never had one, so a run that
# removed nothing would print the same line as a run that removed four.
drop_acl() {  # $1 = path, $2 = account (default: the Advisor's)
  local acct="${2:-$ADVISOR_ACCOUNT}"
  [[ -e "$1" ]] || return 0
  command -v getfacl >/dev/null 2>&1 || return 0
  command -v setfacl >/dev/null 2>&1 || return 0
  getfacl -p "$1" 2>/dev/null | grep -q "^user:${acct}:" || return 0
  # -n: never recompute the mask. Without it, removing our entry recomputes
  # the mask from what is left, which can hand back a write another named
  # entry had masked off (measured: r-x became rwx).
  setfacl -n -x "u:${acct}" "$1" 2>/dev/null || true
  echo "  → ${acct} no longer has an access control entry on $1"
}

# One sudo rule of ours, by exact name, then what is left read back. A failure
# of the read-back is not this removal's doing (taking a file away cannot
# break the others), so it is a thing to go and look at rather than a reason
# to abandon the rest of the run.
remove_sudoers_rule() {  # $1 = the file's name in $SUDOERS_DIR
  [[ -f "$SUDOERS_DIR/$1" || -L "$SUDOERS_DIR/$1" ]] || return 0
  rm -f "$SUDOERS_DIR/$1"
  echo "  → removed ${SUDOERS_DIR}/$1"
  if command -v visudo >/dev/null 2>&1 && ! visudo -c >/dev/null 2>&1; then
    echo "  !! visudo -c is unhappy with what is left in ${SUDOERS_DIR}."
    echo "     That is not this file: read it with  sudo visudo -c"
  fi
}

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

# A shared group this run keeps reads its files to nobody but a dashboard
# that stays, and the Advisor's account while the hand-back keeps it
# (#1023 review, M1). userdel took out the accounts it deleted; a login that
# ran a dashboard before ADR 0024, or anyone added by hand, is still listed,
# and a later install adopts the group by name. Each one taken out is named.
strip_kept_shared_group() {
  local keep_in m
  keep_in=" $(staying_dashboard_accounts | tr '\n' ' ') "
  [[ $HANDBACK_KEEP_ACCOUNT -eq 1 ]] && keep_in+="$ADVISOR_ACCOUNT "
  for m in $(getent group "$SHARED_GROUP" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
    [[ "$keep_in" == *" $m "* ]] && continue
    if gpasswd -d "$m" "$SHARED_GROUP" >/dev/null 2>&1; then
      echo "  → took ${m} out of the '${SHARED_GROUP}' group: it stays for the kept files, not for ${m}"
    else
      echo "  !! could not take ${m} out of the '${SHARED_GROUP}' group; it can still read those files."
      echo "     Take it out by hand:  sudo gpasswd -d ${m} ${SHARED_GROUP}"
    fi
  done
  return 0
}

# The accounts the dashboards that stay on this host run as, one per line,
# each read from its unit (a drop-in's User= over the unit's own), never
# assumed from a name. Every instance, aperire-server and aperire-read alike:
# a second dashboard on an account of its own reads through the shared group
# just as the first does. Prints nothing when no dashboard unit is left.
staying_dashboard_accounts() {
  local u d user v
  in_steps dashboard && return 0
  for u in "$UNIT_DIR"/aperire-server*.service "$UNIT_DIR"/aperire-read*.service; do
    [[ -f "$u" ]] || continue
    user="$(awk -F= '/^[[:space:]]*User[[:space:]]*=/{v=$2; gsub(/[[:space:]]/,"",v)} END{print v}' "$u" 2>/dev/null || true)"
    for d in "$u".d/*.conf; do
      [[ -f "$d" ]] || continue
      v="$(awk -F= '/^[[:space:]]*User[[:space:]]*=/{v=$2; gsub(/[[:space:]]/,"",v)} END{print v}' "$d" 2>/dev/null || true)"
      [[ -n "$v" ]] && user="$v"
    done
    [[ -n "$user" ]] && printf '%s\n' "$user"
  done | awk '!seen[$0]++'
  return 0
}

# Set by hand_back_advisor_files, read by the Advisor step right after it:
# anything that could not be handed back keeps the account (and the group),
# so nothing in the checkout is left on a bare id the next account inherits.
HANDBACK_KEEP_ACCOUNT=0
HANDBACK_KEEP_GROUP=0

# Everything the Advisor account owned inside the checkout, handed back to
# the checkout's own owner BEFORE the account is removed.
#
# userdel does not touch files: every one the account owned is left carrying a
# bare numeric uid, and the next account created on this box inherits them.
# Under --keep that is not academic. advisor/state/approve.token,
# credentials.json, advisor/evidence and the knowledge directories survive on
# purpose; a later reinstall carries them across as root with their ownership
# intact; install-advisord.sh chowns the state DIRECTORY and not what is in it;
# and advisord, running as the operator before the account step, crash-loops on
# "open advisor/state/approve.token: permission denied". Live on aperire4,
# 2026-09-07, on the second install over kept artifacts.
#
# Done on both endings rather than only under --keep, because a --wipe that
# could not identify the checkout leaves it standing too, and that host would
# carry the same orphaned uids.
#
# Before the account goes, and before the group with it: a find by name has
# nothing to match once either is gone.
#
# What the Advisor shared with a dashboard that stays is not the checkout
# owner's to take (#979). aperire-svc is the group the two read each other's
# files through: the dashboard's read token in advisor/state, and on a node
# the fleet-trust.yaml whose peers.aggregator the dashboard checks on every
# link connection. Handed to the owner with the rest, and the group removed
# below, a dashboard that runs as its own account (ADR 0024) could read
# neither. Every fleet read of the node was refused while the aggregator's
# row still read reachable, and the link itself would have been refused at
# its next connection. So when such a dashboard stays, every file on that
# group moves to the dashboard's own group instead, modes untouched: it reads
# exactly what it read before. Only the files the account owned change owner,
# so a file root owned (the node's fleet-trust.yaml) stays root's, as pairing
# left it. Nothing restarts: the running dashboard reads through its primary
# group, which is the group this sets.
#
# Two dashboards on two accounts of their own both read through that group,
# and no one group of theirs can stand in for it, so then the shared files
# keep it and the group stays.
#
# On such a host every change is made on descriptors through state-file.py,
# never by name (#987 review, M1). The dashboard's account is still running
# and still in aperire-svc while this runs, and advisor/knowledge-fleet is
# group-writable on that group with no sticky bit. So the account can move
# one of the Advisor's files into a directory of its own, and swap that
# directory for a link between the find that names the file and the chown
# that acts on it; `chown -h` protects the last component only, and root
# would hand the link's target (anything under /etc) to the operator. The
# helper walks every component without following a link and refuses one by
# name. With no helper on such a host nothing is handed back, rather than
# by name: the files are named, and the account and the group stay.
hand_back_advisor_files() {
  local owner group n dash="" dash_gid="" has_shared=0 rc_u=0 rc_s=0 ouid ogid a
  local -a expr=() user_expr=() shared=() users=() users_shared=() accounts=()
  HANDBACK_KEEP_ACCOUNT=0
  HANDBACK_KEEP_GROUP=0

  # Built from what still exists, because `find -user <name>` is a usage error
  # for a name the passwd database does not have, not an empty result.
  if id "$ADVISOR_ACCOUNT" >/dev/null 2>&1; then
    expr+=(-user "$ADVISOR_ACCOUNT")
    user_expr=(-user "$ADVISOR_ACCOUNT")
  fi
  if getent group "$SHARED_GROUP" >/dev/null 2>&1; then
    [[ ${#expr[@]} -gt 0 ]] && expr+=(-o)
    expr+=(-group "$SHARED_GROUP")
    has_shared=1
  fi
  [[ ${#expr[@]} -gt 0 ]] || return 0
  [[ -d "$REPO_DIR" ]] || return 0

  # The checkout's own owner is the answer, not the account that happens to be
  # running this: on a `sudo bash uninstall.sh` from somewhere else they are
  # different, and the files belong to whoever the checkout belongs to.
  owner="$(stat -c %U "$REPO_DIR" 2>/dev/null || true)"
  group="$(stat -c %G "$REPO_DIR" 2>/dev/null || true)"
  # stat says UNKNOWN for an id with no name, which is exactly the state this
  # exists to prevent and is no use as a target.
  [[ -n "$owner" && "$owner" != "UNKNOWN" ]] || owner="$OP_USER"
  [[ -n "$group" && "$group" != "UNKNOWN" ]] || group="$owner"
  [[ -n "$owner" ]] || return 0

  n="$(find "$REPO_DIR" \( "${expr[@]}" \) -print 2>/dev/null | wc -l)"
  # Nothing to hand back is not a thing to announce. A line here on a host
  # where no file changed hands would be the same class of claim this script
  # refuses everywhere else.
  [[ "${n:-0}" -gt 0 ]] || return 0

  # The dashboards that stay, under accounts of their own. One that runs as
  # the checkout's owner (a host from before ADR 0024) reads what the owner
  # gets, and owns the tree anyway.
  while IFS= read -r a; do
    [[ -n "$a" && "$a" != "$owner" ]] || continue
    id "$a" >/dev/null 2>&1 && accounts+=("$a")
  done < <(staying_dashboard_accounts)

  if [[ ${#accounts[@]} -eq 0 ]]; then
    # -h so a symlink is retargeted rather than whatever it points at, and the
    # group as well as the user, because aperire-svc is removed a few lines
    # below and its gid would be orphaned the same way. By name, because no
    # account other than the checkout's owner is left running to race it.
    find "$REPO_DIR" \( "${expr[@]}" \) -exec chown -h "${owner}:${group}" {} + 2>/dev/null || true
    echo "  → handed the Advisor's state back to ${owner} (${n} file(s) under ${REPO_DIR})"
    return 0
  fi

  if [[ ! -f "$STATE_TOOL" ]] || ! command -v python3 >/dev/null 2>&1; then
    HANDBACK_KEEP_ACCOUNT=1 HANDBACK_KEEP_GROUP=1
    echo "  !! nothing of the Advisor's was handed back: ${accounts[*]} still runs a dashboard here, and"
    echo "     with no python3 or no ${STATE_TOOL} root cannot hand files over without"
    echo "     following a link that account could plant. These ${n} file(s) are left as they are:"
    find "$REPO_DIR" \( "${expr[@]}" \) -print 2>/dev/null | head -20 | sed 's/^/       /'
    echo "     Put the helper back, then run this uninstall again:"
    echo "       curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    return 0
  fi

  ouid="$(stat -c %u "$REPO_DIR" 2>/dev/null || true)"
  ogid="$(stat -c %g "$REPO_DIR" 2>/dev/null || true)"
  [[ "$(stat -c %U "$REPO_DIR" 2>/dev/null)" != UNKNOWN ]] || ouid="$(id -u "$owner" 2>/dev/null || true)"
  [[ "$(stat -c %G "$REPO_DIR" 2>/dev/null)" != UNKNOWN ]] || ogid="$(id -g "$owner" 2>/dev/null || true)"

  # Every list is read before anything moves. The account's own files go to
  # the owner, user and group; the ones on the shared group change owner only,
  # and their group is decided with the rest of the shared files below.
  [[ $has_shared -eq 1 ]] && mapfile -d '' shared < <(find "$REPO_DIR" -group "$SHARED_GROUP" -print0 2>/dev/null)
  if [[ ${#user_expr[@]} -gt 0 ]]; then
    if [[ $has_shared -eq 1 ]]; then
      mapfile -d '' users < <(find "$REPO_DIR" "${user_expr[@]}" ! -group "$SHARED_GROUP" -print0 2>/dev/null)
      mapfile -d '' users_shared < <(find "$REPO_DIR" "${user_expr[@]}" -group "$SHARED_GROUP" -print0 2>/dev/null)
    else
      mapfile -d '' users < <(find "$REPO_DIR" "${user_expr[@]}" -print0 2>/dev/null)
    fi
  fi
  if [[ ${#users[@]} -gt 0 ]]; then
    printf '%s\0' "${users[@]}" \
      | python3 -I "$STATE_TOOL" own-many "$ouid" "$ogid" "" --root "$REPO_DIR" || rc_u=$?
  fi
  if [[ ${#users_shared[@]} -gt 0 ]]; then
    printf '%s\0' "${users_shared[@]}" \
      | python3 -I "$STATE_TOOL" own-many "$ouid" "" "" --root "$REPO_DIR" || rc_u=$?
  fi
  if [[ ${#accounts[@]} -eq 1 && ${#shared[@]} -gt 0 ]]; then
    dash="${accounts[0]}"
    # The group the dashboard's install plants with: the one named after the
    # account, its primary group otherwise.
    dash_gid="$(getent group "$dash" 2>/dev/null | cut -d: -f3 || true)"
    [[ -n "$dash_gid" ]] || dash_gid="$(id -g "$dash" 2>/dev/null || true)"
    if [[ -n "$dash_gid" ]]; then
      printf '%s\0' "${shared[@]}" \
        | python3 -I "$STATE_TOOL" own-many "" "$dash_gid" "" --root "$REPO_DIR" || rc_s=$?
    else
      rc_s=1
    fi
  fi

  if [[ $rc_u -eq 0 ]]; then
    echo "  → handed the Advisor's state back to ${owner} (${n} file(s) under ${REPO_DIR})"
  else
    HANDBACK_KEEP_ACCOUNT=1 HANDBACK_KEEP_GROUP=1
    echo "  !! some of the Advisor's files were not handed back to ${owner} (named above), so its"
    echo "     account and the '${SHARED_GROUP}' group stay: removing them would leave those files on"
    echo "     ids the next account inherits. Take away what is named, then run this uninstall again."
  fi
  [[ ${#shared[@]} -gt 0 ]] || return 0
  if [[ ${#accounts[@]} -gt 1 ]]; then
    HANDBACK_KEEP_GROUP=1
    echo "  !! ${accounts[*]} each run a dashboard here and read through '${SHARED_GROUP}', and no one"
    echo "     group of theirs can stand in for it, so the group and its ${#shared[@]} file(s) stay as"
    echo "     they are. Once only one of them reads these files:  sudo groupdel ${SHARED_GROUP}"
  elif [[ $rc_s -eq 0 ]]; then
    echo "  → what it shared with the dashboard (${#shared[@]} file(s), the read token among them) is on"
    echo "    ${dash}'s own group now, so the dashboard that stays here still reads it"
  else
    # The account too: a file refused here may be one the account owns.
    HANDBACK_KEEP_ACCOUNT=1 HANDBACK_KEEP_GROUP=1
    echo "  !! some of what it shared with the dashboard is not on ${dash}'s group (named above), so"
    echo "     the Advisor's account and the '${SHARED_GROUP}' group stay, and the dashboard still reads"
    echo "     through it. Take away what is named, then run this uninstall again."
  fi
}

# The dashboard's own account (ADR 0024), once no dashboard on this host runs
# as it. In the order the Advisor's goes, for the same reasons: the access
# entries while they still read back by name, then everything it owns handed
# to the checkout's owner (data/ under --keep is the case that matters: a
# reinstall hands it straight back), then the account.
#
# The entries it was given: passage on each directory above the checkout
# (install-aperire-service.sh grants only where it had to, and this takes
# back only what is there), and the named read on the node config and its
# directory (close-node-config-exposure.sh).
#
# The node config's path is only on record in node-wrapper.conf, and the
# Advisor step removes that file, so DASH_CFG_SEEN is read before the first
# step runs (see the step loop) and every call, early or late, uses it.
DASH_CFG_SEEN=""
remove_dashboard_account() {
  local u d owner group cfg uid gid holder="" p parent base rc holder_kind=unit
  id "$DASH_ACCOUNT" >/dev/null 2>&1 || return 0
  # Kept while anything still runs as it or opens a socket to it. A socket
  # left listening under an account that is then deleted is a root program
  # reachable by whatever system account useradd hands that uid next. The
  # seal and trust-sync sockets belong to the Advisor's step, so an uninstall
  # scoped to the dashboard that keeps the Advisor stops here and says why.
  # Drop-ins count: an override that sets User= runs the unit as the account
  # exactly as the unit file does, and this now runs on every Advisor-only
  # uninstall, so a miss here would delete the account under a live dashboard.
  for u in "$UNIT_DIR"/aperire*.service "$UNIT_DIR"/aperire*.socket "$UNIT_DIR"/aperire*.service.d/*.conf "$UNIT_DIR"/aperire*.socket.d/*.conf; do
    [[ -f "$u" ]] || continue
    if grep -qE "^[[:space:]]*(User|SocketUser)[[:space:]]*=[[:space:]]*${DASH_ACCOUNT}[[:space:]]*$" "$u" 2>/dev/null; then
      holder="$(basename "$u")"
      # A drop-in is named by the unit it overrides, then by itself.
      case "$(dirname "$u")" in *.d) holder="$(basename "$(dirname "$u")" .d), through its drop-in ${holder}" ;; esac
      break
    fi
  done
  # What systemd itself says, for the units that do not live in $UNIT_DIR
  # (/usr/lib, /run, transient ones) and for units that are not ours at all: a
  # socket anyone wrote with SocketUser= names the account too, and pgrep can't
  # see a socket nothing has accepted on. One show over every loaded service and
  # socket. A unit counts while it is active or its file is still on disk: one
  # this run just removed stays loaded until the daemon-reload at the end, and
  # that one must not hold the account.
  if [[ -z "$holder" ]] && command -v systemctl >/dev/null 2>&1; then
    local -a names=()
    local id state frag listed shown lrc=0 src=0
    # A systemd that cannot be asked is not an empty answer: this runs as root
    # right before a kill and a userdel, so it fails closed.
    listed="$(systemctl list-units --all --plain --no-legend --type=service,socket 2>/dev/null)" || lrc=$?
    if [[ $lrc -ne 0 ]]; then
      holder="systemd could not be asked"; holder_kind=systemd
    else
      mapfile -t names < <(awk '{print $1}' <<<"$listed")
      [[ ${#names[@]} -eq 1 && -z "${names[0]}" ]] && names=()
      if [[ ${#names[@]} -gt 0 ]]; then
        shown="$(systemctl show -p Id -p User -p SocketUser -p ActiveState -p FragmentPath "${names[@]}" 2>/dev/null)" || src=$?
        if [[ $src -ne 0 ]] || ! grep -q '^Id=' <<<"$shown"; then
          holder="systemd could not be asked"; holder_kind=systemd
        else
          while IFS='|' read -r id state frag; do
            [[ -n "$id" ]] || continue
            if [[ "$state" == active || "$state" == activating || "$state" == reloading || ( -n "$frag" && -f "$frag" ) ]]; then
              holder="$id"; break
            fi
          done < <(awk -v a="$DASH_ACCOUNT" 'BEGIN { RS = ""; FS = "\n" }
              { id = ""; hit = 0; st = ""; fr = ""
                for (i = 1; i <= NF; i++) {
                  k = $i; sub(/=.*/, "", k); v = $i; sub(/^[^=]*=/, "", v)
                  if (k == "Id") id = v
                  else if ((k == "User" || k == "SocketUser") && v == a) hit = 1
                  else if (k == "ActiveState") st = v
                  else if (k == "FragmentPath") fr = v
                }
                if (hit) print id "|" st "|" fr }' <<<"$shown")
        fi
      fi
    fi
  fi
  # And anything still running as it, whatever started it: killing a process
  # the account owns is not this uninstall's call to make.
  if [[ -z "$holder" ]] && command -v pgrep >/dev/null 2>&1 && pgrep -u "$DASH_ACCOUNT" >/dev/null 2>&1; then
    holder="a process still running as it (pgrep -u ${DASH_ACCOUNT})"
    holder_kind=process
  fi
  if [[ -n "$holder" ]]; then
    # An Advisor step in this same run removes the sockets after this point,
    # and the call after the last step takes the account then. Saying "kept"
    # now would be wrong, and the hint to uninstall the Advisor too would
    # point at what is already happening.
    if in_steps advisor && [[ "${1:-}" != final ]]; then return 0; fi
    if [[ $holder_kind == systemd ]]; then
      echo "  → kept the '${DASH_ACCOUNT}' account: ${holder} what runs as it, so nothing was killed or removed"
      echo "    (run this uninstall again once systemctl answers)"
      return 0
    fi
    echo "  → kept the '${DASH_ACCOUNT}' account: ${holder} still names it"
    if ! in_steps advisor; then
      case "$holder" in
        # The Advisor's own units, by exact name. The credcheck unit is left out
        # on purpose: it runs as root, so it is never what holds this account.
        aperire-seal-model-key.socket|aperire-seal-model-key@*.service|aperire-trust-sync.socket|aperire-trust-sync@*.service|aperire-advisord.service)
          echo "    (it is removed with the last unit that does: uninstall the Advisor too)" ;;
        *)
          if [[ $holder_kind == process ]]; then
            echo "    (stop what runs as it, then run this uninstall again)"
          else
            echo "    (stop and remove that unit, then run this uninstall again)"
          fi ;;
      esac
    fi
    return 0
  fi
  # Nothing is left running as it, before anything it owned changes hands.
  pkill -u "$DASH_ACCOUNT" 2>/dev/null || true
  d="$REPO_DIR"
  while [[ -n "$d" && "$d" != "/" ]]; do drop_acl "$d" "$DASH_ACCOUNT"; d="$(dirname "$d")"; done
  drop_acl "$OP_HOME" "$DASH_ACCOUNT"
  # Every directory the installer gave it passage through (the node's chain
  # among them), from root's own record of what it granted.
  if [[ -f "$ETC_APERIRE/dashboard-passage" && ! -L "$ETC_APERIRE/dashboard-passage" ]]; then
    while IFS= read -r p; do
      [[ "$p" == /* ]] && drop_acl "$p" "$DASH_ACCOUNT"
    done < "$ETC_APERIRE/dashboard-passage"
    rm -f "$ETC_APERIRE/dashboard-passage"
  fi
  cfg="$DASH_CFG_SEEN"
  if [[ -n "$cfg" ]]; then
    drop_acl "$cfg" "$DASH_ACCOUNT"; drop_acl "$(dirname "$cfg")" "$DASH_ACCOUNT"
  fi
  if [[ -d "$REPO_DIR" ]]; then
    owner="$(stat -c %U "$REPO_DIR" 2>/dev/null || true)"
    group="$(stat -c %G "$REPO_DIR" 2>/dev/null || true)"
    [[ -n "$owner" && "$owner" != UNKNOWN && "$owner" != "$DASH_ACCOUNT" ]] || owner="$OP_USER"
    [[ -n "$group" && "$group" != UNKNOWN && "$group" != "$DASH_ACCOUNT" ]] || group="$owner"
    uid="$(id -u "$owner" 2>/dev/null || true)"; gid="$(getent group "$group" 2>/dev/null | cut -d: -f3 || true)"
    # Handed back on descriptors, never by name: the account owned data/ and
    # could have put a link anywhere in it. state-file.py refuses a link, a
    # special file and a second link to one file, and names each. The update
    # snapshots beside the checkout (<checkout>.db-*) go back too.
    parent="$(dirname "$REPO_DIR")"; base="$(basename "$REPO_DIR")"
    if [[ -n "$uid" && -n "$gid" && -f "$STATE_TOOL" ]] && command -v python3 >/dev/null 2>&1; then
      rc=0
      { find "$REPO_DIR" \( -user "$DASH_ACCOUNT" -o -group "$DASH_ACCOUNT" \) -print0 2>/dev/null
        find "$parent" -maxdepth 1 -name "${base}.db-*" \( -user "$DASH_ACCOUNT" -o -group "$DASH_ACCOUNT" \) -print0 2>/dev/null
      } | python3 -I "$STATE_TOOL" own-many "$uid" "$gid" "" --root "$parent" || rc=$?
      if [[ $rc -eq 0 ]]; then
        echo "  → handed the dashboard's files back to ${owner}"
      else
        echo "  !! some of the dashboard's files were not handed back (named above); they are left as they are"
      fi
    else
      echo "  !! the dashboard's files were not handed back to ${owner}: no python3 or no"
      echo "     ${STATE_TOOL} here. Find them:  sudo find ${REPO_DIR} -user ${DASH_ACCOUNT}"
    fi
  fi
  if ! release_kept_etc_ids "$DASH_ACCOUNT"; then
    echo "  → kept the '${DASH_ACCOUNT}' account and its group, for the files named above"
    return 0
  fi
  remove_account "$DASH_ACCOUNT"
  if getent group "$DASH_ACCOUNT" >/dev/null 2>&1; then
    groupdel "$DASH_ACCOUNT" 2>/dev/null || true
  fi
}

# A service account's files kept in /etc/aperire, given to root before the
# account goes, and with it the group named after it (#824). userdel and
# groupdel leave every file they owned on a bare id, and the next account or
# group made on this host can be given that id. The env file is the
# dashboard's group's, relay.conf the relay's, and an aggregator with no
# Advisor keeps its fleet tokens on the dashboard's group. Owner and group
# only, modes untouched, so only root reads them until a reinstall gives
# them back (see "The shared group, decided once").
#
# On descriptors through state-file.py, never by name: /etc/aperire is root's,
# and this is the same helper every other root hand-over here goes through.
# Only the group named after the account: a shared primary group (a host
# made without private groups) is not this run's to delete or to empty.
# Returns 1 when anything could not be handed over; the caller then keeps the
# account, and so its group, and the files are named.
release_kept_etc_ids() {  # $1 = account name
  local acct="$1" uid gid rc=0 n
  local -a by_uid=() by_gid=()
  [[ $RM_CONFIG -eq 0 && -d "$ETC_APERIRE" && ! -L "$ETC_APERIRE" ]] || return 0
  uid="$(id -u "$acct" 2>/dev/null || true)"
  gid="$(getent group "$acct" 2>/dev/null | cut -d: -f3 || true)"
  [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || uid=""
  [[ "$gid" =~ ^[0-9]+$ && "$gid" != 0 ]] || gid=""
  [[ -n "$uid" ]] && mapfile -d '' by_uid < <(find "$ETC_APERIRE" -uid "$uid" -print0 2>/dev/null)
  [[ -n "$gid" ]] && mapfile -d '' by_gid < <(find "$ETC_APERIRE" -gid "$gid" -print0 2>/dev/null)
  n=$(( ${#by_uid[@]} + ${#by_gid[@]} ))
  [[ $n -gt 0 ]] || return 0
  if [[ ! -f "$STATE_TOOL" ]] || ! command -v python3 >/dev/null 2>&1; then
    echo "  !! files kept in ${ETC_APERIRE} are on the '${acct}' account or its group, and with no"
    echo "     python3 or no ${STATE_TOOL} root does not hand them over by name:"
    printf '%s\n' ${by_uid[@]+"${by_uid[@]}"} ${by_gid[@]+"${by_gid[@]}"} | sort -u | head -20 | sed 's/^/       /'
    return 1
  fi
  if [[ ${#by_uid[@]} -gt 0 ]]; then
    printf '%s\0' "${by_uid[@]}" | python3 -I "$STATE_TOOL" own-many 0 "" "" --root "$ETC_APERIRE" || rc=$?
  fi
  if [[ ${#by_gid[@]} -gt 0 ]]; then
    printf '%s\0' "${by_gid[@]}" | python3 -I "$STATE_TOOL" own-many "" 0 "" --root "$ETC_APERIRE" || rc=$?
  fi
  n="$(printf '%s\n' ${by_uid[@]+"${by_uid[@]}"} ${by_gid[@]+"${by_gid[@]}"} | sort -u | wc -l)"
  if [[ $rc -ne 0 ]]; then
    echo "  !! some of the ${n} file(s) kept in ${ETC_APERIRE} for '${acct}' are still on its ids"
    echo "     (named above), so the account and its group stay rather than leave them on ids"
    echo "     the next account inherits. Take away what is named, then run this uninstall again."
    return 1
  fi
  echo "  → ${n} file(s) kept in ${ETC_APERIRE} were on the '${acct}' account or its group; they are"
  echo "    root's now, modes unchanged, so only root reads them until a reinstall gives them back"
  return 0
}

remove_account() {  # $1 = account name
  id "$1" >/dev/null 2>&1 || return 0
  # Anything still running as that account holds files open and would keep a
  # home directory alive that userdel is about to unlink.
  pkill -u "$1" 2>/dev/null || true
  userdel "$1" 2>/dev/null || true
  if id "$1" >/dev/null 2>&1; then
    echo "  !! the '$1' account is still here. Something is running as it:"
    echo "     ps -u $1"
  else
    echo "  → removed the '$1' account"
  fi
}

# ── Run the steps ───────────────────────────────────────────────────
# Before the Advisor step deletes the file that holds it (#907).
if [[ -f "$ETC_APERIRE/node-wrapper.conf" ]]; then
  DASH_CFG_SEEN="$(awk -F= '$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$ETC_APERIRE/node-wrapper.conf" 2>/dev/null || true)"
fi
for step in ${STEPS[@]+"${STEPS[@]}"}; do
  echo
  echo "═══ ${step} ═══"
  case "$step" in
    dashboard)
      # The drop-in directory goes with the unit (#475), the way the Advisor's
      # does one step down. scripts/enable-relay-colocated.sh writes
      # <unit>.service.d/relay-env.conf naming /etc/aperire/aperire.env, and a
      # --wipe takes that file: a directory left standing here is inherited by
      # the NEXT dashboard installed on this host, pointing it at an env file
      # nobody wrote. An install interrupted between its own steps can leave
      # the drop-in with no unit at all, which is why the branch below removes
      # it too.
      for inst in ${DASH_INSTANCES[@]+"${DASH_INSTANCES[@]}"}; do
        stop_disable_remove "aperire-server${inst:+-$inst}" "$UNIT_DIR/aperire-server${inst:+-$inst}.service"
        remove_if_present "$LOGROTATE_DIR/aperire${inst:+-$inst}" \
                          "$UNIT_DIR/aperire-server${inst:+-$inst}.service.d"
      done
      if [[ ${#DASH_INSTANCES[@]} -eq 0 ]]; then
        stop_disable_remove "aperire-server" "$UNIT_DIR/aperire-server.service"
        remove_if_present "$LOGROTATE_DIR/aperire" "$UNIT_DIR/aperire-server.service.d"
      fi
      # The host verifier, installed with the dashboard by
      # install-aperire-service.sh. A timer left enabled here keeps firing
      # against an install that is gone, writing its report into a directory
      # nothing reads, forever. The timer is stopped before the service so a
      # run cannot be started while this is taking the unit away.
      if systemctl list-unit-files aperire-verify.timer --no-legend 2>/dev/null | grep -q aperire-verify.timer; then
        systemctl stop aperire-verify.timer 2>/dev/null || true
        systemctl disable aperire-verify.timer 2>/dev/null || true
        # The oneshot too: the timer can have started a run seconds ago, and
        # a run outliving the unit file it was started from is a verifier
        # writing a report for a host that no longer has a dashboard.
        systemctl stop aperire-verify.service 2>/dev/null || true
        echo "  → stopped + disabled aperire-verify.timer"
      fi
      clear_failed aperire-verify.timer aperire-verify.service
      remove_if_present "$UNIT_DIR/aperire-verify.timer" "$UNIT_DIR/aperire-verify.service"
      if [[ -f "$REPO_DIR/data/verify-report.json" ]]; then
        rm -f "$REPO_DIR/data/verify-report.json"
        echo "  → removed ${REPO_DIR}/data/verify-report.json (the verifier's own state)"
      fi

      # The update grant. A socket left listening after the dashboard is gone
      # would answer the NEXT dashboard installed here, and the program behind
      # it rewrites a tree in /etc/aperire/update.conf that by then may be
      # somebody else's. Removed with the dashboard rather than with the
      # Advisor, because it is the dashboard's grant.
      if systemctl list-unit-files aperire-update.socket --no-legend 2>/dev/null | grep -q aperire-update.socket; then
        systemctl stop aperire-update.socket 2>/dev/null || true
        systemctl disable aperire-update.socket 2>/dev/null || true
        echo "  → stopped + disabled aperire-update.socket"
      fi
      clear_failed aperire-update.socket 'aperire-update@*.service'
      remove_if_present "$UNIT_DIR/aperire-update.socket" "$UNIT_DIR/aperire-update@.service" \
                        "$SBIN_DIR/aperire-update" "$ETC_APERIRE/update.conf" \
                        "$RUN_DIR/update.sock" "$RUN_DIR/update.lock"
      # What that program checks a release against: the release key and the
      # function that checks it, both root-owned beside the image recipe, and
      # the signed files of every release this host verified. Nothing else
      # reads them, and a key left behind would be trusted by whatever is
      # installed here next.
      remove_if_present "$ULIB_DIR/aperire/release-verify-lib.sh" "$ULIB_DIR/aperire/release-signers" \
                        "$RELEASE_STORE_DIR"
      # The two libraries the update program's rollback loads (#764). The grant
      # installer puts them here, so they come off with the grant. Left only to
      # the node-wrapper block below, a host that never had a wrapper kept
      # release-digests-lib.sh, and the rmdir after it failed (#903).
      remove_if_present "$ULIB_DIR/aperire/release-digests-lib.sh"
      # trusted-path-lib.sh is the Advisor's too (#987 review, L2): its node
      # wrapper loads this root copy before every verb that makes root run,
      # obey or rewrite a file, and refuses each one without it. So it goes
      # here only when no Advisor stays; the Advisor's step takes it when
      # the Advisor goes.
      if [[ $HAS_ADVISOR -eq 0 ]] || in_steps advisor; then
        remove_if_present "$ULIB_DIR/aperire/trusted-path-lib.sh"
      elif have "$ULIB_DIR/aperire/trusted-path-lib.sh"; then
        echo "  → kept ${ULIB_DIR}/aperire/trusted-path-lib.sh for the Advisor's node wrapper, which checks with it"
      fi
      rmdir "$ULIB_DIR/aperire" 2>/dev/null || true

      # The fleet broker grant (#804), on an aggregator. Left listening, the
      # socket keeps a root program reachable by an account whose dashboard
      # is gone, and the next install on this host refuses on its units.
      # The socket goes first, so nothing can start a new broker while the
      # rest comes off; then any broker it already started, by the template's
      # own name, which matches only its instances; then the files.
      # What is true before the stop, so the line printed after it says what
      # this run actually changed rather than what it asked for.
      _fb_active="$(systemctl is-active aperire-fleet-broker.socket 2>/dev/null || true)"
      _fb_enabled="$(systemctl is-enabled aperire-fleet-broker.socket 2>/dev/null || true)"
      if systemctl list-unit-files aperire-fleet-broker.socket --no-legend 2>/dev/null | grep -q aperire-fleet-broker.socket; then
        systemctl stop aperire-fleet-broker.socket 2>/dev/null || true
        systemctl disable aperire-fleet-broker.socket 2>/dev/null || true
        [[ "$_fb_active" == active ]] && echo "  → stopped aperire-fleet-broker.socket"
        [[ "$_fb_enabled" == enabled ]] && echo "  → disabled aperire-fleet-broker.socket"
        [[ "$_fb_active" != active && "$_fb_enabled" != enabled ]] \
          && echo "  → aperire-fleet-broker.socket was neither running nor enabled"
      fi
      # Whether or not the template is still on disk: after an interrupted
      # run a broker started earlier can outlive its unit file, and while it
      # runs it can write a token file back. The pattern is the template's
      # own name, so it matches its instances and nothing else.
      systemctl stop 'aperire-fleet-broker@*.service' 2>/dev/null || true
      clear_failed aperire-fleet-broker.socket 'aperire-fleet-broker@*.service'
      remove_if_present "$UNIT_DIR/aperire-fleet-broker.socket" "$UNIT_DIR/aperire-fleet-broker@.service" \
                        "$SBIN_DIR/aperire-fleet-broker" "$SBIN_DIR/aperire-fleet-arm" \
                        "$RUN_DIR/fleet-broker.sock"
      # Its configuration, from the lists the plan printed (FLEET_DELETE,
      # FLEET_TOKENS). Only set on a wipe scoped to the dashboard: a whole
      # wipe takes all of /etc/aperire further down, and a keep takes none.
      remove_if_present ${FLEET_DELETE[@]+"${FLEET_DELETE[@]}"}
      if [[ "$FLEET_TOKENS" == delete ]]; then
        remove_if_present "$ETC_APERIRE/fleet-tokens"
      elif [[ "$FLEET_TOKENS" == keep ]]; then
        echo "  → kept ${ETC_APERIRE}/fleet-tokens for the Advisor, which reads them"
      fi
      if [[ $WIPE -ne 1 ]]; then
        for f in "$ETC_APERIRE/fleet-broker.conf" "$ETC_APERIRE/fleet-nodes.conf" \
                 "$ETC_APERIRE/fleet-tokens" "$ETC_APERIRE/fleet-arm.key"; do
          have "$f" && echo "  → kept ${f}"
        done
      fi
      # The hardening guide's two hand-placed pieces (#818). The proxy runs out
      # of this checkout's dashboard/, so it goes with the dashboard, stopped
      # first. The sudo rule names aperire-server, which is gone now.
      stop_disable_remove "aperire-rippled-proxy" "$UNIT_DIR/aperire-rippled-proxy.service"
      remove_sudoers_rule aperire-restart
      remove_dashboard_account
      ;;
    tunnel)
      stop_disable_remove "cloudflared-aperire" "$UNIT_DIR/cloudflared-aperire.service"
      echo "  !! the tunnel itself is still registered with Cloudflare. The unit is"
      echo "     gone, the tunnel is not:  cloudflared tunnel delete aperire"
      ;;
    advisor)
      # The service first, so nothing is running as the account while its
      # sudo rule, its access and the account itself are taken away.
      #
      # The drop-in directory goes with the unit (#451). The sealed model key
      # declares itself in <unit>.service.d/model-credential.conf, so a unit
      # removed without it leaves a directive on the host for a service that
      # is gone, and the next Advisor installed here inherits it. An install
      # interrupted between its own steps can leave the drop-in with no unit
      # at all, which is why the branch below removes it too.
      for inst in ${ADVISORD_UNITS[@]+"${ADVISORD_UNITS[@]}"}; do
        stop_disable_remove "aperire-advisord${inst:+-$inst}" "$UNIT_DIR/aperire-advisord${inst:+-$inst}.service"
        remove_if_present "$UNIT_DIR/aperire-advisord${inst:+-$inst}.service.before-account" \
                          "$UNIT_DIR/aperire-advisord${inst:+-$inst}.service.d"
      done
      if [[ ${#ADVISORD_UNITS[@]} -eq 0 ]]; then
        remove_if_present "$UNIT_DIR/aperire-advisord.service.before-account" \
                          "$UNIT_DIR/aperire-advisord.service.d"
      fi
      # A `.before-account` marker for an instance whose own unit is ALREADY
      # gone before this run is invisible to the loop above: instances_of()
      # only sees units that still exist, so an instance de-installed in an
      # earlier run leaves its marker behind forever, found by
      # scripts/aperire-leftovers.sh and un-removable by any later run of
      # this script (#518). The marker can only be written by
      # install-advisor-account.sh, so glob for it here independent of what
      # this run detected; remove_if_present is a no-op on the ones the
      # loop above already took.
      for f in "$UNIT_DIR"/aperire-advisord*.service.before-account; do
        [[ -e "$f" ]] || continue
        remove_if_present "$f"
      done
      # The copy harden-advisord.sh keeps of the unit it rewrites (#818). That
      # script only ever names the un-suffixed unit, so this is its one name.
      remove_if_present "$UNIT_DIR/aperire-advisord.service.before-hardening"

      # The failure-recovery unit (#541), one per instance, same reasoning as
      # ADVISORD_UNITS above: never enabled, never a socket, but a stray
      # instance whose OWN unit is already gone is still findable by name.
      for inst in ${ADVISORD_UNITS[@]+"${ADVISORD_UNITS[@]}"}; do
        stop_disable_remove "aperire-advisord-credcheck${inst:+-$inst}" \
                            "$UNIT_DIR/aperire-advisord-credcheck${inst:+-$inst}.service"
      done
      if [[ ${#ADVISORD_UNITS[@]} -eq 0 ]]; then
        stop_disable_remove aperire-advisord-credcheck "$UNIT_DIR/aperire-advisord-credcheck.service"
      fi
      for f in "$UNIT_DIR"/aperire-advisord-credcheck*.service; do
        [[ -e "$f" ]] || continue
        remove_if_present "$f"
      done
      # One program for every instance on this host (APERIRE_INSTANCE is an
      # argument to it at runtime, not a suffix on its own path), so it comes
      # off once, here, rather than inside the per-instance loop above.
      remove_if_present "$SBIN_DIR/aperire-advisord-credcheck"
      # The helper both that program and the sealer write advisor/state
      # through (#703) goes with them, not before them: it is a dependency,
      # so leaving it behind would be a root program on a host with nothing
      # left to run it. It is removed further down, after the dashboard's
      # read token is given back, which may run through it.
      # And the library that says how this host keeps a model key (#708).
      # Same rule, same reason: a dependency of the two programs above and of
      # nothing else.
      remove_if_present "$SBIN_DIR/aperire-model-key-method"
      # The Advisor's root socket, every instance's, and the broker behind it
      # (ADR 0025). Stopped first: a socket left listening after its Advisor
      # is gone would answer the account the NEXT Advisor installed here gets.
      for f in "$UNIT_DIR"/aperire-node-wrapper.socket "$UNIT_DIR"/aperire-node-wrapper-*.socket; do
        [[ -e "$f" ]] || continue
        systemctl stop "$(basename "$f")" 2>/dev/null || true
        systemctl disable "$(basename "$f")" 2>/dev/null || true
        echo "  → stopped + disabled $(basename "$f")"
        clear_failed "$(basename "$f")" "$(basename "${f%.socket}")@*.service"
        remove_if_present "$f" "${f%.socket}@.service"
      done
      for f in "$RUN_DIR"/node-wrapper.sock "$RUN_DIR"/node-wrapper-*.sock; do
        [[ -e "$f" ]] && remove_if_present "$f"
      done
      remove_if_present "$SBIN_DIR/aperire-wrapper-broker"
      # The node wrapper that socket runs, every instance's copy, and the two
      # libraries it loads (ADR 0024). A root program left here would be one
      # nothing grants and nothing refreshes.
      for f in "$SBIN_DIR"/aperire-node-wrapper "$SBIN_DIR"/aperire-node-wrapper-*; do
        [[ -e "$f" ]] && remove_if_present "$f"
      done
      remove_if_present "$ULIB_DIR/aperire/config-write-lib.sh"
      # trusted-path-lib.sh is not the Advisor's alone (#982). The dashboard's
      # update grant places it too, and every root run the dashboard half
      # makes checks with it: the Advisor's own bootstrap (Add an Advisor's
      # step 2), the uninstall bootstrap and an update's rollback all refuse
      # without it. So it goes here only when no dashboard stays; the
      # dashboard's step takes it when the dashboard goes.
      if [[ $HAS_DASHBOARD -eq 0 ]] || in_steps dashboard; then
        remove_if_present "$ULIB_DIR/aperire/trusted-path-lib.sh"
      elif have "$ULIB_DIR/aperire/trusted-path-lib.sh"; then
        echo "  → kept ${ULIB_DIR}/aperire/trusted-path-lib.sh for the dashboard, which checks with it"
      fi
      # The start of the Advisor an update remembered while a sudo rule was
      # still in play, one per instance (#780). Left, it keeps the rmdir below
      # from emptying the directory (#903).
      for f in "$ULIB_DIR"/aperire/advisord-sudo-invocation "$ULIB_DIR"/aperire/advisord-sudo-invocation-*; do
        [[ -e "$f" ]] && remove_if_present "$f"
      done
      rmdir "$ULIB_DIR/aperire" 2>/dev/null || true

      # The two root sockets. Each is one program the dashboard may reach, so
      # a socket left listening after its Advisor is gone would answer the
      # NEXT dashboard installed here.
      for sock in aperire-seal-model-key aperire-trust-sync; do
        if systemctl list-unit-files "${sock}.socket" --no-legend 2>/dev/null | grep -q -e "${sock}.socket"; then
          systemctl stop "${sock}.socket" 2>/dev/null || true
          systemctl disable "${sock}.socket" 2>/dev/null || true
          echo "  → stopped + disabled ${sock}.socket"
        fi
        clear_failed "${sock}.socket" "${sock}@*.service"
        remove_if_present "$UNIT_DIR/${sock}.socket" "$UNIT_DIR/${sock}@.service" "$SBIN_DIR/${sock}"
      done
      remove_if_present "$ETC_APERIRE/model-key.arm" \
                        "$RUN_DIR/seal-model-key.sock" "$RUN_DIR/trust-sync.sock"
      # A key an earlier ceremony sealed. install-advisord.sh wires any
      # credential it finds here into the unit it writes, so a key left behind
      # is the next Advisor on this box coming up holding the old one.
      [[ $WIPE -eq 1 ]] && remove_if_present "$ETC_APERIRE/creds"
      # The node wrapper's records under ${VAR_LIB_DIR} (#1005). A verified-
      # image marker is what tells a later run that this host already checked
      # that digest, so a wipe that leaves one hands a future install a check it
      # never made. Root's own directory, root's own files: nothing a service
      # account can write is walked. A keep leaves them and says so; an empty
      # one is not worth keeping.
      for f in "$VERIFIED_IMAGE_DIR" "$PACKAGE_KEEP_DIR"; do
        [[ -e "$f" || -L "$f" ]] || continue
        if [[ $WIPE -eq 1 ]]; then
          remove_if_present "$f"
        elif [[ -d "$f" && ! -L "$f" ]] && rmdir "$f" 2>/dev/null; then
          echo "  → removed ${f}, which was empty"
        elif [[ "$f" == "$VERIFIED_IMAGE_DIR" ]]; then
          echo "  → kept ${f}: the record of each image this host verified. A wipe removes it."
        else
          echo "  → kept ${f}: a package kept for a rollback. A wipe removes it."
        fi
      done
      # The fleet's read tokens, when the dashboard and its broker already
      # went and this is the last half (FLEET_TOKENS, decided before the plan
      # printed). Before the group goes: they are root:aperire-svc, and a
      # file left after it carries a bare gid the next group inherits.
      if [[ "$FLEET_TOKENS" == delete ]] && ! in_steps dashboard; then
        remove_if_present "$ETC_APERIRE/fleet-tokens"
      fi

      # The access control entries, read out of the wrapper's own
      # configuration BEFORE it is removed: CONFIG_FILE is the only record on
      # this host of which node directory carries them. And before the
      # account goes, because once it does the entry is a bare numeric uid
      # and a removal by name stops matching it.
      acl_paths=("$OP_HOME")
      if [[ -f "$ETC_APERIRE/node-wrapper.conf" ]]; then
        cfg="$(awk -F= '$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$ETC_APERIRE/node-wrapper.conf" 2>/dev/null || true)"
        if [[ -n "$cfg" ]]; then
          acl_paths+=("$cfg" "$(dirname "$cfg")" "$(dirname "$(dirname "$cfg")")")
        fi
      else
        echo "  !! ${ETC_APERIRE}/node-wrapper.conf is not here, so the node directory it"
        echo "     named is unknown. Only ${OP_HOME} is checked for a leftover entry:"
        echo "     getfacl <your node dir> | grep ${ADVISOR_ACCOUNT}"  # grep-lint: skip
      fi
      for p in "${acl_paths[@]}"; do drop_acl "$p"; done

      # The sudo rules older releases wrote for the Advisor, one per instance
      # (aperire-advisor, aperire-advisor-<name>). ADR 0025 retired them and
      # nothing writes one now, but an install that predates it may still have
      # one, and it grants root to an account name a reinstall makes again
      # (#1025). Each is removed only when it is exactly what an older release
      # wrote (retired_advisor_rule); any other file under those names is left
      # where it is, and named.
      for f in "$SUDOERS_DIR/$ADVISOR_ACCOUNT" "$SUDOERS_DIR/$ADVISOR_ACCOUNT"-*; do
        [[ -e "$f" || -L "$f" ]] || continue
        if retired_advisor_rule "$f"; then
          remove_sudoers_rule "$(basename "$f")"
        else
          echo "  !! left ${f} in place: it is not the rule an older release wrote, so it is"
          echo "     somebody's own. Read it, and remove it yourself if nothing needs it."
        fi
      done
      # And the model-key sealer's, from before it had a socket (#818). Its
      # installer removes it on a rerun; a host that never reran still has it.
      remove_sudoers_rule aperire-model-key

      hand_back_advisor_files
      # And what it kept in /etc/aperire, before the account and its own group
      # go (#824).
      if [[ $HANDBACK_KEEP_ACCOUNT -eq 0 ]] && ! release_kept_etc_ids "$ADVISOR_ACCOUNT"; then
        HANDBACK_KEEP_ACCOUNT=1
      fi
      if [[ $HANDBACK_KEEP_ACCOUNT -eq 1 ]]; then
        echo "  !! kept the '${ADVISOR_ACCOUNT}' account, for the files named above"
      else
        remove_account "$ADVISOR_ACCOUNT"
      fi
      # Asked again now, after this step's own removals, for the plan's answer.
      SVC_KEPT=()
      while IFS= read -r line; do [[ -n "$line" ]] && SVC_KEPT+=("$line"); done < <(svc_kept_in_etc)
      if [[ $HANDBACK_KEEP_GROUP -eq 1 ]] && getent group "$SHARED_GROUP" >/dev/null 2>&1; then
        echo "  !! kept the '${SHARED_GROUP}' group, for the files named above"
        strip_kept_shared_group
      elif [[ ${#SVC_KEPT[@]} -gt 0 ]]; then
        echo "  → kept the '${SHARED_GROUP}' group: ${#SVC_KEPT[@]} file(s) kept in ${ETC_APERIRE} are on it,"
        for f in "${SVC_KEPT[@]:0:5}"; do echo "      ${f}"; done
        [[ ${#SVC_KEPT[@]} -gt 5 ]] && echo "      and $(( ${#SVC_KEPT[@]} - 5 )) more"
        echo "    so its id is not freed for another group to inherit. A later install reads them"
        echo "    through it again, and a wipe removes it."
        strip_kept_shared_group
      elif getent group "$SHARED_GROUP" >/dev/null 2>&1; then
        groupdel "$SHARED_GROUP" 2>/dev/null || true
        if getent group "$SHARED_GROUP" >/dev/null 2>&1; then
          echo "  !! the '${SHARED_GROUP}' group is still here; it is somebody's primary group."
        else
          echo "  → removed the '${SHARED_GROUP}' group, and with it every membership in it"
        fi
      fi
      # Root's own copy of the helper goes after the hand-back, which may have
      # run through it when this program runs alone with nothing staged
      # beside it. Kept while the hand-back kept the account: the run that
      # finishes it needs the helper again, and without it would only refuse.
      if [[ $HANDBACK_KEEP_ACCOUNT -eq 1 ]]; then
        have "$SBIN_DIR/aperire-state-file" \
          && echo "  → kept ${SBIN_DIR}/aperire-state-file for the run that finishes the hand-back"
      else
        remove_if_present "$SBIN_DIR/aperire-state-file"
      fi

      # Built here, from sources that are here. Never operator data.
      remove_if_present "$REPO_DIR/advisor/bin"
      if [[ $WIPE -eq 1 ]]; then
        if [[ -f "$ETC_APERIRE/node-config-perms.before" ]]; then
          echo "  !! ${ETC_APERIRE}/node-config-perms.before recorded your node config's"
          echo "     modes BEFORE they were closed to the Advisor. Those modes are"
          echo "     unchanged; the record of what they were is about to go."
        fi
        remove_if_present "$ETC_APERIRE/node-wrapper.conf" "$ETC_APERIRE/node-config-perms.before"
        # read.token is the dashboard's read surface, written by the dashboard
        # install and not by the Advisor. On a scoped run the dashboard is
        # still here and still reading it, so it is the one thing in this
        # directory that stays.
        if [[ -d "$REPO_DIR/advisor/state" ]]; then
          find "$REPO_DIR/advisor/state" -mindepth 1 ! -name read.token -exec rm -rf {} + 2>/dev/null || true
          echo "  → emptied ${REPO_DIR}/advisor/state, except read.token (the dashboard's, not the Advisor's)"
        fi
        remove_if_present "$REPO_DIR/advisor/evidence"
      else
        echo "  → kept ${ETC_APERIRE}/node-wrapper.conf, node-config-perms.before,"
        echo "    ${REPO_DIR}/advisor/state and advisor/evidence"
      fi
      ;;
    relay)
      for inst in ${RELAY_INSTANCES[@]+"${RELAY_INSTANCES[@]}"}; do
        stop_disable_remove "aperire-relay${inst:+-$inst}" "$UNIT_DIR/aperire-relay${inst:+-$inst}.service"
      done
      if [[ ${#RELAY_INSTANCES[@]} -eq 0 ]]; then
        stop_disable_remove "aperire-relay" "$UNIT_DIR/aperire-relay.service"
      fi
      remove_if_present "$UBIN_DIR/aperire-relay"
      # relay.conf is root:aperire-relay, and userdel takes that group with
      # the account (#824).
      if release_kept_etc_ids "$RELAY_ACCOUNT"; then
        remove_account "$RELAY_ACCOUNT"
      else
        echo "  → kept the '${RELAY_ACCOUNT}' account, for the files named above"
      fi
      # The signed releases this host verified. Every install from a
      # published release keeps them, a relay-only box included, and the
      # dashboard's branch takes them when it runs. A relay box has no
      # dashboard branch, so this one does, unless a dashboard is staying here
      # and still reads them.
      if [[ $HAS_DASHBOARD -eq 0 || " ${STEPS[*]} " == *" dashboard "* ]]; then
        remove_if_present "$RELEASE_STORE_DIR"
      fi
      ;;
    rotation)
      # The timer is what prunes a node running advisory_delete=1. Removing it
      # without saying so leaves a node that quietly grows until its disk is
      # full, which is a worse ending than the bug it was installed for.
      if systemctl list-unit-files aperire-can-delete.timer --no-legend 2>/dev/null | grep -q aperire-can-delete.timer; then
        systemctl stop aperire-can-delete.timer 2>/dev/null || true
        systemctl disable aperire-can-delete.timer 2>/dev/null || true
        echo "  → stopped + disabled aperire-can-delete.timer"
      fi
      clear_failed aperire-can-delete.timer aperire-can-delete.service
      remove_if_present "$UNIT_DIR/aperire-can-delete.timer" "$UNIT_DIR/aperire-can-delete.service" \
                        "$ULIB_DIR/aperire/aperire-can-delete.sh"
      rmdir "$ULIB_DIR/aperire" 2>/dev/null || true
      echo "  !! advisory_delete=1 may still be set in your node config. Nothing"
      echo "     prunes the ledger store now. Remove that line and restart the"
      echo "     node, or reinstall the timer."
      ;;
    imagerecipe)
      # Files, not a unit: nothing is running to stop. The recipe's own
      # subdirectory is removed whole rather than by naming each file in it:
      # install-xrpld-image-recipe.sh copies scripts/xrpld-image/ as a tree,
      # and a hand-kept list here would drift from that tree the same way it
      # already has once (#730 - signed-binary-sha256.sh, added by #696, was
      # never added to this list). A file added to the recipe from now on
      # needs no matching row here, because there is no row to add: the whole
      # directory the installer owns comes off. $ULIB_DIR/aperire itself goes
      # only if it is empty afterwards, because the rotation timer's own
      # program lives beside it and may be staying.
      remove_if_present "$ULIB_DIR/aperire/build-xrpld-image.sh" \
                        "$ULIB_DIR/aperire/xrpld-image"
      rmdir "$ULIB_DIR/aperire" 2>/dev/null || true
      # The images themselves are deliberately left. They are what a node
      # runs, this script does not stop containers, and removing an image out
      # from under a running one is not something an uninstaller should do
      # without being asked.
      echo "  !! any locally built xrpld images (localhost/xrpld:*) are still here."
      echo "     Remove them when nothing runs them:  docker image rm localhost/xrpld:<version>"
      ;;
    cli)
      # Every aperire* link, not the two this install happens to make today.
      # A third one added later and left behind is a command on PATH that
      # says nothing about having been uninstalled.
      if [[ ${#CLI_LINKS[@]} -eq 0 ]]; then
        echo "  → no operator CLI links under ${OP_HOME}/.local/bin (skipped)"
      else
        remove_if_present ${CLI_LINKS[@]+"${CLI_LINKS[@]}"}
      fi
      ;;
    goprofile)
      # Ours, and named for us, so it goes on a wipe whether or not the Go it
      # points at does. The closing text says so when Go is staying.
      if [[ $WIPE -eq 1 ]]; then
        remove_if_present "$PROFILE_DIR/aperire-go.sh"
        GO_PROFILE_REMOVED=1
      else
        echo "  → kept ${PROFILE_DIR}/aperire-go.sh, the login PATH line for ${GO_DIR}/bin"
      fi
      ;;
  esac
done

# The Advisor's sockets named the account while the dashboard step ran, if it
# did (#905), and an earlier dashboard-scoped run may have kept the account for
# the same reason (#907). Its units are gone now, so ask again. It returns at
# once when the account is already gone and keeps it while any unit still names
# it, so a dashboard that stays here keeps its account.
if in_steps advisor; then
  remove_dashboard_account final
fi

# ── daemon-reload after unit removals ───────────────────────────────
if [[ $CLI_ONLY -ne 1 ]]; then
  systemctl daemon-reload
  echo
  echo "  → systemctl daemon-reload"
fi

# ── The release digests (ADR 0024) ──────────────────────────────────
# The record every root copy out of the checkout was checked against. It
# belongs to the install as a whole, so it goes when the whole install does,
# and stays when only one half of a box was taken off: the other half's
# installers still check against it.
if [[ $CLI_ONLY -ne 1 && $ROLE_SCOPED -eq 0 ]]; then
  # .previous is the rollback pointer an update writes (#764); left out of
  # this list, every host updated since then kept it after a wipe (#918).
  if [[ -e "$ULIB_DIR/aperire/release.sha256" || -e "$ULIB_DIR/aperire/release.sha256.kept" \
        || -e "$ULIB_DIR/aperire/release.sha256.previous" || -e "$ULIB_DIR/aperire/digests-required" ]]; then
    rm -rf "$ULIB_DIR/aperire/release.sha256" "$ULIB_DIR/aperire/release.sha256.kept" \
           "$ULIB_DIR/aperire/release.sha256.previous" "$ULIB_DIR/aperire/digests-required"
    echo "  → removed the release digests (${ULIB_DIR}/aperire/release.sha256 and the ones kept for rollback)"
  fi
  # Only ever an empty one: whatever else is still in it stays.
  rmdir "$ULIB_DIR/aperire" 2>/dev/null || true
fi
# ${VAR_LIB_DIR} itself, once nothing is left in it (#1005), on either ending.
# Not while an Advisor stays: the advisord unit names it in ReadWritePaths=,
# and a unit naming a directory that is gone does not start.
if [[ $CLI_ONLY -ne 1 && -d "$VAR_LIB_DIR" && ! -L "$VAR_LIB_DIR" ]] \
   && { [[ $HAS_ADVISOR -eq 0 ]] || in_steps advisor; }; then
  if rmdir "$VAR_LIB_DIR" 2>/dev/null; then echo "  → removed ${VAR_LIB_DIR}, now empty"; fi
fi

# ── The ending that was chosen ──────────────────────────────────────
echo
echo "═══ ${ANSWER} ═══"

if [[ $RM_CONFIG -eq 1 && -d "$ETC_APERIRE" ]]; then
  rm -rf "$ETC_APERIRE"
  echo "  → DELETED ${ETC_APERIRE}/"
fi
if [[ $RM_DATA -eq 1 && -d "$REPO_DIR/data" ]]; then
  rm -rf "$REPO_DIR/data"
  echo "  → DELETED ${REPO_DIR}/data/"
fi
if [[ $RM_TOOLCHAIN -eq 1 ]]; then
  # The Go module cache write-protects its own files, so a plain rm as the
  # operator leaves it behind. This runs as root, which is the whole reason
  # the flag exists rather than a line in the closing text.
  remove_if_present "$GO_DIR" "$OP_HOME/.nvm" "$OP_HOME/.npm" "$OP_HOME/go"
fi

# The update snapshots go with the checkout they were made from, and are
# listed as they go. Names were matched on the updater's own naming and are
# removed from a pinned parent (remove_pinned).
if [[ $RM_CHECKOUT -eq 1 && $SNAP_PROVEN -eq 1 && ${#SNAPS[@]} -gt 0 ]]; then
  remove_pinned "$SNAP_PARENT" "$SNAP_PARENT_ID" "${SNAPS[@]}" || true
fi

# Last, and only ever the directory a unit named. Everything above reads out
# of the checkout, so it has to still be here until now.
if [[ $RM_CHECKOUT -eq 1 ]]; then
  if [[ -n "$CHECKOUT" && -d "$CHECKOUT" ]]; then
    cd /
    remove_pinned "$(dirname "$CHECKOUT")" "$CHECKOUT_PARENT_ID" "$(basename "$CHECKOUT")" || true
  else
    echo "  !! the checkout at ${REPO_DIR} was NOT removed."
    echo "     No dashboard unit on this host named it, and this is not a directory"
    echo "     to take on a resemblance. Remove it yourself when you are sure:"
    echo "     rm -rf ${REPO_DIR}"
    if [[ ${#SNAPS[@]} -gt 0 ]]; then
      echo
      echo "     Not removed either, for the same reason:"
      print_snapshot_remedy "     "
    fi
  fi
fi

# ── What is left, and why ───────────────────────────────────────────
echo
echo "  ───── uninstall complete ─────"
echo
echo "  Still here, untouched:"
echo "    • your node: the container, its configuration and its ledger store."
echo "      Nothing here reads or writes them."
echo "    • docker itself."
if [[ $RM_TOOLCHAIN -ne 1 ]]; then
  if [[ -d "$GO_DIR" || -d "$OP_HOME/.nvm" ]]; then
    echo "    • Go and node. Pass --wipe --toolchain to remove those as well."
    if [[ $GO_PROFILE_REMOVED -eq 1 ]]; then
      echo "      The login PATH line this install added is gone with the rest of its"
      echo "      configuration, so put ${GO_DIR}/bin on your own PATH if you use Go"
      echo "      for something else."
    fi
  fi
fi
if [[ $RM_CONFIG -ne 1 && -d "$ETC_APERIRE" ]]; then
  echo "    • ${ETC_APERIRE}/, the relay token, authn.yaml and relay.conf. A"
  echo "      re-install reuses them, so no new relay token is minted."
  # An aggregator's fleet model store, kept with the rest of /etc/aperire and
  # named, because it is every node's provider key (#711). On a host with no
  # systemd-creds it is that key in the clear, and so is a temporary a seal
  # left behind if it was cut off between writing and renaming.
  for _fm in "$ETC_APERIRE/fleet-model.cred" "$ETC_APERIRE/fleet-model.cred.plain" \
             "$ETC_APERIRE"/.dirsafe.*; do
    [[ -e "$_fm" || -L "$_fm" ]] || continue
    case "$_fm" in
      */.dirsafe.*) echo "    • ${_fm}, a temporary a root write left when it was cut off; it may hold a key." ;;
      *.plain)      echo "    • ${_fm}, the fleet model with every node's key in the clear." ;;
      *)            echo "    • ${_fm}, the fleet model, sealed to this machine." ;;
    esac
    echo "      If this host is done being an aggregator: sudo rm -f ${_fm}"
  done
fi
if [[ $RM_DATA -ne 1 && -d "$REPO_DIR/data" ]]; then
  echo "    • ${REPO_DIR}/data/, the database. Your operators, their passkeys,"
  echo "      the alert state and the history are in it."
fi
if [[ $RM_CHECKOUT -ne 1 && -d "$REPO_DIR" ]]; then
  echo "    • ${REPO_DIR}/, this checkout."
fi
if [[ $RM_CHECKOUT -ne 1 && ${#SNAPS[@]} -gt 0 ]]; then
  echo "    • $(print_snapshot_remedy "      " | sed '1s/^ *//')"
  # True only when this run took the dashboard unit: a scoped run that kept
  # it leaves a later --wipe able to prove the checkout and take these.
  if ! compgen -G "$UNIT_DIR/aperire-server*.service" >/dev/null; then
    echo "      A later --wipe cannot find these now that this run has removed the dashboard"
    echo "      unit, so that command is the way."
  fi
fi
echo
echo "  To install it again:"
echo
echo "      curl -fsSL https://get.aperire.one | bash"
echo
# A kept host is reinstalled with the one-liner, and the one-liner puts back the
# dashboard and, where it finds a node, the relay. It does not put back the
# Advisor or the pairing grant, and on a host with no node it does not put back
# the relay either (#1181). Said here, with the command for each, because the
# evidence is on this screen now and the host will not say it afterwards.
if [[ $RM_CONFIG -ne 1 ]] \
   && [[ $KEEP_NAMES_RELAY -eq 1 || $KEEP_NAMES_ADVISOR -eq 1 || $KEEP_NAMES_GRANT -eq 1 ]]; then
  echo "  That install brings back the dashboard, with your database, passkeys and config."
  echo "  This run also took off the following, and that install does not bring"
  echo "  them back by itself:"
  echo
  if [[ $KEEP_NAMES_RELAY -eq 1 ]]; then
    # The port is read from the service environment a keep leaves behind. A host
    # that will not show it is given a placeholder rather than a guess.
    _relay_port="$(sed -n 's/^PORT=//p' "$ETC_APERIRE/aperire.env" 2>/dev/null | tail -1 | tr -d "\"' " || true)"
    [[ "$_relay_port" =~ ^[0-9]+$ ]] || _relay_port="<the dashboard's port>"
    echo "    • the relay. The install adds it only when it finds a node running on this"
    echo "      host. A host with no node (an aggregator reporting its own metrics) gets"
    echo "      none, and ${ETC_APERIRE}/relay.conf stays where it is. Once the install is done,"
    echo "      build the relay and wire it beside the dashboard:"
    echo "          curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run prepare-host --role co-located"
    echo "          curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run relay-colocated --unit aperire-server --port ${_relay_port} --binary ${REPO_DIR}/relay/aperire-relay"
  fi
  if [[ $KEEP_NAMES_ADVISOR -eq 1 ]]; then
    echo "    • the Advisor, which is always its own install:"
    echo "          curl -fsSL https://get.aperire.one/advisor | bash"
  fi
  if [[ $KEEP_NAMES_GRANT -eq 1 ]]; then
    echo "    • the pairing grant, which lets this host pair nodes. Its keys stay in"
    echo "      ${ETC_APERIRE}, and putting the grant back reuses them:"
    echo "          curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run fleet-broker-grant"
  fi
  echo
  echo "  The install says again, when it finishes, which of these it did bring back."
  echo
fi
if [[ $RM_CONFIG -eq 1 && $RM_DATA -eq 1 && $RM_CHECKOUT -eq 1 ]]; then
  if [[ ! -e "$REPO_DIR" ]]; then
    echo "  To read back that nothing of ours is left, from any copy of the"
    echo "  release (this checkout is gone):"
    echo
    echo "      bash scripts/aperire-leftovers.sh"
  elif [[ -f "$REPO_DIR/scripts/aperire-leftovers.sh" ]]; then
    echo "  To read back that nothing of ours is left:"
    echo
    echo "      bash ${REPO_DIR}/scripts/aperire-leftovers.sh"
  else
    echo "  To read back that nothing of ours is left, from any copy of the"
    echo "  release:"
    echo
    echo "      bash scripts/aperire-leftovers.sh"
  fi
  # Run as the login, as above, it cannot list /etc/sudoers.d on Ubuntu, and
  # it says so rather than calling the host clean (#1034).
  echo
  echo "  As you, it can't read ${SUDOERS_DIR}. It says so on a \"not checked\""
  echo "  line with the command that reads it, and exits 3 rather than 0."
  echo
fi

# The last line, and it is load-bearing outside this file. This script is
# fetched over the network by scripts/get-aperire-uninstall.sh when the copy on
# a host predates the keep/wipe question, and what that bootstrap checks before
# it installs anything is that this line arrived. A flat script cut in the
# middle runs its top half, and the top half of this one removes things.
# --- end of uninstall.sh ---
