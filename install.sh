#!/bin/bash
# install.sh, Aperire top-level installer.
#
# Thin orchestrator over the role-specific scripts in scripts/. Pick the
# role for THIS host and the orchestrator runs the right sub-installers
# in the right order.
#
# Roles:
#   --role=dashboard    Dashboard host. Installs aperire-server systemd
#                       unit + operator CLI. Add --with-tunnel for
#                       cloudflared-aperire.
#   --role=validator    Validator host (Shape B / split). Installs the
#                       aperire-relay binary + systemd unit only, enabled
#                       and running, standing by until you tell it which
#                       dashboard collects from this host. Auto-detects the
#                       binary at relay/aperire-relay (built in-tree); pass
#                       --relay-binary=PATH to override.
#   --role=co-located   Shape A. Dashboard + relay on the same host.
#                       Same flags as dashboard + validator combined.
#   --role=cli-only     Just the operator CLI to ~/.local/bin. No sudo
#                       required. Useful on an operator workstation that
#                       talks to a remote dashboard host over SSH.
#
# Common flags:
#   --with-tunnel       Also install + start the cloudflared-aperire
#                       systemd unit. Skipped by default, many installs
#                       (either shape) reach the dashboard over LAN
#                       only.
#   --with-advisor      Also install the Advisor, through the same script the
#                       one-line install runs (scripts/install-advisor-stack.sh):
#                       the advisord service, the privilege wrapper configured
#                       from this host's own deployment, the two root grants the
#                       browser needs for the model step and for handing it an
#                       enrolled passkey, a dedicated account, and the Advisor's
#                       own copy of who may approve. Optional; monitoring works
#                       fully without it.
#   --advisor-shared-account
#                       Retired (ADR 0025). Accepted, says so, and changes
#                       nothing: the Advisor always gets its own account now,
#                       on Ubuntu 22.04 as on 24.04, and reaches the node only
#                       through a root socket.
#   --fleet-aggregator=URL
#                       Join this host to a fleet at the end of the install.
#                       URL is the aggregator's origin, https://<host> (or
#                       http:// to loopback). Dashboard and co-located roles
#                       only. The last step waits for this node to report its
#                       own key, asks you for a pairing code on the terminal,
#                       and runs scripts/aperire-fleet-pair.sh. Pairing never
#                       fails the install: a host that could not pair is
#                       installed, enabled and running, and the closing text
#                       prints the one line that pairs it later.
#   --fleet-code=CODE   The pairing code, for a host that is already built and
#                       is being re-run. Skips the prompt, and costs three
#                       things. A code on a command line is in
#                       /proc/<pid>/cmdline while this runs, in your shell
#                       history afterwards, and, when this was reached through
#                       sudo, in /var/log/auth.log, which keeps it for weeks
#                       and is readable by the adm group. A code is live for
#                       fifteen minutes, so the last one is the window that
#                       matters. Leave the flag out and the install asks for
#                       the code at the end, on the terminal, where it is in
#                       none of the three. Needs --fleet-aggregator. The
#                       one-liner does not take it at all, for the same reason:
#                       that layer adds a sudo hop.
#   --fleet-label=LABEL The name to propose for this node, [a-z0-9-]{1,32}.
#                       Defaults to this host's short name. The aggregator
#                       settles it and you may rename before approving.
#                       Needs --fleet-aggregator.
#   --relay-binary=PATH Path to the prebuilt aperire-relay binary
#                       (validator + co-located roles). Auto-detected if
#                       not passed.
#   --instance=NAME     Run more than one dashboard on this host, one per
#                       node (ADR 0009). NAME suffixes the unit names, the
#                       env and relay config files, and the database, so a
#                       second install collides with nothing. Give each
#                       instance its own checkout, its data, Advisor state
#                       and config live inside the repository directory.
#                       Omit for the ordinary single-node layout.
#   --port=N            Dashboard listen port (default 7800). Required for a
#                       second instance, which would otherwise fail to bind.
#   --advisor-port=N    Advisor listen port (default 7810). Same reason.
#   --no-preflight      Skip the step-zero preflight. By default the installer
#                       measures what this host has before it changes anything
#                       (OS, systemd, sudo, disk, memory, the ports, egress,
#                       the clock, the tools, and the node) and refuses on a
#                       missing prerequisite rather than failing minutes into
#                       a build. Skip it for lab and reset tooling that has
#                       already checked, or when the bootstrap ran it.
#   --no-prepare        Skip scripts/prepare-host.sh. By default the installer
#                       first puts the toolchain in place (apt build deps,
#                       Node 22 via nvm, npm ci, Go 1.23) and builds the relay
#                       and Advisor binaries, so a fresh host needs nothing but
#                       git and this checkout. Skip it when you manage the
#                       toolchain yourself or the host is offline.
#   --quiet-existing    This host is already set up: say what changed and skip
#                       the first-install guidance and the advisories it was
#                       given at install time (the authn.yaml warning, "create
#                       your first operator", the ufw notes, the PATH warning).
#                       What every step READ BACK is still printed: a reading is
#                       earned on the run that takes it. This is what an update
#                       passes; it also exports APERIRE_UPDATE=1, because the
#                       sub-installers are run on their own too.
#   --no-restart        Do everything, and start or restart nothing. The unit
#                       files are written and daemon-reload runs, so the new
#                       text is on disk; the processes carry on running the
#                       code they started with until somebody restarts them.
#                       This is what an update uses: a swap that restarted the
#                       dashboard by itself would be the silent restart the
#                       operator ruled out. Every read-back below says so
#                       rather than attesting a process this run never touched.
#   --yes               Don't prompt for confirmation before running.
#
# Examples:
#   sudo bash install.sh --role=dashboard --with-tunnel
#   sudo bash install.sh --role=validator
#   sudo bash install.sh --role=co-located --with-tunnel --with-advisor
#   bash install.sh --role=cli-only
#
#   # Install, then join the fleet at the end. It asks for the code itself:
#   sudo bash install.sh --role=co-located --with-advisor \
#        --fleet-aggregator=https://aggregator.example
#
#   # A second node on the same host, from its own checkout:
#   sudo bash install.sh --role=co-located --instance=node2 \
#        --port=7900 --advisor-port=7910 --with-advisor
#
# Idempotent, safe to re-run after `git pull` or an upgrade.
#
# Exit codes: 0 done, 1 a step failed, 2 run the wrong way (flags, role, no
# root), 3 everything installed and the Advisor answering, but its move onto
# its own account refused, so it still runs on the dashboard's account, which
# is not a supported end state. The closing text names the command that
# finishes it. 4 every step ran, and root refused to copy one or more files
# out of the tree because they are not the release's or a service account
# can change them (#764); the closing text lists each one, and root kept the
# copy it already had.
#
# Two environment variables exist for the tests and for automation, and are
# not meant to be set by hand: APERIRE_RELAY_PUSH_TRIES and
# APERIRE_RELAY_PUSH_SLEEP bound how long the closing summary waits for the
# dashboard to report a push from the relay before it says there is not one.

set -euo pipefail

# Two directories, which are one on a run from the checkout (#764):
#
#   SCRIPTS_DIR   where the code this run executes and sources lives
#   REPO_DIR      the install tree it acts on: builds, units, the dashboard
#
# get-aperire.sh and the rollback run a copy root staged out of the release,
# each file read once and held to the release's digests and the trusted-path
# check, in a directory only root can write. They name the tree with
# APERIRE_INSTALL_TREE, and it is exported below, so every installer this
# runs acts on that tree and runs its own staged siblings, never the tree's
# bytes. TREE_SCRIPTS is the tree's own scripts/, for the commands printed
# for an operator to type and for the steps run as the operator.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SELF_DIR}/scripts"
REPO_DIR="${APERIRE_INSTALL_TREE:-$SELF_DIR}"
if [[ "$REPO_DIR" != /* || ! -d "$REPO_DIR" || ! -f "$REPO_DIR/install.sh" ]]; then
  echo "error: APERIRE_INSTALL_TREE=$REPO_DIR is not an install tree (an absolute directory with install.sh in it)" >&2
  exit 2
fi
REPO_DIR="$(cd "$REPO_DIR" && pwd)"
export APERIRE_INSTALL_TREE="$REPO_DIR"
TREE_SCRIPTS="${REPO_DIR}/scripts"
ETC_APERIRE=/etc/aperire

# ── Run by hand as root, from the checkout: stage first (#955) ──────
# `sudo bash install.sh` from a clone is root running this one file, which the
# operator chose by typing it. Everything else it runs (every installer, the
# preflight, the pair command) it would run out of the same checkout, and the
# checkout belongs to the login that cloned it. So before it runs or sources
# any of them, it stages them the way the bootstrap does: each file under
# scripts/ read once and held to the release's digests where this host has a
# record, and to the trusted-path check (no service account can change it),
# into a directory only root can write. Then the staged install.sh runs, told
# this tree with APERIRE_INSTALL_TREE, and the stage is removed afterwards.
#
# Told apart by real paths, not by a variable: a staged copy sits somewhere
# other than the tree it is told about, and a run from the tree does not.
#
# The two libraries that do the staging are root's own copies when this host
# has them (the update places them in /usr/local/lib/aperire, root's alone),
# so the check comes from outside the tree it judges. A host without them (a
# first install from a clone) loads the checkout's, held to the file the
# operator ran: neither may be a link, and neither, nor the scripts/
# directory, may be owned by another account or writable by anyone install.sh
# itself is not writable by. Root trusts them exactly as far as it trusts
# install.sh, and the staging then checks them with everything else.
INSTALL_ROOT_LIB_DIR=/usr/local/lib/aperire
install_root_owned() { # $1 = a path; root's, and nobody else can write it
  local meta
  [[ -e "$1" && ! -L "$1" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$1" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == 0 ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}
install_no_easier_to_change() { # $1 = a path, $2 = the reference path
  local f="$1" ref="$2" fm refm
  [[ -e "$f" && ! -L "$f" ]] || return 1
  [[ "$(stat -c '%u:%g' -- "$f")" == "$(stat -c '%u:%g' -- "$ref")" ]] || return 1
  fm=$((8#$(stat -c '%a' -- "$f"))); refm=$((8#$(stat -c '%a' -- "$ref")))
  (( (fm & 8#022 & ~refm) == 0 ))
}
install_stage_self() { # the arguments this run was given
  local held lib rc=0 rdlib="$SCRIPTS_DIR/release-digests-lib.sh"
  if install_root_owned "$INSTALL_ROOT_LIB_DIR" \
     && install_root_owned "$INSTALL_ROOT_LIB_DIR/release-digests-lib.sh" \
     && install_root_owned "$INSTALL_ROOT_LIB_DIR/trusted-path-lib.sh"; then
    rdlib="$INSTALL_ROOT_LIB_DIR/release-digests-lib.sh"
  fi
  [[ "$rdlib" == "$INSTALL_ROOT_LIB_DIR/"* ]] || for lib in release-digests-lib.sh trusted-path-lib.sh; do
    if ! install_no_easier_to_change "$SCRIPTS_DIR/$lib" "$SELF_DIR"/install.sh \
       || ! install_no_easier_to_change "$SCRIPTS_DIR" "$SELF_DIR"; then
      echo "error: root would load $SCRIPTS_DIR/$lib to check what it runs out of this checkout," >&2
      echo "       and it is a link, owned by another account, or writable by someone who cannot" >&2
      echo "       change install.sh. Nothing was run. Put its owner and mode back to match" >&2
      echo "       install.sh, or install through the bootstrap, which brings its own check:" >&2
      echo "           curl -fsSL https://get.aperire.one | bash -s -- --role=<role>" >&2
      exit 1
    fi
  done
  # It loads trusted-path-lib.sh from beside itself.
  # shellcheck source=scripts/release-digests-lib.sh
  . "$rdlib"
  # python3, asked once and before anything is staged (#1279). Every file the
  # stage copies goes through a check that runs in it, at /usr/bin or /bin and
  # never off a PATH, so a host without it would refuse each file on its own
  # and name python3 once per file. Same two paths, same sentence the
  # bootstrap uses (#1193).
  if declare -F _tp_python >/dev/null && ! _tp_python >/dev/null; then
    echo "error: this install needs python3, and this host has none at /usr/bin or /bin: the check on every file root runs out of $REPO_DIR runs in it. Nothing was staged or installed. Install it, then run this again: sudo apt-get install -y python3" >&2
    exit 1
  fi
  held="$(mktemp -d -t aperire-install.XXXXXXXX)" || { echo "error: could not make a directory to stage the installers in. Nothing was run." >&2; exit 1; }
  # shellcheck disable=SC2064  # the path is fixed now, on purpose
  trap "rm -rf -- '$held'" EXIT
  chmod 0700 "$held"
  mkdir -m 0755 "$held/run"
  echo "Staging the installers root runs out of $REPO_DIR, each checked, before running any."
  if ! rd_stage_tree "$REPO_DIR" "$held/run"; then
    echo "error: root would not run the installers in $REPO_DIR (the refusals above name each file and why), so nothing was installed." >&2
    exit 1
  fi
  bash "$held/run/install.sh" "$@" || rc=$?
  exit "$rc"
}
if [[ $EUID -eq 0 && "$(cd "$SELF_DIR" && pwd -P)" == "$(cd "$REPO_DIR" && pwd -P)" ]]; then
  install_stage_self "$@"
fi

# The palette the install path shares, so "done", "degraded" and "refused"
# look the same wherever they are printed. Every string in it is empty unless
# the stream is a terminal, so a captured or piped run stays byte-plain.
[[ -r "${SCRIPTS_DIR}/term-style.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${SCRIPTS_DIR}/term-style.sh"

# The rule for which aggregator origin a node may carry its tokens to, shared
# with scripts/aperire-fleet-pair.sh so there is one copy of it. Refused by
# name for the same reason the palette is: a checkout missing it is missing a
# file, not a host to guess the rule on.
[[ -r "${SCRIPTS_DIR}/fleet-origin.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/fleet-origin.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/fleet-origin.sh
. "${SCRIPTS_DIR}/fleet-origin.sh"

# The one reader of authn.yaml's values, shared with scripts/aperire-setup.sh
# and scripts/aperire-fleet-pair.sh so a public_url written as a list is read
# the same way by all three (#1358). Refused by name, like the files above.
[[ -r "${SCRIPTS_DIR}/authn-value.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/authn-value.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/authn-value.sh
. "${SCRIPTS_DIR}/authn-value.sh"

# Is there a terminal to ask a question on? Opened for real rather than tested
# with -r: /dev/tty is mode 0666, so -r says yes on a host with no controlling
# terminal at all and the redirection then fails. Not `[ -t 0 ]` either, which
# answers a different question: stdin is where a piped code arrives, the
# terminal is where the questions are asked.
tty_available() { ( : < /dev/tty ) 2>/dev/null; }

# Everything temporary this run makes, removed on the way out however the run
# ends: the preflight's answer file, and the fleet step's report and its
# capture of what the pair command printed. One trap, because a second `trap
# ... EXIT` replaces the first rather than adding to it.
PREFLIGHT_ANSWER=""
REFUSED_DIR=""
# shellcheck disable=SC2317,SC2329  # reached by the trap below, which shellcheck cannot see
cleanup_temporaries() {
  local f
  for f in "${PREFLIGHT_ANSWER:-}" "${FLEET_REPORT:-}" "${FLEET_CAPTURE:-}"; do
    [[ -n "$f" ]] && rm -f "$f"
  done
  [[ -n "$REFUSED_DIR" ]] && rm -rf "$REFUSED_DIR"
  return 0
}
trap cleanup_temporaries EXIT

# Every root copy a sub-installer refuses is written here (rd_install does
# it, release-digests-lib.sh), and the closing text lists them and the run
# exits 4 (#764). A refusal used to read like any other "could not be
# installed" in a tolerated step and the install carried on to a green
# finish. The caller's file when it handed one over (get-aperire.sh folds the
# list into its own), this run's own otherwise; only a regular file this
# process owns is used, never a link.
if [[ -n "${RD_REFUSED_LOG:-}" && -f "$RD_REFUSED_LOG" && ! -L "$RD_REFUSED_LOG" && -O "$RD_REFUSED_LOG" ]]; then
  :
else
  REFUSED_DIR="$(mktemp -d -t aperire-refused.XXXXXXXX)"
  RD_REFUSED_LOG="$REFUSED_DIR/refused.log"
  : > "$RD_REFUSED_LOG"
fi
export RD_REFUSED_LOG
# What the log held when this run started: a file handed over may already
# carry another run's lines, and only this run's are this run's to list.
REFUSED_AT_START="$(wc -l < "$RD_REFUSED_LOG" 2>/dev/null || echo 0)"

ROLE=""
WITH_TUNNEL=0
RELAY_BINARY=""
ASSUME_YES=0
PREPARE=1
PREFLIGHT=1
# Whether anything on this host is started or restarted by this run. The
# sub-scripts read it as APERIRE_NO_RESTART, exported below, because they are
# also run on their own and a value that only arrived through here would be a
# second way to configure one thing.
RESTART=1
# Whether this host is already set up. It changes nothing this script DOES, it
# changes what it says. First-install guidance and the advisories beside it
# were given once, on the install, and repeating them to a host with enrolled
# operators is worse than noise: "authn.yaml still names localhost" reads as a
# warning about the passkeys already in use (aperire4, 2026-09-09, #269).
# Read-backs are not guidance and stay: each one is measured on this run.
QUIET_EXISTING=0

# ── Instance ────────────────────────────────────────────────────────
# One dashboard per node (ADR 0009): an operator with three validators runs
# three dashboards, each paired with its own Advisor and its own database.
# Naming an instance is what keeps a second one from colliding with the
# first, the unit names, the env and config files, the ports and the
# database all derive from it. No instance is the single-node layout, byte
# for byte what a host installed before this had.
#
# Each instance wants its own checkout, because the repository directory is
# where its data/, advisor/state/ and config live; the instance name only
# separates what lives outside it, in /etc and in systemd.
INSTANCE=""
DASH_PORT=""
ADVISOR_PORT=""

WITH_ADVISOR=0
# The Advisor gets its own account unless told otherwise. Running it as the
# operator's account means an account in the docker group, which is
# root-equivalent, so the privilege wrapper would be an audit trail rather
# than a boundary. The safer arrangement is the default because a setup you
# have to opt into is one most people skip.
# --advisor-shared-account is retired (ADR 0025): the Advisor always runs on
# its own account. The flag is still accepted, so a scripted install that
# passes it keeps working, and the plan says in one line that it did nothing.
ADVISOR_SHARED_ASKED=0

# ── Fleet join ──────────────────────────────────────────────────────
# Empty means this install joins no fleet, which is every install that does
# not ask to. The aggregator origin is the operator's own, typed from their
# own Settings page; the code is one-use and fifteen minutes; the label is
# proposed and the aggregator settles it.
FLEET_AGGREGATOR=""
FLEET_CODE=""
FLEET_LABEL=""
# Whether --fleet-code was given at all, kept separately from its value: a
# code read from stdin is a code that was given, and an empty one is still a
# refusal rather than a silent prompt.
FLEET_CODE_GIVEN=0

# ── Argument parsing ────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --role=*)          ROLE="${arg#*=}" ;;
    --instance=*)      INSTANCE="${arg#*=}" ;;
    --port=*)          DASH_PORT="${arg#*=}" ;;
    --advisor-port=*)  ADVISOR_PORT="${arg#*=}" ;;
    --with-tunnel)     WITH_TUNNEL=1 ;;
    --with-advisor)    WITH_ADVISOR=1 ;;
    --advisor-shared-account) ADVISOR_SHARED_ASKED=1 ;;
    --relay-binary=*)  RELAY_BINARY="${arg#*=}" ;;
    --fleet-aggregator=*) FLEET_AGGREGATOR="${arg#*=}" ;;
    --fleet-code=*)    FLEET_CODE="${arg#*=}"; FLEET_CODE_GIVEN=1 ;;
    --fleet-label=*)   FLEET_LABEL="${arg#*=}" ;;
    --no-prepare)      PREPARE=0 ;;
    --no-preflight)    PREFLIGHT=0 ;;
    --no-restart)      RESTART=0 ;;
    --quiet-existing)  QUIET_EXISTING=1 ;;
    --yes|-y)          ASSUME_YES=1 ;;
    -h|--help)
      awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "$0"
      exit 0
      ;;
    *)
      echo "${E_RED}error: unknown argument: $arg${E_OFF}" >&2
      echo "       run with --help for usage" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ROLE" ]]; then
  echo "${E_RED}error: --role=<dashboard|validator|co-located|cli-only> is required${E_OFF}" >&2
  echo "       run with --help for usage" >&2
  exit 2
fi

case "$ROLE" in
  dashboard|validator|co-located|cli-only) ;;
  *)
    echo "${E_RED}error: invalid role '$ROLE'${E_OFF}" >&2
    echo "       valid roles: dashboard, validator, co-located, cli-only" >&2
    exit 2
    ;;
esac

# ── The fleet flags, checked here and nowhere later ─────────────────
# Before the privilege check, before the preflight, before apt. Everything
# below is knowable from the command line alone, and a mistyped code or a bad
# origin discovered after apt, an nvm Node download, npm ci and two Go builds
# is a mistyped code discovered an hour late.
#
# The shape of a code, the same reading lib/pairing-codes.ts and
# aperire-fleet-pair.sh's normalise_code take: upper-cased, O read as zero, I
# and L read as one, everything outside Crockford base32 dropped, a leading
# APR taken off, twenty characters left. Shape only. What is passed down is
# the text as it was given, because the pair command owns the normalisation
# and two programs normalising one value is how they come to disagree.
fleet_fold_code() { printf '%s' "$1" | tr 'OIL' '011' | tr -cd '0-9A-HJKMNP-TV-Z'; }
fleet_code_shape_ok() {
  local upper whole body
  upper="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')"
  whole="$(fleet_fold_code "$upper")"
  if [[ ${#whole} -eq 20 ]]; then return 0; fi
  case "$upper" in
    APR*)
      body="$(fleet_fold_code "${upper#APR}")"
      if [[ ${#body} -eq 20 ]]; then return 0; fi
      ;;
  esac
  return 1
}

fleet_flag_error() {
  echo "${E_RED}error: $1${E_OFF}" >&2
  shift
  local line
  for line in "$@"; do echo "       $line" >&2; done
  exit 2
}

if [[ -n "$FLEET_AGGREGATOR" || $FLEET_CODE_GIVEN -eq 1 || -n "$FLEET_LABEL" ]]; then
  # Refused by name, per role. A validator host in the split shape runs the
  # relay and no dashboard, so it has no read API to pair and no credential to
  # hold; cli-only installs two symlinks in one account's ~/.local/bin and no
  # service at all. Naming the flag beats ignoring it: an install given a flag
  # it silently dropped did something other than what it was asked for.
  case "$ROLE" in
    validator)
      fleet_flag_error "role 'validator' cannot join a fleet." \
        "This host runs the relay and no dashboard, so there is no read API to" \
        "pair and nothing to hold a link credential. Pair the DASHBOARD host" \
        "that collects from this one."
      ;;
    cli-only)
      fleet_flag_error "role 'cli-only' cannot join a fleet." \
        "It installs the operator CLI and no service. Run the fleet flags on" \
        "the host that runs the dashboard."
      ;;
  esac

  # An update must never pair. It runs --no-restart on a host whose fleet
  # membership was already decided, and re-pairing it would mint a fresh
  # credential nobody asked for and revoke the one that is working.
  if [[ $QUIET_EXISTING -eq 1 ]]; then
    fleet_flag_error "--quiet-existing and the fleet flags are two different runs." \
      "--quiet-existing is what an update passes, and this host's fleet" \
      "membership is already decided. Pair it on its own:" \
      "    curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
  fi

  # There is nowhere to dial without an aggregator, so a code or a label on
  # its own is a command that cannot mean anything.
  if [[ -z "$FLEET_AGGREGATOR" ]]; then
    fleet_flag_error "--fleet-code and --fleet-label need --fleet-aggregator." \
      "They say what to send and what to call this node. Nothing says where."
  fi

  # The trailing slash a copied browser address carries, taken off first and
  # once, so what is checked, echoed in the plan and dialled are one value.
  # aperire-fleet-pair.sh does the same, in the same order.
  FLEET_AGGREGATOR="${FLEET_AGGREGATOR%/}"

  fleet_origin_scheme_ok "$FLEET_AGGREGATOR" \
    || fleet_flag_error "--fleet-aggregator must be https://." \
         "This node's read token and its Advisor token cross on that dial, so" \
         "the hop has to be encrypted. http:// is accepted only to loopback:" \
         "127.0.0.1, localhost or [::1], with an optional port and nothing else." \
         "Given: $FLEET_AGGREGATOR"
  fleet_origin_plain_ok "$FLEET_AGGREGATOR" \
    || fleet_flag_error "--fleet-aggregator is not a plain origin." \
         "Scheme, host, optional port, and no path. Give https://<host>." \
         "Given: $FLEET_AGGREGATOR"

  if [[ $FLEET_CODE_GIVEN -eq 1 ]]; then
    [[ -n "$FLEET_CODE" ]] \
      || fleet_flag_error "--fleet-code was given and carries no code." \
           "Leave the flag out entirely and the install asks for the code at" \
           "the end, on the terminal, which is the better habit anyway."
    fleet_code_shape_ok "$FLEET_CODE" \
      || fleet_flag_error "that is not a pairing code this installer can read." \
           "It is twenty characters in four groups, the way the page printed" \
           "it: APR-XXXXX-XXXXX-XXXXX-XXXXX"
  fi

  # The whole value, not its first line (P3-074). `grep -q` exits 0 when ANY
  # line matches, so `node-two\nsudo rm -rf /` passed this check and then went
  # into the plan note and into the command the closing text tells the operator
  # to copy, as a second line. Same defect the origin rule had, one function
  # away from it, in the change whose ADR note takes credit for removing it.
  if [[ -n "$FLEET_LABEL" ]]; then
    [[ "$FLEET_LABEL" =~ ^[a-z0-9-]{1,32}$ ]] \
      || fleet_flag_error "--fleet-label must match [a-z0-9-]{1,32}." \
           "That is the same rule fleet.yaml uses, so a name refused here is a" \
           "name the aggregator would have refused after the code was spent."
  fi
fi

# ── Privilege check ─────────────────────────────────────────────────
NEEDS_ROOT=1
[[ "$ROLE" == "cli-only" ]] && NEEDS_ROOT=0

if [[ $NEEDS_ROOT -eq 1 && $EUID -ne 0 ]]; then
  echo "${E_RED}error: role '$ROLE' must run as root. Run it through the bootstrap: curl -fsSL https://get.aperire.one | bash -s -- --role=$ROLE${E_OFF}" >&2
  exit 1
fi
if [[ $NEEDS_ROOT -eq 0 && $EUID -eq 0 ]]; then
  echo "${E_RED}error: role 'cli-only' must NOT run as root, install for your${E_OFF}" >&2
  echo "${E_RED}       own user only (drop the sudo)${E_OFF}" >&2
  exit 1
fi

# ── OS sanity check (warn, don't block) ─────────────────────────────
if [[ -r /etc/os-release ]]; then
  # shellcheck source=/dev/null  # runtime file, not present at lint time
  . /etc/os-release
  # Supported: Ubuntu 24.04/22.04 and anything Ubuntu-based (Linux Mint 22
  # is verified). 22.04's systemd 249 used to keep the Advisor off its own
  # account; the root socket removed that (ADR 0025), so this gate only flags
  # a host we have never seen.
  OS_OK=0
  if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" =~ ^(22\.04|24\.04)$ ]]; then OS_OK=1; fi
  if [[ " ${ID_LIKE:-} " == *ubuntu* || "${ID:-}" == "linuxmint" ]]; then OS_OK=1; fi
  if [[ $OS_OK -ne 1 ]]; then
    echo "${S_AMBER}warning: Aperire is verified on Ubuntu 24.04 / 22.04 LTS and Linux Mint 22.${S_OFF}"
    echo "         Detected: ${PRETTY_NAME:-unknown}. Continuing anyway."
    echo
  fi
fi

# ── Step zero: the preflight ────────────────────────────────────────
# Before the plan, not after it. Everything this measures was already true
# when the operator typed the command: no sqlite3, a port another service
# holds, a clock nobody synchronised, a node the dashboard will never find.
# Every one of them used to be discovered minutes in, after `npm ci` and two
# Go builds, and the fix was one line the whole time. So it is said first, and
# a MISSING stops the run here, where nothing has been changed yet.
#
# The later guards are all still in place. prepare-host.sh still refuses a
# root-only account, install-advisor-account.sh still checks systemd's
# version, install-aperire-relay.sh still asserts its unit came up: they run
# standalone too, and a check that only exists up here would not protect them.
#
# The node answer travels in a FILE, because preflight runs as a child and a
# child cannot export into its parent. What it wrote becomes
# APERIRE_RIPPLED_URL, which install-aperire-service.sh writes into
# /etc/aperire/aperire.env once.
if [[ $PREFLIGHT -eq 1 ]]; then
  # Refused by name, the way a missing term-style.sh is. A checkout without
  # the checklist is a checkout that is missing a file, not a host that may
  # be installed on without one.
  [[ -f "${SCRIPTS_DIR}/preflight.sh" ]] \
    || { echo "${E_RED}error: ${SCRIPTS_DIR}/preflight.sh is missing from this checkout${E_OFF}" >&2
         echo "       (--no-preflight installs without it, and without the check)" >&2; exit 1; }
  PREFLIGHT_ANSWER="$(mktemp -t aperire-preflight.XXXXXXXX)"
  PREFLIGHT_ARGS=( "--role=$ROLE" "--dir=$REPO_DIR" "--answer-file=$PREFLIGHT_ANSWER" )
  [[ -n "$INSTANCE" ]]      && PREFLIGHT_ARGS+=( "--instance=$INSTANCE" )
  [[ -n "$DASH_PORT" ]]     && PREFLIGHT_ARGS+=( "--port=$DASH_PORT" )
  [[ -n "$ADVISOR_PORT" ]]  && PREFLIGHT_ARGS+=( "--advisor-port=$ADVISOR_PORT" )
  [[ $WITH_ADVISOR -eq 1 ]] && PREFLIGHT_ARGS+=( --with-advisor )
  [[ $ASSUME_YES -eq 1 ]]   && PREFLIGHT_ARGS+=( --yes )
  if ! bash "${SCRIPTS_DIR}/preflight.sh" "${PREFLIGHT_ARGS[@]}"; then
    {
      echo "${E_RED}error: this host is missing something the install needs, so nothing was installed.${E_OFF}"
      echo
      echo "  The list above says what, and the command that fixes each one. Run"
      echo "  the check again on its own when you have:"
      echo "      bash ${TREE_SCRIPTS}/preflight.sh --role=$ROLE"
    } >&2
    exit 1
  fi
  if [[ -s "$PREFLIGHT_ANSWER" && -z "${APERIRE_RIPPLED_URL:-}" ]]; then
    PREFLIGHT_RIPPLED_URL="$(sed -n 's/^RIPPLED_URL=//p' "$PREFLIGHT_ANSWER" | tail -1)"
    [[ -n "$PREFLIGHT_RIPPLED_URL" ]] && export APERIRE_RIPPLED_URL="$PREFLIGHT_RIPPLED_URL"
  fi
fi

# ── Resolve relay binary if needed ──────────────────────────────────
# Runs after the prepare step, which is what builds relay/aperire-relay on
# a host that arrived without one; before it, a fresh checkout would fail
# here on the very thing prepare exists to provide.
resolve_relay_binary() {
  [[ "$ROLE" == "validator" || "$ROLE" == "co-located" ]] || return 0
  if [[ -z "$RELAY_BINARY" ]]; then
    for guess in \
        "${REPO_DIR}/relay/aperire-relay" \
        "$(pwd)/relay/aperire-relay" \
        "$(pwd)/aperire-relay"; do
      if [[ -n "$guess" && -x "$guess" ]]; then
        RELAY_BINARY="$guess"
        break
      fi
    done
  fi
  if [[ -z "$RELAY_BINARY" || ! -x "$RELAY_BINARY" ]]; then
    cat >&2 <<EOF
${E_RED}error: relay binary not found.${E_OFF}

  Pass it explicitly:
      sudo bash install.sh --role=$ROLE --relay-binary=/path/to/aperire-relay

  Or build it from this repo (pin to a reviewed commit, not floating main):
      git checkout <reviewed-commit>          # then: git rev-parse HEAD
      cd relay && go build -ldflags "-s -w" -o aperire-relay .
      sudo bash ${REPO_DIR}/install.sh --role=$ROLE

  Or let the installer build it (drop --no-prepare).
EOF
    exit 1
  fi
}
# Captured before resolve_relay_binary can fill the variable in from a build
# on disk, so the assertion below can tell "the operator brought one" from
# "the prepare step was supposed to build one".
RELAY_BINARY_GIVEN="$RELAY_BINARY"

# With --no-prepare nothing below will build it, so the check happens now,
# before the plan is shown, as it always did.
[[ $PREPARE -eq 1 ]] || resolve_relay_binary

# What the prepare step has to have produced for THIS role, checked before
# any step that consumes it runs.
#
# On the first real box the prepare step left no Go, no relay binary and no
# unit, the install carried on through the dashboard, the CLI and the closing
# text, and the closing text said the relay was running (#140). A step that
# half-runs must not be able to reach a confident banner: the run stops here,
# names the step, and names what it did not produce.
#
# A binary passed with --relay-binary is not the prepare step's to produce, so
# it is not checked here; resolve_relay_binary already refused a bad path.
assert_prepare_produced() {
  local missing=()
  case "$ROLE" in
    dashboard|co-located)
      [[ -f "${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs" ]] \
        || missing+=("dashboard/node_modules  (npm ci; the service runs from it)")
      ;;
  esac
  case "$ROLE" in
    validator|co-located)
      if [[ -z "$RELAY_BINARY_GIVEN" ]]; then
        [[ -x "${REPO_DIR}/relay/aperire-relay" ]] \
          || missing+=("relay/aperire-relay     (the Go build; no Go, no relay)")
      fi
      ;;
  esac
  if [[ $WITH_ADVISOR -eq 1 ]]; then
    [[ -x "${REPO_DIR}/advisor/bin/aperire-advisord" ]] \
      || missing+=("advisor/bin/aperire-advisord  (the Go build)")
  fi
  [[ ${#missing[@]} -eq 0 ]] && return 0

  {
    echo
    echo "${E_RED}error: the prepare step finished, and role '$ROLE' still has nothing to install.${E_OFF}"
    echo
    echo "  scripts/prepare-host.sh did not produce:"
    local m
    for m in "${missing[@]}"; do echo "      $m"; done
    echo
    echo "  Stopping here. Everything before this step is in place; nothing after it"
    echo "  could succeed, and an install that continues past this point ends with a"
    echo "  summary that describes services it never installed."
    echo
    echo "  Run the step on its own, where its output is not buried, and read it:"
    echo "      curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run prepare-host --role $ROLE$( [[ "$WITH_ADVISOR" == 1 ]] && printf ' --with-advisor' )"
    echo
    echo "  Then run this again. Both are idempotent."
  } >&2
  exit 1
}

# Whether this host has a dashboard unit already. Read from the unit files
# rather than from the role, because the role names what THIS run installs and
# a split validator can be standing beside a dashboard installed on an earlier
# one. `aperire-read` is the second name the dashboard's unit takes.
dashboard_unit_here() {
  local u
  for u in aperire-server aperire-read; do
    [[ -f "${APERIRE_UNIT_DIR:-/etc/systemd/system}/${u}${INSTANCE:+-$INSTANCE}.service" ]] && return 0
  done
  return 1
}

# ── Build the plan ──────────────────────────────────────────────────
declare -a STEPS

[[ $PREPARE -eq 1 && "$ROLE" != "cli-only" ]] && STEPS+=("prepare")
case "$ROLE" in
  dashboard)
    [[ $WITH_TUNNEL -eq 1 ]] && STEPS+=("tunnel")
    STEPS+=("service" "alert-defaults" "cli")
    [[ $WITH_ADVISOR -eq 1 ]] && STEPS+=("advisor")
    STEPS+=("update-grant")
    ;;
  validator)
    STEPS+=("relay" "rotation")
    # Only where a dashboard is already installed. The grant is the
    # dashboard's way to ask, so on a validator-only host in a split shape
    # there is nobody to grant it to, and installing it anyway would put a
    # root socket on a box that has no use for one.
    dashboard_unit_here && STEPS+=("update-grant")
    ;;
  co-located)
    [[ $WITH_TUNNEL -eq 1 ]] && STEPS+=("tunnel")
    STEPS+=("service" "alert-defaults" "cli" "relay" "rotation")
    [[ $WITH_ADVISOR -eq 1 ]] && STEPS+=("advisor")
    STEPS+=("update-grant")
    ;;
  cli-only)
    STEPS+=("cli")
    ;;
esac

# Last, and the ordering is the design rather than a preference. Three
# reasons, each enough on its own:
#
#   The Advisor's token has to exist first. aperire-fleet-pair.sh reads
#   advisor/state/approve.token, and absent is a supported state that
#   registers this node with NO advisor origin. Pairing before the Advisor
#   step means a node the aggregator cannot reach the Advisor on, fixed only
#   by pairing again with a fresh code.
#
#   The dashboard has to be answering. The command reads /read/v1/identity on
#   loopback and dies if nothing answers it.
#
#   Nothing after it can fail. A step that spends a one-time code should not
#   be followed by steps that can leave the host worse.
#
# The role test is belt and braces: the flags are refused by name on
# validator and cli-only at parse time, so the variable cannot be set here on
# those roles. It is spelled out anyway, because a step list is read to find
# out what a role does.
if [[ -n "$FLEET_AGGREGATOR" ]]; then
  case "$ROLE" in
    dashboard|co-located) STEPS+=("fleet-join") ;;
  esac
fi

# ── Print the plan ──────────────────────────────────────────────────
# The optional lines, assembled here rather than inside the heredoc below. A
# command substitution strips trailing newlines, so two of them side by side
# print as one joined line: the second flag's text ran on from the end of the
# first flag's, and both flags are what an update passes.
PLAN_NOTES=()
[[ $RESTART -eq 0 ]] && PLAN_NOTES+=("  Restarts:       none. The units are written and reloaded; what is
                  running keeps running the code it started with")
[[ $QUIET_EXISTING -eq 1 ]] && PLAN_NOTES+=("  Already set up: yes, so nothing below repeats what this host was told
                  on the install. What each step reads back is still said")
# The origin is echoed in the plan and again before the dial. Trust on first
# use is the boundary here and nothing can foreclose it, so the one thing that
# CAN be done is put the address the operator typed in front of them twice,
# before anything is sent to it.
[[ -n "$FLEET_AGGREGATOR" ]] && PLAN_NOTES+=("  Fleet:          join ${FLEET_AGGREGATOR} at the end, $([[ $FLEET_CODE_GIVEN -eq 1 ]] && echo 'with the code given' || echo 'asking you for a code')
                  ${FLEET_LABEL:+proposing the name \"${FLEET_LABEL}\". }A pairing that does not finish
                  leaves this host installed, enabled and running")

cat <<EOF

  ${S_BOLD}───── Aperire installer ─────${S_OFF}

  Role:           $ROLE
  Tunnel:         $([[ $WITH_TUNNEL -eq 1 ]] && echo "yes (cloudflared-aperire)" || echo "no")
  Advisor:        $([[ $WITH_ADVISOR -eq 1 ]] && echo "yes, with its own account$([[ $ADVISOR_SHARED_ASKED -eq 1 ]] && echo ' (--advisor-shared-account is retired and was ignored)')" || echo "no")
  Relay binary:   ${RELAY_BINARY:-$([[ $PREPARE -eq 1 && ( "$ROLE" == validator || "$ROLE" == co-located ) ]] && echo "built by the prepare step" || echo "(n/a)")}
  Repo root:      ${REPO_DIR}
$(printf '%s\n' ${PLAN_NOTES[@]+"${PLAN_NOTES[@]}"})

  Will run, in order:
EOF
for step in "${STEPS[@]}"; do
  case "$step" in
    prepare) echo "    • prepare-host.sh                (toolchain + relay/Advisor builds; --no-prepare to skip)" ;;
    tunnel)  echo "    • setup-aperire-tunnel.sh        (cloudflared-aperire systemd unit)" ;;
    service) echo "    • install-aperire-service.sh     (aperire-server systemd unit)" ;;
    alert-defaults)
             echo "    • set-alert-role-defaults.sh     (a swap threshold you can set for this host)" ;;
    cli)     echo "    • install-aperire-cli.sh         (aperire-auth -> ~/.local/bin)" ;;
    relay)   echo "    • install-aperire-relay.sh       (aperire-relay binary + systemd unit)" ;;
    advisor) echo "    • install-advisor-stack.sh       (Advisor service, both root grants, its own account, trust store)" ;;
    rotation) echo "    • install-can-delete-timer.sh    (scheduled ledger-store rotation window)" ;;
    update-grant)
             echo "    • install-update-grant.sh        (the root socket the dashboard asks for an update on)" ;;
    fleet-join)
             echo "    • aperire-fleet-pair.sh          (join the fleet at ${FLEET_AGGREGATOR}; asks two questions)" ;;
  esac
done
echo

if [[ $ASSUME_YES -ne 1 ]]; then
  # No terminal, no question. `read -p` writes its prompt to the terminal, so
  # under a pipe the operator saw the plan and then a bare `exit 1` from the
  # read's EOF, no error line, nothing naming what to do instead (fresh-host
  # run, 2026-08-20). The flag that makes this same invocation work is printed
  # instead, and the exit code is 2, the same "wrong way to run me" the guided
  # setup uses.
  if [[ ! -t 0 ]]; then
    # The arguments this run was given, back as one line, with two changes.
    #
    # The code is REDACTED (P3-073). This branch fires under a CI job, a
    # cloud-init or anything capturing output to a file, and it fires BEFORE
    # the fleet step, so a code printed here is live for the rest of its
    # fifteen minutes in whatever caught it.
    #
    # And each argument is quoted, because `$*` reprinted a value with a space
    # in it as two arguments, so the command it suggested was not the command
    # that was run.
    # The placeholder carries no character `printf %q` would escape, so the
    # line it lands in is still a line an operator can read and edit.
    SUGGEST=()
    for arg in "$@"; do
      case "$arg" in
        --fleet-code=*) SUGGEST+=("--fleet-code=your-code-here") ;;
        *)              SUGGEST+=("$arg") ;;
      esac
    done
    cat >&2 <<EOF

${E_RED}error: this is not a terminal, and the plan above needs one answer.${E_OFF}

  Take the plan exactly as printed by adding --yes:
      $([[ $NEEDS_ROOT -eq 1 ]] && printf 'sudo ')bash $0 $(printf '%q ' ${SUGGEST[@]+"${SUGGEST[@]}"})--yes

  Or answer the questions in a terminal:
      sudo bash aperire-one
EOF
    exit 2
  fi
  read -r -p "  Proceed? [y/N] " reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "aborted."; exit 0 ;;
  esac
fi

# ── Run the sub-scripts ─────────────────────────────────────────────
run_as_user() {
  # Run a sub-script as the invoking user (not root). Used for the CLI
  # install step when the orchestrator was invoked via sudo.
  #
  # NO_COLOR is handed across the boundary explicitly. sudo's env_reset keeps
  # TERM and drops NO_COLOR, so an operator who set it would otherwise get a
  # plain orchestrator and a coloured CLI installer out of the same run.
  local -a keep=()
  [[ -n "${NO_COLOR:-}" ]] && keep+=("NO_COLOR=${NO_COLOR}")
  # The update flag crosses the same boundary for the same reason: the CLI
  # installer's first-install guidance is gated on it, and the first live
  # update (aperire4, 2026-09-09) printed the PATH warning anyway because
  # sudo had dropped the flag on the way (#269).
  [[ "${APERIRE_UPDATE:-0}" == "1" ]] && keep+=("APERIRE_UPDATE=1")
  if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H env "${keep[@]}" bash "$@"
  else
    bash "$@"
  fi
}

# ── The fleet-join step ─────────────────────────────────────────────
#
# Runs scripts/aperire-fleet-pair.sh, last, with a human at the keyboard, and
# never spends a pairing code this install cannot finish.
#
# Three rules this whole section exists to keep:
#
#   A failed pair never fails the install and never rolls anything back. The
#   host is installed, enabled and running whatever happens here. Every path
#   below returns 0 and writes what happened to a report file, and the closing
#   summary is READ from that file. A failure here must not be able to become
#   a claim down there: that is #140's rule, and it applies unchanged.
#
#   Nothing reaches the pair command that could answer its one question.
#   get-aperire.sh always passes --yes to this installer (a plan taken as
#   printed); the pair command has no --yes at all any more (#741), and its
#   --expect-fingerprint is never passed from here. The operator pastes the
#   aggregator's pairing fingerprint at this terminal, and an installer may
#   not do that for anybody.
#
#   Re-prompting is bounded at three attempts and happens only on a refusal
#   from a dial that actually happened. The aggregator holds four pairing
#   slots, so an installer that retries on its own is a denial of service
#   against the operator's own fleet.
#
# Two variables exist for the tests and are not meant to be set by hand:
# APERIRE_FLEET_IDENTITY_TRIES and APERIRE_FLEET_IDENTITY_SLEEP bound the wait
# for this node to report its own key. The default is five minutes.
FLEET_REPORT=""
FLEET_CAPTURE=""
FLEET_DIALLED=0
FLEET_WAIT_TRIES="${APERIRE_FLEET_IDENTITY_TRIES:-60}"
FLEET_WAIT_SLEEP="${APERIRE_FLEET_IDENTITY_SLEEP:-5}"

# The real command that pairs this host later, printed whenever this step
# defers or is refused. Deliberately not the --dry-run form: a dry run exits 0
# without dialling and cannot show the aggregator's fingerprint, so a 0 from
# it reads as "paired" to anybody skimming.
fleet_deferred_line() {
  local line="curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator ${FLEET_AGGREGATOR}"
  [[ -n "$FLEET_LABEL" ]] && line="$line --fleet-label ${FLEET_LABEL}"
  # The tree is named too, quoted for a shell: a host installed with --dir, or
  # from a clone, is not at the bootstrap's default and would be refused.
  printf '%s --code - --dir %q' "$line" "$REPO_DIR"
}

fleet_report() { printf '%s\n' "$@" >> "$FLEET_REPORT"; }

# Which port this host's dashboard actually answers on.
#
# Not `${DASH_PORT:-7800}`. --port is what THIS run was told, and this
# installer is idempotent and meant to be re-run: the second run on a host
# built with --port=7900, or on an --instance host, usually carries no --port
# at all. Asking 7800 there gets nothing, waits out the whole five minutes and
# reports a deferral that is about the wrong port.
#
# So it is read the way aperire-fleet-pair.sh reads it, and in the same order:
# the unit's own Environment=PORT, then the environment file the unit names,
# then this instance's file in /etc/aperire, then the default. What this run
# was told still wins, because on a first install nothing on disk exists yet.
#
# Every place this installer asks its own dashboard something, or tells the
# operator to, goes through here (#1176): the fleet gate's identity read, the
# closing summary's wait for the relay's first push, and the verify command it
# prints. A value read from the host's files that is not a port number is not a
# reading: it is skipped, the way get-aperire.sh's configured_dash_port skips
# it, so nothing but digits from those files lands in a URL. A --port is the
# operator's own argument and is used as given.
fleet_dash_port() {
  local unit_file="" env_file="" u f p
  if [[ -n "$DASH_PORT" ]]; then printf '%s' "$DASH_PORT"; return 0; fi
  for u in aperire-server aperire-read; do
    f="${APERIRE_UNIT_DIR:-/etc/systemd/system}/${u}${INSTANCE:+-$INSTANCE}.service"
    if [[ -f "$f" ]]; then unit_file="$f"; break; fi
  done
  if [[ -n "$unit_file" ]]; then
    p="$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$unit_file" 2>/dev/null || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s' "$p"; return 0; fi
    env_file="$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$unit_file" 2>/dev/null || true)"
  fi
  for f in "$env_file" "${ETC_APERIRE}/aperire${INSTANCE:+-$INSTANCE}.env"; do
    [[ -n "$f" && -f "$f" ]] || continue
    p="$(awk -F= '$1=="PORT"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$f" 2>/dev/null || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s' "$p"; return 0; fi
  done
  printf '7800'
}
# Read once, at the top of the step, so the wait, its working line and the
# deferral all name one port.
FLEET_DASH_PORT=""

# One reading of this node's own /read/v1/identity. Prints the node key, or
# nothing.
#
# The read token goes in a 0600 file and never on curl's argv (P2-057):
# /proc/<pid>/cmdline is world-readable, so any local account that polled it
# while this ran would read this node's read token off the command line. That
# is the same hand-off aperire-fleet-pair.sh makes for the same call.
fleet_node_key() {
  local token cfg body key
  token="$(tr -d '[:space:]' < "${REPO_DIR}/advisor/state/read.token" 2>/dev/null || true)"
  [[ -n "$token" ]] || return 1
  cfg="$(umask 077; mktemp -t aperire-fleet-curl.XXXXXXXX)"
  ( umask 077; printf 'header = "Authorization: Bearer %s"\n' "$token" >"$cfg" )
  body="$(curl -sS --max-time 5 --config "$cfg" \
            "http://127.0.0.1:${FLEET_DASH_PORT}/read/v1/identity" 2>/dev/null || true)"
  shred -u "$cfg" 2>/dev/null || rm -f "$cfg"
  [[ -n "$body" ]] || return 1
  key="$(printf '%s' "$body" \
    | sed -nE 's/.*"pubkey_node"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' | head -1)"
  [[ -n "$key" ]] || return 1
  # The same shape aperire-fleet-pair.sh refuses on, and the same shape
  # lib/fleet-seal.ts pins. A Pending row carrying anything else is a row
  # nobody can approve into anything useful, so the wait ends on a key that
  # will actually work rather than on any answer at all.
  printf '%s' "$key" | grep -Eq '^n[1-9A-HJ-NP-Za-km-z]{20,60}$' || return 1
  printf '%s' "$key"
}

# The gate, and it is a reading rather than a role. On a --node install the
# node was deployed minutes ago and has not caught up; on a split-shape
# dashboard the relay is standing by with no dashboard named yet. Both report
# no key, both are normal, and neither is a host to spend a code on.
fleet_wait_for_key() {
  local i key
  echo "  ${E_DIM}waiting for this node to report its own key, which is what the aggregator${E_OFF}" >&2
  echo "  ${E_DIM}pins the row to. Asking http://127.0.0.1:${FLEET_DASH_PORT}/read/v1/identity,${E_OFF}" >&2
  echo "  ${E_DIM}every ${FLEET_WAIT_SLEEP}s for up to $(( FLEET_WAIT_TRIES * FLEET_WAIT_SLEEP / 60 )) minutes${E_OFF}" >&2
  for (( i = 1; i <= FLEET_WAIT_TRIES; i++ )); do
    if key="$(fleet_node_key)"; then
      printf '%s' "$key"
      return 0
    fi
    if (( i % 6 == 0 )); then
      echo "  ${E_DIM}still no key after ${i} asks; the node's bridge has not reached it yet${E_OFF}" >&2
    fi
    sleep "$FLEET_WAIT_SLEEP"
  done
  return 1
}

# The code, from the flag or from the terminal. Never echoed, never on any
# argv, never in an environment variable.
fleet_read_code() {
  local code=''
  if [[ -n "$FLEET_CODE" ]]; then
    printf '%s' "$FLEET_CODE"
    return 0
  fi
  printf '   Paste the pairing code, then Enter: ' >&2
  read -rs code < /dev/tty || code=''
  printf '\n' >&2
  [[ -n "$code" ]] || return 1
  printf '%s' "$code"
}

# One invocation. The code crosses on the child's stdin, so it is on nothing's
# command line; the child's output is teed to a file, so the closing summary
# can be read from what the command actually said. Sets FLEET_DIALLED, which
# is what separates a refusal the aggregator made from a refusal this node
# made before sending anything.
fleet_pair_once() {
  local code="$1" rc=0
  local -a args=( --code - --aggregator "$FLEET_AGGREGATOR" --dir "$REPO_DIR" )
  [[ -n "$FLEET_LABEL" ]] && args+=( --label "$FLEET_LABEL" )
  FLEET_DIALLED=0
  : > "$FLEET_CAPTURE"
  set +e
  printf '%s\n' "$code" \
    | bash "${SCRIPTS_DIR}/aperire-fleet-pair.sh" "${args[@]}" 2>&1 \
    | tee -a "$FLEET_CAPTURE"
  rc=${PIPESTATUS[1]}
  set -e
  # The step banner the pair command prints immediately before it opens the
  # WebSocket. Present means the code left this host.
  if grep -q '^== Pairing$' "$FLEET_CAPTURE"; then FLEET_DIALLED=1; fi
  return "$rc"
}

# What the pair command said, read back rather than templated.
#
# Control characters are stripped here, in the one place every value the
# closing summary prints comes through (P3-071). The refusal sentences are the
# aggregator's own text, off the wire, with no length bound and no character
# class in the contract: an escape sequence in one of them erased its own line
# and repainted a "not paired" block as a green registration. It could never
# change WHICH block printed, because the outcome is keyed off the exit code,
# but the one line an operator's eye goes to said the opposite of the two
# around it. LC_ALL=C so the class is bytes rather than the run's locale.
fleet_said() {
  sed -nE "$1" "$FLEET_CAPTURE" | tail -1 | LC_ALL=C tr -d '\000-\037\177'
}

fleet_join_step() {
  FLEET_REPORT="$(umask 077; mktemp -t aperire-fleet-join.XXXXXXXX)"
  FLEET_CAPTURE="$(umask 077; mktemp -t aperire-fleet-pair-out.XXXXXXXX)"
  FLEET_DASH_PORT="$(fleet_dash_port)"

  # The origin, said again. It was in the plan and it is here, the second and
  # last time before this host sends its read token and its Advisor token to
  # whatever answers there. Trust on first use is the boundary and nothing can
  # foreclose it; putting the address in front of the operator twice is what
  # can be done about that.
  echo
  echo "  Joining the fleet at ${S_CYAN}${FLEET_AGGREGATOR}${S_OFF}"

  local key
  if ! key="$(fleet_wait_for_key)"; then
    fleet_report 'outcome=deferred' \
      "detail=this node has not reported its own key yet, so there is nothing for a Pending row to be pinned to. Nothing was sent and no code was spent."
    echo
    echo "  ${S_AMBER}This node does not know its own key yet, so nothing was dialled.${S_OFF}"
    echo "     Its bridge has not reached the node. That is normal on a box where the"
    echo "     node was deployed minutes ago, and on a split shape where the relay is"
    echo "     still standing by. Pair it when the node is answering."
    echo
    return 0
  fi

  echo
  echo "  This node is up and reports its key:"
  echo "      ${key}"
  echo

  # The two questions pairing asks cannot be answered for anybody, so a run
  # with no terminal defers rather than dialling. Refused HERE and not at the
  # pause: the pause sits downstream of an administrator approving the Pending
  # row under a passkey, and a touch nobody gets back is not a thing to spend
  # on a question that was already unanswerable.
  if ! tty_available; then
    fleet_report 'outcome=deferred' \
      "detail=this run had no terminal, and pairing asks two questions that cannot be answered for you. Nothing was sent and no code was spent."
    echo "  ${S_AMBER}This run has no terminal, so nothing was dialled.${S_OFF}"
    echo
    return 0
  fi

  echo "  On the aggregator, open Settings & Updates -> Fleet registry list -> Pair a"
  echo "  node. It prints a code, good for fifteen minutes and one node."
  echo

  local attempt=1 code rc arm
  while (( attempt <= 3 )); do
    if ! code="$(fleet_read_code)"; then
      fleet_report 'outcome=deferred' "detail=no code was given, so nothing was dialled."
      echo
      echo "  ${S_AMBER}No code was given, so nothing was dialled.${S_OFF}"
      echo
      return 0
    fi
    # Whether it came from the flag or the terminal, it is spent now. A second
    # attempt asks for a fresh one rather than re-sending a code the
    # aggregator has already refused.
    FLEET_CODE=''
    rc=0
    fleet_pair_once "$code" || rc=$?
    code=''

    case "$rc" in
      0)
        # The arm key is the one thing a settled pair can still leave undone,
        # and the pair command says so in its own words rather than failing.
        # Read as a fact off this host (the file it writes), and only where
        # the file is absent, why, off what the command printed. The first
        # live run of this step claimed the key was held on a host with no
        # sealer, where the command had just said it refused it.
        # A settlement with no arm key is refused before anything is written
        # (#741), so a paired host was always handed one.
        if [[ -s "${ETC_APERIRE}/fleet-arm.pub" ]]; then arm=trusted
        elif grep -q 'no install-model-key-sealer.sh in this tree' "$FLEET_CAPTURE"; then arm=no_sealer_script
        # Before the refusal line, and it is a different fact (#331): on a host
        # with no Advisor there was never a sealer for the key to be refused
        # by, so "fix it and run --trust-arm-key" is advice about a thing that
        # is not broken. The pair command decides it off that host's own tree.
        # #720: and when it held the key for the Advisor that comes later,
        # that is the whole of it. The pair command prints that line only
        # after --hold-arm-key exited 0, which it does only once the file is
        # written and read back on a descriptor.
        elif grep -q '^   the arm key is held for it at ' "$FLEET_CAPTURE"; then arm=held
        elif grep -q '^   no Advisor here, so there is nothing to arm' "$FLEET_CAPTURE"; then arm=no_advisor
        elif grep -q '^   the sealer refused that key' "$FLEET_CAPTURE"; then arm=refused
        else arm=unknown; fi
        fleet_report 'outcome=paired' \
          "label=$(fleet_said 's/^== Registered as "(.*)"$/\1/p')" \
          "read_port=$(fleet_said 's/^[[:space:]]+read port on the aggregator:[[:space:]]+(.*)$/\1/p')" \
          "advisor_port=$(fleet_said 's/^[[:space:]]+advisor port on the aggregator:[[:space:]]+(.*)$/\1/p')" \
          "fingerprint=$(fleet_said 's/^[[:space:]]+fingerprint matches:[[:space:]]+([0-9a-f ]+)$/\1/p')" \
          "arm_key=$arm"
        return 0
        ;;
      2)
        # #312. Not a refusal and not a success: the aggregator could not say
        # whether it registered this node. Re-running is the ONE action that
        # could double-register, so this never re-dials and never suggests it.
        fleet_report 'outcome=unconfirmed' \
          "detail=$(fleet_said 's/^unconfirmed: (.*)$/\1/p')"
        return 0
        ;;
      4)
        # #741: the fingerprint pasted at this terminal was not this
        # pairing's. Never a retry with a fresh code from here: the keys this
        # node was offered are not the ones root on the aggregator printed,
        # and asking again at once is exactly how a mismatch gets waved
        # through. Nothing was sent and nothing was written.
        #
        # Pairing v2: the pair command asks for the fingerprint BEFORE it
        # dials, and three pastes that are not a fingerprint at all end it
        # there, with the code unspent. `dialled` tells the two apart, so the
        # ending never sends the operator to mint a code they still have.
        fleet_report 'outcome=mismatch' \
          "dialled=${FLEET_DIALLED}" \
          "detail=$(fleet_said 's/^refused: (.*)$/\1/p')"
        return 0
        ;;
      3)
        if (( FLEET_DIALLED == 1 )) && (( attempt < 3 )); then
          echo
          echo "  ${S_AMBER}The aggregator refused that code.${S_OFF} A code is good for fifteen minutes"
          echo "     and one node, so mint a fresh one and paste it. Attempt $(( attempt + 1 )) of 3."
          echo
          attempt=$(( attempt + 1 ))
          continue
        fi
        fleet_report 'outcome=refused' \
          "dialled=${FLEET_DIALLED}" \
          "detail=$(fleet_said 's/^refused: (.*)$/\1/p')"
        return 0
        ;;
      *)
        fleet_report 'outcome=broke' \
          "detail=$(fleet_said 's/^error: (.*)$/\1/p')"
        return 0
        ;;
    esac
  done
  return 0
}

# What an install says when the store-rotation window could not be installed:
# the danger, once. Both refusals below print it, so it has one owner here (and
# the wrapper's rotation-state line is the other, the one the Advisor reads).
# $1 = the sentence that follows, saying what to do about it.
rotation_window_warning() {
  echo
  echo "  ${S_AMBER}!! The scheduled store-rotation window could not be installed here.${S_OFF}"
  echo "     Without it, restarting this node while its store is mid-rotation"
  echo "     can empty the store. $1"
}

# Whether this instance's dashboard runs as its own account (ADR 0024), read
# from the unit the service step wrote.
dashboard_on_own_account() {
  local f="${APERIRE_UNIT_DIR:-/etc/systemd/system}/aperire-server${INSTANCE:+-$INSTANCE}.service"
  [[ -f "$f" ]] && grep -qx 'User=aperire-dashboard' "$f"
}

# Every sub-script reads the same three variables, so an instance is named
# once here and the unit names, config paths and ports follow from it. They
# are exported rather than passed as flags because the scripts are also run
# individually, and a value that only arrives through install.sh would be a
# second way to configure the same thing.
export APERIRE_INSTANCE="${INSTANCE}"
[[ $RESTART -eq 0 ]] && export APERIRE_NO_RESTART=1
[[ $QUIET_EXISTING -eq 1 ]] && export APERIRE_UPDATE=1
[[ -n "$DASH_PORT" ]]    && export APERIRE_PORT="${DASH_PORT}"
[[ -n "$ADVISOR_PORT" ]] && export APERIRE_ADVISOR_PORT="${ADVISOR_PORT}"

for step in "${STEPS[@]}"; do
  echo
  echo "${S_BOLD}═══ ${step} ═══${S_OFF}"
  case "$step" in
    prepare)
      APERIRE_ROLE="$ROLE" APERIRE_WITH_ADVISOR="$WITH_ADVISOR" bash "${SCRIPTS_DIR}/prepare-host.sh"
      # Asserted before anything downstream runs on the assumption it worked.
      assert_prepare_produced
      # Now that the relay may exist, find it the way the no-prepare path did.
      resolve_relay_binary
      ;;
    tunnel)  bash "${SCRIPTS_DIR}/setup-aperire-tunnel.sh" ;;
    service)
      # The role is recorded in aperire.env so the dashboard knows what the
      # install was for (#808). get-aperire.sh sets APERIRE_RECORD_ROLE=0 on
      # an update that only INFERRED the role from the units: a guess is not a
      # fact to write down.
      if [[ "${APERIRE_RECORD_ROLE:-1}" == 0 ]]; then
        env -u APERIRE_INSTALL_ROLE bash "${SCRIPTS_DIR}/install-aperire-service.sh"
      else
        APERIRE_INSTALL_ROLE="$ROLE" bash "${SCRIPTS_DIR}/install-aperire-service.sh"
      fi ;;
    # The swap warn rule ships at 40% for every role now (#576), so a fresh
    # install of either role has nothing to override and this writes nothing.
    # What it is still for: an operator who wants a different number on this
    # box, via --swap-warn on a later run. Run as the operator, not root: it
    # writes a file in the checkout, and a rules file left root-owned is one
    # they cannot tune afterwards. It writes an override in
    # dashboard/config/rules.local.yaml, never in the shipped rules.yaml,
    # which every update replaces (ADR 0020). First install only: once that
    # file has an entry for the rule the number is somebody's, and no
    # upgrade or re-run touches it.
    alert-defaults)
      if ! run_as_user "${TREE_SCRIPTS}/set-alert-role-defaults.sh" "--role=$ROLE"; then
        echo
        echo "  ${S_AMBER}!! The role-aware alert defaults could not be applied.${S_OFF}"
        echo "     The shipped thresholds are in place and the dashboard runs on them."
        echo "     Re-run later: bash scripts/set-alert-role-defaults.sh --role=$ROLE"
        echo
      fi
      ;;
    cli)     run_as_user "${TREE_SCRIPTS}/install-aperire-cli.sh" ;;
    # One script, and the same one `curl -fsSL https://get.aperire.one/advisor`
    # runs. It installs the service, both root grants, the dedicated account and
    # the trust store, and reads the service back before anything is claimed.
    # Until it existed this step ran two of those five, so a host installed with
    # the flag had no browser model step and no way for a passkey enrolled in
    # the browser to reach its Advisor, while the docs said the two paths were
    # the same.
    #
    # Tolerated on failure, like the relay and the rotation timer: the script
    # says which step went and what was lost, everything before it is installed
    # and running, and dying here under set -e swallowed the closing summary
    # once already (fresh-22.04 run, 2026-08-20). Nothing below can lie about
    # it: the closing text is printed from what the script reported.
    advisor)
      ADVISOR_REPORT="$(mktemp -t aperire-advisor-stack.XXXXXXXX)"
      ADVISOR_STACK_ARGS=(--dir "$REPO_DIR" --report "$ADVISOR_REPORT" --yes)
      ADVISOR_STACK_RC=0
      bash "${SCRIPTS_DIR}/install-advisor-stack.sh" "${ADVISOR_STACK_ARGS[@]}" || ADVISOR_STACK_RC=$?
      if [[ $ADVISOR_STACK_RC -eq 3 ]]; then
        # Installed and answering, on the dashboard's account: the move
        # refused and put the old unit back (#806). Named as the account
        # step, since re-running the whole stack is not what fixes it.
        ADVISOR_STEP_FAILED=1
        ADVISOR_ACCOUNT_STAYED=1
        # On the new shape (ADR 0024) the dashboard runs as aperire-dashboard,
        # not as the operator the Advisor stayed on, so it cannot read the
        # Advisor's token: the Advisor tab does not work. That is a failed
        # step, said here and again at the end, never a quiet success.
        if dashboard_on_own_account; then
          ADVISOR_TOKEN_UNREADABLE=1
          echo
          echo "  ${S_RED}!! The Advisor step FAILED: its move onto its own account refused (above).${S_OFF}"
          echo "     The dashboard runs as aperire-dashboard and cannot read the Advisor's"
          echo "     token, so the Advisor tab will not work. Retry the move, once the"
          echo "     reason above is put right:"
          if [[ -n "$INSTANCE" ]]; then
            echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run advisor-account${INSTANCE:+ --instance $INSTANCE}${S_OFF}"
          else
            echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
            echo "         (at a terminal, and answer Y when it offers to move the Advisor)"
          fi
          echo
        fi
      elif [[ $ADVISOR_STACK_RC -ne 0 ]]; then
        ADVISOR_STEP_FAILED=1
        echo
        echo "  ${S_AMBER}!! The Advisor step did not finish. What it reported is above.${S_OFF}"
        echo "     Everything before it is installed. Run the update again, which is"
        echo "     safe and retries it: ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
        echo
      fi
      ;;
    rotation)
      # The scheduled ledger-store rotation window (issue #79). Tolerated on
      # failure for the reason the Advisor account step is: this is a safety
      # timer for a node the installer did not deploy and cannot reconfigure,
      # so on a host where the node cannot be found it prints what is missing
      # and the install carries on. The sub-script also declines to ENABLE
      # the timer until the node's config has advisory_delete=1, which on a
      # fresh install is a step the operator takes afterwards.
      # Exit 3 is its answer for a host it has proven has no node of its own,
      # an aggregator with a relay for one: there is nothing to rotate. Exit 4
      # is a node it could not name. The role cannot say which: update_resolve_role
      # reads dashboard plus relay as co-located and a relay alone as relay, and
      # both plans carry this step, because only the script holds the evidence
      # (docker, units, processes) and a second copy of it here could disagree.
      rotation_rc=0
      bash "${SCRIPTS_DIR}/install-can-delete-timer.sh" || rotation_rc=$?
      if [[ $rotation_rc -eq 3 ]]; then
        echo "  no node on this host, so no rotation window"
      elif [[ $rotation_rc -eq 4 ]]; then
        # It could not find or name the node. The variables it names do not
        # reach it through the update's root run, but it reads the same two
        # values from node.conf, so that is where they go.
        rotation_window_warning "The lines above say what it could not tell."
        echo "     Name the node with the one-liner, which installs the window for it:"
        echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --run rotation-timer --service <container or unit> --admin-rpc http://127.0.0.1:<admin port>${S_OFF}"
        echo "     or tell the Advisor's wrapper which node it is, then run the update again:"
        echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container>${S_OFF}"
        echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native <unit>${S_OFF}   (a node run by systemd)"
        echo "     Or name it in ${S_CYAN}${ETC_APERIRE}/node.conf${S_OFF}, with these lines:"
        echo "         SERVICE=<container or unit name>"
        echo "         ADMIN_RPC=http://127.0.0.1:<admin port>"
        echo "         KIND=native            (only when SERVICE is a systemd unit)"
        echo "     then run the update again, which is safe and retries it:"
        echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
        echo
      elif [[ $rotation_rc -ne 0 ]]; then
        rotation_window_warning "Put the reason above right, then run the update"
        echo "     again, which is safe and retries it:"
        echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
        echo
      fi
      ;;
    # The third root grant (ADR 0022): one socket the dashboard account may
    # open, behind which one root program moves this host to the release the
    # endpoint publishes. It carries no source, so the widest thing a bad web
    # session can do with it is install what the publisher published.
    #
    # Tolerated on failure, like the relay and the rotation timer. A host
    # without it updates exactly the way every host did before it existed, by
    # an operator running the one-liner, and dying here under set -e would
    # swallow the closing summary.
    update-grant)
      if ! bash "${SCRIPTS_DIR}/install-update-grant.sh"; then
        echo
        echo "  ${S_AMBER}!! The update grant could not be installed here.${S_OFF}"
        echo "     Everything else is installed. Updating from the dashboard needs it;"
        echo "     updating from the command line does not:"
        echo "         ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
        echo
      fi
      ;;
    relay)
      # Co-located: the sub-script wires the relay from this box (loopback URL,
      # the dashboard's own token, the node's label) and starts it, with no
      # manual step to forget. Split/validator: it writes a config that names
      # no dashboard and starts the unit standing by, so a reboot cannot take
      # a relay away that the operator was told was enabled.
      #
      # Tolerated on failure, like the Advisor account and the rotation timer:
      # the sub-script asserts its own outcome and exits non-zero when the unit
      # did not come up, and dying here under set -e would swallow the closing
      # summary. The summary reads the unit itself, so a failure here cannot
      # turn into a claim down there.
      if [[ "$ROLE" == "co-located" ]]; then
        APERIRE_COLOCATED=1 bash "${SCRIPTS_DIR}/install-aperire-relay.sh" "$RELAY_BINARY" || RELAY_STEP_FAILED=1
      else
        bash "${SCRIPTS_DIR}/install-aperire-relay.sh" "$RELAY_BINARY" || RELAY_STEP_FAILED=1
      fi
      if [[ ${RELAY_STEP_FAILED:-0} -eq 1 ]]; then
        echo
        echo "  ${S_AMBER}!! The relay step did not finish. What it reported is above.${S_OFF}"
        echo "     Run the update again to retry it: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
        echo
      fi
      ;;
    # Last, and it cannot fail this install. Everything it could have left
    # half-done is already done, it rolls nothing back, and what it did is
    # written to a report the closing summary reads.
    fleet-join) fleet_join_step ;;
  esac
done

# ── Closing summary ─────────────────────────────────────────────────
# Where operators reach this dashboard, read exactly the way the guided setup
# reads it (scripts/aperire-setup.sh, authn_public_url / authn_is_localhost) so the
# two install paths cannot disagree about what "still localhost" means. The
# guided path refuses to issue a link against localhost; this path cannot
# refuse anything, because the operator creates the account themselves after
# it exits, so it names the step instead, before the step that would burn a
# passkey on the wrong origin.
# ── What the closing text is allowed to say about the relay ─────────
# Read, never templated. The old co-located paragraph said the relay was
# "installed as the enabled, non-privileged aperire-relay service and started
# automatically" on every run, including the run where Go was never installed,
# the relay was never built and no unit existed (#140). A sentence in the
# present tense about a service is a claim, and a claim has to be read back.
#
# Three separate readings, because they fail separately: enabled (survives a
# reboot), active (running now), and pushing (the dashboard has actually
# received a frame). A relay standing by with no dashboard configured is
# enabled and active and pushes nothing, which is the whole point of the split
# install, so folding the three into one answer would either lie about a split
# host or refuse a healthy one.
RELAY_UNIT="aperire-relay${INSTANCE:+-$INSTANCE}"
RELAY_CONF="${ETC_APERIRE}/relay${INSTANCE:+-$INSTANCE}.conf"
RELAY_PUSH_TRIES="${APERIRE_RELAY_PUSH_TRIES:-10}"
RELAY_PUSH_SLEEP="${APERIRE_RELAY_PUSH_SLEEP:-2}"

relay_unit_enabled() { [[ "$(systemctl is-enabled "$RELAY_UNIT" 2>/dev/null || true)" == "enabled" ]]; }
relay_unit_active()  { [[ "$(systemctl is-active  "$RELAY_UNIT" 2>/dev/null || true)" == "active"  ]]; }

# The fourth reading, and the one that separates "standing by" from "working"
# on a split host. Standing by is an empty dashboard_url, which is a thing the
# config says, not a thing the role implies: this installer is idempotent and
# meant to be re-run after a pull, so the second run happens on a host where
# the operator has already filled the file in, and telling them then that the
# relay names no dashboard would be a templated claim about a service.
relay_dashboard_url() {
  [[ -r "$RELAY_CONF" ]] || return 0
  sed -nE 's/^[[:space:]]*dashboard_url[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$RELAY_CONF" | head -1
}

# The dashboard's own answer for how long ago it last took a frame from a
# relay. Prints the number, or nothing.
#
# Two things this must not do. It must not use `curl -f`: /healthz answers 503
# while the node is still acquiring its first ledgers, which is the normal
# state of a box five minutes old, and -f would throw away the body that has
# the answer in it. And a missing or null field must read as "no push", never
# as 0: the field is null until the first frame lands, and a null that parses
# to zero would report a relay that has never connected as one that pushed
# this instant. That is this project's own recurring bug, one layer down.
relay_push_age_ms() {
  local body v
  body="$(curl -sS --max-time 3 "http://127.0.0.1:$(fleet_dash_port)/healthz" 2>/dev/null || true)"
  [[ -n "$body" ]] || return 1
  v="$(printf '%s' "$body" | sed -nE 's/.*"relay_last_push_ms"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' | head -1)"
  [[ -n "$v" ]] || return 1
  printf '%s' "$v"
}

# Bounded retry rather than one instantaneous read: the dashboard may have been
# restarted seconds ago to pick up the relay token, and the relay's first frame
# lands a moment after that. Under a minute old counts as pushing.
RELAY_PUSH_AGE=""
relay_is_pushing() {
  local i v
  echo "  ${E_DIM}asking http://127.0.0.1:$(fleet_dash_port)/healthz whether the relay has pushed,${E_OFF}" >&2
  echo "  ${E_DIM}up to ${RELAY_PUSH_TRIES} times, before saying anything about it${E_OFF}" >&2
  for (( i = 1; i <= RELAY_PUSH_TRIES; i++ )); do
    if v="$(relay_push_age_ms)" && [[ "$v" -lt 60000 ]]; then
      RELAY_PUSH_AGE="$v"
      return 0
    fi
    sleep "$RELAY_PUSH_SLEEP"
  done
  return 1
}

# What to print when one of the three readings says no. Names the reading that
# failed and the one command that explains it, in place of the sentence that
# would have been a claim.
relay_shortfall() {
  echo
  if ! relay_unit_enabled; then
    echo "  ${S_RED}Relay: NOT enabled. It will not come back after a reboot.${S_OFF}"
    echo "         ${S_DIM}systemctl is-enabled ${RELAY_UNIT}  ->  $(systemctl is-enabled "$RELAY_UNIT" 2>/dev/null || echo '<no answer>')${S_OFF}"
    echo "         Fix:  sudo systemctl enable ${RELAY_UNIT}"
  fi
  if ! relay_unit_active; then
    echo "  ${S_RED}Relay: NOT running.${S_OFF}"
    echo "         ${S_DIM}systemctl is-active ${RELAY_UNIT}  ->  $(systemctl is-active "$RELAY_UNIT" 2>/dev/null || echo '<no answer>')${S_OFF}"
    echo "         Read: sudo journalctl -u ${RELAY_UNIT} -n 50 --no-pager"
  elif [[ "$ROLE" == "co-located" ]]; then
    echo "  ${S_AMBER}Relay: running, and this dashboard has recorded no push from it.${S_OFF}"
    echo "         ${S_DIM}relay_last_push_ms was ${RELAY_PUSH_AGE:-null} after ${RELAY_PUSH_TRIES} tries.${S_OFF}"
    echo "         Read: sudo journalctl -u ${RELAY_UNIT} -n 50 --no-pager"
  fi
  echo
}

# ── What the closing text is allowed to say about the fleet ─────────
# Read from the report the step wrote, never templated, and a missing report
# reads as NOT paired. The whole reason the step writes a file is that a
# sentence down here about a registration up there is a claim, and a claim has
# to be read back. The same rule the Advisor step's report exists for (#140).
fleet_report_value() {
  [[ -n "${FLEET_REPORT:-}" && -s "${FLEET_REPORT}" ]] || return 0
  sed -n "s/^$1=//p" "$FLEET_REPORT" | tail -1
}

# One detail sentence, as a sentence (P3-078).
#
# Every one of these is read off the pair command or written as a mid-sentence
# clause, so it arrives in lower case and on one line. Printed raw it read
# "Not paired. this run had no terminal, ..." at about 140 characters, in a
# block where every other paragraph is hand-wrapped, and the fleet guide
# printed a tidied version the product did not produce. The guide is the
# contract, so this is what makes the product match it: first letter up, and
# wrapped to the block's own width with the block's own indent.
#
# `fold -s` breaks on spaces, and a value with no spaces at all (a URL, a
# label) is left long rather than cut mid-token.
fleet_sentence() {
  local text="${1:-}"
  [[ -n "$text" ]] || return 0
  # `fold -s` keeps the space it broke on, so it is taken off here: a block
  # with trailing whitespace on half its lines is one no doc can quote.
  printf '%s' "${text^}" | fold -s -w 74 | sed -e 's/[[:space:]]*$//' -e 's/^/  /'
}

# The deferred arm's whole paragraph, verdict and reason together, which is
# what docs/FLEET-GUIDE.md prints and therefore what this has to print
# (P3-078). The other three arms have their own coloured lead line and a
# detail under it; this one is a single sentence, so splitting it made a
# two-line block out of one thought.
#
# The colour goes on after the fold, on the first line only: an escape byte
# inside the text would be counted by `fold` as width it is not.
fleet_not_paired() {
  fleet_sentence "Not paired. ${1^}" \
    | sed "1s/Not paired\./${S_AMBER}Not paired.${S_OFF}/"
}

fleet_closing_text() {
  [[ -n "$FLEET_AGGREGATOR" ]] || return 0
  local outcome detail label
  outcome="$(fleet_report_value outcome)"
  detail="$(fleet_report_value detail)"
  echo
  echo "  ${S_BOLD}───── Fleet ─────${S_OFF}"
  echo
  case "$outcome" in
    paired)
      label="$(fleet_report_value label)"
      cat <<EOF
  ${S_GREEN}Registered at ${FLEET_AGGREGATOR} as "${label}".${S_OFF} Read back from what the pair
  command printed just now, not from what this install asked for.

    read port on the aggregator:     $(fleet_report_value read_port)
    advisor port on the aggregator:  $(fleet_report_value advisor_port)
    pairing fingerprint:             $(fleet_report_value fingerprint)

  This node holds its link credential, the aggregator's fleet trust key and
  its fleet arm key, both covered by the fingerprint you pasted.
  The link comes back by itself after a reboot.
EOF
      # The arm key, from what happened and not from what a pairing usually
      # does. It is the key an "Arm" from the aggregator is checked against
      # on this host, and a host that does not hold it cannot be armed from
      # there, so a summary that said it was held would send an operator to
      # the wrong page when the arm was refused.
      case "$(fleet_report_value arm_key)" in
        trusted)
          echo "  It holds the fleet arm key too, so this host can be armed from the aggregator."
          ;;
        held)
          # #720. Paired before its Advisor: the key is kept for it, and the
          # Advisor install places it. Nothing for the operator to carry over.
          echo "  No Advisor on this host yet, so there is nothing to arm. The fleet arm key is held"
          echo "  for it: installing the Advisor places it, and the aggregator can arm this host"
          echo "  from then on. Nothing to run here for that."
          ;;
        no_advisor)
          # Not a failure, and it does not read as one (#331). This host was
          # installed without the Advisor, so there is no sealer here and
          # nothing to arm. The line is kept for the day the Advisor is added.
          echo "  No Advisor on this host, so there is nothing to arm and no fleet arm key is held."
          echo "  Everything else about the link works. If you add the Advisor later, trust the key then:"
          echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run model-key-sealer --trust-arm-key <key>${S_OFF}"
          ;;
        refused|no_sealer_script)
          echo "  ${S_AMBER}The fleet arm key was NOT trusted${S_OFF} (the pair command's own reason is above)."
          echo "  The link works without it; arming this host from the aggregator needs it. Install the"
          echo "  sealer, then:"
          echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run model-key-sealer --trust-arm-key <key>${S_OFF}"
          ;;
        *)
          echo "  ${S_AMBER}Whether the fleet arm key was trusted could not be read${S_OFF} off what the pair"
          echo "  command printed. Look above under \"The fleet arm key\"."
          ;;
      esac
      ;;
    unconfirmed)
      cat <<EOF
  ${S_AMBER}Not paired, and this one needs you to look before you do anything else.${S_OFF}

$(fleet_sentence "${detail:-the aggregator could not say whether it registered this node.}")

  Nothing was written on this host. Open the aggregator's Fleet registry list
  and see whether a row for this node is there. Do not run the pair command
  again first: re-running is the one action that could register it twice.
EOF
      ;;
    mismatch)
      if [[ "$(fleet_report_value dialled)" == 0 ]]; then
        cat <<EOF
  ${S_AMBER}Not paired. What was pasted is not a pairing fingerprint, so nothing was dialled.${S_OFF}

$(fleet_sentence "${detail:-it is 64 characters of 0-9 and a-f.}")

  The code was not spent: it still works until it runs out. On the aggregator,
  as root, print the fingerprint:

      ${S_CYAN}sudo aperire-fleet-arm --fingerprint${S_OFF}

  Then, at a terminal on this host, run this with the same code, or a fresh
  one if it has run out:

      ${S_CYAN}$(fleet_deferred_line)${S_OFF}
EOF
        return 0
      fi
      cat <<EOF
  ${S_AMBER}Not paired. The fingerprint you pasted is not this pairing's.${S_OFF}

$(fleet_sentence "${detail:-the whole value has to match, and it did not.}")

  Nothing was sent to the aggregator and nothing was written here. On the
  aggregator, as root, print it again:

      ${S_CYAN}sudo aperire-fleet-arm --fingerprint${S_OFF}

  If what you pasted was exactly that, stop: the keys this node was offered
  are not the ones root on that aggregator holds. Otherwise mint a fresh code
  and, at a terminal on this host:

      ${S_CYAN}$(fleet_deferred_line)${S_OFF}
EOF
      ;;
    refused)
      cat <<EOF
  ${S_AMBER}Not paired. The pairing was refused:${S_OFF}

$(fleet_sentence "${detail:-no reason was given.}")

  Everything else on this host is installed, enabled and running. When you
  have a fresh code, at a terminal on this host:

      ${S_CYAN}$(fleet_deferred_line)${S_OFF}
EOF
      ;;
    broke)
      cat <<EOF
  ${S_AMBER}Not paired. The pair command did not finish:${S_OFF}

$(fleet_sentence "${detail:-it gave no reason, and what it printed is above.}")

  Everything else on this host is installed, enabled and running. Read what it
  printed above, then run it again at a terminal on this host:

      ${S_CYAN}$(fleet_deferred_line)${S_OFF}
EOF
      ;;
    *)
      cat <<EOF
$(fleet_not_paired "${detail:-the step did not report an outcome, so nothing is claimed here.}")

  Everything else on this host is installed, enabled and running. Nothing is
  half-done and nothing was rolled back. One line pairs it, at a terminal on
  this host, once you have minted a code on the aggregator:

      ${S_CYAN}$(fleet_deferred_line)${S_OFF}
EOF
      ;;
  esac
}

# #741: on a host that signs for a fleet, the pairing fingerprint a node asks
# for, printed by ROOT (aperire-fleet-arm --fingerprint, which reads this
# host's two keys and writes nothing). The dashboard never shows it, because
# the dashboard's account is the one thing that could put a different arm key
# in front of a node. Silent on a host that is not an aggregator; one line on
# an aggregator whose broker grant predates the grant making its arm key.
#
# The value is read from STDOUT ALONE, which carries exactly one line of 64
# lowercase hex (every sentence goes to stderr), and matched whole. The same
# rule as FLEET_PAIRING_FINGERPRINT_HEX in dashboard/types/fleet-link-contract.ts.
#
# It runs the INSTALLED command, root-owned at a fixed name (placed with the
# fleet broker grant), never the tree's copy: the tree is the dashboard
# account's until ADR 0024 separates them, and this is the value the node's
# operator trusts. A host without it is not set up to pair nodes, and says
# nothing here.
aggregator_pairing_fingerprint_text() {
  [[ $EUID -eq 0 ]] || return 0
  # As root the program is the constant. APERIRE_FLEET_ARM_PROGRAM is a test
  # hook, and root runs whatever file it names, so only an account that is not
  # root (decided from id(1), never from $EUID, which bash imports from the
  # environment, #1109) may point it elsewhere. An id that cannot be read is
  # root's answer (#1123).
  local cmd=/usr/local/sbin/aperire-fleet-arm uid
  uid="$(/usr/bin/id -u 2>/dev/null)" || uid=0
  [[ "$uid" == 0 ]] || cmd="${APERIRE_FLEET_ARM_PROGRAM:-$cmd}"
  [[ -f "$cmd" && ! -L "$cmd" ]] || return 0
  local out rc=0 fp
  out="$(bash "$cmd" --fingerprint 2>/dev/null)" || rc=$?
  case "$rc" in
    0)
      fp=''
      [[ "$out" =~ ^[0-9a-f]{64}$ ]] && fp="$out"
      [[ -n "$fp" ]] || return 0
      echo
      echo "  ${S_BOLD}───── Pairing fingerprint ─────${S_OFF}"
      echo
      echo "      ${fp}"
      echo
      echo "  A node you pair with this aggregator asks you to paste this. It covers the"
      echo "  fleet trust key and the fleet arm key. Print it again any time, as root here:"
      echo "      ${S_CYAN}sudo aperire-fleet-arm --fingerprint${S_OFF}"
      ;;
    3)
      echo
      echo "  ${S_BOLD}───── Pairing fingerprint ─────${S_OFF}"
      echo
      echo "  This host signs for a fleet and has no fleet arm key yet, so there is no"
      echo "  pairing fingerprint to print. Its pairing grant predates the grant making"
      echo "  the key. Run the update again here, which installs the new grant, then print"
      echo "  the fingerprint:"
      echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
      echo "      ${S_CYAN}sudo aperire-fleet-arm --fingerprint${S_OFF}"
      ;;
    *) : ;;
  esac
  return 0
}

AUTHN="${REPO_DIR}/dashboard/config/authn.yaml"
authn_is_localhost() { authn_public_url_is_local "$AUTHN"; }

cat <<EOF

  ${S_BOLD}───── installation complete ─────${S_OFF}

  Role:  $ROLE

EOF

case "$ROLE" in
  dashboard|co-located)
    # The operator's address, guessed from the account that ran the install so
    # the two commands below can be pasted rather than transcribed. Both
    # commands must carry the SAME address, `magic-link` looks the operator up
    # by it, so it is substituted once here instead of appearing twice as a
    # placeholder that only gets edited once.
    # `|| true`: git config exits 1 when the key is unset, and under `set -e`
    # a failing command substitution in an assignment would end the install
    # here, after everything worked, on the line whose only job is to be
    # helpful.
    OP_EMAIL="$(run_as_user -c 'git config --get user.email' 2>/dev/null | head -1 || true)"
    [[ "$OP_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || OP_EMAIL="you@example.com"
    if [[ $QUIET_EXISTING -eq 1 ]]; then
      # An already-set-up host. Everything the first-install text says is
      # either done (operators, passkeys) or false here: authn.yaml naming
      # localhost is the shipped default a first install has not edited yet,
      # and this host's operators enrolled against whatever it names now.
      cat <<EOF
  This host was already set up, so nothing above is a first step.

  What this run changed:   the unit files, written and reloaded, and whatever
                           each step above read back.
  What it did not touch:   ${ETC_APERIRE}, your database, the config files you
                           edited, your operators and their passkeys.
EOF
    elif authn_is_localhost; then
      cat <<EOF
  ${S_AMBER}───── do this BEFORE step 1 ─────${S_OFF}

  ${AUTHN}
  still names localhost, which is the shipped default.

  The enrollment link is built from public_url, and the passkey is bound to
  rp_id. On a machine you will browse from yourself, localhost is right and
  there is nothing to do here. On any other host (a VPS, a LAN box, anything
  reached by name) enrolling against localhost gives you a link nobody can
  open and a passkey bound to the wrong origin. Both have to be thrown away
  and enrolled again.

  So set both values first:

      public_url: https://<the address operators type>
      rp_id:      <that same host name, no scheme, no port>

  then restart the dashboard:

      systemctl restart aperire-server${INSTANCE:+-$INSTANCE}

EOF
    fi
    [[ $QUIET_EXISTING -eq 1 ]] || cat <<EOF
  Next steps:
    1. Create the first operator, one command, which also prints the
       enrollment URL for their passkey. The role is yours to choose:
       admin may approve Advisor actions, monitor sees everything and
       approves nothing. Your first operator wants admin:
         ${S_CYAN}aperire-auth add ${OP_EMAIL} --role admin${S_OFF}

       (Substitute the address you will sign in with. The URL is
       single-use and expires in minutes; if it lapses before it's
       redeemed, re-issue with \`aperire-auth magic-link ${OP_EMAIL}\`,
       the account keeps. It is also emailed, once an email channel is
       configured; nothing is sent before that, and the printed URL is
       the whole story until then.)

       aperire-auth was installed to ~/.local/bin. If that was not already
       on your PATH, open a new shell first.

    2. Open that URL on a device with biometrics and register your passkey.

    3. Verify the service:
         systemctl status aperire-server${INSTANCE:+-$INSTANCE}
         curl -sS http://127.0.0.1:$(fleet_dash_port)/healthz

  See docs/AUTH-GUIDE.md and docs/DEPLOYMENT-GUIDE.md
  for the full operator workflow.
EOF
    if [[ "$ROLE" == "co-located" ]]; then
      echo
      if relay_unit_enabled && relay_unit_active && relay_is_pushing; then
        cat <<EOF
  ${S_GREEN}Relay (co-located): enabled, running, and pushing.${S_OFF} This dashboard took a
  frame from it ${RELAY_PUSH_AGE}ms ago, read from /healthz just now. It is
  wired to loopback with a token this install paired on both sides, it runs
  unprivileged, and it comes back after a reboot. Nothing to do.

  If Network-tab connection-count charts read 0 with a renamed node binary
  (xrpld/xahaud), pin the node ports in /etc/aperire/relay.conf, see
  docs/RELAY-REFERENCE.md (connection counts).
EOF
      else
        echo "  ${S_AMBER}───── the relay is not where it should be ─────${S_OFF}"
        relay_shortfall
      fi
    fi
    # The Advisor's own last step, printed from the same file the one-line
    # install prints it from. Two copies of an instruction is how they stop
    # being the same instruction, and these two paths had already drifted into
    # two different hosts once.
    if [[ $WITH_ADVISOR -eq 1 ]]; then
      echo
      if [[ ${ADVISOR_TOKEN_UNREADABLE:-0} -eq 1 ]]; then
        echo "  ${S_RED}───── the Advisor step FAILED ─────${S_OFF}"
        echo
        echo "  The Advisor runs, but its move onto its own account refused and put the"
        echo "  previous unit back; its own lines above say why. The dashboard runs as"
        echo "  aperire-dashboard and cannot read the Advisor's token, so the Advisor tab"
        echo "  does not work. Once that reason is put right, retry the move:"
        if [[ -n "$INSTANCE" ]]; then
          echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run advisor-account${INSTANCE:+ --instance $INSTANCE}${S_OFF}"
        else
          echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
          echo "      (at a terminal, and answer Y when it offers to move the Advisor)"
        fi
        echo
      elif [[ ${ADVISOR_ACCOUNT_STAYED:-0} -eq 1 ]]; then
        echo "  ${S_AMBER}───── the Advisor is NOT on its own account ─────${S_OFF}"
        echo
        echo "  It is installed and answering, but it runs on the dashboard's account,"
        echo "  a retired arrangement. The move refused and put the previous unit back;"
        echo "  its own lines above say why. Once that is put right, finish it:"
        echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
        echo
      elif [[ ${ADVISOR_STEP_FAILED:-0} -eq 1 ]]; then
        echo "  ${S_AMBER}───── the Advisor did not finish ─────${S_OFF}"
        echo
        echo "  What it reported is above, and nothing here can add to it. It is safe"
        echo "  to run the update again once that is put right:"
        echo "      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --update --force${S_OFF}"
        echo
      else
        echo "  ${S_BOLD}───── Advisor ─────${S_OFF}"
        echo
        echo "  It is installed, running, and reads your node. The model comes last,"
        echo "  after steps 1 and 2 above: the panel is behind an admin session, so"
        echo "  create your operator and enroll the passkey first."
        echo
        # Read from what the step reported, never templated: a host whose sealer
        # could not be armed is given the terminal instead of a browser it
        # cannot seal from. A report that is missing reads as not armed.
        bash "${SCRIPTS_DIR}/install-advisor-stack.sh" \
          --model-steps --dir "$REPO_DIR" --report "${ADVISOR_REPORT:-}"
      fi
    fi
    fleet_closing_text
    aggregator_pairing_fingerprint_text
    ;;
  validator)
    if relay_unit_enabled && relay_unit_active; then
      RELAY_URL="$(relay_dashboard_url)"
      if [[ -n "$RELAY_URL" ]]; then
        cat <<EOF
  ${S_GREEN}The relay is installed, enabled and running,${S_OFF} and ${RELAY_CONF} points it at

      ${RELAY_URL}

  which was already in the file, so this run left it alone. Whether the far
  end accepts the push is the dashboard's answer, not this host's:

    sudo systemctl status ${RELAY_UNIT}
    sudo journalctl -u ${RELAY_UNIT} -n 30 --no-pager
    curl -sS http://127.0.0.1:7800/healthz    # on the DASHBOARD host,
                                              # relay_last_push_ms should be small

  A 403 there means the token crossed the network in the clear and the
  dashboard refused it; a 401 means the token is not in that host's
  RELAY_TOKENS. See docs/RELAY-REFERENCE.md.
EOF
      else
        cat <<EOF
  ${S_GREEN}The relay is installed, enabled and running,${S_OFF} and it is standing by.

  ${RELAY_CONF} names no dashboard, which was read from the file just now,
  because only you know which one collects from this host. So the service
  dials nothing, pushes nothing, and says exactly that once in its journal.
  It is enabled, so it comes back the same way after a reboot.

  Two edits and one command finish it:

    1. Fill in both values:
         sudo editor ${RELAY_CONF}

       dashboard_url  ws://127.0.0.1:7800/ingest through a tunnel, or
                      wss://<dashboard>/ingest with TLS in front. A plain ws
                      URL to another host sends the token in the clear, and a
                      dashboard bound off loopback refuses it with 403.
       auth_token     must match RELAY_TOKENS in /etc/aperire/aperire.env on
                      the dashboard host. Add it there and restart that
                      dashboard first, or the relay's first push is a 401.

    2. Pick it up. Restart, not \`enable --now\`: the unit is already enabled
       and already running, so \`--now\` does nothing and the process keeps the
       config it started with.
         sudo systemctl restart ${RELAY_UNIT}
         sudo systemctl status ${RELAY_UNIT}
         sudo journalctl -u ${RELAY_UNIT} -n 30 --no-pager

  See docs/RELAY-REFERENCE.md for full reference.
EOF
      fi
    else
      echo "  ${S_AMBER}───── the relay is not where it should be ─────${S_OFF}"
      relay_shortfall
      echo "  Once it is up, fill in dashboard_url and auth_token in"
      echo "  ${RELAY_CONF} and restart it."
      echo "  See docs/RELAY-REFERENCE.md for full reference."
    fi
    ;;
  cli-only)
    # The two lines below are for somebody who has just been given the command
    # for the first time. On a host that already had it, the CLI installer's
    # own read-back above is the whole story.
    [[ $QUIET_EXISTING -eq 1 ]] || cat <<'EOF'
  Next steps:
    Try:  aperire-auth list
    (Open a new shell first if ~/.local/bin wasn't already on PATH.)
EOF
    ;;
esac

# The closing list of the copies root refused, said where it is read
# (#764). $1 = the lines this run added to the refusal file, $2 = the tree.
# A line the account check could not run for ends in a tab and "accounts"
# (rd_note_refused): it was never compared with the release, so it is not told
# as a file that changed (#1089).
# get-aperire.sh has its own, for the list it folds together.
install_report_refused() {
  local lines="$1" tree="$2" line n=0 judged=0 unjudged=0 who
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    n=$((n + 1))
    if [[ "$line" == *$'\t'accounts ]]; then unjudged=$((unjudged + 1)); else judged=$((judged + 1)); fi
  done <<<"$lines"
  echo
  echo "  ${E_RED:-}───── root refused to copy $n file(s) out of ${tree} ─────${E_OFF:-}"
  echo
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "      ${line%%$'\t'*}"
  done <<<"$lines"
  echo
  if [[ $judged -gt 0 ]]; then
    who="Each one"
    [[ $unjudged -eq 0 ]] || who="Each one but the $unjudged the account check could not run for"
    echo "  $who is a file that is not the one this release shipped, or a path"
    echo "  a service account can change; the lines at each refusal say which. Root"
    echo "  kept the copy it already had. Find what changed the tree, then put the"
    echo "  release back as it shipped: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  if [[ $unjudged -gt 0 ]]; then
    [[ $judged -eq 0 ]] || echo
    who="The account check could not run: systemd did not answer (the line at each refusal names the call)."
    [[ $judged -eq 0 ]] || who="The account check could not run for $unjudged of them: systemd did not answer (the line at each of those names the call)."
    echo "  $who"
    echo "  Those files were never compared with the release, so nothing here says the"
    echo "  tree changed. Root kept the copy it already had. Run the update again to"
    echo "  retry the check: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
}

# A root copy refused anywhere in this run, listed last, where it is read,
# and the run ends 4 (#764). Root kept the copy it already had of each one.
REFUSED_NOW="$(tail -n +"$((REFUSED_AT_START + 1))" "$RD_REFUSED_LOG" 2>/dev/null || true)"
if [[ -n "$REFUSED_NOW" ]]; then
  install_report_refused "$REFUSED_NOW" "$REPO_DIR"
  exit 4
fi

# Last, after every closing block has printed: an Advisor left on the
# dashboard's account is a finished install with one step refused, not a
# success, and a caller reading only the exit code has to see that (#806).
if [[ ${ADVISOR_ACCOUNT_STAYED:-0} -eq 1 ]]; then
  exit 3
fi
