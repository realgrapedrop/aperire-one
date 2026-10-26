#!/usr/bin/env bash
# Install and start aperire-advisord — the Advisor's read-only state service.
#
# The dashboard's Advisor tab reads from this. Without it the tab still loads
# and its metric cards still work, because those come from the dashboard's own
# store; the Advisor panels say plainly that the service is not answering
# rather than rendering empty and reading like "nothing to report".
#
# Compiles to a real binary rather than running `go run` under systemd. A
# supervised service that recompiles on every restart takes a build failure as
# a startup failure, which is a bad way to find out about a syntax error.
#
# To undo:
#   sudo systemctl disable --now aperire-advisord
#   sudo rm /etc/systemd/system/aperire-advisord.service

set -euo pipefail

# Where this program and its siblings are (ADV_SELF), and the install tree it
# acts on (REPO): a directory and its parent from a checkout, two when it is
# a copy root staged out of the release and APERIRE_INSTALL_TREE names the
# tree (#764). Code is loaded and run from ADV_SELF only.
ADV_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$ADV_SELF/.." && pwd)}"
# The one way anything here asks docker what is running, and the one place
# that tells a refused answer from an absence (#142).
if [[ ! -r "$ADV_SELF/docker-ask-lib.sh" ]]; then
  echo "error: $ADV_SELF/docker-ask-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/docker-ask-lib.sh
. "$ADV_SELF/docker-ask-lib.sh"
# The two files under advisor/state this script creates, the approval token and
# the reveal window, are planted through scripts/state-file.py so no root call
# resolves a name the account that owns that directory could redirect (#661).
# Checked here rather than at the plant, which is two thirds of the way through
# an install: a host without python3 should hear it before anything is built.
# install-advisor-account.sh, which the same stack runs, has required python3
# since #652, so this is a new requirement on no host that completes a stack.
if [[ ! -r "$ADV_SELF/state-file.py" ]]; then
  echo "error: $ADV_SELF/state-file.py is missing from this checkout" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found, and the Advisor's state files are planted through it" >&2
  echo "       Debian or Ubuntu:  sudo apt-get install -y python3" >&2
  echo "       RHEL or Fedora:    sudo dnf install -y python3" >&2
  exit 1
fi
# One Advisor per node, paired with one dashboard (ADR 0009). The instance
# name selects the unit and the listen port together, so a second pairing on
# the same host collides with nothing. Empty is the single-instance layout.
INSTANCE="${APERIRE_INSTANCE:-}"
if [[ -n "$INSTANCE" && ! "$INSTANCE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; then
  echo "error: instance name must be lowercase letters, digits and dashes" >&2
  exit 2
fi
SUFFIX="${INSTANCE:+-$INSTANCE}"
ADVISOR_PORT="${APERIRE_ADVISOR_PORT:-7810}"
# The dashboard this Advisor reads from (ADR 0008). Both directions have to
# name the same pairing: without this the second instance's Advisor asked the
# FIRST instance's dashboard for its metrics — refused, correctly, by a token
# that belongs to the other pairing, but pointed at the wrong node's data.
# Default from the HOST's own truth, not a constant: /etc/aperire/aperire.env
# is where a dashboard's PORT lives when it isn't 7800, and baking 7800 into
# the unit on a :7900 box cost three advisords their metric reads on
# 2026-08-14 — found by node1's own Advisor diagnosing its dashboard as down.
DASH_PORT="${APERIRE_PORT:-}"
if [[ -z "$DASH_PORT" && -r /etc/aperire/aperire.env ]]; then
  DASH_PORT="$(awk -F= '$1=="PORT"{print $2; exit}' /etc/aperire/aperire.env)"
fi
DASH_PORT="${DASH_PORT:-7800}"
# The one declared fact everything below branches on. Read once, here, so the
# container-detection block and the wrapper configuration below agree with
# each other instead of two separate awk calls drifting apart. Absent means
# container, the same default the wrapper's own parser uses, so an existing
# host is untouched by this.
# The facts read out of the wrapper's configuration: the node's kind, the
# directories the wrapper writes into, the container, and whether the unit
# starts the wrapper through sudo. A function because they are read TWICE:
# once here, for the detection below, and again right before the unit is
# written, after this script's own wrapper-configure step has had its say
# (#767). On a first run nothing has written node-wrapper.conf yet, so the
# first read finds nothing, and a unit written from it carried no
# ReadWritePaths for the node's own config: the first upgrade then died
# backing that file up on "Read-only file system".
read_node_facts() {
# The one declared fact everything below branches on. Read once per call, so
# the container-detection block and the wrapper configuration agree with
# each other instead of two separate awk calls drifting apart. Absent means
# container, the same default the wrapper's own parser uses, so an existing
# host is untouched by this.
NODE_KIND=""
if [[ -r /etc/aperire/node-wrapper.conf ]]; then
  NODE_KIND="$(awk -F= '$1=="KIND"{sub(/^[^=]*=/,""); print; exit}' /etc/aperire/node-wrapper.conf)"
fi

# The directories the wrapper writes into when it acts. ProtectHome makes
# the home read-only inside this unit's namespace, and that applies to the
# wrapper the unit spawns — so without these an upgrade fails backing up a
# file it can read perfectly well.
NODE_RW=""
if [[ -r /etc/aperire/node-wrapper.conf ]]; then
  for k in CONFIG_FILE COMPOSE_FILE; do
    f=$(awk -F= -v key="$k" '$1==key{sub(/^[^=]*=/,""); print; exit}' /etc/aperire/node-wrapper.conf)
    [[ -n "$f" ]] || continue
    d=$(dirname "$f")
    [[ -d "$d" ]] || continue
    case " $NODE_RW " in *" $d "*) continue ;; esac
    NODE_RW="$NODE_RW $d"
  done
fi

# The container this Advisor watches. Taken from the wrapper's own config
# when it has been written, because that value was discovered from the
# running deployment. Without it advisord falls back to its compiled-in
# default and, whenever discovery fails, reports a node name that is not
# this host's — "rippledvalidator" on a box whose container is xrpldstock,
# which reads as the Advisor watching the wrong thing.
#
# Native has no container at all, so this stays empty on KIND=native: the
# unit is written with no --container flag rather than one holding the
# systemd unit name, which is the exact lying shape #396 was filed over.
# advisord's own default (SERVICE from this same file, read at start-up)
# already gives it the same identity this block would have handed it, with
# no flag needed to carry it. An explicit APERIRE_NODE_CONTAINER override is
# still honoured on any kind: that is the operator naming a value by hand,
# not this script inventing one. A value the one-container guess below found
# is kept when the configuration still names none.
local conf_container=""
if [[ "$NODE_KIND" != native && -r /etc/aperire/node-wrapper.conf ]]; then
  conf_container="$(awk -F= '$1=="SERVICE"{sub(/^[^=]*=/,""); print; exit}' /etc/aperire/node-wrapper.conf)"
fi
if [[ -n "${APERIRE_NODE_CONTAINER:-}" ]]; then
  NODE_CONTAINER="$APERIRE_NODE_CONTAINER"
elif [[ "$NODE_KIND" == native ]]; then
  NODE_CONTAINER=""
elif [[ -n "$conf_container" ]]; then
  NODE_CONTAINER="$conf_container"
fi

# No --sudo-wrapper, on any shape (ADR 0025). This unit is the one the
# Advisor runs on before install-advisor-account.sh moves it to its own
# account, and that move is what gives it the root socket. There is no sudo
# route for it to take in between: under this unit's NoNewPrivileges sudo
# refuses anyway, which is why the flag this used to set on a native host
# never worked here.
return 0
}
NODE_CONTAINER=""
read_node_facts
# Last resort, only when exactly ONE container runs: a box with no wrapper
# conf got the compiled default ("rippledvalidator" on a host whose
# container is aperire-validator — found live 2026-08-14). One container is
# an answer; several is a guess, and a guess here reads as the Advisor
# watching the wrong thing, so several stays empty.
#
# A docker that refuses is not a host with no containers on it, so it does not
# reach that rule at all: nothing is detected, which is what an unanswered
# question is worth, and the run says so instead of leaving the operator to
# wonder why the Advisor watches nothing (#142).
#
# Skipped entirely on KIND=native: there is no docker to ask, and "docker
# would not say what is running" is a false complaint on a host that never
# had docker in the first place. `docker_ask` would answer "not installed
# here" as its one line of text, which the code below would otherwise read
# as the name of a single running container.
if [[ "$NODE_KIND" != native && -z "$NODE_CONTAINER" ]]; then
  # On a non-zero return _SAID is docker's complaint, not the list.
  _SAID=''; _ASK=0
  _SAID="$(docker_ask '{{.Names}}')" || _ASK=$?
  if [[ $_ASK -eq 2 ]]; then
    echo "   docker would not say what is running (${_SAID}), so no node"
    echo "   container was detected. If this host runs one, name it and run again:"
    echo "     sudo APERIRE_NODE_CONTAINER=<name> bash $0"
  else
    mapfile -t _RUNNING < <(printf '%s\n' "$_SAID" | grep -v '^[[:space:]]*$')
    if [[ ${#_RUNNING[@]} -eq 1 ]]; then
      NODE_CONTAINER="${_RUNNING[0]}"
      echo "   detected the one running container: $NODE_CONTAINER"
    fi
  fi
fi
# A variable only so a test suite can point a whole run at a fake directory
# and read back what this script actually wrote (P2-093), the same override
# install-model-key-sealer.sh already takes. Nothing on a real host should
# ever set this to anything but the default.
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="aperire-advisord${SUFFIX}"
# The Advisor's account name is written into User= and Group=, so it is held
# to the shape useradd takes: a newline in it would write unit lines. Only
# root sets it, so this is hardening and not a boundary.
if [[ -n "${APERIRE_ACCOUNT:-}" && ! "${APERIRE_ACCOUNT}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "error: APERIRE_ACCOUNT must be a plain account name: lowercase letters, digits, dashes and underscores, up to 32, not starting with a digit or dash" >&2
  exit 2
fi
UNIT="$UNIT_DIR/${UNIT_NAME}.service"
BIN="$REPO/advisor/bin/aperire-advisord"
# The recovery unit named on OnFailure= below (#541). One per instance, same
# suffix as the unit it watches, so a second pairing on this host does not
# trip the first one's recovery. Named here; written by
# advisord-credcheck-lib.sh, sourced below, which is the one place that may
# do either (P2-093).
CREDCHECK_UNIT_NAME="aperire-advisord-credcheck${SUFFIX}"
if [[ ! -r "$ADV_SELF/advisord-credcheck-lib.sh" ]]; then
  echo "error: $ADV_SELF/advisord-credcheck-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/advisord-credcheck-lib.sh
. "$ADV_SELF/advisord-credcheck-lib.sh"
if [[ ! -r "$ADV_SELF/advisord-restart-lib.sh" ]]; then
  echo "error: $ADV_SELF/advisord-restart-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/advisord-restart-lib.sh
. "$ADV_SELF/advisord-restart-lib.sh"
# How this host keeps a model key, and the drop-in that loads it (#708). The
# same library the sealer and the credential check read, so the three cannot
# disagree about which method a host uses or what the directive says.
if [[ ! -r "$ADV_SELF/model-key-method-lib.sh" ]]; then
  echo "error: $ADV_SELF/model-key-method-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/model-key-method-lib.sh
. "$ADV_SELF/model-key-method-lib.sh"
# Where the wrapper the unit names lives (ADR 0024): the root-owned copy
# install-node-wrapper.sh places in /usr/local/sbin, never the file in this
# checkout. Behind the Advisor's root socket that copy is what root runs
# (ADR 0025), and a unit naming a file the dashboard's account can rewrite
# would hand that account root the next time the Advisor asked for anything.
if [[ ! -r "$ADV_SELF/trusted-path-lib.sh" ]]; then
  echo "error: $ADV_SELF/trusted-path-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/trusted-path-lib.sh
. "$ADV_SELF/trusted-path-lib.sh"
WRAPPER_PATH="$(trusted_wrapper_path "$INSTANCE")"

# The account the service runs as, before the optional move to a dedicated
# one. Under sudo — which is how this is documented and how install.sh calls
# it — `id -un` is root, and root is exactly wrong here: the unit sets
# CapabilityBoundingSet= (empty), so its root has no CAP_DAC_OVERRIDE and is
# an ordinary uid 0 bound by mode bits. Ubuntu creates home directories 0750,
# so that root cannot traverse the operator's home to reach this repository —
# it cannot even stat its own state directory, and dies at startup unable to
# establish its token. The operator's account owns the repository and needs no
# capability to read it. This also matches what this script prints afterwards,
# which describes the account it runs as being in the docker group.
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_GROUP="$(id -gn "$RUN_USER")"

# The account that actually owns the Advisor's state on THIS host, which is
# not always RUN_USER above (#568). Once install-advisor-account.sh has moved
# the service onto its own account, every chown and chgrp below has to name
# THAT account, resolved from the unit's own User= line, or a re-run of this
# script hands the fleet trust file's group and the state directories back
# to the invoking operator, who is not in the group the dedicated account
# reads them through. See scripts/advisor-owner-lib.sh for the fuller story.
if [[ ! -r "$ADV_SELF/advisor-owner-lib.sh" ]]; then
  echo "error: $ADV_SELF/advisor-owner-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/advisor-owner-lib.sh
. "$ADV_SELF/advisor-owner-lib.sh"
ADVISOR_OWNER_USER="$(advisor_owner_user "$UNIT" "$RUN_USER")"

# Born on the Advisor's own account (#893). The stack that runs this script
# moves the Advisor onto its own account straight afterwards
# (install-advisor-account.sh), and every checked copy root makes in between
# counts whoever the unit names as a service account. A unit that names the
# operator's login, who owns this tree and is usually in the docker group,
# makes root refuse to copy anything out of it: the credential recovery
# program here, and the wrapper and broker in the account step. So on a host
# with no Advisor unit yet, the stack asks for the unit to name the
# Advisor's account from the start, and for the start itself to wait for the
# account step, which makes the account, hands it the state and the socket,
# and starts the unit as it. Nothing then runs as the login at any point.
# Only the stack sets APERIRE_ADVISOR_ACCOUNT_NEXT; run on its own, this
# script keeps starting the Advisor itself.
#
# A unit still carrying the waiting note below is the same state seen from a
# second run: an account step that stopped before it finished, and put the
# unit back as it found it. The move has not happened, nothing runs as the
# account, and the state is the operator's. It is written again, not read as
# a moved Advisor. The account step writes its own unit without the note, so
# the note is gone exactly when the move is done.
UNIT_NOTE="Written by install-advisord.sh."
WAITING=0
grep -q '^# Waiting for install-advisor-account\.sh' "$UNIT" 2>/dev/null && WAITING=1
# The same state reached another way: a unit that names the operator's login,
# nobody runs, and no move has ever touched. A hand-run of this script on a
# host that root refuses it on left exactly that behind (#898 review), and so
# did a first install on main before #893. Both stop before the service is
# enabled or started, so the leftover is exactly: not enabled, and ActiveState
# "inactive". Anything else on the login is a real Advisor, stopped by hand,
# failed, or restarting, and is never rewritten here with no copy kept (#898
# review, N2). There is no .before-account beside it either, so nothing has
# moved: the stack writes it again for the Advisor's account, like a waiting
# unit.
LOGIN_UNIT=0
if [[ "${APERIRE_ADVISOR_ACCOUNT_NEXT:-0}" == 1 && -f "$UNIT" && ! -f "${UNIT}.before-account" ]] \
   && (( ! WAITING )); then
  _cur_user="$(advisor_owner_effective_property "$UNIT" User 2>/dev/null || true)"
  if [[ "$_cur_user" == "$RUN_USER" ]]; then
    _unit_enabled="$(systemctl is-enabled "$UNIT_NAME" 2>/dev/null || true)"
    _unit_active="$(systemctl is-active "$UNIT_NAME" 2>/dev/null || true)"
    if [[ "$_unit_enabled" == disabled && "$_unit_active" == inactive ]]; then
      LOGIN_UNIT=1
    fi
  fi
fi
BORN=0
UNIT_USER="$RUN_USER"
UNIT_GROUP="$RUN_GROUP"
if [[ "${APERIRE_ADVISOR_ACCOUNT_NEXT:-0}" == 1 ]] && { [[ ! -f "$UNIT" ]] || (( WAITING )) || (( LOGIN_UNIT )); }; then
  BORN=1
  UNIT_USER="${APERIRE_ACCOUNT:-aperire-advisor}"
  UNIT_GROUP="$UNIT_USER"
  UNIT_NOTE="Waiting for install-advisor-account.sh, which makes the account and starts it (#893)."
fi
(( WAITING )) && ADVISOR_OWNER_USER="$RUN_USER"
# The unit is the account's only once the account step has finished. Until
# then it names an account nothing runs as, whatever the unit says.
unit_moved() { (( ! WAITING )) && advisor_owner_moved "$UNIT" "$RUN_USER"; }

# Preflight the toolchain BEFORE announcing a build. The first operator to
# run this on a box without Go got "line 80: go: command not found", a stack
# trace where a sentence belongs. Prebuilt binaries are honored: a fleet
# operator can copy advisor/bin/* from a sibling box of the same platform
# instead of installing a compiler on every node.
#
# Go is LOOKED FOR, not asked of PATH. scripts/prepare-host.sh installs the
# pinned toolchain into /usr/local/go and puts it on PATH through
# /etc/profile.d/aperire-go.sh, which only an interactive login shell reads.
# This script runs under sudo, whose PATH has none of that, so `command -v go`
# said "not installed" on a box with a perfectly good Go in the place this
# project itself put it (first live Advisor ceremony, 2026-09-01). The
# candidates below are prepare-host's own, in its own order, so the two cannot
# disagree about whether this host has Go.
#
# Root runs none of them (#1162, ADR 0024). Every candidate is asked its version
# as the login, the account the build runs as, so no program the login chose or
# can replace ever runs as root here. The first two look like root's (this
# project's own location, the PATH this script runs with), but a PATH entry that
# sudo kept, or a parent directory the login can write, makes either one the
# login's. Asking as the login needs no walk of every parent to get that right,
# and a Go the login cannot run could not build anything for it anyway. A host
# with no login to drop to (this run is root's own, no SUDO_USER) asks as itself.
# From /, because sudo keeps the caller's directory and go refuses to run from
# one the login cannot search (a root shell in /root).
as_run_user() { # the command as the account that owns this tree, when root is running this
  if [[ $EUID -eq 0 && "$RUN_USER" != root ]]; then
    sudo -n -u "$RUN_USER" -H "$@"
  else
    "$@"
  fi
}
find_go() {
  local cand v
  for cand in /usr/local/go/bin/go "$(command -v go 2>/dev/null || true)" \
              "$(sudo -u "$RUN_USER" -H bash -lc 'command -v go' 2>/dev/null || true)"; do
    [[ -n "$cand" && -x "$cand" ]] || continue
    v="$(cd / && as_run_user "$cand" version 2>/dev/null)" || continue
    [[ -n "$v" ]] || continue
    printf '%s' "$cand"
    return 0
  done
  return 1
}
GO_BIN="$(find_go || true)"

# >>> advisord build stamp >>>
# The commit these builds carry (#650). Without it advisord reports the literal
# string "dev" from GET /v1/status forever, and the dashboard's Add an Advisor
# row reads "not measured" on a node that was installed perfectly: the sanitizer
# on the far side turns "dev" into null on purpose, so an unstamped build is
# indistinguishable from one that cannot say.
#
# This is the same value, from the same places, that prepare-host.sh already
# stamps the relay and the Advisor with (#266). Three sources, in the order
# that trusts the caller who knows most:
#
#   1. APERIRE_BUILD_COMMIT, which get-aperire.sh exports into install.sh's
#      environment off its own installed_commit(). The one-liner's fresh
#      install reaches this script through install.sh, so this is the ordinary
#      path and it carries the release the host is actually installing.
#   2. $REPO/.release, the stamp get-aperire.sh writes into the install
#      directory at the end of a successful run (ADR 0022). The Advisor's own
#      one-liner (get-aperire-advisor.sh, attaching to an install that already
#      exists) sets no environment at all, so on that path the file on disk is
#      the only thing that knows which release this tree is.
#   3. `git rev-parse` for a checkout, which is what a developer box is.
#
# The shape check is not cosmetic and it is not last. `-ldflags` is split into
# words by the Go toolchain: a ref holding `-linkmode=external -extldflags=...`
# would run a program of the ref-writer's choosing. The build runs as the login
# now (#1136), so that program would run as the login and not as root, but it is
# still a program someone else chose. Anything that is not a plain hex commit is
# refused back to "dev", which is the same honest answer prepare-host.sh gives
# and the shape the dashboard's comparator already reads as "not stamped".
release_commit() {
  [[ -r "$REPO/.release" ]] || return 0
  sed -n 's/^  "commit": "\(.*\)",\?$/\1/p' "$REPO/.release" 2>/dev/null | head -1
}
BUILD_COMMIT="${APERIRE_BUILD_COMMIT:-}"
[[ -n "$BUILD_COMMIT" ]] || BUILD_COMMIT="$(release_commit || true)"
# As the operator, not as root. This script runs under sudo and the checkout
# belongs to the invoking account, so a root `git -C` on it trips git's
# dubious-ownership refusal and answers nothing. get-aperire.sh runs the same
# question through its own as_operator for this reason, and find_go above
# already reaches into that account's shell the same way.
#
# Asked only of a real checkout. A released tree is a tarball with no .git in
# it, and without this guard every such install would run a sudo that has
# nothing to answer, which on a host where that sudo wants a password is an
# install stopping to prompt for one in the middle of a build.
if [[ -z "$BUILD_COMMIT" && -d "$REPO/.git" ]]; then
  BUILD_COMMIT="$(sudo -n -u "$RUN_USER" git -C "$REPO" rev-parse --short HEAD 2>/dev/null || true)"
fi
[[ "$BUILD_COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || BUILD_COMMIT="dev"
BUILD_LDFLAGS="-s -w -X main.version=${BUILD_COMMIT}"
# <<< advisord build stamp <<<

if [[ -z "$GO_BIN" ]]; then
  if [[ -x "$BIN" && -x "$REPO/advisor/bin/aperire-executor" ]]; then
    echo "== Using the prebuilt binaries (no Go toolchain on this host)"
    echo "   $BIN"
    echo "   $REPO/advisor/bin/aperire-executor"
    # The Advisor runs without the linter, so a host that has the other two is
    # let through, as a pre-#1131 box re-running this installer must be. But
    # Promote lints a note with it before the note reaches every Advisor, and
    # the dashboard answers 503 until it is here (#1192). Said at the point the
    # binaries are chosen, with the cost and both ways out, rather than left
    # for the first Promote to find.
    if [[ -x "$REPO/advisor/bin/knowledge-lint" ]]; then
      echo "   $REPO/advisor/bin/knowledge-lint"
    else
      {
        echo "warning: $REPO/advisor/bin/knowledge-lint is missing or not executable."
        echo "         The Advisor installs and runs without it, but Promote and the knowledge"
        echo "         pull on the dashboard cannot check a note until it is in place. With the"
        echo "         file missing they answer 503, \"no knowledge-lint on this host\"."
        echo "         Copy it from a sibling box of the same platform:"
        echo "             scp <sibling>:<repo>/advisor/bin/knowledge-lint  $REPO/advisor/bin/"
        echo "         or put Go on this host, which builds it:"
        echo "             curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run prepare-host --with-advisor"
      } >&2
    fi
  else
    # Says which of the pair is short. A host with the daemon and no executor
    # was told no prebuilt binaries were found, which is not what it has.
    if [[ ! -x "$BIN" && ! -x "$REPO/advisor/bin/aperire-executor" ]]; then
      echo "error: no Go toolchain was found, and no prebuilt binaries were found at" >&2
      echo "       $REPO/advisor/bin/" >&2
    else
      adv_short="aperire-executor"
      [[ -x "$BIN" ]] || adv_short="aperire-advisord"
      echo "error: no Go toolchain was found, and the prebuilt pair at" >&2
      echo "       $REPO/advisor/bin/ is not complete: $adv_short is missing or not executable." >&2
    fi
    echo >&2
    echo "       Looked in /usr/local/go/bin, on this PATH, and in ${RUN_USER}'s login shell." >&2
    echo >&2
    # prepare-host.sh owns the toolchain: it pins a Go version, checks the
    # download against a recorded sha256, and installs it to /usr/local/go.
    # Recommending apt here would fork that ownership and can install a Go
    # older than the minimum this project builds with, which fails later and
    # further away.
    echo "The toolchain and the Advisor binaries both come from one command:" >&2
    echo "    curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run prepare-host --with-advisor" >&2
    echo >&2
    echo "Then run this again. Or copy the three prebuilt binaries from a sibling" >&2
    echo "box of the same platform, which needs no compiler here at all:" >&2
    echo "    scp <sibling>:<repo>/advisor/bin/aperire-advisord  $REPO/advisor/bin/" >&2
    echo "    scp <sibling>:<repo>/advisor/bin/aperire-executor  $REPO/advisor/bin/" >&2
    echo "    scp <sibling>:<repo>/advisor/bin/knowledge-lint    $REPO/advisor/bin/" >&2
    echo "The first two run the Advisor. knowledge-lint is what Promote checks a note" >&2
    echo "with, and Promote refuses on a host without it." >&2
    exit 1
  fi
else
echo "== Building"
echo "   with $GO_BIN ($(cd / && as_run_user "$GO_BIN" version 2>/dev/null | awk '{print $3}'))"
echo "   stamped $BUILD_COMMIT"
# The three `go build` lines run as the operator, not as root (#1136, ADR 0024).
# advisor/bin and the source beside it belong to the login, so a root build
# compiles code the login can edit and writes the result where the login can
# replace it. Each binary is built to a scratch name in advisor/bin and renamed
# into place once all three have built, the way get-aperire.sh's update does,
# so a build that fails on the third leaves the ones that were there. The
# renames are three separate steps; if one of them fails, adv_rename_failed
# says which binaries are new and which are not. A host with no operator to
# drop to (this run is the login, or the login is root) builds as it always did.
ADV_BIN_DIR="$REPO/advisor/bin"
ADV_BIN_SFX=".new.$$"
build_as_user() { # $1 = binary name, $2 = package, built to a scratch name in advisor/bin
  # shellcheck disable=SC2016  # the program text is bash -c's own; $1 and $@ are its arguments
  as_run_user env PATH="$PATH" bash -c 'cd "$1" && shift && exec "$@"' _ "$REPO/advisor" \
    "$GO_BIN" build -ldflags "$BUILD_LDFLAGS" -o "$ADV_BIN_DIR/.$1$ADV_BIN_SFX" "$2"
}
as_run_user mkdir -p "$ADV_BIN_DIR" \
  || { echo "error: could not make $ADV_BIN_DIR as ${RUN_USER}; nothing was built" >&2; exit 1; }
adv_clear_scratch() {
  local b
  for b in aperire-advisord aperire-executor knowledge-lint; do
    as_run_user rm -f -- "$ADV_BIN_DIR/.$b$ADV_BIN_SFX" 2>/dev/null || true
  done
}
# A failed build removes its scratch names and exits. No rename has happened
# yet, so nothing in advisor/bin has been replaced.
adv_build_failed() {
  adv_clear_scratch
  echo "error: the Advisor's binaries did not build; nothing in $ADV_BIN_DIR was replaced, the ones there are as they were" >&2
  exit 1
}
# A failed rename is a different state: the binaries before it are already the
# new ones. Say which, so the half-way state is named and not denied.
adv_rename_failed() { # $1 = the binary that did not move; the rest of the list is in adv_placed
  local b not_yet=()
  adv_clear_scratch
  for b in aperire-advisord aperire-executor knowledge-lint; do
    [[ " ${adv_placed[*]:-} " == *" $b "* ]] || not_yet+=("$b")
  done
  echo "error: could not put $1 into place in $ADV_BIN_DIR." >&2
  echo "       Replaced with the new build: ${adv_placed[*]:-none}" >&2
  echo "       Not replaced: ${not_yet[*]}" >&2
  echo "       Run this installer again to finish; it builds all three and renames them again." >&2
  exit 1
}
# The daemon.
build_as_user aperire-advisord ./cmd/aperire-advisord || adv_build_failed
echo "   built aperire-advisord"
# The executor too. It is the thing an operator runs by hand, often in the
# middle of a staged change, and `go run` recompiles on every invocation: a
# build failure between the prepare and cutover stages is a bad place to
# discover a syntax error.
#
# Stamped with the same ldflags as the daemon, and with the same effect the
# other two build sites in this tree get from it today: none. cmd/aperire-executor
# has no `version` symbol to set, so `-X main.version=` on it is a silent no-op
# (`var version = "dev"` exists only in cmd/aperire-advisord/main.go). The flag
# stays anyway so all three places that build this binary (here,
# get-aperire.sh's update rebuild and prepare-host.sh) read identically, and so
# the stamp lands by itself the day that symbol is added.
build_as_user aperire-executor ./cmd/aperire-executor || adv_build_failed
echo "   built aperire-executor"
# And the corpus linter. An aggregator checks every note with it before the
# note reaches the fleet, and the Promote button answers 503 on a host that
# has none; a release install builds it nowhere else (#1131).
build_as_user knowledge-lint ./cmd/knowledge-lint || adv_build_failed
echo "   built knowledge-lint"
adv_placed=()
for _b in aperire-advisord aperire-executor knowledge-lint; do
  as_run_user mv -fT "$ADV_BIN_DIR/.$_b$ADV_BIN_SFX" "$ADV_BIN_DIR/$_b" || adv_rename_failed "$_b"
  adv_placed+=("$_b")
done
echo "   $BIN"
echo "   $ADV_BIN_DIR/aperire-executor"
echo "   $ADV_BIN_DIR/knowledge-lint"
fi

echo
# >>> advisord ownership >>>
# The shared secret the dashboard presents on every call to the Advisor.
# Generated once, 0640. It gates the whole surface, reads included, because
# loopback is a network boundary and not a user boundary — without it, any
# account on this host could read the audit ledger and the run transcripts.
# advisord generates one itself if this is missing, so the boundary always
# exists; it does not by itself enable web approval, which additionally needs
# a passkey verified against the credential store.
TOKEN="$REPO/advisor/state/approve.token"
if [[ ! -f "$TOKEN" ]]; then
  echo "== Approval token"
  mkdir -p "$(dirname "$TOKEN")"
  # The secret is minted somewhere this account controls and then moved into
  # place in ONE call (#652's class).
  #
  # This branch is reached when [[ ! -f "$TOKEN" ]], and a DANGLING symlink at
  # that name satisfies exactly that: -f follows the link and finds nothing.
  # A plain `> "$TOKEN"` would then follow it and write a freshly minted
  # shared secret into a file of the link-planter's choosing. Unlinking the
  # name first and creating a fresh file would fix that one, but it leaves a
  # gap between the two commands for the account that owns this directory to
  # put a link back before the redirect runs, and the thing crossing that gap
  # is the secret itself.
  #
  # So nothing is ever written through this path. The secret is piped into
  # scripts/state-file.py, which creates the file relative to a descriptor on
  # advisor/state with O_CREAT|O_EXCL|O_NOFOLLOW, writes it, sets the mode on
  # that descriptor, and renames the result onto this name. No root call after
  # the create resolves a name, so there is nothing for the account that owns
  # the directory to redirect.
  #
  # This was `install -m 0640` from a private temporary file, and the secret
  # was safe that way too (it lands on install's own O_EXCL inode). What was
  # not safe is install's last call: fchmodat on the PATH with no nofollow,
  # which a symlink swapped in after the create turns into root chmodding an
  # arbitrary victim to 0640 (#661, closed here).
  #
  # Through a PIPE, never an argument: /proc/<pid>/cmdline is world readable,
  # and this is the shared secret that gates the whole Advisor surface.
  head -c 48 /dev/urandom | base64 | tr -d '\n' \
    | python3 -I "$ADV_SELF/state-file.py" plant "$TOKEN" "" "" 0640 --stdin
  # Owned by the account the unit runs as (#568: ADVISOR_OWNER_USER, not the
  # invoking operator, once install-advisor-account.sh has moved this Advisor
  # onto its own account. A --keep uninstall followed by a reinstall reaches
  # this branch on a moved host, since the reinstall finds no token at all).
  # Created under sudo these land root-owned, and the service, whose root
  # has no CAP_DAC_OVERRIDE and which is not root at all once it moves to
  # its own account, then cannot write the directory it owns.
  #
  # Entry by entry, on descriptors, through the state helper (#879), not
  # `chown -R` on the name. That account writes this directory, and chown -R
  # changes a hard link to a file outside it like any other entry; the
  # helper refuses a link or a second name, says so, and carries on.
  _tok_dir="$(dirname "$TOKEN")"
  _tok_uid="$(id -u "$ADVISOR_OWNER_USER" 2>/dev/null || true)"
  if [[ "$_tok_uid" =~ ^[0-9]+$ ]]; then
    find "$_tok_dir" -print0 2>/dev/null \
      | python3 -I "$ADV_SELF/state-file.py" own-many "$_tok_uid" "" "" --root "$_tok_dir" \
      || echo "   !! some entries in $_tok_dir were left as they were (named above)" >&2
  fi
  # 0640, not 0600: when the Advisor runs as its own account the dashboard
  # reads this through the group they share. At 0600 the tab reports "no
  # advisor token readable on this host" and nothing explains why. Set on the
  # descriptor the plant above created, rather than by a chmod on the name
  # afterwards.
  echo "   $TOKEN"
  echo "   proves the caller can read a file only these services can read."
  echo "   on a host where both run as the same user that is an allow-list and"
  echo "   an audit trail, not containment — see the compact."
  echo
fi

# The fleet trust file, when this host has one. advisord reads it to verify a
# pushed credential bundle against the aggregator's public key, and a file its
# account cannot open makes every push fail with a 403 the operator only ever
# meets as a refused passkey on a node that looked fine (2026-08-19,
# stock-node2, reintroduced 2026-09-20 as #568). Here the service runs as the
# operator's own account, so the group it needs is that account's group;
# install-advisor-account.sh redoes this with the shared group when the
# service moves off it.
#
# Once that move has happened this run has no group of its own to put here:
# ADVISOR_OWNER_USER's OWN group is not the shared one either (see
# advisor-owner-lib.sh), and guessing at a name this script did not grant
# is exactly the bug. So a moved host's trust file is left alone entirely:
# it is install-advisor-account.sh's to set, and it already has.
#
# A file that holds a private_key is never widened here (#868): that is an
# aggregator's signing key, the dashboard account's alone at 0600, and the
# Advisor reads fleet-trust.pub.yaml beside it instead
# (scripts/fleet-trust-split.sh). Only a peers-only file is regrouped.
TRUST_FILE="$REPO/dashboard/config/fleet-trust.yaml"
# grep's 1 is "read it, no key"; a 2 (could not read it) is not the same
# answer and leaves the file alone.
_trust_key_rc=2
if [[ -f "$TRUST_FILE" && ! -L "$TRUST_FILE" ]]; then
  _trust_key_rc=0
  grep -q '^private_key:' "$TRUST_FILE" 2>/dev/null || _trust_key_rc=$?
fi
# Not on a unit born on the Advisor's own account (#996). Nothing runs as
# RUN_USER on that host: the account step that follows sets this file's
# shape itself (fleet-trust-split.sh), and until it does the dashboard reads
# it through the group it already has. Regrouped to the operator's group in
# between, a dashboard running as its own account (ADR 0024) could not read
# it for the 49 s the build and the account step took on a lab node, and a
# link that redialled then would have been refused.
#
# Group and mode are set on a descriptor, through the state helper (#879),
# never by chgrp and chmod on the name as root. The grep above reads the name,
# and between that read and this a name can become a link or a second name
# for a file outside dashboard/config. The helper opens it without following
# a link, refuses a file with more than one name, and changes the file it
# opened. A refusal is said and left; the dashboard still reads its own file.
if (( _trust_key_rc == 1 )) && ! unit_moved && (( ! BORN )); then
  _trust_gid="$(getent group "$RUN_GROUP" 2>/dev/null | head -1 | cut -d: -f3)"
  if [[ "$_trust_gid" =~ ^[0-9]+$ ]]; then
    python3 -I "$ADV_SELF/state-file.py" own "$TRUST_FILE" "" "$_trust_gid" 0640 \
        --root "$(dirname "$TRUST_FILE")" \
      || echo "   !! $TRUST_FILE was left as it was (named above)" >&2
  fi
fi

# Every directory the unit declares writable has to exist and be owned by the
# account that runs it, before it starts. ReadWritePaths on a missing
# directory is a namespace failure, and one owned by root is unwritable to a
# service whose capability set is empty.
#
# knowledge-fleet/ is the third: an accepted knowledge bundle is applied by
# swapping that directory (ADR 0017), so the service writes its PARENT. Its
# two layers are created here as well, so a fresh install has somewhere to
# receive a push and an operator can see where fleet knowledge lands.
mkdir -p "$REPO/advisor/state" "$REPO/advisor/evidence"
# The wrapper's own, root-owned and named in the unit below. Made here for
# the same reason as the two above: ReadWritePaths on a path that does not
# exist takes the unit down with 226/NAMESPACE.
if [[ ! -d /var/lib/aperire ]]; then
  install -d -m 0755 -o root -g root /var/lib/aperire 2>/dev/null \
    || mkdir -p /var/lib/aperire 2>/dev/null \
    || printf 'warning: could not create /var/lib/aperire; the unit names it writable and will not start without it\n' >&2
fi
# The corpus and its layers get a mode when they are CREATED and never
# afterwards. 0750 is the baseline both installers that share it start from
# (scripts/fleet-corpus-perms.sh); a bare `mkdir -p` under root's umask leaves
# 0755, and the share only adds bits to what it finds, so the corpus would end
# up readable by every account on the machine on one install path and not on
# another. `install -d` re-modes a directory that already exists, so it is
# guarded: naming a mode unconditionally would strip the setgid bit and the
# group write a previous run granted. Created by state-file.py, which sets the
# mode on the directory it made and leaves one that was already there alone
# (--mode-if-new): the test-then-create this replaced was two steps, both
# services write knowledge-fleet, and a link put at base or local between them
# turned `install -d` into a chmod on the link's target (#1048).
for _d in "$REPO/advisor/knowledge-fleet" "$REPO/advisor/knowledge-fleet/base" \
          "$REPO/advisor/knowledge-fleet/local"; do
  python3 -I "$ADV_SELF/state-file.py" mkdir "$_d" "" "" 0750 --root "$REPO/advisor" --mode-if-new \
    || echo "   !! $_d was not made or confirmed (named above); it was left as it was" >&2
done
# The account, not RUN_USER (#568): on a moved host the directories already
# belong to the account install-advisor-account.sh moved them to, and this
# has to name the same one or a bare re-run of this installer hands them
# straight back to the invoking operator, who the moved account's own unit
# cannot then be started as (the state directory it must write becomes
# unwritable the instant the service tries).
#
# On descriptors, through the state helper (#879). A plain chown on these
# names follows a link at the last one, and knowledge-fleet is written by
# both services: either could put a link at base or local and have root give
# its target away. The helper refuses a link and names it. --root is
# advisor/, so knowledge-fleet (the Advisor's own on a moved host) is never
# judged as an ancestor.
_dirs_uid="$(id -u "$ADVISOR_OWNER_USER" 2>/dev/null || true)"
if [[ "$_dirs_uid" =~ ^[0-9]+$ ]]; then
  printf '%s\0' "$REPO/advisor/state" "$REPO/advisor/evidence" \
      "$REPO/advisor/knowledge-fleet" "$REPO/advisor/knowledge-fleet/base" \
      "$REPO/advisor/knowledge-fleet/local" \
    | python3 -I "$ADV_SELF/state-file.py" own-many "$_dirs_uid" "" "" --root "$REPO/advisor" \
    || echo "   !! some of the Advisor's directories were left as they were (named above)" >&2
fi

# The group orphaned files are adopted onto below, when this host has moved
# onto a dedicated account. Resolved from the unit's own SupplementaryGroups=
# line (advisor-owner-lib.sh), never invented: an orphaned file has no
# group left to preserve, so something has to be named, and the operator's
# own group is exactly what the dedicated account cannot read through.
ADOPT_GROUP="$(advisor_owner_shared_group "$UNIT" "$RUN_USER")"
ADOPT_GROUP="${ADOPT_GROUP:-$RUN_GROUP}"

# The reveal window (#641): root's own mark that a human recently ran this
# installer, or a re-arm, on THIS box with real sudo. It gates an aggregator
# attaching this node's Advisor to an already-paired link, the second and
# independent half of that gate: the signed job proves the aggregator, this
# marker proves the operator stood here. Content is never read; only the
# marker's own mtime is, so it carries none.
#
# root:ADOPT_GROUP, 0640, deliberately NOT ADVISOR_OWNER_USER, unlike the
# token just above. A program the dashboard's own account could run to open
# its own window would be the same as no window at all, the exact reasoning
# aperire-fleet-broker.sh's arm_guard already uses for the model key's own
# arm marker; this one stays root's, and the dashboard reads it only through
# the group the two accounts already share.
#
# Replanted on EVERY run, unlike the token: the token is a secret, minted
# once and kept; this is a clock, and touching it IS the re-arm. Running the
# curl one-liner a second time is exactly how the Add an Advisor card's "the
# window has closed" copy box tells an operator to recover, and it must
# actually open a fresh window rather than silently doing nothing because a
# marker of the same name already existed.
#
# A fresh inode, not `: > file; chgrp; chmod`. A plain truncate keeps whatever
# owner the file already had, which is not root on a host where this account
# had earlier become the token block's own recursive chown target (the
# token-missing branch above runs `chown -R "$ADVISOR_OWNER_USER"` over this
# whole directory), or after install-advisor-account.sh's own move re-owns
# advisor/state onto the dedicated account before a later re-run of this
# script reaches this line again. The plant forces the owner back to root
# regardless of what it drifted to, together with the group, the mode and a
# fresh mtime, so it is correct no matter what this file looked like a moment
# ago.
#
# Through scripts/state-file.py and not `install`, which is what this line
# used to be: GNU install's last call is fchmodat on the PATH with no nofollow
# flag, so the account that owns advisor/state can swap a symlink in after the
# create and have root chmod its target to 0640 instead (#661: the racer in
# scripts/test-install-advisor-account.sh wins 39 to 150 of 150 attempts,
# across runs on two machines). The helper creates the file
# relative to a descriptor on the directory and never resolves a name again.
#
# Numeric gid: the helper does no name lookups of its own, deliberately, so
# the one `getent` this script already trusts does it here.
REVEAL_WINDOW="$REPO/advisor/state/reveal.window"
if [[ $EUID -eq 0 ]]; then
  _adopt_gid="$(getent group "$ADOPT_GROUP" | cut -d: -f3)"
  [[ -n "$_adopt_gid" ]] || { echo "   !! the group $ADOPT_GROUP has no gid, so no reveal window was opened" >&2; exit 1; }
  python3 -I "$ADV_SELF/state-file.py" plant "$REVEAL_WINDOW" 0 "$_adopt_gid" 0640
  echo "== Reveal window"
  echo "   $REVEAL_WINDOW (open 900s)"
else
  # This script is documented as running under sudo and every caller in this
  # tree invokes it that way; this is the defensive branch for one that does
  # not. A window this account planted would be a window this account could
  # also open at will, which is exactly what the reveal gate must never be.
  echo "   !! not running as root, so no reveal window was opened" >&2
  echo "      run this with sudo to open one for the Advisor attach flow" >&2
fi
# <<< advisord ownership <<<

# ── the install tree above advisor/state (#703) ──────────────────────
#
# Before anything below plants or re-owns a file in there, because every one
# of those runs through scripts/state-file.py and the helper refuses a chain
# whose directories an account other than root or the owner can write. A host
# in that state gets the refusal at the FIRST seal otherwise, which is hours
# later and three hops from the cause.
#
# Found on an aggregator: the install tree was 0775 owner:owner and the
# owner's group held the Advisor's own account, so the Advisor could rename
# a directory root walks through. Neither half is an installer's doing (the
# mode is umask 002, the membership was made by hand), so this repairs rather
# than assumes. Idempotent, and never fatal: it says what is left and the
# refusal names the same script.
if [[ -r "$ADV_SELF/state-ancestors-lib.sh" ]]; then
  # shellcheck source=scripts/state-ancestors-lib.sh
  . "$ADV_SELF/state-ancestors-lib.sh"
  # The helper root runs is the one beside this script, which is the checked
  # copy root staged when it is root, never the tree's (#952).
  STATE_ANCESTORS_TOOL="$ADV_SELF/state-file.py"
  echo "== The install tree above $REPO/advisor/state"
  state_ancestors_narrow "$REPO" "$REPO/advisor/state" || true
fi

# >>> advisord state adoption >>>
# The line above owns the DIRECTORIES. Their contents are a separate question,
# and on one host it was the whole failure (aperire4, 2026-09-07).
#
# What happened: an uninstall that keeps the data removed the aperire-advisor
# account, and the reinstall put the Advisor back on the operator's account.
# advisor/state/approve.token and credentials.json were still owned by uid 995,
# an account that no longer existed, at mode 640. Nothing here rewrote them:
# the token block above runs only when the token is MISSING, and this chown
# names directories. So advisord started, could not open its own token, and
# crash-looped on "could not establish the service token: permission denied"
# while the installer waited on a unit that was never going to come up.
#
# So files whose owner or group no longer resolves are adopted here, before
# the unit starts. Only those. A file owned by an account that EXISTS is left
# exactly as it is, which is the case that matters on a healthy host: where
# aperire-advisor owns the state and the service runs as it, this must be a
# no-op, and a re-arm run must not quietly move the Advisor's own files onto
# the operator.
#
# Owner and group are fixed separately on purpose. A file can be orphaned on
# one and correct on the other, and approve.token is read by the dashboard
# through a group they share: rewriting a group that still resolves would take
# that read away to fix an owner nobody asked about.
adopt_orphaned_files() { # $@ = directories
  local dirs=() d before after adopted
  for d in "$@"; do [[ -d "$d" ]] && dirs+=("$d"); done
  [[ ${#dirs[@]} -gt 0 ]] || return 0

  orphan_count() { find "${dirs[@]}" \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l; }
  before="$(orphan_count)"
  [[ "$before" -gt 0 ]] || return 0

  # ADVISOR_OWNER_USER and ADOPT_GROUP, not RUN_USER/RUN_GROUP (#568): on a
  # moved host an orphan belongs to the dedicated account and the group it
  # shares with the dashboard, never to the operator running this script.
  #
  # Through the state helper, not `find -exec chown` (#703). `find` resolves
  # each hit by name and hands that name to chown, and this tree is one the
  # Advisor's own account owns: a symlink standing where an orphan was is a
  # chown root aims at the link's target. The helper re-owns on a descriptor
  # it opened O_NOFOLLOW under a descriptor on the directory, and refuses an
  # entry that is not a regular file or a directory instead of skipping the
  # rest, so one planted link no longer abandons the adoption.
  #
  # One call per directory, so the ancestor rule stops at the directory being
  # walked rather than at their common parent.
  local uid gid rc
  uid="$(id -u "$ADVISOR_OWNER_USER" 2>/dev/null || true)"
  gid="$(getent group "$ADOPT_GROUP" 2>/dev/null | cut -d: -f3 || true)"
  ADOPT_REFUSED=0
  for d in "${dirs[@]}"; do
    if [[ -n "$uid" ]]; then
      rc=0
      find "$d" -nouser -print0 2>/dev/null \
        | python3 -I "$ADV_SELF/state-file.py" own-many "$uid" "" "" --root "$d" || rc=$?
      [[ "$rc" -eq 3 ]] && ADOPT_REFUSED=1
    fi
    if [[ -n "$gid" ]]; then
      rc=0
      find "$d" -nogroup -print0 2>/dev/null \
        | python3 -I "$ADV_SELF/state-file.py" own-many "" "$gid" "" --root "$d" || rc=$?
      [[ "$rc" -eq 3 ]] && ADOPT_REFUSED=1
    fi
  done

  # Counted again rather than assumed. A chown that could not happen (this run
  # is not root) would otherwise be reported as work done, and the service
  # would fail to start straight afterwards with the installer claiming it had
  # already fixed the reason.
  after="$(orphan_count)"
  adopted=$(( before - after ))
  if [[ "$adopted" -gt 0 ]]; then
    echo "== Adopted $adopted file(s) under advisor/"
    echo "   they were owned by an account that no longer exists (a keep-uninstall"
    echo "   removes the account and leaves its files), so the service could not"
    echo "   read them. They now belong to ${ADVISOR_OWNER_USER}:${ADOPT_GROUP}."
  fi
  if [[ "$after" -gt 0 ]]; then
    # Two different reasons, and they need different answers. A privilege gap
    # is fixed by re-running with sudo; an entry the helper refused is a
    # symlink or a special file standing where an orphan should be, and no
    # amount of privilege makes that safe to re-own (#703).
    if [[ "$ADOPT_REFUSED" -eq 1 ]]; then
      echo "   !! $after more could not be adopted, and at least one was refused as" >&2
      echo "      not a regular file or directory (named above). Look at those by" >&2
      echo "      hand: a link where a state file belongs is not an ownership" >&2
      echo "      problem, and the service will not be able to read them." >&2
    else
      echo "   !! $after more could not be adopted — run this with sudo, or the" >&2
      echo "      service will not be able to read them." >&2
    fi
  fi
}
adopt_orphaned_files "$REPO/advisor/state" "$REPO/advisor/evidence" \
                     "$REPO/advisor/knowledge-fleet"
# <<< advisord state adoption <<<

# Public ledger lookup: written disabled, with the endpoints already filled in.
#
# Reaching a public API is new outbound traffic from this host, so it stays an
# operator decision and is never enabled by an installer. What it should not be
# is invisible: nothing created this file, so a fresh install simply had the
# capability missing, and asking about a ledger index got "the ledger lookup
# isn't enabled on this node" with no hint that a file was all it wanted. Now
# the file exists, says what it is for, and enabling it is one word.
LOOKUP="$REPO/advisor/state/xrpl-lookup.json"
if [[ ! -f "$LOOKUP" ]]; then
  # Planted on a descriptor, like the token and the window above, and for a
  # sharper reason than either: this was `cat > "$LOOKUP"` followed by a bare
  # `chown` and `chmod` on the same name. All three resolve the name, and this
  # branch is entered when `-f` is false, which a DANGLING symlink satisfies.
  # The account that owns advisor/state could aim the redirect at any path it
  # liked and then have root hand it that file's OWNERSHIP, not merely its
  # mode. The guard in scripts/test-node-wrapper-image.sh found this one when
  # it stopped working off a list of variable names and started working off
  # the directory (#661).
  #
  # ADVISOR_OWNER_USER, not RUN_USER (#568): written under advisor/state,
  # which on a moved host belongs to the dedicated account. Numeric, because
  # the helper does no name lookups of its own.
  _lookup_uid="$(id -u "$ADVISOR_OWNER_USER" 2>/dev/null || true)"
  python3 -I "$ADV_SELF/state-file.py" plant "$LOOKUP" "${_lookup_uid:-}" "" 0640 --stdin <<'JSON'
{
  "_comment": "Set enabled to true to let the Advisor look up a ledger by index on the public XRPL API, and to offer explorer links. endpoint is the only address it will fetch from; explorer is used to compose links for you to click and is never fetched.",
  "enabled": false,
  "endpoint": "https://xrplcluster.com",
  "validator_endpoint": "https://api.xrpscan.com",
  "explorer": "https://xrpscan.com"
}
JSON
  echo "  wrote $LOOKUP (disabled — set \"enabled\": true to allow ledger lookups)"
fi

# Once the Advisor has been moved onto its own account, that installer owns
# this unit — it carries the dedicated user, the sandbox and the socket.
# Rewriting it here would quietly put the service back on the operator's
# account, undoing ADR 0007's privilege model without saying so; that is
# exactly what a routine re-run of install.sh did. The backup the account
# installer leaves behind, ${UNIT}.before-account, used to be the only thing
# this checked, and a host moved before that marker existed, or one whose
# unit directory was tidied since (the marker gone, the unit itself left
# alone), still ran as the dedicated account with nothing here to notice,
# so this run rewrote the unit right back onto the operator (#568,
# reintroduced 2026-09-20). advisor_owner_moved now asks the unit's own
# effective User= first and only falls back to the marker when there is
# nothing to compare it to, which is exactly the gate this rewrite needs.
if unit_moved; then
  echo "== Unit"
  echo "   kept as installed by install-advisor-account.sh — it runs as"
  echo "   $ADVISOR_OWNER_USER, with its own sandbox and its root socket."
  if [[ -f "${UNIT}.before-account" ]]; then
    echo "   To rebuild it from scratch, remove ${UNIT}.before-account first."
  else
    echo "   No ${UNIT}.before-account marker was found; this host's own User=,"
    echo "   not the marker, is what says the move already happened (#568)."
    echo "   To rebuild it from scratch, move it back onto $RUN_USER by hand first."
  fi
  systemctl daemon-reload
  advisord_reset_and_restart "${UNIT_NAME}" || true
else
echo "== Configuring the privilege wrapper"
# The wrapper is the whole list of things the Advisor can do to a node, and it
# needs this host's real paths. It runs BEFORE the unit is written, and the
# node facts are read again after it (#767): the unit names the directories
# the wrapper's configuration names, and on a first run that configuration is
# written by this very step. Done here rather than left as a follow-up
# because a security setup you have to assemble by hand is one most operators
# skip — which would leave the weaker arrangement as the easy one.
#
# Not fatal if it does not apply. On a natively installed node, or a container
# not started by compose, there is nothing for the wrapper to drive; the
# Advisor still monitors, explains and refuses to act, which is the correct
# behaviour rather than a broken install.
#
# --native named explicitly on a native host, from the same $NODE_KIND read
# at the top of this script that already drives the container skip above. install-node-wrapper.sh reads its own configuration
# and would reach the same answer bare, on a re-run where that configuration
# already exists. Naming it here means this call cannot demand a docker
# binary a native host never has, on the very first run as much as the tenth
# (#528: the bare call fell into the container branch regardless of
# $NODE_KIND, and printed "wrapper is not configured" on a host where it was
# configured correctly by the step just before this one).
WRAPPER_ARGS=()
[[ "$NODE_KIND" == native ]] && WRAPPER_ARGS+=(--native)
# The instance is named across sudo here: its env reset drops APERIRE_INSTANCE,
# and without it a named instance's install configures the default wrapper
# (#926). INSTANCE was validated at the top of this script.
if sudo env APERIRE_INSTALL_TREE="$REPO" APERIRE_INSTANCE="$INSTANCE" bash "$ADV_SELF/install-node-wrapper.sh" "${WRAPPER_ARGS[@]}"; then
  :
else
  echo
  echo "   The wrapper is not configured, so the Advisor cannot act on this node."
  echo "   Everything else works: it still reads, explains, and says plainly that"
  echo "   the execute path is unavailable. To configure it later:"
  if [[ "$NODE_KIND" == native ]]; then
    echo "     curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native${INSTANCE:+ --instance $INSTANCE}"
  else
    echo "     curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper${INSTANCE:+ --instance $INSTANCE}"
  fi
fi


# What the step above wrote is what the unit below is written from.
read_node_facts

echo
echo "== Unit"
# -e is false for a dangling link and -f for a link to /dev/null, which is
# what `systemctl mask` leaves: either one is the operator's and not this
# run's to remove (#898 review, N4).
UNIT_EXISTED=0
[[ -e "$UNIT" || -L "$UNIT" ]] && UNIT_EXISTED=1
# A login Advisor the operator disabled on the stack's advice is rewritten for
# the account below. Keep it first, under a name the leftover check above does
# not read (.before-account would turn that check off on the next run), so a
# hand edit in it, and the way back from a failed move, are not lost (#898
# review, R2).
LOGIN_COPY="${UNIT}.login-before-stack"
if (( LOGIN_UNIT )); then
  if ! sudo cp -a "$UNIT" "$LOGIN_COPY"; then
    echo "error: could not keep the Advisor unit that names $RUN_USER at $LOGIN_COPY; it was not rewritten." >&2
    exit 1
  fi
  echo "   the unit that names $RUN_USER is kept at $LOGIN_COPY before it is rewritten for the account."
fi
sudo tee "$UNIT" >/dev/null <<UNITFILE
[Unit]
Description=Aperire Advisor (read-only state service)
# ${UNIT_NOTE}
After=network-online.target
Wants=network-online.target
# Two inequalities pin these numbers, and both have to hold (#541 P1-091):
#
#   RestartSec * (Burst - 1) < StartLimitIntervalSec
#     or the limit is never reached at all. The defaults these replace
#     (10s / 5, systemd's own DefaultStartLimit*) fail this one: a rolling
#     10s window only ever holds about four attempts at RestartSec=3, so the
#     fifth that would trip the limit has already aged out of it, and
#     \`systemctl is-active\` reads \`activating\` for as long as the
#     credential stays unopenable. 3 * 4 = 12 < 30 holds here.
#
#   RestartSec * (Burst - 1) >= the longest legitimate transient
#     or an ordinary reboot ends in \`failed\` before whatever this unit was
#     waiting on catches up. Read against advisord's own startup
#     (cmd/aperire-advisord/main.go): the token, the read token and the
#     bind are all local. The state directory it writes to and the address
#     it listens on wait on nothing else over the network, so a cold
#     dashboard is not a transient this margin has to survive. The one
#     real candidate is a TPM-sealed
#     credential decrypting before udev has finished setting up
#     /dev/tpmrm0, which resolves in low single digits of seconds after
#     boot, well inside the 12s this gives it.
#
# StartLimitIntervalSec= and StartLimitBurst= belong here, in [Unit], not in
# [Service]: systemd.unit(5), not systemd.service(5).
StartLimitIntervalSec=30
StartLimitBurst=5
# Fires once, the moment the start limit above is actually reached and the
# unit has stopped trying on its own (systemd.unit(5): "activated when this
# unit enters the failed state"), never mid-loop, and never for a unit that
# is still auto-restarting. aperire-advisord-credcheck.service tells a model
# credential that will not decrypt on this host apart from every other
# reason the service can fail, and only it removes the drop-in that names
# one; anything else is left in \`failed\` for systemctl --failed to find.
OnFailure=${CREDCHECK_UNIT_NAME}.service

[Service]
Type=simple
User=${UNIT_USER}
Group=${UNIT_GROUP}
WorkingDirectory=$REPO/advisor
ExecStart=$BIN --addr=127.0.0.1:${ADVISOR_PORT}${NODE_CONTAINER:+ --container=${NODE_CONTAINER}} --dash-read-url=http://127.0.0.1:${DASH_PORT} --state=$REPO/advisor/state --wrapper=${WRAPPER_PATH}
Restart=always
RestartSec=3
# The service drains on SIGTERM: it stops taking new questions and finishes
# the ones already running, up to 60 seconds. systemd's default here is 90s,
# which would work — but stating it makes the relationship explicit, and it
# has to stay LARGER than the drain window or systemd would SIGKILL through
# the drain and the answer would be lost anyway, which is the failure this
# whole arrangement exists to stop.
TimeoutStopSec=75

NoNewPrivileges=true
PrivateTmp=true
# 0027: files 0640, directories 0750. Without it a service creates
# world-readable files by default, and what these write includes the audit
# ledger, run transcripts and relay state. systemd-analyze flags the omission.
UMask=0027
# strict, not full. The service holds the execute path, so the interesting
# question is not what it can read but what it can rewrite — and until this
# was tightened it could rewrite the three things that constrain it: the
# privilege wrapper, the credential store that authorises every approval, and
# the audit ledger. The code says "in a file the executor cannot write"; this
# is what makes that true rather than aspirational.
ProtectSystem=strict
ProtectHome=read-only
# Everything it legitimately writes, and nothing else. state/ holds the
# ledger, approvals, memory, evidence snapshots, run transcripts and digests;
# evidence/ is where the privilege wrapper appends its own log;
# knowledge-fleet/ is where a signature-verified bundle from the aggregator
# lands (ADR 0017) — the service writes it whole, by rename, and only after
# the signature and every file hash have verified. Note what is NOT here:
# scripts/ (the wrapper), advisor/bin/ (its own binary), advisor/knowledge/
# and persona.md (the operator's words, not the agent's, and not a pushed
# bundle's either).
# /var/lib/aperire is the WRAPPER's, not this service's: the record that a
# container image was checked on this host, and any release package kept for
# a rollback. The wrapper runs through sudo as a child of this unit, and a
# mount namespace applies to children, root included, so without this an
# official-image upgrade dies at the verify step on "Read-only file system"
# while root can plainly write the same path from a shell. The directory is
# root-owned and this account cannot write in it; the mount only decides
# what root reaches once it is there.
ReadWritePaths=$REPO/advisor/state $REPO/advisor/evidence $REPO/advisor/knowledge-fleet /var/lib/aperire$NODE_RW
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# Two syscalls the deny-list above takes away and this service must have.
# Both are killed at the syscall with SIGSYS, so no error path in the code
# can soften them — the process simply dies at startup.
#
# setrlimit/prlimit64 (@resources): the GO RUNTIME raises RLIMIT_NOFILE to
# the hard limit at startup, before main() runs. It only does so when the
# soft limit is below the hard one — which is why this never appeared on a
# host whose systemd sets them equal, and killed every Go service instantly
# on a stock Ubuntu box where the default is 1024 soft / 1048576 hard. The
# same trap applies to the relay, which is also Go.
#
# chown/fchownat (@privileged): setting the group on the tokens this
# service generates (approve.token, read.token) so the dashboard can read
# them through the shared service group.
SystemCallFilter=setrlimit prlimit64 chown fchown fchownat lchown
# Deliberately NOT MemoryDenyWriteExecute. advisord itself is pure Go and
# would tolerate it, but it execs the wrapper, which execs bash and docker —
# breaking those to harden a process that does not need it is a bad trade.

[Install]
WantedBy=multi-user.target
UNITFILE
echo "   $UNIT"

echo
echo "== Credential recovery unit"
# Named on OnFailure= in the unit above (and in install-advisor-account.sh's
# own copy of it, for a host that has moved). Never enabled, never started by
# hand: it exists only to be findable by name the moment aperire-advisord
# gives up (#541). Written on every run so a binary move or a script fix
# reaches a host that already has one, the same as the unit it watches.
#
# The program it runs is copied to /usr/local/sbin first (P1-090): a unit
# naming a file inside this checkout would be root, on demand, for whichever
# account owns the checkout, which on a dashboard-installed host is the
# unprivileged account the dashboard itself runs as. write_advisord_credcheck_unit
# (advisord-credcheck-lib.sh, sourced above) is the one place that copies the
# program and writes the unit that runs it, so the two can never drift apart.
if ! write_advisord_credcheck_unit "$REPO" "$UNIT_DIR" "$CREDCHECK_UNIT_NAME" "$INSTANCE"; then
  # Root counts whoever the unit above names as a service account. On a host
  # where that is the operator's login, and the login can change this tree,
  # the checked copy is refused, and a unit left naming the login would make
  # every later run refuse the same way (#898 review). A unit this run wrote
  # on a host with none is taken back, so a refusal leaves the host as it was.
  if (( ! UNIT_EXISTED )); then
    sudo rm -f "$UNIT"
    echo "   the unit this run wrote at $UNIT was removed: nothing is left behind." >&2
  fi
  echo "error: install-advisord.sh stopped at the credential recovery program (above)." >&2
  if [[ "${APERIRE_ADVISOR_ACCOUNT_NEXT:-0}" == 1 ]] && (( ! BORN )); then
    # Inside the stack, so the command already running is not the next step.
    # An Advisor that is up on the login is a working install and is not
    # rewritten for another account while it runs. Stopped and disabled, the
    # stack writes it for its own account and the copy goes through (#898
    # review, N3).
    # systemd keeps a failed state through stop and disable, so a failed
    # Advisor would read as a real install again on the next run. reset-failed
    # comes last and clears it (#898 review, R1). The stack keeps a copy of the
    # unit at ${UNIT}.login-before-stack when it rewrites it (R2).
    echo "   An Advisor is set up on this login and the stack leaves it alone while it" >&2
    echo "   is enabled, running or failed. Stop it first, then run the stack again." >&2
    echo "   The stack writes it for its own account and keeps this unit at" >&2
    echo "   ${UNIT}.login-before-stack:" >&2
    echo "     sudo systemctl disable --now $UNIT_NAME" >&2
    echo "     sudo systemctl reset-failed $UNIT_NAME" >&2
    echo "     curl -fsSL https://get.aperire.one/advisor | bash" >&2
  elif [[ "${APERIRE_ADVISOR_ACCOUNT_NEXT:-0}" == 1 ]]; then
    echo "   Fix the file it names, then run the stack again:" >&2
    echo "     curl -fsSL https://get.aperire.one/advisor | bash" >&2
  else
    echo "   If it says a service account can change a file, install the Advisor as one" >&2
    echo "   step, which gives the service its own account before anything is copied:" >&2
    echo "     curl -fsSL https://get.aperire.one/advisor | bash" >&2
  fi
  exit 1
fi

echo
# One flow, by operator ruling (2026-08-13): install ends CONFIGURED and
# RUNNING. If a model key was already sealed on this host (running the
# model setup before the install is a legal order, it happened), the
# directive that loads it is put back here, before first start, so
# "install then discover the model isn't loaded" cannot occur. If no
# model is configured yet, the operator is offered the setup inline,
# skippable, and the change-model path in the menu stays for later.
#
# The directive goes in a DROP-IN, never in the unit (#451). The unit above
# is rewritten whole on every run of this installer, so a line written into
# it is a line this script has to put back on every run, and the sealer's
# --reset then has two places to clean instead of one. The drop-in is a file
# of its own, written here in the same bytes
# scripts/aperire-seal-model-key.sh writes, removed by that program's
# --reset, and untouched by the unit write above.
#
# Which makes the common case nothing to do: a host sealed from the browser
# already carries the drop-in, and this reads it and leaves it alone. What
# still needs the write is the host sealed BEFORE this installer ran, and
# the host that kept its sealed key across a --keep uninstall. Both have a
# key and a model config and, once the unit above is written, no directive
# anywhere.
MODEL_CFG="$REPO/advisor/state/model.json"
# Derived from $UNIT rather than composed again from /etc/systemd/system, so
# a harness that points the unit at its own directory gets the drop-in there
# too instead of writing into the host's real unit directory.
DROPIN_DIR="${UNIT}.d"
DROPIN="$DROPIN_DIR/model-credential.conf"
wire_model_credential() {
  local cred_name cred_path method directive sealed_path plain_path
  cred_name="$(python3 -I -c "import json;print(json.load(open('$MODEL_CFG')).get('credential_name',''))" 2>/dev/null || true)"
  [[ -n "$cred_name" ]] || return 0
  # The sealer's own rule, applied here too (#712 review). This name becomes a
  # file name under /etc/aperire/creds and a credential id in a unit, and it
  # comes out of a config file the Advisor's account owns, so it is not a
  # value this script may paste into either without asking. The `.plain`
  # suffix is refused for the same reason the sealer refuses it: it is how
  # this store tells a key kept in the clear from a sealed blob.
  if [[ ! "$cred_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] \
     || [[ "$cred_name" == *".."* ]] || [[ "$cred_name" == *.plain ]]; then
    echo "   $MODEL_CFG names a credential this installer will not wire: '$cred_name'"
    echo "   is not a bare name of letters, digits, dot, dash or underscore. No"
    echo "   directive was written. Seal a key again and the config is rewritten."
    return 0
  fi
  # Two forms a key on this host can be in (#708), told apart by the path they
  # live at rather than by a flag anywhere that could disagree with the disk:
  # a blob sealed to this machine at <name>, or a root-only file at
  # <name>.plain. Which one is HERE decides what gets wired, not which one
  # this host would write today. An operator who upgrades 22.04 to 24.04 in
  # place keeps a working plaintext key, and a re-run of this installer that
  # judged by the host's capability alone would hand that file to
  # `systemd-creds decrypt` and quarantine it.
  sealed_path="$(aperire_key_blob_path /etc/aperire/creds "$cred_name" sealed)"
  plain_path="$(aperire_key_blob_path /etc/aperire/creds "$cred_name" plain)"
  if sudo test -f "$plain_path"; then
    method=plain; cred_path="$plain_path"
  elif sudo test -f "$sealed_path"; then
    method=sealed; cred_path="$sealed_path"
  else
    # No file, no directive. systemd refuses to start a unit that declares a
    # credential which is not on the host: 243/CREDENTIALS, before the program
    # runs, with the restart counter climbing (#446).
    return 0
  fi
  directive="$(aperire_key_directive "$method")"

  # On the host but unusable on it (#514, #541, #708): the exact shape of a
  # backup restored wholesale onto a rebuilt host, or the wrong host's backup
  # restored onto this one. Checked before either return below gets a chance
  # to leave a directive standing that names it. A re-run of this installer is
  # one of the ways a bad blob is found, and it should heal a host the same
  # way aperire-advisord-credcheck.service does at runtime. Quarantined, not
  # deleted: the evidence stays for whoever restored it.
  #
  # Three ways it can be unusable, and the third is new. A sealed blob on a
  # host with no systemd-creds can never be opened here at all, which is a
  # 24.04 backup restored onto 22.04, and it used to leave the unit failing on
  # a credential nothing would ever judge.
  local bad=""
  if [[ "$method" == sealed ]]; then
    if ! command -v systemd-creds >/dev/null 2>&1; then
      bad="this host has no systemd-creds, so a blob sealed to a machine cannot be opened here"
    elif ! sudo systemd-creds decrypt --name="$cred_name" "$cred_path" /dev/null >/dev/null 2>&1; then
      bad="it would not decrypt on this host"
    fi
  else
    # The plain form's own failures. An empty file is a key the Advisor would
    # send as an empty bearer token; a file anything but root may read is a
    # key that has already left root's hands, and leaving it wired would be
    # this installer signing off on that.
    # The owner is compared with the account the privileged half of this
    # script runs as, asked rather than spelled as uid 0: on a host they are
    # the same thing, and asked this way it is a question a suite that cannot
    # become root can put a real answer to.
    local st priv_uid
    priv_uid="$(sudo id -u 2>/dev/null || echo 0)"
    st="$(sudo stat -c '%u %a' "$cred_path" 2>/dev/null || true)"
    if ! sudo test -s "$cred_path"; then
      bad="the key file is empty"
    elif [[ -z "$st" ]]; then
      bad="the key file could not be read"
    elif [[ "${st%% *}" != "$priv_uid" ]]; then
      bad="the key file is owned by uid ${st%% *} and not by root"
    elif (( 8#${st##* } & 8#077 )); then
      bad="the key file is mode ${st##* }, which is readable by an account that is not root"
    fi
  fi
  if [[ -n "$bad" ]]; then
    local quarantine
    quarantine="$(advisord_quarantine_path "$cred_path")"
    sudo mv -f "$cred_path" "$quarantine"
    sudo rm -f "$DROPIN"
    sudo rmdir "$DROPIN_DIR" 2>/dev/null || true
    write_advisord_credential_note "$REPO/advisor/state" credcheck "$cred_name"
    echo "   $cred_name at $cred_path: $bad; moved to $quarantine, no key wired in"
    return 0
  fi

  # Already declared, in the place this writes it.
  if [[ -f "$DROPIN" ]] && grep -q "^$directive=$cred_name:$cred_path\$" "$DROPIN"; then
    return 0
  fi
  # A host still carrying the line in the unit itself is left in that state
  # rather than given a second declaration beside it. Migrating it belongs to
  # the sealer, which does it on the next seal or reset, and one program
  # owning that move is what keeps two places from becoming three.
  if grep -q "^$directive=$cred_name:" "$UNIT" 2>/dev/null; then
    return 0
  fi
  sudo mkdir -p "$DROPIN_DIR"
  sudo chmod 0755 "$DROPIN_DIR"
  # From the method library, the same bytes the sealer writes.
  aperire_key_dropin_text "$cred_name" "$cred_path" "$method" install-advisord.sh \
    | sudo tee "$DROPIN" >/dev/null
  sudo chown root:root "$DROPIN" 2>/dev/null || true
  sudo chmod 0644 "$DROPIN"
  echo "   wired the model key into $DROPIN ($cred_name, $method)"
}
if [[ -f "$MODEL_CFG" ]]; then
  wire_model_credential
elif [[ ! -t 0 ]]; then
  # An unattended run (install.sh --yes from Ansible, cloud-init or an SSH
  # one-liner) reaches here with nothing to answer the question. It used to
  # die on the read's EOF under `set -e` — a bare exit 1 at the very last
  # step, with the Advisor installed and the operator told nothing. Model
  # setup is the one part that needs a key pasted in, so it is deferred and
  # named rather than guessed at.
  echo
  echo "== No terminal, so the model question is skipped."
  echo "   The Advisor is installed; it cannot answer questions until a model"
  echo "   is configured. In the browser: refresh the dashboard, open the menu,"
  echo "   Settings, Advisor AI model (the install command opens the window that"
  echo "   step needs). Or in a terminal on this host, either of:"
  echo "     bash scripts/setup-advisor-model.sh"
  echo "     aperire-one  ->  Advisor  ->  model setup"
else
  echo
  read -r -p "== Configure a model now so the Advisor can answer questions? [Y/n] " CFG_MODEL
  if [[ ! "$CFG_MODEL" =~ ^[Nn] ]]; then
    bash "$ADV_SELF/setup-advisor-model.sh" || true
    wire_model_credential
  else
    echo "   skipped — later: bash scripts/aperire.sh → Advisor → model setup"
  fi
fi

if (( BORN )); then
  # Enabled, not started: it starts as ${UNIT_USER} once the account step has
  # made the account and given it the state, and not before.
  echo "== Starting"
  sudo systemctl daemon-reload
  sudo systemctl enable "${UNIT_NAME}"
  echo "   enabled, not started yet: it runs as ${UNIT_USER}, an account"
  echo "   install-advisor-account.sh makes and starts it as."
else
echo "== Starting"
sudo systemctl daemon-reload
sudo systemctl enable --now "${UNIT_NAME}"
# Restart even if it was already running: a re-run of this installer may
# have just wired a credential or refreshed binaries, and "installed but
# still running yesterday\'s process" is exactly the confusion one cheap
# restart removes. reset-failed first (#541 P1-091): this install sequence
# can restart the unit more than once in one run, and past the burst a plain
# restart is refused as "repeated too quickly" while this script goes on to
# report a state it never actually reached.
advisord_reset_and_restart "${UNIT_NAME}"
fi
fi
# A born unit has nothing running to report on. The account step starts it and
# the stack's own read-back asks it a question before anything is claimed.
if (( BORN )); then
  echo
  echo "Next: curl -fsSL https://get.aperire.one/advisor | ${INSTANCE:+APERIRE_INSTANCE=$INSTANCE }bash"
  exit 0
fi
# >>> advisord start report >>>
# What the unit says about itself, and what it said in the journal. The two
# together are the difference between a fixable install and a puzzle.
#
# On aperire4 (2026-09-07) this step read `is-active` once, got "activating"
# from a unit in its restart loop, and died on that word under set -e. The
# caller reported "install-advisord.sh did not finish" and the operator was
# left with a service that had already written the answer to its own journal:
# "could not establish the service token: permission denied". A line already
# on the host is worth more than any sentence this script could invent, so it
# is read and printed rather than pointed at.
# `|| true` is load-bearing. This is called from the failure path, and
# journalctl exits non-zero on a host whose journal this account cannot open;
# under set -e that non-zero would end the run half way through the very
# explanation it exists to print, leaving the operator with less than before.
journal_tail() { # $1 = unit, $2 = how many lines
  if [[ $EUID -eq 0 ]]; then
    journalctl -u "$1" -n "$2" -o cat --no-pager 2>/dev/null || true
  else
    sudo journalctl -u "$1" -n "$2" -o cat --no-pager 2>/dev/null || true
  fi
}

unit_restarts() { # $1 = unit. The auto-restart counter, or 0 where there is none.
  local n
  n="$(systemctl show -p NRestarts --value "$1" 2>/dev/null || true)"
  [[ "$n" =~ ^[0-9]+$ ]] && printf '%s' "$n" || printf '0'
}

# Named where it failed, with the unit's own last word under it.
unit_trouble() { # $1 = what this check was, $2 = state, $3 = restarts in the window
  local line
  {
    echo
    echo "   $1"
    echo "   ${UNIT_NAME} is '$2'$( [[ "$3" -gt 0 ]] && echo ", and restarted $3 time(s) in the last 2 seconds" )."
    line="$(journal_tail "${UNIT_NAME}" 1)"
    if [[ -n "$line" ]]; then
      echo "   its last journal line:"
      echo "     $line"
    fi
    echo "   the rest of it:  journalctl -u ${UNIT_NAME} -n 30 --no-pager"
  } >&2
}

RESTARTS_BEFORE="$(unit_restarts "${UNIT_NAME}")"
command sleep 2
UNIT_STATE="$(systemctl is-active "${UNIT_NAME}" 2>/dev/null || true)"
RESTARTS_IN_WINDOW=$(( $(unit_restarts "${UNIT_NAME}") - RESTARTS_BEFORE ))
# A unit caught between two crashes reads "activating", and one caught in the
# instant between a start and the crash reads "active" — so the restart
# counter is read as well, and either answer is a failure. Waiting longer
# would only make a broken install slower to say so.
if [[ "$UNIT_STATE" != "active" || "$RESTARTS_IN_WINDOW" -gt 0 ]]; then
  unit_trouble "The service did not stay up." "$UNIT_STATE" "$RESTARTS_IN_WINDOW"
  exit 1
fi
echo "   $UNIT_STATE"

echo
echo "== Checking it answers"
# With the token, because every /v1 endpoint requires it — reads included.
# Without it this check gets a 401 and reports the service as broken when it is
# working perfectly, which is how it behaved between the token landing and now.
# Read through state-file.py, not by name (#703 item 5). This is root
# reading a file in a directory the Advisor's own account owns, and a plain
# redirect follows whatever link that account put at the name: root would
# send the target's first line to a loopback service as a bearer token. The
# helper refuses anything that is not a single-linked regular file.
# The token reaches curl on its standard input (-H @-), never on its argv,
# where any account on the host can read it in /proc (#705).
# A read the helper refuses leaves the token empty, as it always did inside
# the old -H "$(...)": the check below then fails with its explanation,
# instead of set -e ending the install here with none.
_status_tok="$(python3 -I "$ADV_SELF/state-file.py" read "$TOKEN" | tr -d '[:space:]')" || _status_tok=""
if curl -sf -H @- \
     "http://127.0.0.1:${ADVISOR_PORT}/v1/status" >/dev/null <<<"authorization: Bearer $_status_tok"; then
  echo "   /v1/status OK"
else
  unit_trouble "/v1/status did not answer." \
    "$(systemctl is-active "${UNIT_NAME}" 2>/dev/null || true)" \
    "$(( $(unit_restarts "${UNIT_NAME}") - RESTARTS_BEFORE ))"
  exit 1
fi
unset _status_tok
# <<< advisord start report <<<

echo
echo "It listens on loopback only; the binary refuses any other address."
echo "The dashboard proxies to it at /api/advisor/*, behind your session."
