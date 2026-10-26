#!/usr/bin/env bash
# Move this host to the release its endpoint publishes, and restart nothing
# that was not asked for.
#
#   sudo bash scripts/aperire-update.sh   < payload         (an operator)
#   the dashboard, over /run/aperire/update.sock            (the page)
#
# ---- why this exists ------------------------------------------------
#
# The dashboard cannot write the tree it runs out of, and must not: a web
# process that rewrites its own code turns one bad session into persistence.
# It cannot sudo either, because its own unit sets NoNewPrivileges=true and
# an empty CapabilityBoundingSet, and under those sudo refuses before it does
# anything at all. So the privileged side is already running when the page
# arrives: systemd listens on a socket the dashboard account alone may open,
# accepts one connection at a time, and starts this program as root with that
# connection as its three streams. The same shape as
# install-model-key-sealer.sh and install-trust-sync-grant.sh, for the same
# reasons, and this is the third grant a host carries.
#
# ---- the payload carries no source ----------------------------------
#
# This is the load-bearing sentence of ADR 0022, and every refusal below
# hangs off it. Nothing on this socket names a URL, a path, a program or an
# argument. The endpoint comes from /etc/aperire/update.conf, root-owned and
# unwritable by the dashboard account, and this program fetches release.json
# and the sum from it itself. What the payload carries is the tag, the commit
# and the sha256 the page believes is current; they are compared with what
# was fetched and refused when they differ. The payload can NARROW what is
# applied, never widen it.
#
# So what a compromised web session can do with this socket is install the
# release the publisher published, or nothing.
#
# ---- and the publisher is checked too -------------------------------
#
# "What the publisher published" is only worth something if the endpoint
# cannot lie about it, and an endpoint can be taken over. So nothing the
# endpoint serves is believed on its own. Every release is signed with the
# release key, which never touches the build machine or the endpoint, and
# this program checks that signature with `ssh-keygen -Y verify` against the
# signer set installed ROOT-OWNED on this host, in /usr/local/lib/aperire,
# never against anything it fetched (docs/RELEASE-SIGNING.md):
#
#   release.json                  read only as a pointer: which archive
#   release-<sha256>.json(.sig)   the signed document for that archive,
#                                 under a name that never changes, verified
#   get-aperire.sh                run only when its own sha256 is the one the
#                                 signed document names
#
# and a release published before the one this host is on is refused, because
# an old release replayed is still a validly signed one. A host whose key or
# check is missing refuses every update and says which command puts it back.
#
# ---- it reuses the bootstrap rather than reimplementing it ----------
#
# `apply` fetches get-aperire.sh from the same endpoint, checks its sentinel
# last line and that the checksum stamped in it is the one release.json
# names, then runs it as root with --update --yes --no-restart --dir and no
# source override. The carry-and-swap that runs is the one proven on a lab
# host, not a second copy of it: rename the old tree aside, move the new one
# in, then carry data/, the operator's config and the Advisor's directories
# across, so the database exists in exactly one place at every instant.
#
# ---- the verbs ------------------------------------------------------
#
# One line on standard input, one verb per connection, `key=value` after the
# verb and nothing else:
#
#   check                                   what this host is on, what the
#                                           endpoint publishes, and a verdict
#   apply tag=<t> commit=<c> sha256=<s>     the update, streamed as it runs
#   restart units=<a,b>                     restart what the apply left old,
#                                           the dashboard's own unit last
#   rollback                                put the previous tree back
#
# ---- what comes back ------------------------------------------------
#
# Facts the page reads are `key=value` lines: step=, verdict=, needs_restart=,
# stamp=, previous=, db_snapshot=, broker_grant=, error=. broker_grant= is
# rerecorded, already_current, stale, too_old or absent (#828), and on an
# apply it comes from the bootstrap's own line. The page keeps it with the
# other facts and does not show it yet (#842). Everything else is text for a
# human to read, including every line the bootstrap prints, streamed as it
# happens: the socket is the log, and the page tails it.
#
# An exit code does not cross a socket, so the status is PRINTED as the last
# line on every path: `exit=<code>`. 0 ok, 2 the payload was not one this
# program speaks, 3 what the payload named is not what the endpoint
# publishes, 4 a run is already in flight, 5 the endpoint could not be
# reached, 6 the bootstrap failed, 7 the release is not signed by the release
# key (or is older than this host's), so nothing was fetched or run.
#
# ---- what it never does ---------------------------------------------
#
# It restarts nothing on its own. `apply` names the units whose code on disk
# is now newer than the process serving it and stops there; `restart` is a
# second request, with the unit list in front of the operator. The node is
# never touched by any of it: a different service, on its own schedule.
#
# One consequence a caller has to expect: a restart that includes the
# dashboard's own unit takes away the process reading this connection, so the
# answer ends where that happens and there is no `exit=` line. That unit is
# always restarted LAST for exactly this reason, so everything else on the
# list has already been done and read back by then.
#
# To undo an update:  rollback, then restart. The database snapshot is not
# restored by that verb and it says so, because putting a database back costs
# every row written since the update and is not a thing to do by implication.

set -euo pipefail

# Whose account this is, asked of id(1) at a fixed path and never of bash's
# $EUID, which bash imports from the environment: a root shell started with
# EUID=<a login's uid> would take that login's files for root's (#1109). The
# same three helpers as release-digests-lib.sh, which this program cannot
# source this early. Unreadable is neither root nor provably unprivileged.
my_uid() {
  local p u
  for p in /usr/bin/id /bin/id; do
    [[ -x "$p" ]] || continue
    u="$("$p" -u 2>/dev/null)" || continue
    [[ "$u" =~ ^[0-9]+$ ]] || continue
    printf '%s' "$u"
    return 0
  done
  return 1
}
am_root() { [[ "$(my_uid)" == 0 ]]; }
am_unprivileged() { local u; u="$(my_uid)" || return 1; [[ "$u" != 0 ]]; }
# The owner root's own files must have: root, or on an unprivileged test run
# the account running it. Empty when that cannot be read, which no file has.
trusted_owner_uid() {
  if am_root; then printf '0'; else my_uid || true; fi
}

# Where this program reads which endpoint to ask and which tree to update, where
# it keeps its lock, which units it looks for, and how long it waits. As root
# these are constants and nothing else: a variable set in a root shell the
# login started would choose the tree root builds in and the directory it
# locks and reads units from. The environment is honoured only for an
# unprivileged test run, which is what the suite is, decided from id(1) above
# (#1148).
CONF=/etc/aperire/update.conf
RUN_DIR=/run/aperire
UNIT_DIR=/etc/systemd/system
# How long a fetch of one small file may take. Short: these are three files
# of a few hundred bytes each, and a page waiting on a hung endpoint is a
# page that has already lost the operator.
FETCH_TIMEOUT=20
# How long a unit gets to come back after a restart before its state is read
# back as it stands. A dashboard drains before it exits, so this is generous.
RESTART_WAIT=60
if am_unprivileged; then
  CONF="${APERIRE_UPDATE_CONF:-$CONF}"
  RUN_DIR="${APERIRE_UPDATE_RUN_DIR:-$RUN_DIR}"
  UNIT_DIR="${APERIRE_UNIT_DIR:-$UNIT_DIR}"
  FETCH_TIMEOUT="${APERIRE_UPDATE_FETCH_TIMEOUT:-$FETCH_TIMEOUT}"
  RESTART_WAIT="${APERIRE_UPDATE_RESTART_WAIT:-$RESTART_WAIT}"
fi
# The release key and the function that checks it, both root-owned, both put
# there by install-update-grant.sh or by an update, before this program.
# Not overridable from the environment, on purpose: the key a release is
# checked against is the one thing here nothing but root may choose.
LIB_DIR=/usr/local/lib/aperire
# The signed files of the release this host is on, kept by the bootstrap.
RELEASE_STORE=/var/lib/aperire/release
LOCK_FILE="$RUN_DIR/update.lock"
TAG=aperire-update
# The release digests root checks every copy out of the tree against (ADR
# 0024). get-aperire.sh writes them with the tree they describe and keeps the
# one it replaced under its own key (the release's archive sha256) in
# release.sha256.kept/; a rollback puts back the one keyed by the restored
# tree's own stamp. As root the path is the constant and nothing else: the
# environment is honoured only for an unprivileged test run.
if am_unprivileged; then
  RELEASE_DIGESTS="${APERIRE_RELEASE_DIGESTS:-/usr/local/lib/aperire/release.sha256}"
else
  RELEASE_DIGESTS=/usr/local/lib/aperire/release.sha256
fi
# The installed fleet broker and its conf (#828), which a rollback asks to
# re-record which directory the install is. Constants as root, for the same
# reason as the digests: this is a program root runs.
if am_unprivileged; then
  FLEET_BROKER="${APERIRE_UPDATE_FLEET_BROKER:-/usr/local/sbin/aperire-fleet-broker}"
  FLEET_BROKER_ETC="${APERIRE_UPDATE_FLEET_BROKER_ETC:-/etc/aperire}"
else
  FLEET_BROKER=/usr/local/sbin/aperire-fleet-broker
  FLEET_BROKER_ETC=/etc/aperire
fi

# The units this program will ever act on, and the reason the list is here
# rather than in the payload: the dashboard must not be able to name a
# systemd unit. `aperire-read` is on it because that is what the dashboard's
# unit is called on one host, and a program that prints a name in
# needs_restart= and then refuses it in `restart` would be lying to the page
# in front of an operator.
UNITS_ALLOWED=(aperire-server aperire-read aperire-relay aperire-advisord)

# The bootstrap's own step headings, and what each one means to the page.
# Matched on the whole line because that is what `step "..."` prints with
# colour off, and colour is off: the connection is not a terminal, and
# NO_COLOR is set for the run besides.
#
# This couples one program to another's words, so the coupling is checked:
# scripts/test-aperire-update.sh asserts every phrase below is still a
# `step "..."` line in scripts/get-aperire.sh. A rename that broke the page's
# progress would fail there rather than on a host.
STEP_PHRASES=(
  "snapshotting the database, before anything moves:snapshot:1"
  "fetching the release:fetch:2"
  "carrying your files into the new release:carry:3"
  "the earlier checkout held nothing to carry:carry:3"
  "installing:install:4"
)

# What was said last, so a step is announced once and never backwards. The
# bootstrap prints its headings in this order and a page that saw `carry`
# after `install` would be reading a story that did not happen.
STEP_RANK=0

# Shapes, as variables because bash reads a quoted pattern as a literal.
RE_SHA256='^[0-9a-f]{64}$'
RE_COMMIT='^[0-9a-f]{7,40}$'
RE_TAG='^[A-Za-z0-9._-]{1,64}$'
RE_UNIT='^[a-z0-9-]{1,64}$'
RE_ENDPOINT='^https?://[^[:space:]"\\]+$'

# Every invocation says what it did, in the journal, whatever the outcome.
# One line per verb, and the refusals are the point: an operator watching a
# page needs the refusal to exist somewhere they can read it afterwards.
journal() { # $1 = outcome word, rest = detail
  local outcome="$1"; shift
  if command -v logger >/dev/null 2>&1; then
    logger -t "$TAG" -p daemon.notice -- "$outcome: $*" || true
  fi
  return 0
}

# Both tolerate a write that fails, and the reason is one verb below. The
# dashboard is `aperire-server`, and the dashboard is what holds the other end
# of this socket: a restart that includes it takes the reader away mid-answer.
# Under `set -e` a failed printf would end the program there, so the units
# named after it would never be restarted. SIGPIPE is ignored for the same
# reason, at the bottom of this block.
say()  { printf '%s\n' "$*" || true; }
fact() { printf '%s=%s\n' "$1" "$2" || true; }

# ---- the last line, on every path ----------------------------------
#
# One handler, installed before anything can fail. `$?` is captured on the
# first line because everything below it would overwrite it.
# shellcheck disable=SC2329,SC2317  # installed as an EXIT trap below, which shellcheck cannot see as a call (SC2317 is the runner's older name for it)
on_exit() {
  local rc=$?
  if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]]; then rm -rf "$WORK_DIR"; fi
  printf 'exit=%s\n' "$rc" || true
}
trap on_exit EXIT
# Not a failure to be killed by. The connection can close under this program
# while it is still writing, and the work after that point still has to
# happen.
trap '' PIPE

die() { # $1 = exit code, $2 = a sentence an operator can act on
  local code="$1"; shift
  journal refused "$*"
  fact error "$*"
  exit "$code"
}

# ---- the configuration this program is allowed to read -------------
#
# Read by name, never sourced. The file is root-owned and 0644, so sourcing
# it would be safe today and would be a hole the first time somebody widens
# who may write /etc/aperire.
conf_value() { # $1 = key
  [[ -f "$CONF" ]] || return 0
  sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'"'"' ' || true
}

load_conf() {
  [[ -f "$CONF" ]] \
    || die 2 "there is no $CONF on this host, so this program does not know which endpoint to ask or which directory to update. Install the grant again: curl -fsSL https://get.aperire.one | bash -s -- --run update-grant"
  ENDPOINT="$(conf_value ENDPOINT)"
  INSTALL_DIR="$(conf_value INSTALL_DIR)"
  OPERATOR="$(conf_value OPERATOR)"
  # The dashboard's own account (ADR 0024). A conf written before the split
  # has only OPERATOR, which then meant both, so it stands in for this too.
  DASH_USER="$(conf_value DASH_USER)"
  DASH_USER="${DASH_USER:-$OPERATOR}"
  [[ -n "$ENDPOINT" ]]    || die 2 "$CONF names no ENDPOINT, so there is nowhere to ask what the current release is."
  [[ -n "$INSTALL_DIR" ]] || die 2 "$CONF names no INSTALL_DIR, so there is no tree to update."
  [[ -n "$OPERATOR" ]]    || die 2 "$CONF names no OPERATOR, and the checkout and the database belong to that account, not to root."
  [[ "$ENDPOINT" =~ $RE_ENDPOINT ]] \
    || die 2 "$CONF names an endpoint this program will not fetch from: '$ENDPOINT'."
  getent passwd "$OPERATOR" >/dev/null \
    || die 2 "$CONF names the account '$OPERATOR', and there is no such account on this host."
  # Root is never the tree's owner. Everything done "as the operator" here is
  # done to keep root out of a tree a login can change, and runuser -u root
  # would be root running it again, in particular the removal of old
  # rolled-back trees, which has no root fallback and must not gain one (#1150).
  [[ "$OPERATOR" != root && "$(getent passwd "$OPERATOR" | cut -d: -f3)" != 0 ]] \
    || die 2 "$CONF names '$OPERATOR' as the tree's owner, and that is root. The tree belongs to the operator who installed it; reinstall the grant: curl -fsSL https://get.aperire.one | bash -s -- --run update-grant"
  getent passwd "$DASH_USER" >/dev/null \
    || die 2 "$CONF names the dashboard account '$DASH_USER', and there is no such account on this host."
  # The update unpacks and builds the tree as OPERATOR, and root then runs
  # installers out of it. So OPERATOR is never a service account (ADR 0024):
  # not the dashboard's own account, and not any account with no login shell
  # (the dashboard's, the Advisor's, the relay's, the node's). A tree such an
  # account could write is a tree root must not trust.
  if [[ "$OPERATOR" == aperire-dashboard ]] \
     || { [[ "$OPERATOR" == "$DASH_USER" ]] && [[ "$DASH_USER" == aperire-dashboard ]]; }; then
    die 2 "$CONF names '$OPERATOR' as the tree's owner, which is the dashboard's own account. The tree belongs to the operator who installed it; reinstall the grant: curl -fsSL https://get.aperire.one | bash -s -- --run update-grant"
  fi
  case "$(getent passwd "$OPERATOR" | cut -d: -f7)" in
    */nologin|*/false)
      die 2 "$CONF names '$OPERATOR' as the tree's owner, and that is a service account with no login. The update builds the tree as its owner and root runs what it builds, so it will not build as a service account." ;;
  esac
  return 0
}

# ---- the payload ---------------------------------------------------
#
# Keys are allow-listed per verb and a repeat is a refusal, not a
# last-one-wins. Both matter for the same reason: every value below is
# printed back on the stream the page parses as key=value, and a parser that
# ignores what it does not know is a parser that would ignore `source=`.
P_TAG=""; P_COMMIT=""; P_SHA256=""; P_UNITS=""
parse_payload() { # $1 = verb, rest = the key=value words
  local verb="$1"; shift
  local word key value seen=""
  for word in "$@"; do
    [[ -n "$word" ]] || continue
    [[ "$word" == *=* ]] \
      || die 2 "'$word' is not a key=value, and this program reads nothing else after the verb."
    key="${word%%=*}"; value="${word#*=}"
    case " $seen " in
      *" $key "*) die 2 "the payload names '$key' twice, and this program will not guess which one was meant." ;;
    esac
    seen="$seen $key"
    case "$verb:$key" in
      apply:tag)      P_TAG="$value" ;;
      apply:commit)   P_COMMIT="$value" ;;
      apply:sha256)   P_SHA256="$value" ;;
      restart:units)  P_UNITS="$value" ;;
      *) die 2 "'$key' is not something '$verb' takes. This socket carries no source, no path and no argument: the endpoint is $CONF's and this program fetches from it itself." ;;
    esac
  done
  return 0
}

# ---- what the endpoint publishes -----------------------------------
#
# Two files, and they have to agree. release.json is the one a publisher
# could edit by hand; release.tar.gz.sha256 is written by a machine beside
# the archive. A disagreement is the endpoint mid-publish, which is a wait
# and never an update.
PUB_TAG=""; PUB_COMMIT=""; PUB_SHA256=""; PUB_AT=""; PUB_VERDICT=""
json_field() { # $1 = file, $2 = key
  sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1
}

fetch_published() {
  local json="$WORK_DIR/release.json" sums="$WORK_DIR/release.tar.gz.sha256" sum_field
  if ! curl -fsS --max-time "$FETCH_TIMEOUT" -o "$json" "$ENDPOINT/release.json" 2>/dev/null; then
    PUB_VERDICT=unreachable; return 0
  fi
  if ! curl -fsS --max-time "$FETCH_TIMEOUT" -o "$sums" "$ENDPOINT/release.tar.gz.sha256" 2>/dev/null; then
    PUB_VERDICT=unreachable; return 0
  fi
  PUB_TAG="$(json_field "$json" tag)"
  PUB_COMMIT="$(json_field "$json" commit)"
  PUB_SHA256="$(json_field "$json" sha256)"
  PUB_AT="$(json_field "$json" published_at)"
  sum_field="$(cut -d' ' -f1 < "$sums" | head -1)"
  if [[ ! "$PUB_SHA256" =~ $RE_SHA256 || "$PUB_SHA256" != "$sum_field" ]]; then
    PUB_VERDICT=mid_publish; return 0
  fi
  # From here on, release.json has only said WHICH archive. What that archive
  # is gets read from the signed document for it, after the signature checks,
  # and never from the file above.
  if ! verify_published; then
    PUB_TAG=""; PUB_COMMIT=""; PUB_AT=""
    PUB_VERDICT=unsigned
    return 0
  fi
  PUB_VERDICT=ok
  return 0
}

# Lab or real is a question of WHICH key, never of what kind: a host whose
# set is not the release key committed at a release's own commit
# (committed_signers_sha256, read only from a document that just verified
# against this host's set) trusts a lab or test key. Said once per run,
# loudly, because it is never the right state for a host an operator relies
# on. Asked of the release this host is on as well as the one on offer, so a
# lab host still says so when the public release is refused on its key.
LAB_SAID=0
say_if_lab_key() { # $1 = a release.json that has verified against LIB_DIR/release-signers
  [[ $LAB_SAID -eq 0 ]] || return 0
  local committed
  committed="$(release_json_field "$1" committed_signers_sha256 2>/dev/null)" || committed=""
  [[ "$committed" =~ $RE_SHA256 ]] || return 0
  [[ "$(release_signers_digest "$LIB_DIR/release-signers")" != "$committed" ]] || return 0
  LAB_SAID=1
  say "WARNING: this host trusts a release key that is not the one committed for its releases ($LIB_DIR/release-signers)."
  say "WARNING: that is a lab or test key. A host installed from a public release never has one."
  fact signers lab
  journal warning "the installed release key set is not the committed release key"
  return 0
}
say_if_lab_key_kept() {
  local cur dir
  cur="$(cat "$RELEASE_STORE/current" 2>/dev/null || true)"
  [[ "$cur" =~ $RE_SHA256 ]] || return 0
  dir="$RELEASE_STORE/$cur"
  release_verify "$dir/release.json" "$dir/release.json.sig" "$LIB_DIR/release-signers" 2>/dev/null || return 0
  say_if_lab_key "$dir/release.json"
}

# The signed document for PUB_SHA256, fetched under its immutable name and
# checked against this host's own key. Sets PUB_TAG, PUB_COMMIT, PUB_AT and
# PUB_BOOT_SHA256 from it; on any failure sets SIGN_WHY and returns 1.
SIGN_WHY=""; PUB_BOOT_SHA256=""
verify_published() {
  local dir="$WORK_DIR/signed" json sig named why
  mkdir -p "$dir"
  json="$dir/release.json"; sig="$dir/release.json.sig"
  if [[ ! -r "$LIB_DIR/release-verify-lib.sh" || ! -r "$LIB_DIR/release-signers" ]]; then
    SIGN_WHY="this host has no release key installed, so no release can be checked. Put it back with: curl -fsSL https://get.aperire.one | bash -s -- --run update-grant --program-only"
    return 1
  fi
  # shellcheck source=scripts/release-verify-lib.sh
  . "$LIB_DIR/release-verify-lib.sh"
  say_if_lab_key_kept
  if ! curl -fsS --max-time "$FETCH_TIMEOUT" -o "$json" "$ENDPOINT/release-${PUB_SHA256}.json" 2>/dev/null \
     || ! curl -fsS --max-time "$FETCH_TIMEOUT" -o "$sig" "$ENDPOINT/release-${PUB_SHA256}.json.sig" 2>/dev/null; then
    SIGN_WHY="the endpoint serves no signature for the release it names, and an unsigned release is not installed."
    return 1
  fi
  if ! why="$(release_verify "$json" "$sig" "$LIB_DIR/release-signers" 2>&1)"; then
    SIGN_WHY="the release the endpoint names is not signed by this host's release key, so it is not installed. ${why}"
    return 1
  fi
  named="$(release_json_field "$json" sha256)" || named=""
  if [[ "$named" != "$PUB_SHA256" ]]; then
    SIGN_WHY="the signed release.json is for a different archive than the one release.json points at."
    return 1
  fi
  say_if_lab_key "$json"
  PUB_TAG="$(release_json_field "$json" tag)" || PUB_TAG=""
  PUB_COMMIT="$(release_json_field "$json" commit)" || PUB_COMMIT=""
  PUB_AT="$(release_json_field "$json" published_at)" || PUB_AT=""
  # No date, no release: without one it cannot be told apart from an older
  # release replayed, and the downgrade check below would have nothing to do.
  if [[ ! "$PUB_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    SIGN_WHY="the signed release.json states no valid publish date, so it cannot be told apart from an older release."
    return 1
  fi
  PUB_BOOT_SHA256="$(release_json_field "$json" bootstrap_sha256)" || PUB_BOOT_SHA256=""
  if [[ ! "$PUB_BOOT_SHA256" =~ $RE_SHA256 ]]; then
    SIGN_WHY="the signed release.json names no install script, so there is nothing that could be run."
    return 1
  fi
  return 0
}

# The date the release this host is on was published, read from the signed
# copy the bootstrap kept, and believed only once that copy verifies. Empty
# when there is none (a host installed before signing, or from a clone).
installed_published_at() {
  local cur dir
  cur="$(cat "$RELEASE_STORE/current" 2>/dev/null || true)"
  [[ "$cur" =~ $RE_SHA256 ]] || return 0
  dir="$RELEASE_STORE/$cur"
  release_verify "$dir/release.json" "$dir/release.json.sig" "$LIB_DIR/release-signers" 2>/dev/null || return 0
  release_json_field "$dir/release.json" published_at 2>/dev/null || true
  return 0
}

# The newest publish date this host has ever installed, kept by the bootstrap
# in a root-owned file beside the store (high-water). Read whatever happened
# to the kept release: a store emptied or a kept copy gone must not be how
# the downgrade check is skipped. Believed only when it is a regular file,
# root's (or this run's own account in a test), writable by nobody else, and
# one date.
RE_DATE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
high_water_at() {
  local f="$RELEASE_STORE/high-water" meta want_uid at
  [[ -f "$f" && ! -L "$f" ]] || return 0
  want_uid="$(trusted_owner_uid)"
  meta="$(stat -c '%u:%a' -- "$f" 2>/dev/null)" || return 0
  [[ "${meta%%:*}" == "$want_uid" ]] && (( (8#${meta#*:} & 8#022) == 0 )) || return 0
  at="$(head -c 64 "$f" | head -1)"
  [[ "$at" =~ $RE_DATE ]] && printf '%s' "$at"
  return 0
}

# The date a release on offer has to be newer than: the later of the
# release this host is on and the high-water mark. Empty when neither is
# known (a host installed before signed releases, or from a clone).
floor_published_at() {
  local a b
  a="$(installed_published_at)"; b="$(high_water_at)"
  [[ "$a" =~ $RE_DATE ]] || a=""
  if [[ -z "$a" || ( -n "$b" && "$b" > "$a" ) ]]; then a="$b"; fi
  printf '%s' "$a"
}

# ---- what this host says it is -------------------------------------
#
# The same four lines the bootstrap writes, read one at a time so no JSON
# parser is needed on a box that may not have one.
INST_TAG=""; INST_COMMIT=""; INST_SHA256=""
stamp_field() { # $1 = key
  [[ -f "$INSTALL_DIR/.release" ]] || return 0
  sed -n "s/^  \"$1\": \"\(.*\)\",\?\$/\1/p" "$INSTALL_DIR/.release" | head -1
  return 0
}
read_stamp() {
  INST_TAG="$(stamp_field tag)"
  INST_COMMIT="$(stamp_field commit)"
  INST_SHA256="$(stamp_field sha256)"
  return 0
}

# ---- the units, discovered ------------------------------------------
present_units() {
  local u
  for u in "${UNITS_ALLOWED[@]}"; do
    [[ -f "$UNIT_DIR/${u}.service" ]] && printf '%s\n' "$u"
  done
  return 0
}

# What is serving right now. A timer-driven oneshot that happens to be
# running at this instant is a job and not a process serving anybody, so it
# is asked of systemd rather than matched against a list of names.
running_units() {
  local u
  while read -r u; do
    [[ -n "$u" ]] || continue
    [[ "$(systemctl is-active "${u}.service" 2>/dev/null)" == "active" ]] || continue
    [[ "$(systemctl show -p Type --value "${u}.service" 2>/dev/null)" == "oneshot" ]] && continue
    printf '%s\n' "$u"
  done < <(present_units)
  return 0
}

# ---- one run at a time ----------------------------------------------
#
# flock on a descriptor, not a file that has to be tidied up: a run killed
# between the two would leave a path behind and wedge this host until
# somebody found it. The lock is taken by every verb that changes the tree,
# `rollback` included: a rollback landing in the middle of an apply is the
# worst outcome this program can produce.
take_lock() {
  install -d -m 0755 -o root -g root "$RUN_DIR" 2>/dev/null || true
  if ! exec 9>"$LOCK_FILE"; then
    die 4 "this host has no $LOCK_FILE and no way to make one, so a second run cannot be kept out."
  fi
  flock -n 9 \
    || die 4 "another update is already running on this host. Watch that one; when it has finished, ask again."
  return 0
}

# ---- streaming the bootstrap ----------------------------------------
mark_step() { # $1 = one line of the bootstrap's output
  local entry phrase key rank line
  line="$1"
  for entry in "${STEP_PHRASES[@]}"; do
    phrase="${entry%%:*}"
    key="${entry#*:}"; rank="${key#*:}"; key="${key%%:*}"
    [[ "$line" == "$phrase" ]] || continue
    (( rank > STEP_RANK )) || return 0
    STEP_RANK=$rank
    fact step "$key"
    return 0
  done
  return 0
}

# The bootstrap, run as root with the operator's name in front of it.
#
# SUDO_USER is not decoration. get-aperire.sh reads OP_USER from it
# (`OP_USER="${SUDO_USER:-$(id -un)}"`), and everything the operator has to
# own goes through `as_operator`: the unpack, the swap, the database
# snapshot, the stamp. Reached from this socket there is no SUDO_USER at all,
# so the bootstrap would take root as the operator, refuse to run at its own
# privilege guard, and, had it not, leave a tree the dashboard could not
# write. That is what OPERATOR in update.conf is for.
#
# NO_COLOR, because the page renders this stream. The connection is not a
# terminal so the palette is already off; this is the second half of the same
# statement and it crosses into install.sh and its sub-installers.
run_bootstrap() { # $1 = the checked bootstrap
  local boot="$1" rc_file="$WORK_DIR/rc" line rc
  : > "$rc_file"
  while IFS= read -r line; do
    mark_step "$line"
    printf '%s\n' "$line" || true
  done < <(
    env SUDO_USER="$OPERATOR" NO_COLOR=1 \
        bash "$boot" --update --yes --no-restart --dir "$INSTALL_DIR" 2>&1
    printf '%s\n' "$?" > "$rc_file"
  )
  # Read from a file rather than taken from the loop: the loop's own status is
  # the read that ended it, and a pipeline's is not the child's here either.
  rc="$(cat "$rc_file" 2>/dev/null || echo 1)"
  [[ "$rc" =~ ^[0-9]+$ ]] || rc=1
  return "$rc"
}

# ---- verbs -----------------------------------------------------------

verb_check() {
  read_stamp
  fetch_published
  fact installed_tag "$INST_TAG"
  fact installed_commit "$INST_COMMIT"
  fact installed_sha256 "$INST_SHA256"
  if [[ "$PUB_VERDICT" == unreachable ]]; then
    say "$ENDPOINT did not answer, so what this host is on is all that is known here."
    say "Nothing was changed and nothing is claimed about whether it is current."
    fact verdict unreachable
    journal check "endpoint unreachable"
    return 0
  fi
  fact published_tag "$PUB_TAG"
  fact published_commit "$PUB_COMMIT"
  fact published_sha256 "$PUB_SHA256"
  fact published_at "$PUB_AT"
  if [[ "$PUB_VERDICT" == mid_publish ]]; then
    say "release.json and release.tar.gz.sha256 do not agree on the archive's sum,"
    say "which is what $ENDPOINT looks like part way through a publish. Ask again"
    say "in a few minutes; nothing here treats a disagreement as an update."
    fact verdict mid_publish
    journal check "mid publish"
    return 0
  fi
  if [[ "$PUB_VERDICT" == unsigned ]]; then
    # No verdict about this host, and no release offered: a release nobody
    # can show was signed is not a release. `unreachable` is the one reading
    # the page already has that offers nothing to apply.
    say "$SIGN_WHY"
    say "Nothing is offered as an update until the endpoint serves a release signed by the release key."
    fact signature refused
    fact verdict unreachable
    journal check "refused: $SIGN_WHY"
    return 0
  fi
  if [[ -n "$INST_SHA256" && "$INST_SHA256" == "$PUB_SHA256" ]]; then
    say "This host is on the release $ENDPOINT publishes."
    fact verdict current
    journal check "current"
    return 0
  fi
  # A different archive, published no later than what this host already has:
  # a replayed older release, validly signed. Apply would refuse it (exit 7),
  # so check does not offer it.
  local floor
  floor="$(floor_published_at)"
  if [[ -n "$floor" && ! "$PUB_AT" > "$floor" ]]; then
    say "The release $ENDPOINT names was published $PUB_AT, no later than what this host already has ($floor)."
    say "An update never goes backwards, so nothing is offered. A replayed older release looks exactly like this."
    fact published_older yes
    fact verdict unreachable
    journal check "refused: published $PUB_AT, not after $floor"
    return 0
  fi
  if [[ -z "$INST_SHA256" ]]; then
    say "This host carries no release stamp, so it cannot be shown to be current."
    say "An update installs what the endpoint publishes and writes the stamp."
  fi
  fact verdict behind
  journal check "behind"
  return 0
}

# The bootstrap, fetched and checked before it is run.
#
# Three checks, and none is the archive's: the sentinel last line, which is
# the guard a piped run already relies on and which a cut download fails; the
# checksum stamped in it, which has to be the one release.json names; and its
# own sha256, which has to be the one the SIGNED release names. The last one
# is what decides whether root runs it. The archive's own sum is the
# bootstrap's business, and it checks that, and the signature, again itself.
BOOT_PATH=""
fetch_bootstrap() {
  local boot="$WORK_DIR/get-aperire.sh" stamped
  say "fetching the bootstrap from $ENDPOINT"
  curl -fsS --max-time 120 -o "$boot" "$ENDPOINT/" 2>/dev/null \
    || die 5 "$ENDPOINT did not serve the install script, so nothing was fetched and nothing on this host has moved."
  [[ "$(tail -n 1 "$boot")" == '# --- end of get-aperire.sh ---' ]] \
    || die 5 "what $ENDPOINT served does not end with the install script's last line, so it arrived cut short. Nothing on this host has moved."
  # A script naming a different archive is the endpoint part way through a
  # publish: the bootstrap is renamed into place before release.json is. That
  # is a wait, and it is told apart first so it never reads as tampering.
  stamped="$(sed -n "s/^DEFAULT_EXPECTED_SHA256='\(.*\)'\$/\1/p" "$boot" | head -1)"
  if [[ "$stamped" != "$PUB_SHA256" ]]; then
    say "the install script names  ${stamped:-nothing}"
    say "release.json names        $PUB_SHA256"
    die 3 "the install script $ENDPOINT serves and the release.json beside it do not name the same archive, which is what a publish looks like part way through. Nothing was fetched and nothing on this host has moved."
  fi
  # And it is run as root, so it is run only when it is byte for byte the one
  # the signed release names. Whatever the lines above read out of it, this
  # is the check that decides.
  local got
  got="$(sha256sum "$boot" | cut -d' ' -f1)"
  if [[ -z "$PUB_BOOT_SHA256" || "$got" != "$PUB_BOOT_SHA256" ]]; then
    say "the signed release names  ${PUB_BOOT_SHA256:-nothing}"
    say "the install script is     $got"
    die 7 "the install script the endpoint serves is not the one the signed release names, so it was not run. Nothing on this host has moved."
  fi
  BOOT_PATH="$boot"
  return 0
}

# The trees and snapshots this run made, told apart from the ones that were
# already here by listing both sides of the run.
list_matching() { # $1 = glob suffix
  find "$(dirname "$INSTALL_DIR")" -maxdepth 1 -name "$(basename "$INSTALL_DIR")$1" 2>/dev/null \
    | grep -v -- '-wal$' | grep -v -- '-shm$' | sort || true
}
# The newest path matching the glob that was NOT there before the run. A host
# carries the trees and snapshots of earlier updates, and naming one of those
# as this run's would send a rollback to the wrong release.
new_since() { # $1 = a file holding the before list, $2 = glob suffix
  local path found=""
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    grep -qxF -- "$path" "$1" && continue
    found="$path"
  done < <(list_matching "$2")
  printf '%s' "$found"
  return 0
}

verb_apply() {
  local before_prev before_db previous snapshot units_before rc=0
  [[ "$P_TAG" =~ $RE_TAG ]] \
    || die 2 "apply needs tag=<the release's tag>, and '$P_TAG' is not one."
  [[ "$P_COMMIT" =~ $RE_COMMIT ]] \
    || die 2 "apply needs commit=<the release's commit>, and '$P_COMMIT' is not one."
  [[ "$P_SHA256" =~ $RE_SHA256 ]] \
    || die 2 "apply needs sha256=<64 hex characters>, and '$P_SHA256' is not one."

  take_lock
  [[ -f "$INSTALL_DIR/install.sh" ]] \
    || die 2 "there is no Aperire One checkout at $INSTALL_DIR, and an update swaps a tree in place rather than making one."

  fetch_published
  [[ "$PUB_VERDICT" != unreachable ]] \
    || die 5 "$ENDPOINT did not answer, so there is nothing to compare what you asked for against. Nothing was fetched."
  [[ "$PUB_VERDICT" != mid_publish ]] \
    || die 3 "release.json and release.tar.gz.sha256 at $ENDPOINT do not agree on the archive's sum, which is what a publish looks like part way through. Nothing was fetched. Ask again in a few minutes."
  [[ "$PUB_VERDICT" != unsigned ]] \
    || die 7 "$SIGN_WHY Nothing was fetched and nothing on this host has moved."

  # What the endpoint publishes, as facts, before anything is compared. The
  # page needs the NAME of the release root would install to say anything
  # useful about a refusal, and it cannot read update.conf to find out.
  fact published_tag "$PUB_TAG"
  fact published_commit "$PUB_COMMIT"
  fact published_sha256 "$PUB_SHA256"

  # The payload can narrow, never widen. All three, because a tag that agreed
  # and a sum that did not would be a release nobody named.
  #
  # Releases are NAMED in the refusal and the sums are printed beside it, on
  # their own lines. An operator reads a refusal to find out which release
  # this host would get; two 64-character hex strings in the middle of that
  # sentence are the thing that made the first live refusal unreadable (#293).
  if [[ "$P_SHA256" != "$PUB_SHA256" || "$P_TAG" != "$PUB_TAG" || "$P_COMMIT" != "$PUB_COMMIT" ]]; then
    say "asked for  ${P_TAG:-an unnamed release}, commit ${P_COMMIT:-unknown}"
    say "  sha256   $P_SHA256"
    say "published  ${PUB_TAG:-an unnamed release}, commit ${PUB_COMMIT:-unknown}"
    say "  sha256   $PUB_SHA256"
    if [[ "$P_TAG" != "$PUB_TAG" ]]; then
      die 3 "you asked for ${P_TAG:-an unnamed release} and $ENDPOINT publishes ${PUB_TAG:-an unnamed release}. This program installs what the endpoint publishes now, or nothing. Check again and ask for that one."
    fi
    die 3 "you asked for $P_TAG and $ENDPOINT publishes a different build of $P_TAG: the two do not name the same archive. This program installs what the endpoint publishes now, or nothing. Check again and ask for that one."
  fi

  # Already on it, and nothing is fetched to find out. The same guard the
  # bootstrap keeps, made here so that a page asking twice cannot be used to
  # swap this host's tree over and over.
  read_stamp
  if [[ -n "$INST_SHA256" && "$INST_SHA256" == "$PUB_SHA256" ]]; then
    say "This host is already on ${PUB_TAG:-this release}: the same archive, so there is"
    say "nothing to fetch and nothing to swap. Nothing was touched."
    fact verdict current
    fact stamp "${INST_TAG:-$INST_SHA256}"
    journal apply "already on ${PUB_TAG:-the published release}"
    return 0
  fi

  # Never backwards. A replayed older release is still a validly signed one,
  # so the signed date is the only thing that tells it apart.
  local inst_at
  inst_at="$(floor_published_at)"
  if [[ -n "$inst_at" && ! "$PUB_AT" > "$inst_at" ]]; then
    say "installed  published $inst_at"
    say "offered    published $PUB_AT"
    die 7 "the release on offer was published before the one this host is on, and an update never goes backwards. Nothing was fetched and nothing on this host has moved."
  fi

  before_prev="$WORK_DIR/before-previous"; list_matching '.previous-*' > "$before_prev"
  before_db="$WORK_DIR/before-db";           list_matching '.db-*'       > "$before_db"
  units_before="$(running_units | tr '\n' ' ')"
  journal apply "applying ${PUB_TAG:-the published release} ($PUB_SHA256) from $ENDPOINT"

  fetch_bootstrap
  say "the release $ENDPOINT publishes is ${PUB_TAG:-untagged}, commit ${PUB_COMMIT:-unknown}, published ${PUB_AT:-at an unstated time}."
  say ""

  if ! run_bootstrap "$BOOT_PATH"; then
    rc=1
  fi

  previous="$(new_since "$before_prev" '.previous-*')"
  snapshot="$(new_since "$before_db" '.db-*')"

  if [[ $rc -ne 0 ]]; then
    fact step "failed"
    [[ -n "$previous" ]] && fact previous "$previous"
    [[ -n "$snapshot" ]] && fact db_snapshot "$snapshot"
    if [[ -z "$previous" ]]; then
      say ""
      say "Nothing was swapped. The tree at $INSTALL_DIR is exactly as it was, and"
      say "the lines above say where the run stopped."
    else
      say ""
      say "The tree was swapped and the run did not finish. The release before this"
      say "one is kept at $previous, and 'rollback' puts it back."
    fi
    journal failed "the bootstrap did not finish"
    die 6 "the install script did not finish. What it printed is above, and this host is described in the lines beside it."
  fi

  # The previous tree keeps its own name. get-aperire.sh moves the stamp
  # FORWARD into the new tree and then writes over it, so after an update
  # nothing on the host says which release the kept tree is. Rollback needs
  # that answer, and the tree it describes is the honest place for it.
  if [[ -n "$previous" && -n "$INST_SHA256$INST_TAG" && ! -f "$previous/.release" ]]; then
    printf '{\n  "tag": "%s",\n  "commit": "%s",\n  "sha256": "%s",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' \
      "$INST_TAG" "$INST_COMMIT" "$INST_SHA256" \
      | runuser -u "$OPERATOR" -- tee "$previous/.release" >/dev/null 2>&1 || true
  fi

  read_stamp
  fact step "done"
  fact stamp "${INST_TAG:-$INST_SHA256}"
  fact stamp_commit "$INST_COMMIT"
  fact stamp_sha256 "$INST_SHA256"
  [[ -n "$previous" ]] && fact previous "$previous"
  [[ -n "$snapshot" ]] && fact db_snapshot "$snapshot"
  report_needs_restart "$units_before"
  journal applied "${INST_TAG:-$INST_SHA256} is on disk; nothing was restarted"
  return 0
}

# What is still running the release before this one.
#
# Taken from what was serving when the run started, filtered to what is still
# active now. Every one of them is a process whose code on disk changed
# underneath it, which is a real state with a consequence the operator meets
# at once: dashboard/public/ is served out of the tree, so a browser reload
# gets the new page against the old server.
report_needs_restart() { # $1 = the units that were running before the swap
  local u still=()
  # shellcheck disable=SC2086  # the caller passes a space-separated list on purpose
  for u in $1; do
    [[ "$(systemctl is-active "${u}.service" 2>/dev/null)" == "active" ]] || continue
    still+=("$u")
  done
  fact needs_restart "${still[*]-}"
  if [[ ${#still[@]} -eq 0 ]]; then
    say ""
    say "Nothing of Aperire One was running when this started, so there is nothing"
    say "whose code changed underneath it. The units are installed and enabled."
  else
    say ""
    say "The new code is on disk and nothing was restarted. The processes above are"
    say "still running the release before this one. None of this touched the node."
  fi
  return 0
}

verb_restart() {
  local want state waited ok_all=1
  local -a asked=() present=()
  [[ -n "$P_UNITS" ]] \
    || die 2 "restart needs units=<name,name>, and the payload named none."
  take_lock
  mapfile -t present < <(present_units)
  IFS=',' read -r -a asked <<< "$P_UNITS"
  for want in "${asked[@]}"; do
    want="${want// /}"
    [[ -n "$want" ]] || continue
    [[ "$want" =~ $RE_UNIT ]] \
      || die 2 "'$want' is not a unit name this program will act on."
    printf '%s\n' "${present[@]-}" | grep -qxF -e "$want" \
      || die 2 "'$want' is not one of this host's Aperire One units. This host has: ${present[*]:-none}. The node is not on that list and is never restarted from here."
  done

  # The dashboard's own unit goes last, whatever order the payload named, and
  # this is not tidiness. The dashboard is the process holding the other end
  # of this socket: restarting it first takes the reader away, and everything
  # after it in the list would be restarted into a connection nobody is
  # reading, or not at all. It is also the right operational order, because
  # the relay reconnects to a dashboard that is already back.
  local -a ordered=() last=()
  for want in "${asked[@]}"; do
    want="${want// /}"
    [[ -n "$want" ]] || continue
    case "$want" in
      aperire-server|aperire-read) last+=("$want") ;;
      *)                           ordered+=("$want") ;;
    esac
  done
  ordered+=(${last[@]+"${last[@]}"})

  journal restart "restarting ${ordered[*]}"
  for want in "${ordered[@]}"; do
    say "restarting ${want}.service"
    systemctl restart "${want}.service" >/dev/null 2>&1 || true
    # systemctl restart waits for its own job, so this is the second reading
    # rather than the first. A unit that comes back slowly (a dashboard drains
    # before it exits) is given the bound; one that has settled on `failed` is
    # not waited on at all.
    waited=0
    state=""
    while (( waited < RESTART_WAIT )); do
      state="$(systemctl is-active "${want}.service" 2>/dev/null || true)"
      [[ "$state" == "active" || "$state" == "failed" ]] && break
      sleep 1
      waited=$((waited + 1))
    done
    printf 'unit=%s state=%s\n' "$want" "${state:-unknown}" || true
    if [[ "$state" != "active" ]]; then
      ok_all=0
      fact error "${want}.service is ${state:-not answering} after the restart. Read: sudo journalctl -u ${want}.service -n 50 --no-pager"
    fi
  done
  [[ $ok_all -eq 1 ]] || journal restart "one or more units did not come back"
  drop_advisor_sudo_rules "${ordered[@]}"
  return 0
}

# The Advisor's old sudo rule, once the Advisor this restart brought back is
# running on its root socket (ADR 0025). The apply before this left the rule
# in place for the Advisor that was still running on it, because taking it
# first would have cut that process off from the node; this restart is the
# moment it stops mattering. The decision and the removal are the library's,
# the root-owned copy in /usr/local/lib/aperire (ADR 0024), never the tree's.
# A rule it keeps is said, not failed on: the next update finishes it.
TP_LIB=/usr/local/lib/aperire/trusted-path-lib.sh
if am_unprivileged; then TP_LIB="${APERIRE_UPDATE_TP_LIB:-$TP_LIB}"; fi
drop_advisor_sudo_rules() { # $@ = the units just restarted
  local restarted inst out
  [[ -f "$TP_LIB" && ! -L "$TP_LIB" ]] || return 0
  [[ "$(stat -c '%u' "$TP_LIB")" == 0 && $(( 0$(stat -c '%a' "$TP_LIB") & 022 )) -eq 0 ]] || return 0
  for restarted in "$@"; do
    case "$restarted" in
      aperire-advisord) inst="" ;;
      aperire-advisord-credcheck*) continue ;;
      aperire-advisord-*) inst="${restarted#aperire-advisord-}" ;;
      *) continue ;;
    esac
    # shellcheck source=scripts/trusted-path-lib.sh
    out="$( . "$TP_LIB" && trusted_drop_sudo_rule "$inst" 2>&1 )" || true
    [[ -n "$out" ]] && printf '%s\n' "$out"
  done
  return 0
}

# Which kept record belongs to the tree a rollback would bring back (#782).
# Read from what root wrote when the update moved that tree aside: the
# pointer beside the record names the tree by <dev>:<ino> and the key its
# record was kept under. Never from the tree's own .release stamp, which the
# tree's account can rewrite to choose any of the kept records. Prints the
# key; 1 when root holds no pointer for this tree, or none it can trust.
previous_tree_key() { # $1 = the kept tree
  local id key got
  [[ -d "$1" && ! -L "$1" ]] || return 1
  read -r id key < <(previous_pointer) || return 1
  got="$(stat -c '%d:%i' -- "$1" 2>/dev/null)" || return 1
  [[ "$got" == "$id" ]] || return 1
  printf '%s' "$key"
}

# Root's pointer, read and held to the same rule wherever it is read: a
# regular file root owns that nobody else can write, in the shape
# "<dev>:<ino> <key>". Prints "<dev>:<ino> <key>". The first field is the
# identity of the one tree a rollback may bring back, and a rollback keeps it
# from the moment it judges that tree to the moment it has moved it in (#960).
previous_pointer() {
  local ptr="$RELEASE_DIGESTS.previous" meta want_uid line id key
  [[ -f "$ptr" && ! -L "$ptr" ]] || return 1
  want_uid="$(trusted_owner_uid)"
  meta="$(stat -c '%u:%a' -- "$ptr" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$want_uid" ]] && (( (8#${meta##*:} & 8#022) == 0 )) || return 1
  line="$(head -1 -- "$ptr")"
  id="${line%% *}"; key="${line#* }"
  [[ "$id" =~ ^[0-9]+:[0-9]+$ && "$key" =~ ^([0-9a-f]{64}|git-[0-9a-f]{40})$ ]] || return 1
  printf '%s %s\n' "$id" "$key"
}

# The two libraries a rollback stages the restored tree's installers with,
# root's own copies (install-update-grant.sh and every update place them).
# Checked before anything moves: without them root cannot check what it
# would run, so it runs nothing (#764).
rollback_libs_ok() {
  local f meta want_uid
  want_uid="$(trusted_owner_uid)"
  for f in "$LIB_DIR/release-digests-lib.sh" "$LIB_DIR/trusted-path-lib.sh"; do
    [[ -f "$f" && ! -L "$f" ]] || return 1
    meta="$(stat -c '%u:%a' -- "$f" 2>/dev/null)" || return 1
    [[ "${meta%%:*}" == "$want_uid" ]] && (( (8#${meta##*:} & 8#022) == 0 )) || return 1
  done
  return 0
}

# The restored tree's installers, staged by root into its own directory,
# each read once and held to the restored record and the trusted-path check
# (rd_stage_tree, root's own copy of the library). Prints the directory.
stage_restored_tree() {
  local stage_out="$WORK_DIR/run"
  (
    # The record root checks against, for an unprivileged test run only: as
    # root the library takes its constant and ignores this.
    export APERIRE_RELEASE_DIGESTS="$RELEASE_DIGESTS"
    # shellcheck source=scripts/release-digests-lib.sh
    . "$LIB_DIR/release-digests-lib.sh"
    rm -rf -- "$stage_out" && mkdir -m 0755 -- "$stage_out" || exit 2
    rd_stage_tree "$INSTALL_DIR" "$stage_out" || {
      # 6: the account check could not run, which is not a finding about a file (#1111).
      why="${RD_REFUSED_WHY:-}"; rm -rf -- "$stage_out"; [[ "$why" == accounts ]] && exit 6; exit 1
    }
  ) || return $?
  chmod 0755 "$WORK_DIR"
  printf '%s' "$stage_out"
}

# The tree that came back gets the record it came with, and nothing else.
#
# The record being rolled away from is kept under its own key first, so a
# roll forward again finds it. Then the record kept under the restored
# tree's key, the one root recorded for it when it moved aside (#782),
# becomes the record. When there is none, the record becomes one that
# refuses every copy and says how to put a release back. It is never
# removed: "no record" is the fallback that copies unchecked, and nothing a
# socket can ask for may reach it.
restore_release_digests() { # $1 = the restored tree's key, from previous_tree_key
  local cur="$RELEASE_DIGESTS" kept="$RELEASE_DIGESTS.kept" key="${1:-}" out_key tmp
  local key_re='^([0-9a-f]{64}|git-[0-9a-f]{40})$'
  mkdir -p "$(dirname "$cur")" 2>/dev/null || true
  # This host has a record from here on, whichever branch below is taken.
  [[ -f "$(dirname "$cur")/digests-required" ]] \
    || printf 'This host checks every root copy against its release digests.\n' > "$(dirname "$cur")/digests-required"
  if [[ -f "$cur" && ! -L "$cur" ]]; then
    out_key="$(sed -n 's/^# key //p' "$cur" | head -1)"
    if [[ "$out_key" =~ $key_re ]]; then
      [[ -d "$kept" && ! -L "$kept" ]] || { rm -rf "$kept"; mkdir -m 0755 "$kept"; }
      mv -fT "$cur" "$kept/$out_key" 2>/dev/null || true
    fi
  fi
  if [[ "$key" =~ $key_re && -f "$kept/$key" && ! -L "$kept/$key" ]] && mv -fT "$kept/$key" "$cur"; then
    say "the release digests of the tree that came back are in place again (${key:0:12}...)."
    return 0
  fi
  tmp="$(mktemp "$cur.XXXXXXXXXX")"
  {
    printf '# Aperire One release digests: none this host kept for the tree a rollback restored.\n'
    printf '# refuse the tree a rollback restored (%s) has no release digests on this host, so nothing is copied out of it as root. Put a release back with: curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' "${key:-no release stamp}"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -fT "$tmp" "$cur"
  say "the tree that came back has no release digests kept on this host, so its root copies are refused"
  say "rather than made unchecked. Put a release back with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  return 0
}

# A rollback across ADR 0025 (#779 review, M1). An update converts the
# Advisor's unit in place to --wrapper-socket= and removes its sudo rule. The
# release before that knows neither: its root-side programs know nothing of
# the socket, a rebuild of its Advisor from its own source stops on the
# unknown flag and is restarted in a loop by systemd, and the only route that
# release has to the node is the sudo rule this host no longer grants.
# Nothing in a rollback may write a sudo rule back (ADR 0025: none,
# anywhere). So it is refused, before anything moves, and the way back by
# hand is named. (The rollback itself carries the newer Advisor build back,
# so the daemon that is running keeps starting; it is the rest that breaks.)
#
# The kept release is judged by its Advisor's SOURCE, never by a binary in
# the kept tree (#951): an update carries advisor/bin into the new tree, so a
# kept tree has none, and a missing binary says nothing about the release.
# Root's record of that tree (the one previous_tree_key resolves) lists the
# sha256 of every file the release shipped. The Go files the daemon is built
# from are read from the kept tree once, each held to the record's digest,
# and the flag's name is searched for in the bytes that matched.
#
# advisord_source_knows_the_socket answers: 0 the release's Advisor has the
# flag, 1 its source is on record, every file of it verified, and none of it
# has the flag, 2 root cannot tell (no record it trusts, no Advisor source in
# it, or ANY recorded file that is missing, not a regular file, too large, or
# not the one the record names). One bad file is never skipped: the rest
# agreeing would call a release old on evidence that is partly missing.
#
# The tree is the login's, so nothing is opened by a name twice. The python
# below opens the tree's parent once, the tree and each directory under it
# O_NOFOLLOW relative to the one before, and each file O_NOFOLLOW|O_NONBLOCK
# relative to its directory; the open file is checked to be the regular file
# that was listed, read through that descriptor up to the cap, and hashed and
# searched from that one read. A link is never followed, a pipe never blocks,
# a device is never opened. Read, never run.
_ADVISORD_SOURCE_PY="$(cat <<'ADVISORD_SOURCE_EOF'
import hashlib, os, re, stat, subprocess, sys
# Exit 0: the flag is there. Exit 10: every recorded file verified and none
# has it. Anything else, a crash included, is "cannot tell": the caller reads
# no other code as "old".
def main(tree, rec):
    MAX = 16777216
    NF = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
    pat = re.compile(r"^([0-9a-f]{64})  (advisor/cmd/aperire-advisord/[A-Za-z0-9._+-]+\.go)$")
    # Only a run that is not root can be told to act between the check and the
    # open, so a suite can play the login's race. As root it is never read.
    hook = os.environ.get("APERIRE_UPDATE_TEST_BETWEEN") if os.geteuid() != 0 else None
    want = []
    with open(rec, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pat.match(line.rstrip("\n"))
            if m and not m.group(2).endswith("_test.go"):
                want.append((m.group(1), m.group(2)))
    if not want:
        return 2
    found = False
    parent = os.path.realpath(os.path.dirname(tree.rstrip("/")) or ".")
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        tfd = os.open(os.path.basename(tree.rstrip("/")), os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=pfd)
    finally:
        os.close(pfd)
    try:
        for digest, rel in want:
            parts = rel.split("/")
            dfd = os.dup(tfd)
            try:
                for d in parts[:-1]:
                    nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=dfd)
                    os.close(dfd)
                    dfd = nfd
                lst = os.stat(parts[-1], dir_fd=dfd, follow_symlinks=False)
                if not stat.S_ISREG(lst.st_mode) or lst.st_size > MAX:
                    return 2
                if hook:
                    subprocess.run([hook, os.path.join(tree, rel)], check=False)
                fd = os.open(parts[-1], os.O_RDONLY | NF, dir_fd=dfd)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode) or (st.st_ino, st.st_dev) != (lst.st_ino, lst.st_dev):
                        return 2
                    data = b""
                    while len(data) <= MAX:
                        chunk = os.read(fd, 1 << 20)
                        if not chunk:
                            break
                        data += chunk
                finally:
                    os.close(fd)
            finally:
                os.close(dfd)
            if len(data) > MAX or hashlib.sha256(data).hexdigest() != digest:
                return 2
            if b'"wrapper-socket"' in data:
                found = True
    finally:
        os.close(tfd)
    return 0 if found else 10
try:
    code = main(sys.argv[1], sys.argv[2])
except BaseException:
    code = 2
sys.exit(code)
ADVISORD_SOURCE_EOF
)"

advisord_source_knows_the_socket() { # $1 = the kept tree, $2 = the tree's key
  local rec="$RELEASE_DIGESTS.kept/$2" meta want_uid rc=0
  want_uid="$(trusted_owner_uid)"
  [[ -f "$rec" && ! -L "$rec" ]] || return 2
  meta="$(stat -c '%u:%a' -- "$rec" 2>/dev/null)" || return 2
  [[ "${meta%%:*}" == "$want_uid" ]] && (( (8#${meta##*:} & 8#022) == 0 )) || return 2
  timeout 60 python3 -I -c "$_ADVISORD_SOURCE_PY" "$1" "$rec" </dev/null >/dev/null 2>&1 || rc=$?
  # 10 is "verified, and no flag"; nothing else, a crash included, is a verdict.
  case $rc in 0) return 0 ;; 10) return 1 ;; *) return 2 ;; esac
}

refuse_a_rollback_across_the_socket() { # $1 = the kept tree, $2 = its key
  local f rc
  for f in "$UNIT_DIR"/aperire-advisord.service "$UNIT_DIR"/aperire-advisord-*.service; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    case "${f##*/}" in aperire-advisord-credcheck*) continue ;; esac
    grep -q -- '--wrapper-socket=' "$f" || continue
    rc=0
    advisord_source_knows_the_socket "$1" "$2" || rc=$?
    [[ $rc -eq 0 ]] && continue
    if [[ $rc -eq 1 ]]; then
      die 2 "refusing to roll back to $1: ${f##*/} reaches the node through the Advisor's root socket (ADR 0025), and the Advisor in that release predates the socket. A rollback would put that release's root-side programs back, and they know nothing of the socket, and the next rebuild of its Advisor from that source would stop on the --wrapper-socket flag and restart in a loop. The only way that release reached the node was a sudo rule, which this host no longer grants and a rollback will never write back. Nothing was changed. To go back anyway, remove the Advisor first (curl -fsSL https://get.aperire.one/uninstall | bash -s -- --role=advisor), then roll back, and install that release's Advisor with its own installer, knowing it brings the sudo rule with it."
    fi
    die 2 "refusing to roll back to $1: ${f##*/} reaches the node through the Advisor's root socket (ADR 0025), and root cannot confirm that the Advisor in that release has the socket. The release digests root kept for that tree name no Advisor source, or a source file in the tree is not the one they name. Nothing was changed. To go back by hand, install that release from its published archive with get-aperire.sh."
  done
  return 0
}

# The fleet broker's pin on the install directory, after the rollback's swap
# (#828). The same root-only argv mode the update calls, for the same reason:
# the swap is a rename, $INSTALL_DIR gets the inode of the tree that came
# back, and the broker would refuse every approval as install_moved. It
# re-records only when the tree moved aside ($1) carries the recorded id and
# $INSTALL_DIR is the directory root read before it moved in ($2), and
# answers already_current when the pin already names the tree that came back
# (an update whose own re-record was refused, then this rollback).
#
# stdin closed and bounded: this program's stdin is the update socket, and a
# broker from before the mode reads its verb from stdin. Only an exact
# answer is believed. Never fatal: the rollback has happened either way.
rerecord_broker_grant() { # $1 = the tree moved aside, $2 = <dev>:<ino> of the tree moved in
  local out reason
  if [[ ! -e "$FLEET_BROKER" || ! -e "$FLEET_BROKER_ETC/fleet-broker.conf" ]]; then
    fact broker_grant absent
    return 0
  fi
  if [[ -z "$2" ]]; then
    out="refused=no_swap_id"
  else
    out="$(env APERIRE_ETC="$FLEET_BROKER_ETC" timeout -k 5 60 "$FLEET_BROKER" \
             --rerecord-install-dir --previous "$1" --expect "$2" </dev/null 2>&1)" || true
  fi
  if grep -qx 'rerecorded=1' <<<"$out"; then
    fact broker_grant rerecorded
    say "the fleet broker's grant now records the tree that came back."
  elif grep -qx 'already_current=1' <<<"$out"; then
    fact broker_grant already_current
    say "the fleet broker's grant already records the tree that came back."
  elif reason="$(sed -n 's/^refused=\([a-z_]*\)$/\1/p' <<<"$out" | head -1)" && [[ -n "$reason" ]]; then
    fact broker_grant stale
    say "the fleet broker's grant does not record the tree that came back ($reason), so it refuses"
    say "pairing approvals as install_moved. Re-record it with the full installer:"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant"
  else
    fact broker_grant too_old
    say "the installed fleet broker cannot re-record which tree the install is, so it refuses"
    say "pairing approvals as install_moved. Install the grant again:"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant"
  fi
  return 0
}

# The tree that moved into the install directory is not the one that was
# judged. Nothing has been carried and nothing has run from it. The release
# that was running goes back where it was, and the tree that landed is kept
# aside under its own name so it can be looked at; this program removes
# neither. The login owns both parents, so these are the same two renames the
# rollback itself makes, by name, and the result is checked by identity again.
refuse_an_unjudged_tree() { # $1 = where the running release was moved, $2 = judged id, $3 = id that landed, $4 = stamp
  local rolled="$1" judged="$2" landed="$3" aside back
  aside="${INSTALL_DIR}.unjudged-$4"
  while [[ -e "$aside" ]]; do aside="${aside}-1"; done
  fact step "failed"
  fact rolled_back "$rolled"
  journal failed "the tree that moved into $INSTALL_DIR was not the one that was judged"
  if runuser -u "$OPERATOR" -- mv -T "$INSTALL_DIR" "$aside" \
     && runuser -u "$OPERATOR" -- mv -T "$rolled" "$INSTALL_DIR"; then
    back="$(stat -c '%d:%i' -- "$INSTALL_DIR" 2>/dev/null || true)"
    die 6 "refusing to roll back: the name of the kept tree was changed to another tree after root judged it, so what moved into $INSTALL_DIR (${landed:-nothing readable}) was not the tree root had judged ($judged). Nothing was carried across and nothing was installed or run from it. The release that was running is back at $INSTALL_DIR (${back:-unreadable}); the tree that landed is at $aside, and nothing here removes it."
  fi
  die 6 "refusing to roll back: the name of the kept tree was changed to another tree after root judged it, so what moved into $INSTALL_DIR (${landed:-nothing readable}) was not the tree root had judged ($judged). Nothing was carried across and nothing was installed or run from it, but the two renames to put the release back did not both land. The release that was running is at $rolled; the tree that is at $INSTALL_DIR is not trusted. Move it aside and move $rolled back by hand."
}

# Rolled-back trees beside the install: each rollback leaves the release it
# left as $INSTALL_DIR.rolled-back-<stamp>, and until #1122 nothing ever
# removed one. The newest ROLLED_BACK_MAX stay and older ones go, the same way
# get-aperire.sh prunes the trees an update moves aside (#958): by directory,
# with the operator's own account and never root, never the running tree (its
# name has no stamp), never a link, and never one that still holds data/ or
# config, which is the operator's.
#
# Three, not the eight an update keeps: eight is how far back root keeps release
# digests, and a rolled-back tree is nothing a rollback or an update returns to,
# so no record of it is needed. It is the release you left, and what it is worth
# is a look at what you were running when you changed your mind. A failure is
# said and never fatal: the rollback is done.
ROLLED_BACK_MAX=3
ROLLED_BACK_PRUNED=0 ROLLED_BACK_HELD=0 ROLLED_BACK_KEPT=0 ROLLED_BACK_SKIPPED=0
prune_rolled_back_trees() { # $1 = the tree this rollback just made
  ROLLED_BACK_PRUNED=0 ROLLED_BACK_HELD=0 ROLLED_BACK_KEPT=0 ROLLED_BACK_SKIPPED=0
  local parent base name t i=0 c held mine_id=""
  local -a trees=()
  # The tree this rollback just made is the one the closing text says is kept,
  # so it is held by identity and never removed, whatever the names sort to (a
  # clock that stepped back would otherwise put it past the count).
  mine_id="$(stat -c '%d:%i' -- "$1" 2>/dev/null || true)"
  # Held by identity or not at all. Without it the tree just made could be
  # pruned by sort order while the closing text says it was kept, so nothing is
  # removed and the text says so (ROLLED_BACK_SKIPPED).
  if [[ -z "$mine_id" ]]; then
    ROLLED_BACK_SKIPPED=1
    say "could not read $1, the tree this rollback just made, so no older rolled-back tree was looked at or removed."
    fact rolled_back_removed 0
    return 0
  fi
  parent="$(dirname -- "$INSTALL_DIR")"; base="$(basename -- "$INSTALL_DIR")"
  # Newest first: the stamp is UTC to the second and a clash adds -1, so the
  # names sort by age. type d leaves a link out of the list altogether.
  mapfile -t trees < <(find "$parent" -maxdepth 1 -type d -name "${base}.rolled-back-*" -printf '%f\n' 2>/dev/null | LC_ALL=C sort -r)
  for name in "${trees[@]}"; do
    # Only the names a rollback gives. The login chooses what else sits beside
    # the install, and a name outside this shape is not ours to remove or to
    # print into a command line.
    [[ "${name#"$base".rolled-back-}" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)*$ ]] || continue
    i=$((i + 1))
    t="$parent/$name"
    if [[ $i -le $ROLLED_BACK_MAX ]] \
       || { [[ -n "$mine_id" ]] && [[ "$(stat -c '%d:%i' -- "$t" 2>/dev/null)" == "$mine_id" ]]; }; then
      ROLLED_BACK_KEPT=$((ROLLED_BACK_KEPT + 1)); continue
    fi
    held=0
    [[ -d "$t/data" ]] && held=1
    for c in "${CARRY_CONFIG[@]}"; do [[ -f "$t/dashboard/config/$c" ]] && held=1; done
    for c in "${CARRY_ADVISOR[@]}"; do [[ -d "$t/advisor/$c" ]] && held=1; done
    if [[ $held -eq 1 ]]; then
      ROLLED_BACK_HELD=$((ROLLED_BACK_HELD + 1)); ROLLED_BACK_KEPT=$((ROLLED_BACK_KEPT + 1))
      say "kept $t: it still holds files that were meant to move out of it (data/ or config), which are yours. Nothing here removes it."
      continue
    fi
    if runuser -u "$OPERATOR" -- rm -rf -- "$t" 2>/dev/null && [[ ! -e "$t" ]]; then
      ROLLED_BACK_PRUNED=$((ROLLED_BACK_PRUNED + 1)); continue
    fi
    ROLLED_BACK_KEPT=$((ROLLED_BACK_KEPT + 1))
    say "could not remove $t as $OPERATOR (something in it belongs to another account), so it was left. If you know it is an old rolled-back tree, remove it yourself:  sudo rm -rf -- $(printf '%q' "$t")"
  done
  fact rolled_back_kept "$ROLLED_BACK_KEPT"
  fact rolled_back_removed "$ROLLED_BACK_PRUNED"
  return 0
}

verb_rollback() {
  local previous rolled stamp snapshot role n swapped_in judged_id landed
  local -a trees=() found_trees=()
  local t
  take_lock
  mapfile -t found_trees < <(list_matching '.previous-*')
  # A link is not a kept tree: the update moves a directory aside, never a
  # link, and a link here would be moved into the install directory as one.
  for t in "${found_trees[@]}"; do
    [[ -L "$t" ]] || trees+=("$t")
  done
  n=${#trees[@]}
  [[ $n -ne 0 ]] \
    || die 2 "there is no kept tree beside $INSTALL_DIR to roll back to. An update leaves one behind (and keeps the newest 8 of them, the ones root still holds release digests for), so a host with none has not been updated by this program, or its kept trees were removed by hand."
  previous="${trees[0]}"
  if [[ $n -gt 1 ]]; then
    # An update keeps the newest 8 trees it moves aside (older ones are
    # pruned, #958), so a host updated more than once holds several (#951). Root's pointer names one
    # of them by <dev>:<ino>: the tree the last update moved aside, and the
    # only one previous_tree_key accepts. That one is the tree a rollback
    # puts back; the rest are not touched. With the pointer naming none of
    # them, this program still will not choose.
    local found=0
    for t in "${trees[@]}"; do
      if previous_tree_key "$t" >/dev/null; then
        previous="$t"; found=$((found + 1))
      fi
    done
    [[ $found -eq 1 ]] \
      || die 2 "there are $n kept trees beside $INSTALL_DIR, and this program will not choose between them: ${trees[*]}. Root's record of the tree the last update moved aside names none of them. Move the ones you do not want aside, or put one back by hand."
    say "there are $n kept trees; the one the last update moved aside is $previous, and that is the one that comes back."
  fi
  [[ -f "$previous/install.sh" ]] \
    || die 2 "$previous is not an Aperire One checkout, so it is not a release to go back to."
  # Root runs the restored tree's installer only from a copy it checked
  # against that tree's own record (#764), so both have to be here before
  # anything moves.
  rollback_libs_ok \
    || die 2 "refusing to roll back: this host has no root-owned copy of the libraries that check what a rollback runs ($LIB_DIR/release-digests-lib.sh and trusted-path-lib.sh), so root cannot run the restored tree's installer. Nothing was changed. One update from the published release puts them in place: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  local key=""
  key="$(previous_tree_key "$previous")" || key=""
  [[ -n "$key" && -f "$RELEASE_DIGESTS.kept/$key" && ! -L "$RELEASE_DIGESTS.kept/$key" ]] \
    || die 2 "refusing to roll back to $previous: root holds no release digests it recorded for that tree, so it cannot check the installer it would run from it. Its own .release stamp is not used to choose one, since the tree's account can rewrite it. Nothing was changed. To go back by hand, install that release from its published archive with get-aperire.sh."
  refuse_a_rollback_across_the_socket "$previous" "$key"
  # What was judged, by identity, from root's own pointer: previous_tree_key
  # just accepted $previous only because it carries exactly this id.
  judged_id="$(previous_pointer | cut -d' ' -f1)" || judged_id=""
  [[ "$judged_id" =~ ^[0-9]+:[0-9]+$ ]] \
    || die 2 "refusing to roll back to $previous: root's record of which tree the last update moved aside could not be read a second time. Nothing was changed."

  read_stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  rolled="${INSTALL_DIR}.rolled-back-${stamp}"
  while [[ -e "$rolled" ]]; do rolled="${rolled}-1"; done
  resolve_role; role="$ROLE_FOUND"

  journal rollback "returning to $previous"
  fact step "carry"
  say "putting $previous back, and moving what is yours across to it."
  say ""

  # The same order the update uses, and the order is the whole safety
  # argument: rename first, which loses nothing and cannot be half done, then
  # move the new tree in, then carry the files out of the one that was
  # renamed. At every instant the database exists in exactly one place.
  runuser -u "$OPERATOR" -- mv "$INSTALL_DIR" "$rolled" \
    || die 6 "could not move $INSTALL_DIR aside to $rolled, so nothing was replaced."
  # The tree that moves in is the one judged above, identified by root's own
  # pointer (#960). It is also what the fleet broker's pin is told to expect
  # (#828). It is not read off $previous here: the name is in the login's home,
  # and a stat of it now would be a second look at whatever is under it.
  swapped_in="$judged_id"
  # Test-only, and honoured only when not root: a command run between the
  # judgment above and the move below, to put the kept tree's name on
  # something else.
  if am_unprivileged && [[ -n "${APERIRE_UPDATE_TEST_BEFORE_MOVE:-}" ]]; then
    "$APERIRE_UPDATE_TEST_BEFORE_MOVE" "$previous" || true
  fi
  runuser -u "$OPERATOR" -- mv -T "$previous" "$INSTALL_DIR" \
    || die 6 "the tree that was here is at $rolled and $previous did not move into $INSTALL_DIR. Nothing was deleted; move it back by hand."
  # Judged by identity, moved by name: the name could have been changed to
  # another tree in between (#960). What is at $INSTALL_DIR now has to be the
  # tree that was judged, before anything runs from it. If it is not, put the
  # release that was running back and stop.
  landed="$(stat -c '%d:%i' -- "$INSTALL_DIR" 2>/dev/null)" || landed=""
  if [[ "$landed" != "$judged_id" ]]; then
    refuse_an_unjudged_tree "$rolled" "$judged_id" "$landed" "$stamp"
  fi

  carry_back "$rolled"
  restore_release_digests "$key"
  rerecord_broker_grant "$rolled" "$swapped_in"

  fact step "install"
  say ""
  say "installing from the tree that came back, and restarting nothing."
  # No --with-advisor here, deliberately. #641's reveal window is only ever
  # planted by install-advisord.sh, and, since the account-move re-root
  # finding against #645, replanted by install-advisor-account.sh too —
  # both reachable only through install-advisor-stack.sh, which
  # --with-advisor is what threads install.sh's own call into. That must
  # stay unreachable from any signed, aggregator-triggered path (update/apply,
  # and this rollback), or a compromised aggregator could replant its own
  # window rather than waiting for one root actually opens. If a future
  # change ever threads --with-advisor through here, re-check #641's
  # security analysis and #651 (the update carry path's own
  # window-preservation guarantee) first.
  # Root runs a copy of the restored tree's installers it staged and checked
  # against the record that came back with it (#764), never the tree's bytes.
  local staged rc=0 refused_log strc=0
  staged="$(stage_restored_tree)" || strc=$?
  if [[ $strc -ne 0 || -z "$staged" ]]; then
    fact step "failed"
    fact rolled_back "$rolled"
    journal failed "root would not run the restored tree's installers"
    if [[ $strc -eq 6 ]]; then
      die 6 "the tree came back, and root would not run its installers: the account check could not run (systemd did not answer), so no file in it was judged, and nothing says it changed. Nothing was installed from it. $INSTALL_DIR holds the earlier release and $rolled holds the one you left; run the rollback again to retry the check before restarting anything."
    fi
    die 6 "the tree came back, and root would not run its installers: a file in it is not the one its release shipped, or a service account can change it (named above). Nothing was installed from it. $INSTALL_DIR holds the earlier release and $rolled holds the one you left; read the lines above before restarting anything."
  fi
  refused_log="$WORK_DIR/refused.log"
  : > "$refused_log"
  env SUDO_USER="$OPERATOR" NO_COLOR=1 APERIRE_INSTALL_TREE="$INSTALL_DIR" RD_REFUSED_LOG="$refused_log" \
      bash "$staged/install.sh" "--role=$role" --yes --no-restart --no-preflight --quiet-existing || rc=$?
  if [[ $rc -eq 4 ]]; then
    fact step "failed"
    fact rolled_back "$rolled"
    journal failed "the install from the restored tree finished, and root refused copies out of it"
    die 6 "the tree came back and the install from it finished, but root refused to copy $(grep -c . "$refused_log" 2>/dev/null || echo some) file(s) out of it (listed above), and kept the copies it had. $INSTALL_DIR holds the earlier release and $rolled holds the one you left."
  elif [[ $rc -ne 0 ]]; then
    fact step "failed"
    fact rolled_back "$rolled"
    journal failed "the install from the restored tree did not finish"
    die 6 "the tree came back and the install from it did not finish. $INSTALL_DIR holds the earlier release and $rolled holds the one you left; read the lines above before restarting anything."
  fi

  read_stamp
  snapshot="$(list_matching '.db-*' | grep -v -- '-wal$' | grep -v -- '-shm$' | tail -1 || true)"
  prune_rolled_back_trees "$rolled"
  fact step "done"
  fact rolled_back "$rolled"
  fact stamp "${INST_TAG:-${INST_SHA256:-}}"
  fact stamp_sha256 "$INST_SHA256"
  [[ -n "$snapshot" ]] && fact db_snapshot "$snapshot"
  say ""
  if [[ -z "$INST_SHA256$INST_TAG" ]]; then
    say "The tree that came back carries no release stamp, so this host reads as an"
    say "unknown release until it is installed again from a published one."
  fi
  if [[ -n "$snapshot" ]]; then
    say "db snapshot kept at $snapshot; restore it by hand if the update changed the schema."
  else
    say "There is no database snapshot beside the checkout, so there is nothing to"
    say "restore by hand either. The database you have been running on came back with"
    say "the tree."
  fi
  # What this run did with the trees it left behind, said as what was kept and
  # what was removed, with nothing for the operator to clean up (#1122).
  say ""
  if [[ $ROLLED_BACK_SKIPPED -eq 1 ]]; then
    say "The release you left is at $rolled. This host keeps the newest $ROLLED_BACK_MAX rolled-back trees and removes"
    say "older ones, but this rollback could not read that tree to hold it, so it removed none."
  else
    say "The release you left is kept at $rolled. This host keeps the newest $ROLLED_BACK_MAX rolled-back trees"
    say "and removes older ones: $ROLLED_BACK_KEPT kept, $ROLLED_BACK_PRUNED removed by this rollback."
  fi
  [[ $ROLLED_BACK_HELD -eq 0 ]] || say "$ROLLED_BACK_HELD of the kept ones still hold files of yours and were left as they are (named above)."
  report_needs_restart "$(running_units | tr '\n' ' ')"
  journal rolledback "$INSTALL_DIR is the earlier release; nothing was restarted"
  return 0
}

# What the update carried forward, carried back. The Advisor's directories as
# root, because they are its account's and a directory can only be renamed
# into another parent by someone who may write it: the operator owns both
# parents and still got "Permission denied" on the first live reinstall.
# fleet-link.json is the credential pairing wrote: the ONLY copy of it is this
# file, and a node that loses it stops dialling its aggregator on its first
# update, with a re-pair as the only way back. mv keeps its 0600.
# fleet-links.json is the aggregator's half: the hash of every paired node's
# link credential. Lose it and every node fails to link until it is re-paired.
# mv is a rename inside one directory, so it keeps the 0600 and the owner, and
# needs no read of the file. scripts/test-get-aperire.sh holds this list equal
# to the backup set's dashboard/config rows.
CARRY_CONFIG=(rules.local.yaml channels.yaml fleet.yaml fleet-trust.yaml fleet-trust.pub.yaml fleet-link.json fleet-links.json authn.yaml digest.yaml metric-alerts.yaml)
# bin/ too: the advisord unit names the install path, and an update that
# left the binary in the previous tree left the unit exec'ing nothing,
# 203/EXEC in a loop, on every host with the Advisor (#350).
CARRY_ADVISOR=(state evidence knowledge-fleet knowledge-bundles bin)
carry_back() { # $1 = the tree that was in place
  local from="$1" c had_advisord=0
  [[ -f "$from/advisor/bin/aperire-advisord" ]] && had_advisord=1
  if [[ -d "$from/data" ]]; then
    # As root (ADR 0024). data/ is the dashboard's account's, and moving a
    # directory to a new parent needs write on the directory itself (its
    # '..'), which the operator does not have once the two accounts differ.
    # Both parents are the operator's, so the dashboard's account cannot swap
    # either name, and a rename keeps the owner. -T: never move it INTO
    # something already standing at the name.
    runuser -u "$OPERATOR" -- rm -rf "$INSTALL_DIR/data" 2>/dev/null || rm -rf "$INSTALL_DIR/data" 2>/dev/null || true
    if mv -T "$from/data" "$INSTALL_DIR/data"; then
      say "  data/    the database, the passkeys and the logs"
    else
      say "  data/ could not be moved across. It is still at $from/data"
    fi
  fi
  for c in "${CARRY_CONFIG[@]}"; do
    [[ -f "$from/dashboard/config/$c" ]] || continue
    if runuser -u "$OPERATOR" -- mv -f "$from/dashboard/config/$c" "$INSTALL_DIR/dashboard/config/$c"; then
      say "  dashboard/config/$c"
    else
      say "  dashboard/config/$c could not be moved across. It is still at $from/dashboard/config/$c"
    fi
  done
  for c in "${CARRY_ADVISOR[@]}"; do
    [[ -d "$from/advisor/$c" ]] || continue
    rm -rf "$INSTALL_DIR/advisor/$c" 2>/dev/null || true
    if mv "$from/advisor/$c" "$INSTALL_DIR/advisor/$c"; then
      say "  advisor/$c/"
    else
      say "  advisor/$c/ could not be moved across. It is still at $from/advisor/$c"
    fi
  done
  # An update carries the Advisor's programs into the new tree and keeps no
  # earlier build, so these are the build of the release left, not of the one
  # that came back. They run, and the next update rebuilds them (#951).
  if [[ $had_advisord -eq 1 && -x "$INSTALL_DIR/advisor/bin/aperire-advisord" ]]; then
    say "  the Advisor's programs are the build from the release you left; the next update rebuilds them for this one."
  fi
  return 0
}

# The role, read off this host's units the way the bootstrap reads it. Never
# asked and never guessed: a set of units nothing here recognises stops the
# run rather than installing something else.
ROLE_FOUND=""
resolve_role() {
  local dash=0 relay=0
  [[ -f "$UNIT_DIR/aperire-server.service" || -f "$UNIT_DIR/aperire-read.service" ]] && dash=1
  [[ -f "$UNIT_DIR/aperire-relay.service" ]] && relay=1
  if   [[ $dash -eq 1 && $relay -eq 1 ]]; then ROLE_FOUND=co-located
  elif [[ $dash -eq 1 ]];                 then ROLE_FOUND=dashboard
  elif [[ $relay -eq 1 ]];                then ROLE_FOUND=validator
  else
    die 2 "none of this host's units is a dashboard or a relay, so this program cannot tell what to install from the tree it just put back."
  fi
  return 0
}

main() {
  [[ $EUID -eq 0 ]] || die 2 "must run as root; this writes the install tree, the systemd units and /usr/local/sbin"
  [[ $# -eq 0 ]] || die 2 "takes no arguments; the payload arrives on standard input"

  WORK_DIR="$(mktemp -d)"
  local request verb
  IFS= read -r request || die 2 "the payload was empty. One line: check, apply tag=<t> commit=<c> sha256=<s>, restart units=<a,b>, or rollback."
  # shellcheck disable=SC2086  # the request is split on purpose: verb, then its key=value words
  set -- $request
  verb="${1:-}"; shift || true
  load_conf
  # Which endpoint this host installs from, on every verb, because it is the
  # answer to half the questions a refusal raises. The page names it when the
  # endpoint is the problem; nothing else has to go and read update.conf to
  # find out what root was looking at.
  fact endpoint "$ENDPOINT"
  case "$verb" in
    check)    parse_payload check "$@";    verb_check ;;
    apply)    parse_payload apply "$@";    verb_apply ;;
    restart)  parse_payload restart "$@";  verb_restart ;;
    rollback) parse_payload rollback "$@"; verb_rollback ;;
    "")       die 2 "the payload named no verb. One of: check, apply, restart, rollback." ;;
    *)        die 2 "'$verb' is not something this program does. One of: check, apply, restart, rollback." ;;
  esac
  exit 0
}

main "$@"
