#!/usr/bin/env bash
# prepare-host.sh — put the toolchain and the built binaries in place so
# install.sh can run on a fresh Ubuntu host with nothing on it but git.
#
# install.sh runs this first (skip with --no-prepare). It is also fine to
# run alone, and to run again: every step checks before it acts, and a host
# that already has everything gets a short list of "already there" lines.
#
#   sudo APERIRE_ROLE=co-located APERIRE_WITH_ADVISOR=1 bash scripts/prepare-host.sh
#
# What it does, by role (APERIRE_ROLE=dashboard|validator|co-located|cli-only):
#   dashboard, co-located
#     - apt packages the dashboard build needs (build-essential, python3,
#       python3-yaml, git, openssl, curl, ca-certificates, sqlite3)
#     - Node 22 LTS for the operator's account, through nvm, when the account
#       has no Node 22 yet (the unit runs as that account, from that Node)
#     - `npm ci` in dashboard/, as the operator, when node_modules is missing
#       or older than package-lock.json
#   validator, co-located
#     - Go 1.23 or newer (from go.dev into /usr/local/go when apt's is too old
#       or absent), then builds relay/aperire-relay as the operator
#   any role with APERIRE_WITH_ADVISOR=1
#     - the same Go, then builds advisor/bin/aperire-advisord and
#       advisor/bin/aperire-executor as the operator
#   cli-only
#     - sqlite3 only (aperire-auth needs it); nothing else
#
# Builds run as the operator, not root, so the checkout and the Go build cache
# stay theirs. Downloads come from nodejs/nvm on GitHub and go.dev; both are
# checked against a checksum pinned in this file (Go) or pinned to a version
# (nvm). Set APERIRE_OFFLINE=1 to refuse every
# download and only report what is missing.
set -euo pipefail

# Where this program and its siblings are (PREP_SELF), and the install tree it acts
# on (REPO_DIR): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from PREP_SELF only.
PREP_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "$PREP_SELF/.." && pwd)}"
ROLE="${APERIRE_ROLE:-co-located}"
WITH_ADVISOR="${APERIRE_WITH_ADVISOR:-0}"
OFFLINE="${APERIRE_OFFLINE:-0}"
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_HOME="$(getent passwd "${RUN_USER}" | cut -d: -f6)"

# Pinned versions. Bump deliberately, with the release notes open, and
# refresh the two Go checksums from https://go.dev/dl/ when GO_VERSION moves.
NODE_MAJOR=22
NVM_VERSION=v0.40.3
GO_MIN=1.23
GO_VERSION=1.23.12
GO_SHA256_AMD64=d3847fef834e9db11bf64e3fb34db9c04db14e068eeb064f49af747010454f90
GO_SHA256_ARM64=52ce172f96e21da53b1ae9079808560d49b02ac86cecfa457217597f9bc28ab3

# The palette the install path shares, so "done", "degraded" and "refused"
# look the same wherever they are printed. Every string in it is empty unless
# the stream is a terminal, so a captured or piped run stays byte-plain.
[[ -r "${PREP_SELF}/term-style.sh" ]] \
  || { echo "error: ${PREP_SELF}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${PREP_SELF}/term-style.sh"

die()  { echo "  ${E_RED}error: $*${E_OFF}" >&2; exit 1; }
say()  { echo; echo "${S_BOLD}== $*${S_OFF}"; }
info() { echo "   $*"; }
have() { echo "   ${S_GREEN}already there: $*${S_OFF}"; }
caution() { echo "   ${S_AMBER}caution: $*${S_OFF}"; }

[[ $EUID -eq 0 ]] || die "run with sudo (it installs packages and writes under /usr/local)"
case "$ROLE" in dashboard|validator|co-located|cli-only) ;; *) die "APERIRE_ROLE must be dashboard, validator, co-located or cli-only (got '$ROLE')" ;; esac
[[ "$RUN_USER" != "root" ]] || die "run as a normal user with sudo, not as root itself: the services run as that user"

NEED_DASH=0; NEED_RELAY=0; NEED_GO=0
case "$ROLE" in
  dashboard)  NEED_DASH=1 ;;
  validator)  NEED_RELAY=1 ;;
  co-located) NEED_DASH=1; NEED_RELAY=1 ;;
esac
[[ $NEED_RELAY -eq 1 || "$WITH_ADVISOR" == "1" ]] && NEED_GO=1

as_user() { sudo -u "$RUN_USER" -H "$@"; }

# ── 1. apt packages ─────────────────────────────────────────────────
say "apt packages"
# acl (setfacl) and file are what install-advisor-account.sh needs at the
# very end of an install; missing, they abort the LAST step of a 45-second
# run (fresh-22.04 dry run, 2026-08-20).
PKGS=(git curl ca-certificates sqlite3 acl file gawk)
[[ $NEED_DASH -eq 1 ]] && PKGS+=(build-essential python3 python3-yaml openssl)
MISSING=()
for p in "${PKGS[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p")
done
if [[ ${#MISSING[@]} -eq 0 ]]; then
  have "${PKGS[*]}"
elif [[ "$OFFLINE" == "1" ]]; then
  die "offline: missing packages: ${MISSING[*]}"
else
  info "installing: ${MISSING[*]}"
  # needrestart (present on Ubuntu server) can restart services after an
  # apt run, and on some images it does so without asking. On a validator
  # host that list includes docker, which would restart the node container.
  # List-only mode: it may print, it may not act.
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${MISSING[@]}"
fi

# ── 2. Node 22 for the operator ─────────────────────────────────────
# Same resolution order install-aperire-service.sh uses, so the Node found
# here is the Node the unit will run: the user's login shell first (nvm
# sourced from a profile), then the nvm tree directly, then PATH.
find_node() {
  local n
  n="$(as_user bash -lc 'command -v node' 2>/dev/null || true)"
  [[ -z "$n" ]] && n="$(find "${RUN_HOME}/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1)"
  [[ -z "$n" ]] && n="$(command -v node || true)"
  echo "$n"
}
node_major() { [[ -x "$1" ]] && "$1" -e 'process.stdout.write(String(process.versions.node.split(".")[0]))' 2>/dev/null || echo 0; }

if [[ $NEED_DASH -eq 1 ]]; then
  say "Node ${NODE_MAJOR} for ${RUN_USER}"
  NODE_PATH="$(find_node)"
  if [[ -n "$NODE_PATH" && "$(node_major "$NODE_PATH")" -ge $NODE_MAJOR ]]; then
    have "$NODE_PATH ($("$NODE_PATH" -v))"
  elif [[ "$OFFLINE" == "1" ]]; then
    die "offline: Node ${NODE_MAJOR} not found for ${RUN_USER}"
  else
    if [[ ! -s "${RUN_HOME}/.nvm/nvm.sh" ]]; then
      info "installing nvm ${NVM_VERSION} under ${RUN_HOME}/.nvm"
      as_user bash -c "curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh | PROFILE=/dev/null bash" >/dev/null
      # nvm's installer writes the profile lines itself when PROFILE is set;
      # with /dev/null it writes nothing, so add them once, in a form the
      # unit-independent probes above will find.
      for rc in .bashrc .profile; do
        f="${RUN_HOME}/${rc}"
        if [[ -f "$f" ]] && ! grep -q 'NVM_DIR' "$f"; then
          as_user tee -a "$f" >/dev/null <<'EOF'

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
EOF
        fi
      done
    fi
    info "installing Node ${NODE_MAJOR} (nvm install ${NODE_MAJOR}; nvm alias default ${NODE_MAJOR})"
    as_user bash -c "export NVM_DIR=\"\$HOME/.nvm\"; . \"\$NVM_DIR/nvm.sh\"; nvm install ${NODE_MAJOR} >/dev/null && nvm alias default ${NODE_MAJOR} >/dev/null"
    NODE_PATH="$(find_node)"
    [[ -n "$NODE_PATH" && "$(node_major "$NODE_PATH")" -ge $NODE_MAJOR ]] || die "Node ${NODE_MAJOR} still not found for ${RUN_USER} after nvm install"
    info "installed: $NODE_PATH ($("$NODE_PATH" -v))"
  fi
  NODE_BIN="$(dirname "$NODE_PATH")"

  # ── 3. npm ci ───────────────────────────────────────────────────────
  say "dashboard dependencies (npm ci)"
  LOCK="${REPO_DIR}/dashboard/package-lock.json"
  STAMP="${REPO_DIR}/dashboard/node_modules/.package-lock.json"
  if [[ -f "$STAMP" && ! "$LOCK" -nt "$STAMP" && -f "${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs" ]]; then
    have "dashboard/node_modules is current with package-lock.json"
  elif [[ "$OFFLINE" == "1" ]]; then
    die "offline: dashboard/node_modules missing or stale"
  else
    info "running npm ci in dashboard/ as ${RUN_USER}"
    as_user env PATH="${NODE_BIN}:${PATH}" bash -c "cd '${REPO_DIR}/dashboard' && npm ci --no-audit --no-fund --loglevel=error"
    [[ -f "${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs" ]] || die "npm ci finished but dashboard/node_modules/tsx is missing"
  fi
fi

# ── 4. Go ───────────────────────────────────────────────────────────
# apt's golang-go is 1.18 on 22.04 and 1.22 on 24.04; the relay and the
# Advisor are go 1.23 modules, and a Go older than 1.21 cannot fetch a newer
# toolchain for itself. So: use whatever Go is new enough, otherwise put the
# official tarball in /usr/local/go. Nothing on PATH is edited for root;
# the builds below get the path explicitly and /etc/profile.d gets a line
# for interactive shells.
# Asked as the login, never as root (#1162, ADR 0024): the candidates include a
# path out of the login's own shell and a PATH entry, and root would otherwise
# execute a program the login chose or can replace. The builds below run as the
# login too, so this is also the account whose answer decides whether it works.
# From /: sudo keeps the caller's directory, and go refuses to run from one the
# login cannot search (a root shell in /root), which would read as "no Go".
go_ok() { # $1 = go binary; prints version if >= GO_MIN
  local v
  v="$(cd / && as_user "$1" version 2>/dev/null | sed -n 's/.*go\([0-9]*\.[0-9]*\).*/\1/p')"
  [[ -n "$v" ]] || return 1
  [[ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" == "$GO_MIN" ]] && echo "$v"
}
GO_BIN=""
if [[ $NEED_GO -eq 1 ]]; then
  say "Go ${GO_MIN}+ (relay/Advisor builds)"
  for cand in /usr/local/go/bin/go "$(command -v go || true)" "$(as_user bash -lc 'command -v go' 2>/dev/null || true)"; do
    [[ -n "$cand" ]] || continue
    if v="$(go_ok "$cand")"; then GO_BIN="$cand"; have "$cand (go $v)"; break; fi
  done
  if [[ -z "$GO_BIN" ]]; then
    if [[ "$OFFLINE" == "1" ]]; then die "offline: no Go ${GO_MIN}+ on this host"; fi
    case "$(uname -m)" in
      x86_64)        GOARCH=amd64; GO_SHA="$GO_SHA256_AMD64" ;;
      aarch64|arm64) GOARCH=arm64; GO_SHA="$GO_SHA256_ARM64" ;;
      *) die "unsupported architecture for the Go download: $(uname -m)" ;;
    esac
    TARBALL="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    info "downloading https://go.dev/dl/${TARBALL} and checking it against the pinned sha256"
    TMP="$(mktemp -d)"
    curl -fsSL -o "${TMP}/${TARBALL}" "https://go.dev/dl/${TARBALL}"
    echo "${GO_SHA}  ${TMP}/${TARBALL}" | sha256sum -c --quiet - || die "Go tarball checksum mismatch; not installing it"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${TMP}/${TARBALL}"
    rm -rf "$TMP"
    # shellcheck disable=SC2016  # $PATH must expand in the shell that sources this, not here
    printf 'export PATH=$PATH:/usr/local/go/bin\n' > /etc/profile.d/aperire-go.sh
    GO_BIN=/usr/local/go/bin/go
    info "installed: $GO_BIN ($("$GO_BIN" version | awk '{print $3}'))"
  fi
  GO_DIR="$(dirname "$GO_BIN")"
fi

# ── 5. Builds ───────────────────────────────────────────────────────
#
# The commit these builds are stamped with (#266), off the same value
# get-aperire.sh's own .release will name, passed through as
# APERIRE_BUILD_COMMIT because every sub-script here reads its inputs that
# way. "dev" for anything else: a bare `sudo bash install.sh` with no
# bootstrap wrapping it, a shape the check below must never mistake for a
# commit. The dashboard's own comparator reads that shape rule too, so the
# two sides agree on what "not stamped" looks like without sharing code.
BUILD_COMMIT="${APERIRE_BUILD_COMMIT:-dev}"
[[ "$BUILD_COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || BUILD_COMMIT="dev"

build_as_user() { # $1 = dir, rest = go build args
  local d="$1"; shift
  as_user env PATH="${GO_DIR}:${PATH}" GOFLAGS=-trimpath CGO_ENABLED=0 bash -c \
    "cd '$d' && go build -ldflags '-s -w -X main.version=${BUILD_COMMIT}' $*"
}
newest_src_newer_than() { # $1 = binary, $2 = source dir; true if any .go/go.mod newer than binary
  [[ -x "$1" ]] || return 0
  [[ -n "$(find "$2" -name '*.go' -newer "$1" -print -quit 2>/dev/null)$(find "$2" -maxdepth 1 -name 'go.*' -newer "$1" -print -quit 2>/dev/null)" ]]
}
# A binary whose OWN stamp disagrees with the commit this run is installing
# is one this run must rebuild even when its sources did not change (#266):
# an update that only touched the dashboard or only advisor/ would otherwise
# leave relay carrying last release's stamp forever, and the drift note it
# feeds would fire with no rebuild that could ever clear it. Silent, never
# forcing, on a binary this build predates -version on: its stdout is then
# empty, which is read as "cannot say" rather than as a mismatch, the same
# reading an unstamped `dev` gets on the dashboard's side of this.
#
# The binary is the login's: it built it, and it can replace it. So it is asked
# for its stamp AS the login (the account build_as_user builds with), never by
# root, and what comes back is read as data (#952, ADR 0024).
#
# A run that carries no commit to stamp with ("dev") has nothing to hold the
# binary's stamp against, and rebuilding would only replace a release's stamp
# with "dev" (#1142). That is the same reading as a binary that cannot say: not
# stale. A changed source still rebuilds it, through newest_src_newer_than.
stamp_stale() { # $1 = binary
  [[ -x "$1" ]] || return 1   # newest_src_newer_than already covers "missing"
  [[ "$BUILD_COMMIT" != "dev" ]] || return 1
  local have
  have="$(as_user "$1" -version 2>/dev/null || true)"
  [[ -n "$have" ]] || return 1
  [[ "$have" != "$BUILD_COMMIT" ]]
}

# With no commit to stamp with, "newer than their sources" is all that was
# checked, and a release tarball gives every file one fixed time, so a binary
# built later can look newer than a source that changed after it. That is
# worth one line rather than a success that reads as complete (#1142).
unchecked_caution() {
  caution "this run names no release commit, so the stamps were not checked, only file times. If a source changed since these were built, they are not rebuilt: run  curl -fsSL https://get.aperire.one | bash -s -- --update --force"
}

if [[ $NEED_RELAY -eq 1 ]]; then
  say "relay binary (relay/aperire-relay)"
  if newest_src_newer_than "${REPO_DIR}/relay/aperire-relay" "${REPO_DIR}/relay" \
     || stamp_stale "${REPO_DIR}/relay/aperire-relay"; then
    info "building as ${RUN_USER}"
    build_as_user "${REPO_DIR}/relay" -o aperire-relay .
    info "built: ${REPO_DIR}/relay/aperire-relay (commit ${BUILD_COMMIT})"
  elif [[ "$BUILD_COMMIT" == "dev" ]]; then
    have "relay/aperire-relay is newer than its sources"
    unchecked_caution
  else
    have "relay/aperire-relay is newer than its sources, stamped ${BUILD_COMMIT}"
  fi
fi

if [[ "$WITH_ADVISOR" == "1" ]]; then
  say "Advisor binaries (advisor/bin/aperire-advisord, aperire-executor, knowledge-lint)"
  as_user mkdir -p "${REPO_DIR}/advisor/bin"
  if newest_src_newer_than "${REPO_DIR}/advisor/bin/aperire-advisord" "${REPO_DIR}/advisor" \
     || newest_src_newer_than "${REPO_DIR}/advisor/bin/aperire-executor" "${REPO_DIR}/advisor" \
     || newest_src_newer_than "${REPO_DIR}/advisor/bin/knowledge-lint" "${REPO_DIR}/advisor" \
     || stamp_stale "${REPO_DIR}/advisor/bin/aperire-advisord"; then
    info "building as ${RUN_USER}"
    build_as_user "${REPO_DIR}/advisor" -o bin/aperire-advisord ./cmd/aperire-advisord
    build_as_user "${REPO_DIR}/advisor" -o bin/aperire-executor ./cmd/aperire-executor
    # The corpus linter. A fleet aggregator promotes notes and pushes the
    # knowledge bundle only after it has run, and a release install has no
    # other way to get it (#1131).
    build_as_user "${REPO_DIR}/advisor" -o bin/knowledge-lint ./cmd/knowledge-lint
    info "built: advisor/bin/aperire-advisord, advisor/bin/aperire-executor, advisor/bin/knowledge-lint (commit ${BUILD_COMMIT})"
  elif [[ "$BUILD_COMMIT" == "dev" ]]; then
    have "advisor/bin/* are newer than their sources"
    unchecked_caution
  else
    have "advisor/bin/* are newer than their sources, stamped ${BUILD_COMMIT}"
  fi
fi

say "host prepared for role '${ROLE}'$([[ "$WITH_ADVISOR" == "1" ]] && echo ' + Advisor')"
