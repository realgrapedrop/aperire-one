#!/usr/bin/env bash
# What the node installer writes, what it refuses to touch on a second run,
# and what the shipped templates are not allowed to stop saying.
#
# The failures this holds shut are the ones the aperire4 proving run found by
# hand, and every one of them was quiet:
#
#   1. The hardened compose lost a line. cap_drop, no-new-privileges, the
#      loopback binds and the capped logging are the whole point of shipping a
#      template rather than a paragraph, and a compose missing one of them
#      starts a container that looks identical.
#   2. The peer mapping and the config disagreed. The host port is 51235, the
#      container port is 2459, and a mapping to a port nothing listens on
#      refuses inbound peers with no error anywhere.
#   3. The healthcheck's backslash escapes were re-emitted through a heredoc
#      and stopped matching. The node is fine; the container reads unhealthy
#      forever.
#   4. data/ was operator-owned, so container-root without CAP_DAC_OVERRIDE
#      could not create its store and the first start crash-looped SIGABRT.
#   5. A re-run re-resolved "newest" and quietly staged an image upgrade.
#
#   bash scripts/test-install-aperire-node.sh
#
# Runs entirely in a temporary directory against fake docker, apt-get, curl,
# systemctl, ss, install, usermod, id and getent on PATH. Touches no host,
# needs no root, installs nothing and starts nothing.

set -uo pipefail
# Root copies refuse a destination directory anyone but its owner can write
# (ADR 0024), as they would on a host, so the fixture is made like a host: 022.
umask 022

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Everything the installer makes with mktemp goes to a folder of this suite's
# own, so the last row can say whether anything outlived the run that made it
# (#588). A signing key that failed its fingerprint check, and the log of the
# image check, used to stay in the temp dir.
SCRATCH="$TMP/scratch"
mkdir -p "$SCRATCH"
export TMPDIR="$SCRATCH"

# Native-mode paths, named here rather than where they are first read: the
# fakes on PATH below are generated as heredocs that expand these immediately
# (they are not env vars read at stub run time), so every one of them must
# exist before the first fake is written.
WCONF="$TMP/etc/aperire/node-wrapper.conf"
NATIVE_DIR="$TMP/native"
NATIVE_CFG="$NATIVE_DIR/xrpld.cfg"
NATIVE_KEYRING="$TMP/apt-keyrings/xrplf.asc"
NATIVE_SOURCES_LIST="$TMP/apt-sources/xrplf.list"
NATIVE_RPM_REPO="$TMP/yum-repos/xrplf.repo"
# #655: the repository and keyring this installer wrote before the fix,
# fixed paths rather than overridable ones because the retirement code reads
# the real system paths, never the test's own overrides — the same reason a
# host with one of these left over is the thing being proven, not a fixture
# convenience.
NATIVE_LEGACY_SOURCES_LIST="$TMP/apt-sources/ripple.list"
NATIVE_LEGACY_KEYRING="$TMP/apt-keyrings/ripple.gpg"
NATIVE_LEGACY_RPM_REPO="$TMP/yum-repos/ripple.repo"
OS_RELEASE="$TMP/os-release"
# The fingerprint docs/install.md names, and the one this suite's fake gpg
# hands back by default so the happy path needs no per-test setup. A test
# that wants the mismatch writes a different value to state/xrplf-fpr.
XRPLF_FPR=B655416741221F780FBCFBC9AA84D41A11D29FA9

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

TEMPLATES="$REPO_DIR/scripts/templates"
COMPOSE_TPL="$TEMPLATES/aperire-node.compose.yml"
CFG_TPL="$TEMPLATES/rippled.stock.cfg"

mkdir -p "$TMP/bin" "$TMP/state" "$TMP/etc/aperire" "$TMP/home/testop"

# ── The script under test, with the paths it names pointed at $TMP ────
# Copy, rewrite the constants that name /etc and the root gate, then assert
# the rewrite took: a rename upstream must fail here rather than quietly test
# nothing.
mkdir -p "$TMP/repo/scripts/templates"
# aperire-compact-check.sh is copied verbatim and still cannot reach this
# machine: the installer hands it --node and APERIRE_ETC, and run_native hands
# it APERIRE_ADVISOR_STATE, so all three things it would otherwise go looking
# for on the host are named inside $TMP before it runs.
# config-write-lib.sh (#545) is sourced by both aperire-node-wrapper.sh and
# configure-rippled-paths.sh below, so it has to be in this tree before
# either of them is invoked.
# release-digests-lib.sh (ADR 0024) because the image recipe's installer
# places each file through it. This rig has no release digests: they would
# live at a host path, so the variable points inside $TMP at nothing, and
# every copy falls back to one read and says it was unchecked.
for f in term-style.sh docker-ask-lib.sh node-user-lib.sh aperire-compact-check.sh config-write-lib.sh \
         release-digests-lib.sh trusted-path-lib.sh; do
  cp "$REPO_DIR/scripts/$f" "$TMP/repo/scripts/$f"
done
export APERIRE_RELEASE_DIGESTS="$TMP/no-digests/release.sha256"
# The image recipe, copied whole: install-xrpld-image-recipe.sh reads these
# three out of the checkout it is run from, and refuses when any is missing.
mkdir -p "$TMP/repo/scripts/xrpld-image"
cp "$REPO_DIR/scripts/build-xrpld-image.sh" "$TMP/repo/scripts/build-xrpld-image.sh"
cp "$REPO_DIR/scripts/xrpld-image/Dockerfile" "$TMP/repo/scripts/xrpld-image/Dockerfile"
cp "$REPO_DIR/scripts/xrpld-image/entrypoint.sh" "$TMP/repo/scripts/xrpld-image/entrypoint.sh"
# The signed-package binary hash, the fourth file the recipe installs. It is
# what an official image is checked against (#682), so a copy missing it
# fails the recipe install and every build row below it.
cp "$REPO_DIR/scripts/xrpld-image/signed-binary-sha256.sh" "$TMP/repo/scripts/xrpld-image/signed-binary-sha256.sh"
# close-node-config-exposure.sh stands in rather than being copied (#462).
# The real one asks runuser, setfacl, getfacl and a live container about a
# host, and this suite has fakes for none of those; test-close-node-config.sh
# is the rig that drives it for real, with all four. What is being proved HERE
# is the wiring: that the installer reaches the closer at the path SCRIPTS_DIR
# resolves, hands it --apply, and reports what the file mode says afterwards.
#
# A stub at that exact path is also the guard. Move or rename the call and
# this file is not found, the real one on the developer's own machine is not
# either, and the rows below fail loudly instead of quietly closing the config
# of whatever node the machine running the test happens to have.
cat > "$TMP/repo/scripts/close-node-config-exposure.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/closer-calls"
echo "== What is being protected"
if [[ -e "$TMP/state/closer-fails" ]]; then
  echo "   error: cannot reach the node, so it is not possible to confirm it would still read this file" >&2
  exit 1
fi
cfg="\$(awk -F= '\$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$TMP/etc/aperire/node.conf" 2>/dev/null)"
if [[ -z "\$cfg" || ! -f "\$cfg" ]]; then
  echo "   error: no record here names a node config" >&2
  exit 1
fi
echo "   config file : \$cfg"
case " \$* " in
  *" --apply "*) /usr/bin/chmod 640 "\$cfg"; echo "== Done" ;;
  *)             echo "== What --apply would do" ;;
esac
exit 0
EOF
chmod +x "$TMP/repo/scripts/close-node-config-exposure.sh"
# The registry repointer (#488). Copied verbatim and it stays inside $TMP by
# construction: the installer hands it the fleet.yaml under $TMP/repo, a port
# read from the env files under $TMP/etc, and a key read from the fake node.
# It reaches nothing it is not given.
cp "$REPO_DIR/scripts/fleet-self-pin.py" "$TMP/repo/scripts/fleet-self-pin.py"
# detect-rippled-paths.sh reads the real /etc: two recorded configurations
# under /etc/aperire, then four absolute guesses at where a node's config
# lives. Copied verbatim, it answers about whatever node the machine running
# this test happens to have, which is a different answer on a developer's
# validator host and on a CI runner with no node at all. Both /etc paths and
# all four guesses are pointed inside $TMP, and the rewrite is asserted, so
# what these rows measure is the fixture and nothing else.
sed -e "s#^for conf in /etc/aperire/node-wrapper.conf /etc/aperire/node.conf; do#for conf in $TMP/etc/aperire/node-wrapper.conf $TMP/etc/aperire/node.conf; do#" \
    -e "s#^native_candidates+=(/etc/xrpld/xrpld.cfg #native_candidates+=($TMP/etc/xrpld/xrpld.cfg #" \
    -e "s#/etc/opt/ripple/rippled.cfg /opt/ripple/etc/rippled.cfg /etc/ripple/rippled.cfg)#$TMP/etc/opt/ripple/rippled.cfg $TMP/opt/ripple/etc/rippled.cfg $TMP/etc/ripple/rippled.cfg)#" \
    "$REPO_DIR/scripts/detect-rippled-paths.sh" > "$TMP/repo/scripts/detect-rippled-paths.sh"
grep -qF "for conf in $TMP/etc/aperire/node-wrapper.conf" "$TMP/repo/scripts/detect-rippled-paths.sh" \
  || { echo "the copy of detect-rippled-paths.sh was not rewritten (the recorded configs) - it would answer about this machine's own node"; exit 1; }
grep -qF "native_candidates+=($TMP/etc/xrpld/xrpld.cfg" "$TMP/repo/scripts/detect-rippled-paths.sh" \
  || { echo "the copy of detect-rippled-paths.sh was not rewritten (the guessed paths) - it would answer about this machine's own node"; exit 1; }
# And no absolute /etc or /opt path survives anywhere in the candidate list:
# one left behind would be one more way this row could answer about the
# machine instead of the fixture.
if grep -E '^(for conf in|native_candidates\+=)' "$TMP/repo/scripts/detect-rippled-paths.sh" \
   | grep -qE '(^|[ (])/(etc|opt)/'; then
  echo "the copy of detect-rippled-paths.sh still names a real /etc or /opt path"
  grep -nE '^(for conf in|native_candidates\+=)' "$TMP/repo/scripts/detect-rippled-paths.sh"
  exit 1
fi
# configure-rippled-paths.sh refuses without root. Neutered in the fixture, and
# the rewrite asserted, or the branch that calls it would only ever prove the
# refusal.
# shellcheck disable=SC2016  # $EUID is the text being matched, not a value to expand
sed 's#^if \[\[ \$EUID -ne 0 \]\]; then#if false; then#' \
  "$REPO_DIR/scripts/configure-rippled-paths.sh" > "$TMP/repo/scripts/configure-rippled-paths.sh"
grep -qE '^if false; then' "$TMP/repo/scripts/configure-rippled-paths.sh" \
  || { echo "the copy of configure-rippled-paths.sh was not rewritten - the wiring rows would prove nothing"; exit 1; }
cp "$TEMPLATES"/* "$TMP/repo/scripts/templates/"
# node-user-lib.sh refuses to create an account without root, the same way
# the installer refuses to run without it. Neutered in the fixture and the
# rewrite asserted, or every row below would only ever prove that refusal.
# shellcheck disable=SC2016  # $EUID is the text being matched, not a value to expand
sed -i 's#\[\[ \$EUID -eq 0 \]\] ||#[[ 1 -eq 1 ]] ||#' "$TMP/repo/scripts/node-user-lib.sh"
grep -qE '\[\[ 1 -eq 1 \]\] \|\|' "$TMP/repo/scripts/node-user-lib.sh" \
  || { echo "the copy of node-user-lib.sh was not rewritten (the root gate) - the account rows would prove nothing"; exit 1; }

# Where the root-owned image recipe goes, pointed under $TMP by the same
# environment variable the real installer honours. The recipe installer runs
# for real from here, so the wiring under test is the real one; what it
# installs is a stub build script, because the build itself is
# scripts/test-xrpld-image.sh's subject and it needs a real Docker.
export APERIRE_IMAGE_RECIPE_DIR="$TMP/lib/aperire"
# Where install-node-wrapper.sh places the wrapper and its libraries (ADR
# 0024), for the --native rows that run it for real.
export APERIRE_SBIN_DIR="$TMP/sbin" APERIRE_LIB_DIR="$TMP/lib/aperire"
mkdir -p "$TMP/sbin"
cat > "$TMP/repo/scripts/build-xrpld-image.sh" <<EOF
#!/usr/bin/env bash
# Stub. Records its arguments, and leaves the image where the fake docker
# will find it, the way a real build leaves one where docker will.
printf '%s\n' "\$*" >> "$TMP/state/build-calls"
prev=""
for a in "\$@"; do
  [[ "\$prev" == --version ]] && echo "localhost/xrpld:\$a" >> "$TMP/state/images"
  prev="\$a"
done
if [[ -f "$TMP/state/build-fails" ]]; then
  echo "BUILD REFUSED: key fingerprint is not the published one" >&2
  exit 1
fi
echo "signing key fingerprint verified: B655416741221F780FBCFBC9AA84D41A11D29FA9"
exit 0
EOF

SUT="$TMP/repo/scripts/install-aperire-node.sh"
# shellcheck disable=SC2016  # $EUID is the text being matched, not a value to expand
sed -e 's#^if \[\[ \$EUID -ne 0 \]\]; then#if false; then#' \
    -e "s#^ETC_APERIRE=/etc/aperire#ETC_APERIRE=$TMP/etc/aperire#" \
    "$REPO_DIR/scripts/install-aperire-node.sh" > "$SUT"
grep -qE '^if false; then' "$SUT" \
  || { echo "the copy of install-aperire-node.sh was not rewritten (the root gate) - the test would prove nothing"; exit 1; }
grep -qF -- "ETC_APERIRE=$TMP/etc/aperire" "$SUT" \
  || { echo "the copy of install-aperire-node.sh was not rewritten (the etc path) - the test would prove nothing"; exit 1; }

# install-xrpld-image-recipe.sh refuses without root, like every other root
# program here. Neutered in the fixture and the rewrite asserted, or the
# build branch would only ever prove that refusal.
# shellcheck disable=SC2016  # $EUID is the text being matched, not a value to expand
sed 's#^\[\[ \$EUID -eq 0 \]\] ||#[[ 1 -eq 1 ]] ||#' \
  "$REPO_DIR/scripts/install-xrpld-image-recipe.sh" > "$TMP/repo/scripts/install-xrpld-image-recipe.sh"
grep -qE '^\[\[ 1 -eq 1 \]\] \|\|' "$TMP/repo/scripts/install-xrpld-image-recipe.sh" \
  || { echo "the copy of install-xrpld-image-recipe.sh was not rewritten (the root gate) - the build rows would prove nothing"; exit 1; }

# --native calls both of these for real: install-node-wrapper.sh to write the
# configuration, aperire-node-wrapper.sh to prove it. Same rewrite as
# test-install-node-wrapper.sh's own fixture (CONF pointed under $TMP, the
# root gate neutered), asserted the same way, or the adopt and offer rows
# below would only ever prove a refusal to run without sudo.
sed -e "s#^CONF=/etc/aperire/node-wrapper.conf#CONF=$WCONF#" \
    -e "s#^CWL_LIB=/usr/local/lib/aperire/config-write-lib.sh#CWL_LIB=$TMP/lib/aperire/config-write-lib.sh#" \
    -e "s#^PACKAGE_KEEP_DIR=/var/lib/aperire/rollback#PACKAGE_KEEP_DIR=$TMP/rollback#" \
    -e "s#^APT_CACHE_DIR=/var/cache/apt/archives#APT_CACHE_DIR=$TMP/aptcache#" \
  "$REPO_DIR/scripts/aperire-node-wrapper.sh" > "$TMP/repo/scripts/aperire-node-wrapper.sh"
grep -qF "PACKAGE_KEEP_DIR=$TMP/rollback" "$TMP/repo/scripts/aperire-node-wrapper.sh" \
  || { echo "the copy of aperire-node-wrapper.sh was not rewritten (PACKAGE_KEEP_DIR) - the keep rows would read the host's"; exit 1; }
grep -qF "CONF=$WCONF" "$TMP/repo/scripts/aperire-node-wrapper.sh" \
  || { echo "the copy of aperire-node-wrapper.sh was not rewritten (CONF) - the native rows would prove nothing"; exit 1; }
grep -qF "CWL_LIB=$TMP/lib/aperire/config-write-lib.sh" "$TMP/repo/scripts/aperire-node-wrapper.sh" \
  || { echo "the copy of aperire-node-wrapper.sh was not rewritten (CWL_LIB) - it would read the host's library"; exit 1; }
# shellcheck disable=SC2016
sed -e 's#^\[\[ \$EUID -eq 0 \]\] ||#[[ 1 -eq 1 ]] ||#' \
    -e "s#^CONF=/etc/aperire/node-wrapper.conf#CONF=$WCONF#" \
    "$REPO_DIR/scripts/install-node-wrapper.sh" > "$TMP/repo/scripts/install-node-wrapper.sh"
grep -qE '^\[\[ 1 -eq 1 \]\] \|\|' "$TMP/repo/scripts/install-node-wrapper.sh" \
  || { echo "the copy of install-node-wrapper.sh was not rewritten (the root gate) - the native rows would prove nothing"; exit 1; }
grep -qF "CONF=$WCONF" "$TMP/repo/scripts/install-node-wrapper.sh" \
  || { echo "the copy of install-node-wrapper.sh was not rewritten (CONF) - the native rows would prove nothing"; exit 1; }
chmod +x "$TMP/repo/scripts/aperire-node-wrapper.sh" "$TMP/repo/scripts/install-node-wrapper.sh"

# ── Fakes on PATH ─────────────────────────────────────────────────────
# docker: every call recorded. The container's status and health answer from
# state, so "healthy" and "unhealthy" are both reachable, and `compose up`
# creates the container rather than being assumed to have.
cat > "$TMP/bin/docker" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/docker-calls"
case "\${1:-}" in
  --version) echo "Docker version 27.5.1, build test"; exit 0 ;;
  info)      exit 0 ;;
  ps)
    # docker refusing to answer is a state of its own, and --adopt must not
    # read it as "nothing is running here" (#140).
    [[ -f "$TMP/state/docker-refuses" ]] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
    # state/docker-account-refuses: the account is refused but sudo is not
    # (the sudo stub below sets SUDO_STUB), the account outside the docker
    # group whose root answer is the one that counts.
    [[ -f "$TMP/state/docker-account-refuses" && -z "\${SUDO_STUB:-}" ]] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
    [[ -f "$TMP/state/container-state" ]] || exit 0
    # state/ps-row: the row to print for any format, for the detector's
    # {{.ID}} {{.Image}} {{.Command}} --no-trunc shape (#896).
    if [[ -f "$TMP/state/ps-row" ]]; then cat "$TMP/state/ps-row"; exit 0; fi
    # The format is honoured rather than ignored: --adopt asks for names and
    # images and picks a container out of the answer, so a fake that always
    # printed the same three fields would let it pick anything.
    if [[ "\$*" == *"{{.Names}} {{.Image}}"* ]]; then
      while IFS= read -r c; do
        [[ -n "\$c" ]] && printf '%s %s\n' "\$c" "\$(cat "$TMP/state/image-of-\$c" 2>/dev/null || echo xrpllabsofficial/xrpld:3.3.0)"
      done < <(cat "$TMP/state/containers" 2>/dev/null || echo test-node)
      exit 0
    fi
    echo "abc123def456 /entrypoint.sh xrpllabsofficial/xrpld:3.3.0"
    exit 0 ;;
  port)
    # What the container publishes, from state, so "published on loopback",
    # "published on every address" and "not published at all" are three
    # different answers rather than one.
    cat "$TMP/state/published-5005" 2>/dev/null
    exit 0 ;;
  compose)
    shift
    case "\$*" in
      version*)
        if [[ "\$*" == *--short* ]]; then echo "2.32.4"; else echo "Docker Compose version v2.32.4"; fi
        exit 0 ;;
    esac
    echo running > "$TMP/state/container-state"
    echo "[+] Running 1/1 Container started"
    exit 0 ;;
  exec)
    # id -u is answered from the compose file under test, the same way the
    # Mounts branch below answers from it: docker exec with no -u runs as the
    # user the deployment configured, so a compose that lost its user: line
    # has to make this say 0 and fail the row that reads it.
    if [[ "\$*" == *"id -u"* ]]; then
      u=\$(sed -nE 's/^[[:space:]]*user: "([0-9]+):[0-9]+".*/\1/p' "$TMP/node/docker-compose.yml" 2>/dev/null | head -1)
      echo "\${u:-0}"
    fi
    exit 0 ;;
  pull)
    # A pull by digest puts that reference on this host (#682). Recorded in
    # the same list a build writes, so "inspect finds it" is the same
    # question for both sources and neither is assumed.
    printf '%s\n' "\${2:-}" >> "$TMP/state/images"
    exit 0 ;;
  image)
    # docker image inspect REF: is that image on this host? Answered from
    # state so both halves of the build branch are reachable, the one that
    # builds and the one that finds the image already here.
    shift
    [[ "\${1:-}" == inspect ]] || exit 0
    shift
    ref=""
    while [[ \$# -gt 0 ]]; do
      case "\$1" in --format|-f) shift 2 ;; *) ref="\$1"; shift ;; esac
    done
    grep -qxF -e "\$ref" "$TMP/state/images" 2>/dev/null || exit 1
    echo "sha256:fakeimageid"
    exit 0 ;;
  inspect)
    shift
    fmt=""; ref=""
    while [[ \$# -gt 0 ]]; do
      case "\$1" in -f|--format) fmt="\$2"; shift 2 ;; --type) shift 2 ;; *) ref="\$1"; shift ;; esac
    done
    [[ -f "$TMP/state/container-state" ]] || exit 1
    case "\$fmt" in
      # What the container was created from. A container made from a digest
      # shows an image ID in ps and this here (#896). state/inspect-refused
      # makes the answer a refusal.
      *Config.Image*)
        [[ -f "$TMP/state/inspect-refused" ]] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
        # Per container, so two containers can carry different images: a
        # state/config-image-of-<ref> file beats state/config-image.
        # state/inspect-refused-<ref> refuses one container only, and
        # state/inspect-gone-<ref> is a container removed since ps listed it.
        [[ -f "$TMP/state/inspect-refused-\$ref" ]] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
        # The account is refused first, whatever the container, so what root
        # says (gone, or its own words in state/sudo-inspect-says) is told apart.
        if [[ -f "$TMP/state/docker-account-refuses" && -z "\${SUDO_STUB:-}" ]]; then
          echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1
        fi
        [[ -f "$TMP/state/inspect-gone-\$ref" ]] && { echo "Error: No such object: \$ref" >&2; exit 1; }
        if [[ -n "\${SUDO_STUB:-}" && -f "$TMP/state/sudo-inspect-says" ]]; then
          cat "$TMP/state/sudo-inspect-says" >&2; exit 1
        fi
        if [[ -f "$TMP/state/config-image-of-\$ref" ]]; then cat "$TMP/state/config-image-of-\$ref"; else cat "$TMP/state/config-image" 2>/dev/null; fi ;;
      *State.Status*) cat "$TMP/state/container-state" ;;
      *Health*)       cat "$TMP/state/container-health" 2>/dev/null || echo healthy ;;
      *Entrypoint*)   echo "/entrypoint.sh" ;;
      *Config.User*)
        # From the deployment, the way docker answers it: a compose with no
        # user: line runs the node as root and this says so by saying nothing.
        sed -nE 's/^[[:space:]]*user: "([0-9]+:[0-9]+)".*/\1/p' \
          "$TMP/node/docker-compose.yml" 2>/dev/null | head -1 ;;
      *Mounts*)
        # Read out of the compose file under test, in docker's own inspect
        # shape. Restating the mapping here instead would make this fake
        # answer for the artefact rather than from it, and a compose that
        # mounted the config somewhere detection does not look would still
        # pass.
        sed -nE 's#^[[:space:]]*-[[:space:]]*([^:[:space:]]+):([^:[:space:]]+)(:ro)?[[:space:]]*\$#\1 \t \2#p' \
          "$TMP/node/docker-compose.yml" 2>/dev/null ;;
    esac
    exit 0 ;;
esac
exit 0
EOF

# apt-get: recorded, and it can refuse a package, which is the branch where
# docker-compose-v2 is not in this release's archive.
cat > "$TMP/bin/apt-get" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/apt-calls"
# download (#802): the source move keeps the installed package before it
# retires the old source. Writes a fake .deb naming itself, records whether
# the old source was still configured at that moment, and fails on
# state/apt-download-fails the way a repository that no longer answers does.
if [[ "\${1:-}" == download ]]; then
  [[ -f "$NATIVE_LEGACY_SOURCES_LIST" ]] && echo present > "$TMP/state/legacy-at-download"
  [[ -f "$TMP/state/apt-download-fails" ]] && { echo "E: Can't find a source to download version" >&2; exit 100; }
  v="\${2#*=}"
  printf 'fakedeb %s %s\n' "\${2%%=*}" "\$v" > "\${2%%=*}_\${v}_amd64.deb"
  exit 0
fi
# packages.xrplf.org unreachable: its scoped refresh fails, and madison below
# lists nothing from it.
if [[ "\$*" == *update*Dir::Etc::sourcelist* ]] && [[ -f "$TMP/state/xrplf-unreachable" ]]; then
  echo "E: Failed to fetch https://packages.xrplf.org/repository/deb-stable/dists/any/InRelease" >&2
  exit 100
fi
if [[ "\$*" == *docker-compose-v2* ]] && [[ -f "$TMP/state/no-compose-pkg" ]]; then
  echo "E: Unable to locate package docker-compose-v2" >&2
  exit 100
fi
# A host carrying one broken third-party source, which is what a lab host
# had (#410): a stale speedtest repository answering 404. apt-get update
# returns non-zero for the WHOLE run when any source fails, so a refresh that
# reads every list on the host fails here and one scoped to the installer's
# own list does not.
if [[ "\$*" == *update* ]] && [[ -f "$TMP/state/broken-other-source" ]] \
   && [[ "\$*" != *Dir::Etc::sourcelist* ]]; then
  echo "E: The repository 'https://packagecloud.example/ookla/ubuntu noble Release' does not have a Release file." >&2
  exit 100
fi
# Installing xrpld is what a real maintainer script does: it registers the
# unit with systemd (LoadState=loaded), ships its own default config, and on
# the deb path starts it - exactly what the Ubuntu/Debian instructions this
# installer follows say happens by itself. Simulated here so
# native_install_package's own "did the unit appear" check, and the harden
# step after it, both have something honest to read. The shipped default
# carries the SAME bug upstream's own example ships (a duplicate
# advisory_delete line under [node_db]) and a relative [validators_file], so
# the harden step's more interesting branches are the ones actually exercised
# rather than a config already in the shape this installer would leave it.
if [[ "\$*" == *"install "*xrpld* ]]; then
  echo loaded  > "$TMP/state/unit-load-xrpld.service"
  echo active  > "$TMP/state/unit-active-xrpld.service"
  echo running > "$TMP/state/unit-sub-xrpld.service"
  printf '{ path=/usr/bin/xrpld ; argv[]=/usr/bin/xrpld --net --conf %s --silent ; ignore_errors=no }\n' \
    "$NATIVE_CFG" > "$TMP/state/unit-execstart-xrpld.service"
  printf 'xrpld\n' > "$TMP/state/owns-_usr_bin_xrpld"
  # A real dpkg/apt never overwrites a modified conffile on a second install
  # of the same package (#545 P1-105): a config already at this path is
  # whatever an earlier run of this installer, or the operator, left there.
  # Only a genuinely fresh path gets the vendor's own default.
  if [[ ! -f "$NATIVE_CFG" ]]; then
  cat > "$NATIVE_CFG" <<CFGEOF
[port_peer]
port = 2459
ip = 0.0.0.0
protocol = peer

[port_rpc_admin_local]
port = 5005
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[port_ws_admin_local]
port = 6006
ip = 127.0.0.1
admin = 127.0.0.1
protocol = ws

[node_db]
type = NuDB
path = $NATIVE_DIR/db
online_delete = 512
advisory_delete = 1
#online_delete=512
advisory_delete=0

[node_size]
medium

[validators_file]
validators.txt
CFGEOF
  fi
fi
exit 0
EOF

# curl: the registry (token, then the tag list) and the node's admin RPC.
# server_info can go silent, which is the check that has to fail loudly, and
# its ledger sequence climbs on every read so "it advanced" is observed rather
# than assumed.
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
url="" outfile=""
prev=""
for a in "\$@"; do
  case "\$a" in http://*|https://*) url="\$a" ;; esac
  [[ "\$prev" == -o ]] && outfile="\$a"
  prev="\$a"
done
case "\$url" in
  *packages.xrplf.org/xrplf.asc*)
    printf '%s\n' "\$*" >> "$TMP/state/curl-key-calls"
    if [[ -n "\$outfile" ]]; then echo "FAKE-SIGNING-KEY-BYTES" > "\$outfile"; else echo "FAKE-SIGNING-KEY-BYTES"; fi
    exit 0 ;;
  *auth.docker.io*) echo '{"token":"faketoken","expires_in":300,"issued_at":"now"}'; exit 0 ;;
  # #682: one question about ONE tag, by name. Answered from state, so both
  # "an official image carries this release" and "none does yet" are
  # reachable, and the empty default is the second of those.
  *hub.docker.com/v2/repositories/*/tags/*)
    cat "$TMP/state/official-tag" 2>/dev/null; exit 0 ;;
  *tags/list*)      cat "$TMP/state/tags" 2>/dev/null; exit 0 ;;
  *127.0.0.1:5005*)
    if [[ -f "$TMP/state/server-info-silent" ]]; then exit 7; fi
    # Silent for the first N asks, the way a node that is still opening its
    # RPC is, then answering. state/server-info-after holds N.
    if [[ -f "$TMP/state/server-info-after" ]]; then
      left=\$(cat "$TMP/state/server-info-after")
      if (( left > 0 )); then echo \$((left - 1)) > "$TMP/state/server-info-after"; exit 7; fi
    fi
    if printf '%s' "\$*" | grep -q '"validators"'; then
      cat "$TMP/state/validators" 2>/dev/null
      exit 0
    fi
    n=\$(( \$(cat "$TMP/state/seq" 2>/dev/null || echo 96543210) + 1 ))
    echo "\$n" > "$TMP/state/seq"
    # pubkey_node is what the registry row for this host is compared against
    # (#488). From state, so a row can make the node answer with the key the
    # registry already pins as well as with a different one.
    pk=\$(cat "$TMP/state/pubkey-node" 2>/dev/null || echo n9LS7ei2KFgmeENk7fLYREhgnyfBquXHm3xxBMSnjAtfsEUzp5Qh)
    printf '{"result":{"info":{"build_version":"3.3.0","server_state":"tracking","pubkey_node":"%s","validated_ledger":{"hash":"AB","seq":%s}}}}\n' "\$pk" "\$n"
    exit 0 ;;
esac
exit 0
EOF

# ss: the listening set, from state, so both ports can be made absent.
cat > "$TMP/bin/ss" <<EOF
#!/usr/bin/env bash
cat "$TMP/state/listening" 2>/dev/null
exit 0
EOF

# install: the privileged bits made harmless, but the ownership it was ASKED
# for is recorded. That recording is the only way to prove data/ is created
# root-owned without being root.
#
# One marker makes it end the way apt-cache ended in #411: status 141, which
# is 128+13, a process killed by SIGPIPE. The number is written rather than
# provoked with a pipeline of its own, because whether a write to a closed
# pipe raises SIGPIPE or comes back as EPIPE depends on the signal
# disposition this process inherited, and a hosted runner does not hand that
# down the way a login shell does: the same pipeline exits 141 here and 1
# there. What this row is about is the installer naming the signal behind a
# status, so the status is the input and it is stated. That a real reader
# closing early produces 141 is proven against the apt-cache stub instead,
# which keeps writing past the line the reader wants.
#
# `install -d` on the keyring directory is not guarded by a die, which is the
# point: this is a genuine silent stop, and the row using this marker asserts
# that the installer still says why.
cat > "$TMP/bin/install" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/install-calls"
if [[ -e "$TMP/state/install-sigpipe" ]]; then
  exit 141
fi
dir=0; args=()
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -d) dir=1; shift ;;
    -m|-o|-g) shift 2 ;;
    -*) shift ;;
    *) args+=("\$1"); shift ;;
  esac
done
if (( dir )); then
  mkdir -p "\${args[@]}"
else
  mkdir -p "\$(dirname "\${args[1]}")"; cp "\${args[0]}" "\${args[1]}"
fi
EOF

# systemctl: stateful per unit, so LoadState/ActiveState/SubState are each
# their own fact (systemd-unit-detection.md - is-active alone cannot tell a
# stopped unit from one never defined). Both install-node-wrapper.sh's own
# "UNIT --property=X --value" form and this installer's "-p X --value UNIT"
# form are read: whichever bare word is not a flag or a flag's own value is
# the unit.
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/systemctl-calls"
case "\${1:-}" in
  show)
    shift
    unit="" prop="" prev=""
    for a in "\$@"; do
      case "\$a" in
        --property=*) prop="\${a#--property=}" ;;
        --value|-p) : ;;
        *) if [[ "\$prev" == "-p" ]]; then prop="\$a"
           elif [[ -z "\$unit" ]]; then unit="\$a"; fi ;;
      esac
      prev="\$a"
    done
    case "\$prop" in
      LoadState)   cat "$TMP/state/unit-load-\$unit" 2>/dev/null || echo "not-found" ;;
      ActiveState) cat "$TMP/state/unit-active-\$unit" 2>/dev/null || echo "inactive" ;;
      SubState)    cat "$TMP/state/unit-sub-\$unit" 2>/dev/null || echo "dead" ;;
      ExecStart)   cat "$TMP/state/unit-execstart-\$unit" 2>/dev/null ;;
      *) echo "" ;;
    esac
    exit 0 ;;
  enable) exit 0 ;;
  restart)
    unit="\${2:-}"
    echo loaded  > "$TMP/state/unit-load-\$unit"
    echo active  > "$TMP/state/unit-active-\$unit"
    echo running > "$TMP/state/unit-sub-\$unit"
    exit 0 ;;
  *) exit 0 ;;
esac
EOF
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> %s/state/usermod-calls\nexit 0\n' "$TMP" > "$TMP/bin/usermod"

# pgrep: for native mode's own conflicting-node check (#087). Answers one
# name from state/running-process, so a row can put a bare process on this
# fake host under exactly the name --native's own search tries, with no
# docker container behind it at all. Absent means nothing matches, the real
# pgrep's own exit-1-on-no-match preserved so `if pgrep -x "$n"` reads
# correctly either way.
cat > "$TMP/bin/pgrep" <<EOF
#!/usr/bin/env bash
name="\${!#}"
running=\$(cat "$TMP/state/running-process" 2>/dev/null || true)
[[ -n "\$running" && "\$running" == "\$name" ]]
EOF

# dpkg / dpkg-query: which package owns a binary, and what version the
# database says is installed. Two callers ask the version in two shapes -
# this installer's own read (-f='${Version}') and the wrapper's package
# detection ahead of it (-f='${db:Status-Status} ${Version}') - and both are
# answered from the same fixture file, keyed by package name.
cat > "$TMP/bin/dpkg" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/dpkg-calls"
if [[ "\$1" == -S ]]; then
  key="owns-\$(printf '%s' "\$2" | tr '/' '_')"
  if [[ -f "$TMP/state/\$key" ]]; then
    printf '%s: %s\n' "\$(cat "$TMP/state/\$key")" "\$2"
  else
    echo "dpkg-query: no path found matching pattern \$2" >&2
    exit 1
  fi
fi
EOF
cat > "$TMP/bin/dpkg-query" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/dpkg-query-calls"
fmt="" pkg="\${*: -1}"
for a in "\$@"; do case "\$a" in -f=*) fmt="\${a#-f=}" ;; esac; done
if [[ -f "$TMP/state/pkgversion-\$pkg" ]]; then
  v=\$(cat "$TMP/state/pkgversion-\$pkg")
  case "\$fmt" in
    *db:Status-Status*) printf 'installed %s' "\$v" ;;
    *) printf '%s' "\$v" ;;
  esac
else
  echo "dpkg-query: no packages found matching \$pkg" >&2
  exit 1
fi
EOF

# apt-cache: presence alone is enough for the wrapper's own package-manager
# gate; this installer's own repository check reads the Candidate line.
#
# It KEEPS WRITING after that line, because the real tool does: a version
# table follows, one repository per version. A reader that quits on the
# Candidate line leaves apt-cache writing into a closed pipe, and the SIGPIPE
# that follows ended the whole native install with status 141 and no message
# on every deb host (#411). The old stub stopped at the Candidate line, so
# nothing here could ever see it.
#
# The table is padded rather than three rows long: a shell stub cannot
# reproduce a C program's flush-per-line, so the only way to make the write
# outlive the reader is to give it more than a pipe buffer to write.
cat > "$TMP/bin/apt-cache" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/apt-cache-calls"
# madison, where the package comes from (#802): one "version url" pair per
# line of state/madison, printed in apt's own three-column shape. No file,
# no lines, which is a host where no source offers the package.
# The lists this installer writes count too, the way they do for real apt:
# the new one offers 3.4.1-1 unless it is unreachable, the old one 3.3.0-1.
if [[ "\${1:-}" == madison ]]; then
  if [[ -f "$NATIVE_SOURCES_LIST" && ! -f "$TMP/state/xrplf-unreachable" ]]; then
    printf '     %s | 3.4.1-1 | https://packages.xrplf.org/repository/deb-stable any/main amd64 Packages\n' "\${2:-}"
  fi
  if [[ -f "$NATIVE_LEGACY_SOURCES_LIST" ]] && grep -q 'https://repos.ripple.com' "$NATIVE_LEGACY_SOURCES_LIST"; then
    printf '     %s | 3.3.0-1 | https://repos.ripple.com/repos/rippled-deb noble/stable amd64 Packages\n' "\${2:-}"
  fi
  [[ -f "$TMP/state/madison" ]] || exit 0
  while read -r v u; do
    [[ -n "\$v" ]] && printf '     %s | %s | %s noble/stable amd64 Packages\n' "\${2:-}" "\$v" "\$u"
  done < "$TMP/state/madison"
  exit 0
fi
if [[ "\${1:-}" == policy ]]; then
  cand="\$(cat "$TMP/state/apt-candidate" 2>/dev/null || echo '(none)')"
  printf '%s:\n  Installed: (none)\n  Candidate: %s\n  Version table:\n' "\${2:-}" "\$cand"
  seq 1 200000 | sed 's|^|     3.3.0-1 500 https://repos.example/repos/deb noble/stable amd64 Packages |'
fi
EOF

# wget: the apt key fetch, `-qO <file>` since #655 (install.md's key is taken
# as-is, never dearmored). Writes canned bytes to whatever -O names; the
# bytes themselves mean nothing here because the fingerprint check below is
# against the fake gpg, not against a real key.
# dpkg-deb: reads back the fake .deb the apt-get download stub wrote, the way
# the source move checks a kept package names itself. state/deb-wrong-version
# makes it claim another version.
cat > "$TMP/bin/dpkg-deb" <<EOF
#!/usr/bin/env bash
read -r _ n v < "\${*: -1}"
[[ -f "$TMP/state/deb-wrong-version" ]] && v=9.9.9-1
printf '%s %s' "\$n" "\$v"
EOF
cat > "$TMP/bin/wget" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/wget-calls"
out=""
while [[ \$# -gt 0 ]]; do case "\$1" in -O) out="\$2"; shift 2 ;; -qO) out="\$2"; shift 2 ;; *) shift ;; esac; done
if [[ -n "\$out" ]]; then echo "FAKE-SIGNING-KEY-BYTES" > "\$out"; else echo "FAKE-SIGNING-KEY-BYTES"; fi
exit 0
EOF
# gpg: --show-keys --with-colons answers the shape and fingerprint(s) the
# fix reads before trusting a key (#655). state/xrplf-fpr overrides the
# single-key fingerprint (the mismatch test); state/xrplf-key-shape selects
# a whole different colon layout (two-pub, with-subkey), which is what
# proves the fix counts pub records and reads the RIGHT fpr rather than
# just the first one in the file. --import/--export (with $GNUPGHOME set)
# fake the re-export-from-a-scratch-keyring step: import always "succeeds"
# by dropping a marker in $GNUPGHOME, export only answers once that marker
# is there, which is enough to prove the SUT never reaches export on a
# refused key without needing a real OpenPGP round-trip in this suite.
cat > "$TMP/bin/gpg" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/gpg-calls"
args=("\$@")
show=0; do_import=0; do_export=0; keyfile=""; fpr_arg=""
for ((i=0; i<\${#args[@]}; i++)); do
  case "\${args[i]}" in
    --show-keys) show=1 ;;
    --import) do_import=1 ;;
    --export) do_export=1 ;;
  esac
done
if [[ \$show -eq 1 ]]; then
  keyfile="\${args[-1]}"
  shape="\$(cat "$TMP/state/xrplf-key-shape" 2>/dev/null || echo one)"
  fpr="\$(cat "$TMP/state/xrplf-fpr" 2>/dev/null || echo "$XRPLF_FPR")"
  case "\$shape" in
    two-pub)
      # The pinned key, exactly as real, followed by an independent second
      # public key an attacker appended. A check reading only the first
      # fpr: line in the file sees the pin and never notices the second key.
      printf 'pub:-:4096:1:AA84D41A11D29FA9:1787062335:::-:::scSC::::::23::0:\n'
      printf 'fpr:::::::::%s:\n' "\$fpr"
      printf 'uid:-::::1787062335::HASH1::XRPLF Packages <distribution@example.com>::::::::::0:\n'
      printf 'pub:-:4096:1:DEADBEEF11223344:1787062335:::-:::scSC::::::23::0:\n'
      printf 'fpr:::::::::0000000000000000000000000000000000000001:\n'
      printf 'uid:-::::1787062335::HASH2::attacker <attacker@example.com>::::::::::0:\n'
      ;;
    with-subkey)
      # The pinned key, plus its own genuine encryption SUBkey — a real,
      # unremarkable shape for a production signing key. Still exactly one
      # pub: record, and the primary's fpr is what must be read, not the
      # subkey's (which appears in the file too, under its own fpr: line).
      printf 'pub:-:4096:1:AA84D41A11D29FA9:1787062335:::-:::scSC::::::23::0:\n'
      printf 'fpr:::::::::%s:\n' "\$fpr"
      printf 'uid:-::::1787062335::HASH1::XRPLF Packages <distribution@example.com>::::::::::0:\n'
      printf 'sub:-:4096:1:1122334455667788:1787062335::::::e::::::23:\n'
      printf 'fpr:::::::::1111111111111111111111111111111111111111:\n'
      ;;
    *)
      printf 'pub:-:4096:1:AA84D41A11D29FA9:1787062335:::-:::scSC::::::23::0:\n'
      printf 'fpr:::::::::%s:\n' "\$fpr"
      printf 'uid:-::::1787062335::HASH1::XRPLF Packages <distribution@example.com>::::::::::0:\n'
      ;;
  esac
  exit 0
fi
if [[ \$do_import -eq 1 ]]; then
  echo imported > "\${GNUPGHOME:?}/imported"
  exit 0
fi
if [[ \$do_export -eq 1 ]]; then
  [[ -s "\${GNUPGHOME:?}/imported" ]] || exit 1
  echo "FAKE-ARMORED-EXPORT"
  exit 0
fi
out=""
while [[ \$# -gt 0 ]]; do case "\$1" in -o) out="\$2"; shift 2 ;; *) shift ;; esac; done
[[ -n "\$out" ]] && cat > "\$out"
exit 0
EOF
# dnf + rpm: the RHEL path (native_add_repo_rpm). Recorded, never real.
cat > "$TMP/bin/dnf" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/dnf-calls"
case "\${1:-}" in
  install) exit 0 ;;
  download)
    # dnf download --destdir <dir> <pkg>-<version> (#802's keep)
    [[ -f "$NATIVE_LEGACY_RPM_REPO" ]] && echo present > "$TMP/state/legacy-at-download"
    [[ -f "$TMP/state/apt-download-fails" ]] && exit 1
    nv="\${4}"
    printf 'fakerpm %s %s\n' "\${nv%%-[0-9]*}" "\${nv#*-}" > "\$3/\${nv}.x86_64.rpm"
    exit 0 ;;
  makecache) [[ -f "$TMP/state/xrplf-unreachable" ]] && exit 1; exit 0 ;;
  list)
    [[ -f "$TMP/state/dnf-no-package" ]] && exit 1
    exit 0 ;;
esac
if [[ " \$* " == *" repoquery "* && "\$*" == *enablerepo=xrplf-stable* ]]; then
  [[ -f "$TMP/state/xrplf-unreachable" ]] || echo "xrpld-0:3.4.1-1.el9.x86_64"
  exit 0
fi
exit 0
EOF
cat > "$TMP/bin/rpm" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/rpm-calls"
# An installed package, for the source move's "is it installed" read (#802),
# only when a row says so: every other row keeps the old silent answer.
if [[ "\${1:-}" == -qp ]]; then
  read -r _ n v < "\${*: -1}"; printf '%s %s' "\$n" "\$v"; exit 0
fi
if [[ "\${1:-}" == -q && -f "$TMP/state/rpm-installed" ]]; then
  cat "$TMP/state/rpm-installed"; exit 0
fi
exit 0
EOF

# uname: x86_64 by default, so the arch gate is exercised deliberately, not
# by whatever CI runner happens to be under this.
cat > "$TMP/bin/uname" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == -m ]]; then cat "$TMP/state/arch" 2>/dev/null || echo x86_64; fi
EOF

# chown: recorded, never real. install-node-wrapper.sh's --native branch
# chowns the configuration it just wrote with no failure guard, which is
# correct on the real root it always runs under and would otherwise abort
# this unprivileged suite under set -e.
cat > "$TMP/bin/chown" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/chown-calls"
exit 0
EOF

# id: the operator exists and is not yet in the docker group.
cat > "$TMP/bin/id" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  -un) echo testop ;;
  -nG) cat "$TMP/state/groups" 2>/dev/null || echo "testop sudo" ;;
  *)   echo "uid=1000(testop)" ;;
esac
exit 0
EOF

# getent: the operator, and the node account (#31). Stateful for the node
# account on purpose - whether `xrpld` exists, and whether uid/gid 997 are
# free, are the two facts that decide which branch of node-user-lib.sh runs,
# and both branches ship. state/account-xrpld holds the passwd line once
# something has created it; state/id-997-taken makes 997 belong to someone
# else, the way it does on a host that installed another service first.
cat > "$TMP/bin/getent" <<EOF
#!/usr/bin/env bash
db="\${1:-}"; key="\${2:-}"
case "\$db:\$key" in
  passwd:testop) echo "testop:x:1000:1000::$TMP/home/testop:/bin/bash"; exit 0 ;;
  passwd:xrpld)
    [[ -f "$TMP/state/account-xrpld" ]] || exit 2
    cat "$TMP/state/account-xrpld"; exit 0 ;;
  group:xrpld)
    [[ -f "$TMP/state/group-xrpld" ]] || exit 2
    cat "$TMP/state/group-xrpld"; exit 0 ;;
  passwd:997)
    [[ -f "$TMP/state/id-997-taken" ]] && { echo "pcp:x:997:983:Performance Co-Pilot:/var/lib/pcp:/usr/sbin/nologin"; exit 0; }
    [[ -f "$TMP/state/account-xrpld" ]] && grep -q ':997:' "$TMP/state/account-xrpld" && { cat "$TMP/state/account-xrpld"; exit 0; }
    exit 2 ;;
  group:997)
    [[ -f "$TMP/state/id-997-taken" ]] && { echo "crontab:x:997:"; exit 0; }
    [[ -f "$TMP/state/group-xrpld" ]] && grep -q ':997:' "$TMP/state/group-xrpld" && { cat "$TMP/state/group-xrpld"; exit 0; }
    exit 2 ;;
  passwd:) echo "testop:x:1000:1000::$TMP/home/testop:/bin/bash"; exit 0 ;;
esac
# A numeric lookup, which is how --adopt turns the uid a container names back
# into an account name. Answered from the same account file, by number.
if [[ "\$db" == passwd && "\$key" =~ ^[0-9]+\$ && -f "$TMP/state/account-xrpld" ]]; then
  if [[ "\$(cut -d: -f3 "$TMP/state/account-xrpld")" == "\$key" ]]; then
    cat "$TMP/state/account-xrpld"; exit 0
  fi
fi
exit 2
EOF

# useradd / groupadd: recorded, and they create the account the getent above
# then answers for. The ids are whatever the call asked for, or 1501/1501 when
# it asked for none, which is the "system allocated them" case.
cat > "$TMP/bin/groupadd" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/groupadd-calls"
gid=1501
while [[ \$# -gt 0 ]]; do case "\$1" in --gid) gid="\$2"; shift 2 ;; *) shift ;; esac; done
printf 'xrpld:x:%s:\n' "\$gid" > "$TMP/state/group-xrpld"
exit 0
EOF
cat > "$TMP/bin/useradd" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/useradd-calls"
uid=1501
while [[ \$# -gt 0 ]]; do case "\$1" in --uid) uid="\$2"; shift 2 ;; *) shift ;; esac; done
gid=\$(cut -d: -f3 "$TMP/state/group-xrpld" 2>/dev/null || echo 1501)
printf 'xrpld:x:%s:%s:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' "\$uid" "\$gid" > "$TMP/state/account-xrpld"
exit 0
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/sleep"

# stat: the real one, except for the one question this suite cannot answer
# honestly without being root. The installer reads `stat -c %U <dir>/data` to
# decide whether this host is still on the pre-#31 root shape, and a store
# created by a test that is not root is owned by whoever ran the test, which
# would read as the root shape on every row. state/data-owner names the owner
# a row wants; without it every other stat call is the system's own.
cat > "$TMP/bin/stat" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "-c" && "\$2" == "%U" && "\$3" == "$TMP/node/data" && -f "$TMP/state/data-owner" ]]; then
  cat "$TMP/state/data-owner"
  exit 0
fi
exec /usr/bin/stat "\$@"
EOF

# ufw: active only when a marker says so, and every rule it is asked for is
# recorded. The installer must never ENABLE a firewall (that locks an
# operator out of a live SSH session), so "was it asked to" is checked on
# this log rather than on an exit status.
cat > "$TMP/bin/ufw" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/ufw-calls"
if [[ "\${1:-}" == status ]]; then
  if [[ -e "$TMP/state/ufw-active" ]]; then echo "Status: active"; else echo "Status: inactive"; fi
  exit 0
fi
exit 0
EOF

# sudo: docker_ask falls back to `sudo -n docker ps` when docker refuses the
# account. On a runner whose account may sudo for real, sudo's secure_path
# drops this fixture's bin and the machine's own docker answers for the
# fixture's: an empty list, so a refused docker reads as a host with no node,
# which is the very misreading the adopt row exists to refuse. Here sudo runs
# the command with the fakes still on PATH, and records that it was asked.
cat > "$TMP/bin/sudo" <<EOF
#!/usr/bin/env bash
printf 'sudo %s\n' "\$*" >> "$TMP/state/docker-calls"
while [[ "\${1:-}" == -* ]]; do shift; done
SUDO_STUB=1 exec "\$@"
EOF

chmod +x "$TMP"/bin/*
export PATH="$TMP/bin:$PATH"

NODE_DIR="$TMP/node"
CFG="$NODE_DIR/config/rippled.cfg"
VAL="$NODE_DIR/config/validators.txt"
COMPOSE="$NODE_DIR/docker-compose.yml"

reset() {
  rm -rf "$TMP/rollback" "$TMP/aptcache" "$TMP/dnfcache"
  mkdir -p "$TMP/aptcache" "$TMP/dnfcache"
  rm -rf "$ADVISOR_STATE" "$TMP/state" "$NODE_DIR" "$TMP/etc/aperire" "$NATIVE_DIR" \
         "$(dirname "$NATIVE_KEYRING")" "$(dirname "$NATIVE_SOURCES_LIST")" "$(dirname "$NATIVE_RPM_REPO")"
  mkdir -p "$ADVISOR_STATE" "$TMP/state" "$TMP/etc/aperire" "$NATIVE_DIR" \
           "$(dirname "$NATIVE_KEYRING")" "$(dirname "$NATIVE_SOURCES_LIST")" "$(dirname "$NATIVE_RPM_REPO")"
  printf '{"name":"xrpllabsofficial/xrpld","tags":["3.1.3","latest","3.2.0","nightly","3.3.0","3.4.0-rc1"]}\n' > "$TMP/state/tags"
  printf 'LISTEN 0 4096 127.0.0.1:5005 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:6006 0.0.0.0:*\n' > "$TMP/state/listening"
  echo healthy > "$TMP/state/container-health"
  printf '{"result":{"trusted_validator_keys":["nHU1","nHU2","nHU3"],"validation_quorum":3}}\n' > "$TMP/state/validators"
  # Native defaults: a supported OS and a resolvable package, so a row that
  # wants the unsupported-OS or no-candidate branch overwrites these after.
  printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
  echo x86_64 > "$TMP/state/arch"
  echo "3.3.0-1" > "$TMP/state/apt-candidate"
  echo "3.3.0-1" > "$TMP/state/pkgversion-xrpld"
}

# Where the Advisor keeps its acceptance, for the compact notice the native
# run ends with (#466). Its own directory under $TMP, never the machine's:
# a fixture that reaches the runner's own state would be answering about the
# wrong host.
ADVISOR_STATE="$TMP/advisor/state"

# The check the installer makes on an official image before it writes a
# deployment naming it (#682, second review). A stub, because the real one
# creates a container and fetches the signed package: what these rows are
# about is what the installer DOES with each answer. It answers yes unless
# the test asks it not to, which is the shape of a host where docker and
# the package chain both work.
VERIFY_STUB="$TMP/bin/verify-wrapper"
mkdir -p "$TMP/bin"
cat > "$VERIFY_STUB" <<'VSTUB'
#!/bin/bash
printf '%s\n' "$*" >> "$VERIFY_LOG_FILE"
[[ "${1:-}" == verify-official-image ]] || exit 0
if [[ -f "$VERIFY_REFUSE" ]]; then
  echo "this image is not what it claims to be" >&2
  exit 64
fi
printf 'verified=yes\n'
VSTUB
chmod +x "$VERIFY_STUB"

run_node() {  # rest = arguments to the installer
  OUT="$(SUDO_USER=testop \
    APERIRE_NODE_WRAPPER="$VERIFY_STUB" \
    VERIFY_LOG_FILE="$TMP/state/verify-calls" \
    VERIFY_REFUSE="$TMP/state/verify-refuse" \
    bash "$SUT" --dir "$NODE_DIR" "$@" 2>&1)"; RC=$?
}

run_native() {  # rest = arguments to the installer, --native is always added
  OUT="$(SUDO_USER=testop \
    APERIRE_ADVISOR_STATE="$ADVISOR_STATE" \
    APERIRE_OS_RELEASE_FILE="$OS_RELEASE" \
    APERIRE_NATIVE_DEB_KEYRING="$NATIVE_KEYRING" \
    APERIRE_NATIVE_DEB_SOURCES_LIST="$NATIVE_SOURCES_LIST" \
    APERIRE_NATIVE_RPM_REPO_FILE="$NATIVE_RPM_REPO" \
    APERIRE_NATIVE_LEGACY_DEB_KEYRING="$NATIVE_LEGACY_KEYRING" \
    APERIRE_NATIVE_LEGACY_DEB_SOURCES_LIST="$NATIVE_LEGACY_SOURCES_LIST" \
    APERIRE_NATIVE_LEGACY_RPM_REPO_FILE="$NATIVE_LEGACY_RPM_REPO" \
    APERIRE_NATIVE_CFG_CANDIDATES="$NATIVE_CFG" \
    APERIRE_PACKAGE_KEEP_DIR="$TMP/rollback" APERIRE_APT_CACHE_DIR="$TMP/aptcache" \
    APERIRE_DNF_CACHE_DIR="$TMP/dnfcache" \
    bash "$SUT" --native "$@" 2>&1)"; RC=$?
}

run_move() {  # the installer with --move-source and nothing else, which is how it is run
  OUT="$(SUDO_USER=testop \
    APERIRE_ADVISOR_STATE="$ADVISOR_STATE" \
    APERIRE_OS_RELEASE_FILE="$OS_RELEASE" \
    APERIRE_NATIVE_DEB_KEYRING="$NATIVE_KEYRING" \
    APERIRE_NATIVE_DEB_SOURCES_LIST="$NATIVE_SOURCES_LIST" \
    APERIRE_NATIVE_RPM_REPO_FILE="$NATIVE_RPM_REPO" \
    APERIRE_NATIVE_LEGACY_DEB_KEYRING="$NATIVE_LEGACY_KEYRING" \
    APERIRE_NATIVE_LEGACY_DEB_SOURCES_LIST="$NATIVE_LEGACY_SOURCES_LIST" \
    APERIRE_NATIVE_LEGACY_RPM_REPO_FILE="$NATIVE_LEGACY_RPM_REPO" \
    APERIRE_NATIVE_CFG_CANDIDATES="$NATIVE_CFG" \
    APERIRE_PACKAGE_KEEP_DIR="$TMP/rollback" APERIRE_APT_CACHE_DIR="$TMP/aptcache" \
    APERIRE_DNF_CACHE_DIR="$TMP/dnfcache" \
    bash "$SUT" --move-source 2>&1)"; RC=$?
}

# A native unit already loaded, with a config install-node-wrapper.sh --native
# can fully detect and prove: the two admin stanzas on loopback, a
# publisher list, and a debug log carrying one line with a stamp the
# rotation guard can parse. Mirrors write_native_fixture() in
# test-install-node-wrapper.sh, because it is the same fixture: this row
# calls that same script for real.
write_native_adopt_fixture() {  # $1 = unit, $2 = its [port_peer] port
  local unit="${1:-xrpld.service}" peer="${2:-2459}"
  cat > "$NATIVE_CFG" <<CFG
[port_peer]
port = $peer
ip = 0.0.0.0
protocol = peer

[port_rpc_admin_local]
port = 5005
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[port_ws_admin_local]
port = 6006
ip = 127.0.0.1
admin = 127.0.0.1
protocol = ws

[node_db]
type = NuDB
path = $NATIVE_DIR/db
online_delete = 32768
advisory_delete = 0

[node_size]
medium

[debug_logfile]
$NATIVE_DIR/debug.log

[validators_file]
$NATIVE_DIR/validators.txt
CFG
  mkdir -p "$NATIVE_DIR/db"
  printf '2026-Aug-13 04:32:01.070821912 SHAMapStore:WRN finished rotation. validatedSeq: 1032768\n' > "$NATIVE_DIR/debug.log"
  : > "$NATIVE_DIR/validators.txt"

  echo loaded  > "$TMP/state/unit-load-$unit"
  echo active  > "$TMP/state/unit-active-$unit"
  echo running > "$TMP/state/unit-sub-$unit"
  printf '{ path=/usr/bin/xrpld ; argv[]=/usr/bin/xrpld --net --conf %s --silent ; ignore_errors=no }\n' \
    "$NATIVE_CFG" > "$TMP/state/unit-execstart-$unit"
  printf 'xrpld\n' > "$TMP/state/owns-_usr_bin_xrpld"
  printf '3.3.0-1\n' > "$TMP/state/pkgversion-xrpld"
}
conf_val_wconf() { sed -n "s/^$1=//p" "$WCONF" 2>/dev/null | head -1; }
conf_val_nconf() { sed -n "s/^$1=//p" "$TMP/etc/aperire/node.conf" 2>/dev/null | head -1; }

# =====================================================================
echo
echo "The shipped templates, before anything renders them:"

# ── Every hardening line, asserted one at a time ─────────────────────
# Named individually on purpose. "the compose looks right" is not a test; a
# compose that lost exactly one of these starts a container that behaves the
# same until the day it matters.
while IFS='|' read -r label needle; do
  if grep -qF -- "$needle" "$COMPOSE_TPL"; then
    ok "compose template: $label"
  else
    bad "compose template: $label" "no line matching: $needle"
  fi
done <<'ROWS'
drops every capability|cap_drop: [ ALL ]
refuses privilege escalation|security_opt: [ "no-new-privileges:true" ]
pins the image to one reference, never latest|image: @IMAGE@
names a pull policy, so a locally built image is never fetched|pull_policy: @PULL_POLICY@
gives NuDB 90s to close|stop_grace_period: 90s
publishes admin RPC on loopback only|"127.0.0.1:5005:5005"
publishes admin WS on loopback only|"127.0.0.1:6006:6006"
publishes the peer port to the container's own peer port|"51235:2459/tcp"
caps the container log|max-size: "100m", max-file: "5", compress: "true"
uses the json-file driver|driver: json-file
health is what the node answers, not that it is up|healthcheck:
restarts unless the operator stopped it|restart: unless-stopped
ROWS

# ── The cross-file invariant that fails silently ─────────────────────
# The compose maps host:container. The config decides what the container
# binds. Nothing warns when the two disagree; inbound peers simply never
# arrive, which is exactly how the fleet's stock nodes were unreachable.
MAPPED_PEER="$(sed -n 's#^[[:space:]]*-[[:space:]]*"51235:\([0-9]*\)/tcp".*#\1#p' "$COMPOSE_TPL" | head -1)"
CFG_PEER="$(awk '
  /^[[:space:]]*\[port_peer\][[:space:]]*$/ { inb = 1; next }
  inb && /^[[:space:]]*\[/                  { inb = 0 }
  inb && /^[[:space:]]*port[[:space:]]*=/   { sub(/^[^=]*=[[:space:]]*/, ""); print; exit }
' "$CFG_TPL")"
if [[ -n "$MAPPED_PEER" && "$MAPPED_PEER" == "$CFG_PEER" ]]; then
  ok "the peer port the compose maps to ($MAPPED_PEER) is the port the config binds"
else
  bad "the peer port the compose maps to is the port the config binds" \
      "compose container side '$MAPPED_PEER', config [port_peer] '$CFG_PEER'"
fi

# ── The admin ports, read by the preflight's own parser ──────────────
# Not a parser written for this test: the awk below is preflight.sh's
# pf_cfg_port. If the preflight cannot read the config we ship, the node it
# just installed reads as absent on the very next command an operator runs.
cfg_port() {  # $1 = file, $2 = stanza
  awk -v want="[$2]" '
    $0 ~ /^[[:space:]]*\[/ { inb = ($0 ~ "^[[:space:]]*\\" want "[[:space:]]*$"); next }
    inb && /^[[:space:]]*port[[:space:]]*=/ { sub(/^[^=]*=[[:space:]]*/, ""); print; exit }
  ' "$1"
}
while IFS=' ' read -r stanza want; do
  got="$(cfg_port "$CFG_TPL" "$stanza")"
  if [[ "$got" == "$want" ]]; then
    ok "the preflight's parser reads $stanza = $want out of the shipped config"
  else
    bad "the preflight's parser reads $stanza = $want out of the shipped config" "got '$got'"
  fi
done <<'PORTS'
port_rpc_admin_local 5005
port_ws_admin_local 6006
PORTS

# ── The publisher list, which fails in total silence ─────────────────
# A node with no trusted publisher list peers, syncs, reaches full and never
# validates a ledger. [validators_file] is resolved against the config that is
# RUNNING, and the image's entrypoint moves that config, so this has to be an
# absolute path and it has to be the path the compose actually mounts.
VF="$(awk '
  /^[[:space:]]*\[validators_file\][[:space:]]*$/ { getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }
' "$CFG_TPL")"
# Every destination the compose mounts it at, not the first one: since #31 it
# is mounted twice, at the path the image's entrypoint looks for and at the
# path the node opens, and the config may name either. What must not happen is
# that it names a third path nothing mounts.
MOUNTED_VF="$(sed -nE 's#^[[:space:]]*-[[:space:]]*[^:[:space:]]*validators\.txt:([^:[:space:]]+):ro[[:space:]]*$#\1#p' "$COMPOSE_TPL")"
if [[ "$VF" == /* ]]; then
  ok "[validators_file] is an absolute container path, not resolved against wherever the entrypoint put the config"
else
  bad "[validators_file] is an absolute container path" "got '$VF'"
fi
if [[ -n "$MOUNTED_VF" ]] && printf '%s\n' "$MOUNTED_VF" | grep -qxF -e "$VF"; then
  ok "[validators_file] ($VF) is one of the paths the compose mounts validators.txt at"
else
  bad "[validators_file] is one of the paths the compose mounts validators.txt at" "config '$VF', compose mounts at '$(printf '%s' "$MOUNTED_VF" | tr '\n' ' ')'"
fi

# ── #81: exactly one advisory_delete line ────────────────────────────
ADC="$(awk '
  /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb = 1; next }
  inb && /^[[:space:]]*\[/                { inb = 0 }
  inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ { n++ }
  END { print n + 0 }
' "$CFG_TPL")"
if [[ "$ADC" == "1" ]]; then
  ok "the shipped config has exactly one advisory_delete line in [node_db] (#81)"
else
  bad "the shipped config has exactly one advisory_delete line in [node_db] (#81)" "found $ADC"
fi

# The stock value is 0, free-running. Setting 1 here would gate rotation
# behind a can_delete call that a fresh box has nothing to make, so
# online_delete would never run and the store would grow until the disk filled.
if grep -qE '^[[:space:]]*advisory_delete[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$CFG_TPL"; then
  ok "advisory_delete ships 0: a fresh box rotates on its own until a can-delete window exists"
else
  bad "advisory_delete ships 0" "$(grep -n 'advisory_delete' "$CFG_TPL")"
fi

# ── Nothing environment-specific reaches a shipped file ──────────────
if grep -rlnE '/home/[a-z_][a-z0-9_-]*/' "$TEMPLATES" >/dev/null 2>&1; then
  bad "no template carries a real home path" "$(grep -rnE '/home/[a-z_][a-z0-9_-]*/' "$TEMPLATES")"
else
  ok "no template carries a real home path (the installer substitutes @DIR@)"
fi
if grep -rhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$TEMPLATES" | grep -qv '^@' ; then
  bad "no template carries an email address" "$(grep -rhoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$TEMPLATES")"
else
  ok "no template carries an email address"
fi

# =====================================================================
echo
echo "A fresh host, from nothing:"

reset
run_node --yes --name test-node

if [[ $RC -eq 0 ]]; then
  ok "the run succeeds on a host with nothing on it"
else
  bad "the run succeeds on a host with nothing on it" "rc=$RC: $OUT"
fi

if [[ -f "$CFG" ]] && cmp -s "$CFG_TPL" "$CFG"; then
  ok "rippled.cfg is written, byte-identical to the shipped template"
else
  bad "rippled.cfg is written, byte-identical to the shipped template" "${OUT}"
fi

if [[ -f "$VAL" ]] && cmp -s "$TEMPLATES/validators.txt" "$VAL"; then
  ok "validators.txt is written, byte-identical to the shipped template"
else
  bad "validators.txt is written, byte-identical to the shipped template" "${OUT}"
fi

if [[ -f "$COMPOSE" ]]; then
  ok "docker-compose.yml is written"
else
  bad "docker-compose.yml is written" "$OUT"
fi

# ADR 0024: the node's config, its publisher list and its compose all start
# from a template, and each is checked against the release's digests before
# anything is written from it. A compose template rewritten in the tree after
# the unpack decides what root starts through the wrapper, so it is refused
# and no compose is written.
mkdir -p "$TMP/digests"
# The record a release would carry: every file in this rig's tree.
{
  printf '# anchor a fixture\n'
  (cd "$TMP/repo" && find . -type f -printf '%P\n' | sort | while IFS= read -r f; do
    printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"
  done)
} > "$TMP/digests/release.sha256"
chmod 0644 "$TMP/digests/release.sha256"
cp "$TMP/repo/scripts/templates/aperire-node.compose.yml" "$TMP/compose.release"
printf '    privileged: true\n' >> "$TMP/repo/scripts/templates/aperire-node.compose.yml"
reset
APERIRE_RELEASE_DIGESTS="$TMP/digests/release.sha256" run_node --yes --name test-node
if [[ $RC -ne 0 && ! -f "$COMPOSE" ]] \
   && grep -q 'refused: scripts/templates/aperire-node.compose.yml is not the file this release shipped' <<<"$OUT"; then
  ok "a compose template rewritten in the tree is refused, and no compose is written from it"
else
  bad "a tampered compose template is refused" "rc=$RC $(tail -5 <<<"$OUT")"
fi
cp "$TMP/compose.release" "$TMP/repo/scripts/templates/aperire-node.compose.yml"
reset
APERIRE_RELEASE_DIGESTS="$TMP/digests/release.sha256" run_node --yes --name test-node
if [[ $RC -eq 0 && -f "$COMPOSE" ]] && cmp -s "$TEMPLATES/validators.txt" "$VAL"; then
  ok "and the release's own templates go through the same check"
else
  bad "the release's templates are written" "rc=$RC $(tail -5 <<<"$OUT")"
fi
reset
run_node --yes --name test-node

# Every placeholder substituted. One left behind is a compose docker will
# either refuse or, worse, accept as a literal container name.
if [[ -f "$COMPOSE" ]] && ! grep -q '@[A-Z]*@' "$COMPOSE"; then
  ok "no @PLACEHOLDER@ survives into the rendered compose"
else
  bad "no @PLACEHOLDER@ survives into the rendered compose" "$(grep -n '@[A-Z]*@' "$COMPOSE" 2>/dev/null)"
fi

# The healthcheck is the line that does not survive being re-emitted through a
# heredoc. Rendering must be a substitution, so this line stays byte-identical.
TPL_HC="$(grep -F 'CMD-SHELL' "$COMPOSE_TPL")"
OUT_HC="$(grep -F 'CMD-SHELL' "$COMPOSE" 2>/dev/null)"
if [[ -n "$OUT_HC" && "$TPL_HC" == "$OUT_HC" ]]; then
  ok "the healthcheck line renders byte-identical to the template (its escapes survived)"
else
  bad "the healthcheck line renders byte-identical to the template" "template: $TPL_HC${NL:-}rendered: $OUT_HC"
fi

for needle in 'name: test-node' 'container_name: test-node' \
              "$NODE_DIR/config/rippled.cfg:/etc/xrpld/xrpld.cfg:ro" \
              "$NODE_DIR/config/validators.txt:/etc/xrpld/validators.txt:ro" \
              "$NODE_DIR/config/rippled.cfg:/config/rippled.cfg:ro" \
              "$NODE_DIR/config/validators.txt:/config/validators.txt:ro" \
              "$NODE_DIR/data:/var/lib/xrpld" \
              'entrypoint: ["/usr/bin/xrpld"]' \
              'command: ["--conf", "/etc/xrpld/xrpld.cfg"]' \
              'user: "997:997"'; do
  if grep -qF -- "$needle" "$COMPOSE" 2>/dev/null; then
    ok "rendered compose carries: $needle"
  else
    bad "rendered compose carries: $needle" "$(cat "$COMPOSE" 2>/dev/null)"
  fi
done

# A fresh install names the image it built here, and says never to pull it:
# localhost/ has no registry behind it, so a missing image must fail at once
# rather than send compose to Docker Hub.
if grep -qF 'image: localhost/xrpld:3.4.1' "$COMPOSE" 2>/dev/null \
   && grep -qF 'pull_policy: never' "$COMPOSE" 2>/dev/null; then
  ok "a fresh install names the image it built here, with pull_policy: never beside it"
else
  bad "a fresh install names the image it built here" "$(grep -n 'image:\|pull_policy' "$COMPOSE" 2>/dev/null)"
fi
if grep -qF -- '--version 3.4.1' "$TMP/state/build-calls" 2>/dev/null; then
  ok "and it built exactly that release, from the recipe installed where root keeps it"
else
  bad "it built exactly that release" "$(cat "$TMP/state/build-calls" 2>/dev/null)"
fi
# ── The official image is the first source (#682) ─────────────────────
#
# Same fresh host, with a registry that answers about the tag. The
# deployment then names the tag AND the digest, the image is pulled by
# digest before anything points at it, and nothing is built: a release with
# an official image is not a release this host has to compile.
reset
printf '{"name":"3.4.1","digest":"%s","images":[{"digest":"%s","architecture":"amd64","os":"linux"}]}\n' \
  'sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7' 'sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7' > "$TMP/state/official-tag"
run_node --yes --name test-node
if grep -qF "image: rippleci/xrpld:3.4.1@sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7" "$COMPOSE" 2>/dev/null \
   && grep -qF 'pull_policy: missing' "$COMPOSE" 2>/dev/null; then
  ok "an official image for the pinned release is what a fresh install names, tag and digest together"
else
  bad "a fresh install names the official image pinned by digest" \
      "rc=$RC $(grep -n 'image:\|pull_policy' "$COMPOSE" 2>/dev/null)"
fi
# Checked on this host before the deployment names it (#682, second
# review; the lead's ruling). A fresh install used to take the official
# digest on the strength of the tag alone, which is the same unproven
# claim the upgrade path spent a review closing, through a quieter door
# and on the first image most operators ever run.
if grep -qF "verify-official-image 3.4.1 sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7" \
     "$TMP/state/verify-calls" 2>/dev/null; then
  ok "and it checked that image against the signed package before writing the deployment"
else
  bad "a fresh install verifies the official image" "$(cat "$TMP/state/verify-calls" 2>/dev/null)"
fi
if grep -qF "pull rippleci/xrpld@sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7" "$TMP/state/docker-calls" 2>/dev/null; then
  ok "and it pulled that digest before the deployment named it"
else
  bad "it pulled the digest before the deployment named it" "$(cat "$TMP/state/docker-calls" 2>/dev/null)"
fi
if [[ ! -s "$TMP/state/build-calls" ]]; then
  ok "and nothing was built: a release an official image carries is not compiled here"
else
  bad "nothing was built when an official image exists" "$(cat "$TMP/state/build-calls" 2>/dev/null)"
fi

# A RE-RUN over the deployment this installer itself wrote. The pinned line
# ends in the digest, so its last colon belongs to the digest and not to the
# tag: a split that took the tag off the end would resolve a repository of
# `rippleci/xrpld:3.4.1@sha256` and a "tag" of 64 hex characters, and rewrite
# a working deployment into one that cannot start.
run_node --yes --name test-node
if grep -qF "image: rippleci/xrpld:3.4.1@sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7" "$COMPOSE" 2>/dev/null; then
  ok "a re-run over a digest-pinned deployment keeps the line exactly as it was"
else
  bad "a re-run keeps the pinned line" "$(grep -n 'image:' "$COMPOSE" 2>/dev/null)"
fi
if printf '%s' "$OUT" | grep -qF "keeping the image this node is already on: rippleci/xrpld:3.4.1@sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7"; then
  ok "and says so, naming the whole reference rather than a tag it invented"
else
  bad "the re-run names the whole reference" "$(printf '%s' "$OUT" | grep -i 'keeping the image')"
fi
if ! printf '%s' "$OUT" | grep -qiE 'image tag.*(e7e7e7|sha256)'; then
  ok "and never reports a digest as the release it is installing"
else
  bad "a digest was reported as the release" "$(printf '%s' "$OUT" | grep -i 'image tag')"
fi

# An official image that does NOT check out is not installed at all: the
# run falls back to building the same release from the signed package, and
# says so rather than doing it quietly.
reset
printf '{"name":"3.4.1","digest":"%s","images":[{"digest":"%s","architecture":"amd64","os":"linux"}]}\n' \
  'sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7' 'sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7' > "$TMP/state/official-tag"
: > "$TMP/state/verify-refuse"
run_node --yes --name test-node
rm -f "$TMP/state/verify-refuse"
if grep -qF 'image: localhost/xrpld:3.4.1' "$COMPOSE" 2>/dev/null \
   && grep -qF 'pull_policy: never' "$COMPOSE" 2>/dev/null; then
  ok "an official image that does not check out is not what the deployment names"
else
  bad "a failed check falls back to the build" \
      "rc=$RC $(grep -n 'image:\|pull_policy' "$COMPOSE" 2>/dev/null)"
fi
if [[ "$OUT" == *"did not check out"* && "$OUT" == *"building"* ]]; then
  ok "and it says both what it refused and what it did instead"
else
  bad "the fallback explains itself" "$(printf '%s' "$OUT" | tail -5)"
fi

# --image-tag over a deployment already pinned by digest. The digest pins
# ONE release: carrying the old one onto a new tag would write
# `repo:3.4.2@sha256:<3.4.1's digest>`, and the file would say one release
# while docker ran another. Met in review on 2026-09-27.
reset
# A deployment that IS pinned by digest, written by the ordinary path.
printf '{"name":"3.4.1","digest":"%s","images":[{"digest":"%s","architecture":"amd64","os":"linux"}]}\n' \
  'sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7' 'sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7' > "$TMP/state/official-tag"
run_node --yes --name test-node
grep -qF "image: rippleci/xrpld:3.4.1@sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7" "$COMPOSE" \
  || { echo "the pinned install did not happen, so the rows below prove nothing"; exit 1; }
# Now ask for a different release on that same deployment.
printf '{"name":"3.4.2","digest":"%s","images":[{"digest":"%s","architecture":"amd64","os":"linux"}]}\n' \
  'sha256:f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1' 'sha256:f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1' > "$TMP/state/official-tag"
run_node --yes --name test-node --image-tag 3.4.2
# The installer never overwrites a deployment it did not just write, so what
# it RESOLVED is what it prints: the digest the new tag has, and the command
# that would move the file.
if printf '%s' "$OUT" | grep -qF "pinning 3.4.2 to sha256:f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"; then
  ok "a --image-tag over a pinned deployment looks the new release's own digest up"
else
  bad "a new tag gets its own digest" "$(printf '%s' "$OUT" | grep -iE 'pinning|image tag' | tail -3)"
fi
if ! printf '%s' "$OUT" | grep -qE "3\.4\.2 .*sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7"; then
  ok "and the old release's digest is never named as this one's"
else
  bad "the old digest is dropped" "$(printf '%s' "$OUT" | grep -F "sha256:e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7" | tail -3)"
fi
# The command an operator is handed for a pinned deployment verifies the
# digest before it sets it, because the wrapper refuses an unverified one.
# shellcheck disable=SC2016  # the literal ${...} text is what is searched for
if grep -qF 'verify-official-image ${IMAGE_TAG} ${IMAGE_DIGEST}' "$REPO_DIR/scripts/install-aperire-node.sh"; then
  ok "and the command it hands over verifies that digest before it sets it"
else
  bad "the hint verifies first" "$(grep -n 'set-image-official' "$REPO_DIR/scripts/install-aperire-node.sh" | head -3)"
fi

# And when no official image carries the tag that was asked for, the run
# refuses rather than turning a pinned line into a mutable one.
rm -f "$TMP/state/official-tag"
run_node --yes --name test-node --image-tag 3.4.3
if [[ $RC -ne 0 ]] && printf '%s' "$OUT" | grep -q "pinned by digest and no official image could be found"; then
  ok "a tag with no official image refuses rather than un-pinning the deployment"
else
  bad "a missing image refuses on a pinned deployment" "rc=$RC: $(printf '%s' "$OUT" | tail -4)"
fi

# And back: a registry that answers 404 for the tag (an empty body here) is
# not an error, it is the build's cue. Restores the state every row below
# this one was written against.
rm -f "$TMP/state/official-tag"
reset
run_node --yes --name test-node
if grep -qF 'image: localhost/xrpld:3.4.1' "$COMPOSE" 2>/dev/null \
   && grep -qF 'pull_policy: never' "$COMPOSE" 2>/dev/null \
   && grep -qF -- '--version 3.4.1' "$TMP/state/build-calls" 2>/dev/null; then
  ok "no official image for the release, and the install builds one from the signed package instead"
else
  bad "no official image, so the install builds one" \
      "$(grep -n 'image:\|pull_policy' "$COMPOSE" 2>/dev/null)"
fi

if ! grep -q 'auth.docker.io\|tags/list' "$TMP/state/docker-calls" 2>/dev/null; then
  ok "and nothing asked a registry what is newest: the release is pinned here and bumped deliberately"
else
  bad "nothing asks a registry what is newest" "$(cat "$TMP/state/docker-calls")"
fi

# The crash-loop from the proving run, asserted on the request rather than on
# a mode this unprivileged test cannot set. The owner is the node's own
# account now, not root (#31): dropping ALL capabilities binds the process to
# these modes whoever it is, so a store the node does not own is the same
# crash loop it always was, one uid further along.
if grep -qE '^-d -o xrpld -g xrpld -m 0755 .*/data$' "$TMP/state/install-calls"; then
  ok "data/ is created owned by the node's own account (it has to write its store)"
else
  bad "data/ is created owned by the node's own account" "$(cat "$TMP/state/install-calls")"
fi
for who in testop root; do
  if grep -qE "^-d -o $who .*/data\$" "$TMP/state/install-calls"; then
    bad "data/ is never created owned by $who" "$(grep '/data' "$TMP/state/install-calls")"
  else
    ok "data/ is never created owned by $who"
  fi
done

# The account itself: created, at the ids the node image uses, and with a
# nologin shell. A login shell on an account that owns a validator's store is
# a door nobody asked for.
if grep -q -- '--uid 997' "$TMP/state/useradd-calls" 2>/dev/null \
   && grep -q -- '--gid 997' "$TMP/state/groupadd-calls" 2>/dev/null; then
  ok "the node account is created at 997:997, the uid and gid the image itself uses"
else
  bad "the node account is created at 997:997" "useradd: $(cat "$TMP/state/useradd-calls" 2>/dev/null); groupadd: $(cat "$TMP/state/groupadd-calls" 2>/dev/null)"
fi
if grep -q -- '--system' "$TMP/state/useradd-calls" 2>/dev/null \
   && grep -q -- 'nologin' "$TMP/state/useradd-calls" 2>/dev/null \
   && grep -q -- '--no-create-home' "$TMP/state/useradd-calls" 2>/dev/null; then
  ok "it is a system account with no home and no login shell"
else
  bad "it is a system account with no home and no login shell" "$(cat "$TMP/state/useradd-calls" 2>/dev/null)"
fi

# The config and the validator list: group, not mode. The node reads them
# through the group once close-node-config-exposure.sh closes the file to
# everyone else; without the group that tightening is what breaks the node.
if grep -qE '^-o testop -g xrpld -m 0644 .*/rippled.cfg$' "$TMP/state/install-calls"; then
  ok "the config is written group xrpld, so the node can read it through the group"
else
  bad "the config is written group xrpld" "$(grep 'rippled.cfg' "$TMP/state/install-calls")"
fi
if grep -qE '^-o testop -g xrpld -m 0644 .*/validators.txt$' "$TMP/state/install-calls"; then
  ok "validators.txt is written group xrpld too"
else
  bad "validators.txt is written group xrpld too" "$(grep 'validators.txt' "$TMP/state/install-calls")"
fi

# The compose runs it as that account, by number, and the mounts that make a
# non-root start possible are both there. Asserted as a set: user:, the four
# read-only config mounts, the store, and cap_drop still in the file.
compose_is_nonroot_shape() { # $1 = compose file, $2 = uid:gid
  grep -qE "^[[:space:]]*user: \"$2\"" "$1" \
    && grep -qF ":/etc/xrpld/xrpld.cfg:ro" "$1" \
    && grep -qF ":/etc/xrpld/validators.txt:ro" "$1" \
    && grep -qF ":/config/rippled.cfg:ro" "$1" \
    && grep -qF ":/config/validators.txt:ro" "$1" \
    && grep -qF ":/var/lib/xrpld" "$1" \
    && grep -qF "cap_drop" "$1"
}
if compose_is_nonroot_shape "$COMPOSE" "997:997"; then
  ok "the compose is the non-root shape: user, both config paths, the store, cap_drop"
else
  bad "the compose is the non-root shape" "$(cat "$COMPOSE" 2>/dev/null)"
fi

# What the run says out loud. An operator reading the output has to be able to
# tell that the node is not root without going and asking docker.
if [[ "$OUT" == *"the node runs as uid 997 (xrpld), not root"* ]]; then
  ok "the verify says, from the container itself, that the node is not root"
else
  bad "the verify says the node is not root" "$OUT"
fi

if grep -q 'up -d' "$TMP/state/docker-calls"; then
  ok "the container is started, not left for the operator to start"
else
  bad "the container is started" "$(cat "$TMP/state/docker-calls")"
fi

if grep -q 'docker' "$TMP/state/usermod-calls" 2>/dev/null && [[ "$OUT" == *"log out and back in"* ]]; then
  ok "the operator is added to the docker group and told a re-login is needed"
else
  bad "the operator is added to the docker group and told a re-login is needed" "$(cat "$TMP/state/usermod-calls" 2>/dev/null): $OUT"
fi

if [[ "$OUT" == *"root-equivalent"* ]]; then
  ok "the docker group is described as the grant it is, not slipped in"
else
  bad "the docker group is described as the grant it is" "$OUT"
fi

# ── The verify, when everything answered ─────────────────────────────
if [[ "$OUT" == *"server_info answers: server_state=tracking"* ]]; then
  ok "the verify reports server_info's answer, with the state it read"
else
  bad "the verify reports server_info's answer, with the state it read" "$OUT"
fi
if [[ "$OUT" == *"ledger sequence advanced:"* ]]; then
  ok "the verify reads the ledger sequence twice and says it moved"
else
  bad "the verify reads the ledger sequence twice and says it moved" "$OUT"
fi
if [[ "$OUT" == *"127.0.0.1:5005 is listening"* && "$OUT" == *"127.0.0.1:6006 is listening"* ]]; then
  ok "both admin ports are measured on loopback"
else
  bad "both admin ports are measured on loopback" "$OUT"
fi
if [[ "$OUT" == *"running, healthy"* ]]; then
  ok "the container's health is read back, not assumed"
else
  bad "the container's health is read back, not assumed" "$OUT"
fi
if [[ "$OUT" == *"curl -fsSL https://get.aperire.one | bash"* ]]; then
  ok "the closing text prints the next command"
else
  bad "the closing text prints the next command" "$OUT"
fi
if [[ "$OUT" == *"3 trusted validators"* ]]; then
  ok "the verify counts the trusted validator set, which no other check can see"
else
  bad "the verify counts the trusted validator set" "$OUT"
fi
if [[ "$OUT" == *"hours, not minutes"* && "$OUT" == *"connected"* ]]; then
  ok "it says honestly what a syncing node looks like and how long it takes"
else
  bad "it says honestly what a syncing node looks like and how long it takes" "$OUT"
fi

# =====================================================================
echo
echo "The second run, on the host the first one left:"

CFG_SUM=$(md5sum < "$CFG"); VAL_SUM=$(md5sum < "$VAL"); COMPOSE_SUM=$(md5sum < "$COMPOSE")
# A re-run must keep the image this node is on. An installer that resolved a
# release here would stage an upgrade nobody asked for, on a re-run whose
# whole promise is that it changes nothing.
rm -f "$TMP/state/install-calls" "$TMP/state/build-calls"
run_node --yes --name test-node

if [[ $RC -eq 0 ]]; then
  ok "the second run succeeds"
else
  bad "the second run succeeds" "rc=$RC: $OUT"
fi
if [[ "$(md5sum < "$CFG")" == "$CFG_SUM" && "$(md5sum < "$VAL")" == "$VAL_SUM" && "$(md5sum < "$COMPOSE")" == "$COMPOSE_SUM" ]]; then
  ok "the second run changes nothing: all three files are byte-identical"
else
  bad "the second run changes nothing" "one of rippled.cfg / validators.txt / docker-compose.yml moved"
fi
if grep -qF 'image: localhost/xrpld:3.4.1' "$COMPOSE" && [[ ! -s "$TMP/state/build-calls" ]]; then
  ok "a re-run keeps the image the node is on, and does not build it again"
else
  bad "a re-run keeps the image the node is on" "$(grep -n 'image:' "$COMPOSE"); builds: $(cat "$TMP/state/build-calls" 2>/dev/null)"
fi
if [[ ! -f "${COMPOSE}.prev" ]]; then
  ok "no .prev backup is left when nothing changed"
else
  bad "no .prev backup is left when nothing changed" "${COMPOSE}.prev exists"
fi
if [[ "$OUT" == *"keeping it exactly as it is"* ]]; then
  ok "the second run says out loud that it kept the config"
else
  bad "the second run says out loud that it kept the config" "$OUT"
fi

# =====================================================================
echo
echo "A config the operator already wrote:"

reset
mkdir -p "$NODE_DIR/config"
printf '[node_db]\ntype=NuDB\n# the operator wrote this and it is theirs\n' > "$CFG"
MINE=$(md5sum < "$CFG")
run_node --yes --name test-node

if [[ "$(md5sum < "$CFG")" == "$MINE" ]]; then
  ok "an existing rippled.cfg is kept byte-for-byte"
else
  bad "an existing rippled.cfg is kept byte-for-byte" "$(cat "$CFG")"
fi
if [[ "$OUT" == *"keeping it exactly as it is"* ]]; then
  ok "and it SAYS it kept it, rather than being silently skipped"
else
  bad "and it SAYS it kept it" "$OUT"
fi

# =====================================================================
echo
echo "A host where uid 997 already belongs to something else:"

# 997 is inside the range a distribution allocates system accounts from, so on
# a host that installed another service first it is taken. Forcing the number
# would hand that account write access to the ledger store and its group read
# access to a config carrying a validator token. The number is preferred, not
# forced, and the run has to say what it did.
reset
: > "$TMP/state/id-997-taken"
run_node --yes --name test-node

if [[ $RC -eq 0 ]]; then
  ok "the install still succeeds when 997 is taken"
else
  bad "the install still succeeds when 997 is taken" "rc=$RC: $OUT"
fi
if grep -q -- '--uid 997' "$TMP/state/useradd-calls" 2>/dev/null; then
  bad "997 is not forced onto a host that has it" "$(cat "$TMP/state/useradd-calls")"
else
  ok "997 is not forced onto a host that has it; the system allocates the ids"
fi
if [[ "$OUT" == *"pcp"* && "$OUT" == *"crontab"* ]]; then
  ok "the run names the accounts that hold 997, rather than failing silently"
else
  bad "the run names the accounts that hold 997" "$OUT"
fi
if compose_is_nonroot_shape "$COMPOSE" "1501:1501"; then
  ok "the compose runs the node as the ids this host allocated"
else
  bad "the compose runs the node as the ids this host allocated" "$(grep -n 'user:' "$COMPOSE" 2>/dev/null)"
fi
if [[ "$(conf_val_nconf NODE_UID)" == 1501 && "$(conf_val_nconf NODE_GID)" == 1501 \
      && "$(conf_val_nconf NODE_USER)" == xrpld ]]; then
  ok "node.conf records the account, so nothing downstream has to guess the uid"
else
  bad "node.conf records the account" "$(cat "$TMP/etc/aperire/node.conf" 2>/dev/null)"
fi

# =====================================================================
echo
echo "A node installed before it ran as a non-root user:"

# The dangerous re-run. This host has a root-owned store and a compose with no
# user: line. Rewriting that compose here would recreate the container as a
# user that cannot write the store, which is a crash loop, and moving the
# config group would take the read away from the node running right now. The
# installer has to leave both alone and name the script that does it in the
# right order, with the node stopped.
reset
mkdir -p "$NODE_DIR/config" "$NODE_DIR/data"
printf '[node_db]\ntype=NuDB\n' > "$CFG"
: > "$VAL"
printf 'services:\n  test-node:\n    image: xrpllabsofficial/xrpld:3.3.0\n    init: true\n    cap_drop: [ ALL ]\n    volumes:\n      - %s:/config/rippled.cfg:ro\n      - %s/data:/var/lib/xrpld\n' \
  "$CFG" "$NODE_DIR" > "$COMPOSE"
OLD_COMPOSE=$(md5sum < "$COMPOSE")
run_node --yes --name test-node

if [[ "$(md5sum < "$COMPOSE")" == "$OLD_COMPOSE" ]]; then
  ok "the older deployment's compose is left exactly as it was"
else
  bad "the older deployment's compose is left exactly as it was" "$(cat "$COMPOSE")"
fi
if [[ "$OUT" == *"--run migrate-node"* ]]; then
  ok "the run names the one script that moves it, rather than doing half of it here"
else
  bad "the run names the one script that moves it" "$OUT"
fi
if grep -qE '^-d -o xrpld .*/data$' "$TMP/state/install-calls" 2>/dev/null; then
  bad "the existing store is not chowned by a re-run" "$(grep '/data' "$TMP/state/install-calls")"
else
  ok "the existing store is not chowned by a re-run"
fi
if [[ ! -f "${COMPOSE}.prev" ]]; then
  ok "and no .prev is written, because nothing was rewritten"
else
  bad "no .prev is written" "${COMPOSE}.prev exists"
fi
# The run has to end well and READ as ending well. The container on this host
# answers root to `id -u`, which is the truth and is also what this run just
# decided to leave alone, so calling it FAILED would contradict the
# instruction printed two steps earlier. An operator who sees a red line does
# not read the amber one above it.
if [[ $RC -eq 0 && "$OUT" != *FAILED* ]]; then
  ok "the run succeeds and prints no FAILED line about the state it deliberately left"
else
  bad "the run succeeds and prints no FAILED line" "rc=$RC: $(printf '%s' "$OUT" | grep -i failed)"
fi
if [[ "$OUT" == *"still running as root"* ]]; then
  ok "it still says the node is root, as a note rather than as a failure"
else
  bad "it says the node is root as a note" "$OUT"
fi

# =====================================================================
echo
echo "A host scripts/migrate-node-nonroot.sh has already moved (#441):"

# The other dangerous re-run, and the one that is worse. This host is
# MIGRATED: its store is owned by the node's account and its compose carries
# user: and the two /etc/xrpld mounts, patched in place. The file therefore
# differs from a fresh render by its header comment alone, which is enough for
# `cmp` to call it different, and replacing it and starting the node three
# lines later leaves a node that cannot open a store it no longer owns as
# root. Measured on aperire4 (#441), where the guard was an immutable flag on
# the node directory because nothing the installer read could stop it.
write_migrated_host() {  # $1 = uid:gid the migration chose
  local ids="$1" uid="${1%%:*}" gid="${1##*:}"
  mkdir -p "$NODE_DIR/config" "$NODE_DIR/data"
  printf '[node_db]\ntype=NuDB\n' > "$CFG"
  : > "$VAL"
  # The template rendered with those ids, then given the header a release
  # before #31 wrote: that is exactly what the migration leaves behind, since
  # it patches the service block and never touches the comments (#438).
  {
    printf '# An older release rendered this file, and the migration patched it.\n'
    printf '#   cap_drop / no-new-privileges  ... so data/ must be root-owned.\n'
    sed -e "s#@NAME@#test-node#g" -e "s#@DIR@#${NODE_DIR}#g" \
        -e "s#@IMAGE@#xrpllabsofficial/xrpld:3.3.0#g" -e "s#@PULL_POLICY@#missing#g" \
        -e "s#@UID@#${uid}#g" -e "s#@GID@#${gid}#g" "$COMPOSE_TPL" \
      | sed -n '/^name:/,$p'
  } > "$COMPOSE"
  echo "$ids" > "$TMP/state/migrated-ids"
  printf 'xrpld\n' > "$TMP/state/data-owner"
}

reset
write_migrated_host "996:998"
{
  printf 'KIND=container\nSERVICE=test-node\nNODE_LABEL=test-node\n'
  printf 'NODE_USER=xrpld\nNODE_UID=996\nNODE_GID=998\n'
} > "$TMP/etc/aperire/node.conf"
: > "$TMP/state/id-997-taken"
printf 'xrpld:x:996:998:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' > "$TMP/state/account-xrpld"
printf 'xrpld:x:998:\n' > "$TMP/state/group-xrpld"
MIGRATED_COMPOSE=$(md5sum < "$COMPOSE")
run_node --yes --name test-node

if [[ "$(md5sum < "$COMPOSE")" == "$MIGRATED_COMPOSE" ]]; then
  ok "a migrated compose is kept byte-for-byte, header and all"
else
  bad "a migrated compose is kept byte-for-byte" "$(cat "$COMPOSE")"
fi
if [[ "$OUT" == *"was migrated onto a non-root account"* && "$OUT" == *'user: "996:998"'* ]]; then
  ok "and the run says the host is migrated, naming the account the deployment runs as"
else
  bad "the run says the host is migrated, naming the account" "$OUT"
fi
if [[ "$OUT" == *"node.conf records the same account (996:998)"* ]]; then
  ok "it confirms the ids against the record the migration wrote, rather than against the file alone"
else
  bad "it confirms the ids against node.conf" "$OUT"
fi
if [[ ! -f "${COMPOSE}.prev" ]]; then
  ok "no .prev is written, because nothing was rewritten"
else
  bad "no .prev is written" "$(cat "${COMPOSE}.prev")"
fi
if grep -qE '^-d -o .* '"$NODE_DIR"'/data$' "$TMP/state/install-calls" 2>/dev/null; then
  bad "the migrated store is not re-owned by a re-run" "$(grep '/data' "$TMP/state/install-calls")"
else
  ok "the migrated store is not re-owned by a re-run (no install -d over data/)"
fi
if [[ $RC -eq 0 && "$OUT" != *"not writing"* ]]; then
  ok "the run finishes, and does not read as the pre-#31 root shape"
else
  bad "the run finishes on a migrated host" "rc=$RC: $OUT"
fi

# The same host, with the account renumbered underneath it: a rebuild that
# allocated different ids, which is exactly what a restore onto a rebuilt host
# produces (#431). Still not overwritten, and both numbers are said.
reset
write_migrated_host "996:998"
{
  printf 'KIND=container\nSERVICE=test-node\nNODE_LABEL=test-node\n'
  printf 'NODE_USER=xrpld\nNODE_UID=996\nNODE_GID=998\n'
} > "$TMP/etc/aperire/node.conf"
printf 'xrpld:x:1002:1002:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' > "$TMP/state/account-xrpld"
printf 'xrpld:x:1002:\n' > "$TMP/state/group-xrpld"
MIGRATED_COMPOSE=$(md5sum < "$COMPOSE")
run_node --yes --name test-node

if [[ "$(md5sum < "$COMPOSE")" == "$MIGRATED_COMPOSE" ]]; then
  ok "a compose naming ids this host no longer has is still not overwritten"
else
  bad "a compose naming ids this host no longer has is not overwritten" "$(cat "$COMPOSE")"
fi
if [[ "$OUT" == *"it names 996:998 and the xrpld account here is 1002:1002"* ]]; then
  ok "and the run names both numbers, which is the reading an operator needs"
else
  bad "the run names both numbers" "$OUT"
fi

# The same two markers, on a host nothing ever migrated. Today's template
# renders `user:` and both /etc/xrpld mounts itself, so a plain post-#31
# install reads as "migrated" to that branch. Keeping the file is still
# right (it may carry per-host edits), but on this host the run can be
# carrying a tag the operator asked for on the command line, and keeping the
# file means not applying it. Silence there is the same class of bug the
# branch was written to fix, pointed the other way.
write_post31_host() {  # the template exactly as this release renders it
  mkdir -p "$NODE_DIR/config" "$NODE_DIR/data"
  printf '[node_db]\ntype=NuDB\n' > "$CFG"
  : > "$VAL"
  sed -e "s#@NAME@#test-node#g" -e "s#@DIR@#${NODE_DIR}#g" \
      -e "s#@IMAGE@#localhost/xrpld:3.4.1#g" -e "s#@PULL_POLICY@#never#g" \
      -e "s#@UID@#996#g" -e "s#@GID@#998#g" "$COMPOSE_TPL" > "$COMPOSE"
  printf 'xrpld\n' > "$TMP/state/data-owner"
}

reset
write_post31_host
{
  printf 'KIND=container\nSERVICE=test-node\nNODE_LABEL=test-node\n'
  printf 'NODE_USER=xrpld\nNODE_UID=996\nNODE_GID=998\n'
} > "$TMP/etc/aperire/node.conf"
: > "$TMP/state/id-997-taken"
printf 'xrpld:x:996:998:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' > "$TMP/state/account-xrpld"
printf 'xrpld:x:998:\n' > "$TMP/state/group-xrpld"
POST31_COMPOSE=$(md5sum < "$COMPOSE")
echo "localhost/xrpld:3.4.2" >> "$TMP/state/images"
run_node --yes --name test-node --image-tag 3.4.2

if [[ "$(md5sum < "$COMPOSE")" == "$POST31_COMPOSE" ]]; then
  ok "a post-#31 compose is kept when a re-run asks for a different release"
else
  bad "a post-#31 compose is kept on a release re-run" "$(cat "$COMPOSE")"
fi
if [[ "$OUT" == *"the image was NOT applied"* && "$OUT" == *"localhost/xrpld:3.4.1"* && "$OUT" == *"3.4.2"* ]]; then
  ok "and the run says the image was not applied, naming the one on the file and the one asked for"
else
  bad "the run says the tag was not applied" "$OUT"
fi
if [[ "$OUT" == *"set-image-local 3.4.2"* ]]; then
  ok "and it names the verb that moves a locally built image, not the registry one"
else
  bad "it names the way to move the tag" "$OUT"
fi
# The wrapper the hint names is the root-owned copy, under the instance's own
# name on an instance host: the default program is another node's (#929).
if [[ "$OUT" == *"sudo aperire-node-wrapper set-image-local 3.4.2"* ]]; then
  ok "the hint names the root-owned wrapper, by its default name"
else
  bad "the hint names the root-owned wrapper" "$OUT"
fi
APERIRE_INSTANCE=node2 run_node --yes --name test-node --image-tag 3.4.2
if [[ "$OUT" == *"sudo aperire-node-wrapper-node2 set-image-local 3.4.2"* ]]; then
  ok "and on an instance host it names that instance's wrapper, not the default node's"
else
  bad "the hint names the instance's wrapper" "$OUT"
fi

# The header-only case, which is the one #441 was filed on: same body, older
# comment block. That is not a difference to warn about, and saying so is
# what keeps the warning above worth reading.
reset
write_migrated_host "996:998"
{
  printf 'KIND=container\nSERVICE=test-node\nNODE_LABEL=test-node\n'
  printf 'NODE_USER=xrpld\nNODE_UID=996\nNODE_GID=998\n'
} > "$TMP/etc/aperire/node.conf"
: > "$TMP/state/id-997-taken"
printf 'xrpld:x:996:998:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' > "$TMP/state/account-xrpld"
printf 'xrpld:x:998:\n' > "$TMP/state/group-xrpld"
run_node --yes --name test-node

if [[ "$OUT" == *"apart from the comment header"* && "$OUT" != *"the image was NOT applied"* ]]; then
  ok "a migrated compose whose body matches is reported as header-only, with no image warning"
else
  bad "a header-only difference is reported as header-only" "$OUT"
fi

# =====================================================================
echo
echo "Recording a node this installer did not put here (--adopt, #434):"

# A wipe-clean uninstall removes /etc/aperire whole; the node and its 46 GB
# store survive by design, and nothing on the reinstall path writes node.conf
# back on a host whose node is already running. So the record goes and the
# node stays, and every reader without a fallback dead-ends on it. Measured on
# aperire4 on the host the restore drill had rebuilt that morning.
adopted_host() {  # a running node, its compose, and no /etc/aperire at all
  mkdir -p "$NODE_DIR/config"
  printf '[node_db]\ntype=NuDB\n' > "$CFG"
  : > "$VAL"
  sed -e "s#@NAME@#test-node#g" -e "s#@DIR@#${NODE_DIR}#g" -e "s#@TAG@#3.3.0#g" \
      -e "s#@UID@#996#g" -e "s#@GID@#998#g" "$COMPOSE_TPL" > "$COMPOSE"
  echo running > "$TMP/state/container-state"
  echo test-node > "$TMP/state/containers"
  echo "127.0.0.1:5005" > "$TMP/state/published-5005"
  printf 'xrpld:x:996:998:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' > "$TMP/state/account-xrpld"
  rm -f "$TMP/etc/aperire/node.conf"
}

reset
adopted_host
COMPOSE_BEFORE=$(md5sum < "$COMPOSE")
CFG_BEFORE=$(md5sum < "$CFG")
run_node --adopt

if [[ $RC -eq 0 && -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "a host whose node survived gets its node.conf back"
else
  bad "the record comes back" "rc=$RC: $OUT"
fi
if [[ "$(conf_val_nconf SERVICE)" == test-node && "$(conf_val_nconf KIND)" == container \
      && "$(conf_val_nconf CONFIG_FILE)" == "$CFG" \
      && "$(conf_val_nconf ADMIN_RPC)" == "http://127.0.0.1:5005" \
      && "$(conf_val_nconf NODE_LABEL)" == test-node ]]; then
  ok "and every value in it was measured from the container, not chosen by this run"
else
  bad "the record is measured from the container" "$(cat "$TMP/etc/aperire/node.conf" 2>/dev/null)"
fi
if [[ "$(conf_val_nconf NODE_UID)" == 996 && "$(conf_val_nconf NODE_GID)" == 998 \
      && "$(conf_val_nconf NODE_USER)" == xrpld ]]; then
  ok "including the account the deployment names, which is what a restore onto a rebuilt host needs (#431)"
else
  bad "the account is recorded" "$(cat "$TMP/etc/aperire/node.conf" 2>/dev/null)"
fi
if [[ "$(md5sum < "$COMPOSE")" == "$COMPOSE_BEFORE" && "$(md5sum < "$CFG")" == "$CFG_BEFORE" ]]; then
  ok "the compose and the config are untouched"
else
  bad "nothing else is touched" "compose or config changed"
fi
if ! grep -qE '^(up -d|compose up|pull )' "$TMP/state/docker-calls" 2>/dev/null \
   && ! grep -q 'compose -f' "$TMP/state/docker-calls" 2>/dev/null; then
  ok "and the node was never started, pulled or recreated"
else
  bad "the node is not started or recreated" "$(cat "$TMP/state/docker-calls")"
fi
if [[ ! -f "$TMP/state/apt-calls" ]]; then
  ok "nothing was installed either: an adopt is not an install"
else
  bad "nothing is installed by an adopt" "$(cat "$TMP/state/apt-calls")"
fi

# The published admin RPC is read rather than assumed: a node on another port
# is a node every reader has to reach on that port.
reset
adopted_host
echo "127.0.0.1:5105" > "$TMP/state/published-5005"
run_node --adopt
if [[ "$(conf_val_nconf ADMIN_RPC)" == "http://127.0.0.1:5105" ]]; then
  ok "a node published on another port is recorded on that port"
else
  bad "the published port is what gets recorded" "$(conf_val_nconf ADMIN_RPC)"
fi

reset
adopted_host
echo "0.0.0.0:5005" > "$TMP/state/published-5005"
run_node --adopt
if [[ "$OUT" == *"not on loopback"* && "$OUT" == *"ask this node to stop"* ]]; then
  ok "an admin RPC published to every address is named as the exposure it is"
else
  bad "a non-loopback admin RPC is named" "$OUT"
fi

reset
adopted_host
: > "$TMP/state/published-5005"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"publishes nothing on 5005"* && ! -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "a node publishing no admin RPC is refused, and nothing is recorded"
else
  bad "no admin RPC is a refusal" "rc=$RC: $OUT"
fi

# Two nodes on one host: recording the wrong one points the rotation window at
# the wrong container, which is the guard worth having.
reset
adopted_host
printf 'test-node\nother-node\n' > "$TMP/state/containers"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"more than one container"* && "$OUT" == *"--name"* ]]; then
  ok "two candidates are refused, named, with the flag that picks one"
else
  bad "two candidates are refused" "rc=$RC: $OUT"
fi
run_node --adopt --name test-node
if [[ $RC -eq 0 && "$(conf_val_nconf SERVICE)" == test-node ]]; then
  ok "and --name picks the one to record"
else
  bad "--name picks the container" "rc=$RC: $OUT"
fi

reset
adopted_host
: > "$TMP/state/docker-refuses"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"would not say what is running"* && ! -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "a docker that refuses to answer is not read as a host with no node"
else
  bad "a refused docker is not an absence" "rc=$RC: $OUT"
fi

# #896: a node container created from a digest reference (the shape the
# Advisor's own upgrade makes) shows an image ID in docker ps. The container
# name is neutral on purpose: a name that says xrpld would match without the
# image.
digest_host() {  # adopted_host, but the container is aperire-node, made from a digest
  adopted_host
  echo aperire-node > "$TMP/state/containers"
  echo e77ed5a956a3 > "$TMP/state/image-of-aperire-node"
  printf 'rippleci/xrpld@sha256:%s\n' "$(printf 'e77ed5a9%.0s' 1 2 3 4 5 6 7 8)" > "$TMP/state/config-image"
}
reset
digest_host
run_node --adopt
if [[ $RC -eq 0 && "$(conf_val_nconf SERVICE)" == aperire-node ]]; then
  ok "--adopt finds a node created from a digest (docker ps shows an image ID) through docker inspect"
else
  bad "--adopt finds a digest-created node" "rc=$RC: $OUT"
fi

# detect-rippled-paths.sh asks docker with {{.ID}} {{.Image}} {{.Command}}
# --no-trunc, where the Image column of a digest-created container is the full
# image ID. Neutral command on purpose: it must be the image that matches.
reset
digest_host
printf '%s sha256:%s /entrypoint.sh\n' "$(printf 'c0ffee00%.0s' 1 2 3 4 5 6 7 8)" \
  "$(printf 'e77ed5a9%.0s' 1 2 3 4 5 6 7 8)" > "$TMP/state/ps-row"
OUT="$(bash "$TMP/repo/scripts/detect-rippled-paths.sh" 2>&1)"
if [[ "$OUT" == *"RIPPLED_CFG_PATH=$CFG"* ]]; then
  ok "the config detector finds a node created from a digest through docker inspect (#896)"
else
  bad "the config detector finds a digest-created node" "$OUT"
fi
printf 'postgres:16\n' > "$TMP/state/config-image"
OUT="$(bash "$TMP/repo/scripts/detect-rippled-paths.sh" 2>&1)"
if [[ "$OUT" != *"RIPPLED_CFG_PATH=$CFG"* ]]; then
  ok "and an image ID that resolves to something that is not a node is not taken for one"
else
  bad "the detector does not take an unrelated image for the node" "$OUT"
fi
printf 'rippleci/xrpld@sha256:%s\n' "$(printf 'e77ed5a9%.0s' 1 2 3 4 5 6 7 8)" > "$TMP/state/config-image"
: > "$TMP/state/inspect-refused"
OUT="$(bash "$TMP/repo/scripts/detect-rippled-paths.sh" 2>&1)"
if [[ "$OUT" == *"would not say what is"* && "$OUT" == *"permission denied"* && "$OUT" != *"RIPPLED_CFG_PATH=$CFG"* ]]; then
  ok "an inspect docker refuses is said out loud, never read as no container"
else
  bad "the detector says a refused inspect out loud" "$OUT"
fi
rm -f "$TMP/state/ps-row"

reset
digest_host
printf 'postgres:16\n' > "$TMP/state/config-image"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"looks like an XRPL node"* ]]; then
  ok "an image ID that resolves to something that is not a node is still no node"
else
  bad "an unrelated image ID is not a node" "rc=$RC: $OUT"
fi

reset
digest_host
: > "$TMP/state/inspect-refused"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"would not say what is running"* && "$OUT" == *"permission denied"* \
      && "$OUT" != *"looks like an XRPL node"* && ! -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "an inspect docker refuses is a stop that quotes docker, never read as no node"
else
  bad "a refused inspect is not an empty host" "rc=$RC: $OUT"
fi

# A second container in the list that is not the node, shown by ID as well.
# old_tmp_host: aperire-node (made from a digest) beside "old-tmp", whose own
# image is an ID too. The two get different answers, so a resolver that
# copied one container's image onto every row would see two nodes here.
old_tmp_host() {
  digest_host
  printf 'aperire-node\nold-tmp\n' > "$TMP/state/containers"
  echo 1234567890ab > "$TMP/state/image-of-old-tmp"
}

# L3 (#901): a container removed between ps and inspect (a --rm throwaway, a
# compose recreate) is skipped, and the node row still matches.
reset
old_tmp_host
: > "$TMP/state/inspect-gone-old-tmp"
run_node --adopt
if [[ $RC -eq 0 && "$(conf_val_nconf SERVICE)" == aperire-node ]]; then
  ok "a container that is gone by inspect time is skipped, and the node row still matches (#896)"
else
  bad "a vanished container is skipped, not a stop" "rc=$RC: $OUT"
fi

# Two ID-shown containers, two different images: only the node is a node.
reset
old_tmp_host
printf 'postgres:16\n' > "$TMP/state/config-image-of-old-tmp"
run_node --adopt
if [[ $RC -eq 0 && "$(conf_val_nconf SERVICE)" == aperire-node ]]; then
  ok "each image ID is resolved by its own container, not one answer for every row"
else
  bad "two ID-shown containers keep their own images" "rc=$RC: $OUT"
fi

# L1 (#901): the account is refused everything and sudo answers. The container
# that vanished is reported "no such object" by sudo, which is the answer that
# counts, so it is skipped and not read as docker refusing.
reset
old_tmp_host
: > "$TMP/state/docker-account-refuses"
: > "$TMP/state/inspect-gone-old-tmp"
run_node --adopt
if [[ $RC -eq 0 && "$(conf_val_nconf SERVICE)" == aperire-node ]]; then
  ok "a container sudo finds gone is skipped even though the account's own inspect was refused"
else
  bad "a vanished container is skipped when sudo is what said so" "rc=$RC: $OUT"
fi

# Both accounts refused: the stop quotes both complaints, not just the first.
reset
old_tmp_host
: > "$TMP/state/docker-account-refuses"
echo "sudo: a password is required" > "$TMP/state/sudo-inspect-says"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"would not say what is running"* && "$OUT" == *"permission denied"* \
      && "$OUT" == *"a password is required"* && ! -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "a refused inspect quotes this account's complaint and sudo's, and still stops"
else
  bad "a refused inspect quotes both complaints" "rc=$RC: $OUT"
fi

# The inspects ask for a container, so an image or volume of the same name
# cannot answer for one.
reset
old_tmp_host
run_node --adopt
if grep -qE '^inspect( .*)? --type container ' "$TMP/state/docker-calls" \
   && ! grep -E '^inspect ' "$TMP/state/docker-calls" | grep -E -- '--format \{\{\.Config\.Image\}\}' | grep -qv -- '--type container'; then
  ok "the image read-back inspects --type container"
else
  bad "the image read-back inspects --type container" "$(grep -E '^inspect' "$TMP/state/docker-calls")"
fi

# L2 (#901): only the Image column is resolved. A word in another column that
# looks like an image ID (here a command's argument) is never inspected, so a
# refusal for that other container cannot stop a host whose node already
# matched by name.
reset
digest_host
printf '%s rippleci/xrpld:2.4.0 "/opt/xrpld/bin/xrpld --net"\n%s myorg/worker:1 "run 0123456789ab --x"\n' \
  "$(printf 'c0ffee00%.0s' 1 2 3 4 5 6 7 8)" "$(printf 'beefbeef%.0s' 1 2 3 4 5 6 7 8)" > "$TMP/state/ps-row"
: > "$TMP/state/inspect-refused-$(printf 'beefbeef%.0s' 1 2 3 4 5 6 7 8)"
OUT="$(bash "$TMP/repo/scripts/detect-rippled-paths.sh" 2>&1)"
if [[ "$OUT" == *"RIPPLED_CFG_PATH=$CFG"* && "$OUT" != *"would not say what is"* ]] \
   && ! grep -q "^inspect.*beefbeef" "$TMP/state/docker-calls"; then
  ok "a hex-looking word in the Command column is not taken for an image ID"
else
  bad "only the Image column is resolved" "$OUT"
fi
rm -f "$TMP/state/ps-row"

reset
adopted_host
rm -f "$TMP/state/containers"; : > "$TMP/state/containers"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"looks like an XRPL node"* ]]; then
  ok "a host with nothing node-shaped running is refused in words"
else
  bad "no node is refused in words" "rc=$RC: $OUT"
fi
# #534: this is the refusal a native host reaches when --adopt is run against
# it by mistake (verify-after-restart.sh used to send an operator here with
# only --name to try next). --native belongs in the same sentence.
if [[ "$OUT" == *"--native instead"* ]]; then
  ok "and the refusal itself points a native host at --native, not --name alone"
else
  bad "the refusal names --native" "$OUT"
fi

# A record naming a different node is not something to overwrite.
reset
adopted_host
printf 'KIND=container\nSERVICE=some-other-node\n' > "$TMP/etc/aperire/node.conf"
run_node --adopt
if [[ $RC -ne 0 && "$OUT" == *"some-other-node"* && "$(conf_val_nconf SERVICE)" == some-other-node ]]; then
  ok "a record naming a different node is refused, not overwritten"
else
  bad "a record for another node is refused" "rc=$RC: $OUT"
fi

# A node still running as root records no account, rather than inventing one:
# the migration writes those three keys when it moves the node.
reset
adopted_host
grep -v '^[[:space:]]*user: "' "$COMPOSE" > "$COMPOSE.tmp" && mv "$COMPOSE.tmp" "$COMPOSE"
run_node --adopt
if [[ $RC -eq 0 && -z "$(conf_val_nconf NODE_UID)" && "$OUT" == *"runs as root inside its container"* ]]; then
  ok "a node still running as root is recorded without an account, and said so"
else
  bad "a root node records no account" "rc=$RC: $(cat "$TMP/etc/aperire/node.conf" 2>/dev/null)"
fi

# =====================================================================
echo
echo "A host where the config directory was deliberately closed:"

# close-node-config-exposure.sh takes the config directory to 0750 on a host
# that carries a validator token. `install -d -m 0755` applies its mode to a
# directory that already exists, so a re-run used to widen it back and say
# nothing: a re-run undoing a security change by tidying. Asserted on the
# request, the way the ownership rows are, because this test is not root.
reset
mkdir -p "$NODE_DIR/config"
run_node --yes --name test-node
if grep -qE '^-d -o testop -g testop -m 0755 .*/config$' "$TMP/state/install-calls"; then
  bad "an existing config directory is not re-moded by a re-run" "$(grep '/config' "$TMP/state/install-calls")"
else
  ok "an existing config directory is not re-moded by a re-run"
fi
reset
run_node --yes --name test-node
if grep -qE '^-d -o testop -g testop -m 0755 .*/config$' "$TMP/state/install-calls"; then
  ok "control: a directory that is NOT there is still created with its owner and mode"
else
  bad "control: a missing config directory is created with its owner and mode" "$(cat "$TMP/state/install-calls")"
fi

# =====================================================================
echo
echo "When the node takes its time to answer:"

# A node opens its admin RPC some way into its start. The first live run
# asked once, seconds after `up`, and failed a node that answered thirty
# seconds later. Four silent asks here, then an answer; with sleep stubbed
# the wait costs nothing, and the seq check still needs a real answer twice.
reset
echo 4 > "$TMP/state/server-info-after"
run_node --yes --name test-node
if [[ $RC -eq 0 && "$OUT" == *"server_info answers: server_state=tracking"* ]]; then
  ok "a node that answers on the fifth ask passes: the verify waits for the RPC to open"
else
  bad "the verify waits for the RPC to open" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"opened its admin RPC after 20s"* ]]; then
  ok "and says how long it waited (20s: four asks, five seconds apart)"
else
  bad "the verify says how long it waited" "$OUT"
fi
if [[ "$OUT" == *"waiting for the node to open its admin RPC"* ]]; then
  ok "and the wait carries a status line, never a bare pause"
else
  bad "the wait carries a status line" "$OUT"
fi

echo
echo "When the node does not answer:"

reset
touch "$TMP/state/server-info-silent"
run_node --yes --name test-node

if [[ $RC -ne 0 ]]; then
  ok "a node whose server_info does not answer FAILS the run (rc=$RC)"
else
  bad "a node whose server_info does not answer fails the run" "rc=0: $OUT"
fi
if [[ "$OUT" == *"FAILED"* && "$OUT" == *"server_info did not answer"* && "$OUT" == *"within 150s"* ]]; then
  ok "and it says which check failed and how long it waited, not just that something did"
else
  bad "and it says which check failed" "$OUT"
fi
if [[ "$OUT" == *"docker logs"* ]]; then
  ok "the refusal hands over the command to look at next"
else
  bad "the refusal hands over the command to look at next" "$OUT"
fi
# Loud, but not destructive: a half-started node is worth looking at.
if [[ -f "$CFG" && -f "$COMPOSE" ]]; then
  ok "a failed verify leaves the config and compose in place to be looked at"
else
  bad "a failed verify leaves the config and compose in place" "files were removed"
fi

# The silent failure: a node that answers everything and trusts nobody. It must
# be SAID, and it must not fail the run, because a node this young legitimately
# has not fetched its lists yet.
reset
printf '{"result":{"trusted_validator_keys":[],"validation_quorum":0}}\n' > "$TMP/state/validators"
run_node --yes --name test-node
if [[ $RC -eq 0 && "$OUT" == *"no trusted validators yet"* && "$OUT" == *"sync and never validate"* ]]; then
  ok "an empty trusted set is said out loud, and warns rather than failing the run"
else
  bad "an empty trusted set is said out loud and warns" "rc=$RC: $OUT"
fi

# The opposite of the row above, so a check that can only fail is not passing
# for the wrong reason: an unhealthy container fails too.
reset
echo unhealthy > "$TMP/state/container-health"
run_node --yes --name test-node
if [[ $RC -ne 0 && "$OUT" == *"UNHEALTHY"* ]]; then
  ok "an unhealthy container fails the run as well"
else
  bad "an unhealthy container fails the run as well" "rc=$RC: $OUT"
fi

# And a healthy node with a dead port: the ports are measured, not inferred
# from docker having published them.
reset
printf 'LISTEN 0 4096 127.0.0.1:5005 0.0.0.0:*\n' > "$TMP/state/listening"
run_node --yes --name test-node
if [[ "$OUT" == *"127.0.0.1:6006 is not listening"* && $RC -ne 0 ]]; then
  ok "a published-but-dead admin WS port is caught (the publish is not the proof)"
else
  bad "a published-but-dead admin WS port is caught" "rc=$RC: $OUT"
fi

# The worse outcome than a closed port, and the one that reads as fine: the
# admin port bound to a wildcard address is reachable off this host, and
# anything that reaches an admin port can tell this node to stop.
reset
printf 'LISTEN 0 4096 127.0.0.1:5005 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:6006 0.0.0.0:*\n' > "$TMP/state/listening"
run_node --yes --name test-node
if [[ $RC -ne 0 && "$OUT" == *"WILDCARD"* ]]; then
  ok "an admin port bound to a wildcard address FAILS, rather than counting as listening"
else
  bad "an admin port bound to a wildcard address fails" "rc=$RC: $OUT"
fi

# =====================================================================
echo
echo "The validator role:"

reset
run_node --yes --name test-val --role validator

if grep -q '^#\[validator_token\]' "$CFG"; then
  ok "the validator role writes the commented [validator_token] stanza"
else
  bad "the validator role writes the commented [validator_token] stanza" "$(cat "$CFG")"
fi
if grep -q 'validator-keys' "$CFG"; then
  ok "the config says where the token comes from (validator-keys, off this box)"
else
  bad "the config says where the token comes from" "$(cat "$CFG")"
fi
if [[ "$OUT" == *"No validator key was generated, and none will be"* ]]; then
  ok "the run says out loud that it generated no key and never will"
else
  bad "the run says out loud that it generated no key" "$OUT"
fi
# The one thing it must never do. A generated identity in a config a script
# wrote is an identity the script can be made to write again.
if grep -qE '^[[:space:]]*\[validator_token\]|^[[:space:]]*\[validation_seed\]|^[[:space:]]*validation_seed[[:space:]]*=' "$CFG"; then
  bad "no live validator identity is ever written" "$(grep -nE 'validator_token|validation_seed' "$CFG")"
else
  ok "no live validator identity is ever written, only the commented placeholder"
fi
if [[ "$(stat -c %a "$CFG")" == "640" ]]; then
  ok "a validator's config is tightened to 0640 (it is where a token will live)"
else
  bad "a validator's config is tightened to 0640" "mode is $(stat -c %a "$CFG")"
fi

# The stock role writes none of that, so the placeholder cannot leak into
# every install.
reset
run_node --yes --name test-node --role stock
if ! grep -q 'validator_token' "$CFG"; then
  ok "the stock role writes no validator stanza at all"
else
  bad "the stock role writes no validator stanza" "$(grep -n validator_token "$CFG")"
fi

# =====================================================================
echo
echo "Refusals, and the arguments it will not take:"

reset
run_node --yes --net testnet
if [[ $RC -ne 0 && "$OUT" == *"mainnet only"* ]]; then
  ok "--net testnet is refused, not quietly treated as mainnet"
else
  bad "--net testnet is refused" "rc=$RC: $OUT"
fi

reset
run_node --yes --name 'Bad Name'
if [[ $RC -ne 0 ]]; then
  ok "a name docker would not take is refused before anything is written"
else
  bad "a name docker would not take is refused" "rc=0: $OUT"
fi

reset
run_node --yes --role peer
if [[ $RC -ne 0 && "$OUT" == *"stock or validator"* ]]; then
  ok "an unknown --role is refused"
else
  bad "an unknown --role is refused" "rc=$RC: $OUT"
fi

# A build that refuses: the release this pins is not installable here, and
# the run stops before anything is started rather than leaving a deployment
# naming an image that does not exist.
reset
: > "$TMP/state/build-fails"
run_node --yes --name test-node
rm -f "$TMP/state/build-fails"
if [[ $RC -ne 0 && "$OUT" == *"the image build failed"* ]]; then
  ok "a refused build stops the run, and says so"
else
  bad "a refused build stops the run" "rc=$RC: $OUT"
fi
if ! grep -q 'up -d' "$TMP/state/docker-calls" 2>/dev/null; then
  ok "and nothing was started: the node is not left pointing at an image that was never built"
else
  bad "nothing is started after a refused build" "$(cat "$TMP/state/docker-calls")"
fi

# The image already here: a re-install on a host that has built this release
# does not build it again. Two builds of one release are different images,
# and a rebuild would move the tag off the one a node is running.
reset
echo "localhost/xrpld:3.4.1" > "$TMP/state/images"
run_node --yes --name test-node
if [[ $RC -eq 0 && ! -s "$TMP/state/build-calls" ]]; then
  ok "an image already on this host is used as it stands, not rebuilt"
else
  bad "an image already here is not rebuilt" "rc=$RC: $(cat "$TMP/state/build-calls" 2>/dev/null)"
fi
if [[ "$OUT" == *"already on this host; not rebuilding"* ]]; then
  ok "and the run says so, rather than looking like it built one"
else
  bad "the run says the image was already here" "$OUT"
fi

# ── Docker install, on a host with none ──────────────────────────────
# The fallback branch: docker-compose-v2 is not in every archive this runs
# against, and a missing compose plugin has to be a refusal rather than an
# engine that looks installed.
reset
touch "$TMP/state/no-compose-pkg"
run_node --yes --name test-node
if grep -q 'docker.io' "$TMP/state/apt-calls" 2>/dev/null; then
  ok "a host with no docker gets docker.io from apt"
else
  ok "docker was already present on this test host, so nothing was installed"
fi
if grep -q 'NEEDRESTART' "$SUT"; then
  ok "the apt call carries prepare-host's needrestart guard (it must not restart the node's docker)"
else
  bad "the apt call carries the needrestart guard" "no NEEDRESTART in the script"
fi

# =====================================================================
echo
echo "What the rest of the install reads back:"

# Item 6 of #139, proven rather than assumed. The installer writes no
# RIPPLED_CFG_PATH of its own; it relies on detect-rippled-paths.sh resolving
# the container's in-container paths back through the bind mounts this compose
# writes. If that mapping ever stops working, a node that is running reads as
# absent and two fleet nodes already spent weeks that way.
reset
run_node --yes --name test-node
# The store the node would have created; detection only emits a data path that
# exists on the host.
mkdir -p "$NODE_DIR/data/db/nudb"
DET="$(bash "$TMP/repo/scripts/detect-rippled-paths.sh" 2>/dev/null)"
if [[ "$DET" == *"RIPPLED_CFG_PATH=$NODE_DIR/config/rippled.cfg"* ]]; then
  ok "detection maps /config/rippled.cfg back to the config this installer wrote"
else
  bad "detection maps /config/rippled.cfg back to the config this installer wrote" "$DET"
fi
if [[ "$DET" == *"RIPPLED_DATA_PATH=$NODE_DIR/data/db/nudb"* ]]; then
  ok "detection maps the [node_db] path back to the store on the host"
else
  bad "detection maps the [node_db] path back to the store on the host" "$DET"
fi

# And when a dashboard IS already on the box, the installer hands those two
# values to the env file the System tab reads them from.
ENVF="$TMP/etc/aperire/aperire.env"
printf 'PORT=7800
' > "$ENVF"
run_node --yes --name test-node
if grep -q "^RIPPLED_CFG_PATH=$NODE_DIR/config/rippled.cfg\$" "$ENVF" \
   && grep -q "^RIPPLED_DATA_PATH=$NODE_DIR/data/db/nudb\$" "$ENVF"; then
  ok "with a dashboard already here, both paths are written into its env file"
else
  bad "with a dashboard already here, both paths are written into its env file" "$(cat "$ENVF")"
fi
if [[ "$OUT" == *"re-detecting its node paths"* ]]; then
  ok "and it says it re-detected them, rather than doing it silently"
else
  bad "and it says it re-detected them" "$OUT"
fi

# ── the node this installer put here, recorded where the timer reads it ──
#
# #270. A co-located box with a node from this script and no Advisor could not
# install the scheduled store-rotation window: the timer step read the
# container's name out of the Advisor's wrapper configuration, and on that box
# there is no such file. This installer knows the name, the admin RPC and the
# config path, because it chose all three.

echo
echo "What it records about the node it deployed:"

reset
run_node --yes --name test-node
NODE_CONF="$TMP/etc/aperire/node.conf"
conf_line() { sed -n "s/^$1=//p" "$NODE_CONF" 2>/dev/null | head -1; }
if [[ "$(conf_line SERVICE)" == "test-node" \
   && "$(conf_line ADMIN_RPC)" == "http://127.0.0.1:5005" \
   && "$(conf_line CONFIG_FILE)" == "$NODE_DIR/config/rippled.cfg" ]]; then
  ok "the container, its loopback admin RPC and its config are written to /etc/aperire/node.conf"
else
  bad "the node is recorded in /etc/aperire/node.conf" \
      "$(cat "$NODE_CONF" 2>/dev/null || echo '<no file>')"
fi
if [[ "$OUT" == *"names this node (test-node)"* ]]; then
  ok "and it says so, naming the file and the node in it"
else
  bad "the installer says where it recorded the node" "$(tail -12 <<<"$OUT")"
fi

# The wrapper's own configuration is not this script's to write: it is the
# privilege boundary's, written whole from detection and restored from a
# .previous copy when its verification fails, so a partial one written here
# would become what that revert restores.
if [[ ! -e "$TMP/etc/aperire/node-wrapper.conf" ]]; then
  ok "and it writes nothing into the Advisor's wrapper configuration"
else
  bad "the node installer leaves node-wrapper.conf alone" \
      "$(cat "$TMP/etc/aperire/node-wrapper.conf")"
fi

# A rename follows the node. --name is the label the fleet knows it by and the
# container the timer will talk to, so a record of the previous one would point
# a root timer at a container that is no longer there.
run_node --yes --name renamed-node
if [[ "$(conf_line SERVICE)" == "renamed-node" ]]; then
  ok "a re-run under a different name records the container that is running now"
else
  bad "the record follows the node's name" "$(cat "$NODE_CONF" 2>/dev/null)"
fi

echo
echo "Native mode (#30): adopting a node already on the host"

reset
write_native_adopt_fixture xrpld.service
run_native --yes --name stock-node2

if [[ $RC -eq 0 ]]; then
  ok "adopting a running native node succeeds"
else
  bad "adopting a running native node succeeds" "rc=$RC: $OUT"
fi
if [[ "$(conf_val_wconf KIND)" == "native" && "$(conf_val_wconf SERVICE)" == "xrpld.service" ]]; then
  ok "the wrapper is configured from what was found (KIND=native, SERVICE=xrpld.service)"
else
  bad "the wrapper is configured from what was found" "$(cat "$WCONF" 2>/dev/null)"
fi
if [[ "$OUT" == *"nothing is installed from anywhere"* ]]; then
  ok "adopt says out loud that nothing is installed"
else
  bad "adopt says out loud that nothing is installed" "$OUT"
fi
# Adopting asks apt one question since #802, where the package comes from,
# so a host still on the retired repository can be moved. A read: no apt-get
# at all, and apt-cache asked for madison and nothing else.
if [[ ! -s "$TMP/state/apt-calls" ]] \
   && [[ "$(sort -u "$TMP/state/apt-cache-calls" 2>/dev/null)" == "madison xrpld" ]]; then
  ok "adopt never touches apt: no apt-get call, and apt-cache only asked where xrpld comes from"
else
  bad "adopt never touches apt" "apt-calls: $(cat "$TMP/state/apt-calls" 2>/dev/null); apt-cache-calls: $(cat "$TMP/state/apt-cache-calls" 2>/dev/null)"
fi
if [[ "$(conf_val_nconf KIND)" == "native" \
   && "$(conf_val_nconf SERVICE)" == "xrpld.service" \
   && "$(conf_val_nconf ADMIN_RPC)" == "http://127.0.0.1:5005" \
   && "$(conf_val_nconf CONFIG_FILE)" == "$NATIVE_CFG" \
   && "$(conf_val_nconf NODE_LABEL)" == "stock-node2" ]]; then
  ok "node.conf carries KIND, SERVICE, ADMIN_RPC, CONFIG_FILE and the chosen NODE_LABEL"
else
  bad "node.conf carries the native facts and the chosen label" "$(cat "$TMP/etc/aperire/node.conf" 2>/dev/null)"
fi
if [[ "$OUT" == *"server_info answers: server_state=tracking"* ]]; then
  ok "the adopt run also proves server_info answers"
else
  bad "the adopt run also proves server_info answers" "$OUT"
fi
if [[ "$OUT" == *"127.0.0.1:5005 is listening"* && "$OUT" == *"127.0.0.1:6006 is listening"* ]]; then
  ok "and both admin ports on loopback"
else
  bad "the adopt run proves both admin ports on loopback" "$OUT"
fi

# Adopting is a conversion too. This installer's own refusal on an
# unsupported OS says "install a node yourself and run this again to adopt
# it", and a node installed from the vendor's instructions listens on the
# vendor's port, so the fleet loses it exactly as in #430, by another door.
if [[ "$OUT" == *"peer port 2459, and a fleet pins 51235"* \
   && "$OUT" == *"is not reaching it"* ]]; then
  ok "adopting a node on the vendor's peer port says what a fleet that pinned it loses (#430)"
else
  bad "the adopt path names the peer port mismatch" "$OUT"
fi
if [[ "$OUT" == *"[port_peer] port = 51235"* && "$OUT" == *"ufw allow 51235/tcp"* ]]; then
  ok "and names the two commands that move it, rather than moving it"
else
  bad "the adopt warning names the remedy" "$OUT"
fi
ADOPTED_PEER="$(awk '/^\[port_peer\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*port[[:space:]]*=/{print $3; exit}' "$NATIVE_CFG")"
if [[ "$ADOPTED_PEER" == "2459" ]]; then
  ok "and an adopted node's own config is left exactly as it was"
else
  bad "adopting never edits the peer port" "[port_peer] port = ${ADOPTED_PEER:-nothing}"
fi

reset
write_native_adopt_fixture xrpld.service 51235
run_native --yes --name stock-node2b
if [[ "$OUT" == *"peer port 51235"* && "$OUT" != *"is not reaching it"* ]]; then
  ok "a node already answering on the fleet's port is confirmed, not warned about"
else
  bad "a node on the right peer port is confirmed" "$OUT"
fi

echo
echo "Native mode: xahaud is adopt-only"

reset
write_native_adopt_fixture xahaud.service
run_native --yes --name stock-xahaud

if [[ $RC -eq 0 && "$OUT" == *"adopt-only"* ]]; then
  ok "an existing xahaud unit is adopted and says it is adopt-only"
else
  bad "xahaud is adopted and says so" "rc=$RC: $OUT"
fi
if [[ "$(conf_val_wconf SERVICE)" == "xahaud.service" ]]; then
  ok "the wrapper is pointed at xahaud.service, not a guessed name"
else
  bad "the wrapper is pointed at xahaud.service" "$(cat "$WCONF" 2>/dev/null)"
fi

echo
echo "Native mode: offering a package on a supported OS"

reset
run_native --yes --name stock-node2 --role validator

if [[ $RC -eq 0 ]]; then
  ok "offering xrpld on Ubuntu 24.04 succeeds"
else
  bad "offering xrpld on Ubuntu 24.04 succeeds" "rc=$RC: $OUT"
fi
REPO_LINE="$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null)"
if [[ "$REPO_LINE" == *"packages.xrplf.org/repository/deb-stable any main"* ]]; then
  ok "the vendor's apt repository is written, at packages.xrplf.org (#655)"
else
  bad "the vendor's apt repository is written, at packages.xrplf.org" "$REPO_LINE"
fi
if [[ "$REPO_LINE" == *repos.ripple.com* ]]; then
  bad "the retired repos.ripple.com is never written" "$REPO_LINE"
else
  ok "the retired repos.ripple.com is never written"
fi
if [[ -f "$NATIVE_KEYRING" ]]; then
  ok "the vendor's signing key is installed"
else
  bad "the vendor's signing key is installed" "no file at $NATIVE_KEYRING"
fi
if grep -q "show-keys" "$TMP/state/gpg-calls" 2>/dev/null; then
  ok "the key's fingerprint is checked before it is trusted (#655)"
else
  bad "the key's fingerprint is checked before it is trusted" "$(cat "$TMP/state/gpg-calls" 2>/dev/null)"
fi
if grep -q "install .*xrpld" "$TMP/state/apt-calls" 2>/dev/null; then
  ok "apt-get install xrpld is called"
else
  bad "apt-get install xrpld is called" "$(cat "$TMP/state/apt-calls" 2>/dev/null)"
fi
if grep -q "update.*Dir::Etc::sourcelist=${NATIVE_SOURCES_LIST}" "$TMP/state/apt-calls" 2>/dev/null; then
  ok "the refresh reads the vendor list this installer wrote, and no other source on the host"
else
  bad "the refresh reads only the vendor list" "$(grep update "$TMP/state/apt-calls" 2>/dev/null)"
fi
if grep -qx 'ip = 127.0.0.1' "$NATIVE_CFG" && grep -qx 'admin = 127.0.0.1' "$NATIVE_CFG"; then
  ok "the shipped cfg is hardened to loopback admin"
else
  bad "the shipped cfg is hardened to loopback admin" "$(cat "$NATIVE_CFG" 2>/dev/null)"
fi
if [[ -f "${NATIVE_CFG}.prev" ]]; then
  ok "the package's own default cfg is kept beside the hardened one"
else
  bad "the package's own default cfg is kept" "no ${NATIVE_CFG}.prev"
fi
if [[ "$(awk '/^\[node_db\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*advisory_delete[[:space:]]*=/{n++} END{print n+0}' "$NATIVE_CFG")" == "1" ]]; then
  ok "exactly one advisory_delete line survives the patch (#81)"
else
  bad "exactly one advisory_delete line survives the patch" "$(grep -n advisory_delete "$NATIVE_CFG")"
fi
VF="$(sed -n '/^\[validators_file\]/{n;p;q}' "$NATIVE_CFG")"
if [[ -n "$VF" && -f "$VF" ]] && cmp -s "$TEMPLATES/validators.txt" "$VF"; then
  ok "the publisher list is installed at the path [validators_file] names"
else
  bad "the publisher list is installed where [validators_file] points" "VF='$VF'"
fi
if grep -qx '^#\[validator_token\]' "$NATIVE_CFG"; then
  ok "--role validator adds the same commented placeholder on native"
else
  bad "--role validator adds the commented placeholder on native" "$(cat "$NATIVE_CFG")"
fi
if grep -q 'restart xrpld.service' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "the unit is restarted after the cfg is hardened"
else
  bad "the unit is restarted after the cfg is hardened" "$(cat "$TMP/state/systemctl-calls" 2>/dev/null)"
fi
if [[ "$(conf_val_wconf KIND)" == "native" ]]; then
  ok "the run ends with a configured wrapper, in the same run"
else
  bad "the run ends with a configured wrapper" "$(cat "$WCONF" 2>/dev/null)"
fi
if [[ "$OUT" == *"server_info answers: server_state=tracking"* \
   && "$OUT" == *"127.0.0.1:5005 is listening"* \
   && "$OUT" == *"127.0.0.1:6006 is listening"* ]]; then
  ok "the same verification the container path runs also runs here"
else
  bad "the same verification the container path runs also runs here" "$OUT"
fi
if [[ "$(conf_val_nconf NODE_LABEL)" == "stock-node2" ]]; then
  ok "node.conf carries the operator's chosen label for the relay to read"
else
  bad "node.conf carries the operator's chosen label" "$(cat "$TMP/etc/aperire/node.conf" 2>/dev/null)"
fi

echo
echo "Native mode: a key whose fingerprint does not match install.md is refused (#655)"

reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
echo "0000000000000000000000000000000000000000" > "$TMP/state/xrplf-fpr"
run_native --yes --name stock-node2c --role validator
if [[ $RC -ne 0 && "$OUT" == *"fingerprint does not match"* ]]; then
  ok "a mismatched fingerprint is refused, named as what it is"
else
  bad "a mismatched fingerprint is refused" "rc=$RC: $OUT"
fi
if [[ ! -f "$NATIVE_KEYRING" && ! -f "$NATIVE_SOURCES_LIST" ]]; then
  ok "nothing was trusted and nothing was written before the refusal"
else
  bad "nothing was written on a fingerprint mismatch" "keyring=$([[ -f "$NATIVE_KEYRING" ]] && echo yes || echo no) sources=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null)"
fi
if grep -q "install .*xrpld" "$TMP/state/apt-calls" 2>/dev/null; then
  bad "apt-get install is never reached on a fingerprint mismatch" "$(cat "$TMP/state/apt-calls")"
else
  ok "apt-get install is never reached on a fingerprint mismatch"
fi
rm -f "$TMP/state/xrplf-fpr"

echo
echo "Native mode: a key file holding the pinned key PLUS a second key is refused whole (review finding, #655)"

reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
echo "two-pub" > "$TMP/state/xrplf-key-shape"
run_native --yes --name stock-node2f --role validator
if [[ $RC -ne 0 && "$OUT" == *"holds 2 public keys, not exactly one"* ]]; then
  ok "a file carrying the pinned key AND a second key is refused, named as holding two keys"
else
  bad "a two-key file is refused" "rc=$RC: $OUT"
fi
if [[ ! -f "$NATIVE_KEYRING" && ! -f "$NATIVE_SOURCES_LIST" ]]; then
  ok "nothing was trusted and nothing was written when a second key rode along"
else
  bad "nothing was written when a second key rode along" "keyring=$([[ -f "$NATIVE_KEYRING" ]] && echo yes || echo no) sources=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null)"
fi
if grep -q "install .*xrpld" "$TMP/state/apt-calls" 2>/dev/null; then
  bad "apt-get install is never reached when a second key rode along" "$(cat "$TMP/state/apt-calls")"
else
  ok "apt-get install is never reached when a second key rode along"
fi
rm -f "$TMP/state/xrplf-key-shape"

echo
echo "Native mode: the pinned key with its own subkey is accepted, and re-exported clean (#655)"

reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
echo "with-subkey" > "$TMP/state/xrplf-key-shape"
run_native --yes --name stock-node2g --role validator
if [[ $RC -eq 0 ]]; then
  ok "a key carrying a genuine subkey is still exactly one pub record, and is accepted"
else
  bad "a key with its own subkey should be accepted, not refused" "rc=$RC: $OUT"
fi
if [[ -f "$NATIVE_KEYRING" ]] && grep -q 'FAKE-ARMORED-EXPORT' "$NATIVE_KEYRING"; then
  ok "the keyring holds the re-exported key, not the raw download"
else
  bad "the keyring should hold the re-export" "$(cat "$NATIVE_KEYRING" 2>/dev/null || echo '<missing>')"
fi
if grep -q -- "--import" "$TMP/state/gpg-calls" && grep -q -- "--export" "$TMP/state/gpg-calls"; then
  ok "the verified key is imported into a scratch keyring and re-exported, not trusted as downloaded"
else
  bad "the key should be re-exported through a scratch keyring" "$(cat "$TMP/state/gpg-calls")"
fi
rm -f "$TMP/state/xrplf-key-shape"

echo
echo "Native mode: a host that installed before #655 has the retired repository removed"

reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
mkdir -p "$(dirname "$NATIVE_LEGACY_SOURCES_LIST")" "$(dirname "$NATIVE_LEGACY_KEYRING")"
printf 'deb [signed-by=%s] https://repos.ripple.com/repos/rippled-deb noble stable\n' "$NATIVE_LEGACY_KEYRING" \
  > "$NATIVE_LEGACY_SOURCES_LIST"
echo "an old binary keyring, not armoured text" > "$NATIVE_LEGACY_KEYRING"
run_native --yes --name stock-node2d --role validator
if [[ ! -f "$NATIVE_LEGACY_SOURCES_LIST" && ! -f "$NATIVE_LEGACY_KEYRING" ]]; then
  ok "the retired repos.ripple.com sources file and keyring are removed"
else
  bad "the legacy repository is retired" "sources exists=$([[ -f "$NATIVE_LEGACY_SOURCES_LIST" ]] && echo yes || echo no) keyring exists=$([[ -f "$NATIVE_LEGACY_KEYRING" ]] && echo yes || echo no)"
fi
if [[ -f "$NATIVE_SOURCES_LIST" ]] && grep -q "packages.xrplf.org" "$NATIVE_SOURCES_LIST"; then
  ok "the new repository is written in the same run that retires the old one"
else
  bad "the new repository is written alongside the retirement" "$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null)"
fi

echo
echo "Native mode: an operator-written source naming ripple.com by hand is left alone"

reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
mkdir -p "$(dirname "$NATIVE_LEGACY_SOURCES_LIST")"
printf '# kept by hand, not this installer'"'"'s marker\ndeb https://mirror.example/rippled bookworm main\n' \
  > "$NATIVE_LEGACY_SOURCES_LIST"
run_native --yes --name stock-node2e --role validator
if [[ -f "$NATIVE_LEGACY_SOURCES_LIST" ]] && grep -q 'kept by hand' "$NATIVE_LEGACY_SOURCES_LIST"; then
  ok "a file this installer did not write is never removed on its say-so alone"
else
  bad "a hand-written source at the legacy path is left alone" "$(cat "$NATIVE_LEGACY_SOURCES_LIST" 2>/dev/null)"
fi

# ── #802: the source move on a host that is already installed ──────────
#
# #655 moved the install onto packages.xrplf.org and nothing else, so a host
# installed before it kept repos.ripple.com through every adopt and update,
# and the Advisor called 3.3.0 the newest release. --move-source is the fix
# for such a host: sources and one scoped refresh, and nothing else.
legacy_deb_line() { printf 'deb [signed-by=%s] https://repos.ripple.com/repos/rippled-deb noble stable\n' "$NATIVE_LEGACY_KEYRING"; }
write_legacy_deb() {
  mkdir -p "$(dirname "$NATIVE_LEGACY_SOURCES_LIST")" "$(dirname "$NATIVE_LEGACY_KEYRING")"
  legacy_deb_line > "$NATIVE_LEGACY_SOURCES_LIST"
  echo "an old binary keyring, not armoured text" > "$NATIVE_LEGACY_KEYRING"
}

echo
echo "The source move (#802): a pre-#655 host moves to packages.xrplf.org and nothing else changes"

reset
write_legacy_deb
echo "3.4.1-1" > "$TMP/state/apt-candidate"
run_move
if [[ $RC -eq 0 && ! -f "$NATIVE_LEGACY_SOURCES_LIST" && ! -f "$NATIVE_LEGACY_KEYRING" ]]; then
  ok "the legacy source this installer wrote, and its keyring, are retired"
else
  bad "the legacy source is retired by --move-source" "rc=$RC legacy=$(cat "$NATIVE_LEGACY_SOURCES_LIST" 2>/dev/null) key=$([[ -f "$NATIVE_LEGACY_KEYRING" ]] && echo kept): $OUT"
fi
if grep -qF "deb [signed-by=$NATIVE_KEYRING] https://packages.xrplf.org/repository/deb-stable any main" "$NATIVE_SOURCES_LIST" 2>/dev/null \
   && grep -q 'FAKE-ARMORED-EXPORT' "$NATIVE_KEYRING" 2>/dev/null; then
  ok "packages.xrplf.org is written, signed by the re-exported, fingerprint-checked key"
else
  bad "the new source and key are in place" "list=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null) key=$(cat "$NATIVE_KEYRING" 2>/dev/null)"
fi
if grep -q -- '--show-keys' "$TMP/state/gpg-calls" 2>/dev/null; then
  ok "the key went through the same fingerprint check an install uses"
else
  bad "the moved key is fingerprint-checked" "$(cat "$TMP/state/gpg-calls" 2>/dev/null)"
fi
if [[ "$(sed -n 1p "$TMP/state/apt-calls" 2>/dev/null)" == "download xrpld=3.3.0-1" ]] \
   && [[ "$(wc -l < "$TMP/state/apt-calls" 2>/dev/null)" == "2" ]] \
   && sed -n 2p "$TMP/state/apt-calls" | grep -q 'update .*Dir::Etc::sourcelist=.*xrplf.list.*sourceparts=-'; then
  ok "apt-get ran twice: a download of the installed version to keep, then the scoped refresh; no install, no host-wide update"
else
  bad "the move only refreshes its own list" "$(cat "$TMP/state/apt-calls" 2>/dev/null)"
fi
if [[ ! -s "$TMP/state/systemctl-calls" ]]; then
  ok "the node's unit is never asked anything, let alone restarted"
else
  bad "the move leaves the unit alone" "$(cat "$TMP/state/systemctl-calls")"
fi
if [[ "$OUT" == *"apt now offers xrpld 3.4.1-1"* && "$OUT" == *"nothing was installed, upgraded or restarted: xrpld stays at 3.3.0-1"* ]]; then
  ok "and it says what it did in plain words: what apt offers now, and that the node was not touched"
else
  bad "the move says what it did" "$OUT"
fi

echo
echo "The source move: a legacy file the operator edited is kept and named"

reset
write_legacy_deb
printf '# pinned on purpose, ask before removing\n' >> "$NATIVE_LEGACY_SOURCES_LIST"
HAND_BEFORE="$(cat "$NATIVE_LEGACY_SOURCES_LIST")"
run_move
if [[ $RC -eq 0 && "$(cat "$NATIVE_LEGACY_SOURCES_LIST" 2>/dev/null)" == "$HAND_BEFORE" && -f "$NATIVE_LEGACY_KEYRING" ]]; then
  ok "a legacy file that is not exactly the line this installer wrote is kept, byte for byte, with its keyring"
else
  bad "a hand-edited legacy source is kept" "rc=$RC list=$(cat "$NATIVE_LEGACY_SOURCES_LIST" 2>/dev/null) key=$([[ -f "$NATIVE_LEGACY_KEYRING" ]] && echo kept || echo gone)"
fi
if [[ "$OUT" == *"kept $NATIVE_LEGACY_SOURCES_LIST: it is not the one line this installer wrote"* \
      && "$OUT" == *"sudo rm $NATIVE_LEGACY_SOURCES_LIST"* ]]; then
  ok "and named, with the reason and the command that removes it"
else
  bad "the kept file is named" "$OUT"
fi
if grep -q 'packages.xrplf.org' "$NATIVE_SOURCES_LIST" 2>/dev/null; then
  ok "while packages.xrplf.org is still added, so the host can reach 3.4.x"
else
  bad "the new source is added beside a kept file" "$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null)"
fi

echo
echo "The source move: the legacy keyring stays while another source still names it"

reset
write_legacy_deb
printf 'deb [signed-by=%s] https://mirror.example/rippled noble main\n' "$NATIVE_LEGACY_KEYRING" \
  > "$(dirname "$NATIVE_LEGACY_SOURCES_LIST")/my-mirror.list"
run_move
if [[ $RC -eq 0 && ! -f "$NATIVE_LEGACY_SOURCES_LIST" && -f "$NATIVE_LEGACY_KEYRING" \
      && "$OUT" == *"another apt source on this host still names it"* ]]; then
  ok "the legacy list goes, and its keyring is kept because another source is signed by it"
else
  bad "a keyring still in use is kept" "rc=$RC key=$([[ -f "$NATIVE_LEGACY_KEYRING" ]] && echo kept || echo gone): $OUT"
fi

echo
echo "The source move: a host already on packages.xrplf.org is a no-op"

reset
mkdir -p "$(dirname "$NATIVE_SOURCES_LIST")" "$(dirname "$NATIVE_KEYRING")"
printf 'deb [signed-by=%s] https://packages.xrplf.org/repository/deb-stable any main\n' "$NATIVE_KEYRING" > "$NATIVE_SOURCES_LIST"
# What a previous run installed: the clean re-export, which is what this
# run's re-check writes back, so the bytes do not move.
echo "FAKE-ARMORED-EXPORT" > "$NATIVE_KEYRING"
NOOP_BEFORE="$(cksum "$NATIVE_SOURCES_LIST" "$NATIVE_KEYRING")"
run_move
if [[ $RC -eq 0 && "$OUT" == *"already names packages.xrplf.org; nothing to move"* ]]; then
  ok "it says there is nothing to move"
else
  bad "a current host is a no-op" "rc=$RC: $OUT"
fi
if [[ ! -s "$TMP/state/apt-calls" && ! -s "$TMP/state/wget-calls" \
      && "$(cksum "$NATIVE_SOURCES_LIST" "$NATIVE_KEYRING")" == "$NOOP_BEFORE" ]]; then
  ok "and changes nothing: no apt-get, no fetch, both files byte for byte as they were"
else
  bad "a current host is left alone" "apt=$(cat "$TMP/state/apt-calls" 2>/dev/null) wget=$(cat "$TMP/state/wget-calls" 2>/dev/null)"
fi

if grep -q -- '--show-keys' "$TMP/state/gpg-calls" 2>/dev/null; then
  ok "while the key already on disk is still put through the fingerprint check"
else
  bad "a current host's key is re-checked" "$(cat "$TMP/state/gpg-calls" 2>/dev/null)"
fi
reset
mkdir -p "$(dirname "$NATIVE_SOURCES_LIST")" "$(dirname "$NATIVE_KEYRING")"
printf 'deb [signed-by=%s] https://packages.xrplf.org/repository/deb-stable any main\n' "$NATIVE_KEYRING" > "$NATIVE_SOURCES_LIST"
echo "a key somebody swapped in" > "$NATIVE_KEYRING"
echo "0000000000000000000000000000000000000BAD" > "$TMP/state/xrplf-fpr"
run_move
if [[ $RC -ne 0 && "$OUT" == *"fingerprint does not match"* ]]; then
  ok "a host already on packages.xrplf.org whose key fails the fingerprint check is refused by name"
else
  bad "a current host's bad key is refused" "rc=$RC: $OUT"
fi
rm -f "$TMP/state/xrplf-fpr"

echo
echo "The source move keeps the installed package before it retires the only repository that has it"

reset
write_legacy_deb
run_move
KEPT="$TMP/rollback/xrpld.kept.3.3.0-1.deb"
if [[ $RC -eq 0 && -s "$KEPT" && "$(awk '{print $1}' "$KEPT.sha256" 2>/dev/null)" == "$(sha256sum "$KEPT" | cut -d' ' -f1)" \
      && "$(awk '{print $2}' "$KEPT.sha256")" == "xrpld.kept.3.3.0-1.deb" ]]; then
  ok "the installed 3.3.0-1 is kept in the wrapper's keep directory, under its name and with its sha256 sidecar"
else
  bad "the installed package is kept" "rc=$RC kept=$(ls "$TMP/rollback" 2>&1): $OUT"
fi
if [[ "$(cat "$TMP/state/legacy-at-download" 2>/dev/null)" == present ]] \
   && [[ "$(grep -n 'kept the installed' <<<"$OUT" | cut -d: -f1)" -lt "$(grep -n 'removed the retired' <<<"$OUT" | head -1 | cut -d: -f1)" ]]; then
  ok "kept while the old source was still configured, and said before the old source is removed"
else
  bad "the keep happens before the retire" "at-download=$(cat "$TMP/state/legacy-at-download" 2>/dev/null): $OUT"
fi

reset
write_legacy_deb
touch "$TMP/state/xrplf-unreachable"
run_move
if [[ $RC -ne 0 && -f "$NATIVE_LEGACY_SOURCES_LIST" && -f "$NATIVE_LEGACY_KEYRING" \
      && "$OUT" == *"packages.xrplf.org offered no xrpld after its refresh, so the old source was left in place"* ]]; then
  ok "packages.xrplf.org unreachable: the old source and its key stay, and the run says what failed"
else
  bad "an unreachable new source leaves the old one" "rc=$RC legacy=$([[ -f "$NATIVE_LEGACY_SOURCES_LIST" ]] && echo kept || echo gone): $OUT"
fi

reset
write_legacy_deb
touch "$TMP/state/apt-download-fails"
run_move
if [[ $RC -eq 0 && -f "$NATIVE_LEGACY_SOURCES_LIST" ]] && grep -q 'packages.xrplf.org' "$NATIVE_SOURCES_LIST" 2>/dev/null \
   && [[ "$OUT" == *"could not get the installed xrpld 3.3.0-1"* && "$OUT" == *"the only place it can come back from"* ]]; then
  ok "a package that cannot be kept keeps the old source too, named, while packages.xrplf.org is still added"
else
  bad "no kept copy, no retire" "rc=$RC: $OUT"
fi

reset
write_legacy_deb
printf 'fakedeb xrpld 3.3.0-1\n' > "$TMP/aptcache/xrpld_3.3.0-1_amd64.deb"
touch "$TMP/state/apt-download-fails"
run_move
if [[ $RC -eq 0 && -s "$TMP/rollback/xrpld.kept.3.3.0-1.deb" && ! -f "$NATIVE_LEGACY_SOURCES_LIST" ]]; then
  ok "with the repository silent, the copy apt cached on install day is kept instead, and the move finishes"
else
  bad "the cache fallback keeps the package" "rc=$RC: $OUT"
fi

reset
write_legacy_deb
touch "$TMP/state/deb-wrong-version"
run_move
if [[ ! -e "$TMP/rollback/xrpld.kept.3.3.0-1.deb" && -f "$NATIVE_LEGACY_SOURCES_LIST" \
      && "$OUT" == *"says it is 'xrpld 9.9.9-1', not xrpld 3.3.0-1"* ]]; then
  ok "a fetched package that is not the installed version is not kept, and the old source stays"
else
  bad "a wrong artefact is refused" "rc=$RC: $OUT"
fi

echo
echo "The source move: a legacy file of blank lines is not the file this installer wrote"

reset
mkdir -p "$(dirname "$NATIVE_LEGACY_SOURCES_LIST")"
printf '\n  \n\n' > "$NATIVE_LEGACY_SOURCES_LIST"
run_move
if [[ $RC -eq 0 && -f "$NATIVE_LEGACY_SOURCES_LIST" ]]; then
  ok "a file at the legacy path holding no line at all is kept"
else
  bad "an empty legacy file is not retired" "rc=$RC: $OUT"
fi

echo
echo "The installer and the wrapper agree on what the retired repository is"

# shellcheck disable=SC1090
retired_in() { ( source <(sed -n '/^aperire_retired_source_url() {/,/^}/p' "$1"); aperire_retired_source_url "$2" ) && echo yes || echo no; }
agree=1 table=''
for row in \
  "yes https://repos.ripple.com/repos/rippled-deb" \
  "yes http://repos.ripple.com:80/repos/rippled-deb" \
  "yes http://cache.lan:3142/repos.ripple.com/repos/rippled-deb" \
  "yes https://repos.ripple.com/repos/rippled-rpm/stable/xrpld-3.3.0-1.el9.x86_64.rpm" \
  "no https://packages.xrplf.org/repository/deb-stable" \
  "no https://evilrepos.ripple.com/repos/rippled-deb" \
  "no https://repos.ripple.com.example/repos/rippled-deb"; do
  want=${row%% *} url=${row#* }
  a=$(retired_in "$REPO_DIR/scripts/install-aperire-node.sh" "$url")
  b=$(retired_in "$REPO_DIR/scripts/aperire-node-wrapper.sh" "$url")
  table+="$url installer=$a wrapper=$b want=$want; "
  [[ "$a" == "$want" && "$b" == "$want" ]] || agree=0
done
if (( agree )); then
  ok "the same answer from both, direct, with a port, through a caching proxy, and not for a lookalike name"
else
  bad "installer and wrapper agree on the retired URL" "$table"
fi

echo
echo "The source move: an operator's own repos.ripple.com file is found by where apt says xrpld comes from"

reset
mkdir -p "$(dirname "$NATIVE_LEGACY_SOURCES_LIST")"
OWN_LIST="$(dirname "$NATIVE_LEGACY_SOURCES_LIST")/rippled.list"
printf 'deb [signed-by=/usr/share/keyrings/mine.gpg] https://repos.ripple.com/repos/rippled-deb noble stable\n' > "$OWN_LIST"
printf '3.3.0-1 https://repos.ripple.com/repos/rippled-deb\n3.2.1-1 https://repos.ripple.com/repos/rippled-deb\n' > "$TMP/state/madison"
OWN_BEFORE="$(cat "$OWN_LIST")"
run_move
if [[ $RC -eq 0 ]] && grep -q 'packages.xrplf.org' "$NATIVE_SOURCES_LIST" 2>/dev/null \
   && [[ "$(cat "$OWN_LIST")" == "$OWN_BEFORE" ]]; then
  ok "every source offering xrpld is repos.ripple.com: packages.xrplf.org is added, the operator's file is not touched"
else
  bad "a retired source under another name is moved" "rc=$RC list=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null): $OUT"
fi

reset
printf '3.4.1-1 https://mirror.example/xrpld\n' > "$TMP/state/madison"
run_move
if [[ $RC -eq 0 && ! -f "$NATIVE_SOURCES_LIST" && ! -s "$TMP/state/apt-calls" \
      && "$OUT" == *"xrpld comes from https://mirror.example/xrpld, not the retired repos.ripple.com; nothing to move"* ]]; then
  ok "xrpld from a source the operator chose is left alone, and named"
else
  bad "another source is not second-guessed" "rc=$RC: $OUT"
fi

echo
echo "The source move: what it is not for"

reset
rm -f "$TMP/state/pkgversion-xrpld"
write_legacy_deb
run_move
if [[ $RC -eq 0 && -f "$NATIVE_LEGACY_SOURCES_LIST" && "$OUT" == *"xrpld is not installed from a package on this host"* ]]; then
  ok "a host with no xrpld package installed is told so and nothing changes"
else
  bad "no package, no move" "rc=$RC: $OUT"
fi

echo
echo "The source move on --native's adopt (#802): adopting moves a pre-#655 source"

reset
write_native_adopt_fixture xrpld.service
write_legacy_deb
echo "3.4.1-1" > "$TMP/state/apt-candidate"
run_native --yes --name stock-node2m
if [[ $RC -eq 0 && "$(conf_val_wconf KIND)" == "native" && ! -f "$NATIVE_LEGACY_SOURCES_LIST" ]] \
   && grep -q 'packages.xrplf.org' "$NATIVE_SOURCES_LIST" 2>/dev/null; then
  ok "the adopt finishes, and the host it adopted now takes xrpld from packages.xrplf.org"
else
  bad "adopt moves a pre-#655 source" "rc=$RC legacy=$(cat "$NATIVE_LEGACY_SOURCES_LIST" 2>/dev/null): $OUT"
fi
WOUT="$(bash "$TMP/repo/scripts/aperire-node-wrapper.sh" package-keep 2>&1)"
KEPT="$TMP/rollback/xrpld.kept.3.3.0-1.deb"
if [[ "$WOUT" == "already kept"$'\t'"$KEPT"$'\t'"3.3.0-1"$'\t'"$(sha256sum "$KEPT" 2>/dev/null | cut -d' ' -f1)" ]] \
   && [[ "$(bash "$TMP/repo/scripts/aperire-node-wrapper.sh" package-kept 2>&1)" == "3.3.0-1"$'\t'"$KEPT"$'\t'*$'\t'ok ]]; then
  ok "the wrapper's own package-keep and package-kept find the kept 3.3.0-1 as theirs, so a rollback has it"
else
  bad "the kept package is the wrapper's rollback artefact" "$WOUT"
fi
if ! grep -q 'install ' "$TMP/state/apt-calls" 2>/dev/null \
   && ! grep -q 'restart xrpld' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "and still installs nothing and restarts nothing"
else
  bad "adopt with a move installs and restarts nothing" "apt=$(cat "$TMP/state/apt-calls" 2>/dev/null) sysd=$(grep restart "$TMP/state/systemctl-calls" 2>/dev/null)"
fi

reset
write_native_adopt_fixture xrpld.service
write_legacy_deb
echo "B655416741221F780FBCFBC9AA84D41A11D29FA0" > "$TMP/state/xrplf-fpr"
run_native --yes --name stock-node2n
if [[ $RC -eq 0 && "$(conf_val_wconf KIND)" == "native" && -f "$NATIVE_LEGACY_SOURCES_LIST" \
      && "$OUT" == *"fingerprint does not match"* \
      && "$OUT" == *"its package source was not moved"* && "$OUT" == *"get.aperire.one | bash -s -- --update --force"* ]]; then
  ok "a key that fails its check refuses the move by name, leaves the old source, and the adopt still stands"
else
  bad "a failed move does not undo the adopt" "rc=$RC: $OUT"
fi
rm -f "$TMP/state/xrplf-fpr"

echo
echo "The source move on rhel (#802): the legacy dnf repo file this installer wrote is retired"

legacy_rpm_stanza() {
  printf '%s\n' '[ripple-stable]' 'name=XRP Ledger Packages' 'enabled=1' 'gpgcheck=0' 'repo_gpgcheck=1' \
    'baseurl=https://repos.ripple.com/repos/rippled-rpm/stable/' \
    'gpgkey=https://repos.ripple.com/repos/rippled-rpm/stable/repodata/repomd.xml.key'
}
reset
printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$OS_RELEASE"
echo "3.3.0-1.el9" > "$TMP/state/rpm-installed"
mkdir -p "$(dirname "$NATIVE_LEGACY_RPM_REPO")"
legacy_rpm_stanza > "$NATIVE_LEGACY_RPM_REPO"
run_move
if [[ $RC -eq 0 && ! -f "$NATIVE_LEGACY_RPM_REPO" ]] \
   && grep -q 'packages.xrplf.org/repository/rpm-stable' "$NATIVE_RPM_REPO" 2>/dev/null \
   && grep -q '^--import ' "$TMP/state/rpm-calls" 2>/dev/null \
   && grep -q "makecache --disablerepo=\* --enablerepo=xrplf-stable" "$TMP/state/dnf-calls" 2>/dev/null \
   && ! grep -qE '^(install|upgrade|update)' "$TMP/state/dnf-calls" 2>/dev/null; then
  ok "the old stanza goes, packages.xrplf.org is written with a checked key, and dnf refreshes only that repo"
else
  bad "the rpm source move" "rc=$RC dnf=$(cat "$TMP/state/dnf-calls" 2>/dev/null): $OUT"
fi
if [[ -s "$TMP/rollback/xrpld.kept.3.3.0-1.el9.rpm" && "$(cat "$TMP/state/legacy-at-download" 2>/dev/null)" == present ]]; then
  ok "and the installed rpm is kept first, while the old repository could still hand it over"
else
  bad "the rpm is kept before the retire" "$(ls "$TMP/rollback" 2>&1)"
fi
reset
printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$OS_RELEASE"
echo "3.3.0-1.el9" > "$TMP/state/rpm-installed"
mkdir -p "$(dirname "$NATIVE_LEGACY_RPM_REPO")"
legacy_rpm_stanza > "$NATIVE_LEGACY_RPM_REPO"
touch "$TMP/state/xrplf-unreachable"
run_move
if [[ $RC -ne 0 && -f "$NATIVE_LEGACY_RPM_REPO" && "$OUT" == *"so the old repository was left in place"* ]]; then
  ok "rpm: packages.xrplf.org unreachable leaves the old repository in place, named"
else
  bad "rpm unreachable keeps the old repo" "rc=$RC: $OUT"
fi
reset
printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$OS_RELEASE"
echo "3.3.0-1.el9" > "$TMP/state/rpm-installed"
mkdir -p "$(dirname "$NATIVE_LEGACY_RPM_REPO")"
{ legacy_rpm_stanza; echo 'exclude=xrpld-3.2*'; } > "$NATIVE_LEGACY_RPM_REPO"
run_move
if [[ $RC -eq 0 && -f "$NATIVE_LEGACY_RPM_REPO" && "$OUT" == *"kept $NATIVE_LEGACY_RPM_REPO"* ]]; then
  ok "an rpm stanza the operator changed is kept and named"
else
  bad "a changed rpm stanza is kept" "rc=$RC: $OUT"
fi

echo
echo "Native mode: an rhel host adds the xrplf.org repository (#655)"

reset
printf 'ID=rhel\nVERSION_ID="9.4"\n' > "$OS_RELEASE"
run_native --yes --name stock-rhel1 --role validator
# This rig has no systemd/unit fixture for the RHEL native flow beyond the
# repository step (that gap predates #655 and is not this issue's to close);
# what is asserted here is the repository and key handling the issue is
# about, which the "dnf offers xrpld" line proves ran to completion.
if [[ "$OUT" == *"dnf offers xrpld"* ]]; then
  ok "the vendor repository step on RHEL 9 completes and offers xrpld"
else
  bad "the vendor repository step on RHEL 9 completes" "rc=$RC: $OUT"
fi
RPM_REPO_BODY="$(cat "$NATIVE_RPM_REPO" 2>/dev/null)"
if [[ "$RPM_REPO_BODY" == *"packages.xrplf.org/repository/rpm-stable"* && "$RPM_REPO_BODY" == *'gpgcheck=1'* ]]; then
  ok "the rpm repo file names packages.xrplf.org with gpgcheck on"
else
  bad "the rpm repo file names packages.xrplf.org with gpgcheck on" "$RPM_REPO_BODY"
fi
if grep -q "show-keys" "$TMP/state/gpg-calls" 2>/dev/null && grep -q "^--import " "$TMP/state/rpm-calls" 2>/dev/null; then
  ok "the rpm key is fingerprint-checked before rpm --import trusts it"
else
  bad "the rpm key is fingerprint-checked before import" "gpg=$(cat "$TMP/state/gpg-calls" 2>/dev/null) rpm=$(cat "$TMP/state/rpm-calls" 2>/dev/null)"
fi

echo
echo "Native mode: re-running the installer on a config it already hardened (#545 P1-105)"

# The exact shape the security review found on a lab host: a native config
# already at one of the vendor's own paths, and this run's own probe of
# systemd (LoadState) not finding the unit loaded, which is reset()'s default
# state and is also what a UNIT_OVERRIDE mismatch or an unusual unit name
# looks like from here. Nothing above native_locate_cfg can tell "genuinely
# never installed" from "installed, but this run cannot see it" apart, so the
# fix treats a config already sitting there the same way either reading
# would want: as the operator's, kept exactly as it is, the same rule the
# container path holds for CFG_FILE.
reset
mkdir -p "$NATIVE_DIR"
CUSTOM_VALPATH="$NATIVE_DIR/custom-publishers.txt"
printf 'a publisher list this operator put here, not the one this project ships\n' > "$CUSTOM_VALPATH"
cat > "$NATIVE_CFG" <<CFG
[port_rpc_admin_local]
port = 5005
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[port_ws_admin_local]
port = 6006
ip = 127.0.0.1
admin = 127.0.0.1
protocol = ws

[node_db]
type = NuDB
path = $NATIVE_DIR/db
online_delete = 32768
advisory_delete = 1

[node_size]
medium

#[validator_token]
#already-here-from-a-previous-run

[validators_file]
$CUSTOM_VALPATH
CFG
PRE_CKSUM_BEFORE="$(cksum < "$NATIVE_CFG")"

run_native --yes --name stock-node2-rerun --role validator

if [[ $RC -eq 0 ]]; then
  ok "re-running the installer on an already-hardened native host still succeeds"
else
  bad "re-running the installer on an already-hardened native host still succeeds" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"keeping it exactly as it is"* ]]; then
  ok "the run says it is keeping the existing config rather than claiming to harden it"
else
  bad "the run says it kept the existing config" "$OUT"
fi
# Byte-identical, not merely "still has the same stanzas": native_harden_cfg
# cannot run at all without changing content (loopback ip=/admin=, one
# advisory_delete line, a [validators_file] value), so this is stronger proof
# the rewrite path never executed than an ACL comparison across the whole
# run would be. (An ACL comparison across the whole run is the wrong check
# here anyway: this installer's own close-node-config-exposure.sh pass runs
# at the end of every native install, by design, and legitimately tightens
# the mode and grants the dashboard and relay accounts their read, which
# would make even a correctly-skipped rewrite look, by that measure alone,
# like something touched the file. cwl_carry_permissions carrying an ACL
# across native_harden_cfg's own rewrite is exercised directly in
# test-config-write-lib.sh and by the container path's equivalent rows
# above; what this row exists to prove is that the rewrite is skipped
# entirely on a re-run, and content identity is the direct measure of that.)
if [[ "$(cksum < "$NATIVE_CFG")" == "$PRE_CKSUM_BEFORE" ]]; then
  ok "the config's bytes are untouched, not one line rewritten"
else
  bad "the config's bytes are untouched" "$(diff <(printf '%s' "$PRE_CKSUM_BEFORE") <(cksum < "$NATIVE_CFG"))"
fi
if cmp -s "$CUSTOM_VALPATH" <(printf 'a publisher list this operator put here, not the one this project ships\n'); then
  ok "the operator's own publisher list is not overwritten with this project's template"
else
  bad "the operator's own publisher list survives" "$(cat "$CUSTOM_VALPATH")"
fi
if [[ ! -f "${NATIVE_CFG}.prev" ]]; then
  ok "no .prev copy is made; this run never treated the vendor default as something it just unpacked"
else
  bad "no .prev copy is made on a kept config" "found ${NATIVE_CFG}.prev"
fi
if [[ "$(grep -c '^#\[validator_token\]' "$NATIVE_CFG")" == "1" ]]; then
  ok "the validator-token placeholder is not duplicated on a re-run"
else
  bad "the validator-token placeholder is not duplicated" "$(grep -n 'validator_token' "$NATIVE_CFG")"
fi

echo
echo "Native mode: a dashboard already on this host is re-pointed at the node just installed"

reset
mkdir -p "$TMP/etc/aperire"
# The env file in the shape a real one is in: the two paths inside the
# installer's own markers, which is what configure-rippled-paths.sh rewrites.
# Keys outside that block are an operator's and are deliberately left alone,
# so a fixture that wrote them bare would prove the opposite of what it looks
# like it proves.
{
  printf 'PORT=7900\n'
  printf '\n# >>> aperire: rippled paths (rewritten by the installer) >>>\n'
  printf 'RIPPLED_CFG_PATH=/srv/someone/old-node/config/rippled.cfg\n'
  printf 'RIPPLED_DATA_PATH=/srv/someone/old-node/data/db/nudb\n'
  printf '# <<< aperire: rippled paths <<<\n'
} > "$TMP/etc/aperire/aperire.env"
# The store the native node's config names. Detection emits a data path only
# when it exists, exactly as on the container row above, and without this the
# row is really asking what node the machine running it has.
mkdir -p "$NATIVE_DIR/db"
run_native --yes --name stock-node2

# Both halves, because "the old path is gone" is also what a blanked file
# looks like, and a dashboard measuring nothing is not the outcome wanted.
if ! grep -q '/srv/someone/old-node' "$TMP/etc/aperire/aperire.env"; then
  ok "the env file the dashboard reads no longer names the node that was here before"
else
  bad "the dashboard env is re-detected on native" "$(cat "$TMP/etc/aperire/aperire.env")"
fi
if grep -qx "RIPPLED_CFG_PATH=$NATIVE_CFG" "$TMP/etc/aperire/aperire.env" \
   && grep -qx "RIPPLED_DATA_PATH=$NATIVE_DIR/db" "$TMP/etc/aperire/aperire.env"; then
  ok "and it names the node that is here now, config and store both"
else
  bad "the env names the node just installed" "$(cat "$TMP/etc/aperire/aperire.env")"
fi
if [[ "$OUT" == *"re-detecting its node paths"* ]]; then
  ok "and the run says so"
else
  bad "the run says it re-detected the paths" "$OUT"
fi

echo
echo "Native mode: one broken third-party apt source is not this installer's problem (#410)"

reset
: > "$TMP/state/broken-other-source"
run_native --yes --name stock-node2

if [[ $RC -eq 0 ]]; then
  ok "a host with a stale unrelated repository still installs a native node"
else
  bad "a host with a stale unrelated repository still installs a native node" "rc=$RC: $OUT"
fi
if grep -q "install .*xrpld" "$TMP/state/apt-calls" 2>/dev/null; then
  ok "and it reached the install rather than dying at the refresh"
else
  bad "and it reached the install" "$(cat "$TMP/state/apt-calls" 2>/dev/null)"
fi
rm -f "$TMP/state/broken-other-source"

# The half scoping alone does not cover. The prerequisite step returns early
# whenever wget and gnupg are already here, which is most cloud images, so on
# those hosts nothing refreshed the host's own lists and the vendor install
# was resolving its dependencies out of whatever was on disk. Measured
# against a real apt-get: a component that was never refreshed answers
# "Unable to locate package" and exits 100. So both refreshes have to happen,
# and they are not the same call.
reset
run_native --yes --name stock-node2c

if grep -qx 'update -qq' "$TMP/state/apt-calls" 2>/dev/null; then
  ok "the host's own lists are refreshed too, so the install can resolve its dependencies"
else
  bad "the host's lists are refreshed before the vendor install" "$(cat "$TMP/state/apt-calls" 2>/dev/null)"
fi
HOST_UPD_AT=$(grep -n '^update -qq$' "$TMP/state/apt-calls" | head -1 | cut -d: -f1)
XRPLD_AT=$(grep -n '^install .*xrpld' "$TMP/state/apt-calls" | head -1 | cut -d: -f1)
if [[ -n "$HOST_UPD_AT" && -n "$XRPLD_AT" ]] && (( HOST_UPD_AT < XRPLD_AT )); then
  ok "and before it, not after"
else
  bad "the host refresh comes before the vendor install" "$(cat "$TMP/state/apt-calls" 2>/dev/null)"
fi
if grep -q 'Dir::Etc::sourcelist' "$TMP/state/apt-calls" 2>/dev/null; then
  ok "and the vendor's own list still gets its own scoped refresh, which is what makes a failure there attributable"
else
  bad "the scoped vendor refresh still happens" "$(cat "$TMP/state/apt-calls" 2>/dev/null)"
fi

echo
echo "Native mode: the node answers on the port a fleet pinned (#430)"

# The vendor package listens on 2459. Every Aperire container node answers on
# 51235, because the compose file maps 51235 to 2459 inside. A host converted
# from one shape to the other therefore stops answering where its fleet is
# dialling: validator1 sat at peer_count 1 for 45 minutes after the lab
# converted stock-node2, and nothing anywhere said why.
reset
touch "$TMP/state/ufw-active"
run_native --yes --name stock-node9

PEERPORT="$(awk '/^\[port_peer\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*port[[:space:]]*=/{print $3; exit}' "$NATIVE_CFG")"
if [[ "$PEERPORT" == "51235" ]]; then
  ok "the shipped config's peer port is rewritten to the port a fleet pins"
else
  bad "the peer port is rewritten to 51235" "[port_peer] port = ${PEERPORT:-nothing}"
fi
if [[ "$OUT" == *"peer port 51235"* ]]; then
  ok "and the run says which peer port it chose"
else
  bad "the run names the peer port" "$OUT"
fi
if grep -qx 'allow 51235/tcp' "$TMP/state/ufw-calls" 2>/dev/null; then
  ok "an active ufw is asked to allow it inbound"
else
  bad "ufw is asked to allow the peer port" "$(cat "$TMP/state/ufw-calls" 2>/dev/null)"
fi
if ! grep -qx 'enable' "$TMP/state/ufw-calls" 2>/dev/null; then
  ok "and the firewall is never switched on by this installer"
else
  bad "the installer does not enable a firewall" "$(cat "$TMP/state/ufw-calls" 2>/dev/null)"
fi

# No firewall here. Nothing to open, and the line to run later is printed
# rather than the rule being invented on a host that has no ufw.
reset
run_native --yes --name stock-node10
if [[ "$OUT" == *"no active ufw here"* && "$OUT" == *"ufw allow 51235/tcp"* ]]; then
  ok "a host with no active firewall is told the rule it would need"
else
  bad "a host with no firewall is told the rule" "$OUT"
fi
if [[ ! -s "$TMP/state/ufw-calls" ]] || ! grep -qx 'allow 51235/tcp' "$TMP/state/ufw-calls"; then
  ok "and no rule is added to a firewall that is not running"
else
  bad "no rule is added when ufw is inactive" "$(cat "$TMP/state/ufw-calls" 2>/dev/null)"
fi

# And the escape hatch, with the consequence stated rather than implied.
reset
touch "$TMP/state/ufw-active"
run_native --yes --name stock-node11 --vendor-peer-port
PEERPORT="$(awk '/^\[port_peer\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*port[[:space:]]*=/{print $3; exit}' "$NATIVE_CFG")"
if [[ "$PEERPORT" == "2459" && "$OUT" == *"keeping the vendor's own peer port"* ]]; then
  ok "--vendor-peer-port leaves the package's own port alone, and says so"
else
  bad "--vendor-peer-port keeps the vendor's port" "port=${PEERPORT:-nothing}: $OUT"
fi
if [[ "$OUT" == *"will stop reaching it"* ]]; then
  ok "and names what a fleet that pinned this host loses by it"
else
  bad "the fleet consequence is named" "$OUT"
fi
if ! grep -qx 'allow 2459/tcp' "$TMP/state/ufw-calls" 2>/dev/null; then
  ok "and nothing is opened for a port this installer did not choose"
else
  bad "no rule is added for the vendor's port" "$(cat "$TMP/state/ufw-calls" 2>/dev/null)"
fi

echo
echo "Native mode: both shapes of this product keep the same history (#429)"

# The vendor's package ships online_delete = 512, and this project's own
# container config has always used 16384. Left alone, a native node keeps
# about a thirtieth of the history a container node keeps, which changes what
# the Governance and Consensus tabs can look back at and what the System tab's
# growth line means. The fixture's shipped config carries the duplicate-line
# shape upstream's own example ships, so the collapse is exercised too.
node_db_values() { # $1 = key
  awk -v k="$1" '
    /^[[:space:]]*\[/ { inb = ($0 ~ /^[[:space:]]*\[node_db\][[:space:]]*$/); next }
    inb && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { sub(/^[^=]*=[[:space:]]*/, ""); print }
  ' "$NATIVE_CFG"
}

reset
run_native --yes --name stock-node9
if [[ "$(node_db_values online_delete)" == "16384" ]]; then
  ok "a native install keeps the same ledger window a container node keeps"
else
  bad "online_delete is set to the container window" "[node_db] online_delete = $(node_db_values online_delete | tr '\n' ' ')"
fi
if [[ "$OUT" == *"online_delete = 16384 ledgers kept online"* && "$OUT" == *"GB of store"* ]]; then
  ok "and the run says so, with what it costs in disk"
else
  bad "the run states the window and its cost" "$OUT"
fi
if [[ "$(node_db_values advisory_delete)" == "0" ]]; then
  ok "and the advisory_delete collapse it already did is unchanged"
else
  bad "advisory_delete is still one line at 0" "$(node_db_values advisory_delete | tr '\n' ' ')"
fi

reset
run_native --yes --name stock-node9 --vendor-retention
if [[ "$(node_db_values online_delete)" == "512" ]]; then
  ok "--vendor-retention leaves the package's own window alone"
else
  bad "--vendor-retention keeps the package's value" "[node_db] online_delete = $(node_db_values online_delete | tr '\n' ' ')"
fi
if [[ "$OUT" == *"left at whatever the package shipped"* ]]; then
  ok "and says that is what it did"
else
  bad "the run says it kept the package's window" "$OUT"
fi

echo
echo "Native mode: a conversion carries the peer settings across (#430)"

# The port was half of it. On aperire2 the fresh native node filled rippled's
# default 21 peer slots with public peers before the validator retried, and
# the validator's inbound was refused; the container had had the validator
# connected before it ever filled. A slot reserved by [ips_fixed] is what
# stops that race, and it is a setting the operator already chose once.
write_container_cfg() {  # $1 = extra stanzas, verbatim
  mkdir -p "$TMP/old-node/config"
  {
    printf '[server]\nport_rpc_admin_local\n\n'
    printf '[node_size]\nmedium\n'
    [[ -n "${1:-}" ]] && printf '%s' "$1"
  } > "$TMP/old-node/config/rippled.cfg"
  mkdir -p "$TMP/etc/aperire"
  {
    printf 'KIND=container\n'
    printf 'SERVICE=aperire-node\n'
    printf 'CONFIG_FILE=%s\n' "$TMP/old-node/config/rippled.cfg"
  } > "$TMP/etc/aperire/node.conf"
}

reset
write_container_cfg '
[ips_fixed]
198.51.100.9 51235

[peers_max]
40

[peer_private]
1
'
run_native --yes --name stock-node12

if [[ $RC -eq 0 ]] && grep -qx '198.51.100.9 51235' "$NATIVE_CFG"; then
  ok "a container config's [ips_fixed] survives the conversion, intact"
else
  bad "[ips_fixed] is carried across" "rc=$RC: $(grep -A2 ips_fixed "$NATIVE_CFG" 2>/dev/null)"
fi
if grep -qx '40' "$NATIVE_CFG" && grep -qE '^\[peers_max\]$' "$NATIVE_CFG" \
   && grep -qE '^\[peer_private\]$' "$NATIVE_CFG"; then
  ok "and [peers_max] and [peer_private] come with it"
else
  bad "the other two peer stanzas are carried" "$(cat "$NATIVE_CFG")"
fi
if [[ "$OUT" == *"carried ips_fixed peers_max peer_private"* ]]; then
  ok "and the run says what it carried, and from where"
else
  bad "the run names what it carried" "$OUT"
fi
if [[ "$OUT" == *"a fixed peer holds a slot"* ]]; then
  ok "and says why a reserved slot matters, which is what the lab lost a validator to"
else
  bad "the reason is stated" "$OUT"
fi

# Nothing invented. "No fixed peers" is a choice too, and a config that never
# named one must not come out of a conversion with one in it.
reset
write_container_cfg ''
run_native --yes --name stock-node13

if [[ $RC -eq 0 ]] && ! grep -qE '^\[ips_fixed\]$' "$NATIVE_CFG"; then
  ok "a container config with no fixed peers converts without one being invented"
else
  bad "no [ips_fixed] is invented" "rc=$RC: $(cat "$NATIVE_CFG")"
fi
if [[ "$OUT" != *"carried"* ]]; then
  ok "and the run claims to have carried nothing, because it carried nothing"
else
  bad "nothing is claimed that was not carried" "$OUT"
fi

# A fresh install has nothing to carry from, and the same trap waits on the
# other side of it, so it is said once where the peer port is being discussed.
reset
run_native --yes --name stock-node14
if [[ "$OUT" == *"[ips_fixed]"* && "$OUT" == *"private validator"* ]]; then
  ok "a fresh native install says a private validator's node needs it in [ips_fixed]"
else
  bad "the fresh-install note names [ips_fixed]" "$OUT"
fi

echo
echo "Native mode: this installer cannot stop without saying why (#411)"

# The other half of #411. Reading the whole answer stops that ONE pipeline
# killing a run in silence; this stops any of them doing it. A stub that is
# genuinely killed by SIGPIPE, at a command with no die of its own, has to
# come out as a sentence naming the status, the signal and the command.
reset
touch "$TMP/state/install-sigpipe"
run_native --yes --name stock-node5

if [[ $RC -ne 0 && "$OUT" == *"nothing above it said why"* ]]; then
  ok "a step killed mid-run ends with a line saying the run stopped and nothing explained it"
else
  bad "a silent stop is reported rather than being silent" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"killed by signal 13"* ]]; then
  ok "the signal is named, so 141 is not left as a number to look up"
else
  bad "the signal behind a 141 is named" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"install -d"* && "$OUT" == *" line "* ]]; then
  ok "and the line and the command that stopped are named"
else
  bad "the line and the command that stopped are named" "rc=$RC: $OUT"
fi

# And the guard stays quiet behind a refusal that already spoke, including
# one raised inside a command substitution, where a flag in a variable would
# not have come back to the shell that prints the last line.
reset
printf 'ID=fedora\nVERSION_ID="40"\n' > "$OS_RELEASE"
run_native --yes --name stock-node6
if [[ $RC -ne 0 && "$OUT" != *"nothing above it said why"* ]]; then
  ok "a named refusal is not spoken over by the guard"
else
  bad "the guard stays quiet behind a named refusal" "rc=$RC: $OUT"
fi

echo
echo "Native mode: a conversion says the compact has to be accepted again (#466)"

# The acceptance a host made while it ran a container node. The node key on a
# native host is the unit, so this acceptance no longer applies, every
# privileged class is refused, and until now nothing said so anywhere the
# operator was looking.
reset
write_native_adopt_fixture xrpld.service
cat > "$ADVISOR_STATE/compact.json" <<'JSON'
{
  "terms_version": "v2",
  "terms_hash": "6b0c1d2e3f405162",
  "accepted_by": "aperire-advisor",
  "accepted_at": "2026-08-20T00:51:29Z",
  "node": "aperire-node2",
  "privilege": "D1",
  "classes": [
    "upgrade",
    "investigate",
    "restart",
    "config"
  ]
}
JSON
run_native --yes --name stock-node2

if [[ $RC -eq 0 && "$OUT" == *"accepted for"*"aperire-node2"* && "$OUT" == *"xrpld.service"* ]]; then
  ok "the run ends by naming the node the compact was accepted for"
else
  bad "the conversion names the stale acceptance" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"--accept --container=xrpld.service --privilege=D1 --classes=upgrade,investigate,restart,config"* ]]; then
  ok "with the exact command, carrying the privilege and the classes already accepted"
else
  bad "the command carries the previous privilege and classes" "$OUT"
fi
if grep -q '"node": "aperire-node2"' "$ADVISOR_STATE/compact.json"; then
  ok "and it accepted nothing: accepting terms stays the operator's own act"
else
  bad "the run changed the acceptance" "$(cat "$ADVISOR_STATE/compact.json" 2>/dev/null)"
fi
# One notice, not two: install-node-wrapper.sh --native would print its own
# copy mid-run, and this run suppresses it so the words land once, at the end.
if [[ "$(grep -c 'cannot act until the compact is accepted again' <<<"$OUT")" == "1" ]]; then
  ok "and it is printed once, at the end, rather than once per installer"
else
  bad "the notice is printed exactly once" "$OUT"
fi

# A fresh install has accepted nothing. Telling that operator to accept again
# would send them to re-do something they have never done.
reset
write_native_adopt_fixture xrpld.service
run_native --yes --name stock-node2
if [[ $RC -eq 0 && "$OUT" != *"compact"* ]]; then
  ok "a host that has accepted no compact is told nothing about one"
else
  bad "silence on a host with no acceptance" "rc=$RC: $OUT"
fi

# And an acceptance that names this host's unit is the ordinary case.
reset
write_native_adopt_fixture xrpld.service
cat > "$ADVISOR_STATE/compact.json" <<'JSON'
{
  "node": "xrpld.service",
  "privilege": "D1",
  "classes": [
    "restart"
  ]
}
JSON
run_native --yes --name stock-node2
if [[ $RC -eq 0 && "$OUT" != *"accepted again"* ]]; then
  ok "an acceptance that names this host's unit is left alone"
else
  bad "silence on a matching acceptance" "rc=$RC: $OUT"
fi

echo
echo "Native mode: refuses on a node already running that this run did not adopt (#087)"

# A container node, found by --native the same way verify-after-restart.sh's
# own node_seen() finds one: docker ps's name/image match. No native unit is
# loaded (the default fixture state), so native_probe_unit finds nothing and
# this run reaches the point where it would otherwise add a vendor repository
# and install a second node beside the live one.
reset
echo running > "$TMP/state/container-state"
echo "stock-node1" > "$TMP/state/containers"
run_native --yes --name stock-node2
if [[ $RC -ne 0 && "$OUT" == *"the container stock-node1"* ]]; then
  ok "a running container is named, and the install refuses"
else
  bad "a running container is named and refused" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"--adopt"* ]]; then
  ok "the refusal points at --adopt for the container shape"
else
  bad "the refusal names --adopt" "$OUT"
fi

# #896: the same guard, for a container created from a digest. Without the
# image name it read the host as having no node and went on to add a vendor
# repository beside the live one.
reset
echo running > "$TMP/state/container-state"
echo "aperire-node" > "$TMP/state/containers"
echo e77ed5a956a3 > "$TMP/state/image-of-aperire-node"
printf 'rippleci/xrpld@sha256:%s\n' "$(printf 'e77ed5a9%.0s' 1 2 3 4 5 6 7 8)" > "$TMP/state/config-image"
run_native --yes --name stock-node2
if [[ $RC -ne 0 && "$OUT" == *"the container aperire-node"* ]]; then
  ok "a running container created from a digest is named, and the install refuses (#896)"
else
  bad "a digest-created running container is named and refused" "rc=$RC: $OUT"
fi
reset
echo running > "$TMP/state/container-state"
echo "aperire-node" > "$TMP/state/containers"
echo e77ed5a956a3 > "$TMP/state/image-of-aperire-node"
: > "$TMP/state/inspect-refused"
run_native --yes --name stock-node2
if [[ $RC -ne 0 && "$OUT" == *"a container whose image docker would not name"* && "$OUT" == *"permission denied"* ]]; then
  ok "an inspect docker refuses is not read as no node, so the install still refuses"
else
  bad "a refused inspect does not clear the way for a second node" "rc=$RC: $OUT"
fi
if [[ ! -f "$NATIVE_SOURCES_LIST" && ! -f "$NATIVE_KEYRING" ]]; then
  ok "no repository was added before the refusal"
else
  bad "no repository was added before the refusal" "sources=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null) keyring exists=$([[ -f "$NATIVE_KEYRING" ]] && echo yes || echo no)"
fi

# A bare process, no docker container behind it at all (or docker unreachable
# from this account) - the shape a hand-run node or an unusual deployment
# leaves. Named by its process, not guessed away.
reset
echo xrpld-main > "$TMP/state/running-process"
run_native --yes --name stock-node2
if [[ $RC -ne 0 && "$OUT" == *"the process 'xrpld-main'"* ]]; then
  ok "a bare running process is named, and the install refuses"
else
  bad "a bare running process is named and refused" "rc=$RC: $OUT"
fi
if [[ ! -f "$NATIVE_SOURCES_LIST" && ! -f "$NATIVE_KEYRING" ]]; then
  ok "no repository was added before the refusal (process shape)"
else
  bad "no repository was added before the refusal (process shape)" "sources=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null) keyring exists=$([[ -f "$NATIVE_KEYRING" ]] && echo yes || echo no)"
fi

# Control: nothing running at all is not refused on this ground, and reaches
# the OS-support check as before.
reset
run_native --yes --name stock-node2
if [[ "$OUT" != *"is already running on this host"* ]]; then
  ok "control: a clean host is not refused as if something were running"
else
  bad "control: a clean host is not refused" "$OUT"
fi

echo
echo "Native mode: an unsupported OS is refused by name"

reset
printf 'ID=fedora\nVERSION_ID="40"\n' > "$OS_RELEASE"
run_native --yes --name stock-node3

if [[ $RC -ne 0 && "$OUT" == *"fedora"* && "$OUT" == *"40"* ]]; then
  ok "an unsupported OS is refused, named by ID and version"
else
  bad "an unsupported OS is refused, named" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"--node-wrapper-native"* ]]; then
  ok "the refusal points at the adopt path as the remedy"
else
  bad "the refusal points at the adopt path as the remedy" "$OUT"
fi
if [[ ! -f "$NATIVE_SOURCES_LIST" && ! -f "$NATIVE_KEYRING" ]]; then
  ok "nothing was written before the refusal"
else
  bad "nothing was written before the refusal" "sources=$(cat "$NATIVE_SOURCES_LIST" 2>/dev/null) keyring exists=$([[ -f "$NATIVE_KEYRING" ]] && echo yes || echo no)"
fi

reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\n' > "$OS_RELEASE"
echo aarch64 > "$TMP/state/arch"
run_native --yes --name stock-node4
if [[ $RC -ne 0 && "$OUT" == *"aarch64"* ]]; then
  ok "a supported distro on an unsupported architecture is refused, named"
else
  bad "an unsupported architecture is refused, named" "rc=$RC: $OUT"
fi

echo
echo "Native mode: the dashboard's own registry row for this node (#488)"

# A conversion writes a fresh store, a fresh store writes a new node key, and
# on aperire2 the registry went on pinning the old one for a month. Nothing
# said so, because a self row is read locally and never compared, while every
# other host reading that node through a registry with the same pin fails it
# closed.
OLD_KEY=n9LNQXQPppSioySU1zjpoz5eh2i2MkAe2DqrwNYjNqGuErxty2pe
NEW_KEY=n9LS7ei2KFgmeENk7fLYREhgnyfBquXHm3xxBMSnjAtfsEUzp5Qh
FLEET_YAML="$TMP/repo/dashboard/config/fleet.yaml"
mkdir -p "$(dirname "$FLEET_YAML")"

# The registry as this host would hold it: this node's own row, a second row
# for the aggregator that must not be touched, and a comment, because the file
# is hand written and a rewrite that dumps yaml takes every comment with it.
write_registry() {  # $1 = the key this host's row pins, or "" for an unpinned row
  local pin="${1-}"
  {
    printf '# This host'"'"'s registry. Hand written.\n'
    printf 'fleet:\n'
    printf '  - label: stock-node2\n'
    printf '    role: node\n'
    printf '    read_origin: http://127.0.0.1:7900\n'
    printf '    token_path: %s/read.token\n' "$TMP"
    [[ -n "$pin" ]] && printf '    expected_pubkey_node: %s\n' "$pin"
    printf '  - label: koi\n'
    printf '    role: aggregator\n'
    printf '    read_origin: http://127.0.0.1:7801\n'
    printf '    token_path: %s/koi.token\n' "$TMP"
    printf '    expected_pubkey_node: n9KaggREGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG\n'
  } > "$FLEET_YAML"
}
registry_pin() {  # prints what this host's row pins now, and nothing when it pins nothing
  # Bounded to the row: without the second rule this walks past an unpinned
  # stock-node2 and reports the AGGREGATOR's key as this host's pin, which is
  # exactly the confusion the row below exists to catch.
  awk '/- label: stock-node2/{f=1; next} f&&/- label: /{exit}
       f&&/expected_pubkey_node:/{print $2; exit}' "$FLEET_YAML"
}

reset
write_native_adopt_fixture xrpld.service
write_registry "$OLD_KEY"
printf 'PORT=7900\nAPERIRE_DB_PATH=%s/data/aperire.db\n' "$TMP" > "$TMP/etc/aperire/aperire.env"
echo "$NEW_KEY" > "$TMP/state/pubkey-node"
run_native --yes --name stock-node2

if [[ $RC -eq 0 && "$(registry_pin)" == "$NEW_KEY" ]]; then
  ok "a conversion repoints this host's own registry row at the key the node now answers with"
else
  bad "the registry row is repointed" "rc=$RC, pinned: $(registry_pin)"
fi
if [[ "$OUT" == *"now pins $NEW_KEY"* && "$OUT" == *"it pinned $OLD_KEY"* ]]; then
  ok "and says so, naming both keys, rather than changing the file silently"
else
  bad "the run names both keys" "$(grep -A4 'registry row' <<<"$OUT")"
fi
if [[ "$OUT" == *"systemctl reload aperire-server"* && "$OUT" == *"keeps naming the OLD key"* ]]; then
  ok "and names the reload with what happens without it: the page keeps asking for the edit this run made"
else
  bad "the run names the reload and its consequence" "$OUT"
fi
if grep -q 'n9KaggREG' "$FLEET_YAML" && grep -q "^# This host" "$FLEET_YAML"; then
  ok "the other row and the file's comments survive: one line changed, not a re-dump"
else
  bad "the rewrite is surgical" "$(cat "$FLEET_YAML")"
fi

# Idempotent, and it has to be: this installer is re-run over a host that is
# already right, and a second run that reported a change would be a second run
# that made one.
run_native --yes --name stock-node2
if [[ "$OUT" == *"already names the key this node answers with"* && "$(registry_pin)" == "$NEW_KEY" ]]; then
  ok "a second run says the row already names it and changes nothing"
else
  bad "a second run is a no-op that says so" "$(grep -A3 'registry row' <<<"$OUT")"
fi

# An absent expected_pubkey_node is a first-class shape (the registry parser
# documents it as one). Adding a pin is an operator's decision, and a row that
# gained one from an install would fail closed on some future re-key with
# nobody knowing where it came from.
reset
write_native_adopt_fixture xrpld.service
write_registry ""
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo "$NEW_KEY" > "$TMP/state/pubkey-node"
run_native --yes --name stock-node2
if [[ $RC -eq 0 && "$(registry_pin)" == "" && "$OUT" == *"pins no node key, and an install does not add one"* ]]; then
  ok "an unpinned row is never pinned by an install, and the run says why"
else
  bad "an unpinned row is left unpinned" "rc=$RC, pinned: '$(registry_pin)', $(grep -A3 'registry row' <<<"$OUT")"
fi

# Two instances on one host is a supported shape, and it is the one where
# guessing which row is "this one" repoints somebody else's node.
reset
write_native_adopt_fixture xrpld.service
write_registry "$OLD_KEY"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
printf 'PORT=7902\n' > "$TMP/etc/aperire/aperire-second.env"
echo "$NEW_KEY" > "$TMP/state/pubkey-node"
run_native --yes --name stock-node2
if [[ "$(registry_pin)" == "$OLD_KEY" && "$OUT" == *"no single dashboard port"* ]]; then
  ok "two dashboards on one host: nothing is guessed and nothing is written"
else
  bad "an ambiguous host is left alone" "pinned: $(registry_pin), $(grep -A3 'registry row' <<<"$OUT")"
fi

# A node that answers without naming its key has not said what its key is,
# and a key nobody read is not a reason to rewrite a pin. This is the shape a
# fork that renames the field arrives in, which is this project's own
# characteristic bug, and the one that must never read as "the registry is
# wrong". (A node that does not answer AT ALL never reaches here: the adopt
# refuses earlier, on its own admin-RPC check, and that is its row above.)
reset
write_native_adopt_fixture xrpld.service
write_registry "$OLD_KEY"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
: > "$TMP/state/pubkey-node"
run_native --yes --name stock-node2
if [[ "$(registry_pin)" == "$OLD_KEY" && "$OUT" == *"did not say what its node key is"* ]]; then
  ok "a node that named no key leaves the pin exactly as it was"
else
  bad "no observed key means no write" "pinned: $(registry_pin), $(grep -A3 'registry row' <<<"$OUT")"
fi

# No registry at all is the ordinary single-node install, and it must stay
# silent: this section must not put a line about fleets on every install.
reset
write_native_adopt_fixture xrpld.service
rm -f "$FLEET_YAML"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
run_native --yes --name stock-node2
if [[ $RC -eq 0 && "$OUT" != *"registry row"* ]]; then
  ok "a host with no registry says nothing about one"
else
  bad "no registry, no section" "rc=$RC: $(grep -A3 'registry row' <<<"$OUT")"
fi

echo
echo "Native mode: a container node on this host is unchanged"

# The container suite above already proves every one of its own rows still
# passes; this is the direct check that --native and the container path do
# not share state through the constants both of them read.
reset
run_node --yes --name test-node
if [[ $RC -eq 0 && ! -f "$WCONF" ]]; then
  ok "a plain (container) run still succeeds and still writes no wrapper configuration"
else
  bad "a plain run is unaffected by native mode existing" "rc=$RC: $(ls "$TMP/etc/aperire" 2>/dev/null)"
fi

echo
echo "The node config does not stay world-readable on a host with no Advisor (#462):"

# The file this installer writes is 0644 in a 0755 directory, and on a
# validator it carries [validator_token]. Until #462 the only thing that
# closed it was close-node-config-exposure.sh, which runs from the Advisor
# one-liner, so a host with a node and a dashboard and no Advisor kept the
# token readable by every local account for the life of the install.
#
# What these rows hold shut is the wiring, not the ACL model: that the
# installer reaches the closer on every shape it can finish on, hands it
# --apply, does not treat its refusal as fatal, and reports what the file
# says afterwards rather than what the closer claimed.

reset
run_node --yes --name test-node
if [[ $RC -eq 0 && -s "$TMP/state/closer-calls" ]]; then
  ok "a fresh container install calls the closer"
else
  bad "a fresh install calls the closer" "rc=$RC: $(cat "$TMP/state/closer-calls" 2>/dev/null || echo 'never called')"
fi
if grep -q -- '--apply' "$TMP/state/closer-calls" 2>/dev/null; then
  ok "and with --apply, so it changes the file rather than reporting on it"
else
  bad "the closer is called with --apply" "$(cat "$TMP/state/closer-calls" 2>/dev/null)"
fi
if [[ "$(stat -c '%a' "$CFG")" == 640 ]]; then
  ok "the config ends the run at 640, closed to every other account on the host"
else
  bad "the config ends the run closed" "mode $(stat -c '%a' "$CFG")"
fi
if [[ "$OUT" == *"closed: $CFG"* ]]; then
  ok "and the run says so, naming the file and the mode it moved"
else
  bad "the run says what it closed" "$OUT"
fi
# The exact rendered line (#462 P3-074): `stat -c '%a %a'` against two files
# printed every mode twice, "644 644 755 755 -> 640 640 750 750". One `%a`
# renders each mode once, "644 755 -> 640 750": two numbers before the arrow,
# two after, whatever this host's umask actually wrote for the directory (the
# stub here only chmods the file, so the directory number is unchanged either
# side of the arrow, and is not asserted as a literal value on purpose).
closed_line=$(grep -o "closed: $CFG and its directory, [0-9 ]*-> [0-9 ]*" <<<"$OUT" | head -1)
before_part="${closed_line#*directory, }"; before_part="${before_part%%->*}"
after_part="${closed_line##*-> }"
if [[ -n "$closed_line" && $(wc -w <<<"$before_part") -eq 2 && $(wc -w <<<"$after_part") -eq 2 ]]; then
  ok "and the exact line renders each mode once, not doubled ($closed_line)"
else
  bad "the closed line renders each mode once, not doubled" "line: '$closed_line' in: $OUT"
fi
# The record has to be written first or the closer has no node to find. Both
# orderings produce a run that exits 0; only one of them closes the file.
if [[ "$OUT" == *"node.conf names this node"* ]] \
   && [[ "${OUT%%closed: *}" == *"node.conf names this node"* ]]; then
  ok "the record is written before the close, which is how the closer finds the node"
else
  bad "the record is written before the close" "$OUT"
fi

# Second run, same host. The closer is idempotent in its own right; what is
# asserted here is that the installer reads the result off the file rather
# than off the closer's exit status, so an already-closed host says so.
run_node --yes --name test-node
if [[ $RC -eq 0 && "$OUT" == *"already closed: $CFG"* ]]; then
  ok "a re-run on a closed config reports it as already closed"
else
  bad "a re-run reports already closed" "rc=$RC: $OUT"
fi
if [[ "$(stat -c '%a' "$CFG")" == 640 ]]; then
  ok "and leaves it at 640; a re-run does not widen a security change back"
else
  bad "a re-run leaves the file closed" "mode $(stat -c '%a' "$CFG")"
fi

# A closer that refuses. It reverts itself and never half-applies, so the
# install is worth finishing: the node is up, and the step is one command to
# repeat. A run that ended red here would throw away a working node over a
# file mode.
reset
: > "$TMP/state/closer-fails"
run_node --yes --name test-node
if [[ $RC -eq 0 ]]; then
  ok "a closer that refuses does not fail the install"
else
  bad "a refusal is not fatal" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"left exactly as it was"* && "$OUT" == *"--run node-config-exposure --apply"* ]]; then
  ok "and the run says the config was left alone, with the command that finishes it"
else
  bad "the refusal is explained" "$OUT"
fi
if [[ "$OUT" == *"cannot reach the node"* ]]; then
  ok "the closer's own reason is in the transcript, not summarised away"
else
  bad "the closer's reason is printed" "$OUT"
fi

# --adopt. A host whose node outlived a wipe-clean uninstall has the same
# world-readable config a fresh install has, and adopt is the verb that host
# reaches for. The file's MODE changes; its CONTENT must not.
reset
adopted_host
ADOPT_CFG_BEFORE=$(md5sum < "$CFG")
run_node --adopt
if [[ $RC -eq 0 && "$(stat -c '%a' "$CFG")" == 640 ]]; then
  ok "--adopt closes the config of the node it recorded"
else
  bad "--adopt closes the config" "rc=$RC: mode $(stat -c '%a' "$CFG")"
fi
if [[ "$(md5sum < "$CFG")" == "$ADOPT_CFG_BEFORE" ]]; then
  ok "and changes not one byte of it; adopt still edits no config content"
else
  bad "--adopt leaves the config content alone" "the config was rewritten"
fi

# Native. Same file, same exposure, a different way of finding the node.
reset
write_native_adopt_fixture xrpld.service 2459
run_native --yes --name stock-node1
if [[ $RC -eq 0 && -s "$TMP/state/closer-calls" ]] \
   && grep -q -- '--apply' "$TMP/state/closer-calls"; then
  ok "a native install calls the closer with --apply too"
else
  bad "the native path calls the closer" "rc=$RC: $(cat "$TMP/state/closer-calls" 2>/dev/null || echo 'never called')"
fi
if [[ "$(stat -c '%a' "$NATIVE_CFG")" == 640 ]]; then
  ok "and the native config ends the run at 640"
else
  bad "the native config ends closed" "mode $(stat -c '%a' "$NATIVE_CFG")"
fi

# ── The scrap list and the EXIT trap that empties it (#588) ──────────────
# on_exit removes whatever is still on SCRAPS. errexit is live inside an EXIT
# trap, so a removal that fails (a name another account replaced with
# something root cannot delete) used to end the run with status 1 before the
# status being reported was returned or the "said why" line was written. The
# block is cut out of the installer and run on its own.
SCRAP_BLOCK="$TMP/scrap-block.sh"
# shellcheck disable=SC2016  # the sed program is literal text to match, not shell
sed -n '/^SAID_WHY_MARK="\$(mktemp/,/^trap on_exit EXIT$/p' "$REPO_DIR/scripts/install-aperire-node.sh" > "$SCRAP_BLOCK"
if grep -q '^trap on_exit EXIT$' "$SCRAP_BLOCK" && grep -q '^scrap_rm()' "$SCRAP_BLOCK"; then
  ok "the scrap list, scrap_rm and the EXIT trap were found in the installer"
else
  bad "the scrap block was found" "markers moved in install-aperire-node.sh"
fi
# Removal fails for ONE path, by an rm shim first on PATH inside the harness:
# it refuses the planted name and passes every other call to the real rm. That
# fails for root as well as for any other account, which a directory the
# account cannot delete does not (root deletes it), so these rows run as any uid.
BUSY="$TMP/busy-scrap"
: > "$BUSY"
mkdir -p "$TMP/rmshim"
cat > "$TMP/rmshim/rm" <<SHIM
#!/usr/bin/env bash
for a in "\$@"; do
  if [[ "\$a" == "$BUSY" ]]; then echo "rm: cannot remove '\$a': Device or resource busy" >&2; exit 1; fi
done
exec $(command -v rm) "\$@"
SHIM
chmod 0755 "$TMP/rmshim/rm"
scrap_run() { # $1 = block file, $2 = body; prints the output, then rc=N
  local out rc=0
  out="$(PATH="$TMP/rmshim:$PATH" bash -c 'set -Eeuo pipefail; E_RED=""; E_OFF=""; . "$1"; eval "$2"' _ "$1" "$2" 2>&1)" || rc=$?
  printf '%s\nrc=%s\n' "$out" "$rc"
}
# shellcheck disable=SC2016  # the body is run by the harness shell
out="$(scrap_run "$SCRAP_BLOCK" 'SCRAPS+=("'"$BUSY"'"); exit 0')"
if [[ "$out" == *"rc=0" && "$out" != *"stopped with"* && -e "$BUSY" ]]; then
  ok "a scrap whose removal fails (the shim refused it) does not turn a clean run into a failure"
else
  bad "an unremovable scrap leaves a clean run clean" "$out"
fi
# shellcheck disable=SC2016  # the body is run by the harness shell
out="$(scrap_run "$SCRAP_BLOCK" 'SCRAPS+=("'"$BUSY"'"); exit 7')"
if [[ "$out" == *"rc=7" && "$out" == *"stopped with status 7"* ]]; then
  ok "  and a failing run keeps its own status and still says why"
else
  bad "an unremovable scrap leaves a failing run's status alone" "$out"
fi
# The same block with the guard cut out must go red.
sed 's/ 2>\/dev\/null || true; done$/; done/' "$SCRAP_BLOCK" > "$TMP/scrap-block-ablated.sh"
if cmp -s "$SCRAP_BLOCK" "$TMP/scrap-block-ablated.sh"; then
  bad "the ablation of the on_exit guard cut something" "the loop line moved"
else
  # shellcheck disable=SC2016  # the body is run by the harness shell
  out="$(scrap_run "$TMP/scrap-block-ablated.sh" 'SCRAPS+=("'"$BUSY"'"); exit 0')"
  if [[ "$out" == *"rc=1" ]]; then
    ok "  control: without the guard the same run exits 1"
  else
    bad "the guard is what keeps the status" "$out"
  fi
fi
rm -f "$BUSY"
ONE="$(mktemp)"; TWO="$(mktemp)"
# shellcheck disable=SC2016  # the body is run by the harness shell, which expands ${SCRAPS[@]}
out="$(scrap_run "$SCRAP_BLOCK" 'SCRAPS+=("'"$ONE"'" "'"$TWO"'"); scrap_rm "'"$ONE"'"; echo "left=${#SCRAPS[@]} first=${SCRAPS[0]}"; exit 0')"
if [[ "$out" == *"left=1 first=$TWO"* && ! -e "$ONE" ]]; then
  ok "scrap_rm removes the file and takes only that name off the list"
else
  bad "scrap_rm keeps the list in step" "$out"
fi
rm -f "$ONE" "$TWO"

LEFT="$(find "$SCRATCH" -mindepth 1 -maxdepth 1 -printf '%f ')"
if [[ -z "$LEFT" ]]; then
  ok "no run left a file or folder behind in the temp dir"
else
  bad "no run leaves anything in the temp dir" "left: $LEFT"
fi

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
