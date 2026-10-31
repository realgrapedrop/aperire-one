#!/usr/bin/env bash
# Exercise aperire-backup.sh and aperire-restore.sh end to end (#544), and
# name one row per defect a hand-pasted version of this shell actually had:
# #514 (the sealed credential swept into a wider copy), #515 (a restored
# Advisor landing on its old, still-resolving account), #517 (the wrong
# port and the fleet files left behind), #535 (a backup that copies four
# config files where the restore reads seven), #536 (a set its own maker
# cannot read, with a manifest covering a fraction of what it holds), #537
# (a chown that flattens the Advisor's shared group), #539 (a restore that
# arms one side and not the other).
#
#   bash scripts/test-backup-restore.sh
#
# Runs entirely under a temporary directory, as the account already running
# it: no root, no real systemd, no real service. systemctl, curl, runuser,
# id and getent are fakes on PATH ahead of the real ones (id and getent fall
# back to the real binary for any account this fixture did not name, so the
# invoking account's own real identity resolves exactly as it would anywhere
# else). sqlite3 and chown are real: the database is a real one, taken with
# a real `VACUUM INTO`, and a chown onto an account this fixture actually
# has is a real chown, checked back with a real `stat`.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_SRC="$REPO_DIR/scripts/aperire-backup.sh"
RESTORE_SRC="$REPO_DIR/scripts/aperire-restore.sh"
SET_SRC="$REPO_DIR/scripts/aperire-backup-set.sh"
STYLE_SRC="$REPO_DIR/scripts/term-style.sh"
STATE_FILE_SRC="$REPO_DIR/scripts/state-file.py"
ADVISOR_OWNER_LIB_SRC="$REPO_DIR/scripts/advisor-owner-lib.sh"
DASH_ACCOUNT_LIB_SRC="$REPO_DIR/scripts/dashboard-account-lib.sh"
GUIDE="$REPO_DIR/docs/OPERATIONAL-GUIDE.md"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
has()  { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "got: $2 | want substring: $3"; fi; }
hasnt(){ if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "got: $2 | did not want substring: $3"; fi; }
has_q() { [[ "$1" == *"$2"* ]]; }  # a quiet substring test, for compound rows
is()   { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got: [$2] | want: [$3]"; fi; }

CALLER_USER="$(id -un)"
CALLER_GROUP="$(id -gn)"
ALT_GROUP="$(id -Gn | tr ' ' '\n' | grep -vx -e "$CALLER_GROUP" | head -1)"
[[ -n "$ALT_GROUP" ]] || ALT_GROUP="$CALLER_GROUP"

# ── stub binaries, on PATH ahead of the real ones ────────────────────────
BIN="$TMP/bin"
mkdir -p "$BIN"
export FAKE_SYSTEMCTL_STATE="$TMP/systemctl-state"
export FAKE_CHOWN_LOG="$TMP/chown-args"
export FAKE_PLANT_LOG="$TMP/plant-args"
: > "$FAKE_PLANT_LOG"
: > "$FAKE_CHOWN_LOG"
mkdir -p "$FAKE_SYSTEMCTL_STATE"

cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
DIR="${FAKE_SYSTEMCTL_STATE:?}"
mkdir -p "$DIR"
case "${1:-}" in
  is-active)
    if [[ -f "$DIR/$2.active" ]]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
  start) : > "$DIR/$2.active"; exit 0 ;;
  stop)  rm -f "$DIR/$2.active"; exit 0 ;;
  # `systemctl show -p MainPID --value <unit>`, one unit's PID at a time:
  # this fixture only ever asks about the dashboard unit, so one env var is
  # enough rather than a per-unit table.
  show) echo "${FAKE_MAINPID:-0}"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$BIN/systemctl"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
mode="${FAKE_CURL_MODE:-healthy}"
args="$*"
# #791: an aggregator's closing check reads one node through its loopback
# read port. Its argv and whatever header file it was handed are logged, so
# a row can prove the token travelled in the file and never on the argv.
# FAKE_NODE_READ is the HTTP status the node answers; 000 is nothing
# listening, which real curl reports as 000 with exit 7.
# #798: the Advisor's own two checks are logged the same way.
if [[ "$args" == *"/v1/ledger"* || "$args" == *"/v1/status"* ]] && [[ -n "${FAKE_CURL_LOG:-}" ]]; then
  printf '%s\n' "$args" >> "$FAKE_CURL_LOG"
  for a in "$@"; do
    [[ "$a" == @* && -f "${a#@}" && -n "${FAKE_CURL_HDR_LOG:-}" ]] && cat "${a#@}" >> "$FAKE_CURL_HDR_LOG"
  done
fi
if [[ "$args" == *"/read/v1/recent"* ]]; then
  [[ -n "${FAKE_CURL_LOG:-}" ]] && printf '%s\n' "$args" >> "$FAKE_CURL_LOG"
  for a in "$@"; do
    [[ "$a" == @* && -f "${a#@}" && -n "${FAKE_CURL_HDR_LOG:-}" ]] && cat "${a#@}" >> "$FAKE_CURL_HDR_LOG"
  done
  code="${FAKE_NODE_READ:-200}"
  printf '%s' "$code"
  [[ "$code" == 000 ]] && exit 7
  exit 0
fi
case "$args" in
  *"/healthz"*)
    [[ "$mode" == healthy ]] && echo '{"ok":true,"relay_last_push_ms":120}' || echo '{"ok":false}' ;;
  *"/v1/ledger"*)
    [[ "$mode" == healthy ]] && echo '{"chain_intact":true,"count":3}' || echo '{"chain_intact":false}' ;;
  *"/v1/status"*)
    echo '{"model":{"configured":true,"credential_present":false}}' ;;
  *) echo '{}' ;;
esac
exit 0
EOF
chmod +x "$BIN/curl"

cat > "$BIN/runuser" <<'EOF'
#!/usr/bin/env bash
# runuser -u USER -- cmd...  (#796: who each read ran as is logged, so a row
# can prove a file in an account's own directory was read AS that account)
# The command as the caller meant it: as_dashboard puts `env -i PATH=...`
# in front from root, and that prefix is logged without, so a row reads the
# same whichever route took it.
who="$2"
shift 3
logged=("$@")
[[ "${1:-}" == env && "${2:-}" == -i ]] && logged=("${@:4}")
[[ -n "${FAKE_RUNUSER_LOG:-}" ]] && printf '%s :: %s\n' "$who" "${logged[*]}" >> "$FAKE_RUNUSER_LOG"
exec "$@"
EOF
chmod +x "$BIN/runuser"

# sudo -u USER [-n] [--] cmd...  The restore runs as root on a real host and
# reaches the dashboard's account through runuser; a row that names a
# dashboard account other than the one running this suite reaches it
# through here instead, because this suite is not root. Logged the same way
# as runuser, then run as the suite's own account.
cat > "$BIN/sudo" <<'EOF'
#!/usr/bin/env bash
who=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u) who="$2"; shift 2 ;;
    -n|-H) shift ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
[[ -n "${FAKE_SUDO_LOG:-}" ]] && printf '%s :: %s\n' "$who" "$*" >> "$FAKE_SUDO_LOG"
exec "$@"
EOF
chmod +x "$BIN/sudo"

# FAKE_CHOWN_GROUP_FALLBACK=1 (one row sets it): a chown to root that an
# unprivileged run cannot make still applies its group, so a real `stat -c
# %G` can tell which group the restore chose. Every other row sees the plain
# log-and-try shape.
#
# FAKE_CHOWN_SWAP="<path>|<target>" (#776's race rows): the moment a chown is
# aimed at <path>, the name is swapped for a link to <target> first, the way
# the account that owns <path>'s directory could between root's write and
# root's chown. Whatever root does to that name next lands on <target>.
cat > "$BIN/chown" <<EOF
#!/usr/bin/env bash
if [[ -n "\${FAKE_CHOWN_SWAP:-}" && "\${*: -1}" == "\${FAKE_CHOWN_SWAP%%|*}" && ! -L "\${FAKE_CHOWN_SWAP%%|*}" ]]; then
  if [[ -d "\${FAKE_CHOWN_SWAP%%|*}" ]]; then
    mv -- "\${FAKE_CHOWN_SWAP%%|*}" "\${FAKE_CHOWN_SWAP%%|*}.swapped-away"
  else
    rm -f -- "\${FAKE_CHOWN_SWAP%%|*}"
  fi
  ln -s -- "\${FAKE_CHOWN_SWAP#*|}" "\${FAKE_CHOWN_SWAP%%|*}"
  [[ -n "\${FAKE_SWAP_LOG:-}" ]] && echo "swapped \${FAKE_CHOWN_SWAP%%|*}" >> "\$FAKE_SWAP_LOG"
fi
printf '%s\n' "\$*" >> "$FAKE_CHOWN_LOG"
if ! /bin/chown "\$@" 2>/dev/null && [[ -n "\${FAKE_CHOWN_GROUP_FALLBACK:-}" ]]; then
  opts=(); while [[ "\${1:-}" == -* ]]; do opts+=("\$1"); shift; done
  spec="\${1:-}"; shift || true
  [[ "\$spec" == *:?* ]] && /bin/chgrp "\${opts[@]}" "\${spec#*:}" "\$@" 2>/dev/null
fi
exit 0
EOF
chmod +x "$BIN/chown"

# FAKE_ABSENT="name ...": accounts and groups this fixture makes resolve
# nowhere, whatever the box running it has (a dev box may well have an
# aperire-relay account; a CI runner does not).
cat > "$BIN/id" <<'EOF'
#!/usr/bin/env bash
case " ${FAKE_ABSENT:-} " in *" ${2:-} "*) [[ -n "${2:-}" ]] && { echo "id: '$2': no such user" >&2; exit 1; } ;; esac
if [[ "${1:-}" == -u && -n "${2:-}" ]]; then
  for e in ${FAKE_IDS:-}; do n=${e%%=*}; ids=${e#*=}; [[ "$n" == "$2" ]] && { echo "${ids%%:*}"; exit 0; }; done
  case " ${FAKE_USERS:-} " in *" $2 "*) echo 0; exit 0 ;; esac
  exec /usr/bin/id -u "$2"
fi
if [[ "${1:-}" == -nG && -n "${2:-}" ]]; then
  for e in ${FAKE_GROUPS_OF:-}; do n=${e%%=*}; g=${e#*=}; [[ "$n" == "$2" ]] && { echo "${g//,/ }"; exit 0; }; done
  exec /usr/bin/id -nG "$2"
fi
if [[ "${1:-}" == -gn && -n "${2:-}" ]]; then
  for e in ${FAKE_PRIMARY_GROUP:-}; do n=${e%%=*}; g=${e#*=}; [[ "$n" == "$2" ]] && { echo "$g"; exit 0; }; done
  case " ${FAKE_USERS:-} " in *" $2 "*) echo "$2"; exit 0 ;; esac
  exec /usr/bin/id -gn "$2"
fi
exec /usr/bin/id "$@"
EOF
chmod +x "$BIN/id"

# docker: only `docker ps`, the restore's question about a node container
# (#826). It answers FAKE_DOCKER_PS, never the containers of the box running
# this suite: a dev box may well run a node in one.
cat > "$BIN/docker" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == ps ]] && { [[ -n "${FAKE_DOCKER_PS:-}" ]] && printf '%s\n' "$FAKE_DOCKER_PS"; exit 0; }
exit 1
EOF
chmod +x "$BIN/docker"

cat > "$BIN/getent" <<'EOF'
#!/usr/bin/env bash
case " ${FAKE_ABSENT:-} " in *" ${2:-} "*) [[ -n "${2:-}" ]] && exit 2 ;; esac
if [[ "${1:-}" == group && -n "${2:-}" ]]; then
  case " ${FAKE_GROUPS:-} " in *" $2 "*) echo "$2:x:9999:"; exit 0 ;; esac
  exec /usr/bin/getent group "$2"
fi
if [[ "${1:-}" == passwd && -n "${2:-}" ]]; then
  case " ${FAKE_USERS:-} " in *" $2 "*) echo "$2:x:1000:1000::/nonexistent:/bin/false"; exit 0 ;; esac
  exec /usr/bin/getent passwd "$2"
fi
exec /usr/bin/getent "$@"
EOF
chmod +x "$BIN/getent"

# #674. Two cases have to reach into the live database WHILE the restore is
# inside the wait it takes after starting the dashboard. They used to guess at
# that window: three seconds of real sleep in the restore, and a poll here for
# the restored file to appear. On a loaded runner the poll could still be
# running when the window had already closed, and the case failed for a reason
# the code under test had no part in. The window is a handshake now. A stub
# sleep handed the sentinel says it has arrived and holds until the test
# releases it; anything else goes straight to the real sleep, this script's own
# short waits included.
cat > "$BIN/sleep" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" != "${RESTORE_WAIT_SENTINEL:-__no_handshake__}" ]]; then exec /bin/sleep "$@"; fi
: > "${RESTORE_WAIT_ARRIVED:?}"
for _ in $(seq 1 6000); do
  [[ -e "${RESTORE_WAIT_GO:?}" ]] && exit 0
  /bin/sleep 0.05
done
echo "test rig: nothing ever released the restore's wait" >&2
exit 1
EOF
chmod +x "$BIN/sleep"

# #744: the restore places an aggregator's arm key through a temp file and
# `ln -T`, which never replaces a key that appeared after its own check. A
# real race is not something a suite can schedule, so this stands in for the
# other process: handed the arm key's own temp template while
# FAKE_MKTEMP_PLANT names a key, it first puts that key at the final name,
# exactly as a pairing approval landing in that instant would, then makes the
# temp. Every other mktemp goes straight to the real one.
cat > "$BIN/mktemp" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${FAKE_MKTEMP_PLANT:-}" ]]; then
  for a in "$@"; do
    if [[ "$a" == */.fleet-arm.key.XXXXXX ]]; then
      cp "$FAKE_MKTEMP_PLANT" "$(dirname "$a")/fleet-arm.key"
    fi
  done
fi
exec /usr/bin/mktemp "$@"
EOF
chmod +x "$BIN/mktemp"

# Arm the handshake for one case. The restore's wait length IS the sentinel, so
# the stub can tell that wait apart from every other sleep on this PATH.
restore_wait_arm() {  # <case tag>
  RESTORE_WAIT_SENTINEL="held-by-the-test"
  RESTORE_WAIT_ARRIVED="$TMP/restore-arrived-$1"
  RESTORE_WAIT_GO="$TMP/restore-go-$1"
  rm -f "$RESTORE_WAIT_ARRIVED" "$RESTORE_WAIT_GO"
  export RESTORE_WAIT_SENTINEL RESTORE_WAIT_ARRIVED RESTORE_WAIT_GO
  export APERIRE_RESTORE_SLEEP="$RESTORE_WAIT_SENTINEL"
}
# Block until the restore is inside the wait. Gives up early if the restore
# died before it got there, so a broken restore fails its own assertions
# instead of hanging this script.
restore_wait_arrived() {  # <restore pid>
  local pid=$1 _
  for _ in $(seq 1 6000); do
    [[ -e "$RESTORE_WAIT_ARRIVED" ]] && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    /bin/sleep 0.05
  done
  return 1
}
restore_wait_release() { : > "$RESTORE_WAIT_GO"; }
restore_wait_disarm() {
  unset APERIRE_RESTORE_SLEEP RESTORE_WAIT_SENTINEL RESTORE_WAIT_ARRIVED RESTORE_WAIT_GO
}

export PATH="$BIN:$PATH"

# ── the fixture tree ──────────────────────────────────────────────────
# Not under /home/: CI greps every shipped script (this one included) for a
# literal /home/<name>/ path, and a fixture one would fail it exactly like a
# real one would.
REPO="$TMP/repo"
ETC="$TMP/etc"
UNITS="$TMP/etc/systemd/system"
FAKE_PROC="$TMP/proc"

mk_tree() {
  rm -rf "$REPO" "$ETC"
  mkdir -p "$REPO/dashboard/config" "$REPO/data" "$REPO/advisor/state" "$REPO/scripts" \
    "$ETC/aperire" "$UNITS"
}

# The real state-file.py, beside a shim that stands in for it (below).
write_state_shim() {
  cp "$STATE_FILE_SRC" "$REPO/scripts/state-file.real.py"
  # This suite is not root and cannot fchown to uid 0, or to a group it is
  # not in (the getent stand-in's 9999). The shim logs every plant, mkdir and
  # own request as asked (FAKE_PLANT_LOG), then asks for this account's own
  # uid and group where an id it cannot give was named, so the request can be
  # read and the file still lands. Everything else goes to the real tool
  # untouched.
  #
  # FAKE_CHOWN_SWAP="<path>|<target>", the same as the chown stand-in's: the
  # moment a request names <path>, the name is swapped for a link to
  # <target> first, the way the account that owns <path>'s directory could
  # between root's check and root's write (#965).
  cat > "$REPO/scripts/state-file.py" <<SHIM
import os, sys
a = sys.argv[1:]
if a and a[0] in ("plant", "mkdir", "own") and len(a) > 4:
    with open("${FAKE_PLANT_LOG}", "a") as log:
        log.write("%s %s %s %s %s\\n" % (a[0], a[1], a[2], a[3], a[4]))
    if os.getuid() != 0:
        if a[2] not in ("", "dir") and int(a[2]) != os.getuid():
            a[2] = str(os.getuid())
        if a[3] not in ("", "dir") and int(a[3]) not in os.getgroups() + [os.getgid()]:
            a[3] = str(os.getgid())
    swap = os.environ.get("FAKE_CHOWN_SWAP", "")
    if swap and swap.split("|", 1)[0] == a[1]:
        at, to = swap.split("|", 1)
        if not os.path.islink(at):
            if os.path.isdir(at):
                os.rename(at, at + ".swapped-away")
            elif os.path.lexists(at):
                os.unlink(at)
            os.symlink(to, at)
            if os.environ.get("FAKE_SWAP_LOG"):
                with open(os.environ["FAKE_SWAP_LOG"], "a") as log:
                    log.write("swapped %s\\n" % at)
# The set's own hand-over to the operator (#1121) is one own-many, by uid and
# gid: logged as asked, then asked for this account's own where an id it
# cannot give was named, for the same reason.
if a and a[0] == "own-many" and len(a) > 3:
    with open("${FAKE_PLANT_LOG}", "a") as log:
        log.write("own-many %s %s\\n" % (a[1], a[2]))
    if os.getuid() != 0:
        if a[1] not in ("", "dir") and int(a[1]) != os.getuid():
            a[1] = str(os.getuid())
        if a[2] not in ("", "dir") and int(a[2]) not in os.getgroups() + [os.getgid()]:
            a[2] = str(os.getgid())
# FAKE_PLANT_LINKS="<name>|<target>;<name>|<target>" (#1154's rows): at the
# first ancestors call of a run, which the backup makes after it has judged
# --to empty and before it has written a byte, each <name> becomes a symlink to
# <target>, the way the account that owns --to could put one there in the gap
# between root's check and root's write. A backup that writes into --to by name
# follows it; one that builds elsewhere and places the set by descriptor
# refuses it.
if a and a[0] == "ancestors" and os.environ.get("FAKE_PLANT_LINKS"):
    for pair in os.environ["FAKE_PLANT_LINKS"].split(";"):
        at, to = pair.split("|", 1)
        if not os.path.lexists(at):
            os.symlink(to, at)
# FAKE_COPY_TREE_RC=<n> (the review of #1161): copy-tree stops with that exit
# status and says so, so the backup's reading of each status can be seen
# without a disk that fails.
if a and a[0] == "copy-tree" and os.environ.get("FAKE_COPY_TREE_RC"):
    sys.stderr.write("state-file: stand-in for a copy-tree that stopped\\n")
    sys.exit(int(os.environ["FAKE_COPY_TREE_RC"]))
# FAKE_WIDEN_BEFORE_COPY=<octal mode> (#1153): the destination's parent is
# widened just before the copy, after the up-front ancestors check has passed,
# the way an account that could write the parent's own parent could between
# root's check and root's write. The hand-over has to refuse it on its own.
if a and a[0] == "copy-tree" and os.environ.get("FAKE_WIDEN_BEFORE_COPY"):
    os.chmod(os.path.dirname(os.path.abspath(a[2])), int(os.environ["FAKE_WIDEN_BEFORE_COPY"], 8))
real = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state-file.real.py")
# FAKE_TAKEBACK_PARK=<dir> (#1164): the copy is made, one refusal is added so the
# take-back runs, and the take-back parks on its first removal until <dir>/fifo
# is opened for writing, after writing its pid to <dir>/ready. A signal sent
# while it is parked lands during the take-back, which nothing else can aim at.
if a and a[0] == "copy-tree" and os.environ.get("FAKE_TAKEBACK_PARK"):
    import importlib.util
    park = os.environ["FAKE_TAKEBACK_PARK"]
    spec = importlib.util.spec_from_file_location("statefile", real)
    sf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sf)
    real_copy_dir, real_unlink, parked = sf._copy_dir, os.unlink, []
    def refusing(*args):
        return real_copy_dir(*args) + 1
    def parking_unlink(path, *, dir_fd=None):
        if dir_fd is not None and not parked:
            parked.append(1)
            with open(park + "/ready", "w") as f:
                f.write(str(os.getpid()))
            os.close(os.open(park + "/fifo", os.O_RDONLY))
        return real_unlink(path, dir_fd=dir_fd)
    sf._copy_dir, os.unlink = refusing, parking_unlink
    sys.exit(sf.main([real] + a))
os.execv(sys.executable, [sys.executable, real] + a)
SHIM
}

# Copies of the three real scripts, ETC_APERIRE/UNIT_DIR rewritten into the
# fixture and NEEDS_ROOT flipped so this can run without root, the same
# technique scripts/test-uninstall-units.sh uses for the same reason.
build_sut() {
  sed -e "s#^ETC_APERIRE=/etc/aperire\$#ETC_APERIRE=${ETC}/aperire#" \
      -e "s#^UNIT_DIR=/etc/systemd/system\$#UNIT_DIR=${UNITS}#" \
      "$SET_SRC" > "$REPO/scripts/aperire-backup-set.sh"
  grep -q "^ETC_APERIRE=${ETC}/aperire\$" "$REPO/scripts/aperire-backup-set.sh" \
    || { echo "ETC_APERIRE rewrite did not land; the assignment line moved in $SET_SRC" >&2; exit 1; }
  grep -q "^UNIT_DIR=${UNITS}\$" "$REPO/scripts/aperire-backup-set.sh" \
    || { echo "UNIT_DIR rewrite did not land; the assignment line moved in $SET_SRC" >&2; exit 1; }
  cp "$STYLE_SRC" "$REPO/scripts/term-style.sh"
  write_state_shim
  cp "$ADVISOR_OWNER_LIB_SRC" "$REPO/scripts/advisor-owner-lib.sh"
  cp "$REPO_DIR/scripts/fleet-trust-split.sh" "$REPO/scripts/fleet-trust-split.sh"
  sed -e "s#^DA_UNIT_DIR=/etc/systemd/system\$#DA_UNIT_DIR=${UNITS}#" -e "s#^DA_UPDATE_CONF=/etc/aperire/update.conf\$#DA_UPDATE_CONF=${DA_TEST_UPDATE_CONF:-/nonexistent/update.conf}#" \
      "$DASH_ACCOUNT_LIB_SRC" > "$REPO/scripts/dashboard-account-lib.sh"
  grep -q "^DA_UNIT_DIR=${UNITS}\$" "$REPO/scripts/dashboard-account-lib.sh" \
    || { echo "DA_UNIT_DIR rewrite did not land; the assignment line moved in $DASH_ACCOUNT_LIB_SRC" >&2; exit 1; }
  for f in "$BACKUP_SRC" "$RESTORE_SRC"; do
    sed -e "s#^NEEDS_ROOT=1\$#NEEDS_ROOT=0#" \
        -e "s#^PROC_DIR=/proc\$#PROC_DIR=${FAKE_PROC}#" \
        -e "s#^RELAY_BIN_INSTALLED=/usr/local/bin/aperire-relay\$#RELAY_BIN_INSTALLED=${TMP}/usr-local-bin/aperire-relay#" \
        "$f" > "$REPO/scripts/$(basename "$f")"
    grep -q "^NEEDS_ROOT=0\$" "$REPO/scripts/$(basename "$f")" \
      || { echo "NEEDS_ROOT rewrite did not land in $f" >&2; exit 1; }
    chmod +x "$REPO/scripts/$(basename "$f")"
  done
  grep -q "^RELAY_BIN_INSTALLED=${TMP}/usr-local-bin/aperire-relay\$" "$REPO/scripts/$(basename "$RESTORE_SRC")" \
    || { echo "RELAY_BIN_INSTALLED rewrite did not land in $RESTORE_SRC" >&2; exit 1; }
  grep -q "^PROC_DIR=${FAKE_PROC}\$" "$REPO/scripts/$(basename "$RESTORE_SRC")" \
    || { echo "PROC_DIR rewrite did not land in $RESTORE_SRC" >&2; exit 1; }
}

unit() {  # <name> <working-dir-or-empty> <user> [extra ExecStart suffix]
  local name=$1 wd=$2 user=$3 extra=${4:-}
  {
    echo "[Service]"
    [[ -n "$wd" ]] && echo "WorkingDirectory=$wd"
    [[ -n "$extra" ]] && echo "ExecStart=$extra"
    echo "User=$user"
  } > "$UNITS/$name.service"
}

mk_db() {  # <path> [marker, distinguishes one instance's db from another's]
  local marker="${2:-plain}"
  sqlite3 "$1" "CREATE TABLE auth_users(id INTEGER); INSERT INTO auth_users VALUES(1),(2);"
  sqlite3 "$1" "CREATE TABLE auth_credentials(id INTEGER); INSERT INTO auth_credentials VALUES(1);"
  sqlite3 "$1" "CREATE TABLE alerts_history(id INTEGER);"
  sqlite3 "$1" "CREATE TABLE test_marker(v TEXT); INSERT INTO test_marker VALUES('$marker');"
}

# A plain dashboard, nothing else.
mk_plain() {
  mk_tree
  mk_db "$REPO/data/aperire.db"
  printf 'authn: {v: 1}\n'   > "$REPO/dashboard/config/authn.yaml"
  printf 'channels: {v: 1}\n' > "$REPO/dashboard/config/channels.yaml"
  printf 'digest: {v: 1}\n'  > "$REPO/dashboard/config/digest.yaml"
  printf 'rules: {v: 1}\n'   > "$REPO/dashboard/config/rules.local.yaml"
  printf 'PORT=7900\nRELAY_TOKENS=deadbeef\n' > "$ETC/aperire/aperire.env"
  chmod 640 "$ETC/aperire/aperire.env"
  unit aperire-server "$REPO/dashboard" "$CALLER_USER"
  systemctl_mark_active aperire-server
}

systemctl_mark_active() { : > "$FAKE_SYSTEMCTL_STATE/$1.active"; }

# Dashboard + co-located relay + Advisor + fleet member.
mk_full() {
  mk_plain
  printf 'auth_token = "deadbeef"\n' > "$ETC/aperire/relay.conf"
  chmod 640 "$ETC/aperire/relay.conf"
  unit aperire-relay "" "$CALLER_USER"
  systemctl_mark_active aperire-relay

  printf 'label: stock-node1\n' > "$REPO/dashboard/config/fleet.yaml"
  printf 'pin: abc123\n'        > "$REPO/dashboard/config/fleet-trust.yaml"
  printf '{"token":"link-secret"}\n' > "$REPO/dashboard/config/fleet-link.json"
  chmod 600 "$REPO/dashboard/config/fleet.yaml" "$REPO/dashboard/config/fleet-trust.yaml" \
    "$REPO/dashboard/config/fleet-link.json"

  printf 'BEGIN PUBLIC KEY-----fake-----\n' > "$ETC/aperire/fleet-arm.pub"
  chmod 644 "$ETC/aperire/fleet-arm.pub"

  mkdir -p "$REPO/advisor/state"
  printf 'approve-token\n' > "$REPO/advisor/state/approve.token"
  printf 'read-token\n'    > "$REPO/advisor/state/read.token"
  printf '{"seq":1}\n{"seq":2}\n{"seq":3}\n' > "$REPO/advisor/state/ledger.jsonl"
  printf '{"model":"claude"}\n' > "$REPO/advisor/state/model.json"
  chmod 750 "$REPO/advisor/state"
  chmod 640 "$REPO/advisor/state"/*
  chgrp "$ALT_GROUP" "$REPO/advisor/state" "$REPO/advisor/state/approve.token" \
    "$REPO/advisor/state/read.token" 2>/dev/null || true

  unit aperire-advisord "" "$CALLER_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
  systemctl_mark_active aperire-advisord
  # Every host with the Advisor also has its OnFailure= handler (#541), which
  # runs User=root by design. '-' sorts before '.', so a glob over
  # aperire-advisord*.service lists it first, and a resolver that took the
  # first match read the Advisor's account as root (#809).
  unit aperire-advisord-credcheck "" root "/usr/local/sbin/aperire-advisord-credcheck"

  mkdir -p "$ETC/aperire/creds"
  chmod 700 "$ETC/aperire/creds"
  printf 'sealed\n' > "$ETC/aperire/creds/model-api-key-anthropic"
  chmod 600 "$ETC/aperire/creds/model-api-key-anthropic"
}

run_backup() {  # $@ = extra args, DEST already exported
  ( cd "$REPO" && bash "$REPO/scripts/aperire-backup.sh" --to "$DEST" --yes "$@" )
}

# dash_pid_opens <db-path> - fakes a running dashboard whose MainPID has
# <db-path> open on a file descriptor, the shape /proc/<pid>/fd/N -> target
# takes on a real host (#561). Called automatically by run_restore below
# with the path this fixture's OWN env files say is correct, so an ordinary
# round-trip test sees a dashboard that opened the right file, the way a
# real one would; a test can call this again after run_restore's own call
# to point the fd somewhere else and prove the closing check catches it.
DASH_FAKE_PID=4242
dash_pid_opens() {  # <db-path>
  rm -rf "${FAKE_PROC:?}/$DASH_FAKE_PID"
  mkdir -p "$FAKE_PROC/$DASH_FAKE_PID/fd"
  ln -s "$1" "$FAKE_PROC/$DASH_FAKE_PID/fd/9"
  export FAKE_MAINPID="$DASH_FAKE_PID"
}
# fixture_expected_db <suffix> -> the database path a real dashboard would
# open once THIS restore finishes: the set's own aperire.env when $FROM
# carries one (the restore is about to install it over the live file), the
# live file otherwise. Worked out independently of the product's own
# bkset_db_path_from_env rather than by calling it, so this fixture proves
# the SUT's answer against a separate calculation, not against itself; it
# mirrors the SUT's own decision (#561) because that is the fact being
# simulated, not the code being tested.
fixture_expected_db() {  # <suffix, "" or "node2">
  local s=${1:+-$1} envp dbp
  envp="$FROM/aperire.env"
  if [[ ! -f "$envp" ]]; then
    envp="$ETC/aperire/aperire${s}.env"
    [[ -f "$envp" ]] || envp="$ETC/aperire/aperire.env"
  fi
  dbp="$(awk -F= '$1=="APERIRE_DB_PATH"{sub(/^[^=]*=/,""); print; exit}' "$envp" 2>/dev/null)"
  [[ -n "$dbp" ]] || dbp="$REPO/data/aperire${s}.db"
  printf '%s\n' "$dbp"
}
run_restore() {  # $@ = extra args, FROM already exported
  # --overwrite by default: every one of the pre-existing tests below built
  # its own "live" host with mk_plain/mk_full, a fixture db populated with
  # placeholder rows for reasons that have nothing to do with #562, and
  # expects its restore to proceed unconditionally the way it always did.
  # Only the dedicated #562 rows below call the SUT directly, without this,
  # to exercise the refusal itself.
  local inst="" i
  for ((i = 1; i <= $#; i++)); do
    [[ "${!i}" == --instance ]] && { local j=$((i + 1)); inst="${!j}"; }
  done
  dash_pid_opens "$(fixture_expected_db "$inst")"
  ( cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite "$@" )
}

echo "1. the one file table: the guide's own table names exactly what the script does"
# Set-equality on the Where column and a mode-substring check, not a full
# column parser (#544's own review: a full parser is brittle, and the
# defect this guards is a set mismatch, not a prose one, #535).
guide_table="$(awk '/^\| What \| Where \|/{f=1} f{print} f && /^$/{exit}' "$GUIDE")"
python3 - "$SET_SRC" > "$TMP/table.tsv" <<'PYEOF'
import re, sys
path = sys.argv[1]
rows = re.findall(r"^\s*'([^']*(?:'\"'\"'[^']*)*)'", open(path).read(), re.M)
for row in rows:
    row = row.replace("'\"'\"'", "'")
    cells = row.split('|')
    if len(cells) != 7:
        continue
    key, what, where, required, owner, mode, why = cells
    print(f"{key}\t{what}\t{where}\t{required}\t{mode}")
PYEOF
n_table_rows=0
while IFS=$'\t' read -r key what _ required mode; do
  n_table_rows=$((n_table_rows + 1))
  if [[ "$guide_table" == *"$what"* ]]; then
    ok "guide names the '$key' row ($what)"
  else
    bad "guide names the '$key' row" "not found: $what"
  fi
  row_line="$(grep -F -e "$what" <<<"$guide_table" | head -1)"
  has "guide's '$key' row states its required/optional column" "$row_line" "$required"
  [[ "$key" == node-config ]] || has "guide's '$key' row states its mode" "$row_line" "$mode"
done < "$TMP/table.tsv"
is "the guide's table has exactly as many data rows as the shared table" \
  "$(grep -c '^|' <<<"$guide_table" | awk '{print $1-2}')" "$n_table_rows"

echo
echo "2. backup discovers a plain host and takes only what applies"
mk_plain
build_sut
DEST="$TMP/set-plain"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
has "it reports the dashboard it found" "$out" "aperire-server (port 7900)"
has "it takes the database" "$out" "ok    database"
has "it takes the dashboard config" "$out" "ok    dashboard-config"
has "it skips the fleet config: not joined" "$out" "skip  fleet-config"
has "it skips the relay conf: no relay on this host" "$out" "skip  relay-conf"
has "it skips advisor state: none installed" "$out" "skip  advisor-state"
has "it verifies the set as the operator before declaring success" "$out" "verifies, read back as"
is "the set is 0700" "$(stat -c %a "$DEST")" "700"
is "the set is owned by the invoking operator, never root (#536)" "$(stat -c %U "$DEST")" "$CALLER_USER"

echo
echo "3. the manifest covers every file in the set, not a fraction of it (#536)"
n_files="$(find "$DEST" -type f ! -name MANIFEST.sha256 | wc -l | tr -d ' ')"
n_manifest="$(wc -l < "$DEST/MANIFEST.sha256" | tr -d ' ')"
is "MANIFEST.sha256 lists exactly as many files as the set holds" "$n_manifest" "$n_files"
( cd "$DEST" && sha256sum -c MANIFEST.sha256 ) >/tmp/tbr-verify.$$ 2>&1
is "and every one of them verifies" "$?" "0"
rm -f /tmp/tbr-verify.$$
is "no file in the set is group- or other-readable" \
  "$(find "$DEST" -perm -044 -o -perm -004 2>/dev/null | tr '\n' ' ')" ""

echo
echo "4. restore, straight onto a not-yet-installed host, refuses (rc=6) and names the port (#517)"
mk_tree     # a bare tree: no unit at all
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 6" "$rc" "6"
has "it names the one-liner" "$out" "curl -fsSL https://get.aperire.one | bash"
has "it carries the port the set recorded" "$out" "--port 7900"

echo
echo "5. round trip on a plain host: install fresh, restore, byte-identical content"
mk_plain
# The reinstalled host: same paths, fresh (different) content, no fleet or
# advisor files at all, which is what a fresh install actually looks like.
printf 'authn: {v: 0}\n'   > "$REPO/dashboard/config/authn.yaml"
printf 'channels: {v: 0}\n' > "$REPO/dashboard/config/channels.yaml"
rm -f "$REPO/data/aperire.db"
printf 'PORT=7900\nRELAY_TOKENS=freshtoken\n' > "$ETC/aperire/aperire.env"
build_sut
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
has "it stops the dashboard unit" "$out" "stopped: aperire-server"
has "it restores the database" "$out" "ok    database"
is "the database content is byte-identical to the backup" \
  "$(sha256sum < "$REPO/data/aperire.db")" "$(sha256sum < "$DEST/aperire.db")"
is "authn.yaml is byte-identical to the backup" \
  "$(cat "$REPO/dashboard/config/authn.yaml")" "$(cat "$DEST/config/authn.yaml")"
is "the relay env file is byte-identical to the backup" \
  "$(cat "$ETC/aperire/aperire.env")" "$(cat "$DEST/aperire.env")"
has "the closing checks ran and passed" "$out" "PASS  units active"
has "healthz passed" "$out" "PASS  healthz answers ok"
has "it says it never touched the node" "$out" "never read or wrote your node"

echo
echo "6. a second restore over an already-restored host changes nothing, and says so"
out=$(run_restore 2>&1); rc=$?
is "it still exits 0" "$rc" "0"
has "it reports no changes" "$out" "no files needed to change"

echo
echo "7. the fleet config: the backup carries all three files, the restore reads all three (#535)"
mk_full
# An aggregator on a host with no systemd-creds keeps its fleet model store
# in the clear (#711). Planted here so section 8 can say it never travels.
printf '{"v":1,"key":"sk-fleet-in-the-clear-0000"}' > "$ETC/aperire/fleet-model.cred.plain"
chmod 600 "$ETC/aperire/fleet-model.cred.plain"
build_sut
DEST="$TMP/set-full"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
has "it takes the fleet config as one row" "$out" "ok    fleet-config  -> $DEST/config/ (3 files)"
is "fleet.yaml is in the set" "$([[ -f "$DEST/config/fleet.yaml" ]] && echo yes || echo no)" "yes"
is "fleet-trust.yaml is in the set" "$([[ -f "$DEST/config/fleet-trust.yaml" ]] && echo yes || echo no)" "yes"
is "fleet-link.json is in the set" "$([[ -f "$DEST/config/fleet-link.json" ]] && echo yes || echo no)" "yes"

echo
echo "8. the model credential is never in the set, and the README says so (#514)"
is "no creds directory anywhere in the set" \
  "$(find "$DEST" -iname 'creds' -o -iname 'model-api-key*' 2>/dev/null | tr '\n' ' ')" ""
has "the README says it is sealed to this host's own key" "$(cat "$DEST/README")" "sealed against THIS host's own"
has "the README explains the fleet push is how the model comes back" "$(cat "$DEST/README")" "fleet push"
is "no fleet model store in the set, in either form (#711)" \
  "$(find "$DEST" -name 'fleet-model.cred*' 2>/dev/null | tr '\n' ' ')" ""
is "  and the key it holds is in no file of the set" \
  "$(grep -rl 'sk-fleet-in-the-clear-0000' "$DEST" 2>/dev/null | tr '\n' ' ')" ""
has "  and the README names it as left out on purpose, with the way back" "$(cat "$DEST/README")" "seal the fleet model again from Settings"

echo
echo "9. restore onto a host with no Advisor, from a set that carries one, refuses (rc=5)"
mk_plain
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 5" "$rc" "5"
has "it names the Advisor one-liner" "$out" "get.aperire.one/advisor"

echo
echo "10. restore onto a host that runs an Advisor, from a set that carries none, refuses (rc=5)"
mk_full
build_sut
DEST2="$TMP/set-noadvisor"
rm -rf "$REPO/advisor/state"
mkdir -p "$REPO/advisor/state"   # unit still present, state now empty -> host has no state to speak of, but unit IS installed
rm -f "$UNITS/aperire-advisord.service"
run_backup >/dev/null 2>&1  # DEST var stale here; rebuild explicitly
DEST="$DEST2"
out=$(run_backup 2>&1)
unit aperire-advisord "" "$CALLER_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
systemctl_mark_active aperire-advisord
FROM="$DEST2"
out=$(run_restore 2>&1); rc=$?
is "exit code is 5" "$rc" "5"
has "it explains the Advisor on this host would be left untouched" "$out" "leave that Advisor's own"
has "it names the remedy: remove the advisor or use a matching set" "$out" "role=advisor"

echo
echo "11. round trip with the Advisor: shared group survives, dashboard can still read the token (#537)"
mk_full
build_sut
DEST="$TMP/set-full2"
run_backup >/dev/null 2>&1
# The reinstalled host: same accounts, empty Advisor state (a fresh install).
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
rm -f "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-link.json}
rm -f "$ETC/aperire/fleet-arm.pub" "$ETC/aperire/relay.conf"
rm -f "$REPO/data/aperire.db"
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "ledger.jsonl content matches the backup" \
  "$(cat "$REPO/advisor/state/ledger.jsonl")" "$(cat "$DEST/advisor-state/ledger.jsonl")"
has "the account this host's Advisor unit names is used, not a stale one" "$out" "goes to '$CALLER_USER' here"
has "the dashboard's account can still read the Advisor's token" "$out" "PASS  the dashboard's account can read the Advisor's approve.token and read.token"
has "the ledger chain check passed" "$out" "PASS  the ledger chain verifies"

echo
echo "12. the Advisor's account is translated onto THIS host's own account, never copied from the backup (#515); its shared group is derived, not the split-account literal (#755)"
# A hand-built OWNERSHIP, the same shape a real backup writes, naming an old
# account ('old-advisor') that this fixture makes resolve on purpose, exactly
# the trap the field defect was: the name still exists, so a plain chown by
# name would succeed and be wrong.
#
# mk_full's Advisor unit runs as the SAME account as the dashboard
# ($CALLER_USER), the --advisor-shared-account (systemd<250) shape #755 is
# about: advisor_owner_moved reads that unit and says "not moved", so there
# is no split to share a group across, and the group that must land on the
# state dir and the two shared tokens is the account's own primary group,
# never the split-account install's aperire-svc, which this host never
# created.
mk_full
build_sut
DEST="$TMP/set-translate"
run_backup >/dev/null 2>&1
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
printf '{"seq":1}\n' > "$REPO/advisor/state/ledger.jsonl"
printf 'tok\n' > "$REPO/advisor/state/approve.token"
cat > "$DEST/OWNERSHIP" <<EOF
750 5000 5000 old-advisor aperire-svc $REPO/advisor/state
640 5000 5001 old-advisor old-advisor $REPO/advisor/state/ledger.jsonl
640 5000 5000 old-advisor aperire-svc $REPO/advisor/state/approve.token
EOF
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
export FAKE_USERS="old-advisor"
export FAKE_PRIMARY_GROUP="old-advisor=old-advisor"
# old-advisor's own private group resolves too, same as a leftover system
# account's usually would: OWNERSHIP naming it is not on its own grounds to
# refuse (that is test 13, a name nothing on this host recognizes at all).
export FAKE_GROUPS="aperire-svc old-advisor"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore still succeeds even though 'old-advisor' resolves on this host" "$rc" "0"
has "it names THIS host's own Advisor account, not the backup's" "$out" "goes to '$CALLER_USER' here, this host's own Advisor, not the backup's recorded owner"
# The write itself goes through state-file.py now (a real fchown/fchmod on a
# descriptor, #755 review), so what proves it landed right is the file's own
# real ownership on disk, not a shell chown log.
is "the state dir lands on this host's account and its OWN group, the shared-account answer, never aperire-svc" \
  "$(stat -c '%U:%G' "$REPO/advisor/state")" "$CALLER_USER:$CALLER_GROUP"
is "the ledger's group is translated too, not just its owner" \
  "$(stat -c '%U:%G' "$REPO/advisor/state/ledger.jsonl")" "$CALLER_USER:$CALLER_GROUP"
is "approve.token's group is the same account group here, not old-advisor's aperire-svc" \
  "$(stat -c '%U:%G' "$REPO/advisor/state/approve.token")" "$CALLER_USER:$CALLER_GROUP"
unset FAKE_USERS FAKE_PRIMARY_GROUP FAKE_GROUPS

echo
echo "12b. genuine split-account install: Advisor and dashboard are different accounts, tied by one group the unit itself names (#755)"
# install-advisor-account.sh's real shape: the Advisor moves to its OWN
# account, and the ONE thing tying it to the dashboard is that account's
# SupplementaryGroups= line in its own unit -- aperire-svc in a real install,
# a fake name here ('$ALT_GROUP', already a real group this test's own
# account belongs to, chosen at the top of this file). restore.sh reads that
# line straight (advisor-owner-lib.sh's advisor_owner_shared_group), never
# `id -nG`, so a fake account NAME is enough to prove the derivation is
# unit-driven -- but the account's numeric ids are mapped onto this test's
# own real uid/gid (FAKE_IDS, FAKE_PRIMARY_GROUP) so the real fchown two
# lines into the restore actually succeeds without root: an unprivileged
# caller may chgrp a file it owns to any group it is really a member of, and
# a same-uid chown is always a no-op POSIX allows.
if [[ "$ALT_GROUP" == "$CALLER_GROUP" ]]; then
  echo "  SKIP this test's own account belongs to only one real group; nothing here to tell shared and private groups apart with"
else
SPLIT_ADV_USER="aperire-advisor-test"
mk_full
unit aperire-advisord "" "$SPLIT_ADV_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
printf 'SupplementaryGroups=%s\n' "$ALT_GROUP" >> "$UNITS/aperire-advisord.service"
build_sut
DEST="$TMP/set-split"
export FAKE_USERS="$SPLIT_ADV_USER"
_my_uid="$(id -u)"
export FAKE_IDS="$SPLIT_ADV_USER=$_my_uid:$_my_uid"
export FAKE_PRIMARY_GROUP="$SPLIT_ADV_USER=$CALLER_GROUP"
run_backup >/dev/null 2>&1
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "split-account restore exits 0" "$rc" "0"
has "it names the split Advisor account, read from the unit, not the dashboard's" "$out" "goes to '$SPLIT_ADV_USER' here"
is "the state dir lands on the group the unit names as shared, not the Advisor's own private group" \
  "$(stat -c '%G' "$REPO/advisor/state")" "$ALT_GROUP"
is "approve.token lands on the shared group too" \
  "$(stat -c '%G' "$REPO/advisor/state/approve.token")" "$ALT_GROUP"
is "read.token lands on the shared group too" \
  "$(stat -c '%G' "$REPO/advisor/state/read.token")" "$ALT_GROUP"
is "ledger.jsonl, not one of the two shared names, stays on the Advisor's own private group" \
  "$(stat -c '%G' "$REPO/advisor/state/ledger.jsonl")" "$CALLER_GROUP"
unset FAKE_USERS FAKE_IDS FAKE_PRIMARY_GROUP
fi

echo
echo "12c. moved, but the unit names no shared group at all: refused before anything stops (#755)"
SPLIT_ADV_USER="aperire-advisor-test"
mk_full
unit aperire-advisord "" "$SPLIT_ADV_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
build_sut
DEST="$TMP/set-split-nogroup"
export FAKE_USERS="$SPLIT_ADV_USER"
_my_uid="$(id -u)"
export FAKE_IDS="$SPLIT_ADV_USER=$_my_uid:$_my_uid"
export FAKE_PRIMARY_GROUP="$SPLIT_ADV_USER=$CALLER_GROUP"
run_backup >/dev/null 2>&1
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 4" "$rc" "4"
has "it names the account that moved" "$out" "$SPLIT_ADV_USER"
has "it names the remedy" "$out" "--run advisor-account"
has "nothing was changed" "$out" "Nothing was changed"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
unset FAKE_USERS FAKE_IDS FAKE_PRIMARY_GROUP

echo
echo "12d. moved, and the unit names a group the dashboard is not actually in: refused, never a silent write (#755)"
if id -nG "$CALLER_USER" | tr ' ' '\n' | grep -qx root; then
  echo "  SKIP this test's own account is a member of 'root'; nothing here to prove against"
else
  SPLIT_ADV_USER="aperire-advisor-test"
  mk_full
  unit aperire-advisord "" "$SPLIT_ADV_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
  printf 'SupplementaryGroups=root\n' >> "$UNITS/aperire-advisord.service"
  build_sut
  DEST="$TMP/set-split-wronggroup"
  export FAKE_USERS="$SPLIT_ADV_USER"
  _my_uid="$(id -u)"
  export FAKE_IDS="$SPLIT_ADV_USER=$_my_uid:$_my_uid"
  export FAKE_PRIMARY_GROUP="$SPLIT_ADV_USER=$CALLER_GROUP"
  run_backup >/dev/null 2>&1
  FROM="$DEST"
  out=$(run_restore 2>&1); rc=$?
  is "exit code is 4" "$rc" "4"
  has "it names the group the dashboard is not in" "$out" "root"
  has "it says why: the dashboard could not read the Advisor's tokens" "$out" "could not read the Advisor's tokens"
  is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
  unset FAKE_USERS FAKE_IDS FAKE_PRIMARY_GROUP
fi

echo
echo "12e. a symlink planted at approve.token's name is replaced, never followed (ADR 0024)"
# The Advisor's own account (or, on a shared-account host, the dashboard's)
# could put a symlink at this name between a prior run and this restore.
# state-file.py's plant does the safe thing for a NAME it is asked to write:
# renameat replaces whatever sits there, atomically, and never resolves it
# first -- so the link is never followed and whatever it pointed at is never
# touched, but the name itself comes back a real, correctly-owned file
# rather than being left a dangling redirect. own_one (used for the
# directory itself and for a file already known to be legitimate) is the one
# that flatly refuses a symlink instead; the two verbs exist for these two
# different cases.
mk_full
build_sut
DEST="$TMP/set-symlink"
run_backup >/dev/null 2>&1
SENTINEL="$TMP/sentinel-$$"
printf 'do not touch me\n' > "$SENTINEL"
chmod 600 "$SENTINEL"
sentinel_before="$(stat -c '%U:%G:%a' "$SENTINEL"):$(sha256sum "$SENTINEL" | awk '{print $1}')"
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
ln -s "$SENTINEL" "$REPO/advisor/state/approve.token"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "the restore still succeeds" "$rc" "0"
sentinel_after="$(stat -c '%U:%G:%a' "$SENTINEL"):$(sha256sum "$SENTINEL" | awk '{print $1}')"
is "the sentinel's content, owner and mode are exactly as they were: the link was never followed" \
  "$sentinel_after" "$sentinel_before"
is "the planted link itself is gone, replaced by a real file rather than resolved into one" \
  "$([[ -L "$REPO/advisor/state/approve.token" ]] && echo yes || echo no)" "no"
is "the name now holds the set's own restored content, not the sentinel's" \
  "$(cat "$REPO/advisor/state/approve.token")" "$(cat "$DEST/advisor-state/approve.token")"
is "and it landed on the right group" "$(stat -c '%G' "$REPO/advisor/state/approve.token")" "$CALLER_GROUP"

echo
echo "12f. a symlink planted at advisor/state ITSELF is refused, not silently used as the directory (ADR 0024)"
# Unlike a single token name, the state directory is re-owned through
# mkdir_one/own_one, which DOES refuse outright when the name is not really
# a directory: 'mkdir -p' on an existing name follows a directory symlink
# (GNU coreutils checks with stat, which dereferences) and would otherwise
# have this restore write every token underneath it into wherever that link
# points.
mk_full
build_sut
DEST="$TMP/set-symlink-dir"
run_backup >/dev/null 2>&1
ELSEWHERE="$TMP/elsewhere-$$"
mkdir -p "$ELSEWHERE"
rm -rf "$REPO/advisor/state"
ln -s "$ELSEWHERE" "$REPO/advisor/state"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
if [[ $rc -ne 0 ]]; then ok "the restore refuses rather than writing under the linked directory"
else bad "the restore refuses rather than writing under the linked directory" "rc was 0"; fi
has "it says why" "$out" "is not a real directory"
is "nothing was written into the directory the link pointed at" "$(ls -A "$ELSEWHERE")" ""
is "the planted link itself is untouched" "$([[ -L "$REPO/advisor/state" ]] && echo yes || echo no)" "yes"
is "the dashboard was never stopped: this is caught before anything does" \
  "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"

echo
echo "12g. an ancestor directory writable by an account that is not its owner is refused, with the real repair named (#703, #755)"
# Not a link this time: the install tree itself (the koi shape) left group
# write on, which lets the account that owns it replace advisor/state's own
# parent out from under root. Caught by the same pre-stop ancestors() read,
# and the remedy this restore names is the one repair script that already
# exists for this exact rule (fix-state-ancestors.sh), never invented here.
mk_full
build_sut
DEST="$TMP/set-loose-ancestor"
run_backup >/dev/null 2>&1
chmod o+w "$REPO/advisor"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
chmod o-w "$REPO/advisor"
is "exit code is 4" "$rc" "4"
has "it names the update that repairs it, not a script in the tree (#886)" "$out" "curl -fsSL https://get.aperire.one | bash -s -- --update --force"
hasnt "and never runs a tree script as root to do it" "$out" "scripts/fix-state-ancestors.sh"
is "the dashboard was never stopped" \
  "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"

echo
echo "13. an account OWNERSHIP names that this host truly does not have is a note, never a refusal (#777)"
mk_plain
build_sut
DEST="$TMP/set-badaccount"
run_backup >/dev/null 2>&1
cat > "$DEST/OWNERSHIP" <<EOF
640 9999 9999 no-such-user-544 no-such-group-544 $ETC/aperire/aperire.env
EOF
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
rm -f "$REPO/data/aperire.db"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "the restore exits 0" "$rc" "0"
has "it names the missing user in a note" "$out" "user no-such-user-544"
has "and the missing group" "$out" "group no-such-group-544"
has "  saying nothing takes an owner from OWNERSHIP" "$out" "Nothing takes an owner from"
hasnt "it asks for no useradd" "$out" "useradd"
hasnt "  and no groupadd" "$out" "groupadd"
is "the env file lands on this host's own table all the same" "$(cat "$ETC/aperire/aperire.env")" "$(cat "$DEST/aperire.env")"
is "  at the table's mode" "$(stat -c %a "$ETC/aperire/aperire.env")" "640"

echo
echo "13b. a set from a host on the other account shape round-trips with no account created (#777)"
# #777: a set taken where the Advisor has its own account (aperire-advisor,
# aperire-svc) names those accounts in OWNERSHIP. Restored onto a host whose
# Advisor still runs on the retired shared account, nothing here ever
# creates them, and the restore used to refuse with a groupadd remedy. The
# reverse is the same refusal through the operator's login: a set from a
# host whose login has another name. Names that resolve nowhere, checked
# first, so the row cannot pass on an account this box happens to have.
SPLIT_A="split-advisor-777" SPLIT_G="split-svc-777" OLD_OP="old-operator-777"
if id -u "$SPLIT_A" >/dev/null 2>&1 || getent group "$SPLIT_G" >/dev/null 2>&1 || id -u "$OLD_OP" >/dev/null 2>&1; then
  bad "the #777 names resolve nowhere on this box" "$SPLIT_A $SPLIT_G $OLD_OP"
else
  mk_full
  build_sut
  DEST="$TMP/set-777"
  run_backup >/dev/null 2>&1
  # The set as the split host wrote it: the Advisor's state on its own
  # account and the shared group, the config on another operator login.
  awk -v a="$SPLIT_A" -v g="$SPLIT_G" -v o="$OLD_OP" -v st="$REPO/advisor/state" -v cf="$REPO/dashboard/config" '
    index($6, st) == 1 { $4 = a; $5 = ($6 == st || $6 ~ /\/(approve|read)\.token$/) ? g : a }
    index($6, cf) == 1 { $4 = o; $5 = o }
    { print }' "$DEST/OWNERSHIP" > "$DEST/OWNERSHIP.new"
  cat "$DEST/OWNERSHIP.new" > "$DEST/OWNERSHIP"; rm -f "$DEST/OWNERSHIP.new"
  ( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
  has "the set names the split accounts" "$(cat "$DEST/OWNERSHIP")" "$SPLIT_A $SPLIT_G $REPO/advisor/state"
  has "  and the other login" "$(cat "$DEST/OWNERSHIP")" "$OLD_OP $OLD_OP $REPO/dashboard/config/"
  rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
  printf 'changed\n' > "$REPO/dashboard/config/channels.yaml"
  FROM="$DEST"
  out=$(run_restore 2>&1); rc=$?
  is "the restore exits 0" "$rc" "0"
  hasnt "  and asks for no account to be created" "$out" "useradd"
  hasnt "  or group" "$out" "groupadd"
  has "it notes the accounts only the set knows" "$out" "user $SPLIT_A"
  is "the Advisor's ledger round-trips, byte for byte" \
    "$(cat "$REPO/advisor/state/ledger.jsonl" 2>/dev/null)" "$(cat "$DEST/advisor-state/ledger.jsonl")"
  is "  onto this host's own Advisor account" "$(stat -c %U "$REPO/advisor/state/ledger.jsonl")" "$CALLER_USER"
  is "the config round-trips too" "$(cat "$REPO/dashboard/config/channels.yaml")" "channels: {v: 1}"
  has "and the closing checks pass" "$out" "PASS  the ledger chain verifies"
fi

echo
echo "13c. this host's own Advisor account that does not resolve is refused before anything stops (#777)"
# With the set's names a note, what still has to exist is what the restore
# applies: this host's own Advisor account and its groups, read from its
# unit. Met only mid-restore, that was a stop with the services down.
GHOST_777="ghost-advisor-777"
if id -u "$GHOST_777" >/dev/null 2>&1; then
  bad "the #777 ghost account resolves nowhere on this box" "$GHOST_777"
elif [[ "$ALT_GROUP" == "$CALLER_GROUP" ]]; then
  echo "  SKIP this test's own account belongs to only one real group"
else
  mk_full
  build_sut
  DEST="$TMP/set-777c"
  run_backup >/dev/null 2>&1
  unit aperire-advisord "" "$GHOST_777" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
  printf 'SupplementaryGroups=%s\n' "$ALT_GROUP" >> "$UNITS/aperire-advisord.service"
  FROM="$DEST"
  out=$(run_restore 2>&1); rc=$?
  is "exit code is 4" "$rc" "4"
  has "it names the account this host's own unit runs as" "$out" "user $GHOST_777"
  is "the dashboard was never stopped" \
    "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
fi

echo
echo "13d. a set's relay.conf, no relay group, and a node on this host: refused before anything stops (#777, #826)"
# The set's own names used to catch this, by accident: OWNERSHIP named the
# relay's group, and a host without it refused. With those names a note, the
# relay's group is resolved from this host before anything stops instead,
# rather than met as a stop with the database already replaced.
mk_full
build_sut
DEST="$TMP/set-777d"
run_backup >/dev/null 2>&1
# As a real host records it: relay.conf root's, on the relay's own group.
awk -v f="$ETC/aperire/relay.conf" '$6 == f { $5 = "aperire-relay" } { print }' "$DEST/OWNERSHIP" > "$DEST/OWNERSHIP.new"
cat "$DEST/OWNERSHIP.new" > "$DEST/OWNERSHIP"; rm -f "$DEST/OWNERSHIP.new"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
has "the set records relay.conf on the relay's group" "$(cat "$DEST/OWNERSHIP")" "aperire-relay $ETC/aperire/relay.conf"
rm -f "$UNITS/aperire-relay.service"
_db_before="$(sha256sum < "$REPO/data/aperire.db")"
FROM="$DEST"
# The node: the node installer's record. No relay program anywhere yet.
printf 'KIND=container\nSERVICE=aperire-node\n' > "$ETC/aperire/node.conf"
rm -rf "$TMP/usr-local-bin" "$REPO/relay"
out=$(FAKE_ABSENT="aperire-relay" run_restore 2>&1); rc=$?
is "exit code is 4" "$rc" "4"
has "it names the relay's group" "$out" "no 'aperire-relay' group"
# #826: the steps that work on this host, by the bootstrap. Never the relay
# installer by its path in the tree, which on a host with no built relay
# only prints how to build one.
has "it names the step that builds the relay" "$out" \
  "curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run prepare-host --role co-located"
has "and the step that wires it beside this dashboard" "$out" \
  "curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run relay-colocated --unit aperire-server --port 7900 --binary $REPO/relay/aperire-relay"
hasnt "it never names the relay installer's file" "$out" "install-aperire-relay.sh"
is "the dashboard was never stopped" \
  "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
is "the database was never touched" "$(sha256sum < "$REPO/data/aperire.db")" "$_db_before"
# A relay program already installed is the one named, and nothing is built.
mkdir -p "$TMP/usr-local-bin"; printf '#!/bin/sh\n' > "$TMP/usr-local-bin/aperire-relay"; chmod 755 "$TMP/usr-local-bin/aperire-relay"
out=$(FAKE_ABSENT="aperire-relay" run_restore 2>&1); rc=$?
has "with a relay program installed, that one is named" "$out" "--run relay-colocated --unit aperire-server --port 7900 --binary $TMP/usr-local-bin/aperire-relay"
hasnt "and no build step is offered" "$out" "--run prepare-host"
rm -rf "$TMP/usr-local-bin" "$ETC/aperire/node.conf"
# The same host found by a node container instead of a record.
out=$(FAKE_ABSENT="aperire-relay" FAKE_DOCKER_PS="xrpllabsofficial/xrpld:2.4.0 xrpld" run_restore 2>&1); rc=$?
is "a node container is a node too: exit code is 4" "$rc" "4"
has "and the same step is named" "$out" "--run relay-colocated --unit aperire-server"

echo
echo "13e. a set's relay.conf, no relay group, and no node on this host: relay.conf is left out (#826)"
# A dashboard-only host has nothing for a relay to read. Refusing sent its
# operator to install a relay with no node to watch; the restore now goes on
# without that one file, and says so.
printf 'auth_token = "this-hosts-own"\n' > "$ETC/aperire/relay.conf"
_relay_before="$(sha256sum < "$ETC/aperire/relay.conf")"
out=$(FAKE_ABSENT="aperire-relay" run_restore 2>&1); rc=$?
is "exit code is 0" "$rc" "0"
has "it says why relay.conf is left out" "$out" "This host runs no node, so there is no relay here to read it, and it is left out."
has "and marks it skipped where the files are placed" "$out" "skip  relay.conf: this host runs no node"
hasnt "it offers no relay step on a host with no node" "$out" "--run relay-colocated"
is "this host's own relay.conf was not touched" "$(sha256sum < "$ETC/aperire/relay.conf")" "$_relay_before"

echo
echo "14. a set that fails its own manifest refuses (rc=3), before anything is touched"
mk_plain
build_sut
DEST="$TMP/set-corrupt"
run_backup >/dev/null 2>&1
echo "tampered" >> "$DEST/aperire.db"
mk_plain
build_sut
FROM="$DEST"
before_hash="$(sha256sum < "$REPO/data/aperire.db")"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
is "the local database is untouched" "$(sha256sum < "$REPO/data/aperire.db")" "$before_hash"

echo
echo "15. no MANIFEST.sha256 at all refuses (rc=3), by name"
mk_plain; build_sut
DEST="$TMP/set-nomanifest"
mkdir -p "$DEST"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it names the missing manifest" "$out" "MANIFEST.sha256"

echo
echo "16. the last step for the model is printed, not performed, and names both machines (#539)"
mk_full; build_sut
DEST="$TMP/set-arm"
run_backup >/dev/null 2>&1
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
build_sut
FROM="$DEST"
out=$(run_restore 2>&1)
has "it prints the node's own arm command" "$out" "sudo aperire-fleet-arm --node <this host's label>"
has "it prints the aggregator's own arm command too, not just one side" "$out" "sudo aperire-fleet-arm --self-only"
has "  and the update first for an aggregator whose grant predates the installed name" "$out" "curl -fsSL https://get.aperire.one | bash -s -- --update --force"
hasnt "  and never the arm script in the install tree (#812)" "$out" "scripts/aperire-fleet-arm.sh"
has "it says plainly that it does not run either" "$out" "This restore does not run either command"

echo
echo "17. --dry-run touches nothing, on both commands"
mk_plain; build_sut
DEST="$TMP/set-dry"
out=$(run_backup --dry-run 2>&1); rc=$?
is "backup --dry-run exits 0" "$rc" "0"
has "and writes nothing" "$([[ -e "$DEST" ]] && echo present || echo absent)" "absent"

mk_full; build_sut
DEST="$TMP/set-dry2"
run_backup >/dev/null 2>&1
mk_full; build_sut   # a host already fully installed
FROM="$DEST"
before_hash="$(sha256sum < "$ETC/aperire/aperire.env")"
out=$(run_restore --dry-run 2>&1); rc=$?
is "restore --dry-run exits 0" "$rc" "0"
has "it says nothing changed" "$out" "nothing changed"
is "the live env file is untouched" "$(sha256sum < "$ETC/aperire/aperire.env")" "$before_hash"

echo
echo "18. never reads or writes the node's own config or data directory"
mk_full
mkdir -p "$REPO/../node-store"
printf '[validator_token]\nSECRET\n' > "$TMP/rippled.cfg"
build_sut
DEST="$TMP/set-nonode"
run_backup >/dev/null 2>&1
is "the node's own config never appears anywhere in the set" \
  "$(grep -rl 'SECRET' "$DEST" 2>/dev/null | tr '\n' ' ')" ""
has "the README names the node row as the operator's to place" "$(cat "$DEST/README")" "node's own config"

echo
echo "19. --to refuses an existing non-empty directory, and a symlink (finding 100)"
mk_plain; build_sut
PREDEST="$TMP/preexisting-dest-544"
mkdir -p "$PREDEST"; echo "already here" > "$PREDEST/something"
DEST="$PREDEST"
out=$(run_backup 2>&1); rc=$?
is "backup refuses an existing non-empty --to" "$rc" "1"
has "it says why" "$out" "already exists and is not empty"
is "nothing was written into the existing directory" "$(cat "$PREDEST/something")" "already here"

LINKDEST="$TMP/dest-symlink-544"
ln -s "$TMP/somewhere-else-544" "$LINKDEST"
DEST="$LINKDEST"
out=$(run_backup 2>&1); rc=$?
is "backup refuses a --to that is a symlink" "$rc" "1"
has "it says why" "$out" "is a symlink"

# A directory above the parent of --to that anyone can write is refused before
# the set exists (#1150): the hand-over at the end would refuse it, with the
# whole set already written, and root went to / for its walk, which asks the
# directories above it nothing.
mkdir -p "$TMP/wide-1150/mid"
chmod 0777 "$TMP/wide-1150"
DEST="$TMP/wide-1150/mid/set"
out=$(run_backup 2>&1); rc=$?
chmod 0755 "$TMP/wide-1150"
is "backup refuses a --to under a directory anyone can write" "$rc" "1"
has "it names the directory" "$out" "wide-1150 is world-writable"
is "and nothing was written for the set" "$([[ -e "$DEST" ]] && echo exists || echo absent)" "absent"

# The same refusal when the parent of --to is not there yet (#1150): the check
# judges the nearest directory that exists, before install -d makes the chain,
# so nothing is created for a path the hand-over would refuse.
mkdir -p "$TMP/wide-1150b"
chmod 0777 "$TMP/wide-1150b"
DEST="$TMP/wide-1150b/new-a/new-b/set"
out=$(run_backup 2>&1); rc=$?
chmod 0755 "$TMP/wide-1150b"
is "backup refuses a --to whose parent does not exist, under a directory anyone can write" "$rc" "1"
has "it names the directory" "$out" "wide-1150b is world-writable"
is "and not even the missing parent was created" "$([[ -e "$TMP/wide-1150b/new-a" ]] && echo exists || echo absent)" "absent"

# The parent of --to is judged too (#1153). It is the directory root makes the
# set in on the operator's behalf, and it used to be the one directory the walk
# never asked about: only the world-writable-and-not-sticky test above looked
# at it. The real helper answers here; a group with another member cannot be
# made without root, so that row swaps in a copy of the helper whose
# membership test says the group has one.
mk_plain; build_sut
mkdir -p "$TMP/par-1153a" "$TMP/par-1153b" "$TMP/par-1153c" "$TMP/par-1153d"
chmod 0775 "$TMP/par-1153a"
DEST="$TMP/par-1153a/set"
out=$(run_backup 2>&1); rc=$?
is "backup goes into a 0775 parent in the account's own private group, the layout umask 002 makes" "$rc" "0"
is "  and the set is there" "$([[ -d "$DEST" ]] && echo there || echo absent)" "there"

# The operator is the one account besides root the directories above the set may
# belong to (the review of #1207): the set, the arm key included, goes to the
# operator, and a third account that owns one of them can rename what is under
# it before a restore. The operator here is another account than the one that
# owns this fixture, so every directory of it reads as a third account's.
DEST="$TMP/par-1153a/owner-set"
out=$(SUDO_USER=nobody run_backup 2>&1); rc=$?
is "backup refuses a --to under directories a third account owns" "$rc" "1"
has "  it says who they belong to" "$out" "belongs to root or uid $(id -u nobody)"
has "  and it is the check made before the set is built, not the hand-over's" "$out" "so root will not hand the set over through it"
is "  and nothing was written for the set" "$([[ -e "$DEST" ]] && echo exists || echo absent)" "absent"

sed 's/^    key = (gid, uid)$/    return False  # a test copy: the group has another member\n    key = (gid, uid)/' "$STATE_FILE_SRC" > "$REPO/scripts/state-file.real.py"
chmod 0775 "$TMP/par-1153b"
DEST="$TMP/par-1153b/set"
out=$(run_backup 2>&1); rc=$?
is "backup refuses a --to whose parent a group with another member can write" "$rc" "1"
has "  it names the parent" "$out" "$TMP/par-1153b is writable by group"
has "  it names the command that fixes it" "$out" "run: sudo chmod go-w $TMP/par-1153b"
has "  and it is the check made before the set is built, not the hand-over's" "$out" "so root will not hand the set over through it"
is "  and nothing was written for the set" "$([[ -e "$DEST" ]] && echo exists || echo absent)" "absent"
DEST="$TMP/par-1153b/new-a/new-b/set"
out=$(run_backup 2>&1); rc=$?
is "  the same when the parent is not there yet: the nearest directory that is gets judged" "$rc" "1"
has "  also before the set is built" "$out" "so root will not hand the set over through it"
is "  and not even the missing parent was made" "$([[ -e "$TMP/par-1153b/new-a" ]] && echo exists || echo absent)" "absent"
cp "$STATE_FILE_SRC" "$REPO/scripts/state-file.real.py"

# The hand-over agrees with the up-front check on its own: the parent is
# widened after the check has passed, and the copy refuses it (without the
# flag on the copy, the set would be placed into a directory anyone can write).
chmod 0755 "$TMP/par-1153c"
DEST="$TMP/par-1153c/set"
out=$(FAKE_WIDEN_BEFORE_COPY=777 run_backup 2>&1); rc=$?
widened="$(stat -c '%a' "$TMP/par-1153c")"
chmod 0755 "$TMP/par-1153c"
is "the parent widened to anyone-can-write after the check passed: the hand-over refuses it" "$([[ $rc -ne 0 ]] && echo refused || echo "went through ($rc)")" "refused"
is "  with the parent really at 777 when it did" "$widened" "777"
has "  naming the parent and the command" "$out" "run: sudo chmod go-w $TMP/par-1153c"
is "  and no set was placed" "$([[ -e "$DEST" ]] && echo exists || echo absent)" "absent"

echo
echo "20. a widened recorded mode in OWNERSHIP is ignored, never applied, and reported (finding 097a)"
mk_plain; build_sut
DEST="$TMP/set-widenmode"
run_backup >/dev/null 2>&1
awk -v p="$ETC/aperire/aperire.env" '{ if ($NF==p) $1="644"; print }' "$DEST/OWNERSHIP" > "$DEST/OWNERSHIP.new"
mv "$DEST/OWNERSHIP.new" "$DEST/OWNERSHIP"
chmod 600 "$DEST/OWNERSHIP"  # a real set is locked down; the rewrite above made a fresh inode
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore still succeeds" "$rc" "0"
has "it reports the disagreement" "$out" "OWNERSHIP recorded"
is "the restored file's mode is the table's own 640, never the recorded 644" \
  "$(stat -c %a "$ETC/aperire/aperire.env")" "640"

echo
echo "21. a manifest path containing .. is refused, nothing written (finding 097b)"
mk_plain; build_sut
DEST="$TMP/set-dotdot"
run_backup >/dev/null 2>&1
printf '%s  ../../etc/passwd-544\n' "$(printf 'x' | sha256sum | awk '{print $1}')" >> "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
before_hash="$(sha256sum < "$REPO/data/aperire.db")"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it names the unsafe path" "$out" "unsafe path"
is "the local database is untouched" "$(sha256sum < "$REPO/data/aperire.db")" "$before_hash"

echo
echo "22. an unmanifested symlink in the set is refused, nothing written (finding 097c)"
mk_plain; build_sut
DEST="$TMP/set-symlink"
run_backup >/dev/null 2>&1
ln -s /etc/passwd "$DEST/evil-link-544"
mk_plain; build_sut
FROM="$DEST"
before_hash="$(sha256sum < "$REPO/data/aperire.db")"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it names the symlink" "$out" "symbolic link"
is "the local database is untouched" "$(sha256sum < "$REPO/data/aperire.db")" "$before_hash"

echo
echo "23. a set with a file the manifest never named is refused (finding 097)"
mk_plain; build_sut
DEST="$TMP/set-extra"
run_backup >/dev/null 2>&1
echo "extra" > "$DEST/config/extra-file-544.yaml"
chmod 600 "$DEST/config/extra-file-544.yaml"  # closed like a real set's files, so
                                               # only the manifest-membership check can catch this one
mk_plain; build_sut
FROM="$DEST"
before_hash="$(sha256sum < "$REPO/data/aperire.db")"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it names the file the manifest never listed" "$out" "is in the set and is not named in MANIFEST.sha256"
is "the local database is untouched" "$(sha256sum < "$REPO/data/aperire.db")" "$before_hash"

echo
echo "24. a failing mid-restore step stops, keeps the safety copy, prints no PASS line (finding 099)"
mk_plain; build_sut
DEST="$TMP/set-baddb"
run_backup >/dev/null 2>&1
echo "not a real sqlite database" > "$DEST/aperire.db"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits non-zero" "$rc" "1"
has "it names the failing step" "$out" "does not pass integrity_check"
has "it says services are left stopped" "$out" "services are left stopped"
has "it points at the safety copy" "$out" "safety copy"
hasnt "no PASS line appears after a mid-restore failure" "$out" "PASS  "
safety_dir="$(find "$REPO-restore-safety" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | LC_ALL=C sort | tail -1)"
is "the safety copy directory exists" "$([[ -n "$safety_dir" && -d "$safety_dir" ]] && echo yes || echo no)" "yes"
is "the safety copy holds the pre-restore database" \
  "$([[ -n "$safety_dir" && -f "$safety_dir/database/aperire.db" ]] && echo yes || echo no)" "yes"

echo
echo "25. --instance keeps two dashboards on one host from colliding (finding 098)"
mk_plain
printf 'PORT=7901\nRELAY_TOKENS=node2token\n' > "$ETC/aperire/aperire-node2.env"
chmod 640 "$ETC/aperire/aperire-node2.env"
mk_db "$REPO/data/aperire-node2.db" node2-marker
unit aperire-server-node2 "$REPO/dashboard" "$CALLER_USER"
systemctl_mark_active aperire-server-node2
build_sut
DEST="$TMP/set-node2"
out=$(run_backup --instance node2 2>&1); rc=$?
is "backup --instance node2 exits 0" "$rc" "0"
is "it takes node2's own env file, not instance one's" \
  "$(cat "$DEST/aperire.env")" "$(cat "$ETC/aperire/aperire-node2.env")"
# Not a byte comparison: VACUUM INTO (how the backup takes the database) does
# not reproduce the source file byte for byte even for identical content, so
# this checks the row a plain copy would carry unchanged instead.
is "it takes node2's own database, not instance one's" \
  "$(sqlite3 "$DEST/aperire.db" "SELECT v FROM test_marker")" "node2-marker"

before_one_env="$(sha256sum < "$ETC/aperire/aperire.env")"
before_one_db="$(sha256sum < "$REPO/data/aperire.db")"
FROM="$DEST"
out=$(run_restore --instance node2 2>&1); rc=$?
is "restore --instance node2 exits 0" "$rc" "0"
is "instance one's env file is untouched" "$(sha256sum < "$ETC/aperire/aperire.env")" "$before_one_env"
is "instance one's database is untouched" "$(sha256sum < "$REPO/data/aperire.db")" "$before_one_db"
is "node2's own env file now matches the set" \
  "$(sha256sum < "$ETC/aperire/aperire-node2.env")" "$(sha256sum < "$DEST/aperire.env")"
is "node2's own database now matches the set" \
  "$(sha256sum < "$REPO/data/aperire-node2.db")" "$(sha256sum < "$DEST/aperire.db")"

echo
echo "26. an OWNERSHIP row whose path contains .. is refused, the way the manifest refuses it (#566)"
mk_plain; build_sut
DEST="$TMP/set-ownership-dotdot"
run_backup >/dev/null 2>&1
printf '640 0 1000 root aperire %s/dashboard/config/../../../../etc/shadow\n' "$REPO" >> "$DEST/OWNERSHIP"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
before_hash="$(sha256sum < "$REPO/data/aperire.db")"
out=$(run_restore 2>&1); rc=$?
is "exit code is 2" "$rc" "2"
has "it names the unsafe path" "$out" "unsafe path"
is "the local database is untouched" "$(sha256sum < "$REPO/data/aperire.db")" "$before_hash"

echo
echo "27. the backup names the node recorded in node.conf alone, no node-wrapper.conf on this host (#564)"
mk_plain; build_sut
printf 'KIND=container\nSERVICE=aperire-node\n' > "$ETC/aperire/node.conf"
DEST="$TMP/set-nodeconf"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
has "it names the node, not 'not detected'" "$out" "node: container (aperire-node)"
hasnt "it never says not detected when node.conf names one" "$out" "not detected"
has "the README also names it" "$(cat "$DEST/README")" "node: container (aperire-node)"

echo
echo "28. a widened recorded mode is reported for a config file too, not only the env file (#565)"
mk_full; build_sut
DEST="$TMP/set-widenmode-cfg"
run_backup >/dev/null 2>&1
awk -v p="$REPO/dashboard/config/digest.yaml" '{ if ($NF==p) $1="644"; print }' "$DEST/OWNERSHIP" > "$DEST/OWNERSHIP.new"
mv "$DEST/OWNERSHIP.new" "$DEST/OWNERSHIP"
chmod 600 "$DEST/OWNERSHIP"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_full; build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore still succeeds" "$rc" "0"
has "it reports the disagreement for digest.yaml, not only the env file" "$out" "OWNERSHIP recorded $REPO/dashboard/config/digest.yaml"
is "the restored file's mode is the table's own 640, never the recorded 644" \
  "$(stat -c %a "$REPO/dashboard/config/digest.yaml")" "640"

echo
echo "29. --from applies the same parent-directory rule --to already has (#563)"
mk_plain; build_sut
DEST="$TMP/set-563"
run_backup >/dev/null 2>&1
UNSAFE_PARENT="$TMP/pub-563"
mkdir -p "$UNSAFE_PARENT"; chmod 777 "$UNSAFE_PARENT"
cp -a "$DEST" "$UNSAFE_PARENT/set"
chmod 700 "$UNSAFE_PARENT/set"
FROM="$UNSAFE_PARENT/set"
out=$(run_restore 2>&1); rc=$?
is "restore refuses a set kept under an unsafe parent" "$rc" "3"
has "it names the parent" "$out" "parent of --from"

echo
echo "30. the private staging copy is removed on every exit path (#563), staged beside the install (finding 3)"
# The staging area lives at "$REPO-restore-work" now, not under $TMPDIR (a
# large set used to double into /tmp, which is RAM on a host where it is
# tmpfs): watch that directory directly on all three exit paths, rather than
# a $TMPDIR redirect, which would pass vacuously now that the SUT no longer
# reads $TMPDIR for this at all.
WORKROOT="$REPO-restore-work"
mk_full; build_sut
DEST="$TMP/set-563-ok"
run_backup >/dev/null 2>&1
mk_full; build_sut
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
rm -rf "$WORKROOT"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes 2>&1); rc=$?
is "a clean restore exits 0" "$rc" "0"
is "no staging directory is left behind after a clean run" \
  "$(find "$WORKROOT" -mindepth 1 -maxdepth 1 2>/dev/null | tr '\n' ' ')" ""

mk_plain; build_sut
DEST="$TMP/set-563-refuse"
run_backup >/dev/null 2>&1
echo "tampered" >> "$DEST/aperire.db"
mk_plain; build_sut
FROM="$DEST"
rm -rf "$WORKROOT"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes 2>&1); rc=$?
is "a refused set exits 3" "$rc" "3"
is "no staging directory is left behind after a refusal" \
  "$(find "$WORKROOT" -mindepth 1 -maxdepth 1 2>/dev/null | tr '\n' ' ')" ""

mk_plain; build_sut
DEST="$TMP/set-563-fail"
run_backup >/dev/null 2>&1
echo "not a real sqlite database" > "$DEST/aperire.db"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
rm -rf "$WORKROOT"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite 2>&1); rc=$?
is "a forced mid-restore failure exits 1" "$rc" "1"
is "no staging directory is left behind after a mid-restore failure" \
  "$(find "$WORKROOT" -mindepth 1 -maxdepth 1 2>/dev/null | tr '\n' ' ')" ""

echo
echo "31. a restore onto a host that moved its database with APERIRE_DB_PATH lands it at the moved path, not the default (#561)"
mk_plain; build_sut
rm -f "$REPO/data/aperire.db"
mkdir -p "$REPO/data/moved"
mk_db "$REPO/data/moved/aperire.db" "moved-host"
printf 'PORT=7900\nRELAY_TOKENS=deadbeef\nAPERIRE_DB_PATH=%s/data/moved/aperire.db\n' "$REPO" > "$ETC/aperire/aperire.env"
DEST="$TMP/set-561-moved"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
is "the set's OWNERSHIP names the moved path" \
  "$(grep -c -e "$REPO/data/moved/aperire.db" "$DEST/OWNERSHIP")" "1"

# The bare, freshly reinstalled host: its own fresh default database
# (marker "plain") and default env, exactly what curl | bash leaves behind
# before this restore runs (test 5's own fixture shape); the moved path
# does not exist yet.
mk_plain; build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "the database lands at the moved path, with the set's own content" \
  "$(sqlite3 "$REPO/data/moved/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "moved-host"
is "the freshly reinstalled host's own default database is untouched" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "plain"
has "the closing check confirms the running dashboard has it open, with the row count" \
  "$out" "PASS  the running dashboard has the restored database open"

echo
echo "32. a planted regression (deciding the destination from the live env, not the set's) turns the new closing check red"
# The same SUT, patched in place so only the DB_DEST line reverts to the
# ordering #561 fixed: decided from bkset_db_path (this host's LIVE env
# file, before the set's own copy has landed) rather than
# bkset_db_path_from_env (the env file that will be in force). Everything
# else, including the env-file restore step itself, is untouched, so this
# proves the closing check catches exactly the defect #561 describes, not
# a stand-in for it.
mk_plain; build_sut
# Single-quoted on purpose: this is the literal text to find and replace
# inside the SUT's own source, not an expression for this shell to expand.
# shellcheck disable=SC2016
sed -i 's#DB_DEST="\$(bkset_db_path_from_env "\$REPO_DIR" "\$INSTANCE" "\${RESTORE_ENV_SRC:-}")"#DB_DEST="\$(bkset_db_path "\$REPO_DIR" "\$INSTANCE")"#' \
  "$REPO/scripts/aperire-restore.sh"
# shellcheck disable=SC2016
grep -q 'DB_DEST="\$(bkset_db_path "\$REPO_DIR" "\$INSTANCE")"' "$REPO/scripts/aperire-restore.sh" \
  || { echo "the DB_DEST line to revert was not found; the line moved in scripts/aperire-restore.sh" >&2; exit 1; }
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite 2>&1); rc=$?
is "the regressed restore exits non-zero on the failed closing check" "$rc" "1"
hasnt "the new closing check does not pass" "$out" "PASS  the running dashboard has the restored database open"
has "the new closing check fails, named" "$out" "FAIL  the running dashboard has the restored database open"
has "it names the dashboard's own env-derived path as not the one open" "$out" "does not have"
is "the regression wrote the set's content to the default path instead of the moved one" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "moved-host"
is "the moved path, the set's own recorded destination, was never touched by the regressed run" \
  "$([[ -e "$REPO/data/moved/aperire.db" ]] && echo present || echo absent)" "absent"

echo
echo "33. identical content (a VACUUM INTO reformat is not drift) needs no --overwrite (#562)"
mk_plain; build_sut
DEST="$TMP/set-562-identical"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes 2>&1); rc=$?
is "restore exits 0 with no --overwrite, since nothing has changed since the backup" "$rc" "0"
hasnt "it never asks about a database that has moved on" "$out" "moved on"

echo
echo "34. a database with real content of its own refuses without --overwrite, and proceeds with it after a safety copy (#562)"
mk_plain; build_sut
DEST="$TMP/set-562-diverge"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
# Real usage since the backup: an operator enrolled.
sqlite3 "$REPO/data/aperire.db" "INSERT INTO auth_users VALUES(99);"
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes 2>&1); rc=$?
is "exit code is 7 without --overwrite" "$rc" "7"
has "it says what it is about to overwrite, in row counts" "$out" "row(s) total"
has "it names the remedy" "$out" "--overwrite"
is "the live database is untouched" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT COUNT(*) FROM auth_users")" "3"

dash_pid_opens "$(fixture_expected_db "")"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite 2>&1); rc=$?
is "with --overwrite it proceeds and exits 0" "$rc" "0"
has "it takes a safety copy before overwriting" "$out" "safety copy"
is "the database is rolled back to the set's own content" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT COUNT(*) FROM auth_users")" "2"

echo
echo "35. a second restore after that, with nothing changed since, says nothing to do (#562)"
dash_pid_opens "$(fixture_expected_db "")"
out=$(cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes 2>&1); rc=$?
is "exits 0, no --overwrite needed" "$rc" "0"
has "it reports no changes" "$out" "no files needed to change"

echo
echo "36. a set whose env file names an authorized_keys-shaped APERIRE_DB_PATH is refused (rc=8), nothing created"
# The crafted value: an account's own .ssh directory, which does not exist
# yet, the exact shape a set carrying a stray key line would need root to
# create for it. A table (this host's own install root) decides every
# destination; a set supplies content only.
mk_plain; build_sut
DEST="$TMP/set-8-authorizedkeys"
run_backup >/dev/null 2>&1
FAKE_HOME="$TMP/home-account-8"
mkdir -p "$FAKE_HOME"
printf 'APERIRE_DB_PATH=%s/.ssh/authorized_keys\n' "$FAKE_HOME" >> "$DEST/aperire.env"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 8" "$rc" "8"
has "it names the install root" "$out" "$REPO"
has "it names the remedy" "$out" "--db-path"
is "no .ssh directory was ever created for the crafted account" \
  "$([[ -d "$FAKE_HOME/.ssh" ]] && echo present || echo absent)" "absent"

echo
echo "37. an /etc/shadow-shaped APERIRE_DB_PATH never reaches an rm, proven with a sentinel standing in for it"
mk_plain; build_sut
DEST="$TMP/set-8-shadowlike"
run_backup >/dev/null 2>&1
SENTINEL="$TMP/etc-shadow-8-sentinel"
printf 'root:!:19000:0:99999:7:::\n' > "$SENTINEL"
chmod 600 "$SENTINEL"
printf 'APERIRE_DB_PATH=%s\n' "$SENTINEL" >> "$DEST/aperire.env"
( cd "$DEST" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/MANIFEST.sha256"
mk_plain; build_sut
FROM="$DEST"
before_sentinel="$(cat "$SENTINEL")"
out=$(run_restore 2>&1); rc=$?
is "exit code is 8" "$rc" "8"
is "the sentinel standing in for /etc/shadow is never removed or rewritten" \
  "$(cat "$SENTINEL" 2>/dev/null)" "$before_sentinel"

echo
echo "38. --db-path to an existing file that is not a SQLite database is refused"
mk_plain; build_sut
DEST="$TMP/set-dbpath-nonsqlite"
run_backup >/dev/null 2>&1
mk_plain; build_sut
NONSQLITE="$REPO/data/not-a-db-8.db"
printf 'plain text, not a database\n' > "$NONSQLITE"
FROM="$DEST"
out=$(run_restore --db-path "$NONSQLITE" 2>&1); rc=$?
is "exit code is 2" "$rc" "2"
has "it names the SQLite header it expected" "$out" "SQLite format 3"
is "the non-SQLite file at --db-path is untouched" "$(cat "$NONSQLITE")" "plain text, not a database"

echo
echo "38b. --db-path to another project's SQLite database is refused"
mk_plain; build_sut
DEST="$TMP/set-dbpath-foreign"
run_backup >/dev/null 2>&1
mk_plain; build_sut
FOREIGN="$REPO/data/other-project.db"
sqlite3 "$FOREIGN" "CREATE TABLE trades(id INTEGER); INSERT INTO trades VALUES (7);"
before_foreign="$(sha256sum "$FOREIGN" | cut -d' ' -f1)"
FROM="$DEST"
out=$(run_restore --db-path "$FOREIGN" 2>&1); rc=$?
is "exit code is 2" "$rc" "2"
is "the other project's database is untouched" "$(sha256sum "$FOREIGN" | cut -d' ' -f1)" "$before_foreign"

echo
echo "39. staging refuses when there is not enough free space beside the install"
mk_plain; build_sut
DEST="$TMP/set-lowspace"
run_backup >/dev/null 2>&1
mk_plain; build_sut
FROM="$DEST"
cat > "$BIN/df" <<'EOF'
#!/usr/bin/env bash
# Always claims almost no free space, regardless of what is asked, so the
# staging check has to refuse rather than attempt the copy.
echo "Avail"
echo "1024"
EOF
chmod +x "$BIN/df"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it says why" "$out" "not enough free space"
rm -f "$BIN/df"

echo
echo "40. the closing check PASSES while a background writer inserts into a growing table during the wait"
mk_plain; build_sut
DEST="$TMP/set-closingcheck-growing"
run_backup >/dev/null 2>&1
mk_plain; build_sut
sqlite3 "$REPO/data/aperire.db" "UPDATE test_marker SET v='not-yet-restored'"
FROM="$DEST"
LIVE_DB="$(fixture_expected_db "")"
dash_pid_opens "$LIVE_DB"
restore_wait_arm growing
( cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite > "$TMP/bg-growing.out" 2>&1 ) &
RESTORE_PID=$!
# The restore itself says when it is inside the wait (#674), so the insert is
# always in the window and never in a race with it. The restored file has
# landed by then: the copy runs before the wait, not after.
restore_wait_arrived "$RESTORE_PID" || bad "the restore never reached its wait" "$(cat "$TMP/bg-growing.out")"
is "the set's own content landed before the wait" \
  "$(sqlite3 "$LIVE_DB" "SELECT v FROM test_marker" 2>/dev/null)" "plain"
sqlite3 "$LIVE_DB" "INSERT INTO alerts_history VALUES(101),(102)" 2>/dev/null
restore_wait_release
wait "$RESTORE_PID"; rc=$?
out="$(cat "$TMP/bg-growing.out")"
restore_wait_disarm
is "restore still exits 0 while a background writer grows alerts_history during the wait" "$rc" "0"
has "the closing check still passes" "$out" "PASS  the running dashboard has the restored database open"

echo
echo "41. the closing check FAILS when the running dashboard has a different database open"
mk_plain; build_sut
DEST="$TMP/set-closingcheck-wrongfd"
run_backup >/dev/null 2>&1
mk_plain; build_sut
FROM="$DEST"
dash_pid_opens "$TMP/not-the-restored-db"
out=$(cd "$REPO" && APERIRE_RESTORE_SLEEP=1 bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite 2>&1); rc=$?
is "restore exits non-zero when the dashboard has the wrong database open" "$rc" "1"
has "the closing check fails, named" "$out" "FAIL  the running dashboard has the restored database open"
has "it names the path that is not open" "$out" "does not have"

echo
echo "42. the closing check FAILS when an operator row goes missing from the live database during the wait"
mk_plain; build_sut
DEST="$TMP/set-closingcheck-missingop"
run_backup >/dev/null 2>&1
mk_plain; build_sut
sqlite3 "$REPO/data/aperire.db" "UPDATE test_marker SET v='not-yet-restored'"
FROM="$DEST"
LIVE_DB="$(fixture_expected_db "")"
dash_pid_opens "$LIVE_DB"
restore_wait_arm missingop
( cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite > "$TMP/bg-missingop.out" 2>&1 ) &
RESTORE_PID=$!
restore_wait_arrived "$RESTORE_PID" || bad "the restore never reached its wait" "$(cat "$TMP/bg-missingop.out")"
is "the set's own content landed before the wait" \
  "$(sqlite3 "$LIVE_DB" "SELECT v FROM test_marker" 2>/dev/null)" "plain"
sqlite3 "$LIVE_DB" "DELETE FROM auth_users WHERE id = 1" 2>/dev/null
restore_wait_release
wait "$RESTORE_PID"; rc=$?
out="$(cat "$TMP/bg-missingop.out")"
restore_wait_disarm
is "restore exits non-zero when an operator row goes missing during the wait" "$rc" "1"
has "the closing check fails, named" "$out" "FAIL  the running dashboard has the restored database open"
has "it names the table that no longer matches" "$out" "auth_users"

echo
echo "43. a polled-but-unowned database (no operator enrolled yet) is replaced without --overwrite"
mk_plain; build_sut
DEST="$TMP/set-unowned"
run_backup >/dev/null 2>&1
# A freshly reinstalled host that has been polling for a minute: real rows in
# a growing table, but nobody has enrolled yet -- auth_users and
# auth_credentials both empty, the actual mark of "nobody owns this yet"
# (#562, revised: the old discriminator was `rows > 0` across every table,
# which asked the destructive question of exactly this host).
mk_tree
sqlite3 "$REPO/data/aperire.db" \
  "CREATE TABLE auth_users(id INTEGER); CREATE TABLE auth_credentials(id INTEGER);
   CREATE TABLE alerts_history(id INTEGER); INSERT INTO alerts_history VALUES(1),(2),(3);
   CREATE TABLE test_marker(v TEXT); INSERT INTO test_marker VALUES('unowned');"
printf 'authn: {v: 1}\n'    > "$REPO/dashboard/config/authn.yaml"
printf 'channels: {v: 1}\n' > "$REPO/dashboard/config/channels.yaml"
printf 'digest: {v: 1}\n'   > "$REPO/dashboard/config/digest.yaml"
printf 'rules: {v: 1}\n'    > "$REPO/dashboard/config/rules.local.yaml"
printf 'PORT=7900\nRELAY_TOKENS=deadbeef\n' > "$ETC/aperire/aperire.env"
chmod 640 "$ETC/aperire/aperire.env"
unit aperire-server "$REPO/dashboard" "$CALLER_USER"
systemctl_mark_active aperire-server
build_sut
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
out=$(cd "$REPO" && APERIRE_RESTORE_SLEEP=1 bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes 2>&1); rc=$?
is "restore exits 0 without --overwrite even though the live db has rows in a growing table" "$rc" "0"
hasnt "it never asks about a database that has moved on, since nobody owns it yet" "$out" "moved on"
is "the database is replaced with the set's own content" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "plain"

echo
echo "44. the held fleet arm key round-trips, mode 0644, root-owned on a real host (#724)"
mk_full
# The same content at both names, the shape sync_held_arm_key keeps a live
# host in (mk_full's own fleet-arm.pub is the trusted key already; the held
# copy tracks it).
cp "$ETC/aperire/fleet-arm.pub" "$ETC/aperire/fleet-arm.paired.pub"
chmod 644 "$ETC/aperire/fleet-arm.paired.pub"
build_sut
DEST="$TMP/set-held"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
has "it takes the held key as its own row" "$out" "ok    fleet-arm-held-key  -> $DEST/fleet-arm.paired.pub"
is "fleet-arm.paired.pub is in the set" "$([[ -f "$DEST/fleet-arm.paired.pub" ]] && echo yes || echo no)" "yes"
rm -f "$ETC/aperire/fleet-arm.pub" "$ETC/aperire/fleet-arm.paired.pub" "$ETC/aperire/relay.conf"
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
rm -f "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-link.json}
rm -f "$REPO/data/aperire.db"
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
has "it restores the held key" "$out" "ok    fleet-arm.paired.pub"
is "fleet-arm.paired.pub content matches the set" \
  "$(cat "$ETC/aperire/fleet-arm.paired.pub")" "$(cat "$DEST/fleet-arm.paired.pub")"
is "fleet-arm.paired.pub is mode 644, the table's own mode (owner is root on a real host; this fixture runs as its own account, not root)" \
  "$(stat -c %a "$ETC/aperire/fleet-arm.paired.pub")" "644"

echo
echo "45. a set whose fleet-arm.pub and held copy disagree is reconciled on restore: fleet-arm.pub wins (#724, #726 review M1)"
mk_full
printf 'BEGIN PUBLIC KEY-----old-held-----\n' > "$ETC/aperire/fleet-arm.paired.pub"
chmod 644 "$ETC/aperire/fleet-arm.paired.pub"
build_sut
DEST="$TMP/set-rotated"
run_backup >/dev/null 2>&1
# The set now holds two different keys: fleet-arm.pub (from mk_full) and a
# held copy this host held from an earlier pairing, never brought into step
# with it (a real host keeps these two equal, through
# install-model-key-sealer.sh's own sync_held_arm_key; a set is not
# guaranteed to, when it is old, or hand-assembled). Restoring such a set
# still has to leave this host in a state where both agree, or a later
# --remove and reinstall of the Advisor places whichever one the set's own
# held copy happened to name, silently.
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
rm -f "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-link.json}
rm -f "$ETC/aperire/fleet-arm.pub" "$ETC/aperire/fleet-arm.paired.pub" "$ETC/aperire/relay.conf"
rm -f "$REPO/data/aperire.db"
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "fleet-arm.paired.pub matches the restored fleet-arm.pub, not the set's own stale held copy" \
  "$(cat "$ETC/aperire/fleet-arm.paired.pub")" "$(cat "$ETC/aperire/fleet-arm.pub")"
is "and that content is the set's fleet-arm.pub, not the old held file" \
  "$(cat "$ETC/aperire/fleet-arm.paired.pub")" "$(cat "$DEST/fleet-arm.pub")"

echo
echo "46. a paired, no-Advisor node: the held key round-trips through a restore, and is still there once an Advisor is added (#724)"
mk_plain
printf 'label: stock-node1\n' > "$REPO/dashboard/config/fleet.yaml"
printf 'pin: abc123\n'        > "$REPO/dashboard/config/fleet-trust.yaml"
printf '{"token":"link-secret"}\n' > "$REPO/dashboard/config/fleet-link.json"
chmod 600 "$REPO/dashboard/config/fleet.yaml" "$REPO/dashboard/config/fleet-trust.yaml" \
  "$REPO/dashboard/config/fleet-link.json"
printf 'BEGIN PUBLIC KEY-----held-only-----\n' > "$ETC/aperire/fleet-arm.paired.pub"
chmod 644 "$ETC/aperire/fleet-arm.paired.pub"
build_sut
DEST="$TMP/set-noadvisor-held"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
is "no fleet-arm.pub in the set: this host was never armed, only paired" \
  "$([[ -f "$DEST/fleet-arm.pub" ]] && echo yes || echo no)" "no"
is "the held key is in the set" "$([[ -f "$DEST/fleet-arm.paired.pub" ]] && echo yes || echo no)" "yes"
rm -f "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-link.json}
rm -f "$ETC/aperire/fleet-arm.paired.pub"
rm -f "$REPO/data/aperire.db"
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore onto the still-Advisor-less host exits 0" "$rc" "0"
is "the held key is back, mode 0644" \
  "$(stat -c %a "$ETC/aperire/fleet-arm.paired.pub" 2>/dev/null)" "644"
is "no fleet-arm.pub was invented: this host still has nothing to arm with directly" \
  "$([[ -f "$ETC/aperire/fleet-arm.pub" ]] && echo yes || echo no)" "no"
# The Advisor arrives afterward, the way #720 describes: the held key is
# exactly what its install would place as fleet-arm.pub. This suite stops at
# proving the held key survived the restore, ready for that step; placing it
# is install-model-key-sealer.sh's own job, not this one's.
mkdir -p "$REPO/advisor/state"
printf 'approve-token\n' > "$REPO/advisor/state/approve.token"
printf 'read-token\n'    > "$REPO/advisor/state/read.token"
chmod 750 "$REPO/advisor/state"; chmod 640 "$REPO/advisor/state"/*
unit aperire-advisord "" "$CALLER_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
systemctl_mark_active aperire-advisord
is "adding the Advisor afterward leaves the held key exactly as the restore left it" \
  "$(stat -c %a "$ETC/aperire/fleet-arm.paired.pub" 2>/dev/null)" "644"
is "and its content is still the pairing's own key" \
  "$(cat "$ETC/aperire/fleet-arm.paired.pub")" "$(cat "$DEST/fleet-arm.paired.pub")"

# ── #791 and #744: an aggregator's own fleet state ─────────────────────
# An aggregator holds three things a member does not: fleet-links.json (the
# hash of every node's link credential), /etc/aperire/fleet-tokens (the
# tokens it reads its nodes with) and /etc/aperire/fleet-arm.key (its
# private arm key). Before #791 the set carried none of them, and a
# restored aggregator passed every closing check while no node could link,
# be read or be armed.
export FAKE_CURL_LOG="$TMP/curl-node-args"
export FAKE_CURL_HDR_LOG="$TMP/curl-node-hdr"
AGG_TOKEN="node-read-token-core-two-5f1e"

mk_aggregator() {
  mk_full
  # An aggregator holds no dial-out credential of its own and trusts no other
  # aggregator's arm key; its fleet-trust.yaml holds its own trust-bundle
  # signing key instead (aperire-auth.sh's "an aggregator" shape).
  rm -f "$REPO/dashboard/config/fleet-link.json" "$ETC/aperire/fleet-arm.pub"
  printf 'private_key: fake-trust-signing-key\n' > "$REPO/dashboard/config/fleet-trust.yaml"
  chmod 600 "$REPO/dashboard/config/fleet-trust.yaml"
  cat > "$REPO/dashboard/config/fleet.yaml" <<EOF
fleet:
  - label: agg
    role: aggregator
    read_origin: http://127.0.0.1:7900
    token_path: $REPO/advisor/state/read.token
  - label: core-two
    role: validator
    transport: link
    read_origin: http://127.0.0.1:7902
    token_path: $ETC/aperire/fleet-tokens/core-two.token
EOF
  printf '{\n  "links": [\n    {"label": "core-two", "credential_sha256": "%s", "read_port": 7902}\n  ]\n}\n' \
    "$(printf 'link-cred' | sha256sum | cut -d' ' -f1)" > "$REPO/dashboard/config/fleet-links.json"
  chmod 600 "$REPO/dashboard/config/fleet.yaml" "$REPO/dashboard/config/fleet-links.json"
  mkdir -p "$ETC/aperire/fleet-tokens"
  printf '%s\n' "$AGG_TOKEN" > "$ETC/aperire/fleet-tokens/core-two.token"
  printf 'approve-token-core-two\n' > "$ETC/aperire/fleet-tokens/core-two.approve.token"
  chmod 640 "$ETC/aperire/fleet-tokens"/*
  chmod 750 "$ETC/aperire/fleet-tokens"
  ( umask 077; openssl genpkey -algorithm ed25519 -out "$ETC/aperire/fleet-arm.key" 2>/dev/null )
  chmod 600 "$ETC/aperire/fleet-arm.key"
}

# What a fresh install of an aggregator looks like before its restore: none
# of the aggregator's own fleet files, an empty Advisor state.
wipe_aggregator() {
  rm -rf "$ETC/aperire/fleet-tokens" "$REPO/advisor/state"
  mkdir -p "$REPO/advisor/state"
  rm -f "$ETC/aperire/fleet-arm.key" "$ETC/aperire/fleet-arm.key".* "$ETC/aperire"/.fleet-arm.key.* \
    "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-links.json} "$REPO/data/aperire.db"
}

reseal_set() {  # <set dir> - rebuild its manifest after a row edits it on purpose
  ( cd "$1" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$1/MANIFEST.sha256"
}

pub_of() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0; }

if ! command -v openssl >/dev/null 2>&1; then
  echo
  echo "47-58. SKIP: no openssl on this machine, and an aggregator's arm key is an Ed25519 key"
else

echo
echo "47. an aggregator's backup takes fleet-links.json, its node tokens and its private arm key (#791, #744)"
mk_aggregator
build_sut
DEST="$TMP/set-agg"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
has "it names this host an aggregator" "$out" "fleet: aggregator"
has "the plan takes the node tokens" "$out" "take  fleet-tokens  (/etc/aperire/fleet-tokens)"
has "the plan takes the private arm key" "$out" "take  fleet-arm-private-key  (/etc/aperire/fleet-arm.key)"
has "fleet-config carries fleet.yaml, fleet-trust.yaml and fleet-links.json" "$out" "ok    fleet-config  -> $DEST/config/ (3 files)"
is "fleet-links.json is in the set, byte for byte" \
  "$(cat "$DEST/config/fleet-links.json" 2>/dev/null)" "$(cat "$REPO/dashboard/config/fleet-links.json")"
has "it takes the node tokens" "$out" "ok    fleet-tokens  -> $DEST/fleet-tokens (2 files)"
is "the read token is in the set, byte for byte" \
  "$(cat "$DEST/fleet-tokens/core-two.token" 2>/dev/null)" "$AGG_TOKEN"
has "it takes the private arm key" "$out" "ok    fleet-arm-private-key  -> $DEST/fleet-arm.key"
is "the arm key is in the set, byte for byte" \
  "$(sha256sum < "$DEST/fleet-arm.key" 2>/dev/null)" "$(sha256sum < "$ETC/aperire/fleet-arm.key")"
is "  owner-only in the set, 0600, like every token beside it" "$(stat -c %a "$DEST/fleet-arm.key")" "600"
is "  owned by the operator who took the set" "$(stat -c %U "$DEST/fleet-arm.key")" "$CALLER_USER"
is "  and the node tokens are 0600 in the set too" "$(stat -c %a "$DEST/fleet-tokens/core-two.token")" "600"
is "no file in the set is group- or other-readable" \
  "$(find "$DEST" -perm -040 -o -perm -004 2>/dev/null | tr '\n' ' ')" ""
has "OWNERSHIP records the arm key as it was on this host" "$(cat "$DEST/OWNERSHIP")" "600 "
has "  by its own path" "$(cat "$DEST/OWNERSHIP")" "$ETC/aperire/fleet-arm.key"
has "the README names the arm key and says to keep the set owner-only" "$(cat "$DEST/README")" "Keep this set where only"
has "  and says what the key can do" "$(cat "$DEST/README")" "open an arm window on every one of them"
AGG_SET="$DEST"
AGG_KEY_SUM="$(sha256sum < "$ETC/aperire/fleet-arm.key")"
AGG_PUB="$(pub_of "$ETC/aperire/fleet-arm.key")"

echo
echo "48. restore onto a fresh aggregator puts all three back, with this host's own owner, group and mode (#791, #744)"
wipe_aggregator
# The broker program the restore's next step looks for (#825), at a path the
# fixture owns, so whether this host happens to have one decides nothing.
export APERIRE_FLEET_BROKER_PATH="$TMP/sbin/aperire-fleet-broker"
rm -f "$APERIRE_FLEET_BROKER_PATH"
build_sut
: > "$FAKE_CHOWN_LOG"; : > "$FAKE_CURL_LOG"; : > "$FAKE_CURL_HDR_LOG"; : > "$FAKE_PLANT_LOG"
FROM="$AGG_SET"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "the fixture carries the credcheck unit beside the Advisor's own, User=root (#809)" \
  "$(sed -n 's/^User=//p' "$UNITS/aperire-advisord-credcheck.service" 2>/dev/null)" "root"
hasnt "the token group is read from the Advisor's own unit, never the credcheck unit's root (#809)" \
  "$out" "share no group"
is "fleet-links.json is back, byte for byte" \
  "$(cat "$REPO/dashboard/config/fleet-links.json" 2>/dev/null)" "$(cat "$AGG_SET/config/fleet-links.json")"
is "  mode 0600, the table's" "$(stat -c %a "$REPO/dashboard/config/fleet-links.json")" "600"
is "the node token is back, byte for byte" "$(cat "$ETC/aperire/fleet-tokens/core-two.token" 2>/dev/null)" "$AGG_TOKEN"
is "  mode 0640, the table's, not the set's 0600" "$(stat -c %a "$ETC/aperire/fleet-tokens/core-two.token")" "640"
is "  in a 0750 directory" "$(stat -c %a "$ETC/aperire/fleet-tokens")" "750"
# Planted by descriptor, root : this host's shared group (#965); the request
# is read from the shim's log, since this suite cannot give a file to root.
has "  planted root : this host's shared group (the broker's own answer)" \
  "$(cat "$FAKE_PLANT_LOG")" "plant $ETC/aperire/fleet-tokens/core-two.token 0 $(getent group "$CALLER_GROUP" | cut -d: -f3) 0640"
has "  and so is the directory, made by descriptor too" "$(cat "$FAKE_PLANT_LOG")" "mkdir $ETC/aperire/fleet-tokens 0 $(getent group "$CALLER_GROUP" | cut -d: -f3) 0750"
is "  no chown or chmod is aimed at a token or its directory by name (#965)" \
  "$(grep -c -- "$ETC/aperire/fleet-tokens" "$FAKE_CHOWN_LOG")" "0"
is "the arm key is back, byte for byte" "$(sha256sum < "$ETC/aperire/fleet-arm.key" 2>/dev/null)" "$AGG_KEY_SUM"
is "  mode 0600" "$(stat -c %a "$ETC/aperire/fleet-arm.key")" "600"
is "  one link only: the temp it was placed through is gone" "$(stat -c %h "$ETC/aperire/fleet-arm.key")" "1"
is "  no temp file left beside it" "$(find "$ETC/aperire" -maxdepth 1 -name '.fleet-arm.key.*' | wc -l | tr -d ' ')" "0"
has "  chowned root : root before it was linked into place" "$(cat "$FAKE_CHOWN_LOG")" "root:root $ETC/aperire/.fleet-arm.key."
has "it prints the public half it placed" "$out" "public half $AGG_PUB"
has "the closing check reads a linked node, and names it" "$out" "PASS  a linked node answers a read from this aggregator: core-two"
has "  it asked the node's own loopback read port" "$(cat "$FAKE_CURL_LOG")" "http://127.0.0.1:7902/read/v1/recent"
hasnt "  the token never went on curl's argv" "$(cat "$FAKE_CURL_LOG")" "$AGG_TOKEN"
has "  it went in a header file instead" "$(cat "$FAKE_CURL_HDR_LOG")" "Authorization: Bearer $AGG_TOKEN"
hasnt "  this host's own row was never asked" "$(cat "$FAKE_CURL_LOG")" "127.0.0.1:7900/read"
has "it names the command that rebuilds root's node list" "$out" "--run fleet-broker-grant --refresh-nodes"
# #825: this host has no broker grant, and --refresh-nodes refuses on one,
# so the full install is named first and the refresh after it.
_rs_full="$(grep -nxF "      curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant" <<<"$out" | head -1 | cut -d: -f1)"
_rs_ref="$(grep -nxF "      curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant --refresh-nodes" <<<"$out" | head -1 | cut -d: -f1)"
is "on a host with no broker grant it names the full install first, then the refresh (#825)" \
  "$([[ -n "$_rs_full" && -n "$_rs_ref" && "$_rs_full" -lt "$_rs_ref" ]] && echo in-order || echo "full@${_rs_full:-none} refresh@${_rs_ref:-none}")" "in-order"

echo
echo "48b. the same restore on a host that has the grant names only the refresh (#825)"
mkdir -p "$TMP/sbin"
: > "$APERIRE_FLEET_BROKER_PATH"
: > "$UNITS/aperire-fleet-broker.socket"
printf 'INSTALL_DIR=%s\n' "$REPO" > "$ETC/aperire/fleet-broker.conf"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
has "it names the refresh" "$out" "      curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant --refresh-nodes"
is "and not the full install, which this host already has" \
  "$(grep -cxF "      curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant" <<<"$out")" "0"
rm -f "$APERIRE_FLEET_BROKER_PATH" "$UNITS/aperire-fleet-broker.socket" "$ETC/aperire/fleet-broker.conf"

echo
echo "49. an identical arm key already on the host is accepted and left alone (#744)"
: > "$FAKE_CHOWN_LOG"
_ino_before="$(stat -c %i "$ETC/aperire/fleet-arm.key")"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
has "it says the key here is already the set's" "$out" "this host's own is already the set's key"
is "the key is the same file it was, never rewritten" "$(stat -c %i "$ETC/aperire/fleet-arm.key")" "$_ino_before"
has "nothing needed to change" "$out" "no files needed to change"
# The same key, written out another way: a PEM with a line in front of it is
# a different file and the same key. The public half is what nodes trust,
# so that is what decides.
{ echo "# restored by hand"; cat "$AGG_SET/fleet-arm.key"; } > "$ETC/aperire/fleet-arm.key.alt"
mv "$ETC/aperire/fleet-arm.key.alt" "$ETC/aperire/fleet-arm.key"; chmod 600 "$ETC/aperire/fleet-arm.key"
_alt_sum="$(sha256sum < "$ETC/aperire/fleet-arm.key")"
out=$(run_restore 2>&1); rc=$?
is "the same key written another way is accepted too" "$rc" "0"
is "  and left exactly as it is" "$(sha256sum < "$ETC/aperire/fleet-arm.key")" "$_alt_sum"

echo
echo "50. a different arm key already on the host is refused (rc=9), before anything stops (#744)"
rm -f "$ETC/aperire/fleet-arm.key"
( umask 077; openssl genpkey -algorithm ed25519 -out "$ETC/aperire/fleet-arm.key" 2>/dev/null )
_other_sum="$(sha256sum < "$ETC/aperire/fleet-arm.key")"
_other_pub="$(pub_of "$ETC/aperire/fleet-arm.key")"
_db_before="$(sha256sum < "$REPO/data/aperire.db")"
rm -rf "$ETC/aperire/fleet-tokens"
out=$(run_restore 2>&1); rc=$?
is "exit code is 9" "$rc" "9"
has "it prints the key on this host" "$out" "public half $_other_pub"
has "  and the one in the set" "$out" "public half $AGG_PUB"
has "it names the way past, by hand" "$out" "sudo mv $ETC/aperire/fleet-arm.key"
is "the key on this host is untouched" "$(sha256sum < "$ETC/aperire/fleet-arm.key")" "$_other_sum"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
is "the database was never touched" "$(sha256sum < "$REPO/data/aperire.db")" "$_db_before"
is "no node token was written" "$([[ -e "$ETC/aperire/fleet-tokens" ]] && echo yes || echo no)" "no"
out=$( cd "$REPO" && bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --dry-run 2>&1 ); rc=$?
is "a --dry-run says so too, with the same code" "$rc" "9"

echo
echo "51. an arm key name on the host that is a symlink is refused (rc=9), its target untouched"
rm -f "$ETC/aperire/fleet-arm.key"
cp "$AGG_SET/fleet-arm.key" "$TMP/arm-key-target"; chmod 644 "$TMP/arm-key-target"
ln -s "$TMP/arm-key-target" "$ETC/aperire/fleet-arm.key"
out=$(run_restore 2>&1); rc=$?
is "exit code is 9" "$rc" "9"
has "it says why" "$out" "is not a plain file"
is "the link's target keeps its own mode: nothing was written through the link" "$(stat -c %a "$TMP/arm-key-target")" "644"
is "  and the name is still the link" "$([[ -L "$ETC/aperire/fleet-arm.key" ]] && echo yes || echo no)" "yes"
rm -f "$ETC/aperire/fleet-arm.key"

echo
echo "52. a set whose fleet-arm.key is not an Ed25519 private key is refused (rc=3)"
BADKEY_SET="$TMP/set-agg-badkey"
cp -a "$AGG_SET" "$BADKEY_SET"
( umask 077; openssl genpkey -algorithm x25519 -out "$BADKEY_SET/fleet-arm.key" 2>/dev/null )
reseal_set "$BADKEY_SET"
FROM="$BADKEY_SET"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it says what is wrong with it" "$out" "not
       an Ed25519 private key"
is "no key was placed" "$([[ -e "$ETC/aperire/fleet-arm.key" ]] && echo yes || echo no)" "no"
FROM="$AGG_SET"

echo
echo "53. a node token in the set with a name no token has is refused (rc=3)"
BADTOK_SET="$TMP/set-agg-badtok"
cp -a "$AGG_SET" "$BADTOK_SET"
printf 'x\n' > "$BADTOK_SET/fleet-tokens/.hidden token"
chmod 600 "$BADTOK_SET/fleet-tokens/.hidden token"
reseal_set "$BADTOK_SET"
FROM="$BADTOK_SET"
out=$(run_restore 2>&1); rc=$?
is "exit code is 3" "$rc" "3"
has "it names the file" "$out" "fleet-tokens/.hidden token"
FROM="$AGG_SET"

echo
echo "54. /etc/aperire/fleet-tokens as a symlink on the host is refused (rc=4), before anything stops"
mkdir -p "$TMP/elsewhere-tokens"
ln -s "$TMP/elsewhere-tokens" "$ETC/aperire/fleet-tokens"
out=$(run_restore 2>&1); rc=$?
is "exit code is 4" "$rc" "4"
is "nothing was written into the link's target" "$(find "$TMP/elsewhere-tokens" -type f | wc -l | tr -d ' ')" "0"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
rm -f "$ETC/aperire/fleet-tokens"

echo
echo "55. a widened mode recorded in OWNERSHIP never reaches the arm key or a token; the host's table does (#791)"
WIDE_SET="$TMP/set-agg-wide"
cp -a "$AGG_SET" "$WIDE_SET"
sed -i -e "s#^[0-7]* \(.*$ETC/aperire/fleet-arm.key\)\$#644 \1#" \
       -e "s#^[0-7]* \(.*$ETC/aperire/fleet-tokens/core-two.token\)\$#666 \1#" "$WIDE_SET/OWNERSHIP"
reseal_set "$WIDE_SET"
has "  (the fixture really did widen both)" "$(cat "$WIDE_SET/OWNERSHIP")" "644 "
wipe_aggregator
build_sut
FROM="$WIDE_SET"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "the arm key lands 0600, not the recorded 0644" "$(stat -c %a "$ETC/aperire/fleet-arm.key")" "600"
is "the token lands 0640, not the recorded 0666" "$(stat -c %a "$ETC/aperire/fleet-tokens/core-two.token")" "640"
has "and the difference is reported, not applied" "$out" "OWNERSHIP recorded $ETC/aperire/fleet-arm.key as mode 644"
FROM="$AGG_SET"

echo
echo "56. the closing node check fails honestly: no node answering is a FAIL, never a PASS (#791)"
wipe_aggregator
build_sut
export APERIRE_RESTORE_NODE_WAIT=0
export FAKE_NODE_READ=000
out=$(run_restore 2>&1); rc=$?
is "an offline fleet: exit code is 1" "$rc" "1"
has "the FAIL line says none did" "$out" "FAIL  a linked node answers a read from this aggregator: none did"
hasnt "  and no PASS line claims otherwise" "$out" "PASS  a linked node"
has "  it names the node and what it saw" "$out" "core-two nothing answered at http://127.0.0.1:7902"
has "  and the one-hour wait a refused node may be in" "$out" "restart that node's dashboard"
export FAKE_NODE_READ=401
out=$(run_restore 2>&1); rc=$?
is "a node refusing this aggregator's token: exit code is 1" "$rc" "1"
has "  it says the node does not accept the token" "$out" "core-two answered 401: it does not accept this aggregator's token"
export FAKE_NODE_READ=200
NOTOK_SET="$TMP/set-agg-notok"
cp -a "$AGG_SET" "$NOTOK_SET"
sed -i "s#token_path: $ETC/aperire/fleet-tokens/core-two.token#token_path: $TMP/no-such-token#" \
  "$NOTOK_SET/config/fleet.yaml"
reseal_set "$NOTOK_SET"
FROM="$NOTOK_SET"
out=$(run_restore 2>&1); rc=$?
is "a token the dashboard's account cannot read: exit code is 1" "$rc" "1"
has "  it says the token cannot be read, by that account" "$out" "its token at $TMP/no-such-token cannot be read by '$CALLER_USER'"
FROM="$AGG_SET"
unset FAKE_NODE_READ

echo
echo "57. an aggregator with no node but itself gets a SKIP, never a PASS"
SELF_SET="$TMP/set-agg-self"
cp -a "$AGG_SET" "$SELF_SET"
python3 - "$SELF_SET/config/fleet.yaml" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
d["fleet"] = [r for r in d["fleet"] if r["label"] == "agg"]
open(p, "w").write(yaml.safe_dump(d))
PY
reseal_set "$SELF_SET"
wipe_aggregator
build_sut
FROM="$SELF_SET"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
has "the check says there is no node to ask" "$out" "SKIP  a linked node answers a read from this aggregator: fleet.yaml names no node but this host"
hasnt "  and claims no PASS" "$out" "PASS  a linked node"
FROM="$AGG_SET"
unset APERIRE_RESTORE_NODE_WAIT

echo
echo "58. a member's restore never asks the node check at all: it serves no node"
mk_full
build_sut
DEST="$TMP/set-member-791"
run_backup >/dev/null 2>&1
FROM="$DEST"
: > "$FAKE_CURL_LOG"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
hasnt "no linked-node check line" "$out" "a linked node answers"
is "no node read was made" "$(grep -c '/read/v1/recent' "$FAKE_CURL_LOG" | tr -d ' ')" "0"
hasnt "no fleet-arm.key was invented" "$(ls -A "$ETC/aperire")" "fleet-arm.key"

echo
echo "59. a backup refuses to carry a node token that is a symlink"
mk_aggregator
ln -s "$TMP/sentinel-tok" "$ETC/aperire/fleet-tokens/zz-planted.token"
printf 'not a token\n' > "$TMP/sentinel-tok"
build_sut
DEST="$TMP/set-agg-planted"
out=$(run_backup 2>&1); rc=$?
has "it says it will not carry it" "$out" "fail  fleet-tokens"
is "no fleet-tokens directory in the set" "$([[ -e "$DEST/fleet-tokens" ]] && echo yes || echo no)" "no"
is "the planted target's content is in no file of the set" \
  "$(grep -rl 'not a token' "$DEST" 2>/dev/null | tr '\n' ' ')" ""

echo
echo "60. an arm key that appears between the restore's check and its write is never overwritten (#744)"
# Mid-restore, so it stops the way every mid-restore step does (exit 1, a
# safety copy kept, services left stopped), not with the preflight's 9: by
# then the database and the config have already been written.
wipe_aggregator
build_sut
FROM="$AGG_SET"
( umask 077; openssl genpkey -algorithm ed25519 -out "$TMP/race-key" 2>/dev/null )
_race_sum="$(sha256sum < "$TMP/race-key")"
export FAKE_MKTEMP_PLANT="$TMP/race-key"
out=$(run_restore 2>&1); rc=$?
unset FAKE_MKTEMP_PLANT
is "exit code is 1, a mid-restore stop" "$rc" "1"
has "it says a key appeared while it ran" "$out" "appeared at $ETC/aperire/fleet-arm.key while this restore ran"
is "the key that appeared is untouched" "$(sha256sum < "$ETC/aperire/fleet-arm.key")" "$_race_sum"
is "  one link only: the set's temp never became a second name for it" "$(stat -c %h "$ETC/aperire/fleet-arm.key")" "1"
is "no temp file left beside it" "$(find "$ETC/aperire" -maxdepth 1 -name '.fleet-arm.key.*' | wc -l | tr -d ' ')" "0"
hasnt "and no PASS line was printed for a check that never ran" "$out" "PASS  "

# ── #796, #798 and the #793 review: account-owned names, prompts, proxies ──
# A root backup used to `cp -p` every file out of dashboard/config, a
# directory the dashboard account owns, so a link that account planted at
# any name carried whatever root could read into the set (the review's R1:
# fleet-links.json -> the private arm key). Each row below is one of the
# review's reproductions, refused now.
not_in_set() {  # <set> <sha256 of content that must be in no file of it>
  local f
  while IFS= read -r -d '' f; do
    [[ "$(sha256sum < "$f")" == "$2" ]] && { printf '%s\n' "${f#"$1"/}"; return 0; }
  done < <(find "$1" -type f -print0 2>/dev/null)
  return 0
}

echo
echo "61. a link the dashboard account plants at fleet-links.json, aimed at the arm key, is refused (#796, review R1)"
mk_aggregator
build_sut
KEY_SUM="$(sha256sum < "$ETC/aperire/fleet-arm.key")"
rm -f "$REPO/dashboard/config/fleet-links.json"
ln -s "$ETC/aperire/fleet-arm.key" "$REPO/dashboard/config/fleet-links.json"
DEST="$TMP/set-r1"
out=$(run_backup 2>&1); rc=$?
has "the backup says it will not carry it" "$out" "fail  fleet-config  refusing to carry it"
is "the arm key's content is in the set once, as fleet-arm.key, never under a config name" \
  "$(not_in_set "$DEST/config" "$KEY_SUM")" ""
is "no fleet-links.json in the set at all" "$([[ -e "$DEST/config/fleet-links.json" ]] && echo yes || echo no)" "no"

echo
echo "62. the same link at authn.yaml, a row this PR never added, is refused too (#796, review R1b)"
mk_aggregator
build_sut
rm -f "$REPO/dashboard/config/authn.yaml"
ln -s "$ETC/aperire/fleet-arm.key" "$REPO/dashboard/config/authn.yaml"
DEST="$TMP/set-r1b"
out=$(run_backup 2>&1); rc=$?
is "the backup fails: dashboard-config is required" "$rc" "1"
has "it says why" "$out" "fail  dashboard-config  refusing to carry it"
is "the arm key's content is under no config name" "$(not_in_set "$DEST/config" "$KEY_SUM")" ""

echo
echo "63. a link at fleet-links.json aimed at the sealed model credential is refused (#796, review R1c)"
mk_aggregator
build_sut
CRED_SUM="$(sha256sum < "$ETC/aperire/creds/model-api-key-anthropic")"
rm -f "$REPO/dashboard/config/fleet-links.json"
ln -s "$ETC/aperire/creds/model-api-key-anthropic" "$REPO/dashboard/config/fleet-links.json"
DEST="$TMP/set-r1c"
out=$(run_backup 2>&1); rc=$?
has "the backup refuses it" "$out" "fail  fleet-config  refusing to carry it"
is "the sealed credential is in no file of the set" "$(not_in_set "$DEST" "$CRED_SUM")" ""

echo
echo "64. a hard link at fleet-links.json to the arm key is refused: one link only, checked on the open file (#796)"
mk_aggregator
build_sut
rm -f "$REPO/dashboard/config/fleet-links.json"
ln "$ETC/aperire/fleet-arm.key" "$REPO/dashboard/config/fleet-links.json"
DEST="$TMP/set-hardlink"
out=$(run_backup 2>&1); rc=$?
has "the backup refuses it" "$out" "not a plain file with one link"
is "the arm key's content is under no config name" "$(not_in_set "$DEST/config" "$KEY_SUM")" ""

echo
echo "65. a FIFO at authn.yaml is refused without hanging the backup (#796)"
mk_aggregator
build_sut
rm -f "$REPO/dashboard/config/authn.yaml"
mkfifo "$REPO/dashboard/config/authn.yaml"
DEST="$TMP/set-fifo"
out=$( cd "$REPO" && timeout 90 bash "$REPO/scripts/aperire-backup.sh" --to "$DEST" --yes 2>&1 ); rc=$?
is "the backup ends on its own, failing the required row (not killed by a timeout)" "$rc" "1"
has "it says why" "$out" "fail  dashboard-config  refusing to carry it"

echo
echo "66. a link the dashboard account plants at its database is refused (#796)"
mk_aggregator
build_sut
OTHER_DB="$TMP/someone-elses.db"
rm -f "$OTHER_DB"
sqlite3 "$OTHER_DB" "CREATE TABLE secret(v TEXT); INSERT INTO secret VALUES('not-aperire-data');"
rm -f "$REPO/data/aperire.db"
ln -s "$OTHER_DB" "$REPO/data/aperire.db"
DEST="$TMP/set-dblink"
out=$(run_backup 2>&1); rc=$?
is "the backup fails: the database is required" "$rc" "1"
has "it says the database is a link" "$out" "is a symbolic link; refusing to follow it"
is "no database in the set" "$([[ -e "$DEST/aperire.db" ]] && echo yes || echo no)" "no"

echo
echo "67. every file in an account's own directory is read AS that account, the database included (#796)"
mk_aggregator
build_sut
export FAKE_RUNUSER_LOG="$TMP/runuser-log"
: > "$FAKE_RUNUSER_LOG"
DEST="$TMP/set-as-account"
out=$(run_backup 2>&1); rc=$?
is "backup exits 0" "$rc" "0"
_rl="$(cat "$FAKE_RUNUSER_LOG")"
has "authn.yaml was read as the dashboard account" "$_rl" "$CALLER_USER :: python3 -I -c"
has "  by its own path" "$_rl" "$REPO/dashboard/config/authn.yaml"
has "fleet-links.json too" "$_rl" "$REPO/dashboard/config/fleet-links.json"
has "the database snapshot was taken by the dashboard account" "$_rl" "$CALLER_USER :: sqlite3 -init /dev/null $REPO/data/aperire.db VACUUM INTO"
has "the Advisor's ledger was read as the Advisor's account" "$_rl" "$REPO/advisor/state/ledger.jsonl"
is "and the set still verifies, the round trip intact" \
  "$(cd "$DEST" && sha256sum -c MANIFEST.sha256 >/dev/null 2>&1 && echo yes || echo no)" "yes"
unset FAKE_RUNUSER_LOG

echo
echo "68. an encrypted arm key is refused, never a pass-phrase prompt in a root restore (review L1)"
ENC_SET="$TMP/set-agg-enc"
rm -rf "$ENC_SET"; cp -a "$AGG_SET" "$ENC_SET"
openssl genpkey -algorithm ed25519 -aes-256-cbc -pass pass:x -out "$ENC_SET/fleet-arm.key" 2>/dev/null
chmod 600 "$ENC_SET/fleet-arm.key"
reseal_set "$ENC_SET"
wipe_aggregator
build_sut
FROM="$ENC_SET"
out=$(run_restore </dev/null 2>&1); rc=$?
is "no terminal: exit code is 3, the set is the problem" "$rc" "3"
hasnt "  and no pass phrase was asked for" "$out" "pass phrase"
if command -v script >/dev/null 2>&1; then
  dash_pid_opens "$(fixture_expected_db "")"
  export FROM REPO
  # A real terminal: openssl opens /dev/tty itself and would wait at the
  # prompt there. The timeout turns that wait into a red row, not a hang.
  timeout 30 script -qec "cd '$REPO' && bash '$REPO/scripts/aperire-restore.sh' --from '$FROM' --yes --overwrite --dry-run" /dev/null </dev/null > "$TMP/enc-tty.out" 2>&1
  rc=$?
  is "on a terminal too: exit code is 3, with no wait at a prompt" "$rc" "3"
  hasnt "  and no pass phrase was asked for" "$(cat "$TMP/enc-tty.out")" "pass phrase"
fi
# The same key, encrypted, already on the host: unreadable, so never "the same".
FROM="$AGG_SET"
openssl genpkey -algorithm ed25519 -aes-256-cbc -pass pass:x -out "$ETC/aperire/fleet-arm.key" 2>/dev/null
chmod 600 "$ETC/aperire/fleet-arm.key"
out=$(run_restore </dev/null 2>&1); rc=$?
is "an encrypted key already on the host: exit code is 9" "$rc" "9"
hasnt "  and no pass phrase was asked for" "$out" "pass phrase"
rm -f "$ETC/aperire/fleet-arm.key"

echo
echo "68b. a lost arm key on a paired aggregator: the grant refuses and writes nothing, the restore puts the key back, the grant then runs with no hand step (#851)"
# The order an operator meets this in: /etc/aperire came back without the
# arm key while the dashboard's records still name a paired node. Before
# #851 the grant made a fresh key here, and this restore then refused (exit
# 9) to place the set's own key over it. The real installer, under fakeroot
# like test-install-fleet-broker-grant.sh's own rows; its socket check cannot
# pass under fakes, so "runs" is: no refusal, the key kept as the set's,
# both programs and the conf written.
if command -v fakeroot >/dev/null 2>&1; then
  mk_aggregator
  # A real trust seed, so the grant judges this file rather than refusing
  # the fixture's placeholder before it reaches the arm key.
  printf 'private_key: %s\npeers: {}\n' \
    "$(openssl genpkey -algorithm ed25519 2>/dev/null | openssl pkey -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')" \
    > "$REPO/dashboard/config/fleet-trust.yaml"
  chmod 600 "$REPO/dashboard/config/fleet-trust.yaml"
  build_sut
  DEST="$TMP/set-851"; rm -rf "$DEST"
  out=$(run_backup 2>&1); rc=$?
  is "the set is taken" "$rc" "0"
  SET_851_SUM="$(sha256sum < "$DEST/fleet-arm.key" 2>/dev/null)"
  rm -f "$ETC/aperire/fleet-arm.key"
  for f in install-fleet-broker-grant.sh aperire-fleet-broker.sh aperire-fleet-arm.sh release-digests-lib.sh trusted-path-lib.sh fleet-trust-perms.sh fleet-trust-split.sh state-file.py; do
    cp "$REPO_DIR/scripts/$f" "$REPO/scripts/$f"
  done
  rm -rf "$TMP/sbin851" "$TMP/run851"; mkdir -p "$TMP/sbin851"
  # As root the grant drops every APERIRE_* variable but the install tree
  # (#1206), so the copy has the paths it used to take from the environment
  # rewritten to this rig's, each asserted, or it would read this host's /etc.
  # shellcheck disable=SC2016  # the program's own text, matched as text
  sed -i -e 's#^DEST="\${APERIRE_FLEET_BROKER_PATH:-/usr/local/sbin/aperire-fleet-broker}"$#DEST='"$TMP/sbin851/aperire-fleet-broker"'#' \
         -e 's#^SOCK="\${APERIRE_FLEET_BROKER_SOCKET:-/run/aperire/fleet-broker.sock}"$#SOCK='"$TMP/run851/fb.sock"'#' \
         -e 's#^ETC="\${APERIRE_ETC:-/etc/aperire}"$#ETC='"$ETC/aperire"'#' \
         -e 's#^UNIT_DIR="\${APERIRE_UNIT_DIR:-/etc/systemd/system}"$#UNIT_DIR='"$UNITS"'#' \
         -e 's#^INSTALL_DIR="\${APERIRE_DIR:-\$REPO}"$#INSTALL_DIR='"$REPO"'#' \
    "$REPO/scripts/install-fleet-broker-grant.sh"
  for _pin in "DEST=$TMP/sbin851/aperire-fleet-broker" "SOCK=$TMP/run851/fb.sock" "ETC=$ETC/aperire" "UNIT_DIR=$UNITS" "INSTALL_DIR=$REPO"; do
    grep -qxF -e "$_pin" "$REPO/scripts/install-fleet-broker-grant.sh" \
      || { echo "the grant's copy was not pinned to this rig ($_pin); 68b would act on this host's paths"; exit 1; }
  done
  # An installed dashboard (#964): its unit names the node it runs, and the
  # tree has tsx. The grant refuses before any write without both, so this
  # row never depends on whether the runner has node on its PATH.
  mkdir -p "$TMP/node851" "$REPO/dashboard/node_modules/tsx/dist"
  printf '#!/bin/sh\nexit 0\n' > "$TMP/node851/node"; chmod 755 "$TMP/node851/node"
  : > "$REPO/dashboard/node_modules/tsx/dist/cli.mjs"
  unit aperire-server "$REPO/dashboard" "$CALLER_USER" "$TMP/node851/node --import tsx server.ts"
  # The modes a real host has (root 0755), whatever this shell's umask left:
  # the grant's dirsafe refuses a root directory any wider.
  chmod 755 "$TMP/sbin851" "$ETC" "$ETC/aperire" "$TMP/etc/systemd" "$UNITS" "$REPO" "$REPO/dashboard" "$REPO/dashboard/config"
  grant_851() {
    ( cd "$REPO" && timeout 120 fakeroot bash "$REPO/scripts/install-fleet-broker-grant.sh" 2>&1 )
  }
  out="$(grant_851)"; rc=$?
  is "the grant refuses with exit 4" "$rc" "4"
  has "  naming the paired node" "$out" "paired nodes: core-two"
  has "  and the restore, through the bootstrap" "$out" "bash -s -- --dir $REPO --restore --from <backup set>"
  is "  and makes no arm key" "$([[ -e "$ETC/aperire/fleet-arm.key" ]] && echo made || echo none)" "none"
  is "  and writes no program, conf or unit" \
    "$(find "$TMP/sbin851" "$ETC/aperire/fleet-broker.conf" "$UNITS/aperire-fleet-broker.socket" -mindepth 0 2>/dev/null | grep -v "^$TMP/sbin851\$" | tr '\n' ' ')" ""
  FROM="$DEST"
  # The restore runs unprivileged here, through the shim; the grant stages
  # its own copy of the real file, so it gets the real one back after.
  write_state_shim
  out=$(run_restore 2>&1); rc=$?
  is "the restore then exits 0, with no key in its way" "$rc" "0"
  is "  and the arm key is the set's" "$(sha256sum < "$ETC/aperire/fleet-arm.key" 2>/dev/null)" "$SET_851_SUM"
  cp "$REPO_DIR/scripts/state-file.py" "$REPO/scripts/state-file.py"
  out="$(grant_851)"; rc=$?
  hasnt "the grant run again does not refuse" "$out" "paired nodes:"
  has "  it keeps the restored arm key" "$out" "(kept: this aggregator already has a fleet arm key)"
  is "  byte for byte" "$(sha256sum < "$ETC/aperire/fleet-arm.key" 2>/dev/null)" "$SET_851_SUM"
  is "  and places both programs and the conf" \
    "$( [[ -f "$TMP/sbin851/aperire-fleet-broker" && -f "$TMP/sbin851/aperire-fleet-arm" && -f "$ETC/aperire/fleet-broker.conf" ]] && echo yes || echo no)" "yes"
  rm -rf "$TMP/sbin851" "$TMP/run851" "$TMP/node851" "$REPO/dashboard/node_modules"
  unit aperire-server "$REPO/dashboard" "$CALLER_USER"
  rm -f "$ETC/aperire/fleet-arm.key" "$ETC/aperire/fleet-broker.conf" "$UNITS"/aperire-fleet-broker*
else
  bad "68b needs fakeroot to run the real grant installer" ""
fi

echo
echo "69. the node check and the Advisor checks never go through a proxy, and the approve token never rides argv (review L2, #798)"
wipe_aggregator
build_sut
FROM="$AGG_SET"
: > "$FAKE_CURL_LOG"; : > "$FAKE_CURL_HDR_LOG"
out=$(http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
_node_line="$(grep -F '/read/v1/recent' "$FAKE_CURL_LOG" | head -1)"
is "the node read's first argument is -q, so no curlrc adds a proxy" "${_node_line%% *}" "-q"
has "  and it names --noproxy for every host" "$_node_line" "--noproxy *"
_led_line="$(grep -F '/v1/ledger' "$FAKE_CURL_LOG" | head -1)"
is "the ledger check's first argument is -q" "${_led_line%% *}" "-q"
has "  and --noproxy" "$_led_line" "--noproxy *"
hasnt "the Advisor's approve token is on no curl argv (#798)" "$(cat "$FAKE_CURL_LOG")" "approve-token"
has "  it went in a header file" "$(cat "$FAKE_CURL_HDR_LOG")" "Authorization: Bearer approve-token"
has "the ledger check still passes through it" "$out" "PASS  the ledger chain verifies"
is "no header file is left behind in the run's own directory" \
  "$(find "$REPO-restore-work" -name '*.hdr' 2>/dev/null | wc -l | tr -d ' ')" "0"

echo
echo "70. a token_path that names a FIFO cannot hang the restore's last check (review I1)"
FIFO_SET="$TMP/set-agg-fifo"
rm -rf "$FIFO_SET"; cp -a "$AGG_SET" "$FIFO_SET"
mkfifo "$TMP/token-fifo"
sed -i "s#token_path: $ETC/aperire/fleet-tokens/core-two.token#token_path: $TMP/token-fifo#" "$FIFO_SET/config/fleet.yaml"
reseal_set "$FIFO_SET"
wipe_aggregator
build_sut
FROM="$FIFO_SET"
export APERIRE_RESTORE_NODE_WAIT=0
dash_pid_opens "$(fixture_expected_db "")"
out=$( cd "$REPO" && timeout 60 bash "$REPO/scripts/aperire-restore.sh" --from "$FROM" --yes --overwrite 2>&1 ); rc=$?
unset APERIRE_RESTORE_NODE_WAIT
is "the restore ends on its own with a FAIL, not killed by a timeout" "$rc" "1"
has "  naming the token it could not read" "$out" "its token at $TMP/token-fifo cannot be read"
FROM="$AGG_SET"

echo
echo "71. an aggregator whose Advisor has its own account: the restored tokens land on the group the two share (#809)"
# Row 48's Advisor runs as the dashboard's own account, so the right answer
# (the group the two share) and the credcheck misread (root, so the
# dashboard's own primary group) are the same group there, and a reader that
# took the credcheck unit's User=root again would still pass it. Here the
# Advisor has its own account, in a shared group the dashboard's primary
# group is not, the shape install-advisor-account.sh leaves, and the
# credcheck unit (User=root) still sits beside it.
SHARED_809=""
if [[ "$ALT_GROUP" != "$CALLER_GROUP" ]]; then
  SHARED_809="$ALT_GROUP"
elif [[ "$(id -u)" == 0 ]] && getent group daemon >/dev/null 2>&1 && [[ "$CALLER_GROUP" != daemon ]]; then
  SHARED_809="daemon"
fi
if [[ -z "$SHARED_809" ]]; then
  echo "  SKIP this test's own account belongs to only one real group; nothing here to tell shared and private groups apart with"
else
  SPLIT_ADV_USER="aperire-advisor-test"
  mk_aggregator
  unit aperire-advisord "" "$SPLIT_ADV_USER" "/opt/advisord --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
  printf 'SupplementaryGroups=%s\n' "$SHARED_809" >> "$UNITS/aperire-advisord.service"
  export FAKE_USERS="$SPLIT_ADV_USER"
  _my_uid="$(id -u)"
  export FAKE_IDS="$SPLIT_ADV_USER=$_my_uid:$_my_uid"
  export FAKE_PRIMARY_GROUP="$SPLIT_ADV_USER=$CALLER_GROUP"
  export FAKE_GROUPS_OF="$SPLIT_ADV_USER=$SPLIT_ADV_USER,$SHARED_809 $CALLER_USER=$CALLER_GROUP,$SHARED_809"
  build_sut
  DEST="$TMP/set-agg-split"
  run_backup >/dev/null 2>&1
  wipe_aggregator
  build_sut
  : > "$FAKE_CHOWN_LOG"; : > "$FAKE_PLANT_LOG"
  FROM="$DEST"
  out=$(FAKE_CHOWN_GROUP_FALLBACK=1 run_restore 2>&1); rc=$?
  is "restore exits 0" "$rc" "0"
  is "the fixture carries the credcheck unit beside the Advisor's own, User=root" \
    "$(sed -n 's/^User=//p' "$UNITS/aperire-advisord-credcheck.service" 2>/dev/null)" "root"
  hasnt "  and it is not refused as sharing no group" "$out" "share no group"
  has "the node token is planted root : the group the Advisor and the dashboard share" \
    "$(cat "$FAKE_PLANT_LOG")" "plant $ETC/aperire/fleet-tokens/core-two.token 0 $(getent group "$SHARED_809" | cut -d: -f3) 0640"
  is "  and that is the group it has on disk" \
    "$(stat -c %G "$ETC/aperire/fleet-tokens/core-two.token" 2>/dev/null)" "$SHARED_809"
  is "  the directory too" "$(stat -c %G "$ETC/aperire/fleet-tokens" 2>/dev/null)" "$SHARED_809"
  hasnt "  never the dashboard's own primary group, which the Advisor is not in" \
    "$(cat "$FAKE_PLANT_LOG")" "plant $ETC/aperire/fleet-tokens/core-two.token 0 $(getent group "$CALLER_GROUP" | cut -d: -f3) 0640"

  echo
  echo "72. the same aggregator, its Advisor unit naming no User= this can read: refused by name before anything stops (#809)"
  # Its only User= is under [Install], which systemd never applies: the shape
  # that used to read as "no User=, so root", and so the dashboard's group.
  printf '[Service]\nExecStart=/opt/advisord --state=%s\n[Install]\nUser=%s\n' "$REPO/advisor/state" \
    "$SPLIT_ADV_USER" > "$UNITS/aperire-advisord.service"
  wipe_aggregator
  build_sut
  FROM="$DEST"
  out=$(run_restore 2>&1); rc=$?
  is "exit code is 4" "$rc" "4"
  has "it says it could not read the Advisor's account" "$out" "could not read which account the Advisor runs as"
  hasnt "  and does not call that sharing no group" "$out" "share no group"
  is "no node token was written" "$([[ -e "$ETC/aperire/fleet-tokens" ]] && echo yes || echo no)" "no"
  is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
  unset FAKE_USERS FAKE_IDS FAKE_PRIMARY_GROUP FAKE_GROUPS_OF
fi

echo
echo "72b. a restore splits the fleet trust file: an aggregator's key comes back 0600 with its public half beside it, a node's peers-only file 0640 (#868, #821)"
mk_aggregator
SEED72="$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
printf 'private_key: %s\npeers:\n  aggregator: AAAA\n' "$SEED72" > "$REPO/dashboard/config/fleet-trust.yaml"
chmod 640 "$REPO/dashboard/config/fleet-trust.yaml"
WANT72="$(python3 -c 'import base64,sys; s=sys.argv[1]; sys.stdout.buffer.write(bytes.fromhex("302e020100300506032b657004220420")+base64.urlsafe_b64decode(s+"="*(-len(s)%4)))' "$SEED72" \
  | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
# Root's pin of that key (#1008), which the set carries as its own row.
PIN72="$ETC/aperire/fleet-trust.pub"
printf '%s\n' "$WANT72" > "$PIN72"; chmod 644 "$PIN72"
build_sut
DEST="$TMP/set-868"
run_backup >/dev/null 2>&1
is "the set carries root's pin as its own row (#1008)" "$(cat "$DEST/fleet-trust.pub" 2>/dev/null)" "$WANT72"
is "the set does not carry a public file (it is remade, never restored)" \
  "$(find "$DEST" -name '*.pub.yaml' 2>/dev/null | wc -l)" "0"
wipe_aggregator
rm -f "$REPO/dashboard/config/fleet-trust.pub.yaml"
export APERIRE_FLEET_BROKER_PATH="$TMP/sbin/aperire-fleet-broker"
# The Advisor's unit starts a build that reads the public file, the shape
# this release's own build has. Under an older build the key is left as it
# was placed (scripts/test-fleet-trust-split.sh holds that branch).
printf 'a build that reads fleet-trust.pub.yaml\n' > "$TMP/advisord-868"
unit aperire-advisord "" "$CALLER_USER" "$TMP/advisord-868 --addr=127.0.0.1:7810 --state=$REPO/advisor/state"
build_sut
FROM="$DEST"
: > "$FAKE_PLANT_LOG"
# Root's pin (#1008) already holds some other key, as on a host this set is
# restored onto. The restore refuses before anything stops, and takes the
# set's pin only when --replace-trust-pin says so.
OTHER72="$(openssl genpkey -algorithm ed25519 2>/dev/null | openssl pkey -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
printf '%s\n' "$OTHER72" > "$PIN72"; chmod 644 "$PIN72"
out=$(run_restore 2>&1); rc=$?
if [[ $rc -eq 9 && "$(cat "$PIN72")" == "$OTHER72" && ! -e "$REPO/dashboard/config/fleet-trust.yaml" ]] \
   && has_q "$out" "already pins a fleet trust key" && has_q "$out" "--replace-trust-pin"; then
  ok "a set whose pin differs from the one here is refused (exit 9), nothing touched, and the flag is named (#1008)"
else
  bad "a differing pin is refused on restore" "rc=$rc pin $(cat "$PIN72") out: $(tail -5 <<<"$out")"; fi
out=$(run_restore --replace-trust-pin 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
TF72="$REPO/dashboard/config/fleet-trust.yaml"
PF72="$REPO/dashboard/config/fleet-trust.pub.yaml"
is "the key file is back byte for byte" "$(sha256sum < "$TF72")" "$(sha256sum < "$DEST/config/fleet-trust.yaml")"
is "  at 0600, the dashboard account's alone" "$(stat -c '%U %a' "$TF72")" "$CALLER_USER 600"
hasnt "  planted as the dashboard account, never root's (a key is not the Advisor's to read)" \
  "$(cat "$FAKE_PLANT_LOG")" "plant $TF72 0 "
is "the public half is beside it, 0640 on the group the Advisor shares" \
  "$(stat -c '%U %G %a' "$PF72" 2>/dev/null)" "$CALLER_USER $CALLER_GROUP 640"
hasnt "  and it carries no private_key" "$(cat "$PF72" 2>/dev/null)" "private_key"
is "  and it carries the public key the seed derives" \
  "$(sed -n 's/^public_key: //p' "$PF72")" \
  "$(python3 -c 'import base64,sys; s=sys.argv[1]; sys.stdout.buffer.write(bytes.fromhex("302e020100300506032b657004220420")+base64.urlsafe_b64decode(s+"="*(-len(s)%4)))' "$SEED72" \
     | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
has "  and the restore says so" "$out" "fleet-trust.pub.yaml ->"
is "  and with --replace-trust-pin, root's pin is the set's pin now (#1008)" \
  "$(cat "$PIN72" 2>/dev/null)" "${WANT72:-no key derived}"
# The set's fleet-trust.yaml is the dashboard account's file: a key planted
# there before the backup is not what the restore pins. The set's pin row is.
printf 'private_key: %s\npeers: {}\n' "$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')" \
  > "$REPO/dashboard/config/fleet-trust.yaml"
DEST="$TMP/set-1008-planted"
run_backup >/dev/null 2>&1
wipe_aggregator
rm -f "$PIN72" "$REPO/dashboard/config/fleet-trust.pub.yaml"
build_sut
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
if [[ $rc -eq 3 && ! -e "$PIN72" && ! -e "$REPO/dashboard/config/fleet-trust.yaml" ]] \
   && has_q "$out" "root's pin in the set:" && has_q "$out" "$WANT72"; then
  ok "a set whose key is not its own root pin is refused before anything stops (exit 3); root's pin is what it compares with"
else
  bad "a restore takes root's pin, not the dashboard's" "rc=$rc pin '$(cat "$PIN72" 2>/dev/null)' out: $(tail -6 <<<"$out")"; fi
# A set taken before root pinned anything carries no pin row: onto a host with
# no pin, the restore says out loud that it will pin the set's key on first
# sight; onto a host that pins a different key, it refuses (exit 9).
mk_aggregator
SEED1008="$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
printf 'private_key: %s\npeers: {}\n' "$SEED1008" > "$REPO/dashboard/config/fleet-trust.yaml"; chmod 640 "$REPO/dashboard/config/fleet-trust.yaml"
rm -f "$PIN72"
DEST="$TMP/set-1008-nopin"
build_sut
run_backup >/dev/null 2>&1
is "  a set taken with no pin on the host carries no pin row" "$([[ -e "$DEST/fleet-trust.pub" ]] && echo yes || echo no)" "no"
wipe_aggregator
rm -f "$REPO/dashboard/config/fleet-trust.pub.yaml"
FROM="$DEST"
out=$(run_restore --dry-run 2>&1); rc=$?
has "  onto a host with no pin, it says the set's key will be pinned on first sight" "$out" "taken before root pinned the fleet trust key"
printf '%s\n' "$OTHER72" > "$PIN72"; chmod 644 "$PIN72"
out=$(run_restore 2>&1); rc=$?
if [[ $rc -eq 9 && "$(cat "$PIN72")" == "$OTHER72" ]] && has_q "$out" "carries a different key and no pin of its own"; then
  ok "  onto a host that pins a different key, a set with no pin is refused (exit 9), nothing touched"
else
  bad "a pinless set onto a differently pinned host is refused" "rc=$rc out: $(tail -6 <<<"$out")"; fi
rm -f "$PIN72"
# A node: peers only. The table's 0600 would leave the Advisor unable to read
# it (#821); the split puts it on the shared group at 0640.
mk_full
build_sut
DEST="$TMP/set-821"
run_backup >/dev/null 2>&1
rm -f "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-link.json} "$REPO/dashboard/config/fleet-trust.pub.yaml"
rm -f "$REPO/data/aperire.db"
build_sut
FROM="$DEST"
: > "$FAKE_CHOWN_LOG"; : > "$FAKE_PLANT_LOG"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
# Root's, as pairing makes it, never the dashboard account's, which could
# repin peers.aggregator (#873 review, M2). It goes back through the same
# descriptor walk as every other config file, never a chown by name. This rig
# cannot fchown to root, so the request is read from the plant shim's log
# (uid 0, the group's gid, mode 0640), and the mode from the file.
CALLER_GID_868="$(id -g)"
has "a node's peers-only fleet-trust.yaml is planted root's on the Advisor's group at 0640 (M2)" \
  "$(cat "$FAKE_PLANT_LOG")" "plant $REPO/dashboard/config/fleet-trust.yaml 0 $CALLER_GID_868 0640"
hasnt "  and never as the dashboard account's" \
  "$(cat "$FAKE_PLANT_LOG")" "plant $REPO/dashboard/config/fleet-trust.yaml $(id -u) "
is "  and no chown was aimed at it by name" \
  "$(grep -c -- 'dashboard/config/fleet-trust.yaml$' "$FAKE_CHOWN_LOG")" "0"
is "  at 0640, readable by the Advisor, not the table's 0600 (#821)" \
  "$(stat -c '%a' "$REPO/dashboard/config/fleet-trust.yaml")" "640"
is "  and no public file is made for a file with no key" \
  "$([[ -e "$REPO/dashboard/config/fleet-trust.pub.yaml" ]] && echo yes || echo no)" "no"
unset APERIRE_FLEET_BROKER_PATH

fi

# ── #776: the database is written into data/, a directory the dashboard's
#    account owns, and root must never act on a name there ──────────────
# A sentinel stands in for any file root could be steered onto: a real
# SQLite database with the dashboard's own table (so no content check can
# tell it apart), outside the install, mode 0644.
mk_776_sentinel() {
  SENTINEL_DIR="$TMP/outside-776"
  rm -rf "$SENTINEL_DIR"; mkdir -p "$SENTINEL_DIR"
  SENTINEL="$SENTINEL_DIR/victim.db"
  mk_db "$SENTINEL" "victim"
  chmod 0644 "$SENTINEL"
  SENTINEL_SUM="$(sha256sum "$SENTINEL" | awk '{print $1}')"
}

echo
echo "73. a link already at data/aperire.db is refused before anything stops (#776)"
mk_plain; build_sut
DEST="$TMP/set-776-link"
run_backup >/dev/null 2>&1
mk_776_sentinel
rm -f "$REPO/data/aperire.db"
ln -s "$SENTINEL" "$REPO/data/aperire.db"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 4" "$rc" "4"
has "it names the link" "$out" "$REPO/data/aperire.db is a symbolic link"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
is "the link is still the link it was" "$(readlink "$REPO/data/aperire.db")" "$SENTINEL"
is "the file it points at is byte-identical" "$(sha256sum "$SENTINEL" | awk '{print $1}')" "$SENTINEL_SUM"
is "  and keeps its mode" "$(stat -c '%a' "$SENTINEL")" "644"

echo
echo "74. the database's name swapped for a link after it is written: nothing lands on the link's target (#776)"
# The account that owns data/ can swap the name between root's write and
# root's chown and chmod by name. The stub makes that swap at the chown, so
# whatever root does to the name after the write shows up on the sentinel.
mk_plain; build_sut
DEST="$TMP/set-776-race"
run_backup >/dev/null 2>&1
mk_776_sentinel
: > "$FAKE_CHOWN_LOG"
FROM="$DEST"
out=$(FAKE_CHOWN_SWAP="$REPO/data/aperire.db|$SENTINEL" run_restore 2>&1); rc=$?
is "the sentinel is byte-identical" "$(sha256sum "$SENTINEL" | awk '{print $1}')" "$SENTINEL_SUM"
is "  and keeps its mode" "$(stat -c '%a' "$SENTINEL")" "644"
is "no chown is aimed at the database by name" \
  "$(grep -c -- " $REPO/data/aperire.db\$" "$FAKE_CHOWN_LOG")" "0"
is "the restored database is a plain file, not a link" \
  "$([[ -f "$REPO/data/aperire.db" && ! -L "$REPO/data/aperire.db" ]] && echo yes || echo no)" "yes"

echo
echo "75. the database is written by the dashboard unit's User=, not by root (#776, ADR 0024 lane 4)"
# The unit names an account other than the one running this suite, so the
# write has to switch to it. Not root, so the switch is the sudo stub, which
# logs who it switched to and then runs as this suite.
mk_plain; build_sut
DEST="$TMP/set-776-asdash"
run_backup >/dev/null 2>&1
unit aperire-server "$REPO/dashboard" aperire-dashboard
export FAKE_USERS="aperire-dashboard"
# Its uid is this suite's, and its group one this suite is really in, so the
# config files' fchown is one an ordinary account may make and a real stat
# can read back.
FAKE_IDS="aperire-dashboard=$(id -u):$(id -g)"
export FAKE_IDS
export FAKE_PRIMARY_GROUP="aperire-dashboard=$ALT_GROUP"
# Lane C's installer leaves dashboard/config the operator's and closed to
# group and other writes on this shape; the fixture's umask may not.
chmod 0755 "$REPO/dashboard/config"
# One log for both routes: sudo when this suite runs as an ordinary account,
# runuser when it runs as root (a CI runner may), the restore's own route on
# a real host. Both stubs log "<account> :: <command>".
export FAKE_SUDO_LOG="$TMP/sudo-log-776"
export FAKE_RUNUSER_LOG="$FAKE_SUDO_LOG"
: > "$FAKE_SUDO_LOG"
: > "$FAKE_CHOWN_LOG"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
_sl="$(cat "$FAKE_SUDO_LOG")"
has "the database was written as aperire-dashboard" "$_sl" "aperire-dashboard :: python3"
has "  into its own path" "$_sl" "$REPO/data/aperire.db"
has "the integrity check ran as aperire-dashboard too" "$_sl" "aperire-dashboard :: sqlite3"
is "the restored content is the set's" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "plain"
# The operator's own config files stay the operator's: owned by whoever owns
# dashboard/config, read by the dashboard through its group (ADR 0024).
is "authn.yaml goes to the owner of dashboard/config, in the dashboard's group, 0640" \
  "$(stat -c '%U %G %a' "$REPO/dashboard/config/authn.yaml")" "$CALLER_USER $ALT_GROUP 640"
is "  and no chown was aimed at it by name" \
  "$(grep -c -- "dashboard/config/authn.yaml\$" "$FAKE_CHOWN_LOG")" "0"
unset FAKE_USERS FAKE_SUDO_LOG FAKE_RUNUSER_LOG FAKE_IDS FAKE_PRIMARY_GROUP

echo
echo "76. data/ itself swapped for a link to somewhere else is refused before anything stops (#776)"
mk_plain; build_sut
DEST="$TMP/set-776-dirlink"
run_backup >/dev/null 2>&1
mk_776_sentinel
cp "$REPO/data/aperire.db" "$SENTINEL_DIR/aperire.db"
_dl_sum="$(sha256sum "$SENTINEL_DIR/aperire.db" | awk '{print $1}')"
rm -rf "$REPO/data"
ln -s "$SENTINEL_DIR" "$REPO/data"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "exit code is 4" "$rc" "4"
has "it names the directory as a link" "$out" "$REPO/data, the directory the database goes in, is a symbolic link"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
is "nothing in the directory it points at changed" "$(sha256sum "$SENTINEL_DIR/aperire.db" | awk '{print $1}')" "$_dl_sum"
rm -f "$REPO/data"

echo
echo "77. a database directory the dashboard's account cannot write is refused before anything stops (#776)"
if [[ "$(id -u)" == 0 ]]; then
  # Root writes through any mode, so a root run cannot make a directory this
  # suite's own account is unable to write. Said, never silently passed.
  echo "  skip  this suite runs as root here, and root writes through a 0500 directory"
else
mk_plain; build_sut
DEST="$TMP/set-776-unwritable"
run_backup >/dev/null 2>&1
chmod 0500 "$REPO/data"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
chmod 0700 "$REPO/data"
is "exit code is 4" "$rc" "4"
has "it says the account cannot write there" "$out" "cannot write $REPO/data"
has "  and names the command that fixes it" "$out" "sudo install -d -o $CALLER_USER -m 0700 $REPO/data"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
is "the host's own database is untouched" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "plain"
fi

echo
echo "78. the backup reads data/ as the dashboard unit's effective User=, a drop-in's included (ADR 0024 lane 4)"
# The unit body names one account and a drop-in another. systemd runs the
# drop-in's, so that is the reader. The body names an account this host does
# not have, so a reader that took the body's line would fail outright.
mk_plain; build_sut
unit aperire-server "$REPO/dashboard" aperire-dashboard
mkdir -p "$UNITS/aperire-server.service.d"
printf '[Service]\nUser=%s\n' "$CALLER_USER" > "$UNITS/aperire-server.service.d/50-account.conf"
export FAKE_RUNUSER_LOG="$TMP/runuser-log-78"
: > "$FAKE_RUNUSER_LOG"
DEST="$TMP/set-78"
out=$(run_backup 2>&1); rc=$?
if [[ $rc -eq 0 ]]; then ok "backup exits 0"; else bad "backup exits 0" "rc=$rc: $out"; fi
has "the database snapshot was taken as the drop-in's account" "$(cat "$FAKE_RUNUSER_LOG")" \
  "$CALLER_USER :: sqlite3 -init /dev/null $REPO/data/aperire.db VACUUM INTO"
rm -rf "$UNITS/aperire-server.service.d"
unset FAKE_RUNUSER_LOG

echo
echo "79. a dashboard unit whose User= cannot be read is refused, never read as root (ADR 0024 lane 4)"
mk_plain; build_sut
printf '[Service]\nWorkingDirectory=%s/dashboard\n[Install]\nUser=%s\n' "$REPO" "$CALLER_USER" > "$UNITS/aperire-server.service"
export FAKE_RUNUSER_LOG="$TMP/runuser-log-79"
: > "$FAKE_RUNUSER_LOG"
DEST="$TMP/set-79"
out=$(run_backup 2>&1); rc=$?
is "backup exits 1" "$rc" "1"
has "it says it could not read the account" "$out" "could not read which account the dashboard runs as"
is "nothing was read as anyone" "$(cat "$FAKE_RUNUSER_LOG")" ""
unset FAKE_RUNUSER_LOG

echo
echo "80. a WAL-mode database round-trips, and the restore leaves nothing of its own staging behind (#776)"
# The dashboard's real database runs in WAL mode. The staged copy is checked
# read-only beside the destination, and a WAL file can grow -wal and -shm
# siblings under the staged name: none may survive the restore.
mk_plain; build_sut
sqlite3 "$REPO/data/aperire.db" 'PRAGMA journal_mode=WAL;' >/dev/null
sqlite3 "$REPO/data/aperire.db" "UPDATE test_marker SET v='wal-host';"
DEST="$TMP/set-776-wal"
run_backup >/dev/null 2>&1
_wal_mode="$(sqlite3 "$DEST/aperire.db" 'PRAGMA journal_mode;' 2>/dev/null)"
echo "  note  the set's copy reports journal_mode=${_wal_mode:-unknown}"
mk_plain; build_sut
sqlite3 "$REPO/data/aperire.db" 'PRAGMA journal_mode=WAL;' >/dev/null
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "the restored content is the set's" \
  "$(sqlite3 "$REPO/data/aperire.db" "SELECT v FROM test_marker" 2>/dev/null)" "wal-host"
is "nothing named for the staging survives in data/" \
  "$(find "$REPO/data" -maxdepth 1 -name '.aperire-restore.*' | tr '\n' ' ')" ""
is "the restored database passes integrity_check" \
  "$(sqlite3 "$REPO/data/aperire.db" 'PRAGMA integrity_check' 2>/dev/null)" "ok"

echo
echo "81. a config name swapped for a link at root's chown, or already a link, lands nothing outside (#776 config half, #875 review M2)"
# A host installed before ADR 0024: dashboard/config is the dashboard
# account's own directory, so every name in it is that account's to swap.
mk_plain; build_sut
DEST="$TMP/set-776-cfg"
run_backup >/dev/null 2>&1
mk_776_sentinel
SENT2="$SENTINEL_DIR/victim2.txt"; printf 'not yours\n' > "$SENT2"; chmod 0644 "$SENT2"
SENT2_SUM="$(sha256sum "$SENT2" | awk '{print $1}')"
rm -f "$REPO/dashboard/config/channels.yaml"
ln -s "$SENT2" "$REPO/dashboard/config/channels.yaml"
: > "$FAKE_CHOWN_LOG"
FROM="$DEST"
out=$(FAKE_CHOWN_SWAP="$REPO/dashboard/config/authn.yaml|$SENTINEL" run_restore 2>&1); rc=$?
is "restore exits 0" "$rc" "0"
is "the file a swap at authn.yaml points at keeps its mode" "$(stat -c '%a' "$SENTINEL")" "644"
is "  and its bytes" "$(sha256sum "$SENTINEL" | awk '{print $1}')" "$SENTINEL_SUM"
is "authn.yaml is the set's, a plain file" \
  "$([[ -f "$REPO/dashboard/config/authn.yaml" && ! -L "$REPO/dashboard/config/authn.yaml" ]] && cat "$REPO/dashboard/config/authn.yaml")" "authn: {v: 1}"
is "a link already at channels.yaml is replaced, not written through" \
  "$(if [[ -L "$REPO/dashboard/config/channels.yaml" ]]; then echo link; else cat "$REPO/dashboard/config/channels.yaml"; fi)" "channels: {v: 1}"
is "  and the file it pointed at is untouched" "$(sha256sum "$SENT2" | awk '{print $1}')" "$SENT2_SUM"
is "no chown is aimed at a config file by name" "$(grep -c -- '/dashboard/config/' "$FAKE_CHOWN_LOG")" "0"

echo
echo "82. on a dashboard with its own account, a dashboard/config others can write is refused before anything stops (#875 review, L2)"
mk_plain; build_sut
DEST="$TMP/set-776-cfgmode"
run_backup >/dev/null 2>&1
unit aperire-server "$REPO/dashboard" aperire-dashboard
FAKE_IDS="aperire-dashboard=$(id -u):$(id -g)"
export FAKE_USERS="aperire-dashboard" FAKE_IDS FAKE_PRIMARY_GROUP="aperire-dashboard=$ALT_GROUP"
chmod 0775 "$REPO/dashboard/config"
FROM="$DEST"
out=$(run_restore 2>&1); rc=$?
chmod 0755 "$REPO/dashboard/config"
is "exit code is 4" "$rc" "4"
has "it says the directory has to be the operator's and closed" "$out" "closed to group and other writes"
has "  and names the installer re-run" "$out" "--update --force"
is "the dashboard was never stopped" "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
unset FAKE_USERS FAKE_IDS FAKE_PRIMARY_GROUP

echo
echo "83. backup and restore run from the release's staged copy and execute nothing from the install's tree (#941)"
# Under ADR 0024 root never runs a script the login can change. get-aperire.sh
# stages the release's scripts into a root-only directory and runs the copy
# there, naming the install in APERIRE_INSTALL_TREE. This is that shape: the
# program, its libraries and the state helper copied out beside the tree, and
# then every file of the tree's scripts/ replaced with a tripwire that leaves
# its own path in a log and exits 97. A run that loads or runs anything from
# the tree trips it. The same run is traced (every command, with the file it
# was read from) because a tripwire cannot see a file that was read and not
# run, and the trace can.
STAGE_941="$TMP/stage941"; TRIP_941="$TMP/trip941"; TRACE_941="$TMP/trace941"
stage_941() {  # copies $REPO/scripts out to the stage, then tripwires the tree's own
  rm -rf "$STAGE_941"; mkdir -p "$STAGE_941"
  cp -a "$REPO/scripts" "$STAGE_941/scripts"
  : > "$TRIP_941"
  local f
  for f in "$REPO/scripts"/*; do
    case "$f" in
      *.py) printf 'import sys\nopen("%s", "a").write("%s\\n")\nsys.exit(97)\n' "$TRIP_941" "$f" > "$f" ;;
      *)    printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s" >> "%s"\nexit 97\n' "$f" "$TRIP_941" > "$f" ;;
    esac
  done
}
# From outside the tree, with the tree named and a trace on: SHELLOPTS reaches
# every bash the run starts, the prompt carries the file each line is from, and
# BASH_XTRACEFD sends the trace to a file of its own, because the programs read
# their own stderr into variables and a trace there would change what they do.
# shellcheck disable=SC2016  # PS4 is expanded by the traced shell, not this one
staged_941() {  # <program> <args...>; stdout and stderr are the program's, the trace is in $TRACE_941
  local prog=$1; shift
  ( cd "$TMP" && exec 9>"$TRACE_941" \
    && env APERIRE_INSTALL_TREE="$REPO" SHELLOPTS=xtrace BASH_XTRACEFD=9 PS4='+X ${BASH_SOURCE[0]:-}: ' \
      bash "$STAGE_941/scripts/$prog" "$@" ) 2>&1
}
mk_full
build_sut
stage_941
# The control: the tripwire fires on a source, a run and a python start.
ctl_rc=0
bash -c '. "$1"' _ "$REPO/scripts/dashboard-account-lib.sh" >/dev/null 2>&1 || ctl_rc=$?
python3 -I "$REPO/scripts/state-file.py" read /nonexistent >/dev/null 2>&1 || true
if [[ $ctl_rc -eq 97 ]] && grep -qF -e "$REPO/scripts/dashboard-account-lib.sh" "$TRIP_941" \
   && grep -qF -e "$REPO/scripts/state-file.py" "$TRIP_941"; then
  ok "the tripwire fires when the tree's library is sourced and when the tree's state helper is started"
else
  bad "the tripwire fires" "rc=$ctl_rc log=$(cat "$TRIP_941")"
fi
: > "$TRIP_941"

DEST="$TMP/set-941"; rm -rf "$DEST"
out=$(staged_941 aperire-backup.sh --to "$DEST" --yes); rc=$?
is "the staged backup exits 0 on an install named only by APERIRE_INSTALL_TREE" "$rc" "0"
has "  and it backs up that install, not the stage" "$out" "install: $REPO"
is "  the set holds the database and the Advisor's state" \
  "$([[ -f "$DEST/aperire.db" && -f "$DEST/advisor-state/ledger.jsonl" ]] && echo yes || echo no)" "yes"
is "  nothing in the tree's scripts/ was run or sourced (tripwire log)" "$(cat "$TRIP_941")" ""
is "  and no traced command came from a file under the tree's scripts/" \
  "$(grep -cE "^\++X $REPO/scripts/" "$TRACE_941")" "0"
if [[ "$(grep -cE "^\++X $STAGE_941/scripts/" "$TRACE_941")" -gt 20 ]]; then
  ok "  while the trace does show the staged program and its libraries running"
else
  bad "the trace records the staged copy" "$(head -5 "$TRACE_941")"
fi

# A fresh install of the same shape, then the restore from the set above.
rm -rf "$REPO/advisor/state"; mkdir -p "$REPO/advisor/state"
rm -f "$REPO/dashboard/config"/{fleet.yaml,fleet-trust.yaml,fleet-link.json}
rm -f "$ETC/aperire/fleet-arm.pub" "$ETC/aperire/relay.conf" "$REPO/data/aperire.db"
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
: > "$TRIP_941"
out=$(staged_941 aperire-restore.sh --from "$DEST" --yes --overwrite); rc=$?
is "the staged restore exits 0" "$rc" "0"
is "  and put the Advisor's state back" \
  "$(cat "$REPO/advisor/state/ledger.jsonl" 2>/dev/null)" "$(cat "$DEST/advisor-state/ledger.jsonl")"
has "  with the closing checks passing" "$out" "PASS  the ledger chain verifies"
is "  nothing in the tree's scripts/ was run or sourced (tripwire log)" "$(cat "$TRIP_941")" ""
is "  and no traced command came from a file under the tree's scripts/" \
  "$(grep -cE "^\++X $REPO/scripts/" "$TRACE_941")" "0"
is "  the state helper every plant goes through is the staged copy" \
  "$(grep -cE "python3 -I $STAGE_941/scripts/state-file.py (plant|mkdir|ancestors|read)" "$TRACE_941" | awk '{print ($1 > 0) ? "staged" : "none"}')" "staged"
is "  and no run of the tree's state helper appears in the trace" \
  "$(grep -cE "python3 -I $REPO/scripts/state-file.py" "$TRACE_941")" "0"

# The same restore on a set that carries a fleet trust key goes through
# fleet-trust-split.sh, which is sourced, not run, and the only file of the
# four the rows above never reach.
mk_full
build_sut
printf 'private_key: k\npeers: []\n' > "$REPO/dashboard/config/fleet-trust.yaml"
chmod 600 "$REPO/dashboard/config/fleet-trust.yaml"
DEST="$TMP/set-941b"; rm -rf "$DEST"
run_backup >/dev/null 2>&1
stage_941
FROM="$DEST"
dash_pid_opens "$(fixture_expected_db "")"
out=$(staged_941 aperire-restore.sh --from "$DEST" --yes --overwrite); rc=$?
is "a restore of a set with fleet-trust.yaml runs the staged split, not the tree's" \
  "$(cat "$TRIP_941"; grep -cE "^\++X $REPO/scripts/" "$TRACE_941")" "0"
if [[ "$(grep -cE "^\++X $STAGE_941/scripts/fleet-trust-split.sh" "$TRACE_941")" -gt 0 ]]; then
  ok "  and the trace shows fleet-trust-split.sh running from the stage"
else
  bad "the staged fleet-trust-split.sh ran" "rc=$rc $(tail -5 <<<"$out")"
fi

echo
echo "84. every file the restore writes under /etc/aperire: a name swapped for a link at the write lands nothing outside (#965)"
# These used to be `install`, then chown and chmod on the name, as root. A
# link put at the name after the install took both onto whatever it pointed
# at. Each row swaps one name for a link to a file outside, at the moment
# root acts on it (the chown stand-in on a by-name write, the state-file shim
# on a descriptor write), then reads the outside file back: its bytes and
# its mode are what they were. A written file must also be the set's, at the
# table's mode, so no row can pass by the restore doing nothing.
OUT965="$TMP/outside-965"
fresh_victim() {  # <mode>
  rm -rf "$OUT965"; mkdir -p "$OUT965/dir"
  printf 'not yours\n' > "$OUT965/victim"; chmod "$1" "$OUT965/victim"; chmod 0755 "$OUT965/dir"
  VICTIM_SUM="$(sha256sum < "$OUT965/victim")"
}
export FAKE_SWAP_LOG="$TMP/swap-965.log"
mk_full; build_sut
DEST="$TMP/set-965"; rm -rf "$DEST"
run_backup >/dev/null 2>&1
FROM="$DEST"
for _row in "aperire.env|640" "relay.conf|640" "fleet-arm.pub|644" "fleet-arm.paired.pub|644"; do
  _name="${_row%%|*}"; _mode="${_row#*|}"
  _src="$DEST/$_name"; [[ "$_name" == fleet-arm.paired.pub ]] && _src="$DEST/fleet-arm.pub"
  fresh_victim 0600; : > "$FAKE_SWAP_LOG"; : > "$FAKE_CHOWN_LOG"
  out=$(FAKE_CHOWN_SWAP="$ETC/aperire/$_name|$OUT965/victim" run_restore 2>&1); rc=$?
  is "$_name swapped for a link at the write: the restore exits 0" "$rc" "0"
  is "  the file the link points at keeps its mode" "$(stat -c %a "$OUT965/victim")" "600"
  is "  and its bytes" "$(sha256sum < "$OUT965/victim")" "$VICTIM_SUM"
  has "  the swap really happened" "$(cat "$FAKE_SWAP_LOG")" "swapped $ETC/aperire/$_name"
  is "  $_name is the set's, a plain file at the table's mode" \
    "$([[ -f "$ETC/aperire/$_name" && ! -L "$ETC/aperire/$_name" ]] && echo "$(stat -c %a "$ETC/aperire/$_name") $(sha256sum < "$ETC/aperire/$_name")")" \
    "$_mode $(sha256sum < "$_src")"
  is "  no chown is aimed at it by name" "$(grep -c -- "$ETC/aperire/$_name\$" "$FAKE_CHOWN_LOG")" "0"
done

if command -v openssl >/dev/null 2>&1; then
  mk_aggregator; build_sut
  DEST="$TMP/set-965-agg"; rm -rf "$DEST"
  run_backup >/dev/null 2>&1
  FROM="$DEST"

  # A node token: the file is the set's, root's, and nothing outside moves.
  wipe_aggregator; cp "$DEST/fleet-arm.key" "$ETC/aperire/fleet-arm.key"; chmod 600 "$ETC/aperire/fleet-arm.key"
  fresh_victim 0600; : > "$FAKE_SWAP_LOG"
  mkdir -p "$ETC/aperire/fleet-tokens"; chmod 0750 "$ETC/aperire/fleet-tokens"
  out=$(FAKE_CHOWN_SWAP="$ETC/aperire/fleet-tokens/core-two.token|$OUT965/victim" run_restore 2>&1); rc=$?
  is "a node token swapped for a link at the write: the restore exits 0" "$rc" "0"
  is "  the file the link points at keeps its mode" "$(stat -c %a "$OUT965/victim")" "600"
  is "  and its bytes" "$(sha256sum < "$OUT965/victim")" "$VICTIM_SUM"
  has "  the swap really happened" "$(cat "$FAKE_SWAP_LOG")" "swapped $ETC/aperire/fleet-tokens/core-two.token"
  is "  the token is the set's, a plain file at 0640" \
    "$([[ -f "$ETC/aperire/fleet-tokens/core-two.token" && ! -L "$ETC/aperire/fleet-tokens/core-two.token" ]] && echo "$(stat -c %a "$ETC/aperire/fleet-tokens/core-two.token") $(cat "$ETC/aperire/fleet-tokens/core-two.token")")" \
    "640 $AGG_TOKEN"

  # The token directory itself: a link there is refused, never followed.
  wipe_aggregator; cp "$DEST/fleet-arm.key" "$ETC/aperire/fleet-arm.key"; chmod 600 "$ETC/aperire/fleet-arm.key"
  fresh_victim 0600; : > "$FAKE_SWAP_LOG"
  mkdir -p "$ETC/aperire/fleet-tokens"; chmod 0700 "$ETC/aperire/fleet-tokens"
  out=$(FAKE_CHOWN_SWAP="$ETC/aperire/fleet-tokens|$OUT965/dir" run_restore 2>&1); rc=$?
  is "the token directory swapped for a link at the write: the directory it points at keeps its mode" \
    "$(stat -c %a "$OUT965/dir")" "755"
  is "  and nothing was written into it" "$(find "$OUT965/dir" -mindepth 1 | wc -l | tr -d ' ')" "0"
  has "  the swap really happened" "$(cat "$FAKE_SWAP_LOG")" "swapped $ETC/aperire/fleet-tokens"
  is "  the restore stops there, rather than writing through it" "$rc" "1"
  has "  naming the directory" "$out" "could not create $ETC/aperire/fleet-tokens safely"
  rm -f "$ETC/aperire/fleet-tokens"; rm -rf "$ETC/aperire/fleet-tokens.swapped-away"

  # The arm key already the set's: its owner and mode are set on the open
  # key, and a link there since the check is refused.
  wipe_aggregator; cp "$DEST/fleet-arm.key" "$ETC/aperire/fleet-arm.key"; chmod 600 "$ETC/aperire/fleet-arm.key"
  fresh_victim 0644; : > "$FAKE_SWAP_LOG"
  out=$(FAKE_CHOWN_SWAP="$ETC/aperire/fleet-arm.key|$OUT965/victim" run_restore 2>&1); rc=$?
  is "the arm key swapped for a link after the check: the file it points at keeps its mode" \
    "$(stat -c %a "$OUT965/victim")" "644"
  is "  and its bytes" "$(sha256sum < "$OUT965/victim")" "$VICTIM_SUM"
  has "  the swap really happened" "$(cat "$FAKE_SWAP_LOG")" "swapped $ETC/aperire/fleet-arm.key"
  is "  the restore stops there" "$rc" "1"
  has "  naming the key" "$out" "$ETC/aperire/fleet-arm.key safely"
  # The control: no swap, and the same key is set root : root 0600 on the open file.
  wipe_aggregator; cp "$DEST/fleet-arm.key" "$ETC/aperire/fleet-arm.key"; chmod 644 "$ETC/aperire/fleet-arm.key"
  : > "$FAKE_PLANT_LOG"
  out=$(run_restore 2>&1); rc=$?
  is "control: the same arm key, no swap, and the restore exits 0" "$rc" "0"
  is "  the key is 0600 again" "$(stat -c %a "$ETC/aperire/fleet-arm.key")" "600"
  has "  set on the open key, root : root" "$(cat "$FAKE_PLANT_LOG")" "own $ETC/aperire/fleet-arm.key 0 0 0600"

  # A second name on the arm key: the temp a placement was killed before
  # removing. The re-own refuses it, so the restore refuses it first, before
  # anything stops, and names the temp to remove.
  wipe_aggregator; cp "$DEST/fleet-arm.key" "$ETC/aperire/fleet-arm.key"; chmod 600 "$ETC/aperire/fleet-arm.key"
  ln "$ETC/aperire/fleet-arm.key" "$ETC/aperire/.fleet-arm.key.Abc123"
  systemctl_mark_active aperire-server
  _db_before="$(sha256sum < "$REPO/data/aperire.db" 2>/dev/null)"
  _env_before="$(sha256sum < "$ETC/aperire/aperire.env")"
  : > "$FAKE_PLANT_LOG"
  out=$(run_restore 2>&1); rc=$?
  is "an arm key with a second name is refused with exit 9" "$rc" "9"
  has "  naming the stray temp" "$out" "$ETC/aperire/.fleet-arm.key.Abc123"
  has "  and the command that removes it" "$out" "sudo rm -- $ETC/aperire/.fleet-arm.key.Abc123"
  is "  the dashboard was never stopped" \
    "$([[ -f "$FAKE_SYSTEMCTL_STATE/aperire-server.active" ]] && echo yes || echo no)" "yes"
  is "  the database was never touched" "$(sha256sum < "$REPO/data/aperire.db" 2>/dev/null)" "$_db_before"
  is "  nothing was written under /etc/aperire" \
    "$(sha256sum < "$ETC/aperire/aperire.env")|$([[ -e "$ETC/aperire/fleet-tokens" ]] && echo tokens)|$(cat "$FAKE_PLANT_LOG")" "$_env_before||"
  rm -f "$ETC/aperire/.fleet-arm.key.Abc123"
fi
unset FAKE_SWAP_LOG

echo
echo "85. the set is built where only root can enter and placed by descriptor: a link planted in --to is refused, never written through (#1154, #1152)"
if ! command -v openssl >/dev/null 2>&1; then
  echo "  SKIP: no openssl on this machine, and the aggregator's arm key is an Ed25519 key"
else
mk_aggregator; build_sut
DEST="$TMP/set-1154"
mkdir -p "$DEST"
VICTIM_KEY="$TMP/victim-1154-key"; VICTIM_DB="$TMP/victim-1154-db"
printf 'not yours to change\n' > "$VICTIM_KEY"; cp "$VICTIM_KEY" "$VICTIM_DB"
chmod 0644 "$VICTIM_KEY" "$VICTIM_DB"
export FAKE_PLANT_LINKS="$DEST/fleet-arm.key|$VICTIM_KEY;$DEST/aperire.db|$VICTIM_DB"
out=$(run_backup 2>&1); rc=$?
unset FAKE_PLANT_LINKS
is "a link put in --to at fleet-arm.key and aperire.db after the check stops the backup" "$rc" "1"
has "  saying the destination was not empty when the set came to be placed" "$out" "already holds something"
has "  and, read from the disk, what it holds" "$out" "holds: aperire.db fleet-arm.key (" 
is "  the file the fleet-arm.key link points at is untouched" "$(cat "$VICTIM_KEY")|$(stat -c %a "$VICTIM_KEY")" "not yours to change|644"
is "  and so is the one the aperire.db link points at (the chmod 600 and the copy did not follow it)" \
  "$(cat "$VICTIM_DB")|$(stat -c %a "$VICTIM_DB")" "not yours to change|644"
is "  nothing the operator put in --to was changed or removed, and nothing was added" \
  "$(find "$DEST" -mindepth 1 -printf '%f>%l\n' | LC_ALL=C sort | tr '\n' ' ')" "aperire.db>$VICTIM_DB fleet-arm.key>$VICTIM_KEY "
# The control: the line this replaced, run as root into a --to whose owner has
# put a link at the name, writes through it.
CTRL="$TMP/ctrl-1154"; rm -rf "$CTRL"; mkdir -p "$CTRL"
printf 'the private arm key\n' > "$CTRL/src"; printf 'not yours to change\n' > "$CTRL/victim"
ln -s "$CTRL/victim" "$CTRL/fleet-arm.key"
cp -p "$CTRL/src" "$CTRL/fleet-arm.key"
is "  control: cp -p onto a name the owner of the directory linked writes the key into the link's target" \
  "$(cat "$CTRL/victim")" "the private arm key"
# And the set itself, when nothing is planted: only the operator's, and placed.
rm -rf "$DEST" "$TMP/scratch-1154"; mkdir -p "$TMP/scratch-1154"
out=$(TMPDIR="$TMP/scratch-1154" run_backup 2>&1); rc=$?
is "with nothing planted the same run places the set" "$rc" "0"
is "  with the arm key in it, owned by the operator, 0600" \
  "$(stat -c '%U %a' "$DEST/fleet-arm.key" 2>/dev/null)" "$CALLER_USER 600"
is "  and the set's top is the operator's at 0700" "$(stat -c '%U %a' "$DEST")" "$CALLER_USER 700"
is "  and nothing is left of the build once the run ends" \
  "$(find "$TMP/scratch-1154" -mindepth 1 | wc -l | tr -d ' ')" "0"
# A signal during the take-back (#1164). The take-back parks (see the shim) and
# the signal lands then. What the run says is compared with what is on the disk
# in every row: it must not say "run this again" over a key that is still there,
# and a stop must not end in silence.
park_run() { # $1 = tag; leaves PARK_DIR, PARK_PID (also the process group), DEST_P and PARK_OUT
  PARK_DIR="$TMP/park-$1"; DEST_P="$TMP/set-1164-$1"; PARK_OUT="$PARK_DIR/out"
  rm -rf "$PARK_DIR" "$DEST_P"; mkdir -p "$PARK_DIR"; mkfifo "$PARK_DIR/fifo"
  # A job started with & by a script that has no job control has SIGINT ignored,
  # and a shell cannot trap what it inherited ignored. A terminal's Ctrl-C and a
  # service manager's stop do not arrive that way, so the launcher puts the
  # default back, starts a session of its own and becomes the backup.
  # shellcheck disable=SC2016  # the program text is python's own
  ( cd "$REPO" && FAKE_TAKEBACK_PARK="$PARK_DIR" exec python3 -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.setsid()
os.execvp(sys.argv[1], sys.argv[1:])' bash "$REPO/scripts/aperire-backup.sh" --to "$DEST_P" --yes ) >"$PARK_OUT" 2>&1 &
  PARK_PID=$!
  local _i; for _i in $(seq 300); do [[ -e "$PARK_DIR/ready" ]] && break; sleep 0.1; done
  [[ -e "$PARK_DIR/ready" ]] || echo "  (the take-back never parked: $(tail -3 "$PARK_OUT" | tr '\n' ' '))"
  PY_PID="$(cat "$PARK_DIR/ready" 2>/dev/null)"
}
park_release() { timeout 3 bash -c "exec 3>'$PARK_DIR/fifo'" 2>/dev/null || true; }
park_finish() { # waits for the run started by park_run; leaves PARK_RC
  PARK_RC=0; wait "$PARK_PID" || PARK_RC=$?
}
park_names() { find "$DEST_P" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | LC_ALL=C sort | tr '\n' ' '; }

# 1. Python alone is killed outright (an out-of-memory kill): the take-back
#    never ran, so the set is at --to and the run must say so by name.
park_run kill
kill -KILL "$PY_PID"; park_finish
on_disk="$(park_names)"
is "python killed during the take-back: the run exits 1" "$PARK_RC" "1"
if [[ -n "$on_disk" ]]; then
  ok "  the set really is at --to ($on_disk)"
else
  bad "  the set is left at --to by a kill during the take-back" "$(cat "$PARK_OUT")"
fi
all_named=1; for n in $on_disk; do grep -qF -- "$n" "$PARK_OUT" || all_named=0; done
if (( all_named )) && grep -q "holds: " "$PARK_OUT" && ! grep -q "Nothing is at" "$PARK_OUT" \
   && grep -q "the private arm key among them" "$PARK_OUT"; then
  ok "  and the text names what is there, the private arm key among what can be, not an empty destination"
else
  bad "the text after a killed take-back says what is on disk" "$(cat "$PARK_OUT")"
fi
# The text's own advice, followed: clear it and the same destination takes a set.
rm -rf "${DEST_P:?}"
rc=0; ( cd "$REPO" && bash "$REPO/scripts/aperire-backup.sh" --to "$DEST_P" --yes ) >/dev/null 2>&1 || rc=$?
is "  and once it is cleared as the text says, the next run places the set" "$rc" "0"

# 2. Python alone is asked to stop (a kill of that pid): it finishes the
#    take-back first, so the destination is empty and "taken back" is true.
park_run term1
kill -TERM "$PY_PID"; park_release; park_finish
if [[ ! -e "$DEST_P" ]] && grep -q "stopped by SIGTERM" "$PARK_OUT" && grep -q "was taken back" "$PARK_OUT" && [[ "$PARK_RC" == 1 ]]; then
  ok "python told to stop during the take-back finishes it, leaves nothing at --to, and the text says taken back"
else
  bad "a SIGTERM to python alone finishes the take-back" "rc=$PARK_RC on disk: $(park_names): $(cat "$PARK_OUT")"
fi

# 3. The whole group (a systemctl stop, Ctrl-C): bash is stopped too. Python
#    finishes the take-back; bash then reports from the disk and exits 128+n.
for sg in TERM:143:SIGTERM INT:130:SIGINT; do
  IFS=: read -r sig want_rc sig_py <<<"$sg"
  park_run "grp-$sig"
  kill -"$sig" -- "-$PARK_PID"; park_release; park_finish
  if [[ "$PARK_RC" == "$want_rc" && ! -e "$DEST_P" ]] \
     && grep -q "stopped by $sig_py" "$PARK_OUT" && grep -q "Nothing is at $DEST_P" "$PARK_OUT" \
     && ! grep -q "Traceback" "$PARK_OUT"; then
    ok "a group $sig during the take-back: the take-back finishes, the run exits $want_rc and says what is at --to (nothing)"
  else
    bad "a group $sig during the take-back is reported from the disk" "rc=$PARK_RC on disk: $(park_names): $(cat "$PARK_OUT")"
  fi
done

# What the run says for each way copy-tree stops. The text must be true of the
# status: 3 is "taken back", 4 is "still there", and any other says only what
# stopped it, because nothing else is known.
rm -rf "$DEST"
for place_rc in 3 4 1; do
  out=$(FAKE_COPY_TREE_RC=$place_rc run_backup 2>&1); rc=$?
  is "copy-tree exiting $place_rc stops the backup" "$rc" "1"
  has "  and the run names the destination" "$out" "could not be placed at $DEST"
  case $place_rc in
    3) has "  saying what was copied was taken back" "$out" "was taken back"
       hasnt "  and not that anything is still there" "$out" "still at" ;;
    4) has "  saying what it names is still there" "$out" "what is named above is still at $DEST"
       hasnt "  and not that nothing was left" "$out" "Nothing of this set"
       has "  and who has to clear it" "$out" "remove what is named as root" ;;
    1) hasnt "  without claiming it was taken back" "$out" "was taken back"
       hasnt "  or that the take-back could not finish" "$out" "take-back could not"
       hasnt "  or that nothing of the set was left" "$out" "Nothing of this set"
       has "  and what is at the destination, read from the disk" "$out" "Nothing is at $DEST" ;;
  esac
done
fi

echo
echo "pass=$PASS fail=$FAIL"
if [[ $FAIL -eq 0 ]]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAILED"
exit 1
