#!/usr/bin/env bash
# What the non-root migration refuses, what it changes, and what a second run
# is not allowed to change (#31).
#
#   bash scripts/test-migrate-node-nonroot.sh
#
# The failures this holds shut are the expensive ones, and every one of them
# is quiet:
#
#   1. It runs while the node is running. Chowning a store underneath a
#      running node changes what it can write in the middle of a write.
#   2. It runs inside a store rotation. A node stopped inside one came back
#      with an empty store and rebuilt from genesis (#79).
#   3. It follows a symlink out of the node's own directories with a
#      recursive chown, or chowns a directory the node does not even use.
#   4. It patches the compose twice, so the file carries two user: lines, or
#      patches a file it did not understand and leaves no way back.
#   5. It re-renders the compose from the template instead of patching it,
#      silently reverting a per-host edit (a corrected peer mapping).
#   6. The migrated host and a freshly installed one end up different.
#
# Runs entirely in a temporary directory against fake docker, chown, chgrp,
# getent, useradd, groupadd and a stub wrapper on PATH. Touches no host, needs
# no root, changes no ownership anywhere.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

NODE_DIR="$TMP/node"
CFG="$NODE_DIR/config/rippled.cfg"
VAL="$NODE_DIR/config/validators.txt"
COMPOSE="$NODE_DIR/docker-compose.yml"
WCONF="$TMP/etc/aperire/node-wrapper.conf"
NCONF="$TMP/etc/aperire/node.conf"
LOCK="$TMP/run/aperire/node-rotation.lock"
COMPOSE_TPL="$REPO_DIR/scripts/templates/aperire-node.compose.yml"

mkdir -p "$TMP/bin" "$TMP/state" "$TMP/etc/aperire" "$TMP/repo/scripts/templates"
# The shipped template, beside the copy under test, because that is where the
# script looks for it: the header a migrated compose ends up with is rendered
# from this file, and a suite without it would only ever prove the branch that
# leaves the header alone.
cp "$REPO_DIR/scripts/templates/aperire-node.compose.yml" "$TMP/repo/scripts/templates/"

# ── The script under test, with the paths it names pointed at $TMP ────
# Copy, rewrite the constants that name /etc and /run and the root gate, then
# assert every rewrite took: a rename upstream must fail here rather than
# quietly test nothing.
SUT="$TMP/repo/scripts/migrate-node-nonroot.sh"
# shellcheck disable=SC2016  # $EUID is the text being matched, not a value to expand
sed -e "s#^CONF=/etc/aperire/node-wrapper.conf#CONF=$WCONF#" \
    -e "s#^NODE_CONF=/etc/aperire/node.conf#NODE_CONF=$NCONF#" \
    -e "s#^ROTATION_LOCK=/run/aperire/node-rotation.lock#ROTATION_LOCK=$LOCK#" \
    -e 's#^ROTATION_LOCK_WAIT=45$#ROTATION_LOCK_WAIT=1#' \
    -e 's#^\[\[ \$EUID -eq 0 \]\] ||#[[ 1 -eq 1 ]] ||#' \
    "$REPO_DIR/scripts/migrate-node-nonroot.sh" > "$SUT"
for needle in "CONF=$WCONF" "NODE_CONF=$NCONF" "ROTATION_LOCK=$LOCK" "ROTATION_LOCK_WAIT=1" '[[ 1 -eq 1 ]] ||'; do
  grep -qF -- "$needle" "$SUT" \
    || { echo "the copy of migrate-node-nonroot.sh was not rewritten ($needle) - this suite would prove nothing"; exit 1; }
done

# shellcheck disable=SC2016
sed 's#\[\[ \$EUID -eq 0 \]\] ||#[[ 1 -eq 1 ]] ||#' \
  "$REPO_DIR/scripts/node-user-lib.sh" > "$TMP/repo/scripts/node-user-lib.sh"
grep -qF '[[ 1 -eq 1 ]] ||' "$TMP/repo/scripts/node-user-lib.sh" \
  || { echo "the copy of node-user-lib.sh was not rewritten (the root gate)"; exit 1; }

# Sourced beside the script under test (#545), verbatim: it has no root gate
# to rewrite.
cp "$REPO_DIR/scripts/config-write-lib.sh" "$TMP/repo/scripts/config-write-lib.sh"

# The wrapper, stubbed: this suite is about what the migration does with the
# rotation verdict, not about how the wrapper reaches one. state/rotation
# holds the line the real verb would print.
cat > "$TMP/repo/scripts/aperire-node-wrapper.sh" <<EOF
#!/usr/bin/env bash
[[ "\${1:-}" == rotation-state ]] || exit 64
cat "$TMP/state/rotation" 2>/dev/null || printf 'idle\tno rotation in the log\n'
EOF
chmod +x "$TMP/repo/scripts/aperire-node-wrapper.sh"

# ── Fakes on PATH ─────────────────────────────────────────────────────
# chown / chgrp: recorded and harmless. Recording is the only way to prove
# what ownership was asked for without being root.
cat > "$TMP/bin/chown" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/chown-calls"
exit 0
EOF
cat > "$TMP/bin/chgrp" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/chgrp-calls"
exit 0
EOF

# The state helper the store is handed over with (#1121), stood in for: this
# suite is not root and cannot own anything to uid 997. Each path the real
# helper would be given on its standard input is recorded the way a chown by
# name was ("own-many 997:997 <path>", the path last), so every row that asked
# what was chowned still asks it. state/own-many-rc makes it refuse, as the
# real one does for a link or a file with a second name. The real helper, on a
# hard link to a file outside the store, is driven in test-install-advisor-
# account.sh under fakeroot.
cat > "$TMP/repo/scripts/state-file.py" <<STATEFILE
import os, sys
a = sys.argv[1:]
# The ancestor check the run makes up front (#1150): no standard input, and
# whatever state/ancestors-out holds is what the helper reports.
if a[0] == "ancestors":
    with open("$TMP/state/ancestors-argv", "a") as log:
        log.write(" ".join(a) + "\n")
    # state/real-ancestors holds the path of a real helper to answer instead
    # (#1153): the rows that need the shipped rule, and not a canned report.
    real = "$TMP/state/real-ancestors"
    if os.path.exists(real):
        import subprocess
        sys.exit(subprocess.call(["python3", "-I", open(real).read().strip()] + a))
    out = "$TMP/state/ancestors-out"
    if os.path.exists(out):
        sys.stdout.write(open(out).read())
    sys.exit(0)
# read and plant (the compose put back, #1208) have nothing to stand in for:
# the real helper answers, and plant's arguments are kept. state/real-helper
# makes every other call the real one too, for the rows that put the config's
# group back under fakeroot and look at what happened, not what was asked.
if a[0] in ("read", "plant") or os.path.exists("$TMP/state/real-helper"):
    import subprocess
    if a[0] == "plant":
        with open("$TMP/state/plant-argv", "a") as log:
            log.write(" ".join(a) + "\n")
    if "--list" in a:
        with open(a[a.index("--list") + 1], "rb") as rec, open("$TMP/state/list-seen", "ab") as seen:
            seen.write(rec.read().replace(b"\0", b"\n"))
    # state/plant-tamper names the compose: a plant of the rewrite there (the
    # bytes carry the user: line) lands, then gains a line, standing for a
    # landed file that is not what was planted (#1295 re-review).
    tamper = "$TMP/state/plant-tamper"
    if a[0] == "plant" and "--stdin" in a and os.path.exists(tamper):
        data = sys.stdin.buffer.read()
        rc = subprocess.run(["python3", "-I", "$REPO_DIR/scripts/state-file.py"] + a, input=data).returncode
        if rc == 0 and a[1] == open(tamper).read().strip() and b'user: "997:997"' in data:
            with open(a[1], "ab") as landed:
                landed.write(b"# changed after it landed\n")
        sys.exit(rc)
    sys.exit(subprocess.call(["python3", "-I", "$REPO_DIR/scripts/state-file.py"] + a))
# The list root recorded before it changed anything (#1152), as the walk was
# handed it: kept so a row can read what the record held.
if "--list" in a:
    with open(a[a.index("--list") + 1], "rb") as rec, open("$TMP/state/list-seen", "ab") as seen:
        seen.write(rec.read().replace(b"\0", b"\n"))
data = sys.stdin.buffer.read().split(b"\0")
# A group-only call (no uid) is the config's group move, which this suite
# recorded as chgrp "<gid> <path>"; the rest are the store.
log_name = "chgrp-calls" if a[1] == "" else "chown-calls"
with open("$TMP/state/" + log_name, "a") as log:
    for raw in data:
        if raw:
            if a[1] == "":
                log.write("%s %s\n" % (a[2], raw.decode()))
            else:
                log.write("%s %s:%s %s\n" % (a[0], a[1], a[2], raw.decode()))
with open("$TMP/state/own-many-argv", "a") as log:
    log.write(" ".join(a) + "\n")
rc = "$TMP/state/own-many-rc"
sys.exit(int(open(rc).read()) if os.path.exists(rc) else 0)
STATEFILE

# docker: the container's state answers from state/container-state, so
# "running" and "exited" are both reachable, and an absent container is the
# file not being there at all.
cat > "$TMP/bin/docker" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/docker-calls"
case "\${1:-}" in
  inspect)
    [[ -f "$TMP/state/container-state" ]] || exit 1
    for a in "\$@"; do
      case "\$a" in
        *State.Status*) cat "$TMP/state/container-state"; exit 0 ;;
        *config_files*) echo "$COMPOSE"; exit 0 ;;
      esac
    done
    exit 0 ;;
esac
exit 0
EOF

cat > "$TMP/bin/getent" <<EOF
#!/usr/bin/env bash
case "\${1:-}:\${2:-}" in
  passwd:xrpld) [[ -f "$TMP/state/account-xrpld" ]] || exit 2; cat "$TMP/state/account-xrpld"; exit 0 ;;
  group:xrpld)  [[ -f "$TMP/state/group-xrpld" ]] || exit 2; cat "$TMP/state/group-xrpld"; exit 0 ;;
  passwd:997)   [[ -f "$TMP/state/id-997-taken" ]] && { echo "pcp:x:997:983::/var/lib/pcp:/usr/sbin/nologin"; exit 0; }
                [[ -f "$TMP/state/account-xrpld" ]] && grep -q ':997:' "$TMP/state/account-xrpld" && { cat "$TMP/state/account-xrpld"; exit 0; }
                exit 2 ;;
  group:997)    [[ -f "$TMP/state/id-997-taken" ]] && { echo "crontab:x:997:"; exit 0; }
                [[ -f "$TMP/state/group-xrpld" ]] && grep -q ':997:' "$TMP/state/group-xrpld" && { cat "$TMP/state/group-xrpld"; exit 0; }
                exit 2 ;;
esac
exit 2
EOF
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

chmod +x "$TMP"/bin/*

# The real state helper. The copy beside the migration (above) records what the
# run asked for without touching the fixture, which is right for every row that
# reads chgrp-calls, and wrong for the one row below (#471) that has to move a
# real file's real group to tell "asked for" from "happened".
REAL_STATE_FILE="$REPO_DIR/scripts/state-file.py"

export PATH="$TMP/bin:$PATH"

# ── The host the migration runs on ────────────────────────────────────
# The compose is the shipped template rendered, then the three lines #31
# added taken back out: that is exactly what a host installed before this
# change is running, and it is the input the equality row below compares
# against what the template renders today.
render_template() { # $1 = uid, $2 = gid
  sed -e "s#@NAME@#test-node#g" -e "s#@DIR@#${NODE_DIR}#g" -e "s#@TAG@#3.3.0#g" \
      -e "s#@UID@#$1#g" -e "s#@GID@#$2#g" "$COMPOSE_TPL"
}
write_old_shape_compose() {
  render_template 997 997 \
    | grep -vE '^[[:space:]]*user: "997:997"$' \
    | grep -vE ':/etc/xrpld/(xrpld\.cfg|validators\.txt):ro$' \
    > "$COMPOSE"
}

reset() {
  rm -rf "$TMP/state" "$NODE_DIR" "$TMP/etc/aperire" "$(dirname "$LOCK")"
  mkdir -p "$TMP/state" "$NODE_DIR/config" "$NODE_DIR/data" "$TMP/etc/aperire" "$(dirname "$LOCK")"
  # The shipped config's own shape, [debug_logfile] included: the run reads
  # that stanza to name the log an operator should check when the rotation
  # verdict has no source, and it is a container path mapped back through the
  # store mount.
  printf '[node_db]\ntype=NuDB\npath=/var/lib/xrpld/db/nudb\n\n[debug_logfile]\n/var/lib/xrpld/log/debug.log\n' > "$CFG"
  mkdir -p "$NODE_DIR/data/log"
  : > "$NODE_DIR/data/log/debug.log"
  printf '[validator_list_sites]\nhttps://vl.ripple.com\n' > "$VAL"
  write_old_shape_compose
  {
    printf 'KIND=container\n'
    printf 'SERVICE=test-node\n'
    printf 'CONFIG_FILE=%s\n' "$CFG"
    printf 'COMPOSE_FILE=%s\n' "$COMPOSE"
  } > "$WCONF"
  {
    printf 'KIND=container\n'
    printf 'SERVICE=test-node\n'
    printf 'NODE_LABEL=test-node\n'
  } > "$NCONF"
  echo exited > "$TMP/state/container-state"
}

has() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
run_migrate() {
  OUT="$(bash "$SUT" "$@" 2>&1)"
  RC=$?
}

backups() { find "$NODE_DIR" -maxdepth 1 -name 'docker-compose.yml.*.bak' -type f | sort; }

# =====================================================================
echo
echo "What -h prints:"

reset
run_migrate --help
if [[ $RC -eq 0 && "$OUT" == *"Report mode changes nothing"* && "$OUT" == *"Putting it back"* ]]; then
  ok "-h prints the whole header, including the way back"
else
  bad "-h prints the whole header" "rc=$RC: $OUT"
fi
# Bounded by the comment block rather than by a line number, because a line
# number drifts every time the header gains a paragraph and the first thing an
# operator reads becomes shell.
if [[ "$OUT" != *"set -euo"* && "$OUT" != *"ROTATION_LOCK="* ]]; then
  ok "and stops at the end of it, rather than spilling into the code"
else
  bad "-h stops at the end of the header" "$OUT"
fi
run_migrate --nonsense
if [[ $RC -eq 2 && "$OUT" == *"unknown argument"* ]]; then
  ok "an argument it does not know is refused, not treated as a report"
else
  bad "an unknown argument is refused" "rc=$RC: $OUT"
fi

# =====================================================================
echo
echo "The refusals, which all leave the host exactly as they found it:"

reset
echo running > "$TMP/state/container-state"
BEFORE=$(md5sum < "$COMPOSE")
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"the node is running"* ]]; then
  ok "a running node is refused, by name"
else
  bad "a running node is refused, by name" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"docker compose -f ${COMPOSE} stop"* && "$OUT" != *"docker compose -f ${COMPOSE} down"* ]]; then
  ok "and it says the command that stops it, which is stop and never down"
else
  bad "it says the command that stops it, and never down" "$OUT"
fi
if [[ "$(md5sum < "$COMPOSE")" == "$BEFORE" && ! -f "$TMP/state/chown-calls" ]]; then
  ok "nothing was chowned and the compose is untouched"
else
  bad "nothing was chowned and the compose is untouched" "chown: $(cat "$TMP/state/chown-calls" 2>/dev/null)"
fi

reset
printf 'rotating\ta store rotation started 3 minutes ago and has not finished\n' > "$TMP/state/rotation"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"rotation"* && "$OUT" == *"#79"* ]]; then
  ok "a store rotation in flight is refused, with the incident it comes from"
else
  bad "a store rotation in flight is refused" "rc=$RC: $OUT"
fi
if [[ ! -f "$TMP/state/chown-calls" ]]; then
  ok "and nothing was chowned inside the rotation window"
else
  bad "nothing was chowned inside the rotation window" "$(cat "$TMP/state/chown-calls")"
fi

reset
rm -rf "$NODE_DIR/data"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"is not a directory"* ]]; then
  ok "a missing store is refused rather than created"
else
  bad "a missing store is refused rather than created" "rc=$RC: $OUT"
fi
if [[ ! -d "$NODE_DIR/data" ]]; then
  ok "and the directory it refused to find was not invented"
else
  bad "the directory it refused to find was not invented" "$NODE_DIR/data exists"
fi

reset
rm -rf "$NODE_DIR/data"
mkdir -p "$TMP/elsewhere/store"
ln -s "$TMP/elsewhere/store" "$NODE_DIR/data"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"symbolic link"* && "$OUT" == *"$TMP/elsewhere/store"* ]]; then
  ok "a store that is a symlink is refused, and the target is named"
else
  bad "a store that is a symlink is refused, and the target is named" "rc=$RC: $OUT"
fi
if [[ ! -f "$TMP/state/chown-calls" ]]; then
  ok "no recursive chown followed the link out of the node's own directories"
else
  bad "no recursive chown followed the link" "$(cat "$TMP/state/chown-calls")"
fi

reset
sed -i "s#${NODE_DIR}/data:/var/lib/xrpld#/srv/somewhere-else:/var/lib/xrpld#" "$COMPOSE"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"other than ${NODE_DIR}/data"* ]]; then
  ok "a compose whose store is somewhere else is refused, not chowned on a guess"
else
  bad "a compose whose store is somewhere else is refused" "rc=$RC: $OUT"
fi

reset
sed -i 's#^KIND=container#KIND=native#' "$WCONF"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"User=xrpld"* ]]; then
  ok "a native host is refused with the reason: its vendor unit already runs as xrpld"
else
  bad "a native host is refused with the reason" "rc=$RC: $OUT"
fi

# =====================================================================
echo
echo "A box with a node and no Advisor on it:"

# The node installer writes /etc/aperire/node.conf on every host. The
# wrapper's own file only exists where the Advisor was installed, and this
# suite's sibling asserts a plain container run writes none. So a migration
# that could only read the wrapper's file would dead-end on exactly the box
# the installer tells to run it.
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
run_migrate --apply --rotation-checked-by-hand
if [[ $RC -eq 0 ]]; then
  ok "it migrates a box that has node.conf and no wrapper configuration"
else
  bad "it migrates a box with no wrapper configuration" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"read from"*"node.conf"* ]]; then
  ok "and it says which file it read the node out of"
else
  bad "it says which file it read the node out of" "$OUT"
fi
if grep -qE '^    user: "997:997"$' "$COMPOSE"; then
  ok "the compose it found through the container's own compose label is the one it patched"
else
  bad "the compose found through the compose label is the one it patched" "$(cat "$COMPOSE")"
fi

reset
rm -f "$WCONF" "$NCONF"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"node-wrapper.conf"* && "$OUT" == *"node.conf"* ]]; then
  ok "with neither file, it refuses and names both"
else
  bad "with neither file, it refuses and names both" "rc=$RC: $OUT"
fi

# The same box, after the stop these instructions themselves name. `docker
# compose down` removes the container, and a removed container carries no
# compose label, so the inspect above it exits non-zero. Measured on aperire4
# (2026-09-17): the run printed nothing on either stream and exited 1, because
# a failing pipeline inside an assignment under `set -euo pipefail` ends the
# script where it stands. Silence is the failure worth holding shut here: an
# operator following the guide in order gets it every time, on a node that is
# already stopped.
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
rm -f "$TMP/state/container-state"
run_migrate --apply --rotation-checked-by-hand
if [[ -n "$OUT" ]]; then
  ok "a container that was removed rather than stopped still gets a run that says something"
else
  bad "a removed container gets a run that says something" "rc=$RC, and it printed nothing at all"
fi
if [[ $RC -eq 0 ]] && grep -qE '^    user: "997:997"$' "$COMPOSE"; then
  ok "and it reaches the compose beside the config, and migrates that one"
else
  bad "it reaches the compose beside the config" "rc=$RC: $OUT"
fi

# The other half of that fallback: a config whose directory has no compose
# beside it must be refused in words, not guessed at and not exited on.
reset
rm -f "$WCONF" "$TMP/state/container-state"
mkdir -p "$TMP/elsewhere/config"
printf '[node_db]\n' > "$TMP/elsewhere/config/rippled.cfg"
printf 'CONFIG_FILE=%s\n' "$TMP/elsewhere/config/rippled.cfg" >> "$NCONF"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"could not be found"* && "$OUT" == *"docker-compose.yml beside"* ]]; then
  ok "no container and no compose beside the config is refused, naming where it looked"
else
  bad "no container and no compose beside the config is refused" "rc=$RC: $OUT"
fi

# =====================================================================
echo
echo "The report, which is the default and changes nothing:"

reset
BEFORE=$(md5sum < "$COMPOSE")
run_migrate
if [[ $RC -eq 0 && "$OUT" == *"What --apply would do"* ]]; then
  ok "a run with no argument reports"
else
  bad "a run with no argument reports" "rc=$RC: $OUT"
fi
if [[ "$(md5sum < "$COMPOSE")" == "$BEFORE" && ! -f "$TMP/state/chown-calls" \
      && ! -f "$TMP/state/useradd-calls" && -z "$(backups)" ]]; then
  ok "it creates no account, chowns nothing, and writes no backup"
else
  bad "the report changes nothing" "chown: $(cat "$TMP/state/chown-calls" 2>/dev/null); useradd: $(cat "$TMP/state/useradd-calls" 2>/dev/null); backups: $(backups)"
fi
if [[ "$OUT" == *"chown -R xrpld:xrpld ${NODE_DIR}/data"* ]]; then
  ok "and it says what --apply would do, in the commands it would run"
else
  bad "it says what --apply would do" "$OUT"
fi

# =====================================================================
echo
echo "The migration itself:"

reset
run_migrate --apply
if [[ $RC -eq 0 ]]; then
  ok "it succeeds on a stopped node"
else
  bad "it succeeds on a stopped node" "rc=$RC: $OUT"
fi
if grep -q -- '--uid 997' "$TMP/state/useradd-calls" 2>/dev/null; then
  ok "the account is created at the uid the node image itself uses"
else
  bad "the account is created at 997" "$(cat "$TMP/state/useradd-calls" 2>/dev/null)"
fi
if grep -qF -- "own-many 997:997 ${NODE_DIR}/data" "$TMP/state/chown-calls" 2>/dev/null \
   && grep -qF -- "own-many 997 997  --root ${NODE_DIR} --judge-root --list " "$TMP/state/own-many-argv" 2>/dev/null \
   && grep -qxF -- "ancestors ${CFG} --root $(dirname -- "$CFG") --judge-root" "$TMP/state/ancestors-argv" 2>/dev/null \
   && ! grep -q -- '--root /$' "$TMP/state/own-many-argv" 2>/dev/null; then
  ok "the store is handed to the node by descriptor, every entry, none followed through a link (#1121)"
else
  bad "the store is handed over through the state helper's own-many" "$(cat "$TMP/state/chown-calls" 2>/dev/null) :: $(cat "$TMP/state/own-many-argv" 2>/dev/null)"
fi
# The walk acts on what was recorded before the run changed anything (#1152):
# the store's entries by device and inode, and the config file the same way.
if grep -qE -- ":[0-9]+:${NODE_DIR}/data$" "$TMP/state/list-seen" 2>/dev/null \
   && grep -qE -- ":[0-9]+:${NODE_DIR}/data/log$" "$TMP/state/list-seen" 2>/dev/null; then
  ok "the store is handed over from a list recorded as <dev>:<ino>:<path>, the store and what is under it (#1152)"
else
  bad "the store's hand-over is given the list recorded before the run began" "$(cat "$TMP/state/list-seen" 2>/dev/null)"
fi
# The config's group and the validator list's are moved from a record of their
# own, taken at the same moment: each call carries a --list, and the record
# names the file it is for (#1152).
if [[ "$(grep -cF -- "own-many  997  --root " "$TMP/state/own-many-argv" 2>/dev/null)" == 2 ]] \
   && [[ "$(grep -F -- "own-many  997  --root " "$TMP/state/own-many-argv" | grep -cF -- ' --judge-root --list ')" == 2 ]] \
   && grep -qE -- ":[0-9]+:${CFG}$" "$TMP/state/list-seen" 2>/dev/null \
   && grep -qE -- ":[0-9]+:${VAL}$" "$TMP/state/list-seen" 2>/dev/null; then
  ok "the config's group and the validator list's are each moved from a list recorded for that file (#1152)"
else
  bad "the group moves are given the list recorded before the run began" "$(grep -F -- 'own-many  997' "$TMP/state/own-many-argv" 2>/dev/null) :: $(cat "$TMP/state/list-seen" 2>/dev/null)"
fi
# The record has to be taken before the first thing this run changes. A row
# cannot watch the order a run happens in, so this reads it off the shipped
# script: every record_for_handover call comes before the account is created,
# which is before anything is written, and before the first hand-over. Five:
# the apply's store, config and validator list, and --hand-store-back's store
# and the one in its loop over the config and the validator list (#1208).
rec_last="$(grep -n 'record_for_handover "' "$REPO_DIR/scripts/migrate-node-nonroot.sh" | tail -1 | cut -d: -f1)"
rec_first="$(grep -n 'record_for_handover "' "$REPO_DIR/scripts/migrate-node-nonroot.sh" | head -1 | cut -d: -f1)"
# shellcheck disable=SC2016  # the text of the line being looked for
acct="$(grep -n 'LINE="\$(node_account_ensure)"' "$REPO_DIR/scripts/migrate-node-nonroot.sh" | head -1 | cut -d: -f1)"
hand="$(grep -n '^if ! hand_store_to_node' "$REPO_DIR/scripts/migrate-node-nonroot.sh" | head -1 | cut -d: -f1)"
if [[ -n "$rec_first" && -n "$acct" && -n "$hand" && "$rec_last" -lt "$acct" && "$acct" -lt "$hand" ]] \
   && [[ "$(grep -c 'record_for_handover "' "$REPO_DIR/scripts/migrate-node-nonroot.sh")" == 5 ]]; then
  ok "the store, the config and the validator list are recorded (lines $rec_first to $rec_last) before the account is made ($acct) and before the first hand-over ($hand)"
else
  bad "the records are taken before anything changes" "records at ${rec_first:-none}..${rec_last:-none}, account at ${acct:-none}, hand-over at ${hand:-none}"
fi
# Every chown this run asked for, checked one by one: the last word of each
# call is the path it would change, and all of them have to be inside the
# node's own directory. A migration that reaches outside it is the one
# mistake here that cannot be taken back.
outside=""
while IFS= read -r call; do
  [[ -n "$call" ]] || continue
  target="${call##* }"
  [[ "$target" == "$NODE_DIR"/* ]] || outside+="$call"$'\n'
done < "$TMP/state/chown-calls"
if [[ -z "$outside" ]]; then
  ok "every chown it asked for is inside ${NODE_DIR}"
else
  bad "every chown it asked for is inside the node's own directory" "$outside"
fi
if grep -qF -- "997 $CFG" "$TMP/state/chgrp-calls" 2>/dev/null \
   && grep -qF -- "997 $VAL" "$TMP/state/chgrp-calls" 2>/dev/null; then
  ok "the config and the validator list move to the node's group"
else
  bad "the config and the validator list move to the node's group" "$(cat "$TMP/state/chgrp-calls" 2>/dev/null)"
fi
if ! grep -qE 'chmod' "$TMP/state/chgrp-calls" 2>/dev/null && [[ "$OUT" == *"unchanged"* ]]; then
  ok "the config's MODE is not touched, so an ACL mask recalculation cannot drop the relay's read"
else
  bad "the config's mode is not touched" "$OUT"
fi
if [[ "$(sed -n 's/^NODE_UID=//p' "$NCONF")" == 997 && "$(sed -n 's/^NODE_USER=//p' "$NCONF")" == xrpld ]]; then
  ok "node.conf records the account, the same three keys a fresh install writes"
else
  bad "node.conf records the account" "$(cat "$NCONF")"
fi

BAK=$(backups)
if [[ -n "$BAK" && $(printf '%s\n' "$BAK" | wc -l) -eq 1 ]]; then
  ok "the previous deployment is kept, once"
else
  bad "the previous deployment is kept, once" "$BAK"
fi
if [[ -n "$BAK" ]] && [[ "$(basename "$BAK")" =~ ^docker-compose\.yml\.[0-9]{8}-[0-9]{6}\.bak$ ]]; then
  ok "the backup is named the way the wrapper's own restore-compose accepts"
else
  bad "the backup is named the way restore-compose accepts" "$(basename "${BAK:-<none>}")"
fi
if [[ "$OUT" == *"puts ${BAK} back as the compose file"* ]]; then
  ok "and the run names the backup the step puts back"
else
  bad "the run names the backup the step puts back" "$OUT"
fi
if [[ "$OUT" == *"--run migrate-node --hand-store-back"* && "$OUT" != *"chown -R"* ]]; then
  ok "the way back includes the store's old ownership, as the step and not a chown -R to type (#1148)"
else
  bad "the way back includes the store's old ownership" "$OUT"
fi

# The equality this whole change turns on: a host migrated from the old shape
# and a host installed fresh today must be running the same deployment. The
# input here was this template's own previous render, so the comparison is
# byte-for-byte rather than a list of properties.
if diff -u <(render_template 997 997) "$COMPOSE" > "$TMP/state/equality.diff"; then
  ok "a migrated compose is byte-identical to what the installer renders today"
else
  bad "a migrated compose is byte-identical to a fresh render" "$(cat "$TMP/state/equality.diff")"
fi

# =====================================================================
echo
echo "A second run, and a half-migrated file:"

BEFORE=$(md5sum < "$COMPOSE")
rm -f "$TMP/state/chown-calls" "$TMP/state/chgrp-calls"
run_migrate --apply
if [[ $RC -eq 0 && "$(md5sum < "$COMPOSE")" == "$BEFORE" ]]; then
  ok "a second run leaves the compose byte-identical"
else
  bad "a second run leaves the compose byte-identical" "rc=$RC: $(diff <(render_template 997 997) "$COMPOSE")"
fi
if [[ "$(grep -c 'user: "997:997"' "$COMPOSE")" == 1 ]]; then
  ok "and there is exactly one user: line, not two"
else
  bad "there is exactly one user: line" "$(grep -n 'user:' "$COMPOSE")"
fi
if [[ $(backups | wc -l) -eq 1 ]]; then
  ok "no second backup is written when there was nothing to change"
else
  bad "no second backup is written" "$(backups)"
fi
if grep -qF -- "own-many 997:997 ${NODE_DIR}/data" "$TMP/state/chown-calls" 2>/dev/null; then
  ok "the ownership is re-asserted, which is what makes a half-finished run safe to repeat"
else
  bad "the ownership is re-asserted on a second run" "$(cat "$TMP/state/chown-calls" 2>/dev/null)"
fi

# The store is handed over by descriptor and a refusal stops the run (#1121).
# The state helper refuses a link and a file with a second name instead of
# changing it; this run names that, says nothing was done to the entry, and
# does not go on to claim the store is the node's.
reset
echo 3 > "$TMP/state/own-many-rc"
run_migrate --apply
if [[ $RC -ne 0 ]] && has "$OUT" 'was not all handed to xrpld' && has "$OUT" 'is not what was there when this began' \
   && ! has "$OUT" '-> xrpld:xrpld, every entry'; then
  ok "a store with an entry the helper refuses stops the run, names why, and does not claim it was handed over"
else
  bad "a refused entry stops the migration" "rc=$RC: $OUT"
fi
# Without the helper beside the script the run stops before it changes
# anything, rather than after the compose file is rewritten.
reset
before_compose="$(md5sum < "$COMPOSE")"
mv "$TMP/repo/scripts/state-file.py" "$TMP/repo/scripts/state-file.py.away"
run_migrate --apply
mv "$TMP/repo/scripts/state-file.py.away" "$TMP/repo/scripts/state-file.py"
if [[ $RC -ne 0 ]] && has "$OUT" 'state-file.py is missing' && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" ]] \
   && [[ ! -f "$TMP/state/chown-calls" && $(backups | wc -l) -eq 0 ]]; then
  ok "no state helper beside the script: refused before the compose is touched, a backup written, or anything owned"
else
  bad "a missing state helper is refused up front" "rc=$RC backups=$(backups | wc -l): $OUT"
fi

# The directories above the store are judged before anything is written
# (#1150), by the same rule the hand-over applies, and the walk is rooted at
# the install directory and not at /, which would have switched that rule off.
reset
before_compose="$(md5sum < "$COMPOSE")"
printf 'world-write\t%s\t%s is world-writable and not sticky, so anyone on this host can replace what is under it\n' "$TMP" "$TMP" > "$TMP/state/ancestors-out"
run_migrate --apply
if [[ $RC -ne 0 ]] && has "$OUT" "refused: $TMP is world-writable" && has "$OUT" 'nothing has been changed' \
   && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" && ! -f "$TMP/state/chown-calls" && $(backups | wc -l) -eq 0 ]] \
   && grep -qxF -- "ancestors ${NODE_DIR}/data --root ${NODE_DIR} --judge-root" "$TMP/state/ancestors-argv"; then
  ok "a directory above the store that others can write stops the run before the compose is touched or anything is owned"
else
  bad "an unsafe ancestor is refused up front" "rc=$RC: $OUT :: $(cat "$TMP/state/ancestors-argv" 2>/dev/null)"
fi
# The directory the store sits in is judged too (#1153), by the shipped rule
# and not a canned answer: --judge-root turns the exemption the install
# directory had off, so an account that could write it could swap `data` for
# another directory between root's calls. The helper answers for real here.
reset
echo "$REAL_STATE_FILE" > "$TMP/state/real-ancestors"
before_compose="$(md5sum < "$COMPOSE")"
chmod 0777 "$NODE_DIR"
run_migrate --apply
chmod 0755 "$NODE_DIR"
if [[ $RC -ne 0 ]] && has "$OUT" "refused: $NODE_DIR is world-writable" && has "$OUT" "run: sudo chmod go-w $NODE_DIR" \
   && has "$OUT" 'nothing has been changed' \
   && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" && ! -f "$TMP/state/chown-calls" && $(backups | wc -l) -eq 0 ]]; then
  ok "a world-writable install directory is refused up front, naming the chmod, with the compose untouched and nothing owned (#1153)"
else
  bad "a world-writable install directory is refused up front" "rc=$RC: $OUT"
fi
# The config's own directory, which is the root of the config's hand-over.
reset
echo "$REAL_STATE_FILE" > "$TMP/state/real-ancestors"
before_compose="$(md5sum < "$COMPOSE")"
chmod 0777 "$NODE_DIR/config"
run_migrate --apply
chmod 0755 "$NODE_DIR/config"
if [[ $RC -ne 0 ]] && has "$OUT" "refused: $NODE_DIR/config is world-writable" && has "$OUT" "run: sudo chmod go-w $NODE_DIR/config" \
   && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" && ! -f "$TMP/state/chown-calls" ]]; then
  ok "and so is a config directory that anyone can write"
else
  bad "a world-writable config directory is refused up front" "rc=$RC: $OUT"
fi
# A group with another member, answered by a copy of the helper whose
# membership test says so (no account here can make a second member).
sed 's/^    key = (gid, uid)$/    return False  # a test copy: the group has another member\n    key = (gid, uid)/' "$REAL_STATE_FILE" > "$TMP/shared-group-helper.py"
reset
echo "$TMP/shared-group-helper.py" > "$TMP/state/real-ancestors"
before_compose="$(md5sum < "$COMPOSE")"
chmod 0775 "$NODE_DIR"
run_migrate --apply
if [[ $RC -ne 0 ]] && has "$OUT" "refused: $NODE_DIR is writable by group" && has "$OUT" "run: sudo chmod go-w $NODE_DIR" \
   && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" && ! -f "$TMP/state/chown-calls" ]]; then
  ok "an install directory a group with another member can write is refused up front, naming the chmod (#1153)"
else
  bad "a shared-group install directory is refused up front" "rc=$RC: $OUT"
fi
# The control, with the shipped helper: the same 0775 directory in this
# account's own private group, which is what umask 002 makes of every checkout
# and node directory, is allowed, and the run goes through to the hand-over.
reset
echo "$REAL_STATE_FILE" > "$TMP/state/real-ancestors"
chmod 0775 "$NODE_DIR"
run_migrate --apply
if [[ $RC -eq 0 ]] && grep -qF -- "own-many 997:997 ${NODE_DIR}/data" "$TMP/state/chown-calls" 2>/dev/null; then
  ok "  while the same 0775 directory in the account's own private group is not refused: the run goes through"
else
  bad "a private-group install directory is allowed" "rc=$RC: $OUT"
fi

# --hand-store-back proposes only entries the node's account or root owns, so
# its rows run with the store handed to uid 997 first, as the migration leaves
# it. That needs chown, which only root has: fakeroot, as the rows elsewhere in
# this repo do. /bin/chown by its full path, because the chown on PATH here is
# the recorder.
# shellcheck disable=SC2016  # the inner script's own positional parameters
run_put_back() { # the SUT's arguments
  if ! command -v fakeroot >/dev/null 2>&1; then
    OUT="fakeroot is not installed; apt-get install -y fakeroot (what CI uses)"; RC=99; return
  fi
  put_back_account
  OUT="$(fakeroot bash -c '/bin/chown -R 997:997 "$1/data"; shift; bash "$@"' _ "$NODE_DIR" "$SUT" "$@" 2>&1)"
  RC=$?
}
# The node's account, as it is once the migration has run: what --hand-store-back
# reads to know which entries are the node's.
put_back_account() {
  printf 'xrpld:x:997:997:XRP Ledger daemon:/nonexistent:/usr/sbin/nologin\n' > "$TMP/state/account-xrpld"
  printf 'xrpld:x:997:\n' > "$TMP/state/group-xrpld"
}
# The undo is a step, not a chown -R typed by name (#1148). --hand-store-back
# takes every guard --apply takes and then gives back the store, and only the
# store, entry by entry from a record taken first, to root.
reset
before_compose="$(md5sum < "$COMPOSE")"
run_put_back --hand-store-back
if [[ $RC -eq 0 ]] \
   && grep -qF -- "own-many 0:0 ${NODE_DIR}/data" "$TMP/state/chown-calls" 2>/dev/null \
   && grep -qF -- "own-many 0 0  --root ${NODE_DIR} --judge-root --list " "$TMP/state/own-many-argv" 2>/dev/null \
   && grep -qE -- ":[0-9]+:${NODE_DIR}/data/log$" "$TMP/state/list-seen" 2>/dev/null \
   && [[ "$(wc -l < "$TMP/state/own-many-argv")" -eq 1 && ! -f "$TMP/state/chgrp-calls" \
         && ! -f "$TMP/state/useradd-calls" && ! -f "$TMP/state/groupadd-calls" ]] \
   && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" && $(backups | wc -l) -eq 0 ]] \
   && ! has "$OUT" 'chown -R'; then
  ok "--hand-store-back gives the store to root:root by descriptor from a recorded list, and with no backup and no config in the node's group changes the compose, the config and the accounts not at all"
else
  bad "--hand-store-back gives only the store back" "rc=$RC: $OUT :: $(cat "$TMP/state/own-many-argv" 2>/dev/null)"
fi
reset
echo running > "$TMP/state/container-state"
run_migrate --hand-store-back
if [[ $RC -ne 0 ]] && has "$OUT" 'the node is running' && has "$OUT" 'migrate-node --hand-store-back' \
   && [[ ! -f "$TMP/state/chown-calls" ]]; then
  ok "  and it refuses while the node is running, naming the step and not the apply, with nothing owned"
else
  bad "--hand-store-back refuses a running node" "rc=$RC: $OUT"
fi
reset
echo 3 > "$TMP/state/own-many-rc"
run_put_back --hand-store-back
if [[ $RC -ne 0 ]] && has "$OUT" 'was not all given back to root' && has "$OUT" 'again with --hand-store-back'; then
  ok "  and an entry the helper refuses stops it, naming the step to run again"
else
  bad "--hand-store-back stops on a refused entry" "rc=$RC: $OUT"
fi
reset
run_migrate --hand-store-back --apply
if [[ $RC -eq 2 && ! -f "$TMP/state/chown-calls" ]]; then
  ok "  and it is not run with --apply: two different jobs"
else
  bad "--hand-store-back and --apply are refused together" "rc=$RC: $OUT"
fi
# The guards it shares with --apply, each shown for it (the review of #1207):
# a rotation in flight, a verdict that cannot be read, and the scheduled
# window's lock. Nothing is owned in any of them.
reset
printf 'rotating\ta store rotation started 3 minutes ago and has not finished\n' > "$TMP/state/rotation"
run_migrate --hand-store-back
if [[ $RC -ne 0 && "$OUT" == *"#79"* && ! -f "$TMP/state/chown-calls" ]]; then
  ok "--hand-store-back: a store rotation in flight is refused, and nothing is owned"
else
  bad "--hand-store-back refuses a rotation in flight" "rc=$RC: $OUT"
fi
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
run_migrate --hand-store-back
if [[ $RC -ne 0 && "$OUT" == *"whether it is rotating is unknown"* && ! -f "$TMP/state/chown-calls" ]]; then
  ok "  and so is a verdict that cannot be read, until the operator says they read the log"
else
  bad "--hand-store-back refuses an unreadable rotation verdict" "rc=$RC: $OUT"
fi
run_put_back --hand-store-back --rotation-checked-by-hand
if [[ $RC -eq 0 ]] && grep -qF -- "own-many 0:0 ${NODE_DIR}/data" "$TMP/state/chown-calls" 2>/dev/null; then
  ok "  with --rotation-checked-by-hand the same run goes through"
else
  bad "--hand-store-back goes through with --rotation-checked-by-hand" "rc=$RC: $OUT"
fi
for mode in --hand-store-back --apply; do
  reset
  exec 8>"$LOCK"
  flock -n 8
  run_migrate "$mode"
  exec 8>&-
  if [[ $RC -ne 0 && "$OUT" == *"holds ${LOCK}"* && ! -f "$TMP/state/chown-calls" ]]; then
    ok "$mode: the scheduled window holding the rotation lock stops the run, and nothing is owned"
  else
    bad "$mode refuses while the rotation lock is held" "rc=$RC: $OUT"
  fi
done
# Only what the migration handed to the node's account, or root already owns,
# goes back (the review of #1207, L4): an entry owned by anyone else was put in
# the store since and is named and left. Under fakeroot, where chown is allowed.
if (( $(command -v fakeroot >/dev/null 2>&1; echo $?) == 0 )); then
  reset
  put_back_account
  # shellcheck disable=SC2016  # the inner script's own positional parameters
  OUT="$(fakeroot bash -c '/bin/chown -R 997:997 "$1/data"; /bin/chown 1234:1234 "$1/data/log/debug.log"; bash "$2" --hand-store-back' _ "$NODE_DIR" "$SUT" 2>&1)"; RC=$?
  if [[ $RC -eq 0 ]] \
     && grep -qF -- "own-many 0:0 ${NODE_DIR}/data" "$TMP/state/chown-calls" 2>/dev/null \
     && grep -qF -- "own-many 0:0 ${NODE_DIR}/data/log" "$TMP/state/chown-calls" 2>/dev/null \
     && ! grep -qF -- "debug.log" "$TMP/state/chown-calls" 2>/dev/null \
     && [[ "$OUT" == *"1 entry under it belong to neither"* ]]; then
    ok "--hand-store-back proposes the node's entries and root's, and names the entry that belongs to neither and leaves it"
  else
    bad "--hand-store-back leaves an entry owned by another account" "rc=$RC: $OUT :: $(cat "$TMP/state/chown-calls" 2>/dev/null)"
  fi
else
  bad "the ownership row can run" "fakeroot is not installed; apt-get install -y fakeroot (what CI uses)"
fi
# The backup it names is one this script made, and nothing else in the
# directory: the directory is the login's, and the line is one the operator
# pastes into a root shell (the review of #1207).
reset
put_back_account
: > "${COMPOSE}.20260101-010101.bak"
: > "${COMPOSE}.20260202-020202.bak"
: > "${COMPOSE}.1;touch ${TMP}/pwned;.bak"
: > "${COMPOSE}.20260303-030303.bak.evil"
: > "${COMPOSE}.99999999-999999.bak;x"
run_put_back --hand-store-back
if [[ $RC -eq 0 && "$OUT" == *"${COMPOSE} <- ${COMPOSE}.20260202-020202.bak"* \
      && "$OUT" != *"pwned"* && "$OUT" != *".bak.evil"* && "$OUT" != *"99999999"* ]]; then
  ok "the compose it puts back is the newest one this script stamped, not a name somebody else left beside it"
else
  bad "--hand-store-back prints only a backup this script made" "rc=$RC: $OUT"
fi
reset
put_back_account
: > "${COMPOSE}.x y;z.bak"
run_put_back --hand-store-back
if [[ $RC -eq 0 && "$OUT" == *"no dated .bak beside"* && "$OUT" != *"x y;z"* ]]; then
  ok "  and with only such names there it says there is no backup to copy back"
else
  bad "--hand-store-back says there is no backup when only foreign names are there" "rc=$RC: $OUT"
fi

# =====================================================================
echo
echo "The rest of the way back is the step too (#1208):"
# The migration used to print `sudo cp <bak> <compose>` and `sudo chgrp <group>
# <config>`, both by name in a directory the login owns: cp as root writes
# through a link planted at the compose file's name, and chgrp follows one at
# the config's. --hand-store-back now puts both back by descriptor, and no
# output of this script prints either command.
reset
run_migrate --help
HELP_OUT="$OUT"
reset
run_migrate --apply
APPLY_OUT="$OUT"
reset
echo running > "$TMP/state/container-state"
run_migrate
REPORT_OUT="$OUT"
run_migrate --apply
REFUSE_OUT="$OUT"
if [[ "$HELP_OUT$APPLY_OUT$REPORT_OUT$REFUSE_OUT" != *"sudo cp"* && "$HELP_OUT$APPLY_OUT$REPORT_OUT$REFUSE_OUT" != *"sudo chgrp"* \
      && "$APPLY_OUT" == *"--run migrate-node --hand-store-back"* ]]; then
  ok "-h, an --apply run, a report and a refusal print no sudo cp and no sudo chgrp: the way back is the one step"
else
  bad "no output prints sudo cp or sudo chgrp" "$(grep -hE 'sudo (cp|chgrp)' <<<"$HELP_OUT$APPLY_OUT$REPORT_OUT$REFUSE_OUT")"
fi
# The comment on #1208: the report and the running-node refusal printed
# `sudo bash $0 --apply`, which from a checkout is the checkout's copy root
# should not run (ADR 0024). They print the --run step instead.
if [[ "$REPORT_OUT$REFUSE_OUT" != *"sudo bash"* \
      && "$REPORT_OUT" == *"--run migrate-node --apply"* && "$REFUSE_OUT" == *"--run migrate-node --apply"* ]]; then
  ok "the report and the running-node refusal name the --run step for --apply, never sudo bash of this copy"
else
  bad "the report and the refusal name the --run step" "$(grep -hE 'sudo bash|--apply' <<<"$REPORT_OUT$REFUSE_OUT")"
fi

# What happened, not what was asked: one fakeroot session holds the state the
# migration leaves (store and config in the node's group 997), runs the step
# against the real helper, and reads the result back before the session ends.
# $PB_SETUP runs first and $PB_READ last, both shell text; the read-back lands
# in state/after.
# shellcheck disable=SC2016  # the inner script's own variables
put_back_real() {
  if ! command -v fakeroot >/dev/null 2>&1; then
    OUT="fakeroot is not installed; apt-get install -y fakeroot (what CI uses)"; RC=99; return
  fi
  put_back_account
  : > "$TMP/state/real-helper"
  OUT="$(NODE_DIR="$NODE_DIR" CFG="$CFG" VAL="$VAL" COMPOSE="$COMPOSE" SUT="$SUT" TMP="$TMP" \
         PB_SETUP="${PB_SETUP:-:}" PB_READ="${PB_READ:-:}" fakeroot bash -c '
    /bin/chown -R 997:997 "$NODE_DIR/data"
    /bin/chgrp 997 "$CFG" "$VAL"
    eval "$PB_SETUP"
    bash "$SUT" --hand-store-back; rc=$?
    eval "$PB_READ" > "$TMP/state/after" 2>&1
    exit "$rc"' 2>&1)"
  RC=$?
  rm -f "$TMP/state/real-helper"
}
# A migrated host: the dated backup and the rewritten compose, both from a real
# --apply (the recorders on PATH leave every owner as it was).
migrated() {
  reset
  run_migrate --apply
  PB_BAK="$(backups | tail -1)"
}

migrated
# shellcheck disable=SC2016  # the text runs inside the fakeroot session, where these expand
PB_SETUP=':' PB_READ='cmp -s "$COMPOSE" '"$(printf '%q' "$PB_BAK")"' && echo compose=old; [[ -L "$COMPOSE" ]] && echo compose=link; echo "cfg=$(stat -c %g "$CFG") val=$(stat -c %g "$VAL")"' put_back_real
AFTER="$(cat "$TMP/state/after" 2>/dev/null)"
if [[ $RC -eq 0 && "$AFTER" == *"compose=old"* && "$AFTER" != *"compose=link"* && "$AFTER" == *"cfg=0 val=0"* \
      && "$OUT" != *"sudo cp"* && "$OUT" != *"sudo chgrp"* ]]; then
  ok "--hand-store-back puts the compose back from its backup and the config's and validator list's group back to root, by itself"
else
  bad "--hand-store-back puts the compose and the config's group back" "rc=$RC after=[$AFTER]: $OUT"
fi

# A link at the compose file's name. The file it points at keeps its owner and
# its content, and the name ends up holding the backup as a plain file: the
# rename replaces the link instead of writing through it.
# The target is a copy of the migrated compose, so the run reads its shape
# through the link and gets as far as putting it back.
migrated
cp "$COMPOSE" "$TMP/outside-compose"
chmod 0644 "$TMP/outside-compose"
outside_sum="$(md5sum < "$TMP/outside-compose")"
# shellcheck disable=SC2016  # the text runs inside the fakeroot session, where these expand
PB_SETUP='/bin/chown 4242:4242 "$TMP/outside-compose"; rm -f "$COMPOSE"; ln -s "$TMP/outside-compose" "$COMPOSE"' \
PB_READ='echo "outside=$(md5sum < "$TMP/outside-compose") $(stat -c "%u %a" "$TMP/outside-compose")"; [[ -L "$COMPOSE" ]] && echo compose=link; cmp -s "$COMPOSE" '"$(printf '%q' "$PB_BAK")"' && echo compose=old' put_back_real
AFTER="$(cat "$TMP/state/after" 2>/dev/null)"
if [[ $RC -eq 0 && "$AFTER" == *"outside=$outside_sum 4242 644"* && "$AFTER" != *"compose=link"* && "$AFTER" == *"compose=old"* ]]; then
  ok "  a link planted at the compose file's name: its target keeps its owner and content, and the name gets the backup"
else
  bad "a link at the compose name is replaced, not written through" "rc=$RC after=[$AFTER]: $OUT"
fi

# A link at the config's name, itself in the node's group. Its target keeps its
# group, and the step stops and says why rather than following it.
migrated
printf '[x]\n' > "$TMP/outside-cfg"
# shellcheck disable=SC2016  # the text runs inside the fakeroot session, where these expand
PB_SETUP='/bin/chgrp 997 "$TMP/outside-cfg"; rm -f "$CFG"; ln -s "$TMP/outside-cfg" "$CFG"; /bin/chgrp -h 997 "$CFG"' \
PB_READ='echo "outside=$(stat -c %g "$TMP/outside-cfg")"' put_back_real
AFTER="$(cat "$TMP/state/after" 2>/dev/null)"
if [[ $RC -ne 0 && "$AFTER" == *"outside=997"* && "$OUT" == *"was not given back to root"* ]]; then
  ok "  a link planted at the config's name: its target keeps its group, and the step refuses and names it"
else
  bad "a link at the config name is not followed" "rc=$RC after=[$AFTER]: $OUT"
fi

# The newest backup is only the migration's if nothing rewrote the compose
# since: the wrapper keeps backups under the same name. One that already runs
# the node as its own account is not put back.
migrated
cp "$COMPOSE" "${COMPOSE}.29991231-235959.bak"
before_compose="$(md5sum < "$COMPOSE")"
# shellcheck disable=SC2016  # the text runs inside the fakeroot session, where these expand
PB_SETUP=':' PB_READ='md5sum < "$COMPOSE"' put_back_real
AFTER="$(cat "$TMP/state/after" 2>/dev/null)"
if [[ $RC -ne 0 && "$OUT" == *"already has a user: line"* && "$AFTER" == "$before_compose" ]]; then
  ok "  a newest backup that already has a user: line is refused, and the compose is left as it is"
else
  bad "a backup in the new shape is not put back" "rc=$RC after=[$AFTER]: $OUT"
fi
# The same refusal on a backup past 64 KiB with the user: line near the top,
# and on one that spells the key quoted. A `tail | grep -q` under pipefail
# missed the first: grep quit early, tail took SIGPIPE, the pipeline failed,
# and the backup was put back (the review of #1206).
migrated
{ cat "$COMPOSE"; for _i in $(seq 1 1200); do printf '# padding line %04d to carry the backup past 64 KiB.............\n' "$_i"; done; } \
  > "${COMPOSE}.29991231-235959.bak"
before_compose="$(md5sum < "$COMPOSE")"
# shellcheck disable=SC2016  # the text runs inside the fakeroot session, where these expand
PB_SETUP=':' PB_READ='md5sum < "$COMPOSE"' put_back_real
AFTER="$(cat "$TMP/state/after" 2>/dev/null)"
if (( $(stat -c %s "${COMPOSE}.29991231-235959.bak") > 65536 )) \
   && [[ $RC -ne 0 && "$OUT" == *"already has a user: line"* && "$AFTER" == "$before_compose" ]]; then
  ok "  and so is one past 64 KiB with its user: line near the top"
else
  bad "a large backup in the new shape is not put back" "size $(stat -c %s "${COMPOSE}.29991231-235959.bak") rc=$RC after=[$AFTER]: $OUT"
fi
migrated
sed -E 's/^([[:space:]]*)user:/\1"user":/' "$COMPOSE" > "${COMPOSE}.29991231-235959.bak"
before_compose="$(md5sum < "$COMPOSE")"
# shellcheck disable=SC2016  # the text runs inside the fakeroot session, where these expand
PB_SETUP=':' PB_READ='md5sum < "$COMPOSE"' put_back_real
AFTER="$(cat "$TMP/state/after" 2>/dev/null)"
if grep -q '"user":' "${COMPOSE}.29991231-235959.bak" \
   && [[ $RC -ne 0 && "$OUT" == *"already has a user: line"* && "$AFTER" == "$before_compose" ]]; then
  ok "  and so is one that quotes the key, \"user\":"
else
  bad "a backup with a quoted user key is not put back" "rc=$RC after=[$AFTER]: $OUT"
fi
# The log it tells you to read is printed as a command, from a config the login
# owns: quoted, and never through a .. (the review of #1207).
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
printf '[node_db]\ntype=NuDB\n\n[debug_logfile]\n/var/lib/xrpld/a;touch x;b\n' > "$CFG"
: > "$NODE_DIR/data/a;touch x;b"
run_migrate --hand-store-back
if [[ "$OUT" == *'sudo tail -n 200 '*'/data/a\;touch\ x\;b |'* && "$OUT" != *'/data/a;touch x;b'* ]]; then
  ok "a log name with a ; and a space in it is printed quoted, so pasting the line runs one command"
else
  bad "the log path is printed quoted" "$OUT"
fi
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
printf '[node_db]\ntype=NuDB\n\n[debug_logfile]\n/var/lib/xrpld/../../../../etc/hostname\n' > "$CFG"
run_migrate --hand-store-back
if [[ "$OUT" != *"sudo tail"* && "$OUT" == *"docker logs --tail 200 test-node"* ]]; then
  ok "  and a declared log path with a .. in it is not followed out of the store: it is treated as one outside it"
else
  bad "a .. in the declared log path is refused" "$OUT"
fi
# [0-9] follows the locale: under en_US.UTF-8 it also matches U+0663, so a name
# the login planted with that digit would be taken for a backup this script made.
if locale -a 2>/dev/null | grep -qix 'en_US\.utf-\?8'; then
  reset
  put_back_account
  : > "${COMPOSE}.20260101-010101.bak"
  : > "${COMPOSE}.2026100$(printf '\xd9\xa3')-120000.bak"
  LC_ALL=en_US.UTF-8 run_put_back --hand-store-back
  if [[ $RC -eq 0 && "$OUT" == *"${COMPOSE}.20260101-010101.bak"* && "$OUT" != *"$(printf '\xd9\xa3')"* ]]; then
    ok "a backup name with a non-ASCII digit is not taken for one this script stamped, even where [0-9] would match it"
  else
    bad "only ASCII digits make a backup name" "rc=$RC: $OUT"
  fi
elif [[ -n "${CI:-}" ]]; then
  # The workflow generates this locale. A CI job without it would print the
  # SKIP below and go green having measured nothing (#1213).
  bad "the en_US.UTF-8 locale is present, so the non-ASCII digit row runs" "CI is set, so this job is meant to have it; the row was not measured"
else
  echo "  SKIP: no en_US.UTF-8 locale here; the non-ASCII digit row was not measured"
fi
# The messages that follow a failed compose patch say what is true of the store.
if ! grep -qE 'already (been )?chowned' "$REPO_DIR/scripts/migrate-node-nonroot.sh"; then
  ok "no refusal in the script says the store is already handed over when the compose file is patched first"
else
  bad "the compose-patch refusals do not claim a hand-over that has not happened" "$(grep -nE 'already (been )?chowned' "$REPO_DIR/scripts/migrate-node-nonroot.sh" | cut -c1-120)"
fi
# Nothing the script prints, or its header says, is a typed recursive chown.
if ! grep -nE 'chown -R root:root' "$REPO_DIR/scripts/migrate-node-nonroot.sh" >/dev/null \
   && [[ "$(grep -c -- '--run migrate-node --hand-store-back' "$REPO_DIR/scripts/migrate-node-nonroot.sh")" -ge 3 ]]; then
  ok "no hint in the script is a chown -R by name any more: the header, the closing block and the running-node refusal name the step"
else
  bad "the hints name the step" "$(grep -nE 'chown -R root:root' "$REPO_DIR/scripts/migrate-node-nonroot.sh" | head -3)"
fi

# A config that is a link is refused up front too: root changes its group by
# descriptor and never through a link, and finding that out after the store
# was handed over would leave the run half done.
reset
before_compose="$(md5sum < "$COMPOSE")"
mv "$CFG" "$CFG.real"; ln -s "$CFG.real" "$CFG"
run_migrate --apply
if [[ $RC -ne 0 ]] && has "$OUT" "$CFG is a symbolic link" && has "$OUT" 'nothing has been changed' \
   && [[ "$(md5sum < "$COMPOSE")" == "$before_compose" && ! -f "$TMP/state/chown-calls" && ! -f "$TMP/state/chgrp-calls" ]]; then
  ok "a node config that is a link stops the run before anything is changed"
else
  bad "a linked node config is refused up front" "rc=$RC: $OUT"
fi

reset
# A file that has the user: line and not the mounts: an apply that was
# interrupted, or a host somebody edited by hand.
render_template 997 997 | grep -vE ':/etc/xrpld/(xrpld\.cfg|validators\.txt):ro$' > "$COMPOSE"
run_migrate --apply
if [[ $RC -eq 0 && "$(grep -c 'user: "997:997"' "$COMPOSE")" == 1 ]]; then
  ok "a half-migrated file gains the half it is missing and not a second copy of the half it has"
else
  bad "a half-migrated file gains only the half it is missing" "rc=$RC: $(grep -n 'user:' "$COMPOSE")"
fi
if diff -q <(render_template 997 997) "$COMPOSE" >/dev/null; then
  ok "and it lands on the same file as every other route to it"
else
  bad "a half-migrated file lands on the same file" "$(diff <(render_template 997 997) "$COMPOSE")"
fi

# =====================================================================
echo
echo "A compose the operator edited by hand:"

reset
# Not the template: a hand-written deployment with a per-host peer mapping.
# Re-rendering from the template would silently take that mapping away, which
# is why this patches in place.
{
  printf 'services:\n  test-node:\n'
  printf '    image: xrpllabsofficial/xrpld:3.3.0\n'
  printf '    init: true\n'
  printf '    ports:\n      - "51299:2459/tcp"\n'
  printf '    volumes:\n'
  printf '      - %s:/config/rippled.cfg:ro\n' "$CFG"
  printf '      - %s:/config/validators.txt:ro\n' "$VAL"
  printf '      - %s/data:/var/lib/xrpld\n' "$NODE_DIR"
  printf '    cap_drop: [ ALL ]\n'
  printf '    mem_limit: "48g"\n'
} > "$COMPOSE"
run_migrate --apply
if [[ $RC -eq 0 ]] && grep -qF '51299:2459' "$COMPOSE" && grep -qF 'mem_limit: "48g"' "$COMPOSE"; then
  ok "the per-host edits survive: the file is patched, never re-rendered"
else
  bad "the per-host edits survive" "rc=$RC: $(cat "$COMPOSE")"
fi
if grep -qE '^    user: "997:997"$' "$COMPOSE" \
   && grep -qF -- "- ${CFG}:/etc/xrpld/xrpld.cfg:ro" "$COMPOSE" \
   && grep -qF -- "- ${VAL}:/etc/xrpld/validators.txt:ro" "$COMPOSE" \
   && grep -qF 'cap_drop' "$COMPOSE"; then
  ok "it gains user: and both /etc/xrpld mounts, at the indentation the file already uses, and keeps cap_drop"
else
  bad "it gains user: and both /etc/xrpld mounts" "$(cat "$COMPOSE")"
fi
# The mounts are derived from the line they are inserted before, so a host
# whose config lives somewhere else still gets a correct pair rather than the
# template's paths.
if ! grep -qF '/aperire-node/config' "$COMPOSE"; then
  ok "the inserted mounts name this host's own paths, not the template's"
else
  bad "the inserted mounts name this host's own paths" "$(grep -n xrpld "$COMPOSE")"
fi

reset
# A compose with nothing to anchor on. Better to refuse and say so than to
# insert a line into a file this does not understand.
printf 'services:\n  test-node:\n    image: x\n    volumes:\n      - %s/data:/var/lib/xrpld\n' "$NODE_DIR" > "$COMPOSE"
BEFORE=$(md5sum < "$COMPOSE")
run_migrate --apply
if [[ $RC -ne 0 && "$(md5sum < "$COMPOSE")" == "$BEFORE" ]]; then
  ok "a compose this script cannot read is refused, and left alone"
else
  bad "a compose this script cannot read is refused, and left alone" "rc=$RC: $OUT"
fi
if [[ ! -f "$TMP/state/chown-calls" ]]; then
  ok "and the store was not chowned before that refusal: the compose is prepared first"
else
  bad "the store was not chowned before the refusal" "$(cat "$TMP/state/chown-calls")"
fi

# =====================================================================
echo
echo "Report mode, on the running node every operator has when they read about this (#435):"

# The documented first step is a report, and the guide runs it before the node
# is stopped. On a running node it used to stop at the running check, which
# sits above "What is already true" and "What --apply would do", print a
# refusal and exit 1. So the one command an operator was told to run first
# never reported, and a runbook checking statuses read the first step as a
# failure.
reset
echo running > "$TMP/state/container-state"
BEFORE=$(md5sum < "$COMPOSE")
run_migrate
if [[ $RC -eq 0 ]]; then
  ok "a report on a running node exits 0, because it had a report to give"
else
  bad "a report on a running node exits 0" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"What is already true"* && "$OUT" == *"What --apply would do"* ]]; then
  ok "and it prints the whole plan, which is what sits below the running check"
else
  bad "the report prints the whole plan" "$OUT"
fi
if [[ "$OUT" == *"The account the node will run as"* ]]; then
  ok "including the account that would be created or found"
else
  bad "the report names the account" "$OUT"
fi
if [[ "$OUT" == *"Before --apply: stop the node"* && "$OUT" == *"stop, not down"* ]]; then
  ok "and it ends by saying the node must be stopped first, and how"
else
  bad "the report ends with the stop" "$OUT"
fi
if [[ "$(md5sum < "$COMPOSE")" == "$BEFORE" && ! -f "$TMP/state/chown-calls" ]]; then
  ok "and it changed nothing, which is what report mode promises"
else
  bad "report mode changed nothing" "chown: $(cat "$TMP/state/chown-calls" 2>/dev/null)"
fi

# =====================================================================
echo
echo "The rotation verdict, and whether there was anybody to ask (#442):"

# A node-only host has no wrapper configuration, so the wrapper's
# rotation-state prints its refusal on stderr, which was redirected away, and
# the empty string it left behind landed in the arm that proceeds. A 46 GB
# store was migrated under exactly that.
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"NOT ASKED"* && "$OUT" == *"#442"* ]]; then
  ok "--apply refuses where the verdict could not be obtained, rather than proceeding blind"
else
  bad "--apply refuses on an unobtainable verdict" "rc=$RC: $OUT"
fi
if [[ ! -f "$TMP/state/chown-calls" ]]; then
  ok "and nothing was chowned under that refusal"
else
  bad "nothing was chowned under the refusal" "$(cat "$TMP/state/chown-calls")"
fi
if [[ "$OUT" == *"${NODE_DIR}/data/log/debug.log"* && "$OUT" == *"rotating validatedSeq"* ]]; then
  ok "it names the log to read instead, mapped from the config through the store mount"
else
  bad "it names the log to read instead" "$OUT"
fi

# A config naming its log somewhere the store mount does not reach. The path
# exists inside the container and nowhere on the host, so pointing at it would
# be an instruction that fails the moment it is followed.
reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
printf '[node_db]\ntype=NuDB\n\n[debug_logfile]\n/var/log/xrpld/debug.log\n' > "$CFG"
run_migrate --apply
if [[ "$OUT" == *"docker logs --tail 200 test-node"* && "$OUT" == *"no copy of that log outside the container"* ]]; then
  ok "and where the store mount does not reach that log, it says so and names the container's own"
else
  bad "a log outside the store mount is named honestly" "$OUT"
fi

# The same host after a `docker compose down`, which is what the guide used to
# print: the container is gone and docker's json log went with it. Naming
# `docker logs` here would be a command that cannot run.
reset
rm -f "$WCONF" "$TMP/state/container-state"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
printf '[node_db]\ntype=NuDB\n\n[debug_logfile]\n/var/log/xrpld/debug.log\n' > "$CFG"
run_migrate --apply
if [[ "$OUT" == *"neither source is readable on this host"* && "$OUT" != *"docker logs --tail 200 test-node"* ]]; then
  ok "with no container left, it says neither source is readable instead of naming docker logs"
else
  bad "a removed container is not sent to docker logs" "$OUT"
fi
if [[ "$OUT" == *"nothing is writing the store now"* ]]; then
  ok "and it says what is still true with no container, rather than leaving the operator with nothing"
else
  bad "it says what is still true with no container" "$OUT"
fi
if [[ $RC -ne 0 && "$OUT" == *"#442"* ]]; then
  ok "and --apply still refuses, because unreadable is not idle"
else
  bad "--apply still refuses with no container" "rc=$RC: $OUT"
fi

reset
rm -f "$WCONF"
printf 'CONFIG_FILE=%s\n' "$CFG" >> "$NCONF"
run_migrate
if [[ $RC -eq 0 && "$OUT" == *"NOT ASKED"* ]]; then
  ok "report mode says the same thing and still reports, because it changes nothing"
else
  bad "report mode reports on a host with no verdict" "rc=$RC: $OUT"
fi

reset
printf 'rotating\ta store rotation started 3 minutes ago and has not finished\n' > "$TMP/state/rotation"
run_migrate --apply --rotation-checked-by-hand
if [[ $RC -ne 0 && "$OUT" == *"#79"* ]]; then
  ok "control: where the verdict CAN be read, --rotation-checked-by-hand does not override it"
else
  bad "the by-hand flag does not override a real verdict" "rc=$RC: $OUT"
fi

reset
run_migrate
if [[ "$OUT" == *"(from aperire-node-wrapper.sh rotation-state)"* ]]; then
  ok "a verdict that was read says where it was read from"
else
  bad "the verdict names its source" "$OUT"
fi

# =====================================================================
echo
echo "A migrated compose explains itself the way a fresh one does (#438):"

# The migration patches in place, so the comment block above `name:` is
# whatever release rendered the file. On aperire4 that left a compose running
# the node as 996 under a header explaining why data/ has to be root-owned,
# three lines apart in one file.
header_of()   { grep -q '^name:' "$1" || return 1; sed -n '1,/^name:/p' "$1" | sed '$d'; }
body_of()     { sed -n '/^name:/,$p' "$1"; }
fresh_header() { # $1 = uid, $2 = gid
  sed -e "s#@NAME@#test-node#g" -e "s#@DIR@#${NODE_DIR}#g" -e "s#@TAG@#3.3.0#g" \
      -e "s#@UID@#$1#g" -e "s#@GID@#$2#g" "$COMPOSE_TPL" \
    | sed -n '1,/^name:/p' | sed '$d'
}

reset
# The header a release before #31 wrote, which is what a host being migrated
# today is carrying.
{
  printf '# The hardened node compose.\n'
  printf '#   cap_drop / no-new-privileges  ... so data/ must be root-owned or the\n'
  printf '#       first start crash-loops. The installer creates it that way.\n'
  body_of "$COMPOSE"
} > "$COMPOSE.tmp" && mv "$COMPOSE.tmp" "$COMPOSE"
BODY_BEFORE=$(body_of "$COMPOSE" | grep -v '^[[:space:]]*user:' | grep -v ':/etc/xrpld/')
run_migrate --apply
if [[ "$(header_of "$COMPOSE")" == "$(fresh_header 997 997)" ]]; then
  ok "the migrated file's header is byte-for-byte the header a fresh render has"
else
  bad "the migrated header equals a fresh render's" "$(diff <(header_of "$COMPOSE") <(fresh_header 997 997) | head -20)"
fi
if [[ "$(header_of "$COMPOSE")" != *"must be root-owned"* ]]; then
  ok "so it no longer explains why the store has to be owned by root"
else
  bad "the root-owned sentence is gone" "$(header_of "$COMPOSE")"
fi
if [[ "$(body_of "$COMPOSE" | grep -v '^[[:space:]]*user:' | grep -v ':/etc/xrpld/')" == "$BODY_BEFORE" ]]; then
  ok "and every line from 'name:' down is the operator's own, apart from the three the migration adds"
else
  bad "the body is untouched apart from the migration's own three lines" \
      "$(diff <(printf '%s\n' "$BODY_BEFORE") <(body_of "$COMPOSE" | grep -v '^[[:space:]]*user:' | grep -v ':/etc/xrpld/') | head -20)"
fi
if [[ "$OUT" == *"nothing below it changed"* ]]; then
  ok "and the run says it replaced the comment block and nothing else"
else
  bad "the run says what it replaced" "$OUT"
fi

# A host migrated by an earlier build: body already right, header still the
# old one. A re-run is how it gets the rest.
BODY_KEPT=$(body_of "$COMPOSE")
{
  printf '# An older release rendered this, and it says data/ must be root-owned.\n'
  printf '%s\n' "$BODY_KEPT"
} > "$COMPOSE.tmp" && mv "$COMPOSE.tmp" "$COMPOSE"
run_migrate --apply
if [[ "$(header_of "$COMPOSE")" == "$(fresh_header 997 997)" && "$(body_of "$COMPOSE")" == "$BODY_KEPT" ]]; then
  ok "a re-run on an already-migrated host fixes the header alone"
else
  bad "a re-run fixes the header alone" "$(diff <(printf '%s\n' "$BODY_KEPT") <(body_of "$COMPOSE") | head -10)"
fi
run_migrate --apply
if [[ "$OUT" == *"the header is already this release's; unchanged"* ]]; then
  ok "and a third run says there is nothing left to do to it"
else
  bad "a third run leaves the header alone and says so" "$OUT"
fi

# =====================================================================
echo
echo "The three ways a compose header compares to this release's (#467):"

# A compose with no name: line at all: the shape of a hand-written deployment
# from before install-aperire-node.sh existed. The bug this holds shut read
# that shape as "current" without ever comparing anything, on a real host
# (a lab host) whose header still explained why the store had to be
# root-owned after the migration ran.
reset
sed -i '/^name:/d' "$COMPOSE"
run_migrate
if [[ "$OUT" == *"compose header  : no 'name:' line in this file, so it is not this release's header"* ]]; then
  ok "no name: line reports itself as not this release's header, distinct from current"
else
  bad "no name: line is reported as not current, not folded into it" "$OUT"
fi
if [[ "$OUT" == *"leave the header as it is: there is no 'name:' line to safely anchor a replacement on"* ]]; then
  ok "and the report says the same thing about what --apply would do"
else
  bad "the report explains why --apply would leave an unanchored header alone" "$OUT"
fi
run_migrate --apply --rotation-checked-by-hand
if [[ $RC -eq 0 && "$OUT" == *"no 'name:' line to safely anchor a header on; left as it is"* ]]; then
  ok "and --apply says plainly why it leaves the header alone, rather than guessing at one"
else
  bad "--apply explains why it leaves an unanchored header alone" "rc=$RC: $OUT"
fi
if ! grep -q '^name:' "$COMPOSE" && grep -qE '^[[:space:]]*user:[[:space:]]*"997:997"' "$COMPOSE"; then
  ok "the body still gets patched even though the header decision is left alone"
else
  bad "the body is patched independently of the header decision" "$(cat "$COMPOSE")"
fi

# A stale header: an older release's, same three lines #438 was filed about.
reset
{
  printf '# An older release rendered this header.\n'
  sed -n '/^name:/,$p' "$COMPOSE"
} > "$COMPOSE.tmp" && mv "$COMPOSE.tmp" "$COMPOSE"
run_migrate
if [[ "$OUT" == *"compose header  : written before the node ran as xrpld, and says the store must be root-owned"* ]]; then
  ok "a stale header is named for what it is"
else
  bad "a stale header reports itself as stale" "$OUT"
fi

# A current header: exactly what a fresh render produces, which is what
# reset() itself lays down.
reset
run_migrate
if [[ "$OUT" == *"compose header  : current"* ]]; then
  ok "a header that already matches this release's render reports current"
else
  bad "a current header reports itself as current" "$OUT"
fi

# =====================================================================
echo
echo "With no node.conf, the account is still said somewhere (#468):"

# The node predates install-aperire-node.sh, so it has no node.conf, and the
# wrapper's own file is what names the container and the compose. Before this
# fix the account this migration settled on went unrecorded and unmentioned.
reset
rm -f "$NCONF"
run_migrate --apply
if [[ $RC -eq 0 ]]; then
  ok "it still migrates a host that has no node.conf"
else
  bad "it still migrates a host with no node.conf" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"no ${NCONF} on this host, so the account is recorded only in the compose file: xrpld uid 997 gid 997"* ]]; then
  ok "and it says so, naming both ids and where the only record of them lives"
else
  bad "it names the account and says where its only record lives" "$OUT"
fi

# =====================================================================
echo
echo "The config's ACL survives the group move untouched (#471):"

# The no-chmod rule's whole reason to exist: a named ACL entry and the mask
# it forces onto the file, the shape a relay's read grant leaves and the
# shape no live host has carried through a migration yet. Three separate
# measurements, because the first one by itself proves less than it looks:
#
#   1. through the migration   chgrp is a fake on this suite's PATH (every
#                               other row here relies on that to read what
#                               was asked for without being root), so this
#                               measurement really shows "the migration
#                               issues no chmod against this file" (a real
#                               chmod would run right here and be caught)
#                               and not, by itself, that a group move is
#                               safe: the fake never touches the fixture.
#   2. the real group move      the test moves the fixture's group itself,
#                               through the real state helper, to a group
#                               this account actually has. This is the property the
#                               migration's own comment rests its no-chmod
#                               rule on.
#   3. a real chmod, as a      the negative control, on the same fixture,
#      control                 run directly rather than through the
#                               migration (which never calls chmod at all).
#                               If this stopped failing, the two checks
#                               above would have stopped proving anything.
#
# `getfacl -e` prints the effective right beside every entry, always, so a
# byte-for-byte comparison of that output is the named entry, the mask AND
# the effective read in one assertion rather than three that could drift
# apart. If setfacl/getfacl are not usable here, or this filesystem grants
# the fixture no mask:: line, every row below says so and skips rather than
# failing the suite over a runner it cannot prove anything on.
ACL_USABLE=0
if command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1; then
  reset
  if setfacl -m u:daemon:r-- "$CFG" 2>/dev/null \
     && getfacl -pe "$CFG" 2>/dev/null | grep -q '^mask::'; then
    ACL_USABLE=1
  fi
fi

if ((ACL_USABLE)); then
  # 1. Through the migration, with the fake chgrp this suite runs under.
  reset
  setfacl -m u:daemon:r-- "$CFG"
  ACL_BEFORE=$(getfacl -pe "$CFG" 2>/dev/null)
  run_migrate --apply
  ACL_AFTER=$(getfacl -pe "$CFG" 2>/dev/null)
  if [[ "$ACL_BEFORE" == "$ACL_AFTER" ]]; then
    ok "through the migration: the named entry, the mask and the effective read are byte-identical before and after"
  else
    bad "the ACL is untouched by the migration's group-only move" "$(diff <(printf '%s\n' "$ACL_BEFORE") <(printf '%s\n' "$ACL_AFTER"))"
  fi
  if grep -qF -- "997 $CFG" "$TMP/state/chgrp-calls" 2>/dev/null; then
    ok "and the group move that would change it on a real host was still asked for"
  else
    bad "the group move was still asked for" "$(cat "$TMP/state/chgrp-calls" 2>/dev/null)"
  fi

  # 2. The real group move, to a group this account actually has: the stand-in
  # above never touches the fixture, so the row alone cannot tell "a group move is
  # safe" from "nothing happened". The header's own group: line is expected
  # to move; only the ACL entries below it are asserted unchanged.
  ALT_GROUP=''
  for g in $(id -Gn); do
    [[ "$g" != "$(id -gn)" ]] && { ALT_GROUP="$g"; break; }
  done
  if [[ -n "$ALT_GROUP" ]]; then
    reset
    setfacl -m u:daemon:r-- "$CFG"
    ENTRIES_BEFORE=$(getfacl -pe "$CFG" 2>/dev/null | grep -E '^(user|group|mask|other):')
    # The move the migration makes: the group alone, by descriptor, through the
    # real helper (this suite's copy of it is a stand-in that changes nothing).
    ALT_GID="$(/usr/bin/getent group "$ALT_GROUP" | cut -d: -f3)"
    printf '%s\0' "$CFG" | python3 -I "$REAL_STATE_FILE" own-many "" "$ALT_GID" "" --root "$(dirname -- "$CFG")" --judge-root
    GROUP_AFTER=$(stat -c '%G' "$CFG")
    ENTRIES_AFTER=$(getfacl -pe "$CFG" 2>/dev/null | grep -E '^(user|group|mask|other):')
    if [[ "$GROUP_AFTER" == "$ALT_GROUP" && "$ENTRIES_BEFORE" == "$ENTRIES_AFTER" ]]; then
      ok "the real group move leaves the named entry, the mask and the effective read exactly as they were"
    else
      bad "a real group move leaves the ACL entries untouched" "group now ${GROUP_AFTER}, wanted ${ALT_GROUP}: $(diff <(printf '%s\n' "$ENTRIES_BEFORE") <(printf '%s\n' "$ENTRIES_AFTER"))"
    fi
  else
    echo "  skip  this runner belongs to only one group; there is no second group to move the fixture to"
  fi

  # 3. The negative control. Same fixture, a chmod instead of a chgrp. Read
  # the read bit off the mask:: line itself rather than the effective-rights
  # column getfacl prints beside it: that column's exact spacing is a
  # rendering detail of one getfacl build, and the mask's own starting value
  # depends on this runner's umask (644 or 664 both leave the group class
  # readable), so neither is a string to pin exactly. What has to be true
  # either way is the bit: readable in the mask before chmod 600, gone from
  # it after, since that is the named entry's read being masked out.
  reset
  setfacl -m u:daemon:r-- "$CFG"
  CTRL_BEFORE=$(getfacl -pe "$CFG" 2>/dev/null)
  MASK_BEFORE=$(printf '%s\n' "$CTRL_BEFORE" | sed -n 's/^mask::\([rwx-][rwx-][rwx-]\).*/\1/p')
  chmod 600 "$CFG"
  CTRL_AFTER=$(getfacl -pe "$CFG" 2>/dev/null)
  MASK_AFTER=$(printf '%s\n' "$CTRL_AFTER" | sed -n 's/^mask::\([rwx-][rwx-][rwx-]\).*/\1/p')
  if [[ "$CTRL_BEFORE" != "$CTRL_AFTER" \
        && "${MASK_BEFORE:0:1}" == r && "${MASK_AFTER:0:1}" != r ]]; then
    ok "control: a chmod on the same fixture recalculates the mask and drops the relay's effective read, so the two checks above are not vacuous"
  else
    bad "control: a chmod changes the mask and the effective read" "mask ${MASK_BEFORE:-<none>} -> ${MASK_AFTER:-<none>}: $(diff <(printf '%s\n' "$CTRL_BEFORE") <(printf '%s\n' "$CTRL_AFTER"))"
  fi
else
  echo "  skip  setfacl/getfacl are not usable on this runner, or this filesystem gave the fixture no mask:: line; the ACL rows cannot run here"
fi

# =====================================================================
echo
echo "The compose file's own ACL is named, not carried, when a patch replaces it (#545, #1295):"

# Both patches build the new file in root's own temporary directory and land
# it with the state helper's plant, which carries the owner, group and
# permission bits and not an ACL (#1295): carrying one meant chown, chmod and
# setfacl by name in the login's directory. A compose with named entries is
# still migrated, and the run says plainly that the ACL did not come across.
ACL_COMPOSE_USABLE=0
if command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1; then
  reset
  if setfacl -m u:daemon:r-- "$COMPOSE" 2>/dev/null \
     && getfacl -p "$COMPOSE" 2>/dev/null | grep -q '^mask::'; then
    ACL_COMPOSE_USABLE=1
  fi
fi
ACL_NOTE="had an ACL with named entries, and it was not carried over to the rewritten file"

if ((ACL_COMPOSE_USABLE)); then
  # The body patch: an old-shape compose with two named grants, migrated for
  # the first time. daemon and bin, so this runs on a bare CI image too.
  reset
  setfacl -m u:daemon:r-- -m u:bin:r-- "$COMPOSE"
  ACL_MODE_BEFORE=$(stat -c '%u %g %a' "$COMPOSE")
  run_migrate --apply
  if [[ $RC -eq 0 && "$OUT" == *"${COMPOSE} ${ACL_NOTE}"* && "$(stat -c '%u %g %a' "$COMPOSE")" == "$ACL_MODE_BEFORE" ]] \
     && grep -qE '^[[:space:]]*user:[[:space:]]*"997:997"' "$COMPOSE" && ! getfacl -p "$COMPOSE" 2>/dev/null | grep -q '^user:daemon:'; then
    ok "the body patch migrates a compose with named ACL entries, keeps its owner, group and mode, and says the ACL was not carried over"
  else
    bad "a compose with an ACL is migrated and the dropped ACL is named" "rc=$RC mode=$(stat -c '%u %g %a' "$COMPOSE") want $ACL_MODE_BEFORE: $(grep -i acl <<<"$OUT")"
  fi

  # The header patch: body already migrated, header staled by hand the way
  # the #438 fixture does it, then granted again.
  BODY_FOR_HEADER_TEST=$(body_of "$COMPOSE")
  {
    printf '# An older release rendered this header.\n'
    printf '%s\n' "$BODY_FOR_HEADER_TEST"
  } > "$COMPOSE.tmp" && mv "$COMPOSE.tmp" "$COMPOSE"
  setfacl -m u:daemon:r-- -m u:bin:r-- "$COMPOSE"
  ACL_MODE_BEFORE=$(stat -c '%u %g %a' "$COMPOSE")
  run_migrate --apply
  if [[ $RC -eq 0 && "$OUT" == *"${COMPOSE} ${ACL_NOTE}"* && "$(stat -c '%u %g %a' "$COMPOSE")" == "$ACL_MODE_BEFORE" ]] \
     && [[ "$(header_of "$COMPOSE")" == "$(fresh_header 997 997)" ]]; then
    ok "  and so does the header patch"
  else
    bad "the header patch names the ACL it did not carry" "rc=$RC mode=$(stat -c '%u %g %a' "$COMPOSE") want $ACL_MODE_BEFORE: $(grep -i acl <<<"$OUT")"
  fi
  # With a named entry, the mode's group bits are the ACL mask, not the
  # owning group's own permission. Group read-only plus a named user at
  # read-write reads as 664; the rewrite, which has no ACL, must land with
  # the group still read-only (644), never writable by the owning group.
  reset
  chmod 0644 "$COMPOSE"
  setfacl -m u:daemon:rw- "$COMPOSE"
  ACL_MASKED=$(stat -c '%a' "$COMPOSE")
  run_migrate --apply
  if [[ $RC -eq 0 && "$ACL_MASKED" == 664 && "$(stat -c '%a' "$COMPOSE")" == 644 ]] \
     && grep -qE '^[[:space:]]*user:[[:space:]]*"997:997"' "$COMPOSE"; then
    ok "  a named user at read-write over a read-only group: the rewrite lands 644, the owning group's own bits, not the mask's"
  else
    bad "the rewrite takes the owning group's bits, not the ACL mask" "rc=$RC before=$ACL_MASKED after=$(stat -c '%a' "$COMPOSE"), want 644"
  fi
  # The other direction: the owning group's own entry is wider than the mask.
  # Group rw-, mask r-- (set explicitly): the group could only read, so the
  # rewrite must land group read-only, never the group entry's rw.
  reset
  chmod 0664 "$COMPOSE"
  setfacl -m u:daemon:r-- -m m::r-- "$COMPOSE"
  GOBJ=$(getfacl -p --omit-header "$COMPOSE" 2>/dev/null | awk -F: '$1=="group" && $2=="" {split($3, a, /[ \t#]/); print a[1]; exit}')
  ACL_MASKED=$(stat -c '%a' "$COMPOSE")
  run_migrate --apply
  if [[ $RC -eq 0 && "$GOBJ" == rw- && "$ACL_MASKED" == 644 && "$(stat -c '%a' "$COMPOSE")" == 644 ]] \
     && grep -qE '^[[:space:]]*user:[[:space:]]*"997:997"' "$COMPOSE"; then
    ok "  an owning group at read-write under a read-only mask: the rewrite lands 644, the group's entry limited by the mask"
  else
    bad "the rewrite limits the owning group's entry by the ACL mask" "rc=$RC group_obj=$GOBJ before=$ACL_MASKED after=$(stat -c '%a' "$COMPOSE"), want 644"
  fi
else
  echo "  skip  setfacl/getfacl are not usable on this runner, or this filesystem gave the fixture no mask:: line; the compose-file ACL rows cannot run here"
fi
# The control: a compose with no named entries gets no such line.
reset
run_migrate --apply
if [[ $RC -eq 0 && "$OUT" != *"$ACL_NOTE"* ]]; then
  ok "  and a compose with no named entries gets no such line"
else
  bad "no ACL line for a compose without one" "rc=$RC: $(grep -i acl <<<"$OUT")"
fi

# =====================================================================
echo
echo "The backup --apply keeps is made by descriptor, never through a link (#1295):"
# The compose's directory is the login's. A `cp -a` by name there, as root,
# writes through a link planted at the backup's name, and copies a link
# planted at the compose's name instead of refusing it. The backup's name
# carries the second it was made in; a date on PATH that answers one fixed
# stamp lets a row plant the link at the exact name the run will use. The
# real state helper answers read and plant (the stand-in passes them on).
FIXED_STAMP=20990101-000000
cat > "$TMP/bin/date" <<EOF
#!/usr/bin/env bash
[[ "\${1:-}" == +%Y%m%d-%H%M%S ]] && { echo $FIXED_STAMP; exit 0; }
exec /usr/bin/date "\$@"
EOF
chmod +x "$TMP/bin/date"
FIXED_BAK="${COMPOSE}.${FIXED_STAMP}.bak"

# A link at the backup's name, on the body patch.
reset
printf 'not the compose\n' > "$TMP/outside-bak"; chmod 0600 "$TMP/outside-bak"
outside_before="$(md5sum < "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")"
old_compose="$(md5sum < "$COMPOSE")"
ln -s "$TMP/outside-bak" "$FIXED_BAK"
run_migrate --apply
if [[ $RC -eq 0 && "$(md5sum < "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")" == "$outside_before" \
      && -f "$FIXED_BAK" && ! -L "$FIXED_BAK" && "$(md5sum < "$FIXED_BAK")" == "$old_compose" ]]; then
  ok "a link planted at the backup's name: its target keeps its content and mode, and the name gets the compose as it was"
else
  bad "a link at the backup's name is replaced, not written through" \
      "rc=$RC outside=[$(cat "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")] link=$([[ -L "$FIXED_BAK" ]] && echo yes || echo no): $OUT"
fi

# The same on the header-only rewrite: a compose already in the new shape
# under an older release's header, where the backup is made further down.
reset
{
  printf '# The hardened node compose, from an older release.\n'
  render_template 997 997 | sed -n '/^name:/,$p'
} > "$COMPOSE"
printf 'not the compose\n' > "$TMP/outside-bak"; chmod 0600 "$TMP/outside-bak"
outside_before="$(md5sum < "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")"
old_compose="$(md5sum < "$COMPOSE")"
ln -s "$TMP/outside-bak" "$FIXED_BAK"
run_migrate --apply
if [[ $RC -eq 0 && "$OUT" == *"kept the previous deployment at ${FIXED_BAK}"* \
      && "$(md5sum < "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")" == "$outside_before" \
      && -f "$FIXED_BAK" && ! -L "$FIXED_BAK" && "$(md5sum < "$FIXED_BAK")" == "$old_compose" ]]; then
  ok "  and on the header-only rewrite: the target is left, and the name gets the compose as it was"
else
  bad "a link at the backup's name on the header rewrite is replaced, not written through or taken for a backup" \
      "rc=$RC outside=[$(cat "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")] link=$([[ -L "$FIXED_BAK" ]] && echo yes || echo no): $OUT"
fi

# A link at the compose's own name, to a copy of the old-shape compose, so the
# run gets as far as the backup. It is refused there: no backup, the link and
# its target as they were, and the store not handed over.
reset
mv "$COMPOSE" "$TMP/outside-compose"
ln -s "$TMP/outside-compose" "$COMPOSE"
outside_before="$(md5sum < "$TMP/outside-compose")"
run_migrate --apply
if [[ $RC -ne 0 && "$OUT" == *"could not be read safely"* && -L "$COMPOSE" \
      && "$(md5sum < "$TMP/outside-compose")" == "$outside_before" \
      && -z "$(find "$NODE_DIR" -maxdepth 1 -name 'docker-compose.yml.*.bak')" && ! -f "$TMP/state/chown-calls" ]]; then
  ok "a link at the compose's name is refused at the backup: nothing kept, nothing rewritten, the store not handed over"
else
  bad "a link at the compose's name is refused, not copied as a link" \
      "rc=$RC baks=[$(find "$NODE_DIR" -maxdepth 1 -name 'docker-compose.yml.*.bak' -printf '%y %p\n')] link=$([[ -L "$COMPOSE" ]] && echo yes || echo no): $OUT"
fi

# Everything the run reads out of the compose comes from one copy taken by
# descriptor, so the report (no --apply) refuses a link at the compose's name
# too, before it reads a line of what the link points at. The target here is
# a copy of the compose, so a read by name would go on and report.
reset
mv "$COMPOSE" "$TMP/outside-compose"
ln -s "$TMP/outside-compose" "$COMPOSE"
run_migrate
if [[ $RC -ne 0 && "$OUT" == *"could not be read safely"* && "$OUT" != *"What is already true"* ]]; then
  ok "  and the report refuses it too, before it reads anything out of it"
else
  bad "the report reads the compose by descriptor, never through a link" "rc=$RC: $(tail -5 <<<"$OUT")"
fi

# The rewrite used to be built beside the compose, in a temporary file named
# after it, and chowned, chmodded and setfacl'd by name before the rename: the
# login owns that directory and can swap the name for a link in between. A
# mktemp on PATH that answers such a template with a link it planted itself
# stands for that swap. The new file is built in root's own temporary
# directory now, so the link is never written or changed.
reset
printf 'not the compose\n' > "$TMP/outside-tmp"; chmod 0600 "$TMP/outside-tmp"
outside_before="$(md5sum < "$TMP/outside-tmp") $(stat -c %a "$TMP/outside-tmp")"
compose_mode_before="$(stat -c %a "$COMPOSE")"
cat > "$TMP/bin/mktemp" <<MKTEMP
#!/usr/bin/env bash
for a in "\$@"; do
  if [[ "\$a" == "$COMPOSE".XXXXXX ]]; then
    ln -sfn "$TMP/outside-tmp" "$COMPOSE.planted"; echo "$COMPOSE.planted"; exit 0
  fi
done
exec /usr/bin/mktemp "\$@"
MKTEMP
chmod +x "$TMP/bin/mktemp"
run_migrate --apply
rm -f "$TMP/bin/mktemp"
if [[ $RC -eq 0 && "$(md5sum < "$TMP/outside-tmp") $(stat -c %a "$TMP/outside-tmp")" == "$outside_before" \
      && ! -L "$COMPOSE" && "$(stat -c %a "$COMPOSE")" == "$compose_mode_before" ]] \
   && grep -qE '^[[:space:]]*user:[[:space:]]*"997:997"' "$COMPOSE"; then
  ok "a link at the old temporary name beside the compose is never written or chmodded, and the compose lands with its mode"
else
  bad "the rewrite is built in root's own directory, not beside the compose" \
      "rc=$RC outside=[$(head -c 60 "$TMP/outside-tmp") $(stat -c %a "$TMP/outside-tmp")]: $(tail -5 <<<"$OUT")"
fi

# The read-back itself: the state helper lands the rewrite and the file then
# gains a line before it is read back (the stand-in's plant-tamper). The run
# must see that what landed is not what it wrote, put the compose back from
# the bytes it read, and stop.
reset
compose_before="$(md5sum < "$COMPOSE") $(stat -c %a "$COMPOSE")"
printf '%s\n' "$COMPOSE" > "$TMP/state/plant-tamper"
run_migrate --apply
rm -f "$TMP/state/plant-tamper"
if [[ $RC -ne 0 && "$OUT" == *"did not read back as the rewrite wrote it"* && "$OUT" == *"put back from ${FIXED_BAK}: its bytes"* \
      && "$(md5sum < "$COMPOSE") $(stat -c %a "$COMPOSE")" == "$compose_before" && ! -f "$TMP/state/chown-calls" ]]; then
  ok "a rewrite that lands as anything but what was written is caught on the read-back, and the compose is put back"
else
  bad "the read-back compares what landed with what was written" "rc=$RC compose=[$(md5sum < "$COMPOSE") $(stat -c %a "$COMPOSE")] want [$compose_before]: $(tail -3 <<<"$OUT")"
fi

# A rewrite that does not read back as written is put back from the bytes root
# read, never from the backup's name: by then the login can have swapped that
# name for a link. No fixture makes a plant land something else, so a copy of
# the run, beside the real one, forces the read-back check to fail and swaps
# the backup's name for a link to an outside file just before. The refusal
# says what came back and what did not. The compose must come back byte for byte, with its
# mode, and the outside file must be left alone.
reset
printf 'not the compose\n' > "$TMP/outside-bak"; chmod 0600 "$TMP/outside-bak"
outside_before="$(md5sum < "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")"
compose_before="$(md5sum < "$COMPOSE") $(stat -c %a "$COMPOSE")"
SUT_RESTORE="$TMP/repo/scripts/migrate-node-forced-restore.sh"
python3 - "$SUT" "$SUT_RESTORE" "$TMP/outside-bak" <<'PY'
import shlex, sys
src, dst, outside = sys.argv[1:4]
s = open(src).read()
old = '    ok=1\n  fi\n  rm -f "$back" "$1"\n'
new = ('    ok=1\n  fi\n  ok=0; rm -f "$BACKUP"; ln -s %s "$BACKUP"\n'
       '  rm -f "$back" "$1"\n') % shlex.quote(outside)
if s.count(old) != 1:
    sys.exit("land_compose's read-back check was not found once in the copy; the forced-restore row would prove nothing")
open(dst, "w").write(s.replace(old, new))
PY
[[ -f "$SUT_RESTORE" ]] || { echo "the forced-restore copy was not made"; exit 1; }
OUT="$(bash "$SUT_RESTORE" --apply 2>&1)"; RC=$?
if [[ $RC -ne 0 && "$OUT" == *"put back from ${FIXED_BAK}: its bytes, owner, group and permission bits. Not put back: an ACL with named entries, and the file times"* \
      && "$(md5sum < "$COMPOSE") $(stat -c %a "$COMPOSE")" == "$compose_before" && ! -L "$COMPOSE" \
      && "$(md5sum < "$TMP/outside-bak") $(stat -c %a "$TMP/outside-bak")" == "$outside_before" ]]; then
  ok "a failed rewrite is put back from what root read: the compose byte for byte with its mode, and a link at the backup's name is never read"
else
  bad "a failed rewrite is put back from root's own copy, not through the backup's name" \
      "rc=$RC compose=[$(md5sum < "$COMPOSE") $(stat -c %a "$COMPOSE")] want [$compose_before] outside=[$(cat "$TMP/outside-bak")]: $OUT"
fi
rm -f "$SUT_RESTORE" "$TMP/bin/date"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
