#!/usr/bin/env bash
# Exercise three things scripts/install-advisord.sh does around who owns the
# Advisor's files: resolving that account correctly on a host already moved
# onto a dedicated one (#568), adopting files left behind by an account that
# no longer exists, and what it says when the unit does not stay up.
#
# What is being protected, from one host (aperire4, 2026-09-07). An uninstall
# that keeps the data removed the aperire-advisor account and left
# advisor/state/approve.token and credentials.json owned by uid 995 at mode
# 640. The reinstall put the Advisor back on the operator's account, chowned
# the state DIRECTORY and not its contents, and started the unit. advisord
# could not open its own token, crash-looped on "could not establish the
# service token: permission denied", and the installer's one-word `is-active`
# check died under set -e. What the operator saw was "install-advisord.sh did
# not finish", thirty seconds after the host had already written the answer
# into its own journal.
#
# Also being protected, from stock-node2 (2026-08-19, reintroduced on
# a lab host 2026-09-20, #568): a re-run of install-advisord.sh on a host
# install-advisor-account.sh had already moved onto its own account chowned
# the fleet trust file's group and five state directories to the invoking
# operator, because the block below decided the owner from SUDO_USER instead
# of the unit's own User=. Every fleet trust push then failed with a 403 the
# operator only meets three hops away, at a refused passkey.
#
# Five promises, each of which fails silently if it breaks:
#
#   1. A file whose owner or group no longer resolves is adopted before the
#      unit starts, and the run says how many and why.
#   2. A file owned by an account that EXISTS is left exactly alone. This is
#      the healthy fleet host, where aperire-advisor owns the state and the
#      service runs as it; an installer that "helpfully" chowned there would
#      undo the privilege boundary ADR 0007 exists for.
#   3. Owner and group are decided separately. approve.token is read by the
#      dashboard through a group the two accounts share, so rewriting a group
#      that still resolves would take that read away to fix an owner nobody
#      asked about.
#   4. A unit that does not stay up is reported with the unit's own last
#      journal line under it, not with a pointer to where the line lives.
#   5. On a host already moved onto a dedicated account, a re-run of this
#      installer touches no owner and no group it does not itself resolve
#      from the unit: the fleet trust file's group is left alone entirely,
#      and every chown names the unit's own account, never the operator.
#   6. advisor/state/reveal.window (#641) is planted root-owned, never onto
#      ADVISOR_OWNER_USER the way the token is, and, unlike the token, a
#      SECOND run replants it rather than leaving it at its first mtime: the
#      window is a clock, not a secret, and touching it again is the re-arm.
#
#   bash scripts/test-advisord-state-adoption.sh
#
# The three blocks are lifted out of the installer between their markers and
# run on their own: the rest of that file builds Go, asks docker what is
# running and writes a systemd unit, none of which these rows are about. A row
# asserts the lift found all three, so a marker that moves fails here rather
# than quietly testing nothing.
#
# Rows that chown need to look like root, and nothing here is privileged: the
# tree is a temporary directory and every program it reaches is a fake on
# PATH. fakeroot is enough and is tried first, the runner's passwordless sudo
# is the fallback, and already being root is the third.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIG="$REPO_DIR/scripts/install-advisord.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$ORIG" ]] || { echo "no install-advisord.sh at $ORIG"; exit 1; }

mkdir -p "$TMP/bin"

# ── How a row gets EUID 0 ───────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then ROOT_HOW=direct
elif command -v fakeroot >/dev/null 2>&1; then ROOT_HOW=fakeroot
elif sudo -n true 2>/dev/null; then ROOT_HOW=sudo
else
  echo "error: these rows chown files and read EUID. Install fakeroot, run as root," >&2
  echo "       or use a host where 'sudo -n true' succeeds." >&2
  exit 1
fi

# ── An account that has no passwd entry ─────────────────────────────
# Found, never assumed: a number picked out of the air is a real account on
# somebody's host, and the row would then assert the opposite of its name.
ORPHAN_ID=""
for u in $(seq 60000 60200); do
  getent passwd "$u" >/dev/null 2>&1 || getent group "$u" >/dev/null 2>&1 || { ORPHAN_ID="$u"; break; }
done
[[ -n "$ORPHAN_ID" ]] || { echo "no unused uid/gid in 60000-60200 on this host"; exit 1; }

# And one that does exist, to stand for the account the files legitimately
# belong to on a healthy host.
KEEP_USER="$(getent passwd 1 | cut -d: -f1)"
KEEP_GROUP="$(getent group 1 | cut -d: -f1)"
[[ -n "$KEEP_USER" && -n "$KEEP_GROUP" ]] || { echo "uid/gid 1 has no name on this host"; exit 1; }

# A second real account and a real group distinct from both of the above, to
# stand for the dedicated account and its shared group on a host
# install-advisor-account.sh has moved (#568). chown needs a name that
# actually resolves, fakeroot included, so this cannot be a literal string
# like "advisord" on a box with no such account.
MOVED_USER="$(getent passwd 2 | cut -d: -f1)"
MOVED_GROUP="$(getent group 3 | cut -d: -f1)"
[[ -n "$MOVED_USER" && -n "$MOVED_GROUP" ]] || { echo "uid 2 or gid 3 has no name on this host"; exit 1; }

# ── The two blocks, lifted between their markers ────────────────────
lift() { # $1 = marker name
  awk -v m="$1" '
    $0 ~ ("^# >>> " m " >>>$") {on=1; next}
    $0 ~ ("^# <<< " m " <<<$") {on=0}
    on {print}
  ' "$ORIG"
}
lift 'advisord state adoption' > "$TMP/adoption.sh"
lift 'advisord start report'   > "$TMP/start.sh"
lift 'advisord ownership'      > "$TMP/ownership.sh"

echo
echo "── the lift, before anything rests on it ──────────────────────────"
if grep -q 'adopt_orphaned_files()' "$TMP/adoption.sh" \
   && grep -qE 'adopt_orphaned_files "[^"]*advisor/state"' "$TMP/adoption.sh"
then ok "the adoption block was found, and it is the definition and the call"
else bad "the adoption block lifted" "$(wc -l < "$TMP/adoption.sh") lines"; fi
if grep -q 'journal_tail()' "$TMP/start.sh" && grep -q 'is-active' "$TMP/start.sh"
then ok "the start report was found, and it reads the unit and the journal"
else bad "the start report lifted" "$(wc -l < "$TMP/start.sh") lines"; fi
if grep -q 'TRUST_FILE=' "$TMP/ownership.sh" && grep -q 'ADOPT_GROUP=' "$TMP/ownership.sh"
then ok "the ownership block was found, token through the adopt-group resolution"
else bad "the ownership block lifted" "$(wc -l < "$TMP/ownership.sh") lines"; fi

# ── The fixture ─────────────────────────────────────────────────────
make_tree() {
  rm -rf "$TMP/tree"
  mkdir -p "$TMP/tree/advisor/state" "$TMP/tree/advisor/evidence" \
           "$TMP/tree/advisor/knowledge-fleet/base"
}

# One run of the adoption block over the fixture, as root, with the files a
# row has staged. Prints what the block printed; the row reads ownership back
# from inside the same fakeroot session, because that is the only place a
# faked chown is visible.
run_adoption() { # $1 = ADVISOR_OWNER_USER, $2 = ADOPT_GROUP, $3.. = staging lines
  local owner="$1" group="$2"; shift 2
  local stage="$*"
  local script="$TMP/run-adoption.sh"
  # set -euo pipefail below is the installer's own, so a guard the lifted
  # block is missing fails here rather than on a host: under set -e an
  # unguarded non-zero on a failure path ends the run before it has finished
  # saying what went wrong.
  cat > "$script" <<EOF
set -euo pipefail
REPO="$TMP/tree"
ADVISOR_OWNER_USER=$owner
ADOPT_GROUP=$group
# The adoption re-owns through \$REPO/scripts/state-file.py now (#703), never
# with find -exec chown, so the fixture tree needs the real one.
mkdir -p "\$REPO/scripts"
cp "$REPO_DIR/scripts/state-file.py" "\$REPO/scripts/"
# The installer loads and runs its siblings from beside itself (#764).
ADV_SELF="\$REPO/scripts"
$stage
. "$TMP/adoption.sh"
echo "---- ownership ----"
find "\$REPO/advisor" -type f -printf '%f %u:%g\n' 2>/dev/null | sort
EOF
  case "$ROOT_HOW" in
    direct)   bash "$script" 2>&1 ;;
    fakeroot) fakeroot bash "$script" 2>&1 ;;
    sudo)     sudo -n bash "$script" 2>&1 ;;
  esac
}

# One run of the ownership block (token, fleet trust, the state directories
# and ADOPT_GROUP's own resolution) over a fresh tree. $1 = moved (yes/no):
# whether ${UNIT}.before-account exists, which is the one thing that decides
# whether the block touches the trust file's group at all (#568).
run_ownership() { # $1 = moved yes|no, $2 = extra setup, run inside the fixture before the block, $3 = a report run after it
  local moved="$1" extra="${2:-}" report="${3:-}"
  rm -rf "$TMP/owntree"
  local unit="$TMP/owntree/aperire-advisord.service"
  local moved_setup="rm -f '$unit' '${unit}.before-account'"
  if [[ "$moved" == yes ]]; then
    moved_setup="printf '[Service]\nUser=%s\nGroup=%s\nSupplementaryGroups=%s\n' '$MOVED_USER' '$MOVED_USER' '$MOVED_GROUP' > '$unit'
: > '${unit}.before-account'"
  fi
  local script="$TMP/run-ownership.sh"
  cat > "$script" <<EOF
set -euo pipefail
mkdir -p "$TMP/owntree/dashboard/config"
printf 'peers: {}\n' > "$TMP/owntree/dashboard/config/fleet-trust.yaml"
chown $KEEP_USER:$KEEP_GROUP "$TMP/owntree/dashboard/config/fleet-trust.yaml"
$moved_setup
REPO="$TMP/owntree"
UNIT="$unit"
RUN_USER=$KEEP_USER
RUN_GROUP=\$(id -gn "\$RUN_USER")
# Set before the block in install-advisord.sh: 1 when the stack has the unit
# born on the Advisor's own account (#893). A row's extra setup may set it.
BORN=0
mkdir -p "\$REPO/advisor/state" "\$REPO/scripts"
# The plants in this block run through it (#661), and the block reads it from
# \$REPO/scripts, so the fixture tree needs the real one.
cp "$REPO_DIR/scripts/state-file.py" "\$REPO/scripts/"
# The installer loads and runs its siblings from beside itself (#764).
ADV_SELF="\$REPO/scripts"
$extra
. "$REPO_DIR/scripts/advisor-owner-lib.sh"
ADVISOR_OWNER_USER="\$(advisor_owner_user "\$UNIT" "\$RUN_USER")"
. "$TMP/ownership.sh"
echo "---- trust file ----"
stat -c '%U:%G' "\$REPO/dashboard/config/fleet-trust.yaml"
echo "---- state dir ----"
stat -c '%U' "\$REPO/advisor/state"
echo "---- report ----"
$report
EOF
  case "$ROOT_HOW" in
    direct)   bash "$script" 2>&1 ;;
    fakeroot) fakeroot bash "$script" 2>&1 ;;
    sudo)     sudo -n bash "$script" 2>&1 ;;
  esac
}

echo
echo "── the ownership block, on a host not yet moved ────────────────────"

RUN_GROUP_NAME="$(id -gn "$KEEP_USER")"
out="$(run_ownership no)"
if grep -A1 'trust file ----' <<<"$out" | tail -1 | grep -qx -e "$KEEP_USER:$RUN_GROUP_NAME"
then ok "on an unmoved host the trust file's group still follows RUN_GROUP, as before"
else bad "an unmoved host still chgrps the trust file" "$out"; fi
if grep -A1 'state dir ----' <<<"$out" | tail -1 | grep -qx -e "$KEEP_USER"
then ok "and the state directory belongs to RUN_USER, the account this host runs as"
else bad "an unmoved host's state directory belongs to RUN_USER" "$out"; fi

# #996: a unit born on the Advisor's own account. Nothing runs as RUN_USER,
# and the account step that follows sets the trust file's shape itself, so
# the dashboard keeps the group it reads the file through until then. The
# operator's group is made to differ from the file's here, so a regroup shows;
# the control row is the same host with the unit not born.
out="$(run_ownership no "RUN_GROUP=$MOVED_GROUP")"
if grep -A1 'trust file ----' <<<"$out" | tail -1 | grep -qx -e "$KEEP_USER:$MOVED_GROUP"
then ok "control: an unborn unit regroups the trust file to the operator's group"
else bad "control: an unborn unit follows RUN_GROUP" "$out"; fi
out="$(run_ownership no "RUN_GROUP=$MOVED_GROUP; BORN=1")"
if grep -A1 'trust file ----' <<<"$out" | tail -1 | grep -qx -e "$KEEP_USER:$KEEP_GROUP"
then ok "a unit born on the Advisor's account leaves the trust file's group alone for the account step (#996)"
else bad "a born unit does not regroup the trust file to RUN_GROUP" "$out"; fi

echo
echo "── the ownership block, on a host already moved (#568) ─────────────"

out="$(run_ownership yes)"
if grep -A1 'trust file ----' <<<"$out" | tail -1 | grep -qx -e "$KEEP_USER:$KEEP_GROUP"
then ok "a moved host's trust file group is left exactly as it was, not RUN_GROUP"
else bad "a moved host's trust file is untouched" "$out"; fi
if grep -A1 'state dir ----' <<<"$out" | tail -1 | grep -qx -e "$MOVED_USER"
then ok "and the state directory belongs to the unit's own account, not the operator running this script"
else bad "a moved host's state directory belongs to the resolved account" "$out"; fi

echo
echo "── nothing in the ownership block changes a file outside the tree (#879) ──"

# The block runs as root over names a service account can write: the trust
# file in dashboard/config, the five directories under advisor/ (both
# services write knowledge-fleet), and advisor/state itself. Each row puts a
# link, a second name, or a swap timed after the block's own check at one of
# those names, aimed at a file or directory outside the tree, and reads the
# outside one back in the same root session. Every row is the operator's
# group swapped for MOVED_GROUP, so a regroup that escapes shows as a group.
OUTSIDE="$TMP/outside"
report_of() { grep -A1 'report ----' <<<"$1" | tail -1; }
reset_outside() {
  rm -rf "$OUTSIDE"; mkdir -p "$OUTSIDE/dir"
}
# Stand-ins that swap the trust file for a link to the outside file at the
# moment root acts on it: chgrp for an installer that names it, python3 for
# one that hands it to the state helper. Either way the swap lands after the
# block's own -f, -L and grep, which is the window a by-name call leaves.
SWAPBIN="$TMP/swapbin"; mkdir -p "$SWAPBIN"
REAL_CHGRP="$(command -v chgrp)"; REAL_PY3="$(command -v python3)"
cat > "$SWAPBIN/chgrp" <<EOF
#!/usr/bin/env bash
if [[ -n "\${SWAP_AT:-}" && "\${*: -1}" == "\$SWAP_AT" && ! -L "\$SWAP_AT" ]]; then
  rm -f -- "\$SWAP_AT"; ln -s -- "\$SWAP_TO" "\$SWAP_AT"; echo swapped >> "\$SWAP_LOG"
fi
exec "$REAL_CHGRP" "\$@"
EOF
cat > "$SWAPBIN/python3" <<EOF
#!/usr/bin/env bash
if [[ -n "\${SWAP_AT:-}" && ! -L "\$SWAP_AT" ]]; then
  for a in "\$@"; do
    if [[ "\$a" == "\$SWAP_AT" ]]; then
      rm -f -- "\$SWAP_AT"; ln -s -- "\$SWAP_TO" "\$SWAP_AT"; echo swapped >> "\$SWAP_LOG"; break
    fi
  done
fi
exec "$REAL_PY3" "\$@"
EOF
chmod +x "$SWAPBIN"/*

# A second name: the trust file is a hard link to a peers-only file outside.
reset_outside
out="$(run_ownership no "RUN_GROUP=$MOVED_GROUP
printf 'peers: {}\n' > '$OUTSIDE/trust'
chown $KEEP_USER:$KEEP_GROUP '$OUTSIDE/trust'; chmod 0600 '$OUTSIDE/trust'
rm -f \"\$REPO/dashboard/config/fleet-trust.yaml\"
ln '$OUTSIDE/trust' \"\$REPO/dashboard/config/fleet-trust.yaml\"" \
  "stat -c '%G:%a' '$OUTSIDE/trust'")"
if [[ "$(report_of "$out")" == "$KEEP_GROUP:600" ]]
then ok "a trust file that is a second name for a file outside: the outside file keeps its group and mode"
else bad "a hard link at fleet-trust.yaml carries no regroup out of the tree" "$(report_of "$out") | $out"; fi
if grep -q 'fleet-trust.yaml was left as it was' <<<"$out"
then ok "  and the run says the trust file was left alone"
else bad "the refused trust file is named" "$out"; fi

# A swap after the block's check: a link put at the name at the moment root acts.
reset_outside
: > "$TMP/swap.log"
# Set inside the fixture, not handed in: a sudo fallback resets the
# environment the way real sudo does.
out="$(run_ownership no "RUN_GROUP=$MOVED_GROUP; PATH='$SWAPBIN':\$PATH; hash -r
export SWAP_AT='$TMP/owntree/dashboard/config/fleet-trust.yaml' SWAP_TO='$OUTSIDE/trust' SWAP_LOG='$TMP/swap.log'
printf 'peers: {}\n' > '$OUTSIDE/trust'
chown $KEEP_USER:$KEEP_GROUP '$OUTSIDE/trust'; chmod 0600 '$OUTSIDE/trust'" \
  "stat -c '%G:%a' '$OUTSIDE/trust'")"
if [[ "$(report_of "$out")" == "$KEEP_GROUP:600" ]]
then ok "a trust file swapped for a link after the check: the file it points at keeps its group and mode"
else bad "a swap at fleet-trust.yaml after the check carries nothing out of the tree" "$(report_of "$out") | $out"; fi
if grep -qx swapped "$TMP/swap.log"
then ok "  the swap really happened"
else bad "the swap at fleet-trust.yaml happened" "$(cat "$TMP/swap.log") | $out"; fi

# A link at knowledge-fleet/base, which the dashboard's account can write
# through the corpus's group, aimed at a directory outside.
reset_outside
out="$(run_ownership no "mkdir -p \"\$REPO/advisor/knowledge-fleet\"
ln -s '$OUTSIDE/dir' \"\$REPO/advisor/knowledge-fleet/base\"" \
  "stat -c '%U' '$OUTSIDE/dir'")"
if [[ "$(report_of "$out")" == root ]]
then ok "a link at knowledge-fleet/base: the directory it points at is not given to the Advisor's account"
else bad "a link at knowledge-fleet/base carries no chown out of the tree" "$(report_of "$out") | $out"; fi
if grep -q "left as they were" <<<"$out"
then ok "  and the run says a directory was left alone"
else bad "the refused directory is named" "$out"; fi
if grep -A1 'state dir ----' <<<"$out" | tail -1 | grep -qx -e "$KEEP_USER"
then ok "  while the directories that are real still go to the Advisor's account"
else bad "the real directories are still owned" "$out"; fi

# A second name inside advisor/state, which the Advisor's account owns, for
# a file outside. The token block re-owns that directory's entries when it
# mints a token.
reset_outside
out="$(run_ownership no "printf 'outside\n' > '$OUTSIDE/victim'
mkdir -p \"\$REPO/advisor/state\"
ln '$OUTSIDE/victim' \"\$REPO/advisor/state/linked\"" \
  "stat -c '%U' '$OUTSIDE/victim'")"
if [[ "$(report_of "$out")" == root ]]
then ok "a second name in advisor/state for a file outside: that file is not given to the Advisor's account"
else bad "a hard link in advisor/state carries no chown out of the tree" "$(report_of "$out") | $out"; fi
if grep -q "were left as they were" <<<"$out" && grep -q 'approve.token' <<<"$out"
then ok "  and the token is still minted, with the refusal named"
else bad "the token block carries on past the refused entry" "$out"; fi

echo
echo "── the reveal window (#641): root's own, replanted on every run ────"

# The same lifted ownership block plants advisor/state/reveal.window right
# beside the token, so this fixture already builds everything it needs. Two
# things matter and neither is the token's own rule: it is never
# ADVISOR_OWNER_USER (a program that account could run must not be able to
# open its own window), and unlike the token it is NOT a no-op on a re-run:
# touching it again IS the re-arm the Add an Advisor card's recovery copy
# promises.
run_reveal_twice() { # $1 = ADVISOR_OWNER_USER, $2 = ADOPT_GROUP-ish (RUN_USER for the unmoved case)
  rm -rf "$TMP/revealtree"
  local script="$TMP/run-reveal.sh"
  cat > "$script" <<EOF
set -euo pipefail
mkdir -p "$TMP/revealtree/dashboard/config"
printf 'peers: {}\n' > "$TMP/revealtree/dashboard/config/fleet-trust.yaml"
chown $KEEP_USER:$KEEP_GROUP "$TMP/revealtree/dashboard/config/fleet-trust.yaml"
rm -f "$TMP/revealtree/aperire-advisord.service" "$TMP/revealtree/aperire-advisord.service.before-account"
REPO="$TMP/revealtree"
UNIT="$TMP/revealtree/aperire-advisord.service"
RUN_USER=$KEEP_USER
RUN_GROUP=\$(id -gn "\$RUN_USER")
BORN=0
mkdir -p "\$REPO/advisor/state" "\$REPO/scripts"
cp "$REPO_DIR/scripts/state-file.py" "\$REPO/scripts/"
# The installer loads and runs its siblings from beside itself (#764).
ADV_SELF="\$REPO/scripts"
. "$REPO_DIR/scripts/advisor-owner-lib.sh"
ADVISOR_OWNER_USER="\$(advisor_owner_user "\$UNIT" "\$RUN_USER")"
. "$TMP/ownership.sh"
echo "---- first run ----"
stat -c '%U:%G:%a' "\$REPO/advisor/state/reveal.window"
FIRST_TOKEN="\$(cat "\$REPO/advisor/state/approve.token")"
# Push the marker's mtime into the past, standing for a window opened a
# long time ago, then run the SAME lifted block again, standing for the
# operator running the installer (or a re-arm) a second time.
touch -d '2000-01-01T00:00:00' "\$REPO/advisor/state/reveal.window"
. "$TMP/ownership.sh"
echo "---- second run ----"
stat -c '%U:%G:%a' "\$REPO/advisor/state/reveal.window"
stat -c '%Y' "\$REPO/advisor/state/reveal.window"
SECOND_TOKEN="\$(cat "\$REPO/advisor/state/approve.token")"
echo "---- token across both runs ----"
[[ "\$FIRST_TOKEN" == "\$SECOND_TOKEN" ]] && echo SAME || echo CHANGED
# Stand for ownership drifting away from root between two runs of this
# installer: the token block's own recursive chown when a token goes
# missing, or install-advisor-account.sh's move onto the dedicated account,
# both land on this same file. A plain truncate would leave that drift in
# place forever; \`install -o root\` must not.
chown $KEEP_USER "\$REPO/advisor/state/reveal.window"
. "$TMP/ownership.sh"
echo "---- third run, after drifting to a non-root owner ----"
stat -c '%U:%G:%a' "\$REPO/advisor/state/reveal.window"
EOF
  case "$ROOT_HOW" in
    direct)   bash "$script" 2>&1 ;;
    fakeroot) fakeroot bash "$script" 2>&1 ;;
    sudo)     sudo -n bash "$script" 2>&1 ;;
  esac
}

out="$(run_reveal_twice)"
first="$(grep -A1 'first run ----' <<<"$out" | tail -1)"
if [[ "$first" == "root:$RUN_GROUP_NAME:640" ]]
then ok "the window is planted root-owned, group-readable through the shared group, mode 640"
else bad "the reveal window's ownership, group and mode" "$out: expected root:$RUN_GROUP_NAME:640, got $first"; fi

second_stat="$(grep -A1 'second run ----' <<<"$out" | sed -n '2p')"
second_mtime="$(grep -A2 'second run ----' <<<"$out" | tail -1)"
past_epoch="$(date -d '2000-01-01T00:00:00' +%s)"
if [[ "$second_stat" == "root:$RUN_GROUP_NAME:640" ]]
then ok "and a second run keeps it root-owned, group-readable, mode 640"
else bad "the reveal window's ownership survives a second run" "$out"; fi
if [[ "$second_mtime" =~ ^[0-9]+$ ]] && (( second_mtime > past_epoch ))
then ok "a second run REPLANTS the window: its mtime moves forward past a window this old, unlike the token"
else bad "the reveal window is replanted on every run, not left at its old mtime" "$out"; fi
if grep -q '^SAME$' <<<"$out"
then ok "and the token itself is untouched across the second run: that block stays a no-op once the token exists"
else bad "the token stayed a no-op across a second run of the ownership block" "$out"; fi

third_stat="$(grep -A1 'third run, after drifting' <<<"$out" | tail -1)"
if [[ "$third_stat" == "root:$RUN_GROUP_NAME:640" ]]
then ok "and a run after the window drifted to a non-root owner puts it straight back to root"
else bad "the plant forces ownership back to root even after it drifted" "$out: expected root:$RUN_GROUP_NAME:640, got $third_stat"; fi

echo
echo "── files an account left behind ───────────────────────────────────"

# The failure itself: the token that stopped the service starting.
make_tree
out="$(run_adoption root root "
: > \$REPO/advisor/state/approve.token
: > \$REPO/advisor/state/credentials.json
chown $ORPHAN_ID:$ORPHAN_ID \$REPO/advisor/state/approve.token \$REPO/advisor/state/credentials.json
")"
if grep -q 'Adopted 2 file(s)' <<<"$out"
then ok "both files left by the removed account are adopted, and counted"
else bad "the orphaned files are adopted" "$out"; fi
if grep -q 'owned by an account that no longer exists' <<<"$out"
then ok "and the line says why they needed adopting"
else bad "the reason is named" "$out"; fi
if grep -q 'approve.token root:root' <<<"$out" && grep -q 'credentials.json root:root' <<<"$out"
then ok "and they belong to the account the unit runs as, which is what the service needed"
else bad "the files are chowned to the run user" "$out"; fi

# #568: on a host install-advisor-account.sh has already moved, an orphan must
# land on the DEDICATED account and the group it shares with the dashboard,
# never on the invoking operator: that is the same failure this fixture was
# built to catch, aimed at the group instead of the file's own owner.
make_tree
out="$(run_adoption "$MOVED_USER" "$MOVED_GROUP" "
: > \$REPO/advisor/state/approve.token
chown $ORPHAN_ID:$ORPHAN_ID \$REPO/advisor/state/approve.token
")"
if grep -q "approve.token $MOVED_USER:$MOVED_GROUP" <<<"$out"
then ok "on a moved host, an orphan is adopted onto the dedicated account and its shared group"
else bad "a moved host adopts onto the resolved account, not root" "$out"; fi
if grep -q "They now belong to $MOVED_USER:$MOVED_GROUP" <<<"$out"
then ok "and the line names that account, not the operator who ran this script"
else bad "the adoption line names the resolved account" "$out"; fi

# The healthy fleet host, and the row that stops this being a chown -R.
make_tree
out="$(run_adoption root root "
: > \$REPO/advisor/state/approve.token
chown $KEEP_USER:$KEEP_GROUP \$REPO/advisor/state/approve.token
")"
if grep -q "approve.token $KEEP_USER:$KEEP_GROUP" <<<"$out"
then ok "a file owned by an account that exists is left exactly as it is"
else bad "an existing account's file is untouched" "$out"; fi
if ! grep -q 'Adopted' <<<"$out"
then ok "and nothing is said, because nothing happened"
else bad "a healthy host is silent" "$out"; fi

# The two beside each other, which is the case a recursive chown would get
# wrong while every row above still passed: one orphan is enough to make the
# block act, and the file next to it must come through untouched.
make_tree
out="$(run_adoption root root "
: > \$REPO/advisor/state/approve.token
: > \$REPO/advisor/state/model.json
chown $ORPHAN_ID:$ORPHAN_ID \$REPO/advisor/state/approve.token
chown $KEEP_USER:$KEEP_GROUP \$REPO/advisor/state/model.json
")"
if grep -q 'Adopted 1 file(s)' <<<"$out" \
   && grep -q "model.json $KEEP_USER:$KEEP_GROUP" <<<"$out" \
   && grep -q 'approve.token root:root' <<<"$out"
then ok "one orphan beside a file that is fine adopts the orphan and only the orphan"
else bad "adoption is not a recursive chown" "$out"; fi

# Owner and group are separate questions. Only the group is orphaned here, and
# the owner is an account that still exists.
make_tree
out="$(run_adoption root root "
: > \$REPO/advisor/state/approve.token
chown $KEEP_USER:$ORPHAN_ID \$REPO/advisor/state/approve.token
")"
if grep -q "approve.token $KEEP_USER:root" <<<"$out"
then ok "an orphaned group is replaced and the owner beside it is kept"
else bad "owner and group are decided separately" "$out"; fi

# The reverse, so the row above is not passing on a coincidence.
make_tree
out="$(run_adoption root root "
: > \$REPO/advisor/state/approve.token
chown $ORPHAN_ID:$KEEP_GROUP \$REPO/advisor/state/approve.token
")"
if grep -q "approve.token root:$KEEP_GROUP" <<<"$out"
then ok "and an orphaned owner is replaced with the group beside it kept"
else bad "the group is kept when only the owner is orphaned" "$out"; fi

# Every other directory the block names may legitimately not be there yet.
make_tree
rm -rf "$TMP/tree/advisor/evidence" "$TMP/tree/advisor/knowledge-fleet"
out="$(run_adoption root root "
: > \$REPO/advisor/state/approve.token
chown $ORPHAN_ID:$ORPHAN_ID \$REPO/advisor/state/approve.token
")"
if grep -q 'Adopted 1 file(s)' <<<"$out" && ! grep -qi 'No such file' <<<"$out"
then ok "a directory that is not there yet is skipped, not complained about"
else bad "missing directories are skipped" "$out"; fi

echo
echo "── what a unit that will not stay up says ─────────────────────────"

# systemctl and journalctl, both answering from files a row writes.
# NRestarts climbs on every read while state/climbing is there, which is what
# a unit in a restart loop does between two reads two seconds apart. A fake
# that answered the same number twice would report a crash loop as settled,
# and the row named for that case would pass on the wrong reason.
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
case "\$*" in
  *is-active*) cat "$TMP/state/active" 2>/dev/null || echo unknown ;;
  *NRestarts*)
    n="\$(cat "$TMP/state/restarts" 2>/dev/null || echo 0)"
    echo "\$n"
    [[ -f "$TMP/state/climbing" ]] && echo "\$(( n + 1 ))" > "$TMP/state/restarts"
    ;;
esac
exit 0
EOF
# Exits non-zero when there is nothing to read, the way journalctl does on a
# host whose journal this account cannot open. That is a failure ON the
# failure path, which is where an unguarded command substitution under set -e
# would cut the explanation in half.
cat > "$TMP/bin/journalctl" <<EOF
#!/usr/bin/env bash
[[ -s "$TMP/state/journal" ]] || exit 1
cat "$TMP/state/journal"
EOF
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
[[ "\$(cat "$TMP/state/answers" 2>/dev/null)" == yes ]] || exit 22
echo '{}'
EOF
chmod +x "$TMP/bin/"*
mkdir -p "$TMP/state"

run_start() { # the fixture's state files decide the outcome
  local script="$TMP/run-start.sh"
  cat > "$script" <<EOF
set -euo pipefail
UNIT_NAME=aperire-advisord
ADVISOR_PORT=7810
TOKEN="$TMP/state/token"
. "$TMP/start.sh"
EOF
  case "$ROOT_HOW" in
    direct)   ( PATH="$TMP/bin:$PATH" bash "$script" 2>&1 ) ;;
    fakeroot) ( PATH="$TMP/bin:$PATH" fakeroot bash "$script" 2>&1 ) ;;
    sudo)     ( sudo -n env PATH="$TMP/bin:$PATH" bash "$script" 2>&1 ) ;;
  esac
}

printf 'tok\n' > "$TMP/state/token"
JOURNAL='could not establish the service token: open /home-of-the-install/advisor/state/approve.token: permission denied'

# The host this was written for.
printf 'activating\n' > "$TMP/state/active"
printf '4\n'          > "$TMP/state/restarts"
printf '%s\n' "$JOURNAL" > "$TMP/state/journal"
printf 'no\n'         > "$TMP/state/answers"
out="$(run_start)"; rc=$?
if [[ $rc -ne 0 ]]; then ok "a unit that is only ever 'activating' fails the install"
else bad "activating is a failure" "exit $rc: $out"; fi
if grep -q 'permission denied' <<<"$out"
then ok "and the operator is shown the unit's own last journal line, not told where to find it"
else bad "the journal line is printed" "$out"; fi
if grep -q "is 'activating'" <<<"$out"
then ok "with the state that was actually read beside it"
else bad "the state is named" "$out"; fi

# The crash caught in its up moment: the loop happens to be between two
# crashes when is-active is read, so a single reading calls this healthy.
printf 'active\n' > "$TMP/state/active"
printf '9\n'      > "$TMP/state/restarts"
: > "$TMP/state/climbing"
out="$(run_start)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'restarted 1 time' <<<"$out"
then ok "a unit that reads 'active' while its restart counter climbs is still a failure"
else bad "a climbing restart counter is a failure" "exit $rc: $out"; fi

# Up, and silent. Everything is installed; what is refused is the claim.
rm -f "$TMP/state/climbing"
printf '0\n'  > "$TMP/state/restarts"
printf 'no\n' > "$TMP/state/answers"
out="$(run_start)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q '/v1/status did not answer' <<<"$out" && grep -q 'permission denied' <<<"$out"
then ok "a service that is up and does not answer is refused, with the journal line too"
else bad "the answer check prints the journal" "exit $rc: $out"; fi

# A host whose journal has nothing to say. This is where set -e bites: the
# report is the failure path, so a read that comes back empty must not end the
# run before it has printed where to look.
printf 'failed\n' > "$TMP/state/active"
printf '0\n'      > "$TMP/state/restarts"
rm -f "$TMP/state/journal"
out="$(run_start)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'journalctl -u aperire-advisord -n 30' <<<"$out"
then ok "a journal with nothing in it still leaves the operator the command to read more"
else bad "an empty journal does not cut the report short" "exit $rc: $out"; fi
if ! grep -q 'its last journal line' <<<"$out"
then ok "and no empty 'its last journal line:' is printed over nothing"
else bad "no heading over an absent line" "$out"; fi

# The control. Without it every row above passes on a script that always fails.
printf 'active\n' > "$TMP/state/active"
printf '%s\n' "$JOURNAL" > "$TMP/state/journal"
printf 'yes\n' > "$TMP/state/answers"
out="$(run_start)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '/v1/status OK' <<<"$out"
then ok "and a service that is up and answering passes, quietly"
else bad "a healthy start passes" "exit $rc: $out"; fi
if ! grep -q 'journal line' <<<"$out"
then ok "with no journal noise on a host where nothing went wrong"
else bad "a healthy start is quiet" "$out"; fi

echo
echo "── minting the approval token cannot be aimed somewhere else (#652) ─"

# The token block runs when [[ ! -f "$TOKEN" ]], and a DANGLING symlink at
# that name satisfies exactly that: -f follows the link and finds nothing.
# advisor/state belongs to the Advisor's own account on a moved host, so that
# account can leave one there and wait for the next install. A plain
# `> "$TOKEN"` then writes a freshly minted shared secret straight into the
# file the link names, and the old chmod set it 0640 afterwards for good
# measure.
victim="$TMP/owntree-victim"
rm -f "$victim"
out=$(run_ownership no "ln -s '$victim' \"\$REPO/advisor/state/approve.token\"")
if [[ ! -e "$victim" ]]; then
  ok "a dangling link at approve.token gets no secret written through it"
else
  bad "the mint never follows a dangling link" "$victim exists: $(head -c 40 "$victim" 2>/dev/null)"
fi
tokpath="$TMP/owntree/advisor/state/approve.token"
if [[ -f "$tokpath" && ! -L "$tokpath" ]]; then
  ok "and an ordinary file sits at that name afterwards, not the link"
else
  bad "the link is replaced by a regular token" "$(ls -la "$tokpath" 2>/dev/null)"
fi
if [[ -s "$tokpath" ]]; then
  ok "with a real token in it, so the install is not merely refusing to work"
else
  bad "the minted token has content" "$(ls -la "$tokpath" 2>/dev/null); $out"
fi
if [[ "$(stat -c '%a' "$tokpath" 2>/dev/null)" == "640" ]]; then
  ok "at 0640, set by the same call that created it rather than a chmod after"
else
  bad "the minted token is 0640" "$(stat -c '%a' "$tokpath" 2>/dev/null)"
fi

echo
echo "── the build stamp this installer's own builds carry (#650) ────────"

# Both builds here used to carry no -ldflags at all, so main.version kept its
# compiled-in "dev" and a freshly installed node reported that literal string
# from GET /v1/status forever. The dashboard sanitizes "dev" to null on
# purpose, so the Add an Advisor row read "not measured" on a node that had
# just been installed perfectly, and stayed that way until that node's first
# ordinary update rebuilt advisord through get-aperire.sh's stamped step
# instead. The two paths are different scripts; only one of them stamped.
#
# The resolution block is lifted and run the same way the two blocks above
# are, so these rows read the shipped lines rather than a copy of them.
lift 'advisord build stamp' > "$TMP/stamp.sh"
if [[ -s "$TMP/stamp.sh" ]]
then ok "the build-stamp block was found between its markers"
else bad "the build-stamp block is where this test expects it" "lift matched nothing"; fi

stamp() { # $1 = APERIRE_BUILD_COMMIT ("" for unset), $2 = .release commit ("" for no file)
  local env_ref="$1" rel="$2" d="$TMP/stamptree"
  rm -rf "$d"; mkdir -p "$d"
  [[ -z "$rel" ]] || printf '{\n  "tag": "",\n  "commit": "%s",\n  "sha256": ""\n}\n' "$rel" > "$d/.release"
  ( set -euo pipefail
    # Both are read by the lifted block, which shellcheck cannot see into.
    # shellcheck disable=SC2034
    REPO="$d"
    # An empty value must behave as unset, not as a ref, which is what a
    # caller that exports the variable off an empty installed_commit() does.
    # shellcheck disable=SC2034
    if [[ -n "$env_ref" ]]; then APERIRE_BUILD_COMMIT="$env_ref"; fi
    # shellcheck disable=SC1090,SC1091
    . "$TMP/stamp.sh"
    printf '%s|%s\n' "$BUILD_COMMIT" "$BUILD_LDFLAGS"
  )
}

# The ordinary fresh-install path: get-aperire.sh exports this into install.sh's
# environment off its own installed_commit(), and install.sh runs the stack in
# the same environment.
got="$(stamp 3f9ab12 '')"
if [[ "$got" == '3f9ab12|-s -w -X main.version=3f9ab12' ]]
then ok "APERIRE_BUILD_COMMIT reaches the linker flags, so a fresh install is stamped"
else bad "the environment's ref is stamped" "$got"; fi

# The Advisor's own one-liner sets no environment at all. .release is the only
# thing on that path that knows which release this tree is.
got="$(stamp '' 8c4d0e7f9a1b)"
if [[ "$got" == '8c4d0e7f9a1b|-s -w -X main.version=8c4d0e7f9a1b' ]]
then ok "with no environment, the ref comes off .release, which the attach path has"
else bad ".release is the fallback ref" "$got"; fi

got="$(stamp 3f9ab12 8c4d0e7f9a1b)"
if [[ "${got%%|*}" == '3f9ab12' ]]
then ok "and the caller that knows most wins: the environment beats the file"
else bad "the environment takes precedence" "$got"; fi

# Nothing to go on is "dev", which is the honest answer and the one the
# dashboard already reads as "not stamped". Never an invented ref.
got="$(stamp '' '')"
if [[ "$got" == 'dev|-s -w -X main.version=dev' ]]
then ok "a tree with no ref anywhere stays dev rather than inventing one"
else bad "no ref means dev" "$got"; fi

# The shape check, which is not cosmetic. This build runs as root and Go
# splits -ldflags into words, so a ref carrying linker options would run a
# program of the ref-writer's choosing with root's privileges. Every one of
# these must come back "dev".
while IFS= read -r hostile; do
  [[ -n "$hostile" ]] || continue
  got="$(stamp "$hostile" '')"
  if [[ "${got%%|*}" == 'dev' ]]
  then ok "refused back to dev: ${hostile:0:46}"
  else bad "a ref that is not a plain hex commit is refused" "$hostile -> $got"; fi
done <<'HOSTILE'
3f9ab12 -linkmode=external -extldflags=-Wl,-rpath,/tmp
-X main.version=x -X crypto.disabled=1
3f9ab12; touch /tmp/aperire-stamp-pwned
$(touch /tmp/aperire-stamp-pwned)
../../etc/passwd
3f9ab
DEADBEEF
v3.4.1
dev
HOSTILE

# And the resolution is actually USED. The rows above would all pass on a
# script that computed BUILD_LDFLAGS perfectly and then built without it,
# which is precisely the bug: the value existed nowhere and the build said
# nothing about it.
for cmd in aperire-advisord aperire-executor; do
  # The binary is built through build_as_user (as the operator, #1136), whose
  # one go build line carries the flags for all three.
  if grep -qE "^build_as_user $cmd \./cmd/$cmd( |\$)" "$ORIG" \
     && grep -qF "build -ldflags \"\$BUILD_LDFLAGS\" -o" "$ORIG"
  then ok "$cmd is built with those flags, not without them"
  else bad "$cmd's build carries -ldflags" "$(grep -n "cmd/$cmd\b" "$ORIG")"; fi
done

echo
printf '  %d passed, %d failed  (root via %s)\n\n' "$PASS" "$FAIL" "$ROOT_HOW"
[[ $FAIL -eq 0 ]]
