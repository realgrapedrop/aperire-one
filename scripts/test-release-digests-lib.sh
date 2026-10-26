#!/usr/bin/env bash
# Exercise scripts/release-digests-lib.sh: root copies only the bytes the
# release shipped (ADR 0024, lane 2).
#
#   bash scripts/test-release-digests-lib.sh
#
# Every refusal row has its opposite beside it, because "nothing was copied"
# is also what a broken function proves. The race row has a positive control:
# the same racer against a check-then-copy that reads the file twice, which
# has to land the wrong bytes at least once, or the racer proves nothing.
#
# Runs unprivileged in a temporary directory. `install` is faked on PATH
# (the real one refuses -o root to an ordinary account); everything else is
# the real tool.

set -uo pipefail
# Root copies refuse a directory anyone but its owner can write, as they
# would on a host, so the fixture is made the way a host is: 022.
umask 022

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$REPO_DIR/scripts/release-digests-lib.sh"
GET="$REPO_DIR/scripts/get-aperire.sh"
TMP=$(mktemp -d)
RACER_PID=""
cleanup() {
  [[ -n "$RACER_PID" ]] && kill "$RACER_PID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$LIB" ]] || { echo "no release-digests-lib.sh at $LIB"; exit 1; }

mkdir -p "$TMP/bin" "$TMP/tree/scripts" "$TMP/dest"
cat > "$TMP/bin/install" <<'EOF'
#!/usr/bin/env bash
mode="" dir=0
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m) mode="$2"; shift 2 ;;
    -o|-g) shift 2 ;;
    -d) dir=1; shift ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ $dir -eq 1 ]]; then mkdir -p -- "${args[@]}"; exit; fi
cp -- "${args[0]}" "${args[1]}" || exit 1
[[ -z "$mode" ]] || chmod "$mode" "${args[1]}"
EOF
chmod +x "$TMP/bin/install"
# Every copy also makes the trusted-path check (trusted-path-lib.sh, loaded
# beside this library), which reads the service accounts from systemd. The
# fixture's are the ones a row writes into $TMP/units.list, never the host's:
# a dashboard on this login would otherwise refuse every destination here.
cat > "$TMP/bin/systemctl" <<SHIM
#!/usr/bin/env bash
case "\${1:-}" in
  list-unit-files) cat "$TMP/units.list" 2>/dev/null; exit 0 ;;
  show)
    unit="\$2"; prop=""; shift 2
    while [[ \$# -gt 0 ]]; do case "\$1" in -p) prop="\$2"; shift 2 ;; *) shift ;; esac; done
    cat "$TMP/units.\$unit.\$prop" 2>/dev/null; exit 0 ;;
esac
exit 0
SHIM
chmod +x "$TMP/bin/systemctl"
export PATH="$TMP/bin:$PATH"

DIGESTS="$TMP/release.sha256"
write_record() { # rel... ; digests of the tree as it stands now
  local rel
  {
    printf '# Aperire One release digests\n# anchor sha256 feedface, a fixture\n'
    for rel in "$@"; do
      printf '%s  %s\n' "$(sha256sum < "$TMP/tree/$rel" | cut -c1-64)" "$rel"
    done
  } > "$DIGESTS"
  chmod 0644 "$DIGESTS"
}

# Each call in its own shell, so the record is read fresh, the way every
# installer run and every rd_priv call reads it.
run_install() { # tree rel dest mode ; sets OUT (stdout), ERR, RC
  local e="$TMP/err"
  OUT="$(APERIRE_RELEASE_DIGESTS="$DIGESTS" bash -c '. "$1"; shift; rd_install "$@"' _ "$LIB" "$@" 2>"$e")"; RC=$?
  ERR="$(cat "$e")"
}

echo
echo "release-digests-lib.sh, root copies only what the release shipped"
echo

# ── 0. one body, two copies ─────────────────────────────────────────
# get-aperire.sh carries the block inline because it cannot source anything
# out of the tree it is about to check. The two must be the same bytes.
block_of() { sed -n '/^# >>> release digests >>>$/,/^# <<< release digests <<<$/p' "$1"; }
if [[ -n "$(block_of "$LIB")" && "$(block_of "$LIB")" == "$(block_of "$GET")" ]]; then
  ok "get-aperire.sh carries the library's block byte for byte"
else
  bad "the inline block in get-aperire.sh matches the library" \
      "$(diff <(block_of "$LIB") <(block_of "$GET") | head -20)"
fi

# ── 1. the bytes match ──────────────────────────────────────────────
printf 'the release sealer\n' > "$TMP/tree/scripts/sealer.sh"
printf 'the release helper\n' > "$TMP/tree/scripts/helper.py"
write_record scripts/sealer.sh scripts/helper.py
run_install "$TMP/tree" scripts/sealer.sh "$TMP/dest/aperire-sealer" 0755
if [[ $RC -eq 0 && "$OUT" == placed && "$(cat "$TMP/dest/aperire-sealer")" == "the release sealer" ]] \
   && [[ "$(stat -c %a "$TMP/dest/aperire-sealer")" == 755 ]]; then
  ok "a file whose bytes match the record is placed, with the mode asked for"
else
  bad "a matching file is placed" "rc=$RC out=$OUT err=$ERR"
fi
ino="$(stat -c %i "$TMP/dest/aperire-sealer")"
run_install "$TMP/tree" scripts/sealer.sh "$TMP/dest/aperire-sealer" 0755
if [[ $RC -eq 0 && "$OUT" == same && "$(stat -c %i "$TMP/dest/aperire-sealer")" == "$ino" ]]; then
  ok "and a second run finds the same bytes and touches nothing"
else
  bad "a current copy is left alone" "rc=$RC out=$OUT"
fi
if [[ -z "$(find "$TMP/dest" -name '.*')" ]]; then
  ok "no staging file is left beside the destination"
else
  bad "staging files are cleaned up" "$(find "$TMP/dest" -name '.*')"
fi

# ── 2. the bytes differ ─────────────────────────────────────────────
printf 'a sealer somebody rewrote\n' > "$TMP/tree/scripts/sealer.sh"
run_install "$TMP/tree" scripts/sealer.sh "$TMP/dest/aperire-sealer" 0755
want="$(awk '$2 == "scripts/sealer.sh" { print $1 }' "$DIGESTS")"
got="$(sha256sum < "$TMP/tree/scripts/sealer.sh" | cut -c1-64)"
if [[ $RC -eq 1 && -z "$OUT" && "$(cat "$TMP/dest/aperire-sealer")" == "the release sealer" ]]; then
  ok "a file that changed after the record was taken is refused, and the root copy stays"
else
  bad "a changed file is refused" "rc=$RC out=$OUT dest=$(cat "$TMP/dest/aperire-sealer") err=$ERR"
fi
if grep -q 'refused: scripts/sealer.sh is not the file this release shipped' <<<"$ERR" \
   && grep -q "release  $want" <<<"$ERR" && grep -q "tree     $got" <<<"$ERR" \
   && grep -q 'anchor\|feedface' <<<"$ERR" && grep -q 'left exactly as it was' <<<"$ERR"; then
  ok "and the refusal names the file, both digests and the record's anchor"
else
  bad "the refusal says what and why" "$ERR"
fi
# Same row with no copy there yet: a first install refuses too, and leaves
# nothing at the destination.
run_install "$TMP/tree" scripts/sealer.sh "$TMP/dest/fresh-sealer" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/fresh-sealer" ]]; then
  ok "a first install of a changed file places nothing at all"
else
  bad "a refused first install leaves no file" "rc=$RC $(ls "$TMP/dest")"
fi
printf 'the release sealer\n' > "$TMP/tree/scripts/sealer.sh"

# ── 3. no entry for the file ────────────────────────────────────────
printf 'something the release never carried\n' > "$TMP/tree/scripts/extra.sh"
run_install "$TMP/tree" scripts/extra.sh "$TMP/dest/aperire-extra" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-extra" ]] \
   && grep -q 'not a file this release shipped: the release digests have no entry for it' <<<"$ERR"; then
  ok "a file the record has no entry for is refused, not waved through"
else
  bad "a missing entry refuses" "rc=$RC err=$ERR"
fi

# ── 4. no record on this host ───────────────────────────────────────
mv "$DIGESTS" "$DIGESTS.aside"
run_install "$TMP/tree" scripts/extra.sh "$TMP/dest/aperire-extra" 0755
if [[ $RC -eq 0 && "$OUT" == placed ]] \
   && grep -q 'unchecked: scripts/extra.sh (no release digests on this host' <<<"$ERR"; then
  ok "with no record at all it copies from the one read and says the file was unchecked"
else
  bad "the no-record fallback copies and says so" "rc=$RC out=$OUT err=$ERR"
fi
mv "$DIGESTS.aside" "$DIGESTS"

# ── 5. a record that cannot be trusted ──────────────────────────────
# Never read as "no record": that would let whoever can break the record
# switch the check off.
check_bad_record() { # label
  run_install "$TMP/tree" scripts/helper.py "$TMP/dest/aperire-helper" 0755
  if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-helper" ]] && grep -q 'refused' <<<"$ERR"; then
    ok "$1: every copy is refused"
  else
    bad "$1 refuses" "rc=$RC out=$OUT err=$ERR"
  fi
  rm -f "$TMP/dest/aperire-helper"
}
chmod 0664 "$DIGESTS"; check_bad_record "a group-writable record"; chmod 0644 "$DIGESTS"
mv "$DIGESTS" "$DIGESTS.real"; ln -s "$DIGESTS.real" "$DIGESTS"
check_bad_record "a record that is a symlink"
rm -f "$DIGESTS"; mv "$DIGESTS.real" "$DIGESTS"
cp "$DIGESTS" "$DIGESTS.good"
printf 'not a digest  scripts/helper.py\n' >> "$DIGESTS"
check_bad_record "a record with a line that is not a digest"
cp "$DIGESTS.good" "$DIGESTS"
printf '# anchor nothing\n' > "$DIGESTS"
check_bad_record "a record that names no file"
cp "$DIGESTS.good" "$DIGESTS"
run_install "$TMP/tree" scripts/helper.py "$TMP/dest/aperire-helper" 0755
if [[ $RC -eq 0 && "$OUT" == placed ]]; then
  ok "and the same copy goes through once the record is put right"
else
  bad "a good record copies" "rc=$RC err=$ERR"
fi

# ── 6. what the path names ──────────────────────────────────────────
# A symlink in the tree is refused even with no record: with no digest to
# catch it, a link to /etc/shadow would otherwise be copied out world-readable.
ln -s "$TMP/tree/scripts/sealer.sh" "$TMP/tree/scripts/linked.sh"
mv "$DIGESTS" "$DIGESTS.aside"
run_install "$TMP/tree" scripts/linked.sh "$TMP/dest/aperire-linked" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-linked" ]] && grep -q 'is a symlink' <<<"$ERR"; then
  ok "a symlink in the tree is refused, record or no record"
else
  bad "a symlinked tree file refuses" "rc=$RC err=$ERR"
fi
mkdir -p "$TMP/elsewhere/scripts"
printf 'the release sealer\n' > "$TMP/elsewhere/scripts/sealer.sh"
mkdir -p "$TMP/tree2"; ln -s "$TMP/elsewhere/scripts" "$TMP/tree2/scripts"
run_install "$TMP/tree2" scripts/sealer.sh "$TMP/dest/aperire-via" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-via" ]]; then
  ok "and so is a directory in the path swapped for a symlink"
else
  bad "a symlinked directory in the path refuses" "rc=$RC err=$ERR"
fi
mv "$DIGESTS.aside" "$DIGESTS"
for rel in ../tree/scripts/sealer.sh /etc/passwd scripts/./sealer.sh 'scripts//sealer.sh'; do
  run_install "$TMP/tree" "$rel" "$TMP/dest/aperire-rel" 0755
  if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-rel" ]]; then
    ok "a path spelled '$rel' is refused before anything is opened"
  else
    bad "'$rel' refuses" "rc=$RC err=$ERR"
  fi
done
# Both with an entry in the record, so it is the read that refuses them and
# not the missing entry. The walk opens each component O_PATH, which never
# blocks on a FIFO, and refuses anything that is not a regular file before
# it is opened for reading.
cp "$DIGESTS" "$TMP/digests.before-fifo"
printf '%064d  scripts/fifo.sh\n%064d  scripts/huge.sh\n' 0 0 >> "$DIGESTS"
mkfifo "$TMP/tree/scripts/fifo.sh"
# shellcheck disable=SC2016  # the inner shell's own arguments
OUT="$(APERIRE_RELEASE_DIGESTS="$DIGESTS" timeout 20 bash -c '. "$1"; RD_READ_TIMEOUT=2; rd_install "$2" scripts/fifo.sh "$3" 0755' _ "$LIB" "$TMP/tree" "$TMP/dest/aperire-fifo" 2>"$TMP/err")"; RC=$?
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-fifo" ]] && grep -q 'is not a regular file' "$TMP/err"; then
  ok "a FIFO in the tree is refused at once, not a hung update"
else
  bad "a FIFO refuses within the bound" "rc=$RC $(cat "$TMP/err")"
fi
head -c 17000000 /dev/zero > "$TMP/tree/scripts/huge.sh"
run_install "$TMP/tree" scripts/huge.sh "$TMP/dest/aperire-huge" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-huge" ]] && grep -q 'larger than any' <<<"$ERR"; then
  ok "a file larger than any release file is refused"
else
  bad "an oversized file refuses" "rc=$RC err=$ERR"
fi
rm -f "$TMP/tree/scripts/huge.sh" "$TMP/tree/scripts/fifo.sh"
cp "$TMP/digests.before-fifo" "$DIGESTS"

# ── 7. what sits at the destination ─────────────────────────────────
printf 'root-only secret\n' > "$TMP/secret"
ln -s "$TMP/secret" "$TMP/dest/aperire-helper2"
run_install "$TMP/tree" scripts/helper.py "$TMP/dest/aperire-helper2" 0755
if [[ $RC -eq 0 && ! -L "$TMP/dest/aperire-helper2" && "$(cat "$TMP/secret")" == "root-only secret" ]]; then
  ok "a symlink planted at the destination is replaced, never written through"
else
  bad "a destination symlink is replaced" "rc=$RC link=$(readlink "$TMP/dest/aperire-helper2") secret=$(cat "$TMP/secret")"
fi
ln -s "$TMP/elsewhere" "$TMP/dest-link"
run_install "$TMP/tree" scripts/helper.py "$TMP/dest-link/aperire-helper3" 0755
if [[ $RC -eq 2 && ! -e "$TMP/elsewhere/aperire-helper3" ]]; then
  ok "a destination directory that is a symlink is not written into"
else
  bad "a symlinked destination directory refuses" "rc=$RC err=$ERR"
fi

# ── 8. rd_priv carries the code, not a path to it ───────────────────
# The root side of rd_priv must run the functions this shell has, never a
# fresh read of a library file in a tree. A fake sudo that runs the command
# with the library file already gone proves it.
cat > "$TMP/bin/sudo" <<'EOF'
#!/usr/bin/env bash
while [[ "${1:-}" == -* ]]; do shift; done
exec "$@"
EOF
chmod +x "$TMP/bin/sudo"
cp "$LIB" "$TMP/lib-copy.sh"
cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/trusted-path-lib.sh"
printf 'the release helper\n' > "$TMP/tree/scripts/helper.py"
# Both libraries are gone before the root side runs: the trusted-path check
# travels as text with the rest, never as a path to a file.
OUT="$(APERIRE_RELEASE_DIGESTS="$DIGESTS" bash -c '. "$1"; rm -f "$1" "${1%/*}/trusted-path-lib.sh"; rd_priv rd_install "$2" scripts/helper.py "$3" 0755' \
        _ "$TMP/lib-copy.sh" "$TMP/tree" "$TMP/dest/aperire-priv" 2>"$TMP/err")"; RC=$?
# EUID is not 0 here, so rd_priv takes the sudo branch.
if [[ $RC -eq 0 && "$OUT" == placed && "$(cat "$TMP/dest/aperire-priv")" == "the release helper" ]]; then
  ok "rd_priv runs the functions as text through sudo, with the record path carried along"
else
  bad "rd_priv works through sudo" "rc=$RC out=$OUT $(cat "$TMP/err")"
fi

# The record's path is root's to resolve. A caller that exports a path to
# nothing must not hand root the no-record fallback: real sudo resets the
# environment, and this fake stands in for that by setting root's own value.
mkdir -p "$TMP/rootenv-bin"
cat > "$TMP/rootenv-bin/sudo" <<EOF
#!/usr/bin/env bash
while [[ "\${1:-}" == -* ]]; do shift; done
exec env APERIRE_RELEASE_DIGESTS="$DIGESTS" "\$@"
EOF
chmod +x "$TMP/rootenv-bin/sudo"
printf 'a helper somebody rewrote\n' > "$TMP/tree/scripts/helper.py"
rm -f "$TMP/dest/aperire-envpath"
OUT="$(PATH="$TMP/rootenv-bin:$PATH" APERIRE_RELEASE_DIGESTS="$TMP/nothing-here/release.sha256" \
        bash -c '. "$1"; rd_priv rd_install "$2" scripts/helper.py "$3" 0755' _ "$LIB" "$TMP/tree" "$TMP/dest/aperire-envpath" 2>"$TMP/err")"; RC=$?
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-envpath" ]] && grep -q 'is not the file this release shipped' "$TMP/err"; then
  ok "a caller that points the record at nothing does not switch the check off for root"
else
  bad "root resolves the record path itself" "rc=$RC out=$OUT $(cat "$TMP/err")"
fi
printf 'the release helper\n' > "$TMP/tree/scripts/helper.py"

# ── 8b. a host that has had a record, and a record that refuses ─────
# "No record" copies unchecked, so it has to be unreachable on a host that
# has ever had one: digests-required beside the record makes a missing
# record a refusal.
mv "$DIGESTS" "$DIGESTS.aside"
printf 'required\n' > "$(dirname "$DIGESTS")/digests-required"
run_install "$TMP/tree" scripts/helper.py "$TMP/dest/aperire-marker" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-marker" ]] && grep -q 'has had release digests' <<<"$ERR"; then
  ok "a record that is gone from a host that had one refuses; it is never the unchecked fallback"
else
  bad "a missing record on a marked host refuses" "rc=$RC err=$ERR"
fi
rm -f "$(dirname "$DIGESTS")/digests-required"
mv "$DIGESTS.aside" "$DIGESTS"
cp "$DIGESTS" "$DIGESTS.good"
printf '# refuse the tree a rollback restored (abc) has no release digests on this host. Put a release back with: curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' > "$DIGESTS"
run_install "$TMP/tree" scripts/helper.py "$TMP/dest/aperire-refuse" 0755
if [[ $RC -eq 1 && ! -e "$TMP/dest/aperire-refuse" ]] && grep -q 'update --force' <<<"$ERR"; then
  ok "a refuse record refuses every copy and names --update --force"
else
  bad "a refuse record refuses" "rc=$RC err=$ERR"
fi
cp "$DIGESTS.good" "$DIGESTS"

# The destination directory: root's alone, or nothing is written into it.
mkdir -p "$TMP/wide"; chmod 0777 "$TMP/wide"
run_install "$TMP/tree" scripts/helper.py "$TMP/wide/aperire-wide" 0755
if [[ $RC -eq 1 && ! -e "$TMP/wide/aperire-wide" ]] && grep -q 'nobody else can write' <<<"$ERR"; then
  ok "a destination directory anybody can write is refused"
else
  bad "a world-writable destination directory refuses" "rc=$RC err=$ERR"
fi
chmod 0775 "$TMP/wide"
run_install "$TMP/tree" scripts/helper.py "$TMP/wide/aperire-wide" 0755
if [[ $RC -eq 1 && ! -e "$TMP/wide/aperire-wide" ]]; then
  ok "and so is one a group other than root can write"
else
  bad "a group-writable destination directory refuses" "rc=$RC err=$ERR"
fi

# ── 8c. as root ─────────────────────────────────────────────────────
# Under EUID 0 every owner check is against uid 0, the "already current" check
# includes owner and mode, the functions run directly, and the environment's
# APERIRE_RELEASE_DIGESTS is ignored. Driven under fakeroot, in ONE session so
# the faked owners hold, with a copy whose constant points at this fixture.
if command -v fakeroot >/dev/null 2>&1; then
  R="$TMP/asroot"
  mkdir -p "$R/tree/scripts" "$R/lib" "$R/dest"
  sed "s#^RD_DIGESTS_DEFAULT=/usr/local/lib/aperire/release\.sha256\$#RD_DIGESTS_DEFAULT=$R/lib/release.sha256#" "$LIB" > "$R/lib.sh"
  grep -qxF "RD_DIGESTS_DEFAULT=$R/lib/release.sha256" "$R/lib.sh" \
    || bad "the root copy of the library points at the fixture" "the RD_DIGESTS_DEFAULT line has moved"
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$R/trusted-path-lib.sh"
  printf 'the release helper\n' > "$R/tree/scripts/h.py"
  printf '# anchor a fixture\n%s  scripts/h.py\n' "$(sha256sum < "$R/tree/scripts/h.py" | cut -c1-64)" > "$R/lib/release.sha256"
  chmod 0644 "$R/lib/release.sha256"
  # shellcheck disable=SC2016  # expanded inside the fakeroot session
  ROOTOUT="$(PATH="$TMP/bin:$PATH" APERIRE_RELEASE_DIGESTS="$TMP/nothing/release.sha256" fakeroot bash -c '
    R="$1"; . "$R/lib.sh"
    say() { printf "%s=%s\n" "$1" "$2"; }
    say path "$RD_DIGESTS"
    chown 0:0 "$R/lib/release.sha256" "$R/dest"; chmod 0755 "$R/dest"
    out=$(rd_install "$R/tree" scripts/h.py "$R/dest/h" 0755 2>/dev/null); say first "$?:$out"
    say owner "$(stat -c %u:%a "$R/dest/h")"
    out=$(rd_install "$R/tree" scripts/h.py "$R/dest/h" 0755 2>/dev/null); say second "$?:$out"
    chmod 0700 "$R/dest/h"
    out=$(rd_install "$R/tree" scripts/h.py "$R/dest/h" 0755 2>/dev/null); say wrongmode "$?:$out"
    printf "rewritten\n" > "$R/tree/scripts/h.py"
    out=$(rd_install "$R/tree" scripts/h.py "$R/dest/h2" 0755 2>/dev/null); say tampered "$?:$out"
    printf "the release helper\n" > "$R/tree/scripts/h.py"
    chown 1234 "$R/lib/release.sha256"
    out=$(rd_install "$R/tree" scripts/h.py "$R/dest/h3" 0755 2>/dev/null); say recordowner "$?:$out"
    chown 0 "$R/lib/release.sha256"; chown 1234 "$R/dest"
    RD_STATE=; out=$(rd_install "$R/tree" scripts/h.py "$R/dest/h4" 0755 2>/dev/null); say dirowner "$?:$out"
  ' _ "$R" 2>&1)"
  rootval() { sed -n "s/^$1=//p" <<<"$ROOTOUT" | tail -1; }
  if [[ "$(rootval path)" == "$R/lib/release.sha256" ]]; then ok "as root the environment's record path is ignored for the library's own"; else bad "root ignores APERIRE_RELEASE_DIGESTS" "$ROOTOUT"; fi
  if [[ "$(rootval first)" == "0:placed" && "$(rootval owner)" == "0:755" ]]; then ok "as root a matching file is placed root:root with the mode asked for"; else bad "root places a matching file" "$ROOTOUT"; fi
  if [[ "$(rootval second)" == "0:same" && "$(rootval wrongmode)" == "0:placed" ]]; then ok "and is 'same' only when the bytes, the owner and the mode all match"; else bad "root's current-copy check covers owner and mode" "$ROOTOUT"; fi
  if [[ "$(rootval tampered)" == "1:" ]]; then ok "as root a rewritten file is refused, with the environment pointing the record at nothing"; else bad "root refuses a rewritten file" "$ROOTOUT"; fi
  if [[ "$(rootval recordowner)" == "1:" && "$(rootval dirowner)" == "1:" ]]; then ok "as root a record not owned by root, and a destination not owned by root, both refuse"; else bad "root refuses records and directories it does not own" "$ROOTOUT"; fi
else
  bad "the as-root rows can run" "they need fakeroot (what CI installs)"
fi

# ── 8e. a poisoned $EUID does not make a login's file root's (#1109) ─
# bash takes EUID from its environment: `env EUID=1000 bash -c 'echo $EUID'`
# prints 1000, and a root shell started that way read the login's uid as its
# own, took APERIRE_RELEASE_DIGESTS for its record, and accepted a record and
# a destination directory owned by that login. Whose account this is now
# comes from id(1), which fakeroot answers 0. Each row runs a root session
# with EUID=1000 in its environment, against the library and against the
# block get-aperire.sh carries, and a control without the poison on the same
# fixture has to place the file, or a refusal here could be the fixture.
if command -v fakeroot >/dev/null 2>&1; then
  R2="$TMP/poison"
  mkdir -p "$R2/tree/scripts" "$R2/lib"
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$R2/trusted-path-lib.sh"
  printf 'the release helper\n' > "$R2/tree/scripts/h.py"
  printf '# anchor a fixture\n%s  scripts/h.py\n' "$(sha256sum < "$R2/tree/scripts/h.py" | cut -c1-64)" > "$R2/lib/release.sha256"
  chmod 0644 "$R2/lib/release.sha256"
  # The library as it is, and the copy get-aperire.sh carries, each pointed at
  # this fixture's record. The second has nothing but the two blocks, which is
  # all the bootstrap has when it runs.
  sed "s#^RD_DIGESTS_DEFAULT=/usr/local/lib/aperire/release\.sha256\$#RD_DIGESTS_DEFAULT=$R2/lib/release.sha256#" "$LIB" > "$R2/lib.sh"
  { sed -n '/^# >>> trusted path >>>$/,/^# <<< trusted path <<<$/p' "$GET"; block_of "$GET"; } \
    | sed "s#^RD_DIGESTS_DEFAULT=/usr/local/lib/aperire/release\.sha256\$#RD_DIGESTS_DEFAULT=$R2/lib/release.sha256#" > "$R2/get-block.sh"
  if ! grep -qxF "RD_DIGESTS_DEFAULT=$R2/lib/release.sha256" "$R2/lib.sh" "$R2/get-block.sh"; then
    bad "the poisoned-EUID fixtures point at this directory" "the RD_DIGESTS_DEFAULT line has moved"
  fi
  poison_rows() { # $1 = which copy to source, $2 = EUID to put in the environment, or "" for none
    local -a ev=()
    [[ -z "$2" ]] || ev=(EUID="$2")
    # shellcheck disable=SC2016  # expanded inside the fakeroot session
    env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP" "${ev[@]}" APERIRE_RELEASE_DIGESTS="$TMP/nothing/release.sha256" \
      fakeroot bash -c '
        R="$1"; . "$2"
        say() { printf "%s=%s\n" "$1" "$2"; }
        say euid "$EUID"
        say path "$RD_DIGESTS"
        # The record is named here, so what the next rows judge is the owner
        # root is willing to accept and not which file the environment named.
        RD_DIGESTS="$R/lib/release.sha256"; RD_REQUIRED="$R/lib/digests-required"
        chown 0:0 "$R/lib/release.sha256"; rm -rf "$R/d1" "$R/d2"; mkdir -p "$R/d1" "$R/d2"
        chown 0:0 "$R/d1" "$R/d2"; chmod 0755 "$R/d1" "$R/d2"
        RD_STATE=; out=$(rd_install "$R/tree" scripts/h.py "$R/d1/h" 0755 2>/dev/null); say placed "$?:$out"
        chown 1000 "$R/lib/release.sha256"
        RD_STATE=; rd_manifest_load >/dev/null 2>&1; say recordowner "$?:$RD_STATE"
        chown 0 "$R/lib/release.sha256"
        chown 1000 "$R/d2"
        RD_STATE=; out=$(rd_install "$R/tree" scripts/h.py "$R/d2/h3" 0755 2>/dev/null); say dirowner "$?:$out"
      ' _ "$R2" "$1" 2>&1
  }
  pv() { sed -n "s/^$1=//p" <<<"$2" | tail -1; }
  for copy in lib get-block; do
    PCTL="$(poison_rows "$R2/$copy.sh" "")"
    if [[ "$(pv placed "$PCTL")" == "0:placed" && "$(pv path "$PCTL")" == "$R2/lib/release.sha256" ]]; then
      ok "$copy: control, no poison: a root session places the file from root's record"
    else
      bad "$copy: the poison fixture places a file when nothing is poisoned" "$PCTL"
    fi
    POUT="$(poison_rows "$R2/$copy.sh" 1000)"
    if [[ "$(pv euid "$POUT")" == 1000 ]]; then
      ok "$copy: the fixture does poison bash's \$EUID (it reads 1000 under fakeroot)"
    else
      bad "$copy: the fixture puts EUID=1000 into the session" "$POUT"
    fi
    if [[ "$(pv path "$POUT")" == "$R2/lib/release.sha256" ]]; then
      ok "$copy: with EUID=1000 in the environment, root still takes its own record path and ignores the environment's"
    else
      bad "$copy: a poisoned EUID makes root read the record the environment names (#1109)" "$POUT"
    fi
    if [[ "$(pv placed "$POUT")" == "0:placed" ]]; then
      ok "$copy: and a root-owned record and destination are still accepted: root is root, whatever \$EUID says"
    else
      bad "$copy: a poisoned EUID makes root refuse its own files (#1109)" "$POUT"
    fi
    if [[ "$(pv recordowner "$POUT")" == "1:bad" ]]; then
      ok "$copy: and a record owned by that uid is refused, not taken for root's"
    else
      bad "$copy: a poisoned EUID makes root accept a record the login owns (#1109)" "$POUT"
    fi
    if [[ "$(pv dirowner "$POUT")" == "1:" ]]; then
      ok "$copy: and so is a destination directory owned by that uid"
    else
      bad "$copy: a poisoned EUID makes root accept a destination the login owns (#1109)" "$POUT"
    fi
  done
else
  bad "the poisoned-EUID rows can run" "they need fakeroot (what CI installs)"
fi

# The sweep behind those rows (#1109). A pure "refuse unless root" gate is
# harmless to poison (a root shell whose EUID was set to a login's uid is
# refused, not trusted). What is not harmless is bash's $EUID used as a VALUE
# (an owner a file is held to, a uid written onto a file) or as the switch
# between a constant and an environment override. No shipped script does the
# first, and the files that keep a root-only constant keep it without $EUID.
evalue=""
for f in "$REPO_DIR"/scripts/*.sh "$REPO_DIR/install.sh" "$REPO_DIR/uninstall.sh" "$REPO_DIR/aperire-one"; do
  case "${f##*/}" in test-*) continue ;; esac
  # shellcheck disable=SC2016  # a pattern for grep, not an expansion
  hits="$(grep -vE '^[[:space:]]*#' "$f" | grep -E '"\$EUID"|[=:]\$EUID|\$\{EUID' || true)"
  [[ -z "$hits" ]] || evalue+="${f##*/}: $(head -1 <<<"$hits") "
done
if [[ -z "$evalue" ]]; then
  ok "no shipped script reads bash's \$EUID as a value: owners and uids come from id(1)"
else
  bad "a shipped script reads \$EUID as a value (#1109)" "$evalue"
fi
# What each of these keeps, by count: the updater its fail-closed root gate, the
# credential check library its sudo-or-direct switch (a poisoned EUID turns it
# into sudo, the harmless direction), and nothing in the rest.
econst=""
for pair in release-digests-lib.sh:0 trusted-path-lib.sh:0 reseal-model-key.sh:0 state-ancestors-lib.sh:0 aperire-update.sh:1 advisord-credcheck-lib.sh:1; do
  f="${pair%%:*}"; want="${pair##*:}"
  n="$(grep -vE '^[[:space:]]*#' "$REPO_DIR/scripts/$f" | grep -cE '\bEUID\b' || true)"
  [[ "$n" == "$want" ]] || econst+="$f has $n, wants $want; "
done
if [[ -z "$econst" ]]; then
  ok "the files that keep a root-only constant keep it without bash's \$EUID (only a fail-closed gate or a sudo switch remains)"
else
  bad "a root-only constant still follows bash's \$EUID (#1109)" "$econst"
fi

# ── 8d. archives built to fool the record ───────────────────────────
# get-aperire.sh's own reader, on archives no release would ship: the record
# must fail, or must leave the trick without an entry (which refuses later).
eval "$(sed -n '/^rd_record_digests() {/,/^}/p' "$GET")"
mk_archive() { # $1 = out.tar.gz, then pairs of kind:name[:target]
  python3 - "$@" <<'PY2'
import sys, tarfile, io
out = sys.argv[1]
with tarfile.open(out, "w:gz") as t:
    for spec in sys.argv[2:]:
        kind, name, *rest = spec.split(":")
        ti = tarfile.TarInfo(name)
        if kind == "file":
            data = (rest[0] if rest else name).encode() + b"\n"
            ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        elif kind == "sym":
            ti.type = tarfile.SYMTYPE; ti.linkname = rest[0]; t.addfile(ti)
        elif kind == "hard":
            ti.type = tarfile.LNKTYPE; ti.linkname = rest[0]; t.addfile(ti)
PY2
}
record_of() { # $1 = archive; sets REC, RC
  mkdir -p "$TMP/arch"; cp "$1" "$TMP/arch/a.tar.gz"
  REC="$TMP/arch/rec"; rm -f "$REC"
  ( RD_ANCHOR=t RD_SOURCE=t rd_record_digests "$TMP/arch/a.tar.gz" "$REC" ) >/dev/null 2>&1; RC=$?
}
mk_archive "$TMP/m1.tgz" file:aperire-one/scripts/a.sh sym:aperire-one/scripts/s.sh:/etc/shadow \
  hard:aperire-one/scripts/h.sh:aperire-one/scripts/a.sh
record_of "$TMP/m1.tgz"
if [[ $RC -eq 0 ]] && grep -q '  scripts/a.sh$' "$REC" && ! grep -q '  scripts/s.sh$' "$REC" \
   && ! grep -q '  scripts/h.sh$' "$REC" && grep -qE '^# key [0-9a-f]{64}$' "$REC"; then
  ok "a symlink and a hardlink in the archive get no entry, so a copy of either refuses"
else
  bad "links in the archive get no entry" "rc=$RC $(cat "$REC" 2>/dev/null)"
fi
mk_archive "$TMP/m2.tgz" file:aperire-one/scripts/a.sh "file:aperire-one/../escape.sh"
record_of "$TMP/m2.tgz"
if [[ $RC -ne 0 ]]; then ok "an entry that climbs out with .. fails the whole record"; else bad "a .. entry fails the record" "$(cat "$REC" 2>/dev/null)"; fi
mk_archive "$TMP/m3.tgz" file:aperire-one/scripts/a.sh:first file:aperire-one/scripts/a.sh:second
record_of "$TMP/m3.tgz"
if [[ $RC -ne 0 ]]; then ok "a name that appears twice fails the whole record"; else bad "a duplicate name fails the record" "$(cat "$REC" 2>/dev/null)"; fi
mk_archive "$TMP/m4.tgz" file:loose.sh
record_of "$TMP/m4.tgz"
if [[ $RC -ne 0 ]]; then ok "an entry outside the one top directory fails the whole record"; else bad "a top-level entry fails the record" "$(cat "$REC" 2>/dev/null)"; fi

# ── 9. the race ─────────────────────────────────────────────────────
# A racer that swaps the tree file between the release's bytes and other
# bytes by rename, as fast as it can. rename(2) is atomic, so every open sees
# one whole file or the other, which is the attack a tree-writer actually has.
# (unlink-then-symlink loses every time and would read as safe.)
printf 'GOOD sealer\n' > "$TMP/tree/scripts/race.sh"
write_record scripts/race.sh
printf 'GOOD sealer\n' > "$TMP/race-good"
printf 'EVIL sealer\n' > "$TMP/race-evil"
(
  while :; do
    cp "$TMP/race-evil" "$TMP/tree/scripts/.r1"; mv -fT "$TMP/tree/scripts/.r1" "$TMP/tree/scripts/race.sh"
    cp "$TMP/race-good" "$TMP/tree/scripts/.r2"; mv -fT "$TMP/tree/scripts/.r2" "$TMP/tree/scripts/race.sh"
  done
) &
RACER_PID=$!

# The positive control: check the tree file's digest, then copy the tree
# file, which is what every root copy did before this (cmp or sha256sum on
# the path, then `install` on the same path). If this never lands EVIL the
# racer is not racing and the row below proves nothing.
naive_evil=0
want="$(awk '$2 == "scripts/race.sh" { print $1 }' "$DIGESTS")"
for _ in $(seq 1 400); do
  if [[ "$(sha256sum < "$TMP/tree/scripts/race.sh" | cut -c1-64)" == "$want" ]]; then
    cp "$TMP/tree/scripts/race.sh" "$TMP/dest/naive"
    [[ "$(cat "$TMP/dest/naive" 2>/dev/null)" == "EVIL sealer" ]] && naive_evil=$((naive_evil + 1))
  fi
done
evil=0 placed=0 refused=0
for _ in $(seq 1 200); do
  rm -f "$TMP/dest/raced"
  run_install "$TMP/tree" scripts/race.sh "$TMP/dest/raced" 0755
  case $RC in
    0) placed=$((placed + 1))
       [[ "$(cat "$TMP/dest/raced")" == "GOOD sealer" ]] || evil=$((evil + 1)) ;;
    1) refused=$((refused + 1)) ;;
  esac
done
kill "$RACER_PID" 2>/dev/null; wait "$RACER_PID" 2>/dev/null; RACER_PID=""
if [[ $naive_evil -gt 0 ]]; then
  ok "control: check-then-copy landed the EVIL bytes $naive_evil time(s) in 400 under the racer"
else
  bad "control: the racer beats a check-then-copy" "0 in 400; the race row below would prove nothing"
fi
if [[ $evil -eq 0 && $placed -gt 0 && $refused -gt 0 ]]; then
  ok "rd_install under the same racer: 0 EVIL in 200 ($placed placed the release's bytes, $refused refused)"
else
  bad "rd_install never lands the racer's bytes" "evil=$evil placed=$placed refused=$refused"
fi

# ── 10. no root copy goes around it ─────────────────────────────────
# Every copy out of a tree into a root location goes through this library.
# The shape it replaced was `install -o root ... "$SRC" <root path>`: a raw
# copy from a tree path, checked (if at all) by a separate read. Any line of
# that shape in a shipped script is a copy this check does not cover.
RAW_RE='install\b[^#]*-o root[^#]*"\$\{?([A-Z_]*SRC|src|tool_src|method_src|cc_src|tsrc|msrc|REPO[A-Z_]*/scripts|TEMPLATE_DIR)\b'
# The other shape: dirsafe.py's "put" handed a tree path, which writes root's
# copy from a file the tree's owner can still rewrite. Its staged copies are
# named *_STAGED; a name ending in SRC, or one under REPO or a *DIR, is the
# tree. (Lowercase src is not in this half: the broker's one "put" of $src
# writes from root's own 0700 work directory.)
RAW_RE+='|dirsafe\b[^#]*\bput\b[^#]*"\$\{?(([A-Z_]*SRC|TEMPLATE_DIR)\b|(REPO[A-Z_]*|[A-Z_]*DIR)/)'
# And the bootstrap's own shape: get-aperire.sh calls its tree $DIR, and an
# `install` (run_root or not) reading from it is a copy around this library.
# The release key's refresh was written that way once (#736) and nothing here
# caught it, because it named neither -o root nor a *SRC variable.
RAW_RE+='|install\b[^#]*"\$\{?DIR/'
# (The lab deploy tool is held to the same rule by its own --place-self-test,
# since it does not ship.)
raw="$(cd "$REPO_DIR" && { grep -nE -e "$RAW_RE" scripts/*.sh install.sh uninstall.sh 2>/dev/null \
        | grep -v '^scripts/test-'; })"
if [[ -z "$raw" ]]; then
  ok "no shipped script copies a tree file into a root location except through this library"
else
  bad "every root copy goes through rd_install" "$raw"
fi
# And lane 1's own copy (#765). The trusted-path copy is the one read under
# rd_stage, and it is only both checks when rd_stage hands it the release's
# digest. Named anywhere else, by a call of any shape, through a variable or
# by running the walk's program text directly, it is a copy that decided its
# own digest. So only the files that define it may name it at all:
# trusted-path-lib.sh, release-digests-lib.sh, and get-aperire.sh inside its
# two inline blocks. Every shipped script is read, scripts/ at any depth and
# the operator command aperire-one included (#877 review, L4). The copy it
# replaced, trusted_path_install, is gone and must stay gone.
TPC_RE='\btrusted_path_copy\b|\b_TP_PY\b|\btrusted_path_install\b|\b_tp_run\b[^#]*\bcopy\b'
tpc_files="$(cd "$REPO_DIR" && { find scripts -name '*.sh' ! -name 'test-*' -type f; printf '%s\n' aperire-one install.sh uninstall.sh; } | sort -u)"
tpc_hits="$(cd "$REPO_DIR" && while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    case "$f" in scripts/trusted-path-lib.sh|scripts/release-digests-lib.sh) continue ;; esac
    if [[ "$f" == scripts/get-aperire.sh ]]; then
      # The two blocks blanked, not cut, so the line numbers stay the file's.
      sed -e '/^# >>> trusted path >>>$/,/^# <<< trusted path <<<$/s/.*//' \
          -e '/^# >>> release digests >>>$/,/^# <<< release digests <<<$/s/.*//' "$f" \
        | grep -nE -e "$TPC_RE" | grep -vE '^[0-9]+:[[:space:]]*#' | sed "s|^|$f:|"
    else
      grep -nE -e "$TPC_RE" "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | sed "s|^|$f:|"
    fi
  done <<<"$tpc_files")"
if [[ -z "$tpc_hits" && "$(wc -l <<<"$tpc_files")" -gt 50 ]]; then
  ok "the trusted-path copy is reached only through rd_stage, and the unchecked copy it replaced is gone"
else
  bad "the trusted-path copy is reached only through rd_stage" "$(wc -l <<<"$tpc_files") files read: $tpc_hits"
fi

# ── 11. the grants that had no driver of their own ──────────────────
# The trust-sync grant and the fleet broker grant, run for real up to and
# through their copy, with the root gate taken out and fakes for what a
# scratch directory cannot be (systemd, and root for the broker's dirsafe).
G="$TMP/grants"
mkdir -p "$G/tree/scripts" "$G/tree/dashboard/config" "$G/sbin" "$G/etc" "$G/units" "$G/bin" "$G/run"
for f in install-trust-sync-grant.sh aperire-trust-sync.sh install-fleet-broker-grant.sh aperire-fleet-broker.sh \
         aperire-fleet-arm.sh release-digests-lib.sh trusted-path-lib.sh fleet-trust-perms.sh fleet-trust-split.sh state-file.py; do
  cp "$REPO_DIR/scripts/$f" "$G/tree/scripts/$f"
done
# The broker rows run under fakeroot, where EUID is 0 and the library ignores
# APERIRE_RELEASE_DIGESTS by design. So the copy's one constant is rewritten
# instead, and pinned, or those rows would read the host's own record.
sed -i "s#^RD_DIGESTS_DEFAULT=/usr/local/lib/aperire/release\.sha256\$#RD_DIGESTS_DEFAULT=$G/release.sha256#" \
  "$G/tree/scripts/release-digests-lib.sh"
grep -qxF "RD_DIGESTS_DEFAULT=$G/release.sha256" "$G/tree/scripts/release-digests-lib.sh" \
  || bad "the grants' copy of the library points at the fixture's record" "the RD_DIGESTS_DEFAULT line has moved"
# shellcheck disable=SC2016  # $EUID is the text being matched, not a value
sed -i 's#^\[\[ \$EUID -eq 0 \]\] || die "run with sudo#true || die "run with sudo#' \
  "$G/tree/scripts/install-trust-sync-grant.sh" "$G/tree/scripts/install-fleet-broker-grant.sh"
if grep -q 'EUID -eq 0 ]] || die "run with sudo' "$G/tree/scripts/install-trust-sync-grant.sh" "$G/tree/scripts/install-fleet-broker-grant.sh"; then
  bad "the grants' root gates were taken out" "the sed matched nothing; every row below would prove nothing"
fi
# An installed dashboard (#964): its unit names the node it runs, and the
# tree has tsx. The broker grant refuses before any write without both, so
# these rows never depend on whether the runner has node on its PATH.
mkdir -p "$G/nodebin" "$G/tree/dashboard/node_modules/tsx/dist"
printf '#!/bin/sh\nexit 0\n' > "$G/nodebin/node"; chmod 755 "$G/nodebin/node"
: > "$G/tree/dashboard/node_modules/tsx/dist/cli.mjs"
printf '[Service]\nUser=%s\nExecStart=%s/nodebin/node --import tsx server.ts\n' "$(id -un)" "$G" > "$G/units/aperire-server.service"
cat > "$G/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in is-active) echo active ;; esac
exit 0
EOF
chmod +x "$G/bin/systemctl"
g_record() { # rel... ; the release's digests for these, taken now
  local rel
  {
    printf '# anchor a fixture\n'
    for rel in "$@"; do
      printf '%s  %s\n' "$(sha256sum < "$G/tree/$rel" | cut -c1-64)" "$rel"
    done
  } > "$G/release.sha256"
  chmod 0644 "$G/release.sha256"
}
run_trust() {
  OUT="$(cd "$G" && env PATH="$G/bin:$TMP/bin:$PATH" \
    APERIRE_TRUST_SYNC_PATH="$G/sbin/aperire-trust-sync" APERIRE_ETC="$G/etc" \
    APERIRE_UNIT_DIR="$G/units" APERIRE_TRUST_SYNC_SOCKET="$G/run/ts.sock" \
    APERIRE_DB_PATH="$G/aperire.db" APERIRE_ADVISOR_STATE="$G/state" \
    APERIRE_RELEASE_DIGESTS="$G/release.sha256" \
    bash "$G/tree/scripts/install-trust-sync-grant.sh" 2>&1)"; RC=$?
}
g_record scripts/aperire-trust-sync.sh
run_trust
# The run ends later, at the live-socket checks a scratch directory cannot
# pass, which is why RC is not asserted here: what is under test is the copy
# and that the units after it were reached.
if cmp -s "$G/tree/scripts/aperire-trust-sync.sh" "$G/sbin/aperire-trust-sync" \
   && [[ -f "$G/units/aperire-trust-sync.socket" ]]; then
  ok "trust-sync grant: the release's program is placed, and its units after it"
else
  bad "the trust-sync grant places the release's program" "rc=$RC $OUT"
fi
rm -f "$G/units/aperire-trust-sync.socket" "$G/units/aperire-trust-sync@.service"
printf '#!/usr/bin/env bash\necho rewritten after the unpack\n' > "$G/tree/scripts/aperire-trust-sync.sh"
run_trust
if [[ $RC -ne 0 ]] && ! cmp -s "$G/tree/scripts/aperire-trust-sync.sh" "$G/sbin/aperire-trust-sync" \
   && [[ ! -f "$G/units/aperire-trust-sync.socket" ]] \
   && grep -q 'refused: scripts/aperire-trust-sync.sh is not the file this release shipped' <<<"$OUT"; then
  ok "trust-sync grant: a program rewritten in the tree is refused, the installed one stays, no unit names it"
else
  bad "the trust-sync grant refuses a rewritten program" "rc=$RC $OUT"
fi

# The broker's own writes go through dirsafe.py, which chowns to root and
# checks every directory's owner, so it runs under fakeroot here the way its
# --refresh-nodes rows do. Only the copy is under test: the run stops later
# on things a scratch directory is not, which is why RC is not asserted.
if command -v fakeroot >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
  run_broker() {
    OUT="$(cd "$G" && env PATH="$G/bin:$PATH" \
      APERIRE_FLEET_BROKER_PATH="$G/sbin/aperire-fleet-broker" APERIRE_ETC="$G/etc" \
      APERIRE_UNIT_DIR="$G/units" APERIRE_FLEET_BROKER_SOCKET="$G/run/fb.sock" \
      APERIRE_DIR="$G/tree" APERIRE_RELEASE_DIGESTS="$G/release.sha256" \
      timeout 120 fakeroot bash "$G/tree/scripts/install-fleet-broker-grant.sh" 2>&1)"; RC=$?
  }
  cp "$G/tree/scripts/aperire-fleet-broker.sh" "$G/broker.orig"
  g_record scripts/aperire-fleet-broker.sh scripts/aperire-fleet-arm.sh scripts/fleet-trust-perms.sh \
    scripts/fleet-trust-split.sh scripts/state-file.py
  run_broker
  if cmp -s "$G/tree/scripts/aperire-fleet-broker.sh" "$G/sbin/aperire-fleet-broker" \
     && cmp -s "$G/tree/scripts/aperire-fleet-arm.sh" "$G/sbin/aperire-fleet-arm" \
     && grep -q 'is the same bytes as the release' <<<"$OUT"; then
    ok "broker grant: the release's broker and arm command are put through dirsafe from the checked copies"
  else
    bad "the broker grant places the release's broker" "rc=$RC $(tail -8 <<<"$OUT")"
  fi
  printf 'the broker as the release shipped it\n' > "$G/sbin/aperire-fleet-broker"
  printf '#!/usr/bin/env bash\necho rewritten after the unpack\n' > "$G/tree/scripts/aperire-fleet-broker.sh"
  run_broker
  if [[ $RC -ne 0 && "$(cat "$G/sbin/aperire-fleet-broker")" == "the broker as the release shipped it" ]] \
     && grep -q 'refused: scripts/aperire-fleet-broker.sh is not the file this release shipped' <<<"$OUT" \
     && ! grep -q '== What it may write' <<<"$OUT"; then
    ok "broker grant: a broker rewritten in the tree is refused before anything is written"
  else
    bad "the broker grant refuses a rewritten broker" "rc=$RC $(tail -8 <<<"$OUT")"
  fi
  # #741's arm command is the second root copy in that installer, and the
  # same rule holds for it: the broker is the release's again, the arm is
  # rewritten in the tree after the record was taken.
  cp "$G/broker.orig" "$G/tree/scripts/aperire-fleet-broker.sh"
  printf 'the arm command as the release shipped it\n' > "$G/sbin/aperire-fleet-arm"
  printf '#!/usr/bin/env bash\necho rewritten after the unpack\n' > "$G/tree/scripts/aperire-fleet-arm.sh"
  run_broker
  if [[ $RC -ne 0 && "$(cat "$G/sbin/aperire-fleet-arm")" == "the arm command as the release shipped it" ]] \
     && grep -q 'refused: scripts/aperire-fleet-arm.sh is not the file this release shipped' <<<"$OUT" \
     && ! grep -q '== What it may write' <<<"$OUT"; then
    ok "broker grant: an arm command rewritten in the tree is refused, the installed one stays"
  else
    bad "the broker grant refuses a rewritten arm command" "rc=$RC $(tail -8 <<<"$OUT")"
  fi
  # Pairing v2: the rule the grant makes the fleet trust key by is sourced
  # as root, so it is the release's copy or nothing, and nothing is written.
  cp "$G/broker.orig" "$G/tree/scripts/aperire-fleet-broker.sh"
  cp "$REPO_DIR/scripts/aperire-fleet-arm.sh" "$G/tree/scripts/aperire-fleet-arm.sh"
  printf 'the broker as the release shipped it\n' > "$G/sbin/aperire-fleet-broker"
  # shellcheck disable=SC2016  # a rewritten function, written as text
  printf 'ft_target() { echo "$1 root 666"; }\n' > "$G/tree/scripts/fleet-trust-perms.sh"
  # The first run above made one; this row is about whether one is made.
  rm -f "$G/tree/dashboard/config/fleet-trust.yaml"
  run_broker
  if [[ $RC -ne 0 && "$(cat "$G/sbin/aperire-fleet-broker")" == "the broker as the release shipped it" ]] \
     && grep -q 'refused: scripts/fleet-trust-perms.sh is not the file this release shipped' <<<"$OUT" \
     && [[ ! -e "$G/tree/dashboard/config/fleet-trust.yaml" ]] && ! grep -q '== What it may write' <<<"$OUT"; then
    ok "broker grant: a fleet-trust-perms.sh rewritten in the tree is refused before anything is written"
  else
    bad "the broker grant refuses a rewritten fleet-trust-perms.sh" "rc=$RC $(tail -8 <<<"$OUT")"
  fi
  # #868: the split the grant runs as root on the key it makes is the
  # release's copy too, or nothing is written.
  cp "$REPO_DIR/scripts/fleet-trust-perms.sh" "$G/tree/scripts/fleet-trust-perms.sh"
  # shellcheck disable=SC2016  # a rewritten function, written as text
  printf 'fts_converge() { chmod 644 "$1/dashboard/config/fleet-trust.yaml"; }\n' > "$G/tree/scripts/fleet-trust-split.sh"
  rm -f "$G/tree/dashboard/config/fleet-trust.yaml"
  run_broker
  if [[ $RC -ne 0 && "$(cat "$G/sbin/aperire-fleet-broker")" == "the broker as the release shipped it" ]] \
     && grep -q 'refused: scripts/fleet-trust-split.sh is not the file this release shipped' <<<"$OUT" \
     && [[ ! -e "$G/tree/dashboard/config/fleet-trust.yaml" ]] && ! grep -q '== What it may write' <<<"$OUT"; then
    ok "broker grant: a fleet-trust-split.sh rewritten in the tree is refused before anything is written (#868)"
  else
    bad "the broker grant refuses a rewritten fleet-trust-split.sh" "rc=$RC $(tail -8 <<<"$OUT")"
  fi
else
  bad "the broker grant rows can run" "they need fakeroot and python3-yaml (what CI installs)"
fi

echo
echo "── #1089: the account check could not run is not a file that changed ──"
# A fresh install reloaded systemd many times, one systemctl call in the
# account read failed meanwhile, and the closing text blamed the tree. The
# copy's refusal now says it never judged the file, tags the refusal file's
# line so the closing text can tell, and does not remember a failed read as a
# bad record. The fixture systemctl is in front on PATH only for each call,
# every call under LC_ALL=C. It fails the unit listing for calls
# skip+1 .. skip+first (counted in flaky/count) and is the suite's own after.
# A sleep that does not wait, in front for these rows, so the retry's seconds are
# not spent here; test-trusted-path-lib.sh holds the wait itself.
mkdir -p "$TMP/flaky" "$TMP/nosleep"
printf '#!/bin/sh\nexit 0\n' > "$TMP/nosleep/sleep"; chmod +x "$TMP/nosleep/sleep"
cat > "$TMP/flaky/systemctl" <<SHIM
#!/usr/bin/env bash
if [[ "\${1:-}" == list-unit-files ]]; then
  n=\$(( \$(cat "$TMP/flaky/count" 2>/dev/null || echo 0) + 1 )); echo "\$n" > "$TMP/flaky/count"
  skip=\$(cat "$TMP/flaky/skip" 2>/dev/null || echo 0); first=\$(cat "$TMP/flaky/first" 2>/dev/null || echo 0)
  [[ \$n -gt \$skip && \$n -le \$((skip + first)) ]] && exit 1
fi
exec "$TMP/bin/systemctl" "\$@"
SHIM
chmod +x "$TMP/flaky/systemctl"
printf 'the acct script\n' > "$TMP/tree/scripts/acct.sh"
write_record scripts/acct.sh
printf 'the copy root already had\n' > "$TMP/dest/acct"
flaky_install() { # $1 = calls that pass first, $2 = calls that then fail, rest = rd_install's arguments; sets OUT ERR RC, log in acct.log
  printf '%s' "$1" > "$TMP/flaky/skip"; printf '%s' "$2" > "$TMP/flaky/first"; rm -f "$TMP/flaky/count"
  shift 2
  : > "$TMP/acct.log"
  # shellcheck disable=SC2016  # the inner shell's own arguments
  OUT="$(env LC_ALL=C PATH="$TMP/nosleep:$TMP/flaky:$PATH" RD_REFUSED_LOG="$TMP/acct.log" APERIRE_RELEASE_DIGESTS="$DIGESTS" \
         bash -c '. "$1"; shift; rd_install "$@"' _ "$LIB" "$@" 2>"$TMP/err")"; RC=$?
  ERR="$(cat "$TMP/err")"
}
TAB=$'\t'

flaky_install 0 99 "$TMP/tree" scripts/acct.sh "$TMP/dest/acct" 0755 --kinds
if [[ $RC -eq 1 && "$OUT" == "refused:accounts" && "$(cat "$TMP/dest/acct")" == "the copy root already had" \
      && "$ERR" == *"the account check could not run: systemd did not answer"* \
      && "$ERR" != *"cannot be trusted"* && "$ERR" != *"not the file this release shipped"* ]]; then
  ok "a systemd that never answers: refused, the copy untouched, and the cause is the account check"
else
  bad "the refusal is the account check's" "rc=$RC out=$OUT err=$ERR"
fi
if [[ "$(cat "$TMP/acct.log")" == "$TMP/dest/acct (from scripts/acct.sh)${TAB}accounts" ]]; then
  ok "  and the refusal file's line carries the kind, a tab and the word"
else
  bad "the refusal file's line is tagged" "$(cat -A "$TMP/acct.log")"
fi

flaky_install 0 99 "$TMP/tree" scripts/acct.sh "$TMP/dest/acct" 0755
if [[ $RC -eq 1 && -z "$OUT" ]]; then
  ok "  with no --kinds the stdout contract is unchanged: nothing on it for a refusal"
else
  bad "rd_install's stdout is placed or same, and nothing for a refusal" "rc=$RC out=$OUT"
fi

# The account read in the record's own check passes; the copy's own read is
# the one that fails. Still the account check, still tagged.
flaky_install 1 99 "$TMP/tree" scripts/acct.sh "$TMP/dest/acct" 0755 --kinds
if [[ $RC -eq 1 && "$OUT" == "refused:accounts" && "$ERR" == *"scripts/acct.sh was not copied: the account check could not run"* \
      && "$(cat "$TMP/acct.log")" == *"${TAB}accounts" ]]; then
  ok "  the same when the copy's own read is the one that fails"
else
  bad "the copy's own account read is told as what it is" "rc=$RC out=$OUT err=$ERR log=$(cat -A "$TMP/acct.log")"
fi

# Control: a file that really changed is not mistaken for it, even though the
# caller asked for kinds.
printf 'an acct script somebody rewrote\n' > "$TMP/tree/scripts/acct.sh"
flaky_install 0 0 "$TMP/tree" scripts/acct.sh "$TMP/dest/acct" 0755 --kinds
if [[ $RC -eq 1 && -z "$OUT" && "$ERR" == *"refused: scripts/acct.sh is not the file this release shipped"* \
      && "$ERR" != *"account check"* && "$(cat "$TMP/acct.log")" == "$TMP/dest/acct (from scripts/acct.sh)" ]]; then
  ok "  while a file that really changed is still untagged: a tab-less line, no kind on stdout"
else
  bad "a changed file keeps its own kind" "rc=$RC out=$OUT err=$ERR log=$(cat -A "$TMP/acct.log")"
fi
printf 'the acct script\n' > "$TMP/tree/scripts/acct.sh"

# And a systemd that fails twice and then answers does not refuse at all.
flaky_install 0 2 "$TMP/tree" scripts/acct.sh "$TMP/dest/acct" 0755 --kinds
if [[ $RC -eq 0 && "$OUT" == placed && "$(cat "$TMP/dest/acct")" == "the acct script" && ! -s "$TMP/acct.log" ]]; then
  ok "a systemctl that fails its first two calls and answers the third: the copy goes through"
else
  bad "the retry lets the copy through" "rc=$RC out=$OUT err=$ERR"
fi
printf 'the copy root already had\n' > "$TMP/dest/acct"

# A failed account read is a fault of the check, not a verdict on the record:
# the next copy in the same process asks again instead of refusing for the
# rest of the run on a "record that cannot be trusted".
printf '0' > "$TMP/flaky/skip"; printf '5' > "$TMP/flaky/first"; rm -f "$TMP/flaky/count"
# shellcheck disable=SC2016  # the inner shell's own arguments
OUT="$(env LC_ALL=C PATH="$TMP/nosleep:$TMP/flaky:$PATH" APERIRE_RELEASE_DIGESTS="$DIGESTS" bash -c '
  . "$1"
  rd_stage "$2" scripts/acct.sh "$3/one" >/dev/null 2>&1; a=$?
  rd_stage "$2" scripts/acct.sh "$3/two" >/dev/null 2>&1; b=$?
  echo "first=$a second=$b"' _ "$LIB" "$TMP/tree" "$TMP/dest" 2>&1)"
if [[ "$OUT" == "first=1 second=0" ]]; then
  ok "a failed account read is not remembered as a bad record: the next copy in the run goes through"
else
  bad "the record is not poisoned by one failed read" "$OUT"
fi

# get-aperire.sh places its own files through root_place, which reads only the
# status and stdout rd_install gives back across a sudo. Run its own copies of
# the two blocks and of root_place, with rd_priv as a plain call, and it tells
# the account check apart: status 6 and a tagged entry for the closing list,
# where a refusal about the file stays 1 and untagged.
printf '0' > "$TMP/flaky/skip"; printf '99' > "$TMP/flaky/first"; rm -f "$TMP/flaky/count"
root_place_run() { # sets OUT
  # shellcheck disable=SC2016  # the inner shell's own arguments
  OUT="$(env LC_ALL=C PATH="$TMP/nosleep:$TMP/flaky:$PATH" APERIRE_RELEASE_DIGESTS="$DIGESTS" bash -c '
    eval "$(sed -n "/^# >>> trusted path >>>\$/,/^# <<< trusted path <<<\$/p" "$1")"
    eval "$(sed -n "/^# >>> release digests >>>\$/,/^# <<< release digests <<<\$/p" "$1")"
    eval "$(sed -n "/^root_place() {\$/,/^}\$/p" "$1")"
    rd_priv() { "$@"; }
    ROOT_COPY_REFUSED=(); DIR="$2"
    root_place scripts/acct.sh "$3/acct" 0755 2>/dev/null; rc=$?
    printf "rc=%s placed=[%s] n=%s entry=%s\n" "$rc" "$ROOT_PLACED" "${#ROOT_COPY_REFUSED[@]}" "$(printf %s "${ROOT_COPY_REFUSED[0]:-}" | cat -A)"' \
    _ "$GET" "$TMP/tree" "$TMP/dest" 2>&1)"
}
root_place_run
if [[ "$OUT" == "rc=6 placed=[] n=1 entry=$TMP/dest/acct (from scripts/acct.sh)^Iaccounts" ]]; then
  ok "get-aperire.sh's root_place: an account-check refusal is status 6 and a tagged entry for the closing list"
else
  bad "root_place tells the account check apart" "$OUT"
fi
printf '0' > "$TMP/flaky/first"
printf 'an acct script somebody rewrote\n' > "$TMP/tree/scripts/acct.sh"
root_place_run
if [[ "$OUT" == "rc=1 placed=[] n=1 entry=$TMP/dest/acct (from scripts/acct.sh)" ]]; then
  ok "  and a file that really changed stays status 1 with an untagged entry"
else
  bad "root_place keeps a changed file as it was" "$OUT"
fi
printf 'the acct script\n' > "$TMP/tree/scripts/acct.sh"
root_place_run
if [[ "$OUT" == "rc=0 placed=[placed] n=0 entry=" ]]; then
  ok "  and a copy that is judged is placed, status 0"
else
  bad "root_place places a judged copy" "$OUT"
fi
printf 'the copy root already had\n' > "$TMP/dest/acct"

# rd_place is the installers' own voice for a copy (install-can-delete-timer.sh
# places the rotation timer with it, the one that failed in #1089). It says the
# account check could not run, and keeps the old sentence for a changed file.
rd_place_run() { # $1 = calls that then fail (all of them when 99); sets OUT
  printf '0' > "$TMP/flaky/skip"; printf '%s' "$1" > "$TMP/flaky/first"; rm -f "$TMP/flaky/count"
  # shellcheck disable=SC2016  # the inner shell's own arguments
  OUT="$(env LC_ALL=C PATH="$TMP/nosleep:$TMP/flaky:$PATH" APERIRE_RELEASE_DIGESTS="$DIGESTS" \
         bash -c '. "$1"; shift; rd_place "$@"; echo "rc=$?"' _ "$LIB" "$TMP/tree" scripts/acct.sh "$TMP/dest/acct" 0755 2>&1)"
}
rd_place_run 99
if [[ "$OUT" == *"error: $TMP/dest/acct was not written: the account check could not run (above), so scripts/acct.sh was not judged."* \
      && "$OUT" != *"is not the file this release shipped"* && "$OUT" == *"rc=1"* ]]; then
  ok "rd_place: the installers' own line says the account check could not run, not that the file changed"
else
  bad "rd_place names the account check" "$OUT"
fi
printf 'an acct script somebody rewrote\n' > "$TMP/tree/scripts/acct.sh"
rd_place_run 0
if [[ "$OUT" == *"scripts/acct.sh in the tree is not the file this release shipped, or a service account can change it (above)"* \
      && "$OUT" != *"account check"* && "$OUT" == *"rc=1"* ]]; then
  ok "  and a changed file keeps its own line"
else
  bad "rd_place keeps the changed-file line" "$OUT"
fi
printf 'the acct script\n' > "$TMP/tree/scripts/acct.sh"

# The staging of a whole release says the same thing in its own words.
mkdir -p "$TMP/stageout"
printf '0' > "$TMP/flaky/skip"; printf '99' > "$TMP/flaky/first"; rm -f "$TMP/flaky/count"
# shellcheck disable=SC2016  # the inner shell's own arguments
OUT="$(env LC_ALL=C PATH="$TMP/nosleep:$TMP/flaky:$PATH" APERIRE_RELEASE_DIGESTS="$DIGESTS" bash -c '. "$1"; rd_stage_tree "$2" "$3"; echo "rc=$?"' _ "$LIB" "$TMP/tree" "$TMP/stageout" 2>&1)"
if [[ "$OUT" == *"the account check could not run: systemd did not answer"* && "$OUT" != *"did not list its units"* ]]; then
  ok "staging a release names the account check, in the one sentence"
else
  bad "rd_stage_tree names the account check" "$OUT"
fi

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
