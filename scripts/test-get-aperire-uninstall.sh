#!/usr/bin/env bash
# Exercise scripts/get-aperire-uninstall.sh, the bootstrap behind the one-line
# uninstall.
#
# What is being protected: this is the script an operator runs by pasting a URL
# into a root-capable shell on a box that already matters, and what it starts
# is a removal. Four of its promises fail silently if they break.
#
#   1. A half-delivered copy must not run. `curl | bash` executes what has
#      arrived as it arrives, so a connection cut mid-download runs the top
#      half and stops. Every check here has its opposite beside it, because
#      "nothing happened" is also what a test proves when the script never
#      ran at all.
#   2. The refusal must be a refusal, and it must download nothing. There is
#      no honest way to uninstall on a box with nothing on it, and fetching a
#      release here would download the thing the operator is removing.
#      Asserted both ways: a bare box refuses and runs no uninstaller, and a
#      box with a checkout hands over to it.
#   3. It must find the install the RUNNING dashboard uses, not a directory
#      with a familiar name. The unit's WorkingDirectory is the only answer
#      that cannot be wrong, and a second checkout beside it is the case that
#      tells the two apart.
#   4. The flags must arrive. --keep and --wipe are the answer to a question
#      with no default, so a flag dropped between here and the uninstaller
#      turns an unattended run into a refusal, and the exit code the
#      uninstaller chose has to come back out of this script unchanged.
#   5. An install older than the question must still uninstall. Every host
#      installed from a release before --keep/--wipe existed carries an
#      uninstall.sh that refuses them as unknown arguments, and that is what
#      the one-liner met on aperire4 on 2026-09-07: the plan printed, the
#      handover happened, and the old script exited 2. So the current
#      uninstall.sh is fetched, checked whole, installed over the old one and
#      run. Asserted in several directions, because most of them are silent: a
#      current install must NOT be overwritten and must fetch nothing, and a
#      copy that arrives short, stale or not at all must be refused with
#      nothing run.
#
#   7. A fetched uninstall.sh runs only when the release key vouches for it
#      (#762). Root fetches the signed release.json the endpoint names, checks
#      it against root's own copy of the key set, and runs the download only
#      when its sha256 is the signed uninstaller_sha256. A changed download, a
#      release signed by another key or by nobody, and a host with no key are
#      each refused with nothing run.
#
#   6. Root never runs the checkout's own uninstall.sh (#943). The bootstrap
#      stages it, with the rest of the install's scripts, against root's own
#      copy of the checking libraries and the release's digests, and runs the
#      staged copy, told which install it removes. A changed file is refused
#      with nothing run, a host without root's libraries is refused by name,
#      and an uninstall.sh too old to be staged is replaced by the fetched
#      one, run from a directory only root can write and never written into
#      the checkout.
#
#   bash scripts/test-get-aperire-uninstall.sh
#
# Runs entirely in a temporary directory against fake curl, sudo and systemctl
# on PATH, and a fake install whose uninstall.sh records what it was called
# with. Touches no host, needs no root, and removes nothing.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUT="$REPO_DIR/scripts/get-aperire-uninstall.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$SUT" ]] || { echo "no get-aperire-uninstall.sh at $SUT"; exit 1; }

# The operator's home in this fixture is "op", not "home": the docs gate in CI
# greps every shipped script for a literal /home/<name>/ path, and a fake one
# in a test would fail it exactly like a real one.
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/op" "$TMP/rootlib"
# Root's own copy of the checking libraries, which every install and update
# puts under /usr/local/lib/aperire. The bootstrap stages the install against
# these and never against anything in the checkout.
cp "$REPO_DIR/scripts/release-digests-lib.sh" "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/rootlib/"
# And the release key (#762): the verifier every install puts there, and a key
# set naming a key made for this run. The endpoint below signs with it.
mkdir -p "$TMP/keys"
ssh-keygen -q -t ed25519 -N '' -C fixture-release -f "$TMP/keys/release" </dev/null
ssh-keygen -q -t ed25519 -N '' -C fixture-stranger -f "$TMP/keys/stranger" </dev/null
cp "$REPO_DIR/scripts/release-verify-lib.sh" "$TMP/rootlib/"
printf 'aperire-release-key namespaces="aperire-release" ssh-ed25519 %s fixture\n' \
  "$(cut -d' ' -f2 "$TMP/keys/release.pub")" > "$TMP/rootlib/release-signers"
chmod 0755 "$TMP/rootlib"; chmod 0644 "$TMP/rootlib/"*

# ── The fake install ────────────────────────────────────────────────
# A directory that satisfies looks_like_an_install, whose uninstall.sh records
# its arguments, what it was given for stdin, and nothing else. It removes
# nothing: what is under test here is what reaches it, not what it does.
# The flag surface is copied from the real uninstall.sh, not invented, and so
# is the sentinel on its last line. Both are read by the script under test:
# it greps the installed copy for --wipe to decide whether that copy predates
# the keep/wipe question, and it checks the sentinel on anything it fetches.
# A stub missing either would put every row down the upgrade path and prove
# nothing about the one that is supposed to take it.
write_uninstaller() { # $1 = file, $2 = label
  local f="$1" label="$2"
  cat > "$f" <<EOF
#!/usr/bin/env bash
# --keep --wipe --toolchain --role= --yes are the flags this understands.
# APERIRE_INSTALL_TREE names the install it removes when root runs a staged
# copy of it (#943); the bootstrap greps for the name to tell a current one.
printf 'self=%s tree=%s leak=%s helper=%s\n' "\$0" "\${APERIRE_INSTALL_TREE:-unset}" "\${APERIRE_LEAK-unset}" \
  "\$( [[ -f "\$(dirname "\$0")/scripts/state-file.py" ]] && echo beside || echo none )" >> "$TMP/state/where"
printf '%s\n' "uninstall from=$label args=\$*" >> "$TMP/state/calls"
printf 'TTY=%s\n' "\$( [[ -t 0 ]] && echo yes || echo no )" >> "$TMP/state/calls"
if [[ -f "$TMP/state/uninstall-rc" ]]; then exit "\$(cat "$TMP/state/uninstall-rc")"; fi
echo "  uninstall complete"
exit 0
# --- end of uninstall.sh ---
EOF
  chmod +x "$f"
}

make_install() { # $1 = directory, $2 = a label so the two are told apart
  local d="$1" label="$2"
  mkdir -p "$d/scripts"
  # Every real install has one, and root stages the install only when it does.
  printf '#!/usr/bin/env bash\necho install\n' > "$d/install.sh"
  # The helper the dashboard hand-back plants with, which a staged run finds
  # beside the uninstaller.
  printf 'import sys\n' > "$d/scripts/state-file.py"
  write_uninstaller "$d/uninstall.sh" "$label"
}

# The uninstall.sh a host installed before the keep/wipe question carries: it
# requires --role and refuses --keep and --wipe outright, which is exactly
# what came back off aperire4. The refusal text and the exit code are that
# script's own, copied rather than invented.
make_old_install() { # $1 = directory, $2 = a label so the two are told apart
  local d="$1" label="$2"
  mkdir -p "$d/scripts"
  printf '#!/usr/bin/env bash\necho install\n' > "$d/install.sh"
  printf 'import sys\n' > "$d/scripts/state-file.py"
  cat > "$d/uninstall.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "OLD uninstall from=$label args=\$*" >> "$TMP/state/calls"
for arg in "\$@"; do
  case "\$arg" in
    --role=*|--purge-config|--purge-data|--purge-all|--yes|-y) ;;
    *) echo "error: unknown argument: \$arg" >&2; exit 2 ;;
  esac
done
echo "  uninstallation complete"
exit 0
EOF
  chmod +x "$d/uninstall.sh"
}

make_install "$TMP/op/aperire-one" "the-real-one"

# A second checkout, complete and plausible, that the running dashboard is NOT
# using. Row 3's whole point: a directory with the right shape is not evidence.
make_install "$TMP/op/other-checkout" "the-lookalike"

# ── Fakes on PATH ───────────────────────────────────────────────────
# curl: this script has exactly one caller, the self-fetch, told by -o. A call
# without -o would be this script downloading something, which is the thing it
# promises never to do, so it is recorded and refused.
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
out=""; url=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    http*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
if [[ -n "\$out" ]]; then
  case "\$url" in
    */release.json|*/release-*.json|*/release-*.json.sig)
      printf '%s\n' "release-fetch \$url" >> "$TMP/state/curl-calls"
      exec bash "$TMP/fake-release" "\$url" "\$out" ;;
    *uninstall.sh)
      printf '%s\n' "script-fetch \$url" >> "$TMP/state/curl-calls"
      [[ -f "$TMP/state/served-uninstall" ]] || exit 22
      cp "$TMP/state/served-uninstall" "\$out"; exit 0 ;;
  esac
  printf '%s\n' "self-fetch \$url" >> "$TMP/state/curl-calls"
  [[ -f "$TMP/state/self" ]] || exit 22
  cp "$TMP/state/self" "\$out"; exit 0
fi
printf '%s\n' "DOWNLOAD \$url" >> "$TMP/state/curl-calls"
exit 22
EOF

# The release beside the uninstaller, as the publisher writes it: release.json
# naming an archive, and release-<sha>.json with its signature under the names
# that never change, its uninstaller_sha256 the sum of whatever uninstall.sh
# the endpoint serves. A row bends one thing at a time:
#   state/signed-uninstaller  the file whose sum is signed, when it is not the
#                             one served (a changed download)
#   state/sig-mode            stranger (another key signs), tampered (the
#                             signed text changes after signing), missing (no
#                             .sig), unsigned (no release-<sha>.json at all),
#                             other-archive (a genuine signed release for an
#                             archive release.json does not name)
cat > "$TMP/fake-release" <<EOF
#!/usr/bin/env bash
url="\$1"; out="\$2"; name="\${url##*/}"
arch=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
signed="$TMP/state/signed-uninstaller"
[[ -f "\$signed" ]] || signed="$TMP/state/served-uninstall"
[[ -f "\$signed" ]] || exit 22
unish="\$(sha256sum "\$signed" | cut -d' ' -f1)"
mode="\$(cat "$TMP/state/sig-mode" 2>/dev/null || true)"
json() { # \$1 = the archive it names
  printf '{\n  "tag": "snapshot-fixture",\n  "commit": "0a1b2c3",\n  "sha256": "%s",\n  "published_at": "2026-10-01T00:00:00Z",\n  "uninstaller_sha256": "%s"\n}\n' "\$1" "\$unish"
}
doc="\$arch"
[[ "\$mode" != other-archive ]] || doc=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
case "\$name" in
  release.json) json "\$arch" > "\$out" ;;
  "release-\$arch.json")
    [[ "\$mode" != unsigned ]] || exit 22
    if [[ "\$mode" == tampered ]]; then json "\$doc" | sed 's/snapshot-fixture/snapshot-changed/' > "\$out"; else json "\$doc" > "\$out"; fi ;;
  "release-\$arch.json.sig")
    [[ "\$mode" != unsigned && "\$mode" != missing ]] || exit 22
    key="$TMP/keys/release"; [[ "\$mode" == stranger ]] && key="$TMP/keys/stranger"
    json "\$doc" | ssh-keygen -Y sign -q -f "\$key" -n aperire-release > "\$out" 2>/dev/null ;;
  *) exit 22 ;;
esac
EOF

# sudo: drop its own flags and run the rest here, so what the bootstrap asks
# root to do is observable. Real sudo resets the environment (`Defaults
# env_reset` keeps TERM and drops NO_COLOR, and everything else the caller
# exported), so this one does too: only an allow-list crosses, and a row that
# reads a variable the bootstrap never passed would otherwise pass by leak.
# The record is the one name the fixture's root side reads.
cat > "$TMP/bin/sudo" <<EOF
#!/usr/bin/env bash
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -H|-E) shift ;;
    -n) shift
        [[ "\${1:-}" == "true" ]] && exit 0
        ;;
    -v) exit 0 ;;
    -u) shift 2 ;;
    *) break ;;
  esac
done
[[ \$# -eq 0 ]] && exit 0
# The one constant directory root reads its checking libraries from is mapped
# to the fixture's, here and only here: the product has no override for it.
args=( "\$@" )
for i in "\${!args[@]}"; do
  [[ "\${args[\$i]}" == /usr/local/lib/aperire ]] && args[\$i]="\${FAKE_ROOTLIB_MAP:-/nonexistent}"
done
set -- "\${args[@]}"
printf '%s\n' "\$*" | cut -c1-200 >> "$TMP/state/sudo-exec"
# state/tamper-before-stage lists paths in the install: just before root stages
# them, each is rewritten with a file that leaves a mark if it ever runs, and
# says nothing of the install variable (a program older than the one the
# bootstrap read first).
if [[ -f "$TMP/state/tamper-before-stage" ]]; then
  args=( "\$@" )
  for i in "\${!args[@]}"; do
    if [[ "\${args[\$i]}" == rd-stage-tree ]]; then
      tree="\${args[\$((i + 3))]}"
      while IFS= read -r rel; do
        [[ -n "\$rel" ]] || continue
        printf '#!/usr/bin/env bash\necho "TREE RAN %s" >> "$TMP/state/TREE-RAN"\n' "\$rel" > "\$tree/\$rel"
      done < "$TMP/state/tamper-before-stage"
      rm -f "$TMP/state/tamper-before-stage"
      break
    fi
  done
fi
# state/tamper-before-install and state/tamper-after-install: the login's own
# file in /tmp is rewritten just before root copies it, or just after.
if [[ -f "$TMP/state/tamper-before-install" || -f "$TMP/state/tamper-after-install" ]]; then
  args=( "\$@" )
  for i in "\${!args[@]}"; do
    if [[ "\${args[\$i]}" == 0755 && "\${args[\$((i - 1))]}" == -m && "\${args[\$((i + 1))]}" == /*aperire-uninstall.*.sh ]]; then
      src="\${args[\$((i + 1))]}"
      if [[ -f "$TMP/state/tamper-before-install" ]]; then
        cp "$TMP/state/tampered-uninstall" "\$src"
        exec env -i PATH="\$PATH" "\$@"
      fi
      env -i PATH="\$PATH" "\$@" || exit \$?
      cp "$TMP/state/tampered-uninstall" "\$src"
      exit 0
    fi
  done
fi
exec env -i PATH="\$PATH" HOME="\${HOME:-}" TERM="\${TERM:-dumb}" SUDO_USER="\$(/usr/bin/id -un)" \
  \${APERIRE_RELEASE_DIGESTS:+APERIRE_RELEASE_DIGESTS="\$APERIRE_RELEASE_DIGESTS"} \
  "\$@"
EOF

# systemctl: every reading comes from a state file, so a row can put the host
# in any of the states this script has to tell apart.
#   state/workdir   what the dashboard unit reports as WorkingDirectory
#   state/units     which unit files systemd knows about
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/systemctl-calls"
case "\$*" in
  *"show -p WorkingDirectory"*)
    cat "$TMP/state/workdir" 2>/dev/null; exit 0 ;;
  *list-unit-files*)
    cat "$TMP/state/units" 2>/dev/null; exit 0 ;;
esac
exit 0
EOF

# id: only -un is answered, from a state file, because "which account does
# this run belong to" is a row's own business. Everything else goes to the
# real one. Absent file means the ordinary operator, which is most rows.
cat > "$TMP/bin/id" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  -un) cat "$TMP/state/whoami" 2>/dev/null || echo op; exit 0 ;;
esac
exec /usr/bin/id "\$@"
EOF

chmod +x "$TMP/bin/"*

# ── The run harness ─────────────────────────────────────────────────
# One place that decides the environment, so a row says only what it changes.
# HOME is the fixture's, never this machine's.
RUN_HOME="$TMP/op"

run_sut() {
  ( cd "$TMP" && env -i \
      PATH="$TMP/bin:/usr/bin:/bin" \
      HOME="$RUN_HOME" \
      TERM=dumb \
      APERIRE_UNINSTALL_GET_SELF_URL="https://example.invalid/uninstall" \
      APERIRE_UNINSTALL_GET_SCRIPT_URL="https://example.invalid/uninstall.sh" \
      FAKE_ROOTLIB_MAP="${ROOTLIB_FOR_RUN:-$TMP/rootlib}" \
      ${LOGIN_LIBVARS_FOR_RUN:+APERIRE_UNINSTALL_GET_TESTING=1 APERIRE_UNINSTALL_GET_ROOT_LIB_DIR="$TMP/rootlib"} \
      APERIRE_RELEASE_DIGESTS="${RECORD_FOR_RUN:-$TMP/no-release-record}" \
      ${APERIRE_LEAK:+APERIRE_LEAK="$APERIRE_LEAK"} \
      bash "$SUT" "$@" 2>&1 )
}

reset_state() {
  RUN_HOME="$TMP/op"
  rm -f "$TMP/state/"*
  : > "$TMP/state/units"
  printf '%s\n' "$TMP/op/aperire-one/dashboard" > "$TMP/state/workdir"
  # A row that exercised the upgrade replaced the fixture's uninstall.sh with
  # whatever the endpoint served, so both installs are rebuilt here rather
  # than in the rows, and a row says only what it changes.
  make_install "$TMP/op/aperire-one" "the-real-one"
  make_install "$TMP/op/other-checkout" "the-lookalike"
}

echo
echo "── the refusal: there is nothing here to remove ───────────────────"

reset_state
: > "$TMP/state/workdir"
RUN_HOME="$TMP/nobody"
out="$(run_sut --keep --yes)"; rc=$?
if [[ $rc -ne 0 ]]; then ok "a box with no Aperire One install refuses"
else bad "a box with no install refuses" "exit $rc"; fi
if grep -q 'no Aperire One install on this host' <<<"$out"
then ok "the refusal names what is missing, not what failed"
else bad "the refusal names what is missing" "$(tail -4 <<<"$out")"; fi
if grep -q 'does not download one' <<<"$out"
then ok "and says out loud that it fetched no release to remove"
else bad "the refusal says it downloaded nothing" "$(tail -6 <<<"$out")"; fi
# The negative control. A refusal that had already run something would print
# the same words.
if [[ ! -f "$TMP/state/calls" ]]
then ok "and it ran no uninstaller on the way to refusing"
else bad "ran no uninstaller while refusing" "$(cat "$TMP/state/calls")"; fi
if ! grep -q '^DOWNLOAD' "$TMP/state/curl-calls" 2>/dev/null
then ok "and fetched nothing but itself, which is the whole promise"
else bad "it downloaded something" "$(cat "$TMP/state/curl-calls")"; fi

# A host whose checkout was deleted before it was uninstalled from. Still a
# refusal, but a different one: telling an operator with leftover units that
# they have none is the worse of the two mistakes.
reset_state
: > "$TMP/state/workdir"
RUN_HOME="$TMP/nobody"
printf 'aperire-server.service enabled enabled\n' > "$TMP/state/units"
out="$(run_sut --keep --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'this host still has units whose names begin with' <<<"$out"
then ok "a host with units but no checkout is told that, not told it is clean"
else bad "leftover units are named in the refusal" "exit $rc: $(tail -8 <<<"$out")"; fi
if grep -q 'aperire-leftovers.sh' <<<"$out"
then ok "and pointed at the read-back that lists them"
else bad "the refusal names the leftover finder" "$(tail -8 <<<"$out")"; fi

# The opposite: the same script, the same flags, on a box that HAS one.
reset_state
out="$(run_sut --keep --yes)"; rc=$?
if [[ $rc -eq 0 ]]; then ok "a box with an install proceeds (the refusal is not unconditional)"
else bad "a box with an install proceeds" "exit $rc: $(tail -4 <<<"$out")"; fi

# --dir naming a directory that is not one.
reset_state
mkdir -p "$TMP/op/not-an-install"
out="$(run_sut --keep --yes --dir "$TMP/op/not-an-install")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'is not an Aperire One install' <<<"$out"
then ok "--dir at a directory that is not an install is refused by name"
else bad "--dir at a non-install is refused" "exit $rc: $(tail -2 <<<"$out")"; fi

echo
echo "── finding the install the RUNNING dashboard uses ─────────────────"

reset_state
out="$(run_sut --keep --yes)"
if grep -q "install    $TMP/op/aperire-one " <<<"$out"
then ok "the install comes from the dashboard unit's WorkingDirectory"
else bad "the install comes from the unit" "$(grep -F 'install ' <<<"$out")"; fi
if grep -q 'from the installed dashboard unit' <<<"$out"
then ok "and it says that is where it came from, before removing anything"
else bad "it names the evidence" "$(tail -6 <<<"$out")"; fi
if grep -q 'from=the-real-one' "$TMP/state/calls" 2>/dev/null
then ok "and that is the uninstaller it ran"
else bad "the right uninstaller ran" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

# The unit points at the OTHER checkout. A script that guessed from $HOME
# would uninstall a tree the running dashboard does not use, and both
# directories exist and both look right, so only the unit tells them apart.
reset_state
printf '%s\n' "$TMP/op/other-checkout/dashboard" > "$TMP/state/workdir"
out="$(run_sut --keep --yes)"
if grep -q 'from=the-lookalike' "$TMP/state/calls" 2>/dev/null
then ok "a second plausible checkout does not win over the running unit"
else bad "the running unit wins over a lookalike" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

# No unit at all, but a checkout is at the default location. A guess, and it
# says so. This is the ordinary case for a host whose dashboard unit was
# already removed by hand.
reset_state
: > "$TMP/state/workdir"
out="$(run_sut --keep --yes)"
if grep -q 'no dashboard unit named one' <<<"$out"
then ok "with no dashboard unit the default location is named as a guess"
else bad "the default location is named as a guess" "$(tail -6 <<<"$out")"; fi

echo
echo "── the flags reach the uninstaller ────────────────────────────────"

reset_state
run_sut --wipe --toolchain --yes >/dev/null
if grep -q 'args=--wipe --toolchain --yes' "$TMP/state/calls" 2>/dev/null
then ok "--wipe --toolchain --yes arrive in that order and unchanged"
else bad "the flags pass through" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

reset_state
run_sut --keep >/dev/null
if grep -q 'args=--keep$' "$TMP/state/calls" 2>/dev/null
then ok "--keep alone arrives alone, with no --yes invented beside it"
else bad "--keep is not embellished" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

# --role takes a value both ways round and reaches the uninstaller in the one
# form it parses.
reset_state
run_sut --role validator --keep --yes >/dev/null
if grep -q 'args=--role=validator --keep --yes' "$TMP/state/calls" 2>/dev/null
then ok "--role <value> is handed on as --role=<value>, which is what it parses"
else bad "--role is normalised" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

# --dir is consumed here and must NOT be passed on: the uninstaller has no
# such flag and would refuse the whole run with 'unknown argument'.
reset_state
run_sut --dir "$TMP/op/other-checkout" --keep --yes >/dev/null
if grep -q 'args=--keep --yes' "$TMP/state/calls" 2>/dev/null \
   && ! grep -q -- '--dir' "$TMP/state/calls"
then ok "--dir is consumed here and not handed on to a script with no such flag"
else bad "--dir is consumed" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

# The exit code is the uninstaller's. Its refusal is exit 2, and a bootstrap
# that flattened that to 0 would report a removal that never happened.
reset_state
printf '2\n' > "$TMP/state/uninstall-rc"
out="$(run_sut)"; rc=$?
if [[ $rc -eq 2 ]]
then ok "the uninstaller's exit code comes back out of this script unchanged"
else bad "the exit code is passed through" "exit $rc"; fi

# And the opposite, so the row above is not passing on a script that always
# fails.
reset_state
run_sut --keep --yes >/dev/null; rc=$?
if [[ $rc -eq 0 ]]
then ok "and a run that finished is exit 0"
else bad "a finished run exits 0" "exit $rc"; fi

# stdin is not redirected, because the question needs a keyboard. Under this
# harness there is none, and that is the point: what must not happen is this
# script closing it.
reset_state
run_sut --keep --yes >/dev/null
if grep -q '^TTY=' "$TMP/state/calls" 2>/dev/null
then ok "the uninstaller is run with whatever stdin this script had, not /dev/null"
else bad "stdin reaches the uninstaller" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi

reset_state
out="$(run_sut --nonsense)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'unknown argument' <<<"$out"
then ok "an unknown flag stops the run rather than being handed on"
else bad "an unknown flag is refused" "exit $rc"; fi

echo
echo "── an install older than the question ─────────────────────────────"

# The live failure, reproduced. A host installed from a release before
# --keep/--wipe existed carries an uninstall.sh that refuses them, so the
# handover ended with "unknown argument: --wipe" and exit 2 (aperire4,
# 2026-09-07). The fixture's old script is the control: run by hand it still
# refuses, so the rows below are fixing something.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
out="$(bash "$TMP/op/aperire-one/uninstall.sh" --wipe --yes 2>&1)"; rc=$?
if [[ $rc -eq 2 ]] && grep -q 'unknown argument: --wipe' <<<"$out"; then
  ok "the old uninstaller really does refuse --wipe, which is the bug being fixed"
else
  bad "the fixture reproduces the live failure" "exit $rc: $(tail -3 <<<"$out")"
fi
rm -f "$TMP/state/calls"
# --no-upgrade on an install like that has no safe form (#943): the only way
# left to run its uninstall.sh is as root out of the checkout, which this
# script no longer does. Refused by name, before sudo, with nothing run.
out="$(run_sut --no-upgrade --wipe --yes)"; rc=$?
if [[ $rc -ne 0 && "$out" == *"--no-upgrade rules out the current one"* && "$out" == *"predates the keep/wipe question"* \
      && ! -f "$TMP/state/calls" && ! -f "$TMP/state/sudo-exec" && ! -f "$TMP/state/curl-calls" ]]; then
  ok "--no-upgrade on an install whose uninstall.sh cannot be staged is refused by name, with no root call and no download"
else
  bad "--no-upgrade on an old install is refused" "exit $rc: $(tail -3 <<<"$out") sudo=$(cat "$TMP/state/sudo-exec" 2>/dev/null)"
fi

# And with the upgrade allowed, the same host uninstalls.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -eq 0 ]]; then
  ok "with the current uninstaller fetched, the same host uninstalls"
else
  bad "an older install uninstalls" "exit $rc: $(tail -6 <<<"$out")"
fi
if grep -q 'uninstall from=the-fetched-one args=--wipe --yes' "$TMP/state/calls" 2>/dev/null; then
  ok "and it is the FETCHED copy that ran, with the flags the old one refused"
else
  bad "the fetched copy is what runs" "$(cat "$TMP/state/calls" 2>/dev/null)"; fi
if grep -q "predates the keep/wipe question" <<<"$out" \
   && grep -q 'using the current one from https://example.invalid/uninstall.sh' <<<"$out"; then
  ok "and it says so on screen, with the address it took it from"
else
  bad "the replacement is announced" "$(tail -10 <<<"$out")"; fi
if grep -q 'script-fetch https://example.invalid/uninstall.sh' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "the uninstaller is fetched from beside this script, not from a guess"
else
  bad "the uninstaller is fetched" "$(cat "$TMP/state/curl-calls" 2>/dev/null)"; fi
if grep -q 'OLD uninstall' "$TMP/op/aperire-one/uninstall.sh" && ! grep -q -- '--wipe' "$TMP/op/aperire-one/uninstall.sh"; then
  ok "and the checkout's own uninstall.sh is left exactly as it was: nothing is written into the tree root would then run"
else
  bad "the checkout's uninstall.sh is not rewritten" "$(head -3 "$TMP/op/aperire-one/uninstall.sh")"; fi
fetched_self="$(sed -n 's/^self=\([^ ]*\) .*/\1/p' "$TMP/state/where" 2>/dev/null | head -1)"
if [[ -n "$fetched_self" && "$fetched_self" != "$TMP/op/"* && "$fetched_self" == */uninstall.sh ]] \
   && grep -q "tree=$TMP/op/aperire-one " "$TMP/state/where"; then
  ok "it ran from a directory outside the checkout, told which install it removes"
else
  bad "the fetched copy runs from outside the checkout" "where=$(cat "$TMP/state/where" 2>/dev/null)"; fi
if ! grep -q 'OLD uninstall' "$TMP/state/calls" 2>/dev/null; then
  ok "the old one is never run, not even once"
else
  bad "the old uninstaller does not run" "$(cat "$TMP/state/calls")"; fi
if grep -q 'downloads  the current uninstall.sh' <<<"$out"; then
  ok "and the plan says what it is about to download, rather than 'nothing'"
else
  bad "the plan is honest about the download" "$(grep -F 'downloads' <<<"$out")"; fi

# The other direction, and it is the quiet one: a host that is already current
# must not be overwritten and must fetch nothing at all.
reset_state
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
before="$(md5sum "$TMP/op/aperire-one/uninstall.sh" | cut -d' ' -f1)"
out="$(run_sut --wipe --yes)"; rc=$?
after="$(md5sum "$TMP/op/aperire-one/uninstall.sh" | cut -d' ' -f1)"
if [[ $rc -eq 0 && "$before" == "$after" ]]; then
  ok "an install that already understands the question is left exactly as it was"
else
  bad "a current install is not overwritten" "exit $rc, md5 $before -> $after"
fi
if ! grep -q 'script-fetch' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "and nothing is downloaded for it, which is what the plan claims"
else
  bad "a current install downloads nothing" "$(cat "$TMP/state/curl-calls")"; fi
if grep -q 'downloads  nothing' <<<"$out"; then
  ok "and the plan says so"
else
  bad "the plan says nothing is downloaded" "$(grep -F 'downloads' <<<"$out")"; fi

# A copy that arrives short is refused, and NOTHING runs. This is the whole
# reason uninstall.sh carries a sentinel now: it is a flat script, so a
# truncated copy runs its top half, and the top half of that one removes
# things.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
head -n 200 "$REPO_DIR/uninstall.sh" > "$TMP/state/served-uninstall"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'did not arrive whole' <<<"$out"; then
  ok "a truncated uninstall.sh is refused by its own last line"
else
  bad "a truncated fetch is refused" "exit $rc: $(tail -4 <<<"$out")"; fi
if ! grep -q 'uninstall from=' "$TMP/state/calls" 2>/dev/null; then
  ok "and nothing is run: not the truncated copy, and not the old one either"
else
  bad "nothing runs after a truncated fetch" "$(cat "$TMP/state/calls")"; fi
if ! grep -q -- '--wipe' "$TMP/op/aperire-one/uninstall.sh"; then
  ok "and the checkout still holds the file it had, not half of another"
else
  bad "a truncated copy is not installed" "the checkout was overwritten"; fi

# An endpoint serving a whole but OLD uninstall.sh. Installing that would swap
# one script that refuses --wipe for another, and then hand it --wipe.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
{ printf '#!/usr/bin/env bash\necho stale\n'; printf '%s\n' '# --- end of uninstall.sh ---'; } > "$TMP/state/served-uninstall"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'does not understand --keep or --wipe either' <<<"$out"; then
  ok "a whole but stale copy is refused, and the endpoint is named as the problem"
else
  bad "a stale served copy is refused" "exit $rc: $(tail -4 <<<"$out")"; fi
if ! grep -q 'uninstall from=' "$TMP/state/calls" 2>/dev/null; then
  ok "with nothing run for that either"
else
  bad "nothing runs after a stale fetch" "$(cat "$TMP/state/calls")"; fi

# The endpoint being unreachable is a refusal, not a fall-through to the old
# script with flags it cannot take.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
rm -f "$TMP/state/served-uninstall"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'could not fetch' <<<"$out" \
   && grep -q 'nothing was removed' <<<"$out"; then
  ok "an endpoint that does not answer is a refusal that says nothing was removed"
else
  bad "an unreachable endpoint refuses" "exit $rc: $(tail -4 <<<"$out")"; fi
if ! grep -q 'uninstall from=' "$TMP/state/calls" 2>/dev/null; then
  ok "and, again, nothing ran"
else
  bad "nothing runs when the fetch fails" "$(cat "$TMP/state/calls")"; fi

echo
echo "── the fetched uninstall.sh is the one the release signed (#762) ──"

# What runs as root on this path is a download. Until #762 it was checked for
# its last line and two words, so an endpoint that served a different
# uninstall.sh beside a genuine bootstrap had root run it. Every row serves a
# copy that passes every other check, so the signature is all that can stop it.
no_fetched_run() { ! grep -q 'uninstall from=' "$TMP/state/calls" 2>/dev/null && [[ ! -f "$TMP/state/TAMPERED-RAN" ]]; }

reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'uninstall from=the-fetched-one args=--wipe --yes' "$TMP/state/calls" 2>/dev/null \
   && grep -q 'signed by the release key: release cccccccccccc' <<<"$out"; then
  ok "signed: the fetched uninstall.sh is the one the signed release names, so it runs, and says so"
else
  bad "a signed fetched uninstaller runs" "exit $rc: $(tail -6 <<<"$out")"; fi
if grep -q "release-fetch https://example.invalid/release-c\{64\}\.json$" "$TMP/state/curl-calls" 2>/dev/null \
   && grep -q "release-fetch https://example.invalid/release-c\{64\}\.json\.sig$" "$TMP/state/curl-calls" 2>/dev/null; then
  ok "  and the signed release.json and its signature were fetched under the names that never change"
else
  bad "the signed pair is fetched by its immutable names" "$(cat "$TMP/state/curl-calls" 2>/dev/null)"; fi
if grep -q 'rd-verify-uninstaller /usr/local/lib/aperire\|rd-verify-uninstaller '"$TMP"'/rootlib' "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "  and root did the check, against root's own key set"
else
  bad "root checks the signature" "$(cat "$TMP/state/sudo-exec" 2>/dev/null)"; fi

# A changed download. Whole, current, understands --wipe and the install
# variable, ends with the sentinel: everything but the bytes the release signed.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/signed-uninstaller" "the-fetched-one"
sed "2i echo TAMPERED >> '$TMP/state/TAMPERED-RAN'" "$TMP/state/signed-uninstaller" > "$TMP/state/served-uninstall"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'is not the one the signed release names, so it was not run. Nothing was removed.' <<<"$out" && no_fetched_run; then
  ok "a changed uninstall.sh beside a genuine release is refused by its signed sum, and never run"
else
  bad "a tampered uninstall.sh is refused" "exit $rc: $(tail -5 <<<"$out") calls=$(cat "$TMP/state/calls" 2>/dev/null)"; fi

for mode in tampered stranger; do
  reset_state
  make_old_install "$TMP/op/aperire-one" "the-old-one"
  write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
  echo "$mode" > "$TMP/state/sig-mode"
  out="$(run_sut --wipe --yes)"; rc=$?
  if [[ $rc -ne 0 ]] && grep -q 'is not signed by a key this host trusts, so the uninstall.sh beside it was not run' <<<"$out" && no_fetched_run; then
    ok "a release whose signature does not verify ($mode) is refused, and its uninstall.sh never run"
  else
    bad "a bad signature ($mode) is refused" "exit $rc: $(tail -6 <<<"$out")"; fi
done

for mode in missing unsigned; do
  reset_state
  make_old_install "$TMP/op/aperire-one" "the-old-one"
  write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
  echo "$mode" > "$TMP/state/sig-mode"
  out="$(run_sut --wipe --yes)"; rc=$?
  if [[ $rc -ne 0 ]] && grep -q 'serves no signed release.json for the release it names' <<<"$out" && no_fetched_run; then
    ok "an endpoint with no signed release ($mode) gets its uninstall.sh refused, never run"
  else
    bad "no signature ($mode) is refused" "exit $rc: $(tail -5 <<<"$out")"; fi
done

# A genuine, validly signed release, served under the name of another one.
# Its signature is good and its uninstaller sum matches; only the archive it
# names is wrong, so only the tie between the two files can refuse it.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
echo other-archive > "$TMP/state/sig-mode"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'the signed release.json names the archive d\{64\}, and release.json names c\{64\}' <<<"$out" && no_fetched_run; then
  ok "a signed release for a different archive than release.json names is refused, and its uninstall.sh never run"
else
  bad "a signed release for another archive is refused" "exit $rc: $(tail -6 <<<"$out")"; fi

# A host with no release key: nothing to check the download against.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
mkdir -p "$TMP/rootlib-nokey"; chmod 0755 "$TMP/rootlib-nokey"
cp -p "$TMP/rootlib/release-digests-lib.sh" "$TMP/rootlib/trusted-path-lib.sh" "$TMP/rootlib-nokey/"
out="$(ROOTLIB_FOR_RUN="$TMP/rootlib-nokey" run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no release key root can check the current uninstall.sh against' <<<"$out" \
   && grep -q 'Update the install first' <<<"$out" && no_fetched_run; then
  ok "a host with no release key is told to update first, and runs nothing it fetched"
else
  bad "no key refuses" "exit $rc: $(tail -5 <<<"$out")"; fi
# The verifier without a key set, and a key set another account can write:
# root's check holds the signer set to what it holds the libraries to.
for shape in nosigners writable; do
  reset_state
  make_old_install "$TMP/op/aperire-one" "the-old-one"
  write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
  rm -rf "$TMP/rootlib-$shape"; cp -rp "$TMP/rootlib" "$TMP/rootlib-$shape"
  if [[ $shape == nosigners ]]; then rm -f "$TMP/rootlib-$shape/release-signers"; else chmod 0666 "$TMP/rootlib-$shape/release-signers"; fi
  out="$(ROOTLIB_FOR_RUN="$TMP/rootlib-$shape" run_sut --wipe --yes)"; rc=$?
  if [[ $rc -ne 0 ]] && grep -q 'no release key root can check the current uninstall.sh against' <<<"$out" && no_fetched_run; then
    ok "a key set root cannot trust ($shape) is no key at all: refused, nothing fetched is run"
  else
    bad "an untrustworthy key set ($shape) refuses" "exit $rc: $(tail -5 <<<"$out")"; fi
done

# The sentinel is only a guard while it is the last line of the file it
# guards, and that file is in another directory entirely.
if [[ "$(tail -n 1 "$REPO_DIR/uninstall.sh")" == '# --- end of uninstall.sh ---' ]]; then
  ok "uninstall.sh still ends with the line this script checks for"
else
  bad "uninstall.sh carries its sentinel" "$(tail -n 1 "$REPO_DIR/uninstall.sh")"; fi

echo
echo "── a copy that arrived short ──────────────────────────────────────"

# Guard 2: everything is a function and main is the last line. A copy cut
# anywhere above it defines its functions and does nothing.
reset_state
head -n 200 "$SUT" > "$TMP/cut.sh"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_UNINSTALL_GET_REEXEC=1 bash "$TMP/cut.sh" --wipe --yes 2>&1 )"; rc=$?
# The exit code is not the promise and must not be asserted: a cut that lands
# inside a heredoc is a parse error and a cut between functions runs to the
# missing `main` call. Both run nothing, which is the whole guarantee.
if [[ ! -f "$TMP/state/calls" ]]
then ok "a copy cut in the middle removes nothing (exit $rc, either way)"
else bad "a cut copy removes nothing" "exit $rc, calls: $(cat "$TMP/state/calls" 2>/dev/null)"; fi

# Guard 1: a piped run re-fetches itself and checks the sentinel. A whole copy
# is exec'd; a truncated one is not, and the run continues from the pipe.
reset_state
cp "$SUT" "$TMP/state/self"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_UNINSTALL_GET_SELF_URL="https://example.invalid/uninstall" \
        FAKE_ROOTLIB_MAP="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
        bash -c "cat '$SUT' | bash -s -- --keep --yes" 2>&1 )"
if grep -q 'self-fetch' "$TMP/state/curl-calls" 2>/dev/null
then ok "a piped run fetches itself to a file before running"
else bad "a piped run re-fetches itself" "$(cat "$TMP/state/curl-calls" 2>/dev/null)"; fi
if grep -q 'from=the-real-one' "$TMP/state/calls" 2>/dev/null
then ok "and a whole copy runs through to the uninstaller"
else bad "a whole re-fetched copy runs" "$(tail -4 <<<"$out")"; fi

reset_state
head -n 40 "$SUT" > "$TMP/state/self"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_UNINSTALL_GET_SELF_URL="https://example.invalid/uninstall" \
        FAKE_ROOTLIB_MAP="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
        bash -c "cat '$SUT' | bash -s -- --keep --yes" 2>&1 )"
if grep -q 'arrived without its last line' <<<"$out"
then ok "a truncated re-fetch is refused by the sentinel, and says so"
else bad "a truncated re-fetch is refused" "$(head -4 <<<"$out")"; fi

# The sentinel is only a guard while it is the last line.
if [[ "$(tail -n 1 "$SUT")" == '# --- end of get-aperire-uninstall.sh ---' ]]
then ok "the script still ends with the sentinel a piped run checks for"
else bad "the sentinel is the last line" "$(tail -n 1 "$SUT")"; fi

echo
echo "── root runs a staged copy, never the checkout's own (#943) ───────"

# The handover used to be `bash "$DIR/uninstall.sh"` under sudo: root running
# the one file in the install a login can rewrite, and the last thing run on a
# host the operator is trusting to come clean. Now the install's scripts are
# staged against root's own checking libraries and the staged uninstall.sh
# runs, told which install it removes.
reset_state
APERIRE_LEAK=leaked run_sut --keep --yes >/dev/null; rc=$?
staged_self="$(sed -n 's/^self=\([^ ]*\) .*/\1/p' "$TMP/state/where" 2>/dev/null | head -1)"
if [[ $rc -eq 0 && -n "$staged_self" && "$staged_self" != "$TMP/op/"* && "$staged_self" == */run/uninstall.sh ]]; then
  ok "what root ran is the staged uninstall.sh, in a directory outside the install"
else
  bad "root runs the staged uninstall.sh" "rc=$rc where=$(cat "$TMP/state/where" 2>/dev/null)"
fi
if grep -q "tree=$TMP/op/aperire-one " "$TMP/state/where" 2>/dev/null; then
  ok "  told which install it removes, because it no longer sits in it"
else
  bad "the staged uninstaller is told its install" "where=$(cat "$TMP/state/where" 2>/dev/null)"
fi
if grep -q 'leak=unset' "$TMP/state/where" 2>/dev/null; then
  ok "  under the environment sudo leaves it: nothing the caller exported crosses"
else
  bad "the uninstaller runs in sudo's environment" "where=$(cat "$TMP/state/where" 2>/dev/null)"
fi
if grep -qE "bash [^ ]*/run/uninstall\.sh" "$TMP/state/sudo-exec" 2>/dev/null \
   && ! grep -qE "bash \"?$TMP/op/aperire-one/uninstall\.sh" "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "  and no root call names the checkout's uninstall.sh to run"
else
  bad "no root call runs the checkout's uninstall.sh" "$(cat "$TMP/state/sudo-exec" 2>/dev/null)"
fi
reset_state
out="$(run_sut --keep --yes)"
if [[ "$out" == *"running    a checked copy of"* ]]; then
  ok "  and the plan says it is a checked copy"
else
  bad "the plan names the checked copy" "$(grep -F 'running' <<<"$out")"
fi

# --no-upgrade means no download, and a current install needs none.
reset_state
run_sut --no-upgrade --keep --yes >/dev/null; rc=$?
staged_self="$(sed -n 's/^self=\([^ ]*\) .*/\1/p' "$TMP/state/where" 2>/dev/null | head -1)"
if [[ $rc -eq 0 && "$staged_self" == */run/uninstall.sh && ! -f "$TMP/state/curl-calls" ]]; then
  ok "--no-upgrade on a current install runs the staged copy and downloads nothing"
else
  bad "--no-upgrade on a current install" "rc=$rc where=$(cat "$TMP/state/where" 2>/dev/null)"
fi

# A file in the install that is not the one its release shipped: refused,
# named, and the uninstaller never runs (the digest is the release's, not the
# tree's).
reset_state
{ printf '# anchor a fixture\n'
  (cd "$TMP/op/aperire-one" && for f in install.sh uninstall.sh; do
     printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"; done)
} > "$TMP/record"
chmod 0644 "$TMP/record"
printf '#!/usr/bin/env bash\n# --wipe APERIRE_INSTALL_TREE\necho "TREE RAN" >> "%s/state/TREE-RAN"\n' "$TMP" > "$TMP/op/aperire-one/uninstall.sh"
out="$(RECORD_FOR_RUN="$TMP/record" run_sut --keep --yes)"; rc=$?
if [[ $rc -ne 0 && ! -f "$TMP/state/TREE-RAN" && ! -f "$TMP/state/calls" ]] \
   && grep -q 'refused: uninstall.sh is not the file this release shipped' <<<"$out" \
   && grep -q 'Nothing was removed' <<<"$out"; then
  ok "an uninstall.sh changed after its release was recorded is refused by its digest and never run by root"
else
  bad "a changed uninstall.sh is never run by root" "rc=$rc ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null) $(tail -4 <<<"$out")"
fi
# And the same record with the file as shipped: the control, so the row above
# is red because of the change and not because of the record.
reset_state
{ printf '# anchor a fixture\n'
  (cd "$TMP/op/aperire-one" && for f in install.sh uninstall.sh; do
     printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"; done)
} > "$TMP/record"
RECORD_FOR_RUN="$TMP/record" run_sut --keep --yes >/dev/null; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'from=the-real-one' "$TMP/state/calls" 2>/dev/null; then
  ok "  while the file as released, against the same record, is staged and run"
else
  bad "an unchanged uninstall.sh passes its record" "rc=$rc"
fi

# Without root's own copy of the checking libraries there is nothing to judge
# the install by, so nothing out of it is run as root, and the way back says so.
# The way back is --update --force (#982): a plain --update on a host already
# on the published release answers "nothing on this host was touched" and
# puts nothing back.
reset_state
mv "$TMP/rootlib/trusted-path-lib.sh" "$TMP/rootlib/away"
out="$(run_sut --keep --yes)"; rc=$?
mv "$TMP/rootlib/away" "$TMP/rootlib/trusted-path-lib.sh"
if [[ $rc -ne 0 && ! -f "$TMP/state/calls" ]] && grep -q 'no root-owned copy of' <<<"$out" \
   && grep -q 'Nothing was removed' <<<"$out" && grep -qF -- 'bash -s -- --update --force' <<<"$out"; then
  ok "a host with no root-owned checking library runs no uninstaller as root, and is told the update that puts it back"
else
  bad "the stage needs root's own libraries" "rc=$rc ran=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi

# An uninstall.sh that knows keep/wipe but was written before staged runs would
# take the staging directory for the install. Treated like the older one: the
# current copy is fetched and run from a root-held directory.
reset_state
cat > "$TMP/op/aperire-one/uninstall.sh" <<OLD2
#!/usr/bin/env bash
# --keep --wipe --toolchain --role= --yes, from before staged runs.
printf '%s\n' "OLD2 uninstall args=\$*" >> "$TMP/state/calls"
exit 0
OLD2
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -eq 0 && "$out" == *"predates staged runs"* ]] && grep -q 'from=the-fetched-one' "$TMP/state/calls" \
   && ! grep -q 'OLD2' "$TMP/state/calls"; then
  ok "an uninstall.sh from before staged runs is replaced by the fetched one, and the old one never runs"
else
  bad "a pre-staging uninstall.sh is replaced" "rc=$rc $(tail -4 <<<"$out") calls=$(cat "$TMP/state/calls" 2>/dev/null)"
fi
# The fetched copy has to be one that takes its install from the environment;
# a stale endpoint serving the keep/wipe one is named, and nothing runs.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
{ printf '#!/usr/bin/env bash\n# --keep --wipe only\necho stale\n'; printf '%s\n' '# --- end of uninstall.sh ---'; } > "$TMP/state/served-uninstall"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 && "$out" == *"does not take the install it removes from APERIRE_INSTALL_TREE"* && ! -f "$TMP/state/calls" ]]; then
  ok "a fetched copy that cannot be told its install is refused, with nothing run"
else
  bad "a fetched copy without the install variable is refused" "rc=$rc $(tail -3 <<<"$out")"
fi

# The fetched copy keeps the helper the dashboard hand-back plants with. A host
# older than this change is exactly the one with a dashboard account of its own
# and a database in a directory that account owns; without the helper the
# account is removed and the files stay owned by it (#943 review).
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
run_sut --wipe --yes >/dev/null; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'self=.*/run/uninstall.sh .*helper=beside' "$TMP/state/where" 2>/dev/null; then
  ok "the fetched uninstall.sh runs beside the install's staged state helper, so the dashboard hand-back still has it"
else
  bad "the fetched copy has the staged state helper beside it" "rc=$rc where=$(cat "$TMP/state/where" 2>/dev/null)"
fi
# No root-owned libraries on an old host: the install cannot be staged, and the
# fetched copy runs on its own, which runs no code from the install. It warns.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
mv "$TMP/rootlib/trusted-path-lib.sh" "$TMP/rootlib/away"
out="$(run_sut --wipe --yes)"; rc=$?
mv "$TMP/rootlib/away" "$TMP/rootlib/trusted-path-lib.sh"
if [[ $rc -eq 0 && "$out" == *"runs on its own"* ]] && grep -q 'from=the-fetched-one' "$TMP/state/calls" 2>/dev/null \
   && grep -q 'helper=none' "$TMP/state/where" && ! grep -q 'OLD uninstall' "$TMP/state/calls"; then
  ok "an old host with no root-owned libraries still uninstalls: the fetched copy runs alone, and says so"
else
  bad "an old host with no root libraries uninstalls" "rc=$rc $(tail -4 <<<"$out") where=$(cat "$TMP/state/where" 2>/dev/null)"
fi
# The same with a file that fails its record: refused for the stage, but the
# fetched copy (which runs nothing of the install's) still goes.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
{ printf '# anchor a fixture\n'
  (cd "$TMP/op/aperire-one" && for f in install.sh uninstall.sh scripts/state-file.py; do
     printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"; done)
} > "$TMP/record"
chmod 0644 "$TMP/record"
printf 'import os\n# changed after the release was recorded\n' > "$TMP/op/aperire-one/scripts/state-file.py"
out="$(RECORD_FOR_RUN="$TMP/record" run_sut --wipe --yes)"; rc=$?
if [[ $rc -eq 0 && "$out" == *"is not the file this release shipped"* ]] && grep -q 'helper=none' "$TMP/state/where" 2>/dev/null \
   && grep -q 'from=the-fetched-one' "$TMP/state/calls"; then
  ok "a changed state helper in an old install is refused for the stage, never run, and the fetched copy still uninstalls"
else
  bad "a refused stage on an old host" "rc=$rc $(tail -5 <<<"$out") where=$(cat "$TMP/state/where" 2>/dev/null)"
fi

# ── The review round (#943): the check reads what root runs, the login picks
# no path root sources, and the fetched copy is judged where it is run from.

# L1. The probe read the checkout's file; root runs the staged one, a separate
# read. A file swapped between the two puts an older program in the stage that
# takes the stage for the install. The staged copy is judged after staging.
reset_state
printf 'uninstall.sh\n' > "$TMP/state/tamper-before-stage"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 && ! -f "$TMP/state/TREE-RAN" && ! -f "$TMP/state/calls" ]] \
   && grep -q 'older than the one that was read first' <<<"$out" && grep -q 'Nothing was removed' <<<"$out"; then
  ok "an uninstall.sh swapped for an older one between the probe and the stage is refused on the staged copy, and never run"
else
  bad "the staged copy is judged after staging" "rc=$rc ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null) calls=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi

# L2. The bootstrap normally runs as the login, so nothing the login's
# environment says may choose the directory root sources. The product has no
# variable and no switch for it; the old pair (APERIRE_UNINSTALL_GET_TESTING
# with APERIRE_UNINSTALL_GET_ROOT_LIB_DIR) set in the login's environment
# changes nothing root runs. Here root's directory is the (empty) constant and
# the old variables point at a good fixture; root must still find no libraries.
reset_state
out="$(ROOTLIB_FOR_RUN="$TMP/no-such-rootlib" LOGIN_LIBVARS_FOR_RUN=1 run_sut --keep --yes)"; rc=$?
if [[ $rc -ne 0 && ! -f "$TMP/state/calls" ]] && grep -q 'no root-owned copy of the checking libraries in /usr/local/lib/aperire' <<<"$out" \
   && ! grep -q -e "$TMP/rootlib" "$TMP/state/sudo-exec"; then
  ok "the old test variables in the login's environment change nothing: root looks in /usr/local/lib/aperire, never names the fixture, and runs nothing"
else
  bad "the library directory is a constant for the login" "rc=$rc ran=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi
# The directory, or a library in it, being a link is refused by root's own
# check on the path it then sources, which does not follow a link.
reset_state
ln -s "$TMP/rootlib" "$TMP/rootlink"
out="$(ROOTLIB_FOR_RUN="$TMP/rootlink" run_sut --keep --yes)"; rc=$?
if [[ $rc -ne 0 && ! -f "$TMP/state/calls" ]] && grep -q 'no root-owned copy of the checking libraries' <<<"$out"; then
  ok "a library directory that is a symlink is refused by root's check, not followed"
else
  bad "a symlinked library directory is refused" "rc=$rc ran=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi
rm -f "$TMP/rootlink"
reset_state
mkdir -p "$TMP/rootlib2"; chmod 0755 "$TMP/rootlib2"
cp "$TMP/rootlib/release-digests-lib.sh" "$TMP/rootlib2/"; ln -s "$TMP/rootlib/trusted-path-lib.sh" "$TMP/rootlib2/trusted-path-lib.sh"
out="$(ROOTLIB_FOR_RUN="$TMP/rootlib2" run_sut --keep --yes)"; rc=$?
if [[ $rc -ne 0 && ! -f "$TMP/state/calls" ]] && grep -q 'no root-owned copy of the checking libraries' <<<"$out"; then
  ok "a library that is a symlink is refused by root's check, not followed"
else
  bad "a symlinked library is refused" "rc=$rc ran=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi
rm -rf "$TMP/rootlib2"
reset_state
chmod g+w "$TMP/rootlib/release-digests-lib.sh"
out="$(run_sut --keep --yes)"; rc=$?
chmod g-w "$TMP/rootlib/release-digests-lib.sh"
if [[ $rc -ne 0 && ! -f "$TMP/state/calls" ]] && grep -q 'no root-owned copy of the checking libraries' <<<"$out"; then
  ok "a library another account can write is refused by root's check"
else
  bad "a group-writable library is refused" "rc=$rc ran=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi

# L3. The fetched file is the login's, in /tmp. It is copied into root's
# directory first and every check reads that copy, so the bytes checked are the
# bytes run. Rewritten just before the copy, it is the copy that is judged (and
# refused here); rewritten after the copy, it changes nothing.
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "uninstall from=the-swapped-one args=$*" >> "%s/state/calls"\nexit 0\n' "$TMP" > "$TMP/state/tampered-uninstall"
: > "$TMP/state/tamper-before-install"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -ne 0 ]] && ! grep -q 'the-swapped-one' "$TMP/state/calls" 2>/dev/null \
   && grep -q 'did not arrive whole' <<<"$out"; then
  ok "a fetched file rewritten before root copies it is checked as the copy root holds, refused, and never run"
else
  bad "the checks read root's copy" "rc=$rc calls=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi
reset_state
make_old_install "$TMP/op/aperire-one" "the-old-one"
write_uninstaller "$TMP/state/served-uninstall" "the-fetched-one"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "uninstall from=the-swapped-one args=$*" >> "%s/state/calls"\nexit 0\n# --- end of uninstall.sh ---\n' "$TMP" > "$TMP/state/tampered-uninstall"
: > "$TMP/state/tamper-after-install"
out="$(run_sut --wipe --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'from=the-fetched-one' "$TMP/state/calls" 2>/dev/null && ! grep -q 'the-swapped-one' "$TMP/state/calls"; then
  ok "  and the file in /tmp rewritten after the copy changes nothing: the copy that was checked is the copy that runs"
else
  bad "the /tmp file is not what runs" "rc=$rc calls=$(cat "$TMP/state/calls" 2>/dev/null) $(tail -3 <<<"$out")"
fi

echo
echo "── refusing before it can do damage ───────────────────────────────"

# A root-only login owns none of this: not the checkout, not the database, not
# the aperire commands on some other account's PATH. An uninstall started
# there takes the units off and leaves those commands behind.
reset_state
printf 'root\n' > "$TMP/state/whoami"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME=/root TERM=dumb \
        FAKE_ROOTLIB_MAP="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
        APERIRE_UNINSTALL_GET_REEXEC=1 bash "$SUT" --keep --yes 2>&1 )"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'run this from the account that owns the install' <<<"$out"
then ok "a root-only login is refused, and told which account to use"
else bad "a root-only login is refused" "exit $rc: $(tail -4 <<<"$out")"; fi
if [[ ! -f "$TMP/state/calls" ]]
then ok "and no uninstaller runs on the way to that refusal"
else bad "the root refusal removes nothing" "$(cat "$TMP/state/calls")"; fi

# The same run under sudo, which is a root run that belongs to somebody. This
# is the row that keeps the guard above from refusing the documented way to
# do this: `curl -fsSL <url> | sudo bash`.
reset_state
printf 'root\n' > "$TMP/state/whoami"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME=/root TERM=dumb \
        FAKE_ROOTLIB_MAP="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
        SUDO_USER=op APERIRE_UNINSTALL_GET_REEXEC=1 bash "$SUT" --keep --yes 2>&1 )"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'from=the-real-one' "$TMP/state/calls" 2>/dev/null
then ok "and the same run under sudo goes through, because it belongs to an operator"
else bad "sudo is not refused by the root guard" "exit $rc: $(tail -4 <<<"$out")"; fi

# And a root HOME is not an identity: with the unit naming an install, that
# is the install, not /root.
reset_state
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME=/root TERM=dumb \
        FAKE_ROOTLIB_MAP="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
        APERIRE_UNINSTALL_GET_REEXEC=1 bash "$SUT" --keep --yes 2>&1 )"; rc=$?
if [[ $rc -eq 0 ]] && grep -q "install    $TMP/op/aperire-one " <<<"$out"
then ok "a root HOME does not outrank the dashboard unit"
else bad "the unit outranks HOME" "exit $rc: $(grep -F 'install ' <<<"$out")"; fi

echo
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
