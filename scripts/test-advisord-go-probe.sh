#!/usr/bin/env bash
# Exercise how scripts/install-advisord.sh finds Go, and what it says when it
# cannot.
#
# What is being protected: the failure from the first live Advisor ceremony
# (2026-09-01). prepare-host.sh installs the pinned Go into /usr/local/go and
# puts it on PATH through /etc/profile.d, which only an interactive login shell
# reads. install-advisord runs under sudo, whose PATH has none of that, so
# `command -v go` reported "not installed" on a box holding a perfectly good Go
# in the place this project itself put it. Three promises:
#
#   1. Go in the pinned location is found, even when it is on no PATH.
#   2. The remedy names prepare-host.sh, which owns the toolchain. It must not
#      name apt: apt's Go can be older than the minimum this project builds
#      with, and a second owner of the toolchain is how a host ends up with two.
#   3. Prebuilt binaries are still honoured with no Go at all, because a fleet
#      operator should not need a compiler on every node.
#
#   bash scripts/test-advisord-go-probe.sh
#
# Runs against fake `go` binaries in a temporary tree. Builds nothing and
# installs nothing. It needs no root; the last block runs the build step under
# fakeroot, to show whose account each binary is built as (#1136).
#
# THE ONE MODIFICATION. install-advisord.sh continues past the build into
# writing a unit and starting a service, which is not what these rows are
# about. So the success rows run a scratch copy cut off immediately after the
# build block, and a row asserts the cut landed where it was meant to. The
# refusal row runs the file UNMODIFIED, because that path exits inside the
# block itself.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIG="$REPO_DIR/scripts/install-advisord.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }
ents()  { find "$1" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | LC_ALL=C sort | tr '\n' ' '; }
nents() { find "$1" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' '; }

[[ -f "$ORIG" ]] || { echo "no install-advisord.sh at $ORIG"; exit 1; }

mkdir -p "$TMP/tree/scripts" "$TMP/tree/advisor/bin" "$TMP/pinned/bin" "$TMP/onpath" "$TMP/login"

# ── The scratch copy, cut after the build ───────────────────────────
# The build block ends with the `fi` that closes the "no Go" alternative. It is
# found from the executor build inside it rather than by counting `fi` lines
# from the top, which finds the argument check near line 27 and cuts the whole
# probe off. A cut that lands in the wrong place must be loud, so the first row
# below asserts what survived it.
BUILD_LINE=$(grep -n '^build_as_user aperire-executor ' "$ORIG" | head -1 | cut -d: -f1)
[[ -n "$BUILD_LINE" ]] || { echo "cannot find the executor build in $ORIG"; exit 1; }
CUT_LINE=$(awk -v start="$BUILD_LINE" 'NR>start && /^fi$/ {print NR; exit}' "$ORIG")
[[ -n "$CUT_LINE" ]] || { echo "cannot find the end of the build block in $ORIG"; exit 1; }
SUT="$TMP/tree/scripts/install-advisord.sh"
{ head -n "$CUT_LINE" "$ORIG"; printf 'echo "CUT: reached the end of the build block"\n'; } > "$SUT"
chmod +x "$SUT"

# The installer refuses to run without every file it sources (#142: one place
# tells a refused docker answer from an absence), and a fixture that only
# copied docker-ask-lib.sh by name went missing docker-ask-lib.sh, then
# missing advisord-credcheck-lib.sh and advisord-restart-lib.sh (#541) the
# moment the installer picked up a second and third lib, each one silently
# failing every row here for a reason that had nothing to do with Go. The
# fixture now reads every "$REPO/scripts/..." (and, since #764, every
# "$ADV_SELF/...") the cut copy names and copies
# whatever is there, so the next file the installer reaches for arrives beside
# it without anyone having to remember to add a line here. The real files are
# copied in rather than stubbed, because a stub of one is a fixture asserting
# itself.
#
# Every reference, not only the `. ` source lines: #661 added a check for
# scripts/state-file.py, which the installer runs rather than sources, and the
# source-only version of this loop failed nine rows here for a reason that had
# nothing to do with Go, exactly as the two before it did.
# shellcheck disable=SC2016  # matching the literal, unexpanded path
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  [[ -r "$REPO_DIR/scripts/$f" ]] || continue
  cp "$REPO_DIR/scripts/$f" "$TMP/tree/scripts/$f"
done < <(grep -oE '\$(REPO/scripts|ADV_SELF)/[A-Za-z0-9_.-]+' "$SUT" | sed -E 's#.*/##' | sort -u)

echo
echo "── the copy under test is the real probe ──────────────────────────"

if grep -q 'find_go()' "$SUT" && grep -q 'Using the prebuilt binaries' "$SUT"; then
  ok "the cut copy still holds the whole Go probe and both of its branches"
else
  bad "the cut kept the probe" "cut at line $CUT_LINE of $(wc -l < "$ORIG")"
fi
# Comments stripped first: the header's "To undo" note names systemctl in
# prose, and a row that counted that would be measuring the wrong thing. What
# matters is that no row here can RUN one. A read of a unit's state
# (is-enabled, is-active) changes nothing, and the #893 leftover check makes
# two of them before the build, so only a systemctl that is not one of those
# reads counts.
# shellcheck disable=SC2016  # the pattern matches the literal text $UNIT_NAME
svc_work="$(grep -v '^\s*#' "$SUT" | grep -n 'systemctl' | grep -vE 'systemctl is-(enabled|active) "\$UNIT_NAME"' || true)"
if [[ -z "$svc_work" ]]; then
  ok "and nothing past the build runs, so no row here can touch a service"
else
  bad "the cut removed the service work" "$(head -2 <<<"$svc_work")"
fi

# ── Fake toolchains ─────────────────────────────────────────────────
mkgo() { # $1 = path, $2 = version string
  mkdir -p "$(dirname "$1")"
  # A build writes the file -o names, because the installer builds to a scratch
  # name and renames it into place (#1136); a fake that wrote nothing would
  # leave the rename with nothing to move.
  cat > "$1" <<FAKEGO
#!/usr/bin/env bash
case "\$1" in
  version) echo "go version go$2 linux/amd64" ;;
  build) while [[ \$# -gt 0 ]]; do
           if [[ "\$1" == -o ]]; then : > "\$2"; chmod +x "\$2"; fi
           shift
         done
         exit 0 ;;
esac
exit 0
FAKEGO
  chmod +x "$1"
}
# The pinned location the real prepare-host uses, relocated for the test.
mkgo "$TMP/pinned/bin/go" 1.23.4
mkgo "$TMP/onpath/go" 1.24.0

# `sudo` is called by the probe for the login-shell candidate. It runs the
# rest here, so a login shell that has Go can be simulated by putting one on
# the PATH that fake inherits.
cat > "$TMP/bin-sudo" <<'EOF'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  case "$1" in -H|-E) shift ;; -u) shift 2 ;; *) break ;; esac
done
exec "$@"
EOF
mkdir -p "$TMP/shim"; mv "$TMP/bin-sudo" "$TMP/shim/sudo"; chmod +x "$TMP/shim/sudo"
# "No Go on PATH" has to be true on the host running this test too. The
# rows keep /usr/bin on PATH for their own tools, and GitHub's Ubuntu image
# has /usr/bin/go, so the probe found a Go the rows said was absent (CI,
# 2026-09-07). The shim is first on every PATH below; a go there that fails
# is what the probe sees, and a candidate whose "version" fails is skipped,
# which is the same as no Go. The on-PATH row puts its working go AHEAD of
# the shim, so that row still finds one.
printf '#!/usr/bin/env bash\nexit 1\n' > "$TMP/shim/go"; chmod +x "$TMP/shim/go"

# The probe reads /usr/local/go/bin/go by absolute path, which a test cannot
# write to. So the copy has that one path pointed at the fixture, and a row
# asserts the ORIGINAL names the real one.
sed -i "s#/usr/local/go/bin/go#$TMP/pinned/bin/go#" "$SUT"

run_sut() { # $1 = PATH to run with
  ( cd "$TMP/tree" && env -i PATH="$1" HOME="$TMP/home" \
      SUDO_USER="$(id -un)" TERM=dumb bash "$SUT" 2>&1 )
}

echo
echo "── Go where prepare-host puts it, and on no PATH at all ───────────"

if grep -q '^\s*for cand in /usr/local/go/bin/go' "$ORIG"; then
  ok "the real script probes /usr/local/go/bin/go, the pinned location"
else
  bad "the pinned location is probed" "$(grep -n 'for cand in' "$ORIG" | head -1)"
fi

rm -f "$TMP/tree/advisor/bin/"*
out="$(run_sut "$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'CUT:' <<<"$out"; then
  ok "with Go ONLY in the pinned location it builds, rather than refusing"
else
  bad "the pinned Go is found" "exit $rc: $(tail -4 <<<"$out")"
fi
if grep -q "with $TMP/pinned/bin/go (go1.23.4)" <<<"$out"; then
  ok "and it says which Go it used, so a wrong one is visible in the log"
else
  bad "it names the Go it used" "$(grep -i 'with ' <<<"$out" | head -2)"
fi

# The negative control for the row above: this is the state the live failure
# was in, and without the fix it is a refusal.
rm -f "$TMP/tree/advisor/bin/"*
mv "$TMP/pinned/bin/go" "$TMP/pinned/bin/go.hidden"
out="$(run_sut "$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no Go toolchain was found' <<<"$out"; then
  ok "with no Go anywhere and no binaries it refuses (the row above is not unconditional)"
else
  bad "no Go and no binaries refuses" "exit $rc: $(tail -3 <<<"$out")"
fi

echo
echo "── the remedy names the one owner of the toolchain ────────────────"

# Through the bootstrap's step, the release's checked copy, never the
# install's own file under sudo (#929).
if grep -q -- '--run prepare-host --with-advisor' <<<"$out" && ! grep -q 'sudo .*prepare-host\.sh' <<<"$out"; then
  ok "the refusal names prepare-host, as the bootstrap's step"
else
  bad "the refusal names prepare-host" "$(tail -8 <<<"$out")"
fi
# --with-advisor is the step's spelling of APERIRE_WITH_ADVISOR=1, which sudo
# would drop from the operator's environment.
if grep -q -- '--run prepare-host --with-advisor' <<<"$out"; then
  ok "with the flag that makes it build the Advisor as well as install Go"
else
  bad "the remedy carries the advisor flag" "$(grep -i prepare <<<"$out")"
fi
# apt's Go can be older than the minimum this project builds with, and a
# second owner of the toolchain is how a host ends up with two of them.
if ! grep -qi 'apt-get\|apt install\|golang-go' <<<"$out"; then
  ok "and it does NOT send the operator to apt for a Go this project pins"
else
  bad "no apt in the remedy" "$(grep -i apt <<<"$out")"
fi
if grep -q 'Looked in' <<<"$out"; then
  ok "and says where it looked, so 'not installed' is a claim with evidence"
else
  bad "the refusal says where it looked" "$(tail -8 <<<"$out")"
fi
# The other way out of the refusal is copying binaries from a sibling box, and
# the Advisor is three of them. The copy lines named two for as long as the
# linter was missing from them, so an operator who followed them got an Advisor
# whose Promote answered 503 (#1192). Each name on its own scp line, and what
# the third one is for, so leaving it out is a choice and not an omission.
scp_names="$(grep -oE '^    scp <sibling>:<repo>/advisor/bin/[a-z-]+ ' <<<"$out" | sed -E 's#.*/##; s/ $//' | tr '\n' ' ')"
if [[ "$scp_names" == "aperire-advisord aperire-executor knowledge-lint " ]]; then
  ok "the sibling-copy lines name all three binaries, knowledge-lint among them"
else
  bad "the sibling-copy lines name all three binaries" "scp lines name: ${scp_names:-nothing}"
fi
if grep -q 'knowledge-lint is what Promote checks a note' <<<"$out"; then
  ok "and say what knowledge-lint is for, so the operator knows what leaving it out costs"
else
  bad "the refusal says what knowledge-lint is for" "$(grep -i -e promote -e lint <<<"$out" | head -3)"
fi
# With nothing in advisor/bin the headline is the plain one. The rows further
# down show that a host holding one of the pair is told which one is short.
if grep -q 'no prebuilt binaries were found at' <<<"$out" && ! grep -q 'is not complete' <<<"$out"; then
  ok "with nothing in advisor/bin the refusal says no prebuilt binaries were found"
else
  bad "the refusal with nothing present" "$(head -3 <<<"$out")"
fi

echo
echo "── prebuilt binaries still need no compiler ───────────────────────"

for b in aperire-advisord aperire-executor knowledge-lint; do : > "$TMP/tree/advisor/bin/$b"; done
chmod +x "$TMP/tree/advisor/bin/"*
out="$(run_sut "$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'Using the prebuilt binaries' <<<"$out" \
   && grep -qE '^   .*/advisor/bin/knowledge-lint$' <<<"$out" && ! grep -qi 'warning' <<<"$out"; then
  ok "with no Go but all three binaries present it uses them, lists the linter, and has nothing to warn of"
else
  bad "prebuilt binaries are honoured" "exit $rc: $(tail -4 <<<"$out")"
fi

# The daemon and the executor with no linter: a host set up from the old copy
# lines, or a pre-#1131 box re-running this installer with no Go (#1192). The
# Advisor does not need the linter, so the install goes ahead, but Promote
# refuses without it, so the run says so by name with the cost and both ways
# out. It must not list the linter among the binaries it is using.
rm -f "$TMP/tree/advisor/bin/knowledge-lint"
out="$(run_sut "$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'Using the prebuilt binaries' <<<"$out" && grep -q 'CUT:' <<<"$out"; then
  ok "with the daemon and the executor but no linter it still installs, as it did before"
else
  bad "two binaries and no linter still install" "exit $rc: $(tail -4 <<<"$out")"
fi
if grep -q 'warning: .*/advisor/bin/knowledge-lint is missing or not executable' <<<"$out" \
   && ! grep -qE '^   .*/advisor/bin/knowledge-lint$' <<<"$out"; then
  ok "and names the missing linter, without counting it among the binaries in use"
else
  bad "the missing linter is named" "$(grep -i -e lint -e warning <<<"$out" | head -4)"
fi
if grep -q 'Promote and the knowledge' <<<"$out" && grep -q '"no knowledge-lint on this host"' <<<"$out"; then
  ok "says what it costs: Promote and the knowledge pull stop, in the words the dashboard will use"
else
  bad "the warning says what it costs" "$(grep -i -e promote -e refuse <<<"$out" | head -4)"
fi
# The quoted words are the dashboard's own, read from its source here, so a
# reworded 503 there turns this red instead of leaving the warning quoting
# something the operator will never see.
if grep -q "no knowledge-lint on this host" "$REPO_DIR/dashboard/knowledge-admin.ts"; then
  ok "and those words are the ones dashboard/knowledge-admin.ts answers with"
else
  bad "the warning quotes the dashboard's 503" "dashboard/knowledge-admin.ts no longer says 'no knowledge-lint on this host'"
fi
# On stderr, where this script's refusals and its other warning go, so a run
# that keeps stdout for a log or a pipe does not lose it. run_sut folds the two
# together, so the same run is repeated with stderr thrown away.
out_stdout="$(cd "$TMP/tree" && env -i PATH="$TMP/shim:/usr/bin:/bin" HOME="$TMP/home" \
  SUDO_USER="$(id -un)" TERM=dumb bash "$SUT" 2>/dev/null)"
if grep -q 'CUT:' <<<"$out_stdout" && ! grep -qi 'warning' <<<"$out_stdout"; then
  ok "and the warning is on stderr, not mixed into what the run prints for a log"
else
  bad "the warning is on stderr" "$(grep -i -e warning -e lint <<<"$out_stdout" | head -3)"
fi
if grep -qE '^             scp <sibling>:<repo>/advisor/bin/knowledge-lint ' <<<"$out" \
   && grep -q -- '--run prepare-host --with-advisor' <<<"$out"; then
  ok "and gives both ways out: copy it from a sibling, or put Go here and build it"
else
  bad "the warning gives both ways out" "$(grep -i -e scp -e prepare <<<"$out" | head -4)"
fi

# Still a pair. The linter on its own does not make a half-copied install
# whole, so the daemon and the executor are what a host must have. Each of the
# two is taken away in turn, with the other and the linter left in place, and
# the refusal names the one that is short rather than saying nothing was found.
: > "$TMP/tree/advisor/bin/knowledge-lint"; chmod +x "$TMP/tree/advisor/bin/knowledge-lint"
: > "$TMP/tree/advisor/bin/aperire-advisord"; chmod +x "$TMP/tree/advisor/bin/aperire-advisord"
rm -f "$TMP/tree/advisor/bin/aperire-executor"
out="$(run_sut "$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no Go toolchain was found' <<<"$out" \
   && grep -q 'is not complete: aperire-executor is missing or not executable' <<<"$out" \
   && ! grep -q 'no prebuilt binaries were found' <<<"$out"; then
  ok "but a missing executor is not made up for by the linter, and the refusal names it"
else
  bad "a daemon and a linter without the executor are refused by name" "exit $rc: $(tail -9 <<<"$out")"
fi
: > "$TMP/tree/advisor/bin/aperire-executor"; chmod +x "$TMP/tree/advisor/bin/aperire-executor"
rm -f "$TMP/tree/advisor/bin/aperire-advisord"
out="$(run_sut "$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no Go toolchain was found' <<<"$out" \
   && grep -q 'is not complete: aperire-advisord is missing or not executable' <<<"$out" \
   && ! grep -q 'no prebuilt binaries were found' <<<"$out"; then
  ok "nor is a missing daemon, and that refusal names the daemon"
else
  bad "an executor and a linter without the daemon are refused by name" "exit $rc: $(tail -9 <<<"$out")"
fi

echo
echo "── Go on the ordinary PATH still works ────────────────────────────"

rm -f "$TMP/tree/advisor/bin/"*
out="$(run_sut "$TMP/onpath:$TMP/shim:/usr/bin:/bin")"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'CUT:' <<<"$out"; then
  ok "a host whose Go is on PATH is unaffected by the pinned-location probe"
else
  bad "PATH Go still works" "exit $rc: $(tail -4 <<<"$out")"
fi
if grep -q "with $TMP/onpath/go (go1.24.0)" <<<"$out"; then
  ok "and that is the one it reports using"
else
  bad "the PATH Go is the one used" "$(grep -i 'with ' <<<"$out" | head -2)"
fi

echo
echo "── root builds nothing: the three binaries are built as the operator (#1136) ──"

# Under the Advisor stack this installer runs as root (sudo), and advisor/bin
# and the source beside it are the login's. A root build compiled code the login
# can edit and wrote the result where the login can replace it (ADR 0024). The
# rows run the cut copy under fakeroot, where EUID is 0 and everything root
# does is root's, with a stand-in sudo that behaves like the real one on the one
# point that matters: it resets the environment (env -i plus an allow-list) and
# the only way a command can learn it was dropped to the operator is the marker
# that stand-in sets after the reset. A stand-in that passed the caller's
# environment through would let a row pass by leak.
if ! command -v fakeroot >/dev/null 2>&1; then
  bad "fakeroot is here for the build-account rows" "fakeroot is not installed; the account the build ran as was not measured"
else
  FK="$TMP/fk"; rm -rf "$FK"; mkdir -p "$FK/shim" "$FK/pinned"
  OPNAME="$(id -un)"
  cat > "$FK/shim/sudo" <<FAKESUDO
#!/usr/bin/env bash
user=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in -n|-H|-E) shift ;; -u) user="\$2"; shift 2 ;; --) shift; break ;; -*) shift ;; *) break ;; esac
done
# What real sudo hands the command: a fresh environment, the target's home, a
# plain PATH. The marker is the only thing that says "dropped to the operator".
exec env -i HOME="$FK/home-of-\$user" PATH="$FK/shim:/usr/bin:/bin" RAN_AS_OPERATOR="\$user" "\$@"
FAKESUDO
  for t in mkdir mv; do
    cat > "$FK/shim/$t" <<RECORD
#!/usr/bin/env bash
printf '%s as=%s\n' "$t" "\${RAN_AS_OPERATOR:-root}" >> "$FK/log"
exec /usr/bin/$t "\$@"
RECORD
  done
  cat > "$FK/pinned/go" <<FAKEGO
#!/usr/bin/env bash
case "\$1" in
  version) # Go refuses to run from a directory its user cannot search; the
           # test's directory is enterable, so the refusal is modelled by name.
           [[ "\$PWD" == "$FK/noenter" ]] && { echo "go: cannot determine current directory: stat .: permission denied" >&2; exit 1; }
           printf 'version as=%s\n' "\${RAN_AS_OPERATOR:-root}" >> "$FK/vlog"
           echo "go version go1.23.4 linux/amd64"; exit 0 ;;
  build) out=""
         while [[ \$# -gt 0 ]]; do [[ "\$1" == -o ]] && out="\$2"; shift; done
         who="\${RAN_AS_OPERATOR:-root}"
         printf 'go as=%s home=%s\n' "\$who" "\${HOME:-}" >> "$FK/log"
         printf 'built-as:%s\n' "\$who" > "\$out"; chmod +x "\$out"
         exit 0 ;;
esac
exit 0
FAKEGO
  chmod +x "$FK/shim/sudo" "$FK/shim/mkdir" "$FK/shim/mv" "$FK/pinned/go"
  # The pinned location the cut copy probes is $TMP/pinned/bin/go; point it at
  # the recording one for these rows.
  FK_SUT="$TMP/tree/scripts/install-advisord.fk.sh"
  sed "s#$TMP/pinned/bin/go#$FK/pinned/go#" "$SUT" > "$FK_SUT"
  # The same copy with the drop to the operator taken out: the plain go build
  # as whoever runs the installer, which is what the installer did.
  FK_OLD="$TMP/tree/scripts/install-advisord.fk-old.sh"
  # shellcheck disable=SC2016  # the program text being rewritten
  sed 's/^  if \[\[ \$EUID -eq 0 && "\$RUN_USER" != root \]\]; then$/  if false; then/' "$FK_SUT" > "$FK_OLD"
  if cmp -s "$FK_SUT" "$FK_OLD"; then
    bad "the control copy has the drop to the operator taken out" "the sed did not find the test in as_run_user"
  fi
  fk_run() { # $1 = the copy to run; leaves $FK/log and the tree
    rm -rf "$FK/log" "$TMP/tree/advisor/bin"
    ( cd "$TMP/tree" && env -i PATH="$FK/shim:/usr/bin:/bin" HOME="$TMP/home" SUDO_USER="$OPNAME" TERM=dumb \
        fakeroot bash "$1" 2>&1 )
  }
  out="$(fk_run "$FK_SUT")"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q 'CUT:' <<<"$out"; then
    ok "the installer's build step runs to the end under root (fakeroot)"
  else
    bad "the build step runs under fakeroot" "exit $rc: $(tail -4 <<<"$out")"
  fi
  built="$(grep -c '^go as='"$OPNAME"' ' "$FK/log" 2>/dev/null || true)"
  if [[ "$built" == 3 ]] && ! grep -q '^go as=root' "$FK/log"; then
    ok "all three binaries are built as the operator: the daemon, the executor and the corpus linter"
  else
    bad "the three builds run as the operator" "$(tr '\n' ' ' < "$FK/log" 2>/dev/null)"
  fi
  if grep -q "^go as=$OPNAME home=$FK/home-of-$OPNAME\$" "$FK/log"; then
    ok "  with the operator's home, from the reset environment the stand-in sudo gave it"
  else
    bad "the build has the operator's environment" "$(tr '\n' ' ' < "$FK/log" 2>/dev/null)"
  fi
  if ! grep -q 'as=root' "$FK/log" && grep -q "^mkdir as=$OPNAME" "$FK/log" && [[ "$(grep -c "^mv as=$OPNAME" "$FK/log")" == 3 ]]; then
    ok "  advisor/bin is made, and each binary renamed into place, as the operator too"
  else
    bad "advisor/bin and the renames are the operator's" "$(tr '\n' ' ' < "$FK/log" 2>/dev/null)"
  fi
  got="$(cat "$TMP/tree/advisor/bin/aperire-advisord" "$TMP/tree/advisor/bin/aperire-executor" "$TMP/tree/advisor/bin/knowledge-lint" 2>/dev/null | tr '\n' ' ')"
  if [[ "$got" == "built-as:$OPNAME built-as:$OPNAME built-as:$OPNAME " && -z "$(find "$TMP/tree/advisor/bin" -name '.*.new.*' 2>/dev/null)" ]]; then
    ok "  the binaries are in place, built by the operator, and no scratch name is left beside them"
  else
    bad "the binaries are in place and nothing is left over" "$got; $(ents "$TMP/tree/advisor/bin")"
  fi
  out="$(fk_run "$FK_OLD")"
  if grep -q '^go as=root' "$FK/log" 2>/dev/null; then
    ok "  control: with the drop taken out, the same step builds as root, so the rows above can fail"
  else
    bad "control: the fixture can show a build as root" "$(tr '\n' ' ' < "$FK/log" 2>/dev/null): $(tail -3 <<<"$out")"
  fi
  # One failed build leaves the others as they were and no scratch behind.
  printf 'old-daemon\n' > "$FK/old"; mkdir -p "$TMP/tree/advisor/bin"
  sed 's#build) out=""#build) [[ "\$*" == *cmd/knowledge-lint* ]] \&\& exit 1; out=""#' "$FK/pinned/go" > "$FK/pinned/go.fail"
  chmod +x "$FK/pinned/go.fail"
  sed "s#$FK/pinned/go#$FK/pinned/go.fail#" "$FK_SUT" > "$TMP/tree/scripts/install-advisord.fk-fail.sh"
  rm -rf "$FK/log" "$TMP/tree/advisor/bin"; mkdir -p "$TMP/tree/advisor/bin"
  cp "$FK/old" "$TMP/tree/advisor/bin/aperire-advisord"
  out="$( cd "$TMP/tree" && env -i PATH="$FK/shim:/usr/bin:/bin" HOME="$TMP/home" SUDO_USER="$OPNAME" TERM=dumb \
            fakeroot bash "$TMP/tree/scripts/install-advisord.fk-fail.sh" 2>&1 )"; rc=$?
  if [[ $rc -ne 0 && "$(cat "$TMP/tree/advisor/bin/aperire-advisord")" == old-daemon && -z "$(find "$TMP/tree/advisor/bin" -name '.*.new.*')" ]] \
     && grep -q 'are as they were' <<<"$out"; then
    ok "a build that fails on the third binary stops the install and leaves the daemon that was there, with no scratch file"
  else
    bad "a failed build leaves advisor/bin as it was" "exit $rc: $(cat "$TMP/tree/advisor/bin/aperire-advisord" 2>/dev/null): $(ents "$TMP/tree/advisor/bin"): $(tail -3 <<<"$out")"
  fi
  # One failed RENAME is not a failed build: the binary before it is already the
  # new one. The message names which are which, and the scratch names are gone.
  cp "$FK/shim/mv" "$FK/mv.good"
  cat > "$FK/shim/mv" <<COUNTMV
#!/usr/bin/env bash
printf '%s' x >> "$FK/mvcount"
if [[ "\$(wc -c < "$FK/mvcount")" -eq 2 ]]; then exit 1; fi
exec /usr/bin/mv "\$@"
COUNTMV
  chmod +x "$FK/shim/mv"
  rm -rf "$FK/log" "$FK/mvcount" "$TMP/tree/advisor/bin"; mkdir -p "$TMP/tree/advisor/bin"
  printf 'old-daemon\n' > "$TMP/tree/advisor/bin/aperire-advisord"
  printf 'old-executor\n' > "$TMP/tree/advisor/bin/aperire-executor"
  printf 'old-lint\n' > "$TMP/tree/advisor/bin/knowledge-lint"
  out="$( cd "$TMP/tree" && env -i PATH="$FK/shim:/usr/bin:/bin" HOME="$TMP/home" SUDO_USER="$OPNAME" TERM=dumb \
            fakeroot bash "$FK_SUT" 2>&1 )"; rc=$?
  cp "$FK/mv.good" "$FK/shim/mv"; chmod +x "$FK/shim/mv"
  if [[ $rc -ne 0 && "$(cat "$TMP/tree/advisor/bin/aperire-advisord")" == built-as:$OPNAME \
        && "$(cat "$TMP/tree/advisor/bin/aperire-executor")" == old-executor \
        && "$(cat "$TMP/tree/advisor/bin/knowledge-lint")" == old-lint \
        && -z "$(find "$TMP/tree/advisor/bin" -name '.*.new.*')" ]] \
     && grep -q 'could not put aperire-executor into place' <<<"$out" \
     && grep -q 'Replaced with the new build: aperire-advisord$' <<<"$out" \
     && grep -q 'Not replaced: aperire-executor knowledge-lint$' <<<"$out" \
     && ! grep -q 'are as they were' <<<"$out"; then
    ok "a rename that fails on the second binary says one is new and two are not, and does not claim they are as they were"
  else
    bad "a failed rename names the mixed state" "exit $rc: $(ents "$TMP/tree/advisor/bin"): $(tail -5 <<<"$out")"
  fi
  # Candidate three of the Go probe is a path out of the login's own shell, a file
  # the login can edit. Root must not execute it: its version is asked as the login.
  # Candidates one and two are made to fail (no pinned Go; a `go` that is not one),
  # and the login's ~/.profile puts a go ahead of everything else.
  mkdir -p "$FK/loginbin" "$FK/home-of-$OPNAME"
  cp "$FK/pinned/go" "$FK/loginbin/go"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$FK/shim/go"
  chmod +x "$FK/shim/go"
  # shellcheck disable=SC2016  # $PATH is for the login's shell to expand
  printf 'PATH="%s:$PATH"\n' "$FK/loginbin" > "$FK/home-of-$OPNAME/.profile"
  sed "s#$FK/pinned/go#$FK/absent/go#" "$FK_SUT" > "$TMP/tree/scripts/install-advisord.fk-login.sh"
  rm -rf "$FK/log" "$FK/vlog" "$TMP/tree/advisor/bin"
  out="$( cd "$TMP/tree" && env -i PATH="$FK/shim:/usr/bin:/bin" HOME="$TMP/home" SUDO_USER="$OPNAME" TERM=dumb \
            fakeroot bash "$TMP/tree/scripts/install-advisord.fk-login.sh" 2>&1 )"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q "with $FK/loginbin/go" <<<"$out" \
     && grep -q "^version as=$OPNAME\$" "$FK/vlog" 2>/dev/null && ! grep -q '^version as=root' "$FK/vlog"; then
    ok "a Go found through the login's own shell is asked its version as the login, never as root"
  else
    bad "the login's Go is probed as the login" "exit $rc: $(tr '\n' ' ' < "$FK/vlog" 2>/dev/null): $(tail -4 <<<"$out")"
  fi
  rm -f "$FK/shim/go"

  # ---- root runs no found Go (#1162) ------------------------------------------
  # Candidates one and two used to be asked their version as root. A script the
  # login owns, at each position in turn, writes its caller to $FK/vlog; every
  # line must name the operator and none may name root. The Go is the same fake
  # the rows above use, so the build that follows the probe runs to the end.
  login_go() { # $1 = path: a login-owned go that records who asked its version
    mkdir -p "$(dirname "$1")"
    cp "$FK/pinned/go" "$1"
    chmod +x "$1"
  }
  login_go "$FK/login1/go"
  login_go "$FK/login2/go"
  c1_sut="$TMP/tree/scripts/install-advisord.fk-c1.sh"
  c2_sut="$TMP/tree/scripts/install-advisord.fk-c2.sh"
  sed "s#$FK/pinned/go#$FK/login1/go#" "$FK_SUT" > "$c1_sut"
  sed "s#$FK/pinned/go#$FK/absent/go#" "$FK_SUT" > "$c2_sut"
  fk_go() { # $1 = copy to run, $2 = PATH, rest = extra environment; leaves $FK/vlog and $FK/log
    local sut="$1" path="$2"; shift 2
    rm -rf "$FK/log" "$FK/vlog" "$TMP/tree/advisor/bin"
    ( cd "$TMP/tree" && env -i PATH="$path" HOME="$TMP/home" SUDO_USER="$OPNAME" TERM=dumb "$@" \
        fakeroot bash "$sut" 2>&1 )
  }
  out="$(fk_go "$c1_sut" "$FK/shim:/usr/bin:/bin")"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q "with $FK/login1/go" <<<"$out" \
     && grep -q "^version as=$OPNAME\$" "$FK/vlog" 2>/dev/null && ! grep -q '^version as=root' "$FK/vlog"; then
    ok "a login-owned Go at the pinned location is asked its version as the login, never as root"
  else
    bad "the pinned Go is probed as the login" "exit $rc: $(tr '\n' ' ' < "$FK/vlog" 2>/dev/null): $(tail -4 <<<"$out")"
  fi
  out="$(fk_go "$c2_sut" "$FK/login2:$FK/shim:/usr/bin:/bin")"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q "with $FK/login2/go" <<<"$out" \
     && grep -q "^version as=$OPNAME\$" "$FK/vlog" 2>/dev/null && ! grep -q '^version as=root' "$FK/vlog"; then
    ok "a login-owned Go on the PATH root runs with is asked its version as the login, never as root"
  else
    bad "the PATH Go is probed as the login" "exit $rc: $(tr '\n' ' ' < "$FK/vlog" 2>/dev/null): $(tail -4 <<<"$out")"
  fi
  # The build that follows runs as the login too, with the Go that was found.
  if ! grep -q 'as=root' "$FK/log" 2>/dev/null && [[ "$(grep -c '^go as='"$OPNAME" "$FK/log" 2>/dev/null)" == 3 ]]; then
    ok "  and the three builds that use it run as the login as well"
  else
    bad "the builds with that Go are the login's" "$(tr '\n' ' ' < "$FK/log" 2>/dev/null)"
  fi

  # A GO_BIN in the environment is not a candidate. sudo -E, or a caller that
  # exports one, must not name the program root's probe runs. The legitimate Go
  # sits at the pinned location; the exported one records any call at all.
  mkdir -p "$FK/exported"
  cat > "$FK/exported/go" <<EXPGO
#!/usr/bin/env bash
printf 'called as=%s args=%s\n' "\${RAN_AS_OPERATOR:-root}" "\$*" >> "$FK/exported-marker"
echo "go version go1.23.4 linux/amd64"
EXPGO
  chmod +x "$FK/exported/go"
  rm -f "$FK/exported-marker"
  out="$(fk_go "$FK_SUT" "$FK/shim:/usr/bin:/bin" GO_BIN="$FK/exported/go")"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q "with $FK/pinned/go" <<<"$out" && [[ ! -e "$FK/exported-marker" ]]; then
    ok "an exported GO_BIN is never run: the Go that was looked for is the one used"
  else
    bad "an exported GO_BIN is ignored" "exit $rc: $(cat "$FK/exported-marker" 2>/dev/null): $(grep -i 'with ' <<<"$out" | head -2)"
  fi

  # When the drop to the login cannot be made, the candidate is skipped. It is
  # not run as root instead.
  mkdir -p "$FK/nosudo"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$FK/nosudo/sudo"
  chmod +x "$FK/nosudo/sudo"
  out="$(fk_go "$c1_sut" "$FK/nosudo:/usr/bin:/bin")"; rc=$?
  if [[ $rc -ne 0 ]] && grep -q 'no Go toolchain was found' <<<"$out" && [[ ! -s "$FK/vlog" ]]; then
    ok "with no way to drop to the login the Go is skipped and nothing runs as root in its place"
  else
    bad "no drop, no probe" "exit $rc: $(tr '\n' ' ' < "$FK/vlog" 2>/dev/null): $(tail -3 <<<"$out")"
  fi

  # Controls. The fix is one line: the version is asked through as_run_user. The
  # same copy with that line back to a direct call must show root asking, or the
  # rows above would pass whatever the probe did.
  c1_old="$TMP/tree/scripts/install-advisord.fk-c1-old.sh"
  # shellcheck disable=SC2016  # the program text being rewritten
  sed 's|^    v="\$(cd / \&\& as_run_user "\$cand" version 2>/dev/null)" \|\| continue$|    v="$("$cand" version 2>/dev/null)" \|\| continue|' "$c1_sut" > "$c1_old"
  if cmp -s "$c1_sut" "$c1_old"; then
    bad "control: the copy has the probe asked directly" "the sed did not find the probe line in find_go"
  else
    out="$(fk_go "$c1_old" "$FK/shim:/usr/bin:/bin")"
    if grep -q '^version as=root' "$FK/vlog" 2>/dev/null; then
      ok "  control: with the probe asked directly, the same Go is asked as root, so the rows above can fail"
    else
      bad "control: the fixture can show a probe as root" "$(tr '\n' ' ' < "$FK/vlog" 2>/dev/null): $(tail -3 <<<"$out")"
    fi
  fi
  # The same for the exported name: a copy that takes GO_BIN from the environment
  # first runs it.
  gb_old="$TMP/tree/scripts/install-advisord.fk-gb-old.sh"
  # shellcheck disable=SC2016  # the program text being rewritten
  sed 's|^GO_BIN="\$(find_go \|\| true)"$|GO_BIN="${GO_BIN:-$(find_go \|\| true)}"|' "$FK_SUT" > "$gb_old"
  if cmp -s "$FK_SUT" "$gb_old"; then
    bad "control: the copy takes GO_BIN from the environment" "the sed did not find the GO_BIN assignment"
  else
    rm -f "$FK/exported-marker"
    out="$(fk_go "$gb_old" "$FK/shim:/usr/bin:/bin" GO_BIN="$FK/exported/go")"
    if [[ -e "$FK/exported-marker" ]]; then
      ok "  control: a copy that honours an exported GO_BIN runs it, so the row above can fail"
    else
      bad "control: the fixture can show an exported GO_BIN being run" "$(tail -3 <<<"$out")"
    fi
  fi

  # From a directory the login cannot enter. sudo keeps the caller's directory
  # and go will not run from one its user cannot search, so a root shell in
  # /root (sudo -i, then the one-liner) made every candidate read as "no Go".
  # The probe is made from /. The fake go refuses in $FK/noenter, by name.
  mkdir -p "$FK/noenter"
  fk_go_in() { # $1 = directory to start in, $2 = copy to run, $3 = PATH
    rm -rf "$FK/log" "$FK/vlog" "$TMP/tree/advisor/bin"
    ( cd "$1" && env -i PATH="$3" HOME="$TMP/home" SUDO_USER="$OPNAME" TERM=dumb \
        fakeroot bash "$2" 2>&1 )
  }
  out="$(fk_go_in "$FK/noenter" "$c1_sut" "$FK/shim:/usr/bin:/bin")"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q "with $FK/login1/go" <<<"$out" && grep -q "^version as=$OPNAME\$" "$FK/vlog" 2>/dev/null; then
    ok "a Go is found when the installer is started from a directory the login cannot enter"
  else
    bad "the probe does not depend on the starting directory" "exit $rc: $(tr '\n' ' ' < "$FK/vlog" 2>/dev/null): $(tail -3 <<<"$out")"
  fi
  c1_cwd="$TMP/tree/scripts/install-advisord.fk-c1-cwd.sh"
  # shellcheck disable=SC2016  # the program text being rewritten
  sed 's|^    v="\$(cd / && as_run_user|    v="$(as_run_user|' "$c1_sut" > "$c1_cwd"
  if cmp -s "$c1_sut" "$c1_cwd"; then
    bad "control: the copy probes from the starting directory" "the sed did not find the cd / in find_go"
  else
    out="$(fk_go_in "$FK/noenter" "$c1_cwd" "$FK/shim:/usr/bin:/bin")"; rc=$?
    if [[ $rc -ne 0 ]] && grep -q 'no Go toolchain was found' <<<"$out"; then
      ok "  control: probed from the starting directory the same Go reads as no Go at all, so the row above can fail"
    else
      bad "control: the fixture can show the starting directory mattering" "exit $rc: $(tail -3 <<<"$out")"
    fi
  fi
fi

# ── prepare-host asks the same way (#1162) ──────────────────────────
# Its go_ok() is where the bootstrap's host preparation finds a Go for the
# relay and the Advisor, and it ran each candidate as root, the third one out
# of the login's own shell. The function and as_user are lifted out of the real
# file; sudo is a stand-in that records who the command was handed to.
echo
echo "── prepare-host's Go probe is the login's, not root's ─────────────"

PH="$REPO_DIR/scripts/prepare-host.sh"
PHD="$TMP/ph"; mkdir -p "$PHD/bin"
{ grep -m1 '^as_user()' "$PH"; awk '/^go_ok\(\) \{/,/^\}/' "$PH"; } > "$PHD/fns.sh"
if [[ "$(grep -c '' "$PHD/fns.sh")" -ge 6 ]] && grep -q '^go_ok()' "$PHD/fns.sh" && grep -q '^as_user()' "$PHD/fns.sh"; then
  ok "the lift found as_user and go_ok in the real prepare-host.sh"
else
  bad "the lift found the functions" "$(cat "$PHD/fns.sh")"
fi
cat > "$PHD/bin/sudo" <<'PHSUDO'
#!/usr/bin/env bash
user=""
while [[ $# -gt 0 ]]; do
  case "$1" in -n|-H|-E) shift ;; -u) user="$2"; shift 2 ;; --) shift; break ;; *) break ;; esac
done
RAN_AS_OPERATOR="$user" exec "$@"
PHSUDO
chmod +x "$PHD/bin/sudo"
cat > "$PHD/go" <<PHGO
#!/usr/bin/env bash
[[ "\$PWD" == "$PHD/noenter" ]] && { echo "go: cannot determine current directory: stat .: permission denied" >&2; exit 1; }
printf 'version as=%s\n' "\${RAN_AS_OPERATOR:-root}" >> "$PHD/vlog"
echo "go version go1.23.4 linux/amd64"
PHGO
mkdir -p "$PHD/noenter"
chmod +x "$PHD/go"
ph_probe() { # $1 = the functions file, $2 = the directory to start in (default: here); prints go_ok's answer
  rm -f "$PHD/vlog"
  ( cd "${2:-.}" || exit 1
    PATH="$PHD/bin:/usr/bin:/bin"; GO_MIN=1.23; RUN_USER="loginuser"; export PATH GO_MIN RUN_USER
    # shellcheck disable=SC1090  # the functions file is the argument
    . "$1"; go_ok "$PHD/go" )
}
ans="$(ph_probe "$PHD/fns.sh")"
if [[ "$ans" == 1.23 && "$(cat "$PHD/vlog" 2>/dev/null)" == "version as=loginuser" ]]; then
  ok "go_ok asks the candidate's version as the login, and still passes a Go that is new enough"
else
  bad "go_ok asks as the login" "answer '$ans': $(cat "$PHD/vlog" 2>/dev/null)"
fi
# shellcheck disable=SC2016  # the program text being rewritten
sed 's|v="\$(cd / \&\& as_user "\$1" version|v="$("$1" version|' "$PHD/fns.sh" > "$PHD/fns-old.sh"
if cmp -s "$PHD/fns.sh" "$PHD/fns-old.sh"; then
  bad "control: go_ok asking directly" "the sed did not find the probe in go_ok"
else
  ph_probe "$PHD/fns-old.sh" >/dev/null
  if [[ "$(cat "$PHD/vlog" 2>/dev/null)" == "version as=root" ]]; then
    ok "  control: with go_ok asking directly the same Go is asked as root, so the row above can fail"
  else
    bad "control: the fixture can show go_ok asking as root" "$(cat "$PHD/vlog" 2>/dev/null)"
  fi
fi

# Started from a directory the login cannot enter (a root shell in /root): the
# probe is made from /, and the same function probing from where it started
# reads the Go as absent.
ans="$(ph_probe "$PHD/fns.sh" "$PHD/noenter")"
if [[ "$ans" == 1.23 ]]; then
  ok "go_ok still finds the Go when started from a directory the login cannot enter"
else
  bad "go_ok does not depend on the starting directory" "answer '$ans': $(cat "$PHD/vlog" 2>/dev/null)"
fi
# shellcheck disable=SC2016  # the program text being rewritten
sed 's|v="\$(cd / && as_user|v="$(as_user|' "$PHD/fns.sh" > "$PHD/fns-cwd.sh"
if cmp -s "$PHD/fns.sh" "$PHD/fns-cwd.sh"; then
  bad "control: go_ok probing from where it started" "the sed did not find the cd / in go_ok"
else
  ans="$(ph_probe "$PHD/fns-cwd.sh" "$PHD/noenter")"
  if [[ -z "$ans" ]]; then
    ok "  control: probing from where it started the same Go reads as absent, so the row above can fail"
  else
    bad "control: the fixture can show the starting directory mattering" "answer '$ans'"
  fi
fi

echo
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
