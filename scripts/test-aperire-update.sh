#!/usr/bin/env bash
# Exercise scripts/aperire-update.sh, the root program behind the dashboard's
# Update, and scripts/install-update-grant.sh, the socket that reaches it.
#
# What is being protected: this is the third program the dashboard account can
# reach as root, and the only one that rewrites the tree the dashboard runs
# out of. Its promises fail silently if they break.
#
#   1. The payload carries no source. A request that names one is refused
#      before anything is fetched, and the endpoint's own request log is read
#      back to prove nothing was.
#   2. It installs what the endpoint publishes, or nothing. A tag, a commit or
#      a checksum that disagrees with what was fetched is refused, and again
#      nothing is fetched afterwards.
#   3. One run at a time. A second apply while one is in flight is refused
#      without touching the endpoint or the tree.
#   4. It reuses the bootstrap rather than reimplementing the swap, and it
#      hands it exactly four arguments and the operator's name. The name is
#      the load-bearing one: without SUDO_USER the bootstrap takes root as
#      the operator and leaves a tree the dashboard cannot write.
#   5. The page can follow it. Step markers appear, once each and in order,
#      keyed off the bootstrap's own headings, and those headings are asserted
#      against scripts/get-aperire.sh so a rename fails here and not on a host.
#   6. It restarts nothing, and names only what this host actually has.
#   7. Restart is a second ask, and refuses a name that is not one of this
#      host's units.
#   8. Rollback refuses to choose. Zero kept trees and two are both refusals;
#      one is a swap, and the database comes with it.
#   9. It says how it ended, in words. An exit code does not cross a socket,
#      so `exit=<code>` is the last line on every path.
#  10. It installs only what the release key signed. The signature is checked
#      against the key installed on the host, never one fetched; the script it
#      runs as root is run only when its sha256 is the signed one; and a
#      release older than the one installed is refused however validly it is
#      signed. The key here is a throwaway made for this run.
#
#   bash scripts/test-aperire-update.sh
#
# Runs entirely in a temporary directory against a real HTTP endpoint on
# loopback, a fake bootstrap, and fake systemctl, runuser and logger on PATH.
# Touches no host, needs no root, updates nothing real.
#
# THE MODIFICATIONS. The program refuses to run as anything but root, and
# these tests are not root and cannot become root. So the rows below run a
# scratch copy with that single line removed, and two rows assert against the
# ORIGINAL: that the line is there, and that a non-root caller is refused by
# it. Two more lines are rewritten, the two fixed root-owned locations the
# program reads the release key and the kept signed release from, because
# neither can be overridden from the environment and this test cannot write
# to /usr/local or /var. The scratch copy is compared with the original so
# that "these three lines and no others" is a checked claim.

set -uo pipefail
# Root copies refuse a destination directory anyone but its owner can write
# (ADR 0024), as they would on a host, so the fixture is made like a host: 022.
umask 022

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIG="$REPO_DIR/scripts/aperire-update.sh"
BOOTSTRAP="$REPO_DIR/scripts/get-aperire.sh"
TMP=$(mktemp -d)
STUB_PID=""
cleanup() {
  [[ -n "$STUB_PID" ]] && kill "$STUB_PID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$ORIG" ]] || { echo "no aperire-update.sh at $ORIG"; exit 1; }

mkdir -p "$TMP/bin" "$TMP/etc" "$TMP/run" "$TMP/units" "$TMP/state" "$TMP/serve"

# ── The scratch copy, and the proof of what it changed ───────────────
# shellcheck disable=SC2016  # a literal to grep for, not an expression to run
GUARD='  [[ $EUID -eq 0 ]] || die 2 "must run as root; this writes the install tree, the systemd units and /usr/local/sbin"'
SUT="$TMP/update.sh"
grep -vxF -e "$GUARD" "$ORIG" \
  | sed -e "s|^LIB_DIR=/usr/local/lib/aperire\$|LIB_DIR=$TMP/lib|" \
        -e "s|^RELEASE_STORE=/var/lib/aperire/release\$|RELEASE_STORE=$TMP/store|" > "$SUT"
chmod +x "$SUT"
if ! grep -qx "LIB_DIR=$TMP/lib" "$SUT" || ! grep -qx "RELEASE_STORE=$TMP/store" "$SUT"; then
  echo "LIB_DIR= or RELEASE_STORE= has moved in $ORIG; the rewrite matched nothing"; exit 1
fi

echo
echo "── the root guard, asserted against the real file ─────────────────"

if grep -qxF -e "$GUARD" "$ORIG"; then
  ok "the real program refuses to run as anything but root"
else
  bad "the root guard is in the real program" "the line these tests remove is not there any more"
fi

diffcount=$(( $(wc -l < "$ORIG") - $(wc -l < "$SUT") ))
changed="$(diff "$ORIG" "$SUT" | grep -c '^[<>]' || true)"
if [[ "$diffcount" -eq 1 && "$changed" -eq 5 ]]; then
  ok "and the copy under test differs from it by exactly that line and the two locations"
else
  bad "the scratch copy differs by the guard and two locations" "it differs by $diffcount lines, $changed changed"
fi

out="$(bash "$ORIG" </dev/null 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'must run as root' <<<"$out"; then
  ok "and running the real one without root is refused, saying why"
else
  bad "the real program refuses a non-root caller" "exit $rc: $out"; fi

if [[ "$(tail -n 1 <<<"$out")" == "exit=2" ]]; then
  ok "and even that refusal ends with its status, because an exit code does not cross a socket"
else
  bad "every path ends with exit=" "the last line was '$(tail -n 1 <<<"$out")'"; fi

# ── The bootstrap's headings, asserted where they are written ───────
#
# The program keys the page's progress off lines the bootstrap prints. That
# is a coupling between two files, so it is checked here rather than trusted:
# a heading reworded in get-aperire.sh fails this row instead of leaving a
# page tailing eight minutes of silence.
echo
echo "── the step markers are keyed off headings that still exist ───────"
missing=()
while IFS= read -r phrase; do
  grep -qF "step \"$phrase\"" "$BOOTSTRAP" || missing+=("$phrase")
done < <(sed -n 's/^  "\(.*\):[a-z]*:[0-9]*"$/\1/p' "$ORIG")
if [[ ${#missing[@]} -eq 0 ]]; then
  ok "every phrase the program watches for is still a step in get-aperire.sh"
else
  bad "the step phrases match the bootstrap" "not found as a step: ${missing[*]}"; fi

# ── Fakes on PATH ───────────────────────────────────────────────────
# systemctl: is-active and Type answered from state files, restart recorded
# in the order it was asked for.
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
cmd="\$1"; shift
args=(); for a in "\$@"; do case "\$a" in --*) ;; *) args+=("\$a") ;; esac; done
unit="\${args[0]:-}"; unit="\${unit%.service}"
case "\$cmd" in
  is-active) if [[ -e "$TMP/state/down-\$unit" ]]; then echo failed; exit 3; fi
             if [[ -e "$TMP/state/active-\$unit" ]]; then echo active; exit 0; fi
             echo inactive; exit 3 ;;
  show)      echo simple; exit 0 ;;
  restart|start)
             printf '%s\n' "\$unit" >> "$TMP/state/restarted"
             : > "$TMP/state/active-\$unit"; exit 0 ;;
  *)         exit 0 ;;
esac
EOF
# runuser: this account already, so the fake runs the command as it stands.
# Every call is recorded, so a row can tell a step run as the operator from
# one run as root.
cat > "$TMP/bin/runuser" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/runuser-log"
EOF
cat >> "$TMP/bin/runuser" <<'EOF'
while [[ $# -gt 0 ]]; do case "$1" in -u) shift 2 ;; --) shift; break ;; *) shift ;; esac; done
exec "$@"
EOF
# logger: the journal, in a file, so a row can read what was recorded.
cat > "$TMP/bin/logger" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/journal"
EOF
# install: records what it was asked and does the copy or the mkdir. The real
# one cannot chown to root as this account, and every installer in this
# project writes root-owned files with it.
cat > "$TMP/bin/install" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/install-calls"
dirmode=0; want=0; mode=""; args=()
for a in "\$@"; do
  case "\$want" in 1) want=0; continue ;; 2) mode="\$a"; want=0; continue ;; esac
  case "\$a" in
    -d) dirmode=1 ;;
    -m) want=2 ;;
    -o|-g) want=1 ;;
    *) args+=("\$a") ;;
  esac
done
if [[ \$dirmode == 1 ]]; then mkdir -p "\${args[@]}"; exit 0; fi
[[ \${#args[@]} -ge 2 ]] || exit 0
cp -f "\${args[0]}" "\${args[-1]}"
# The real one sets the mode it was given even over an existing file, and the
# rows below read the exec bit back off what landed.
[[ -n "\$mode" ]] && chmod "\$mode" "\${args[-1]}"
exit 0
EOF
chmod +x "$TMP/bin/systemctl" "$TMP/bin/runuser" "$TMP/bin/logger" "$TMP/bin/install"

# ── A real endpoint on loopback ─────────────────────────────────────
#
# A real HTTP server rather than a fake curl: the fetch, the cross-check
# between the two files and the sentinel check on the bootstrap are the things
# under test, and a fake curl would test the fake. Every request is logged, so
# a row that says "nothing was fetched" can read that back.
cat > "$TMP/stub.py" <<'PYEOF'
import http.server, os, sys
D, portfile, logfile = sys.argv[1], sys.argv[2], sys.argv[3]
MAP = {'/': 'get-aperire.sh'}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        open(logfile, 'a').write(self.path + '\n')
        path = self.path.split('?')[0]
        # One flat directory, the way the real origin serves it: any other
        # name is itself, and a separator or a leading dot is a 404.
        name = path[1:]
        f = MAP.get(path) or (name if name and '/' not in name and not name.startswith('.') else None)
        if not f or not os.path.exists(os.path.join(D, f)):
            self.send_response(404); self.end_headers(); return
        b = open(os.path.join(D, f), 'rb').read()
        self.send_response(200)
        self.send_header('content-length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
open(portfile, 'w').write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
HITS="$TMP/state/hits"
: > "$HITS"
rm -f "$TMP/state/port"
python3 "$TMP/stub.py" "$TMP/serve" "$TMP/state/port" "$HITS" &
STUB_PID=$!
for _ in $(seq 1 50); do [[ -s "$TMP/state/port" ]] && break; sleep 0.3; done
if [[ -s "$TMP/state/port" ]]; then
  ok "the stub endpoint is serving, so the rows below are about the program"
else
  bad "the stub endpoint comes up" "no port file after 15s"
fi
ENDPOINT="http://127.0.0.1:$(cat "$TMP/state/port" 2>/dev/null || echo 0)"

NEW_SHA=$(printf 'the release the endpoint publishes' | sha256sum | cut -d' ' -f1)
OLD_SHA=$(printf 'the release this host is on' | sha256sum | cut -d' ' -f1)
NEW_TAG=snapshot-2026-09-10
NEW_COMMIT=abc1234

# The release key this "host" trusts, made for this run and never anything
# else's, installed where the program reads it. A second key stands for
# somebody who is not the publisher.
mkdir -p "$TMP/lib" "$TMP/store"
ssh-keygen -q -t ed25519 -N '' -C 'test-key-never-trusted' -f "$TMP/testkey" </dev/null
ssh-keygen -q -t ed25519 -N '' -C 'somebody-else' -f "$TMP/otherkey" </dev/null
printf 'aperire-release-key namespaces="aperire-release" %s test-key-never-trusted\n' \
  "$(cut -d' ' -f1,2 "$TMP/testkey.pub")" > "$TMP/lib/release-signers"
cp "$REPO_DIR/scripts/release-verify-lib.sh" "$TMP/lib/release-verify-lib.sh"
# The two libraries a rollback stages the restored tree's installers with
# (#764), root's own copies in the real program's LIB_DIR.
cp "$REPO_DIR/scripts/release-digests-lib.sh" "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/lib/"
chmod 0644 "$TMP/lib/release-digests-lib.sh" "$TMP/lib/trusted-path-lib.sh"
# A kept record for a tree, with the real digest of every file root would
# run out of it, the way get-aperire.sh writes one.
kept_record() { # $1 = tree, $2 = anchor words, $3 = key
  printf '# anchor %s\n# key %s\n' "$2" "$3"
  (cd "$1" && for f in install.sh scripts/* advisor/cmd/aperire-advisord/*.go; do [[ -f "$f" ]] && printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"; done)
}
# What get-aperire.sh writes when its swap moves a tree aside (#782): the
# tree by <dev>:<ino> and the key its record went into kept/ under.
point_previous() { # $1 = tree, $2 = key
  printf '%s %s\n' "$(stat -c '%d:%i' "$1")" "$2" > "$TMP/lib/release.sha256.previous"
}

# What the publisher serves: release.json, its sum file, and the signed copy
# of release.json under the name that never changes, signed with $3 (the
# test key unless a row says otherwise). bootstrap_sha256 is the sum of the
# install script being served, unless $4 names another.
publish() { # $1 = the sha release.json names, $2 = the sha the sums file names, $3 = key, $4 = bootstrap sum, $5 = published_at
  local key="${3:-$TMP/testkey}"
  local boot="${4:-$(sha256sum "$TMP/serve/get-aperire.sh" | cut -d' ' -f1)}"
  local at="${5:-2026-09-10T00:00:00Z}"
  cat > "$TMP/serve/release.json" <<EOF
{
  "tag": "$NEW_TAG",
  "commit": "$NEW_COMMIT",
  "sha256": "$1",
  "published_at": "$at",
  "bootstrap_sha256": "$boot",
  "committed_signers_sha256": "${COMMITTED_FOR_PUBLISH:-$(awk '!/^[[:space:]]*#/ && NF >= 4 { print $3 " " $4 }' "$TMP/lib/release-signers" | LC_ALL=C sort | sha256sum | cut -d' ' -f1)}",
  "files_sha256": "$(printf 'f%.0s' {1..64})"
}
EOF
  printf '%s  release.tar.gz\n' "$2" > "$TMP/serve/release.tar.gz.sha256"
  rm -f "$TMP/serve"/release-*.json "$TMP/serve"/release-*.json.sig "$TMP/serve/release.json.sig"
  ssh-keygen -q -Y sign -f "$key" -n aperire-release "$TMP/serve/release.json" </dev/null
  cp "$TMP/serve/release.json" "$TMP/serve/release-$1.json"
  cp "$TMP/serve/release.json.sig" "$TMP/serve/release-$1.json.sig"
}

# The bootstrap the endpoint serves. It records what it was handed, prints the
# headings the real one prints, and leaves behind exactly what the real one
# leaves behind: a kept tree, a database snapshot beside the checkout, and a
# stamp naming the release that was applied.
cat > "$TMP/serve/get-aperire.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" > "$TMP/state/boot-argv"
printf '%s\n' "\${SUDO_USER:-<none>}" > "$TMP/state/boot-operator"
printf '%s\n' "\${NO_COLOR:-<none>}" > "$TMP/state/boot-nocolor"
dir=""
while [[ \$# -gt 0 ]]; do case "\$1" in --dir) dir="\$2"; shift 2 ;; *) shift ;; esac; done
[[ -e "$TMP/state/boot-fails" ]] && { echo "the release did not unpack"; exit 1; }
echo ""
echo "snapshotting the database, before anything moves"
touch "\${dir}.db-20260910T101010Z"
echo ""
echo "fetching the release"
echo ""
echo "carrying your files into the new release"
mkdir -p "\${dir}.previous-20260910T101010Z"
cp "\${dir}/install.sh" "\${dir}.previous-20260910T101010Z/install.sh"
echo ""
echo "installing"
echo "  ok    everything from the release"
printf '{\n  "tag": "$NEW_TAG",\n  "commit": "$NEW_COMMIT",\n  "sha256": "$NEW_SHA",\n  "published_at": "2026-09-10T00:00:00Z",\n  "source_url": "",\n  "installed_at": ""\n}\n' > "\${dir}/.release"
exit 0
EOF
printf "DEFAULT_EXPECTED_SHA256='%s'\n" "$NEW_SHA" >> "$TMP/serve/get-aperire.sh"
printf '%s\n' '# --- end of get-aperire.sh ---' >> "$TMP/serve/get-aperire.sh"

# ── The host this program is pointed at ─────────────────────────────
DIR="$TMP/aperire-one"
ME="$(id -un)"
reset_host() {
  rm -rf "$TMP"/aperire-one*
  mkdir -p "$DIR/data" "$DIR/dashboard/config" "$DIR/advisor"
  # shellcheck disable=SC2016  # the fixture's own $0 and $*, written as text
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> %s/state/install-argv\nprintf "%%s %%s\\n" "$0" "${APERIRE_INSTALL_TREE:-<unset>}" >> %s/state/install-self\nexit 0\n' "$TMP" "$TMP" > "$DIR/install.sh"
  chmod +x "$DIR/install.sh"
  printf 'the database\n' > "$DIR/data/aperire.db"
  printf 'this tree is the new one\n' > "$DIR/marker"
  printf '{\n  "tag": "snapshot-2026-09-01",\n  "commit": "0000111",\n  "sha256": "%s",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' "$OLD_SHA" > "$DIR/.release"
  rm -f "$TMP/state/restarted" "$TMP/state/boot-argv" "$TMP/state/install-argv" "$TMP/state/install-self"
  rm -f "$TMP/run/update.lock"
}
write_conf() { # $1 = the endpoint
  cat > "$TMP/etc/update.conf" <<EOF
ENDPOINT=$1
INSTALL_DIR=$DIR
OPERATOR=$ME
EOF
}
units() { # the unit files this "host" carries
  rm -f "$TMP/units"/*.service "$TMP/state"/active-* "$TMP/state"/down-*
  local u
  for u in "$@"; do
    printf '[Service]\nUser=%s\n' "$ME" > "$TMP/units/${u}.service"
    : > "$TMP/state/active-$u"
  done
}

run_sut() { # payload on stdin
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_UPDATE_CONF="$TMP/etc/update.conf" \
      APERIRE_UPDATE_RUN_DIR="$TMP/run" \
      APERIRE_UNIT_DIR="$TMP/units" \
      APERIRE_UPDATE_RESTART_WAIT=2 \
      APERIRE_RELEASE_DIGESTS="$TMP/lib/release.sha256" \
      APERIRE_UPDATE_FLEET_BROKER="${FLEET_BROKER_828:-$TMP/no-such-broker}" \
      APERIRE_UPDATE_FLEET_BROKER_ETC="${FLEET_BROKER_ETC_828:-$TMP/no-such-etc}" \
      ${TEST_POISON_EUID:+EUID=$TEST_POISON_EUID} \
      bash "$SUT"
}
status_of() { sed -n 's/^exit=//p' <<<"$1" | tail -1; }
fact_of()   { sed -n "s/^$2=//p" <<<"$1" | tail -1; }
steps_of()  { sed -n 's/^step=//p' <<<"$1" | tr '\n' ' ' | sed 's/ $//'; }

publish "$NEW_SHA" "$NEW_SHA"
write_conf "$ENDPOINT"
units aperire-server aperire-relay
reset_host

echo
echo "── check: two files, and they have to agree ───────────────────────"

out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(fact_of "$out" verdict)" == behind \
      && "$(fact_of "$out" published_tag)" == "$NEW_TAG" \
      && "$(fact_of "$out" installed_sha256)" == "$OLD_SHA" ]]; then
  ok "a host on an older release reads behind, and both stamps are named"
else
  bad "check names both releases and grades them" "$out"; fi

printf '{\n  "tag": "snapshot-2026-09-01",\n  "commit": "0000111",\n  "sha256": "%s",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' "$NEW_SHA" > "$DIR/.release"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == current ]]; then
  ok "and a host on the published archive reads current"
else
  bad "a host on the published archive reads current" "$out"; fi

rm -f "$DIR/.release"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == behind ]] && grep -q 'carries no release stamp' <<<"$out"; then
  ok "and a host with no stamp is never current, and is told why"
else
  bad "unknown is never current" "$out"; fi
reset_host

publish "$NEW_SHA" "0000000000000000000000000000000000000000000000000000000000000000"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == mid_publish && "$(status_of "$out")" == 0 ]]; then
  ok "release.json and the sum beside it disagreeing is a publish in progress, not an update"
else
  bad "a disagreement between the two files is mid_publish" "$out"; fi

write_conf "http://127.0.0.1:1"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == unreachable && "$(status_of "$out")" == 0 ]]; then
  ok "an endpoint that does not answer is unreachable, and check still ends 0"
else
  bad "an unreachable endpoint is said out loud" "$out"; fi
write_conf "$ENDPOINT"
publish "$NEW_SHA" "$NEW_SHA"

echo
echo "── the release signature, against the key on this host ────────────"

# Signed by somebody else: check offers nothing, and says why.
publish "$NEW_SHA" "$NEW_SHA" "$TMP/otherkey"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(fact_of "$out" verdict)" == unreachable \
      && "$(fact_of "$out" signature)" == refused && -z "$(fact_of "$out" published_tag)" ]] \
   && grep -q 'not signed by this host' <<<"$out"; then
  ok "check refuses a release signed by any other key: no verdict, no release offered, and the reason said"
else
  bad "check refuses a release not signed by the host's key" "$out"; fi

reset_host
before=$(wc -l < "$HITS")
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
after=$(wc -l < "$HITS")
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]] \
   && ! sed -n "$((before + 1)),\$p" "$HITS" | grep -qx '/'; then
  ok "and apply refuses it with exit 7, without ever fetching the install script"
else
  bad "apply refuses a release signed by another key" "exit $(status_of "$out"): $out"; fi

# No signature at all.
publish "$NEW_SHA" "$NEW_SHA"
rm -f "$TMP/serve/release-$NEW_SHA.json.sig"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]] && grep -q 'no signature' <<<"$out"; then
  ok "a release with no signature is refused the same way"
else
  bad "an unsigned release is refused" "$out"; fi

# Tampered after signing: the signed copy says one thing, its signature was
# made over another.
publish "$NEW_SHA" "$NEW_SHA"
sed -i 's/"snapshot-2026-09-10"/"snapshot-evil"/' "$TMP/serve/release-$NEW_SHA.json"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]]; then
  ok "a signed release.json changed after signing is refused, and nothing is run"
else
  bad "a tampered signed release.json is refused" "$out"; fi

# The install script is the thing root runs. Signed release, correct stamp in
# the script, and the script's own bytes are not the ones signed.
publish "$NEW_SHA" "$NEW_SHA" "$TMP/testkey" "$(printf 'e%.0s' {1..64})"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]] \
   && grep -q 'not the one the signed release names, so it was not run' <<<"$out"; then
  ok "an install script that is not byte for byte the signed one is fetched and never run"
else
  bad "a bootstrap that is not the signed one is not run" "$out"; fi

# That row has to be able to fail. Take the comparison out and the same
# script runs as root.
NOBOOT="$TMP/update-no-boot-check.sh"
# shellcheck disable=SC2016  # a literal line to find in the file, not an expression
sed 's/^  if \[\[ -z "$PUB_BOOT_SHA256" || "$got" != "$PUB_BOOT_SHA256" \]\]; then$/  if false; then/' "$SUT" > "$NOBOOT"
if grep -q '^  if false; then$' "$NOBOOT"; then
  reset_host
  out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" \
    | env PATH="$TMP/bin:/usr/bin:/bin" APERIRE_UPDATE_CONF="$TMP/etc/update.conf" APERIRE_UPDATE_RUN_DIR="$TMP/run" \
          APERIRE_UNIT_DIR="$TMP/units" APERIRE_UPDATE_RESTART_WAIT=2 bash "$NOBOOT" 2>&1)"
  if [[ -f "$TMP/state/boot-argv" ]]; then
    ok "take that comparison out and the same unsigned script is run as root, which is what it is there to stop"
  else
    bad "without the bootstrap comparison the script runs" "$out"; fi
else
  bad "the bootstrap comparison can be found to take out" "the line has moved in $ORIG"; fi

# Signed, and with no publish date: refused, never waved through the
# downgrade check.
publish "$NEW_SHA" "$NEW_SHA" "$TMP/testkey" "" "someday"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]] && grep -q 'no valid publish date' <<<"$out"; then
  ok "a signed release with no valid publish date is refused, so the downgrade check cannot be skipped"
else
  bad "a signed release with no date is refused" "$out"; fi

# Lab or real is WHICH key, never what kind. A host whose set is the key
# committed for the release says nothing; a host whose set is not (a lab or
# test key) says so on every run.
publish "$NEW_SHA" "$NEW_SHA"
out="$(printf 'check\n' | run_sut 2>&1)"
if ! grep -q 'WARNING: this host trusts a release key' <<<"$out" && [[ -z "$(fact_of "$out" signers)" ]]; then
  ok "a host trusting the committed release key does not call itself a lab host"
else
  bad "the committed key reads as real" "$out"; fi
COMMITTED_FOR_PUBLISH="$(printf 'e%.0s' {1..64})" publish "$NEW_SHA" "$NEW_SHA"
out="$(printf 'check\n' | run_sut 2>&1)"
if grep -q '^WARNING: this host trusts a release key that is not the one committed for its releases' <<<"$out" \
   && [[ "$(fact_of "$out" signers)" == lab ]]; then
  ok "a host trusting a key that is not the committed one (a lab or test key) says so loudly on every run"
else
  bad "a lab-keyed host warns" "$out"; fi

# A host with no key installed refuses everything, and says what to run.
publish "$NEW_SHA" "$NEW_SHA"
mv "$TMP/lib/release-signers" "$TMP/lib/release-signers.away"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
mv "$TMP/lib/release-signers.away" "$TMP/lib/release-signers"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]] && grep -q -- '--run update-grant --program-only' <<<"$out"; then
  ok "a host with no release key installed refuses every release, and names the command that puts it back"
else
  bad "a host with no key refuses" "$out"; fi

# Never backwards: the host's kept signed release is newer than what is on
# offer. Validly signed, and still refused.
publish "$NEW_SHA" "$NEW_SHA" "$TMP/testkey" "" "2026-09-10T00:00:00Z"
KEPT_SHA="$OLD_SHA"
mkdir -p "$TMP/store/$KEPT_SHA"
printf '{\n  "tag": "snapshot-later",\n  "commit": "0000999",\n  "sha256": "%s",\n  "published_at": "2026-09-20T00:00:00Z"\n}\n' "$KEPT_SHA" > "$TMP/store/$KEPT_SHA/release.json"
ssh-keygen -q -Y sign -f "$TMP/testkey" -n aperire-release "$TMP/store/$KEPT_SHA/release.json" </dev/null
printf '%s\n' "$KEPT_SHA" > "$TMP/store/current"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" ]] && grep -q 'never goes backwards' <<<"$out"; then
  ok "a validly signed release published before the one this host is on is refused"
else
  bad "an older release is refused" "$out"; fi
# L3 of #759's review: check offers nothing apply would refuse. Reproduced
# first: check used to read this release as behind and offer it.
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == unreachable && "$(fact_of "$out" published_older)" == yes ]] \
   && grep -q 'never goes backwards' <<<"$out"; then
  ok "check does not offer a replayed older release as an update"
else
  bad "check refuses an older release" "$out"; fi
# The same moment, a different archive: refused on the tie, not let through.
publish "$NEW_SHA" "$NEW_SHA" "$TMP/testkey" "" "2026-09-20T00:00:00Z"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
out2="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" && "$(fact_of "$out2" published_older)" == yes ]]; then
  ok "a different archive published at the same moment is refused by apply and not offered by check"
else
  bad "an equal publish date is refused" "$out / $out2"; fi
publish "$NEW_SHA" "$NEW_SHA" "$TMP/testkey" "" "2026-09-10T00:00:00Z"
# The same kept release, re-signed by somebody else, is not believed: the
# date it states is ignored and the update goes ahead.
ssh-keygen -q -Y sign -f "$TMP/otherkey" -n aperire-release "$TMP/store/$KEPT_SHA/release.json" <<<y >/dev/null 2>&1 || true
rm -f "$TMP/store/$KEPT_SHA/release.json.sig"
ssh-keygen -q -Y sign -f "$TMP/otherkey" -n aperire-release "$TMP/store/$KEPT_SHA/release.json" </dev/null
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && -f "$TMP/state/boot-argv" ]]; then
  ok "and a kept release the host's key did not sign is not believed about its date"
else
  bad "an unverified kept release does not block an update" "$out"; fi
rm -rf "$TMP/store"/*
# The high-water mark the bootstrap keeps holds on its own: the kept release
# is gone, and an older release is still refused and not offered.
printf '2026-09-20T00:00:00Z\n' > "$TMP/store/high-water"; chmod 0644 "$TMP/store/high-water"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
out2="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 7 && ! -f "$TMP/state/boot-argv" && "$(fact_of "$out2" published_older)" == yes ]]; then
  ok "with no kept release, the high-water date still refuses an older release in apply and in check"
else
  bad "the high-water date holds without a kept release" "$out / $out2"; fi
# A high-water file someone else could write is not believed.
chmod 0666 "$TMP/store/high-water"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && -f "$TMP/state/boot-argv" ]]; then
  ok "and a high-water file writable by others is not believed about its date"
else
  bad "a writable high-water file is ignored" "$out"; fi
rm -rf "$TMP/store"/*
# Info of #759's review: a lab-keyed host says so even when the public
# release is refused on its key. The release it is on (kept, signed by its
# own key) names a committed set that is not its set.
mkdir -p "$TMP/store/$OLD_SHA"
printf '{\n  "sha256": "%s",\n  "published_at": "2026-09-01T00:00:00Z",\n  "committed_signers_sha256": "%s"\n}\n' \
  "$OLD_SHA" "$(printf 'e%.0s' {1..64})" > "$TMP/store/$OLD_SHA/release.json"
ssh-keygen -q -Y sign -f "$TMP/testkey" -n aperire-release "$TMP/store/$OLD_SHA/release.json" </dev/null
printf '%s\n' "$OLD_SHA" > "$TMP/store/current"
publish "$NEW_SHA" "$NEW_SHA" "$TMP/otherkey"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(fact_of "$out" signature)" == refused && "$(fact_of "$out" signers)" == lab ]]; then
  ok "a lab-keyed host still says lab when the public release is refused on its key"
else
  bad "the lab label survives a refused release" "$out"; fi
rm -rf "$TMP/store"/*
publish "$NEW_SHA" "$NEW_SHA"
reset_host

echo
echo "── apply: the payload carries no source ───────────────────────────"

before=$(wc -l < "$HITS")
out="$(printf 'apply tag=%s commit=%s sha256=%s source=http://evil.example\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
after=$(wc -l < "$HITS")
if [[ "$(status_of "$out")" == 2 && "$before" == "$after" ]] && grep -q "carries no source" <<<"$out"; then
  ok "a payload naming a source is refused, and nothing was fetched"
else
  bad "a source in the payload is refused before any fetch" "exit $(status_of "$out"), $((after-before)) requests: $out"; fi

out="$(printf 'apply tag=%s commit=%s sha256=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q "twice" <<<"$out"; then
  ok "and a key named twice is refused rather than resolved"
else
  bad "a repeated key is refused" "$out"; fi

out="$(printf 'apply tag=%s commit=%s\n' "$NEW_TAG" "$NEW_COMMIT" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q 'sha256=' <<<"$out"; then
  ok "and an apply with no checksum is refused, naming what is missing"
else
  bad "an apply needs all three" "$out"; fi

echo
echo "── apply: it installs what the endpoint publishes, or nothing ─────"

for pair in "tag:snapshot-of-my-own" "commit:deadbee" "sha256:$OLD_SHA"; do
  key="${pair%%:*}"; value="${pair#*:}"
  t="$NEW_TAG"; c="$NEW_COMMIT"; s="$NEW_SHA"
  case "$key" in tag) t="$value" ;; commit) c="$value" ;; sha256) s="$value" ;; esac
  before=$(wc -l < "$HITS")
  out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$t" "$c" "$s" | run_sut 2>&1)"
  after=$(wc -l < "$HITS")
  # Four requests: release.json, the sum, and the signed release.json with its
  # signature. The bootstrap would be the fifth, and it is the one that must
  # not have been asked for.
  if [[ "$(status_of "$out")" == 3 && $((after - before)) -eq 4 && ! -f "$TMP/state/boot-argv" ]]; then
    ok "a $key that is not the endpoint's is refused, and the install script was never fetched"
  else
    bad "a $key that disagrees is refused with nothing fetched" "exit $(status_of "$out"), $((after-before)) requests: $out"
  fi
done

# What an operator READS when that happens (#293). The refusal names the two
# RELEASES; the sums are on their own lines above it, where they can be
# compared without reading a sentence through them.
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "snapshot-of-my-own" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
err="$(fact_of "$out" error)"
if [[ "$(status_of "$out")" == 3 ]] \
   && grep -q "you asked for snapshot-of-my-own and $ENDPOINT publishes $NEW_TAG" <<<"$err" \
   && ! grep -q -e "$NEW_SHA" <<<"$err" \
   && grep -q "^  sha256   $NEW_SHA\$" <<<"$out"; then
  ok "the refusal names both releases, and the sums are beside it rather than inside it"
else
  bad "a refusal an operator can read" "$out"; fi

if [[ "$(fact_of "$out" published_tag)" == "$NEW_TAG" && "$(fact_of "$out" published_sha256)" == "$NEW_SHA" ]]; then
  ok "and it says what the endpoint publishes, so the page can name it"
else
  bad "apply reports the published release as facts" "$out"; fi

for v in check rollback; do
  out="$(printf '%s\n' "$v" | run_sut 2>&1)"
  if [[ "$(fact_of "$out" endpoint)" == "$ENDPOINT" ]]; then
    ok "$v says which endpoint this host installs from"
  else
    bad "every verb names the endpoint it read from update.conf" "$out"; fi
done

# ── the verb set, asserted against the REAL file ────────────────────
#
# #275 put a second caller on the other side of this socket: an aggregator
# can now ask a node's dashboard to run this program, over the fleet link. It
# added NOTHING here, and that is a property worth asserting rather than
# assuming. A fifth verb arriving with a fleet feature would be a privileged
# act crossing the link, which is its own decision and its own review.
#
# Read off the dispatch in the original rather than off the scratch copy, and
# grep is given `|| true` so a pattern that matches nothing cannot end this
# script before it reaches its own refusal line.
# shellcheck disable=SC2016  # a literal to match in the file, not an expression
verbs="$(sed -n '/^  case "$verb" in$/,/^  esac$/p' "$ORIG" \
  | grep -oE '^    [a-z]+\)' || true)"
verbs="$(printf '%s\n' "$verbs" | tr -d ' )' | sort | tr '\n' ' ' | sed 's/ $//')"
if [[ "$verbs" == "apply check restart rollback" ]]; then
  ok "the verb set is still exactly check, apply, restart, rollback"
else
  bad "this program does four things and no more" "found: '$verbs'"; fi

# And the two sentences that name them for an operator agree with the switch.
if grep -qF 'One of: check, apply, restart, rollback.' "$ORIG"; then
  ok "  and the refusal it prints names the same four"
else
  bad "the refusal names the verb set" "the sentence naming the four verbs is not in $ORIG"; fi

echo
echo "── apply: one run at a time ───────────────────────────────────────"

( exec 9>"$TMP/run/update.lock"; flock 9; sleep 6 ) &
HOLDER=$!
sleep 1
before=$(wc -l < "$HITS")
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
after=$(wc -l < "$HITS")
if [[ "$(status_of "$out")" == 4 && "$before" == "$after" ]] && grep -q 'already running' <<<"$out"; then
  ok "a second apply while one is in flight is refused, and asks the endpoint nothing"
else
  bad "the lock refuses a second apply" "exit $(status_of "$out"), $((after-before)) requests: $out"; fi
kill "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null

echo
echo "── apply: what it hands the bootstrap, and what comes back ────────"

reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
argv="$(cat "$TMP/state/boot-argv" 2>/dev/null || true)"
if [[ "$argv" == "--update --yes --no-restart --dir $DIR" ]]; then
  ok "the bootstrap is run with exactly --update --yes --no-restart --dir <dir>, and no source"
else
  bad "the bootstrap's arguments are exactly four" "got: '$argv'"; fi

if [[ "$(cat "$TMP/state/boot-operator" 2>/dev/null)" == "$ME" ]]; then
  ok "and with the operator's name in front of it, so the tree it swaps stays theirs"
else
  bad "SUDO_USER reaches the bootstrap" "got: '$(cat "$TMP/state/boot-operator" 2>/dev/null)'"; fi

if [[ "$(cat "$TMP/state/boot-nocolor" 2>/dev/null)" == "1" ]]; then
  ok "and with colour off, because the page renders this stream"
else
  bad "NO_COLOR reaches the bootstrap" "got: '$(cat "$TMP/state/boot-nocolor" 2>/dev/null)'"; fi

if [[ "$(steps_of "$out")" == "snapshot fetch carry install done" ]]; then
  ok "the step markers appear once each, in the order the update takes them"
else
  bad "the step markers are in order" "got: '$(steps_of "$out")'"; fi

if grep -q '^  ok    everything from the release$' <<<"$out"; then
  ok "and every line the bootstrap printed is on the stream, so the page can tail it"
else
  bad "the bootstrap's output is streamed" "$out"; fi

if [[ "$(fact_of "$out" stamp)" == "$NEW_TAG" && "$(fact_of "$out" stamp_sha256)" == "$NEW_SHA" ]]; then
  ok "the new stamp is named, read back off the host rather than from the payload"
else
  bad "the stamp is named" "$out"; fi

if [[ "$(fact_of "$out" previous)" == "${DIR}.previous-20260910T101010Z" \
      && "$(fact_of "$out" db_snapshot)" == "${DIR}.db-20260910T101010Z" ]]; then
  ok "and the kept tree and the database snapshot are named by path"
else
  bad "the kept tree and the snapshot are named" "$out"; fi

if [[ "$(sed -n 's/^  "sha256": "\(.*\)",$/\1/p' "${DIR}.previous-20260910T101010Z/.release" 2>/dev/null)" == "$OLD_SHA" ]]; then
  ok "and the kept tree is left carrying the release it IS, which is what a rollback needs"
else
  bad "the kept tree keeps its own stamp" "$(cat "${DIR}.previous-20260910T101010Z/.release" 2>/dev/null)"; fi

if [[ "$(status_of "$out")" == 0 && ! -f "$TMP/state/restarted" ]]; then
  ok "and nothing was restarted"
else
  bad "an apply restarts nothing" "exit $(status_of "$out"), restarted: $(cat "$TMP/state/restarted" 2>/dev/null)"; fi

echo
echo "── apply: needs_restart is only what this host has ────────────────"

# systemd says the Advisor is active, and this host has no Advisor unit. What
# a page is told to offer must come from the unit files, not from a name.
: > "$TMP/state/active-aperire-advisord"
reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(fact_of "$out" needs_restart)" == "aperire-server aperire-relay" ]]; then
  ok "needs_restart names the two units this host carries and not the one it does not"
else
  bad "needs_restart is what the host has" "got: '$(fact_of "$out" needs_restart)'"; fi
rm -f "$TMP/state/active-aperire-advisord"

reset_host
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == current && "$(status_of "$out")" == 0 && ! -f "$TMP/state/boot-argv" ]]; then
  bad "applying twice is a no-op" "the second apply should have found the stamp already current"
else
  # The host was reset to the older stamp, so this one really does apply.
  ok "a host that is not on the release applies it"
fi

printf '{\n  "tag": "%s",\n  "commit": "%s",\n  "sha256": "%s",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' \
  "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" > "$DIR/.release"
rm -f "$TMP/state/boot-argv"
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(fact_of "$out" verdict)" == current && "$(status_of "$out")" == 0 && ! -f "$TMP/state/boot-argv" ]]; then
  ok "a host already on the published release is told so, and nothing is fetched or swapped"
else
  bad "an apply on a current host does nothing" "$out"; fi

echo
echo "── apply: when the bootstrap does not finish ──────────────────────"

reset_host
: > "$TMP/state/boot-fails"
out="$(printf 'apply tag=%s commit=%s sha256=%s\n' "$NEW_TAG" "$NEW_COMMIT" "$NEW_SHA" | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 6 ]] && grep -q '^step=failed$' <<<"$out" \
   && grep -q 'Nothing was swapped' <<<"$out"; then
  ok "a bootstrap that fails before it swapped says so, and says the tree is untouched"
else
  bad "a failed apply names the step and the state of the box" "$out"; fi
rm -f "$TMP/state/boot-fails"

echo
echo "── restart: a second ask, and only this host's units ──────────────"

reset_host
out="$(printf 'restart units=aperire-server,nginx\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && ! -f "$TMP/state/restarted" ]] && grep -q 'not one of this host' <<<"$out"; then
  ok "a unit this host does not have is refused, and nothing is restarted"
else
  bad "an unknown unit is refused before anything moves" "$out"; fi

# Asked for with the dashboard FIRST, which is the order that breaks it: the
# dashboard is what holds the other end of this socket, so restarting it first
# takes the reader away and everything after it is never restarted at all.
out="$(printf 'restart units=aperire-server,aperire-relay\n' | run_sut 2>&1)"
if [[ "$(tr '\n' ' ' < "$TMP/state/restarted")" == "aperire-relay aperire-server " ]]; then
  ok "and the dashboard's own unit is restarted last, whatever order it was asked for"
else
  bad "the dashboard's unit goes last" "got: $(tr '\n' ' ' < "$TMP/state/restarted")"; fi

if grep -q '^unit=aperire-server state=active$' <<<"$out" && [[ "$(status_of "$out")" == 0 ]]; then
  ok "and each one's state is read back afterwards rather than assumed"
else
  bad "each unit's state is read back" "$out"; fi

rm -f "$TMP/state/restarted" "$TMP/state/active-aperire-relay"
: > "$TMP/state/down-aperire-relay"
out="$(printf 'restart units=aperire-relay\n' | run_sut 2>&1)"
if grep -q '^unit=aperire-relay state=failed$' <<<"$out" && grep -q '^error=' <<<"$out"; then
  ok "and one that does not come back is named, with the command that reads why"
else
  bad "a unit that did not come back is named" "$out"; fi
rm -f "$TMP/state/down-aperire-relay"
units aperire-server aperire-relay

echo
echo "── update.conf: who owns the tree, and who runs the dashboard (ADR 0024) ──"
# OPERATOR alone is a conf from before the split, and it still reads: every
# row above runs on one. A DASH_USER beside it is read and checked.
reset_host; write_conf "$ENDPOINT"
printf 'DASH_USER=no-such-account-here\n' >> "$TMP/etc/update.conf"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q "names the dashboard account 'no-such-account-here'" <<<"$out"; then
  ok "a DASH_USER naming no account is refused by name, so the key is read"
else
  bad "DASH_USER is read and checked" "exit $(status_of "$out"): $out"; fi
reset_host; write_conf "$ENDPOINT"
printf 'DASH_USER=%s\n' "$ME" >> "$TMP/etc/update.conf"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 ]]; then
  ok "  and a DASH_USER that exists is taken"
else
  bad "a good DASH_USER is taken" "exit $(status_of "$out"): $out"; fi
# The tree's owner is never a service account: the update builds the tree
# as OPERATOR and root runs installers out of it (#869 review, L7). nobody
# is a real account here with no login shell.
reset_host; write_conf "$ENDPOINT"
sed -i "s/^OPERATOR=.*/OPERATOR=nobody/" "$TMP/etc/update.conf"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q "names 'nobody' as the tree's owner, and that is a service account" <<<"$out"; then
  ok "an OPERATOR with no login shell is refused: the update never builds the tree as a service account"
else
  bad "a service-account OPERATOR is refused" "exit $(status_of "$out"): $out"; fi
# And never root: runuser -u root is root running the tree's owner's work
# again, which is the fallback the rolled-back prune is built not to have
# (#1150).
reset_host; write_conf "$ENDPOINT"
sed -i "s/^OPERATOR=.*/OPERATOR=root/" "$TMP/etc/update.conf"
out="$(printf 'check\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q "names 'root' as the tree's owner, and that is root" <<<"$out"; then
  ok "an OPERATOR of root is refused: the tree belongs to the operator who installed it"
else
  bad "OPERATOR=root is refused" "exit $(status_of "$out"): $out"; fi
reset_host; write_conf "$ENDPOINT"

echo "── rollback: it will not choose between two, or invent one ────────"

reset_host
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q 'no kept tree' <<<"$out"; then
  ok "with no kept tree there is nothing to go back to, and it says so"
else
  bad "rollback with no kept tree is refused" "$out"; fi

# No pointer from an earlier row: a recycled inode must not name one of these.
rm -f "$TMP/lib/release.sha256.previous"
mkdir -p "${DIR}.previous-A/dashboard/config" "${DIR}.previous-B"
cp "$DIR/install.sh" "${DIR}.previous-A/install.sh"
cp "$DIR/install.sh" "${DIR}.previous-B/install.sh"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q 'will not choose' <<<"$out"; then
  ok "with two, it refuses to choose and names both"
else
  bad "rollback with two kept trees is refused" "$out"; fi
rm -rf "${DIR}.previous-B"

printf 'this tree is the old one\n' > "${DIR}.previous-A/marker"
# The tree's own stamp names a DECOY key (#782): the tree's account can
# rewrite .release, and a rollback that chose its record by it would bring
# back whichever kept record that account named. Root's pointer names OLD.
DECOY_SHA="$(printf 'd%.0s' {1..64} | tr d e)"
printf '{\n  "tag": "snapshot-2026-09-01",\n  "commit": "0000111",\n  "sha256": "%s",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' "$DECOY_SHA" > "${DIR}.previous-A/.release"
touch "${DIR}.db-20260910T101010Z"
# The release digests (ADR 0024): the record of the tree being rolled away
# from, and kept beside it under its key, the one the kept tree came with.
# A decoy kept under another key must not be the one chosen.
mkdir -p "$TMP/lib/release.sha256.kept"
printf '# anchor the NEW release\n# key %s\n' "$NEW_SHA" > "$TMP/lib/release.sha256"
# What the update that moved the tree aside recorded for it, Advisor source
# included: the record lists every file the release shipped (#951). The kept
# tree's Advisor source is a pre-socket one to begin with.
ADV_SRC_DIR="${DIR}.previous-A/advisor/cmd/aperire-advisord"
mkdir -p "$ADV_SRC_DIR"
printf 'package main\n\nfunc main() {\n\tflag.String("wrapper", "", "the node wrapper")\n\tflag.Bool("sudo-wrapper", false, "reach it with sudo")\n}\n' > "$ADV_SRC_DIR/main.go"
# The real directory holds about forty Go files; one is not enough to tell a
# release judged on all of its source from one judged on whichever file
# happened to agree.
CALLER_SRC=$'package main\n\nfunc call() string {\n\treturn "the caller"\n}\n'
printf '%s' "$CALLER_SRC" > "$ADV_SRC_DIR/caller.go"
record_kept_A() {
  kept_record "${DIR}.previous-A" "the OLD release" "$OLD_SHA" > "$TMP/lib/release.sha256.kept/$OLD_SHA"
  kept_record "${DIR}.previous-A" "a decoy" "$DECOY_SHA" > "$TMP/lib/release.sha256.kept/$DECOY_SHA"
}
record_kept_A
point_previous "${DIR}.previous-A" "$OLD_SHA"
# A rollback across ADR 0025 (#779 review, M1): the Advisor's unit was
# converted to its root socket, and the kept release's advisord predates the
# flag. Reproduced first: an advisord without the flag stops on it, so the
# Advisor would restart in a loop, with no sudo rule left to reach the node
# by. Refused before anything moves, naming the way back by hand.
#
# The release is judged by its Advisor source, held to root's record of that
# tree (#951), never by a binary: a kept tree has none, because the update
# carries advisor/bin into the new tree. The live tree has the carried build,
# which knows the flag; the kept tree carries a decoy binary that does too, so
# a row can only pass by reading the source.
printf '[Service]\nUser=%s\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=/usr/local/sbin/aperire-node-wrapper --wrapper-socket=/run/aperire/node-wrapper.sock\n' "${ADV_ACCT:-aperire-advisor}" \
  "$DIR" > "$TMP/units/aperire-advisord.service"
mkdir -p "$DIR/advisor/bin"
printf 'the build carried from the release left, knows --wrapper-socket\n' > "$DIR/advisor/bin/aperire-advisord"
chmod 0755 "$DIR/advisor/bin/aperire-advisord"
mkdir -p "${DIR}.previous-A/advisor/bin"
printf 'a decoy binary that mentions wrapper-socket\n' > "${DIR}.previous-A/advisor/bin/aperire-advisord"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && "$(cat "$DIR/marker" 2>/dev/null)" != "this tree is the old one" \
      && -d "${DIR}.previous-A" ]] && grep -q 'predates the socket' <<<"$out" \
   && grep -q 'get.aperire.one/uninstall | bash -s -- --role=advisor' <<<"$out" && grep -q 'never write back' <<<"$out"; then
  ok "a rollback to a release whose Advisor source predates the socket is refused before anything moves, with the way back named, whatever binary sits in the tree"
else
  bad "a rollback never strands a socket Advisor" "exit $(status_of "$out"): $out"; fi
rm -rf "${DIR}.previous-A/advisor/bin"

# One of the kept tree's Advisor source files gained the flag after root
# recorded it, while the other still agrees: root cannot tell what that
# release is, and says so rather than guessing either way (#951 review, L1).
printf '\tflag.String("wrapper-socket", "", "the root socket")\n' >> "$ADV_SRC_DIR/caller.go"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-A" ]] && grep -q 'cannot confirm' <<<"$out" \
   && ! grep -q 'predates the socket' <<<"$out"; then
  ok "a kept tree whose Advisor source is not the one root recorded is refused as unconfirmed, not read as old or new"
else
  bad "a rewritten Advisor source is not believed" "exit $(status_of "$out"): $out"; fi

# A recorded source file that is gone: the same answer, not a verdict from
# the files that remain.
rm -f "$ADV_SRC_DIR/caller.go"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-A" ]] && grep -q 'cannot confirm' <<<"$out" \
   && ! grep -q 'predates the socket' <<<"$out"; then
  ok "a recorded Advisor source file that is missing is refused as unconfirmed, not read as old"
else
  bad "a missing Advisor source file is not a pre-socket release" "exit $(status_of "$out"): $out"; fi

# The tree's account controls every name in it (#951 review, M1). A FIFO
# stands for any file root must never open: a writer waits on it and leaves a
# mark if anything opens it for reading. A stand-in for timeout swaps the
# file for a link between the check and the read, the race itself.
TRAP_FIFO="$TMP/trap.fifo"; TRAP_OPENED="$TMP/trap.opened"
arm_trap() {
  rm -f "$TRAP_FIFO" "$TRAP_OPENED"; mkfifo "$TRAP_FIFO"
  # shellcheck disable=SC2016  # the inner shell's own positional parameters
  ( timeout 30 bash -c 'exec 3>"$1"; : > "$2"' trap "$TRAP_FIFO" "$TRAP_OPENED" >/dev/null 2>&1 & )
}
disarm_trap() { pkill -f -- "$TRAP_FIFO" 2>/dev/null || true; rm -f "$TRAP_FIFO"; }
REAL_TIMEOUT="$(command -v timeout)"
cat > "$TMP/bin/timeout" <<TIMEOUT_STUB
#!/usr/bin/env bash
if [[ -n "\${SWAP_FILE:-}" ]]; then
  case "\$*" in *cat*|*python3*) rm -f "\$SWAP_FILE"; ln -s "\$SWAP_TARGET" "\$SWAP_FILE" ;; esac
fi
exec $REAL_TIMEOUT "\$@"
TIMEOUT_STUB
chmod +x "$TMP/bin/timeout"
restore_caller() { rm -f "$ADV_SRC_DIR/caller.go"; printf '%s' "$CALLER_SRC" > "$ADV_SRC_DIR/caller.go"; }

restore_caller
arm_trap
out="$(printf 'rollback\n' | SWAP_FILE="$ADV_SRC_DIR/caller.go" SWAP_TARGET="$TRAP_FIFO" run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-A" && ! -e "$TRAP_OPENED" ]] && grep -q 'cannot confirm' <<<"$out"; then
  ok "a source file swapped for a link between the check and the read is never followed"
else
  bad "root never opens through a link the tree's account plants" "opened=$([[ -e "$TRAP_OPENED" ]] && echo yes || echo no) exit $(status_of "$out"): $out"; fi
disarm_trap

rm -f "$ADV_SRC_DIR/caller.go"; arm_trap; ln -s "$TRAP_FIFO" "$ADV_SRC_DIR/caller.go"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && ! -e "$TRAP_OPENED" ]] && grep -q 'cannot confirm' <<<"$out"; then
  ok "and a source file that is a link is refused without being opened"
else
  bad "a planted link is not followed" "opened=$([[ -e "$TRAP_OPENED" ]] && echo yes || echo no) exit $(status_of "$out"): $out"; fi
disarm_trap

# A file past any size a release carries is refused, not streamed.
rm -f "$ADV_SRC_DIR/caller.go"; truncate -s 20M "$ADV_SRC_DIR/caller.go"
record_kept_A
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q 'cannot confirm' <<<"$out" && ! grep -q 'predates the socket' <<<"$out"; then
  ok "an Advisor source file larger than any a release carries is refused, even when it matches the record"
else
  bad "an oversized source file is capped" "exit $(status_of "$out"): $out"; fi
restore_caller

# The race inside the helper itself (#951 re-review, N2). The stand-in above
# acts before the helper starts, so only its first look at the file sees the
# swap. The helper honours one test hook, and only when it is not root: a
# command run between that look and the open. A file replaced there by a link
# to a FIFO must not be followed, and one replaced by a FIFO with no writer
# must not be waited on.
if [[ $EUID -ne 0 ]]; then
  record_kept_A
  # shellcheck disable=SC2016  # the hook's own $1
  printf '#!/usr/bin/env bash\nrm -f "$1"; ln -s "%s" "$1"\n' "$TRAP_FIFO" > "$TMP/swap-link.sh"
  # shellcheck disable=SC2016  # the hook's own $1
  printf '#!/usr/bin/env bash\nrm -f "$1"; mkfifo "$1"\n' > "$TMP/swap-fifo.sh"
  chmod +x "$TMP/swap-link.sh" "$TMP/swap-fifo.sh"

  arm_trap
  out="$(printf 'rollback\n' | APERIRE_UPDATE_TEST_BETWEEN="$TMP/swap-link.sh" run_sut 2>&1)"
  if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-A" && ! -e "$TRAP_OPENED" ]] && grep -q 'cannot confirm' <<<"$out"; then
    ok "a source file replaced by a link between the helper's look and its open is not followed"
  else
    bad "the open itself refuses a link" "opened=$([[ -e "$TRAP_OPENED" ]] && echo yes || echo no) exit $(status_of "$out"): $out"; fi
  disarm_trap
  restore_caller

  SECONDS=0
  out="$(printf 'rollback\n' | APERIRE_UPDATE_TEST_BETWEEN="$TMP/swap-fifo.sh" run_sut 2>&1)"
  if [[ "$(status_of "$out")" == 2 && $SECONDS -lt 30 ]] && grep -q 'cannot confirm' <<<"$out"; then
    ok "and one replaced by a pipe nobody writes to is refused at once, not waited on"
  else
    bad "the open never blocks" "took ${SECONDS}s, exit $(status_of "$out"): $out"; fi
  restore_caller

  # A helper that fails is not a verdict (N1): the record cannot be read, so
  # root cannot tell, and says so; it does not call the release old.
  chmod 000 "$TMP/lib/release.sha256.kept/$OLD_SHA"
  out="$(printf 'rollback\n' | run_sut 2>&1)"
  chmod 644 "$TMP/lib/release.sha256.kept/$OLD_SHA"
  if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-A" ]] && grep -q 'cannot confirm' <<<"$out" \
     && ! grep -q 'predates the socket' <<<"$out"; then
    ok "a helper that fails is read as 'cannot confirm', never as a pre-socket release"
  else
    bad "a crash is not a verdict" "exit $(status_of "$out"): $out"; fi
fi

# A record that names no Advisor source at all says nothing about the release.
mv "$ADV_SRC_DIR/main.go" "$TMP/main.go.held"; mv "$ADV_SRC_DIR/caller.go" "$TMP/caller.go.held"
record_kept_A
mv "$TMP/main.go.held" "$ADV_SRC_DIR/main.go"; mv "$TMP/caller.go.held" "$ADV_SRC_DIR/caller.go"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-A" ]] && grep -q 'cannot confirm' <<<"$out"; then
  ok "a record that names no Advisor source is refused as unconfirmed"
else
  bad "no Advisor source on record is not read as a pre-socket release" "exit $(status_of "$out"): $out"; fi

# The release as it shipped, with the flag in one of its files and the record
# naming both.
printf '\tflag.String("wrapper-socket", "", "the root socket")\n' >> "$ADV_SRC_DIR/caller.go"

# The record as the release shipped it, with the flag: the rollback goes ahead
# (the row below), and the kept tree has no advisor/bin at all.
record_kept_A

out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the old one" ]]; then
  ok "with exactly one, the kept tree comes back into place, a socket host and no advisor/bin in the kept tree"
else
  bad "rollback swaps the kept tree back" "exit $(status_of "$out"): $out"; fi
# The Advisor's programs come back with the tree: the carried build is there
# and runnable, so the unit has something to exec, and the operator is told
# it is the build of the release left.
if [[ -x "$DIR/advisor/bin/aperire-advisord" && "$(cat "$DIR/advisor/bin/aperire-advisord")" == *"carried from the release left"* ]] \
   && grep -q 'build from the release you left' <<<"$out"; then
  ok "and the Advisor's program is carried back with it, runnable, and said to be the build of the release left"
else
  bad "advisor/bin is carried back" "$(ls -l "$DIR/advisor/bin" 2>&1) $out"; fi

if [[ "$(head -1 "$TMP/lib/release.sha256" 2>/dev/null)" == "# anchor the OLD release" \
      && ! -e "$TMP/lib/release.sha256.kept/$OLD_SHA" \
      && "$(head -1 "$TMP/lib/release.sha256.kept/$NEW_SHA" 2>/dev/null)" == "# anchor the NEW release" ]]; then
  ok "and the record root recorded for the restored tree comes back, not the one its rewritten stamp names (#782)"
else
  bad "the kept tree's release digests come back with it, chosen by root's pointer, swapped not overwritten" \
      "current=$(head -2 "$TMP/lib/release.sha256" 2>/dev/null) kept=$(ls "$TMP/lib/release.sha256.kept" 2>/dev/null)"; fi
if [[ -f "$TMP/lib/release.sha256.kept/$DECOY_SHA" ]] && ! grep -q 'a decoy' "$TMP/lib/release.sha256"; then
  ok "and the decoy the tree's stamp named stays where it was"
else
  bad "the decoy is never chosen" "current=$(head -1 "$TMP/lib/release.sha256" 2>/dev/null)"; fi
# Root ran a copy of the restored tree's install.sh it staged and checked
# against that record (#764), never the tree's own file, and named the tree.
read -r SELF_RAN TREE_NAMED < <(head -1 "$TMP/state/install-self" 2>/dev/null) || true
if [[ -n "${SELF_RAN:-}" && "$SELF_RAN" != "$DIR/"* && "$SELF_RAN" == */run/install.sh && "${TREE_NAMED:-}" == "$DIR" ]]; then
  ok "and the installer root ran is a staged, checked copy of the restored tree's, told which tree to install"
else
  bad "the rollback runs a staged install.sh" "$(cat "$TMP/state/install-self" 2>/dev/null)"; fi

if [[ "$(cat "$DIR/data/aperire.db" 2>/dev/null)" == "the database" ]]; then
  ok "and the database comes with it, carried rather than left in the tree being replaced"
else
  bad "the database is carried back" "$(ls "$DIR/data" 2>/dev/null)"; fi
# As root, never as the operator (ADR 0024 lane 3): data/ is the dashboard's
# own account's on a fresh install, and the operator cannot move a directory
# it does not own to a new parent.
if [[ -s "$TMP/state/runuser-log" ]] && ! grep -q -- "mv .*/data " "$TMP/state/runuser-log"; then
  ok "and data/ is carried back by root, not by the operator"
else
  bad "data/ is carried back as root" "$(cat "$TMP/state/runuser-log" 2>/dev/null || echo 'runuser was never called')"; fi

if [[ "$(fact_of "$out" stamp)" == "snapshot-2026-09-01" ]]; then
  ok "and the host says which release it is on again"
else
  bad "the stamp comes back with the tree" "$out"; fi

if grep -q "^--role=co-located --yes --no-restart --no-preflight --quiet-existing$" "$TMP/state/install-argv" 2>/dev/null; then
  ok "and the restored tree's installer is run for this host's role, restarting nothing"
else
  bad "install.sh is re-run from the restored tree" "$(cat "$TMP/state/install-argv" 2>/dev/null)"; fi

# #641's second gate (the reveal window) is load-bearing on this NEVER
# passing --with-advisor: that flag is the only thing that makes install.sh
# reach install-advisor-stack.sh, which is the only caller of
# install-advisord.sh, which is the only thing that plants reveal.window.
# The exact-string match just above already pins this by construction (any
# added flag breaks it), and this row names the invariant so a future diff
# that loosens that match to a substring check does not quietly drop it.
if ! grep -q -- '--with-advisor' "$TMP/state/install-argv" 2>/dev/null; then
  ok "and --with-advisor is never one of the flags, so rollback can never replant #641's reveal window"
else
  bad "rollback's install.sh call must never carry --with-advisor (#641)" "$(cat "$TMP/state/install-argv" 2>/dev/null)"; fi

if grep -q 'db snapshot kept at' <<<"$out" && [[ "$(fact_of "$out" db_snapshot)" == "${DIR}.db-20260910T101010Z" ]]; then
  ok "and the database snapshot is named and left alone, in words that say it is not restored"
else
  bad "the snapshot is named and not restored" "$out"; fi

if [[ ! -f "$TMP/state/restarted" ]] && grep -q '^needs_restart=' <<<"$out"; then
  ok "and a rollback restarts nothing either: it names what is old and stops"
else
  bad "rollback restarts nothing" "restarted: $(cat "$TMP/state/restarted" 2>/dev/null)"; fi

rm -f "$TMP/units/aperire-advisord.service"

# The other branch (M1): the tree that comes back has no record kept for it.
# The record must never simply go: "no record" is the fallback that copies
# unchecked, and the update socket, which the dashboard account can reach,
# is how a rollback is asked for. It becomes a record that refuses every copy.
reset_host
mkdir -p "${DIR}.previous-C/dashboard/config"
cp "$DIR/install.sh" "${DIR}.previous-C/install.sh"
printf '{\n  "tag": "t",\n  "commit": "c",\n  "sha256": "%s",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' \
  "$(printf 'f%.0s' {1..64})" > "${DIR}.previous-C/.release"
# The release digests start clean; the release key beside them stays, since
# the rows after this one check releases against it.
find "$TMP/lib" -mindepth 1 -maxdepth 1 ! -name release-signers ! -name release-verify-lib.sh \
     ! -name release-digests-lib.sh ! -name trusted-path-lib.sh -exec rm -rf {} +
mkdir -p "$TMP/lib/release.sha256.kept"
printf '# anchor the NEW release\n# key %s\n' "$NEW_SHA" > "$TMP/lib/release.sha256"
printf '# anchor the OLD release\n# key %s\n' "$OLD_SHA" > "$TMP/lib/release.sha256.kept/$OLD_SHA"
# Since #764 and #782 a tree root recorded nothing for is refused before
# anything moves: root cannot check the installer it would run from it, and
# the tree's own stamp is not a source it may choose a record by. The record
# in place stays exactly as it was, so the host is never without one.
before_rec="$(cat "$TMP/lib/release.sha256")"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 ]] && grep -q 'root holds no release digests it recorded for that tree' <<<"$out" \
   && [[ -d "${DIR}.previous-C" && "$(cat "$TMP/lib/release.sha256")" == "$before_rec" ]] \
   && [[ ! -s "$TMP/state/install-argv" ]]; then
  ok "a tree root recorded no digests for is refused before anything moves, and the record in place is untouched"
else
  bad "a rollback to an unrecorded tree is refused" \
      "exit $(status_of "$out") current=$(head -2 "$TMP/lib/release.sha256" 2>/dev/null) $out"; fi
# The pointer has to name THIS tree: one naming another tree's inode, or a
# key with no record kept, is the same refusal.
printf '1:1 %s\n' "$OLD_SHA" > "$TMP/lib/release.sha256.previous"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-C" ]] && grep -q 'root holds no release digests' <<<"$out"; then
  ok "a pointer that names another tree is not this tree's, and the rollback is refused"
else
  bad "the pointer is matched by inode" "exit $(status_of "$out"): $out"; fi
rm -f "$TMP/lib/release.sha256.previous"

# Without root's own copy of the two libraries, root cannot check what it
# would run, so the rollback is refused before anything moves (#764).
point_previous "${DIR}.previous-C" "$OLD_SHA"
kept_record "${DIR}.previous-C" "the OLD release" "$OLD_SHA" > "$TMP/lib/release.sha256.kept/$OLD_SHA"
mv "$TMP/lib/trusted-path-lib.sh" "$TMP/lib/trusted-path-lib.sh.away"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 2 && -d "${DIR}.previous-C" ]] && grep -q 'no root-owned copy of the libraries' <<<"$out"; then
  ok "with root's copy of the checking libraries missing, a rollback is refused before anything moves"
else
  bad "a rollback needs root's own libraries" "exit $(status_of "$out"): $out"; fi
mv "$TMP/lib/trusted-path-lib.sh.away" "$TMP/lib/trusted-path-lib.sh"

# The restored tree's install.sh rewritten after root recorded it: the stage
# refuses it on its digest, and root never runs it (#764).
printf '#!/usr/bin/env bash\necho TREE RAN >> %s/state/TREE-RAN\n' "$TMP" > "${DIR}.previous-C/install.sh"
rm -f "$TMP/state/TREE-RAN"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 6 && ! -e "$TMP/state/TREE-RAN" ]] \
   && grep -q 'refused: install.sh is not the file this release shipped' <<<"$out" \
   && grep -q 'root would not run its installers' <<<"$out"; then
  ok "a restored tree whose install.sh was rewritten is never run by root, and the rollback says so"
else
  bad "a rewritten install.sh in the restored tree is never run" "exit $(status_of "$out") ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null): $out"; fi
rm -rf "${DIR}.previous-C" "${DIR}.rolled-back-"*

echo
echo "── rollback: the fleet broker's pin comes with the tree (#828) ────"
#
# A rollback swaps the tree by rename, like the update, so the broker's pin
# on the install directory has to follow it or every pairing approval is
# refused as install_moved. The REAL broker, less its one root-guard line.
# shellcheck disable=SC2016  # a literal to grep for
BROKER_GUARD='[[ $EUID -eq 0 ]] || fail not_root "this program is root'"'"'s; it is reached through a systemd socket, and by root'"'"'s update with argv"'
mkdir -p "$TMP/sbin828" "$TMP/etc828"
chmod 755 "$TMP/etc828"
grep -vxF -e "$BROKER_GUARD" "$REPO_DIR/scripts/aperire-fleet-broker.sh" > "$TMP/sbin828/aperire-fleet-broker"
chmod 755 "$TMP/sbin828/aperire-fleet-broker"
if [[ $(( $(wc -l < "$REPO_DIR/scripts/aperire-fleet-broker.sh") - $(wc -l < "$TMP/sbin828/aperire-fleet-broker") )) -eq 1 ]]; then
  ok "the broker under test is the real one, less its root guard and nothing else"
else
  bad "the broker differs by its guard alone" "the guard line was not found"; fi
python3 - "$REPO_DIR/scripts/aperire-fleet-broker.sh" > "$TMP/dirsafe-828.py" <<'PY828'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r"# --- DIRSAFE-PY-BEGIN ---\ncat > \"\$WORK/dirsafe\.py\" <<'DIRSAFE_PY_EOF'\n(.*?)\nDIRSAFE_PY_EOF", src, re.S)
sys.stdout.write(m.group(1) if m else "")
PY828
dir_id_828() { python3 "$TMP/dirsafe-828.py" "$1" "" "" 002 identity | awk '{print $2}'; }
kept_for_rollback() { # a host just updated: one kept tree beside $DIR
  reset_host
  mkdir -p "${DIR}.previous-R/dashboard/config"
  cp "$DIR/install.sh" "${DIR}.previous-R/install.sh"
  printf 'this tree is the old one\n' > "${DIR}.previous-R/marker"
  cp "$DIR/.release" "${DIR}.previous-R/.release"
  # What the update that moved it aside recorded for it (#782, #764).
  mkdir -p "$TMP/lib/release.sha256.kept"
  kept_record "${DIR}.previous-R" "the OLD release" "$OLD_SHA" > "$TMP/lib/release.sha256.kept/$OLD_SHA"
  point_previous "${DIR}.previous-R" "$OLD_SHA"
}
broker_conf_828() { # $1 = the INSTALL_DIR_ID recorded
  printf '# Written by scripts/install-fleet-broker-grant.sh\nINSTALL_DIR=%s\nINSTALL_DIR_ID=%s\nFLEET_LINK_PORT_MIN=7900\nFLEET_LINK_PORT_MAX=7903\nDASH_ACCOUNT=%s\n' \
    "$DIR" "$1" "$ME" > "$TMP/etc828/fleet-broker.conf"
  chmod 644 "$TMP/etc828/fleet-broker.conf"
}
probe_828() {
  printf 'no-such-verb\nend\n' | timeout -k 2 30 env PATH="$TMP/bin:/usr/bin:/bin" \
    APERIRE_ETC="$TMP/etc828" APERIRE_UNIT_DIR="$TMP/units" \
    bash "$TMP/sbin828/aperire-fleet-broker" 2>&1 || true
}

# No grant on this host: nothing is asked, and the fact says so.
kept_for_rollback
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(fact_of "$out" broker_grant)" == absent ]]; then
  ok "a rollback on a host with no broker grant asks nothing and says broker_grant=absent"
else
  bad "no grant, no re-record" "exit $(status_of "$out"): $(grep broker <<<"$out")"; fi
rm -rf "${DIR}.rolled-back-"*

# Several kept trees (#951): an update never prunes, so a host updated more
# than once has several. Root's pointer names the one the last update moved
# aside, and that is the one that comes back; the others are not touched.
kept_for_rollback
for t in Q S; do
  mkdir -p "${DIR}.previous-$t/dashboard/config"
  cp "$DIR/install.sh" "${DIR}.previous-$t/install.sh"
  printf 'an older tree, %s\n' "$t" > "${DIR}.previous-$t/marker"
done
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the old one" \
      && "$(cat "${DIR}.previous-Q/marker")" == "an older tree, Q" && "$(cat "${DIR}.previous-S/marker")" == "an older tree, S" ]] \
   && grep -q '3 kept trees' <<<"$out"; then
  ok "with several kept trees, the one root's pointer names comes back and the rest stay where they are"
else
  bad "rollback picks the tree the pointer binds" "exit $(status_of "$out"): $out"; fi
rm -rf "${DIR}.rolled-back-"* "${DIR}.previous-Q" "${DIR}.previous-S"

# Rolled-back trees (#1122). Each rollback leaves the release it left as
# <install>.rolled-back-<stamp>, and nothing removed one. The newest 3 stay and
# older ones go, by directory and with the operator's own account: never the
# install that is running, never a link, never a name that is not a stamp, and
# never a tree that still holds data/ or config, which is the operator's.
kept_for_rollback
plain_rb() { # $1 = stamp
  mkdir -p "${DIR}.rolled-back-$1/dashboard/config"
  printf 'a rolled-back tree, %s\n' "$1" > "${DIR}.rolled-back-$1/marker"
}
for stamp in 20260101T000000Z 20260102T000000Z 20260104T000000Z 20260105T000000Z 20260106T000000Z; do plain_rb "$stamp"; done
plain_rb 20260103T000000Z
mkdir -p "${DIR}.rolled-back-20260103T000000Z/data"
printf 'the operator database\n' > "${DIR}.rolled-back-20260103T000000Z/data/aperire.db"
ln -s "${DIR}.rolled-back-20260106T000000Z" "${DIR}.rolled-back-20260107T000000Z"
# A name that is not a stamp, and that sorts old ("0" is below every digit a
# stamp starts with under LC_ALL=C), so it is outside the newest 3 and only
# the stamp rule keeps it from being removed.
mkdir -p "${DIR}.rolled-back-0keepme"
out="$(printf 'rollback\n' | run_sut 2>&1)"
gone=""; for stamp in 20260101T000000Z 20260102T000000Z 20260104T000000Z; do [[ -e "${DIR}.rolled-back-$stamp" ]] || gone+="$stamp "; done
if [[ "$(status_of "$out")" == 0 && "$gone" == "20260101T000000Z 20260102T000000Z 20260104T000000Z " \
      && -d "${DIR}.rolled-back-20260105T000000Z" && -d "${DIR}.rolled-back-20260106T000000Z" \
      && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the old one" ]]; then
  ok "a rollback removes rolled-back trees past the newest 3, and the install it just put back is untouched"
else
  bad "rolled-back trees past the count are removed" "exit $(status_of "$out") gone=[$gone]: $(printf '%s ' "${DIR}".rolled-back-*)"; fi
if [[ -f "${DIR}.rolled-back-20260103T000000Z/data/aperire.db" ]] && grep -q "kept ${DIR}.rolled-back-20260103T000000Z" <<<"$out" \
   && grep -q 'still holds files that were meant to move out of it' <<<"$out"; then
  ok "  a rolled-back tree that still holds data/ is left, and named"
else
  bad "a rolled-back tree holding data/ is left" "$(ls "${DIR}.rolled-back-20260103T000000Z" 2>&1): $out"; fi
if [[ -L "${DIR}.rolled-back-20260107T000000Z" && -d "${DIR}.rolled-back-0keepme" ]]; then
  ok "  a link and a name that is not a stamp are not rolled-back trees, and are left alone"
else
  bad "a link and an odd name are left alone" "$(printf '%s ' "${DIR}".rolled-back-*)"; fi
rolled_now="$(fact_of "$out" rolled_back)"
if [[ -d "$rolled_now" && "$(fact_of "$out" rolled_back_removed)" == 3 && "$(fact_of "$out" rolled_back_kept)" == 4 ]] \
   && grep -qF "The release you left is kept at $rolled_now." <<<"$out" \
   && grep -q 'keeps the newest 3 rolled-back trees' <<<"$out" && grep -q '4 kept, 3 removed by this rollback' <<<"$out" \
   && grep -q '1 of the kept ones still hold files of yours' <<<"$out"; then
  ok "  and the closing text says what was kept and what was removed, with nothing left for the operator to clean up"
else
  bad "the rollback says what it kept and removed" "kept=$(fact_of "$out" rolled_back_kept) removed=$(fact_of "$out" rolled_back_removed): $(tail -12 <<<"$out")"; fi
rm -rf "${DIR}.rolled-back-"*

# The tree this rollback just made is held by identity. A clock that stepped
# back names it older than three others, and it still has to be there, because
# the closing text says it is kept.
kept_for_rollback
for stamp in 20990101T000000Z 20990102T000000Z 20990103T000000Z 20990104T000000Z; do plain_rb "$stamp"; done
out="$(printf 'rollback\n' | run_sut 2>&1)"
rolled_now="$(fact_of "$out" rolled_back)"
if [[ "$(status_of "$out")" == 0 && -d "$rolled_now" && ! -e "${DIR}.rolled-back-20990101T000000Z" \
      && -d "${DIR}.rolled-back-20990104T000000Z" && -d "${DIR}.rolled-back-20990103T000000Z" && -d "${DIR}.rolled-back-20990102T000000Z" ]] \
   && grep -qF "The release you left is kept at $rolled_now." <<<"$out"; then
  ok "the tree this rollback made is never removed, even when its name sorts past the count"
else
  bad "the new rolled-back tree is held by identity" "exit $(status_of "$out") rolled=$rolled_now: $(printf '%s ' "${DIR}".rolled-back-*)"; fi
rm -rf "${DIR}.rolled-back-"*

# The tree this rollback made cannot be read back. It is then not held by
# identity, so nothing is pruned and the closing text does not say it is kept:
# a name that sorts past the count would otherwise be removed under a sentence
# that promised it (#1150). The stat is blinded for that one question only.
kept_for_rollback
for stamp in 20990101T000000Z 20990102T000000Z 20990103T000000Z 20990104T000000Z; do plain_rb "$stamp"; done
cat > "$TMP/bin/stat" <<'STATSHIM'
#!/bin/sh
# Answers like stat, except when told to be blind to a rolled-back tree's identity.
if [ -e "$TMP_STATE/stat-blind" ] && [ "$1" = "-c" ] && [ "$2" = "%d:%i" ]; then
  for a in "$@"; do case "$a" in *.rolled-back-*) exit 1 ;; esac; done
fi
exec /usr/bin/stat "$@"
STATSHIM
sed -i "s#\$TMP_STATE#$TMP/state#g" "$TMP/bin/stat"
chmod +x "$TMP/bin/stat"
: > "$TMP/state/stat-blind"
out="$(printf 'rollback\n' | run_sut 2>&1)"
rm -f "$TMP/state/stat-blind" "$TMP/bin/stat"
rolled_now="$(fact_of "$out" rolled_back)"
if [[ "$(status_of "$out")" == 0 && -d "$rolled_now" ]] \
   && [[ -d "${DIR}.rolled-back-20990101T000000Z" && -d "${DIR}.rolled-back-20990104T000000Z" ]] \
   && [[ "$(fact_of "$out" rolled_back_removed)" == 0 ]] \
   && grep -q 'could not read .*the tree this rollback just made' <<<"$out" \
   && ! grep -q 'is kept at' <<<"$out" && grep -qF "The release you left is at $rolled_now." <<<"$out"; then
  ok "a rollback that cannot read back the tree it made removes nothing, and does not say it kept it"
else
  bad "an unreadable new tree is not pruned and not claimed kept" "exit $(status_of "$out") rolled=$rolled_now: $(printf '%s ' "${DIR}".rolled-back-*): $(tail -8 <<<"$out")"; fi
rm -rf "${DIR}.rolled-back-"*

# Fewer than the count: nothing is removed, and the text says so in numbers.
kept_for_rollback
plain_rb 20260101T000000Z
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && -d "${DIR}.rolled-back-20260101T000000Z" && "$(fact_of "$out" rolled_back_removed)" == 0 ]] \
   && grep -q '2 kept, 0 removed by this rollback' <<<"$out"; then
  ok "under the count nothing is removed, and the closing text says 2 kept, 0 removed"
else
  bad "a rollback under the count removes nothing" "exit $(status_of "$out"): $(tail -8 <<<"$out")"; fi
rm -rf "${DIR}.rolled-back-"*

# One the operator's own account cannot remove (a directory it cannot enter)
# is left and named with the command for it, and the rollback still succeeds:
# no root fallback, the same rule as the trees an update moves aside.
if [[ $EUID -ne 0 ]]; then
  kept_for_rollback
  for stamp in 20260101T000000Z 20260102T000000Z 20260103T000000Z 20260104T000000Z; do plain_rb "$stamp"; done
  mkdir -p "${DIR}.rolled-back-20260101T000000Z/locked"
  : > "${DIR}.rolled-back-20260101T000000Z/locked/f"
  chmod 000 "${DIR}.rolled-back-20260101T000000Z/locked"
  out="$(printf 'rollback\n' | run_sut 2>&1)"
  chmod 755 "${DIR}.rolled-back-20260101T000000Z/locked"
  if [[ "$(status_of "$out")" == 0 && -d "${DIR}.rolled-back-20260101T000000Z" ]] \
     && grep -q "could not remove ${DIR}.rolled-back-20260101T000000Z as" <<<"$out" && grep -q 'sudo rm -rf --' <<<"$out"; then
    ok "a rolled-back tree the operator's account cannot remove is left, named, with the command, and the rollback still succeeds"
  else
    bad "an unremovable rolled-back tree is named, not forced" "exit $(status_of "$out"): $(tail -10 <<<"$out")"; fi
  rm -rf "${DIR}.rolled-back-"*
fi

# A link is not a kept tree (#951 review, L2). The tree root's pointer names
# is real, kept elsewhere; a link to it under the kept name must not be put
# back, or the link itself is what gets moved into the install directory.
kept_for_rollback
mv "${DIR}.previous-R" "${DIR}.stash-R"
ln -s "${DIR}.stash-R" "${DIR}.previous-R"
point_previous "${DIR}.stash-R" "$OLD_SHA"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" != 0 && -L "${DIR}.previous-R" && ! -L "$DIR" && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the new one" ]]; then
  ok "a link under the kept name is not a kept tree, and nothing is moved"
else
  bad "a symlinked kept tree is never chosen" "exit $(status_of "$out"), install dir link=$([[ -L "$DIR" ]] && echo yes || echo no): $out"; fi
rm -rf "${DIR}.previous-R" "${DIR}.stash-R" "${DIR}.rolled-back-"*

# The name changed between the judgment and the move (#960). The kept tree is
# judged by <dev>:<ino> against root's pointer, then moved by its name, and the
# name is in the login's home. A tree put under it in between must not end up
# in the install directory, and nothing may run from it. The hook runs between
# the two, only when not root, and puts a different tree under the kept name.
if [[ $EUID -ne 0 ]]; then
  kept_for_rollback
  # shellcheck disable=SC2016  # the hook's own $1
  printf '#!/usr/bin/env bash\nmv "$1" "$1.judged"\nmkdir -p "$1/dashboard/config"\ncp "%s/install.sh" "$1/install.sh"\nprintf "an unjudged tree\\n" > "$1/marker"\n' "$DIR" > "$TMP/swap-name.sh"
  chmod +x "$TMP/swap-name.sh"
  out="$(printf 'rollback\n' | APERIRE_UPDATE_TEST_BEFORE_MOVE="$TMP/swap-name.sh" run_sut 2>&1)"
  if [[ "$(status_of "$out")" != 0 && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the new one" \
        && ! -e "$TMP/state/install-self" ]] \
     && grep -q 'after root judged it' <<<"$out" \
     && [[ "$(cat "${DIR}".unjudged-*/marker 2>/dev/null)" == "an unjudged tree" ]] \
     && [[ "$(cat "${DIR}.previous-R.judged/marker" 2>/dev/null)" == "this tree is the old one" ]]; then
    ok "a kept tree whose name was changed after it was judged is refused, the running release is put back, and nothing runs from the other"
  else
    bad "an unjudged tree is never put in place (#960)" "exit $(status_of "$out") marker=$(cat "$DIR/marker" 2>/dev/null) ran=$(cat "$TMP/state/install-self" 2>/dev/null): $out"
  fi
  # And the same hook with an honest name: the tree that was judged, moved by
  # the same renames, goes ahead. Without this the row above could be passing
  # because the rollback refuses everything.
  kept_for_rollback
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/swap-none.sh"; chmod +x "$TMP/swap-none.sh"
  out="$(printf 'rollback\n' | APERIRE_UPDATE_TEST_BEFORE_MOVE="$TMP/swap-none.sh" run_sut 2>&1)"
  if [[ "$(status_of "$out")" == 0 && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the old one" ]]; then
    ok "  control: with no change of name, the judged tree moves in and the rollback goes ahead"
  else
    bad "control: an honest name still rolls back" "exit $(status_of "$out"): $out"
  fi
  rm -rf "${DIR}.rolled-back-"* "${DIR}".unjudged-* "${DIR}.previous-R.judged"
fi

# #1109. bash takes EUID from its environment. This program decided whose
# files count as root's, and whether the environment may name the record, from
# $EUID, so EUID=0 in the environment of an unprivileged run made it ignore the
# test's record for the constant path (and, the other way round, a root run
# with EUID=1000 would take a login's files for root's). The account now comes
# from id(1). The rollback below has to behave as it does without the poison.
if [[ $EUID -ne 0 ]]; then
  kept_for_rollback
  out="$(printf 'rollback\n' | TEST_POISON_EUID=0 run_sut 2>&1)"
  if [[ "$(status_of "$out")" == 0 && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the old one" ]]; then
    ok "a rollback is unchanged by EUID=0 in the environment: the account comes from id, not from bash's EUID (#1109)"
  else
    bad "a poisoned EUID changes the rollback's trust decisions (#1109)" "exit $(status_of "$out"): $out"
  fi
  rm -rf "${DIR}.rolled-back-"*
fi

# T5: the update re-recorded the pin for the tree it moved in; the rollback
# puts the previous tree back and re-records it again.
kept_for_rollback
broker_conf_828 "$(dir_id_828 "$DIR")"
export FLEET_BROKER_828="$TMP/sbin828/aperire-fleet-broker" FLEET_BROKER_ETC_828="$TMP/etc828"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(cat "$DIR/marker" 2>/dev/null)" == "this tree is the old one" \
      && "$(fact_of "$out" broker_grant)" == rerecorded ]] \
   && grep -qxF "INSTALL_DIR_ID=$(dir_id_828 "$DIR")" "$TMP/etc828/fleet-broker.conf"; then
  ok "a rollback re-records the broker's pin for the tree that came back"
else
  bad "the rollback re-records the pin" "exit $(status_of "$out"): $(grep -i broker <<<"$out") conf=$(grep INSTALL_DIR_ID "$TMP/etc828/fleet-broker.conf")"; fi
out="$(probe_828)"
if grep -qx 'error=unknown_verb' <<<"$out" && ! grep -q install_moved <<<"$out"; then
  ok "  and the broker accepts afterwards: a connection reaches the verb, not install_moved"
else
  bad "the broker accepts after a rollback" "$out"; fi
rm -rf "${DIR}.rolled-back-"*

# T6b: the update's own re-record was refused, so the pin still names the
# tree the update moved aside. The rollback puts exactly that tree back: the
# pin is current again, and nothing is written or warned about.
kept_for_rollback
broker_conf_828 "$(dir_id_828 "${DIR}.previous-R")"
before="$(sha256sum < "$TMP/etc828/fleet-broker.conf")"
out="$(printf 'rollback\n' | run_sut 2>&1)"
if [[ "$(status_of "$out")" == 0 && "$(fact_of "$out" broker_grant)" == already_current \
      && "$(sha256sum < "$TMP/etc828/fleet-broker.conf")" == "$before" ]] \
   && ! grep -q 'fleet-broker-grant' <<<"$out"; then
  ok "a rollback onto the tree the pin already names answers already_current, writes nothing and warns of nothing"
else
  bad "rule 0 on a rollback" "exit $(status_of "$out"): $(grep -i broker <<<"$out")"; fi
rm -rf "${DIR}.rolled-back-"*
unset FLEET_BROKER_828 FLEET_BROKER_ETC_828

echo
echo "── the payload this program does not speak ────────────────────────"

for payload in "" "upgrade" "check please" "apply"; do
  out="$(printf '%s\n' "$payload" | run_sut 2>&1)"
  if [[ "$(status_of "$out")" == 2 ]] && grep -q '^error=' <<<"$out"; then
    ok "'${payload:-<empty>}' is refused with a sentence"
  else
    bad "'${payload:-<empty>}' is refused" "$out"
  fi
done

if grep -q 'refused: ' "$TMP/state/journal" 2>/dev/null \
   && grep -q 'check: ' "$TMP/state/journal" 2>/dev/null \
   && grep -q 'applied: ' "$TMP/state/journal" 2>/dev/null \
   && grep -q 'rolledback: ' "$TMP/state/journal" 2>/dev/null; then
  ok "and every verb, refusal included, reaches the journal"
else
  bad "the journal records each verb" "$(tail -5 "$TMP/state/journal" 2>/dev/null)"; fi

echo
echo "── the grant that lets the dashboard reach it ─────────────────────"

INST_ORIG="$REPO_DIR/scripts/install-update-grant.sh"
# shellcheck disable=SC2016  # a literal to grep for, not an expression to run
IGUARD='[[ $EUID -eq 0 ]] || die "run with sudo: this installs a program as root and two systemd units"'
mkdir -p "$TMP/tree/scripts"
INST="$TMP/tree/scripts/install-update-grant.sh"
grep -vxF -e "$IGUARD" "$INST_ORIG" > "$INST"
cp "$ORIG" "$TMP/tree/scripts/aperire-update.sh"
cp "$BOOTSTRAP" "$TMP/tree/scripts/get-aperire.sh"
cp "$REPO_DIR/scripts/release-verify-lib.sh" "$TMP/tree/scripts/release-verify-lib.sh"
cp "$TMP/lib/release-signers" "$TMP/tree/scripts/release-signers"
GRANT_LIB="$TMP/grant-lib"
cp "$REPO_DIR/scripts/release-digests-lib.sh" "$TMP/tree/scripts/release-digests-lib.sh"
cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/tree/scripts/trusted-path-lib.sh"

if grep -qxF -e "$IGUARD" "$INST_ORIG"; then
  ok "the grant installer refuses to run as anything but root"
else
  bad "the installer's root guard is there" "the line these tests remove is gone"; fi

cat > "$TMP/bin/getent" <<'EOF'
#!/usr/bin/env bash
[[ "$2" == nosuchuser ]] && exit 2
# FAKE_NOLOGIN names an account to report with no login shell.
if [[ -n "${FAKE_NOLOGIN:-}" && "$2" == "$FAKE_NOLOGIN" ]]; then
  printf '%s:x:999:999::/nonexistent:/usr/sbin/nologin\n' "$2"; exit 0
fi
printf '%s:x:1000:1000::/home/x:/bin/bash\n' "$2"
EOF
chmod +x "$TMP/bin/getent"

GRANT_ETC="$TMP/grant-etc"
GRANT_DEST="$TMP/sbin/aperire-update"
mkdir -p "$TMP/sbin" "$GRANT_ETC"
printf '[Service]\nUser=%s\n' "$ME" > "$TMP/units/aperire-server.service"

run_grant() {
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_UPDATE_PATH="$GRANT_DEST" \
      APERIRE_UPDATE_LIB_DIR="$GRANT_LIB" \
      APERIRE_UPDATE_RELEASE_STORE="${GRANT_STORE_FOR_RUN:-$TMP/no-release-store}" \
      APERIRE_UPDATE_CONF="$GRANT_ETC/update.conf" \
      APERIRE_ETC="$GRANT_ETC" \
      APERIRE_UNIT_DIR="$TMP/units" \
      APERIRE_RELEASE_DIGESTS="$TMP/grant-lib/release.sha256" \
      bash "$INST" "$@" 2>&1
}

printf '{\n  "tag": "t",\n  "commit": "c",\n  "sha256": "s",\n  "published_at": "",\n  "source_url": "https://mirror.example/release.tar.gz",\n  "installed_at": ""\n}\n' > "$TMP/tree/.release"
out="$(run_grant --program-only)"
if grep -q '^ENDPOINT=https://mirror.example$' "$GRANT_ETC/update.conf"; then
  ok "the endpoint comes off this host's own stamp, so a mirror stays a mirror"
else
  bad "the endpoint is read from the stamp" "$(cat "$GRANT_ETC/update.conf" 2>/dev/null)"; fi

# And it SAYS which of the three it took. An update runs this installer from
# inside the update program, and that line is the only record on the host of
# why this box is pointed where it is (#293).
if grep -q '^source=stamp$' <<<"$out" && grep -q 'taken from .*\.release' <<<"$out"; then
  ok "and it says the stamp is where it took it from, as a fact and in words"
else
  bad "the installer names the source it took the endpoint from" "$out"; fi

if grep -q "^INSTALL_DIR=$TMP/tree$" "$GRANT_ETC/update.conf" && grep -q "^OPERATOR=$ME$" "$GRANT_ETC/update.conf"; then
  ok "and the tree and the account that owns it, read off the dashboard's own unit"
else
  bad "the conf names the tree and the operator" "$(cat "$GRANT_ETC/update.conf" 2>/dev/null)"; fi

# ADR 0024 lane 3: once the dashboard runs as its own account, the two are
# different people. OPERATOR is who owns the tree (read from the tree), which
# is the account the update builds it as; DASH_USER is the unit's User=. The
# line before the split wrote the unit's account as OPERATOR, and an update
# would then have unpacked and built the tree as the dashboard's account.
cp -a "$TMP/units" "$TMP/units.keep"
for u in "$TMP/units"/aperire-server*.service; do
  [[ -f "$u" ]] && sed -i 's/^User=.*/User=nobody/' "$u"
done
[[ -f "$TMP/units/aperire-server.service" ]] || printf '[Service]\nUser=nobody\n' > "$TMP/units/aperire-server.service"
out="$(run_grant --program-only)"
if grep -q "^OPERATOR=$ME$" "$GRANT_ETC/update.conf" && grep -q '^DASH_USER=nobody$' "$GRANT_ETC/update.conf"; then
  ok "a dashboard on its own account: OPERATOR is the tree's owner, DASH_USER the unit's account"
else
  bad "update.conf splits OPERATOR and DASH_USER" "$(cat "$GRANT_ETC/update.conf" 2>/dev/null)"; fi
rm -rf "$TMP/units"; mv "$TMP/units.keep" "$TMP/units"
# And the grant refuses to write a tree owner that is a service account.
out_l7="$(FAKE_NOLOGIN="$ME" run_grant --program-only)"
if grep -q "a service account with no login; the update never builds a tree as one" <<<"$out_l7"; then
  ok "the grant refuses a tree owned by an account with no login shell"
else
  bad "the grant refuses a service-account tree owner" "$out_l7"; fi

if [[ -x "$GRANT_DEST" ]] && cmp -s "$TMP/tree/scripts/aperire-update.sh" "$GRANT_DEST"; then
  ok "and the program is copied out of the tree, byte for byte"
else
  bad "the program is installed" "$out"; fi

# The key the program checks every release against, and the check, placed
# BEFORE the program: a program without its key refuses every update.
key_at="$(grep -n -e "$GRANT_LIB/release-signers  (root:root" <<<"$out" | head -1 | cut -d: -f1)"
prog_at="$(grep -nF -e "$GRANT_DEST  (" <<<"$out" | head -1 | cut -d: -f1)"
if cmp -s "$GRANT_LIB/release-signers" "$TMP/tree/scripts/release-signers" \
   && cmp -s "$GRANT_LIB/release-verify-lib.sh" "$TMP/tree/scripts/release-verify-lib.sh" \
   && [[ -n "$key_at" && -n "$prog_at" && "$key_at" -lt "$prog_at" ]] \
   && grep -q 'checks every release against 1 release key' <<<"$out"; then
  ok "and the release key and its check are placed beside it first, root-owned, and counted"
else
  bad "the release key is installed before the program" "key@${key_at:-none} program@${prog_at:-none}: $(grep -i 'release' <<<"$out" | head -3)"; fi

# The key is copied only as the signed release names it. install.sh runs
# this installer on every install AND every update, out of a tree the
# operator owns and npm ci has run in, so this is where a key added to the
# tree would reach root. The bootstrap keeps the signed release before
# install.sh runs; this reads it.
GRANT_STORE="$TMP/grant-store"
G_SHA="$(printf '9%.0s' {1..64})"
signers_digest() { awk '!/^[[:space:]]*#/ && NF >= 4 { print $3 " " $4 }' "$1" | LC_ALL=C sort | sha256sum | cut -d' ' -f1; }
# The kept signed release, and the release digests get-aperire.sh writes from
# its signed file list (keyed by the same archive sum), both naming the tree's
# files as they are now. $1 = key set it names, $2 = key that signs.
make_grant_store() {
  local set="${1:-$TMP/tree/scripts/release-signers}" key="${2:-$TMP/testkey}" f
  rm -rf "$GRANT_STORE"; mkdir -p "$GRANT_STORE/$G_SHA"
  for f in release-signers release-verify-lib.sh aperire-update.sh release-digests-lib.sh trusted-path-lib.sh; do
    printf '%s  scripts/%s\n' "$(sha256sum "$TMP/tree/scripts/$f" | cut -d' ' -f1)" "$f"
  done > "$GRANT_STORE/$G_SHA/release.files"
  { printf '# anchor signed release.json for sha256 %s, a fixture\n# key %s\n' "$G_SHA" "$G_SHA"
    cat "$GRANT_STORE/$G_SHA/release.files"; } > "$GRANT_LIB/release.sha256"
  chmod 0644 "$GRANT_LIB/release.sha256"
  printf '{\n  "sha256": "%s",\n  "files_sha256": "%s",\n  "signers_sha256": "%s"\n}\n' "$G_SHA" \
    "$(sha256sum "$GRANT_STORE/$G_SHA/release.files" | cut -d' ' -f1)" "$(signers_digest "$set")" > "$GRANT_STORE/$G_SHA/release.json"
  rm -f "$GRANT_STORE/$G_SHA/release.json.sig"
  ssh-keygen -q -Y sign -f "$key" -n aperire-release "$GRANT_STORE/$G_SHA/release.json" </dev/null
  printf '%s\n' "$G_SHA" > "$GRANT_STORE/current"
}
make_grant_store
GRANT_STORE_FOR_RUN="$GRANT_STORE"
out="$(run_grant --program-only)"
if cmp -s "$GRANT_LIB/release-signers" "$TMP/tree/scripts/release-signers" \
   && grep -q "release-signers  (root:root 0644, the signed release's key set)" <<<"$out"; then
  ok "with a signed release kept for this host, the key is copied only as that release names it, and it says so"
else
  bad "the grant copies the key the signed release names" "$(grep -i 'release' <<<"$out" | head -4)"; fi

# Something with write access to the tree adds its own key beside the real
# one after the bootstrap checked the tree.
cp "$GRANT_LIB/release-signers" "$TMP/grant-key-before"
cp "$TMP/tree/scripts/release-signers" "$TMP/tree-signers-good"
printf 'aperire-release-key namespaces="aperire-release" %s planted\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  >> "$TMP/tree/scripts/release-signers"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-key-before" \
   && ! grep -q planted "$GRANT_LIB/release-signers" \
   && grep -q 'refused: scripts/release-signers is not the file this release shipped' <<<"$out"; then
  ok "a key added to the tree's release-signers after it was checked is refused, and the key on the host stays as it was"
else
  bad "a planted key in the tree is refused by the grant" "rc=$rc: $(tail -2 <<<"$out")"; fi

# Replaced outright with somebody else's: the sum the signed release names is
# not this file's, which is refused the same way.
printf 'aperire-release-key namespaces="aperire-release" %s planted\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  > "$TMP/tree/scripts/release-signers"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-key-before" \
   && grep -q 'refused: scripts/release-signers is not the file this release shipped' <<<"$out"; then
  ok "and a key replaced outright is refused too: the release digests name the signed file, not this one"
else
  bad "a replaced key in the tree is refused by the grant" "rc=$rc: $(tail -2 <<<"$out")"; fi
cp "$TMP/tree-signers-good" "$TMP/tree/scripts/release-signers"

# A build that put its own key in the tree AND in the manifest, consistently,
# while release.json names the key set the Mac holds (all the Mac checks).
# The file sum passes; the key set does not.
printf 'aperire-release-key namespaces="aperire-release" %s planted\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  >> "$TMP/tree/scripts/release-signers"
make_grant_store "$TMP/tree-signers-good"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-key-before" \
   && grep -q 'is not the key set the signed release names' <<<"$out"; then
  ok "a key added to both the tree and the signed manifest is refused: it is not the key set the signed release names"
else
  bad "a key set other than the signed one is refused by the grant" "rc=$rc: $(tail -2 <<<"$out")"; fi
cp "$TMP/tree-signers-good" "$TMP/tree/scripts/release-signers"

# The host already trusts a key set, and the kept release is signed by a key
# outside it (while naming, and carrying, that key as the new set). A new set
# arrives only signed by the old: refused, the installed key untouched.
printf 'aperire-release-key namespaces="aperire-release" %s other\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  > "$TMP/tree/scripts/release-signers"
make_grant_store "$TMP/tree/scripts/release-signers" "$TMP/otherkey"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-key-before" \
   && grep -q 'does not verify, so the release key on this host was left as it was' <<<"$out"; then
  ok "a new key set signed only by itself is refused on a host that already trusts another: the old key has to sign the new"
else
  bad "a self-signed new key set is refused by the grant" "rc=$rc: $(tail -2 <<<"$out")"; fi

# Signed by the key the host trusts, naming a set that swaps it for another
# in one step: refused. A key changes in two signed steps, never one.
make_grant_store "$TMP/tree/scripts/release-signers" "$TMP/testkey"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-key-before" \
   && grep -q 'more than one rotation step' <<<"$out"; then
  ok "a release signed by the trusted key that swaps the whole set at once is refused by the grant"
else
  bad "a one-step key swap is refused by the grant" "rc=$rc: $(tail -2 <<<"$out")"; fi

# Phase 1, then phase 2, through the grant: {test} -> {test, other} -> {other}.
cat "$TMP/tree-signers-good" > "$TMP/tree/scripts/release-signers"
printf 'aperire-release-key namespaces="aperire-release" %s other\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  >> "$TMP/tree/scripts/release-signers"
make_grant_store "$TMP/tree/scripts/release-signers" "$TMP/testkey"
out1="$(run_grant --program-only)"; rc1=$?
printf 'aperire-release-key namespaces="aperire-release" %s other\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  > "$TMP/tree/scripts/release-signers"
make_grant_store "$TMP/tree/scripts/release-signers" "$TMP/otherkey"
out2="$(run_grant --program-only)"; rc2=$?
if [[ $rc1 -eq 0 && $rc2 -eq 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/tree/scripts/release-signers"; then
  ok "and the two signed steps go through it: the old key adds the new, then the new key drops the old"
else
  bad "a two-phase rotation passes the grant" "rc1=$rc1 rc2=$rc2: $(tail -2 <<<"$out1") / $(tail -2 <<<"$out2")"; fi
cp "$TMP/grant-key-before" "$GRANT_LIB/release-signers"
cp "$TMP/tree-signers-good" "$TMP/tree/scripts/release-signers"
make_grant_store
GRANT_STORE_FOR_RUN=""
rm -f "$GRANT_LIB/release.sha256"

# L1 of #759's review. The grant shape-checks the set it is about to install,
# before the rename: a three-field line ssh-keygen would read as a key, and
# the updater's check would refuse, never reaches /usr/local/lib/aperire.
# Reproduced first: the grant used to install it as it stood.
cp "$GRANT_LIB/release-signers" "$TMP/grant-key-before"
printf 'aperire-release-key %s three-field\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" >> "$TMP/tree/scripts/release-signers"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-key-before" \
   && grep -q 'is not a release key set' <<<"$out"; then
  ok "the grant refuses a signer set the updater would refuse, before it renames anything into place"
else
  bad "the grant shape-checks the set before installing it" "rc=$rc: $(tail -2 <<<"$out")"; fi
cp "$TMP/tree-signers-good" "$TMP/tree/scripts/release-signers"
# And a set already installed that is not one this code accepts is a
# refusal, never "nothing installed", so the rotation rule cannot be skipped
# by breaking the file it reads.
printf 'release@example.org namespaces="aperire-release" %s broken\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" > "$GRANT_LIB/release-signers"
cp "$GRANT_LIB/release-signers" "$TMP/grant-broken-before"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 ]] && cmp -s "$GRANT_LIB/release-signers" "$TMP/grant-broken-before" \
   && grep -q 'is not a set this installer accepts' <<<"$out"; then
  ok "a broken release key set already on the host makes the grant refuse, never read as no key"
else
  bad "a broken installed set is a refusal in the grant" "rc=$rc: $(tail -2 <<<"$out")"; fi
cp "$TMP/grant-key-before" "$GRANT_LIB/release-signers"

# The rename, not the overwrite. An update runs this installer out of the new
# tree while the OLD copy is the running process, and `install` over the top
# would hand that bash new bytes at its old offset.
inode_before=$(stat -c %i "$GRANT_DEST")
printf '#!/usr/bin/env bash\n# a newer release\n' > "$TMP/tree/scripts/aperire-update.sh"
run_grant --program-only > /dev/null
inode_after=$(stat -c %i "$GRANT_DEST")
if [[ "$inode_before" != "$inode_after" ]]; then
  ok "refreshing it renames a new file into place rather than writing over the running one"
else
  bad "the program is replaced by rename" "the inode did not change ($inode_before)"; fi

# ADR 0024: with the release's digests on the host, the program is copied only
# if the tree's copy is the one the release shipped. A tree rewritten after the
# unpack is refused, the installed program stays, and nothing below is written.
mkdir -p "$TMP/grant-lib"
printf '# anchor a fixture\n%s  scripts/aperire-update.sh\n%s  scripts/release-signers\n%s  scripts/release-verify-lib.sh\n%s  scripts/release-digests-lib.sh\n%s  scripts/trusted-path-lib.sh\n' \
  "$(sha256sum < "$TMP/tree/scripts/aperire-update.sh" | cut -c1-64)" \
  "$(sha256sum < "$TMP/tree/scripts/release-signers" | cut -c1-64)" \
  "$(sha256sum < "$TMP/tree/scripts/release-verify-lib.sh" | cut -c1-64)" \
  "$(sha256sum < "$TMP/tree/scripts/release-digests-lib.sh" | cut -c1-64)" \
  "$(sha256sum < "$TMP/tree/scripts/trusted-path-lib.sh" | cut -c1-64)" > "$TMP/grant-lib/release.sha256"
chmod 0644 "$TMP/grant-lib/release.sha256"
before="$(cat "$GRANT_DEST")"
printf '#!/usr/bin/env bash\n# rewritten after the unpack\n' > "$TMP/tree/scripts/aperire-update.sh"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -ne 0 && "$(cat "$GRANT_DEST")" == "$before" ]] \
   && grep -q 'refused: scripts/aperire-update.sh is not the file this release shipped' <<<"$out"; then
  ok "a program the release did not ship is refused, and the installed one stays"
else
  bad "the update grant refuses a tree copy that is not the release's" "rc=$rc $out"; fi
printf '#!/usr/bin/env bash\n# a newer release\n' > "$TMP/tree/scripts/aperire-update.sh"
out="$(run_grant --program-only)"; rc=$?
if [[ $rc -eq 0 ]] && cmp -s "$TMP/tree/scripts/aperire-update.sh" "$GRANT_DEST"; then
  ok "and the release's own copy goes through the same check"
else
  bad "the release's copy is placed" "rc=$rc $out"; fi
rm -rf "$TMP/grant-lib"

rm -f "$TMP/tree/.release"
out="$(run_grant --program-only)"
stamped="$(sed -n "s/^DEFAULT_SELF_URL='\(.*\)'\$/\1/p" "$TMP/tree/scripts/get-aperire.sh" | head -1)"
if grep -q "^ENDPOINT=$stamped$" "$GRANT_ETC/update.conf"; then
  ok "and a host with no stamp falls back to the address the bootstrap in the tree names"
else
  bad "the endpoint falls back to the tree's bootstrap" "$(cat "$GRANT_ETC/update.conf" 2>/dev/null)"; fi

if grep -q '^source=tree$' <<<"$out"; then
  ok "and says so: source=tree, not a silent fall-through"
else
  bad "the fall-back says which source it took" "$out"; fi

if grep -q 'left as they are' <<<"$out" && [[ ! -f "$TMP/units/aperire-update.socket" ]]; then
  ok "and --program-only writes no unit, which is what an update in flight needs"
else
  bad "--program-only leaves the units alone" "$out"; fi

# A real AF_UNIX socket, bound and left on disk, owned by this account and
# mode 0600: the installer's last checks read its owner and mode with stat,
# and a regular file standing in for it would not be the thing being checked.
GRANT_SOCK="$TMP/run/update.sock"
rm -f "$GRANT_SOCK"
python3 -c 'import os, socket, sys
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX)
s.bind(p)
s.listen(1)
os.chmod(p, 0o600)' "$GRANT_SOCK"

run_grant_full() {
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_UPDATE_PATH="$GRANT_DEST" \
      APERIRE_UPDATE_LIB_DIR="$GRANT_LIB" \
      APERIRE_UPDATE_RELEASE_STORE="${GRANT_STORE_FOR_RUN:-$TMP/no-release-store}" \
      APERIRE_UPDATE_CONF="$GRANT_ETC/update.conf" \
      APERIRE_ETC="$GRANT_ETC" \
      APERIRE_UNIT_DIR="$TMP/units" \
      APERIRE_UPDATE_SOCKET="$GRANT_SOCK" \
      APERIRE_RELEASE_DIGESTS="$TMP/grant-lib/release.sha256" \
      bash "$INST" 2>&1
}

rm -f "$TMP/state/restarted"
out="$(run_grant_full)"
if [[ -f "$TMP/units/aperire-update.socket" && -f "$TMP/units/aperire-update@.service" ]] \
   && grep -q "^ListenStream=$GRANT_SOCK$" "$TMP/units/aperire-update.socket"; then
  ok "the full installer writes the socket and the service unit"
else
  bad "the units are written" "$out"; fi

if grep -q '^SuccessExitStatus=2 3 4 5 6 7$' "$TMP/units/aperire-update@.service" \
   && grep -q '^RuntimeMaxSec=3600$' "$TMP/units/aperire-update@.service"; then
  ok "and every refusal code is a success to systemd, with an hour for a run that builds"
else
  bad "the service unit tolerates the refusals and allows a real build" "$(cat "$TMP/units/aperire-update@.service")"; fi

if grep -qx 'aperire-update.socket' "$TMP/state/restarted"; then
  ok "and the socket is restarted, because its text is new on this host"
else
  bad "a first install restarts the socket" "restarted: $(cat "$TMP/state/restarted" 2>/dev/null)"; fi

# The second run is the one that matters. An update runs this installer out of
# the new tree while the process driving that update is an instance systemd
# started from this very socket, so a release that did not change these two
# files must not restart it underneath itself.
rm -f "$TMP/state/restarted"
out="$(run_grant_full)"
if [[ ! -f "$TMP/state/restarted" ]] && grep -q 'already this release' <<<"$out"; then
  ok "and running it again with the same unit text reloads nothing and restarts nothing"
else
  bad "unchanged units are not reloaded" "restarted: $(cat "$TMP/state/restarted" 2>/dev/null); $out"; fi

echo
echo "── install.sh installs the grant where a dashboard is ─────────────"

if grep -q 'STEPS+=("update-grant")' "$REPO_DIR/install.sh" \
   && grep -q 'dashboard_unit_here && STEPS+=("update-grant")' "$REPO_DIR/install.sh"; then
  ok "install.sh runs it for a dashboard and a co-located host, and for a validator only beside a dashboard"
else
  bad "install.sh installs the grant" "no update-grant step in install.sh"; fi

if grep -q 'scripts/aperire-update.sh:aperire-update' "$BOOTSTRAP"; then
  ok "and an update refreshes the program from the new tree, so the next one runs the next release's code"
else
  bad "the bootstrap refreshes this program too" "aperire-update is not in refresh_root_programs"; fi

# The same list, and the other root program an aggregator runs: the fleet
# broker (#443). An apply that swaps the tree and leaves that one behind is
# how a seal called model-store-put on a broker four days old, got
# unknown_verb, and left the aggregator's own sealed copy unwritten while
# every node reported sealed. The behaviour is driven in
# scripts/test-get-aperire.sh, where the refresh lives; what is checked here
# is that this program's apply still hands off to a bootstrap that does it.
if grep -q 'scripts/aperire-fleet-broker.sh:aperire-fleet-broker' "$BOOTSTRAP"; then
  ok "and the fleet broker with it, so an applied release cannot leave an aggregator's root service behind the tree"
else
  bad "the bootstrap refreshes the fleet broker" "aperire-fleet-broker is not in refresh_root_programs"; fi

if grep -q 'aperire-update.socket' "$REPO_DIR/uninstall.sh" \
   && grep -q 'SBIN_DIR/aperire-update' "$REPO_DIR/uninstall.sh" \
   && grep -q 'ETC_APERIRE/update.conf' "$REPO_DIR/uninstall.sh"; then
  ok "and the uninstaller takes the socket, the program and its config back off"
else
  bad "the uninstaller removes this grant" "a socket left listening answers the next dashboard installed here"; fi

echo
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
