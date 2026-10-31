#!/usr/bin/env bash
# Exercise scripts/aperire-seal-model-key.sh, the one privileged step in the
# browser model setup.
#
# What is being protected: this is the only program the dashboard account can
# reach as root, and it is handed a secret on standard input. Six of its
# promises fail silently if they break.
#
#   1. It seals once per arming. The marker is spent on the first success, so
#      a second call has nothing left. Asserted by doing it: seal, then call
#      again with the same payload and require a refusal.
#   2. An arming lapses on its own. A marker older than the window is refused
#      even though it is present, and the refusal says so in different words
#      than "not armed", because the two send an operator to different places.
#   3. The key never leaves standard input. The fake systemd-creds records its
#      own arguments and its whole environment, and both are searched for the
#      key. A process's arguments and environment are readable in /proc for as
#      long as it runs.
#   4. Every invocation is on the record. Armed, unarmed, expired, sealed and
#      refused each reach the journal, and no journal line ever holds the key.
#   5. It refuses before it writes. A bad payload, a missing unit or a closed
#      window must leave the host exactly as it was, so every refusal row also
#      asserts that no credential appeared.
#   6. It says how it ended, in words. The dashboard reaches it through a
#      socket, and an exit code does not cross a socket: the connection just
#      closes. So `exit=<code>` is printed as the last line on every path, and
#      a run that ends without one must never read as a success.
#   7. An arm token is for ONE host. It names its target by node key inside
#      the signed bytes, and this program compares that with the node key its
#      installer stamped, so a token cut for the machine next door is refused
#      here and not only in the dashboard that carried it (#184).
#
# It also covers the two scripts either side of the arm verb: the grant
# installer that tells a node whose arm tokens to honour, and
# aperire-fleet-arm.sh, which mints them on the aggregator. The last section
# runs the whole chain: a token minted there, posted as the aggregator posts
# it, is fed to the sealer here and opens a window.
#
#   bash scripts/test-seal-model-key.sh
#
# Runs entirely in a temporary directory against fake systemd-creds, systemctl
# and logger on PATH, with the credential store, the unit directory and the
# arming marker redirected there. Touches no host, needs no root, seals
# nothing real.
#
# THE ONE MODIFICATION. The script under test refuses to run as anything but
# root, and these tests are not root and cannot become root (a user namespace
# is not available on a CI runner). So the rows below run a scratch copy with
# that single line removed, and two rows assert against the ORIGINAL: that the
# line is there, and that a non-root caller is actually refused by it. The
# scratch copy is compared with the original so that "one line removed" is a
# checked claim rather than a comment.

set -uo pipefail
# Root copies refuse a destination directory anyone but its owner can write
# (ADR 0024), as they would on a host, so the fixture is made like a host: 022.
umask 022

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIG="$REPO_DIR/scripts/aperire-seal-model-key.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$ORIG" ]] || { echo "no aperire-seal-model-key.sh at $ORIG"; exit 1; }

mkdir -p "$TMP/bin" "$TMP/etc/creds" "$TMP/units" "$TMP/state" "$TMP/advstate"

# The state helper (#703) and the method library (#708). On a real host the
# sealer finds root-owned copies of both beside itself in /usr/local/sbin, put
# there by install-model-key-sealer.sh. Nothing in the environment names them
# any more (#1148): the sealer looks beside itself, and a checkout copy is what
# it finds when it is run out of one. The scratch copy under test is that, so
# the two files from this tree sit beside it. The library is what decides
# whether a run seals with systemd-creds or keeps the key as a root-only file,
# and the fake systemctl below is what it reads the version from, so every row
# can choose which host it is standing on.
[[ -r "$REPO_DIR/scripts/state-file.py" ]] || { echo "no state-file.py at $REPO_DIR/scripts/state-file.py"; exit 1; }
[[ -r "$REPO_DIR/scripts/model-key-method-lib.sh" ]] || { echo "no model-key-method-lib.sh at $REPO_DIR/scripts/model-key-method-lib.sh"; exit 1; }
cp "$REPO_DIR/scripts/state-file.py" "$REPO_DIR/scripts/model-key-method-lib.sh" "$TMP/"

# ── The scratch copy, and the proof of what it changed ───────────────
# shellcheck disable=SC2016  # a literal to grep for, not an expression to run
GUARD='[[ $EUID -eq 0 ]] || die refused "must run as root; sealing reads the systemd host key, which is root-only"'
SUT="$TMP/seal.sh"
grep -vxF -e "$GUARD" "$ORIG" > "$SUT"
chmod +x "$SUT"

echo
echo "── the root guard, asserted against the real file ─────────────────"

if grep -qxF -e "$GUARD" "$ORIG"; then
  ok "the real script refuses to run as anything but root"
else
  bad "the root guard is in the real script" "the line these tests remove is not there any more"
fi

# One line, and only that line. Otherwise the rows below are testing a
# different program than the one that ships.
diffcount=$(( $(wc -l < "$ORIG") - $(wc -l < "$SUT") ))
if [[ "$diffcount" -eq 1 ]]; then
  ok "and the copy under test differs from it by exactly that one line"
else
  bad "the scratch copy differs by one line" "it differs by $diffcount lines"
fi

# What the seal path IS, line for line, in the file that ships. The arm verb
# was added beside it, and "beside" is the whole claim: these are the lines
# that read a key, validate it and seal it, and every row below is about a
# program that still reads them in this order. A refactor that touched one of
# them would be a different program under test.
mapfile -t SEAL_LINES <<'SEALEOF'
BASE_URL="$LINE1"
IFS= read -r SHAPE      || die refused "the payload ended before shape"
IFS= read -r MODEL      || die refused "the payload ended before model"
IFS= read -r CRED_NAME  || die refused "the payload ended before credential_name"
IFS= read -r KEY        || die refused "the payload ended before the key"
KEY="${KEY//[$'\t\r\n ']/}"
[[ -n "$KEY" ]] || die refused "the key is empty"
  openai|anthropic) ;;
[[ "$BASE_URL" =~ $BASE_URL_HTTPS_RE || "$BASE_URL" =~ $BASE_URL_LOOPBACK_RE ]] \
  if ! printf '%s' "$KEY" | systemd-creds encrypt --name="$CRED_NAME" - "$TMP_CRED" 2>/dev/null; then
KEY=""
unset KEY
  mv -f "$TMP_CRED" "$CRED_PATH"
rm -f "$ARM_FILE" "$ARM_ISSUER_FILE"
SEALEOF
seal_missing=()
for _l in "${SEAL_LINES[@]}"; do
  grep -qxF -- "$_l" "$ORIG" || seal_missing+=("$_l")
done
if [[ ${#seal_missing[@]} -eq 0 ]]; then
  ok "and every line of the five-line seal path is still there, unchanged"
else
  bad "the seal path is unchanged" "not found: ${seal_missing[*]}"; fi

# And in that ORDER, which the presence check above cannot see. The whole
# request is read before any of it is judged, because the caller is a socket
# and a program that decides between two reads breaks whoever is still writing
# (#454). Re-splitting the reads back around the window gate leaves every line
# above present and puts the defect back, so the line numbers are the pin.
key_read_at="$(grep -n 'IFS= read -r KEY ' "$ORIG" | head -1 | cut -d: -f1)"
window_gate_at="$(grep -n 'no arming marker at' "$ORIG" | head -1 | cut -d: -f1)"
if [[ -n "$key_read_at" && -n "$window_gate_at" ]] && (( key_read_at < window_gate_at )); then
  ok "and the whole request is read (line $key_read_at) before the window is judged (line $window_gate_at)"
else
  bad "the request is read before it is judged" \
    "key read at ${key_read_at:-nowhere}, window gate at ${window_gate_at:-nowhere}"; fi

# Run the real one, unmodified, as this ordinary account.
out="$(bash "$ORIG" </dev/null 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'must run as root' <<<"$out"; then
  ok "and running the real one without root is refused, saying why"
else
  bad "the real script refuses a non-root caller" "exit $rc: $out"; fi

# ── Fakes on PATH ───────────────────────────────────────────────────
# systemd-creds: records its own arguments AND its whole environment, then
# consumes stdin and writes a blob. The two recordings are what rows about the
# key never leaving stdin are asserted against.
cat > "$TMP/bin/systemd-creds" <<EOF
#!/usr/bin/env bash
verb="\${1:-}"
printf '%s\n' "\$*" >> "$TMP/state/creds-argv"
env >> "$TMP/state/creds-env"
# The read-back check (#541) is its own verb and its own failure switch: a
# blob that sealed fine and will not decrypt is a different host state than
# sealing itself failing, and the two rows below have to be able to tell
# them apart.
if [[ "\$verb" == decrypt && -f "$TMP/state/creds-decrypt-fails" ]]; then
  echo "Failed to set up credentials: Protocol error" >&2
  exit 1
fi
name=""; out=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --name=*) name="\${1#*=}"; shift ;;
    -) shift ;;
    *) out="\$1"; shift ;;
  esac
done
[[ -f "$TMP/state/creds-fails" ]] && { echo "sealing failed" >&2; exit 1; }
payload="\$(cat)"
printf '%s\n' "\$payload" >> "$TMP/state/creds-stdin"
printf 'SEALED(%s)\n' "\$name" > "\$out"
exit 0
EOF

# systemctl: records what it was asked, and answers is-active from a file.
#
# It also models the one systemd behaviour --reset exists to survive: a unit
# past its start limit is in failed state, and `restart` on it starts nothing
# until `reset-failed` clears it. $TMP/state/failed is that state.
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/systemctl-calls"
case "\$*" in
  # Which systemd this run is standing on (#708). 255 unless a row asks for
  # an older one, because that is the host every row written before the
  # fallback existed assumed.
  --version)
    if [[ -f "$TMP/state/systemd-249" ]]; then
      echo "systemd 249 (249.11-0ubuntu3.22)"
    else
      echo "systemd 255 (255.4-1ubuntu8.17)"
    fi
    exit 0 ;;
  *is-active*) [[ -f "$TMP/state/active" ]] && exit 0 || exit 1 ;;
  reset-failed*) rm -f "$TMP/state/failed" ;;
  # What the service would find at the moment it starts: the config it reads
  # has to be there already, or it comes up with a key and no model.
  restart*)
    if [[ -f "$TMP/state/failed" || -f "$TMP/state/refuse-restart" ]]; then
      rm -f "$TMP/state/active"
      echo "Job for x failed because start of the service was attempted too often." >&2
      exit 1
    fi
    [[ -f "$TMP/advstate/model.json" ]] && echo yes > "$TMP/state/restart-saw-config" || echo no > "$TMP/state/restart-saw-config"
    # The unit is Type=simple: it reads active the moment systemd has forked
    # it, and the listener comes up later (#1120). state/listener-after holds
    # the delay in seconds; state/listener-never is a unit that is up and
    # never listens. The Advisor's answer is state/status.json, which the
    # fake curl serves, so "the listener comes up" is that file appearing.
    if [[ -f "$TMP/state/listener-never" ]]; then
      rm -f "$TMP/state/status.json"
    elif [[ -f "$TMP/state/listener-after" ]]; then
      cp "$TMP/state/status.json" "$TMP/state/status.late.json" 2>/dev/null
      rm -f "$TMP/state/status.json"
      ( sleep "\$(cat "$TMP/state/listener-after")"; cp "$TMP/state/status.late.json" "$TMP/state/status.json" ) >/dev/null 2>&1 &
    fi ;;
esac
exit 0
EOF

# curl: the Advisor's own answer about itself, as a file. Absent is a service
# that did not answer, which is the state a crash-looping host is in and the
# one the reset has to survive rather than refuse on.
#
# Only for /v1/status. Everything else is handed to the real curl, because
# the installer rows further down ask a node for its own key over one, and a
# fake that swallowed those would be testing the fake.
REAL_CURL="$(command -v curl || echo /usr/bin/curl)"
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/curl-calls"
# And one argument per line, so a row can assert the header VALUE exactly
# rather than as a substring of a joined command line.
printf '%s\n' "\$@" >> "$TMP/state/curl-args"
# A header handed on standard input (-H @-, #705) lands in the same file, so
# a row asks what was sent and not by which route. Argv apart, in
# curl-argv-only, for the row that says the token was never on it.
printf '%s\n' "\$@" >> "$TMP/state/curl-argv-only"
case "\$*" in
  */v1/status*) printf 'ask\n' >> "$TMP/state/status-asks"
    # A listener that accepts and never replies: curl waits out its own -m and
    # gives up with 28, as the real one does (#1120 review).
    if [[ -f "$TMP/state/listener-hangs" ]]; then
      m=""; prev=""; for a in "\$@"; do [[ "\$prev" == -m ]] && m="\$a"; prev="\$a"; done
      sleep "\${m:-4}"; exit 28
    fi
    for a in "\$@"; do [[ "\$a" == @- ]] && cat >> "$TMP/state/curl-args"; done ;;
  *) exec "$REAL_CURL" "\$@" ;;
esac
# 22 is what curl -f reports for an answer of 400 or worse, which is how a
# service that is up and refuses the token reaches the caller.
[[ -f "$TMP/state/http-401" ]] && exit 22
[[ -f "$TMP/state/status.json" ]] || exit 7
cat "$TMP/state/status.json"
exit 0
EOF

# logger: the journal, as a file. It records the MESSAGE, which is everything
# after the `--`, because that is what a journal holds. Recording logger's own
# flags instead would make every assertion below depend on argument order.
cat > "$TMP/bin/logger" <<EOF
#!/usr/bin/env bash
msg=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --) shift; msg="\$*"; break ;;
    -t|-p) shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' "\$msg" >> "$TMP/state/journal"
exit 0
EOF

# install: records what it was asked and copies the source into place. Up here
# with the others rather than beside the installer rows below, because the arm
# verb writes its marker with `install -o root` too, and the real one cannot
# chown to root as this account.
cat > "$TMP/bin/install" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/install-calls"
# One destination can be told to fail, for the rows that prove a failed write
# is reported as one rather than as a key trusted.
if [[ -f "$TMP/state/install-fail" && "\${*: -1}" == "\$(cat "$TMP/state/install-fail")" ]]; then
  echo "install: cannot create regular file '\${*: -1}': Read-only file system" >&2
  exit 1
fi
args=(); for a in "\$@"; do case "\$a" in -o|-g|-m) skip=1 ;; *) if [[ "\${skip:-0}" == 1 ]]; then skip=0; else args+=("\$a"); fi ;; esac; done
[[ \${#args[@]} -ge 2 ]] || exit 0
cp -f "\${args[0]}" "\${args[-1]}"
exit 0
EOF

chmod +x "$TMP/bin/"*

# Whether the installer asked for <dest> as root:root <mode>. Every root copy
# now goes through release-digests-lib.sh (ADR 0024): the checked bytes are
# staged beside the destination and installed from there under a temporary
# name, then renamed over it. So the call names the staged file and that
# temporary, both beside <dest>, never the tree.
asked_root() { # $1 = mode, $2 = destination
  # Checked on disk now: the owner and mode are set on the staging file and
  # it is renamed into place (ADR 0024), so there is no install call to read.
  # This suite runs unprivileged, so the owner is its own; the mode is real.
  [[ -f "$2" && ! -L "$2" && "$(stat -c %a "$2")" == "${1#0}" ]]
}

# ── The run harness ─────────────────────────────────────────────────
ARM="$TMP/etc/model-key.arm"
CREDS="$TMP/etc/creds"
UNITS="$TMP/units"
UNITFILE="$UNITS/aperire-advisord.service"
DROPIN="$UNITFILE.d/model-credential.conf"
ISSUER="$ARM.issuer"

# A key that is obviously a key, so a search for it in an argv dump or an
# environment dump cannot match something else by accident.
THEKEY='sk-test-KEYMATERIAL-0123456789-do-not-log'

payload() {
  printf 'https://api.x.ai/v1\nopenai\ngrok-4\nmodel-api-key-xai\n%s\n' "$THEKEY"
}

run_seal() { # stdin is the payload
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_CRED_DIR="$CREDS" \
      APERIRE_ARM_FILE="$ARM" \
      APERIRE_UNIT_DIR="$UNITS" \
      APERIRE_ARM_WINDOW_SEC="${WINDOW:-900}" \
      APERIRE_SEAL_LISTEN_SECONDS="${LISTEN_BUDGET:-2}" \
      bash "$SUT" 2>&1
}

# The unit names its state directory the way install-advisord.sh writes it:
# one ExecStart line, `--state=<dir>` among the flags. That is where the
# sealer learns where model.json goes.
ADVSTATE="$TMP/advstate"
reset_state() {
  rm -f "$TMP/state/"* "$CREDS/"* "$ARM" "$ISSUER" "$ADVSTATE/"* "$ADVSTATE"/.model.* 2>/dev/null
  rm -rf "$UNITFILE.d"
  printf '[Unit]\nDescription=x\n\n[Service]\nExecStart=/bin/true --addr=127.0.0.1:7810 --state=%s --wrapper=/x\n' "$ADVSTATE" > "$UNITFILE"
  : > "$TMP/state/active"
  # And listening: a unit that is up answers /v1/status, which the sealer now
  # waits for before it says the service is up (#1120). Rows that mean an
  # Advisor that does not answer take the file away.
  status_doc false false
  # The service's own token, which is what a root caller reads to ask the
  # Advisor about itself. A real state directory has one from first start.
  printf 'advisor-token-for-tests\n' > "$ADVSTATE/approve.token"
  WINDOW=900
}

# Mode stated, as the real `install -m 0600` states it: the sealer refuses a
# marker that group or others may write, and this harness must not depend on
# the umask of whoever runs it.
arm_now() { : > "$ARM"; chmod 0600 "$ARM"; }
arm_aged() { arm_now; touch -d "@$(( $(date +%s) - ${1:-1000} ))" "$ARM"; }

credential_count() { find "$CREDS" -maxdepth 1 -type f | wc -l; }

run_reset() {
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_CRED_DIR="$CREDS" \
      APERIRE_ARM_FILE="$ARM" \
      APERIRE_UNIT_DIR="$UNITS" \
      SUDO_USER="${OPERATOR:-grape}" \
      APERIRE_SEAL_LISTEN_SECONDS="${LISTEN_BUDGET:-2}" \
      bash "$SUT" --reset 2>&1
}

# What the Advisor answers on /v1/status, in the shape it answers it: two
# spaces of indent, keys in the order Go's encoder sorts them into. The two
# blocks the sealer reads are objects at the top level, and it finds each by
# that indent.
#
# $3 is the config's declared model name, and it is what tells "no model at
# all" apart from "a model, with no credential behind it" (P3-083): both
# report configured:false, and only the first has no name in the block.
# Optional, because most rows below are the plain no-model shape.
status_doc() { # $1 = is a window open, $2 = is a model configured, $3 = declared model name, if any
  local name_field=""
  [[ -z "${3:-}" ]] || name_field=",
    \"name\": \"$3\""
  cat > "$TMP/state/status.json" <<JSON
{
  "breakglass": {
    "expires_at": "2026-09-17T15:00:00Z",
    "node": "n1",
    "open": $1
  },
  "model": {
    "config_path": "$ADVSTATE/model.json",
    "configured": $2$name_field
  },
  "read_only": true
}
JSON
}

# A host sealed before the drop-in existed: the directive in the unit itself,
# a credential behind it, and a config that names it.
old_style_seal() { # $1 = credential name
  printf '[Unit]\nDescription=x\n\n[Service]\nLoadCredentialEncrypted=%s:%s/%s\nExecStart=/bin/true --addr=127.0.0.1:7810 --state=%s --wrapper=/x\n' \
    "$1" "$CREDS" "$1" "$ADVSTATE" > "$UNITFILE"
  printf 'SEALED(%s)\n' "$1" > "$CREDS/$1"
  printf '{\n  "enabled": true,\n  "shape": "openai",\n  "base_url": "https://api.x.ai/v1",\n  "model": "grok-4",\n  "credential_name": "%s"\n}\n' "$1" > "$ADVSTATE/model.json"
}

echo
echo "── the window: armed, unarmed, expired ────────────────────────────"

reset_state
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no arming marker' <<<"$out"; then
  ok "with no arming marker it refuses, and names the file it looked for"
else
  bad "an unarmed call is refused" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and it wrote no credential on the way to refusing"
else
  bad "an unarmed refusal writes nothing" "$(ls "$CREDS")"; fi
if grep -q '^unarmed:' "$TMP/state/journal" 2>/dev/null; then
  ok "and the refusal is in the journal as 'unarmed'"
else
  bad "the unarmed refusal reaches the journal" "$(cat "$TMP/state/journal" 2>/dev/null)"; fi

# #454. The dashboard reaches this program through a socket, and a program
# that refuses BETWEEN two reads of one request breaks the connection under
# whoever is still writing it. That is what the lab saw: the window check
# refused after line one, the four lines behind it were never read, and the
# refusal this program had already put on the wire went with the broken write.
# The operator was told the sealer could not be reached, on a host where it
# had answered in words.
#
# So a refusal reads the whole request first, and that is asserted by sharing
# the file offset with it: the program's standard input is this shell's own
# descriptor, and whatever is left on it after the program exits is what it
# did not read. A sentinel line past the payload says the read stopped in the
# right place rather than running on.
reset_state
{ payload; printf 'SENTINEL\n'; } > "$TMP/p454"
exec 9< "$TMP/p454"
out="$(run_seal <&9)"; rc=$?
IFS= read -r rest <&9 || rest="(end of the request)"
exec 9<&-
if [[ $rc -ne 0 ]] && grep -q 'no arming marker' <<<"$out" && [[ "$rest" == "SENTINEL" ]]; then
  ok "an unarmed refusal has read the whole five-line request, so the writer can finish"
else
  bad "an unarmed refusal reads the whole request" "exit $rc, left unread: $rest"; fi

# The same claim at the transport it actually runs on: a real AF_UNIX pair,
# the program holding one end as its three streams the way systemd hands it
# over, and a writer that sends line one, pauses, then sends the rest. On a
# program that refuses after line one, that second write lands on a socket
# nobody holds any more and the writer is broken; here the writer finishes and
# reads back the refusal with its own exit line.
cat > "$TMP/sockdrive.py" <<'PYEOF'
import os, socket, subprocess, sys, time

sut, key = sys.argv[1], sys.argv[2]
parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
proc = subprocess.Popen(['bash', sut], stdin=child, stdout=child, stderr=child)
child.close()
broke = ''
try:
    parent.sendall(b'https://api.x.ai/v1\n')
    # Long enough for a program that was going to decide after line one to
    # have decided and gone.
    time.sleep(0.5)
    parent.sendall(b'openai\ngrok-4\nmodel-api-key-xai\n' + key.encode() + b'\n')
    parent.shutdown(socket.SHUT_WR)
except OSError as exc:
    broke = os.strerror(exc.errno)
answer = b''
while True:
    chunk = parent.recv(4096)
    if not chunk:
        break
    answer += chunk
proc.wait()
sys.stdout.write('broke=%s\n' % (broke or 'nothing'))
sys.stdout.write(answer.decode('utf-8', 'replace'))
PYEOF
reset_state
out="$(env PATH="$TMP/bin:/usr/bin:/bin" \
    APERIRE_CRED_DIR="$CREDS" APERIRE_ARM_FILE="$ARM" APERIRE_UNIT_DIR="$UNITS" \
    APERIRE_ARM_WINDOW_SEC=900 \
    python3 "$TMP/sockdrive.py" "$SUT" "$THEKEY" 2>&1)"
if grep -q '^broke=nothing$' <<<"$out" && grep -q 'no arming marker' <<<"$out" \
  && grep -q '^exit=1$' <<<"$out"; then
  ok "over a real socket, the writer finishes and the refusal comes back with its exit line"
else
  bad "a socket writer is not broken by a refusal" "$out"; fi
if ! grep -q -e "$THEKEY" "$TMP/state/journal" 2>/dev/null; then
  ok "  and the key the writer sent is nowhere in the journal"
else
  bad "  and the key is nowhere in the journal" "$(cat "$TMP/state/journal")"; fi

reset_state
arm_aged 1000
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'arming window closed' <<<"$out"; then
  ok "an arming older than the window is refused, in different words than 'not armed'"
else
  bad "an expired arming is refused" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and it wrote no credential"
else
  bad "an expired refusal writes nothing" "$(ls "$CREDS")"; fi
if grep -q '^expired:' "$TMP/state/journal" 2>/dev/null; then
  ok "and the journal tells the two refusals apart"
else
  bad "the expired refusal is its own journal outcome" "$(cat "$TMP/state/journal" 2>/dev/null)"; fi
if [[ ! -f "$ARM" ]]; then
  ok "and the lapsed marker is removed, so it cannot go on being refused forever"
else
  bad "an expired marker is cleared" "it is still there"; fi

# A marker whose time is in the future is not a fresh arming.
reset_state
arm_now; touch -d "@$(( $(date +%s) + 3600 ))" "$ARM"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'arming window closed' <<<"$out"; then
  ok "a marker dated in the future is treated as expired, not as fresh"
else
  bad "a future-dated marker is refused" "exit $rc: $out"; fi

# A marker anyone may write is not an arming, whatever its age. The dashboard
# account cannot create one while /etc/aperire is root's, and the sealer does
# not rely on that (#181).
reset_state
arm_now; chmod 0666 "$ARM"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'is mode 666' <<<"$out" && [[ "$(credential_count)" -eq 0 ]]; then
  ok "a marker that others may write is refused as not an arming, and nothing was sealed"
else
  bad "a world-writable marker is refused" "exit $rc: $out"; fi
reset_state
arm_now; chmod 0620 "$ARM"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'is mode 620' <<<"$out"; then
  ok "a marker the group may write is refused the same way"
else
  bad "a group-writable marker is refused" "exit $rc: $out"; fi

# Just inside the window still works, so the rows above are not passing
# because sealing never works at all.
reset_state
arm_aged 800
out="$(payload | run_seal)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^sealed=model-api-key-xai$' <<<"$out"; then
  ok "an arming inside the window seals (the refusals above are not unconditional)"
else
  bad "a valid arming seals" "exit $rc: $out"; fi

echo
echo "── once per arming ────────────────────────────────────────────────"

reset_state
arm_now
out="$(payload | run_seal)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^service=active$' <<<"$out"; then
  ok "the first call seals and reports the service it read back"
else
  bad "the first call seals" "exit $rc: $out"; fi
if [[ -f "$CREDS/model-api-key-xai" ]]; then
  ok "and the credential is where the unit will look for it"
else
  bad "the credential is written" "$(ls "$CREDS")"; fi
if [[ ! -f "$ARM" ]]; then
  ok "and the arming is spent"
else
  bad "the arming is spent on success" "the marker is still there"; fi

# The same payload again, immediately. Nothing about the host changed except
# that the window was used, which is the whole point.
out2="$(payload | run_seal)"; rc2=$?
if [[ $rc2 -ne 0 ]] && grep -q 'no arming marker' <<<"$out2"; then
  ok "a second call with the same payload is refused, because the window was spent"
else
  bad "the second call is refused" "exit $rc2: $out2"; fi

echo
echo "── the exit status, printed because it cannot cross a socket ──────"

# The dashboard reaches this through a socket-activated unit: the accepted
# connection is stdin, stdout and stderr, and when the program ends the
# connection closes carrying nothing about why. So the status is printed, last,
# on every path. A reader that saw fields and no status would have to guess.
reset_state
arm_now
out="$(payload | run_seal)"
if [[ "$(printf '%s\n' "$out" | tail -n 1)" == "exit=0" ]]; then
  ok "a success ends with exit=0, as its very last line"
else
  bad "a success prints its status last" "last line: $(printf '%s\n' "$out" | tail -n 1)"; fi
if [[ "$(printf '%s\n' "$out" | grep -n '^sealed=' | cut -d: -f1)" -lt \
      "$(printf '%s\n' "$out" | grep -n '^exit=' | cut -d: -f1)" ]]; then
  ok "and its fields come before it, so nothing is written after the status"
else
  bad "the status is last" "$out"; fi

reset_state
out="$(payload | run_seal)"
if [[ "$(printf '%s\n' "$out" | tail -n 1)" == "exit=1" ]]; then
  ok "a refusal ends with exit=1, so a failure is never read as a success"
else
  bad "a refusal prints its status too" "last line: $(printf '%s\n' "$out" | tail -n 1)"; fi
if grep -q 'no arming marker' <<<"$out"; then
  ok "and the refusal's own words are still there to read"
else
  bad "the refusal keeps its words" "$out"; fi

# The temporary credential is removed by the same handler that prints the
# status, on the path where sealing itself failed part-way.
reset_state
arm_now
: > "$TMP/state/creds-fails"
out="$(payload | run_seal)"
if [[ "$(printf '%s\n' "$out" | tail -n 1)" == "exit=1" ]] \
   && [[ "$(find "$CREDS" -maxdepth 1 -name '.seal.*' | wc -l)" -eq 0 ]]; then
  ok "a failed seal leaves no temporary credential behind, and still reports"
else
  bad "the exit handler cleans up as well" "$(ls -a "$CREDS")"; fi

echo
echo "── the key never leaves standard input ────────────────────────────"

reset_state
arm_now
payload | run_seal >/dev/null 2>&1

if [[ -s "$TMP/state/creds-argv" ]] && ! grep -qF -e "$THEKEY" "$TMP/state/creds-argv"; then
  ok "the key is in no argument of the program that seals it"
else
  bad "the key is not in argv" "$(cat "$TMP/state/creds-argv" 2>/dev/null)"; fi
if [[ -s "$TMP/state/creds-env" ]] && ! grep -qF -e "$THEKEY" "$TMP/state/creds-env"; then
  ok "and in no variable of its environment"
else
  bad "the key is not in the environment" "$(grep -F -e "$THEKEY" "$TMP/state/creds-env" | head -2)"; fi
# The positive control: it did arrive, on the one channel it is meant to.
if grep -qF -e "$THEKEY" "$TMP/state/creds-stdin" 2>/dev/null; then
  ok "and it did arrive on standard input, which is the only channel it uses"
else
  bad "the key reaches the sealer on stdin" "nothing recorded"; fi
if [[ -s "$TMP/state/journal" ]] && ! grep -qF -e "$THEKEY" "$TMP/state/journal"; then
  ok "and no journal line holds a byte of it"
else
  bad "the journal never holds the key" "$(grep -F -e "$THEKEY" "$TMP/state/journal" | head -1)"; fi
if grep -q '^sealed:' "$TMP/state/journal"; then
  ok "while the success itself is on the record, naming the credential and the model"
else
  bad "a success reaches the journal" "$(cat "$TMP/state/journal")"; fi

echo
echo "── a key that will not read back is refused, not wired in (#541) ───"

# The backup-restore shape: the same bytes systemd-creds just wrote for THIS
# host refuse to decrypt on it, modelled here as sealing succeeding and the
# read-back failing, which is what a host whose credential.secret changed
# underneath the file actually produces.
reset_state
arm_now
: > "$TMP/state/creds-decrypt-fails"
out="$(payload | run_seal)"
if [[ "$(printf '%s\n' "$out" | tail -n 1)" == "exit=1" ]] \
   && grep -q 'would not read back on this host' <<<"$out"; then
  ok "a seal that will not read back is refused, saying so"
else
  bad "the read-back check refuses" "$out"
fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and the credential it just wrote is removed again"
else
  bad "the unreadable credential is cleaned up" "$(ls "$CREDS")"
fi
if [[ ! -f "$DROPIN" ]]; then
  ok "and no drop-in is written for a key nothing can load"
else
  bad "no drop-in on a failed read-back" "$(cat "$DROPIN")"
fi
if [[ -f "$ARM" ]]; then
  ok "and the arming window is not spent, so the same operator can retry"
else
  bad "the window survives a read-back failure" "arm file is gone"
fi
if grep -qF -e "$THEKEY" "$TMP/state/journal" 2>/dev/null; then
  bad "the journal never holds the key" "$(grep -F -e "$THEKEY" "$TMP/state/journal")"
else
  ok "and the journal still holds none of the key"
fi

echo
echo "── refusing before it writes ──────────────────────────────────────"

check_refusal() { # $1 = label, $2 = expected words, stdin = payload
  reset_state
  arm_now
  local o r
  o="$(run_seal)"; r=$?
  if [[ $r -ne 0 ]] && grep -q -e "$2" <<<"$o"; then
    ok "$1"
  else
    bad "$1" "exit $r: $o"
  fi
  if [[ "$(credential_count)" -eq 0 ]]; then
    ok "  and nothing was written"
  else
    bad "  and nothing was written" "$(ls "$CREDS")"
  fi
}

printf 'https://api.x.ai/v1\nopenai\ngrok-4\nmodel-api-key-xai\n\n' > "$TMP/p"
check_refusal "an empty key is refused" 'the key is empty' < "$TMP/p"

printf 'https://api.x.ai/v1\nnonsense\ngrok-4\nmodel-api-key-xai\nk\n' > "$TMP/p"
check_refusal "a shape that is neither openai nor anthropic is refused" 'shape must be' < "$TMP/p"

printf 'http://evil.example\nopenai\ngrok-4\nmodel-api-key-xai\nk\n' > "$TMP/p"
check_refusal "a plain-http provider that is not loopback is refused" 'must be https' < "$TMP/p"

# The base_url is written into JSON by root, and the frame above it is five
# lines with nothing between them. So: no quote, no backslash, no whitespace,
# anchored (#179). Each of these once passed a prefix glob.
printf 'https://a","enabled":false,"z":"x\nopenai\ngrok-4\nmodel-api-key-xai\nk\n' > "$TMP/p"
check_refusal "a base_url carrying a quote is refused" 'no spaces, quotes or backslashes' < "$TMP/p"
printf 'https://a\\\nopenai\ngrok-4\nmodel-api-key-xai\nk\n' > "$TMP/p"
check_refusal "a base_url ending in a backslash is refused" 'no spaces, quotes or backslashes' < "$TMP/p"
printf 'https://api.x.ai/v1 extra\nopenai\ngrok-4\nmodel-api-key-xai\nk\n' > "$TMP/p"
check_refusal "a base_url with a space is refused" 'no spaces, quotes or backslashes' < "$TMP/p"
printf 'http://127.0.0.1.evil.example/v1\nopenai\ngrok-4\nmodel-api-key-xai\nk\n' > "$TMP/p"
check_refusal "a loopback prefix on another host is refused" 'must be https' < "$TMP/p"

printf 'https://api.x.ai/v1\nopenai\ngrok-4\n../../etc/shadow\nk\n' > "$TMP/p"
check_refusal "a credential name that is a path is refused" 'must be a bare name' < "$TMP/p"

printf 'https://api.x.ai/v1\nopenai\ngrok-4\nmodel-api-key-xai\n' > "$TMP/p"
check_refusal "a payload that ends before the key is refused" 'ended before the key' < "$TMP/p"

# The unit has to exist. Sealing for a service that is not here produces a
# credential nothing loads and a success nobody can act on.
reset_state
arm_now
rm -f "$UNITFILE"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no .* on this host' <<<"$out"; then
  ok "sealing for a service that is not installed is refused"
else
  bad "an absent unit is refused" "exit $rc: $out"; fi
if [[ -f "$ARM" ]]; then
  ok "and the arming is NOT spent by a refusal, so the operator keeps their window"
else
  bad "a refusal does not spend the arming" "the marker is gone"; fi

# A failure inside systemd-creds must not report success, and must not leave a
# half-written credential behind.
reset_state
arm_now
: > "$TMP/state/creds-fails"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'could not seal' <<<"$out"; then
  ok "a sealing tool that fails is reported as a failure"
else
  bad "a failed seal is a failure" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and no partial credential is left where a whole one goes"
else
  bad "no partial credential" "$(ls "$CREDS")"; fi

echo
echo "── what it does to the unit, and what it reads back ───────────────"

reset_state
arm_now
payload | run_seal >/dev/null 2>&1
# The directive lives in a drop-in and not in the unit, so that it and the
# credential file can be removed together. A unit that declares a credential
# which is not there exits 243/CREDENTIALS before the program runs (#446).
if [[ -f "$DROPIN" ]] && grep -q "^LoadCredentialEncrypted=model-api-key-xai:$CREDS/model-api-key-xai\$" "$DROPIN"; then
  ok "the credential is wired into a drop-in this program owns, under [Service]"
else
  bad "the drop-in loads the credential" "$(ls -la "$UNITFILE.d" 2>&1; cat "$DROPIN" 2>&1)"; fi
if grep -q '^\[Service\]' "$DROPIN"; then
  ok "and the drop-in names the section, or systemd would refuse the file"
else
  bad "the drop-in has a [Service] section" "$(cat "$DROPIN")"; fi
if ! grep -q '^LoadCredentialEncrypted' "$UNITFILE"; then
  ok "and the unit the installer wrote is left alone"
else
  bad "the unit is not edited" "$(cat "$UNITFILE")"; fi
if [[ "$(grep -c '^LoadCredentialEncrypted=model-api-key-xai' "$DROPIN")" -eq 1 ]]; then
  ok "exactly once, so a re-seal cannot leave two lines naming one credential"
else
  bad "one credential line" "$(grep -c '^LoadCredentialEncrypted' "$DROPIN") lines"; fi

# Every fleet host today carries the line in the main unit. Nobody has to do
# anything about that: the next seal takes it out and the drop-in replaces it.
reset_state
old_style_seal model-api-key-anthropic
arm_now
out="$(payload | run_seal 2>/dev/null)"
if ! grep -q '^LoadCredentialEncrypted' "$UNITFILE"; then
  ok "a host carrying the line in its main unit is migrated by the next seal"
else
  bad "the old unit line is migrated away" "$(cat "$UNITFILE")"; fi
if grep -q '^migrated=yes$' <<<"$out"; then
  ok "and the run says so, rather than leaving it to be discovered"
else
  bad "the migration is reported" "$out"; fi
if [[ -f "$DROPIN" ]] && grep -q '^LoadCredentialEncrypted=model-api-key-xai:' "$DROPIN"; then
  ok "and the drop-in is the only declaration left"
else
  bad "the drop-in carries it after a migration" "$(cat "$DROPIN" 2>&1)"; fi
if grep -q 'daemon-reload' "$TMP/state/systemctl-calls" \
   && grep -q 'restart aperire-advisord' "$TMP/state/systemctl-calls"; then
  ok "and systemd is reloaded and the Advisor restarted, because the key arrives at start"
else
  bad "reload and restart happen" "$(cat "$TMP/state/systemctl-calls")"; fi

# #898 review, L1: a unit still carrying the waiting note (written by a fresh
# install, its account step not finished) names an account that owns nothing
# yet. A seal there puts the key in place and leaves the start to the account
# step: restarting it would start a service that crash-loops, and the read-back
# below says the truth, that it is not running.
reset_state
rm -f "$TMP/state/active"
sed -i 's/^\[Unit\]$/&\n# Waiting for install-advisor-account.sh, which makes the account and starts it (#893)./' "$UNITFILE"
arm_now
out="$(payload | run_seal 2>/dev/null)"
if grep -q '^sealed=' <<<"$out" && ! grep -q 'restart aperire-advisord' "$TMP/state/systemctl-calls"; then
  ok "a seal on a unit still waiting for the account step seals the key and starts nothing"
else
  bad "a waiting unit is not started by a seal" "$(cat "$TMP/state/systemctl-calls")"; fi
if grep -q 'service inactive' <<<"$out"; then
  ok "  and the read-back says it is not running"
else
  bad "a waiting unit reads back as not running" "$out"; fi

# The config the service reads. The first real browser seal left this file
# unwritten and the Advisor came back with a key and no model to use it for.
reset_state
arm_now
out="$(payload | run_seal 2>/dev/null)"
if [[ -f "$ADVSTATE/model.json" ]] && grep -q '^config='"$ADVSTATE/model.json"'$' <<<"$out"; then
  ok "model.json is written where the unit's --state= points, and the path is read back"
else
  bad "the config is written" "exit: $out; $(ls -la "$ADVSTATE")"; fi
if python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
assert c["enabled"] is True, c
assert c["shape"]=="openai" and c["model"]=="grok-4", c
assert c["base_url"]=="https://api.x.ai/v1", c
assert c["credential_name"]=="model-api-key-xai", c
# The hint is the one thing derived from the key that lives on: first six,
# last four, and nothing between. The key itself must not be in the file, and
# neither may any run of it longer than the hint shows.
assert c["key_hint"]=="sk-tes\u2026-log", c
key=sys.argv[2]
assert key not in json.dumps(c), c
assert key[6:-4] not in json.dumps(c), c
assert "key" not in json.dumps(c).lower().replace("credential_name","").replace("api-key","").replace("key_hint",""), c
' "$ADVSTATE/model.json" "$THEKEY" 2>/dev/null; then
  ok "it is enabled, names the provider, model and credential, carries the key hint and holds no key"
else
  bad "the config content" "$(cat "$ADVSTATE/model.json")"; fi
if [[ "$(stat -c %a "$ADVSTATE/model.json")" == "640" ]] && ! ls "$ADVSTATE"/.model.* >/dev/null 2>&1; then
  ok "mode 0640, and no temporary file is left beside it"
else
  bad "config mode and tidiness" "$(ls -la "$ADVSTATE")"; fi
# Written before the restart, because the service reads it from the moment it
# comes up. The fake systemctl looked for the file when it was asked to restart.
if [[ "$(cat "$TMP/state/restart-saw-config" 2>/dev/null)" == yes ]]; then
  ok "and it is already there when the service is restarted"
else
  bad "config before restart" "restart saw config: $(cat "$TMP/state/restart-saw-config" 2>/dev/null)"; fi

# A unit with no --state= is refused before anything is sealed: the alternative
# is a credential with a config nobody can place.
reset_state
arm_now
printf '[Unit]\nDescription=x\n\n[Service]\nExecStart=/bin/true\n' > "$UNITFILE"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'names no --state= directory' <<<"$out" && [[ "$(credential_count)" -eq 0 ]] && [[ -f "$ARM" ]]; then
  ok "a unit with no --state= is refused, and nothing was sealed or spent"
else
  bad "no state dir is refused before the seal" "exit $rc: $out; creds $(credential_count)"; fi

# An explicit --model-config= on the unit wins over the derived path.
reset_state
arm_now
printf '[Unit]\n\n[Service]\nExecStart=/bin/true --state=%s --model-config=%s/custom.json\n' "$ADVSTATE" "$ADVSTATE" > "$UNITFILE"
out="$(payload | run_seal 2>/dev/null)"
if [[ -f "$ADVSTATE/custom.json" && ! -f "$ADVSTATE/model.json" ]] && grep -q '^config='"$ADVSTATE/custom.json"'$' <<<"$out"; then
  ok "an explicit --model-config= on the unit is where it writes instead"
else
  bad "--model-config= is honoured" "$out; $(ls "$ADVSTATE")"; fi

# A service that does not come back is not a success, however well the sealing
# went. What is printed is what was read back.
reset_state
arm_now
rm -f "$TMP/state/active"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q '^service=inactive$' <<<"$out"; then
  ok "a service that does not come back is reported inactive, and the call fails"
else
  bad "an inactive service is a failure" "exit $rc: $out"; fi
if [[ -f "$CREDS/model-api-key-xai" && ! -f "$ARM" ]]; then
  ok "and it still says the key was sealed and the window spent, because both were"
else
  bad "the honest state after a failed restart" "cred:$(credential_count) arm:$([[ -f $ARM ]] && echo yes || echo no)"; fi

echo
echo "── it takes no arguments ──────────────────────────────────────────"

# The unit behind the socket names this program and nothing after it, so the
# dashboard has no way to pass an argument. Refused here as well, so an
# operator invocation cannot point it at a different credential path either,
# and the two do not have to agree by luck.
reset_state
arm_now
out="$(payload | env PATH="$TMP/bin:/usr/bin:/bin" APERIRE_CRED_DIR="$CREDS" \
        APERIRE_ARM_FILE="$ARM" APERIRE_UNIT_DIR="$UNITS" bash "$SUT" --anything 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'the only argument is --reset' <<<"$out"; then
  ok "an argument other than --reset is refused"
else
  bad "arguments are refused" "exit $rc: $out"; fi
if [[ -f "$ARM" ]]; then
  ok "and that refusal does not spend the window either"
else
  bad "an argument refusal keeps the window" "the marker is gone"; fi
# Two of them is not --reset either, and neither is --reset with a payload
# behind it: the seal path must not be reachable by an argument.
out="$(payload | env PATH="$TMP/bin:/usr/bin:/bin" APERIRE_CRED_DIR="$CREDS" \
        APERIRE_ARM_FILE="$ARM" APERIRE_UNIT_DIR="$UNITS" bash "$SUT" --reset --anything 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'the only argument is --reset' <<<"$out" && [[ "$(credential_count)" -eq 0 ]]; then
  ok "and so is --reset with anything after it, with nothing sealed on the way out"
else
  bad "a second argument is refused" "exit $rc: $out"; fi


echo
echo "── --reset: the whole of an unseal, as one action ─────────────────"

# What this is for: removing the sealed key without also removing the
# directive that loads it leaves a service that cannot start at all
# (243/CREDENTIALS, restart counter climbing), and the two steps that undo a
# seal were documented in the sealer's own header and enforced nowhere (#446).

seal_one() {   # a host in the state a seal leaves it in
  reset_state
  arm_now
  payload | run_seal >/dev/null 2>&1
  : > "$TMP/state/systemctl-calls"
  rm -f "$TMP/state/curl-calls" "$ADVSTATE/model-change.json"
}

seal_one
status_doc false false
out="$(run_reset)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^exit=0$' <<<"$out"; then
  ok "a reset from a sealed state ends well, and says so on its last line"
else
  bad "the reset succeeds" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and the sealed key is gone from the credential store"
else
  bad "the credential is removed" "$(ls -la "$CREDS")"; fi
if [[ ! -e "$DROPIN" ]] && [[ ! -d "$UNITFILE.d" ]]; then
  ok "and the drop-in that loaded it is gone with it, directory and all"
else
  bad "the drop-in is removed" "$(ls -la "$UNITFILE.d" 2>&1)"; fi
if ! grep -q '^LoadCredentialEncrypted' "$UNITFILE"; then
  ok "and the unit declares no credential, so the service can start"
else
  bad "no credential is declared" "$(cat "$UNITFILE")"; fi
if grep -q '^service=active$' <<<"$out" && grep -q '^model=none$' <<<"$out"; then
  ok "and the Advisor came back and reported no model, which is what is printed"
else
  bad "the daemon is active and unconfigured" "$out"; fi
if python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
assert c.get("enabled") is False, c
assert "credential_name" not in c, c
assert "key_hint" not in c, c
' "$ADVSTATE/model.json" 2>/dev/null; then
  ok "the config is the honest no-model state: disabled, with no key hint left behind"
else
  bad "the config after a reset" "$(cat "$ADVSTATE/model.json" 2>&1)"; fi
if grep -q 'daemon-reload' "$TMP/state/systemctl-calls" \
   && grep -q 'restart aperire-advisord' "$TMP/state/systemctl-calls"; then
  ok "and systemd was reloaded and the Advisor restarted, in one action"
else
  bad "reload and restart happen" "$(cat "$TMP/state/systemctl-calls")"; fi
if grep -q '^reset:' "$TMP/state/journal"; then
  ok "and the whole of it is in the journal as 'reset'"
else
  bad "the reset reaches the journal" "$(cat "$TMP/state/journal")"; fi
# The audit record is the Advisor's, written from what it observes. This is
# the one thing it cannot observe: who asked for the reset, and for which
# credential (#446, #447).
if python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
assert c["via"]=="reset", c
assert c["by"]=="grape", c
assert c["credential_name"]=="model-api-key-xai", c
assert c["at"].endswith("Z"), c
' "$ADVSTATE/model-change.json" 2>/dev/null; then
  ok "and it leaves the operator and the credential for the ledger entry to quote"
else
  bad "the change file names the operator" "$(cat "$ADVSTATE/model-change.json" 2>&1)"; fi
# Exactly, not as a substring: the daemon compares the whole bearer value
# against the token file with the whitespace trimmed, so a header carrying one
# extra space is a 401 and a window this program then cannot see.
if grep -qxF "authorization: Bearer $(tr -d '[:space:]' < "$ADVSTATE/approve.token")" "$TMP/state/curl-args" 2>/dev/null; then
  ok "the Advisor was asked about itself with its own token, whitespace off, as the service reads it"
else
  bad "the status read carries the token" "$(cat "$TMP/state/curl-args" 2>&1)"; fi
# And never on curl's command line, which every account on the host can read
# in /proc (#705).
if [[ -s "$TMP/state/curl-argv-only" ]] && ! grep -qF -e "$(tr -d '[:space:]' < "$ADVSTATE/approve.token")" "$TMP/state/curl-argv-only"; then
  ok "  and the token was handed to curl on its standard input, never on its argv"
else
  bad "  the token is not on curl's argv (#705)" "$(grep -c . "$TMP/state/curl-argv-only" 2>/dev/null) argv lines, token among them"; fi

# Run twice. Nothing left to undo is not a failure, and not a reason to bounce
# a service that is already in the state this verb produces.
: > "$TMP/state/systemctl-calls"
out="$(run_reset)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^already=unsealed$' <<<"$out"; then
  ok "a reset on a host that is already unsealed says so, and ends well"
else
  bad "the second reset is a no-op" "exit $rc: $out"; fi
if ! grep -q 'restart' "$TMP/state/systemctl-calls"; then
  ok "and restarts nothing, because there is nothing to change"
else
  bad "a no-op restarts nothing" "$(cat "$TMP/state/systemctl-calls")"; fi
if grep -q '^unsealed:' "$TMP/state/journal"; then
  ok "and the no-op is on the record too, in its own word"
else
  bad "the no-op reaches the journal" "$(cat "$TMP/state/journal")"; fi

# P3-083. configured:false is what a genuine no-model reset reports, and it
# is also what a model with no credential on this host reports, since the
# Advisor started publishing that as a conjunction. A reset that cleared the
# credential but somehow left the model still declared would read exactly
# like a clean one on that string alone. Simulated directly, at the
# verification step: the removal steps still ran (this is still `seal_one`
# followed by `--reset`), and only the Advisor's own read-back is engineered
# to say the model is still declared.
seal_one
status_doc false false model-still-declared
out="$(run_reset)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q '^model=configured$' <<<"$out"; then
  ok "a model still declared in the block reads as still configured, even though configured:false"
else
  bad "the reset's own verification tells the two configured:false shapes apart" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and the credential is still removed either way: the verification is a read, not a gate on the removal"
else
  bad "the removal itself is unconditional on the read-back" "$(ls -la "$CREDS")"; fi

# A window is an operator part-way through something with raised ceilings.
# Taking the model out from under them is the wrong moment, so this refuses,
# and a refusal leaves the host exactly as it was.
seal_one
status_doc true false
out="$(run_reset)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'break-glass window is open' <<<"$out"; then
  ok "a reset while a break-glass window is open is refused, and says which"
else
  bad "an open window refuses the reset" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 1 ]] && [[ -f "$DROPIN" ]]; then
  ok "and the refusal removed nothing: the key and the drop-in are where they were"
else
  bad "the refusal changes nothing" "$(ls "$CREDS"); $(ls -la "$UNITFILE.d" 2>&1)"; fi
if ! grep -q 'restart' "$TMP/state/systemctl-calls"; then
  ok "and nothing was restarted on the way to refusing"
else
  bad "the refusal restarts nothing" "$(cat "$TMP/state/systemctl-calls")"; fi

# Answered, and would not say. A live Advisor whose token no longer matches
# is not the state this verb repairs, and "nobody is mid-ceremony" is not a
# claim that can be made about a service that is up and will not answer.
seal_one
status_doc false false
: > "$TMP/state/http-401"
out="$(run_reset)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'refused this host'"'"'s own token' <<<"$out"; then
  ok "an Advisor that answers and refuses this host's token refuses the reset, naming the file"
else
  bad "a refused token refuses the reset" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 1 ]] && [[ -f "$DROPIN" ]]; then
  ok "and that refusal removed nothing either"
else
  bad "the token refusal changes nothing" "$(ls "$CREDS")"; fi
rm -f "$TMP/state/http-401"

# And the other half of that: the check fails OPEN. A window lives in the
# running process and a restart ends it, so a service that cannot answer is a
# service holding no window, and a crash-looping Advisor, the exact host this
# verb exists for, can never answer.
seal_one
rm -f "$TMP/state/status.json"
out="$(run_reset)"; rc=$?
if [[ "$(credential_count)" -eq 0 ]] && grep -q '^reset=' <<<"$out"; then
  ok "an Advisor that does not answer does not block its own repair"
else
  bad "the window check fails open" "exit $rc: $out"; fi
# The repair went ahead, and the report no longer claims a service that cannot
# answer (#1120): the unit is up, nothing listens, and it says so.
if [[ $rc -ne 0 ]] && grep -q '^service=not-answering$' <<<"$out" && grep -q '^listener=silent$' <<<"$out"; then
  ok "but the read-back says the service is not answering, and exits non-zero"
else
  bad "a silent service is not reported as up" "exit $rc: $out"; fi
if grep -q '^model=unchecked$' <<<"$out"; then
  ok "and the read-back says 'unchecked' rather than claiming a state nobody read"
else
  bad "an unread status is named" "$out"; fi
if grep -q 'the Advisor did not answer' "$TMP/state/journal"; then
  ok "and the journal says the Advisor did not answer, and why going ahead is safe"
else
  bad "the unchecked window is on the record" "$(cat "$TMP/state/journal")"; fi

echo
echo "── the report says the service is up only when it answers (#1120) ──"

# The unit reads active at once; the listener comes 300 ms later. The sealer
# used to print service=active on the first read of the unit. Now it asks the
# Advisor, and it must have asked more than once to have waited for it.
reset_state; arm_now
status_doc false false
: > "$TMP/state/listener-after"; printf '0.3\n' > "$TMP/state/listener-after"
out="$(payload | run_seal)"; rc=$?
asks="$(wc -l < "$TMP/state/status-asks" 2>/dev/null || echo 0)"
if [[ $rc -eq 0 ]] && grep -q '^service=active$' <<<"$out" && grep -q '^listener=answering$' <<<"$out"; then
  ok "a seal reports the service up once the late listener answers"
else
  bad "a late listener is waited for" "exit $rc: $out"; fi
if (( asks >= 2 )); then
  ok "and it asked more than once: the first ask met no listener, and the report waited for the second"
else
  bad "the seal asked the Advisor before it said the service was up" "status asks: $asks"; fi

# The same wait on the reset, which restarts the Advisor too.
reset_state; arm_now
payload | run_seal >/dev/null
rm -f "$TMP/state/status-asks"
status_doc false false
printf '0.3\n' > "$TMP/state/listener-after"
out="$(run_reset)"; rc=$?
asks="$(wc -l < "$TMP/state/status-asks" 2>/dev/null || echo 0)"
if [[ $rc -eq 0 ]] && grep -q '^service=active$' <<<"$out" && grep -q '^listener=answering$' <<<"$out" && (( asks >= 2 )); then
  ok "a reset reports the service up only after the late listener answers"
else
  bad "the reset waits for the listener" "exit $rc, asks $asks: $out"; fi
rm -f "$TMP/state/listener-after"

# A unit that is up and never listens: the report says so plainly and the exit
# is non-zero. The key is sealed, and nothing claims the Advisor came back.
reset_state; arm_now
: > "$TMP/state/listener-never"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q '^sealed=' <<<"$out" && grep -q '^service=not-answering$' <<<"$out" && grep -q '^listener=silent$' <<<"$out"; then
  ok "a unit that never listens is reported as not answering, with a non-zero exit, and the key stays sealed"
else
  bad "a silent service is not 'active'" "exit $rc: $out"; fi
if grep -q 'nothing answered on 127.0.0.1:7810 within 2 s' <<<"$out"; then
  ok "and says in plain words what it waited for and for how long"
else
  bad "the silence is explained" "$out"; fi
if ! grep -q '^service=active$' <<<"$out"; then
  ok "service=active appears nowhere in that report"
else
  bad "no service=active for a silent unit" "$out"; fi
rm -f "$TMP/state/listener-never"

# A listener that accepts and never replies. The wait is a budget of time, not
# a count of probes: with a probe held for its whole timeout, counting probes
# ran many times the budget (about 400 s at the default 20). Budget 1 s here,
# probes capped at 2 s, so the seal ends well inside 6 s.
reset_state; arm_now
: > "$TMP/state/listener-hangs"
LISTEN_BUDGET=1
t0=$SECONDS
out="$(payload | run_seal)"; rc=$?
took=$(( SECONDS - t0 ))
LISTEN_BUDGET=2
if [[ $rc -ne 0 ]] && grep -q '^service=not-answering$' <<<"$out" && grep -q '^listener=silent$' <<<"$out" && (( took <= 6 )); then
  ok "a listener that never replies ends the wait within the budget plus one probe (${took} s for a 1 s budget)"
else
  bad "the wait is bounded by time" "exit $rc after ${took} s: $out"; fi
rm -f "$TMP/state/listener-hangs"

# Nothing to ask with (no token to send): nothing is known either way, so the
# report keeps the unit's own word and labels it unchecked rather than claiming
# the listener answered.
reset_state; arm_now
rm -f "$ADVSTATE/approve.token"
out="$(payload | run_seal)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^service=active$' <<<"$out" && grep -q '^listener=unchecked$' <<<"$out"; then
  ok "with no token to ask with, the report says the listener was unchecked"
else
  bad "an unaskable host is labelled unchecked" "exit $rc: $out"; fi

# And the other reason a window goes unchecked, which is not about the service
# at all: nothing here could ask. Claiming "the Advisor did not answer" for a
# request that was never sent is a reading nobody observed.
seal_one
status_doc false false
rm -f "$ADVSTATE/approve.token"
# The seal above asked the Advisor whether it was listening (#1120); this row
# is about the reset's own asks, so that record starts again here.
rm -f "$TMP/state/curl-args" "$TMP/state/curl-calls" "$TMP/state/curl-argv-only" "$TMP/state/status-asks"
out="$(run_reset)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'there was no way to ask' "$TMP/state/journal"; then
  ok "a host this program cannot ask says so in its own words, not the service's"
else
  bad "no way to ask is its own sentence" "exit $rc: $(cat "$TMP/state/journal")"; fi
if [[ ! -e "$TMP/state/curl-args" ]]; then
  ok "and it is honest about that: no request went out at all"
else
  bad "nothing was sent" "$(cat "$TMP/state/curl-args")"; fi

# Every fleet host today carries the directive in the main unit. A reset has
# to take that one out too, or it removes the key and leaves the service
# unable to start, which is the defect itself.
reset_state
old_style_seal model-api-key-anthropic
status_doc false false
out="$(run_reset)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^migrated=yes$' <<<"$out"; then
  ok "a host with the line in its main unit is migrated by the reset, and says so"
else
  bad "the reset migrates the unit line" "exit $rc: $out"; fi
if ! grep -q '^LoadCredentialEncrypted' "$UNITFILE" && [[ "$(credential_count)" -eq 0 ]]; then
  ok "and it leaves neither the directive nor the key it pointed at"
else
  bad "the old-style host is unsealed" "$(cat "$UNITFILE"); $(ls "$CREDS")"; fi
if grep -q '^reset=model-api-key-anthropic$' <<<"$out"; then
  ok "and it names the credential it removed, which it read from the config"
else
  bad "the credential is named" "$out"; fi

# The host this verb exists for has been crash-looping. Past its start limit
# the unit is in failed state, `systemctl restart` answers "start request
# repeated too quickly" and starts nothing, and a reset that did the removals
# and then reported the service down would be the same defect one step along.
seal_one
status_doc false false
: > "$TMP/state/failed"
out="$(run_reset)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^service=active$' <<<"$out"; then
  ok "a unit stopped by its own start limit is cleared, and comes back up"
else
  bad "a failed unit is restarted" "exit $rc: $out"; fi
if grep -q 'reset-failed aperire-advisord' "$TMP/state/systemctl-calls"; then
  ok "because the failed state is cleared before the restart, not after it"
else
  bad "reset-failed is called" "$(cat "$TMP/state/systemctl-calls")"; fi

# And a restart this host refuses anyway. The removals are done by then, and
# an operator who asked for a reset must be told what state the box is in, not
# handed an empty screen because the run ended on the failing line.
seal_one
status_doc false false
: > "$TMP/state/failed"
: > "$TMP/state/refuse-restart"
out="$(run_reset)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q '^service=inactive$' <<<"$out" && grep -q '^exit=1$' <<<"$out"; then
  ok "a restart this host refuses is reported in full, and the run ends non-zero"
else
  bad "a refused restart is reported" "exit $rc: $out"; fi
if grep -q 'systemctl refused to restart' "$TMP/state/journal"; then
  ok "and the journal carries the refusal, with what was already removed"
else
  bad "the refused restart reaches the journal" "$(cat "$TMP/state/journal")"; fi
rm -f "$TMP/state/refuse-restart"

# A reset is not a seal and spends nothing. An operator who armed the host,
# reset it and then sealed from the browser would otherwise find the window
# gone for no reason they could see.
seal_one
arm_now
status_doc false false
run_reset >/dev/null
if [[ -f "$ARM" ]]; then
  ok "and a reset leaves an arming where it found it: it spends no window"
else
  bad "the reset keeps the arming" "the marker is gone"; fi


echo
echo "── the arm verb: a window opened by root on another host ──────────"

# The second payload shape: `arm`, a token, its signature. What makes it safe
# is not that the dashboard is trusted with the token (it is not, it only
# carries it) but that this program verifies a signature the dashboard cannot
# produce. The private half is root's, on the aggregator; this host holds only
# the public one, and only root can have put it there.
#
# Real openssl, and a throwaway key pair made here. A fake would be asserting
# that the test's idea of a signature matches the test's idea of a check.
# In a directory of their own: the installer's rows below write a fleet arm
# key into $TMP/etc, which is what --trust-arm-key does on a real host, and
# these must not be the same file by accident.
mkdir -p "$TMP/armkeys"
ARMKEY="$TMP/armkeys/fleet-arm.key"
OTHERKEY="$TMP/armkeys/other-arm.key"
ARMPUB="$TMP/armkeys/fleet-arm.pub"
ARMSEEN="$TMP/armkeys/fleet-arm.seen"
# This host's own node key, as the sealer's stamp and as every token's target.
# ONE value for the whole file: the chain rows at the end mint a real token
# from a real fleet.yaml row, and a second constant would be a second thing to
# keep in step. Real node keys, so the shape check in the sealer is exercised
# rather than worked around.
NODE_KEY=nHUeq2wYUj1JLTnSpiF9RxAF9mJqNn1oyXaLxL8CFmACpJvKuf9E
OTHER_NODE_KEY=nHBidGCa7NuWJVDeLZjBLoBSbxmvRcJmnAKAiQdZTgWkKKCAqTfM
NODE_KEY_STAMP="$TMP/armkeys/node-key"
openssl genpkey -algorithm ed25519 -out "$ARMKEY" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$OTHERKEY" 2>/dev/null
openssl pkey -in "$ARMKEY" -pubout -out "$ARMPUB" 2>/dev/null
chmod 0644 "$ARMPUB"

arm_token() { # $1 = nonce, $2 = issued_at, $3 = version (1), $4 = target
  printf 'v=%s\nissuer=lab-aggregator\ntarget=%s\nnonce=%s\nissued_at=%s\n' \
    "${3:-1}" "${4:-$NODE_KEY}" "$1" "$2" > "$TMP/arm-token"
}
# A token with no target line at all, which is a token for whoever receives it.
arm_token_untargeted() { # $1 = nonce, $2 = issued_at
  printf 'v=1\nissuer=lab-aggregator\nnonce=%s\nissued_at=%s\n' "$1" "$2" > "$TMP/arm-token"
}
# What install-model-key-sealer.sh writes on a real host: the node's own
# pubkey_node, root-owned, world-readable, and not writable by anyone else.
stamp_node_key() { # $1 = the key
  printf '%s\n' "$1" > "$NODE_KEY_STAMP"; chmod 0644 "$NODE_KEY_STAMP"
}
arm_payload() { # $1 = the key to sign the token with
  local sig
  sig="$(openssl pkeyutl -sign -inkey "$1" -rawin -in "$TMP/arm-token" 2>/dev/null | base64 -w0)"
  printf 'arm\n%s\n%s\n' "$(base64 -w0 < "$TMP/arm-token")" "$sig"
}
run_arm() { # stdin is the payload
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_CRED_DIR="$CREDS" \
      APERIRE_ARM_FILE="$ARM" \
      APERIRE_UNIT_DIR="$UNITS" \
      APERIRE_FLEET_ARM_PUB="$ARMPUB" \
      APERIRE_FLEET_ARM_SEEN="$ARMSEEN" \
      APERIRE_NODE_KEY_FILE="$NODE_KEY_STAMP" \
      bash "$SUT"
}
reset_arm() { reset_state; rm -f "$ARMSEEN"; stamp_node_key "$NODE_KEY"; }

reset_arm
NONCE="$(openssl rand -hex 16)"
arm_token "$NONCE" "$(date +%s)"
# Standard output ALONE, and asserted whole. The dashboard parses this stream
# as key=value lines, so a stray line from a tool (openssl announces a good
# signature on stdout) is not cosmetic: it is a field the reader never
# expected, arriving on the socket.
out="$(arm_payload "$ARMKEY" | run_arm 2>/dev/null)"; rc=$?
if [[ $rc -eq 0 && "$out" == $'armed=1\nwindow_s=900\nissuer=lab-aggregator\nexit=0' ]]; then
  ok "a signed arm token opens a window, and prints those four lines and nothing else"
else
  bad "a signed arm token arms" "exit $rc, stdout: $out"; fi
if [[ -f "$ARM" ]] \
   && grep -qF -- "-o root -g root -m 0600 /dev/null $ARM" "$TMP/state/install-calls"; then
  ok "and the marker it writes is the one --arm writes: root-owned, mode 0600"
else
  bad "the arm verb writes the same marker" "$(cat "$TMP/state/install-calls" 2>/dev/null)"; fi
if [[ "$(credential_count)" -eq 0 && ! -f "$TMP/state/creds-argv" ]]; then
  ok "and it never reaches the seal: no credential, and systemd-creds was not called at all"
else
  bad "arming seals nothing" "creds $(credential_count), argv $(cat "$TMP/state/creds-argv" 2>/dev/null)"; fi
# Who opened the window, beside the window. The seal one step later quotes it
# in the fact it leaves for the audit record, so a key landing on a node can
# name the aggregator that moved it (#447).
if [[ "$(cat "$ISSUER" 2>/dev/null)" == "lab-aggregator" ]] \
   && [[ "$(stat -c %a "$ISSUER" 2>/dev/null)" == "600" ]]; then
  ok "and the issuer is written beside the marker, readable by root alone"
else
  bad "the arm verb records its issuer" "$(ls -la "$ISSUER" 2>&1); $(cat "$ISSUER" 2>&1)"; fi
if grep -q '^armed:' "$TMP/state/journal" 2>/dev/null \
   && ! grep -qF -e "$(base64 -w0 < "$TMP/arm-token")" "$TMP/state/journal" \
   && ! grep -qF "nonce=$NONCE" "$TMP/state/journal"; then
  ok "the arming is on the record, and no journal line carries the token or its nonce"
else
  bad "the journal names the arming and not the token" "$(cat "$TMP/state/journal" 2>/dev/null)"; fi
if [[ "$(cat "$ARMSEEN")" =~ ^$NONCE\ [0-9]+$ ]]; then
  ok "and the nonce is remembered with its issue time, which is what makes the next row possible"
else
  bad "the nonce is remembered" "$(cat "$ARMSEEN" 2>/dev/null)"; fi

# The same token again, with the window deliberately closed first, so what is
# being asserted is that the token opens no SECOND window.
rm -f "$ARM"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'arm token already used' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "the same token a second time is refused, and opens no window"
else
  bad "a replayed arm token is refused" "exit $rc: $out"; fi

reset_arm
arm_token "$(openssl rand -hex 16)" "$(( $(date +%s) - 400 ))"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'arm token is stale' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a token minted 400s ago is stale, and opens no window"
else
  bad "a stale arm token is refused" "exit $rc: $out"; fi

reset_arm
arm_token "$(openssl rand -hex 16)" "$(date +%s)"
mv "$ARMPUB" "$TMP/armkeys/pub.away"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
mv "$TMP/armkeys/pub.away" "$ARMPUB"
if [[ $rc -ne 0 ]] && grep -q 'trusts no fleet arm key' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a host that was never given a fleet arm key refuses by name, not by signature"
else
  bad "no arm key is its own refusal" "exit $rc: $out"; fi

reset_arm
arm_token "$(openssl rand -hex 16)" "$(date +%s)"
out="$(arm_payload "$OTHERKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'not signed by the fleet arm key' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a token signed by a key this host does not trust is refused, and opens no window"
else
  bad "a bad signature is refused" "exit $rc: $out"; fi

# Same bytes, one field changed, so the signature is good and the version is
# not. A sealer that ignored the version would take a future token shape it
# does not understand.
reset_arm
arm_token "$(openssl rand -hex 16)" "$(date +%s)" 2
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q "version '2' is not 1" <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a correctly signed token of another version is refused by name"
else
  bad "an unknown token version is refused" "exit $rc: $out"; fi

reset_arm
printf 'arm\nnot base64 at all\nnor is this\n' | run_arm >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 && ! -f "$ARM" ]]; then
  ok "a token that is not base64 is refused before anything is written"
else
  bad "a malformed arm payload is refused" "exit $rc"; fi

# The seen file is bounded by age, not by count. A fleet arming every day for
# a year must not be a file that grows for ever, and a nonce still fresh
# enough to be accepted must never be the one pruned (#182).
reset_arm
now="$(date +%s)"
# 300 nonces still inside twice the skew, 55 too old to ever be accepted
# again, and one line in the old bare-nonce format.
awk -v now="$now" 'BEGIN{for(i=1;i<=300;i++) printf "%032x %d\n", i, now-100; for(i=301;i<=355;i++) printf "%032x %d\n", i, now-1000; printf "%032x\n", 999}' > "$ARMSEEN"
chmod 0600 "$ARMSEEN"
NONCE="$(openssl rand -hex 16)"
arm_token "$NONCE" "$now"
arm_payload "$ARMKEY" | run_arm >/dev/null 2>&1
if [[ "$(wc -l < "$ARMSEEN")" -eq 301 ]] && grep -qE "^$NONCE " "$ARMSEEN" \
   && grep -qE "^$(printf '%032x' 300) " "$ARMSEEN" && ! grep -qE "^$(printf '%032x' 301) " "$ARMSEEN" \
   && [[ "$(stat -c %a "$ARMSEEN")" == 600 ]]; then
  ok "the remembered nonces are pruned by age: 300 fresh kept plus the new one, 55 stale and one untimed dropped, still mode 0600"
else
  bad "the seen file is bounded by age" "$(wc -l < "$ARMSEEN") lines, mode $(stat -c %a "$ARMSEEN")"; fi

# A fresh nonce is remembered whatever the record's size: more than 200 live
# nonces used to push the oldest out while still replayable.
reset_arm
now="$(date +%s)"
awk -v now="$now" 'BEGIN{for(i=1;i<=250;i++) printf "%032x %d\n", i, now-10}' > "$ARMSEEN"
chmod 0600 "$ARMSEEN"
arm_token "$(printf '%032x' 1)" "$((now-10))"
if ! arm_payload "$ARMKEY" | run_arm >/dev/null 2>&1 && [[ ! -f "$ARM" ]]; then
  ok "the oldest of 250 live nonces is still refused as a replay"
else
  bad "a live nonce was pruned by count" "the replay was accepted"; fi

# ── who the token is for ──────────────────────────────────────────
#
# The property #184 is about. `target` is inside the bytes the aggregator
# signed, so nobody carrying a token can re-address one; what was missing was
# anybody on this side READING it. The dashboard read it, and the dashboard is
# the process this whole design says must not be able to arm.

reset_arm
arm_token "$(openssl rand -hex 16)" "$(date +%s)" 1 "$OTHER_NODE_KEY"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q "addressed to another node: it names $OTHER_NODE_KEY and this host is $NODE_KEY" <<<"$out" \
   && [[ ! -f "$ARM" ]]; then
  ok "a correctly signed token addressed to ANOTHER node is refused, naming both keys"
else
  bad "a token for another node is refused" "exit $rc: $out"; fi
if grep -q '^refused: that arm token is addressed to another node' "$TMP/state/journal" 2>/dev/null; then
  ok "and the refusal is in the journal, by name, on the host that refused it"
else
  bad "the mismatch reaches the journal" "$(cat "$TMP/state/journal" 2>/dev/null)"; fi
# Refused before the nonce record is touched: a token that was never for this
# host must not be able to fill the file that stops replays.
if [[ ! -s "$ARMSEEN" ]]; then
  ok "and it spends no nonce, because a token for somebody else costs this host nothing"
else
  bad "a foreign token spends no nonce" "$(cat "$ARMSEEN")"; fi

# A token with no address is a token for whoever receives it, which is what a
# fleet of couriers would turn into a token for whoever asks first.
reset_arm
arm_token_untargeted "$(openssl rand -hex 16)" "$(date +%s)"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'names no target' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a signed token that names no target at all is refused, and opens no window"
else
  bad "an unaddressed token is refused" "exit $rc: $out"; fi

# The row that makes the two above mean something.
reset_arm
arm_token "$(openssl rand -hex 16)" "$(date +%s)" 1 "$NODE_KEY"
out="$(arm_payload "$ARMKEY" | run_arm 2>/dev/null)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^armed=1$' <<<"$out" && [[ -f "$ARM" ]]; then
  ok "and a token addressed to THIS host's stamped key still opens a window"
else
  bad "a token for this host arms" "exit $rc: $out"; fi

# Fail closed. A host that cannot say what it is cannot say a token is for it,
# and the refusal names the command that fixes it rather than the signature.
reset_arm
rm -f "$NODE_KEY_STAMP"
arm_token "$(openssl rand -hex 16)" "$(date +%s)"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'has not stamped its own node key' <<<"$out" \
   && grep -q -- '--refresh-node-key' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a host that never stamped its own node key refuses every token, and says how to fix it"
else
  bad "no stamp is a refusal by name" "exit $rc: $out"; fi

# The same two stats the fleet arm key gets, for the same reason: whoever may
# write this file re-addresses every token this host is sent.
reset_arm
chmod 0666 "$NODE_KEY_STAMP"
arm_token "$(openssl rand -hex 16)" "$(date +%s)"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'is mode 666' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "a stamped node key others may write is refused, because writing it re-addresses every token"
else
  bad "a world-writable stamp is refused" "exit $rc: $out"; fi

reset_arm
printf 'not a node key\n' > "$NODE_KEY_STAMP"; chmod 0644 "$NODE_KEY_STAMP"
arm_token "$(openssl rand -hex 16)" "$(date +%s)"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'does not hold a node key' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "and a stamp that is not a node key is its own refusal, not a mismatch"
else
  bad "a malformed stamp is refused" "exit $rc: $out"; fi

# ---- where a key came from, for the record ------------------------
#
# Last in this section because each row below spends a window. A seal under
# an arming an aggregator opened names that aggregator; a seal under an
# arming this host opened names nobody; and the naming file never outlives
# the window it belongs to (#447).
reset_arm
arm_token "$(openssl rand -hex 16)" "$(date +%s)"
arm_payload "$ARMKEY" | run_arm >/dev/null 2>&1
payload | run_seal >/dev/null 2>&1
if python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
assert c["via"]=="fleet-push", c
assert c["issuer"]=="lab-aggregator", c
assert c["credential_name"]=="model-api-key-xai", c
' "$ADVSTATE/model-change.json" 2>/dev/null; then
  ok "a seal under an aggregator's window records that the key arrived by push, and from whom"
else
  bad "a fleet seal names its issuer" "$(cat "$ADVSTATE/model-change.json" 2>&1)"; fi
if [[ ! -e "$ISSUER" ]]; then
  ok "and the issuer goes when the window is spent, so no later seal can claim it"
else
  bad "the issuer is spent with the window" "$(cat "$ISSUER")"; fi

reset_arm
arm_aged 1000
printf 'lab-aggregator\n' > "$ISSUER"
chmod 0600 "$ISSUER"
payload | run_seal >/dev/null 2>&1
if [[ ! -e "$ISSUER" ]]; then
  ok "an arming that lapsed takes its issuer with it, so no later seal can name it either"
else
  bad "an expired window clears the issuer" "$(cat "$ISSUER")"; fi

# A third program writes this marker: aperire-fleet-arm.sh arms this host
# locally. So an issuer from a window that lapsed with no seal attempted can
# still be sitting there when a LOCAL arming opens the next one, and without
# the age check that local seal would be recorded as a push from an
# aggregator that armed nothing.
reset_arm
printf 'lab-aggregator\n' > "$ISSUER"
chmod 0600 "$ISSUER"
touch -d "@$(( $(date +%s) - 1200 ))" "$ISSUER"
arm_now
payload | run_seal >/dev/null 2>&1
if python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
assert c["via"]=="seal", c
assert "issuer" not in c, c
' "$ADVSTATE/model-change.json" 2>/dev/null; then
  ok "an issuer older than the marker beside it is not believed: a local arming stays a local seal"
else
  bad "a stale issuer is not quoted" "$(cat "$ADVSTATE/model-change.json" 2>&1)"; fi

reset_arm
arm_now
payload | run_seal >/dev/null 2>&1
if python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
assert c["via"]=="seal", c
assert "issuer" not in c, c
' "$ADVSTATE/model-change.json" 2>/dev/null; then
  ok "and a seal under a window this host opened itself names no issuer at all"
else
  bad "a local seal claims no issuer" "$(cat "$ADVSTATE/model-change.json" 2>&1)"; fi

echo
echo "── the grant that lets the dashboard reach it ─────────────────────"

# scripts/install-model-key-sealer.sh writes the socket the dashboard reaches
# this through, and the unit behind it. Same treatment as the sealer: the root
# guard is removed in a scratch copy, and asserted against the original.
# `install -o root` and `systemctl` are faked, because this account cannot
# chown to root or talk to systemd, and the interesting part is what they were
# asked to do. The socket itself is real: a unix socket this account owns, so
# the installer's own ownership check runs for real against a real file.
# ── the node, answering for itself ─────────────────────────────────
#
# The installer asks THIS host's node who it is, over the loopback admin RPC
# that /etc/aperire/node-wrapper.conf names, and stamps the answer. A real
# HTTP stub rather than a fake curl: the shape it answers with is rippled's
# own (pretty-printed, `result.info.pubkey_node`), and the parsing that reads
# it is the thing under test. The key it reports is read per request from a
# file, so a row can change what the node says without a restart.
cat > "$TMP/rpcstub.py" <<'PYEOF'
import http.server, json, sys
portfile, keyfile = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get('content-length', 0) or 0))
        key = open(keyfile).read().strip()
        info = {"build_version": "3.3.0", "server_state": "proposing"}
        if key:
            info["pubkey_node"] = key
        b = json.dumps({"result": {"info": info, "status": "success"}}, indent=3).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
open(portfile, 'w').write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
RPC_KEYFILE="$TMP/rpc-key"
printf '%s\n' "$NODE_KEY" > "$RPC_KEYFILE"
rm -f "$TMP/rpc-port"
python3 "$TMP/rpcstub.py" "$TMP/rpc-port" "$RPC_KEYFILE" &
RPC_PID=$!
for _ in $(seq 1 50); do
  [[ -s "$TMP/rpc-port" ]] && break
  sleep 0.3
done
if [[ -s "$TMP/rpc-port" ]]; then
  ok "the stub node is answering server_info, so the stamping rows below are about the installer"
else
  bad "the stub node comes up" "no port file after 15s; the stamping rows cannot mean anything"
fi
RPC_PORT="$(cat "$TMP/rpc-port" 2>/dev/null || echo 0)"
# A port nothing is listening on, for the host whose node is stopped. Port 1
# on loopback: privileged, unbound, and curl fails on it at once.
RPC_DEAD=http://127.0.0.1:1

INST_ORIG="$REPO_DIR/scripts/install-model-key-sealer.sh"
# shellcheck disable=SC2016  # a literal to grep for, not an expression to run
IGUARD='[[ $EUID -eq 0 ]] || die "run with sudo: this installs a program as root and two systemd units"'
# In a scripts/ directory beside a copy of the sealer, because the installer
# resolves both out of its own location, exactly as it does in a real tree.
mkdir -p "$TMP/tree/scripts"
INST="$TMP/tree/scripts/install-model-key-sealer.sh"
grep -vxF -e "$IGUARD" "$INST_ORIG" > "$INST"
cp "$ORIG" "$TMP/tree/scripts/aperire-seal-model-key.sh"
# The helper ships with the sealer and the installer places it beside it
# (#703), so the fake tree carries it too. Without this the installer refuses,
# which is the right refusal and the wrong test.
cp "$REPO_DIR/scripts/state-file.py" "$TMP/tree/scripts/state-file.py"
# And the method library, for the same reason (#708): the installer places it
# beside the sealer and refuses a tree without it.
cp "$REPO_DIR/scripts/model-key-method-lib.sh" "$TMP/tree/scripts/model-key-method-lib.sh"
# The installer's root copies go through this (ADR 0024); the fixture has no
# release digests of its own unless a row writes some, so they fall back.
cp "$REPO_DIR/scripts/release-digests-lib.sh" "$TMP/tree/scripts/release-digests-lib.sh"
cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/tree/scripts/trusted-path-lib.sh"
# What the installed copy is compared against, by bytes: the release's own.
TREE_STATE_TOOL="$TMP/tree/scripts/state-file.py"
TREE_SRC="$TMP/tree/scripts/aperire-seal-model-key.sh"  # what the installer copies from

if grep -qxF -e "$IGUARD" "$INST_ORIG"; then
  ok "the grant installer refuses to run as anything but root"
else
  bad "the installer's root guard is there" "the line these tests remove is gone"; fi

cat > "$TMP/bin/getent" <<EOF
#!/usr/bin/env bash
[[ "\$2" == nosuchuser ]] && exit 2
printf '%s:x:1000:1000::/home/x:/bin/bash\n' "\$2"
EOF
# The installer's last check runs as the dashboard account, through runuser,
# which only root may call. Here it is this account already, so the fake runs
# the command as is; and it can be told to refuse, which stands in for the
# directory the account cannot traverse (#171).
cat > "$TMP/bin/runuser" <<EOF
#!/usr/bin/env bash
[[ -e "$TMP/state/unreachable" ]] && exit 1
while [[ \$# -gt 0 ]]; do case "\$1" in -u) shift 2 ;; --) shift; break ;; *) shift ;; esac; done
exec "\$@"
EOF
chmod +x "$TMP/bin/getent" "$TMP/bin/runuser"

SEALER_DEST="$TMP/sbin/aperire-seal-model-key"
# Where --trust-arm-key puts a key on this "host": $ETC, as on a real one.
TRUSTED_PUB="$TMP/etc/fleet-arm.pub"
TRUSTED_SEEN="$TMP/etc/fleet-arm.seen"
# And where the stamped node key and the wrapper's record of the node live,
# both under the same $ETC for the same reason.
TRUSTED_NODE_KEY="$TMP/etc/node-key"
WCONF_T="$TMP/etc/node-wrapper.conf"
# What install-node-wrapper.sh leaves behind, reduced to the two lines this
# reads: which node is here, and where to ask it.
write_wconf() { # $1 = the admin RPC address, $2 = the service (xrpld unless given)
  mkdir -p "$TMP/etc"
  printf 'SERVICE=%s\nADMIN_RPC=%s\n' "${2:-xrpld}" "$1" > "$WCONF_T"
}
# Exactly what install-node-wrapper.sh --no-node writes on an aggregator: no
# node, and an admin RPC on a port nothing listens on.
write_wconf_nonode() { write_wconf http://127.0.0.1:0 none; }
# The shape this grant used to take, and cannot use: sudo does not run inside
# the dashboard's unit at all. Left here as a file the installer has to take
# away on a host that carries one.
LEGACY_SUDOERS="$TMP/etc/sudoers.d-aperire-model-key"
SOCKET="$TMP/run/seal-model-key.sock"
SOCKET_UNIT="$UNITS/aperire-seal-model-key.socket"
SERVICE_UNIT="$UNITS/aperire-seal-model-key@.service"
ME="$(id -un)"
mkdir -p "$TMP/sbin" "$TMP/run"

# A real AF_UNIX socket, bound and left on disk, owned by this account and mode
# 0600. The installer's last check reads its owner and mode with stat, and a
# regular file standing in for it would not be the thing being checked.
make_socket() {
  rm -f "$SOCKET"
  python3 -c 'import os, socket, sys
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX)
s.bind(p)
s.listen(1)
os.chmod(p, 0o600)' "$SOCKET"
}

run_install() {
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_SEALER_PATH="$SEALER_DEST" \
      APERIRE_SEALER_SUDOERS="$LEGACY_SUDOERS" \
      APERIRE_SEAL_SOCKET="$SOCKET" \
      APERIRE_ETC="$TMP/etc" \
      APERIRE_UNIT_DIR="$UNITS" \
      APERIRE_RELEASE_DIGESTS="${DIGESTS_FOR_RUN:-$TMP/no-digests/release.sha256}" \
      bash "$INST" "$@" 2>&1
}

# Where the installer puts the state helper: beside the sealer, which on a
# real host is /usr/local/sbin and here is wherever SEALER_DEST points (#703).
STATE_TOOL_DEST="${SEALER_DEST%/*}/aperire-state-file"
METHOD_LIB_DEST="${SEALER_DEST%/*}/aperire-model-key-method"
CREDCHECK_DEST="${SEALER_DEST%/*}/aperire-advisord-credcheck"

reset_install() { # $1 = the account the dashboard unit names, this one by default
  rm -f "$TMP/state/"* "$LEGACY_SUDOERS" "$SEALER_DEST" "$ARM" "$SOCKET_UNIT" "$SERVICE_UNIT"
  rm -f "$STATE_TOOL_DEST" "$METHOD_LIB_DEST" "$CREDCHECK_DEST"
  rm -f "$TRUSTED_PUB" "$TRUSTED_SEEN" "$TRUSTED_NODE_KEY" "$TMP/etc/fleet-arm.paired.pub"
  # The trust directory's mode, stated rather than left to this runner's
  # umask: --trust-arm-key keeps the held copy in step through a directory
  # it checks on a descriptor, and refuses one that group may write.
  chmod 0755 "$TMP/etc"
  printf '%s\n' "$NODE_KEY" > "$RPC_KEYFILE"
  write_wconf "http://127.0.0.1:$RPC_PORT"
  printf '[Unit]\n\n[Service]\nUser=%s\nExecStart=/bin/true\n' "${1:-$ME}" > "$UNITS/aperire-server.service"
  printf '[Unit]\n\n[Service]\nExecStart=/bin/true\n' > "$UNITFILE"
  # The socket unit comes up, and the socket is there: the successful host.
  : > "$TMP/state/active"
  make_socket
}

reset_install
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]]; then ok "the grant installs"
else bad "the grant installs" "exit $rc: $out"; fi

# ── the state helper travels with the sealer (#703) ────────────────
#
# The sealer runs from /usr/local/sbin with no tree beside it and writes
# every file it puts under advisor/state through scripts/state-file.py. So
# the helper has to be there too, and it has to be THIS release's copy: the
# drift #185 is about is a current source and a stale installed program, met
# live twice, and a helper one release behind is the same failure in a new
# place. These rows compare bytes, not timestamps, and they compare against
# the release rather than against whatever happens to be on the host.
if [[ -f "$STATE_TOOL_DEST" ]]; then
  ok "the install places the state helper beside the sealer"
else
  bad "the state helper is installed beside the sealer" "nothing at $STATE_TOOL_DEST"
fi
if cmp -s "$TREE_STATE_TOOL" "$STATE_TOOL_DEST"; then
  ok "and the installed copy is byte for byte the release's own"
else
  bad "the installed helper matches the release" \
      "$(md5sum "$TREE_STATE_TOOL" "$STATE_TOOL_DEST" 2>&1 | tr '\n' ' ')"
fi
# root:root 0755, asserted on the install call rather than on the file's mode:
# `install` here is the suite's own fake, which records what it was asked for
# and does not apply it. Root copies no longer go through it (ADR 0024): the
# mode is set on the staged file itself, so it is read off the disk.
if asked_root 0755 "$STATE_TOOL_DEST"; then
  ok "as root:root 0755, which is what a root program beside the sealer has to be"
else
  bad "the helper is installed root:root 0755" \
      "$(stat -c '%a %F' "$STATE_TOOL_DEST" 2>&1)"
fi

# A stale helper is replaced on a re-run, the way the sealer itself is.
printf 'the PREVIOUS release helper\n' > "$STATE_TOOL_DEST"
out="$(run_install)"
if cmp -s "$TREE_STATE_TOOL" "$STATE_TOOL_DEST"; then
  ok "a helper left behind by an older release is replaced on the next install"
else
  bad "a stale helper is refreshed" "it is still the previous release's copy"
fi

# --remove: the helper is shared with the credential check, so it goes only
# when nothing is left that needs it. A removal that took it while credcheck
# was still installed would leave that program unable to write the one note
# it exists to write, on the run where a credential has just gone.
: > "$CREDCHECK_DEST"
out="$(run_install --remove)"
if [[ -f "$STATE_TOOL_DEST" ]] && grep -q "still uses it" <<<"$out"; then
  ok "--remove leaves the helper while the credential check is still installed, and says so"
else
  bad "--remove keeps the helper for the credential check" \
      "$([[ -f "$STATE_TOOL_DEST" ]] && echo present || echo gone): $out"
fi
rm -f "$CREDCHECK_DEST"
reset_install
out="$(run_install)"
rm -f "$CREDCHECK_DEST"
out="$(run_install --remove)"
if [[ ! -f "$STATE_TOOL_DEST" ]] && grep -q "removed $STATE_TOOL_DEST" <<<"$out"; then
  ok "and takes it once nothing else on the host uses it"
else
  bad "--remove takes the helper when credcheck is gone" \
      "$([[ -f "$STATE_TOOL_DEST" ]] && echo present || echo gone): $out"
fi

reset_install
out="$(run_install)"

# The socket's directory is shared with the node wrapper, which made it 0750
# on aperire1 before this grant was installed; DirectoryMode= in the unit
# never touches a directory that already exists. So the installer sets the
# mode itself, every run, and then checks the socket AS the dashboard account
# rather than as root, who can see through any directory (#171).
if grep -qF -- "-d -m 0755 -o root -g root $(dirname "$SOCKET")" "$TMP/state/install-calls" \
   && grep -q "reachable as $ME" <<<"$out"; then
  ok "the socket's directory is made 0755 on every run, and the socket is checked as the dashboard account"
else
  bad "the socket directory mode is set and checked" "$(grep -- '-d ' "$TMP/state/install-calls" 2>/dev/null) / $out"; fi

# ── a credential directive with nothing behind it ──────────────────
#
# The uninstall takes /etc/aperire/creds away and leaves the drop-in, so the
# next Advisor installed here would declare a credential that is not on the
# host and fail to start at all, 243/CREDENTIALS, with the restart counter
# climbing and nothing saying why (#446). The install is the run before that
# start, so it is the run that checks.
reset_install
mkdir -p "$UNITFILE.d"
printf '[Service]\nLoadCredentialEncrypted=model-api-key-xai:%s/model-api-key-xai\n' "$CREDS" > "$DROPIN"
rm -f "$CREDS/model-api-key-xai"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -e "$DROPIN" ]]; then
  ok "a drop-in loading a credential that is not on this host is removed at install"
else
  bad "a stale drop-in is removed" "exit $rc: $(cat "$DROPIN" 2>&1)"; fi
if grep -q 'which is not on this host' <<<"$out" && grep -q 'comes back with it' <<<"$out"; then
  ok "and the run says what it removed, and how to get the key back"
else
  bad "the removal is explained" "$out"; fi

# The same state on a host that cannot seal (#712 review L2), which is the
# one this check used to walk past: its key is declared with LoadCredential=,
# so a repair that matched only the encrypted spelling left the unit refusing
# to start with nothing on the run that could say why.
reset_install
mkdir -p "$UNITFILE.d"
printf '[Service]\nLoadCredential=model-api-key-xai:%s/model-api-key-xai.plain\n' "$CREDS" > "$DROPIN"
rm -f "$CREDS/model-api-key-xai.plain"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -e "$DROPIN" ]]; then
  ok "a drop-in loading a plaintext key that is not on this host is removed too"
else
  bad "a stale plain drop-in is removed" "exit $rc: $(cat "$DROPIN" 2>&1)"; fi
if grep -q 'model-api-key-xai.plain, which is not on this host' <<<"$out"; then
  ok "and the run names the file it was loading"
else
  bad "the plain removal names the file" "$out"; fi

# And the one that must NOT be touched: a host with a key sealed and working.
reset_install
mkdir -p "$UNITFILE.d"
printf 'SEALED(model-api-key-xai)\n' > "$CREDS/model-api-key-xai"
printf '[Service]\nLoadCredentialEncrypted=model-api-key-xai:%s/model-api-key-xai\n' "$CREDS" > "$DROPIN"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && -f "$DROPIN" ]]; then
  ok "and a drop-in whose credential is right there is left exactly as it was"
else
  bad "a live drop-in survives an install" "exit $rc: $out"; fi
rm -f "$CREDS/model-api-key-xai"
rm -rf "$UNITFILE.d"

# --arm opens a window belonging to THIS host. An issuer left beside the
# marker belongs to an aggregator's window from earlier, and a seal made
# under this one must not be recorded as having come from there (#447).
reset_install
printf 'koi\n' > "$ISSUER"
chmod 0600 "$ISSUER"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && -f "$ARM" && ! -e "$ISSUER" ]]; then
  ok "--arm opens a window of this host's own, and clears any issuer left from another"
else
  bad "--arm clears a stale issuer" "exit $rc: $(cat "$ISSUER" 2>&1)"; fi

# ── the stamp: this host's own node key ────────────────────────────
#
# Read from the node itself, over the loopback admin RPC the wrapper's conf
# names, and written beside the fleet arm key. Without it the sealer cannot
# tell a token addressed here from one addressed to the machine next door.

reset_install
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]] \
   && grep -qF -- "-o root -g root -m 0644" <<<"$(grep -F -e "$TRUSTED_NODE_KEY" "$TMP/state/install-calls")"; then
  ok "the install asks the node who it is and stamps the answer, root-owned and world-readable"
else
  bad "the node key is stamped from the node's own answer" "exit $rc: $(cat "$TRUSTED_NODE_KEY" 2>/dev/null) / $out"; fi
if grep -qF -e "$NODE_KEY" <<<"$out" && grep -q 'refused here' <<<"$out"; then
  ok "and it prints the key it stamped, and what that now means for a token addressed elsewhere"
else
  bad "the stamp is printed" "$out"; fi

# A node that is stopped at install time. Not fatal: the seal path and --arm
# do not need this, and a grant that refused to install because a node was
# down would trade a working local ceremony for a fleet feature this host may
# never use. It must say so, and name both ways to fix it.
reset_install
write_wconf "$RPC_DEAD"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -f "$TRUSTED_NODE_KEY" ]] \
   && grep -q 'not stamped: the node did not answer' <<<"$out" \
   && grep -q -- '--refresh-node-key' <<<"$out" && grep -q -- '--node-key' <<<"$out"; then
  ok "a node that is down leaves the grant installed and the key unstamped, saying so and naming both fixes"
else
  bad "a down node does not fail the install" "exit $rc: $out"; fi

# No wrapper conf at all: a host where the Advisor was never installed.
reset_install
rm -f "$WCONF_T"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -f "$TRUSTED_NODE_KEY" ]] && grep -q 'no admin RPC address to ask' <<<"$out"; then
  ok "and a host with no record of where its node is says that, rather than guessing a port"
else
  bad "no admin RPC address is named" "exit $rc: $out"; fi

# A stamp from an earlier run is still on disk and this run cannot ask the node
# (#935): the old text said "not stamped ... arm tokens are refused" over a
# stamp it had not touched. Kept, said as kept, with the key it kept, and the
# fix offered in case the key has changed. The stamp is the old one, byte for
# byte, and the hint is the bootstrap's flag, never sudo on a tree script.
reset_install
rm -f "$WCONF_T"
printf '%s\n' "$OTHER_NODE_KEY" > "$TRUSTED_NODE_KEY"
before_stamp="$(cat "$TRUSTED_NODE_KEY")"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY")" == "$before_stamp" ]] \
   && ! grep -q 'not stamped' <<<"$out" && ! grep -q 'tokens are refused until' <<<"$out" \
   && grep -q 'kept:' <<<"$out" && grep -qF -e "$OTHER_NODE_KEY" <<<"$out"; then
  ok "a stamp that stays when the node cannot be asked is said to be kept, with its key, and not called unstamped"
else
  bad "a kept stamp is not reported as missing" "exit $rc: $out"; fi
# Honoured only as far as it is true: with no fleet arm key trusted here, the
# program refuses every token (no $FLEET_ARM_PUB), so this host is not told
# otherwise.
if ! grep -q 'honoured' <<<"$out" && grep -q 'trusts no fleet arm key yet' <<<"$out" \
   && grep -q 'refused until it is paired' <<<"$out"; then
  ok "  and with no fleet arm key trusted it says tokens are refused until the host is paired, not that they are honoured"
else
  bad "a kept stamp does not promise tokens it would refuse" "$out"; fi
# And with a trust root the sealer would accept, it is honoured, with the owner
# and mode read off the file rather than assumed: a 0640 stamp prints 640.
reset_install
rm -f "$WCONF_T"
printf '%s\n' "$OTHER_NODE_KEY" > "$TRUSTED_NODE_KEY"; chmod 0640 "$TRUSTED_NODE_KEY"
printf 'pem\n' > "$TRUSTED_PUB"; chmod 0644 "$TRUSTED_PUB"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'still honoured' <<<"$out" && ! grep -q 'refused until it is paired' <<<"$out" \
   && grep -qF "($(stat -c '%U:%G' "$TRUSTED_NODE_KEY") 640)" <<<"$out"; then
  ok "  with a fleet arm key the sealer would trust, tokens for the kept key are said to be honoured, and the stamp's real owner and mode are shown"
else
  bad "a kept stamp with a trust root is honoured" "exit $rc: $out"; fi
chmod 0666 "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'will not trust a file with that owner or mode' <<<"$out" && grep -q ' 666)' <<<"$out" \
   && ! grep -q 'still honoured' <<<"$out" && grep -q 'refused until the stamp is written again' <<<"$out"; then
  ok "  and a stamp the sealer would refuse (mode 666) is not described as sound, nor its tokens as honoured, even beside a trusted arm key"
else
  bad "a bad-mode stamp is named" "exit $rc: $out"; fi
# A stamp that is a link reads as mode 777 and is refused the same way.
rm -f "$TRUSTED_NODE_KEY"; printf '%s\n' "$OTHER_NODE_KEY" > "$TMP/stamp-target"; chmod 0644 "$TMP/stamp-target"
ln -s "$TMP/stamp-target" "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'will not trust a file with that owner or mode' <<<"$out" && grep -q ' 777)' <<<"$out" \
   && ! grep -q 'still honoured' <<<"$out" && grep -q 'refused until the stamp is written again' <<<"$out"; then
  ok "  and a stamp that is a symlink is treated the same way"
else
  bad "a symlinked stamp is not honoured" "exit $rc: $out"; fi
rm -f "$TRUSTED_NODE_KEY" "$TMP/stamp-target"
# The success branch (#935): the wrapper is repaired first now, so a stamp that
# held another key is re-addressed by a write that used to be skipped. It says
# so, with the old key and where to update the aggregator.
reset_install
printf '%s\n' "$OTHER_NODE_KEY" > "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY")" == "$NODE_KEY" ]] \
   && grep -qF "it was $OTHER_NODE_KEY" <<<"$out" && grep -q 'expected_pubkey_node' <<<"$out" \
   && ! grep -q 'addressed to any other node is refused here' <<<"$out"; then
  ok "an install that finds a stamp holding a different key names the old key and the aggregator's expected_pubkey_node"
else
  bad "a re-addressed stamp is said so" "exit $rc: $out"; fi
reset_install
printf '%s\n' "$NODE_KEY" > "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]] && ! grep -q '^ *it was n' <<<"$out" && grep -q 'addressed to any other node is refused here' <<<"$out"; then
  ok "  and an unchanged key says nothing about a change"
else
  bad "an unchanged stamp is quiet" "exit $rc: $out"; fi
reset_install
rm -f "$WCONF_T"
printf '%s\n' "$OTHER_NODE_KEY" > "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if grep -q 'bash -s -- --refresh-node-key' <<<"$out" && grep -q 'https://get.aperire.one' <<<"$out" \
   && ! grep -q 'sudo bash' <<<"$out"; then
  ok "  and the way to stamp it again is the bootstrap's flag, not sudo on a script in the tree"
else
  bad "the kept-stamp hint is a root-owned form" "$out"; fi
reset_install
rm -f "$WCONF_T" "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'not stamped: no admin RPC address to ask' <<<"$out" \
   && ! grep -q 'kept:' <<<"$out" && grep -q 'tokens are refused until' <<<"$out" \
   && grep -q 'bash -s -- --refresh-node-key' <<<"$out" && grep -q 'bash -s -- --refresh-node-key --node-key <pubkey_node>' <<<"$out" \
   && ! grep -q 'sudo bash' <<<"$out"; then
  ok "a host with no stamp still says not stamped, that arm tokens are refused, and names both fixes by the bootstrap"
else
  bad "no stamp still reads as not stamped" "exit $rc: $out"; fi
# The stamp file is there but is not a key: that is not a stamp to keep.
reset_install
rm -f "$WCONF_T"
printf 'garbage\n' > "$TRUSTED_NODE_KEY"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'not stamped:' <<<"$out" && ! grep -q 'kept:' <<<"$out"; then
  ok "  and a stamp file that does not hold a key is not called kept"
else
  bad "a malformed stamp is not kept" "exit $rc: $out"; fi
# --help prints the script's leading comment, so a hint there is a hint an
# operator reads: the refresh line in it is the bootstrap's flag too.
help_out="$(bash "$INST" --help 2>&1)"
if grep -q -- '--refresh-node-key' <<<"$help_out" \
   && ! grep -- '--refresh-node-key' <<<"$help_out" | grep -q 'sudo' \
   && grep -- '--refresh-node-key' <<<"$help_out" | grep -q 'get.aperire.one'; then
  ok "  and the sealer's --help gives the bootstrap's flag, not sudo on the script"
else
  bad "--help names the root-owned form" "$(grep -n -- 'refresh-node-key' <<<"$help_out")"
fi
# The hint names the tree when it is not the owner's default, and leaves it
# off when it is. The function is cut out of the installer and run with a
# fake getent, so the default case needs no home directory of the runner's.
mkdir -p "$TMP/nkhome/bin" "$TMP/nkhome/op/aperire-one"
printf '#!/bin/sh\necho "op:x:1000:1000::%s:/bin/bash"\n' "$TMP/nkhome/op" > "$TMP/nkhome/bin/getent"
chmod +x "$TMP/nkhome/bin/getent"
sed -n '/^refresh_node_key_line() {/,/^}/p' "$INST" > "$TMP/nkhome/fn.sh"
dflt="$(PATH="$TMP/nkhome/bin:$PATH" REPO="$TMP/nkhome/op/aperire-one" bash -c '. "$1"; refresh_node_key_line' x "$TMP/nkhome/fn.sh")"
odd="$(PATH="$TMP/nkhome/bin:$PATH" REPO="$TMP/nkhome/op/odd tree" bash -c '. "$1"; refresh_node_key_line "--node-key <pubkey_node>"' x "$TMP/nkhome/fn.sh")"
if [[ "$dflt" == "curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key" ]] \
   && [[ "$odd" == "curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key --node-key <pubkey_node> --dir $(printf '%q' "$TMP/nkhome/op/odd tree")" ]]; then
  ok "  the hint names a tree that is not the default, shell-quoted, and says nothing of one that is"
else
  bad "the hint's --dir" "default=[$dflt] odd=[$odd]"; fi

# The node answering, but not with a name yet: a node still starting reports
# no pubkey_node at all. A stamp of the empty string would be a stamp that
# matches nothing and reads as installed.
reset_install
: > "$RPC_KEYFILE"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -f "$TRUSTED_NODE_KEY" ]] && grep -q 'reported no pubkey_node' <<<"$out"; then
  ok "a node that answers without a key yet is not stamped, and the reason says which of the two it was"
else
  bad "an answer with no key is not stamped" "exit $rc: $out"; fi

# What the operator states wins, and is the answer for a host whose node is
# down. Checked for shape first: a stamp is what every arm token is compared
# with, and one that could never match anything is worse than none.
reset_install
write_wconf "$RPC_DEAD"
out="$(run_install --node-key "$OTHER_NODE_KEY")"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$OTHER_NODE_KEY" ]]; then
  ok "--node-key stamps what the operator states, on a host whose node cannot be asked"
else
  bad "--node-key overrides the read" "exit $rc: $out"; fi

reset_install
out="$(run_install --node-key "not-a-node-key")"; rc=$?
if [[ $rc -ne 0 && ! -f "$TRUSTED_NODE_KEY" ]] && grep -q 'not shaped like a node key' <<<"$out"; then
  ok "and a --node-key that is not one is refused before anything is written"
else
  bad "a malformed --node-key is refused" "exit $rc: $out"; fi

# An aggregator. Nothing is wrong with it, and a run that printed four lines
# about starting a node would be describing a host that has none. It is armed
# by its own marker and is never sent a token, so it needs no stamp at all.
reset_install
write_wconf_nonode
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -f "$TRUSTED_NODE_KEY" ]] \
   && grep -q 'runs no node' <<<"$out" \
   && ! grep -q -- '--refresh-node-key' <<<"$out"; then
  ok "a host that runs no node says so in one line, with no advice about starting one"
else
  bad "an aggregator is not told to start a node" "exit $rc: $out"; fi

# The override still reaches a host whose conf describes it wrongly.
reset_install
write_wconf_nonode
out="$(run_install --node-key "$NODE_KEY")"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]]; then
  ok "and --node-key stamps one anyway, for a host whose conf says none and does run one"
else
  bad "--node-key wins over SERVICE=none" "exit $rc: $out"; fi

reset_install
: > "$TMP/state/unreachable"
out="$(run_install)"; rc=$?
rm -f "$TMP/state/unreachable"
if [[ $rc -ne 0 ]] && grep -q "cannot reach it" <<<"$out"; then
  ok "a socket the dashboard account cannot reach fails the install, and says which directory to look at"
else
  bad "an unreachable socket is refused" "exit $rc: $out"; fi

# The socket IS the grant. Every line of it is doing something: one path, one
# account, a mode nobody else can open, and one connection at a time.
if grep -qxF "ListenStream=$SOCKET" "$SOCKET_UNIT" 2>/dev/null \
   && grep -qxF "SocketUser=$ME" "$SOCKET_UNIT" \
   && grep -qxF "SocketGroup=$ME" "$SOCKET_UNIT" \
   && grep -qxF 'SocketMode=0600' "$SOCKET_UNIT" \
   && grep -qxF 'Accept=yes' "$SOCKET_UNIT" \
   && grep -qxF 'MaxConnections=1' "$SOCKET_UNIT"; then
  ok "the socket is one path, owned by the dashboard account, mode 0600, one connection at a time"
else
  bad "the socket unit is exact" "$(grep -v '^#' "$SOCKET_UNIT" 2>/dev/null | tr '\n' ' ')"; fi

if grep -qxF 'WantedBy=sockets.target' "$SOCKET_UNIT" 2>/dev/null; then
  ok "and it is wanted by sockets.target, so it is listening after a reboot"
else
  bad "the socket is enabled at boot" "$(grep -v '^#' "$SOCKET_UNIT" 2>/dev/null | tr '\n' ' ')"; fi

# The program behind it, with the connection as its three streams and no
# arguments after the path. A unit that named an argument would be the same
# hole the sudoers rule's trailing '""' was closing.
if grep -qxF "ExecStart=$SEALER_DEST" "$SERVICE_UNIT" 2>/dev/null \
   && grep -qxF 'StandardInput=socket' "$SERVICE_UNIT" \
   && grep -qxF 'StandardOutput=socket' "$SERVICE_UNIT" \
   && grep -qxF 'StandardError=socket' "$SERVICE_UNIT"; then
  ok "one program is behind it, with no arguments, and the connection as its three streams"
else
  bad "the service unit is exact" "$(grep -v '^#' "$SERVICE_UNIT" 2>/dev/null | tr '\n' ' ')"; fi

# A refusal exits 1 and is an outcome the sealer has already reported. Without
# this line every refused attempt stayed in `systemctl --failed` on the lab
# box, which is what the verifier reads as a broken host.
if grep -qxF 'SuccessExitStatus=1' "$SERVICE_UNIT" 2>/dev/null; then
  ok "a refusal (exit 1) is not left behind as a failed unit"
else
  bad "SuccessExitStatus=1 in the service unit" "$(grep -v '^#' "$SERVICE_UNIT" 2>/dev/null | tr '\n' ' ')"; fi

# CollectMode= is a [Unit] key. Under [Service] systemd logs "Unknown key
# name" and ignores it, which is what stock-node1's journal showed, so the
# line is pinned to the section it is read from.
if awk '/^\[/{sec=$0} sec=="[Unit]" && $0=="CollectMode=inactive-or-failed"{found=1} END{exit !found}' "$SERVICE_UNIT" 2>/dev/null \
   && ! awk '/^\[/{sec=$0} sec=="[Service]" && /^CollectMode=/{found=1} END{exit !found}' "$SERVICE_UNIT" 2>/dev/null; then
  ok "and a finished instance may be unloaded: CollectMode= sits under [Unit], where systemd reads it"
else
  bad "CollectMode=inactive-or-failed under [Unit]" "$(grep -v '^#' "$SERVICE_UNIT" 2>/dev/null | tr '\n' ' ')"; fi

if grep -q 'daemon-reload' "$TMP/state/systemctl-calls" \
   && grep -q 'enable aperire-seal-model-key.socket' "$TMP/state/systemctl-calls" \
   && grep -q 'restart aperire-seal-model-key.socket' "$TMP/state/systemctl-calls"; then
  ok "systemd is reloaded, the socket enabled, and restarted so a re-run takes new unit text"
else
  bad "the socket is enabled and restarted" "$(cat "$TMP/state/systemctl-calls" 2>/dev/null)"; fi

# Nothing is granted through sudo any more, and nothing may quietly go back to
# it: the dashboard's own unit forbids sudo outright.
if [[ ! -f "$LEGACY_SUDOERS" ]]; then
  ok "and no sudoers rule is written at all"
else
  bad "no sudoers rule is written" "$(cat "$LEGACY_SUDOERS")"; fi

# Copied, not linked. A symlink into the checkout would put the grantee back in
# charge of what root runs, which is the whole reason this is not in the tree.
if [[ -f "$SEALER_DEST" && ! -L "$SEALER_DEST" ]] && asked_root 0755 "$SEALER_DEST"; then
  ok "the sealer is COPIED to a root-owned path outside the checkout, not linked to it"
else
  bad "the sealer is copied out of the tree" "$(stat -c '%a %F' "$SEALER_DEST" 2>&1)"; fi

# A host upgraded from the sudo shape carries a root-owned rule the dashboard
# cannot use. It has to go, and be said out loud, or it stays there for someone
# to read as a grant that means something.
reset_install
printf 'dashops ALL=(root) NOPASSWD: %s ""\n' "$SEALER_DEST" > "$LEGACY_SUDOERS"
out="$(run_install)"; rc=$?
if [[ $rc -eq 0 && ! -f "$LEGACY_SUDOERS" ]] && grep -q 'removed .*sudoers' <<<"$out"; then
  ok "an older sudo grant found on the host is removed, and the removal is said out loud"
else
  bad "the old sudoers rule is taken away" "exit $rc, present: $([[ -f $LEGACY_SUDOERS ]] && echo yes || echo no)"; fi

reset_install
run_install --arm >/dev/null 2>&1
if [[ -f "$ARM" ]] && grep -q -- "-m 0600 .*model-key.arm" "$TMP/state/install-calls"; then
  ok "--arm opens a window, root-owned and readable by nobody else"
else
  bad "--arm opens a window" "$(cat "$TMP/state/install-calls" 2>/dev/null)"; fi

reset_install
run_install >/dev/null 2>&1
if [[ ! -f "$ARM" ]]; then
  ok "and installing the grant without --arm opens none, so the socket alone seals nothing"
else
  bad "no window without --arm" "the marker is there"; fi

# The grant has to WORK for the account it names, not merely be written. A
# socket unit that did not come up is a dashboard that discovers this at the
# end of a ceremony an operator was watching.
reset_install
rm -f "$TMP/state/active"
out="$(run_install --arm)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'did not come up' <<<"$out"; then
  ok "a socket unit that did not come up is reported, not assumed"
else
  bad "the socket is checked, not assumed" "exit $rc: $out"; fi
if [[ ! -f "$ARM" ]]; then
  ok "and no window is opened by an install that failed its own check"
else
  bad "a failed install opens no window" "the marker is there"; fi

# Active, and no socket. systemd said yes and there is nothing to connect to,
# which is exactly the state that reads as "installed" and is not.
reset_install
rm -f "$SOCKET"
out="$(run_install)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no socket at' <<<"$out"; then
  ok "an active unit with no socket behind it is refused, and says which path is empty"
else
  bad "a missing socket is refused" "exit $rc: $out"; fi

# The account comes from the dashboard's own unit, not from whoever ran this.
# On a host where one operator installs and the service runs as another, the
# grant has to follow the service, and a socket the service cannot open is
# caught here rather than in a browser.
reset_install dashops
out="$(run_install)"; rc=$?
if grep -qxF 'SocketUser=dashops' "$SOCKET_UNIT" 2>/dev/null; then
  ok "the account is read from the dashboard unit, not from who ran the install"
else
  bad "the account comes from the unit" "$(grep -v '^#' "$SOCKET_UNIT" 2>/dev/null | tr '\n' ' ')"; fi
if [[ $rc -ne 0 ]] && grep -q "not 'dashops 600'" <<<"$out"; then
  ok "and a socket that account could not open is refused, naming what it found"
else
  bad "the ownership is checked for real" "exit $rc: $out"; fi

# A dashboard running as root needs no grant and must not be given one.
reset_install root
out="$(run_install)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'runs as root' <<<"$out"; then
  ok "a dashboard that already runs as root is refused a grant it does not need"
else
  bad "a root dashboard is refused" "exit $rc: $out"; fi

# ── --trust-arm-key: whose arm tokens this host will honour ─────────
#
# The key placed here is the trust root of the arm verb above: a token
# verified against it opens a window without anyone touching this host. So the
# ways it can be got wrong all have to be refusals, and the fingerprint has to
# be something an operator can actually compare.
ARMPUB_B64="$(openssl pkey -in "$ARMKEY" -pubout -outform DER | tail -c 32 | base64 -w0)"
ARMPUB_FP="$(openssl pkey -pubin -in "$ARMPUB" -outform DER | tail -c 32 | sha256sum | cut -c1-16)"

# A host the grant is already installed on: the only kind a key is trusted on.
reset_trusting() { reset_install; run_install >/dev/null 2>&1; : > "$TMP/state/install-calls"; }

reset_trusting
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -eq 0 && -f "$TRUSTED_PUB" ]] \
   && grep -qF -- "-o root -g root -m 0644" "$TMP/state/install-calls"; then
  ok "--trust-arm-key writes the fleet arm key, root-owned and world-readable"
else
  bad "--trust-arm-key installs the key" "exit $rc: $out"; fi
if [[ "$(openssl pkey -pubin -in "$TRUSTED_PUB" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)" == "$ARMPUB_B64" ]]; then
  ok "and what it wrote is that key, not something that merely parses"
else
  bad "the key written is the key given" "$(cat "$TRUSTED_PUB" 2>/dev/null)"; fi
if grep -qF -e "$ARMPUB_FP" <<<"$out"; then
  ok "and it prints the fingerprint, which is the only way to check a copy and paste"
else
  bad "the fingerprint is printed" "$out"; fi

# The same key, the other accepted shape. Two forms that produced two
# fingerprints would make the comparison worthless.
reset_trusting
out="$(run_install --trust-arm-key "$ARMPUB")"; rc=$?
if [[ $rc -eq 0 ]] && grep -qF -e "$ARMPUB_FP" <<<"$out"; then
  ok "a PEM file path is the same key and the same fingerprint as its base64"
else
  bad "a PEM path is accepted" "exit $rc: $out"; fi

# A DIFFERENT key already trusted here is refused, not overwritten (P2-056).
#
# This is the artefact whose substitution is durable: whoever holds the key in
# this file can open an arm window on this host whenever they like. Pairing
# calls this flag as root from the settlement frame, so before the settlement
# was signed, an interceptor who forwarded the honest welcome could re-point
# it. The refusal is the second line of defence and is worth having either
# way, because it is the only one that survives a wrong key arriving by hand.
reset_trusting
run_install --trust-arm-key "$ARMPUB_B64" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$TMP/armkeys/other.key" 2>/dev/null
OTHER_B64="$(openssl pkey -in "$TMP/armkeys/other.key" -pubout -outform DER | tail -c 32 | base64 -w0)"
: > "$TMP/state/install-calls"
out="$(run_install --trust-arm-key "$OTHER_B64")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'already trusts a different aggregator' <<<"$out"; then
  ok "a second, different arm key is refused by name rather than silently replacing the first"
else
  bad "a differing arm key is refused" "exit $rc: $out"; fi
if [[ "$(openssl pkey -pubin -in "$TRUSTED_PUB" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)" == "$ARMPUB_B64" ]]; then
  ok "  and the key that was already there is still there, byte for byte"
else
  bad "the existing key survives a refused replacement" "$(cat "$TRUSTED_PUB" 2>/dev/null)"; fi
if grep -qF -- "$TRUSTED_PUB" "$TMP/state/install-calls" 2>/dev/null; then
  bad "nothing is installed on a refusal" "$(cat "$TMP/state/install-calls")"
else
  ok "  and the refusal happens before the install, so there is no window"; fi

# The SAME key again is idempotent, not a refusal: a re-run of the pair
# command, or a second node built from the same notes, must not need an
# operator to delete a file first. Compared as the key, so the two accepted
# encodings agree.
out="$(run_install --trust-arm-key "$ARMPUB")"; rc=$?
if [[ $rc -eq 0 ]] && ! grep -q 'already trusts a different' <<<"$out"; then
  ok "  and the same key in the other encoding is accepted again, not refused as a change"
else
  bad "re-trusting the same key is idempotent" "exit $rc: $out"; fi

# The mistake that matters: the aggregator's PRIVATE key copied to a node
# would hand every node's operator the fleet's arming decision.
reset_install
out="$(run_install --trust-arm-key "$ARMKEY")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'PRIVATE key' <<<"$out" && [[ ! -f "$TRUSTED_PUB" ]]; then
  ok "a private key passed by mistake is refused by name, and nothing is written"
else
  bad "a private key is refused" "exit $rc: $out"; fi

reset_install
out="$(run_install --trust-arm-key "not a key at all")"; rc=$?
if [[ $rc -ne 0 && ! -f "$TRUSTED_PUB" ]]; then
  ok "and so is text that is neither a PEM file nor base64"
else
  bad "garbage is refused" "exit $rc: $out"; fi

# A key of the wrong algorithm parses perfectly and can never verify an arm
# token. Caught here, not at the far end of an operator's first fleet arm.
reset_install
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/armkeys/rsa.key" 2>/dev/null
openssl pkey -in "$TMP/armkeys/rsa.key" -pubout -out "$TMP/armkeys/rsa.pub" 2>/dev/null
out="$(run_install --trust-arm-key "$TMP/armkeys/rsa.pub")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'not an Ed25519 key' <<<"$out" && [[ ! -f "$TRUSTED_PUB" ]]; then
  ok "a public key of another algorithm is refused, because an arm token is Ed25519"
else
  bad "a non-Ed25519 key is refused" "exit $rc: $out"; fi

# The program the key is for. On stock-node1 (2026-09-03) the tree had the arm
# verb and /usr/local/sbin did not: the trusted key sat beside a sealer that
# read the arm payload as a seal and refused it as one, while this flag said
# "nothing else changed". So an installed program that differs from the tree
# is refreshed here, one that matches is left alone and said so, and a host
# with none is the wrong order rather than a silent half-install.
reset_trusting
printf '#!/usr/bin/env bash\nexit 3\n' > "$SEALER_DEST"
: > "$TMP/state/install-calls"
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -eq 0 ]] && cmp -s "$TREE_SRC" "$SEALER_DEST" \
   && asked_root 0755 "$SEALER_DEST" \
   && grep -q 'refreshed from the tree' <<<"$out"; then
  ok "--trust-arm-key refreshes a sealer that differs from the tree, root 0755, and says so"
else
  bad "a stale sealer is refreshed with the key" "exit $rc: $out / $(cat "$TMP/state/install-calls" 2>/dev/null)"; fi

reset_trusting
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'already matches the release' <<<"$out" \
   && ! grep -qF -- "-m 0755" "$TMP/state/install-calls"; then
  ok "one that already matches is left alone, and the output says which happened"
else
  bad "a current sealer is not rewritten" "exit $rc: $out / $(cat "$TMP/state/install-calls" 2>/dev/null)"; fi

# ADR 0024: with the release's digests on the host, a sealer the tree holds
# that is not the release's is refused, on both paths that copy it: the key
# is not trusted, the grant is not installed, and the installed copy stays.
mkdir -p "$TMP/digests"
printf '# anchor a fixture\n%s  scripts/aperire-seal-model-key.sh\n%s  scripts/state-file.py\n%s  scripts/model-key-method-lib.sh\n' \
  "$(printf 'the sealer the release shipped\n' | sha256sum | cut -c1-64)" \
  "$(sha256sum < "$TMP/tree/scripts/state-file.py" | cut -c1-64)" \
  "$(sha256sum < "$TMP/tree/scripts/model-key-method-lib.sh" | cut -c1-64)" > "$TMP/digests/release.sha256"
chmod 0644 "$TMP/digests/release.sha256"
reset_trusting
printf 'the previous sealer\n' > "$SEALER_DEST"
DIGESTS_FOR_RUN="$TMP/digests/release.sha256"
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -ne 0 && ! -f "$TRUSTED_PUB" && "$(cat "$SEALER_DEST")" == "the previous sealer" ]] \
   && grep -q 'refused: scripts/aperire-seal-model-key.sh is not the file this release shipped' <<<"$out"; then
  ok "--trust-arm-key refuses a sealer the release did not ship: no key trusted, the installed copy stays"
else
  bad "--trust-arm-key refuses an unshipped sealer" "exit $rc: $out"; fi
reset_install
out="$(run_install)"; rc=$?
if [[ $rc -ne 0 && ! -f "$SEALER_DEST" && ! -f "$SOCKET_UNIT" ]] \
   && grep -q 'the sealer was not installed' <<<"$out"; then
  ok "and a full install refuses it too, before any socket unit names it"
else
  bad "the sealer grant refuses an unshipped sealer" "exit $rc: $out"; fi
DIGESTS_FOR_RUN=""

reset_install
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -ne 0 && ! -f "$TRUSTED_PUB" && ! -f "$SEALER_DEST" ]] \
   && grep -q 'without flags first' <<<"$out"; then
  ok "a host with no sealer is told to install the grant first, and no key is placed"
else
  bad "trust before install is refused" "exit $rc: $out"; fi

# An aggregator is never sent an arm token: it opens its own window with a
# marker, and aperire-fleet-arm.sh skips its own row rather than posting to
# it. A key trusted there could never be used, so it is refused by name
# instead of quietly installed.
reset_install
run_install >/dev/null 2>&1
rm -f "$TRUSTED_NODE_KEY"
write_wconf_nonode
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -ne 0 && ! -f "$TRUSTED_PUB" ]] \
   && grep -q 'runs no node' <<<"$out" && grep -q -- '--self-only' <<<"$out"; then
  ok "a host that runs no node is refused an arm key it could never use, naming the line that arms it instead"
else
  bad "an aggregator is refused an arm key" "exit $rc: $out"; fi

# The arm trust and the address are installed together or not at all. A node
# that trusts an aggregator to open windows here, and cannot tell which node a
# token names, is exactly the state #184 is about, and --trust-arm-key is the
# one command that could create it.
reset_install
run_install >/dev/null 2>&1
rm -f "$TRUSTED_NODE_KEY"
write_wconf "$RPC_DEAD"
: > "$TMP/state/install-calls"
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -ne 0 && ! -f "$TRUSTED_PUB" && ! -f "$TRUSTED_NODE_KEY" ]] \
   && grep -q 'does not know its own node key' <<<"$out" \
   && grep -q 'the node did not answer' <<<"$out" \
   && grep -q -- '--node-key <pubkey_node>' <<<"$out"; then
  ok "--trust-arm-key on a host that cannot say what it is refuses, and names --node-key as the way through"
else
  bad "trust without an address is refused" "exit $rc: $out"; fi

reset_install
run_install >/dev/null 2>&1
rm -f "$TRUSTED_NODE_KEY"
write_wconf "$RPC_DEAD"
out="$(run_install --trust-arm-key "$ARMPUB_B64" --node-key "$NODE_KEY")"; rc=$?
if [[ $rc -eq 0 && -f "$TRUSTED_PUB" ]] \
   && [[ "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]] \
   && grep -qF "checked against $NODE_KEY" <<<"$out"; then
  ok "and with --node-key it stamps that key, installs the arm key, and says what tokens will be checked against"
else
  bad "--node-key carries --trust-arm-key through" "exit $rc: $out"; fi

# The upgrade that every node in an existing fleet takes: a stale sealer, no
# stamp, and this one flag. Both halves have to land, or the host runs a
# sealer that checks an address nobody wrote.
reset_trusting
printf '#!/usr/bin/env bash\nexit 3\n' > "$SEALER_DEST"
rm -f "$TRUSTED_NODE_KEY"
: > "$TMP/state/install-calls"
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -eq 0 ]] && cmp -s "$TREE_SRC" "$SEALER_DEST" \
   && [[ "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]] && [[ -f "$TRUSTED_PUB" ]]; then
  ok "on an existing node it refreshes the sealer AND stamps the key in the same run, so neither half waits for the other"
else
  bad "the upgrade path lands both halves" "exit $rc: $out"; fi

# A stamp already here is kept rather than re-read, because this flag is the
# upgrade path and a node stopped for maintenance must still be able to take
# a new aggregator key.
reset_trusting
write_wconf "$RPC_DEAD"
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -eq 0 && -f "$TRUSTED_PUB" ]] \
   && grep -qF "already stamped here" <<<"$out"; then
  ok "a host that is already stamped takes a new arm key with its node stopped, and says which key it will check"
else
  bad "an existing stamp is kept" "exit $rc: $out"; fi

# ── --refresh-node-key, and what a changed key invalidates ─────────

reset_install
run_install >/dev/null 2>&1
printf '%s\n' "$OTHER_NODE_KEY" > "$RPC_KEYFILE"
out="$(run_install --refresh-node-key)"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$OTHER_NODE_KEY" ]] \
   && grep -qF "it was $NODE_KEY" <<<"$out" \
   && grep -q 'refused here from now on' <<<"$out" \
   && grep -q 'expected_pubkey_node' <<<"$out"; then
  ok "--refresh-node-key re-reads the node, says what the key was, and says what that invalidates"
else
  bad "a changed key is re-stamped" "exit $rc: $out"; fi

reset_install
run_install >/dev/null 2>&1
write_wconf "$RPC_DEAD"
out="$(run_install --refresh-node-key)"; rc=$?
if [[ $rc -ne 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]] \
   && grep -q 'cannot say what its own node key is' <<<"$out" \
   && grep -q -- '--node-key <pubkey_node>' <<<"$out"; then
  ok "a refresh it cannot complete refuses and leaves the old stamp alone, rather than clearing it"
else
  bad "a failed refresh changes nothing" "exit $rc: $out"; fi

reset_install
out="$(run_install --refresh-node-key --arm)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'run of its own' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "and refreshing the key is a run of its own, never a window opened on the side"
else
  bad "--refresh-node-key is not combined with --arm" "exit $rc: $out"; fi

# #949: a host with a named instance. The stamp is one file per host, so:
#   - where the instance's node is the host's only node (no default
#     configuration, or an aggregator's SERVICE=none), it is that node's,
#     read through the instance's own configuration, found by the rule the
#     wrapper installer writes it by;
#   - where the default instance runs a node too, it stays the default
#     node's, and the instance's run says so rather than flipping the file
#     to its own key, which would refuse every token cut for the other.
INST_WCONF="$(bash -c '. "$1"; trusted_wrapper_conf node2 "$2"' _ "$REPO_DIR/scripts/trusted-path-lib.sh" "$WCONF_T")"
reset_install
run_install >/dev/null 2>&1
write_wconf_nonode
printf 'SERVICE=xrpld-node2\nADMIN_RPC=http://127.0.0.1:%s\n' "$RPC_PORT" > "$INST_WCONF"
printf '%s\n' "$OTHER_NODE_KEY" > "$RPC_KEYFILE"
out="$(APERIRE_INSTANCE=node2 run_install --refresh-node-key)"; rc=$?
if [[ $rc -eq 0 && "$INST_WCONF" != "$WCONF_T" && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$OTHER_NODE_KEY" ]]; then
  ok "where the instance's node is the host's only node, the stamp asks it, through the instance's own configuration"
else
  bad "the instance's node is the one stamped on a host with no default node (#949)" "exit $rc, stamp $(cat "$TRUSTED_NODE_KEY" 2>/dev/null): $out"; fi
# Its configuration missing, and no default node: refused by name.
reset_install
run_install >/dev/null 2>&1
rm -f "$INST_WCONF" "$WCONF_T"
out="$(APERIRE_INSTANCE=node2 run_install --refresh-node-key)"; rc=$?
if [[ $rc -ne 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]] \
   && grep -qF "instance 'node2' has no wrapper configuration ($INST_WCONF)" <<<"$out" \
   && grep -qF -- "--refresh-node-key --node-key <pubkey_node> --instance node2" <<<"$out"; then
  ok "and an instance with no wrapper configuration is refused by name, the stamp left as it was, its hint naming the instance"
else
  bad "a missing instance configuration is refused by name" "exit $rc, stamp $(cat "$TRUSTED_NODE_KEY" 2>/dev/null): $out"; fi
# Both nodes on one host: the default answers with one key, the instance's
# configuration names a node that is down. The instance's run keeps the
# default node's stamp, and says why, rather than stamping its own.
reset_install
run_install >/dev/null 2>&1
printf 'SERVICE=xrpld-node2\nADMIN_RPC=%s\n' "$RPC_DEAD" > "$INST_WCONF"
out="$(APERIRE_INSTANCE=node2 run_install --refresh-node-key)"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRUSTED_NODE_KEY" 2>/dev/null)" == "$NODE_KEY" ]] \
   && grep -qF "the node-key stamp is one per host, and this host's default node holds it" <<<"$out" \
   && grep -qF "Instance 'node2' is not stamped" <<<"$out"; then
  ok "with a default node too, an instance's run keeps the host's one stamp on the default node, and says so"
else
  bad "an instance's run never moves the host's stamp off a default node" "exit $rc, stamp $(cat "$TRUSTED_NODE_KEY" 2>/dev/null): $out"; fi
out="$(APERIRE_INSTANCE='../x' run_install --refresh-node-key)"; rc=$?
if [[ $rc -eq 2 ]] && grep -q "is not an instance name" <<<"$out"; then
  ok "and an instance name that is not one is refused before anything is read"
else
  bad "a bad instance name is refused" "exit $rc: $out"; fi
rm -f "$INST_WCONF"

# The two programs on one file: the sealer reads exactly what the installer
# wrote, and a token cut for the key it replaced stops working at that moment.
# Asserted across both rather than against the test's idea of a stamp.
reset_install
run_install >/dev/null 2>&1
STAMP_WAS="$NODE_KEY_STAMP"
NODE_KEY_STAMP="$TRUSTED_NODE_KEY"
reset_state; rm -f "$ARMSEEN"
arm_token "$(openssl rand -hex 16)" "$(date +%s)" 1 "$NODE_KEY"
if arm_payload "$ARMKEY" | run_arm >/dev/null 2>&1; then
  ok "a token cut for the stamped key arms this host, through the file the installer wrote"
else
  bad "the installer's stamp is the sealer's stamp" "the token was refused"; fi

printf '%s\n' "$OTHER_NODE_KEY" > "$RPC_KEYFILE"
run_install --refresh-node-key >/dev/null 2>&1
reset_state; rm -f "$ARMSEEN"
arm_token "$(openssl rand -hex 16)" "$(date +%s)" 1 "$NODE_KEY"
out="$(arm_payload "$ARMKEY" | run_arm 2>&1)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'addressed to another node' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "and after the key is refreshed a FRESH token cut for the old one is refused, nonce and clock notwithstanding"
else
  bad "a refreshed key invalidates the old address" "exit $rc: $out"; fi
reset_state; rm -f "$ARMSEEN"
arm_token "$(openssl rand -hex 16)" "$(date +%s)" 1 "$OTHER_NODE_KEY"
if arm_payload "$ARMKEY" | run_arm >/dev/null 2>&1 && [[ -f "$ARM" ]]; then
  ok "while one cut for the new key arms it, so the refresh moved the address rather than breaking arming"
else
  bad "the new address works" "the token was refused"; fi
NODE_KEY_STAMP="$STAMP_WAS"
printf '%s\n' "$NODE_KEY" > "$RPC_KEYFILE"

# --remove takes the stamp with everything else: it is read by one program,
# and that program is going.
reset_install
run_install >/dev/null 2>&1
out="$(run_install --remove)"; rc=$?
if [[ $rc -eq 0 && ! -f "$TRUSTED_NODE_KEY" ]] && grep -q 'the node key an arm token was checked against' <<<"$out"; then
  ok "--remove takes the stamped node key away too, and says what it was for"
else
  bad "--remove takes the stamp" "exit $rc: $out"; fi

# Nonces honoured under the old key mean nothing under a new one, and keeping
# them would only refuse a fresh token that reused one.
reset_trusting
printf 'deadbeefdeadbeefdeadbeefdeadbeef\n' > "$TRUSTED_SEEN"
run_install --trust-arm-key "$ARMPUB_B64" >/dev/null 2>&1
if [[ ! -f "$TRUSTED_SEEN" ]]; then
  ok "trusting a new key forgets the nonces honoured under the old one"
else
  bad "the seen file is cleared with the key" "$(cat "$TRUSTED_SEEN")"; fi

# One job per run. Trusting a key and opening a window are different decisions.
reset_install
out="$(run_install --trust-arm-key "$ARMPUB_B64" --arm)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'run of its own' <<<"$out" \
   && [[ ! -f "$TRUSTED_PUB" && ! -f "$ARM" ]]; then
  ok "--trust-arm-key together with --arm is refused, and neither half happens"
else
  bad "the two are not combined" "exit $rc: $out"; fi

reset_trusting
run_install --trust-arm-key "$ARMPUB_B64" >/dev/null 2>&1
printf 'deadbeefdeadbeefdeadbeefdeadbeef\n' > "$TRUSTED_SEEN"
out="$(run_install --remove)"; rc=$?
if [[ $rc -eq 0 && ! -f "$TRUSTED_PUB" && ! -f "$TRUSTED_SEEN" ]] \
   && grep -q 'trusts no fleet arm key' <<<"$out"; then
  ok "--remove takes the fleet arm key away too, and says the host now trusts none"
else
  bad "--remove takes the arm key" "exit $rc: $out"; fi

reset_install
run_install --arm >/dev/null 2>&1
printf 'dashops ALL=(root) NOPASSWD: %s ""\n' "$SEALER_DEST" > "$LEGACY_SUDOERS"
out="$(run_install --remove)"; rc=$?
if [[ $rc -eq 0 && ! -f "$SOCKET_UNIT" && ! -f "$SERVICE_UNIT" \
      && ! -f "$SEALER_DEST" && ! -f "$ARM" && ! -f "$LEGACY_SUDOERS" ]]; then
  ok "--remove takes back both units, the program, any open window and any old rule"
else
  bad "--remove takes it all off" "exit $rc"; fi
if grep -q 'disable --now aperire-seal-model-key.socket' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "and stops it listening rather than only deleting the file"
else
  bad "--remove disables the socket" "$(cat "$TMP/state/systemctl-calls" 2>/dev/null)"; fi
if grep -q 'setup-advisor-model.sh' <<<"$out"; then
  ok "and says the operator ceremony still works, because removing this is not losing the feature"
else
  bad "--remove names what still works" "$out"; fi

echo
echo "── the aggregator's side, and the chain end to end ────────────────"

# scripts/aperire-fleet-arm.sh is the root line on the aggregator that mints
# the tokens the verb above honours. Same treatment as the other two: the root
# guard comes out of a scratch copy and is asserted against the original.
FLEETARM_ORIG="$REPO_DIR/scripts/aperire-fleet-arm.sh"
# shellcheck disable=SC2016  # a literal to grep for, not an expression to run
FGUARD='[[ $EUID -eq 0 ]] || die "run with sudo: the fleet arm key is root'"'"'s, and arming this host writes a root-owned marker"'
FLEETARM="$TMP/fleet-arm.sh"
grep -vxF -e "$FGUARD" "$FLEETARM_ORIG" > "$FLEETARM"
AGGETC="$TMP/aggetc"
mkdir -p "$AGGETC"
# The copy under test is not inside a checkout's scripts/, so it resolves its
# install the way the installed /usr/local/sbin/aperire-fleet-arm does
# (#741): from the broker grant's conf, root's (here, this account's) 0644.
printf 'INSTALL_DIR=%s\n' "$REPO_DIR" > "$AGGETC/fleet-broker.conf"; chmod 644 "$AGGETC/fleet-broker.conf"

if grep -qxF -e "$FGUARD" "$FLEETARM_ORIG"; then
  ok "the fleet arm script refuses to run as anything but root"
else
  bad "the fleet arm root guard is there" "the line these tests remove is gone"; fi
if [[ $(( $(wc -l < "$FLEETARM_ORIG") - $(wc -l < "$FLEETARM") )) -eq 1 ]]; then
  ok "and the copy under test differs from it by exactly that one line"
else
  bad "one line removed" "$(( $(wc -l < "$FLEETARM_ORIG") - $(wc -l < "$FLEETARM") )) lines"; fi

run_fleet_arm() {
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_ETC="$AGGETC" \
      APERIRE_UNIT_DIR="$UNITS" \
      APERIRE_FLEET_FILE="${FLEETYAML:-$TMP/no-such-fleet.yaml}" \
      bash "$FLEETARM" "$@" 2>&1
}

rm -f "$TMP/state/"* "$AGGETC/"* 2>/dev/null
printf 'INSTALL_DIR=%s\n' "$REPO_DIR" > "$AGGETC/fleet-broker.conf"; chmod 644 "$AGGETC/fleet-broker.conf"
out="$(run_fleet_arm --self-only)"; rc=$?
if [[ $rc -eq 0 && -f "$AGGETC/fleet-arm.key" ]] \
   && [[ "$(stat -c %a "$AGGETC/fleet-arm.key")" == 600 ]]; then
  ok "the first run makes the aggregator's signing key, readable by nobody else"
else
  bad "the signing key is made" "exit $rc: $out"; fi
if grep -qF -- "-o root -g root -m 0600 /dev/null $AGGETC/model-key.arm" "$TMP/state/install-calls" 2>/dev/null; then
  ok "and arms this host with the same marker the sealer's own --arm writes"
else
  bad "self is armed with that marker" "$(cat "$TMP/state/install-calls" 2>/dev/null)"; fi

# #851 review L3: the arming run never makes a key where one was lost. Its
# key leaves fleet-arm.made beside it; with that marker, or any fleet record
# at all, a missing key is refused by name and nothing is made or armed.
if [[ -f "$AGGETC/fleet-arm.made" && ! -s "$AGGETC/fleet-arm.made" && "$(stat -c %a "$AGGETC/fleet-arm.made")" == 600 ]]; then
  ok "the key it made leaves fleet-arm.made beside it, empty, 0600"
else
  bad "the arming run's key leaves the marker" "$(ls -la "$AGGETC")"; fi
mv "$AGGETC/fleet-arm.key" "$TMP/fleet-arm.key.851"
arm851_ok=1; arm851_detail=''
# Root's own records (the marker, fleet-nodes.conf) name the restore and the
# re-key. A dashboard fleet file alone, even one holding only this host's own
# row, cannot be judged here, so it names the plain grant install first,
# which judges it safely and makes the key when no node is paired (#853
# review, L3).
for why in marker nodes yaml selfrow; do
  rm -f "$AGGETC/fleet-arm.made" "$AGGETC/fleet-nodes.conf" "$TMP/fleet851.yaml"
  case "$why" in
    marker)  : > "$AGGETC/fleet-arm.made"; chmod 600 "$AGGETC/fleet-arm.made" ;;
    nodes)   printf 'node-a n9KnownKeyAAAA 7901 0\n' > "$AGGETC/fleet-nodes.conf" ;;
    yaml)    printf 'fleet:\n  - label: node-a\n' > "$TMP/fleet851.yaml" ;;
    selfrow) printf 'fleet:\n  - label: agg\n    role: aggregator\n' > "$TMP/fleet851.yaml" ;;
  esac
  out="$(FLEETYAML="$([[ "$why" == yaml || "$why" == selfrow ]] && echo "$TMP/fleet851.yaml")" run_fleet_arm --self-only)"; rc=$?
  if [[ $rc -eq 0 || -e "$AGGETC/fleet-arm.key" ]] || ! grep -qF -- '--restore --from <backup set>' <<<"$out"; then
    arm851_ok=0; arm851_detail="$arm851_detail $why: rc=$rc $out;"
  fi
  case "$why" in
    marker|nodes) grep -qF -- '--run fleet-broker-grant --new-fleet-keys' <<<"$out" \
                    || { arm851_ok=0; arm851_detail="$arm851_detail $why names no re-key: $out;"; } ;;
    *) { grep -qxF "       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run fleet-broker-grant" <<<"$out" \
           && ! grep -qF -- '--new-fleet-keys' <<<"$out"; } \
         || { arm851_ok=0; arm851_detail="$arm851_detail $why names no plain grant install first: $out;"; } ;;
  esac
done
if (( arm851_ok )); then
  ok "a missing key beside fleet-arm.made, root's node record or a fleet.yaml (even one with only this host's row) is refused by the arming run, which makes and arms nothing, naming the plain grant install where only a fleet file matched"
else
  bad "the arming run never remakes a lost key" "$arm851_detail"; fi
rm -f "$AGGETC/fleet-arm.made" "$AGGETC/fleet-nodes.conf" "$TMP/fleet851.yaml"
mv "$TMP/fleet-arm.key.851" "$AGGETC/fleet-arm.key"
# #853 review L2: the arming run says when the marker cannot be written.
chmod 555 "$AGGETC"
out="$(run_fleet_arm --self-only)"
chmod 755 "$AGGETC"
if grep -qF -e "$AGGETC/fleet-arm.key has no fleet-arm.made beside it" <<<"$out" && [[ ! -e "$AGGETC/fleet-arm.made" ]]; then
  ok "an arming run whose marker cannot be written says the key has none, and what that leaves"
else
  bad "the arming run says when the marker could not be made" "$out"; fi

# The one invariant that spans the two scripts: an operator is asked to read a
# fingerprint off the aggregator and compare it with what the node printed.
# Two different computations would make that comparison meaningless.
AGG_FP="$(run_fleet_arm --self-only | sed -n 's/^ *fingerprint  //p;s/^== Fleet arm key //p' | head -n 1)"
reset_trusting
NODE_FP="$(run_install --trust-arm-key "$(openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -outform DER | tail -c 32 | base64 -w0)" \
           | sed -n 's/^ *fingerprint  //p')"
if [[ -n "$AGG_FP" && "$AGG_FP" == "$NODE_FP" ]]; then
  ok "the fingerprint the aggregator prints is the one the node prints back ($AGG_FP)"
else
  bad "the two fingerprints agree" "aggregator '$AGG_FP', node '$NODE_FP'"; fi

# ── #741: the pairing fingerprint, root's to print ────────────────────
#
# One value over the fleet trust key and the fleet arm key. A node asks the
# operator to paste it and compares the whole value; this script, as root, is
# its only reference. Two implementations (this bash, and
# fleetPairingFingerprint in the contract), held together by one vector the
# contract pins and the unit test asserts too.
has741() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
CONTRACT="$REPO_DIR/dashboard/types/fleet-link-contract.ts"
vec() { sed -n "s/^  $1: '\([^']*\)',\$/\1/p" "$CONTRACT" | head -n 1; }
V_TRUST="$(vec trust_b64url)"; V_ARM="$(vec arm_b64)"; V_FP="$(vec fingerprint)"
sed -n '/^# ---- BEGIN fleet_pairing_fingerprint/,/^# ---- END fleet_pairing_fingerprint/p' "$FLEETARM_ORIG" > "$TMP/pairfp.sh"
got="$(bash -c '. "$1"; fleet_pairing_fingerprint "$2" "$3"' _ "$TMP/pairfp.sh" "$V_TRUST" "$V_ARM" 2>&1)"
if [[ -n "$V_FP" && "$got" == "$V_FP" ]]; then
  ok "the arm script's pairing fingerprint of the contract's vector is the contract's value ($V_FP)"
else
  bad "the bash and TypeScript pairing fingerprints agree on the vector" "contract '$V_FP' ($V_TRUST / $V_ARM), bash '$got'"; fi
# A key the node would refuse has no fingerprint here either.
if ! bash -c '. "$1"; fleet_pairing_fingerprint "$2" "$3"' _ "$TMP/pairfp.sh" "$V_TRUST" "${V_ARM:0:10}!${V_ARM:10}" >/dev/null 2>&1 \
   && ! bash -c '. "$1"; fleet_pairing_fingerprint "$2" "$3"' _ "$TMP/pairfp.sh" "$V_ARM" "$V_ARM" >/dev/null 2>&1; then
  ok "  and a key that is not a canonical 32-byte encoding has none, as on the node"
else
  bad "non-canonical keys have no pairing fingerprint" "the bash twin produced one"; fi

# A real trust key for this aggregator, the way fleet-trust.yaml holds one:
# the private half is the last 32 bytes of its PKCS8 DER, base64url.
openssl genpkey -algorithm ed25519 -out "$TMP/trust741.pem" 2>/dev/null
TRUST741_PUB="$(openssl pkey -in "$TMP/trust741.pem" -pubout -outform DER | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
# Root's pin of it (#1008), in root's directory: the only place this program
# takes the trust key from.
PIN741="$AGGETC/fleet-trust.pub"
printf '%s\n' "$TRUST741_PUB" > "$PIN741"; chmod 644 "$PIN741"
ARM741_PUB="$(openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -outform DER | tail -c 32 | base64 -w0)"
WANT741="$(bash -c '. "$1"; fleet_pairing_fingerprint "$2" "$3"' _ "$TMP/pairfp.sh" "$TRUST741_PUB" "$ARM741_PUB")"
rm -f "$AGGETC/model-key.arm"
# T8 (pairing v2): stdout carries the value and nothing else, one line of 64
# lowercase hex, so FP=$(sudo aperire-fleet-arm --fingerprint) is the value.
# Every sentence is on stderr. Captured apart here, because run_fleet_arm
# merges the two and a merged capture is exactly what would hide a label
# that leaked onto stdout.
run_fleet_arm_split() { # stdout -> $TMP/fp.out, stderr -> $TMP/fp.err; returns the exit status
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_ETC="$AGGETC" \
      APERIRE_UNIT_DIR="$UNITS" \
      APERIRE_FLEET_FILE="${FLEETYAML:-$TMP/no-such-fleet.yaml}" \
      bash "$FLEETARM" "$@" >"$TMP/fp.out" 2>"$TMP/fp.err"
}
rc=0; run_fleet_arm_split --fingerprint || rc=$?
if [[ $rc -eq 0 && -n "$WANT741" && "$(cat "$TMP/fp.out")" == "$WANT741" ]] \
   && [[ "$(wc -l < "$TMP/fp.out")" -eq 1 ]] \
   && [[ "$(od -An -c "$TMP/fp.out" | tr -d ' \n' | tail -c 2)" == '\n' ]] \
   && grep -qxE '[0-9a-f]{64}' "$TMP/fp.out" && [[ ! -e "$AGGETC/model-key.arm" ]]; then
  ok "--fingerprint's stdout is exactly one line, the 64 hex of this host's trust and arm keys, and it arms nothing"
else
  bad "--fingerprint prints the bare value alone on stdout and arms nothing" "exit $rc, want '$WANT741', stdout: $(od -c "$TMP/fp.out" | head -3)"; fi
if has741 "$(cat "$TMP/fp.err")" 'Pairing fingerprint for this aggregator' && ! has741 "$(cat "$TMP/fp.err")" "$WANT741"; then
  ok "  the label naming the host is on stderr, and the value is not"
else
  bad "the label is on stderr alone" "stderr: $(cat "$TMP/fp.err")"; fi
out="$(run_fleet_arm --self-only)"
if has741 "$out" '== Pairing fingerprint' && grep -qxF -e "$WANT741" <<<"$out"; then
  ok "  and every ordinary run prints the same bare value, alone on its line"
else
  bad "an ordinary run prints the bare pairing fingerprint" "$out"; fi
rm -f "$AGGETC/model-key.arm"
# Read-only means read-only (ruling 2, 2026-10-04): with no arm key it exits
# 3, makes nothing, and prints nothing on stdout. The grant installer makes
# the key; this never does.
mv "$AGGETC/fleet-arm.key" "$TMP/fleet-arm.key.741"
before_etc="$(find "$AGGETC" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')"
rc=0; run_fleet_arm_split --fingerprint || rc=$?
if [[ $rc -eq 3 && ! -e "$AGGETC/fleet-arm.key" && ! -s "$TMP/fp.out" ]] \
   && [[ "$(find "$AGGETC" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" == "$before_etc" ]] \
   && has741 "$(cat "$TMP/fp.err")" 'no fleet arm key yet' \
   && has741 "$(cat "$TMP/fp.err")" '--run fleet-broker-grant'; then
  ok "  with no arm key it exits 3, makes nothing, prints nothing on stdout, and names the grant that makes it"
else
  bad "--fingerprint makes no key" "exit $rc, stdout '$(cat "$TMP/fp.out")', stderr: $(cat "$TMP/fp.err"), etc now: $(find "$AGGETC" -mindepth 1 -maxdepth 1 -printf '%f ') (was $before_etc)"; fi
mv "$TMP/fleet-arm.key.741" "$AGGETC/fleet-arm.key"
# #1008: the trust key comes from root's pin and from nowhere else. The
# install the conf names holds a DIFFERENT key at the default path, where the
# dashboard account writes, and the fingerprint is still the pinned key's.
TREE741="$TMP/tree741"
mkdir -p "$TREE741/dashboard/config"
openssl genpkey -algorithm ed25519 -out "$TMP/plant741.pem" 2>/dev/null
printf 'private_key: %s\n' "$(openssl pkey -in "$TMP/plant741.pem" -outform DER | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')" \
  > "$TREE741/dashboard/config/fleet-trust.yaml"
PLANT741_PUB="$(openssl pkey -in "$TMP/plant741.pem" -pubout -outform DER | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
PLANTFP741="$(bash -c '. "$1"; fleet_pairing_fingerprint "$2" "$3"' _ "$TMP/pairfp.sh" "$PLANT741_PUB" "$ARM741_PUB")"
cp "$AGGETC/fleet-broker.conf" "$TMP/fbc741.keep"
printf 'INSTALL_DIR=%s\n' "$TREE741" > "$AGGETC/fleet-broker.conf"; chmod 644 "$AGGETC/fleet-broker.conf"
rc=0; run_fleet_arm_split --fingerprint || rc=$?
if [[ $rc -eq 0 && "$(cat "$TMP/fp.out")" == "$WANT741" && "$WANT741" != "$PLANTFP741" ]]; then
  ok "  a key planted in the install's fleet-trust.yaml is ignored: the fingerprint is root's pinned key's"
else
  bad "root ignores a key planted in the dashboard's file" "exit $rc, got '$(cat "$TMP/fp.out")', pinned '$WANT741', planted '$PLANTFP741'"; fi
# Exit 2, no pin: nothing on stdout, never a fingerprint over the planted
# key, and the update that pins it named, with the grant for a host with none.
mv "$PIN741" "$TMP/pin741.aside"
rc=0; run_fleet_arm_split --fingerprint || rc=$?
if [[ $rc -eq 2 && ! -s "$TMP/fp.out" ]] && has741 "$(cat "$TMP/fp.err")" 'root holds no fleet trust key pin it will read' \
   && has741 "$(cat "$TMP/fp.err")" '--update --force' && has741 "$(cat "$TMP/fp.err")" '--run fleet-broker-grant'; then
  ok "  with no pin it exits 2, nothing on stdout, and names the update that pins it and the grant that makes a key"
else
  bad "--fingerprint with no pin" "exit $rc, stdout '$(cat "$TMP/fp.out")', stderr: $(cat "$TMP/fp.err")"; fi
mv "$TMP/pin741.aside" "$PIN741"
cp "$TMP/fbc741.keep" "$AGGETC/fleet-broker.conf"; chmod 644 "$AGGETC/fleet-broker.conf"
# A pin root will not read is no pin: a link (not followed, whatever it
# points at) and one another account could write.
mv "$PIN741" "$TMP/pin741.real"; ln -s "$TMP/pin741.real" "$PIN741"
out="$(run_fleet_arm --fingerprint)"; rc=$?
rm -f "$PIN741"; mv "$TMP/pin741.real" "$PIN741"
if [[ $rc -eq 2 ]] && has741 "$out" 'no pairing fingerprint' && ! has741 "$out" "$WANT741"; then
  ok "  a pin that is a symlink is not followed: no fingerprint"
else
  bad "the pin is never read through a link" "exit $rc: $out"; fi
chmod 664 "$PIN741"
out="$(run_fleet_arm --fingerprint)"; rc=$?
chmod 644 "$PIN741"
if [[ $rc -eq 2 ]] && has741 "$out" 'can be written by another account' && ! has741 "$out" "$WANT741" \
   && has741 "$out" "never replaces a pin that is there" && ! has741 "$out" "the update pins it"; then
  ok "  and neither is one another account could write, and it names the file, not an update that would not replace it"
else
  bad "a group-writable pin is no pin" "exit $rc: $out"; fi
out="$(run_fleet_arm --fingerprint --node stock-node1)"; rc=$?
if [[ $rc -ne 0 ]] && has741 "$out" 'arms nothing'; then
  ok "  --fingerprint with --node is refused: it only prints"
else
  bad "--fingerprint takes no --node" "exit $rc: $out"; fi
# The installed copy (not inside a checkout's scripts/) takes its install
# from the broker grant's conf, and only from one that is its owner's alone.
cp "$AGGETC/fleet-broker.conf" "$TMP/fbc.keep"
chmod 664 "$AGGETC/fleet-broker.conf"
out="$(run_fleet_arm --fingerprint)"; rc=$?
if [[ $rc -ne 0 ]] && has741 "$out" "is not root's alone"; then
  ok "  the installed copy refuses a broker conf another account could write"
else
  bad "a writable conf names no install" "exit $rc: $out"; fi
rm -f "$AGGETC/fleet-broker.conf"
out="$(run_fleet_arm --fingerprint)"; rc=$?
if [[ $rc -ne 0 ]] && has741 "$out" '--run fleet-broker-grant'; then
  ok "  and with no conf at all it says which command records one"
else
  bad "no conf is refused by name" "exit $rc: $out"; fi
cp "$TMP/fbc.keep" "$AGGETC/fleet-broker.conf"; chmod 644 "$AGGETC/fleet-broker.conf"

# The fallback port, which decides which fleet.yaml row is this host when the
# dashboard's unit does not say. It has to be the port the installer gives a
# dashboard, or a correct fleet arms its own aggregator a second time.
# shellcheck disable=SC2016  # the installer's literal text, not an expansion
if grep -qxF 'DEFAULT_PORT=7800' "$FLEETARM_ORIG" \
   && grep -qF 'PORT=${APERIRE_PORT:-7800}' "$REPO_DIR/scripts/install-aperire-service.sh"; then
  ok "its fallback dashboard port is still the one install-aperire-service.sh gives"
else
  bad "the fallback port agrees with the installer" "$(grep -n '^DEFAULT_PORT=' "$FLEETARM_ORIG")"; fi

# ── the chain: minted there, honoured here ─────────────────────────
#
# A stub node dashboard on a loopback port of its own, standing in for the
# route that carries the token. It records what arrived; the token it records
# is then fed to the sealer above, which is the only thing in the chain that
# verifies the signature. Nothing is simulated on either end: real openssl
# signs, real openssl verifies.
cat > "$TMP/nodestub.py" <<'PYEOF'
import http.server, os, sys
out, portfile, tokfile = sys.argv[1], sys.argv[2], sys.argv[3]
bearer = open(tokfile).read().strip()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('content-length', 0)))
        open(out, 'wb').write(body)
        open(out + '.auth', 'w').write(self.headers.get('Authorization', ''))
        open(out + '.path', 'w').write(self.path)
        # A dashboard from before the fleet-write API: the route is unknown,
        # page auth answers with a login redirect. Switched on by a file so
        # the stub need not be restarted between rows.
        if os.path.exists(out + '.stale'):
            self.send_response(302)
            self.send_header('location', '/login.html?next=%2Ffleet%2Fv1%2Fmodel%2Farm')
            self.send_header('content-length', '0')
            self.end_headers()
            return
        # What a node answers when its own root sealer refused: the class in
        # `error`, the sealer's sentence in `detail`, exactly as armOutcome
        # builds it from the sealer's last stderr line.
        if os.path.exists(out + '.refused'):
            b = (b'{"ok":false,"armed":false,"window_s":null,"issuer":null,'
                 b'"error":"refused","detail":"that arm token is addressed to another '
                 b'node: it names nHUeqOTHER and this host is nHUeqTHIS"}')
            self.send_response(409)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        b = b'{"armed":true,"window_s":900}'
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
open(portfile, 'w').write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF

NODETOKEN="$TMP/node-read.token"
head -c 48 /dev/urandom | base64 | tr -d '\n=' > "$NODETOKEN"
rm -f "$TMP/stub-body" "$TMP/stub-port"
python3 "$TMP/nodestub.py" "$TMP/stub-body" "$TMP/stub-port" "$NODETOKEN" &
STUB_PID=$!
# Up to fifteen seconds for python to start and bind. A loaded runner is slow,
# and a stub that never came up must say THAT: without this row it would fail
# as "a peer is armed", which reads as a broken feature.
for _ in $(seq 1 50); do
  [[ -s "$TMP/stub-port" ]] && break
  sleep 0.3
done
if [[ -s "$TMP/stub-port" ]]; then
  ok "the stub node dashboard is listening, so the rows below are about the script"
else
  bad "the stub node comes up" "no port file after 15s; the rows below cannot mean anything"
fi
STUB_PORT="$(cat "$TMP/stub-port" 2>/dev/null || echo 0)"

FLEETYAML="$TMP/fleet.yaml"
# The same key the sealer above is stamped with, so the token minted here is
# addressed to the host that honours it at the end of this file.
PIN="$NODE_KEY"
cat > "$FLEETYAML" <<EOF
fleet:
  - label: aggregator-here
    read_origin: http://127.0.0.1:7800
    token_path: $NODETOKEN
  - label: stock-node1
    role: node
    read_origin: http://127.0.0.1:$STUB_PORT
    token_path: $NODETOKEN
    expected_pubkey_node: $PIN
  - label: unpinned-node
    read_origin: http://127.0.0.1:$STUB_PORT
    token_path: $NODETOKEN
EOF

out="$(run_fleet_arm)"; rc=$?
if grep -q "^armed stock-node1 (900 s)$" <<<"$out"; then
  ok "the aggregator arms a pinned peer over its loopback origin, and says so in one line"
else
  bad "a peer is armed" "exit $rc: $out"; fi
if [[ "$(cat "$TMP/stub-body.path" 2>/dev/null)" == "/fleet/v1/model/arm" ]] \
   && [[ "$(cat "$TMP/stub-body.auth" 2>/dev/null)" == "Bearer $(cat "$NODETOKEN")" ]]; then
  ok "on that node's fleet-write path, carrying that node's own read token"
else
  bad "the request is addressed and authenticated" "path $(cat "$TMP/stub-body.path" 2>/dev/null), auth $(cat "$TMP/stub-body.auth" 2>/dev/null)"; fi
# A row nobody pinned cannot be addressed, so it is skipped, and a skip is not
# a success: the run must end non-zero or an operator reads "done".
if grep -q '^skipped unpinned-node: no pinned key' <<<"$out" && [[ $rc -ne 0 ]]; then
  ok "a row with no expected_pubkey_node is skipped by name, and the run does not read as done"
else
  bad "an unpinned row is skipped and counted" "exit $rc: $out"; fi
# The row that describes the aggregator itself is armed by its marker, never
# posted to. Getting this wrong turns a correct fleet into a failing run.
if ! grep -q 'aggregator-here' <<<"$(grep -v '^armed aggregator-here' <<<"$out")"; then
  ok "and the row that is this host is armed locally, not posted to as a peer"
else
  bad "self is not treated as a peer" "$out"; fi

# --node names one node, and only it. Arming this host as a side effect is a
# window nobody asked for, open on the aggregator for fifteen minutes; it is
# how the aggregator's own row read ARMED after a seal that went to stock-node1.
: > "$TMP/state/install-calls"
rm -f "$AGGETC/model-key.arm"
out="$(run_fleet_arm --node stock-node1)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^armed stock-node1 (900 s)$' <<<"$out" \
   && ! grep -qF -- "$AGGETC/model-key.arm" "$TMP/state/install-calls" \
   && grep -q '^not armed aggregator-here: --node stock-node1 did not ask for this host$' <<<"$out"; then
  ok "--node <peer> arms that peer and leaves this host unarmed, and says so"
else
  bad "--node <peer> does not arm this host" "exit $rc: $out
$(cat "$TMP/state/install-calls" 2>/dev/null)"; fi
: > "$TMP/state/install-calls"
rm -f "$TMP/stub-body.path"
out="$(run_fleet_arm --node aggregator-here)"; rc=$?
if [[ $rc -eq 0 ]] && grep -qF -- "-o root -g root -m 0600 /dev/null $AGGETC/model-key.arm" "$TMP/state/install-calls" \
   && [[ ! -f "$TMP/stub-body.path" ]] && grep -q 'is this host, and it is armed above' <<<"$out"; then
  ok "--node <this host's label> arms this host by its marker and posts to nobody"
else
  bad "--node <self> arms self only" "exit $rc: $out"; fi

# A node still on a build from before the fleet-write API answers the arm with
# a login redirect. That is a stale node, not a key it was never given, and
# the advice must say update, not --trust-arm-key: on that node the installer
# does not know the flag either (stock-node2, 2026-09-03).
: > "$TMP/stub-body.stale"
out="$(run_fleet_arm --node stock-node1)"; rc=$?
if [[ $rc -ne 0 ]] \
   && grep -q '^refused stock-node1: its dashboard has no fleet write API (HTTP 302); it runs a build older than this feature$' <<<"$out" \
   && grep -q 'update' <<<"$out" && ! grep -q -- '--trust-arm-key' <<<"$out"; then
  ok "a node on a build without the fleet write API is named as stale, and told to update, not to trust a key"
else
  bad "a stale node is named as stale" "exit $rc: $out"; fi
rm -f "$TMP/stub-body.stale"

# A node whose sealer refused says WHY, and that sentence has to survive the
# hop back. The class alone reads as "refused stock-node1: refused", which
# sends an operator nowhere: the reason a node gives is the whole value of
# refusing by name.
: > "$TMP/stub-body.refused"
out="$(run_fleet_arm --node stock-node1)"; rc=$?
if [[ $rc -ne 0 ]] \
   && grep -q '^refused stock-node1: refused: that arm token is addressed to another node' <<<"$out"; then
  ok "a node's own refusal reaches the aggregator with the sentence, not just the class"
else
  bad "the node's reason survives the hop" "exit $rc: $out"; fi
rm -f "$TMP/stub-body.refused"

# Now the other end. The sealer here trusts the aggregator's key, and is given
# exactly what the aggregator sent: the token text and its signature.
openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -out "$ARMPUB" 2>/dev/null
chmod 0644 "$ARMPUB"
python3 - "$TMP/stub-body" "$TMP/chain-token" "$TMP/chain-sig" <<'PYEOF'
import base64, json, sys
j = json.load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(j["token"])
open(sys.argv[3], 'wb').write(base64.b64decode(j["signature"]))
PYEOF
reset_arm
out="$(printf 'arm\n%s\n%s\n' "$(base64 -w0 < "$TMP/chain-token")" "$(base64 -w0 < "$TMP/chain-sig")" | run_arm 2>/dev/null)"; rc=$?
if [[ $rc -eq 0 && "$out" == $'armed=1\nwindow_s=900\nissuer=aggregator-here\nexit=0' ]]; then
  ok "a token minted on the aggregator and sent as it sends it opens a window here"
else
  bad "the chain works end to end" "exit $rc: $out"; fi
# And the same token cannot do it twice, which is the property the whole
# nonce file exists for, asserted against a real token rather than a made one.
rm -f "$ARM"
out="$(printf 'arm\n%s\n%s\n' "$(base64 -w0 < "$TMP/chain-token")" "$(base64 -w0 < "$TMP/chain-sig")" | run_arm 2>&1)"
if grep -q 'arm token already used' <<<"$out" && [[ ! -f "$ARM" ]]; then
  ok "and it opens exactly one: the same real token again is refused"
else
  bad "a real token is single use" "$out"; fi

echo
echo "── #720: paired first, Advisor second, armed from the aggregator ──"
#
# The order #720 was found in, on a real node (aperire4, 2026-09-29): the box
# pairs with no Advisor, so there is no sealer for --trust-arm-key; the
# Advisor goes on afterwards through its own one-liner, which runs this
# installer with --arm; then the aggregator arms it. Nothing in that order
# placed the key the pairing was handed, so the arm was refused with "this
# node trusts no fleet arm key" and the only way on was a root shell there.
#
# Every step below is the real program: this installer, the real sealer it
# installs, and aperire-fleet-arm.sh minting a token on the aggregator's own
# key. The last row is the one that is red without the fix.
HELD="$TMP/etc/fleet-arm.paired.pub"
AGG_PUB_B64="$(openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -outform DER | tail -c 32 | base64 -w0)"
AGG_ARM_FP="$(openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -outform DER | tail -c 32 | sha256sum | cut -c1-16)"
run_node_sealer() { # stdin is the payload; the files the installer wrote, nothing else
  env PATH="$TMP/bin:/usr/bin:/bin" \
      APERIRE_CRED_DIR="$CREDS" \
      APERIRE_ARM_FILE="$ARM" \
      APERIRE_UNIT_DIR="$UNITS" \
      APERIRE_FLEET_ARM_PUB="$TRUSTED_PUB" \
      APERIRE_FLEET_ARM_SEEN="$TRUSTED_SEEN" \
      APERIRE_NODE_KEY_FILE="$TRUSTED_NODE_KEY" \
      bash "$SUT"
}
# A fresh host: no sealer, nothing trusted, nothing held. The directory is
# stated 0755 rather than left to this runner's umask, because a trust
# directory group may write is exactly what the installer refuses.
fresh_host() { reset_install; rm -f "$SEALER_DEST" "$HELD"; chmod 0755 "$TMP/etc"; : > "$TMP/state/install-calls"; }

# 1. The pairing, on a host with no Advisor.
fresh_host
out="$(run_install --hold-arm-key "$AGG_PUB_B64")"; rc=$?
if [[ $rc -eq 0 && -f "$HELD" && "$(stat -c %a "$HELD")" == 644 && -O "$HELD" ]] \
   && [[ "$(openssl pkey -pubin -in "$HELD" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)" == "$AGG_PUB_B64" ]]; then
  ok "pairing holds the key on a host with no sealer: that key, 0644, owned by the account running it"
else
  bad "the pairing holds the arm key with no sealer on the host" "exit $rc: $out"; fi
if [[ ! -e "$TRUSTED_PUB" && ! -e "$SEALER_DEST" ]]; then
  ok "  and holding it trusts nothing: no fleet-arm.pub, and no sealer was installed by it"
else
  bad "holding a key trusts nothing" "$(ls -la "$TMP/etc" "$TMP/sbin" 2>&1)"; fi
if grep -q "fingerprint  $AGG_ARM_FP" <<<"$out"; then
  ok "  and it prints the aggregator's own fingerprint for that key"
else
  bad "hold prints the fingerprint the aggregator prints" "$out"; fi
out="$(run_install --trust-arm-key "$AGG_PUB_B64")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no sealer at' <<<"$out" && [[ ! -e "$TRUSTED_PUB" ]]; then
  ok "  and --trust-arm-key on that host still refuses for want of a sealer, as the pairing saw"
else
  bad "--trust-arm-key with no sealer is unchanged" "exit $rc: $out"; fi

# 2. The Advisor install, exactly as install-advisor-stack.sh runs it.
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && -f "$TRUSTED_PUB" ]] \
   && [[ "$(openssl pkey -pubin -in "$TRUSTED_PUB" -outform DER 2>/dev/null | base64 -w0)" == "$(openssl pkey -pubin -in "$HELD" -outform DER 2>/dev/null | base64 -w0)" ]]; then
  ok "the Advisor's own install places the held key as fleet-arm.pub, with no other command"
else
  bad "the grant install places the held key" "exit $rc: $out"; fi
# The call whose destination is fleet-arm.pub, not any 0644 call: the node-key
# stamp is written with the same flags in the same run.
if grep -qE -- "^-o root -g root -m 0644 [^ ]+ $TRUSTED_PUB\$" "$TMP/state/install-calls" \
   && grep -q "fingerprint  $AGG_ARM_FP" <<<"$out"; then
  ok "  root:root 0644, the way --trust-arm-key writes it, and the install says whose key it is"
else
  bad "the placed key is root-owned 0644 and fingerprinted" "$(cat "$TMP/state/install-calls") / $out"; fi

# 3. The aggregator arms it, and the node's own sealer honours the token.
#
# The suite's `install` records the mode it was asked for (asserted above)
# and does not apply it, so the two files it wrote carry this runner's umask.
# Set here to what install -m 0644 leaves on a host, which the sealer checks.
chmod 0644 "$TRUSTED_PUB" "$TRUSTED_NODE_KEY"
rm -f "$TMP/stub-body" "$ARM" "$ISSUER" "$TRUSTED_SEEN"
out="$(run_fleet_arm --node stock-node1)"; rc=$?
python3 - "$TMP/stub-body" "$TMP/chain720-token" "$TMP/chain720-sig" <<'PYEOF' 2>/dev/null
import base64, json, sys
j = json.load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(j["token"])
open(sys.argv[3], 'wb').write(base64.b64decode(j["signature"]))
PYEOF
out="$(printf 'arm\n%s\n%s\n' "$(base64 -w0 < "$TMP/chain720-token" 2>/dev/null)" "$(base64 -w0 < "$TMP/chain720-sig" 2>/dev/null)" | run_node_sealer 2>&1)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^armed=1$' <<<"$out" && [[ -f "$ARM" ]]; then
  ok "paired first, Advisor second: the aggregator's arm opens a window on the node, with no root shell there"
else
  bad "#720: a node paired before its Advisor is armable from the aggregator" "exit $rc: $out"; fi

echo
echo "── #723: paired to an aggregator that had never armed ─────────────"
#
# The case #720 could not reach: the aggregator had no arm key when the node
# paired, so the settlement carried none and there was nothing to hold. Since
# #723 the broker's approval makes the key. The maker is taken out of the
# REAL broker by its markers, so this row runs the code an approval runs, and
# then everything after it is the same real chain as #720's: hold, the
# Advisor's install, a token cut on the aggregator, the node's own sealer.
AGGETC_720="$AGGETC"
AGGETC="$TMP/aggetc723"
rm -rf "$AGGETC"; mkdir -p "$AGGETC"; chmod 0755 "$AGGETC"
printf 'INSTALL_DIR=%s\n' "$REPO_DIR" > "$AGGETC/fleet-broker.conf"; chmod 644 "$AGGETC/fleet-broker.conf"
sed -n '/^# ---- BEGIN ensure_fleet_arm_key/,/^# ---- END ensure_fleet_arm_key/p' \
  "$REPO_DIR/scripts/aperire-fleet-broker.sh" > "$TMP/ensure723.sh"
made="$(bash -c '. "$1"; ensure_fleet_arm_key "$2" && echo "made=$FLEET_ARM_KEY_MADE"' _ "$TMP/ensure723.sh" "$AGGETC/fleet-arm.key" 2>&1 || true)"
PUB723="$(openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 || true)"
if [[ "$made" == "made=1" && -n "$PUB723" ]]; then
  ok "the approval's own maker makes the aggregator's arm key on a host that has none"
else
  bad "#723: the broker makes the arm key at approval" "$made"; fi
fresh_host
run_install --hold-arm-key "$PUB723" >/dev/null 2>&1 || true
run_install --arm >/dev/null 2>&1 || true
chmod 0644 "$TRUSTED_PUB" "$TRUSTED_NODE_KEY" 2>/dev/null || true
rm -f "$TMP/stub-body" "$ARM" "$ISSUER" "$TRUSTED_SEEN"
FP723="$(openssl pkey -in "$AGGETC/fleet-arm.key" -pubout -outform DER 2>/dev/null | tail -c 32 | sha256sum | cut -c1-16)"
out="$(run_fleet_arm --node stock-node1)"; rc=$?
# Positive halves first (#743 review, L4): a run that failed outright also
# prints no "made now", so the absence alone proved nothing.
if [[ $rc -eq 0 ]] && grep -qF "== Fleet arm key $FP723" <<<"$out" && ! grep -q 'made now' <<<"$out"; then
  ok "  and aperire-fleet-arm.sh signs with that key ($FP723) rather than claiming to make one"
else
  bad "the arm script uses the approval's key" "exit $rc, expected fingerprint $FP723: $out"; fi
python3 - "$TMP/stub-body" "$TMP/chain723-token" "$TMP/chain723-sig" <<'PYEOF' 2>/dev/null
import base64, json, sys
j = json.load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(j["token"])
open(sys.argv[3], 'wb').write(base64.b64decode(j["signature"]))
PYEOF
out="$(printf 'arm\n%s\n%s\n' "$(base64 -w0 < "$TMP/chain723-token" 2>/dev/null)" "$(base64 -w0 < "$TMP/chain723-sig" 2>/dev/null)" | run_node_sealer 2>&1)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^armed=1$' <<<"$out" && [[ -f "$ARM" ]]; then
  ok "  a node paired to an aggregator that had never armed is armable from it, with no root shell there"
else
  bad "#723: a node paired before the aggregator's first arm is armable from it" "exit $rc: $out"; fi
AGGETC="$AGGETC_720"

echo
echo "── the held key: what it refuses, and what it never overwrites ────"

# A key trusted by hand is never replaced by one a pairing held, and the
# install that finds them disagreeing still installs the grant: its exit
# status is what install-advisor-stack.sh reads as "the browser can seal".
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
openssl pkey -in "$OTHERKEY" -pubout -out "$TRUSTED_PUB" 2>/dev/null
before="$(sha256sum < "$TRUSTED_PUB")"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && "$(sha256sum < "$TRUSTED_PUB")" == "$before" ]] && grep -q 'left as it is' <<<"$out"; then
  ok "a different fleet-arm.pub is left exactly as it is, said out loud, and the grant install still succeeds"
else
  bad "a trusted key is never replaced by a held one" "exit $rc: $out"; fi

# A host whose node cannot say who it is does not get a key that makes tokens
# believable (#184). The grant still installs; --refresh-node-key places it.
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
write_wconf "$RPC_DEAD"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && ! -e "$TRUSTED_PUB" ]] && grep -q 'not placed yet' <<<"$out" \
   && grep -q -- '--refresh-node-key' <<<"$out"; then
  ok "no node key: the held key is not placed, the grant still installs, and the way on is named"
else
  bad "a host with no node key does not place the held key" "exit $rc: $out"; fi
write_wconf "http://127.0.0.1:$RPC_PORT"
out="$(run_install --refresh-node-key)"; rc=$?
if [[ $rc -eq 0 && -f "$TRUSTED_PUB" ]] && grep -q "fingerprint  $AGG_ARM_FP" <<<"$out"; then
  ok "  and --refresh-node-key places it once the node answers"
else
  bad "--refresh-node-key places the held key" "exit $rc: $out"; fi

# Read on descriptors: a link, or a file somebody else may write, is not a
# key root trusts. Each one leaves no fleet-arm.pub and a grant that installed.
fresh_host
openssl pkey -in "$OTHERKEY" -pubout -out "$TMP/attacker.pub" 2>/dev/null
ln -s "$TMP/attacker.pub" "$HELD"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && ! -e "$TRUSTED_PUB" ]] && grep -q 'symbolic link' <<<"$out"; then
  ok "a held key that is a symlink is not followed and not placed"
else
  bad "a symlinked held key is refused" "exit $rc: $out"; fi
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
chmod 0664 "$HELD"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && ! -e "$TRUSTED_PUB" ]] && grep -q 'group or others may write' <<<"$out"; then
  ok "a held key group may write is not placed"
else
  bad "a group-writable held key is refused" "exit $rc: $out"; fi
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
ln "$HELD" "$TMP/held-second-name"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && ! -e "$TRUSTED_PUB" ]] && grep -q 'has 2 names' <<<"$out"; then
  ok "a held key with a second name is not placed"
else
  bad "a hard-linked held key is refused" "exit $rc: $out"; fi
rm -f "$TMP/held-second-name"

# --hold-arm-key itself: the same checks as --trust-arm-key, and the same
# refusal to replace a different key.
fresh_host
# The text of the key, because that is what this flag takes: the pairing
# hands it the base64 it was sent, never a path.
out="$(run_install --hold-arm-key "$(cat "$ARMKEY")")"; rc=$?
if [[ $rc -ne 0 && ! -e "$HELD" ]] && grep -q 'PRIVATE key' <<<"$out"; then
  ok "--hold-arm-key refuses a private key by name, and writes nothing"
else
  bad "a private key is never held" "exit $rc: $out"; fi
out="$(run_install --hold-arm-key "not a key at all")"; rc=$?
if [[ $rc -ne 0 && ! -e "$HELD" ]]; then
  ok "  and text that is not a key"
else
  bad "rubbish is never held" "exit $rc: $out"; fi
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
before="$(sha256sum < "$HELD")"
out="$(run_install --hold-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -ne 0 && "$(sha256sum < "$HELD")" == "$before" ]] && grep -q 'already holds a different arm key' <<<"$out"; then
  ok "a different key is refused, never replaced, and the held one is untouched"
else
  bad "a held key is not replaced by another" "exit $rc: $out"; fi
out="$(run_install --hold-arm-key "$AGG_PUB_B64")"; rc=$?
if [[ $rc -eq 0 && "$(sha256sum < "$HELD")" == "$before" ]] && grep -q 'already holds that key' <<<"$out"; then
  ok "the same key again is a no-op, which is what a re-pair to the same aggregator is"
else
  bad "holding the same key twice is idempotent" "exit $rc: $out"; fi
fresh_host
chmod 0775 "$TMP/etc"
out="$(run_install --hold-arm-key "$AGG_PUB_B64")"; rc=$?
chmod 0755 "$TMP/etc"
if [[ $rc -ne 0 && ! -e "$HELD" ]] && grep -q 'group or others may write' <<<"$out"; then
  ok "a trust directory group may write is refused before anything is held in it"
else
  bad "--hold-arm-key refuses a group-writable directory" "exit $rc: $out"; fi
out="$(run_install --hold-arm-key "$AGG_PUB_B64" --arm)"; rc=$?
if [[ $rc -eq 2 && ! -e "$HELD" && ! -e "$SEALER_DEST" ]]; then
  ok "--hold-arm-key with anything else is refused, and neither half happens"
else
  bad "--hold-arm-key is a run of its own" "exit $rc: $out"; fi

# A write that fails is a failure on both paths, never a key reported as
# trusted. Both writers run as `f || ...`, where bash turns errexit off inside
# the function, so this is checked by hand there and asserted here.
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
printf '%s' "$TRUSTED_PUB" > "$TMP/state/install-fail"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && ! -e "$TRUSTED_PUB" ]] && grep -q "not placed: could not write $TRUSTED_PUB" <<<"$out" \
   && ! grep -q 'can now open a sealing window' <<<"$out"; then
  ok "a placement whose write fails says so, claims nothing, and the grant still installs"
else
  bad "a failed placement write is reported as a failure" "exit $rc: $out"; fi
out="$(run_install --trust-arm-key "$AGG_PUB_B64")"; rc=$?
rm -f "$TMP/state/install-fail"
if [[ $rc -ne 0 && ! -e "$TRUSTED_PUB" ]] && grep -q "could not write $TRUSTED_PUB" <<<"$out" \
   && ! grep -q '^ *fingerprint ' <<<"$out"; then
  ok "  and --trust-arm-key whose write fails exits non-zero and prints no fingerprint"
else
  bad "a failed --trust-arm-key write is a failure" "exit $rc: $out"; fi

# #720 review, M1: a rotation done on the node is not undone by a reinstall.
# Hold A1, place it, rotate to A2 by hand (remove fleet-arm.pub, trust A2),
# --remove, reinstall. The held copy must have followed to A2, or the
# reinstall silently trusts A1 again.
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
run_install --arm >/dev/null 2>&1
rm -f "$TRUSTED_PUB"
out="$(run_install --trust-arm-key "$ARMPUB_B64")"; rc=$?
if [[ $rc -eq 0 ]] && [[ "$(openssl pkey -pubin -in "$HELD" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)" == "$ARMPUB_B64" ]]; then
  ok "a key trusted by hand rewrites the held copy to match"
else
  bad "the held copy follows --trust-arm-key" "exit $rc: $out / held $(openssl pkey -pubin -in "$HELD" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)"; fi
run_install --remove >/dev/null 2>&1
make_socket
: > "$TMP/state/active"
out="$(run_install --arm)"; rc=$?
got="$(openssl pkey -pubin -in "$TRUSTED_PUB" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)"
if [[ $rc -eq 0 && "$got" == "$ARMPUB_B64" ]]; then
  ok "  and rotate, --remove, reinstall trusts the rotated key, never the one the pairing first held"
else
  bad "a rotation survives --remove and reinstall" "trusted '$got', wanted the rotated key; exit $rc: $out"; fi

# --remove takes the trust away and keeps what the pairing handed over, so a
# node that is still paired and gets its Advisor back is armable again.
fresh_host
run_install --hold-arm-key "$AGG_PUB_B64" >/dev/null 2>&1
run_install --arm >/dev/null 2>&1
out="$(run_install --remove)"; rc=$?
if [[ $rc -eq 0 && ! -e "$TRUSTED_PUB" && -f "$HELD" ]] && grep -q "kept $HELD" <<<"$out"; then
  ok "--remove takes fleet-arm.pub away, keeps the pairing's held key, and says so"
else
  bad "--remove keeps the held key and says it did" "exit $rc: $out"; fi
make_socket
: > "$TMP/state/active"
out="$(run_install --arm)"; rc=$?
if [[ $rc -eq 0 && -f "$TRUSTED_PUB" ]] && grep -q "fingerprint  $AGG_ARM_FP" <<<"$out"; then
  ok "  and an Advisor installed again places it again, with its fingerprint on screen"
else
  bad "reinstalling after --remove places the held key again" "exit $rc: $out"; fi
rm -f "$HELD"

kill "$STUB_PID" "$RPC_PID" 2>/dev/null
wait "$STUB_PID" "$RPC_PID" 2>/dev/null

echo
echo
echo "── a host with no systemd-creds: the key is kept, not refused (#708) ─"

# Ubuntu 22.04 ships systemd 249, which has neither systemd-creds nor
# LoadCredentialEncrypted=. Every seal on such a host used to be refused with
# "systemd-creds could not seal the key on this host", so the node installed,
# paired, and could never hold a model. The fallback keeps the key as a
# root-only file and loads it with LoadCredential=, under the SAME credential
# name, so the Advisor reads $CREDENTIALS_DIRECTORY/<name> exactly as before.
PLAIN_CRED="$CREDS/model-api-key-xai.plain"
SEALED_CRED="$CREDS/model-api-key-xai"

reset_state
: > "$TMP/state/systemd-249"
arm_now
status_doc false true grok-4
out="$(payload | run_seal)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^method=plain$' <<<"$out"; then
  ok "a 249 host seals, and says which of the two methods it used"
else
  bad "a 249 host seals" "exit $rc: $out"; fi
if [[ -f "$PLAIN_CRED" && ! -f "$SEALED_CRED" ]]; then
  ok "the key is at <name>.plain, and there is no blob at <name> beside it"
else
  bad "the key lands at the plain path" "$(ls -a "$CREDS")"; fi
if [[ "$(stat -c '%a' "$PLAIN_CRED" 2>/dev/null)" == 600 ]]; then
  ok "and it is mode 0600"
else
  bad "the key file is 0600" "$(stat -c '%a %U:%G' "$PLAIN_CRED" 2>/dev/null)"; fi
if [[ -O "$PLAIN_CRED" ]]; then
  ok "and owned by the account that sealed it, which on a host is root"
else
  bad "the key file is owned by the sealing account" "$(stat -c '%U:%G' "$PLAIN_CRED" 2>/dev/null)"; fi
if [[ "$(cat "$PLAIN_CRED")" == "$THEKEY" ]] && [[ "$(wc -c < "$PLAIN_CRED")" -eq "${#THEKEY}" ]]; then
  ok "and it holds exactly the key that was sent, with nothing added to it"
else
  bad "the key file holds the key verbatim" "$(wc -c < "$PLAIN_CRED") bytes"; fi
if grep -qx "LoadCredential=model-api-key-xai:$PLAIN_CRED" "$DROPIN"; then
  ok "the drop-in loads it with LoadCredential=, under the same credential name"
else
  bad "the drop-in uses LoadCredential=" "$(cat "$DROPIN" 2>/dev/null)"; fi
if ! grep -q 'LoadCredentialEncrypted' "$DROPIN"; then
  ok "and never names a directive this systemd has not heard of"
else
  bad "no LoadCredentialEncrypted= on a 249 host" "$(cat "$DROPIN")"; fi
if [[ ! -s "$TMP/state/creds-argv" ]]; then
  ok "and systemd-creds was never called, because there is none to call"
else
  bad "systemd-creds is not called on the fallback" "$(cat "$TMP/state/creds-argv")"; fi
if grep -q 'sealed:.*method plain' "$TMP/state/journal" 2>/dev/null; then
  ok "the journal line says which method this host used"
else
  bad "the journal names the method" "$(cat "$TMP/state/journal" 2>/dev/null)"; fi
if ! grep -q 'could not seal' <<<"$out"; then
  ok "and nothing anywhere says the key could not be sealed on a supported host"
else
  bad "a supported host is never told the key could not be sealed" "$out"; fi
if [[ -f "$ADVSTATE/model.json" ]] && grep -q '"credential_name": "model-api-key-xai"' "$ADVSTATE/model.json"; then
  ok "and the config names the credential, not the path, so the Advisor is unchanged"
else
  bad "the config is written the same way" "$(cat "$ADVSTATE/model.json" 2>/dev/null)"; fi

# --reset has to take the form this host actually wrote. A reset that only
# knew the sealed name would report the key removed and leave it on disk,
# which for a key in the clear is the whole of the problem.
out="$(run_reset)"; rc=$?
if [[ ! -e "$PLAIN_CRED" ]]; then
  ok "--reset removes the plain key file too"
else
  bad "--reset removes the plain key" "$PLAIN_CRED is still here"; fi
if grep -q 'reset=model-api-key-xai' <<<"$out"; then
  ok "and names the credential it removed"
else
  bad "the reset names what it removed" "$out"; fi

# The other direction: a host that kept a key in the clear and then gained
# systemd-creds (an in-place OS upgrade) must not be left with a live key
# sitting beside the blob that replaced it.
reset_state
: > "$TMP/state/systemd-249"
arm_now
status_doc false true grok-4
payload | run_seal >/dev/null
rm -f "$TMP/state/systemd-249"
arm_now
out="$(payload | run_seal)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^method=sealed$' <<<"$out"; then
  ok "the same host on 255 seals with systemd-creds instead"
else
  bad "a 255 host seals with systemd-creds" "exit $rc: $out"; fi
if [[ -f "$SEALED_CRED" && ! -e "$PLAIN_CRED" ]]; then
  ok "and the plaintext key from the older systemd is removed, not left beside it"
else
  bad "a seal removes the other form" "$(ls -a "$CREDS")"; fi

echo
echo "── no plaintext key outlives the name that held it (#712 review M1) ─"

# A key kept in the clear is a WORKING key, wherever the file ends up. Two
# ways one used to be left behind on a 22.04 host, both proven in review:
#
#   1. a provider switch. The seal removes the other FORM of the same name,
#      so sealing xai and then anthropic left model-api-key-xai.plain sitting
#      in the store with nothing naming it and nothing that would ever remove
#      it, because --reset only knows the names the config and the drop-in
#      carry.
#   2. a quarantine. The credential check and the installer move a bad key
#      aside as <name>.plain.unopenable-<ts>-<pid>, and "bad" there can mean
#      a widened mode on a perfectly good key.
#
# So a successful seal, and a reset, each sweep every plaintext key in the
# store the name now in hand does not claim. A sealed blob is not swept: it
# is ciphertext bound to this machine and inert anywhere else.
xai_payload()  { printf 'https://api.x.ai/v1\nopenai\ngrok-4\nmodel-api-key-xai\n%s\n' "$THEKEY"; }
ant_payload()  { printf 'https://api.anthropic.com\nanthropic\nclaude-opus-4-7\nmodel-api-key-anthropic\n%s\n' "$THEKEY"; }

reset_state
: > "$TMP/state/systemd-249"
arm_now
status_doc false true grok-4
xai_payload | run_seal >/dev/null
arm_now
out="$(ant_payload | run_seal)"; rc=$?
if [[ $rc -eq 0 && -f "$CREDS/model-api-key-anthropic.plain" ]]; then
  ok "a provider switch seals the new key"
else
  bad "the second seal succeeds" "exit $rc: $out"; fi
if [[ ! -e "$CREDS/model-api-key-xai.plain" ]]; then
  ok "and the previous provider's plaintext key is gone, not left in the store"
else
  bad "a seal sweeps an older name's plaintext key" "$(ls -a "$CREDS")"; fi
if grep -q '^swept=' <<<"$out"; then
  ok "and the sweep is reported, so a removal is never silent"
else
  bad "the seal says what it swept" "$out"; fi

# The quarantine shape, which no name in the config or the drop-in ever
# claims, and which --reset used to leave behind for good.
reset_state
: > "$TMP/state/systemd-249"
arm_now
status_doc false true grok-4
xai_payload | run_seal >/dev/null
printf 'xai-aquarantinedbutworkingkey' > "$CREDS/model-api-key-anthropic.plain.unopenable-1700000000-999"
printf 'xai-anoldproviderskey' > "$CREDS/model-api-key-openai.plain"
out="$(run_reset)"; rc=$?
if [[ ! -e "$CREDS/model-api-key-xai.plain" ]]; then
  ok "--reset removes the key it was holding"
else
  bad "--reset removes the current key" "$(ls -a "$CREDS")"; fi
if [[ ! -e "$CREDS/model-api-key-openai.plain" ]]; then
  ok "and a plaintext key under a name nothing declares any more"
else
  bad "--reset sweeps an unclaimed plaintext key" "$(ls -a "$CREDS")"; fi
if ! compgen -G "$CREDS/*.plain.unopenable-*" >/dev/null; then
  ok "and a quarantined plaintext key, which is a working key with a longer name"
else
  bad "--reset sweeps a quarantined plaintext key" "$(ls -a "$CREDS")"; fi

# The sealed form is NOT swept: ciphertext bound to this machine is not a key
# anywhere else, and a host that changes provider has always kept the old
# blob. Sweeping it would be this program deleting evidence it has no reason
# to touch.
reset_state
arm_now
status_doc false true grok-4
xai_payload | run_seal >/dev/null
arm_now
ant_payload | run_seal >/dev/null
if [[ -f "$CREDS/model-api-key-xai" && -f "$CREDS/model-api-key-anthropic" ]]; then
  ok "on a host that seals, the older provider's blob is left where it was"
else
  bad "a sealed blob is never swept" "$(ls -a "$CREDS")"; fi

# And the name rule closes the one way the two forms could be confused.
reset_state
arm_now
status_doc false true grok-4
out="$(printf 'https://api.x.ai/v1\nopenai\ngrok-4\nmodel-api-key.plain\n%s\n' "$THEKEY" | run_seal)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'refused' <<<"$out"; then
  ok "a credential name ending in .plain is refused: that suffix is this store's own"
else
  bad "a .plain credential name is refused" "exit $rc: $out"; fi
if [[ "$(credential_count)" -eq 0 ]]; then
  ok "and nothing was written on the way to refusing it"
else
  bad "the .plain refusal writes nothing" "$(ls "$CREDS")"; fi

echo "── a refused install tree, on both paths (#703 review) ────────────"

# What this measures, and why it is two rows and not one.
#
# The ancestor rule refuses a state directory whose parents an account other
# than root or the owner can write. A real aggregator was in that state. The
# rule is right, and the two ways this program met it were both wrong:
#
#   SEAL   the config is planted LAST, after the credential and the drop-in.
#          A layout discovered at that write left the host with a credential
#          and a directive and no config, and "re-run this seal" failed at
#          the same step for ever.
#   RESET  the first thing the refusal breaks is the READ of this host's own
#          token, and a read that could not happen was indistinguishable from
#          "there is no token", which the window check treats as "no window is
#          open". So it failed OPEN: curl was never called, and the key came
#          off under an operator who was mid-ceremony.
#
# Both are now asked up front, before anything is written or removed. These
# rows assert the WHOLE-HOST outcome, not the message: nothing written on the
# seal, nothing removed on the reset.
#
# The stand-in for the layout is the same one the shape suite uses: a group
# this account is in that has members other than the directory's owner. No
# root needed, and it is the only property the rule reads.
layout_group="$(id -Gn | tr ' ' '\n' | grep -vx -e "$(id -un)" | head -1 || true)"
if [[ -z "$layout_group" ]]; then
  bad "this account is in a second group, so a refused layout can be built" \
      "id -Gn gave only $(id -gn); these rows did not run"
else
  BADTREE="$TMP/badtree"
  rm -rf "$BADTREE"; mkdir -p "$BADTREE/advisor/state"
  chgrp "$layout_group" "$BADTREE/advisor"; chmod 0775 "$BADTREE/advisor"
  BADSTATE="$BADTREE/advisor/state"
  printf 'advisor-token-for-tests\n' > "$BADSTATE/approve.token"
  printf '[Unit]\n\n[Service]\nExecStart=/bin/true --addr=127.0.0.1:7810 --state=%s\n' \
    "$BADSTATE" > "$UNITFILE"
  rm -rf "$UNITFILE.d"; rm -f "$CREDS"/* 2>/dev/null
  : > "$ARM"; chmod 0600 "$ARM"

  out="$(printf '%s\n' "https://api.x.ai/v1" openai grok-4 model-api-key-xai "xai-$(printf 'A%.0s' {1..30})" \
         | env PATH="$TMP/bin:/usr/bin:/bin" APERIRE_CRED_DIR="$CREDS" \
               APERIRE_ARM_FILE="$ARM" APERIRE_UNIT_DIR="$UNITS" bash "$SUT" 2>&1)"
  if grep -q 'curl -fsSL https://get.aperire.one | bash -s -- --update --force' <<<"$out" && ! grep -q 'scripts/fix-state-ancestors.sh' <<<"$out" && grep -q '^exit=1' <<<"$out"; then
    ok "a seal onto a refused install tree is refused, and names the update that repairs it"
  else
    bad "a refused layout refuses the seal" "$(tail -3 <<<"$out")"
  fi
  # The whole point: nothing moved. A credential or a drop-in here is the
  # half-seal this closes.
  if [[ -z "$(ls -A "$CREDS" 2>/dev/null)" && ! -e "$DROPIN" && ! -e "$BADSTATE/model.json" ]]; then
    ok "and it wrote no credential, no drop-in and no config, so there is nothing half done"
  else
    bad "a refused seal leaves the host as it was" \
        "creds=[$(ls "$CREDS" 2>/dev/null)] dropin=$([[ -e $DROPIN ]] && echo yes || echo no)"
  fi

  # RESET, on a host that IS sealed, with a window open. The status document
  # says open:true, so a reset that ever reached the service would refuse on
  # the window; the failure this catches is the one that never asks.
  mkdir -p "$UNITFILE.d"
  printf '[Service]\nLoadCredentialEncrypted=model-api-key-xai:%s/model-api-key-xai\n' \
    "$CREDS" > "$DROPIN"
  printf 'SEALED\n' > "$CREDS/model-api-key-xai"
  printf '{\n  "enabled": true,\n  "credential_name": "model-api-key-xai"\n}\n' > "$BADSTATE/model.json"
  rm -f "$TMP/state/curl-calls"
  out="$(env PATH="$TMP/bin:/usr/bin:/bin" APERIRE_CRED_DIR="$CREDS" \
             APERIRE_ARM_FILE="$ARM" APERIRE_UNIT_DIR="$UNITS" \
             bash "$SUT" --reset 2>&1)"
  if grep -q 'curl -fsSL https://get.aperire.one | bash -s -- --update --force' <<<"$out" && ! grep -q 'scripts/fix-state-ancestors.sh' <<<"$out" && grep -q '^exit=1' <<<"$out"; then
    ok "a --reset on a refused install tree is refused too"
  else
    bad "a refused layout refuses the reset" "$(tail -3 <<<"$out")"
  fi
  if [[ -e "$CREDS/model-api-key-xai" && -e "$DROPIN" ]]; then
    ok "and the credential and the drop-in are still there: nothing was removed"
  else
    bad "a refused reset removes nothing" \
        "cred=$([[ -e $CREDS/model-api-key-xai ]] && echo yes || echo no) dropin=$([[ -e $DROPIN ]] && echo yes || echo no)"
  fi
  # The refusal has to come BEFORE the window question, not instead of an
  # answer to it. Nothing was asked of the service, and nothing claims to
  # know whether a window is open.
  if ! grep -qi 'no break-glass window was open' <<<"$out"; then
    ok "and it never claims the window was closed, which is what it could not know"
  else
    bad "a refused reset makes no claim about the window" "$out"
  fi
  rm -rf "$BADTREE"; rm -f "$CREDS"/* "$DROPIN" 2>/dev/null; rm -rf "$UNITFILE.d"
fi

# #898 review, N6: the waiting note skips the restart only while the unit is
# not running. A unit that still carries it but is up (an account step
# interrupted after its grants, then a reboot) holds the old key in memory, so
# a reset or a seal has to restart it, or the host reports service=active on
# a key that was meant to be gone.
NOTE_SED='s/^\[Unit\]$/&\n# Waiting for install-advisor-account.sh, which makes the account and starts it (#893)./'
seal_one
: > "$TMP/state/active"
sed -i "$NOTE_SED" "$UNITFILE"
status_doc false false
out="$(run_reset)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'restart aperire-advisord' "$TMP/state/systemctl-calls" && [[ "$(credential_count)" -eq 0 ]]
then ok "a reset on a RUNNING unit that carries the waiting note restarts it"
else bad "a reset restarts a running unit whatever its note says" "exit $rc: restarts=$(grep -c 'restart aperire-advisord' "$TMP/state/systemctl-calls"); $(grep -E '^(service|exit)=' <<<"$out")"; fi
seal_one
rm -f "$TMP/state/active"
sed -i "$NOTE_SED" "$UNITFILE"
status_doc false false
out="$(run_reset)"; rc=$?
# Exit 1 here is the read-back saying the service is not running, which is
# true; what this row holds is that nothing was started to make it say more.
if ! grep -q 'restart aperire-advisord' "$TMP/state/systemctl-calls" && [[ "$(credential_count)" -eq 0 ]] \
   && grep -q '^service=inactive$' <<<"$out"
then ok "a reset on a STOPPED unit that carries the waiting note starts nothing"
else bad "a reset leaves a waiting, stopped unit stopped" "exit $rc: $(cat "$TMP/state/systemctl-calls")"; fi
reset_state
: > "$TMP/state/active"
sed -i "$NOTE_SED" "$UNITFILE"
arm_now
out="$(payload | run_seal 2>/dev/null)"
if grep -q '^sealed=' <<<"$out" && grep -q 'restart aperire-advisord' "$TMP/state/systemctl-calls"
then ok "a seal on a RUNNING unit that carries the waiting note restarts it"
else bad "a seal restarts a running unit whatever its note says" "$(cat "$TMP/state/systemctl-calls")"; fi

echo
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
