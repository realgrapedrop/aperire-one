#!/usr/bin/env bash
# Exercise scripts/preflight.sh, the prerequisite check the install runs first.
#
# What is being protected: this is the one screen an operator reads before
# anything on their box changes, and every line of it is a claim about their
# host. Three ways it can quietly stop being true.
#
#   1. A check that cannot fail. Every row below has its opposite beside it:
#      the same check, the same stubs, one measurement moved, and the verdict
#      has to change. A check that says ok on a host with 2 GB free is worse
#      than no check, because the install stops later anyway and now the
#      operator has been told twice that it would not.
#   2. A verdict that blocks when it should not, or waves through when it
#      should not. warn never blocks. MISSING always does, and --yes does not
#      skip it. A dashboard-only host has no node on it BY DEFINITION, so the
#      node question warns there and refuses on the two roles that mean the
#      node is here.
#   3. The node answer not arriving. The probe can end with an operator
#      typing a port, and that answer travels through a file into
#      APERIRE_RIPPLED_URL and into /etc/aperire/aperire.env. Every hop is
#      silent when it breaks.
#
#   bash scripts/test-preflight.sh
#
# Runs in a temporary directory against fake ss, systemctl, timedatectl, df,
# free, docker, pgrep, curl, sudo and apt-get on PATH, and against REAL
# servers on ports the kernel hands out: a WebSocket that completes the
# handshake and answers server_info, an HTTP one that answers it over RPC, and
# a socket that accepts and says nothing. Touches no host, needs no root, and
# installs nothing.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUT="$REPO_DIR/scripts/preflight.sh"
TMP=$(mktemp -d)

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$SUT" ]] || { echo "no preflight.sh at $SUT"; exit 1; }
command -v python3 >/dev/null 2>&1 \
  || { echo "this test needs python3: it stands real servers up to probe"; exit 1; }
command -v script >/dev/null 2>&1 \
  || { echo "this test needs 'script' (util-linux) to give a run a terminal"; exit 1; }

REAL_CURL="$(command -v curl)"
[[ -n "$REAL_CURL" ]] || { echo "this test needs curl on PATH"; exit 1; }
# The real one, for the row that counts leftover stubs: a fake pgrep goes on
# PATH below, and a count read through it would always be zero.
REAL_PGREP="$(command -v pgrep)"
[[ -n "$REAL_PGREP" ]] || { echo "this test needs pgrep (procps) on PATH"; exit 1; }

mkdir -p "$TMP/bin" "$TMP/state" "$TMP/etc" "$TMP/home"

# ── The fake node ───────────────────────────────────────────────────
# Three modes on a port the kernel picks, so nothing here has to bind 6006 on
# the machine running the suite.
#
#   ws     completes the RFC 6455 handshake and answers one server_info frame
#   rpc    answers a server_info POST the way the admin RPC port does
#   quiet  accepts the connection and says nothing, which is every other
#          service on the box and is what "listening" must not be read as
cat > "$TMP/fakenode.py" <<'PY'
import base64, hashlib, json, os, socket, struct, sys, threading, time

mode, portfile = sys.argv[1], sys.argv[2]
# The suite's own pid, and a ceiling. A stub outlives nothing that started
# it: it goes when that shell is gone (a suite killed by a timeout or a
# SIGKILL runs no trap), and in any case after ten minutes, which is many
# times a full run.
watch_pid = int(sys.argv[3]) if len(sys.argv) > 3 else 0
max_s = float(os.environ.get("FAKENODE_MAX_S", "600"))


def watchdog():
    started = time.monotonic()
    while True:
        time.sleep(0.5)
        if watch_pid:
            try:
                os.kill(watch_pid, 0)
            except ProcessLookupError:
                os._exit(0)
            except PermissionError:
                pass
        if time.monotonic() - started > max_s:
            os._exit(0)


threading.Thread(target=watchdog, daemon=True).start()
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
INFO = {"build_version": "3.3.0", "server_state": "proposing"}

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
with open(portfile, "w") as fh:
    fh.write(str(srv.getsockname()[1]))


def read_head(c):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = c.recv(4096)
        if not chunk:
            return None, None
        data += chunk
        if len(data) > 65536:
            return None, None
    head, _, rest = data.partition(b"\r\n\r\n")
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return hdrs, rest


def handle(c):
    c.settimeout(5)
    try:
        if mode == "quiet":
            c.recv(4096)
            return
        hdrs, _ = read_head(c)
        if hdrs is None:
            return
        if mode == "ws":
            key = hdrs.get(b"sec-websocket-key", b"")
            acc = base64.b64encode(hashlib.sha1(key + GUID).digest()).decode()
            c.sendall((
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n" % acc).encode())
            b0 = c.recv(2)
            if len(b0) < 2:
                return
            ln = b0[1] & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", c.recv(2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", c.recv(8))[0]
            if b0[1] & 0x80:
                c.recv(4)
            got = b""
            while len(got) < ln:
                chunk = c.recv(ln - len(got))
                if not chunk:
                    break
                got += chunk
            payload = json.dumps(
                {"result": {"info": INFO}, "status": "success", "type": "response"}).encode()
            hdr = b"\x81"
            if len(payload) < 126:
                hdr += bytes([len(payload)])
            else:
                hdr += bytes([126]) + struct.pack("!H", len(payload))
            c.sendall(hdr + payload)
        else:
            body = json.dumps({"result": dict(INFO, status="success")}).encode()
            c.sendall((
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Content-Length: %d\r\n\r\n" % len(body)).encode() + body)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY

# Started in THIS shell, never inside $(...). A command substitution is a
# subshell: the pid it appends to NODE_PIDS is gone with it, the EXIT trap
# then kills nothing, and every run left three stubs looping on accept()
# for good (#1084). The port comes back through a variable instead.
NODE_PIDS=()
start_node() { # $1 = mode, $2 = the variable that gets the port it took
  local pf="$TMP/state/port.$1.$RANDOM" i
  python3 "$TMP/fakenode.py" "$1" "$pf" "$$" >/dev/null 2>&1 &
  NODE_PIDS+=($!)
  for (( i = 0; i < 100; i++ )); do
    [[ -s "$pf" ]] && { printf -v "$2" '%s' "$(cat "$pf")"; return 0; }
    sleep 0.05
  done
  echo "the fake $1 node never came up" >&2
  return 1
}

stop_nodes() {
  local p
  for p in ${NODE_PIDS[@]+"${NODE_PIDS[@]}"}; do kill "$p" 2>/dev/null; done
  for p in ${NODE_PIDS[@]+"${NODE_PIDS[@]}"}; do wait "$p" 2>/dev/null; done
  NODE_PIDS=()
  return 0
}

cleanup() {
  stop_nodes
  rm -rf "$TMP"
}
trap cleanup EXIT

WS_PORT='' RPC_PORT='' QUIET_PORT=''
start_node ws WS_PORT       || exit 1
start_node rpc RPC_PORT     || exit 1
start_node quiet QUIET_PORT || exit 1
# One port nothing is on. Taken by binding and releasing, so it is a number
# this machine really had free rather than one that looked free.
DEAD_PORT="$(python3 -c 'import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); print(p)')"

# ── Fakes on PATH ───────────────────────────────────────────────────
cat > "$TMP/bin/ss" <<EOF
#!/usr/bin/env bash
echo "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process"
cat "$TMP/state/ss" 2>/dev/null
exit 0
EOF

cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  --version)       cat "$TMP/state/systemd-version" 2>/dev/null || echo "systemd 255 (255.4-1ubuntu8.17)"; exit 0 ;;
  list-unit-files) cat "$TMP/state/units" 2>/dev/null; exit 0 ;;
  status)          cat "$TMP/state/unit-for-pid-\${2:-none}" 2>/dev/null; exit 0 ;;
  # Only ever called here as: systemctl show -p PROP --value UNIT (\$2=-p
  # \$3=PROP \$4=--value \$5=UNIT), so the fixture is keyed on those two
  # positions rather than a general argument parser.
  show)            cat "$TMP/state/unit-\${5:-}-\${3:-}" 2>/dev/null; exit 0 ;;
esac
exit 0
EOF

cat > "$TMP/bin/timedatectl" <<EOF
#!/usr/bin/env bash
echo "NTPSynchronized=\$(cat "$TMP/state/ntp" 2>/dev/null || echo yes)"
exit 0
EOF

# df -Pk <path>. The second line is the one preflight reads: \$4 available in
# 1K blocks, \$6 the mount point.
cat > "$TMP/bin/df" <<EOF
#!/usr/bin/env bash
avail="\$(cat "$TMP/state/df-avail-kb" 2>/dev/null || echo 104857600)"
echo "Filesystem     1024-blocks      Used Available Capacity Mounted"
echo "/dev/sda1        209715200      1000 \$avail       1% /"
exit 0
EOF

cat > "$TMP/bin/free" <<EOF
#!/usr/bin/env bash
avail="\$(cat "$TMP/state/free-avail-kb" 2>/dev/null || echo 8388608)"
echo "               total        used        free      shared  buff/cache   available"
echo "Mem:        16000000      100000      100000        1000      200000 \$avail"
exit 0
EOF

cat > "$TMP/bin/pgrep" <<EOF
#!/usr/bin/env bash
name="\${!#}"
grep -qx -e "\$name" "$TMP/state/procs" 2>/dev/null || exit 1
echo 4211
EOF

cat > "$TMP/bin/docker" <<EOF
#!/usr/bin/env bash
if [[ -f "$TMP/state/docker-no-daemon" ]]; then
  echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2
  exit 1
fi
if [[ -f "$TMP/state/docker-denied" && "\${APERIRE_TEST_VIA_SUDO:-0}" != "1" ]]; then
  echo "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock" >&2
  exit 1
fi
[[ "\${1:-}" == "ps" ]] && cat "$TMP/state/containers" 2>/dev/null
# inspect --format {{.Config.Image}}: what a container was created from. A
# container made from a digest shows an image ID in ps and this here (#896).
if [[ "\${1:-}" == "inspect" ]]; then
  if [[ -f "$TMP/state/inspect-refused" ]]; then
    echo "permission denied while trying to connect to the Docker daemon socket" >&2
    exit 1
  fi
  cat "$TMP/state/config-image" 2>/dev/null
fi
exit 0
EOF

cat > "$TMP/bin/sudo" <<EOF
#!/usr/bin/env bash
saw_n=0
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -H|-E) shift ;;
    -n) saw_n=1; shift
        if [[ -f "$TMP/state/sudo-n-denied" ]]; then
          echo "sudo: a password is required" >&2
          exit 1
        fi
        [[ "\${1:-}" == "true" ]] && exit 0
        ;;
    -v) exit 0 ;;
    -u) shift 2 ;;
    *) break ;;
  esac
done
[[ \$# -eq 0 ]] && exit 0
export APERIRE_TEST_VIA_SUDO=\$saw_n
exec "\$@"
EOF

# Two callers, told apart by the address. A loopback URL is the node probe
# asking server_info of a server this test really started, so it goes to the
# real curl. Anything else is the egress check, answered from state.
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
url=""
for a in "\$@"; do case "\$a" in http://127.0.0.1*|https://*|http://*) url="\$a" ;; esac; done
case "\$url" in
  http://127.0.0.1:*) exec "$REAL_CURL" "\$@" ;;
esac
host="\${url#*://}"; host="\${host%%/*}"
printf '%s\n' "\$host" >> "$TMP/state/egress-asked"
if grep -qx -e "\$host" "$TMP/state/egress-down" 2>/dev/null; then
  printf '000'
  exit 7
fi
printf '200'
exit 0
EOF

printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/apt-get"

# The config resolver, stubbed. The real one is scripts/detect-rippled-paths.sh
# and it works: on the machine writing this it found the developer's own node
# through docker and the whole suite started reading a live host. A test that
# reads the box it runs on passes for the wrong reason, so the resolver is
# pointed at this instead and the rows that care about a config file hand it
# one.
cat > "$TMP/bin/detect-stub.sh" <<EOF
#!/usr/bin/env bash
echo "RIPPLED_CFG_PATH=\$(cat "$TMP/state/detected-cfg" 2>/dev/null)"
echo "RIPPLED_DATA_PATH="
EOF
chmod +x "$TMP"/bin/*
export PATH="$TMP/bin:$PATH"

printf 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n' > "$TMP/ubuntu.os-release"
printf 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$TMP/debian.os-release"
: > "$TMP/ca-certificates.crt"

# A PATH with the named commands nowhere on it. Moving the fake aside is not
# the same thing: this machine has a real python3 and a real curl further down
# PATH, and the run would find those instead.
path_without() { # $@ = command names to hide
  local key d f b mirror hide root
  key="$(printf '%s-' "$@")"
  root="$TMP/nopath/$key"
  if [[ ! -d "$root" ]]; then
    mkdir -p "$root"
    local -a dirs=() parts=()
    IFS=: read -r -a dirs <<< "$PATH"
    for d in "${dirs[@]}"; do
      hide=0
      for b in "$@"; do [[ -x "$d/$b" ]] && hide=1; done
      if [[ $hide -eq 1 ]]; then
        mirror="$root/$(printf '%s' "$d" | tr -c 'A-Za-z0-9' '_')"
        mkdir -p "$mirror"
        for f in "$d"/*; do
          b="${f##*/}"
          case " $* " in *" $b "*) continue ;; esac
          ln -sf "$f" "$mirror/$b"
        done
        parts+=("$mirror")
      else
        parts+=("$d")
      fi
    done
    printf '%s\n' "$(IFS=:; printf '%s' "${parts[*]}")" > "$root/PATH"
  fi
  cat "$root/PATH"
}

# ── Running the thing under test ────────────────────────────────────
OUT=""; RC=0
PATH_FOR_RUN=""
WS_PORTS_FOR_RUN=""
RPC_PORTS_FOR_RUN=""
CFG_PATHS_FOR_RUN=""

reset() {
  rm -rf "$TMP/state"
  mkdir -p "$TMP/state"
  PATH_FOR_RUN=""
  # Nothing on the standard ports, unless a row puts something there. Two
  # numbers this machine had free, so a row that means "nothing answers" is
  # not quietly reading somebody else's service.
  WS_PORTS_FOR_RUN="$DEAD_PORT"
  RPC_PORTS_FOR_RUN="$DEAD_PORT"
  CFG_PATHS_FOR_RUN="$TMP/state/no-such-rippled.cfg"
}

# A loaded systemd unit, standing for either package. $1 = unit name,
# $2 = what ActiveState answers for it (active, inactive, failed, ...).
set_native_unit() {
  printf 'loaded\n' > "$TMP/state/unit-$1-LoadState"
  printf '%s\n' "$2" > "$TMP/state/unit-$1-ActiveState"
}

env_for() {
  printf '%s\n' \
    "PATH=${PATH_FOR_RUN:-$PATH}" \
    "HOME=$TMP/home" \
    "NO_COLOR=1" \
    "APERIRE_PREFLIGHT_OS_RELEASE=${OS_FILE:-$TMP/ubuntu.os-release}" \
    "APERIRE_PREFLIGHT_ETC=$TMP/etc/aperire" \
    "APERIRE_PREFLIGHT_EGRESS=${EGRESS_FOR_RUN:-https://github.com https://go.dev/dl/}" \
    "APERIRE_PREFLIGHT_WS_PORTS=$WS_PORTS_FOR_RUN" \
    "APERIRE_PREFLIGHT_RPC_PORTS=$RPC_PORTS_FOR_RUN" \
    "APERIRE_PREFLIGHT_PEER_PORT=${PEER_PORT_FOR_RUN:-$DEAD_PORT}" \
    "APERIRE_PREFLIGHT_CFG_PATHS=$CFG_PATHS_FOR_RUN" \
    "APERIRE_PREFLIGHT_DETECT=$TMP/bin/detect-stub.sh" \
    "APERIRE_PREFLIGHT_CA_BUNDLE=${CA_FOR_RUN:-$TMP/ca-certificates.crt}"
}

run_pf() {
  local -a e; mapfile -t e < <(env_for)
  OUT="$(env "${e[@]}" bash "$SUT" "$@" 2>&1)"; RC=$?
}

# With a terminal on both ends, which is the only way the node question is
# asked at all. The answers go in through a fifo this shell holds open: fed
# down a pipe they arrive and the pipe closes, `script` tears the terminal
# down before the run gets as far as asking, and the read comes back empty,
# which looks exactly like an operator who typed nothing.
run_pf_tty() { # $1 = answers, one per line; rest = arguments
  local answers="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  local cmd fifo="$TMP/tty-in"
  cmd="env $(printf '%q ' "${e[@]}")bash $(printf '%q ' "$SUT" "$@")"
  rm -f "$fifo"; mkfifo "$fifo"
  exec {ttyfd}<>"$fifo"
  printf '%s' "$answers" >&"$ttyfd"
  OUT="$(script -qec "$cmd" /dev/null < "$fifo" 2>&1)"; RC=$?
  exec {ttyfd}>&-
  rm -f "$fifo"
}

# The verdict on one row, by the check's name. Empty when the row was not
# printed at all, which is its own answer: a check that is gated off a role
# prints nothing rather than printing ok.
# Matched anywhere on the line, not anchored to its start: under a terminal
# the prompt has no newline after it, so the verdict that follows the answer
# shares a line with the question that produced it. Carriage returns become
# newlines first, for the same reason.
row_of() { # $1 = check name
  printf '%s\n' "$OUT" | tr '\r' '\n' \
    | grep -oE "(ok|warn|MISSING)[[:space:]]+$1:[[:space:]].*" | head -1
}
verdict_of() { row_of "$1" | awk '{print $1}'; }
value_of()   { row_of "$1" | sed -E "s/^(ok|warn|MISSING)[[:space:]]+$1:[[:space:]]*//"; }

is() { # $1 = check, $2 = expected verdict, $3 = what this row proves
  local got; got="$(verdict_of "$1")"
  if [[ "$got" == "$2" ]]; then ok "$3"; else bad "$3" "$1 came out '$got', not '$2' (value: $(value_of "$1"))"; fi
}

echo
echo "preflight.sh, the prerequisite check the install runs first"
echo

# ── the OS, systemd and the account ─────────────────────────────────
echo "The system underneath:"

reset
run_pf --role=dashboard --check
is OS ok "a verified distribution passes, named"
if [[ "$(value_of OS)" == "Ubuntu 24.04.3 LTS" ]]; then
  ok "and the line carries the distribution it measured, not the fact that it looked"
else
  bad "the OS line carries the measured value" "$(value_of OS)"
fi

reset
OS_FILE="$TMP/debian.os-release" run_pf --role=dashboard --check
is OS warn "an unverified distribution warns and does not block"
if [[ $RC -eq 0 && "$(value_of OS)" == *"Debian GNU/Linux 12"* ]]; then
  ok "and names it, and a warning never blocks"
else
  bad "an unverified distribution warns by name and does not block" "rc=$RC, $(value_of OS)"
fi

reset
printf 'systemd 255 (255.4-1ubuntu8.17)\n' > "$TMP/state/systemd-version"
run_pf --role=dashboard --check
is systemd ok "systemd 255 is enough for everything"

reset
printf 'systemd 249 (249.11-0ubuntu3.12)\n' > "$TMP/state/systemd-version"
run_pf --role=dashboard --check
# Ubuntu 22.04. Its systemd used to keep the Advisor off its own account,
# because the Advisor reached the node through sudo and 249's sandbox forces
# no_new_privs. It reaches the node through a root socket now (ADR 0025).
is systemd ok "systemd 249 is fine for everything, the Advisor's own account included"
if [[ "$OUT" != *"--advisor-shared-account"* && "$OUT" != *"needs 250"* ]]; then
  ok "and nothing sends the operator to the retired shared account"
else
  bad "no shared-account advice on 249" "$OUT"
fi

reset
printf '' > "$TMP/state/systemd-version"
run_pf --role=dashboard --check
is systemd MISSING "no systemd at all is a refusal: there is nothing to install a unit into"

# ── which way this host will keep the Advisor's model key (#708) ─────
#
# A 22.04 host used to install, pair, and then refuse every model key with a
# sentence about systemd-creds. Finding that out at the first seal was half
# the defect, so the checklist says it up front, and it is never a refusal:
# both methods work and 22.04 is a supported host.
#
# The version rows run with a stub systemd-creds on PATH and nothing else of
# the host's. Without it the answer depends on the machine running the test:
# a CI image with no systemd-creds takes the missing-binary branch, and a
# "names systemd-creds" check passes on the sentence that says it is absent.
_pf_bin_dir() { # $1 = directory to fill: this suite's stubs plus the basics
  mkdir -p "$1"
  for _t in "$TMP/bin/"*; do ln -sf "$_t" "$1/$(basename "$_t")"; done
  for _t in bash env grep awk sed cat head cut tr sort find id uname date printf python3 curl stat wc mktemp rm ln chmod mkdir sleep tail basename dirname readlink; do
    _r="$(command -v "$_t" 2>/dev/null)"; [[ -n "$_r" ]] && ln -sf "$_r" "$1/$_t"
  done
}
WITHCREDS="$TMP/bin-with-creds"
_pf_bin_dir "$WITHCREDS"
printf '#!/bin/sh\nexit 0\n' > "$WITHCREDS/systemd-creds"; chmod +x "$WITHCREDS/systemd-creds"
reset
printf 'systemd 255 (255.4-1ubuntu8.17)\n' > "$TMP/state/systemd-version"
PATH_FOR_RUN="$WITHCREDS" run_pf --role=dashboard --check
is "model key" ok "a host on 250 or newer is told its key is sealed to the machine"
if [[ "$(value_of "model key")" == *"sealed to this machine with systemd-creds"* ]]; then
  ok "and the line names the tool that does it"
else
  bad "the sealed line names systemd-creds" "$(value_of "model key")"
fi

reset
printf 'systemd 249 (249.11-0ubuntu3.12)\n' > "$TMP/state/systemd-version"
PATH_FOR_RUN="$WITHCREDS" run_pf --role=dashboard --check
is "model key" ok "a host on 249 is told its key is a root-only file, and is never refused for it"
if [[ "$(value_of "model key")" == *"LoadCredential="* && "$(value_of "model key")" == *"249"* ]]; then
  ok "and the line names the directive and the version that decided it"
else
  bad "the 249 line names LoadCredential= and the version" "$(value_of "model key")"
fi

# And the other half of the same question, which a version test alone cannot
# see: a host whose systemd is new enough but whose systemd-creds binary is
# not installed. PATH without it, and without /usr/bin, because this dev host
# has a real one there and finding it would defeat the row.
reset
printf 'systemd 255 (255.4-1ubuntu8.17)\n' > "$TMP/state/systemd-version"
NOCREDS="$TMP/bin-no-creds"
_pf_bin_dir "$NOCREDS"
PATH_FOR_RUN="$NOCREDS" run_pf --role=dashboard --check
is "model key" ok "a host with systemd 255 and no systemd-creds binary keeps the key as a file too"
if [[ "$(value_of "model key")" == *"no systemd-creds"* ]]; then
  ok "and says the binary is what is missing, not the version"
else
  bad "a missing binary is named as such" "$(value_of "model key")"
fi

reset
run_pf --role=dashboard --check
is account ok "an ordinary account with sudo passes"

reset
PATH_FOR_RUN="$(path_without sudo)" run_pf --role=dashboard --check
is account MISSING "the same account with no sudo on the host is a refusal"
if [[ "$OUT" == *"apt-get install -y sudo"* ]]; then
  ok "and the refusal carries the command that fixes it"
else
  bad "the sudo refusal carries a remedy" "$OUT"
fi

reset
run_pf --role=cli-only --check
is account ok "cli-only wants no root at all, and says so"

reset
run_pf --role=dashboard --check
is arch ok "this architecture is one the Go download is pinned to"

# ── what the host has room for ──────────────────────────────────────
echo
echo "Disk and memory, measured:"

reset
printf '104857600\n' > "$TMP/state/df-avail-kb"     # 100 GB
run_pf --role=dashboard --check
is disk ok "100 GB free passes"

reset
printf '7340032\n' > "$TMP/state/df-avail-kb"       # 7 GB
run_pf --role=dashboard --check
is disk warn "7 GB installs and warns, because the database and the store both grow"

reset
printf '2097152\n' > "$TMP/state/df-avail-kb"       # 2 GB
run_pf --role=dashboard --check
is disk MISSING "2 GB is a refusal"
if [[ $RC -eq 1 ]]; then
  ok "and one MISSING is a non-zero exit"
else
  bad "a MISSING exits non-zero" "rc=$RC"
fi
if [[ "$OUT" == *"Before Aperire can install, fix these:"* && "$OUT" == *"--dir"* ]]; then
  ok "and the remedy block names it with the flag that moves the install"
else
  bad "the remedy block names the disk row" "$OUT"
fi

reset
printf '8388608\n' > "$TMP/state/free-avail-kb"     # 8 GB
run_pf --role=dashboard --check
is memory ok "8 GB available passes"

reset
printf '524288\n' > "$TMP/state/free-avail-kb"      # 512 MB
run_pf --role=dashboard --check
is memory warn "512 MB warns and does not block: the build is slow there, not impossible"

# ── the ports ───────────────────────────────────────────────────────
echo
echo "The ports the dashboard and the Advisor need:"

reset
run_pf --role=dashboard --check
is "port 7800" ok "a free port is free"

reset
printf 'LISTEN 0      511          0.0.0.0:7800       0.0.0.0:*    users:(("nginx",pid=812,fd=6))\n' > "$TMP/state/ss"
run_pf --role=dashboard --check
is "port 7800" MISSING "a port another service holds is a refusal"
if [[ "$(value_of "port 7800")" == *"nginx"* && "$(value_of "port 7800")" == *"812"* ]]; then
  ok "and it names the process and the pid holding it"
else
  bad "the busy-port line names the process" "$(value_of "port 7800")"
fi

reset
printf 'LISTEN 0      511        127.0.0.1:7800       0.0.0.0:*    users:(("node",pid=4242,fd=21))\n' > "$TMP/state/ss"
printf 'aperire-server.service - Aperire dashboard\n' > "$TMP/state/unit-for-pid-4242"
run_pf --role=dashboard --check
is "port 7800" ok "our own unit on our own port is an existing install, not a collision"
if [[ "$(value_of "port 7800")" == *"aperire-server.service"* ]]; then
  ok "and it says which unit"
else
  bad "the existing-install line names the unit" "$(value_of "port 7800")"
fi

reset
printf 'LISTEN 0      511          0.0.0.0:7800       0.0.0.0:*\n' > "$TMP/state/ss"
run_pf --role=dashboard --check
is "port 7800" warn "a port held by a process this account cannot see is its own answer, never rounded to free or to busy"
if [[ "$OUT" == *"sudo ss -ltnp"* ]]; then
  ok "and it says how to name the holder"
else
  bad "the unnameable-holder line says how to name it" "$OUT"
fi

reset
run_pf --role=dashboard --check
if [[ -z "$(verdict_of "port 7810")" ]]; then
  ok "the Advisor's port is not checked when no Advisor was asked for"
else
  bad "the Advisor port is only checked when it is wanted" "$(verdict_of "port 7810")"
fi

reset
run_pf --role=dashboard --with-advisor --check
is "port 7810" ok "and it is checked when it is"

reset
run_pf --role=dashboard --instance=node2 --port=7900 --check
is "port 7900" ok "a second instance's port is the one checked"

# ── egress, the clock and the tools ─────────────────────────────────
echo
echo "What the install has to reach, and what it has to run:"

reset
run_pf --role=dashboard --check
is egress ok "every download host answering is ok"

reset
printf 'go.dev\n' > "$TMP/state/egress-down"
run_pf --role=dashboard --check
is egress warn "one host down warns and names it"
if [[ "$(value_of egress)" == *"go.dev"* ]]; then
  ok "and says which one"
else
  bad "the egress warning names the host" "$(value_of egress)"
fi

reset
printf 'github.com\ngo.dev\n' > "$TMP/state/egress-down"
run_pf --role=dashboard --check
is egress MISSING "nothing reachable is a refusal: there is no install without a download"

reset
PATH_FOR_RUN="$(path_without curl)" run_pf --role=dashboard --check
is egress MISSING "and no curl at all is the same refusal, said differently"

reset
printf 'yes\n' > "$TMP/state/ntp"
run_pf --role=dashboard --check
is clock ok "a synchronised clock passes"

reset
printf 'no\n' > "$TMP/state/ntp"
PATH_FOR_RUN="$(path_without chronyc ntpstat)" run_pf --role=dashboard --check
is clock warn "a drifted clock warns and does not block"
if [[ "$OUT" == *"timedatectl set-ntp true"* && "$OUT" == *"passkey"* ]]; then
  ok "and says both the fix and why it matters, which is the sign-in afterwards"
else
  bad "the clock warning carries the fix and the reason" "$OUT"
fi

reset
run_pf --role=dashboard --check
is tools ok "the four tools present is ok"

reset
CA_FOR_RUN="$TMP/state/no-such-bundle.crt" run_pf --role=dashboard --check
is tools warn "one missing with apt here warns: the prepare step installs it"
if [[ "$(value_of tools)" == *"ca-certificates"* ]]; then
  ok "and names what is missing"
else
  bad "the tools warning names what is missing" "$(value_of tools)"
fi

reset
CA_FOR_RUN="$TMP/state/no-such-bundle.crt" PATH_FOR_RUN="$(path_without apt-get)" \
  run_pf --role=dashboard --check
is tools MISSING "one missing with no apt-get to install it is a refusal"

# ── docker, and an install that is already here ─────────────────────
echo
echo "Docker, asked only when it matters:"

reset
run_pf --role=dashboard --check
if [[ -z "$(verdict_of docker)" ]]; then
  ok "docker is not asked about on a host with no Advisor and no container node"
else
  bad "docker is only reported when it matters" "$(verdict_of docker)"
fi

reset
run_pf --role=dashboard --with-advisor --check
is docker ok "it is reported when the Advisor is wanted"

reset
set_native_unit xrpld.service active
run_pf --role=co-located --with-advisor --check
if [[ -z "$(verdict_of docker)" ]]; then
  ok "and it is not asked about at all on a native host, even with the Advisor wanted: there is no docker there to ask"
else
  bad "docker is skipped on a native host" "$(verdict_of docker)"
fi

reset
: > "$TMP/state/docker-denied"
: > "$TMP/state/sudo-n-denied"
run_pf --role=dashboard --with-advisor --check
is docker warn "a docker that refuses to answer is said out loud, and is never read as absent"

reset
: > "$TMP/state/docker-no-daemon"
run_pf --role=dashboard --with-advisor --check
is docker warn "and a daemon that is not running is an answer of its own"

echo
echo "An install that is already here:"

reset
run_pf --role=dashboard --check
is install ok "a clean host says so"

reset
printf 'aperire-server.service enabled enabled\n' > "$TMP/state/units"
run_pf --role=dashboard --check
is install warn "an installed host is reported and not blocked, because the menu is what it needs"
if [[ "$OUT" == *"aperire-one"* ]]; then
  ok "and it names the menu"
else
  bad "the installed-host line names the menu" "$OUT"
fi

# ── the node ────────────────────────────────────────────────────────
echo
echo "The node, found the way v3 found it:"

reset
printf 'rippled\n' > "$TMP/state/procs"
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" run_pf --role=co-located --check
is node ok "a running process plus a port that answers server_info is a node"
if [[ "$(value_of node)" == "rippled 3.3.0 (proposing), admin WS 127.0.0.1:${WS_PORT}, RPC 127.0.0.1:${RPC_PORT}" ]]; then
  ok "and the line reads back the version, the state and both addresses"
else
  bad "the node line reads back what was measured" "$(value_of node)"
fi

reset
printf '[port_ws_admin_local]\nip = 127.0.0.1\nport = %s\nprotocol = ws\n\n[port_rpc_admin_local]\nip = 127.0.0.1\nport = %s\nprotocol = http\n' \
  "$WS_PORT" "$RPC_PORT" > "$TMP/state/rippled.cfg"
printf '%s\n' "$TMP/state/rippled.cfg" > "$TMP/state/detected-cfg"
run_pf --role=co-located --check
is node ok "a node on a port no standard list holds is found through its own config file"
if [[ "$OUT" == *"config: $TMP/state/rippled.cfg"* ]]; then
  ok "and the config it read is printed under the line"
else
  bad "the config path is printed" "$OUT"
fi

reset
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" run_pf --role=co-located --check
is node ok "no process, no container and no config still finds it by probing the standard ports"

reset
WS_PORTS_FOR_RUN="$QUIET_PORT" RPC_PORTS_FOR_RUN="$QUIET_PORT" run_pf --role=co-located --yes
is node MISSING "a socket that accepts and says nothing is not a node, and is not reported as one"

reset
printf 'somenode xrpl-labs/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" run_pf --role=co-located --check
if [[ "$(value_of node)" == xrpld* ]]; then
  ok "a node in a container is found, and the line carries the fork's own name"
else
  bad "a containerised node is named by its fork" "$(value_of node)"
fi
is docker ok "and docker is reported, because a container node is why it was asked"

# What the caller acts on (#434). The bootstrap records a node this host is
# already running when nothing on the host names it, and that verb is the
# container one, so the shape and the container's name have to travel. This
# check is the only thing that measures them on a run whose role was NAMED:
# --role=co-located short-circuits the bootstrap's own probe, and a first
# install driven that way left the node unrecorded on a rebuilt host.
reset
ANSWER_FILE="$TMP/state/answer-node"
printf 'somenode xrpl-labs/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" \
  run_pf --role=co-located --yes "--answer-file=$ANSWER_FILE"
if [[ "$(sed -n 's/^NODE_SHAPE=//p' "$ANSWER_FILE" 2>/dev/null)" == container \
   && "$(sed -n 's/^NODE_CONTAINER=//p' "$ANSWER_FILE" 2>/dev/null)" == somenode ]]; then
  ok "the shape and the container's name are written where the caller reads them"
else
  bad "the node facts reach the caller" "answer file: $(cat "$ANSWER_FILE" 2>/dev/null || echo '<not written>')"
fi

# #896: a container created from a digest reference (the shape the Advisor's
# own upgrade makes) shows an image ID in docker ps. Neutral container name
# and command on purpose: a row that says xrpld would match without the image.
reset
ANSWER_FILE="$TMP/state/answer-digest"
printf 'aperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf 'rippleci/xrpld@sha256:%s\n' "$(printf 'e77ed5a9%.0s' 1 2 3 4 5 6 7 8)" > "$TMP/state/config-image"
run_pf --role=co-located --yes "--answer-file=$ANSWER_FILE"
if [[ "$(sed -n 's/^NODE_SHAPE=//p' "$ANSWER_FILE" 2>/dev/null)" == container \
   && "$(sed -n 's/^NODE_CONTAINER=//p' "$ANSWER_FILE" 2>/dev/null)" == aperire-node ]]; then
  ok "a node created from a digest (docker ps shows an image ID) is found as a container through docker inspect"
else
  bad "a digest-created node is found as a container" "answer file: $(cat "$ANSWER_FILE" 2>/dev/null || echo '<not written>')"
fi

reset
printf 'db-1 e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf 'postgres:16\n' > "$TMP/state/config-image"
run_pf --role=co-located --yes
is node MISSING "an image ID that resolves to something that is not a node is still no node"

reset
printf 'aperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
: > "$TMP/state/inspect-refused"
run_pf --role=co-located --yes
is node warn "an inspect docker refuses is not a node that is absent: it warns"
if [[ "$(value_of node)" == *"permission denied"* ]]; then
  ok "and the line quotes docker's own complaint"
else
  bad "a refused inspect quotes docker's complaint" "$(value_of node)"
fi

reset
ANSWER_FILE="$TMP/state/answer-node2"
set_native_unit rippled.service active
run_pf --role=co-located --yes "--answer-file=$ANSWER_FILE"
if [[ "$(sed -n 's/^NODE_SHAPE=//p' "$ANSWER_FILE" 2>/dev/null)" == native ]] \
   && ! grep -q '^NODE_CONTAINER=' "$ANSWER_FILE" 2>/dev/null; then
  ok "a native node writes its shape and no container name, because it has none"
else
  bad "a native node carries no container name" "answer file: $(cat "$ANSWER_FILE" 2>/dev/null || echo '<not written>')"
fi

# A node found by its process name alone is neither: no unit answered and no
# container matched, so the shape is not something this run measured. Written
# as `unknown` rather than guessed, because the caller acts differently on the
# two and a guess here is an action taken on the wrong shape.
reset
ANSWER_FILE="$TMP/state/answer-node2b"
printf 'rippled\n' > "$TMP/state/procs"
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" \
  run_pf --role=co-located --yes "--answer-file=$ANSWER_FILE"
if [[ "$(sed -n 's/^NODE_SHAPE=//p' "$ANSWER_FILE" 2>/dev/null)" == unknown ]]; then
  ok "a node seen only as a process says its shape is unknown, rather than guessing one"
else
  bad "an unmeasured shape is unknown" "answer file: $(cat "$ANSWER_FILE" 2>/dev/null || echo '<not written>')"
fi

reset
ANSWER_FILE="$TMP/state/answer-node3"
run_pf --role=co-located --yes "--answer-file=$ANSWER_FILE"
if [[ ! -s "$ANSWER_FILE" ]] || ! grep -q '^NODE_SHAPE=' "$ANSWER_FILE"; then
  ok "control: a host with no node writes no shape, so nothing downstream invents one"
else
  bad "no node means no shape written" "$(cat "$ANSWER_FILE" 2>/dev/null)"
fi

reset
PEER_PORT_FOR_RUN="$QUIET_PORT" WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" \
  run_pf --role=co-located --check
if [[ "$OUT" == *"peer port 127.0.0.1:${QUIET_PORT} is open"* ]]; then
  ok "the peer port is read and reported as detail, never as a verdict"
else
  bad "the peer port is reported under the node line" "$OUT"
fi

reset
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" \
  PATH_FOR_RUN="$(path_without python3)" run_pf --role=co-located --check
if [[ "$(value_of node)" == *"listening, not confirmed"* ]]; then
  ok "with no python3 to speak WebSocket, a listening admin port says exactly that and claims nothing"
else
  bad "a listening but unconfirmed WS port says so" "$(value_of node)"
fi

echo
echo "Native, the fourth way in: a unit, not a container:"

reset
printf 'xrpld\n' > "$TMP/state/procs"
set_native_unit xrpld.service active
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" run_pf --role=co-located --check
is node ok "a native unit that is active, with its process running and the admin port confirmed, is a node"
if [[ "$(value_of node)" == "xrpld 3.3.0 (proposing), native, xrpld.service, admin WS 127.0.0.1:${WS_PORT}, RPC 127.0.0.1:${RPC_PORT}" ]]; then
  ok "and the line names the shape and the unit, the way the container line below names the shape and the container"
else
  bad "a native node's line names its shape and its unit" "$(value_of node)"
fi
if [[ $RC -eq 0 ]]; then
  ok "and a native co-located box exits 0, the same as a container one"
else
  bad "a native co-located box with a confirmed admin port exits 0" "rc=$RC"
fi

reset
set_native_unit rippled.service active
run_pf --role=co-located --check
is node ok "a native unit that is active is found even when the admin port itself never confirms anything"
if [[ "$(value_of node)" == "a node, native, rippled.service, found by unit active" ]]; then
  ok "and it says exactly that: found by the unit, not by an admin port that never answered"
else
  bad "a native node found by unit alone says so, and claims no admin port" "$(value_of node)"
fi
if [[ "$(value_of node)" != *"admin WS"* && "$(value_of node)" != *", RPC "* ]]; then
  ok "and it makes no claim about an admin port it never confirmed"
else
  bad "an unconfirmed admin port must not appear in the line" "$(value_of node)"
fi

reset
set_native_unit rippled.service inactive
run_pf --role=co-located --check
is node warn "a native unit that is loaded but not active is installed and stopped, not absent"
if [[ "$(value_of node)" == "installed as rippled.service (inactive), not running" ]]; then
  ok "and the line names the unit and says plainly that it is not running"
else
  bad "a stopped native unit names itself and says so" "$(value_of node)"
fi
if [[ "$OUT" != *"No node answered on this host"* ]]; then
  ok "and the three absent-node reasons are never printed for a unit known to be there, just stopped"
else
  bad "a stopped unit must not fall into the absent-node reasons" "$OUT"
fi
if [[ $RC -eq 0 ]]; then
  ok "and it never blocks: starting the unit is the operator's own next step"
else
  bad "a stopped native unit does not block the install" "rc=$RC"
fi

reset
run_pf --role=co-located --yes
if [[ "$(verdict_of node)" == "MISSING" && "$OUT" != *"installed as"* ]]; then
  ok "and a host with no unit loaded at all reads as absent, not as a stopped native install"
else
  bad "a host with no unit at all must not read as native-stopped" "$OUT"
fi

echo
echo "No node, which is a different answer for every role:"

reset
run_pf --role=dashboard --check
is node warn "a dashboard-only host has no node here BY DEFINITION, so it warns and installs"
if [[ $RC -eq 0 ]]; then
  ok "and the run is clean: this is the shape of every fleet dashboard"
else
  bad "a dashboard with no node exits clean" "rc=$RC: $OUT"
fi
if [[ "$OUT" != *"--node"* ]]; then
  ok "a dashboard the operator NAMED is not told to install a node"
else
  bad "a named dashboard role is not offered a node" "$OUT"
fi

# The same reading, but nobody named it: the bootstrap's probe found no
# node and read 'dashboard' into that. A box with no node YET looks the
# same, and only the operator knows which, so the line has to say how to
# get a node here (#139) and stay a warning, never a refusal.
reset
run_pf --role=dashboard --check --role-guessed
is node warn "a dashboard the probe GUESSED still warns and passes"
if [[ $RC -eq 0 && "$OUT" == *"--node"* && "$OUT" == *"answer 5"* ]]; then
  ok "and says how to put a node here first: --node, or answer 5 at the install's role prompt"
else
  bad "a guessed dashboard names --node and answer 5" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"bash aperire-one, then the fleet helper"* && "$OUT" != *"sudo bash aperire-one"* ]]; then
  ok "and still says what to do when 'dashboard' is right after all"
else
  bad "the guessed reading keeps the fleet path" "$OUT"
fi

reset
run_pf --role=co-located --yes
is node MISSING "a co-located host with no node found is a refusal, because the role says the node is here"
for reason in "the port is not exposed" "there is no node on this host" "the node listens on a non-standard port"; do
  if [[ "$OUT" == *"$reason"* ]]; then
    ok "the three reasons are printed: $reason"
  else
    bad "the reason is printed: $reason" "$OUT"
  fi
done
if [[ $RC -eq 1 ]]; then
  ok "and --yes does not skip a MISSING: an unattended run that cannot guess stops"
else
  bad "--yes does not skip a MISSING" "rc=$RC"
fi

reset
PEER_PORT_FOR_RUN="$QUIET_PORT" run_pf --role=co-located --yes
if [[ "$OUT" == *"though 127.0.0.1:${QUIET_PORT} IS open"* ]]; then
  ok "an open peer port beside a silent admin port is said inside reason 2, where it changes the answer"
else
  bad "the three reasons carry the open peer port" "$OUT"
fi

reset
run_pf --role=validator --yes
is node MISSING "the validator role refuses too, because the relay reads the node's own config"

# The one that must not become a refusal. On a hardened host the operator is
# deliberately not in the docker group and sudo -n is denied, so a node in a
# container is invisible to everything running here. That is not the same fact
# as "there is no node", and it is the fact that once installed a node box as
# a dashboard.
reset
: > "$TMP/state/docker-denied"
: > "$TMP/state/sudo-n-denied"
run_pf --role=co-located --yes
is node warn "a docker nobody here can ask is not a node that is absent: it warns, and the install goes on"
if [[ $RC -eq 0 && "$(value_of node)" == *"permission denied"* ]]; then
  ok "and the line quotes what stopped it, so the next guess is not a guess"
else
  bad "the unavailable node line quotes docker's own complaint" "rc=$RC, $(value_of node)"
fi

reset
: > "$TMP/state/docker-denied"
: > "$TMP/state/sudo-n-denied"
PATH_FOR_RUN="$(path_without pgrep)" run_pf --role=co-located --yes
is node warn "and a host with no pgrep on it cannot look for a process either, which is the same answer"

echo
echo "The node question, with somebody at the keyboard:"

reset
ANSWER_FILE="$TMP/state/answer"
WS_PORTS_FOR_RUN="$DEAD_PORT" RPC_PORTS_FOR_RUN="$DEAD_PORT" \
  run_pf_tty "$WS_PORT
" --role=co-located "--answer-file=$ANSWER_FILE"
is node ok "a port typed at the prompt is probed, and a node that answers there settles it"
# The URL's own line, not the whole file: the answer file carries the node
# facts as well now, so "what the install reads for RIPPLED_URL" and "every
# byte in the file" are two different questions.
if [[ "$(sed -n 's/^RIPPLED_URL=//p' "$ANSWER_FILE" 2>/dev/null)" == "ws://127.0.0.1:${WS_PORT}" ]]; then
  ok "and the answer is written where the install reads it"
else
  bad "the answer reaches the install" "answer file: $(cat "$ANSWER_FILE" 2>/dev/null || echo '<not written>')"
fi

reset
ANSWER_FILE="$TMP/state/answer2"
run_pf_tty "
" --role=co-located "--answer-file=$ANSWER_FILE"
is node warn "Enter at the prompt is an answer: install, and the dashboard waits for a node"
if [[ $RC -eq 0 && ! -s "$ANSWER_FILE" ]]; then
  ok "and nothing is written, so nothing overrides the dashboard's own default"
else
  bad "Enter writes no answer and does not block" "rc=$RC, answer=$(cat "$ANSWER_FILE" 2>/dev/null)"
fi

reset
ANSWER_FILE="$TMP/state/answer3"
run_pf_tty "$DEAD_PORT
" --role=co-located "--answer-file=$ANSWER_FILE"
is node warn "a port nothing answers on is taken anyway, and said out loud: the operator knows their host"
if [[ "$(sed -n 's/^RIPPLED_URL=//p' "$ANSWER_FILE" 2>/dev/null)" == "ws://127.0.0.1:${DEAD_PORT}" ]]; then
  ok "and it is still the value the install uses"
else
  bad "a typed port is used even when nothing answered yet" "$(cat "$ANSWER_FILE" 2>/dev/null)"
fi

reset
run_pf_tty "notaport
" --role=co-located
is node MISSING "something that is not a port number is refused rather than written into a URL"

reset
ANSWER_FILE="$TMP/state/answer4"
WS_PORTS_FOR_RUN="$WS_PORT" RPC_PORTS_FOR_RUN="$RPC_PORT" \
  run_pf --role=co-located --check "--answer-file=$ANSWER_FILE"
if [[ ! -e "$ANSWER_FILE" ]]; then
  ok "--check writes no answer at all: a report changes nothing, not even a temporary file"
else
  bad "--check writes nothing" "$(cat "$ANSWER_FILE")"
fi

# ── --json and --check ──────────────────────────────────────────────
echo
echo "The machine-readable shape, and the report-only door:"

reset
run_pf --role=dashboard --json
if printf '%s' "$OUT" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  ok "--json is JSON, parsed by a parser rather than eyeballed"
else
  bad "--json parses" "$OUT"
fi
if printf '%s' "$OUT" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
assert isinstance(rows, list) and rows, "not a non-empty array"
for r in rows:
    assert set(r) == {"check", "verdict", "value", "remedy"}, r
    assert r["verdict"] in ("ok", "warn", "MISSING"), r
names = [r["check"] for r in rows]
for want in ("OS", "systemd", "model key", "account", "disk", "egress", "clock", "tools", "install", "node"):
    assert want in names, want
' 2>/dev/null; then
  ok "and every row is {check, verdict, value, remedy} with a verdict from the three"
else
  bad "the JSON row shape" "$OUT"
fi

reset
printf '2097152\n' > "$TMP/state/df-avail-kb"
run_pf --role=dashboard --json
if [[ $RC -eq 1 ]] && printf '%s' "$OUT" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
d = [r for r in rows if r["check"] == "disk"][0]
assert d["verdict"] == "MISSING", d
assert d["remedy"], "a MISSING with no remedy"
' 2>/dev/null; then
  ok "a MISSING in --json is a MISSING row, a remedy, and a non-zero exit"
else
  bad "--json carries the MISSING and exits non-zero" "rc=$RC: $OUT"
fi

# A real distro string arrives quoted, and a process name can carry a
# backslash. One escaping helper, or the array stops parsing on somebody's
# ordinary host.
reset
printf 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 \\"LTS\\" (a\\\\b)"\n' > "$TMP/state/odd.os-release"
OS_FILE="$TMP/state/odd.os-release" run_pf --role=dashboard --json
if printf '%s' "$OUT" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
os_row = [r for r in rows if r["check"] == "OS"][0]
assert "\"LTS\"" in os_row["value"], os_row
assert "a\\b" in os_row["value"], os_row
' 2>/dev/null; then
  ok "a distribution name with quotes and a backslash in it still produces JSON that parses"
else
  bad "quotes and backslashes are escaped in --json" "$OUT"
fi

reset
run_pf --role=dashboard --check
if [[ $RC -eq 0 && "$OUT" == *"This host can install Aperire One."* ]]; then
  ok "--check on a ready host exits 0 and says so"
else
  bad "--check exits 0 on a ready host" "rc=$RC: $OUT"
fi

reset
printf '2097152\n' > "$TMP/state/df-avail-kb"
run_pf --role=dashboard --check
if [[ $RC -eq 1 && "$OUT" == *"has to be fixed first, so nothing was installed."* ]]; then
  ok "--check on a host that is not ready exits 1 and says nothing was installed"
else
  bad "--check exits 1 and says nothing was installed" "rc=$RC: $OUT"
fi

# ── the standard ports are still the standard ports ─────────────────
#
# Everything above drove the probe through the test seam, which is the only
# way to stand a node up without binding 6006 on this machine. That makes the
# seam's DEFAULTS the one thing no row above can see, so they are read here.
echo
echo "The list the seam defaults to, which is the list the product uses:"

# shellcheck disable=SC2016  # these are the file's own literal text, matched, never expanded
if grep -q 'PF_WS_PORTS="${APERIRE_PREFLIGHT_WS_PORTS:-6006 6005}"' "$SUT"; then
  ok "the admin WebSocket ports are still 6006 then 6005"
else
  bad "the admin WS port list is 6006 then 6005" "$(grep -n 'PF_WS_PORTS=' "$SUT")"
fi
# shellcheck disable=SC2016  # the file's own literal text, matched, never expanded
if grep -q 'PF_RPC_PORTS="${APERIRE_PREFLIGHT_RPC_PORTS:-5005 5006 51234}"' "$SUT"; then
  ok "the RPC ports are still 5005, 5006 then 51234"
else
  bad "the RPC port list is 5005, 5006 then 51234" "$(grep -n 'PF_RPC_PORTS=' "$SUT")"
fi
# shellcheck disable=SC2016  # the file's own literal text, matched, never expanded
if grep -q 'PF_PEER_PORT="${APERIRE_PREFLIGHT_PEER_PORT:-51235}"' "$SUT"; then
  ok "the peer port is still 51235"
else
  bad "the peer port is 51235" "$(grep -n 'PF_PEER_PORT=' "$SUT")"
fi
# shellcheck disable=SC2016  # the file's own literal text, matched, never expanded
if grep -q 'PF_CFG_PATHS="${APERIRE_PREFLIGHT_CFG_PATHS:-/etc/xrpld/xrpld.cfg /etc/opt/ripple/rippled.cfg /opt/ripple/etc/rippled.cfg /etc/ripple/rippled.cfg}"' "$SUT"; then
  ok "the config files are the current native layout plus the three legacy ones this tree has always looked in"
else
  bad "the config path list" "$(grep -n 'PF_CFG_PATHS=' "$SUT")"
fi

# ── and it blocks the installer it runs in front of ─────────────────
#
# The whole point. A checklist that refuses and an installer that installs
# anyway is worse than no checklist. Proven on cli-only, which is the one role
# install.sh runs without root, so this row needs none either.
echo
echo "What a MISSING does to install.sh:"

FAKE_REPO="$TMP/fakerepo"
mkdir -p "$FAKE_REPO/scripts"
cp "$REPO_DIR/install.sh" "$FAKE_REPO/install.sh"
cp "$REPO_DIR/scripts/term-style.sh" "$FAKE_REPO/scripts/term-style.sh"
# install.sh also sources the aggregator-origin rule and refuses a tree
# without it by name, so it sits beside term-style.sh here too.
cp "$REPO_DIR/scripts/fleet-origin.sh" "$FAKE_REPO/scripts/fleet-origin.sh"
cp "$REPO_DIR/scripts/authn-value.sh" "$FAKE_REPO/scripts/authn-value.sh"
cat > "$FAKE_REPO/scripts/install-aperire-cli.sh" <<EOF
#!/usr/bin/env bash
printf 'cli ran\n' >> "$TMP/state/installer-steps"
EOF
cat > "$FAKE_REPO/scripts/prepare-host.sh" <<EOF
#!/usr/bin/env bash
printf 'prepare ran\n' >> "$TMP/state/installer-steps"
EOF
chmod +x "$FAKE_REPO/scripts/"*.sh

# $1 = the exit status it takes. $2 = the whole answer file it writes, one
# line per key; the default is the single RIPPLED_URL line this file carried
# before the node facts joined it.
write_fake_preflight() {
  local answer=${2:-"RIPPLED_URL=ws://127.0.0.1:6009"}
  cat > "$FAKE_REPO/scripts/preflight.sh" <<EOF
#!/usr/bin/env bash
printf 'preflight ran\n' >> "$TMP/state/installer-steps"
printf '%s\n' "\$*" >> "$TMP/state/installer-preflight-args"
for a in "\$@"; do
  case "\$a" in --answer-file=*) printf '%s\n' "$answer" > "\${a#*=}" ;; esac
done
echo "  MISSING  disk: 2 GB free on / (/), and the build needs 5"
exit $1
EOF
  chmod +x "$FAKE_REPO/scripts/preflight.sh"
}

reset
write_fake_preflight 1
OUT="$(cd "$TMP" && bash "$FAKE_REPO/install.sh" --role=cli-only --yes 2>&1)"; RC=$?
if [[ $RC -ne 0 && "$(cat "$TMP/state/installer-steps" 2>/dev/null)" == "preflight ran" ]]; then
  ok "install.sh runs the check first and stops on a MISSING, having installed nothing"
else
  bad "a MISSING stops install.sh before it installs anything" \
      "rc=$RC, steps: $(tr '\n' ',' < "$TMP/state/installer-steps" 2>/dev/null)"
fi
if [[ "$OUT" == *"MISSING  disk"* && "$OUT" == *"missing something the install needs"* ]]; then
  ok "and the operator is left with the checklist's own line and one command to re-run"
else
  bad "install.sh prints the checklist and its own refusal" "$OUT"
fi

reset
write_fake_preflight 0
OUT="$(cd "$TMP" && bash "$FAKE_REPO/install.sh" --role=cli-only --yes 2>&1)"; RC=$?
if [[ $RC -eq 0 && "$(tr '\n' ',' < "$TMP/state/installer-steps" 2>/dev/null)" == "preflight ran,cli ran," ]]; then
  ok "and the same run with the check passing installs (the control that makes the row above mean something)"
else
  bad "a passing check lets install.sh through" \
      "rc=$RC, steps: $(tr '\n' ',' < "$TMP/state/installer-steps" 2>/dev/null)"
fi

reset
write_fake_preflight 0
OUT="$(cd "$TMP" && bash "$FAKE_REPO/install.sh" --role=cli-only --yes --no-preflight 2>&1)"; RC=$?
if [[ $RC -eq 0 && "$(tr '\n' ',' < "$TMP/state/installer-steps" 2>/dev/null)" == "cli ran," ]]; then
  ok "--no-preflight skips it, which is what the bootstrap uses when it has already run it"
else
  bad "--no-preflight skips the check" \
      "rc=$RC, steps: $(tr '\n' ',' < "$TMP/state/installer-steps" 2>/dev/null)"
fi

# The answer's last hop inside install.sh: what the check wrote has to become
# the variable install-aperire-service.sh reads.
reset
write_fake_preflight 0
# Two files, because `${VAR:-<unset>}` cannot tell a variable that was never
# exported from one exported empty, and those are exactly the two answers the
# row below has to keep apart.
cat > "$FAKE_REPO/scripts/install-aperire-cli.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\${APERIRE_RIPPLED_URL:-<unset>}" > "$TMP/state/installer-node-url"
printf '%s\n' "\${APERIRE_RIPPLED_URL+set}" > "$TMP/state/installer-node-url-set"
EOF
chmod +x "$FAKE_REPO/scripts/install-aperire-cli.sh"
OUT="$(cd "$TMP" && bash "$FAKE_REPO/install.sh" --role=cli-only --yes 2>&1)"; RC=$?
if [[ "$(cat "$TMP/state/installer-node-url" 2>/dev/null)" == "ws://127.0.0.1:6009" ]]; then
  ok "the node answer becomes APERIRE_RIPPLED_URL for every step underneath"
else
  bad "the node answer reaches the sub-installers" \
      "they saw '$(cat "$TMP/state/installer-node-url" 2>/dev/null)'"
fi

# The other shape that file can have now. Until the node facts travelled in
# it, a non-empty answer file implied a RIPPLED_URL line, and install.sh's
# read is gated on the file having bytes. A host where the check found the
# node but the node question resolved no URL writes NODE_SHAPE and nothing
# else, and an empty URL exported from that would point the dashboard at
# nothing at all, on exactly the shape #434 is about.
reset
write_fake_preflight 0 "NODE_SHAPE=container
NODE_CONTAINER=aperire-node"
OUT="$(cd "$TMP" && bash "$FAKE_REPO/install.sh" --role=cli-only --yes 2>&1)"; RC=$?
if [[ -z "$(cat "$TMP/state/installer-node-url-set" 2>/dev/null)" ]]; then
  ok "an answer file carrying node facts and no URL exports no URL, rather than an empty one"
else
  bad "no URL means no APERIRE_RIPPLED_URL" \
      "it was exported, as '$(cat "$TMP/state/installer-node-url" 2>/dev/null)'"
fi
if [[ $RC -eq 0 ]]; then
  ok "and the install still goes through, because the node facts are not its business"
else
  bad "the install is unaffected by the extra keys" "rc=$RC: $OUT"
fi

# And the last hop of all, read out of the installer that writes the file the
# service reads. A grep, because running it needs root and a systemd.
# shellcheck disable=SC2016  # the installer's literal text, matched, not expanded
if grep -q 'APERIRE_RIPPLED_URL' "$REPO_DIR/scripts/install-aperire-service.sh" \
   && grep -q 'RIPPLED_URL=${APERIRE_RIPPLED_URL}' "$REPO_DIR/scripts/install-aperire-service.sh"; then
  ok "and install-aperire-service.sh is what writes RIPPLED_URL into the service environment"
else
  bad "install-aperire-service.sh writes RIPPLED_URL from APERIRE_RIPPLED_URL" \
      "$(grep -n 'RIPPLED_URL' "$REPO_DIR/scripts/install-aperire-service.sh" || echo 'no mention at all')"
fi

# ── No stub outlives the suite (#1084) ─────────────────────────────
# Every run used to leave its three stubs behind, looping on accept() for
# good: hundreds of them on one box, days old. Three ways out, one row each.
gone_or_zombie() { # $1 = pid; true once it is gone or only a zombie
  [[ ! -e "/proc/$1" ]] || [[ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" == Z ]]
}
wait_gone() { # $1 = pid, $2 = tenths of a second
  local i
  for (( i = 0; i < $2; i++ )); do gone_or_zombie "$1" && return 0; sleep 0.1; done
  return 1
}

# A suite killed outright runs no trap. The stub goes when the shell it was
# told to watch does: here a shell that starts it and exits at once.
pf="$TMP/state/port.orphaned"
orphan="$(bash -c 'python3 "$1" quiet "$2" "$$" >/dev/null 2>&1 & echo $!' _ "$TMP/fakenode.py" "$pf")"
for (( i = 0; i < 100; i++ )); do [[ -s "$pf" ]] && break; sleep 0.05; done
if [[ -s "$pf" ]] && wait_gone "$orphan" 50; then
  ok "a stub whose suite is gone exits on its own, so a killed run leaves nothing behind"
else
  bad "a stub whose suite is gone exits on its own" "pid $orphan still running 5s after the shell it watched exited"
  kill "$orphan" 2>/dev/null
fi

# And a ceiling, for a suite that is alive but stuck.
pf="$TMP/state/port.capped"
FAKENODE_MAX_S=1 python3 "$TMP/fakenode.py" quiet "$pf" "$$" >/dev/null 2>&1 &
capped=$!
if wait_gone "$capped" 60; then
  ok "a stub stops at its ceiling even while the suite is still running"
else
  bad "a stub stops at its ceiling" "pid $capped still running 6s after a 1s ceiling"
  kill "$capped" 2>/dev/null
fi
wait "$capped" 2>/dev/null

# The clean exit. The same stop the EXIT trap runs, then nothing started
# from this run's fakenode.py may be left.
stop_nodes
left="$("$REAL_PGREP" -f "$TMP/fakenode.py" || true)"
if [[ -z "$left" ]]; then
  ok "the stop the EXIT trap runs leaves no fake node behind"
else
  bad "the stop the EXIT trap runs leaves no fake node behind" \
      "still running: ${left//$'\n'/ }"
  # shellcheck disable=SC2086  # a list of pids, split on purpose
  kill $left 2>/dev/null
fi

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
