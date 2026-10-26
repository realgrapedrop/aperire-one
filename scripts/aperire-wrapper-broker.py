#!/usr/bin/python3 -IS
# The one way the Advisor reaches the node wrapper as root (ADR 0025).
#
# Installed root-owned as /usr/local/sbin/aperire-wrapper-broker and run by
# systemd, never by hand: aperire-node-wrapper<-instance>.socket listens on
# /run/aperire/node-wrapper<-instance>.sock, root:<advisor group> 0660, with
# Accept=yes, and each connection starts one aperire-node-wrapper@.service
# instance running this program as root with the connection as its standard
# input and output. The unit names the interpreter explicitly
# (`/usr/bin/python3 -I -S`), so the shebang above is only for reading.
#
# It replaces the Advisor's sudo rule. On systemd 249 any seccomp directive
# in a unit forces no_new_privs on a non-root User=, and sudo refuses under
# it, so the Advisor's own account could never hold that rule on Ubuntu
# 22.04. A connection to a socket needs no privilege at all, so the Advisor's
# unit now runs NoNewPrivileges=true everywhere.
#
# ---- what it does, in order --------------------------------------------
#
#   1. SO_PEERCRED on the connection. Any uid but the one named by
#      --allow-uid (the Advisor's account, written into the unit by root) is
#      refused. So is root: nothing legitimate comes this way as root.
#   2. One request line, at most 1024 bytes, within 5 seconds:
#
#          v1 <verb> [arg] [arg]
#
#      Single spaces between tokens, every token from [A-Za-z0-9._:=-] and
#      at most 128 bytes. No quoting and no escapes, so there is nothing to
#      parse wrongly.
#   3. The verb is looked up in VERBS below, a fixed table that mirrors the
#      wrapper's own dispatch, and each argument is matched against that
#      verb's own pattern. Nothing in a request is a path: restore-compose
#      takes a backup's FILE NAME, which the wrapper resolves beside the
#      compose file it already knows, and package-install's `--from <path>`
#      form is not reachable here at all. scripts/test-wrapper-broker.sh
#      derives the wrapper's verbs from its own `case` and fails when the two
#      lists differ in either direction.
#   4. The wrapper named by --wrapper (the root-owned copy in
#      /usr/local/sbin, placed by trusted-path-lib.sh) is checked again:
#      a regular file, owned by root, writable by nobody else. Then it runs,
#      as root, with a fixed environment, / as its directory, /dev/null as
#      its input and its own process group.
#   5. Its output comes back in frames: one type byte, a 4-byte big-endian
#      length, then the bytes. `a` (empty) says the call was accepted and is
#      about to run, and is sent before anything runs, so a caller that saw
#      no frame at all knows nothing ran and may retry safely. `o` is
#      standard output, `e` standard error, `x` the exit code as ASCII
#      digits, always last. A refusal at any step
#      above is an `e` frame ("wrapper: refused ...") and `x` 64, the code the
#      wrapper itself refuses with, so the Advisor reads it the same way.
#   6. One JSON line per connection goes to the journal (this program's
#      standard error is the journal, at notice): who, what, the outcome,
#      how long, how much. The arguments are all validated tokens and none is
#      secret.
#
# ---- bounds -------------------------------------------------------------
#
#   read-only verbs  600 s, and stopped if the caller hangs up: they change
#                    nothing, and an answer nobody reads is worth nothing
#   everything else  7200 s, and run to the end whether or not anyone is still
#                    reading. A compose rewrite or a package install stopped
#                    halfway is worse than an answer that goes unread. The
#                    Advisor's execute path sets no deadline on a step, so a
#                    build or a pull is never cut off here first.
#   output           32 MiB per call. A read-only verb past that is stopped;
#                    any other verb keeps running, and what it prints past the
#                    cap is dropped and said to have been.
#
# RuntimeMaxSec= on the service unit is the backstop behind all of this.
#
# ---- what it never does -------------------------------------------------
#
# It never runs a shell, never builds a command string, never reads a path or
# an environment variable from the request, and never runs the wrapper from
# an install tree. It has no configuration file: everything it needs is on
# its own command line, which only root writes.

import json
import os
import re
import signal
import socket
import stat
import struct
import sys
import time

PROTOCOL = "v1"
MAX_REQUEST = 1024
MAX_TOKEN = 128
REQUEST_TIMEOUT = 5.0
READ_TIMEOUT = 600.0
ACT_TIMEOUT = 7200.0
# What an act gets when its verb is not named below: long enough for a
# recreate or a restart behind a generous stop grace, and short enough that a
# caller who went away does not hold one of the socket's sixteen slots for
# two hours (#779 review, L4). The verbs that fetch or build keep longer
# bounds, and only a build gets the whole of ACT_TIMEOUT.
ACT_DEFAULT_TIMEOUT = 1800.0
ACT_TIMEOUTS = {
    "pull": 3600.0,
    "pull-official": 3600.0,
    "package-install": 3600.0,
    "build-image": ACT_TIMEOUT,
}
MAX_OUTPUT = 32 * 1024 * 1024
CHUNK = 64 * 1024
STOP_GRACE = 10.0
REFUSED = 64
# The one owner the wrapper and its directory may have. A constant, not a
# literal, so a test can point it at the account it runs as by rewriting
# this line in a copy, the same as the wrapper's own IMAGE_RECIPE_OWNER.
WRAPPER_OWNER = 0
# Where the walk up the wrapper's directories stops: "/" on a host, which is
# the whole chain. A constant for the same reason, so a test can stop it at
# its own temporary directory, the way the wrapper's IMAGE_RECIPE_CHAIN_TOP
# is stopped.
CHAIN_TOP = "/"

# The environment the wrapper gets, whole. sudo gave it roughly this (its
# env_reset plus secure_path); nothing of the Advisor's environment crosses.
# /snap/bin stays for the same reason trusted-path-lib.sh keeps it: a snap
# docker lives there, and it is root's.
WRAPPER_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
    "HOME": "/root",
    "LOGNAME": "root",
    "USER": "root",
    "SHELL": "/bin/bash",
    "LANG": "C.UTF-8",
}

TOKEN_RE = re.compile(r"^[A-Za-z0-9._:=-]{1,%d}$" % MAX_TOKEN)

# One validator per argument shape, each the wrapper's own require_* rule.
VERSION_RE = re.compile(r"^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$")       # require_version
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")                   # require_digest
USERSPEC_RE = re.compile(r"^[0-9]{1,10}:[0-9]{1,10}$")             # require_userspec
BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.bak$")
CONFIG_KEYS = ("online_delete", "advisory_delete", "node_size", "ledger_history")
CONFIG_VALUE_RE = re.compile(r"^[A-Za-z0-9]{1,24}$")


def a_version(v):
    return bool(VERSION_RE.match(v))


def a_digest(v):
    return bool(DIGEST_RE.match(v))


def a_count(v):  # require_count: 1 to 2000, no leading zero (bash reads one as octal)
    return bool(re.match(r"^[1-9][0-9]{0,3}$", v)) and int(v) <= 2000


def a_userspec(v):
    return bool(USERSPEC_RE.match(v))


def a_artefact(v):
    return v in ("node-config", "deployment-definition")


def a_config(v):  # set-config: one allow-listed key, one plain value
    key, sep, val = v.partition("=")
    return sep == "=" and key in CONFIG_KEYS and bool(CONFIG_VALUE_RE.match(val))


def a_backup_name(v):  # a name, never a path
    return ".." not in v and bool(BACKUP_NAME_RE.match(v))


def a_wait(v):  # rotation-state --wait: the read with no time limit, and nothing else
    return v == "--wait"


READ = "read"
ACT = "act"

# verb: (class, required argument validators, optional argument validators)
VERBS = {
    "status":                (READ, (), ()),
    "backup-config":         (ACT, (), ()),
    "backup-compose":        (ACT, (), ()),
    "pull":                  (ACT, (a_version,), ()),
    "image-digest":          (READ, (a_version,), (a_digest,)),
    "running-digest":        (READ, (), ()),
    "image-version":         (ACT, (a_version,), (a_digest,)),
    "set-image":             (ACT, (a_version,), ()),
    "set-image-local":       (ACT, (a_version,), ()),
    "compose-config":        (READ, (), ()),
    "pull-official":         (ACT, (a_version, a_digest), ()),
    "image-provenance":      (ACT, (a_version,), (a_digest,)),
    "signed-binary-sha256":  (ACT, (a_version,), ()),
    "verify-official-image": (ACT, (a_version, a_digest), ()),
    "set-image-official":    (ACT, (a_version, a_digest), ()),
    "set-node-args":         (ACT, (), ()),
    "add-config-mount":      (ACT, (), ()),
    "set-runtime-user":      (ACT, (a_userspec,), ()),
    "build-image":           (ACT, (a_version,), ()),
    "restore-compose":       (ACT, (a_backup_name,), (a_version,)),
    "recreate":              (ACT, (), ()),
    "restart":               (ACT, (), ()),
    "inspect":               (READ, (), ()),
    "rotation-state":        (READ, (), (a_wait,)),
    "can-delete-timer":      (READ, (), ()),
    "compose-backups":       (READ, (), ()),
    "rotation-window":       (READ, (), ()),
    "image-headroom":        (READ, (), ()),
    "recipe-state":          (READ, (), ()),
    "config-readable":       (READ, (), ()),
    "show-config":           (READ, (), ()),
    "show-validators":       (READ, (), ()),
    "show-toml":             (READ, (), ()),
    "disk":                  (READ, (), ()),
    "store-size":            (READ, (), ()),
    "store-headroom":        (READ, (), ()),
    "node-log":              (READ, (a_count,), ()),
    "sysctl-relevant":       (READ, (), ()),
    "limits":                (READ, (), ()),
    "unit-status":           (READ, (), ()),
    "resources":             (READ, (), ()),
    "journal":               (READ, (a_count,), ()),
    "artefact-hashes":       (READ, (a_artefact,), ()),
    "set-config":            (ACT, (a_config,), ()),
    "package-latest":        (READ, (), ()),
    "package-available":     (READ, (a_version,), ()),
    "package-install":       (ACT, (a_version,), ()),
    "package-keep":          (ACT, (), ()),
    "package-kept":          (READ, (), ()),
    "package-version":       (READ, (), ()),
}


class Refused(Exception):
    pass


def ledger(entry):
    # <5> is notice: the service's LogLevelMax=notice lets it through while
    # dropping systemd's own per-connection start and stop lines.
    try:
        sys.stderr.write("<5>" + json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except OSError:
        pass


def parse_args(argv):
    wrapper = None
    allow_uid = None
    instance = ""
    for a in argv:
        if a.startswith("--wrapper="):
            wrapper = a[len("--wrapper="):]
        elif a.startswith("--allow-uid="):
            v = a[len("--allow-uid="):]
            if not v.isdigit() or len(v) > 10:
                raise SystemExit("aperire-wrapper-broker: --allow-uid takes a number")
            allow_uid = int(v)
        elif a.startswith("--instance="):
            instance = a[len("--instance="):]
            if instance and not re.match(r"^[a-z0-9][a-z0-9-]{0,30}$", instance):
                raise SystemExit("aperire-wrapper-broker: --instance is lowercase letters, digits and dashes")
        else:
            raise SystemExit("aperire-wrapper-broker: unknown argument: %s" % a)
    if not wrapper or not os.path.isabs(wrapper):
        raise SystemExit("aperire-wrapper-broker: --wrapper takes an absolute path")
    if allow_uid is None:
        raise SystemExit("aperire-wrapper-broker: --allow-uid is required")
    if allow_uid == 0:
        raise SystemExit("aperire-wrapper-broker: --allow-uid may not be root")
    return wrapper, allow_uid, instance


def validate(tokens):
    """tokens -> (verb, args). Raises Refused with the reason."""
    if len(tokens) < 2 or tokens[0] != PROTOCOL:
        raise Refused("the request is not '%s <verb> [args]'" % PROTOCOL)
    verb, args = tokens[1], tokens[2:]
    for t in tokens[1:]:
        if not TOKEN_RE.match(t):
            raise Refused("a token is empty, longer than %d bytes, or has a character outside [A-Za-z0-9._:=-]" % MAX_TOKEN)
    if verb not in VERBS:
        raise Refused("'%s' is not a verb this socket carries" % verb)
    _cls, required, optional = VERBS[verb]
    if len(args) < len(required) or len(args) > len(required) + len(optional):
        want = str(len(required)) if not optional else "%d to %d" % (len(required), len(required) + len(optional))
        raise Refused("%s takes %s argument(s), and was given %d" % (verb, want, len(args)))
    for i, a in enumerate(args):
        check = required[i] if i < len(required) else optional[i - len(required)]
        if not check(a):
            raise Refused("%s: argument %d does not have the shape this verb takes" % (verb, i + 1))
    return verb, args


def read_request(sock):
    sock.settimeout(REQUEST_TIMEOUT)
    deadline = time.monotonic() + REQUEST_TIMEOUT
    buf = b""
    while b"\n" not in buf:
        left = deadline - time.monotonic()
        if left <= 0:
            raise Refused("no complete request within %d seconds" % REQUEST_TIMEOUT)
        sock.settimeout(left)
        try:
            chunk = sock.recv(MAX_REQUEST + 1 - len(buf))
        except socket.timeout:
            raise Refused("no complete request within %d seconds" % REQUEST_TIMEOUT)
        if not chunk:
            raise Refused("the request ended before its newline")
        buf += chunk
        if len(buf) > MAX_REQUEST and b"\n" not in buf[:MAX_REQUEST]:
            raise Refused("the request is longer than %d bytes" % MAX_REQUEST)
    line, _, rest = buf.partition(b"\n")
    if rest:
        raise Refused("one request per connection, and nothing after it")
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("the request is not ASCII")
    return text.split(" ")


def check_wrapper(path):
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        raise Refused("the wrapper this socket names, %s, is not installed; run: curl -fsSL https://get.aperire.one | bash -s -- --update --force" % path)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("%s is not a regular file" % path)
    if st.st_uid != WRAPPER_OWNER or st.st_mode & 0o022:
        raise Refused("%s is not root-owned and writable by root alone, so root will not run it" % path)
    # Every directory above it, to /, by the same rule: whoever could write
    # one of them could swap the wrapper between this check and the run.
    # A sticky directory is no exception here; none belongs on this chain.
    parent = os.path.dirname(path)
    while True:
        try:
            pst = os.stat(parent, follow_symlinks=False)
        except OSError:
            raise Refused("%s cannot be read, so the wrapper's place cannot be judged" % parent)
        if not stat.S_ISDIR(pst.st_mode) or pst.st_mode & 0o022 or \
                pst.st_uid not in (WRAPPER_OWNER, 0):
            raise Refused("%s is not a root-owned directory writable by root alone" % parent)
        if parent in ("/", CHAIN_TOP):
            break
        parent = os.path.dirname(parent)


class Conn:
    """The connection, blocking with a bound on every send. A caller that
    stops reading for 30 seconds, or has gone, is marked gone and sent
    nothing more; what happens to the wrapper then is run()'s business."""

    def __init__(self, sock):
        self.sock = sock
        self.gone = False

    def frame(self, kind, data):
        if self.gone:
            return
        try:
            self.sock.settimeout(30.0)
            for i in range(0, max(len(data), 1), CHUNK):
                part = data[i:i + CHUNK]
                self.sock.sendall(kind + struct.pack(">I", len(part)) + part)
        except (OSError, socket.timeout):
            self.gone = True

    def refuse(self, reason):
        self.frame(b"e", ("wrapper: refused by the root socket: %s\n" % reason).encode())
        self.frame(b"x", str(REFUSED).encode())


def stop_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        return
    end = time.monotonic() + STOP_GRACE
    while time.monotonic() < end:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def run(conn, wrapper, verb, args, entry):
    import select
    import subprocess

    cls = VERBS[verb][0]
    limit = READ_TIMEOUT if cls == READ else ACT_TIMEOUTS.get(verb, ACT_DEFAULT_TIMEOUT)
    # Accepted, before anything runs. A caller that sees no frame at all
    # knows nothing ran and may try again (systemd at MaxConnections accepts
    # and closes); one that saw this frame must never repeat the call.
    conn.frame(b"a", b"")
    # In the journal before anything runs (#779 review, L3): an act whose
    # broker is killed mid-run still leaves a line that says it started.
    ledger(dict(entry, outcome="accepted", limit_s=int(limit)))
    proc = subprocess.Popen(
        [wrapper, verb] + args,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd="/", env=dict(WRAPPER_ENV), close_fds=True, start_new_session=True,
    )
    tags = {proc.stdout.fileno(): b"o", proc.stderr.fileno(): b"e"}
    poller = select.poll()
    for fd in tags:
        poller.register(fd, select.POLLIN)
    # The connection, to notice a caller that has gone. Registered for no
    # event at all: poll reports POLLHUP and POLLERR whatever is asked for,
    # and POLLHUP on a stream socket is the peer's full close. A half close
    # (the peer shut its writing side after the request) is not a hangup,
    # and reading the socket for EOF could not tell the two apart.
    sock_fd = conn.sock.fileno()
    poller.register(sock_fd, 0)
    deadline = time.monotonic() + limit
    hard_stop = None
    total = 0
    stopped = None
    truncated = False

    def halt(why):
        nonlocal stopped, hard_stop
        stopped = why
        stop_group(proc)
        hard_stop = time.monotonic() + 5.0

    while tags:
        now = time.monotonic()
        if stopped is None and now >= deadline:
            halt("timed out after %d seconds" % limit)
            continue
        if hard_stop is not None and now >= hard_stop:
            break  # stopped, and something still holds a pipe open: stop waiting on it
        wait = (hard_stop if hard_stop is not None else deadline) - now
        for fd, ev in poller.poll(int(max(min(wait, 1.0), 0.05) * 1000)):
            if fd == sock_fd:
                if ev & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    poller.unregister(sock_fd)
                    conn.gone = True
                    entry["client_gone"] = True
                    if cls == READ and stopped is None:
                        halt("the caller hung up")
                continue
            data = os.read(fd, CHUNK) if ev & (select.POLLIN | select.POLLHUP | select.POLLERR) else b""
            if not data:
                poller.unregister(fd)
                del tags[fd]
                continue
            total += len(data)
            if total > MAX_OUTPUT:
                if not truncated:
                    truncated = True
                    entry["truncated"] = True
                    conn.frame(b"e", b"\nwrapper-socket: output past 32 MiB was dropped\n")
                    if cls == READ and stopped is None:
                        halt("its output passed 32 MiB")
                continue
            conn.frame(tags[fd], data)
            # A caller that stopped reading (30 seconds on one send) is
            # treated as gone, the same as a hangup: a read is stopped, an
            # act runs to its end.
            if conn.gone and not entry.get("client_gone"):
                entry["client_gone"] = True
                if cls == READ and stopped is None:
                    halt("the caller stopped reading")
    try:
        rc = proc.wait(timeout=STOP_GRACE)
    except subprocess.TimeoutExpired:
        stop_group(proc)
        rc = proc.wait()
    if rc < 0:
        rc = 128 - rc
    if stopped:
        entry["stopped"] = stopped
        conn.frame(b"e", ("\nwrapper-socket: stopped: %s\n" % stopped).encode())
        if stopped.startswith("timed out"):
            rc = 124
    entry["bytes"] = total
    return rc


def main():
    wrapper, allow_uid, instance = parse_args(sys.argv[1:])
    started = time.monotonic()
    entry = {"socket": "node-wrapper" + ("-" + instance if instance else "")}
    try:
        sock = socket.socket(fileno=os.dup(0))
    except OSError as e:
        ledger(dict(entry, outcome="refused", reason="standard input is not a socket: %s" % e))
        return 2
    conn = Conn(sock)
    try:
        pid, uid, _gid = struct.unpack("iII", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")))
        entry.update(peer_pid=pid, peer_uid=uid)
        # Root is refused by name as well as by not being --allow-uid (which
        # parse_args already holds to non-zero): nothing legitimate comes
        # this way as root, and a request that does is not the Advisor's.
        if uid == 0:
            raise Refused("uid 0 is root, and root never comes this way")
        if uid != allow_uid:
            raise Refused("uid %d is not the Advisor's account" % uid)
        tokens = read_request(sock)
        verb, args = validate(tokens)
        entry.update(verb=verb, args=args)
        check_wrapper(wrapper)
    except Refused as r:
        conn.refuse(str(r))
        entry.update(outcome="refused", reason=str(r), exit=REFUSED,
                     ms=int((time.monotonic() - started) * 1000))
        ledger(entry)
        return 0
    try:
        rc = run(conn, wrapper, verb, args, entry)
    except OSError as e:
        conn.refuse("the wrapper could not be started: %s" % e.strerror)
        entry.update(outcome="refused", reason="start failed: %s" % e.strerror, exit=REFUSED,
                     ms=int((time.monotonic() - started) * 1000))
        ledger(entry)
        return 0
    conn.frame(b"x", str(rc).encode())
    entry.update(outcome="ran", exit=rc, ms=int((time.monotonic() - started) * 1000))
    ledger(entry)
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    return 0


def list_verbs():
    # One line per verb: the verb, its class, its required argument shapes
    # and its optional ones ("-" for none). The test reads this to build a
    # valid call for every verb and to compare the table with the wrapper.
    def names(fs):
        return ",".join(f.__name__[2:] for f in fs) or "-"
    for verb in sorted(VERBS):
        cls, req, opt = VERBS[verb]
        print("%s %s %s %s" % (verb, cls, names(req), names(opt)))


def check_request(tokens):
    # One request, given as arguments rather than read from a socket, judged
    # by the same validate() and nothing else. For the Advisor's own tests:
    # every step its plans can produce has to be a request this table takes.
    try:
        verb, args = validate(tokens)
    except Refused as r:
        print("refused: %s" % r)
        return REFUSED
    print("ok %s" % " ".join([verb] + args))
    return 0


def guarded_main():
    # Anything this program did not expect still leaves a ledger line and an
    # answer, never only a traceback. The unit's SyslogLevel=err keeps the
    # traceback in the journal as well, past LogLevelMax=notice.
    try:
        return main()
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 - the last line of defence
        ledger({"outcome": "error", "reason": "%s: %s" % (type(e).__name__, e)})
        try:
            conn = Conn(socket.socket(fileno=os.dup(0)))
            conn.refuse("the broker failed: %s" % type(e).__name__)
        except Exception:  # noqa: BLE001
            pass
        raise


if __name__ == "__main__":
    if sys.argv[1:] == ["--list-verbs"]:
        list_verbs()
        sys.exit(0)
    if sys.argv[1:2] == ["--check"]:
        sys.exit(check_request(sys.argv[2:]))
    sys.exit(guarded_main())
