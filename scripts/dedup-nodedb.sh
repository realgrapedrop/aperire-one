#!/usr/bin/env bash
# One-time cleanup: drop stray duplicate advisory_delete lines inside [node_db],
# keeping the first. Preserves the config's owner/group/mode by truncate-writing
# the existing inode (never a rename), so a bind-mounted validator config is not
# handed to rippled under a new owner. Verifies before and after. Issue #81.
#
# Written on a descriptor (#1132). The install runs this as root, and the name
# it is given can be changed by whoever can write the directory the config is
# in. `cp -a` for the backup and `cat > cfg` for the rewrite both followed a
# link at that name, so a link put there after the last read took root's write
# to its target. Now the config is opened once, no-follow, and everything is
# read from and written through that descriptor: a link at the name is refused,
# and a name swapped later cannot redirect a write that never uses the name.
# The backup is created exclusively and without following, beside the config.
# The installer also refuses to run this unless the trusted-path check passes
# on the config (install-can-delete-timer.sh).
set -euo pipefail
cfg="${1:?usage: dedup-nodedb.sh /path/to/rippled.cfg}"
[[ -f "$cfg" ]] || { echo "no such file: $cfg" >&2; exit 1; }
[[ -w "$cfg" ]] || { echo "$cfg not writable by $(id -un)" >&2; exit 1; }

# Root's own interpreter at a fixed path, never one a PATH finds.
py=""
for p in /usr/bin/python3 /bin/python3; do
  if [[ -x "$p" ]]; then py="$p"; break; fi
done
[[ -n "$py" ]] || { echo "no python3 at /usr/bin or /bin to rewrite $cfg with" >&2; exit 1; }

exec "$py" -I - "$cfg" <<'PY'
import grp
import os
import pwd
import re
import stat
import sys
import time

cfg = sys.argv[1]


def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)


NODE_DB = re.compile(rb"^\s*\[node_db\]\s*$")
ANY_STANZA = re.compile(rb"^\s*\[")
ADV = re.compile(rb"^\s*advisory_delete\s*=")


def count(lines):
    n, inb = 0, False
    for ln in lines:
        if NODE_DB.match(ln):
            inb = True
            continue
        if inb and ANY_STANZA.match(ln):
            inb = False
        if inb and ADV.match(ln):
            n += 1
    return n


def owner_of(st):
    try:
        u = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        u = str(st.st_uid)
    try:
        g = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        g = str(st.st_gid)
    return "%s:%s:%o" % (u, g, stat.S_IMODE(st.st_mode))


def split(data):
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


# One open, no-follow. A link at the name is ELOOP here, and nothing below
# looks the name up again for a read or a write.
try:
    fd = os.open(cfg, os.O_RDWR | os.O_NOFOLLOW | os.O_NOCTTY)
except OSError as e:
    die("cannot open %s without following a link: %s" % (cfg, e.strerror))
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode):
    die("%s is not a regular file" % cfg)


def read_all():
    out = b""
    off = 0
    while True:
        chunk = os.pread(fd, 1 << 20, off)
        if not chunk:
            return out
        out += chunk
        off += len(chunk)


old = read_all()
old_lines = split(old)
before = count(old_lines)
own_before = owner_of(st)
print("before: %d advisory_delete line(s) in [node_db], owner %s" % (before, own_before))
if before <= 1:
    print("already <=1; nothing to do.")
    sys.exit(0)

# The backup: created exclusively and without following, from the bytes read
# through the descriptor, then given the config's owner, mode and times.
stamp = time.strftime("%Y%m%d-%H%M%S")
bak = "%s.%s.predup.bak" % (cfg, stamp)
try:
    bfd = os.open(bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except OSError as e:
    die("cannot create the backup %s: %s" % (bak, e.strerror))
try:
    boff = 0
    while boff < len(old):
        boff += os.write(bfd, old[boff:])
    os.fchown(bfd, st.st_uid, st.st_gid)
    os.fchmod(bfd, stat.S_IMODE(st.st_mode))
    os.utime(bfd, ns=(st.st_atime_ns, st.st_mtime_ns))
finally:
    os.close(bfd)
with open(bak, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as f:
    if f.read() != old:
        die("backup mismatch")

# Keep the first advisory_delete line inside [node_db].
kept, removed = [], []
inb, seen = False, False
for ln in old_lines:
    if NODE_DB.match(ln):
        inb = True
        kept.append(ln)
        continue
    if inb and ANY_STANZA.match(ln):
        inb = False
    if inb and ADV.match(ln):
        if seen:
            removed.append(ln)
            continue
        seen = True
    kept.append(ln)

after = count(kept)
if after != 1:
    die("rewrite left %d advisory_delete lines, aborting; %s untouched" % (after, cfg))
# The only change may be removed advisory_delete lines.
strip = lambda ls: [x for x in ls if not ADV.match(x)]
if strip(old_lines) != strip(kept):
    die("rewrite changed a non-advisory_delete line, aborting; %s untouched" % cfg)

print("--- lines being removed ---")
for ln in removed:
    sys.stdout.write("< " + ln.decode("utf-8", "replace") + "\n")
sys.stdout.flush()

# Another hook point for the suite: a command run between the last read and the
# write, to put a link at the config's name. Honoured only when not root.
hook = os.environ.get("APERIRE_DEDUP_TEST_BETWEEN") if os.geteuid() != 0 else None
if hook:
    import subprocess
    subprocess.run([hook, cfg], check=False)

# Truncate-write the inode we hold: owner/group/mode ride through unchanged.
new = b"\n".join(kept) + b"\n"
os.ftruncate(fd, 0)
view = memoryview(new)
off = 0
while off < len(view):
    off += os.pwrite(fd, view[off:], off)
os.fsync(fd)

st2 = os.fstat(fd)
own_after = owner_of(st2)
if own_after != own_before:
    die("owner/mode changed %s -> %s; restore %s" % (own_before, own_after, bak))
final = count(split(read_all()))
if final != 1:
    die("final count is %d, restore %s" % (final, bak))
print("done: 1 advisory_delete line in [node_db], owner %s (unchanged), backup %s" % (own_after, bak))
PY
