#!/usr/bin/env python3
"""Repoint THIS host's own row in dashboard/config/fleet.yaml at the node key
its node now answers with (#488).

    fleet-self-pin.py <fleet.yaml> <this dashboard's port> <pubkey_node>

Exit codes, because the caller prints a different sentence for each:

    0   the row was rewritten. stdout says which row and which two keys.
    2   nothing to do, and stdout says which of the reasons it was: no row
        for this host, more than one, a row that pins nothing, or a row
        already naming this key.
    1   refused. stdout says why, and the file is untouched.

Why a line rewrite and not a load-and-dump: fleet.yaml is hand-edited and
carries comments, and yaml.safe_dump would return a file with none of them,
every row reordered and every string requoted. The parse is used only to FIND
the row; one line is then replaced in place, so the bytes around it, and the
file's owner and mode, are exactly what they were.

Which row is this host's: the one whose read_origin is a loopback origin on
this dashboard's own port. That is resolveFleet's rule in
dashboard/lib/fleet-health.ts, re-stated here rather than guessed at, because
a second rule for the same question is how an installer repoints the wrong
node's row on a host running two instances.
"""
import os
import re
import sys
import tempfile
from urllib.parse import urlsplit

try:
    import yaml
except ImportError:
    print("python3 has no yaml module (apt install python3-yaml), so the registry row was not checked")
    sys.exit(1)

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
KEY_RE = re.compile(r"^n[1-9A-HJ-NP-Za-km-z]{20,}$")


def is_self(origin, port):
    try:
        u = urlsplit(str(origin))
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    if host == "::1":
        host = "::1"
    if host not in LOOPBACK:
        return False
    got = u.port
    if got is None:
        got = 443 if u.scheme == "https" else 80
    return got == port


def main():
    if len(sys.argv) != 4:
        print("usage: fleet-self-pin.py <fleet.yaml> <port> <pubkey_node>")
        return 1
    path, port_s, key = sys.argv[1], sys.argv[2], sys.argv[3]
    if not port_s.isdigit():
        print("the dashboard port is not a number, so no row could be identified")
        return 1
    port = int(port_s)
    # The key came off this host's own node over loopback, and it is about to
    # be written into a file the dashboard fails closed on. Shape-checked with
    # the same expression fleet-registry.ts refuses a malformed pin with, so a
    # garbled read can never turn a working registry into an empty fleet.
    if not KEY_RE.match(key):
        print("the node reported something that is not shaped like a node key, so nothing was written")
        return 1

    with open(path) as f:
        raw = f.read()
    try:
        doc = yaml.safe_load(raw) or {}
    except yaml.YAMLError as e:
        print("could not parse %s (%s)" % (path, str(e).splitlines()[0]))
        return 1
    rows = doc.get("fleet") or doc.get("nodes") or []
    if not isinstance(rows, list):
        print("%s has no list of nodes in it" % path)
        return 1

    mine = [r for r in rows if isinstance(r, dict) and is_self(r.get("read_origin"), port)]
    if not mine:
        print("no row in %s names this host (no read_origin on loopback:%d)" % (path, port))
        return 2
    if len(mine) > 1:
        print("%d rows in %s name loopback:%d, so which one is this host is ambiguous"
              % (len(mine), path, port))
        return 2
    row = mine[0]
    label = str(row.get("label") or "")
    pinned = row.get("expected_pubkey_node")
    if not pinned:
        # An unpinned row is a supported shape, not a lesser one. Adding a pin
        # is a decision an operator makes; an install must not make it for
        # them, and a row that gains one silently is a row that will fail
        # closed on a future re-key with nobody knowing why.
        print("the row for %s pins no node key, and an install does not add one" % (label or "this host"))
        return 2
    if str(pinned) == key:
        print("the row for %s already names the key this node answers with" % label)
        return 2

    # One line, found by the row's own value rather than by line number: the
    # file may hold several rows and only this one holds this key. A trailing
    # comment is matched and carried across untouched. It may well be about
    # the old key and read oddly afterwards, and that is still better than an
    # installer deleting a sentence an operator wrote.
    pat = re.compile(
        r"^(?P<indent>[ \t]*)expected_pubkey_node[ \t]*:[ \t]*(?P<q>['\"]?)"
        + re.escape(str(pinned)) + r"(?P=q)(?P<tail>[ \t]*(?:#.*)?)$",
        re.MULTILINE,
    )
    hits = pat.findall(raw)
    if len(hits) != 1:
        print("the expected_pubkey_node line for %s could not be located exactly once in the file "
              "(%d matches), so it was left alone" % (label, len(hits)))
        return 1
    new_raw = pat.sub(
        lambda m: "%sexpected_pubkey_node: %s%s" % (m.group("indent"), key, m.group("tail")),
        raw, count=1,
    )

    # Read the result back through the same parser before it replaces
    # anything: a rewrite that does not parse as the row it meant to write is
    # a rewrite that empties this fleet on the next reload.
    try:
        check = yaml.safe_load(new_raw) or {}
    except yaml.YAMLError as e:
        print("the rewritten registry does not parse (%s), so nothing was written"
              % str(e).splitlines()[0])
        return 1
    crows = check.get("fleet") or check.get("nodes") or []
    cmine = [r for r in crows if isinstance(r, dict) and is_self(r.get("read_origin"), port)]
    if len(cmine) != 1 or cmine[0].get("expected_pubkey_node") != key or len(crows) != len(rows):
        print("the rewritten registry does not read back as this host pinning that key, "
              "so nothing was written")
        return 1

    # Owner and mode kept across the swap: fleet.yaml belongs to the account
    # the dashboard runs as, and this runs as root.
    st = os.stat(path)
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".fleet-self-pin.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new_raw)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print("%s: the row for %s now pins %s (it pinned %s; owner and mode kept)"
          % (path, label, key, pinned))
    return 0


if __name__ == "__main__":
    sys.exit(main())
