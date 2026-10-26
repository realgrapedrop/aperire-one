#!/usr/bin/env python3
# Build the knowledge-bundle job for knowledge-push.mjs (ADR 0017 decision 3).
#
# Kept in its own file (not a heredoc inside the shell caller) so nested
# quoting can never break the CLI's parse, and because the tar and the
# manifest have to describe exactly the same set of files — the node refuses
# a bundle where either side carries something the other does not, so the two
# are built here in one pass rather than by two commands that could drift.
#
# Reads everything from the environment the caller sets. It never signs, never
# touches the network, and never reads the database:
#
#   KNOW_DIR    the aggregator's advisor/knowledge-fleet
#   OUT_TAR     where to write the tar.gz
#   SEQ         this bundle's sequence number (already reserved by the caller)
#   ISSUER      which peers.<label> key on the node verifies this
#   PUSHED_BY   the operator account building it
#   ONLY        optional single node label to target
#   FLEET_FILE  path to the aggregator's fleet.yaml
#
# Emits the job JSON on stdout, or exits non-zero with a message on stderr.
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time

know = os.environ["KNOW_DIR"]
out_tar = os.environ["OUT_TAR"]
seq = int(os.environ["SEQ"])
issuer = os.environ.get("ISSUER") or "aggregator"
pushed_by = os.environ.get("PUSHED_BY") or "unknown"
only = os.environ.get("ONLY") or ""

# ── the corpus ────────────────────────────────────────────────────────────
# Only the two layers, only markdown, only regular files. The node refuses
# everything else at its door; refusing it here as well means the operator
# hears about it before the push rather than as a rejection from every node.
files = []
for layer in ("base", "local"):
    root = os.path.join(know, layer)
    if not os.path.isdir(root):
        continue
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        if "nodes" in dirnames:
            print(f"refusing to push: {os.path.join(dirpath, 'nodes')} — nodes/ belongs to "
                  "per-node knowledge written on the node itself", file=sys.stderr)
            sys.exit(3)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            if not name.endswith(".md"):
                continue
            if name == "role-policy.md":
                print(f"refusing to push: {full} — role-policy.md ships with the release, "
                      "it is never pushed", file=sys.stderr)
                sys.exit(3)
            rel = os.path.relpath(full, know).replace(os.sep, "/")
            files.append((rel, full))

if not files:
    print(f"nothing to push: no markdown under {know}/base or {know}/local", file=sys.stderr)
    sys.exit(3)

# ── the archive ───────────────────────────────────────────────────────────
# Deterministic: sorted names, fixed modes, no owner, no timestamps. The same
# corpus produces the same bytes twice, which is what makes an archived
# bundle comparable to the one before it.
manifest_files = []
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
    with tarfile.open(fileobj=gz, mode="w") as tar:
        for rel, full in sorted(files):
            with open(full, "rb") as fh:
                body = fh.read()
            info = tarfile.TarInfo(rel)
            info.size = len(body)
            info.mode = 0o640
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(body))
            manifest_files.append({"path": rel, "sha256": hashlib.sha256(body).hexdigest()})

with open(out_tar, "wb") as fh:
    fh.write(buf.getvalue())
os.chmod(out_tar, 0o640)

# ── the targets ───────────────────────────────────────────────────────────
# A node is a target only if its fleet.yaml block carries BOTH advisor_origin
# and advisor_token_path. A node without them has no advisor stack and is
# skipped. Same rule and same shape as lib/fleet-trust-job.py's parse; kept
# separate on purpose, so a change to how knowledge is pushed can never
# alter which nodes a CREDENTIAL push reaches.
targets, cur = [], {}


def flush():
    if cur.get("label") and cur.get("origin") and cur.get("token_path"):
        targets.append(dict(cur))


for line in open(os.environ["FLEET_FILE"]):
    m = re.match(r"\s*-\s*label:\s*(\S+)", line)
    if m:
        flush()
        cur.clear()
        cur["label"] = m.group(1)
        continue
    m = re.match(r"\s*advisor_origin:\s*(\S+)", line)
    if m:
        cur["origin"] = m.group(1)
    m = re.match(r"\s*advisor_token_path:\s*(\S+)", line)
    if m:
        cur["token_path"] = m.group(1)
flush()

out = []
for t in targets:
    if only and t["label"] != only:
        continue
    try:
        with open(t["token_path"]) as fh:
            tok = fh.read().strip()
    except OSError as e:
        print(f"  {t['label']}: SKIPPED — token unreadable ({e})", file=sys.stderr)
        continue
    out.append({"label": t["label"], "origin": t["origin"], "token": tok})

if not out:
    extra = f" matching --node {only}" if only else ""
    print(f"no fleet nodes with an advisor stack to push to{extra}", file=sys.stderr)
    sys.exit(3)

json.dump({
    "manifest": {
        "seq": seq,
        "files": manifest_files,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issuer_label": issuer,
        "pushed_by": pushed_by,
    },
    "bundle_path": out_tar,
    "targets": out,
}, sys.stdout)
