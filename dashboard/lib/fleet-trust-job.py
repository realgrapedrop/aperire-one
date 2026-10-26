#!/usr/bin/env python3
# Assemble the fleet-trust-push job for fleet-trust-push.mjs.
#
# Kept in its own file (not a heredoc inside aperire-auth.sh) so nested
# quoting can never break the CLI's parse. Reads everything from the
# environment the bash caller sets — it never touches the database or the
# network, only shapes the job:
#
#   ORIGIN      public_url from authn.yaml (may be a comma list of origins)
#   RP_ID       the single rp_id (already comma-split by the caller)
#   PRIV        the aggregator's Ed25519 private seed (base64url)
#   ROWS        admin credential rows as JSON (the exact advisor-sync query)
#   ONLY        optional single node label to target
#   FLEET_FILE  path to the aggregator's fleet.yaml
#
# Emits the job JSON on stdout, or exits non-zero with a message on stderr
# when there is nothing to push to (3). Exit 4 means at least one node's
# Advisor token could not be read: those nodes are named on stderr, the job
# for the rest is still on stdout (empty when there is none), and the caller
# fails the run after sending it (#872).
import json, os, re, sys

origins = [o.strip() for o in os.environ["ORIGIN"].split(",") if o.strip()]
rows = json.loads(os.environ.get("ROWS") or "[]")
only = os.environ.get("ONLY") or ""

# Minimal, strict fleet.yaml target parse: a node is a target only if its
# block carries BOTH advisor_origin and advisor_token_path (slice 1's
# registration). A node without them has no advisor stack and is skipped.
targets, cur = [], {}
def flush():
    if cur.get("label") and cur.get("origin") and cur.get("token_path"):
        targets.append(dict(cur))

for line in open(os.environ["FLEET_FILE"]):
    m = re.match(r'\s*-\s*label:\s*(\S+)', line)
    if m:
        flush()
        cur.clear()
        # A hand-quoted label ("node-x" or 'node-x') is the label, not the quotes.
        lab = m.group(1)
        if len(lab) >= 2 and lab[0] == lab[-1] and lab[0] in "\"'":
            lab = lab[1:-1]
        cur["label"] = lab
        continue
    m = re.match(r'\s*advisor_origin:\s*(\S+)', line)
    if m: cur["origin"] = m.group(1)
    m = re.match(r'\s*advisor_token_path:\s*(\S+)', line)
    if m: cur["token_path"] = m.group(1)
flush()

out = []
unread = []
for t in targets:
    if only and t["label"] != only:
        continue
    try:
        tok = open(t["token_path"]).read().strip()
    except OSError as e:
        # Not a node without an Advisor: one this push cannot reach, which
        # keeps the previous trust set. Named, and the run fails (#872). The
        # word "failed" is what operator-admin.ts's parseTrustNodes reads as
        # a failure, so the page cannot show this node as pushed.
        print(f"  {t['label']}: failed, not pushed: its Advisor token could not be read ({e})", file=sys.stderr)
        unread.append(t["label"])
        continue
    out.append({"label": t["label"], "origin": t["origin"], "token": tok})

if not out and not unread:
    extra = f" matching --node {only}" if only else ""
    print(f"no fleet nodes with an advisor stack to push to{extra}", file=sys.stderr)
    sys.exit(3)
if not out:
    sys.exit(4)

json.dump({
    "rp_id": os.environ["RP_ID"],
    "origins": origins,
    "private_key": os.environ["PRIV"],
    "issuer_label": "aggregator",
    "rows": rows,
    "targets": out,
}, sys.stdout)
# 4: the job above is sent, and the run still fails, because the nodes named
# above keep the previous set.
if unread:
    sys.exit(4)
