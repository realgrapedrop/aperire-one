#!/usr/bin/env bash
# Exercise scripts/get-aperire.sh, the bootstrap behind the one-line install.
#
# What is being protected: this is the script an operator runs by pasting a
# URL into a root-capable shell on a box with nothing on it. Three of its
# promises fail silently if they break.
#
#   1. A half-delivered copy must not run. `curl | bash` executes what has
#      arrived as it arrives, so a connection cut mid-download runs the top
#      half of an installer and stops. Every check here has its opposite
#      beside it, because "nothing happened" is also what a test proves when
#      the script never ran at all.
#   2. What it decided must be what it passed on. The role it detects is the
#      role install.sh receives, `relay` included, which install.sh calls
#      `validator` and nothing else in the tree renames.
#   3. The closing banner must mean something. It prints after the dashboard
#      answered, never instead of it, so the health check is asserted both
#      ways: up prints the banner, down prints the log to read and exits
#      non-zero with no banner at all.
#
#   bash scripts/test-get-aperire.sh
#
# Runs entirely in a temporary directory against fake git, curl, sudo,
# systemctl, pgrep, docker and apt-get on PATH, and a fake release tree that
# records what install.sh was called with. Touches no host, needs no root,
# and installs nothing.

set -uo pipefail
# Root copies refuse a destination directory anyone but its owner can write
# (ADR 0024), as they would on a host, so the fixture is made like a host: 022.
umask 022

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The file in the repository. It carries no release key (the builder stamps
# one in), so the copy these rows run is SUT below: the same bytes with a
# throwaway key stamped into the signer block, made once the key exists.
SUT_REPO="$REPO_DIR/scripts/get-aperire.sh"
SUT="$SUT_REPO"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$SUT" ]] || { echo "no get-aperire.sh at $SUT"; exit 1; }

# The operator's home in this fixture is "op", not "home": the docs gate in CI
# greps every shipped script for a literal /home/<name>/ path, and a fake one
# in a test would fail it exactly like a real one.
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/op" "$TMP/etc" "$TMP/release/scripts"

# ── The fake release ────────────────────────────────────────────────
# What `git clone` hands back. Its install.sh records the arguments it was
# given and does the two things the bootstrap later checks for: it registers
# a unit and it puts the CLI where cli-only promises to.
# Written through a function because two rows further down replace this
# file with a smaller one for their own purposes, and a row after those
# that still expects the full fixture would otherwise be reading theirs.
write_fake_install() {
cat > "$TMP/release/install.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/install-args"
printf 'install\n' >> "$TMP/state/order"
# Which copy root ran, and the tree it was told to act on (#764): root runs
# a copy it staged out of the release, never the tree's own install.sh.
printf '%s\n' "\$0" >> "$TMP/state/install-self"
printf '%s\n' "\${APERIRE_INSTALL_TREE:-<unset>}" >> "$TMP/state/install-tree"
TREE="\${APERIRE_INSTALL_TREE:-\$(cd "\$(dirname "\$0")" && pwd)}"
# state/tamper-signers: something with write access to the tree changes the
# release key in it while the install runs, which is the window root's copy
# afterwards must not trust.
if [[ -f "$TMP/state/tamper-signers" ]]; then
  printf 'aperire-release-key namespaces="aperire-release" %s planted\n' "\$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
    >> "\$TREE/scripts/release-signers"
fi
# state/tamper-download: the same account also rewrites the signed manifest
# it downloaded, so that it names the planted file. Root must never read the
# download again after checking its own copy.
if [[ -f "$TMP/state/tamper-download" ]]; then
  planted="\$(sha256sum "\$TREE/scripts/release-signers" | cut -d' ' -f1)"
  for d in "$TMP/tmpd"/aperire-fetch.*; do
    [[ -f "\$d/release.files" ]] || continue
    sed -i "s|^[0-9a-f]\\{64\\}  scripts/release-signers\$|\$planted  scripts/release-signers|" "\$d/release.files"
    printf 'tampered %s\n' "\$d" >> "$TMP/state/tampered"
  done
fi
printf '%s\n' "\${APERIRE_RIPPLED_URL:-<unset>}" >> "$TMP/state/install-node-url"
printf '%s\n' "\${APERIRE_RECORD_ROLE:-<unset>}" >> "$TMP/state/install-record-role"
# Whether install.sh was handed a real terminal on stdin. The fleet-join step
# asks for a pairing code and the pair command below it pauses twice, and both
# of those need one. The chain is guard 1's \`exec bash "\$tmp" "\$@" < /dev/tty\`
# -> run_root -> sudo -> here, and every link of it is an assumption until
# something records what arrived at the far end.
printf '%s\n' "\$( [[ -t 0 ]] && echo yes || echo no )" >> "$TMP/state/install-stdin-tty"
case "\$*" in
  *--role=validator*) printf 'aperire-relay.service enabled\n'  >> "$TMP/state/units" ;;
  *--role=cli-only*)  mkdir -p "$TMP/op/.local/bin"
                      : > "$TMP/op/.local/bin/aperire-auth"
                      chmod +x "$TMP/op/.local/bin/aperire-auth" ;;
  *)                  printf 'aperire-server.service enabled\n' >> "$TMP/state/units" ;;
esac
# state/install-adds-units: unit lines this install leaves besides the dashboard,
# for a host where role detection found a node and the relay came back (#1181).
[[ -f "$TMP/state/install-adds-units" ]] && cat "$TMP/state/install-adds-units" >> "$TMP/state/units"
# The real install.sh writes the service environment. This is where the
# closing banner reads the bind address from, so the fixture writes it too
# and only after the install, exactly like the real one: a directory that
# existed BEFORE would make the host read as already installed.
if [[ -f "$TMP/state/bindhost" ]]; then
  mkdir -p "$TMP/etc/aperire"
  printf 'HOST=%s\nPORT=7800\n' "\$(cat "$TMP/state/bindhost")" > "$TMP/etc/aperire/aperire.env"
fi
# Something writing into the tree between the unpack and the root steps,
# which on a real update is minutes of npm ci and builds run as the tree's
# own account. state/tamper lists paths in the release; each is rewritten
# here, or created when the release never shipped it (ADR 0024, lane 2).
if [[ -f "$TMP/state/tamper" ]]; then
  here="\$TREE"
  while IFS= read -r rel; do
    [[ -n "\$rel" ]] || continue
    mkdir -p "\$(dirname "\$here/\$rel")"
    # state/tamper-payload, when there is one, is what gets written: code
    # that leaves a mark if anything ever runs it.
    if [[ -f "$TMP/state/tamper-payload" ]]; then
      cp "$TMP/state/tamper-payload" "\$here/\$rel"
    else
      printf 'EVIL %s\n' "\$rel" > "\$here/\$rel"
    fi
  done < "$TMP/state/tamper"
fi
# state/shape-703: the tree and advisor/ left group-writable (umask 002),
# the shape #703 found on koi.
if [[ -f "$TMP/state/shape-703" ]]; then
  chmod 0775 "\$TREE" "\$TREE/advisor"
fi
if [[ -f "$TMP/state/install-refuses" && -n "\${RD_REFUSED_LOG:-}" ]]; then
  cat "$TMP/state/install-refuses" >> "\$RD_REFUSED_LOG"
  echo "  ----- installation complete, with refusals -----"
  exit 4
fi
echo "  ----- installation complete -----"
EOF
chmod +x "$TMP/release/install.sh"
}
write_fake_install
printf '#!/usr/bin/env bash\necho prepare-host\n' > "$TMP/release/scripts/prepare-host.sh"

# The release's own checklist, stubbed. What is under test here is the ORDER
# and the wiring, not the checks themselves: those are scripts/test-preflight.sh,
# which drives the real file. This one records that it ran, when it ran, and
# what it was told, answers the node question into the answer file it was
# given, and refuses when state/preflight-fails says to.
cat > "$TMP/release/scripts/preflight.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/preflight-args"
printf 'preflight\n' >> "$TMP/state/order"
echo "  ok       node: a node, admin WS 127.0.0.1:6006"
for a in "\$@"; do
  case "\$a" in
    --answer-file=*)
      [[ -f "$TMP/state/preflight-answer" ]] \
        && cp "$TMP/state/preflight-answer" "\${a#*=}" ;;
  esac
done
if [[ -f "$TMP/state/preflight-fails" ]]; then
  echo "  MISSING  disk: 2 GB free on / (/root), and the build needs 5"
  exit 1
fi
exit 0
EOF
chmod +x "$TMP/release/scripts/preflight.sh"
printf '#!/usr/bin/env bash\necho menu\n' > "$TMP/release/aperire-one"
# The node installer, stubbed: records that it ran and where in the order,
# and from then on the fake host has a node (the process list the probe
# reads), which is what the real one leaves behind.
cat > "$TMP/release/scripts/install-aperire-node.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/node-install-args"
# --adopt is the other verb entirely: it records a node that is already here
# and installs nothing, so this stub writes the record and leaves the fake
# host's process and container lists alone. state/adopt-fails makes it refuse
# the way the real one does when it cannot be sure which node it is looking
# at, which is what the bootstrap must survive rather than stop on.
# --move-source (#802) changes package sources and nothing else, so it is
# recorded and answers; state/move-fails makes it refuse, which an update
# has to survive rather than stop on.
if [[ "\$*" == *--move-source* ]]; then
  printf 'move-source\n' >> "$TMP/state/order"
  if [[ -f "$TMP/state/move-fails" ]]; then
    echo "  error: the downloaded apt key's fingerprint does not match" >&2
    exit 1
  fi
  echo "   apt now offers xrpld 3.4.1-1"
  exit 0
fi
if [[ "\$*" == *--adopt* ]]; then
  printf 'adopt\n' >> "$TMP/state/order"
  if [[ -f "$TMP/state/adopt-fails" ]]; then
    echo "  error: more than one container here looks like an XRPL node" >&2
    exit 1
  fi
  mkdir -p "$TMP/etc/aperire"
  printf 'KIND=container\nSERVICE=stock-node1\nCONFIG_FILE=/n/config/rippled.cfg\nNODE_LABEL=stock-node1\n' \
    > "$TMP/etc/aperire/node.conf"
  echo "   /etc/aperire/node.conf names stock-node1"
  exit 0
fi
printf 'node\n' >> "$TMP/state/order"
printf 'rippled\n' >> "$TMP/state/procs"
echo "The node is up. 6 check(s) passed."
EOF
chmod +x "$TMP/release/scripts/install-aperire-node.sh"
# The two directories a carried file lands in, and the release's own defaults
# in one of them: a config file the operator tuned has to beat the shipped one,
# and a mv into a directory that does not exist would fail silently otherwise.
# The programs that run as root out of /usr/local/sbin. They live in the
# tree and are COPIED there by their installers, so a tree swap leaves the
# installed copies on the previous release (#185): the update refreshes them,
# and these are what it refreshes from. The fleet broker is the third of
# them and the one #443 was met on: only an aggregator has one.
printf 'the NEW sealer\n'     > "$TMP/release/scripts/aperire-seal-model-key.sh"
printf 'the NEW trust sync\n' > "$TMP/release/scripts/aperire-trust-sync.sh"
printf 'the NEW updater\n'    > "$TMP/release/scripts/aperire-update.sh"
printf 'the NEW broker, with the fleet-model store verbs\n' > "$TMP/release/scripts/aperire-fleet-broker.sh"
printf 'the NEW fleet arm, with --fingerprint\n' > "$TMP/release/scripts/aperire-fleet-arm.sh"
printf 'the NEW credcheck\n'  > "$TMP/release/scripts/aperire-advisord-credcheck.sh"
# The real library, not a stub (#541): refresh_advisord_recovery sources this
# for real to reach write_advisord_credcheck_unit, the one function that
# copies the credcheck program and writes its recovery unit for every caller.
# A fake here would test this suite's own fixture, not the wiring that has
# to hold on a real release.
cp "$REPO_DIR/scripts/advisord-credcheck-lib.sh" "$TMP/release/scripts/advisord-credcheck-lib.sh"
# The state helper travels with the credcheck program and the sealer (#703):
# both write advisor/state through it and resolve it from /usr/local/sbin, so
# the function above places it on the same compare. A release without one is
# a release those two programs refuse on, which is the right refusal and the
# wrong fixture.
# The real grants program (#699), for the same reason as the library above:
# refresh_advisord_grants runs it as root out of the new tree, and a stub
# would prove only that a stub was called.
cp "$REPO_DIR/scripts/advisord-unit-grants.sh" "$TMP/release/scripts/advisord-unit-grants.sh"
cp "$REPO_DIR/scripts/advisord-unit-grants-lib.sh" "$TMP/release/scripts/advisord-unit-grants-lib.sh"
printf 'the NEW state helper\n' > "$TMP/release/scripts/state-file.py"
# And the method library (#708), which travels the same way and for the same
# reason: the sealer and the credential check both read it to learn how this
# host keeps a model key, and both refuse without it.
printf 'the NEW key method library\n' > "$TMP/release/scripts/model-key-method-lib.sh"

# The xrpld image recipe: four files. An update places them itself, each
# through the same checked copy as the programs above, and never runs the
# tree's own recipe installer to do it (ADR 0024): that would be root running
# a script the tree's account can rewrite. The installer here records every
# call, so a row can prove nothing called it, and otherwise copies what the
# tree holds the way the real one does, so the tamper row below fails for
# the right reason on a tree that still runs it.
mkdir -p "$TMP/release/scripts/xrpld-image"
printf 'the NEW build script\n'  > "$TMP/release/scripts/build-xrpld-image.sh"
printf 'the NEW Dockerfile\n'    > "$TMP/release/scripts/xrpld-image/Dockerfile"
printf 'the NEW entrypoint\n'    > "$TMP/release/scripts/xrpld-image/entrypoint.sh"
printf 'the NEW signed hash\n'   > "$TMP/release/scripts/xrpld-image/signed-binary-sha256.sh"
cat > "$TMP/release/scripts/install-xrpld-image-recipe.sh" <<'RECIPE'
#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${APERIRE_IMAGE_RECIPE_DIR:-/usr/local/lib/aperire}"
printf '%s\n' "$*" >> "${APERIRE_RECIPE_CALLS:-/dev/null}"
if [[ "${1:-}" == --refresh-only && ! -e "$dest/build-xrpld-image.sh" ]]; then
  exit 0
fi
mkdir -p "$dest/xrpld-image"
cp "$here/build-xrpld-image.sh" "$dest/build-xrpld-image.sh"
for f in Dockerfile entrypoint.sh signed-binary-sha256.sh; do
  cp "$here/xrpld-image/$f" "$dest/xrpld-image/$f"
done
RECIPE
chmod +x "$TMP/release/scripts/install-xrpld-image-recipe.sh"
# The node wrapper and the two libraries it loads (ADR 0024). The update
# places them in /usr/local/sbin and /usr/local/lib/aperire through the real
# library, which judges the source first, so the library is the real one and
# the two it copies are stand-ins with their own words in them.
cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/release/scripts/trusted-path-lib.sh"
# The broker behind the Advisor's root socket (ADR 0025), which the update
# places as root through the release's digests.
cp "$REPO_DIR/scripts/aperire-wrapper-broker.py" "$TMP/release/scripts/aperire-wrapper-broker.py"
# The account installer and every file it loads or runs, which an accepted
# move stages out of the release as a checked set (#779 review, L1).
for f in install-advisor-account.sh fleet-corpus-perms.sh advisord-credcheck-lib.sh \
         advisord-restart-lib.sh release-digests-lib.sh trusted-path-lib.sh state-ancestors-lib.sh \
         state-file.py close-node-config-exposure.sh fleet-trust-split.sh fleet-trust-perms.sh \
         advisor-owner-lib.sh dashboard-account-lib.sh; do
  [[ -e "$TMP/release/scripts/$f" ]] || cp "$REPO_DIR/scripts/$f" "$TMP/release/scripts/$f"
done
printf '#!/usr/bin/env bash\necho the NEW wrapper\n' > "$TMP/release/scripts/aperire-node-wrapper.sh"
printf '# the NEW config-write library\n' > "$TMP/release/scripts/config-write-lib.sh"
mkdir -p "$TMP/release/dashboard/config" "$TMP/release/advisor"
printf 'swap_warn: 60   # the release default\n' > "$TMP/release/dashboard/config/rules.yaml"
printf 'daily: false    # the release default\n' > "$TMP/release/dashboard/config/digest.yaml"
chmod +x "$TMP/release/install.sh" "$TMP/release/scripts/prepare-host.sh" "$TMP/release/aperire-one"
chmod +x "$TMP/release/scripts/preflight.sh"

# The release key and the check, in the tree the way a real release carries
# them, so an update's refresh of the root copies has something to copy.
cp "$REPO_DIR/scripts/release-verify-lib.sh" "$TMP/release/scripts/release-verify-lib.sh"

# ── The test key ────────────────────────────────────────────────────
# Made fresh for every run, never committed, and never the release key: a
# software ed25519 key, which is exactly the type the publisher refuses to
# put in front of an operator. A second one stands for "somebody else".
ssh-keygen -q -t ed25519 -N '' -C 'test-key-never-trusted' -f "$TMP/testkey" </dev/null
ssh-keygen -q -t ed25519 -N '' -C 'somebody-else' -f "$TMP/otherkey" </dev/null
printf 'aperire-release-key namespaces="aperire-release" %s test-key-never-trusted\n' \
  "$(cut -d' ' -f1,2 "$TMP/testkey.pub")" > "$TMP/test-signers"
cp "$TMP/test-signers" "$TMP/release/scripts/release-signers"

# The copy under test: the repository's file with the test key stamped into
# its signer block, the way the builder stamps the release key.
SUT="$TMP/get-aperire.sh"
awk -v body="RELEASE_SIGNERS='$(cat "$TMP/test-signers")'" '
  $0 == "# >>> release signers >>>" { print; print body; skip = 1; next }
  $0 == "# <<< release signers <<<" { skip = 0 }
  skip { next }
  { print }' "$SUT_REPO" > "$SUT"
grep -q "^RELEASE_SIGNERS='aperire-release-key " "$SUT" \
  || { echo "the release-signers block has moved in $SUT_REPO; the stamp matched nothing"; exit 1; }

# ── The same release, as an archive ─────────────────────────────────
# What the endpoint serves: one .tar.gz holding one aperire-one/ directory,
# built out of the same fake release the fake `git clone` hands back. Same
# tree through both doors, which is what lets the two be compared file for
# file below.
mkdir -p "$TMP/tarsrc/aperire-one"
cp -r "$TMP/release/." "$TMP/tarsrc/aperire-one/"
tar -czf "$TMP/release.tar.gz" -C "$TMP/tarsrc" aperire-one
GOOD_SHA="$(sha256sum "$TMP/release.tar.gz" | cut -d' ' -f1)"

# A download that was cut: the first 400 bytes of that same archive. Every
# row about the checksum uses this rather than an invented mismatch, because
# a connection dropped mid-download is the failure the checksum is there for,
# and a truncated gzip is also the input that would half-unpack if anything
# ever unpacked before checking.
head -c 400 "$TMP/release.tar.gz" > "$TMP/truncated.tar.gz"

# ── The signed files for that archive ──────────────────────────────
# What the publisher serves beside it: release.json naming the archive and
# the per-file manifest, signed with the test key, under the names that never
# change. The fake curl serves them out of $TMP/signed, or out of whatever
# directory state/signed-from names, which is how a row serves a tampered set.
# The key set a release names, reduced the way the lib reduces it: the type
# and base64 columns, sorted, hashed.
signers_digest() { awk '!/^[[:space:]]*#/ && NF >= 4 { print $3 " " $4 }' "$1" | LC_ALL=C sort | sha256sum | cut -d' ' -f1; }
sign_release() { # $1 = dir, $2 = archive sha, $3 = key, $4 = published_at, $5 = manifest source tree, $6 = signer set it names
  local d="$1" sha="$2" key="$3" at="$4" tree="${5:-$TMP/tarsrc/aperire-one}" set="${6:-$TMP/test-signers}"
  mkdir -p "$d"
  ( cd "$tree" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum ) \
    | sed 's|^\([0-9a-f]\{64\}\)  \./|\1  |' > "$d/release-$sha.files"
  printf '{\n  "tag": "snapshot-test",\n  "commit": "abc1234",\n  "sha256": "%s",\n  "published_at": "%s",\n  "bootstrap_sha256": "%s",\n  "files_sha256": "%s",\n  "signers_sha256": "%s"\n}\n' \
    "$sha" "$at" "$(printf 'b%.0s' {1..64})" "$(sha256sum "$d/release-$sha.files" | cut -d' ' -f1)" "$(signers_digest "$set")" \
    > "$d/release-$sha.json"
  rm -f "$d/release-$sha.json.sig"
  ssh-keygen -q -Y sign -f "$key" -n aperire-release "$d/release-$sha.json" </dev/null
}
sign_release "$TMP/signed" "$GOOD_SHA" "$TMP/testkey" 2026-09-01T00:00:00Z

# ── Fakes on PATH ───────────────────────────────────────────────────
# git: clone copies the fake release; everything else is quiet and recorded.
cat > "$TMP/bin/git" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/git-calls"
args=(); for a in "\$@"; do args+=("\$a"); done
case "\${args[0]}" in
  clone)
    dest="\${args[\${#args[@]}-1]}"
    mkdir -p "\$dest" && cp -r "$TMP/release/." "\$dest/" && mkdir -p "\$dest/.git"
    ;;
  -C) case "\${args[2]}" in
        rev-parse) echo abc1234 ;;
        *) : ;;
      esac ;;
esac
exit 0
EOF

# curl: three callers, told apart by their arguments. A .tar.gz is the release
# being fetched (real curl reads a file:// path itself; an https one is served
# from whatever state/tarball names). Any other -o is the script fetching
# itself (state/self decides what arrives). No -o is the closing health check
# (state/healthz decides what answers, below). It reads -f and -w the way the
# real curl does, because the check under test is a question of which of them
# it leans on (#1177): -f turns a 4xx or 5xx into exit 22, and -w prints the
# status after the body, as it does on a refused connection too (000).
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
out=""; url=""; src=""; wfmt=""; fail=0
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    -w) wfmt="\$2"; shift 2 ;;
    -*f*) fail=1; shift ;;
    http*|file://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
# The signed files beside an archive: release-<sha>.json, .json.sig, .files.
case "\$url" in
  *.json|*.json.sig|*.files)
    if [[ -n "\$out" ]]; then
      who=operator; [[ -n "\${APERIRE_TEST_VIA_SUDO+x}" ]] && who=root
      printf '%s\n' "signed-fetch \$who \$url" >> "$TMP/state/curl-calls"
      # What an attacker on the operator's account does to a download it can
      # reach: a symlink to a root file, or a FIFO. Root never fetches into a
      # place that account can reach, so neither is ever met there.
      if [[ "\$who" == operator && -f "$TMP/plant/link" ]]; then ln -sf "\$(cat "$TMP/plant/link")" "\$out"; exit 0; fi
      if [[ "\$who" == operator && -f "$TMP/plant/fifo" ]]; then rm -f "\$out"; mkfifo "\$out"; exit 0; fi
      if [[ -f "$TMP/plant/oversize" ]]; then head -c 9000000 /dev/zero > "\$out"; exit 0; fi
      from="\$(cat "$TMP/state/signed-from" 2>/dev/null || echo "$TMP/signed")"
      [[ -f "\$from/\${url##*/}" ]] || exit 22
      cp "\$from/\${url##*/}" "\$out"; exit 0
    fi ;;
esac
if [[ -n "\$out" && "\$url" == *.tar.gz ]]; then
  printf '%s\n' "tarball-fetch \$url" >> "$TMP/state/curl-calls"
  case "\$url" in
    file://*) src="\${url#file://}" ;;
    *)        src="\$(cat "$TMP/state/tarball" 2>/dev/null)" ;;
  esac
  [[ -n "\$src" && -f "\$src" ]] || exit 22
  cp "\$src" "\$out"; exit 0
fi
if [[ -n "\$out" ]]; then
  printf '%s\n' "self-fetch \$url" >> "$TMP/state/curl-calls"
  [[ -f "$TMP/state/self" ]] || exit 22
  cp "$TMP/state/self" "\$out"; exit 0
fi
printf '%s\n' "\$url" >> "$TMP/state/curl-calls"
# state/healthz is what answers. up is the handler's 200. unready and
# unready-connected are its 503 for a node still catching up, with the bodies
# the real server wrote when it was booted for exactly that (dashboard/server.ts
# /healthz, node role, rippled unreachable; the second is the same body with the
# connection open, which the handler gives when no ledger has closed yet).
# other-<code> is some other program on the port. Anything else is nothing
# listening.
code=000; body=""
case "\$(cat "$TMP/state/healthz" 2>/dev/null)" in
  up)                code=200; body='{"ok":true}' ;;
  unready)           code=503; body='{"ok":false,"role":"node","rippled_connected":false,"ledger_age_ms":null,"relay_last_push_ms":null,"relay_last_push_at":null,"relay_label":null,"uptime_s":3,"asks_in_flight":0}' ;;
  unready-connected) code=503; body='{"ok":false,"role":"node","rippled_connected":true,"ledger_age_ms":null,"relay_last_push_ms":null,"relay_last_push_at":null,"relay_label":null,"uptime_s":3,"asks_in_flight":0}' ;;
  unready-then-up)   # a synced node's first seconds: 503 on the first ask, 200 after
                     if (( \$(grep -c '/healthz' "$TMP/state/curl-calls") <= 1 )); then
                       code=503; body='{"ok":false,"role":"node","rippled_connected":true,"ledger_age_ms":null,"relay_last_push_ms":null,"relay_last_push_at":null,"relay_label":null,"uptime_s":1,"asks_in_flight":0}'
                     else code=200; body='{"ok":true}'; fi ;;
  unready-then-down) # a dashboard that said 503 and then stopped answering (a crash loop that hit its start limit)
                     if (( \$(grep -c '/healthz' "$TMP/state/curl-calls") <= 1 )); then
                       code=503; body='{"ok":false,"role":"node","rippled_connected":true,"ledger_age_ms":null,"relay_last_push_ms":null,"relay_last_push_at":null,"relay_label":null,"uptime_s":1,"asks_in_flight":0}'
                     fi ;;
  unready-then-404)  if (( \$(grep -c '/healthz' "$TMP/state/curl-calls") <= 1 )); then
                       code=503; body='{"ok":false,"role":"node","rippled_connected":true,"ledger_age_ms":null,"relay_last_push_ms":null,"relay_last_push_at":null,"relay_label":null,"uptime_s":1,"asks_in_flight":0}'
                     else code=404; body='<html><body>not the dashboard</body></html>'; fi ;;
  404-then-down)     if (( \$(grep -c '/healthz' "$TMP/state/curl-calls") <= 1 )); then
                       code=404; body='<html><body>not the dashboard</body></html>'
                     fi ;;
  other-503-nojson)  code=503; body='{"ok":false,"error":"upstream"}' ;;
  other-503-norole)  code=503; body='{"role":"gateway","error":"upstream"}' ;;
  other-*)           code="\$(cat "$TMP/state/healthz")"; code="\${code#other-}"; body='<html><body>not the dashboard</body></html>' ;;
esac
# state/healthz-port: the dashboard listens on THIS port and nowhere else. A
# stub that answers every URL cannot tell a check that asked the right port
# from one that asked 7800 and got lucky (#1175).
if [[ -f "$TMP/state/healthz-port" ]]; then
  [[ "\$url" == "http://127.0.0.1:\$(cat "$TMP/state/healthz-port")/healthz" ]] || { code=000; body=""; }
fi
writeout() { local tok='%{http_code}'; [[ -n "\$wfmt" ]] && printf '%s' "\${wfmt//"\$tok"/\$1}"; return 0; }
if [[ "\$code" == 000 ]]; then writeout 000; exit 7; fi
if [[ \$fail -eq 1 && "\$code" -ge 400 ]]; then writeout "\$code"; exit 22; fi
printf '%s' "\$body"
writeout "\$code"
exit 0
EOF

# sudo: drop its own flags and run the rest here. -n and -v answer yes, so
# the run never stops to ask for a password it could not read anyway, unless
# state/sudo-n-denied says otherwise: a host where the operator has no
# password-less sudo is the second half of the role-detection story, and it
# refuses exactly the way sudo does, on stderr and non-zero.
# Anything sudo runs is marked, so the fake docker can tell an ordinary
# `docker ps` from the same call made through sudo.
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
# Real sudo resets the environment: \`Defaults env_reset\` keeps TERM and drops
# NO_COLOR. A fake that passed it through would say the bootstrap carries it
# across the boundary when nothing is carrying it at all.
unset NO_COLOR
# Distinguishes -u <operator> (as_operator) from a plain root run: the
# kept-artifacts carry-over has to move the Advisor's directories as root.
printf '%s\n' "\$*" >> "$TMP/state/sudo-exec"
# state/tamper-before-stage lists paths in the release. Just before root
# stages the release's scripts (#764), each is rewritten in the tree with
# code that leaves a mark if anything ever runs it: the last moment anything
# with write access to the tree could swap an installer.
if [[ -f "$TMP/state/tamper-before-stage" ]]; then
  args=( "\$@" )
  for i in "\${!args[@]}"; do
    if [[ "\${args[\$i]}" == rd-stage-tree ]]; then
      # rd-stage-tree <held> <tree> [<record>]
      tree="\${args[\$((i + 2))]}"
      while IFS= read -r rel; do
        [[ -n "\$rel" ]] || continue
        printf '#!/usr/bin/env bash\necho "TREE RAN %s" >> "$TMP/state/TREE-RAN"\n' "\$rel" > "\$tree/\$rel"
      done < "$TMP/state/tamper-before-stage"
      rm -f "$TMP/state/tamper-before-stage"
      break
    fi
  done
fi
# state/sudo-no-markers stands in for a staged library older than the
# @move-needed marker: it never prints one, whatever the caller asked for (#946).
if [[ -f "$TMP/state/sudo-no-markers" ]]; then
  args=( "\$@" )
  for i in "\${!args[@]}"; do
    [[ "\${args[\$i]}" != APERIRE_MOVE_MARKERS=1 ]] || args[\$i]=APERIRE_MOVE_MARKERS=0
  done
  set -- "\${args[@]}"
fi
# Real sudo's env_reset, for the one command a row asks about (state/sudo-env-
# reset): everything the caller exported is dropped, and only what sudo itself
# keeps survives. A row that reads a variable the bootstrap never passed across
# the boundary would otherwise pass by leak (#935).
# sudo-env-reset-run (the --run rows) resets it for every staged program.
if [[ -f "$TMP/state/sudo-env-reset" && ( "\$*" == *install-model-key-sealer.sh* || "\$*" == *install-advisor-account.sh* || "\$*" == *scripts/aperire-backup.sh* || "\$*" == *scripts/aperire-restore.sh* ) ]] \
   || [[ -f "$TMP/state/sudo-env-reset-run" && "\$*" == */run/scripts/* ]]; then
  exec env -i PATH="\$PATH" TERM="\${TERM:-dumb}" HOME=/root LOGNAME=root USER=root \
    SUDO_USER="\$(id -un)" SUDO_UID="\$(id -u)" SUDO_GID="\$(id -g)" "\$@"
fi
exec "\$@"
EOF

# systemctl: unit files come from state/units, and is-enabled / is-active
# answer from their own state files. The relay banner reads both back now,
# because the installer enables and starts the unit on the split path too,
# so "installed" and "running" are separate facts again.
# is-active answers per unit when the row wrote an answer for that unit
# (state/active-<unit>), which is what the update rows need: they ask about
# every unit on the host one at a time, and "the relay is active" is not an
# answer about aperire-server. Everything else still falls back to
# state/relay-active, so the relay banner's rows read what they always did.
# Every call is recorded, restarts included: a restart nobody asked for is
# invisible to a fake that swallows it.
# stop, start and restart move the unit's own is-active answer (#787): a
# fake whose stop leaves the unit "active" cannot catch a run that stops a
# unit and then says it is still running.
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/systemctl-calls"
case "\${1:-}" in
  stop|start|restart)
    verb="\$1"; shift
    for u in "\$@"; do
      case "\$u" in -*) continue ;; esac
      if [[ "\$verb" == stop ]]; then echo inactive > "$TMP/state/active-\$u"
      else echo active > "$TMP/state/active-\$u"; fi
    done
    exit 0 ;;
  list-unit-files)
    # Unfiltered, the way trusted-path-lib.sh asks: every unit file here.
    if [[ "\${2:-}" == --type=* ]]; then
      for f in "$TMP/etc/systemd/system"/*.service; do
        [[ -e "\$f" ]] && printf '%s enabled enabled\n' "\${f##*/}"
      done
      exit 0
    fi
    grep -- "\$(printf '%s' "\${2:-aperire-}" | tr -d '*')" "$TMP/state/units" 2>/dev/null
    exit 0 ;;
  is-enabled)
    cat "$TMP/state/relay-enabled" 2>/dev/null || echo disabled
    exit 0 ;;
  is-active)
    if [[ -f "$TMP/state/active-\${2:-}" ]]; then cat "$TMP/state/active-\${2:-}"; exit 0; fi
    cat "$TMP/state/relay-active" 2>/dev/null || echo inactive
    exit 0 ;;
  show)
    # refresh_advisord_recovery's own read of what systemd actually loaded
    # (#541 P1-091 follow-up), never the file on disk: the unit body, then
    # every drop-in beside it, sorted, last assignment wins for a scalar
    # setting -- StartLimitBurst -- and every OnFailure= line accumulates
    # instead, exactly as systemd.unit(5) documents for a dependency-type
    # setting. StartLimitIntervalSec has no property of its own in the real
    # thing; it answers back as StartLimitIntervalUSec, rendered with a
    # trailing "s" (measured by hand against systemd 255.4-1ubuntu8.17,
    # 2026-09-20), which is reproduced here rather than the bare integer the
    # unit is written with.
    shift
    prop="" uarg=""
    while [[ \$# -gt 0 ]]; do
      case "\$1" in
        -p) prop="\$2"; shift 2 ;;
        --value) shift ;;
        *) uarg="\${1%.service}"; shift ;;
      esac
    done
    ufile="$TMP/etc/systemd/system/\${uarg}.service"
    [[ -f "\$ufile" ]] || exit 0
    case "\$prop" in
      StartLimitBurst)
        val=""
        for f in "\$ufile" "\$ufile.d"/*.conf; do
          [[ -f "\$f" ]] || continue
          v=\$(grep '^StartLimitBurst=' "\$f" 2>/dev/null | tail -1)
          [[ -n "\$v" ]] && val="\${v#StartLimitBurst=}"
        done
        printf '%s\n' "\$val" ;;
      StartLimitIntervalUSec)
        val=""
        for f in "\$ufile" "\$ufile.d"/*.conf; do
          [[ -f "\$f" ]] || continue
          v=\$(grep '^StartLimitIntervalSec=' "\$f" 2>/dev/null | tail -1)
          [[ -n "\$v" ]] && val="\${v#StartLimitIntervalSec=}"
        done
        [[ -n "\$val" ]] && printf '%ss\n' "\$val" || printf '10s\n' ;;
      ReadWritePaths)
        # Accumulates across the unit and its drop-ins, and an empty
        # assignment resets it (systemd.exec(5)). Rendered space-separated,
        # the way systemd 255 prints it with --value.
        val=""
        for f in "\$ufile" "\$ufile.d"/*.conf; do
          [[ -f "\$f" ]] || continue
          while IFS= read -r line; do
            case "\$line" in
              ReadWritePaths=) val="" ;;
              ReadWritePaths=*) val="\${val:+\$val }\${line#ReadWritePaths=}" ;;
            esac
          done < "\$f"
        done
        printf '%s\n' "\$val" ;;
      OnFailure)
        { grep '^OnFailure=' "\$ufile" 2>/dev/null
          for f in "\$ufile.d"/*.conf; do [[ -f "\$f" ]] && grep '^OnFailure=' "\$f" 2>/dev/null; done
        } | sed 's/^OnFailure=//' | tr '\n' ' ' | sed 's/ *\$//'
        printf '\n' ;;
      # The account a unit runs as, for trusted-path-lib.sh's service set:
      # the last assignment in the unit file, the way systemd reads it.
      User|Group|SupplementaryGroups|AmbientCapabilities|Type)
        grep "^\$prop=" "\$ufile" 2>/dev/null | tail -1 | cut -d= -f2- ;;
      *) : ;;
    esac
    exit 0 ;;
esac
exit 0
EOF

# pgrep: prints a pid like the real one, because the detection line quotes it.
cat > "$TMP/bin/pgrep" <<EOF
#!/usr/bin/env bash
name="\${!#}"
grep -qx -e "\$name" "$TMP/state/procs" 2>/dev/null || exit 1
echo 4211
EOF

# docker: state/containers is what it would report, and two state files make
# it behave the way it does on a host the operator cannot query.
#   docker-denied     refuse this account the way a socket owned by root
#                     does: nothing on stdout, a permission error on stderr,
#                     non-zero. Through sudo it answers normally.
#   docker-no-daemon  installed, with nothing to talk to. That failure is an
#                     answer, and it refuses through sudo too.
cat > "$TMP/bin/docker" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/docker-calls"
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
# state/inspect-refused makes it refuse, through sudo as well.
# Per container, so two containers can carry different images:
# state/config-image-of-<ref> beats state/config-image, state/inspect-refused-<ref>
# refuses one container only, and state/inspect-gone-<ref> is a container
# removed since ps listed it.
if [[ "\${1:-}" == "inspect" ]]; then
  shift; ref=""
  while [[ \$# -gt 0 ]]; do
    case "\$1" in --format|-f|--type) shift 2 ;; *) ref="\$1"; shift ;; esac
  done
  if [[ -f "$TMP/state/inspect-refused" || -f "$TMP/state/inspect-refused-\$ref" ]]; then
    echo "permission denied while trying to connect to the Docker daemon socket" >&2
    exit 1
  fi
  if [[ -f "$TMP/state/inspect-gone-\$ref" ]]; then
    echo "Error: No such object: \$ref" >&2
    exit 1
  fi
  if [[ -f "$TMP/state/config-image-of-\$ref" ]]; then cat "$TMP/state/config-image-of-\$ref"; else cat "$TMP/state/config-image" 2>/dev/null; fi
fi
exit 0
EOF

# install: the real one refuses `-o root` to an ordinary account, and the
# ownership is precisely what the sudo in front of it would have provided. So
# this records the call and copies the file, which is what the rows below
# read back.
cat > "$TMP/bin/install" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/install-calls"
# install -d: every operand is a directory to make. Its owner flags are the
# sudo's to provide, and this suite runs as nobody in particular.
if [[ " \$* " == *" -d "* ]]; then
  for x in "\$@"; do case "\$x" in -*|root|0[0-7][0-7][0-7]) ;; *) mkdir -p "\$x" ;; esac; done
  exit 0
fi
a=("\$@"); n=\${#a[@]}
mkdir -p "\$(dirname "\${a[n-1]}")"
cp "\${a[n-2]}" "\${a[n-1]}"
EOF

# visudo: the host's own reads /etc/sudoers, which an ordinary account cannot.
# The rule writer's two checks are recorded and pass.
cat > "$TMP/bin/visudo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/visudo-calls"
exit 0
EOF

cat > "$TMP/bin/apt-get" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/apt-calls"
EOF

# getent: the operator's home is the fake one, so the DEFAULT install
# directory ($HOME/aperire-one) is what the run exercises rather than a
# path the test handed it.
cat > "$TMP/bin/getent" <<EOF
#!/usr/bin/env bash
# The Advisor's own account is a system account with no login, as
# install-advisor-account.sh creates it; everyone else here is the operator.
case "\${2:-}" in
  aperire-advisor*) printf '%s:x:999:999::/nonexistent:/usr/sbin/nologin\n' "\$2" ;;
  *) printf '%s:x:1000:1000::%s:/bin/bash\n' "\${3:-tester}" "$TMP/op" ;;
esac
EOF

# sqlite3, recorded and then real. The update's snapshot must try VACUUM INTO
# before .backup: the shell's .backup restarts whenever the dashboard writes,
# and on a gigabyte it restarted for 43 minutes on a live node (#348). The
# fixture's database is a text file, so both verbs refuse and the copy
# falls through to cp exactly as before; what this shim adds is the ORDER
# they were tried in, which is the fact the row reads.
REAL_SQLITE3="$(command -v sqlite3 || true)"
cat > "$TMP/bin/sqlite3" <<EOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "\$*" >> "$TMP/state/sqlite3-args"
[[ -n "$REAL_SQLITE3" ]] || exit 1
exec "$REAL_SQLITE3" "\$@"
EOF

# go, recorded and fake, parameterised so every fixture location gets the
# same behaviour: what the Advisor rebuild rows (#383) need is not a real
# compiler, it is proof of whether `go build` was ASKED for, with what
# commit, and a file at -o afterwards that answers -version the way the real
# binary would (main.version stamped by -ldflags -X). A real build would work
# here too, but it would also make the "no Go toolchain" rows about whatever
# happens to be on the runner rather than about this suite's own fixture.
#
# `go version` answers too (#633), non-empty and exit 0, because
# advisor_go_bin() now probes every candidate the same way
# install-advisord.sh's find_go() does before it trusts one: a candidate
# that cannot answer `version` is skipped, the same as one that is not
# executable at all, or that answers older than 1.23.
#
# $2 is recorded to go-used on every call the shim answers, never to
# go-build-calls (builds_asked() counts that file, and neither a version
# probe nor an identity marker is a build): a row that gives two candidates
# two different identities can then tell which physical file a build
# actually ran through, which is what proves precedence between them
# (#633 done-when #1).
make_go_shim() { # $1 = path to write, $2 = identity recorded in go-used
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "$2" >> "$TMP/state/go-used"
if [[ "\${1:-}" == version ]]; then
  echo "go version go1.23.4 linux/amd64"
  exit 0
fi
printf '%s\n' "\$*" >> "$TMP/state/go-build-calls"
# Two levers for the #787 rows: a build that fails, and a build during which
# something else takes the Advisor down (so the closing text has a unit that
# was captured running and is not running any more).
[[ -e "$TMP/state/go-down-advisord" ]] && echo inactive > "$TMP/state/active-aperire-advisord.service"
# go-fail names the one command whose build fails, so a row can let the
# first binary build and fail the second.
if [[ "\${1:-}" == build && -e "$TMP/state/go-fail" && " \$* " == *" ./cmd/\$(cat "$TMP/state/go-fail") "* ]]; then
  echo "go: build failed on purpose" >&2
  exit 1
fi
if [[ "\${1:-}" == build ]]; then
  shift
  ldflags="" out=""
  while [[ \$# -gt 0 ]]; do
    case "\$1" in
      -ldflags) ldflags="\$2"; shift 2 ;;
      -o) out="\$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  commit="\$(printf '%s' "\$ldflags" | sed -n 's/.*main\.version=\([^ ]*\).*/\1/p')"
  # go-unstamped names a program whose build drops the stamp, the way a package
  # without a version symbol does (go build ignores the flag without a word).
  [[ -e "$TMP/state/go-unstamped" && "\$out" == *".\$(cat "$TMP/state/go-unstamped")."* ]] && commit=dev
  mkdir -p "\$(dirname "\$out")"
  printf '#!/bin/sh\ncase "\$1" in -version|version) echo %s ;; *) echo built-by-the-go-shim ;; esac\n' "\${commit:-dev}" > "\$out"
  chmod +x "\$out"
fi
exit 0
EOF
  chmod +x "$1"
}
make_go_shim "$TMP/bin/go" "on-path"

chmod +x "$TMP"/bin/*
export PATH="$TMP/bin:$PATH"

printf 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n' > "$TMP/ubuntu.os-release"
printf 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$TMP/debian.os-release"

# ── Running the thing under test ────────────────────────────────────
# Which door the release comes through, and what the script says it weighs.
# Reset with every row, so an archive row cannot leak into the next one.
SOURCE_URL_FOR_RUN=""
SHA_FOR_RUN=""
ADV_PINNED_GO=""

reset() {
  rm -rf "$TMP/op/aperire-one" "$TMP/state" "$TMP/etc/aperire"
  find "$TMP/op" -maxdepth 1 -name '.aperire-release.*' -exec rm -rf {} +
  # The trees a reinstall keeps. Removed between rows, not by the script: the
  # script never removes one, which is the point, and a row that found the
  # PREVIOUS row's tree would be reading somebody else's evidence.
  find "$TMP/op" -maxdepth 1 -name 'aperire-one.previous-*' -exec rm -rf {} +
  # And the database snapshots an update takes beside the checkout, for the
  # same reason: the script keeps them (that is the point), so a row that
  # found the previous row's copy would be reading somebody else's evidence.
  find "$TMP/op" -maxdepth 1 -name 'aperire-one.db-*' -exec rm -rf {} +
  rm -rf "$TMP/sbin" "$TMP/etc/systemd" "$TMP/lib/aperire" "$TMP/store" "$TMP/tmpd"
  # The Advisor's sudo rule is a fact about the host like its units: a row
  # that leaves one (the wrapper rows) would hand it to the next, and a
  # "host with no wrapper" row would then be updating a host that has one.
  rm -rf "$TMP/etc/sudoers.d"
  rm -rf "${TMP:?}/var"
  mkdir -p "$TMP/var/lib"
  # 0755 like the real /var and /var/lib: the grants program refuses a grant
  # under an ancestor group or other could write, and a runner's umask
  # decides what mkdir -p makes.
  chmod 0755 "$TMP/var" "$TMP/var/lib"
  # Every host has a /usr/local/sbin. A root copy into one that is missing is
  # refused rather than made, so the fixture's stands where a host's would.
  mkdir -p "$TMP/state" "$TMP/sbin" "$TMP/tmpd"
  : > "$TMP/state/units"
  echo up > "$TMP/state/healthz"
  SOURCE_URL_FOR_RUN=""
  SHA_FOR_RUN=""
  ADV_PINNED_GO=""
}

# The environment every run shares. The health check is wound right down:
# what is under test is whether the banner waits for it, not how patient it is.
env_for() {
  printf '%s\n' \
    "PATH=${PATH_FOR_RUN:-$PATH}" \
    "HOME=$TMP/op" \
    "APERIRE_GET_OS_RELEASE=${OS_FILE:-$TMP/ubuntu.os-release}" \
    "APERIRE_GET_ETC=$TMP/etc/aperire" \
    "APERIRE_GET_SBIN=$TMP/sbin" \
    "APERIRE_GET_UNIT_DIR=$TMP/etc/systemd/system" \
    "APERIRE_GET_SUDOERS_DIR=$TMP/etc/sudoers.d" \
    "APERIRE_GET_PROC_DIR=$TMP/proc" \
    "APERIRE_GET_WRAPPER_STATE=$TMP/var/lib/aperire" \
    "APERIRE_GET_SOURCE_URL=${SOURCE_URL_FOR_RUN:-file://$TMP/release}" \
    "APERIRE_GET_EXPECTED_SHA256=${SHA_FOR_RUN:-}" \
    "APERIRE_GET_RELEASE_STORE=$TMP/store" \
    "APERIRE_GET_RELEASE_LIB_DIR=$TMP/lib/aperire" \
    "TMPDIR=$TMP/tmpd" \
    "APERIRE_GET_HEALTH_TRIES=2" \
    "APERIRE_GET_HEALTH_SLEEP=0" \
    "APERIRE_IMAGE_RECIPE_DIR=$TMP/lib/aperire" \
    "APERIRE_RELEASE_DIGESTS=$TMP/lib/aperire/release.sha256" \
    "APERIRE_RECIPE_CALLS=$TMP/state/recipe-calls"
}

run_sut() { # runs the real file; prints its output, sets RC
  local -a e; mapfile -t e < <(env_for)
  OUT="$(env "${e[@]}" bash "$SUT" "$@" 2>&1)"; RC=$?
}

run_file() { # $1 = a script file (a cut copy, usually), rest = arguments
  local f="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  OUT="$(env "${e[@]}" bash "$f" "$@" 2>&1)"; RC=$?
}

run_piped() { # feed a script on stdin, the way curl | bash does
  local f="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  OUT="$(env "${e[@]}" bash -s -- "$@" < "$f" 2>&1)"; RC=$?
}

# With a terminal on both ends, which is the only way the questions are
# asked at all: the script checks -t 0 and -t 1 before it prompts, and a
# command substitution has neither. `script` lends it a pty and feeds the
# answers in; -e is what makes RC the script's own exit status.
run_tty_file() { # $1 = a script file, $2 = answers one per line, rest = arguments
  local f="$1" answers="$2"; shift 2
  local -a e; mapfile -t e < <(env_for)
  local cmd
  cmd="env $(printf '%q ' "${e[@]}")bash $(printf '%q ' "$f" "$@")"
  # The answers go in through a fifo this shell holds open, not a pipe that
  # ends. Fed down a pipe they arrive and then the pipe closes, `script`
  # tears the terminal down before the run gets as far as asking, and every
  # read comes back empty, which looks exactly like an operator who typed
  # nothing. `script` ends with the child rather than with its own stdin,
  # so holding it open costs no time at all.
  local fifo="$TMP/tty-in"
  rm -f "$fifo"; mkfifo "$fifo"
  exec {ttyfd}<>"$fifo"
  printf '%s' "$answers" >&"$ttyfd"
  OUT="$(script -qec "$cmd" /dev/null < "$fifo" 2>&1)"; RC=$?
  exec {ttyfd}>&-
  rm -f "$fifo"
}

run_tty() { # $1 = answers, one per line; rest = arguments
  local answers="$1"; shift
  run_tty_file "$SUT" "$answers" "$@"
}

# No skipping this one quietly. The interactive half of role detection is
# the half that keeps an operator at the keyboard from being refused, and a
# row that silently disappears is a row that stops protecting it.
command -v script >/dev/null 2>&1 \
  || { echo "this test needs 'script' (util-linux) to give the run a terminal"; exit 1; }

# A copy of the script with the one refusal turned back into the silent
# default it used to be, for the rows that have to prove they can fail.
MUTANT="$TMP/silent-default.sh"
sed 's/^       role_when_unknown$/       ROLE="dashboard"/' "$SUT" > "$MUTANT"
grep -q '^       ROLE="dashboard"$' "$MUTANT" \
  || { echo "the role_when_unknown call has moved in $SUT; the mutation matched nothing"; exit 1; }

# A copy cut where a download would cut it: everything from the fetch step
# down is gone, which is past guard 1 and well before main.
CUT="$TMP/cut.sh"
cut_line="$(grep -n '^# -- Fetch' "$SUT" | cut -d: -f1)"
[[ -n "$cut_line" ]] || { echo "the '# -- Fetch' section header has moved in $SUT"; exit 1; }
head -n "$cut_line" "$SUT" > "$CUT"
grep -q '^main "\$@"' "$CUT" && { echo "the cut copy still calls main; the cut point is wrong"; exit 1; }

echo
echo "get-aperire.sh, the one-line install bootstrap"
echo

# ── 1. the truncation guard, both ways ──────────────────────────────
#
# The negative on its own proves nothing: a script that is never run also
# installs nothing. So the same cut file and the same whole file run under
# the same fakes, and the difference between them is the whole assertion.

echo "A half-delivered copy, and a whole one:"

reset
run_file "$CUT" --role=co-located --yes
if [[ ! -f "$TMP/state/install-args" && ! -d "$TMP/op/aperire-one" ]]; then
  ok "a copy cut mid-download installs nothing and fetches nothing"
else
  bad "a copy cut mid-download installs nothing and fetches nothing" \
      "install-args=$(cat "$TMP/state/install-args" 2>/dev/null), dir exists=$([[ -d "$TMP/op/aperire-one" ]] && echo yes || echo no)"
fi

reset
run_sut --role=co-located --yes
if [[ -f "$TMP/state/install-args" ]]; then
  ok "the whole copy, same fakes, reaches install.sh (the control that makes the check above mean something)"
else
  bad "the whole copy, same fakes, reaches install.sh" "rc=$RC: $OUT"
fi

if [[ "$(tail -n 1 "$SUT")" == '# --- end of get-aperire.sh ---' ]]; then
  ok "the script still ends with the sentinel the re-fetch checks for"
else
  bad "the script still ends with the sentinel the re-fetch checks for" "last line: $(tail -n 1 "$SUT")"
fi

# ── 2. guard 1: a cut PIPE is re-fetched whole ──────────────────────
#
# The reason the re-exec sits at the top of the file. Piped in cut, with a
# whole copy available to fetch, the run completes anyway.

echo
echo "A cut pipe, with and without a copy to re-fetch:"

reset
cp "$SUT" "$TMP/state/self"
run_piped "$CUT" --role=co-located --yes
if [[ -f "$TMP/state/install-args" ]]; then
  ok "a cut pipe is re-fetched whole and the install still happens"
else
  bad "a cut pipe is re-fetched whole and the install still happens" "rc=$RC: $OUT"
fi

reset
rm -f "$TMP/state/self"
run_piped "$CUT" --role=co-located --yes
if [[ ! -f "$TMP/state/install-args" && "$OUT" == *"could not re-fetch itself"* ]]; then
  ok "a cut pipe with nothing to re-fetch from says so and installs nothing"
else
  bad "a cut pipe with nothing to re-fetch from says so and installs nothing" "rc=$RC: $OUT"
fi

reset
head -n "$cut_line" "$SUT" > "$TMP/state/self"      # the re-fetch is cut too
run_piped "$CUT" --role=co-located --yes
if [[ ! -f "$TMP/state/install-args" && "$OUT" == *"without its last line"* ]]; then
  ok "a re-fetched copy missing its last line is refused by name"
else
  bad "a re-fetched copy missing its last line is refused by name" "rc=$RC: $OUT"
fi
rm -f "$TMP/state/self"

# ── 2b. what the writer on the other end of the pipe is left with ───
#
# `curl -fsSL https://get.aperire.one | bash` re-execs from a file, and the
# exec closes the read end of the pipe while curl is still writing the tail of
# the script into it. curl dies of that write and prints
#
#     curl: (23) Failure writing output to destination
#
# as the FIRST line of a run that then works perfectly (aperire4, 2026-09-09,
# issue #269). What is asserted here is the WRITER's exit status, not the
# message: this suite's curl is fed from a file and cannot produce a real 23,
# and `cat` on the same broken pipe is killed by SIGPIPE instead. Clean exit
# against non-zero is the same fact either way.
#
# It only means anything because the writer is still writing when the re-exec
# happens, and it is still writing because the script is larger than a pipe
# buffer. The mutant row below is what keeps that honest: with the drain taken
# out of the copy that is fed in, the same rig has to fail.

# A real pipe with a real process on the far end, which `run_piped` is not:
# that one redirects stdin from a file, and a file has no writer to fail.
pipe_writer() { # $1 = the script fed in, rest = arguments. Sets WRITER_RC.
  local f="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  OUT="$( { cat "$f"; printf '%s' "$?" > "$TMP/state/writer-rc"; } \
          | env "${e[@]}" bash -s -- "$@" 2>&1 )"; RC=$?
  WRITER_RC="$(cat "$TMP/state/writer-rc" 2>/dev/null)"
}

echo
echo "The process on the other end of the pipe:"

reset
cp "$SUT" "$TMP/state/self"
pipe_writer "$SUT" --role=co-located --yes
if [[ -f "$TMP/state/install-args" && "${WRITER_RC:-none}" == "0" ]]; then
  ok "the pipe is drained before the re-exec, so what fed it exits clean (the curl (23) of #269)"
else
  bad "the pipe is drained before the re-exec, so what fed it exits clean" \
      "writer rc=${WRITER_RC:-<none>}, installed=$([[ -f "$TMP/state/install-args" ]] && echo yes || echo no): $(tail -3 <<<"$OUT")"
fi

# The control. Without the drain the same run installs exactly as well and the
# writer dies, which is the whole of the bug: an alarming first line above a
# run that worked.
NODRAIN="$TMP/no-drain.sh"
grep -v '^  \[\[ -t 0 \]\] || cat >/dev/null 2>/dev/null || true$' "$SUT" > "$NODRAIN"
if [[ "$(wc -l < "$NODRAIN")" -eq "$(( $(wc -l < "$SUT") - 1 ))" ]]; then
  reset
  cp "$SUT" "$TMP/state/self"
  pipe_writer "$NODRAIN" --role=co-located --yes
  if [[ -f "$TMP/state/install-args" && "${WRITER_RC:-0}" != "0" ]]; then
    ok "and with the drain taken out, the same rig kills the writer (so the row above is not vacuous)"
  else
    bad "with the drain taken out, the same rig kills the writer" \
        "writer rc=${WRITER_RC:-<none>}, installed=$([[ -f "$TMP/state/install-args" ]] && echo yes || echo no)"
  fi
else
  bad "the drain line is still where the mutation looks for it" \
      "the single-line removal matched nothing in $SUT"
fi
rm -f "$TMP/state/self"

# ── 2c. the terminal survives the pipe, the exec and the sudo ───────
#
# The load-bearing assumption behind joining a fleet from the one-liner. The
# install's last step asks for a pairing code, and the pair command under it
# pauses twice: once while an administrator approves the pending row, and once
# for the operator to compare the aggregator's fingerprint. That second pause
# is the entire security boundary of a fleet link.
#
# Under `curl ... | bash` stdin is the pipe, and guard 1's re-exec hands the
# run /dev/tty instead. The chain from there is run_root -> sudo -> install.sh,
# and "sudo does not close stdin" was a claim in a design document until this
# row. Driven both ways, because a run that never had a terminal also records
# "no".

# The script fed in on a real pipe, with a controlling terminal present. That
# is what an operator pasting the one-liner into their shell produces.
pipe_writer_tty() { # $1 = the script fed in, rest = arguments
  local f="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  local inner
  inner="cat $(printf '%q' "$f") | env $(printf '%q ' "${e[@]}")bash -s -- $(printf '%q ' "$@")"
  OUT="$(script -qec "bash -c $(printf '%q' "$inner")" /dev/null < /dev/null 2>&1)"; RC=$?
  OUT="${OUT//$'\r'/}"
}

echo
echo "The terminal, from the operator's keyboard to install.sh:"

reset
cp "$SUT" "$TMP/state/self"
pipe_writer_tty "$SUT" --role=co-located --yes
if [[ "$(cat "$TMP/state/install-stdin-tty" 2>/dev/null)" == "yes" ]]; then
  ok "piped in with a terminal present, install.sh is handed that terminal on stdin"
else
  bad "the terminal reaches install.sh through the pipe, the exec and the sudo" \
      "install.sh saw stdin as '$(cat "$TMP/state/install-stdin-tty" 2>/dev/null || echo '<never ran>')'"
fi

# The control. With no terminal anywhere the same rig installs exactly as well
# and records "no", so the row above is about the terminal rather than about
# the rig happening to have one.
pipe_writer_notty() { # $1 = the script fed in, rest = arguments
  local f="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  local inner
  inner="cat $(printf '%q' "$f") | env $(printf '%q ' "${e[@]}")bash -s -- $(printf '%q ' "$@")"
  # setsid, not just a redirect: a redirect says nothing about /dev/tty, and
  # /dev/tty is exactly what guard 1 opens. Run from somebody's terminal this
  # row would otherwise take the same branch as the one above it and prove
  # nothing.
  OUT="$(setsid -w bash -c "$inner" < /dev/null 2>&1)"; RC=$?
}

reset
cp "$SUT" "$TMP/state/self"
pipe_writer_notty "$SUT" --role=co-located --yes
if [[ -f "$TMP/state/install-args" \
      && "$(cat "$TMP/state/install-stdin-tty" 2>/dev/null)" == "no" ]]; then
  ok "and with no terminal anywhere it still installs, and records that there was none"
else
  bad "a run with no terminal is told apart from one that has it" \
      "installed=$([[ -f "$TMP/state/install-args" ]] && echo yes || echo no), stdin='$(cat "$TMP/state/install-stdin-tty" 2>/dev/null)'"
fi
rm -f "$TMP/state/self"

# ── 3. the OS gate ──────────────────────────────────────────────────

echo
echo "The systems it will and will not install on unattended:"

reset
OS_FILE="$TMP/debian.os-release" run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"Debian GNU/Linux 12"* ]]; then
  ok "an unverified distribution is refused, by name, before anything is fetched"
else
  bad "an unverified distribution is refused, by name, before anything is fetched" "rc=$RC: $OUT"
fi

# On a phrase only the refusal carries. The plan prints an install.sh command
# too, so a check for that would still pass with the gate ripped out.
if [[ "$OUT" == *"git clone"* && "$OUT" == *"warning on a system it does not recognise"* ]]; then
  ok "the refusal names the manual path, which is not gated on the distribution"
else
  bad "the refusal names the manual path" "$OUT"
fi

reset
run_sut --role=co-located --yes
if [[ $RC -eq 0 ]]; then
  ok "Ubuntu 24.04 is installed on without a word about the distribution"
else
  bad "Ubuntu 24.04 is installed on without a word about the distribution" "rc=$RC: $OUT"
fi

# ── 4. what this host is, and what install.sh is told ───────────────

echo
echo "Role detection, and the role install.sh receives:"

role_passed() { sed -n 's/.*--role=\([a-z-]*\).*/\1/p' "$TMP/state/install-args" 2>/dev/null | head -1; }

reset
printf 'rippled\n' > "$TMP/state/procs"
run_sut --yes
if [[ "$(role_passed)" == "co-located" ]]; then
  ok "a running node makes it co-located"
else
  bad "a running node makes it co-located" "install.sh got '$(role_passed)' (rc=$RC)"
fi

# The other half of #269, on the run that has no update in it. A first install
# is the one host that HAS to be told about authn.yaml, the first operator and
# the firewall, so the flag that silences all three must not reach it.
if ! grep -q -- '--quiet-existing' "$TMP/state/install-args"; then
  ok "and a first install is not told to be quiet: it is the run that has to say all of it"
else
  bad "a first install is not passed --quiet-existing" \
      "args=$(cat "$TMP/state/install-args" 2>/dev/null)"
fi

reset
printf 'xrpld\n' > "$TMP/state/procs"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"a node is running here"* ]]; then
  ok "a renamed node binary counts as a node, and the evidence is printed"
else
  bad "a renamed node binary counts as a node, and the evidence is printed" "'$(role_passed)': $OUT"
fi

reset
printf 'somenode xrpl-labs/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
run_sut --yes
if [[ "$(role_passed)" == "co-located" ]]; then
  ok "a node in a container counts too"
else
  bad "a node in a container counts too" "install.sh got '$(role_passed)'"
fi

reset
run_sut --yes
if [[ "$(role_passed)" == "dashboard" ]]; then
  ok "no node running here means dashboard-only"
else
  bad "no node running here means dashboard-only" "install.sh got '$(role_passed)'"
fi

# ── 4b. a docker this account cannot ask ────────────────────────────
#
# The one that installed a node box as a dashboard. On a hardened host the
# operator is deliberately not in the docker group, so `docker ps` fails
# with a permission error and prints nothing, which is indistinguishable
# from a box with no containers unless somebody looks at the exit status.
# Three answers have to stay apart here: a node found (through sudo), no
# node (docker said so), and nobody knows (docker would not say).

echo
echo "A docker this account cannot query:"

# A PATH with the named commands on it nowhere, for the host that has none
# of them. Moving the fake aside is not the same thing: this machine may
# have a real docker further down PATH, and the test would then be reading
# its containers. So every directory holding one of the names is mirrored
# without it.
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
    (IFS=:; printf '%s' "${parts[*]}") > "$root/.path"
  fi
  cat "$root/.path"
}

reset
: > "$TMP/state/docker-denied"
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container stock-node1 via sudo docker"* ]]; then
  ok "a node this account cannot see is found through sudo, and the line says which asked"
else
  bad "a node this account cannot see is found through sudo, and the line says which asked" \
      "'$(role_passed)': $OUT"
fi

# The sudo announcement claims root is used for four things and nothing
# else. Detection spends one more, before that text prints, so it says so.
if [[ "$OUT" == *"asked it through "*"sudo -n"* ]]; then
  ok "and the sudo announcement counts that query, rather than claiming nothing else was run"
else
  bad "the sudo announcement counts the docker query" "$OUT"
fi

# #896: a node container created from a digest reference (the shape the
# Advisor's own upgrade makes) shows an image ID in docker ps. The container
# name and command are neutral on purpose: a row that says xrpld would match
# without the image.
DIGEST_REF="rippleci/xrpld@sha256:$(printf 'e77ed5a9%.0s' 1 2 3 4 5 6 7 8)"
reset
printf 'aperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf '%s\n' "$DIGEST_REF" > "$TMP/state/config-image"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container aperire-node via docker"* ]]; then
  ok "a node created from a digest (docker ps shows an image ID) is found through docker inspect (#896)"
else
  bad "a digest-created node is found" "'$(role_passed)': $OUT"
fi

reset
: > "$TMP/state/docker-denied"
printf 'aperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf '%s\n' "$DIGEST_REF" > "$TMP/state/config-image"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container aperire-node via sudo docker"* ]]; then
  ok "and the image is read back through sudo when sudo is what answered ps"
else
  bad "the image is read back through the same account that answered ps" "'$(role_passed)': $OUT"
fi

reset
printf 'db-1 e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf 'postgres:16\n' > "$TMP/state/config-image"
run_sut --yes
if [[ "$(role_passed)" == "dashboard" ]]; then
  ok "an image ID that resolves to something that is not a node is still no node"
else
  bad "an unrelated image ID is not a node" "'$(role_passed)': $OUT"
fi

# #901: a container removed between ps and inspect is skipped, and the node
# row still matches. Through sudo as well, where the answer is root's.
reset
printf 'old-tmp 1234567890ab /bin/sh\naperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf '%s\n' "$DIGEST_REF" > "$TMP/state/config-image"
: > "$TMP/state/inspect-gone-old-tmp"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container aperire-node via docker"* ]]; then
  ok "a container gone by inspect time is skipped, and the node row still matches"
else
  bad "a vanished container is skipped" "'$(role_passed)': $OUT"
fi
reset
: > "$TMP/state/docker-denied"
printf 'old-tmp 1234567890ab /bin/sh\naperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf '%s\n' "$DIGEST_REF" > "$TMP/state/config-image"
: > "$TMP/state/inspect-gone-old-tmp"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container aperire-node via sudo docker"* ]]; then
  ok "and the same through sudo, where root's answer is the one that counts"
else
  bad "a vanished container is skipped through sudo" "'$(role_passed)': $OUT"
fi

# Two ID-shown containers, two images, the non-node first: each is read for
# itself, so a copied answer would name db-1 as the node.
reset
printf 'db-1 1234567890ab /bin/sh\naperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf '%s\n' "$DIGEST_REF" > "$TMP/state/config-image"
printf 'postgres:16\n' > "$TMP/state/config-image-of-db-1"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container aperire-node via docker"* ]]; then
  ok "each image ID is read from its own container"
else
  bad "two ID-shown containers keep their own images" "'$(role_passed)': $OUT"
fi

# Only the Image column is read. A word in the command that looks like an
# image ID is never inspected, so a refusal for that container stops nothing
# on a host whose node already matched by name.
reset
printf 'xrpld-node rippleci/xrpld:2.4.0 "/opt/xrpld/bin/xrpld --net"\nworker myorg/worker:1 "run 0123456789ab --x"\n' > "$TMP/state/containers"
: > "$TMP/state/inspect-refused-worker"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"running container xrpld-node via docker"* \
      && "$OUT" != *"permission denied"* ]]; then
  ok "a hex-looking word in the Command column is not taken for an image ID"
else
  bad "only the Image column is resolved" "'$(role_passed)': $OUT"
fi

# The read-back asks for a container, not an image or volume of the same name.
reset
printf 'aperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
printf '%s\n' "$DIGEST_REF" > "$TMP/state/config-image"
run_sut --yes
if grep -q '^inspect ' "$TMP/state/docker-calls" \
   && ! grep '^inspect ' "$TMP/state/docker-calls" | grep -qv -- '--type container'; then
  ok "the image read-back inspects --type container"
else
  bad "the image read-back inspects --type container" "$(grep '^inspect' "$TMP/state/docker-calls")"
fi

# The one that must not default: a box with a node on it, where docker would
# not say which image a container came from, is not a dashboard box.
reset
printf 'aperire-node e77ed5a956a3 /entrypoint\n' > "$TMP/state/containers"
: > "$TMP/state/inspect-refused"
run_sut --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"permission denied"* \
      && "$OUT" == *"I cannot tell what this host is"* ]]; then
  ok "an inspect docker refuses is not read as no node: nothing is guessed, and docker's reason is quoted"
else
  bad "a refused inspect does not default to a dashboard" "rc=$RC, '$(role_passed)': $OUT"
fi

reset
: > "$TMP/state/docker-denied"
printf 'rippled\n' > "$TMP/state/procs"
run_sut --yes
if [[ "$(role_passed)" == "co-located" && "$OUT" == *"process rippled pid 4211"* \
   && ! -s "$TMP/state/docker-calls" ]]; then
  ok "a node process needs no privileges, so docker is never asked and the pid is the evidence"
else
  bad "a node process needs no privileges, so docker is never asked" \
      "'$(role_passed)', docker calls=$(cat "$TMP/state/docker-calls" 2>/dev/null): $OUT"
fi

reset
PATH_FOR_RUN="$(path_without docker)" run_sut --yes
if [[ "$(role_passed)" == "dashboard" && "$OUT" == *"docker is not installed here"* ]]; then
  ok "no docker at all is an answer, not a silence: dashboard, and it says why"
else
  bad "no docker at all is an answer, not a silence" "'$(role_passed)': $OUT"
fi

# The same rounding, one step to the left. A host with no pgrep answers
# "no node process" to a question nothing asked, and a native node would
# be as invisible as the container was.
reset
PATH_FOR_RUN="$(path_without pgrep)" run_sut --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"no pgrep on this host"* ]]; then
  ok "with no pgrep, an empty docker is not enough to call this a dashboard"
else
  bad "with no pgrep, an empty docker is not enough to call this a dashboard" \
      "rc=$RC, '$(role_passed)': $OUT"
fi

reset
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
PATH_FOR_RUN="$(path_without pgrep)" run_sut --yes
if [[ "$(role_passed)" == "co-located" ]]; then
  ok "and a node docker can see is still found there: only the empty answer needed both halves"
else
  bad "a node docker can see is still found with no pgrep" "'$(role_passed)': $OUT"
fi

reset
PATH_FOR_RUN="$(path_without pgrep docker)" run_sut --yes
if [[ $RC -ne 0 && "$OUT" == *"no pgrep on this host"* && "$OUT" == *"docker is not installed here"* ]]; then
  ok "neither half available names both, and still refuses"
else
  bad "neither half available names both, and still refuses" "rc=$RC: $OUT"
fi

reset
: > "$TMP/state/docker-no-daemon"
run_sut --yes
if [[ "$(role_passed)" == "dashboard" && "$OUT" == *"docker has no daemon running"* ]]; then
  ok "a docker with no daemon is an answer too: nothing is running for anybody"
else
  bad "a docker with no daemon is an answer too" "'$(role_passed)': $OUT"
fi

# ── 4c. when nobody can be asked, nothing is guessed ─────────────────

echo
echo "Docker refuses and sudo cannot help, which is the one case that must not default:"

deny_everything() {
  : > "$TMP/state/docker-denied"
  : > "$TMP/state/sudo-n-denied"
  printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
}

reset
deny_everything
run_sut --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "under --yes it refuses, and installs nothing at all"
else
  bad "under --yes it refuses, and installs nothing at all" "rc=$RC, role='$(role_passed)': $OUT"
fi

if [[ "$OUT" == *"--role=co-located"* && "$OUT" == *"sudo -n docker ps"* ]]; then
  ok "and the refusal names both ways on: name the role, or run it where docker answers"
else
  bad "the refusal names both ways on" "$OUT"
fi

if [[ "$OUT" == *"neither this account nor 'sudo -n' could ask it"* \
   && "$OUT" == *"permission denied"* && "$OUT" == *"a password is required"* ]]; then
  ok "the reason is both refusals in their own words, not a generic failure"
else
  bad "the reason is both refusals in their own words" "$OUT"
fi

# Docker's own account of a daemon that is not running settles it whichever
# call came back with it: no daemon means no container, for this account and
# for root alike. Without that, a box with a stopped daemon and a sudo that
# wants a password would be refused for a question docker had answered.
reset
: > "$TMP/state/docker-no-daemon"
: > "$TMP/state/sudo-n-denied"
run_sut --yes
# The plan is where this one is read: a host whose sudo wants a password
# stops later, at the sudo it genuinely needs, and that is not what is
# under test here. What is under test is that it got as far as a role.
if [[ "$OUT" == *"Role:       dashboard"* && "$OUT" == *"docker has no daemon running"* \
   && "$OUT" != *"I cannot tell what this host is"* ]]; then
  ok "a stopped daemon is still an answer when sudo cannot be asked either"
else
  bad "a stopped daemon is still an answer when sudo cannot be asked either" "$OUT"
fi

reset
deny_everything
run_sut
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "no terminal and no --yes refuses too: there is nobody to ask either way"
else
  bad "no terminal and no --yes refuses too" "rc=$RC, role='$(role_passed)': $OUT"
fi

# --yes at a terminal is still --yes: it means answer nothing, and there is
# no answer here to take. Refusing beats asking somebody who said not to ask.
reset
deny_everything
run_tty '' --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "a terminal does not soften --yes: it refuses rather than ask what it was told not to"
else
  bad "a terminal does not soften --yes" "rc=$RC, role='$(role_passed)': $OUT"
fi

# The prove-can-fail half, and the whole point of the change. Same fixture,
# same terminal, through a copy where the refusal is the silent default it
# used to be: no question, exit 0, and a node box installed as a dashboard.
reset
deny_everything
run_tty_file "$MUTANT" '' --yes
if [[ $RC -eq 0 && "$(role_passed)" == "dashboard" && "$OUT" != *"I cannot tell what this host is"* ]]; then
  ok "put the silent default back and the node box installs as a dashboard again, which is what the refusal prevents"
else
  bad "the mutation that restores the silent default is caught" "rc=$RC, role='$(role_passed)': $OUT"
fi

# Both ways out are asserted, or the refusal is advertising a dead end.
reset
deny_everything
run_tty '' --role=co-located --yes
if [[ $RC -eq 0 && "$(role_passed)" == "co-located" && ! -s "$TMP/state/docker-calls" \
   && "$OUT" != *"I cannot tell what this host is"* ]]; then
  ok "way out 1: naming the role installs on the same host, with docker never asked"
else
  bad "way out 1: naming the role installs on the same host, with docker never asked" \
      "rc=$RC, '$(role_passed)', docker calls=$(cat "$TMP/state/docker-calls" 2>/dev/null): $OUT"
fi

reset
: > "$TMP/state/docker-denied"
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
run_sut --yes
if [[ "$(role_passed)" == "co-located" ]]; then
  ok "way out 2: on a host where sudo -n does work, the same run needs no flags"
else
  bad "way out 2: on a host where sudo -n does work, the same run needs no flags" \
      "'$(role_passed)': $OUT"
fi

# With somebody at the keyboard it asks instead of refusing.
reset
deny_everything
run_tty 'co-located
y
'
if [[ $RC -eq 0 && "$(role_passed)" == "co-located" && "$OUT" == *"I cannot tell what this host is"* ]]; then
  ok "at a terminal it says what it could not check and asks, and the answer is the role"
else
  bad "at a terminal it says what it could not check and asks" "rc=$RC, role='$(role_passed)': $OUT"
fi

reset
deny_everything
run_tty 'nonsense
nonsense
nonsense
'
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "three answers that are not roles end in the same refusal, not in a loop or a default"
else
  bad "three answers that are not roles end in the same refusal" "rc=$RC, role='$(role_passed)': $OUT"
fi

# ── 4d. the questions are asked, not just printed ───────────────────
#
# Every question here is asked as reply="$(ask ...)", and a command
# substitution hands the function a pipe for stdout. A terminal check on
# that pipe is false on a real terminal, so the prompts printed and took
# their own default without waiting for anybody. The refusal above depends
# on the opposite, so it is asserted here with its mutation beside it.

echo
echo "The questions, with somebody at the keyboard to answer them:"

TTY_MUTANT="$TMP/deaf.sh"
sed 's/^have_tty() { \[\[ -t 0 && -t 2 \]\]; }$/have_tty() { [[ -t 0 \&\& -t 1 ]]; }/' "$SUT" > "$TTY_MUTANT"
grep -q '^have_tty() { \[\[ -t 0 && -t 1 \]\]; }$' "$TTY_MUTANT" \
  || { echo "have_tty has moved in $SUT; the mutation matched nothing"; exit 1; }

reset
printf 'rippled\n' > "$TMP/state/procs"
run_tty 'n
'
if [[ $RC -eq 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"aborted, nothing was changed"* ]]; then
  ok "answering no to the plan stops the run, which means the answer was read"
else
  bad "answering no to the plan stops the run" "rc=$RC: $OUT"
fi

reset
printf 'rippled\n' > "$TMP/state/procs"
run_tty '2
y
'
if [[ -f "$TMP/state/install-args" ]] && grep -q -- '--role=dashboard' "$TMP/state/install-args"; then
  ok "a number picks its role: 2 installs as dashboard over a detected node"
else
  bad "a number picks its role" "rc=$RC args=$(cat "$TMP/state/install-args" 2>/dev/null): $OUT"
fi

reset
printf 'rippled\n' > "$TMP/state/procs"
run_tty '6
n
'
if [[ ! -f "$TMP/state/install-args" && "$OUT" == *"not one of the four roles"* ]]; then
  ok "a number off the menu is refused by name, not treated as an answer"
else
  bad "a number off the menu is refused by name" "rc=$RC: $OUT"
fi

# No node here, and the operator says there should be one: answer 5 puts a
# node in first, out of the fetched release, and the install lands
# co-located because a node is now running, in that order.
reset
: > "$TMP/state/procs"
run_tty '5
'
if [[ -f "$TMP/state/node-install-args" && "$(role_passed)" == co-located \
      && "$(tr '\n' ' ' < "$TMP/state/order")" == "node preflight install " ]]; then
  ok "answer 5 on a box with no node: the node installer runs first, then the preflight, then install.sh as co-located"
else
  bad "answer 5 installs a node first" "rc=$RC order=$(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null) role=$(role_passed): $OUT"
fi
if [[ "$OUT" == *"answer 5"* && "$OUT" != *"scripts/install-aperire-node.sh"* ]]; then
  ok "the nodeless reading points at answer 5, never at a file the fetch has not made yet"
else
  bad "the nodeless reading points at answer 5" "$OUT"
fi

# The same, unattended.
reset
: > "$TMP/state/procs"
run_sut --node --yes
if [[ -f "$TMP/state/node-install-args" && "$(role_passed)" == co-located \
      && "$(tr '\n' ' ' < "$TMP/state/order")" == "node preflight install " \
      && "$OUT" == *"a node is installed here first"* ]]; then
  ok "--node --yes: the plan says so, the node installer runs first with --yes, install.sh gets co-located"
else
  bad "--node --yes installs a node first" "rc=$RC order=$(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null): $OUT"
fi
if grep -q -- '--yes' "$TMP/state/node-install-args" 2>/dev/null; then
  ok "the node installer is told --yes when the bootstrap was"
else
  bad "the node installer is told --yes" "$(cat "$TMP/state/node-install-args" 2>/dev/null)"
fi

# --check on a box with no node says so, and does not install a node.
reset
: > "$TMP/state/procs"
run_sut --check
if [[ ! -f "$TMP/state/node-install-args" && ! -f "$TMP/state/install-args" \
      && "$(cat "$TMP/state/preflight-args")" == *"--role-guessed"* ]]; then
  ok "--check on a box with no node tells the checklist the role was guessed, and installs nothing"
else
  bad "--check on a box with no node" "preflight-args=$(cat "$TMP/state/preflight-args" 2>/dev/null): $OUT"
fi

reset
printf 'rippled\n' > "$TMP/state/procs"
run_tty_file "$TTY_MUTANT" 'n
'
if [[ -f "$TMP/state/install-args" ]]; then
  ok "check the terminal on the substitution's own pipe instead and the same no installs anyway"
else
  bad "the mutation that stops the questions being asked is caught" "rc=$RC: $OUT"
fi

# The same question on the other path: an installed host is offered its
# menu rather than an install, and that offer is an offer now.
reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/op/aperire-one"
cp "$TMP/release/aperire-one" "$TMP/op/aperire-one/aperire-one"
run_tty 'y
'
if [[ $RC -eq 0 && "$OUT" == *"menu"* ]]; then
  ok "on an installed host, saying yes to the menu opens it"
else
  bad "on an installed host, saying yes to the menu opens it" "rc=$RC: $OUT"
fi

reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/op/aperire-one"
cp "$TMP/release/aperire-one" "$TMP/op/aperire-one/aperire-one"
run_tty 'n
'
if [[ $RC -eq 0 && "$OUT" != *"menu"* && ! -f "$TMP/state/install-args" ]]; then
  ok "and saying no leaves the host exactly as it was found"
else
  bad "saying no to the menu leaves the host as it was" "rc=$RC: $OUT"
fi

echo
echo "Role detection, continued:"

reset
printf 'rippled\n' > "$TMP/state/procs"
run_sut --role dashboard --yes
if [[ "$(role_passed)" == "dashboard" && "$OUT" == *"you named it"* ]]; then
  ok "an explicit role beats detection, and says so"
else
  bad "an explicit role beats detection, and says so" "install.sh got '$(role_passed)'"
fi

reset
run_sut --role relay --yes
if [[ "$(role_passed)" == "validator" ]]; then
  ok "--role relay reaches install.sh as --role=validator, the name it and the docs use"
else
  bad "--role relay reaches install.sh as --role=validator" "install.sh got '$(role_passed)'"
fi

reset
run_sut --role=nonsense --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "a role that is not one of the four is refused before anything is fetched"
else
  bad "a role that is not one of the four is refused" "rc=$RC: $OUT"
fi

reset
run_sut --role
if [[ $RC -ne 0 && "$OUT" == *"--role needs a value"* && ! -f "$TMP/state/install-args" ]]; then
  ok "a flag left without its value is named, not a bare shift error"
else
  bad "a flag left without its value is named" "rc=$RC: $OUT"
fi

reset
run_sut --role=dashboard --port abc --yes
if [[ $RC -ne 0 && "$OUT" == *"1 to 65535"* && ! -f "$TMP/state/install-args" ]]; then
  ok "a port that is not a number is refused here, not left to fail as a URL later"
else
  bad "a port that is not a number is refused" "rc=$RC: $OUT"
fi

reset
run_sut --role=dashboard --port 7900 --yes
if grep -q -- '--port=7900' "$TMP/state/install-args"; then
  ok "a port that is a number reaches install.sh"
else
  bad "a port that is a number reaches install.sh" "$(cat "$TMP/state/install-args" 2>/dev/null)"
fi

reset
run_sut --role=co-located --yes
if grep -q -- '--yes' "$TMP/state/install-args"; then
  ok "install.sh is always given --yes (under a pipe it exits 2 without one)"
else
  bad "install.sh is always given --yes" "$(cat "$TMP/state/install-args")"
fi

if [[ "$(cat "$TMP/state/install-args")" != *"--with-advisor"* \
   && "$(cat "$TMP/state/install-args")" != *"--with-tunnel"* ]]; then
  ok "neither the Advisor nor the tunnel is installed behind the operator's back"
else
  bad "neither the Advisor nor the tunnel is installed behind the operator's back" \
      "$(cat "$TMP/state/install-args")"
fi

# ── 4e. the release as an archive ───────────────────────────────────
#
# The published release is one .tar.gz and the script that names it also
# names its sha256. Three things have to be true together, and the first is
# worth nothing without the other two:
#
#   1. a good archive installs,
#   2. a cut one does not,
#   3. and a cut one leaves NOTHING behind, because the checksum is checked
#      before anything is unpacked and the unpack happens beside the target
#      rather than inside it.
#
# The bad input is a genuinely truncated copy of the real archive, not an
# invented mismatch: a dropped connection is the failure this guards.

echo
echo "The release as an archive, fetched and checked before it is unpacked:"

reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
run_sut --role=co-located --yes
if [[ -f "$TMP/state/install-args" && -f "$TMP/op/aperire-one/install.sh" ]] \
   && grep -qF "tarball-fetch https://get.example.test/release.tar.gz" "$TMP/state/curl-calls" \
   && grep -qF "sha256 $GOOD_SHA" <<<"$OUT"; then
  ok "an archive is fetched, matched against the sha256 this script names, unpacked, and install.sh runs out of it"
else
  bad "an archive is fetched, checked and unpacked, and install.sh runs out of it" \
      "rc=$RC, install-args=$(cat "$TMP/state/install-args" 2>/dev/null), curl=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null)"
fi

# The two doors, compared. as_operator is not a boundary under these fakes,
# so ownership cannot be asserted here and is not pretended at; what can be,
# and is, is that the tree lands at the same path with the same layout, so
# nothing after the fetch can tell which door the release came through.
TAR_LAYOUT="$(cd "$TMP/op/aperire-one" && find . | sort)"
reset
run_sut --role=co-located --yes
CLONE_LAYOUT="$(cd "$TMP/op/aperire-one" && find . -not -path './.git*' | sort)"
if [[ -n "$CLONE_LAYOUT" && "$TAR_LAYOUT" == "$CLONE_LAYOUT" ]]; then
  ok "the unpacked tree lands exactly where a clone lands it, with the same layout"
else
  bad "the unpacked tree lands exactly where a clone lands it" \
      "$(diff <(printf '%s\n' "$CLONE_LAYOUT") <(printf '%s\n' "$TAR_LAYOUT") | head -8)"
fi

reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/truncated.tar.gz" > "$TMP/state/tarball"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" && ! -f "$TMP/state/install-args" ]] \
   && grep -qF -e "$GOOD_SHA" <<<"$OUT" && grep -qF 'nothing was unpacked' <<<"$OUT"; then
  ok "a cut download fails the checksum, and is refused with both sums named and nothing unpacked"
else
  bad "a cut download fails the checksum and nothing is unpacked" \
      "rc=$RC, dir exists=$([[ -e "$TMP/op/aperire-one" ]] && echo yes || echo no), $(tail -4 <<<"$OUT")"
fi

# The unpack directory is made beside $DIR, which is what makes the last step
# a rename on one filesystem instead of an 18MB copy that can itself be cut.
# Beside it means it has to be cleaned up, so that is asserted too.
LEFTOVER="$(find "$TMP/op" -maxdepth 1 -name '.aperire-release.*' -o -maxdepth 1 -name 'aperire-release.*' | head -3)"
if [[ -z "$LEFTOVER" ]]; then
  ok "and it leaves no half-unpacked directory beside the one it was going to make"
else
  bad "and it leaves no half-unpacked directory beside the one it was going to make" "found: $LEFTOVER"
fi

# The row above has to be able to fail. With the comparison taken out, the
# same cut archive gets one step further: no refusal about a checksum, and
# root's read of the digests out of it dies on a truncated gzip instead. It
# still installs nothing, because that read is a second guard, not the same
# one.
NOSUM="$TMP/no-checksum.sh"
sed 's/^    if \[\[ .* != .*EXPECTED_SHA256.* \]\]; then$/    if false; then/' "$SUT" > "$NOSUM"
grep -q '^    if false; then$' "$NOSUM" \
  || { echo "the checksum comparison has moved in $SUT; the mutation matched nothing"; exit 1; }
reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/truncated.tar.gz" > "$TMP/state/tarball"
run_file "$NOSUM" --role=co-located --yes
if [[ $RC -ne 0 ]] && ! grep -qF 'not the one this script names' <<<"$OUT" \
   && grep -qF 'could not be read out of the archive' <<<"$OUT" && [[ ! -e "$TMP/op/aperire-one" ]]; then
  ok "take the comparison out and the same cut archive reaches the unpack, which is what the checksum is there to prevent"
else
  bad "take the comparison out and the same cut archive reaches the unpack" \
      "rc=$RC, $(tail -4 <<<"$OUT")"
fi

reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" ]] \
   && ! grep -q 'tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null \
   && grep -qF 'names an archive but no checksum' <<<"$OUT"; then
  ok "an archive over https with no checksum is refused by name, before it is even fetched"
else
  bad "an archive over https with no checksum is refused before it is fetched" \
      "rc=$RC, curl=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null), $(tail -3 <<<"$OUT")"
fi

# What may go unchecked is a list of one. Written the other way round, as
# "refuse it when it is https", plain http would have sailed through.
reset
SOURCE_URL_FOR_RUN="http://get.example.test/release.tar.gz"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" ]] && grep -qF 'names an archive but no checksum' <<<"$OUT"; then
  ok "and plain http with no checksum is refused the same way, rather than only https"
else
  bad "plain http with no checksum is refused the same way" "rc=$RC, $(tail -3 <<<"$OUT")"
fi

reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
run_sut --role=co-located --yes
if [[ -f "$TMP/state/install-args" && -f "$TMP/op/aperire-one/install.sh" ]] \
   && grep -qF 'no checksum for a local file' <<<"$OUT"; then
  ok "a local archive installs without one, which is the developer's path, and it says out loud that nothing was checked"
else
  bad "a local archive installs without a checksum, and says nothing was checked" \
      "rc=$RC, $(tail -3 <<<"$OUT")"
fi

reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
run_sut --role=co-located --yes --ref v9.9.9
if [[ -f "$TMP/state/install-args" ]] && grep -qF 'labels this run only' <<<"$OUT"; then
  ok "--ref against an archive says it chooses nothing, rather than being quietly accepted"
else
  bad "--ref against an archive says it chooses nothing" "rc=$RC, $(tail -3 <<<"$OUT")"
fi

# The two doors differ here, and the difference is worth a row. A clone
# updates a checkout it finds; an archive unpacks into a new directory and
# has nothing to update against, so it stops rather than unpack over what is
# there. Reachable after an install.sh that failed before /etc/aperire
# existed, which is the retry-on-a-fresh-box path, so the refusal has to say
# what to do next.
reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
mkdir -p "$TMP/op/aperire-one"
: > "$TMP/op/aperire-one/left-behind"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && -f "$TMP/op/aperire-one/left-behind" && ! -f "$TMP/state/install-args" ]] \
   && grep -qF -- '--dir' <<<"$OUT"; then
  ok "a directory that is already there is not unpacked over: the run stops, names --dir, and leaves it untouched"
else
  bad "a directory that is already there is not unpacked over" \
      "rc=$RC, left-behind=$([[ -f "$TMP/op/aperire-one/left-behind" ]] && echo kept || echo GONE), $(tail -3 <<<"$OUT")"
fi

reset
run_sut --role=co-located --yes --sha256 "$GOOD_SHA"
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]] && grep -qF 'nothing to check' <<<"$OUT"; then
  ok "a checksum against a git remote is refused: a clone is pinned with --ref, and a flag that does nothing is not accepted"
else
  bad "a checksum against a git remote is refused" "rc=$RC, $(tail -3 <<<"$OUT")"
fi

reset
run_sut --role=co-located --yes --source "file://$TMP/release.tar.gz" --sha256 deadbeef
if [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" ]] && grep -qF '64 hex characters' <<<"$OUT"; then
  ok "a checksum that is not a sha256 is refused where the mistake is, not blamed on the download later"
else
  bad "a checksum that is not a sha256 is refused where the mistake is" "rc=$RC, $(tail -3 <<<"$OUT")"
fi

# ── 4f. the release signature ───────────────────────────────────────
#
# A published release is refused unless the signed release.json for exactly
# the archive this script names verifies against the key built into it, and
# that is decided before the archive is even fetched. Each refusal below is a
# real way to get it wrong, and each one asserts the same three things: a
# non-zero exit, no archive fetched, nothing unpacked.

echo
echo "The release signature, checked before the archive is fetched:"

signed_run() { # $1 = directory the fake endpoint serves the signed files from
  reset
  SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
  printf '%s\n' "$1" > "$TMP/state/signed-from"
  run_sut --role=co-located --yes
}
nothing_fetched() {
  [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" && ! -f "$TMP/state/install-args" ]] \
    && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null
}

signed_run "$TMP/signed"
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]] \
   && grep -qF "signed-fetch root https://get.example.test/release-$GOOD_SHA.json.sig" "$TMP/state/curl-calls" \
   && grep -qF 'signed by the release key' <<<"$OUT" \
   && grep -qF 'every file matches the signed manifest' <<<"$OUT"; then
  ok "a signed release installs: the signature for that exact archive is fetched and verified, and the unpacked tree matches its signed manifest"
else
  bad "a signed release installs" "rc=$RC, $(tail -4 <<<"$OUT")"
fi
if [[ "$(cat "$TMP/store/current" 2>/dev/null)" == "$GOOD_SHA" ]] \
   && cmp -s "$TMP/store/$GOOD_SHA/release.json" "$TMP/signed/release-$GOOD_SHA.json" \
   && cmp -s "$TMP/store/$GOOD_SHA/release.json.sig" "$TMP/signed/release-$GOOD_SHA.json.sig" \
   && cmp -s "$TMP/store/$GOOD_SHA/release.files" "$TMP/signed/release-$GOOD_SHA.files"; then
  ok "and the signed files are kept, keyed by the archive, with current naming it, for the root copies that check against them later"
else
  bad "the signed files are kept under the store" "$(find "$TMP/store" -maxdepth 2 2>&1 | head -4) $(grep -iE 'kept|keep|store' <<<"$OUT" | head -4)"
fi

# Tampered: one byte of release.json changed after it was signed.
T="$TMP/signed-tampered"; rm -rf "$T"; cp -r "$TMP/signed" "$T"
sed -i 's/"snapshot-test"/"snapshot-evil"/' "$T/release-$GOOD_SHA.json"
signed_run "$T"
if nothing_fetched && grep -qF 'not signed by the release key' <<<"$OUT"; then
  ok "a release.json changed after it was signed is refused, before the archive is fetched, and nothing is unpacked"
else
  bad "a tampered release.json is refused before anything is fetched" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# Signed by somebody else's key.
W="$TMP/signed-wrongkey"; rm -rf "$W"
sign_release "$W" "$GOOD_SHA" "$TMP/otherkey" 2026-09-01T00:00:00Z
signed_run "$W"
if nothing_fetched && grep -qF 'not signed by the release key' <<<"$OUT"; then
  ok "a release signed by any other key is refused the same way"
else
  bad "a release signed by another key is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# No signature at all.
N="$TMP/signed-nosig"; rm -rf "$N"; cp -r "$TMP/signed" "$N"
rm -f "$N/release-$GOOD_SHA.json.sig"
signed_run "$N"
if nothing_fetched && grep -qF 'An unsigned release is not installed' <<<"$OUT"; then
  ok "a release with no signature is refused, by name, and nothing is fetched"
else
  bad "an unsigned release is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# Signed, but for a different archive: the signature is good and says so,
# and it vouches for nothing this script is about to fetch.
O="$TMP/signed-otherarchive"; rm -rf "$O"; mkdir -p "$O"
OTHER_SHA="$(printf 'c%.0s' {1..64})"
sign_release "$O" "$OTHER_SHA" "$TMP/testkey" 2026-09-01T00:00:00Z
cp "$O/release-$OTHER_SHA.json" "$O/release-$GOOD_SHA.json"
cp "$O/release-$OTHER_SHA.json.sig" "$O/release-$GOOD_SHA.json.sig"
cp "$O/release-$OTHER_SHA.files" "$O/release-$GOOD_SHA.files"
signed_run "$O"
if nothing_fetched && grep -qF 'names the archive' <<<"$OUT"; then
  ok "a genuine signature over a release.json for a different archive is refused: it names the archive, and it is not this one"
else
  bad "a signed release.json naming another archive is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# Signed, and the manifest it names does not describe the archive: the tree
# inside is checked file by file after the unpack, before the move into place.
M="$TMP/signed-badmanifest"; rm -rf "$M"
mkdir -p "$TMP/tree-other"; cp -r "$TMP/tarsrc/aperire-one/." "$TMP/tree-other/"
printf 'not what shipped\n' > "$TMP/tree-other/install.sh"
sign_release "$M" "$GOOD_SHA" "$TMP/testkey" 2026-09-01T00:00:00Z "$TMP/tree-other"
signed_run "$M"
if [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" && ! -f "$TMP/state/install-args" ]] \
   && grep -qF 'the archive is not the tree its signed file list names' <<<"$OUT"; then
  ok "an archive whose tree is not the one its signed file list names is refused by root before it is unpacked, and no release digests are written from it"
else
  bad "a tree that does not match the signed manifest is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# Signed, and naming a key set that is not the one this script carries.
KS="$TMP/signed-otherset"; rm -rf "$KS"
printf 'aperire-release-key namespaces="aperire-release" %s other\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" > "$TMP/other-signers"
sign_release "$KS" "$GOOD_SHA" "$TMP/testkey" 2026-09-01T00:00:00Z "" "$TMP/other-signers"
signed_run "$KS"
if nothing_fetched && grep -qF 'is not the key set the signed release names' <<<"$OUT"; then
  ok "a signed release naming a different key set from the one this script carries is refused before anything is fetched"
else
  bad "a key set mismatch between the script and the signed release is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# Signed, with no usable publish date: it could not be told from an older one.
ND="$TMP/signed-nodate"; rm -rf "$ND"
sign_release "$ND" "$GOOD_SHA" "$TMP/testkey" "soon"
signed_run "$ND"
if nothing_fetched && grep -qF 'states no publish date' <<<"$OUT"; then
  ok "a signed release with no valid publish date is refused, so the downgrade check can never be skipped"
else
  bad "a signed release with no date is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# Symlink in the archive, whose target has the bytes the manifest names:
# sha256sum would pass it, and the unpack check refuses it (L5).
mkdir -p "$TMP/tarsrc-link/aperire-one"
cp -r "$TMP/tarsrc/aperire-one/." "$TMP/tarsrc-link/aperire-one/"
sign_release "$TMP/signed-link-pre" "x" "$TMP/testkey" 2026-09-01T00:00:00Z "$TMP/tarsrc-link/aperire-one"
mv "$TMP/tarsrc-link/aperire-one/aperire-one" "$TMP/aperire-one-real"
ln -s "$TMP/aperire-one-real" "$TMP/tarsrc-link/aperire-one/aperire-one"
tar -czf "$TMP/release-link.tar.gz" -C "$TMP/tarsrc-link" aperire-one
LINK_SHA="$(sha256sum "$TMP/release-link.tar.gz" | cut -d' ' -f1)"
mkdir -p "$TMP/signed-link"
cp "$TMP/signed-link-pre/release-x.files" "$TMP/signed-link/release-$LINK_SHA.files"
printf '{\n  "tag": "snapshot-test",\n  "commit": "abc1234",\n  "sha256": "%s",\n  "published_at": "2026-09-01T00:00:00Z",\n  "bootstrap_sha256": "%s",\n  "files_sha256": "%s",\n  "signers_sha256": "%s"\n}\n' \
  "$LINK_SHA" "$(printf 'b%.0s' {1..64})" "$(sha256sum "$TMP/signed-link/release-$LINK_SHA.files" | cut -d' ' -f1)" "$(signers_digest "$TMP/test-signers")" \
  > "$TMP/signed-link/release-$LINK_SHA.json"
ssh-keygen -q -Y sign -f "$TMP/testkey" -n aperire-release "$TMP/signed-link/release-$LINK_SHA.json" </dev/null
reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$LINK_SHA"
printf '%s\n' "$TMP/release-link.tar.gz" > "$TMP/state/tarball"
printf '%s\n' "$TMP/signed-link" > "$TMP/state/signed-from"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -e "$TMP/op/aperire-one" ]] && grep -qF 'the archive is not the tree its signed file list names' <<<"$OUT"; then
  ok "a symlink in the release, even one whose target has the signed bytes, is refused before the tree is unpacked: it is not a file the signed list can name"
else
  bad "a symlink in the unpacked tree is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# The copy in the repository carries no key, and refuses rather than
# installing unchecked.
reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
local_e=(); mapfile -t local_e < <(env_for)
OUT="$(env "${local_e[@]}" bash "$SUT_REPO" --role=co-located --yes 2>&1)"; RC=$?
if nothing_fetched && grep -qF 'carries no release key' <<<"$OUT"; then
  ok "a copy with no release key in it (the one in the repository) refuses a published release rather than installing it unchecked"
else
  bad "a copy with no release key refuses" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# The rows above have to be able to fail. Take the signature check out and
# the tampered release.json sails through to the archive.
NOSIG="$TMP/no-signature-check.sh"
# shellcheck disable=SC2016  # a literal line to find in the file, not an expression
sed 's/^  if ! why="$(release_verify "$json" "$sig" "$signers" 2>&1)"; then$/  if false; then/' "$SUT" > "$NOSIG"
grep -q '^  if false; then$' "$NOSIG" \
  || { echo "the signature check has moved in $SUT; the mutation matched nothing"; exit 1; }
reset
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
printf '%s\n' "$TMP/signed-tampered" > "$TMP/state/signed-from"
run_file "$NOSIG" --role=co-located --yes
if grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "take the signature check out and the same tampered release.json reaches the archive fetch, which is what the check is there to stop"
else
  bad "without the signature check the tampered release.json reaches the fetch" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# ── 5. the banner comes after the health check, never instead ───────

echo
echo "The closing banner, against a dashboard that answers and one that does not:"

reset
echo up > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* && "$OUT" == *"healthz answered"* ]]; then
  ok "the banner prints once /healthz has answered"
else
  bad "the banner prints once /healthz has answered" "rc=$RC: $OUT"
fi

if [[ "$OUT" == *"ssh -L 7800:127.0.0.1:7800"* ]]; then
  ok "a loopback-bound dashboard is given the tunnel command that reaches it"
else
  bad "a loopback-bound dashboard is given the tunnel command that reaches it" "$OUT"
fi

# The other half of that claim: the bind is READ, not assumed. A dashboard
# bound to a LAN address must not be told to tunnel to itself.
reset
echo up > "$TMP/state/healthz"
echo 10.0.0.9 > "$TMP/state/bindhost"
run_sut --role=dashboard --yes
if [[ "$OUT" != *"ssh -L"* && "$OUT" == *"Keep it off the internet"* ]]; then
  ok "a dashboard bound off loopback is not told to tunnel to itself"
else
  bad "a dashboard bound off loopback is not told to tunnel to itself" "rc=$RC: $OUT"
fi
rm -rf "$TMP/etc/aperire"

if [[ "$OUT" == *"aperire-one"* ]]; then
  ok "the one next command is printed"
else
  bad "the one next command is printed" "$OUT"
fi

reset
echo down > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* ]]; then
  ok "a dashboard that never answers gets no banner and a non-zero exit"
else
  bad "a dashboard that never answers gets no banner and a non-zero exit" "rc=$RC: $OUT"
fi

if [[ "$OUT" == *"journalctl -u aperire-server"* ]]; then
  ok "and it names the log to read"
else
  bad "and it names the log to read" "$OUT"
fi

# ── the port the closing check asks (#1175) ─────────────────────────
#
# The server takes its port from PORT in the unit's environment file, written
# once by the first install and never overwritten, and no role chooses it. A
# reinstall carries no --port, so the check has to read the host rather than
# default to 7800. The stub answers on one port only, so a check that asked
# the wrong one gets nothing, as it does on a real host.

echo
echo "The closing check asks the port this host is configured with:"

# A dashboard unit as install-aperire-service.sh writes it, reduced to the
# lines that carry the port: the name, and the environment file it names.
fake_dash_unit() { # $1 = unit name, $2 = the environment file the unit names
  mkdir -p "$TMP/etc/systemd/system" "$TMP/etc/aperire"
  printf '[Service]\nEnvironment=NODE_ENV=production\nEnvironmentFile=%s\n' "$2" \
    > "$TMP/etc/systemd/system/$1.service"
}

# A co-located host first installed with --port=7900, reinstalled with no
# --port. Seen live on a node that had been installed that way, 2026-10-20.
reset
fake_dash_unit aperire-server "$TMP/etc/aperire/aperire.env"
printf 'RELAY_TOKENS=x\nPORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7900 > "$TMP/state/healthz-port"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* \
   && "$OUT" == *"asking http://127.0.0.1:7900/healthz"* \
   && "$OUT" == *"http://127.0.0.1:7900/healthz answered"* ]] \
   && grep -q 'http://127.0.0.1:7900/healthz' "$TMP/state/curl-calls" \
   && ! grep -q ':7800/' "$TMP/state/curl-calls"; then
  ok "a co-located reinstall asks 7900, the port aperire.env holds, says so, and exits 0"
else
  bad "a co-located reinstall asks the configured port" "rc=$RC calls=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null) $(tail -4 <<<"$OUT")"
fi
if [[ "$OUT" == *"ssh -L 7900:127.0.0.1:7900"* \
   && "$OUT" == *"The dashboard can be accessed on   http://127.0.0.1:7900"* ]]; then
  ok "and the address and tunnel command it prints are that port"
else
  bad "the banner names the configured port" "$(grep -F -e 'accessed' -e 'ssh -L' <<<"$OUT")"
fi

# The other dashboard unit name, with the port in an environment file the
# unit names rather than aperire.env. aperire.env says 7800 here, so a reader
# that went to aperire.env first, or skipped the unit, asks the wrong port.
reset
fake_dash_unit aperire-read "$TMP/etc/aperire/aperire-read.env"
printf 'PORT=7901\n' > "$TMP/etc/aperire/aperire-read.env"
printf 'RELAY_TOKENS=x\nPORT=7800\n' > "$TMP/etc/aperire/aperire.env"
echo 7901 > "$TMP/state/healthz-port"
run_sut --role=dashboard --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* \
   && "$OUT" == *"http://127.0.0.1:7901/healthz answered"* ]] \
   && ! grep -q ':7800/' "$TMP/state/curl-calls"; then
  ok "an aperire-read host asks the port its unit's own environment file names, and exits 0"
else
  bad "an aperire-read host asks the port its unit's environment file names" "rc=$RC calls=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null) $(tail -4 <<<"$OUT")"
fi

# A port in the unit's own Environment= line wins over any file.
reset
mkdir -p "$TMP/etc/systemd/system" "$TMP/etc/aperire"
printf '[Service]\nEnvironment=PORT=7902\nEnvironmentFile=%s\n' "$TMP/etc/aperire/aperire.env" \
  > "$TMP/etc/systemd/system/aperire-server.service"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7902 > "$TMP/state/healthz-port"
run_sut --role=co-located --yes
if [[ $RC -eq 0 ]] && grep -q 'http://127.0.0.1:7902/healthz' "$TMP/state/curl-calls" \
   && ! grep -q ':7900/' "$TMP/state/curl-calls"; then
  ok "a PORT in the unit's own Environment= is asked before any file"
else
  bad "the unit's Environment=PORT is asked first" "rc=$RC calls=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null)"
fi

# --port is what this run was told. The file is what the server reads, and it
# is written once, so on a reinstall they can disagree. The server's answer is
# the one that can be reached, and the run says that --port did not change it.
reset
fake_dash_unit aperire-server "$TMP/etc/aperire/aperire.env"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7900 > "$TMP/state/healthz-port"
run_sut --role=co-located --port=7800 --yes
if [[ $RC -eq 0 && "$OUT" == *"--port 7800 was given"* && "$OUT" == *"Asking 7900"* ]] \
   && ! grep -q ':7800/' "$TMP/state/curl-calls"; then
  ok "a --port that disagrees with the host's own file is said, and the file's port is asked"
else
  bad "a --port against a different configured port" "rc=$RC calls=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null) $(grep -i 'port' <<<"$OUT" | head -4)"
fi

# A host with nothing configured yet is a first install: the default, as before.
reset
echo 7800 > "$TMP/state/healthz-port"
run_sut --role=co-located --yes
if [[ $RC -eq 0 ]] && grep -q 'http://127.0.0.1:7800/healthz' "$TMP/state/curl-calls"; then
  ok "a first install with nothing on disk still asks 7800"
else
  bad "a first install asks the default port" "rc=$RC calls=$(tr '\n' ' ' < "$TMP/state/curl-calls" 2>/dev/null)"
fi

# The half that must keep failing. Nothing answers on the configured port: the
# run exits non-zero, and the message says where it looked and which unit to
# read. The stub has the dashboard on 7800, the port the old check asked, so
# this fails only because the check went where the host is configured to be.
reset
fake_dash_unit aperire-read "$TMP/etc/aperire/aperire.env"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7800 > "$TMP/state/healthz-port"
run_sut --role=dashboard --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* \
   && "$OUT" == *"did not answer on http://127.0.0.1:7900/healthz"* \
   && "$OUT" == *"journalctl -u aperire-read "* \
   && "$OUT" == *"curl -sS -i http://127.0.0.1:7900/healthz"* ]]; then
  ok "no listener on the configured port: non-zero, and the message names the port and the unit it looked at"
else
  bad "a dashboard that is not on its configured port fails and says where it looked" "rc=$RC $(tail -12 <<<"$OUT")"
fi

# And with no listener anywhere.
reset
fake_dash_unit aperire-server "$TMP/etc/aperire/aperire.env"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo down > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" == *"did not answer on http://127.0.0.1:7900/healthz"* ]]; then
  ok "no listener at all: non-zero, naming the port it asked"
else
  bad "no listener at all fails and names the port" "rc=$RC $(tail -8 <<<"$OUT")"
fi

# The rows above have to be able to fail. Each mutant is the script with one
# line of the fix taken out, and each must turn its rows red.
mutant() { # $1 = out file, $2 = sed script, $3 = a line the script must still hold afterwards
  sed "$2" "$SUT" > "$1"
  cmp -s "$SUT" "$1" && { echo "the script has moved in $SUT; the mutation for $1 matched nothing"; exit 1; }
  grep -qF -- "$3" "$1" || { echo "the mutation for $1 took out more than its line"; exit 1; }
}
M_NOSETTLE="$TMP/no-settle.sh"
# shellcheck disable=SC2016  # literal sed text and a literal line to find, not expressions
mutant "$M_NOSETTLE" 's/^      settle_dash_port$/      :/' 'info "asking http://127.0.0.1:${PORT}/healthz'
reset
fake_dash_unit aperire-server "$TMP/etc/aperire/aperire.env"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7900 > "$TMP/state/healthz-port"
run_file "$M_NOSETTLE" --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" == *"did not answer on http://127.0.0.1:7800/healthz"* ]]; then
  ok "without the port read, the same host exits 1 asking 7800, which is the bug (#1175)"
else
  bad "the port read has to be what turns the co-located row green" "rc=$RC $(tail -6 <<<"$OUT")"
fi

M_NOUNITENV="$TMP/no-unit-env.sh"
# shellcheck disable=SC2016  # literal sed text and a literal line to find, not expressions
mutant "$M_NOUNITENV" 's|^  for f in "\$env_file" "\${ETC_APERIRE}/aperire.env"; do$|  for f in "${ETC_APERIRE}/aperire.env"; do|' 'for f in "${ETC_APERIRE}/aperire.env"; do'
reset
fake_dash_unit aperire-read "$TMP/etc/aperire/aperire-read.env"
printf 'PORT=7901\n' > "$TMP/etc/aperire/aperire-read.env"
printf 'PORT=7800\n' > "$TMP/etc/aperire/aperire.env"
echo 7901 > "$TMP/state/healthz-port"
run_file "$M_NOUNITENV" --role=dashboard --yes
if [[ $RC -ne 0 && "$OUT" == *"did not answer on http://127.0.0.1:7800/healthz"* ]]; then
  ok "without the unit's own environment file, the aperire-read row asks 7800 and fails"
else
  bad "reading the unit's environment file has to be what turns the aperire-read row green" "rc=$RC $(tail -6 <<<"$OUT")"
fi

M_NOUNITPORT="$TMP/no-unit-port.sh"
# shellcheck disable=SC2016  # literal sed text and a literal line to find, not expressions
mutant "$M_NOUNITPORT" 's|/^Environment=PORT=/|/^Environment=NOPE=/|' "/^Environment=NOPE=/"
reset
mkdir -p "$TMP/etc/systemd/system" "$TMP/etc/aperire"
printf '[Service]\nEnvironment=PORT=7902\nEnvironmentFile=%s\n' "$TMP/etc/aperire/aperire.env" \
  > "$TMP/etc/systemd/system/aperire-server.service"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7902 > "$TMP/state/healthz-port"
run_file "$M_NOUNITPORT" --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" == *"did not answer on http://127.0.0.1:7900/healthz"* ]]; then
  ok "without the unit's own Environment=PORT read first, the host asks its file's 7900 and fails"
else
  bad "reading the unit's Environment=PORT has to be what turns that row green" "rc=$RC $(tail -6 <<<"$OUT")"
fi

M_PORTWINS="$TMP/port-flag-wins.sh"
# shellcheck disable=SC2016  # literal sed text and a literal line to find, not expressions
mutant "$M_PORTWINS" '/^settle_dash_port() {/,/^}/ s/^  configured_dash_port || return 0$/  configured_dash_port || return 0\n  [[ $PORT_GIVEN -eq 1 ]] \&\& return 0/' '  [[ $PORT_GIVEN -eq 1 ]] && return 0'
reset
fake_dash_unit aperire-server "$TMP/etc/aperire/aperire.env"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7900 > "$TMP/state/healthz-port"
run_file "$M_PORTWINS" --role=co-located --port=7800 --yes
if [[ $RC -ne 0 && "$OUT" == *"did not answer on http://127.0.0.1:7800/healthz"* ]]; then
  ok "if --port outranked the host's own file, the check would ask 7800 where nothing listens and fail"
else
  bad "the file outranking --port has to be what turns that row green" "rc=$RC $(tail -6 <<<"$OUT")"
fi

M_NOUNIT="$TMP/hardcoded-unit.sh"
# shellcheck disable=SC2016  # literal sed text and a literal line to find, not expressions
mutant "$M_NOUNIT" 's/\${DASH_UNIT_FOUND:-aperire-server}/aperire-server/g' 'journalctl -u aperire-server -n 50'
reset
fake_dash_unit aperire-read "$TMP/etc/aperire/aperire.env"
printf 'PORT=7900\n' > "$TMP/etc/aperire/aperire.env"
echo 7800 > "$TMP/state/healthz-port"
run_file "$M_NOUNIT" --role=dashboard --yes
if [[ "$OUT" != *"journalctl -u aperire-read "* ]]; then
  ok "with the unit name hardcoded the failure message points at aperire-server on an aperire-read host"
else
  bad "the unit named in the failure has to be the one found" "$(tail -8 <<<"$OUT")"
fi

# ── a dashboard that answers 503: up, and its node not ready (#1177) ─
#
# /healthz answers 503, with a JSON body, until the node the dashboard reads
# has closed a ledger in the last 30 seconds, and a node installed minutes ago
# is still catching up. The check used `curl -f`, which turns that into a
# failure: "the dashboard did not answer", exit 1, on an install that was
# correct. The stub's 503 bodies are the ones the real server wrote when it was
# booted for this (see the curl stub above), and it honours -f the way curl
# does, so a check that leans on -f fails here as it does on a host.

echo
echo "The closing check on a dashboard that is up and whose node is not ready (#1177):"

reset
echo unready > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* \
   && "$OUT" == *"http://127.0.0.1:7800/healthz answered 503"* \
   && "$OUT" == *"It is not connected to the node."* \
   && "$OUT" == *"A 503 is the dashboard's own answer, not a failed install."* \
   && "$OUT" == *"curl -sS http://127.0.0.1:7800/healthz"* \
   && "$OUT" == *"The dashboard can be accessed on"* \
   && "$OUT" != *"did not answer"* && "$OUT" != *"something answered"* \
   && "$OUT" != *"  ok    http://127.0.0.1:7800/healthz answered"* ]]; then
  ok "a 503 from the dashboard's own handler is an answer: exit 0, the banner, and what the 503 means"
else
  bad "a dashboard that answers 503 passes the closing check, and says it is not ready" "rc=$RC $(tail -22 <<<"$OUT")"
fi

reset
echo unready-connected > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"answered 503"* \
   && "$OUT" == *"It is connected to the node, and no ledger has closed there in the last 30 seconds."* \
   && "$OUT" != *"It is not connected to the node."* ]]; then
  ok "and the reason is read off the body: connected to the node, no ledger yet, is said as that"
else
  bad "the 503's reason follows rippled_connected" "rc=$RC $(grep -F -e 'node' <<<"$OUT" | head -4)"
fi

# A 503 does not end the wait. A node that is already synced answers 503 for
# the first seconds after the dashboard starts, and ending on it would call a
# host that is a few seconds from ready "not ready".
reset
echo unready-then-up > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"  ok    http://127.0.0.1:7800/healthz answered"* \
   && "$OUT" != *"healthz answered 503"* \
   && "$OUT" == *"it answered 503: the dashboard is up and its node is not ready."* \
   && "$(grep -c '/healthz' "$TMP/state/curl-calls")" -eq 2 ]]; then
  ok "a 503 that turns into a 200 inside the window ends on the 200, and the banner is the plain one"
else
  bad "the wait outlasts a 503" "rc=$RC asks=$(grep -c '/healthz' "$TMP/state/curl-calls" 2>/dev/null) $(grep -F -e '503' -e 'answered' <<<"$OUT" | head -4)"
fi

# What must keep failing. Something else on the port is not the dashboard, and
# passing it off as one would say "installed, and answering" about a dashboard
# that is down or failing.
reset
echo other-404 > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* \
   && "$OUT" == *"something answered on http://127.0.0.1:7800/healthz with HTTP 404, and it was not the dashboard's own"* \
   && "$OUT" != *"did not answer"* && "$OUT" == *"curl -sS -i http://127.0.0.1:7800/healthz"* ]]; then
  ok "a 404 from whatever holds the port fails the check, and says something answered and what"
else
  bad "a 404 is not the dashboard answering" "rc=$RC $(tail -12 <<<"$OUT")"
fi

reset
echo other-503 > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* \
   && "$OUT" == *"something answered on http://127.0.0.1:7800/healthz with HTTP 503, and it was not the dashboard's own"* ]]; then
  ok "a 503 whose body is not the dashboard's (a proxy's error page) fails the check as well"
else
  bad "a 503 that is not the handler's is not the dashboard answering" "rc=$RC $(tail -12 <<<"$OUT")"
fi

reset
echo down > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" == *"the dashboard did not answer on http://127.0.0.1:7800/healthz"* \
   && "$OUT" != *"something answered"* ]]; then
  ok "and nothing listening is still 'did not answer', not 'something answered'"
else
  bad "no listener is told apart from a wrong listener" "rc=$RC $(tail -12 <<<"$OUT")"
fi

# What the LAST ask heard is what counts. A dashboard that said 503 and then
# stopped answering (a crash loop that hit its start limit) is not up, and an
# earlier 503 or 404 must not be remembered into a later silence.
reset
echo unready-then-down > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* \
   && "$OUT" == *"the dashboard did not answer on http://127.0.0.1:7800/healthz"* ]]; then
  ok "a dashboard that said 503 and then went quiet fails the check: the last ask decides"
else
  bad "a 503 followed by silence is not an answer" "rc=$RC $(tail -12 <<<"$OUT")"
fi
reset
echo unready-then-404 > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* \
   && "$OUT" == *"something answered on http://127.0.0.1:7800/healthz with HTTP 404"* ]]; then
  ok "a 503 followed by a 404 fails the check, and names the 404"
else
  bad "a 503 followed by a 404 is not an answer" "rc=$RC $(tail -12 <<<"$OUT")"
fi
reset
echo 404-then-down > "$TMP/state/healthz"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" == *"the dashboard did not answer on http://127.0.0.1:7800/healthz"* \
   && "$OUT" != *"something answered"* ]]; then
  ok "and a 404 followed by silence reads as silence, not as a 404 held over"
else
  bad "an earlier stray status is not held over a later silence" "rc=$RC $(tail -12 <<<"$OUT")"
fi

# A 503 has to be the handler's: both halves of its body, {"ok":false,"role":...}.
for st in other-503-nojson other-503-norole; do
  reset
  echo "$st" > "$TMP/state/healthz"
  run_sut --role=co-located --yes
  if [[ $RC -ne 0 && "$OUT" == *"something answered on http://127.0.0.1:7800/healthz with HTTP 503"* ]]; then
    ok "a 503 whose body is JSON but not the handler's ($st) fails the check"
  else
    bad "a 503 that is only half the handler's body is not the dashboard answering ($st)" "rc=$RC $(tail -10 <<<"$OUT")"
  fi
done

# The rows above have to be able to fail: each mutant is the script with one
# line of the fix taken out.
# shellcheck disable=SC2016  # literal sed text and literal lines to find, not expressions
{
mutant "$TMP/hz-sticky.sh" '/^healthz_heard() {/,/^}/ s#^  HEALTHZ_CODE="" HEALTHZ_BODY="" HEALTHZ_STRAY=""$#  :#' '  :'
mutant "$TMP/hz-role.sh" "s# \&\& grep -q '\"role\"' <<<\"\$body\"##" '"ok"[[:space:]]*:[[:space:]]*false'"'"' <<<"$body"; }; then'
mutant "$TMP/hz-okfalse.sh" "s#grep -Eq '\"ok\"\[\[:space:\]\]\*:\[\[:space:\]\]\*false' <<<\"\$body\" \&\& ##" "{ grep -q '\"role\"' <<<\"\$body\"; }"
mutant "$TMP/hz-000.sh" 's# \&\& "\$code" != 000 \]\]# ]]#' '^[0-9]{3}$ ]] || return 1'
mutant "$TMP/hz-f.sh" 's#curl -sS --max-time 3 -w#curl -fsS --max-time 3 -w#' 'curl -fsS --max-time 3 -w'
mutant "$TMP/hz-any.sh" 's#^    \*)   HEALTHZ_STRAY="\$code"; return 1 ;;$#    *)   ;;#' '    *)   ;;'
mutant "$TMP/hz-shape.sh" 's#503) if ! {#503) if false \&\& ! {#' '503) if false && ! {'
mutant "$TMP/hz-early.sh" 's#^      \[\[ "\$HEALTHZ_CODE" == 200 \]\] && return 0$#      return 0#' '      return 0'
mutant "$TMP/hz-no503.sh" 's#^    503) if ! {#    5xx) if ! {#' '5xx) if ! {'
mutant "$TMP/hz-paint.sh" 's#^  if \[\[ "\$HEALTHZ_CODE" == 200 \]\]; then$#  if true; then#' '  if true; then'
}
reset
echo unready > "$TMP/state/healthz"
run_file "$TMP/hz-f.sh" --role=co-located --yes
if [[ $RC -ne 0 && "$OUT" != *"installed, and answering"* ]]; then
  ok "control: with curl -f put back, the same 503 exits 1 on a correct install, which is the bug (#1177)"
else
  bad "control: -f is what the 503 row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo other-404 > "$TMP/state/healthz"
run_file "$TMP/hz-any.sh" --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* ]]; then
  ok "control: if any status counted, a 404 from another program would read as the dashboard installed and answering"
else
  bad "control: the status rule is what the 404 row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo other-503 > "$TMP/state/healthz"
run_file "$TMP/hz-shape.sh" --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* ]]; then
  ok "control: if every 503 counted, a proxy's error page would read as a dashboard that is up"
else
  bad "control: the body check is what the proxy-503 row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo unready-then-up > "$TMP/state/healthz"
run_file "$TMP/hz-early.sh" --role=co-located --yes
if [[ "$OUT" == *"answered 503"* ]]; then
  ok "control: if the first 503 ended the wait, a host seconds from ready would be called not ready"
else
  bad "control: the full window is what the 503-then-200 row turns on" "rc=$RC $(grep -F -e '503' -e 'answered' <<<"$OUT" | head -4)"
fi
reset
echo unready > "$TMP/state/healthz"
run_file "$TMP/hz-no503.sh" --role=co-located --yes
if [[ $RC -ne 0 ]]; then
  ok "control: without the 503 case the handler's own answer is a stray status and the install exits 1"
else
  bad "control: the 503 case is what the 503 row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo unready > "$TMP/state/healthz"
run_file "$TMP/hz-paint.sh" --role=co-located --yes
if [[ "$OUT" == *"  ok    http://127.0.0.1:7800/healthz answered"* && "$OUT" != *"A 503 is the dashboard's own answer"* ]]; then
  ok "control: a banner that always painted success would say a 503 'answered' with an ok and explain nothing"
else
  bad "control: the report is what the wording rows turn on" "rc=$RC $(tail -8 <<<"$OUT")"
fi
reset
echo unready-then-down > "$TMP/state/healthz"
run_file "$TMP/hz-sticky.sh" --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* ]]; then
  ok "control: if an earlier 503 were remembered, a dashboard that then went quiet would read as installed and answering"
else
  bad "control: clearing what the last ask heard is what the 503-then-silence row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo unready-then-404 > "$TMP/state/healthz"
run_file "$TMP/hz-sticky.sh" --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* ]]; then
  ok "control: and an earlier 503 would pass a later 404 as well"
else
  bad "control: clearing what the last ask heard is what the 503-then-404 row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo 404-then-down > "$TMP/state/healthz"
run_file "$TMP/hz-sticky.sh" --role=co-located --yes
if [[ "$OUT" == *"something answered on http://127.0.0.1:7800/healthz with HTTP 404"* ]]; then
  ok "control: and an earlier 404 would be named for a silence that came after it"
else
  bad "control: clearing what the last ask heard is what the 404-then-silence row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo other-503-nojson > "$TMP/state/healthz"
run_file "$TMP/hz-role.sh" --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* ]]; then
  ok "control: without the role half of the body check, another service's {\"ok\":false} 503 would read as a dashboard that is up"
else
  bad "control: the role half is what the nojson row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo other-503-norole > "$TMP/state/healthz"
run_file "$TMP/hz-okfalse.sh" --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"installed, and answering"* ]]; then
  ok "control: without the ok:false half of the body check, a 503 with a role and no verdict would pass"
else
  bad "control: the ok:false half is what the norole row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi
reset
echo down > "$TMP/state/healthz"
run_file "$TMP/hz-000.sh" --role=co-located --yes
if [[ "$OUT" == *"something answered on http://127.0.0.1:7800/healthz with HTTP 000"* ]]; then
  ok "control: without the 000 test, a refused connection is reported as something answering with HTTP 000"
else
  bad "control: the 000 test is what the nothing-listening row turns on" "rc=$RC $(tail -6 <<<"$OUT")"
fi

reset
echo down > "$TMP/state/healthz"
echo enabled > "$TMP/state/relay-enabled"
echo active  > "$TMP/state/relay-active"
run_sut --role relay --yes
# The relay installer enables and starts the unit on the split path now (#138),
# so the banner says "enabled and running, and standing by" and every word of
# that is read back from systemctl before it prints.
if [[ $RC -eq 0 && "$OUT" == *"the relay is installed on this host"* \
   && "$OUT" == *"enabled and running, and standing by"* ]]; then
  ok "the relay-only host is verified on its unit, not on a dashboard it does not run"
else
  bad "the relay-only host is verified on its unit, not on a dashboard it does not run" "rc=$RC: $OUT"
fi

# The prove-can-fail half. A unit that did not come up must not be reported as
# standing by: standing by is a running service that has nowhere to push, and
# a dead one reading as that is the failure this whole change is about.
reset
echo down > "$TMP/state/healthz"
echo enabled > "$TMP/state/relay-enabled"
echo failed  > "$TMP/state/relay-active"
run_sut --role relay --yes
if [[ $RC -ne 0 && "$OUT" != *"standing by"* && "$OUT" == *"did not come up"* ]]; then
  ok "a relay unit that did not come up gets the journal to read, not a banner"
else
  bad "a relay unit that did not come up gets the journal to read, not a banner" "rc=$RC: $OUT"
fi

reset
echo down > "$TMP/state/healthz"
rm -f "$TMP/release/install.sh"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s"\n' "$TMP/state/install-args" > "$TMP/release/install.sh"
chmod +x "$TMP/release/install.sh"
run_sut --role relay --yes
if [[ $RC -ne 0 && "$OUT" != *"the relay is installed on this host"* ]]; then
  ok "a relay install that leaves no unit behind fails instead of congratulating anybody"
else
  bad "a relay install that leaves no unit behind fails" "rc=$RC: $OUT"
fi

# ── 6. a second run on a host that already has it ───────────────────

echo
echo "Running it again on an installed host:"

reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/op/aperire-one"
cp "$TMP/release/aperire-one" "$TMP/op/aperire-one/aperire-one"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"already installed"* ]]; then
  ok "an installed host is not installed over"
else
  bad "an installed host is not installed over" "rc=$RC: $OUT"
fi

if [[ "$OUT" == *"aperire-one"* && "$OUT" == *"aperire-server.service"* ]]; then
  ok "it says what it found and points at the menu instead"
else
  bad "it says what it found and points at the menu instead" "$OUT"
fi

# The rule this row used to assert, inverted, because the rule changed and the
# old one was a bug. /etc/aperire with no unit beside it is what
# `uninstall.sh --keep` leaves, and the uninstaller says of it "A later install
# picks them up where they are". Counting it as an installed host made that
# sentence false: the reinstall it names printed "already installed" and did
# nothing (aperire4, 2026-09-07).
reset
mkdir -p "$TMP/etc/aperire"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]]; then
  ok "config left by an earlier install is reused, not installed over: a unit is what counts"
else
  bad "config left by an earlier install is reused and the install proceeds" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"what an earlier install left on this host"* && "$OUT" == *"config:   $TMP/etc/aperire"* ]]; then
  ok "and it is named on screen before anything is fetched"
else
  bad "the kept config is named on screen" "$OUT"
fi
if [[ "$OUT" != *"carrying your files"* ]]; then
  ok "with no checkout beside it there is nothing to carry, and nothing is claimed"
else
  bad "no carry-over is claimed when there is no checkout" "$OUT"
fi

# ── 7. colour, and every run that must not carry it ─────────────────
#
# The install path is dressed so an operator watching it can see at a glance
# what was done, what warned and what failed. Two promises come with that,
# and both are easy to break by accident.
#
# A run whose output is not a terminal has to be byte-plain. That is what a
# captured log has to stay, and it is also what every other row in this file
# greps: colour that leaked into a pipe would go on passing the substring
# checks right up until the day one of them straddled an escape.
#
# And NO_COLOR has to be honoured, because an operator who set it meant it.
#
# Every row here byte-greps for ESC itself. A substring check would pass on a
# plain run, which is the answer half of these rows are trying to disprove.

echo
echo "Colour, and the runs that must not carry it:"

has_escapes() { [[ "$OUT" == *$'\033'* ]]; }
seen()        { printf '%s' "$OUT" | cat -v | grep -n '\^\[' | head -3; }

# The same file fed through a pty, so fd 1 is a terminal. `script` gives the
# run one; TERM is named here rather than inherited, so the row means the same
# thing on a workstation and on a CI runner, where it is usually unset.
run_tty_piped() { # $1 = a script file fed on stdin, rest = arguments
  local f="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  local cmd
  cmd="env $(printf '%q ' "${e[@]}")bash -s -- $(printf '%q ' "$@")< $(printf '%q' "$f")"
  OUT="$(script -qec "$cmd" /dev/null 2>&1)"; RC=$?
}

TERM_BEFORE="${TERM:-}"
export TERM=xterm-256color

reset
run_sut --role=co-located --yes
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]] && ! has_escapes; then
  ok "a captured run carries no ANSI escape at all, whatever TERM says"
else
  bad "a captured run carries no ANSI escape at all" "rc=$RC: $(seen)"
fi

# The row above proves nothing on its own: a run that printed no colour
# because it printed nothing would pass it too. So the same run again, from a
# copy with the one line that asks whether this is a terminal taken out.
COLOUR_MUTANT="$TMP/always-colour.sh"
# shellcheck disable=SC2016  # $fd is the text being matched, not a value to expand
sed 's% \[\[ -t "$fd" \]\] || on=0$%  true  # the terminal gate, removed%' "$SUT" > "$COLOUR_MUTANT"
grep -q 'the terminal gate, removed' "$COLOUR_MUTANT" \
  || { echo "the terminal gate has moved in $SUT; the mutation matched nothing"; exit 1; }

reset
run_file "$COLOUR_MUTANT" --role=co-located --yes
if has_escapes; then
  ok "and the same run with that gate removed does carry them (the control)"
else
  bad "and the same run with that gate removed does carry them" "rc=$RC: $OUT"
fi

# With a terminal on the other end, the states have to be told apart.
reset
run_tty '' --role=co-located --yes
if [[ $RC -eq 0 ]] && has_escapes \
   && [[ "$OUT" == *$'\033[1m'* && "$OUT" == *$'\033[32m'* ]]; then
  ok "on a terminal the phase headers come out bold and what was read back comes out green"
else
  bad "on a terminal the headers are bold and what was read back is green" "rc=$RC: $(seen)"
fi

# A refusal goes to stderr, and stderr is dressed from its own reading of the
# stream, so this is the row that would catch S_ used where E_ belongs.
reset
run_tty '' --role=not-a-role
if [[ $RC -ne 0 && "$OUT" == *$'\033[31m'*"invalid role"* ]]; then
  ok "a refusal on stderr comes out red"
else
  bad "a refusal on stderr comes out red" "rc=$RC: $(seen)"
fi

reset
export NO_COLOR=1
run_tty '' --role=co-located --yes
NO_COLOR_RC=$RC
unset NO_COLOR
if [[ $NO_COLOR_RC -eq 0 ]] && ! has_escapes; then
  ok "NO_COLOR is honoured with a terminal on both ends, which is where it matters"
else
  bad "NO_COLOR is honoured with a terminal on both ends" "rc=$NO_COLOR_RC: $(seen)"
fi

# The install runs behind sudo, and sudo drops NO_COLOR. So an operator who
# set it and watched a plain bootstrap hand over to a coloured installer would
# have been told the setting was honoured by the half that honoured it.
reset
export NO_COLOR=1
# Its own install.sh, which records what arrived rather than what it was told.
# Section 5 above swapped the shared fixture out for a stripped one and left it
# that way, so a row here that leaned on the rich one would read a stale answer.
# shellcheck disable=SC2016  # ${NO_COLOR} and $* are the generated script's, not this one's
printf '#!/usr/bin/env bash\nprintf "NO_COLOR=[%%s]" "${NO_COLOR:-unset}" > "%s"\nprintf "%%s\\n" "$*" >> "%s"\n' \
  "$TMP/state/install-env" "$TMP/state/install-args" > "$TMP/release/install.sh"
chmod +x "$TMP/release/install.sh"
run_sut --role=co-located --yes
NO_COLOR_SUDO="$(cat "$TMP/state/install-env" 2>/dev/null || echo '<install.sh never ran>')"
unset NO_COLOR
if [[ "$NO_COLOR_SUDO" == "NO_COLOR=[1]" ]]; then
  ok "NO_COLOR reaches install.sh through sudo, which resets the environment"
else
  bad "NO_COLOR reaches install.sh through sudo" "install.sh saw $NO_COLOR_SUDO"
fi

reset
export TERM=dumb
run_tty '' --role=co-located --yes
DUMB_RC=$RC
export TERM=xterm-256color
if [[ $DUMB_RC -eq 0 ]] && ! has_escapes; then
  ok "TERM=dumb is a terminal that gets no escapes"
else
  bad "TERM=dumb is a terminal that gets no escapes" "rc=$DUMB_RC: $(seen)"
fi

# curl | bash is the run this whole script exists for, and it is not the same
# shape as either of the above: stdin is the pipe, stdout is still the
# operator's window. The re-exec hands stdin back a terminal on the way
# through, and the colour has to survive that.
reset
cp "$SUT" "$TMP/state/self"
run_tty_piped "$SUT" --role=co-located --yes
if [[ -f "$TMP/state/install-args" ]] && has_escapes; then
  ok "a piped run whose output is still a terminal keeps its colour (the curl | bash shape)"
else
  bad "a piped run whose output is still a terminal keeps its colour" "rc=$RC: $(seen)"
fi
rm -f "$TMP/state/self"

if [[ -n "$TERM_BEFORE" ]]; then export TERM="$TERM_BEFORE"; else unset TERM; fi

# ── the release stamp, which two other scripts write into ───────────
#
# scripts/build-release-snapshot.sh rewrites the first four lines in here so
# that a published copy fetches the release that was served with it. The
# publisher writes the last three, which say which release that is. Both
# match by name and refuse when a line has moved, so the shape is a contract
# between three files and this is the end of it that gets edited.
#
# The first four are asserted together on purpose. A copy served from one
# place that fetches its release from another, that re-fetches itself from a
# third, or that names a checksum belonging to none of them, is exactly the
# state nobody notices by reading the script, which is the one defence a
# `curl | bash` installer has.
STAMP_BLOCK="$(sed -n '/^# >>> release stamp >>>$/,/^# <<< release stamp <<<$/p' "$SUT")"
STAMP_LINES=0
for v in DEFAULT_SOURCE_URL DEFAULT_SOURCE_REF DEFAULT_SELF_URL DEFAULT_EXPECTED_SHA256; do
  [[ "$(grep -c "^${v}='" <<<"$STAMP_BLOCK")" == "1" ]] && STAMP_LINES=$((STAMP_LINES + 1))
done
if [[ -n "$STAMP_BLOCK" && $STAMP_LINES -eq 4 ]]; then
  ok "the release-stamp block holds exactly the four lines the snapshot build rewrites"
else
  bad "the release-stamp block holds exactly the four lines the snapshot build rewrites" \
      "found $STAMP_LINES of 4 inside a block of $(wc -l <<<"$STAMP_BLOCK") lines"
fi

# And the three the publisher writes: the release this copy was published as.
# Empty in the tree and in the archive, filled in the copy served beside it,
# which is why the rows further down stamp their own copy rather than trust
# these to hold anything.
PUBLISHER_LINES=0
for v in DEFAULT_RELEASE_TAG DEFAULT_RELEASE_COMMIT DEFAULT_PUBLISHED_AT; do
  [[ "$(grep -c "^${v}='" <<<"$STAMP_BLOCK")" == "1" ]] && PUBLISHER_LINES=$((PUBLISHER_LINES + 1))
done
if [[ $PUBLISHER_LINES -eq 3 ]]; then
  ok "and the three the publisher fills in: the tag, the commit and the date this copy was published with"
else
  bad "the block holds the three lines the publisher fills in" \
      "found $PUBLISHER_LINES of 3 inside a block of $(wc -l <<<"$STAMP_BLOCK") lines"
fi

# The self-fetch a piped run re-execs from must come from that block and
# nowhere else. Asserted by running the thing: a piped run with no
# APERIRE_GET_SELF_URL set has to ask for the stamped URL.
reset
: > "$TMP/state/curl-calls"
run_piped "$SUT" --role=co-located --yes
STAMPED_SELF="$(sed -n "s/^DEFAULT_SELF_URL='\(.*\)'$/\1/p" "$SUT")"
if grep -qF "self-fetch $STAMPED_SELF" "$TMP/state/curl-calls" 2>/dev/null; then
  ok "a piped run re-fetches itself from the stamped self URL, not from anywhere else"
else
  bad "a piped run re-fetches itself from the stamped self URL" \
      "wanted 'self-fetch $STAMPED_SELF', saw: $(head -3 "$TMP/state/curl-calls" 2>/dev/null)"
fi

# ── reinstalling over what an uninstall kept ────────────────────────
#
# The third phase of the lifecycle, and the one that was a dead end.
# `uninstall.sh --keep` leaves /etc/aperire and the checkout with the database
# inside it, removes every unit, and prints "A later install picks them up
# where they are" above the one-line reinstall. That reinstall then said the
# host was already installed and did nothing (aperire4, 2026-09-07): keeping
# your data made putting it back impossible.
#
# What has to hold now: a unit is what "installed" means; a kept checkout is
# carried into the new release file by file, each one said on screen; the old
# tree is renamed and never deleted; and /etc/aperire is not touched at all,
# which is what keeps the relay token the same one the dashboard already
# trusts.

echo
echo "Reinstalling over what an uninstall kept:"

# The fixture: exactly what `--keep` leaves. An install.sh (every release tree
# has one, and it is what tells a kept checkout from somebody else's
# directory), a database, two config files the operator tuned, and the four
# Advisor directories no release carries.
KEPT="$TMP/op/aperire-one"
make_kept_checkout() {
  rm -rf "$KEPT"
  mkdir -p "$KEPT/dashboard/config" "$KEPT/data/logs" \
           "$KEPT/advisor/state" "$KEPT/advisor/evidence" \
           "$KEPT/advisor/knowledge-fleet" "$KEPT/advisor/knowledge-bundles" \
           "$KEPT/dashboard"
  printf 'an-earlier-release\n'   > "$KEPT/install.sh"
  printf 'THE-OPERATORS-DATABASE\n' > "$KEPT/data/aperire.db"
  printf 'yesterday\n'            > "$KEPT/data/logs/dashboard.log"
  printf 'swap_warn: 60   # AN OLDER RELEASE\n' > "$KEPT/dashboard/config/rules.yaml"
  printf 'swap_warn: 92   # tuned by the operator\n' > "$KEPT/dashboard/config/rules.local.yaml"
  printf 'rp_id: dash.example\n'  > "$KEPT/dashboard/config/authn.yaml"
  # The link credential pairing wrote, 0600, the only copy there is.
  printf '{"label":"node1","credential":"THE-LINK-CREDENTIAL"}\n' > "$KEPT/dashboard/config/fleet-link.json"
  chmod 0600 "$KEPT/dashboard/config/fleet-link.json"
  # The aggregator's half (#805): the hash of every paired node's link
  # credential, 0600. Two entries and a trailing byte pattern that a rewrite
  # or a re-serialise would change. A reference copy and the owner are taken
  # now, so the rows can say "byte for byte, same owner" about this file.
  printf '{"nodes":{"node1":{"credential_sha256":"%s","read_port":7800,"advisor_port":7801},"node2":{"credential_sha256":"%s","read_port":7800,"advisor_port":7801}}}  \n' \
    "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" > "$KEPT/dashboard/config/fleet-links.json"
  chmod 0600 "$KEPT/dashboard/config/fleet-links.json"
  cp -p "$KEPT/dashboard/config/fleet-links.json" "$TMP/fleet-links.reference"
  LINKS_OWNER_BEFORE="$(stat -c '%u:%g' "$KEPT/dashboard/config/fleet-links.json")"
  printf 'THE-READ-TOKEN\n'       > "$KEPT/advisor/state/read.token"
  # The reveal window (#641), with a deliberately OLD timestamp. #645's second
  # gate treats this file's age as proof a human ran the installer on this box
  # recently, so an update that recreated it, rather than moving it, would
  # hand every update a fresh 900-second window nobody opened. Dated here so
  # the rows below can tell "moved" from "recreated" (#651).
  : > "$KEPT/advisor/state/reveal.window"
  chmod 0640 "$KEPT/advisor/state/reveal.window"
  touch -d '2020-03-04 05:06:07' "$KEPT/advisor/state/reveal.window"
  printf 'a-run\n'                > "$KEPT/advisor/evidence/run.json"
  printf 'node1 knowledge\n'      > "$KEPT/advisor/knowledge-fleet/node1.md"
  printf 'a-bundle\n'             > "$KEPT/advisor/knowledge-bundles/b.tar"
  printf '{"seq":44,"reserved_at":"2026-09-22T10:56:24Z","reserved_by":"koi"}\n' > "$KEPT/advisor/knowledge-bundles/seq.json"
  # The Advisor's binary, which its unit names by install path. An update
  # that left it behind left the unit exec'ing nothing (#350).
  mkdir -p "$KEPT/advisor/bin"
  printf '#!/bin/sh\necho THE-ADVISOR-BINARY\n' > "$KEPT/advisor/bin/aperire-advisord"
  chmod 0755 "$KEPT/advisor/bin/aperire-advisord"
  # Source from the earlier release that the new one has to replace.
  printf 'the OLD dashboard\n'    > "$KEPT/dashboard/server.ts"
}

previous_tree() { find "$TMP/op" -maxdepth 1 -name 'aperire-one.previous-*' | head -1; }

# The fleet-links.json rows (#805): content equal to the reference taken when
# the fixture was made, mode 600, owner unchanged, and named in the carry list
# printed on screen. No row passes on a file the release happened to ship.
links_carried() {
  local f="$KEPT/dashboard/config/fleet-links.json"
  [[ -f "$f" ]] && cmp -s "$f" "$TMP/fleet-links.reference" \
    && [[ "$(stat -c %a "$f")" == "600" ]] \
    && [[ "$(stat -c '%u:%g' "$f")" == "$LINKS_OWNER_BEFORE" ]] \
    && [[ "$OUT" == *"dashboard/config/fleet-links.json"* ]]
}
links_seen() {
  local f="$KEPT/dashboard/config/fleet-links.json"
  if [[ -f "$f" ]]; then
    printf 'mode=%s owner=%s (was %s) same=%s' "$(stat -c %a "$f")" "$(stat -c '%u:%g' "$f")" \
      "$LINKS_OWNER_BEFORE" "$(cmp -s "$f" "$TMP/fleet-links.reference" && echo yes || echo NO)"
  else
    printf 'MISSING'
  fi
}

# Both doors, because they are two different code paths: a .tar.gz unpacks
# beside the checkout, a git remote clones beside it, and both then swap.
for door in archive clone; do
  reset
  make_kept_checkout
  mkdir -p "$TMP/etc/aperire"
  printf 'auth_token = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"\n' > "$TMP/etc/aperire/relay.conf"
  if [[ "$door" == archive ]]; then
    SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
    SHA_FOR_RUN="$GOOD_SHA"
  fi
  run_sut --role=co-located --yes
  PREV="$(previous_tree)"

  if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]]; then
    ok "$door: a kept checkout is installed over rather than refused"
  else
    bad "$door: a kept checkout is installed over" "rc=$RC: $OUT"
  fi

  if [[ "$(cat "$KEPT/data/aperire.db" 2>/dev/null)" == "THE-OPERATORS-DATABASE" \
     && "$(cat "$KEPT/data/logs/dashboard.log" 2>/dev/null)" == "yesterday" ]]; then
    ok "$door: the database and the logs are in the new tree, with their contents"
  else
    bad "$door: data/ is carried across whole" "db=$(cat "$KEPT/data/aperire.db" 2>/dev/null)"
  fi

  if [[ "$(cat "$KEPT/dashboard/config/rules.local.yaml" 2>/dev/null)" == *"tuned by the operator"* \
     && "$(cat "$KEPT/dashboard/config/authn.yaml" 2>/dev/null)" == "rp_id: dash.example" ]]; then
    ok "$door: a config file the operator tuned beats the one the release ships"
  else
    bad "$door: the operator's config wins" "rules=$(cat "$KEPT/dashboard/config/rules.local.yaml" 2>/dev/null)"
  fi

  # The other half of ADR 0020, and the reason #237 was opened: rules.yaml is
  # the product's, so an update REPLACES it. Carrying it across is how a rule
  # the product corrected reached fresh installs only.
  if [[ "$(cat "$KEPT/dashboard/config/rules.yaml" 2>/dev/null)" == *"release default"* ]]; then
    ok "$door: the shipped rules.yaml is the release's, so a corrected rule reaches this host"
  else
    bad "$door: rules.yaml is replaced by the release's" "rules=$(cat "$KEPT/dashboard/config/rules.yaml" 2>/dev/null)"
  fi

  # digest.yaml was never touched by this operator, so the release's own copy
  # is what is there. The control for the row above: it proves the carry moved
  # files rather than the whole directory.
  if [[ "$(cat "$KEPT/dashboard/config/digest.yaml" 2>/dev/null)" == *"release default"* ]]; then
    ok "$door: a config file they never had stays the release's own (the control)"
  else
    bad "$door: an uncarried config file is the release's" "$(cat "$KEPT/dashboard/config/digest.yaml" 2>/dev/null)"
  fi

  if [[ "$(cat "$KEPT/advisor/state/read.token" 2>/dev/null)" == "THE-READ-TOKEN" \
     && "$(cat "$KEPT/advisor/knowledge-fleet/node1.md" 2>/dev/null)" == "node1 knowledge" \
     && -f "$KEPT/advisor/evidence/run.json" && -f "$KEPT/advisor/knowledge-bundles/b.tar" ]]; then
    ok "$door: all four Advisor directories come across, not just state/"
  else
    bad "$door: the Advisor's own directories are carried" "$(find "$KEPT/advisor" -maxdepth 1 -mindepth 1 -printf '%f ' 2>/dev/null)"
  fi
  # The aggregator's push counter lives in that directory (#1218). Carried, it
  # is what the next push builds on; left behind, the first push after the
  # reinstall is sequence 1 and every node that applied a higher one refuses it.
  if grep -q '"seq":44' "$KEPT/advisor/knowledge-bundles/seq.json" 2>/dev/null; then
    ok "$door: the push counter comes across with the bundles, at the number it had"
  else
    bad "$door: the push counter is carried" "$(cat "$KEPT/advisor/knowledge-bundles/seq.json" 2>&1)"
  fi
  # As root. The directories are the Advisor account's (mode 700), and a
  # directory is renamed into another parent only by someone who may write
  # it; the operator was refused on the first live reinstall. The fake sudo
  # records every command it ran, so the move has to appear there without
  # a -u <operator> in front of it.
  if grep -q -- "mv $TMP/op/aperire-one.previous-[^ ]*/advisor/state " "$TMP/state/sudo-exec" 2>/dev/null \
     && ! grep -q -- "-u .*mv .*/advisor/state " "$TMP/state/sudo-exec" 2>/dev/null; then
    ok "$door: the Advisor directories move as root, never as the operator"
  else
    bad "$door: advisor/state moves under sudo, not as the operator" "$(grep -- '/advisor/state' "$TMP/state/sudo-exec" 2>/dev/null | head -2)"
  fi

  # data/ too, as root (ADR 0024 lane 3). On a fresh install it belongs to
  # aperire-dashboard, not the operator, and moving a directory to a new
  # parent needs write on the directory itself, so the operator's mv was
  # refused there. In this rig as_operator runs without sudo and run_root
  # through it, so a data/ move in the sudo log is a move made as root, the
  # one that carries a data/ whatever uid owns it. -T, so a name already
  # standing in the new tree is replaced, never moved into.
  if grep -q -- "mv -T $TMP/op/aperire-one.previous-[^ ]*/data $TMP/op/aperire-one/data" "$TMP/state/sudo-exec" 2>/dev/null; then
    ok "$door: data/ moves as root, so a data/ the dashboard's own account owns is carried"
  else
    bad "$door: data/ moves under sudo, not as the operator" "$(grep -- '/data' "$TMP/state/sudo-exec" 2>/dev/null | head -3)"
  fi

  if [[ "$(cat "$KEPT/install.sh" 2>/dev/null)" != "an-earlier-release" \
     && "$(cat "$KEPT/dashboard/server.ts" 2>/dev/null)" != "the OLD dashboard" ]]; then
    ok "$door: and the code is the new release's, not the old tree's"
  else
    bad "$door: the new tree is the release" "install.sh=$(cat "$KEPT/install.sh" 2>/dev/null)"
  fi

  if [[ -n "$PREV" && -f "$PREV/dashboard/server.ts" ]]; then
    ok "$door: the old tree is kept beside it under a dated name, not deleted"
  else
    bad "$door: the old tree is renamed and kept" "found: ${PREV:-<nothing>}"
  fi
  # The link credential pairing wrote. It is the only copy, so an update that
  # left it in the old tree would take a paired node off its aggregator on
  # its first update, and only a re-pair puts it back. Carried, still 0600,
  # and said on screen like the rest.
  if [[ "$(cat "$KEPT/dashboard/config/fleet-link.json" 2>/dev/null)" == *"THE-LINK-CREDENTIAL"* \
     && "$(stat -c %a "$KEPT/dashboard/config/fleet-link.json" 2>/dev/null)" == "600" \
     && "$OUT" == *"dashboard/config/fleet-link.json"* ]]; then
    ok "$door: the fleet link credential is carried, still 0600, and said on screen"
  else
    bad "$door: the fleet link credential survives an update" \
        "file=$(cat "$KEPT/dashboard/config/fleet-link.json" 2>/dev/null || echo MISSING) mode=$(stat -c %a "$KEPT/dashboard/config/fleet-link.json" 2>/dev/null)"
  fi
  # The aggregator's fleet-links.json (#805): koi lost the hash of all three
  # paired nodes' link credentials on a reinstall over a kept tree, and every
  # node then failed to link with no line saying why.
  if links_carried; then
    ok "$door: an aggregator's fleet-links.json is carried byte for byte, still 0600, same owner, and said on screen"
  else
    bad "$door: an aggregator's fleet-links.json survives an install over a kept tree" "$(links_seen)"
  fi
  # The Advisor's binary crosses with its state, still executable, and is
  # named on screen. Left behind, the advisord unit exec'd a path that was
  # no longer there, 203/EXEC in a loop, on every host with the Advisor (#350).
  if [[ -x "$KEPT/advisor/bin/aperire-advisord" \
     && "$(cat "$KEPT/advisor/bin/aperire-advisord" 2>/dev/null)" == *"THE-ADVISOR-BINARY"* \
     && "$OUT" == *"advisor/bin/"* ]]; then
    ok "$door: the Advisor's binary is carried, still executable, and said on screen"
  else
    bad "$door: the Advisor's binary survives an update" \
        "bin=$(find "$KEPT/advisor/bin" -maxdepth 1 -type f -printf '%m %f ' 2>/dev/null)"
  fi
  if [[ "$OUT" == *"carrying your files into the new release"* \
     && "$OUT" == *"data/    the database"* \
     && "$OUT" == *"dashboard/config/rules.local.yaml"* \
     && "$OUT" == *"advisor/knowledge-fleet/"* \
     && "$OUT" == *"$PREV"* ]]; then
    ok "$door: every file that moved is said on screen, and so is where the old tree went"
  else
    bad "$door: the carry-over is printed file by file" "$OUT"
  fi

  # The relay token. /etc/aperire is the dashboard's and the relay's shared
  # secret, and a bootstrap that rewrote it would break a relay that is
  # already paired. This proves the BOOTSTRAP leaves it alone; what the real
  # installer does with it is asserted separately, below.
  if [[ "$(cat "$TMP/etc/aperire/relay.conf" 2>/dev/null)" == 'auth_token = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"' ]]; then
    ok "$door: the relay token in /etc/aperire is the same one, byte for byte"
  else
    bad "$door: the relay token is untouched" "$(cat "$TMP/etc/aperire/relay.conf" 2>/dev/null)"
  fi
done

# The carry lists and the backup set, held equal (#805). The backup set's
# dashboard/config rows say which files of an install are the operator's, and
# the bootstrap's carry list says which files an update keeps. They were two
# hand-kept lists, and the aggregator's fleet-links.json was in one and not the
# other, so a backup kept every node's link and an update dropped it. Read from
# the three source files, not copied here, so a change to any of them is seen.
#
# Every difference is named below with its reason. A new one fails the row.
# fleet-trust.pub.yaml (#868) is carried so the Advisor keeps reading it across the swap, and never backed up: it is the public half of fleet-trust.yaml, remade from it by every restore and every update.
CARRY_ONLY_ALLOWED="fleet-trust.pub.yaml metric-alerts.yaml"  # metric-alerts.yaml: carried since the first carry list; the backup set has never had a row for it, and dashboard/config no longer holds it (the insights knowledge file is dashboard/knowledge/metric-alerts.yaml)
BACKUP_ONLY_ALLOWED=""                   # nothing: a file the backup keeps and the update drops is the #805 bug

backup_config_files() { # the dashboard/config/ files in the backup set's rows, one per line
  local row path pre body suf
  while IFS= read -r row; do
    path="$(cut -d'|' -f3 <<<"$row")"
    [[ "$path" == dashboard/config/* ]] || continue
    path="${path#dashboard/config/}"
    if [[ "$path" == *'{'*'}'* ]]; then
      pre="${path%%\{*}"; body="${path#*\{}"; body="${body%%\}*}"; suf="${path#*\}}"
      tr ',' '\n' <<<"$body" | sed "s|^|$pre|; s|\$|$suf|"
    else
      printf '%s\n' "$path"
    fi
  done < <(grep "^  '[a-z-]*|" "$REPO_DIR/scripts/aperire-backup-set.sh")
}
carry_list_of() { # $1 = a script; its CARRY_CONFIG, one per line
  sed -n 's/^CARRY_CONFIG=(\(.*\))$/\1/p' "$1" | tr ' ' '\n' | grep -v '^$'
}
BACKUP_CFG="$(backup_config_files | sort -u)"
if [[ -n "$BACKUP_CFG" && "$(wc -l <<<"$BACKUP_CFG")" -ge 8 ]]; then
  ok "the backup set's dashboard/config rows were read ($(wc -l <<<"$BACKUP_CFG") files)"
else
  bad "the backup set's dashboard/config rows are readable" "got: $(tr '\n' ' ' <<<"$BACKUP_CFG")"
fi
for carrier in get-aperire.sh aperire-update.sh; do
  CARRY_CFG="$(carry_list_of "$REPO_DIR/scripts/$carrier" | sort -u)"
  only_carry="$(comm -13 <(printf '%s\n' "$BACKUP_CFG") <(printf '%s\n' "$CARRY_CFG") | tr '\n' ' ')"
  only_backup="$(comm -23 <(printf '%s\n' "$BACKUP_CFG") <(printf '%s\n' "$CARRY_CFG") | tr '\n' ' ')"
  if [[ "${only_carry% }" == "$CARRY_ONLY_ALLOWED" && "${only_backup% }" == "$BACKUP_ONLY_ALLOWED" ]]; then
    ok "$carrier: CARRY_CONFIG and the backup set's config rows differ only by what this test names"
  else
    bad "$carrier: CARRY_CONFIG and the backup set's config rows have drifted" \
        "carried but not backed up: ${only_carry:-nothing}; backed up but not carried: ${only_backup:-nothing}"
  fi
done

# (c) a checkout with no /etc/aperire beside it. The same carry, and the
# config line must not be claimed for a directory that is not there.
reset
make_kept_checkout
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$(cat "$KEPT/data/aperire.db" 2>/dev/null)" == "THE-OPERATORS-DATABASE" ]]; then
  ok "a checkout with no /etc/aperire beside it is carried across just the same"
else
  bad "a checkout alone is carried across" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"checkout: $KEPT"* && "$OUT" != *"config:   $TMP/etc/aperire"* ]]; then
  ok "and only what is really there is named: no config line for a directory that is not"
else
  bad "only what is there is named" "$OUT"
fi
if [[ "$OUT" == *"data/aperire.db is here"* ]]; then
  ok "the database is named before the fetch, where somebody can still stop"
else
  bad "the kept database is named up front" "$OUT"
fi

# The closing text has to name the tree it left behind, and how to remove it.
# Nothing here ever deletes it.
if [[ "$OUT" == *"Your earlier checkout is still on this host"* && "$OUT" == *"rm -rf $(previous_tree)"* ]]; then
  ok "the closing text names the old tree and the one command that removes it"
else
  bad "the closing text names the kept tree" "$OUT"
fi

# What the earlier install had beyond the dashboard (#1181). `uninstall --keep`
# takes off the relay, the Advisor and the pairing grant and keeps their
# configuration; this install brings back the dashboard and, only where it finds
# a node, the relay. The closing text sets what was there against what came back,
# so a host that came back less than it was says so, with the command for each.
# This section's fixture release is a smaller install.sh that records its
# environment. These rows read the units the install leaves, so they put the
# full fake back for their own length and restore the smaller one after.
cp "$TMP/release/install.sh" "$TMP/install.sh.section"
write_fake_install
reset
make_kept_checkout
mkdir -p "$TMP/etc/aperire"
printf 'node_label = "label-one"\n' > "$TMP/etc/aperire/relay.conf"
printf 'INSTALL_DIR_ID=1\n' > "$TMP/etc/aperire/fleet-broker.conf"
run_sut --role=dashboard --yes
if [[ $RC -eq 0 && "$OUT" == *"what the earlier install had, against what this one put back"* \
   && "$OUT" == *"the relay is NOT back"* && "$OUT" == *"--run relay-colocated --unit aperire-server --port 7800 --binary $KEPT/relay/aperire-relay"* \
   && "$OUT" == *"the Advisor is NOT back"* && "$OUT" == *"curl -fsSL https://get.aperire.one/advisor | bash"* \
   && "$OUT" == *"the pairing grant is NOT back"* && "$OUT" == *"--dir $KEPT --run fleet-broker-grant"* ]]; then
  ok "a dashboard reinstall over a kept relay, Advisor and grant names each as not back, with its command"
else
  bad "the closing text names what did not come back" "rc=$RC: $(tail -25 <<<"$OUT")"
fi
if [[ "$OUT" != *"is not missing"* ]]; then
  ok "  and does not tell a host that had an Advisor that it is not missing"
else
  bad "a host that had an Advisor is not told it is not missing" "$(grep -n 'not missing' <<<"$OUT")"
fi

# The other half, so the row above cannot pass on a text that always says it:
# a host whose role detection found a node gets the relay back, and the text
# says so, still naming the two that are never restored.
reset
make_kept_checkout
mkdir -p "$TMP/etc/aperire"
printf 'node_label = "label-one"\n' > "$TMP/etc/aperire/relay.conf"
printf 'INSTALL_DIR_ID=1\n' > "$TMP/etc/aperire/fleet-broker.conf"
printf 'aperire-relay.service enabled\n' > "$TMP/state/install-adds-units"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"the relay is back"* && "$OUT" != *"the relay is NOT back"* \
   && "$OUT" == *"the Advisor is NOT back"* && "$OUT" == *"the pairing grant is NOT back"* ]]; then
  ok "a host whose install put the relay back says so, and still names the Advisor and the grant"
else
  bad "the comparison reads the relay unit, not the plan" "rc=$RC: $(tail -25 <<<"$OUT")"
fi

# And when all three are back, all three are said to be: the "back" branches
# read the units too, so a text that could only ever say "NOT back" fails here.
reset
make_kept_checkout
mkdir -p "$TMP/etc/aperire"
printf 'node_label = "label-one"\n' > "$TMP/etc/aperire/relay.conf"
printf 'INSTALL_DIR_ID=1\n' > "$TMP/etc/aperire/fleet-broker.conf"
printf 'aperire-relay.service enabled\naperire-advisord.service enabled\naperire-fleet-broker.socket enabled\n' \
  > "$TMP/state/install-adds-units"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && "$OUT" == *"the relay is back"* && "$OUT" == *"the Advisor is back"* \
   && "$OUT" == *"the pairing grant is back"* && "$OUT" != *"NOT back"* ]]; then
  ok "a host that has all three again is told all three are back, and no command"
else
  bad "the back branches read the units" "rc=$RC: $(tail -20 <<<"$OUT")"
fi

# A kept host that had none of the three is told nothing about them.
reset
make_kept_checkout
rm -rf "$KEPT/advisor/bin"
mkdir -p "$TMP/etc/aperire"
printf 'SERVICE=1\n' > "$TMP/etc/aperire/aperire.env"
run_sut --role=dashboard --yes
if [[ $RC -eq 0 && "$OUT" != *"against what this one put back"* && "$OUT" != *"NOT back"* ]]; then
  ok "a kept host that never had a relay, an Advisor or a grant is told nothing about them"
else
  bad "no comparison for a host that had nothing to compare" "rc=$RC: $(grep -n 'back' <<<"$OUT")"
fi
if [[ "$OUT" == *"The Advisor is not installed, and is not missing"* ]]; then
  ok "  and still hears that the Advisor is optional"
else
  bad "a host with no Advisor still hears it is optional" "$(tail -12 <<<"$OUT")"
fi

# Only the Advisor's own config files are enough evidence, with no kept tree.
reset
mkdir -p "$TMP/etc/aperire"
printf 'SERVICE=x\n' > "$TMP/etc/aperire/node-wrapper.conf"
run_sut --role=dashboard --yes
if [[ $RC -eq 0 && "$OUT" == *"the Advisor is NOT back"* && "$OUT" != *"the relay is NOT back"* \
   && "$OUT" != *"the pairing grant is NOT back"* ]]; then
  ok "the Advisor is named from its kept config alone, and only the Advisor"
else
  bad "one component is named from its own evidence" "rc=$RC: $(tail -15 <<<"$OUT")"
fi

# The aggregator's shape, which walks 1 and 2 on koi both hit (#1181). It has no
# node wrapper, and the keep removed its model key and its build output; all that
# is left of its Advisor is advisor/state. The install said nothing about an
# Advisor that the uninstall had named a minute earlier.
reset
make_kept_checkout
rm -rf "$KEPT/advisor/bin"
printf 'a-token-only-the-advisor-writes-xxxxxxxxxxxx\n' > "$KEPT/advisor/state/approve.token"
mkdir -p "$TMP/etc/aperire"
run_sut --role=dashboard --yes
if [[ $RC -eq 0 && "$OUT" == *"what the earlier install had, against what this one put back"* \
   && "$OUT" == *"the Advisor is NOT back"* && "$OUT" == *"curl -fsSL https://get.aperire.one/advisor | bash"* \
   && "$OUT" != *"the relay is NOT back"* && "$OUT" != *"the pairing grant is NOT back"* ]]; then
  ok "an aggregator whose keep left only advisor/state/approve.token is told its Advisor is not back, with the command"
else
  bad "the Advisor is named from the token in its state directory" "rc=$RC: $(tail -15 <<<"$OUT")"
fi
if [[ "$OUT" != *"is not missing"* ]]; then
  ok "  and is not told the Advisor is not missing"
else
  bad "a host whose state holds an Advisor token is not told it never had one" "$(grep -n 'not missing' <<<"$OUT")"
fi

# The control: the dashboard's own read.token and the reveal window sit in that
# directory on a host that never had an Advisor, so neither is evidence. This is
# the fixture the "none of the three" row above uses, said again here with the
# token's absence as the one difference.
reset
make_kept_checkout
rm -rf "$KEPT/advisor/bin"
mkdir -p "$TMP/etc/aperire"
run_sut --role=dashboard --yes
if [[ $RC -eq 0 && -e "$KEPT/advisor/state/read.token" && "$OUT" != *"Advisor is NOT back"* \
   && "$OUT" != *"against what this one put back"* ]]; then
  ok "a state directory with the dashboard's read.token and no approve.token is not an Advisor"
else
  bad "read.token alone does not name an Advisor" "rc=$RC: $(tail -12 <<<"$OUT")"
fi

# The row has to be able to fail: the script with the token line taken out.
M_NOSTATETOKEN="$TMP/no-state-token.sh"
# shellcheck disable=SC2016  # literal sed text and a literal line to find, not expressions
mutant "$M_NOSTATETOKEN" '/^  \[\[ -e "\$DIR\/advisor\/state\/approve.token" \]\] && KEPT_ADVISOR=1$/d' 'for f in "$ETC_APERIRE/fleet-broker.conf"'
reset
make_kept_checkout
rm -rf "$KEPT/advisor/bin"
printf 'a-token-only-the-advisor-writes-xxxxxxxxxxxx\n' > "$KEPT/advisor/state/approve.token"
mkdir -p "$TMP/etc/aperire"
printf 'node_label = "label-one"\n' > "$TMP/etc/aperire/relay.conf"
run_file "$M_NOSTATETOKEN" --role=dashboard --yes
if [[ $RC -eq 0 && "$OUT" == *"the relay is NOT back"* && "$OUT" != *"the Advisor is NOT back"* ]]; then
  ok "without the state-token line the same host is told about its relay and not its Advisor, which is the bug (#1181)"
else
  bad "the token line is what names the Advisor" "rc=$RC: $(tail -12 <<<"$OUT")"
fi

cp "$TMP/install.sh.section" "$TMP/release/install.sh"
chmod +x "$TMP/release/install.sh"
rm -f "$TMP/install.sh.section"

# An install that died halfway leaves a checkout with nothing of the
# operator's in it. It is still replaced, and nothing is claimed to have been
# carried, because there was nothing to carry. Every other row in this section
# builds a fixture WITH data in it, so without this one the screen text could
# promise files that do not exist and no row would notice.
reset
rm -rf "$KEPT"
mkdir -p "$KEPT/dashboard/config" "$KEPT/advisor"
printf 'a half-unpacked release\n' > "$KEPT/install.sh"
run_sut --role=co-located --yes
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]]; then
  ok "a checkout with nothing of the operator's in it is replaced, not refused"
else
  bad "a bare checkout is replaced" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"nothing of yours is in it"* && "$OUT" != *"carrying your files"* \
   && "$OUT" != *"These are yours"* ]]; then
  ok "and nothing is claimed to have been carried, because nothing was"
else
  bad "no carry-over is claimed for a bare checkout" "$OUT"
fi

# --check reports; it does not promise. The same host, the same finding, and
# a sentence that cannot be read as something the run is about to do.
reset
make_kept_checkout
run_sut --role=co-located --check
if [[ "$OUT" == *"This is what an install here would find."* && "$OUT" != *"this install reuses them"* ]]; then
  ok "--check says what it found and promises nothing, because it installs nothing"
else
  bad "--check reports rather than promises" "$OUT"
fi
if [[ -f "$KEPT/data/aperire.db" && -z "$(previous_tree)" ]]; then
  ok "and it leaves the kept checkout exactly where it was"
else
  bad "--check does not touch the kept checkout" "db=$(cat "$KEPT/data/aperire.db" 2>/dev/null), previous=$(previous_tree)"
fi

# #1046. After an install refused partway, data/ belongs to the dashboard's
# account at 0700 and the login cannot look inside it. The preamble tested
# `-f data/aperire.db` as the login, read "absent", and said there was no
# database to carry. A mode-000 directory is the same condition for a login
# that is not root, which is the only account this row can be run as.
reset
make_kept_checkout
chmod 0000 "$KEPT/data"
if [[ ! -x "$KEPT/data" ]]; then
  run_sut --role=co-located --check
  if [[ "$OUT" == *"no database to carry"* ]]; then
    bad "a data/ the login can't list is not reported as having no database (#1046)" "$OUT"
  elif [[ "$OUT" == *"data/ is here, but it belongs to another account"* && "$OUT" == *"can't be checked from here"* ]]; then
    ok "a data/ this account can't list is reported as unchecked, never as having no database (#1046)"
  else
    bad "a data/ the login can't list says it can't be checked (#1046)" "$OUT"
  fi
else
  ok "(skipped: this run can list a mode-000 directory, so it is root; the 0700-owned-by-another row needs a login)"
fi
chmod 0700 "$KEPT/data"
# And a data/ the login CAN list with no database in it still says so.
reset
make_kept_checkout
rm -f "$KEPT/data/aperire.db"
run_sut --role=co-located --check
if [[ "$OUT" == *"no data/aperire.db in it, so there is no database to carry"* ]]; then
  ok "a data/ that can be listed and holds no database still says so"
else
  bad "a listable data/ with no database says there is none" "$OUT"
fi

# The negative control for the whole section: a directory at $DIR that is NOT
# an Aperire checkout is still refused by name. Without this row, "install
# over anything" would pass every check above.
reset
mkdir -p "$TMP/op/aperire-one/somebody-elses-work"
printf 'not ours\n' > "$TMP/op/aperire-one/notes.txt"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"pass --dir"* ]]; then
  ok "a directory that is not an Aperire checkout is still refused, and not carried"
else
  bad "a non-checkout directory is refused" "rc=$RC: $OUT"
fi

# The other half of the token claim, which no fake install.sh can prove: the
# real relay installer reuses the token already in the config before it mints
# one. Asserted as a reading of that file, and labelled as one.
# shellcheck disable=SC2016  # the installer's literal text, matched, never expanded
if grep -q 'TOKEN="$(conf_token)"' "$REPO_DIR/scripts/install-aperire-relay.sh" \
   && grep -q 'reusing the relay token already in' "$REPO_DIR/scripts/install-aperire-relay.sh"; then
  ok "and install-aperire-relay.sh reuses a token that is already there before it mints one"
else
  bad "the relay installer reuses an existing token" \
      "$(grep -n 'conf_token\|openssl rand' "$REPO_DIR/scripts/install-aperire-relay.sh" | head -5)"
fi

# ── the checklist, and where it sits in the run ─────────────────────
#
# The operator's ruling: the install checks its prerequisites and says what is
# missing BEFORE it goes any further. The checklist lives in the release, so
# it cannot run before the fetch; what has to hold is that it runs after the
# unpack and before install.sh, every time, and that a refusal from it stops
# the run with nothing installed.

echo
echo "The prerequisite check, and the order it runs in:"

write_fake_install

reset
run_sut --role=co-located --yes
if [[ "$(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null)" == "preflight install " ]]; then
  ok "the checklist runs after the unpack and before install.sh"
else
  bad "the checklist runs after the unpack and before install.sh" \
      "order: $(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null), rc=$RC"
fi

if [[ "$(cat "$TMP/state/preflight-args" 2>/dev/null)" == *"--role=validator"* ]]; then
  bad "the checklist is given the role install.sh is given" "co-located run passed a validator role"
elif [[ "$(cat "$TMP/state/preflight-args" 2>/dev/null)" == *"--role=co-located"* ]]; then
  ok "the checklist is given the same role install.sh is given"
else
  bad "the checklist is given the same role install.sh is given" \
      "$(cat "$TMP/state/preflight-args" 2>/dev/null)"
fi

if [[ "$(cat "$TMP/state/install-args" 2>/dev/null)" == *--no-preflight* ]]; then
  ok "install.sh is told the check already ran, so the node question is asked once"
else
  bad "install.sh is told the check already ran" "$(cat "$TMP/state/install-args" 2>/dev/null)"
fi

# The refusal, with its control beside it: the same run, same fakes, with the
# checklist passing, does reach install.sh.
reset
: > "$TMP/state/preflight-fails"
run_sut --role=co-located --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && "$OUT" == *"missing something the install needs"* ]]; then
  ok "a MISSING stops the run before install.sh, and says so"
else
  bad "a MISSING stops the run before install.sh" "rc=$RC, install-args=$(cat "$TMP/state/install-args" 2>/dev/null)"
fi
if [[ "$OUT" == *"MISSING  disk"* ]]; then
  ok "and the checklist's own line is what the operator is left looking at"
else
  bad "the checklist's own line is printed" "$OUT"
fi

# The node answer, all the way through. The checklist writes a port into the
# answer file it was handed; install.sh has to receive it as the variable the
# service installer reads. Four hops, and every one of them is silent when it
# breaks.
reset
printf 'RIPPLED_URL=ws://127.0.0.1:6009\n' > "$TMP/state/preflight-answer"
run_sut --role=co-located --yes
if [[ "$(cat "$TMP/state/install-node-url" 2>/dev/null)" == "ws://127.0.0.1:6009" ]]; then
  ok "the port the checklist settled on reaches install.sh as APERIRE_RIPPLED_URL"
  if [[ "$(tail -1 "$TMP/state/install-record-role" 2>/dev/null)" == "<unset>" ]]; then
    ok "  and a role the operator named is left to be recorded (no APERIRE_RECORD_ROLE=0)"
  else
    bad "a named role is recorded" "install.sh saw '$(cat "$TMP/state/install-record-role" 2>/dev/null)'"
  fi
else
  bad "the port the checklist settled on reaches install.sh" \
      "install.sh saw '$(cat "$TMP/state/install-node-url" 2>/dev/null)'"
fi

reset
run_sut --role=co-located --yes
if [[ "$(cat "$TMP/state/install-node-url" 2>/dev/null)" == "<unset>" ]]; then
  ok "and nothing is passed when the checklist settled on nothing (the control)"
else
  bad "nothing is passed when the checklist settled on nothing" \
      "install.sh saw '$(cat "$TMP/state/install-node-url" 2>/dev/null)'"
fi

# A release from before the checklist existed. The bootstrap and the release
# ship together, but a --source pointed at an older tree is a real thing an
# operator can do, and it must install rather than refuse an argument.
reset
mv "$TMP/release/scripts/preflight.sh" "$TMP/preflight.parked"
run_sut --role=co-located --yes
mv "$TMP/preflight.parked" "$TMP/release/scripts/preflight.sh"
if [[ -f "$TMP/state/install-args" && "$(cat "$TMP/state/install-args")" != *--no-preflight* ]]; then
  ok "a release with no checklist still installs, and install.sh runs its own"
else
  bad "a release with no checklist still installs, running install.sh's own check" \
      "rc=$RC, args=$(cat "$TMP/state/install-args" 2>/dev/null)"
fi
if [[ "$OUT" == *"carries no scripts/preflight.sh"* ]]; then
  ok "and it says so rather than skipping quietly"
else
  bad "it says the release carries no checklist" "$OUT"
fi

echo
echo "--check: a report that installs nothing:"

reset
run_sut --role=co-located --check
if [[ $RC -eq 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "--check runs the checklist and installs nothing"
else
  bad "--check runs the checklist and installs nothing" "rc=$RC: $OUT"
fi
if [[ ! -d "$TMP/op/aperire-one" ]]; then
  ok "and leaves no checkout behind: it fetched into a directory that went with the run"
else
  bad "--check leaves no checkout behind" "$TMP/op/aperire-one is still there"
fi
if [[ "$(cat "$TMP/state/preflight-args" 2>/dev/null)" == *--check* ]]; then
  ok "and the checklist is told it is a check, so it asks nothing and writes nothing"
else
  bad "the checklist is told it is a check" "$(cat "$TMP/state/preflight-args" 2>/dev/null)"
fi

reset
: > "$TMP/state/preflight-fails"
run_sut --role=co-located --check
if [[ $RC -eq 1 && ! -f "$TMP/state/install-args" ]]; then
  ok "--check exits non-zero when something is missing"
else
  bad "--check exits non-zero when something is missing" "rc=$RC: $OUT"
fi

# An installed host. --check has to answer there too: it is exactly where
# somebody asks what is missing, and the menu short-circuit would swallow it.
reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
run_sut --role=co-located --check
if [[ $RC -eq 0 && "$OUT" != *"already installed on this host"* ]]; then
  ok "--check on an installed host reports instead of opening the menu"
else
  bad "--check on an installed host reports instead of opening the menu" "rc=$RC: $OUT"
fi
# And with a config directory and a checkout beside the unit, which is every
# installed host: the report says installed, never "No unit is installed",
# which is the sentence written for a host an uninstall --keep left behind.
reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire" "$TMP/op/aperire-one"; : > "$TMP/op/aperire-one/install.sh"
run_sut --role=co-located --check
if [[ $RC -eq 0 && "$OUT" == *"Installed here: aperire-server.service"* && "$OUT" != *"No unit is installed"* ]]; then
  ok "--check on an installed host with its config and checkout says installed, not 'No unit is installed'"
else
  bad "--check on an installed host names the units" "rc=$RC: $OUT"
fi

# ── the release stamp ───────────────────────────────────────────────
#
# .release is how a host says which release it is running, and nothing else
# on a box records that (ADR 0022). Two ways it fails quietly: a stamp that
# is not written at all, which reads as "unknown, older than 2026-09-08" and
# looks like an old host rather than a broken write; and a stamp carrying
# values this copy of the script never had, which reads as current when it
# is not. So the rows below assert the file, its fields, and where each
# value came from.

echo
echo "The release stamp, written at the end of an install:"

STAMP="$TMP/op/aperire-one/.release"
STAMP_TAG='snapshot-2026-09-08'
STAMP_COMMIT='f92ee3b'
STAMP_AT='2026-09-08T00:00:00Z'

# The published copy: the same script with the block the publisher stamps
# filled in, pointing at the archive fixture. Made here rather than by hand
# so that a renamed stamp line fails loudly instead of leaving these rows
# asserting an empty string against an empty string.
PUBLISHED_COPY="$TMP/published-copy.sh"
sed -e "s|^DEFAULT_SOURCE_URL=.*|DEFAULT_SOURCE_URL='file://$TMP/release.tar.gz'|" \
    -e "s|^DEFAULT_EXPECTED_SHA256=.*|DEFAULT_EXPECTED_SHA256='$GOOD_SHA'|" \
    -e "s|^DEFAULT_RELEASE_TAG=.*|DEFAULT_RELEASE_TAG='$STAMP_TAG'|" \
    -e "s|^DEFAULT_RELEASE_COMMIT=.*|DEFAULT_RELEASE_COMMIT='$STAMP_COMMIT'|" \
    -e "s|^DEFAULT_PUBLISHED_AT=.*|DEFAULT_PUBLISHED_AT='$STAMP_AT'|" \
    "$SUT" > "$PUBLISHED_COPY"
for v in DEFAULT_RELEASE_TAG DEFAULT_RELEASE_COMMIT DEFAULT_PUBLISHED_AT; do
  grep -q "^$v='" "$PUBLISHED_COPY" \
    || { echo "the $v line has moved in $SUT; the release-stamp rows below would prove nothing"; exit 1; }
done

# One field out of the object, without needing a JSON parser on the host:
# every value this script writes is a string on its own line.
field_of() { # $1 = file, $2 = key
  sed -n "s/^  \"$2\": \"\(.*\)\",\?\$/\1/p" "$1"
}

reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --role=co-located --yes
missing=""
for k in tag commit sha256 published_at source_url installed_at; do
  grep -q "^  \"$k\": " "$STAMP" 2>/dev/null || missing="$missing $k"
done
if [[ -f "$STAMP" && -z "$missing" ]]; then
  ok "an install writes .release at the tree root, with all six fields"
else
  bad "an install writes .release with all six fields" \
      "file=$([[ -f "$STAMP" ]] && echo yes || echo no) missing:${missing:-none}"
fi

if [[ "$(field_of "$STAMP" tag)" == "$STAMP_TAG" \
   && "$(field_of "$STAMP" commit)" == "$STAMP_COMMIT" \
   && "$(field_of "$STAMP" published_at)" == "$STAMP_AT" \
   && "$(field_of "$STAMP" sha256)" == "$GOOD_SHA" \
   && "$(field_of "$STAMP" source_url)" == "file://$TMP/release.tar.gz" ]]; then
  ok "and every value in it is the one the stamp block carries, not one this run made up"
else
  bad "the stamp writes the values the stamp block carries" "$(tr '\n' ' ' < "$STAMP" 2>/dev/null)"
fi

# installed_at is the one value that is this run's own, and the one that may
# never be empty: a stamp with no date cannot be told from a stamp nobody
# wrote.
if [[ "$(field_of "$STAMP" installed_at)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
  ok "and installed_at is this run's own time, in UTC"
else
  bad "installed_at is an ISO 8601 UTC time" "installed_at=$(field_of "$STAMP" installed_at)"
fi

# The control for the two rows above, and the honest half of the reading: a
# copy that came out of a clone was never published, so it has no tag and no
# date. It writes them empty rather than guessing, and fills in the one
# thing a clone does know.
reset
run_sut --role=co-located --yes
if [[ -f "$STAMP" && -z "$(field_of "$STAMP" tag)" && -z "$(field_of "$STAMP" published_at)" \
   && "$(field_of "$STAMP" commit)" == "abc1234" ]]; then
  ok "an unstamped copy writes no tag and no date, and names the commit it checked out"
else
  bad "an unstamped copy invents nothing" "$(tr '\n' ' ' < "$STAMP" 2>/dev/null)"
fi

# One file claims identity. A host the fleet update has been on carries a
# .deploy-ref naming a commit that is no longer installed here, and two
# files answering one question is how a page reads the wrong one.
#
# Through the clone door, into a checkout that is updated in PLACE, because
# that is the one path where the earlier file is still there when the stamp
# is written: the archive door renames the whole tree aside and the
# .deploy-ref goes with it. A row driven through the archive would pass with
# the removal deleted.
reset
mkdir -p "$TMP/op/aperire-one"
cp -r "$TMP/release/." "$TMP/op/aperire-one/"
mkdir -p "$TMP/op/aperire-one/.git"
printf '0123456789abcdef0123456789abcdef01234567\n' > "$TMP/op/aperire-one/.deploy-ref"
run_sut --role=co-located --yes
if [[ -f "$STAMP" && ! -e "$TMP/op/aperire-one/.deploy-ref" ]]; then
  ok "writing the stamp removes the .deploy-ref beside it, so one file claims this install"
else
  bad "the .deploy-ref goes when the stamp lands" \
      "stamp=$([[ -f "$STAMP" ]] && echo yes || echo no) deploy-ref=$([[ -e "$TMP/op/aperire-one/.deploy-ref" ]] && echo still there || echo gone)"
fi

# A reinstall over a kept checkout: the old stamp comes across with the
# operator's files, and then this run's own stamp replaces it. The carry
# matters for the run that dies in between, which would otherwise leave a
# host saying nothing. The kept tree keeps its own copy too (ADR 0024): its
# sha256 is the key a rollback finds that tree's release digests by.
reset
make_kept_checkout
printf '{\n  "tag": "snapshot-2026-01-01",\n  "commit": "0000001",\n  "sha256": "",\n  "published_at": "2026-01-01T00:00:00Z",\n  "source_url": "",\n  "installed_at": "2026-01-01T00:00:00Z"\n}\n' \
  > "$TMP/op/aperire-one/.release"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --role=co-located --yes
PREV="$(previous_tree)"
if [[ "$(field_of "$STAMP" tag)" == "$STAMP_TAG" && -n "$PREV" \
      && "$(field_of "$PREV/.release" tag)" == "snapshot-2026-01-01" ]]; then
  ok "a reinstall carries the earlier stamp into the new tree, overwrites it with this release's, and the kept tree keeps its own"
else
  bad "a reinstall carries the stamp across and rewrites it" \
      "tag=$(field_of "$STAMP" tag) previous=${PREV:-none} left behind=$([[ -f "${PREV:-/nowhere}/.release" ]] && echo yes || echo no)"
fi

# --check installs nothing, and a stamp is a claim about an install. The
# host here already has one, which is the case where a wrong write would be
# read as truth by everything downstream.
reset
make_kept_checkout
printf '{\n  "tag": "snapshot-2026-01-01",\n  "commit": "0000001",\n  "sha256": "",\n  "published_at": "2026-01-01T00:00:00Z",\n  "source_url": "",\n  "installed_at": "2026-01-01T00:00:00Z"\n}\n' \
  > "$TMP/op/aperire-one/.release"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --role=co-located --check
if [[ "$(field_of "$STAMP" tag)" == "snapshot-2026-01-01" && -z "$(previous_tree)" ]]; then
  ok "--check writes no stamp: the one already on the host is untouched"
else
  bad "--check leaves the stamp alone" "tag=$(field_of "$STAMP" tag), previous=$(previous_tree)"
fi

# ── --update: moving an installed host to this release ──────────────
#
# The gap this closes, found live on 2026-09-09: the dashboard's Updates card
# told an operator whose host was behind to run the one-line install, and the
# bootstrap answered "Aperire One is already installed on this host" and
# opened the menu, which had no update entry either. There was no
# operator-facing way to move an installed host to a newer release at all.
#
# What has to hold: the role is READ and never asked; a host already on the
# release is told so and nothing is fetched; a bad archive changes nothing;
# the same carry-and-swap a reinstall does runs, with a database snapshot
# taken out of the tree first; install.sh is run with --no-restart on every
# update; and nothing restarts without an answer.

echo
echo "Updating a host that is already installed:"

# The fixture: units, a checkout with the operator's files in it, and
# /etc/aperire beside it. What every installed host looks like.
make_installed_host() { # $1... = extra unit lines
  make_kept_checkout
  printf 'aperire-server.service enabled\n' > "$TMP/state/units"
  printf 'aperire-relay.service enabled\n' >> "$TMP/state/units"
  echo active > "$TMP/state/active-aperire-server.service"
  echo active > "$TMP/state/active-aperire-relay.service"
  mkdir -p "$TMP/etc/aperire"
  printf 'auth_token = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"\n' > "$TMP/etc/aperire/relay.conf"
}
# A stamp naming a release this host is NOT on, so the gate lets the run
# through. The sha is the one field the gate compares.
stamp_an_older_release() {
  printf '{\n  "tag": "snapshot-2026-01-01",\n  "commit": "0000001",\n  "sha256": "%s",\n  "published_at": "2026-01-01T00:00:00Z",\n  "source_url": "",\n  "installed_at": "2026-01-01T00:00:00Z"\n}\n' \
    "$(printf '0%.0s' {1..64})" > "$TMP/op/aperire-one/.release"
}
db_snapshot() { find "$TMP/op" -maxdepth 1 -name 'aperire-one.db-*' | head -1; }

reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
# Read before the run, so the rows at the end of this section compare the
# marker that crossed against the marker that was there (#651).
REVEAL_MTIME_BEFORE="$(stat -c '%Y' "$KEPT/advisor/state/reveal.window")"
REVEAL_INODE_BEFORE="$(stat -c '%i' "$KEPT/advisor/state/reveal.window")"
REVEAL_OWNER_BEFORE="$(stat -c '%u' "$KEPT/advisor/state/reveal.window")"
run_file "$PUBLISHED_COPY" --update --yes
PREV="$(previous_tree)"

if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]]; then
  ok "--update on an installed host installs, where the plain install would open the menu"
else
  bad "--update installs on an installed host" "rc=$RC: $OUT"
fi
if [[ "$(cat "$KEPT/data/aperire.db" 2>/dev/null)" == "THE-OPERATORS-DATABASE" \
   && "$(cat "$KEPT/dashboard/config/rules.local.yaml" 2>/dev/null)" == *"tuned by the operator"* \
   && "$(cat "$KEPT/advisor/state/read.token" 2>/dev/null)" == "THE-READ-TOKEN" \
   && "$(cat "$KEPT/install.sh" 2>/dev/null)" != "an-earlier-release" ]]; then
  ok "it is the same carry-and-swap a reinstall does: data, config and Advisor state cross, the code is new"
else
  bad "--update carries and swaps" "db=$(cat "$KEPT/data/aperire.db" 2>/dev/null) install.sh=$(cat "$KEPT/install.sh" 2>/dev/null)"
fi
if links_carried; then
  ok "--update carries an aggregator's fleet-links.json byte for byte, still 0600, same owner, and says so (#805)"
else
  bad "--update keeps an aggregator's fleet-links.json" "$(links_seen)"
fi
if [[ -n "$PREV" && -f "$PREV/dashboard/server.ts" ]]; then
  ok "and the tree it replaced is kept beside it under a dated name"
else
  bad "--update keeps the old tree" "found: ${PREV:-<nothing>}"
fi
# The snapshot's first attempt is VACUUM INTO, and .backup only after it
# (#348): the shell's .backup restarts whenever the dashboard writes, and on
# a gigabyte it restarted for 43 minutes on a live node. Read off what
# sqlite3 was actually asked, in order, by the shim on PATH.
first_vacuum="$(grep -n 'VACUUM INTO' "$TMP/state/sqlite3-args" 2>/dev/null | head -1 | cut -d: -f1)"
first_backup="$(grep -n '\.backup' "$TMP/state/sqlite3-args" 2>/dev/null | head -1 | cut -d: -f1)"
if [[ -n "$first_vacuum" && ( -z "$first_backup" || "$first_vacuum" -lt "$first_backup" ) ]]; then
  ok "the database snapshot tries VACUUM INTO first, and .backup only after it"
else
  bad "the snapshot is taken with VACUUM INTO before .backup" \
      "sqlite3 was asked: $(cut -c1-120 "$TMP/state/sqlite3-args" 2>/dev/null | tr '\n' '|')"
fi
if [[ "$(field_of "$STAMP" tag)" == "$STAMP_TAG" && "$(field_of "$STAMP" sha256)" == "$GOOD_SHA" ]]; then
  ok "and the new stamp names the release that was just applied"
else
  bad "--update writes the new stamp" "$(tr '\n' ' ' < "$STAMP" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/etc/aperire/relay.conf" 2>/dev/null)" == 'auth_token = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"' ]]; then
  ok "the relay token in /etc/aperire is the same one, byte for byte"
else
  bad "--update leaves the relay token alone" "$(cat "$TMP/etc/aperire/relay.conf" 2>/dev/null)"
fi

# ── The two facts #645's reveal window stands on (#651) ──────────────
#
# advisorRevealWindowOpen reads advisor/state/reveal.window's age and owner as
# proof that a human with real sudo ran the installer on THIS box in the last
# fifteen minutes. That proof is only worth anything while nothing except
# install-advisord.sh's own plant can make the marker look freshly opened.
# Two things make that true today, and until these rows existed, neither was
# enforced by anything a change would trip over.
#
# Fact 1: a signed update/apply job never reaches install-advisord.sh. The
# chain is update/apply -> aperire-update.sh apply -> get-aperire.sh ->
# install.sh, and install.sh only runs install-advisor-stack.sh (whose step 1
# is install-advisord.sh) when --with-advisor is on its argv. Nothing on the
# update path puts it there. Held here by reading the argv that actually
# crossed into install.sh on the run above, which was a real --update.
#
# Not the same as the fresh-install row further up that also looks for this
# flag: that one is about installing an Advisor nobody asked for. This one is
# about an automated, remotely-triggered job being able to open a window that
# only a human at the keyboard was supposed to open.
if ! grep -q -- '--with-advisor' "$TMP/state/install-args"; then
  ok "an update never passes --with-advisor, so no update can reach the reveal window's planter"
else
  bad "the update path never asks for the Advisor installer" "$(cat "$TMP/state/install-args")"
fi

# Fact 2: the carry moves advisor/state, it does not recreate it. A rename
# within one filesystem keeps the inode, and with it the mtime and the owner,
# so a carried marker keeps its real age. A carry rewritten to use cp, rsync
# or a tar extract would give every update a marker stamped "just now".
#
# The inode is the assertion that actually holds the invariant. mtime alone
# would still pass a `cp -p`, which preserves the timestamp and creates a new
# file; only the inode can tell "this is the same file" from "this is a copy
# that looks like it".
carried="$KEPT/advisor/state/reveal.window"
if [[ -f "$carried" ]]; then
  ok "the reveal window crossed the update, rather than being left in the old tree"
else
  bad "the carry brings reveal.window across" "nothing at $carried"
fi
if [[ "$(stat -c '%Y' "$carried" 2>/dev/null)" == "$REVEAL_MTIME_BEFORE" ]]; then
  ok "with its real age intact: an update opens no window, it carries the one that was there"
else
  bad "the carry preserves reveal.window's mtime" \
      "before=$REVEAL_MTIME_BEFORE after=$(stat -c '%Y' "$carried" 2>/dev/null)"
fi
if [[ "$(stat -c '%i' "$carried" 2>/dev/null)" == "$REVEAL_INODE_BEFORE" ]]; then
  ok "and it is the same inode, so the carry is a rename and not a copy that looks like one"
else
  bad "the carry moves reveal.window rather than recreating it" \
      "before=$REVEAL_INODE_BEFORE after=$(stat -c '%i' "$carried" 2>/dev/null)"
fi
# Ownership is read too, but only where this suite can really test it. As an
# ordinary account every file here is already this account's, so an owner
# check would pass on a broken carry as readily as a working one and would be
# theatre. Under root, or fakeroot, it is a real reading.
if [[ $EUID -eq 0 ]]; then
  if [[ "$(stat -c '%u' "$carried" 2>/dev/null)" == "$REVEAL_OWNER_BEFORE" ]]; then
    ok "and the same owner: root's mark stays root's across the update"
  else
    bad "the carry preserves reveal.window's owner" \
        "before=$REVEAL_OWNER_BEFORE after=$(stat -c '%u' "$carried" 2>/dev/null)"
  fi
fi

# The role. Read off the units, passed to install.sh, and never asked: the run
# above had a terminal on neither end and named no role, and a run that had
# asked would have taken a default rather than a reading.
if grep -q -- '--role=co-located' "$TMP/state/install-args" \
   && grep -q "read from this host's units" <<<"$OUT"; then
  ok "the role is read off the units on the host, not asked and not guessed"
else
  bad "the role is read from the units" "args=$(cat "$TMP/state/install-args" 2>/dev/null)"
fi

# #808: a role READ off the units is a guess, and install.sh is told not to
# write a guess into aperire.env as the install role. A box with a node and no
# relay unit reads as a dashboard here, and recording that would turn its
# bridge off while /healthz said ok.
if [[ "$(tail -1 "$TMP/state/install-record-role" 2>/dev/null)" == "0" ]]; then
  ok "an update that inferred the role from the units tells install.sh not to record it"
else
  bad "an inferred role is not recorded" "install.sh saw '$(cat "$TMP/state/install-record-role" 2>/dev/null)'"
fi

# The trap this row exists for: --no-restart has to reach install.sh on EVERY
# update, not only when the operator passed the bootstrap's own --no-restart.
# Coupled to the flag, the default update would restart the dashboard inside
# install.sh and then ask about it, and no fake install.sh could notice.
if grep -q -- '--no-restart' "$TMP/state/install-args" \
   && grep -q -- '--no-preflight' "$TMP/state/install-args"; then
  ok "install.sh is run with --no-restart and --no-preflight on every update"
else
  bad "install.sh is told not to restart and not to re-ask the checklist" \
      "args=$(cat "$TMP/state/install-args" 2>/dev/null)"
fi

# And the third one, for the same reason: without it install.sh and its
# sub-installers print the first-install banner at a host that has been
# running for months. "authn.yaml still names localhost" to a host with
# enrolled passkeys, "create the first operator" to a host that has them, two
# firewall advisories and a PATH warning (aperire4, 2026-09-09, #269).
if grep -q -- '--quiet-existing' "$TMP/state/install-args"; then
  ok "and with --quiet-existing, so nothing below repeats what this host was told on the install"
else
  bad "install.sh is told this host is already set up" \
      "args=$(cat "$TMP/state/install-args" 2>/dev/null)"
fi

# The database, copied out of the tree before anything moved. Beside the
# checkout, because the swap renames the tree and carries data/ with it: a
# copy inside data/ travels with the database it is a copy of.
SNAP="$(db_snapshot)"
if [[ -n "$SNAP" && -s "$SNAP" ]] && grep -qF "database snapshot: $SNAP" <<<"$OUT"; then
  ok "the database is copied out of the tree first, and the copy is named on screen"
else
  bad "a database snapshot is taken beside the checkout" "found: ${SNAP:-<nothing>}"
fi
if [[ "$(cat "$SNAP" 2>/dev/null)" == "THE-OPERATORS-DATABASE" ]]; then
  ok "and it holds the database as it was before the update, which is what a rollback needs"
else
  bad "the snapshot is a copy of the operator's database" "$(head -c 60 "$SNAP" 2>/dev/null)"
fi
if grep -qF -e "$SNAP" <<<"$OUT" && grep -q "as it was before this update" <<<"$OUT"; then
  ok "and the closing text names it, beside the tree that holds the old code"
else
  bad "the closing text names the snapshot" "$(tail -12 <<<"$OUT")"
fi

# The release key and its check, which the updater needs and which an update
# refreshes BEFORE the updater itself, from the bytes the signed manifest
# names and nothing else.
signed_update() {
  reset
  make_installed_host
  stamp_an_older_release
  mkdir -p "$TMP/sbin"
  printf 'the OLD updater\n' > "$TMP/sbin/aperire-update"
  SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
  run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$GOOD_SHA"
}
signed_update
key_line="$(grep -n 'release-verify-lib.sh and release-signers are this release' <<<"$OUT" | head -1 | cut -d: -f1)"
upd_line="$(grep -n 'sbin/aperire-update refreshed from the new tree' <<<"$OUT" | head -1 | cut -d: -f1)"
if [[ $RC -eq 0 ]] && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/test-signers" \
   && cmp -s "$TMP/lib/aperire/release-verify-lib.sh" "$REPO_DIR/scripts/release-verify-lib.sh" \
   && [[ "$(cat "$TMP/sbin/aperire-update")" == "the NEW updater" ]] \
   && [[ -n "$key_line" && -n "$upd_line" && "$key_line" -lt "$upd_line" ]] \
   && grep -qF "are this release's (the signed release's key set)" <<<"$OUT" \
   && grep -q 'release key SHA256:' <<<"$OUT"; then
  ok "an update puts the release key and its check in place from the signed release, before the updater that needs them"
else
  bad "the release key is refreshed before the updater" \
      "rc=$RC key@${key_line:-none} updater@${upd_line:-none}: $(grep -iE 'release-signers|release-verify|updater' <<<"$OUT" | head -4)"
fi

signed_update_tampered() {
  reset
  make_installed_host
  stamp_an_older_release
  mkdir -p "$TMP/sbin" "$TMP/lib/aperire"
  printf 'the OLD updater\n' > "$TMP/sbin/aperire-update"
  cp "$TMP/test-signers" "$TMP/lib/aperire/release-signers"
  : > "$TMP/state/tamper-signers"
  [[ "${TAMPER_DOWNLOAD:-0}" == 1 ]] && : > "$TMP/state/tamper-download"
  SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
  run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$GOOD_SHA"
}
signed_update_tampered
if cmp -s "$TMP/lib/aperire/release-signers" "$TMP/test-signers" \
   && ! grep -q planted "$TMP/lib/aperire/release-signers" \
   && grep -qF 'release-signers was NOT refreshed: scripts/release-signers in the tree is not the file this release shipped' <<<"$OUT"; then
  ok "a release key changed in the tree after it was checked is not copied: root keeps the key it had, and says which file and why"
else
  bad "a key planted in the tree during the install is not copied" \
      "$(grep -c planted "$TMP/lib/aperire/release-signers" 2>/dev/null) planted line(s): $(grep -iE 'release-signers' <<<"$OUT" | head -3)"
fi

# The same planted key, and the downloaded copy of the signed manifest
# rewritten to name it. Root checked its own copy, in a directory only root
# can write, and reads nothing from the download afterwards (L1, #736).
TAMPER_DOWNLOAD=1 signed_update_tampered
if [[ ! -s "$TMP/state/tampered" ]] && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/test-signers" \
   && grep -qF 'release-signers was NOT refreshed: scripts/release-signers in the tree is not the file this release shipped' <<<"$OUT"; then
  ok "there is no operator download of the signed files to rewrite: root fetched its own, and the planted key is still refused"
else
  bad "the downloaded manifest is never read after the check" \
      "tampered=$(wc -l < "$TMP/state/tampered" 2>/dev/null), $(grep -iE 'release-signers' <<<"$OUT" | head -3)"
fi
rm -f "$TMP/state/tamper-download"

# A build that slips its own key into the tree's release-signers AND into the
# per-file manifest, consistently, while release.json still names the key set
# the Mac holds (which is all the Mac checks). The archive, the manifest and
# the signature are all good; the key set is not the one that was approved.
mkdir -p "$TMP/tarsrc-m1/aperire-one"
cp -r "$TMP/tarsrc/aperire-one/." "$TMP/tarsrc-m1/aperire-one/"
printf 'aperire-release-key namespaces="aperire-release" %s planted\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  >> "$TMP/tarsrc-m1/aperire-one/scripts/release-signers"
tar -czf "$TMP/release-m1.tar.gz" -C "$TMP/tarsrc-m1" aperire-one
M1_SHA="$(sha256sum "$TMP/release-m1.tar.gz" | cut -d' ' -f1)"
sign_release "$TMP/signed-m1" "$M1_SHA" "$TMP/testkey" 2026-09-02T00:00:00Z "$TMP/tarsrc-m1/aperire-one"
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin" "$TMP/lib/aperire"
printf 'the OLD updater\n' > "$TMP/sbin/aperire-update"
cp "$TMP/test-signers" "$TMP/lib/aperire/release-signers"
printf '%s\n' "$TMP/release-m1.tar.gz" > "$TMP/state/tarball"
printf '%s\n' "$TMP/signed-m1" > "$TMP/state/signed-from"
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$M1_SHA"
run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$M1_SHA"
if cmp -s "$TMP/lib/aperire/release-signers" "$TMP/test-signers" \
   && grep -qF 'is not the key set the signed release names' <<<"$OUT"; then
  ok "a key added to the tree and the manifest together is still refused: it is not the key set the signed release names"
else
  bad "a key set that is not the signed one is never installed" \
      "$(grep -c planted "$TMP/lib/aperire/release-signers" 2>/dev/null) planted line(s): $(grep -iE 'release-signers|key set' <<<"$OUT" | head -3)"
fi

# A host that already trusts a key set believes a release only when a key in
# THAT set signed it. Here it trusts somebody else's key, and the release (and
# this script's own built-in key) is the test key: refused before any fetch.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/lib/aperire"
printf 'aperire-release-key namespaces="aperire-release" %s other\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  > "$TMP/lib/aperire/release-signers"
cp "$TMP/lib/aperire/release-signers" "$TMP/installed-before"
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$GOOD_SHA"
if [[ $RC -ne 0 && -z "$(previous_tree)" ]] && grep -qF 'not signed by a key this host already trusts' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null \
   && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/installed-before"; then
  ok "a host refuses a release no key it already trusts signed, whatever key the script carries: a new key set arrives signed by the old one"
else
  bad "a release not signed by the installed key set is refused" "rc=$RC, $(tail -4 <<<"$OUT")"
fi

# ── #759 review: L1, L2, L3 ─────────────────────────────────────────
# L2: root fetches the signed files itself, into its own directory. An
# attacker on the operator's account who swaps a download for a symlink to a
# root file, or for a FIFO, meets nothing: there is no operator download.
signed_run "$TMP/signed"
if [[ $RC -eq 0 ]] && ! grep -q '^signed-fetch operator ' "$TMP/state/curl-calls" \
   && [[ "$(grep -c '^signed-fetch root ' "$TMP/state/curl-calls")" == 3 ]] \
   && [[ -z "$(find "$TMP/tmpd" -maxdepth 1 -name 'aperire-fetch.*' 2>/dev/null)" ]]; then
  ok "root fetches the three signed files itself; nothing passes through a directory the operator's account owns"
else
  bad "the signed files are fetched by root" "rc=$RC $(grep signed-fetch "$TMP/state/curl-calls" 2>/dev/null | head -3)"
fi
mkdir -p "$TMP/plant"
printf 'a root secret\n' > "$TMP/root-secret"
printf '%s\n' "$TMP/root-secret" > "$TMP/plant/link"
signed_run "$TMP/signed"
rm -f "$TMP/plant/link"
if [[ $RC -eq 0 ]] && ! grep -rqs 'a root secret' "$TMP/store"; then
  ok "a symlink to a root file planted where the operator downloads is never followed by root"
else
  bad "a planted symlink is not followed" "rc=$RC: $(grep -rls 'a root secret' "$TMP/store" 2>/dev/null)"
fi
: > "$TMP/plant/fifo"
signed_run "$TMP/signed"
rm -f "$TMP/plant/fifo"
if [[ $RC -eq 0 ]]; then
  ok "and a FIFO planted there is never opened, so the install neither hangs nor fails"
else
  bad "a planted FIFO is not opened" "rc=$RC: $(tail -3 <<<"$OUT")"
fi
: > "$TMP/plant/oversize"
signed_run "$TMP/signed"
rm -f "$TMP/plant/oversize"
if nothing_fetched && grep -qF 'serves no signed release.json' <<<"$OUT" \
   && [[ -z "$(find "$TMP/store" -type f -size +8M 2>/dev/null)" ]]; then
  ok "a signed file over the size cap is refused and removed, and nothing is fetched"
else
  bad "an oversize signed file is refused" "rc=$RC: $(tail -3 <<<"$OUT")"
fi

# L1: a release key set that is there and is not one this script accepts is
# a refusal, never "none", so the checks that need it cannot be skipped by
# breaking the file. Reproduced first: the old reading ignored it and
# installed whatever the script carried.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/lib/aperire"
printf 'release@example.org namespaces="aperire-release" %s broken\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" \
  > "$TMP/lib/aperire/release-signers"
cp "$TMP/lib/aperire/release-signers" "$TMP/installed-before"
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
printf '%s\n' "$TMP/signed" > "$TMP/state/signed-from"
run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$GOOD_SHA"
if [[ $RC -ne 0 ]] && grep -qF 'is there but is not a release key set this script accepts' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null \
   && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/installed-before"; then
  ok "a host whose installed release key set is broken refuses the update, never reads it as no key, and keeps the file"
else
  bad "a broken installed set is a refusal" "rc=$RC: $(tail -4 <<<"$OUT")"
fi

# L3: the newest publish date this host has installed is kept apart from the
# store, so a kept release that went missing does not switch the downgrade
# check off; and a different archive with the SAME date is refused too.
older_than_kept() { # $1 = published_at for a re-signed GOOD archive, $2 = high-water date, $3 = remove the kept release?
  reset
  make_installed_host
  stamp_an_older_release
  mkdir -p "$TMP/lib/aperire" "$TMP/store"
  cp "$TMP/test-signers" "$TMP/lib/aperire/release-signers"
  printf '%s\n' "$2" > "$TMP/store/high-water"; chmod 0644 "$TMP/store/high-water"
  if [[ "$3" != remove ]]; then
    local kept; kept="$(printf 'c%.0s' {1..64})"
    mkdir -p "$TMP/store/$kept"
    printf '{\n  "sha256": "%s",\n  "published_at": "%s"\n}\n' "$kept" "$2" > "$TMP/store/$kept/release.json"
    ssh-keygen -q -Y sign -f "$TMP/testkey" -n aperire-release "$TMP/store/$kept/release.json" </dev/null
    printf '%s\n' "$kept" > "$TMP/store/current"
  fi
  rm -rf "$TMP/signed-l3"
  sign_release "$TMP/signed-l3" "$GOOD_SHA" "$TMP/testkey" "$1"
  SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
  printf '%s\n' "$TMP/signed-l3" > "$TMP/state/signed-from"
  run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$GOOD_SHA"
}
older_than_kept 2026-09-01T00:00:00Z 2026-09-05T00:00:00Z remove
if [[ $RC -ne 0 ]] && grep -qF 'no later than the newest this host has installed (2026-09-05T00:00:00Z)' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "with the kept release gone, the high-water date still refuses an older release before anything is fetched"
else
  bad "the high-water date holds without a kept release" "rc=$RC: $(tail -4 <<<"$OUT")"
fi
older_than_kept 2026-09-05T00:00:00Z 2026-09-05T00:00:00Z keep
if [[ $RC -ne 0 ]] && grep -qF 'no later than the newest this host has installed' <<<"$OUT"; then
  ok "a different archive published at the same moment as the one installed is refused, not let through on a tie"
else
  bad "an equal publish date is refused" "rc=$RC: $(tail -4 <<<"$OUT")"
fi
rot_hw() { cat "$TMP/store/high-water" 2>/dev/null; }
reset
signed_run "$TMP/signed"
if [[ $RC -eq 0 && "$(rot_hw)" == 2026-09-01T00:00:00Z ]] \
   && [[ "$(stat -c %a "$TMP/store/high-water")" == 644 ]]; then
  ok "an install records the release's publish date as this host's high-water mark"
else
  bad "the high-water mark is written" "rc=$RC hw=$(rot_hw)"
fi
rm -f "$TMP/state/signed-from"

# ── The key changes, in two signed steps, end to end ────────────────
#
# K1 is the test key, K2 "somebody else". A host that trusts {K1}:
#   phase 1  K1 signs a release whose set is {K1, K2}  -> the host trusts both
#   phase 2  K2 signs a release whose set is {K2}      -> the host trusts K2
# A host that skipped phase 1 refuses phase 2, and K1 signing a release that
# swaps {K1} for {K2} in one step is refused too. Each release carries its
# set in the tree, in the bootstrap's built-in block and in signers_sha256,
# the way the builder and the publisher make one.
printf 'aperire-release-key namespaces="aperire-release" %s k2\n' "$(cut -d' ' -f1,2 "$TMP/otherkey.pub")" > "$TMP/set-2"
cat "$TMP/test-signers" "$TMP/set-2" > "$TMP/set-12"
rot_release() { # $1 = name, $2 = signer set, $3 = signing key, $4 = published_at; sets ROT_SHA
  local n="$1"
  rm -rf "$TMP/tarsrc-$n"; mkdir -p "$TMP/tarsrc-$n/aperire-one"
  cp -r "$TMP/tarsrc/aperire-one/." "$TMP/tarsrc-$n/aperire-one/"
  cp "$2" "$TMP/tarsrc-$n/aperire-one/scripts/release-signers"
  tar -czf "$TMP/release-$n.tar.gz" -C "$TMP/tarsrc-$n" aperire-one
  ROT_SHA="$(sha256sum "$TMP/release-$n.tar.gz" | cut -d' ' -f1)"
  rm -rf "$TMP/signed-$n"
  sign_release "$TMP/signed-$n" "$ROT_SHA" "$3" "$4" "$TMP/tarsrc-$n/aperire-one" "$2"
  awk -v body="RELEASE_SIGNERS='$(cat "$2")'" '
    $0 == "# >>> release signers >>>" { print; print body; skip = 1; next }
    $0 == "# <<< release signers <<<" { skip = 0 }
    skip { next }
    { print }' "$PUBLISHED_COPY" > "$TMP/boot-$n.sh"
}
rot_host() { # a host on an older release that trusts $1
  reset
  make_installed_host
  stamp_an_older_release
  mkdir -p "$TMP/sbin" "$TMP/lib/aperire"
  printf 'the OLD updater\n' > "$TMP/sbin/aperire-update"
  cp "$1" "$TMP/lib/aperire/release-signers"
  cp "$REPO_DIR/scripts/release-verify-lib.sh" "$TMP/lib/aperire/release-verify-lib.sh"
}
rot_update() { # $1 = name; the release rot_release made under it
  SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
  SHA_FOR_RUN="$(sha256sum "$TMP/release-$1.tar.gz" | cut -d' ' -f1)"
  printf '%s\n' "$TMP/release-$1.tar.gz" > "$TMP/state/tarball"
  printf '%s\n' "$TMP/signed-$1" > "$TMP/state/signed-from"
  run_file "$TMP/boot-$1.sh" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$SHA_FOR_RUN"
}
rot_release p1 "$TMP/set-12" "$TMP/testkey" 2026-09-02T00:00:00Z; P1_SHA="$ROT_SHA"
rot_release p2 "$TMP/set-2" "$TMP/otherkey" 2026-09-03T00:00:00Z
rot_release swap "$TMP/set-2" "$TMP/testkey" 2026-09-02T00:00:00Z

rot_host "$TMP/test-signers"
rot_update p1
P1_RC=$RC
P1_SET_OK=0; cmp -s "$TMP/lib/aperire/release-signers" "$TMP/set-12" && P1_SET_OK=1
if [[ $P1_RC -eq 0 && $P1_SET_OK -eq 1 ]]; then
  ok "rotation, phase 1: a release signed by the old key that names both keys is installed, and the host trusts both"
else
  bad "phase 1 of a key change is accepted" "rc=$P1_RC set_ok=$P1_SET_OK: $(grep -iE 'release key|release-signers|refused|rotation' <<<"$OUT" | head -4)"
fi
# The join with the release digests (ADR 0024): the record root checks every
# later root copy against is the signed file list, and it says so.
REC="$TMP/lib/aperire/release.sha256"
if grep -q "^# anchor signed release.json for sha256 $P1_SHA, release key SHA256:" "$REC" 2>/dev/null \
   && grep -q "^# key $P1_SHA\$" "$REC" \
   && grep -qx '# body: the signed release.files, which the archive matched entry for entry' "$REC" \
   && cmp -s <(grep -E '^[0-9a-f]{64}  ' "$REC" | LC_ALL=C sort) <(LC_ALL=C sort "$TMP/signed-p1/release-$P1_SHA.files"); then
  ok "the release digests root records are the signed file list, anchored to the signature and the key's fingerprint"
else
  bad "the release digests come from the signed file list" "$(head -6 "$REC" 2>/dev/null)"
fi
rot_update p2
if [[ $RC -eq 0 ]] && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/set-2"; then
  ok "rotation, phase 2: the new key signs a release naming only itself, and the host now trusts the new key alone"
else
  bad "phase 2 of a key change is accepted after phase 1" "rc=$RC: $(grep -iE 'release key|release-signers|refused|rotation' <<<"$OUT" | head -4)"
fi

rot_host "$TMP/test-signers"
rot_update p2
if [[ $RC -ne 0 ]] && grep -qF 'not signed by a key this host already trusts' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null \
   && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/test-signers"; then
  ok "a host that skipped phase 1 refuses phase 2 before fetching anything, and keeps the key it had"
else
  bad "phase 2 without phase 1 is refused" "rc=$RC: $(tail -4 <<<"$OUT")"
fi

# K1 signing a release that swaps {K1} for {K2} in one step: the release's
# own set does not hold the key that signed it, so it is refused at the first
# check, before anything is fetched.
rot_host "$TMP/test-signers"
rot_update swap
if [[ $RC -ne 0 ]] && grep -qF 'is not signed by the release key' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null \
   && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/test-signers"; then
  ok "the old key signing a release that swaps the whole set at once is refused before anything is fetched"
else
  bad "a one-step key swap is refused" "rc=$RC: $(tail -4 <<<"$OUT")"
fi
# Mid-rotation, the host trusts {K1, K2}. K2 signs a release naming {K2, K3}:
# signed by a key the host trusts and by a key in its own set, so only the
# one-step rule stands in its way.
ssh-keygen -q -t ed25519 -N '' -C 'a-third-key' -f "$TMP/thirdkey" </dev/null
{ cat "$TMP/set-2"; printf 'aperire-release-key namespaces="aperire-release" %s k3\n' "$(cut -d' ' -f1,2 "$TMP/thirdkey.pub")"; } > "$TMP/set-23"
rot_release pairswap "$TMP/set-23" "$TMP/otherkey" 2026-09-03T00:00:00Z
rot_host "$TMP/set-12"
rot_update pairswap
if [[ $RC -ne 0 ]] && grep -qF 'by more than one rotation step' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null \
   && cmp -s "$TMP/lib/aperire/release-signers" "$TMP/set-12"; then
  ok "mid-rotation, a release that swaps one key of the pair for a third is refused before anything is fetched"
else
  bad "a pair swapping one of its keys is refused" "rc=$RC: $(tail -4 <<<"$OUT")"
fi
rm -f "$TMP/state/signed-from"

# The two root programs. They run out of /usr/local/sbin, a tree swap does not
# touch them, and the host then runs a program from the release before this
# one. That is #185, met live: an arm token refused by a sealer whose source
# was current and whose installed copy was not.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)" == "the NEW sealer" ]] \
   && grep -q 'refreshed from the new tree' <<<"$OUT"; then
  ok "a root program already on the host is refreshed from the new tree, and said on screen"
else
  bad "the root programs are refreshed from the new tree" \
      "sealer=$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)"
fi
# The control, and the line between refreshing a grant and adding one: the
# trust sync was not on this host, and an update does not install root
# programs nobody asked it for.
if [[ ! -e "$TMP/sbin/aperire-trust-sync" ]]; then
  ok "and one that was never installed here is not installed by an update"
else
  bad "an absent root program stays absent" "$(ls "$TMP/sbin")"
fi

# The state helper (#703), which is not a grant but a DEPENDENCY of two of
# them: the sealer and the credential check both write advisor/state through
# it and resolve it from beside themselves. So it follows a different rule
# from the loop above, and the difference is the point. "Only refresh what is
# already there" is right for a grant, because installing one nobody asked
# for widens what root will do. It is wrong for a dependency: a host carrying
# a sealer from an older release has no helper yet, and leaving it that way
# is a sealer that refuses every seal after this update.
if [[ "$(cat "$TMP/sbin/aperire-state-file" 2>/dev/null)" == "the NEW state helper" ]] \
   && grep -q -e "$TMP/sbin/aperire-state-file refreshed from the new tree" <<<"$OUT"; then
  ok "the state helper is placed for a host that has the sealer but no helper yet"
else
  bad "the state helper is placed beside the sealer on an update" \
      "helper=$(cat "$TMP/sbin/aperire-state-file" 2>/dev/null)"
fi

# The method library travels on exactly the same rule (#708), and for a
# sharper reason: without it the sealer refuses every seal and the credential
# check refuses to judge anything, on every host, 24.04 included.
if [[ "$(cat "$TMP/sbin/aperire-model-key-method" 2>/dev/null)" == "the NEW key method library" ]] \
   && grep -q -e "$TMP/sbin/aperire-model-key-method refreshed from the new tree" <<<"$OUT"; then
  ok "the key method library is placed beside the sealer on the same update"
else
  bad "the key method library is placed beside the sealer" \
      "library=$(cat "$TMP/sbin/aperire-model-key-method" 2>/dev/null)"
fi

# And its own control: a host with neither program gets neither. The helper is
# a dependency of two things, not something an update leaves on every box.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/sbin/aperire-state-file" && ! -e "$TMP/sbin/aperire-model-key-method" ]]; then
  ok "and a host with neither the sealer nor the credential check gets neither helper"
else
  bad "the helpers follow the two programs that use them" "$(ls "$TMP/sbin")"
fi

# The other half of that rule: the credential check alone is enough, because
# it writes its attribution note through the helper on the run where a model
# credential has just gone.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
printf 'the OLD credcheck\n' > "$TMP/sbin/aperire-advisord-credcheck"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/sbin/aperire-state-file" 2>/dev/null)" == "the NEW state helper" ]]; then
  ok "the credential check on its own is enough to bring the helper along"
else
  bad "the credential check alone brings the helper" \
      "helper=$(cat "$TMP/sbin/aperire-state-file" 2>/dev/null)"
fi

# The node wrapper (ADR 0024, and the #756 review's M1). An updated host is
# not a reinstalled one: its sudo rule and its Advisor unit still name the
# tree's wrapper. The update places the root-owned copy and points the unit
# at it, and restarts nothing. Converting the unit to the root socket (ADR
# 0025) is the library's, tested row by row in test-trusted-path-lib.sh; what
# this suite holds is the one guard the update path adds around it: a tree
# whose advisord binary predates the socket flag is never handed it.
wrapper_host() { # the shape of every host updated from before this release
  mkdir -p "$TMP/sbin" "$TMP/etc/aperire" "$TMP/etc/sudoers.d" "$TMP/etc/systemd/system"
  printf 'KIND=container\nSERVICE=xrpldstock\n' > "$TMP/etc/aperire/node-wrapper.conf"
  printf 'aperire-advisor ALL=(root) NOPASSWD: %s\nDefaults:aperire-advisor !requiretty\n' \
    "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" > "$TMP/etc/sudoers.d/aperire-advisor"
  printf '[Service]\nUser=aperire-advisor\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s --sudo-wrapper\n' \
    "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
    > "$TMP/etc/systemd/system/aperire-advisord.service"
}
reset
make_installed_host
stamp_an_older_release
wrapper_host
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
RULE_NOW="$(sed -n 's/.*NOPASSWD:[[:space:]]*//p' "$TMP/etc/sudoers.d/aperire-advisor" 2>/dev/null)"
if [[ $RC -eq 0 && "$RULE_NOW" == "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" ]] \
   && grep -q 'the NEW wrapper' "$TMP/sbin/aperire-node-wrapper" 2>/dev/null \
   && grep -q -- "--wrapper=$TMP/sbin/aperire-node-wrapper --sudo-wrapper" "$TMP/etc/systemd/system/aperire-advisord.service" \
   && [[ "$OUT" == *"predates the wrapper socket"* ]]; then
  ok "an updated host whose Advisor binary predates the socket: the copy is placed and named, and the unit keeps the rule it runs on"
else
  bad "the update converges the rule and the unit" \
      "rc=$RC rule=$RULE_NOW unit=$(grep ExecStart "$TMP/etc/systemd/system/aperire-advisord.service" 2>&1) $(grep -A8 'the node wrapper' <<<"$OUT")"
fi
if [[ "$(cat "$TMP/lib/aperire/config-write-lib.sh" 2>/dev/null)" == "# the NEW config-write library" ]] \
   && grep -q "the node wrapper: the root-owned copy, and how the Advisor reaches it" <<<"$OUT"; then
  ok "and its library is placed, and the run says so"
else
  bad "the library and the step's line" "$(ls "$TMP/lib/aperire" 2>&1)"
fi

# A refused copy while the rule still grants the tree's file, and a service
# account can write that file: the update finishes and then exits non-zero,
# naming it. Here the Advisor's unit runs as the account that owns the
# tree, so it can rewrite the file its own rule grants.
reset
make_installed_host
stamp_an_older_release
wrapper_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
cat > "$TMP/etc/systemd/system/aperire-advisord.service" <<UNIT
[Service]
User=$(id -un)
ExecStart=$TMP/op/aperire-one/advisor/bin/aperire-advisord --wrapper=$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh --sudo-wrapper
UNIT
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
before_rule="$(cat "$TMP/etc/sudoers.d/aperire-advisor")"
# The Advisor's account here owns the whole fixture, the directory the
# release record sits in included, so root distrusts the record (#877 review,
# L3), and since #764 the update stops before anything of the release runs
# as root: install.sh never runs and the rule is never touched.
if [[ $RC -ne 0 && "$before_rule" == *"$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh"* \
      && ! -s "$TMP/state/install-self" ]] \
   && { [[ "$OUT" == *"root would not run the installers in"* ]] \
        || [[ "$OUT" == *"sit where a service account can change them"* ]]; }; then
  ok "a tree the Advisor's account can write fails the update before root runs anything from it, loudly"
else
  bad "the refusal fails the update" "rc=$RC: $(grep -iE 'refused|writable|error' <<<"$OUT" | head -8)"
fi

# A host whose Advisor build reaches the node only through its socket, and
# the socket never comes up: the next restart cuts it off from the node. The
# update finishes and then fails, loudly, naming it (ADR 0025). The broker is
# placed through the root shell's own release-digests functions, never a
# second read of the tree, and the library it ran is the staged copy.
reset
make_installed_host
stamp_an_older_release
wrapper_host
mkdir -p "$TMP/advbin"
printf 'ELF ... --wrapper-socket ...\n' > "$TMP/advbin/aperire-advisord"
sed -i "s#^ExecStart=[^ ]*#ExecStart=$TMP/advbin/aperire-advisord#" "$TMP/etc/systemd/system/aperire-advisord.service"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && "$OUT" == *"STRANDED: aperire-advisord runs a build that reaches the node only"* \
      && "$OUT" == *"its root socket, and that socket is not working"* ]] \
   && grep -q -- '--sudo-wrapper' "$TMP/etc/systemd/system/aperire-advisord.service" \
   && [[ -f "$TMP/etc/sudoers.d/aperire-advisor" ]]; then
  ok "a socket-only Advisor whose socket does not come up fails the update, loudly, with its unit and rule untouched"
else
  bad "a stranded Advisor fails the update" "rc=$RC: $(grep -A12 'the node wrapper' <<<"$OUT" | head -30)"
fi
if cmp -s "$TMP/op/aperire-one/scripts/aperire-wrapper-broker.py" "$TMP/sbin/aperire-wrapper-broker" \
   && [[ "$OUT" == *"aperire-wrapper-broker placed: checked against the release"* ]]; then
  ok "and the broker it placed was checked against the release's digests, as root's copy"
else
  bad "the broker goes through the release digests" "$(ls "$TMP/sbin"): $(grep -i broker <<<"$OUT" | head -5)"
fi

# An Advisor on the retired shared account: the dashboard's own. The update
# may not move it (install-advisor-account.sh restarts two services and plants
# a reveal window), and a run nobody is at, which is how the dashboard's own
# update socket runs this (--yes, no terminal), must never do it (#641). It
# says so and names the one command.
reset
make_installed_host
stamp_an_older_release
wrapper_host
rm -f "$TMP/etc/sudoers.d/aperire-advisor"
printf '[Service]\nUser=op\n' > "$TMP/etc/systemd/system/aperire-server.service"
printf '[Service]\nUser=%s\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s\n' "${SHARED_ACCT:-op}" \
  "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
  > "$TMP/etc/systemd/system/aperire-advisord.service"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 && "$OUT" == *"shared account: it runs as op, the dashboard's account"* \
      && "$OUT" == *"Nobody is here to agree to that restart, so it was not moved"* \
      && "$OUT" == *"When you are ready:"*"get.aperire.one"*"| bash -s -- --update --force"* \
      && "$OUT" != *"get.aperire.one/advisor"* ]] \
   && ! grep -qE 'install-advisor-account' "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "a shared-account Advisor is named and the move offered, and a run nobody is at never runs it (#641)"
else
  bad "the shared-account move is never run unattended" "rc=$RC: $(grep -iE 'shared|move|agree|install-advisor-account' <<<"$OUT" | head -8) $(grep advisor "$TMP/state/sudo-exec" 2>/dev/null)"
fi

# The same host with an operator at the terminal who accepts the move. The
# account installer runs as root, so it runs from a checked copy: it and every
# file it loads or runs staged out of the tree into a directory only root can
# write, matched against the release's digests, and pointed at this tree
# (#779 review, L1). The tree's own copy is never what root runs.
reset
make_installed_host
stamp_an_older_release
wrapper_host
rm -f "$TMP/etc/sudoers.d/aperire-advisor"
printf '[Service]\nUser=%s\n' "${SHARED_ACCT:-op}" > "$TMP/etc/systemd/system/aperire-server.service"
printf '[Service]\nUser=%s\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s\n' "${SHARED_ACCT:-op}" \
  "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
  > "$TMP/etc/systemd/system/aperire-advisord.service"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_tty_file "$PUBLISHED_COPY" $'y\nn\ny\n' --update
moved="$(grep 'install-advisor-account.sh' "$TMP/state/sudo-exec" 2>/dev/null)"
if [[ "$moved" == *"APERIRE_INSTALL_TREE=$TMP/op/aperire-one"*"/account-move/install-advisor-account.sh"* \
      && "$moved" != *"bash $TMP/op/aperire-one/scripts/install-advisor-account.sh"* ]]; then
  ok "an accepted move runs a checked, staged copy of the account installer, never the tree's"
else
  bad "the account move runs from a checked copy" "rc=$RC sudo-exec: $moved :: $(tail -40 <<<"$OUT")"
fi

# An unnamed dashboard and an Advisor of a named instance on a shared account
# (#946). The staged move acts on the default instance, so offering it for
# the instance would move the wrong unit, account and state. The update names
# the instance and runs nothing, even when the operator is at the terminal and
# says yes.
reset
make_installed_host
stamp_an_older_release
wrapper_host
rm -f "$TMP/etc/sudoers.d/aperire-advisor" "$TMP/etc/systemd/system/aperire-advisord.service"
printf '[Service]\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s\n' \
  "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
  > "$TMP/etc/systemd/system/aperire-advisord-lab.service"
: > "$TMP/state/sudo-env-reset"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_tty_file "$PUBLISHED_COPY" $'y\ny\ny\n' --update
if [[ "$OUT" == *"The Advisor of instance lab runs on a shared account"* \
      && "$OUT" != *"Move it now?"* && "$OUT" != *"@move-needed"* ]] \
   && ! grep -qE 'install-advisor-account' "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "an instanced shared-account Advisor is named and never moved by the default instance's move (#946)"
else
  bad "the move is not run for an instanced Advisor" "rc=$RC $(grep -iE 'instance|shared|move' <<<"$OUT" | head -8) $(grep advisor "$TMP/state/sudo-exec" 2>/dev/null)"
fi

if [[ "$OUT" != *"is offered below, after the restart"* && "$OUT" == *"the node wrapper step above name the command"* ]]; then
  ok "and with only a named instance on a shared account, the update does not promise an offer it will not make (#946)"
else
  bad "no false 'offered below' for a named instance" "$(grep -iE 'offered below|node wrapper step' <<<"$OUT" | head -4)"
fi

# A staged library that names no instance (older than the marker): rc 7 with
# no marker. The default Advisor is not offered the move, so the update warns
# and prints the command rather than dropping it.
reset
make_installed_host
stamp_an_older_release
wrapper_host
rm -f "$TMP/etc/sudoers.d/aperire-advisor"
printf '[Service]\nUser=%s\n' "${SHARED_ACCT:-op}" > "$TMP/etc/systemd/system/aperire-server.service"
printf '[Service]\nUser=%s\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s\n' "${SHARED_ACCT:-op}" \
  "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
  > "$TMP/etc/systemd/system/aperire-advisord.service"
: > "$TMP/state/sudo-no-markers"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_tty_file "$PUBLISHED_COPY" $'y\ny\ny\n' --update
if [[ "$OUT" == *"did not say which, so the move is not offered here"* \
      && "$OUT" == *"to move it: curl -fsSL"*"| bash -s -- --update --force"* \
      && "$OUT" != *"is offered below, after the restart"* ]] \
   && ! grep -qE 'install-advisor-account' "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "a shared-account Advisor reported with no instance is warned about and given the command, not dropped (#946)"
else
  bad "rc 7 with no marker warns and prints the move" "$(grep -iE 'shared|move|offered' <<<"$OUT" | head -6)"
fi

# Both at once: the default instance's Advisor is offered the move, which acts
# on the default instance with no instance named, and the instance is named as
# left alone.
reset
make_installed_host
stamp_an_older_release
wrapper_host
rm -f "$TMP/etc/sudoers.d/aperire-advisor"
printf '[Service]\nUser=%s\n' "${SHARED_ACCT:-op}" > "$TMP/etc/systemd/system/aperire-server.service"
printf '[Service]\nUser=%s\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s\n' "${SHARED_ACCT:-op}" \
  "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
  > "$TMP/etc/systemd/system/aperire-advisord.service"
printf '[Service]\nExecStart=%s/advisor/bin/aperire-advisord --wrapper=%s\n' \
  "$TMP/op/aperire-one" "$TMP/op/aperire-one/scripts/aperire-node-wrapper.sh" \
  > "$TMP/etc/systemd/system/aperire-advisord-lab.service"
: > "$TMP/state/sudo-env-reset"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_tty_file "$PUBLISHED_COPY" $'y\ny\ny\n' --update
moved="$(grep 'install-advisor-account.sh' "$TMP/state/sudo-exec" 2>/dev/null)"
if [[ "$OUT" == *"The Advisor of instance lab runs on a shared account"* \
      && "$moved" == *"/account-move/install-advisor-account.sh"* && "$moved" != *"APERIRE_INSTANCE=lab"* \
      && "$(grep -c 'bash .*/account-move/install-advisor-account.sh' <<<"$moved")" -eq 1 ]]; then
  ok "with both on a shared account, the move runs once for the default instance and the named one is left alone (#946)"
else
  bad "the default move runs once and the instance is named" "rc=$RC sudo-exec: $moved :: $(grep -iE 'instance|shared|move' <<<"$OUT" | head -8)"
fi

reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/sbin/aperire-node-wrapper" && ! -e "$TMP/lib/aperire/config-write-lib.sh" ]]; then
  ok "and a host with no wrapper at all gets neither"
else
  bad "no wrapper, nothing placed" "$(ls "$TMP/sbin" "$TMP/lib/aperire" 2>&1)"
fi

# The xrpld image recipe on a container node (#675). An update used to run
# the recipe installer in --refresh-only, always, and that mode writes
# nothing on a host with no copy, so the recipe landed only where it
# already was. Every container node installed before it shipped had a card
# showing every precondition green and a run that refused at the build
# step, after the operator had approved. Prod is one of those hosts.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=container\nSERVICE=xrpldstock\nREPO=xrpllabsofficial/xrpld\n' \
  > "$TMP/etc/aperire/node-wrapper.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/lib/aperire/build-xrpld-image.sh" 2>/dev/null)" == "the NEW build script" ]] \
   && [[ "$(cat "$TMP/lib/aperire/xrpld-image/entrypoint.sh" 2>/dev/null)" == "the NEW entrypoint" ]] \
   && [[ "$(cat "$TMP/lib/aperire/xrpld-image/signed-binary-sha256.sh" 2>/dev/null)" == "the NEW signed hash" ]]; then
  ok "an update places all four recipe files on a container node that has none"
else
  bad "the image recipe is placed on a container node" \
      "$(ls -R "$TMP/lib" 2>/dev/null): $OUT"
fi
if grep -q 'xrpld image recipe' <<<"$OUT" && grep -q 'all four files match the release as it arrived' <<<"$OUT"; then
  ok "and says so on screen, having checked each one against the release"
else
  bad "the update says it placed the recipe and checked it" "$OUT"
fi
if [[ ! -s "$TMP/state/recipe-calls" ]]; then
  ok "and root never ran the tree's own recipe installer to do it"
else
  bad "the tree's recipe installer is not run as root" "$(cat "$TMP/state/recipe-calls")"
fi
if grep -q 'checked before anything ran in the tree' <<<"$OUT"; then
  ok "and a clean run says what the check actually proves"
else
  bad "the success line says what it proves" "$OUT"
fi

# ── what root RUNS out of the release (#764) ──────────────────────
# Root runs a copy of install.sh it staged out of the release, each file
# read once and held to the release's digests and the trusted-path check,
# never the tree's own file, and names the tree it installs.
echo
echo "What root runs out of the release (#764):"
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
SELF_RAN="$(head -1 "$TMP/state/install-self" 2>/dev/null)"
if [[ $RC -eq 0 && "$SELF_RAN" == */run/install.sh && "$SELF_RAN" != "$TMP/op/aperire-one/"* \
      && "$(head -1 "$TMP/state/install-tree" 2>/dev/null)" == "$TMP/op/aperire-one" ]]; then
  ok "an update runs a staged copy of install.sh, not the tree's, and names the tree it installs"
else
  bad "root runs the staged install.sh" "rc=$RC self=$SELF_RAN tree=$(cat "$TMP/state/install-tree" 2>/dev/null)"
fi

# The swap itself: install.sh in the tree rewritten after the unpack, at the
# last moment before root stages it. It is refused on its digest, nothing
# of the release runs as root, and the run ends non-zero with the remedy.
reset
make_installed_host
stamp_an_older_release
printf 'install.sh\n' > "$TMP/state/tamper-before-stage"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && ! -e "$TMP/state/TREE-RAN" && ! -s "$TMP/state/install-self" ]] \
   && grep -q 'refused: install.sh is not the file this release shipped' <<<"$OUT" \
   && grep -q 'root would not run the installers in' <<<"$OUT" \
   && grep -q 'before the release was moved into place, so nothing on' <<<"$OUT" \
   && ! compgen -G "$TMP/op/aperire-one.previous-*" >/dev/null \
   && grep -q -- '--update --force' <<<"$OUT"; then
  ok "an install.sh swapped in the release before the stage is never run by root, and the update stops before the tree is replaced"
else
  bad "a swapped install.sh is never run by root" "rc=$RC ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null) $(grep -iE 'refused|error' <<<"$OUT" | head -5)"
fi
# A sub-installer swapped the same way: the whole set is refused, so root
# does not run install.sh either, which would have run that file.
reset
make_installed_host
stamp_an_older_release
printf 'scripts/prepare-host.sh\n' > "$TMP/state/tamper-before-stage"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && ! -e "$TMP/state/TREE-RAN" && ! -s "$TMP/state/install-self" ]] \
   && grep -q 'refused: scripts/prepare-host.sh is not the file this release shipped' <<<"$OUT"; then
  ok "a swapped sub-installer refuses the whole set: root runs no installer out of that tree"
else
  bad "a swapped sub-installer stops the stage" "rc=$RC ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null) $(grep -iE 'refused|error' <<<"$OUT" | head -5)"
fi
# And a first install takes the same path: the staged copy, the tree named.
reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --role=dashboard --yes
SELF_RAN="$(head -1 "$TMP/state/install-self" 2>/dev/null)"
if [[ -n "$SELF_RAN" && "$SELF_RAN" == */run/install.sh && "$SELF_RAN" != "$TMP/op/aperire-one/"* \
      && "$(head -1 "$TMP/state/install-tree" 2>/dev/null)" == "$TMP/op/aperire-one" ]]; then
  ok "a first install runs the staged install.sh too, and names the tree"
else
  bad "a first install runs the staged install.sh" "rc=$RC self=$SELF_RAN $(tail -5 <<<"$OUT")"
fi
# A refusal an installer makes is written to the run's refusal file, and the
# update ends non-zero listing it rather than finishing green (install.sh's
# exit 4).
reset
make_installed_host
stamp_an_older_release
cat > "$TMP/state/install-refuses" <<'REF'
/usr/local/sbin/aperire-update (from scripts/aperire-update.sh)
REF
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 ]] && grep -q 'root refused to copy 1 file(s)' <<<"$OUT" \
   && grep -q '/usr/local/sbin/aperire-update (from scripts/aperire-update.sh)' <<<"$OUT" \
   && [[ -s "$TMP/op/aperire-one/.release" ]]; then
  ok "a copy an installer refused fails the update, listed at the end, after the release is stamped"
else
  bad "an installer's refusal fails the update" "rc=$RC $(tail -12 <<<"$OUT")"
fi
if grep -q 'Find out what changed it first' <<<"$OUT" && ! grep -q 'account check could not run' <<<"$OUT"; then
  ok "  and a refusal about a file still gets the changed-tree text, not the account-check text"
else
  bad "a judged refusal keeps its own closing text" "$(tail -30 <<<"$OUT")"
fi
# A copy the account check could not run for (#1089): the installer's refusal
# line carries a tab and "accounts" (rd_note_refused). The closing text names
# the check and the retry, and never says the tree changed: nothing was
# compared with the release.
reset
make_installed_host
stamp_an_older_release
printf '/etc/systemd/system/aperire-can-delete.timer (from scripts/aperire-can-delete.timer)\taccounts\n' > "$TMP/state/install-refuses"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
LC_ALL=C run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 ]] && grep -q 'root refused to copy 1 file(s)' <<<"$OUT" \
   && grep -qF '/etc/systemd/system/aperire-can-delete.timer (from scripts/aperire-can-delete.timer)' <<<"$OUT" \
   && ! grep -q -e "$(printf '\t')accounts" <<<"$OUT" \
   && grep -q 'The account check could not run: systemd did not answer' <<<"$OUT" \
   && grep -q 'Run the update again to' <<<"$OUT" && grep -q -- '--update --force' <<<"$OUT"; then
  ok "a copy the account check could not run for ends the update naming that check and the retry"
else
  bad "the closing text names the account check" "rc=$RC $(tail -20 <<<"$OUT")"
fi
if ! grep -qE 'something changed the tree|Find out what changed it first|not the one this release shipped|swaps the tree|refuses the same way' <<<"$OUT"; then
  ok "  and does not send the operator looking for a changed file"
else
  bad "the account-check refusal does not blame the tree" "$(grep -nE 'changed the tree|what changed it|not the one this release|swaps the tree|refuses the same way' <<<"$OUT")"
fi
# One of each: both texts, each for the files it is about.
reset
make_installed_host
stamp_an_older_release
printf '/usr/local/sbin/aperire-update (from scripts/aperire-update.sh)\n/etc/systemd/system/aperire-can-delete.timer (from scripts/aperire-can-delete.timer)\taccounts\n' > "$TMP/state/install-refuses"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
LC_ALL=C run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 ]] && grep -q 'root refused to copy 2 file(s)' <<<"$OUT" \
   && grep -q 'Find out what changed it first' <<<"$OUT" \
   && grep -q 'The account check could not run for 1 of them' <<<"$OUT"; then
  ok "  with one of each, both texts are said, each for the files it is about"
else
  bad "a mixed list gets both texts" "rc=$RC $(tail -30 <<<"$OUT")"
fi
# The update's refresh steps on status 6 do not claim the tree is clean: nothing
# was compared, so a tree that changed during a reload is not told as untouched.
if ! grep -q 'Nothing changed the tree' "$REPO_DIR/scripts/get-aperire.sh" \
   && grep -q "copy is still in place. Nothing about the file was judged." "$REPO_DIR/scripts/get-aperire.sh"; then
  ok "  and the refresh step for an account-check refusal says the file was not judged, never that the tree is unchanged"
else
  bad "the refresh step's status 6 text is true" "$(grep -n 'Nothing changed the tree' "$REPO_DIR/scripts/get-aperire.sh")"
fi

# Kept trees past the record window (#958). Root keeps release digests for the
# newest 8 updates, and an update used to keep every tree it moved aside for
# ever, so most of them could never be rolled back to and the disk grew with
# every update. The newest 8 stay; older ones go, counted. Eleven old trees
# beside the checkout, the oldest of which still holds a database that never
# moved out, a link under a kept name, and the checkout itself: after an update
# the running tree and the link are untouched, the three plain old trees past
# the window are removed, and the one holding data is kept and named.
reset
make_installed_host
stamp_an_older_release
for n in 01 02 03 04 05 06 07 08 09 10 11; do
  mkdir -p "$TMP/op/aperire-one.previous-202601${n}T000000Z/dashboard"
  printf 'old code\n' > "$TMP/op/aperire-one.previous-202601${n}T000000Z/dashboard/x"
done
mkdir -p "$TMP/op/aperire-one.previous-20260101T000000Z/data"
printf 'a database that never moved\n' > "$TMP/op/aperire-one.previous-20260101T000000Z/data/aperire.db"
mkdir -p "$TMP/linktarget"; printf 'not a kept tree\n' > "$TMP/linktarget/keep"
ln -s "$TMP/linktarget" "$TMP/op/aperire-one.previous-20251231T000000Z"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
gone_ok=1; for n in 02 03 04; do [[ -e "$TMP/op/aperire-one.previous-202601${n}T000000Z" ]] && gone_ok=0; done
stay_ok=1; for n in 01 05 06 07 08 09 10 11; do [[ -d "$TMP/op/aperire-one.previous-202601${n}T000000Z" ]] || stay_ok=0; done
kept_count="$(find "$TMP/op" -maxdepth 1 -type d -name 'aperire-one.previous-*' | wc -l)"
if [[ $RC -eq 0 && $gone_ok -eq 1 && $stay_ok -eq 1 && "$kept_count" -eq 9 ]] \
   && grep -q 'removed 3 kept tree(s) older than the newest 8' <<<"$OUT"; then
  ok "an update keeps the newest 8 kept trees and removes the older ones, saying how many"
else
  bad "kept trees past the record window are pruned (#958)" "rc=$RC gone=$gone_ok stay=$stay_ok kept=$kept_count: $(grep -iE 'kept tree|removed' <<<"$OUT" | head -5)"
fi
if [[ -f "$TMP/op/aperire-one.previous-20260101T000000Z/data/aperire.db" ]] \
   && grep -q "previous-20260101T000000Z: it still holds files that were meant to move out of it" <<<"$OUT"; then
  ok "  a kept tree that still holds a database is left, and named"
else
  bad "a kept tree holding data is never pruned" "$(grep -n 'previous-20260101' <<<"$OUT" | head -3)"
fi
if [[ -L "$TMP/op/aperire-one.previous-20251231T000000Z" && -f "$TMP/linktarget/keep" \
      && -d "$TMP/op/aperire-one/dashboard" ]]; then
  ok "  and the running tree and a link under a kept name are untouched"
else
  bad "the running tree and a link are never pruned" "$(find "$TMP/op" -maxdepth 1 -printf '%M %f\n' | head -20)"
fi
if grep -q 'keeps the newest 8 such trees' <<<"$OUT" || grep -q 'An update keeps the newest 8 such trees' <<<"$OUT"; then
  ok "  and the closing text says what is kept and which one a rollback returns to"
else
  bad "the closing text names the kept trees" "$(grep -n -A4 'earlier checkout' <<<"$OUT" | head -12)"
fi

# The tree root's pointer names is never pruned, whatever its age: the function
# alone, with the pointer aimed at the ninth-newest tree.
reset
mkdir -p "$TMP/op/aperire-one"
for n in 01 02 03 04 05 06 07 08 09 10; do mkdir -p "$TMP/op/aperire-one.previous-202601${n}T000000Z/dashboard"; done
printf '%s %s\n' "$(stat -c '%d:%i' "$TMP/op/aperire-one.previous-20260102T000000Z")" "$(printf 'a%.0s' {1..64})" > "$TMP/pointer.previous"
# shellcheck disable=SC2016  # the inner shell's own variables
OUT="$(env PATH="$PATH" DIR="$TMP/op/aperire-one" OP_USER="$(id -un)" RD_DIGESTS="$TMP/pointer" GET="$SUT_REPO" bash -c '
  warn() { echo "WARN $*"; }; info() { echo "INFO $*"; }; step() { echo "STEP $*"; }
  as_operator() { "$@"; }
  checkout_holds_operator_files() { return 1; }
  eval "$(sed -n "/^prune_kept_trees() {/,/^}/p" "$GET")"
  KEPT_TREES_MAX=8 KEPT_PREVIOUS=x
  prune_kept_trees; echo "pruned=$KEPT_TREES_PRUNED held=$KEPT_TREES_HELD kept=$KEPT_TREES_KEPT"' 2>&1)"
if [[ -d "$TMP/op/aperire-one.previous-20260102T000000Z" && ! -e "$TMP/op/aperire-one.previous-20260101T000000Z" \
      && "$OUT" == *"pruned=1 held=1 kept=9"* && "$OUT" == *"it is the tree a rollback returns to"* ]]; then
  ok "the tree root's pointer names is kept whatever its age, and named"
else
  bad "the rollback target is never pruned" "$OUT"
fi

# The prune never has root remove a name the login chose (#958 review). A real
# directory renamed to an old kept stamp, with a file in it the login cannot
# delete (standing in for a service account's file under advisor/state), is
# left and named; root's remove-tree is never asked. The stub records a call and
# does the removal a root fallback would have done.
prune_fixture() {
  chmod -R u+w "$TMP/op" 2>/dev/null; reset
  mkdir -p "$TMP/op/aperire-one"
  for n in 01 02 03 04 05 06 07 08 09 10; do mkdir -p "$TMP/op/aperire-one.previous-202601${n}T000000Z/dashboard"; done
  mkdir -p "$TMP/op/aperire-one.previous-20260101T000000Z/node_modules/svc-owned"
  printf 'a service account owns this\n' > "$TMP/op/aperire-one.previous-20260101T000000Z/node_modules/svc-owned/ledger"
  chmod 0555 "$TMP/op/aperire-one.previous-20260101T000000Z/node_modules/svc-owned"
}
prune_fixture
prune_run() { # $1 = 1 to put the old root fallback back; sets OUT
  # shellcheck disable=SC2016  # the inner shell's own variables
  OUT="$(env PATH="$PATH" DIR="$TMP/op/aperire-one" OP_USER="$(id -un)" RD_DIGESTS="$TMP/nopointer" GET="$SUT_REPO" MUTANT="$1" ROOTMARK="$TMP/root-remove-called" bash -c '
    warn() { echo "WARN $*"; }; info() { echo "INFO $*"; }; step() { echo "STEP $*"; }; dim() { echo "DIM $*"; }
    as_operator() { "$@"; }
    checkout_holds_operator_files() { return 1; }
    root_remove_in_tree() { : > "$ROOTMARK"; chmod -R u+w "$2"; rm -rf "$2"; }
    fn="$(sed -n "/^prune_kept_trees() {/,/^}/p" "$GET")"
    if [[ "$MUTANT" == regex ]]; then
      fn="${fn//=~ ^\[0-9\]\{8\}T\[0-9\]\{6\}Z(-\[0-9\]+)?\$/=~ .*}"
    fi
    if [[ "$MUTANT" == 1 ]]; then
      fn="$(python3 -c "import sys; t=sys.stdin.read(); k=\"    KEPT_TREES_KEPT=\$((KEPT_TREES_KEPT + 1))\n    warn \\\"could not remove\"; assert k in t; print(t.replace(k, \"    if root_remove_in_tree remove-tree \\\"\$t\\\" \\\"\$parent\\\" && [[ ! -e \\\"\$t\\\" ]]; then KEPT_TREES_PRUNED=\$((KEPT_TREES_PRUNED + 1)); continue; fi\n\" + k))" <<<"$fn")"
    fi
    eval "$fn"
    KEPT_TREES_MAX=8 KEPT_PREVIOUS=x
    prune_kept_trees; echo "pruned=$KEPT_TREES_PRUNED held=$KEPT_TREES_HELD kept=$KEPT_TREES_KEPT"' 2>&1)"
}
rm -f "$TMP/root-remove-called"
prune_run 0
if [[ -d "$TMP/op/aperire-one.previous-20260101T000000Z/node_modules/svc-owned" && ! -e "$TMP/root-remove-called" \
      && "$OUT" == *"could not remove $TMP/op/aperire-one.previous-20260101T000000Z as "* \
      && "$OUT" == *"sudo rm -rf -- $TMP/op/aperire-one.previous-20260101T000000Z"* && "$OUT" == *"pruned=1 held=0 kept=9"* ]]; then
  ok "a kept-stamp directory the login cannot fully remove is left and named with its command, and root is never asked to remove it"
else
  bad "the prune has no root fallback (#958 review)" "$OUT"
fi
# Ablation: the root fallback put back removes it.
prune_fixture; rm -f "$TMP/root-remove-called"
prune_run 1
if [[ -e "$TMP/root-remove-called" && ! -e "$TMP/op/aperire-one.previous-20260101T000000Z" ]]; then
  ok "  ablation: with the root fallback back, the same tree is removed as root, so the row above is red"
else
  bad "ablation: the root-fallback row can go red" "$OUT"
fi
chmod -R u+w "$TMP/op" 2>/dev/null

# A name the login chose (#958 review). Only the stamp shape an update gives is
# ever considered: a hostile name beside the checkout is not pruned and no line
# prints it, so a quote in it cannot become a command. It holds a file the
# login cannot delete, which is what would make the prune name it.
hostile="aperire-one.previous-2025'\$(echo INJECTED)'"
prune_fixture
mkdir -p "$TMP/op/$hostile/x/locked"; : > "$TMP/op/$hostile/x/locked/f"; chmod 0555 "$TMP/op/$hostile/x/locked"
rm -f "$TMP/root-remove-called"
prune_run 0
if [[ -d "$TMP/op/$hostile" && "$OUT" != *INJECTED* && "$OUT" == *"pruned=1 held=0 kept=9"* ]]; then
  ok "a kept-stamp name that is not an update's stamp is neither pruned nor printed"
else
  bad "a hostile name beside the checkout is ignored" "$OUT"
fi
prune_fixture
mkdir -p "$TMP/op/$hostile/x/locked"; : > "$TMP/op/$hostile/x/locked/f"; chmod 0555 "$TMP/op/$hostile/x/locked"
prune_run regex
if [[ "$OUT" == *INJECTED* ]]; then
  ok "  ablation: with the name check taken out, the hostile name is considered and printed, so the row above is red"
else
  bad "ablation: the hostile-name row can go red" "$OUT"
fi
prune_fixture
chmod -R u+w "$TMP/op" 2>/dev/null

# A recipe file rewritten in the tree after the unpack. Main placed it: the
# installer copied whatever the tree held and the check afterwards only
# warned. Now it is refused before it is copied, the file is not placed,
# and the run ends non-zero naming it.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=container\nSERVICE=xrpldstock\n' > "$TMP/etc/aperire/node-wrapper.conf"
printf 'scripts/build-xrpld-image.sh\n' > "$TMP/state/tamper"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/lib/aperire/build-xrpld-image.sh" 2>/dev/null)" != EVIL* ]] \
   && [[ ! -e "$TMP/lib/aperire/build-xrpld-image.sh" ]]; then
  ok "a recipe file rewritten in the tree after the unpack is not placed as root"
else
  bad "a tampered recipe file is never placed" "build=$(cat "$TMP/lib/aperire/build-xrpld-image.sh" 2>/dev/null)"
fi
if [[ $RC -ne 0 ]] && grep -q 'refused: scripts/build-xrpld-image.sh is not the file this release shipped' <<<"$OUT" \
   && grep -q "release  $(sha256sum < "$TMP/release/scripts/build-xrpld-image.sh" | cut -c1-64)" <<<"$OUT" \
   && grep -q 'root refused to copy' <<<"$OUT"; then
  ok "and the run names it with the release's digest, and ends non-zero"
else
  bad "a tampered recipe file is named and the run fails" "rc=$RC $OUT"
fi
# The fourth file (#682), the signed binary hash the verify step trusts, is
# checked the same way as the other three.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=container\nSERVICE=xrpldstock\n' > "$TMP/etc/aperire/node-wrapper.conf"
printf 'scripts/xrpld-image/signed-binary-sha256.sh\n' > "$TMP/state/tamper"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/lib/aperire/xrpld-image/signed-binary-sha256.sh" && $RC -ne 0 ]] \
   && grep -q 'refused: scripts/xrpld-image/signed-binary-sha256.sh is not the file this release shipped' <<<"$OUT"; then
  ok "the signed-binary-hash reader is checked against the release too, and a rewritten one is not placed"
else
  bad "the update refuses a rewritten signed-binary-sha256.sh" "rc=$RC $(grep -i 'recipe\|signed' <<<"$OUT")"
fi
if [[ "$(cat "$TMP/lib/aperire/xrpld-image/Dockerfile" 2>/dev/null)" == "the NEW Dockerfile" ]]; then
  ok "while the three files nobody touched are placed as usual"
else
  bad "untouched recipe files still land" "$(ls -R "$TMP/lib" 2>/dev/null)"
fi

# And the hosts this must not widen. A native node builds nothing, and a
# host with no node wrapper at all was never granted this, so both keep the
# old rule: refresh a copy that is here, add nothing that is not.
for kindline in "KIND=native" ""; do
  label="${kindline:-no node wrapper}"
  reset
  make_installed_host
  stamp_an_older_release
  mkdir -p "$TMP/etc/aperire"
  if [[ -n "$kindline" ]]; then
    printf '%s\nSERVICE=xrpld.service\n' "$kindline" > "$TMP/etc/aperire/node-wrapper.conf"
  fi
  SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  run_file "$PUBLISHED_COPY" --update --yes
  if [[ ! -e "$TMP/lib/aperire/build-xrpld-image.sh" ]]; then
    ok "$label: no recipe is added by an update"
  else
    bad "$label does not gain a recipe" "$(ls -R "$TMP/lib" 2>/dev/null)"
  fi
  reset
  make_installed_host
  stamp_an_older_release
  mkdir -p "$TMP/etc/aperire" "$TMP/lib/aperire/xrpld-image"
  if [[ -n "$kindline" ]]; then
    printf '%s\nSERVICE=xrpld.service\n' "$kindline" > "$TMP/etc/aperire/node-wrapper.conf"
  fi
  printf 'the OLD build script\n' > "$TMP/lib/aperire/build-xrpld-image.sh"
  SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  run_file "$PUBLISHED_COPY" --update --yes
  if [[ "$(cat "$TMP/lib/aperire/build-xrpld-image.sh" 2>/dev/null)" == "the NEW build script" ]]; then
    ok "$label: a recipe copy that is already here is refreshed"
  else
    bad "$label refreshes an existing copy" "build=$(cat "$TMP/lib/aperire/build-xrpld-image.sh" 2>/dev/null)"
  fi
done

# The Advisor's model-credential recovery program and its unit's own start
# limit (#541). Neither reached an existing host through --update before
# this: refresh_root_programs used to gate credcheck on "a copy is already at
# this destination", which is exactly the destination a host installed
# before 17f never had, and nothing else here ever rewrote the unit that
# names the recovery hook on OnFailure=.
#
# The unit fixture lives under APERIRE_GET_UNIT_DIR (env_for's
# $TMP/etc/systemd/system), never the real /etc/systemd/system: this suite
# runs unprivileged and touches no host.
ADVISORD_UNIT_FIXTURE="$TMP/etc/systemd/system/aperire-advisord.service"

# make_advisord_unit: the shape a host installed before #541 carries, no
# StartLimit* at all (systemd's own default, 10s / 5, which the fix exists
# to replace), no OnFailure=, and every line a real install would have
# written for a native, sudo-wrapped, credentialed deployment, so a row can
# assert each one survives untouched.
make_advisord_unit() {
  mkdir -p "$(dirname "$ADVISORD_UNIT_FIXTURE")"
  {
    printf '[Unit]\n'
    printf 'Description=Aperire Advisor (read-only state service)\n'
    printf 'After=network-online.target\nWants=network-online.target\n\n'
    printf '[Service]\n'
    printf 'LoadCredentialEncrypted=model-api-key-anthropic:/etc/aperire/creds/model-api-key-anthropic\n'
    printf 'Type=simple\n'
    printf 'User=aperire-advisor\nGroup=aperire-advisor\n'
    printf 'SupplementaryGroups=aperire-svc\n'
    printf 'WorkingDirectory=%s/advisor\n' "$TMP/op/aperire-one"
    printf 'ExecStart=%s/advisor/bin/aperire-advisord --addr=127.0.0.1:7810 --container=xrpldstock --dash-read-url=http://127.0.0.1:7800 --state=%s/advisor/state --wrapper=%s/scripts/aperire-node-wrapper.sh --sudo-wrapper\n' \
      "$TMP/op/aperire-one" "$TMP/op/aperire-one" "$TMP/op/aperire-one"
    printf 'Restart=always\nRestartSec=3\n\n'
    # And the sandbox a host installed before #682 carries (#699): strict,
    # with every writable path a fresh install names except /var/lib/aperire.
    printf 'ProtectSystem=strict\n'
    printf 'ReadWritePaths=%s/advisor/state %s/advisor/evidence %s/advisor/knowledge-fleet /srv/stock/config\n' \
      "$TMP/op/aperire-one" "$TMP/op/aperire-one" "$TMP/op/aperire-one"
    printf 'NoNewPrivileges=false\n\n'
    printf '[Install]\nWantedBy=multi-user.target\n'
  } > "$ADVISORD_UNIT_FIXTURE"
}

reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
printf 'the OLD credcheck\n' > "$TMP/sbin/aperire-advisord-credcheck"
make_advisord_unit
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/sbin/aperire-advisord-credcheck" 2>/dev/null)" == "the NEW credcheck" ]]; then
  ok "the credcheck program is refreshed when this host has an Advisor unit"
else
  bad "the update refreshes the credcheck program" \
      "credcheck=$(cat "$TMP/sbin/aperire-advisord-credcheck" 2>/dev/null)"
fi
if grep -q '^StartLimitIntervalSec=30$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^StartLimitBurst=5$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^OnFailure=aperire-advisord-credcheck.service$' "$ADVISORD_UNIT_FIXTURE"; then
  ok "the reachable start limit and the recovery hook are added to an old-layout unit"
else
  bad "the old-layout unit gets the reachable start limit and the hook" "$(cat "$ADVISORD_UNIT_FIXTURE")"
fi
if grep -q '^User=aperire-advisor$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^Group=aperire-advisor$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^SupplementaryGroups=aperire-svc$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -qF -- '--container=xrpldstock' "$ADVISORD_UNIT_FIXTURE" \
   && grep -qF -- '--dash-read-url=http://127.0.0.1:7800' "$ADVISORD_UNIT_FIXTURE" \
   && grep -qF -- '--sudo-wrapper' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^LoadCredentialEncrypted=model-api-key-anthropic:' "$ADVISORD_UNIT_FIXTURE"; then
  ok "the account, every ExecStart flag and the credential line are unchanged"
else
  bad "the update never touches account, flags or credentials" "$(cat "$ADVISORD_UNIT_FIXTURE")"
fi
if grep -q 'reachable start limit' <<<"$OUT" && grep -q 'nothing was restarted' <<<"$OUT"; then
  ok "and the run says the change applies at the unit's next start, restarting nothing"
else
  bad "the run explains what changed and that nothing restarted" "$(grep -i 'start limit\|recovery hook' <<<"$OUT")"
fi

# Idempotent: run again with the unit already current, and nothing about it
# should change a second time.
BEFORE_UNIT="$(cat "$ADVISORD_UNIT_FIXTURE")"
run_file "$PUBLISHED_COPY" --update --yes --force
if [[ "$(cat "$ADVISORD_UNIT_FIXTURE")" == "$BEFORE_UNIT" ]] \
   && grep -q 'already carries the reachable start limit and the recovery hook' <<<"$OUT"; then
  ok "a unit already carrying the fix is left byte for byte alone on a second update"
else
  bad "a current unit is a no-op on a re-run" "$(diff <(printf '%s' "$BEFORE_UNIT") "$ADVISORD_UNIT_FIXTURE")"
fi

# A hand edit the operator made to a line this project does not own survives
# next to the three it does.
reset
make_installed_host
stamp_an_older_release
make_advisord_unit
printf 'Environment=APERIRE_DEBUG=1\n' >> "$ADVISORD_UNIT_FIXTURE"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if grep -qF 'Environment=APERIRE_DEBUG=1' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^StartLimitIntervalSec=30$' "$ADVISORD_UNIT_FIXTURE"; then
  ok "a hand-added line an operator put in the unit survives beside the three lines this fix owns"
else
  bad "a hand edit to the unit is not lost" "$(cat "$ADVISORD_UNIT_FIXTURE")"
fi

# A unit with no [Unit] section at all -- older than this project ever having
# one -- used to be left byte for byte alone while the run claimed "needed no
# change": the awk pass had nothing to attach the three lines to, and nothing
# noticed the insertion never happened.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$(dirname "$ADVISORD_UNIT_FIXTURE")"
{
  printf '[Service]\n'
  printf 'Type=simple\nUser=aperire-advisor\nGroup=aperire-advisor\n'
  printf 'ExecStart=%s/advisor/bin/aperire-advisord --addr=127.0.0.1:7810\n' "$TMP/op/aperire-one"
  printf 'Restart=always\nRestartSec=3\n'
} > "$ADVISORD_UNIT_FIXTURE"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if grep -qx '\[Unit\]' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^StartLimitIntervalSec=30$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^StartLimitBurst=5$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^OnFailure=aperire-advisord-credcheck.service$' "$ADVISORD_UNIT_FIXTURE"; then
  ok "a unit with no [Unit] section at all gets one, with the three lines in it"
else
  bad "a unit with no [Unit] section must still get the fix" "$(cat "$ADVISORD_UNIT_FIXTURE")"
fi
if grep -q 'in place' <<<"$OUT"; then
  ok "and the run reports success from what systemd actually loaded, not a byte-identical file"
else
  bad "a unit that needed a [Unit] section added must not read as unchanged" "$OUT"
fi

# An operator's own drop-in with a [Unit] section of its own wins over
# whatever the unit body says. The rewrite still happens -- the body is this
# project's to keep current -- but a re-read of what systemd effectively
# loaded still disagrees, and that has to be said, naming the file that is
# overriding it, never claimed as fixed.
reset
make_installed_host
stamp_an_older_release
make_advisord_unit
mkdir -p "${ADVISORD_UNIT_FIXTURE}.d"
printf '[Unit]\nStartLimitBurst=99\n' > "${ADVISORD_UNIT_FIXTURE}.d/90-operator-override.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if grep -q '^StartLimitBurst=5$' "$ADVISORD_UNIT_FIXTURE"; then
  ok "the unit body still gets this project's own value, drop-in or not"
else
  bad "the unit body is still this project's to write" "$(cat "$ADVISORD_UNIT_FIXTURE")"
fi
if grep -q '90-operator-override.conf' <<<"$OUT" && grep -qi 'overrides' <<<"$OUT"; then
  ok "the overriding drop-in is named, not left as a mystery"
else
  bad "an overriding drop-in must be named" "$OUT"
fi
if ! grep -q 'reachable start limit (30s / 5) and the recovery hook are in place' <<<"$OUT"; then
  ok "and success is never claimed while a drop-in still wins"
else
  bad "success must not be claimed while the effective value still disagrees" "$OUT"
fi

# A host with no Advisor unit at all: nothing is installed and the unit
# fixture, absent from the start, stays that way.
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/sbin/aperire-advisord-credcheck" && ! -e "$ADVISORD_UNIT_FIXTURE" ]]; then
  ok "a host with no Advisor gets no credcheck program and no unit rewrite"
else
  bad "a host with no Advisor is untouched" \
      "sbin=$(ls "$TMP/sbin" 2>/dev/null), unit=$([[ -e "$ADVISORD_UNIT_FIXTURE" ]] && echo present || echo absent)"
fi

# ── the Advisor's writable grants, the fresh-install set (#699) ─────
#
# The unit above is the previous release's layout: no /var/lib/aperire on
# ReadWritePaths=, so the wrapper's verify step dies on "Read-only file
# system" the first time an official-image upgrade runs. After an update it
# has to pass the SAME predicate the fresh-install suite holds the installer
# to (advisord_can_record_verified_image, one function, both suites), read off
# what systemd loaded rather than the bytes written.
APERIRE_WRAPPER_STATE_DIR="$TMP/var/lib/aperire"
# shellcheck source=scripts/advisord-unit-grants-lib.sh
. "$REPO_DIR/scripts/advisord-unit-grants-lib.sh"
unset APERIRE_WRAPPER_STATE_DIR
loaded_rw() { systemctl show aperire-advisord -p ReadWritePaths --value 2>/dev/null; }

reset
make_installed_host
stamp_an_older_release
make_advisord_unit
if ! advisord_can_record_verified_image "$(loaded_rw)"; then
  ok "the previous release's unit cannot record a verified image (the fixture is the bug)"
else
  bad "the fixture must start without the grant" "$(loaded_rw)"
fi
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if advisord_can_record_verified_image "$(loaded_rw)"; then
  ok "after --update the Advisor can record a verified image, as a fresh install can"
else
  bad "the update brings the grant" "loaded=$(loaded_rw)
$(grep -A4 '#699' <<<"$OUT")"
fi
if [[ -d "$TMP/var/lib/aperire" && ! -L "$TMP/var/lib/aperire" && "$(stat -c %a "$TMP/var/lib/aperire")" == 755 ]]; then
  ok "and the directory the unit now names exists, 0755, so the unit still starts"
else
  bad "the named directory exists" "$(ls -ld "$TMP/var/lib/aperire" 2>&1)"
fi
if grep -qF "ReadWritePaths=$TMP/op/aperire-one/advisor/state $TMP/op/aperire-one/advisor/evidence $TMP/op/aperire-one/advisor/knowledge-fleet /srv/stock/config $TMP/var/lib/aperire" "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^User=aperire-advisor$' "$ADVISORD_UNIT_FIXTURE" \
   && grep -qF -- '--sudo-wrapper' "$ADVISORD_UNIT_FIXTURE" \
   && grep -q '^LoadCredentialEncrypted=model-api-key-anthropic:' "$ADVISORD_UNIT_FIXTURE"; then
  ok "every path it already had is kept, and the account, the flags and the credential are untouched"
else
  bad "the grant is appended, nothing else moves" "$(cat "$ADVISORD_UNIT_FIXTURE")"
fi
if ! grep -qE '^(install-advisor-stack|install-advisor-account|harden-advisord|install-advisord)' "$TMP/state/sudo-exec" 2>/dev/null \
   && ! grep -qE 'bash [^ ]*/scripts/(install-advisor-stack|install-advisor-account|harden-advisord|install-advisord)\.sh' "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "no Advisor installer ran to get there (#641)"
else
  bad "the update must not reach an Advisor installer" "$(grep -E 'advisor|harden' "$TMP/state/sudo-exec")"
fi
BEFORE_UNIT="$(cat "$ADVISORD_UNIT_FIXTURE")"
run_file "$PUBLISHED_COPY" --update --yes --force
if [[ "$(cat "$ADVISORD_UNIT_FIXTURE")" == "$BEFORE_UNIT" ]] && grep -q 'already names' <<<"$OUT"; then
  ok "a second update leaves the granted unit byte for byte alone"
else
  bad "the grant is idempotent" "$(diff <(printf '%s\n' "$BEFORE_UNIT") "$ADVISORD_UNIT_FIXTURE")"
fi

# The node's own directories (#767). A first install wrote its unit before
# node-wrapper.conf existed, so the unit names none of them and the first
# upgrade dies backing up the node's config. The update names every one the
# configuration does.
reset
make_installed_host
stamp_an_older_release
make_advisord_unit
sed -i 's# /srv/stock/config$##' "$ADVISORD_UNIT_FIXTURE"
mkdir -p "$TMP/etc/aperire" "$TMP/stocknode/config"
printf 'KIND=container\nSERVICE=xrpldstock\nCONFIG_FILE=%s/stocknode/config/rippled.cfg\nCOMPOSE_FILE=%s/stocknode/docker-compose.yml\n' \
  "$TMP" "$TMP" > "$TMP/etc/aperire/node-wrapper.conf"
chmod 0644 "$TMP/etc/aperire/node-wrapper.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if advisord_rw_names "$(loaded_rw)" "$TMP/stocknode/config" && advisord_rw_names "$(loaded_rw)" "$TMP/stocknode"; then
  ok "after --update the unit names the node's config and compose directories (#767)"
else
  bad "the update converges the node's directories" "loaded=$(loaded_rw)"
fi
rm -rf "$TMP/stocknode"

# A directory the wrapper could not trust is refused, the unit left as it
# was, and the update carries on: a refused grant is a warning with the
# command to re-run, never a half-updated host.
reset
make_installed_host
stamp_an_older_release
make_advisord_unit
mkdir -m 0775 "$TMP/var/lib/aperire"; chmod 0775 "$TMP/var/lib/aperire"
BEFORE_GRANTS="$(grep '^ReadWritePaths=' "$ADVISORD_UNIT_FIXTURE")"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(grep '^ReadWritePaths=' "$ADVISORD_UNIT_FIXTURE")" == "$BEFORE_GRANTS" ]] \
   && grep -q 'writable by group or other' <<<"$OUT" \
   && grep -qF 'bash -s -- --update --force' <<<"$OUT" \
   && ! grep -q 'sudo bash.*advisord-unit-grants' <<<"$OUT"; then
  ok "a group-writable /var/lib/aperire is not named, and the run says why and the checked-copy run that redoes it (#897)"
else
  bad "an untrustworthy directory is refused" "$(grep -A3 '#699' <<<"$OUT")"
fi

# No Advisor unit: no directory, no write, not a word.
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/var/lib/aperire" ]] && ! grep -q '#699' <<<"$OUT"; then
  ok "a host with no Advisor gets no /var/lib/aperire and no grant step"
else
  bad "no Advisor, no grant" "$(ls -ld "$TMP/var/lib/aperire" 2>&1)"
fi

# ── the fleet broker, on an aggregator (#443) ───────────────────────
#
# The same trap as the sealer, and the one it was met on: the lab aggregator's tree was
# current, the installed broker was four days old with none of the
# fleet-model store verbs, the page's seal called one and got unknown_verb,
# and the aggregator's own sealed copy of the fleet model was never written
# while all four nodes reported sealed. Three rows: stale, current, absent.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
printf 'the 2026-09-13 broker, no store verbs\n' > "$TMP/sbin/aperire-fleet-broker"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/sbin/aperire-fleet-broker" 2>/dev/null)" == "the NEW broker, with the fleet-model store verbs" ]] \
   && grep -q -e "$TMP/sbin/aperire-fleet-broker refreshed from the new tree" <<<"$OUT"; then
  ok "an aggregator's root broker is refreshed from the new tree, and said on screen"
else
  bad "the update refreshes the fleet broker" \
      "broker=$(cat "$TMP/sbin/aperire-fleet-broker" 2>/dev/null)"
fi

# #741: the pairing fingerprint's command is placed beside a broker, by its
# fixed name, even on an aggregator whose grant predates it: the node's prompt
# names /usr/local/sbin/aperire-fleet-arm and nothing else.
if [[ "$(cat "$TMP/sbin/aperire-fleet-arm" 2>/dev/null)" == "the NEW fleet arm, with --fingerprint" ]] \
   && grep -q -e "$TMP/sbin/aperire-fleet-arm refreshed from the new tree" <<<"$OUT"; then
  ok "an aggregator with a broker is given aperire-fleet-arm by the update, and said on screen"
else
  bad "the update places the fingerprint command beside the broker" "$(grep 'fleet-arm' <<<"$OUT" | head -3)"
fi

# What the copy does NOT do, said rather than left to be discovered: the
# socket unit, the service unit and the conf are the grant installer's, and
# an update restarts nothing, so it does not run it.
if grep -q -- '--run fleet-broker-grant' <<<"$OUT" \
   && grep -q 'were not touched' <<<"$OUT"; then
  ok "and it names the installer that refreshes the broker's units and conf, which it left alone"
else
  bad "a refreshed broker names what was not refreshed with it" "$(grep -A2 'aperire-fleet-broker' <<<"$OUT" | head -6)"
fi

# Current: said, and untouched. The inode, not the bytes, because a copy of
# identical content would pass a bytes check and still be a write nobody
# asked for on a root-owned program.
BROKER_INO="$(stat -c %i "$TMP/sbin/aperire-fleet-broker")"
stamp_an_older_release
run_file "$PUBLISHED_COPY" --update --yes
if grep -q -e "$TMP/sbin/aperire-fleet-broker already matches this release" <<<"$OUT" \
   && [[ "$(stat -c %i "$TMP/sbin/aperire-fleet-broker")" == "$BROKER_INO" ]]; then
  ok "a broker already on this release is said to match, and not written over"
else
  bad "an up-to-date broker is left alone and said so" \
      "inode $BROKER_INO -> $(stat -c %i "$TMP/sbin/aperire-fleet-broker")"
fi

# Absent: every host that is not an aggregator. Nothing is installed and
# nothing is said, because a node has no broker to be behind the tree.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/sbin"
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/sbin/aperire-fleet-broker" && ! -e "$TMP/sbin/aperire-fleet-arm" ]] \
   && ! grep -q 'aperire-fleet-broker\|aperire-fleet-arm' <<<"$OUT"; then
  ok "and a host with no broker is given none, and told nothing about one"
else
  bad "a host with no broker stays silent" "$(grep 'fleet-broker' <<<"$OUT" | head -3)"
fi
if grep -qx 'broker_grant=absent' <<<"$OUT"; then
  ok "  and the one fact it prints says the host has no broker grant (#828)"
else
  bad "a host with no grant is named as one" "$(grep 'broker_grant' <<<"$OUT" | head -3)"
fi

# ── the fleet broker's pin, re-recorded by the update (#828) ────────
#
# The broker grant pins the install directory by identity, and the swap is a
# rename, so every update used to leave the broker refusing every pairing
# approval as install_moved. These rows run the REAL broker, out of a
# release that ships it (minus its one root-guard line, because this suite
# is not root), against a conf pinned the way the grant installer pins it.
# shellcheck disable=SC2016  # a literal to grep for
BROKER_GUARD='[[ $EUID -eq 0 ]] || fail not_root "this program is root'"'"'s; it is reached through a systemd socket, and by root'"'"'s update with argv"'
BROKER_REAL="$REPO_DIR/scripts/aperire-fleet-broker.sh"
python3 - "$BROKER_REAL" > "$TMP/dirsafe-828.py" <<'PY828'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r"# --- DIRSAFE-PY-BEGIN ---\ncat > \"\$WORK/dirsafe\.py\" <<'DIRSAFE_PY_EOF'\n(.*?)\nDIRSAFE_PY_EOF", src, re.S)
sys.stdout.write(m.group(1) if m else "")
PY828
dir_id_828() { python3 "$TMP/dirsafe-828.py" "$1" "" "" 002 identity | awk '{print $2}'; }
release_with_broker() { # $1 = name, $2 = the broker file it ships; sets REL828_SHA
  rm -rf "$TMP/tarsrc-$1"
  mkdir -p "$TMP/tarsrc-$1"
  cp -r "$TMP/tarsrc/aperire-one" "$TMP/tarsrc-$1/aperire-one"
  cp "$2" "$TMP/tarsrc-$1/aperire-one/scripts/aperire-fleet-broker.sh"
  tar -czf "$TMP/release-$1.tar.gz" -C "$TMP/tarsrc-$1" aperire-one
  REL828_SHA="$(sha256sum "$TMP/release-$1.tar.gz" | cut -d' ' -f1)"
}
grep -vxF -e "$BROKER_GUARD" "$BROKER_REAL" > "$TMP/broker-828.sh"
if [[ $(( $(wc -l < "$BROKER_REAL") - $(wc -l < "$TMP/broker-828.sh") )) -eq 1 ]]; then
  ok "the release's broker for these rows is the real one, less its root guard and nothing else"
else
  bad "the broker under test differs by the guard alone" "the guard line was not found in $BROKER_REAL"
fi
release_with_broker 828 "$TMP/broker-828.sh"
REL828_REAL_SHA="$REL828_SHA"
# An aggregator with the grant: an installed broker (the release's refresh
# replaces it), and the conf, pinned to the tree as it stands.
grant_host() { # $1 = the INSTALL_DIR_ID the conf records, or "" for the tree's own
  reset
  make_installed_host
  stamp_an_older_release
  chmod 0755 "$KEPT" "$KEPT/dashboard" "$KEPT/dashboard/config" "$TMP/etc/aperire"
  printf 'the previous broker\n' > "$TMP/sbin/aperire-fleet-broker"
  cat > "$TMP/etc/aperire/fleet-broker.conf" <<CONF
# Written by scripts/install-fleet-broker-grant.sh
INSTALL_DIR=$KEPT
INSTALL_DIR_ID=${1:-$(dir_id_828 "$KEPT")}
FLEET_LINK_PORT_MIN=7900
FLEET_LINK_PORT_MAX=7903
DASH_ACCOUNT=$(id -un)
CONF
  chmod 0644 "$TMP/etc/aperire/fleet-broker.conf"
}
probe_broker() { # the socket's view of the installed broker, after the update
  printf 'no-such-verb\nend\n' | env PATH="$PATH" APERIRE_ETC="$TMP/etc/aperire" \
    APERIRE_UNIT_DIR="$TMP/etc/systemd/system" timeout -k 2 30 \
    bash "$TMP/sbin/aperire-fleet-broker" 2>&1 || true
}

# T1: an update on an aggregator with the grant leaves the broker accepting.
grant_host ""
OLD_ID="$(dir_id_828 "$KEPT")"
SOURCE_URL_FOR_RUN="file://$TMP/release-828.tar.gz"
SHA_FOR_RUN="$REL828_REAL_SHA"
run_file "$PUBLISHED_COPY" --update --yes
NEW_ID="$(dir_id_828 "$KEPT")"
if [[ $RC -eq 0 && "$NEW_ID" != "$OLD_ID" ]] && grep -qx 'broker_grant=rerecorded' <<<"$OUT" \
   && grep -qxF "INSTALL_DIR_ID=$NEW_ID" "$TMP/etc/aperire/fleet-broker.conf"; then
  ok "an update on an aggregator re-records the broker's pin for the tree it swapped in"
else
  bad "the update re-records the broker's pin" \
      "rc=$RC old=$OLD_ID new=$NEW_ID $(grep -i 'broker' <<<"$OUT" | head -6) conf=$(grep INSTALL_DIR_ID "$TMP/etc/aperire/fleet-broker.conf")"
fi
PROBE="$(probe_broker)"
if grep -qx 'error=unknown_verb' <<<"$PROBE" && ! grep -q 'install_moved' <<<"$PROBE"; then
  ok "  and the broker accepts afterwards, with no manual step: a connection reaches the verb, not install_moved"
else
  bad "the broker accepts after an update" "$PROBE"
fi

# T4: a pin that was already stale before the update stays stale, and the
# update names the full install. The update itself still succeeds.
grant_host "1:1"
SOURCE_URL_FOR_RUN="file://$TMP/release-828.tar.gz"
SHA_FOR_RUN="$REL828_REAL_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 ]] && grep -qx 'broker_grant=stale' <<<"$OUT" \
   && grep -q 'previous_not_recorded' <<<"$OUT" \
   && grep -qF -- "--dir $KEPT --run fleet-broker-grant" <<<"$OUT" \
   && grep -qx 'INSTALL_DIR_ID=1:1' "$TMP/etc/aperire/fleet-broker.conf"; then
  ok "an already-stale pin is left as it is, the update still finishes, and the full grant install is named"
else
  bad "a stale pin stays stale and is named" "rc=$RC $(grep -i 'broker' <<<"$OUT" | head -6)"
fi

# T6a: the broker refresh did not place the new program, so the installed
# one predates the mode: it ignores argv and reads its verb from stdin. On a
# page-driven update stdin is the update's own socket, held open, which is
# what the process substitution below stands for. The update must not wait
# on it, must not believe anything that broker says, and must say what is
# left to do.
cat > "$TMP/broker-old-828.sh" <<'OLD'
#!/usr/bin/env bash
# A broker from before #828: no argv mode, the verb is read from stdin.
IFS= read -r verb || true
printf 'error=unknown_verb\nexit=3\n'
OLD
release_with_broker 828old "$TMP/broker-old-828.sh"
grant_host ""
SOURCE_URL_FOR_RUN="file://$TMP/release-828old.tar.gz"
SHA_FOR_RUN="$REL828_SHA"
exec {T6A_FD}< <(sleep 90)
T6A_SLEEP=$!
T6A_START=$SECONDS
run_file "$PUBLISHED_COPY" --update --yes <&"$T6A_FD"
T6A_TOOK=$(( SECONDS - T6A_START ))
exec {T6A_FD}<&-
kill "$T6A_SLEEP" 2>/dev/null || true
if [[ $RC -eq 0 && $T6A_TOOK -lt 40 ]] && grep -qx 'broker_grant=too_old' <<<"$OUT" \
   && grep -qF -- "--dir $KEPT --run fleet-broker-grant" <<<"$OUT"; then
  ok "a broker without the mode is never waited on (${T6A_TOOK}s), its answer is not believed, and the full install is named"
else
  bad "an older broker never blocks the update" "rc=$RC took=${T6A_TOOK}s $(grep -i 'broker' <<<"$OUT" | head -6)"
fi

# #938: broker_grant=<state> is the update's machine line, read by
# aperire-update's result parser from the bootstrap's output on an apply.
# The row at "the one fact it prints" above and the T1, T4 and T6a rows name
# that contract: an update whose output is not a terminal still prints
# broker_grant=absent, rerecorded, stale and too_old. These rows hold the
# other side: the line is not shown to an operator.
#
# An install with no broker, the shape a lab box showed a bare
# broker_grant=absent on, between the Fleet block and the stamp line.
reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --role=co-located --yes
if [[ $RC -eq 0 ]] && ! grep -q 'broker_grant' <<<"$OUT"; then
  ok "an install on a host with no broker prints no broker_grant= line (#938)"
else
  bad "a fresh install keeps the update's machine line off the operator's terminal" \
      "rc=$RC $(grep 'broker_grant' <<<"$OUT" | head -3)"
fi

# A reinstall over a kept tree on an aggregator (an uninstall --keep, then
# the one-line install): the grant is re-recorded and the sentence says so,
# without the key=value beside it. No root programs are refreshed on this
# path, so the broker is the one the last update placed: the real one.
reset
make_kept_checkout
mkdir -p "$TMP/etc/aperire"
chmod 0755 "$KEPT" "$KEPT/dashboard" "$KEPT/dashboard/config" "$TMP/etc/aperire"
cp "$TMP/broker-828.sh" "$TMP/sbin/aperire-fleet-broker"
chmod 0755 "$TMP/sbin/aperire-fleet-broker"
cat > "$TMP/etc/aperire/fleet-broker.conf" <<CONF
# Written by scripts/install-fleet-broker-grant.sh
INSTALL_DIR=$KEPT
INSTALL_DIR_ID=$(dir_id_828 "$KEPT")
FLEET_LINK_PORT_MIN=7900
FLEET_LINK_PORT_MAX=7903
DASH_ACCOUNT=$(id -un)
CONF
chmod 0644 "$TMP/etc/aperire/fleet-broker.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release-828.tar.gz"
SHA_FOR_RUN="$REL828_REAL_SHA"
run_file "$PUBLISHED_COPY" --role=co-located --yes
if [[ $RC -eq 0 ]] && ! grep -q 'broker_grant' <<<"$OUT" \
   && grep -q "the fleet broker's grant now records the new tree" <<<"$OUT"; then
  ok "an install over a kept tree re-records the grant, says so in words, and prints no broker_grant= line (#938)"
else
  bad "the install's re-record is in words only" "rc=$RC $(grep -i 'broker' <<<"$OUT" | head -6)"
fi

# The same update on a terminal: an operator running --update by hand reads
# the sentences, and the pipe-only key=value is not printed to them.
grant_host ""
SOURCE_URL_FOR_RUN="file://$TMP/release-828.tar.gz"
SHA_FOR_RUN="$REL828_REAL_SHA"
run_tty_file "$PUBLISHED_COPY" "" --update --yes
if [[ $RC -eq 0 ]] && ! grep -q 'broker_grant' <<<"$OUT" \
   && grep -q "the fleet broker's grant now records the new tree" <<<"$OUT"; then
  ok "an update run by hand on a terminal says the grant was re-recorded and prints no broker_grant= line (#938)"
else
  bad "an update on a terminal is in words only" "rc=$RC $(grep -i 'broker' <<<"$OUT" | head -6)"
fi

# A grant that needs the operator is said in words on every path, with the
# command that fixes it.
grant_host "1:1"
SOURCE_URL_FOR_RUN="file://$TMP/release-828.tar.gz"
SHA_FOR_RUN="$REL828_REAL_SHA"
run_tty_file "$PUBLISHED_COPY" "" --update --yes
if [[ $RC -eq 0 ]] && ! grep -q 'broker_grant' <<<"$OUT" \
   && grep -q 'previous_not_recorded' <<<"$OUT" \
   && grep -q 'refuses pairing approvals as install_moved' <<<"$OUT" \
   && grep -qF -- "--dir $KEPT --run fleet-broker-grant" <<<"$OUT"; then
  ok "a stale grant on a terminal is said in words with the fix command, and no broker_grant= line (#938)"
else
  bad "a stale grant is in words on a terminal" "rc=$RC $(grep -i 'broker' <<<"$OUT" | head -6)"
fi

# The port. Everything after the install reads it: the health check and the
# address in the banner. Left at the default, a host installed with
# --port=7900 would be updated correctly and then declared broken, because
# 7800 answers nothing.
reset
make_installed_host
stamp_an_older_release
printf 'HOST=127.0.0.1\nPORT=7900\n' > "$TMP/etc/aperire/aperire.env"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if grep -q 'http://127.0.0.1:7900/healthz' "$TMP/state/curl-calls" 2>/dev/null \
   && ! grep -q '127.0.0.1:7800/healthz' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "the port is read off this host's own service environment, not defaulted"
else
  bad "the update reads the port from /etc/aperire" "$(grep healthz "$TMP/state/curl-calls" 2>/dev/null | tr '\n' ' ')"
fi
if grep -qF 'The dashboard can be accessed on   http://127.0.0.1:7900' <<<"$OUT"; then
  ok "and the address it prints is that one"
else
  bad "the banner names the port this host listens on" "$(grep -F 'can be accessed' <<<"$OUT")"
fi

# A named instance (ADR 0009) suffixes the units, the config files and the
# database, and this run passes no --instance to install.sh. Updating it
# would install a SECOND unnamed set of units beside the named ones and mint
# a new relay token in a new env file. Refused, and the refusal names the way
# to do it by hand.
reset
make_kept_checkout
printf 'aperire-server-node2.service enabled\n' > "$TMP/state/units"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && -z "$(previous_tree)" ]] \
   && grep -q 'named instance' <<<"$OUT" && grep -q -- '--instance' <<<"$OUT"; then
  ok "a host running a named instance is refused, and told how to update it by hand"
else
  bad "an instance host is refused" "rc=$RC: $(tail -5 <<<"$OUT")"
fi

# The closing banner. An update has operators already and has whatever
# Advisor this host runs, so the first-install paragraphs are false sentences
# there. This is the row that caught them: 171 green rows asserted what the
# update DID and none asserted what it said.
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$OUT" != *"The Advisor is not installed"* && "$OUT" != *"first operator admin"* ]] \
   && grep -q 'as it was: your operators' <<<"$OUT"; then
  ok "the closing banner says nothing that is only true of a first install"
else
  bad "the update banner claims nothing about a first install" "$(tail -16 <<<"$OUT")"
fi
# And what it does say: which release this host came off and which it is on.
# Read from the stamp before the new one is written over it, so it is a
# reading of the host and not of the script's own name for the release.
if grep -q "moved from snapshot-2026-01-01" <<<"$OUT" \
   && grep -q "to ${STAMP_TAG}" <<<"$OUT"; then
  ok "and it names the release this host moved from and the one it moved to"
else
  bad "the closing banner names the release moved from and to" "$(tail -12 <<<"$OUT")"
fi

# ── the stamp gate ──────────────────────────────────────────────────
# A host already on this release is told so, and nothing is fetched. This is
# what makes the command safe to run twice, which is what an operator does
# when they are not sure whether the first one worked.
reset
make_installed_host
printf '{\n  "tag": "%s",\n  "commit": "%s",\n  "sha256": "%s",\n  "published_at": "%s",\n  "source_url": "",\n  "installed_at": "2026-09-08T00:00:00Z"\n}\n' \
  "$STAMP_TAG" "$STAMP_COMMIT" "$GOOD_SHA" "$STAMP_AT" > "$TMP/op/aperire-one/.release"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 && "$OUT" == *"already on ${STAMP_TAG}"* ]]; then
  ok "a host already on this release is told so, and exits 0"
else
  bad "an up-to-date host is told so" "rc=$RC: $OUT"
fi
if [[ ! -f "$TMP/state/install-args" && -z "$(previous_tree)" && -z "$(db_snapshot)" ]] \
   && ! grep -q 'tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "and nothing was fetched, nothing was swapped and no snapshot was taken"
else
  bad "an up-to-date host is not touched" \
      "install=$(cat "$TMP/state/install-args" 2>/dev/null) prev=$(previous_tree) curl=$(cat "$TMP/state/curl-calls" 2>/dev/null)"
fi

# --force is the way back through that gate, and it is the control for the
# row above: without it the difference between "refused because it is current"
# and "refused for some other reason" is invisible.
reset
make_installed_host
printf '{\n  "tag": "%s",\n  "commit": "%s",\n  "sha256": "%s",\n  "published_at": "%s",\n  "source_url": "",\n  "installed_at": "2026-09-08T00:00:00Z"\n}\n' \
  "$STAMP_TAG" "$STAMP_COMMIT" "$GOOD_SHA" "$STAMP_AT" > "$TMP/op/aperire-one/.release"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --force --yes
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]]; then
  ok "--update --force applies the same release again (the control)"
else
  bad "--force re-applies the release" "rc=$RC: $OUT"
fi

# ── a bad archive changes nothing ───────────────────────────────────
# The checksum is the only thing standing between a cut download and a tree
# that gets built and installed. On an update it protects a HOST THAT IS
# RUNNING, so the assertion is that the live tree is exactly as it was.
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/truncated.tar.gz" > "$TMP/state/tarball"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && -z "$(previous_tree)" ]] \
   && grep -qF 'nothing was unpacked' <<<"$OUT"; then
  ok "an archive that fails its checksum stops the update, and nothing was unpacked"
else
  bad "a bad archive refuses the update" "rc=$RC, prev=$(previous_tree): $(tail -6 <<<"$OUT")"
fi
if [[ "$(cat "$KEPT/install.sh" 2>/dev/null)" == "an-earlier-release" \
   && "$(cat "$KEPT/data/aperire.db" 2>/dev/null)" == "THE-OPERATORS-DATABASE" \
   && "$(cat "$KEPT/dashboard/server.ts" 2>/dev/null)" == "the OLD dashboard" ]]; then
  ok "and the tree the host is running is untouched, file for file"
else
  bad "a refused update leaves the running tree alone" "install.sh=$(cat "$KEPT/install.sh" 2>/dev/null)"
fi
if ! grep -qE '^restart ' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "and nothing was restarted, because nothing was replaced"
else
  bad "a refused update restarts nothing" "$(grep -E '^restart' "$TMP/state/systemctl-calls")"
fi

# Never backwards: an update to a release published before the one this host
# is on is refused, however validly it is signed.
reset
make_installed_host
NEWER_SHA="$(printf 'd%.0s' {1..64})"
sign_release "$TMP/store-src" "$NEWER_SHA" "$TMP/testkey" 2026-09-20T00:00:00Z
mkdir -p "$TMP/store/$NEWER_SHA"
cp "$TMP/store-src/release-$NEWER_SHA.json" "$TMP/store/$NEWER_SHA/release.json"
cp "$TMP/store-src/release-$NEWER_SHA.json.sig" "$TMP/store/$NEWER_SHA/release.json.sig"
cp "$TMP/store-src/release-$NEWER_SHA.files" "$TMP/store/$NEWER_SHA/release.files"
printf '%s\n' "$NEWER_SHA" > "$TMP/store/current"
printf '{\n  "tag": "snapshot-newer",\n  "commit": "0000009",\n  "sha256": "%s",\n  "published_at": "2026-09-20T00:00:00Z",\n  "source_url": "",\n  "installed_at": "2026-09-20T00:00:00Z"\n}\n' \
  "$NEWER_SHA" > "$TMP/op/aperire-one/.release"
SOURCE_URL_FOR_RUN="https://get.example.test/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
printf '%s\n' "$TMP/release.tar.gz" > "$TMP/state/tarball"
run_file "$PUBLISHED_COPY" --update --yes --source https://get.example.test/release.tar.gz --sha256 "$GOOD_SHA"
if [[ $RC -ne 0 && -z "$(previous_tree)" ]] && grep -qF 'An update never goes backwards' <<<"$OUT" \
   && ! grep -q '^tarball-fetch' "$TMP/state/curl-calls" 2>/dev/null; then
  ok "an update to a release published before the one this host is on is refused, before anything is fetched, however validly it is signed"
else
  bad "an older release is refused on update" "rc=$RC, $(tail -5 <<<"$OUT")"
fi

# ── nothing restarts without an answer ──────────────────────────────
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if grep -qE '^restart aperire-server.service aperire-relay.service$' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "--yes answers the restart question yes, and restarts exactly the units that were running"
else
  bad "--yes restarts the units that were running" "$(tr '\n' '|' < "$TMP/state/systemctl-calls" 2>/dev/null)"
fi
# The restart offer lists exactly what capture_running_units found, which is
# read off registered units, never off a carried file: this host's tree has
# advisor/bin/aperire-advisord (make_kept_checkout gives every tree one, to
# prove it carries), and it has no aperire-advisord.service, so nothing here
# is a unit for it to be offered a restart for. Matched on the unit-listing
# line's own shape so a rebuild message that also names the binary (a
# different sentence, no such unit to stop or restart) cannot be confused
# with it.
if [[ "$OUT" == *"what is still running the old code"* ]] \
   && ! grep -qE '^ +aperire-advisord\.service *$' <<<"$OUT"; then
  ok "the units are discovered from the host, so a host with no Advisor unit is not offered a restart for one"
else
  bad "only the units on this host are offered a restart" "$OUT"
fi

reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes --no-restart
if [[ -f "$TMP/state/install-args" ]] \
   && ! grep -qE '^restart ' "$TMP/state/systemctl-calls" 2>/dev/null \
   && grep -qF 'sudo systemctl restart aperire-server.service aperire-relay.service' <<<"$OUT"; then
  ok "--no-restart applies the release, restarts nothing, and prints the command"
else
  bad "--no-restart prints the command instead of restarting" \
      "calls=$(tr '\n' '|' < "$TMP/state/systemctl-calls" 2>/dev/null): $(tail -8 <<<"$OUT")"
fi

# An update does not compare against an earlier install (#1181): the host never
# lost anything, and "the Advisor is NOT back" about one that has been running
# all along would be a false sentence. The kept config below is on every host
# that has a relay, an Advisor and a grant, so only the update guard keeps this
# quiet.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'node_label = "label-one"\n' > "$TMP/etc/aperire/relay.conf"
printf 'INSTALL_DIR_ID=1\n' > "$TMP/etc/aperire/fleet-broker.conf"
printf 'SERVICE=x\n' > "$TMP/etc/aperire/node-wrapper.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes --no-restart
if [[ -f "$TMP/state/install-args" && "$OUT" != *"against what this one put back"* && "$OUT" != *"NOT back"* ]]; then
  ok "an update over a host with a relay, an Advisor and a grant compares nothing against an earlier install"
else
  bad "an update makes no 'not back' claim" "$(grep -n 'back' <<<"$OUT" | head -5)"
fi

# On a terminal the question is actually asked, and an operator who says no
# gets the command. Without this row the two above prove only that the flags
# work, and the question they are answers to could have been deleted.
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_tty_file "$PUBLISHED_COPY" $'y\nn\n' --update
if grep -q 'Restart them now?' <<<"$OUT" \
   && ! grep -qE '^restart ' "$TMP/state/systemctl-calls" 2>/dev/null \
   && grep -qF 'sudo systemctl restart aperire-server.service' <<<"$OUT"; then
  ok "on a terminal the question is asked, and no leaves the processes alone"
else
  bad "the restart question is asked on a terminal" \
      "calls=$(tr '\n' '|' < "$TMP/state/systemctl-calls" 2>/dev/null): $(tail -12 <<<"$OUT")"
fi
if [[ -f "$TMP/state/install-args" ]]; then
  ok "and the release is still applied: declining the restart is not declining the update"
else
  bad "declining the restart still applies the release" "$(tail -12 <<<"$OUT")"
fi

# ── an update needs something to update ─────────────────────────────
reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]] \
   && grep -q 'nothing installed on this host to update' <<<"$OUT" \
   && grep -q 'curl -fsSL' <<<"$OUT"; then
  ok "--update on a host with nothing on it refuses, and names the install instead"
else
  bad "--update on an empty host names the install" "rc=$RC: $OUT"
fi

# A checkout with no units is a host an uninstall --keep left behind. It is
# not an installed host, so it gets the same refusal: the way back is the
# install, which reuses what was kept.
reset
make_kept_checkout
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]] \
   && grep -q 'nothing installed on this host to update' <<<"$OUT"; then
  ok "a kept checkout with no unit is not an installed host, so an update refuses it too"
else
  bad "a kept checkout with no unit refuses the update" "rc=$RC: $(tail -8 <<<"$OUT")"
fi

# --check reports and --update changes the host. Asking for both is asking
# for two runs, and the one thing that must not happen is the update running
# under a flag the operator read as "look, do not touch".
reset
make_installed_host
run_file "$PUBLISHED_COPY" --update --check --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" && -z "$(previous_tree)" ]]; then
  ok "--check and --update together are refused, rather than one of them silently winning"
else
  bad "--check with --update is refused" "rc=$RC: $(tail -4 <<<"$OUT")"
fi

# The two flags that only mean something beside --update.
reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --role=co-located --force --yes
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]] && grep -q -- '--force only means something' <<<"$OUT"; then
  ok "--force on a plain install is refused rather than ignored"
else
  bad "--force without --update is refused" "rc=$RC: $(tail -4 <<<"$OUT")"
fi

# The claim no fake install.sh can prove: the real service installer honours
# the flag the bootstrap passes it. Asserted as a reading of that file, and
# labelled as one, the way the relay token row above is.
if grep -q 'APERIRE_NO_RESTART' "$REPO_DIR/scripts/install-aperire-service.sh" \
   && grep -q 'APERIRE_NO_RESTART' "$REPO_DIR/scripts/install-aperire-relay.sh" \
   && grep -q 'export APERIRE_NO_RESTART=1' "$REPO_DIR/install.sh"; then
  ok "and install.sh passes --no-restart down to the two installers that restart things"
else
  bad "the sub-installers honour APERIRE_NO_RESTART" \
      "$(grep -c APERIRE_NO_RESTART "$REPO_DIR/scripts/install-aperire-service.sh" "$REPO_DIR/scripts/install-aperire-relay.sh" "$REPO_DIR/install.sh" | tr '\n' ' ')"
fi

# The same claim for --quiet-existing, and the same kind of reading. The three
# lines an operator saw on the first real update come from three different
# files, and each one reads the environment install.sh exports rather than a
# flag of its own, because each is run on its own as well (#269). What each
# one then prints is asserted in scripts/test-install-relay-wiring.sh, which
# drives install.sh and the relay installer for real.
if grep -q 'APERIRE_UPDATE' "$REPO_DIR/scripts/install-aperire-service.sh" \
   && grep -q 'APERIRE_UPDATE' "$REPO_DIR/scripts/install-aperire-relay.sh" \
   && grep -q 'APERIRE_UPDATE' "$REPO_DIR/scripts/install-aperire-cli.sh" \
   && grep -q 'export APERIRE_UPDATE=1' "$REPO_DIR/install.sh"; then
  ok "and --quiet-existing reaches the three installers that print first-install text"
else
  bad "the sub-installers read APERIRE_UPDATE" \
      "$(grep -c APERIRE_UPDATE "$REPO_DIR/scripts/install-aperire-service.sh" "$REPO_DIR/scripts/install-aperire-relay.sh" "$REPO_DIR/scripts/install-aperire-cli.sh" "$REPO_DIR/install.sh" | tr '\n' ' ')"
fi

# ── the fleet flags, which this script only carries ─────────────────
#
# install.sh owns the pairing step, the prompt and every refusal about it.
# What this script owes is that the three flags arrive there unchanged, in
# both spellings, and that a run which cannot pair is refused here rather than
# an hour into a build.

echo
echo "Joining a fleet from the one-liner:"

reset
run_sut --role=co-located --yes \
        --fleet-aggregator https://agg.example --fleet-label node-two
args="$(cat "$TMP/state/install-args" 2>/dev/null)"
if [[ "$args" == *"--fleet-aggregator=https://agg.example"* \
      && "$args" == *"--fleet-label=node-two"* ]]; then
  ok "--flag value reaches install.sh as --flag=value"
else
  bad "the fleet flags reach install.sh" "args=$args"
fi

reset
run_sut --role=co-located --yes --fleet-aggregator=https://agg.example
args="$(cat "$TMP/state/install-args" 2>/dev/null)"
if [[ "$args" == *"--fleet-aggregator=https://agg.example"* ]]; then
  ok "and --flag=value works too, the way every other flag here does"
else
  bad "both spellings reach install.sh" "args=$args"
fi

# The code does NOT have a spelling here, and that is the finding rather than
# an omission (P3-072). This layer reaches install.sh through `sudo`, and sudo
# writes the whole command line to /var/log/auth.log: 0640 syslog:adm, kept for
# weeks, on a value that is live for fifteen minutes. /proc is a window of
# seconds. install.sh keeps the flag, where there is no sudo in the chain when
# the operator is already root.
#
# Both spellings, because the two-word form is the one that used to fall
# through to "unknown argument: APR-..." and print the live code back.
for form in "--fleet-code=APR-00000-00000-00000-00000" "--fleet-code APR-00000-00000-00000-00000"; do
  reset
  # shellcheck disable=SC2086  # the two forms are one and two words on purpose
  run_sut --role=co-located --yes --fleet-aggregator=https://agg.example $form
  if [[ $RC -ne 0 && "$OUT" == *"auth.log"* && ! -f "$TMP/state/install-args" ]]; then
    ok "\`$form\` is refused, naming auth.log, and nothing is fetched or installed"
  else
    bad "--fleet-code is refused by the one-liner" "rc=$RC: $OUT"
  fi
  if [[ "$OUT" != *"APR-00000"* ]]; then
    ok "  and the refusal does not print the code back"
  else
    bad "the refusal does not echo the code" "$OUT"
  fi
  if [[ "$OUT" == *"bash -s -- --fleet-aggregator <url> --code -"* && "$OUT" != *"sudo bash"* ]]; then
    ok "  and it says what to run instead, on a box that is already built"
  else
    bad "the refusal names the way that works, and sends root to no tree script" "$OUT"
  fi
done

# --yes is this script's own and it stops at install.sh: install.sh never
# hands it to the pair command, because on that command it would mean the
# fingerprint comparison had already been made by hand.
reset
run_sut --role=co-located --yes --fleet-aggregator=https://agg.example
args="$(cat "$TMP/state/install-args" 2>/dev/null)"
if [[ "$args" == *"--yes"* ]]; then
  ok "  and install.sh is still taken at its plan, which is what --yes means here"
else
  bad "--yes still reaches install.sh" "args=$args"
fi

reset
run_sut --update --fleet-aggregator https://agg.example --yes
if [[ $RC -ne 0 && "$OUT" == *"already decided its fleet"* ]]; then
  ok "an update refuses to pair: that host's fleet membership was decided already"
else
  bad "--update refuses the fleet flags" "rc=$RC: $OUT"
fi

reset
run_sut --check --fleet-aggregator https://agg.example --yes
if [[ $RC -ne 0 && "$OUT" == *"installs nothing"* ]]; then
  ok "a check refuses them too: there is nothing to join a fleet"
else
  bad "--check refuses the fleet flags" "rc=$RC: $OUT"
fi

# P3-059 at this layer, an hour before the build would have found it.
reset
run_sut --role=co-located --yes --fleet-aggregator http://127.0.0.1.evil.example
if [[ $RC -ne 0 && ! -f "$TMP/state/install-args" ]]; then
  ok "a hostname that merely starts with a loopback name is refused, and nothing is fetched"
else
  bad "a look-alike loopback aggregator is refused here" "rc=$RC: $OUT"
fi

reset
run_sut --role=co-located --yes --fleet-label node-two
if [[ $RC -ne 0 && "$OUT" == *"need --fleet-aggregator"* ]]; then
  ok "a label with nowhere to dial is refused before anything is fetched"
else
  bad "--fleet-label alone is refused" "rc=$RC: $OUT"
fi

reset
run_sut --code APR-00000-00000-00000-00000
if [[ $RC -ne 0 && "$OUT" == *"need --fleet-aggregator"* ]]; then
  ok "--code alone, with nowhere to dial, is refused the same way"
else
  bad "--code alone is refused" "rc=$RC: $OUT"
fi

# P3-074, at this layer. `grep -q` exits 0 when ANY line matches, so a
# two-line label went through and forged a second line in the command the
# closing text tells the operator to copy.
reset
run_sut --role=co-located --yes --fleet-aggregator https://agg.example \
        --fleet-label "$(printf 'node-two\nsudo rm -rf /')"
if [[ $RC -ne 0 && "$OUT" == *"must match [a-z0-9-]{1,32}"* && ! -f "$TMP/state/install-args" ]]; then
  ok "a two-line label is refused, so it cannot forge a second line in a printed command"
else
  bad "a two-line label is refused" "rc=$RC: $OUT"
fi

# P3-077. install.sh's own rule, in its own words: an install given a flag it
# silently dropped did something other than what it was asked for. This is the
# path where the flags are validated and then never reach it, and it is a
# realistic mistake now that the Settings page prints the line permanently.
reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire" "$TMP/op/aperire-one"
run_sut --role=co-located --yes --fleet-aggregator https://agg.example --fleet-label node-two
if [[ $RC -eq 0 && "$OUT" == *"already installed"* \
      && "$OUT" == *"asked to join https://agg.example, and it did not"* ]]; then
  ok "an already-installed host is TOLD the fleet flags were not used, by name"
else
  bad "the dropped fleet flags are named" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"bash -s -- --fleet-aggregator https://agg.example --fleet-label node-two --code -"* ]]; then
  ok "  and it prints the one line that pairs that host, carrying the label that was given"
else
  bad "the pair command is printed on an already-installed host" "$OUT"
fi
if [[ "$OUT" != *"--code - --dir"* ]]; then
  ok "  and a tree at the default place needs no --dir"
else
  bad "the default tree is not named" "$OUT"
fi
# A tree somewhere else, with a space in it: the line must name it, quoted.
reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire" "$TMP/op/odd tree"
run_sut --dir "$TMP/op/odd tree" --role=co-located --yes --fleet-aggregator https://agg.example
if [[ "$OUT" == *"--code - --dir $(printf '%q' "$TMP/op/odd tree")"* ]]; then
  ok "  and a tree that is not the default is named with --dir, shell-quoted (#914)"
else
  bad "the pair command names a non-default tree" "rc=$RC: $OUT"
fi
reset

# ── --code, on a host that IS already installed: it pairs now (#611) ─
#
# The Settings page's mint step prints one line that carries both
# --fleet-aggregator and --code, because the old shape named a path the
# aggregator could not know and failed as typed the moment it was copied.
# On a host that turns out to be already built, this is where that line
# actually runs.
write_fake_pair_script() { # $1 = where the checkout is
  mkdir -p "$1/scripts"
  # A real checkout always has one; looks_like_a_checkout is what the pair
  # branch gates on before it runs anything (#613).
  printf 'a fake checkout\n' > "$1/install.sh"
  # Root runs the pair script only from a copy staged through both checks
  # (#764), and the check is loaded from the checkout's own library.
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$1/scripts/trusted-path-lib.sh"
  cat > "$1/scripts/aperire-fleet-pair.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/pair-args"
cat >> "$TMP/state/pair-stdin"
printf '%s\n' "\$( [[ -t 0 ]] && echo yes || echo no )" >> "$TMP/state/pair-stdin-tty"
echo "== Pairing"
echo "  ok    paired, label validator1"
EOF
  chmod +x "$1/scripts/aperire-fleet-pair.sh"
}

echo
echo "--code, given with --fleet-aggregator, on a host that is already installed (#611):"

reset
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire"
write_fake_pair_script "$TMP/op/aperire-one"
run_sut --fleet-aggregator https://agg.example --code APR-00000-00000-00000-00000
if [[ $RC -eq 0 && -f "$TMP/state/pair-args" ]]; then
  ok "an installed host given both flags runs the pair script from the checkout it found, and exits with its status"
else
  bad "the pair script ran" "rc=$RC out=$OUT $(ls "$TMP/state" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/state/pair-args" 2>/dev/null)" == "--code - --aggregator https://agg.example" ]]; then
  ok "  called with --code - and --aggregator, never the code as an argument"
else
  bad "the pair script's own argv" "$(cat "$TMP/state/pair-args" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/state/pair-stdin" 2>/dev/null)" == "APR-00000-00000-00000-00000" ]]; then
  ok "  and the code crossed on its stdin, exactly the value that was given"
else
  bad "the code arrived on the pair script's stdin" "$(cat "$TMP/state/pair-stdin" 2>/dev/null)"
fi
if [[ "$OUT" != *"APR-00000-00000-00000-00000"* ]]; then
  ok "  and the code never appears in the bootstrap's own output"
else
  bad "the code stayed out of this script's own output" "$OUT"
fi
if [[ "$OUT" == *"pairing"* && "$OUT" == *"$TMP/op/aperire-one"* ]]; then
  ok "  and it said what it was about to do, and where the checkout is, before it ran"
else
  bad "the one announcing line" "$OUT"
fi
reset

printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire"
write_fake_pair_script "$TMP/op/aperire-one"
run_sut --fleet-aggregator https://agg.example --code APR-00000-00000-00000-00000 --fleet-label node-two
if [[ "$(cat "$TMP/state/pair-args" 2>/dev/null)" == "--code - --aggregator https://agg.example --label node-two"* ]]; then
  ok "and --fleet-label carries through to the pair script it now runs"
else
  bad "the label reached the pair script" "$(cat "$TMP/state/pair-args" 2>/dev/null)"
fi
reset

# --code - reads the code from THIS run's own stdin, the better habit
# aperire-fleet-pair.sh's own header names, and hands it on the same way.
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire"
write_fake_pair_script "$TMP/op/aperire-one"
run_sut_with_stdin() {
  local code="$1"; shift
  local -a e; mapfile -t e < <(env_for)
  OUT="$(printf '%s\n' "$code" | env "${e[@]}" bash "$SUT" "$@" 2>&1)"; RC=$?
}
run_sut_with_stdin "APR-00000-00000-00000-00000" --fleet-aggregator https://agg.example --code -
if [[ $RC -eq 0 && "$(cat "$TMP/state/pair-stdin" 2>/dev/null)" == "APR-00000-00000-00000-00000" ]]; then
  ok "--code - reads the code from this run's own stdin, and hands it on unchanged"
else
  bad "--code - resolved to the piped value" "rc=$RC $(cat "$TMP/state/pair-stdin" 2>/dev/null)"
fi
if [[ "$OUT" != *"APR-00000-00000-00000-00000"* ]]; then
  ok "  and that code still never appears in this script's own output"
else
  bad "the piped code stayed out of the output" "$OUT"
fi
reset

# A checkout built before fleet pairing (#176) has no pair script to run: a
# named refusal, never a bare "No such file or directory" from bash itself.
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire" "$TMP/op/aperire-one/scripts"
printf 'an earlier release\n' > "$TMP/op/aperire-one/install.sh"
run_sut --fleet-aggregator https://agg.example --code APR-00000-00000-00000-00000
if [[ $RC -ne 0 && "$OUT" == *"aperire-fleet-pair.sh is missing"* && ! -f "$TMP/state/pair-args" ]]; then
  ok "a checkout with no aperire-fleet-pair.sh is refused by name, and nothing runs"
else
  bad "the missing pair script is refused" "rc=$RC: $OUT"
fi
reset

# And a $DIR that is not a checkout at all (no install.sh) is refused before
# either of the checks above get a chance to run something in it (#613, the
# same gate the print path takes at report_kept_artifacts).
printf 'aperire-server.service enabled\n' > "$TMP/state/units"
mkdir -p "$TMP/etc/aperire" "$TMP/op/aperire-one"
run_sut --fleet-aggregator https://agg.example --code APR-00000-00000-00000-00000
if [[ $RC -ne 0 && "$OUT" == *"does not look like an Aperire checkout"* && ! -f "$TMP/state/pair-args" ]]; then
  ok "a \$DIR without install.sh is refused by name, and nothing runs"
else
  bad "a checkout-less \$DIR is refused" "rc=$RC: $OUT"
fi
reset

# NOT installed: --code has nothing to pair yet. install.sh's own --fleet-code
# is refused above this script for the auth.log reason, and forwarding the
# value here through run_install's sudo would be that same exposure by
# another route (P3-072), so the flag is named as unused rather than wired
# through, and the fresh install still asks for a code on the terminal at the
# end, the way it always has.
run_sut --role=co-located --yes --fleet-aggregator https://agg.example --code APR-00000-00000-00000-00000
args="$(cat "$TMP/state/install-args" 2>/dev/null)"
if [[ $RC -eq 0 && "$OUT" == *"--code pairs a host that is already installed; this one is not"* ]]; then
  ok "a box with nothing installed is TOLD --code was not used, by name, rather than silently dropped"
else
  bad "the unused --code is named on a fresh install" "rc=$RC: $OUT"
fi
if [[ "$args" == *"--fleet-aggregator=https://agg.example"* && "$args" != *"--fleet-code"* ]]; then
  ok "  --fleet-aggregator still reaches install.sh; --fleet-code never does"
else
  bad "install.sh's own args on a fresh install with --code given" "args=$args"
fi
if [[ "$OUT" != *"APR-00000-00000-00000-00000"* ]]; then
  ok "  and the code itself never appears in this run's output either"
else
  bad "the code stayed out of the fresh-install output" "$OUT"
fi
reset

# ── --node-wrapper: the wrapper installer's arguments, through the bootstrap (#924) ─
#
# install-node-wrapper.sh asks the operator for a container name, a unit or an
# admin RPC port, and root may not run it out of the tree. The bootstrap takes
# the argument, holds it to a whitelist before any root call, stages the
# release and runs the checked copy. These rows hold both halves: what runs is
# the staged copy with exactly the argument given, and what is refused is
# refused with no root call at all.
write_fake_wrapper_installer() { # $1 = where the checkout is
  mkdir -p "$1/scripts"
  printf 'a fake checkout\n' > "$1/install.sh"
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$1/scripts/trusted-path-lib.sh"
  cat > "$1/scripts/install-node-wrapper.sh" <<WEOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "\$0" > "$TMP/state/wrap-self"
printf '%s\n' "\$*" > "$TMP/state/wrap-args"
printf '%s\n' "\$#" > "$TMP/state/wrap-argc"
printf '%s\n' "\${APERIRE_INSTALL_TREE:-}" > "$TMP/state/wrap-tree"
printf '%s\n' "\${APERIRE_INSTANCE-unset}" > "$TMP/state/wrap-instance"
echo "== configured"
exit \${WRAP_FAKE_RC:-0}
WEOF
  chmod +x "$1/scripts/install-node-wrapper.sh"
}
wrap_installed() { # an installed host with a checkout that carries the installer
  reset
  printf 'aperire-server.service enabled\n' > "$TMP/state/units"
  mkdir -p "$TMP/etc/aperire"
  write_fake_wrapper_installer "$TMP/op/aperire-one"
}

echo
echo "--node-wrapper, --node-wrapper-native: the wrapper installer runs staged, with a whitelisted argument (#924):"

wrap_installed
run_sut --node-wrapper xrpld-1
if [[ $RC -eq 0 && "$(cat "$TMP/state/wrap-args" 2>/dev/null)" == "xrpld-1" ]]; then
  ok "--node-wrapper <container> hands the installer exactly that name, and exits with its status"
else
  bad "--node-wrapper <container>" "rc=$RC args=$(cat "$TMP/state/wrap-args" 2>/dev/null) out=$OUT"
fi
self_ran="$(cat "$TMP/state/wrap-self" 2>/dev/null)"
if [[ -n "$self_ran" && "$self_ran" != "$TMP/op/aperire-one/"* && "$self_ran" == */scripts/install-node-wrapper.sh ]]; then
  ok "  and what ran is the staged copy, never the checkout's own"
else
  bad "the staged copy ran" "ran=$self_ran tree=$TMP/op/aperire-one"
fi
if [[ "$(cat "$TMP/state/wrap-tree" 2>/dev/null)" == "$TMP/op/aperire-one" && "$(cat "$TMP/state/wrap-instance" 2>/dev/null)" == "" ]]; then
  ok "  told which tree it acts on, and no instance unless one was named"
else
  bad "the tree and instance reached the installer" "tree=$(cat "$TMP/state/wrap-tree" 2>/dev/null) instance=$(cat "$TMP/state/wrap-instance" 2>/dev/null)"
fi
if [[ "$OUT" == *"configuring the privilege wrapper for the container xrpld-1"* && "$OUT" == *"the wrapper is configured"* ]]; then
  ok "  and it said what it was doing and what it did"
else
  bad "the announcing and closing lines" "$OUT"
fi

wrap_installed
run_sut --node-wrapper
if [[ $RC -eq 0 && "$(cat "$TMP/state/wrap-argc" 2>/dev/null)" == "0" ]]; then
  ok "a bare --node-wrapper runs the installer with no argument, which is its own detection"
else
  bad "bare --node-wrapper" "rc=$RC argc=$(cat "$TMP/state/wrap-argc" 2>/dev/null) out=$OUT"
fi

wrap_installed
run_sut --node-wrapper xrpld --node-wrapper-rpc 5006
if [[ "$(cat "$TMP/state/wrap-args" 2>/dev/null)" == "xrpld http://127.0.0.1:5006" ]]; then
  ok "--node-wrapper-rpc <port> becomes the loopback URL the installer takes"
else
  bad "--node-wrapper-rpc <port>" "args=$(cat "$TMP/state/wrap-args" 2>/dev/null) out=$OUT"
fi
wrap_installed
run_sut --node-wrapper=xrpld --node-wrapper-rpc=http://localhost:6010
if [[ "$(cat "$TMP/state/wrap-args" 2>/dev/null)" == "xrpld http://localhost:6010" ]]; then
  ok "  and a loopback http URL passes as given, in the = spelling too"
else
  bad "--node-wrapper-rpc <url>" "args=$(cat "$TMP/state/wrap-args" 2>/dev/null) out=$OUT"
fi

wrap_installed
run_sut --node-wrapper-native
if [[ $RC -eq 0 && "$(cat "$TMP/state/wrap-args" 2>/dev/null)" == "--native" ]]; then
  ok "--node-wrapper-native with no unit runs the installer's --native, which tries xrpld then rippled"
else
  bad "--node-wrapper-native" "rc=$RC args=$(cat "$TMP/state/wrap-args" 2>/dev/null) out=$OUT"
fi
wrap_installed
run_sut --node-wrapper-native xrpld.service
if [[ "$(cat "$TMP/state/wrap-args" 2>/dev/null)" == "--native xrpld.service" ]]; then
  ok "  and with a unit it names that unit"
else
  bad "--node-wrapper-native <unit>" "args=$(cat "$TMP/state/wrap-args" 2>/dev/null)"
fi

wrap_installed
printf 'aperire-server.service enabled\naperire-advisord-node2.service enabled\n' > "$TMP/state/units"
APERIRE_INSTANCE='' run_sut --node-wrapper xrpld --instance node2
if [[ "$(cat "$TMP/state/wrap-instance" 2>/dev/null)" == "node2" ]]; then
  ok "--instance crosses sudo inside the env the root run is given, where sudo's reset cannot drop it"
else
  bad "--instance reached the installer" "instance=$(cat "$TMP/state/wrap-instance" 2>/dev/null) out=$OUT"
fi

# optional_value is what keeps a flag from being read as a name; held on its
# own, because the name regex would refuse a dash-led name anyway and hide it.
ov="$(bash -c "$(sed -n '/^optional_value()/,/^}/p' "$SUT_REPO")"'
  optional_value --node-wrapper --refresh; echo "|"; optional_value --node-wrapper xrpld; echo "|"; optional_value --node-wrapper ""; echo "|"')"
if [[ "$ov" == $'|\nxrpld|\n|' ]]; then
  ok "optional_value takes the next word only when it is a value: not a flag, not empty"
else
  bad "optional_value's dash and empty guards" "$ov"
fi

wrap_installed
WRAP_FAKE_RC=7 run_sut --node-wrapper xrpld
if [[ $RC -eq 7 && "$OUT" == *"exited 7"* ]]; then
  ok "the installer's own exit status is the run's, with a line that says it did not finish"
else
  bad "the installer's status is passed through" "rc=$RC out=$OUT"
fi

echo
echo "The same flags, refused before any root call:"
# Each bad value must end the run with a non-zero status, run no installer,
# and make no root call (the fake sudo writes state/sudo-exec on every one).
refused_before_root() { # $1 = label, rest = arguments
  local label="$1"; shift
  wrap_installed
  run_sut "$@"
  if [[ $RC -ne 0 && ! -e "$TMP/state/wrap-args" && ! -e "$TMP/state/sudo-exec" ]]; then
    ok "$label"
  else
    bad "$label" "rc=$RC ran=$(cat "$TMP/state/wrap-args" 2>/dev/null) sudo=$(cat "$TMP/state/sudo-exec" 2>/dev/null) out=$OUT"
  fi
}
refused_before_root "a container name with a shell metacharacter (x;id) is refused" --node-wrapper 'x;id'
# shellcheck disable=SC2016  # the literal text is the point
refused_before_root "  with a command substitution" --node-wrapper '$(id)'
# shellcheck disable=SC2016  # the literal text is the point
refused_before_root "  with a backtick" --node-wrapper 'x`id`'
refused_before_root "  with a space" --node-wrapper 'x y'
refused_before_root "  with a newline" --node-wrapper $'x\ny'
refused_before_root "  with ../" --node-wrapper '../x'
refused_before_root "  with a slash" --node-wrapper 'a/b'
refused_before_root "  empty (--node-wrapper=)" --node-wrapper=
refused_before_root "  an installer flag spelled with = (--node-wrapper=--refresh)" --node-wrapper=--refresh
refused_before_root "  and --node-wrapper=--no-node" --node-wrapper=--no-node
refused_before_root "  and a flag after a bare --node-wrapper is judged as a flag, not taken as a name" --node-wrapper --refresh
refused_before_root "a unit with a metacharacter is refused" --node-wrapper-native 'xrpld;id'
refused_before_root "  with ../" --node-wrapper-native '../xrpld'
refused_before_root "  with a newline" --node-wrapper-native $'x\ny'
refused_before_root "  empty (--node-wrapper-native=)" --node-wrapper-native=
refused_before_root "  an installer flag spelled with = (--node-wrapper-native=--refresh)" --node-wrapper-native=--refresh
refused_before_root "an RPC port of 0 is refused" --node-wrapper x --node-wrapper-rpc 0
refused_before_root "  65536" --node-wrapper x --node-wrapper-rpc 65536
refused_before_root "  a leading zero (08)" --node-wrapper x --node-wrapper-rpc 08
refused_before_root "  a port with a command (5005;id)" --node-wrapper x --node-wrapper-rpc '5005;id'
refused_before_root "  a URL to another host" --node-wrapper x --node-wrapper-rpc http://evil.example:5005
refused_before_root "  a URL with a path" --node-wrapper x --node-wrapper-rpc http://127.0.0.1:5005/x
refused_before_root "  a URL with userinfo" --node-wrapper x --node-wrapper-rpc http://a@127.0.0.1:5005
refused_before_root "  an https URL" --node-wrapper x --node-wrapper-rpc https://127.0.0.1:5005
refused_before_root "  a two-line value" --node-wrapper x --node-wrapper-rpc $'5005\n5006'
refused_before_root "an RPC with no container beside it is refused" --node-wrapper --node-wrapper-rpc 5005
refused_before_root "  and an RPC beside a native unit" --node-wrapper-native xrpld --node-wrapper-rpc 5005
refused_before_root "both the container and the native form together are refused" --node-wrapper x --node-wrapper-native y
refused_before_root "an instance with ../ is refused" --node-wrapper x --instance '../x'
refused_before_root "  with a capital" --node-wrapper x --instance Node2
refused_before_root "  with a leading dash" --node-wrapper x --instance=-x
refused_before_root "an instance nobody installed (no aperire-advisord-ghost unit) is refused, not configured for nothing" --node-wrapper x --instance ghost
refused_before_root "--source with --node-wrapper is refused, it fetches nothing" --node-wrapper x --source https://example.invalid/r.tar.gz
refused_before_root "--sha256 with --node-wrapper is refused, it fetches nothing" --node-wrapper x --sha256 0000000000000000000000000000000000000000000000000000000000000000
# Under a UTF-8 locale a range like [a-z0-9] matches letters outside ASCII, so
# each validator pins LC_ALL=C. Same refusals, same absence of a root call.
# The unit exists in this row, so only the name check can refuse it.
wrap_installed
printf 'aperire-server.service enabled\naperire-advisord-é1.service enabled\n' > "$TMP/state/units"
LC_ALL=en_US.UTF-8 run_sut --node-wrapper x --instance 'é1'
if [[ $RC -ne 0 && ! -e "$TMP/state/wrap-args" && ! -e "$TMP/state/sudo-exec" && "$OUT" == *"--instance must match"* ]]; then
  ok "under a UTF-8 locale, an instance with an accented letter (é1) is refused by its name"
else
  bad "an accented instance name is refused by the name check" "rc=$RC out=$OUT"
fi
LC_ALL=en_US.UTF-8 refused_before_root "  a container with a fullwidth letter (ａ) is refused" --node-wrapper 'ａ'
LC_ALL=en_US.UTF-8 refused_before_root "  a unit with a fullwidth letter is refused" --node-wrapper-native 'ａxrpld'
LC_ALL=en_US.UTF-8 refused_before_root "  a port with a fullwidth digit is refused" --node-wrapper x --node-wrapper-rpc '５００５'
refused_before_root "--instance alone names nothing to configure and is refused" --instance node2
refused_before_root "--node-wrapper with --update is refused" --node-wrapper x --update
refused_before_root "  with --check" --node-wrapper x --check
refused_before_root "  with --role" --node-wrapper x --role co-located
refused_before_root "  with --yes" --node-wrapper x --yes
refused_before_root "  with the fleet flags" --node-wrapper x --fleet-aggregator https://agg.example

# Not installed: nothing to configure, and nothing is installed over the host.
reset
mkdir -p "$TMP/etc/aperire"
write_fake_wrapper_installer "$TMP/op/aperire-one"
run_sut --node-wrapper xrpld
if [[ $RC -ne 0 && "$OUT" == *"is not installed on this host"* && ! -e "$TMP/state/wrap-args" && ! -e "$TMP/state/install-args" && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a host with nothing installed is refused by name, installs nothing and makes no root call"
else
  bad "not installed is refused" "rc=$RC out=$OUT"
fi
# A checkout that does not carry the installer, and one that is not a checkout.
wrap_installed
rm -f "$TMP/op/aperire-one/scripts/install-node-wrapper.sh"
run_sut --node-wrapper xrpld
if [[ $RC -ne 0 && "$OUT" == *"install-node-wrapper.sh is missing"* && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a checkout with no installer in it is refused by name, before any root call"
else
  bad "a missing installer is refused" "rc=$RC out=$OUT"
fi
wrap_installed
rm -f "$TMP/op/aperire-one/install.sh"
run_sut --node-wrapper xrpld
if [[ $RC -ne 0 && "$OUT" == *"does not look like an Aperire checkout"* && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a directory that is not a checkout is refused by name, before any root call"
else
  bad "a non-checkout is refused" "rc=$RC out=$OUT"
fi
reset

# ── --backup and --restore: the host's operator state, through the bootstrap (#941) ─
#
# `sudo bash <tree>/scripts/aperire-restore.sh --from <set>` had root run the
# checkout, and the state helper it plants every file with. The bootstrap takes
# the program's arguments, holds each to a whitelist before any root call,
# stages the release and runs the checked copy, naming the install. The fake
# sudo resets the environment for these programs the way the real one does, so
# a variable that leaked in from the caller shows up as a row that goes red.
write_fake_br_programs() { # $1 = where the checkout is
  local prog
  mkdir -p "$1/scripts"
  printf 'a fake checkout\n' > "$1/install.sh"
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$1/scripts/trusted-path-lib.sh"
  for prog in aperire-backup.sh aperire-restore.sh; do
    cat > "$1/scripts/$prog" <<WEOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "\$0" > "$TMP/state/br-self"
printf '%s\n' "\$@" > "$TMP/state/br-args"
printf '%s\n' "\$#" > "$TMP/state/br-argc"
printf '%s\n' "\${APERIRE_INSTALL_TREE:-}" > "$TMP/state/br-tree"
printf '%s\n' "\${SUDO_USER-unset}" > "$TMP/state/br-sudo-user"
printf '%s\n' "\${APERIRE_LEAK-unset}" > "$TMP/state/br-leak"
printf '%s\n' "\$( [[ -t 0 ]] && echo tty || echo notty )" > "$TMP/state/br-stdin"
echo "== ran $prog"
exit \$(cat "$TMP/state/br-rc" 2>/dev/null || echo 0)
WEOF
    chmod +x "$1/scripts/$prog"
  done
}
br_installed() { # an installed host with a checkout that carries both programs
  reset
  printf 'aperire-server.service enabled\n' > "$TMP/state/units"
  mkdir -p "$TMP/etc/aperire"
  write_fake_br_programs "$TMP/op/aperire-one"
  : > "$TMP/state/sudo-env-reset"
}

echo
echo "--backup, --restore: the programs run staged, with whitelisted arguments (#941):"

br_installed
APERIRE_LEAK=leaked run_sut --backup --to /srv/sets/one --instance node2 --yes --dry-run < /dev/null
if [[ $RC -eq 0 && "$(tr '\n' ' ' < "$TMP/state/br-args")" == "--to /srv/sets/one --instance node2 --yes --dry-run " \
      && "$(cat "$TMP/state/br-argc")" == 6 ]]; then
  ok "--backup hands the program exactly the arguments given, one word each, and exits with its status"
else
  bad "--backup arguments" "rc=$RC args=$(tr '\n' ' ' < "$TMP/state/br-args" 2>/dev/null) out=$OUT"
fi
self_ran="$(cat "$TMP/state/br-self" 2>/dev/null)"
if [[ "$self_ran" == */run/scripts/aperire-backup.sh && "$self_ran" != "$TMP/op/aperire-one/"* ]]; then
  ok "  what ran is the staged copy, never the checkout's own"
else
  bad "backup runs the staged copy" "ran=$self_ran"
fi
if [[ "$(cat "$TMP/state/br-tree" 2>/dev/null)" == "$TMP/op/aperire-one" ]]; then
  ok "  and it is told which install it acts on"
else
  bad "backup is told the install" "tree=$(cat "$TMP/state/br-tree" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/state/br-leak" 2>/dev/null)" == unset && "$(cat "$TMP/state/br-sudo-user" 2>/dev/null)" == "$(id -un)" ]]; then
  ok "  under the environment sudo leaves it: nothing the caller exported crosses, and SUDO_USER does"
else
  bad "backup runs in sudo's environment" "leak=$(cat "$TMP/state/br-leak" 2>/dev/null) sudo_user=$(cat "$TMP/state/br-sudo-user" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/state/br-stdin" 2>/dev/null)" == notty ]] && grep -q -e "$TMP/op/aperire-one" "$TMP/state/sudo-exec"; then
  ok "  with no terminal there, its stdin is closed rather than the pipe this script may be arriving on"
else
  bad "no terminal, no stdin" "stdin=$(cat "$TMP/state/br-stdin" 2>/dev/null)"
fi

br_installed
run_sut --restore --from /srv/sets/one --yes --overwrite --instance node2 --db-path /srv/data/aperire.db --dry-run < /dev/null
if [[ $RC -eq 0 && "$(tr '\n' ' ' < "$TMP/state/br-args")" == "--from /srv/sets/one --yes --overwrite --instance node2 --db-path /srv/data/aperire.db --dry-run " \
      && "$(cat "$TMP/state/br-self")" == */run/scripts/aperire-restore.sh && "$(cat "$TMP/state/br-tree")" == "$TMP/op/aperire-one" ]]; then
  ok "--restore --from <set> runs the staged restore with every argument it was given, told the install"
else
  bad "--restore arguments" "rc=$RC args=$(tr '\n' ' ' < "$TMP/state/br-args" 2>/dev/null) self=$(cat "$TMP/state/br-self" 2>/dev/null) out=$OUT"
fi

br_installed
run_sut --restore --from=/srv/sets/one -y --dir "$TMP/op/aperire-one" < /dev/null
if [[ $RC -eq 0 && "$(tr '\n' ' ' < "$TMP/state/br-args")" == "--from /srv/sets/one --yes " && "$(cat "$TMP/state/br-tree")" == "$TMP/op/aperire-one" ]]; then
  ok "the = form and -y are taken, and --dir after the verb names the install without being passed on"
else
  bad "= form, -y, --dir after the verb" "rc=$RC args=$(tr '\n' ' ' < "$TMP/state/br-args" 2>/dev/null) out=$OUT"
fi
br_installed
mkdir -p "$TMP/op/other-install"; write_fake_br_programs "$TMP/op/other-install"
run_sut --dir "$TMP/op/other-install" --backup --yes < /dev/null
if [[ $RC -eq 0 && "$(cat "$TMP/state/br-tree")" == "$TMP/op/other-install" ]]; then
  ok "--dir before the verb names the install too"
else
  bad "--dir before the verb" "rc=$RC tree=$(cat "$TMP/state/br-tree" 2>/dev/null) out=$OUT"
fi
rm -rf "$TMP/op/other-install"

br_installed
echo 7 > "$TMP/state/br-rc"
run_sut --backup --yes < /dev/null
if [[ $RC -eq 7 && "$OUT" == *"aperire-backup.sh exited 7"* ]]; then
  ok "the program's own exit status is the run's, with a line that says it did not finish"
else
  bad "the program's status is passed through" "rc=$RC out=$OUT"
fi

# With a terminal, the questions it asks reach it.
if command -v script >/dev/null 2>&1; then
  br_installed
  run_tty "" --backup --dry-run
  if [[ "$(cat "$TMP/state/br-stdin" 2>/dev/null)" == tty ]]; then
    ok "with a terminal on this run, the program has the terminal for its own questions"
  else
    bad "the program keeps the terminal" "stdin=$(cat "$TMP/state/br-stdin" 2>/dev/null) out=$OUT"
  fi
fi

echo
echo "The same arguments, refused before any root call:"
br_refused() { # $1 = label, rest = arguments
  local label="$1"; shift
  br_installed
  run_sut "$@" < /dev/null
  if [[ $RC -ne 0 && ! -e "$TMP/state/br-args" && ! -e "$TMP/state/sudo-exec" ]]; then
    ok "$label"
  else
    bad "$label" "rc=$RC ran=$(cat "$TMP/state/br-args" 2>/dev/null) sudo=$(cat "$TMP/state/sudo-exec" 2>/dev/null) out=$OUT"
  fi
}
br_refused "a relative --to is refused" --backup --to sets/one
# shellcheck disable=SC2088  # the unexpanded tilde is the point
br_refused "  a ~ that was never expanded" --backup --to '~/sets'
br_refused "  with .. in it" --backup --to /srv/../etc
br_refused "  with . in it" --backup --to /srv/./sets
br_refused "  with a double slash" --backup --to /srv//sets
br_refused "  with a space" --backup --to '/srv/my sets'
br_refused "  with a quote" --backup --to "/srv/it's"
# shellcheck disable=SC2016  # the literal text is the point
br_refused "  with a command substitution" --backup --to '/srv/$(id)'
# shellcheck disable=SC2016  # the literal text is the point
br_refused "  with a backtick" --backup --to '/srv/`id`'
br_refused "  with a semicolon" --backup --to '/srv/x;id'
br_refused "  with a newline" --backup --to $'/srv/x\ny'
br_refused "  empty (--to=)" --backup --to=
br_refused "  / alone" --backup --to /
br_refused "  with no value" --backup --to
br_refused "  whose value is a flag" --backup --to --yes
br_refused "--from is refused the same way" --restore --from relative/set
br_refused "  and --db-path" --restore --from /srv/set --db-path data/aperire.db
br_refused "--dir is held to the rule too" --backup --dir relative --yes
br_refused "--instance with ../ is refused" --backup --instance '../x'
br_refused "  with a capital" --backup --instance Node2
br_refused "  with a leading dash" --backup --instance=-x
br_refused "  empty" --backup --instance=
br_refused "  too long (32 characters)" --backup --instance abcdefghijklmnopqrstuvwxyz012345
br_refused "an argument that is not the program's is refused" --backup --bogus
br_refused "  and one that is the other program's (--from beside --backup)" --backup --from /srv/set
br_refused "  and --overwrite beside --backup" --backup --overwrite
br_refused "  and --to beside --restore" --restore --from /srv/set --to /srv/other
br_refused "  and a positional word" --backup /srv/sets
br_refused "  and a flag given a value it does not take (--yes=1)" --backup --yes=1
br_refused "a flag given twice is refused" --backup --to /srv/a --to /srv/b
br_refused "  --yes in both spellings" --backup --yes -y
br_refused "--restore without --from is refused" --restore --yes
br_refused "--backup then --restore is refused" --backup --restore --from /srv/set
br_refused "--restore then --backup is refused" --restore --from /srv/set --backup
br_refused "--backup with --update is refused" --update --backup
br_refused "  with --check" --check --backup
br_refused "  with --node" --node --backup
br_refused "  with --role" --role co-located --backup
br_refused "  with --port" --port 7800 --backup
br_refused "  with --ref" --ref main --backup
br_refused "  with --source" --source https://example.invalid/r.tar.gz --backup
br_refused "  with the fleet flags" --fleet-aggregator https://agg.example --backup
br_refused "  with a --node-wrapper flag" --node-wrapper x --backup
br_refused "  with --refresh-node-key" --refresh-node-key --restore --from /srv/set
br_refused "  and a --yes before the verb is not the program's" --yes --backup
LC_ALL=en_US.UTF-8 br_refused "under a UTF-8 locale, an accented path is refused" --backup --to /srv/é
LC_ALL=en_US.UTF-8 br_refused "  a fullwidth letter in a path is refused" --backup --to /srv/ａ
LC_ALL=en_US.UTF-8 br_refused "  an accented instance is refused" --backup --instance é1

# Not installed, a checkout without the program, and one that is not a checkout:
# each is refused by name, before any root call.
reset
mkdir -p "$TMP/etc/aperire"
write_fake_br_programs "$TMP/op/aperire-one"
run_sut --backup --yes < /dev/null
if [[ $RC -ne 0 && "$OUT" == *"is not installed on this host"* && ! -e "$TMP/state/br-args" && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a host with nothing installed is refused by name, backs up nothing and makes no root call"
else
  bad "backup on a bare host is refused" "rc=$RC out=$OUT"
fi
br_installed
rm -f "$TMP/op/aperire-one/scripts/aperire-restore.sh"
run_sut --restore --from /srv/set < /dev/null
if [[ $RC -ne 0 && "$OUT" == *"aperire-restore.sh is missing"* && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a checkout with no restore program in it is refused by name, before any root call"
else
  bad "a missing restore program is refused" "rc=$RC out=$OUT"
fi
br_installed
rm -f "$TMP/op/aperire-one/install.sh"
run_sut --backup --yes < /dev/null
if [[ $RC -ne 0 && "$OUT" == *"does not look like an Aperire checkout"* && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a directory that is not a checkout is refused by name, before any root call"
else
  bad "a non-checkout is refused" "rc=$RC out=$OUT"
fi

# A program from before staged runs finds its install from where it sits, so a
# copy root checked and ran from elsewhere would take the stage for the install
# (a backup of nothing, or a restore that refuses with the wrong reason). The
# one-liner is the published bootstrap and stages whatever the tree has, so it
# reads the checkout's program for the name it carries and sends the operator
# to update first, before any root call.
# The same check on the file root runs. The checkout's copy is current when the
# bootstrap reads it and older by the time root stages it (the fake sudo
# rewrites it just before the stage), so only a check of the staged copy sees it.
for verb_prog in "--backup --yes:aperire-backup.sh" "--restore --from /srv/set:aperire-restore.sh"; do
  br_installed
  rm -f "$TMP/state/TREE-RAN"
  printf 'scripts/%s\n' "${verb_prog##*:}" > "$TMP/state/tamper-before-stage"
  # shellcheck disable=SC2086  # the verb and its arguments are separate words
  run_sut ${verb_prog%%:*} < /dev/null
  if [[ $RC -ne 0 && "$OUT" == *"older than the one that was read first"* && ! -e "$TMP/state/TREE-RAN" && ! -e "$TMP/state/br-args" ]]; then
    ok "a ${verb_prog##*:} swapped for an older one between the check and the stage is refused on the staged copy, and never run"
  else
    bad "the staged ${verb_prog##*:} is judged after staging" "rc=$RC ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null) out=$OUT"
  fi
done
for verb_prog in "--backup --yes:aperire-backup.sh" "--restore --from /srv/set:aperire-restore.sh"; do
  br_installed
  printf '#!/usr/bin/env bash\n# from before staged runs: finds its install from where it sits\nexit 0\n' > "$TMP/op/aperire-one/scripts/${verb_prog##*:}"
  # shellcheck disable=SC2086  # the verb and its arguments are separate words
  run_sut ${verb_prog%%:*} < /dev/null
  if [[ $RC -ne 0 && "$OUT" == *"predates staged runs"* && "$OUT" == *"--update"* && ! -e "$TMP/state/br-args" && ! -e "$TMP/state/sudo-exec" ]]; then
    ok "a ${verb_prog##*:} from before staged runs is refused by name, with the update to run, before any root call"
  else
    bad "an old ${verb_prog##*:} is refused" "rc=$RC out=$OUT"
  fi
done

reset

# ── --run: one root step of the release, with whitelisted arguments (#929, #955) ─
#
# Every printed root step that used to read `sudo bash <tree>/scripts/<x>.sh
# <args>` (and the menu's root entries) goes through the bootstrap: the step's
# name and its arguments, each held to a whitelist before any root call, the
# release staged, and the checked copy run with the install named to it. The
# fake programs record how they were run. The fake sudo resets the
# environment the way the real one does, so a caller's variable that crossed
# would show.
RS_PROGRAMS=( install-fleet-broker-grant.sh install-model-key-sealer.sh install-advisor-account.sh
  install-trust-sync-grant.sh install-update-grant.sh install-advisor-stack.sh install-aperire-service.sh
  install-aperire-relay.sh prepare-host.sh install-aperire-node.sh harden-advisord.sh reseal-model-key.sh
  close-node-config-exposure.sh migrate-node-nonroot.sh enable-advisory-delete.sh setup-aperire-tunnel.sh
  enable-relay-colocated.sh install-can-delete-timer.sh )
write_fake_step_programs() { # $1 = where the checkout is
  local prog
  mkdir -p "$1/scripts"
  printf 'a fake checkout\n' > "$1/install.sh"
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$1/scripts/trusted-path-lib.sh"
  for prog in "${RS_PROGRAMS[@]}"; do
    cat > "$1/scripts/$prog" <<WEOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "\$0" > "$TMP/state/rs-self"
printf '%s\n' "\$@" > "$TMP/state/rs-args"
printf '%s\n' "\$#" > "$TMP/state/rs-argc"
printf 'tree=%s instance=%s account=%s with_advisor=%s role=%s leak=%s\n' "\${APERIRE_INSTALL_TREE-unset}" \
  "\${APERIRE_INSTANCE-unset}" "\${APERIRE_ACCOUNT-unset}" "\${APERIRE_WITH_ADVISOR-unset}" \
  "\${APERIRE_ROLE-unset}" "\${APERIRE_LEAK-unset}" > "$TMP/state/rs-env"
printf '%s\n' "\$( [[ -t 0 ]] && echo tty || echo notty )" > "$TMP/state/rs-stdin"
printf '%s\n' "\${APERIRE_BUILD_COMMIT-unset}" > "$TMP/state/rs-build-commit"
printf 'service=%s rpc=%s config=%s kind=%s\n' "\${APERIRE_NODE_SERVICE-unset}" "\${APERIRE_NODE_ADMIN_RPC-unset}" \
  "\${APERIRE_NODE_CONFIG-unset}" "\${APERIRE_NODE_KIND-unset}" > "$TMP/state/rs-node-env"
echo "== ran $prog"
exit \$(cat "$TMP/state/rs-rc" 2>/dev/null || echo 0)
WEOF
    chmod +x "$1/scripts/$prog"
  done
}
rs_installed() { # an installed host whose checkout carries every step's program
  reset
  printf 'aperire-server.service enabled\n' > "$TMP/state/units"
  mkdir -p "$TMP/etc/aperire"
  write_fake_step_programs "$TMP/op/aperire-one"
  : > "$TMP/state/sudo-env-reset-run"
}
rs_args() { [[ "$(cat "$TMP/state/rs-argc" 2>/dev/null)" == 0 ]] || tr '\n' ' ' < "$TMP/state/rs-args" 2>/dev/null; }
rs_ran_staged() { # $1 = the program; true when what ran is the staged copy
  local s; s="$(cat "$TMP/state/rs-self" 2>/dev/null)"
  [[ "$s" == */run/scripts/"$1" && "$s" != "$TMP/op/aperire-one/"* ]]
}

echo
echo "--run: one root step, the release's checked copy, with whitelisted arguments (#929, #955):"

rs_installed
APERIRE_LEAK=leaked APERIRE_INSTANCE=from-env run_sut --run fleet-broker-grant --refresh-nodes < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--refresh-nodes " ]] && rs_ran_staged install-fleet-broker-grant.sh; then
  ok "--run fleet-broker-grant --refresh-nodes runs the staged grant installer with that one argument"
else
  bad "--run fleet-broker-grant --refresh-nodes" "rc=$RC args=$(rs_args) self=$(cat "$TMP/state/rs-self" 2>/dev/null) out=$OUT"
fi
if [[ "$(cat "$TMP/state/rs-env" 2>/dev/null)" == "tree=$TMP/op/aperire-one instance=unset account=unset with_advisor=unset role=unset leak=unset" ]]; then
  ok "  told the install it acts on, and nothing the caller exported crosses sudo (not even APERIRE_INSTANCE)"
else
  bad "  --run runs in sudo's environment" "env=$(cat "$TMP/state/rs-env" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/state/rs-stdin" 2>/dev/null)" == notty ]]; then
  ok "  with no terminal there, its stdin is closed"
else
  bad "  no terminal, no stdin" "stdin=$(cat "$TMP/state/rs-stdin" 2>/dev/null)"
fi

rs_installed
ARMKEY='MCowBQYDK2VwAyEAq1dJkh2Yv3b3yT2b7m7Qb0n8xg3gYk6m0jY7b2Yb3qY='
run_sut --run model-key-sealer --trust-arm-key "$ARMKEY" --node-key n9KUjqxCr5FKThSNXdzb7oqN8rYwScB2dUnNqxQxbEA17JkaWy5x < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--trust-arm-key $ARMKEY --node-key n9KUjqxCr5FKThSNXdzb7oqN8rYwScB2dUnNqxQxbEA17JkaWy5x " ]] \
   && rs_ran_staged install-model-key-sealer.sh; then
  ok "--run model-key-sealer --trust-arm-key <key> --node-key <n...> hands both on, one word each"
else
  bad "--run model-key-sealer --trust-arm-key" "rc=$RC args=$(rs_args) out=$OUT"
fi

rs_installed
run_sut --run advisor-account --instance node2 --account my-advisor < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "" && "$(cat "$TMP/state/rs-env")" == *"instance=node2 account=my-advisor "* ]] \
   && rs_ran_staged install-advisor-account.sh; then
  ok "--run advisor-account --instance --account: the two reach the program as the variables it reads, past sudo's reset"
else
  bad "--run advisor-account" "rc=$RC args=$(rs_args) env=$(cat "$TMP/state/rs-env" 2>/dev/null) out=$OUT"
fi

rs_installed
run_sut --run prepare-host --with-advisor < /dev/null
if [[ $RC -eq 0 && "$(cat "$TMP/state/rs-env")" == *"with_advisor=1 "* && "$(rs_args)" == "" ]]; then
  ok "--run prepare-host --with-advisor sets APERIRE_WITH_ADVISOR=1 and passes no argument"
else
  bad "--run prepare-host --with-advisor" "rc=$RC env=$(cat "$TMP/state/rs-env" 2>/dev/null) out=$OUT"
fi

# The commit host preparation stamps its builds with (#1142). A --run puts no
# release down, so the stamp is the one the host's own record names, and the
# step is never handed one by the caller. Without it prepare-host.sh read
# "dev", called a release-stamped binary stale and rebuilt it as dev.
rs_record() { # $1 = the commit field, written the way write_release_stamp writes it
  printf '{\n  "tag": "v1",\n  "commit": "%s",\n  "sha256": "",\n  "published_at": "",\n  "source_url": "",\n  "installed_at": ""\n}\n' "$1" \
    > "$TMP/op/aperire-one/.release"
}
rs_build_commit() { cat "$TMP/state/rs-build-commit" 2>/dev/null; }

rs_installed
rs_record abc1234
run_sut --run prepare-host --with-advisor < /dev/null
if [[ $RC -eq 0 && "$(rs_build_commit)" == abc1234 ]]; then
  ok "--run prepare-host is handed the commit the host's own record names (#1142)"
else
  bad "--run prepare-host carries the installed release's commit" "rc=$RC commit=$(rs_build_commit) out=$OUT"
fi

rs_installed
rs_record abc1234
APERIRE_BUILD_COMMIT=deadbee run_sut --run prepare-host --with-advisor < /dev/null
if [[ $RC -eq 0 && "$(rs_build_commit)" == abc1234 ]]; then
  ok "  and what the caller exported does not choose it"
else
  bad "the record chooses the stamp, not the caller" "rc=$RC commit=$(rs_build_commit)"
fi

rs_installed
APERIRE_BUILD_COMMIT=deadbee run_sut --run prepare-host --with-advisor < /dev/null
if [[ $RC -eq 0 && "$(rs_build_commit)" == unset ]]; then
  ok "  a host with no record is sent no commit, and the caller's does not stand in for it"
else
  bad "no record, no stamp" "rc=$RC commit=$(rs_build_commit)"
fi

# The value ends up inside a go build line, so a record that does not hold a
# commit sends nothing, and nothing it holds is ever run.
inject_quote="abc1234'; touch $TMP/state/injected; '"
inject_subst="abc1234\$(touch $TMP/state/injected)"
for bad_commit in "" "dev" "ABC1234" "abc12" "$inject_quote" "$inject_subst"; do
  rs_installed
  rs_record "$bad_commit"
  run_sut --run prepare-host --with-advisor < /dev/null
  if [[ $RC -eq 0 && "$(rs_build_commit)" == unset && ! -e "$TMP/state/injected" ]]; then
    ok "  a record whose commit is '${bad_commit:0:12}' is not sent on"
  else
    bad "a malformed commit is not passed to root" "rc=$RC commit=$(rs_build_commit)"
  fi
done

rs_installed
rs_record abc1234
run_sut --run fleet-broker-grant --refresh-nodes < /dev/null
if [[ $RC -eq 0 && "$(rs_build_commit)" == unset ]]; then
  ok "  and no other step is handed a stamp"
else
  bad "only host preparation is stamped" "rc=$RC commit=$(rs_build_commit)"
fi

rs_installed
run_sut --run advisory-delete --config /etc/xrpld/xrpld.cfg < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "/etc/xrpld/xrpld.cfg " ]] && rs_ran_staged enable-advisory-delete.sh; then
  ok "--run advisory-delete --config <file> hands the file on as the program's one positional"
else
  bad "--run advisory-delete --config" "rc=$RC args=$(rs_args) out=$OUT"
fi

rs_installed
run_sut --run relay-colocated --binary /usr/local/bin/aperire-relay --port 7900 --unit aperire-server-node2 < /dev/null
staged_relay="$(sed -n 4p "$TMP/state/rs-args" 2>/dev/null)"
if [[ $RC -eq 0 && "$(sed -n 1,3p "$TMP/state/rs-args" | tr '\n' ' ')" == "aperire-server-node2 7900 /usr/local/bin/aperire-relay " \
      && "$staged_relay" == */run/scripts/install-aperire-relay.sh && "$staged_relay" != "$TMP/op/aperire-one/"* ]]; then
  ok "--run relay-colocated hands the enabler its four in its own order, the fourth the staged relay installer"
else
  bad "--run relay-colocated" "rc=$RC args=$(rs_args) out=$OUT"
fi

# #1068. The rotation window's installer had no step, so a host whose node it
# could not find had no one-line fix: APERIRE_NODE_SERVICE set in the
# operator's shell never crosses sudo. The step takes the node by name, holds
# each value to its shape, and hands it on as the variable the program reads.
rs_installed
APERIRE_NODE_SERVICE=leaked run_sut --run rotation-timer < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "" && "$(cat "$TMP/state/rs-node-env")" == "service=unset rpc=unset config=unset kind=unset" ]] \
   && rs_ran_staged install-can-delete-timer.sh; then
  ok "--run rotation-timer runs the staged rotation installer, and a variable the caller exported does not cross"
else
  bad "--run rotation-timer, bare" "rc=$RC args=$(rs_args) env=$(cat "$TMP/state/rs-node-env" 2>/dev/null) out=$OUT"
fi
rs_installed
run_sut --run rotation-timer --service xrpld.service --admin-rpc http://127.0.0.1:5005 --config /etc/opt/xrpld/xrpld.cfg --kind native < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "" && "$(cat "$TMP/state/rs-node-env")" == "service=xrpld.service rpc=http://127.0.0.1:5005 config=/etc/opt/xrpld/xrpld.cfg kind=native" ]] \
   && rs_ran_staged install-can-delete-timer.sh; then
  ok "  with the node named, the installer gets its service, admin RPC, config and kind as the variables it reads"
else
  bad "--run rotation-timer names the node" "rc=$RC args=$(rs_args) env=$(cat "$TMP/state/rs-node-env" 2>/dev/null) out=$OUT"
fi

# The trust sync grant's --if-stale (#1133): the update runs it, and an
# operator can ask for it by name.
rs_installed
APERIRE_LEAK=leaked run_sut --run trust-sync-grant --if-stale < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--if-stale " ]] && rs_ran_staged install-trust-sync-grant.sh; then
  ok "--run trust-sync-grant --if-stale hands the flag to the staged grant installer"
else
  bad "--run trust-sync-grant --if-stale" "rc=$RC args=$(rs_args) out=$OUT"
fi

# The Advisor account installer's --hand-trees-back (#1121), the step its
# printed undo names.
rs_installed
run_sut --run advisor-account --hand-trees-back --instance node2 < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--hand-trees-back " ]] && rs_ran_staged install-advisor-account.sh \
   && [[ "$(cat "$TMP/state/rs-env" 2>/dev/null)" == "tree=$TMP/op/aperire-one instance=node2 account=unset with_advisor=unset role=unset leak=unset" ]]; then
  ok "--run advisor-account --hand-trees-back hands the flag on, and the instance still crosses as the variable it is"
else
  bad "--run advisor-account --hand-trees-back" "rc=$RC args=$(rs_args) env=$(cat "$TMP/state/rs-env" 2>/dev/null) out=$OUT"
fi
# The node migration's undo (#1148), the step its "Putting it back" names: the
# flag crosses and nothing else does, so the store's path is never typed.
rs_installed
run_sut --run migrate-node --hand-store-back < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--hand-store-back " ]] && rs_ran_staged migrate-node-nonroot.sh; then
  ok "--run migrate-node --hand-store-back hands the flag to the staged migration, and runs the checked copy"
else
  bad "--run migrate-node --hand-store-back" "rc=$RC args=$(rs_args) out=$OUT"
fi
# The node installer's --help names --role and --image-tag as arguments the
# bootstrap hands on, so the step takes both, each held to its own shape.
rs_installed
run_sut --run node --native --role validator --image-tag 3.3.0 --yes < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--native --role validator --image-tag 3.3.0 --yes " ]] && rs_ran_staged install-aperire-node.sh; then
  ok "--run node takes --role and --image-tag, as its --help says"
else
  bad "--run node --role --image-tag" "rc=$RC args=$(rs_args) out=$OUT"
fi

rs_installed
run_sut --dir "$TMP/op/aperire-one" --run harden-advisord < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "" ]] && rs_ran_staged harden-advisord.sh; then
  ok "--dir before --run names the install, and a step with no arguments runs with none"
else
  bad "--dir before --run" "rc=$RC args=$(rs_args) out=$OUT"
fi

rs_installed
echo 5 > "$TMP/state/rs-rc"
run_sut --run update-grant --program-only < /dev/null
if [[ $RC -eq 5 && "$OUT" == *"install-update-grant.sh exited 5"* ]]; then
  ok "the step's own exit status is the run's, with a line that says it did not finish"
else
  bad "the step's status is passed through" "rc=$RC out=$OUT"
fi

# A host installed by the manual path on a distribution the one-line install
# is not verified on still runs its root steps: the menu reaches its root
# entries through --run, and the gate is about the install, not about them.
rs_installed
OS_FILE="$TMP/debian.os-release" run_sut --run harden-advisord < /dev/null
if [[ $RC -eq 0 ]] && rs_ran_staged harden-advisord.sh; then
  ok "on a distribution the one-liner does not take, a root step still runs (the gate is the install's)"
else
  bad "--run is not gated on the distribution" "rc=$RC out=$OUT"
fi
# The steps that are pieces of an install run on a host with nothing
# installed yet, as the menu's install entries always did; the rest refuse.
for st in dashboard-service relay advisor-stack tunnel prepare-host; do
  reset
  mkdir -p "$TMP/etc/aperire"
  write_fake_step_programs "$TMP/op/aperire-one"
  : > "$TMP/state/sudo-env-reset-run"
  run_sut --run "$st" < /dev/null
  if [[ $RC -eq 0 && -s "$TMP/state/rs-self" ]]; then
    ok "--run $st runs on a host with nothing installed yet"
  else
    bad "--run $st runs before an install" "rc=$RC out=$OUT"
  fi
done

if command -v script >/dev/null 2>&1; then
  rs_installed
  run_tty "" --run tunnel
  if [[ "$(cat "$TMP/state/rs-stdin" 2>/dev/null)" == tty ]]; then
    ok "with a terminal on this run, the step has the terminal for its own questions"
  else
    bad "the step keeps the terminal" "stdin=$(cat "$TMP/state/rs-stdin" 2>/dev/null) out=$OUT"
  fi
fi

echo
echo "--run, refused before any root call:"
rs_refused() { # $1 = label, rest = arguments
  local label="$1"; shift
  rs_installed
  run_sut "$@" < /dev/null
  if [[ $RC -ne 0 && ! -e "$TMP/state/rs-args" && ! -e "$TMP/state/sudo-exec" ]]; then
    ok "$label"
  else
    bad "$label" "rc=$RC ran=$(rs_args) sudo=$(cat "$TMP/state/sudo-exec" 2>/dev/null) out=$OUT"
  fi
}
rs_refused "--run with no step" --run
rs_refused "  a step it does not know" --run install-fleet-broker-grant.sh
rs_refused "  a path for a step" --run ../scripts/x
rs_refused "an argument that is not the step's" --run fleet-broker-grant --arm
rs_refused "  a bare word" --run fleet-broker-grant refresh-nodes
rs_refused "  an argument to a step that takes none" --run harden-advisord --yes
rs_refused "  a flag given a value (--remove=1)" --run trust-sync-grant --remove=1
rs_refused "  a flag given a value (--if-stale=1)" --run trust-sync-grant --if-stale=1
rs_refused "  a flag on a step that does not take it (--if-stale)" --run harden-advisord --if-stale
rs_refused "  a flag given a value (--hand-trees-back=1)" --run advisor-account --hand-trees-back=1
rs_refused "  a flag given a value (--hand-store-back=1)" --run migrate-node --hand-store-back=1
rs_refused "  a path after --hand-store-back (the store is never typed)" --run migrate-node --hand-store-back /srv/node/data
rs_refused "  a flag given twice" --run fleet-broker-grant --remove --remove
rs_refused "  a value with no value after it" --run advisor-account --instance
rs_refused "--instance with ../" --run advisor-account --instance ../x
rs_refused "  a capital" --run dashboard-service --instance Node2
rs_refused "--account with a space" --run advisor-account --account 'my advisor'
rs_refused "  a capital" --run node-config-exposure --account Root
rs_refused "--config relative" --run advisory-delete --config etc/xrpld.cfg
rs_refused "  with .." --run advisory-delete --config /etc/../root/x.cfg
rs_refused "  with a quote" --run advisory-delete --config "/etc/it's.cfg"
# shellcheck disable=SC2016  # the literal text is the point
rs_refused "  with a command substitution" --run advisory-delete --config '/etc/$(id).cfg'
rs_refused "--trust-arm-key with a quote" --run model-key-sealer --trust-arm-key "abc'def"
rs_refused "  with a space" --run model-key-sealer --trust-arm-key 'abc def'
rs_refused "--node-key that is not one" --run model-key-sealer --trust-arm-key "$ARMKEY" --node-key xyz
rs_refused "--port out of range" --run relay-colocated --unit aperire-server --port 70000 --binary /usr/local/bin/aperire-relay
rs_refused "--unit that is not a dashboard's" --run relay-colocated --unit sshd --port 7900 --binary /usr/local/bin/aperire-relay
rs_refused "relay-colocated with one of its three missing" --run relay-colocated --unit aperire-server --binary /usr/local/bin/aperire-relay
rs_refused "--name with a slash" --run node --adopt --name a/b
rs_refused "--run rotation-timer is a step; a near name is not" --run rotation-timers
rs_refused "--service with a space" --run rotation-timer --service 'my node'
rs_refused "--service with a slash" --run rotation-timer --service ../x
rs_refused "--admin-rpc that is not loopback" --run rotation-timer --service x --admin-rpc http://evil.example:5005
rs_refused "  nor a loopback look-alike" --run rotation-timer --service x --admin-rpc http://127.0.0.1.evil.example:5005
rs_refused "  nor a port out of range" --run rotation-timer --service x --admin-rpc http://127.0.0.1:99999
rs_refused "--kind that is neither" --run rotation-timer --service x --kind docker
rs_refused "--config relative" --run rotation-timer --service x --config rippled.cfg
rs_refused "--role it does not know" --run prepare-host --role root
rs_refused "the node's --role is stock or validator" --run node --adopt --role co-located
rs_refused "--image-tag that is not a release version" --run node --adopt --image-tag latest
rs_refused "  with a semicolon" --run node --adopt --image-tag '3.3.0;id'
rs_refused "  with a space" --run node --adopt --image-tag '3.3.0 x'
rs_refused "--dir relative after the step" --run harden-advisord --dir relative
rs_refused "--run with --update" --update --run harden-advisord
rs_refused "  with --check" --check --run harden-advisord
rs_refused "  a --yes before it" --yes --run harden-advisord
rs_refused "  with --role" --role co-located --run harden-advisord
rs_refused "  with the fleet flags" --fleet-aggregator https://agg.example --run harden-advisord
rs_refused "  with a --node-wrapper flag" --node-wrapper x --run harden-advisord
rs_refused "  --run then --backup is its own argument, refused" --run harden-advisord --backup
LC_ALL=en_US.UTF-8 rs_refused "under a UTF-8 locale, an accented account is refused" --run advisor-account --account é

reset
mkdir -p "$TMP/etc/aperire"
write_fake_step_programs "$TMP/op/aperire-one"
run_sut --run fleet-broker-grant < /dev/null
if [[ $RC -ne 0 && "$OUT" == *"is not installed on this host"* && ! -e "$TMP/state/rs-args" && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a host with nothing installed is refused by name, before any root call"
else
  bad "--run on a bare host is refused" "rc=$RC out=$OUT"
fi
rs_installed
rm -f "$TMP/op/aperire-one/scripts/install-trust-sync-grant.sh"
run_sut --run trust-sync-grant < /dev/null
if [[ $RC -ne 0 && "$OUT" == *"install-trust-sync-grant.sh is missing"* && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a checkout without the step's program is refused by name, before any root call"
else
  bad "a missing step program is refused" "rc=$RC out=$OUT"
fi
# A step whose program finds the install from where it sits (one from before
# staged runs) would take the stage for the install. Its staged copy is the
# one judged, and it is never run. One that never reads the install (the node
# config fix) is not held to it.
rs_installed
printf '#!/usr/bin/env bash\n# from before staged runs\nprintf ran > "%s"\n' "$TMP/state/rs-args" \
  > "$TMP/op/aperire-one/scripts/harden-advisord.sh"
run_sut --run harden-advisord < /dev/null
if [[ $RC -ne 0 && "$OUT" == *"predates staged runs"* && "$OUT" == *"--update"* && ! -e "$TMP/state/rs-args" ]]; then
  ok "a step program from before staged runs is refused on its staged copy, with the update to run, and never run"
else
  bad "an old step program is refused" "rc=$RC ran=$(rs_args) out=$OUT"
fi
rs_installed
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$@" > "%s"\n' "$TMP/state/rs-args" \
  > "$TMP/op/aperire-one/scripts/close-node-config-exposure.sh"
run_sut --run node-config-exposure --apply < /dev/null
if [[ $RC -eq 0 && "$(rs_args)" == "--apply " ]]; then
  ok "  and a step whose program never reads the install is not held to it"
else
  bad "a tree-free step runs without the marker" "rc=$RC args=$(rs_args) out=$OUT"
fi

reset

# ── --refresh-node-key: the sealer's node-key stamp, through the bootstrap (#935) ─
#
# `sudo bash <tree>/scripts/install-model-key-sealer.sh --refresh-node-key` was
# the hint the sealer printed, and root running a script the login can change
# is what the staged copy exists to prevent. The bootstrap takes the flag (and
# --node-key, held to the key's own shape before any root call), stages the
# release and runs the checked copy. The fake sudo resets the environment for
# this command the way the real one does, so a variable that leaked in from
# the caller shows up as a row that goes red.
write_fake_sealer_installer() { # $1 = where the checkout is
  mkdir -p "$1/scripts"
  printf 'a fake checkout\n' > "$1/install.sh"
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$1/scripts/trusted-path-lib.sh"
  cat > "$1/scripts/install-model-key-sealer.sh" <<WEOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "\$0" > "$TMP/state/seal-self"
printf '%s\n' "\$*" > "$TMP/state/seal-args"
printf '%s\n' "\${APERIRE_INSTALL_TREE:-}" > "$TMP/state/seal-tree"
printf '%s\n' "\${APERIRE_NODE_ADMIN_RPC-unset}" > "$TMP/state/seal-leak"
printf '%s\n' "\${APERIRE_INSTANCE-unset}" > "$TMP/state/seal-instance"
echo "== stamped"
exit \$(cat "$TMP/state/seal-rc" 2>/dev/null || echo 0)
WEOF
  chmod +x "$1/scripts/install-model-key-sealer.sh"
}
seal_installed() {
  reset
  printf 'aperire-server.service enabled\n' > "$TMP/state/units"
  : > "$TMP/state/sudo-env-reset"
  mkdir -p "$TMP/etc/aperire"
  write_fake_sealer_installer "$TMP/op/aperire-one"
}
NK_VALID=nZyXwVuTsRqPoNmLkJhGfEdCbA98765

echo
echo "--refresh-node-key, --node-key: the sealer's installer runs staged, with a held key (#935):"

seal_installed
APERIRE_NODE_ADMIN_RPC=http://127.0.0.1:1 run_sut --refresh-node-key
if [[ $RC -eq 0 && "$(cat "$TMP/state/seal-args" 2>/dev/null)" == "--refresh-node-key" ]]; then
  ok "--refresh-node-key hands the sealer's installer exactly that flag, and exits with its status"
else
  bad "--refresh-node-key" "rc=$RC args=$(cat "$TMP/state/seal-args" 2>/dev/null) out=$OUT"
fi
self_ran="$(cat "$TMP/state/seal-self" 2>/dev/null)"
if [[ -n "$self_ran" && "$self_ran" != "$TMP/op/aperire-one/"* && "$self_ran" == */scripts/install-model-key-sealer.sh ]]; then
  ok "  and what ran is the staged copy, never the checkout's own"
else
  bad "the staged copy ran" "ran=$self_ran tree=$TMP/op/aperire-one"
fi
if [[ "$(cat "$TMP/state/seal-tree" 2>/dev/null)" == "$TMP/op/aperire-one" ]]; then
  ok "  told which tree it acts on"
else
  bad "the tree reached the installer" "tree=$(cat "$TMP/state/seal-tree" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/state/seal-leak" 2>/dev/null)" == "unset" ]]; then
  ok "  and nothing the caller exported crosses sudo's environment reset"
else
  bad "the environment is reset at the sudo boundary" "saw APERIRE_NODE_ADMIN_RPC=$(cat "$TMP/state/seal-leak" 2>/dev/null)"
fi
if [[ "$OUT" == *"stamping this host's own node key"* && "$OUT" == *"this host's own node key is stamped"* ]]; then
  ok "  and it said what it was doing and what it did"
else
  bad "the announcing and closing lines" "$OUT"
fi

seal_installed
run_sut --refresh-node-key --node-key "$NK_VALID"
if [[ $RC -eq 0 && "$(cat "$TMP/state/seal-args" 2>/dev/null)" == "--refresh-node-key --node-key $NK_VALID" ]]; then
  ok "--node-key is handed over as one word, beside the flag"
else
  bad "--node-key reaches the installer" "args=$(cat "$TMP/state/seal-args" 2>/dev/null) out=$OUT"
fi
seal_installed
run_sut --node-key="$NK_VALID" --refresh-node-key
if [[ $RC -eq 0 && "$(cat "$TMP/state/seal-args" 2>/dev/null)" == "--refresh-node-key --node-key $NK_VALID" ]]; then
  ok "  in the = spelling too, in either order"
else
  bad "--node-key=<key>" "args=$(cat "$TMP/state/seal-args" 2>/dev/null) out=$OUT"
fi
seal_installed
echo 5 > "$TMP/state/seal-rc"
run_sut --refresh-node-key
if [[ $RC -eq 5 && "$OUT" == *"exited 5"* ]]; then
  ok "the installer's own exit status is the run's, with a line that says it did not finish"
else
  bad "the installer's status is passed through" "rc=$RC out=$OUT"
fi

# #949: the node to ask, on a host that runs it as a named instance. Passed
# to the sealer by name, since sudo's env reset would drop it. Only an
# explicit --instance counts: both rows run with a stale APERIRE_INSTANCE
# exported, the way curl | bash keeps a login's exports, and it is never the
# answer.
seal_installed
APERIRE_INSTANCE=node9 run_sut --refresh-node-key --instance node2
if [[ $RC -eq 0 && "$(cat "$TMP/state/seal-args" 2>/dev/null)" == "--refresh-node-key" \
      && "$(cat "$TMP/state/seal-instance" 2>/dev/null)" == node2 ]]; then
  ok "--refresh-node-key --instance node2 hands the sealer APERIRE_INSTANCE=node2"
else
  bad "--instance reaches the sealer (#949)" "rc=$RC args=$(cat "$TMP/state/seal-args" 2>/dev/null) instance=$(cat "$TMP/state/seal-instance" 2>/dev/null) out=$OUT"
fi
seal_installed
APERIRE_INSTANCE=node9 run_sut --refresh-node-key
if [[ $RC -eq 0 && "$(cat "$TMP/state/seal-instance" 2>/dev/null)" == "" ]]; then
  ok "  and without it the sealer is told the default instance, by an empty name, whatever the login exports"
else
  bad "no --instance is the default instance" "instance=$(cat "$TMP/state/seal-instance" 2>/dev/null) out=$OUT"
fi

echo
echo "The same flags, refused before any root call:"
refused_seal_before_root() { # $1 = label, rest = arguments
  local label="$1"; shift
  seal_installed
  run_sut "$@"
  if [[ $RC -ne 0 && ! -e "$TMP/state/seal-args" && ! -e "$TMP/state/sudo-exec" ]]; then
    ok "$label"
  else
    bad "$label" "rc=$RC ran=$(cat "$TMP/state/seal-args" 2>/dev/null) sudo=$(cat "$TMP/state/sudo-exec" 2>/dev/null) out=$OUT"
  fi
}
refused_seal_before_root "a key with a shell metacharacter is refused" --refresh-node-key --node-key "${NK_VALID};id"
# shellcheck disable=SC2016  # the literal text is the point
refused_seal_before_root "  with a command substitution" --refresh-node-key --node-key 'n$(id)aaaaaaaaaaaaaaaaaaaaaaaa'
refused_seal_before_root "  with a newline" --refresh-node-key --node-key "$NK_VALID"$'\nid'
refused_seal_before_root "  not starting with n" --refresh-node-key --node-key "XZyXwVuTsRqPoNmLkJhGfEdCbA98765"
refused_seal_before_root "  with a character base58 leaves out (0)" --refresh-node-key --node-key "n0ZyXwVuTsRqPoNmLkJhGfEdCbA98765"
refused_seal_before_root "  too short" --refresh-node-key --node-key nabc
refused_seal_before_root "  empty (--node-key=)" --refresh-node-key --node-key=
refused_seal_before_root "  an installer flag taken as the value" --refresh-node-key --node-key --refresh
refused_seal_before_root "--node-key without --refresh-node-key says nothing to do" --node-key "$NK_VALID"
refused_seal_before_root "an --instance that is not an instance name" --refresh-node-key --instance '../x'
refused_seal_before_root "  with a shell metacharacter" --refresh-node-key --instance 'node2;id'
refused_seal_before_root "--refresh-node-key with a --node-wrapper flag is still two jobs" --refresh-node-key --instance node2 --node-wrapper-rpc 5005
refused_seal_before_root "--refresh-node-key with --update is refused" --refresh-node-key --update
refused_seal_before_root "  with --check" --refresh-node-key --check
refused_seal_before_root "  with --yes" --refresh-node-key --yes
refused_seal_before_root "  with --role" --refresh-node-key --role co-located
refused_seal_before_root "  with a --node-wrapper flag" --refresh-node-key --node-wrapper xrpld
refused_seal_before_root "  with the fleet flags" --refresh-node-key --fleet-aggregator https://agg.example
refused_seal_before_root "  with --source, it fetches nothing" --refresh-node-key --source https://example.invalid/r.tar.gz

reset
mkdir -p "$TMP/etc/aperire"
write_fake_sealer_installer "$TMP/op/aperire-one"
run_sut --refresh-node-key
if [[ $RC -ne 0 && "$OUT" == *"is not installed on this host"* && ! -e "$TMP/state/seal-args" && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a host with nothing installed is refused by name, installs nothing and makes no root call"
else
  bad "not installed is refused" "rc=$RC out=$OUT"
fi
seal_installed
rm -f "$TMP/op/aperire-one/scripts/install-model-key-sealer.sh"
run_sut --refresh-node-key
if [[ $RC -ne 0 && "$OUT" == *"install-model-key-sealer.sh is missing"* && ! -e "$TMP/state/sudo-exec" ]]; then
  ok "a checkout with no sealer installer in it is refused by name, before any root call"
else
  bad "a missing sealer installer is refused" "rc=$RC out=$OUT"
fi
reset

# ── the update path rebuilds the Advisor when it needs to (#383) ─────
#
# Carrying advisor/bin across an update (#350) is not the same as keeping it
# CORRECT. install.sh only rebuilds it with --with-advisor, and an update
# never passes that, so the binary carried above would otherwise run
# forever, on every release after the one that built it, unless
# rebuild_advisor_if_installed() steps in. What has to hold: a real change
# in advisor/'s Go source is rebuilt and stamped with the release commit; an
# unchanged tree whose binary already carries that stamp is left alone; an
# unchanged tree whose binary's stamp is stale, or too old to answer
# -version at all, is rebuilt anyway; a host with no Go on its PATH keeps
# the carried binary and says so by name; and a unit that was not running
# before the update is built for, never started.
#
# The suite's one shared release.tar.gz carries no advisor/ Go source at
# all, so each row below gets its own tiny archive, its own commit and its
# own published copy of the bootstrap, the same way the release-stamp rows
# above make PUBLISHED_COPY.

echo
echo "The update path rebuilds the Advisor when it needs to (#383):"

# Two commands, one module, a marker comment: the same marker in the old
# tree and the new one is "nothing changed", a different one is a real
# source diff, which is what advisor_sources_changed() reads (as a
# checksum, never a timestamp, so a freshly unpacked tree cannot fake it).
make_advisor_source() { # $1 = advisor/ root, $2 = a marker string
  mkdir -p "$1/cmd/aperire-advisord" "$1/cmd/aperire-executor" "$1/cmd/knowledge-lint"
  printf 'module aperire-advisor-fixture\n\ngo 1.21\n' > "$1/go.mod"
  printf '// %s\npackage main\n\nfunc main() {}\n' "$2" > "$1/cmd/aperire-advisord/main.go"
  printf '// %s\npackage main\n\nfunc main() {}\n' "$2" > "$1/cmd/aperire-executor/main.go"
  printf '// %s\npackage main\n\nfunc main() {}\n' "$2" > "$1/cmd/knowledge-lint/main.go"
}

# The carried binary, answering -version the way the real one does: a
# commit when it was built stamped, nothing (exit 2, no stdout) when it
# predates the flag, which is what advisor_stamp_stale() reads as stale.
make_advisor_binary() { # $1 = path, $2 = the commit it answers -version with, or "" for none
  # shellcheck disable=SC2016  # $1 is the generated script's own, matched by it, never expanded here
  if [[ -n "$2" ]]; then
    printf '#!/bin/sh\ncase "$1" in -version) echo %s ;; *) echo carried-binary ;; esac\n' "$2" > "$1"
  else
    printf '#!/bin/sh\ncase "$1" in -version) exit 2 ;; *) echo carried-binary ;; esac\n' > "$1"
  fi
  chmod +x "$1"
}

# A release archive with its own advisor/ source and its own stamp. Sets
# ADV_TARBALL, ADV_SHA and ADV_COPY (a published bootstrap pointing at
# both), the same shape PUBLISHED_COPY is above, one per row rather than
# shared: each row needs its own pairing of "did the source change" and
# "what commit is this release".
# ADV_PINNED_GO, read here rather than taken as an argument: every row goes
# through this one function, and a literal path in the script under test
# cannot be reached by an env var the way DEFAULT_SOURCE_URL and friends
# above can. Unset (the default set by reset(), below), it points
# advisor_go_bin()'s pinned candidate at a fixture path this suite never
# creates, so a runner whose real /usr/local/go happens to hold a working Go
# cannot make a row pass, or fail, by accident (#633; the risk this guards
# against is the one test-advisord-go-probe.sh already met with /usr/bin/go
# on 2026-09-07). Row 6 sets it to a fixture it DOES create, to prove the
# pinned location is actually read.
make_advisor_release() { # $1 = advisor source marker, $2 = commit
  local root="$TMP/advisor-rel-$2"
  rm -rf "$root"
  mkdir -p "$root/aperire-one"
  cp -r "$TMP/release/." "$root/aperire-one/"
  rm -rf "$root/aperire-one/advisor"
  make_advisor_source "$root/aperire-one/advisor" "$1"
  ADV_TARBALL="$TMP/advisor-release-$2.tar.gz"
  rm -f "$ADV_TARBALL"
  tar -czf "$ADV_TARBALL" -C "$root" aperire-one
  ADV_SHA="$(sha256sum "$ADV_TARBALL" | cut -d' ' -f1)"
  ADV_COPY="$TMP/advisor-published-$2.sh"
  sed -e "s|^DEFAULT_SOURCE_URL=.*|DEFAULT_SOURCE_URL='file://$ADV_TARBALL'|" \
      -e "s|^DEFAULT_EXPECTED_SHA256=.*|DEFAULT_EXPECTED_SHA256='$ADV_SHA'|" \
      -e "s|^DEFAULT_RELEASE_TAG=.*|DEFAULT_RELEASE_TAG='snapshot-advisor-$2'|" \
      -e "s|^DEFAULT_RELEASE_COMMIT=.*|DEFAULT_RELEASE_COMMIT='$2'|" \
      -e "s|^DEFAULT_PUBLISHED_AT=.*|DEFAULT_PUBLISHED_AT='2026-09-15T00:00:00Z'|" \
      -e "s#/usr/local/go/bin/go#${ADV_PINNED_GO:-$TMP/no-pinned-go/bin/go}#" \
      "$SUT" > "$ADV_COPY"
}

builds_asked() { grep -c '^build ' "$TMP/state/go-build-calls" 2>/dev/null || echo 0; }

# #787's two guards, as functions every row below can ask.
#
# unmatched_stops: every `stop <unit>` the run made, with no `start` or
# `restart` naming that unit later in the same call log. A stop with no
# start after it is a service this run took down and left down.
unmatched_stops() {
  local -a calls=()
  local i j u later found
  [[ -f "$TMP/state/systemctl-calls" ]] || return 0
  mapfile -t calls < "$TMP/state/systemctl-calls"
  for ((i = 0; i < ${#calls[@]}; i++)); do
    [[ "${calls[i]}" == "stop "* ]] || continue
    for u in ${calls[i]#stop }; do
      [[ "$u" == -* ]] && continue
      found=0
      for ((j = i + 1; j < ${#calls[@]}; j++)); do
        later="${calls[j]}"
        [[ "$later" == "start "* || "$later" == "restart "* ]] || continue
        [[ " ${later#* } " == *" $u "* ]] && { found=1; break; }
      done
      [[ $found -eq 1 ]] || printf '%s\n' "$u"
    done
  done
}
# running_claims_down: every unit the closing text lists as still running
# whose own is-active answer is not active. The list is the indented lines
# under "still running, on the old code:" up to the first line with nothing
# after its indent.
running_claims_down() {
  local u
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    [[ "$(cat "$TMP/state/active-$u" 2>/dev/null)" == active ]] || printf '%s\n' "$u"
  done < <(awk '/still running, on the old code:/ {on=1; next}
               on && /^[[:space:]]*$/ {if (seen) exit; next}
               on {gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; seen=1}' <<<"$OUT")
}
# The scratch name is the build's target, never the live binary's, and
# nothing is left behind under it.
advisor_build_outputs_ok() { # $1 = label
  local live_o left
  live_o="$(grep -E -- '-o bin/(aperire-advisord|aperire-executor|knowledge-lint)( |$)' "$TMP/state/go-build-calls" 2>/dev/null || true)"
  left="$(find "$TMP/op/aperire-one/advisor/bin" -maxdepth 1 -name '.*.new.*' 2>/dev/null)"
  if [[ -z "$live_o" && -z "$left" ]]; then
    ok "$1 built to a scratch name and renamed into place; nothing was written at the live binary's name, and no scratch file is left"
  else
    bad "$1 never builds at the live name and leaves no scratch file" "built at live name: ${live_o:-none}; left: ${left:-none}"
  fi
}

# A Go too old for the Advisor's own minimum (advisor/go.mod pins 1.23):
# answers `version` honestly, and fails everything else, so a row that
# ends up building through this one anyway fails loudly rather than
# quietly passing on a binary this project could not really have built.
make_old_go_shim() { # $1 = path to write, $2 = identity recorded in go-used
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "$2" >> "$TMP/state/go-used"
if [[ "\${1:-}" == version ]]; then
  echo "go version go1.20.0 linux/amd64"
  exit 0
fi
exit 1
EOF
  chmod +x "$1"
}

# Row 1: a real source change. Rebuilt, and stamped with the release commit.
# The unit is running, so this row also carries the stop-before-build and
# the restart-after: capture_running_units freezes the "was running" list
# before any of this, so the same unit that is stopped here is the one
# offer_the_restart brings back at the very end.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000abc"
stamp_an_older_release
make_advisor_release "NEW-SOURCE" "1111111"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "main.version=1111111" "$TMP/state/go-build-calls" \
   && grep -q "rebuilt, stamped 1111111" <<<"$OUT"; then
  ok "a real change in advisor/'s Go source is rebuilt and stamped with the release commit"
else
  bad "a source change triggers a rebuild, stamped with the commit" \
      "builds=$(builds_asked) out=$OUT"
fi
if [[ "$("$TMP/op/aperire-one/advisor/bin/aperire-advisord" -version 2>/dev/null)" == "1111111" ]]; then
  ok "and the binary this host now has answers -version with that commit"
else
  bad "the rebuilt binary answers -version with the release commit" \
      "$("$TMP/op/aperire-one/advisor/bin/aperire-advisord" -version 2>&1)"
fi
# Never stopped, and never written at its own name (#787). This row used to
# assert the opposite, a stop before the build and a restart after it; that
# stop is what left an unattended update with no Advisor. Now the build goes
# to a scratch name and is renamed over the old one, the running process
# keeps its inode, and --yes restarts it once, at the end, onto the new build.
if ! grep -q '^stop aperire-advisord.service$' "$TMP/state/systemctl-calls" 2>/dev/null \
   && grep -qE '^restart .*aperire-advisord.service' "$TMP/state/systemctl-calls" 2>/dev/null \
   && [[ "$(cat "$TMP/state/active-aperire-advisord.service")" == active ]]; then
  ok "a running Advisor is never stopped for its rebuild, and --yes restarts it once onto the new build"
else
  bad "the running unit is not stopped around the rebuild, and is restarted at the end" \
      "$(cat "$TMP/state/systemctl-calls" 2>/dev/null)"
fi
advisor_build_outputs_ok "the rebuild"

# Row 2: nothing changed, and the carried binary already answers -version
# with the commit this run is applying. Carried, not rebuilt.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "SAME-SOURCE"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "2222222"
make_advisor_binary "$KEPT/advisor/bin/knowledge-lint" "2222222"
stamp_an_older_release
make_advisor_release "SAME-SOURCE" "2222222"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 0 ]] && grep -q "already stamped 2222222; carried, not rebuilt" <<<"$OUT"; then
  ok "an unchanged source tree whose binary already carries that stamp is carried, not rebuilt"
else
  bad "an unchanged, already-stamped binary is left alone" "builds=$(builds_asked) out=$OUT"
fi
if [[ "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)" == *"carried-binary"* ]]; then
  ok "and the binary on disk is the one that was carried, not one the go shim wrote"
else
  bad "the carried binary is untouched" "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)"
fi
if ! grep -q 'stop aperire-advisord.service' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "and nothing here stopped a unit for a rebuild that never happened"
else
  bad "a carry with no rebuild never stops the unit" "$(cat "$TMP/state/systemctl-calls" 2>/dev/null)"
fi

# Row 3: nothing changed, and the carried binary predates -version (empty,
# exit non-zero). Read as stale on purpose, the opposite of
# prepare-host.sh's own stamp_stale(): this is the only signal an update
# with an unchanged source tree has left.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo inactive > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "STABLE-SOURCE"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" ""
stamp_an_older_release
make_advisor_release "STABLE-SOURCE" "3333333"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "rebuilt, stamped 3333333" <<<"$OUT"; then
  ok "an unchanged tree whose binary cannot answer -version at all is rebuilt, not carried"
else
  bad "a binary too old to answer -version is read as stale" "builds=$(builds_asked) out=$OUT"
fi

# Row 4: a real source change, and no Go anywhere advisor_go_bin looks (the
# pinned default here is the fixture make_advisor_release() points at when
# ADV_PINNED_GO is unset, which this suite never creates). Named skip, the
# carried binary is what this host still runs, and the remedy printed is
# the one that actually fixes it, not the Advisor's own installer.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-NOGO"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-NOGO" "4444444"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 0 ]] && grep -q 'no Go toolchain anywhere this looks' <<<"$OUT" \
   && grep -q -- '--run prepare-host --with-advisor' <<<"$OUT" \
   && grep -q 'bash -s -- --update --force' <<<"$OUT"; then
  ok "a host with no Go toolchain is told so by name, and given the two commands that actually fix it"
else
  bad "a missing Go toolchain is a named skip, with a working remedy" "builds=$(builds_asked) out=$OUT"
fi
# Not install-advisor-stack.sh (#633, Opus review): that installer honors a
# carried, executable binary as a prebuilt one and re-registers it rather
# than rebuilding, so naming it here would be a remedy that does nothing.
if ! grep -q 'install-advisor-stack.sh' <<<"$OUT"; then
  ok "and the remedy named is not the command that would re-register this exact stale build"
else
  bad "install-advisor-stack.sh is not named as the fix for a missing Go toolchain" "$OUT"
fi
if [[ "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)" == *"carried-binary"* ]] \
   && ! grep -q 'stop aperire-advisord.service' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "and the carried binary is untouched, never stopped for a build that could not run"
else
  bad "the carried binary survives a host with no Go" \
      "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)"
fi

# Row 5: a real source change, and the unit was not running before the
# update. Built, because the release still has to be correct on disk, and
# never started: capture_running_units never saw it running, so
# offer_the_restart never offers it.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo inactive > "$TMP/state/active-aperire-advisord.service"
# Three that are installed and not running and are no service to start:
# a timer's oneshot, a socket's per-connection template, and a unit the
# operator disabled. #803's line names none of them.
printf 'aperire-verify.service enabled\naperire-trust-sync@.service static\naperire-can-delete.service disabled\n' >> "$TMP/state/units"
mkdir -p "$TMP/etc/systemd/system"
printf '[Service]\nType=oneshot\n' > "$TMP/etc/systemd/system/aperire-verify.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-DOWN"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-DOWN" "5555555"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "rebuilt, stamped 5555555" <<<"$OUT"; then
  ok "a unit that was not running is still built for, so the release on disk is correct either way"
else
  bad "an inactive unit is built for" "builds=$(builds_asked) out=$OUT"
fi
if ! grep -q 'stop aperire-advisord.service' "$TMP/state/systemctl-calls" 2>/dev/null \
   && ! grep -qE '^restart .*aperire-advisord' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "and it is never stopped or started: it was not running, and this is not the thing that starts it"
else
  bad "an inactive unit is built for, not started" "$(cat "$TMP/state/systemctl-calls" 2>/dev/null)"
fi
# #803: and it is NAMED. The closing text used to list only what was running
# at the start, so an Advisor already down ended a run that read as all up.
if grep -q 'Installed and enabled, and NOT running' <<<"$OUT" \
   && grep -qE 'aperire-advisord\.service \(inactive\)' <<<"$OUT" \
   && grep -qF 'sudo systemctl start aperire-advisord.service' <<<"$OUT" \
   && ! grep -qE '^  .*aperire-(server|relay|verify|trust-sync@|can-delete)\.service \(' <<<"$OUT"; then
  ok "an installed, enabled Advisor that was down before the update is named as not running, with its start command"
else
  bad "the closing text names an installed unit that is not running (#803)" "$(tail -25 <<<"$OUT")"
fi
reset

# Row 5b (#787): the dashboard's own path, --update --yes --no-restart, with
# the Advisor running and a real source change. Nothing restarts and nothing
# stops: the Advisor is still running afterwards, on its old build, and the
# closing text says exactly that. This is the run that left aperire4 with no
# Advisor on 2026-10-02 while it printed "still the old ones".
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-NR"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-NR" "5b5b5b5"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes --no-restart
stops="$(unmatched_stops)"
if [[ "$(builds_asked)" == 3 && -z "$stops" ]] \
   && [[ "$(cat "$TMP/state/active-aperire-advisord.service")" == active ]] \
   && ! grep -qE '^(stop|start|restart) .*aperire-advisord' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "--update --yes --no-restart rebuilds the Advisor and leaves it running: no stop, so nothing to start again"
else
  bad "--no-restart never leaves the Advisor stopped" \
      "builds=$(builds_asked) unmatched stops: ${stops:-none}; calls: $(tr '\n' '|' < "$TMP/state/systemctl-calls" 2>/dev/null)"
fi
down="$(running_claims_down)"
if [[ -z "$down" ]] && grep -q 'still running, on the old code:' <<<"$OUT" \
   && grep -qE '^[[:space:]]+aperire-advisord\.service$' <<<"$OUT" \
   && grep -qF 'sudo systemctl restart' <<<"$OUT" && ! grep -q 'NOT running now' <<<"$OUT"; then
  ok "and the closing text lists it as still running on the old code, which it is"
else
  bad "the closing text is true of every unit it lists" "listed but down: ${down:-none}; $(tail -20 <<<"$OUT")"
fi
if [[ "$("$TMP/op/aperire-one/advisor/bin/aperire-advisord" -version 2>/dev/null)" == "5b5b5b5" ]]; then
  ok "and the binary on disk is the new build, ready for the restart the text names"
else
  bad "the new build is in place after --no-restart" "$("$TMP/op/aperire-one/advisor/bin/aperire-advisord" -version 2>&1)"
fi
advisor_build_outputs_ok "and that rebuild"

# Row 5c (#787): the first binary builds and the second fails. Neither is
# swapped (the daemon is not left newer than its executor), the one that did
# build is not left under its scratch name, and the Advisor was never
# stopped for it.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-FAIL"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-FAIL" "5c5c5c5"
echo aperire-executor > "$TMP/state/go-fail"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes --no-restart
left="$(find "$TMP/op/aperire-one/advisor/bin" -maxdepth 1 -name '.*.new.*' 2>/dev/null)"
if [[ "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)" == *"carried-binary"* && -z "$left" ]] \
   && grep -q 'the Advisor rebuild failed' <<<"$OUT" && [[ -z "$(unmatched_stops)" ]] \
   && [[ "$(cat "$TMP/state/active-aperire-advisord.service")" == active ]]; then
  ok "a failed rebuild keeps the previous binary, leaves no scratch file, and never stopped the Advisor"
else
  bad "a failed rebuild changes nothing" "left=${left:-none} stops=$(unmatched_stops) $(tail -12 <<<"$OUT")"
fi

# Row 5d (#787): something takes the Advisor down while the update runs. The
# closing text reads systemd again before it speaks: the unit is named as
# NOT running, with the command that starts it, and never listed as still
# running the old code. This run does not start it: it does not know why it
# went down.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-DOWNED"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-DOWNED" "5d5d5d5"
touch "$TMP/state/go-down-advisord"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes --no-restart
down="$(running_claims_down)"
if [[ -z "$down" ]] && grep -q 'NOT running now' <<<"$OUT" \
   && grep -qE 'aperire-advisord\.service \(inactive\)' <<<"$OUT" \
   && grep -qF 'sudo systemctl start aperire-advisord.service' <<<"$OUT" \
   && ! grep -qE '^(start|restart) .*aperire-advisord' "$TMP/state/systemctl-calls" 2>/dev/null; then
  ok "a unit captured running and down by the end is named as down, with its start command, never as still running"
else
  bad "the closing text never claims a down unit is running" "listed but down: ${down:-none}; $(tail -20 <<<"$OUT")"
fi
reset

# ── the Advisor is asked its version as the operator, from / (#1201) ──
#
# advisor_stamp_stale ran the binary with the run's own EUID. The page update
# runs this bootstrap as root, and advisor/bin is the operator's directory (the
# Advisor's account owns what it writes there), so root executed a program the
# login can replace: ADR 0024, root never runs what the login can change. The
# rows lift the real functions out of the script under test and run them under
# fakeroot, where EUID is 0 and everything root does is root's. The sudo is a
# stand-in that behaves like the real one on the one point that matters: it
# resets the environment, and the only way a program can learn it was handed to
# the operator is the marker the stand-in sets after the reset. A stand-in that
# passed the caller's environment through would let a row pass by leak.

echo
echo "The Advisor is asked its version as the operator, from /, never as root (#1201):"

if ! command -v fakeroot >/dev/null 2>&1; then
  bad "fakeroot is here for the Advisor-version rows" "fakeroot is not installed; who the Advisor was asked as was not measured"
else
  FK="$TMP/fk1201"; rm -rf "$FK"; mkdir -p "$FK/shim" "$FK/dir/advisor/bin" "$FK/noenter" "$FK/home"
  OPNAME="$(id -un)"
  cat > "$FK/shim/sudo" <<FAKESUDO
#!/usr/bin/env bash
user=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in -n|-H|-E) shift ;; -u) user="\$2"; shift 2 ;; --) shift; break ;; -*) shift ;; *) break ;; esac
done
exec env -i HOME="$FK/home" PATH="$FK/shim:/usr/bin:/bin" RAN_AS_OPERATOR="\$user" "\$@"
FAKESUDO
  chmod +x "$FK/shim/sudo"
  # The three programs advisor/bin holds, owned by the login (this account) and
  # each recording who ran it and from where. Go will not run from a directory
  # its user cannot search; the test's directory is enterable, so that refusal
  # is modelled by name. The stamp each answers with is state/stamp-<name>.
  for b in aperire-advisord aperire-executor knowledge-lint; do
    cat > "$FK/dir/advisor/bin/$b" <<FAKEBIN
#!/usr/bin/env bash
[[ "\$PWD" == "$FK/noenter" ]] && { echo "cannot determine current directory" >&2; exit 1; }
printf '%s as=%s cwd=%s args=%s\n' "$b" "\${RAN_AS_OPERATOR:-root}" "\$PWD" "\$*" >> "$FK/log"
case "\$1" in -version|version) cat "$FK/stamp-$b" ;; esac
FAKEBIN
    chmod +x "$FK/dir/advisor/bin/$b"
    echo abc1234 > "$FK/stamp-$b"
  done
  lift_fn() { awk -v n="$1" '$0 ~ "^" n "\\(\\) \\{" {p=1} p {print} p && /^}$/ {exit}' "$SUT"; }
  {
    echo 'NO_COLOR_ENV=()'
    echo "OP_USER=$OPNAME"
    echo "DIR=$FK/dir"
    lift_fn as_operator; lift_fn advisor_ask; lift_fn advisor_stamp_stale; lift_fn advisor_unstamped
  } > "$FK/fns.sh"
  if [[ "$(grep -c '^[a-z_]*() {' "$FK/fns.sh")" -eq 4 ]]; then
    ok "the lift found as_operator, advisor_ask, advisor_stamp_stale and advisor_unstamped in the real script"
  else
    bad "the lift found the four functions" "$(grep '^[a-z_]*() {' "$FK/fns.sh")"
  fi
  fk_run() { # $1 = the functions file, $2 = the command to run in it, $3 = the directory to start in
    rm -f "$FK/log"
    ( cd "$3" && env -i PATH="$FK/shim:/usr/bin:/bin" HOME="$FK/home" fakeroot bash -c ". \"$1\"; $2" 2>&1 )
  }
  asked_by() { # the accounts the recording programs saw, one word per ask
    sed -nE 's/.* as=([^ ]+) .*/\1/p' "$FK/log" 2>/dev/null | sort -u | tr '\n' ' '
  }
  BIN="$FK/dir/advisor/bin/aperire-advisord"

  out="$(fk_run "$FK/fns.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" /)"
  if [[ "$out" == *"rc=1"* && "$(asked_by)" == "$OPNAME " ]] && grep -q 'cwd=/ ' "$FK/log"; then
    ok "advisor_stamp_stale asks the binary as the operator under root, from /, and a matching stamp reads as current"
  else
    bad "advisor_stamp_stale asks as the operator" "$out: asked by '$(asked_by)': $(cat "$FK/log" 2>/dev/null)"
  fi
  echo def5678 > "$FK/stamp-aperire-advisord"
  out="$(fk_run "$FK/fns.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" /)"
  if [[ "$out" == *"rc=0"* && "$(asked_by)" == "$OPNAME " ]]; then
    ok "  and a different stamp reads as stale, the answer still the operator's"
  else
    bad "a different stamp reads as stale" "$out: asked by '$(asked_by)'"
  fi
  echo abc1234 > "$FK/stamp-aperire-advisord"
  out="$(fk_run "$FK/fns.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" "$FK/noenter")"
  if [[ "$out" == *"rc=1"* && "$(asked_by)" == "$OPNAME " ]]; then
    ok "  and started from a directory the login cannot search it still gets its answer, because the ask is made from /"
  else
    bad "the ask does not depend on the starting directory" "$out: asked by '$(asked_by)'"
  fi
  out="$(fk_run "$FK/fns.sh" "advisor_unstamped abc1234 aperire-advisord aperire-executor knowledge-lint; echo rc=\$?" "$FK/noenter")"
  if [[ "$out" == "rc=0" && "$(asked_by)" == "$OPNAME " && "$(wc -l < "$FK/log")" -eq 3 ]] && ! grep -q 'cwd=/[^ ]' "$FK/log"; then
    ok "advisor_unstamped asks all three binaries as the operator from /, and names none of them"
  else
    bad "advisor_unstamped asks as the operator from /" "$out: asked by '$(asked_by)': $(cat "$FK/log" 2>/dev/null)"
  fi
  echo old0000 > "$FK/stamp-aperire-executor"
  out="$(fk_run "$FK/fns.sh" "advisor_unstamped abc1234 aperire-advisord aperire-executor knowledge-lint" /)"
  if [[ "$out" == "aperire-executor" ]]; then
    ok "  and a binary that answers with another commit is the one it names"
  else
    bad "advisor_unstamped names the stale binary" "$out"
  fi
  echo abc1234 > "$FK/stamp-aperire-executor"

  # Each of these is the functions with one line of the fix taken out, and each
  # must turn a row above red. The first is the issue's own ablation.
  cut_fns() { # $1 = out, $2 = sed script, $3 = a fragment the result must hold
    sed "$2" "$FK/fns.sh" > "$1"
    if cmp -s "$FK/fns.sh" "$1"; then echo "the cut for $1 matched nothing; the row would prove nothing"; exit 1; fi
    grep -qF -- "$3" "$1" || { echo "the cut for $1 took out more than its line"; exit 1; }
  }
  # shellcheck disable=SC2016  # literal sed text and fragments to find, not expressions
  {
  cut_fns "$FK/no-asop.sh" 's#^  ( cd / \&\& as_operator "\$@" ) 2>/dev/null$#  ( cd / \&\& "$@" ) 2>/dev/null#' '( cd / && "$@" )'
  cut_fns "$FK/old-stale.sh" 's#^  have="\$(advisor_ask "\$1" -version || true)"$#  have="$("$1" -version 2>/dev/null || true)"#' 'have="$("$1" -version 2>/dev/null || true)"'
  cut_fns "$FK/no-cd.sh" 's#^  ( cd / \&\& as_operator "\$@" ) 2>/dev/null$#  ( as_operator "$@" ) 2>/dev/null#' '( as_operator "$@" )'
  cut_fns "$FK/no-drop.sh" 's#^  if \[\[ \$EUID -eq 0 \&\& "\$OP_USER" != "root" \]\]; then$#  if false; then#' '  if false; then'
  }
  out="$(fk_run "$FK/no-asop.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" /)"
  if [[ "$(asked_by)" == "root " ]]; then
    ok "control: with as_operator taken out of the ask, the binary records root, so the row above can fail"
  else
    bad "control: as_operator is what the account row turns on" "$out: asked by '$(asked_by)'"
  fi
  out="$(fk_run "$FK/old-stale.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" /)"
  if [[ "$(asked_by)" == "root " ]]; then
    ok "control: the old direct call in advisor_stamp_stale records root, which is the bug (#1201)"
  else
    bad "control: the direct call is what the account row turns on" "$out: asked by '$(asked_by)'"
  fi
  out="$(fk_run "$FK/no-cd.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" "$FK/noenter")"
  if [[ "$out" == *"rc=0"* ]]; then
    ok "control: asked from the starting directory, a current binary reads as stale for a login that cannot search it"
  else
    bad "control: the cd / is what the starting-directory row turns on" "$out"
  fi
  out="$(fk_run "$FK/no-cd.sh" "advisor_unstamped abc1234 aperire-advisord aperire-executor knowledge-lint" "$FK/noenter")"
  if [[ "$(wc -l <<<"$out")" -eq 3 ]]; then
    ok "control: and advisor_unstamped would call all three binaries unstamped"
  else
    bad "control: the cd / is what the unstamped row turns on" "$out"
  fi
  out="$(fk_run "$FK/no-drop.sh" "advisor_stamp_stale '$BIN' abc1234; echo rc=\$?" /)"
  if [[ "$(asked_by)" == "root " ]]; then
    ok "control: with the drop to the operator taken out of as_operator, the ask records root"
  else
    bad "control: the drop in as_operator is what the account row turns on" "$out: asked by '$(asked_by)'"
  fi
fi

# ── the corpus linter is built with the other two (#1131, #1133) ────
#
# knowledge-lint is the third binary the Advisor's build makes. The update's
# own loop named only the daemon and the executor, so a host installed from a
# release (no Go at install time) never had one, and an update whose sources
# had not changed said "carried, not rebuilt" for ever. Three promises: the
# build, the rename and the clean-up all name it; a host that has the daemon
# current and no linter is rebuilt anyway; and a build that fails on it swaps
# nothing.
echo
echo "The corpus linter is part of the Advisor build (#1131, #1133):"

# L1: nothing changed, the daemon already carries the stamp, and there is no
# linter. Judged on the daemon alone this is the carry above.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "LINT-SOURCE"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "1a1a1a1"
stamp_an_older_release
make_advisor_release "LINT-SOURCE" "1a1a1a1"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes --no-restart
if [[ "$(builds_asked)" == 1 ]] && grep -q "knowledge-lint built, stamped 1a1a1a1; the Advisor itself is unchanged" <<<"$OUT" \
   && grep -q 'cmd/knowledge-lint' "$TMP/state/go-build-calls" \
   && ! grep -q 'cmd/aperire-advisord\|cmd/aperire-executor' "$TMP/state/go-build-calls" \
   && [[ "$("$TMP/op/aperire-one/advisor/bin/knowledge-lint" -version 2>/dev/null)" == "1a1a1a1" ]] \
   && [[ "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)" == *"-version"* ]]; then
  ok "an Advisor current in source and stamp but with no corpus linter builds the linter alone, and it answers with the release"
else
  bad "a missing linter builds the linter and nothing else" "builds=$(builds_asked) out=$OUT"
fi
advisor_build_outputs_ok "and that build"
if grep -c '^build ' "$TMP/state/go-build-calls" >/dev/null && grep -q -- "-X main.version=1a1a1a1.* -o bin/.knowledge-lint" "$TMP/state/go-build-calls"; then
  ok "  the linter is built with the same -ldflags as the others"
else
  bad "the linter is built with the release stamp" "$(cat "$TMP/state/go-build-calls")"
fi

# L2: the third build fails. Neither of the others is swapped, nothing is left
# under a scratch name, and no linter appears.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "LINT-FAIL-OLD"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
make_advisor_binary "$KEPT/advisor/bin/aperire-executor" "0000000"
stamp_an_older_release
make_advisor_release "LINT-FAIL-NEW" "1b1b1b1"
echo knowledge-lint > "$TMP/state/go-fail"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes --no-restart
left="$(find "$TMP/op/aperire-one/advisor/bin" -maxdepth 1 -name '.*.new.*' 2>/dev/null)"
if [[ "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-advisord" 2>/dev/null)" == *"carried-binary"* \
   && "$(cat "$TMP/op/aperire-one/advisor/bin/aperire-executor" 2>/dev/null)" == *"carried-binary"* \
   && ! -e "$TMP/op/aperire-one/advisor/bin/knowledge-lint" && -z "$left" ]] \
   && grep -q 'the Advisor rebuild failed' <<<"$OUT"; then
  ok "a build that fails on the linter swaps nothing and leaves no scratch file"
else
  bad "a failed linter build changes nothing" "left=${left:-none} $(tail -12 <<<"$OUT")"
fi

# L3: nothing changed, no linter, and no Go to build one. Said as what it is:
# the Advisor is current and Promote cannot lint, with the step that fixes it,
# in the run and again at the end.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "LINT-NOGO"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "1c1c1c1"
stamp_an_older_release
make_advisor_release "LINT-NOGO" "1c1c1c1"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes --no-restart
banner_line="$(grep -n '^  This host moved from' <<<"$OUT" | head -1 | cut -d: -f1)"
close_line="$(grep -n 'knowledge-lint is missing, so Promote cannot lint a note' <<<"$OUT" | head -1 | cut -d: -f1)"
if [[ "$(builds_asked)" == 0 ]] && grep -q 'advisor/bin/knowledge-lint is missing, and this host has no Go toolchain' <<<"$OUT" \
   && grep -q -- '--run prepare-host --with-advisor' <<<"$OUT" \
   && ! grep -q 'the Advisor changed in this release' <<<"$OUT" \
   && ! grep -q 'the Advisor is still on its previous build' <<<"$OUT" \
   && [[ -n "$banner_line" && -n "$close_line" && "$close_line" -gt "$banner_line" ]]; then
  ok "no linter and no Go is told as a missing linter, not as a stale Advisor, in the run and after the banner"
else
  bad "a missing linter with no Go is named as itself" "builds=$(builds_asked) banner=$banner_line close=$close_line out=$OUT"
fi
reset

# L4: the closing summary finds that verdict by its key, never by its wording
# (#838): the sentence is reworded where it is set, in the copy under test, and
# the summary still names the missing linter and the step that fixes it. A
# check that compared the sentence would stop matching here.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "LINT-NOGO2"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "1d1d1d1"
stamp_an_older_release
make_advisor_release "LINT-NOGO2" "1d1d1d1"
sed -i '/ADVISOR_CARRIED_REASON="no corpus linter/s/no corpus linter, and no Go toolchain to build it/nothing on this host can build the linter/' "$ADV_COPY"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes --no-restart
if grep -qF 'knowledge-lint is missing, so Promote cannot lint a note (nothing on this host can build the linter)' <<<"$OUT" \
   && ! grep -q 'the Advisor is still on its previous build' <<<"$OUT" \
   && [[ "$(grep -c -- '--run prepare-host --with-advisor' <<<"$OUT")" -ge 2 ]]; then
  ok "the closing summary finds the missing-linter verdict by its key: reword the sentence and it still names the linter and the fix"
else
  bad "the carried verdict is matched by key, not by sentence" "$(tail -14 <<<"$OUT")"
fi
reset

# L5: "stamped" is printed only for a binary that answered with the commit. The
# build of the linter drops its stamp here, as a package without a version
# symbol would, and the run says which program did not answer.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "STAMP-OLD"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
make_advisor_binary "$KEPT/advisor/bin/aperire-executor" "0000000"
stamp_an_older_release
make_advisor_release "STAMP-NEW" "1e1e1e1"
echo knowledge-lint > "$TMP/state/go-unstamped"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes --no-restart
if [[ "$(builds_asked)" == 3 ]] && grep -q 'built, but knowledge-lint did not answer 1e1e1e1 when asked' <<<"$OUT" \
   && ! grep -q 'rebuilt, stamped 1e1e1e1' <<<"$OUT"; then
  ok "a rebuild does not claim a stamp for a program that does not answer with the commit, and names it"
else
  bad "stamped is claimed only for a binary that answers" "builds=$(builds_asked) out=$(tail -12 <<<"$OUT")"
fi
rm -f "$TMP/state/go-unstamped"
reset

# The guard on the source: every site that builds the executor builds the
# linter, and the update's own loop reads one list for the build, the rename
# and the clean-up. A fourth loop that named the pair would put a half-built
# set back.
# shellcheck disable=SC2016  # literal program text to count, not an expansion
if [[ "$(grep -c 'in "${ADVISOR_BINARIES\[@\]}"' "$SUT")" == 3 ]] \
   && grep -q '^ADVISOR_BINARIES=(aperire-advisord aperire-executor knowledge-lint)$' "$SUT" \
   && ! grep -q 'for name in aperire-advisord aperire-executor' "$SUT"; then
  ok "the build, the rename and the clean-up read one list, and the list names the linter"
else
  bad "advisor_build_and_swap names the linter in all three loops" "$(grep -n 'ADVISOR_BINARIES\|for name in aperire' "$SUT")"
fi

# ── the trust sync unit is brought up to date by the update (#800, #1133) ─
#
# An older trust-sync unit logs "Unknown key name" on every passkey
# enrollment, and fixing the installer did not reach a host that already had
# it. The update runs the grant installer's --if-stale out of the staged copy,
# only when the unit is installed here. The fake sudo resets the environment
# for staged programs, so nothing the caller exported can reach it.
echo
echo "The update refreshes the trust sync unit (#800, #1133):"

# A grant installer that records how it was run. Put in the release before the
# row's archive is cut from it, taken out again after.
write_fake_grant_installer() {
  cat > "$TMP/release/scripts/install-trust-sync-grant.sh" <<WEOF
#!/usr/bin/env bash
mkdir -p "$TMP/state"
printf '%s\n' "\$0" >> "$TMP/state/ts-self"
printf '%s\n' "\$@" >> "$TMP/state/ts-args"
printf 'tree=%s unitdir=%s leak=%s\n' "\${APERIRE_INSTALL_TREE-unset}" "\${APERIRE_UNIT_DIR-unset}" "\${APERIRE_LEAK-unset}" >> "$TMP/state/ts-env"
echo "   the fake grant installer ran"
exit \$(cat "$TMP/state/ts-rc" 2>/dev/null || echo 0)
WEOF
  chmod +x "$TMP/release/scripts/install-trust-sync-grant.sh"
}
trust_sync_row() { # $1 = commit; the unit is on the host unless $TS_ABSENT is set
  reset
  make_installed_host
  [[ -n "${TS_ABSENT:-}" ]] || printf 'aperire-trust-sync@.service static\n' >> "$TMP/state/units"
  make_advisor_source "$KEPT/advisor" "TS-$1"
  stamp_an_older_release
  : > "$TMP/state/sudo-env-reset-run"
  make_advisor_release "TS-$1" "$1"
  SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
  SHA_FOR_RUN="$ADV_SHA"
}

write_fake_grant_installer
trust_sync_row 2a2a2a2
APERIRE_LEAK=leaked run_file "$ADV_COPY" --update --yes --no-restart
if [[ "$(cat "$TMP/state/ts-args" 2>/dev/null)" == "--if-stale" ]] \
   && [[ "$(cat "$TMP/state/ts-self" 2>/dev/null)" == */run/scripts/install-trust-sync-grant.sh \
      && "$(cat "$TMP/state/ts-self" 2>/dev/null)" != "$TMP/op/aperire-one/"* ]] \
   && [[ "$(cat "$TMP/state/ts-env" 2>/dev/null)" == "tree=$TMP/op/aperire-one unitdir=unset leak=unset" ]]; then
  ok "an installed trust sync unit: the staged grant installer runs once with --if-stale, told the install, and nothing the caller exported crosses sudo"
else
  bad "the update runs the grant installer's --if-stale from the staged copy" \
      "args=$(cat "$TMP/state/ts-args" 2>/dev/null) self=$(cat "$TMP/state/ts-self" 2>/dev/null) env=$(cat "$TMP/state/ts-env" 2>/dev/null) rc=$RC out=$OUT"
fi
if [[ $RC -eq 0 ]] && ! grep -q 'trust sync unit was not brought up to date' <<<"$OUT"; then
  ok "  a clean refresh says nothing to do at the end of the run"
else
  bad "a clean refresh leaves no warning behind" "rc=$RC out=$OUT"
fi

TS_ABSENT=1 trust_sync_row 2b2b2b2
run_file "$ADV_COPY" --update --yes --no-restart
if [[ ! -e "$TMP/state/ts-args" && $RC -eq 0 ]]; then
  ok "a host without the trust sync unit is left alone: the installer is not run"
else
  bad "no unit, no run" "args=$(cat "$TMP/state/ts-args" 2>/dev/null) rc=$RC"
fi

trust_sync_row 2c2c2c2
echo 3 > "$TMP/state/ts-rc"
run_file "$ADV_COPY" --update --yes --no-restart
banner_line="$(grep -n '^  This host moved from' <<<"$OUT" | head -1 | cut -d: -f1)"
close_line="$(grep -n 'the trust sync unit was not brought up to date' <<<"$OUT" | head -1 | cut -d: -f1)"
if [[ -n "$banner_line" && -n "$close_line" && "$close_line" -gt "$banner_line" ]] \
   && grep -q "Unknown key name" <<<"$OUT" \
   && grep -q -- "--run trust-sync-grant$" <<<"$OUT"; then
  ok "an installer that fails is named at the end of the update, with the why and the one command, and the update itself is not failed by it"
else
  bad "a failed trust sync refresh is said at the end" "banner=$banner_line close=$close_line rc=$RC out=$OUT"
fi

rm -f "$TMP/release/scripts/install-trust-sync-grant.sh"
trust_sync_row 2d2d2d2
run_file "$ADV_COPY" --update --yes --no-restart
if grep -q 'install-trust-sync-grant.sh is missing from the new release' <<<"$OUT" \
   && grep -q -- "--run trust-sync-grant$" <<<"$OUT" && ! grep -q 'install-trust-sync-grant' "$TMP/state/sudo-exec"; then
  ok "a release without the grant installer is said at the end too, and nothing is run for it"
else
  bad "a release without the installer is named" "out=$OUT"
fi
reset

# Row 6: Go only where the installer itself puts it, /usr/local/go/bin/go,
# never on PATH and never in the operator's login shell (#633). The literal
# path in advisor_go_bin() cannot be pointed at a fixture by an env var, so
# this row patches ITS OWN COPY of the script the same way
# test-advisord-go-probe.sh already does for install-advisord.sh: sed the one
# hardcoded path in a scratch copy, never the real /usr/local, through
# ADV_PINNED_GO, which make_advisor_release() reads. A real source change
# with only the pinned Go present still has to rebuild.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-PINNED"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_go_shim "$TMP/pinned-go/bin/go" "pinned"
ADV_PINNED_GO="$TMP/pinned-go/bin/go"
make_advisor_release "NEW-SOURCE-PINNED" "6666666"
ADV_PINNED_GO=""
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "rebuilt, stamped 6666666" <<<"$OUT"; then
  ok "Go only at /usr/local/go/bin/go, the installer's own location, is found and still rebuilds"
else
  bad "the pinned Go location is looked at the way install-advisord.sh looks at it" \
      "builds=$(builds_asked) out=$OUT"
fi
reset

# Row 7: no Go anywhere advisor_go_bin looks, including the pinned location,
# which make_advisor_release() already points at a fixture this suite never
# creates (ADV_PINNED_GO unset, its own default), so a runner that happens
# to carry a real /usr/local/go cannot make this row pass by accident.
# Carried, exactly like row 4, and now also named once more in the closing
# summary (#633), not only in the mid-run warn that scrolled past a fetch
# and an install step ago.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-NOWHERE"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-NOWHERE" "7777777"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 0 ]] && grep -q 'no Go toolchain anywhere this looks' <<<"$OUT"; then
  ok "no Go anywhere this looks is still a named skip, the carried binary untouched"
else
  bad "a host with no Go anywhere carries the binary" "builds=$(builds_asked) out=$OUT"
fi
if grep -q 'the Advisor is still on its previous build (no Go toolchain found on this host)\.' <<<"$OUT"; then
  ok "and the closing summary says so plainly, not only the mid-run warn"
else
  bad "the closing summary names the stale Advisor" "$OUT"
fi
# Not merely present somewhere in the output: after the update's own banner
# ("This host moved from"), which is what makes it the CLOSING summary
# rather than a second copy of the mid-run warn sitting beside the first.
# The unique warn text picked here ("...its previous build (...)") only
# exists in the closing block; the mid-run one reads differently
# ("...the Advisor changed in this release...").
banner_line="$(grep -n '^  This host moved from' <<<"$OUT" | head -1 | cut -d: -f1)"
advisor_line="$(grep -n 'the Advisor is still on its previous build' <<<"$OUT" | head -1 | cut -d: -f1)"
if [[ -n "$banner_line" && -n "$advisor_line" && "$advisor_line" -gt "$banner_line" ]]; then
  ok "and it prints after the update's own banner, where an operator reading the end of the run sees it"
else
  bad "the stale-Advisor line comes after the update banner, not only beside the mid-run warn" \
      "banner_line=$banner_line advisor_line=$advisor_line"
fi
# And the closing block carries its OWN copy of the actual remedy, not just
# the mid-run's: the LAST occurrence of the rerun command in the whole
# output is the closing block's, since the mid-run's own copy comes first.
remedy_line="$(grep -n 'bash -s -- --update --force' <<<"$OUT" | tail -1 | cut -d: -f1)"
if [[ -n "$banner_line" && -n "$remedy_line" && "$remedy_line" -gt "$banner_line" ]]; then
  ok "and the closing summary repeats the actual fix, not just that something is stale"
else
  bad "the closing summary carries its own copy of the remedy" \
      "banner_line=$banner_line remedy_line=$remedy_line"
fi
if ! grep -q 'install-advisor-stack.sh' <<<"$OUT"; then
  ok "and install-advisor-stack.sh is never named: it would re-register this exact stale build"
else
  bad "install-advisor-stack.sh is not named anywhere in this run's output" "$OUT"
fi
reset

# Row 8: a pinned Go older than the Advisor's own minimum is skipped, not
# trusted, and the run falls through to the next candidate rather than
# failing on syntax this project's module already requires. PATH is left at
# its default here (the "on-path" shim from setup, real Go 1.23.4), so a
# skip that worked has somewhere to land.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-TOOOLD"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_old_go_shim "$TMP/too-old-go/bin/go" "too-old"
ADV_PINNED_GO="$TMP/too-old-go/bin/go"
make_advisor_release "NEW-SOURCE-TOOOLD" "8888888"
ADV_PINNED_GO=""
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "rebuilt, stamped 8888888" <<<"$OUT" \
   && grep -qx 'too-old' "$TMP/state/go-used" && grep -qx 'on-path' "$TMP/state/go-used"; then
  ok "a pinned Go older than 1.23 is probed, rejected, and PATH's own Go builds instead"
else
  bad "an old pinned Go falls through to the next candidate" \
      "builds=$(builds_asked) out=$OUT go-used=$(cat "$TMP/state/go-used" 2>/dev/null)"
fi
reset

# Row 9: with a working Go on PATH too, the pinned location still wins,
# because it is checked first (#633 done-when #1). PATH is again left at its
# default; go-used carries only "pinned" if the order held, "on-path" too
# (or instead) if it did not.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-BOTH"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_go_shim "$TMP/pinned-go-2/bin/go" "pinned"
ADV_PINNED_GO="$TMP/pinned-go-2/bin/go"
make_advisor_release "NEW-SOURCE-BOTH" "9999999"
ADV_PINNED_GO=""
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "rebuilt, stamped 9999999" <<<"$OUT" \
   && grep -qx 'pinned' "$TMP/state/go-used" && ! grep -qx 'on-path' "$TMP/state/go-used"; then
  ok "the pinned location wins over a working Go on PATH: it is tried first, not merely tried at all"
else
  bad "the pinned candidate takes precedence over PATH" \
      "builds=$(builds_asked) out=$OUT go-used=$(cat "$TMP/state/go-used" 2>/dev/null)"
fi
reset

# Row 10 (#633, blocking on the Opus review of PR #634): the printed remedy
# has to actually work, followed literally, not just read plausibly. A host
# carrying a stale build with no Go anywhere gets the two-command remedy in
# its closing summary; this row runs both commands for real. Step one, Go
# appears where the remedy's own prepare-host.sh command would have put it
# (the pinned location this row's own copy already names). Step two, the
# same release again with --force, because by the time the remedy printed,
# this run had already written its own stamp, and a bare --update would
# find the host already on it and touch nothing. The result has to be a
# stamped rebuild, attributed to the operator by name in its own output,
# not a reason to trust the printed words on faith.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-REMEDY"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
ADV_PINNED_GO="$TMP/remedy-go/bin/go"
make_advisor_release "NEW-SOURCE-REMEDY" "aaaaaaa"
ADV_PINNED_GO=""
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes
if [[ "$(builds_asked)" == 0 ]]; then
  ok "step zero: this row starts exactly like row 7, carried, no Go anywhere yet"
else
  bad "the row's own setup carries no Go before the remedy is followed" "builds=$(builds_asked)"
fi
# Step 1 of the printed remedy, literally: Go now exists at the pinned
# location this copy already points at.
make_go_shim "$TMP/remedy-go/bin/go" "remedy"
# Step 2 of the printed remedy, literally: the same update, forced.
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --force --yes
if [[ "$(builds_asked)" == 3 ]] && grep -q "rebuilt, stamped aaaaaaa" <<<"$OUT"; then
  ok "step one and two, followed literally, end in a stamped rebuild, not another carry"
else
  bad "the printed remedy actually rebuilds when followed" "builds=$(builds_asked) out=$OUT"
fi
if [[ "$("$TMP/op/aperire-one/advisor/bin/aperire-advisord" -version 2>/dev/null)" == "aaaaaaa" ]]; then
  ok "and the binary this host now has answers -version with the release the remedy was for"
else
  bad "the rebuilt binary is stamped with the release the remedy applied" \
      "$("$TMP/op/aperire-one/advisor/bin/aperire-advisord" -version 2>&1)"
fi
if grep -q 'rebuilding advisor/bin/aperire-advisord, advisor/bin/aperire-executor and advisor/bin/knowledge-lint as ' <<<"$OUT"; then
  ok "and the run's own words attribute the rebuild to the operator by name, not to root"
else
  bad "the rebuild is attributed to the operator account" "$OUT"
fi
if ! grep -q 'the Advisor is still on its previous build' <<<"$OUT"; then
  ok "and the second run's own closing summary has nothing left to warn about"
else
  bad "a successful rebuild still carries a stale-Advisor warning" "$OUT"
fi
reset

# Row 11 (Opus review, low): a failed health check on an update still names
# the stale Advisor. health_failed() exits before verify_and_report's own
# trailing call to mention_previous_tree ever runs, so an operator chasing a
# dashboard that will not answer used to learn nothing about their Advisor
# also being stale, from the same run that knew both things.
reset
make_installed_host
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
echo active > "$TMP/state/active-aperire-advisord.service"
make_advisor_source "$KEPT/advisor" "OLD-SOURCE-DOWNHEALTH"
make_advisor_binary "$KEPT/advisor/bin/aperire-advisord" "0000000"
stamp_an_older_release
make_advisor_release "NEW-SOURCE-DOWNHEALTH" "bbbbbbb"
SOURCE_URL_FOR_RUN="file://$ADV_TARBALL"
SHA_FOR_RUN="$ADV_SHA"
echo down > "$TMP/state/healthz"
PATH_FOR_RUN="$(path_without go)" run_file "$ADV_COPY" --update --yes
if [[ $RC -ne 0 ]] && grep -q 'the Advisor is still on its previous build' <<<"$OUT"; then
  ok "a failed health check still names the stale Advisor, not only a clean run"
else
  bad "the stale-Advisor line survives a failed health check" "rc=$RC out=$OUT"
fi
reset

# ── a node that survived an uninstall, and its record (#434) ────────
#
# The wipe-clean uninstall removes /etc/aperire whole and leaves the node
# running, which is what it is for. node.conf goes with the directory, and
# until now nothing on the reinstall path wrote it back: the node installer
# runs only where the host has NO node, and this is the opposite case. So the
# rebuilt host came back with a healthy node and nothing on it naming that
# node, and the four readers #437 added all dead-end there.
#
# The fixture's node installer answers --adopt by writing the record and
# touching nothing else, which is what the real verb does.
echo
echo "A node that is already here, and the record of it:"

reset
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
run_sut --yes
if [[ -f "$TMP/etc/aperire/node.conf" ]] && grep -q 'SERVICE=stock-node1' "$TMP/etc/aperire/node.conf"; then
  ok "a node running with no record has one written during the install"
else
  bad "the node's record is written" "rc=$RC: $OUT"
fi
if grep -qx 'adopt' "$TMP/state/node-install-args" 2>/dev/null \
   || grep -q '^--adopt$' "$TMP/state/node-install-args" 2>/dev/null; then
  ok "and it is the installer's own record-what-is-here verb that wrote it"
else
  bad "the adopt verb is what ran" "node-install-args=$(cat "$TMP/state/node-install-args" 2>/dev/null)"
fi
if [[ "$OUT" == *"recording the node that is already here"* ]] \
   && [[ "$OUT" == *"running container stock-node1"* ]]; then
  ok "the run says it is doing it, and which node it found"
else
  bad "the run says what it is doing" "$OUT"
fi
if [[ "$OUT" == *"not touched"* && "$OUT" == *"not restarted"* ]]; then
  ok "and says the node itself is not touched, which is the whole of why this is safe unasked"
else
  bad "it says the node is not touched" "$OUT"
fi
# The order matters: the record has to exist before install.sh runs, because
# the checks that read it arrive with that run. Both line numbers are required
# to exist, or a run that never adopted at all would read as "adopt came
# first" on an empty answer.
line_of() { grep -n "^$1\$" "$TMP/state/order" 2>/dev/null | awk -F: 'NR==1{print $1}'; }
adopt_at="$(line_of adopt)"; install_at="$(line_of install)"
if [[ -n "$adopt_at" && -n "$install_at" && $adopt_at -lt $install_at ]]; then
  ok "it runs before the install, so the readers that arrive with it find the file"
else
  bad "the adopt runs before the install" "order=$(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null)"
fi

reset
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
mkdir -p "$TMP/etc/aperire"
printf 'KIND=container\nSERVICE=stock-node1\nCONFIG_FILE=/n/config/rippled.cfg\n' \
  > "$TMP/etc/aperire/node.conf"
BEFORE_CONF="$(cat "$TMP/etc/aperire/node.conf")"
run_sut --yes
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null; then
  ok "a host that already has the record runs nothing against its node"
else
  bad "nothing runs where the record is there" "$(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/etc/aperire/node.conf")" == "$BEFORE_CONF" ]]; then
  ok "and the record it has is left exactly as it was"
else
  bad "the existing record is untouched" "$(cat "$TMP/etc/aperire/node.conf")"
fi

reset
run_sut --yes --role=dashboard
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null && [[ $RC -eq 0 ]]; then
  ok "a box with no node runs nothing and refuses nothing"
else
  bad "a box with no node is quiet" "rc=$RC: $(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$OUT" != *"recording the node that is already here"* ]]; then
  ok "and says nothing about a node it does not have"
else
  bad "it says nothing about a node it does not have" "$OUT"
fi

# A node that is a package and a unit is the one shape this must NOT run
# against: the installer's native mode installs where it finds no unit, which
# is far more than a missing text file is worth. Named, never run.
reset
printf 'xrpld\n' > "$TMP/state/procs"
run_sut --yes
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null; then
  ok "a native node is not adopted by this run"
else
  bad "a native node is not adopted" "$(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$OUT" == *"recording the node that is already here"* && "$OUT" == *"bash -s -- --dir "*" --run node --native"* \
      && "$OUT" != *"sudo bash"*"install-aperire-node.sh"* ]]; then
  ok "and the run says so, naming the one command that records it"
else
  bad "a native node is named rather than dropped" "$OUT"
fi

# The other half of "never a reason to stop": an adopt that refuses, which is
# what the real verb does whenever it cannot be sure which node it is looking
# at, must leave the install running.
reset
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
: > "$TMP/state/adopt-fails"
run_sut --yes
if [[ $RC -eq 0 ]] && grep -q 'install' "$TMP/state/order" 2>/dev/null; then
  ok "an adopt that refuses does not stop the install"
else
  bad "a refused adopt does not stop the install" "rc=$RC: $(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$OUT" == *"was not recorded and the install carries on"* ]]; then
  ok "and the refusal is said out loud, with the command that finishes it later"
else
  bad "the refusal is said out loud" "$OUT"
fi

# The aperire4 case, and the reason the fact comes off the checklist rather
# than off this script's own probe: `--role co-located` short-circuits role
# detection, which is the way out of a box where docker cannot be asked at
# all. A first install driven that way found the node in the checklist, wrote
# its config paths into the service environment, and still ended with nothing
# naming the node. Nothing running that this script's own probe could see
# here, on purpose: the answer can only have come from the checklist.
reset
printf 'NODE_SHAPE=container\nNODE_CONTAINER=stock-node1\n' > "$TMP/state/preflight-answer"
run_sut --yes --role=co-located
if [[ -f "$TMP/etc/aperire/node.conf" ]] && grep -q 'SERVICE=stock-node1' "$TMP/etc/aperire/node.conf"; then
  ok "a named role still records the node, because the checklist is what found it"
else
  bad "a named role records the node" "rc=$RC: $OUT"
fi
if [[ "$OUT" == *"container stock-node1"* ]]; then
  ok "and the run names the node the checklist measured"
else
  bad "the run names the checklist's node" "$OUT"
fi
if [[ ! -s "$TMP/state/docker-calls" ]]; then
  ok "with docker still never asked by this script, which is what naming the role buys"
else
  bad "naming the role asks docker nothing" "$(cat "$TMP/state/docker-calls" 2>/dev/null)"
fi

# A check reports and changes nothing, which is this script's own promise. It
# exits inside the checklist today, so this is an assertion about the promise
# rather than about the line that keeps it.
reset
printf 'NODE_SHAPE=container\nNODE_CONTAINER=stock-node1\n' > "$TMP/state/preflight-answer"
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
run_sut --check --yes
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null && [[ ! -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "a check records nothing, on the same host that an install would record"
else
  bad "a check records nothing" "rc=$RC: $(cat "$TMP/state/order" 2>/dev/null)"
fi

# The control for all of the above: --node installs a node and that install
# writes the record itself, so nothing here may run a second time over it.
reset
run_sut --yes --node
if grep -q '^node$' "$TMP/state/order" 2>/dev/null && ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null; then
  ok "control: a node this run installed is not then adopted on top of itself"
else
  bad "a freshly installed node is not adopted" "$(cat "$TMP/state/order" 2>/dev/null)"
fi

# ── and the same record on the update path (#480) ───────────────────
#
# --update branches out of main() before role detection and runs install.sh
# with --no-preflight, so neither of the two things that measure a node on an
# install happens there. Every host that was updated rather than installed
# therefore kept a running node with nothing naming it, and the verify, which
# is honest about that now, goes red on it nightly: three of the fleet's hosts
# were in that state the night this was filed.
#
# The same fixture the update rows above use, plus a node running on the host.
echo
echo "The same record, on the update path:"

reset
make_installed_host
stamp_an_older_release
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ -f "$TMP/etc/aperire/node.conf" ]] && grep -q 'SERVICE=stock-node1' "$TMP/etc/aperire/node.conf"; then
  ok "an update on a host with a node and no record writes one, naming the container that is running"
else
  bad "the update records the node" "rc=$RC: $OUT"
fi
if grep -q '^adopt$' "$TMP/state/order" 2>/dev/null \
   && grep -q -- '--adopt' "$TMP/state/node-install-args" 2>/dev/null; then
  ok "and it is the same record-what-is-here verb the install path runs, not a second way of writing the file"
else
  bad "the update runs the adopt verb" "order=$(cat "$TMP/state/order" 2>/dev/null) args=$(cat "$TMP/state/node-install-args" 2>/dev/null)"
fi
if [[ "$OUT" == *"recording the node that is already here"* ]] \
   && [[ "$OUT" == *"running container stock-node1"* ]]; then
  ok "in the install path's words, naming the node this run found"
else
  bad "the update says what it is doing" "$OUT"
fi
# Same order as the install, and for the same reason: the checks that read the
# file arrive with the release this run has just swapped in. Both line numbers
# are required to exist, or a run that never adopted would read as "adopt came
# first" on an empty answer.
adopt_at="$(line_of adopt)"; install_at="$(line_of install)"
if [[ -n "$adopt_at" && -n "$install_at" && $adopt_at -lt $install_at ]]; then
  ok "and it runs before install.sh, so the readers that arrive with the new tree find the file"
else
  bad "the update's adopt runs before the install" "order=$(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null)"
fi
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]] \
   && [[ "$(field_of "$STAMP" sha256)" == "$GOOD_SHA" ]]; then
  ok "with the update itself finishing as it always did: installed, stamped, exit 0"
else
  bad "the update still completes" "rc=$RC: stamp=$(tr '\n' ' ' < "$STAMP" 2>/dev/null)"
fi

# A host that has the record is not asked anything at all: no probe, no verb,
# and the file it has is the file it keeps. This is the ordinary update, which
# is every update after the first one that recorded the node.
reset
make_installed_host
stamp_an_older_release
printf 'stock-node1 xrpllabsofficial/xrpld:latest /entrypoint\n' > "$TMP/state/containers"
printf 'KIND=container\nSERVICE=stock-node1\nCONFIG_FILE=/n/config/rippled.cfg\n' \
  > "$TMP/etc/aperire/node.conf"
BEFORE_CONF="$(cat "$TMP/etc/aperire/node.conf")"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null; then
  ok "an update on a host that has the record runs nothing against its node"
else
  bad "nothing runs where the record is there" "$(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$(cat "$TMP/etc/aperire/node.conf")" == "$BEFORE_CONF" ]]; then
  ok "and the record it has is left byte for byte as it was"
else
  bad "the existing record is untouched" "$(cat "$TMP/etc/aperire/node.conf")"
fi
if [[ ! -s "$TMP/state/docker-calls" ]]; then
  ok "with docker never asked either: a host with the record has nothing for the probe to answer"
else
  bad "a host with the record asks docker nothing" "$(cat "$TMP/state/docker-calls" 2>/dev/null)"
fi

# A host with no node. Nothing to record, nothing to refuse, and the update
# is the update it would have been: this is the aggregator's shape, and it
# must not learn to complain about a node it was never supposed to have.
reset
make_installed_host
stamp_an_older_release
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null \
   && [[ ! -f "$TMP/etc/aperire/node.conf" ]]; then
  ok "an update on a host with no node records nothing"
else
  bad "a host with no node is quiet" "$(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ $RC -eq 0 && -f "$TMP/state/install-args" ]] \
   && [[ "$OUT" != *"recording the node that is already here"* ]] \
   && [[ "$OUT" != *"was not recorded"* ]]; then
  ok "and refuses nothing and says nothing: the update completes exactly as before"
else
  bad "a host with no node updates as before" "rc=$RC: $OUT"
fi

# The container-only rule, on this path too. A node that is a package and a
# unit is named and left alone: the installer's native mode installs where it
# finds no unit, which is far more than a missing text file is worth doing to
# a host in the middle of an update.
reset
make_installed_host
stamp_an_older_release
printf 'xrpld\n' > "$TMP/state/procs"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if ! grep -q 'adopt' "$TMP/state/order" 2>/dev/null && [[ $RC -eq 0 ]]; then
  ok "an update over a native node adopts nothing and finishes"
else
  bad "a native node is not adopted on the update path" "rc=$RC: $(cat "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$OUT" == *"recording the node that is already here"* && "$OUT" == *"bash -s -- --dir "*" --run node --native"* \
      && "$OUT" != *"sudo bash"*"install-aperire-node.sh"* ]]; then
  ok "and names the one command that records it, the way the install path does"
else
  bad "a native node is named rather than dropped" "$OUT"
fi

# ── the node's package source, on the update path (#802) ────────────
#
# A native host installed before #655 kept repos.ripple.com through every
# update, and the Advisor called 3.3.0 the newest release. An update on a
# native host now runs the installer's source move, out of the release it
# fetched, before the install.
echo
echo "The node's package source, on the update path (#802):"

reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=native\nSERVICE=xrpld.service\nCONFIG_FILE=/etc/xrpld/xrpld.cfg\nNODE_LABEL=n2\n' > "$TMP/etc/aperire/node.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
move_at="$(line_of move-source)"; install_at="$(line_of install)"
if [[ $RC -eq 0 && -n "$move_at" ]] && grep -q -- '^--move-source$' "$TMP/state/node-install-args" 2>/dev/null; then
  ok "an update on a native host runs the installer's source move, and only that verb"
else
  bad "the update moves a native node's source" "rc=$RC args=$(cat "$TMP/state/node-install-args" 2>/dev/null): $OUT"
fi
if [[ -n "$move_at" && -n "$install_at" && $move_at -lt $install_at ]] \
   && ! grep -q '^node$' "$TMP/state/order" 2>/dev/null; then
  ok "before the install, and never the installer's install path"
else
  bad "the move runs before the install and installs no node" "order=$(tr '\n' ' ' < "$TMP/state/order" 2>/dev/null)"
fi
if [[ "$OUT" == *"the node's package source"* && "$OUT" == *"the node is"*"not upgraded, not restarted"* \
      && "$OUT" == *"apt now offers xrpld 3.4.1-1"* ]]; then
  ok "and it says what it is doing and what it is not, and the installer's own answer is shown"
else
  bad "the update says what the source move does" "$OUT"
fi

# The wrapper's record is the other way a host says it is native.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=native\nSERVICE=xrpld.service\n' > "$TMP/etc/aperire/node-wrapper.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 ]] && grep -q '^move-source$' "$TMP/state/order" 2>/dev/null; then
  ok "a host whose wrapper configuration says native gets the same move"
else
  bad "the wrapper's KIND=native also moves the source" "rc=$RC order=$(cat "$TMP/state/order" 2>/dev/null)"
fi

# A refusal is said, with the command, and the update finishes.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=native\nSERVICE=xrpld.service\n' > "$TMP/etc/aperire/node.conf"
touch "$TMP/state/move-fails"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 && -f "$TMP/state/install-args" && "$OUT" == *"fingerprint does not match"* \
      && "$OUT" == *"was not moved, and the update carries on"* \
      && "${OUT#*was not moved, and the update carries on}" == *"| bash -s -- --update --force"* ]]; then
  ok "a refused move is named with the command that finishes it, and the update still completes"
else
  bad "a refused move does not stop the update" "rc=$RC: $OUT"
fi
rm -f "$TMP/state/move-fails"

# The control: a container host has no package source to move.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/etc/aperire"
printf 'KIND=container\nSERVICE=stock-node1\nCONFIG_FILE=/n/config/rippled.cfg\n' > "$TMP/etc/aperire/node.conf"
printf 'KIND=container\nSERVICE=stock-node1\n' > "$TMP/etc/aperire/node-wrapper.conf"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 ]] && ! grep -q 'move-source' "$TMP/state/order" 2>/dev/null \
   && [[ "$OUT" != *"the node's package source"* ]]; then
  ok "control: an update on a container host runs no source move and says nothing about one"
else
  bad "a container host is not moved" "order=$(cat "$TMP/state/order" 2>/dev/null)"
fi

# ── root copies only what the release shipped (ADR 0024, lane 2) ────
# A release carrying the state-ancestors library too (the shared fixture has
# only the credential check's), for the rows that tamper with each.
mkdir -p "$TMP/tarsrc-withlibs"
rm -rf "$TMP/tarsrc-withlibs/aperire-one"
cp -r "$TMP/tarsrc/aperire-one" "$TMP/tarsrc-withlibs/aperire-one"
cp "$REPO_DIR/scripts/state-ancestors-lib.sh" "$TMP/tarsrc-withlibs/aperire-one/scripts/state-ancestors-lib.sh"
tar -czf "$TMP/release-withlibs.tar.gz" -C "$TMP/tarsrc-withlibs" aperire-one
WITHLIBS_SHA="$(sha256sum "$TMP/release-withlibs.tar.gz" | cut -d' ' -f1)"

#
# Each row here fails on the tree before this lane: there, every root copy
# was `install <tree file> <root location>`, so whatever the tree held at that
# moment is what root ran next.

# The record itself. Written by root from the archive it held, with the
# anchor that vouches for it, and an entry per file.
reset
make_installed_host
stamp_an_older_release
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
RD_FILE="$TMP/lib/aperire/release.sha256"
if [[ -f "$RD_FILE" ]] && grep -q "^# anchor sha256 $GOOD_SHA" "$RD_FILE" \
   && grep -qx -e "$(sha256sum < "$TMP/release/scripts/aperire-seal-model-key.sh" | cut -c1-64)  scripts/aperire-seal-model-key.sh" "$RD_FILE" \
   && grep -q 'release digests recorded at' <<<"$OUT"; then
  ok "an archive update records the release digests, anchored on the sha256 it checked"
else
  bad "the release digests are recorded" "$(head -5 "$RD_FILE" 2>/dev/null) :: $OUT"
fi
RD_FIRST="$(cat "$RD_FILE" 2>/dev/null)"
run_file "$PUBLISHED_COPY" --update --yes --force
RD_KEY="$(sed -n 's/^# key //p' <<<"$RD_FIRST" | head -1)"
if [[ "$RD_KEY" == "$GOOD_SHA" && "$(cat "$RD_FILE.kept/$RD_KEY" 2>/dev/null)" == "$RD_FIRST" ]] \
   && [[ -f "$TMP/lib/aperire/digests-required" ]]; then
  ok "and the next update keeps the record it replaces under the archive's sha256, the key a rollback looks it up by"
else
  bad "the replaced record is kept under its key" "key=$RD_KEY $(ls -R "$TMP/lib/aperire" 2>/dev/null)"
fi
if [[ -n "$(find "$TMP/op" -maxdepth 2 -path '*aperire-one.previous-*/.release' -print -quit)" ]]; then
  ok "and the kept tree keeps its own stamp, which names that key"
else
  bad "the kept tree keeps its .release" "$(ls -a "$(previous_tree)" 2>/dev/null)"
fi

# A root program rewritten in the tree after the unpack.
reset
make_installed_host
stamp_an_older_release
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
printf 'scripts/aperire-seal-model-key.sh\n' > "$TMP/state/tamper"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)" == "the OLD sealer" ]]; then
  ok "a root program rewritten in the tree after the unpack is not copied; the previous copy stays"
else
  bad "a tampered root program is refused" "sealer=$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)"
fi
if [[ $RC -ne 0 ]] \
   && grep -q 'refused: scripts/aperire-seal-model-key.sh is not the file this release shipped' <<<"$OUT" \
   && grep -q "tree     $(printf 'EVIL scripts/aperire-seal-model-key.sh\n' | sha256sum | cut -c1-64)" <<<"$OUT" \
   && grep -q "aperire-seal-model-key (from scripts/aperire-seal-model-key.sh)" <<<"$OUT"; then
  ok "and the run names it with both digests, lists it again at the end, and ends non-zero"
else
  bad "a tampered root program is named and fails the run" "rc=$RC $OUT"
fi

# And the remedy the refusal names has to work: --update --force fetches the
# release again, swaps the tree, and this time the sealer is the release's.
if grep -q -- '--update --force' <<<"$OUT"; then
  ok "the refusal names --update --force as the way to put the release back"
else
  bad "the refusal names the remedy" "$(grep -A8 'root refused to copy' <<<"$OUT")"
fi
rm -f "$TMP/state/tamper"
run_file "$PUBLISHED_COPY" --update --yes --force
if [[ $RC -eq 0 && "$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)" == "the NEW sealer" ]]; then
  ok "and it does: the release comes back as it shipped and the sealer is placed"
else
  bad "--update --force puts the release back" "rc=$RC sealer=$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)"
fi

# A root program the release never shipped, turning up in the tree after the
# unpack. An aggregator has a broker installed; this release carries none.
mkdir -p "$TMP/tarsrc-nobroker"
rm -rf "$TMP/tarsrc-nobroker/aperire-one"
cp -r "$TMP/tarsrc/aperire-one" "$TMP/tarsrc-nobroker/aperire-one"
rm -f "$TMP/tarsrc-nobroker/aperire-one/scripts/aperire-fleet-broker.sh"
tar -czf "$TMP/release-nobroker.tar.gz" -C "$TMP/tarsrc-nobroker" aperire-one
NOBROKER_SHA="$(sha256sum "$TMP/release-nobroker.tar.gz" | cut -d' ' -f1)"
reset
make_installed_host
stamp_an_older_release
printf 'the OLD broker\n' > "$TMP/sbin/aperire-fleet-broker"
printf 'scripts/aperire-fleet-broker.sh\n' > "$TMP/state/tamper"
SOURCE_URL_FOR_RUN="file://$TMP/release-nobroker.tar.gz"
SHA_FOR_RUN="$NOBROKER_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ "$(cat "$TMP/sbin/aperire-fleet-broker" 2>/dev/null)" == "the OLD broker" && $RC -ne 0 ]] \
   && grep -q 'refused: scripts/aperire-fleet-broker.sh is not a file this release shipped: the release digests have no entry for it' <<<"$OUT"; then
  ok "a root program the release never shipped is refused for having no entry, not copied because it turned up"
else
  bad "a file with no entry in the record is refused" \
      "rc=$RC broker=$(cat "$TMP/sbin/aperire-fleet-broker" 2>/dev/null) $(grep -i 'broker' <<<"$OUT")"
fi

# The archive swapped between the checksum and the unpack. Before this lane
# the checksum was taken of the operator's own copy and the unpack read that
# same path again a moment later, so a swap in between unpacked bytes nobody
# checked. The sha256sum below swaps the file it was just asked about, which
# is that race won every time.
mkdir -p "$TMP/tarsrc-evil" "$TMP/swapbin"
rm -rf "$TMP/tarsrc-evil/aperire-one"
cp -r "$TMP/tarsrc/aperire-one" "$TMP/tarsrc-evil/aperire-one"
printf 'the EVIL sealer\n' > "$TMP/tarsrc-evil/aperire-one/scripts/aperire-seal-model-key.sh"
tar -czf "$TMP/release-evil.tar.gz" -C "$TMP/tarsrc-evil" aperire-one
REAL_SHA256SUM="$(command -v sha256sum)"
cat > "$TMP/swapbin/sha256sum" <<EOF
#!/usr/bin/env bash
"$REAL_SHA256SUM" "\$@"; rc=\$?
for a in "\$@"; do
  case "\$(basename -- "\$a")" in
    aperire-release.*.tar.gz) cp "$TMP/release-evil.tar.gz" "\$a" ;;
  esac
done
exit \$rc
EOF
chmod +x "$TMP/swapbin/sha256sum"
reset
make_installed_host
stamp_an_older_release
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
PATH_FOR_RUN="$TMP/swapbin:$PATH"
run_file "$PUBLISHED_COPY" --update --yes
PATH_FOR_RUN=""
if [[ "$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)" == "the NEW sealer" \
      && "$(cat "$KEPT/scripts/aperire-seal-model-key.sh" 2>/dev/null)" == "the NEW sealer" ]]; then
  ok "an archive swapped after its checksum was taken is not what is unpacked, and not what root copies"
else
  bad "the checked archive is the unpacked one" \
      "installed=$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null) tree=$(cat "$KEPT/scripts/aperire-seal-model-key.sh" 2>/dev/null)"
fi

# A git source has no archive, so no record, and on a host that has one it is
# refused before anything moves: replacing the record with nothing is the one
# thing that would turn the check off.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/lib/aperire"
printf '# anchor an earlier archive\n%s  scripts/aperire-seal-model-key.sh\n' "$(printf '0%.0s' {1..64})" > "$TMP/lib/aperire/release.sha256"
RD_BEFORE="$(cat "$TMP/lib/aperire/release.sha256")"
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
run_sut --update --yes
if [[ $RC -ne 0 && "$(cat "$TMP/lib/aperire/release.sha256" 2>/dev/null)" == "$RD_BEFORE" ]] \
   && [[ "$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)" == "the OLD sealer" ]] \
   && grep -q 'a git source has none, so nothing was fetched' <<<"$OUT" \
   && [[ ! -s "$TMP/state/git-calls" ]]; then
  ok "a git source on a host with release digests is refused before anything is fetched or moved"
else
  bad "a git source cannot remove the record" "rc=$RC $(ls "$TMP/lib/aperire" 2>/dev/null) $(tail -5 <<<"$OUT")"
fi
# The marker alone is enough: a record that is gone on a host that had one.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$TMP/lib/aperire"
printf 'required\n' > "$TMP/lib/aperire/digests-required"
run_sut --update --yes
if [[ $RC -ne 0 ]] && grep -q 'a git source has none' <<<"$OUT"; then
  ok "and so is one on a host whose record is gone but whose marker says it had one"
else
  bad "the marker alone refuses a git source" "rc=$RC $(tail -4 <<<"$OUT")"
fi
# A host that never had one: the copies are made unchecked, each says so, and
# the closing summary says the host has no release digests.
reset
make_installed_host
stamp_an_older_release
printf 'the OLD sealer\n' > "$TMP/sbin/aperire-seal-model-key"
run_sut --update --yes
if [[ ! -e "$TMP/lib/aperire/release.sha256" ]] \
   && [[ "$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null)" == "the NEW sealer" ]] \
   && grep -q 'unchecked: scripts/aperire-seal-model-key.sh' <<<"$OUT" \
   && grep -q 'this host has no release digests' <<<"$OUT"; then
  ok "a git source on a host that never had a record copies unchecked, names each copy, and says so at the end"
else
  bad "a git source on a clean host falls back and says so" \
      "rc=$RC sealer=$(cat "$TMP/sbin/aperire-seal-model-key" 2>/dev/null) $(tail -8 <<<"$OUT")"
fi

# The two libraries this script used to source straight out of the tree, as
# root under `curl | sudo bash`, the credential check's and the state
# ancestors', and the Advisor's unit-grants program (#699) and the library it
# loads, which it runs as root. A rewritten one must never run. Its payload
# leaves a mark if it does.
for lib in scripts/advisord-credcheck-lib.sh scripts/state-ancestors-lib.sh \
           scripts/advisord-unit-grants.sh scripts/advisord-unit-grants-lib.sh; do
  reset
  make_installed_host
  stamp_an_older_release
  make_advisord_unit
  mkdir -p "$KEPT/advisor/state"
  printf '%s\n' "$lib" > "$TMP/state/tamper"
  printf 'touch "%s"\n' "$TMP/state/tree-code-ran" > "$TMP/state/tamper-payload"
  SOURCE_URL_FOR_RUN="file://$TMP/release-withlibs.tar.gz"
  SHA_FOR_RUN="$WITHLIBS_SHA"
  run_file "$PUBLISHED_COPY" --update --yes
  if [[ ! -e "$TMP/state/tree-code-ran" && $RC -ne 0 ]] \
     && grep -q "refused: $lib is not the file this release shipped" <<<"$OUT"; then
    ok "$lib rewritten in the tree is refused, and never sourced or run"
  else
    bad "a rewritten $lib is never sourced" \
        "ran=$([[ -e "$TMP/state/tree-code-ran" ]] && echo yes || echo no) rc=$RC $(grep -i 'refused\|ancestors\|recovery' <<<"$OUT")"
  fi
done

# #868: the fleet trust key split runs on every update, from the release's
# checked copies of the split and the three files it loads. Staged and run:
# the fake sudo here runs it as this account, which the split refuses (it
# wants root), and that refusal is the proof the staging got through. A
# staging refusal would instead say "its program in the tree is not the
# release's" and fail every aggregator's update.
reset
make_installed_host
stamp_an_older_release
mkdir -p "$KEPT/dashboard/config"
printf 'private_key: %s\npeers: {}\n' "$(printf 'k%.0s' {1..43})" > "$KEPT/dashboard/config/fleet-trust.yaml"
SOURCE_URL_FOR_RUN="file://$TMP/release-withlibs.tar.gz"
SHA_FOR_RUN="$WITHLIBS_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if grep -q 'the fleet trust key is not in its target shape' <<<"$OUT" \
   && grep -q 'run it as root' <<<"$OUT" \
   && ! grep -q 'the fleet trust key was not checked' <<<"$OUT"; then
  ok "an update stages the fleet trust key split from the release and runs it as root (#868)"
else
  bad "the update runs the fleet trust key split" "rc=$RC $(grep -i 'fleet trust\|refused' <<<"$OUT")"
fi
reset
make_installed_host
stamp_an_older_release
mkdir -p "$KEPT/dashboard/config"
printf 'peers: {}\n' > "$KEPT/dashboard/config/fleet-trust.yaml"
printf 'scripts/fleet-trust-split.sh\n' > "$TMP/state/tamper"
printf 'touch "%s"\n' "$TMP/state/tree-code-ran" > "$TMP/state/tamper-payload"
SOURCE_URL_FOR_RUN="file://$TMP/release-withlibs.tar.gz"
SHA_FOR_RUN="$WITHLIBS_SHA"
run_file "$PUBLISHED_COPY" --update --yes
if [[ ! -e "$TMP/state/tree-code-ran" && $RC -ne 0 ]] \
   && grep -q 'refused: scripts/fleet-trust-split.sh is not the file this release shipped' <<<"$OUT" \
   && grep -q 'the fleet trust key was not checked' <<<"$OUT"; then
  ok "scripts/fleet-trust-split.sh rewritten in the tree is refused, and never run as root (#868)"
else
  bad "a rewritten fleet-trust-split.sh is never run" \
      "ran=$([[ -e "$TMP/state/tree-code-ran" ]] && echo yes || echo no) rc=$RC $(grep -i 'refused\|fleet trust' <<<"$OUT")"
fi

# #877 review, M2: the #703 shape through a whole update. The tree and its
# advisor/ are group-writable, and the Advisor's account is in the tree
# owner's group, so the trusted-path check refuses every copy out of that
# tree. The narrowing is what repairs it, so it runs first, from copies
# pinned to the release's digests, and every copy after it goes through.
mkdir -p "$TMP/tarsrc-703"
rm -rf "$TMP/tarsrc-703/aperire-one"
cp -r "$TMP/tarsrc-withlibs/aperire-one" "$TMP/tarsrc-703/aperire-one"
# The narrowing's helper, as a stand-in that reads the modes and nothing
# else: the real state-file.py judges group membership from /etc/group, where
# the fixture's Advisor account is not, while the trusted-path check reads it
# from the unit (the fake id below). Both have to see the same shape. What is
# under test is the order and the pinning, not the helper, which
# test-state-file-shape.sh drives on its own.
cat > "$TMP/tarsrc-703/aperire-one/scripts/state-file.py" <<'PY'
import os, stat, sys
if sys.argv[1] == "ancestors":
    state = sys.argv[2]
    for d in (os.path.dirname(os.path.dirname(state)), os.path.dirname(state)):
        if stat.S_IMODE(os.stat(d).st_mode) & 0o022:
            print("group-write\t%s\t%s can be written by its group" % (d, d))
elif sys.argv[1] == "narrow":
    was = stat.S_IMODE(os.stat(sys.argv[2]).st_mode)
    os.chmod(sys.argv[2], was & ~0o022)
    print("%o %o" % (was, was & ~0o022))
PY
tar -czf "$TMP/release-703.tar.gz" -C "$TMP/tarsrc-703" aperire-one
SHA_703="$(sha256sum "$TMP/release-703.tar.gz" | cut -d' ' -f1)"
# advsvc: the Advisor's account, a member of the tree owner's primary group.
# Every other name goes to the real id.
cat > "$TMP/bin/id" <<EOF
#!/usr/bin/env bash
if [[ "\${*: -1}" == advsvc ]]; then
  case "\$1" in
    -u) echo 99011 ;;
    -G) echo "99011 $(id -g)" ;;
    -nG) echo "advsvc $(id -gn)" ;;
    *) exit 1 ;;
  esac
  exit 0
fi
exec /usr/bin/id "\$@"
EOF
chmod +x "$TMP/bin/id"
reset
make_installed_host
stamp_an_older_release
mkdir -p "$KEPT/advisor/state"
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
mkdir -p "$(dirname "$ADVISORD_UNIT_FIXTURE")"
printf '[Service]\nUser=advsvc\nExecStart=%s/advisor/bin/aperire-advisord\n' "$TMP/op/aperire-one" > "$ADVISORD_UNIT_FIXTURE"
touch "$TMP/state/shape-703"
SOURCE_URL_FOR_RUN="file://$TMP/release-703.tar.gz"
SHA_FOR_RUN="$SHA_703"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -eq 0 && "$OUT" == *"the install tree above advisor/state"* && "$OUT" == *"->"* \
      && "$OUT" != *"can be changed by a service account"* && "$OUT" != *"root refused to copy"* ]] \
   && [[ "$(stat -c %a "$TMP/op/aperire-one")" == 755 ]]; then
  ok "the #703 shape: the narrowing runs first from pinned copies, repairs the tree, and every root copy after it goes through"
else
  bad "an update repairs the #703 shape before it copies anything" \
      "rc=$RC mode=$(stat -c %a "$TMP/op/aperire-one") $OUT"
fi
# The same shape where the narrowing's own library is not the release's: it
# is refused, and the refusal names the command that repairs the tree: the
# release fetched again, never the tree's own fix script, which sits beside
# the library that was just refused (#764).
reset
make_installed_host
stamp_an_older_release
mkdir -p "$KEPT/advisor/state"
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
mkdir -p "$(dirname "$ADVISORD_UNIT_FIXTURE")"
printf '[Service]\nUser=advsvc\nExecStart=%s/advisor/bin/aperire-advisord\n' "$TMP/op/aperire-one" > "$ADVISORD_UNIT_FIXTURE"
touch "$TMP/state/shape-703"
printf 'scripts/state-ancestors-lib.sh\n' > "$TMP/state/tamper"
SOURCE_URL_FOR_RUN="file://$TMP/release-703.tar.gz"
SHA_FOR_RUN="$SHA_703"
run_file "$PUBLISHED_COPY" --update --yes
if [[ $RC -ne 0 && "$OUT" == *"put the release back as it shipped, then run this again"*"--update --force"* \
      && "$OUT" != *"fix it with:  sudo bash"*"scripts/fix-state-ancestors.sh"* ]]; then
  ok "and when the narrowing cannot run, the refusal prints the command that repairs the tree, not the tree's own script"
else
  bad "a refused narrowing names its fix" "rc=$RC $OUT"
fi
rm -f "$TMP/state/shape-703" "$TMP/state/tamper" "$TMP/bin/id"

# --check installs nothing and runs nothing as root, so it records nothing.
reset
SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
SHA_FOR_RUN="$GOOD_SHA"
run_file "$PUBLISHED_COPY" --check
if [[ ! -e "$TMP/lib/aperire/release.sha256" ]] && ! grep -q 'rd-hold\|rd-record' "$TMP/state/sudo-exec" 2>/dev/null; then
  ok "--check neither records digests nor takes a root copy of the archive"
else
  bad "--check records nothing as root" "$(cat "$TMP/state/sudo-exec" 2>/dev/null)"
fi

# ── the one deliberate copy of the palette ──────────────────────────
#
# This script runs before any checkout exists, so it carries the palette
# inline instead of sourcing scripts/term-style.sh the way every in-repo
# installer does. One copy is a decision. Two that have drifted apart is the
# bug that decision invites, so they are compared here byte for byte.
palette_of() { sed -n '/^# >>> aperire palette >>>$/,/^# <<< aperire palette <<<$/p' "$1"; }
INLINE="$(palette_of "$SUT")"
SHARED="$(palette_of "$REPO_DIR/scripts/term-style.sh")"
if [[ -n "$INLINE" && "$INLINE" == "$SHARED" ]]; then
  ok "the inline palette is byte-identical to the one scripts/term-style.sh shares"
else
  bad "the inline palette is byte-identical to scripts/term-style.sh" \
      "$(diff <(printf '%s\n' "$SHARED") <(printf '%s\n' "$INLINE") | head -12)"
fi

echo
echo "The pre-update snapshot when the dashboard has its own account (ADR 0024):"
# ADR 0024 lane 3: a dashboard on its own account. sqlite3 writes a journal
# beside the file it fills, so the copy is made inside data/ (the only
# directory that account may write) and root renames it out beside the tree.
# A copy straight into the operator's directory fails there, measured.
# Driven with a real database and a unit naming another account, through a
# runuser that records and then runs the command as this suite.
if [[ -n "$REAL_SQLITE3" ]]; then
  reset
  make_installed_host
  stamp_an_older_release
  SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
  SHA_FOR_RUN="$GOOD_SHA"
  rm -f "$KEPT/data/aperire.db"
  "$REAL_SQLITE3" "$KEPT/data/aperire.db" "create table t(x); insert into t values('kept');"
  mkdir -p "$TMP/etc/systemd/system"
  printf '[Service]\nUser=nobody\n' > "$TMP/etc/systemd/system/aperire-server.service"
  cat > "$TMP/bin/runuser" <<RUEOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/runuser-log"
while [[ \$# -gt 0 && "\$1" != -- ]]; do shift; done
shift; exec "\$@"
RUEOF
  chmod +x "$TMP/bin/runuser"; rm -f "$TMP/state/runuser-log"
  run_file "$PUBLISHED_COPY" --update --yes
  SNAP="$(db_snapshot)"
  if [[ -n "$SNAP" && ! -L "$SNAP" && "$("$REAL_SQLITE3" "$SNAP" 'select x from t' 2>/dev/null)" == kept ]] \
     && grep -q -- '-u nobody -- sh -c' "$TMP/state/runuser-log" 2>/dev/null \
     && [[ -z "$(find "$KEPT/data" -maxdepth 1 -name '.update-snapshot-*' 2>/dev/null)" ]]; then
    ok "a dashboard on its own account: the snapshot is taken as that account inside data/, and moved out by root"
  else
    bad "the snapshot works when the dashboard has its own account" \
        "snap=${SNAP:-none} runuser=$(cat "$TMP/state/runuser-log" 2>/dev/null) sudo=$(grep -i snapshot "$TMP/state/sudo-exec" 2>/dev/null) left=$(find "$KEPT/data" -maxdepth 1 -printf '%f ' 2>/dev/null) rc=$RC: $(grep -B3 -iE "state-file.py beside" <<<"$OUT" | head -6)"
  fi
  # The account controls what sits at the temporary name inside data/. A
  # link, a directory, or a second link to the live database is never kept
  # as the snapshot, and nothing it points at is touched. The runuser fake
  # plants the shape in place of the copy, at the name the run chose.
  printf 'not yours\n' > "$TMP/victim"; chmod 0644 "$TMP/victim"
  for shape in link dir hardlink; do
    reset
    make_installed_host
    stamp_an_older_release
    SOURCE_URL_FOR_RUN="file://$TMP/release.tar.gz"
    SHA_FOR_RUN="$GOOD_SHA"
    rm -f "$KEPT/data/aperire.db"
    "$REAL_SQLITE3" "$KEPT/data/aperire.db" "create table t(x); insert into t values('kept');"
    mkdir -p "$TMP/etc/systemd/system"
    printf '[Service]\nUser=nobody\n' > "$TMP/etc/systemd/system/aperire-server.service"
    cat > "$TMP/bin/runuser" <<RUEOF
#!/usr/bin/env bash
args=("\$@")
last="\${args[\$((\${#args[@]}-1))]}"
if [[ "\$last" == "VACUUM INTO '"* ]]; then
  t="\${last#VACUUM INTO \'}"; t="\${t%\'}"
  case "$shape" in
    link)     ln -s "$TMP/victim" "\$t" ;;
    dir)      mkdir "\$t"; : > "\$t/inside" ;;
    hardlink) ln "$KEPT/data/aperire.db" "\$t" ;;
  esac
  exit 0
fi
while [[ \$# -gt 0 && "\$1" != -- ]]; do shift; done
shift; exec "\$@"
RUEOF
    chmod +x "$TMP/bin/runuser"
    run_file "$PUBLISHED_COPY" --update --yes
    if [[ -z "$(db_snapshot)" && "$OUT" == *"was removed"* \
          && "$(cat "$TMP/victim")" == "not yours" && "$(stat -c %a "$TMP/victim")" == 644 \
          && "$(stat -c %h "$KEPT/data/aperire.db")" == 1 ]]; then
      ok "a $shape at the snapshot's temporary name is removed, never kept as the snapshot, and nothing it named is touched"
    else
      bad "a $shape at the snapshot's name is not kept" \
          "snap=$(db_snapshot) victim=$(stat -c '%a %s' "$TMP/victim") db-links=$(stat -c %h "$KEPT/data/aperire.db" 2>/dev/null) rc=$RC: $(grep -i snapshot <<<"$OUT" | tail -3)"
    fi
  done
  rm -f "$TMP/bin/runuser" "$TMP/etc/systemd/system/aperire-server.service"
else
  ok "SKIP: no sqlite3 on this host to drive the own-account snapshot with"
fi


echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
