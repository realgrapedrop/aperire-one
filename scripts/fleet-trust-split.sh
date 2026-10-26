#!/usr/bin/env bash
# The fleet trust key is the dashboard's alone; the Advisor reads only the
# public half (#868, ADR 0024 row 19).
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run fleet-trust-split
#   source scripts/fleet-trust-split.sh     the functions, for another script
#
# Root runs it only as a copy it checked: the bootstrap's step above, the
# update, or the installers' own staged copies (#897). It takes
# [--repo DIR] [--dry-run] when run that way.
#
# ---- what it fixes ---------------------------------------------------
#
# dashboard/config/fleet-trust.yaml on an aggregator holds `private_key:`, the
# seed that signs every trust bundle and every model.seal, update and attach
# job for every paired node. It used to sit at <dashboard>:aperire-svc 0640,
# because the Advisor reads the same file for public keys: `peers:` to verify
# a pushed bundle, and the public half of private_key to verify a record
# issued as `self` (#477). So the Advisor's account could read the key too.
# Nothing it ran signed with it, but it had no reason to hold it.
#
# ---- the shape this leaves -------------------------------------------
#
# A file that holds a private_key:
#   fleet-trust.yaml       <dashboard>:<its own group> 0600. Unchanged in
#                          content. Every reader of the key runs as the
#                          dashboard account or as root.
#   fleet-trust.pub.yaml   root:<group shared with the Advisor> 0640 (its
#                          creator; the dashboard account never needs it).
#                          fleet-trust.yaml with the private_key line taken
#                          out and a `public_key:` line put in, so the peers
#                          block is the same bytes. advisord reads this one
#                          whenever it exists (host.TrustReadPath).
# A file that holds no private_key (a node's, peers only):
#   fleet-trust.yaml       root:<group shared with the Advisor> 0640, the
#                          shape pairing makes. It is never handed to the
#                          dashboard account, which could then rewrite the
#                          key the Advisor trusts, and a file the operator's
#                          login or the dashboard account owns is made root's
#                          wherever the dashboard runs as an account of its
#                          own (#1187: an uninstall --keep hands it to the
#                          login, and a reinstall used to leave it there). On
#                          a host whose dashboard runs as the tree's owner
#                          the owner is left as it is. When a public file
#                          sits beside it (a key was removed by hand), the
#                          public file is rewritten to the same peers, so
#                          advisord never reads a stale copy.
#
# The public file is always written BEFORE the key file is narrowed, so there
# is no moment where the Advisor has neither.
#
# ---- who runs it -----------------------------------------------------
#
#   install-advisor-account.sh   on the Advisor's own account move
#   install-fleet-broker-grant.sh  right after it makes a new trust key
#   aperire-restore.sh           after it puts fleet-trust.yaml back
#   aperire-fleet-pair.sh        after it writes peers.aggregator
#   aperire-fleet-add.sh         after it writes either trust file
#   get-aperire.sh --update      on every update, from the release's checked copy
#   an operator                  the bootstrap's step at the top
#
# Every write goes through scripts/state-file.py: the file is read without
# following a link, the public file is planted on a directory descriptor and
# renamed onto its name, and the key file is re-owned on a descriptor. The
# dashboard account can own dashboard/config on a host that has not moved to
# the target shape yet, and a by-name chown there is a root primitive it can
# point anywhere.
#
# Its ancestor rule stops at <install>/dashboard (--root): every component
# above it must be root's or the install owner's and not writable by a shared
# group, and dashboard/ itself is not judged. An umask-002 tree leaves
# dashboard/ at 0775 on the operator's group, and on a host where that group
# also holds the Advisor's account (koi, #703) the default rule refused it.
# The update narrows <install> itself before this runs (state-ancestors-lib),
# and every hop below is still opened O_NOFOLLOW and the file must have one
# link, so a swapped name is refused rather than followed.

FTS_LEAF=fleet-trust.yaml
FTS_PUB_LEAF=fleet-trust.pub.yaml
FTS_KEY_MODE=0600
FTS_PUB_MODE=0640

# ── the pure part ────────────────────────────────────────────────────────

# fts_render : reads a trust file on stdin, writes its public file to stdout.
#
# Exit 0  it holds a usable private_key; stdout is the public file.
# Exit 3  it holds no private_key; stdout is the file as it is (peers only).
# Exit 4  it has a private_key line that is not a 32-byte seed; nothing out.
# Exit 1  anything else (no python3, no openssl, not UTF-8); nothing out.
#
# The seed is found the way every other reader finds it: the first line
# that starts with `private_key:` at the top level, trimmed, one quote off
# each end (lib/trust-bundle.ts readOwnPrivateKey, advisord's OwnPubKey,
# aperire-fleet-arm.sh). The public half is derived by openssl from a PKCS8
# DER handed over on a pipe, never an argument. Every top-level private_key
# line is dropped, and the output is refused if the seed text appears in it
# anywhere at all.
fts_render() {
  python3 -I -c '
import base64, subprocess, sys
try:
    text = sys.stdin.buffer.read().decode("utf-8")
except UnicodeDecodeError:
    sys.exit(1)
lines = text.split("\n")
seed = None
for line in lines:
    if line.startswith("private_key:"):
        seed = line[len("private_key:"):].strip()
        if seed[:1] in ("\x27", "\""):
            seed = seed[1:]
        if seed[-1:] in ("\x27", "\""):
            seed = seed[:-1]
        break
if seed is None:
    sys.stdout.write(text)
    sys.exit(3)
try:
    raw = base64.urlsafe_b64decode(seed + "=" * (-len(seed) % 4))
except Exception:
    sys.exit(4)
if len(seed) < 40 or len(raw) != 32:
    sys.exit(4)
der = bytes.fromhex("302e020100300506032b657004220420") + raw
try:
    p = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                       input=der, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
except (OSError, subprocess.CalledProcessError):
    sys.exit(1)
pub_raw = p.stdout[-32:]
if len(p.stdout) < 32:
    sys.exit(1)
pub = base64.urlsafe_b64encode(pub_raw).decode().rstrip("=")
kept = [l for l in lines if not l.startswith("private_key:")]
out = "# The public half of fleet-trust.yaml, written by scripts/fleet-trust-split.sh.\n"
out += "# Remade from fleet-trust.yaml on every install and update; edit that file, not this one.\n"
out += "public_key: " + pub + "\n" + "\n".join(kept)
if not out.endswith("\n"):
    out += "\n"
if seed in out:
    sys.exit(1)
sys.stdout.write(out)
sys.exit(0)
'
}

# ── the host part ────────────────────────────────────────────────────────

# fts_advisor_reads_pub : 0 when the Advisor this host runs reads
# fleet-trust.pub.yaml, or there is no Advisor here. 1 when it does not, or
# that cannot be told.
#
# The public file is new in this release, and an advisord built before it
# opens fleet-trust.yaml on every request. Narrow the key under that process
# and every push, self record and knowledge bundle it verifies is a 403 until
# it restarts on the new build. An update from the page restarts nothing,
# and a build carried across an update without Go is still the old one. So
# the key is narrowed only once both the running process (if there is one)
# and the binary its unit starts carry the reader, found by the file name in
# the binary. Until then the public file is written and the key is left as
# it was, which is what every host had before this release.
#
#   FTS_ADVISOR_UNIT        the unit's name (default aperire-advisord)
#   FTS_UNIT_DIR            where it lives (APERIRE_UNIT_DIR, /etc/systemd/system)
#   FTS_ADVISOR_RESTARTING  1 when the caller restarts the Advisor on the
#                           unit's binary right after (the account move), so
#                           only that binary is asked
#   FTS_PROC_DIR            /proc, for a test
fts_advisor_reads_pub() {
  local name="${FTS_ADVISOR_UNIT:-aperire-advisord}"
  local dir="${FTS_UNIT_DIR:-${APERIRE_UNIT_DIR:-/etc/systemd/system}}"
  local proc="${FTS_PROC_DIR:-/proc}" unit pid bin f
  unit="$dir/$name.service"
  [[ -e "$unit" || -L "$unit" ]] || return 0
  if [[ "${FTS_ADVISOR_RESTARTING:-0}" != 1 ]]; then
    pid="$(systemctl show "$name" -p MainPID --value 2>/dev/null)" || pid=""
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
      grep -qaF -e "$FTS_PUB_LEAF" "$proc/$pid/exe" 2>/dev/null || return 1
    fi
  fi
  # The binary the unit starts: the last ExecStart= under [Service], in the
  # unit and then its drop-ins in name order, with systemd's prefixes off.
  bin=""
  for f in "$unit" "$unit.d"/*.conf; do
    [[ -r "$f" ]] || continue
    local b
    b="$(awk '
      /^[[:space:]]*\[/ { sec = $0; gsub(/[[:space:]]/, "", sec); next }
      sec == "[Service]" && /^[[:space:]]*ExecStart[[:space:]]*=/ {
        v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/^[-@:+!]+/, "", v)
        split(v, w, /[[:space:]]+/); last = w[1]
      }
      END { print last }' "$f")"
    [[ -n "$b" ]] && bin="$b"
  done
  [[ -n "$bin" && -r "$bin" ]] || return 1
  grep -qaF -e "$FTS_PUB_LEAF" "$bin"
}

# fts_render_meta <file> : reads state-file.py's `read --meta-ino` on stdin.
# The first line (owner, group, mode, device, inode of the file as opened) goes
# to <file>; the rest is the file's bytes, rendered as fts_render does, with its
# exit status. The inode is what the re-owns below are held to.
fts_render_meta() {
  local first=""
  IFS= read -r first || true
  printf '%s\n' "$first" > "$1"
  fts_render
}

# fts_converge <repo> <dashboard-account> <public-group> <state-file.py>
#
# Puts this host's trust file in the shape above. Prints one line per thing
# it did or found. Returns 0 when the file is in that shape (or there is no file), 1 when it
# could not be put there; what it says names why.
fts_converge() {
  local repo="$1" dash="$2" pubgrp="$3" tool="$4"
  local cfg="$repo/dashboard/config" trust pub dash_uid dash_gid pub_gid work rc=0 rc_read rc_render
  trust="$cfg/$FTS_LEAF"
  pub="$cfg/$FTS_PUB_LEAF"
  if [[ ! -e "$trust" && ! -L "$trust" ]]; then
    printf '%s\n' "no $FTS_LEAF on this host, nothing to split"
    return 0
  fi
  [[ -r "$tool" ]] || { printf '%s\n' "state-file.py is not at $tool, so $trust was not touched" >&2; return 1; }
  if ! dash_uid="$(id -u "$dash" 2>/dev/null)" || ! dash_gid="$(id -g "$dash" 2>/dev/null)"; then
    printf '%s\n' "the dashboard account '$dash' does not exist here, so $trust was not touched" >&2
    return 1
  fi
  [[ "$dash_uid" != 0 ]] || { printf '%s\n' "the dashboard account resolved to root, so $trust was not touched" >&2; return 1; }
  pub_gid="$(getent group "$pubgrp" | cut -d: -f3)"
  [[ -n "$pub_gid" ]] || { printf '%s\n' "the group '$pubgrp' does not exist here, so $trust was not touched" >&2; return 1; }

  work="$(mktemp -d)" || return 1
  # The private key crosses from the read straight into the render on a
  # pipe and is never written to disk; only the public file lands in $work.
  python3 -I "$tool" read "$trust" --meta-ino --root "$repo/dashboard" | fts_render_meta "$work/meta" > "$work/pub"
  rc_read=${PIPESTATUS[0]} rc_render=${PIPESTATUS[1]}
  local t_uid t_dev t_ino expect
  read -r t_uid _ _ t_dev t_ino < "$work/meta" || true
  if (( rc_read != 0 )) || ! [[ "${t_uid:-}" =~ ^[0-9]+$ && "${t_dev:-}" =~ ^[0-9]+$ && "${t_ino:-}" =~ ^[0-9]+$ ]]; then
    rm -rf -- "$work"
    printf '%s\n' "$trust could not be read safely (a link, a special file, or more than one name), so nothing was changed" >&2
    return 1
  fi
  # Every re-own of the trust file below is held to the inode that was read, so
  # a file renamed onto the name since is refused and left as it is, not given
  # to whoever this decided the one it read should go to.
  expect="$t_dev:$t_ino"
  case "$rc_render" in
    0)
      if ! python3 -I "$tool" plant "$pub" "" "$pub_gid" "$FTS_PUB_MODE" --stdin --root "$repo/dashboard" < "$work/pub"; then
        rm -rf -- "$work"
        printf '%s\n' "could not write $pub, so $trust was left as it was" >&2
        return 1
      fi
      printf '%s\n' "$FTS_PUB_LEAF -> $(id -un):$pubgrp $FTS_PUB_MODE, the public half the Advisor reads"
      if ! fts_advisor_reads_pub; then
        printf '%s\n' "not yet narrowed: $FTS_LEAF is left as it was, because the Advisor running here predates $FTS_PUB_LEAF and would refuse every push without the key file. Restart it on this release's build (sudo systemctl restart ${FTS_ADVISOR_UNIT:-aperire-advisord}), then: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      elif ! python3 -I "$tool" own "$trust" "$dash_uid" "$dash_gid" "$FTS_KEY_MODE" --root "$repo/dashboard" --expect "$expect"; then
        rc=1
        printf '%s\n' "could not narrow $trust to $FTS_KEY_MODE; the Advisor's account may still read the key" >&2
      else
        printf '%s\n' "$FTS_LEAF -> $dash:$(id -gn "$dash") $FTS_KEY_MODE, the private key, the dashboard's alone"
      fi
      ;;
    3)
      if [[ -e "$pub" || -L "$pub" ]]; then
        if python3 -I "$tool" plant "$pub" "" "$pub_gid" "$FTS_PUB_MODE" --stdin --root "$repo/dashboard" < "$work/pub"; then
          printf '%s\n' "$FTS_PUB_LEAF rewritten to the same peers as $FTS_LEAF, which holds no private key"
        else
          rc=1
          printf '%s\n' "could not rewrite $pub, which the Advisor reads in place of $FTS_LEAF; remove it by hand" >&2
        fi
      fi
      # Pairing makes a node's file root's, and an account that owned it could
      # rewrite peers.aggregator, the key the Advisor verifies every push
      # against. So on a host whose dashboard runs as an account of its own
      # (ADR 0024: the tree's owner is somebody else), a file any other
      # account owns goes to root: the dashboard account's, which a restore or
      # an older account move left (#873 review, M2), and the operator's
      # login's, which an uninstall --keep hands it to and a reinstall used to
      # keep (#1187). Where the dashboard runs as the tree's owner, that
      # account owns the whole tree anyway and the owner is left as it is.
      # A file root already owns keeps its owner; only the group and the mode
      # are this program's to set on it.
      local keep_uid="" r_uid
      r_uid="$(stat -c '%u' "$repo" 2>/dev/null)"
      if [[ "$t_uid" != 0 && -n "$r_uid" && "$r_uid" != "$dash_uid" ]]; then keep_uid=0; fi
      if python3 -I "$tool" own "$trust" "$keep_uid" "$pub_gid" "$FTS_PUB_MODE" --root "$repo/dashboard" --expect "$expect"; then
        printf '%s\n' "$FTS_LEAF -> $(stat -c '%U' "$trust" 2>/dev/null):$pubgrp $FTS_PUB_MODE, peers only, so the Advisor reads it where it is"
      else
        rc=1
        printf '%s\n' "could not set $trust to group $pubgrp, $FTS_PUB_MODE" >&2
      fi
      ;;
    4)
      # A key line that is not a key is still possibly a secret: narrow it,
      # and make no public file from it.
      python3 -I "$tool" own "$trust" "$dash_uid" "$dash_gid" "$FTS_KEY_MODE" --root "$repo/dashboard" --expect "$expect" || true
      rc=1
      printf '%s\n' "$trust has a private_key line that is not a 32-byte seed. It was narrowed to $FTS_KEY_MODE and no public file was made from it. Fix it by hand" >&2
      ;;
    *)
      rc=1
      printf '%s\n' "$trust could not be split (python3 or openssl failed, or it is not UTF-8 text), so nothing was changed" >&2
      ;;
  esac
  rm -rf -- "$work"
  return "$rc"
}

# fts_fingerprint <trust> <pub>: owner, group, mode and content hash of the
# public file, and owner, group and mode of the key file. Metadata only for
# the key file, so its bytes are never read here.
fts_fingerprint() {
  local f out=""
  for f in "$1" "$2"; do
    out+="$(stat -c '%u:%g:%a:%F' -- "$f" 2>/dev/null || printf 'absent');"
  done
  out+="$(sha256sum -- "$2" 2>/dev/null | cut -d' ' -f1)"
  printf '%s' "$out"
}

# Run directly, or be sourced. ${BASH_SOURCE[0]} != $0 when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -uo pipefail
  FTS_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # The install: the one APERIRE_INSTALL_TREE names when root runs a copy the
  # bootstrap staged (--run fleet-trust-split), else this checkout. --repo wins.
  FTS_REPO="${APERIRE_INSTALL_TREE:-$(cd "$FTS_SELF/.." && pwd)}"
  FTS_DRY=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) FTS_REPO="${2:?--repo takes a directory}"; shift 2 ;;
      --dry-run) FTS_DRY=1; shift ;;
      -h|--help) awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
      *) printf 'error: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
  done
  [[ $EUID -eq 0 ]] || { printf 'error: run it as root: sudo bash %s\n' "$0" >&2; exit 2; }
  # shellcheck source=scripts/fleet-trust-perms.sh
  # shellcheck disable=SC1091  # resolved at runtime, beside this file
  . "$FTS_SELF/fleet-trust-perms.sh" || exit 2
  FTS_UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
  # Which account runs the dashboard: the one rule every tool uses for it
  # (dashboard-account-lib.sh, ADR 0024 lane 4), the unit serving this
  # checkout with its drop-ins, never a third reading (#873 review, L4).
  # shellcheck source=scripts/dashboard-account-lib.sh
  # shellcheck disable=SC1091  # resolved at runtime, beside this file
  . "$FTS_SELF/dashboard-account-lib.sh" || exit 2
  DA_UNIT_DIR="$FTS_UNIT_DIR"
  FTS_DA_RC=0
  da_resolve_repo "$FTS_REPO" || FTS_DA_RC=$?
  if (( FTS_DA_RC >= 2 )) || [[ -z "$DA_ACCOUNT" || "$DA_ACCOUNT" == root ]]; then
    printf 'error: could not tell which account runs the dashboard here, so nothing was changed: %s\n' "${DA_WHY:-it resolved to root}" >&2
    exit 2
  fi
  FTS_DASH="$DA_ACCOUNT"
  # Exit 3 is a unit that is there and names no User= this can read (#809).
  # That is not "no Advisor": the public file would land on the dashboard's
  # own group, where the real Advisor cannot read it, so it is a refusal.
  FTS_ADV="" FTS_ADV_RC=0
  FTS_ADV="$(ft_advisor_account "$FTS_UNIT_DIR" "${FTS_ADVISOR_UNIT:-aperire-advisord}")" || FTS_ADV_RC=$?
  if (( FTS_ADV_RC != 0 )); then
    printf 'error: the %s unit is there but names no account this can read, so which account reads the public file is unknown. Nothing was changed. Check: systemctl cat %s\n' \
      "${FTS_ADVISOR_UNIT:-aperire-advisord}" "${FTS_ADVISOR_UNIT:-aperire-advisord}" >&2
    exit 2
  fi
  FTS_PLAN="$(ft_target "$FTS_DASH" "$FTS_ADV")" \
    || { printf 'error: the dashboard account %s and the Advisor account %s share no group, so no public file could be read by both\n' "$FTS_DASH" "$FTS_ADV" >&2; exit 2; }
  read -r _ FTS_GROUP _ <<<"$FTS_PLAN"
  [[ -n "$FTS_GROUP" ]] || { printf 'error: no group for the public file\n' >&2; exit 2; }
  FTS_BEFORE="$(fts_fingerprint "$FTS_REPO/dashboard/config/$FTS_LEAF" "$FTS_REPO/dashboard/config/$FTS_PUB_LEAF")"
  if (( FTS_DRY )); then
    printf 'would split %s/dashboard/config/%s: key %s:%s %s, public file root:%s %s\n' \
      "$FTS_REPO" "$FTS_LEAF" "$FTS_DASH" "$(id -gn "$FTS_DASH")" "$FTS_KEY_MODE" "$FTS_GROUP" "$FTS_PUB_MODE"
    exit 0
  fi
  FTS_OUT="$(fts_converge "$FTS_REPO" "$FTS_DASH" "$FTS_GROUP" "$FTS_SELF/state-file.py" 2>&1)"; FTS_RC=$?
  # Quiet when nothing moved: an update runs this every time, and a line
  # that says the same thing on every run is a line nobody reads.
  if (( FTS_RC == 0 )) && [[ "$FTS_OUT" != *"nothing to split"* && "$FTS_OUT" != *"not yet narrowed"* ]] \
     && [[ "$(fts_fingerprint "$FTS_REPO/dashboard/config/$FTS_LEAF" "$FTS_REPO/dashboard/config/$FTS_PUB_LEAF")" == "${FTS_BEFORE:-}" ]]; then
    printf '%s\n' "fleet-trust.yaml is already in shape, nothing changed"
  else
    printf '%s\n' "$FTS_OUT"
  fi
  exit "$FTS_RC"
fi
