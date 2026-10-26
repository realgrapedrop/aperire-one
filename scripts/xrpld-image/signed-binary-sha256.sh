#!/bin/sh
# The SHA-256 of one release's xrpld binary, as it comes through the XRPL
# Foundation's signed package chain.
#
# Why this exists. The official rippleci/xrpld image publishes a DEB_SHA256
# build argument and a --version string. Both are claims: the image's build
# fetched its .deb from packages-upload.xrplf.org and compared one hash, not
# apt's signed repository metadata, so neither claim binds the bytes that
# would run to the Foundation's signing key. This does. It walks the same
# chain the Dockerfile beside it walks (the pinned key fingerprint, the
# signed InRelease, the Packages entry's SHA-256), unpacks the .deb apt
# verified, and hashes usr/bin/xrpld out of it. Nothing is installed, nothing
# is built, and no hash is typed into a file anywhere: the answer is derived
# from the signed chain every time it is asked for.
#
# It also asks that binary what release and commit it is. That is where the
# "announced commit" comes from: not a table somebody types a hash into
# after reading an announcement, but the binary the signed chain just
# verified, saying so itself. A release with no row anywhere still has an
# answer, and the answer cannot drift from the package.
#
# Run inside a throwaway ubuntu container by the wrapper's
# signed-binary-sha256 verb. It installs the package inside that throwaway
# container, maintainer scripts and all, because a bare binary unpacked from
# a .deb has none of its shared libraries and an exec failure would read as
# a release that reports nothing. Nothing is installed on the host, and the
# container is gone when it returns.
#
# It expects XRPLD_VERSION in the environment, and XRPLD_DEB_SHA256 when it
# is checking an image: the .deb hash that image says it was built from. On
# success it writes these lines to stdout, after the md5sum: lines:
#
#   package=xrpld=<pkg version>
#   deb_sha256=<64 hex, the .deb apt verified>
#   newest_revision=<the newest signed revision of this release>
#   binary_sha256=<64 hex>
#   binary_version=<release>
#   binary_commit=<40 hex, or empty when the binary does not print one>
#
# Everything else goes to stderr, so a caller can read the facts without
# parsing apt. Exit 3 is a finding about the image (no revision of this
# release in the signed index is the .deb it names); any other failure is
# the chain not being read.

set -eu

fail() { echo "signed-binary-sha256: $*" >&2; exit 1; }
# Not "could not read the chain": the chain was read, and the image's own
# claim is not in it. A caller says those two differently.
refuse() { echo "signed-binary-sha256: $*" >&2; exit 3; }

# The same fingerprint the recipe's Dockerfile pins, from the XRPL install
# guide and xrpl.org's Ubuntu page. Two copies of one constant is a thing to
# watch; the alternative is this script sourcing a file it would then have to
# trust, inside a container where that file is the thing being established.
EXPECTED_FPR=B655416741221F780FBCFBC9AA84D41A11D29FA9
APT_SOURCE='deb [signed-by=/etc/apt/keyrings/xrplf.asc] https://packages.xrplf.org/repository/deb-stable any main'

case "${XRPLD_VERSION:-}" in
  '') fail "XRPLD_VERSION is required" ;;
  *[!0-9.]*) fail "XRPLD_VERSION must be digits and dots, got '$XRPLD_VERSION'" ;;
esac
[ "${#XRPLD_VERSION}" -le 24 ] || fail "XRPLD_VERSION is longer than 24 characters"
case "${XRPLD_DEB_SHA256:-}" in
  '') ;;
  *[!0-9a-f]*) fail "XRPLD_DEB_SHA256 must be lowercase hex" ;;
  *) [ "${#XRPLD_DEB_SHA256}" -eq 64 ] || fail "XRPLD_DEB_SHA256 must be 64 hex characters" ;;
esac

export DEBIAN_FRONTEND=noninteractive

echo "fetching the signing key" >&2
apt-get update >&2
apt-get install -y --no-install-recommends ca-certificates curl gnupg binutils >&2
install -d -m 0755 /etc/apt/keyrings
curl -fsS --proto '=https' --tlsv1.2 https://packages.xrplf.org/xrplf.asc \
  -o /etc/apt/keyrings/xrplf.asc

# The fingerprint, and the shape of the key file: exactly one primary key and
# no subkeys, so a key file that carries a second signer cannot be read as
# the one this pins.
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
gpg --batch --show-keys --with-colons /etc/apt/keyrings/xrplf.asc > "$GNUPGHOME/keyinfo"
pubs=$(grep -c '^pub:' "$GNUPGHOME/keyinfo" || true)
subs=$(grep -c '^sub:' "$GNUPGHOME/keyinfo" || true)
fpr=$(awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; exit }' "$GNUPGHOME/keyinfo")
[ "$pubs" = 1 ] || fail "the key file holds $pubs primary keys, expected exactly 1"
[ "$subs" = 0 ] || fail "the key file holds $subs subkeys, expected none"
[ "$fpr" = "$EXPECTED_FPR" ] || fail "key fingerprint is '$fpr', expected $EXPECTED_FPR"
echo "signing key fingerprint verified: $fpr" >&2
rm -rf "$GNUPGHOME"; unset GNUPGHOME

echo "$APT_SOURCE" > /etc/apt/sources.list.d/xrplf.list
apt-get update >&2

# Which package revision to read (#1001). One release can be published as
# more than one revision: 3.4.1-1, then 3.4.1-2 on 2026-10-09, each with
# its own binary. The official image carries one of them, and checking it
# against "the newest revision of 3.4.1" refused every genuine 3.4.1 image
# the day -2 appeared. So the revision is the one whose .deb hash, in apt's
# own signed index, is the hash the image names. Never the newest, never the
# first: with no hash to go by and more than one revision, it refuses.
#
# Everything between the two marker lines is cut out and run by
# test-xrpld-image.sh against a fake apt-cache. Keep it plain sh, as the
# after-fetch block below.
# -- which revision: begin
listing=$(apt-cache madison xrpld 2>/dev/null \
       | awk -v v="$XRPLD_VERSION" -F'|' '{ gsub(/ /, "", $2)
           if (index($2, v "-") == 1 && substr($2, length(v) + 2) ~ /^[0-9]+$/) print $2 }')
revs=$(printf '%s\n' "$listing" | sort -u)
[ -n "$listing" ] || fail "packages.xrplf.org lists no xrpld $XRPLD_VERSION in deb-stable"
# The newest signed revision of this release, in apt's own version order
# (madison lists newest first). Reported, never chosen: an image carrying an
# older revision still verifies, and the caller says it is not the newest
# (operator ruling on #1001).
newest=$(printf '%s\n' "$listing" | head -1)
listed=$(printf '%s\n' "$revs" | paste -sd' ' -)
pkg=""
if [ -n "${XRPLD_DEB_SHA256:-}" ]; then
  for r in $revs; do
    s=$(apt-cache show "xrpld=$r" 2>/dev/null | sed -n 's/^SHA256:[[:space:]]*//p' | head -1)
    if [ "$s" = "$XRPLD_DEB_SHA256" ]; then pkg=$r; break; fi
  done
  [ -n "$pkg" ] || refuse "no revision of xrpld $XRPLD_VERSION in the signed index is the package $XRPLD_DEB_SHA256 (it lists $listed)"
else
  n=$(printf '%s\n' "$revs" | grep -c .)
  [ "$n" -eq 1 ] || fail "xrpld $XRPLD_VERSION is published as $n package revisions ($listed); which one is meant depends on the image being checked, and the newest is never assumed"
  pkg=$revs
fi
echo "package revision: xrpld=$pkg" >&2
# -- which revision: end

# --download-only first, so the bytes are on disk and hashed before
# anything runs them. apt verifies the Packages entry's SHA-256 against the
# signed InRelease before it writes the file, which is the whole point of
# going through apt rather than fetching a URL.
apt-get install -y --no-install-recommends --download-only "xrpld=${pkg}" >&2
deb="/var/cache/apt/archives/xrpld_${pkg}_amd64.deb"
[ -f "$deb" ] || fail "apt did not leave $deb in its cache"
# The .deb apt verified against the signed index, hashed here. When the
# caller named one, these are the same bytes or nothing below is read: the
# revision was chosen by that hash, and this is the chain confirming it.
# Cut out and run by test-xrpld-image.sh against a fake fetched .deb.
# -- after fetch: begin
deb_sha=$(sha256sum "$deb" | cut -d' ' -f1)
if [ -n "${XRPLD_DEB_SHA256:-}" ] && [ "$deb_sha" != "$XRPLD_DEB_SHA256" ]; then
  refuse "apt fetched xrpld=$pkg as $deb_sha, not the package $XRPLD_DEB_SHA256"
fi
# -- after fetch: end

out=$(mktemp -d)
dpkg-deb -x "$deb" "$out"
[ -f "$out/usr/bin/xrpld" ] || fail "the package holds no usr/bin/xrpld"
sha=$(sha256sum "$out/usr/bin/xrpld" | cut -d' ' -f1)

# And what that binary says it is. Installed rather than run out of the
# unpacked tree, because a bare binary has none of its shared libraries and
# an exec failure here would read as a release that reports nothing. The
# .deb is already in apt's cache, so this installs from the bytes just
# hashed and fetches only the runtime dependencies. systemd-standalone-
# sysusers first satisfies the package's systemd alternative without
# pulling in systemd, exactly as the recipe's Dockerfile does.
#
# The hash above is taken from the unpacked copy on purpose: it is the
# package's own bytes, before any maintainer script has run.
apt-get install -y --no-install-recommends systemd-standalone-sysusers >&2
apt-get install -y --no-install-recommends "xrpld=${pkg}" >&2
installed=$(sha256sum /usr/bin/xrpld | cut -d' ' -f1)
[ "$installed" = "$sha" ] \
  || fail "the installed binary hashes $installed and the package holds $sha"
vout=$(/usr/bin/xrpld --version 2>&1) || fail "the binary would not report a version"
ver=$(printf '%s\n' "$vout" | sed -n 's/^xrpld version \([0-9.]*\)$/\1/p' | head -1)
commit=$(printf '%s\n' "$vout" | sed -n 's/^Git commit hash: \([0-9a-f]\{40\}\)$/\1/p' | head -1)
[ "$ver" = "$XRPLD_VERSION" ] \
  || fail "the signed package's binary reports '$ver', asked for $XRPLD_VERSION"
# Every file the package owns, with the hash the package itself records for
# it (#682, review of 2026-09-27). The binary's hash says nothing about the
# rest of the package: validator-keys sits beside xrpld, the stock config
# and the unit are read by the installer, and a genuine binary beside a
# tampered anything-else is not a genuine node. Printed as `md5sum: <hash>
# <path>` so the caller can compare an image's own copies file by file
# without running any of that image's code.
#
# md5, because that is what dpkg records in the package's own md5sums and
# the point here is "what the .deb says these files are", not a hash chosen
# for strength: the .deb itself is already bound to the Foundation's key by
# apt's signed metadata, which is the strong link.
if [ -f "$out/DEBIAN/md5sums" ]; then
  sed 's/^/md5sum: /' "$out/DEBIAN/md5sums"
else
  # Some builds strip DEBIAN/md5sums from an unpacked tree. Recompute from
  # what the package actually holds, which is the same statement.
  ( cd "$out" && find . -type f ! -path './DEBIAN/*' -exec md5sum {} + \
    | sed 's#\./##; s/^/md5sum: /' )
fi

rm -rf "$out"

printf 'package=xrpld=%s\n' "$pkg"
printf 'deb_sha256=%s\n' "$deb_sha"
printf 'newest_revision=%s\n' "$newest"
printf 'binary_sha256=%s\n' "$sha"
printf 'binary_version=%s\n' "$ver"
printf 'binary_commit=%s\n' "$commit"
