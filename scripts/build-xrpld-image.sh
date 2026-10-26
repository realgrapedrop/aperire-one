#!/usr/bin/env bash
# Build xrpld into a local Docker image from the XRPL Foundation's signed DEB
# package, then prove the image holds the version that was asked for.
#
#   bash scripts/build-xrpld-image.sh                  # the default version below
#   bash scripts/build-xrpld-image.sh --version 3.4.1
#
# Options:
#   --version V         xrpld upstream version, digits and dots (default below)
#   --revision N        the package revision, the "1" in 3.4.1-1 (default 1)
#   --deb-sha256 HEX    the .deb's SHA-256 as the release announcement gives
#                       it. Taken from the table below for a version listed
#                       there; any other version needs this or --no-deb-sha256
#   --no-deb-sha256     build a version the table does not list without the
#                       second hash check. The signed repository still
#                       verifies the package; this only drops the extra pin
#   --tag NAME:TAG      the local tag (default localhost/xrpld:<version>). It
#                       has to start with localhost/, which can never resolve
#                       to Docker Hub, and its tag part has to be the version
#                       being built, either 3.4.1 or 3.4.1-2, so the name
#                       cannot say 3.4.0 over a 3.4.1 image. Use the
#                       package-version form to keep a second revision of one
#                       release beside the first
#   --rebuild           build again even though the tag already exists, and
#                       move the tag to the new image. Without it an existing
#                       tag is verified and kept, never replaced. If the new
#                       image fails to verify, the tag goes back on the image
#                       it named before this run
#   --no-cache          rebuild every layer (implies nothing about the tag)
#   -h, --help          this header
#
# Exit status: 0 built or verified, 1 refused or failed (the last line says
# why), 3 the version asked for is not in the repository's index.
#
# What it does, in order:
#   1. docker build scripts/xrpld-image/ with the version, package version,
#      the .deb hash and the build time as build args. The Dockerfile checks
#      the signing key's fingerprint and fails on a mismatch.
#      If the tag already exists, it is NOT rebuilt: it is verified as it
#      stands. Two builds of one version are different images (the build
#      date is in them), so a rebuild would move the tag away from the image
#      a running node was created from, and the next recreate would change
#      the node's image with nobody having asked. --rebuild does it on
#      purpose, and prints the image ID it displaced.
#   2. Prints the image ID and whatever RepoDigests holds. Which one is the
#      "digest" depends on the Docker image store. With the containerd store
#      the ID is the manifest digest and RepoDigests repeats it under the
#      local name (seen on Docker 29). The classic overlay2 store is expected
#      to show no RepoDigests for a local build (not tested here). Either
#      way nothing here came from a registry, and this script never pushes.
#   3. Runs the image, with no network: `xrpld --version`, the package
#      database's version of xrpld, and the provenance file the build wrote.
#      All of it must match what was asked for: the binary, the package, the
#      default user 997:997, the version label, the signing-key fingerprint
#      the image records, and, when a .deb hash is pinned, the hash the build
#      actually saw. That last pair is what makes verifying an existing tag
#      worth anything: without it a tag built months ago from some other
#      package would pass on its version number alone.
#      On any mismatch the script exits non-zero. A tag this run built is
#      taken off the bad image, and goes back on the image it named before
#      the run if there was one; a tag that already existed is left alone and
#      reported, because a node may be running it.
#
# It needs docker and an x86_64 host: the package is published for amd64 only.
# It pulls one image, the ubuntu base, by the digest the Dockerfile pins.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTEXT="${HERE}/xrpld-image"

# Versions whose .deb hash I have read from the release announcement myself.
# Bump DEFAULT_VERSION only together with a row here, with the announcement
# open. The default is the newest version this table can vouch for.
#   3.4.1  https://xrpl.org/blog/2026/xrpld-3.4.1
#   3.4.0  https://xrpl.org/blog/2026/xrpld-3.4.0
DEFAULT_VERSION=3.4.1
# The default revision stays 1 (#1001). 3.4.1-2 appeared in the signed
# repository on 2026-10-09 with a different binary and no announcement to
# read a hash from, and the official image carries 3.4.1-1. A build that
# followed the newest revision would stop matching the official image and
# take a hash nobody has read. Build -2 on purpose with --revision 2 and
# --deb-sha256 (or --no-deb-sha256).
known_deb_sha256() {
  case "$1" in
    3.4.1-1) echo cae8ce3b9bc9451b19975c890714ba789d2004987cdfff9cbd55522c612c6f26 ;;
    3.4.0-1) echo 4dc40a21b12b7d21f2760b16545c1d842962a96978dd3199eb8de9aa0aff8339 ;;
    *) return 1 ;;
  esac
}

# The signing key the Dockerfile checks, printed here so the build log says it.
KEY_FINGERPRINT=B655416741221F780FBCFBC9AA84D41A11D29FA9
REPO_INDEX=https://packages.xrplf.org/repository/deb-stable/dists/any/main/binary-amd64/Packages

die()  { echo "error: $*" >&2; exit 1; }
say()  { printf '\n== %s\n' "$*"; }

VERSION="$DEFAULT_VERSION"
REVISION=1
DEB_SHA256=""
NO_DEB_SHA256=0
TAG=""
NO_CACHE=()
REBUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)       [[ $# -ge 2 ]] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
    --revision)      [[ $# -ge 2 ]] || die "--revision needs a value"; REVISION="$2"; shift 2 ;;
    --deb-sha256)    [[ $# -ge 2 ]] || die "--deb-sha256 needs a value"; DEB_SHA256="$2"; shift 2 ;;
    --no-deb-sha256) NO_DEB_SHA256=1; shift ;;
    --tag)           [[ $# -ge 2 ]] || die "--tag needs a value"; TAG="$2"; shift 2 ;;
    --no-cache)      NO_CACHE=(--no-cache); shift ;;
    --rebuild)       REBUILD=1; shift ;;
    -h|--help)       sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)               die "unknown option: $1 (see --help)" ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]] || die "--version must be digits and dots, got '$VERSION'"
[[ "$REVISION" =~ ^[0-9]+$ ]] || die "--revision must be digits, got '$REVISION'"
PKG_VERSION="${VERSION}-${REVISION}"
TAG="${TAG:-localhost/xrpld:${VERSION}}"
[[ "$TAG" =~ ^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || die "--tag must be name:tag, got '$TAG'"
[[ "${TAG##*:}" != latest ]] || die "refusing the tag 'latest': a version tag says what the node runs, 'latest' does not"
[[ "$TAG" == localhost/* ]] || die "--tag must start with localhost/, got '$TAG'. Any other name can be resolved against a registry, and then a pull of it fetches someone else's image instead of failing"
# Either form of the version being built. The upstream version is the usual
# tag; the package version lets a second revision of the same upstream release
# sit beside the first (localhost/xrpld:3.4.1 and localhost/xrpld:3.4.1-2)
# instead of one having to displace the other. Any other version is refused:
# a name that says one version over another version's image is how the wrong
# node gets deployed.
[[ "${TAG##*:}" == "$VERSION" || "${TAG##*:}" == "$PKG_VERSION" ]] \
  || die "--tag's tag part must be the version being built, '${VERSION}' or '${PKG_VERSION}', got '${TAG##*:}'"

if [[ -z "$DEB_SHA256" ]] && DEB_SHA256="$(known_deb_sha256 "$PKG_VERSION")"; then
  :
elif [[ -z "$DEB_SHA256" ]] && (( NO_DEB_SHA256 == 0 )); then
  die "no announced SHA-256 on file for xrpld ${PKG_VERSION}. Pass --deb-sha256 from its release announcement, or --no-deb-sha256 to rely on the signed repository alone"
fi
[[ -z "$DEB_SHA256" || "$DEB_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--deb-sha256 must be 64 lowercase hex characters"

command -v docker >/dev/null 2>&1 || die "docker is not installed"
[[ "$(uname -m)" == x86_64 ]] || die "the xrpld package is published for x86_64 only; this host is $(uname -m)"
[[ -f "${CONTEXT}/Dockerfile" && -f "${CONTEXT}/entrypoint.sh" ]] || die "missing ${CONTEXT}/Dockerfile or entrypoint.sh"

# Is there something newer than what is being built, and is the version
# asked for there at all? The index is read unauthenticated here, so it never
# vouches for a package: apt checks the signed chain inside the build. What
# it can do is refuse a build that could only fail, and the one refusal it
# makes is below.
#
# Every line is held to the version shape BEFORE it is compared, not after.
# This output is printed, and the Advisor relays it (#664): one crafted
# Version: line in a response nobody authenticated would otherwise both win
# the sort, hiding a genuinely newer version, and put its own text on an
# operator's screen.
newest=""
listed=()
carried=0
# Read whole, and judged only when curl says it read it whole. A reply cut
# off part way (a timeout, a short body) ends in a non-zero exit, and a list
# missing its last lines must never be taken for "not carried". Bounded in
# size, since nobody authenticated it.
index=""
index_read=0
if index="$(curl -fsS --max-time 15 --max-filesize 33554432 "$REPO_INDEX" 2>/dev/null)"; then
  index_read=1
else
  index=""
fi
while read -r candidate; do
  [[ "$candidate" =~ ^[0-9]+(\.[0-9]+)*-[0-9]+$ ]] || continue
  [[ "$candidate" == "$PKG_VERSION" ]] && carried=1
  listed+=("$candidate")
  if [[ -z "$newest" ]] \
     || [[ "$(printf '%s\n%s\n' "$newest" "$candidate" | sort -V | tail -1)" == "$candidate" ]]; then
    newest="$candidate"
  fi
done < <(awk '/^Package: xrpld$/ { p = 1; next } /^Package:/ { p = 0 } p && /^Version:/ { print $2 }' <<<"$index")
if [[ -n "$newest" && "$newest" != "$PKG_VERSION" ]] \
   && [[ "$(printf '%s\n%s\n' "$newest" "$PKG_VERSION" | sort -V | tail -1)" == "$newest" ]]; then
  echo "note: the stable repository lists xrpld ${newest}, newer than ${PKG_VERSION}. Read its announcement before building it."
fi

EXISTING_ID="$(docker image inspect --format '{{.Id}}' "$TAG" 2>/dev/null || true)"

# A version the repository does not carry. apt says so inside the build, on
# one line of a log several hundred lines long and under the Dockerfile's RUN
# step printed again, and the caller sees only that the build failed (#801).
# Refused here instead, in one line that names what the index does list. Only
# on an index read whole that has xrpld versions in it, and judged against
# every one of them: no route, a reply cut short, or one with no xrpld in it
# decides nothing, and the build runs as it always did. And only when this
# run would build: an existing tag is verified, never fetched. The list
# printed is the newest 40, because a line of a thousand versions is not one
# anybody reads.
if (( index_read == 1 && ${#listed[@]} > 0 && carried == 0 )) \
   && [[ -z "$EXISTING_ID" || "$REBUILD" -eq 1 ]]; then
  shown="$(printf '%s\n' "${listed[@]}" | sort -uV | tail -40 | paste -sd, - | sed 's/,/, /g')"
  total="$(printf '%s\n' "${listed[@]}" | sort -u | grep -c .)"
  if (( total > 40 )); then
    echo "error: xrpld ${PKG_VERSION} is not in the signed repository's index (the newest 40 of the ${total} it lists: ${shown})" >&2
  else
    echo "error: xrpld ${PKG_VERSION} is not in the signed repository's index (it lists: ${shown})" >&2
  fi
  exit 3
fi

if [[ -n "$EXISTING_ID" && "$REBUILD" -eq 0 ]]; then
  say "${TAG} already exists: verifying it, not rebuilding"
  echo "   image ID  ${EXISTING_ID}"
  echo "   (pass --rebuild to build it again and move the tag)"
  BUILT=0
else
  BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  say "building ${TAG}"
  echo "   xrpld          ${VERSION}"
  echo "   package        xrpld=${PKG_VERSION}"
  echo "   .deb SHA-256   ${DEB_SHA256:-(not pinned; signed repository only)}"
  echo "   signing key    ${KEY_FINGERPRINT}"
  echo "   build date     ${BUILD_DATE}"
  [[ -n "$EXISTING_ID" ]] && echo "   replacing      ${EXISTING_ID} (--rebuild)"

  docker build "${NO_CACHE[@]}" \
    --build-arg "XRPLD_VERSION=${VERSION}" \
    --build-arg "XRPLD_PKG_VERSION=${PKG_VERSION}" \
    --build-arg "XRPLD_DEB_SHA256=${DEB_SHA256}" \
    --build-arg "BUILD_DATE=${BUILD_DATE}" \
    --tag "$TAG" \
    "$CONTEXT"
  BUILT=1
fi

IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$TAG")"

refuse() {
  echo "VERIFY FAILED: $*" >&2
  if (( BUILT == 1 )); then
    # This run moved the tag, so this run puts it back where it found it.
    if [[ -n "$EXISTING_ID" ]]; then
      # --rebuild over a tag a node may be running. Re-tagging beats removing:
      # the next recreate reads this name, and a missing image is a node that
      # will not come back at all.
      if docker tag "$EXISTING_ID" "$TAG" >/dev/null 2>&1; then
        echo "${TAG} names ${EXISTING_ID} again, the image it named before this run" >&2
        echo "the image this run built (${IMAGE_ID}) keeps no name. It stays on disk until something prunes it" >&2
      else
        # The old image is gone too (pruned between the build and the verify,
        # say). Leaving the tag on an image that did not verify is the one
        # outcome to avoid, so take the name off it and say what happened.
        docker image rm "$TAG" >/dev/null 2>&1 || true
        echo "could not put ${TAG} back on ${EXISTING_ID}, so the tag was removed instead: it named the image this run built (${IMAGE_ID}), which did not verify, and that is worse than a name that is missing" >&2
        echo "nothing is called ${TAG} now. ${EXISTING_ID} is gone as well, or re-tagging it would have worked" >&2
      fi
    else
      docker image rm "$TAG" >/dev/null 2>&1 || true
      echo "removed the tag ${TAG}" >&2
      echo "the image this run built (${IMAGE_ID}) keeps no name. It stays on disk until something prunes it" >&2
    fi
  else
    # A tag this run did not make may be what a node is running. Leave it,
    # and say so: removing it would only turn a wrong image into a missing one.
    echo "left the existing tag ${TAG} (${IMAGE_ID}) in place; it did not verify, so do not deploy it" >&2
  fi
  exit 1
}

say "verifying ${TAG}"
got_bin="$(docker run --rm --network none --read-only --entrypoint /usr/bin/xrpld "$TAG" --version 2>&1 | head -1)" \
  || refuse "the image would not run xrpld --version"
got_pkg="$(docker run --rm --network none --read-only --entrypoint /usr/bin/dpkg-query "$TAG" -W -f '${Version}' xrpld 2>&1)" \
  || refuse "the image would not answer dpkg-query"
got_user="$(docker image inspect --format '{{.Config.User}}' "$TAG")"
got_label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$TAG")"
got_fpr="$(docker image inspect --format '{{index .Config.Labels "xrpld.package.signing-key-fingerprint"}}' "$TAG")"

# The provenance file is written by the build, from what the build saw. The
# sha256 label is only what the build was told to pin, so the file is the
# answer and the label is not a fallback: this recipe always writes the file
# and always writes a package_sha256 line into it, so an image missing either
# is not an image this script built and is refused.
#
# It is also text out of an image, printed here and relayed onward by the
# Advisor (#664), so it is held to bounded key=value lines of printable ASCII
# before anything reads or prints it. An image is not a trusted source of
# terminal escapes.
sanitize_provenance() {
  LC_ALL=C tr -d '\000-\010\013-\037\177' \
    | grep -aE '^[a-z0-9_]{1,32}=[[:print:]]{0,300}$' \
    | head -20
}
PROVENANCE="$(docker run --rm --network none --read-only --entrypoint /bin/cat "$TAG" /usr/share/doc/xrpld-image/provenance 2>&1)" \
  || refuse "the image has no /usr/share/doc/xrpld-image/provenance: nothing in it says which package it was built from"
# `|| true`: a file with nothing worth keeping leaves grep at 1, and the
# refusal below is a better answer than set -e ending the run in silence.
PROVENANCE="$(sanitize_provenance <<<"$PROVENANCE" || true)"
[[ -n "$PROVENANCE" ]] \
  || refuse "the image's provenance file holds no readable key=value line"
got_sha="$(sed -n 's/^package_sha256=//p' <<<"$PROVENANCE" | head -1)"
[[ "$got_sha" =~ ^[0-9a-f]{64}$ ]] \
  || refuse "the image's provenance gives its package SHA-256 as '${got_sha}', which is not 64 lowercase hex characters"

echo "   xrpld --version       ${got_bin}"
echo "   dpkg xrpld version    ${got_pkg}"
echo "   default user          ${got_user}"
echo "   version label         ${got_label}"
echo "   signing key label     ${got_fpr}"
echo "   package SHA-256       ${got_sha}"

[[ "$got_bin" == "xrpld version ${VERSION}" ]] || refuse "the binary says '${got_bin}', asked for ${VERSION}"
[[ "$got_pkg" == "$PKG_VERSION" ]]             || refuse "the package database says '${got_pkg}', asked for ${PKG_VERSION}"
[[ "$got_user" == "997:997" ]]                 || refuse "the image's default user is '${got_user}', expected 997:997"
[[ "$got_label" == "$VERSION" ]]               || refuse "the version label is '${got_label}', expected ${VERSION}"
[[ "$got_fpr" == "$KEY_FINGERPRINT" ]]         || refuse "the image says its package was signed by '${got_fpr}', expected ${KEY_FINGERPRINT}"

# A pinned hash is checked against the image whether this run built it or
# found it. An existing tag that verified on its version number alone proved
# only that something calling itself xrpld ${VERSION} is in there.
if [[ -n "$DEB_SHA256" ]]; then
  [[ "$got_sha" == "$DEB_SHA256" ]] \
    || refuse "the image was built from a .deb whose SHA-256 is ${got_sha}, not the ${DEB_SHA256} on file for xrpld ${PKG_VERSION}"
fi

say "provenance"
printf '%s\n' "$PROVENANCE"

say "done"
echo "   image        ${TAG}"
echo "   image ID     ${IMAGE_ID}"
echo "   RepoDigests  $(docker image inspect --format '{{json .RepoDigests}}' "$TAG")"
echo "   (a local build: no registry has seen this image)"
