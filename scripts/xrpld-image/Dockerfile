# xrpld in a container, built from the XRPL Foundation's signed DEB package.
#
# This directory holds two files, this one and entrypoint.sh. Build from it:
#
#   docker build \
#     --build-arg XRPLD_VERSION=3.4.1 \
#     --build-arg XRPLD_PKG_VERSION=3.4.1-1 \
#     --build-arg XRPLD_DEB_SHA256=cae8ce3b9bc9451b19975c890714ba789d2004987cdfff9cbd55522c612c6f26 \
#     --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     --tag localhost/xrpld:3.4.1 .
#
# The SHA-256 is the one the release announcement publishes for that .deb
# (https://xrpl.org/blog/2026/xrpld-3.4.1). The localhost/ prefix means the
# name can never be resolved against Docker Hub: a pull of it fails instead of
# fetching someone else's image.
#
# Why this exists: xrpld 3.4.x is published as signed DEB and RPM packages at
# packages.xrplf.org, and the install guide has no Docker section. This file
# follows that guide's APT steps exactly, inside an image:
#   https://github.com/XRPLF/rippled/blob/4a4fded2eba11427c48ce3f24d9c1aea5e7a9d17/docs/install.md#L34-L83
#
# It is written as a drop-in replacement for xrpllabsofficial/xrpld, which
# stops at 3.3.0. "The previous image" below means that one.
#
# What it holds to:
#
#   - The base image is pinned by digest. ubuntu:24.04 because the xrpl.org
#     Ubuntu install page names 22.04 and 24.04 on x86_64 as the most
#     supported and tested, and because the previous image is 24.04 too.
#     A digest does not move, so base-layer patches arrive when the digest in
#     this line is bumped on purpose, never behind anyone's back.
#   - The signing key is fetched and its fingerprint checked against the
#     published value before apt is allowed to trust it. The key file must
#     hold exactly one primary key, no subkeys, with that fingerprint: apt's
#     signed-by trusts every key in the file, so the file's whole shape is
#     checked, not one line of it. Any mismatch fails the build.
#   - The repository line is the install guide's, character for character.
#   - apt's signature checking is left on. Nothing here passes trusted=yes,
#     --allow-unauthenticated or an insecure-repository option.
#   - The package is installed at one exact version (xrpld=<version>-<rev>),
#     and, when a SHA-256 is passed, the downloaded .deb must match it. The
#     release announcement publishes that hash.
#   - The runtime account is xrpld, uid 997 gid 997, the account and the
#     numbers the previous image ships. What differs is the default: that
#     image sets no USER, so it runs as root unless a deployment says
#     otherwise, and this one defaults to 997:997. A `--user` or compose
#     `user:` still wins, as it did before. A deployment that was relying on
#     root to let the entrypoint write into /etc/xrpld now hears about it at
#     the first start, because the entrypoint stops instead of falling back
#     to the package's default config.
#   - Same entrypoint path and argument contract as the previous image (see
#     entrypoint.sh for why it is kept), and no HEALTHCHECK, because that
#     image has none and deployments carry their own.
#   - Nothing goes in but xrpld, its package's own files, ca-certificates and
#     the base image. Labels and the provenance file record only facts about
#     the package and the base.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

# xrpld's upstream version (3.4.1) and the package version apt knows
# (3.4.1-1). Both are required.
ARG XRPLD_VERSION=
ARG XRPLD_PKG_VERSION=
# SHA-256 of the .deb as the release announcement publishes it. Optional here,
# because the package is already verified through the signed repository
# metadata; when set, it is a second, independent check on the same bytes.
ARG XRPLD_DEB_SHA256=
# RFC 3339 UTC, passed in so the label is the build's own time.
ARG BUILD_DATE=

RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive; \
    fail() { echo "BUILD REFUSED: $*" >&2; exit 1; }; \
    case "$XRPLD_VERSION" in ''|*[!0-9.]*) fail "XRPLD_VERSION must be digits and dots, got '$XRPLD_VERSION'";; esac; \
    case "$XRPLD_PKG_VERSION" in "${XRPLD_VERSION}"-[0-9]*) ;; *) fail "XRPLD_PKG_VERSION '$XRPLD_PKG_VERSION' is not a revision of $XRPLD_VERSION";; esac; \
    case "$XRPLD_PKG_VERSION" in *[!0-9.-]*) fail "XRPLD_PKG_VERSION must be digits, dots and one dash";; esac; \
    case "$XRPLD_DEB_SHA256" in '') ;; *[!0-9a-f]*) fail "XRPLD_DEB_SHA256 must be lowercase hex";; *) [ "${#XRPLD_DEB_SHA256}" -eq 64 ] || fail "XRPLD_DEB_SHA256 must be 64 hex characters";; esac; \
    [ -n "$BUILD_DATE" ] || fail "BUILD_DATE is required"; \
    \
    # Tools for fetching and reading the key. Removed again below.
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    \
    # Install guide step 2: the XRPL Foundation package-signing key.
    install -d -m 0755 /etc/apt/keyrings; \
    curl -fsS --proto '=https' --tlsv1.2 https://packages.xrplf.org/xrplf.asc -o /etc/apt/keyrings/xrplf.asc; \
    \
    # Install guide step 3: check the fingerprint, and fail if it differs.
    # Published in the install guide (L50-L64) and on xrpl.org's Ubuntu page.
    expected_fpr=B655416741221F780FBCFBC9AA84D41A11D29FA9; \
    GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
    gpg --batch --show-keys --with-colons /etc/apt/keyrings/xrplf.asc > "$GNUPGHOME/keyinfo"; \
    pubs=$(grep -c '^pub:' "$GNUPGHOME/keyinfo" || true); \
    subs=$(grep -c '^sub:' "$GNUPGHOME/keyinfo" || true); \
    fpr=$(awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; exit }' "$GNUPGHOME/keyinfo"); \
    [ "$pubs" = 1 ] || fail "the key file holds $pubs primary keys, expected exactly 1"; \
    [ "$subs" = 0 ] || fail "the key file holds $subs subkeys, expected none"; \
    [ "$fpr" = "$expected_fpr" ] || fail "key fingerprint is '$fpr', expected $expected_fpr"; \
    echo "signing key fingerprint verified: $fpr"; \
    rm -rf "$GNUPGHOME"; unset GNUPGHOME; \
    \
    # Install guide step 4: the stable channel, exactly as written there.
    echo "deb [signed-by=/etc/apt/keyrings/xrplf.asc] https://packages.xrplf.org/repository/deb-stable any main" > /etc/apt/sources.list.d/xrplf.list; \
    \
    # The runtime account, before anything can allocate 997. The package's
    # sysusers entry ("u xrpld -") then finds it and leaves it alone.
    groupadd --system --gid 997 xrpld; \
    useradd --system --uid 997 --gid 997 --home-dir /var/lib/xrpld --no-create-home \
            --shell /sbin/nologin --comment "XRP Ledger daemon" xrpld; \
    install -d -o xrpld -g xrpld -m 0750 /var/lib/xrpld /var/log/xrpld; \
    \
    # Install guide steps 5 and 6, at one exact version. The package depends
    # on "systemd | systemd-standalone-sysusers | systemd-sysusers"; installed
    # first, the standalone one satisfies it without pulling in systemd.
    apt-get update; \
    apt-get install -y --no-install-recommends systemd-standalone-sysusers; \
    apt-get install -y --no-install-recommends --download-only "xrpld=${XRPLD_PKG_VERSION}"; \
    deb="/var/cache/apt/archives/xrpld_${XRPLD_PKG_VERSION}_amd64.deb"; \
    [ -f "$deb" ] || fail "apt did not leave $deb in its cache"; \
    deb_sha=$(sha256sum "$deb" | cut -d' ' -f1); \
    if [ -n "$XRPLD_DEB_SHA256" ]; then \
      [ "$deb_sha" = "$XRPLD_DEB_SHA256" ] || fail "the .deb's SHA-256 is $deb_sha, the announcement says $XRPLD_DEB_SHA256"; \
      echo "package SHA-256 matches the announcement: $deb_sha"; \
    fi; \
    apt-get install -y --no-install-recommends "xrpld=${XRPLD_PKG_VERSION}"; \
    \
    # What was installed is what was asked for, by the package database and
    # by the binary itself.
    got_pkg=$(dpkg-query -W -f='${Version}' xrpld); \
    [ "$got_pkg" = "$XRPLD_PKG_VERSION" ] || fail "dpkg reports xrpld $got_pkg, asked for $XRPLD_PKG_VERSION"; \
    got_bin=$(/usr/bin/xrpld --version | head -1); \
    [ "$got_bin" = "xrpld version ${XRPLD_VERSION}" ] || fail "the binary reports '$got_bin', asked for $XRPLD_VERSION"; \
    [ "$(id -u xrpld):$(id -g xrpld)" = "997:997" ] || fail "the xrpld account is $(id -u xrpld):$(id -g xrpld), expected 997:997"; \
    \
    # A record of what this image is, readable with `docker run --rm
    # --entrypoint cat <image> /usr/share/doc/xrpld-image/provenance`.
    install -d -m 0755 /usr/share/doc/xrpld-image; \
    { echo "xrpld_version=${XRPLD_VERSION}"; \
      echo "package=xrpld=${got_pkg}"; \
      echo "package_sha256=${deb_sha}"; \
      echo "apt_source=deb [signed-by=/etc/apt/keyrings/xrplf.asc] https://packages.xrplf.org/repository/deb-stable any main"; \
      echo "signing_key_fingerprint=${expected_fpr}"; \
      echo "binary=$(/usr/bin/xrpld --version | tr '\n' ' ')"; \
      echo "base=ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"; \
      echo "build_date=${BUILD_DATE}"; \
    } > /usr/share/doc/xrpld-image/provenance; \
    \
    # Nothing the node needs at runtime is removed: ca-certificates stays,
    # because xrpld fetches its validator list over HTTPS. curl and gnupg
    # were only for the key.
    apt-get purge -y --auto-remove curl gnupg; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# Only facts about xrpld, its package and the base image. Their position buys
# no cache: BUILD_DATE is read inside the RUN above, so every build with a new
# build date rebuilds that layer whatever order these come in.
LABEL org.opencontainers.image.title="xrpld" \
      org.opencontainers.image.version="${XRPLD_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://packages.xrplf.org/repository/deb-stable" \
      org.opencontainers.image.documentation="https://github.com/XRPLF/rippled/blob/release/3.4.x/docs/install.md" \
      org.opencontainers.image.licenses="ISC" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:24.04" \
      org.opencontainers.image.base.digest="sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3" \
      xrpld.package.version="${XRPLD_PKG_VERSION}" \
      xrpld.package.sha256="${XRPLD_DEB_SHA256}" \
      xrpld.package.signing-key-fingerprint="B655416741221F780FBCFBC9AA84D41A11D29FA9"

# Documentation only, EXPOSE publishes nothing: the package's default config
# binds peer 2459, admin RPC 5005 and admin WebSocket 6006, and 51235 is the
# conventional public peer port a deployment maps onto 2459.
EXPOSE 2459 5005 6006 51235

USER 997:997
ENTRYPOINT ["/entrypoint.sh"]
