# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# SOGo for the groupware role: ghcr.io/keepia/mail-sogo (#5 plan,
# "Per-image decisions"; #25). sogod serves webmail, CalDAV and CardDAV
# behind the edge's HTTPS front (architecture section 4a). Build context:
# images/ (docker-bake.hcl).
#
# Own build from Alinto's release tags: SOPE and SOGo come from GitHub's
# tag archives of the same release, each by ADD --checksum. Rejected:
# Debian's sogo package, which follows Debian stable, while #5 chose the
# release tags. The build dependencies are Debian's own Build-Depends of
# sope and sogo (M9). sogod runs as the fixed uid 10060 with no
# capabilities (coordinator decision C7).

# Alinto/sope and Alinto/sogo at the tags SOPE-5.12.13 and SOGo-5.12.13,
# the newest 5.x release when #25 pinned them (2026-11-12), as GitHub's tag
# archives. Each sha256 was computed offline from a clone of the public
# repository (git archive with GitHub's prefix, gzip -n) and matches CI's
# own download (#25). check-source ties each archive to the tag's tree:
# sope-source.sha256 and sogo-source.sha256 list every file with its
# sha256, taken from the clones.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS sope-source
ADD --checksum=sha256:76efdbc86d04842fad0fd447798f6b834703f0bc17e93d9900f8789536696969 https://github.com/Alinto/sope/archive/refs/tags/SOPE-5.12.13.tar.gz /tmp/sope.tar.gz
RUN --mount=type=bind,source=common/check-source,target=/tmp/check-source --mount=type=bind,source=sogo/sope-source.sha256,target=/tmp/sope-source.sha256 \
    sh /tmp/check-source /tmp/sope.tar.gz /tmp/sope-source.sha256 /src/sope

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS sogo-source
ADD --checksum=sha256:0c6b4cf8992634ab14c9a7860c21189cf48db69cba3d82ee76a556a0b083708b https://github.com/Alinto/sogo/archive/refs/tags/SOGo-5.12.13.tar.gz /tmp/sogo.tar.gz
RUN --mount=type=bind,source=common/check-source,target=/tmp/check-source --mount=type=bind,source=sogo/sogo-source.sha256,target=/tmp/sogo-source.sha256 \
    sh /tmp/check-source /tmp/sogo.tar.gz /tmp/sogo-source.sha256 /src/sogo

# The build: SOPE is installed into this stage's system tree, so that SOGo
# builds against it, and both are installed into /out for the image.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS build
# Debian's Build-Depends of sope 5.12.1 and sogo 5.12.1 in trixie (M9),
# except: default-libmysqlclient-dev (Keepia's database is Postgres, so the
# MySQL adaptor is not built), libsbjson-dev and libsope-dev (built here
# from the SOPE tag), debhelper (no Debian package is made).
# python-is-python3: SOGo's gen-saml2-exceptions.py starts with
# #!/usr/bin/python.
RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install --mount=type=secret,id=ca,required=false,mode=0444 \
    sh /tmp/keepia-apt-install make gobjc gnustep-make libgnustep-base-dev pkgconf \
      libxml2-dev libldap-dev libpq-dev libssl-dev zlib1g-dev \
      libcurl4-openssl-dev liblasso3-dev libmemcached-dev liboath-dev libsodium-dev \
      libwbxml2-dev libytnef-dev libzip-dev python3 python-is-python3
COPY --from=sope-source /src/sope /src/sope
COPY --from=sogo-source /src/sogo /src/sogo
# GNUstep.sh reads unset variables, so the shell runs without -u. The
# configure flags follow Alinto's packaging/debian/rules for trixie:
# SAML2 and MFA on, libsodium found by configure; ActiveSync is built as
# its own step there too.
WORKDIR /src/sope
RUN . /usr/share/GNUstep/Makefiles/GNUstep.sh \
 && ./configure --with-gnustep --disable-debug --disable-strip --disable-mysql \
 && make -j"$(nproc)" \
 && make install GNUSTEP_INSTALLATION_DOMAIN=SYSTEM \
 && make install GNUSTEP_INSTALLATION_DOMAIN=SYSTEM DESTDIR=/out
WORKDIR /src/sogo
RUN . /usr/share/GNUstep/Makefiles/GNUstep.sh \
 && ./configure --disable-debug --disable-strip --enable-saml2 --enable-mfa \
 && make -j"$(nproc)" \
 && make install GNUSTEP_INSTALLATION_DOMAIN=SYSTEM DESTDIR=/out \
 && make -C ActiveSync -j"$(nproc)" \
 && make -C ActiveSync install GNUSTEP_INSTALLATION_DOMAIN=SYSTEM DESTDIR=/out
# Debian's gnustep-multiarch makes some directories under
# /usr/lib/<triplet>/GNUstep symlinks into /usr/share/GNUstep (Libraries,
# for SOPE's and SOGo's resources); an install with DESTDIR creates them as
# directories. Their content moves to the symlinks' targets, so the COPY
# below merges into Debian's layout instead of failing on a symlink.
# Then only what sogod needs at run time stays: no headers, no
# gnustep-make files and no debug symbols (every ELF file is stripped).
# The licences of both projects go with the binaries.
RUN cd /out/usr/lib/*/GNUstep \
 && for d in *; do \
      sys=$(dirname "$(pwd)" | sed 's|^/out||')/GNUstep/$d; \
      if [ -L "$sys" ]; then \
        target=$(readlink -f "$sys"); \
        mkdir -p "/out$target"; \
        cp -a "$d"/. "/out$target"/; \
        rm -rf "$d"; \
        echo "moved $d to $target"; \
      fi; \
    done \
 && rm -rf /out/usr/include /out/usr/share/GNUstep/Makefiles \
 && find /out -type f -exec sh -c 'for f; do if [ "$(head -c 4 "$f" | tail -c 3)" = ELF ]; then strip --strip-unneeded "$f"; fi; done' sh {} + \
 && install -D -m 0644 /src/sope/COPYRIGHT /out/usr/share/doc/sope/COPYRIGHT \
 && install -D -m 0644 /src/sogo/COPYING.GPL /out/usr/share/doc/sogo/COPYING.GPL \
 && install -D -m 0644 /src/sogo/COPYING.LGPL /out/usr/share/doc/sogo/COPYING.LGPL

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# The home holds GNUstep's user defaults; the spool is SOGo's mail spool
# (the named volume sogo-spool in part 3).
RUN groupadd --system --gid 10060 sogo \
 && useradd --system --uid 10060 --gid sogo \
      --home-dir /var/lib/sogo --no-create-home --shell /usr/sbin/nologin sogo \
 && install -d -o sogo -g sogo -m 0750 /var/lib/sogo /var/spool/sogo

# The run-time libraries of SOPE and SOGo (their ldd, mapped to Debian
# packages in #25), tzdata for calendar time zones, and tini.
RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install --mount=type=secret,id=ca,required=false,mode=0444 \
    sh /tmp/keepia-apt-install libgnustep-base1.31 libobjc4 libxml2 libldap2 libpq5 libssl3t64 zlib1g \
      libcurl4t64 liblasso3t64 libmemcached11t64 liboath0t64 libsodium23 libwbxml2-1 libytnef0 libzip5 \
      tzdata tini

COPY --from=build /out/ /
# Fails the build if any ELF file of SOPE or SOGo (the build's /out, now
# at /) misses a shared library at run time.
RUN --mount=type=bind,from=build,source=/out,target=/tmp/out \
    ldconfig \
 && cd /tmp/out \
 && missing=$(find . -type f -exec sh -c 'for f; do if [ "$(head -c 4 "$f" | tail -c 3)" = ELF ]; then ldd "/${f#./}" | sed "s|^|/${f#./}: |"; fi; done' sh {} + | grep 'not found' || true) \
 && if [ -n "$missing" ]; then echo "missing shared libraries:" >&2; echo "$missing" >&2; exit 1; fi \
 && echo "every ELF file of SOPE and SOGo finds its shared libraries"

COPY --chmod=0755 sogo/keepia-health /usr/local/bin/keepia-health
COPY --chmod=0755 sogo/keepia-sogod /usr/local/bin/keepia-sogod

ENV HOME=/var/lib/sogo
USER 10060:10060
WORKDIR /var/lib/sogo
EXPOSE 20000
# sogod listens on loopback by default; Compose sets the container's
# private address (R-BIND-PRIVATE) as WOPort and KEEPIA_HEALTH_ADDR. It
# logs to stdout and stays in the foreground under tini and keepia-sogod,
# which bounds the stop (SIGTERM to the master, SIGKILL to workers still
# running after KEEPIA_SOGOD_GRACE seconds).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/keepia-sogod", "/usr/sbin/sogod", "-WONoDetach", "YES", "-WOPort", "127.0.0.1:20000", "-WOLogFile", "-", "-WOPidFile", "/tmp/sogod.pid"]
# GET /SOGo/ needs an HTTP status line from sogod (keepia-health).
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --start-interval=1s --retries=2 \
  CMD ["/usr/local/bin/keepia-health"]
