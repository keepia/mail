# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Postfix for the edge role: ghcr.io/keepia/mail-postfix (#5 plan,
# "Per-image decisions"). Build context: images/ (docker-bake.hcl), so the
# shared files in images/common are in reach without named contexts.
#
# The master runs as root, which Postfix needs; Compose gives the container
# exactly CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID with
# no-new-privileges (coordinator decision C14). Without SYS_CHROOT no
# service can chroot, so every master.cf service runs with chroot = n; the
# container is the boundary instead. Every RUN that needs no download runs
# with --network=none (#59, as #55 did for olefy and SOGo).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Fixed ids, created before the package would pick its own (Debian picked
# uid 100; coordinator decision C7): postfix 10025, postdrop 10026, and
# keepia-auth 2525, the group of the edge's auth sockets that Postfix and
# the edge Dovecot share (R-AUTH-SOCKET).
RUN --network=none groupadd --system --gid 2525 keepia-auth \
 && groupadd --system --gid 10025 postfix \
 && groupadd --system --gid 10026 postdrop \
 && useradd --system --uid 10025 --gid postfix --groups keepia-auth \
      --home-dir /var/spool/postfix --no-create-home --shell /usr/sbin/nologin postfix

RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install --mount=type=secret,id=ca,required=false,mode=0444 \
    sh /tmp/keepia-apt-install postfix tini inotify-tools

# chroot = n for every service (C14; Debian ships chroot = y, which fails
# without SYS_CHROOT while `postfix status` still says running). Logs go
# to stdout through postlogd. The hostname is a placeholder that the
# Compose configuration replaces. Postfix listens on loopback only unless
# the configuration names addresses: a fail-safe default, because Debian's
# is every interface (R-BIND-PRIVATE; the Compose template's main.cf sets
# the container's own addresses, #26).
RUN --network=none postconf -F '*/*/chroot = n' \
 && postconf -e 'inet_interfaces = loopback-only' \
 && postconf -e 'maillog_file = /dev/stdout' \
 && postconf -e 'myhostname = localhost.invalid' \
 && postconf -e 'mydestination = localhost' \
 && postfix check \
 && test -z "$(postconf -F '*/*/chroot' | grep -v ' = n$')"

COPY --chmod=0755 common/keepia-reload-watch /usr/local/bin/keepia-reload-watch
COPY --chmod=0755 postfix/keepia-health /usr/local/bin/keepia-health

# The reload watcher (C15): a new generation file runs `postfix reload`.
ENV KEEPIA_RELOAD_COMMAND="postfix reload"
EXPOSE 25
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/keepia-reload-watch"]
CMD ["postfix", "start-fg"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --start-interval=1s --retries=2 \
  CMD ["/usr/local/bin/keepia-health"]
