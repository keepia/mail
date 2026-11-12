# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Unbound for the edge, filter and control roles:
# ghcr.io/keepia/mail-unbound (#5 plan, "Per-image decisions"). Build
# context: images/ (docker-bake.hcl).
#
# It runs as the fixed uid 10053 with no capabilities: Docker sets
# net.ipv4.ip_unprivileged_port_start to 0 in the container, so port 53
# needs none (#5 plan, M4).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# The fixed id before the package would pick its own (coordinator
# decision C7).
RUN groupadd --system --gid 10053 unbound \
 && useradd --system --uid 10053 --gid unbound \
      --home-dir /var/lib/unbound --no-create-home --shell /usr/sbin/nologin unbound

RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install --mount=type=secret,id=ca,required=false,mode=0444 \
    sh /tmp/keepia-apt-install unbound dns-root-data tini inotify-tools

COPY --chmod=0644 unbound/unbound.conf /etc/unbound/unbound.conf
COPY --chmod=0755 common/keepia-reload-watch /usr/local/bin/keepia-reload-watch

# The directory of the control socket belongs to the service user.
RUN install -d -o unbound -g unbound -m 0750 /run/unbound \
 && unbound-checkconf /etc/unbound/unbound.conf

# The reload watcher (C15): a new generation file runs
# `unbound-control reload`.
ENV KEEPIA_RELOAD_COMMAND="unbound-control reload"
USER 10053:10053
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/keepia-reload-watch"]
CMD ["unbound", "-d", "-p", "-c", "/etc/unbound/unbound.conf"]
# A protocol reply over the control socket: `unbound-control status`
# times out when Unbound is stopped (#5 plan, M15).
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --start-interval=1s --retries=2 \
  CMD ["unbound-control", "status"]
