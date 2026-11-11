# syntax=docker/dockerfile:1
# Postfix for the #3 prototype: delivers example.test over LMTP to the edge.
# Also carries the check clients (curl, netcat-openbsd, find, cat).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# The optional "ca" secret is a CA bundle for builds behind a TLS-inspecting
# proxy (passed by the sandbox build command; see README). apt then uses
# https. Mode 0444: apt fetches as the unprivileged _apt user.
RUN --mount=type=secret,id=ca,required=false,mode=0444 \
    set -eu; \
    if [ -s /run/secrets/ca ]; then \
      echo 'Acquire::https::CAInfo "/run/secrets/ca";' > /etc/apt/apt.conf.d/99ca; \
      sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix curl netcat-openbsd; \
    rm -f /etc/apt/apt.conf.d/99ca; \
    rm -rf /var/lib/apt/lists/*; \
    postconf -F '*/*/chroot = n'

COPY main.cf /etc/postfix/main.cf
COPY vmailbox /etc/postfix/vmailbox

CMD ["postfix", "start-fg"]
