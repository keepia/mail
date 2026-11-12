# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# olefy for the filter role: ghcr.io/keepia/mail-olefy (#5 plan,
# "Per-image decisions"; #44). rspamd sends Office attachments to it, and
# it answers with oletools' olevba analysis. Build context: images/
# (docker-bake.hcl).
#
# Own build: there is no maintained image, and Debian has no
# python3-oletools (#5 plan, M9). olefy.py comes from one pinned commit of
# HeinleinSupport/olefy, which has no release tags (maintainer decision on
# #44: O1). The oletools and pcodedmp wheels come from files.pythonhosted.org;
# their own dependencies are Debian packages (M8). It runs as the fixed uid
# 10055 with no capabilities (coordinator decision C7).

# HeinleinSupport/olefy at commit 9c01c571f11da1a41dda33b75e46d45d303270e4
# (2026-11-05, the newest on master when #44 pinned it), as GitHub's commit
# archive. Its sha256 was taken from CI's own download (BuildKit's digest
# mismatch against a placeholder, the same on amd64 and arm64; #44), and
# check-source ties the archive to that commit's tree.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS source
ADD --checksum=sha256:ad84687d875a1e4a8687224e9c97907e3711a730fc468482c06172a4ea500b2e https://github.com/HeinleinSupport/olefy/archive/9c01c571f11da1a41dda33b75e46d45d303270e4.tar.gz /tmp/olefy.tar.gz
RUN --mount=type=bind,source=common/check-source,target=/tmp/check-source --mount=type=bind,source=olefy/olefy-source.sha256,target=/tmp/olefy-source.sha256 \
    sh /tmp/check-source /tmp/olefy.tar.gz /tmp/olefy-source.sha256 /src/olefy

# The wheels, in their own stage so they never reach a layer of the image.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS wheels
ADD --checksum=sha256:72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96 https://files.pythonhosted.org/packages/ac/ff/05257b7183279b80ecec6333744de23f48f0faeeba46c93e6d13ce835515/oletools-0.60.2-py2.py3-none-any.whl /wheels/
ADD --checksum=sha256:4441f7c0ab4cbda27bd4668db3b14f36261d86e5059ce06c0828602cbe1c4278 https://files.pythonhosted.org/packages/ba/72/b380fb5c89d89c3afafac8cf02a71a45f4f4a4f35531ca949a34683962d1/pcodedmp-1.2.6-py2.py3-none-any.whl /wheels/

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN groupadd --system --gid 10055 olefy \
 && useradd --system --uid 10055 --gid olefy \
      --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin olefy

# oletools' requirements from Debian: olefile, pyparsing, colorclass,
# easygui and msoffcrypto-tool; python3-magic for olefy itself.
RUN --mount=type=bind,source=common/keepia-apt-install,target=/tmp/keepia-apt-install --mount=type=secret,id=ca,required=false,mode=0444 \
    sh /tmp/keepia-apt-install python3 python3-pip python3-magic python3-olefile python3-pyparsing \
      python3-colorclass python3-easygui python3-msoffcrypto-tool tini

# Only the two pinned wheels, from the local files: no index and no
# dependency resolution. pip check fails the build if a requirement of
# theirs is not met by the Debian packages above.
RUN --mount=type=bind,from=wheels,source=/wheels,target=/tmp/wheels \
    python3 -m pip install --no-index --no-deps --no-cache-dir --break-system-packages --root-user-action=ignore \
      /tmp/wheels/oletools-0.60.2-py2.py3-none-any.whl /tmp/wheels/pcodedmp-1.2.6-py2.py3-none-any.whl \
 && python3 -m pip check

COPY --from=source --chmod=0644 /src/olefy/olefy.py /usr/local/bin/olefy.py
COPY --from=source --chmod=0644 /src/olefy/LICENSE /usr/share/doc/olefy/LICENSE
COPY --chmod=0755 olefy/keepia-health /usr/local/bin/keepia-health

# olefy reads its settings from the environment. It listens on loopback
# only by default; Compose sets the container's private address
# (R-BIND-PRIVATE) and KEEPIA_HEALTH_ADDR to match.
ENV OLEFY_BINDADDRESS=127.0.0.1 \
    OLEFY_BINDPORT=10050 \
    OLEFY_TMPDIR=/tmp \
    OLEFY_PYTHON_PATH=/usr/bin/python3 \
    OLEFY_OLEVBA_PATH=/usr/local/bin/olevba \
    OLEFY_LOGLVL=20
USER 10055:10055
EXPOSE 10050
# olefy ends cleanly (status 0, "stopped serving") on SIGINT, which Python
# turns into KeyboardInterrupt; tini forwards it.
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/usr/local/bin/olefy.py"]
# olefy's own ping: "PING" gets "PONG" (keepia-health).
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --start-interval=1s --retries=2 \
  CMD ["/usr/local/bin/keepia-health"]
