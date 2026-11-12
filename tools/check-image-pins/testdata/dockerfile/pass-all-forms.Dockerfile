# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# escape=\
# A pinned build stage on the build platform, a pinned final stage, and
# every form the check accepts.
ARG VERSION=dev
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS Build
RUN --mount=type=cache,target=/root/.cache \
    # a comment inside a continuation is dropped, as BuildKit does
    go version

FROM --platform=${TARGETPLATFORM} gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS final
COPY --from=build /out/a /a
COPY --from=0 /out/b /b
COPY --from=localhost:5000/tools/x:1.0@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 /x /x
RUN --mount=type=bind,from=build,source=/out,target=/mnt true
ADD --checksum=sha256:72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96 https://files.pythonhosted.org/packages/x/oletools.whl /tmp/
ADD --checksum=sha256:72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96 ["https://files.pythonhosted.org/packages/x/a.whl", "/tmp/"]
ADD local.tar /opt/
COPY --chmod=0644 local.conf \
    other.conf /etc/

FROM scratch
COPY --from=final /a /a
