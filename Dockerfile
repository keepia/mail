# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Keepia: ghcr.io/keepia/mail, one Go image with modes (architecture
# section 1): control's `serve` and the `km` commands today; the agent,
# keepia-edge and the gate later.

# The Go stage runs on the build platform and cross-compiles (CGO off), so
# both platforms build without emulation. Keep the golang tag equal to the
# `toolchain` line in go.mod: the image sets GOTOOLCHAIN=local, and
# scripts/check-go-toolchain.sh fails the build on a mismatch.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
COPY scripts/check-go-toolchain.sh ./scripts/
# The optional "ca" secret is a CA bundle for local builds behind a
# TLS-inspecting proxy (make images with KEEPIA_BUILD_CA); CI passes none.
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi \
 && sh scripts/check-go-toolchain.sh go.mod \
 && go mod download \
 && go mod verify
COPY cmd ./cmd
COPY internal ./internal
# The build reads only the modules downloaded above: no network (#66).
# /out/keepia/kek is the empty mount point of the volume keepia-kek.
RUN --network=none CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/keepia-mail ./cmd/keepia-mail \
 && mkdir -p /out/keepia/kek

# distroless static, nonroot (65532): no shell, no package manager.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/keepia-mail /usr/local/bin/keepia-mail
# The key-encryption key's directory (#96, CD1): owned by 65532 with mode
# 0700. Docker copies a mount point's owner and mode into a new, empty
# named volume, so keepia-kek starts that way and serve can create the KEK
# there at its first start.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/keepia /var/lib/keepia
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/keepia-mail"]
CMD ["serve"]
# `keepia-mail healthcheck` exits 0 only when /healthz answers 200, which
# serve gives after `SELECT 1` (#6); the image has no curl.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --start-interval=1s --retries=2 \
  CMD ["/usr/local/bin/keepia-mail", "healthcheck"]
