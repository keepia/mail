# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN --mount=type=bind,from=alpine:3.22,target=/mnt ls /mnt
RUN --mount=type=bind,FROM="busybox",target=/mnt ls /mnt
# want-lines: 3 4
