# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# BuildKit reads --mount as one CSV record, so quotes around a field or the
# whole value are removed: each of these mounts busybox:latest.
RUN --mount=type=bind,"from=busybox:latest",target=/mnt true
RUN --mount="type=bind,from=busybox:latest,target=/mnt" true
RUN --mount=type=bind,"FROM=busybox:latest" true
# Not valid CSV: reported instead of read.
RUN --mount=type=bind,"from=busybox:latest,target=/mnt true
# want-lines: 5 6 7 9
