# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# BuildKit expands ARG and ENV values in ADD sources: each line downloads
# without a checksum, or from a URL the check cannot see.
ARG SRC=https://example.invalid/payload.tar.gz
ADD $SRC /opt/a/
ADD ${SRC} /opt/b/
ADD ["$SRC", "/opt/c/"]
ADD --checksum=sha256:72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96 ${SRC} /opt/d/
ENV DL=https://example.invalid/other.tar.gz
ADD https://example.invalid/${DL}.whl /opt/e/
# want-lines: 6 7 8 9 11
