# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ADD --checksum=sha256:72ad8bd748fd0c4e7b5b4733af770d11543ebb2bf2697455f99f975fcd50cc96 https://example.org/a.whl https://example.org/b.whl /tmp/
# want-lines: 3
