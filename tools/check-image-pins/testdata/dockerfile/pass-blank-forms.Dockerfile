# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# #88: BuildKit skips the empty line inside this RUN and joins the next
# line to it, so that FROM is an argument of echo, not a stage. The form
# feed, no-break space and carriage return forms are invisible in a file,
# so TestDockerfileBlankForms holds them as Go string escapes.
RUN --network=none echo one \

    FROM alpine:latest
# A lone backslash as the last line continues into the end of the file:
# no instruction.
\
