#!/bin/sh
# Rewrites the later steps' Go and tool lookup. The DOCKER_CONFIG line is
# allowed only in scripts/ci-docker-mirror.sh.
echo "GOWORK=$PWD/tools/go.work" >>"$GITHUB_ENV"
echo "$PWD/tools/bin" >>"$GITHUB_PATH"
echo "DOCKER_CONFIG=$DOCKER_CONFIG" >>"$GITHUB_ENV"
