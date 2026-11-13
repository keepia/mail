#!/bin/sh
# The repository's mirror script writes one variable to GITHUB_ENV, the
# anonymous Docker client config; the check allows exactly these lines in
# this file.
if [ -n "${GITHUB_ENV:-}" ]; then
	DOCKER_CONFIG="${RUNNER_TEMP:?}/docker-config-anonymous"
	echo "DOCKER_CONFIG=$DOCKER_CONFIG" >>"$GITHUB_ENV"
fi
