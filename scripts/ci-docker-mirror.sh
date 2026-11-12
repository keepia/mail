#!/bin/sh
# CI only: makes the runner's dockerd pull Docker Hub images through
# mirror.gcr.io, Google's public Docker Hub cache, so a Docker Hub error (a
# 500) or its anonymous rate limit (429) does not fail the job. dockerd tries
# the mirror first and falls back to Docker Hub on any mirror error, including
# a tag the mirror has not cached yet (404). Pulled images keep their docker.io
# names, so tags and digest pins resolve as before. This covers pulls by
# dockerd itself and by its built-in BuildKit (docker compose --build), and the
# moby/buildkit image of a docker-container builder; such a builder needs the
# mirror in its own buildkitd config as well (see ci.yml).
#
# It merges the mirror into /etc/docker/daemon.json, keeping the runner's
# other settings, and restarts dockerd. Run it before anything uses Docker:
# the restart stops running containers.
#
# GitHub's runners are logged in to Docker Hub (`docker info` shows a user).
# dockerd sends those credentials to the mirror as well, and mirror.gcr.io
# refuses them ("unauthorized: authentication failed"), so every pull would
# skip the mirror. In GitHub Actions the script therefore points DOCKER_CONFIG
# at an empty client config for the job's later steps: pulls are anonymous,
# through the mirror first and from Docker Hub as the fallback.
#
# Usage: scripts/ci-docker-mirror.sh   (needs sudo, jq and systemd)
set -eu

mirror=https://mirror.gcr.io
conf=/etc/docker/daemon.json

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

if sudo test -s "$conf"; then
	sudo cat "$conf"
else
	echo '{}'
fi | jq --arg m "$mirror" '.["registry-mirrors"] = [$m] + ((.["registry-mirrors"] // []) - [$m])' >"$tmp"

sudo install -m 0644 "$tmp" "$conf"
echo "$conf:"
cat "$tmp"

# A restart rather than a reload (SIGHUP): it makes sure the built-in BuildKit
# uses the mirror too. Nothing runs on Docker yet at this point.
sudo systemctl restart docker

if [ -n "${GITHUB_ENV:-}" ]; then
	DOCKER_CONFIG="${RUNNER_TEMP:?}/docker-config-anonymous"
	mkdir -p "$DOCKER_CONFIG"
	echo '{}' >"$DOCKER_CONFIG/config.json"
	export DOCKER_CONFIG
	echo "DOCKER_CONFIG=$DOCKER_CONFIG" >>"$GITHUB_ENV"
	echo "Docker client config for the later steps, without credentials: $DOCKER_CONFIG"
fi

mirrors=$(docker info --format '{{json .RegistryConfig.Mirrors}}')
echo "registry mirrors: $mirrors"
case $mirrors in
*mirror.gcr.io*) ;;
*)
	echo "dockerd does not list $mirror as a registry mirror" >&2
	exit 1
	;;
esac
