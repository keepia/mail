#!/bin/sh
# Runs its arguments after the first as a command, up to $1 times.
set -eu
n=$1
shift

retry() {
	i=0
	while [ "$i" -lt "$n" ]; do
		"$@" && return 0
		i=$((i + 1))
	done
	return 1
}

retry "$@"
