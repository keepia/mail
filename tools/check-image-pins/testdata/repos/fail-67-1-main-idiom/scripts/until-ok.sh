#!/bin/bash
# Runs its arguments as a command until it succeeds, at most five times.
function until_ok {
	local n=0
	while ! "$@"; do
		n=$((n + 1))
		[ "$n" -lt 5 ] || return 1
	done
}

until_ok "$@"
