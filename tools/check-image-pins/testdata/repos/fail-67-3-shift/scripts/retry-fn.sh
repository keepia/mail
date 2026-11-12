#!/bin/sh
# Runs its arguments after the first as a command, up to $1 times; the
# function takes the count off itself.
retry() {
	n=$1
	shift
	until [ "$n" -eq 0 ]; do
		if "$@"; then
			return 0
		fi
		n=$((n - 1))
	done
	return 1
}

retry "$@"
