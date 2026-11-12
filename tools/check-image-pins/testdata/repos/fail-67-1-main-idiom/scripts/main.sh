#!/bin/sh
# Runs its arguments as a command, up to three times.
main() {
	for i in 1 2 3; do
		"$@" && return 0
		sleep "$i"
	done
	return 1
}

main "$@"
