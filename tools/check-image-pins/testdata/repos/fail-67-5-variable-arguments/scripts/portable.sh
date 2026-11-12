#!/bin/sh
# Runs its arguments as a command, up to three times. ${1+"$@"} is the
# portable spelling of "$@" for old shells.
main() {
	for i in 1 2 3; do
		"$@" && return 0
	done
	return 1
}

main ${1+"$@"}
