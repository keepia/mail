#!/bin/bash
# Logs its arguments as one line, then runs them as a command.
run() {
	"$@"
}

main() {
	local c="$*"
	echo "running: $c"
	# shellcheck disable=SC2086 # the words are meant to split
	run $c
}

main "$@"
