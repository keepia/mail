#!/bin/sh
# Logs its arguments as one line, then runs them as a command.
main() {
	"$@"
}

cmd="$*"
echo "running: $cmd"
# shellcheck disable=SC2086 # the words are meant to split
main $cmd
