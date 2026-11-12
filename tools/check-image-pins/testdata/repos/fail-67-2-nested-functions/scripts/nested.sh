#!/bin/sh
# Runs its arguments as a command, a second time if the first fails,
# through a function defined inside main.
main() {
	attempt() {
		echo "attempt: $*"
		"$@"
	}
	attempt "$@" || attempt "$@"
}

main "$@"
