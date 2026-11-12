#!/bin/sh
# main → retry → run: only run runs its arguments as a command.
run() {
	exec "$@"
}

retry() {
	(run "${@}") || (run "${@}")
}

main() {
	retry "$@"
}

main "$@"
