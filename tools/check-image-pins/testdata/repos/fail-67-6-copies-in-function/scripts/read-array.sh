#!/bin/bash
# Splits its arguments into words again, then runs them, a second time if
# the first fails.
retry() {
	"$@" || "$@"
}

main() {
	local a
	read -r -a a <<< "$*"
	retry "${a[@]}"
}

main "$@"
