#!/bin/sh
# Functions that take the script's arguments as arguments, not as a
# command.
set -eu

say() {
	echo "$1"
}

show() {
	ls --color=never "$1"
}

stamp() {
	date -u
}

list() {
	for a in "$@"; do
		printf '%s\n' "$a"
	done
}

say "$@"
show "$1"
stamp "${@}"
list "$@"
