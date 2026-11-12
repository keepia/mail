#!/bin/bash
# options-main.sh [-n N] command...: runs the command up to N times.
set -euo pipefail

retry() {
	local i=0
	while [ "$i" -lt "$n" ]; do
		"$@" && return 0
		i=$((i + 1))
	done
	return 1
}

main() {
	n=3
	while [ $# -gt 0 ]; do
		case $1 in
		-n)
			n=$2
			shift 2
			;;
		*) break ;;
		esac
	done
	local args=("$@")
	retry "${args[@]}"
}

main "$@"
