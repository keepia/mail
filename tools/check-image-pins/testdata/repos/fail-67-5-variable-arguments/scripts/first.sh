#!/bin/sh
# Runs the command its first argument names; fails without one.
run_one() {
	"$1"
}

run_one "${1?usage: first.sh command}"
