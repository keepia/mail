#!/bin/bash
# Prints its arguments, then runs them as a command.
wrap() {
	echo "+ ${*}" >&2
	"${@}"
}

wrap "${@}"
