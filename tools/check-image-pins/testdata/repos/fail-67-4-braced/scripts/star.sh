#!/bin/sh
# Runs its first argument as root, or as the user when sudo is missing.
SUDO=sudo
command -v sudo >/dev/null || SUDO=
as_root() {
	$SUDO $1
}

as_root "$*"
