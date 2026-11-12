#!/bin/sh
# Forwards its arguments to the retry wrapper next to it.
echo "running: $*"
sh "$(dirname "$0")/retry.sh" "$@"
