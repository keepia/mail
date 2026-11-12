#!/bin/sh
# Runs its arguments as a command, a second time if the first fails.
"$@" || "$@"
