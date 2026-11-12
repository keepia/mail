#!/bin/sh
# Runs a script next to itself.
set -eu
sh "$(dirname "$0")/save.sh"
