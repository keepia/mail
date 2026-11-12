#!/bin/bash
# The forms of the repository's image test script: a sudo prefix in a
# variable, and a helper that runs the command its caller passes.
sudo=
[ "$(id -u)" = 0 ] || sudo=sudo
quietly() { "$@" >/dev/null; }
$sudo true
quietly docker image ls
