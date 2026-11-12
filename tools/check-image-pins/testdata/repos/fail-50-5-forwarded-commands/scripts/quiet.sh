#!/bin/bash
# "$@" inside a function runs the function's arguments, words of this
# text.
quietly() { "$@" >/dev/null; }
quietly docker image ls
