#!/bin/bash
# A test script the Makefile runs: it runs and inspects images, it does not
# build them.
docker run --rm "$1" --version
docker image inspect "$1"
