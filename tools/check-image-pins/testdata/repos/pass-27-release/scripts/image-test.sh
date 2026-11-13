#!/bin/bash
# A test script: it runs and inspects the image it is given, it does not
# build it.
docker run --rm "$2" --version
docker image inspect "$2"
