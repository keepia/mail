#!/bin/sh
# A script that runs bake itself, outside make images and bake-action.
docker buildx bake -f ci-alt.hcl --load
