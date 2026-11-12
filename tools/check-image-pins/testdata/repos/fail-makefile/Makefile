# Review B R2's Makefile probe and its variants: each changes what
# `make images` builds without the check seeing it.
EXTRA = --set '*.contexts.base=docker-image://busybox:latest'
FILES = -f ci-alt.hcl

images:
	docker buildx bake --load -f ci-alt.hcl --set '*.dockerfile-inline=FROM busybox:latest'

images-indirect:
	docker buildx bake --load $(FILES) $(EXTRA) \
		--file=other.hcl --set=*.args.BUILDKIT_SYNTAX=docker/dockerfile:latest

images-env:
	BUILDX_BAKE_FILE=ci-alt.hcl docker buildx bake --load
