# #46 point 6 (review B delta 3, N3): the variables local mode passes to
# docker, set from the Makefile. make passes its own value of PATH and
# HOME to a recipe even without export. Reading them is fine.
export PATH := $(CURDIR)/evil:$(PATH)
HOME = $(CURDIR)/home
images: DOCKER_CONFIG := $(CURDIR)/dc
export DOCKER_HOST
DOCKER_CONTEXT ?= other
images-env:
	env PATH=$(CURDIR)/evil go run ./tools/check-image-pins -bake-local
GOPATH := $(CURDIR)/go
SECRETS_PATH := x

images:
	go run ./tools/check-image-pins -bake-local -version "$(VERSION)"

show:
	@echo "$(PATH) $(HOME) $$PATH"
