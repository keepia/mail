# #49 point 8 (review A note 5, review B finding 5): Makefile forms that
# reroute `$(GO) run ./tools/check-image-pins -bake-local` itself or hide
# lines from the Makefile rule. The allowlisted line for the go tool (line
# 5) and a literal *.mk include stay allowed.
GO ?= go
SHELL := ./evil-sh
.SHELLFLAGS := -ec
include local.cfg
include tools.mk
export GOFLAGS := -overlay=ov.json
GOWORK = ./go.work
E :=
export PA$(E)TH := $(CURDIR)/evil:$(PATH)

images:
	$(GO) run ./tools/check-image-pins -bake-local

images-go:
	$(eval GO := ./evil/go)
	$(GO) run ./tools/check-image-pins -bake-local
