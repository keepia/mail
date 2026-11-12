# The repository's make images shape: the tool is the only build path.
VERSION ?= dev
REGISTRY ?= ghcr.io/keepia
KEEPIA_BUILD_CA ?=
LOCAL_BUILD_OPTIONS = $(if $(KEEPIA_BUILD_CA),-ca "$(KEEPIA_BUILD_CA)" -host-network -https-proxy "$(HTTPS_PROXY)")

images:
	go run ./tools/check-image-pins -bake-local -version "$(VERSION)" -registry "$(REGISTRY)" $(LOCAL_BUILD_OPTIONS)

image-test:
	bash scripts/image-test.sh $(IMAGE)

clean:
	rm -f bin/x
