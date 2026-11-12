# The repository's make images shape: the allowed --set keys only, in a
# variable the bake line uses.
VERSION ?= dev
REGISTRY ?= ghcr.io/keepia
KEEPIA_BUILD_CA ?=
comma := ,
BAKE_CA_FLAGS = $(if $(KEEPIA_BUILD_CA),--allow fs.read=$(abspath $(dir $(KEEPIA_BUILD_CA))) \
	--allow network.host --set '*.secrets=id=ca$(comma)src=$(abspath $(KEEPIA_BUILD_CA))' \
	--set '*.network=host' --set '*.args.HTTPS_PROXY=$(HTTPS_PROXY)')

images:
	VERSION=$(VERSION) REGISTRY=$(REGISTRY) docker buildx bake --load $(BAKE_CA_FLAGS)

clean:
	rm -f bin/x
