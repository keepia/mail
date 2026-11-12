# Review A delta 2 (finding 2) and review B delta 2 (D1, V1-V5): make
# variables, includes, $(shell) and computed names around a bake call,
# with m.txt as a bake definition under another name.
include flags.mk
include extra.mk
BAKE := docker buildx bake
FLAGS := --set *.contexts.base=docker-image://debian:trixie-slim
SHF := $(shell printf '%s' '--fi''le=m.txt')
VERB := bake
E :=
export BUILD$(E)X_BAKE_FILE := m.txt

images: BAKE_CA_FLAGS += --file=m.txt
images:
	docker buildx bake --load $(BAKE_CA_FLAGS)

images-a:
	$(BAKE) $(FLAGS) $(EXTRA)

images-v2:
	docker buildx bake --load $(XF)

images-v3:
	docker buildx bake --load $(SHF)

images-v4:
	docker buildx $(VERB) --load --file=m.txt

images-txt:
	docker bu""ildx bake -f m.txt

images-classic:
	docker build -f m.txt .
