.DEFAULT_GOAL := publish

images:
	go run ./tools/check-image-pins -bake-local

publish:
	docker push ghcr.io/keepia/mail-root:dev
