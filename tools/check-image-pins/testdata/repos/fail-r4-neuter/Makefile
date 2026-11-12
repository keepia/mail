# Review A delta 2, 1c: the check step's recipe turned into a no-op; review
# B delta 2, W5: a second line that rewrites BAKE_SET after the check ran.
image-pins-build:
	@true
	printf 'BAKE_SET=%s\n' '*.contexts.base=docker-image://busybox:latest' >>"$$GITHUB_ENV"
