# A bake file outside the root (`bake -f build/docker-bake.hcl`) is not
# resolved, so it is reported instead of passed.
target "a" { context = "https://example.invalid/team/repo.git" }
