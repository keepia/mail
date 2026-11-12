# A Dockerfile outside the context or the repository cannot be checked;
# so can a missing one, which the build would fail on anyway.
group "default" {
  targets = ["a", "b", "c"]
}

target "a" {
  dockerfile = "../elsewhere/Dockerfile"
}

target "b" {
  dockerfile = "/srv/Dockerfile"
}

target "c" {
  dockerfile = "missing.Dockerfile"
}
