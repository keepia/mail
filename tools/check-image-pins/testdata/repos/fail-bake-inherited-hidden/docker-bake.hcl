# A hidden target (not in `bake --list`) carries named contexts and a
# remote context; a real target inherits them (review B 1).
group "default" {
  targets = ["app"]
}

target "_hidden" { contexts = { base = "docker-image://busybox:latest" } }

target "_remote" {
  context = "https://example.invalid/team/repo.git"
}

target "app" {
  inherits = ["_hidden"]
  context  = "."
}
