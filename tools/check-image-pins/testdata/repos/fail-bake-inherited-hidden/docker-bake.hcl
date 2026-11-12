# A hidden target (not in `bake --list`) carries named contexts; a real
# target inherits them, and --print of the real target shows them
# (review B 1). _remote is inherited by nothing, so nothing builds it, and
# the check reads only what builds read (round 3: names only from --list).
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
