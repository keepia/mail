# A bake file under another name (review A delta): a build could use it
# with `-f images.hcl` or bake-action `files:`.
target "a" {
  context  = "https://example.invalid/team/repo.git"
  contexts = { base = "docker-image://debian:trixie-slim" }
}
