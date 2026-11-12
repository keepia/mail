target "a" {
  "context" = "https://example.org/team/repo.git"
  "contexts" = { base = "docker-image://debian:trixie-slim" }
}
# want-lines: 2 3
