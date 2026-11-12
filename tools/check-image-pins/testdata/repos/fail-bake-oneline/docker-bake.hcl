# One-line blocks (review A 1b, review B 1): a line-based reading never
# sees these attributes; bake resolves them like any other.
group "default" { targets = ["a", "b"] }
target "a" { context = "https://example.invalid/team/repo.git#main" }
target "b" { contexts = { base = "docker-image://debian:trixie-slim" } }
