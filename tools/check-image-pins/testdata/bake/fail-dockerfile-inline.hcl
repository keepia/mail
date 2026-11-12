target "a" {
  context           = "."
  dockerfile-inline = "FROM debian:trixie-slim"
}
# want-lines: 3
