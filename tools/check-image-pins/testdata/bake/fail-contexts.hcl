target "postfix" {
  context = "images"
  contexts = {
    base = "docker-image://debian:trixie-slim"
  }
}
# want-lines: 3
