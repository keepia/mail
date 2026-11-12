# dockerfile-inline is not a file the Dockerfile rules can read, and
# BUILDKIT_SYNTAX replaces the pinned # syntax= frontend; the second comes
# from a hidden target through inheritance.
group "default" {
  targets = ["a", "b"]
}

target "a" { dockerfile-inline = "FROM debian:trixie-slim" }

target "_syntax" {
  args = {
    BUILDKIT_SYNTAX = "docker/dockerfile:1"
  }
}

target "b" {
  inherits = ["_syntax"]
}
