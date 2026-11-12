target "a" {
  context = "."
  args = {
    BUILDKIT_SYNTAX = "docker/dockerfile:1"
  }
}
# want-lines: 4
