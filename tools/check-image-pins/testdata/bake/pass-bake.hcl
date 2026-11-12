# A bake file in the repository's style.
variable "VERSION" {
  default = "dev"
}

target "_common" {
  args = { VERSION = VERSION }
}

target "keepia" {
  inherits   = ["_common"]
  context    = "."
  dockerfile = "Dockerfile"
}

target "postfix" {
  inherits   = ["_common"]
  context    = "images" # the shared files in images/common
  dockerfile = "postfix/Dockerfile"
}
// a C-style comment: contexts = { x = "docker-image://x" }
