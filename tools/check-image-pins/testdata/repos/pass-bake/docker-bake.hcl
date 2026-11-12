# The repository's own shape: a hidden common target, a root build and an
# image under images/ with a shared context.
variable "VERSION" {
  default = "dev"
}

group "default" {
  targets = ["root", "a"]
}

target "_common" {
  args = { VERSION = VERSION }
}

target "root" {
  inherits = ["_common"]
  context  = "."
}

target "a" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "a/Dockerfile"
}
