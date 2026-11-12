# Variables a build's environment sets (review A delta: CTX=https://…
# docker buildx bake; review B R2: DF=build.txt). The defaults are clean;
# the check resolves again with every variable at a sentinel and reports
# what moves. VERSION is harmless here: it only sets an argument.
variable "CTX" {
  default = "."
}

variable "DF" {
  default = "Dockerfile"
}

variable "VERSION" {
  default = "dev"
}

target "a" {
  context = CTX
  args    = { VERSION = VERSION }
}

target "b" {
  dockerfile = DF
}
