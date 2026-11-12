# The own images: one definition for CI (the docker-build job),
# `make images` and the release workflow (#5 plan, "Repository layout").
#
#   docker buildx bake                      # every image, native platform
#   docker buildx bake postfix --load       # one image into the local store
#   PLATFORM=linux/arm64 docker buildx bake unbound
#
# Contexts are relative paths inside the repository; named `contexts` are
# not used (tools/check-image-pins, rule 5).

variable "VERSION" {
  default = "dev"
}

# Registry prefix of the image names.
variable "REGISTRY" {
  default = "ghcr.io/keepia"
}

# One platform, such as linux/arm64; empty builds for the builder's own.
variable "PLATFORM" {
  default = ""
}

group "default" {
  targets = ["keepia", "postfix", "unbound"]
}

target "_common" {
  platforms = PLATFORM == "" ? [] : [PLATFORM]
  args = {
    VERSION = VERSION
  }
  labels = {
    "org.opencontainers.image.source"   = "https://github.com/keepia/mail"
    "org.opencontainers.image.version"  = VERSION
    "org.opencontainers.image.licenses" = "MIT"
    "org.opencontainers.image.vendor"   = "Keepia"
  }
}

target "keepia" {
  inherits   = ["_common"]
  context    = "."
  dockerfile = "Dockerfile"
  tags       = ["${REGISTRY}/mail:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail"
    "org.opencontainers.image.description" = "Keepia Mail service and command-line tool"
  }
}

target "postfix" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "postfix/Dockerfile"
  tags       = ["${REGISTRY}/mail-postfix:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail Postfix"
    "org.opencontainers.image.description" = "Postfix for the Keepia Mail edge role"
  }
}

target "unbound" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "unbound/Dockerfile"
  tags       = ["${REGISTRY}/mail-unbound:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail Unbound"
    "org.opencontainers.image.description" = "Unbound resolver for the Keepia Mail roles"
  }
}
