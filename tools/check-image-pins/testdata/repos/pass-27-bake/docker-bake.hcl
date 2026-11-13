# The release build's shape (#27, test 19): the repository's variables
# and tags. "other" names another repository in its tags, which build
# mode refuses in a release build.
variable "VERSION" {
  default = "dev"
}

variable "REGISTRY" {
  default = "ghcr.io/keepia"
}

group "default" {
  targets = ["postfix"]
}

target "postfix" {
  context    = "images"
  dockerfile = "postfix/Dockerfile"
  tags       = ["${REGISTRY}/mail-postfix:${VERSION}"]
  labels = {
    "org.opencontainers.image.version" = VERSION
  }
}

target "other" {
  context    = "images"
  dockerfile = "postfix/Dockerfile"
  tags       = ["ghcr.io/other/mail-postfix:${VERSION}"]
}
