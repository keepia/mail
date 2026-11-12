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
  targets = ["keepia", "postfix", "unbound", "olefy", "sogo"]
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

# olefy and the two wheels (#44). Their licences, not Keepia's MIT, apply to
# the image's content (#55), read from the pinned wheels' files (#59):
# - olefy at 9c01c571: Apache-2.0 (its LICENSE and olefy.py's header).
# - oletools 0.60.2: BSD-2-Clause (LICENSE.md), which excludes its
#   thirdparty folder and names MIT for the officeparser code in olevba.
#   Its other parts: ezhexviewer's hexdump3 (PSF-2.0, a Python Cookbook
#   recipe), ppt_record_parser's IterStream (a Stack Overflow answer of
#   2013, CC-BY-SA-3.0), and in thirdparty/ prettytable (BSD-3-Clause,
#   COPYING), xglob and tablestream (BSD-2-Clause), xxxswf (GPL-3.0,
#   LICENSE.txt) and oledump (public domain, the files' headers).
# - pcodedmp 1.2.6: GPL-3.0 (its LICENSE and classifier; it grants no "or
#   later", nor does xxxswf).
target "olefy" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "olefy/Dockerfile"
  tags       = ["${REGISTRY}/mail-olefy:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail olefy"
    "org.opencontainers.image.description" = "olefy (oletools for rspamd) for the Keepia Mail filter role"
    "org.opencontainers.image.licenses"    = "Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND PSF-2.0 AND CC-BY-SA-3.0 AND GPL-3.0-only AND LicenseRef-Public-Domain"
  }
}

# SOGo and SOPE built from Alinto's release tags (#25). Their licences, not
# Keepia's MIT, apply to the image's content.
target "sogo" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "sogo/Dockerfile"
  tags       = ["${REGISTRY}/mail-sogo:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail SOGo"
    "org.opencontainers.image.description" = "SOGo groupware for the Keepia Mail groupware role"
    "org.opencontainers.image.licenses"    = "GPL-2.0-or-later AND LGPL-2.0-or-later"
  }
}
