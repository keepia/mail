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
  # The licences label is per target (#27 plan, finding 5): Keepia's MIT
  # covers only Keepia's own files. The per-package licences of the Debian
  # base and of every other component are in the release's SBOMs.
  # io.github.keepia.sources points to the release's SOURCES.md, the
  # directions to the sources next to the object code (GPLv3 section 6(d),
  # the licence decision 6835095391); a dev build names a URL that does
  # not resolve, which is right for an unreleased build.
  labels = {
    "org.opencontainers.image.source"  = "https://github.com/keepia/mail"
    "org.opencontainers.image.version" = VERSION
    "org.opencontainers.image.vendor"  = "Keepia"
    "io.github.keepia.sources"         = "https://github.com/keepia/mail/releases/download/v${VERSION}/SOURCES.md"
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
    # Keepia's own binary. The Go modules it is built from and the
    # distroless base packages are listed with their licences in the SBOM.
    "org.opencontainers.image.licenses" = "MIT"
  }
}

# Postfix (Debian's package): "dual-licensed under both the Eclipse Public
# License version 2.0 and the IBM Public License version 1.0", as
# /usr/share/doc/postfix/copyright in the built image says (#27 part 4b);
# MIT for Keepia's own scripts.
target "postfix" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "postfix/Dockerfile"
  tags       = ["${REGISTRY}/mail-postfix:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail Postfix"
    "org.opencontainers.image.description" = "Postfix for the Keepia Mail edge role"
    "org.opencontainers.image.licenses"    = "MIT AND (IPL-1.0 OR EPL-2.0)"
  }
}

# Unbound (Debian's package): BSD-3-Clause, NLnet Labs' licence of
# "Files: *" in /usr/share/doc/unbound/copyright in the built image (#27
# part 4b; a few compat files are ISC or other BSD texts, listed there and
# in the SBOM); MIT for Keepia's own scripts.
target "unbound" {
  inherits   = ["_common"]
  context    = "images"
  dockerfile = "unbound/Dockerfile"
  tags       = ["${REGISTRY}/mail-unbound:${VERSION}"]
  labels = {
    "org.opencontainers.image.title"       = "Keepia Mail Unbound"
    "org.opencontainers.image.description" = "Unbound resolver for the Keepia Mail roles"
    "org.opencontainers.image.licenses"    = "MIT AND BSD-3-Clause"
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
