#!/bin/sh
# Builds the release bundle of Keepia Mail (#27 plan section 4):
# keepia-mail/ in OUTDIR/keepia-mail-VERSION.tar.gz (owner 0/0), plus
# OUTDIR/SHA256SUMS. The bundle holds:
#   - docker-compose.yml with every own image pinned by digest:
#     ${KEEPIA_<NAME>_IMAGE:-ghcr.io/keepia/mail-<name>:VERSION@sha256:<index>}
#     (the override variable stays, so a verified local image ID still
#     works), and no build: section;
#   - .env.example without KEEPIA_REGISTRY and KEEPIA_VERSION;
#   - deploy/, km (mode 0755, unchanged), README.txt and, when given,
#     SOURCES.md.
# It fails unless all five own images were rewritten and no build:,
# KEEPIA_REGISTRY or KEEPIA_VERSION is left.
#
# Usage: scripts/release-bundle.sh VERSION OUTDIR DIGESTS [SOURCES_MD]
#   VERSION     X.Y.Z
#   DIGESTS     a file of lines "<name> sha256:<64 hex>", exactly one for
#               each of mail, mail-postfix, mail-unbound, mail-olefy and
#               mail-sogo (the index digests -publish-index put out)
#   SOURCES_MD  the release's SOURCES.md (tools/release-sources)
#
# KEEPIA_BUNDLE_SOURCE (tests only): the directory to read
# docker-compose.yml, .env.example, km and deploy/ from; default the
# repository.
set -eu

usage="usage: release-bundle.sh VERSION OUTDIR DIGESTS [SOURCES_MD]"
if [ $# -lt 3 ] || [ $# -gt 4 ]; then
	echo "$usage" >&2
	exit 2
fi
version=$1 out=$2 digests=$3 sources=${4:-}
# The case rejects newlines, which grep would treat as separate lines.
case $version in
'' | *[!0-9.]*) bad=1 ;;
*) bad= ;;
esac
if [ -n "$bad" ] || ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
	echo "release-bundle: not a release version (X.Y.Z): $version" >&2
	exit 2
fi
if [ ! -f "$digests" ]; then
	echo "release-bundle: no digests file $digests" >&2
	exit 2
fi
if [ -n "$sources" ] && [ ! -f "$sources" ]; then
	echo "release-bundle: no SOURCES.md at $sources" >&2
	exit 2
fi

names="mail mail-postfix mail-unbound mail-olefy mail-sogo"
# The digest of each name, checked: exactly the five names, once each.
for n in $names; do
	eval "digest_$(echo "$n" | tr - _)="
done
while IFS= read -r line || [ -n "$line" ]; do
	[ -n "$line" ] || continue
	name=${line%% *} d=${line#* }
	case " $names " in
	*" $name "*) ;;
	*)
		echo "release-bundle: unknown image name in $digests: $name" >&2
		exit 2
		;;
	esac
	if ! printf '%s\n' "$d" | grep -Eq '^sha256:[0-9a-f]{64}$' || [ "$name $d" != "$line" ]; then
		echo "release-bundle: not \"<name> sha256:<64 hex>\": $line" >&2
		exit 2
	fi
	var=digest_$(echo "$name" | tr - _)
	if [ -n "$(eval "echo \"\$$var\"")" ]; then
		echo "release-bundle: $name is named twice in $digests" >&2
		exit 2
	fi
	eval "$var=$d"
done < "$digests"
for n in $names; do
	var=digest_$(echo "$n" | tr - _)
	if [ -z "$(eval "echo \"\$$var\"")" ]; then
		echo "release-bundle: no digest for $n in $digests" >&2
		exit 2
	fi
done

src=${KEEPIA_BUNDLE_SOURCE:-$(cd "$(dirname "$0")/.." && pwd)}
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
dir=$stage/keepia-mail
mkdir "$dir"

# docker-compose.yml: the own images by digest; no build sections (a
# "build:" line and the lines indented deeper, and the comment before a
# `build: .`); the header names the pull instead of `make images`.
sed_args=
for n in $names; do
	var=digest_$(echo "$n" | tr - _)
	d=$(eval "echo \"\$$var\"")
	sed_args="$sed_args -e s|\${KEEPIA_REGISTRY:-ghcr.io/keepia}/$n:\${KEEPIA_VERSION:-dev}}|ghcr.io/keepia/$n:$version@$d}|"
done
{
	echo "# Keepia Mail $version: https://github.com/keepia/mail/releases/tag/v$version"
	echo "#"
	awk '
		/^# Copy \.env\.example to \.env and fill it in first\. The own images$/ {
			print "# Copy .env.example to .env and fill it in first. The own images"
			print "# (ghcr.io/keepia/mail*) are pinned by digest: `docker compose pull`"
			print "# fetches them, then start with `docker compose up -d --no-build` and"
			print "# run commands with ./km."
			header = 1
			next
		}
		header && /^# mutable tag\)\. / { sub(/^# mutable tag\)\. /, "# "); header = 0; print; next }
		header { next }
		/^    # The definition `make images` builds/ { next }
		/^    # only ever used with --no-build\.$/ { next }
		/^    build:/ { skip = 1; next }
		skip && /^      / { next }
		{ skip = 0 }
		{ print }
	' "$src/docker-compose.yml" | sed $sed_args
} > "$dir/docker-compose.yml"
for n in $names; do
	var=digest_$(echo "$n" | tr - _)
	if ! grep -qF "ghcr.io/keepia/$n:$version@$(eval "echo \"\$$var\"")}" "$dir/docker-compose.yml"; then
		echo "release-bundle: docker-compose.yml has no pinned $n" >&2
		exit 1
	fi
done
if grep -Eq '^[[:space:]]+build:|KEEPIA_REGISTRY|KEEPIA_VERSION|nothing here builds or pulls them' "$dir/docker-compose.yml"; then
	echo "release-bundle: docker-compose.yml still has a build:, KEEPIA_REGISTRY or KEEPIA_VERSION:" >&2
	grep -En '^[[:space:]]+build:|KEEPIA_REGISTRY|KEEPIA_VERSION|nothing here builds or pulls them' "$dir/docker-compose.yml" >&2
	exit 1
fi

# .env.example: no registry and version; the overrides instead.
awk '
	/^# The own images: \$\{KEEPIA_REGISTRY\}/ {
		print "# The own images are pinned by digest in docker-compose.yml. To run"
		print "# another build of one, set KEEPIA_IMAGE, KEEPIA_POSTFIX_IMAGE,"
		print "# KEEPIA_UNBOUND_IMAGE, KEEPIA_OLEFY_IMAGE or KEEPIA_SOGO_IMAGE to its"
		print "# image name or ID."
		skip = 1
		next
	}
	skip && /^KEEPIA_VERSION=/ { skip = 0; next }
	skip { next }
	{ print }
' "$src/.env.example" > "$dir/.env.example"
if grep -q 'KEEPIA_REGISTRY\|KEEPIA_VERSION' "$dir/.env.example"; then
	echo "release-bundle: .env.example still has KEEPIA_REGISTRY or KEEPIA_VERSION" >&2
	exit 1
fi

cp -R "$src/deploy" "$dir/deploy"
cp -p "$src/km" "$dir/km"
if [ ! -x "$dir/km" ]; then
	echo "release-bundle: km is not executable" >&2
	exit 1
fi
if [ -n "$sources" ]; then
	cp "$sources" "$dir/SOURCES.md"
fi

{
	cat << EOF
Keepia Mail $version

Images:  ghcr.io/keepia/mail, mail-postfix, mail-unbound, mail-olefy and
         mail-sogo, $version (linux/amd64, linux/arm64), pinned by digest in
         docker-compose.yml
Release: https://github.com/keepia/mail/releases/tag/v$version

Needs Docker Engine 28 or later: the internal networks use the gateway
mode isolated, which Engine 27 refuses and 26 or older ignores silently.
After the first start, check that the host has no address in the internal
subnets, as section 7 of
https://github.com/keepia/mail/blob/v$version/docs/development/architecture.md
shows.

First start:
  cp .env.example .env            # fill it in (KEEPIA_POSTGRES_PASSWORD, edge addresses)
  docker compose pull
  ./km migrate
  docker compose up -d --no-build

Upgrade: back up first, then extract the newer keepia-mail-X.Y.Z.tar.gz in
the directory above this one, so that it replaces these files and keeps
.env and the volumes:
  docker compose pull
  ./km migrate
  docker compose up -d --no-build

Tags: X.Y.Z never changes. The bundle pins every image by digest.
EOF
	if [ "${version%%.*}" = 0 ]; then
		cat << EOF
Before 1.0, \`latest\` follows every 0.x release and can include breaking
changes: pin X.Y.Z or a digest.

$version is not a working mail server: the 0.x releases build Keepia
Mail step by step, and their notes say what works.
EOF
	fi
} > "$dir/README.txt"

file=keepia-mail-$version.tar.gz
# Numeric owner 0/0, not the build machine's user.
tar -C "$stage" --owner=0 --group=0 --numeric-owner -czf "$out/$file" keepia-mail
(cd "$out" && sha256sum "$file" > SHA256SUMS)
echo "$out/$file"
