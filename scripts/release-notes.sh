#!/bin/sh
# Prints the head of a release's notes, in Markdown (#27 plan sections 1
# and 3, revision 4): the images with their tags, digests and platforms;
# for 0.x that the release is not a working mail server and what `latest`
# means before 1.0; Docker Engine 28; new installation and upgrade from
# the bundle; how to verify the attestations; and "Licences and sources".
# The release job passes it to `gh release create --notes-file`, which
# appends the notes generated from the pull requests (.github/release.yml).
#
# Usage: scripts/release-notes.sh VERSION LAST DIGESTS LICENCES
#   VERSION   X.Y.Z
#   LAST      the last release X.Y.Z; empty for the first release
#   DIGESTS   lines "<name> sha256:<64 hex>" (as for release-bundle.sh)
#   LICENCES  lines "<name> <licence expression>" (tools/release-sources)
set -eu

if [ $# -ne 4 ]; then
	echo "usage: release-notes.sh VERSION LAST DIGESTS LICENCES" >&2
	exit 2
fi
version=$1 last=$2 digests=$3 licences=$4
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
for v in "$version" ${last:+"$last"}; do
	case $v in
	'' | *[!0-9.]*) bad=1 ;;
	*) bad= ;;
	esac
	if [ -n "$bad" ] || ! printf '%s\n' "$v" | grep -Eq "$semver"; then
		echo "release-notes: not X.Y.Z: $v" >&2
		exit 2
	fi
done
names="mail mail-postfix mail-unbound mail-olefy mail-sogo"
for n in $names; do
	if [ "$(grep -c "^$n sha256:[0-9a-f]\{64\}\$" "$digests")" != 1 ]; then
		echo "release-notes: $digests has no single digest line for $n" >&2
		exit 2
	fi
	if [ "$(grep -c "^$n [^ ]" "$licences")" != 1 ]; then
		echo "release-notes: $licences has no single licence line for $n" >&2
		exit 2
	fi
done

base=https://github.com/keepia/mail/releases/download/v$version
echo "## Images"
echo
echo "| Image | Tags | Index digest | Platforms |"
echo "|---|---|---|---|"
for n in $names; do
	d=$(grep "^$n " "$digests" | cut -d' ' -f2)
	echo "| \`ghcr.io/keepia/$n\` | \`$version\`, \`latest\` | \`$d\` | linux/amd64, linux/arm64 |"
done
echo
echo "\`$version\` never changes. The bundle pins every image by digest."
if [ "${version%%.*}" = 0 ]; then
	cat << EOF
Before 1.0, \`latest\` follows every 0.x release and **can include breaking changes**: pin \`$version\` or a digest.

**$version is not a working mail server.** The 0.x releases build Keepia Mail step by step; do not use this one for mail.
EOF
fi
cat << EOF

Needs **Docker Engine 28 or later**: the internal networks use the gateway mode \`isolated\`, which Engine 27 refuses and 26 or older ignores silently.

**New installation:** download \`keepia-mail-$version.tar.gz\` below, extract it and follow \`README.txt\`: \`cp .env.example .env\`, fill it in, then \`docker compose pull\`, \`./km migrate\` and \`docker compose up -d --no-build\` (the images are pinned by digest).

EOF
if [ -n "$last" ]; then
	echo "**Upgrade from $last:** back up, extract \`keepia-mail-$version.tar.gz\` in the directory above your \`keepia-mail/\` directory (it keeps \`.env\` and the volumes), then \`docker compose pull\`, \`./km migrate\` and \`docker compose up -d --no-build\` (read the breaking changes and database migrations below first)."
else
	echo "This is the first release: there is nothing to upgrade from."
fi
cat << EOF

**Verify** the provenance of an image and the SBOM of a platform image:

\`\`\`
gh attestation verify oci://ghcr.io/keepia/mail-postfix:$version --owner keepia
gh attestation verify oci://ghcr.io/keepia/mail-postfix@<platform digest> --owner keepia --predicate-type https://spdx.dev/Document/v2.3
\`\`\`

## Licences and sources

| Image | Licences (\`org.opencontainers.image.licenses\`) |
|---|---|
EOF
for n in $names; do
	l=$(grep "^$n " "$licences" | cut -d' ' -f2-)
	echo "| \`ghcr.io/keepia/$n\` | \`$l\` |"
done
cat << EOF

Every source of every image is listed in [SOURCES.md]($base/SOURCES.md) and \`sources.json\`, and per image and architecture in the SBOMs \`sbom-<image>-<arch>.spdx.json\` (SPDX 2.3), also as attestations. The GPL-3.0-only parts of \`mail-olefy\` (pcodedmp, and xxxswf in oletools) ship with their Python sources and licence files in the image and are listed with their wheels' sha256.

CC-BY-SA-3.0 attribution: \`IterStream\` in oletools' \`ppt_record_parser.py\` (in \`mail-olefy\`) is, as its docstring says, "Copied from stackoverflow answer by Mechanical snail from Nov 18th 2013 https://stackoverflow.com/a/20260030/4405656 and extended."
EOF
