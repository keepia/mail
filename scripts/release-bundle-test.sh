#!/bin/sh
# Test 15 (#27): scripts/release-bundle.sh with fixed fake digests. Needs
# docker compose (config only: no daemon, no network), jq, tar and
# sha256sum.
set -eu

for c in docker jq tar sha256sum; do
	command -v "$c" > /dev/null || {
		echo "release-bundle-test: $c is required" >&2
		exit 1
	}
done

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
bundle=$here/release-bundle.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0 passed=0
names="mail mail-postfix mail-unbound mail-olefy mail-sogo"

fail() {
	echo "FAIL $1: $2"
	failed=$((failed + 1))
}
pass() { passed=$((passed + 1)); }

# digest NAME: a fixed fake digest per name.
digest() {
	case $1 in
	mail) d=1 ;; mail-postfix) d=2 ;; mail-unbound) d=3 ;; mail-olefy) d=4 ;; mail-sogo) d=5 ;;
	esac
	printf 'sha256:%064d\n' "$d"
}
digests=$tmp/digests.txt
for n in $names; do
	echo "$n $(digest "$n")"
done > "$digests"
echo "# Sources of Keepia Mail 99.0.0" > "$tmp/SOURCES.md"

# compose_config DIR ARGS...: docker compose config of an extracted bundle,
# every profile on, no daemon needed.
compose_config() {
	d=$1
	shift
	COMPOSE_PROFILES=control,edge,store,filter,groupware KEEPIA_POSTGRES_PASSWORD=x \
		docker compose --project-directory "$d" -f "$d/docker-compose.yml" --env-file "$d/.env.example" config "$@"
}

# --- a bundle of 99.0.0 -----------------------------------------------------

out=$tmp/dist
if sh "$bundle" 99.0.0 "$out" "$digests" "$tmp/SOURCES.md" > "$tmp/log" 2>&1; then
	pass
else
	fail "bundle 99.0.0" "$(cat "$tmp/log")"
fi
tarball=$out/keepia-mail-99.0.0.tar.gz
mkdir "$tmp/x"
tar -xzf "$tarball" -C "$tmp/x"
b=$tmp/x/keepia-mail

# Every own image by digest, every upstream image unchanged.
images=$(compose_config "$b" --images | sort -u)
for n in $names; do
	case $images in
	*"ghcr.io/keepia/$n:99.0.0@$(digest "$n")"*) pass ;;
	*) fail "image $n" "not pinned: $images" ;;
	esac
done
upstream=$(COMPOSE_PROFILES=control,edge,store,filter,groupware KEEPIA_POSTGRES_PASSWORD=x \
	docker compose --project-directory "$repo" -f "$repo/docker-compose.yml" --env-file "$repo/.env.example" config --images | grep '@sha256:' | sort -u)
own=$(printf '%s\n' "$images" | grep -c '^ghcr.io/keepia/mail')
if [ "$(printf '%s\n' "$images" | grep -v '^ghcr.io/keepia/mail' | sort -u)" = "$upstream" ] && [ "$own" -eq 5 ]; then
	pass
else
	fail "upstream images" "bundle: $images; repository: $upstream"
fi
if [ "$(compose_config "$b" --format json | jq '[.services[] | select(has("build"))] | length')" = 0 ]; then
	pass
else
	fail "no build" "a service has build"
fi
# The override variable stays: a verified local ID replaces the default.
if KEEPIA_POSTFIX_IMAGE=sha256:abc compose_config "$b" --images | grep -qx 'sha256:abc'; then
	pass
else
	fail "override" "KEEPIA_POSTFIX_IMAGE does not replace the image"
fi

# The exact file list, owner 0/0, km executable, SHA256SUMS.
want_files=$(
	cd "$repo"
	echo keepia-mail
	for f in .env.example README.txt SOURCES.md docker-compose.yml km; do
		echo "keepia-mail/$f"
	done
	find deploy | sed 's|^|keepia-mail/|'
)
want_files=$(printf '%s\n' "$want_files" | sort)
got_files=$(tar -tzf "$tarball" | sed 's|/$||' | sort)
if [ "$got_files" = "$want_files" ]; then
	pass
else
	fail "file list" "got:
$got_files
want:
$want_files"
fi
if tar -tvzf "$tarball" | awk '{ print $2 }' | grep -vqx '0/0'; then
	fail "owner" "$(tar -tvzf "$tarball" | awk '{ print $2 }' | sort -u)"
else
	pass
fi
if [ -x "$b/km" ] && cmp -s "$b/km" "$repo/km"; then pass; else fail "km" "not executable or changed"; fi
if (cd "$out" && sha256sum -c SHA256SUMS > /dev/null); then pass; else fail "SHA256SUMS" "does not match"; fi
for f in .env.example docker-compose.yml; do
	if grep -q 'KEEPIA_REGISTRY\|KEEPIA_VERSION' "$b/$f"; then fail "$f" "names KEEPIA_REGISTRY or KEEPIA_VERSION"; else pass; fi
done
grep -q '^# Keepia Mail 99.0.0: https://github.com/keepia/mail/releases/tag/v99.0.0$' "$b/docker-compose.yml" && pass || fail "header" "no version line"
grep -q 'nothing here builds or pulls them' "$b/docker-compose.yml" && fail "header" "still says nothing pulls" || pass
grep -q 'Docker Engine 28 or later' "$b/README.txt" && pass || fail "README" "no Docker Engine 28"
grep -q 'not a working mail server' "$b/README.txt" && fail "README" "99.0.0 is not 0.x" || pass
# The placeholders stay documentation values.
grep -q '^EDGE_IPV4=192.0.2.10$' "$b/.env.example" && pass || fail ".env.example" "edge placeholder changed"

# A 0.x bundle carries the 0.x notes.
if sh "$bundle" 0.1.0 "$tmp/dist0" "$digests" > "$tmp/log" 2>&1; then
	r=$(tar -xzOf "$tmp/dist0/keepia-mail-0.1.0.tar.gz" keepia-mail/README.txt)
	case $r in
	*"0.1.0 is not a working mail server"*"latest"*|*"latest"*"0.1.0 is not a working mail server"*) pass ;;
	*) fail "0.x README" "$r" ;;
	esac
	tar -tzf "$tmp/dist0/keepia-mail-0.1.0.tar.gz" | grep -q SOURCES.md && fail "no SOURCES.md" "listed" || pass
else
	fail "bundle 0.1.0" "$(cat "$tmp/log")"
fi

# --- refused inputs -----------------------------------------------------------

# refused NAME ARGS...: the script exits 2 and writes no tarball.
refused() {
	name=$1
	shift
	rm -rf "$tmp/r"
	set +e
	sh "$bundle" "$@" > "$tmp/log" 2>&1
	rc=$?
	set -e
	if [ "$rc" -ne 2 ] || ls "$tmp/r"/*.tar.gz > /dev/null 2>&1; then
		fail "$name" "exit $rc, want 2: $(cat "$tmp/log")"
	else
		pass
	fi
}
grep -v '^mail-olefy ' "$digests" > "$tmp/missing.txt"
{ cat "$digests"; echo "mail-other $(digest mail)"; } > "$tmp/unknown.txt"
{ cat "$digests"; echo "mail $(digest mail-sogo)"; } > "$tmp/twice.txt"
sed 's/^mail-sogo .*/mail-sogo sha256:abc/' "$digests" > "$tmp/short.txt"
refused "missing digest" 99.0.0 "$tmp/r" "$tmp/missing.txt"
refused "unknown name" 99.0.0 "$tmp/r" "$tmp/unknown.txt"
refused "a name twice" 99.0.0 "$tmp/r" "$tmp/twice.txt"
refused "malformed digest" 99.0.0 "$tmp/r" "$tmp/short.txt"
for v in 1.0 v1.0.0 01.0.0 1.0.0-rc1; do
	refused "version $v" "$v" "$tmp/r" "$digests"
done
refused "version with a newline" "1.0.0
x" "$tmp/r" "$digests"
refused "no digests file" 99.0.0 "$tmp/r" "$tmp/none.txt"
refused "usage" 99.0.0 "$tmp/r"

# --- counter-proofs: a leftover build or an own image without a digest ----

# source NAME: a copy of the repository's bundle inputs to change.
source_copy() {
	s=$tmp/src-$1
	mkdir -p "$s"
	cp -R "$repo/deploy" "$s/deploy"
	cp -p "$repo/km" "$repo/.env.example" "$repo/docker-compose.yml" "$s/"
	echo "$s"
}
s=$(source_copy build)
# A build: deeper than a service's own keys is not a build section the
# rewrite drops; the final check must catch it.
printf '  extra:\n    image: postgres:18.6-trixie@sha256:%064d\n    x-nested:\n      build: { context: x }\n' 0 >> "$s/docker-compose.yml"
if KEEPIA_BUNDLE_SOURCE=$s sh "$bundle" 99.0.0 "$tmp/c1" "$digests" > "$tmp/log" 2>&1; then
	fail "counter-proof: leftover build" "accepted"
else
	grep -q 'still has a build:' "$tmp/log" && pass || fail "counter-proof: leftover build" "$(cat "$tmp/log")"
fi
s=$(source_copy digest)
sed 's|\${KEEPIA_OLEFY_IMAGE:-\${KEEPIA_REGISTRY:-ghcr.io/keepia}/mail-olefy:\${KEEPIA_VERSION:-dev}}|${KEEPIA_OLEFY_IMAGE:-ghcr.io/keepia/mail-olefy:latest}|' "$repo/docker-compose.yml" > "$s/docker-compose.yml"
if KEEPIA_BUNDLE_SOURCE=$s sh "$bundle" 99.0.0 "$tmp/c2" "$digests" > "$tmp/log" 2>&1; then
	fail "counter-proof: own image without a digest" "accepted"
else
	grep -q 'has no pinned mail-olefy' "$tmp/log" && pass || fail "counter-proof: own image without a digest" "$(cat "$tmp/log")"
fi

# --- release-notes.sh (also test 15) ---------------------------------------

notes=$here/release-notes.sh
lic=$tmp/licences.txt
for n in $names; do
	echo "$n MIT AND GPL-2.0-or-later"
done > "$lic"
if out=$(sh "$notes" 0.2.0 0.1.0 "$digests" "$lic" 2>&1); then
	contains() {
		case $out in
		*"$2"*) pass ;;
		*) fail "notes: $1" "'$2' missing" ;;
		esac
	}
	contains "image row" "| \`ghcr.io/keepia/mail-postfix\` | \`0.2.0\`, \`latest\` | \`$(digest mail-postfix)\` | linux/amd64, linux/arm64 |"
	contains "0.x" "0.2.0 is not a working mail server"
	contains "latest before 1.0" "can include breaking changes**: pin \`0.2.0\` or a digest"
	contains "Docker 28" "Docker Engine 28 or later"
	contains "upgrade" "Upgrade from 0.1.0"
	contains "provenance" "gh attestation verify oci://ghcr.io/keepia/mail-postfix:0.2.0 --owner keepia"
	contains "SBOM" "--predicate-type https://spdx.dev/Document/v2.3"
	contains "licences" "| \`ghcr.io/keepia/mail-sogo\` | \`MIT AND GPL-2.0-or-later\` |"
	contains "SOURCES.md" "(https://github.com/keepia/mail/releases/download/v0.2.0/SOURCES.md)"
	contains "attribution" "Mechanical snail from Nov 18th 2013 https://stackoverflow.com/a/20260030/4405656"
else
	fail "notes 0.2.0" "$out"
fi
out=$(sh "$notes" 1.0.0 "" "$digests" "$lic")
case $out in
*"not a working mail server"* | *"Upgrade from"*) fail "notes 1.0.0" "has the 0.x or upgrade text" ;;
*"first release"*) pass ;;
*) fail "notes 1.0.0" "no first-release line" ;;
esac
for args in "v0.2.0 0.1.0" "0.2.0 v0.1.0"; do
	set -- $args
	if sh "$notes" "$1" "$2" "$digests" "$lic" > /dev/null 2>&1; then fail "notes: $args" "accepted"; else pass; fi
done
if sh "$notes" 0.2.0 0.1.0 "$tmp/missing.txt" "$lic" > /dev/null 2>&1; then fail "notes: missing digest" "accepted"; else pass; fi

echo "release-bundle-test: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
