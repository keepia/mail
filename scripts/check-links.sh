#!/bin/sh
# Checks every relative Markdown link of the form [text](path#anchor) in the
# Markdown files of a git checkout (tracked files and untracked files that are
# not ignored):
# - the target, resolved relative to the linking file's directory (with `./`
#   and `../`; a leading `/` means the repository root), must be a file or a
#   directory in the checkout and must not lie outside it;
# - if the link has a #fragment and the target is a Markdown file (or the
#   link has no path, meaning the linking file itself), a heading with that
#   GitHub slug must exist in the target.
# External links (any URL scheme such as https: or mailto:) are skipped; this
# check never uses the network. Inline-code spans and fenced code blocks (```
# or ~~~, also indented) are skipped. The fixtures of the self-test
# (scripts/testdata/check-links/) contain broken links on purpose and are
# skipped. Known limits: reference-style links, <path> autolinks, link titles,
# percent-encoded paths, duplicate headings (-1, -2 suffixes), non-ASCII and
# underscore slugs are not modelled.
#
# Usage: check-links.sh [checkout directory]  (default: this repository)
# Reports every broken link and exits 1 if there is any, 2 on a usage error.
set -eu

if [ $# -gt 0 ]; then
	root=$1
else
	root=$(cd "$(dirname "$0")/.." && pwd)
fi
cd "$root" || exit 2
git rev-parse --git-dir >/dev/null 2>&1 || {
	echo "check-links: $root is not a git checkout" >&2
	exit 2
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Every path in the checkout, relative to the root.
git ls-files --cached --others --exclude-standard >"$tmp/files"

# slugs_of <file>: the GitHub slug of each heading: lowercase, drop everything
# but letters, digits, spaces and hyphens, spaces to hyphens. Headings inside
# fenced code blocks are not headings.
slugs_of() {
	sed -E '/^ *(```|~~~)/,/^ *(```|~~~)/d' "$1" |
		grep -E '^#{1,6} ' |
		sed -E 's/^#{1,6} +//; s/ +#* *$//' |
		tr '[:upper:]' '[:lower:]' |
		sed -E 's/[^a-z0-9 -]//g; s/ /-/g'
}

# links_of <file>: the link targets, after stripping fenced code blocks and
# inline code.
links_of() {
	sed -E '/^ *(```|~~~)/,/^ *(```|~~~)/d; s/`[^`]*`//g' "$1" |
		grep -o -E '\]\([^)]+\)' |
		sed -E 's/^\]\(//; s/\)$//' || true
}

# normalize <path>: prints the path with `.`, `..` and empty segments
# resolved (empty for the root); fails if it leaves the root.
normalize() {
	awk -v p="$1" 'BEGIN {
		n = split(p, seg, "/"); k = 0
		for (i = 1; i <= n; i++) {
			s = seg[i]
			if (s == "" || s == ".") continue
			if (s == "..") { if (k == 0) exit 1; k--; continue }
			out[++k] = s
		}
		r = ""
		for (i = 1; i <= k; i++) r = r (i > 1 ? "/" : "") out[i]
		print r
	}'
}

# exists <path>: the path is a file in the checkout, or a directory holding
# one (the root included).
exists() {
	[ -z "$1" ] && return 0
	awk -v p="$1" '$0 == p || index($0, p "/") == 1 { found = 1; exit }
		END { exit !found }' "$tmp/files"
}

grep -E '\.md$' "$tmp/files" | grep -v '^scripts/testdata/check-links/' >"$tmp/md" || true

broken=0
while IFS= read -r file; do
	[ -f "$file" ] || continue
	dir=$(dirname "$file")
	links_of "$file" >"$tmp/links"
	while IFS= read -r link; do
		[ -n "$link" ] || continue
		# A URL scheme (letters, digits, + . - before the first colon).
		scheme=${link%%:*}
		if [ "$scheme" != "$link" ]; then
			case $scheme in
			[a-zA-Z]*) case $scheme in *[!a-zA-Z0-9+.-]*) ;; *) continue ;; esac ;;
			esac
		fi
		path=${link%%#*}
		fragment=
		case $link in *'#'*) fragment=${link#*#} ;; esac
		case $path in
		'') target=$file ;;
		/*) target=$path ;;
		*) target=$dir/$path ;;
		esac
		if ! target=$(normalize "$target"); then
			echo "$file: target '$path' is outside the repository (link '$link')"
			broken=$((broken + 1))
			continue
		fi
		if ! exists "$target"; then
			echo "$file: missing target '$target' (link '$link')"
			broken=$((broken + 1))
			continue
		fi
		case $target in *.md) ;; *) continue ;; esac
		if [ -n "$fragment" ] && ! slugs_of "$target" | grep -qxF -- "$fragment"; then
			echo "$file: no heading '#$fragment' in '$target' (link '$link')"
			broken=$((broken + 1))
		fi
	done <"$tmp/links"
done <"$tmp/md"

if [ "$broken" -eq 0 ]; then
	echo "check-links: all relative links resolve ($(wc -l <"$tmp/md" | tr -d ' ') Markdown files)."
	exit 0
fi
echo "check-links: $broken broken link(s)."
exit 1
