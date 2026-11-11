#!/bin/sh
# Checks that every `uses:` in the workflows is pinned:
# - an action or reusable workflow: owner/repo[/path]@<full 40-hex commit SHA>
#   followed by a version comment, `# vX.Y.Z` (Dependabot keeps both current);
# - a local action (./path) is allowed as is;
# - a Docker action: docker://image@sha256:<64 hex>.
# Anything else (a tag, a branch, a short SHA, a SHA without the version
# comment, a docker:// image without a digest, a `uses:` whose value is not on
# the same line) is reported.
#
# Every `uses` key counts, in any YAML form: block style (`uses: x`,
# `- uses: x`), a quoted key (`"uses": x`, `'uses': x`) and flow style
# (`- {uses: x}`, `steps: [{uses: x}]`). The key search runs on the whole
# line, so a `uses:` inside a run: script line or after something that looks
# like a comment is checked too. The version comment must be a real YAML
# comment at the end of that line: a `#` after whitespace and outside any
# quoted string (`''` inside single quotes is an escaped quote); `# v1.2.3`
# inside a quoted value does not count. Only full-line comments are skipped.
#
# Lines this scanner cannot read are rejected, whatever follows:
# - an explicit key (`? ` as the first non-space characters, also `- ? `);
# - a quoted key that contains a backslash (an escape such as `"u\x73es":`
#   or `"\u0075ses":`); escapes are not decoded.
#
# Known limits: this is a line scanner, not a YAML parser. It fails closed on
# the forms above, but it does not follow a value across lines. Known gap: a
# continuation line of a multi-line double-quoted value that starts with `#`
# is skipped as a full-line comment, so a `uses:` key on that line is not
# checked, for example
#   - {name: "a
#     # ", uses: actions/checkout@v7}
# Such YAML is only written on purpose and is caught by the two reviews every
# workflow change gets. A real YAML parser (zizmor's unpinned-uses or a small
# Go tool) is planned with #6.
#
# Usage: check-action-pins.sh [directory]  (default: .github/workflows of this
# repository). Checks every *.yml and *.yaml file directly in the directory.
# Exits 1 if any `uses:` is not pinned, 2 on a usage error.
set -eu

if [ $# -gt 0 ]; then
	dir=$1
else
	dir=$(cd "$(dirname "$0")/.." && pwd)/.github/workflows
fi
[ -d "$dir" ] || {
	echo "check-action-pins: no directory $dir" >&2
	exit 2
}

# The value of a `uses` key, quotes removed, and the comment of its line.
action='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@[:space:]]+)?@[0-9a-f]{40}$'
version_comment='^#[[:space:]]*v[0-9]+\.[0-9]+\.[0-9]+([^0-9.]|$)'
local_action='^\./'
docker='^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$'

# uses_of <file>: one line per `uses` key: line number, value and the end-of-
# line comment (empty if none), separated by tabs. Keys are searched on the
# raw line; the comment split is used only for the version comment. The
# value ends at whitespace, `,`, `}` or `]`. Value and comment start with
# `=`, so that an empty field stays a field. A line the scanner cannot read gets one record
# whose value names the reason, so it is reported.
uses_of() {
	awk -v q="'" '
	BEGIN { key = "(^|[ \t{,])[\"" q "]?uses[\"" q "]?[ \t]*:" }
	/^[ \t]*#/ { next }
	{
		line = $0
		# Split off the end-of-line comment: the first # that follows
		# whitespace and lies outside a quoted string. A quote opens a
		# string only at the start of a token; `''` inside single quotes
		# is an escaped quote.
		comment = ""; inq = ""; prev = " "
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			if (inq == "\"") {
				if (c == "\\") { i++; prev = ""; continue }
				if (c == "\"") inq = ""
			} else if (inq == q) {
				if (c == q && substr(line, i + 1, 1) == q) { i++; continue }
				if (c == q) inq = ""
			} else if ((c == "\"" || c == q) && prev ~ /^[ \t\[{,:]$/) {
				inq = c
			} else if (c == "#" && prev ~ /^[ \t]$/) {
				comment = substr(line, i)
				line = substr(line, 1, i - 1)
				break
			}
			prev = c
		}
		if (line ~ /^[ \t]*(-[ \t]+)*\?([ \t]|$)/) {
			printf "%d\t=(explicit key \"?\", not readable)\t=\n", NR
			next
		}
		if (line ~ ("[\"" q "][^\"" q "]*\\\\[^\"" q "]*[\"" q "][ \t]*:")) {
			printf "%d\t=(quoted key with a backslash escape, not readable)\t=\n", NR
			next
		}
		rest = $0
		while (match(rest, key)) {
			rest = substr(rest, RSTART + RLENGTH)
			sub(/^[ \t]*/, "", rest)
			match(rest, /^[^] \t,}]*/)
			value = substr(rest, 1, RLENGTH)
			rest = substr(rest, RLENGTH + 1)
			gsub(/["\047]/, "", value)
			printf "%d\t=%s\t=%s\n", NR, value, comment
		}
	}' "$1"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bad=0
files=0
for f in "$dir"/*.yml "$dir"/*.yaml; do
	[ -f "$f" ] || continue
	files=$((files + 1))
	uses_of "$f" >"$tmp/uses"
	tab=$(printf '\t')
	while IFS="$tab" read -r n value comment; do
		value=${value#=} comment=${comment#=}
		if printf '%s\n' "$value" | grep -qE -e "$local_action" -e "$docker"; then
			continue
		fi
		if printf '%s\n' "$value" | grep -qE "$action" &&
			printf '%s\n' "$comment" | grep -qE "$version_comment"; then
			continue
		fi
		echo "$f:$n: not pinned to a full commit SHA with a '# vX.Y.Z' comment (or a docker:// digest): uses: $value"
		bad=$((bad + 1))
	done <"$tmp/uses"
done

if [ "$files" -eq 0 ]; then
	echo "check-action-pins: no workflow files in $dir" >&2
	exit 2
fi
if [ "$bad" -gt 0 ]; then
	echo "check-action-pins: $bad unpinned uses: line(s)."
	exit 1
fi
echo "check-action-pins: every uses: is pinned ($files workflow files)."
