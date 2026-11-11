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
# (`- {uses: x}`, `steps: [{uses: x}]`); in flow style the version comment
# goes at the end of the line. Only full-line comments are skipped, so the
# check fails closed: a `uses:` inside a run: script line is checked too.
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

# The value of a `uses` key, quotes removed, and the rest of its line.
action='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@[:space:]]+)?@[0-9a-f]{40}$'
version_comment='#[[:space:]]*v[0-9]+\.[0-9]+\.[0-9]+([^0-9.]|$)'
local_action='^\./'
docker='^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$'

# uses_of <file>: one line per `uses` key: line number, value and the rest of
# the line, separated by tabs. The value ends at whitespace, `,`, `}` or `]`.
# Value and rest start with `=`, so that an empty value stays a field.
uses_of() {
	awk -v q="'" '
	BEGIN { key = "(^|[ \t{,])[\"" q "]?uses[\"" q "]?[ \t]*:" }
	/^[ \t]*#/ { next }
	{
		rest = $0
		while (match(rest, key)) {
			rest = substr(rest, RSTART + RLENGTH)
			sub(/^[ \t]*/, "", rest)
			match(rest, /^[^] \t,}]*/)
			value = substr(rest, 1, RLENGTH)
			rest = substr(rest, RLENGTH + 1)
			gsub(/["\047]/, "", value)
			printf "%d\t=%s\t=%s\n", NR, value, rest
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
	while IFS="$tab" read -r n value rest; do
		value=${value#=} rest=${rest#=}
		if printf '%s\n' "$value" | grep -qE -e "$local_action" -e "$docker"; then
			continue
		fi
		if printf '%s\n' "$value" | grep -qE "$action" &&
			printf '%s\n' "$rest" | grep -qE "$version_comment"; then
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
