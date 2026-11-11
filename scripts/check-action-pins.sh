#!/bin/sh
# Checks that every `uses:` in the workflows is pinned:
# - an action or reusable workflow: owner/repo[/path]@<full 40-hex commit SHA>
#   followed by a version comment, `# vX.Y.Z` (Dependabot keeps both current);
# - a local action (./path) is allowed as is;
# - a Docker action: docker://image@sha256:<64 hex>.
# Anything else (a tag, a branch, a short SHA, a SHA without the version
# comment, a docker:// image without a digest) is reported.
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

pinned='^["'\'']?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@[:space:]"'\'']+)?@[0-9a-f]{40}["'\'']?[[:space:]]+#[[:space:]]*v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)'
local_action='^["'\'']?\./'
docker='^["'\'']?docker://[^@[:space:]"'\'']+@sha256:[0-9a-f]{64}["'\'']?([[:space:]]|$)'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bad=0
files=0
for f in "$dir"/*.yml "$dir"/*.yaml; do
	[ -f "$f" ] || continue
	files=$((files + 1))
	# Each `uses:` line, with its line number; `- uses:` included.
	grep -n -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$f" >"$tmp/uses" || true
	while IFS= read -r line; do
		n=${line%%:*}
		value=$(printf '%s\n' "${line#*:}" | sed -E 's/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//')
		if printf '%s\n' "$value" | grep -qE -e "$pinned" -e "$local_action" -e "$docker"; then
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
