#!/bin/sh
# Self-test for scripts/check-links.sh. Copies each fixture of
# scripts/testdata/check-links/ into its own throwaway git repo in a temporary
# directory and checks the exit code and the report. No network. Run it with
# `make links-test`.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
check=$here/check-links.sh
fixtures=$here/testdata/check-links
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Keep the user's and the system's git config out of it.
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM
fail=0

# expect <case> <want exit> <want output substring, or empty>
expect() {
	name=$1 want=$2 msg=$3
	cp -R "$fixtures/$name" "$tmp/$name"
	git init -q "$tmp/$name"
	rc=0
	out=$(sh "$check" "$tmp/$name" 2>&1) || rc=$?
	if [ "$rc" != "$want" ]; then
		echo "FAIL $name: exit $rc, want $want:" >&2
		printf '%s\n' "$out" >&2
		fail=1
	elif [ -n "$msg" ] && ! printf '%s\n' "$out" | grep -qF -- "$msg"; then
		echo "FAIL $name: output lacks '$msg':" >&2
		printf '%s\n' "$out" >&2
		fail=1
	else
		echo "ok   $name"
	fi
}

# Links to files, headings, directories, the root and an external URL resolve.
expect good 0 ""
# A link to a file that does not exist fails.
expect missing-file 1 "missing target 'docs/nope.md'"
# A link to a heading that does not exist fails.
expect missing-anchor 1 "no heading '#no-such-heading' in 'guide.md'"
# Links inside inline code and fenced code blocks are ignored.
expect code-block 0 ""
# ../ resolves relative to the linking file's directory.
expect parent-dir 0 ""
# A link that leaves the repository fails.
expect outside-root 1 "outside the repository"
# Heading slugs are lowercase.
expect uppercase-heading 0 ""

exit "$fail"
