#!/bin/sh
# Self-test for scripts/check-action-pins.sh. Runs the check on each fixture
# of scripts/testdata/check-action-pins/ alone, in its own temporary
# directory: pass-*.yml must pass, fail-*.yml must fail and name the line.
# No network. Run it with `make workflows-test`.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
check=$here/check-action-pins.sh
fixtures=$here/testdata/check-action-pins
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
cases=0

for f in "$fixtures"/*.yml; do
	name=$(basename "$f" .yml)
	case $name in
	pass-*) want=0 ;;
	fail-*) want=1 ;;
	*)
		echo "FAIL $name: fixture name must start with pass- or fail-" >&2
		fail=1
		continue
		;;
	esac
	cases=$((cases + 1))
	mkdir "$tmp/$name"
	cp "$f" "$tmp/$name/"
	rc=0
	out=$(sh "$check" "$tmp/$name" 2>&1) || rc=$?
	if [ "$rc" != "$want" ]; then
		echo "FAIL $name: exit $rc, want $want:" >&2
		printf '%s\n' "$out" >&2
		fail=1
	elif [ "$want" = 1 ] && ! printf '%s\n' "$out" | grep -qF "$name.yml:"; then
		echo "FAIL $name: report does not name the file and line:" >&2
		printf '%s\n' "$out" >&2
		fail=1
	else
		echo "ok   $name"
	fi
done

# An empty directory is a usage error, not a pass.
mkdir "$tmp/empty"
rc=0
sh "$check" "$tmp/empty" >/dev/null 2>&1 || rc=$?
if [ "$rc" = 2 ]; then echo "ok   empty directory"; else echo "FAIL empty directory: exit $rc, want 2" >&2; fail=1; fi

if [ "$cases" -lt 9 ]; then
	echo "FAIL only $cases fixtures found, want 9" >&2
	fail=1
fi
exit "$fail"
