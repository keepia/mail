#!/bin/sh
# The version rules of Keepia Mail before 1.0.0 (#5 decision Q2, #27 plan
# section 5), over the shared scripts/next-version.sh (byte-identical with
# pklnx/mail-archive, which has no 0.x rules). It prints the version on
# stdout and one line on stderr that names the rule that applied, for the
# release summary.
#
# Usage: scripts/version-policy.sh LAST INPUT < prs.tsv
#   LAST   the last release X.Y.Z (next-version.sh last); empty before the
#          first release
#   INPUT  the workflow's version input; empty for none
#   prs.tsv the lines of `next-version.sh pr` for every commit since LAST
#
# The rules:
#   - First release (LAST empty): next-version.sh next 0.0.0 "${INPUT:-0.1.0}".
#     next-version.sh's own first-release floor of 1.0.0 applies only to an
#     empty LAST, so a virtual last version 0.0.0 lets it check 0.1.0 as
#     X.Y.Z and greater than the last version. Commits without a pull
#     request (the history before the process) are allowed here only,
#     because an override is set.
#   - 0.x (LAST 0.y.z, no INPUT): the proposal of next-version.sh, except
#     that a `breaking` pull request (a major proposal) raises the minor
#     version: 0.(y+1).0.
#   - INPUT given, or LAST 1.0.0 or later: next-version.sh unchanged. 1.0.0
#     comes only through INPUT, with the maintainer's OK.
#
# Errors exit 2 (next-version.sh's codes and messages pass through).
set -eu

if [ $# -ne 2 ]; then
	echo "usage: version-policy.sh LAST INPUT < prs.tsv" >&2
	exit 2
fi
last=$1 input=$2
here=$(cd "$(dirname "$0")" && pwd)
next="$here/next-version.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The 0.x path reads the lines twice: buffer stdin once.
cat > "$tmp/prs.tsv"

# run LAST OVERRIDE: next-version.sh next; its stderr is kept in err.
run() {
	if sh "$next" next "$1" "$2" < "$tmp/prs.tsv" > "$tmp/out" 2> "$tmp/err"; then
		return 0
	else
		rc=$?
		cat "$tmp/err" >&2
		exit "$rc"
	fi
}

# lower_warning_only: next-version.sh wrote nothing to stderr but its
# "lower than the proposal" warning, which the 0.x rules expect.
lower_warning_only() {
	! grep -qv 'warning: version .* is lower than the proposal' "$tmp/err"
}

if [ -z "$last" ]; then
	version=${input:-0.1.0}
	run 0.0.0 "$version"
	if lower_warning_only; then
		echo "version-policy: first release $(cat "$tmp/out") (a virtual last version 0.0.0 lets next-version.sh check it; commits without a pull request are allowed only here)" >&2
	else
		cat "$tmp/err" >&2
	fi
	cat "$tmp/out"
	exit 0
fi

case $last in
0.*)
	if [ -z "$input" ]; then
		run "$last" ""
		proposal=$(cat "$tmp/out")
		if [ "${proposal%%.*}" -ge 1 ]; then
			minor=${last#0.}
			minor=${minor%%.*}
			run "$last" "0.$((minor + 1)).0"
			if lower_warning_only; then
				echo "version-policy: 0.x: \`breaking\` raises the minor version: $(cat "$tmp/out") (next-version.sh proposed $proposal)" >&2
			else
				cat "$tmp/err" >&2
			fi
		else
			cat "$tmp/err" >&2
			echo "version-policy: 0.x: $proposal, the proposal of next-version.sh" >&2
		fi
		cat "$tmp/out"
		exit 0
	fi
	;;
esac

run "$last" "$input"
cat "$tmp/err" >&2
if [ -n "$input" ]; then
	echo "version-policy: the version input $(cat "$tmp/out") (next-version.sh checked it)" >&2
else
	echo "version-policy: $(cat "$tmp/out"), the proposal of next-version.sh" >&2
fi
cat "$tmp/out"
