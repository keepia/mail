#!/bin/sh
# Test 14 (#27): scripts/version-policy.sh with TSV fixtures, and the
# behaviour of the shared scripts/next-version.sh that the policy and the
# release workflow rely on (last, base, pr, next, summary). mail-archive's
# next-version-test.sh is not vendored: its last sections test
# mail-archive's own release scripts (docs/development/index.md, "Shared
# scripts"). No network.
#
# Usage: scripts/version-policy-test.sh
#   VERSION_POLICY=path  test another copy of the policy (counter-proofs)
set -eu

command -v jq > /dev/null || {
	echo "version-policy-test: jq is required" >&2
	exit 1
}
command -v git > /dev/null || {
	echo "version-policy-test: git is required" >&2
	exit 1
}

here=$(cd "$(dirname "$0")" && pwd)
policy=${VERSION_POLICY:-$here/version-policy.sh}
next=$here/next-version.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tab=$(printf '\t')
nl='
'
failed=0 passed=0

GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM

fail() {
	echo "FAIL $1: $2"
	failed=$((failed + 1))
}

# row NUMBER TITLE LABEL...: a line as `next-version.sh pr` prints it.
row() {
	r="$1$tab$2"
	shift 2
	for l in "$@"; do
		r="$r$tab$l"
	done
	printf '%s\n' "$r"
}

# ok NAME WANT RULE INPUT SCRIPT ARGS...: SCRIPT prints WANT, exits 0, and
# its stderr contains RULE ("" for no check).
ok() {
	name=$1 want=$2 rule=$3 input=$4 script=$5
	shift 5
	if got=$(printf '%s' "$input" | sh "$script" "$@" 2> "$tmp/err"); then
		if [ "$got" != "$want" ]; then
			fail "$name" "got '$got', want '$want'"
		elif [ -n "$rule" ] && ! grep -qF -- "$rule" "$tmp/err"; then
			fail "$name" "stderr '$(cat "$tmp/err")' lacks '$rule'"
		else
			passed=$((passed + 1))
		fi
	else
		fail "$name" "exit $?, want '$want': $(cat "$tmp/err")"
	fi
}

# bad NAME TEXT INPUT SCRIPT ARGS...: SCRIPT exits 2 with TEXT on stderr and
# prints nothing on stdout.
bad() {
	name=$1 text=$2 input=$3 script=$4
	shift 4
	set +e
	got=$(printf '%s' "$input" | sh "$script" "$@" 2> "$tmp/err")
	code=$?
	set -e
	if [ "$code" -ne 2 ]; then
		fail "$name" "exit $code, want 2 (stdout '$got')"
	elif [ -n "$got" ]; then
		fail "$name" "printed '$got' on failure"
	elif ! grep -qF -- "$text" "$tmp/err"; then
		fail "$name" "message '$(cat "$tmp/err")' lacks '$text'"
	else
		passed=$((passed + 1))
	fi
}

contains() {
	case $3 in
	*"$2"*) passed=$((passed + 1)) ;;
	*) fail "$1" "'$2' missing in: $3" ;;
	esac
}

sha=0123456789abcdef0123456789abcdef01234567
other=fedcba9876543210fedcba9876543210fedcba98
bug=$(row 10 "Fix" bug)
chore=$(row 11 "Chore" chore)
security=$(row 12 "Security" security)
feature=$(row 13 "Feature" feature)
breaking=$(row 14 "Breaking" breaking)
migration=$(row 15 "Schema" db-migration)
nopr="-$tab$sha$tab"

# --- test 14: version-policy.sh (plan section 5) --------------------------

first="first release 0.1.0"
ok "first: only bug PRs" 0.1.0 "$first" "$bug$nl$chore$nl" "$policy" "" ""
ok "first: with feature" 0.1.0 "$first" "$bug$nl$feature$nl" "$policy" "" ""
ok "first: with breaking" 0.1.0 "$first" "$breaking$nl$feature$nl" "$policy" "" ""
ok "first: with a commit without PR" 0.1.0 "$first" "$nopr$nl$bug$nl" "$policy" "" ""
ok "first: input 1.0.0" 1.0.0 "first release 1.0.0" "$bug$nl" "$policy" "" 1.0.0
ok "last 0.1.0: breaking" 0.2.0 "0.x: \`breaking\` raises the minor version: 0.2.0 (next-version.sh proposed 1.0.0)" "$breaking$nl$bug$nl" "$policy" 0.1.0 ""
ok "last 0.4.2: breaking" 0.5.0 "raises the minor version" "$breaking$nl" "$policy" 0.4.2 ""
ok "last 0.1.0: feature" 0.2.0 "0.x: 0.2.0, the proposal" "$feature$nl" "$policy" 0.1.0 ""
ok "last 0.1.0: db-migration" 0.2.0 "0.x: 0.2.0" "$migration$nl$bug$nl" "$policy" 0.1.0 ""
ok "last 0.1.0: bug only" 0.1.1 "0.x: 0.1.1" "$bug$nl" "$policy" 0.1.0 ""
ok "last 0.1.0: chore only" 0.1.1 "0.x: 0.1.1" "$chore$nl" "$policy" 0.1.0 ""
ok "last 0.1.0: security only" 0.1.1 "0.x: 0.1.1" "$security$nl" "$policy" 0.1.0 ""
ok "last 0.1.0: input 1.0.0" 1.0.0 "the version input 1.0.0" "$breaking$nl" "$policy" 0.1.0 1.0.0
ok "last 0.9.3: minor resets the patch, numeric" 0.10.0 "0.x: 0.10.0" "$feature$nl" "$policy" 0.9.3 ""
bad "last 0.1.0: input 0.1.0" "not greater than the last version 0.1.0" "$bug$nl" "$policy" 0.1.0 0.1.0
bad "last 0.1.0: input v0.2.0" "not X.Y.Z" "$bug$nl" "$policy" 0.1.0 v0.2.0
bad "first: input v0.1.0" "not X.Y.Z" "$bug$nl" "$policy" "" v0.1.0
bad "last 0.1.0: nothing merged" "nothing merged" "" "$policy" 0.1.0 ""
bad "first: nothing merged" "nothing merged" "" "$policy" "" ""
bad "last 0.1.0: commit without PR, no input" "commits without a merged pull request: $sha" "$bug$nl$nopr$nl" "$policy" 0.1.0 ""
bad "last 0.1.0: breaking, commit without PR" "commits without a merged pull request" "$breaking$nl$nopr$nl" "$policy" 0.1.0 ""
ok "last 1.2.3: breaking" 2.0.0 "2.0.0, the proposal of next-version.sh" "$breaking$nl" "$policy" 1.2.3 ""
ok "last 1.2.3: feature" 1.3.0 "" "$feature$nl" "$policy" 1.2.3 ""
bad "last not X.Y.Z" "last version is not X.Y.Z" "$bug$nl" "$policy" v0.1.0 ""
bad "usage" "usage" "$bug$nl" "$policy" 0.1.0

# Counter-proof: the approved plan's form (override 0.1.0 with an empty
# LAST) is what next-version.sh refuses, so the policy needs 0.0.0.
bad "counter-proof: next '' 0.1.0" "the first semver release must be at least 1.0.0" "$bug$nl" "$next" next "" 0.1.0
ok "counter-proof: next 0.0.0 0.1.0" 0.1.0 "" "$feature$nl" "$next" next 0.0.0 0.1.0

# --- next-version.sh: what the policy and release.yml rely on -------------

ok "next: bug gives patch" 1.2.4 "" "$bug$nl" "$next" next 1.2.3
ok "next: feature and bug give minor" 1.3.0 "" "$feature$nl$bug$nl" "$next" next 1.2.3
ok "next: db-migration gives minor" 1.3.0 "" "$migration$nl" "$next" next 1.2.3
ok "next: breaking gives major" 2.0.0 "" "$breaking$nl$feature$nl" "$next" next 1.2.3
ok "next: 'breaking change' is not breaking" 1.2.4 "" "$(row 18 "Spaced" "breaking change")$nl" "$next" next 1.2.3
ok "next: override below the proposal warns" 1.2.4 "lower than the proposal 1.3.0" "$feature$nl" "$next" next 1.2.3 1.2.4
bad "next: malformed line" "not a pull request line" "abc${tab}x$nl" "$next" next 1.2.3
bad "next: override with a newline" "not X.Y.Z" "$bug$nl" "$next" next 1.2.3 "1.2.4${nl}x"

# last and base, in a temporary repository.
repo=$tmp/repo
git init -q "$repo"
cd "$repo"
git -c user.name=test -c user.email=test@example.org -c commit.gpgsign=false commit -q --allow-empty -m tags
ok "last: no tags" "" "" "" "$next" last
ok "base: no tags" "" "" "" "$next" base
git tag v1.0.0-rc1
git tag v01.0.0
git tag v0.9.0
git tag v0.10.0
git tag v0.9.10
ok "last: numeric, malformed ignored" 0.10.0 "" "" "$next" last
ok "base: the last tag" v0.10.0 "" "" "$next" base
cd "$tmp"

# pr, with API response fixtures.
pull() {
	jq -n --arg sha "$1" --argjson n "$2" --argjson merged "$3" --arg base "$4" --argjson labels "$5" \
		'{number: $n, title: ("Title " + ($n | tostring)), merged_at: $merged, merge_commit_sha: $sha,
		  base: {ref: $base}, labels: [$labels[] | {name: .}]}'
}
merged='"2026-10-23T12:00:00Z"'
ok "pr: merged into main" "$(row 21 "Title 21" bug feature)" "" "[$(pull $sha 21 "$merged" main '["bug","feature"]')]" "$next" pr $sha
ok "pr: not merged" "$nopr" "" "[$(pull $sha 5 null main '["feature"]')]" "$next" pr $sha
ok "pr: other merge commit" "$nopr" "" "[$(pull $other 5 "$merged" main '["feature"]')]" "$next" pr $sha
bad "pr: API error object" "not a JSON array" '{"message":"Not Found"}' "$next" pr $sha
bad "pr: empty input" "no API response" "" "$next" pr $sha

# summary.
s=$(printf '%s\n' "$breaking" "$nopr" | sh "$next" summary)
contains "summary: header" "| PR | Title | Labels | Effect |" "$s"
contains "summary: breaking" "| #14 | Breaking | \`breaking\` | major |" "$s"
contains "summary: commit without PR" "| - | $sha | | commit without pull request: set \`version\` |" "$s"

echo "version-policy-test: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
