#!/bin/sh
# Self-test for the secret scan (.gitleaks.toml, scripts/secret-scan-range.sh).
# Builds throwaway git repos in a temporary directory and runs gitleaks on
# them. No network. Run it with `make secrets-test`, which sets GITLEAKS to
# the pinned binary.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
gitleaks=${GITLEAKS:?set GITLEAKS to the gitleaks binary, or run make secrets-test}
config=$repo/.gitleaks.toml
range=$here/secret-scan-range.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Keep the user's and the system's git config (signing, hooks) out of it.
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM

# Fake GitHub tokens, assembled at runtime so that this file contains nothing
# a gitleaks rule matches. They are not real credentials.
p=ghp
fake=${p}_$(printf '%s' 'mQ7rT2vX9kL4pZ8wN3bY6cH1dF5gJ0sA' | tr 'a-zA-Z' 'n-za-mN-ZA-M')Qx4E
other=${p}_$(printf '%s' 'Vb3Nq8Lm2Ks7Jd1Hf6Gp4Rt9Wy0Zc5Xe' | tr 'a-zA-Z' 'n-za-mN-ZA-M')Tu8M
fail=0

# newrepo <dir>: an empty git repo.
newrepo() {
	git init -q -b main "$1"
}

# commit <dir> <file> <content>: commits one file and prints the commit SHA.
commit() {
	mkdir -p "$(dirname "$1/$2")"
	printf '%s\n' "$3" >"$1/$2"
	git -C "$1" add -- "$2"
	git -C "$1" -c user.name=test -c user.email=test@example.invalid \
		commit -q -m "add $2"
	git -C "$1" rev-parse HEAD
}

# expect <name> <0|1> <repo dir> <config> <log opts>: runs gitleaks in the repo
# (so no .gitleaksignore from this repository applies) and checks its exit
# code. The output must never contain a fake value (--redact).
expect() {
	name=$1 want=$2 dir=$3 cfg=$4 opts=$5
	rc=0
	out=$(cd "$dir" && "$gitleaks" git --redact --verbose --no-banner \
		--exit-code 1 --config "$cfg" --log-opts="$opts" . 2>&1) || rc=$?
	if [ "$rc" != "$want" ]; then
		echo "FAIL $name: exit $rc, want $want:" >&2
		printf '%s\n' "$out" >&2
		fail=1
	elif printf '%s\n' "$out" | grep -qF -e "$fake" -e "$other"; then
		echo "FAIL $name: output contains a fake value unredacted" >&2
		fail=1
	else
		echo "ok   $name"
	fi
}

# 1. A clean commit passes.
newrepo "$tmp/clean"
commit "$tmp/clean" README.md "nothing to see here" >/dev/null
expect "1 clean commit" 0 "$tmp/clean" "$config" ""

# 2. A commit with a fake credential fails.
newrepo "$tmp/dirty"
commit "$tmp/dirty" config.txt "token: $fake" >/dev/null
expect "2 fake credential" 1 "$tmp/dirty" "$config" ""

# 3. A narrow allowlist entry (path AND value) exempts exactly that fixture.
# The test config extends the repository config, so the production config
# gets no exemption just for this test.
cat >"$tmp/allow.toml" <<TOML
[extend]
path = "$config"

[[allowlists]]
description = "self-test fixture"
condition = "AND"
paths = ['''^testdata/fake-token\.txt$''']
regexes = ['''^$fake$''']
TOML
newrepo "$tmp/allowed"
commit "$tmp/allowed" testdata/fake-token.txt "$fake" >/dev/null
expect "3a fake value in the allowlisted fixture" 0 "$tmp/allowed" "$tmp/allow.toml" ""
newrepo "$tmp/elsewhere"
commit "$tmp/elsewhere" internal/x/fake-token.txt "$fake" >/dev/null
expect "3b same fake value in another path" 1 "$tmp/elsewhere" "$tmp/allow.toml" ""
newrepo "$tmp/othervalue"
commit "$tmp/othervalue" testdata/fake-token.txt "$other" >/dev/null
expect "3c other value in the allowlisted fixture" 1 "$tmp/othervalue" "$tmp/allow.toml" ""

# 4. A range A..B scans only the commits after A; a secret in A is not reported.
newrepo "$tmp/range"
a=$(commit "$tmp/range" config.txt "token: $fake")
b=$(commit "$tmp/range" README.md "clean follow-up")
expect "4a range A..B skips the secret in A" 0 "$tmp/range" "$config" "$a..$b"
expect "4b full history finds the secret in A" 1 "$tmp/range" "$config" ""
expect "4c -1 B (push fallback) scans only B" 0 "$tmp/range" "$config" "-1 $b"

# 5. secret-scan-range.sh picks the range for each event.
zero=0000000000000000000000000000000000000000
unknown=1111111111111111111111111111111111111111
# expect_range <name> <want stdout> <want stderr substring> <env...>
expect_range() {
	name=$1 want=$2 msg=$3
	shift 3
	rc=0
	got=$(cd "$tmp/range" && env "$@" sh "$range" 2>"$tmp/stderr") || rc=$?
	if [ "$rc" != 0 ] || [ "$got" != "$want" ]; then
		echo "FAIL $name: exit $rc, got '$got', want '$want': $(cat "$tmp/stderr")" >&2
		fail=1
	elif [ -n "$msg" ] && ! grep -qF -- "$msg" "$tmp/stderr"; then
		echo "FAIL $name: stderr lacks '$msg': $(cat "$tmp/stderr")" >&2
		fail=1
	else
		echo "ok   $name"
	fi
}
expect_range "5a pull request" "$a..$b" "" EVENT=pull_request BASE_SHA="$a" HEAD_SHA="$b"
expect_range "5b push" "$a..$b" "" EVENT=push BEFORE_SHA="$a" AFTER_SHA="$b"
expect_range "5c push without previous commit" "-1 $b" "no previous commit" EVENT=push BEFORE_SHA="$zero" AFTER_SHA="$b"
expect_range "5d push with unknown previous commit" "-1 $b" "not in the clone" EVENT=push BEFORE_SHA="$unknown" AFTER_SHA="$b"
rc=0
(cd "$tmp/range" && EVENT=push BEFORE_SHA="--all" AFTER_SHA="$b" sh "$range" >/dev/null 2>&1) || rc=$?
if [ "$rc" = 2 ]; then echo "ok   5e rejects a non-SHA"; else echo "FAIL 5e rejects a non-SHA: exit $rc" >&2; fail=1; fi

exit "$fail"
