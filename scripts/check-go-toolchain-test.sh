#!/bin/sh
# Tests scripts/check-go-toolchain.sh. No network: the script runs go with
# GOTOOLCHAIN=local outside any module. Needs `go` on PATH.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
script=$here/check-go-toolchain.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

have=$(cd / && GOTOOLCHAIN=local go env GOVERSION)
have=${have%% *}
fail=0

# expect <name> <0|1> <message-substring> <go.mod path>
expect() {
	name=$1 code=$2 msg=$3 file=$4
	rc=0
	out=$(sh "$script" "$file" 2>&1) || rc=$?
	if [ "$rc" != "$code" ]; then
		echo "FAIL $name: exit $rc, want $code: $out" >&2
		fail=1
	elif [ -n "$msg" ] && ! printf '%s\n' "$out" | grep -qF -- "$msg"; then
		echo "FAIL $name: message lacks '$msg': $out" >&2
		fail=1
	else
		echo "ok   $name"
	fi
}

# Full mismatch message per case (expect takes one substring).
remedy1="Go toolchain is $have, go.mod requires go1.0.0: update the golang tag in the Dockerfile (image build) or your local Go (host)"
remedy2="Go toolchain is $have, go.mod requires go1.20: update the golang tag in the Dockerfile (image build) or your local Go (host)"

mk() { printf '%b' "$2" >"$tmp/$1"; }

expect "real go.mod" 0 "matches" "$repo/go.mod"
mk toolchain-old 'module x\n\ngo 1.20\n\ntoolchain go1.0.0\n'
expect "wrong toolchain line" 1 "$remedy1" "$tmp/toolchain-old"
mk go-only-old 'module x\n\ngo 1.20\n'
expect "no toolchain line, wrong go line" 1 "$remedy2" "$tmp/go-only-old"
mk match "module x\n\ngo 1.20\n\ntoolchain $have\n"
expect "matching toolchain line" 0 "matches" "$tmp/match"
mk crlf "module x\r\n\r\ngo 1.20\r\n\r\ntoolchain $have\r\n"
expect "CRLF line endings" 0 "matches" "$tmp/crlf"
mk comment "module x\n\ngo 1.20\n\ntoolchain   $have   // pinned\n"
expect "spaces and trailing comment" 0 "matches" "$tmp/comment"
mk go-only-match "module x\n\ngo ${have#go}  \n"
expect "go line only, matching" 0 "matches" "$tmp/go-only-match"
mk none 'module x\n'
expect "no go or toolchain line" 1 "no toolchain or go line" "$tmp/none"

exit "$fail"
