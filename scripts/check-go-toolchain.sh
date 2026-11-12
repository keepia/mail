#!/bin/sh
# Fails if the Go toolchain in use differs from the one go.mod asks for: the
# `toolchain goX.Y.Z` line, or the `go` line when there is none. The Dockerfile
# runs this in the build stage so the pinned golang image tag cannot drift from
# go.mod. It also runs on hosts: in the CI lint job (through
# check-go-toolchain-test.sh) and when a developer runs it locally.
#
# Usage: scripts/check-go-toolchain.sh [go.mod]   (default: ./go.mod)
set -eu

gomod=${1:-go.mod}

# First field after the keyword; tolerates CRLF, extra spaces and // comments.
field() {
	tr -d '\r' <"$gomod" | awk -v kw="$1" '$1 == kw { print $2; exit }'
}

want=$(field toolchain)
if [ -z "$want" ]; then
	want=$(field go)
	[ -n "$want" ] && want="go$want"
fi
if [ -z "$want" ]; then
	echo "check-go-toolchain: no toolchain or go line in $gomod" >&2
	exit 1
fi

# Run outside any module and without toolchain switching, so the result only
# reflects the installed Go and never a go.mod or a download.
have=$(cd / && GOTOOLCHAIN=local go env GOVERSION)
have=${have%% *}

if [ "$have" != "$want" ]; then
	echo "Go toolchain is $have, go.mod requires $want: update the golang tag in the Dockerfile (image build) or your local Go (host)" >&2
	exit 1
fi
echo "Go toolchain $have matches $gomod"
