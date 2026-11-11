#!/bin/sh
# Prints the `git log` options for the secret-scan CI check: the commits a
# pull request adds, or the commits a push to main adds. Reads the SHAs from
# the environment (set by .github/workflows/secrets.yml):
#   EVENT=pull_request  BASE_SHA, HEAD_SHA  ->  BASE_SHA..HEAD_SHA
#   EVENT=push          BEFORE_SHA, AFTER_SHA -> BEFORE_SHA..AFTER_SHA
# A push whose BEFORE_SHA is all zeros (new branch) or not in the clone (for
# example after a force push) scans only AFTER_SHA, with a message on stderr.
# Run it inside the git checkout.
set -eu

# sha <name> <value>: fails unless value is a full hex commit SHA.
sha() {
	case $2 in
	'' | *[!0-9a-f]*)
		echo "secret-scan-range: $1 is not a commit SHA: '$2'" >&2
		exit 2
		;;
	esac
	if [ "${#2}" -ne 40 ] && [ "${#2}" -ne 64 ]; then
		echo "secret-scan-range: $1 is not a commit SHA: '$2'" >&2
		exit 2
	fi
}

case ${EVENT:-} in
pull_request)
	sha BASE_SHA "${BASE_SHA:-}"
	sha HEAD_SHA "${HEAD_SHA:-}"
	echo "$BASE_SHA..$HEAD_SHA"
	;;
push)
	sha BEFORE_SHA "${BEFORE_SHA:-}"
	sha AFTER_SHA "${AFTER_SHA:-}"
	case $BEFORE_SHA in
	*[!0]*)
		if git cat-file -e "$BEFORE_SHA^{commit}" 2>/dev/null; then
			echo "$BEFORE_SHA..$AFTER_SHA"
		else
			echo "secret-scan-range: previous commit $BEFORE_SHA is not in the clone (force push?); scanning only $AFTER_SHA" >&2
			echo "-1 $AFTER_SHA"
		fi
		;;
	*)
		echo "secret-scan-range: push has no previous commit; scanning only $AFTER_SHA" >&2
		echo "-1 $AFTER_SHA"
		;;
	esac
	;;
*)
	echo "secret-scan-range: unsupported EVENT '${EVENT:-}' (want pull_request or push)" >&2
	exit 2
	;;
esac
