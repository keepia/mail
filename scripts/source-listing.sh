#!/bin/bash
# source-listing.sh: writes the listing of a git tree that
# images/common/check-source computes from the unpacked archive (#55): one
# line per file or directory, sorted by path in the C locale, from a clone,
# never from a download.
#
#   f 644 <sha256> <path>   a blob (100644)
#   f 755 <sha256> <path>   an executable blob (100755)
#   d 755 - <path>          a tree, or a submodule (GitHub's archive holds
#                           an empty directory for it)
#
# A symlink, any other mode, or a path with a newline or a backslash fails.
# The archive equals the tree only without export-ignore or export-subst in
# .gitattributes; check-source fails closed otherwise.
#
# Usage: scripts/source-listing.sh GIT-DIR REV
# For a manifest's "listing" line: the listing's sha256sum and its wc -l.
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: $0 GIT-DIR REV" >&2
	exit 2
fi
git_dir=$1 rev=$2

git --git-dir="$git_dir" ls-tree -r -t -z "$rev" |
	while IFS= read -r -d '' entry; do
		meta=${entry%%$'\t'*}
		path=${entry#*$'\t'}
		case $path in
		*$'\n'* | *\\*)
			echo "source-listing: unsupported path name: ${path@Q}" >&2
			exit 1
			;;
		esac
		read -r mode _ object <<<"$meta"
		case $mode in
		040000 | 160000) echo "d 755 - $path" ;;
		100644 | 100755)
			sum=$(git --git-dir="$git_dir" cat-file blob "$object" | sha256sum)
			echo "f ${mode#100} ${sum%% *} $path"
			;;
		*)
			echo "source-listing: unsupported mode $mode: $path" >&2
			exit 1
			;;
		esac
	done |
	LC_ALL=C sort -t ' ' -k4
