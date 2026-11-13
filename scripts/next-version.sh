#!/bin/sh
# Semantic versioning for releases (X.Y.Z). The version follows the labels of
# the pull requests merged into main since the last release: any `breaking`
# pull request makes a major release, else any `feature` or `db-migration`
# pull request a minor release, else a patch release. The first semver
# release, with no vX.Y.Z tag yet, is 1.0.0.
#
# The script makes no network calls: the release workflow lists the commits,
# fetches each commit's pull requests from the GitHub API and pipes the
# responses through `pr`. It uses POSIX sh, git (for `last` and `base`) and
# jq (for `pr`).
#
# Usage:
#   scripts/next-version.sh last
#       The highest X.Y.Z of the tags vX.Y.Z; nothing if there is none.
#       Old vYY.MM-N tags never match.
#   scripts/next-version.sh base
#       The tag the release range and the notes start from: v$(last), else
#       the highest vYY.MM-N tag, else nothing (the whole history).
#   scripts/next-version.sh pr SHA < pulls.json
#       Reads the JSON array of GET repos/{repo}/commits/{SHA}/pulls and
#       prints NUMBER<TAB>TITLE<TAB>LABEL... for each pull request merged into
#       main by the commit SHA, or -<TAB>SHA<TAB> if there is none.
#   scripts/next-version.sh next LAST [OVERRIDE] < prs.tsv
#       The next version after LAST (empty for the first semver release),
#       from the lines of `pr`. OVERRIDE (X.Y.Z, greater than LAST) replaces
#       the proposal; an empty OVERRIDE means none. An OVERRIDE below the
#       proposal prints a warning on stderr (exit 0).
#   scripts/next-version.sh summary < prs.tsv
#       A Markdown table of the pull requests, their labels and their effect.
#
# Errors exit 2 with a message on stderr.
set -eu

semver_tag='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
old_tag='^v[0-9]{2}\.[0-1][0-9]-[1-9][0-9]*$'
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
# Labels that say what kind of change a pull request is. A row without one
# gets a warning in the summary; the version does not depend on it.
kinds='breaking feature bug chore docs dependencies security'
tab=$(printf '\t')

die() {
	echo "next-version: $*" >&2
	exit 2
}

# is_semver V: V is X.Y.Z without a v, leading zeros or a suffix. The case
# rejects newlines, which grep would treat as separate lines.
is_semver() {
	case $1 in
	'' | *[!0-9.]*) return 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eq "$semver"
}

# gt A B: version A is greater than version B, field by field as numbers.
gt() {
	a1=${1%%.*} a3=${1##*.} a2=${1#*.} b1=${2%%.*} b3=${2##*.} b2=${2#*.}
	a2=${a2%.*} b2=${b2%.*}
	[ "$a1" -ne "$b1" ] && { [ "$a1" -gt "$b1" ]; return; }
	[ "$a2" -ne "$b2" ] && { [ "$a2" -gt "$b2" ]; return; }
	[ "$a3" -gt "$b3" ]
}

tags() {
	git tag -l 'v*'
}

cmd_last() {
	all=$(tags)
	printf '%s\n' "$all" | grep -E "$semver_tag" | sed 's/^v//' |
		sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1
}

cmd_base() {
	last=$(cmd_last)
	if [ -n "$last" ]; then
		echo "v$last"
		return
	fi
	all=$(tags)
	# vYY.MM-N → "YY MM N tag", numeric order on YY, MM and N.
	printf '%s\n' "$all" | grep -E "$old_tag" |
		sed 's/^v\([0-9]*\)\.\([0-9]*\)-\([0-9]*\)$/\1 \2 \3 &/' |
		sort -k1,1n -k2,2n -k3,3n | tail -n 1 | cut -d' ' -f4
}

cmd_pr() {
	sha=${1:-}
	[ -n "$sha" ] || die "usage: next-version.sh pr SHA < pulls.json"
	command -v jq > /dev/null || die "jq is required"
	json=$(cat)
	case $json in
	*[![:space:]]*) ;;
	*) die "no API response for commit $sha" ;;
	esac
	if ! printf '%s\n' "$json" | jq -e 'type == "array"' > /dev/null 2>&1; then
		die "API response for commit $sha is not a JSON array: $(printf '%.200s' "$json")"
	fi
	printf '%s\n' "$json" | jq -r --arg sha "$sha" '
		[.[] | select(.merged_at != null and .base.ref == "main" and .merge_commit_sha == $sha)]
		| if length == 0 then "-\t" + $sha + "\t"
		  else .[] | [(.number | tostring), (.title // "" | gsub("[\t\r\n]"; " "))]
			+ [(.labels // [])[] | (.name // "") | gsub("[\t\r\n]"; " ")] | join("\t")
		  end'
}

# effect LINE: major, minor or patch for a line of `pr`, or unknown for a
# commit without a pull request. Labels match whole fields only.
effect() {
	eff_number=${1%%"$tab"*}
	if [ "$eff_number" = - ]; then
		echo unknown
		return
	fi
	if has_label "$1" breaking; then
		echo major
	elif has_label "$1" feature || has_label "$1" db-migration; then
		echo minor
	else
		echo patch
	fi
}

# has_label LINE LABEL: LABEL is one of the label fields (after number and
# title) of LINE. The helpers use their own variable names (sh has no local).
has_label() {
	hl_fields="$1$tab"
	hl_fields=${hl_fields#*"$tab"}
	hl_fields=$tab${hl_fields#*"$tab"}
	case $hl_fields in
	*"$tab$2$tab"*) return 0 ;;
	esac
	return 1
}

# check_line LINE: the line is a `pr` line: a pull request number or -.
check_line() {
	case ${1%%"$tab"*} in
	-) ;;
	'' | 0* | *[!0-9]*) die "not a pull request line: $1" ;;
	esac
}

cmd_next() {
	[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: next-version.sh next LAST [OVERRIDE] < prs.tsv"
	last=$1
	override=${2:-}
	if [ -n "$last" ] && ! is_semver "$last"; then
		die "last version is not X.Y.Z: $last"
	fi
	if [ -n "$override" ] && ! is_semver "$override"; then
		die "version input is not X.Y.Z (no v, no leading zeros, no suffix): $override"
	fi

	rank=0 lines=0 without=
	while IFS= read -r line || [ -n "$line" ]; do
		[ -n "$line" ] || continue
		check_line "$line"
		lines=$((lines + 1))
		case $(effect "$line") in
		major) rank=3 ;;
		minor) [ "$rank" -ge 2 ] || rank=2 ;;
		patch) [ "$rank" -ge 1 ] || rank=1 ;;
		unknown)
			sha=${line#-"$tab"}
			without="$without ${sha%%"$tab"*}"
			;;
		esac
	done

	if [ "$lines" -eq 0 ]; then
		die "nothing merged since ${last:-the last release}; there is nothing to release"
	fi
	if [ -n "$without" ] && [ -z "$override" ]; then
		die "commits without a merged pull request:$without; check them and set the version input"
	fi

	if [ -n "$without" ]; then
		proposal=
	elif [ -z "$last" ]; then
		proposal=1.0.0
	else
		major=${last%%.*} patch=${last##*.} minor=${last#*.}
		minor=${minor%.*}
		case $rank in
		3) proposal="$((major + 1)).0.0" ;;
		2) proposal="$major.$((minor + 1)).0" ;;
		*) proposal="$major.$minor.$((patch + 1))" ;;
		esac
	fi

	if [ -z "$override" ]; then
		echo "$proposal"
		return
	fi
	if [ -z "$last" ]; then
		[ "${override%%.*}" -ge 1 ] || die "the first semver release must be at least 1.0.0, not $override"
	else
		gt "$override" "$last" || die "version $override is not greater than the last version $last"
	fi
	if [ -n "$proposal" ] && gt "$proposal" "$override"; then
		echo "next-version: warning: version $override is lower than the proposal $proposal" >&2
	fi
	echo "$override"
}

# md TEXT: TEXT for a Markdown table cell.
md() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/|/\\|/g'
}

cmd_summary() {
	echo "| PR | Title | Labels | Effect |"
	echo "|---|---|---|---|"
	while IFS= read -r line || [ -n "$line" ]; do
		[ -n "$line" ] || continue
		check_line "$line"
		rest="$line$tab"
		number=${rest%%"$tab"*}
		rest=${rest#*"$tab"}
		title=${rest%%"$tab"*}
		rest=${rest#*"$tab"}
		eff=$(effect "$line")
		if [ "$eff" = unknown ]; then
			# shellcheck disable=SC2016 # literal backticks: Markdown code
			printf '| - | %s | | commit without pull request: set `version` |\n' "$(md "$title")"
			continue
		fi
		labels=
		while [ -n "$rest" ]; do
			label=${rest%%"$tab"*}
			rest=${rest#*"$tab"}
			labels="$labels${labels:+, }\`$label\`"
		done
		kind=
		for k in $kinds; do
			if has_label "$line" "$k"; then
				kind=yes
				break
			fi
		done
		[ -n "$kind" ] || eff="$eff, no kind label"
		printf '| #%s | %s | %s | %s |\n' "$number" "$(md "$title")" "$(md "$labels")" "$eff"
	done
}

cmd=${1:-}
[ $# -eq 0 ] || shift
case $cmd in
last) cmd_last ;;
base) cmd_base ;;
pr) cmd_pr "$@" ;;
next) cmd_next "$@" ;;
summary) cmd_summary ;;
*) die "usage: next-version.sh last|base|pr SHA|next LAST [OVERRIDE]|summary" ;;
esac
