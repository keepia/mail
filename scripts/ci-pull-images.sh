#!/bin/sh
# CI only: pulls the images the Compose smoke test needs, with retries, so a
# brief registry error does not fail the job. With scripts/ci-docker-mirror.sh
# run first, each pull goes through mirror.gcr.io with Docker Hub as the
# fallback. The build then takes its base images from the local store.
#
# The images come from the files themselves, so the list stays current:
# - the Dockerfile's `# syntax=` frontend and its FROM images (flags such as
#   --platform and the AS name dropped; a FROM that names an earlier stage,
#   such as `FROM build AS test`, is skipped);
# - every `image:` in docker-compose.yml without a variable (an image with a
#   variable, ${MAIL_ARCHIVE_IMAGE:-…}, is the one Compose builds).
# It fails when it finds no image or a FROM it cannot read (a variable, a line
# continuation), so a new Dockerfile form does not slip by silently.
#
# Usage: scripts/ci-pull-images.sh [--list]   (--list prints the images only)
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)

list_only=false
case ${1:-} in
--list) list_only=true ;;
"") ;;
*)
	echo "usage: $0 [--list]" >&2
	exit 2
	;;
esac

dockerfile_images() {
	awk '
		function fail(msg) { print FILENAME ":" FNR ": " msg > "/dev/stderr"; bad = 1; exit 1 }
		# Parser directives: comments before the first instruction.
		!started && /^#[ \t]*syntax[ \t]*=/ {
			line = $0
			sub(/^#[ \t]*syntax[ \t]*=[ \t]*/, "", line)
			sub(/[ \t]+$/, "", line)
			if (line == "") fail("empty syntax directive")
			print line
			next
		}
		/^[ \t]*(#|$)/ { next }
		{ started = 1 }
		toupper($1) == "FROM" {
			if ($0 ~ /\\[ \t]*$/) fail("FROM continues on the next line")
			image = ""
			for (i = 2; i <= NF; i++) {
				if ($i ~ /^--/) continue
				image = $i
				if (toupper($(i + 1)) == "AS") stage = tolower($(i + 2))
				else stage = ""
				break
			}
			if (image == "") fail("FROM without an image")
			if (image ~ /[$\\]/) fail("cannot read FROM image " image)
			if (!(tolower(image) in stages)) print image
			if (stage != "") stages[stage] = 1
		}
		END { if (bad) exit 1 }
	' "$repo/Dockerfile"
}

compose_images() {
	awk '
		/^[ \t]+image:[ \t]*/ {
			image = $0
			sub(/^[ \t]+image:[ \t]*/, "", image)
			sub(/[ \t]+#.*$/, "", image)
			gsub(/["\047]/, "", image)
			if (image != "" && image !~ /\$/) print image
		}
	' "$repo/docker-compose.yml"
}

# Separate substitutions, so a failing parse stops the script (set -e).
from_dockerfile=$(dockerfile_images)
from_compose=$(compose_images)
images=$(printf '%s\n%s\n' "$from_dockerfile" "$from_compose" | awk 'NF && !seen[$0]++')
if [ -z "$images" ]; then
	echo "no images found in the Dockerfile and docker-compose.yml" >&2
	exit 1
fi

echo "images:"
# shellcheck disable=SC2086 # one image per word
printf '  %s\n' $images
if $list_only; then
	exit 0
fi

# shellcheck disable=SC2086 # one image per word
for image in $images; do
	attempt=1
	until docker pull --quiet "$image"; do
		if [ "$attempt" -ge 3 ]; then
			echo "pulling $image failed $attempt times" >&2
			exit 1
		fi
		# A short backoff before the next attempt (a CI script, not a test).
		sleep $((attempt * 10))
		attempt=$((attempt + 1))
	done
done
