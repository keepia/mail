#!/bin/sh
# Self-test for images/common/check-source and scripts/source-listing.sh
# (#44, #25, #55). Makes a git repository with an executable file, a path
# with a space, nested directories and a submodule, writes its listing with
# source-listing.sh (the listing and the digest form of the manifest), and
# runs check-source with dash, as the images do, on `git archive` of it and
# on archives changed with tar. No network. Run it with
# `make image-scripts-test`.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
# CHECK_SOURCE: another copy of check-source (a counter-proof).
check=${CHECK_SOURCE:-$here/../images/common/check-source}
listing=$here/source-listing.sh
shell=$(command -v dash || command -v sh)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM
fail=0

# The upstream repository.
repo=$tmp/repo
mkdir -p "$repo/src/sub" "$repo/docs"
echo "readme" >"$repo/README"
printf '#!/bin/sh\necho configured\n' >"$repo/configure"
echo "int a;" >"$repo/src/a b.c"
echo "x" >"$repo/src/sub/x.txt"
echo "doc" >"$repo/docs/index.md"
git -C "$repo" init -q
git -C "$repo" add .
# configure as an executable blob, and a submodule (gitlink).
git -C "$repo" update-index --cacheinfo "100755,$(git -C "$repo" hash-object -w configure),configure"
git -C "$repo" update-index --add --cacheinfo 160000,1111111111111111111111111111111111111111,ext/mod
git -C "$repo" -c user.name=test -c user.email=test@example.org commit -q -m fixture

bash "$listing" "$repo/.git" HEAD >"$tmp/listing"
{
	echo "# the fixture's listing"
	cat "$tmp/listing"
} >"$tmp/manifest-listing"
{
	echo "# the fixture's digest"
	echo "listing $(sha256sum <"$tmp/listing" | cut -d' ' -f1) $(wc -l <"$tmp/listing")"
} >"$tmp/manifest-digest"

# The listing names every entry of the tree with its mode.
for want in "f 755 " "d 755 - ext/mod" "d 755 - src/sub" " src/a b.c"; do
	if ! grep -qF -- "$want" "$tmp/listing"; then
		echo "FAIL source-listing: no line with '$want':" >&2
		cat "$tmp/listing" >&2
		fail=1
	fi
done
if [ "$(wc -l <"$tmp/listing")" != 10 ]; then
	echo "FAIL source-listing: $(wc -l <"$tmp/listing") lines, want 10" >&2
	fail=1
fi

# source-listing.sh rejects the path names that check-source rejects: a
# newline, a carriage return (#59: sha256sum escapes it, so check-source
# would find no sha256 for the path) and a backslash.
nl='
'
cr=$(printf '\r')
# listing_rejects <case> <file name>: a repository with that one file.
listing_rejects() {
	r=$tmp/name-$1
	mkdir "$r"
	echo "x" >"$r/$2"
	git -C "$r" init -q
	git -C "$r" add .
	git -C "$r" -c user.name=test -c user.email=test@example.org commit -q -m fixture
	rc=0
	out=$(bash "$listing" "$r/.git" HEAD 2>&1) || rc=$?
	if [ "$rc" = 0 ] || ! printf '%s\n' "$out" | grep -qF "unsupported path name"; then
		echo "FAIL source-listing $1: exit $rc, want a failure with 'unsupported path name':" >&2
		printf '%s\n' "$out" >&2
		fail=1
	else
		echo "ok   source-listing $1: rejected (exit $rc)"
	fi
}
listing_rejects newline-name "new${nl}line"
listing_rejects carriage-return-name "car${cr}return"
listing_rejects backslash-name 'back\slash'

# The archive as GitHub serves it, and its unpacked tree to change.
git -C "$repo" archive --format=tar.gz --prefix=top/ -o "$tmp/genuine.tar.gz" HEAD
mkdir "$tmp/genuine"
tar -xzf "$tmp/genuine.tar.gz" -C "$tmp/genuine"

# stage <name>: a copy of the genuine tree in $tmp/<name>, to change.
stage() {
	cp -a "$tmp/genuine" "$tmp/$1"
}
# pack <name> [tar options and members]: $tmp/<name>.tar.gz from $tmp/<name>
# (members: top by default).
pack() {
	n=$1
	shift
	[ $# -gt 0 ] || set -- top
	tar -C "$tmp/$n" --owner=0 --group=0 -czf "$tmp/$n.tar.gz" "$@"
}
# pack_mode <name> <path under top> <mode>: as pack, but <path> (a file,
# or a directory, whose content follows) with the archive mode <mode>.
pack_mode() {
	n=$1 p=$2 mode=$3
	tar -C "$tmp/$n" --owner=0 --group=0 --exclude="top/$p" -cf "$tmp/$n.tar" top
	tar -C "$tmp/$n" --owner=0 --group=0 --no-recursion --mode="$mode" -rf "$tmp/$n.tar" "top/$p"
	if [ -d "$tmp/$n/top/$p" ]; then
		(cd "$tmp/$n" && find "top/$p" -mindepth 1 -maxdepth 1) | while IFS= read -r member; do
			tar -C "$tmp/$n" --owner=0 --group=0 -rf "$tmp/$n.tar" "$member"
		done
	fi
	gzip -n "$tmp/$n.tar"
}

# expect <case> <archive> <manifest> <want exit> <want output substring>:
# runs check-source on $tmp/<archive>.tar.gz with $tmp/manifest-<manifest>.
expect() {
	name=$1 archive=$2 form=$3 want=$4 msg=$5
	out_dir=$tmp/out-$name-$form
	rc=0
	out=$("$shell" "$check" "$tmp/$archive.tar.gz" "$tmp/manifest-$form" "$out_dir" 2>&1) || rc=$?
	if [ "$rc" != "$want" ]; then
		echo "FAIL $name ($form): exit $rc, want $want:" >&2
		printf '%s\n' "$out" | tail -n 20 >&2
		fail=1
	elif [ -n "$msg" ] && ! printf '%s\n' "$out" | grep -qF -- "$msg"; then
		echo "FAIL $name ($form): output lacks '$msg':" >&2
		printf '%s\n' "$out" | tail -n 20 >&2
		fail=1
	else
		echo "ok   $name ($form): exit $rc"
	fi
}

for form in listing digest; do
	expect genuine genuine "$form" 0 "10 entries match the pinned tree"
done

stage extra-file && echo "x" >"$tmp/extra-file/top/src/extra.c" && pack extra-file
stage changed && echo "readme!" >"$tmp/changed/top/README" && pack changed
stage missing && rm "$tmp/missing/top/docs/index.md" && pack missing
stage renamed && mv "$tmp/renamed/top/README" "$tmp/renamed/top/README.txt" && pack renamed
stage extra-dir && mkdir "$tmp/extra-dir/top/install" && pack extra-dir
stage no-submodule && rmdir "$tmp/no-submodule/top/ext/mod" && pack no-submodule
stage symlink && ln -s /etc/hostname "$tmp/symlink/top/link" && pack symlink
stage backslash && echo "x" >"$tmp/backslash/top/back\\slash" && pack backslash
stage newline && echo "x" >"$tmp/newline/top/new
line" && pack newline
stage carriage-return && echo "x" >"$tmp/carriage-return/top/car${cr}return" && pack carriage-return
stage not-exec && pack_mode not-exec configure 0644
stage exec && pack_mode exec README 0755
stage private-dir && pack_mode private-dir src/sub 0700
for form in listing digest; do
	expect extra-file extra-file "$form" 1 ""
	expect changed-byte changed "$form" 1 ""
	expect missing-file missing "$form" 1 ""
	expect renamed-file renamed "$form" 1 ""
	expect extra-empty-directory extra-dir "$form" 1 ""
	expect missing-submodule-directory no-submodule "$form" 1 ""
	expect symlink symlink "$form" 1 "not files or directories"
	expect backslash-name backslash "$form" 1 "a newline, a carriage return or a backslash"
	expect newline-name newline "$form" 1 "a newline, a carriage return or a backslash"
	expect carriage-return-name carriage-return "$form" 1 "a newline, a carriage return or a backslash"
	expect exec-bit-removed not-exec "$form" 1 ""
	expect exec-bit-added exec "$form" 1 ""
	expect directory-mode-700 private-dir "$form" 1 ""
done
expect digest-mismatch-prints-listing changed digest 1 "f 755 "
expect listing-mismatch-prints-diff changed listing 1 "+f 644 "

# Manifests that pin nothing, or the wrong count, fail.
grep -v '^listing' "$tmp/manifest-digest" >"$tmp/manifest-empty" || true
sed 's/ 10$/ 9/' "$tmp/manifest-digest" >"$tmp/manifest-count"
expect comments-only-manifest genuine empty 1 ""
expect wrong-count genuine count 1 ""
# A missing manifest fails with its own message, not as a mismatch (#59).
expect missing-manifest genuine none 1 "cannot read the manifest"

# Relative paths, from the caller's directory: check-source reads the
# manifest before it changes into DIR (#59).
rc=0
out=$(cd "$tmp" && "$shell" "$check" genuine.tar.gz manifest-listing out-relative 2>&1) || rc=$?
if [ "$rc" != 0 ] || ! printf '%s\n' "$out" | grep -qF "10 entries match the pinned tree"; then
	echo "FAIL relative-manifest-path: exit $rc, want 0:" >&2
	printf '%s\n' "$out" | tail -n 20 >&2
	fail=1
else
	echo "ok   relative-manifest-path: exit 0"
fi

# Relative operands that start with "-" are paths, not options or stdin
# (#66). expect_operands <case> <cwd> <want exit> <want output> ARCHIVE
# MANIFEST DIR: runs check-source in $tmp/<cwd>, with stdin from /dev/null
# (an ARCHIVE "-" read as stdin fails instead of waiting) and OLDPWD at the
# checked genuine tree (a DIR "-" taken by cd as "cd -" checks that tree).
expect_operands() {
	name=$1 cwd=$tmp/$2 want=$3 msg=$4
	shift 4
	mkdir -p "$cwd"
	rc=0
	out=$(cd "$cwd" && OLDPWD=$tmp/out-genuine-listing "$shell" "$check" "$@" </dev/null 2>&1) || rc=$?
	if [ "$rc" != "$want" ] || ! printf '%s\n' "$out" | grep -qF -- "$msg"; then
		echo "FAIL $name: exit $rc, want $want with '$msg':" >&2
		printf '%s\n' "$out" | tail -n 20 >&2
		fail=1
	else
		echo "ok   $name: exit $rc"
	fi
}
mkdir "$tmp/dash-manifest" "$tmp/dash-archive"
cp "$tmp/manifest-listing" "$tmp/dash-manifest/-fx"
cp "$tmp/genuine.tar.gz" "$tmp/dash-archive/-"
# grep would read "-fx" as -f x.
expect_operands dash-manifest dash-manifest 0 "10 entries match the pinned tree" \
	"$tmp/genuine.tar.gz" -fx out
# tar would read "-" as stdin.
expect_operands dash-archive dash-archive 0 "10 entries match the pinned tree" \
	- "$tmp/manifest-listing" out
# cd would read "-" as "cd -" and check the genuine tree, not this one.
expect_operands dash-dir dash-dir 1 "differ from the pinned tree" \
	"$tmp/extra-file.tar.gz" "$tmp/manifest-listing" -
# An empty DIR would become "./", the caller's directory.
expect_operands empty-dir empty-dir 2 "usage: check-source" \
	"$tmp/genuine.tar.gz" "$tmp/manifest-listing" ""

# Setuid, setgid, sticky and group or world write bits in the archive do not
# reach the disk, whatever the caller's umask: the tree is the pinned one.
# expect_modes <case> <path under top> <archive mode>: with the caller's
# umask 000, check-source passes and unpacks <path> as 755, README as 644.
#
# GNU tar keeps the archive's modes by default only for root; for any
# other user it applies the umask and drops setuid and setgid by itself,
# so without more, a check-source that lost --no-same-permissions would
# still pass here as non-root, as CI runs it (#59). TAR_OPTIONS (which GNU
# tar reads before its command line) turns --same-permissions on for every
# user: check-source's own --no-same-permissions overrides it, and a
# check-source without it unpacks the archive's 6777 or 1777, as root
# would. TAR_OPTIONS is GNU tar's: another tar ignores it, and these cases
# would prove nothing, so without GNU tar the suite fails (#66).
require_gnu_tar() {
	if tar --version 2>/dev/null | grep -qF 'GNU tar'; then
		return 0
	fi
	version=$(tar --version 2>&1 | head -n 1) || true
	echo "FAIL mode cases: need GNU tar, tar --version says: $version" >&2
	return 1
}
expect_modes() {
	name=$1 p=$2 mode=$3
	stage "$name"
	pack_mode "$name" "$p" "$mode"
	out_dir=$tmp/out-$name
	rc=0
	out=$(umask 000 && TAR_OPTIONS=--same-permissions "$shell" "$check" "$tmp/$name.tar.gz" "$tmp/manifest-listing" "$out_dir" 2>&1) || rc=$?
	modes=$(stat -c '%a' "$out_dir/$p" "$out_dir/README" 2>&1 | tr '\n' ' ' || true)
	if [ "$rc" != 0 ] || [ "$modes" != "755 644 " ]; then
		echo "FAIL $name: $p archived as $mode: exit $rc, want 0; modes of $p and README: $modes, want 755 644" >&2
		printf '%s\n' "$out" | tail -n 20 >&2
		fail=1
	else
		echo "ok   $name: $p archived as $mode, unpacked as 755 (exit 0)"
	fi
}
require_gnu_tar || fail=1
expect_modes setuid-setgid-world-writable-file configure 6777
expect_modes sticky-world-writable-directory src 1777

# The guard itself, with a tar first on PATH that is not GNU tar. A
# subshell: neither its PATH nor its failure reaches the rest of the suite.
mkdir "$tmp/fake-tar"
printf '#!/bin/sh\necho "bsdtar 3.7.2 - libarchive 3.7.2"\n' >"$tmp/fake-tar/tar"
chmod 755 "$tmp/fake-tar/tar"
rc=0
out=$(PATH=$tmp/fake-tar:$PATH && require_gnu_tar 2>&1) || rc=$?
if [ "$rc" != 1 ] || ! printf '%s\n' "$out" | grep -qF "FAIL mode cases: need GNU tar, tar --version says: bsdtar 3.7.2"; then
	echo "FAIL gnu-tar-guard: with bsdtar, exit $rc, want 1 with 'need GNU tar':" >&2
	printf '%s\n' "$out" >&2
	fail=1
else
	echo "ok   gnu-tar-guard: bsdtar fails the mode cases (exit 1)"
fi

# check-source removes its temporary directory, on success and on failure.
mkdir "$tmp/tmpdir"
for case in "genuine 0" "extra-dir 1" "changed 1"; do
	set -- $case
	rc=0
	TMPDIR=$tmp/tmpdir "$shell" "$check" "$tmp/$1.tar.gz" "$tmp/manifest-digest" "$tmp/out-tmpdir-$1" >/dev/null 2>&1 || rc=$?
	left=$(ls -A "$tmp/tmpdir")
	if [ "$rc" != "$2" ] || [ -n "$left" ]; then
		echo "FAIL temporary directory ($1): exit $rc, want $2; left behind: $left" >&2
		fail=1
		rm -rf "$tmp/tmpdir" && mkdir "$tmp/tmpdir"
	else
		echo "ok   temporary directory removed ($1, exit $rc)"
	fi
done

if [ "$fail" != 0 ]; then
	echo "check-source-test: FAILED" >&2
	exit 1
fi
echo "check-source-test: all checks passed"
