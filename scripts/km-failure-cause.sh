#!/bin/sh
# Names why ./km failed in test 7's counter-case (the CI compose job, "./km
# with a wrong database password fails"; #61, #69). With a wrong database
# password, keepia's serve cannot log in and exits, and Docker restarts it
# again and again (restart: unless-stopped). km's exec meets that loop.
#
# Usage: sh scripts/km-failure-cause.sh <exit status> <output>
#
# <output> is the combined output of `PS4='+ ' sh -x ./km migrate status`:
# km's own trace, then what its exec printed. Exit 0 and a "cause:" line if
# km failed at its exec because of keepia's restart loop; exit 1 and the
# reason otherwise. The caller still checks that loop in Docker: keepia is
# running or restarting, has restarted, and its log has SQLSTATE 28P01.
#
# Why by stage and not by the exec's message alone (#69): in the loop,
# Docker shows keepia only as running or restarting, never as exited (the
# exit handler switches running to restarting under the container lock).
# The exec's create step reads that state under the same lock:
# - restarting: Docker refuses the exec ("is restarting"), always the same;
# - running: Docker creates the exec in the current run of keepia, which
#   exits a few milliseconds later on the wrong password. Where that exit
#   lands in the exec's way through dockerd, containerd, the shim, runc
#   and the kernel decides the message. 400 local runs gave 11 different
#   ones (scripts/km-failure-cause-test.sh), among them "cannot exec in a
#   stopped container" and exit 137 with no output at all, so no list of
#   messages is complete.
# What does not depend on that timing decides here:
# 1. km reached its exec: km runs with set -eu, so the shell traces the
#    exec line only after every earlier step (daemon, images, postgres
#    healthy, keepia up) has succeeded. Without that line km failed
#    before its exec, and that fails the test whatever the message. The
#    exec is km's last command, so a traced line after it can only come
#    from a traced value with a newline in it: that fails too (#70, N1).
# 2. keepia-mail did not crash: its main exits 0, 1, 3 or 64 (#95: 3 for
#    "already exists", 64 for a usage error), and the Go
#    runtime exits 2 on a panic or a fatal error, with a "panic: ",
#    "fatal error: " or "goroutine N [" line. Exit 2 or such a line fails
#    the test (#70, B1); no runtime answer to the loop exits 2.
# 3. migrate ran to its end: keepia-mail then printed "error: ..." (main.go),
#    and that error must be the wrong password (SQLSTATE 28P01). Any other
#    error of keepia-mail fails the test.
# Any other failure at the exec is taken as the restart loop: refused
# while keepia was restarting, or cut off by the exit of the run it
# entered. That fallback also takes a Docker or Compose exec failure that
# is not the loop (a stopped service, a missing executable, the socket);
# a systematic one fails the positive step `./km migrate (test 7)` just
# before, which uses the same exec, so only an intermittent one passes.
set -u

if [ $# -ne 2 ]; then
	echo "usage: sh scripts/km-failure-cause.sh <exit status> <output>" >&2
	exit 2
fi
rc=$1
out=$2
nl='
'
# The trace of km's last line, `exec docker compose ... exec -T keepia
# keepia-mail "$@"`, with PS4 '+ '.
exec_line='+ exec docker compose --progress quiet exec -T keepia keepia-mail '

if [ "$rc" = 0 ]; then
	echo "km succeeded with a wrong database password"
	exit 1
fi
case $nl$out in
*"$nl$exec_line"*) ;;
*)
	echo "km failed before its exec (exit $rc)"
	exit 1
	;;
esac

# What the exec printed: everything after the traced exec line.
after=${out#*"$exec_line"}
case $after in
*"$nl"*) execout=${after#*"$nl"} ;;
*) execout= ;;
esac

# A traced line after the exec line.
if printf '%s\n' "$execout" | grep -q '^+ '; then
	echo "a traced line follows km's exec line (exit $rc)"
	exit 1
fi

# keepia-mail's own crash.
if [ "$rc" = 2 ] || printf '%s\n' "$execout" | grep -Eq '^(panic: |fatal error: |goroutine [0-9]+ \[)'; then
	echo "keepia-mail crashed (exit $rc)"
	exit 1
fi

# keepia-mail's own errors: lines starting with "error: ".
errors=$(printf '%s\n' "$execout" | grep '^error: ')
if [ -n "$errors" ]; then
	if printf '%s\n' "$errors" | grep -v 'password authentication failed.*(SQLSTATE 28P01)' | grep -q .; then
		echo "keepia-mail failed for another reason (exit $rc)"
		exit 1
	fi
	echo "cause: migrate's own login failed (SQLSTATE 28P01)"
	exit 0
fi

case $execout in
*'is restarting, wait until the container is running'*)
	echo "cause: km's exec found keepia restarting"
	;;
*)
	first=$(printf '%s\n' "$execout" | tr -d '\r' | grep -m1 . | cut -c1-200)
	echo "cause: km's exec met keepia as that run of it exited (exit $rc: ${first:-no output})"
	;;
esac
exit 0
