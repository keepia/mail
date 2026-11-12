#!/bin/bash
# Self-test for images/sogo/keepia-sogod (#25, #55), without Docker: a fake
# sogod master forks one worker that ignores SIGTERM, as an idle sogod
# worker does. Checks that
#
# - a KEEPIA_SOGOD_GRACE that is not a whole number from 0 to 300 ends the
#   wrapper with status 2 before it starts anything, and that the value is
#   never evaluated (Review B of #54: "i[$(touch …)]+1" ran the command);
# - on SIGTERM the wrapper stops the master, sends SIGKILL to the worker
#   after the grace time (not before), and exits with the master's status.
#
# Run it with `make image-scripts-test`. No network.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# KEEPIA_SOGOD_WRAPPER: another copy of the wrapper (a counter-proof).
wrapper=${KEEPIA_SOGOD_WRAPPER:-$here/../images/sogo/keepia-sogod}
tmp=$(mktemp -d)
pids=()
cleanup() {
	local p
	for p in "${pids[@]}"; do
		kill -KILL "$p" 2>/dev/null || true
	done
	rm -rf "$tmp"
}
trap cleanup EXIT
fail=0
ok() { echo "ok   $*"; }
bad() {
	echo "FAIL $*" >&2
	fail=1
}

# The fake master: forks a worker that ignores SIGTERM, forwards SIGTERM to
# it and exits 0 once it is gone (as sogod's watchdog does once its
# children are down). The worker writes its pid to the FIFO $1/ready once
# it ignores SIGTERM. The test holds the FIFO open for reading and writing
# on fd 3, so the write never blocks.
# shellcheck disable=SC2016 # expanded by the fake master
fake_master='
trap "kill -TERM \"\$w\"" TERM
bash -c "trap \"\" TERM; echo \$\$ >\"\$1/ready\"; exec sleep 600" worker "$1" &
w=$!
while kill -0 "$w" 2>/dev/null; do wait "$w" || true; done
exit 0
'
mkfifo "$tmp/ready"
exec 3<>"$tmp/ready"

# exited <pid> <limit s>: waits until <pid> has exited, at most <limit> s.
exited() {
	timeout "$2" tail -s 0.1 --pid="$1" -f /dev/null
}

# Hostile and out-of-range values: status 2 with a clear error, the fake
# sogod never started and no command run. If a wrapper does start it, the
# test stops it with SIGTERM and reports what the value did.
for value in 'i[$(touch "$TMP/pwned")]+1' 'master[$(touch "$TMP/pwned")]' \
	abc 5s -1 1.5 ' 5' '5 ' 0x10 301 1000 99999999999999999999; do
	rm -f "$tmp/pwned" "$tmp/out"
	TMP=$tmp KEEPIA_SOGOD_GRACE=$value bash "$wrapper" bash -c "$fake_master" fake-sogod "$tmp" >"$tmp/out" 2>&1 &
	wpid=$!
	pids+=("$wpid")
	if ! exited "$wpid" 5; then
		worker=
		read -t 5 -r -u 3 worker || true
		pids+=("$worker")
		t0=$(date +%s%N)
		kill -TERM "$wpid"
		exited "$wpid" 3 || true
		ms=$((($(date +%s%N) - t0) / 1000000))
		kill -KILL "$wpid" "$worker" 2>/dev/null || true
		rc=0
		wait "$wpid" || rc=$?
		bad "grace $value: sogod started (worker ${worker:-?}); after SIGTERM: exit $rc after $ms ms" \
			"(cut at 3 s), command in the value ran: $([ -e "$tmp/pwned" ] && echo yes || echo no)"
		continue
	fi
	rc=0
	wait "$wpid" || rc=$?
	out=$(cat "$tmp/out")
	if [ "$rc" != 2 ]; then
		bad "grace $value: exit $rc, want 2: $out"
	elif [ -e "$tmp/pwned" ]; then
		bad "grace $value: the command in the value ran"
	elif [[ $out != *"must be a whole number of seconds from 0 to 300"* ]]; then
		bad "grace $value: no clear error: $out"
	else
		ok "grace $value: rejected with status 2, nothing run"
	fi
done

# Accepted values (a leading zero is decimal, not octal): the command runs.
for value in 0 08 300 ''; do
	rm -f "$tmp/started"
	rc=0
	KEEPIA_SOGOD_GRACE=$value bash "$wrapper" touch "$tmp/started" || rc=$?
	if [ "$rc" = 0 ] && [ -e "$tmp/started" ]; then
		ok "grace '$value': accepted"
	else
		bad "grace '$value': exit $rc, started: $([ -e "$tmp/started" ] && echo yes || echo no)"
	fi
done

# workers, from a fake /proc: the master's children only (also with ") "
# in the command), and no message for a process that exits between the
# glob and the read (#59; a dangling stat link fails to open the same way).
proc=$tmp/proc
mkdir -p "$proc/100" "$proc/101" "$proc/102" "$proc/103"
echo "100 (sogod) S 42 100 100 0 -1" >"$proc/100/stat"
echo "101 (a) b) S 42 100 100 0 -1" >"$proc/101/stat"
ln -s "$tmp/vanished" "$proc/102/stat"
echo "103 (other) S 7 7 7 0 -1" >"$proc/103/stat"
rc=0
# shellcheck disable=SC2016 # expanded by the inner bash
out=$(bash -c 'source "$1" && master=42 && workers "$2"' workers-test "$wrapper" "$proc" 2>"$tmp/err") || rc=$?
err=$(cat "$tmp/err")
if [ "$rc" != 0 ] || [ "$out" != $'100\n101' ] || [ -n "$err" ]; then
	bad "workers: exit $rc, pids $(echo $out), want 100 101; stderr: $err"
else
	ok "workers: the master's children 100 101, a vanished entry skipped silently"
fi

# The master's own exit status is passed through; no arguments is status 2.
rc=0
bash "$wrapper" sh -c 'exit 3' || rc=$?
[ "$rc" = 3 ] && ok "exit status 3 passed through" || bad "exit $rc, want 3"
rc=0
bash "$wrapper" 2>/dev/null || rc=$?
[ "$rc" = 2 ] && ok "no arguments: status 2" || bad "no arguments: exit $rc, want 2"

# stop_case <grace>: SIGTERM to the wrapper; the worker gets SIGKILL after
# <grace> s, and the wrapper exits 0 within <grace> + 3 s.
stop_case() {
	local grace=$1 wpid worker= rc t0 ms
	KEEPIA_SOGOD_GRACE=$grace bash "$wrapper" bash -c "$fake_master" fake-sogod "$tmp" &
	wpid=$!
	pids+=("$wpid")
	if ! read -t 5 -r -u 3 worker || [ -z "$worker" ]; then
		bad "grace $grace: the fake master did not start its worker within 5 s"
		return
	fi
	pids+=("$worker")
	t0=$(date +%s%N)
	kill -TERM "$wpid"
	rc=0
	exited "$wpid" $((grace + 3)) || rc=$?
	ms=$((($(date +%s%N) - t0) / 1000000))
	if [ "$rc" != 0 ]; then
		bad "grace $grace: the wrapper still runs after $((grace + 3)) s"
		return
	fi
	rc=0
	wait "$wpid" || rc=$?
	if [ "$rc" != 0 ]; then
		bad "grace $grace: wrapper exit $rc, want 0"
	elif kill -0 "$worker" 2>/dev/null; then
		bad "grace $grace: the worker $worker still runs"
	elif ((ms < grace * 1000)); then
		bad "grace $grace: stopped after $ms ms, before the grace time"
	else
		ok "grace $grace: worker killed, wrapper exit 0 after $ms ms"
	fi
}
stop_case 0
stop_case 2

if [ "$fail" != 0 ]; then
	echo "keepia-sogod-test: FAILED" >&2
	exit 1
fi
echo "keepia-sogod-test: all checks passed"
