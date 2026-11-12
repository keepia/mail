#!/bin/bash
# Tests one own image after its build (#5 plan, tests 3 and 16; the CI
# docker-build job runs it on every row, `make image-test IMAGE=<name>`
# locally):
#
# - smoke: the image's own check command, and its package list
#   (/usr/share/keepia/packages.txt) printed;
# - user and capabilities as the plan sets them (Compose sets the same in
#   part 3): Keepia as 65532, Unbound as 10053, olefy as 10055, SOGo as
#   10060, all with no capabilities; Postfix's root master with exactly
#   CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID; no-new-privileges
#   everywhere;
# - olefy: a scan over olefy's protocol, answered by olevba;
# - SOGo: sogod starts without a database or configuration and answers
#   GET /SOGo/, logging that nobody can log in;
# - healthcheck: green, then red with every process of the container
#   stopped (SIGSTOP from the host); for Postfix also red with Debian's
#   chroot = y, where `postfix status` still says running; for Keepia the
#   probe is red with nothing listening (green needs Postgres: part 3);
# - reload watcher (Postfix, Unbound): a write-and-rename of `generation`
#   into the watched volume from another container gives the reload line,
#   and killing inotifywait stops the container with status 1;
# - docker stop ends the service cleanly (status 0).
#
# Every wait reads a signal (docker events, a log line, docker wait), bounded
# by a timeout. No network: the containers run with --network none.
#
# Usage: scripts/image-test.sh <keepia|postfix|unbound|olefy|sogo> <image reference>
# Needs root or sudo for kill on the container's host processes.
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: $0 <keepia|postfix|unbound|olefy|sogo> <image reference>" >&2
	exit 2
fi
name=$1 ref=$2
prefix=keepia-image-test-$$
sudo=
[ "$(id -u)" = 0 ] || sudo=sudo

created=()
cleanup() {
	local c
	for c in "${created[@]}"; do
		docker rm -f "$c" >/dev/null 2>&1 || true
	done
	docker volume rm -f "$prefix-gen" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pass() { echo "ok   $*"; }
fail() {
	echo "FAIL $*" >&2
	exit 1
}

# Health flags: probe every second after a 1 s start period (the image's
# 60 s interval would make the red case slow). Timeout and retries stay as
# in the image (5 s, 2).
health_flags=(--health-interval 1s --health-start-period 1s --health-start-interval 1s)

# mark: the events a later wait_health reads start now (nanoseconds), so a
# state reached before, such as an unhealthy probe during start-up, cannot
# satisfy it.
mark() {
	t0=$(date +%s.%N)
}

# start <container> [docker run options] -- [command]: runs a detached
# container and records it for cleanup. Sets t0 for wait_health; a later
# wait that must see a new state calls mark first.
start() {
	local c=$1
	shift
	created+=("$c")
	mark
	docker run -d --name "$c" --network none --security-opt no-new-privileges:true "$@" >/dev/null
}

# read_until <limit s> <want> <stop> -- <command...>: runs the command
# (bounded by the limit) and reads its output line by line. Returns 0 at
# the first line that contains <want>, 3 at the first that contains <stop>
# (empty: none), 1 when the output ends first. The command is stopped in
# every case, so nothing waits for a further line.
read_until() {
	local limit=$1 want=$2 stop=$3 line pid rc=1
	shift 4
	coproc STREAM { exec timeout "$limit" "$@" 2>&1; }
	pid=$STREAM_PID
	while IFS= read -r -u "${STREAM[0]}" line; do
		if [[ $line == *"$want"* ]]; then
			rc=0
			break
		fi
		if [ -n "$stop" ] && [[ $line == *"$stop"* ]]; then
			rc=3
			break
		fi
	done
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	return "$rc"
}

# wait_health <container> <healthy|unhealthy> <limit s>: reads Docker's
# health events since the container started; fails if the container dies
# first or the limit passes.
wait_health() {
	local c=$1 want=$2 limit=$3 rc=0
	read_until "$limit" "health_status: $want" die -- docker events --since "$t0" \
		--filter "container=$c" --filter event=health_status --filter event=die \
		--format '{{.Action}}' || rc=$?
	[ "$rc" = 0 ] && return 0
	docker logs "$c" 2>&1 | tail -20 >&2
	docker inspect -f '{{json .State.Health}}' "$c" >&2 || true
	if [ "$rc" = 3 ]; then
		fail "$c died while waiting for $want"
	fi
	fail "$c not $want within $limit s"
}

# wait_log <container> <fixed string> <limit s>: follows the container's log
# until a line contains the string.
wait_log() {
	local c=$1 want=$2 limit=$3
	if ! read_until "$limit" "$want" "" -- docker logs -f "$c"; then
		docker logs "$c" 2>&1 | tail -20 >&2
		fail "$c: no log line '$want' within $limit s"
	fi
}

# signal_all <container> <signal>: sends a signal to every process of the
# container from the host.
signal_all() {
	local pids
	pids=$(docker top "$1" -eo pid | awk 'NR > 1 { print $1 }')
	# shellcheck disable=SC2086 # one pid per word
	$sudo kill "-$2" $pids
}

# last_probe <container>: the output of the last health probe.
last_probe() {
	docker inspect -f '{{json .State.Health.Log}}' "$1" | jq -r 'last | "exit \(.ExitCode): \(.Output | rtrimstr("\n"))"'
}

check_config() {
	local want_user=$1
	local user
	user=$(docker image inspect -f '{{.Config.User}}' "$ref")
	[ "$user" = "$want_user" ] || fail "image user is '$user', want '$want_user'"
	local hc
	hc=$(docker image inspect -f '{{if .Config.Healthcheck}}{{.Config.Healthcheck.Test}}{{end}}' "$ref")
	[ -n "$hc" ] || fail "image has no HEALTHCHECK"
	pass "image user '$want_user' and a HEALTHCHECK: $hc"
}

# proc_status <container> <field>: CapEff or NoNewPrivs of the container's
# PID 1 (tini; the service inherits both), read from the host.
proc_status() {
	local pid
	pid=$(docker inspect -f '{{.State.Pid}}' "$1")
	$sudo awk -v k="$2:" '$1 == k { print $2 }' "/proc/$pid/status"
}

# health_cycle <container> <CapEff of PID 1> <run options...>: green, with
# no-new-privileges and exactly the expected effective capabilities; then
# red after SIGSTOP of every process; then the container is removed.
health_cycle() {
	local c=$1 want_cap=$2 nnp cap
	shift 2
	start "$c" "${health_flags[@]}" "$@" "$ref"
	wait_health "$c" healthy 60
	pass "$name healthy: $(last_probe "$c" | tail -1)"
	nnp=$(proc_status "$c" NoNewPrivs)
	cap=$(proc_status "$c" CapEff)
	[ "$nnp" = 1 ] || fail "$c: NoNewPrivs is '$nnp', want 1"
	[ "$cap" = "$want_cap" ] || fail "$c: CapEff of PID 1 is $cap, want $want_cap"
	pass "$name: NoNewPrivs 1, CapEff of PID 1 $cap"
	# Only an unhealthy event after the stop counts (review B 2).
	[ "$(docker inspect -f '{{.State.Health.Status}}' "$c")" = healthy ] || fail "$c is not healthy before the stop"
	mark
	signal_all "$c" STOP
	wait_health "$c" unhealthy 60
	pass "$name unhealthy with its processes stopped: $(last_probe "$c" | tail -1)"
	signal_all "$c" CONT
	docker rm -f "$c" >/dev/null
}

# watcher_test <container> <service reload line> <run options...>
watcher_test() {
	local c=$1 reload_line=$2
	shift 2
	docker volume create "$prefix-gen" >/dev/null
	start "$c" "${health_flags[@]}" -v "$prefix-gen:/run/keepia/generation:ro" "$@" "$ref"
	wait_log "$c" "Watches established." 30
	# A reload needs a running service: write once the service answers.
	wait_health "$c" healthy 60
	# The agent's write-and-rename, from another container (as in 0.2.0).
	docker run --rm --name "$prefix-agent" --network none --user 0 --entrypoint sh \
		-v "$prefix-gen:/g" "$ref" -c 'echo 7 >/g/.generation.tmp && mv /g/.generation.tmp /g/generation'
	wait_log "$c" "keepia-entrypoint: generation 7, reloading" 30
	wait_log "$c" "$reload_line" 30
	wait_log "$c" "keepia-entrypoint: reload of generation 7 done" 30
	pass "$name: generation 7 written and renamed by another container gives the reload ('$reload_line')"

	local pid
	pid=$(docker top "$c" -eo pid,comm | awk '$2 == "inotifywait" { print $1 }')
	[ -n "$pid" ] || fail "$c runs no inotifywait"
	$sudo kill -TERM "$pid"
	local rc
	rc=$(timeout 30 docker wait "$c") || fail "$c still runs 30 s after inotifywait was killed"
	[ "$rc" = 1 ] || fail "$c exited with $rc after inotifywait was killed, want 1"
	# Read the whole log first: `| grep -q` would end the pipe early, and
	# pipefail would count docker's SIGPIPE as a miss.
	local logs
	logs=$(docker logs "$c" 2>&1)
	if [[ $logs != *"the reload watcher stopped"* ]]; then
		printf '%s\n' "$logs" | tail -20 >&2
		fail "$c: no 'reload watcher stopped' line"
	fi
	pass "$name: killing inotifywait stops the container with status 1"
	docker rm -f "$c" >/dev/null
	docker volume rm "$prefix-gen" >/dev/null
}

# stop_test <container> <run options...>: docker stop gives status 0.
stop_test() {
	local c=$1
	shift
	start "$c" "${health_flags[@]}" "$@" "$ref"
	wait_health "$c" healthy 60
	docker stop -t 20 "$c" >/dev/null
	local rc
	rc=$(docker inspect -f '{{.State.ExitCode}}' "$c")
	[ "$rc" = 0 ] || fail "$c exited with $rc after docker stop, want 0"
	pass "$name: docker stop ends the service with status 0"
	docker rm -f "$c" >/dev/null
}

print_packages() {
	echo "---- /usr/share/keepia/packages.txt"
	docker run --rm --name "$prefix-pkgs" --network none --entrypoint cat "$ref" /usr/share/keepia/packages.txt
	echo "----"
}

postfix_caps=(--cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETUID --cap-add SETGID)

case $name in
keepia)
	out=$(docker run --rm --name "$prefix-smoke" --network none "$ref" --version)
	case $out in "keepia-mail version "*) ;; *) fail "--version printed '$out'" ;; esac
	pass "smoke: $out"
	check_config 65532:65532
	rc=0
	out=$(docker run --rm --name "$prefix-probe" --network none --cap-drop ALL "$ref" healthcheck 2>&1) || rc=$?
	[ "$rc" = 1 ] || fail "healthcheck with nothing listening exited $rc, want 1: $out"
	pass "healthcheck red with nothing listening (exit 1): $out"
	;;
postfix)
	docker run --rm --name "$prefix-smoke" --network none --entrypoint postfix "$ref" check
	pass "smoke: postfix check"
	all=$(docker run --rm --name "$prefix-chroot" --network none --entrypoint postconf "$ref" -F '*/*/chroot')
	[ -n "$all" ] || fail "postconf -F listed no master.cf service"
	out=$(printf '%s\n' "$all" | awk '$NF != "n"')
	[ -z "$out" ] || fail "master.cf services with chroot other than n: $out"
	pass "every master.cf service ($(printf '%s\n' "$all" | wc -l)) has chroot = n"
	print_packages
	check_config ""
	# 0xcb: CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID.
	health_cycle "$prefix-health" 00000000000000cb "${postfix_caps[@]}"
	# Counter-check of the probe: Debian's chroot = y without SYS_CHROOT.
	# Every smtpd dies on chroot() while the master keeps running.
	start "$prefix-chroot-y" "${health_flags[@]}" "${postfix_caps[@]}" --entrypoint sh "$ref" \
		-c "postconf -F '*/*/chroot = y' && exec /usr/bin/tini -- /usr/local/bin/keepia-reload-watch postfix start-fg"
	wait_health "$prefix-chroot-y" unhealthy 60
	# `postfix status` can block after it printed; bounded, for the log only.
	status=$(timeout 10 docker exec "$prefix-chroot-y" postfix status 2>&1 | head -1 || true)
	# The point of this case: the master still reports itself as running.
	[[ $status == *"the Postfix mail system is running"* ]] ||
		fail "postfix status with chroot = y says '$status', want 'the Postfix mail system is running'"
	pass "postfix with chroot = y unhealthy ($(last_probe "$prefix-chroot-y")) while postfix status says: $status"
	docker logs "$prefix-chroot-y" 2>&1 | grep -m1 'chroot(' || true
	docker rm -f "$prefix-chroot-y" >/dev/null
	watcher_test "$prefix-watch" "refreshing the Postfix mail system" "${postfix_caps[@]}"
	stop_test "$prefix-stop" "${postfix_caps[@]}"
	;;
unbound)
	docker run --rm --name "$prefix-smoke" --network none --entrypoint unbound-checkconf "$ref"
	pass "smoke: unbound-checkconf"
	print_packages
	check_config 10053:10053
	health_cycle "$prefix-health" 0000000000000000 --cap-drop ALL
	watcher_test "$prefix-watch" "Restart of unbound" --cap-drop ALL
	stop_test "$prefix-stop" --cap-drop ALL
	;;
olefy)
	out=$(docker run --rm --name "$prefix-smoke" --network none --cap-drop ALL --entrypoint python3 "$ref" \
		-I -c 'import oletools.olevba as v, pcodedmp; print("oletools", v.__version__)')
	[ "$out" = "oletools 0.60.2" ] || fail "smoke printed '$out', want 'oletools 0.60.2'"
	pass "smoke: $out"
	print_packages
	check_config 10055:10055
	# A scan over olefy's protocol: olefy runs olevba on the payload (olefy.py
	# itself, over olefy's 500-byte minimum) and answers with its JSON.
	start "$prefix-scan" "${health_flags[@]}" --cap-drop ALL "$ref"
	wait_health "$prefix-scan" healthy 60
	pass "olefy runs as: $(docker exec "$prefix-scan" id)"
	out=$(docker exec "$prefix-scan" python3 -I -c '
import socket
with open("/usr/local/bin/olefy.py", "rb") as f:
    payload = f.read()
with socket.create_connection(("127.0.0.1", 10050), timeout=30) as s:
    s.sendall(b"OLEFY/1.0\nMethod: oletools\nRspamd-ID: test01\n\n" + payload)
    s.shutdown(socket.SHUT_WR)
    reply = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        reply += chunk
print(reply.decode("utf-8", "replace"))
')
	for want in '"script_name": "olevba"' '"version": "0.60.2"' '"json_conversion_successful": true'; do
		[[ $out == *"$want"* ]] || fail "olefy's scan reply lacks $want: ${out:0:400}"
	done
	pass "scan over olefy's protocol: olevba 0.60.2 answered (${#out} bytes)"
	docker rm -f "$prefix-scan" >/dev/null
	health_cycle "$prefix-health" 0000000000000000 --cap-drop ALL
	stop_test "$prefix-stop" --cap-drop ALL
	;;
sogo)
	# sogod has no --help (it detaches and exits 0); sogo-tool loads the
	# same SOGo and SOPE libraries and prints its usage.
	out=$(docker run --rm --name "$prefix-smoke" --network none --cap-drop ALL "$ref" sogo-tool --help 2>&1)
	[[ $out == *"sogo-tool [-v|--verbose] [-h|--help] command"* ]] || fail "sogo-tool --help printed: ${out:0:400}"
	pass "smoke: sogo-tool --help prints its usage"
	print_packages
	check_config 10060:10060
	# sogod without a database and without any configuration (#5 plan,
	# Risks): it starts, loads every SOGo product, listens, and answers
	# GET /SOGo/ (healthy), while it logs that nobody can log in.
	start "$prefix-nodb" "${health_flags[@]}" --cap-drop ALL "$ref"
	wait_health "$prefix-nodb" healthy 60
	logs=$(docker logs "$prefix-nodb" 2>&1)
	for want in "version 5.12.13" "All products loaded" "listening on 127.0.0.1:20000" \
		"No authentication sources defined - nobody will be able to login"; do
		[[ $logs == *"$want"* ]] || {
			printf '%s\n' "$logs" | head -30 >&2
			fail "sogod's log lacks '$want'"
		}
	done
	echo "---- sogod's log without a database (first 16 lines)"
	printf '%s\n' "$logs" | head -16
	echo "----"
	pass "sogod runs as: $(docker exec "$prefix-nodb" id)"
	pass "sogod without a database: $(docker top "$prefix-nodb" -eo pid,user,comm | awk 'NR > 1 { printf "%s%s(%s)", s, $3, $2; s = ", " }') up, $(last_probe "$prefix-nodb")"
	docker rm -f "$prefix-nodb" >/dev/null
	health_cycle "$prefix-health" 0000000000000000 --cap-drop ALL
	stop_test "$prefix-stop" --cap-drop ALL
	;;
*)
	fail "unknown image $name"
	;;
esac
echo "image-test $name: all checks passed"
