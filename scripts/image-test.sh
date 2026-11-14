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
# - reload watcher (Postfix, Unbound; #45 names the cases T1 to T12):
#   - with the real service: a generation written before the start is the
#     applied one, and an equal value is ignored while a lower and a higher
#     one reload, the higher one written and renamed by another container
#     after `healthy` (T3); no service process holds the event pipe (T12);
#     killing inotifywait stops the container with status 1;
#   - a symlink (T4) and a FIFO (T5) in place of `generation`, and content
#     that is not a decimal generation (T6, for Unbound also a file it
#     cannot read), are refused and logged without their content, and a
#     valid write after them reloads;
#   - with a fake service (Postfix row, test code in a test volume): a
#     generation written between the config read and readiness reloads
#     once the service is ready (T1), the ready gate holds only until its
#     first success (T8), a failed reload is retried (T2), an end of the
#     event stream during a pending retry stops the container with
#     status 1 (T10), and a stop during the set-up exits 0 before the
#     service starts (T11);
#   - with the real Postfix: a generation written before the master runs
#     reloads once the master handles SIGHUP (T1b), and a config broken
#     from the start (chroot = y for smtpd, the probe red) can still be
#     reloaded (T9);
#   - a watch that cannot be set up exits 1 (Unbound row, T7);
# - docker stop ends the service cleanly (status 0).
#
# Every wait reads a signal (docker events, a log line, docker wait), bounded
# by a timeout. No network: the containers run with --network none.
#
# Usage: scripts/image-test.sh <keepia|postfix|unbound|olefy|sogo> <image reference>
# Needs root or sudo for kill on the container's host processes and to read
# their file descriptors. For local runs, IMAGE_TEST_CASES (space
# separated: base t1 t1b t2 t3 t4 t5 t6 t7 t9 t10 t11) limits the cases of
# the Postfix and Unbound rows; unset, every case runs (CI).
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
volumes=()
cleanup() {
	local c v
	for c in "${created[@]}"; do
		docker rm -f "$c" >/dev/null 2>&1 || true
	done
	for v in "${volumes[@]}"; do
		docker volume rm -f "$v" >/dev/null 2>&1 || true
	done
}
trap cleanup EXIT

# want <case>: whether the case runs (IMAGE_TEST_CASES, header).
want() {
	[ -z "${IMAGE_TEST_CASES:-}" ] || [[ " $IMAGE_TEST_CASES " == *" $1 "* ]]
}

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

# wait_log_n <container> <fixed string> <n> <limit s>: follows the
# container's log until the n-th line that contains the string.
wait_log_n() {
	local c=$1 want=$2 n=$3 limit=$4 line pid k=0
	coproc STREAM { exec timeout "$limit" docker logs -f "$c" 2>&1; }
	pid=$STREAM_PID
	while IFS= read -r -u "${STREAM[0]}" line; do
		if [[ $line == *"$want"* ]]; then
			k=$((k + 1))
			[ "$k" -lt "$n" ] || break
		fi
	done
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	if [ "$k" -lt "$n" ]; then
		docker logs "$c" 2>&1 | tail -20 >&2
		fail "$c: $k of $n log lines '$want' within $limit s"
	fi
}

# logs_of <container>: the whole log. Read in full first: `| grep -q`
# would end the pipe early, and pipefail would count docker's SIGPIPE as a
# miss.
logs_of() {
	docker logs "$1" 2>&1
}

# log_count <container> <fixed string>: the number of log lines with it.
log_count() {
	local logs
	logs=$(logs_of "$1")
	grep -cF -- "$2" <<<"$logs" || true
}

# log_lacks <container> <fixed string> <what>: fails if a line has it.
log_lacks() {
	local logs
	logs=$(logs_of "$1")
	if [[ $logs == *"$2"* ]]; then
		printf '%s\n' "$logs" | tail -20 >&2
		fail "$1: $3"
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

# new_volume <name>: an empty volume, removed at exit.
new_volume() {
	docker volume rm -f "$1" >/dev/null 2>&1 || true
	docker volume create "$1" >/dev/null
	volumes+=("$1")
}

# agent <docker run options...> -- <sh script> [args...]: a write of the
# agent, from another container (as in 0.2.0): root, no network.
agent() {
	local opts=()
	while [ "$1" != -- ]; do
		opts+=("$1")
		shift
	done
	shift
	docker run --rm --name "$prefix-agent" --network none --user 0 --entrypoint sh "${opts[@]}" "$ref" -c "$@"
}

# write_gen <volume> <printf format>: the agent's write-and-rename of
# `generation` (contract rule 2).
write_gen() {
	agent -v "$1:/g" -- 'printf "$1" >/g/.generation.tmp && mv /g/.generation.tmp /g/generation' sh "$2"
}

# watcher_dies <container> <when>: inotifywait killed from the host stops
# the container with status 1 and the watcher's line.
watcher_dies() {
	local c=$1 when=$2 pid rc
	pid=$(docker top "$c" -eo pid,comm | awk '$2 == "inotifywait" { print $1 }')
	[ -n "$pid" ] || fail "$c runs no inotifywait"
	$sudo kill -TERM "$pid"
	rc=$(timeout 30 docker wait "$c") || fail "$c still runs 30 s after inotifywait was killed $when"
	[ "$rc" = 1 ] || fail "$c exited with $rc after inotifywait was killed $when, want 1"
	if [[ $(logs_of "$c") != *"the reload watcher stopped"* ]]; then
		logs_of "$c" | tail -20 >&2
		fail "$c: no 'reload watcher stopped' line"
	fi
	pass "$name: killing inotifywait $when stops the container with status 1"
}

# no_event_pipe <container>: no process of the service holds the pipe
# that inotifywait writes the events to (T12). The service is the child of
# the watcher's main shell that is neither the delivery subshell nor
# inotifywait, with all its descendants.
no_event_pipe() {
	local c=$1 top init main svc ipid pipe pids p links
	top=$(docker top "$c" -eo pid,ppid,comm)
	init=$(docker inspect -f '{{.State.Pid}}' "$c")
	ipid=$(awk '$3 == "inotifywait" { print $1 }' <<<"$top")
	[ -n "$ipid" ] || fail "$c runs no inotifywait"
	pipe=$($sudo readlink "/proc/$ipid/fd/1")
	[[ $pipe == pipe:* ]] || fail "$c: inotifywait writes to '$pipe', not a pipe"
	main=$(awk -v p="$init" '$2 == p { print $1 }' <<<"$top")
	svc=$(awk -v p="$main" '$2 == p && $3 != "inotifywait" && $3 != "keepia-reload-w" { print $1 }' <<<"$top")
	[ -n "$svc" ] || fail "$c: no service process under the watcher"
	pids=$(awk -v root="$svc" 'NR > 1 { pp[$1] = $2 }
		END {
			s[root] = 1
			do {
				n = 0
				for (p in pp)
					if (!(p in s) && (pp[p] in s)) { s[p] = 1; n++ }
			} while (n)
			for (p in s) print p
		}' <<<"$top")
	for p in $pids; do
		# A short-lived process (smtpd) may be gone by now.
		links=$($sudo sh -c 'cd "/proc/$1/fd" && for f in *; do readlink "$f"; done' sh "$p" 2>/dev/null) || continue
		if grep -qxF -- "$pipe" <<<"$links"; then
			fail "$c: service process $p ($(awk -v p="$p" '$1 == p { print $3 }' <<<"$top")) holds the event pipe $pipe"
		fi
	done
	pass "$name: no service process holds the event pipe $pipe ($(wc -w <<<"$pids") checked: $(awk -v l=" $(tr '\n' ' ' <<<"$pids") " 'index(l, " " $1 " ") { printf "%s%s", s, $3; s = ", " }' <<<"$top")) (T12)"
}

# watcher_test <container> <service reload line> <run options...>: the real
# service: T3, T12 and a dead watch.
watcher_test() {
	local c=$1 reload_line=$2 n
	shift 2
	new_volume "$prefix-gen"
	write_gen "$prefix-gen" '5\n'
	start "$c" "${health_flags[@]}" -v "$prefix-gen:/run/keepia/generation:ro" "$@" "$ref"
	wait_log "$c" "(generation at start: 5)" 30
	# A reload needs a running service: write once the service answers.
	wait_health "$c" healthy 60
	no_event_pipe "$c"
	write_gen "$prefix-gen" '5\n'
	wait_log "$c" "keepia-entrypoint: generation 5 ignored: already applied" 30
	write_gen "$prefix-gen" '4\n'
	wait_log "$c" "keepia-entrypoint: generation 4, reloading" 30
	wait_log "$c" "$reload_line" 30
	wait_log "$c" "keepia-entrypoint: reload of generation 4 done" 30
	write_gen "$prefix-gen" '6\n'
	wait_log "$c" "keepia-entrypoint: reload of generation 6 done" 30
	n=$(log_count "$c" ", reloading")
	[ "$n" = 2 ] || fail "$c: $n reloads, want 2 (4 and 6)"
	pass "$name: generation 5 at the start is applied, writing 5 again is ignored, 4 and 6 written and renamed by another container reload ('$reload_line') (T3)"
	watcher_dies "$c" "after a reload"
	docker rm -f "$c" >/dev/null
}

# safety_start <container> <run options...>: the real service with an
# empty generation volume, healthy.
safety_start() {
	local c=$1
	shift
	new_volume "$prefix-gen"
	start "$c" "${health_flags[@]}" -v "$prefix-gen:/run/keepia/generation:ro" "$@" "$ref"
	wait_health "$c" healthy 60
}

# symlink_test <container> <run options...>: T4. The target holds a value
# that would pass the format check; the log must never show it.
symlink_test() {
	local c=$1
	shift
	safety_start "$c" "$@"
	docker exec -u 0 "$c" sh -c 'echo 424242 >/run/keepia-test-secret'
	agent -v "$prefix-gen:/g" -- 'ln -s /run/keepia-test-secret /g/.generation.tmp && mv -T /g/.generation.tmp /g/generation'
	wait_log "$c" "keepia-entrypoint: generation file refused: symbolic link" 30
	write_gen "$prefix-gen" '8\n'
	wait_log "$c" "keepia-entrypoint: reload of generation 8 done" 30
	log_lacks "$c" 424242 "the log shows the symlink target's content"
	pass "$name: a symlink in place of generation is refused without its target's content, a later write reloads (T4)"
	docker rm -f "$c" >/dev/null
}

# fifo_test <container> <run options...>: T5.
fifo_test() {
	local c=$1
	shift
	safety_start "$c" "$@"
	agent -v "$prefix-gen:/g" -- 'mkfifo /g/.generation.tmp && mv /g/.generation.tmp /g/generation'
	wait_log "$c" "keepia-entrypoint: generation file refused: fifo" 30
	write_gen "$prefix-gen" '9\n'
	wait_log "$c" "keepia-entrypoint: reload of generation 9 done" 30
	pass "$name: a FIFO in place of generation is refused and does not hang the watcher, a later write reloads (T5)"
	docker rm -f "$c" >/dev/null
}

# content_test <container> <unreadable case: 0|1> <run options...>: T6.
# Each file is handled before the next is written (the n-th refusal), so
# none collapses into another.
content_test() {
	local c=$1 unreadable=$2 bad k=0 n
	shift 2
	safety_start "$c" "$@"
	for bad in '07\n' '12a\n' '12345678901234567890\n' '' '5\n\n' '5\n\n\n' '1\0002\n'; do
		write_gen "$prefix-gen" "$bad"
		k=$((k + 1))
		wait_log_n "$c" "keepia-entrypoint: generation file refused: not a decimal generation (" "$k" 30
	done
	if [ "$unreadable" = 1 ]; then
		# A valid value the service user (not root) cannot read (N4).
		agent -v "$prefix-gen:/g" -- 'umask 077 && echo 11 >/g/.generation.tmp && mv /g/.generation.tmp /g/generation'
		wait_log "$c" "keepia-entrypoint: generation file refused: unreadable" 30
	fi
	write_gen "$prefix-gen" '10\n'
	wait_log "$c" "keepia-entrypoint: reload of generation 10 done" 30
	n=$(log_count "$c" ", reloading")
	[ "$n" = 1 ] || fail "$c: $n reloads, want 1 (10)"
	pass "$name: $k files that are not a decimal generation$([ "$unreadable" = 0 ] || echo ' and an unreadable one') are refused without a reload, a later write reloads (T6)"
	docker rm -f "$c" >/dev/null
}

# The fake service of T1, T2, T8, T10 and T11: test code only, in the test
# volume /t; nothing is added to the image. It loads /cfg/value at its
# start and on SIGHUP. It blocks on the FIFO /tmp/gate until the test
# writes into it; only then does it handle SIGHUP and create /tmp/up (read
# by its reload command) and /tmp/ready (for the ready command). With
# FAKE_AGENT=1 it acts as the agent during its start-up (T1): after it
# loaded its config, it writes "new" and then generation 2.
fake_service='#!/bin/bash
set -u
load() { echo "fake-service: loaded $(cat /cfg/value)" >&2; }
mkfifo /tmp/gate
echo "$$" >/tmp/service.pid
load
if [ "${FAKE_AGENT:-}" = 1 ]; then
	echo new >/cfg/.value.tmp && mv /cfg/.value.tmp /cfg/value
	echo 2 >/gen-rw/.generation.tmp && mv /gen-rw/.generation.tmp /gen-rw/generation
fi
read -r _ </tmp/gate
trap load HUP
touch /tmp/up /tmp/ready
echo "fake-service: up" >&2
while :; do
	sleep infinity &
	wait "$!"
	kill "$!" 2>/dev/null
done'
# Its reload command: SIGHUP to the fake service once it is up. Before
# that it fails with FAKE_RELOAD=fail (T2, T10); else it "succeeds"
# without applying anything (T1), as Postfix would for a HUP before its
# master handles SIGHUP.
fake_reload='#!/bin/bash
if [ ! -e /tmp/up ]; then
	if [ "${FAKE_RELOAD:-}" = fail ]; then
		echo "fake-reload: the service is not up" >&2
		exit 1
	fi
	echo "fake-reload: the service is not up, the signal is lost" >&2
	exit 0
fi
kill -HUP "$(cat /tmp/service.pid)"'
# T11: a stand-in for inotifywait (PATH=/t:...) that holds the watcher in
# its set-up.
fake_inotifywait='#!/bin/sh
echo held >&2
mkfifo /tmp/hold
read -r _ </tmp/hold
exec /usr/bin/inotifywait "$@"'

# fake_volume: the test volume /t with the three files above.
fake_volume() {
	new_volume "$prefix-t"
	printf '%s\n' "$fake_service" | agent -i -v "$prefix-t:/t" -- 'cat >/t/service && chmod 0755 /t/service'
	printf '%s\n' "$fake_reload" | agent -i -v "$prefix-t:/t" -- 'cat >/t/reload && chmod 0755 /t/reload'
	printf '%s\n' "$fake_inotifywait" | agent -i -v "$prefix-t:/t" -- 'cat >/t/inotifywait && chmod 0755 /t/inotifywait'
}

# fake_start <container> [docker run options]: the fake service under the
# watcher. The config volume /cfg holds "old" and the generation volume 1;
# the service can write both (/cfg, /gen-rw) to act as the agent.
fake_start() {
	local c=$1
	shift
	new_volume "$prefix-cfg"
	new_volume "$prefix-gen"
	agent -v "$prefix-cfg:/cfg" -- 'echo old >/cfg/value'
	write_gen "$prefix-gen" '1\n'
	start "$c" --cap-drop ALL -v "$prefix-t:/t:ro" -v "$prefix-cfg:/cfg" \
		-v "$prefix-gen:/run/keepia/generation:ro" -v "$prefix-gen:/gen-rw" \
		-e KEEPIA_RELOAD_COMMAND=/t/reload "$@" "$ref" /t/service
}

# agent_state <value> <generation>: the agent's write of a new state to the
# fake service: the config first, then generation (contract rule 2).
agent_state() {
	agent -v "$prefix-cfg:/cfg" -v "$prefix-gen:/g" -- \
		'echo "$1" >/cfg/.value.tmp && mv /cfg/.value.tmp /cfg/value && echo "$2" >/g/.generation.tmp && mv /g/.generation.tmp /g/generation' \
		sh "$1" "$2"
}

# open_gate <container>: lets the gated service go on.
open_gate() {
	docker exec "$1" sh -c 'echo go >/tmp/gate'
}

# startup_race_test: T1, then T8 in the same container.
startup_race_test() {
	local c=$prefix-race
	fake_start "$c" -e FAKE_AGENT=1 -e "KEEPIA_READY_COMMAND=test -e /tmp/ready"
	wait_log "$c" "fake-service: loaded old" 30
	wait_log "$c" "keepia-entrypoint: generation 2: service not ready" 30
	open_gate "$c"
	# The retry delay may have grown to 16 s by then.
	wait_log "$c" "fake-service: loaded new" 60
	wait_log "$c" "keepia-entrypoint: reload of generation 2 done" 60
	pass "$name: generation 2 written between the config read and readiness is reloaded once the service is ready (T1)"
	# T8: once ready, a red ready command no longer holds a reload.
	docker exec "$c" rm /tmp/ready
	agent_state newer 3
	wait_log "$c" "keepia-entrypoint: reload of generation 3 done" 30
	wait_log "$c" "fake-service: loaded newer" 30
	pass "$name: after the first success the ready command no longer gates a reload (T8)"
	docker rm -f "$c" >/dev/null
}

# retry_test: T2.
retry_test() {
	local c=$prefix-retry
	fake_start "$c" -e FAKE_RELOAD=fail -e KEEPIA_READY_COMMAND=
	wait_log "$c" "fake-service: loaded old" 30
	agent_state new 3
	wait_log "$c" "keepia-entrypoint: reload of generation 3 failed (exit 1), retry" 30
	open_gate "$c"
	wait_log "$c" "fake-service: loaded new" 60
	wait_log "$c" "keepia-entrypoint: reload of generation 3 done" 60
	pass "$name: a failed reload is retried until the service has the new config (T2)"
	docker rm -f "$c" >/dev/null
}

# retry_eof_test: T10, the end of the event stream during a pending retry.
retry_eof_test() {
	local c=$prefix-retry-eof
	fake_start "$c" -e FAKE_RELOAD=fail -e KEEPIA_READY_COMMAND=
	wait_log "$c" "fake-service: loaded old" 30
	agent_state new 3
	wait_log "$c" "keepia-entrypoint: reload of generation 3 failed (exit 1), retry" 30
	watcher_dies "$c" "during a pending retry (T10)"
	docker rm -f "$c" >/dev/null
}

# setup_stop_test: T11, docker stop while the watcher waits for its watch.
setup_stop_test() {
	local c=$prefix-setup-stop path rc
	path=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ref" | awk '/^PATH=/ { print substr($0, 6) }')
	[ -n "$path" ] || fail "the image sets no PATH"
	fake_start "$c" -e "PATH=/t:$path"
	wait_log "$c" "keepia-entrypoint: inotifywait: held" 30
	docker stop -t 20 "$c" >/dev/null
	rc=$(docker inspect -f '{{.State.ExitCode}}' "$c")
	[ "$rc" = 0 ] || fail "$c exited with $rc after docker stop during the set-up, want 0"
	log_lacks "$c" "fake-service:" "the service started before the watch was established"
	log_lacks "$c" "unbound variable" "the watcher failed on an unset variable"
	pass "$name: docker stop during the watcher's set-up exits 0 before the service starts (T11)"
	docker rm -f "$c" >/dev/null
}

# postfix_gate_test: T1b, the real Postfix started only after a generation
# arrived; the reload waits until the master handles SIGHUP.
postfix_gate_test() {
	local c=$prefix-gate pf
	new_volume "$prefix-gen"
	start "$c" "${postfix_caps[@]}" -v "$prefix-gen:/run/keepia/generation:ro" "$ref" \
		sh -c 'mkfifo /tmp/gate && echo "gated-service: waiting" >&2 && read -r _ </tmp/gate && exec postfix start-fg'
	wait_log "$c" "gated-service: waiting" 30
	write_gen "$prefix-gen" '2\n'
	wait_log "$c" "keepia-entrypoint: generation 2: service not ready" 30
	open_gate "$c"
	wait_log "$c" "refreshing the Postfix mail system" 60
	wait_log "$c" "keepia-entrypoint: reload of generation 2 done" 60
	pf=$(docker exec "$c" cat /var/spool/postfix/pid/master.pid)
	pass "$name: generation 2 written before the master ran is reloaded once $(docker exec "$c" /usr/local/bin/keepia-reload-ready) (master.pid: '${pf//[[:space:]]/}' right-aligned in ${#pf} characters) (T1b)"
	docker rm -f "$c" >/dev/null
}

# broken_start_test: T9, a config broken from the start can still be
# reloaded: chroot = y for smtpd only, so every smtpd dies and the probe
# stays red while the master runs. (With chroot = y for every service, as
# in the probe's counter-check, postlogd dies as well, and `postfix
# reload` blocks in postlog before it sends the HUP, with or without the
# watcher.)
broken_start_test() {
	local c=$prefix-broken
	new_volume "$prefix-gen"
	start "$c" "${health_flags[@]}" "${postfix_caps[@]}" -v "$prefix-gen:/run/keepia/generation:ro" --entrypoint sh "$ref" \
		-c "postconf -F 'smtp/inet/chroot = y' && exec /usr/bin/tini -- /usr/local/bin/keepia-reload-watch postfix start-fg"
	wait_health "$c" unhealthy 60
	write_gen "$prefix-gen" '2\n'
	wait_log "$c" "refreshing the Postfix mail system" 60
	wait_log "$c" "keepia-entrypoint: reload of generation 2 done" 60
	pass "$name: with chroot = y for smtpd from the start ($(last_probe "$c")) generation 2 is still reloaded (T9)"
	docker rm -f "$c" >/dev/null
}

# watch_fails_test <run options...>: T7, the service user cannot watch the
# directory (a root-owned tmpfs with mode 0700).
watch_fails_test() {
	local c=$prefix-nowatch rc logs
	start "$c" --tmpfs /run/keepia/generation:mode=0700 "$@" "$ref"
	rc=$(timeout 30 docker wait "$c") || fail "$c still runs 30 s after a watch that cannot be set up"
	[ "$rc" = 1 ] || fail "$c exited with $rc when it could not watch, want 1"
	logs=$(logs_of "$c")
	if [[ $logs != *"keepia-entrypoint: could not watch /run/keepia/generation"* ]]; then
		printf '%s\n' "$logs" | tail -20 >&2
		fail "$c: no 'could not watch' line"
	fi
	pass "$name: a directory it cannot watch exits 1 ($(awk '/inotifywait:/ && !/Setting up watches/ { print; exit }' <<<"$logs")) (T7)"
	docker rm -f "$c" >/dev/null
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
	if want base; then
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
	fi
	if want t3; then watcher_test "$prefix-watch" "refreshing the Postfix mail system" "${postfix_caps[@]}"; fi
	if want t4; then symlink_test "$prefix-symlink" "${postfix_caps[@]}"; fi
	if want t5; then fifo_test "$prefix-fifo" "${postfix_caps[@]}"; fi
	if want t6; then content_test "$prefix-content" 0 "${postfix_caps[@]}"; fi
	if want t1 || want t2 || want t10 || want t11; then fake_volume; fi
	if want t1; then startup_race_test; fi
	if want t2; then retry_test; fi
	if want t10; then retry_eof_test; fi
	if want t11; then setup_stop_test; fi
	if want t1b; then postfix_gate_test; fi
	if want t9; then broken_start_test; fi
	if want base; then stop_test "$prefix-stop" "${postfix_caps[@]}"; fi
	;;
unbound)
	if want base; then
		docker run --rm --name "$prefix-smoke" --network none --entrypoint unbound-checkconf "$ref"
		pass "smoke: unbound-checkconf"
		print_packages
		check_config 10053:10053
		health_cycle "$prefix-health" 0000000000000000 --cap-drop ALL
	fi
	if want t3; then watcher_test "$prefix-watch" "Restart of unbound" --cap-drop ALL; fi
	if want t4; then symlink_test "$prefix-symlink" --cap-drop ALL; fi
	if want t5; then fifo_test "$prefix-fifo" --cap-drop ALL; fi
	if want t6; then content_test "$prefix-content" 1 --cap-drop ALL; fi
	if want t7; then watch_fails_test --cap-drop ALL; fi
	if want base; then stop_test "$prefix-stop" --cap-drop ALL; fi
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
