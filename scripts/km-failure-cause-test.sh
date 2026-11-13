#!/bin/sh
# Tests scripts/km-failure-cause.sh, which names why ./km failed in test 7's
# counter-case (#69). No Docker, no network. Run it with
# `make image-scripts-test`.
#
# It feeds the classifier km's outputs one by one. The accepted ones are
# the exec's messages seen when km's exec meets a keepia in its restart
# loop, behind the trace of a km that reached its exec: in CI (Engine
# 28.0.4: "is restarting", "cannot exec in a stopped container", and
# migrate's own SQLSTATE 28P01) and in 400 local runs of km's up and exec
# against a container that exits 30 ms after each start (Engine 29.9.2,
# containerd 2.4.2, runc 1.5.2). The refused ones are every other reason.
# TestKmFailureCause (cmd/keepia-mail/km_test.go) runs the real ./km with
# sh -x and a fake docker through the classifier, so a change of km's exec
# line, which the classifier looks for, fails there.
set -u

cd "$(dirname "$0")/.."
# KM_FAILURE_CAUSE: another classifier (a counter-proof).
classify=${KM_FAILURE_CAUSE:-scripts/km-failure-cause.sh}
shell=$(command -v dash || command -v sh)

failed=0
n=0
id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
trace="+ cd .
+ docker version --format {{.Server.Version}}
+ docker compose --progress quiet config --images postgres keepia
+ images=ghcr.io/keepia/mail:dev
+ set -f
+ docker image inspect -- ghcr.io/keepia/mail:dev
+ set +f
+ docker compose --progress quiet up -d --wait --no-build --pull never postgres
+ docker compose --progress quiet up -d --no-build --pull never keepia
+ exec docker compose --progress quiet exec -T keepia keepia-mail migrate status"

# check <ok|fail> <exit status> <output> <what>
check() {
	n=$((n + 1))
	msg=$($shell "$classify" "$2" "$3")
	rc=$?
	case $1 in
	ok) want=0 ;;
	fail) want=1 ;;
	esac
	if [ "$rc" = "$want" ]; then
		echo "ok   $1, $4: $msg"
	else
		echo "FAIL want $1, $4; got exit $rc: $msg" >&2
		failed=$((failed + 1))
	fi
}

# exec <ok|fail> <exit status> <exec output>: km reached its exec.
exec_case() {
	check "$1" "$2" "$trace
$3" "exit $2: $(printf '%s' "$3" | head -n 1 | cut -c1-60)"
}

# ---- Part 1: accepted, km's exec met keepia's restart loop ----
# Refused while restarting (CI, and 273 of the 400 local runs).
exec_case ok 1 "Error response from daemon: Container $id is restarting, wait until the container is running"
# migrate ran in a live run of keepia and failed its own login (CI).
exec_case ok 1 'error: connect to database: failed to connect to `user=keepia database=keepia`: 172.29.1.11:5432 (172.29.1.11): failed SASL auth: FATAL: password authentication failed for user "keepia" (SQLSTATE 28P01)'
# The run of keepia the exec entered exited on the way (#69: CI runs
# 43290615323 and 43303299019, and locally).
exec_case ok 128 'OCI runtime exec failed: exec failed: cannot exec in a stopped container'
exec_case ok 128 'OCI runtime exec failed: exec failed: unable to start container process: error writing config to pipe: write init-p: broken pipe'
exec_case ok 137 ''
exec_case ok 128 'OCI runtime exec failed: exec failed: unable to start container process: procReady not received'
exec_case ok 128 'cannot exec in a stopped state'
exec_case ok 128 'OCI runtime exec failed: exec failed: unable to start container process: reading from parent failed: fetch packet length from socket: recvfrom: connection reset by peer'
exec_case ok 1 'unable to upgrade to tcp, received 409'
exec_case ok 1 "failed to open stdin fifo: error creating fifo /run/docker/containerd/$id/$id-stdin: no such file or directory
Error response from daemon: No such exec instance: $id"
exec_case ok 127 'OCI runtime exec failed: exec failed: unable to start container process: error executing setns process: exit status 1; runc init error(s): nsexec-1[6564]: failed to open /proc/6512/ns/ipc: No such file or directory; nsexec-0[6563]: failed to sync with stage-1: next state (got 0 of 4 bytes)'
exec_case ok 128 "FailedPrecondition: container $id init process is not running: failed precondition"
# Seen by Review B in its own loop (14 of 230 runs; message abridged there).
exec_case ok 127 'OCI runtime exec failed: exec failed: unable to create new parent process: namespace path …'

# ---- Part 1: refused, every other reason ----
# km succeeded.
check fail 0 "$trace
00001_baseline.sql   applied   2026-11-12" "km succeeded"
# keepia-mail ran and failed for another reason, also with a runtime
# message beside it.
exec_case fail 1 'error: connect to database: failed to connect to `user=keepia database=keepia`: 172.29.1.11:5432 (172.29.1.11): dial error: dial tcp 172.29.1.11:5432: connect: connection refused'
exec_case fail 1 'error: migrate: relation "goose_db_version" does not exist (SQLSTATE 42P01)'
exec_case fail 137 'error: unknown command "migrate" for "keepia-mail"
OCI runtime exec failed: exec failed: cannot exec in a stopped container'
# keepia-mail crashed (#70, B1): the Go runtime exits 2 on a panic or a
# fatal error and prints no "error:" line; keepia-mail's main exits only 0
# or 1, and no runtime answer to the restart loop exits 2.
exec_case fail 2 'panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x6a2f1c]

goroutine 1 [running]:
main.runMigrate(...)'
exec_case fail 2 'fatal error: concurrent map writes'
exec_case fail 2 ''
exec_case fail 137 'goroutine 7 [chan receive]:'
# A traced line after km's exec line (#70, N1): km's exec is its last
# command, so such a line can only come from a traced value with a
# newline in it.
exec_case fail 1 "+ docker compose --progress quiet up -d --no-build --pull never keepia
Error response from daemon: Container $id is restarting, wait until the container is running"
# km stopped before its exec: no traced exec line, whatever the message,
# even one that names a restarting container or the wrong password.
check fail 1 "+ cd .
+ docker version --format {{.Server.Version}}
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
km: the Docker daemon is not reachable (see docker's error above)." "daemon not reachable"
check fail 1 "+ docker image inspect -- ghcr.io/keepia/mail:dev
km: the image ghcr.io/keepia/mail:dev (Compose service postgres or keepia, or a service they depend on) is missing." "image missing"
check fail 1 "+ docker compose --progress quiet up -d --wait --no-build --pull never postgres
container keepia-postgres-1 is restarting, wait until the container is running
dependency failed to start: container keepia-postgres-1 is unhealthy" "postgres up failed"
check fail 1 "+ docker compose --progress quiet up -d --no-build --pull never keepia
Error response from daemon: password authentication failed (SQLSTATE 28P01)" "keepia up failed"
# An exec line that is not km's.
check fail 1 "+ exec docker compose exec -T postgres psql
Error response from daemon: Container $id is restarting, wait until the container is running" "another exec"
check fail 1 "" "no output"

if [ "$failed" != 0 ]; then
	echo "km-failure-cause: $failed of $n cases failed" >&2
	exit 1
fi
echo "km-failure-cause: all $n cases passed"
