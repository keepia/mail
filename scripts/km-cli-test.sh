#!/usr/bin/env bash
# Test 7b (#95 part 2): the operator CLI through ./km in the running
# Compose template. The CI compose job runs it after test 7 (./km migrate)
# and before test 7's counter-case, which recreates postgres. It needs the
# template's control and store roles running (scripts/compose-test.sh
# leaves them up) and uses `docker compose exec` only, never `compose run`
# (.claude/rules/docker.md).
#
#  1. psql adds one server with the role store and one active store
#     (placeholder names, the documentation address 192.0.2.10).
#  2. ./km adds a group, a domain and a mailbox with a CI-only password on
#     --password-stdin; ./km mailbox list shows the store and ARGON2ID.
#  3. ./km mailbox set <addr> --store x exits 64 with `error: unknown flag:
#     --store`, and nothing looks like a crash of keepia-mail (exit 2,
#     "panic: ", "fatal error: ", "goroutine N [").
#  4. Dovecot interoperability, both ways: the stored hash, read with
#     psql, passes `doveadm pw -t` in store-dovecot; a hash that `doveadm
#     pw -s ARGON2ID` writes with its default cost (no -r) is accepted by
#     mailbox add --password-hash-stdin. Its parameters are printed.
#  5. Two mailbox adds with a password run at the same time and both exit
#     0 (the hash lock queues them).
#  6. keepia was not OOM-killed (State.OOMKilled false, RestartCount and
#     the cgroup's memory.events oom_kill unchanged), and the keepia
#     cgroup's memory.peak, read from the runner and printed before and
#     after, stays under 192 MiB (#111, C6).
#
# No password or hash is printed: they are CI-only placeholders, and the
# script does not run under `set -x`.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
	echo "km-cli-test: $*" >&2
	exit 1
}

# psql in the postgres container, on its socket; prints tuples only.
psql_q() {
	docker compose exec -T postgres psql -X -q -t -A -v ON_ERROR_STOP=1 -U keepia -d keepia -c "$1"
}

# CI-only placeholders: no real password, and no real user's.
pw_a='ci-7b-placeholder-alpha'
pw_b='ci-7b-placeholder-bravo'
pw_c='ci-7b-placeholder-charlie'
limit=$((192 * 1024 * 1024))

keepia=$(docker compose ps -q keepia)
[ -n "$keepia" ] || fail "keepia is not running"
id=$(docker inspect -f '{{.Id}}' "$keepia")
cg=
for d in "/sys/fs/cgroup/system.slice/docker-$id.scope" "/sys/fs/cgroup/docker/$id"; do
	if [ -r "$d/memory.peak" ]; then
		cg=$d
		break
	fi
done
[ -n "$cg" ] || fail "no memory.peak for keepia's cgroup (cgroup v2, kernel 5.19 or later)"

# oom_kills prints the oom_kill count of keepia's cgroup.
oom_kills() {
	local key value
	while read -r key value; do
		if [ "$key" = oom_kill ]; then
			echo "$value"
			return
		fi
	done <"$cg/memory.events"
	echo 0
}

read -r restarts0 < <(docker inspect -f '{{.RestartCount}}' "$keepia")
ooms0=$(oom_kills)
echo "keepia memory.peak before: $(<"$cg/memory.peak") bytes (limit for this test: $limit)"

# 1. A store server and an active store, as N2 and N4 will add them.
psql_q "INSERT INTO servers (name, roles) VALUES ('ci-store', '{store}');
	INSERT INTO stores (server_id, gate_name, gate_ipv4, egress_port, state)
	SELECT id, 'ci-store.store.keepia.internal', '192.0.2.10', 2001, 'active' FROM servers WHERE name = 'ci-store';"

# 2. Group, domain and a mailbox with a new password, all through ./km.
out=$(./km group add ci)
[ "$out" = "group ci added" ] || fail "group add: $out"
out=$(./km domain add example.org --group ci)
[ "$out" = "domain example.org added to group ci" ] || fail "domain add: $out"
out=$(printf '%s\n' "$pw_a" | ./km mailbox add alice@example.org --quota 1GiB --password-stdin)
[ "$out" = "mailbox alice@example.org added on store ci-store.store.keepia.internal" ] || fail "mailbox add: $out"
list=$(./km mailbox list)
echo "$list"
grep -Eq '^alice@example\.org +ci +ci-store\.store\.keepia\.internal +1GiB +true +true +true +active +ARGON2ID$' <<<"$list" ||
	fail "mailbox list does not show alice on the store with ARGON2ID"

# 3. No --store on set: a usage error, exit 64, and no crash.
rc=0
out=$(./km mailbox set alice@example.org --store x 2>&1) || rc=$?
echo "mailbox set --store: exit $rc: $out"
[ "$rc" = 64 ] || fail "mailbox set --store exited $rc, want 64"
grep -qx 'error: unknown flag: --store' <<<"$out" || fail "no line 'error: unknown flag: --store'"
if grep -Eq '^(panic: |fatal error: |goroutine [0-9]+ \[)' <<<"$out"; then
	fail "keepia-mail crashed"
fi

# 4. Dovecot reads keepia-mail's hash, and keepia-mail takes Dovecot's.
docker compose exec -T store-dovecot doveadm pw -l | grep -qw ARGON2ID ||
	fail "doveadm pw -l lists no ARGON2ID in the store's Dovecot"
hash=$(psql_q "SELECT m.password_hash FROM mailboxes m JOIN domains d ON d.id = m.domain_id
	WHERE d.name = 'example.org' AND m.local_part = 'alice'")
docker compose exec -T store-dovecot doveadm pw -t "$hash" -p "$pw_a" >/dev/null ||
	fail "doveadm pw -t does not verify keepia-mail's Argon2id hash"
echo "doveadm pw -t verified keepia-mail's hash ($(cut -d'$' -f1-4 <<<"$hash")\$...)"
dhash=$(docker compose exec -T store-dovecot doveadm pw -s ARGON2ID -p "$pw_b")
echo "doveadm pw -s ARGON2ID writes $(cut -d'$' -f1-4 <<<"$dhash")\$<salt>\$<hash>"
out=$(printf '%s\n' "$dhash" | ./km mailbox add bob@example.org --quota 1GiB --password-hash-stdin)
[ "$out" = "mailbox bob@example.org added on store ci-store.store.keepia.internal" ] || fail "import of doveadm's hash: $out"
stored=$(psql_q "SELECT m.password_hash FROM mailboxes m JOIN domains d ON d.id = m.domain_id
	WHERE d.name = 'example.org' AND m.local_part = 'bob'")
[ "$stored" = "$dhash" ] || fail "the imported hash was not stored as given"

# 5. Two password adds at once: both succeed, one hash after the other.
printf '%s\n' "$pw_c" | ./km mailbox add carol@example.org --quota 1GiB --password-stdin &
p1=$!
printf '%s\n' "$pw_c" | ./km mailbox add dave@example.org --quota 1GiB --password-stdin &
p2=$!
rc1=0 rc2=0
wait "$p1" || rc1=$?
wait "$p2" || rc2=$?
[ "$rc1" = 0 ] && [ "$rc2" = 0 ] || fail "concurrent password adds exited $rc1 and $rc2"
n=$(psql_q "SELECT count(*) FROM mailboxes
	WHERE local_part IN ('alice', 'carol', 'dave') AND password_hash LIKE '{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$%'")
[ "$n" = 3 ] || fail "$n new Argon2id hashes, want 3 (alice, carol, dave)"

# 6. keepia survived, within the memory limit of this test.
peak=$(<"$cg/memory.peak")
echo "keepia memory.peak after: $peak bytes ($((peak / 1024 / 1024)) MiB)"
read -r oomkilled restarts1 < <(docker inspect -f '{{.State.OOMKilled}} {{.RestartCount}}' "$keepia")
ooms1=$(oom_kills)
echo "keepia: OOMKilled $oomkilled, restarts $restarts0 -> $restarts1, oom_kill $ooms0 -> $ooms1"
[ "$oomkilled" = false ] || fail "keepia was OOM-killed"
[ "$restarts1" = "$restarts0" ] || fail "keepia restarted"
[ "$ooms1" = "$ooms0" ] || fail "the kernel OOM-killed a process in keepia's cgroup"
[ "$peak" -lt "$limit" ] || fail "memory.peak $peak is not under $limit bytes"
echo "km-cli-test: ok"
