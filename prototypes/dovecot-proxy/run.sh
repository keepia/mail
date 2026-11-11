#!/usr/bin/env bash
# Throwaway prototype for #3: runs checks 0-8 of the plan against the Compose
# project keepia-proto3 and prints a transcript (command, output, PASS/FAIL).
# Exits non-zero on the first FAIL. On exit (also on failure) it runs
# `docker compose down -v --rmi local`, removes the Postfix image and the
# untracked .run/ copies, unless --keep is given.
#
# Usage: ./run.sh [--keep]
# Behind a TLS-inspecting proxy, set PROTO3_CA_BUNDLE to a CA bundle file; the
# Postfix image is then built with it as a BuildKit secret (see README).
#
# Waits are bounded polls on a signal (a log line, a queue entry, an open
# port, a protocol reply) with a deadline that fails the check.
set -uo pipefail
cd "$(dirname "$0")" || exit 2

KEEP=0
for a in "$@"; do
	case $a in
	--keep) KEEP=1 ;;
	*) echo "usage: run.sh [--keep]" >&2; exit 2 ;;
	esac
done

P=keepia-proto3
SESS_LOG=.run/session.log
C() { docker compose -p "$P" "$@"; }
X() { local s=$1; shift; docker compose -p "$P" exec -T "$s" "$@"; }
E() { docker compose -p "$P" exec -T postfix "$@"; }

check() { printf '\n=== %s\n' "$*"; }
step() { printf '$ %s\n' "$*"; }
show() { sed 's/^/  /'; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
# run <cmd...>: prints the command and its indented output; returns its status.
run() { step "$*"; "$@" 2>&1 | show; return "${PIPESTATUS[0]}"; }

# Logs: mark <svc> is the current line count, since <svc> <mark> the lines
# after it.
logs() { C logs --no-color --no-log-prefix "$1" 2>/dev/null; }
mark() { logs "$1" | wc -l; }
since() { logs "$1" | tail -n +"$(($2 + 1))"; }
# The log is read into a variable first: with pipefail, grep -q closing the
# pipe early would make a match look like a failure (SIGPIPE, 141).
has() { local l; l=$(since "$1" "$2"); grep -qE "$3" <<<"$l"; }
count() { local l; l=$(since "$1" "$2"); grep -cE "$3" <<<"$l"; }
lines() { local l; l=$(since "$1" "$2"); grep -E "$3" <<<"$l" | show; }

# wait_until <seconds> <what> <cmd...>: polls every 0.5 s; FAIL at the deadline.
wait_until() {
	local dl=$1 what=$2 end
	shift 2
	end=$((SECONDS + dl))
	until "$@" >/dev/null 2>&1; do
		[ "$SECONDS" -ge "$end" ] && fail "no $what within ${dl}s"
		sleep 0.5
	done
}
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }

# curl_v <url> <user> <password>: curl -v through the Postfix container; only
# the protocol lines (capability lists cut), plus curl's own error line.
curl_v() {
	E curl -v --max-time 60 --user "$2:$3" "$1" 2>&1 |
		grep -E '^(< |> |curl: )' | grep -v 'CAPABILITY' | cut -c1-160
}

# curl_step <-v|-s> <url> <user> <password> [note]: prints a curl command.
# curl_s <url> <user> <password>: curl -s through the Postfix container.
# User and password stay separate arguments throughout.
curl_step() { step "E curl $1 --user $3:$4 $2${5:+  ($5)}"; }
curl_s() { E curl -s --max-time 60 --user "$2:$3" "$1"; }

# A line-based client session (IMAP, ManageSieve) that waits for each reply.
sess_open() {
	coproc SESS { docker compose -p "$P" exec -T postfix nc 172.30.3.10 "$1" 2>&1; }
	SESS_PID_SAVED=$SESS_PID
	exec {SR}<&"${SESS[0]}" {SW}>&"${SESS[1]}"
}
# A write after the server closed must not kill the script (SIGPIPE).
sess_send() { printf '  > %s\n' "$1"; (trap '' PIPE; printf '%s\r\n' "$1" >&"$SW") 2>/dev/null; }
# sess_expect <regex> [seconds]: prints reply lines until one matches.
sess_expect() {
	local re=$1 end=$((SECONDS + ${2:-20})) line left
	while :; do
		left=$((end - SECONDS))
		[ "$left" -le 0 ] && return 1
		IFS= read -r -t "$left" line <&"$SR" || return 1
		line=${line%$'\r'}
		printf '  < %s\n' "$(printf '%s' "$line" | cut -c1-160)"
		[[ $line =~ $re ]] && return 0
	done
}
sess_close() {
	exec {SW}>&-
	kill "$SESS_PID_SAVED" 2>/dev/null
	wait "$SESS_PID_SAVED" 2>/dev/null
	exec {SR}<&-
	SESS_PID_SAVED=
}

# curl -v does not print the server's final NO/-ERR line of a failed login,
# so the failure texts come from these dialogs, which wait for each reply.
# imap_login <user> <password>
imap_login() {
	step "E nc 172.30.3.10 143  (IMAP LOGIN $1)"
	sess_open 143
	sess_expect '^\* (OK|BYE)' 15 || { sess_close; return 1; }
	sess_send "a LOGIN $1 $2"
	if sess_expect '^a (OK|NO|BAD)' 60 | tee "$SESS_LOG"; then :; fi
	if grep -q '< a OK' "$SESS_LOG"; then
		sess_send 'b LIST "" "*"'
		sess_expect '^b ' 15
	fi
	sess_send 'z LOGOUT'
	sess_expect '^z ' 15
	sess_close
	return 0
}
# pop3_login <user> <password>
pop3_login() {
	step "E nc 172.30.3.10 110  (POP3 USER/PASS $1)"
	sess_open 110
	sess_expect '^(\+OK|-ERR)' 15 || { sess_close; return 1; }
	sess_send "USER $1"
	sess_expect '^(\+OK|-ERR)' 15
	sess_send "PASS $2"
	sess_expect '^(\+OK|-ERR)' 60
	sess_send 'QUIT'
	sess_expect '^(\+OK|-ERR)' 15
	sess_close
	return 0
}

# mail <rcpt> <message-id>: a synthetic message through Postfix's sendmail.
mail() {
	step "printf 'From: sender@example.test ... Message-ID: <$2>' | E sendmail -f sender@example.test $1"
	printf 'From: sender@example.test\nTo: %s\nSubject: keepia-proto3 %s\nMessage-ID: <%s>\n\nSynthetic test message.\n' \
		"$1" "$2" "$2" | E sendmail -f sender@example.test "$1"
}
# msgid_on <store> <user> <message-id>: number of messages with that id.
msgid_on() {
	X "$1" doveadm search -u "$2" mailbox INBOX header message-id "$3" 2>/dev/null | grep -c .
}

# Edge restart that waits for its listeners (signal: the LMTP and IMAP ports).
edge_restart() {
	run C restart edge || fail "edge restart"
	wait_until 30 "edge LMTP listener" X edge nc -z 127.0.0.1 24
	wait_until 30 "edge IMAP listener" X edge nc -z 127.0.0.1 143
}

MAIN_PID=$BASHPID
CLEANED=0
cleanup() {
	local rc=$?
	# Only the main shell cleans up, and only once.
	[ "$BASHPID" = "$MAIN_PID" ] && [ "$CLEANED" = 0 ] || exit "$rc"
	CLEANED=1
	[ -n "${SESS_PID_SAVED:-}" ] && kill "$SESS_PID_SAVED" 2>/dev/null
	if [ "$KEEP" = 1 ]; then
		printf '\n--keep: project %s left running; clean up with ./run.sh after\n' "$P"
		printf 'docker compose -p %s down -v --rmi local; docker image rm keepia-proto3-postfix\n' "$P"
		exit "$rc"
	fi
	printf '\n=== Cleanup\n'
	run docker compose -p keepia-proto3 down -v --rmi local
	run docker image rm keepia-proto3-postfix
	rm -f .run/session.log
	rm -f .run/routing/routing.passwd .run/store/users.passwd .run/edge.d/cache.conf .run/edge.d/storage.conf
	rmdir .run/routing .run/store .run/edge.d .run
	exit "$rc"
}
trap cleanup EXIT

###########################################################################
check "0. Start"
mkdir -p .run/routing .run/store .run/edge.d
cp edge/routing/routing.passwd .run/routing/routing.passwd
cp store/users.passwd .run/store/users.passwd
if [ -n "${PROTO3_CA_BUNDLE:-}" ]; then
	run docker build -q --network host --build-arg HTTPS_PROXY \
		--secret id=ca,src="$PROTO3_CA_BUNDLE" -t keepia-proto3-postfix ./postfix ||
		fail "Postfix image build"
else
	run docker build -q -t keepia-proto3-postfix ./postfix || fail "Postfix image build"
fi
run C up -d --wait || fail "compose up --wait"
pass "docker compose up -d --wait returned 0"
v=$(X edge dovecot --version | tr -d '\r')
step "X edge dovecot --version"; echo "  $v"
[ "$v" = "2.4.5 (0cbb641)" ] || fail "dovecot version"
pass "edge runs 2.4.5 (0cbb641)"
run E dpkg-query -W postfix curl netcat-openbsd
for s in edge store-a store-b; do
	run X "$s" doveconf -n || fail "doveconf -n on $s"
done
pass "doveconf -n exits 0 on edge, store-a, store-b"
step "X edge doveconf -n | grep -E '^mail_(driver|home|path)'"
m=$(X edge doveconf -n | grep -E '^mail_(driver|home|path)')
[ -z "$m" ] || { echo "$m" | show; fail "edge has mail storage settings"; }
echo "  (no output)"
pass "edge has no mail_driver, mail_home or mail_path"
for uh in alice:172.30.3.21 bob:172.30.3.22; do
	u=${uh%%:*} h=${uh#*:}
	out=$(X edge doveadm auth lookup "$u@example.test")
	step "X edge doveadm auth lookup $u@example.test"; echo "$out" | show
	grep -qE '^ *proxy *: y' <<<"$out" && grep -qE "^ *host *: $h\$" <<<"$out" ||
		fail "routing lookup for $u"
	pass "$u routes to $h (proxy : y)"
done
out=$(X edge doveadm auth lookup carol@example.test)
step "X edge doveadm auth lookup carol@example.test"; echo "$out" | show
grep -q proxy <<<"$out" && fail "carol has proxy fields"
pass "carol's routing line has no proxy fields"

echo "--- counter-proof 0: a routing line with 6 colons is not proxied"
step "echo 'dave@example.test::::::proxy=y host=172.30.3.21 nopassword=y' >> .run/routing/routing.passwd"
echo 'dave@example.test::::::proxy=y host=172.30.3.21 nopassword=y' >>.run/routing/routing.passwd
# The edge rereads the file about once a second: wait until it knows dave.
dave_known() { X edge doveadm auth lookup dave@example.test | grep -qE '^ *user *: dave@example.test$'; }
wait_until 30 "routing line for dave" dave_known
out=$(X edge doveadm auth lookup dave@example.test)
step "X edge doveadm auth lookup dave@example.test"; echo "$out" | show
grep -q proxy <<<"$out" && fail "counter-proof 0: 6-colon line was proxied"
pass "counter-proof 0: the 6-colon line returns no proxy/host, so check 0 catches a wrong colon count"
sed -i '/^dave@/d' .run/routing/routing.passwd

###########################################################################
check "1. IMAP through the edge, two stores"
for uss in alice:a:b:21 bob:b:a:22; do
	IFS=: read -r u own other ip <<<"$uss"
	mE=$(mark edge) mO=$(mark "store-$own") mX=$(mark "store-$other")
	curl_step -v imap://172.30.3.10/ "$u@example.test" "$u-test-only"
	out=$(curl_v imap://172.30.3.10/ "$u@example.test" "$u-test-only"); echo "$out" | show
	grep -q "LIST .* store-$own" <<<"$out" && ! grep -q "store-$other" <<<"$out" ||
		fail "$u: LIST does not name store-$own only"
	pass "$u: LIST names INBOX and store-$own"
	wait_until 10 "edge proxy line for $u" has edge "$mE" "imap-login: .*proxy\($u@example.test,172.30.3.$ip:143\): Started"
	lines edge "$mE" "proxy\($u@example.test"
	wait_until 10 "store-$own login for $u" has "store-$own" "$mO" "imap-login: Info: Logged in: user=<$u@example.test>"
	lines "store-$own" "$mO" "imap-login: Info: Logged in: user=<$u@example.test>"
	has "store-$other" "$mX" "Logged in: user=<$u@example.test>" && fail "$u logged in on store-$other"
	pass "$u: edge proxies to 172.30.3.$ip:143; login on store-$own only"
done
echo "--- counter-proof 1: wrong password"
mE=$(mark edge)
out=$(imap_login alice@example.test wrong-password); echo "$out"
grep -q '< a NO \[AUTHENTICATIONFAILED\]' <<<"$out" || fail "counter-proof 1: no AUTHENTICATIONFAILED"
wait_until 15 "proxy_dest_auth_failed" has edge "$mE" "proxy_dest_auth_failed"
lines edge "$mE" "proxy_dest_auth_failed"
pass "counter-proof 1: [AUTHENTICATIONFAILED]; the edge logs proxy_dest_auth_failed (the store judged the password)"

###########################################################################
check "2. POP3 through the edge"
for uss in alice:a:b:21 bob:b:a:22; do
	IFS=: read -r u own other ip <<<"$uss"
	mE=$(mark edge) mO=$(mark "store-$own") mX=$(mark "store-$other")
	curl_step -v pop3://172.30.3.10/ "$u@example.test" "$u-test-only"
	out=$(curl_v pop3://172.30.3.10/ "$u@example.test" "$u-test-only"); echo "$out" | show
	grep -q '^< +OK' <<<"$out" && ! grep -qE '^< -ERR|^curl: ' <<<"$out" || fail "$u: POP3 failed"
	wait_until 10 "edge pop3 proxy line for $u" has edge "$mE" "pop3-login: .*proxy\($u@example.test,172.30.3.$ip:110\): Started"
	lines edge "$mE" "proxy\($u@example.test"
	wait_until 10 "store-$own pop3 login" has "store-$own" "$mO" "pop3-login: Info: Logged in: user=<$u@example.test>"
	lines "store-$own" "$mO" "pop3-login: Info: Logged in: user=<$u@example.test>"
	has "store-$other" "$mX" "Logged in: user=<$u@example.test>" && fail "$u logged in on store-$other"
	pass "$u: POP3 through the edge to 172.30.3.$ip:110; login on store-$own only (empty maildrop)"
done
echo "--- counter-proof 2: wrong password"
mE=$(mark edge)
out=$(pop3_login bob@example.test wrong-password); echo "$out"
grep -q '< -ERR \[AUTH\]' <<<"$out" || fail "counter-proof 2: no -ERR [AUTH]"
wait_until 15 "proxy_dest_auth_failed" has edge "$mE" "pop3-login: .*proxy_dest_auth_failed"
lines edge "$mE" "proxy_dest_auth_failed"
pass "counter-proof 2: -ERR [AUTH]; the edge logs proxy_dest_auth_failed"

###########################################################################
check "3. LMTP delivery lands on the right store"
for uss in alice:a:b bob:b:a; do
	IFS=: read -r u own other <<<"$uss"
	mP=$(mark postfix)
	mail "$u@example.test" "c3-$u@example.test"
	wait_until 60 "Postfix result for $u" has postfix "$mP" "to=<$u@example.test>.*status="
	lines postfix "$mP" "to=<$u@example.test>"
	has postfix "$mP" "to=<$u@example.test>, relay=172.30.3.10\[172.30.3.10\]:24, .*status=sent \(250 2.0.0 <$u@example.test> .* Saved\)" ||
		fail "$u: not sent through the edge"
	run X "store-$own" doveadm fetch -u "$u@example.test" hdr.message-id all
	[ "$(msgid_on "store-$own" "$u@example.test" "c3-$u@example.test")" = 1 ] || fail "$u: message not on store-$own"
	run X "store-$other" doveadm mailbox status -u "$u@example.test" messages INBOX
	[ "$(msgid_on "store-$other" "$u@example.test" "c3-$u@example.test")" = 0 ] || fail "$u: message on store-$other"
	st=$(X "store-$other" doveadm mailbox status -u "$u@example.test" messages INBOX)
	grep -q 'messages=0' <<<"$st" || fail "$u: store-$other not empty"
	pass "$u: status=sent through 172.30.3.10:24, exactly once on store-$own, messages=0 on store-$other"
done
curl_step -v pop3://172.30.3.10/ alice@example.test alice-test-only "check 2 after delivery"
out=$(curl_v pop3://172.30.3.10/ alice@example.test alice-test-only); echo "$out" | show
st=$(curl_s pop3://172.30.3.10/ alice@example.test alice-test-only)
grep -qE '^1 [0-9]+' <<<"$st" || fail "POP3 list after delivery"
pass "POP3 LIST for alice now has one message"
echo "--- counter-proof 3: in check 5 the same store-b count for alice turns 1 after a re-routed delivery"

###########################################################################
check "4. ManageSieve through the edge"
sieve() { # <user> <password> <expected reply regex>
	local b64
	b64=$(printf '\0%s\0%s' "$1" "$2" | base64 -w0)
	step "E nc 172.30.3.10 4190  (waits for each reply)"
	sess_open 4190
	sess_expect '^OK' 15 || fail "no ManageSieve greeting"
	sess_send "AUTHENTICATE \"PLAIN\" \"$b64\""
	sess_expect '^(OK|NO|BYE)' 30 || fail "no AUTHENTICATE reply"
	if [[ $3 == OK ]]; then
		sess_send 'LISTSCRIPTS'
		sess_expect '^(OK|NO|BYE)' 15 || fail "no LISTSCRIPTS reply"
	fi
	sess_send 'LOGOUT'
	sess_expect '^(OK|NO|BYE)' 15
	sess_close
}
mE=$(mark edge) mA=$(mark store-a) mB=$(mark store-b)
out=$(sieve alice@example.test alice-test-only OK); echo "$out"
grep -q '< OK "Logged in."' <<<"$out" || fail "ManageSieve login"
grep -q '< OK "Listscripts completed."' <<<"$out" || fail "LISTSCRIPTS"
wait_until 10 "edge 4190 proxy line" has edge "$mE" "managesieve-login: .*proxy\(alice@example.test,172.30.3.21:4190\): Started"
lines edge "$mE" "proxy\(alice@example.test"
wait_until 10 "store-a managesieve login" has store-a "$mA" "managesieve-login: .*user=<alice@example.test>"
lines store-a "$mA" "managesieve-login: .*user=<alice@example.test>"
has store-b "$mB" "user=<alice@example.test>" && fail "alice on store-b"
pass "ManageSieve: OK \"Logged in.\" and LISTSCRIPTS through the edge to 172.30.3.21:4190"
echo "--- counter-proof 4: wrong password"
mE=$(mark edge)
out=$(sieve alice@example.test wrong-password NO); echo "$out"
grep -qE '< NO' <<<"$out" || fail "counter-proof 4: no NO"
wait_until 15 "proxy_dest_auth_failed" has edge "$mE" "managesieve-login: .*proxy_dest_auth_failed"
lines edge "$mE" "proxy_dest_auth_failed"
pass "counter-proof 4: NO; the edge logs proxy_dest_auth_failed"

###########################################################################
check "5. Store change re-routes the next login"
mE=$(mark edge)
step "E nc 172.30.3.10 143  (alice's session, kept open)"
sess_open 143
sess_expect '^\* OK' 15 || fail "no IMAP greeting"
sess_send 'a LOGIN alice@example.test alice-test-only'
out=$(sess_expect '^a (OK|NO|BAD)' 30); echo "$out"
grep -q '^  < a OK' <<<"$out" || fail "IMAP login (open session)"
sess_send 'b LIST "" "store-*"'
sess_expect '^b ' 15 || fail "LIST in the open session"
wait_until 10 "edge line for the open session" has edge "$mE" "proxy\(alice@example.test,172.30.3.21:143\): Started"
lines edge "$mE" "proxy\(alice@example.test"
run sed -i '/^alice@/s/host=172.30.3.21/host=172.30.3.22/' .run/routing/routing.passwd
t0=$(now)
run grep '^alice@' .run/routing/routing.passwd
lookup22() { X edge doveadm auth lookup alice@example.test | grep -qE '^ *host *: 172.30.3.22$'; }
wait_until 30 "re-routed lookup" lookup22
out=$(X edge doveadm auth lookup alice@example.test)
step "X edge doveadm auth lookup alice@example.test  (polled until it changed: $(elapsed "$t0") s after the edit)"
echo "$out" | show
pass "the lookup returns host 172.30.3.22 without a restart"
mE=$(mark edge)
curl_step -v imap://172.30.3.10/ alice@example.test alice-test-only
out=$(curl_v imap://172.30.3.10/ alice@example.test alice-test-only); echo "$out" | show
grep -q 'LIST .* store-b' <<<"$out" || fail "next login not on store-b"
wait_until 10 "edge line .22" has edge "$mE" "proxy\(alice@example.test,172.30.3.22:143\): Started"
lines edge "$mE" "proxy\(alice@example.test"
pass "the next IMAP login of alice lists store-b; the edge proxies to 172.30.3.22:143"
mP=$(mark postfix)
mail alice@example.test c5-alice@example.test
wait_until 60 "Postfix result" has postfix "$mP" "to=<alice@example.test>.*status="
lines postfix "$mP" "to=<alice@example.test>"
has postfix "$mP" "to=<alice@example.test>.*status=sent" || fail "c5 not sent"
run X store-b doveadm fetch -u alice@example.test hdr.message-id all
[ "$(msgid_on store-b alice@example.test c5-alice@example.test)" = 1 ] || fail "c5 not on store-b"
run X store-a doveadm mailbox status -u alice@example.test messages INBOX
[ "$(msgid_on store-a alice@example.test c5-alice@example.test)" = 0 ] || fail "c5 on store-a"
st=$(X store-a doveadm mailbox status -u alice@example.test messages INBOX)
grep -q 'messages=1' <<<"$st" || fail "store-a count changed"
pass "the next delivery lands on store-b; store-a keeps messages=1 (counter-proof 3: the store-b check now sees 1)"
echo "--- the open session (opened before the change)"
mE=$(mark edge)
sess_send 'c LIST "" "store-*"'
sess_expect '^c ' 15 || fail "the old session is gone"
has edge "$mE" "proxy\(alice@example.test,172.30.3.21:143\): Disconnected" && fail "the old session was disconnected"
pass "the old session is still connected to store-a (LIST still names store-a)"
echo "--- counter-proof 5: the same LIST assertion on the session opened before the edit names store-a, not store-b;"
echo "    the planned auth-cache counter-proof does not reproduce on 2.4.5 passwd-file (observation 5 below)"
run X edge doveadm proxy list
run X edge doveadm proxy kick alice@example.test
wait_until 10 "edge disconnect line" has edge "$mE" "proxy\(alice@example.test,172.30.3.21:143\): Disconnected"
lines edge "$mE" "proxy\(alice@example.test,172.30.3.21:143\): Disconnected"
# netcat-openbsd keeps running while its stdin is open, so the evidence is the
# edge's line above plus a command that gets no reply.
sess_send 'd NOOP'
sess_expect '^d ' 5 && fail "the kicked session still answers"
echo "  (no reply within 5 s)"
sess_close
pass "doveadm proxy kick ends the old session"

echo "--- observation 5: the auth cache does not cache passwd-file lookups (2.4.5)"
step "printf 'auth_cache_size = 1M\\nauth_cache_ttl = 1h\\nauth_debug = yes\\n' > .run/edge.d/cache.conf"
printf 'auth_cache_size = 1M\nauth_cache_ttl = 1h\nauth_debug = yes\n' >.run/edge.d/cache.conf
edge_restart
run X edge doveconf -h auth_cache_size
mE=$(mark edge)
for i in 1 2; do
	curl_step -s imap://172.30.3.10/ alice@example.test alice-test-only "login $i"
	curl_s imap://172.30.3.10/ alice@example.test alice-test-only | grep store | show
done
wait_until 10 "two proxied logins" test "$(count edge "$mE" 'proxy\(alice@example.test,.*\): Started')" -ge 2
lines edge "$mE" "passwd-file: Performing passdb lookup"
n=$(count edge "$mE" "sasl:plain.*passwd-file: Performing passdb lookup")
echo "  passdb lookups for 2 logins with auth_cache_size = 1M: $n"
[ "$n" = 2 ] || fail "observation 5: expected a passdb lookup per login, got $n"
pass "observation 5: auth_cache_size = 1M, yet every login does a passwd-file lookup (no cache hit; finding F2)"
run rm -f .run/edge.d/cache.conf
edge_restart

echo "--- back to store-a"
run sed -i '/^alice@/s/host=172.30.3.22/host=172.30.3.21/' .run/routing/routing.passwd
lookup21() { X edge doveadm auth lookup alice@example.test | grep -qE '^ *host *: 172.30.3.21$'; }
wait_until 30 "lookup back on .21" lookup21
mE=$(mark edge)
curl_step -v imap://172.30.3.10/ alice@example.test alice-test-only
curl_v imap://172.30.3.10/ alice@example.test alice-test-only | grep LIST | show
wait_until 10 "edge line .21" has edge "$mE" "proxy\(alice@example.test,172.30.3.21:143\): Started"
lines edge "$mE" "proxy\(alice@example.test"
pass "alice is back on 172.30.3.21"

###########################################################################
# 6: unreachable store; variant <name> <down command> <up command>
unreachable() {
	local v=$1 down=$2 up=$3 t0 out mP mE mR dj dr
	echo "--- 6$v: docker compose $down store-b"
	mP=$(mark postfix) mE=$(mark edge)
	run C "$down" store-b || fail "$down store-b"
	t0=$(now)
	out=$(imap_login bob@example.test bob-test-only); echo "$out"
	echo "  (LOGIN reply after $(elapsed "$t0") s, including the greeting)"
	grep -q '< a NO \[UNAVAILABLE\] Account is temporarily unavailable' <<<"$out" || fail "6$v IMAP: no [UNAVAILABLE]"
	grep -q AUTHENTICATIONFAILED <<<"$out" && fail "6$v IMAP: AUTHENTICATIONFAILED"
	pass "6$v IMAP: NO [UNAVAILABLE], never AUTHENTICATIONFAILED"
	t0=$(now)
	out=$(pop3_login bob@example.test bob-test-only); echo "$out"
	echo "  (PASS reply after $(elapsed "$t0") s, including the greeting)"
	grep -q '< -ERR \[SYS/TEMP\] Account is temporarily unavailable' <<<"$out" || fail "6$v POP3: no [SYS/TEMP]"
	pass "6$v POP3: -ERR [SYS/TEMP]"
	lines edge "$mE" "(imap|pop3)-login: .*bob@example.test"
	mP=$(mark postfix) mE=$(mark edge)
	t0=$(now)
	mail bob@example.test "c6$v-bob@example.test"
	wait_until 60 "Postfix result for bob" has postfix "$mP" "to=<bob@example.test>.*status="
	echo "  (after $(elapsed "$t0") s)"
	lines postfix "$mP" "to=<bob@example.test>"
	has postfix "$mP" "to=<bob@example.test>.*dsn=4\.4\.0, status=deferred \(host 172.30.3.10\[172.30.3.10\] said: 451 4\.4\.0 Proxy failed .*in reply to RCPT TO command\)" ||
		fail "6$v LMTP: not deferred with 451 4.4.0 at RCPT"
	lines edge "$mE" "lmtp.*(rror|Proxy|timed out|connect)"
	step "E postqueue -j  (delay_reason of bob's entry)"
	dj=$(E postqueue -j)
	dr=$(printf '%s\n' "$dj" | jq -r '.recipients[] | select(.address == "bob@example.test") | .delay_reason')
	printf '%s\n' "$dj" | jq -c '{queue_name, queue_id, recipients}' | show
	grep -qE 'said: 4[0-9][0-9] ' <<<"$dr" || fail "6$v: delay_reason is not a 4xx"
	pass "6$v LMTP: status=deferred, dsn=4.4.0, 451 at RCPT; queued with a 4xx delay_reason"
	step "count of status=bounced and postfix/bounce in the Postfix log since 6$v started"
	echo "  status=bounced: $(count postfix "$mP" 'status=bounced'), postfix/bounce: $(count postfix "$mP" 'postfix/bounce')"
	[ "$(count postfix "$mP" 'status=bounced|postfix/bounce')" = 0 ] || fail "6$v: Postfix bounced"
	pass "6$v: no bounce"
	echo "--- 6$v recovery"
	mR=$(mark postfix)
	run C "$up" store-b || fail "$up store-b"
	wait_until 30 "store-b listeners" X store-b nc -z 127.0.0.1 24
	run E postqueue -f
	wait_until 60 "delivery after recovery" has postfix "$mR" "to=<bob@example.test>.*status=sent"
	lines postfix "$mR" "to=<bob@example.test>"
	step "X store-b doveadm search -u bob@example.test mailbox INBOX header message-id c6$v-bob@example.test | wc -l"
	n=$(msgid_on store-b bob@example.test "c6$v-bob@example.test"); echo "  $n"
	[ "$n" = 1 ] || fail "6$v: message not exactly once on store-b"
	pass "6$v recovery: status=sent, exactly once on store-b"
}
check "6. Unreachable store: temporary failure, mail stays queued, no bounce"
unreachable a stop start
unreachable b pause unpause

###########################################################################
check "7. A routing entry without proxy/host never delivers on the edge"
mE=$(mark edge)
out=$(imap_login carol@example.test carol-test-only); echo "$out"
grep -q '< a NO ' <<<"$out" || fail "carol's login did not fail"
has edge "$mE" "proxy\(carol@" && fail "carol was proxied"
lines edge "$mE" "carol@example.test"
pass "IMAP login for carol fails on the edge (not proxied)"
mP=$(mark postfix) mE=$(mark edge)
mail carol@example.test c7-carol@example.test
wait_until 60 "Postfix result for carol" has postfix "$mP" "to=<carol@example.test>.*status="
lines postfix "$mP" "to=<carol@example.test>"
has postfix "$mP" "to=<carol@example.test>.*dsn=4\.3\.0, status=deferred .*said: 451 4\.3\.0 <carol@example.test> Temporary internal error \(in reply to end of DATA command\)" ||
	fail "carol not deferred with 451 4.3.0"
lines edge "$mE" "lmtp.*carol"
has edge "$mE" "carol.*Failed to initialize user" || fail "no 'Failed to initialize user'"
has edge "$mE" "Saved" && fail "the edge saved mail"
[ "$(count postfix "$mP" 'status=bounced|postfix/bounce')" = 0 ] || fail "Postfix bounced carol"
pass "carol: 451 4.3.0 after DATA, deferred, no bounce; edge: Failed to initialize user, no Saved"
run docker run --rm --network none --entrypoint find -v keepia-proto3_edge-vmail:/v:ro keepia-proto3-postfix /v -type f
[ -z "$(docker run --rm --network none --entrypoint find -v keepia-proto3_edge-vmail:/v:ro keepia-proto3-postfix /v -type f)" ] ||
	fail "files on the edge's /srv/vmail"
pass "the edge's /srv/vmail volume has no file"
run docker diff keepia-proto3-edge-1
# Allowed: /run, /tmp, and the mount points Docker creates for the edge's two
# bind-mounted directories (/etc/dovecot/routing, /etc/dovecot/edge.d).
d=$(docker diff keepia-proto3-edge-1 | grep -vE '^[ACD] /(run|tmp)(/|$)|^C /etc$|^C /etc/dovecot$|^A /etc/dovecot/(routing|edge\.d)$')
[ -z "$d" ] || { echo "$d" | show; fail "docker diff shows changes outside /run, /tmp and the mount points"; }
pass "docker diff: no change outside /run, /tmp and the two mount points"
echo "--- counter-proof 7: the same edge WITH mail storage stores carol's mail on the edge"
step "printf 'mail_driver = maildir\\nmail_home = /srv/vmail/%%{user | lower}\\nmail_path = ~/Maildir\\n' > .run/edge.d/storage.conf"
printf 'mail_driver = maildir\nmail_home = /srv/vmail/%%{user | lower}\nmail_path = ~/Maildir\n' >.run/edge.d/storage.conf
edge_restart
mP=$(mark postfix)
run E postqueue -f
wait_until 60 "carol delivered" has postfix "$mP" "to=<carol@example.test>.*status=sent"
lines postfix "$mP" "to=<carol@example.test>"
run docker run --rm --network none --entrypoint find -v keepia-proto3_edge-vmail:/v:ro keepia-proto3-postfix /v -path '*/new/*' -type f
[ -n "$(docker run --rm --network none --entrypoint find -v keepia-proto3_edge-vmail:/v:ro keepia-proto3-postfix /v -path '*/new/*' -type f)" ] ||
	fail "counter-proof 7: nothing stored on the edge"
pass "counter-proof 7: with storage settings the edge answers 250 Saved and stores carol's mail on itself (finding F3)"
run rm -f .run/edge.d/storage.conf
edge_restart
step "X edge doveconf -n | grep -E '^mail_(driver|home|path)'"
[ -z "$(X edge doveconf -n | grep -E '^mail_(driver|home|path)')" ] || fail "storage settings still on the edge"
echo "  (no output)"

###########################################################################
check "8. Unknown user"
mP=$(mark postfix) mA=$(mark store-a) mB=$(mark store-b)
mail nobody@example.test c8-nobody@example.test
wait_until 60 "Postfix result for nobody" has postfix "$mP" "to=<nobody@example.test>.*status="
lines postfix "$mP" "to=<nobody@example.test>"
has postfix "$mP" "to=<nobody@example.test>.*dsn=5\.1\.1, status=bounced .*said: 550 5\.1\.1 <nobody@example.test> User doesn't exist: nobody@example.test" ||
	fail "nobody not bounced with the edge's 550 5.1.1"
has store-a "$mA" "nobody@example.test" || has store-b "$mB" "nobody@example.test" && fail "a store saw nobody"
pass "nobody: the edge itself answers 550 5.1.1 User doesn't exist (no store saw it); Postfix bounces (a correct permanent failure)"
echo "--- counter-proof 8: with a routing line for nobody the store answers, and its log shows it"
step "echo 'nobody@example.test:::::::proxy=y host=172.30.3.21 nopassword=y' >> .run/routing/routing.passwd"
echo 'nobody@example.test:::::::proxy=y host=172.30.3.21 nopassword=y' >>.run/routing/routing.passwd
nobody_routed() { X edge doveadm auth lookup nobody@example.test | grep -qE '^ *host *: 172.30.3.21$'; }
wait_until 30 "routing line for nobody" nobody_routed
run X edge doveadm auth lookup nobody@example.test
mP=$(mark postfix) mA=$(mark store-a)
mail nobody@example.test c8b-nobody@example.test
wait_until 60 "Postfix result for nobody" has postfix "$mP" "to=<nobody@example.test>.*status="
lines postfix "$mP" "to=<nobody@example.test>"
has postfix "$mP" "to=<nobody@example.test>.*status=bounced .*said: 550 5\.1\.1 <nobody@example.test> User doesn't exist" ||
	fail "counter-proof 8: no 550"
wait_until 10 "store-a log line for nobody" has store-a "$mA" "nobody@example.test"
lines store-a "$mA" "nobody@example.test"
pass "counter-proof 8: now store-a logs the lookup for nobody (same 550 text), so check 8's 'no store saw it' assertion tells edge and store apart"
sed -i '/^nobody@/d' .run/routing/routing.passwd

###########################################################################
check "6c. Counter-proof 6 (run last, review N8): a store that answers 5xx makes Postfix bounce"
step "sed -i '/^bob@/d' .run/store/users.passwd"
sed -i '/^bob@/d' .run/store/users.passwd
bob_gone() { ! X store-b doveadm auth lookup bob@example.test >/dev/null 2>&1; }
wait_until 30 "store-b without bob" bob_gone
run X store-b doveadm auth lookup bob@example.test
mP=$(mark postfix)
mail bob@example.test c6c-bob@example.test
wait_until 60 "Postfix result for bob" has postfix "$mP" "to=<bob@example.test>.*status="
lines postfix "$mP" "to=<bob@example.test>"
has postfix "$mP" "to=<bob@example.test>.*status=bounced .*said: 550 5\.1\.1 <bob@example.test> User doesn't exist" ||
	fail "counter-proof 6: no bounce on a 5xx"
echo "  status=bounced since 6c: $(count postfix "$mP" 'status=bounced')"
pass "counter-proof 6: the store's 550 5.1.1 is relayed and Postfix bounces, so check 6's no-bounce count tells the outcomes apart"
cp store/users.passwd .run/store/users.passwd

###########################################################################
check "Resources (F7)"
run docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' \
	keepia-proto3-edge-1 keepia-proto3-store-a-1 keepia-proto3-store-b-1 keepia-proto3-postfix-1
run docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' keepia-proto3-postfix

printf '\nALL CHECKS PASSED\n'
