#!/bin/bash
# Tests the Compose template "all roles on one server" (docker-compose.yml;
# #5 plan, tests 6 and 8-13; #61, test 14; #66, the checks marked so
# below). The CI compose job runs it after loading the verified images;
# ./km migrate (test 7) runs in the job's next steps.
#
# It starts every service with `docker compose up -d --wait --no-build
# --pull never` (nothing is built or pulled: the images must already be in
# the local store) and leaves them running, except edge-postfix, which it
# stops at its end (test 14b); the caller removes them (`docker compose
# down -v`). Then:
#
# 14  wildcard edge addresses (first, before the template starts): with
#     EDGE_IPV4=0.0.0.0, and then EDGE_IPV6=::, starting edge-postfix
#     fails, the guard edge-addresses names the variable, and edge-postfix
#     never runs (#61). A `docker start` of the edge-postfix left behind
#     (the guard's bypass) must exit 1 on edge-postfix's own check, before
#     Postfix runs. The partial start is removed again.
# 14b stop (at the very end): edge-postfix runs, and a stop of it must
#     exit 0 and not be OOM-killed: its check must exec Postfix's
#     launcher, so the stop signal reaches it (#66).
#  6  containers and health: the project's containers are exactly the 14
#     expected services, one each, plus the one-shot guard edge-addresses,
#     which exited 0; every one of the 14 has a healthcheck and is
#     healthy. olefy also scans with its read-only root (its /tmp is a
#     tmpfs; without it every scan fails while the probe stays green).
#  8  listeners (R-BIND-PRIVATE): every listening TCP socket and unconnected
#     UDP socket of every container (/proc/net/{tcp,tcp6,udp,udp6}, read
#     by a helper container in the container's network namespace; a
#     missing file is tolerated) is either on loopback or exactly one of
#     the container's planned listeners (protocol, address and port,
#     want_listen below), and every planned listener is there; so a bind on another of
#     the container's own addresses fails too (#61). Dovecot has nothing on
#     8080 or 9090.
#  9  networks: every network but edge-public is internal, with the gateway
#     mode isolated; the host has no address in their subnets and cannot
#     reach rspamd, clamd, olefy or memcached, which a container on the
#     same network can (#61); every container is on exactly its networks,
#     with exactly its fixed addresses; only edge-postfix publishes, port
#     25 on EDGE_IPV4 and EDGE_IPV6. The line in architecture section 7
#     that lists the internal subnets, read from the document (one fixed
#     form, checked before it runs) and run with no active profile, lists
#     exactly the subnets this test checks (#66).
# 10  privileges: CapDrop ALL, exactly the planned CapAdd (Postfix five,
#     Dovecot SYS_CHROOT, all others none), no-new-privileges, not
#     privileged, no host network, no Docker socket, the template's
#     pids_limit; every process runs as a non-zero uid, except Postfix's
#     master and its launchers. The same for edge-addresses, which also
#     has no network and a read-only root. edge-postfix's entrypoint is
#     its image's with the edge address check put in after `tini --`, and
#     its command is the image's (#66).
# 11  volumes: a user line in store-users and a message over LMTP to
#     store-dovecot land as a file in the named volume store-mail;
#     edge-vmail stays empty; no container has an anonymous volume.
# 12  edge tempfail: LMTP RCPT to edge-dovecot gets 451 4.3.0 and IMAP
#     LOGIN gets NO [UNAVAILABLE].
# 13  edge NAT: SNAT of edge-public to EDGE_IPV4 (and EDGE_IPV6) and a DNAT
#     of port 25 to edge-postfix, in iptables or nftables.
# 15  the key-encryption key (#96, CD1): the volume keepia-kek is mounted
#     only into keepia, read-write at /var/lib/keepia/kek; serve created
#     the KEK there, mode 0400 and uid 65532 in a 0700 directory (read by
#     the helper image as uid 65532, the volume read-only); keepia logged
#     the first-start warning once; after `docker compose restart keepia`
#     it is healthy again, with no second "created" line.
# 16  the PostgreSQL log (#95): a mailboxes row refused by a CHECK is logged
#     without its DETAIL ("Failing row contains", which would quote the
#     password hash): postgres runs with log_error_verbosity=terse.
#
# Every test runs, also after a failure, and names what failed; the exit
# status is 1 if any failed. Every wait is `--wait` or bounded by a timeout.
#
# Environment: the Compose variables (.env, or the job's env), with
# COMPOSE_PROFILES naming all five roles. In GitHub Actions the own images
# must be given as verified image IDs (KEEPIA_IMAGE, KEEPIA_POSTFIX_IMAGE,
# KEEPIA_UNBOUND_IMAGE, KEEPIA_OLEFY_IMAGE, KEEPIA_SOGO_IMAGE), and the
# script puts EDGE_IPV4 and EDGE_IPV6 on the runner's loopback.
#
# Usage: scripts/compose-test.sh   (needs root or sudo to read the NAT
# rules and, in GitHub Actions, to put the edge addresses on loopback;
# the containers' sockets are read by helper containers, without sudo)
set -euo pipefail

cd "$(dirname "$0")/.."

sudo=
[ "$(id -u)" = 0 ] || sudo=sudo

failed=0
pass() { echo "ok   $*"; }
fail() {
	echo "FAIL $*" >&2
	failed=$((failed + 1))
}
die() {
	echo "FAIL $*" >&2
	exit 1
}

# The planned services: the 14 containers of the five roles in 0.1.0.
expected_services=(
	keepia postgres valkey control-unbound
	edge-postfix edge-dovecot edge-unbound
	store-dovecot
	filter-rspamd filter-clamd filter-olefy filter-unbound
	groupware-sogo groupware-memcached
)

# The capabilities each container gets back (#5 plan, test 10).
declare -A want_caps=(
	[edge-postfix]="CHOWN DAC_OVERRIDE FOWNER SETGID SETUID"
	[edge-dovecot]="SYS_CHROOT"
	[store-dovecot]="SYS_CHROOT"
)

# The networks each container joins (#5 plan, "Networks"; test 9).
declare -A want_networks=(
	[keepia]="control-private"
	[postgres]="control-private"
	[valkey]="control-private"
	[control-unbound]="control-private"
	[edge-postfix]="edge-private edge-public"
	[edge-dovecot]="edge-private"
	[edge-unbound]="edge-private"
	[store-dovecot]="store-private"
	[filter-rspamd]="filter-olefy filter-private"
	[filter-clamd]="filter-private"
	[filter-olefy]="filter-olefy"
	[filter-unbound]="filter-private"
	[groupware-sogo]="groupware-private"
	[groupware-memcached]="groupware-private"
)

# The listeners each container has besides loopback (test 8):
# <tcp|udp>:<network>:<port>, where <network> is the container's IPv4
# address on that network and <network>/6 its IPv6 address. Exactly these,
# so a listener on another of the container's own addresses (rspamd on
# filter-olefy), a UDP socket on a TCP port (memcached without -U 0), or
# an Unbound that lost TCP 53 fails.
declare -A want_listen=(
	[keepia]="tcp:control-private:8080"
	[postgres]="tcp:control-private:5432"
	[valkey]="tcp:control-private:6379"
	[control-unbound]="tcp:control-private:53 udp:control-private:53"
	[edge-postfix]="tcp:edge-private:25 tcp:edge-public:25 tcp:edge-public/6:25"
	[edge-dovecot]="tcp:edge-private:24 tcp:edge-private:143"
	[edge-unbound]="tcp:edge-private:53 udp:edge-private:53"
	[store-dovecot]="tcp:store-private:24 tcp:store-private:143"
	[filter-rspamd]="tcp:filter-private:11332 tcp:filter-private:11333"
	[filter-clamd]="tcp:filter-private:3310"
	[filter-olefy]="tcp:filter-olefy:10050"
	[filter-unbound]="tcp:filter-private:53 udp:filter-private:53"
	[groupware-sogo]="tcp:groupware-private:20000"
	[groupware-memcached]="tcp:groupware-private:11211"
)

# The one-shot services: each runs once per start and must exit 0.
oneshot_services=(edge-addresses)

image_id='^sha256:[0-9a-f]{64}$'
if [ "${GITHUB_ACTIONS:-}" = true ]; then
	# The own images are the verified IDs of the loaded tars, never a tag
	# (.claude/rules/docker.md): an empty variable would fall back to it.
	for v in KEEPIA_IMAGE KEEPIA_POSTFIX_IMAGE KEEPIA_UNBOUND_IMAGE KEEPIA_OLEFY_IMAGE KEEPIA_SOGO_IMAGE; do
		[[ ${!v:-} =~ $image_id ]] || die "$v is '${!v:-}', want a verified image ID"
	done
	# The edge addresses on the runner's loopback, so port 25 can be
	# published to them and the NAT rules name them (test 13).
	for a in "${EDGE_IPV4:?}/32" "${EDGE_IPV6:?}/128"; do
		if ! ip -o addr show dev lo | grep -qF " ${a%/*}/"; then
			$sudo ip addr add "$a" dev lo
		fi
	done
fi

# The whole template, every profile: the expected addresses and volumes.
config=$(docker compose --profile '*' config --format json)
project=$(jq -r .name <<<"$config")
docker version --format 'Docker Engine {{.Server.Version}}, client {{.Client.Version}}'

# container <service>: the ID of the service's container ("" if none).
container() {
	docker ps -aq --filter "label=com.docker.compose.project=$project" \
		--filter "label=com.docker.compose.service=$1"
}

# Probes run in a helper container: the memcached image (pinned, already
# in the store, with bash), no capabilities, either on no network
# (volumes), on one role's internal network (a client of that role), or
# in a container's network namespace (its sockets, test 8). Every run is
# bounded by a timeout, and they read every reply with one.
helper_image=$(jq -r '.services["groupware-memcached"].image' <<<"$config")
helper() {
	timeout 60 docker run --rm --pull never --cap-drop ALL --security-opt no-new-privileges:true "$@"
}

# client <network> <function> <arguments...>: runs the function in a
# helper on the project's network.
client() {
	local net=$1 fn=$2
	shift 2
	helper --network "${project}_$net" --user 65534:65534 --entrypoint bash "$helper_image" \
		-c "$(declare -f "$fn"); $fn \"\$@\"" "$fn" "$@" 2>&1
}

# tcp_open <host> <port>: a TCP connection opens within 3 s.
tcp_open() {
	timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2"
}

# ---- test 14: wildcard edge addresses -------------------------------------

# Before the template starts: a start of edge-postfix with a wildcard edge
# address must fail in the guard, and edge-postfix must never run; a
# direct start of that edge-postfix must fail in its own check. Then the
# partial start is removed.
echo "---- test 14: wildcard edge addresses are refused"
for wildcard in EDGE_IPV4=0.0.0.0 EDGE_IPV6=::; do
	var=${wildcard%%=*}
	rc=0
	out=$(env "$wildcard" timeout 120 docker compose up -d --no-build --pull never edge-postfix 2>&1) || rc=$?
	c=$(container edge-postfix)
	# A container that never ran keeps the zero StartedAt (0001-01-01).
	state="no container" started=0001-
	[ -z "$c" ] || read -r state started < <(docker inspect -f '{{.State.Status}} {{.State.StartedAt}}' "$c")
	guard=$(docker compose logs --no-log-prefix edge-addresses 2>&1 || true)
	if [ "$state" = running ] || [[ $started != 0001-* ]]; then
		fail "test 14: $wildcard: edge-postfix was started ($state, at $started)"
	elif [ "$rc" != 0 ] && [[ $guard == *"keepia: $var='${wildcard#*=}'"* ]]; then
		pass "test 14: $wildcard refused, edge-postfix never ran ($state): $(grep -m1 "$var" <<<"$guard")"
	else
		fail "test 14: $wildcard: up exited $rc, edge-postfix is $state, guard: $(tr '\n' ' ' <<<"$guard" | cut -c1-300); up: $(tr '\n' ' ' <<<"$out" | tail -c 300)"
	fi
	# The bypass: start the edge-postfix the refusal left Created directly,
	# as `docker compose restart` or `docker start` would, without the
	# dependency. Its own entrypoint check must end it with exit 1 before
	# Postfix runs. The signal is its first "die" event, read with a
	# timeout; a Postfix that runs gives none.
	if [ -n "$c" ]; then
		since=$(date +%s)
		docker start "$c" >/dev/null 2>&1 || true
		code=$(timeout 60 docker events --since "$since" --filter "container=$c" --filter event=die \
			--format '{{index .Actor.Attributes "exitCode"}}' | head -n 1) || true
		logs=$(docker logs "$c" 2>&1 || true)
		if [ "$code" = 1 ] && [[ $logs == *"keepia: $var='${wildcard#*=}'"* ]] && [[ $logs != *"starting the Postfix"* ]]; then
			pass "test 14: $wildcard: a docker start of that edge-postfix exits 1 on its own check, before Postfix: $(grep -m1 "$var" <<<"$logs")"
		else
			fail "test 14: $wildcard: a docker start of that edge-postfix gave exit '${code:-none within 60 s}', log: $(tr '\n' ' ' <<<"$logs" | tail -c 300)"
		fi
	fi
	timeout 120 docker compose down --volumes --timeout 10 2>&1 | tail -n 3 || true
done

# ---- start -------------------------------------------------------------

echo "---- start: project $project"
up_rc=0
docker compose up -d --wait --wait-timeout 300 --no-build --pull never || up_rc=$?

# ---- test 6: containers and health -------------------------------------

echo "---- test 6: containers and health"
mapfile -t running < <(docker ps -a --filter "label=com.docker.compose.project=$project" \
	--format '{{.Label "com.docker.compose.service"}}' | sort)
mapfile -t want < <(printf '%s\n' "${expected_services[@]}" "${oneshot_services[@]}" | sort)
if [ "${running[*]}" = "${want[*]}" ]; then
	pass "test 6: exactly the ${#expected_services[@]} planned containers and the one-shot ${oneshot_services[*]}: ${running[*]}"
else
	fail "test 6: the project's containers are [${running[*]}], want [${want[*]}]"
fi
for s in "${oneshot_services[@]}"; do
	c=$(container "$s")
	if [ -z "$c" ]; then
		fail "test 6: $s has no container"
		continue
	fi
	st=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$c")
	if [ "$st" = "exited 0" ]; then
		pass "test 6: $s ran once and exited 0: $(docker logs "$c" 2>&1 | tail -n 1)"
	else
		fail "test 6: $s is '$st', want 'exited 0'"
		docker logs "$c" >&2 || true
	fi
done
for s in "${expected_services[@]}"; do
	c=$(container "$s")
	if [ -z "$c" ]; then
		fail "test 6: $s has no container"
		continue
	fi
	hc=$(docker inspect -f '{{if .Config.Healthcheck}}{{join .Config.Healthcheck.Test " "}}{{end}}' "$c")
	case $hc in
	"" | NONE*) fail "test 6: $s has no healthcheck" ;;
	esac
	health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c")
	if [ "$health" = healthy ]; then
		pass "test 6: $s healthy ($(docker inspect -f '{{json .State.Health.Log}}' "$c" | jq -r 'last | "exit \(.ExitCode)  \(.Output | gsub("\\s+"; " ") | .[0:60])"'))"
	else
		fail "test 6: $s is $health ($(docker inspect -f '{{.State.Status}}' "$c"))"
		docker compose logs --no-log-prefix --tail 20 "$s" >&2 || true
	fi
done
[ "$up_rc" = 0 ] || fail "test 6: the start (--wait) exited $up_rc"

# olefy with its read-only root: one scan over olefy's protocol (olefy.py
# itself as the payload), answered by olevba. Every scan writes to /tmp.
c=$(container filter-olefy)
if [ -n "$c" ]; then
	addr=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" | sed -n 's/^OLEFY_BINDADDRESS=//p')
	out=$(timeout 60 docker exec "$c" python3 -I -c '
import socket, sys
with open("/usr/local/bin/olefy.py", "rb") as f:
    payload = f.read()
with socket.create_connection((sys.argv[1], 10050), timeout=30) as s:
    s.sendall(b"OLEFY/1.0\nMethod: oletools\nRspamd-ID: compose\n\n" + payload)
    s.shutdown(socket.SHUT_WR)
    reply = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        reply += chunk
print(reply.decode("utf-8", "replace"))
' "$addr" 2>&1) || true
	if [[ $out == *'"json_conversion_successful": true'* ]]; then
		pass "test 6: olefy scans on $addr with its read-only root (${#out} bytes from olevba)"
	else
		fail "test 6: olefy's scan on $addr failed: ${out:0:300}"
	fi
fi

# ---- test 8: listeners --------------------------------------------------

# hex4 <8 hex digits, little-endian>: the IPv4 address.
hex4() {
	local h=$1
	echo "$((16#${h:6:2})).$((16#${h:4:2})).$((16#${h:2:2})).$((16#${h:0:2}))"
}
# hex6 <32 hex digits, four little-endian words>: the full IPv6 address.
hex6() {
	local h=$1 out="" w i
	for i in 0 8 16 24; do
		w=${h:i:8}
		out+="${w:6:2}${w:4:2}:${w:2:2}${w:0:2}:"
	done
	echo "${out%:}" | tr 'A-F' 'a-f'
}
# full6 <IPv6 address>: the address with all eight groups of four digits.
full6() {
	local a=${1,,} head tail n i out=""
	local -a hg=() tg=()
	if [[ $a == *::* ]]; then
		head=${a%%::*} tail=${a#*::}
	else
		head=$a tail=""
	fi
	[ -n "$head" ] && IFS=: read -ra hg <<<"$head"
	[ -n "$tail" ] && IFS=: read -ra tg <<<"$tail"
	n=$((8 - ${#hg[@]} - ${#tg[@]}))
	for i in "${hg[@]}"; do out+=$(printf '%04x:' "$((16#$i))"); done
	for ((i = 0; i < n; i++)); do out+="0000:"; done
	for i in "${tg[@]}"; do out+=$(printf '%04x:' "$((16#$i))"); done
	echo "${out%:}"
}

# socket_tables <container>: /proc/net/{tcp,tcp6,udp,udp6} of the
# container's network namespace, each after a line "# <name>", read by a
# helper that joins that namespace (no sudo, no host /proc).
socket_tables() {
	helper --network "container:$1" --user 65534:65534 --entrypoint bash "$helper_image" -c '
		for f in tcp tcp6 udp udp6; do
			[ -e "/proc/net/$f" ] || continue
			echo "# $f"
			tail -n +2 "/proc/net/$f"
		done'
}

# listeners <container>: "<proto> <address> <port>" per listening TCP
# socket and unconnected UDP socket in the container's network namespace.
listeners() {
	local f="" local_addr rem st addr port tables
	tables=$(socket_tables "$1") || return 1
	while read -r first local_addr rem st _; do
		if [ "$first" = "#" ]; then
			f=$local_addr
			continue
		fi
		case $f in
		tcp*) [ "$st" = 0A ] || continue ;;
		udp*) [ "$st" = 07 ] && [[ $rem =~ ^0+:0000$ ]] || continue ;;
		*) continue ;;
		esac
		port=$((16#${local_addr#*:}))
		addr=${local_addr%:*}
		if [ ${#addr} = 8 ]; then
			addr=$(hex4 "$addr")
		else
			addr=$(hex6 "$addr")
		fi
		echo "$f $addr $port"
	done <<<"$tables"
}

# planned_listeners <service>: "<tcp|udp>:<address>:<port>" per planned
# listener (want_listen), the IPv6 address in full form, from the template.
planned_listeners() {
	local s=$1 l proto net port fam a
	for l in ${want_listen[$s]}; do
		IFS=: read -r proto net port <<<"$l"
		fam=ipv4_address
		if [[ $net == */6 ]]; then
			net=${net%/6} fam=ipv6_address
		fi
		a=$(jq -r --arg s "$s" --arg n "$net" --arg f "$fam" '.services[$s].networks[$n][$f] // ""' <<<"$config")
		[ "$fam" = ipv6_address ] && [ -n "$a" ] && a=$(full6 "$a")
		echo "$proto:${a:-<no $fam on $net>}:$port"
	done
}

echo "---- test 8: listeners (R-BIND-PRIVATE, one planned protocol and address per listener)"
loop6=$(full6 ::1)
for s in "${expected_services[@]}"; do
	c=$(container "$s")
	[ -n "$c" ] || continue
	if [ "$(docker inspect -f '{{.State.Running}}' "$c")" != true ]; then
		fail "test 8: $s is not running"
		continue
	fi
	mapfile -t planned < <(planned_listeners "$s")
	if ! socks=$(listeners "$c"); then
		fail "test 8: could not read the sockets of $s"
		continue
	fi
	n=0 bad=0 seen=" " lo=0
	while read -r proto addr port; do
		[ -n "$proto" ] || continue
		n=$((n + 1))
		case $addr in
		127.*)
			lo=$((lo + 1))
			continue
			;;
		*:*)
			if [ "$addr" = "$loop6" ]; then
				lo=$((lo + 1))
				continue
			fi
			;;
		esac
		case $s:$port in
		*dovecot:8080 | *dovecot:9090)
			fail "test 8: $s listens on $proto $addr:$port (the image's HTTP listeners)"
			bad=$((bad + 1))
			continue
			;;
		esac
		# tcp6/udp6 are the same protocols as tcp/udp.
		key="${proto%6}:$addr:$port"
		if [[ " ${planned[*]} " == *" $key "* ]]; then
			seen+="$key "
		else
			fail "test 8: $s listens on $key, which is not one of its planned listeners [${planned[*]}] nor loopback"
			bad=$((bad + 1))
		fi
	done <<<"$socks"
	for p in "${planned[@]}"; do
		if [[ $seen != *" $p "* ]]; then
			fail "test 8: $s does not listen on its planned $p"
			bad=$((bad + 1))
		fi
	done
	if [ "$n" = 0 ]; then
		fail "test 8: $s has no listening socket"
	elif [ "$bad" = 0 ]; then
		pass "test 8: $s: $n listening sockets: exactly [${planned[*]}], and $lo on loopback"
	fi
done

# ---- test 9: networks -----------------------------------------------------

echo "---- test 9: networks"
public=$(jq -r '.networks["edge-public"].name' <<<"$config")
public_v6=$(docker network inspect -f '{{.EnableIPv6}}' "$public" 2>/dev/null || echo false)
if [ "${GITHUB_ACTIONS:-}" = true ] && [ "$public_v6" != true ]; then
	fail "test 9: edge-public has no IPv6"
fi
host_addrs=$(ip -o addr show | awk '{ print $4 }')
for n in $(jq -r '.networks | keys[]' <<<"$config"); do
	name=$(jq -r --arg n "$n" '.networks[$n].name' <<<"$config")
	# One inspect: a missing network fails here, with nothing printed.
	if ! info=$(docker network inspect -f '{{.Internal}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv6"}}' "$name" 2>/dev/null); then
		fail "test 9: network $n ($name) is missing"
		continue
	fi
	read -r internal mode4 mode6 <<<"$info"
	if [ "$n" = edge-public ]; then
		if [ "$internal" = false ]; then
			pass "test 9: network $n internal=false"
		else
			fail "test 9: network $n internal=$internal, want false"
		fi
		continue
	fi
	ok=true
	if [ "$internal" != true ]; then
		fail "test 9: network $n internal=$internal, want true"
		ok=false
	fi
	if [ "$mode4 $mode6" != "isolated isolated" ]; then
		fail "test 9: network $n has gateway modes [$mode4 $mode6], want [isolated isolated]"
		ok=false
	fi
	# No host interface holds an address in the network's subnets.
	for sub in $(jq -r --arg n "$n" '.networks[$n].ipam.config[].subnet' <<<"$config"); do
		case $sub in
		*::/*) prefix="${sub%%::/*}:" ;;
		*) prefix="${sub%.0/24}." ;;
		esac
		if hit=$(grep -m1 -F -- "$prefix" <<<"$host_addrs"); then
			fail "test 9: network $n: the host has the address $hit in $sub"
			ok=false
		fi
	done
	$ok && pass "test 9: network $n internal=true, gateway mode isolated, no host address in it"
done

# The operator's line in architecture section 7 that lists the internal
# subnets (the host must hold no address in them), taken from the document,
# so the document cannot drift from what is tested. It runs with no active
# profile, as for an operator without .env or COMPOSE_PROFILES: it must
# still list exactly the subnets checked above (#66). The CI checkout has
# no .env; a local .env sets the profiles again, so only a run without one
# proves that.
#
# That line is CI input, so it is checked before anything runs. Only this
# one form is accepted: `docker compose --profile '*' config --format json
# | jq -r '<filter>'`, word for word, with a filter of letters, digits,
# spaces and . [ ] | ( ) _ - only (no $, quote, backtick or @), whose only
# jq function is select (no env, input or other builtin; field names after
# a dot are free). Any other line fails here without running. The shell
# never reads the line: the fixed words run as written here, and the
# filter goes to jq as one argument. What stays possible is a jq program
# over the template's own configuration.
arch=docs/development/architecture.md
doc_re=$'^ *`docker compose --profile \'[*]\' config --format json [|] jq -r \'([][a-zA-Z0-9 .|()_-]+)\'`[.]?$'
doc_line=$(awk '/^## 7\. /{ s = 1; next } /^## /{ s = 0 } s && /config --format json \| jq/' "$arch")
# words: the lines of stdin, sorted, on one line (no xargs: a quote in the
# output must give a FAIL below, not end the script).
words() { sort | paste -sd ' ' -; }
want_subnets=$(jq -r '.networks | to_entries[] | select(.key != "edge-public") | .value.ipam.config[].subnet' <<<"$config" | words)
if [[ $doc_line == *$'\n'* ]] || ! [[ $doc_line =~ $doc_re ]]; then
	fail "test 9: $arch section 7 has no single subnet line of exactly the form \`docker compose --profile '*' config --format json | jq -r '<filter>'\` (filter: letters, digits, spaces, . [ ] | ( ) _ -); nothing was run: [$doc_line]"
else
	doc_filter=${BASH_REMATCH[1]}
	# The bare names in the filter (jq functions and keywords; a name right
	# after a dot is a field). Only select is allowed.
	names=$(jq -nr --arg f "$doc_filter" '[$f | scan("(?<![.A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*")] - ["select"] | join(" ")')
	if [ -n "$names" ]; then
		fail "test 9: the section 7 filter uses the jq names [$names]; only select is allowed; nothing was run: $doc_filter"
	elif ! got=$(
		unset COMPOSE_PROFILES
		docker compose --profile '*' config --format json | jq -r "$doc_filter"
	); then
		fail "test 9: the section 7 line failed with no active profile, filter: $doc_filter"
	else
		got=$(words <<<"$got")
		if [ -n "$want_subnets" ] && [ "$got" = "$want_subnets" ]; then
			pass "test 9: the section 7 line lists the $(wc -w <<<"$got") internal subnets with no active profile, filter: $doc_filter"
		else
			fail "test 9: the section 7 line lists [$got] with no active profile, want [$want_subnets], filter: $doc_filter"
		fi
	fi
fi

# The host cannot reach the services without authentication on the
# internal networks (the bridge has no address there), while a container
# on the same network can (#61).
for probe in filter-rspamd:filter-private:11333 filter-clamd:filter-private:3310 \
	filter-olefy:filter-olefy:10050 groupware-memcached:groupware-private:11211; do
	IFS=: read -r s n port <<<"$probe"
	a=$(jq -r --arg s "$s" --arg n "$n" '.services[$s].networks[$n].ipv4_address' <<<"$config")
	if timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$a" "$port" 2>/dev/null; then
		fail "test 9: the host reaches $s at $a:$port"
	elif ! client "$n" tcp_open "$a" "$port" >/dev/null; then
		fail "test 9: a container on $n does not reach $s at $a:$port either; the host check proves nothing"
	else
		pass "test 9: the host cannot reach $s at $a:$port; a container on $n can"
	fi
done
for s in "${expected_services[@]}"; do
	c=$(container "$s")
	[ -n "$c" ] || continue
	got=$(docker inspect "$c" | jq -r --arg p "${project}_" '.[0].NetworkSettings.Networks | keys[] | ltrimstr($p)' | sort | xargs)
	if [ "$got" != "${want_networks[$s]}" ]; then
		fail "test 9: $s is on [$got], want [${want_networks[$s]}]"
		continue
	fi
	# Every address is the fixed one from the Compose file.
	ok=true
	for n in $got; do
		want4=$(jq -r --arg s "$s" --arg n "$n" '.services[$s].networks[$n].ipv4_address // ""' <<<"$config")
		want6=$(jq -r --arg s "$s" --arg n "$n" '.services[$s].networks[$n].ipv6_address // ""' <<<"$config")
		got4=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${project}_$n\").IPAddress}}" "$c")
		got6=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${project}_$n\").GlobalIPv6Address}}" "$c")
		if [ -z "$want4" ] || [ "$got4" != "$want4" ]; then
			fail "test 9: $s on $n has IPv4 '$got4', want the fixed '$want4'"
			ok=false
		fi
		[[ $got6 == *:* ]] || got6=""
		if [ -n "$want6" ] && { [ -z "$got6" ] || [ "$(full6 "$got6")" != "$(full6 "$want6")" ]; }; then
			fail "test 9: $s on $n has IPv6 '$got6', want the fixed '$want6'"
			ok=false
		fi
	done
	$ok && pass "test 9: $s on [$got] with its fixed addresses"
	ports=$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$c" |
		jq -r 'to_entries[]? | .key as $k | .value[] | "\(.HostIp) \(.HostPort) \($k)"' | sort | xargs)
	if [ "$s" = edge-postfix ]; then
		want_ports="$EDGE_IPV4 25 25/tcp"
		if [ "$public_v6" = true ]; then
			want_ports=$(printf '%s\n' "$want_ports" "$EDGE_IPV6 25 25/tcp" | sort | xargs)
		fi
		if [ "$ports" = "$want_ports" ]; then
			pass "test 9: edge-postfix publishes only $ports"
		else
			fail "test 9: edge-postfix publishes [$ports], want [$want_ports]"
		fi
	elif [ -n "$ports" ]; then
		fail "test 9: $s publishes [$ports]; only edge-postfix may publish"
	fi
done

# ---- test 10: privileges ----------------------------------------------------

echo "---- test 10: privileges"
for s in "${expected_services[@]}"; do
	c=$(container "$s")
	[ -n "$c" ] || continue
	hc=$(docker inspect "$c" | jq '.[0].HostConfig')
	caps=$(jq -r '.CapAdd // [] | .[] | ltrimstr("CAP_")' <<<"$hc" | sort | xargs)
	drop=$(jq -r '.CapDrop // [] | .[] | ltrimstr("CAP_")' <<<"$hc" | sort | xargs)
	ok=true
	if [ "$caps" != "${want_caps[$s]:-}" ]; then
		fail "test 10: $s has CapAdd [$caps], want [${want_caps[$s]:-}]"
		ok=false
	fi
	if [ "$drop" != ALL ]; then
		fail "test 10: $s has CapDrop [$drop], want [ALL]"
		ok=false
	fi
	if ! jq -e '(.SecurityOpt // []) | index("no-new-privileges:true")' <<<"$hc" >/dev/null; then
		fail "test 10: $s runs without no-new-privileges"
		ok=false
	fi
	if [ "$(jq -r .Privileged <<<"$hc")" != false ]; then
		fail "test 10: $s is privileged"
		ok=false
	fi
	mode=$(jq -r '"\(.NetworkMode) \(.PidMode) \(.IpcMode)"' <<<"$hc")
	if [[ " $mode " == *" host "* || $mode == *container:* ]]; then
		fail "test 10: $s shares a namespace with the host or a container (network, pid, ipc: $mode)"
		ok=false
	fi
	sockets=$(docker inspect "$c" | jq -r '.[0].Mounts[] | select(.Source | test("docker\\.sock|/run/docker|containerd")) | .Source')
	if [ -n "$sockets" ]; then
		fail "test 10: $s mounts $sockets"
		ok=false
	fi
	want_pids=$(jq -r --arg s "$s" '.services[$s].pids_limit // 0' <<<"$config")
	pids=$(jq -r '.PidsLimit // 0' <<<"$hc")
	if [ "$want_pids" -le 0 ] || [ "$pids" != "$want_pids" ]; then
		fail "test 10: $s has PidsLimit $pids, want the template's pids_limit ($want_pids, above 0)"
		ok=false
	fi
	# Every process's uid, read on the host. Only Postfix's master (and
	# tini and the scripts that start it) runs as root, and its health
	# probe, which Docker runs as the image's user.
	procs=$(docker top "$c" -eo pid,uid,comm | awk 'NR > 1 { print $2, $3 }')
	root=$(awk '$1 == 0 { print $2 }' <<<"$procs" | sort -u | xargs)
	if [ "$s" = edge-postfix ]; then
		# shellcheck disable=SC2086 # one name per word
		extra=$(printf '%s\n' $root | grep -vxE 'tini|keepia-reload-w|postfix-script|master|keepia-health' | xargs || true)
		[[ " $root " == *" master "* ]] || {
			fail "test 10: edge-postfix runs no master as root (root: [$root])"
			ok=false
		}
		if [ -n "$extra" ]; then
			fail "test 10: edge-postfix runs [$extra] as root; only the master and its launchers may"
			ok=false
		fi
	elif [ -n "$root" ]; then
		fail "test 10: $s runs [$root] as root"
		ok=false
	fi
	uids=$(awk '{ print $1 }' <<<"$procs" | sort -un | xargs)
	$ok && pass "test 10: $s: CapAdd [${caps}], CapDrop ALL, no-new-privileges, PidsLimit $pids, uids [$uids]"
done
# The one-shot guard has exited: its configuration, not its processes.
for s in "${oneshot_services[@]}"; do
	c=$(container "$s")
	[ -n "$c" ] || continue
	got=$(docker inspect "$c" | jq -r '.[0] | [
		"CapAdd=\((.HostConfig.CapAdd // []) | map(ltrimstr("CAP_")) | join(","))",
		"CapDrop=\((.HostConfig.CapDrop // []) | map(ltrimstr("CAP_")) | join(","))",
		"nnp=\((.HostConfig.SecurityOpt // []) | index("no-new-privileges:true") != null)",
		"privileged=\(.HostConfig.Privileged)",
		"network=\(.HostConfig.NetworkMode)",
		"readonly=\(.HostConfig.ReadonlyRootfs)",
		"user=\(.Config.User)",
		"pids=\(.HostConfig.PidsLimit // 0)",
		"mounts=\([.Mounts[] | select(.Type != "bind")] | length)"
	] | join(" ")')
	want="CapAdd= CapDrop=ALL nnp=true privileged=false network=none readonly=true user=65534:65534 pids=$(jq -r --arg s "$s" '.services[$s].pids_limit // 0' <<<"$config") mounts=0"
	if [ "$got" = "$want" ]; then
		pass "test 10: $s: $got"
	else
		fail "test 10: $s has [$got], want [$want]"
	fi
done
# edge-postfix runs its image's entrypoint and command, with the edge
# address check put in after `tini --` (#61). The template copies both from
# images/postfix/Dockerfile, so a change on one side must reach the other
# (#66): compared with the image this container runs, by its ID.
c=$(container edge-postfix)
if [ -n "$c" ]; then
	got=$(docker inspect "$c" | jq -c '.[0].Config | {Entrypoint, Cmd}')
	img=$(docker image inspect "$(docker inspect -f '{{.Image}}' "$c")" | jq -c '.[0].Config | {Entrypoint, Cmd}')
	want=$(jq -c 'if .Entrypoint[0:2] == ["/usr/bin/tini", "--"]
		then .Entrypoint |= (.[0:2] + ["sh", "/etc/keepia/check-edge-addresses.sh"] + .[2:])
		else .Entrypoint = "the image entrypoint \(.Entrypoint) does not start with tini --" end' <<<"$img")
	if [ "$got" = "$want" ]; then
		pass "test 10: edge-postfix runs its image's entrypoint and command with the edge address check after tini: $got"
	else
		fail "test 10: edge-postfix runs $got, want $want (its image has $img)"
	fi
fi

# ---- test 11: volumes ---------------------------------------------------------

# Tests 11 and 12 use the helpers (helper, client) defined at the top.

# smtp_talk <host> <port> <line>...: an SMTP/LMTP client in bash. It reads
# the greeting, then sends each line and prints the server's reply to it
# (up to its last line, "<code> "). A line with CRLFs inside is a message
# body ending in ".", which gets one reply.
smtp_talk() {
	local host=$1 port=$2 l cmd
	shift 2
	exec 3<>"/dev/tcp/$host/$port" || return 1
	smtp_reply() {
		while IFS= read -r -t 10 l <&3; do
			l=${l%$'\r'}
			echo "$l"
			[[ $l =~ ^[0-9]{3}\  ]] && return 0
		done
		echo "(no complete reply within 10 s)"
		return 1
	}
	smtp_reply || return 1
	for cmd in "$@"; do
		printf '%s\r\n' "$cmd" >&3
		echo ">> ${cmd%%$'\r'*}"
		smtp_reply || return 1
	done
}

# imap_login <host> <port> <user> <password>: the greeting and the tagged
# reply to LOGIN.
imap_login() {
	local l
	exec 3<>"/dev/tcp/$1/$2" || return 1
	IFS= read -r -t 10 l <&3 || return 1
	echo "${l%$'\r'}"
	printf 'a LOGIN %s %s\r\n' "$3" "$4" >&3
	while IFS= read -r -t 10 l <&3; do
		l=${l%$'\r'}
		echo "$l"
		[[ $l == "a "* ]] && break
	done
	printf 'b LOGOUT\r\n' >&3
}

echo "---- test 11: volumes"
named_volumes=$(jq -r '.volumes[].name' <<<"$config" | sort | xargs)

store_addr=$(jq -r '.services["store-dovecot"].networks["store-private"].ipv4_address' <<<"$config")
# store-users belongs to root (the agent writes it from 0.2.0 on); the
# Dovecot user only reads it.
helper --network none --user 0 --entrypoint sh -v "${project}_store-users:/u" "$helper_image" \
	-c 'echo "probe@example.org:{PLAIN}compose-test::::::" >/u/users.passwd && chmod 0644 /u/users.passwd' ||
	fail "test 11: could not write the user line into store-users"
lmtp=$(client store-private smtp_talk "$store_addr" 24 "LHLO probe.example.org" \
	"MAIL FROM:<sender@example.org>" "RCPT TO:<probe@example.org>" "DATA" \
	$'Subject: keepia compose test 11\r\n\r\ntest 11\r\n.' "QUIT") || true
if [[ $lmtp == *"250 2.0.0 <probe@example.org>"*"Saved"* ]]; then
	pass "test 11: LMTP to store-dovecot: $(grep -m1 'Saved' <<<"$lmtp")"
else
	fail "test 11: LMTP to store-dovecot did not save the message: $(tr '\n' ' ' <<<"$lmtp" | cut -c1-400)"
fi
# The mail volumes belong to the Dovecot user (1000).
files=$(helper --network none --user 1000:1000 --entrypoint sh -v "${project}_store-mail:/m:ro" "$helper_image" \
	-c 'find /m -path "*/Maildir/new/*" -type f' 2>&1 || true)
if [[ $files == /m/example.org/probe/Maildir/new/* ]]; then
	files=${files%%$'\n'*}
	pass "test 11: the message is in the named volume store-mail: ${files#/m/}"
else
	fail "test 11: no message in the named volume store-mail (found: [$files])"
fi
edge_files=$(helper --network none --user 1000:1000 --entrypoint sh -v "${project}_edge-vmail:/v:ro" "$helper_image" \
	-c 'find /v -mindepth 1' 2>&1 || true)
if [ -z "$edge_files" ]; then
	pass "test 11: edge-vmail is empty"
else
	fail "test 11: edge-vmail is not empty: $(xargs <<<"$edge_files" | cut -c1-200)"
fi
anon=0
for s in "${expected_services[@]}" "${oneshot_services[@]}"; do
	c=$(container "$s")
	[ -n "$c" ] || continue
	while read -r vname dest; do
		[ -n "$vname" ] || continue
		if [[ " $named_volumes " != *" $vname "* ]]; then
			fail "test 11: $s has the volume $vname at $dest, which is not a named volume of the template"
			anon=$((anon + 1))
		fi
	done < <(docker inspect "$c" | jq -r '.[0].Mounts[] | select(.Type == "volume") | "\(.Name) \(.Destination)"')
done
[ "$anon" = 0 ] && pass "test 11: every volume is one of the template's named volumes ($named_volumes)"

# ---- test 12: edge tempfail -------------------------------------------------

echo "---- test 12: edge tempfail"
edge_addr=$(jq -r '.services["edge-dovecot"].networks["edge-private"].ipv4_address' <<<"$config")
out=$(client edge-private smtp_talk "$edge_addr" 24 "LHLO probe.example.org" \
	"MAIL FROM:<sender@example.org>" "RCPT TO:<probe@example.org>" "QUIT") || true
if rcpt=$(grep -m1 '^451 4\.3\.0' <<<"$out"); then
	pass "test 12: LMTP RCPT to edge-dovecot: $rcpt"
else
	fail "test 12: LMTP RCPT to edge-dovecot did not get 451 4.3.0: $(tr '\n' ' ' <<<"$out" | cut -c1-300)"
fi
out=$(client edge-private imap_login "$edge_addr" 143 probe@example.org compose-test) || true
if login=$(grep -m1 '^a NO \[UNAVAILABLE\]' <<<"$out"); then
	pass "test 12: IMAP LOGIN to edge-dovecot: $login"
else
	fail "test 12: IMAP LOGIN to edge-dovecot did not get NO [UNAVAILABLE]: $(tr '\n' ' ' <<<"$out" | cut -c1-300)"
fi

# ---- test 13: edge NAT --------------------------------------------------------

echo "---- test 13: edge NAT"
rules=$({
	$sudo iptables-save -t nat 2>/dev/null || true
	$sudo ip6tables-save -t nat 2>/dev/null || true
	if command -v nft >/dev/null; then $sudo nft list ruleset 2>/dev/null || true; fi
})
families=4
[ "$public_v6" = true ] && families="4 6"
postfix=$(container edge-postfix)
[ -n "$postfix" ] || {
	fail "test 13: edge-postfix has no container"
	families=""
}
for fam in $families; do
	if [ "$fam" = 4 ]; then
		edge_ip=$EDGE_IPV4
		subnet=$(jq -r '.networks["edge-public"].ipam.config[].subnet | select(contains(".") )' <<<"$config")
		dest=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$public\").IPAddress}}" "$postfix")
	else
		edge_ip=$EDGE_IPV6
		subnet=$(jq -r '.networks["edge-public"].ipam.config[].subnet | select(contains(":"))' <<<"$config")
		dest=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$public\").GlobalIPv6Address}}" "$postfix")
	fi
	snat=$(grep -F -- "$subnet" <<<"$rules" | grep -iE 'snat' | grep -F -- "$edge_ip" | head -1 || true)
	if [ -n "$snat" ]; then
		pass "test 13: IPv$fam SNAT of edge-public to $edge_ip: $(xargs <<<"$snat")"
	else
		fail "test 13: no IPv$fam SNAT of $subnet to $edge_ip"
	fi
	dnat=$(grep -F -- "$edge_ip" <<<"$rules" | grep -iE 'dnat' | grep -E 'dport 25( |$)' | grep -F -- "$dest" | head -1 || true)
	if [ -n "$dnat" ]; then
		pass "test 13: IPv$fam DNAT of $edge_ip:25 to edge-postfix: $(xargs <<<"$dnat")"
	else
		fail "test 13: no IPv$fam DNAT of $edge_ip port 25 to $dest"
	fi
done
[ "$families" = 4 ] && echo "note test 13: edge-public has no IPv6 here; only IPv4 checked"

# ---- test 15: the key-encryption key -----------------------------------------

# The KEK volume (#96, CD1): only keepia mounts it; serve created the KEK
# at its first start, mode 0400 and uid 65532 in a 0700 directory, and
# logged the warning; a restart loads it without a second "created" line.
echo "---- test 15: the key-encryption key"
kek_volume="${project}_keepia-kek"
mounted_by=()
for s in "${expected_services[@]}" "${oneshot_services[@]}"; do
	c=$(container "$s")
	[ -n "$c" ] || continue
	if docker inspect "$c" | jq -e --arg v "$kek_volume" '.[0].Mounts[] | select(.Type == "volume" and .Name == $v)' >/dev/null; then
		mounted_by+=("$s")
	fi
done
if [ "${mounted_by[*]}" = keepia ]; then
	pass "test 15: $kek_volume is mounted only into keepia"
else
	fail "test 15: $kek_volume is mounted into [${mounted_by[*]}], want [keepia]"
fi
c=$(container keepia)
dest=$(docker inspect "$c" | jq -r --arg v "$kek_volume" '.[0].Mounts[] | select(.Name == $v) | "\(.Destination) rw=\(.RW)"')
if [ "$dest" = "/var/lib/keepia/kek rw=true" ]; then
	pass "test 15: keepia mounts it at $dest"
else
	fail "test 15: keepia mounts $kek_volume as '$dest', want '/var/lib/keepia/kek rw=true'"
fi
# Read with the helper image (pinned, already in the store) as uid 65532,
# the volume read-only and no network.
modes=$(helper --network none --user 65532:65532 --entrypoint stat -v "$kek_volume:/k:ro" "$helper_image" \
	-c '%n %F %a %u' /k /k/kek 2>&1 || true)
want_modes=$'/k directory 700 65532\n/k/kek regular file 400 65532'
if [ "$modes" = "$want_modes" ]; then
	pass "test 15: $(tr '\n' ';' <<<"$modes")"
else
	fail "test 15: the KEK volume holds [$(tr '\n' ';' <<<"$modes")], want [$(tr '\n' ';' <<<"$want_modes")]"
fi
created=$(docker logs "$c" 2>&1 | grep -c 'control secrets created' || true)
warning=$(docker logs "$c" 2>&1 | grep -m1 'control secrets created' || true)
if [ "$created" = 1 ] && [[ $warning == *level=WARN*"/var/lib/keepia/kek/kek on the volume keepia-kek"* ]]; then
	pass "test 15: keepia logged the warning once: ${warning:0:160}"
else
	fail "test 15: keepia logged 'control secrets created' $created times, want once at WARN naming the volume: ${warning:0:300}"
fi
reminders=$(docker logs "$c" 2>&1 | grep -c 'control secrets never exported' || true)
if ! out=$(timeout 120 docker compose restart --timeout 30 keepia 2>&1); then
	fail "test 15: docker compose restart keepia failed: $(tr '\n' ' ' <<<"$out" | tail -c 300)"
elif ! out=$(timeout 180 docker compose up -d --wait --no-build --pull never keepia 2>&1); then
	fail "test 15: keepia is not healthy after the restart: $(tr '\n' ' ' <<<"$out" | tail -c 300)"
else
	created=$(docker logs "$c" 2>&1 | grep -c 'control secrets created' || true)
	reminder=$(docker logs "$c" 2>&1 | grep -c 'control secrets never exported' || true)
	health=$(docker inspect -f '{{.State.Health.Status}}' "$c")
	if [ "$created" = 1 ] && [ "$reminder" = $((reminders + 1)) ] && [ "$health" = healthy ]; then
		pass "test 15: after a restart keepia is $health, with no second 'created' line and one more 'never exported' reminder"
	else
		fail "test 15: after a restart: health $health, 'created' $created times (want 1), 'never exported' $reminder times (want $((reminders + 1)))"
	fi
fi

# ---- test 16: a refused row stays out of the PostgreSQL log --------------------

# A CHECK that refuses a row makes PostgreSQL log the row as DETAIL
# ("Failing row contains (...)"), and a mailboxes row holds the password
# hash. postgres runs with log_error_verbosity=terse, which logs no DETAIL
# (#95, Review B F1). The probe inserts, in one transaction that the
# refusal rolls back, an active store and a mailbox with quota -1, so the
# mailbox passes the triggers and fails mailboxes_quota_bytes_range. The
# refusal must be in the log (the probe reached the server and its error
# was logged), without a "Failing row" line. The hash is a placeholder.
echo "---- test 16: a refused mailbox row is not in the PostgreSQL log"
probe_sql="INSERT INTO customer_groups (name) VALUES ('compose-probe');
INSERT INTO domains (group_id, name) SELECT id, 'compose-probe.example' FROM customer_groups WHERE name = 'compose-probe';
INSERT INTO servers (name, roles) VALUES ('compose-probe', '{store}');
INSERT INTO stores (server_id, gate_name, gate_ipv4, egress_port, state) SELECT id, 'compose-probe.store.keepia.internal', '192.0.2.99', 65000, 'active' FROM servers WHERE name = 'compose-probe';
INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) SELECT d.id, 'probe', '{SSHA512}cGxhY2Vob2xkZXItY29tcG9zZS1wcm9iZQ==', -1, s.id FROM domains d, stores s WHERE d.name = 'compose-probe.example' AND s.gate_name = 'compose-probe.store.keepia.internal';"
out=$(timeout 60 docker compose exec -T postgres psql -X -q -v ON_ERROR_STOP=1 -U keepia -d keepia -c "$probe_sql" 2>&1 || true)
logs=$(timeout 60 docker compose logs --no-color postgres 2>&1 || true)
if [[ $out != *mailboxes_quota_bytes_range* ]]; then
	fail "test 16: the probe was not refused by mailboxes_quota_bytes_range: $(head -n1 <<<"$out" | cut -c1-200)"
elif [[ $logs != *mailboxes_quota_bytes_range* ]]; then
	fail "test 16: the PostgreSQL log has no line for the refused probe"
elif grep -q 'Failing row' <<<"$logs"; then
	fail "test 16: the PostgreSQL log quotes the refused row ('Failing row contains'), want log_error_verbosity=terse"
else
	pass "test 16: the refusal is logged without the row (log_error_verbosity=terse)"
fi

# ---- resources ----------------------------------------------------------------

echo "---- resources (docker stats; image size in MB)"
mapfile -t ids < <(docker ps -q --filter "label=com.docker.compose.project=$project")
stats=""
if [ "${#ids[@]}" -gt 0 ]; then
	stats=$(docker stats --no-stream --format '{{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}|{{.PIDs}}' "${ids[@]}" | sort)
fi
table=$(while IFS='|' read -r name mem perc cpu pids; do
	[ -n "$name" ] || continue
	health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$name")
	limit=$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$name")
	size=$(docker image inspect -f '{{.Size}}' "$(docker inspect -f '{{.Image}}' "$name")")
	echo "$name|$health|$mem|$perc|$cpu|$pids / $limit|$((size / 1000000))"
done <<<"$stats")
printf '%s\n' "$table" | tr '|' '\t'
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "### Compose template: containers"
		echo
		echo "| Container | Health | Memory (use / limit) | Memory % | CPU % | PIDs (use / limit) | Image MB |"
		echo "|---|---|---|---:|---:|---:|---:|"
		printf '%s\n' "$table" | sed 's/|/ | /g; s/^/| /; s/$/ |/'
	} >>"$GITHUB_STEP_SUMMARY"
fi

# ---- test 14b: a stop of edge-postfix -----------------------------------------

# Last, because it stops a service (test 7, which the CI job runs next,
# needs only postgres and keepia). A stop must end edge-postfix with status
# 0, not by the kill after the timeout: its entrypoint puts the edge
# address check between tini and Postfix's launcher, and the check must
# exec the launcher, or the stop signal ends the check's sh instead (#66).
# It must be running (not restarting) right before the stop, or a
# container that had already exited 0 on its own would pass. The job's
# own `docker compose down` removes the container with its status, so it
# is read here.
echo "---- test 14b: a stop of edge-postfix exits 0"
c=$(container edge-postfix)
before=""
[ -z "$c" ] || before=$(docker inspect -f '{{.State.Running}} {{.State.Restarting}}' "$c" || true)
if [ -z "$c" ]; then
	fail "test 14b: edge-postfix has no container to stop"
elif [ "$before" != "true false" ]; then
	fail "test 14b: edge-postfix is not running before the stop (running, restarting: $before); nothing was stopped"
elif ! out=$(timeout 60 docker compose stop --timeout 30 edge-postfix 2>&1); then
	fail "test 14b: docker compose stop edge-postfix failed: $(tr '\n' ' ' <<<"$out" | tail -c 300)"
else
	st=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}' "$c")
	if [ "$st" = "exited 0 false" ]; then
		pass "test 14b: a running edge-postfix stops with exit 0 (status, exit code, OOM-killed: $st)"
	else
		fail "test 14b: after a stop, edge-postfix is [$st] (status, exit code, OOM-killed), want [exited 0 false]"
		docker logs --tail 20 "$c" >&2 || true
	fi
fi

if [ "$failed" != 0 ]; then
	echo "FAIL compose-test: $failed failure(s)" >&2
	exit 1
fi
echo "ok   compose-test: tests 6, 8-13, 14, 14b, 15 and 16 passed"
