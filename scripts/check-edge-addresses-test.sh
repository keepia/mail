#!/bin/sh
# Tests deploy/edge/check-edge-addresses.sh, the guard that refuses edge
# addresses meaning every interface (#61). No Docker, no network: each
# case runs the script with sh and checks its exit status and message.
# `make image-scripts-test` runs it; the compose job (compose-test.sh,
# test 14) shows that the guard stops edge-postfix.
#
# Usage: sh scripts/check-edge-addresses-test.sh
set -u

cd "$(dirname "$0")/.."
guard=deploy/edge/check-edge-addresses.sh

failed=0
n=0
# expect <ok|wildcard|invalid> <EDGE_IPV4> <EDGE_IPV6>
expect() {
	n=$((n + 1))
	out=$(EDGE_IPV4=$2 EDGE_IPV6=$3 sh "$guard" 2>&1)
	rc=$?
	case $1 in
	ok) want_rc=0 want_msg="edge addresses" ;;
	wildcard) want_rc=1 want_msg="every interface" ;;
	invalid) want_rc=1 want_msg="is not an IPv" ;;
	esac
	case $out in
	*"$want_msg"*) msg_ok=true ;;
	*) msg_ok=false ;;
	esac
	if [ "$rc" = "$want_rc" ] && $msg_ok; then
		echo "ok   $1: EDGE_IPV4='$2' EDGE_IPV6='$3'"
	else
		echo "FAIL want $1 (exit $want_rc, '$want_msg'): EDGE_IPV4='$2' EDGE_IPV6='$3' gave exit $rc: $out" >&2
		failed=$((failed + 1))
	fi
}

good4=192.0.2.10
good6=2001:db8::10

# Accepted: the documentation defaults and other own addresses.
expect ok "$good4" "$good6"
expect ok 198.51.100.7 2001:db8:0:1::25
expect ok 203.0.113.255 2001:DB8::A
expect ok 192.0.2.1 2001:db8:1:2:3:4:5:6
expect ok 192.0.2.1 2001:db8::
expect ok 192.0.2.1 2001:db8:1:2:3:4:5::

# Every interface, IPv4: 0.0.0.0 and the rest of 0.0.0.0/8.
expect wildcard 0.0.0.0 "$good6"
expect wildcard 0.1.2.3 "$good6"

# Every interface, IPv6: :: in every spelling, and the ::/80 forms
# Docker may unmap to 0.0.0.0 (or that are no edge address at all).
expect wildcard "$good4" ::
expect wildcard "$good4" ::0
expect wildcard "$good4" 0::
expect wildcard "$good4" 0::0
expect wildcard "$good4" 0:0:0:0:0:0:0:0
expect wildcard "$good4" 0000:0000:0000:0000:0000:0000:0000:0000
expect wildcard "$good4" ::ffff:0:0
expect wildcard "$good4" ::FFFF:0:0
expect wildcard "$good4" ::1
expect wildcard "$good4" 0:0:0:0:0:ffff:c000:20a

# Not an address of the family, or a form the guard does not read.
expect invalid "" "$good6"
expect invalid " " "$good6"
expect invalid "$good4" ""
expect invalid 0 "$good6"
expect invalid 000.0.0.0 "$good6"
expect invalid 192.0.2.010 "$good6"
expect invalid 192.0.2.256 "$good6"
expect invalid 192.0.2 "$good6"
expect invalid 192.0.2.10.1 "$good6"
expect invalid 192.0.2.10. "$good6"
expect invalid .192.0.2.10 "$good6"
expect invalid 192..2.10 "$good6"
expect invalid :: "$good6"
expect invalid "$good4" 0.0.0.0
expect invalid "$good4" "[::]"
expect invalid "$good4" ::ffff:0.0.0.0
expect invalid "$good4" ::0.0.0.0
expect invalid "$good4" "fe80::1%eth0"
expect invalid "$good4" 2001:db8::1::2
expect invalid "$good4" 2001:db8:::2
expect invalid "$good4" 2001:db8:1:2:3:4:5:6:7
expect invalid "$good4" 2001:db8:1:2:3:4:5
expect invalid "$good4" 2001:db8::1:2:3:4:5:6
expect invalid "$good4" 2001:db8::12345
expect invalid "$good4" :2001:db8::1
expect invalid "$good4" 2001:db8::1:
expect invalid "$good4" 2001

# Both wrong: both are named.
n=$((n + 1))
out=$(EDGE_IPV4=0.0.0.0 EDGE_IPV6=:: sh "$guard" 2>&1)
case $out in
*"EDGE_IPV4='0.0.0.0'"*"EDGE_IPV6='::'"*) echo "ok   both wildcards are named" ;;
*)
	echo "FAIL both wildcards: $out" >&2
	failed=$((failed + 1))
	;;
esac

# Unset (not empty): refused as well.
n=$((n + 1))
out=$(env -u EDGE_IPV4 -u EDGE_IPV6 sh "$guard" 2>&1) && rc=0 || rc=$?
if [ "$rc" = 1 ]; then
	echo "ok   unset variables are refused"
else
	echo "FAIL unset variables gave exit $rc: $out" >&2
	failed=$((failed + 1))
fi

if [ "$failed" != 0 ]; then
	echo "FAIL check-edge-addresses-test: $failed of $n failed" >&2
	exit 1
fi
echo "ok   check-edge-addresses-test: $n cases"
