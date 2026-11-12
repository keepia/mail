# Keepia Mail: refuses edge addresses that would publish port 25 on every
# interface (#61). The Compose service edge-addresses runs it before
# edge-postfix starts (depends_on: service_completed_successfully), so a
# wildcard in EDGE_IPV4 or EDGE_IPV6 stops the start of the edge role
# before anything is published.
#
# It accepts exactly one form per family and refuses the rest:
# - EDGE_IPV4: a dotted quad (four decimal octets, no leading zeros, each
#   at most 255) whose first octet is not 0 (0.0.0.0 is every interface,
#   0.0.0.0/8 is "this network");
# - EDGE_IPV6: hex groups with colons, at most one "::", no embedded IPv4,
#   no zone, no brackets, and not in ::/80: that range holds :: (every
#   interface), ::1, and the IPv4-mapped and -compatible forms, which
#   Docker may unmap to an IPv4 address such as 0.0.0.0.
# An empty value cannot reach it through Compose (the template's :- turns
# it into the documentation address); it is refused all the same.
#
# Only shell builtins: the Dovecot image it runs in has no coreutils.
# Usage: EDGE_IPV4=<a> EDGE_IPV6=<b> sh check-edge-addresses.sh
set -eu

bad=0
refuse() {
	echo "keepia: $*" >&2
	bad=1
}

# check_v4 <value>: 0 if it is an accepted IPv4 edge address.
check_v4() {
	v=$1
	case $v in
	"" | *[!0-9.]* | .* | *. | *..*) return 1 ;;
	esac
	old_ifs=$IFS
	IFS=.
	# shellcheck disable=SC2086 # split on the dots
	set -- $v
	IFS=$old_ifs
	[ $# = 4 ] || return 1
	for o in "$@"; do
		case $o in
		"" | ????*) return 1 ;;
		0) ;;
		0*) return 1 ;;
		esac
		[ "$o" -le 255 ] || return 1
	done
	[ "$1" != 0 ] || return 2
	return 0
}

# groups <part>: the number of colon-separated hex groups in part (one
# side of a "::"), each one to four hex digits; nothing if one is not.
groups() {
	p=$1
	[ -n "$p" ] || {
		echo 0
		return 0
	}
	case $p in
	:* | *: | *::*) return 1 ;;
	esac
	old_ifs=$IFS
	IFS=:
	# shellcheck disable=SC2086 # split on the colons
	set -- $p
	IFS=$old_ifs
	for g in "$@"; do
		case $g in
		"" | ?????*) return 1 ;;
		esac
	done
	echo $#
}

# zero <part>: 0 if every hex digit in part is 0.
zero() {
	case $1 in
	*[!0:]*) return 1 ;;
	esac
	return 0
}

# check_v6 <value>: 0 if it is an accepted IPv6 edge address, 2 if it is
# in ::/80.
check_v6() {
	v=$1
	case $v in
	"" | *[!0-9A-Fa-f:]* | *::*::* | *:::*) return 1 ;;
	*:*) ;;
	*) return 1 ;;
	esac
	case $v in
	*::*)
		head=${v%%::*}
		tail=${v#*::}
		nh=$(groups "$head") || return 1
		nt=$(groups "$tail") || return 1
		[ $((nh + nt)) -le 7 ] || return 1
		;;
	*)
		head=$v
		tail=
		nh=$(groups "$v") || return 1
		nt=0
		[ "$nh" = 8 ] || return 1
		;;
	esac
	# The first five groups (80 bits): the head's first five, then the
	# zeros of "::", then the tail's leading groups if the head is short.
	nz=$((8 - nh - nt))
	old_ifs=$IFS
	IFS=:
	# shellcheck disable=SC2086 # split on the colons
	set -- $head
	IFS=$old_ifs
	i=0
	first=
	for g in "$@"; do
		[ "$i" -lt 5 ] || break
		first="$first$g:"
		i=$((i + 1))
	done
	while [ "$i" -lt 5 ] && [ "$nz" -gt 0 ]; do
		first="${first}0:"
		i=$((i + 1))
		nz=$((nz - 1))
	done
	if [ "$i" -lt 5 ]; then
		IFS=:
		# shellcheck disable=SC2086 # split on the colons
		set -- $tail
		IFS=$old_ifs
		for g in "$@"; do
			[ "$i" -lt 5 ] || break
			first="$first$g:"
			i=$((i + 1))
		done
	fi
	if zero "$first"; then
		return 2
	fi
	return 0
}

v4=${EDGE_IPV4-}
v6=${EDGE_IPV6-}

rc=0
check_v4 "$v4" || rc=$?
case $rc in
0) ;;
2) refuse "EDGE_IPV4='$v4' means every interface (0.0.0.0/8): port 25 would be published on all of them. Set this server's own IPv4 address." ;;
*) refuse "EDGE_IPV4='$v4' is not an IPv4 address in dotted-quad form (four octets, no leading zeros). Set this server's own IPv4 address." ;;
esac

rc=0
check_v6 "$v6" || rc=$?
case $rc in
0) ;;
2) refuse "EDGE_IPV6='$v6' is in ::/80 (:: means every interface; ::1 and the IPv4-mapped forms are no edge address either). Set this server's own IPv6 address." ;;
*) refuse "EDGE_IPV6='$v6' is not an IPv6 address in hex form (no embedded IPv4, zone or brackets). Set this server's own IPv6 address." ;;
esac

if [ "$bad" != 0 ]; then
	echo "keepia: refusing to start the edge role; fix EDGE_IPV4/EDGE_IPV6 in .env" >&2
	exit 1
fi
echo "keepia: edge addresses $v4 and $v6"
