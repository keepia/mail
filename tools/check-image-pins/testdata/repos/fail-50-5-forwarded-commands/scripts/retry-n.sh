#!/bin/sh
# Runs its arguments after the first as a command, up to $1 times.
n=$1
shift
i=0
while [ "$i" -lt "$n" ]; do
	"$@" && exit 0
	i=$((i + 1))
done
exit 1
