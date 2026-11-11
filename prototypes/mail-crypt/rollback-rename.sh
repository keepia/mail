#!/bin/sh
# Test tool for phase E2 of prototype #4 (not a migration proposal).
# Usage: rollback-rename.sh MAILDIR
# Dovecot 2.4.5 renames maildir++ folder directories whose name has "~" at
# the start of a hierarchy part other than the first (2.3 stored ".x.\7ey",
# 2.4.5 renames it to ".x.~y" when it lists mailboxes). Dovecot 2.3 cannot
# select such a folder any more. This renames each of them back to the 2.3
# form with mv (no deletion) and prints "OLD -> NEW" for each rename;
# it prints nothing when there is none.
set -eu
maildir=${1:?usage: rollback-rename.sh MAILDIR}
cd "$maildir"
for d in .?*; do
  [ -d "$d" ] || continue
  case "$d" in ..) continue ;; esac
  # Hierarchy parts are separated by "."; the first part keeps its "~"
  # handling (2.4.5 escapes "~" there itself).
  rest=${d#.}
  new=.$(printf '%s\n' "$rest" | sed 's/\.~/.\\7e/g')
  [ "$new" = "$d" ] && continue
  if [ -e "$new" ]; then
    echo "rollback-rename: $new exists, not renaming $d" >&2
    exit 1
  fi
  mv -- "$d" "$new"
  printf '%s -> %s\n' "$d" "$new"
done
