#!/usr/bin/env bash
# Prototype #4: Dovecot 2.4.5 reads mail that Dovecot 2.3.21.1 wrote with
# mailcow's mail_crypt (global keys) and compression settings.
#
# Runs phases 0, A-E, the counter-proofs CP1-CP3 and the hygiene checks,
# prints every command and its result, and ends with PASS or FAIL.
# Everything goes into work/ (git-ignored); the run refuses to start if
# work/ exists and never deletes anything. See README.md.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
W="$HERE/work"
IMG23=dovecot/dovecot:2.3.21.1@sha256:547d28f9a893c93a1d2f6dc164880cd7bfa74009106dfa46b36a6a2ee636d921
IMG24=dovecot/dovecot:2.4.5@sha256:43c14def08a57f25107593cbcf64a0a6fbae84a7b9de7aa038513c9b21e91914
C23=keepia-proto4-d23
C24=keepia-proto4-d24
U=alice@example.test
PY=(python3 -I)
IH="$HERE/imap-hashes.py"
WAIT_S=30      # deadline for the master to answer
CMD_S=120      # deadline for one docker exec

if [ -e "$W" ]; then
  echo "refusing to start: $W exists; remove it by its literal absolute path first (README.md)" >&2
  exit 2
fi
mkdir -p "$W/logs" "$W/imap" "$W/out"
exec > >(tee "$W/transcript.txt") 2>&1 < /dev/null

FAILS=0
step() { printf '\n=== %s\n' "$*"; }
ok() { echo "ok: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
finding() { echo "EXPECTED FINDING: $*"; }
csort() { LC_ALL=C sort "$@"; }

cleanup() { docker rm -f -v "$C23" "$C24" keepia-proto4-conf keepia-proto4-keys >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "check 9 (start): docker volumes before the run"
docker volume ls -q | csort > "$W/out/volumes-before.txt"
echo "$(wc -l < "$W/out/volumes-before.txt") volume(s)"

# ---------------------------------------------------------------- containers
CUR="" CURV="" PHASE="" LOGPID="" CONFOPT=() EXECLOG=""

# start VER STATE KEYDIR PHASE [CONF]: start the master on work/STATE.
start() {
  local ver=$1 state=$2 keys=$3 conf=${5:-} img confdir vol dov
  PHASE=$4
  if [ "$ver" = 23 ]; then
    CUR=$C23 img=$IMG23 confdir="$HERE/conf23" vol=/srv/mail dov=/usr/sbin/dovecot DA=/usr/bin/doveadm
  else
    CUR=$C24 img=$IMG24 confdir="$HERE/conf24" vol=/srv/vmail dov=/dovecot/sbin/dovecot DA=/dovecot/bin/doveadm
  fi
  CURV=$ver
  CONFOPT=()
  [ -n "$conf" ] && CONFOPT=(-c "/etc/dovecot/$conf")
  EXECLOG="$W/logs/$PHASE.exec.log"
  : > "$EXECLOG"
  echo "+ docker run -d --rm --network none --name $CUR (conf$ver${conf:+, -c $conf}, /data = work/$state, /mail_crypt = work/$keys, tmpfs $vol) $dov -F ${CONFOPT[*]}"
  docker run -d --rm --network none --name "$CUR" \
    --mount "type=bind,src=$confdir,dst=/etc/dovecot,readonly" \
    --mount "type=bind,src=$W/$state,dst=/data" \
    --mount "type=bind,src=$W/$keys,dst=/mail_crypt,readonly" \
    --mount "type=tmpfs,dst=$vol" \
    "$img" "$dov" -F "${CONFOPT[@]}" > /dev/null || { fail "$PHASE: docker run"; return 1; }
  local mounts
  mounts=$(docker inspect -f '{{range .Mounts}}{{.Type}}:{{.Destination}} {{end}}' "$CUR")
  if grep -q 'volume:' <<< "$mounts"; then fail "$PHASE: container has a docker volume: $mounts"; else echo "mounts: $mounts(no docker volume)"; fi
  docker logs -f "$CUR" > "$W/logs/$PHASE.log" 2>&1 &
  LOGPID=$!
  local deadline=$((SECONDS + WAIT_S))
  until docker exec "$CUR" "$DA" "${CONFOPT[@]}" user "$U" > /dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "$PHASE: master did not answer within ${WAIT_S}s"
      return 1
    fi
    sleep 0.2
  done
  echo "master answers (doveadm user $U)"
}

# da ARGS...: doveadm in the running container; stdin passes through.
da() {
  echo "+ doveadm ${CONFOPT[*]} $*" >&2
  timeout "$CMD_S" docker exec -i "$CUR" "$DA" "${CONFOPT[@]}" "$@" 2> >(tee -a "$EXECLOG" >&2)
}

# memory: peak memory of the running container (cgroup), then docker stats.
memory() {
  local id peak="" f
  id=$(docker inspect -f '{{.Id}}' "$CUR")
  for f in "/sys/fs/cgroup/memory/docker/$id/memory.max_usage_in_bytes" \
           "/sys/fs/cgroup/system.slice/docker-$id.scope/memory.peak" \
           "/sys/fs/cgroup/docker/$id/memory.peak"; do
    if [ -r "$f" ]; then peak=$(( $(cat "$f") / 1024 / 1024 )); break; fi
  done
  echo "memory $PHASE: peak ${peak:-n/a} MiB (cgroup), now $(docker stats --no-stream --format '{{.MemUsage}}' "$CUR")" | tee -a "$W/out/memory.txt"
}

# stop [expect-error-regex]: doveadm stop, wait for the container, check the logs.
# Without an argument, the logs must have no Error:/Panic:/Fatal:/corrupt line.
# With one (CP1, CP2), they must contain a line matching it instead.
stop() {
  local expect=${1:-}
  # the master ends the container, so docker exec usually reports a non-zero status
  da stop || echo "(doveadm stop: exit $?, the container ended)"
  local deadline=$((SECONDS + WAIT_S))
  while docker ps -a -q --filter "name=^${CUR}\$" | grep -q .; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "$PHASE: container still there after ${WAIT_S}s"
      docker rm -f -v "$CUR" > /dev/null
      break
    fi
    sleep 0.2
  done
  wait "$LOGPID" 2>/dev/null || true
  echo "--- log $PHASE (master, then doveadm/imap stderr)"
  cat "$W/logs/$PHASE.log" "$EXECLOG"
  local errs
  errs=$(cat "$W/logs/$PHASE.log" "$EXECLOG" | grep -E 'Error:|Panic:|Fatal:|corrupt' || true)
  if [ -z "$expect" ]; then
    if [ -z "$errs" ]; then ok "$PHASE: no Error/Panic/Fatal/corrupt lines in the logs"
    else fail "$PHASE: log lines: $errs"; fi
  else
    if printf '%s\n' "$errs" | grep -qE "$expect"; then ok "$PHASE: logs contain the expected error /$expect/ ($(printf '%s\n' "$errs" | grep -cE "$expect") lines)"
    else fail "$PHASE: logs lack the expected error /$expect/"; fi
    if printf '%s\n' "$errs" | grep -qE 'Panic:|Fatal:'; then fail "$PHASE: Panic/Fatal in the logs"; fi
  fi
}

# ------------------------------------------------------------------- helpers
mapfile -t BOXES < <(printf '%s\n' INBOX "Archiv/2025" "a.b" "~tilde" "x/~y" 'back\slash' "Entwürfe" "Sent & Co")
SRC="$W/msgs/src.tsv"

# hash_all OUT [BOX-EXPECTED-TO-FAIL]: one IMAP session per mailbox.
hash_all() {
  local out=$1 expect_no=${2:-} i box f
  : > "$out"
  for i in "${!BOXES[@]}"; do
    box=${BOXES[$i]}
    f="$W/imap/$PHASE-box$i"
    "${PY[@]}" "$IH" cmd "$box" | da exec imap -u "$U" > "$f.txt" 2> "$f.err"
    if "${PY[@]}" "$IH" parse "$box" < "$f.txt" >> "$out" 2> "$f.parse"; then
      [ "$box" = "$expect_no" ] && fail "$PHASE: $box was expected to fail but read fine"
    elif [ "$box" = "$expect_no" ]; then
      finding "$PHASE: $box: $(grep -a '^a ' "$f.txt")"
    else
      fail "$PHASE: $box: $(cat "$f.parse")"
    fi
  done
  echo "--- $(basename "$out") (mailbox uid sha256 size flags)"
  cat "$out"
}

# same A B WHAT: diff two files, print the diff.
same() {
  if diff "$1" "$2" > "$W/out/diff.tmp"; then ok "$3"; else fail "$3"; cat "$W/out/diff.tmp"; fi
}

dirs() { # dirs STATE NAME: top-level folder directories of maildir and index dir
  (cd "$W/$1/vmail/example.test/alice/Maildir" && find . -maxdepth 1 -type d | csort) > "$W/out/dirs-$2-maildir.txt"
  if [ -d "$W/$1/vmail_index/$U" ]; then
    (cd "$W/$1/vmail_index/$U" && find . -maxdepth 1 -type d | csort) > "$W/out/dirs-$2-index.txt"
  else
    : > "$W/out/dirs-$2-index.txt"
  fi
}

# dirdiff OLD NEW: print the directory changes between two snapshots.
dirdiff() {
  local k
  for k in maildir index; do
    echo "--- directory diff $1 -> $2 ($k)"
    { diff "$W/out/dirs-$1-$k.txt" "$W/out/dirs-$2-$k.txt" || true; } | grep '^[<>]' || echo "(none)"
  done
}

uidlists() { # uidlists STATE NAME: first line of every dovecot-uidlist
  (cd "$W/$1/vmail/example.test/alice/Maildir" && find . -name dovecot-uidlist | csort | while IFS= read -r f; do
    printf '%s\t%s\n' "$(dirname "$f")" "$(head -n 1 "$f")"; done) > "$W/out/uidlist-$2.txt"
  echo "--- dovecot-uidlist headers ($2)"
  cat "$W/out/uidlist-$2.txt"
}

record() { # record NAME: metadata, folder list, status and fetch output
  da mailbox metadata get -u "$U" INBOX /private/comment > "$W/out/metadata-$1.txt"
  echo "metadata INBOX /private/comment = $(cat "$W/out/metadata-$1.txt")"
  da mailbox list -u "$U" | csort > "$W/out/list-$1.txt"
  echo "--- mailbox list ($1)"; cat "$W/out/list-$1.txt"
  da mailbox status -u "$U" "messages uidvalidity uidnext guid" "*" | csort > "$W/out/status-$1.txt"
  echo "--- mailbox status ($1)"; cat "$W/out/status-$1.txt"
  da fetch -u "$U" "mailbox uid guid flags size.virtual" all > "$W/out/fetch-$1.txt"
  echo "--- doveadm fetch ($1): $(grep -c '^mailbox: ' "$W/out/fetch-$1.txt") messages, saved in work/out/fetch-$1.txt"
}

time_big() { # time_big: one session that fetches p08 (INBOX UID 8, 2 MB)
  local t0 t1 ms res
  t0=$(date +%s%N)
  "${PY[@]}" "$IH" cmd INBOX 8 | da exec imap -u "$U" > "$W/imap/$PHASE-p08.txt" 2> /dev/null
  t1=$(date +%s%N)
  ms=$(( (t1 - t0) / 1000000 ))
  res=$("${PY[@]}" "$IH" single INBOX 8 "$(awk -F'\t' '$1=="p08"{print $4}' "$SRC")" < "$W/imap/$PHASE-p08.txt")
  echo "timing $PHASE: p08 ($(awk -F'\t' '$1=="p08"{print $5}' "$SRC") bytes) read in one session: ${ms} ms; result: $(cut -f3 <<< "$res")" | tee -a "$W/out/timing.txt"
}

# copy_noindex SRC DST: copy of a state without vmail_index/
copy_noindex() {
  mkdir -p "$W/$2/vmail_index"
  cp -a "$W/$1/vmail" "$W/$1/volatile" "$W/$2/"
  chown 1000:1000 "$W/$2/vmail_index"
}

# ------------------------------------------------------------------ phase 0
step "phase 0: test messages and keys"
"${PY[@]}" "$HERE/make-mail.py" "$W/msgs" || { fail "make-mail.py"; exit 1; }
echo "--- src.tsv (id mailbox variant sha256 size phase dir23)"
cat "$SRC"
mkdir -p "$W/mail_crypt" "$W/mail_crypt-other"
for k in mail_crypt mail_crypt-other; do
  echo "+ (2.3 container) openssl ecparam -name prime256v1 -genkey | openssl pkey -out /mail_crypt/ecprivkey.pem; openssl pkey -in /mail_crypt/ecprivkey.pem -pubout -out /mail_crypt/ecpubkey.pem  [work/$k]"
  docker run --rm --network none --name keepia-proto4-keys \
    --mount type=tmpfs,dst=/etc/dovecot --mount type=tmpfs,dst=/srv/mail \
    --mount "type=bind,src=$W/$k,dst=/mail_crypt" --entrypoint /bin/sh "$IMG23" -c \
    'openssl ecparam -name prime256v1 -genkey | openssl pkey -out /mail_crypt/ecprivkey.pem &&
     openssl pkey -in /mail_crypt/ecprivkey.pem -pubout -out /mail_crypt/ecpubkey.pem &&
     chown 1000:1000 /mail_crypt/ecprivkey.pem /mail_crypt/ecpubkey.pem &&
     openssl pkey -in /mail_crypt/ecprivkey.pem -noout -text | grep "ASN1 OID"' \
    || fail "key generation $k"
done
if cmp -s "$W/mail_crypt/ecpubkey.pem" "$W/mail_crypt-other/ecpubkey.pem"; then fail "the two key pairs are equal"; else ok "two different P-256 key pairs"; fi
if git -C "$HERE" check-ignore -q "$W/mail_crypt/ecprivkey.pem"; then ok "keys are git-ignored"; else fail "keys are not git-ignored"; fi

step "check 1: doveconf -n and versions"
for v in 23 24; do
  if [ $v = 23 ]; then img=$IMG23 vol=/srv/mail bin=/usr/bin; else img=$IMG24 vol=/srv/vmail bin=/dovecot/bin; fi
  for conf in dovecot.conf $( [ $v = 24 ] && echo cp-no-compress.conf cp-visible-escape.conf ); do
    echo "+ doveconf -n -c /etc/dovecot/$conf ($v)"
    if docker run --rm --network none --name keepia-proto4-conf --entrypoint "$bin/doveconf" \
        --mount "type=bind,src=$HERE/conf$v,dst=/etc/dovecot,readonly" \
        --mount "type=bind,src=$W/mail_crypt,dst=/mail_crypt,readonly" \
        --mount "type=tmpfs,dst=$vol" \
        "$img" -n -c "/etc/dovecot/$conf" > "$W/out/doveconf-$v-$conf.txt" 2>&1; then
      ok "doveconf -n exits 0 for conf$v/$conf"
    else
      fail "doveconf -n conf$v/$conf"; cat "$W/out/doveconf-$v-$conf.txt"
    fi
  done
done
echo "--- doveconf -n (2.4, dovecot.conf)"
cat "$W/out/doveconf-24-dovecot.conf.txt"
for v in 23 24; do
  if [ $v = 23 ]; then img=$IMG23 dov=/usr/sbin/dovecot vol=/srv/mail; else img=$IMG24 dov=/dovecot/sbin/dovecot vol=/srv/vmail; fi
  echo "dovecot --version ($v): $(docker run --rm --network none --name keepia-proto4-conf --mount "type=tmpfs,dst=$vol" \
    $( [ $v = 23 ] && echo --mount type=tmpfs,dst=/etc/dovecot ) --entrypoint "$dov" "$img" --version)"
done

# ------------------------------------------------------------------ phase A
step "phase A: Dovecot 2.3.21.1 writes (mailcow settings)"
mkdir -p "$W/main/vmail" "$W/main/vmail_index" "$W/main/volatile"
chown -R 1000:1000 "$W/main"
start 23 main mail_crypt A || exit 1
for box in "${BOXES[@]}"; do
  [ "$box" = INBOX ] && continue
  da mailbox create -u "$U" "$box" || fail "A: mailbox create $box"
done
while IFS=$'\t' read -r id box variant _ _ ph _; do
  [ "$ph" = A ] || continue
  case $variant in
    plain) o=(-o mail_plugins=listescape) ;;
    crypt) o=(-o plugin/zlib_save=) ;;
    crypt+gz) o=(-o plugin/zlib_save=gz) ;;
    crypt+zstd) o=(-o plugin/zlib_save=zstd) ;;
    crypt+lz4) o=() ;;
  esac
  da "${o[@]}" save -u "$U" -m "$box" < "$W/msgs/$id.eml" || fail "A: save $id"
done < "$SRC"
da flags add -u "$U" '\Seen' mailbox INBOX header Message-ID '<p02@example.test>' || fail "A: flags p02"
da flags add -u "$U" '\Seen' mailbox INBOX header Message-ID '<p05@example.test>' || fail "A: flags p05"
da flags add -u "$U" '$label1' mailbox INBOX header Message-ID '<p06@example.test>' || fail "A: flags p06"
da mailbox metadata set -u "$U" INBOX /private/comment proto4 || fail "A: metadata set"
hash_all "$W/out/h23.tsv"
record A
time_big
memory
stop
dirs main A
for k in maildir index; do echo "--- folder directories after A ($k)"; cat "$W/out/dirs-A-$k.txt"; done
uidlists main A

echo "--- check 2: files on disk per folder (from src.tsv)"
MD="$W/main/vmail/example.test/alice/Maildir"
while IFS= read -r d; do
  want=$(D="$d" awk -F'\t' '$6=="A" && $7==ENVIRON["D"]' "$SRC" | wc -l)
  wantc=$(D="$d" awk -F'\t' '$6=="A" && $7==ENVIRON["D"] && $3!="plain"' "$SRC" | wc -l)
  n=0 c=0
  while IFS= read -r -d '' f; do
    n=$((n + 1))
    [ "$(head -c 7 "$f")" = CRYPTED ] && c=$((c + 1))
  done < <(find "$MD/$d/cur" "$MD/$d/new" -type f -print0 2>/dev/null)
  line="folder '$d': $n files (src.tsv: $want), $c start with CRYPTED (src.tsv: $wantc non-plain)"
  if [ "$n" = "$want" ] && [ "$c" = "$wantc" ]; then ok "$line"; else fail "$line"; fi
done < <(awk -F'\t' '$6=="A"{print $7}' "$SRC" | awk '!s[$0]++')
echo "--- on-disk size per message (variant, file size S=/W= in the name)"
find "$MD" -path '*/cur/*' -type f | csort | while IFS= read -r f; do
  printf '%s\t%s bytes\t%s\n' "$(head -c 7 "$f" | tr -c 'A-Za-z' '?')" "$(stat -c %s "$f")" "${f#"$MD"/}"
done

# expected h23: src.tsv in save order (UIDs from 1 per mailbox) with the flags set above
awk -F'\t' -v OFS='\t' '$6=="A"{u[$2]++; f="-"; if($1=="p02"||$1=="p05")f="\\Seen"; if($1=="p06")f="$label1"; print $2,u[$2],$4,$5,f}' "$SRC" | csort > "$W/out/h23-expected.tsv"
csort "$W/out/h23.tsv" > "$W/out/h23.sorted"
same "$W/out/h23-expected.tsv" "$W/out/h23.sorted" "A: 2.3 reads every message byte-identically to src.tsv (sha256, size, UID order, flags)"

# ------------------------------------------------------------------ phase B
step "phase B: Dovecot 2.4.5 opens the 2.3 mailbox, indexes carried over"
start 24 main mail_crypt B || exit 1
hash_all "$W/out/h24b.tsv"
record B
time_big
memory
stop
dirs main B
dirdiff A B
same "$W/out/h23.tsv" "$W/out/h24b.tsv" "B: check 3: 2.4 hashes = 2.3 hashes (mailbox, UID, sha256, size, flags without \\Recent)"
same "$W/out/status-A.txt" "$W/out/status-B.txt" "B: mailbox status equal (messages, uidvalidity, uidnext, guid)"
same "$W/out/list-A.txt" "$W/out/list-B.txt" "B: check 6: 2.4 lists the same folder names as 2.3"
if [ "$(cat "$W/out/metadata-B.txt")" = proto4 ] || grep -qx 'value: proto4\|proto4' "$W/out/metadata-B.txt"; then ok "B: METADATA reads proto4"; else fail "B: METADATA: $(cat "$W/out/metadata-B.txt")"; fi
printf '%s\n' '< ./.x.\7ey' '> ./.x.~y' > "$W/out/dirdiff-B-expected.txt"
{ diff "$W/out/dirs-A-maildir.txt" "$W/out/dirs-B-maildir.txt" || true; } | grep '^[<>]' > "$W/out/dirdiff-B.txt"
same "$W/out/dirdiff-B-expected.txt" "$W/out/dirdiff-B.txt" "B: maildir directory diff A->B is exactly .x.\\7ey -> .x.~y (B2)"

# ------------------------------------------------------------------ phase C
step "phase C: Dovecot 2.4.5 writes, then fresh containers read"
find "$MD/cur" "$MD/new" "$MD/.Archiv.2025/cur" "$MD/.Archiv.2025/new" -type f | csort > "$W/out/files-before-C.txt"
start 24 main mail_crypt C-write || exit 1
da save -u "$U" -m INBOX < "$W/msgs/p20.eml" || fail "C: save p20"
da save -u "$U" -m "Archiv/2025" < "$W/msgs/p21.eml" || fail "C: save p21"
da flags add -u "$U" '\Flagged' mailbox INBOX header Message-ID '<p03@example.test>' || fail "C: flags p03"
da expunge -u "$U" mailbox INBOX header Message-ID '<p08@example.test>' || fail "C: expunge p08"
memory
stop
find "$MD/cur" "$MD/new" "$MD/.Archiv.2025/cur" "$MD/.Archiv.2025/new" -type f | csort > "$W/out/files-after-C.txt"
# compare by maildir base name: a flag change renames the file (":2,F")
newfiles=$(comm -13 <(sed 's/:2,.*$//; s,/\(cur\|new\)/,/,' "$W/out/files-before-C.txt" | csort) \
                     <(sed 's/:2,.*$//; s,/\(cur\|new\)/,/,' "$W/out/files-after-C.txt" | csort))
nnew=0 ncr=0
while IFS= read -r b; do
  [ -n "$b" ] || continue
  f=$(grep -F "${b##*/}" "$W/out/files-after-C.txt")
  nnew=$((nnew + 1)); [ "$(head -c 7 "$f")" = CRYPTED ] && ncr=$((ncr + 1))
  echo "new file: ${f#"$MD"/} starts with $(head -c 7 "$f" | tr -c 'A-Za-z' '?')"
done <<< "$newfiles"
if [ "$nnew" = 2 ] && [ "$ncr" = 2 ]; then ok "C: p20 and p21 are stored encrypted (CRYPTED)"; else fail "C: $nnew new files, $ncr CRYPTED"; fi

start 24 main mail_crypt C-read1 || exit 1
hash_all "$W/out/h24c.tsv"
record C
memory
stop
start 24 main mail_crypt C-read2 || exit 1
hash_all "$W/out/h24c2.tsv"
stop
dirs main C
dirdiff B C
uidlists main C
same "$W/out/h24c.tsv" "$W/out/h24c2.tsv" "C: a second fresh 2.4 container gives the same hashes"
# expected: h24b minus p08 (INBOX UID 8), p03 (INBOX UID 3) + \Flagged, plus p20/p21 with the next UIDs
awk -F'\t' -v OFS='\t' -v s20="$(awk -F'\t' '$1=="p20"{print $4"\t"$5}' "$SRC")" -v s21="$(awk -F'\t' '$1=="p21"{print $4"\t"$5}' "$SRC")" '
  { if ($2+0 > max[$1]) max[$1] = $2+0 }
  $1=="INBOX" && $2==8 { next }
  $1=="INBOX" && $2==3 { $5 = ($5=="-") ? "\\Flagged" : "\\Flagged " $5 }
  { print }
  END { print "INBOX", max["INBOX"]+1, s20, "-"; print "Archiv/2025", max["Archiv/2025"]+1, s21, "-" }' "$W/out/h24b.tsv" | csort > "$W/out/h24c-expected.tsv"
csort "$W/out/h24c.tsv" > "$W/out/h24c.sorted"
same "$W/out/h24c-expected.tsv" "$W/out/h24c.sorted" "C: check 4: hashes = B minus p08, plus p20/p21 (src.tsv hashes), p03 \\Flagged"
# the dovecot-uidlist header N is only rewritten now and then (A: "N1" in a
# folder that holds UID 1), so UIDNEXT comes from mailbox status
for box in INBOX Archiv/2025; do
  a=$(grep "^$box " "$W/out/status-A.txt") c=$(grep "^$box " "$W/out/status-C.txt")
  va=$(grep -o 'uidvalidity=[0-9]*' <<< "$a") vc=$(grep -o 'uidvalidity=[0-9]*' <<< "$c")
  na=$(grep -o 'uidnext=[0-9]*' <<< "$a" | cut -d= -f2) nc=$(grep -o 'uidnext=[0-9]*' <<< "$c" | cut -d= -f2)
  if [ -n "$va" ] && [ "$va" = "$vc" ] && [ "$nc" = $((na + 1)) ]; then ok "C: $box: $va kept, uidnext $na -> $nc"; else fail "C: $box: A '$a', C '$c'"; fi
done
v1=$(awk -F'\t' '$1=="."{print $2}' "$W/out/uidlist-A.txt" | grep -o 'V[0-9]*') v2=$(awk -F'\t' '$1=="."{print $2}' "$W/out/uidlist-C.txt" | grep -o 'V[0-9]*')
[ -n "$v1" ] && [ "$v1" = "$v2" ] && ok "C: INBOX dovecot-uidlist keeps $v1" || fail "C: INBOX dovecot-uidlist $v1 -> $v2"

# ------------------------------------------------------------------ phase D
step "phase D: indexes dropped (copy of the post-C state without vmail_index/)"
copy_noindex main d
dirs d D-before
start 24 d mail_crypt D || exit 1
hash_all "$W/out/h24d.tsv"
record D
memory
stop
dirs d D
dirdiff D-before D
same "$W/out/h24c.tsv" "$W/out/h24d.tsv" "D: hashes, UIDs, flags and keywords equal phase C without the index"
sed -E 's/ guid=[^ ]*//' "$W/out/status-C.txt" > "$W/out/status-C.noguid"
sed -E 's/ guid=[^ ]*//' "$W/out/status-D.txt" > "$W/out/status-D.noguid"
same "$W/out/status-C.noguid" "$W/out/status-D.noguid" "D: messages, uidvalidity and uidnext equal phase C"
if diff "$W/out/status-C.txt" "$W/out/status-D.txt" > /dev/null; then echo "recorded: mailbox GUIDs equal phase C after the index rebuild"
else echo "recorded: mailbox GUIDs differ from phase C after the index rebuild:"; diff "$W/out/status-C.txt" "$W/out/status-D.txt"; fi
same "$W/out/metadata-C.txt" "$W/out/metadata-D.txt" "D: METADATA unchanged"

# ------------------------------------------------------------------ phase E
step "phase E1: rollback, 2.3 reads the post-C state as 2.4 left it"
mkdir -p "$W/e1"; cp -a "$W/main/vmail" "$W/main/vmail_index" "$W/main/volatile" "$W/e1/"
dirs e1 E1-before
start 23 e1 mail_crypt E1 || exit 1
hash_all "$W/out/h23e1.tsv" "x/~y"
da mailbox list -u "$U" | csort > "$W/out/list-E1.txt"
echo "--- mailbox list (E1)"; cat "$W/out/list-E1.txt"
stop
dirs e1 E1
dirdiff E1-before E1
grep -v -P '^x/~y\t' "$W/out/h24c.tsv" > "$W/out/h24c-without-xy.tsv"
same "$W/out/h24c-without-xy.tsv" "$W/out/h23e1.tsv" "E1: 2.3 reads everything except x/~y byte-identically to phase C"
if grep -aq "^a NO Mailbox doesn't exist: x/~y" "$W/imap/E1-box4.txt"; then finding "E1: 2.3 SELECT \"x/~y\" -> $(grep -a '^a ' "$W/imap/E1-box4.txt")"
else fail "E1: no 'NO Mailbox doesn't exist: x/~y'"; fi

step "phase E2: rollback after rollback-rename.sh"
mkdir -p "$W/e2"; cp -a "$W/main/vmail" "$W/main/vmail_index" "$W/main/volatile" "$W/e2/"
echo "+ rollback-rename.sh work/e2/vmail/example.test/alice/Maildir"
"$HERE/rollback-rename.sh" "$W/e2/vmail/example.test/alice/Maildir" | tee "$W/out/rollback-rename.txt"
printf '%s\n' '.x.~y -> .x.\7ey' > "$W/out/rollback-rename-expected.txt"
same "$W/out/rollback-rename-expected.txt" "$W/out/rollback-rename.txt" "E2: rollback-rename.sh renamed exactly .x.~y -> .x.\\7ey"
dirs e2 E2-before
start 23 e2 mail_crypt E2 || exit 1
hash_all "$W/out/h23e2.tsv"
stop
dirs e2 E2
dirdiff E2-before E2
same "$W/out/h24c.tsv" "$W/out/h23e2.tsv" "E2: 2.3 reads every mailbox byte-identically to phase C"

# ------------------------------------------------------- counter-proofs
# cp_each OUT: one session per message of h24c.tsv; columns of `single` plus id and variant.
cp_each() {
  local out=$1 box uid sha size fl id variant i=0
  : > "$out"
  while IFS=$'\t' read -r box uid sha size fl; do
    i=$((i + 1))
    id=$(awk -F'\t' -v s="$sha" '$4==s{print $1}' "$SRC")
    variant=$(awk -F'\t' -v s="$sha" '$4==s{print $3}' "$SRC")
    "${PY[@]}" "$IH" cmd "$box" "$uid" < /dev/null | da exec imap -u "$U" > "$W/imap/$PHASE-$id.txt" 2> "$W/imap/$PHASE-$id.err"
    printf '%s\t%s\t%s\n' "$id" "$variant" "$("${PY[@]}" "$IH" single "$box" "$uid" "$sha" < "$W/imap/$PHASE-$id.txt")" >> "$out"
  done < "$W/out/h24c.tsv"
  echo "--- $(basename "$out") (id variant mailbox uid result sha256 first4 announced received reason)"
  cat "$out"
}

step "CP1: 2.4 without mail_compress (copy without vmail_index/, one UID FETCH per session)"
copy_noindex main cp1
start 24 cp1 mail_crypt CP1 cp-no-compress.conf || exit 1
cp_each "$W/out/cp1.tsv"
stop 'Error: '
while IFS=$'\t' read -r id variant box uid result sha first ann rec reason; do
  case $variant in
    plain|crypt) [ "$result" = same ] && ok "CP1: $id ($variant) unchanged" || fail "CP1: $id ($variant) $result" ;;
    *)
      case $variant in crypt+gz) magic=1f8b ;; crypt+zstd) magic=28b52ffd ;; crypt+lz4) magic=446f7665 ;; esac
      if [ "$result" = differs ]; then
        ok "CP1: $id ($variant) differs: first bytes $first (expected magic $magic), literal $ann announced, $rec received"
      else
        fail "CP1: $id ($variant) read identically without mail_compress"
      fi ;;
  esac
done < "$W/out/cp1.tsv"

step "CP2: 2.4 with the other key pair (copy without vmail_index/, one UID FETCH per session)"
copy_noindex main cp2
start 24 cp2 mail_crypt-other CP2 || exit 1
cp_each "$W/out/cp2.tsv"
stop 'no private key available'
while IFS=$'\t' read -r id variant box uid result sha first ann rec reason; do
  if [ "$variant" = plain ]; then
    [ "$result" = same ] && ok "CP2: $id (plain) still readable" || fail "CP2: $id (plain) $result"
  else
    e=$(grep -m1 -E 'Error:' "$W/imap/CP2-$id.err" | sed -E 's/^.*Error: //')
    [ "$result" = differs ] && ok "CP2: $id ($variant) fails: $reason; log: $e" || fail "CP2: $id ($variant) read with the wrong key"
  fi
done < "$W/out/cp2.tsv"

step "CP3: 2.4 with mailbox_list_visible_escape_char = \"\\\\\" (counter-proof of check 6)"
copy_noindex main cp3
start 24 cp3 mail_crypt CP3 cp-visible-escape.conf || exit 1
da mailbox list -u "$U" | csort > "$W/out/list-CP3.txt"
echo "--- mailbox list (CP3)"; cat "$W/out/list-CP3.txt"
stop
if grep -qxF 'back\5cslash' "$W/out/list-CP3.txt" && ! grep -qxF 'back\slash' "$W/out/list-CP3.txt"; then
  ok "CP3: with the visible escape char 2.4 lists back\\5cslash, so check 6 detects it"
else
  fail "CP3: list did not change"
fi
if diff -q "$W/out/list-B.txt" "$W/out/list-CP3.txt" > /dev/null; then fail "CP3: folder list equal to phase B"; else ok "CP3: folder list differs from phase B"; fi

# ------------------------------------------------------------------ check 9
step "check 9: hygiene"
if docker ps -a --filter name=keepia-proto4 -q | grep -q .; then fail "containers left: $(docker ps -a --filter name=keepia-proto4)"; else ok "no keepia-proto4 container left"; fi
docker volume ls -q | csort > "$W/out/volumes-after.txt"
newvols=$(comm -13 "$W/out/volumes-before.txt" "$W/out/volumes-after.txt")
if [ -z "$newvols" ]; then ok "docker volume list unchanged"
elif grep -qE '^[0-9a-f]{64}$' <<< "$newvols"; then fail "new anonymous docker volume(s): $newvols"
else echo "recorded: named volumes created during the run by something else (not keepia-proto4): $(tr '\n' ' ' <<< "$newvols")"; fi
pem=$(git -C "$HERE" ls-files . | grep -c '\.pem$' || true)
[ "$pem" = 0 ] && ok "git ls-files: 0 .pem files" || fail "git ls-files: $pem .pem files"
st=$(git -C "$HERE" status --porcelain --untracked-files=all -- . | grep -E 'work/|\.pem' || true)
[ -z "$st" ] && ok "git status shows nothing from work/ and no .pem" || fail "git status: $st"
echo "work/ size: $(du -sh "$W" | cut -f1)"

echo
echo "--- memory"; cat "$W/out/memory.txt"
echo "--- timing"; cat "$W/out/timing.txt"
if [ "$FAILS" = 0 ]; then echo "PASS"; exit 0; else echo "FAIL ($FAILS)"; exit 1; fi
