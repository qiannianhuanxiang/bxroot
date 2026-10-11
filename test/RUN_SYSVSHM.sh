#!/bin/sh
# 0=PASS, 1=failed probe/build/timeout, 2=missing prerequisite only.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
BX="$ROOT/tools/bxroot-run"
MODE=${1:-runtime}
case "$MODE" in runtime|--compile-only) ;; *) exit 1 ;; esac
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-shm-XXXXXX") || exit 1
OWNED_ID=''
cleanup() {
    if [ -n "$OWNED_ID" ] && [ -x "$W/xproc" ]; then
        timeout 10 "$W/xproc" rm-id "$OWNED_ID" >/dev/null 2>&1 || echo "WARNING: cleanup id=$OWNED_ID failed" >&2
    fi
    case "$W" in /*/bxroot-shm-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for p in spec xproc race rebuild; do
    "${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -pthread \
        -o "$W/$p" "$ROOT/test/shm/probe_shm_$p.c" || exit 1
done
if [ "$MODE" = --compile-only ]; then echo 'RESULT: compile PASS'; exit 0; fi
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo 'SKIP: no official proroot comparison session'; exit 2;
}
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo 'SKIP: missing runtime'; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo 'SKIP: missing python3'; exit 2; }
# Collision resistance, not a claim of kernel namespace isolation. Initial
# keyed creations use IPC_EXCL and fail on collision; never remove unknown IDs.
KEYS=$(python3 - <<'PY'
import secrets
values=set()
while len(values)<6: values.add(secrets.randbelow(2**30-1)+1)
v=list(values)
print(*v[:5], -v[5])
PY
) || exit 1
set -- $KEYS
SPEC_KEY=$1; MISSING_KEY=$2; XKEY=$3; RACE_KEY=$4; REBUILD_KEY=$5; NEG_KEY=$6
fail() { echo "FAIL: $*" >&2; exit 1; }
run() {
    logfile=$1; seconds=$2; shift 2
    rc=0
    timeout --kill-after=5 "$seconds" "$@" >"$logfile" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then cat "$logfile"; fail "probe rc=$rc"; fi
}
marker() { [ "$(grep -cFx "$2" "$1")" = 1 ] || fail "missing/duplicate $2"; }
norm() {
    python3 - "$1" <<'PY'
import re,sys
for line in open(sys.argv[1]):
    line=re.sub(r'\bid=\d+', 'id=ID', line)
    if line.startswith('shmget('): line=re.sub(r'= \d+ errno=', '= ID errno=', line)
    if line.startswith(' segsz='): line=re.sub(r'nattch=\d+', 'nattch=N', line)
    print(line,end='')
PY
}
echo '--- A) semantic comparison ---'
run "$W/off.txt" 60 "$W/spec" "$SPEC_KEY" "$MISSING_KEY" "$NEG_KEY"
run "$W/bx.txt" 120 "$BX" -- "$W/spec" "$SPEC_KEY" "$MISSING_KEY" "$NEG_KEY"
marker "$W/off.txt" SPEC_DONE; marker "$W/bx.txt" SPEC_DONE
# Only the known local nattch difference is normalized, after assertions.
grep -q '^ segsz=5000 nattch=0 mode=600 ' "$W/off.txt" || fail 'official IPC_STAT fields'
grep -q '^ segsz=5000 nattch=2 mode=600 ' "$W/bx.txt" || fail 'bxroot IPC_STAT fields'
norm "$W/off.txt" >"$W/off.norm"; norm "$W/bx.txt" >"$W/bx.norm"
if ! cmp -s "$W/off.norm" "$W/bx.norm"; then diff -u "$W/off.norm" "$W/bx.norm"; fail 'semantic difference'; fi
echo '--- B) bidirectional publication ---'
run "$W/put" 30 "$W/xproc" put "$XKEY" from-off
OWNED_ID=$(sed -n "s/^put id=\([0-9][0-9]*\) 'from-off'$/\1/p" "$W/put")
[ -n "$OWNED_ID" ] || fail 'official put marker'
run "$W/get" 30 "$BX" -- "$W/xproc" get "$XKEY"
grep -qx "get id=$OWNED_ID 'from-off'" "$W/get" || fail 'official -> bxroot payload'
run "$W/rm" 30 "$W/xproc" rm-id "$OWNED_ID"; OWNED_ID=''
run "$W/absent" 30 "$W/xproc" expect-absent "$XKEY"; marker "$W/absent" ABSENT
run "$W/put" 30 "$BX" -- "$W/xproc" put "$XKEY" from-bx
OWNED_ID=$(sed -n "s/^put id=\([0-9][0-9]*\) 'from-bx'$/\1/p" "$W/put")
[ -n "$OWNED_ID" ] || fail 'bxroot put marker'
run "$W/get" 30 "$W/xproc" get "$XKEY"
grep -qx "get id=$OWNED_ID 'from-bx'" "$W/get" || fail 'bxroot -> official payload'
run "$W/rm" 30 "$BX" -- "$W/xproc" rm-id "$OWNED_ID"; OWNED_ID=''
run "$W/absent" 30 "$W/xproc" expect-absent "$XKEY"; marker "$W/absent" ABSENT
echo '--- C) initial publication and attach concurrency ---'
run "$W/race.txt" 120 "$BX" -- "$W/race" "$RACE_KEY"
marker "$W/race.txt" RACE_DONE
grep -qx 'counter=1600 (expect 1600) bad=0' "$W/race.txt" || fail 'counter'
grep -qx 'nattch after threads=1 (expect 1)' "$W/race.txt" || fail 'attach count'
[ "$(grep -c '^[0-9][0-9]*$' "$W/race.txt")" = 16 ] || fail 'child count'
[ "$(grep '^[0-9][0-9]*$' "$W/race.txt" | sort -u | wc -l)" -eq 1 ] || fail 'multiple IDs'
echo '--- D) RMID mapping retention and concurrent rebuild ---'
run "$W/rebuild.txt" 120 "$BX" -- "$W/rebuild" "$REBUILD_KEY"
marker "$W/rebuild.txt" 'RMID_REBUILD_DONE rounds=100'
echo 'RESULT: PASS'
