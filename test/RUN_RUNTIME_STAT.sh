#!/bin/sh
# Test actual shm_do_ctl for both compile-time copyout modes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(uname -m)" = aarch64 ] || { echo 'SKIP: actual runtime probe requires AArch64'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-stat-build-XXXXXX") || exit 1
cleanup() { case "$W" in /*/bxroot-stat-build-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for mode in 0 1; do
    "${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror \
        -DBXROOT_SHM_COPYOUT_VERIFIED="$mode" -o "$W/probe-$mode" \
        "$ROOT/test/shm/probe_runtime_stat.c" || exit 1
    rc=0
    timeout --kill-after=5 45 "$W/probe-$mode" >"$W/output-$mode" 2>&1 || rc=$?
    cat "$W/output-$mode"
    [ "$rc" -eq 0 ] || { echo "FAIL: runtime IPC_STAT mode=$mode rc=$rc"; exit 1; }
    [ "$(grep -cFx RUNTIME_IPC_STAT_PASS "$W/output-$mode")" = 1 ] || exit 1
done
