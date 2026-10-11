#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(uname -m)" = aarch64 ] || { echo 'SKIP: claim source probe requires AArch64'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-claim-XXXXXX") || exit 1
cleanup() { case "$W" in /*/bxroot-claim-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
CC=${CC:-gcc}
for mode in 0 1; do
    "$CC" -std=c11 -O1 -Wall -Wextra -Werror -DBXROOT_SHM_CLAIM_VERIFIED="$mode" \
        -o "$W/probe-$mode" "$ROOT/test/shm/probe_shm_claim.c" || exit 1
    rc=0
    timeout --kill-after=5 30 "$W/probe-$mode" >"$W/result-$mode" 2>&1 || rc=$?
    cat "$W/result-$mode"
    [ "$rc" -eq 0 ] || { echo "FAIL: claim mode=$mode rc=$rc"; exit 1; }
    if [ "$mode" = 0 ]; then marker=SHM_CLAIM_GATE_CLOSED_PASS; else marker=SHM_CLAIM_PASS; fi
    [ "$(grep -cFx "$marker" "$W/result-$mode")" = 1 ] || exit 1
done
echo 'RESULT: SHM claim PASS'
