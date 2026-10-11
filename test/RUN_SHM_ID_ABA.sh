#!/bin/sh
# Deterministic ID ABA regression: allocator source is unchanged except randomness.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(uname -m)" = aarch64 ] || { echo 'SKIP: allocator source requires AArch64'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-id-build-XXXXXX") || exit 1
cleanup() { case "$W" in /*/bxroot-id-build-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$ROOT/src/runtime/sysvshm.c" "$W/sysvshm-id-test.c" <<'PY'
import pathlib,sys
source=pathlib.Path(sys.argv[1]).read_text()
old='SVC(NR_GETRANDOM, &r, sizeof r, 0)'
if source.count(old)!=1:
    raise SystemExit('FAIL: allocator randomness injection must match exactly once')
pathlib.Path(sys.argv[2]).write_text(source.replace(old,'fixed_random(&r, sizeof r)'))
PY
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -DBXROOT_SHM_CLAIM_VERIFIED=1 \
    -I"$W" -I"$ROOT/src/runtime" -o "$W/probe" "$ROOT/test/shm/probe_shm_id_aba.c"
rc=0
timeout --kill-after=5 30 "$W/probe" >"$W/output" 2>&1 || rc=$?
cat "$W/output"
[ "$rc" -eq 0 ] || { echo "FAIL: ID ABA probe rc=$rc"; exit 1; }
[ "$(grep -cFx SHM_ID_ABA_PASS "$W/output")" = 1 ] || exit 1
