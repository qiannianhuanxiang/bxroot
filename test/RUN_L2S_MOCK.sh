#!/bin/sh
# l2s mock-FS closure: no host symlink/lstat or PRoot layout assumptions.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-l2s-mock-XXXXXX") || exit 1
cleanup() { case "$W" in /*/bxroot-l2s-mock-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac; }
trap cleanup EXIT INT TERM
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE= -Isrc/l2s \
    -o "$W/probe" "$ROOT/test/test_l2s_rt.c" "$ROOT/src/l2s/l2s.c" "$ROOT/src/l2s/l2s-runtime.c"
L2S_MOCK_ONLY=1 timeout --kill-after=5 45 "$W/probe" >"$W/output" 2>&1 || { cat "$W/output"; exit 1; }
cat "$W/output"
[ "$(grep -c '^RESULT: PASS$' "$W/output")" = 1 ] || exit 1
[ "$(grep -c '^cases:' "$W/output")" = 1 ] || exit 1
echo 'RESULT: L2S mock closure PASS'
