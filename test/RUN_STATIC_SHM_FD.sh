#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(uname -m)" = aarch64 ] || { echo 'SKIP: AArch64 required'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-static-shm-fd-XXXXXX") || exit 1
cleanup() { case "$W" in /*/bxroot-static-shm-fd-*) [ -d "$W" ] && rm -rf -- "$W";; esac; }
trap cleanup EXIT INT TERM
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -o "$W/probe" \
    "$ROOT/test/shm/probe_static_shm_fd.c" -ldl
out=$(timeout --kill-after=5 30 "$W/probe" 2>&1) || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
[ "$(printf '%s\n' "$out" | grep -cFx STATIC_SHM_FD_PASS)" = 1 ] || exit 1
