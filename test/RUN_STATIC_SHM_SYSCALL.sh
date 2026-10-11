#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(uname -m)" = aarch64 ] || { echo 'SKIP: AArch64 required'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-static-shm-syscall-XXXXXX") || exit 1
cleanup(){ case "$W" in /*/bxroot-static-shm-syscall-*) [ -d "$W" ]&&rm -rf -- "$W";;esac;};trap cleanup EXIT INT TERM
unavailable=0
for mode in 0 1; do
 for claim in 0 1; do
  "${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -DBXROOT_SHM_COPYOUT_VERIFIED="$mode" -DBXROOT_SHM_CLAIM_VERIFIED="$claim" -o "$W/p-$mode-$claim" "$ROOT/test/shm/probe_static_shm_syscall.c" || exit 1
  rc=0; timeout --kill-after=5 30 "$W/p-$mode-$claim" >"$W/o-$mode-$claim" 2>&1 || rc=$?; cat "$W/o-$mode-$claim"
  if grep -q '^TRAP_UNREACHED' "$W/o-$mode-$claim"; then [ "$rc" -eq 2 ] || exit 1; unavailable=$((unavailable+1)); continue; fi
  [ "$rc" -eq 0 ] || exit 1; grep -qx STATIC_SHM_SYSCALL_PASS "$W/o-$mode-$claim" || exit 1
 done
done
[ "$unavailable" -eq 0 ] || { echo "SKIP: $unavailable configurations cannot reach SHM TRAP"; exit 2; }
echo 'RESULT: static SHM syscall PASS'
