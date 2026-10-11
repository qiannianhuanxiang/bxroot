#!/bin/sh
# Optional real bridge/linker chain test, not a dlsym-only hook test.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MODE=${1:-runtime}
case "$MODE" in runtime|--compile-only) ;; *) exit 1 ;; esac
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-native-wait-XXXXXX") || exit 1
cleanup() {
    case "$W" in /*/bxroot-native-wait-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -DPX_PURE_LOGIC=0 \
    -I"$ROOT/src/proc" -o "$W/probe" "$ROOT/test/host/probe_native_fork_wait.c" || exit 1
if [ "$MODE" = --compile-only ]; then echo 'RESULT: native fork/wait compile PASS'; exit 0; fi
BRIDGE=${BXROOT_CHAIN_BRIDGE:-}
LINKER=${BXROOT_CHAIN_LINKER:-}
LIB=${BXROOT_CHAIN_RUNTIME:-$ROOT/build/libbxroot-runtime.so}
if [ -z "$BRIDGE" ] || [ -z "$LINKER" ] || [ ! -x "$BRIDGE" ] || [ ! -r "$LINKER" ] || [ ! -r "$LIB" ]; then
    echo 'SKIP: explicit executable bridge, readable linker and runtime required'; exit 2
fi
CHAIN_ROOT=${BXROOT_CHAIN_ROOTFS:-/}
rc=0
BXROOT_ROOTFS="$CHAIN_ROOT" PROROOT_ROOTFS="$CHAIN_ROOT" \
    timeout --kill-after=5 45 "$BRIDGE" "$LINKER" --argv0 native-fork-wait \
    --preload "$LIB" "$W/probe" >"$W/output" 2>&1 || rc=$?
cat "$W/output"
[ "$rc" -eq 0 ] || { echo "FAIL: native chain rc=$rc"; exit 1; }
[ "$(grep -cFx NATIVE_CHAIN_FORK_WAIT_PASS "$W/output")" = 1 ] || { echo 'FAIL: missing/duplicate marker'; exit 1; }
