#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NODE=$(command -v node || true)
LIB="${BXROOT_SO:-$ROOT/build/libbxroot-runtime.so}"
if [ -z "$NODE" ] || [ ! -f "$LIB" ]; then echo 'SKIP: node/runtime prerequisite unavailable'; exit 2; fi
timeout --kill-after=3 90 env BXROOT_ROOTFS=/ LD_PRELOAD="$LIB" "$NODE" "$ROOT/test/ptc-fork-exec.mjs"
