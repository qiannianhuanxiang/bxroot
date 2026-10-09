#!/bin/sh
# V3: execute static and actual freestanding native PIE helpers, capture loader exec.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC=${NATIVE_CC:-gcc}
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-enter-XXXXXX")
W=$(CDPATH= cd -- "$W" && pwd -P)
case "$W" in /*/bxroot-enter-??????) ;; *) echo 'invalid fixture path' >&2; exit 2 ;; esac
cleanup() { case "$W" in /*/bxroot-enter-??????) rm -rf -- "${W:?}" ;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ENTRY=""
ARCH=$(uname -m)
case "$ARCH" in aarch64|arm64) ENTRY="-Wl,-e,bx_early_start" ;; esac
"$CC" -std=c11 -O1 -Wall -Wextra -Wformat=2 -D_GNU_SOURCE= -I"$ROOT/src/host" \
    ${ENTER_TEST_CFLAGS:-} -static -Wl,-z,max-page-size=16384 $ENTRY \
    "$ROOT/src/host/bx-enter.c" "$ROOT/src/host/session.c" -o "$W/bx-enter-static"
"$CC" -std=c11 -O1 -Wall -Wextra -Wformat=2 -D_GNU_SOURCE= -I"$ROOT/src/host" \
    -static -Wl,-z,max-page-size=16384 $ENTRY -DTRAMP_ONLY \
    "$ROOT/test/host/test_enter.c" -o "$W/fake-tramp"
"$CC" -std=c11 -O1 -Wall -Wextra -Wformat=2 -D_GNU_SOURCE= -I"$ROOT/src/host" \
    ${ENTER_TEST_CFLAGS:-} "$ROOT/test/host/test_enter.c" "$ROOT/src/host/session.c" -o "$W/probe"
# Keep the contaminated LD_PRELOAD real so the Linux interpreter remains quiet.
# The probe still asserts helper replaces it with the session's guest preload.
"$CC" -shared -fPIC -nostdlib -x c -o "$W/host-preload.so" - <<'PRELOAD'
void bx_host_preload_fixture(void) {}
PRELOAD
mkdir "$W/static" "$W/native"
echo 'RUN: static helper actual exec integration'
"$W/probe" "$W/static" "$W/bx-enter-static" "$W/fake-tramp"
case "$ARCH" in
    aarch64|arm64)
        "$CC" -std=c11 -O2 -Wall -Wextra -Wformat=2 -D_GNU_SOURCE= \
            -DBX_ENTER_NATIVE -ffreestanding -fno-builtin -fno-stack-protector \
            -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -I"$ROOT/src/host" \
            -nostdlib -pie -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
            -Wl,-e,bx_native_start -Wl,-z,max-page-size=16384 -Wl,--no-undefined \
            "$ROOT/src/host/bx-enter.c" "$ROOT/src/host/session.c" \
            "$ROOT/src/host/enter-libc.c" -o "$W/bx-enter-native"
        echo 'RUN: native PIE helper actual exec integration (Linux interpreter)'
        "$W/probe" "$W/native" "$W/bx-enter-native" "$W/fake-tramp"
        ;;
    *) echo 'SKIP: actual AArch64 native PIE needs AArch64 executor' ;;
esac
