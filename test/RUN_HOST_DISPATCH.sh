#!/bin/sh
# Runtime integration: real proc dispatch + real ELF IO, captured process exits.
# No Android bridge, device shell, credentials, or source-pattern assertions.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo 'SKIP: proc hook integration requires native AArch64'; exit 0 ;;
esac
CC=${NATIVE_CC:-gcc}
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-host-dispatch-XXXXXX")
W=$(CDPATH= cd -- "$W" && pwd -P)
case "$W" in /*/bxroot-host-dispatch-??????) ;; *) echo 'invalid temporary path' >&2; exit 2 ;; esac
cleanup() {
    # W was resolved and verified above; never remove an unchecked path.
    case "$W" in /*/bxroot-host-dispatch-??????) rm -rf -- "${W:?}" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
attempt=1
while :; do
    if "$CC" -O1 -Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter \
        -D_GNU_SOURCE= -DPX_PURE_LOGIC=0 \
        -o "$W/probe" "$ROOT/test/host/probe_proc_host.c" -ldl -pthread 2>"$W/cc.err"; then
        break
    fi
    if [ "$attempt" -ge 10 ] || ! grep -q 'internal compiler error' "$W/cc.err"; then
        echo 'FAIL: proc host integration compilation' >&2
        sed -n '1,100p' "$W/cc.err" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
done
if [ -s "$W/cc.err" ]; then
    sed -n '1,100p' "$W/cc.err" >&2
fi
"$W/probe" "$W"
