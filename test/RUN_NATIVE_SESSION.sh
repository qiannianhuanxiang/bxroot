#!/bin/sh
# V3 actual native-session/session backend regression; no device/network.
# Every case runs via a fresh exec to avoid static backend state contamination.
# Only temporary fixture products are created and removed, never shared build/.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC=${NATIVE_CC:-gcc}
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-native-session-XXXXXX")
W=$(CDPATH= cd -- "$W" && pwd -P)
case "$W" in /*/bxroot-native-session-??????) ;; *) echo 'invalid fixture path' >&2; exit 2 ;; esac
cleanup() {
    # W is resolved and checked above, never remove an unchecked computed path.
    case "$W" in /*/bxroot-native-session-??????) rm -rf -- "${W:?}" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
attempt=1
while :; do
    if "$CC" -std=c11 -O1 -Wall -Wextra -Wformat=2 -Werror \
        ${NATIVE_SESSION_TEST_CFLAGS:-} -D_GNU_SOURCE= -I"$ROOT/src/host" \
        "$ROOT/test/host/test_native_session.c" "$ROOT/src/host/native-session.c" \
        "$ROOT/src/host/session.c" -ldl -o "$W/probe" 2>"$W/cc.err"; then
        break
    fi
    if [ "$attempt" -ge 8 ] || ! grep -q 'internal compiler error' "$W/cc.err"; then
        echo 'FAIL: native-session backend compilation' >&2
        sed -n '1,120p' "$W/cc.err" >&2
        exit 1
    fi
    echo "native-session gcc ICE attempt=$attempt; retry" >&2
    attempt=$((attempt + 1))
done
if [ -s "$W/cc.err" ]; then sed -n '1,120p' "$W/cc.err" >&2; fi
"$W/probe" "$W"
