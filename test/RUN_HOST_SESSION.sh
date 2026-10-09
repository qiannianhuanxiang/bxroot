#!/bin/sh
# V3: actual session wire/fd/path regression, no device or network.
# Strict by default. BX_SESSION_ALLOW_OUTER_PROC_DUP=1 can SKIP only two
# O_RDONLY/EBADF assertions if an independent inline-svc diagnostic proves
# proc O_RDONLY open duplicates a sealed O_RDWR fd (write still fails EPERM).
# These skips are reported separately and never counted as passing checks.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC=${NATIVE_CC:-gcc}
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-session-XXXXXX")
W=$(CDPATH= cd -- "$W" && pwd -P)
case "$W" in /*/bxroot-session-??????) ;; *) echo 'invalid fixture path' >&2; exit 2 ;; esac
cleanup() { case "$W" in /*/bxroot-session-??????) rm -rf -- "${W:?}" ;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$CC" -std=c11 -O1 -Wall -Wextra -Wformat=2 ${SESSION_TEST_CFLAGS:-} \
    -D_GNU_SOURCE= -I"$ROOT/src/host" \
    "$ROOT/test/host/test_session.c" "$ROOT/src/host/session.c" -o "$W/probe"
"$W/probe" "$W"
