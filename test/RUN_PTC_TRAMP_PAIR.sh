#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC=${NATIVE_CC:-gcc}
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-ptc-pair-XXXXXX")
W=$(CDPATH= cd -- "$W" && pwd -P)
case "$W" in /*/bxroot-ptc-pair-??????) ;; *) echo 'invalid fixture path' >&2; exit 2 ;; esac
cleanup() { case "$W" in /*/bxroot-ptc-pair-??????) rm -rf -- "$W" ;; esac; }
trap cleanup EXIT INT TERM

"$CC" -std=c11 -O1 -Wall -Wextra -Werror \
    -I"$ROOT/src/proc" "$ROOT/test/test_tramp_pair.c" -o "$W/probe"
"$W/probe"
