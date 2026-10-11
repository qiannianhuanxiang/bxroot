#!/bin/sh
# Source-level AArch64 lifecycle test; no SysV kernel IPC required.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(uname -m)" != aarch64 ]; then
    echo 'SKIP: anchor source probe requires AArch64'
    exit 2
fi
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-anchor-build-XXXXXX")
cleanup() {
    case "$W" in /*/bxroot-anchor-build-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -o "$W/probe" "$ROOT/test/shm/probe_dirfd_anchor.c"
timeout 30 "$W/probe"
