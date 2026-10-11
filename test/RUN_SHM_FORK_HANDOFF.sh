#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-fork-handoff-XXXXXX") || exit 1
cleanup(){ case "$W" in /*/bxroot-fork-handoff-*) [ -d "$W" ] && rm -rf -- "$W";; esac; }
trap cleanup EXIT INT TERM
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -pthread \
  -o "$W/probe" "$ROOT/test/shm/probe_fork_handoff.c" || exit 1
timeout --kill-after=5 30 "$W/probe"
