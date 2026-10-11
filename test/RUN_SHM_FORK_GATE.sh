#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-shm-fork-gate-XXXXXX") || exit 1
cleanup(){ case "$W" in /*/bxroot-shm-fork-gate-*) [ -d "$W" ] && rm -rf -- "$W";; esac; }
trap cleanup EXIT INT TERM
python3 - "$ROOT/src/runtime/sysvshm.c" "$W/sysvshm_gate_impl.c" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text()
a='                    K_MAP_SHARED, fd, 0);\n'
b=a+'    test_shm_window(1);\n'
if s.count(a)!=1: raise SystemExit('mmap injection anchor mismatch')
s=s.replace(a,b)
a='    r = SVC(NR_MUNMAP, addr, len, 0);\n'
b='    test_shm_window(2);\n'+a
if s.count(a)!=1: raise SystemExit('munmap injection anchor mismatch')
s=s.replace(a,b)
pathlib.Path(sys.argv[2]).write_text(s)
PY
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror -pthread \
  -I"$ROOT/src/runtime" -I"$W" -o "$W/probe" "$ROOT/test/shm/probe_shm_fork_gate.c" || exit 1
timeout --kill-after=5 45 "$W/probe"
