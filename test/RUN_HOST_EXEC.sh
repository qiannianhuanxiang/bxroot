#!/bin/sh
# ---------------------------------------------------------------------
# bx-host 第一版产物契约：必须是可由 guest static-exec 装载的、无 PT_INTERP
# 的 AArch64 静态 ELF，并且 LOAD 对齐保持 Android 16K 页约束。
# 真机行为由 Termux harness 验证；本脚本钉住构建产物形状，避免误把
# glibc 动态程序装进 native host world。
# ---------------------------------------------------------------------
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BX_HOST_BIN:-$ROOT/build/bx-host}
[ -x "$BIN" ] || { echo "⏭️  跳过：没有 $BIN"; exit 0; }
python3 - "$BIN" <<'PY'
import struct, sys
p = sys.argv[1]
d = open(p, 'rb').read()
assert d[:4] == b'\x7fELF', 'not ELF'
assert d[4] == 2 and d[5] == 1, 'not ELF64 little-endian'
assert struct.unpack_from('<H', d, 18)[0] == 183, 'not AArch64'
assert struct.unpack_from('<H', d, 16)[0] == 2, 'bx-host must be ET_EXEC'
phoff = struct.unpack_from('<Q', d, 32)[0]
phentsize, phnum = struct.unpack_from('<HH', d, 54)
seen_load = False
for i in range(phnum):
    off = phoff + i * phentsize
    typ, flags, poff, vaddr, paddr, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', d, off)
    if typ == 3:
        raise AssertionError('bx-host unexpectedly has PT_INTERP')
    if typ == 1:
        seen_load = True
        assert align >= 16384, 'LOAD is not 16K aligned'
assert seen_load, 'no LOAD segment'
print('RESULT: PASS bx-host static AArch64 16K ELF')
PY
