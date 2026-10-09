#!/bin/sh
# Native entry artifact contract; no device or execution permission changes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${BX_ENTER_BIN:-$ROOT/build/libbxroot-enter.so}
[ -f "$BIN" ] || { echo 'FAIL: missing native entry artifact' >&2; exit 1; }
python3 - "$BIN" <<'PY'
import struct
import sys
from pathlib import Path
b = Path(sys.argv[1]).read_bytes()
assert len(b) >= 64 and b[:7] == b'\x7fELF\x02\x01\x01', 'not ELF64 LE'
assert struct.unpack_from('<HH', b, 16) == (3, 183), 'not AArch64 PIE'
entry, phoff = struct.unpack_from('<QQ', b, 24)
phsize, phnum = struct.unpack_from('<HH', b, 54)
assert phsize == 56 and 0 < phnum <= 128, 'invalid phdr geometry'
assert phoff + phnum * phsize <= len(b), 'truncated phdr table'
interps, loads = [], []
dynamic = None
for i in range(phnum):
    t, flags, off, va, pa, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', b, phoff + i * phsize)
    assert filesz <= memsz and off + filesz <= len(b), 'invalid segment extent'
    if t == 1:
        assert align >= 16384 and off % align == va % align, 'LOAD alignment'
        loads.append((va, memsz, flags))
    elif t == 3:
        interps.append(b[off:off + filesz])
    elif t == 2:
        dynamic = (off, filesz)
    assert t != 7, 'TLS not allowed in entry'
assert loads and any(va <= entry < va + n and flags & 1 for va, n, flags in loads), 'entry not executable'
assert interps == [b'/system/bin/linker64\x00'], 'wrong Android interpreter'
assert dynamic is not None and dynamic[1] % 16 == 0, 'invalid dynamic segment'
off, n = dynamic
terminated = False
for pos in range(off, off + n, 16):
    tag, value = struct.unpack_from('<qQ', b, pos)
    assert tag != 1, 'libc dependency is not allowed'
    if tag == 0:
        terminated = True
        break
assert terminated, 'unterminated dynamic segment'
print('RESULT: PASS bx-enter Android PIE / no NEEDED / no TLS / 16K LOAD')
PY
