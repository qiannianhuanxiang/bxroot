#!/bin/sh
# ---------------------------------------------------------------------
# seccomp TRAP 号 × 官方对照：找出"官方能用、bxroot 却是 ENOSYS"的调用
#
# 【为什么要有】2026-09-25 实测：Android 白名单 TRAP 掉 ~116 个真实存在
# 的系统调用。sigsys.c 默认一律回 ENOSYS —— 对 io_uring 这类"客户有回退
# 路径"的号是对的，但对内核其实支持、官方做了模拟的号就是**静默降级**：
#   accept(202)        → 容器内所有 accept() 服务端不可用（已修：accept4 重放）
#   setgroups(159) 等  → glibc initgroups() 内联 svc，su/login 第一步失败（已修）
# 这类缺陷单测看不出来，只有逐号对照官方才能暴露。本测试把那次枚举固化。
#
# 【判据】对每个在本环境被 TRAP 的号，比较两侧（均不装客户处理器）的 x0：
#   官方 x0 ≠ -38（ENOSYS）而 bxroot x0 == -38  → 差异
# 已知且接受的差异列在 KNOWN 里（每项写明理由）。出现 KNOWN 以外的差异 → FAIL。
# 不在本容器（无外层 proroot）时无对照 → rc=2。
# ---------------------------------------------------------------------
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-trap-XXXXXX")
trap 'rm -rf "$W"' EXIT

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在官方 proroot 下，没有对照组"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }
command -v gcc >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || {
    echo "⏭️  跳过：缺 gcc 或 python3"; exit 2; }

# 已知差异（号: 理由）。**只许带理由加，不许为了变绿加。**
#   （空）—— 194-197 SysV shm 曾在此列，2026-09-25 实现 sysvshm.c 后移除。
KNOWN=""

i=1
while [ $i -le 10 ]; do
    gcc -O0 -w -o "$W/p" "$ROOT/test/probe_trap_enum.c" 2>"$W/cc" && break
    grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/p" ] || { echo "❌ 探针编译失败"; exit 1; }

timeout 300 "$W/p" 0 462 2>/dev/null | sort -un -k1,1 > "$W/trap.txt"
NOH=1 timeout 300 "$W/p" 0 462 2>/dev/null | sort -un -k1,1 > "$W/off.txt"
NOH=1 timeout 600 "$ROOT/tools/bxroot-run" -- "$W/p" 0 462 2>/dev/null \
    | sort -un -k1,1 > "$W/bx.txt"

python3 - "$W" "${KNOWN:-}" <<'EOF'
import re, sys
w, known = sys.argv[1], set(int(x) for x in sys.argv[2].split() if x)
names = {}
for l in open('/usr/include/asm-generic/unistd.h'):
    m = re.match(r'#define __NR(?:3264)?_(\w+)\s+(\d+)', l)
    if m: names.setdefault(int(m.group(2)), m.group(1))
def load(f):
    d = {}
    for l in open(f):
        p = l.split()
        if len(p) >= 2: d[int(p[0])] = p[1:]
    return d
trap, off, bx = load(w+'/trap.txt'), load(w+'/off.txt'), load(w+'/bx.txt')
trapped = sorted(n for n, v in trap.items() if v[0] == 'TRAP' and n in names)
if len(trapped) < 10 or len(bx) < 400:
    print(f"❌ 枚举不完整（trapped={len(trapped)} bx={len(bx)}），探针没跑起来")
    sys.exit(1)
new, kept = [], []
for n in trapped:
    o, b = off.get(n, ['?'])[-1], bx.get(n, ['?'])[-1]
    if o != '-38' and b == '-38':
        (kept if n in known else new).append((n, o))
print(f"本环境被 TRAP 的真实调用: {len(trapped)} 个")
for n, o in kept:
    print(f"  ⚠️  已知差异 {n:3} {names[n]:12} 官方 x0={o}  bxroot ENOSYS")
for n, o in new:
    print(f"  ❌ 新差异   {n:3} {names[n]:12} 官方 x0={o}  bxroot ENOSYS")
stale = [n for n in known if n not in [k for k, _ in kept]]
for n in stale:
    print(f"  ℹ️  KNOWN 里的 {n} 已不再有差异 —— 请从 KNOWN 移除")
if new:
    print("RESULT: FAIL —— 官方可用而 bxroot 回 ENOSYS 的调用出现新增")
    sys.exit(1)
print(f"RESULT: PASS —— 无新增差异（已知 {len(kept)} 项）")
EOF
