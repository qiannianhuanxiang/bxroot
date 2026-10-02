#!/bin/sh
# ---------------------------------------------------------------------
# 安全审计修复回归（2026-10 审计：A2-1/A2-5/A3-1/SG-1/SL-1/B2-4/F5）
#
# A3-1（堆缓冲反向 bind 溢出）由 test/RUN_REALPATH_FIXUP.sh 的源码级单元覆盖。
#
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在外层 proroot 下，bxroot-run 无法注入"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime 产物"; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：无 gcc"; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-audit-XXXXXX")
trap 'rm -rf "$W"' EXIT

i=1
while [ $i -le 10 ]; do
    gcc -O1 -w -o "$W/probe" "$ROOT/test/probe_audit_fixes.c" 2>"$W/cc" && break
    grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/probe" ] || { echo "❌ 探针编译失败"; exit 1; }

out=$(timeout 60 "$BX" --no-check -- "$W/probe" 2>&1)
echo "$out" | sed 's/^/  /'

echo "$out" | grep -q '^DONE bad=0$' || { echo "RESULT: FAIL"; exit 1; }
n=$(echo "$out" | grep -c '^OK ')
[ "$n" -ge 8 ] || { echo "RESULT: FAIL（只有 $n 项 OK，探针可能中途崩溃）"; exit 1; }
echo "RESULT: PASS"
exit 0
