#!/bin/sh
# ---------------------------------------------------------------------
# 小栈线程崩溃回归（2026-10-26）
#
# 缺陷：resolve_symlink_full / resolve_intermediate_symlinks 曾在栈上各放
# 16 x MAX_PATH_LEN(8KB) 的循环检测集合，单帧 64KB。openat/statx/fstatat
# 的钩子互相嵌套（translate_follow -> stat_pre_resolve -> resolve_*），
# 8 层就是 512KB。实测：pthread 栈 512KB 的线程里调 stat/lstat 直接
# SIGSEGV，1MB 正常。Android 上大量程序把栈调小，所以是真实崩溃。
#
# 修法：seen 改到堆上（calloc），语义等价。
#
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在外层 proroot 下"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime 产物"; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：无 gcc"; exit 2; }

W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-stack-XXXXXX")
trap 'rm -rf "$W"' EXIT

i=1
while [ $i -le 10 ]; do
    gcc -O1 -w -pthread -o "$W/probe" "$ROOT/test/probe_small_stack.c" 2>"$W/cc" && break
    grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/probe" ] || { echo "❌ 探针编译失败"; exit 1; }

out=$(cd / && timeout 120 "$BX" --no-check -- "$W/probe" 2>&1)
echo "$out" | sed "s/^/  /"

if echo "$out" | grep -q "SMALL_STACK_OK"; then
    echo "RESULT: PASS"
    exit 0
fi
if echo "$out" | grep -q "STACK_DEPTH_SKIPPED"; then
    echo "RESULT: PASS（内核不允许小栈，已跳过）"
    exit 0
fi
if echo "$out" | grep -q "Segmentation fault"; then
    echo "RESULT: FAIL（小栈线程 SIGSEGV —— resolver 栈帧回归）"
    exit 1
fi
echo "RESULT: FAIL"
exit 1
