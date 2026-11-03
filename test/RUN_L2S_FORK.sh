#!/bin/sh
# ---------------------------------------------------------------------
# l2s 计数锁 fork 安全回归（2026-10-26）
#
# 缺陷：l2s 的 g_cnt_lock 是进程内自旋锁。父进程某线程持锁做 link 计数时
# 另一线程 fork，子进程继承锁位=1 而持锁线程不存在 → 之后第一次走
# read/write 回退分支就永久自旋（或直接崩）。fakeroot / sysvshm 早已在
# atfork child 回调里复位，唯独 l2s 漏了。
#
# 修法：新增 bxroot_l2s_fork_child()，由 preload.c 的 fork child 回调调用。
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

W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-l2sfork-XXXXXX")
trap 'rm -rf "$W"' EXIT

i=1
while [ $i -le 10 ]; do
    gcc -O1 -w -o "$W/probe" "$ROOT/test/probe_l2s_fork.c" 2>"$W/cc" && break
    grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/probe" ] || { echo "❌ 探针编译失败"; exit 1; }

out=$(cd / && BXROOT_LINK2SYMLINK=1 timeout 120 "$BX" --no-check -- "$W/probe" 2>&1)
echo "$out" | grep -E "L2S_FORK|FAIL|Segmentation" | sed "s/^/  /"

if echo "$out" | grep -q "L2S_FORK_OK"; then
    echo "RESULT: PASS"
    exit 0
fi
if echo "$out" | grep -q "Segmentation fault"; then
    echo "RESULT: FAIL（子进程崩溃 —— l2s 计数锁 fork 复位缺失）"
    exit 1
fi
echo "RESULT: FAIL"
exit 1
