#!/bin/sh
# ---------------------------------------------------------------------
# statx(fd, NULL, AT_EMPTY_PATH) 不崩溃回归（自主发现，2026-09-28）
#
#   glibc __nonnull((2,5)) 让编译器删掉 statx 钩子里的 path!=NULL 守卫，
#   合法的 statx(fd, NULL, AT_EMPTY_PATH) 触发 runtime 内空指针解引用 →
#   整进程 SIGSEGV。修：钩子入口 volatile 洗掉 nonnull 假设。
#
# 判据：探针必须打印 "DONE"（= statx 返回了、进程没被信号打死）。
#   若崩溃则 bxroot-run 捕获到非零信号退出、无 DONE。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：无 gcc"; exit 2; }

W=$(mktemp -d /tmp/bxroot-statxnull-XXXXXX)
trap 'rm -rf "$W"' EXIT

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
# 探针放进 rootfs 内（容器 /tmp = rootfs/tmp），guest 可 exec。
bld -O1 -w -o /tmp/px_statxnull "$ROOT/test/probe_statx_null.c" || exit 1

echo "== statx(fd, NULL, AT_EMPTY_PATH) 不崩溃 =="
o=$(timeout 60 "$BX" --no-check -- /tmp/px_statxnull /etc/hostname 2>&1)
rm -f /tmp/px_statxnull
echo "$o" | grep -q "DONE " \
    && { echo "  ✅ statx(fd,NULL) 未崩溃（$(echo "$o" | grep DONE)）"; exit 0; } \
    || { echo "  ❌ statx(fd,NULL) 疑似崩溃：$(echo "$o" | grep -iE 'SIGSEGV|SETUP-FAIL|backtrace' | head -2 | tr '\n' ' ')"; exit 1; }
