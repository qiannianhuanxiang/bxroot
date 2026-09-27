#!/bin/sh
# ---------------------------------------------------------------------
# mkfifo/mknod/utime/utimes 路径翻译 + mknod errno 归一化回归
# （自主发现，2026-09-28 压测子代理 B/E）
#
#   这几个 libc 符号此前未 hook → rootfs 内路径走未翻译字面路径 →
#   ENOENT（基线正常）；且 mknod 设备节点非特权失败的 errno 不是 EPERM。
#   修：preload.c 补 mkfifo/mkfifoat/mknod/mknodat/utime/utimes/lutimes/
#   futimes/futimens 钩子，设备节点失败 errno 归一化为 EPERM。
#
# 判据（rootfs 内可写目录 /tmp）：
#   MKFIFO   rc=0 且 isfifo=1
#   UTIME    rc=0 且 mtime=1000000000
#   UTIMES   rc=0 且 mtime=1200000000
#   MKNOD_CHR rc=-1 errno=1(EPERM)   ← 归一化后
# 与官方基线对照（基线也应 MKFIFO/UTIME 成功、MKNOD EPERM）。
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

W=$(mktemp -d /tmp/bxroot-mknod-XXXXXX)
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
bld -O1 -w -o /tmp/px_mknod "$ROOT/test/probe_mknod_utime.c" || exit 1

# guest 里用一个 rootfs 内可写目录。/tmp（=rootfs/tmp）即可。
run() { timeout 60 "$@" -- /tmp/px_mknod /tmp 2>&1; }

FAIL=0
chk() {
    _label="$1"; _out="$2"; _pat="$3"
    if echo "$_out" | grep -q "$_pat"; then
        echo "  ✅ $_label"
    else
        echo "  ❌ $_label（实际：$(echo "$_out" | grep -iE 'MKFIFO|UTIME|UTIMES|MKNOD' | tr '\n' ' ')）"
        FAIL=1
    fi
}

echo "== bxroot: mkfifo/utime/utimes/mknod =="
BX_OUT=$(run "$BX" --no-check)
chk "mkfifo 创建 FIFO 成功"            "$BX_OUT" 'MKFIFO rc=0 errno=[0-9]* isfifo=1'
chk "utime 设置 mtime 成功"            "$BX_OUT" 'UTIME rc=0 errno=0 mtime=1000000000'
chk "utimes 设置 mtime 成功"           "$BX_OUT" 'UTIMES rc=0 errno=0 mtime=1200000000'
chk "mknod 字符设备非特权→EPERM(1)"    "$BX_OUT" 'MKNOD_CHR rc=-1 errno=1'

echo "== 基线 off-rt.so 对照 =="
if [ -f /tmp/off-rt.so ]; then
    BL_OUT=$(BXROOT_RUN_RUNTIME=/tmp/off-rt.so run "$BX" --no-check)
    echo "$BL_OUT" | grep -q 'MKFIFO rc=0' \
        && echo "  ✅ 基线 mkfifo 也成功（确认非环境限制）" \
        || echo "  ⚠️  基线 mkfifo 未成功（环境差异，不判 bxroot 失败）"
    echo "$BL_OUT" | grep -q 'MKNOD_CHR rc=-1 errno=1' \
        && echo "  ✅ 基线 mknod 也 EPERM（确认归一化正确）" \
        || echo "  ⚠️  基线 mknod errno 非 1（$(echo "$BL_OUT" | grep MKNOD)）"
fi

rm -f /tmp/px_mknod
[ "$FAIL" -eq 0 ] && { echo "RESULT: PASS"; exit 0; } || { echo "RESULT: FAIL"; exit 1; }
