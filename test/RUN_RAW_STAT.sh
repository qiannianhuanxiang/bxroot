#!/bin/sh
# ---------------------------------------------------------------------
# 裸 syscall stat 的 nlink/属主伪装回归（自主发现，2026-09-28）
#
#   node/libuv、静态程序绕过 libc 发 syscall(newfstatat=79)/statx(291)，
#   只经 syscall_guard.c。guard 此前只翻译路径、不补结果：l2s 硬链接
#   nlink 停在 1、fakeroot 属主停在磁盘真实 app uid。修：guard 给 79 补
#   l2s nlink + fakeroot 属主，给 291 补属主，__thread 守卫防 probe 递归。
#
# 判据：3 硬链接文件经裸 newfstatat 必须 nlink=3 uid=0 gid=0（= libc 符号
#   钩子入口、= 官方基线）。node fs.statSync（走 libuv 裸 statx）同样验证。
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

W=$(mktemp -d /tmp/bxroot-rawstat-XXXXXX)
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
bld -O1 -w -o /tmp/px_rawstat "$ROOT/test/probe_raw_stat.c" || exit 1

FAIL=0
echo "== 裸 newfstatat：l2s nlink + fakeroot 属主伪装 =="
# 工作目录用 rootfs 内可写目录（/tmp = rootfs/tmp）。
out=$(timeout 60 "$BX" --no-check -- /tmp/px_rawstat /tmp 2>&1)
echo "$out" | grep -E 'LIBC|RAW79'
case "$out" in
    *RAWSTAT-OK*) echo "  ✅ 裸 newfstatat nlink=3 uid=0 gid=0（与 libc 入口一致）" ;;
    *) echo "  ❌ 裸 newfstatat 未伪装（nlink/属主停在内核真值）"; FAIL=1 ;;
esac

# node fs.statSync：libuv 直接发裸 statx，属真实工具受影响面。
if "$BX" -- /usr/local/bin/node -e 'process.exit(0)' >/dev/null 2>&1; then
    echo "== node fs.statSync（libuv 裸 statx）属主伪装 =="
    n_out=$("$BX" --no-check -- /usr/local/bin/node -e \
        'const s=require("fs").statSync("/etc/hostname");console.log("NODE uid="+s.uid+" gid="+s.gid)' \
        2>&1 | grep NODE)
    echo "  $n_out"
    case "$n_out" in
        *"uid=0 gid=0"*) echo "  ✅ node statSync 属主=0（裸 statx 入口已伪装）" ;;
        *) echo "  ❌ node statSync 属主未伪装：[$n_out]"; FAIL=1 ;;
    esac
else
    echo "  ⏭️  跳过 node 判据（无 node）"
fi

# 官方基线对照（应同为 nlink=3 uid=0）。
if [ -f /tmp/off-rt.so ]; then
    echo "== 官方基线 off-rt.so 对照 =="
    b_out=$(BXROOT_RUN_RUNTIME=/tmp/off-rt.so timeout 60 "$BX" --no-check \
        -- /tmp/px_rawstat /tmp 2>&1 | grep RAW79)
    echo "  基线 $b_out"
fi

rm -f /tmp/px_rawstat
[ "$FAIL" -eq 0 ] && { echo "RESULT: PASS"; exit 0; } || { echo "RESULT: FAIL"; exit 1; }
