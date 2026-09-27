#!/bin/sh
# ---------------------------------------------------------------------
# statx AT_EMPTY_PATH 空路径回归（自主发现，2026-09-28）
#
#   statx(fd, "", AT_EMPTY_PATH, …) 作用于 fd 自身。preload.c 的 statx
#   钩子曾对空串误判为「相对路径」→ bxroot_absolutize("") 产出 "cwd/"，
#   把对 fd 的 stat 误导到 CWD 目录。修：空串既不绝对化也不翻译，
#   直接让底层 statx 按 fd 语义处理。
#
# 判据：statx(fd,"",AT_EMPTY_PATH) 的 ino/size 必须与 fstat(fd) 一致。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }

W=$(mktemp -d /tmp/bxroot-statx-XXXXXX)
trap 'rm -rf "$W"' EXIT
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp"
ln -s ../../../usr "$RF/usr"
ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
echo "STATX-GUEST" > "$RF/etc/hostname"

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
bld -O1 -w -o "$RF/tmp/px" "$ROOT/test/probe_statx_empty.c" || exit 1

echo "== statx AT_EMPTY_PATH 空路径 =="
# 空路径经 absolutize 会产出 "cwd/"（目录），与被测文件（普通文件）
# 的 ino/size 必然不同，无论 CWD 是什么都有判别力。
o=$(cd / && timeout 60 "$BX" --rootfs "$RF" -- /tmp/px /tmp/canary-file 2>&1)
echo "$o" | grep -q "DONE ok=1" \
    && { echo "  ✅ statx(fd,\"\",AT_EMPTY_PATH) 与 fstat 一致"; exit 0; } \
    || { echo "  ❌ $(echo "$o" | grep -E 'MISMATCH|STATX-FAIL|SETUP-FAIL|DONE' | tr '\n' ' ')"; exit 1; }
