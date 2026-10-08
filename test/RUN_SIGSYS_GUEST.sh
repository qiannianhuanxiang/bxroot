#!/bin/sh
# ---------------------------------------------------------------------
# guest 对 SIGSYS 的设置 + 进程发给自己的 SIGSYS（2026-10-09 真机缺陷）
#
# DSHA 内置终端打开即崩（"[proroot] child killed by signal 11"）。根因：
# 交互式 bash 给 SIGSYS 装了终止处理器。
#   旧实现 A：吞掉 signal(SIGSYS,SIG_DFL) → bash 的处理器摘不掉，
#             kill(self,SIGSYS) 无限递归 → 栈耗尽 SEGV（rc=139）
#   旧实现 B（只吞 kill）：bash 的处理器仍顶掉 runtime 的，faccessat2 被
#             seccomp TRAP 时 SIGSYS 直接进 bash 处理器 → rc=159
# 修法：guest 的设置进影子槽（真处理器常驻）+ 吞掉发给自己的 SIGSYS。
#
# 判别力：恢复旧版 sigsys.c / proc.c 任一半，对应探针变红。
# 退出：0 通过 / 1 失败（环境不允许装 seccomp 时该探针跳过）
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
case "$(uname -m)" in aarch64|arm64) ;; *) echo "⏭️  跳过：非 aarch64"; exit 0 ;; esac
RT=${BXROOT_RUNTIME_SO:-$ROOT/build/libbxroot-runtime.so}
[ -f "$RT" ] || { echo "⏭️  跳过：没有 $RT（先 ./BUILD_RUNTIME.sh）"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-sigsysg-XXXXXX"); trap 'rm -rf "$W"' EXIT
fail=0
for p in probe_self_sigsys probe_guest_sigsys_slot; do
    gcc -O1 -w -o "$W/$p" "$ROOT/test/sigsys/$p.c" || { echo "❌ 编译 $p 失败"; exit 1; }
    out=$(LD_PRELOAD="$RT" BXROOT_ROOTFS=/tmp "$W/$p" 2>&1); rc=$?
    echo "--- $p"; echo "$out" | tail -6
    if [ "$rc" -eq 2 ]; then echo "⏭️  $p 跳过（环境）"; continue; fi
    [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q '^RESULT: PASS$' || fail=1
done
[ "$fail" -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit "$fail"
