#!/bin/sh
# ---------------------------------------------------------------------
# livepatch 静态链接 guest 主映像扫描（2026-09-28）
#
# 【验什么】静态链接（gcc -static）的 guest 里，glibc 的 set_robust_list(99)/
# rseq(293) 内联 svc 在**主可执行映像自己的 .text**，不在独立 libc.so.6 段。
# livepatch 早先只扫 libc.so.6 段、且 find_libc_base()==0 时直接早退，于是
# 静态 guest 一条都补不到 —— 真机（无外层 proroot）上其 pthread_create 新线程
# 在 clone 前屏蔽全信号、start_thread 内联发 set_robust_list → seccomp
# KILL_PROCESS → SIGSYS 投递不了 → 死 159（docs/真机验证清单.md 的残余条）。
#
# 修复：livepatch.c 新增 find_main_exec_range()，当没有独立 libc.so.6 r-x 段
# （静态特征）时，用"本函数自身地址"作锚点定位主映像 r-x 段并扫描补 99/293。
#
# 【判别力】探针把 livepatch.c 以 -DLP_TEST_HOOK 静态编入 —— 它自己就是一个
# 静态 guest（无 libc.so.6 段，走主映像扫描分支）。探针内放一个"外层 proroot
# 会漏补"的 far 形态 99 站点（mov x8,#99 与 svc 间隔栈 spill，超出外层紧凑
# 补丁窗口），从而在本容器（嵌套外层 proroot）里也有判别力：
#   修复前：站点 UNPATCHED，屏蔽全信号下调用它 → 进程被 SIGSYS 杀；
#   修复后：站点 PATCHED，同样的 masked 调用存活。
# 撤修复（去掉 find_main_exec_range 分支）→ apply 后仍 UNPATCHED → 变红。
# （已实测：撤修复 RESULT: FAIL / masked_survives=0。）
#
# 退出：0 通过 / 1 失败 / 2 环境不满足（非 aarch64、无 seccomp、外层已补齐）
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)

case "$(uname -m)" in
aarch64|arm64) ;;
*) echo "⏭️  跳过：本机非 aarch64（$(uname -m)），站点指令编码不适用"; exit 2 ;;
esac

W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-staticthr-XXXXXX")
trap 'rm -rf "$W"' EXIT

NCC=${NATIVE_CC:-gcc}
i=1
while [ "$i" -le 12 ]; do
    "$NCC" -O1 -w -DLP_TEST_HOOK -D_GNU_SOURCE -static -no-pie \
        -I"$ROOT/src/runtime" \
        -o "$W/probe" \
        "$ROOT/test/static/probe_static_thread.c" \
        "$ROOT/src/runtime/livepatch.c" 2>"$W/cc.err" && break
    grep -q 'internal compiler error' "$W/cc.err" || {
        # 无静态 libc 时链接会失败 —— 归为环境不满足
        if grep -qiE 'cannot find|-static|libc\.a|crt' "$W/cc.err"; then
            echo "⏭️  跳过：无法静态链接（缺静态 libc）"; head -3 "$W/cc.err"; exit 2
        fi
        echo "❌ 编译失败"; head -20 "$W/cc.err"; exit 1
    }
    i=$((i + 1))
done
[ -x "$W/probe" ] || { echo "❌ 未产出可执行文件"; exit 1; }

out=$("$W/probe" 2>&1)
rc=$?
echo "$out"
case "$rc" in
0) exit 0 ;;
2) exit 2 ;;   # 探针自报环境不满足（无 seccomp / 外层已补齐）
*) exit 1 ;;
esac
