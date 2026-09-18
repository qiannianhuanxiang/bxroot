#!/bin/sh
# 系统调用路径参数表 —— 实测审计器驱动（评估报告 8.6）
#
# 为什么需要本项：这张表用位掩码声明"第几个寄存器是路径"，**没有类型
# 检查**。本项目已因此出过两次致命事故（symlinkat 把 AT_FDCWD 当指针；
# 260 被当成 linkat 实为 wait4，wstatus=0x2f 恰是 '/'）。而当时的回归
# 测不到这张表（只编测试自己，不链接 guard）。
#
# 本驱动器跑 test/test_syscall_table_audit.c —— 它用**裸 svc** 对内核
# 逐号实测（不经 libc syscall()），因此量的是内核行为而非我们的代码；
# 再与源码里的表比对，报出"实测是路径型但表里没有"（遗漏，必须为 0）
# 与"表里有但实测不符"（不一致，必须为 0）。
#
# 判据：g_missing == 0 且 g_fails == 0 → PASS。
# 「存疑」项（被 seccomp 仿真层遮挡、无法实测）不判 FAIL，但会列出，
# 便于真机环境复核。
#
# 用法：sh test/RUN_SYSCALL_TABLE_AUDIT.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
OUT="/tmp/scg-audit.$$"

echo "▶️  系统调用路径参数表实测审计"

# gcc13 间歇 ICE：重试 + 降优化（与项目其他构建脚本同策略）
OPT="-O1"
for i in 1 2 3 4 5; do
    if $CC -std=c11 $OPT -D_GNU_SOURCE -Wall -Wextra \
        -o "$OUT" "$ROOT/test/test_syscall_table_audit.c" 2>"$OUT.err"; then
        break
    fi
    if grep -q "internal compiler error" "$OUT.err"; then
        [ "$OPT" = "-O1" ] && { OPT="-O0"; continue; }
    fi
    echo "   ❌ 编译失败："
    head -15 "$OUT.err"
    rm -f "$OUT" "$OUT.err"
    exit 1
done

if [ ! -f "$OUT" ]; then
    echo "   ❌ 探针未产出（检查 $OUT.err）"
    rm -f "$OUT.err"
    exit 1
fi

# 审计器需要知道源码路径（默认就是 src/runtime/syscall_guard.c）
cd "$ROOT"
timeout 600 "$OUT" "$ROOT/src/runtime/syscall_guard.c" > "$OUT.out" 2>&1
rc=$?

# 摘要输出（完整日志留在文件里，失败时打印）
grep -E "^  (检查项|不一致|存疑|遗漏|RESULT)" "$OUT.out" | sed 's/^/   /'

if [ $rc -ne 0 ]; then
    echo "   ---- 失败详情（尾 40 行）----"
    tail -40 "$OUT.out"
fi

if [ $rc -eq 0 ]; then
    echo "   RESULT: PASS"
else
    echo "   RESULT: FAIL"
fi

rm -f "$OUT" "$OUT.err" "$OUT.out"
exit $rc
