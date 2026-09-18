#!/bin/sh
# BXROOT_RAW_SYSCALL 透传开关单元测试：守卫决策矩阵（源码级，
# 见 probe_raw_syscall.c 头注）
# 用法：sh test/RUN_RAW_SYSCALL.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
OUT="/tmp/syswork-rawsyscall-probe.$$"

echo "▶️  RAW_SYSCALL 透传开关（源码级单元）"

# gcc13 间歇 ICE：重试 + 降优化级（与 BUILD_RUNTIME.sh / RUN_D3_FIXUP.sh 同策略）
#
# ★ 额外 -Wno-address（仅本探针）★
# 本探针按 D3 模式把 preload.c 与 syscall_guard.c 合并进**同一个**编译
# 单元：guard 里对 weak 桥（bxroot_fakeroot_*）的判空在合并后变成
# "强定义地址恒非 NULL"，gcc 必报 -Waddress。逐单元构建（BUILD_RUNTIME /
# RUN_WARN_GATE）里这些比较仍是真 weak，警告照常受门禁 —— 这里只是
# 探针台的已知假告警，压掉以免淹没结果。
OPT="-O2"
for i in 1 2 3 4; do
    if $CC $OPT -Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter \
        -Wno-format-truncation -Wno-address \
        -I"$ROOT/src/l2s" -I"$ROOT/src/proc" -DFAKEROOT_PURE_LOGIC -DPX_PURE_LOGIC=0 \
        -Wl,--allow-multiple-definition \
        -o "$OUT" "$ROOT/test/probe_raw_syscall.c" "$ROOT/src/l2s/l2s.c" \
        "$ROOT/src/l2s/l2s-runtime.c" "$ROOT/src/runtime/fakeroot.c" \
        "$ROOT/src/runtime/crash.c" "$ROOT/src/runtime/sigsys.c" \
        "$ROOT/src/runtime/syscall_guard.c" "$ROOT/src/runtime/livepatch.c" \
        "$ROOT/src/proc/proc.c" -ldl -lpthread 2>"$OUT.err"; then
        break
    fi
    if grep -q "internal compiler error" "$OUT.err" && [ "$OPT" = "-O2" ]; then
        OPT="-O1"; continue
    fi
    if grep -q "internal compiler error" "$OUT.err" && [ "$OPT" = "-O1" ]; then
        OPT="-O0"; continue
    fi
    echo "   ❌ 编译失败（非 ICE）："
    head -20 "$OUT.err"
    rm -f "$OUT" "$OUT.err"
    exit 1
done

if [ ! -f "$OUT" ]; then
    echo "   ❌ 探针未产出（编译失败，检查 $OUT.err）"
    rm -f "$OUT.err"
    exit 1
fi

# BXROOT_NO_AUTORUN=1：跳过 preload.c 构造链（源码级单元测试逃生门）
BXROOT_NO_AUTORUN=1 "$OUT"
rc=$?
rm -f "$OUT" "$OUT.err"

if [ $rc -eq 0 ]; then
    echo "   RESULT: PASS"
else
    echo "   RESULT: FAIL"
fi
exit $rc
