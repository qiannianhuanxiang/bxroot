#!/bin/sh
# =====================================================================
# bxroot 全量回归入口
# =====================================================================
#
# 由来
# ----
# Makefile 里的 `make test` 一直指向 `test/full_test.sh` —— 而那个文件
# **从来不存在**。也就是说"跑测试"这个动作在过去是空转的：谁执行
# `make test` 都会拿到 "No such file or directory"，于是没人真的跑过
# 全量回归。本脚本把它补成一个真实可跑的总入口。
#
# 覆盖范围
# --------
#   1. 编译告警门禁        test/RUN_WARN_GATE.sh
#   2. l2s 运行时          test/test_l2s_rt.c
#   3. l2s × fakeroot 协同 test/RUN_INTEGRATION.sh
#   4. fakeroot 纯逻辑     test/RUN_TESTS.sh
#   5. 系统调用参数位置    test/test_syscall_argpos.c
#   6. crash 崩溃处理器    src/runtime/RUN_CRASH_TESTS.sh
#   7. D4 进程管理         src/proc/RUN_TESTS.sh
#   8. wait 家族钩子       test/RUN_WAIT_TESTS.sh
#   9. 运行时构建 + 符号导出  BUILD_RUNTIME.sh
#
# 为什么第 9 项也算回归
# --------------------
# 构建脚本结尾会核对 D4 的 19 个符号是否在**动态符号表**里。LD_PRELOAD
# 靠动态符号表插入，符号漏导出 = 钩子静默失效，而进程照样能跑 ——
# 这类缺陷只有构建期检查能拦住。
#
# 可选：端到端（默认**不跑**）
# ---------------------------
#   sh test/RUN_ALL.sh --e2e
# 会额外尝试在真机容器里用 bxroot 启动 dsh。它需要真实 rootfs 与
# Android 环境，在纯 Ubuntu 容器里会跳过。
#
# 用法
# ----
#   sh test/RUN_ALL.sh             # 全量回归
#   sh test/RUN_ALL.sh --quick     # 跳过构建（只跑测试）
#   sh test/RUN_ALL.sh --e2e       # 追加端到端
#
# 退出码
# ------
#   0 = 全部通过     1 = 有失败
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 1; }

QUICK=0
DO_E2E=0
for a in "$@"; do
    case "$a" in
    --quick) QUICK=1 ;;
    --e2e)   DO_E2E=1 ;;
    esac
done

# ---------------------------------------------------------------------
# 结果收集。用文件暂存，因为各测试跑在子 shell 里。
# ---------------------------------------------------------------------
RESULT_FILE="/tmp/bxroot-all-$$.txt"
: > "$RESULT_FILE"

PASS=0
FAIL=0

# 记录一条结果：$1=状态(PASS/FAIL/SKIP) $2=名称 $3=摘要
note() {
    printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$RESULT_FILE"
}

echo "======================================================"
echo " bxroot 全量回归"
echo " 仓库: $ROOT"
echo "======================================================"
echo

# ---------------------------------------------------------------------
# 通用执行器：跑一条命令，捕获退出码与输出尾部
#
# 之所以不直接 `set -e`：需要跑完所有测试再统一汇报，
# 第一个失败就退出会掩盖后面测试的状态。
# ---------------------------------------------------------------------
run_step() {
    name="$1"; shift
    logf="/tmp/bxroot-step-$$.log"

    if [ "$#" -eq 0 ]; then
        note SKIP "$name" "无命令"
        printf '⏭️  %-26s 跳过\n' "$name"
        return 0
    fi

    printf '▶️  %-26s ' "$name"
    # shellcheck disable=SC2068
    if "$@" >"$logf" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    # 摘要：优先取输出里的"通过/失败"统计行，否则取末行
    summary=$(grep -aoE '[0-9]+ *(用例|个用例|passed|通过)[^,，]*' "$logf" 2>/dev/null | tail -1)
    [ -z "$summary" ] && summary=$(tail -1 "$logf" 2>/dev/null | cut -c1-48)

    if [ "$rc" -eq 0 ]; then
        note PASS "$name" "$summary"
        PASS=$((PASS + 1))
        printf '✅ rc=0  %s\n' "$summary"
    else
        note FAIL "$name" "rc=$rc $summary"
        FAIL=$((FAIL + 1))
        printf '❌ rc=%s  %s\n' "$rc" "$summary"
        echo "   --- 末尾 15 行 ---"
        tail -15 "$logf" | sed 's/^/   /'
        echo "   ------------------"
    fi
    rm -f "$logf"
    return 0
}

# =====================================================================
# 1. 编译告警门禁 —— 放第一位：编译不过后面都没意义
# =====================================================================
run_step "编译告警门禁" sh test/RUN_WARN_GATE.sh

# =====================================================================
# 2. l2s 运行时（15 用例）
# =====================================================================
if [ -f test/test_l2s_rt.c ]; then
    cat >/tmp/bxroot-l2s-$$.sh <<'L2SEOF'
i=1
while [ $i -le 8 ]; do
    if gcc -std=c11 -O1 -Wall -Wextra -D_GNU_SOURCE \
        -Isrc/l2s -o /tmp/bxroot-t-l2s \
        test/test_l2s_rt.c src/l2s/l2s.c src/l2s/l2s-runtime.c \
        2>/tmp/bxroot-l2s-cc.err; then
        exec /tmp/bxroot-t-l2s
    fi
    grep -q 'internal compiler error' /tmp/bxroot-l2s-cc.err || {
        cat /tmp/bxroot-l2s-cc.err; exit 1; }
    i=$((i + 1))
done
exec gcc -std=c11 -O0 -D_GNU_SOURCE -Isrc/l2s -o /tmp/bxroot-t-l2s \
    test/test_l2s_rt.c src/l2s/l2s.c src/l2s/l2s-runtime.c && /tmp/bxroot-t-l2s
L2SEOF
    run_step "l2s 运行时" sh /tmp/bxroot-l2s-$$.sh
    rm -f /tmp/bxroot-l2s-$$.sh
else
    run_step "l2s 运行时"
fi

# =====================================================================
# 3. 协同（l2s × fakeroot）
# =====================================================================
[ -f test/RUN_INTEGRATION.sh ] && run_step "l2s×fakeroot 协同" sh test/RUN_INTEGRATION.sh \
    || run_step "l2s×fakeroot 协同"

# =====================================================================
# 4. fakeroot 纯逻辑
# =====================================================================
[ -f test/RUN_TESTS.sh ] && run_step "fakeroot 纯逻辑" sh test/RUN_TESTS.sh \
    || run_step "fakeroot 纯逻辑"

# =====================================================================
# 5. 系统调用参数位置（防回归：symlinkat 的 a1 不是路径）
# =====================================================================
if [ -f test/test_syscall_argpos.c ]; then
    cat >/tmp/bxroot-argpos-$$.sh <<'ARGEOF'
i=1
while [ $i -le 8 ]; do
    if gcc -std=c11 -O1 -Wall -Wextra -o /tmp/bxroot-t-argpos \
        test/test_syscall_argpos.c 2>/tmp/bxroot-argpos-cc.err; then
        exec /tmp/bxroot-t-argpos
    fi
    grep -q 'internal compiler error' /tmp/bxroot-argpos-cc.err || {
        cat /tmp/bxroot-argpos-cc.err; exit 1; }
    i=$((i + 1))
done
exec gcc -std=c11 -O0 -o /tmp/bxroot-t-argpos test/test_syscall_argpos.c \
    && /tmp/bxroot-t-argpos
ARGEOF
    run_step "系统调用参数位置" sh /tmp/bxroot-argpos-$$.sh
    rm -f /tmp/bxroot-argpos-$$.sh
else
    run_step "系统调用参数位置"
fi

# =====================================================================
# 6. crash 崩溃处理器
# =====================================================================
[ -f src/runtime/RUN_CRASH_TESTS.sh ] \
    && run_step "crash 崩溃处理器" sh src/runtime/RUN_CRASH_TESTS.sh \
    || run_step "crash 崩溃处理器"

# =====================================================================
# 7. D4 进程管理
# =====================================================================
if [ -f src/proc/RUN_TESTS.sh ]; then
    run_step "D4 进程管理" sh -c 'cd src/proc && sh RUN_TESTS.sh'
else
    run_step "D4 进程管理"
fi

# =====================================================================
# 8. wait 家族钩子
# =====================================================================
[ -f test/RUN_WAIT_TESTS.sh ] && run_step "wait 家族钩子" sh test/RUN_WAIT_TESTS.sh \
    || run_step "wait 家族钩子"

# =====================================================================
# 9. 运行时构建 + 符号导出核对
# =====================================================================
if [ "$QUICK" = 0 ]; then
    run_step "运行时构建" sh BUILD_RUNTIME.sh
else
    run_step "运行时构建"
fi

# =====================================================================
# 10. 可选端到端
# =====================================================================
if [ "$DO_E2E" = 1 ]; then
    if [ -f test/RUN_E2E.sh ] && [ -d /data/data/com.dsh.client ]; then
        run_step "端到端 dsh" sh test/RUN_E2E.sh --version
    else
        note SKIP "端到端 dsh" "非真机环境"
        printf '⏭️  %-26s 跳过（需真机 rootfs）\n' "端到端 dsh"
    fi
fi

# =====================================================================
# 汇总
# =====================================================================
echo
echo "======================================================"
echo " 回归汇总"
echo "======================================================"
while IFS='|' read -r st nm sm; do
    case "$st" in
    PASS) printf '  ✅ %-24s %s\n' "$nm" "$sm" ;;
    FAIL) printf '  ❌ %-24s %s\n' "$nm" "$sm" ;;
    SKIP) printf '  ⏭️  %-24s %s\n' "$nm" "$sm" ;;
    esac
done < "$RESULT_FILE"
echo "------------------------------------------------------"
echo "  通过 $PASS / 失败 $FAIL"
rm -f "$RESULT_FILE"

if [ "$FAIL" -gt 0 ]; then
    echo "  ❌ 回归未通过"
    exit 1
fi
echo "  ✅ 全部通过"
exit 0
