#!/system/bin/sh
# =====================================================================
# bxroot 编译告警门禁
# =====================================================================
#
# 为什么需要这个脚本
# ------------------
# BUILD_RUNTIME.sh 原来用 `-w`，把**全部**警告静默掉了。这不是"图省事"，
# 而是造成过真实缺陷：
#
#   launcher.c 里一处 `fprintf(fd, fmt, a, b, c)` 少传了两个实参，
#   被调用方从栈上取到垃圾指针 → 进程 exit 139。编译期本可由
#   -Wformat=2 直接拦下，但 -w 把它一起关掉了，直到有人肉眼看代码
#   才发现。
#
# 所以修复分两步：
#   ① BUILD_RUNTIME.sh 改用精确警告集（-Wall -Wextra -Wformat=2，
#      只压掉确认无意义的 -Wnonnull-compare / -Wunused-parameter）；
#   ② 本脚本作为**独立门禁**跑在回归里 —— 编译通过不等于没有回归，
#      新代码带进来的告警必须让 CI 变红，否则下次还会有人用 -w 图快。
#
# 判据
# ----
# 对每个编译单元做 `-fsyntax-only`（不产出目标文件，快），
# 统计 `warning:` 行数。任何一条都算失败。
#
# 已知的两类"假告警"及其处理
# --------------------------
# ① `"_GNU_SOURCE" redefined`
#    部分文件（preload.c / sigsys.c / livepatch.c / launcher.c / bridge.c）
#    在文件头自行 #define _GNU_SOURCE，另一些（l2s.c / proc.c /
#    fakeroot.c）依赖命令行提供。两边都传就会重复定义。
#    → 构建脚本改为传**空定义** `-D_GNU_SOURCE=`：需要它的文件照样拿到
#      特性，自备定义的文件不再报重复。本脚本沿用同一写法。
#    注意：**不要**改用 -Wno-cpp 掩盖。那会连 `#warning` 和
#    `#if` 中的可疑写法一起吞掉，属于用 -w 换了个马甲。
#
# ② `-Wnonnull-compare`（防御性判空）
#    我们对几乎所有 hook 入口都做 `if (path == NULL) { errno = EFAULT; ... }`。
#    这些 hook 声明带 `__nonnull`（必须与 libc 原型逐字一致，否则
#    LD_PRELOAD 插入的符号签名对不上），于是 gcc 认定判空是死代码。
#    但这些判空恰恰是防上层乱传 NULL 的，不能删。
#    → 显式 -Wno-nonnull-compare。
#
# 用法
# ----
#   sh RUN_WARN_GATE.sh          # 门禁：有告警则 exit 1
#   sh RUN_WARN_GATE.sh -v       # 同时打印每条告警的上下文
#
# 退出码
# ------
#   0 = 零告警
#   1 = 有告警（回归失败）
#   2 = 环境问题（找不到 gcc / 源文件）
# =====================================================================

set -u

VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1

# ---------------------------------------------------------------------
# 定位仓库根目录：以 BUILD_RUNTIME.sh 为锚点，避免依赖调用者的 cwd
# ---------------------------------------------------------------------
SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 2; }

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

# proc.c 的编译单元位置（与 BUILD_RUNTIME.sh 保持同一套回退逻辑）
PROC_DIR=""
if [ -n "${BXROOT_PROC_DIR:-}" ] && [ -f "$BXROOT_PROC_DIR/proc.c" ]; then
    PROC_DIR="$BXROOT_PROC_DIR"
elif [ -f "src/proc/proc.c" ]; then
    PROC_DIR="src/proc"
elif [ -f "../proc/proc.c" ]; then
    PROC_DIR="../proc"
fi

# ---------------------------------------------------------------------
# 与 BUILD_RUNTIME.sh 完全一致的警告策略。
# 这里刻意**复制**而不是 source 构建脚本 —— 构建脚本会在被 source 时
# 直接开始编译，门禁必须能独立跑。
# 两处若不一致，本脚本结尾会检测（见底下 SANITY 段）。
# ---------------------------------------------------------------------
WARN="-Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter"
BASE="-shared -fPIC $WARN -D_GNU_SOURCE= -Isrc/l2s -Isrc/runtime"
DEFS="-DFAKEROOT_PURE_LOGIC -DPX_PURE_LOGIC=0"

# ---------------------------------------------------------------------
# 一致性自检：确保本脚本的警告集没和构建脚本漂移
# ---------------------------------------------------------------------
if [ -f BUILD_RUNTIME.sh ]; then
    if ! grep -q 'Wno-nonnull-compare' BUILD_RUNTIME.sh; then
        echo "⚠️  BUILD_RUNTIME.sh 里已没有 -Wno-nonnull-compare，"
        echo "    门禁与构建策略可能已漂移，请同步后重跑。"
    fi
    if grep -qE '^\s*CFLAGS=.*\s-w\s' BUILD_RUNTIME.sh; then
        echo "❌ BUILD_RUNTIME.sh 又用回了 -w（全量静默），这会让门禁失去意义。"
        echo "   请改回精确警告集。"
        exit 1
    fi
fi

UNITS="src/runtime/preload.c
src/runtime/syscall_guard.c
src/runtime/sigsys.c
src/runtime/crash.c
src/runtime/livepatch.c
src/runtime/fakeroot.c
src/l2s/l2s.c
src/l2s/l2s-runtime.c
src/launcher/launcher.c
src/bridge/bridge.c"

[ -n "$PROC_DIR" ] && UNITS="$UNITS $PROC_DIR/proc.c"

echo "== bxroot 编译告警门禁 =="
echo "   编译器 : $CC ($("$CC" -dumpversion 2>/dev/null))"
echo "   警告集 : $WARN"
echo "   proc.c : ${PROC_DIR:-<未找到，将跳过>}"

TOTAL=0
FAILED=""
CHECKED=0

for f in $UNITS; do
    [ -f "$f" ] || continue
    CHECKED=$((CHECKED + 1))

    # gcc 13.3.0 在本环境有随机 ICE（RTL / IRA / sched-deps），重试即可。
    # 与构建脚本同样的三级重试，但这里只做语法检查，不涉及链接。
    rc=1
    i=1
    while [ "$i" -le 3 ]; do
        # shellcheck disable=SC2086
        "$CC" $BASE -I"${PROC_DIR:-.}" $DEFS -fsyntax-only "$f" \
            >/dev/null 2>"/tmp/bxroot-warn-$$.txt"
        rc=$?
        grep -q 'internal compiler error' "/tmp/bxroot-warn-$$.txt" || break
        i=$((i + 1))
    done

    if [ "$rc" -ne 0 ] && ! grep -q 'warning:' "/tmp/bxroot-warn-$$.txt" 2>/dev/null; then
        echo "❌ $f —— 编译失败（非告警，是真错误）"
        head -20 "/tmp/bxroot-warn-$$.txt" | sed 's/^/     /'
        FAILED="$FAILED $f"
        TOTAL=$((TOTAL + 1))
        continue
    fi

    n=$(grep -c 'warning:' "/tmp/bxroot-warn-$$.txt" 2>/dev/null)
    n=${n:-0}
    # grep -c 在无匹配时输出 "0" 但退出码非零，用 printf 归一化
    n=$(printf '%s' "$n" | head -1)

    if [ "$n" -gt 0 ]; then
        printf '⚠️  %-34s %s 条告警\n' "$f" "$n"
        TOTAL=$((TOTAL + n))
        FAILED="$FAILED $f"
        if [ "$VERBOSE" = 1 ]; then
            grep -A2 'warning:' "/tmp/bxroot-warn-$$.txt" | sed 's/^/     /'
        fi
    else
        printf '✅ %-34s 0 条\n' "$f"
    fi
done

rm -f "/tmp/bxroot-warn-$$.txt"

echo "---------------------------------------------------------------------"
if [ "$CHECKED" -eq 0 ]; then
    echo "❌ 一个源文件都没检查到 —— 脚本可能跑错了目录"
    exit 2
fi

if [ "$TOTAL" -eq 0 ]; then
    echo "✅ 零告警（检查了 $CHECKED 个编译单元）"
    exit 0
fi

echo "❌ 共 $TOTAL 条告警，涉及:$FAILED"
echo "   加 -v 可看上下文。修掉再提交 —— 这些正是 -w 时代漏掉的那类问题。"
exit 1
