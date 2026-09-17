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
# 对每个编译单元做**真实编译**（`-c -o /dev/null`，与构建同级别 -O1），
# 统计 `warning:` 行数。任何一条都算失败。
#
# ★ 为什么不是 -fsyntax-only ★
# 实测：同一份 launcher.c，-fsyntax-only 报 0 条，-c -O1 报 3 条。
# 后端才产生的告警（-Wformat-truncation / -Wstringop-truncation 等）
# 全部漏掉。本门禁的价值就是"不让告警被静默"，用 -fsyntax-only 等于
# 自己把同一类问题又静默了一遍。详见下方循环里的注释。
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
# 因 ICE 耗尽而**未被检查**的单元（见下方重试循环的注释）。
# 与 FAILED 分开统计：ICE 是环境噪声，不是代码缺陷，不该让门禁变红；
# 但也必须显式报出来，否则就成了新的"静默跳过"。
SKIPPED=""

for f in $UNITS; do
    [ -f "$f" ] || continue
    CHECKED=$((CHECKED + 1))

    # gcc 13.3.0 在本环境有随机 ICE（RTL / IRA / sched-deps），重试即可。
    #
    # ★ 必须真的编译，不能用 -fsyntax-only ★
    #
    # 这是一处**实测出来的漏洞**（红队复核发现）：-fsyntax-only 只跑前端，
    # 任何在后端才产生的告警**全部漏报**。实测同一份 launcher.c：
    #     -fsyntax-only           → 0 条告警   ← 门禁看到的
    #     -c -O1 -o /dev/null     → 3 条告警   ← 真实情况
    # 也就是说本门禁"唯一卖点是拦住告警"，却自己静默了 3 条现存告警。
    # 典型受害者是 -Wformat-truncation / -Wstringop-truncation —— 它们的
    # 数据流分析在后端做，前端根本不报。
    #
    # 同时补上 -O1：gcc 的 -O2 才有的那批告警（如 bridge.c 的
    # -Wstringop-truncation）在 -O0 下不报，而构建脚本实际用 -O2/-O1。
    # 门禁的优化级别必须与真实构建**对齐**，否则策略漂移。
    #
    # ★ 重试次数必须与真实构建一致：都取 10 ★
    #
    # 实测缺陷（2026-09-17，由"回归偶发变红"暴露）：这里原先只重试 **3**
    # 次，而 BUILD_RUNTIME.sh 重试 **10** 次。实测 sigsys.c 的 ICE 发生率：
    #
    #     $ for i in $(seq 1 30); do gcc ... -c -o /dev/null src/runtime/sigsys.c; done
    #     ICE 次数 = 5 / 30        ← 约 17%
    #
    # 3 次重试全部撞上 ICE 的概率约 0.5%，单看很小；但全量回归里这一项
    # 每轮都跑、且经常连跑多轮，累积起来就成了**偶发假红**：
    #
    #     通过 11 / 失败 1   ← 报的是 sigsys.c "编译失败（非告警，是真错误）"
    #     通过 12 / 失败 0   ← 同一条命令重跑就绿
    #
    # 而报错信息会把 ICE 说成"真错误"，把排查方向指向 src/runtime/sigsys.c
    # 的代码 —— 那里其实没有任何问题。**假红比不红更贵**。
    rc=1
    i=1
    ICE=0
    while [ "$i" -le 10 ]; do
        # shellcheck disable=SC2086
        "$CC" $BASE -O1 -I"${PROC_DIR:-.}" $DEFS -c -o /dev/null "$f" \
            >/dev/null 2>"/tmp/bxroot-warn-$$.txt"
        rc=$?
        grep -q 'internal compiler error' "/tmp/bxroot-warn-$$.txt" || break
        ICE=1
        i=$((i + 1))
    done

    if [ "$rc" -ne 0 ] && ! grep -q 'warning:' "/tmp/bxroot-warn-$$.txt" 2>/dev/null; then
        # ★ 区分"ICE 耗尽"与"真错误" ★
        #
        # 两者的处置完全不同：真错误要改代码，ICE 耗尽只说明这次运气差
        # （重跑即可），且**不能算作告警门禁失败** —— 那会把一个环境噪声
        # 报成代码缺陷。但也不能静默放过：ICE 耗尽意味着这个编译单元
        # 这一轮**没被检查到**，必须显式说出来，否则门禁又在"静默跳过"。
        if [ "$ICE" = 1 ]; then
            echo "⚠️  $f —— 10 次重试均遇 gcc ICE（环境问题，非代码缺陷）"
            echo "     该单元本轮**未被检查**。重跑本脚本即可；"
            echo "     若持续复现，说明 ICE 命中率异常高，需单独排查。"
            SKIPPED="$SKIPPED $f"
            continue
        fi
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

# ICE 跳过的单元单独汇报：它不构成失败，但必须让人看见"这一轮漏检了什么"。
# 静默跳过是本项目反复出现的缺陷模式（见 docs/测试基础设施红队报告.md）。
if [ -n "$SKIPPED" ]; then
    echo "⚠️  因 gcc ICE 耗尽而**未被检查**的单元:$SKIPPED"
    echo "    （环境问题，非代码缺陷；重跑本脚本即可。上面已逐个列出原因）"
fi

if [ "$TOTAL" -eq 0 ]; then
    echo "✅ 零告警（检查了 $CHECKED 个编译单元）"
    exit 0
fi

echo "❌ 共 $TOTAL 条告警，涉及:$FAILED"
echo "   加 -v 可看上下文。修掉再提交 —— 这些正是 -w 时代漏掉的那类问题。"
exit 1
