#!/bin/sh
# =====================================================================
# 裸 syscall 层身份伪装 —— 契约测试运行器
# =====================================================================
#
# 防的是什么
# ----------
# fakeroot 此前只在 **libc 符号层**伪装身份（preload.c 的 getuid/geteuid/
# getgid/getegid 钩子），而 `syscall_guard.c` 的 `syscall()` 接管层只做了
# 路径翻译与 statx 结果补丁。于是绕过 libc 直接 `syscall(174)` 的程序
# （静态链接的 Go/Rust、libuv、以及大量"我是不是 root"的自检代码）看到
# **真实 uid**，与官方不一致，并因此走错分支。
#
#     官方 : libc getuid=0   syscall(174)=0
#     bxroot(修前): libc getuid=0   syscall(174)=10655
#
# 为什么必须与 syscall_guard.c 一起编译
# ------------------------------------
# 被测对象就是那个文件里的 `syscall()` 接管层。本测试自带两个**强定义桩**：
#   - `bxroot_translate_path`  —— 路径翻译（断言它仍照常工作）
#   - `bxroot_fakeroot_ids`    —— 身份查询（guard 里是 weak 声明）
# 桩返回的是真值**绝不可能取到**的伪造值（12345/54321），所以
# "fakeroot 开 → 必须等于伪造值"这条判据在**任何环境**下都有判别力 ——
# 包括本容器这种"外层 proroot 已经把裸 svc 的 getuid 改写成 0"的环境。
# 若判据写成 `== 0`，改之前就会是绿的，等于没测（本项目记录过的事故类型）。
#
# 为什么是独立脚本而不是塞进 RUN_ALL.sh 的编译行
# ---------------------------------------------
# RUN_ALL.sh 里加一行就够，但把编译参数写在两处必然漂移（本项目在
# 门禁与构建脚本的警告集上已经为此加过一致性自检）。这里做成独立脚本，
# RUN_ALL.sh 只 `sh` 它一行，参数只有一份。
#
# 用法
# ----
#   sh test/RUN_ID_SYSCALL.sh
#
# 退出码
# ------
#   0 = 契约成立   1 = 契约被破坏   2 = 环境问题（编译失败）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

for f in test/test_id_syscall_guard.c src/runtime/syscall_guard.c; do
    [ -f "$f" ] || { echo "❌ 缺少 $f"; exit 2; }
done

# 工作目录：优先 build/，退到私有目录（/tmp 会间歇被 chmod 000）
if [ -d build ] && [ -w build ]; then
    BIN=build/test_id_syscall_guard
else
    BIN="${TMPDIR:-/tmp}/bxroot-id-guard-$$"
fi

# ---------------------------------------------------------------------
# 编译。与 RUN_ALL.sh 里同类测试项**完全相同的参数集**
#
# -D_GNU_SOURCE= （空定义）而不是 -D_GNU_SOURCE：与本仓库既有约定一致，
# 自备 #define 的文件不会报"重定义"。
#
# ★ 必须带 gcc ICE 重试 ★
#
# 本脚本此前是**唯一没有 ICE 重试的 runner**，而 gcc 13.3.0 在本容器有
# 间歇性 ICE（实测本文件 40 次编译撞 2 次 ≈ 5%，`during GIMPLE pass:
# alias` 段错误）。没有重试的后果不是"偶尔变红"，而是**该项被静默跳过**：
# 编译失败走 exit 2，RUN_ALL 按约定把 rc=2 记成"环境不满足"⏭️ ——
# 看起来一切正常，实际这条契约那一轮没跑。实测确实发生过
# （一次全量回归里 `身份 syscall 伪装` 显示 ⏭️ rc=2）。
#
# 重试次数与优化级回退策略与其余 runner 对齐（见 RUN_SIGSYS_NUM.sh /
# RUN_RAW_SYSCALL.sh）。**不因为 ICE 就整体降优化级** —— 那是本项目的
# 既定立场（BUILD_RUNTIME.sh 头注）：重试即可，只在全部重试失败时才回退。
# ---------------------------------------------------------------------
CC_OK=0
OPT="-O2"
i=1
while [ "$i" -le 10 ]; do
    if "$CC" -std=c11 $OPT -Wall -Wextra \
            -D_GNU_SOURCE= -Isrc/runtime \
            test/test_id_syscall_guard.c src/runtime/syscall_guard.c \
            -o "$BIN" 2>"${TMPDIR:-/tmp}/id-guard-cc.$$.err"; then
        CC_OK=1
        break
    fi
    if grep -q 'internal compiler error' "${TMPDIR:-/tmp}/id-guard-cc.$$.err" 2>/dev/null; then
        # 撞 ICE：先重试同级别，仍不行再逐级降
        if [ "$i" -ge 4 ] && [ "$OPT" = "-O2" ]; then OPT="-O1"; fi
        if [ "$i" -ge 7 ] && [ "$OPT" = "-O1" ]; then OPT="-O0"; fi
        i=$((i + 1))
        continue
    fi
    break                      # 非 ICE = 真错误，立刻停
done

if [ "$CC_OK" -ne 1 ]; then
    echo "❌ 编译失败："
    cat "${TMPDIR:-/tmp}/id-guard-cc.$$.err"
    rm -f "${TMPDIR:-/tmp}/id-guard-cc.$$.err"
    exit 2
fi
rm -f "${TMPDIR:-/tmp}/id-guard-cc.$$.err"

"$BIN"
rc=$?
[ "$BIN" = "build/test_id_syscall_guard" ] || rm -f "$BIN"
exit $rc
