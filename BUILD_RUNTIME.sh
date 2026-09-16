#!/bin/sh
# libbxroot-runtime.so 构建脚本（P0-3 / D4 进程管理层已接入）
#
#   ./BUILD_RUNTIME.sh            构建（-O2 → -O1 → -O0 逐级回退，每级带 ICE 重试）
#   ./BUILD_RUNTIME.sh -O1        指定起始优化等级
#   ./BUILD_RUNTIME.sh clean      只删产物
#
# 为什么需要这个脚本而不是直接敲 gcc：
#
#   1. ★ 本容器 aarch64 gcc 13.3.0 有**间歇性 ICE**（internal compiler
#      error，实测出现在 fakeroot.c:292、l2s.c:520、test_l2s_rt.c:481 等，
#      位置随机、RTL/IRA 阶段段错误）。同一条命令重试几次往往就过，
#      所以下面每级优化都重试若干次。**不因为 ICE 而降低整个项目的
#      优化等级** —— 只有在重试全部失败时才逐级回退。
#   2. 构建到临时文件再 mv：失败时**不会**留下半截 .so 覆盖掉可用的旧产物。
#   3. proc.c（D4 进程管理层）是独立编译单元，需要 -I 到它所在目录。
#
# 关于宏（INTEGRATION.md §1.2，两个宏名字不同、语义不同、可以共存）：
#   -DFAKEROOT_PURE_LOGIC  存在性宏（#ifndef）→ fakeroot 只编纯逻辑
#   -DPX_PURE_LOGIC=0       取值宏（#if !PX_PURE_LOGIC）→ proc.c 编钩子层
# ★ 必须是 `-DPX_PURE_LOGIC=0` 而不是 `-DPX_PURE_LOGIC` ★
#   后者会被当成「已定义但取值为空」→ 钩子层声明被跳过而实现仍编译
#   → 整片 `unknown type name 'px_rtconfig'`。
set -u

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT" || exit 1

# 产物目录：全新克隆时不存在，必须自建 —— 否则链接阶段报
# "cannot open output file .../build/....tmp: No such file or directory"，
# 而且这个错误**不是 ICE**，会直接判定为"真错误"退出，不会重试。
mkdir -p "$ROOT/build" || { echo "❌ 无法创建 build 目录"; exit 1; }

OUT="$ROOT/build/libbxroot-runtime.so"
TMP="$OUT.tmp"
LOG=/tmp/bxroot-runtime-cc.err

# 编译器：默认用 PATH 里的 gcc（本容器是 aarch64 原生 gcc 13.3.0）。
# 允许 CC=<交叉前缀 gcc> 覆盖，与顶层 Makefile 的 CC 变量对齐。
CC="${CC:-gcc}"

# proc.c / proc.h 所在目录（D4 域源）。允许用环境变量覆盖，
# 但默认按仓库布局推导，避免把绝对路径写死进仓库。
# 优先仓库内的 src/proc（自足），其次仓库外的 ../proc（开发期布局）。
PROC_DIR="${BXROOT_PROC_DIR:-}"
if [ -z "$PROC_DIR" ]; then
    if [ -f "$ROOT/src/proc/proc.c" ]; then
        PROC_DIR="$ROOT/src/proc"
    else
        PROC_DIR="$(cd "$ROOT/../proc" 2>/dev/null && pwd)"
    fi
fi

SRC="src/runtime/preload.c \
     src/l2s/l2s.c src/l2s/l2s-runtime.c \
     src/runtime/fakeroot.c src/runtime/crash.c src/runtime/sigsys.c \
     src/runtime/syscall_guard.c src/runtime/livepatch.c"

# 警告策略：原先的 -w 会把**全部**警告静默掉 —— 包括 -Wformat=2。
# 真实教训：launcher.c 里一处 fprintf 少传两个实参（栈上取垃圾指针），
# 就是被 -w 掩盖的（现已修）。这里改为精确开启，只压掉确认无意义的类别。
#   -Wnonnull-compare：我们对所有防御性判空都会触发，属误报（函数声明带
#     __nonnull，gcc 认为判空是死代码，但这些判空正是防上层乱传 NULL 的）。
#   -Wunused-parameter：大量 hook 签名必须与 libc 原型逐字一致，用不到也得留。
#   -D_GNU_SOURCE=（空定义）：部分编译单元（l2s.c / proc.c / fakeroot.c）
#     依赖命令行提供该宏，而另一些（preload.c / sigsys.c / …）在文件头
#     自行 #define，两边一撞就是 "redefined" 告警。写成空定义后，
#     需要它的文件照样拿到特性，自备定义的文件也不再报重复。
WARN="-Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter"
CFLAGS="-shared -fPIC $WARN -D_GNU_SOURCE="
INCS="-Isrc/l2s -Isrc/runtime"
DEFS="-DFAKEROOT_PURE_LOGIC -DPX_PURE_LOGIC=0"
LDFLAGS="-ldl -nostartfiles"

case "${1:-}" in
clean)
    rm -f "$OUT" "$TMP"
    echo "已删除 $OUT"
    exit 0
    ;;
esac

START_OPT="${1:--O2}"

# ------------------------------------------------------------------
# 前置检查
# ------------------------------------------------------------------
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "❌ 找不到编译器 $CC"; exit 1
fi
if [ -z "$PROC_DIR" ] || [ ! -f "$PROC_DIR/proc.c" ]; then
    echo "❌ 找不到 proc.c（D4 进程管理层的编译单元）"
    echo "   期望位置：$ROOT/../proc/proc.c"
    echo "   可用 BXROOT_PROC_DIR=<dir> 显式指定"
    exit 1
fi
for f in src/runtime/preload.c src/runtime/syscall_guard.c src/runtime/sigsys.c; do
    if [ ! -f "$f" ]; then
        echo "❌ 缺少源文件 $f"; exit 1
    fi
done
echo "== 构建 libbxroot-runtime.so =="
echo "   编译器     : $CC ($("$CC" -dumpversion))"
echo "   proc.c     : $PROC_DIR/proc.c"
echo "   起始优化   : $START_OPT"

# ------------------------------------------------------------------
# 单次尝试。成功返回 0（产物已在 $TMP）。
# ------------------------------------------------------------------
attempt() {
    opt="$1"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS $opt $INCS -I"$PROC_DIR" $DEFS \
        -o "$TMP" $SRC "$PROC_DIR/proc.c" $LDFLAGS 2>"$LOG"
}

# 逐级优化；每级最多 10 次（ICE 是随机的，重试即可）
tier() {
    opt="$1"
    i=1
    while [ "$i" -le 10 ]; do
        if attempt "$opt"; then
            echo "   ✅ 链接成功（$opt，第 $i 次尝试）"
            return 0
        fi
        if ! grep -q 'internal compiler error' "$LOG"; then
            echo "   ❌ $opt 编译失败（非 ICE，是真错误）"
            echo "--- 编译器输出 ---"
            cat "$LOG"
            return 1
        fi
        echo "   gcc ICE（$opt 第 $i 次），重试"
        i=$((i + 1))
    done
    echo "   ⚠️  $opt 连续 10 次 ICE，回退下一级优化"
    return 2
}

RC=0
case "$START_OPT" in
-O0) LEVELS="-O0" ;;
-O1) LEVELS="-O1 -O0" ;;
*)   LEVELS="-O2 -O1 -O0" ;;
esac

for opt in $LEVELS; do
    tier "$opt"
    RC=$?
    case "$RC" in
    0) break ;;
    1) rm -f "$TMP"; exit 1 ;;    # 真错误，不回退
    *) continue ;;                # 持续 ICE → 试下一级
    esac
done

if [ "$RC" -ne 0 ]; then
    echo "❌ 所有优化等级都因 ICE 失败（-O2/-O1/-O0 各 10 次）"
    echo "   这是已知的编译器问题，请稍后重跑；旧产物未被破坏。"
    rm -f "$TMP"
    exit 1
fi

mv -f "$TMP" "$OUT" || { echo "❌ mv 失败"; exit 1; }

# ------------------------------------------------------------------
# 交付检查：产物存在 + D4 的 19 个符号已导出
# ------------------------------------------------------------------
SIZE=$(wc -c < "$OUT")
NSYM=$(nm -D --defined-only "$OUT" 2>/dev/null | wc -l)
echo "   产物: $OUT"
echo "   大小: $SIZE 字节"
echo "   导出符号（nm -D --defined-only）: $NSYM"

# D4 的进程管理符号必须在**动态符号表**里。
#
# ★ 为什么这一条必须让构建失败（而不是打个 ⚠️ 就走）★
#
# 这处是回归第 9 项唯一的实质内容，而它此前**永远不会让构建变红**：
# `MISSING` 非空时只打印一行 ⚠️ 然后 `exit 0`。实测（红队复核）：往清单里
# 塞一个不存在的符号 `THIS_SYMBOL_DOES_NOT_EXIST_ZZZ`，得到
#     ⚠️  未导出的 D4 符号: THIS_SYMBOL_DOES_NOT_EXIST_ZZZ
# 而退出码是 **0**。
#
# 后果不是"少个功能"而是**静默失效**：LD_PRELOAD 靠动态符号表插入，符号
# 漏导出意味着那个钩子根本没被装上，而进程照样能跑 —— 容器在那条路径上
# 悄悄失去翻译/fakeroot/进程管理能力，现象离原因极远。
# 这正是本文档自己点名"只有构建期检查能拦住"的那类缺陷，所以这里必须
# 硬失败。
#
# 顺带修正一处**文档错误**：注释原写"19 个符号"，实际清单是 23 个。
# 用下面的计数自动核对，避免以后再漂移。
D4="fork vfork posix_spawn posix_spawnp kill killpg tgkill tkill system popen \
    execve execv execvp execvpe execl execlp execle execveat fexecve \
    waitpid wait4 wait3 waitid"
D4_N=0
for s in $D4; do D4_N=$((D4_N + 1)); done

MISSING=""
for s in $D4; do
    if ! nm -D --defined-only "$OUT" 2>/dev/null | awk '{print $3}' | grep -qx "$s"; then
        MISSING="$MISSING $s"
    fi
done
if [ -n "$MISSING" ]; then
    echo "   ❌ 未导出的 D4 符号:$MISSING"
    echo "      （共核对 $D4_N 个；漏导出 = 对应钩子静默失效，容器照样能启动，"
    echo "        只是那条路径上不再有翻译/fakeroot/进程管理）"
    echo "      构建按失败处理。"
    exit 1
fi
echo "   ✅ D4 进程管理符号全部导出（$D4_N/$D4_N，含 waitpid/wait4/wait3/waitid）"
exit 0
