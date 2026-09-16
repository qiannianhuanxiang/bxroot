#!/bin/sh
# =====================================================================
# proot CLI 兼容性回归
# =====================================================================
#
# 由来
# ----
# bxroot 加了一层 proot CLI 兼容（见 `docs/proot-CLI兼容性报告.md`），
# 目标是「proot 能接受的命令行，bxroot 也要能接受」。这类东西**最容易
# 悄悄退化** —— 别人重构参数解析时顺手删掉一个不常用的别名，没有任何
# 测试会红，直到某个用户的启动脚本突然跑不起来。
#
# 所以本测试把「每个 proot 选项的处理方式」逐条钉住。
#
# 判据分三类（这个分法本身是设计决定，见报告）
# ------------------
#   ✅ 已支持     —— 选项被识别。测试判据：**不是**「报未知选项/未实现」
#   🚫 明确拒绝   —— 本实现没有该能力，但**必须报错**，不能静默忽略
#   ❌ 静默忽略   —— 不允许出现（用户以为生效了，实际没有）
#
# ★ 为什么判据是"看输出内容"而不是"看退出码" ★
# 踩过的坑：退出码无法区分三种情况 ——
#   - `-h`（打印帮助）退出码 0，而帮助文本里含"未实现"字样
#   - `-r /nonexistent /bin/true` 退出码 1，但选项本身完全正常
# 第一版用退出码判据，把 `-h` 误判成"明确拒绝"、把正常选项误判成失败。
# 现在改为看**首行**是否匹配拒绝语。
#
# 用法
# ----
#   sh test/RUN_CLI_COMPAT.sh
#
# 退出码
# ------
#   0 = 全部符合预期     1 = 有回归
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 1; }

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

# 编译到临时目录（不用 /tmp 固定名 —— 本容器 /tmp 出过权限问题）
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-cli-XXXXXX" 2>/dev/null) || {
    WORK="$ROOT/.tmp-cli"; mkdir -p "$WORK"
}
LAUNCHER="$WORK/libbxroot-cli"

# 静态链接：launcher 在 Android 上是静态二进制（见 Makefile 的 -static）
i=1
while [ "$i" -le 6 ]; do
    if "$CC" -static -O1 -Wall -Wextra -Wformat=2 \
        -Wno-nonnull-compare -Wno-unused-parameter \
        -o "$LAUNCHER" src/launcher/launcher.c 2>"$WORK/cc.err"; then
        break
    fi
    grep -q 'internal compiler error' "$WORK/cc.err" || {
        echo "❌ launcher.c 编译失败（非 ICE）"
        head -15 "$WORK/cc.err"
        exit 1
    }
    i=$((i + 1))
done
[ -x "$LAUNCHER" ] || { echo "❌ 编译未产出可执行文件"; exit 1; }

PASS=0
FAIL=0
FAILED_LIST=""

ok()  { PASS=$((PASS + 1)); printf '  ✅ %-26s %s\n' "$1" "$2"; }
bad() { FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $1"
        printf '  ❌ %-26s %s\n' "$1" "$2"; }

# 判断一次调用的结果分类。
# 用法: classify <选项标签> <参数...>
# 输出: supported / refused / silent（silent = 静默忽略，不允许）/ error
classify() {
    label="$1"; shift
    timeout 10 "$LAUNCHER" "$@" >"$WORK/out.txt" 2>&1
    first=$(head -1 "$WORK/out.txt")

    # 「明确拒绝」的判据：首行是拒绝语。
    #
    # ★ 这里踩过一次：判据最初只匹配"未实现"/"未知选项"，而
    # `-i 1000:1000` 的拒绝信息写的是「只支持 "0:0"」—— 用词不同，
    # 于是**正确的拒绝被误报成"静默接受"**。
    #
    # 教训：判据不能依赖某几个具体措辞。改为匹配所有以"错误:"开头的
    # 首行（本 launcher 的拒绝路径统一用这个前缀），再排除那些
    # "选项没错、只是缺 rootfs/参数"的情况。
    # 缺 rootfs 的错误信息里带"找不到命令"/"需要"等，单独放行。
    case "$first" in
        *未实现*|*未知选项*) echo refused; return ;;
    esac
    case "$first" in
        错误:*)
            # 排除"选项本身没错、只是环境不满足"的两类
            case "$first" in
                *找不到命令*|*需要*参数*|*rootfs*) echo supported; return ;;
            esac
            echo refused; return
            ;;
    esac

    # 其余一律视为"已支持"（后续可能因缺 rootfs / 参数而失败，那是预期的）
    echo supported
}

echo "== proot CLI 兼容性回归 =="
echo

# ---------------------------------------------------------------------
# A. 信息类：应"已支持"且退出码 0
# ---------------------------------------------------------------------
echo "--- A) 信息类 ---"
for opt in -h --help -V --version --about --usage; do
    if timeout 10 "$LAUNCHER" "$opt" >"$WORK/o" 2>&1; then
        ok "$opt" "rc=0"
    else
        bad "$opt" "应 rc=0"
    fi
done

# ---------------------------------------------------------------------
# B. 基本选项：应"已支持"（不报未知/未实现）
# ---------------------------------------------------------------------
echo
echo "--- B) 基本选项与长名别名 ---"
# 需要值的选项给一个占位值
for spec in \
    "-r:/tmp" "--rootfs:/tmp" \
    "-w:/tmp" "--cwd:/tmp" "--pwd:/tmp" \
    "-b:/tmp:/tmp" "--bind:/tmp:/tmp" \
    "-m:/tmp:/tmp" "--mount:/tmp:/tmp" \
    "-0:" "--root-id:" \
    "-k:6.1.0" "--kernel-release:6.1.0" \
    "-i:0:0" "--change-id:0:0"
do
    opt=${spec%%:*}; val=${spec#*:}
    if [ -n "$val" ]; then
        cls=$(classify "$opt" "$opt" "$val" /bin/true)
    else
        cls=$(classify "$opt" "$opt" /bin/true)
    fi
    [ "$cls" = "supported" ] && ok "$opt" "已支持" || bad "$opt" "被当成未实现/未知"
done

# 无值选项
for opt in --link2symlink --kill-on-exit -v --verbose; do
    cls=$(classify "$opt" -r /tmp "$opt" /bin/true)
    [ "$cls" = "supported" ] && ok "$opt" "已支持" || bad "$opt" "被当成未实现/未知"
done

# ---------------------------------------------------------------------
# C. 明确拒绝：**必须**报错，不能静默
# ---------------------------------------------------------------------
echo
echo "--- C) 明确拒绝（不可静默忽略）---"
for opt in -H -L -p --sysvipc --ashmem-memfd; do
    cls=$(classify "$opt" -r /tmp "$opt" /bin/true)
    if [ "$cls" = "refused" ]; then
        ok "$opt" "明确拒绝"
    else
        bad "$opt" "★ 未报错 —— 静默忽略，用户会以为生效了"
    fi
done
# -q / --qemu 需要参数
for opt in -q --qemu; do
    cls=$(classify "$opt" -r /tmp "$opt" /bin/true /bin/true)
    [ "$cls" = "refused" ] && ok "$opt" "明确拒绝" || bad "$opt" "★ 未报错"
done

# ---------------------------------------------------------------------
# D. -i 的取值边界：只有 0:0 被接受
# ---------------------------------------------------------------------
echo
echo "--- D) -i/--change-id 取值 ---"
cls=$(classify "-i 0:0" -r /tmp -i 0:0 /bin/true)
[ "$cls" = "supported" ] && ok "-i 0:0" "已支持" || bad "-i 0:0" "被拒绝"
cls=$(classify "-i 1000:1000" -r /tmp -i 1000:1000 /bin/true)
[ "$cls" = "refused" ] && ok "-i 1000:1000" "明确拒绝" \
                       || bad "-i 1000:1000" "★ 静默接受了不支持的映射"

# ---------------------------------------------------------------------
# E. 未知选项：必须报"未知选项"，不能当 guest 命令
# ---------------------------------------------------------------------
echo
echo "--- E) 未知选项 ---"
timeout 10 "$LAUNCHER" --definitely-not-an-option >"$WORK/o" 2>&1
if grep -q '未知选项' "$WORK/o"; then
    ok "--未知选项" "报未知选项"
else
    bad "--未知选项" "★ 未报未知选项（会被当 guest 命令，错误信息误导）"
fi

# ---------------------------------------------------------------------
# F. 别名组合 -R / -S：应被识别
# ---------------------------------------------------------------------
echo
echo "--- F) 别名组合 ---"
for opt in -R -S; do
    cls=$(classify "$opt" "$opt" /tmp /bin/true)
    [ "$cls" = "supported" ] && ok "$opt <path>" "已支持" || bad "$opt <path>" "被当成未实现"
done

# ---------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------
rm -rf "$WORK"

echo
echo "----------------------------------------"
echo "通过 $PASS / 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "失败项:$FAILED_LIST"
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
exit 0
