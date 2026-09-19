#!/bin/sh
# =====================================================================
# 上游 proot CLI 选项覆盖对照（bxroot vs 上游选项表）
# =====================================================================
#
# 由来
# ----
# "proot 兼容"这件事不能靠印象，必须以**上游源码的选项表**为准。
# 本脚本从上游 `src/cli/proot.h` 提取全部选项名，与 bxroot launcher 的
# 识别分支逐一对照，把差异钉成可复现的判据。
#
# ★ 为什么判据是「从源码提取」而不是「读 --help 文本」★
# 上游的 `--help` 输出是给人看的，选项名与 handler 的对应关系在
# `proot_cli.options[]` 结构体里 —— 一个 arguments[] 组里的多个名字
# **共用同一个 handler**（例如 `-b` / `--bind` / `-m` / `--mount`）。
# 只读 --help 会漏掉别名（`-l` 就是这么被漏掉的）。
#
# 三个判据类别
# ------------
#   ✅ 已支持   —— bxroot 有对应识别分支
#   🚫 明确拒绝 —— bxroot 无此能力，但**必须报错**，不得静默忽略
#   ❌ 缺失     —— 上游有、bxroot 既不支持也不拒绝（静默吞掉/当命令）
#
# ★ 为什么"缺失"是最坏的一类 ★
# 静默吞掉比报错更糟：用户以为选项生效了，实际没有，错误现象出现在
# 很远的地方（典型：`-l` 没生效 → tar 解包 EPERM）。所以缺失类必须为 0。
#
# 用法
# ----
#   sh test/RUN_UPSTREAM_CLI.sh                  # 用内置的上游选项清单
#   UPSTREAM_PROOT_H=/path/proot.h sh test/RUN_UPSTREAM_CLI.sh   # 用真实源码
#
# 退出码
# ------
#   0 = 无缺失且所有拒绝类都确实报错     1 = 有回归
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 1; }

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-upcli-XXXXXX" 2>/dev/null) || {
    WORK="$ROOT/.tmp-upcli"; mkdir -p "$WORK"
}
LAUNCHER="$WORK/libbxroot-cli"

# 静态链接（与 Android 上的实际形态一致）；带 ICE 重试，因为本容器
# 的 gcc 13.3.0 有间歇性 internal compiler error。
i=1
while [ "$i" -le 10 ]; do
    if "$CC" -static -O1 -Wall -Wextra -Wno-nonnull-compare \
        -o "$LAUNCHER" src/launcher/launcher.c 2>"$WORK/cc.err"; then
        break
    fi
    if ! grep -q 'internal compiler error' "$WORK/cc.err"; then
        echo "❌ launcher 编译失败（非 ICE）:"; cat "$WORK/cc.err"; exit 2
    fi
    i=$((i + 1))
done
[ -x "$LAUNCHER" ] || { echo "❌ launcher 编译 10 次均撞 ICE"; exit 2; }

# ---------------------------------------------------------------------
# ★ 前置能力自检：launcher 必须**真的能干活** ★
#
# 踩过的坑（2026-09-19 发现，红队审计）：本脚本对"支持类"选项的判据是
# **否定式**的 —— 只看输出里**没有**"未知选项/unknown option/unrecognized"
# 这几个词就算"已识别"。于是任何**什么都没实现**的 launcher 都能满分：
#
#     $ cat > launcher.c <<'EOF'
#     #include <stdio.h>
#     int main(int argc,char**argv){ printf("错误: 未实现\n"); return 1; }
#     EOF
#     $ sh test/RUN_UPSTREAM_CLI.sh
#     通过 35 / 失败 0   RESULT: PASS      ← 一个上游选项都不支持
#
# 也就是说这个测试**没有判别力覆盖它自称要防的东西**（"选择项被静默
# 忽略/退化"）。归因要精确：它能抓住"漏掉某个选项的别名"这类**局部**
# 回归（实测删掉 `-l` 别名可得 34/35 FAIL），抓不住的是"识别层整体失效"。
#
# 修法：在逐选项对照之前，先做一次**正向**能力断言 —— launcher 必须能
# 用上游语法真跑通一条最简单的命令。不满足就直接判失败（而不是让后面
# 的否定式判据把它读成"全部已识别"）。
# ---------------------------------------------------------------------
CANARY="$("$LAUNCHER" -r / -w / /bin/true 2>&1)"
CANARY_RC=$?
case "$CANARY" in
    *未知选项*|*unknown\ option*|*unrecognized*|*未实现*|*错误*|*Error*|*error*)
        echo "❌ 前置能力自检失败：launcher 连最基本的调用都跑不通"
        echo "   命令: $LAUNCHER -r / -w / /bin/true"
        echo "   输出: $(printf '%s' "$CANARY" | head -2)"
        echo "   → 后续的否定式判据（'输出里没有未知选项'）会把它读成满分，"
        echo "     所以这里必须先行拦下。"
        exit 1 ;;
esac
if [ "$CANARY_RC" -ne 0 ]; then
    echo "❌ 前置能力自检失败：launcher -r / -w / /bin/true 退出码 $CANARY_RC"
    echo "   输出: $(printf '%s' "$CANARY" | head -2)"
    echo "   → 同上：否定式判据无法发现'整体不可用'。"
    exit 1
fi
echo "✔ 前置能力自检：launcher 可正常执行（-r / -w / /bin/true → rc=0）"
echo

# ---------------------------------------------------------------------
# 上游选项清单
# ---------------------------------------------------------------------
# 有真实源码就用它提取（最权威）；没有就用内置清单（从上游源码抄录，
# 含 21 组选项共 36 个名字）。
UPSTREAM_LIST="$WORK/upstream-opts.txt"
if [ -n "${UPSTREAM_PROOT_H:-}" ] && [ -f "$UPSTREAM_PROOT_H" ]; then
    grep -oE '\.name = "[^"]+"' "$UPSTREAM_PROOT_H" \
        | sed 's/.*= "//;s/"//' | sort -u > "$UPSTREAM_LIST"
    echo "（选项清单来源：$UPSTREAM_PROOT_H）"
else
    cat > "$UPSTREAM_LIST" <<'OPTS'
--about
--ashmem-memfd
--bind
--change-id
--cwd
--help
--kernel-release
--kill-on-exit
--link2symlink
--mount
--pwd
--qemu
--root-id
--rootfs
--sysvipc
--usage
--verbose
--version
-0
-H
-L
-R
-S
-V
-b
-h
-i
-k
-l
-m
-p
-q
-r
-v
-w
OPTS
    echo "（选项清单来源：内置抄录表）"
fi

N_UP=$(wc -l < "$UPSTREAM_LIST" | tr -d ' ')
echo "上游选项数：$N_UP"
echo

PASS=0
FAIL=0
FAILED_LIST=""

ok()  { PASS=$((PASS + 1)); printf '  ✅ %-20s %s\n' "$1" "$2"; }
bad() { FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $1"
        printf '  ❌ %-20s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------
# 明确拒绝清单：这些选项 bxroot 不支持，**必须**报错
# ---------------------------------------------------------------------
# 判据是"输出里含拒绝语"，不是"退出码非 0" —— 因为 `-h` 也退出 0，
# 而帮助文本里含"未实现"字样（曾经的误判来源）。
REJECT_LIST="-H -p -q --qemu --sysvipc --ashmem-memfd"

is_reject() {
    case " $REJECT_LIST " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# 需要参数的选项（探测时要补一个占位参数，否则报"缺参数"而非"拒绝"）
needs_arg() {
    case "$1" in
        -q|--qemu|--sysvipc|--ashmem-memfd|-H|-p) return 1 ;;  # 无参数
        *) return 0 ;;
    esac
}

echo "== 逐选项对照 =="
MISSING=""
while IFS= read -r opt; do
    [ -n "$opt" ] || continue
    if is_reject "$opt"; then
        # 拒绝类：必须报"未实现/错误"，且绝不能静默成功
        OUT=$("$LAUNCHER" "$opt" /bin/true 2>&1)
        RC=$?
        case "$OUT" in
            *未实现*|*错误*|*Error*|*error*)
                ok "$opt" "明确拒绝（rc=$RC）" ;;
            *)
                bad "$opt" "应拒绝但输出无拒绝语: $(echo "$OUT" | head -1)" ;;
        esac
        continue
    fi

    # 支持类：跑一次，检查是否落进"未知选项"分支
    if needs_arg "$opt"; then
        OUT=$("$LAUNCHER" "$opt" /nonexistent-probe /bin/true 2>&1)
    else
        OUT=$("$LAUNCHER" "$opt" /bin/true 2>&1)
    fi
    case "$OUT" in
        *未知选项*|*unknown\ option*|*unrecognized*)
            MISSING="$MISSING $opt"
            bad "$opt" "未识别（应支持或明确拒绝）" ;;
        *)
            ok "$opt" "已识别" ;;
    esac
done < "$UPSTREAM_LIST"

echo
echo "== 覆盖统计 =="
echo "  上游选项        : $N_UP"
echo "  通过            : $PASS"
echo "  失败            : $FAIL"
[ -n "$MISSING" ] && echo "  静默缺失项      :$MISSING"

echo
echo "通过 $PASS / 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "失败项:$FAILED_LIST"
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
exit 0
