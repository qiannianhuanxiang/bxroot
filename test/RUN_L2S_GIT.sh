#!/bin/sh
# ---------------------------------------------------------------------
# l2s × 真实 git：三种 BXROOT_L2S_DIR 入口形态（行动清单 #2）
#
# 【为什么要有】本容器 /tmp 是 tmpfs，**真硬链接可用** —— 不强制 l2s，
# git 根本不走它，验收会"假绿"（2026-09-25 首轮就这样全绿了）。所以：
#   · 一律 BXROOT_LINK2SYMLINK=1 强制启用；
#   · 每种形态都**先证明 l2s 真的生效**（外层 readlink 能看到 .l2s 链），
#     证明不了就判 FAIL，而不是当作通过。
#
# 【三种形态与各自曾经的缺陷】
#   A. 未设（--no-l2s-default）：runtime 自己决定布局。
#      缺陷：未设 → 散落布局 → .git/objects 下残留 27 个 .l2s.*，
#      git fsck 报 bad sha1 file、git clone 本地失败。
#      （link() 失败自动启用、读路径懒启用都不经 launcher 的默认值）
#   B. 显式容器视角路径（/tmp/…）：
#      缺陷：翻译结果存在栈上，g_cfg.l2s_dir 悬垂 → 读到垃圾 → 当作未设
#      → **静默**退化成散落布局，集中目录里 0 个文件。
#   C. 宿主视角默认（bxroot-run 兜底 <rootfs>/.l2s）：一直正常，作对照。
# 判据：git_acceptance.sh 全部 ok；客户目录树内 0 个 .l2s.*；
#       客户文件的外层 readlink 指向集中目录（证明走了 l2s 且是集中布局）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
ACC="$ROOT/test/l2s/git_acceptance.sh"

[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime"; exit 2; }
command -v git >/dev/null 2>&1 || { echo "⏭️  跳过：没有 git"; exit 2; }
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：bxroot-run 需要外层 proroot 注入链路"; exit 2; }

FAIL=0
run_case() {
    name=$1; wd=$2; expect_dir=$3; shift 3
    rm -rf "$wd" "$wd-clone"
    out=$(env BXROOT_LINK2SYMLINK=1 "$@" timeout 600 "$BX" ${NO_DEF:-} -- /bin/sh "$ACC" "$wd" 2>&1)
    rc=$?
    bad=$(printf '%s\n' "$out" | grep '^FAIL' | head -3)
    resid=$(find "$wd" -name '.l2s.*' 2>/dev/null | wc -l)
    tgt=$(readlink "$wd/h/f" 2>/dev/null)
    case "$tgt" in
        "$expect_dir"/.l2s.*) where=ok ;;
        "")                   where="未走 l2s（h/f 不是链接）" ;;
        *)                    where="链接指向 $tgt（期望 $expect_dir/.l2s.*）" ;;
    esac
    if [ $rc = 0 ] && [ -z "$bad" ] && [ "$resid" = 0 ] && [ "$where" = ok ]; then
        echo "  ✅ $name：git 全流程通过，客户树 0 残留，集中布局生效"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ $name：rc=$rc 残留=$resid 布局=$where"
        [ -n "$bad" ] && printf '%s\n' "$bad" | sed 's/^/       /' | cut -c1-140
    fi
    rm -rf "$wd" "$wd-clone"
}

HOSTROOT=${PROROOT_ROOTFS:-}
echo "--- A) 未设 BXROOT_L2S_DIR（runtime 默认）---"
NO_DEF=--no-l2s-default run_case "未设" /tmp/l2sgit-a "/.l2s"
echo "--- B) 显式容器视角 /tmp/l2sgit-dir ---"
rm -rf /tmp/l2sgit-dir
run_case "容器视角路径" /tmp/l2sgit-b "/tmp/l2sgit-dir" BXROOT_L2S_DIR=/tmp/l2sgit-dir
n=$(ls -A /tmp/l2sgit-dir 2>/dev/null | wc -l)
echo "     （集中目录 /tmp/l2sgit-dir 条目数 $n）"
rm -rf /tmp/l2sgit-dir
echo "--- C) bxroot-run 默认 <rootfs>/.l2s（对照）---"
run_case "宿主视角默认" /tmp/l2sgit-c "/.l2s"

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
