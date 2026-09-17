#!/bin/sh
# =====================================================================
# 安全推送：推完核对 hash，不一致就报警
# =====================================================================
#
# 由来
# ----
# 本项目发生过一次**远端被旧 clone 强制覆盖**的事件（见
# `docs/事件-远端被旧clone覆盖.md`）。最危险的特性是：
#
#   ★ `git push --force` 报成功，但推上去的不是我的东西 ★
#
# `--force` 的语义是"用我这条谱系无条件替换远端"，所以另一个停留在
# 旧状态的 clone 一推，就把远端整体换回去了。而推送输出里照样写着
# `forced update`、退出码照样是 0。
#
# 只看"推送成功"这一个信号，这类事故永远发现不了。
# 本脚本把两个必需动作固化下来：
#
#   1. 推之前：远端当前 HEAD 必须是本地 HEAD 的祖先
#      （不是祖先 → 远端有我没见过的提交 → 停，先看清楚）
#   2. 推之后：远端 HEAD 必须 == 本地 HEAD
#      （不等 → 推的不是我的东西 → 报错退出）
#
# 用法
# ----
#   sh tools/push-verified.sh [远程名] [分支]
#   缺省：origin main
#
# 退出码
# ------
#   0 = 推送完成且核对通过    1 = 前置检查失败或核对不一致
# =====================================================================

set -u

REMOTE="${1:-origin}"
BRANCH="${2:-main}"

die() { echo "❌ $*" >&2; exit 1; }

LOCAL=$(git rev-parse HEAD) || die "取不到本地 HEAD"
[ -n "$LOCAL" ] || die "本地 HEAD 为空"

echo "本地 HEAD : $LOCAL  ($(git log -1 --format=%s | cut -c1-50))"
echo "目标      : $REMOTE/$BRANCH"
echo

# ---- 前置检查：远端 HEAD 是不是本地 HEAD 的祖先 ----
echo "== 前置检查：远端与我方的关系 =="
git fetch "$REMOTE" "$BRANCH" >/dev/null 2>&1 || die "fetch 失败（网络/凭证？）"

if git rev-parse --verify --quiet "refs/remotes/$REMOTE/$BRANCH" >/dev/null; then
    REMOTE_HEAD=$(git rev-parse "refs/remotes/$REMOTE/$BRANCH")
    echo "远端 HEAD : $REMOTE_HEAD"

    if [ "$REMOTE_HEAD" = "$LOCAL" ]; then
        echo "  ℹ️  远端与本地已一致，无需推送"
        exit 0
    fi

    if git merge-base --is-ancestor "$REMOTE_HEAD" "$LOCAL"; then
        echo "  ✅ 远端是本地祖先 —— 本次推送是纯前进"
    else
        echo "  ⚠️  远端**不是**本地祖先 —— 远端有本地没有的提交"
        echo
        echo "  远端独有（本地缺失）的提交："
        git log --oneline "$LOCAL..$REMOTE_HEAD" 2>/dev/null | head -20 | sed 's/^/     /'
        echo
        echo "  ★ 先看清楚这些提交是什么再决定 ★"
        echo "    如果它们确实该被覆盖，用 --force 并（强烈建议）先"
        echo "    把远端固化到一个 rescue 分支："
        echo "      git branch -f rescue-\$(date +%s) $REMOTE_HEAD"
        die "前置检查未通过：远端有本地没有的提交"
    fi
else
    echo "  ℹ️  远端分支不存在，将新建"
fi
echo

# ---- 推送 ----
echo "== 推送 =="
git push "$REMOTE" "HEAD:$BRANCH" || die "推送失败"

# ---- 核对：这一步是重点，不能省 ----
echo
echo "== 核对：远端 HEAD 是否 == 本地 HEAD =="
git fetch "$REMOTE" "$BRANCH" >/dev/null 2>&1 || die "推送后 fetch 失败"
GOT=$(git rev-parse "refs/remotes/$REMOTE/$BRANCH")
echo "  本地: $LOCAL"
echo "  远端: $GOT"

if [ "$GOT" != "$LOCAL" ]; then
    echo
    echo "❌ 核对不一致 —— 推上去的不是本地 HEAD！"
    echo
    echo "   最可能的原因：有另一个 clone 同时推了同一个远端"
    echo "   （本项目实际发生过，见 docs/事件-远端被旧clone覆盖.md）"
    echo
    echo "   排查："
    echo "     git log --oneline -1 $GOT        # 远端现在是什么"
    echo "     ls -d /tmp/*bxroot* /root/*bxroot*   # 还有哪些 clone"
    echo "     # 停用可疑 clone 的 remote："
    echo "     #   git -C <clone> remote set-url origin https://invalid.local/DISABLED.git"
    echo "   恢复："
    echo "     git push --force $REMOTE HEAD:$BRANCH   # 停用干扰源之后再推"
    exit 1
fi

echo "  ✅ 一致"
echo
echo "RESULT: PASS"
exit 0
