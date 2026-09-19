#!/bin/sh
# =====================================================================
# 开发树 → GitHub 单向同步（"实时跟进最新源码"）
# =====================================================================
#
# 为什么需要这个脚本
# ------------------
# 开发发生在 /root/proroot-work/agents/rename-bxroot（**不是** git 仓库：
# 里面有 rootfs/ 镜像、几十个 proot-* 探针目录、build 产物，体积远超源码），
# 而推送走 /tmp/bxroot-git（干净的 clone）。
#
# 手工 `cp` + `git add -A` 在本项目反复踩坑：
#   - `git add -A` 会把 src/runtime/t_null 等几 MB 测试二进制提交进去
#   - 开发树顶层混着 l2s 中间层残留（`target`、`tgt`、`lnk`、`rel_out`）
#     和一次性实验目录，误提交后没人会去看 diff
#
# 本脚本把"哪些路径属于源码"这个判断**固化成白名单**，不依赖记忆。
#
# 用法
# ----
#   sh tools/sync-to-github.sh            # 同步并推送
#   sh tools/sync-to-github.sh --dry-run  # 只看会改什么，不提交
#   sh tools/sync-to-github.sh -m "消息"  # 指定 commit 消息
#
# 退出码：0 = 已同步或无需同步；1 = 出错（不会留下半提交状态）
# =====================================================================

set -u

SRC="${BXROOT_SRC:-/root/proroot-work/agents/rename-bxroot}"
DST="${BXROOT_GIT:-/tmp/bxroot-git}"
BRANCH="${BXROOT_BRANCH:-main}"
DRY=0
MSG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        -m) shift; MSG="${1:-}" ;;
        *) echo "未知参数: $1" >&2; exit 1 ;;
    esac
    shift
done

die() { echo "❌ $*" >&2; exit 1; }

[ -d "$SRC" ] || die "源目录不存在: $SRC"
[ -d "$DST/.git" ] || die "推送克隆不存在或不是 git 仓库: $DST"

# ---- 白名单：只有这些路径属于仓库源码 ----
# 目录（递归同步）
DIRS="docs src test tools tests-upstream .github"
# 单文件
FILES="README.md Makefile LICENSE BUILD_RUNTIME.sh .gitignore RENAME-REPORT.md issue-regression-test.sh"

echo "源   : $SRC"
echo "目标 : $DST  (分支 $BRANCH)"
echo

# 权限位是这里最大的噪声源：开发树 umask 是 077，源文件是 600/700，
# 而仓库里记的是 644/755。若用 `cp -p`，每次同步都会产生一堆
# "mode 100644 → 100755" 的空 diff（实测 5 个文件全是零内容差异）。
# 因此改为：复制后按 **git 索引里记录的模式** 回设权限；索引里没有的
# 新文件按类型给默认值（.sh → 755，其余 644）。
MODEMAP=$(mktemp)
( cd "$DST" && git -c core.quotePath=false ls-files -s ) > "$MODEMAP" 2>/dev/null || true

fix_mode() {
    _f="$1"
    _m=$(awk -v p="$_f" '$4==p {print $1; exit}' "$MODEMAP")
    if [ -z "$_m" ]; then
        case "$_f" in *.sh) _m=100755 ;; *) _m=100644 ;; esac
    fi
    case "$_m" in
        100755) chmod 755 "$DST/$_f" 2>/dev/null ;;
        *)      chmod 644 "$DST/$_f" 2>/dev/null ;;
    esac
}

# ---- 1) 同步 ----
echo "== 同步文件 =="
for d in $DIRS; do
    if [ -d "$SRC/$d" ]; then
        mkdir -p "$DST/$d"
        ( cd "$SRC" && find "$d" -type f ) | while IFS= read -r f; do
            case "$f" in
                */build/*|*.o|*.so|*.so.*|*.a|*.ub) continue ;;
            esac
            mkdir -p "$DST/$(dirname "$f")"
            cp "$SRC/$f" "$DST/$f" 2>/dev/null || true
        done
        echo "  $d  ✔"
    else
        echo "  $d  (源侧无，跳过)"
    fi
done

for f in $FILES; do
    if [ -f "$SRC/$f" ]; then
        cp "$SRC/$f" "$DST/$f"
        echo "  $f  ✔"
    fi
done

# 统一回设权限
for d in $DIRS; do
    [ -d "$SRC/$d" ] && ( cd "$SRC" && find "$d" -type f ) | while IFS= read -r f; do
        case "$f" in */build/*|*.o|*.so|*.so.*|*.a|*.ub) continue ;; esac
        fix_mode "$f"
    done
done
for f in $FILES; do [ -f "$SRC/$f" ] && fix_mode "$f"; done
rm -f "$MODEMAP"
echo

# ---- 2) 检查有无"仓库里有、开发树没有"的跟踪文件 ----
# 不自动删（可能是 git 侧的测试夹具，如 tools/investigations/），只提示
# 注意：必须关掉 core.quotePath，否则非 ASCII 路径会被 git 输出成
# 带双引号的转义形式（"docs/\346\211\253..."），`[ -f ]` 必然判否，
# 于是每个中文文档都误报一次"开发树没有"。实测踩过。
echo "== 仓库有而开发树没有的跟踪文件（不自动删除，仅提示）=="
( cd "$DST" && git -c core.quotePath=false ls-files ) | while IFS= read -r f; do
    if [ ! -f "$SRC/$f" ]; then
        echo "  ⚠ $f"
    fi
done | head -20
echo

# ---- 3) 是否有改动 ----
cd "$DST" || die "无法进入 $DST"
if [ -z "$(git status --porcelain)" ]; then
    echo "✅ 工作树干净 —— 开发树与仓库一致，无需推送"
    echo "RESULT: NOCHANGE"
    exit 0
fi

echo "== 待提交改动 =="
git status --short | head -40
echo

if [ "$DRY" = 1 ]; then
    echo "（--dry-run：到此为止，未提交）"
    exit 0
fi

# ---- 4) 提交 ----
if [ -z "$MSG" ]; then
    MSG="sync: 同步开发树最新源码 ($(date +%Y-%m-%d\ %H:%M))"
fi

git add -A || die "git add 失败"

# 提交前再拦一次：确认没有二进制产物被 stage
BIG=$(git diff --cached --numstat | awk '$1=="-" {print $3}' | head -5)
if [ -n "$BIG" ]; then
    echo "⚠ 以下为二进制文件（确认是否该入库）:"
    echo "$BIG" | sed 's/^/    /'
fi

git -c user.name=bxroot -c user.email=bxroot@users.noreply.github.com \
    commit -q -m "$MSG" || die "commit 失败"
echo "  ✔ 已提交: $(git log -1 --format='%h %s')"
echo

# ---- 5) 安全推送（含推送前后 hash 核对）----
sh tools/push-verified.sh origin "$BRANCH"
