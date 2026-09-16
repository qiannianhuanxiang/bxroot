#!/bin/sh
# =====================================================================
# l2s 硬链接模拟的端到端契约测试
# =====================================================================
#
# 由来
# ----
# `test/test_l2s_rt.c` 是 **纯逻辑**测试（15 用例 / 119 断言，全过）——
# 它验证的是 l2s 库**自身**正确。但库正确 ≠ **接线正确**。
#
# 实测发现的缺口：bxroot 下 l2s 的**创建**那一半工作正常（目录里能看到
# `.l2s.*` 中间文件），但**伪装**那一半没生效：
#
#     官方 proroot:  link() → st_nlink=2, lstat 看到普通文件
#     bxroot:        link() → st_nlink=1, lstat 看到符号链接   ❌
#
# 连跑 3 次稳定复现，所以不是偶发。本脚本把这个契约钉住。
#
# 为什么必须端到端测
# ------------------
# 这个缺陷**只有**在"客户程序真的调 link() 再 stat()"时才暴露。
# 纯逻辑测试注入的都是 l2s 自己的 ops 表，走的路径与真实 stat 钩子不同，
# 所以永远测不出来。
#
# 用法
# ----
#   sh test/RUN_L2S_E2E.sh
#
# 退出码
# ------
#   0 = 契约成立     1 = 契约被破坏     2 = 环境不满足（无法测）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

# ---------------------------------------------------------------------
# 环境探测。这个测试需要真机 rootfs + 官方库目录，缺一不可。
# ---------------------------------------------------------------------
detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}

APP_LIB="${APP_LIB:-$(detect_app_lib)}"
ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
NODE="$ROOTFS/usr/local/bin/node"
OFFICIAL="${OFFICIAL_RT:-/root/proroot-work/backup/libproroot-runtime.so}"

# 落地目录按进程隔离（教训：共享固定路径 + rm -rf 会删掉别人的工作文件）
STAGE_MKDIR="${BXROOT_STAGE:-/tmp/bxroot-l2s-$$}"
STAGE_LOAD="$ROOTFS${STAGE_MKDIR}"

# ★ 不要对 $APP_LIB 做任何存在性探测 ★
#
# 这是本项目的经典双视角陷阱，实测六种探测方式**全部失败**：
#
#     [ -f ]  [ -d ]  head -c 0  cat  ls  test -x      ← 全部"不存在"
#
# 而 `exec "$APP_LIB/libproroot-bridge.so"` 却能正常工作。
#
# 原因：探测函数从 `/proc/<pid>/maps` 拿到的是**内核视图**路径
# （`/data/app/...`），而 shell 的所有内建/外部命令都走**容器视角**的
# 路径翻译 —— 后者看不到内核视图的路径。`exec` 则与 `--preload` 一样
# 直达内核，所以能成功。
#
# 结论：**唯一可靠的判据是"试着跑一次"**。下面的流程改为：
#   1) 形状检查（纯字符串，不碰文件系统）
#   2) 直接尝试运行 —— 失败就报"环境不满足"并给出原始输出
if [ -z "$APP_LIB" ]; then
    echo "⏭️  跳过：探测不到官方库目录（需要真机容器）"
    exit 2
fi
case "$APP_LIB" in
    */lib/arm64) ;;
    *) echo "⏭️  跳过：探测到的库目录形状异常（$APP_LIB）"; exit 2 ;;
esac
# 不做 [ -f ] / [ -d ]：见上，那些判据在本环境下恒为假

rm -rf "$STAGE_MKDIR" 2>/dev/null
mkdir -p "$STAGE_MKDIR" || { echo "❌ 无法创建落地目录"; exit 2; }
cp -f build/libbxroot-runtime.so "$STAGE_MKDIR/libbxroot-runtime.so" || exit 2

# ---------------------------------------------------------------------
# 探针：测 link() 之后的 st_nlink 与"是否被看成符号链接"
# ---------------------------------------------------------------------
cat > "$STAGE_MKDIR/l2s_probe.js" <<'JSEOF'
const fs = require("fs");
const d = "/tmp/l2s-e2e-" + process.pid;
try { fs.mkdirSync(d, {recursive: true}); } catch (e) {}
const a = d + "/a.txt", b = d + "/b.txt";
fs.writeFileSync(a, "hello");
try { fs.unlinkSync(b); } catch (e) {}

let nlink = -1, isLink = null, content = null, err = "";
try {
    fs.linkSync(a, b);
    const st = fs.statSync(a);
    nlink = st.nlink;
    isLink = fs.lstatSync(a).isSymbolicLink();
    content = fs.readFileSync(b, "utf8");
} catch (e) { err = e.code || e.message; }

try { fs.rmSync(d, {recursive: true}); } catch (e) {}

/* 单行、机器可解析的输出 —— 便于本脚本与人工核对 */
console.log("RESULT nlink=" + nlink + " islink=" + isLink +
            " content=" + JSON.stringify(content) +
            (err ? (" err=" + err) : ""));
JSEOF

run_one() {
    # $1 = runtime 的 .so 路径（容器视角）
    BXROOT_ROOTFS="$ROOTFS" \
    BXROOT_TMP_DIR="$STAGE_LOAD/tmp" \
    BXROOT_WORKDIR="/" \
    BXROOT_FAKEROOT=1 \
    BXROOT_LINK2SYMLINK=1 \
    BXROOT_GUEST_EXE="$NODE" \
    timeout 150 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
        --argv0 node \
        --preload "$STAGE_LOAD/$1" \
        "$NODE" "$STAGE_LOAD/l2s_probe.js" 2>&1 \
      | grep -vE '^\[NEXT\]|^\[bxroot\]|^node\[' \
      | grep '^RESULT' | head -1
}

echo "== l2s 硬链接模拟端到端契约 =="
echo

# ---------------------------------------------------------------------
# 1) bxroot 的结果
# ---------------------------------------------------------------------
GOT=$(run_one libbxroot-runtime.so)
if [ -z "$GOT" ]; then
    echo "❌ bxroot 侧没有产出 RESULT 行（探针没跑起来？）"
    rm -rf "$STAGE_MKDIR"
    exit 1
fi
echo "  bxroot: $GOT"

# 解析
nlink=$(echo "$GOT" | sed -n 's/.*nlink=\([0-9-]*\).*/\1/p')
islink=$(echo "$GOT" | sed -n 's/.*islink=\([a-z]*\).*/\1/p')
content=$(echo "$GOT" | sed -n 's/.*content=\(".*"\).*/\1/p')

FAIL=0
[ "$nlink" = "2" ]    || { echo "  ❌ st_nlink 应为 2，实得 $nlink"; FAIL=1; }
[ "$islink" = "false" ] || { echo "  ❌ lstat 不应把它看成符号链接（实得 islink=$islink）"; FAIL=1; }
[ "$content" = '"hello"' ] || { echo "  ❌ 内容应为 \"hello\"，实得 $content"; FAIL=1; }

# ---------------------------------------------------------------------
# 2) 官方对照（可选 —— 拿不到官方 runtime 就只做绝对判据）
# ---------------------------------------------------------------------
if [ -f "$OFFICIAL" ]; then
    cp -f "$OFFICIAL" "$STAGE_MKDIR/liboff-runtime.so" 2>/dev/null
    OFF=$(run_one liboff-runtime.so)
    if [ -n "$OFF" ]; then
        echo "  官方  : $OFF"
        onlink=$(echo "$OFF" | sed -n 's/.*nlink=\([0-9-]*\).*/\1/p')
        oislink=$(echo "$OFF" | sed -n 's/.*islink=\([a-z]*\).*/\1/p')
        # 官方应是 2 / false —— 若官方不是，说明环境本身有问题，
        # 那我们的判据也不可信，应当报告而不是硬判 bxroot 失败。
        if [ "$onlink" != "2" ] || [ "$oislink" != "false" ]; then
            echo "  ⚠️  官方对照也不符合预期（nlink=$onlink islink=$oislink）"
            echo "      → 环境本身可疑，本次判据不可信"
            rm -rf "$STAGE_MKDIR"
            exit 2
        fi
        # 措辞要谨慎：这里只说明"官方侧的对照值符合预期"，
        # 不代表 bxroot 与官方一致（bxroot 是否合格由上面的 FAIL 判据决定）。
        if [ "$FAIL" -eq 0 ]; then
            echo "  ✅ 与官方一致"
        else
            echo "  ↑ 官方对照有效（bxroot 与它不一致，见上方 ❌）"
        fi
    fi
else
    echo "  ℹ️  无官方 runtime 副本，跳过对照（绝对判据仍有效）"
fi

rm -rf "$STAGE_MKDIR"

echo
if [ "$FAIL" -ne 0 ]; then
    echo "RESULT: FAIL —— l2s 的 stat 伪装未生效"
    echo "  已知根因方向：创建那半正常（目录里有 .l2s.* 中间文件），"
    echo "  但 l2s_rt_patch_stat / _statx / _rewrite_readlink 这条链没接到"
    echo "  实际的 stat/lstat/readlink 钩子上。详见 docs/l2s-stat伪装修复.md"
    exit 1
fi
echo "RESULT: PASS"
exit 0
