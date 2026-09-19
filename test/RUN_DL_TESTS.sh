#!/bin/sh
# =====================================================================
# dl 家族契约回归：`dlerror` / `dlsym` 同源 + `dl_iterate_phdr` 模块视图
# =====================================================================
#
# 判据来源与理由见 test/dltest.c 头部注释。这里只负责：
#   1. 编译探针；
#   2. 在 proroot bridge/linker 下**真的跑起来**（这是唯一能暴露
#      dlerror 恒 NULL、模块视图塌成 1 个的地方）；
#   3. 把 dltest 的逐条 PASS/FAIL 透传成自己的退出码。
#
# ★ 为什么需要"容器内真跑"这一层 ★
# 本库的 dlsym 走 linker 服务，**只有挂在 proroot linker 下才成立**。
# 在普通 Ubuntu 环境里 LD_PRELOAD 跑，走的是另一条降级路径，
# 测不到真实缺陷（这一点是实测出来的）。
#
# ★ 环境不可用时不静默放过 ★
# 拿不到 bridge/linker/rootfs 时明确 SKIP 并 **exit 2**（"环境不满足"，
# 与 RUN_ALL 的 rc=2 约定一致，见 RUN_NSS_EDGE.sh / RUN_PATH_FORMS.sh），
# 且把原因打出来 —— 静默跳过是本项目反复出现的缺陷模式。
#
# 用法： sh test/RUN_DL_TESTS.sh
# 退出码：0 = 通过；1 = 契约失败；2 = 环境不满足（无法测）
# =====================================================================
set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 1

# ---------------------------------------------------------------------
# ★ APP_LIB 必须**动态探测**，不能硬编码 ★
#
# 踩过的坑（2026-09-19 发现）：这里原先硬编码了一个**过期**的 APK 路径
# （`com.dsh.client-7Lg5Zt8zAVL829axfo2lQQ==`），而本机的真实路径是
# `com.dsh.client-Bqbh8yjCugq4VmZdjRfkTg==` —— APK 一重装，那个随机
# 后缀就变了。后果：`bridge_ok()` 恒失败 → 本项**每次静默跳过**，
# 而跳过方式是 `exit 0`，于是 RUN_ALL 把它记成 **✅ dl 家族契约**。
#
# 危害不止"少测一项"：这是一个自述"只有真跑才测得到真实缺陷"的测试
# （见头注：普通环境下 LD_PRELOAD 走的是另一条降级路径），它被跳过的
# 时候恰恰是最需要它的时候。实测改用探测值后 11/11 全过。
#
# 注意本文件上面那段"可用性探测必须真跑一下、不能用 [ -f ]"的注释是
# **对的**，但它只解决了"怎么判断可用"，没解决"去哪儿找" —— 同一个
# 静默跳过换个入口又出现了一次。两者都要管。
#
# 探测方法与其他 runner 一致（RUN_NSS_EDGE.sh:173 / RUN_E2E.sh:88 /
# RUN_PATH_FORMS.sh:399）：从 /proc/<pid>/maps 反查 bridge 的真实路径。
# ---------------------------------------------------------------------
detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}

APP_LIB="${BXROOT_APP_LIB:-$(detect_app_lib || true)}"
ROOTFS="${BXROOT_ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
RT="${BXROOT_DL_RT:-$ROOT/build/libbxroot-runtime.so}"
TMPL="${BXROOT_DL_TMPL:-$ROOTFS/root/dlfix/test}"

say() { printf '%s\n' "$*"; }

if [ ! -f "$RT" ]; then
    say "⏭️  跳过：缺构建产物 $RT（先跑 sh BUILD_RUNTIME.sh）"
    exit 2
fi
# ★ 可用性探测必须用"真跑一下"，不能用 [ -f ] ★
#
# 实测（本容器）：`/data/app/…/lib/arm64/libproroot-bridge.so` 是
# **可执行但不可 stat/open** 的 —— `[ -f ]`、`[ -x ]`、`[ -e ]` 全部为假，
# `python3 os.path.exists()` 也是 False，而**直接 exec 它却能跑**
# （打印 "[proroot-trampoline] usage: trampoline <linker> [args...]"）。
# 用文件属性做守卫会导致这一项**永远被静默跳过** —— 正是本项目反复
# 出现的缺陷模式。所以这里用真实的 exec 探测。
bridge_ok() {
    [ -n "$APP_LIB" ] || return 1
    out=$(timeout 20 "$APP_LIB/libproroot-bridge.so" 2>&1)
    case "$out" in
    *trampoline*) return 0 ;;
    *) return 1 ;;
    esac
}

if ! bridge_ok; then
    say "⏭️  跳过：proroot bridge/linker 不可用（$APP_LIB）"
    say "    本项只在 proroot linker 下有意义 —— 本库的 dlsym 走 linker 服务，"
    say "    在普通环境里走的是另一条降级路径，测不到真实缺陷。"
    exit 2
fi
if [ ! -d "$ROOTFS" ]; then
    say "⏭️  跳过：找不到 ROOTFS（$ROOTFS）"
    exit 2
fi

# 落盘目录必须**在 ROOTFS 内**（Python os.makedirs：shell 的 mkdir 在
# ROOTFS 内会"成功但看不见"，见 docs/高频符号缺口调查.md §6.3）
python3 - "$TMPL" <<'PY' 2>/dev/null || { say "⏭️  跳过：无法创建 $TMPL"; exit 2; }
import os, sys
os.makedirs(sys.argv[1], exist_ok=True)
PY

# 编译探针（-O1，与项目其它测试一致）。ICE 重试由 RUN_ALL 的重试逻辑兜底。
gcc -O1 -o "$TMPL/dltest" test/dltest.c -ldl -lpthread 2>"$TMPL/cc.err" || {
    say "❌ 探针编译失败："; cat "$TMPL/cc.err"; exit 1
}

# 内核视角路径（给 bridge/linker 用的那些）。
#
# ★ 为什么必须区分"宿主路径"与"内核视角路径" ★
# 探针是**在容器里**跑的，但它看到的路径是 **proroot 翻译后**的路径。
# bridge 的 --preload 参数直接交给 linker，linker **不做 rootfs 翻译**，
# 所以它必须是内核视角的真实路径。实测教训：把宿主路径
# `/root/proroot-work/...` 传给 --preload，得到
#
#     deps: failed to preload /root/proroot-work/.../libbxroot-runtime.so
#     proroot-ldso: failure rc=2
#
# 而 ROOTFS/root 与 /root 是**同一 inode**（同一个目录），所以
# 内核视角路径 = ROOTFS + 宿主绝对路径。这一条实测有效。
#
# 允许用 BXROOT_DL_KRT 直接覆盖（例如产物在别处）。
krt_of() {
    # $1 = 宿主绝对路径（仓库内的）
    case "$1" in
    "$ROOTFS"/*) printf '%s' "$1" ;;                       # 已在 ROOTFS 内
    /*)          printf '%s%s' "$ROOTFS" "$1" ;;           # 加 ROOTFS 前缀
    *)           printf '%s/%s' "$ROOTFS" "$1" ;;
    esac
}

KTMP="${BXROOT_DL_KTMP:-$ROOTFS/root/dlfix/test}"
KRT="${BXROOT_DL_KRT:-$(krt_of "$RT")}"

# ★ 两侧对照：官方只认 PROROOT_*，bxroot 只认 BXROOT_* ★
# 给官方传 BXROOT_* 会被静默忽略 —— 那就不是对照实验。
say "== dl 家族契约（bxroot runtime）=="
BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$KTMP" BXROOT_WORKDIR="/" \
BXROOT_FAKEROOT=1 BXROOT_LINK2SYMLINK=1 BXROOT_GUEST_EXE="$KTMP/dltest" \
timeout 300 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
    --argv0 dltest --preload "$KRT" "$KTMP/dltest" 2>&1
RC=$?

say ""
if [ "$RC" -eq 0 ]; then
    say "✅ dl 家族契约全部通过"
    exit 0
fi
say "❌ dl 家族契约失败（退出码 $RC；139 = SIGSEGV，通常是自递归防护缺失）"
exit 1
