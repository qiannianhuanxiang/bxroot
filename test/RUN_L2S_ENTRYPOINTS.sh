#!/bin/sh
# =====================================================================
# l2s stat 伪装的「多入口」契约测试 —— 运行器
# =====================================================================
#
# 由来
# ----
# 本轮修的是 l2s 硬链接模拟的 stat 伪装，而三个缺陷**全部出在接线**上，
# 各坏在一个不同的入口：
#
#   ① cfg.scheme 传成 PROROOT，而 l2s-runtime 只会写 PROOT 式名字
#      -> probe_fake_link() 永远返回 0，patch 静默不生效
#   ② fstatat 钩子漏了 l2s_rt_patch_stat 调用
#      （stat/lstat/stat64/lstat64 都有，fstatat 是唯一漏的）
#   ③ node/libuv 的 uv__fs_statx() **故意绕开 libc**，走裸
#      syscall(SYS_statx) —— 接在 libc statx() 钩子上对 node 完全无效
#
# 为什么既有测试没抓到
# --------------------
#   test/test_l2s_rt.c  注入内存 FS，只测**库自身**的逻辑 -> 测不到接线
#   test/RUN_L2S_E2E.sh 只用 node 一个入口                -> 覆盖不全
#
# 「能力已实现」不等于「能力已生效」，「一个入口对了」不等于「所有入口
# 都对了」。本脚本把**判据本身**钉住：无论调用方传什么 scheme，无论客户
# 走哪个入口，伪装都必须成立。
#
# 用法
# ----
#   sh test/RUN_L2S_ENTRYPOINTS.sh
#
# 退出码
# ------
#   0 = 全部通过     1 = 有失败     2 = 环境不满足（无法编译）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

# 产物放仓库内的临时目录，不写 /tmp（本容器 /tmp 被改坏过）
OUT_DIR="$ROOT/.tmp-l2s-entry"
mkdir -p "$OUT_DIR" 2>/dev/null || { echo "❌ 无法创建 $OUT_DIR"; exit 2; }
BIN="$OUT_DIR/test_l2s_entrypoints"

echo "== l2s stat 伪装：多入口契约 =="

# gcc 13.3.0 在本环境有间歇性 ICE，重试即可（与 BUILD_RUNTIME.sh 同策略）
rc=1
i=1
while [ "$i" -le 8 ]; do
    # shellcheck disable=SC2086
    "$CC" -std=c11 -O1 -Wall -Wextra -D_GNU_SOURCE= -Isrc/l2s \
        -o "$BIN" \
        test/test_l2s_entrypoints.c src/l2s/l2s.c src/l2s/l2s-runtime.c \
        2>"$OUT_DIR/cc.err"
    rc=$?
    [ "$rc" -eq 0 ] && break
    if ! grep -q 'internal compiler error' "$OUT_DIR/cc.err" 2>/dev/null; then
        echo "❌ 编译失败（非 ICE，是真错误）"
        cat "$OUT_DIR/cc.err"
        exit 1
    fi
    i=$((i + 1))
done

if [ "$rc" -ne 0 ]; then
    echo "❌ 连续 8 次 ICE，未能编译（编译器问题，非代码问题）"
    exit 2
fi

# 测试自己会建/删沙箱目录，工作目录给它 $OUT_DIR，避免污染仓库根
cd "$OUT_DIR" || exit 2
"$BIN"
rc=$?
cd "$ROOT" || exit 2

rm -rf "$OUT_DIR"
exit "$rc"
