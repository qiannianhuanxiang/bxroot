#!/bin/sh
# fakeroot 测试运行器
#
#   ./RUN_TESTS.sh          编译 + 运行（红灯则脚本失败）
#   ./RUN_TESTS.sh ubsan    带 UndefinedBehaviorSanitizer
#
# 注意：ASan 在本容器内不可用（外层 proot 里「ASan runtime does not come
# first in initial library list」），所以统一用 UBSan。
#
# 又：本容器 aarch64 gcc 13.3.0 会**间歇性**内部编译器错误（ICE），
# 同一个命令重试几次往往就过。所以下面每个编译都带重试循环。
#
# ★ 路径修正（重要）★
# 本脚本原先 cd 到 test/ 后直接引用 `fakeroot.c` / `fakeroot.h`，
# 那是 **D4 之前的老布局**（源码曾与测试同目录）。源码迁到
# src/runtime/ 之后，这两条引用就再也找不到了 —— 脚本一直是坏的，
# 只是没人从脚本入口跑过（全绿记录其实来自手敲的 gcc 命令行）。
# 现在改为以**仓库根**为工作目录，显式带上 -Isrc/runtime。
set -e
cd "$(dirname "$0")/.."

retry_build() {
    # $1 = 输出文件；其余 = 编译参数
    out="$1"; shift
    i=1
    while [ "$i" -le 8 ]; do
        if gcc "$@" -o "$out" 2>/tmp/fakeroot-cc.err; then
            return 0
        fi
        if ! grep -q 'internal compiler error' /tmp/fakeroot-cc.err; then
            cat /tmp/fakeroot-cc.err
            return 1
        fi
        echo "gcc ICE（第 $i 次），重试"
        i=$((i + 1))
    done
    echo "gcc 持续 ICE，退回 -O0"
    gcc "$@" -O0 -o "$out"
}

case "${1:-}" in
ubsan)
    retry_build test/test_fakeroot.ub -std=c11 -O1 -g -D_GNU_SOURCE \
        -Isrc/runtime -DFAKEROOT_PURE_LOGIC \
        -fsanitize=undefined -fno-sanitize-recover=all \
        test/test_fakeroot.c src/runtime/fakeroot.c
    exec ./test/test_fakeroot.ub
    ;;
*)
    retry_build test/test_fakeroot -std=c11 -O1 -Wall -Wextra -D_GNU_SOURCE \
        -Isrc/runtime -DFAKEROOT_PURE_LOGIC \
        test/test_fakeroot.c src/runtime/fakeroot.c
    exec ./test/test_fakeroot
    ;;
esac
