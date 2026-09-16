#!/bin/sh
# 协同测试运行器 —— l2s × fakeroot 在同一进程里的交互
#
#   ./RUN_INTEGRATION.sh          编译 + 运行
#   ./RUN_INTEGRATION.sh ubsan    带 UndefinedBehaviorSanitizer
#
# 注意：本容器 aarch64 gcc 13.3.0 会间歇性内部编译器错误（ICE），
# 所以带重试循环。实测 fakeroot.c 的 fakeroot_lookup() 在 RTL/IRA 阶段
# 大约每两次编译崩一次。
set -e
cd "$(dirname "$0")"

retry_build() {
    out="$1"; shift
    i=1
    while [ "$i" -le 10 ]; do
        if gcc "$@" -o "$out" 2>/tmp/integ-cc.err; then
            return 0
        fi
        if ! grep -q 'internal compiler error' /tmp/integ-cc.err; then
            cat /tmp/integ-cc.err
            return 1
        fi
        echo "gcc ICE（第 $i 次），重试"
        i=$((i + 1))
    done
    echo "gcc 持续 ICE，退回 -O0"
    gcc "$@" -O0 -o "$out"
}

SRC="test_integration.c l2s-runtime.c l2s.c fakeroot.c"
FLAGS="-std=c11 -D_GNU_SOURCE -DFAKEROOT_PURE_LOGIC -I."

case "${1:-}" in
ubsan)
    # ASan 在本容器不可用（外层 proot 吞掉预加载），只用 UBSan。
    retry_build test_integration.ub -O1 -g $FLAGS \
        -fsanitize=undefined -fno-sanitize-recover=all $SRC
    exec ./test_integration.ub
    ;;
*)
    retry_build test_integration -O1 -Wall -Wextra $FLAGS $SRC
    exec ./test_integration
    ;;
esac
