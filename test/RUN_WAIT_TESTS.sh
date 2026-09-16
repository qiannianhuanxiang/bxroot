#!/bin/sh
# wait 家族钩子的运行器（P0-3 / D4 补充项）
#
#   ./RUN_WAIT_TESTS.sh          编译 + 运行
#
# ★ 这**不是** LD_PRELOAD 端到端测试 ★
# 本容器外层 proot 会吞掉注入（_shared/容器内测试不可信.md），所以测试用
# dlopen 打开构建产物、dlsym 取要验证的四个符号后**直接调用**：
# 走的是同一份机器码、同一份 pid 账本，但绕过了「符号插入」那一层。
# 能证明的是钩子逻辑正确（含 WNOHANG 边界）与符号确实导出；
# **不能**证明真实 preload 下 PLT 插入生效 —— 那需要真机验证。
set -u
cd "$(dirname "$0")" || exit 1

ROOT=$(cd .. && pwd)
LIB="${BXROOT_SO:-$ROOT/build/libbxroot-runtime.so}"
# proc.c 的编译单元位置。
#
# ★ 必须**优先查仓库内** `src/proc` ★
#
# 原实现只找 `$ROOT/../proc` —— 那是 D4 还是独立子项目时的开发期布局。
# 源码迁进仓库（`src/proc/`）之后，本脚本在**干净克隆里就找不到 proc.h**，
# 而开发机上因为 `../proc` 恰好存在而侥幸能跑。
#
# 这个缺陷是**干净克隆验证**抓到的：
#     干净克隆 → ❌ 找不到 proc.h
#     开发机   → ✅（因为 ../proc 存在）
# 与 BUILD_RUNTIME.sh、RUN_WARN_GATE.sh 的做法保持一致（它们都已优先查
# 仓库内），否则三个脚本对同一件事的判断会不一致。
if [ -n "${BXROOT_PROC_DIR:-}" ] && [ -f "$BXROOT_PROC_DIR/proc.h" ]; then
    PROC_DIR="$BXROOT_PROC_DIR"
elif [ -f "$ROOT/src/proc/proc.h" ]; then
    PROC_DIR="$ROOT/src/proc"
else
    PROC_DIR="$(cd "$ROOT/../proc" 2>/dev/null && pwd)"
fi
OUT=/tmp/test_wait_hooks
STUB=/tmp/libwaitstub.so
LOG=/tmp/wait-hooks-cc.err

if [ ! -f "$LIB" ]; then
    echo "❌ 找不到被测库：$LIB"
    echo "   先跑 ../BUILD_RUNTIME.sh"
    exit 1
fi
if [ ! -f "$PROC_DIR/proc.h" ]; then
    echo "❌ 找不到 proc.h（$PROC_DIR）"; exit 1
fi

# 本容器 gcc 13.3.0 会间歇性 ICE，重试即可
retry_build() {
    i=1
    while [ "$i" -le 10 ]; do
        if gcc "$@" 2>"$LOG"; then
            return 0
        fi
        if ! grep -q 'internal compiler error' "$LOG"; then
            echo "--- 编译失败 ---"; cat "$LOG"; return 1
        fi
        echo "   gcc ICE（第 $i 次），重试"
        i=$((i + 1))
    done
    echo "   持续 ICE，退回 -O0"
    gcc "$@" -O0 -o "$OUT" 2>"$LOG" || { cat "$LOG"; return 1; }
}

echo "== 构建 =="
retry_build -O1 -g -I"$PROC_DIR" -o "$OUT" test_wait_hooks.c -ldl || exit 1
# 「真实实现」替身：编成独立 .so，在运行时**晚于**产物 dlopen，
# 这样钩子内部的 RTLD_NEXT 就会命中它（本容器 RTLD_NEXT 到 libc 不可用）
retry_build -O1 -g -fPIC -shared -o "$STUB" waitstub.c || exit 1
echo "   测试驱动: $OUT"
echo "   真实实现替身: $STUB"
echo "   被测产物: $LIB"

echo "== 运行 =="
BXROOT_WAIT_TEST_LIB="$LIB" BXROOT_WAIT_STUB_LIB="$STUB" "$OUT" 2>/dev/null
RC=$?

# 顺带做一次符号门禁：四个符号必须**导出**（UND 不算）
echo "== 符号门禁 =="
MISSING=""
for s in waitpid wait4 wait3 waitid; do
    if ! nm -D --defined-only "$LIB" 2>/dev/null | awk '{print $3}' | grep -qx "$s"; then
        MISSING="$MISSING $s"
    fi
done
if [ -n "$MISSING" ]; then
    echo "   ❌ 未导出:$MISSING"; exit 1
fi
echo "   ✅ waitpid/wait4/wait3/waitid 均已导出"
exit "$RC"
