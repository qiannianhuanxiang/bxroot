#!/bin/sh
# proc（D4 进程管理）测试运行器
#
#   ./RUN_TESTS.sh          编译 + 运行（默认）
#   ./RUN_TESTS.sh ubsan    带 UndefinedBehaviorSanitizer
#   ./RUN_TESTS.sh asan     带 AddressSanitizer（本容器**不可用**，见下）
#   ./RUN_TESTS.sh clean    清理产物
#
# 两个设计约束：
#   1. 本容器 aarch64 gcc 13.3.0 会间歇性内部编译器错误（ICE），
#      同一命令重试往往就过 → 所有编译都带重试循环。
#   2. **零警告是硬性要求**，所以脚本必须真的**检查**警告，而不是只看
#      退出码 —— 编译成功但有警告时退出码仍然是 0。
#      （早先版本只在末尾打印「零警告检查：通过」而从未检查过任何东西，
#        这个**假通过**比没有检查更糟：它让人以为门禁在守着。现在有
#        warn_gate 逐条断言 stderr 里没有 "warning:"。）
#
# 关于 ASan：本容器不可用。实测报
#   "ASan runtime does not come first in initial library list"
# 因为外层 proot 吞掉了 LD_PRELOAD，ASan 运行时无法抢占首位置。
# 这是已记录的容器限制（见 _shared/容器内测试不可信.md），用 ubsan 代替。
set -u
cd "$(dirname "$0")" || exit 1

# ★ 警告集必须与真实构建对齐 —— 否则就是"策略漂移" ★
#
# 实测缺陷（2026-09-17）：这里原先**没有** `-Wno-nonnull-compare`，而项目
# 另外三处都有：
#     BUILD_RUNTIME.sh:89        WARN="... -Wno-nonnull-compare ..."
#     test/RUN_WARN_GATE.sh:94   同上
#     test/RUN_ALL.sh:275        同上
# 于是同一个 proc.c 在别的门禁里干净、在这里却报红：
#
#     proc.c:4611:8: warning: 'nonnull' argument 'stream' compared to NULL
#                   [-Wnonnull-compare]
#
# 那条告警来自 `pclose` 钩子里的 `if (stream == NULL)`。**它是必须保留的
# 防御性判空**：glibc 用 `__nonnull` 标注了这个参数，但那是**给编译器的
# 承诺**，不是运行时的保证 —— 我们自己导出的 `pclose` 是公开符号，任何
# 客户都能传 NULL 进来。项目对此的既定处置就是显式关掉这条告警
# （见 test/RUN_WARN_GATE.sh:49 的说明），不是删掉判空。
#
# 四处警告集必须一致，否则"零告警门禁"会随入口不同而给出不同答案 ——
# 这正是 RUN_WARN_GATE.sh 开头警告过的那种漂移。
WARN="-Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion -Wno-nonnull-compare"
BASE="-std=c11 -D_GNU_SOURCE -I."
LOG=/tmp/proc-cc.err
FAILED=0

# ------------------------------------------------------------------
# 带 ICE 重试的编译。  用法: retry_build <输出文件> <gcc 参数...>
# ------------------------------------------------------------------
retry_build() {
    out="$1"; shift
    i=1
    while [ "$i" -le 10 ]; do
        if gcc "$@" -o "$out" 2>"$LOG"; then
            return 0
        fi
        if ! grep -q 'internal compiler error' "$LOG"; then
            echo "--- 编译失败 ---"
            cat "$LOG"
            return 1
        fi
        echo "   gcc ICE（第 $i 次），重试"
        i=$((i + 1))
    done
    echo "   gcc 持续 ICE，退回 -O0"
    gcc "$@" -O0 -o "$out" 2>"$LOG"
}

# ------------------------------------------------------------------
# 零警告门禁：编译并**断言 stderr 里没有 warning**
#   用法: warn_gate <标签> <gcc 参数...>
# ------------------------------------------------------------------
warn_gate() {
    label="$1"; shift
    if ! retry_build /tmp/proc-gate.o -c "$@"; then
        echo "   ❌ $label：编译失败"
        FAILED=1
        return 1
    fi
    if [ -s "$LOG" ] && grep -q 'warning:' "$LOG"; then
        echo "   ❌ $label：有警告（本项目要求零警告）"
        grep 'warning:' "$LOG"
        FAILED=1
        return 1
    fi
    echo "   ✅ $label：零警告"
    return 0
}

# ------------------------------------------------------------------
case "${1:-}" in
clean)
    rm -f test_proc test_proc.ub test_proc.as /tmp/proc-gate.o
    echo "已清理"
    exit 0
    ;;
esac

# ------------------------------------------------------------------
# 步骤 0：前置检查（保证从干净检出也能重跑）
# ------------------------------------------------------------------
echo "== [0/4] 前置检查 =="
if ! command -v gcc >/dev/null 2>&1; then
    echo "❌ 找不到 gcc"; exit 1
fi
echo "   gcc: $(gcc -dumpversion)"

for f in proc.h proc.c test_proc.c; do
    if [ ! -f "$f" ]; then
        echo "❌ 缺少源文件 $f（请确认在 agents/proc/ 下运行）"; exit 1
    fi
done
echo "   源文件齐全（proc.h / proc.c / test_proc.c）"

# ------------------------------------------------------------------
# 步骤 1：零警告门禁 —— 两种模式都必须干净
# ------------------------------------------------------------------
echo "== [1/4] 零警告门禁 =="
warn_gate "纯逻辑模式 (PX_PURE_LOGIC=1)" \
    -O1 $WARN $BASE -DPX_PURE_LOGIC=1 proc.c

warn_gate "钩子层模式 (PX_PURE_LOGIC=0)" \
    -O1 $WARN $BASE -DPX_PURE_LOGIC=0 proc.c

if [ "$FAILED" -ne 0 ]; then
    echo
    echo "RESULT: FAIL（零警告门禁未通过）"
    exit 1
fi

# ------------------------------------------------------------------
# 步骤 2/3：构建 + 运行
# ------------------------------------------------------------------
case "${1:-}" in
ubsan)
    echo "== [2/4] 构建（UBSan）=="
    retry_build test_proc.ub -O1 -g $WARN $BASE \
        -fsanitize=undefined -fno-sanitize-recover=all \
        test_proc.c proc.c -lpthread || exit 1
    echo "== [3/4] 运行（UBSan：任何 UB 都会让用例失败）=="
    ./test_proc.ub
    ;;
asan)
    echo "== [2/4] 构建（ASan + LSan）=="
    retry_build test_proc.as -O1 -g $WARN $BASE \
        -fsanitize=address,leak -fno-omit-frame-pointer \
        test_proc.c proc.c -lpthread || exit 1
    echo "== [3/4] 运行（ASan）=="
    echo "   注意：本容器大概率报 'ASan runtime does not come first'"
    echo "   （外层 proot 吞掉 LD_PRELOAD），那是已知限制，请改用 ubsan"
    ASAN_OPTIONS=detect_leaks=1 ./test_proc.as
    ;;
*)
    echo "== [2/4] 构建（普通）=="
    retry_build test_proc -O1 $WARN $BASE test_proc.c proc.c -lpthread || exit 1
    echo "== [3/4] 运行 =="
    ./test_proc
    ;;
esac
RC=$?

# ------------------------------------------------------------------
echo "== [4/4] 门禁汇总 =="
echo "   零警告门禁：通过"
if [ "$RC" -eq 0 ]; then
    echo "   断言门禁：通过"
else
    echo "   断言门禁：❌ 失败（见上方 FAIL 行）"
fi
exit "$RC"
