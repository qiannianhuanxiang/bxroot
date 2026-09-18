#!/bin/sh
# fakeroot 账本多线程竞态测试（评估报告 8.7）
#
# 为什么需要：账本原先假设单线程（全项目零锁）。实测（8 线程 × 400 键）
# 在**无锁**下稳定复现堆破坏：
#     double free or corruption (fasttop)
#     malloc(): unaligned tcache chunk detected
# 根因：fr_map_compact（整表 realloc + 键所有权转移）与 fr_map_probe
# （按 cap 取模遍历探测链）并发放行。node worker / pnpm 并发 IO 都会经
# chown/chmod 记账进来 —— 这是真实客户路径。
#
# 本测试两阶段：
#   阶段 A 小容量 + 开淘汰 → 最大化重哈希，检测堆破坏/不变量破坏
#   阶段 B 大容量 + 关淘汰 → 检测丢更新（count 必须精确）
#
# 判据：两阶段不变量成立、count 正确、进程不崩。
#
# 用法：sh test/RUN_CONCUR.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
OUT="/tmp/t-concur.$$"

echo "▶️  fakeroot 账本多线程并发"

# gcc13 间歇 ICE：重试 + 降优化
OPT="-O1"
for i in 1 2 3 4 5 6; do
    if $CC -std=c11 $OPT -D_GNU_SOURCE -DFAKEROOT_PURE_LOGIC \
        -Wall -Wextra -Wno-unused-parameter \
        -o "$OUT" "$ROOT/test/t_concur.c" "$ROOT/src/runtime/fakeroot.c" \
        -lpthread 2>"$OUT.err"; then
        break
    fi
    if grep -q "internal compiler error" "$OUT.err"; then
        [ "$OPT" = "-O1" ] && { OPT="-O0"; continue; }
    fi
    echo "   ❌ 编译失败："
    head -15 "$OUT.err"
    rm -f "$OUT" "$OUT.err"
    exit 1
done

if [ ! -f "$OUT" ]; then
    echo "   ❌ 探针未产出（检查 $OUT.err）"
    rm -f "$OUT.err"
    exit 1
fi

timeout 300 "$OUT" > "$OUT.out" 2>&1
rc=$?

# 摘要
grep -E "put 成功数|记录数|不变量|计数精确|容量约束|→ |RESULT" "$OUT.out" \
    | sed 's/^/   /'

if [ $rc -ne 0 ]; then
    echo "   ---- 完整输出（尾 25 行）----"
    tail -25 "$OUT.out"
fi

if [ $rc -eq 0 ]; then
    echo "   RESULT: PASS"
else
    echo "   RESULT: FAIL"
fi

rm -f "$OUT" "$OUT.err" "$OUT.out"
exit $rc
