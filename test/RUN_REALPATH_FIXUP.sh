#!/bin/sh
# 8.2 修复单元测试：realpath 返回值反向翻译（源码级，见 probe_realpath_fixup.c 头注）
# 用法：sh test/RUN_REALPATH_FIXUP.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
OUT="/tmp/rpwork-realpath-probe.$$"

echo "▶️  realpath 返回值反向翻译（源码级单元）"

# gcc13 间歇 ICE：重试 + 降优化级（与 RUN_D3_FIXUP.sh 同策略）
OPT="-O2"
for i in 1 2 3 4; do
    if $CC $OPT -Wall -Wextra -Wformat=2 -Wno-nonnull-compare -Wno-unused-parameter \
        -Wno-format-truncation \
        -I"$ROOT/src/l2s" -I"$ROOT/src/proc" -DFAKEROOT_PURE_LOGIC -DPX_PURE_LOGIC=0 \
        -Wl,--allow-multiple-definition \
        -o "$OUT" "$ROOT/test/probe_realpath_fixup.c" "$ROOT/src/l2s/l2s.c" \
        "$ROOT/src/l2s/l2s-runtime.c" "$ROOT/src/runtime/fakeroot.c" \
        "$ROOT/src/runtime/crash.c" "$ROOT/src/runtime/sigsys.c" \
        "$ROOT/src/runtime/syscall_guard.c" "$ROOT/src/runtime/livepatch.c" \
        "$ROOT/src/proc/proc.c" -ldl -lpthread 2>"$OUT.err"; then
        break
    fi
    if grep -q "internal compiler error" "$OUT.err" && [ "$OPT" = "-O2" ]; then
        OPT="-O1"; continue
    fi
    if grep -q "internal compiler error" "$OUT.err" && [ "$OPT" = "-O1" ]; then
        OPT="-O0"; continue
    fi
    echo "   ❌ 编译失败（非 ICE）："
    head -20 "$OUT.err"
    rm -f "$OUT" "$OUT.err"
    exit 1
done

if [ ! -f "$OUT" ]; then
    echo "   ❌ 探针未产出（编译失败，检查 $OUT.err）"
    rm -f "$OUT.err"
    exit 1
fi

BXROOT_NO_AUTORUN=1 "$OUT"
rc=$?
rm -f "$OUT" "$OUT.err"

if [ $rc -eq 0 ]; then
    echo "   RESULT: PASS"
else
    echo "   RESULT: FAIL"
fi
exit $rc
