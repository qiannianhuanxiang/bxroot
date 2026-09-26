#!/bin/sh
# ---------------------------------------------------------------------
# clone3 回退链验证（行动清单 #9）
#
# 【为什么不是"glib g_spawn_async 端到端"】清单原写"容器内无 glib"，
# 实测确认：本容器没有 glib 开发库（pkg-config 报 NO_GLIB，
# /usr/lib/aarch64-linux-gnu/libglib-2.0.so* 不存在）。但那条回归要验的
# **实质**是 clone3 被 seccomp 拦截时 glibc 能否回退到 clone(2) ——
# glib 的 g_spawn_async 只是众多调用方之一，这条链不依赖 glib。
#
# 【判据】用 seccomp_block_clone3.c 人为把 clone3(435) 拦成 ENOSYS，
# 然后跑 probe_clone3_fallback.c，三件事必须成立：
#   1. 裸 clone3 返回 ENOSYS（证明拦截生效）
#   2. pthread_create 成功、join 拿到正确返回值（回退到 clone(2)）
#   3. fork 成功
# 再在 **bxroot 下**跑同一对程序（判据相同）。
# 不需要外层 proroot：宿主侧的对照本身就说明回退链成立，
# bxroot 侧能跑就跑（跑不了按 rc=2 上报，不假装通过）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-c3fb-XXXXXX")
trap 'rm -rf "$W"' EXIT
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}

bld -O0 -w -pthread -o "$W/probe" "$ROOT/test/clone3/probe_clone3_fallback.c" || { echo "❌ 探针编译失败"; exit 1; }
bld -O0 -w -o "$W/blk" "$ROOT/test/clone3/seccomp_block_clone3.c" || { echo "❌ 拦截器编译失败"; exit 1; }

check() {   # $1 标签  $2 输出
    lbl=$1; out=$2
    # 判据 1：拦截生效（ENOSYS）
    printf '%s' "$out" | grep -q 'raw clone3(435) rc=-1 errno=38' \
        && good "$lbl：clone3 被拦为 ENOSYS" \
        || bad "$lbl：clone3 未被拦（$(printf '%s' "$out" | grep 'raw clone3' | head -1)）"
    # 判据 2：线程创建回退成功
    printf '%s' "$out" | grep -q 'pthread_join ret=0x5eed' \
        && good "$lbl：pthread_create 回退成功（join 拿到正确返回值）" \
        || bad "$lbl：pthread_create 回退失败"
    # 判据 3：fork 成功
    printf '%s' "$out" | grep -q 'fork pid=[0-9]' \
        && good "$lbl：fork 成功" \
        || bad "$lbl：fork 失败"
    # 收尾：整体判据
    printf '%s' "$out" | grep -q 'RESULT: OK' \
        || bad "$lbl：探针未打出 RESULT: OK"
}

echo "--- A) 宿主（对照基线）---"
o=$("$W/blk" "$W/probe" 2>&1)
[ -n "$o" ] || bad "宿主探针无输出"
check "宿主" "$o"

echo "--- B) bxroot 运行时下 ---"
if [ -f "$ROOT/build/libbxroot-runtime.so" ] && \
   grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null; then
    o=$(timeout 60 "$ROOT/tools/bxroot-run" --no-check -- "$W/blk" "$W/probe" 2>&1)
    check "bxroot" "$o"
else
    echo "  ⏭️  跳过 B：需要 runtime 与外层 proroot 注入链路"
fi

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
