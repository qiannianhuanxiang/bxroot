#!/bin/sh
# ---------------------------------------------------------------------
# livepatch 运行期指令扫描（2026-09-27）
#
# 【验什么】版本精确站点表只覆盖 2.39/2.41；换 glibc 就得人肉补偏移，
# 否则真机上 fork/pthread 子进程死于 SIGSYS(159)。新增的运行期扫描按
# 指令形态（mov x8,#99|#293 近距离跟 svc#0）中和这两个号，对任意 glibc
# 版本生效。本测试用 -DLP_TEST_HOOK 把 livepatch.c 的**真实扫描函数**
# 编入，对合成机器码断言：该改的改、不该碰的（别的号/夹写x8/超窗口）不碰。
#
# 判别力：把 livepatch.c 里 g_scan_nrs 改成不含 99/293，或把窗口设 0，
# 本测试立刻变红（改写数 != 2 或站点未改）。
#
# 端到端（真 2.41 rootfs、去掉版本表仍绿）由 RUN_ALT_ROOTFS.sh 覆盖。
# 退出：0 通过 / 1 失败
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${CC:-aarch64-linux-gnu-gcc-13}
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-lvscan-XXXXXX")
trap 'rm -rf "$W"' EXIT

bld() {   # 带 gcc13 ICE 重试
    i=1
    while [ "$i" -le 12 ]; do
        "$CC" "$@" 2>"$W/cc.err" && return 0
        grep -q 'internal compiler error' "$W/cc.err" || { cat "$W/cc.err"; return 1; }
        i=$((i + 1))
    done
    return 1
}

# livepatch.c 以 LP_TEST_HOOK 编入（暴露 scan_buffer_for_test），
# 与探针一起链成一个本机可执行文件。用本机 gcc（能直接跑）。
NCC=${NATIVE_CC:-gcc}
i=1
while [ "$i" -le 12 ]; do
    "$NCC" -O1 -w -DLP_TEST_HOOK -D_GNU_SOURCE \
        -I"$ROOT/src/runtime" \
        -o "$W/t" \
        "$ROOT/test/livepatch/probe_livepatch_scan.c" \
        "$ROOT/src/runtime/livepatch.c" 2>"$W/cc.err" && break
    grep -q 'internal compiler error' "$W/cc.err" || { echo "❌ 编译失败"; head -20 "$W/cc.err"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/t" ] || { echo "❌ 未产出可执行文件"; exit 1; }

# 仅当本机是 aarch64 才有意义（指令编码是 aarch64 的）。
case "$(uname -m)" in
aarch64|arm64) ;;
*) echo "⏭️  跳过：本机非 aarch64（$(uname -m)），扫描指令编码不适用"; exit 0 ;;
esac

out=$("$W/t" 2>&1)
echo "$out"
printf '%s\n' "$out" | grep -q '^RESULT: PASS$'