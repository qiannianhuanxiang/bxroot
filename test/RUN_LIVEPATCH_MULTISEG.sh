#!/bin/sh
# ---------------------------------------------------------------------
# livepatch 扫描必须覆盖 libc 的**全部** r-x 段（2026-10-09 真机缺陷）
#
# 真机（DSHA 自带 glibc 2.39-0ubuntu8.5）：版本表(按 8.9)不命中，却把页改
# RWX 不复位，libc 的 r-x 被劈成多段；旧扫描只看第一段，99/293 站点在后段
# → 0 命中 → node 新线程 rseq/set_robust_list 撞 seccomp，SIGSYS 杀进程。
#
# 判别力：恢复旧版（只取第一段的 find_libc_exec_range）本测试变红。
# 退出：0 通过 / 1 失败 / 0 跳过（非 aarch64）
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
case "$(uname -m)" in aarch64|arm64) ;; *) echo "⏭️  跳过：非 aarch64"; exit 0 ;; esac
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-lvms-XXXXXX")
trap 'rm -rf "$W"' EXIT
NCC=${NATIVE_CC:-gcc}
i=1
while [ "$i" -le 12 ]; do
    "$NCC" -O1 -w -D_GNU_SOURCE -I"$ROOT/src/runtime" -o "$W/t" \
        "$ROOT/test/livepatch/probe_livepatch_multiseg.c" \
        "${LIVEPATCH_SRC:-$ROOT/src/runtime/livepatch.c}" 2>"$W/cc.err" && break
    grep -q 'internal compiler error' "$W/cc.err" || { echo "❌ 编译失败"; head -20 "$W/cc.err"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/t" ] || { echo "❌ 未产出可执行文件"; exit 1; }
out=$("$W/t" 2>&1); rc=$?
echo "$out"
[ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q '^RESULT: PASS$'
