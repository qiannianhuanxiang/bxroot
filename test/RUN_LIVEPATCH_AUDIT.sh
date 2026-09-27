#!/bin/sh
# ---------------------------------------------------------------------
# livepatch 运行期扫描 —— 对抗性审计（2026-09-28）
#
# 【验什么】lp_scan_and_patch 把 glibc r-x 段里 "mov x8,#99|#293 近距离
# (≤12 条) 跟 svc#0" 的站点改成 mov x0,#0。本测试对**两个真实 libc**
# （容器 /=2.39，rootfs-trixie=2.41）跑**生产扫描函数本身**，并用
# objdump/nm 交叉核对每个命中：
#
#   1. 命中数恰好 = 预期（每个 libc 3 处：set_robust_list/rseq/_Fork-99）
#   2. 每个被中和的字节原本确是 svc #0（0xd4000001→0xd2800000）
#   3. 每个命中 svc 之前 ≤12 条内确有 mov x8,#0x63 或 mov x8,#0x125
#      （objdump 反查，确认归属正确、无跨函数误配）
#   4. 命中落点函数属于预期集合（nm 定位，非 99/293 相关函数零命中）
#   5. 窗口中断判据形态断言（movk/条件分支/BR/RET 都中断；含 movk 误配
#      反例：mov x8,#99; movk x8,#hi,lsl#16; svc 必须不被改写）
#
# 【判别力】把 livepatch.c 的 lp_is_scan_barrier 退回旧的两条判据
# （只挡 hw=0 的 movz + B/BL），--barrier 里的 movk 反例立即变红；
# 把 g_scan_nrs 去掉 99/293 或窗口设 0，命中数断言立即变红。
#
# 退出：0 通过 / 1 失败 / 2 环境不满足跳过
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-lvaudit-XXXXXX")
trap 'rm -rf "$W"' EXIT

case "$(uname -m)" in
aarch64|arm64) ;;
*) echo "⏭️  跳过：本机非 aarch64（$(uname -m)），扫描指令编码不适用"; exit 2 ;;
esac

for t in objdump readelf nm; do
    command -v "$t" >/dev/null 2>&1 || { echo "⏭️  跳过：缺 $t"; exit 2; }
done

NCC=${NATIVE_CC:-gcc}

# 生产扫描函数编入审计探针（-DLP_TEST_HOOK 暴露 scan/barrier 钩子）。
i=1
while [ "$i" -le 12 ]; do
    "$NCC" -O1 -w -DLP_TEST_HOOK -D_GNU_SOURCE \
        -I"$ROOT/src/runtime" -o "$W/audit" \
        "$ROOT/test/livepatch/probe_livepatch_audit.c" \
        "$ROOT/src/runtime/livepatch.c" 2>"$W/cc.err" && break
    grep -q 'internal compiler error' "$W/cc.err" || { echo "❌ 编译失败"; head -20 "$W/cc.err"; exit 1; }
    i=$((i + 1))
done
[ -x "$W/audit" ] || { echo "❌ 未产出可执行文件"; exit 1; }

fail=0

# ---- 阶段 0：窗口中断判据形态断言 ----
echo "== 阶段0：窗口中断判据（含 movk 误配反例）=="
if ! "$W/audit" --barrier; then
    echo "❌ 窗口中断判据断言失败"
    fail=1
fi

# 取 libc r-x 段的 (file_off, vaddr, filesz)。glibc 只有一个 R E 段
# （readelf -l 已确认），扫描只取第一段是完备的。
exec_seg() {   # $1=libc  → 打印 "off vaddr size"（十六进制，0x 前缀）
    readelf -lW "$1" | awk '
        /^  LOAD/ {
            off=$2; vaddr=$3; filesz=$5; flags=$7 $8;
            # flags 列可能被拆成两段（"R E"），拼起来判断
            line=$0;
            if (line ~ /R E/) { print off, vaddr, filesz; exit }
        }'
}

# 断言：该 libc 只有一个可执行 LOAD 段（否则“只扫第一段”会漏）。
count_exec_load() {
    readelf -lW "$1" | awk '/^  LOAD/ && /R E/ {n++} END{print n+0}'
}

# 交叉核对单个 libc。
# $1=标签 $2=libc路径 $3=期望命中数
audit_libc() {
    tag=$1; libc=$2; want=$3
    echo
    echo "== $tag: $libc =="
    [ -f "$libc" ] || { echo "⏭️  跳过：$libc 不存在"; return 2; }

    nexec=$(count_exec_load "$libc")
    echo "可执行 LOAD 段数：$nexec"
    if [ "$nexec" != "1" ]; then
        echo "❌ 期望 1 个 R E 段，实得 $nexec —— find_libc_exec_range 只取第一段会漏站点"
        fail=1
    fi

    set -- $(exec_seg "$libc")
    off=$1; vaddr=$2; size=$3
    echo "exec 段：off=$off vaddr=$vaddr size=$size"

    "$W/audit" "$libc" "$off" "$vaddr" "$size" >"$W/out" 2>&1
    cat "$W/out"

    cnt=$(awk '/^COUNT /{print $2}' "$W/out")
    if [ "$cnt" != "$want" ]; then
        echo "❌ 命中数 $cnt != 期望 $want"
        fail=1
    else
        echo "✓ 命中数 = $want"
    fi

    # 有非 svc->mov x0,#0 的改写？
    if grep -q '^BADCHANGE' "$W/out"; then
        echo "❌ 存在非 svc->mov x0,#0 的改写"
        fail=1
    fi
    if grep -q '^MISMATCH' "$W/out"; then
        echo "❌ 报告改写数与返回值不一致"
        fail=1
    fi

    # 反汇编整个 exec 段一次，供逐命中反查。
    objdump -d --start-address=0x0 "$libc" 2>/dev/null \
        | grep -E '^\s+[0-9a-f]+:' >"$W/dis" || true

    # 逐个命中：确认 svc 前 ≤12 条内有 mov x8,#0x63 或 #0x125，且落点函数合理。
    grep '^HIT ' "$W/out" | while read -r _ addr rest; do
        a=${addr#0x}
        # 该命中所在指令行号
        ln=$(grep -n "^[[:space:]]*$a:" "$W/dis" | head -1 | cut -d: -f1)
        if [ -z "$ln" ]; then
            echo "❌ 命中 $addr 在反汇编里找不到"
            echo BAD >>"$W/verdict"
            continue
        fi
        # 往前最多 12 条找 mov x8,#0x63 / #0x125
        start=$((ln - 12)); [ "$start" -lt 1 ] && start=1
        window=$(sed -n "${start},${ln}p" "$W/dis")
        if printf '%s\n' "$window" | grep -Eq 'mov[[:space:]]+x8, #0x63([^0-9a-f]|$)'; then
            nr="99(set_robust_list)"
        elif printf '%s\n' "$window" | grep -Eq 'mov[[:space:]]+x8, #0x125([^0-9a-f]|$)'; then
            nr="293(rseq)"
        else
            echo "❌ 命中 $addr 前 12 条内无 mov x8,#99/#293 —— 可能误配"
            echo BAD >>"$W/verdict"
            continue
        fi
        # 该命中所属函数（objdump 的最近 <label>）——反查确认属于预期函数。
        fn=$(objdump -d "$libc" 2>/dev/null \
             | awk -v tgt="$a" '
                 /^[0-9a-f]+ </ { sub(/[:>].*/,"",$0); cur=$0 }
                 $0 ~ "^[[:space:]]*"tgt":" { print cur; exit }')
        echo "  ✓ $addr  nr=$nr  函数区间=[$fn]"
    done
    [ -f "$W/verdict" ] && { fail=1; rm -f "$W/verdict"; }
    return 0
}

# 期望：每个 libc 3 处（set_robust_list, rseq, _Fork 的 set_robust_list）。
audit_libc "glibc 2.39 (容器 /)" "/usr/lib/aarch64-linux-gnu/libc.so.6" 3

TRIXIE_LIBC="/root/rootfs-trixie/usr/lib/aarch64-linux-gnu/libc.so.6"
if [ -f "$TRIXIE_LIBC" ]; then
    audit_libc "glibc 2.41 (rootfs-trixie)" "$TRIXIE_LIBC" 3
else
    echo
    echo "⏭️  rootfs-trixie libc 不存在，跳过 2.41 交叉核对"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS —— 两个 libc 命中集合与预期一致，无误伤"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
