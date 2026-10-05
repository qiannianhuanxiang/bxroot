#!/bin/sh
# ---------------------------------------------------------------------
# 无 PT_INTERP 的 ELF：静态 EXEC / static-PIE / ld.so 自身 / ldd（行动清单 #6）
#
# 【缺陷】trampoline 的 linker 只装载动态可执行文件，于是 bxroot 下：
#   静态程序        → loader: failed no PT_DYNAMIC
#   static-PIE      → reloc: unsupported type 0（ldconfig.real 即此类）
#   ld.so --version → SIGSEGV
#   ldd /bin/true   → "not a dynamic executable"（成功形状的错答案）
# 官方 runtime 经 stub-loader 全部正常。现 proc.c 对无 PT_INTERP 的 aarch64
# ELF 改走 stub-loader（PROROOT_STUB_LOADER）。
#
# 【判据】（全部在 bxroot 下，经 guest 的 /bin/sh exec —— 即 runtime 的
#   exec 钩子路径）
#   A. 静态 EXEC、static-PIE 在**非默认 rootfs** 下读到 rootfs 内的标记文件
#      （证明不只是"能跑"，路径翻译也生效）
#   B. ld.so --version 正常；`ld.so <动态程序>` 在非默认 rootfs 下翻译生效
#   C. ldd /bin/true 输出与**官方 runtime 作内层**时逐行一致（地址归一）
#   D. posix_spawn（带 file_actions + attr）静态/动态程序都正常
#   E. 动态程序不受影响（仍走 trampoline）
# 需要外层 proroot（提供 bridge/linker/stub-loader 与注入链路）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime"; exit 2; }
[ -n "${PROROOT_STUB_LOADER:-}" ] || { echo "⏭️  跳过：环境无 PROROOT_STUB_LOADER"; exit 2; }

W=$(mktemp -d /tmp/bxroot-static-XXXXXX)
trap 'rm -rf "$W"' EXIT
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# 非默认 rootfs：复用宿主 /usr（只读用），自带 /etc 标记与 /tmp
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp"
# ★ 必须是**相对**链接 ★ 绝对的 `/usr` 在内核视角指向 Android 的真根
# （那里没有 /usr），bxroot-run 找不到 /bin/sh。相对链接 ../../../usr
# 在两个视角下都落到容器自己的 /usr（$RF = /tmp/<dir>/rf）。
ln -s ../../../usr "$RF/usr"
ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
echo "INSIDE-ROOTFS" > "$RF/etc/bx-static-marker"

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
P="$ROOT/test/static/probe_static_read.c"
bld -O1 -static     -o "$RF/tmp/p_static" "$P" || { echo "⏭️  跳过：无静态 libc"; exit 2; }
bld -O1 -static-pie -o "$RF/tmp/p_spie"   "$P" || { echo "⏭️  跳过：不支持 static-pie"; exit 2; }
bld -O1             -o "$RF/tmp/p_dyn"    "$P" || exit 1
bld -O1             -o "$RF/tmp/p_spawn"  "$ROOT/test/static/probe_spawn.c" || exit 1

# 符号链接 /usr 在 rootfs 里指向宿主 /usr —— 外层视角即 $PROROOT_ROOTFS/usr，
# 与 guest 的 /usr 同一目录，动态程序与 ld.so 可用。
run_rf() { timeout 60 "$BX" --no-check --rootfs "$RF" -- /bin/sh -c "$1" 2>&1; }

echo "--- A) 静态程序（非默认 rootfs）---"
o=$(run_rf '/tmp/p_static')
[ "$o" = "marker=INSIDE-ROOTFS" ] && good "静态 EXEC 读到 rootfs 内文件" || bad "静态 EXEC：$o"
o=$(run_rf '/tmp/p_spie')
[ "$o" = "marker=INSIDE-ROOTFS" ] && good "static-PIE 读到 rootfs 内文件" || bad "static-PIE：$o"

echo "--- B) ld.so 直接调用 ---"
# 经 guest 的 sh 调用（= runtime 的 exec 钩子路径，本修复所在处）。
# bxroot-run **顶层**直接把 ld.so 交给 bridge/linker 仍会段错误 —— 那是
# 外层加载器的入口，官方 runtime 作内层时同样如此，不在本项范围。
o=$(timeout 60 "$BX" --no-check -- /bin/sh -c '/lib/ld-linux-aarch64.so.1 --version' 2>&1 | head -1)
case "$o" in ld.so*) good "ld.so --version：$o" ;; *) bad "ld.so --version：$o" ;; esac
o=$(run_rf '/lib/ld-linux-aarch64.so.1 /tmp/p_dyn')
[ "$o" = "marker=INSIDE-ROOTFS" ] && good "ld.so <动态程序> 路径翻译生效" || bad "ld.so <prog>：$o"

echo "--- C) ldd 与官方一致 ---"
OFF=/proc/$$/root$PROROOT_LIB_PATH
if cp "$OFF" "$W/off-rt.so" 2>/dev/null; then
    norm() { sed -E 's/\(0x[0-9a-f]+\)/(ADDR)/; s#/lib/ld-linux-aarch64.so.1 => .*#/lib/ld-linux-aarch64.so.1 => LDSO#'; }
    timeout 60 "$BX" --no-check -- /usr/bin/ldd /bin/true 2>&1 | norm > "$W/bx"
    BXROOT_RUN_RUNTIME="$W/off-rt.so" timeout 60 "$BX" --no-check -- /usr/bin/ldd /bin/true 2>&1 | norm > "$W/off"
    if cmp -s "$W/bx" "$W/off" && grep -q 'libc.so.6 =>' "$W/bx"; then
        good "ldd /bin/true 与官方逐行一致（$(wc -l < "$W/bx") 行）"
    else
        bad "ldd 不一致："; diff "$W/off" "$W/bx" | head -6
    fi
else
    echo "  ⏭️  C 跳过：读不到官方 runtime 做对照"
fi

echo "--- D) posix_spawn（带 file_actions + attr）---"
# spawn 走的是另一条 trampoline（px_trampoline_spawn），曾漏掉静态分支：
# fork+exec 已修好时，C 程序 posix_spawn 静态程序仍 "no PT_DYNAMIC"。
o=$(run_rf '/tmp/p_spawn /tmp/p_static' | tr '\n' ' ')
case "$o" in "marker=INSIDE-ROOTFS spawn r=0 status=0 ") good "posix_spawn 静态程序，翻译生效" ;;
             *) bad "posix_spawn 静态：$o" ;; esac
o=$(run_rf '/tmp/p_spawn /tmp/p_dyn' | tr '\n' ' ')
case "$o" in "marker=INSIDE-ROOTFS spawn r=0 status=0 ") good "posix_spawn 动态程序照常" ;;
             *) bad "posix_spawn 动态：$o" ;; esac

echo "--- E) 动态程序不受影响 ---"
o=$(run_rf '/tmp/p_dyn')
[ "$o" = "marker=INSIDE-ROOTFS" ] && good "动态程序照常（trampoline 路径）" || bad "动态程序：$o"

echo "--- F) 有 CFG blob 时不注入 STUB_ROOTFS ---"
# 官方 runtime 从不写 PROROOT_STUB_ROOTFS。bxroot 在无 CFG 时仍要注入
# （自己的 launcher 路径），有 PROROOT_CFG_FD 时必须剥掉，否则 beta stub
# 的 renameat 落到 Android /etc overlay → ldconfig.real EROFS。
# 探针是静态 ELF，必定走 px_stub_prepare。
bld -O1 -static -o "$RF/tmp/p_env" "$ROOT/test/static/probe_stub_env.c" \
    || { echo "⏭️  F 跳过：静态探针编不过"; }
if [ -x "$RF/tmp/p_env" ]; then
    o=$(run_rf '/tmp/p_env' | tr '\n' ' ')
    case "$o" in
        *"PROROOT_STUB_ROOTFS=SET"*"PROROOT_CFG_FD=EMPTY"*)
            good "无 CFG_FD：注入 STUB_ROOTFS" ;;
        *)
            bad "无 CFG_FD 期望 STUB_ROOTFS=SET CFG_FD=EMPTY，实得 '$o'" ;;
    esac
    # 只需要环境变量非空；blob 文件存在与否不影响 inject_stub_rootfs 判定。
    o=$(
        export PROROOT_CFG_FD="/tmp/bxroot-cfg-dummy-$$"
        run_rf '/tmp/p_env' | tr '\n' ' '
    )
    case "$o" in
        *"PROROOT_STUB_ROOTFS=EMPTY"*"PROROOT_CFG_FD=SET"*)
            good "有 CFG_FD：不注入 STUB_ROOTFS" ;;
        *)
            bad "有 CFG_FD 期望 STUB_ROOTFS=EMPTY CFG_FD=SET，实得 '$o'" ;;
    esac
fi

echo "--- G) 静态程序的 rename/link/unlink 等路径类 syscall ---"
# 官方 stub-loader 只翻译 openat/stat，对绝对路径的 renameat/linkat/unlinkat/
# faccessat/fchmodat/truncate 不翻译（ldconfig.real 写 ld.so.cache 时 rename
# 落到宿主只读 /etc → EROFS）。进程内执行（src/runtime/static_exec.c）把这些
# svc 站点接回 runtime 的路径翻译。判据：全部成功，且宿主 /etc 没有泄漏。
bld -O1 -static     -o "$RF/tmp/p_fs"  "$ROOT/test/static/probe_static_fsops.c" || true
bld -O1 -static-pie -o "$RF/tmp/p_fsp" "$ROOT/test/static/probe_static_fsops.c" || true
for v in p_fs p_fsp; do
    [ -x "$RF/tmp/$v" ] || continue
    rm -rf /etc/bx-fs-* 2>/dev/null
    o=$(run_rf "/tmp/$v" | tr '\n' ' ')
    [ "$o" = "fsops=OK " ] && good "$v：路径类 syscall 全部成功" || bad "$v：$o"
    leak=$(ls -d /etc/bx-fs-* 2>/dev/null | tr '\n' ' ')
    [ -z "$leak" ] && good "$v：宿主 /etc 无泄漏" || { bad "$v：宿主 /etc 泄漏 $leak"; rm -rf /etc/bx-fs-*; }
done

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
