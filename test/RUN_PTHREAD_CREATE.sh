#!/bin/sh
# =====================================================================
# pthread_create 栈下限修正 —— A/B 对照验收
# =====================================================================
#
# 为什么需要这个脚本
# ------------------
# bxroot 的 pthread_create 钩子补的是"官方 runtime 有、bxroot 没有"的
# 一个行为：**把小于 max(2*PTHREAD_STACK_MIN, 256K) 的显式栈请求抬到该下限**。
# 这个行为无法用"符号是否存在"来验收（符号存在 ≠ 行为一致），
# 必须**真起线程、读回真实栈大小**才算数。
#
# ★ 三条踩过的坑，本脚本按正确写法固化 ★
#
#   1. `--preload` 与 guest exe 只认**内核视角**路径
#      （容器视角 /root/x 在内核里是 $ROOTFS/root/x）。
#      给容器视角 → 加载器算错 lib_dir → SIGSEGV(139) / SIGILL(132)。
#   2. 官方库目录必须从 /proc/*/maps 探测 —— shell 的 test/ls 走
#      翻译后的视图，**看不到** /data/app。探测到的那个路径就是内核视角，
#      不能再加 /proc/<pid>/root 前缀（加了会 SIGSEGV）。
#   3. 官方 runtime 只认 `PROROOT_*`，bxroot 只认 `BXROOT_*`
#      （官方 strings 里 BXROOT 计数为 0）。两侧各设各的才是对照实验。
#
# 用法
# ----
#   sh test/RUN_PTHREAD_CREATE.sh          # 跑全部对照
#   sh test/RUN_PTHREAD_CREATE.sh -v       # 额外打印每档明细
#
# 退出码
# ------
#   0 = 全部通过 / 1 = 有失败 / 2 = 环境不具备（缺 rootfs、缺官方 runtime）
#
# ★ 本脚本**不**被 test/RUN_ALL.sh 调用 ★
#   它需要真实的 proroot 官方库（/data/app 下的 .so），
#   在纯 Ubuntu 容器里不存在。RUN_ALL.sh 的判据因此保持不变。
# =====================================================================

set -u

VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
BXROOT_SO="${BXROOT_SO:-$ROOT/build/libbxroot-runtime.so}"

# 官方 runtime 的来源：优先环境变量，其次仓库内的 parity 存档
OFFICIAL_SO="${OFFICIAL_SO:-$ROOT/work/parity/off/libproroot-runtime.so}"

# ---------------------------------------------------------------------
# 环境探测
# ---------------------------------------------------------------------
if [ ! -d "$ROOTFS" ]; then
    echo "⏭️  跳过：找不到 rootfs（$ROOTFS）—— 本脚本只在真机容器里可跑"
    exit 2
fi
if [ ! -f "$BXROOT_SO" ]; then
    echo "❌ 找不到 bxroot 产物 $BXROOT_SO（先跑 sh BUILD_RUNTIME.sh）"
    exit 1
fi
if [ ! -f "$OFFICIAL_SO" ]; then
    echo "❌ 找不到官方 runtime $OFFICIAL_SO"
    echo "   可用 OFFICIAL_SO=<路径> 指定"
    exit 2
fi

detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}
APP_LIB="${APP_LIB:-$(detect_app_lib)}"
if [ -z "${APP_LIB:-}" ]; then
    echo "⏭️  跳过：探测不到官方库目录（/proc/*/maps 里没有 libproroot-bridge.so）"
    exit 2
fi

# ---------------------------------------------------------------------
# 落地目录：两个视角各用一次（见上文坑 1）
# ---------------------------------------------------------------------
# ★ 建目录/复制/删除**必须用 Python**（坑 4）★
#   `mkdir -p "$ROOTFS/xxx"` 会返回 rc=0 但目录**并不存在** ——
#   proroot 的双重翻译把前缀又套了一层，属静默失败。实测：
#     $ mkdir -p "$ROOTFS/tmp/probe-test" ; echo rc=$?   → rc=0
#     $ ls -ld  "$ROOTFS/tmp/probe-test"                 → No such file or directory
#   紧接着 `cp` 到该路径也会失败（"cannot create regular file ..."）。
#   Python 的 os.makedirs / shutil.copyfile 走真实 syscall 序列，能正确落地。
mkdir_rootfs_dir() {
    python3 - "$1" <<'PYEOF' || return 1
import os, sys
os.makedirs(sys.argv[1], exist_ok=True)
sys.exit(0 if os.path.isdir(sys.argv[1]) else 1)
PYEOF
}
copy_rootfs_file() {
    python3 - "$1" "$2" <<'PYEOF' || return 1
import shutil, sys, os
shutil.copyfile(sys.argv[1], sys.argv[2])
sys.exit(0 if os.path.isfile(sys.argv[2]) else 1)
PYEOF
}
rm_rootfs_dir() {
    python3 - "$1" <<'PYEOF' || true
import shutil, sys, os
if os.path.isdir(sys.argv[1]):
    shutil.rmtree(sys.argv[1], ignore_errors=True)
PYEOF
}

STAGE_MKDIR="${BXROOT_STAGE:-$ROOTFS/tmp/bxroot-pthread-$$}"
STAGE_LOAD="$STAGE_MKDIR"          # 已是内核视角，供 --preload 使用
mkdir_rootfs_dir "$STAGE_MKDIR" || { echo "❌ 无法创建 $STAGE_MKDIR"; exit 2; }
copy_rootfs_file "$BXROOT_SO"   "$STAGE_MKDIR/libbxroot-runtime.so"  || { echo "❌ 复制 bxroot 运行时失败"; exit 2; }
copy_rootfs_file "$OFFICIAL_SO" "$STAGE_MKDIR/libproroot-runtime.so" || { echo "❌ 复制官方运行时失败"; exit 2; }

# 探针落地到内核视角
PROBE_DIR="$ROOTFS/root/.bxroot-pthread-probe-$$"
mkdir_rootfs_dir "$PROBE_DIR" || exit 2
CC="${CC:-gcc}"

build_probe() {
    name="$1"; shift
    src="$SELF_DIR/pthread_create_probe.c"
    [ -f "$src" ] || { echo "❌ 缺少探针源码 $src"; exit 2; }
    i=1
    while [ "$i" -le 6 ]; do
        if "$CC" "$@" -o "$PROBE_DIR/$name" "$src" -lpthread 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
    done
    echo "❌ 探针 $name 编译失败（已重试，可能是 gcc 间歇性 ICE）"
    return 1
}
build_probe thrprobe -O1 || exit 2

run_side() {
    who="$1"; rt="$2"; shift 2
    if [ "$who" = off ]; then
        env PROROOT_ROOTFS="$ROOTFS" PROROOT_TMP_DIR="$STAGE_LOAD/tmp" \
            PROROOT_GUEST_EXE="$PROBE_DIR/thrprobe" \
            timeout 120 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
            --argv0 thrprobe --preload "$rt" "$PROBE_DIR/thrprobe" "$@" 2>&1
    else
        env BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" \
            BXROOT_WORKDIR="/" BXROOT_FAKEROOT=1 BXROOT_LINK2SYMLINK=1 \
            BXROOT_GUEST_EXE="$PROBE_DIR/thrprobe" \
            timeout 120 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
            --argv0 thrprobe --preload "$rt" "$PROBE_DIR/thrprobe" "$@" 2>&1
    fi
}

PASS=0; FAIL=0
cleanup() { rm_rootfs_dir "$STAGE_MKDIR"; rm_rootfs_dir "$PROBE_DIR"; }
trap cleanup EXIT INT TERM

echo "== pthread_create 栈下限修正：A/B 对照 =="
echo "   rootfs   : $ROOTFS"
echo "   官方 rt  : $OFFICIAL_SO"
echo "   bxroot rt: $BXROOT_SO"
echo "   官方库目录: $APP_LIB"
echo

# ---------------------------------------------------------------------
# 用例 1：四个档位的创建结果（128K 是原本 EINVAL 的那档）
# ---------------------------------------------------------------------
echo "--- 用例 1：四档栈大小 ---"
SHOWN=0
for sz in 131072 135168 262144 524288; do
    b=$(run_side bx "$STAGE_LOAD/libbxroot-runtime.so" "$sz")
    rc=$?
    line=$(echo "$b" | grep -E 'RESULT' | head -1)
    if [ "$rc" = 0 ] && [ -n "$line" ]; then
        echo "   ✅ size=$sz  $line"
        PASS=$((PASS + 1))
    else
        echo "   ❌ size=$sz  rc=$rc  $(echo "$b" | tail -1)"
        FAIL=$((FAIL + 1))
    fi
    [ "$VERBOSE" = 1 ] && { echo "$b" | sed 's/^/        /'; SHOWN=1; }
done

# ---------------------------------------------------------------------
# 用例 2：与官方的真实栈大小逐档一致（这是真正的 parity 判据）
# ---------------------------------------------------------------------
echo "--- 用例 2：与官方真实栈大小对照 ---"
for sz in 131072 135168 147456 262143 262144 524288; do
    o=$(run_side off "$STAGE_LOAD/libproroot-runtime.so" "$sz" | grep -oE '真实栈=[0-9]+')
    b=$(run_side bx  "$STAGE_LOAD/libbxroot-runtime.so"  "$sz" | grep -oE '真实栈=[0-9]+')
    if [ -n "$o" ] && [ "$o" = "$b" ]; then
        echo "   ✅ size=$sz  官方 $o = bxroot $b"
        PASS=$((PASS + 1))
    else
        echo "   ❌ size=$sz  官方 [$o] != bxroot [$b]"
        FAIL=$((FAIL + 1))
    fi
done

# ---------------------------------------------------------------------
# 用例 3：压力测试（32 轮小栈 + TLS + 16KB 栈上变量）
# ---------------------------------------------------------------------
echo "--- 用例 3：压力测试（与官方逐字对照）---"
o=$(run_side off "$STAGE_LOAD/libproroot-runtime.so" --stress | tail -1)
b=$(run_side bx  "$STAGE_LOAD/libbxroot-runtime.so"  --stress | tail -1)
if [ -n "$b" ] && [ "$o" = "$b" ]; then
    echo "   ✅ 官方 [$o] = bxroot [$b]"
    PASS=$((PASS + 1))
else
    echo "   ❌ 官方 [$o] != bxroot [$b]"
    FAIL=$((FAIL + 1))
fi

echo
echo "----------------------------------------"
if [ "$FAIL" = 0 ]; then
    echo "✅ pthread_create 对照全部通过（$PASS 项）"
    exit 0
fi
echo "❌ 通过 $PASS / 失败 $FAIL"
exit 1
