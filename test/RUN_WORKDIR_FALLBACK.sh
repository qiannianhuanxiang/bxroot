#!/bin/sh
# ---------------------------------------------------------------------
# workdir 不可用时的回退（上游 proot #307/#66：-w/$PWD 不在 rootfs 内）
#
# 被测：src/runtime/preload.c 构造函数里的 BXROOT_WORKDIR chdir。
# 上游语义：workdir 在 guest 里不存在 / 不是目录 → stderr 警告
#     "can't chdir to <dir>, falling back to /"
#   → chdir 到 rootfs 根 → $PWD 同步为 "/"。
#
# 为什么必须用**子目录 rootfs**（迷你 rootfs）而不能用容器自己的 /：
#   缺陷的可观测后果是"chdir 失败后 cwd 留在宿主启动目录"。若 rootfs 就是
#   容器的 /，宿主启动目录恰好也在 rootfs 里，getcwd 反翻译能把它剥干净，
#   现象被掩盖。rootfs 换成 /tmp 下的迷你目录后，宿主启动目录在 rootfs
#   **之外**：修复前 `/bin/pwd` 回显 /data/data/.../ubuntu/<宿主目录>
#   （宿主路径泄漏）、`cd .` 报 ENOENT；修复后回到 "/"。
#
# 判据（全部取自被测对象自己的痕迹，rc 不算）：
#   A. workdir 不存在      → 有警告；PWD=/；/bin/pwd=/；cd . 成功
#   B. workdir 是普通文件  → 同 A（errno ENOTDIR）
#   C. workdir 存在        → 无警告；PWD 与 /bin/pwd 都是该目录
#   D. 警告只打一次（DONE 标记生效：子进程 exec 不再重试/重置 cwd）
#   E. 回退后 guest 自己 cd 仍能被子进程继承（不被重置）
#   F. 官方 runtime 对照（可选，有 /tmp/off-rt.so 或 $OFFICIAL_SO 时）：
#      官方不读 *_WORKDIR（launcher 侧完成 chdir），只对照"不泄漏宿主路径"
#
# 退出码：0 通过，1 失败，2 环境不满足。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
OFFICIAL_SO="${OFFICIAL_SO:-/tmp/off-rt.so}"

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在官方 proroot 下，bxroot-run 链路不可用"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }
[ -x /bin/dash ] && [ -x /bin/pwd ] || { echo "⏭️  跳过：缺 dash 或 /bin/pwd"; exit 2; }

W=$(mktemp -d /tmp/bxroot-wd-XXXXXX)
trap 'rm -rf "$W"' EXIT
MINI="$W/rootfs"

# ---------------------------------------------------------------------
# 迷你 rootfs：dash + pwd + libc + ld.so，外加 /etc（作为"存在的 workdir"）
# ---------------------------------------------------------------------
LIBDIR=lib/aarch64-linux-gnu
mkdir -p "$MINI/bin" "$MINI/$LIBDIR" "$MINI/etc" "$MINI/tmp" "$MINI/dir with space" || exit 2
cp /bin/dash "$MINI/bin/dash" && ln -s dash "$MINI/bin/sh" && cp /bin/pwd "$MINI/bin/pwd" || exit 2
for f in libc.so.6 ld-linux-aarch64.so.1; do
    src=$(readlink -f "/$LIBDIR/$f" 2>/dev/null || readlink -f "/usr/$LIBDIR/$f")
    [ -f "$src" ] && cp "$src" "$MINI/$LIBDIR/$f" || { echo "⏭️  跳过：找不到 $f"; exit 2; }
done
ln -s "aarch64-linux-gnu/ld-linux-aarch64.so.1" "$MINI/lib/ld-linux-aarch64.so.1"
: > "$MINI/etc/afile"
mkdir -p "$W/hostcwd"      # 宿主启动目录，故意放在迷你 rootfs 之外

FAIL=0
bad() { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# run <workdir> <sh -c 脚本>：在宿主目录 $W/hostcwd 启动 guest
# stdout → $W/out，stderr → $W/err（去掉 livepatch/inject 噪声）
run() {
    _wd=$1; shift
    ( cd "$W/hostcwd" && BXROOT_WORKDIR=$_wd BXROOT_VERBOSE=0 \
        "$BX" --no-check --rootfs "$MINI" -- /bin/sh -c "$1" ) \
        >"$W/out" 2>"$W/err.raw"
    grep -v 'livepatch\|inject=\|glibc 线程' "$W/err.raw" > "$W/err" || true
}
PROBE='echo PWD=$PWD; echo BIN=$(/bin/pwd); if cd .; then echo DOT=ok; else echo DOT=fail; fi'

check_fallback() {   # $1 = 场景名 $2 = workdir
    run "$2" "$PROBE"
    if grep -q "^bxroot warning: can't chdir to $2 .*falling back to /" "$W/err"; then
        good "$1：有警告 $(grep -o "can't chdir.*" "$W/err" | head -1)"
    else
        bad "$1：缺少警告，stderr=$(head -c 200 "$W/err")"
    fi
    grep -qx 'PWD=/' "$W/out" && good "$1：\$PWD=/" || bad "$1：\$PWD 不是 /：$(grep PWD= "$W/out")"
    grep -qx 'BIN=/' "$W/out" && good "$1：/bin/pwd=/" || bad "$1：/bin/pwd 泄漏/错误：$(grep BIN= "$W/out")"
    grep -qx 'DOT=ok' "$W/out" && good "$1：cd . 成功" || bad "$1：cd . 失败（cwd 不在 rootfs 内）"
    if grep -q '/data/\|hostcwd' "$W/out"; then bad "$1：输出含宿主路径：$(cat "$W/out" | tr '\n' ' ')"; fi
}

echo "--- A) workdir 不存在 ---"
check_fallback A /nonexistent
echo "--- B) workdir 是普通文件 ---"
check_fallback B /etc/afile

echo "--- C) workdir 存在 ---"
run /etc "$PROBE"
[ -s "$W/err" ] && bad "C：不该有警告：$(head -1 "$W/err")" || good "C：无警告"
grep -qx 'PWD=/etc' "$W/out" && good "C：\$PWD=/etc" || bad "C：\$PWD：$(grep PWD= "$W/out")"
grep -qx 'BIN=/etc' "$W/out" && good "C：/bin/pwd=/etc" || bad "C：/bin/pwd：$(grep BIN= "$W/out")"

echo "--- D) 警告只打一次（DONE 标记）---"
run /nonexistent '/bin/pwd >/dev/null; /bin/pwd >/dev/null; sh -c "/bin/pwd" >/dev/null'
n=$(grep -c 'bxroot warning' "$W/err")
[ "$n" = 1 ] && good "D：3 次 exec 只有 1 条警告" || bad "D：警告条数 $n（应为 1）"

echo "--- E) 回退后 guest 的 cd 不被子进程 exec 重置 ---"
run /nonexistent 'cd /etc && echo SUB=$(sh -c /bin/pwd)'
grep -qx 'SUB=/etc' "$W/out" && good "E：子进程继承 /etc" || bad "E：$(grep SUB= "$W/out")"

echo "--- F) 官方 runtime 对照 ---"
if [ -f "$OFFICIAL_SO" ]; then
    ( cd "$W/hostcwd" && PROROOT_WORKDIR=/nonexistent BXROOT_RUN_RUNTIME=$OFFICIAL_SO \
        "$BX" --no-check --rootfs "$MINI" -- /bin/sh -c 'echo PWD=$PWD; echo BIN=$(/bin/pwd)' ) \
        >"$W/off" 2>&1
    if grep -q '/data/' "$W/off"; then
        echo "  ⚠️  官方也泄漏宿主路径：$(tr '\n' ' ' < "$W/off") —— 对照不可信"
    else
        good "官方：$(tr '\n' ' ' < "$W/off")（不泄漏宿主路径；bxroot 修后同样不泄漏）"
    fi
else
    echo "  ℹ️  无官方 runtime 副本（$OFFICIAL_SO），跳过对照"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "RESULT: PASS（6 组判据通过）"; exit 0; fi
echo "RESULT: FAIL（$FAIL 条）"; exit 1
