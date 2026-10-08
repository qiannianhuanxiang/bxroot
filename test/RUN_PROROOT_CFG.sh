#!/bin/sh
# ---------------------------------------------------------------------
# 官方 proroot launcher 配置块（PROROOT_CFG_FD）读取回归
#
# 场景：bxroot runtime 以 libproroot-runtime.so 之名替换进官方 DSHA APK 后，
# launcher 不设 BXROOT_*，只写 .proroot-config-<pid> 并 setenv
# PROROOT_CFG_FD=<路径>。PROROOT_ROOTFS 不一定会设。runtime 必须从中读出 -b，
# 并在环境变量缺失时从 blob +0x0000 / ESCAPE_FD 补 rootfs。
#
# ★ 加载方式 ★ 容器内 LD_PRELOAD 不生效（见 tools/bxroot-run 头注释），
# 用 LD_PRELOAD 会得到假绿。这里走 bridge + linker + --preload，并先做
# 注入自检（BXROOT_VERBOSE 日志里必须有 inject=1）。
#
# ★ 路径视角 ★ 配置块里的路径与 PROROOT_CFG_FD 都是内核视角
# （= $PROROOT_ROOTFS + 容器视角路径），与真实 launcher 一致。
#
# 用例：
#   A) 内核视角路径直读：bind 生效
#   B) 路径带 "//" "./" 冗余：规范化重试后生效
#   C) BXROOT_BINDS 显式给出：配置块被忽略
#   D) 配置块过短 / 不存在：不崩溃，bind 不生效
#   E) 条数越界（0xFFFFFFFF）：被钳制，不崩溃
#   F) 不设 PROROOT_ROOTFS：从 blob +0x0000 读出 rootfs 并 setenv
#   N) 对照：不设 PROROOT_CFG_FD 时 bind 不生效（证明 A 不是巧合）
# 退出码：0 通过 / 1 失败 / 2 环境不满足（无外层 proroot 等）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SO="$ROOT/build/libbxroot-runtime.so"
[ -f "$SO" ] || { echo "rc=2 跳过：没有 $SO"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "rc=2 跳过：没有 python3"; exit 2; }
HR=${PROROOT_ROOTFS:-}
[ -n "$HR" ] || { echo "rc=2 跳过：需要外层 proroot（无 PROROOT_ROOTFS）"; exit 2; }

APP=${BXROOT_RUN_APP_LIB:-}
if [ -z "$APP" ]; then
    for m in /proc/[0-9]*/maps; do
        p=$(grep -o '/data/app[^ ]*libproroot-bridge\.so' "$m" 2>/dev/null | head -1)
        [ -n "$p" ] && { APP=${p%/*}; break; }
    done
fi
[ -n "$APP" ] || { echo "rc=2 跳过：探测不到 proroot 库目录"; exit 2; }

BASE=${TMPDIR:-/tmp}
T=$(mktemp -d "$BASE/prcfg.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# 内核视角 = $PROROOT_ROOTFS + 容器视角绝对路径
case "$T" in /*) ;; *) echo "rc=2 跳过：临时目录不是绝对路径"; exit 2 ;; esac
K="$HR$T"
mkdir -p "$T/host"; echo "FROM-HOST-BIND" > "$T/host/f"
mkdir -p "$T/host2"; echo "FROM-ENV" > "$T/host2/f"
cp "$SO" "$T/rt.so"
L="$K/rt.so"

mkblob() {   # $1 输出  $2 条数  $3 host(内核视角)  $4 guest  $5 size  $6 rootfs
    python3 - "$@" <<'PY'
import struct, sys
out, n, host, guest = sys.argv[1], int(sys.argv[2], 0), sys.argv[3], sys.argv[4]
size = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x43130
rootfs = sys.argv[6] if len(sys.argv) > 6 else ''
b = bytearray(size)
if size >= 0x42118:
    struct.pack_into('<I', b, 0x42108, n)
    if n == 1:
        b[0x2008:0x2008 + len(guest)] = guest.encode()
        b[0x3008:0x3008 + len(host)] = host.encode()
    if rootfs:
        raw = rootfs.encode()[:4095]
        b[0:len(raw)] = raw
open(out, 'wb').write(b)
PY
}

# run_guest <额外 export 语句> -- <guest 程序 (内核视角)> [参数…]
run_guest() {
    _ex=$1; shift; shift
    (
        unset BXROOT_ROOTFS BXROOT_BINDS BXROOT_FAKEROOT BXROOT_L2S_DIR
        export PROROOT_ROOTFS="$HR"
        eval "$_ex"
        exec "$APP/libproroot-bridge.so" "$APP/libproroot-linker.so" \
            --argv0 guest --preload "$L" "$@"
    ) 2>&1
}
CAT="$HR/usr/bin/cat"; [ -e "$CAT" ] || CAT="$HR/bin/cat"

echo "== 注入自检"
log=$(run_guest 'export BXROOT_VERBOSE=1' -- "$HR/usr/bin/true")
case "$log" in
*inject=1*) good "runtime 已注入（inject=1）" ;;
*) echo "$log" | head -5; echo "rc=2 跳过：注入自检失败（此环境无法加载 bxroot）"; exit 2 ;;
esac

echo "== N 对照：不设 PROROOT_CFG_FD"
out=$(run_guest ':' -- "$CAT" /mnt/f)
case "$out" in *FROM-HOST-BIND*) bad "没有配置块却读到了 bind：'$out'" ;; *) good "bind 不生效（基线）" ;; esac

echo "== A 内核视角路径直读"
mkblob "$T/cfgA" 1 "$K/host" /mnt
out=$(run_guest "export PROROOT_CFG_FD='$K/cfgA'" -- "$CAT" /mnt/f)
[ "$out" = "FROM-HOST-BIND" ] && good "bind 生效" || bad "期望 FROM-HOST-BIND，实得 '$out'"

echo "== B 路径冗余（// 与 ./）"
out=$(run_guest "export PROROOT_CFG_FD='$K//./cfgA'" -- "$CAT" /mnt/f)
[ "$out" = "FROM-HOST-BIND" ] && good "规范化后生效" || bad "实得 '$out'"

echo "== C 显式 BXROOT_BINDS 优先"
out=$(run_guest "export PROROOT_CFG_FD='$K/cfgA' BXROOT_BINDS='$K/host2:/mnt'" -- "$CAT" /mnt/f)
[ "$out" = "FROM-ENV" ] && good "环境变量优先" || bad "期望 FROM-ENV，实得 '$out'"

echo "== D 损坏 / 缺失的配置块"
mkblob "$T/short" 1 "$K/host" /mnt 0x1000
for c in short nonexistent; do
    out=$(run_guest "export PROROOT_CFG_FD='$K/$c'" -- "$CAT" /mnt/f)
    case "$out" in *FROM-HOST-BIND*) bad "$c：不该生效，实得 '$out'" ;; *) good "$c：不崩溃且 bind 不生效" ;; esac
done

echo "== E 条数越界"
python3 - "$T/cfgE" <<'PY'
import struct, sys
b = bytearray(0x43130); struct.pack_into('<I', b, 0x42108, 0xFFFFFFFF)
open(sys.argv[1], 'wb').write(b)
PY
out=$(run_guest "export PROROOT_CFG_FD='$K/cfgE'" -- "$HR/usr/bin/echo" alive)
[ "$out" = "alive" ] && good "越界被钳制，进程正常" || bad "out='$out'"

echo "== F blob 补 rootfs（不设 PROROOT_ROOTFS / BXROOT_ROOTFS）"
MARK="/tmp/bxroot-cfg-rootfs-mark-$$"
mkblob "$T/cfgF" 0 /nope /nope 0x43130 "$MARK"
PRINTENV="$HR/usr/bin/printenv"; [ -e "$PRINTENV" ] || PRINTENV="$HR/bin/printenv"
out=$(
    unset BXROOT_ROOTFS BXROOT_BINDS BXROOT_FAKEROOT BXROOT_L2S_DIR PROROOT_ROOTFS
    export PROROOT_CFG_FD="$K/cfgF"
    exec "$APP/libproroot-bridge.so" "$APP/libproroot-linker.so" \
        --argv0 guest --preload "$L" "$PRINTENV" BXROOT_ROOTFS
)
[ "$out" = "$MARK" ] && good "blob +0x0000 → BXROOT_ROOTFS" || bad "BXROOT_ROOTFS='$out' 期望 '$MARK'"

echo
if [ "$FAIL" -eq 0 ]; then echo "PROROOT_CFG: 全部通过"; exit 0; fi
echo "PROROOT_CFG: $FAIL 项失败"; exit 1
