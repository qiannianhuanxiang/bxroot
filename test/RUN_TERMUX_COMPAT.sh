#!/bin/sh
# ---------------------------------------------------------------------
# Termux 路径兼容（src/runtime/termux_compat.h + translate_path 接法）端到端
#
# 判据（被测对象：真实 runtime 下 guest 程序看到的文件系统）：
#   a. $PREFIX/bin/{sh,env} 存在且可执行（映射到 /usr/bin）
#   b. $PREFIX/etc/passwd 读到 guest 的 /etc/passwd
#   c. Termux home 映射到 /root：在 /root 写的文件经 Termux home 路径读得到
#   d. $PREFIX/tmp 与 /tmp 是同一处：一边写、另一边读到
#   e. /data/user/0/com.termux 写法同样生效
#   f. cd 到 Termux home 后 pwd -P 是 /root（getcwd 反向翻译；不带 -P 的 pwd 是 shell 记的逻辑路径）
#   g. 含 .. 的 Termux 路径先夹紧再映射
#   h. BXROOT_NO_TERMUX_COMPAT=1 时不映射
#
# 环境不满足（不在外层 proroot、缺 runtime 产物）→ rc=2 跳过。
# 用 BXROOT_RUN_RUNTIME=<so> 指定被测 runtime。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
RT=${BXROOT_RUN_RUNTIME:-$ROOT/build/libbxroot-runtime.so}

grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在外层 proroot 下，bxroot-run 无法注入"; exit 2; }
[ -f "$RT" ] || { echo "⏭️  跳过：没有 runtime 产物 $RT"; exit 2; }
export BXROOT_RUN_RUNTIME="$RT"

W=/tmp/bxroot-termux-$$
mkdir -p "$W" || exit 2
trap 'rm -rf "$W" /root/.bxroot-termux-probe-$$ /tmp/.bxroot-termux-tmp-$$' EXIT

P=/data/data/com.termux/files/usr
H=/data/data/com.termux/files/home
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# 只用 sh 内建（echo / read / test / cd）判定：本容器里 guest sh exec 外部程序会
# Permission denied（与 RUN_STATIC_ELF 基线同一环境问题），而且 bxroot-run 自己在
# 宿主侧解析 argv[0]，不经 runtime —— 两者都不是被测对象。shebang 解释器路径与
# 普通 open 走同一个 bxroot_translate_path（proc.c px_runtime_translate），由 b/c 覆盖。
echo "probe-$$" > /root/.bxroot-termux-probe-$$
G() { "$BX" /bin/sh -c "$1" 2>&1 | grep -v '^\[bxroot\]'; }

out=$(G "test -x $P/bin/sh && test -x $P/bin/env && echo ok")
[ "$out" = "ok" ] && good "a \$PREFIX/bin/{sh,env} 存在且可执行（→ /usr/bin）" || bad "a bin: $out"

out=$(G "read l < $P/etc/passwd; echo \"\${l%%:*}\"")
[ "$out" = "root" ] && good "b \$PREFIX/etc/passwd → /etc/passwd" || bad "b etc: $out"

out=$(G "read l < $H/.bxroot-termux-probe-$$; echo \$l")
[ "$out" = "probe-$$" ] && good "c Termux home → /root" || bad "c home: $out"

out=$(G "echo tmp-$$ > $P/tmp/.bxroot-termux-tmp-$$ && read l < /tmp/.bxroot-termux-tmp-$$ && echo \$l")
[ "$out" = "tmp-$$" ] && good "d \$PREFIX/tmp 与 /tmp 同处" || bad "d tmp: $out"

out=$(G "read l < /data/user/0/com.termux/files/home/.bxroot-termux-probe-$$; echo \$l")
[ "$out" = "probe-$$" ] && good "e /data/user/0 写法" || bad "e user0: $out"

out=$(G "cd $H && pwd -P")
[ "$out" = "/root" ] && good "f cd Termux home 后 pwd -P = /root（getcwd 反向翻译）" || bad "f cd: $out"

out=$(G "test -e $P/../usr/bin/sh && echo ok")
[ "$out" = "ok" ] && good "g \$PREFIX/.. 不越界（.. 先夹紧）" || bad "g dotdot: $out"

out=$(BXROOT_NO_TERMUX_COMPAT=1 "$BX" /bin/sh -c "test -e $P/bin/sh && echo mapped || echo unmapped" 2>&1 | grep -v '^\[bxroot\]')
[ "$out" = "unmapped" ] && good "h BXROOT_NO_TERMUX_COMPAT=1 不映射" || bad "h opt-out: $out"

[ $FAIL -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL ($FAIL)"; exit 1
