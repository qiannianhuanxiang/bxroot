#!/bin/sh
# ---------------------------------------------------------------------
# livepatch 运行期指令扫描 —— **真实 seccomp 端到端** (2026-09-27)
#
# 【与 RUN_LIVEPATCH_SCAN.sh 的分工】
#   RUN_LIVEPATCH_SCAN.sh 只对**合成机器码**跑扫描逻辑（证明扫描认得
#   站点）。本测试证明扫描在**真实 seccomp 环境**下独立地救活了本会必死
#   的进程 —— 用两条互补的判据链，且都带判别力（关掉 livepatch → 变红）。
#
# ── 判据 A：真 glibc 2.41 rootfs 经 bxroot exec 重入的派生族 ──
#   容器自身的 glibc 2.39 已被**外层官方 runtime** 补过（其内联 svc 已是
#   mov x0,#0）。而 /root/rootfs-trixie 的 glibc 2.41 是**另一份映像**，
#   外层补的不是它。所以在 2.41 rootfs 下，能不能活完全取决于 bxroot
#   自己的 livepatch（版本表 + 运行期扫描）：
#       BXROOT_NO_LIVEPATCH=1 → 经 exec 重入的进程 fork/pthread 子进程
#                               死于 SIGSYS(159)
#       默认（走扫描）        → 全部正常，rc=0
#   这直接把"是扫描、而非外层"钉死：外层根本没碰这份 2.41 libc。
#
# ── 判据 B：容器内强隔离，完全不依赖 bxroot-run / 外层 proroot ──
#   probe_seccomp_isolation.c 在**本进程**亲手装 seccomp 过滤器把
#   set_robust_list(99) 设成 SECCOMP_RET_TRAP，再复刻 glibc _Fork 的致命
#   形态（全信号屏蔽下发 99 的内联 svc）。补丁走 livepatch.c 里**真实的**
#   lp_scan_and_patch。control 模式子进程死于 SIGSYS；patch 模式子进程
#   存活。这条链不碰 proroot，把"扫描独立救活进程"钉成容器内可复现契约。
#
# 【判别力】
#   A：BXROOT_NO_LIVEPATCH=1 使 2.41 派生族探针 rc=159（本脚本据此断言）。
#   B：patch 模式再叠 BXROOT_NO_LIVEPATCH=1 → 探针内部跳过打补丁 → 子进程
#      死于 SIGSYS（探针对此返回 PASS，本脚本额外断言"确实死了"这一现象）。
#   整体判别力：把 livepatch.c 的 g_scan_nrs 去掉 99，A 与 B 的 patch 侧
#   都会变红。
#
# 退出码：0 通过 / 1 契约破坏 / 2 环境不满足
#   （无 rootfs-trixie / 无 build 产物 / 无外层 proroot / 无 seccomp）
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-lve2e-XXXXXX")
trap 'rm -rf "$W"' EXIT
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# ---- 架构门：站点指令编码是 aarch64 的 -------------------------------
case "$(uname -m)" in
aarch64|arm64) ;;
*) echo "rc=2 跳过：本机非 aarch64（$(uname -m)），扫描指令编码不适用"; exit 2 ;;
esac

# ---- seccomp 门：本环境必须真的装了过滤器（否则 99 不会被拦，无判别力）
SECCOMP=$(awk '/^Seccomp:/{print $2}' /proc/self/status 2>/dev/null)
[ "${SECCOMP:-0}" = "2" ] || { echo "rc=2 跳过：本环境无 seccomp 过滤器（Seccomp=$SECCOMP）"; exit 2; }

NCC=${NATIVE_CC:-gcc}
bld() {   # $1 输出  其余 源码/参数；gcc13 ICE 重试
    out=$1; shift
    i=1
    while [ "$i" -le 12 ]; do
        "$NCC" -O1 -w -o "$out" "$@" 2>"$W/cc.err" && return 0
        grep -q 'internal compiler error' "$W/cc.err" || { cat "$W/cc.err"; return 1; }
        i=$((i + 1))
    done
    return 1
}

# =====================================================================
# 判据 B：容器内强隔离（先跑，因为它不依赖 proroot，最能独立成立）
# =====================================================================
echo "--- B) 容器内强隔离：本进程自装 seccomp TRAP(99) + 真实扫描 ---"
bld "$W/isoP" -DLP_TEST_HOOK -D_GNU_SOURCE -I"$ROOT/src/runtime" \
    "$ROOT/test/livepatch/probe_seccomp_isolation.c" \
    "$ROOT/src/runtime/livepatch.c" \
    || { echo "❌ 隔离探针编译失败"; exit 1; }

# B1 对照：不打补丁 → 子进程必须死于 SIGSYS
oc=$("$W/isoP" control 2>&1); rcc=$?
echo "$oc" | sed 's/^/    /'
if [ $rcc -eq 0 ] && printf '%s' "$oc" | grep -q 'RESULT: PASS'; then
    good "B 对照：seccomp TRAP(99) 下无补丁 → 子进程死于 SIGSYS"
else
    bad "B 对照未按预期（rc=$rcc）"
fi

# B2 打补丁：真实扫描中和 99 → 子进程存活
op=$("$W/isoP" patch 2>&1); rcp=$?
echo "$op" | sed 's/^/    /'
if [ $rcp -eq 0 ] && printf '%s' "$op" | grep -q 'RESULT: PASS（打补丁'; then
    good "B 打补丁：真实 lp_scan_and_patch 中和 99 → 子进程存活 rc=0"
else
    bad "B 打补丁未救活（rc=$rcp）"
fi

# B3 判别力：patch 模式叠 BXROOT_NO_LIVEPATCH=1 → 退化为对照，子进程死于 SIGSYS
od=$(BXROOT_NO_LIVEPATCH=1 "$W/isoP" patch 2>&1); rcd=$?
echo "$od" | sed 's/^/    /'
if [ $rcd -eq 0 ] && printf '%s' "$od" | grep -q '被信号 31 杀死'; then
    good "B 判别力：关掉 livepatch → patch 退化为对照，子进程确实死于 SIGSYS"
else
    bad "B 判别力缺失（关掉 livepatch 后子进程未死于 SIGSYS，rc=$rcd）"
fi

# =====================================================================
# 判据 A：真 glibc 2.41 rootfs 经 bxroot exec 重入的派生族
# =====================================================================
echo "--- A) 真 glibc 2.41 rootfs（外层补的不是这份 libc）---"
ALT=${BXROOT_ALT_ROOTFS:-/root/rootfs-trixie}
SKIP_A=0
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "  ⏭️  跳过 A：无 build/libbxroot-runtime.so"; SKIP_A=1; }
if [ "$SKIP_A" = 0 ]; then
    grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null \
        || { echo "  ⏭️  跳过 A：需要外层 proroot 注入链路"; SKIP_A=1; }
fi
if [ "$SKIP_A" = 0 ]; then
    [ -x "$ALT/usr/bin/cat" ] && [ -x "$ALT/bin/sh" ] \
        || { echo "  ⏭️  跳过 A：$ALT 不是可用 rootfs（缺 /bin/sh 或 /usr/bin/cat）"; SKIP_A=1; }
fi

if [ "$SKIP_A" = 0 ]; then
    # 派生族探针必须落在 rootfs 内（guest 视角可见），先 exec 重入自身
    # 才真正加载该 rootfs 的 2.41 glibc。
    PB="$ALT/tmp/.bxroot-lve2e-fork-$$"
    if bld "$PB" "$ROOT/test/altrootfs/probe_fork_family.c" -lpthread; then
        GUEST="/tmp/$(basename "$PB")"
        ver=$(timeout 60 "$ROOT/tools/bxroot-run" --rootfs "$ALT" -- /bin/sh -c \
              'for l in /usr/lib/*/libc.so.6 /lib/*/libc.so.6; do [ -x "$l" ] && { "$l" 2>/dev/null|head -1; break; }; done' 2>/dev/null)
        echo "  rootfs=$ALT"
        echo "  libc: ${ver:-未知}"

        # A1 默认（走扫描）→ 全部成功、rc=0
        on=$(timeout 60 "$ROOT/tools/bxroot-run" --rootfs "$ALT" -- "$GUEST" "$GUEST" 2>&1); rcon=$?
        echo "$on" | grep -v 'livepatch' | sed 's/^/    /'
        if [ $rcon -eq 0 ] && printf '%s' "$on" | grep -q 'posix_spawn RESETIDS: ok'; then
            good "A 默认：2.41 rootfs 经 exec 重入 _Fork/fork/pthread/posix_spawn 全部成功"
        else
            bad "A 默认：派生族探针未全绿（rc=$rcon）"
        fi

        # A2 判别力：关掉 livepatch → 子进程死于 SIGSYS(159)
        off=$(BXROOT_NO_LIVEPATCH=1 timeout 60 "$ROOT/tools/bxroot-run" --rootfs "$ALT" -- "$GUEST" "$GUEST" 2>&1); rcoff=$?
        echo "$off" | grep -v 'livepatch' | sed 's/^/    /'
        if [ $rcoff -eq 159 ] || printf '%s' "$off" | grep -q 'killed by signal 31'; then
            good "A 判别力：BXROOT_NO_LIVEPATCH=1 → 2.41 派生族子进程死于 SIGSYS（rc=$rcoff）"
        else
            bad "A 判别力缺失：关掉 livepatch 后 2.41 派生族未死（rc=$rcoff）——可能另有兜底路径，需查"
        fi
        rm -f "$PB"
    else
        echo "  ⏭️  跳过 A：派生族探针编译失败"
    fi
fi

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
exit 0
