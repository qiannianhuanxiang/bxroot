#!/bin/sh
# ---------------------------------------------------------------------
# 非默认 rootfs 下 `sh -c '/bin/cat …'` 回归（钉住已知限制文档的结论）
#
# 背景：docs/已知限制-非默认rootfs的cat崩溃.md 记录过
#   bxroot-run --rootfs <另一 rootfs> -- /bin/sh -c '/bin/cat /etc/hostname'
# 在 Debian 13（glibc 2.41）rootfs 下偶发 `munmap_chunk(): invalid pointer`
# （rc=134），"直接跑正常、经 shell 转一手就崩"。2026-09-26 在真机
# （aarch64、外层 proroot）用真 glibc 2.41 rootfs 重测 0/60，无法复现；
# 本测试把"必须 0 崩溃 + 输出必须来自那个 rootfs"钉成契约，
# 以后一旦回归立即变红。
#
# 判据（每个子用例）：
#   1. N 次 `sh -c '/bin/cat /etc/hostname'` 全部 rc=0（任何非 0 都算契约破坏，
#      rc=134/139 会单独点名）；
#   2. 输出必须等于 **该 rootfs 自己的** /etc/hostname —— 这是"被测对象自己
#      的痕迹"：证明 cat 读的是非默认 rootfs 而非容器默认 /；
#   3. 多一层 exec 链（sh -c 'sh -c …'）同样成立。
#
# 子用例：
#   A) 同 glibc 的另一 rootfs：由本脚本用 cp -al（硬链接）从容器自身现做，
#      落在 build/alt-rootfs-hl（约 20MB 元数据，同一文件系统才能硬链接），
#      本环境**总能跑**，用来区分"非默认 rootfs 本身"与"glibc 2.41"；
#   B) 异 glibc rootfs：BXROOT_ALT_ROOTFS 指定，或自动探测
#      /root/rootfs-trixie、/root/bxtest-pd/rootfs；不存在则明确打印跳过
#      （不影响 A 的判定）。
#
# 退出码：0 通过 / 1 契约破坏 / 2 环境不满足（无 build 产物、无外层
#        proroot、硬链接 rootfs 建不出来）。
# 变量：BXROOT_ALT_ROOTFS 异 glibc rootfs 路径；ALT_N 重复次数（默认 15）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
N=${ALT_N:-15}
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "rc=2 跳过：没有 build/libbxroot-runtime.so"; exit 2; }
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || { echo "rc=2 跳过：需要外层 proroot 注入链路"; exit 2; }
[ -x "$ROOT/tools/bxroot-run" ] || { echo "rc=2 跳过：没有 tools/bxroot-run"; exit 2; }

# ---- 子用例 A 的 rootfs：容器自身的硬链接镜像 -------------------------
HL="$ROOT/build/alt-rootfs-hl"
if [ ! -x "$HL/usr/bin/cat" ]; then
    rm -rf "$HL"
    mkdir -p "$HL" || { echo "rc=2 跳过：无法创建 $HL"; exit 2; }
    if ! cp -al /usr "$HL/usr" 2>/dev/null; then
        rm -rf "$HL"
        echo "rc=2 跳过：cp -al /usr 失败（build/ 与 /usr 不在同一文件系统？）"
        exit 2
    fi
    cp -a /etc "$HL/etc" 2>/dev/null
    ( cd "$HL" && ln -sfn usr/bin bin && ln -sfn usr/lib lib && ln -sfn usr/sbin sbin \
        && mkdir -p tmp proc sys dev root )
fi
# 与默认 rootfs 不同的 hostname —— 判据 2 靠它区分"读的是哪棵树"
echo "alt-rootfs-hl-$$" > "$HL/etc/hostname"

run_case() {   # $1 标签  $2 rootfs
    lbl=$1; rfs=$2
    want=$(cat "$rfs/etc/hostname")
    crash=0; wrong=0; other=0
    i=1
    while [ $i -le "$N" ]; do
        out=$(timeout 60 "$ROOT/tools/bxroot-run" --rootfs "$rfs" -- \
              /bin/sh -c '/bin/cat /etc/hostname' 2>/tmp/alt-rootfs-err.$$)
        rc=$?
        if [ $rc -eq 134 ] || [ $rc -eq 139 ]; then
            crash=$((crash + 1))
            [ $crash -eq 1 ] && { echo "    第 $i 次 rc=$rc："; tail -2 /tmp/alt-rootfs-err.$$ | sed 's/^/      /'; }
        elif [ $rc -ne 0 ]; then
            other=$((other + 1))
            [ $other -eq 1 ] && { echo "    第 $i 次 rc=$rc："; tail -2 /tmp/alt-rootfs-err.$$ | sed 's/^/      /'; }
        elif [ "$out" != "$want" ]; then
            wrong=$((wrong + 1))
            [ $wrong -eq 1 ] && echo "    第 $i 次输出 '$out'，期望 '$want'"
        fi
        i=$((i + 1))
    done
    rm -f /tmp/alt-rootfs-err.$$
    if [ $crash -eq 0 ] && [ $other -eq 0 ]; then
        good "$lbl：sh -c cat ×$N 全部 rc=0"
    else
        bad "$lbl：sh -c cat ×$N 崩溃(134/139) $crash 次、其它非 0 $other 次"
    fi
    if [ $wrong -eq 0 ]; then
        good "$lbl：输出全部等于该 rootfs 的 /etc/hostname（$want）"
    else
        bad "$lbl：$wrong 次输出不是该 rootfs 的 hostname（路径翻译没落到 --rootfs）"
    fi
    # 两层 exec 链
    out=$(timeout 60 "$ROOT/tools/bxroot-run" --rootfs "$rfs" -- \
          /bin/sh -c '/bin/sh -c "/bin/cat /etc/hostname"' 2>/dev/null); rc=$?
    if [ $rc -eq 0 ] && [ "$out" = "$want" ]; then
        good "$lbl：两层 sh -c 链 rc=0 且输出正确"
    else
        bad "$lbl：两层 sh -c 链 rc=$rc 输出 '$out'"
    fi
}

echo "--- A) 同 glibc 的另一 rootfs（硬链接镜像 $HL）---"
run_case "同glibc" "$HL"

echo "--- B) 异 glibc rootfs ---"
ALT=${BXROOT_ALT_ROOTFS:-}
if [ -z "$ALT" ]; then
    for c in /root/rootfs-trixie /root/bxtest-pd/rootfs; do
        [ -x "$c/usr/bin/cat" ] && [ -f "$c/etc/hostname" ] && { ALT=$c; break; }
    done
fi
if [ -n "$ALT" ] && [ -x "$ALT/usr/bin/cat" ] && [ -f "$ALT/etc/hostname" ]; then
    ver=$(timeout 60 "$ROOT/tools/bxroot-run" --rootfs "$ALT" -- /bin/sh -c \
          'for l in /usr/lib/*/libc.so.6 /lib/*/libc.so.6; do [ -x "$l" ] && { "$l" 2>/dev/null | head -1; break; }; done' 2>/dev/null)
    echo "  rootfs=$ALT"
    echo "  libc: ${ver:-未知}"
    run_case "异glibc" "$ALT"
else
    echo "  ⏭️  跳过 B：没有异 glibc rootfs（可设 BXROOT_ALT_ROOTFS=/path/to/rootfs；"
    echo "      前提：其中有 /bin/sh、/bin/cat、/etc/hostname，且与本机同架构）"
fi

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
exit 0
