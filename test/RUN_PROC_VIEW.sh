#!/bin/sh
# ---------------------------------------------------------------------
# /proc 视角：/proc/self、/proc/thread-self、/proc/<pid> 的 exe/cwd/root/fd
# 反向翻译 + 跟随 + 中间组件 + 自重执行（上游 proot #421 / #438 / #384 / #385）
#
# 【背景】
#   #438/#384/#385：proot 对 `readlink /proc`（顶层，非链接）崩溃；
#   #421：rootfs 不可写时 /proc/self 被遮蔽（proot 想在 rootfs 里建 /proc）。
#   bxroot 不建 /proc 也不 ptrace，这两类崩溃形态天然不存在；但实测
#   （2026-09-26，bxroot-run + --rootfs 子目录 rootfs）暴露了另一组缺陷：
#     readlink /proc/self/cwd            → "/et"（客户缓冲先被宿主路径截断）
#     ls -l /proc/self/cwd               → $ROOTFS 前缀泄漏（FORTIFY 入口没接 fixup）
#     stat -L /proc/self/exe             → ENOENT（叶子跟随把 bridge.so 再套 $ROOTFS）
#     cat /proc/self/root/etc/hostname   → ENOENT（中间组件不展开）
#     wc -c </proc/self/exe              → 20200 = bridge.so（读到宿主映像）
#     /proc/self/exe -c 'echo ok'        → not found（exec 自重执行）
#   修复见 preload.c proc_magic_link_target / readlink_finish、proc.c
#   px_exec_proc_exe_alias、tools/bxroot-run 首进程 BXROOT_GUEST_EXE。
#
# 【判据】全部 rc=0、不 hang（timeout 30）、结果为 guest 视角（不含
#   "/data/data/" 或 rootfs 宿主前缀）；C 探针逐 key 与期望值比对；
#   与官方 runtime 双基线时**共同子集**必须一致（官方对 thread-self/exe、
#   readlinkat(dirfd,"exe") 自身泄漏 bridge.so，不作为参照）。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }

W=$(mktemp -d /tmp/bxroot-procview-XXXXXX)
trap 'rm -rf "$W"' EXIT
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# 子目录 rootfs（宿主 cwd 放在 rootfs 之外，更能暴露泄漏）：复用宿主 /usr
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp"
ln -s ../../../usr "$RF/usr"
ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
echo "PROCVIEW-MARK" > "$RF/etc/hostname"
# 宿主视角的 rootfs 前缀（用于"泄漏"判定）
HOSTPFX=$(readlink -f "$RF")

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
bld -O1 -Wall -Wextra -o "$RF/tmp/ppv" "$ROOT/test/probe_proc_view.c" || exit 1

run_rf() { timeout 30 "$BX" --no-check --rootfs "$RF" -- /bin/sh -c "$1" 2>&1; }
leak() { printf '%s\n' "$1" | grep -q -e '/data/data/' -e "$HOSTPFX"; }

echo "▶️  /proc 视角回归（#421 / #438）"
cd "$W" || exit 1     # 宿主 cwd 在 rootfs 之外

echo "--- A) shell 级：readlink / ls / stat -L / find（不 hang、rc=0、guest 视角）---"
o=$(run_rf 'readlink /proc/self/exe'); [ "$o" = "/usr/bin/readlink" ] && good "readlink self/exe = $o" || bad "self/exe: $o"
o=$(run_rf 'cd /etc && readlink /proc/self/cwd'); [ "$o" = "/etc" ] && good "readlink self/cwd = $o" || bad "self/cwd: $o（截断/泄漏）"
o=$(run_rf 'readlink /proc/self/root'); [ "$o" = "/" ] && good "readlink self/root = /" || bad "self/root: $o"
o=$(run_rf 'readlink /proc/thread-self/exe'); [ "$o" = "/usr/bin/readlink" ] && good "readlink thread-self/exe = $o" || bad "thread-self/exe: $o"
o=$(run_rf 'cd /etc; readlink /proc/$$/exe; readlink /proc/$$/cwd; readlink /proc/$$/root' | tr '\n' ' ')
# 已知边界（bxroot 与官方一致）：/proc/<其它pid>/exe 回答的是**调用进程**的 guest_exe
# （内核对所有 guest 进程都答 bridge.so，别的进程的 guest_exe 在它自己的 env 里拿不到），
# 所以 sh 里 `readlink /proc/$$/exe` 得到的是 readlink 自己而不是 dash。cwd/root 精确。
[ "$o" = "/usr/bin/readlink /etc / " ] && good "readlink /proc/<pid>/{exe,cwd,root} = $o（exe=调用者，同官方）" || bad "/proc/<pid>: $o"
# #438：readlink 顶层 /proc 不是链接 → rc=1、EINVAL，不得崩溃/hang
o=$(run_rf 'readlink /proc; echo rc=$?'); [ "$o" = "rc=1" ] && good "readlink /proc → rc=1（不崩溃）" || bad "readlink /proc: $o"
o=$(run_rf 'ls -al /proc 2>/dev/null | head -30; echo rc=$?' ); r=${o##*rc=}
if [ "$r" = "0" ] && ! leak "$o"; then good "ls -al /proc（rc=0，无泄漏）"; else bad "ls -al /proc: rc=$r"; fi
o=$(run_rf 'ls -al /proc/self/fd 2>&1; echo rc=$?'); r=${o##*rc=}
# 只看 guest 自己打开的 fd（0/1/2）；bxroot-run 注入链继承的 fd 指向宿主 sigsys 日志，两个 runtime 皆如此
o012=$(printf '%s\n' "$o" | grep -E ' [012] -> ')
if [ "$r" = "0" ] && ! leak "$o012"; then good "ls -al /proc/self/fd（rc=0，0/1/2 无泄漏）"; else bad "ls fd: rc=$r $o012"; fi
o=$(run_rf 'readlink /proc/self/fd/0 </dev/null'); [ "$o" = "/dev/null" ] && good "readlink fd/0 = /dev/null" || bad "fd/0: $o"
o=$(run_rf 'stat -L -c "%s" /proc/self/exe; stat -c "%s" /usr/bin/stat' | tr '\n' ' ')
set -- $o; [ -n "${1:-}" ] && [ "${1:-a}" = "${2:-b}" ] && good "stat -L /proc/self/exe = /usr/bin/stat（$1 B）" || bad "stat -L exe: $o"
o=$(run_rf 'cd /etc; find /proc/self -maxdepth 1 -type l -exec readlink {} \; 2>&1; echo rc=$?'); r=${o##*rc=}
if [ "$r" = "0" ] && ! leak "$o"; then good "find /proc/self -type l -exec readlink（rc=0，无泄漏）"; else bad "find: $o"; fi
o=$(run_rf 'cat /proc/self/root/etc/hostname'); [ "$o" = "PROCVIEW-MARK" ] && good "cat /proc/self/root/etc/hostname 读到 rootfs 内文件" || bad "root/etc: $o"
o=$(run_rf 'cd /etc && cat /proc/self/cwd/hostname'); [ "$o" = "PROCVIEW-MARK" ] && good "cat /proc/self/cwd/hostname" || bad "cwd/x: $o"
o=$(run_rf 'wc -c </proc/self/exe; stat -c %s /usr/bin/dash' | tr '\n' ' ')
set -- $o; [ -n "${1:-}" ] && [ "${1:-a}" = "${2:-b}" ] && good "wc -c </proc/self/exe = dash 大小（$1）" || bad "wc exe: $o（读到宿主映像？）"
o=$(run_rf '/proc/self/exe -c "echo reexec-ok"'); [ "$o" = "reexec-ok" ] && good "exec /proc/self/exe 自重执行" || bad "exec exe: $o"
# realpath 族（readlink -f 走 realpath/canonicalize）：#421 的验证命令
o=$(run_rf 'readlink -f /proc/self/exe; echo rc=$?' | tr '\n' ' '); [ "$o" = "/usr/bin/readlink rc=0 " ] && good "readlink -f /proc/self/exe = /usr/bin/readlink" || bad "readlink -f exe: $o"
o=$(run_rf 'readlink -f /proc/self/root/etc/hostname'); [ "$o" = "/etc/hostname" ] && good "readlink -f /proc/self/root/etc/hostname = $o" || bad "readlink -f root/etc: $o"
# 顶层首进程（bxroot-run 直接启动的进程）也要有 guest_exe
o=$(timeout 30 "$BX" --no-check --rootfs "$RF" -- /usr/bin/readlink /proc/self/exe 2>&1); [ "$o" = "/usr/bin/readlink" ] && good "首进程 readlink self/exe = $o" || bad "首进程 self/exe: $o"

echo "--- B) C 探针：/proc/<childpid> 与 self/thread-self 一致、截断、readlinkat、stat 跟随、socket ---"
timeout 30 "$BX" --no-check --rootfs "$RF" -- /tmp/ppv > "$W/bx.out" 2>&1; rc=$?
[ $rc -eq 0 ] || bad "探针 rc=$rc"
get() { sed -n "s/^$1=//p" "$W/bx.out" | head -1; }
exp() { v=$(get "$1"); if [ "$v" = "$2" ]; then good "$1=$v"; else bad "$1='$v' 期望 '$2'"; fi; }
exp self_exe /tmp/ppv
exp tself_exe /tmp/ppv
exp self_cwd /
exp self_root /
exp self_cwd_b16 "/|n=1"
exp self_exe_b8 "/tmp/ppv|n=8"
exp child_exe /tmp/ppv
exp child_cwd /etc
exp child_root /
exp child_fd3 /etc/hostname
exp child_cwd_b3 "/et|n=3"
exp at_self_exe /tmp/ppv
exp at_self_cwd /
exp at_child_exe /tmp/ppv
exp at_child_cwd /etc
exp at_tmp_exe ERR2
exp sock_fd "socket:"
exp stat_exe 1
exp fstatat_exe 1
exp statx_exe 1
exp lstat_exe_islnk 1
exp stat_child_exe 1
exp open_root_etc PROCVIEW-MARK
exp open_child_cwd PROCVIEW-MARK
exp open_exe_elf 1
exp open_exe_same 1
exp open_exe_nofollow_eloop 1
exp reexec ok
leak "$(cat "$W/bx.out")" && bad "探针输出含宿主前缀：$(grep -e /data/data/ -e "$HOSTPFX" "$W/bx.out" | head -3)"

echo "--- C) 官方 runtime 双基线（共同子集；官方 runtime 不认 bxroot-run 的 --rootfs，故双方都用默认 rootfs）---"
OFF=${OFFICIAL_SO:-/proc/$$/root${PROROOT_LIB_PATH:-/nonexistent}}
[ -f "$OFF" ] || OFF=/tmp/off-rt.so
if cp "$OFF" "$W/off-rt.so" 2>/dev/null; then
    cp "$RF/tmp/ppv" "$W/ppv"
    HN=$(cat /etc/hostname)
    ( cd /etc && timeout 30 "$BX" --no-check -- "$W/ppv" > "$W/bx2.out" 2>&1 )
    ( cd /etc && BXROOT_RUN_RUNTIME="$W/off-rt.so" timeout 30 "$BX" --no-check -- "$W/ppv" > "$W/off.out" 2>&1 )
    getb() { sed -n "s/^$1=//p" "$W/bx2.out" | head -1; }
    geto() { sed -n "s/^$1=//p" "$W/off.out" | head -1; }
    # 官方自身已知泄漏（tself_exe / at_*_exe / at_self_cwd / at_child_cwd 指向宿主）不比；
    # open_exe_nofollow_eloop 官方=0（它对 O_NOFOLLOW 叶子不返回 ELOOP），也不比。
    # self_exe/child_exe/reexec 也不比：官方在 bxroot-run 直启的 C 程序里 guest_exe 停留在
    # 首进程形状（答 /usr/bin/dash、自重执行进了 dash），bxroot 此处更准，是有意的差异。
    for k in self_cwd self_root self_cwd_b16 child_cwd child_root \
             child_fd3 child_cwd_b3 sock_fd stat_exe fstatat_exe statx_exe lstat_exe_islnk \
             stat_child_exe open_root_etc open_child_cwd open_exe_elf open_exe_same; do
        a=$(getb "$k"); b=$(geto "$k")
        [ -n "$a" ] && [ "$a" = "$b" ] && good "官方一致 $k=$a" || bad "官方 $k='$b' vs bxroot '$a'"
    done
    [ "$(getb open_root_etc)" = "$HN" ] || bad "默认 rootfs 下 open_root_etc 应为 $HN"
else
    echo "  ⏭️  C 跳过：读不到官方 runtime（OFFICIAL_SO / PROROOT_LIB_PATH / /tmp/off-rt.so）"
fi

echo
if [ "$FAIL" -gt 0 ]; then echo "   RESULT: FAIL（$FAIL 项）"; exit 1; fi
echo "   RESULT: PASS"
exit 0
