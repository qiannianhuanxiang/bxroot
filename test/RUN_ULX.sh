#!/bin/sh
# =====================================================================
# ulx（用户态 exec 加载器）+ 早期 SIGSYS 处理器 —— 容器内可判定部分
#
# 背景（2026-09-27 Termux 真机）：Android app 沙箱 seccomp 对
# set_robust_list/rseq 是 TRAP，glibc 程序在 main 之前即被杀（rc=159）。
# 修法见 src/ldr/early_sigsys.h 与 src/ldr/ulx.c。端到端验证（guest 真的
# 经 ulx 跑起来）只能在真机上做：test/device/run-termux.sh（26 项）。
#
# 本容器嵌套在 proroot 里，ld.so 装主程序会被外层干扰，所以这里钉：
#   U1  launcher / ulx 的 ELF 入口是 bx_early_start（链接参数没丢）
#   U2  入口桩确实先装 SIGSYS 处理器：在"SIGSYS 被 TRAP"的模拟环境里
#       （seccomp 过滤器把 set_robust_list 设为 RET_TRAP）静态程序能活着
#       走到 main —— 对照组（无桩）必须被杀，保证判别力
#   U3  ulx 错误路径：用法 rc=2 / 不存在 rc=127 / 非 ELF rc=126
#   U4  preload.c 的 dladdr 在无 ldso 服务时不再恒返回 0（源码钉）
#   U5  proc.c 的 trampoline 配置回落 BXROOT_ULX_PATH/LDSO（源码钉）
# 注意：本容器里静态程序在某些 cwd 下会被外层 loader 断言崩溃，
#       所有执行一律 cd / 后进行。
# =====================================================================
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${CC:-aarch64-linux-gnu-gcc-13}
W=$(mktemp -d "${TMPDIR:-/tmp}/ulx.XXXXXX")
trap 'rm -rf "$W"' EXIT
P=0; F=0
ok()  { P=$((P+1)); echo "  ✅ $*"; }
bad() { F=$((F+1)); echo "  ❌ $*"; }

build() {   # 带 ICE 重试
    i=0
    while [ $i -lt 12 ]; do
        "$CC" "$@" 2>"$W/cc.err" && return 0
        grep -q "internal compiler error" "$W/cc.err" || { cat "$W/cc.err"; return 1; }
        i=$((i+1))
    done
    return 1
}

LF="-static -Wl,-z,max-page-size=16384 -Wl,-e,bx_early_start"
build -O1 -w -D_GNU_SOURCE $LF -o "$W/ulx" "$ROOT/src/ldr/ulx.c" || { echo "❌ ulx 编译失败"; exit 1; }
build -O1 -w -D_GNU_SOURCE $LF -o "$W/L" "$ROOT/src/launcher/launcher.c" || { echo "❌ launcher 编译失败"; exit 1; }

echo "== U1 入口 =="
for b in ulx L; do
    e=$(readelf -h "$W/$b" | awk '/Entry point/{print $4}')
    s=$(nm "$W/$b" | awk '$3=="bx_early_start"{print "0x"$1}' | sed 's/0x0*/0x/')
    [ -n "$s" ] && [ "$e" = "$s" ] && ok "$b 入口 = bx_early_start ($e)" || bad "$b 入口 $e ≠ bx_early_start [$s]"
done
grep -q -- '-e,bx_early_start' "$ROOT/Makefile" && ok "Makefile LAUNCH_LDFLAGS 带 -e bx_early_start" || bad "Makefile 丢了 -e bx_early_start"

echo "== U2 早期处理器在 TRAP 环境下保命（含对照组）=="
cat > "$W/trap.c" <<'EOF'
/* 装一个 seccomp 过滤器：set_robust_list/rseq → RET_TRAP，然后 exec 目标。
 * 模拟 Android app 沙箱。PR_SET_NO_NEW_PRIVS 后非特权也可装。 */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int c, char **v, char **e) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_set_robust_list, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rseq, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog p = { sizeof f / sizeof f[0], f };
    if (c < 2) return 2;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p))
        return 3;
    execve(v[1], v + 1, e);
    return 4;
}
EOF
cat > "$W/hello.c" <<EOF
#include <stdio.h>
#include "$ROOT/src/ldr/early_sigsys.h"
int main(void) { puts("alive"); return 0; }
EOF
build -O1 -w -static -o "$W/trap" "$W/trap.c" || bad "trap 编译失败"
build -O1 -w -static -Wl,-e,bx_early_start -o "$W/h_early" "$W/hello.c" || bad "h_early 编译失败"
build -O1 -w -static -o "$W/h_plain" "$W/hello.c" || bad "h_plain 编译失败"
( cd / && "$W/trap" "$W/h_plain" ) >"$W/o1" 2>&1; r1=$?
( cd / && "$W/trap" "$W/h_early" ) >"$W/o2" 2>&1; r2=$?
if [ $r1 -eq 3 ]; then
    echo "  ⏭️  本环境不允许装 seccomp 过滤器，U2 跳过"
elif [ $r1 -eq 0 ] && ! grep -q alive "$W/o1"; then
    echo "  ⏭️  对照组结果异常（$(head -c 120 "$W/o1")），U2 跳过"
elif [ $r1 -eq 0 ]; then
    echo "  ⏭️  对照组未被杀（外层环境已处理 TRAP？），U2 无判别力，跳过"
else
    ok "对照组（无桩）被杀 rc=$r1 —— 模拟环境有效"
    [ $r2 -eq 0 ] && grep -q alive "$W/o2" && ok "带 bx_early_start 的程序存活并打印 alive" \
        || bad "带桩程序 rc=$r2 out=[$(head -c 200 "$W/o2")]"
fi

echo "== U3 ulx 错误路径 =="
( cd / && "$W/ulx" ) >/dev/null 2>&1; r=$?
[ $r -eq 2 ] && ok "无参 rc=2" || bad "无参 rc=$r"
( cd / && "$W/ulx" /nonexistent/ld.so x ) >"$W/e" 2>&1; r=$?
[ $r -eq 127 ] && grep -q "装载" "$W/e" && ok "不存在 rc=127" || bad "不存在 rc=$r [$(cat "$W/e")]"
echo notelf > "$W/txt"
( cd / && "$W/ulx" "$W/txt" x ) >/dev/null 2>&1; r=$?
[ $r -eq 126 ] && ok "非 ELF rc=126" || bad "非 ELF rc=$r"
( cd / && "$W/ulx" "$W/h_plain" x ) >/dev/null 2>&1; r=$?
[ $r -eq 0 ] || [ $r -eq 126 ] && ok "静态 ET_EXEC 可装载或明确拒绝 rc=$r" || bad "静态 ET_EXEC rc=$r"

echo "== U4/U5 源码钉 =="
awk '/^int dladdr\(/,/^}/' "$ROOT/src/runtime/preload.c" > "$W/dladdr.c"
grep -q 'bxroot_next_symbol("dladdr")' "$W/dladdr.c" && ok "dladdr 无服务时转发 libc" \
    || bad "dladdr 无 ldso 服务时仍恒返回 0（真机 envp 注入会被禁用）"
grep -q 'BXROOT_ULX_PATH' "$ROOT/src/proc/proc.c" && grep -q 'px_tramp_cfg(&tramp, &linker)' "$ROOT/src/proc/proc.c" \
    && [ "$(grep -c 'px_tramp_cfg(&tramp, &linker)' "$ROOT/src/proc/proc.c")" -eq 2 ] \
    && ok "exec/spawn 两条 trampoline 路径都回落 ulx" || bad "trampoline 配置未回落 ulx"

echo "------------------------------------------------------"
echo "通过 $P / 失败 $F"
[ $F -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
[ $F -eq 0 ]
