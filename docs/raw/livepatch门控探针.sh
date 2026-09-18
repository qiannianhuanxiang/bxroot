#!/bin/sh
# =====================================================================
# livepatch 门控修复 —— 原始证据探针（可复跑）
# =====================================================================
#
# 配套文档：docs/livepatch门控修复.md
#
# 这个脚本把该修复依赖的每一条**事实**重新测一遍。之所以单独留一份：
# 本修复的两个关键判据（"PR_GET_SECCOMP 判不出过滤器的种类"、
# "本容器确实存在过滤器但站点系统调用并未被封"）都是**对环境的断言**，
# 环境一变结论就可能不成立 —— 必须能一键复验，而不是只信文档里的字。
#
# 用法：
#     sh docs/raw/livepatch门控探针.sh            # 全部跑
#     sh docs/raw/livepatch门控探针.sh 1          # 只跑第 1 项
#
# 退出码：0 = 所有断言符合预期；1 = 有偏差（文档需要更新）
#
# ★ 全程 fork 隔离：探针里有直发 svc 的用例，若环境真的会 KILL，
#   死的是子进程，不会带走这个脚本。★
# =====================================================================
set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-lp-probe-XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

WHICH="${1:-all}"
FAILS=0

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  ✅ %s\n' "$*"; }
bad()  { printf '  ❌ %s\n' "$*"; FAILS=$((FAILS + 1)); }
# 编译带 ICE 重试（本容器 gcc 13.3.0 有间歇性 ICE）
cc_retry() {
    _out="$1"; shift
    _i=1
    while [ "$_i" -le 10 ]; do
        if gcc "$@" -o "$_out" 2>"$WORK/cc.err"; then return 0; fi
        grep -q 'internal compiler error' "$WORK/cc.err" || { cat "$WORK/cc.err"; return 1; }
        _i=$((_i + 1))
    done
    return 1
}

# ---------------------------------------------------------------------
hdr "0. 环境基线"
# ---------------------------------------------------------------------
say "  内核      : $(uname -r)"
say "  glibc     : $(ldd --version 2>/dev/null | head -1)"
say "  PR_GET_SECCOMP 常量 : 21"

cat > "$WORK/base.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/prctl.h>
#include <gnu/libc-version.h>
int main(void)
{
    printf("  /proc 视角 PR_GET_SECCOMP = %d\n", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    printf("  gnu_get_libc_version()    = %s\n", gnu_get_libc_version());
    return 0;
}
EOF
cc_retry "$WORK/base" "$WORK/base.c" || exit 1
"$WORK/base"
say "  （1=STRICT 2=FILTER；本容器实测为 2）"

# ---------------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "1" ]; then
hdr "1. 站点上的系统调用在本容器**并未**被 KILL —— 没有白名单要绕"
# ---------------------------------------------------------------------
# 论点：livepatch 存在的唯一理由是"宿主白名单会 KILL 掉这些调用"。
#      若内联 svc 直发这两个号**能正常返回**，就证明本环境没有那套
#       白名单 ⇒ 补丁在此毫无收益，只承担风险。
cat > "$WORK/svc.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
static long raw_svc(long nr, long a0, long a1, long a2)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
int main(void)
{
    struct { long nr; const char *what; } t[] = {
        { 99,  "set_robust_list（站点 1）" },
        { 293, "rseq（站点 2）" },
        { 425, "io_uring_setup（已知被 TRAP 的对照）" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        fflush(stdout);
        pid_t p = fork();
        if (p == 0) {
            long r = raw_svc(t[i].nr, 0, 0, 0);
            /* 内核/过滤器返回 -ENOSYS 时，这是"如实报告不支持"，
             * 不是被 KILL —— 这正是 livepatch 要模拟的语义。 */
            printf("  nr=%-4ld %-38s -> %ld%s\n", t[i].nr, t[i].what, r,
                   r == -38 ? "  (= -ENOSYS，调用被拒绝但进程存活)" : "");
            fflush(stdout);
            _exit(0);
        }
        int st = 0; waitpid(p, &st, 0);
        if (WIFSIGNALED(st))
            printf("  nr=%-4ld %-38s -> ☠ 死于信号 %d (%s)\n", t[i].nr, t[i].what,
                   WTERMSIG(st), strsignal(WTERMSIG(st)));
    }
    return 0;
}
EOF
cc_retry "$WORK/svc" "$WORK/svc.c" || exit 1
"$WORK/svc"
say "  判据：出现 ☠ 才说明本环境有 KILL 白名单（那样补丁才有收益）。"
say "        实测全为 -ENOSYS/正常返回 ⇒ 本环境无白名单 ⇒ 补丁应被门控跳过。"
fi

# ---------------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "2" ]; then
hdr "2. ★ 判据局限：PR_GET_SECCOMP=2 也可能是**与 Android 无关**的过滤器 ★"
# ---------------------------------------------------------------------
# 论点：PR_GET_SECCOMP 只报"有没有过滤器"，不报"是不是白名单"。
#      装一个只拦 chmod 的 3 条 BPF 指令过滤器，看它同样报 2。
cat > "$WORK/mkf.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
int main(void)
{
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53 /* chmod */, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = (unsigned short)(sizeof f / sizeof f[0]), .filter = f };
    printf("  装过滤器前 PR_GET_SECCOMP = %d\n", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("NO_NEW_PRIVS"); return 1; }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) { perror("seccomp"); return 1; }
    printf("  装过滤器后 PR_GET_SECCOMP = %d   ← 与 Android 毫无关系的过滤器也是这个值\n",
           prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    /* ★ 先调用、再取 errno ★ 若把 chmod(...) 与 errno 写成同一个 printf
     * 的两个实参，C 未规定求值顺序，实测会把 errno 印成调用前的旧值
     * （本轮就踩到一次：印出 errno=-1 而真实值是 38）。 */
    errno = 0;
    int cr = chmod("/nonexistent", 0);
    printf("  对照：chmod 被这条过滤器拒绝 -> rc=%d errno=%d (%s)\n",
           cr, errno, strerror(errno));
    return 0;
}
EOF
cc_retry "$WORK/mkf" "$WORK/mkf.c" || exit 1
"$WORK/mkf"
say "  判据：两次都是 2 ⇒ 该判据**证明不了**过滤器是 Android 白名单。"
say "        这正是修复采用『宁可多跑，不可误跳过』保守方向的原因。"
fi

# ---------------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "3" ]; then
hdr "3. 站点偏移是否仍与站点表一致（glibc 2.39）"
# ---------------------------------------------------------------------
LIBC=$(ls /lib/aarch64-linux-gnu/libc.so.6 2>/dev/null || \
       ls /usr/lib/aarch64-linux-gnu/libc.so.6 2>/dev/null)
if [ -z "$LIBC" ]; then
    say "  ⏭  找不到 libc.so.6，跳过"
else
    say "  $LIBC"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$LIBC" <<'PY'
import sys, struct
d = open(sys.argv[1], 'rb').read()
for off, what in ((0x855c4, 'set_robust_list'), (0x85850, 'rseq')):
    w = struct.unpack_from('<I', d, off)[0]
    tag = 'svc #0 ✅' if w == 0xd4000001 else '不是 svc ❌（站点表已过期）'
    print(f"  off=0x{off:x} {what:16s} word=0x{w:08x}  {tag}")
PY
    else
        od -A x -t x4 -j $((0x855c4)) -N 4 "$LIBC"
        od -A x -t x4 -j $((0x85850)) -N 4 "$LIBC"
    fi
    say "  期望两个 word 都是 0xd4000001（svc #0）。"
    say "  注意：/proc/self/maps 里的**活体** libc 可能已被外层 runtime 改成"
    say "        0xd2800000 —— 那是别人打的，与本仓库的站点表校验无关。"
fi
fi

# ---------------------------------------------------------------------
if [ "$WHICH" = "all" ] || [ "$WHICH" = "4" ]; then
hdr "4. 门控行为（驱动真实 livepatch.c，用可编程替身注入环境）"
# ---------------------------------------------------------------------
# 这一段需要仓库里的 livepatch.c。用 prctl/mprotect/gnu_get_libc_version
# 的替身把"环境"做成可编程的，并**数 mprotect 次数** —— 门控是否真的
# 挡住了危险路径，唯一硬的判据就是"一次都没调 mprotect"。
cat > "$WORK/gate.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "livepatch.h"

static int fake_prctl_rc = 2;
int prctl(int op, ...)
{
    (void)op;
    if (fake_prctl_rc < 0) { errno = EINVAL; return -1; }
    return fake_prctl_rc;
}
static const char *fake_ver = "2.39";
const char *gnu_get_libc_version(void) { return fake_ver; }

static int mp_calls = 0, mp_rwx = 0;
int mprotect(void *a, size_t l, int p)
{
    mp_calls++;
    if (p == (PROT_READ | PROT_WRITE | PROT_EXEC)) mp_rwx++;
    return (int)syscall(SYS_mprotect, a, l, p);
}

static int fails = 0;
static void chk(const char *n, int c)
{ printf("  [%s] %s\n", c ? "PASS" : "FAIL", n); if (!c) fails++; }

int main(void)
{
    printf("  站点表声明版本 = %s\n", bxroot_livepatch_site_libc_version());

    fake_prctl_rc = 0; unsetenv("BXROOT_NO_LIVEPATCH"); mp_calls = mp_rwx = 0;
    int rc = bxroot_livepatch_apply();
    printf("  无过滤器:          rc=%d skip=%d mprotect=%d\n", rc,
           bxroot_livepatch_skip_reason(), mp_calls);
    chk("无过滤器 → 跳过且**未碰代码页**",
        rc == LP_SKIP_NO_SECCOMP && mp_calls == 0);

    fake_prctl_rc = 1; mp_calls = mp_rwx = 0;
    rc = bxroot_livepatch_apply();
    chk("MODE_STRICT(1) → 同样跳过且未碰代码页",
        rc == LP_SKIP_NO_SECCOMP && mp_calls == 0);

    setenv("BXROOT_NO_LIVEPATCH", "1", 1);
    fake_prctl_rc = 2; mp_calls = mp_rwx = 0;
    rc = bxroot_livepatch_apply();
    printf("  硬开关:            rc=%d skip=%d mprotect=%d\n", rc,
           bxroot_livepatch_skip_reason(), mp_calls);
    chk("BXROOT_NO_LIVEPATCH=1 → 跳过且未碰代码页",
        rc == LP_SKIP_ENV && mp_calls == 0);
    unsetenv("BXROOT_NO_LIVEPATCH");

    return fails == 0 ? 0 : 1;
}
EOF
if [ ! -f "$ROOT/src/runtime/livepatch.c" ]; then
    say "  ⏭  找不到 $ROOT/src/runtime/livepatch.c，跳过"
else
    if cc_retry "$WORK/gate" -Wall -Wextra -Wno-unused-parameter -Wno-misleading-indentation \
                 -I"$ROOT/src/runtime" "$WORK/gate.c" "$ROOT/src/runtime/livepatch.c"; then
        if "$WORK/gate"; then ok "门控三项断言全部符合预期"; else bad "门控断言有偏差"; fi
    else
        bad "探针编译失败"
    fi
fi
fi

# ---------------------------------------------------------------------
hdr "汇总"
if [ "$FAILS" -eq 0 ]; then
    say "  ✅ 所有断言符合 docs/livepatch门控修复.md 的记载"
    exit 0
fi
say "  ❌ 有 $FAILS 项偏差 —— 文档里的环境断言需要更新"
exit 1
