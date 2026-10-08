/*
 * probe_guest_sigsys_slot.c —— guest 的 SIGSYS 设置只进影子槽，真处理器不被顶掉
 *
 * 钉住 2026-10-09 真机缺陷的第二半：交互式 bash 给 SIGSYS 装了自己的终止
 * 处理器；旧实现放行，于是 faccessat2 被 seccomp TRAP 时 SIGSYS 直接递给 bash
 * 的处理器，bash 当成致命信号退出（rc=159）。
 *
 * 判据（装一个 seccomp 过滤器把 faccessat2(439) 设为 TRAP，等价于 Android）：
 *   1. guest 装了 SIGSYS 处理器之后，faccessat2 仍能被 runtime 兜底
 *      （返回值是 -1 + errno，而不是进到 guest 处理器 / 被杀）
 *   2. guest 的处理器对「seccomp 产生的」SIGSYS 从不被调用
 *   3. sigaction(SIGSYS, NULL, &old) 读回 guest 自己设置的处理器（可观测一致）
 *   4. guest 设 SIG_DFL 后 kill(getpid(), SIGSYS) 不递归（见 probe_self_sigsys）
 *
 * 退出码：0 = 成立；1 = 被打破；2 = 环境问题（装不了 seccomp）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif

#include <stdint.h>
/* 内核视角的 struct sigaction（aarch64）：handler(0) flags(8) restorer(16) mask(24) */
struct ksa { unsigned long handler, flags, restorer, mask; };
static unsigned long real_kernel_handler(void)
{
    struct ksa k;
    memset(&k, 0, sizeof k);
    if (syscall(SYS_rt_sigaction, SIGSYS, NULL, &k, 8) != 0) return (unsigned long)-1;
    return k.handler;
}

static volatile int guest_called;
static void guest_handler(int s) { (void)s; guest_called++; }

static int install_trap_439(void)
{
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 439, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { .len = sizeof f / sizeof f[0], .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p);
}

int main(void)
{
    struct sigaction sa, old;
    int fail = 0;
    long r;

    /* 先让 runtime 的处理器就位（LD_PRELOAD 构造函数已装）；再装 seccomp */
    if (install_trap_439() != 0) { puts("SKIP 无法装 seccomp"); return 2; }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = guest_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);              /* guest 像 bash 一样装自己的处理器 */

    {
        unsigned long real = real_kernel_handler();
        printf("内核里实际的 SIGSYS 处理器 = %#lx, guest 的 = %#lx\n",
               real, (unsigned long)guest_handler);
        if (real == (unsigned long)guest_handler) {
            puts("FAIL 内核处理器被 guest 顶掉了（seccomp 的 SIGSYS 会直接进 guest）");
            fail = 1;
        } else puts("OK 内核处理器仍是 runtime 的，没被 guest 顶掉");
    }

    memset(&old, 0, sizeof old);
    sigaction(SIGSYS, NULL, &old);
    if (old.sa_handler != guest_handler) {
        printf("FAIL 回读到的处理器不是 guest 设置的（%p）\n", (void *)old.sa_handler);
        fail = 1;
    } else puts("OK 回读到 guest 自己设置的处理器");

    errno = 0;
    r = syscall(SYS_faccessat2, AT_FDCWD, "/", F_OK, 0);
    printf("faccessat2 -> %ld errno=%d  guest_called=%d\n", r, errno, guest_called);
    if (guest_called) { puts("FAIL seccomp 的 SIGSYS 进了 guest 处理器"); fail = 1; }
    else puts("OK seccomp 的 SIGSYS 由 runtime 兜底，guest 处理器未被调用");

    puts(fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
