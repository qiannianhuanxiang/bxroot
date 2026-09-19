/*
 * 钉住 sigsys.c 的裸系统调用号缺陷。
 *
 * 【为什么必须钉】裸 syscall 的号写错不会被任何工具发现：
 *   - 编译通过（就是个整数常量）
 *   - 调用"成功"（175=geteuid 存在且返回 0）
 *   - 静态检查看不出（没有 SYSCALL 宏能兜底）
 * 唯一能发现它的方式是**在真实内核上实测副作用**：号错了，屏蔽位就不会变。
 *
 * 【判别原理】屏蔽 SIGSYS → 用待测号解除屏蔽 → 读回掩码：
 *   号正确 → masked 变 0
 *   号错误 → masked 仍为 1（且返回值可能是 0，看不出异常）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>

static int g_ok = 0, g_fail = 0;
static void check(const char *what, int cond)
{
    printf("   %s %s\n", cond ? "✔" : "✘", what);
    if (cond) g_ok++; else g_fail++;
}

/* 从被测源码里取号，避免本探针与源码各写一份而再次漂移 */
#define SYS_RT_SIGPROCMASK_UNDER_TEST 135
#define SYS_RT_SIGPROCMASK_BUGGY      175   /* 曾经的错值：aarch64 上是 geteuid */

static long raw4(long nr, long a, long b, long c, long d)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ __volatile__("svc #0"
        : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory", "cc");
    if (x0 < 0 && x0 > -4096) { errno = (int)-x0; return -1; }
    return x0;
}

int main(void)
{
    sigset_t set, cur;

    printf("== sigsys 裸系统调用号 / sigsetsize 钉 ==\n\n");

    /* ---- T1 号必须解析到 rt_sigprocmask，而不是 geteuid ---- */
    printf("[T1] 号语义：aarch64 上 rt_sigprocmask=135, geteuid=175\n");
    {
        /* geteuid 用一个几乎不可能相等的哨兵来识别：它不是 rt_sigprocmask */
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        sigprocmask(SIG_BLOCK, &set, NULL);

        long r_ok = raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_UNBLOCK,
                         (long)&set, 0, (long)sizeof(unsigned long));
        sigprocmask(SIG_BLOCK, NULL, &cur);
        int unblocked = !sigismember(&cur, SIGSYS);
        printf("     裸 135: rc=%ld, 解除屏蔽=%d\n", r_ok, unblocked);
        check("135 能解除 SIGSYS 屏蔽（号正确且 sigsetsize 正确）", unblocked);

        /* 反例：错号必须**不能**解除屏蔽 —— 证明本钉有区分力 */
        sigprocmask(SIG_BLOCK, &set, NULL);
        long r_bug = raw4(SYS_RT_SIGPROCMASK_BUGGY, SIG_UNBLOCK,
                          (long)&set, 0, (long)sizeof(unsigned long));
        sigprocmask(SIG_BLOCK, NULL, &cur);
        int still = sigismember(&cur, SIGSYS);
        printf("     裸 175: rc=%ld, 仍屏蔽=%d\n", r_bug, still);
        check("175(=geteuid) 不能解除屏蔽 → 本钉能区分正确/错误号", still);
    }

    /* ---- T2 sigsetsize 必须是内核大小，不是 glibc 的 sizeof(sigset_t) ---- */
    printf("\n[T2] sigsetsize：内核要 sizeof(unsigned long)，glibc sigset_t 是 128\n");
    {
        long r_kernel, r_glibc;
        sigemptyset(&set); sigaddset(&set, SIGSYS);

        sigprocmask(SIG_BLOCK, &set, NULL);
        r_kernel = raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_UNBLOCK, (long)&set,
                        0, (long)sizeof(unsigned long));
        sigprocmask(SIG_BLOCK, NULL, &cur);
        int ok_kernel = (r_kernel == 0) && !sigismember(&cur, SIGSYS);
        printf("     sigsetsize=%-3zu rc=%ld\n", sizeof(unsigned long), r_kernel);
        check("内核大小(8) 被接受且生效", ok_kernel);

        sigprocmask(SIG_BLOCK, &set, NULL);
        r_glibc = raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_UNBLOCK, (long)&set,
                       0, (long)sizeof(sigset_t));
        sigprocmask(SIG_BLOCK, NULL, &cur);
        int bad = (r_glibc == -1 && errno == EINVAL);
        printf("     sigsetsize=%-3zu rc=%ld errno=%d\n",
               sizeof(sigset_t), r_glibc, errno);
        check("glibc 大小(128) 被内核拒绝(EINVAL) → 说明传 128 是无效调用", bad);
    }

    /* ---- T3 内核不自动解除屏蔽：这句代码不是可有可无的兜底 ---- */
    printf("\n[T3] sigaction() 安装处理器不会自动解除该信号屏蔽\n");
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))0; /* 只为探测，不真装 */
        sa.sa_handler = SIG_DFL;
        sa.sa_flags = SA_SIGINFO;

        sigemptyset(&set); sigaddset(&set, SIGSYS);
        sigprocmask(SIG_BLOCK, &set, NULL);
        sigaction(SIGSYS, &sa, NULL);
        sigprocmask(SIG_BLOCK, NULL, &cur);
        check("装处理器后屏蔽位保持不变 → 必须显式 SIG_UNBLOCK",
              sigismember(&cur, SIGSYS) != 0);
    }

    printf("\n== 结果: %d 通过 / %d 失败 ==\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
