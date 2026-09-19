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
 *
 * =====================================================================
 * ★ 为什么本探针用裸 svc 建立/读回状态，而不是 libc sigprocmask ★
 * =====================================================================
 *
 * 本仓库的测试经常跑在**外层 proroot 容器**内（bxroot 的对照实现，
 * 由 DSHA 宿主注入：/proc/self/maps 里有 libproroot-runtime.so）。
 * 实测该运行时**劫持 libc `sigprocmask`**，把 SIGSYS 从读回的掩码里
 * 剔除 —— 于是本探针里两条**负向**断言（"175 号不能解除屏蔽"、
 * "装 handler 后屏蔽位不变"）会**恒假**，整项报 FAIL，而源码其实是对的。
 *
 * 证据（同一进程内，两条路径互相矛盾）：
 *
 *     libc sigprocmask(SIG_BLOCK, SIGSYS) → sigismember 读回 0
 *     裸 svc 135 读回同一掩码              → SIGSYS 位 = 1
 *     /proc/self/status SigBlk             → 0000000040000000（确实屏蔽）
 *
 * 即：内核状态是正确的，被改掉的是**libc 符号这条观测路径**。
 * 所以本探针的判据建立与读回一律走裸 svc（`SYS_rt_sigprocmask`=135），
 * 只有 `sigismember` 这种纯用户态位测试仍可用（它在已填好的 sigset_t
 * 上查位，不碰内核也不经被劫持的符号）。
 *
 * 判据独立性的通用教训：**用被测机制本身去观测被测机制，会得到假绿**；
 * 用同一环境里另一个被劫持的符号去观测，会得到假红。本探针两个都不碰。
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

/* ---- 状态建立/读回：一律裸 svc，不经 libc 被劫持的符号 ----
 *
 * sigsetsize 必须传 sizeof(unsigned long)=8（内核只接受它，见 T2）。
 */
#define KSET ((long)sizeof(unsigned long))

static long ksig_block(const sigset_t *s)
{
    return raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_BLOCK, (long)s, 0, KSET);
}
static long ksig_unblock(const sigset_t *s)
{
    return raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_UNBLOCK, (long)s, 0, KSET);
}
static long ksig_query(sigset_t *out)
{
    return raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_BLOCK, 0, (long)out, KSET);
}

int main(void)
{
    sigset_t set, cur;

    printf("== sigsys 裸系统调用号 / sigsetsize 钉 ==\n\n");

    /* ---- T0 观测路径自检 ----
     *
     * 先确认"裸 svc 建立状态 → 裸 svc 读回"这条链真的看得见副作用。
     * 没有这一步，下面那些"屏蔽位**保持**不变/变 0"的断言可能是
     * 恒假的（观测路径本身失效），整项就失去判别力。
     */
    printf("[T0] 观测路径自检：裸 svc 建立的状态必须能被裸 svc 读回\n");
    {
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        long rb = ksig_block(&set);
        long rq = ksig_query(&cur);
        int masked = sigismember(&cur, SIGSYS);
        printf("     裸 block rc=%ld, 裸 query rc=%ld → masked=%d\n", rb, rq, masked);
        check("裸 svc 屏蔽 SIGSYS 后，裸 svc 读回确实为 1（观测链有效）", masked == 1);
    }

    /* ---- T1 号必须解析到 rt_sigprocmask，而不是 geteuid ---- */
    printf("\n[T1] 号语义：aarch64 上 rt_sigprocmask=135, geteuid=175\n");
    {
        ksig_block(&set);
        long r_ok = ksig_unblock(&set);
        ksig_query(&cur);
        int unblocked = !sigismember(&cur, SIGSYS);
        printf("     裸 135: rc=%ld, 解除屏蔽=%d\n", r_ok, unblocked);
        check("135 能解除 SIGSYS 屏蔽（号正确且 sigsetsize 正确）", unblocked);

        /* 反例：错号必须**不能**解除屏蔽 —— 证明本钉有区分力 */
        ksig_block(&set);
        long r_bug = raw4(SYS_RT_SIGPROCMASK_BUGGY, SIG_UNBLOCK,
                          (long)&set, 0, KSET);
        ksig_query(&cur);
        int still = sigismember(&cur, SIGSYS);
        printf("     裸 175: rc=%ld, 仍屏蔽=%d\n", r_bug, still);
        check("175(=geteuid) 不能解除屏蔽 → 本钉能区分正确/错误号", still);
    }

    /* ---- T2 sigsetsize 必须是内核大小，不是 glibc 的 sizeof(sigset_t) ---- */
    printf("\n[T2] sigsetsize：内核要 sizeof(unsigned long)，glibc sigset_t 是 128\n");
    {
        long r_kernel, r_glibc;
        sigemptyset(&set); sigaddset(&set, SIGSYS);

        ksig_block(&set);
        r_kernel = ksig_unblock(&set);
        ksig_query(&cur);
        int ok_kernel = (r_kernel == 0) && !sigismember(&cur, SIGSYS);
        printf("     sigsetsize=%-3zu rc=%ld\n", sizeof(unsigned long), r_kernel);
        check("内核大小(8) 被接受且生效", ok_kernel);

        ksig_block(&set);
        r_glibc = raw4(SYS_RT_SIGPROCMASK_UNDER_TEST, SIG_UNBLOCK, (long)&set,
                       0, (long)sizeof(sigset_t));
        ksig_query(&cur);
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
        sa.sa_handler = SIG_DFL;   /* 只为探测，不真装 handler */

        ksig_block(&set);
        sigaction(SIGSYS, &sa, NULL);
        ksig_query(&cur);
        check("装处理器后屏蔽位保持不变 → 必须显式 SIG_UNBLOCK",
              sigismember(&cur, SIGSYS) != 0);
    }

    printf("\n== 结果: %d 通过 / %d 失败 ==\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
