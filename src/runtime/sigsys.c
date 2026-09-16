/*
 * sigsys.c —— seccomp/SIGSYS 兼容层
 *
 * 为什么需要这一层
 * ----------------
 * Android app 沙箱会给进程装 seccomp 过滤器（/proc/self/status 显示
 * Seccomp: 2 表示 SECCOMP_MODE_FILTER）。实测该过滤器 TRAP 掉
 * io_uring_setup(425)：直接调用时内核返回 ENOSYS，不致命。
 *
 * 但 libuv（node 的事件循环）在**工作线程**里发起这个调用，而线程可能
 * 屏蔽了 SIGSYS。规则是：seccomp 以 SECCOMP_RET_TRAP 拦下系统调用时，
 * 内核投递 SIGSYS；**若该信号被屏蔽，内核直接杀掉进程**，表现为
 * 退出码 159 = 128+31，无法捕获、无法抢救。
 *
 * 这是官方 proroot 必须有 2624 字节 SIGSYS 模拟层（proroot_sigsys_emulate
 * / sigsys_log_append / proroot_sigsys_handler）的真正原因，也是 bxroot
 * 此前跑不了 dsh 的唯一原因：
 *     node --version         → rc=0    （不触发事件循环）
 *     node -e 'console.log'  → rc=159  （触发事件循环，工作线程被拦）
 *
 * 本层的职责
 * ----------
 * 1. 安装 SIGSYS 处理器，把被拦系统调用模拟成可回退的 errno，
 *    使客户程序走它既有的回退路径（libuv 见 ENOSYS 即退回 epoll）。
 * 2. **阻止任何代码屏蔽 SIGSYS** —— 屏蔽等于自杀，所以必须拦截
 *    pthread_sigmask / sigprocmask 把这些位剔除，并拒绝把 SIGSYS
 *    设成 SIG_IGN/SIG_DFL。
 * 3. 重复出现的被拦调用去重计数，避免刷屏（官方有 sigsys_log_append）。
 *
 * 实现约束（都来自实测踩坑）
 * --------------------------
 * - 处理器内只做异步信号安全操作：不 malloc、不 stdio、不 dlsym。
 * - **不推进 PC**：aarch64 上进入处理器时 PC 已指向 svc 之后。早期版本
 *   多加了 4 字节，跳过紧随的 `cmn x0, #0xfff`（errno 判定），使调用方
 *   把 -ENOSYS 当成有效 fd，node 断言 `fd > STDERR_FILENO` 失败并 abort。
 * - 用裸 syscall 而非 dlsym(RTLD_NEXT)：实测该环境里 dlsym 拿到的 libc
 *   地址不可靠（外层 proroot 做活体代码补丁，跳进去会 SIGSEGV，故障
 *   地址呈 0xffffffff…… 形态）。
 * - 默认不打印，靠 BXROOT_SIGSYS_LOG=1 打开。
 */

#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>

#include "sigsys.h"

/* ------------------------------------------------------------------ */
/* 状态                                                                */
/* ------------------------------------------------------------------ */

static volatile int g_installed = 0;
static volatile int g_verbose = 0;
static volatile unsigned long g_total = 0;

/* 每个被拦系统调用号的命中计数，用于抑制重复日志。
 * 上限 512：aarch64 常用号都在这以内。用固定数组 —— 处理器内不能 malloc。 */
#define SC_MAX 512
static volatile unsigned int g_hits[SC_MAX];

/*
 * aarch64 的 siginfo 中 SIGSYS 专属字段布局：
 *   offset  0 : si_signo
 *   offset  4 : si_errno
 *   offset  8 : si_code
 *   offset 12 : padding
 *   offset 16 : si_call_addr
 *   offset 24 : si_syscall
 *   offset 28 : si_arch
 * 不要用 glibc 的 si_syscall 宏 —— 部分版本未定义，且 si_addr 在 SIGSYS
 * 下与 si_call_addr 重叠，容易误读。
 */
struct raw_sigsys_info {
    void   *call_addr;
    int     syscall;
    unsigned arch;
};

/* ------------------------------------------------------------------ */
/* 无 stdio 的输出                                                     */
/* ------------------------------------------------------------------ */

static void em_say(const char *s)
{
    if (s != NULL) {
        ssize_t r = write(2, s, strlen(s));
        (void)r;
    }
}

static void em_num(long v)
{
    char buf[24];
    int n = 0;
    unsigned long u = (v < 0) ? (unsigned long)(-v) : (unsigned long)v;

    do {
        buf[n++] = (char)('0' + (u % 10));
        u /= 10;
    } while (u > 0 && n < 20);

    if (v < 0)
        buf[n++] = '-';

    /* 反转后就地输出 */
    {
        char out[24];
        int i;
        for (i = 0; i < n; i++)
            out[i] = buf[n - 1 - i];
        {
            ssize_t w = write(2, out, (size_t)n);
            (void)w;
        }
    }
}

/* ------------------------------------------------------------------ */
/* 裸系统调用                                                          */
/* ------------------------------------------------------------------ */

static long raw4(long nr, long a, long b, long c, long d)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory", "cc");
    if (x0 < 0 && x0 > -4096) {
        errno = (int)(-x0);
        return -1;
    }
    return x0;
}

#define SYS_RT_SIGPROCMASK 175
#define SYS_RT_SIGACTION   134

/* ------------------------------------------------------------------ */
/* 处理器                                                              */
/* ------------------------------------------------------------------ */

/*
 * 被拦系统调用的模拟返回值。
 *
 * 统一 ENOSYS：这是程序**期望看到的、可回退的**错误码。libuv 见 ENOSYS
 * 即判定内核不支持 io_uring 并回退 epoll —— 是它已有的代码路径，
 * 不需要我们伪造任何结构体。
 */
static int emulate_errno(long sc)
{
    (void)sc;
    return ENOSYS;
}

static void sigsys_handler(int sig, siginfo_t *si, void *uc)
{
    struct raw_sigsys_info *rs;
    ucontext_t *u = (ucontext_t *)uc;
    long sc;

    (void)sig;

    if (si == NULL || u == NULL)
        return;

    rs = (struct raw_sigsys_info *)((char *)si + 16);
    sc = rs->syscall;
    g_total++;

    if (sc >= 0 && sc < SC_MAX) {
        unsigned int n = g_hits[sc];
        if (n != 0xffffffffu)
            g_hits[sc] = n + 1;
        if (g_verbose && n < 3) {
            em_say("[bxroot] sigsys: 模拟 syscall ");
            em_num(sc);
            em_say(" -> ENOSYS\n");
        }
    } else if (g_verbose) {
        em_say("[bxroot] sigsys: 模拟未知 syscall ");
        em_num(sc);
        em_say("\n");
    }

    /* 只设返回值，**不推进 PC** —— 理由见文件头。 */
    u->uc_mcontext.regs[0] = (unsigned long)(-emulate_errno(sc));
}

/* ------------------------------------------------------------------ */
/* 屏蔽防护                                                            */
/* ------------------------------------------------------------------ */

/*
 * 【重要更正】不拦截 pthread_sigmask / sigprocmask。
 *
 * 早期版本在这里做了"剔除 SIGSYS 屏蔽位"的防护，理由是实测有线程用
 * SIG_SETMASK 屏蔽 SIGSYS。但后续用最小复现程序验证发现：
 *
 *     pthread_sigmask(SIG_BLOCK, {SIGSYS}, &old) → 返回 0
 *     回读掩码：SIGSYS **并未被屏蔽**
 *
 * 也就是说 proroot 的加载器已经在保护 SIGSYS（静默忽略对它的屏蔽），
 * 我们的防护不仅多余，还有害：node 在 PlatformInit 阶段会调用
 * pthread_sigmask 并检查返回码与掩码一致性，我们的实现破坏了它的
 * 预期，导致 `Assertion failed: (err) == (0)` 后 abort（rc=134）。
 *
 * 结论：这一层只保留 SIGSYS 处理器的安装。屏蔽防护交给加载器。
 * 若将来在没有该保护的环境下运行（例如真机直跑、不经 proroot 加载器），
 * 再按需恢复 —— 但必须有实测证据表明屏蔽确实发生。
 */

/*
 * 防住 sigaction(SIGSYS, SIG_IGN/SIG_DFL)：忽略 SIGSYS 与屏蔽等价 ——
 * 被 TRAP 的调用没人处理，进程照样死。
 *
 * 注意这里**只拦截 SIGSYS 这一个信号**，其余一律透传给真实实现。
 * 早期版本对所有信号都走裸 syscall 转发，结果把 crash.c 的 SIGSEGV
 * 处理器安装也一起弄坏了（打印 "SIGSEGV handler install failed"），
 * 因为 glibc 的 sigaction 与内核 rt_sigaction 在 struct sigaction 的
 * 布局/标志处理上并不完全等价（glibc 会做 sa_restorer 等修补）。
 * 教训：能用真实实现的场合不要自己拼系统调用。
 */
int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
{
    static int (*real_sigaction_fn)(int, const struct sigaction *,
                                    struct sigaction *);

    if (sig == SIGSYS && act != NULL && g_installed) {
        if (act->sa_handler == SIG_IGN || act->sa_handler == SIG_DFL)
            return 0;   /* 静默拒绝，保持我们的处理器 */
    }

    /*
     * 透传一律走 glibc 的 __libc_sigaction。
     *
     * 不用 dlsym(RTLD_NEXT,"sigaction")：实测该环境里 dlsym 拿到的 libc
     * 地址不可靠（外层做活体代码补丁，跳进去会 SIGSEGV）。
     * 也不用裸 rt_sigaction：结构体布局不同（见安装处的详细说明）。
     */
    {
        extern int __libc_sigaction(int, const struct sigaction *,
                                    struct sigaction *);
        return __libc_sigaction(sig, act, old);
    }
    (void)real_sigaction_fn;
}

/* ------------------------------------------------------------------ */
/* 安装 / 卸载                                                         */
/* ------------------------------------------------------------------ */

int bxroot_sigsys_install(void)
{
    struct sigaction sa;
    sigset_t s;
    const char *e;

    if (g_installed)
        return 0;

    e = getenv("BXROOT_SIGSYS_LOG");
    g_verbose = (e != NULL && e[0] == '1') ? 1 : 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    /* 不设 SA_NODEFER：允许处理期间再被 SIGSYS 中断会引入重入风险。
     * 不设 SA_RESTART：本处理器不涉及被中断系统调用的恢复。 */
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSYS);

    /*
     * 【重要的坑】必须用 glibc 的 __libc_sigaction，**不能**直接调
     * rt_sigaction 传 glibc 的 struct sigaction。
     *
     * 两者布局不同：
     *   glibc: handler(0) mask(8,128字节) flags(136) restorer(144)  共 152 字节
     *   内核 : handler(0) flags(8) restorer(16) mask(24,128字节)
     *
     * 直接传会返回 EINVAL，处理器根本没装上（实测验证过：
     * "裸 rt_sigaction(glibc结构) = -1 errno=22"，读回 flags=0、
     * SA_SIGINFO 未置位）。这就是本层此前"装了却收不到信号"的原因。
     *
     * __libc_sigaction 是 glibc 导出的 GLIBC_PRIVATE 符号，内部做布局转换。
     */
    {
        extern int __libc_sigaction(int, const struct sigaction *,
                                    struct sigaction *);
        if (__libc_sigaction(SIGSYS, &sa, NULL) != 0)
            return -1;
    }

    /*
     * 主线程解除 SIGSYS 屏蔽。
     *
     * 用裸 syscall 而非 libc 的 sigprocmask —— 我们自己就 hook 了那个名字，
     * 在这里调用它会绕回本文件（重入）。而且实测加载器已保护 SIGSYS
     * （屏蔽请求会被静默忽略），这一步主要是幂等保险。
     */
    sigemptyset(&s);
    sigaddset(&s, SIGSYS);
    /*
     * sigset_t 在内核与 glibc 里都是 128 字节位图，布局一致，
     * 所以这里用裸 rt_sigprocmask 是安全的（与 sigaction 的情况不同）。
     * 用裸调用而非 libc 包装，是为了避免绕到本文件自己的钩子（重入）。
     */
    (void)raw4(SYS_RT_SIGPROCMASK, SIG_UNBLOCK, (long)&s, 0,
               (long)sizeof(sigset_t));

    g_installed = 1;

    if (g_verbose)
        em_say("[bxroot] sigsys 模拟层已安装\n");

    return 0;
}

int bxroot_sigsys_installed(void)
{
    return g_installed;
}

unsigned long bxroot_sigsys_total(void)
{
    return g_total;
}
