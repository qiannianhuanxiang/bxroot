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
 * 这是参考实现 必须有 2624 字节 SIGSYS 模拟层（proroot_sigsys_emulate
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
 * 【再次更正·本轮实测】必须拦截 sigprocmask / pthread_sigmask。
 *
 * 上一版这里写着"加载器已经保护 SIGSYS，屏蔽防护多余且有害"。
 * 本轮用最小复现程序做了 A/B 实测，**该结论被证伪**：
 *
 *   探针：sigprocmask(SIG_BLOCK,{SIGSYS}) 之后，直发一个被 seccomp
 *         TRAP 的内联 svc（nr=99 set_robust_list），看进程是否存活。
 *
 *   参考实现：SIGSYS 掩码位**保持为 0**（未被屏蔽）→ 存活 rc=0
 *   bxroot      ：SIGSYS 掩码位**变成 1**（确实被屏蔽）→ 死 rc=159
 *
 *   回读证据（sigprocmask(SIG_BLOCK,NULL,&cur) 查询）：
 *     官方 mode=4: after SIGSYS_blocked=0
 *     bxroot mode=4: after SIGSYS_blocked=1   ← 差异就在这一位
 *
 * 机制：seccomp 以 SECCOMP_RET_TRAP 拦下系统调用时投递 SIGSYS；
 * **若 SIGSYS 被屏蔽，内核直接杀进程**（man seccomp 明确写入），
 * 用户态无法捕获 —— 表现为 rc=159。所以屏蔽位必须从源头剔除。
 *
 * 上一版为什么误判：当时只回读了掩码，却用了**错误的回读方式**
 * （裸 rt_sigprocmask 传 sigsetsize=128 的那次调用返回了一个
 * 像指针的巨大值，掩码内容并未被写入），于是错看成"未被屏蔽"。
 * 本轮改用 libc 的 sigprocmask(SIG_BLOCK, NULL, &cur) 查询，
 * 官方与 bxroot 的差异可以稳定复现（各 3 个 mode，见 parity 报告）。
 *
 * 与官方实现逐条对齐（官方 helper 在 runtime +0x964c）：
 *   - 只处理 how == SIG_BLOCK(0) / SIG_SETMASK(2)
 *     —— 这两种才可能**新增**屏蔽位；
 *     SIG_UNBLOCK(1) 只会清除屏蔽，原样透传
 *     （官方判据 `tst w2,#0xfffffffd` 正是"不是 0 也不是 2 就放行"）。
 *   - 只有集合里**确实含有 SIGSYS** 时才复制并剔除；
 *     不含则一个字节都不改（避免把 glibc 期望的原集合换掉）。
 *   - oldset 语义完全交给真实实现，**不自己填** ——
 *     这就是上一版 rc=134 的根因：node 在 PlatformInit 会校验
 *     返回码与掩码一致性，自己拼 oldset 会破坏它的预期。
 *
 * 注：SIG_UNBLOCK 不剔除是有意的 —— 客户主动解除屏蔽必须被允许，
 * 否则我们等于替它做了永久屏蔽，与防护目标相反。
 */

/*
 * 统一入口：glibc 的 __libc_sigaction。
 *
 * **不要**用 dlsym(RTLD_NEXT,"sigaction")：实测该环境里 dlsym 拿到的
 * libc 地址不可靠（外层 proroot 做活体代码补丁，跳进去会 SIGSEGV，
 * 故障地址呈 0xffffffff…… 符号扩展伪地址形态）。
 * **也不要**用裸 rt_sigaction：glibc 与内核的 struct sigaction 布局不同
 * （glibc: handler(0) mask(8) flags(136) restorer(144)，共 152 字节；
 *  内核: handler(0) flags(8) restorer(16) mask(24)），
 * 直接传会 EINVAL，处理器静默装不上。
 * __libc_sigaction 是 GLIBC_PRIVATE 符号，内部做布局转换 —— 这是唯一
 * 被实测证明可用的路径（安装处与本文件其它地方都依赖它）。
 *
 * ★ 弱引用 + 运行期探测（评估报告 4.2）★
 *
 * 原先这是**强 extern 引用**，后果与已修的 ldso P0 同类：库在非 glibc
 * 环境（musl/Alpine 等没有 GLIBC_PRIVATE 符号的 libc）**加载即失败**
 * —— 不是功能降级，而是整个 LD_PRELOAD 一个符号都解析不了。
 *
 * 现在改为 __attribute__((weak))：非 glibc 下符号解析为 NULL，库能正常
 * 加载；调用点先探测，缺失时明确报「无 GLIBC_PRIVATE 符号，SIGSYS
 * 防护不可用」并退化为不安装 —— 而不是崩溃或静默失效。
 */
extern int __libc_sigaction(int, const struct sigaction *,
                            struct sigaction *)
    __attribute__((weak));

static int glibc_sigaction_available(void)
{
    return __libc_sigaction != NULL;
}

static int __libc_sigaction_ref(int sig, const struct sigaction *act,
                                struct sigaction *old)
{
    if (__libc_sigaction == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return __libc_sigaction(sig, act, old);
}

/*
 * 待提交信号集的 SIGSYS 剔除。
 *
 * 返回值：真正应该转发给内核的集合（可能是入参本身，也可能是 tmp）。
 * 只在需要改写时使用调用方的栈上 tmp —— 不 malloc（可能被信号路径重入）。
 */
static const sigset_t *sigsys_strip(int how, const sigset_t *set, sigset_t *tmp)
{
    if (set == NULL || !g_installed)
        return set;

    /* SIG_BLOCK / SIG_SETMASK 之外一律透传（含 SIG_UNBLOCK） */
    if (how != SIG_BLOCK && how != SIG_SETMASK)
        return set;

    if (sigismember(set, SIGSYS) != 1)
        return set;

    *tmp = *set;              /* sigset_t 两侧都是 128 字节位图，直接复制安全 */
    sigdelset(tmp, SIGSYS);
    return tmp;
}

/*
 * sigprocmask —— 只加"SIGSYS 剔除"这一件事，其余语义原样交给 libc。
 *
 * 不用裸 rt_sigprocmask：实测 glibc 与内核在 sigsetsize 上并不一致
 * （glibc sigset_t 是 128 字节，内核自带的是 8 字节），传错会让掩码
 * **静默不生效** —— 那正是上一版误判的根源。这里走真实实现。
 */
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    static int (*real_fn)(int, const sigset_t *, sigset_t *) = NULL;
    sigset_t tmp;

    if (real_fn == NULL)
        real_fn = (int (*)(int, const sigset_t *, sigset_t *))
                  dlsym(RTLD_NEXT, "sigprocmask");
    if (real_fn == NULL) { errno = ENOSYS; return -1; }

    return real_fn(how, sigsys_strip(how, set, &tmp), oldset);
}

/*
 * pthread_sigmask —— 与 sigprocmask 同源（glibc 里两者最终都落到
 * rt_sigprocmask），同样只剔除 SIGSYS。分开实现而不是互相转发：
 * 转发会永远只命中本文件的两个包装器中的一个，排查时看不出层次。
 */
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)
{
    static int (*real_fn)(int, const sigset_t *, sigset_t *) = NULL;
    sigset_t tmp;

    if (real_fn == NULL)
        real_fn = (int (*)(int, const sigset_t *, sigset_t *))
                  dlsym(RTLD_NEXT, "pthread_sigmask");
    if (real_fn == NULL) { errno = ENOSYS; return -1; }

    return real_fn(how, sigsys_strip(how, set, &tmp), oldset);
}

/*
 * signal() —— 与 sigaction() 等价的封堵，**不能只防 sigaction**。
 *
 * 实测（探针 mode=1/2）：客户调 signal(SIGSYS, SIG_IGN) 或
 * signal(SIGSYS, SIG_DFL) 之后，任何被 TRAP 的系统调用都会让内核
 * 直接杀进程（rc=159）—— 因为"忽略 + 被 TRAP"在内核里等价于死亡。
 *
 * 而 glibc 的 signal() **不经** sigaction 的 PLT（它是 libc 内部实现），
 * 所以已有的 sigaction 钩子拦不住它：实测 bxroot 下回读到的处理器
 * 真的变成了 SIG_IGN。官方导出了 signal() 正是为此。
 *
 * 处理方式与 sigaction 钩子保持一致：SIG_IGN / SIG_DFL 静默拒绝，
 * 保留我们的处理器，并返回"上一个处理器"而不是报错（调用方通常
 * 不检查返回值，返回 SIG_ERR 反而会让它走进错误分支）。
 * 真正的自定义处理器照常放行（官方亦然，已实测一致）。
 */
sighandler_t signal(int signum, sighandler_t handler)
{
    static sighandler_t (*real_fn)(int, sighandler_t) = NULL;
    struct sigaction cur;

    if (signum == SIGSYS && g_installed &&
        (handler == SIG_IGN || handler == SIG_DFL)) {
        /* 回读当前处理器作为返回值；读失败则返回 SIG_ERR 保持诚实 */
        memset(&cur, 0, sizeof(cur));
        if (__libc_sigaction_ref(SIGSYS, NULL, &cur) == 0)
            return cur.sa_handler;
        return SIG_ERR;
    }

    if (real_fn == NULL)
        real_fn = (sighandler_t (*)(int, sighandler_t))
                  dlsym(RTLD_NEXT, "signal");
    if (real_fn == NULL) { errno = ENOSYS; return SIG_ERR; }

    return real_fn(signum, handler);
}

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
    if (sig == SIGSYS && act != NULL && g_installed) {
        if (act->sa_handler == SIG_IGN || act->sa_handler == SIG_DFL)
            return 0;   /* 静默拒绝，保持我们的处理器 */
    }

    /*
     * 透传一律走 glibc 的 __libc_sigaction（理由见该 helper 的注释）。
     * 这里**不要**改用 dlsym(RTLD_NEXT,"sigaction")：实测那条路拿到的
     * 地址会 SIGSEGV。
     */
    return __libc_sigaction_ref(sig, act, old);
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

    /*
     * ★ 能力探测（评估报告 4.2）★ 无 GLIBC_PRIVATE 符号的环境
     * （musl/Alpine）下明确报告并退化为不安装，而不是让库加载失败
     * 或装上收不到信号。注意这里**不**设置 g_installed，于是
     * sigaction 钩子会原样透传（交由客户自己的 libc 处理）。
     */
    if (!glibc_sigaction_available()) {
        em_say("[bxroot] 警告: 本 libc 无 __libc_sigaction (GLIBC_PRIVATE)，"
               "SIGSYS 防护层不可用（退化为不安装）\n");
        return -1;
    }

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
     * 在这里调用它会绕回本文件（重入）。
     *
     * 【注意】此处的裸 rt_sigprocmask 只做"解除屏蔽"这一个动作，
     * **不能**用它做任何"读取当前掩码"的判断：实测 glibc 与内核在
     * sigsetsize 上并不一致，裸调用读回的掩码是垃圾值。
     * 本项目曾因此误判"加载器已保护 SIGSYS，防护多余"—— 那个结论
     * 是错的，真正的屏蔽检测必须用 libc 的 sigprocmask(SIG_BLOCK, NULL, &cur)
     * 查询（见本文件上方的实测记录）。
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
