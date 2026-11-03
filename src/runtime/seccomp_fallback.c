/*
 * seccomp_fallback.c —— 静态映像的 seccomp 兜底层（被 static_exec.c 包含）
 *
 * 为什么需要
 * ----------
 * 装载期改写（sx_scan）只能改「看得见的」svc：号来自寄存器（Go 的
 * syscall.Syscall6）默认不改；JIT / 运行期生成的代码根本扫不到。这些 svc
 * 直达内核，路径不翻译，guest 静默访问到宿主文件系统。
 *
 * 做法：跳进静态映像前，自己再叠一层 seccomp 过滤器：
 *   - 只判定路径类系统调用（与 sx_wants_site 同集合）和 rt_sigaction /
 *     rt_sigprocmask；
 *   - 只在 instruction_pointer 落在本映像装载范围 [lo, hi) 内时返回
 *     SECCOMP_RET_TRAP | SFB_TAG；其余一律 ALLOW。
 * runtime、veneer 池、跳板、ld/bionic 都在范围外 → 经改写的站点（svc 在
 * 跳板里发）不进陷阱，只有漏网的 svc 才进。
 *
 * 代价（experiments/seccomp-window/README.md 的真机实测）：过滤器每个
 * syscall 约 +90 ns；陷阱路径 9–20 µs。所以它只能兜底，主路径仍是改写。
 *
 * 继承安全性（未经真机验证 → 默认关闭）
 * ------------------------------------
 * seccomp 过滤器跨 fork/exec 继承且不可撤销。真 execve 进原生程序后，只有
 * 原生代码恰好映射进 [lo, hi) 且发出上述系统调用时才会 TRAP（那时没有我们
 * 的处理器 → SIGSYS 杀进程）。ET_EXEC 静态程序通常在 0x400000 附近，Android
 * 原生可执行映射在 0x5x…/0x7x…，经验上不重叠，但这不是保证。所以默认关闭，
 * BXROOT_SECCOMP_FALLBACK=1 开启。
 *
 * 信号语义
 * --------
 * - 陷阱处理器常驻 SIGSYS。guest 经 rt_sigaction 改 SIGSYS 时（Go runtime 给
 *   几乎所有信号装处理器），只记进影子槽，不动真处理器；查询回读影子槽。
 * - 信号处理器的 sa_mask、rt_sigprocmask 的新集合都剔除 SIGSYS：SIGSYS 被
 *   屏蔽时内核遇 TRAP 直接杀进程。这两条只对映像范围内发出的调用生效。
 * - SA_NODEFER：dispatch 里发出的真 syscall 若被 Android 外层过滤器 TRAP
 *   （如 faccessat2），要能重入本处理器（走非 tag 分支 → sx_early_sigsys）。
 * - SA_ONSTACK：Go 给每个 M 配 gsignal 备用栈；guest 没配就用当前栈。
 *
 * 已知边界（如实）
 * ----------------
 * - guest 自己调 seccomp()/prctl(PR_SET_SECCOMP) 不拦。
 * - 陷阱里 dispatch 用 guest 当前栈（或其备用栈）；dispatch 帧约 8 KB。
 *   Go 的 gsignal 栈 32 KB，够；极小栈上直接发 svc 会溢出。
 * - 非 aarch64 不编译本层。
 */

#if defined(__aarch64__)

#define SFB_TAG        0x0bb1u        /* si_errno 里的标记（实验探针用 0x0bb0） */
#define SFB_SIGSYS     31
#define SFB_SIGBIT     (1UL << (SFB_SIGSYS - 1))

/* cBPF 指令（与 <linux/filter.h> 同布局；自带定义，免头文件组合差异） */
struct sfb_insn { unsigned short code; unsigned char jt, jf; unsigned int k; };
struct sfb_prog { unsigned short len; struct sfb_insn *filter; };

#define SFB_LD_W_ABS   0x20            /* BPF_LD|BPF_W|BPF_ABS */
#define SFB_JEQ_K      0x15            /* BPF_JMP|BPF_JEQ|BPF_K */
#define SFB_JGT_K      0x25            /* BPF_JMP|BPF_JGT|BPF_K */
#define SFB_JGE_K      0x35            /* BPF_JMP|BPF_JGE|BPF_K */
#define SFB_RET_K      0x06            /* BPF_RET|BPF_K */

#define SFB_RET_ALLOW  0x7fff0000u
#define SFB_RET_TRAP   0x00030000u

#define SFB_OFF_NR     0
#define SFB_OFF_ARCH   4
#define SFB_OFF_IP_LO  8
#define SFB_OFF_IP_HI  12

static volatile int sfb_active;                 /* 本进程已装过本层的过滤器（诊断） */
static volatile int sfb_guest_set;              /* guest 是否改过 SIGSYS */
static struct sx_ksigaction sfb_guest_sa;       /* guest 要求的 SIGSYS 处理方式 */
static volatile unsigned long sfb_traps;        /* 诊断：陷阱次数 */

/* 需要陷阱的号：路径类（与 sx_wants_site 一致）+ 信号设置 */
static const unsigned short sfb_nrs[] = {
    5, 6, 8, 9, 11, 12, 14, 15,                 /* *xattr */
    17,                                         /* getcwd */
    33, 34, 35, 36, 37, 38, 43, 45, 48, 49, 53, 54, 56,
    78, 79, 88,
    134, 135,                                   /* rt_sigaction / rt_sigprocmask */
    194, 195, 196, 197,                         /* SysV shm（dispatch 模拟） */
    221, 276, 281, 291, 439,
};
#define SFB_NNR    (sizeof(sfb_nrs) / sizeof(sfb_nrs[0]))
#define SFB_MAXINS (4 + SFB_NNR + 16)

/*
 * 生成过滤器，返回指令条数（失败 -1）。布局：
 *   ld arch; jeq AARCH64 ? next : ALLOW
 *   ld nr;   jeq nr_i ? RANGE : next  ×N；末尾 → ALLOW
 *   RANGE:   ip >= lo ? CHKHI : ALLOW      （64 位无符号，拆高低 32 位）
 *   CHKHI:   ip <  hi ? TRAP  : ALLOW
 *   ALLOW / TRAP
 * 跳转目标先记符号/绝对下标，最后换算成相对偏移（目标 - 当前 - 1）。
 */
enum { SFB_L_NEXT = -1, SFB_L_ALLOW = -2, SFB_L_TRAP = -3, SFB_L_RANGE = -4, SFB_L_CHKHI = -5 };

static int sfb_build(struct sfb_insn *f, int cap, unsigned long lo, unsigned long hi)
{
    int jt[SFB_MAXINS], jf[SFB_MAXINS];
    int n = 0, i, at_range = -1, at_chkhi = -1, at_allow, at_trap;
    unsigned lo_h = (unsigned)(lo >> 32), lo_l = (unsigned)lo;
    unsigned hi_h = (unsigned)(hi >> 32), hi_l = (unsigned)hi;

    if (cap > (int)SFB_MAXINS || hi <= lo)
        return -1;
#define SFB_EMIT(c, t, e, kk) do { \
        if (n >= cap) return -1; \
        f[n].code = (c); f[n].k = (kk); f[n].jt = 0; f[n].jf = 0; \
        jt[n] = (t); jf[n] = (e); n++; \
    } while (0)

    SFB_EMIT(SFB_LD_W_ABS, 0, 0, SFB_OFF_ARCH);
    SFB_EMIT(SFB_JEQ_K, SFB_L_NEXT, SFB_L_ALLOW, 0xC00000B7u);   /* AUDIT_ARCH_AARCH64 */
    SFB_EMIT(SFB_LD_W_ABS, 0, 0, SFB_OFF_NR);
    for (i = 0; i < (int)SFB_NNR; i++)
        SFB_EMIT(SFB_JEQ_K, SFB_L_RANGE,
                 i + 1 == (int)SFB_NNR ? SFB_L_ALLOW : SFB_L_NEXT, sfb_nrs[i]);

    /* RANGE: ip >= lo */
    at_range = n;
    SFB_EMIT(SFB_LD_W_ABS, 0, 0, SFB_OFF_IP_HI);
    SFB_EMIT(SFB_JGT_K, SFB_L_CHKHI, SFB_L_NEXT, lo_h);      /* ip_h >  lo_h → 过下界 */
    SFB_EMIT(SFB_JEQ_K, SFB_L_NEXT, SFB_L_ALLOW, lo_h);      /* ip_h <  lo_h → 放行 */
    SFB_EMIT(SFB_LD_W_ABS, 0, 0, SFB_OFF_IP_LO);
    SFB_EMIT(SFB_JGE_K, SFB_L_CHKHI, SFB_L_ALLOW, lo_l);

    /* CHKHI: ip < hi */
    at_chkhi = n;
    SFB_EMIT(SFB_LD_W_ABS, 0, 0, SFB_OFF_IP_HI);
    SFB_EMIT(SFB_JGT_K, SFB_L_ALLOW, SFB_L_NEXT, hi_h);      /* ip_h >  hi_h → 放行 */
    SFB_EMIT(SFB_JEQ_K, SFB_L_NEXT, SFB_L_TRAP, hi_h);       /* ip_h <  hi_h → 陷阱 */
    SFB_EMIT(SFB_LD_W_ABS, 0, 0, SFB_OFF_IP_LO);
    SFB_EMIT(SFB_JGE_K, SFB_L_ALLOW, SFB_L_TRAP, hi_l);

    at_allow = n;
    SFB_EMIT(SFB_RET_K, 0, 0, SFB_RET_ALLOW);
    at_trap = n;
    SFB_EMIT(SFB_RET_K, 0, 0, SFB_RET_TRAP | SFB_TAG);
#undef SFB_EMIT

    for (i = 0; i < n; i++) {
        int k, tgt[2];

        if ((f[i].code & 0x07) != 0x05)        /* 非 BPF_JMP */
            continue;
        tgt[0] = jt[i];
        tgt[1] = jf[i];
        for (k = 0; k < 2; k++) {
            int t = tgt[k], off;

            switch (t) {
            case SFB_L_NEXT:  t = i + 1;   break;
            case SFB_L_ALLOW: t = at_allow; break;
            case SFB_L_TRAP:  t = at_trap;  break;
            case SFB_L_RANGE: t = at_range; break;
            case SFB_L_CHKHI: t = at_chkhi; break;
            default: break;
            }
            off = t - i - 1;
            if (off < 0 || off > 255)
                return -1;
            if (k == 0) f[i].jt = (unsigned char)off;
            else        f[i].jf = (unsigned char)off;
        }
    }
    return n;
}

/* rt_sigaction(134)：SIGSYS 只进影子槽；其余信号剔除 sa_mask 里的 SIGSYS 后真调 */
static long sfb_sigaction(long sig, long act, long old, long size)
{
    struct sx_ksigaction tmp;

    if (sig == SFB_SIGSYS) {
        if (old != 0) {
            if (sfb_guest_set)
                memcpy((void *)(uintptr_t)old, &sfb_guest_sa, sizeof tmp);
            else
                memset((void *)(uintptr_t)old, 0, sizeof tmp);   /* SIG_DFL */
        }
        if (act != 0) {
            memcpy(&sfb_guest_sa, (const void *)(uintptr_t)act, sizeof tmp);
            sfb_guest_set = 1;
        }
        return 0;
    }
    if (act != 0) {
        memcpy(&tmp, (const void *)(uintptr_t)act, sizeof tmp);
        if (tmp.mask & SFB_SIGBIT) {
            tmp.mask &= ~SFB_SIGBIT;
            act = (long)(uintptr_t)&tmp;
        }
    }
    return sx_sc6(134, sig, act, old, size, 0, 0);
}

/*
 * rt_sigprocmask(135)：BLOCK / SETMASK 的新集合剔除 SIGSYS。
 *
 * ★ 必须改 ucontext 里的 uc_sigmask，不能在处理器里真调 rt_sigprocmask ★
 * 处理器返回时 rt_sigreturn 会用 uc_sigmask 恢复掩码，处理器里改的掩码
 * 随即被覆盖（单测 F 实测：改完读回 mask=0）。所以这里按内核语义直接
 * 计算新掩码写回 uc_sigmask（AArch64：ucontext 偏移 40，8 字节内核 sigset）。
 * SIGKILL/SIGSTOP 与内核一样不可屏蔽。
 */
static long sfb_sigprocmask(void *uc, long how, long set, long old, long size)
{
    unsigned long *cur = (unsigned long *)((char *)uc + 40);
    unsigned long m, nm;

    if (size != 8)
        return -EINVAL;
    if (set != 0 && how != 0 && how != 1 && how != 2)
        return -EINVAL;
    nm = *cur;
    if (set != 0) {
        memcpy(&m, (const void *)(uintptr_t)set, sizeof m);
        if (how == 0)      nm |= m;
        else if (how == 1) nm &= ~m;
        else               nm = m;
        nm &= ~(SFB_SIGBIT | (1UL << (9 - 1)) | (1UL << (19 - 1)));
    }
    if (old != 0)
        memcpy((void *)(uintptr_t)old, cur, sizeof *cur);
    *cur = nm;
    return 0;
}

/* 非 seccomp 来源的 SIGSYS（kill/tgkill）：交给 guest 的影子设置；没有就忽略 */
static void sfb_forward_guest(int s, void *si, void *uc)
{
    unsigned long h = sfb_guest_sa.handler;

    if (!sfb_guest_set || h <= 1UL)
        return;
    if (sfb_guest_sa.flags & 4 /* SA_SIGINFO */)
        ((void (*)(int, void *, void *))h)(s, si, uc);
    else
        ((void (*)(int))h)(s);
}

static void sfb_handler(int s, void *si, void *uc)
{
    int *sv = (int *)si;
    unsigned long long *regs;
    unsigned long gtls;
    long nr, r;

    if (si == NULL || uc == NULL)
        return;
    if (sv[2] != 1 /* SYS_SECCOMP */) {
        sfb_forward_guest(s, si, uc);
        return;
    }
    if ((unsigned)sv[1] != SFB_TAG) {
        sx_early_sigsys(s, si, uc);           /* Android 外层过滤器的陷阱：原有语义 */
        return;
    }
    /* AArch64 ucontext：mcontext.regs 在偏移 184（见 sx_early_sigsys） */
    regs = (unsigned long long *)((char *)uc + 184);
    nr = (long)regs[8];
    sfb_traps++;

    if (nr == 134) {
        regs[0] = (unsigned long)sfb_sigaction((long)regs[0], (long)regs[1],
                                               (long)regs[2], (long)regs[3]);
        return;
    }
    if (nr == 135) {
        regs[0] = (unsigned long)sfb_sigprocmask(uc, (long)regs[0], (long)regs[1],
                                                 (long)regs[2], (long)regs[3]);
        return;
    }

    /* dispatch 要用 runtime（动态 libc）的 TLS：errno / getenv / malloc */
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(gtls));
    if (px_static_dyn_tls != 0)
        __asm__ volatile("msr tpidr_el0, %0" :: "r"(px_static_dyn_tls) : "memory");
    r = px_static_dispatch((long)regs[0], (long)regs[1], (long)regs[2],
                           (long)regs[3], (long)regs[4], (long)regs[5], nr);
    __asm__ volatile("msr tpidr_el0, %0" :: "r"(gtls) : "memory");
    regs[0] = (unsigned long)r;            /* PC 已在 svc 之后，不推进 */
}

/* 常驻 SIGSYS 处理器（替代 sx_early_sigsys 的安装） */
static int sfb_install_handler(void)
{
    struct sx_ksigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.handler = (unsigned long)(void *)&sfb_handler;
    sa.flags = 4 /* SA_SIGINFO */ | 0x40000000 /* SA_NODEFER */ | 0x08000000 /* SA_ONSTACK */;
    sfb_guest_set = 0;                     /* execve 语义：guest 设置随旧映像作废 */
    memset(&sfb_guest_sa, 0, sizeof sfb_guest_sa);
    return (int)SC(SYS_rt_sigaction, SFB_SIGSYS, &sa, 0, 8);
}

/* 叠加过滤器：[lo, hi) 内发出的路径类 / 信号设置调用 → TRAP|SFB_TAG */
static int sfb_install_filter(unsigned long lo, unsigned long hi)
{
    struct sfb_insn f[SFB_MAXINS];
    struct sfb_prog prog;
    int n = sfb_build(f, SFB_MAXINS, lo, hi);
    long r;

    if (n <= 0)
        return -EINVAL;
    r = SC(167 /* prctl */, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0);
    if (r != 0)
        return (int)r;
    prog.len = (unsigned short)n;
    prog.filter = f;
    r = SC(277 /* seccomp */, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &prog, 0);
    if (r != 0)
        return (int)r;
    sfb_active = 1;
    return 0;
}

#endif /* __aarch64__ */
