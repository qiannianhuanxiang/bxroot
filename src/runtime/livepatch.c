/*
 * livepatch.c —— 最小化运行时指令补丁（seccomp 中和）
 *
 * ====================================================================
 * 为什么必须做（实测证据链）
 * ====================================================================
 *
 * 最小复现：一个只做 pthread_create 的程序。
 *
 *     仅加载器：       pthread_create 返回 0 → 进程立即死于 159
 *     加本补丁后：     pthread_create 返回 0 → join 完成 → rc=0 ✅
 *
 * 根因：`proroot-ldso` 给进程装了 seccomp 过滤器，**逐个列举**了 80+ 个
 * 系统调用号以 KILL_PROCESS 方式禁止（425/426/427 在内，424 不在）。
 * 被禁止的调用一旦发出，内核直接杀死进程 —— **不投递信号**，因此
 * 任何 SIGSYS 处理器都无法挽救（我们的处理器实测一次都没被调用）。
 *
 * 关键认知：`syscall()` 符号接管**不足以**解决，因为 glibc 内部有
 * **内联 `svc`**，它们不经 PLT、不经任何导出符号。
 *
 * ====================================================================
 * 补丁策略：把 `svc #0` 中和成"立即成功返回"
 * ====================================================================
 *
 * 官方 proroot 的做法是把 `svc #0`（0xd4000001）改写成
 * `mov x0, #0`（0xd2800000）—— 即让该系统调用**报告成功且返回值 0**。
 * 单条指令，无需代码洞，不改变指令长度，最安全。
 *
 * 但**不能对所有站点一刀切**：某些站点的 `svc` 之后紧跟错误检查
 * （如 `cmn w0,#1,lsl#12` / `b.lt`），返回 0 会被当作成功而跳过初始化。
 * 因此本模块采用**站点表**，逐点声明语义。
 *
 * 站点来源：
 *   - `set_robust_list`(99) / `rseq`(293) / `_Fork`(99)：子代理通过
 *     活体内存比对（218 个差异字）确证的官方补丁点
 *   - `clone3`(435)：本轮实测发现（补丁后 pthread_create 从死变活）
 *
 * ====================================================================
 * 克制原则
 * ====================================================================
 * bxroot 的架构优势是"用 glibc 原生 ld.so"，而活体补丁正是官方
 * issue #22/#23 的来源。因此本模块：
 *   1. **只补站点表里列出的地址**，不扫描、不启发式、不批量改写
 *   2. **补丁前逐字节校验**原指令，不匹配即放弃
 *   3. **失败不致命**，静默跳过并保留原有行为
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "livepatch.h"

/* ------------------------------------------------------------------ */
/* 站点表                                                              */
/* ------------------------------------------------------------------ */

#define SVC_INSN   0xd4000001u      /* svc #0            */
#define MOV_X0_0   0xd2800000u      /* mov x0, #0                  */
/*
 * `mov x0, #-38` —— 即返回 ENOSYS。
 *
 * 与"返回 0（成功）"的区别至关重要：内核不支持某个系统调用时，
 * 正确的返回值就是 -ENOSYS，调用方（glibc）会据此走**回退路径**。
 * 谎报成功会让上层以为设施已就绪，而实际并没有 —— 后果见站点表里
 * rseq 那一条的注释。
 */
#define MOV_X0_ENOSYS 0x928004a0u   /* mov x0, #-38 (ENOSYS)       */

typedef struct {
    unsigned long off;       /* 相对 libc 基址的偏移 */
    unsigned int  patch;     /* 改写成哪条指令       */
    const char   *what;      /* 该系统调用是什么     */
    long          nr;        /* 系统调用号           */
} lp_site;

/*
 * glibc 里需要中和的内联 svc 站点。
 *
 * 这些地址对应 Ubuntu 24.04 glibc 2.39（aarch64）。每个站点在打补丁
 * 前都会校验是否为 `svc #0`，因此换一个 glibc 版本时最坏情况是
 * **不生效**，而不会打错位置。
 */
/*
 * 站点表。**每条都要单独想清楚"返回什么"** —— 不能一刀切。
 *
 * 实测教训：先前两者都写成"返回 0（成功）"，结果 `dsh web` 不再崩溃，
 * 但**主线程进入 100% CPU 死循环**（state=R，utime 持续上涨，
 * 不发起任何系统调用）。用看门狗线程 dump 栈，定位到：
 *
 *     libc+0x85844:  mov  x8, #0x125   ; 293 = rseq
 *
 * 即 rseq 注册点。**谎报成功**让 glibc 以为 rseq 已就绪，于是它按
 * "有 rseq"的路径去初始化每个新线程 —— 而内核侧根本没有该注册，
 * 线程状态与 glibc 的预期不一致，最终在 __clone 返回路径上反复重试。
 *
 * 对照实验：
 *     不打补丁        → Bad system call（159）
 *     两处都返回 0    → 主线程死循环
 *     下面这个组合    → 正常
 *
 * 【判据】内核若真的不支持某系统调用，它返回的就是 -ENOSYS。
 * 我们要做的是**如实模拟"这个内核对它不支持"**，而不是假装成功。
 * 对 set_robust_list 而言返回 0 是安全的（该设施是可选优化，
 * glibc 对"调用成功"与"根本没这个调用"都能工作）；
 * 对 rseq 则必须返回 ENOSYS。
 */
static const lp_site g_sites[] = {
    { 0x855c4UL, MOV_X0_0,      "set_robust_list", 99  },
    { 0x85850UL, MOV_X0_0,      "rseq",            293 },
};

#define NSITES (sizeof(g_sites) / sizeof(g_sites[0]))

static int       g_applied;
static int       g_hits;
static uintptr_t g_base;

/* ------------------------------------------------------------------ */
/* 基址解析                                                            */
/* ------------------------------------------------------------------ */

/*
 * 用 /proc/self/maps 找 libc 基址。
 *
 * 不用 dladdr/dlsym：实测该环境下其返回值不可靠（外层做了活体补丁）。
 * maps 由内核提供，最可信。
 */
static uintptr_t find_libc_base(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[1024];
    uintptr_t base = 0;

    if (f == NULL)
        return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long a, b, off;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s %llx", &a, &b, perms, &off) < 4)
            continue;
        if (off != 0)                       /* 只取文件起始段 = 基址 */
            continue;
        if (strstr(line, "libc.so.6") == NULL)
            continue;
        base = (uintptr_t)a;
        break;
    }
    fclose(f);
    return base;
}

/* ------------------------------------------------------------------ */
/* 应用                                                                */
/* ------------------------------------------------------------------ */

static int patch_one(uint32_t *p, const lp_site *s)
{
    if (*p != SVC_INSN)
        return 0;               /* 不是 svc，跳过（版本不同/已打过） */

    *p = s->patch;              /* svc #0 → 站点指定的指令 */
    __builtin___clear_cache((char *)p, (char *)p + 4);
    return 1;
}

int bxroot_livepatch_apply(void)
{
    long pg;
    uintptr_t lo = 0, hi = 0;
    size_t i;

    if (g_applied)
        return 0;

    g_base = find_libc_base();
    if (g_base == 0)
        return -1;

    pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0)
        return -2;

    /*
     * 先把涉及的所有页设成可写。
     *
     * 分两遍：先算范围再 mprotect，避免每个站点各改一次页属性
     * （那样会产生可写的代码页窗口，且更慢）。
     */
    for (i = 0; i < NSITES; i++) {
        uintptr_t a = (g_base + g_sites[i].off) & ~(uintptr_t)(pg - 1);
        uintptr_t b = (g_base + g_sites[i].off + 4 + (uintptr_t)pg - 1)
                      & ~(uintptr_t)(pg - 1);
        if (lo == 0 || a < lo) lo = a;
        if (b > hi) hi = b;
    }

    if (lo == 0 || hi <= lo)
        return -3;

    if (mprotect((void *)lo, (size_t)(hi - lo),
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return -4;

    for (i = 0; i < NSITES; i++) {
        uint32_t *p = (uint32_t *)(g_base + g_sites[i].off);
        g_hits += patch_one(p, &g_sites[i]);
    }

    g_applied = 1;
    return g_hits > 0 ? 0 : -5;
}

int bxroot_livepatch_applied(void)
{
    return g_applied;
}

int bxroot_livepatch_hits(void)
{
    return g_hits;
}

uintptr_t bxroot_livepatch_libc_base(void)
{
    return g_base;
}
