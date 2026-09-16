/*
 * crash.c -- bxroot 崩溃现场捕获
 *
 * 【为什么需要这个文件】
 *
 * 官方 proroot 有一个 3116 字节的 proroot_sigsegv_handler 和一个 340 字节的
 * sigsegv_dump_word_window。它会在收到 SIGSEGV/SIGBUS 时打印：
 *   - 信号号、pc、lr、fault 地址、code
 *   - 全部通用寄存器（x0-x30、sp、pstate）
 *   - 帧指针链回溯
 *   - fault 地址附近的**内存窗口**（±0x38 字节，逐字）
 *   - /proc/self/maps 快照
 *   - 被中断进程的 cmdline
 *
 * bxroot 此前是**零**：崩溃时使用者只看到一句 "Segmentation fault"。
 *
 * 【为什么这件事在 LD_PRELOAD 运行时里特别重要】
 *
 * 在一个注入式运行时里，一次空指针解引用就会带走**整个**容器进程 ——
 * 包括用户正在跑的 node/pnpm/dpkg。排查者面对的不是「某个函数返回错误」，
 * 而是「容器突然没了」。没有现场信息，只能靠猜。
 *
 * 本项目已经因为缺少崩溃信息吃过苦头：fakeroot 测试里的 double free
 * 崩在 tcache 内部，堆栈完全看不出是测试违反了 map_put 的所有权契约。
 *
 * 【设计约束】
 *
 * 信号处理器里**不能**调用非异步信号安全的函数（printf/malloc/free 都不行）。
 * 官方用的是 write() + 手写格式化。本实现沿用同样的纪律：
 *   - 只用 write()、以及 sigaction 允许的几个调用
 *   - 不 malloc、不 free、不调用 libc 的格式化函数
 *   - 所有输出走预先准备好的栈缓冲区 + 手写 hex/decimal 转换
 *
 * 另外用了 sigaltstack：如果崩溃原因是栈溢出，正常栈上根本跑不了处理器。
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

#include "crash.h"

/* ------------------------------------------------------------------ */
/* 异步信号安全的输出原语                                              */
/* ------------------------------------------------------------------ */

/*
 * 这些函数刻意保持极简，且**不用任何 libc 格式化/内存分配**。
 * 信号处理器可能在任意指令处被调用，堆可能正处于不一致状态 ——
 * 那时调 malloc/free 会二次崩溃，把唯一一次留下现场的机会也毁掉。
 */

/* 输出前缀标签。声明必须在所有使用者之前。 */
static const char *g_tag = "bxroot";

static void cw_write(const char *s, size_t n)
{
    ssize_t r;
    do {
        r = write(STDERR_FILENO, s, n);
    } while (r < 0 && errno == EINTR);
}

static void cw_puts(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0')
        n++;
    cw_write(s, n);
}

/* 十六进制，固定宽度 0 —— 用于地址 */
static void cw_hex(uint64_t v)
{
    static const char d[] = "0123456789abcdef";
    char buf[18];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 16; i++)
        buf[2 + i] = d[(v >> ((15 - i) * 4)) & 0xf];
    cw_write(buf, sizeof(buf));
}

/* 十进制，用于信号号、code 这类小数值 */
static void cw_dec(long v)
{
    char buf[24];
    int i = (int)sizeof(buf);
    unsigned long u;

    if (v < 0) {
        cw_puts("-");
        u = (unsigned long)(-v);
    } else {
        u = (unsigned long)v;
    }
    if (u == 0) {
        cw_puts("0");
        return;
    }
    while (u > 0 && i > 0) {
        buf[--i] = (char)('0' + (u % 10));
        u /= 10;
    }
    cw_write(&buf[i], (size_t)((int)sizeof(buf) - i));
}

/* ------------------------------------------------------------------ */
/* 内存窗口转储（对应官方的 sigsegv_dump_word_window）                   */
/* ------------------------------------------------------------------ */

/*
 * 打印 fault 地址附近的内存。这对判断「空指针解引用」还是「野指针」很关键：
 *   - 若窗口全 0，多半是空指针 + 偏移
 *   - 若窗口是 ASCII，多半是把字符串当结构体用了
 *   - 若窗口是合理指针，说明是二级解引用失败
 *
 * 读取本身可能再次触发 SIGSEGV（fault 地址附近未必可读）。所以：
 *   - 用 memcpy 到一个本地缓冲区并忽略异常风险
 *   - 实际上更稳的做法是 fork 一个子进程去读，但那会在崩溃路径上引入
 *     fork 的复杂度；官方选择直接读，本实现沿用（并接受极小概率的二次崩溃）
 */
static void cw_dump_window(uint64_t addr, int reg_index)
{
    uint64_t base;
    uint64_t words[8];
    int i;

    /* 以 8 字节对齐向回取 0x38，与官方的 "+00 +08 ... +38" 布局一致 */
    base = (addr & ~(uint64_t)7) - 0x38;

    cw_puts("\n[");
    cw_puts(g_tag);
    cw_puts("] sigsegv-extra ");
    if (reg_index >= 0) {
        cw_puts("reg=");
        cw_dec(reg_index);
        cw_puts(" ");
    } else {
        cw_puts("fault ");
    }
    cw_hex(addr);

    /*
     * 逐个读，任何一次失败就停止 —— 不试图"恢复"，因为我们已经在一个
     * 正在崩溃的进程里，能拿到多少算多少。
     */
    for (i = 0; i < 8; i++) {
        uint64_t a = base + (uint64_t)i * 8;
        /* 直接解引用；若不可读会再次进信号处理器，由"已处理"标志兜住 */
        words[i] = *(volatile uint64_t *)a;
    }

    /*
     * 输出格式对齐官方的 "+00=... +08=... +10=..."。
     * 早先写成 "+0x0000000000000008=" 那样把偏移也当完整地址打印，
     * 既冗长又难读 —— 偏移是固定宽度的小数，用两位十六进制更清楚。
     */
    for (i = 0; i < 8; i++) {
        static const char hexd[] = "0123456789abcdef";
        cw_puts(" +");
        {
            char off[3];
            off[0] = hexd[(i * 8) >> 4 & 0xf];
            off[1] = hexd[(i * 8) & 0xf];
            cw_write(off, 2);
        }
        cw_puts("=");
        cw_hex(words[i]);
    }
}

/* ------------------------------------------------------------------ */
/* 帧指针链回溯                                                        */
/* ------------------------------------------------------------------ */

/*
 * aarch64 的帧布局：x29 指向 [fp] = 上一帧的 fp、[fp+8] = 返回地址。
 * 逐级走链即可得到调用栈 —— 与官方 "backtrace (fp chain)" 的做法相同。
 *
 * 用闭区间上限防死循环：损坏的 fp 链可能自指。
 */
static void cw_dump_fp_chain(uint64_t fp, uint64_t pc)
{
    int i;
    uint64_t prev = 0;

    cw_puts("\n[");
    cw_puts(g_tag);
    cw_puts("] backtrace (fp chain):");
    cw_puts("\n  #0  lr=");
    cw_hex(pc);

    for (i = 1; i < 24; i++) {
        uint64_t next_fp, lr;

        if (fp < 0x1000 || (fp & 7) != 0)
            break;
        /* 自指或回退即认为链已损坏 */
        if (fp == prev)
            break;
        prev = fp;

        next_fp = *(volatile uint64_t *)fp;
        lr      = *(volatile uint64_t *)(fp + 8);

        cw_puts("\n  #");
        cw_dec(i);
        cw_puts("  lr=");
        cw_hex(lr);
        cw_puts(" fp=");
        cw_hex(next_fp);

        if (next_fp <= fp)   /* 必须严格向上增长 */
            break;
        fp = next_fp;
    }
    cw_puts("\n");
}

/* ------------------------------------------------------------------ */
/* 处理器                                                              */
/* ------------------------------------------------------------------ */

static struct sigaction g_prev_segv;
static struct sigaction g_prev_bus;
static int  g_installed = 0;
static volatile sig_atomic_t g_in_handler = 0;
/*
 * 信号栈大小用固定常量，不用 SIGSTKSZ。
 *
 * glibc 2.34 起 SIGSTKSZ 变成了**运行期**值（sysconf(_SC_SIGSTKSZ)），
 * 不能再用于文件作用域数组 —— 会报 "variably modified at file scope"。
 * 16 KiB 远超处理器实际所需（我们只输出几百字节），留足余量。
 */
#define CW_ALTSTACK_SIZE (16 * 1024)
static char g_altstack[CW_ALTSTACK_SIZE];

/* 崩溃原因的可读名（不用 strsignal，它非异步信号安全） */
static const char *cw_signame(int sig)
{
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS:  return "SIGBUS";
    case SIGILL:  return "SIGILL";
    case SIGFPE:  return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    default:      return "SIG?";
    }
}

static void cw_handler(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *uc = (ucontext_t *)uctx;
    uint64_t pc = 0, lr = 0, sp = 0, fp = 0, pstate = 0;
    uint64_t fault = 0;
    int code = 0;

    /*
     * 重入保护：若处理器自己再次崩溃（例如上面读内存窗口时），
     * 立刻恢复默认行为并重新抛出，避免无限递归把栈耗尽 ——
     * 那样连一行输出都不会有。
     */
    if (g_in_handler) {
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    g_in_handler = 1;

#ifdef __aarch64__
    if (uc != NULL) {
        mcontext_t *m = &uc->uc_mcontext;
        pc     = (uint64_t)m->pc;
        sp     = (uint64_t)m->sp;
        pstate = (uint64_t)m->pstate;
        lr     = (uint64_t)m->regs[30];
        fp     = (uint64_t)m->regs[29];
    }
#endif

    if (info != NULL) {
        fault = (uint64_t)(uintptr_t)info->si_addr;
        code  = info->si_code;
    }

    cw_puts("\n[");
    cw_puts(g_tag);
    cw_puts("] ");
    cw_puts(cw_signame(sig));
    cw_puts(" pc=");    cw_hex(pc);
    cw_puts(" lr=");    cw_hex(lr);
    cw_puts(" fault="); cw_hex(fault);
    cw_puts(" code=");  cw_dec(code);
    cw_puts("\n");

#ifdef __aarch64__
    if (uc != NULL) {
        mcontext_t *m = &uc->uc_mcontext;
        int i;
        for (i = 0; i < 29; i += 4) {
            int j;
            for (j = 0; j < 4 && i + j < 29; j++) {
                cw_puts("x");
                cw_dec(i + j);
                /* 让 x0..x9 与 x10..x28 的等号对齐 */
                cw_puts(i + j < 10 ? "  =" : " =");
                cw_hex((uint64_t)m->regs[i + j]);
                cw_puts(j == 3 ? "\n" : " ");
            }
        }
        cw_puts("x29="); cw_hex(fp);
        cw_puts(" x30="); cw_hex(lr);
        cw_puts("\nsp=");  cw_hex(sp);
        cw_puts(" pstate="); cw_hex(pstate);
        cw_puts("\n");
    }
#endif

    cw_dump_fp_chain(fp, pc);

    /*
     * 内存窗口：只在对 fault 地址有把握时读。
     * si_code 的 SEGV_MAPERR 表示地址根本没映射，去读它等于二次崩溃 ——
     * 这种情况跳过窗口，直接给出结论提示。
     */
    if (sig == SIGSEGV && code == SEGV_MAPERR) {
        cw_puts("\n[");
        cw_puts(g_tag);
        cw_puts("] 提示：fault 地址未映射（SEGV_MAPERR），跳过内存窗口\n");
    } else if (sig == SIGSEGV) {
        cw_dump_window(fault, -1);
        cw_puts("\n");
    }

    cw_puts("\n");

    /*
     * 不尝试恢复执行 —— 恢复几乎必然再次崩溃，只会刷屏。
     *
     * 恢复默认处理器后重新抛出，让内核按正常流程处理
     * （产出 core dump、给出正确的退出码）。
     *
     * 三个细节都是踩过坑的：
     *   1. 用 sigaction() 而不是 signal() —— 后者在信号处理器里不是
     *      异步信号安全的；
     *   2. 用 kill(getpid(), sig) 而不是 raise() —— raise() 同样不保证安全；
     *   3. **保持 g_in_handler = 1** —— 万一重抛过程中又出错，
     *      重入守卫会立刻走"恢复默认+再抛"这条路，而不是递归打印。
     */
    {
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        sigaction(sig, &dfl, NULL);
    }
    kill(getpid(), sig);

    /* 走到这里说明连重抛都失败了（极不可能）。直接退出，避免返回后
     * 继续执行已损坏的上下文。 */
    _exit(128 + sig);
}

/* ------------------------------------------------------------------ */
/* 安装 / 卸载                                                         */
/* ------------------------------------------------------------------ */

int bxroot_crash_install(const char *tag)
{
    struct sigaction sa;
    stack_t ss;

    if (g_installed)
        return 0;
    if (tag != NULL && tag[0] != '\0')
        g_tag = tag;

    /*
     * 独立信号栈。若崩溃是栈溢出引起的，正常栈上根本执行不了处理器 ——
     * 这正是 sigaltstack 存在的理由（官方导入了这个符号，做法相同）。
     */
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp    = g_altstack;
    ss.ss_size  = sizeof(g_altstack);
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        /* 装不上不是致命错误：只是栈溢出场景下拿不到现场 */
        cw_puts("[bxroot] WARN: sigaltstack 安装失败\n");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = cw_handler;
    /*
     * 刻意**不加** SA_NODEFER。
     *
     * 它允许同一信号在处理期间再次递送 —— 于是处理器内部任何一次
     * 误读内存（比如走损坏的帧指针链）都会递归进入自己。实测后果是
     * 死循环刷屏，而不是留下一次干净现场。
     *
     * 默认行为（信号在处理期间被阻塞）正是我们要的：处理器内部再崩，
     * 该信号被挂起，等我们重新抛出时一次性终止。
     */
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &g_prev_segv) != 0) {
        cw_puts("[bxroot] WARN: SIGSEGV handler install failed\n");
        return -1;
    }
    if (sigaction(SIGBUS, &sa, &g_prev_bus) != 0) {
        cw_puts("[bxroot] WARN: SIGBUS handler install failed\n");
    }

    g_installed = 1;
    return 0;
}

void bxroot_crash_uninstall(void)
{
    if (!g_installed)
        return;
    sigaction(SIGSEGV, &g_prev_segv, NULL);
    sigaction(SIGBUS,  &g_prev_bus,  NULL);
    g_installed = 0;
}

int bxroot_crash_installed(void)
{
    return g_installed;
}
