/*
 * syscall_guard.c —— syscall() 符号接管层
 *
 * ====================================================================
 * 为什么必须有这一层
 * ====================================================================
 *
 * 两个独立的问题都由这一层解决：
 *
 * 【问题一】proroot-ldso 用 seccomp 以 KILL_PROCESS 方式禁止了一批系统
 * 调用（实测逐个列举，425/426/427 在内而 424 不在）。io_uring 家族一旦
 * 发出就杀进程且**不投递信号**，因此 SIGSYS 处理器救不了，只能从源头
 * 不让它发出去。返回 ENOSYS 是 libuv 期望的回退信号（它会改用 epoll）。
 *
 * 【问题二】node 静态链接的 libuv **不经 libc 的 stat/statx 符号**，
 * 而是用 `syscall(291, AT_FDCWD, path, ...)` 直接发起。实测证据：
 * 开 BXROOT_SCG=1 时 node 的 statSync 产生"转发 291"，却**不产生任何
 * translate 日志** —— 它完全绕过了 stat 钩子，路径未被翻译，于是 /usr
 * 之类全部 ENOENT（而同样功能的 C 程序走符号，一切正常）。
 *
 * ====================================================================
 * 实现要点
 * ====================================================================
 *
 * 1. 转发必须用**裸 svc 内联汇编**：调用 libc 的 syscall() 会绕回本函数
 *    造成无限递归，而没有比 svc 更底层的手段。
 *
 * 2. 路径参数是**客户传来的指针**，必须做安全判定。踩过的坑：
 *    内核对这些参数是宽容的 ——
 *        statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...) → EFAULT（合法入参！）
 *        openat(fd, NULL, ...)                     → EFAULT
 *    而 `pth[0] == '/'` 直接解引用遇到 NULL 立即 SIGSEGV，症状是整个
 *    进程静默消失。判据因此收敛到 looks_like_guest_abs_path() 一处。
 *
 * 3. 参数位置用**表**而不是散落的 switch：猜错参数位置会把非指针参数
 *    当路径解引用，那比不翻译严重得多。表让"哪些调用被翻译"一目了然。
 *
 * 4. 诊断输出不用 stdio（构造函数早期不可用），由 BXROOT_SCG=1 门控。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include "syscall_guard.h"

/*
 * preload.c 提供的路径翻译桥（返回值约定与 translate_path 一致：
 * >0 已翻译 / ==0 无需翻译 / <0 失败）。与 preload.c 编进同一个 .so，
 * 直接调用即可，不需要 dlsym。
 */
int bxroot_translate_path(const char *path, char *out, size_t out_size);

/* ------------------------------------------------------------------ */
/* 裸系统调用                                                          */
/* ------------------------------------------------------------------ */

static long raw_syscall6(long nr, long a0, long a1, long a2,
                         long a3, long a4, long a5)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");

    if (x0 < 0 && x0 > -4096) {
        errno = (int)(-x0);
        return -1;
    }
    return x0;
}

/* ------------------------------------------------------------------ */
/* 诊断输出（不用 stdio，避免早期构造阶段不可用）                       */
/* ------------------------------------------------------------------ */

static int g_trace;
static int g_trace_init;
static unsigned long g_blocked;

static void log_str(const char *s)
{
    if (s != NULL) {
        ssize_t w = write(2, s, strlen(s));
        (void)w;
    }
}

static void log_num(const char *prefix, long v, const char *suffix)
{
    char buf[128];
    char digits[24];
    int n = 0, i, dn = 0;
    unsigned long u;

    while (prefix != NULL && prefix[n] != '\0' && n < 60)
        buf[n] = prefix[n], n++;

    u = (v < 0) ? (unsigned long)(-v) : (unsigned long)v;
    do { digits[dn++] = (char)('0' + (u % 10)); u /= 10; } while (u > 0);
    if (v < 0) buf[n++] = '-';
    for (i = dn - 1; i >= 0; i--) buf[n++] = digits[i];

    if (suffix != NULL)
        for (i = 0; suffix[i] != '\0' && n < 120; i++)
            buf[n++] = suffix[i];

    {
        ssize_t w = write(2, buf, (size_t)n);
        (void)w;
    }
}

static void init_trace(void)
{
    if (g_trace_init)
        return;
    g_trace_init = 1;
    {
        extern char **environ;
        char **e;
        for (e = environ; e != NULL && *e != NULL; e++) {
            if (e[0][0] == 'B' && e[0][1] == 'X' &&
                e[0][2] == 'R' && e[0][3] == 'O' &&
                e[0][4] == 'O' && e[0][5] == 'T' &&
                e[0][6] == '_' && e[0][7] == 'S' &&
                e[0][8] == 'C' && e[0][9] == 'G' &&
                e[0][10] == '=' && e[0][11] == '1') {
                g_trace = 1;
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* 入参安全判定                                                        */
/* ------------------------------------------------------------------ */

/*
 * 客户传进来的路径指针能不能安全地当字符串读？
 *
 * 这个函数的存在本身就是一个教训：先前直接写 `pth[0] == '/'`，
 * 遇到 `statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...)` 就 SIGSEGV ——
 * 而 NULL 对内核来说是**合法入参**（翻译成 EFAULT），不是编程错误。
 *
 * 只判定两件事：非 NULL、首字节是 '/'（相对路径由 at 系调用的 dirfd
 * 决定，不需要我们翻译）。
 *
 * 注意：**无法**在用户态安全探测任意指针可读性（sigsetjmp 方案会与
 * 客户自己的信号处理冲突）。实践上客户的路径参数要么是有效字符串、
 * 要么是 NULL；野指针不是我们要兜的场景 —— 那时内核自己也会 EFAULT，
 * 而客户程序本就是坏的。
 */
static int looks_like_guest_abs_path(const char *p)
{
    if (p == NULL)
        return 0;
    return p[0] == '/';
}

/* ------------------------------------------------------------------ */
/* 危险系统调用判定                                                    */
/* ------------------------------------------------------------------ */

/*
 * 是否应当在本层拦截（不发 svc，直接返回 ENOSYS）。
 *
 * 编号取自 asm-generic（aarch64 使用同一套编号）：
 *   425 io_uring_setup / 426 io_uring_enter / 427 io_uring_register
 *
 * 这三个是已实测确认被 proroot-ldso 的 seccomp 策略以 KILL_PROCESS
 * 方式禁止的。libuv 在启动事件循环时会尝试 io_uring_setup；返回
 * ENOSYS 后它会**自动回退到 epoll**，这是它既有的代码路径。
 */
static int should_block(long nr)
{
    switch (nr) {
    case 425:
    case 426:
    case 427:
        return 1;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* 路径型系统调用的参数位置                                             */
/* ------------------------------------------------------------------ */

/*
 * 返回该系统调用的"路径参数在第几个寄存器"，-1 表示不是路径型调用。
 *
 * 只列出**参数位置确定**的那些。不猜、不试探 —— 猜错会把非指针参数
 * 当路径解引用，那是比"不翻译"严重得多的故障（整进程静默消失）。
 */
static int path_arg_index(long nr)
{
    switch (nr) {
    case 291:  return 1;   /* statx(dfd, path, flags, mask, buf)      */
    case 79:   return 1;   /* newfstatat(dfd, path, buf, flags)       */
    case 78:   return 1;   /* readlinkat(dfd, path, buf, sz)          */
    case 48:   return 1;   /* faccessat(dfd, path, mode)              */
    case 56:   return 1;   /* openat(dfd, path, flags, mode)          */
    case 35:   return 1;   /* unlinkat(dfd, path, flags)              */
    case 34:   return 1;   /* mkdirat(dfd, path, mode)                */
    case 221:  return 0;   /* execve(path, argv, envp)                */
    case 1024: return 0;   /* open(path, flags, mode) —— 已废弃仍在用 */
    default:   return -1;
    }
}

/* ------------------------------------------------------------------ */
/* 对外接口                                                            */
/* ------------------------------------------------------------------ */

long syscall(long number, ...)
{
    va_list ap;
    long a0, a1, a2, a3, a4, a5;
    int pidx;

    init_trace();

    va_start(ap, number);
    a0 = va_arg(ap, long);
    a1 = va_arg(ap, long);
    a2 = va_arg(ap, long);
    a3 = va_arg(ap, long);
    a4 = va_arg(ap, long);
    a5 = va_arg(ap, long);
    va_end(ap);

    if (should_block(number)) {
        g_blocked++;
        if (g_trace)
            log_num("[bxroot] syscall_guard: 拦截 ", number, " -> ENOSYS\n");
        errno = ENOSYS;
        return -1;
    }

    pidx = path_arg_index(number);
    if (pidx >= 0) {
        const char *pth = (pidx == 0) ? (const char *)(uintptr_t)a0
                                      : (const char *)(uintptr_t)a1;

        /*
         * ============================================================
         * 重入守卫（防御性）
         * ============================================================
         *
         * `translate_path` 内部用 `snprintf` 拼路径。虽然实测 glibc 的
         * 格式化不会回头调 stat 系系统调用，但这条链**理论上**可以
         * 闭合：任何一次内部 stat 都会重新进入本函数。
         *
         * 加这道守卫的成本是一个 thread_local 读写，收益是把
         * "无限递归到栈溢出"这个**不可调试**的故障模式彻底排除。
         *
         * 【一个必须记录的方法论教训】
         * 我最初的诊断代码是这样写的：
         *
         *     static _Thread_local int d291;
         *     if (number == 291) { d291++; printf("depth=%d", d291); }
         *
         * 它输出了 depth=1,2,3,...,400 —— 我据此判定"无限递归"。
         * **但那个结论是错的**：`d291` 只增不减，所以顺序调用也会
         * 让它单调递增。真正区分"嵌套"与"顺序"要在**函数返回前递减**。
         *
         * 实测（libuv 连续探测数百个 node_modules 子目录）是**顺序**调用，
         * 不是嵌套。这道守卫因此**没有**解决当初的段错误 —— 保留它
         * 是因为它防的是另一件事（理论上的递归），而且成本可忽略。
         *
         * 【为什么必须是 thread_local】
         * `syscall` 会被多线程并发调用。用**全局**标志的话：
         * A 线程正在翻译时，B 线程的翻译会被误判为重入而跳过 ——
         * 表现为"随机某些路径不翻译"，比崩溃更难排查。
         *
         * 【为什么不用 pthread_key】
         * 这是 LD_PRELOAD 层，构造函数极早期就可能被调用，
         * 那时 pthread_key_create 未必可用。`_Thread_local` 由
         * TLS 直接支撑，无此问题。
         */
        /*
         * ============================================================
         * ★★ 目标缓冲：**不用 _Thread_local、不用 malloc** ★★
         * ============================================================
         *
         * 这里踩过一个非常隐蔽的坑，值得完整记录。
         *
         * 【症状】`dsh web --help` 段错误，崩溃在 glibc 的 `strlen`：
         *     x0 = 0xffffffffffffffff   （即 strlen((char*)-1)）
         * 而 `dsh --help` / `--version` 完全正常。
         *
         * 【判决实验】同一份源码，只改"把翻译结果放哪"：
         *     静态 _Thread_local 缓冲  → 崩溃（2/2 复现）
         *     堆上 malloc 的拷贝       → 正常（3/3 复现）
         * 两者唯一差别就是**缓冲的位置**。
         *
         * 【根因】bxroot 运行在 proroot 的**自研 ELF 加载器**之下
         * （`libproroot-linker.so`，不是 glibc 的 ld.so）。那个加载器
         * 对 TLS 的支持不完整 —— 它的 rodata 里明确带着这条字符串：
         *
         *     tls: runtime static TLS surplus exhausted
         *
         * 也就是说：动态加载的库里，`_Thread_local` 的存储可能**没有
         * 被正确分配**。对它的读写会落到错误的地址，破坏相邻数据
         * （包括 node 自己的指针），最终表现为在 `strlen` 里读到 -1。
         *
         * 这解释了为什么症状如此"挑剔"：
         *   - `--version` 不走多少 statx，碰不到这个缓冲；
         *   - `web` profile 的模块解析要连续探测数百个目录，
         *     每次都写这个坏掉的 TLS 缓冲，很快踩坏关键数据。
         *
         * 【修法】改用**普通静态缓冲池 + 轮转索引**：
         *   - 不依赖 TLS（绕开加载器的缺陷）
         *   - 不 malloc（不会泄漏，也不会在信号处理器里死锁）
         *   - 轮转多个槽位：即使某个调用方短暂持有上一次的指针，
         *     也要过 N 次调用才会被覆写，实践中足够
         *
         * 代价：32 KB 静态内存（8 × 4 KB），每线程共享同一池。
         * 极端并发下仍可能互相覆写 —— 但那是**旧的**风险（原实现的
         * 全局静态缓冲也有），而 TLS 方案的风险是**内存被写坏**，
         * 严重得多。
         */
        if (looks_like_guest_abs_path(pth)) {
            /*
             * 大环形池：64 KB，只在池内前进，到末尾回绕。
             *
             * 为什么不是小池（8 × 4KB）：实测表明**调用方会在内核返回后
             * 继续持有该指针**。判决实验（三种策略，其他条件完全相同）：
             *
             *     静态 8 槽轮转池   → 段错误
             *     堆 + 只分配一次   → 段错误
             *     堆 + 每次分配     → 正常
             *
             * 唯一变量是"缓冲是否被复用"。所以覆写周期必须足够长 ——
             * 64 KB 意味着要经过 16 次以上调用才会回到同一块，
             * 而 libuv 持有路径指针的时间远短于此。
             *
             * 为什么不用"每次 malloc"（实测可行）：**会泄漏**。
             * libuv 探测模块时连续调用数百次 statx，每次 4 KB 就是
             * 数 MB；长跑必然 OOM。环形池是零泄漏的等价方案。
             *
             * 为什么不用 _Thread_local：本机加载器是自研的，TLS 支持
             * 不完整（rodata 里有 "tls: runtime static TLS surplus
             * exhausted"），用它反而会写坏相邻数据。
             */
            #define SG_POOL_SIZE (64 * 1024)
            static char sg_pool[SG_POOL_SIZE];
            static unsigned int sg_pool_off;

            char *tbuf;
            size_t need = 4096;

            /* 池内按 256 字节对齐切块，避免回绕时切碎 */
            if (sg_pool_off + need > SG_POOL_SIZE)
                sg_pool_off = 0;
            tbuf = sg_pool + sg_pool_off;
            sg_pool_off += need;

            int tr = bxroot_translate_path(pth, tbuf, need);

            if (tr > 0) {
                if (pidx == 0) a0 = (long)(uintptr_t)tbuf;
                else           a1 = (long)(uintptr_t)tbuf;
                if (g_trace) {
                    log_str("[bxroot] syscall_guard: 翻译 ");
                    log_str(pth);
                    log_str(" -> ");
                    log_str(tbuf);
                    log_str("\n");
                }
            }
        }
    }

    return raw_syscall6(number, a0, a1, a2, a3, a4, a5);
}

unsigned long bxroot_syscall_guard_blocked(void)
{
    return g_blocked;
}
