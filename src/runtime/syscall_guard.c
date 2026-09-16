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

        if (looks_like_guest_abs_path(pth)) {
            /*
             * 静态缓冲是刻意的：syscall 可能在任何线程被调用，不能 malloc。
             * 代价是非线程安全 —— 但 bxroot_translate_path 内部本来也有
             * 静态状态，所以这里不引入新的限制。
             */
            static _Thread_local char tbuf[4096];
            int tr = bxroot_translate_path(pth, tbuf, sizeof(tbuf));
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
