/*
 * waitstub.c -- 供 test_wait_hooks 使用的「真实实现」替身
 *
 * ★ 它存在的唯一理由 ★
 *
 * 被测的生产 .so（libbxroot-runtime.so）里的钩子是用
 * `dlsym(RTLD_NEXT, "waitpid")` 之类的形式去取「真实实现」的。
 * 本容器的外层 proot 运行时**破坏了 RTLD_NEXT**（实测：dlopen + dlsym
 * 之后 RTLD_NEXT 解析 libc 导出符号返回 NULL，报
 * "undefined symbol: getpid"），而真实 LD_PRELOAD 注入在本容器里
 * 完全不被采纳（实测连一个玩具 preload 都不生效）。
 *
 * 但 RTLD_NEXT 的语义是「按加载顺序在本库**之后**找同名符号」。于是可以
 * 构造一个等价于真实插入的场景：
 *
 *   1. dlopen(被测产物, RTLD_GLOBAL)
 *   2. dlopen(本文件编出的 libwaitstub.so, RTLD_GLOBAL)   ← 排在产物之后
 *   3. 通过 dlsym(产物句柄, "waitpid") 拿到**钩子本体**并直接调用
 *
 * 此时钩子内部的 RTLD_NEXT 查找会先命中本文件的同名符号 ——
 * 与真实 preload 下「找到 libc 的 waitpid」是同一个代码路径、
 * 同一套分支。区别只在于底下那层是 syscall() 直调而不是 glibc 包装。
 *
 * 每个替换实现都记一次调用数（waitstub_calls），测试据此断言
 * 「钩子确实把调用转发下去了」而不是自己吞了。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int g_calls;

__attribute__((constructor))
static void waitstub_ctor(void)
{
    fprintf(stderr, "[waitstub] 已加载（作为「真实实现」排在产物之后）\n");
}

/*
 * 与内核的 WNOWAIT 语义保持一致：本容器内核实测
 *   wait4(…, WNOHANG|WNOWAIT, …) → EINVAL(22)
 * 所以这里也把该位剥掉 —— 与生产钩子的 PX_WAIT4_OPTIONS 一致，
 * 否则测试会在一个真实 libc 不会出现的 EINVAL 上做判断。
 */
pid_t waitpid(pid_t pid, int *status, int options)
{
    g_calls++;
    errno = 0;
    return (pid_t)syscall(SYS_wait4, (int)pid, status,
                          options & ~WNOWAIT, (void *)0);
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
    g_calls++;
    errno = 0;
    return (pid_t)syscall(SYS_wait4, (int)pid, status,
                          options & ~WNOWAIT, (void *)rusage);
}

pid_t wait3(int *status, int options, struct rusage *rusage)
{
    g_calls++;
    errno = 0;
    return (pid_t)syscall(SYS_wait4, -1, status,
                          options & ~WNOWAIT, (void *)rusage);
}

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
    g_calls++;
    errno = 0;
    return (int)syscall(SYS_waitid, (int)idtype, (int)id, infop, options,
                        (void *)0);
}

int waitstub_calls(void)
{
    return g_calls;
}

void waitstub_reset(void)
{
    g_calls = 0;
}
