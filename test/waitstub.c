/*
 * Independent wait syscall adapter tested via dlsym(stub_handle, name).
 * Late RTLD_GLOBAL loading is not an RTLD_NEXT interposition guarantee.
 * The counter proves direct stub calls only; runtime is allowed to resolve libc
 * or a syscall backend without visiting this fixture.
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

static int g_calls;

static long stub_raw5(long nr, long a, long b, long c, long d, long e)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm__ __volatile__("svc #0" : "+r"(x0)
                         : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                         : "memory", "cc");
    if (x0 < 0 && x0 >= -4095) { errno = (int)-x0; return -1; }
    return x0;
#else
    return syscall(nr, a, b, c, d, e);
#endif
}

__attribute__((constructor))
static void waitstub_ctor(void)
{
    fprintf(stderr, "[waitstub] 已加载（独立 syscall fixture）\n");
}

/*
 * 与内核的 WNOWAIT 语义保持一致：本容器内核实测
 *   wait4(…, WNOHANG|WNOWAIT, …) → EINVAL(22)
 * 所以这里也把该位剥掉 —— 与生产钩子的 PX_WAIT4_OPTIONS 一致，
 * 否则测试会在一个真实 libc 不会出现的 EINVAL 上做判断。
 */
pid_t waitpid(pid_t pid, int *status, int options)
{
    __atomic_add_fetch(&g_calls, 1, __ATOMIC_RELAXED);
    errno = 0;
    return (pid_t)stub_raw5(SYS_wait4, pid, (long)status,
                          options & ~WNOWAIT, 0, 0);
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
    __atomic_add_fetch(&g_calls, 1, __ATOMIC_RELAXED);
    errno = 0;
    return (pid_t)stub_raw5(SYS_wait4, pid, (long)status,
                          options & ~WNOWAIT, (long)rusage, 0);
}

pid_t wait3(int *status, int options, struct rusage *rusage)
{
    __atomic_add_fetch(&g_calls, 1, __ATOMIC_RELAXED);
    errno = 0;
    return (pid_t)stub_raw5(SYS_wait4, -1, (long)status,
                          options & ~WNOWAIT, (long)rusage, 0);
}

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
    __atomic_add_fetch(&g_calls, 1, __ATOMIC_RELAXED);
    errno = 0;
    return (int)stub_raw5(SYS_waitid, idtype, id, (long)infop, options, 0);
}

int waitstub_calls(void)
{
    return __atomic_load_n(&g_calls, __ATOMIC_RELAXED);
}

void waitstub_reset(void)
{
    __atomic_store_n(&g_calls, 0, __ATOMIC_RELAXED);
}
