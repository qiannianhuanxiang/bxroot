/*
 * early_sigsys.h —— 在 glibc 启动代码之前装 SIGSYS→ENOSYS 处理器
 *
 * ★ 为什么需要（2026-09-27 Termux 真机实测）★
 *
 * Android app 沙箱（untrusted_app，Seccomp:2）的 seccomp 白名单对
 * set_robust_list(99)、rseq(293) 返回 SECCOMP_RET_TRAP。glibc 的启动
 * 代码（静态程序的 __libc_setup_tls 之后、动态程序 ld.so 的
 * __libc_early_init）**在 main / 任何构造函数之前**就发这两个调用：
 *
 *     $ strace ./bxroot -V                     # 静态 glibc launcher
 *     set_robust_list(...)  --- SIGSYS ---     +++ killed by SIGSYS +++
 *
 * 连一个纯静态 `puts("hello")` 也是同样下场 —— 不是 bxroot 的缺陷，
 * 是 glibc 程序在 app 沙箱里的通病。LD_PRELOAD 的构造函数、livepatch
 * 都晚于这两个调用，所以必须在**进程入口**处就装好处理器。
 *
 * 用法：链接时 `-Wl,-e,bx_early_start`（入口改到这里，装完后跳 _start）。
 * 处理器只做一件事：把被 TRAP 的调用的返回值（ucontext→regs[0]）改成
 * -ENOSYS。glibc 对两者都容忍 ENOSYS（robust list / rseq 不可用即降级）。
 *
 * 布局依据（aarch64 Linux）：ucontext = uc_flags(8) + uc_link(8) +
 * uc_stack(24) + uc_sigmask(128) = 168，mcontext 16 字节对齐 → 176，
 * mcontext.fault_address(8) 之后即 regs[0] → 偏移 184。
 * （strace 里看到 `rt_sigreturn(...) = -1 ENOSYS` 是**正常的**：
 *   rt_sigreturn 的"返回值"就是恢复出来的 x0，也就是我们写入的 -ENOSYS。）
 *
 * 不用 SA_RESTORER：aarch64 内核在未给 restorer 时使用 vDSO 的
 * __kernel_rt_sigreturn。
 *
 * 局限：处理器在**信号被屏蔽**时无法投递 —— glibc pthread_create 在
 * clone 前 SIG_BLOCK 全部信号，新线程里的 set_robust_list 若被 TRAP
 * 会被内核直接杀掉。动态程序由 runtime 的 livepatch 中和该站点；
 * 本头文件只保证"能活着走到 main / 走到 runtime 构造函数"。
 */
#ifndef BXROOT_EARLY_SIGSYS_H
#define BXROOT_EARLY_SIGSYS_H

#if defined(__aarch64__)
static void bx_early_sigsys(int s, void *si, void *uc) __attribute__((used));
static void bx_early_sigsys(int s, void *si, void *uc)
{
    (void)s; (void)si;
    ((unsigned long *)((char *)uc + 184))[0] = (unsigned long)-38; /* -ENOSYS */
}
__asm__(
    ".text\n"
    ".globl bx_early_start\n"
    ".type bx_early_start,%function\n"
    "bx_early_start:\n"
    "  mov x19, x0\n"               /* x0 = 内核/动态链接器传来的 rtld_fini */
    "  mov x20, sp\n"
    "  sub sp, sp, #32\n"           /* struct kernel_sigaction */
    "  adrp x9, bx_early_sigsys\n"
    "  add x9, x9, :lo12:bx_early_sigsys\n"
    "  str x9, [sp]\n"              /* sa_handler */
    "  mov x9, #4\n"                /* SA_SIGINFO */
    "  str x9, [sp, #8]\n"
    "  str xzr, [sp, #16]\n"        /* sa_restorer */
    "  str xzr, [sp, #24]\n"        /* sa_mask */
    "  mov x0, #31\n"               /* SIGSYS */
    "  mov x1, sp\n"
    "  mov x2, #0\n"
    "  mov x3, #8\n"
    "  mov x8, #134\n"              /* rt_sigaction */
    "  svc #0\n"
    "  mov sp, x20\n"
    "  mov x0, x19\n"
    "  b _start\n"
    ".size bx_early_start, .-bx_early_start\n");
#endif

#endif /* BXROOT_EARLY_SIGSYS_H */
