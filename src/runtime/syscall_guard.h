/*
 * syscall_guard.h —— syscall() 符号接管层
 *
 * 完整设计说明见 syscall_guard.c。要点：
 *
 * Android 沙箱的 seccomp 过滤器会 TRAP 掉 io_uring_setup(425)，
 * 而**用户态 SIGSYS 处理器救不了**（实测处理器被调用且返回 ENOSYS，
 * 进程仍死于 159）。官方 proroot 的解法是导出一个自己的 syscall()
 * 覆盖 libc 的，从源头不让该系统调用发出。
 *
 * 本层做同样的事：拦截 io_uring 家族，返回 ENOSYS，让 libuv 回退 epoll。
 */

#ifndef BXROOT_SYSCALL_GUARD_H
#define BXROOT_SYSCALL_GUARD_H

/* 被本层拦截（未发出 svc）的调用次数，诊断用。 */
unsigned long bxroot_syscall_guard_blocked(void);

#endif /* BXROOT_SYSCALL_GUARD_H */
