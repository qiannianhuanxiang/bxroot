/*
 * syscall_guard.h —— syscall() 符号接管层
 *
 * 完整设计说明见 syscall_guard.c。要点：
 *
 * Android 沙箱的 seccomp 过滤器会 TRAP 掉 io_uring_setup(425)，
 * 而**用户态 SIGSYS 处理器救不了**（实测处理器被调用且返回 ENOSYS，
 * 进程仍死于 159）。参考实现的解法是导出一个自己的 syscall()
 * 覆盖 libc 的，从源头不让该系统调用发出。
 *
 * 本层做同样的事：拦截 io_uring 家族，返回 ENOSYS，让 libuv 回退 epoll。
 *
 * 平台差异（评估报告 3.6/8.3）：这份"恒定 ENOSYS"名单针对 Android 宿主
 * loader 的 seccomp 策略；非 Android 平台可用 BXROOT_RAW_SYSCALL=1 让
 * 这一类调用真透传（由真实内核回答）。身份/降权伪装与路径翻译不受该
 * 开关影响（判据见 syscall_guard.c 的 should_block 注释）。
 */

#ifndef BXROOT_SYSCALL_GUARD_H
#define BXROOT_SYSCALL_GUARD_H

/* 被本层拦截（未发出 svc）的调用次数，诊断用。 */
unsigned long bxroot_syscall_guard_blocked(void);

#endif /* BXROOT_SYSCALL_GUARD_H */

/*
 * 测试钩子：返回该 syscall 号上"第几个参数是路径"的位掩码
 * （bit N 表示 aN 是路径；0 表示不在表内）。
 *
 * 仅供测试使用，生产代码不调用。详见 syscall_guard.c 里的说明 ——
 * 这张表出过两次致命缺陷，而当时的回归测不到它。
 */
unsigned bxroot_test_path_arg_mask(long nr);

