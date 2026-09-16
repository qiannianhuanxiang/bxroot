/*
 * clone3_guard.h —— __clone3 禁用层
 *
 * 完整设计说明见 clone3_guard.c。要点：
 * proroot-ldso 的过滤器以 KILL_PROCESS 方式禁止 clone3(435)，
 * 无法用 SIGSYS 处理器挽救。官方 runtime 的做法是导出一个返回
 * -1/ENOSYS 的 __clone3，让 glibc 回退到 clone(2)。
 */

#ifndef BXROOT_CLONE3_GUARD_H
#define BXROOT_CLONE3_GUARD_H

/* 本层被调用的次数（诊断用）。 */
int bxroot_clone3_guard_count(void);

#endif /* BXROOT_CLONE3_GUARD_H */
