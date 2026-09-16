/*
 * livepatch.h —— 最小化运行时指令补丁（seccomp 中和）
 *
 * 完整设计说明与实测证据见 livepatch.c。要点：
 *
 * proroot-ldso 用 seccomp 以 KILL_PROCESS 方式禁止 80+ 个系统调用号。
 * glibc 内部有**内联 svc**（不经 PLT、不经导出符号），LD_PRELOAD 类手段
 * 在原理上拦不住，只能改写指令。
 *
 * 本模块把站点表里列出的 `svc #0` 改写成 `mov x0, #0`（立即成功返回），
 * 每点先校验字节，失败静默跳过。
 */

#ifndef BXROOT_LIVEPATCH_H
#define BXROOT_LIVEPATCH_H

#define _GNU_SOURCE
#include <stdint.h>

/*
 * 应用补丁。返回 0 表示至少有一个站点打上；
 * 负数表示未应用（原因不同），调用方**不应**视作致命错误。
 */
int bxroot_livepatch_apply(void);

/* 是否已尝试应用。 */
int bxroot_livepatch_applied(void);

/* 成功改写的站点数。 */
int bxroot_livepatch_hits(void);

/* 解析到的 libc 基址（诊断用）。 */
uintptr_t bxroot_livepatch_libc_base(void);

#endif /* BXROOT_LIVEPATCH_H */
