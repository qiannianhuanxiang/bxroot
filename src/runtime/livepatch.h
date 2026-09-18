/*
 * livepatch.h —— 最小化运行时指令补丁（seccomp 中和）
 *
 * 完整设计说明与实测证据见 livepatch.c。要点：
 *
 * 宿主 loader 用 seccomp 以 KILL_PROCESS 方式禁止 80+ 个系统调用号。
 * glibc 内部有**内联 svc**（不经 PLT、不经导出符号），LD_PRELOAD 类手段
 * 在原理上拦不住，只能改写指令。
 *
 * 本模块把站点表里列出的 `svc #0` 改写成 `mov x0, #0`（立即成功返回），
 * 每点先校验字节，失败静默跳过。
 *
 * ★ 门控（P1，2026-09-17 补）★
 * 补丁本身只在"存在 seccomp 过滤器"的环境里才有意义，而它要 mprotect
 * 整个 libc 代码页为 RWX —— 在没有过滤器的环境里（普通 Ubuntu、其它
 * 容器）收益为零、风险全担。因此本模块在动手之前先过三道门：
 *
 *    ① BXROOT_NO_LIVEPATCH=1  → 硬开关，无条件跳过
 *    ② prctl(PR_GET_SECCOMP) != 2 → 没有过滤器，跳过
 *    ③ glibc 版本与站点表声明不符 → 站点偏移不可信，跳过并告警
 *
 * 三道门都是"跳过"（返回 LP_SKIP_* 常量），**不是失败** —— 调用方
 * 本来就把本层当尽力而为的优化，跳过不该有任何副作用。
 */

#ifndef BXROOT_LIVEPATCH_H
#define BXROOT_LIVEPATCH_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>

/*
 * 跳过原因（bxroot_livepatch_skip_reason 的返回值）。
 *
 * ★ 为什么单独区分"没 seccomp"和"版本不符" ★
 * 前者是**预期行为**（在非 Android 环境就该这样），不该产生任何日志；
 * 后者是**告警**（站点表已过期，真机上也会静默失效），必须让用户看见。
 * 两者混成一个"跳过"会让 P2-4.1 那类缺陷重新变成静默失效。
 */
#define LP_SKIP_NONE          0  /* 没跳过（要么打上了，要么真失败了） */
#define LP_SKIP_ENV           1  /* BXROOT_NO_LIVEPATCH=1 硬开关 */
#define LP_SKIP_NO_SECCOMP    2  /* prctl(PR_GET_SECCOMP) != 2 */
#define LP_SKIP_LIBC_VERSION  3  /* glibc 版本与站点表不符 */
#define LP_SKIP_ARCH          4  /* 非 aarch64，站点指令编码无意义 */

/*
 * 应用补丁。返回 0 表示至少有一个站点打上；
 * 负数表示未应用（原因不同），调用方**不应**视作致命错误。
 *
 * ★ 注意：返回 0 有两种含义 ★
 * 早先的实现里 `g_hits == 0` 也返回 0（`-5` 那支已被下面的语义修正）。
 * 现在的约定是：
 *     0            至少改写了 1 个站点（真的干了活）
 *     LP_SKIP_*    >0，被门控跳过（预期行为，非错误）
 *     负数         真失败（找不到 libc 基址 / mprotect 失败等）
 * 调用方若要区分"打上了"与"跳过了"，用 bxroot_livepatch_applied()
 * （它只在实际改写成功时为 1）或 bxroot_livepatch_skip_reason()。
 */
int bxroot_livepatch_apply(void);

/* 是否已**实际改写**过站点（被门控跳过时为 0）。 */
int bxroot_livepatch_applied(void);

/* 成功改写的站点数。 */
int bxroot_livepatch_hits(void);

/* 被跳过时的原因（LP_SKIP_*）；未跳过为 LP_SKIP_NONE。 */
int bxroot_livepatch_skip_reason(void);

/* 站点表声明所针对的 glibc 版本（诊断/告警用，形如 "2.39"）。 */
const char *bxroot_livepatch_site_libc_version(void);

/* 解析到的 libc 基址（诊断用）。 */
uintptr_t bxroot_livepatch_libc_base(void);

/* 探针：当前环境是否装了 seccomp 过滤器（1=是）。非 aarch64 恒为 0。
 * 单独导出是为了让测试能在**不触发 mprotect** 的前提下断言门控判据。 */
int bxroot_livepatch_has_seccomp(void);

#endif /* BXROOT_LIVEPATCH_H */
