/*
 * crash.h -- bxroot 崩溃现场捕获
 *
 * 为什么需要：见 crash.c 顶部的长篇说明。一句话 —— 参考实现 有
 * 3116 字节的 SIGSEGV 处理器，bxroot 此前是零；在一个 LD_PRELOAD
 * 运行时里，一次空指针就会带走整个容器进程，没有现场信息只能靠猜。
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef BXROOT_CRASH_H
#define BXROOT_CRASH_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 安装 SIGSEGV / SIGBUS 处理器。
 *
 * tag 只用于输出前缀（如 "proroot" 或 "bxroot"），NULL 表示用默认值。
 * 幂等：重复调用只装一次。
 *
 * 返回 0 成功；-1 表示 SIGSEGV 处理器装不上（此时不启用，但不影响
 * 进程继续运行）。sigaltstack 失败只打警告不返回错误 —— 它只影响
 * 「栈溢出」这一种崩溃场景。
 */
int bxroot_crash_install(const char *tag);

/* 卸载，恢复原有处理器。 */
void bxroot_crash_uninstall(void);

/* 是否已安装。 */
int bxroot_crash_installed(void);

#ifdef __cplusplus
}
#endif

#endif /* BXROOT_CRASH_H */
