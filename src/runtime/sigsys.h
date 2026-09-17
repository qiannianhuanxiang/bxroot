/*
 * sigsys.h —— seccomp/SIGSYS 兼容层
 *
 * 设计背景与实测依据见 sigsys.c 顶部的长注释。要点：
 *   Android app 沙箱的 seccomp 过滤器会 TRAP 掉 io_uring_setup(425)；
 *   若 SIGSYS 被屏蔽（libuv 工作线程确实会屏蔽），内核直接杀进程，
 *   表现为退出码 159。参考实现 用 2624 字节的 SIGSYS 模拟层解决，
 *   bxroot 此前没有这一层，所以只能跑 node --version 这类不触发事件
 *   循环的命令。
 */

#ifndef BXROOT_SIGSYS_H
#define BXROOT_SIGSYS_H

/*
 * 安装 SIGSYS 处理器与屏蔽防护。
 * 返回 0 成功，-1 失败（安装处理器失败；此时仍会保留屏蔽防护）。
 * 可重复调用，只有首次生效。
 */
int bxroot_sigsys_install(void);

/* 是否已安装。 */
int bxroot_sigsys_installed(void);

/* 累计模拟次数（诊断用）。 */
unsigned long bxroot_sigsys_total(void);

#endif /* BXROOT_SIGSYS_H */
