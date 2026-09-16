/*
 * ====================================================================
 * ⚠️ 本文件是【已被实验证伪】的方案，**未接线、不参与构建**。
 * ====================================================================
 *
 * 保留它的理由：记录一条走过并排除的路径，避免后人重复尝试。
 *
 * 【假设】glibc 的线程创建会先试 clone3(435)，被 proroot-ldso 的
 *         seccomp 以 KILL_PROCESS 禁止 → 只要导出 __clone3 让它返回
 *         ENOSYS，glibc 就会回退到老的 clone(2)。
 *
 * 【证伪实验】加了这个层之后，`pthread_create` 仍然导致进程死于 159。
 *   原因：glibc 的 clone3 内联 svc 是**内部静态函数**，调用不经 PLT、
 *   不经导出符号（libc+0xebb20 落在 __clone 导出范围 0xeb880+76 之外），
 *   所以覆盖符号根本拦不到它。详见 docs/E2E-试跑报告.md。
 *
 * 【真正可行的方案】见 livepatch.c —— 不是禁用 clone3，而是把
 *   set_robust_list(99) 与 rseq(293) 两处内联 svc 中和成
 *   `mov x0,#0`。实测只有这样 `pthread_create` 才能存活。
 *   （另外还试过连 clone3 一起中和，会触发 glibc 的
 *   allocatestack.c 断言 —— 那两点是**必需且充分**的组合。）
 * ====================================================================
 */
/*
 * clone3_guard.c —— __clone3 禁用层
 *
 * ====================================================================
 * 为什么需要（本轮最终定位的根因）
 * ====================================================================
 *
 * 最小复现：一个只做 pthread_create 的程序
 *     pthread_create() 返回 0（成功）
 *     但进程**立即死于 159 (SIGSYS / Bad system call)**
 *     且我们安装的 SIGSYS 处理器**一次都没被调用**
 *
 * 没有信号投递 ⇒ 不是 SECCOMP_RET_TRAP，而是
 * **SECCOMP_RET_KILL_PROCESS 直接杀**。这类拦截无法用信号处理器挽救。
 *
 * 定位方式：对照官方 runtime 的导出符号，发现它导出了
 *     __clone3        （36 字节）
 *     pthread_create  （856 字节）
 *
 * 反汇编官方 __clone3（0x10808，36 字节，仅 9 条指令）：
 *
 *     10808: stp  x29, x30, [sp, #-16]!
 *     1080c: mov  x29, sp
 *     10810: bl   __errno_location
 *     10814: mov  x1, x0
 *     10818: mov  w2, #0x26          ; 38 = ENOSYS
 *     1081c: ldp  x29, x30, [sp], #16
 *     10820: mov  w0, #0xffffffff    ; -1
 *     10824: str  w2, [x1]           ; *errno = ENOSYS
 *     10828: ret
 *
 * **它无条件返回 -1/ENOSYS，一条 svc 都不发。**
 *
 * 原理：glibc 的线程创建路径会**先尝试 clone3**，失败后再回退到老的
 * clone(2)。clone3 的系统调用号是 435，被 proroot-ldso 的过滤器禁止
 * 且以 KILL_PROCESS 处理 —— 所以只要让它"看起来不存在"，glibc 就会
 * 安静地走 clone 回退路径，新线程得以正常创建。
 *
 * ====================================================================
 * 注意
 * ====================================================================
 * - 本层**不是**在"假装成功"，而是如实报告内核不支持 clone3。
 *   这与老内核（< 5.3）的行为一致，glibc 对这种情况有成熟处理。
 * - 我们比官方多做了一件事：把 errno 设置为 ENOSYS 而非 EINVAL 之类，
 *   因为 ENOSYS 是 glibc 判定"该系统调用不存在，请回退"的明确信号。
 */

#define _GNU_SOURCE
#include <errno.h>

#include "clone3_guard.h"

/*
 * 覆盖 glibc 的 __clone3。
 *
 * glibc 2.34+ 在 aarch64 上通过 __clone3 发起 clone3 系统调用。
 * 我们直接返回失败并置 ENOSYS，让调用方回退到 clone(2)。
 *
 * 变参签名是为了与 glibc 的声明兼容 —— 我们不解析任何参数。
 */
int __clone3(void *args, ...)
{
    (void)args;
    errno = ENOSYS;
    return -1;
}

/* 计数：诊断用，可确认这层是否被调用到。 */
static int g_clone3_blocked;

int bxroot_clone3_guard_count(void)
{
    return g_clone3_blocked;
}
