/*
 * clone3 回退链验证（行动清单 #9 的可做部分）。
 *
 * 【为什么需要人为拦截】本环境 seccomp 并不拦 clone3（实测裸调用返回
 * 真实 fd），所以"能跑通"不能证明回退链。真正的判据是：**把 clone3 拦掉
 * 之后**，glibc 的 pthread_create / fork 是否仍然成功（回退到 clone(2)）。
 * 官方 runtime 导出 __clone3 恒返回 ENOSYS 就是这个策略（clone3_guard.c
 * 文件头记录）。
 *
 * 做法：先装一个只对 clone3(435) 返回 ENOSYS 的 seccomp 过滤器，再执行
 * 目标程序（用 execv 保留过滤器）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

int main(int argc, char **argv)
{
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 435 /* clone3 */, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (38 & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 4, .filter = filt };

    if (argc < 2) { fprintf(stderr, "用法: %s <prog> [args...]\n", argv[0]); return 2; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("NO_NEW_PRIVS"); return 125; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) { perror("SECCOMP"); return 125; }
    execv(argv[1], &argv[1]);
    perror("execv");
    return 126;
}
