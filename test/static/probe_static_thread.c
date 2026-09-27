/*
 * probe_static_thread.c —— 静态链接 guest 多线程在 seccomp 下存活的判别性探针
 *
 * 【钉住的缺陷】静态链接（gcc -static）的 guest 里，glibc 的 set_robust_list
 * (99)/rseq(293) 内联 svc 在**主可执行映像自己的 .text**，不在独立的
 * libc.so.6 段。livepatch 早先只扫 libc.so.6 段（find_libc_exec_range），
 * 对静态 guest 一条都补不到；且 apply() 在 find_libc_base()==0 时直接早退。
 * 于是静态 guest 的 pthread_create 新线程在 clone 前屏蔽全信号、start_thread
 * 里内联发 set_robust_list → seccomp KILL_PROCESS → SIGSYS 投递不了 → 死 159。
 *
 * 【判别力设计】直接把 livepatch.c 以 -DLP_TEST_HOOK 静态编入本探针，让本
 * 探针自身就是"静态 guest"（无 libc.so.6 段，走新增的 find_main_exec_range
 * 主映像扫描分支）。探针内放一个"外层 proroot 会漏补"的 far 形态 99 站点
 * （mov x8,#99 与 svc 之间隔栈 spill，超出外层紧凑补丁窗口），从而在本容器
 * （嵌套外层 proroot）里也有判别力：外层漏补 → 修复前 masked 调用必被杀。
 *
 * 判据（都要成立才 PASS）：
 *   1. 修复前站点 UNPATCHED，且屏蔽全信号下调用它进程被杀（SIGSYS）——
 *      证明本探针在测真实缺陷，而不是站点已被别人补过的假绿；
 *   2. bxroot_livepatch_apply() 后站点变 PATCHED；
 *   3. 修复后同样的 masked 调用存活。
 *
 * 撤修复变红：把 livepatch.c 里 find_main_exec_range 分支去掉（或恢复
 * apply() 的 `if (g_base==0) return -1` 早退），apply 后站点仍 UNPATCHED，
 * masked 调用被杀 → 判据 2/3 失败。
 *
 * 退出：0 PASS / 1 FAIL / 2 环境不满足（无 seccomp 过滤器，无判别力）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "livepatch.h"

/*
 * 一个"外层 proroot 会漏补"的 set_robust_list(99) 站点：mov x8,#99 与 svc
 * 之间隔着栈 spill/reload，超出外层的紧凑补丁窗口（外层实测只补 gap≤2）。
 * 形态仍在 bxroot 扫描窗口（12 条）内且中途不写 x8/不分支，所以 bxroot
 * 的 lp_scan_and_patch 能补上。
 */
__attribute__((noinline, used)) static long far_robust(void)
{
    register long x0 __asm__("x0") = 0;
    __asm__ volatile(
        "mov x8, #99\n"
        "str x8, [sp, #-16]!\n"
        "ldr x8, [sp], #16\n"
        "mov x1, #24\n"
        "svc #0\n"
        : "+r"(x0) :: "x8", "x1", "memory");
    return x0;
}

static const char *site_state(void)
{
    uint32_t *p = (uint32_t *)(void *)far_robust;
    int i, s;
    for (i = 0; i < 24; i++) {
        uint32_t w = p[i];
        if ((w & 0xffe0001fu) == 0xd2800008u && ((w >> 5) & 0xffff) == 99) {
            for (s = 1; s <= 12; s++) {
                uint32_t v = p[i + s];
                if (v == 0xd4000001u) return "UNPATCHED";
                if (v == 0xd2800000u) return "PATCHED";
                if ((v & 0xffe0001fu) == 0xd2800008u ||
                    (v >> 26) == 0x05u || (v >> 26) == 0x25u) break;
            }
        }
    }
    return "NOTFOUND";
}

/*
 * 在子进程里屏蔽全部信号后调用该站点 —— 复刻 glibc pthread_create 新线程的
 * 处境。站点未中和：seccomp KILL_PROCESS 处理 99，SIGSYS 屏蔽投递不了 →
 * 进程被杀（返回 0）。站点已中和：svc→mov x0,#0，直接存活（返回 1）。
 */
static int masked_call_survives(void)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        sigset_t all;
        sigfillset(&all);
        sigprocmask(SIG_BLOCK, &all, NULL);
        (void)far_robust();
        _exit(0);
    }
    int st = 0;
    if (waitpid(p, &st, 0) < 0) return -1;
    if (WIFSIGNALED(st)) return 0;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 1 : -1;
}

int main(void)
{
    int sec = bxroot_livepatch_has_seccomp();
    if (sec != 1) {
        printf("SKIP: 无 seccomp 过滤器（PR_GET_SECCOMP=%d），本探针无判别力\n", sec);
        return 2;
    }

    const char *before_site = site_state();
    int before = masked_call_survives();
    fprintf(stderr, "before: site=%s masked_survives=%d\n", before_site, before);

    int rc = bxroot_livepatch_apply();
    fprintf(stderr, "apply rc=%d hits=%d scan_hits=%d skip=%d\n",
            rc, bxroot_livepatch_hits(), bxroot_livepatch_scan_hits(),
            bxroot_livepatch_skip_reason());

    const char *after_site = site_state();
    int survives = masked_call_survives();
    fprintf(stderr, "after: site=%s masked_survives=%d\n", after_site, survives);

    if (strcmp(before_site, "UNPATCHED") != 0 || before != 0) {
        printf("SKIP: 修复前站点=%s masked_survives=%d —— 外层已补齐该形态，"
               "本容器测不到真实缺陷（真机无外层，仍由本修复覆盖）\n",
               before_site, before);
        return 2;
    }
    int ok = (strcmp(after_site, "PATCHED") == 0) && (survives == 1);
    printf(ok ? "RESULT: PASS\n" : "RESULT: FAIL\n");
    return ok ? 0 : 1;
}
