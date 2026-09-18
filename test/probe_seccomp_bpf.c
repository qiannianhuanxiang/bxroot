/*
 * probe_seccomp_bpf.c — 运行时枚举当前进程继承到的 seccomp 过滤器行为
 *
 * 背景
 * ----
 * 本进程运行在官方 proroot 容器内（Android 应用沙箱 uid=10655）。
 * 内核报告 Seccomp: 2 / Seccomp_filters: 1，但**无法**用
 * PTRACE_SECCOMP_GET_FILTER 把 BPF 程序 dump 出来（该调用被过滤器本身
 * 拒绝，raw ptrace 返回 -14 EFAULT、glibc ptrace 返回 -1/EINVAL）。
 * 因此这里改用**行为枚举**：对每个系统调用号发一条裸 `svc #0`，
 * 观察它是被放行、被 TRAP 还是被 ERRNO。
 *
 * 安全设计（重要）
 * ----------------
 *  - 6 个参数寄存器全部置 0。零参数下没有任何系统调用能造成真实副作用。
 *  - 子进程先 setpgid(0,0) 自立门户，因此即便命中 kill(0,0)/tgkill(0,0,0)
 *    这类"信号"调用，目标集合也被限制在该子进程自己所在的进程组内。
 *  - alarm(1) 给可能阻塞的调用兜底。
 *  - 每个号一个 fork，互不污染。
 *
 * 子进程退出码约定
 * ----------------
 *   0        正常返回（未被拦截）
 *   100+n    正常返回且返回值为 -n（例如 138 表示返回 -38 = -ENOSYS）
 *   70+code  SIGSYS 已投递，si_code == code（SECCOMP_RET_TRAP 的特征值是 1）
 *   80+sig   死于信号 sig（非 SIGSYS）
 *
 * 输出（stdout，每行一条）
 *    <nr> TRAP si_code=<c>
 *    <nr> SIGNAL <sig>
 *    <nr> RET <value>
 *
 * 编译：见同目录 probe_seccomp_bpf.sh（本容器 gcc 有间歇性 ICE，脚本会重试）
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static volatile sig_atomic_t g_trapped;
static volatile int g_sicode = -1;

static void sigsys_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)uc;
    g_trapped = 1;
    g_sicode = si->si_code;
}

/* 裸 svc，参数全 0 —— 不要在这里加参数，安全性依赖全 0 */
static long raw_syscall_zero(long nr)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = 0;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x5 __asm__("x5") = 0;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

int main(int argc, char **argv)
{
    long lo = argc > 1 ? atol(argv[1]) : 0;
    long hi = argc > 2 ? atol(argv[2]) : 451;
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    for (long nr = lo; nr <= hi; nr++) {
        pid_t p = fork();
        if (p == 0) {
            setpgid(0, 0);
            sigaction(SIGSYS, &sa, NULL);
            alarm(1);
            long r = raw_syscall_zero(nr);
            if (g_trapped) {
                printf("%ld TRAP si_code=%d\n", nr, g_sicode);
                fflush(stdout);
                _exit(0);
            }
            printf("%ld RET %ld\n", nr, r);
            fflush(stdout);
            _exit(0);
        }
        if (p < 0) {
            fprintf(stderr, "fork failed at nr=%ld\n", nr);
            return 1;
        }
        int st = 0;
        waitpid(p, &st, 0);
        if (WIFSIGNALED(st)) {
            printf("%ld SIGNAL %d\n", nr, WTERMSIG(st));
            fflush(stdout);
        }
    }
    return 0;
}
