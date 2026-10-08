/*
 * probe_self_sigsys.c —— 进程发给自己的 SIGSYS 必须被吞掉（2026-10-09 真机缺陷）
 *
 * 真机（DSHA 内置终端）：交互式 bash 给 SIGSYS 装了自己的终止处理器
 * （termsig_sighandler：先恢复默认处理，再 kill(getpid(), sig)）。
 * bxroot 的 signal()/sigaction() 钩子为了保住 seccomp 兜底处理器，会静默吞掉
 * 对 SIGSYS 的 SIG_DFL/SIG_IGN 设置，于是 bash 的处理器没被摘掉，
 * kill(getpid(), SIGSYS) 又回到同一个处理器 → 无限递归 → 栈耗尽 SIGSEGV
 *（终端里看到 "[proroot] child killed by signal 11"，退出码 139）。
 *
 * 官方 runtime 的做法（反汇编 kill/tkill/tgkill，日志串
 * "[proroot-kill] swallow self SIGSYS"）：进程发给自己的 SIGSYS 直接吞掉，
 * 返回成功但不真正发送。真正的 seccomp SIGSYS 由内核直接投递，不经过 kill()。
 *
 * 判据：fork 出子进程，装一个"递归计数"处理器并 kill(getpid(), SIGSYS)。
 *   - 无 runtime / 吞掉  → 子进程要么被 SIGSYS 终止(31)，要么处理器最多进一次
 *   - 有缺陷的 runtime    → 处理器被反复进入 → 深度超过阈值 → exit 77
 * 另测 tgkill(getpid(), gettid(), SIGSYS)。其它信号（SIGUSR1）必须照常送达，
 * 避免"误吞一切"。
 *
 * 退出码：0 = 期望成立；1 = 期望被打破
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static volatile int depth;
static volatile int usr1_seen;

static void rec(int s)
{
    if (++depth > 20) {
        static const char m[] = "RECURSE>20\n";
        ssize_t r = write(2, m, sizeof m - 1);
        (void)r;
        _exit(77);
    }
    signal(s, SIG_DFL);      /* bash termsig_sighandler: 恢复默认 */
    kill(getpid(), s);       /* bash termsig_sighandler: 再发给自己 */
}

static void on_usr1(int s) { (void)s; usr1_seen = 1; }

/* 返回子进程状态码语义：
 *   0 正常退出(吞掉) / 31 被 SIGSYS 终止(未吞掉但没递归) / 77 递归失控 */
static int child_kill(int use_tgkill)
{
    pid_t p = fork();
    if (p == 0) {
        signal(SIGSYS, rec);
        if (use_tgkill)
            syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGSYS);
        else
            kill(getpid(), SIGSYS);
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    if (WIFSIGNALED(st)) return WTERMSIG(st);
    return WEXITSTATUS(st);
}

int main(void)
{
    int fail = 0, r;

    r = child_kill(0);
    printf("kill(self,SIGSYS)    -> %d (0=吞掉 31=被SIGSYS终止 77=递归失控)\n", r);
    if (r == 77) { printf("FAIL kill: 递归失控\n"); fail = 1; }

    r = child_kill(1);
    printf("tgkill(self,SIGSYS)  -> %d\n", r);
    if (r == 77) { printf("FAIL tgkill: 递归失控\n"); fail = 1; }

    /* 其它信号必须照常送达 */
    signal(SIGUSR1, on_usr1);
    kill(getpid(), SIGUSR1);
    if (!usr1_seen) { printf("FAIL SIGUSR1 被误吞\n"); fail = 1; }
    else printf("OK SIGUSR1 照常送达\n");

    printf(fail ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return fail;
}
