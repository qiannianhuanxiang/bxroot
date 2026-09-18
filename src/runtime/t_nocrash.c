/* T6：BXROOT_NO_CRASH=1 时不安装处理器，客户自己的 handler 生效 */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crash.h"

static volatile sig_atomic_t g_mine = 0;

/* 客户自己的 handler：只设一个标志 + 写一行，不恢复执行 */
static void my_handler(int sig)
{
    (void)sig;
    g_mine = 1;
    const char msg[] = "[客户 handler] 被调用\n";
    (void)!write(1, msg, sizeof(msg) - 1);
    /* 恢复默认后重抛，让进程按正常语义死掉（退出码 139） */
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(void)
{
    /*
     * 先装客户 handler，再调 bxroot_crash_install。
     * 若 BXROOT_NO_CRASH=1 生效，bxroot 不安装 → 我们的 handler 存活。
     */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = my_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    bxroot_crash_install("bxroot");

    /* 无论安装与否，都不应装成"bxroot 优先"：用 installed() 判断 */
    if (bxroot_crash_installed()) {
        /* 未生效：报告出去（脚本据此判 FAIL） */
        const char msg[] = "[探针] bxroot_crash_installed()=1（NO_CRASH 未生效）\n";
        (void)!write(1, msg, sizeof(msg) - 1);
    } else {
        const char msg[] = "[探针] bxroot_crash_installed()=0（NO_CRASH 生效）\n";
        (void)!write(1, msg, sizeof(msg) - 1);
    }

    volatile int *p = (int *)0;
    *p = 42;
    return 0;
}
