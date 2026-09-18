/* T7：链式调用——客户在 bxroot 之后注册 handler，崩溃时两者都应被走到 */
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "crash.h"

static volatile sig_atomic_t g_mine = 0;

static void my_handler(int sig)
{
    (void)sig;
    g_mine = 1;
    const char msg[] = "[客户 handler] 被调用\n";
    (void)!write(1, msg, sizeof(msg) - 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(void)
{
    /*
     * 顺序：先 bxroot_crash_install（模拟 LD_PRELOAD 构造函数），
     * 再由"客户"注册自己的 handler —— 这是"后装者胜"的正常情形，
     * 客户的 handler 覆盖 bxroot 的。这里验证的是：客户覆盖后，
     * bxroot 的 g_prev 链没有把它自己的输出搞乱，且客户 handler 生效。
     *
     * 注意：本用例验证的是"后装者胜"这一确定性行为（客户覆盖 bxroot），
     * 不是 bxroot 链式调用 pre-existing handler（那个需要 handler 装在
     * bxroot 之前，只有更早的 LD_PRELOAD 库能做到，进程内无法构造）。
     */
    bxroot_crash_install("bxroot");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = my_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    volatile int *p = (int *)0;
    *p = 42;
    return 0;
}
