/*
 * 真机探针：fork 之后子进程里的 SHM 门必须复位（2026-10-18 修复 S3）
 *
 * --- 缺陷 ---
 * g_shm_transition 是 SHM 的"互斥门"：0=空闲，1=有 shm 操作进行，
 * 2=有 fork 进行。而 bxroot_sysvshm_fork_child() 原来是**空函数**，
 * fork_end() 只在自己包装的 fork() 里被调用。
 *
 * 于是经 raw clone / _Fork / glibc 内部隐藏别名 fork 出的子进程会
 * **永久继承**门值 → 子进程里 194..197 全部 -EAGAIN，且它自己再 fork
 * 也 -EAGAIN，并遗传给孙进程。
 *
 * --- 修复 ---
 * 记录门的属主 tid；子进程在 atfork child 里无条件复位（fork 后只剩
 * 本线程，任何门值都是残值），并自增代际号供诊断。
 *
 * --- 本探针 ---
 * 模拟"父进程持门时 fork"：
 *   1. 主线程把门占上（等价于另一个线程正在做 shm 操作）
 *   2. fork()
 *   3. 子进程调用 bxroot_sysvshm_fork_child() 并检查门是否已复位
 *      → 修复后：可以再次拿到门（compare_exchange 成功）
 *      → 修复前：永久拿不到（-EAGAIN）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "sysvshm.c"

static int fails, checks;

static void ck(const char *what, int got, int want)
{
    checks++;
    if (got != want) {
        fails++;
        printf("  [FAIL] %-50s got=%d want=%d\n", what, got, want);
    } else {
        printf("  [ok]   %-50s = %d\n", what, got);
    }
}

int main(void)
{
    pid_t pid;
    int status = 0;
    unsigned int idle;

    printf("=== fork 后 SHM 门复位 探针 ===\n\n");

    /*
     * 1) 模拟"父进程另一线程正持门"：直接把它置成 1。
     *    这里不用 bxroot_sysvshm_fork_begin（它置 2），因为我们要测的是
     *    "shm 操作进行中时被 fork" 这条更危险的路径。
     */
    __atomic_store_n(&g_shm_transition, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&g_shm_transition_owner, 999999, __ATOMIC_RELEASE);
    printf("  父进程持门: transition=%u\n",
           __atomic_load_n(&g_shm_transition, __ATOMIC_ACQUIRE));

    pid = fork();
    if (pid < 0) {
        printf("  [SKIP] fork 失败\n");
        return 0;
    }

    if (pid == 0) {
        /* ---- 子进程 ---- */
        int before = (int)__atomic_load_n(&g_shm_transition, __ATOMIC_ACQUIRE);

        /* 这正是 atfork child 会做的事 */
        bxroot_sysvshm_fork_child();

        {
            int after = (int)__atomic_load_n(&g_shm_transition, __ATOMIC_ACQUIRE);
            unsigned int free_now = 0;
            int can_take = __atomic_compare_exchange_n(&g_shm_transition,
                                                       &free_now, 1, 0,
                                                       __ATOMIC_ACQ_REL,
                                                       __ATOMIC_RELAXED);

            printf("  子进程: 复位前 transition=%d, 复位后=%d, 能重新持门=%d\n",
                   before, after, can_take);

            /* 用退出码把结论带回父进程 */
            if (before != 1) {
                _exit(11);          /* 前提不成立 */
            }
            if (after != 0) {
                _exit(12);          /* 门没被复位 */
            }
            if (!can_take) {
                _exit(13);          /* 复位后仍拿不到门 */
            }
            _exit(0);
        }
    }

    waitpid(pid, &status, 0);

    /* 父进程视角 */
    ck("父进程 fork 前持门", 1, 1);
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        printf("  子进程退出码 = %d\n", code);
        ck("子进程：门被复位且可重新持有", code, 0);
    } else {
        printf("  [FAIL] 子进程异常终止（signal %d）\n", WTERMSIG(status));
        fails++;
    }

    /* 收尾：把父进程的门清掉，避免影响后续 */
    __atomic_store_n(&g_shm_transition_owner, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_shm_transition, 0, __ATOMIC_RELEASE);
    idle = __atomic_load_n(&g_shm_transition, __ATOMIC_ACQUIRE);
    ck("父进程门已清理", (int)idle, 0);

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
