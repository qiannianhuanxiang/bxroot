/*
 * probe_clone3_fallback.c —— clone3 回退链探针（RUN_CLONE3_FALLBACK.sh 用）
 *
 * 【为什么要有】行动清单 #9 原写"glib g_spawn_async 端到端回归缺失"，
 * 而本容器**没有 glib 开发库**，真实 glib 栈不可复现。但那条回归要验的
 * 实质是 **clone3 被 seccomp 拦截时，glibc 能否回退到 clone(2)** ——
 * glib 的 g_spawn_async 只是众多调用方之一，这条链本身不依赖 glib。
 *
 * 【判据】三件事必须同时成立：
 *   1. 裸 clone3(435) 调用能返回（无论是真实 fd 还是 ENOSYS）——
 *      不能是进程被杀（SECCOMP_RET_KILL 会给 rc=159/137，不可挽救）
 *   2. pthread_create 成功且 join 拿到正确返回值（glibc 线程创建走了
 *      clone3→clone 回退链）
 *   3. fork 成功（另一条 clone 路径）
 * 配合 seccomp_block_clone3.c 人为拦截 clone3 时，第 2、3 条必须仍然成立。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

/* clone3 的裸调用（glibc 线程创建会先试它）。结构体布局按内核 uapi 定义。 */
struct clone_args {
    unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal;
    unsigned long long stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

static void *worker(void *a) { (void)a; return (void *)0x5eed; }

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct clone_args ca;
    long r;

    /* 1) clone3 裸调用：被拦时期望 ENOSYS，而不是进程死 */
    memset(&ca, 0, sizeof ca);
    ca.exit_signal = 17; /* SIGCHLD */
    errno = 0;
    r = syscall(435 /* clone3 */, &ca, (unsigned long)sizeof ca);
    printf("raw clone3(435) rc=%ld errno=%d (%s)\n", r, errno, strerror(errno));

    /* 2) pthread_create 必须仍然成功 —— 这就是回退链的实证 */
    {
        pthread_t t;
        void *ret = NULL;
        int rc = pthread_create(&t, NULL, worker, NULL);
        printf("pthread_create rc=%d\n", rc);
        if (rc == 0) {
            pthread_join(t, &ret);
            printf("pthread_join ret=%p\n", ret);
            if (ret != (void *)0x5eed)
                return 2;
        } else {
            return 1;
        }
    }

    /* 3) fork 也要正常（另一条 clone 路径） */
    {
        pid_t p = fork();
        if (p == 0) _exit(0);
        printf("fork pid=%d\n", (int)p);
        if (p < 0)
            return 3;
    }
    printf("RESULT: OK\n");
    return 0;
}
