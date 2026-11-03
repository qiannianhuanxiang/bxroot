/*
 * environ 悬垂指针崩溃回归（2026-10-26）
 *
 * 缺陷：px_runtime_build_env() 内部 px_build_forced() 会 setenv() 回写
 * BXROOT_ULX_PATH / BXROOT_ULX_LDSO。glibc 在 environ 数组没有空位时会
 * realloc 整个数组并 free 旧块，于是调用方持有的环境指针悬垂。
 *
 * 有两条独立悬垂路径，都必须覆盖：
 *  1) 函数内部入口取的 src（environ 或调用方 envp）—— 由 system() 触发；
 *  2) 调用方传进来的 envp 本身就是 environ（execve(p, argv, environ)）。
 *
 * ★ 判别力关键：必须用**全新进程的第一次** exec/system。
 *   一旦本进程先 setenv 过，environ 容量变了，realloc 不再发生，缺陷被
 *   完全掩盖 —— 本探针第一版就是这样在有缺陷的 runtime 上也 PASS 的。
 *   所以每个场景都 fork 出干净子进程单独验证。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

/* 在干净子进程里跑 execve(p, argv, environ) —— 悬垂路径 2 */
static void case_execve_environ(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        extern char **environ;
        char *const argv[] = { (char *)"/bin/true", NULL };
        execve("/bin/true", argv, environ);
        _exit(127);
    }
    if (pid > 0) {
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) {
            fprintf(stderr, "FAIL waitpid(execve environ): %s\n", strerror(errno));
            failures++;
        } else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV) {
            fprintf(stderr, "FAIL execve(p,argv,environ) 子进程 SIGSEGV"

                            "（envp==environ 悬垂指针回归）\n");
            failures++;
        } else {
            printf("ok   execve(argv, environ) 子进程未崩溃 status=%d\n",
                   WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        }
    }
}

/* 在干净子进程里跑 execv（不传 envp）—— 悬垂路径 1 的 exec 形态 */
static void case_execv_noenv(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = { (char *)"/bin/true", NULL };
        execv(argv[0], argv);
        _exit(127);
    }
    if (pid > 0) {
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) {
            fprintf(stderr, "FAIL waitpid(execv): %s\n", strerror(errno));
            failures++;
        } else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV) {
            fprintf(stderr, "FAIL execv(no envp) 子进程 SIGSEGV\n");
            failures++;
        } else {
            printf("ok   execv(no envp) 子进程未崩溃 status=%d\n",
                   WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        }
    }
}

/* system() —— 悬垂路径 1 的 system 形态 */
static void case_system(const char *what)
{
    errno = 0;
    int rc = system("true");
    if (rc == -1) {
        fprintf(stderr, "FAIL %s: errno=%d(%s)\n", what, errno, strerror(errno));
        failures++;
    } else {
        printf("ok   %s -> rc=%d\n", what, rc);
    }
}

int main(void)
{
    char name[64];
    int i;

    /* ★ 顺序不能改：最敏感的场景必须在 environ 未被本进程改动前跑 ★ */
    case_execve_environ();
    case_execv_noenv();
    case_system("system #0 (pristine environ)");
    case_system("system #1 (pristine environ)");

    /* 撑大环境后再来一轮 */
    for (i = 0; i < 32; i++) {
        snprintf(name, sizeof(name), "BXROOT_TEST_PAD_%d", i);
        if (setenv(name, "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 1) != 0) {
            fprintf(stderr, "FAIL setenv(%s): %s\n", name, strerror(errno));
            failures++;
        }
    }
    case_system("system after environ growth");
    case_execve_environ();

    /* 挖洞再填 */
    for (i = 0; i < 24; i++) {
        snprintf(name, sizeof(name), "BXROOT_TEST_HOLE_%d", i);
        if (setenv(name, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0) != 0) {
            fprintf(stderr, "FAIL setenv(%s): %s\n", name, strerror(errno));
            failures++;
        }
    }
    for (i = 0; i < 24; i += 2) {
        snprintf(name, sizeof(name), "BXROOT_TEST_HOLE_%d", i);
        (void)unsetenv(name);
    }
    case_system("system with environ holes");

    if (failures == 0) {
        puts("SYSTEM_ENV_SAFETY_OK");
        return 0;
    }
    fprintf(stderr, "SYSTEM_ENV failures=%d\n", failures);
    return 1;
}
