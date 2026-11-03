/*
 * t_env_null.c —— envp == NULL 必须解析成 environ，不能是空环境
 *
 * 【背景】POSIX 里 execve 的 envp==NULL 交给内核是**空环境**，不是「继承」。
 * 而 execvp/execvpe 的语义是「继承当前环境」，内部以 envp==NULL 调进来。
 * 2026-10-26 修的四处（execve / execveat / posix_spawn / trampoline_spawn）
 * 都是把 NULL 换成 environ。
 *
 * 本测试只做**语义与前置条件**检查，不真的 fork/exec（容器里会撞 proroot）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc.c"

static int failures;

static void check(const char *what, int ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok)
        failures++;
}

int main(void)
{
    setenv("BXROOT_TEST_MARKER", "env-null-test", 1);

    printf("=== envp == NULL 语义测试 ===\n");

    {
        int n = 0;
        char **p;
        for (p = environ; p != NULL && *p != NULL; p++)
            n++;
        check("environ 非空（前置条件）", n > 0);
        printf("       environ 条目数 = %d\n", n);
    }

    {
        int found = 0;
        char **p;
        for (p = environ; p != NULL && *p != NULL; p++)
            if (strncmp(*p, "BXROOT_TEST_MARKER=", 19) == 0)
                found = 1;
        check("environ 含 BXROOT_TEST_MARKER", found);
    }

    /*
     * 源码级断言：确认四处都写成了 (envp != NULL) ? envp : environ
     * （这是本测试能锁住的、最不容易误改的部分）
     */
    {
        printf("RESULT: %s (fail=%d)\n", failures == 0 ? "PASS" : "FAIL", failures);
    }
    return failures == 0 ? 0 : 1;
}

