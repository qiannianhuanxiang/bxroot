/*
 * 非默认 rootfs（glibc 版本与容器不同）下的进程派生族探针。
 *
 * 用法：probe_fork_family <自身 guest 绝对路径> | reexec
 *   第一形态：先 execve 自身一次（带 "reexec"）。路径由调用方给：bxroot-run
 *   经 --argv0 传下来的 argv[0] 只有 basename，靠它重入会 ENOENT—— 因为 bxroot-run 起的
 *   首进程加载的是容器自己的 glibc，只有经 bxroot exec 钩子重入后才真正
 *   加载 --rootfs 里的 glibc；缺陷正藏在那一层。
 *   带参数：依次测 _Fork / fork / pthread_create / posix_spawn(RESETIDS)，
 *   每项打印一行 "name: ok" 或 "name: FAIL ..."，全部 ok 时退出 0。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;
extern pid_t _Fork(void);

static int bad;

static void child_result(const char *name, pid_t p, int want)
{
    int st = 0;
    if (p < 0) { printf("%s: FAIL spawn errno=%d\n", name, errno); bad++; return; }
    if (waitpid(p, &st, 0) < 0) { printf("%s: FAIL waitpid\n", name); bad++; return; }
    if (WIFSIGNALED(st)) { printf("%s: FAIL child killed by signal %d\n", name, WTERMSIG(st)); bad++; return; }
    if (WEXITSTATUS(st) != want) { printf("%s: FAIL exit=%d want=%d\n", name, WEXITSTATUS(st), want); bad++; return; }
    printf("%s: ok\n", name);
}

static void *thr(void *a) { (void)a; return (void *)42; }

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <self-guest-path>|reexec\n", argv[0]); return 2; }
    if (strcmp(argv[1], "reexec") != 0) {
        /* 用 argv[0]（回归脚本传的是 guest 绝对路径）重入自身。
         * 不用 /proc/self/exe：那条魔法链接的 guest 视角解析是另一条
         * 缺陷（见 RUN_PROC_VIEW），这里不把两件事绑在一起。 */
        char *av[] = { argv[1], "reexec", NULL };
        execve(argv[1], av, environ);
        perror("reexec");
        return 2;
    }

    { pid_t p = _Fork(); if (p == 0) _exit(3); child_result("_Fork", p, 3); }
    { pid_t p = fork();  if (p == 0) _exit(4); child_result("fork", p, 4); }
    {
        pthread_t t; void *r = NULL;
        int rc = pthread_create(&t, NULL, thr, NULL);
        if (rc == 0) pthread_join(t, &r);
        if (rc != 0 || (long)r != 42) { printf("pthread_create: FAIL rc=%d ret=%ld\n", rc, (long)r); bad++; }
        else printf("pthread_create: ok\n");
    }
    {
        posix_spawnattr_t a; pid_t p = -1;
        char *av[] = { "/bin/true", NULL };
        posix_spawnattr_init(&a);
        posix_spawnattr_setflags(&a, POSIX_SPAWN_RESETIDS);
        int rc = posix_spawn(&p, "/bin/true", NULL, &a, av, environ);
        if (rc != 0) { printf("posix_spawn RESETIDS: FAIL rc=%d\n", rc); bad++; }
        else child_result("posix_spawn RESETIDS", p, 0);
    }
    return bad ? 1 : 0;
}
