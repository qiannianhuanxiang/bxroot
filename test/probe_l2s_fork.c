/*
 * l2s cnt_lock fork 死锁回归（2026-10-26）
 *
 * g_cnt_lock 是进程内自旋锁。父进程某线程持锁做 link 计数时另一线程 fork，
 * 子进程继承 g_cnt_lock=1 且持锁线程不存在 → 之后第一次走 read/write
 * 回退分支就永久自旋。修法：在 atfork 的 child 回调里复位。
 *
 * 判据：fork 出的子进程里做 link/unlink（会走计数路径）必须能完成。
 * 用 -DBXROOT_LINK2SYMLINK=1 强制走 l2s 计数路径。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    char dir[] = "/tmp/l2sfork-XXXXXX";
    char a[512], b[512], c[512];
    int i, fails = 0;

    if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 2; }
    snprintf(b, sizeof(b), "%s/base", dir);

    { FILE *f = fopen(b, "w"); if (!f) { perror("create"); return 2; }
      fputs("x", f); fclose(f); }

    /* 反复 fork + 在子进程里做 link（触发 l2s 计数路径） */
    for (i = 0; i < 8; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            snprintf(a, sizeof(a), "%s/l%d", dir, i);
            snprintf(c, sizeof(c), "%s/m%d", dir, i);
            if (link(b, a) != 0) _exit(30);
            if (link(a, c) != 0) _exit(31);
            if (unlink(a) != 0) _exit(32);
            if (unlink(c) != 0) _exit(33);
            _exit(0);
        }
        if (pid > 0) {
            int st = 0;
            if (waitpid(pid, &st, 0) < 0) { fails++; continue; }
            if (WIFSIGNALED(st)) {
                fprintf(stderr, "FAIL child %d killed by sig %d\n", i, WTERMSIG(st));
                fails++;
            } else if (WEXITSTATUS(st) != 0) {
                fprintf(stderr, "FAIL child %d exit=%d\n", i, WEXITSTATUS(st));
                fails++;
            }
        }
    }

    { char cmd[640];
      snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
      if (system(cmd) != 0) { /* cleanup best effort */ } }

    if (fails == 0) { puts("L2S_FORK_OK"); return 0; }
    fprintf(stderr, "L2S_FORK fails=%d\n", fails);
    return 1;
}
