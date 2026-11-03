/*
 * 小栈线程崩溃回归（2026-10-26）
 *
 * 缺陷：resolve_symlink_full / resolve_intermediate_symlinks 曾在**栈上**
 * 各放 16 x MAX_PATH_LEN(8KB) = 128KB 的循环检测集合，实际单帧 64KB
 * （objdump: sub sp, sp, #0x10, lsl #12）。而 openat/statx/fstatat 的钩子
 * 会互相嵌套（translate_follow -> stat_pre_resolve -> resolve_* ），
 * 8 层就是 512KB。
 *
 * 实测：pthread 栈 512KB 的线程里调 stat/lstat 直接 SIGSEGV；1MB 正常。
 * Android 上大量程序用 pthread_attr_setstacksize 把栈调小，所以这是真实
 * 崩溃。修法：seen 改到堆上（calloc），语义完全等价。
 *
 * 判据：512KB 栈的线程能跑完 stat/lstat/realpath/open，不得崩溃。
 * 注意：不同内核 pthread 最小栈不同，setstacksize 失败时跳过而不是判失败。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static volatile int worker_rc;

static void *worker(void *arg)
{
    struct stat st;
    char buf[4096];
    int i;

    (void)arg;
    for (i = 0; i < 50; i++) {
        if (stat("/etc", &st) != 0) { worker_rc = 10; return NULL; }
        if (lstat("/etc", &st) != 0) { worker_rc = 11; return NULL; }
        if (realpath("/etc", buf) == NULL) { worker_rc = 12; return NULL; }
        { int fd = open("/etc/hostname", O_RDONLY);
          if (fd < 0) { worker_rc = 13; return NULL; }
          close(fd); }
        if (access("/etc", F_OK) != 0) { worker_rc = 14; return NULL; }
    }
    worker_rc = 0;
    return NULL;
}

int main(void)
{
    pthread_attr_t at;
    pthread_t th;
    size_t sizes[] = { 524288, 1048576 };
    size_t i;
    int tested = 0;

    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        int rc;

        if (pthread_attr_init(&at) != 0) { fprintf(stderr, "attr_init failed\n"); return 2; }
        rc = pthread_attr_setstacksize(&at, sizes[i]);
        if (rc != 0) {
            printf("skip stack=%zu (setstacksize rc=%d)\n", sizes[i], rc);
            pthread_attr_destroy(&at);
            continue;
        }
        worker_rc = -1;
        rc = pthread_create(&th, &at, worker, NULL);
        pthread_attr_destroy(&at);
        if (rc != 0) {
            printf("skip stack=%zu (create rc=%d)\n", sizes[i], rc);
            continue;
        }
        pthread_join(th, NULL);
        if (worker_rc != 0) {
            fprintf(stderr, "FAIL stack=%zu worker_rc=%d\n", sizes[i], worker_rc);
            return 1;
        }
        printf("ok   stack=%zu 线程完成 stat/lstat/realpath/open/access\n", sizes[i]);
        tested++;
    }

    if (tested == 0) {
        puts("STACK_DEPTH_SKIPPED (\u5185\u6838\u4e0d\u5141\u8bb8\u5c0f\u6808)");
        return 0;
    }
    puts("SMALL_STACK_OK");
    return 0;
}
