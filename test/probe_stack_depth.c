#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void *worker(void *arg)
{
    (void)arg;
    struct stat st;
    char p[512];
    int i;
    /* 触发多层 resolver 嵌套：绝对符号链接 + 中间组件 */
    for (i = 0; i < 200; i++) {
        snprintf(p, sizeof(p), "/tmp/stackdeep-XXXXXX");
        if (mkdir(p, 0700) != 0) break;
        (void)stat("/tmp", &st);
        (void)lstat("/tmp", &st);
        (void)realpath("/tmp", NULL);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    size_t sz = argc > 1 ? (size_t)strtoul(argv[1], NULL, 0) : 0;
    pthread_attr_t at;
    pthread_t th;
    int rc;

    if (sz == 0) {          /* 主线程：直接跑 */
        worker(NULL);
        puts("MAIN-OK");
        return 0;
    }
    pthread_attr_init(&at);
    rc = pthread_attr_setstacksize(&at, sz);
    if (rc != 0) { fprintf(stderr, "setstacksize(%zu) rc=%d\n", sz, rc); return 2; }
    rc = pthread_create(&th, &at, worker, NULL);
    if (rc != 0) { fprintf(stderr, "create rc=%d\n", rc); return 2; }
    pthread_join(th, NULL);
    printf("THREAD-OK stack=%zu\n", sz);
    return 0;
}
