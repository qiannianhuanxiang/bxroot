/*
 * pthread_create 栈下限修正的验收探针（配合 test/RUN_PTHREAD_CREATE.sh）。
 *
 * 为什么需要它
 * ------------
 * 要验收的 parity 是"**小于下限的栈请求被抬到下限**"，而这件事
 * 只看 pthread_create 的返回值是**看不出来**的：
 *
 *     请求 135168 → bxroot 修前也返回 rc=0，但线程真实只拿到 135168，
 *     调用方随后在深调用链上撞守卫页 → SIGSEGV。
 *
 * 所以判据必须是"**读回线程真实拿到的栈大小**"（pthread_getattr_np）。
 * 单看 rc 会把"没修"误判成"修好了"。
 *
 * 用法
 * ----
 *   pthread_create_probe <size>   测一个栈大小（字节）；0 = 默认属性
 *   pthread_create_probe --stress 32 轮小栈 + TLS + 16KB 栈上变量
 *
 * 输出（供 shell 侧 grep）
 * -----------------------
 *   RESULT size=<n> 真实栈=<n> create_rc=<n> ret_ok=<0|1>
 *   STRESS 成功 <n> / 失败 <n>
 *
 * 退出码：0 成功 / 3 创建失败 / 4 join 失败 / 5 线程结果异常
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

#define MAGIC ((void *)(uintptr_t)0x1234)

/* 线程体：先写一小段栈，再返回哨兵值 —— 同时验证"栈真的可写"。 */
static void *worker(void *a)
{
    volatile char probe[512];
    memset((void *)probe, 0x5a, sizeof probe);
    return probe[0] == 0x5a ? MAGIC : NULL;
}

/* ------------------------------------------------------------------ */
/* 压力测试：TLS + 16KB 栈上局部变量，验证"抬升后的栈真的够用"          */
/* ------------------------------------------------------------------ */
static __thread int tls_counter;
static int results[64];

static void *stress_worker(void *a)
{
    long id = (long)a;
    volatile char big[16384];

    tls_counter = (int)id * 7;
    memset((void *)big, (int)id, sizeof big);
    int sum = 0;
    for (size_t i = 0; i < sizeof big; i += 1024)
        sum += big[i];
    results[id] = (tls_counter == (int)id * 7) && (sum != 0);
    return (void *)(long)results[id];
}

static int run_stress(void)
{
    long psm = sysconf(_SC_THREAD_STACK_MIN);
    int ok = 0, fail = 0;

    for (long i = 0; i < 32; i++) {
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setstacksize(&at, (size_t)(psm + (i % 4) * 4096));

        pthread_t t;
        void *ret = NULL;
        int rc = pthread_create(&t, &at, stress_worker, (void *)i);
        if (rc) {
            printf("  迭代 %ld: pthread_create rc=%d (%s)\n", i, rc, strerror(rc));
            fail++;
            pthread_attr_destroy(&at);
            continue;
        }
        pthread_join(t, &ret);
        if (ret == (void *)1)
            ok++;
        else {
            printf("  迭代 %ld: 线程结果异常 %p\n", i, ret);
            fail++;
        }
        pthread_attr_destroy(&at);
    }
    printf("STRESS 成功 %d / 失败 %d\n", ok, fail);
    return fail ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* 单档位：创建线程并读回**真实**栈大小                                */
/* ------------------------------------------------------------------ */
static int run_one(size_t sz)
{
    pthread_attr_t at;
    pthread_t t;
    void *ret = NULL;
    size_t real = 0;
    int rc, jrc;

    pthread_attr_init(&at);
    if (sz)
        pthread_attr_setstacksize(&at, sz);

    errno = 0;
    rc = pthread_create(&t, &at, worker, NULL);
    pthread_attr_destroy(&at);
    if (rc) {
        printf("RESULT size=%zu 真实栈=0 create_rc=%d ret_ok=0 (%s)\n",
               sz, rc, strerror(rc));
        return 3;
    }

    /*
     * ★ 关键一步：pthread_getattr_np 读回内核真正给的栈大小。
     * 它与"请求值"不同才是本修正的核心证据。
     */
    {
        pthread_attr_t got;
        if (pthread_getattr_np(t, &got) == 0) {
            pthread_attr_getstacksize(&got, &real);
            pthread_attr_destroy(&got);
        }
    }

    jrc = pthread_join(t, &ret);
    if (jrc) {
        printf("RESULT size=%zu 真实栈=%zu create_rc=0 ret_ok=0 join_rc=%d\n",
               sz, real, jrc);
        return 4;
    }

    int ok = (ret == MAGIC);
    printf("RESULT size=%zu 真实栈=%zu create_rc=0 ret_ok=%d\n", sz, real, ok);
    return ok ? 0 : 5;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1 && strcmp(argv[1], "--stress") == 0)
        return run_stress();

    size_t sz = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 0) : 131072;
    return run_one(sz);
}
