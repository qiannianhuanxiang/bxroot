/*
 * 多线程并发压测：验证 fakeroot 账本在并发写下的正确性（评估报告 8.7）。
 *
 * 背景：账本原先假设单线程（全项目零锁）。报告指出多线程客户（node
 * worker、pnpm 并发 IO）下 chown/chmod 记账会竞态。
 *
 * ★ 实测结果（2026-09-18）★
 *   修复前：8 线程 × 400 键，**稳定复现**堆破坏 ——
 *       double free or corruption (fasttop)
 *       malloc(): unaligned tcache chunk detected
 *   根因：fr_map_compact（整表 realloc + 键所有权转移）与 fr_map_probe
 *   （按 cap 取模遍历探测链）并发放行：一个线程正在重哈希、另一个按旧
 *   cap 访问，读到已释放/搬移的槽位。
 *   修复后：两阶段均恒 PASS。
 *
 * 两阶段设计（各自针对一类缺陷）：
 *   阶段 A（小容量 64 + 开淘汰）：最大化重哈希窗口，检测**堆破坏/不变量
 *       破坏**。断言：不变量成立、进程不崩、count 不超过 cap。
 *   阶段 B（大容量 8192 + 关淘汰）：容量足够容纳全部键且不淘汰，
 *       检测**丢更新**（竞态导致某些 put 未生效）。断言：count == 期望。
 *
 * 编译（源码级，与项目其他纯逻辑测试同法）：
 *   gcc -std=c11 -O1 -D_GNU_SOURCE -DFAKEROOT_PURE_LOGIC \
 *       -o t_concur test/t_concur.c src/runtime/fakeroot.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "../src/runtime/fakeroot.h"

#define NTHREAD     8
#define PER_THREAD  400

static fakeroot_map *g_map;
static volatile int  g_go;
static int           g_put_ok;      /* 成功的 put 计数（原子累加） */

/* 每个线程只写自己的键段：路径 /conc/<tid>/<i> */
static void *worker(void *arg)
{
    long tid = (long)arg;
    char path[128];

    while (!g_go)          /* 同步起跑，最大化交错 */
        ;

    for (int i = 0; i < PER_THREAD; i++) {
        fr_key k;
        fr_record rec;

        snprintf(path, sizeof(path), "/conc/%ld/%d", tid, i);
        if (fakeroot_key_path(&k, path) != 0)
            continue;

        memset(&rec, 0, sizeof(rec));
        rec.uid       = (uid_t)(tid * 1000 + i);
        rec.uid_faked = true;

        if (fakeroot_map_put(g_map, k, &rec) == FR_OK)
            __atomic_fetch_add(&g_put_ok, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static int run_phase(const char *name, size_t slots, bool eviction_on,
                     int check_count)
{
    pthread_t th[NTHREAD];
    size_t    expect = (size_t)NTHREAD * PER_THREAD;
    int       rc, fails = 0;

    printf("== %s（cap=%zu，淘汰=%s）==\n", name, slots,
           eviction_on ? "开" : "关");

    g_map     = fakeroot_map_create(slots);
    g_go      = 0;
    g_put_ok  = 0;
    if (g_map == NULL) {
        printf("  创建账本失败\n");
        return 1;
    }
    if (!eviction_on)
        fakeroot_map_set_eviction(g_map, false);

    for (long i = 0; i < NTHREAD; i++) {
        rc = pthread_create(&th[i], NULL, worker, (void *)i);
        if (rc != 0) {
            printf("  pthread_create 失败 rc=%d\n", rc);
            return 1;
        }
    }
    g_go = 1;
    for (int i = 0; i < NTHREAD; i++)
        pthread_join(th[i], NULL);

    size_t got = fakeroot_map_count(g_map);
    bool   inv = fakeroot_map_check_invariants(g_map);

    printf("  put 成功数 : %d / %zu\n", g_put_ok, expect);
    printf("  记录数     : %zu\n", got);
    printf("  不变量     : %s %s\n", inv ? "成立" : "破坏", inv ? "✅" : "❌");
    printf("  重哈希次数 : %zu\n", fakeroot_map_rehash_count(g_map));

    if (!inv) { printf("  ❌ 不变量破坏\n"); fails++; }

    if (check_count) {
        if (got == expect) printf("  计数精确   : ✅（无丢更新）\n");
        else { printf("  ❌ 计数 %zu != 期望 %zu（丢更新）\n", got, expect); fails++; }
        if (g_put_ok == (int)expect) printf("  put 全成功 : ✅\n");
        else { printf("  ❌ 仅 %d 次 put 成功\n", g_put_ok); fails++; }
    } else {
        /* 阶段 A：有淘汰，count 只需不超过 cap（不变量已在上面判） */
        if (got <= fakeroot_map_capacity(g_map)) printf("  容量约束   : ✅\n");
        else { printf("  ❌ count %zu > cap\n", got); fails++; }
    }

    fakeroot_map_destroy(g_map);
    g_map = NULL;
    printf("  → %s\n\n", fails == 0 ? "PASS" : "FAIL");
    return fails;
}

int main(void)
{
    int fails = 0;

    /* 阶段 A：小容量 + 开淘汰 —— 最大化重哈希，检测堆破坏/不变量 */
    fails += run_phase("阶段 A：重哈希压力（堆破坏/不变量检测）", 64, true, 0);

    /* 阶段 B：大容量 + 关淘汰 —— 检测丢更新 */
    fails += run_phase("阶段 B：计数精确性（丢更新检测）", 8192, false, 1);

    if (fails == 0) {
        printf("RESULT: PASS（并发下账本自洽）\n");
        return 0;
    }
    printf("RESULT: FAIL（%d 项失败）\n", fails);
    return 1;
}
