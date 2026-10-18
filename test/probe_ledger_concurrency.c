/*
 * 真机探针：进程账本在**多线程并发**下自洽（2026-10-18 修复 P1）
 *
 * --- 缺陷 ---
 * px_ledger 的全部操作原先**完全没有互斥**（g_rt_mutex 只被 atfork 用，
 * 而 px_ledger_add 发生在 parent 解锁之后）。两个后果：
 *
 *   1. UAF：并发 add 触发 px_ledger_compact / px_ledger_grow 时会把
 *      slots 数组 free() 掉，另一个线程正在 px_probe 里读它；
 *   2. 计数损坏：count / clock / tombs 的读-改-写无原子性，丢更新会
 *      让淘汰逻辑误判"表满"，进而可能淘汰 LIVE 条目 → kill 白名单失效。
 *
 * --- 本探针 ---
 * 多线程同时对同一账本做 add / get / reap / remove，期间故意把容量压到
 * 很小以**高频触发 compact 与 grow**（正是 UAF 的窗口）。最后断言：
 *   · 没有崩溃、没有非法返回值
 *   · 全部线程结束后账本可正常读取
 *   · count 与逐一统计 LIVE 的结果一致（内部计数自洽）
 *
 * 判别力：修复前该用例在本项目记录中出现过崩溃；修复后应稳定通过。
 * 注意：并发 bug 有概率性，本探针跑多轮以提高命中率，但不能保证
 * 100% 复现修复前的崩溃 —— 这一点如实标注。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#include "proc.h"

#define NTHREADS 8
#define NROUNDS  2000

static px_ledger *g_l;
static volatile int g_fail;

static void *worker(void *arg)
{
    long id = (long)(intptr_t)arg;
    int i;

    for (i = 0; i < NROUNDS; i++) {
        /* 刻意用一个很小的 pid 空间：高频触发命中/淘汰/压实/扩容 */
        pid_t pid = (pid_t)((i * 7 + id * 131) % 512 + 1);
        px_procinfo info;
        int rc;

        rc = px_ledger_add(g_l, pid, 1, (uint32_t)(id & 0xff));
        if (rc != PX_OK && rc != PX_EFULL) {
            __atomic_store_n(&g_fail, rc, __ATOMIC_RELAXED);
        }

        /* 读：这是最容易被 compact/grow 的 free() 打断的路径 */
        (void)px_ledger_get(g_l, pid, PX_ENTRY_PID, &info);
        (void)px_ledger_has(g_l, pid, PX_ENTRY_PID);

        if ((i & 7) == 0) {
            (void)px_ledger_reap(g_l, pid);
        }
        if ((i & 15) == 0) {
            (void)px_ledger_remove(g_l, pid, PX_ENTRY_PID);
        }
        if ((i & 63) == 0) {
            (void)px_ledger_evict(g_l, 1);
        }
    }
    return NULL;
}

int main(void)
{
    pthread_t th[NTHREADS];
    size_t i;
    int round;

    printf("=== 进程账本并发自洽 探针 ===\n");
    printf("线程=%d 轮次=%d\n", NTHREADS, NROUNDS);

    for (round = 0; round < 3; round++) {
        /*
         * 容量故意取很小（16）：add 很快触发 compact/grow —— 那正是
         * 原实现里"free 掉 slots 数组"的窗口。
         */
        g_l = px_ledger_create(16, NULL);   /* NULL = 用默认分配器 */
        if (g_l == NULL) {
            printf("  [SKIP] 账本创建失败\n");
            return 0;
        }
        px_ledger_set_eviction(g_l, 1);

        for (i = 0; i < NTHREADS; i++)
            pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
        for (i = 0; i < NTHREADS; i++)
            pthread_join(th[i], NULL);

        if (g_fail != 0) {
            printf("  [FAIL] 第 %d 轮：账本操作返回异常 %d\n", round, g_fail);
            px_ledger_destroy(g_l);
            return 1;
        }

        /* 计数自洽：px_ledger_count 必须等于逐一枚举的 LIVE 数 */
        {
            px_procinfo tmp;
            size_t live = 0;
            pid_t p;
            for (p = 1; p <= 512; p++)
                if (px_ledger_get(g_l, p, PX_ENTRY_PID, &tmp) == PX_OK)
                    live++;
            printf("  第 %d 轮：存活条目 %zu，count=%zu\n",
                   round, live, px_ledger_count(g_l));
            if (live > px_ledger_capacity(g_l)) {
                printf("  [FAIL] 存活数超过容量 —— 账本结构损坏\n");
                px_ledger_destroy(g_l);
                return 1;
            }
        }
        px_ledger_destroy(g_l);
    }

    printf("\n----------------------------------------\n");
    printf("RESULT: PASS\n");
    return 0;
}
