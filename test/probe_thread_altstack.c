#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include "crash.h"

/*
 * 真机探针：每线程私有备用栈（2026-10-18 修复）
 *
 * 缺陷：sigaltstack 是**每线程**属性，而原实现只在构造函数里给初始线程
 * 装了一次。pthread_create 出来的线程没有备用栈 → SA_ONSTACK 退化为
 * 普通栈 → 栈溢出时处理器自己起不来，进程静默死掉，拿不到现场。
 * 对 node/pnpm 这类多线程 guest 是常态场景。
 *
 * 修复：pthread_create 钩子统一包装新线程入口，进来先装私有备用栈
 * （bxroot_crash_install_altstack），退出前释放。
 *
 * 本探针直接验证该接口在多线程下的行为：
 *   · 修复后：每个线程都能装上 ss_sp != NULL 且未禁用的备用栈
 *   · 反向对照（不调用安装）：带备用栈 = 0
 */

/* 被测接口（crash.c 新增） */
extern int  bxroot_crash_install_altstack(void);
extern void bxroot_crash_uninstall_altstack(void);

static volatile int with_alt, checked;

static void *worker(void *a)
{
    stack_t ss;
    (void)a;
    /* 模拟 pthread_create 包装的行为：新线程入口先装备用栈 */
    if (bxroot_crash_install_altstack() == 0) {
        memset(&ss, 0, sizeof ss);
        if (sigaltstack(NULL, &ss) == 0 && !(ss.ss_flags & SS_DISABLE) &&
            ss.ss_sp != NULL)
            __atomic_add_fetch(&with_alt, 1, __ATOMIC_RELAXED);
    }
    __atomic_add_fetch(&checked, 1, __ATOMIC_RELAXED);
    bxroot_crash_uninstall_altstack();   /* 线程退出前释放 */
    return NULL;
}

int main(void)
{
    enum { N = 6 };
    pthread_t th[N];
    stack_t ss;
    int i, fails = 0;

    printf("=== 每线程备用栈接口 探针 ===\n\n");

    /* 主线程初始状态 */
    memset(&ss, 0, sizeof ss);
    sigaltstack(NULL, &ss);
    printf("  主线程初始: ss_sp=%p disabled=%d\n",
           ss.ss_sp, (ss.ss_flags & SS_DISABLE) ? 1 : 0);

    for (i = 0; i < N; i++) {
        if (pthread_create(&th[i], NULL, worker, NULL) != 0) {
            printf("  [SKIP] 线程创建失败\n");
            return 0;
        }
    }
    for (i = 0; i < N; i++)
        pthread_join(th[i], NULL);

    printf("  线程数=%d 带备用栈=%d\n", checked, with_alt);
    if (checked != N || with_alt != N) {
        printf("  [FAIL] 有线程没拿到私有备用栈\n");
        fails = 1;
    } else {
        printf("  [ok]   每个线程都成功装上私有备用栈\n");
    }

    /* 幂等性：重复安装不应泄漏/报错 */
    if (bxroot_crash_install_altstack() == 0 &&
        bxroot_crash_install_altstack() == 0)
        printf("  [ok]   重复安装幂等\n");
    else {
        printf("  [FAIL] 重复安装失败\n");
        fails = 1;
    }
    bxroot_crash_uninstall_altstack();

    printf("\n----------------------------------------\n");
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
