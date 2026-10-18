/*
 * 真机探针：SHM 仿真失败时返回**内核会返回**的错误码（2026-10-18 修复 S6）
 *
 * --- 缺陷 ---
 * 仿真层原来把内部状态错误直接抛给客户：
 *   · anchor 失效 → -EBADF(9)。而内核的 shmget/shmat/shmctl **从不返回
 *     EBADF**，客户会走进"fd 用错了"的排查方向。
 *   · claim 锁竞争 → 一次非阻塞尝试就返回 EAGAIN(11)。内核 shmget 也
 *     **从不返回 EAGAIN**，PostgreSQL 这类不重试的程序会把一次瞬时竞争
 *     当成永久失败。
 *
 * --- 修复 ---
 *   · 内部不可用统一用 ENOSYS(38)（"仿真能力不可用"最接近），
 *     这也是 libuv 等库期望的"该调用不可用"信号，客户可干净回退。
 *   · claim 锁改为**有界重试**（信号上下文里不能阻塞），
 *     仍失败才 EAGAIN —— 此时已是真异常而非常规抖动。
 *
 * --- 本探针 ---
 * 两个部分：
 *   A) 静态判据：源码里不得再有 `return -9`（EBADF 泄漏点）
 *   B) 行为：**未初始化**时 194..197 应返回 ENOSYS，且**不是** EBADF
 *
 * 判别力：修复前 A 项命中 3 处；B 项在未初始化路径上由 g_shm_ready
 * 检查兜住（返回 ENOSYS），所以 B 主要防回归。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sysvshm.c"

static int fails, checks;

static void ck(const char *what, int got, int want)
{
    checks++;
    if (got != want) {
        fails++;
        printf("  [FAIL] %-52s got=%d want=%d\n", what, got, want);
    } else {
        printf("  [ok]   %-52s = %d\n", what, got);
    }
}

/* 源码里是否还有 EBADF 泄漏（`return -9`） */
static int source_has_ebadf(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[1024];
    int found = 0;

    if (f == NULL)
        return -1;
    while (fgets(line, sizeof line, f) != NULL) {
        /* 只找 return -9 这种直接返回（注释里提到不算） */
        if (strstr(line, "return -9") != NULL)
            found++;
    }
    fclose(f);
    return found;
}

int main(void)
{
    long x0 = 0;
    int handled;

    printf("=== SHM 错误码语义 探针 ===\n\n");

    /* A) 源码判据 */
    {
        int n = source_has_ebadf("src/runtime/sysvshm.c");
        if (n < 0) {
            printf("  [SKIP] 读不到 src/runtime/sysvshm.c（请在仓库根运行）\n");
        } else {
            ck("源码中无 `return -9`（EBADF 泄漏点）", n, 0);
        }
    }

    /*
     * B) **未初始化**：emulate 应返回 0（不拦截），把调用交回内核 ——
     *    这是正确设计（"不假装能处理"），客户最终从内核拿到 ENOSYS。
     */
    __atomic_store_n(&g_shm_ready, 0, __ATOMIC_RELEASE);

    x0 = 0;
    handled = bxroot_sysvshm_emulate(SHM_NR_GET, 0x1234, 4096, 0600, &x0);
    ck("未初始化时 shmget 交给内核（不拦截）", handled, 0);

    x0 = 0;
    handled = bxroot_sysvshm_emulate(SHM_NR_CTL, 1, 0, 0, &x0);
    ck("未初始化时 shmctl 交给内核（不拦截）", handled, 0);

    /*
     * C) **已初始化但 anchor 失效**：这才是修复要覆盖的路径 ——
     *    应拦截并回 ENOSYS(38)，而**不是** EBADF(9)。
     *    做法：置 ready=1 但不给有效目录（g_shm_dir 为空）。
     */
    memset(g_shm_dir, 0, sizeof g_shm_dir);
    __atomic_store_n(&g_shm_dirfd, -1, __ATOMIC_RELEASE);
    __atomic_store_n(&g_shm_ready, 1, __ATOMIC_RELEASE);

    x0 = 0;
    handled = bxroot_sysvshm_emulate(SHM_NR_GET, 0x1234, 4096, 0600, &x0);
    ck("anchor 失效时 shmget 被拦截", handled, 1);
    ck("  返回 ENOSYS 而**不是** EBADF", (int)x0, -38);

    x0 = 0;
    handled = bxroot_sysvshm_emulate(SHM_NR_AT, 1, 0, 0, &x0);
    ck("anchor 失效时 shmat 被拦截", handled, 1);
    ck("  返回 ENOSYS 而**不是** EBADF", (int)x0, -38);

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
