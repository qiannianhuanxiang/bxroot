/*
 * 真机探针：SysV SHM 的段目录被删除后能自愈（2026-10-18 修复 S5）
 *
 * --- 缺陷 ---
 * shm_mkdir() 原来只有一句 `return shm_anchor_valid() ? 0 : -1;`
 * —— **只校验、从不重建**。而 bxroot_sysvshm_init() 只在构造函数跑一次，
 * g_shm_ready 一旦置 1 就永不回 0。于是段目录被删之后：
 *
 *     194..197 全部失败，且**无法自愈**，只能重启进程。
 *
 * 而内核从不因这种原因让 shmget/shmat 返回 EINVAL，客户程序行为不可预期。
 *
 * --- 本探针 ---
 * 直接调用内部接口，验证"删目录 → 调用 → 自愈 → 再删 → 再自愈"：
 *   1. init 到临时目录 → 成功
 *   2. 目录删掉 → shm_mkdir() 应能重建并返回 0
 *   3. 重建后 anchor 校验应恢复有效
 *   4. 连删两次同样能恢复（不是一次性的）
 *
 * 判别力：修复前第 2 步返回 -1 → RESULT: FAIL。
 *
 * 注意：本机内核无 SysV IPC，所以这里只测"目录自愈"这一层，
 * 不测真正的 shmget/shmat（那在本环境恒 ENOSYS，属环境限制）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "sysvshm.c"

static int fails, checks;

static void ck(const char *what, int got, int want)
{
    checks++;
    if (got != want) {
        fails++;
        printf("  [FAIL] %-50s got=%d want=%d\n", what, got, want);
    } else {
        printf("  [ok]   %-50s = %d\n", what, got);
    }
}

/* 递归删除一个小目录（只为探针使用，路径都是自己造的） */
static void rmrf(const char *p)
{
    char cmd[512];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", p);
    if (system(cmd) != 0) { /* 忽略 */ }
}

int main(void)
{
    /*
     * ★ 路径必须是**宿主可见**的（缺陷探针的环境约束，2026-10-18）★
     *
     * sysvshm.c 内部全部用**裸 svc**（不经过 libc 钩子），而裸 svc 的
     * 路径参数**不被路径翻译层处理**。在本容器（proroot）里，
     * `/tmp/x` 经 libc 会落到 rootfs 内，但裸 svc 会去宿主根找 —— 实测
     * 返回 -ENOENT。所以这里必须用 PROROOT_ROOTFS 前缀拼出宿主可见路径。
     */
    static char dir[512];
    static char base[512];
    const char *rf = getenv("PROROOT_ROOTFS");
    int round;

    if (rf == NULL || rf[0] == '\0') {
        printf("  [SKIP] 没有 PROROOT_ROOTFS，裸 svc 路径无法对齐\n");
        return 0;
    }
    snprintf(base, sizeof base, "%s/tmp/bxroot-s5-probe", rf);
    snprintf(dir, sizeof dir, "%s/shm", base);

    printf("=== SysV SHM 段目录自愈 探针 ===\n");
    printf("段目录: %s\n\n", dir);

    rmrf(base);
    memset(g_shm_dir, 0, sizeof g_shm_dir);

    /*
     * init 只 mkdir 最后一级（与生产用法一致：/tmp 已存在）。
     * 所以父目录要用 libc 先建好 —— 注意不能用裸 svc，理由见上面。
     */
    if (mkdir(base, 0700) != 0 && errno != EEXIST) {
        printf("  [SKIP] 建父目录失败: %s\n", strerror(errno));
        return 0;
    }

    /* 1) 首次初始化 */
    ck("init 到临时目录", bxroot_sysvshm_init(dir), 0);
    ck("anchor 有效", shm_anchor_valid(), 1);

    /* 2) 删掉目录，再走 shm_mkdir */
    for (round = 0; round < 3; round++) {
        rmrf(base);
        ck("删目录后 anchor 失效", shm_anchor_valid(), 0);
        /* 与生产一致：父目录存在，只有段目录被删 */
        if (mkdir(base, 0700) != 0 && errno != EEXIST) {
            printf("  [SKIP] 重建父目录失败\n");
            return 0;
        }

        {
            int rc = shm_mkdir();
            char what[128];
            snprintf(what, sizeof what, "第 %d 次删除后 shm_mkdir 自愈", round + 1);
            ck(what, rc, 0);
        }
        {
            char what[128];
            snprintf(what, sizeof what, "第 %d 次自愈后 anchor 恢复有效", round + 1);
            ck(what, shm_anchor_valid(), 1);
        }
    }

    rmrf(base);
    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
