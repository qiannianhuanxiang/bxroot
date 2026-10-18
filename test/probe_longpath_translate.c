/*
 * 真机探针：裸 syscall 入口的长路径翻译不再被静默跳过
 *          （2026-10-18 修复 #3）
 *
 * --- 缺陷 ---
 * SG_SLOT_SIZE 原为 4096，而翻译层路径上限 MAX_PATH_LEN = PATH_MAX*2 = 8192。
 * bxroot_translate_path(src, tbuf, need) 的 need 恰好就是 SG_SLOT_SIZE，因此
 * **翻译后长度 >= 4096** 时它返回 -1；而调用侧是
 *
 *     if (tr > 0) *args[i] = tbuf;
 *
 * —— 返回 -1 就**静默跳过翻译**，把客户的 guest 路径原样交给内核，内核于是
 * 从**宿主根**解析。fail-open，方向危险且几乎不可察觉。
 *
 * --- 本探针的判别法 ---
 * 不需要在磁盘上造长路径。做法是让"rootfs 前缀"本身很长：
 *
 *   · 桩翻译的 rootfs 是一个 4000 字符的串；
 *   · 客户路径用**很短的**、宿主上**真实存在**的文件（/tmp/p3marker）；
 *   · 翻译后长度 = 4000 + len(短路径) > 4096。
 *
 *   修复前：translate 返回 -1 → 跳过翻译 → 内核看到 /tmp/p3marker
 *           → **成功** statx 到宿主文件          ← 缺陷复现
 *   修复后：槽位 8192 够用 → 翻译成功 → 内核看到 4000+ 字符路径
 *           → 超过 PATH_MAX → **ENAMETOOLONG**，绝不命中宿主文件
 *
 * 所以：rc == 0 即复现缺陷；rc != 0 才是修复后的正确行为。
 *
 * 另有一条前置断言：SG_SLOT_SIZE 必须 >= MAX_PATH_LEN（编译期常量检查）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/stat.h>

/* ------------------------------------------------------------------ */
/* 桩翻译：忠实复刻 bxroot_translate_path 的契约                       */
/*   · 相对路径 -> 0（不翻译）                                          */
/*   · 放不下   -> -1（真实实现同样如此）                               */
/*   · 放得下   -> 1 且 out = rootfs + path                             */
/* rootfs 用 4000 字符，把"翻译后超 4096"这个条件做出来。               */
/* ------------------------------------------------------------------ */
static char g_long_rootfs[4091];

static void init_long_rootfs(void)
{
    memset(g_long_rootfs, 'r', 4090);
    g_long_rootfs[0] = '/';
    g_long_rootfs[4090] = '\0';
}

/* 诊断记录：桩被调用时看到了什么、返回了什么 */
static char g_last_in[512];
static int  g_last_ret = -999;
static size_t g_last_outsz = 0;

int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    size_t need;

    if (path != NULL) {
        size_t n = strlen(path);
        snprintf(g_last_in, sizeof g_last_in, "%s", n < sizeof g_last_in ? path : "(too long)");
        g_last_outsz = out_size;
    }

    if (path == NULL || path[0] != '/') {
        g_last_ret = 0;
        return 0;                       /* 相对路径：与真实实现一致，不翻译 */
    }
    need = strlen(g_long_rootfs) + strlen(path) + 1;
    if (need > out_size) {
        g_last_ret = -1;
        return -1;                      /* 放不下：与真实实现一致 */
    }
    snprintf(out, out_size, "%s%s", g_long_rootfs, path);
    g_last_ret = 1;
    return 1;
}

/* fakeroot 桩：weak 符号需可解析（本探针不用其功能） */
int bxroot_fakeroot_res_ids(unsigned int *a, unsigned int *b, unsigned int *c,
                            unsigned int *d, unsigned int *e, unsigned int *f)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return 0; }
int bxroot_fakeroot_groups(unsigned int *g, int cap, int *cnt)
{ (void)g;(void)cap; if (cnt) *cnt = 0; return 0; }

#include "syscall_guard.c"

/* ------------------------------------------------------------------ */

int main(void)
{
    /*
     * 标记文件必须放在**宿主上也存在的路径**，否则"翻译被跳过"只会得到
     * ENOENT（宿主没有这个文件），看不出 fail-open。
     *
     * 本容器（proroot）里，只有以 PROROOT_ROOTFS 前缀开头的路径是**幂等
     * 透传**的（前缀已存在就不再翻译），因此那类路径在 guest 与宿主是
     * 同一个 inode。用 $PROROOT_ROOTFS/tmp/p3marker 最合适。
     */
    static char marker[1024];
    {
        const char *rf = getenv("PROROOT_ROOTFS");
        if (rf == NULL || rf[0] == '\0')
            rf = getenv("BXROOT_ROOTFS");
        if (rf == NULL || rf[0] == '\0') {
            printf("  [SKIP] 没有 PROROOT_ROOTFS/BXROOT_ROOTFS，无法定位宿主可见路径\n");
            return 0;
        }
        snprintf(marker, sizeof marker, "%s/tmp/p3marker", rf);
    }
    struct statx stx;
    struct stat sb;
    long rc;
    int fd;
    int fails = 0;

    printf("=== 裸 syscall 长路径翻译 真机探针 ===\n");
    printf("PATH_MAX=%d  MAX_PATH_LEN=%d  SG_SLOT_SIZE=%d\n\n",
           (int)PATH_MAX, (int)(PATH_MAX * 2), (int)SG_SLOT_SIZE);

    /*
     * 0) 前置：槽位必须 >= 翻译上限，否则本修复形同虚设。
     *    **只记录不早退** —— 这样在修复前的代码上还能继续跑到下面的
     *    运行时断言，一次看清"常量不对"和"运行时 fail-open"两个层面。
     */
    if ((size_t)SG_SLOT_SIZE < (size_t)(PATH_MAX * 2)) {
        fails++;
        printf("  [FAIL] SG_SLOT_SIZE(%d) < MAX_PATH_LEN(%d) —— 修复缺失\n",
               (int)SG_SLOT_SIZE, (int)(PATH_MAX * 2));
    } else {
        printf("  [ok]   SG_SLOT_SIZE >= MAX_PATH_LEN\n");
    }

    /* 1) 造一个**短**的宿主标记文件 */
    unlink(marker);
    fd = open(marker, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        printf("  [SKIP] 无法创建 %s：%s\n", marker, strerror(errno));
        return 0;
    }
    if (write(fd, "X", 1) != 1) { /* 忽略 */ }
    close(fd);

    if (stat(marker, &sb) != 0) {
        printf("  [SKIP] 无法 stat 标记文件\n");
        unlink(marker);
        return 0;
    }
    printf("  [ok]   宿主标记文件就位（路径长度 %d）\n", (int)strlen(marker));

    init_long_rootfs();
    printf("  [ok]   桩 rootfs 长度 %d（翻译后 %d，须 > %d 才有判别力）\n\n",
           (int)strlen(g_long_rootfs),
           (int)(strlen(g_long_rootfs) + strlen(marker)),
           (int)PATH_MAX);

    /* 2) 关键断言 */
    memset(&stx, 0, sizeof stx);
    errno = 0;
    rc = syscall(SYS_statx, AT_FDCWD, marker, 0, STATX_ALL, &stx);
    printf("  statx(短路径, 长前缀) -> rc=%ld errno=%d (%s)\n",
           rc, errno, strerror(errno));
    printf("  [诊断] 桩最近一次调用: in=\"%s\" outsz=%zu ret=%d\n",
           g_last_in, g_last_outsz, g_last_ret);

    if (rc == 0) {
        fails++;
        printf("  [FAIL] 成功了 —— 说明翻译被跳过，内核直接命中了**宿主**文件\n");
        printf("         这正是修复前的症状（fail-open）\n");
    } else if (errno == ENAMETOOLONG) {
        printf("  [ok]   ENAMETOOLONG —— 翻译已生效，超长路径被内核拒绝\n");
    } else {
        printf("  [ok]   未命中宿主文件（errno=%d）\n", errno);
    }

    /* 3) 对照：同一标记文件不经翻译时必须能 stat 到 */
    if (stat(marker, &sb) == 0) {
        printf("  [ok]   对照：直接 stat 标记文件成功（文件确实存在）\n");
    } else {
        fails++;
        printf("  [FAIL] 对照失败，探测无判别力\n");
    }

    unlink(marker);
    printf("\n----------------------------------------\n");
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
