/*
 * 沙箱边界爆破探针 #2（BXR-ESC-4 写侧，2026-09-28）。
 *
 * 专测"创建/改名/硬链接/符号链接到 rootfs 之外"的构造。这类无法只看
 * 返回值判定（在 rootfs 内建 /X 也返回 0），必须由外层脚本审计**宿主
 * 父目录**是否多出文件。本探针只负责发起操作并打印 rc，全部落点都用
 * `../NAME`（相对 rootfs 根）。
 *
 * 命名约定：所有对外写入都用前缀 EPWN_，脚本据此在父目录里找痕迹。
 * 源文件放在 rootfs 内的 tmp/ 下。
 *
 * 退出码 0（判定交给脚本审计父目录）。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define P(name, expr) printf("%-34s rc=%d errno=%d\n", name, (expr), errno)

static void mk_src(int d, const char *rel)
{
    int f = openat(d, rel, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (f >= 0) close(f);
}

int main(void)
{
    int d = open("/", O_RDONLY | O_DIRECTORY);      /* rootfs 根 */

    if (chdir("/") != 0) { perror("chdir /"); return 99; }

    printf("== 写侧构造：全部目标 ../EPWN_*（应落在 rootfs 内，不得进父目录）==\n");

    /* 普通相对 */
    P("mkdir  ../EPWN_mk",  mkdir("../EPWN_mk", 0755));
    P("symlink x ../EPWN_sl", symlink("x", "../EPWN_sl"));
    { int f = open("../EPWN_oc", O_WRONLY | O_CREAT, 0644); P("open O_CREAT ../EPWN_oc", f); if (f >= 0) close(f); }
    mk_src(d, "tmp/src_rn");
    P("rename tmp/src_rn ../EPWN_rn", rename("tmp/src_rn", "../EPWN_rn"));
    mk_src(d, "tmp/src_ln");
    P("link tmp/src_ln ../EPWN_ln", link("tmp/src_ln", "../EPWN_ln"));

    /* *at 家族，dirfd=rootfs 根 */
    P("mkdirat ../EPWN_mkat", mkdirat(d, "../EPWN_mkat", 0755));
    P("symlinkat x ../EPWN_slat", symlinkat("x", d, "../EPWN_slat"));
    { int f = openat(d, "../EPWN_ocat", O_WRONLY | O_CREAT, 0644); P("openat O_CREAT ../EPWN_ocat", f); if (f >= 0) close(f); }
    mk_src(d, "tmp/src_rnat");
    P("renameat tmp/src_rnat ../EPWN_rnat", renameat(d, "tmp/src_rnat", d, "../EPWN_rnat"));
    mk_src(d, "tmp/src_rn2at");
    P("renameat2 tmp/src_rn2at ../EPWN_rn2at", (int)syscall(SYS_renameat2, d, "tmp/src_rn2at", d, "../EPWN_rn2at", 0u));
    mk_src(d, "tmp/src_lnat");
    P("linkat tmp/src_lnat ../EPWN_lnat", linkat(d, "tmp/src_lnat", d, "../EPWN_lnat", 0));

    printf("DONE\n");
    return 0;
}
