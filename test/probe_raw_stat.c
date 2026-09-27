/* probe_raw_stat.c —— 裸 syscall(newfstatat/statx) 的 nlink/属主伪装回归。
 *
 * 背景（压测子代理 A 报出、深挖子代理定位，2026-09-28）：
 *   node/libuv、静态链接程序绕过 libc 的 stat 符号钩子，直接发
 *   syscall(SYS_newfstatat=79) / syscall(SYS_statx=291)。这条路只经
 *   syscall_guard.c，而 guard 此前对 stat 家族**只翻译路径、不做结果
 *   伪装**：
 *     ① l2s 用带 .l2s. 前缀的符号链接模拟硬链接，内核对 symlink 恒报
 *        nlink=1，真实链长在 .cnt 里。libc 符号钩子会 l2s_rt_patch_stat
 *        改回链长，但裸 79 没有 l2s 补丁 → nlink 停在 1。
 *     ② rootfs 文件磁盘真实属主是 Android app uid（如 10665）。fakeroot
 *        OWNER 启发式把它归一成 0，但只在 libc 符号钩子里调，裸 syscall
 *        入口从不触发 → uid 停在 10665。
 *   修：syscall_guard 给 79 补 l2s nlink + fakeroot 属主，给 291 补
 *   fakeroot 属主，带 __thread 重入守卫防 probe 递归。
 *
 * 判据：对一个有 3 个硬链接的文件，裸 newfstatat 必须报 nlink=3、
 *   uid=0、gid=0（与 libc stat 符号钩子、与官方基线一致）。
 * 用法：probe <工作目录>（须在 rootfs 内、可写）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    char a[512], b[512], c[512];
    snprintf(a, sizeof a, "%s/rs_a", dir);
    snprintf(b, sizeof b, "%s/rs_b", dir);
    snprintf(c, sizeof c, "%s/rs_c", dir);
    unlink(a); unlink(b); unlink(c);

    FILE *f = fopen(a, "w");
    if (!f) { printf("SETUP-FAIL fopen errno=%d\n", errno); return 2; }
    fputs("0123456789", f); fclose(f);
    if (link(a, b) != 0 || link(a, c) != 0) {
        printf("SETUP-FAIL link errno=%d\n", errno);
        unlink(a); unlink(b); unlink(c);
        return 2;
    }

    /* libc 符号钩子入口（对照基准）。 */
    struct stat sc;
    memset(&sc, 0, sizeof sc);
    stat(a, &sc);
    printf("LIBC   nlink=%lu uid=%d gid=%d\n",
           (unsigned long)sc.st_nlink, sc.st_uid, sc.st_gid);

    /* 裸 newfstatat(79) —— 缺陷入口。 */
    struct stat sr;
    memset(&sr, 0, sizeof sr);
    syscall(SYS_newfstatat, AT_FDCWD, a, &sr, 0);
    printf("RAW79  nlink=%lu uid=%d gid=%d\n",
           (unsigned long)sr.st_nlink, sr.st_uid, sr.st_gid);

    int ok = (sr.st_nlink == 3 && sr.st_uid == 0 && sr.st_gid == 0);
    printf("%s\n", ok ? "RAWSTAT-OK" : "RAWSTAT-BAD");

    unlink(a); unlink(b); unlink(c);
    return ok ? 0 : 1;
}
