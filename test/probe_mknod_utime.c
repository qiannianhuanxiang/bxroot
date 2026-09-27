/* probe_mknod_utime.c —— mkfifo/mknod/utime/utimes 路径翻译 + errno 归一化。
 *
 * 背景（实测缺陷，2026-09-28 压测子代理 B/E）：
 *   ① mkfifo/mknod/utime/utimes 的**路径版**此前完全未 hook → 走未翻译的
 *      字面 guest 路径 → rootfs 内任何路径 ENOENT（基线正常创建/设时间）。
 *   ② 非特权用户 mknod 字符/块设备，POSIX 与官方基线恒为 EPERM(1)；
 *      bxroot 若照透翻译后落点内核 errno 会返回 EACCES/ENOENT/EROFS，
 *      父目录明明存在却报 ENOENT，误导 `errno==EPERM ? skip` 的程序。
 *      修：设备节点非特权失败统一归一化成 EPERM。
 *
 * 用法：probe <可写工作目录>（该目录须在 rootfs 内、可写）。
 * 输出以 KEY=VAL 行，判据脚本据此断言。所有临时文件建后即删。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <utime.h>
#include <sys/time.h>

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    char fifo[512], reg[512], dev[512];
    snprintf(fifo, sizeof fifo, "%s/pm_fifo", dir);
    snprintf(reg,  sizeof reg,  "%s/pm_reg",  dir);
    snprintf(dev,  sizeof dev,  "%s/pm_dev",  dir);
    unlink(fifo); unlink(reg); unlink(dev);

    /* ① mkfifo：应成功且是 FIFO。 */
    errno = 0;
    int r = mkfifo(fifo, 0644);
    struct stat s;
    int isfifo = (r == 0 && stat(fifo, &s) == 0 && S_ISFIFO(s.st_mode));
    printf("MKFIFO rc=%d errno=%d isfifo=%d\n", r, errno, isfifo);

    /* ② utime：先建普通文件，再设时间戳，读回验证。 */
    FILE *f = fopen(reg, "w"); if (f) { fputs("x", f); fclose(f); }
    struct utimbuf ut = { 1000000000, 1000000000 };
    errno = 0;
    r = utime(reg, &ut);
    long mt = (stat(reg, &s) == 0) ? (long)s.st_mtime : -1;
    printf("UTIME rc=%d errno=%d mtime=%ld\n", r, errno, mt);

    /* ③ utimes：另设一组时间。 */
    struct timeval tv[2] = {{1200000000,0},{1200000000,0}};
    errno = 0;
    r = utimes(reg, tv);
    long mt2 = (stat(reg, &s) == 0) ? (long)s.st_mtime : -1;
    printf("UTIMES rc=%d errno=%d mtime=%ld\n", r, errno, mt2);

    /* ④ mknod 字符设备：非特权应 EPERM（归一化后）。 */
    errno = 0;
    r = mknod(dev, S_IFCHR | 0644, makedev(1, 3));
    printf("MKNOD_CHR rc=%d errno=%d\n", r, errno);

    unlink(fifo); unlink(reg); unlink(dev);
    printf("DONE\n");
    return 0;
}
