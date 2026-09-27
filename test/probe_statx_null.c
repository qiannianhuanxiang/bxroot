/* probe_statx_null.c —— statx(fd, NULL, AT_EMPTY_PATH, …) 不得崩溃回归。
 *
 * 背景（实测缺陷，2026-09-28 压测子代理 B/文件系统折磨报出）：
 *   <bits/statx-generic.h> 把 statx 声明成 __nonnull((2,5))。gcc 据此在
 *   preload.c 的 statx 钩子函数体内**认定 path 恒非空**，把所有
 *   `path != NULL` 守卫整段删除（-fno-delete-null-pointer-checks 也挡不住
 *   这个基于 attribute 的假设）。于是合法调用
 *       statx(fd, NULL, AT_EMPTY_PATH, STATX_ALL, &buf)   （作用于 fd 自身）
 *   在 runtime 内解空指针 → 整进程 SIGSEGV。官方 glibc 对 NULL 返回 EFAULT。
 *   修法：钩子入口用 volatile 过一遍 path，让编译器无法证明其非空。
 *
 * 判据：statx(fd, NULL, AT_EMPTY_PATH) 必须**返回**（不崩溃）。返回 -1/EFAULT
 *   或 0（内核实现允许对 NULL+AT_EMPTY_PATH 直接按 fd 处理）都算通过 ——
 *   关键是进程不能被 SIGSEGV 打死。打印 DONE 才算走到了返回之后。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/stat.h>

int main(int argc, char **argv) {
    const char *target = argc > 1 ? argv[1] : "/etc/hostname";
    int fd = open(target, O_RDONLY);
    if (fd < 0) {
        printf("SETUP-FAIL open(%s) errno=%d\n", target, errno);
        return 2;
    }
    struct statx sx;
    memset(&sx, 0, sizeof sx);
    errno = 0;
    int r = statx(fd, NULL, AT_EMPTY_PATH, STATX_ALL, &sx);
    /* 走到这一行就说明没崩。r/errno 具体值不作强断言（EFAULT 最常见）。 */
    printf("DONE rc=%d errno=%d\n", r, errno);
    close(fd);
    return 0;
}
