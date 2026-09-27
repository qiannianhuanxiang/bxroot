/*
 * 沙箱边界爆破探针（BXR-ESC-4，2026-09-28 更狠的对抗性测试）。
 *
 * 覆盖 9a2d539（ESC-1/2/3）**没测到**的入口与组合：相对路径 `..`、
 * *at 家族用指向 rootfs 根/子目录的 dirfd + 相对 `..`、AT_FDCWD + 相对
 * `..`，逐个 glibc 入口验证 `..` 是否在 guest 根处夹紧。
 *
 * 【测试布局】rootfs 是宿主某目录的**子目录**，canary/decoy 放在
 * rootfs 的**上一层**（宿主视角）。探针用 dirfd=rootfs 根 或 chdir("/")
 * 后的相对 `../X`。正确的沙箱把 `..` 在 guest 根夹紧：`../canary` 变成
 * guest `/canary`（不存在 → ENOENT），**绝不**碰到宿主父目录的 canary。
 *
 * 【判据 —— 被测对象自己的痕迹】
 *   读类（open/openat/access/stat/…）：只有**读到 CANARY 字节**才算逃逸；
 *   元数据类（faccessat/fstatat/chmod/chown/utimensat 对 ../canary）：
 *     返回 0 即逃逸（rootfs 内没有 /canary，成功只可能命中父目录的）；
 *   删除类（unlink/unlinkat ../decoy）：返回 0 即逃逸（rootfs 内无 /decoy）；
 *   创建/改名/硬链接类（mkdir/openat O_CREAT/rename/link/symlink → ../X）：
 *     **由外层脚本审计宿主父目录**是否多出文件，探针只报告 rc。
 *
 * argv[1] = 宿主父目录（canary 所在，rootfs 之上一层）——仅用于读类构造
 *           里"能不能读到 CANARY"的判定；相对构造不需要它。
 *
 * 退出码：逃逸计数（0 = 未逃逸）。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int escapes;
static int rd_canary(int fd)
{
    char b[64] = {0};
    if (fd < 0) return 0;
    int n = read(fd, b, 63);
    close(fd);
    return n > 0 && strstr(b, "CANARY") != NULL;
}
/* cond 为真 = 逃逸 */
#define R(name, cond)                                                    \
    do {                                                                 \
        if (cond) { printf("ESCAPE %s\n", name); escapes++; }            \
        else       printf("clamp  %-32s (errno=%d)\n", name, errno);     \
    } while (0)

int main(int argc, char **argv)
{
    (void)argv;
    struct stat st;
    char rl[512];
    int d = open("/", O_RDONLY | O_DIRECTORY);      /* rootfs 根 */

    printf("== A) 普通相对 `..`（chdir 到 guest 根）==\n");
    if (chdir("/") != 0) { perror("chdir /"); return 99; }
    R("open   ../canary",     rd_canary(open("../canary", O_RDONLY)));
    R("access ../canary",     access("../canary", R_OK) == 0);
    R("stat   ../canary",     stat("../canary", &st) == 0);
    R("lstat  ../canary",     lstat("../canary", &st) == 0);
    R("chmod  ../canary",     chmod("../canary", 0644) == 0);
    R("chown  ../canary",     chown("../canary", 0, 0) == 0);
    R("truncate ../canary",   truncate("../canary", 0) == 0);
    R("unlink ../decoy",      unlink("../decoy") == 0);
    R("rmdir  ../rmtgt",      rmdir("../rmtgt") == 0);
    R("readlink ../slk",      readlink("../slk", rl, sizeof rl) > 0);
    { char rb[4096]; R("realpath ../canary", realpath("../canary", rb) != NULL &&
                       strstr(rb, argv[1] ? argv[1] : "\x01") != NULL); }
    R("a/../../../canary",    rd_canary(open("a/../../../../../../../canary", O_RDONLY)));

    printf("== B) *at 家族：dirfd=rootfs 根 + 相对 `..` ==\n");
    R("openat  read ../canary", rd_canary(openat(d, "../canary", O_RDONLY)));
    R("faccessat ../canary",    faccessat(d, "../canary", R_OK, 0) == 0);
    R("faccessat2 ../canary",   syscall(SYS_faccessat2, d, "../canary", R_OK, 0) == 0);
    R("fstatat ../canary",      fstatat(d, "../canary", &st, 0) == 0);
    R("statx   ../canary",      syscall(SYS_statx, d, "../canary", 0, 0, &st) == 0);
    R("fchmodat ../canary",     fchmodat(d, "../canary", 0644, 0) == 0);
    R("fchownat ../canary",     fchownat(d, "../canary", 0, 0, 0) == 0);
    R("utimensat ../canary",    utimensat(d, "../canary", NULL, 0) == 0);
    R("unlinkat ../decoy",      unlinkat(d, "../decoy", 0) == 0);
    R("readlinkat ../slk",      readlinkat(d, "../slk", rl, sizeof rl) > 0);

    printf("== C) AT_FDCWD + 相对 `..`（cwd=guest 根）==\n");
    R("AT_FDCWD faccessat ../canary", faccessat(AT_FDCWD, "../canary", R_OK, 0) == 0);
    R("AT_FDCWD fchmodat ../canary",  fchmodat(AT_FDCWD, "../canary", 0644, 0) == 0);
    R("AT_FDCWD fchownat ../canary",  fchownat(AT_FDCWD, "../canary", 0, 0, 0) == 0);
    R("AT_FDCWD utimensat ../canary", utimensat(AT_FDCWD, "../canary", NULL, 0) == 0);
    R("AT_FDCWD unlinkat ../decoy",   unlinkat(AT_FDCWD, "../decoy", 0) == 0);
    R("AT_FDCWD openat read ../canary", rd_canary(openat(AT_FDCWD, "../canary", O_RDONLY)));

    printf("DONE escapes=%d\n", escapes);
    return escapes;
}
