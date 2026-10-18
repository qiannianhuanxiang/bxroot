/*
 * probe_shm_nofollow.c —— SysV SHM 段目录的 O_NOFOLLOW 有效性
 *
 * 背景（真实缺陷，2026-10-18 第五轮）：
 *   src/runtime/sysvshm.c 里 `#define K_O_NOFOLLOW 0400000` 是照抄
 *   asm-generic 的值。aarch64 上 O_NOFOLLOW 是 0100000，0400000 等于
 *   O_DIRECT|O_LARGEFILE —— 真正的 NOFOLLOW 位是 0。
 *
 *   后果不是"少一层加固"，而是**这一层的加固完全不存在**：段目录里
 *   出现一个符号链接 seg-<id>（guest 自己就能造，同 uid 可写），
 *   它的目标会被真的打开、mmap、写入。也就是说 shm 的段目录能从
 *   目录里"伸出去"，写穿到目录之外的任意文件。
 *
 *   syscall_guard.c 里同一个判据修过两次（0x800 → 00400000 都错过），
 *   注释里留了教训；sysvshm.c 这份是漏改的副本。本探针钉住它。
 *
 * 判据：
 *   1. K_O_NOFOLLOW 必须等于本平台的 O_NOFOLLOW（编译期拿不到就运行期比）。
 *   2. 段目录里放一个指向目录外的符号链接 seg-<id>，
 *      shm_open_seg() / shm_do_at() 必须**拒绝**（ELOOP），不得跟随。
 *   3. 反证（防止有人把判据改回去）：用旧的错值 0400000 打开同一个
 *      符号链接必须**成功** —— 说明探针测的确实是那个位，而不是
 *      别的机制顺带挡住了。
 *
 * 退出码 0 = 全部通过。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "../src/runtime/sysvshm.c"

static int g_fail;

static void ok(const char *what, int cond, const char *detail)
{
    printf("%s %s%s%s\n", cond ? "  ✅" : "  ❌", what,
           detail && *detail ? " —— " : "", detail ? detail : "");
    if (!cond) g_fail = 1;
}

static long mkfile(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return (long)n;
}

int main(void)
{
    char root[] = "/tmp/probe-nofollow-XXXXXX";
    char back[64];
    long fd, addr;
    int nf;

    /* 本平台的 O_NOFOLLOW —— 只用来对照，被测值来自 sysvshm.c */
    nf = O_NOFOLLOW;

    if (!mkdtemp(root)) { perror("mkdtemp"); return 2; }
    if (chdir(root) != 0) { perror("chdir"); return 2; }

    printf("[0] 常量核对\n");
    printf("     sysvshm.c K_O_NOFOLLOW = 0%o\n", K_O_NOFOLLOW);
    printf("     本平台 O_NOFOLLOW      = 0%o\n", nf);
    ok("K_O_NOFOLLOW 等于平台值", (int)K_O_NOFOLLOW == nf,
       (int)K_O_NOFOLLOW == nf ? "" : "错值等于没加 NOFOLLOW（0400000=O_DIRECT|O_LARGEFILE）");

    if (bxroot_sysvshm_init("shm") != 0) {
        printf("  ❌ bxroot_sysvshm_init 失败，后续无法进行\n");
        return 2;
    }

    printf("[1] 段目录里放符号链接 seg-777 -> ../victim\n");
    if (mkfile("victim", "SECRET-DATA") < 0) { perror("mkfile"); return 2; }
    if (symlink("../victim", "shm/seg-777") != 0) { perror("symlink"); return 2; }

    errno = 0;
    fd = shm_open_seg(777, 0);
    if (fd < 0) {
        /* 本文件的约定：失败返回 -errno（不是 -1 + errno），所以 ELOOP => -40 */
        printf("     shm_open_seg(777) = %ld (-errno=%ld, %s)\n", fd, -fd,
               strerror((int)-fd));
        ok("拒绝通过符号链接打开段", -fd == ELOOP, "应为 -ELOOP");
    } else {
        struct stat a, b;
        int same = 0;
        if (fstat(fd, &a) == 0 && stat("victim", &b) == 0)
            same = (a.st_dev == b.st_dev && a.st_ino == b.st_ino);
        printf("     shm_open_seg(777) = %ld —— 打开了\n", fd);
        ok("拒绝通过符号链接打开段", 0,
           same ? "打开的就是目录外的 victim（同 inode）" : "符号链接被跟随");
        close(fd);
    }

    printf("[2] 经 shm_do_at 映射并写入，不得改动目录外的文件\n");
    addr = shm_do_at(777, 0);
    if (addr > 0) {
        memcpy((void *)addr, "PWNED-DATA!", 11);
        munmap((void *)addr, 4096);
    }
    memset(back, 0, sizeof back);
    {
        int vf = open("victim", O_RDONLY);
        if (vf >= 0) { ssize_t r = read(vf, back, sizeof back - 1); (void)r; close(vf); }
    }
    printf("     shm_do_at(777) = %ld；victim 现在是 \"%s\"\n", addr, back);
    ok("目录外的文件未被写穿", strcmp(back, "SECRET-DATA") == 0, back);

    printf("[3] 反证：旧的错值 0400000 必须仍然跟随符号链接\n");
    {
        long bad = syscall(56 /* openat */, AT_FDCWD, "shm/seg-777", O_RDONLY | 0400000, 0);
        long good;
        errno = 0;
        good = syscall(56, AT_FDCWD, "shm/seg-777", O_RDONLY | nf, 0);
        printf("     openat(0400000) = %ld %s\n", bad,
               bad < 0 ? "(也拒绝了？判据可疑)" : "(跟随 —— 错值确实是空操作)");
        printf("     openat(0%o) = %ld errno=%d(%s)\n", nf, good, good < 0 ? errno : 0,
               good < 0 ? strerror(errno) : "ok");
        ok("错值 0400000 不设 NOFOLLOW 位（反证成立）", bad >= 0,
           "若这里也失败，说明探针测的不是这个位");
        if (bad >= 0) close((int)bad);
        {
            char d[64];
            snprintf(d, sizeof d, "平台值 0%o 应得 ELOOP", nf);
            ok(d, good < 0 && errno == ELOOP, "应得 ELOOP");
        }
        if (good >= 0) close((int)good);
    }

    printf("[4] 正常段仍然可用（不能为了安全把功能打死）\n");
    {
        int wf = open("shm/seg-778", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (wf < 0) {
            ok("普通段落盘", 0, "无法创建 seg-778");
        } else {
            char z[4096] = {0};
            ssize_t w = write(wf, z, sizeof z);
            (void)w;
            close(wf);
            long f2 = shm_open_seg(778, 0);
            ok("普通文件段仍能打开", f2 >= 0, "");
            if (f2 >= 0) close((int)f2);
        }
    }

    printf("\n%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail;
}
