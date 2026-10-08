/*
 * 静态程序的路径类 syscall 探针（test/RUN_STATIC_ELF.sh 的 G 段）。
 * 在 /etc 下做 rename/link/symlink/unlink/mkdir/chmod/access/truncate/
 * stat/rmdir/renameat2；全部成功才输出 "fsops=OK"，否则输出第一个失败项。
 * 复现 ldconfig.real 写 /etc/ld.so.cache 时 rename 落到宿主只读 /etc 的缺陷。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STEP(name, expr) do { if ((expr) != 0) { \
    printf("fsops=FAIL %s: %s\n", name, strerror(errno)); return 1; } } while (0)

int main(void)
{
    struct stat st;
    int f = open("/etc/bx-fs-1", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (f < 0) { printf("fsops=FAIL open: %s\n", strerror(errno)); return 1; }
    close(f);
    STEP("rename",    rename("/etc/bx-fs-1", "/etc/bx-fs-2"));
    STEP("link",      link("/etc/bx-fs-2", "/etc/bx-fs-3"));
    STEP("symlink",   symlink("x", "/etc/bx-fs-4"));
    STEP("unlink",    unlink("/etc/bx-fs-3"));
    STEP("mkdir",     mkdir("/etc/bx-fs-d", 0755));
    STEP("chmod",     chmod("/etc/bx-fs-2", 0600));
    STEP("access",    access("/etc/bx-fs-2", F_OK));
    STEP("truncate",  truncate("/etc/bx-fs-2", 0));
    STEP("stat",      stat("/etc/bx-fs-2", &st));
    STEP("lstat",     lstat("/etc/bx-fs-4", &st));
    STEP("rmdir",     rmdir("/etc/bx-fs-d"));
    STEP("renameat2", renameat2(AT_FDCWD, "/etc/bx-fs-2", AT_FDCWD, "/etc/bx-fs-5", 0));
    puts("fsops=OK");
    return 0;
}
