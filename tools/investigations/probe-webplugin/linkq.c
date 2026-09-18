#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>

static const char *LINK = "/root/.dsh/profiles/web/node_modules/dsh-device-shell-guide";
static const char *LINK2 = "/proc/self/root/root/.dsh/profiles/web/node_modules/dsh-device-shell-guide";

int main(void)
{
    char buf[PATH_MAX]; ssize_t n; struct stat st; char *rp;
    const char *paths[2]; int i;

    printf("== Q1. readlink 返回的内容对不对？ ==\n");
    for (i = 0, paths[0] = LINK, paths[1] = LINK2; i < 2; i++) {
        errno = 0; n = readlink(paths[i], buf, sizeof buf - 1);
        if (n >= 0) { buf[n] = 0; printf("  readlink(%s)\n      -> \"%s\"\n", paths[i], buf); }
        else printf("  readlink(%s)\n      -> ERR %d(%s)\n", paths[i], errno, strerror(errno));
    }

    printf("\n== Q2. realpath / stat / access 解析对不对？ ==\n");
    for (i = 0, paths[0] = LINK, paths[1] = LINK2; i < 2; i++) {
        errno = 0; rp = realpath(paths[i], buf);
        printf("  realpath(%s)\n      -> %s\n", paths[i], rp ? rp : strerror(errno));
        errno = 0;
        printf("  stat     -> %s", stat(paths[i], &st) == 0 ? "ok" : strerror(errno));
        if (st.st_ino) printf(" (ino=%llu)", (unsigned long long)st.st_ino);
        printf("\n");
        printf("  access   -> %s\n", access(paths[i], F_OK) == 0 ? "ok" : strerror(errno));
        printf("  lstat is symlink -> %s\n", (lstat(paths[i], &st) == 0 && S_ISLNK(st.st_mode)) ? "yes" : "no");
    }

    printf("\n== Q3. openat 的相对路径基准对不对？ ==\n");
    {
        /* 用 profile/node_modules 作为 dirfd，相对路径打开 dsh-device-shell-guide/package.json */
        int dfd = open("/root/.dsh/profiles/web/node_modules", O_RDONLY | O_DIRECTORY);
        printf("  open(dirfd=/root/.dsh/profiles/web/node_modules) = %d %s\n", dfd, dfd < 0 ? strerror(errno) : "ok");
        if (dfd >= 0) {
            int f = openat(dfd, "dsh-device-shell-guide/package.json", O_RDONLY);
            printf("  openat(dirfd, \"dsh-device-shell-guide/package.json\") = %d %s\n", f, f < 0 ? strerror(errno) : "ok");
            if (f >= 0) { n = read(f, buf, sizeof buf - 1); if (n > 0) { buf[n] = 0; printf("      读到 %zd 字节，首行: %.60s\n", n, buf); } close(f); }
            /* 再来一次：用 AT_SYMLINK_NOFOLLOW 的 fstatat */
            struct stat st2;
            printf("  fstatat(dirfd, \"dsh-device-shell-guide\", NOFOLLOW) -> %s\n",
                   fstatat(dfd, "dsh-device-shell-guide", &st2, AT_SYMLINK_NOFOLLOW) == 0 ? (S_ISLNK(st2.st_mode) ? "符号链接 ok" : "非链接?!") : strerror(errno));
            printf("  fstatat(dirfd, \"dsh-device-shell-guide\", 0)         -> %s\n",
                   fstatat(dfd, "dsh-device-shell-guide", &st2, 0) == 0 ? (S_ISDIR(st2.st_mode) ? "目录 ok" : "非目录?!") : strerror(errno));
            close(dfd);
        }
    }
    return 0;
}
