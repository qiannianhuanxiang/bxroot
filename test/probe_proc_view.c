/*
 * /proc 视角探针（由 test/RUN_PROC_VIEW.sh 驱动，在 bxroot-run 下运行）
 *
 * 逐行输出 "key=value"，由脚本按期望值断言。覆盖：
 *   - readlink 小缓冲截断（不得泄漏宿主前缀）
 *   - fork 子进程后从父进程读 /proc/<childpid>/{exe,cwd,root,fd/N}
 *   - readlinkat(dirfd=/proc/self 或 /proc/<child>, "exe"/"cwd")
 *   - stat/fstatat/statx 跟随 /proc/self/exe（stat -L 语义）
 *   - open 经 /proc/self/root/... 与 /proc/self/cwd/... 中间组件
 *   - execv("/proc/self/exe") 自重执行
 *   - socket:[N] 形态原样保留
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void rl(const char *key, const char *p)
{
    char b[4096];
    ssize_t n = readlink(p, b, sizeof b - 1);
    if (n < 0) { printf("%s=ERR%d\n", key, errno); return; }
    b[n] = '\0';
    printf("%s=%s\n", key, b);
}

static void rl_small(const char *key, const char *p, size_t sz)
{
    char b[4096];
    ssize_t n;
    memset(b, 0, sizeof b);
    n = readlink(p, b, sz);
    if (n < 0) { printf("%s=ERR%d\n", key, errno); return; }
    printf("%s=%.*s|n=%zd\n", key, (int)n, b, n);
}

static void rlat(const char *key, int dirfd, const char *p)
{
    char b[4096];
    ssize_t n = readlinkat(dirfd, p, b, sizeof b - 1);
    if (n < 0) { printf("%s=ERR%d\n", key, errno); return; }
    b[n] = '\0';
    printf("%s=%s\n", key, b);
}

int main(int argc, char **argv)
{
    char p[256];
    pid_t c;

    if (argc > 1 && strcmp(argv[1], "--reexeced") == 0) {
        printf("reexec=ok\n");
        return 0;
    }

    /* 子进程：切到 /etc，打开 /etc/hostname 为 fd 3，挂起等待。
     * 用管道同步"子进程已就位"—— 固定 usleep 在 RUN_ALL 的负载下会
     * 抢在子进程 chdir/open 之前读 /proc/<pid>/cwd（实测偶发 1 项红）。 */
    {
        int pfd[2];
        char sync_ch;
        if (pipe(pfd) != 0) { printf("pipe=ERR%d\n", errno); return 1; }
        c = fork();
        if (c == 0) {
            int fd;
            close(pfd[0]);
            if (chdir("/etc") != 0) _exit(3);
            fd = open("/etc/hostname", O_RDONLY);
            if (fd != 3) { dup2(fd, 3); }
            if (write(pfd[1], "R", 1) != 1) _exit(4);
            close(pfd[1]);
            pause();
            _exit(0);
        }
        close(pfd[1]);
        if (read(pfd[0], &sync_ch, 1) != 1) { printf("child_sync=ERR\n"); }
        close(pfd[0]);
    }

    /* --- 自身 --- */
    rl("self_exe", "/proc/self/exe");
    rl("self_cwd", "/proc/self/cwd");
    rl("self_root", "/proc/self/root");
    rl("tself_exe", "/proc/thread-self/exe");
    rl_small("self_cwd_b16", "/proc/self/cwd", 16);
    rl_small("self_exe_b8", "/proc/self/exe", 8);

    /* --- 子进程（/proc/<数字pid>/…）--- */
    snprintf(p, sizeof p, "/proc/%d/exe", (int)c);  rl("child_exe", p);
    snprintf(p, sizeof p, "/proc/%d/cwd", (int)c);  rl("child_cwd", p);
    snprintf(p, sizeof p, "/proc/%d/root", (int)c); rl("child_root", p);
    snprintf(p, sizeof p, "/proc/%d/fd/3", (int)c); rl("child_fd3", p);
    snprintf(p, sizeof p, "/proc/%d/cwd", (int)c);  rl_small("child_cwd_b3", p, 3);

    /* --- readlinkat + dirfd --- */
    {
        int d = open("/proc/self", O_RDONLY | O_DIRECTORY);
        rlat("at_self_exe", d, "exe");
        rlat("at_self_cwd", d, "cwd");
        close(d);
        snprintf(p, sizeof p, "/proc/%d", (int)c);
        d = open(p, O_RDONLY | O_DIRECTORY);
        rlat("at_child_exe", d, "exe");
        rlat("at_child_cwd", d, "cwd");
        close(d);
        /* 非 /proc 目录下的裸 "exe" 不得被伪装（此前对任何 dirfd 都伪装） */
        d = open("/tmp", O_RDONLY | O_DIRECTORY);
        rlat("at_tmp_exe", d, "exe");
        close(d);
    }

    /* --- socket 形态原样 --- */
    {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        snprintf(p, sizeof p, "/proc/self/fd/%d", s);
        {
            char b[256];
            ssize_t n = readlink(p, b, sizeof b - 1);
            if (n > 0) { b[n] = '\0'; printf("sock_fd=%.7s\n", b); }
            else printf("sock_fd=ERR%d\n", errno);
        }
        close(s);
    }

    /* --- 跟随 exe（stat -L 语义）--- */
    {
        struct stat st, ref;
        struct statx sx;
        char me[4096];
        ssize_t mn = readlink("/proc/self/exe", me, sizeof me - 1);
        int have_ref = 0;
        if (mn > 0) { me[mn] = '\0'; have_ref = (stat(me, &ref) == 0); }
        /* 参照：readlink 给出的 guest 路径本身的 inode（两条 API 必须自洽） */
        printf("stat_exe=%d\n", stat("/proc/self/exe", &st) == 0 && have_ref &&
               st.st_ino == ref.st_ino && st.st_dev == ref.st_dev);
        printf("fstatat_exe=%d\n",
               fstatat(AT_FDCWD, "/proc/self/exe", &st, 0) == 0 && have_ref &&
               st.st_ino == ref.st_ino);
        printf("statx_exe=%d\n",
               statx(AT_FDCWD, "/proc/self/exe", 0, STATX_BASIC_STATS, &sx) == 0 &&
               have_ref && sx.stx_ino == ref.st_ino);
        printf("lstat_exe_islnk=%d\n",
               lstat("/proc/self/exe", &st) == 0 && S_ISLNK(st.st_mode));
        snprintf(p, sizeof p, "/proc/%d/exe", (int)c);
        printf("stat_child_exe=%d\n", stat(p, &st) == 0 && have_ref &&
               st.st_ino == ref.st_ino);
    }

    /* --- open 经魔法链接中间组件 / 叶子 --- */
    {
        char b[128];
        int fd;
        ssize_t n;

        fd = open("/proc/self/root/etc/hostname", O_RDONLY);
        n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
        if (n > 0) { b[n] = '\0'; b[strcspn(b, "\n")] = '\0'; printf("open_root_etc=%s\n", b); }
        else printf("open_root_etc=ERR%d\n", errno);
        if (fd >= 0) close(fd);

        snprintf(p, sizeof p, "/proc/%d/cwd/hostname", (int)c);
        fd = open(p, O_RDONLY);
        n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
        if (n > 0) { b[n] = '\0'; b[strcspn(b, "\n")] = '\0'; printf("open_child_cwd=%s\n", b); }
        else printf("open_child_cwd=ERR%d\n", errno);
        if (fd >= 0) close(fd);

        fd = open("/proc/self/exe", O_RDONLY);
        n = fd >= 0 ? read(fd, b, 4) : -1;
        printf("open_exe_elf=%d\n", n == 4 && memcmp(b, "\177ELF", 4) == 0);
        if (fd >= 0) {
            struct stat st, ref;
            char me[4096];
            ssize_t mn = readlink("/proc/self/exe", me, sizeof me - 1);
            if (mn > 0) me[mn] = '\0';
            printf("open_exe_same=%d\n", mn > 0 && fstat(fd, &st) == 0 &&
                   stat(me, &ref) == 0 && st.st_ino == ref.st_ino);
            close(fd);
        } else {
            printf("open_exe_same=0\n");
        }

        fd = open("/proc/self/exe", O_RDONLY | O_NOFOLLOW);
        printf("open_exe_nofollow_eloop=%d\n", fd < 0 && errno == ELOOP);
        if (fd >= 0) close(fd);
    }

    kill(c, SIGTERM);              /* 精确 pid 回收，绝不按名字杀 */
    waitpid(c, NULL, 0);
    fflush(stdout);

    /* --- 自重执行 --- */
    {
        char *av[] = { argv[0], "--reexeced", NULL };
        execv("/proc/self/exe", av);
        printf("reexec=ERR%d\n", errno);
    }
    return 0;
}
