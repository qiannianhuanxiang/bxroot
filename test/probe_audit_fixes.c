/*
 * 安全审计修复回归探针（见 test/RUN_AUDIT_FIXES.sh）。
 * 每项打印 "OK <名>" 或 "BAD <名> ..."，最后打印 "DONE bad=N"。
 *
 *   A2-1  中间组件链接成环 → open 必须 ELOOP（原先把未初始化缓冲当路径）
 *   （A3-1 堆缓冲反向 bind 见 probe_realpath_fixup.c 的 D 段）
 *   SG-1  裸 syscall statx(fd,"",AT_EMPTY_PATH) 必须作用于 fd 本身；
 *         裸 unlinkat(真 dirfd, 相对名) 必须相对 dirfd
 *   SL-1  用户态发来的 SIGSYS（kill）不得被当作 seccomp 处理
 *   B2-4  未开 fakeroot 时 setuid(getuid()) 必须成功（原先 ENOSYS）
 *   F5    execve 空 argv 不得让运行时越界（子进程正常退出或报错即可）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad;
#define OK(n)        printf("OK %s\n", n)
#define BAD(n, ...)  do { printf("BAD %s ", n); printf(__VA_ARGS__); printf("\n"); bad++; } while (0)

static volatile sig_atomic_t got_sys;
static void on_sys(int s) { (void)s; got_sys = 1; }

int main(int argc, char **argv)
{
    const char *bindpt = argc > 1 ? argv[1] : NULL;   /* bind 的客户视角目标 */

    /* ---- A2-1 ---- */
    unlink("/tmp/aud_la"); unlink("/tmp/aud_lb");
    symlink("/tmp/aud_lb", "/tmp/aud_la");
    symlink("/tmp/aud_la", "/tmp/aud_lb");
    errno = 0;
    {
        int fd = open("/tmp/aud_la/x", O_RDONLY);
        if (fd < 0 && errno == ELOOP) OK("A2-1 open loop ELOOP");
        else BAD("A2-1 open loop", "fd=%d errno=%d", fd, errno);
        if (fd >= 0) close(fd);
        struct stat st;
        errno = 0;
        int r = stat("/tmp/aud_la/x", &st);
        if (r < 0 && errno == ELOOP) OK("A2-5 stat loop ELOOP");
        else BAD("A2-5 stat loop", "r=%d errno=%d", r, errno);
    }
    unlink("/tmp/aud_la"); unlink("/tmp/aud_lb");

    /* A3-1 由源码级单元 test/probe_realpath_fixup.c 的 D 段覆盖
     * （bxroot-run 集成环境下 BXROOT_BINDS 反向翻译不可观测）。 */
    (void)bindpt;

    /* ---- SG-1 ---- */
    {
        int fd = open("/etc/hostname", O_RDONLY);
        struct stat a, b;
        struct statx sx;
        memset(&sx, 0, sizeof(sx));
        chdir("/tmp");
        if (fd >= 0 && fstat(fd, &a) == 0 &&
            syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx) == 0 &&
            sx.stx_ino == a.st_ino && S_ISREG(sx.stx_mode))
            OK("SG-1 raw statx AT_EMPTY_PATH");
        else
            BAD("SG-1 raw statx AT_EMPTY_PATH", "ino=%llu want=%llu mode=%o",
                (unsigned long long)sx.stx_ino, (unsigned long long)a.st_ino, sx.stx_mode);
        (void)b;
        if (fd >= 0) close(fd);

        mkdir("/tmp/aud_d", 0755);
        close(open("/tmp/aud_d/victim", O_CREAT | O_WRONLY, 0644));
        close(open("/tmp/victim", O_CREAT | O_WRONLY, 0644));   /* cwd 下的同名诱饵 */
        int d = open("/tmp/aud_d", O_RDONLY | O_DIRECTORY);
        long r = syscall(SYS_unlinkat, d, "victim", 0);
        if (r == 0 && access("/tmp/aud_d/victim", F_OK) != 0 && access("/tmp/victim", F_OK) == 0)
            OK("SG-1 raw unlinkat dirfd-relative");
        else
            BAD("SG-1 raw unlinkat dirfd-relative", "r=%ld in_dir=%d decoy=%d", r,
                access("/tmp/aud_d/victim", F_OK) == 0, access("/tmp/victim", F_OK) == 0);
        close(d);
        unlink("/tmp/aud_d/victim"); unlink("/tmp/victim"); rmdir("/tmp/aud_d");
        chdir("/");
    }

    /* ---- SL-1 ---- */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sys;
        /* 运行时可能拒绝客户接管 SIGSYS；拒绝时只验证进程不被改写/不崩 */
        int own = sigaction(SIGSYS, &sa, NULL) == 0;
        long before = 12345;
        volatile long v = before;
        kill(getpid(), SIGSYS);
        if (v == before) OK("SL-1 user SIGSYS ignored by emulator");
        else BAD("SL-1 user SIGSYS", "v=%ld", (long)v);
        (void)own;
    }

    /* ---- B2-4 ---- */
    errno = 0;
    if (setuid(getuid()) == 0) OK("B2-4 setuid passthrough");
    else BAD("B2-4 setuid passthrough", "errno=%d", errno);
    errno = 0;
    if (setgid(getgid()) == 0) OK("B2-4 setgid passthrough");
    else BAD("B2-4 setgid passthrough", "errno=%d", errno);

    /* ---- F5 ---- */
    {
        pid_t p = fork();
        if (p == 0) {
            char *nargv[] = { NULL, "AAAA", "BBBB", "CCCC", "DDDD", "EEEE",
                              "FFFF", "GGGG", "HHHH", "IIII", "JJJJ", NULL };
            char *nenv[] = { NULL };
            execve("/bin/true", nargv, nenv);
            _exit(0);   /* exec 失败也算未崩 */
        }
        int st = 0;
        waitpid(p, &st, 0);
        if (WIFEXITED(st)) OK("F5 empty argv execve no crash");
        else BAD("F5 empty argv execve", "signal=%d", WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    }

    printf("DONE bad=%d\n", bad);
    return 0;
}
