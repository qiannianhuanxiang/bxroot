/*
 * seccomp 兜底层端到端：经真实 px_static_exec 装载一个 ET_EXEC 静态 guest，
 * guest 用「号经寄存器搬运」的 openat（mov x6,#56; mov x8,x6; svc），改写器默认不改。
 *
 *   off：BXROOT_SECCOMP_FALLBACK 未设 → svc 直达内核，/bxtest/hello 不翻译 → guest 退出码 2 (ENOENT)
 *   on ：BXROOT_SECCOMP_FALLBACK=1   → 陷阱翻译 → guest 打印文件内容、退出码 0
 *
 * guest 源码在 test/data/sfb_guest.S：
 *   gcc -nostdlib -static -no-pie -o /tmp/sfb_guest test/data/sfb_guest.S
 * 构建：cd test && gcc -std=gnu11 -O1 -ffixed-x18 -o /tmp/tsfbe2e test_seccomp_fallback_e2e.c -ldl
 * 运行：/tmp/tsfbe2e /tmp/sfb_guest
 */
#define _GNU_SOURCE
#include "../src/runtime/static_exec.c"
#include <sys/wait.h>

static char g_root[64];

/* /bxtest/<x> → <g_root>/<x>（g_root 是 /proc/self/fd/N：容器里裸 svc 也能解析） */
int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    int n;

    if (strncmp(path, "/bxtest/", 8) != 0)
        return 0;
    n = snprintf(out, out_size, "%s/%s", g_root, path + 8);
    return (n > 0 && (size_t)n < out_size) ? n : 0;
}

static int run(const char *host, int on, char *out, size_t outn)
{
    int pfd[2], st = 0;
    pid_t c;
    ssize_t n, got = 0;

    if (pipe(pfd) != 0)
        return -1;
    c = fork();
    if (c == 0) {
        char *argv[] = { "sfb_guest", NULL };
        char *env_on[] = { "BXROOT_SECCOMP_FALLBACK=1", NULL };
        char *env_off[] = { "X=1", NULL };

        dup2(pfd[1], 1);
        close(pfd[0]);
        close(pfd[1]);
        px_static_exec(host, "sfb_guest", argv, on ? env_on : env_off);
        fprintf(stderr, "px_static_exec returned errno=%d\n", errno);
        _exit(98);
    }
    close(pfd[1]);
    while (got < (ssize_t)outn - 1 && (n = read(pfd[0], out + got, outn - 1 - got)) > 0)
        got += n;
    out[got] = '\0';
    close(pfd[0]);
    waitpid(c, &st, 0);
    return st;
}

int main(int argc, char **argv)
{
    char dir[64], path[128], host[64], out[128];
    int dfd, gfd, fd, st, fails = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <sfb_guest>\n", argv[0]);
        return 2;
    }
    snprintf(dir, sizeof dir, "/tmp/sfbe2e-%d", (int)getpid());
    mkdir(dir, 0700);
    dfd = open(dir, O_RDONLY | O_DIRECTORY);
    gfd = open(argv[1], O_RDONLY);
    if (dfd < 0 || gfd < 0) { perror("open"); return 2; }
    snprintf(g_root, sizeof g_root, "/proc/self/fd/%d", dfd);
    snprintf(host, sizeof host, "/proc/self/fd/%d", gfd);
    snprintf(path, sizeof path, "%s/hello", dir);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "sfb-e2e\n", 8) != 8) { perror("setup"); return 2; }
    close(fd);

    st = run(host, 0, out, sizeof out);
    printf("  off: st=%x out=\"%s\"\n", st, out);
    if (!(WIFEXITED(st) && WEXITSTATUS(st) == 2 && out[0] == '\0')) {
        printf("  FAIL: off should leave svc untranslated (exit 2 = ENOENT)\n");
        fails++;
    }
    st = run(host, 1, out, sizeof out);
    printf("  on:  st=%x out=\"%s\"\n", st, out);
    if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0 && strcmp(out, "sfb-e2e\n") == 0)) {
        printf("  FAIL: on should trap+translate and print file\n");
        fails++;
    }
    unlink(path);
    close(dfd);
    close(gfd);
    rmdir(dir);
    printf("%s (%d failures)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}
