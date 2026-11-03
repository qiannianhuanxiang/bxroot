/*
 * seccomp 兜底层性能基准。所有测量都在 fork 出的子进程里（过滤器不可撤销），
 * 同一子进程内先测「装过滤器前」，再装，测「装过滤器后」，避免跨进程状态差异。
 *
 *   1. 非路径调用 getppid（libc，范围外）            前 / 后  → 过滤器对普通调用的代价
 *   2. 路径调用 newfstatat（libc，范围外）           前 / 后  → 过滤器对范围外路径调用的代价
 *   3. 范围内 openat+close 走陷阱翻译                         → 兜底路径代价
 *      对照：范围外直接 openat+close 已翻译的路径              → 相当于改写站点（跳板开销≈0，见 test_svc_all）
 *   4. 范围内 rt_sigprocmask（处理器内纯模拟，不发真 syscall）  → 陷阱本身的固定开销
 *
 * 构建：cd test && gcc -std=gnu11 -O2 -ffixed-x18 -o /tmp/bsfb bench_seccomp_fallback.c -ldl
 * 运行：/tmp/bsfb [轮数，默认 5]   每轮输出一行，最后输出中位数
 */
#define _GNU_SOURCE
#include "../src/runtime/static_exec.c"
#include <sys/wait.h>
#include <time.h>

static char g_root[64];

int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    int n;

    if (strncmp(path, "/bxtest/", 8) != 0)
        return 0;
    n = snprintf(out, out_size, "%s/%s", g_root, path + 8);
    return (n > 0 && (size_t)n < out_size) ? n : 0;
}

typedef long (*sc_fn)(long, long, long, long, long, long, long);
static const uint32_t stub_code[] = { 0xaa0603e8u, SX_SVC_INSN, 0xd65f03c0u };

static long nsec(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

enum { M_PPID_PRE, M_PPID_POST, M_STAT_PRE, M_STAT_POST, M_TRAP_OPEN, M_DIRECT_OPEN, M_TRAP_MASK, M_N };
static const char *names[M_N] = {
    "getppid 装前", "getppid 装后", "fstatat 装前", "fstatat 装后",
    "陷阱 openat+close", "直接 openat+close", "陷阱 sigprocmask",
};

static void one_round(sc_fn G, unsigned long lo, unsigned long hi, const char *real, long out[M_N])
{
    const int N = 300000, P = 100000, T = 20000;
    struct stat st;
    long t0;
    int i;

    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(px_static_dyn_tls));

    t0 = nsec(); for (i = 0; i < N; i++) getppid();               out[M_PPID_PRE] = (nsec() - t0) / N;
    t0 = nsec(); for (i = 0; i < P; i++) fstatat(AT_FDCWD, real, &st, 0); out[M_STAT_PRE] = (nsec() - t0) / P;

    if (sfb_install_handler() != 0 || sfb_install_filter(lo, hi) != 0) {
        fprintf(stderr, "install failed\n");
        _exit(3);
    }

    t0 = nsec(); for (i = 0; i < N; i++) getppid();               out[M_PPID_POST] = (nsec() - t0) / N;
    t0 = nsec(); for (i = 0; i < P; i++) fstatat(AT_FDCWD, real, &st, 0); out[M_STAT_POST] = (nsec() - t0) / P;
    t0 = nsec();
    for (i = 0; i < T; i++) {
        long fd = G(-100, (long)"/bxtest/hello", O_RDONLY, 0, 0, 0, 56);
        if (fd >= 0) close((int)fd);
    }
    out[M_TRAP_OPEN] = (nsec() - t0) / T;
    t0 = nsec();
    for (i = 0; i < T; i++) {
        long fd = sx_sc6(56, -100, (long)real, O_RDONLY, 0, 0, 0);
        if (fd >= 0) close((int)fd);
    }
    out[M_DIRECT_OPEN] = (nsec() - t0) / T;
    t0 = nsec();
    for (i = 0; i < T; i++) {
        unsigned long m = 0;
        G(0, 0, (long)&m, 8, 0, 0, 135);
    }
    out[M_TRAP_MASK] = (nsec() - t0) / T;
}

static int cmpl(const void *a, const void *b)
{
    long x = *(const long *)a, y = *(const long *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 5, r, k;
    long all[M_N][32];
    char dir[64], real[128];
    int dfd, fd;
    uint8_t *page;
    sc_fn G;

    if (rounds < 1 || rounds > 32) rounds = 5;
    snprintf(dir, sizeof dir, "/tmp/bsfb-%d", (int)getpid());
    mkdir(dir, 0700);
    dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { perror("dir"); return 2; }
    snprintf(g_root, sizeof g_root, "/proc/self/fd/%d", dfd);
    snprintf(real, sizeof real, "%s/hello", g_root);
    fd = openat(dfd, "hello", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "x\n", 2) != 2) { perror("setup"); return 2; }
    close(fd);

    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(page, stub_code, sizeof stub_code);
    mprotect(page, 4096, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)page, (char *)page + sizeof stub_code);
    G = (sc_fn)(void *)page;

    for (r = 0; r < rounds; r++) {
        int pfd[2], st = 0;
        pid_t c;

        if (pipe(pfd) != 0) return 2;
        c = fork();
        if (c == 0) {
            long out[M_N];
            close(pfd[0]);
            one_round(G, (unsigned long)page, (unsigned long)page + 4096, real, out);
            if (write(pfd[1], out, sizeof out) != (ssize_t)sizeof out) _exit(4);
            _exit(0);
        }
        close(pfd[1]);
        {
            long out[M_N];
            if (read(pfd[0], out, sizeof out) != (ssize_t)sizeof out) { fprintf(stderr, "round %d failed\n", r); return 1; }
            for (k = 0; k < M_N; k++) all[k][r] = out[k];
            printf("round %d:", r + 1);
            for (k = 0; k < M_N; k++) printf(" %ld", out[k]);
            printf("\n");
        }
        close(pfd[0]);
        waitpid(c, &st, 0);
    }
    printf("\n中位数（ns/次，%d 轮）:\n", rounds);
    for (k = 0; k < M_N; k++) {
        qsort(all[k], (size_t)rounds, sizeof(long), cmpl);
        printf("  %-22s %6ld\n", names[k], all[k][rounds / 2]);
    }
    unlinkat(dfd, "hello", 0);
    close(dfd);
    rmdir(dir);
    return 0;
}