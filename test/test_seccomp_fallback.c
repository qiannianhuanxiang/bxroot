/*
 * seccomp 兜底层（src/runtime/seccomp_fallback.c）的单测。
 * 直接 #include static_exec.c。过滤器不可撤销，所有用例都在 fork 出的子进程里跑。
 *
 * 构造：一页可执行「guest 代码」：mov x8,x6 ; svc #0 ; ret（号来自寄存器，
 * 改写器默认不改的那一类）。过滤器范围 = 这一页。
 *
 *   A. 范围内 openat("/bxtest/hello") → 陷阱 → 翻译成 /tmp/sfbtest-<pid>/hello，读到内容
 *   B. 范围外（libc）同一路径 → 不翻译，ENOENT
 *   C. 范围内 getpid（不在陷阱集合）→ 不进陷阱，结果正确
 *   D. 范围内 rt_sigaction(SIGSYS) 只进影子槽：真处理器不变，查询回读影子
 *   E. 范围内 rt_sigaction(SIGUSR1, mask 含 SIGSYS) → 真 mask 不含 SIGSYS
 *   F. 范围内 rt_sigprocmask(BLOCK, {SIGSYS,SIGUSR2}) → 只有 SIGUSR2 被屏蔽
 *   G. kill(self, SIGSYS) → 转给影子处理器
 *   H. fork 出的孙进程继承过滤器 + 处理器，翻译仍生效
 *   I. 装过滤器后 execve 范围外的动态程序（/bin/true）→ 正常退出
 *   J. 开销：范围内未陷阱 getppid / 范围外 libc getppid / 陷阱 openat
 *
 * 构建：cd test && gcc -std=gnu11 -O1 -ffixed-x18 -o /tmp/tsfb test_seccomp_fallback.c -ldl
 */
#define _GNU_SOURCE
#include "../src/runtime/static_exec.c"
#include <sys/wait.h>
#include <time.h>

static int fails;
#define CHECK(cond, ...)                                  \
    do {                                                  \
        if (cond) printf("  ok:   ");                     \
        else { fails++; printf("  FAIL: "); }             \
        printf(__VA_ARGS__);                              \
        printf("\n");                                     \
        fflush(stdout);                                   \
    } while (0)

static char g_root[64];

/* 测试用翻译：/bxtest/<x> → <g_root>/<x> */
int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    int n;

    if (strncmp(path, "/bxtest/", 8) != 0)
        return 0;
    n = snprintf(out, out_size, "%s/%s", g_root, path + 8);
    return (n > 0 && (size_t)n < out_size) ? n : 0;
}

typedef long (*sc_fn)(long, long, long, long, long, long, long);
/* long f(a0..a5, nr)：mov x8,x6 ; svc #0 ; ret */
static const uint32_t stub_code[] = { 0xaa0603e8u, SX_SVC_INSN, 0xd65f03c0u };
static sc_fn G;
static unsigned long g_lo, g_hi;

static volatile int g_shadow_hits;
static void shadow_handler(int s) { (void)s; g_shadow_hits++; }

static int read_file_via(sc_fn f, const char *p, char *buf, size_t n)
{
    long fd = f(-100, (long)p, O_RDONLY, 0, 0, 0, 56);
    long r;

    if (fd < 0)
        return (int)fd;
    r = read((int)fd, buf, n - 1);
    close((int)fd);
    if (r < 0)
        return -1;
    buf[r] = '\0';
    return (int)r;
}

static long nsec(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

static unsigned long kmask_now(void)
{
    unsigned long m = 0;
    sx_sc6(135, 0 /* SIG_BLOCK */, 0, (long)&m, 8, 0, 0);
    return m;
}

/* 子进程里跑全部用例；返回失败数 */
static int run_cases(void)
{
    char buf[256];
    int r;

    /* 动态进程：dispatch 不需要切 TLS，但走 static 路径的切换代码 → 设成当前值 */
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(px_static_dyn_tls));
    sx_sfb_want = 1;
    r = sfb_install_handler();
    CHECK(r == 0, "install handler rc=%d", r);
    r = sfb_install_filter(g_lo, g_hi);
    CHECK(r == 0, "install filter [%lx,%lx) rc=%d", g_lo, g_hi, r);
    if (r != 0)
        return fails;

    /* A */
    r = read_file_via(G, "/bxtest/hello", buf, sizeof buf);
    CHECK(r > 0 && strcmp(buf, "sfb-hello\n") == 0, "A in-range openat translated (r=%d, traps=%lu)",
          r, sfb_traps);
    /* B */
    errno = 0;
    r = open("/bxtest/hello", O_RDONLY);
    CHECK(r < 0 && errno == ENOENT, "B out-of-range libc openat untranslated (r=%d errno=%d)", r, errno);
    if (r >= 0) close(r);
    /* C */
    {
        unsigned long t0 = sfb_traps;
        long p = G(0, 0, 0, 0, 0, 0, 172);
        CHECK(p == getpid() && sfb_traps == t0, "C in-range getpid not trapped (%ld)", p);
    }
    /* D */
    {
        struct sx_ksigaction ns, os, real;

        memset(&ns, 0, sizeof ns);
        ns.handler = (unsigned long)(void *)&shadow_handler;
        long rr = G(31, (long)&ns, 0, 8, 0, 0, 134);
        memset(&os, 0, sizeof os);
        long rq = G(31, 0, (long)&os, 8, 0, 0, 134);
        memset(&real, 0, sizeof real);
        sx_sc6(134, 31, 0, (long)&real, 8, 0, 0);   /* 范围外：真实设置 */
        CHECK(rr == 0 && rq == 0 && os.handler == ns.handler &&
              real.handler == (unsigned long)(void *)&sfb_handler,
              "D SIGSYS action shadowed (query=%lx real=%lx)", os.handler, real.handler);
    }
    /* E */
    {
        struct sx_ksigaction ns, real;

        memset(&ns, 0, sizeof ns);
        ns.handler = (unsigned long)(void *)&shadow_handler;
        ns.mask = SFB_SIGBIT | (1UL << (SIGUSR2 - 1));
        long rr = G(SIGUSR1, (long)&ns, 0, 8, 0, 0, 134);
        memset(&real, 0, sizeof real);
        sx_sc6(134, SIGUSR1, 0, (long)&real, 8, 0, 0);
        CHECK(rr == 0 && !(real.mask & SFB_SIGBIT) && (real.mask & (1UL << (SIGUSR2 - 1))),
              "E SIGSYS stripped from sa_mask (mask=%lx)", real.mask);
    }
    /* F */
    {
        unsigned long set = SFB_SIGBIT | (1UL << (SIGUSR2 - 1));
        long rr = G(0 /* SIG_BLOCK */, (long)&set, 0, 8, 0, 0, 135);
        unsigned long m = kmask_now();
        CHECK(rr == 0 && !(m & SFB_SIGBIT) && (m & (1UL << (SIGUSR2 - 1))),
              "F SIGSYS stripped from sigprocmask (mask=%lx)", m);
        set = 1UL << (SIGUSR2 - 1);
        sx_sc6(135, 1, (long)&set, 0, 8, 0, 0);
    }
    /* G */
    {
        int before = g_shadow_hits;
        kill(getpid(), SIGSYS);
        CHECK(g_shadow_hits == before + 1, "G kill(SIGSYS) forwarded to shadow (%d)", g_shadow_hits);
    }
    /* H */
    {
        pid_t c = fork();
        int st = 0;

        if (c == 0) {
            char b2[64];
            int q = read_file_via(G, "/bxtest/hello", b2, sizeof b2);
            _exit(q > 0 && strcmp(b2, "sfb-hello\n") == 0 ? 0 : 3);
        }
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "H forked child inherits filter+handler (st=%x)", st);
    }
    /* I */
    {
        pid_t c = fork();
        int st = 0;

        if (c == 0) {
            char *av[] = { "true", NULL };
            execv("/bin/true", av);
            _exit(99);
        }
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "I execve native-range program under filter (st=%x)", st);
    }
    /* J */
    {
        const int N = 200000, M = 2000;
        long t0, t1, t2, t3;
        int i;

        t0 = nsec();
        for (i = 0; i < N; i++) G(0, 0, 0, 0, 0, 0, 173);
        t1 = nsec();
        for (i = 0; i < N; i++) getppid();
        t2 = nsec();
        for (i = 0; i < M; i++) {
            long fd = G(-100, (long)"/bxtest/hello", O_RDONLY, 0, 0, 0, 56);
            if (fd >= 0) close((int)fd);
        }
        t3 = nsec();
        printf("  bench: in-range untrapped getppid %ld ns, libc getppid %ld ns, trapped openat+close %ld ns\n",
               (t1 - t0) / N, (t2 - t1) / N, (t3 - t2) / M);
        fflush(stdout);
    }
    return fails;
}

int main(void)
{
    uint8_t *page;
    char path[128], dir[64];
    int fd, dfd, st = 0;
    pid_t c;

    /*
     * 目录先经 libc 打开，再用 /proc/self/fd/N 做翻译目标：容器（proroot）里
     * /tmp 由外层 LD_PRELOAD 翻译，裸 svc 看不到；fd 魔术链接由内核直接解析。
     */
    snprintf(dir, sizeof dir, "/tmp/sfbtest-%d", (int)getpid());
    mkdir(dir, 0700);
    dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { perror("opendir"); return 2; }
    snprintf(g_root, sizeof g_root, "/proc/self/fd/%d", dfd);
    snprintf(path, sizeof path, "%s/hello", dir);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "sfb-hello\n", 10) != 10) { perror("setup"); return 2; }
    close(fd);

    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(page, stub_code, sizeof stub_code);
    mprotect(page, 4096, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)page, (char *)page + sizeof stub_code);
    G = (sc_fn)(void *)page;
    g_lo = (unsigned long)page;
    g_hi = g_lo + 4096;

    /* 过滤器生成的边界单测（不装）：高 32 位不同的范围也能生成 */
    {
        struct sfb_insn f[SFB_MAXINS];
        int n1 = sfb_build(f, SFB_MAXINS, 0x400000, 0x500000);
        int n2 = sfb_build(f, SFB_MAXINS, 0xfffff000UL, 0x100002000UL);
        int n3 = sfb_build(f, SFB_MAXINS, 0x500000, 0x400000);
        CHECK(n1 > 0 && n2 == n1 && n3 == -1, "build: n=%d/%d, inverted range rejected (%d)", n1, n2, n3);
    }

    c = fork();
    if (c == 0)
        _exit(run_cases());
    waitpid(c, &st, 0);
    if (!WIFEXITED(st)) {
        printf("  FAIL: case child died st=%x\n", st);
        fails++;
    } else {
        fails += WEXITSTATUS(st);
    }
    unlink(path);
    close(dfd);
    rmdir(dir);
    printf("%s (%d failures)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}