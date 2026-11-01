/*
 * 野 svc 站点（号不是 movz x8,#imm）改写的单测。
 * 直接 #include static_exec.c，用 px_inline_tramp（不切 TLS）验证。
 * sx_svc_all() 会缓存环境变量，所以开关用两次运行覆盖：
 *   ./test_svc_all off    默认行为：号未知的 svc 不改写
 *   ./test_svc_all on     BXROOT_SVC_ALL=1：改写，且语义不变
 *
 * on 模式的判据：
 *   B. 野站点被计数、被改写成 b veneer
 *   C. 改写后经跳板调 getpid(172)，结果与直接 syscall 一致（号来自寄存器）
 *   D. clone(220) 经前置桩原样放行：子进程从桩返回 0，父进程拿到 pid
 *   E. exit_group(94) 原样放行：子进程退出码正确
 *   F. 已知且不关心的号（movz x8,#63）开启后也不改
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
    } while (0)

typedef long (*sc_fn)(long a0, long a1, long nr);

/* long f(a0,a1,nr)：mov x8,x2 ; svc #0 ; ret  —— 号来自寄存器 */
static const uint32_t wild_code[] = { 0xaa0203e8u, SX_SVC_INSN, 0xd65f03c0u };
/* movz x8,#63(read) ; svc #0 ; ret —— 号已知、不关心 */
static const uint32_t known_code[] = { 0xd28007e8u, SX_SVC_INSN, 0xd65f03c0u };

/* 代码页与 veneer 池放同一块映射，保证 b 够得着 */
static uint32_t *mk(const uint32_t *c, size_t n, uint32_t **pool)
{
    uint8_t *page = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(page, c, n * 4);
    *pool = (uint32_t *)(page + 4096);
    return (uint32_t *)page;
}

static void flush(void *p) { __builtin___clear_cache((char *)p, (char *)p + (1 << 16)); }

int main(int argc, char **argv)
{
    int on = argc > 1 && strcmp(argv[1], "on") == 0;
    uint32_t *pool, *code;
    size_t n;

    if (on) setenv("BXROOT_SVC_ALL", "1", 1);
    else unsetenv("BXROOT_SVC_ALL");
    sx_scan_tramp = px_inline_tramp;

    printf("mode=%s\n", on ? "on" : "off");

    code = mk(wild_code, 3, &pool);
    n = sx_scan(code, 3, NULL, 0);
    CHECK(n == (on ? 1u : 0u), "计数：野站点 n=%zu（期望 %u）", n, on ? 1u : 0u);

    code = mk(known_code, 3, &pool);
    n = sx_scan(code, 3, NULL, 0);
    CHECK(n == 0, "F 已知且不关心的号不计数 n=%zu", n);

    if (!on) {
        printf(fails ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", fails);
        return fails ? 1 : 0;
    }

    code = mk(wild_code, 3, &pool);
    n = sx_scan(code, 3, pool, 4096);
    flush(code);
    CHECK(n == 1 && (code[1] >> 26) == 0x05u, "B 站点被改成 b veneer（ins=%08x）", code[1]);

    sc_fn f = (sc_fn)(void *)code;
    long viaTramp = f(0, 0, 172);
    CHECK(viaTramp == (long)getpid(), "C 经跳板 getpid=%ld（真实 %d）", viaTramp, (int)getpid());
    long bad = f(0, 0, 9999);
    CHECK(bad == -ENOSYS, "C2 无效号经跳板返回 -ENOSYS（%ld）", bad);

    {   /* G：开销。直接 syscall vs 经真实跳板（保存 x1..x18 + q0..q31 + NZCV） */
        enum { N = 200000 };
        struct timespec t0, t1;
        double direct, tramp;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < N; i++) syscall(172);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        direct = ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec)) / N;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < N; i++) f(0, 0, 172);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        tramp = ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec)) / N;
        printf("  bench: 直接 getpid %.0f ns, 经跳板 getpid %.0f ns, 额外 %.0f ns\n",
               direct, tramp, tramp - direct);
    }

    /* D：clone(SIGCHLD) 等价 fork，子进程从桩返回 0 */
    long pid = f(17 /* SIGCHLD */, 0, 220);
    if (pid == 0) {
        long rc = f(7, 0, 94);          /* E：exit_group(7) 也走桩 */
        _exit(100 + (int)rc);           /* 不应到达 */
    }
    int st = 0;
    waitpid((pid_t)pid, &st, 0);
    CHECK(pid > 0, "D clone 父进程拿到 pid=%ld", pid);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7, "E exit_group(7) 子进程退出码=%d",
          WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    printf(fails ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", fails);
    return fails ? 1 : 0;
}
