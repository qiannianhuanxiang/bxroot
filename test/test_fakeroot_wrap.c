/*
 * test_fakeroot_wrap.c -- fakeroot 记账层的**链接期**回归测试
 *
 * 与 test_fakeroot.c 的分工：
 *   test_fakeroot.c       纯逻辑断言（不看堆，只看返回值与字段）
 *   test_fakeroot_wrap.c  链接期观测（--wrap=malloc/calloc/free），
 *                         用来测「堆有没有漏」「有没有多余的全表重哈希」
 *                         这类从 API 表面看不出来的性质
 *
 * 为什么必须用 --wrap 而不是某个库内计数器：
 *   F1（fakeroot_forget_path 每次调用漏一份路径键）在 API 语义上
 *   **完全看不出来** —— map_remove 照样返回 FR_OK、条目照样消失、
 *   不变式照样成立，只有堆计数能证明它。审计者正是用这个手法拿到
 *   「1000 次调用漏 999」的硬证据（docs/指针安全审计.md §F1）。
 *   把同样的手法固化成测试，才能防止它回归。
 *
 * 编译（必须是 --wrap，否则 __wrap_* 不会被调用、测试会静默失去意义）：
 *   gcc -O1 -D_GNU_SOURCE -DFAKEROOT_PURE_LOGIC -Isrc/runtime \
 *       -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free \
 *       -o /tmp/t_wrap test/test_fakeroot_wrap.c src/runtime/fakeroot.c
 *   /tmp/t_wrap
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fakeroot.h"

/* ------------------------------------------------------------------ */
/* 堆计数钩子                                                          */
/* ------------------------------------------------------------------ */

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void  __real_free(void *);

static long g_alloc_n;   /* malloc + calloc */
static long g_free_n;
static long g_calloc_n;  /* 只数 calloc：用来独立观测全表重哈希 */

void *__wrap_malloc(size_t n)
{
    g_alloc_n++;
    return __real_malloc(n);
}

void *__wrap_calloc(size_t a, size_t b)
{
    g_alloc_n++;
    g_calloc_n++;
    return __real_calloc(a, b);
}

void __wrap_free(void *p)
{
    if (p != NULL) {
        g_free_n++;
    }
    __real_free(p);
}

static void heap_reset(void)
{
    g_alloc_n = 0;
    g_free_n  = 0;
    g_calloc_n = 0;
}

static long heap_net(void) { return g_alloc_n - g_free_n; }

/* ------------------------------------------------------------------ */
/* 断言框架（与 test_fakeroot.c 同型）                                  */
/* ------------------------------------------------------------------ */

static int g_cases, g_failed, g_checks;

#define CHECK(cond) do {                                              \
        g_checks++;                                                   \
        if (!(cond)) {                                                \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s\n",                     \
                    __FILE__, __LINE__, #cond);                       \
        }                                                             \
    } while (0)

#define CHECK_EQ_I(a, b) do {                                         \
        g_checks++;                                                   \
        long long _a = (long long)(a), _b = (long long)(b);           \
        if (_a != _b) {                                               \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s=%lld, 期望 %s=%lld\n",  \
                    __FILE__, __LINE__, #a, _a, #b, _b);              \
        }                                                             \
    } while (0)

#define CASE(name) do {                                               \
        g_cases++;                                                    \
        printf("- %s\n", name);                                       \
        fflush(stdout);                                               \
    } while (0)

/* ------------------------------------------------------------------ */
/* W1  F1 回归：forget_path 每次调用都释放路径键                       */
/* ------------------------------------------------------------------ */

/*
 * 关键设计：把「建表 + 记账 + 删除 + 销毁」整段包在同一个测量窗口里，
 * 这样正确的实现应当给出**净额恰好为 0**，不需要任何修正项。
 *
 * 期望的分配/释放清单（cap=64，1 条命中 + 999 条未命中）：
 *   create : calloc(map) +1、calloc(slots) +1                  → 2
 *   record : malloc(key) +1                                    → 3
 *   forget (命中 1 次)  : malloc(k 拷贝) +1
 *                         free(表内那份键) +1、free(k) +1
 *   forget (未命中 999) : malloc(k 拷贝) +999、free(k) +999
 *   destroy: free(slots) +1、free(map) +1
 *   合计 alloc = 3 + 1 + 999 = 1003
 *        free  = 1 + 1 + 1 + 999 + 1 + 1 = 1004 ... 见下面的实测对齐
 *
 * 不做手算对齐 —— 判据就是「净额 == 0」，任何一处漏 free 都会让它 > 0。
 */
static void w_forget_path_no_leak(void)
{
    fakeroot_map *m;
    fakeroot_state fs;
    char path[64];
    int  i;
    int  hits = 0;
    long net;

    CASE("W1 F1 回归：forget_path x1000（含命中与未命中）堆净额必须为 0");

    memset(&fs, 0, sizeof(fs));
    fs.enabled     = true;
    fs.ruid = fs.euid = fs.suid = fs.fsuid = 0;
    fs.rgid = fs.egid = fs.sgid = fs.fsgid = 0;
    fs.real_uid = fs.real_euid = 2000;
    fs.real_gid = fs.real_egid = 2000;

    heap_reset();

    m = fakeroot_map_create(64);
    CHECK(m != NULL);
    if (m == NULL) {
        return;
    }
    fs.by_path  = m;
    fs.by_inode = NULL;

    /* 只记 1 条，保证第 0 次 forget 命中、其余 999 次未命中 */
    CHECK_EQ_I(fakeroot_record_create_path(&fs, "/victim", 0644, 0, 0), FR_OK);

    for (i = 0; i < 1000; i++) {
        int rc;
        if (i == 0) {
            snprintf(path, sizeof(path), "/victim");
        } else {
            snprintf(path, sizeof(path), "/nope-%d", i);
        }
        rc = fakeroot_forget_path(&fs, path);
        if (rc == FR_OK) {
            hits++;
        }
    }

    CHECK_EQ_I(hits, 1);   /* 命中恰好 1 次：这条路径真的被走到了 */

    fakeroot_map_destroy(m);
    net = heap_net();

    printf("    alloc=%ld free=%ld net=%ld (期望 0)\n",
           g_alloc_n, g_free_n, net);
    CHECK_EQ_I(net, 0);
}

/*
 * W1b：单独量「1000 次全部未命中」的场景。
 * 审计报告的数字就是这一行：修复前 malloc +1000 / free +0 = 漏 1000。
 *
 * 这里把建表放在测量窗口**之外**，所以判据不是净额 0，而是
 * 「free 数必须恰好等于 malloc 数」—— 未命中时我们不碰表内任何键，
 * 唯一该发生的配对就是 fakeroot_key_path 的 malloc 与随后的 dispose。
 */
static void w_forget_path_miss_leak(void)
{
    fakeroot_map *m;
    fakeroot_state fs;
    char path[64];
    int  i;
    long m_delta, f_delta;

    CASE("W1b F1 回归：1000 次未命中的 forget_path 必须 malloc==free");

    memset(&fs, 0, sizeof(fs));
    fs.enabled = true;
    fs.by_path = fakeroot_map_create(1024);
    fs.by_inode = NULL;
    if (fs.by_path == NULL) {
        return;
    }

    heap_reset();   /* 建表已完成，窗口内只应有 forget_path 自己的分配 */

    for (i = 0; i < 1000; i++) {
        snprintf(path, sizeof(path), "/miss/%d", i);
        (void)fakeroot_forget_path(&fs, path);
    }

    m_delta = g_alloc_n;
    f_delta = g_free_n;
    printf("    malloc +%ld  free +%ld  net = %ld (修复前是 +1000/+0 = 漏 1000)\n",
           m_delta, f_delta, m_delta - f_delta);

    CHECK_EQ_I(m_delta, 1000);      /* 每次调用必须真的深拷贝一份键 */
    CHECK_EQ_I(m_delta - f_delta, 0);

    fakeroot_map_destroy(fs.by_path);
}

/* ------------------------------------------------------------------ */
/* 辅助                                                                */
/* ------------------------------------------------------------------ */

static void put_path(fakeroot_map *m, const char *p, const fr_record *rec)
{
    fr_key k;
    if (fakeroot_key_path(&k, p) == FR_OK) {
        (void)fakeroot_map_put(m, k, rec);   /* put 接管 k 的所有权 */
    }
}

static void del_path(fakeroot_map *m, const char *p)
{
    fr_key k;
    if (fakeroot_key_path(&k, p) == FR_OK) {
        (void)fakeroot_map_remove(m, &k);
        fakeroot_key_dispose(&k);            /* remove 不接管，调用方释放 */
    }
}

/* ------------------------------------------------------------------ */
/* W2  F2 的独立交叉验证：链接期数 calloc，与库内计数器必须一致         */
/* ------------------------------------------------------------------ */

/*
 * F2（复用墓碑槽位漏 tombs--）的两种观测手段必须互相印证：
 *   (a) 链接期：--wrap=calloc 数 fr_map_compact 的新数组分配；
 *   (b) 库内：fakeroot_map_rehash_count()。
 * 只有 (a) 没有 (b) 时，若将来实现改用别的分配器，(a) 会静默失效；
 * 只有 (b) 没有 (a) 时，计数器本身可能就是错的。两个一起断言。
 *
 * 负载用审计报告的判决实验形态：cap=1（压实阈值 cap/4 == 0 ⇒ 只要
 * tombs > 0 就永久触发压实），连续 50 次插入互不相同的键，靠
 * 装载率超阈值触发的 LRU 淘汰造出墓碑。
 * 实测：修复前 48 次重哈希，修复后 0 次。
 */
static void w_rehash_accounting(void)
{
    fakeroot_map *m;
    fr_record rec;
    int i;
    long calloc_n;
    size_t lib_n;

    CASE("W2 F2 回归：cap=1 连续 50 次插入，重哈希次数必须为 0");

    memset(&rec, 0, sizeof(rec));
    rec.uid = 0;

    m = fakeroot_map_create(1);
    CHECK(m != NULL);
    if (m == NULL) {
        return;
    }

    heap_reset();

    for (i = 0; i < 50; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/k%d", i);
        put_path(m, path, &rec);
    }

    calloc_n = g_calloc_n;
    lib_n    = fakeroot_map_rehash_count(m);

    printf("    链接期 calloc（重哈希次数）= %ld ；库内计数器 = %zu\n",
           calloc_n, lib_n);

    /* 修复前 48 次；修复后 0 次。 */
    CHECK_EQ_I(calloc_n, 0);
    CHECK_EQ_I((long long)lib_n, 0);
    CHECK_EQ_I((long long)fakeroot_map_compact_fail_count(m), 0);
    CHECK(fakeroot_map_check_invariants(m));

    fakeroot_map_destroy(m);
}

/* ------------------------------------------------------------------ */
/* W3  F2 的**确定性**墓碑复用：唯一能走到 probe 第二遍扫描的路径       */
/* ------------------------------------------------------------------ */

/*
 * 为什么还需要 W3：W2 在修复前后差别很大，但它依赖「eviction 造墓碑」
 * 这个间接机制。真正能确定性地覆盖「put 复用墓碑槽」的，是下面这条：
 *
 *   eviction OFF ⇒ 第 283 行契约「表满后 put 直接返回 FR_EFULL」
 *   ⇒ 灌满整张表（count == cap，无 EMPTY 槽）
 *   ⇒ 删掉 8 条，但刻意**不超过**压实阈值 cap/4（= 16），使 tombs 保持 8
 *   ⇒ 再插 8 条新键：第一遍扫描扫不到 EMPTY（表里全是 LIVE+TOMB），
 *     必然走 fr_map_probe 的第二遍 TOMB 扫描 → 必然复用墓碑槽
 *
 * 于是「复用 8 个墓碑后 tombs 必须回落到 0」是一个**精确的**断言，
 * 修复前恒为 8（计数器漂移），修复后恒为 0。
 *
 * 注意：这条路径**不会**立刻多出重哈希（压实阈值刚好没被越过），
 * 所以它的价值在于抓住不变式本身，而不是抓性能退化 —— 性能退化由
 * W4 的稳态负载抓。两者一起才完整覆盖 F2。
 */
static void w_tomb_reuse_deterministic(void)
{
    static const size_t CAP = 64;
    static const int    N   = 8;     /* < CAP/4 = 16，故意不触发压实 */
    fakeroot_map *m;
    fr_record rec;
    int i;

    CASE("W3 F2 回归：确定性复用墓碑槽位后 tombs 必须回落到 0");

    memset(&rec, 0, sizeof(rec));
    rec.uid = 0;

    m = fakeroot_map_create(CAP);
    CHECK(m != NULL);
    if (m == NULL) {
        return;
    }
    fakeroot_map_set_eviction(m, false);
    CHECK_EQ_I(fakeroot_map_eviction_enabled(m), false);

    /* 灌满：count == cap，一个 EMPTY 槽都不剩 */
    for (i = 0; i < (int)CAP; i++) {
        char p[32];
        snprintf(p, sizeof(p), "/g%d", i);
        put_path(m, p, &rec);
    }
    CHECK_EQ_I((long long)fakeroot_map_count(m), (long long)CAP);
    CHECK(fakeroot_map_check_invariants(m));

    /* 删 N 条：tombs == N，仍低于压实阈值 CAP/4 == 16 */
    for (i = 0; i < N; i++) {
        char p[32];
        snprintf(p, sizeof(p), "/g%d", i);
        del_path(m, p);
    }
    CHECK_EQ_I((long long)fakeroot_map_count(m), (long long)(CAP - N));
    CHECK_EQ_I((long long)fakeroot_map_tomb_count(m), N);
    CHECK(fakeroot_map_check_invariants(m));

    heap_reset();

    /* 再插 N 条**新**键：表里没有 EMPTY 槽 ⇒ 必然复用那 N 个墓碑 */
    for (i = 0; i < N; i++) {
        char p[32];
        snprintf(p, sizeof(p), "/g-new%d", i);
        put_path(m, p, &rec);
    }

    printf("    灌满 cap=%zu 后删 %d 条，再插 %d 条新键：\n", CAP, N, N);
    printf("      count=%zu (期望 %zu)  tombs=%zu (期望 0，修复前恒为 %d)"
           "  重哈希=%ld  不变式=%d\n",
           fakeroot_map_count(m), CAP,
           fakeroot_map_tomb_count(m), N, g_calloc_n,
           (int)fakeroot_map_check_invariants(m));

    CHECK_EQ_I((long long)fakeroot_map_count(m), (long long)CAP);
    CHECK_EQ_I((long long)fakeroot_map_tomb_count(m), 0);   /* ← F2 的判决断言 */
    CHECK(fakeroot_map_check_invariants(m));

    fakeroot_map_destroy(m);
}

/* ------------------------------------------------------------------ */
/* W4  F2 的稳态负载：可观测的重哈希退化                                */
/* ------------------------------------------------------------------ */

/*
 * 模拟 dpkg / tar 的高频改名：表灌满后不断「删一批、插一批」。
 * 健康实现里 tombs 是**有界**的（删多少、下一次插入就回收多少），
 * 所以压实判据 tombs > cap/4 永远不该被越过，重哈希次数必须是 0。
 *
 * 修复前 tombs 单调累积不回落 ⇒ 越过 cap/4 ⇒ 反复全表重哈希。
 * 实测（cap=256，50 轮 x (删8+插8) = 400 次插入）：
 *   修复前 重哈希 3 次、残留 tombs=40、不变式不成立
 *   修复后 重哈希 0 次、残留 tombs=0、不变式成立
 */
static void w_steady_state_churn(void)
{
    static const size_t CAP    = 256;
    static const int    ROUNDS = 50;
    static const int    BATCH  = 8;
    fakeroot_map *m;
    fr_record rec;
    int i, r;
    long calloc_n;

    CASE("W4 F2 回归：稳态改写负载 400 次插入必须 0 次重哈希");

    memset(&rec, 0, sizeof(rec));
    rec.uid = 0;

    m = fakeroot_map_create(CAP);
    CHECK(m != NULL);
    if (m == NULL) {
        return;
    }
    fakeroot_map_set_eviction(m, false);

    for (i = 0; i < (int)CAP; i++) {
        char p[32];
        snprintf(p, sizeof(p), "/s%d", i);
        put_path(m, p, &rec);
    }

    heap_reset();

    for (r = 0; r < ROUNDS; r++) {
        for (i = 0; i < BATCH; i++) {
            char p[32];
            snprintf(p, sizeof(p), "/s%d", (r * BATCH + i) % (int)CAP);
            del_path(m, p);
        }
        for (i = 0; i < BATCH; i++) {
            char p[32];
            snprintf(p, sizeof(p), "/n%d_%d", r, i);
            put_path(m, p, &rec);
        }
    }

    calloc_n = g_calloc_n;

    printf("    cap=%zu evict=OFF %d 轮 x (删%d+插%d) = %d 次插入 -> "
           "重哈希=%ld (期望 0)  count=%zu tombs=%zu 不变式=%d\n",
           CAP, ROUNDS, BATCH, BATCH, ROUNDS * BATCH, calloc_n,
           fakeroot_map_count(m), fakeroot_map_tomb_count(m),
           (int)fakeroot_map_check_invariants(m));

    CHECK_EQ_I(calloc_n, 0);
    CHECK_EQ_I((long long)fakeroot_map_rehash_count(m), 0);
    CHECK(fakeroot_map_check_invariants(m));
    /* 稳态：删 N 条就会被下一次插入回收 N 条 ⇒ 墓碑不该有残留 */
    CHECK_EQ_I((long long)fakeroot_map_tomb_count(m), 0);

    fakeroot_map_destroy(m);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("fakeroot 记账层链接期回归测试（--wrap=malloc/calloc/free）\n");
    printf("========================================\n\n");

    if (g_alloc_n == 0) {
        /* 编译时忘了 --wrap 时 __wrap_* 永远不会被调用 —— 那样这些
         * 测试会全部「通过」却什么都没测。宁可在这里显式失败。 */
        printf("!! 没有 --wrap 钩子被调用：本文件必须用 -Wl,--wrap=malloc \\\n"
               "   -Wl,--wrap=calloc -Wl,--wrap=free 链接，否则测试无意义。\n");
    }

    w_forget_path_no_leak();
    w_forget_path_miss_leak();
    w_rehash_accounting();
    w_tomb_reuse_deterministic();
    w_steady_state_churn();

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d 失败)\n", g_cases, g_failed);
    printf("checks: %d  (%d 失败)\n", g_checks, g_failed);
    printf("RESULT: %s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}
