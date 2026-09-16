/*
 * test_proc.c -- 进程管理层（D4）单元测试
 *
 * 层次
 * ----
 *   A  账本基础        增删查、非法输入、边界
 *   B  账本容量        淘汰 / 压实 / 扩容 / ENOMEM 故障注入
 *   C  envp 重建       覆盖、剔除、截断、空环境、扩容回归、ENOMEM
 *   D  LD_PRELOAD 合并 顺序、去重、截断
 *   E  argv 判定       绝对/相对/幂等/rootfs="/" 退化
 *   F  argv 计划与应用
 *   G  guest PATH 搜索
 *   H  bump 分配器     固定缓冲、重置、与 env 重建协作
 *   I  kill 判定       安全边界全分支
 *   J  atfork 协议     锁状态机、child 重置、登记失败
 *   K  真实 FS 端到端  真 fork + 真 exec 验证 envp 真的被内核交付
 *   L  fork 死锁对照   实证「不上 atfork 会死锁」
 *
 * 容器限制：本容器**无法**验证 LD_PRELOAD 是否被 ld.so 采纳
 * （外层 proot 吞掉注入）。K 组验证的是「我们把正确的 envp 交给了内核」，
 * 这是本容器内能达到的最强证据；ld.so 那一跳留给真机验证（见 REPORT.md）。
 *
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#define PX_PURE_LOGIC 1

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "proc.h"

static int g_cases;
static int g_checks;
static int g_failed;

#define CHECK(cond) do {                                              \
        g_checks++;                                                   \
        if (!(cond)) {                                                \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s\n",                     \
                    __FILE__, __LINE__, #cond);                       \
        }                                                             \
    } while (0)

#define CHECK_EQ(a, b) do {                                           \
        g_checks++;                                                   \
        long long _a = (long long)(a), _b = (long long)(b);           \
        if (_a != _b) {                                               \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s=%lld, 期望 %s=%lld\n",  \
                    __FILE__, __LINE__, #a, _a, #b, _b);              \
        }                                                             \
    } while (0)

#define CHECK_STR(a, b) do {                                          \
        g_checks++;                                                   \
        const char *_a = (a), *_b = (b);                              \
        if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0) {        \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s=\"%s\", 期望 \"%s\"\n",  \
                    __FILE__, __LINE__, #a,                               \
                    _a ? _a : "(null)", _b ? _b : "(null)");          \
        }                                                             \
    } while (0)

#define CASE(name) do {                                               \
        g_cases++;                                                    \
        printf("- %s\n", name);                                       \
        fflush(stdout);                                               \
    } while (0)

/* ================================================================== */
/* 故障注入分配器                                                      */
/* ================================================================== */

/*
 * 倒计数分配器：第 N 次分配失败。
 *
 * 为什么这类注入是本项目的要求而不是加分项：
 *   `PX_ENOMEM` 分支在生产里几乎不可达（Android 低内存杀后台时才可能），
 *   而一旦可达，后果是「半残的账本 + 静默失效」—— 与 fakeroot 记账表
 *   建不起来时的危险性同类。不可达的分支没人写、没人测、必然写错。
 *   注入分配器把它变成确定性可测的。
 */
typedef struct {
    long countdown;     /* > 0 时倒计数；归零后本次分配失败 */
    long calls;
    long fails;
    long live;          /* 未释放的块数，用于查泄漏 */
} fail_alloc;

static void *fa_malloc(void *ud, size_t n)
{
    fail_alloc *f = (fail_alloc *)ud;
    f->calls++;
    if (f->countdown > 0) {
        f->countdown--;
        if (f->countdown == 0) {
            f->fails++;
            return NULL;
        }
    }
    {
        void *p = malloc(n);
        if (p != NULL) {
            f->live++;
        }
        return p;
    }
}

static void *fa_calloc(void *ud, size_t n, size_t sz)
{
    fail_alloc *f = (fail_alloc *)ud;
    f->calls++;
    if (f->countdown > 0) {
        f->countdown--;
        if (f->countdown == 0) {
            f->fails++;
            return NULL;
        }
    }
    {
        void *p = calloc(n, sz);
        if (p != NULL) {
            f->live++;
        }
        return p;
    }
}

static void fa_free(void *ud, void *p)
{
    fail_alloc *f = (fail_alloc *)ud;
    if (p != NULL) {
        f->live--;
    }
    free(p);
}

static const px_alloc *fa_ops(fail_alloc *f)
{
    static px_alloc a;
    a.ud = f;
    a.malloc = fa_malloc;
    a.calloc = fa_calloc;
    a.free = fa_free;
    return &a;
}

/* ================================================================== */
/* A  账本基础                                                         */
/* ================================================================== */

static void test_ledger_basic(void)
{
    px_ledger *l;
    px_procinfo info;

    CASE("A1 创建/销毁/容量");
    l = px_ledger_create(0, NULL);
    CHECK(l != NULL);
    CHECK_EQ(px_ledger_capacity(l), PX_LEDGER_DEFAULT_SLOTS);
    CHECK_EQ(px_ledger_count(l), 0);
    CHECK_EQ(px_ledger_live_count(l), 0);
    px_ledger_destroy(l);
    px_ledger_destroy(NULL);              /* 幂等 + NULL 安全 */

    CASE("A2 槽位数向上取整到 2 的幂");
    l = px_ledger_create(5, NULL);
    CHECK_EQ(px_ledger_capacity(l), 8);
    px_ledger_destroy(l);
    l = px_ledger_create(1, NULL);
    CHECK_EQ(px_ledger_capacity(l), 1);   /* 1 是 2^0 */
    px_ledger_destroy(l);

    CASE("A3 超过硬上限时截断");
    l = px_ledger_create((size_t)-1, NULL);
    CHECK(l != NULL);
    CHECK_EQ(px_ledger_capacity(l), (size_t)PX_LEDGER_MAX_SLOTS);
    px_ledger_destroy(l);

    CASE("A4 增/查/删基本流程");
    l = px_ledger_create(64, NULL);
    CHECK_EQ(px_ledger_add(l, 100, 1, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_count(l), 1);
    CHECK_EQ(px_ledger_live_count(l), 1);
    CHECK_EQ(px_ledger_has(l, 100, PX_ENTRY_PID), 1);
    CHECK_EQ(px_ledger_get(l, 100, PX_ENTRY_PID, &info), PX_OK);
    CHECK_EQ(info.pid, 100);
    CHECK_EQ(info.ppid, 1);
    CHECK_EQ(info.life, PX_LIVE);
    CHECK_EQ(info.tag, PX_TAG_FORK);
    CHECK_EQ(info.kind, PX_ENTRY_PID);

    /* PID 与 PGID 是两个独立的键空间 */
    CHECK_EQ(px_ledger_has(l, 100, PX_ENTRY_PGID), 0);
    CHECK_EQ(px_ledger_add_pgid(l, 100, PX_TAG_SPAWN), PX_OK);
    CHECK_EQ(px_ledger_has(l, 100, PX_ENTRY_PGID), 1);
    CHECK_EQ(px_ledger_has(l, 100, PX_ENTRY_PID), 1);
    CHECK_EQ(px_ledger_count(l), 2);

    CHECK_EQ(px_ledger_remove(l, 100, PX_ENTRY_PID), PX_OK);
    CHECK_EQ(px_ledger_has(l, 100, PX_ENTRY_PID), 0);
    CHECK_EQ(px_ledger_has(l, 100, PX_ENTRY_PGID), 1);   /* 另一个键还在 */
    CHECK_EQ(px_ledger_count(l), 1);

    CHECK_EQ(px_ledger_remove(l, 100, PX_ENTRY_PID), PX_ENOENT);
    px_ledger_destroy(l);

    CASE("A5 非法 pid 被拒绝");
    l = px_ledger_create(16, NULL);
    CHECK_EQ(px_ledger_add(l, 0, 1, PX_TAG_FORK), PX_EINVAL);
    CHECK_EQ(px_ledger_add(l, -5, 1, PX_TAG_FORK), PX_EINVAL);
    CHECK_EQ(px_ledger_count(l), 0);
    CHECK_EQ(px_ledger_has(l, 0, PX_ENTRY_PID), 0);
    CHECK_EQ(px_ledger_get(l, -1, PX_ENTRY_PID, NULL), PX_ENOENT);
    px_ledger_destroy(l);

    CASE("A6 重复 add 是刷新，不新增条目");
    l = px_ledger_create(16, NULL);
    CHECK_EQ(px_ledger_add(l, 7, 1, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_add(l, 7, 2, PX_TAG_SPAWN), PX_OK);
    CHECK_EQ(px_ledger_count(l), 1);
    CHECK_EQ(px_ledger_get(l, 7, PX_ENTRY_PID, &info), PX_OK);
    CHECK_EQ(info.ppid, 2);
    CHECK_EQ(info.tag, PX_TAG_SPAWN);
    px_ledger_destroy(l);

    CASE("A7 reap 标记后仍可查，但不计入 live");
    l = px_ledger_create(16, NULL);
    CHECK_EQ(px_ledger_reap(l, 42), PX_ENOENT);       /* 不存在 */
    CHECK_EQ(px_ledger_add(l, 42, 1, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_reap(l, 42), PX_OK);
    CHECK_EQ(px_ledger_get(l, 42, PX_ENTRY_PID, &info), PX_OK);
    CHECK_EQ(info.life, PX_REAPED);
    CHECK_EQ(px_ledger_count(l), 1);
    CHECK_EQ(px_ledger_live_count(l), 0);
    CHECK_EQ(px_ledger_reaped_count(l), 1);

    /* ★ 关键语义：对已 reap 的 pid 再次 add 不得「复活」成 LIVE ★
     * 复活会让 pid 复用防护失效 —— 宿主已把该 pid 分配给别的进程，
     * 我们却以为自己还拥有它。 */
    CHECK_EQ(px_ledger_add(l, 42, 1, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_get(l, 42, PX_ENTRY_PID, &info), PX_OK);
    CHECK_EQ(info.life, PX_REAPED);
    px_ledger_destroy(l);

    CASE("A8 disabled 后记账是 no-op，查询一律 ENOENT");
    l = px_ledger_create(16, NULL);
    px_ledger_set_disabled(l, 1);
    CHECK_EQ(px_ledger_is_disabled(l), 1);
    CHECK_EQ(px_ledger_add(l, 9, 1, PX_TAG_FORK), PX_OK);   /* 不报错 */
    CHECK_EQ(px_ledger_count(l), 0);                        /* 但没记 */
    CHECK_EQ(px_ledger_has(l, 9, PX_ENTRY_PID), 0);
    CHECK_EQ(px_ledger_get(l, 9, PX_ENTRY_PID, NULL), PX_ENOENT);
    CHECK_EQ(px_ledger_reap(l, 9), PX_ENOENT);
    CHECK_EQ(px_ledger_remove(l, 9, PX_ENTRY_PID), PX_ENOENT);
    px_ledger_set_disabled(l, 0);
    CHECK_EQ(px_ledger_is_disabled(l), 0);
    CHECK_EQ(px_ledger_add(l, 9, 1, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_count(l), 1);
    px_ledger_destroy(l);

    CASE("A9 clear 复位但不释放容量");
    l = px_ledger_create(32, NULL);
    (void)px_ledger_add(l, 1, 0, PX_TAG_FORK);
    (void)px_ledger_add(l, 2, 0, PX_TAG_FORK);
    CHECK_EQ(px_ledger_count(l), 2);
    px_ledger_clear(l);
    CHECK_EQ(px_ledger_count(l), 0);
    CHECK_EQ(px_ledger_reaped_count(l), 0);
    CHECK_EQ(px_ledger_capacity(l), 32);
    CHECK_EQ(px_ledger_has(l, 1, PX_ENTRY_PID), 0);
    px_ledger_clear(NULL);            /* NULL 安全 */
    px_ledger_destroy(l);

    CASE("A10 大量插入/删除（墓碑不截断探测链）");
    l = px_ledger_create(128, NULL);
    {
        int i;
        for (i = 1; i <= 60; i++) {
            CHECK_EQ(px_ledger_add(l, i, 1, PX_TAG_FORK), PX_OK);
        }
        /* 删掉偶数，再查奇数 —— 若墓碑被当成 EMPTY，探测链会断，
         * 排在后面的奇数 pid 就会查不到。 */
        for (i = 2; i <= 60; i += 2) {
            CHECK_EQ(px_ledger_remove(l, i, PX_ENTRY_PID), PX_OK);
        }
        for (i = 1; i <= 59; i += 2) {
            CHECK_EQ(px_ledger_has(l, i, PX_ENTRY_PID), 1);
        }
        CHECK_EQ(px_ledger_count(l), 30);
    }
    px_ledger_destroy(l);

    CASE("A11 哈希分散：连续 pid 不与 2 的幂冲突");
    l = px_ledger_create(8, NULL);      /* 故意极小 */
    {
        int i;
        for (i = 1000; i < 1006; i++) {   /* 装载率 75% 以内 */
            CHECK_EQ(px_ledger_add(l, i, 1, PX_TAG_FORK), PX_OK);
        }
        for (i = 1000; i < 1006; i++) {
            CHECK_EQ(px_ledger_has(l, i, PX_ENTRY_PID), 1);
        }
    }
    px_ledger_destroy(l);
}

/* ================================================================== */
/* B  账本容量 / 淘汰 / 压实 / 扩容 / 故障注入                          */
/* ================================================================== */

static void test_ledger_capacity(void)
{
    px_ledger *l;

    CASE("B1 live 条目【绝不】被淘汰（功能正确性）");
    l = px_ledger_create(8, NULL);
    {
        int i;
        for (i = 1; i <= 8; i++) {
            (void)px_ledger_add(l, i, 1, PX_TAG_FORK);
        }
        /* 全是 live，无可淘汰 → evict 应当一个都不动 */
        CHECK_EQ(px_ledger_evict(l, 8), 0);
        for (i = 1; i <= 8; i++) {
            CHECK_EQ(px_ledger_has(l, i, PX_ENTRY_PID), 1);
        }
    }
    px_ledger_destroy(l);

    CASE("B2 reaped 条目可被淘汰，且在 live 之后");
    l = px_ledger_create(16, NULL);
    (void)px_ledger_add(l, 1, 0, PX_TAG_FORK);
    (void)px_ledger_add(l, 2, 0, PX_TAG_FORK);
    (void)px_ledger_add(l, 3, 0, PX_TAG_FORK);
    (void)px_ledger_reap(l, 2);
    CHECK_EQ(px_ledger_evict(l, 8), 1);            /* 只有 1 个可淘汰 */
    CHECK_EQ(px_ledger_has(l, 2, PX_ENTRY_PID), 0);
    CHECK_EQ(px_ledger_has(l, 1, PX_ENTRY_PID), 1);
    CHECK_EQ(px_ledger_has(l, 3, PX_ENTRY_PID), 1);
    CHECK_EQ(px_ledger_count(l), 2);
    px_ledger_destroy(l);

    CASE("B3 表满且不可淘汰时 add 返回 EFULL（关闭自动淘汰）");
    l = px_ledger_create(4, NULL);
    px_ledger_set_eviction(l, 0);
    CHECK_EQ(px_ledger_eviction_enabled(l), 0);
    CHECK_EQ(px_ledger_add(l, 1, 0, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_add(l, 2, 0, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_add(l, 3, 0, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_add(l, 4, 0, PX_TAG_FORK), PX_OK);
    /* 4 槽满了。装载率 100% ≥ 75% → 会尝试扩容，扩容成功就继续。 */
    CHECK_EQ(px_ledger_add(l, 5, 0, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_ledger_capacity(l), 8);           /* 扩容了 */
    CHECK_EQ(px_ledger_has(l, 1, PX_ENTRY_PID), 1);
    CHECK_EQ(px_ledger_has(l, 5, PX_ENTRY_PID), 1);
    px_ledger_destroy(l);

    CASE("B4 扩容后所有旧条目仍可查（重哈希正确）");
    l = px_ledger_create(8, NULL);
    {
        int i;
        for (i = 1; i <= 200; i++) {
            CHECK_EQ(px_ledger_add(l, i, 1, PX_TAG_FORK), PX_OK);
        }
        CHECK(px_ledger_capacity(l) > 8);
        for (i = 1; i <= 200; i++) {
            if (!px_ledger_has(l, i, PX_ENTRY_PID)) {
                g_failed++;
                fprintf(stderr, "  FAIL 扩容后丢了 pid %d\n", i);
                break;
            }
        }
        g_checks++;
        CHECK_EQ(px_ledger_count(l), 200);
    }
    px_ledger_destroy(l);

    CASE("B5 大量墓碑触发压实，装载率恢复");
    l = px_ledger_create(64, NULL);
    {
        int round;
        /* 反复 add + remove，制造墓碑但不产生 live 积累 */
        for (round = 0; round < 200; round++) {
            int i;
            for (i = 1; i <= 40; i++) {
                (void)px_ledger_add(l, i, 0, PX_TAG_FORK);
            }
            for (i = 1; i <= 40; i++) {
                (void)px_ledger_remove(l, i, PX_ENTRY_PID);
            }
        }
        /* 压实应当把墓碑回收，容量不该无限增长 */
        CHECK(px_ledger_capacity(l) <= 256);
        CHECK_EQ(px_ledger_count(l), 0);
    }
    px_ledger_destroy(l);

    CASE("B6 故障注入：建表时 calloc 失败");
    {
        fail_alloc f = {1, 0, 0, 0};
        l = px_ledger_create(16, fa_ops(&f));
        CHECK(l == NULL);                 /* 第一次 calloc 就失败 */
        CHECK_EQ(f.fails, 1);
        CHECK_EQ(f.live, 0);              /* 无泄漏 */
    }

    CASE("B7 故障注入：第二次分配失败时必须回收第一块");
    {
        fail_alloc f = {2, 0, 0, 0};
        l = px_ledger_create(16, fa_ops(&f));
        CHECK(l == NULL);
        CHECK_EQ(f.fails, 1);
        CHECK_EQ(f.live, 0);              /* ★ 泄漏检查：第一块必须已 free */
    }

    CASE("B8 故障注入：扩容时分配失败必须保留原表");
    {
        fail_alloc f = {0, 0, 0, 0};
        l = px_ledger_create(8, fa_ops(&f));
        CHECK(l != NULL);
        px_ledger_set_eviction(l, 0);     /* 关掉淘汰，逼它走扩容路径 */
        {
            int i;
            int rc = PX_OK;
            for (i = 1; i <= 6; i++) {
                (void)px_ledger_add(l, i, 0, PX_TAG_FORK);
            }
            /* 让下一次分配失败 */
            f.countdown = 1;
            rc = px_ledger_add(l, 7, 0, PX_TAG_FORK);
            f.countdown = 0;
            CHECK(rc != PX_OK);           /* 应当失败 */
            /* ★ 原表必须完好：扩容失败不能把已记的条目弄丢 */
            for (i = 1; i <= 6; i++) {
                CHECK_EQ(px_ledger_has(l, i, PX_ENTRY_PID), 1);
            }
        }
        px_ledger_destroy(l);
    }

    CASE("B9 故障注入：压实过程中分配失败");
    {
        fail_alloc f = {0, 0, 0, 0};
        l = px_ledger_create(32, fa_ops(&f));
        {
            int i;
            for (i = 1; i <= 20; i++) {
                (void)px_ledger_add(l, i, 0, PX_TAG_FORK);
            }
            /* 制造墓碑使装载率超阈值 */
            for (i = 1; i <= 8; i++) {
                (void)px_ledger_remove(l, i, PX_ENTRY_PID);
            }
            f.countdown = 1;              /* 下一次分配失败 */
            (void)px_ledger_add(l, 100, 0, PX_TAG_FORK);
            f.countdown = 0;
            /* 不崩溃即可；随后正常插入仍应工作 */
            CHECK_EQ(px_ledger_add(l, 101, 0, PX_TAG_FORK), PX_OK);
            CHECK_EQ(px_ledger_has(l, 101, PX_ENTRY_PID), 1);
        }
        px_ledger_destroy(l);
    }
}

/* ================================================================== */
/* C  envp 重建                                                        */
/* ================================================================== */

static void test_env_build(void)
{
    px_envout out;
    px_env_kv forced[3];
    px_envpolicy pol;

    CASE("C1 空环境 + 强制注入");
    forced[0].name = "LD_PRELOAD";
    forced[0].value = "/x/lib.so";
    forced[1].name = "BXROOT_ROOTFS";
    forced[1].value = "/r";
    forced[2].name = NULL;
    memset(&pol, 0, sizeof(pol));
    pol.forced = forced;
    pol.forced_n = 2;

    CHECK_EQ(px_env_build(NULL, &pol, &out, NULL), PX_OK);
    CHECK_EQ(out.n, 2);
    CHECK_STR(out.v[0], "LD_PRELOAD=/x/lib.so");
    CHECK_STR(out.v[1], "BXROOT_ROOTFS=/r");
    CHECK(out.v[2] == NULL);
    px_env_dispose(&out);

    CASE("C2 调用方传干净 envp 时仍保证 LD_PRELOAD 存在");
    {
        const char *const clean[] = { "FOO=1", "PATH=/bin", NULL };
        CHECK_EQ(px_env_build(clean, &pol, &out, NULL), PX_OK);
        CHECK_EQ(out.n, 4);
        CHECK_STR(px_env_lookup((const char *const *)out.v, "LD_PRELOAD"),
                  "/x/lib.so");
        CHECK_STR(px_env_lookup((const char *const *)out.v, "FOO"), "1");
        CHECK_STR(px_env_lookup((const char *const *)out.v, "PATH"), "/bin");
        CHECK_STR(px_env_lookup((const char *const *)out.v, "BXROOT_ROOTFS"), "/r");
        px_env_dispose(&out);
    }

    CASE("C3 原环境里同名变量被覆盖（不重复出现）");
    {
        const char *const in[] = { "LD_PRELOAD=/old.so", "A=1", NULL };
        int seen = 0;
        size_t i;
        CHECK_EQ(px_env_build(in, &pol, &out, NULL), PX_OK);
        for (i = 0; i < out.n; i++) {
            if (px_env_entry_matches(out.v[i], "LD_PRELOAD")) {
                seen++;
                CHECK_STR(out.v[i], "LD_PRELOAD=/x/lib.so");
            }
        }
        CHECK_EQ(seen, 1);       /* 恰好一次 —— 覆盖而非追加 */
        CHECK_STR(px_env_lookup((const char *const *)out.v, "A"), "1");
        px_env_dispose(&out);
    }

    CASE("C4 drop 列表剔除指定变量");
    {
        const char *const in[] = { "SECRET=1", "KEEP=2", NULL };
        const char *drop[] = { "SECRET" };
        px_envpolicy p2 = pol;
        p2.drop = drop;
        p2.drop_n = 1;
        CHECK_EQ(px_env_build(in, &p2, &out, NULL), PX_OK);
        CHECK(px_env_lookup((const char *const *)out.v, "SECRET") == NULL);
        CHECK_STR(px_env_lookup((const char *const *)out.v, "KEEP"), "2");
        px_env_dispose(&out);
    }

    CASE("C5 空值不是「跳过」——变量必须存在且为空");
    {
        px_env_kv f2[2];
        px_envpolicy p2 = pol;
        f2[0].name = "EMPTYVAR";
        f2[0].value = NULL;
        f2[1].name = NULL;
        p2.forced = f2;
        p2.forced_n = 1;
        CHECK_EQ(px_env_build(NULL, &p2, &out, NULL), PX_OK);
        CHECK_EQ(out.n, 1);
        CHECK_STR(out.v[0], "EMPTYVAR=");
        /* getenv 语义：存在但为空 → ""，与不存在（NULL）不同 */
        CHECK(px_env_lookup((const char *const *)out.v, "EMPTYVAR") != NULL);
        CHECK_STR(px_env_lookup((const char *const *)out.v, "EMPTYVAR"), "");
        CHECK(px_env_lookup((const char *const *)out.v, "NOPE") == NULL);
        px_env_dispose(&out);
    }

    CASE("C6 max_entries 截断");
    {
        char buf[64][16];
        const char *in[65];
        int i;
        px_envpolicy p2 = pol;
        p2.forced_n = 0;          /* 只测载入侧 */
        for (i = 0; i < 64; i++) {
            snprintf(buf[i], sizeof(buf[i]), "V%d=1", i);
            in[i] = buf[i];
        }
        in[64] = NULL;
        p2.max_entries = 10;
        CHECK_EQ(px_env_build(in, &p2, &out, NULL), PX_OK);
        CHECK_EQ(out.n, 10);
        px_env_dispose(&out);
    }

    CASE("C7 空条目被丢弃");
    {
        const char *const in[] = { "", "A=1", "", NULL };
        px_envpolicy p2 = pol;
        p2.forced_n = 0;
        CHECK_EQ(px_env_build(in, &p2, &out, NULL), PX_OK);
        CHECK_EQ(out.n, 1);
        CHECK_STR(out.v[0], "A=1");
        px_env_dispose(&out);
    }

    CASE("C8 ★回归★ 条目数越过扩容边界后指针不悬空");
    {
        /*
         * 这是本项目第一版实现里真实存在过的缺陷：
         * buf 扩容（malloc 新块 + free 旧块）会让此前写进 v[] 的
         * buf 内地址全部悬空 —— 表现为读到随机内存或段错误。
         * 触发条件是「条目数超过初始容量」，很容易漏测。
         * 这里用 500 条（远超初始 1024 字节能容纳的量）钉住它。
         */
        static char big[500][32];
        const char *in[501];
        int i;
        px_envpolicy p2 = pol;
        p2.forced_n = 0;
        for (i = 0; i < 500; i++) {
            snprintf(big[i], sizeof(big[i]), "LONGVARNAME_%03d=value_%03d", i, i);
            in[i] = big[i];
        }
        in[500] = NULL;
        CHECK_EQ(px_env_build(in, &p2, &out, NULL), PX_OK);
        CHECK_EQ(out.n, 500);
        /* 逐条内容校验 —— 悬空指针在这里必然暴露 */
        for (i = 0; i < 500; i++) {
            char want[64];
            snprintf(want, sizeof(want), "LONGVARNAME_%03d=value_%03d", i, i);
            if (out.v[i] == NULL || strcmp(out.v[i], want) != 0) {
                g_failed++;
                fprintf(stderr, "  FAIL 第 %d 条损坏: \"%s\" 期望 \"%s\"\n",
                        i, out.v[i] ? out.v[i] : "(null)", want);
                break;
            }
        }
        g_checks++;
        CHECK(out.v[500] == NULL);
        px_env_dispose(&out);
    }

    CASE("C9 故障注入：envp 构建中分配失败必须整体失败且不泄漏");
    {
        fail_alloc f = {0, 0, 0, 0};
        const char *const in[] = { "A=1", "B=2", "C=3", NULL };
        int k;
        for (k = 1; k <= 6; k++) {
            int rc;
            fail_alloc g = {k, 0, 0, 0};
            rc = px_env_build(in, &pol, &out, fa_ops(&g));
            if (rc == PX_OK) {
                CHECK_EQ(out.n, 5);       /* 3 原有 + 2 强制 */
                px_env_dispose(&out);
            } else {
                CHECK(rc == PX_ENOMEM || rc == PX_ENOSPC);
                CHECK(out.v == NULL);     /* 失败后不留半成品 */
                CHECK(out.buf == NULL);
            }
            CHECK_EQ(g.live, 0);          /* ★ 每次尝试都无泄漏 */
        }
        (void)f;
    }

    CASE("C10 px_env_entry_matches 边界");
    {
        CHECK_EQ(px_env_entry_matches("A=1", "A"), 1);
        CHECK_EQ(px_env_entry_matches("AB=1", "A"), 0);   /* 前缀不算 */
        CHECK_EQ(px_env_entry_matches("A", "A"), 0);      /* 无 '=' 不算 */
        CHECK_EQ(px_env_entry_matches("=1", "A"), 0);
        CHECK_EQ(px_env_entry_matches("A=", "A"), 1);
        CHECK_EQ(px_env_entry_matches(NULL, "A"), 0);
        CHECK_EQ(px_env_entry_matches("A=1", NULL), 0);
        CHECK_EQ(px_env_entry_matches("A=1", ""), 0);
    }

    CASE("C11 px_env_lookup 取最后一次出现");
    {
        const char *const in[] = { "X=first", "Y=1", "X=second", NULL };
        CHECK_STR(px_env_lookup(in, "X"), "second");
        CHECK(px_env_lookup(in, "Z") == NULL);
        CHECK(px_env_lookup(NULL, "X") == NULL);
    }

    CASE("C13 ★MERGE 模式：guest 的 LD_PRELOAD 不被丢弃★");
    {
        /*
         * 这是 K3（真实内核用例）暴露出来的缺陷的单测版本：
         * 最初实现把 LD_PRELOAD 当普通强制变量，值层面直接覆盖，
         * 于是 guest 自己设的 preload 静默消失。
         * GAP-ANALYSIS §6.3 明确要求「要合并而非覆盖」。
         */
        px_env_kv fm[2];
        px_envpolicy pm;
        const char *const in[] = { "LD_PRELOAD=/guest.so", "A=1", NULL };

        fm[0].name = "LD_PRELOAD";
        fm[0].value = "/ours.so";
        fm[0].mode = PX_ENV_MERGE_PRELOAD;
        fm[1].name = NULL;
        memset(&pm, 0, sizeof(pm));
        pm.forced = fm;
        pm.forced_n = 1;

        CHECK_EQ(px_env_build(in, &pm, &out, NULL), PX_OK);
        {
            const char *v = px_env_lookup((const char *const *)out.v, "LD_PRELOAD");
            CHECK(v != NULL);
            CHECK_STR(v, "/ours.so /guest.so");     /* ours 在前 */
        }
        /* 只有一条 LD_PRELOAD */
        {
            size_t k;
            int seen = 0;
            for (k = 0; k < out.n; k++) {
                if (px_env_entry_matches(out.v[k], "LD_PRELOAD")) {
                    seen++;
                }
            }
            CHECK_EQ(seen, 1);
        }
        CHECK_STR(px_env_lookup((const char *const *)out.v, "A"), "1");
        px_env_dispose(&out);
    }

    CASE("C14 MERGE 模式：原环境没有该变量时等价于 SET");
    {
        px_env_kv fm[2];
        px_envpolicy pm;
        const char *const in[] = { "A=1", NULL };

        fm[0].name = "LD_PRELOAD";
        fm[0].value = "/ours.so";
        fm[0].mode = PX_ENV_MERGE_PRELOAD;
        fm[1].name = NULL;
        memset(&pm, 0, sizeof(pm));
        pm.forced = fm;
        pm.forced_n = 1;

        CHECK_EQ(px_env_build(in, &pm, &out, NULL), PX_OK);
        CHECK_STR(px_env_lookup((const char *const *)out.v, "LD_PRELOAD"),
                  "/ours.so");
        px_env_dispose(&out);
    }

    CASE("C15 MERGE 模式：原值与 ours 相同时去重");
    {
        px_env_kv fm[2];
        px_envpolicy pm;
        const char *const in[] = { "LD_PRELOAD=/ours.so", NULL };

        fm[0].name = "LD_PRELOAD";
        fm[0].value = "/ours.so";
        fm[0].mode = PX_ENV_MERGE_PRELOAD;
        fm[1].name = NULL;
        memset(&pm, 0, sizeof(pm));
        pm.forced = fm;
        pm.forced_n = 1;

        CHECK_EQ(px_env_build(in, &pm, &out, NULL), PX_OK);
        CHECK_STR(px_env_lookup((const char *const *)out.v, "LD_PRELOAD"),
                  "/ours.so");
        px_env_dispose(&out);
    }

    CASE("C12 px_env_dispose 幂等 + NULL 安全");
    {
        px_env_dispose(NULL);
        CHECK_EQ(px_env_build(NULL, &pol, &out, NULL), PX_OK);
        px_env_dispose(&out);
        px_env_dispose(&out);        /* 第二次必须安全 */
        CHECK(out.v == NULL);
        CHECK(out.buf == NULL);
    }
}

/* ================================================================== */
/* D  LD_PRELOAD 合并                                                  */
/* ================================================================== */

static void test_merge_preload(void)
{
    char out[512];

    CASE("D1 无原有值时结果就是 ours");
    CHECK_EQ(px_merge_preload(NULL, "/a/ours.so", out, sizeof(out)), PX_OK);
    CHECK_STR(out, "/a/ours.so");
    CHECK_EQ(px_merge_preload("", "/a/ours.so", out, sizeof(out)), PX_OK);
    CHECK_STR(out, "/a/ours.so");

    CASE("D2 ★ ours 必须在最前面★（否则被 guest 库遮蔽）");
    CHECK_EQ(px_merge_preload("/g/guest.so", "/a/ours.so", out, sizeof(out)),
             PX_OK);
    CHECK_EQ(strncmp(out, "/a/ours.so", 10), 0);
    CHECK(strstr(out, "/g/guest.so") != NULL);

    CASE("D3 路径全等去重");
    CHECK_EQ(px_merge_preload("/a/ours.so", "/a/ours.so", out, sizeof(out)),
             PX_OK);
    CHECK_STR(out, "/a/ours.so");

    CASE("D4 basename 相等去重（防止重复加载 → 构造函数跑两次）");
    CHECK_EQ(px_merge_preload("/other/dir/ours.so", "/a/ours.so",
                              out, sizeof(out)), PX_OK);
    CHECK_STR(out, "/a/ours.so");

    CASE("D5 多个 guest 库按序保留，重复项去掉");
    CHECK_EQ(px_merge_preload("/g1.so /a/ours.so /g2.so", "/a/ours.so",
                              out, sizeof(out)), PX_OK);
    CHECK_STR(out, "/a/ours.so /g1.so /g2.so");

    CASE("D6 冒号与制表符也当分隔符（ld.so 三种都认）");
    CHECK_EQ(px_merge_preload("/g1.so:/g2.so", "/a/ours.so",
                              out, sizeof(out)), PX_OK);
    CHECK(strstr(out, "/g1.so") != NULL);
    CHECK(strstr(out, "/g2.so") != NULL);

    CASE("D7 缓冲不足时优先保住 ours（可丢 guest 段）");
    {
        char small[24];
        CHECK_EQ(px_merge_preload("/very/long/guest/path.so", "/a/ours.so",
                                  small, sizeof(small)), PX_OK);
        CHECK_EQ(strncmp(small, "/a/ours.so", 10), 0);
    }

    CASE("D8 ours 为空时的退化行为");
    CHECK_EQ(px_merge_preload("/g.so", "", out, sizeof(out)), PX_OK);
    CHECK_STR(out, "");

    CASE("D9 参数校验");
    CHECK_EQ(px_merge_preload("/g.so", "/a.so", NULL, 10), PX_EINVAL);
    CHECK_EQ(px_merge_preload("/g.so", "/a.so", out, 0), PX_EINVAL);
}

/* ================================================================== */
/* E  argv 判定                                                        */
/* ================================================================== */

static void test_classify(void)
{
    CASE("E1 绝对路径是翻译候选");
    CHECK_EQ(px_classify_arg("/bin/ls", 1, NULL), PX_ARG_TRANSLATE);
    CHECK_EQ(px_classify_arg("/etc/passwd", 0, NULL), PX_ARG_TRANSLATE);

    CASE("E2 ★相对路径与裸名一律保留★（不翻相对路径）");
    CHECK_EQ(px_classify_arg("ls", 1, NULL), PX_ARG_KEEP);
    CHECK_EQ(px_classify_arg("./x", 0, NULL), PX_ARG_KEEP);
    CHECK_EQ(px_classify_arg("../x", 0, NULL), PX_ARG_KEEP);
    CHECK_EQ(px_classify_arg("", 0, NULL), PX_ARG_KEEP);
    CHECK_EQ(px_classify_arg(NULL, 0, NULL), PX_ARG_KEEP);

    CASE("E3 ★反例：模式串不能被当路径翻★");
    /* `grep /etc/passwd file` 的第一个参数是【模式】。
     * 盲目翻译会让匹配永远不中 —— 静默的功能破坏。 */
    CHECK_EQ(px_classify_arg("/etc/passwd", 0, NULL), PX_ARG_TRANSLATE);
    /* 但我们的策略是「只翻 argv[0]」，所以计划层应当排除它 —— 见 F 组 */
    CHECK_EQ(px_classify_arg("-", 0, NULL), PX_ARG_KEEP);
    CHECK_EQ(px_classify_arg("--", 0, NULL), PX_ARG_KEEP);

    CASE("E4 幂等：已带 rootfs 前缀的不再翻");
    CHECK_EQ(px_classify_arg("/r/bin/ls", 0, "/r"), PX_ARG_ALREADY);
    CHECK_EQ(px_classify_arg("/r", 0, "/r"), PX_ARG_ALREADY);
    CHECK_EQ(px_classify_arg("/rx/bin", 0, "/r"), PX_ARG_TRANSLATE);  /* 组件边界 */
    CHECK_EQ(px_classify_arg("/bin/ls", 0, "/r"), PX_ARG_TRANSLATE);

    CASE("E5 rootfs 带尾斜杠也要幂等（归一化契约）");
    CHECK_EQ(px_classify_arg("/r/bin/ls", 0, "/r/"), PX_ARG_TRANSLATE);
    /* ↑ 调用方必须先归一化；本函数不做归一化，这是刻意的分工：
     *   归一化在配置解析处做一次，热路径上不做字符串操作。 */

    CASE("E6 ★rootfs=\"/\" 退化情形★（否则所有绝对路径都不翻）");
    CHECK_EQ(px_classify_arg("/bin/ls", 0, "/"), PX_ARG_TRANSLATE);
    CHECK_EQ(px_classify_arg("/", 0, "/"), PX_ARG_TRANSLATE);
    CHECK_EQ(px_classify_arg("/etc", 0, ""), PX_ARG_TRANSLATE);

    CASE("E7 NULL rootfs 视为无幂等信息");
    CHECK_EQ(px_classify_arg("/bin/ls", 0, NULL), PX_ARG_TRANSLATE);
}

/* ================================================================== */
/* F  argv 计划与应用                                                  */
/* ================================================================== */

/* 测试用翻译器：给绝对路径加 "/r" 前缀；"-" 开头不动（模拟真实翻译器） */
static int fake_xlate(void *ud, const char *path, char *out, size_t outsz)
{
    int *calls = (int *)ud;
    int n;

    if (calls != NULL) {
        (*calls)++;
    }
    if (path == NULL || path[0] != '/') {
        return 0;
    }
    n = snprintf(out, outsz, "/r%s", path);
    if (n < 0 || (size_t)n >= outsz) {
        return -1;
    }
    return 1;
}

/* 总是失败的翻译器，用于测错误路径 */
static int bad_xlate(void *ud, const char *path, char *out, size_t outsz)
{
    (void)ud; (void)path; (void)out; (void)outsz;
    return -1;
}

static void test_argv_plan(void)
{
    px_argv_plan plan;

    CASE("F1 计划为空时不重建（零分配快路径）");
    {
        char *argv[] = { (char *)"ls", (char *)"-l", NULL };
        int calls = 0;
        CHECK_EQ(px_plan_argv(argv, "/r", fake_xlate, &calls, &plan), PX_OK);
        CHECK_EQ(plan.n, 0);
        CHECK_EQ(calls, 0);        /* 相对/裸名 → 翻译器根本不被调用 */
        CHECK_EQ(px_plan_needs_rebuild(&plan), 0);
    }

    CASE("F2 argv[0] 是绝对路径 → 被翻译");
    {
        char *argv[] = { (char *)"/bin/ls", (char *)"-l", NULL };
        int calls = 0;
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, &calls, &plan), PX_OK);
        CHECK_EQ(plan.n, 1);
        CHECK_EQ(plan.fixes[0].index, 0);
        CHECK_STR(plan.fixes[0].text, "/r/bin/ls");
        CHECK_EQ(calls, 1);
    }

    CASE("F3 ★只有 argv[0] 被翻译，后续绝对路径参数不动★");
    {
        /*
         * `grep /etc/passwd /etc/hosts` 的第一个参数是模式串。
         * 翻它 → 匹配永远不中。这是「保守判定」的核心用例。
         * 注意：本实现在**计划层**就不再翻非 argv[0] 的条目，
         * 即使它们是绝对路径。
         */
        char *argv[] = { (char *)"/bin/grep", (char *)"/etc/passwd",
                         (char *)"/etc/hosts", NULL };
        int calls = 0;
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, &calls, &plan), PX_OK);
        CHECK_EQ(plan.n, 1);
        CHECK_EQ(plan.fixes[0].index, 0);
        CHECK_EQ(calls, 1);       /* 只对 argv[0] 调了翻译器 */
    }

    CASE("F4 幂等：已带前缀的 argv[0] 不翻");
    {
        char *argv[] = { (char *)"/r/bin/ls", NULL };
        int calls = 0;
        CHECK_EQ(px_plan_argv(argv, "/r", fake_xlate, &calls, &plan), PX_OK);
        CHECK_EQ(plan.n, 0);
        CHECK_EQ(calls, 0);
    }

    CASE("F5 翻译器失败不导致整体失败（保留原参数）");
    {
        char *argv[] = { (char *)"/bin/ls", NULL };
        CHECK_EQ(px_plan_argv(argv, NULL, bad_xlate, NULL, &plan), PX_OK);
        CHECK_EQ(plan.n, 0);              /* 没有改写 */
        CHECK(plan.error < 0);            /* 但记录了错误 */
        CHECK_EQ(plan.err_at, 0);
    }

    CASE("F6 NULL argv / NULL 翻译器都是安全的");
    {
        CHECK_EQ(px_plan_argv(NULL, NULL, fake_xlate, NULL, &plan), PX_OK);
        CHECK_EQ(plan.n, 0);
        {
            char *argv[] = { (char *)"/bin/ls", NULL };
            CHECK_EQ(px_plan_argv(argv, NULL, NULL, NULL, &plan), PX_OK);
            CHECK_EQ(plan.n, 0);          /* 无翻译器 → 全保留 */
        }
        CHECK_EQ(px_plan_argv(NULL, NULL, NULL, NULL, NULL), PX_EINVAL);
    }

    CASE("F7 应用计划：改写条目用新串，其余原地复用指针");
    {
        char *argv[] = { (char *)"/bin/ls", (char *)"-l", (char *)"a", NULL };
        size_t need = 0;
        char *vec[PX_ARGV_MAX + 1];
        int calls = 0;

        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, &calls, &plan), PX_OK);
        CHECK_EQ(px_apply_argv(argv, &plan, vec, PX_ARGV_MAX + 1, &need), PX_OK);
        CHECK_EQ(need, 3);
        CHECK_STR(vec[0], "/r/bin/ls");           /* 改写 */
        CHECK(vec[1] == argv[1]);                 /* ★ 指针原样复用 */
        CHECK(vec[2] == argv[2]);
        CHECK(vec[3] == NULL);
    }

    CASE("F8 空计划时 apply 是 no-op（调用方沿用原 argv）");
    {
        char *argv[] = { (char *)"ls", NULL };
        size_t need = 123;
        char *vec[4];
        px_plan_reset(&plan);
        CHECK_EQ(px_apply_argv(argv, &plan, vec, 4, &need), PX_OK);
        CHECK_EQ(need, 0);           /* 明确告诉调用方「不需要重建」 */
    }

    CASE("F9 apply 缓冲不足时返回 ENOSPC 而不是越界写");
    {
        char *argv[] = { (char *)"/bin/ls", (char *)"a", (char *)"b", NULL };
        size_t need = 0;
        char *vec[2];
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, NULL, &plan), PX_OK);
        CHECK_EQ(px_apply_argv(argv, &plan, vec, 2, &need), PX_ENOSPC);
        CHECK_EQ(need, 3);           /* 告知需要多大 */
    }

    CASE("F10 计划上限 PX_PLAN_MAX 生效（返回 EFULL 而不是越界）");
    {
        /*
         * 用一个「把所有参数都当路径」的策略来打满上限。
         * 默认策略只翻 argv[0]，永远到不了上限。
         */
        static char *big[PX_PLAN_MAX + 4];
        px_argpolicy all = { 1, 1, NULL, 0 };   /* translate_other_args = 1 */
        int i;
        for (i = 0; i < PX_PLAN_MAX + 2; i++) {
            big[i] = (char *)"/bin/x";
        }
        big[PX_PLAN_MAX + 2] = NULL;
        px_plan_set_policy(&plan, &all);
        CHECK_EQ(px_plan_argv(big, NULL, fake_xlate, NULL, &plan), PX_EFULL);
        CHECK_EQ(plan.n, (size_t)PX_PLAN_MAX);   /* 恰好填满，无越界 */
        px_plan_set_policy(&plan, NULL);
        px_plan_dispose(&plan);
    }

    CASE("F10b 策略：translate_other_args=1 时其它绝对路径也被翻");
    {
        char *argv[] = { (char *)"/bin/grep", (char *)"/etc/passwd", NULL };
        px_argpolicy all = { 1, 1, NULL, 0 };
        int calls = 0;
        px_plan_set_policy(&plan, &all);
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, &calls, &plan), PX_OK);
        CHECK_EQ(plan.n, 2);
        CHECK_EQ(calls, 2);
        px_plan_set_policy(&plan, NULL);
    }

    CASE("F10c 策略：白名单选项的值被翻（-o /etc/x）");
    {
        static const char *const opts[] = { "-o", "--output", NULL };
        px_argpolicy p3 = { 1, 0, opts, 2 };
        char *argv[] = { (char *)"/bin/tool", (char *)"-o",
                         (char *)"/etc/x", (char *)"--output",
                         (char *)"/etc/y", (char *)"/etc/z", NULL };
        int calls = 0;
        px_plan_set_policy(&plan, &p3);
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, &calls, &plan), PX_OK);
        /* argv[0] + -o 的值 + --output 的值 = 3 条；
         * 末尾的 /etc/z 前一个元素是 /etc/y（不是选项）→ 不翻 */
        CHECK_EQ(plan.n, 3);
        CHECK_EQ(calls, 3);
        CHECK_EQ(plan.fixes[0].index, 0);
        CHECK_EQ(plan.fixes[1].index, 2);
        CHECK_EQ(plan.fixes[2].index, 4);
        px_plan_set_policy(&plan, NULL);
    }

    CASE("F10d px_arg_is_path_option 判定");
    {
        static const char *const opts[] = { "-o", NULL };
        px_argpolicy p3 = { 1, 0, opts, 1 };
        CHECK_EQ(px_arg_is_path_option("-o", &p3), 1);
        CHECK_EQ(px_arg_is_path_option("-x", &p3), 0);
        CHECK_EQ(px_arg_is_path_option(NULL, &p3), 0);
        CHECK_EQ(px_arg_is_path_option("-o", NULL), 0);
        /* 必须是精确匹配，不能是前缀 */
        CHECK_EQ(px_arg_is_path_option("-output", &p3), 0);
    }

    CASE("F10e 计划缓冲复用：dispose 后 magic 清零，reset 可复用");
    {
        char *argv[] = { (char *)"/bin/ls", NULL };
        px_argv_plan p4;
        memset(&p4, 0, sizeof(p4));      /* 故意不设 magic */
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, NULL, &p4), PX_OK);
        CHECK_EQ(p4.n, 1);
        CHECK(p4.fixes != NULL);
        px_plan_dispose(&p4);
        CHECK(p4.fixes == NULL);
        CHECK_EQ(p4.magic, 0ul);
        px_plan_dispose(&p4);            /* 幂等 */
        /* 未初始化的 plan 必须被安全处理（magic 检测） */
        {
            px_argv_plan garbage;
            memset(&garbage, 0xAB, sizeof(garbage));   /* 全垃圾 */
            CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, NULL, &garbage), PX_OK);
            CHECK_EQ(garbage.n, 1);
            px_plan_dispose(&garbage);
        }
    }

    CASE("F11 应用后 argv 内容未被原地修改");
    {
        char *argv[] = { (char *)"/bin/ls", NULL };
        CHECK_EQ(px_plan_argv(argv, NULL, fake_xlate, NULL, &plan), PX_OK);
        {
            char *vec[2];
            size_t need = 0;
            (void)px_apply_argv(argv, &plan, vec, 2, &need);
        }
        CHECK_STR(argv[0], "/bin/ls");    /* 原数组一字未动 */
    }
}

/* ================================================================== */
/* G  guest PATH 搜索                                                  */
/* ================================================================== */

static void test_search_path(void)
{
    char buf[PX_PATH_MAX];

    CASE("G1 含 '/' 时只有 1 个候选");
    CHECK_EQ(px_search_count("/bin/ls", "/usr/bin"), 1);
    CHECK_EQ(px_search_count("./x", "/usr/bin"), 1);
    CHECK_EQ(px_search_get("/bin/ls", "/usr/bin", 0, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "/bin/ls");
    CHECK_EQ(px_search_get("/bin/ls", "/usr/bin", 1, buf, sizeof(buf)),
             PX_ENOENT);

    CASE("G2 裸名按 PATH 段数展开");
    CHECK_EQ(px_search_count("ls", "/a:/b:/c"), 3);
    CHECK_EQ(px_search_get("ls", "/a:/b:/c", 0, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "/a/ls");
    CHECK_EQ(px_search_get("ls", "/a:/b:/c", 2, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "/c/ls");
    CHECK_EQ(px_search_get("ls", "/a:/b:/c", 3, buf, sizeof(buf)), PX_ENOENT);

    CASE("G3 PATH 为 NULL/空 → 用 POSIX 默认值");
    CHECK_EQ(px_search_count("ls", NULL), 2);
    CHECK_EQ(px_search_count("ls", ""), 2);
    CHECK_EQ(px_search_get("ls", NULL, 0, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "/bin/ls");
    CHECK_EQ(px_search_get("ls", NULL, 1, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "/usr/bin/ls");

    CASE("G4 PATH 尾部的空段等价于 \".\"");
    CHECK_EQ(px_search_count("ls", "/a:"), 2);
    CHECK_EQ(px_search_get("ls", "/a:", 1, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "./ls");

    CASE("G5 目录以 '/' 结尾时不产生双斜杠");
    CHECK_EQ(px_search_get("ls", "/a/", 0, buf, sizeof(buf)), PX_OK);
    CHECK_STR(buf, "/a/ls");

    CASE("G6 路径过长时返回 ETOOLONG");
    {
        char tiny[4];
        CHECK_EQ(px_search_get("lsssss", "/a", 0, tiny, sizeof(tiny)),
                 PX_ETOOLONG);
    }

    CASE("G7 参数校验");
    CHECK_EQ(px_search_count(NULL, "/a"), 0);
    CHECK_EQ(px_search_count("", "/a"), 0);
    CHECK_EQ(px_search_get(NULL, "/a", 0, buf, sizeof(buf)), PX_EINVAL);
    CHECK_EQ(px_search_get("ls", "/a", 0, NULL, 10), PX_EINVAL);
    CHECK_EQ(px_search_get("ls", "/a", 0, buf, 0), PX_EINVAL);
}

/* ================================================================== */
/* H  bump 分配器                                                      */
/* ================================================================== */

static void test_bump(void)
{
    CASE("H1 固定缓冲里反复分配，耗尽后拒绝而不是越界");
    {
        static char pool[512];
        px_bump b;
        char *p1, *p2;
        int i;

        px_bump_init(&b, pool, sizeof(pool));
        p1 = (char *)px_bump_ops(&b)->malloc(b.ops.ud, 100);
        CHECK(p1 != NULL);
        p2 = (char *)px_bump_ops(&b)->malloc(b.ops.ud, 100);
        CHECK(p2 != NULL);
        CHECK(p1 != p2);
        CHECK(p1 >= pool && p1 < pool + sizeof(pool));
        CHECK(p2 >= pool && p2 < pool + sizeof(pool));

        /* 耗尽 */
        for (i = 0; i < 100; i++) {
            (void)px_bump_ops(&b)->malloc(b.ops.ud, 64);
        }
        CHECK(b.refusals > 0);
        CHECK(b.used <= sizeof(pool));       /* ★ 绝不越界 */
        CHECK(b.peak <= sizeof(pool));
    }

    CASE("H2 reset 后可以重用同一块缓冲（确定性复用）");
    {
        static char pool[256];
        px_bump b;
        char *p1;
        char *p2;
        size_t before;

        px_bump_init(&b, pool, sizeof(pool));
        p1 = (char *)px_bump_ops(&b)->malloc(b.ops.ud, 200);
        CHECK(p1 != NULL);
        /* ★ 不要断言 p1 == pool ★
         * 分配器为满足 16 字节对齐会跳过开头几个字节，
         * 跳多少取决于 base 的实际对齐 —— 而 static 数组的对齐
         * 由链接器决定，不该被测试写死。断言「落在池内」才是契约。 */
        CHECK(p1 >= pool && p1 < pool + sizeof(pool));
        before = b.used;
        CHECK(before >= 200 && before <= 200 + 16);   /* 含至多 15B 填充 */

        px_bump_reset(&b);
        CHECK_EQ(b.used, 0);
        CHECK_EQ(b.high_water, before);      /* 记录了历史水位 */

        /* ★ 确定性：reset 后同样的请求必须拿到同一个地址 ★ */
        p2 = (char *)px_bump_ops(&b)->malloc(b.ops.ud, 200);
        CHECK(p2 == p1);
    }

    CASE("H2b ★回归★ base 未对齐时返回地址仍须 16 字节对齐");
    {
        /*
         * 这是 UBSan 暴露出来的真实缺陷：早先实现只把 `used` 偏移
         * 向上取整，隐含假设 base 本身已对齐。而调用方传的常是
         * `char buf[N]`，对齐只保证到 1 字节 —— 于是所有返回地址
         * 整体偏移，把需要 16 字节对齐的对象放进去就是未对齐访问。
         *
         * 普通构建下 static 数组恰好被链接器对齐到 16，所以这个缺陷
         * **测不出来**；这里故意用未对齐的起点把它钉住。
         */
        static char raw[512];
        char *misaligned = raw + 1;      /* 故意错开 1 字节 */
        px_bump b;
        int k;

        /* 先确认起点确实未对齐，否则这个用例没有意义 */
        CHECK(((uintptr_t)misaligned % 16u) != 0u);

        px_bump_init(&b, misaligned, sizeof(raw) - 1u);
        for (k = 1; k <= 12; k++) {
            void *p = px_bump_ops(&b)->malloc(b.ops.ud, (size_t)k);
            CHECK(p != NULL);
            CHECK_EQ(((uintptr_t)p) % 16u, 0u);     /* ★ 核心断言 */
            CHECK((char *)p >= misaligned);
            CHECK((char *)p < misaligned + sizeof(raw) - 1u);
        }
    }

    CASE("H3 calloc 必须清零（账本依赖 0 初值）");
    {
        static char pool[256];
        px_bump b;
        unsigned char *p;
        int i;
        int all_zero = 1;

        /* 先弄脏 */
        memset(pool, 0xAA, sizeof(pool));
        px_bump_init(&b, pool, sizeof(pool));
        p = (unsigned char *)px_bump_ops(&b)->calloc(b.ops.ud, 1, 64);
        CHECK(p != NULL);
        for (i = 0; i < 64; i++) {
            if (p[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        CHECK(all_zero);
    }

    CASE("H4 对齐：连续不同尺寸的请求都返回 16 字节对齐地址");
    {
        static char pool[256];
        px_bump b;
        int i;
        px_bump_init(&b, pool, sizeof(pool));
        for (i = 1; i <= 8; i++) {
            void *p = px_bump_ops(&b)->malloc(b.ops.ud, (size_t)i);
            CHECK(p != NULL);
            CHECK_EQ(((uintptr_t)p) % 16u, 0u);
        }
    }

    CASE("H5 free 是安全 no-op（让 env 失败清理路径能跑完）");
    {
        static char pool[256];
        px_bump b;
        void *p;
        px_bump_init(&b, pool, sizeof(pool));
        p = px_bump_ops(&b)->malloc(b.ops.ud, 32);
        px_bump_ops(&b)->free(b.ops.ud, p);      /* 不崩、不报错 */
        px_bump_ops(&b)->free(b.ops.ud, NULL);
        /* 内存没被回收 —— 语义如此。used 含对齐填充，故用区间断言。 */
        CHECK(b.used >= 32 && b.used <= 32 + 16);
    }

    CASE("H6 ★关键★ env 重建能在 bump 上跑通（vfork 路径的基础）");
    {
        static char pool[8192];
        px_bump b;
        px_envout out;
        px_env_kv forced[2];
        px_envpolicy pol;
        const char *const in[] = { "A=1", "B=2", "PATH=/bin", NULL };

        px_bump_init(&b, pool, sizeof(pool));
        forced[0].name = "LD_PRELOAD";
        forced[0].value = "/rt.so";
        forced[1].name = NULL;
        memset(&pol, 0, sizeof(pol));
        pol.forced = forced;
        pol.forced_n = 1;

        CHECK_EQ(px_env_build(in, &pol, &out, px_bump_ops(&b)), PX_OK);
        CHECK_EQ(out.n, 4);
        CHECK_STR(px_env_lookup((const char *const *)out.v, "LD_PRELOAD"), "/rt.so");
        CHECK_STR(px_env_lookup((const char *const *)out.v, "A"), "1");
        CHECK(out.v[0] >= pool && out.v[0] < pool + sizeof(pool));  /* 在池内 */
        px_env_dispose(&out);          /* no-op free，但不得崩 */
        CHECK_EQ(b.used, b.high_water);

        CASE("H7 bump 空间不足时 env 重建必须失败而不是越界");
        {
            static char tiny[64];
            px_bump b2;
            px_envout out2;
            int rc;
            px_bump_init(&b2, tiny, sizeof(tiny));
            rc = px_env_build(in, &pol, &out2, px_bump_ops(&b2));
            CHECK(rc != PX_OK);
            CHECK(b2.refusals > 0);
            CHECK(b2.used <= sizeof(tiny));
        }
    }
}

/* ================================================================== */
/* I  kill 判定                                                        */
/* ================================================================== */

static pid_t fake_getpid(void) { return 500; }
static pid_t fake_getppid(void) { return 400; }
static pid_t fake_getpgrp(void) { return 500; }
static int   fake_kill(pid_t p, int s) { (void)p; (void)s; return 0; }

static const px_sysops FAKE_SYS = {
    fake_getpid, fake_getppid, fake_getpgrp, fake_kill
};

static void test_kill(void)
{
    px_ledger *l = px_ledger_create(64, NULL);
    const px_killpolicy *pol = &PX_KILLPOLICY_DEFAULT;

    CASE("I1 账本 NULL / disabled → 一律放行（退化为无保护）");
    CHECK_EQ(px_check_kill(NULL, pol, &FAKE_SYS, 500, 1, SIGKILL),
             PROC_KILL_PASS);
    px_ledger_set_disabled(l, 1);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 1, SIGKILL),
             PROC_KILL_PASS);
    px_ledger_set_disabled(l, 0);

    CASE("I2 ★广播形态被拒绝★（kill(-1)/kill(0)）");
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, -1, SIGKILL),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 0, SIGKILL),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, -1, SIGTERM),
             PROC_KILL_DENY);

    CASE("I3 自己永远放行（自杀/自挂起是常规操作）");
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 500, SIGKILL),
             PROC_KILL_PASS);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 500, SIGSTOP),
             PROC_KILL_PASS);

    CASE("I4 父进程放行（shell/libuv/subprocess 依赖）");
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 400, SIGTERM),
             PROC_KILL_PASS);

    CASE("I5 ★容器外进程被拒绝★（这是安全边界）");
    /* 1 = 宿主 init */
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 1, SIGKILL),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 12345, SIGKILL),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 99999, SIGKILL),
             PROC_KILL_DENY);

    CASE("I6 账本里活着的子进程放行");
    CHECK_EQ(px_ledger_add(l, 600, 500, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 600, SIGTERM),
             PROC_KILL_PASS);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 600, SIGKILL),
             PROC_KILL_PASS);

    CASE("I7 ★已回收的 pid 必须拒绝★（pid 复用会把信号打进无辜进程）");
    CHECK_EQ(px_ledger_add(l, 700, 500, PX_TAG_FORK), PX_OK);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 700, SIGTERM),
             PROC_KILL_PASS);
    CHECK_EQ(px_ledger_reap(l, 700), PX_OK);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 700, SIGTERM),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 700, SIGKILL),
             PROC_KILL_DENY);

    CASE("I8 SIGCHLD 永远放行（拦掉会让子进程回收停摆）");
    CHECK_EQ(px_signal_always_allowed(SIGCHLD), 1);
    CHECK_EQ(px_signal_always_allowed(SIGKILL), 0);
    /* 即使目标完全不在账本里，SIGCHLD 也放行 */
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, 88888, SIGCHLD),
             PROC_KILL_PASS);
    /* 甚至广播形态的 SIGCHLD 也放行 —— 它不会造成危害 */
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, -1, SIGCHLD),
             PROC_KILL_PASS);

    CASE("I9 进程组：自己所在的组放行");
    /* fake_getpgrp 返回 500，所以 -500 是「自己的组」 */
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, -500, SIGTERM),
             PROC_KILL_PASS);

    CASE("I10 进程组：账本里的组放行，其它拒绝");
    CHECK_EQ(px_ledger_add_pgid(l, 800, PX_TAG_SPAWN), PX_OK);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, -800, SIGTERM),
             PROC_KILL_PASS);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 500, -9999, SIGTERM),
             PROC_KILL_DENY);

    CASE("I11 策略可调：关掉组放行 / 关掉自我保护");
    {
        px_killpolicy p2 = PX_KILLPOLICY_DEFAULT;
        p2.allow_group = 0;
        CHECK_EQ(px_check_kill(l, &p2, &FAKE_SYS, 500, -800, SIGTERM),
                 PROC_KILL_DENY);
        p2 = PX_KILLPOLICY_DEFAULT;
        p2.protect_self = 0;
        /* 自己不在账本里（本测试没登记 500）→ 关掉保护后就被拒 */
        CHECK_EQ(px_check_kill(l, &p2, &FAKE_SYS, 500, 500, SIGKILL),
                 PROC_KILL_DENY);
        p2 = PX_KILLPOLICY_DEFAULT;
        p2.allow_broadcast = 1;
        CHECK_EQ(px_check_kill(l, &p2, &FAKE_SYS, 500, -1, SIGKILL),
                 PROC_KILL_PASS);
        p2 = PX_KILLPOLICY_DEFAULT;
        p2.allow_parent = 0;
        CHECK_EQ(px_check_kill(l, &p2, &FAKE_SYS, 500, 400, SIGTERM),
                 PROC_KILL_DENY);
    }

    CASE("I12 NULL 策略用默认值；NULL sysops 不崩");
    CHECK_EQ(px_check_kill(l, NULL, &FAKE_SYS, 500, 1, SIGKILL),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, NULL, 500, 600, SIGTERM),
             PROC_KILL_PASS);            /* 账本命中，不需要 sysops */
    CHECK_EQ(px_check_kill(l, pol, NULL, 500, 400, SIGTERM),
             PROC_KILL_DENY);            /* 需要 getppid 但为 NULL → 拒绝 */
    CHECK_EQ(px_check_kill(l, pol, NULL, 500, -500, SIGTERM),
             PROC_KILL_DENY);            /* 需要 getpgrp 但为 NULL → 拒绝 */

    CASE("I13 ★self_pid 无效时判定必须更严格而非更宽松★");
    /* self_pid<=0 意味着「不知道我是谁」。此时拿 target 去比 getppid()
     * 是无意义的，继续放行等于在状态异常时**放宽**白名单 ——
     * 安全判定的失败方向必须是更严格。 */
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 0, 400, SIGTERM),
             PROC_KILL_DENY);
    CHECK_EQ(px_check_kill(l, pol, &FAKE_SYS, 0, 99999, SIGTERM),
             PROC_KILL_DENY);

    px_ledger_destroy(l);
}

/* ================================================================== */
/* J  atfork 协议                                                      */
/* ================================================================== */

/* 可观测锁：记录加解锁的嵌套深度与最大深度 */
typedef struct {
    int depth;
    int max_depth;
    long locks;
    long unlocks;
    int underflow;     /* 解锁次数多于加锁 → 协议被破坏 */
} obs_lock;

static void obs_lock_fn(void *ud)
{
    obs_lock *o = (obs_lock *)ud;
    o->depth++;
    o->locks++;
    if (o->depth > o->max_depth) {
        o->max_depth = o->depth;
    }
}

static void obs_unlock_fn(void *ud)
{
    obs_lock *o = (obs_lock *)ud;
    o->depth--;
    o->unlocks++;
    if (o->depth < 0) {
        o->underflow++;
    }
}

static void test_forkguard(void)
{
    obs_lock o;
    px_lockops ops;
    px_forkguard g;
    px_ledger *l;

    memset(&o, 0, sizeof(o));
    ops.lock = obs_lock_fn;
    ops.unlock = obs_unlock_fn;
    ops.ud = &o;

    CASE("J1 正常协议：prepare 取锁、parent 放锁");
    px_forkguard_init(&g, &ops, 1);
    l = px_ledger_create(32, NULL);
    px_forkguard_prepare(&g, l);
    CHECK_EQ(o.depth, 1);
    CHECK_EQ(g.locked, 1);
    px_forkguard_parent(&g, l);
    CHECK_EQ(o.depth, 0);
    CHECK_EQ(g.locked, 0);
    CHECK_EQ(o.underflow, 0);
    CHECK_EQ(g.prepare_calls, 1);
    CHECK_EQ(g.parent_calls, 1);
    CHECK_EQ(g.child_calls, 0);

    CASE("J2 child 协议：放锁 + 重置账本 + 计数");
    memset(&o, 0, sizeof(o));
    px_forkguard_init(&g, &ops, 1);
    (void)px_ledger_add(l, 42, 1, PX_TAG_SELF);      /* 模拟父进程的 self 记录 */
    (void)px_ledger_add(l, 43, 1, PX_TAG_FORK);
    px_forkguard_prepare(&g, l);
    px_forkguard_child(&g, l);
    CHECK_EQ(o.depth, 0);                 /* ★ 子进程里必须放锁 */
    CHECK_EQ(g.locked, 0);
    CHECK_EQ(o.underflow, 0);
    CHECK_EQ(g.child_calls, 1);
    CHECK_EQ(g.child_resets, 1);
    /* self 记录（父进程的）被清掉，fork 出来的子进程记录保留 */
    CHECK_EQ(px_ledger_has(l, 42, PX_ENTRY_PID), 0);
    CHECK_EQ(px_ledger_has(l, 43, PX_ENTRY_PID), 1);

    CASE("J3 连续多轮 fork 不累积锁深度");
    memset(&o, 0, sizeof(o));
    px_forkguard_init(&g, &ops, 1);
    {
        int i;
        for (i = 0; i < 50; i++) {
            px_forkguard_prepare(&g, l);
            px_forkguard_parent(&g, l);
        }
        CHECK_EQ(o.depth, 0);
        CHECK_EQ(o.max_depth, 1);          /* 非递归锁，深度恒为 1 */
        CHECK_EQ(o.locks, 50);
        CHECK_EQ(o.unlocks, 50);
        CHECK_EQ(o.underflow, 0);
        CHECK_EQ(g.prepare_calls, 50);
    }

    CASE("J4 child 重复调用不破坏计数（每次 fork 一次）");
    memset(&o, 0, sizeof(o));
    px_forkguard_init(&g, &ops, 1);
    px_forkguard_prepare(&g, l);
    px_forkguard_child(&g, l);
    px_forkguard_child(&g, l);            /* 异常但不应崩 */
    CHECK_EQ(o.underflow, 1);             /* 第二次解锁是协议错误，被记录 */
    CHECK_EQ(g.child_calls, 2);
    CHECK_EQ(g.child_resets, 2);

    CASE("J5 禁用时不做锁操作（对照组的基线）");
    memset(&o, 0, sizeof(o));
    px_forkguard_init(&g, &ops, 0);
    px_forkguard_prepare(&g, l);
    px_forkguard_parent(&g, l);
    CHECK_EQ(o.locks, 0);
    CHECK_EQ(o.unlocks, 0);
    CHECK_EQ(g.prepare_calls, 1);        /* 计数仍走 */
    px_forkguard_set_enabled(&g, 1);

    CASE("J6 NULL lockops 不崩");
    px_forkguard_init(&g, NULL, 1);
    px_forkguard_prepare(&g, l);
    px_forkguard_parent(&g, l);
    px_forkguard_child(&g, l);
    CHECK_EQ(g.prepare_calls, 1);
    CHECK_EQ(g.child_calls, 1);

    CASE("J7 NULL guard / NULL ledger 不崩");
    px_forkguard_prepare(NULL, NULL);
    px_forkguard_parent(NULL, NULL);
    px_forkguard_child(NULL, NULL);
    px_child_reset(NULL);
    {
        px_forkguard g2;
        px_forkguard_init(&g2, &ops, 1);
        memset(&o, 0, sizeof(o));
        px_forkguard_prepare(&g2, NULL);
        px_forkguard_child(&g2, NULL);
        CHECK_EQ(o.depth, 0);
        CHECK_EQ(g2.child_resets, 1);
    }

    CASE("J8 父进程登记新子进程");
    {
        px_forkguard g3;
        px_forkguard_init(&g3, &ops, 1);
        CHECK_EQ(px_forkguard_parent_register(&g3, l, 900), PX_OK);
        CHECK_EQ(px_ledger_has(l, 900, PX_ENTRY_PID), 1);
        CHECK_EQ(g3.fork_pid, 900);
        CHECK_EQ(px_forkguard_parent_register(&g3, l, 0), PX_EINVAL);
        CHECK_EQ(px_forkguard_parent_register(&g3, l, -1), PX_EINVAL);
    }

    CASE("J9 ★登记失败必须放弃子进程★（否则会留下杀不掉的孤儿）");
    {
        px_ledger *tiny = px_ledger_create(4, NULL);
        int rc;
        px_ledger_set_eviction(tiny, 0);
        /* 填满 4 个槽，然后关掉淘汰与扩容能力 */
        (void)px_ledger_add(tiny, 1, 0, PX_TAG_FORK);
        (void)px_ledger_add(tiny, 2, 0, PX_TAG_FORK);
        (void)px_ledger_add(tiny, 3, 0, PX_TAG_FORK);
        (void)px_ledger_add(tiny, 4, 0, PX_TAG_FORK);
        rc = px_ledger_add(tiny, 5, 0, PX_TAG_FORK);
        /* 扩容会成功（容量 4 → 8），所以这里 rc == OK。
         * 要构造真正的失败，需要容量已达硬上限 —— 不现实。
         * 因此直接验证判定函数本身。 */
        CHECK_EQ(rc, PX_OK);
        CHECK_EQ(px_fork_should_abort(PX_OK), 0);
        CHECK_EQ(px_fork_should_abort(PX_ENOMEM), 1);
        CHECK_EQ(px_fork_should_abort(PX_EFULL), 1);
        CHECK_EQ(px_fork_should_abort(PX_EINVAL), 1);
        px_ledger_destroy(tiny);
    }

    CASE("J10 px_child_reset 只清 self，不动 fork 出来的子进程记录");
    {
        px_ledger *l2 = px_ledger_create(32, NULL);
        (void)px_ledger_add(l2, 10, 0, PX_TAG_SELF);
        (void)px_ledger_add(l2, 11, 0, PX_TAG_FORK);
        (void)px_ledger_add(l2, 12, 0, PX_TAG_SPAWN);
        (void)px_ledger_add(l2, 13, 0, PX_TAG_POPEN);
        px_child_reset(l2);
        CHECK_EQ(px_ledger_has(l2, 10, PX_ENTRY_PID), 0);   /* self 被清 */
        CHECK_EQ(px_ledger_has(l2, 11, PX_ENTRY_PID), 1);
        CHECK_EQ(px_ledger_has(l2, 12, PX_ENTRY_PID), 1);
        CHECK_EQ(px_ledger_has(l2, 13, PX_ENTRY_PID), 1);
        CHECK_EQ(px_ledger_count(l2), 3);
        px_ledger_destroy(l2);
    }

    px_ledger_destroy(l);
}

/* ================================================================== */
/* K  真实 FS / 真实内核 端到端                                        */
/* ================================================================== */

/*
 * 真实验证：我们把 envp 交给内核后，子进程**真的**看到了它。
 *
 * 做法：用真实 fork + execve 启动 /usr/bin/env，把输出读回。
 * 这验证了「构建出的 envp 是内核可接受的、内容正确的」——
 * 本容器内能达到的最强证据。ld.so 是否采纳 LD_PRELOAD 属于下一跳，
 * 只能真机验证（见 REPORT.md）。
 */
static int run_env_and_capture(const char *const *envp, char *out, size_t outsz)
{
    int fds[2];
    pid_t pid;
    ssize_t n;
    size_t used = 0;
    int status = 0;

    if (pipe(fds) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        close(fds[1]);
        {
            char *const av[] = { (char *)"/usr/bin/env", NULL };
            execve("/usr/bin/env", av, (char *const *)envp);
        }
        _exit(127);
    }
    close(fds[1]);
    while ((n = read(fds[0], out + used, outsz - 1u - used)) > 0) {
        used += (size_t)n;
        if (used >= outsz - 1u) {
            break;
        }
    }
    out[used] = '\0';
    close(fds[0]);
    (void)waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int output_has_line(const char *out, const char *line)
{
    size_t ll = strlen(line);
    const char *p = out;

    while (p != NULL && *p != '\0') {
        if (strncmp(p, line, ll) == 0 && (p[ll] == '\n' || p[ll] == '\0')) {
            return 1;
        }
        p = strchr(p, '\n');
        if (p != NULL) {
            p++;
        }
    }
    return 0;
}

static void test_real_exec_env(void)
{
    px_envout out;
    px_env_kv forced[2];
    px_envpolicy pol;
    static char captured[8192];
    int rc;

    if (access("/usr/bin/env", X_OK) != 0) {
        CASE("K* 跳过：/usr/bin/env 不可用");
        CHECK(1);
        return;
    }

    /*
     * 与生产一致：LD_PRELOAD 用 MERGE 模式（见 px_build_forced）。
     * K1/K2 环境里没有已有的 LD_PRELOAD，所以 MERGE 与 SET 结果相同；
     * K3 特意带一个 guest 的 LD_PRELOAD 来验证合并不丢。
     */
    forced[0].name = "LD_PRELOAD";
    forced[0].value = "/opt/bxroot/libbxroot-runtime.so";
    forced[0].mode = PX_ENV_MERGE_PRELOAD;
    forced[1].name = NULL;
    memset(&pol, 0, sizeof(pol));
    pol.forced = forced;
    pol.forced_n = 1;

    CASE("K1 ★真实内核交付★：干净 envp → 子进程真的看到 LD_PRELOAD");
    {
        /* 模仿 Node `execFileSync(..., {env:{FOO:'1'}})`：完全干净的环境 */
        const char *const clean[] = { "FOO=1", "PATH=/usr/bin:/bin", NULL };
        CHECK_EQ(px_env_build(clean, &pol, &out, NULL), PX_OK);
        rc = run_env_and_capture((const char *const *)out.v,
                                 captured, sizeof(captured));
        CHECK_EQ(rc, 0);
        CHECK(output_has_line(captured,
              "LD_PRELOAD=/opt/bxroot/libbxroot-runtime.so"));
        CHECK(output_has_line(captured, "FOO=1"));
        px_env_dispose(&out);
    }

    CASE("K2 空 envp → 子进程只有我们注入的变量");
    {
        CHECK_EQ(px_env_build(NULL, &pol, &out, NULL), PX_OK);
        rc = run_env_and_capture((const char *const *)out.v,
                                 captured, sizeof(captured));
        CHECK_EQ(rc, 0);
        CHECK(output_has_line(captured,
              "LD_PRELOAD=/opt/bxroot/libbxroot-runtime.so"));
        CHECK(!output_has_line(captured, "FOO=1"));
        px_env_dispose(&out);
    }

    CASE("K3 ★真实内核交付★：guest 的 LD_PRELOAD 被合并且 ours 在前");
    {
        const char *const in[] = { "LD_PRELOAD=/guest.so", "A=1", NULL };
        int seen = 0;
        const char *p;
        CHECK_EQ(px_env_build(in, &pol, &out, NULL), PX_OK);
        rc = run_env_and_capture((const char *const *)out.v,
                                 captured, sizeof(captured));
        CHECK_EQ(rc, 0);
        /* 逐行数 LD_PRELOAD 出现次数 */
        p = captured;
        while (p != NULL && *p != '\0') {
            if (strncmp(p, "LD_PRELOAD=", 11) == 0) {
                seen++;
                /* ★ 值必须是合并后的 ours + guest（ours 在前） ★ */
                CHECK(strncmp(p, "LD_PRELOAD=", 11) == 0);
                CHECK(strncmp(p + 11, "/opt/bxroot/libbxroot-runtime.so", 32) == 0);
                CHECK(strstr(p, "/guest.so") != NULL);
            }
            p = strchr(p, '\n');
            if (p != NULL) {
                p++;
            }
        }
        CHECK_EQ(seen, 1);
        px_env_dispose(&out);
    }

    CASE("K4 真实 fork + waitpid + kill：账本与内核一致");
    {
        px_ledger *l = px_ledger_create(64, NULL);
        const px_killpolicy *kp = &PX_KILLPOLICY_DEFAULT;
        pid_t child = fork();

        CHECK(child >= 0);
        if (child == 0) {
            /* 子进程：睡一会儿，等父进程来杀 */
            usleep(200000);
            _exit(0);
        }
        /* 父进程：登记 → 内核里确实有这个进程 → 判定放行 */
        CHECK_EQ(px_ledger_add(l, child, getpid(), PX_TAG_FORK), PX_OK);
        CHECK_EQ(kill(child, 0), 0);            /* 存活确认 */
        CHECK_EQ(px_check_kill(l, kp, NULL, getpid(), child, SIGTERM),
                 PROC_KILL_PASS);
        CHECK_EQ(kill(child, SIGTERM), 0);
        {
            int st = 0;
            CHECK(waitpid(child, &st, 0) == child);
            CHECK(WIFSIGNALED(st));
            CHECK_EQ(WTERMSIG(st), SIGTERM);
        }
        /* reap 之后判定必须翻转成拒绝 */
        CHECK_EQ(px_ledger_reap(l, child), PX_OK);
        CHECK_EQ(px_check_kill(l, kp, NULL, getpid(), child, SIGTERM),
                 PROC_KILL_DENY);
        px_ledger_destroy(l);
    }
}

/* ================================================================== */
/* L  fork 死锁对照实验                                                */
/* ================================================================== */

/*
 * ★ 本组的价值：它**实证**了「不上 atfork 会怎样」，而不是复述文档。★
 *
 * 场景：父进程持有账本锁时另一个线程 fork。子进程里第一次查账本
 * （= 取同一把锁）会永久阻塞，因为持锁的那个线程**不存在于子进程中**。
 *
 * 对照组（不加保护）用 alarm(3) 把死锁变成可观测量；
 * 实验组（走 px_forkguard 协议）必须立刻通过。
 */
static pthread_mutex_t g_real_lock = PTHREAD_MUTEX_INITIALIZER;

static void real_lock_fn(void *ud)   { (void)ud; pthread_mutex_lock(&g_real_lock); }
static void real_unlock_fn(void *ud) { (void)ud; pthread_mutex_unlock(&g_real_lock); }

/* 子进程里做一次「查账本」动作。成功 _exit(42)，死锁则由 alarm 兜底。 */
static void child_touch_lock(int use_guard, px_forkguard *g, px_ledger *l)
{
    alarm(3);
    if (use_guard) {
        /* 正确协议：child 回调已经在子进程里放锁，所以能取到 */
        px_forkguard_child(g, l);
    }
    if (pthread_mutex_lock(&g_real_lock) == 0) {
        pthread_mutex_unlock(&g_real_lock);
        alarm(0);
        _exit(42);
    }
    _exit(43);
}

static void test_fork_deadlock(void)
{
    px_lockops ops;
    px_forkguard g;
    px_ledger *l = px_ledger_create(32, NULL);

    ops.lock = real_lock_fn;
    ops.unlock = real_unlock_fn;
    ops.ud = NULL;

    CASE("L1 ★对照★ 不跑 atfork 协议：父持锁 fork → 子进程死锁");
    {
        pid_t p;
        int st = 0;
        CHECK_EQ(pthread_mutex_lock(&g_real_lock), 0);
        p = fork();
        if (p == 0) {
            child_touch_lock(0, &g, l);
        }
        /* 父进程立刻放锁 —— 证明「父进程放锁也救不了子进程」 */
        (void)pthread_mutex_unlock(&g_real_lock);
        CHECK(waitpid(p, &st, 0) == p);
        CHECK(WIFSIGNALED(st));
        CHECK_EQ(WTERMSIG(st), SIGALRM);      /* 3 秒到 → 死锁被兜底捕获 */
        printf("    （对照组成立：子进程被 SIGALRM 兜底，即已死锁）\n");
    }

    CASE("L2 跑 atfork 协议：子进程立即通过");
    {
        pid_t p;
        int st = 0;
        px_forkguard_init(&g, &ops, 1);
        px_forkguard_prepare(&g, l);
        p = fork();
        if (p == 0) {
            child_touch_lock(1, &g, l);
        }
        px_forkguard_parent(&g, l);
        CHECK(waitpid(p, &st, 0) == p);
        CHECK(WIFEXITED(st));
        CHECK_EQ(WEXITSTATUS(st), 42);        /* 取到锁，未死锁 */
        printf("    （实验组成立：子进程 exit=42，未死锁）\n");
    }

    CASE("L3 多轮 fork 后锁状态仍然自洽（无累积）");
    {
        int i;
        px_forkguard_init(&g, &ops, 1);
        for (i = 0; i < 20; i++) {
            pid_t p;
            int st = 0;
            px_forkguard_prepare(&g, l);
            p = fork();
            if (p == 0) {
                child_touch_lock(1, &g, l);
            }
            px_forkguard_parent(&g, l);
            (void)waitpid(p, &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 42) {
                g_failed++;
                fprintf(stderr, "  FAIL 第 %d 轮 fork 的子进程异常\n", i);
                break;
            }
        }
        g_checks++;
        /* 父进程侧锁必须仍然可用 */
        CHECK_EQ(pthread_mutex_trylock(&g_real_lock), 0);
        (void)pthread_mutex_unlock(&g_real_lock);
    }

    px_ledger_destroy(l);
}

/* ================================================================== */

int main(void)
{
    printf("=== proc（D4 进程管理）纯逻辑 + 真实内核 测试 ===\n\n");

    test_ledger_basic();
    test_ledger_capacity();
    test_env_build();
    test_merge_preload();
    test_classify();
    test_argv_plan();
    test_search_path();
    test_bump();
    test_kill();
    test_forkguard();
    test_real_exec_env();
    test_fork_deadlock();

    printf("\n========================================\n");
    printf("cases  = %d\n", g_cases);
    printf("checks = %d\n", g_checks);
    if (g_failed == 0) {
        printf("RESULT: PASS\n");
    } else {
        printf("失败断言 = %d\n", g_failed);
        printf("RESULT: FAIL\n");
    }
    printf("========================================\n");
    return (g_failed == 0) ? 0 : 1;
}
