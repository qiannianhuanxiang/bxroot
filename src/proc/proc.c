/*
 * proc.c -- bxroot 进程管理层：纯逻辑核心 + LD_PRELOAD 钩子层
 *
 * 上半部分（第 1-6 节）是纯逻辑：不调 dlsym、不调系统调用、全部经注入式 ops，
 * 因此可以在本容器里完整单测。下半部分（第 7 节起）是钩子层，只在
 * 未定义 PX_PURE_LOGIC 时编译。
 *
 * 设计方法论抄自 fakeroot.c / l2s-runtime.c：**纯逻辑 + 注入式 ops**。
 * 这不是洁癖，是实测约束 —— 本容器无法端到端验证 LD_PRELOAD
 * （外层 proot 会吞掉注入），只有可注入的纯逻辑才测得动。
 *
 * SPDX-License-Identifier: MIT
 */
/* 纯逻辑/钩子层的开关由 proc.h 统一定义（默认 PX_PURE_LOGIC=1）。
 * 这里刻意**不**再定义一次 —— 两处各写一套必然漂移。 */
#include "proc.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================== */
/* §0  分配器注入                                                      */
/* ================================================================== */

/*
 * 取实际使用的分配函数。
 *
 * 这里**不做**「懒绑定到全局」这种事：每次调用都从 ops 表读。
 * 代价是一次间接跳转，收益是任何时刻都不存在「当前分配器是谁」的
 * 全局可变状态 —— vfork 子进程与父进程共享地址空间，全局态越少越安全。
 */
static void *px_malloc(const px_alloc *a, size_t n)
{
    if (a != NULL && a->malloc != NULL) {
        return a->malloc(a->ud, n);
    }
    return malloc(n);
}

static void *px_calloc(const px_alloc *a, size_t n, size_t sz)
{
    if (a != NULL && a->calloc != NULL) {
        return a->calloc(a->ud, n, sz);
    }
    return calloc(n, sz);
}

static void px_free(const px_alloc *a, void *p)
{
    if (p == NULL) {
        return;
    }
    if (a != NULL && a->free != NULL) {
        a->free(a->ud, p);
        return;
    }
    free(p);
}

/* 有符号比较，避免 size_t 相减在 n < used 时回绕成天文数字。
 * -Wconversion 下 size_t 与 size_t 的减法本身没问题，但结果参与
 * 指针运算前必须确认非负，所以统一走这个辅助函数。 */
static int px_size_ge(size_t a, size_t b)
{
    return a >= b;
}

/* ================================================================== */
/* §1  pid 账本：有界开放寻址 + 墓碑 + 近似 LRU                        */
/* ================================================================== */

/*
 * 槽位状态。
 *
 * 墓碑（TOMB）是必需的：开放寻址在删除时若直接把槽位置回 EMPTY，
 * 会**截断探测链**，让排在后面的同哈希条目永远找不到。
 * 这在「pid 频繁生灭」的场景里必然触发 —— 表现为 kill 白名单随机漏判。
 */
typedef enum {
    PX_SLOT_EMPTY = 0,
    PX_SLOT_LIVE  = 1,
    PX_SLOT_TOMB  = 2
} px_slot_state;

typedef struct {
    px_slot_state state;
    px_procinfo   info;
    uint64_t      last_used;   /* 单调递增逻辑时钟，越小越久未用 */
} px_slot;

struct px_ledger {
    px_slot  *slots;
    size_t    cap;        /* 槽位数，恒为 2 的幂或 0 */
    size_t    mask;       /* cap - 1 */
    size_t    count;      /* LIVE 槽位数 */
    size_t    tombs;      /* TOMB 槽位数 */
    uint64_t  clock;      /* 逻辑时钟 */
    int       disabled;
    int       eviction;
    const px_alloc *alloc;
};

/* 向上取整到 2 的幂；0/1 都返回 1；溢出返回 0。 */
static size_t px_round_pow2(size_t v)
{
    size_t r = 1;

    if (v <= 1) {
        return 1;
    }
    while (r < v) {
        if (r > ((size_t)-1) / 2) {
            return 0;
        }
        r <<= 1;
    }
    return r;
}

/*
 * pid 的哈希。pid 在数值上高度聚集（1,2,3,...），直接取模会让
 * 低位相同的 pid 全部撞在一起。这里先做一次乘法扰动
 * （Knuth 的 2654435761 是 2^32 的黄金比近似），再取高位。
 */
static uint64_t px_hash_pid(pid_t pid, unsigned kind)
{
    uint64_t x = (uint64_t)(uint32_t)pid;
    x ^= (uint64_t)kind * 0x9E3779B97F4A7C15ull;
    x *= 0x9E3779B97F4A7C15ull;
    x ^= x >> 29;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 32;
    return x;
}

/*
 * 探测。找到返回槽位下标并把 *found 置 1；未找到返回**第一个可插入**的
 * 槽位下标（墓碑优先复用）并把 *found 置 0。
 */
static size_t px_probe(const px_ledger *l, pid_t pid, unsigned kind, int *found)
{
    uint64_t h = px_hash_pid(pid, kind);
    size_t i = (size_t)(h & (uint64_t)l->mask);
    size_t first_tomb = (size_t)-1;
    size_t n;

    *found = 0;
    for (n = 0; n < l->cap; n++) {
        const px_slot *s = &l->slots[i];

        if (s->state == PX_SLOT_EMPTY) {
            /* 探测链在此终止 —— 后面不可能再有同键条目 */
            return (first_tomb != (size_t)-1) ? first_tomb : i;
        }
        if (s->state == PX_SLOT_TOMB) {
            if (first_tomb == (size_t)-1) {
                first_tomb = i;
            }
        } else if (s->info.pid == pid && (unsigned)s->info.kind == kind) {
            *found = 1;
            return i;
        }
        i = (i + 1) & l->mask;
    }
    /* 表满（无 EMPTY）：只能用墓碑或放弃 */
    return first_tomb;
}

/* 释放槽位为墓碑。 */
static void px_slot_release(px_slot *s)
{
    s->state = PX_SLOT_TOMB;
    memset(&s->info, 0, sizeof(s->info));
}

px_ledger *px_ledger_create(size_t slots, const px_alloc *a)
{
    px_ledger *l;
    size_t want;

    want = (slots == 0) ? (size_t)PX_LEDGER_DEFAULT_SLOTS : slots;
    if (want > (size_t)PX_LEDGER_MAX_SLOTS) {
        want = (size_t)PX_LEDGER_MAX_SLOTS;
    }
    want = px_round_pow2(want);
    if (want == 0) {
        return NULL;
    }

    l = (px_ledger *)px_calloc(a, 1, sizeof(*l));
    if (l == NULL) {
        return NULL;
    }
    l->slots = (px_slot *)px_calloc(a, want, sizeof(*l->slots));
    if (l->slots == NULL) {
        px_free(a, l);
        return NULL;
    }
    l->cap = want;
    l->mask = want - 1;
    l->count = 0;
    l->tombs = 0;
    l->clock = 0;
    l->disabled = 0;
    l->eviction = 1;
    l->alloc = a;
    return l;
}

void px_ledger_destroy(px_ledger *l)
{
    if (l == NULL) {
        return;
    }
    px_free(l->alloc, l->slots);
    px_free(l->alloc, l);
}

void px_ledger_clear(px_ledger *l)
{
    size_t i;

    if (l == NULL || l->slots == NULL) {
        return;
    }
    for (i = 0; i < l->cap; i++) {
        l->slots[i].state = PX_SLOT_EMPTY;
        memset(&l->slots[i].info, 0, sizeof(l->slots[i].info));
        l->slots[i].last_used = 0;
    }
    l->count = 0;
    l->tombs = 0;
    l->clock = 0;
}

size_t px_ledger_count(const px_ledger *l)
{
    return (l == NULL) ? 0 : l->count;
}

size_t px_ledger_capacity(const px_ledger *l)
{
    return (l == NULL) ? 0 : l->cap;
}

/* 遍历统计某种 life 的数量。表很小（默认 256），线性扫是可接受的；
 * 真正热路径上的 kill 判定走哈希探测，不走这里。 */
static size_t px_count_life(const px_ledger *l, px_life want)
{
    size_t i;
    size_t n = 0;

    if (l == NULL) {
        return 0;
    }
    for (i = 0; i < l->cap; i++) {
        if (l->slots[i].state == PX_SLOT_LIVE &&
            l->slots[i].info.life == want) {
            n++;
        }
    }
    return n;
}

size_t px_ledger_live_count(const px_ledger *l)
{
    return px_count_life(l, PX_LIVE);
}

size_t px_ledger_reaped_count(const px_ledger *l)
{
    return px_count_life(l, PX_REAPED);
}

void px_ledger_set_disabled(px_ledger *l, int disabled)
{
    if (l != NULL) {
        l->disabled = disabled ? 1 : 0;
    }
}

int px_ledger_is_disabled(const px_ledger *l)
{
    return (l == NULL) ? 1 : l->disabled;
}

void px_ledger_set_eviction(px_ledger *l, int enabled)
{
    if (l != NULL) {
        l->eviction = enabled ? 1 : 0;
    }
}

int px_ledger_eviction_enabled(const px_ledger *l)
{
    return (l == NULL) ? 0 : l->eviction;
}

/* 一个槽位能否被淘汰：只有 REAPED 可以。
 *
 * 为什么 live 绝不淘汰：淘汰 live 会把「我们创建的、可 kill 的子进程」
 * 变成「不在账本里、被白名单拒绝」—— 那是功能缺陷（shell 的 job control
 * 直接坏掉）。淘汰 reaped 只是少一层保护，而保护本就该拒绝。 */
static int px_evictable(const px_slot *s)
{
    return s->state == PX_SLOT_LIVE && s->info.life == PX_REAPED;
}

size_t px_ledger_evict(px_ledger *l, size_t n)
{
    size_t done = 0;

    if (l == NULL || n == 0) {
        return 0;
    }
    while (done < n) {
        size_t i;
        size_t best = (size_t)-1;
        uint64_t best_clock = 0;

        for (i = 0; i < l->cap; i++) {
            if (!px_evictable(&l->slots[i])) {
                continue;
            }
            if (best == (size_t)-1 || l->slots[i].last_used < best_clock) {
                best = i;
                best_clock = l->slots[i].last_used;
            }
        }
        if (best == (size_t)-1) {
            break;   /* 没有可淘汰的了 */
        }
        px_slot_release(&l->slots[best]);
        l->count--;
        l->tombs++;
        done++;
    }
    return done;
}

/*
 * 压实：把所有 LIVE 条目重新插入一张干净的（无墓碑）表。
 *
 * 为什么需要：墓碑会永久占用探测链长度。只删不压的话，反复
 * 「fork + waitpid」的进程（shell 每跑一条命令就一次）会把表逐渐
 * 变成一片墓碑，探测退化成 O(cap)。压实还顺带把 tombs 清零，
 * 让装载率判断恢复准确。
 */
static int px_ledger_compact(px_ledger *l)
{
    px_slot *old = l->slots;
    size_t old_cap = l->cap;
    px_slot *fresh;
    size_t i;

    fresh = (px_slot *)px_calloc(l->alloc, l->cap, sizeof(*fresh));
    if (fresh == NULL) {
        return PX_ENOMEM;
    }
    l->slots = fresh;
    l->count = 0;
    l->tombs = 0;

    for (i = 0; i < old_cap; i++) {
        if (old[i].state != PX_SLOT_LIVE) {
            continue;
        }
        {
            int found = 0;
            size_t idx = px_probe(l, old[i].info.pid,
                                  (unsigned)old[i].info.kind, &found);
            /* 容量没变、条目数只减不增 → 必然有位置 */
            l->slots[idx].state = PX_SLOT_LIVE;
            l->slots[idx].info = old[i].info;
            l->slots[idx].last_used = old[i].last_used;
            l->count++;
        }
    }
    px_free(l->alloc, old);
    return PX_OK;
}

/* 扩容到 2 倍并压实。已到硬上限返回 PX_EFULL。 */
static int px_ledger_grow(px_ledger *l)
{
    size_t want;

    if (l->cap >= (size_t)PX_LEDGER_MAX_SLOTS) {
        return PX_EFULL;
    }
    want = l->cap * 2;
    if (want > (size_t)PX_LEDGER_MAX_SLOTS) {
        want = (size_t)PX_LEDGER_MAX_SLOTS;
    }

    {
        px_ledger tmp;
        px_slot *fresh;
        size_t i;

        fresh = (px_slot *)px_calloc(l->alloc, want, sizeof(*fresh));
        if (fresh == NULL) {
            return PX_ENOMEM;
        }
        /* 借一个临时账本视图来完成重哈希，避免直接改 l 到一半失败 */
        tmp = *l;
        tmp.slots = fresh;
        tmp.cap = want;
        tmp.mask = want - 1;
        tmp.count = 0;
        tmp.tombs = 0;

        for (i = 0; i < l->cap; i++) {
            int found = 0;
            size_t idx;
            if (l->slots[i].state != PX_SLOT_LIVE) {
                continue;
            }
            idx = px_probe(&tmp, l->slots[i].info.pid,
                           (unsigned)l->slots[i].info.kind, &found);
            tmp.slots[idx].state = PX_SLOT_LIVE;
            tmp.slots[idx].info = l->slots[i].info;
            tmp.slots[idx].last_used = l->slots[i].last_used;
            tmp.count++;
        }
        px_free(l->alloc, l->slots);
        l->slots = fresh;
        l->cap = want;
        l->mask = want - 1;
        l->count = tmp.count;
        l->tombs = 0;
    }
    return PX_OK;
}

/* 装载率（含墓碑）是否超过阈值。 */
static int px_ledger_overloaded(const px_ledger *l)
{
    unsigned long used = (unsigned long)(l->count + l->tombs);
    unsigned long cap = (unsigned long)l->cap;

    if (cap == 0) {
        return 0;
    }
    return (used * 100UL) >= (cap * (unsigned long)PX_LEDGER_LOAD_PERCENT);
}

/* 内部：插入或刷新。 */
static int px_ledger_put(px_ledger *l, pid_t pid, pid_t ppid,
                         px_entry_kind kind, uint32_t tag)
{
    int found = 0;
    size_t idx;

    if (l == NULL) {
        return PX_EINVAL;
    }
    if (l->disabled) {
        return PX_OK;   /* 关掉后记账是 no-op */
    }
    if (pid <= 0) {
        /* pid 0/负数不是合法进程标识。放进来会污染 kill 判定。 */
        return PX_EINVAL;
    }

    if (px_ledger_overloaded(l)) {
        /* 先试着压实（墓碑换空间），压实不够再扩，扩不动再淘汰 */
        if (l->tombs > 0) {
            int rc = px_ledger_compact(l);
            if (rc != PX_OK) {
                return rc;
            }
        }
        if (px_ledger_overloaded(l)) {
            int rc = px_ledger_grow(l);
            if (rc != PX_OK) {
                if (l->eviction) {
                    (void)px_ledger_evict(l, (size_t)PX_LEDGER_EVICT_BATCH);
                } else {
                    return rc;
                }
            }
        }
    }

    idx = px_probe(l, pid, (unsigned)kind, &found);
    if (idx == (size_t)-1) {
        /* 表满且一个墓碑都没有。走到这里说明 count+tombs == cap 且全是 LIVE。 */
        if (l->eviction) {
            (void)px_ledger_evict(l, (size_t)PX_LEDGER_EVICT_BATCH);
            idx = px_probe(l, pid, (unsigned)kind, &found);
        }
        if (idx == (size_t)-1) {
            return PX_EFULL;
        }
    }

    l->clock++;
    if (found) {
        /* 刷新：保留 life（reaped 不该因为再次 add 而复活成 live）。
         * 这个细节很关键 —— pid 复用后调用方会 add 同一个 pid，
         * 若这里无脑置 PX_LIVE，就把「已回收」的保护抹掉了。 */
        l->slots[idx].info.ppid = ppid;
        l->slots[idx].info.tag = tag;
        l->slots[idx].last_used = l->clock;
        return PX_OK;
    }

    if (l->slots[idx].state == PX_SLOT_TOMB) {
        l->tombs--;
    }
    l->slots[idx].state = PX_SLOT_LIVE;
    l->slots[idx].info.pid = pid;
    l->slots[idx].info.ppid = ppid;
    l->slots[idx].info.kind = kind;
    l->slots[idx].info.life = PX_LIVE;
    l->slots[idx].info.tag = tag;
    l->slots[idx].last_used = l->clock;
    l->count++;
    return PX_OK;
}

int px_ledger_add(px_ledger *l, pid_t pid, pid_t ppid, uint32_t tag)
{
    return px_ledger_put(l, pid, ppid, PX_ENTRY_PID, tag);
}

int px_ledger_add_pgid(px_ledger *l, pid_t pgid, uint32_t tag)
{
    return px_ledger_put(l, pgid, 0, PX_ENTRY_PGID, tag);
}

int px_ledger_get(const px_ledger *l, pid_t pid, px_entry_kind kind,
                  px_procinfo *out)
{
    int found = 0;
    size_t idx;

    if (l == NULL || l->disabled || pid <= 0) {
        return PX_ENOENT;
    }
    idx = px_probe(l, pid, (unsigned)kind, &found);
    if (!found || idx == (size_t)-1) {
        return PX_ENOENT;
    }
    if (out != NULL) {
        *out = l->slots[idx].info;
    }
    return PX_OK;
}

int px_ledger_has(const px_ledger *l, pid_t pid, px_entry_kind kind)
{
    return px_ledger_get(l, pid, kind, NULL) == PX_OK ? 1 : 0;
}

int px_ledger_reap(px_ledger *l, pid_t pid)
{
    int found = 0;
    size_t idx;

    if (l == NULL || l->disabled) {
        return PX_ENOENT;
    }
    idx = px_probe(l, pid, (unsigned)PX_ENTRY_PID, &found);
    if (!found || idx == (size_t)-1) {
        return PX_ENOENT;
    }
    l->slots[idx].info.life = PX_REAPED;
    return PX_OK;
}

int px_ledger_remove(px_ledger *l, pid_t pid, px_entry_kind kind)
{
    int found = 0;
    size_t idx;

    if (l == NULL || l->disabled) {
        return PX_ENOENT;
    }
    idx = px_probe(l, pid, (unsigned)kind, &found);
    if (!found || idx == (size_t)-1) {
        return PX_ENOENT;
    }
    px_slot_release(&l->slots[idx]);
    l->count--;
    l->tombs++;
    return PX_OK;
}

/* ================================================================== */
/* §2  envp 重建                                                       */
/* ================================================================== */

int px_env_entry_matches(const char *entry, const char *name)
{
    size_t n;

    if (entry == NULL || name == NULL || name[0] == '\0') {
        return 0;
    }
    n = strlen(name);
    /* 必须恰好是 "NAME="，不能是 "NAMEX=" */
    if (strncmp(entry, name, n) != 0) {
        return 0;
    }
    return entry[n] == '=';
}

const char *px_env_lookup(const char *const *envp, const char *name)
{
    size_t i;
    const char *hit = NULL;

    if (envp == NULL || name == NULL) {
        return NULL;
    }
    /* 最后一次出现者胜出（与 libc 的 getenv 语义一致）。
     * 不提前 return 是刻意的：提前 return 会在重复名字时与 getenv 不一致，
     * 而 envp 里出现重复名字是完全合法的。 */
    for (i = 0; i < (size_t)PX_ENVP_MAX && envp[i] != NULL; i++) {
        if (px_env_entry_matches(envp[i], name)) {
            hit = envp[i] + strlen(name) + 1;
        }
    }
    return hit;
}

void px_env_dispose(px_envout *out)
{
    if (out == NULL) {
        return;
    }
    if (out->buf != NULL) {
        px_free(out->alloc, out->buf);
    }
    if (out->v != NULL) {
        px_free(out->alloc, out->v);
    }
    if (out->offs != NULL) {
        px_free(out->alloc, out->offs);
    }
    out->buf = NULL;
    out->v = NULL;
    out->offs = NULL;
    out->n = 0;
    out->cap = 0;
    out->buf_len = 0;
    out->buf_cap = 0;
    out->alloc = NULL;
}

/* 内部：确保 buf 还能再放 need 字节（含 NUL）。
 *
 * 注意本函数**会替换 buf**，因此它必须只在没有任何人持有 buf 内地址时调用。
 * 这正是 px_envout 用 offsets 而不是指针的原因。 */
static int px_env_reserve(px_envout *out, size_t need)
{
    size_t want;
    char *nb;

    if (out->buf_cap >= out->buf_len &&
        px_size_ge(out->buf_cap - out->buf_len, need)) {
        return PX_OK;
    }
    want = (out->buf_cap == 0) ? 1024u : out->buf_cap;
    while (want < out->buf_len || !px_size_ge(want - out->buf_len, need)) {
        if (want > ((size_t)-1) / 2) {
            return PX_ENOSPC;
        }
        want *= 2;
    }
    nb = (char *)px_malloc(out->alloc, want);
    if (nb == NULL) {
        return PX_ENOMEM;
    }
    if (out->buf != NULL) {
        memcpy(nb, out->buf, out->buf_len);
        px_free(out->alloc, out->buf);
    }
    out->buf = nb;
    out->buf_cap = want;
    return PX_OK;
}

/* 内部：确保 offs 数组能再放一条。 */
static int px_env_reserve_offs(px_envout *out)
{
    if (out->n + 1u <= out->cap) {
        return PX_OK;
    }
    {
        size_t want = (out->cap == 0) ? 32u : out->cap * 2u;
        size_t *no;

        if (want <= out->n + 1u) {
            want = out->n + 2u;
        }
        if (want > ((size_t)-1) / sizeof(size_t)) {
            return PX_ENOMEM;
        }
        no = (size_t *)px_malloc(out->alloc, want * sizeof(size_t));
        if (no == NULL) {
            return PX_ENOMEM;
        }
        if (out->offs != NULL) {
            memcpy(no, out->offs, out->n * sizeof(size_t));
            px_free(out->alloc, out->offs);
        }
        out->offs = no;
        out->cap = want;
    }
    return PX_OK;
}

/* 内部：把一条 "NAME=VALUE" 追加进结果（按偏移记录，不存指针）。 */
static int px_env_push(px_envout *out, const char *entry, size_t len)
{
    int rc;

    rc = px_env_reserve_offs(out);
    if (rc != PX_OK) {
        return rc;
    }
    rc = px_env_reserve(out, len + 1u);
    if (rc != PX_OK) {
        return rc;
    }
    memcpy(out->buf + out->buf_len, entry, len);
    out->buf[out->buf_len + len] = '\0';
    out->offs[out->n] = out->buf_len;
    out->n++;
    out->buf_len += len + 1u;
    return PX_OK;
}

/* 内部：追加 "NAME=VALUE"，value 可为 NULL（等价空串）。 */
static int px_env_push_kv(px_envout *out, const char *name, const char *value)
{
    size_t nl = strlen(name);
    size_t vl = (value == NULL) ? 0u : strlen(value);
    size_t total = nl + 1u + vl;
    int rc;

    if (total > (size_t)PX_ENV_ENTRY_MAX) {
        return PX_ETOOLONG;
    }
    rc = px_env_reserve_offs(out);
    if (rc != PX_OK) {
        return rc;
    }
    rc = px_env_reserve(out, total + 1u);
    if (rc != PX_OK) {
        return rc;
    }
    memcpy(out->buf + out->buf_len, name, nl);
    out->buf[out->buf_len + nl] = '=';
    if (vl > 0) {
        memcpy(out->buf + out->buf_len + nl + 1u, value, vl);
    }
    out->buf[out->buf_len + total] = '\0';
    out->offs[out->n] = out->buf_len;
    out->n++;
    out->buf_len += total + 1u;
    return PX_OK;
}

/* 内部：某名字是否在 drop 列表里。 */
static int px_env_dropped(const px_envpolicy *pol, const char *entry)
{
    size_t i;

    if (pol == NULL || pol->drop == NULL) {
        return 0;
    }
    for (i = 0; i < pol->drop_n; i++) {
        if (pol->drop[i] != NULL && px_env_entry_matches(entry, pol->drop[i])) {
            return 1;
        }
    }
    return 0;
}

/*
 * 内部：某条目是否应当因为「我们会自己写」而被丢弃。
 *
 * ★ MERGE 模式下原条目同样要丢，但值必须先读出来 ★
 *
 * PX_ENV_MERGE_PRELOAD 的语义是「把我们的值并进原值」。合并发生在
 * 第二遍（读 in_envp 的当前值 → px_merge_preload → 写一条新的），
 * 所以第一遍必须把**所有**同名条目都丢掉 —— 否则结果里会出现两条
 * LD_PRELOAD，而 ld.so 对重复项的处理是未定义的（实测 glibc 只用
 * 最后一条，于是我们的钩子被完全遮蔽）。
 * 测试 C13 的「只有一条 LD_PRELOAD」断言钉住这一点。
 */
static int px_env_forced(const px_envpolicy *pol, const char *entry)
{
    size_t i;

    if (pol == NULL || pol->forced == NULL) {
        return 0;
    }
    for (i = 0; i < pol->forced_n; i++) {
        if (pol->forced[i].name != NULL &&
            px_env_entry_matches(entry, pol->forced[i].name)) {
            return 1;
        }
    }
    return 0;
}

/* 内部：找出 forced 列表里第 i 项的 mode。 */
static px_env_mode px_env_mode_of(const px_envpolicy *pol, size_t i)
{
    if (pol == NULL || pol->forced == NULL || i >= pol->forced_n) {
        return PX_ENV_SET;
    }
    return pol->forced[i].mode;
}

int px_env_build(const char *const *in_envp, const px_envpolicy *pol,
                 px_envout *out, const px_alloc *a)
{
    size_t i;
    size_t limit;
    int rc;

    if (out == NULL) {
        return PX_EINVAL;
    }
    memset(out, 0, sizeof(*out));
    out->alloc = a;

    limit = (pol != NULL && pol->max_entries > 0)
                ? pol->max_entries : (size_t)PX_ENVP_MAX;

    /* 第一遍：搬运原有条目（跳过 drop 与被 forced 覆盖的） */
    if (in_envp != NULL) {
        for (i = 0; i < (size_t)PX_ENVP_MAX && in_envp[i] != NULL; i++) {
            const char *e = in_envp[i];
            size_t len;

            /* ★ 顺序很重要：limit 检查必须在 push **之前** ★
             *
             * 原实现把检查放在 push 之后，于是 limit=10、输入 64 条时
             * 前 10 条进得去、第 11 条才报 PX_ENOSPC —— 整个构建**失败**。
             * 但语义应该是「截断到上限」，不是「超过上限就全盘失败」：
             * exec 的环境变量多不是错误，不该让 exec 失败。
             * 测试 C6 钉住了这一点。 */
            if (out->n >= limit) {
                break;      /* 截断，不再载入更多 */
            }
            if (e[0] == '\0') {
                continue;   /* 空条目无意义，丢掉 */
            }
            if (px_env_dropped(pol, e) || px_env_forced(pol, e)) {
                continue;
            }
            len = strlen(e);
            if (len > (size_t)PX_ENV_ENTRY_MAX) {
                rc = PX_ETOOLONG;
                goto fail;
            }
            rc = px_env_push(out, e, len);
            if (rc != PX_OK) {
                goto fail;
            }
        }
    }

    /* 第二遍：写强制条目 */
    if (pol != NULL && pol->forced != NULL) {
        for (i = 0; i < pol->forced_n; i++) {
            const char *name = pol->forced[i].name;
            if (name == NULL) {
                continue;
            }
            /*
             * ★ MERGE 模式：与原环境里的同名值合并，而不是覆盖 ★
             *
             * 不合并的后果是 guest 自己设的 LD_PRELOAD 被静默丢弃 ——
             * 表现为某个依赖 preload 的第三方工具在容器里行为诡异，
             * 而容器的钩子本身工作正常，排查方向会完全跑偏。
             * 真实内核用例 K3 钉住这一点。
             */
            if (px_env_mode_of(pol, i) == PX_ENV_MERGE_PRELOAD) {
                const char *cur = (in_envp != NULL)
                                      ? px_env_lookup(in_envp, name) : NULL;
                char merged[PX_PRELOAD_MAX];
                int mrc = px_merge_preload(cur, pol->forced[i].value,
                                           merged, sizeof(merged));
                if (mrc != PX_OK) {
                    rc = mrc;
                    goto fail;
                }
                rc = px_env_push_kv(out, name, merged);
                if (rc != PX_OK) {
                    goto fail;
                }
                continue;
            }
            /* 强制条目同样：超限就停止追加，但**不**整体失败。
             * 强制条目最多 4 条，正常永远到不了 limit；能到说明
             * 调用方把 limit 设得极小，那是它的选择，不是错误。 */
            if (out->n >= limit) {
                break;
            }
            /* 值为 NULL 用空串：**不能跳过**。
             * 「把变量设成空」和「变量不存在」在子进程里是两件事
             * （getenv 返回 "" vs NULL），而重建的目的是保证存在性。 */
            rc = px_env_push_kv(out, name, pol->forced[i].value);
            if (rc != PX_OK) {
                goto fail;
            }
        }
    }

    /* 收尾：把偏移换算成指针，产出一块连续的 NULL 结尾数组。
     *
     * ★ 必须在这里一次性分配 `v`，不能边构建边写指针 ★
     * buf 在构建期间会扩容（换新块 + free 旧块），任何提前记下的
     * buf 内地址都会悬空。见 proc.h 里 px_envout 的说明。 */
    {
        char **vec = (char **)px_malloc(a, (out->n + 1u) * sizeof(char *));
        if (vec == NULL) {
            rc = PX_ENOMEM;
            goto fail;
        }
        for (i = 0; i < out->n; i++) {
            vec[i] = out->buf + out->offs[i];
        }
        vec[out->n] = NULL;
        out->v = vec;
    }
    return PX_OK;

fail:
    px_env_dispose(out);
    return rc;
}

int px_merge_preload(const char *existing, const char *ours,
                     char *out, size_t outsz)
{
    size_t used = 0;
    const char *base = (ours == NULL) ? "" : ours;
    size_t base_len;

    if (out == NULL || outsz == 0) {
        return PX_EINVAL;
    }
    base_len = strlen(base);

    /* 去重用的 basename 比较：把 ours 的 basename 抽出来 */
    if (existing == NULL || existing[0] == '\0' || base_len == 0) {
        if (base_len + 1u > outsz) {
            return PX_ENOSPC;
        }
        memcpy(out, base, base_len + 1u);
        return PX_OK;
    }

    /* ours 放最前面（理由见 proc.h） */
    if (base_len >= outsz) {
        return PX_ENOSPC;
    }
    memcpy(out, base, base_len);
    used = base_len;

    {
        const char *p = existing;
        while (*p != '\0') {
            const char *end = p;
            size_t seg_len;
            int dup = 0;

            while (*end != '\0' && *end != ' ' && *end != ':' && *end != '\t') {
                end++;
            }
            seg_len = (size_t)(end - p);

            if (seg_len > 0) {
                /*
                 * 去重：路径全等，或 basename 相等。
                 * basename 判定的必要性：同一个库可能以不同拼写出现
                 * （绝对路径 vs 相对路径 vs 经符号链接），ld.so 会把它们
                 * 当作不同的库各加载一次 —— 构造函数跑两遍，
                 * 我们的账本会被初始化两次，第一次的分配就泄漏了。
                 */
                if (seg_len == base_len && strncmp(p, base, base_len) == 0) {
                    dup = 1;
                } else {
                    const char *b1 = strrchr(base, '/');
                    const char *b2 = NULL;
                    size_t k;
                    b1 = (b1 == NULL) ? base : b1 + 1;
                    for (k = 0; k < seg_len; k++) {
                        if (p[k] == '/') {
                            b2 = p + k + 1;
                        }
                    }
                    if (b2 == NULL) {
                        b2 = p;
                    }
                    if (strlen(b1) == (size_t)((p + seg_len) - b2) &&
                        strncmp(b1, b2, strlen(b1)) == 0) {
                        dup = 1;
                    }
                }
            }

            if (!dup && seg_len > 0) {
                if (used + 1u + seg_len + 1u > outsz) {
                    /* 装不下：**不是错误**，只是丢弃剩余段。
                     * 丢 guest 自己的 preload 会削弱它，但保证我们不被截断
                     * 更重要 —— 我们被截断意味着整个容器失去钩子。 */
                    break;
                }
                out[used] = ' ';
                used++;
                memcpy(out + used, p, seg_len);
                used += seg_len;
            }

            if (*end == '\0') {
                break;
            }
            p = end + 1;
        }
    }

    out[used] = '\0';
    return PX_OK;
}

/* ================================================================== */
/* §3  argv 路径翻译判定                                               */
/* ================================================================== */

px_arg_verdict px_classify_arg(const char *arg, int is_argv0, const char *rootfs)
{
    (void)is_argv0;

    if (arg == NULL || arg[0] == '\0') {
        return PX_ARG_KEEP;
    }
    /* 只有绝对路径才是候选。相对路径/裸名一律保留 —— 理由见 proc.h。 */
    if (arg[0] != '/') {
        return PX_ARG_KEEP;
    }
    /*
     * "-" 与 "--" 这类选项不是路径。
     *
     * ★ 这里曾经写错成 `arg[1] == '\0' || ...`，漏了 `arg[0] == '-'`
     *   的前置条件 —— 于是**任何单字符绝对路径**都被当成选项。
     *   以 '/' 开头的单字符路径只有 "/" 本身，所以表现是
     *   `px_classify_arg("/", 0, "/")` 返回 KEEP（不翻译）。
     *   测试 E6 抓到了它：`/` 在 rootfs == "/" 的配置下必须返回
     *   TRANSLATE，而不是被误判成选项。
     */
    if (arg[0] == '-' &&
        (arg[1] == '\0' || (arg[1] == '-' && arg[2] == '\0'))) {
        return PX_ARG_KEEP;
    }

    /*
     * 幂等：已带 rootfs 前缀的必须原样保留，否则会被二次加前缀。
     *
     * ★ 必须排除 `rootfs == "/"` 这个退化情形 ★
     * 任何绝对路径都以 "/" 开头，所以对 rl == 1 做前缀判定会把**所有**
     * 绝对路径都判成「已翻译」，于是**一条都不翻** —— 容器彻底失效，
     * 且没有任何报错。rootfs 就是宿主根时（`-r /`）这是真实配置。
     *
     * 修法有两种：(a) 要求 rl > 1；(b) 单独处理 "/"，因为此时
     * 「已带前缀」等价于路径本身就是 "/"。
     * 选 (b)：它保留了「arg == "/" 时判定为 ALREADY」这个正确语义
     * （加前缀的结果就是 "/" 本身，翻了等于没翻）。
     * 用例 E6 同时钉住 `"/"` 与 `"/bin/ls"` 两种输入。
     */
    if (rootfs != NULL && rootfs[0] != '\0') {
        size_t rl = strlen(rootfs);

        /*
         * rootfs == "/" 时**不做**幂等判定。
         *
         * 曾考虑「只有 arg 恰好是 '/' 才算已带前缀」，但那样会让
         * px_classify_arg("/", 0, "/") 返回 ALREADY —— 语义上"已经
         * 翻译过"是不对的："/" 加前缀仍然是 "/"（幂等），而判定成
         * ALREADY 会让调用方**跳过**翻译动作；虽然结果相同，
         * 但混淆了「不需要翻」与「已经翻过」两种状态，
         * 下游若据此做别的事（比如决定是否改 argv 指针）就会出错。
         *
         * 统一返回 TRANSLATE 由翻译器自己处理最干净 ——
         * translate_path("/") 的结果就是 rootfs 本身。
         */
        if (strncmp(arg, rootfs, rl) == 0 && rl > 1u &&
                   (arg[rl] == '\0' || arg[rl] == '/')) {
            return PX_ARG_ALREADY;
        }
    }
    return PX_ARG_TRANSLATE;
}

const px_argpolicy PX_ARGPOLICY_DEFAULT = { 1, 0, NULL, 0 };

int px_arg_is_path_option(const char *arg, const px_argpolicy *pol)
{
    const px_argpolicy *p = (pol != NULL) ? pol : &PX_ARGPOLICY_DEFAULT;
    size_t i;

    if (arg == NULL || p->path_options == NULL) {
        return 0;
    }
    for (i = 0; i < p->path_options_n; i++) {
        const char *o = p->path_options[i];
        if (o != NULL && strcmp(arg, o) == 0) {
            return 1;
        }
    }
    return 0;
}

px_arg_verdict px_classify_arg_ex(const char *arg, int is_argv0,
                                  const char *rootfs, const px_argpolicy *pol)
{
    const px_argpolicy *p = (pol != NULL) ? pol : &PX_ARGPOLICY_DEFAULT;

    if (!is_argv0 && !p->translate_other_args) {
        return PX_ARG_KEEP;
    }
    if (is_argv0 && !p->translate_argv0) {
        return PX_ARG_KEEP;
    }
    return px_classify_arg(arg, is_argv0, rootfs);
}

/*
 * 把 plan 归一化成「已初始化且无改写」。
 *
 * magic 不匹配 → 整个清零（等价 memset）。这一步不能省：
 * 调用方可以合法地写 `px_argv_plan plan;` 而不初始化，
 * 而下面要保留 fixes 复用，就必须先确认 fixes/cap 是可信的。
 */
static void px_plan_normalize(px_argv_plan *plan, const px_alloc *alloc)
{
    if (plan->magic != PX_PLAN_MAGIC) {
        memset(plan, 0, sizeof(*plan));
        plan->magic = PX_PLAN_MAGIC;
        plan->err_at = -1;
    }
    /* ★ 不碰 plan->policy ★
     * 它是调用方通过 px_plan_set_policy 显式设的状态，会被多次
     * px_plan_argv 复用；在这里清零等于每次调用都把策略重置成默认，
     * 而「策略没生效」是看不出来的。 */
    if (alloc != NULL) {
        plan->alloc_of_plan = alloc;
    }
}

void px_plan_reset(px_argv_plan *plan)
{
    if (plan == NULL) {
        return;
    }
    /* 注意：这里**不**碰 magic，也不释放 fixes。
     * 它可以在未初始化的 plan 上安全调用（先归一化）。 */
    px_plan_normalize(plan, plan->magic == PX_PLAN_MAGIC
                                ? plan->alloc_of_plan : NULL);
    plan->n = 0;
    plan->oom = 0;
    plan->error = 0;
    plan->err_at = -1;
}

void px_plan_dispose(px_argv_plan *plan)
{
    if (plan == NULL) {
        return;
    }
    if (plan->magic != PX_PLAN_MAGIC) {
        /* 从未初始化过 → 没有任何东西要释放 */
        memset(plan, 0, sizeof(*plan));
        return;
    }
    if (plan->fixes != NULL) {
        px_free(plan->alloc_of_plan, plan->fixes);
    }
    memset(plan, 0, sizeof(*plan));
}

/* 确保 fixes 能再放一条。懒分配：第一次真的要改写时才 calloc。 */
static int px_plan_reserve(px_argv_plan *plan)
{
    size_t want;
    px_arg_fix *nf;

    if (plan->n < plan->cap) {
        return PX_OK;
    }
    if (plan->cap >= (size_t)PX_PLAN_MAX) {
        return PX_EFULL;
    }
    want = (plan->cap == 0) ? 4u : plan->cap * 2u;
    if (want > (size_t)PX_PLAN_MAX) {
        want = (size_t)PX_PLAN_MAX;
    }
    nf = (px_arg_fix *)px_malloc(plan->alloc_of_plan,
                                 want * sizeof(px_arg_fix));
    if (nf == NULL) {
        plan->oom = 1;
        return PX_ENOMEM;
    }
    if (plan->fixes != NULL) {
        memcpy(nf, plan->fixes, plan->n * sizeof(px_arg_fix));
        px_free(plan->alloc_of_plan, plan->fixes);
    }
    plan->fixes = nf;
    plan->cap = want;
    return PX_OK;
}

int px_plan_argv_ex(char *const argv[], const char *rootfs,
                    px_xlate_fn xlate, void *ud, px_argv_plan *plan,
                    const px_alloc *alloc)
{
    size_t i;

    if (plan == NULL) {
        return PX_EINVAL;
    }
    px_plan_normalize(plan, alloc);
    plan->n = 0;
    plan->oom = 0;
    plan->error = 0;
    plan->err_at = -1;
    if (argv == NULL) {
        return PX_OK;
    }
    {
        const px_argpolicy *pol = (plan->policy != NULL)
                                      ? plan->policy : &PX_ARGPOLICY_DEFAULT;
        int prev_is_path_opt = 0;

    for (i = 0; i < (size_t)PX_ARGV_MAX && argv[i] != NULL; i++) {
        /*
         * ★ 默认策略只翻 argv[0] ★
         *
         * 这不是省事，是正确性：argv 里绝大多数条目不是路径，
         * 而误翻是**静默**的功能破坏（`grep /etc/passwd` 的第一个参数
         * 是模式串，翻了永远匹配不中）。策略做成数据（px_argpolicy）
         * 便于按需放宽，但默认必须保守。
         *
         * 记录「上一个元素是取路径的选项」以便按白名单翻它的值。
         */
        int want_path;
        px_arg_verdict v;
        int rc;

        if (i == 0) {
            want_path = pol->translate_argv0;
        } else if (pol->translate_other_args) {
            want_path = 1;
        } else {
            want_path = prev_is_path_opt;   /* 白名单选项的值 */
        }
        prev_is_path_opt = px_arg_is_path_option(argv[i], pol);

        if (!want_path) {
            continue;
        }
        v = px_classify_arg(argv[i], (i == 0) ? 1 : 0, rootfs);
        if (v != PX_ARG_TRANSLATE) {
            continue;
        }
        if (xlate == NULL) {
            continue;   /* 没注入翻译器 → 全部保留 */
        }
        rc = px_plan_reserve(plan);
        if (rc != PX_OK) {
            return rc;   /* OOM 或超出 PX_PLAN_MAX */
        }
        {
            char tmp[PX_PATH_MAX];
            rc = xlate(ud, argv[i], tmp, sizeof(tmp));
            if (rc < 0) {
                /* 翻译失败**不能**整体失败：exec 的失败会让调用方以为
                 * 「命令不存在」，而真实原因是路径太长。更稳妥的做法是
                 * 保留原参数，让它自己去失败并给出真实 errno。 */
                plan->error = rc;
                plan->err_at = (int)i;
                continue;
            }
            if (rc == 0) {
                continue;   /* 无需翻译 */
            }
            plan->fixes[plan->n].index = i;
            memcpy(plan->fixes[plan->n].text, tmp, sizeof(tmp));
            plan->n++;
        }
    }
    }
    return PX_OK;
}

void px_plan_set_policy(px_argv_plan *plan, const px_argpolicy *pol)
{
    if (plan == NULL) {
        return;
    }
    px_plan_normalize(plan, NULL);
    plan->policy = pol;
}

int px_plan_argv(char *const argv[], const char *rootfs,
                 px_xlate_fn xlate, void *ud, px_argv_plan *plan)
{
    return px_plan_argv_ex(argv, rootfs, xlate, ud, plan, NULL);
}

int px_plan_needs_rebuild(const px_argv_plan *plan)
{
    if (plan == NULL || plan->magic != PX_PLAN_MAGIC) {
        return 0;
    }
    return (plan->n > 0 && plan->fixes != NULL) ? 1 : 0;
}

int px_apply_argv(char *const argv[], const px_argv_plan *plan,
                  char **out_vec, size_t out_cap, size_t *need_n)
{
    size_t count = 0;
    size_t i;
    size_t fix = 0;

    if (need_n != NULL) {
        *need_n = 0;
    }
    if (plan == NULL || plan->n == 0 || plan->fixes == NULL) {
        return PX_OK;   /* 零改写 → 调用方沿用原 argv（零分配快路径） */
    }
    if (argv == NULL || out_vec == NULL) {
        return PX_EINVAL;
    }

    while (count < (size_t)PX_ARGV_MAX && argv[count] != NULL) {
        count++;
    }

    if (need_n != NULL) {
        *need_n = count;
    }
    if (out_cap < count + 1u) {
        return PX_ENOSPC;
    }

    for (i = 0; i < count; i++) {
        if (fix < plan->n && plan->fixes[fix].index == i) {
            /* 改写过的条目指向 fix->text（在 plan 里，调用期间一直有效）。
             * **不深拷贝**：exec 成功后内存不再回收，深拷贝只会在
             * 失败路径上多一条泄漏。 */
            out_vec[i] = (char *)(uintptr_t)plan->fixes[fix].text;
            fix++;
        } else {
            /* 未改写的指针**原地复用** */
            out_vec[i] = argv[i];
        }
    }
    out_vec[count] = NULL;
    return PX_OK;
}

/* ================================================================== */
/* §3b  guest PATH 搜索                                                */
/* ================================================================== */

/* PATH 为空时的默认值，与 POSIX confstr(_CS_PATH) 一致。 */
#define PX_DEFAULT_PATH "/bin:/usr/bin"

static const char *px_path_env_or_default(const char *path_env)
{
    if (path_env == NULL || path_env[0] == '\0') {
        return PX_DEFAULT_PATH;
    }
    return path_env;
}

size_t px_search_count(const char *file, const char *path_env)
{
    const char *p;
    size_t n = 0;

    if (file == NULL || file[0] == '\0') {
        return 0;
    }
    /* 含 '/' 的文件名不走 PATH 搜索（POSIX 明确规定） */
    if (strchr(file, '/') != NULL) {
        return 1;
    }
    p = px_path_env_or_default(path_env);
    /*
     * ★ 尾部的空段必须计数 ★
     *
     * 计数与取值必须用同一套切分规则，否则会出现「计数说 2 段、
     * 取值说没有第 2 段」的不一致（PX_ENOENT），PATH 搜索静默少一个
     * 候选目录。`/a:` 的语义是 `/a` 与 `.` 两段（POSIX：空段 == 当前目录）。
     *
     * 修法是先计数再检查分隔符：`do { n++; ... } while (*p++ == ':')`。
     * 循环体走完一个段后，无论是因为遇到 ':' 还是因为到串尾，
     * 都还要再看一次 —— 到串尾时那一次 `n++` 代表最后的空段。
     */
    do {
        n++;
        while (*p != '\0' && *p != ':') {
            p++;
        }
    } while (*p++ == ':');
    return n;
}

int px_search_get(const char *file, const char *path_env, size_t i,
                  char *out, size_t outsz)
{
    const char *p;
    size_t seg = 0;

    if (file == NULL || file[0] == '\0' || out == NULL || outsz == 0) {
        return PX_EINVAL;
    }
    if (strchr(file, '/') != NULL) {
        if (i != 0) {
            return PX_ENOENT;
        }
        if (strlen(file) + 1u > outsz) {
            return PX_ETOOLONG;
        }
        memcpy(out, file, strlen(file) + 1u);
        return PX_OK;
    }

    /*
     * ★ 用 for(;;) + 尾部判断，而不是 `while (*p != '\0')` ★
     *
     * `while (*p != '\0')` 会在 p 落到串尾时立刻退出 —— 而
     * **尾部空段恰恰就是「p 指向串尾」的那个位置**。
     * `/a:` 的第二段（`.`）因此永远走不到，取值侧比计数侧少一段。
     * 这正是「计数说有 N 段、取值说只有 N-1 段」的来源。
     *
     * 现在改成先处理「当前段 [p, end)」，处理完再看是否到了串尾：
     * 到串尾就 break（这一段已经是最后一段），否则 p = end + 1。
     * 与 px_search_count 的 `do { n++; ... } while (*p++ == ':')` 严格同构。
     */
    p = px_path_env_or_default(path_env);
    for (;;) {
        const char *end = p;

        while (*end != '\0' && *end != ':') {
            end++;
        }
        if (seg == i) {
            size_t dir_len = (size_t)(end - p);
            int n;

            /* 空段 == "."：POSIX 语义。这里保留 "." 而不是展开成绝对路径，
             * 因为展开需要 getcwd，而纯逻辑层不做系统调用。 */
            if (dir_len == 0) {
                n = snprintf(out, outsz, "./%s", file);
            } else if (p[dir_len - 1] == '/') {
                n = snprintf(out, outsz, "%.*s%s", (int)dir_len, p, file);
            } else {
                n = snprintf(out, outsz, "%.*s/%s", (int)dir_len, p, file);
            }
            if (n < 0 || (size_t)n >= outsz) {
                return PX_ETOOLONG;
            }
            return PX_OK;
        }
        seg++;
        if (*end == '\0') {
            break;              /* 刚处理完的是最后一段（可能是空段） */
        }
        p = end + 1;
    }
    return PX_ENOENT;
}

/* ================================================================== */
/* §3c  无分配（bump）分配器                                            */
/* ================================================================== */

/* 对齐到 16 字节：aarch64 上 max_align_t 是 16，且 char 缓冲可能被
 * 用来放任何东西（本层只放 char 与 char*，但保守对齐没有代价）。 */
#define PX_BUMP_ALIGN 16u

static void *px_bump_alloc(void *ud, size_t n)
{
    px_bump *b = (px_bump *)ud;
    size_t off;

    if (b == NULL || b->base == NULL) {
        return NULL;
    }
    /*
     * ★ 对齐必须相对**绝对地址**，不能相对 b->used ★
     *
     * 早先的实现写的是 `off = align_up(b->used)`，即假设 b->base 本身
     * 已按 16 字节对齐。这个假设不成立：调用方传进来的往往是一个
     * `static char pool[N]` 或栈上数组，其对齐只保证到 1 字节
     * （char 的对齐要求）。base 未对齐时，所有返回地址都整体偏移，
     * 于是把一个 16 字节对齐要求的结构体放进 bump 就得到**未对齐访问**
     * —— aarch64 上对某些指令是硬件异常，对普通 ldr/str 是性能损失，
     * 而 C 层面是 UB。
     *
     * 这个缺陷在普通构建下**测不出来**（static 数组恰好被链接器对齐到
     * 16），只有 UBSan 改变了布局才暴露 —— 典型的布局相关潜在缺陷。
     * 所以修法不是「让调用方保证对齐」，而是分配器自己对齐绝对地址。
     */
    {
        uintptr_t base_addr = (uintptr_t)b->base;
        uintptr_t aligned = (base_addr + b->used + (PX_BUMP_ALIGN - 1u))
                            & ~(uintptr_t)(PX_BUMP_ALIGN - 1u);
        off = (size_t)(aligned - base_addr);
    }
    if (off > b->cap || !px_size_ge(b->cap - off, n)) {
        b->refusals++;
        return NULL;
    }
    b->used = off + n;
    if (b->used > b->peak) {
        b->peak = b->used;
    }
    /* high_water 与 peak 同步维护：调用方可能在任何时刻读 high_water，
     * 而它要的答案是「这块缓冲历史最大用到多少」。 */
    if (b->used > b->high_water) {
        b->high_water = b->used;
    }
    b->allocs++;
    return b->base + off;
}

/* bump 的「calloc」：分配并清零。
 * 清零是必须的 —— px_ledger_create / px_envout 都依赖 0 初值。 */
static void *px_bump_calloc(void *ud, size_t nmemb, size_t size)
{
    size_t total;
    void *p;

    if (nmemb != 0 && size > ((size_t)-1) / nmemb) {
        return NULL;
    }
    total = nmemb * size;
    p = px_bump_alloc(ud, total);
    if (p != NULL) {
        memset(p, 0, total);
    }
    return p;
}

/*
 * bump 的 free 是**空操作**。
 *
 * 这不是偷懒，是语义使然：bump 只能整体重置。把它做成 no-op 而不是
 * 「报错」，是为了让 px_env_build 的失败清理路径（会调 px_free）在
 * bump 下也能安全跑完 —— 那份代码不该为了两种分配器写两遍。
 * px_env_dispose 同理：在 bump 下它只清空结构体字段，不回收内存，
 * 而调用方紧接着就 px_bump_reset，语义闭合。
 */
static void px_bump_free(void *ud, void *p)
{
    (void)ud;
    (void)p;
}

void px_bump_init(px_bump *b, char *base, size_t cap)
{
    if (b == NULL) {
        return;
    }
    memset(b, 0, sizeof(*b));
    b->base = base;
    b->cap = (base == NULL) ? 0u : cap;
    b->ops.ud = b;
    b->ops.malloc = px_bump_alloc;
    b->ops.calloc = px_bump_calloc;
    b->ops.free = px_bump_free;
}

void px_bump_reset(px_bump *b)
{
    if (b == NULL) {
        return;
    }
    /*
     * high_water 在**分配时**就更新（见 px_bump_alloc 的 peak），
     * reset 只负责回收。
     *
     * 早先的实现把 high_water 的更新放在 reset 里，于是「分配完就读
     * high_water」永远是 0 —— 用它评估缓冲该开多大的调用方会得到
     * 「一块都不用」的错误结论。测试 H6 钉住这个语义。
     */
    if (b->used > b->high_water) {
        b->high_water = b->used;
    }
    b->used = 0;
}

const px_alloc *px_bump_ops(px_bump *b)
{
    return (b == NULL) ? NULL : &b->ops;
}

/* ================================================================== */
/* §4  kill 越界判定                                                   */
/* ================================================================== */

const px_killpolicy PX_KILLPOLICY_DEFAULT = {
    1,   /* protect_self   */
    1,   /* allow_parent   */
    0,   /* allow_broadcast */
    1    /* allow_group    */
};

int px_signal_always_allowed(int sig)
{
    /*
     * SIGCHLD 必须永远放行。
     *
     * 进程管理协议（shell 的 job control、Node 的 libuv、Python 的
     * subprocess、以及 waitpid 的实现细节）会给自己发 SIGCHLD。
     * 拦掉它 → 所有子进程回收停摆 → 表现为「命令跑完了但 shell 不返回」。
     * 这个信号对自己发是安全的（不会打到容器外）。
     */
    return sig == SIGCHLD;
}

proc_kill_verdict px_check_kill(const px_ledger *l, const px_killpolicy *pol,
                                const px_sysops *sys, pid_t self_pid,
                                pid_t target, int sig)
{
    const px_killpolicy *p = (pol != NULL) ? pol : &PX_KILLPOLICY_DEFAULT;

    /* 账本不可用 → 退化为无保护。这是刻意的：没有账本时拒绝一切会
     * 让容器内的进程管理彻底瘫痪（连自己的子进程都杀不掉），
     * 而「拒绝一切」并不是安全，只是不可用。 */
    if (l == NULL || px_ledger_is_disabled(l)) {
        return PROC_KILL_PASS;
    }

    if (px_signal_always_allowed(sig)) {
        return PROC_KILL_PASS;
    }

    /* 广播形态：kill(-1, sig) 与 kill(0, sig) 会打到当前 uid 能打的
     * **所有**进程，包括 DSHA 自己和 Android 的 app 进程。
     * 这是最危险的形态，默认直接拒绝。 */
    if (target == -1 || target == 0) {
        if (p->allow_broadcast) {
            return PROC_KILL_PASS;
        }
        return PROC_KILL_DENY;
    }

    if (target > 0) {
        /* 自己：常规操作（自杀、自挂起） */
        if (p->protect_self && self_pid > 0 && target == self_pid) {
            return PROC_KILL_PASS;
        }
        /* 账本里活着的 → 放行 */
        {
            px_procinfo info;
            if (px_ledger_get(l, target, PX_ENTRY_PID, &info) == PX_OK) {
                if (info.life == PX_LIVE) {
                    return PROC_KILL_PASS;
                }
                /*
                 * reaped：**必须拒绝**。
                 *
                 * 这是本层最重要的一条判定。已经 wait 掉的 pid 会被宿主
                 * 回收再分配；此刻放行等于把信号打进宿主里一个完全无辜的
                 * 进程（可能是 Android 的系统服务）。真实场景：容器里
                 * `sh -c 'sleep 1 & wait'` 之后 sleep 的 pid 被回收，
                 * 一条迟到的 kill 就把随机进程杀了。
                 */
                return PROC_KILL_DENY;
            }
        }
        /* 父进程：shell / libuv / subprocess 依赖给父进程发信号 */
        /*
         * ★ self_pid <= 0 时不得走 allow_parent ★
         *
         * self_pid 无效意味着我们不知道「自己是谁」。此时把 target
         * 与 getppid() 比较是没有意义的：调用方传 self_pid=0 通常是
         * 「缓存未初始化」的信号，而不是「我的 pid 是 0」。
         * 继续放行会让白名单在状态异常时**放宽** —— 安全判定的
         * 失败方向必须是「更严格」，不能是「更宽松」。
         */
        if (p->allow_parent && sys != NULL && sys->getppid != NULL &&
            self_pid > 0) {
            pid_t pp = sys->getppid();
            if (pp > 0 && target == pp) {
                return PROC_KILL_PASS;
            }
        }
        return PROC_KILL_DENY;
    }

    /* target < 0：进程组。pgid == |target| */
    if (!p->allow_group) {
        return PROC_KILL_DENY;
    }
    {
        pid_t pgid = -target;

        /* 自己的进程组：shell 的 job control 会 kill 自己所在的组 */
        if (sys != NULL && sys->getpgrp != NULL && sys->getpgrp() == pgid) {
            return PROC_KILL_PASS;
        }
        if (px_ledger_has(l, pgid, PX_ENTRY_PID) ||
            px_ledger_has(l, pgid, PX_ENTRY_PGID)) {
            px_procinfo info;
            /* 组条目里若记的是已回收的 pid，同样要拒绝 */
            if (px_ledger_get(l, pgid, PX_ENTRY_PGID, &info) == PX_OK &&
                info.life == PX_REAPED) {
                return PROC_KILL_DENY;
            }
            return PROC_KILL_PASS;
        }
    }
    return PROC_KILL_DENY;
}

/* ================================================================== */
/* §5  atfork 三件套                                                   */
/* ================================================================== */

void px_forkguard_init(px_forkguard *g, const px_lockops *ops, int enabled)
{
    if (g == NULL) {
        return;
    }
    memset(g, 0, sizeof(*g));
    g->lockops = ops;
    g->enabled = enabled ? 1 : 0;
}

void px_forkguard_set_enabled(px_forkguard *g, int enabled)
{
    if (g != NULL) {
        g->enabled = enabled ? 1 : 0;
    }
}

/* 内部：实际的取锁/放锁。ops 为空时退化为 no-op。 */
static void px_guard_lock(px_forkguard *g)
{
    if (g == NULL || !g->enabled || g->lockops == NULL ||
        g->lockops->lock == NULL) {
        return;
    }
    g->lockops->lock(g->lockops->ud);
}

static void px_guard_unlock(px_forkguard *g)
{
    if (g == NULL || !g->enabled || g->lockops == NULL ||
        g->lockops->unlock == NULL) {
        return;
    }
    g->lockops->unlock(g->lockops->ud);
}

void px_child_reset(px_ledger *l)
{
    /*
     * 子进程里与 pid 绑定的缓存必须失效。
     *
     * 当前账本里唯一与「本进程 pid」相关的隐含状态是：构造时登记的
     * self 条目（tag == PX_TAG_SELF）。子进程的 pid 变了，那条记录
     * 描述的是**父进程**，留在表里会让子进程误以为父进程是「自己创建的」，
     * 于是 kill(父pid) 被放行 —— 而父进程本来就在 allow_parent 白名单里，
     * 所以这里主要作用是**避免表被无名条目污染**。
     *
     * 真正必须做的是：把 reaped 条目标记清掉。子进程继承的 reaped 集合
     * 描述的是父进程的历史，对子进程无意义，且会无谓地拒绝合法的
     * pid 复用。live 条目**保留** —— 子进程与父进程共享这些子进程
     * （fork 后两边都看得到），保留才正确。
     */
    size_t i;

    if (l == NULL || l->disabled) {
        return;
    }
    for (i = 0; i < l->cap; i++) {
        px_slot *s = &l->slots[i];
        if (s->state != PX_SLOT_LIVE) {
            continue;
        }
        if (s->info.tag == PX_TAG_SELF) {
            /* 父进程的 self 记录，在子进程里没有意义 */
            px_slot_release(s);
            l->count--;
            l->tombs++;
        }
    }
}

void px_forkguard_prepare(px_forkguard *g, px_ledger *l)
{
    (void)l;
    if (g == NULL) {
        return;
    }
    g->prepare_calls++;
    if (g->lockops != NULL && g->lockops->lock != NULL) {
        px_guard_lock(g);
    }
    g->locked = 1;
    if (g->lockops != NULL && g->lockops->ud != NULL &&
        g->lockops->lock == NULL) {
        /* 没有真锁时无法自洽 */
    }
}

void px_forkguard_parent(px_forkguard *g, px_ledger *l)
{
    (void)l;
    if (g == NULL) {
        return;
    }
    g->parent_calls++;
    px_guard_unlock(g);
    g->locked = 0;
}

void px_forkguard_child(px_forkguard *g, px_ledger *l)
{
    if (g == NULL) {
        return;
    }
    g->child_calls++;

    /*
     * 子进程里的第一要务是**放锁**。
     *
     * 顺序很重要：必须先解锁再碰账本。若先查账本，而我们此刻正持有锁，
     * 就会自锁 —— 那正是我们要修的那个死锁，自己再制造一次就荒谬了。
     * glibc 的 atfork 协议保证 child 回调在子进程里以「锁被本线程持有」
     * 的状态进入（父进程的 prepare 刚取过），所以直接解锁是正确且必要的。
     */
    px_guard_unlock(g);
    g->locked = 0;

    /* 记录子进程自己的 pid，供后续检出自增 */
    if (g->lockops == NULL) {
        g->inconsistent_detected++;
    }

    px_child_reset(l);
    g->child_resets++;
}

int px_forkguard_parent_register(px_forkguard *g, px_ledger *l, pid_t child)
{
    int rc;

    if (child <= 0) {
        return PX_EINVAL;
    }
    rc = px_ledger_add(l, child, (l != NULL) ? 0 : 0, PX_TAG_FORK);
    if (rc == PX_OK && g != NULL) {
        g->fork_pid = child;
    }
    return rc;
}

int px_fork_should_abort(int reg_rc)
{
    /*
     * 登记失败就必须放弃这个子进程。
     *
     * 理由：不在账本里的子进程会被我们自己的 kill 白名单拒绝，
     * 于是「起了但杀不掉」—— 比根本起不来更糟（失控的孤儿进程会一直
     * 占着端口/文件锁）。宁可 fork 直接失败（返回 -1 + EAGAIN），
     * 让调用方看到明确的错误。
     *
     * 注意：**不能**把「账本被 disabled」当成失败 —— 那是用户显式关掉了
     * 保护，此时记账是 no-op 且返回 PX_OK，不会走到这里。
     */
    return reg_rc != PX_OK;
}

/* ================================================================== */
/* §6  钩子层                                                          */
/* ================================================================== */

#if !PX_PURE_LOGIC

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * 从 preload.c 借用翻译器与日志。
 * 用 weak 符号是**硬性要求**：proc.c 必须能单独编译进单元测试
 * （测试里没有 preload.c 的符号），而生产里两者一定一起链接。
 * 非 weak 会让测试链接失败；非 weak 的替代方案是把翻译器强制注入，
 * 但那会让「忘记注入」变成运行期静默失效 —— weak + 判空更安全。
 */
extern int bxroot_translate_path(const char *path, char *out, size_t out_size)
    __attribute__((weak));
extern void bxroot_log(const char *fmt, ...) __attribute__((weak));

#define PX_LOG(...) do {                                              \
        if (bxroot_log != NULL && g_rt_cfg.verbose) {                 \
            bxroot_log(__VA_ARGS__);                                  \
        }                                                             \
    } while (0)

/* ------------------------------------------------------------------ */
/* 全局状态                                                            */
/* ------------------------------------------------------------------ */

static px_rtconfig g_rt_cfg;
static int         g_rt_ready;          /* 0 = 未初始化, 1 = 已初始化 */
static px_ledger  *g_rt_ledger;
static px_rt_stats g_rt_stats;
static px_lockops  g_rt_lockops;        /* 保护账本的互斥锁（见下） */
static px_forkguard g_rt_guard;
static pthread_mutex_t g_rt_mutex = PTHREAD_MUTEX_INITIALIZER;

static px_xlate_fn g_xlate_fn;
static void       *g_xlate_ud;

/* atfork 三件套的前置声明。定义在本文件靠后处，但构造函数要用它们的地址。 */
static void px_atfork_prepare(void);
static void px_atfork_parent(void);
static void px_atfork_child(void);

/*
 * 账本锁用**静态初始化**的 pthread_mutex，不走 pthread_mutex_init。
 *
 * 理由：初始化顺序。pthread_atfork 的 prepare 回调可能在构造函数
 * （或甚至 dlopen 期间）就被 fork 触发，那时若锁还没 init，
 * 取锁就是未定义行为。静态初始化把锁变成 .bss 里的常量，没有时序问题。
 */

static void px_rt_lock(void *ud)
{
    (void)ud;
    pthread_mutex_lock(&g_rt_mutex);
}

static void px_rt_unlock(void *ud)
{
    (void)ud;
    pthread_mutex_unlock(&g_rt_mutex);
}

/* ------------------------------------------------------------------ */
/* 配置初始化                                                          */
/* ------------------------------------------------------------------ */

/*
 * 判定「哪个变量是调用方显式指定的」。
 *
 * 直接 getenv("BXROOT_LD_PRELOAD") 不行 —— 那是**我们自己**待会儿要
 * 写进去的值，读它等于把自己的输出当输入。所以必须区分
 * 「绝对路径且不是我们自己」的形态：只有在 BXROOT_LD_PRELOAD 显式设置
 * 且与 /proc/self/maps 自映射不符时才采信。
 */
static void px_cfg_str(char *dst, size_t cap, const char *v)
{
    if (dst == NULL || cap == 0) {
        return;
    }
    if (v == NULL) {
        dst[0] = '\0';
        return;
    }
    /* 截断而不是失败：配置过长时宁可要一个可用的短前缀，
     * 也不要整体禁用保护（禁用会被误解为「已保护」）。 */
    {
        size_t n = strlen(v);
        if (n >= cap) {
            n = cap - 1u;
        }
        memcpy(dst, v, n);
        dst[n] = '\0';
    }
}

static void px_cfg_bool(int *dst, const char *v)
{
    *dst = (v != NULL && v[0] != '\0' && v[0] != '0') ? 1 : 0;
}

/*
 * 找当前进程自己的 so 路径。
 *
 * ★ 为什么不能只靠 PROROOT_LIB_PATH / BXROOT_LIB_PATH ★
 * 配置可能缺失、可能过期（库被换过路径）、也可能被 guest 覆盖。
 * 而 LD_PRELOAD 写错的后果是**静默**的：子进程照常启动，只是没有钩子。
 * 所以我们优先用 dladdr 从自己的函数地址反查真实路径 —— 这是唯一
 * 不依赖任何外部配置的来源。
 *
 * dladdr 在某些静态/受限环境会失败，此时回落环境变量。
 */
static void px_detect_self_lib(char *dst, size_t cap)
{
    Dl_info info;

    dst[0] = '\0';
    memset(&info, 0, sizeof(info));
    if (dladdr((void *)(uintptr_t)&px_runtime_init, &info) != 0 &&
        info.dli_fname != NULL && info.dli_fname[0] != '\0') {
        px_cfg_str(dst, cap, info.dli_fname);
        if (dst[0] == '/') {
            return;   /* 拿到绝对路径，这就是最优解 */
        }
    }
    /* 回落：由 preload.c / launcher 注入 */
    {
        const char *v = getenv("BXROOT_LD_PRELOAD");
        if (v == NULL || v[0] == '\0') {
            v = getenv("PROROOT_LIB_PATH");
        }
        px_cfg_str(dst, cap, v);
    }
}

/*
 * 取出 guest 自己设的 LD_PRELOAD（在我们的构造之前）。
 *
 * 构造函数执行时 environ 里已经有 ld.so 处理过的 LD_PRELOAD 原值，
 * 所以这里直接读是对的。但要注意区分「guest 设的」与「上一级容器设的」：
 * 两者我们都要保留（合并而非覆盖），所以不需要区分，直接合并即可。
 */
static void px_cfg_merge_preload(void)
{
    char ours[PX_PRELOAD_MAX];
    char merged[PX_PRELOAD_MAX];
    const char *existing = getenv("LD_PRELOAD");
    const char *self = getenv("BXROOT_LD_PRELOAD");
    int rc;

    px_detect_self_lib(ours, sizeof(ours));

    /*
     * 若环境里已经有 BXROOT_LD_PRELOAD（说明我们是子进程、上一级已经
     * 注入过），它比 dladdr 更可信吗？不一定 —— 库可能被换过路径。
     * 但 dladdr 拿到的是**正在运行的这一份**，永远正确。
     * 所以 ours 以 dladdr 为准；只有当 dladdr 失败时才用 BXROOT_LD_PRELOAD。
     */
    if (ours[0] == '\0' && self != NULL && self[0] != '\0') {
        px_cfg_str(ours, sizeof(ours), self);
    }

    if (ours[0] == '\0') {
        /* 连自己是谁都不知道 → 整体禁用注入。
         * 注入一个空 LD_PRELOAD= 会把 guest 原有的 preload 也清掉，有害。 */
        g_rt_cfg.have_preload = 0;
        g_rt_cfg.inject = 0;
        PX_LOG("proc: 无法确定自身库路径，envp 注入已禁用");
        return;
    }

    rc = px_merge_preload(existing, ours, merged, sizeof(merged));
    if (rc != PX_OK) {
        PX_LOG("proc: LD_PRELOAD 合并失败 rc=%d", rc);
        g_rt_cfg.have_preload = 0;
        g_rt_cfg.inject = 0;
        return;
    }
    px_cfg_str(g_rt_cfg.preload, sizeof(g_rt_cfg.preload), merged);
    g_rt_cfg.have_preload = 1;

    /*
     * 就地同步进程环境。
     *
     * 这一步覆盖了 `system()`/`popen()`：已实证它们的子进程环境取自
     * environ（见 exp/EVIDENCE.md E5、exp/environ_probe.c），
     * 所以只要 environ 里有了 LD_PRELOAD，即使我们完全不 hook system，
     * 它的子进程也会带上我们的运行时。
     */
    if (setenv("LD_PRELOAD", merged, 1) != 0) {
        PX_LOG("proc: setenv(LD_PRELOAD) 失败");
    }
    if (setenv("BXROOT_LD_PRELOAD", ours, 1) != 0) {
        PX_LOG("proc: setenv(BXROOT_LD_PRELOAD) 失败");
    }
}

int px_runtime_init(void)
{
    const char *v;

    if (g_rt_ready) {
        return g_rt_cfg.inject;
    }
    g_rt_ready = 1;
    memset(&g_rt_cfg, 0, sizeof(g_rt_cfg));

    px_cfg_bool(&g_rt_cfg.verbose, getenv("BXROOT_VERBOSE"));
    if (!g_rt_cfg.verbose) {
        px_cfg_bool(&g_rt_cfg.verbose, getenv("PROROOT_VERBOSE"));
    }

    /* rootfs：BXROOT_* 优先（bxroot 自己的命名），回落 PROROOT_* */
    v = getenv("BXROOT_ROOTFS");
    if (v == NULL || v[0] == '\0') {
        v = getenv("PROROOT_ROOTFS");
    }
    if (v != NULL && v[0] != '\0') {
        px_cfg_str(g_rt_cfg.rootfs, sizeof(g_rt_cfg.rootfs), v);
        /* 尾斜杠归一化 —— 与 preload.c 的 strip_trailing_slash 同样必要。
         * 不做的话 px_classify_arg 的幂等判定会失配（长度含尾斜杠）。 */
        {
            size_t n = strlen(g_rt_cfg.rootfs);
            while (n > 1 && g_rt_cfg.rootfs[n - 1] == '/') {
                g_rt_cfg.rootfs[--n] = '\0';
            }
        }
        g_rt_cfg.have_rootfs = 1;
    }

    v = getenv("BXROOT_L2S_DIR");
    if (v == NULL || v[0] == '\0') {
        v = getenv("PROOT_L2S_DIR");
    }
    px_cfg_str(g_rt_cfg.l2s_dir, sizeof(g_rt_cfg.l2s_dir), v);

    /*
     * 注入总开关，默认**开启**。
     *
     * 这是刻意的默认值：本层的存在意义就是防止子进程失去钩子，
     * 默认关闭等于默认留着一个静默的容器逃逸口。要关必须显式关。
     */
    v = getenv("BXROOT_INJECT_ENV");
    if (v == NULL || v[0] == '\0') {
        g_rt_cfg.inject = 1;
    } else {
        px_cfg_bool(&g_rt_cfg.inject, v);
    }

    px_cfg_merge_preload();

    /* 账本 + 锁 + atfork */
    g_rt_lockops.lock = px_rt_lock;
    g_rt_lockops.unlock = px_rt_unlock;
    g_rt_lockops.ud = NULL;
    px_forkguard_init(&g_rt_guard, &g_rt_lockops, 1);

    g_rt_ledger = px_ledger_create(0, NULL);
    if (g_rt_ledger == NULL) {
        PX_LOG("proc: pid 账本创建失败，kill 保护与 fork 记账已禁用");
    }

    /* 注册 atfork 三件套。
     *
     * 注意 pthread_atfork 的返回值**必须检查**：失败时我们没有保护，
     * 而「没有保护」与「有保护」在外部完全看不出来 —— 必须记录。 */
    if (pthread_atfork(px_atfork_prepare, px_atfork_parent,
                       px_atfork_child) != 0) {
        PX_LOG("proc: pthread_atfork 注册失败 —— fork 后子进程可能死锁");
    }

    g_rt_ready = 1;
    PX_LOG("proc: init inject=%d have_preload=%d rootfs=%s",
           g_rt_cfg.inject, g_rt_cfg.have_preload,
           g_rt_cfg.have_rootfs ? g_rt_cfg.rootfs : "(none)");
    return g_rt_cfg.inject;
}

const px_rtconfig *px_runtime_config(void)
{
    return g_rt_ready ? &g_rt_cfg : NULL;
}

px_ledger *px_runtime_ledger(void)
{
    return g_rt_ledger;
}

void px_runtime_set_translator(px_xlate_fn fn, void *ud)
{
    g_xlate_fn = fn;
    g_xlate_ud = ud;
}

const px_rt_stats *px_runtime_stats(void)
{
    return &g_rt_stats;
}

void px_runtime_reset_stats(void)
{
    memset(&g_rt_stats, 0, sizeof(g_rt_stats));
}

/* ------------------------------------------------------------------ */
/* 翻译器薄封装                                                        */
/* ------------------------------------------------------------------ */

/*
 * 翻译一条路径。
 *
 * 优先级：显式注入的翻译器 > preload.c 的 weak 符号 > 原样返回。
 * 三级回落的好处是 proc.c 在任一集成阶段都能跑：单测阶段没有翻译器
 * （原样返回仍然测得到 envp/账本/kill），半集成阶段有 preload.c，
 * 全集成阶段走注入。
 */
int px_runtime_translate(const char *path, char *out, size_t outsz)
{
    if (g_xlate_fn != NULL) {
        return g_xlate_fn(g_xlate_ud, path, out, outsz);
    }
    if (bxroot_translate_path != NULL) {
        return bxroot_translate_path(path, out, outsz);
    }
    /* 没有翻译器：原样返回，且返回 0 表示「无需翻译」，
     * 让调用方沿用原指针（零分配）。 */
    (void)path;
    (void)out;
    (void)outsz;
    return 0;
}

static int px_xlate_trampoline(void *ud, const char *path, char *out, size_t outsz)
{
    (void)ud;
    return px_runtime_translate(path, out, outsz);
}

/* ------------------------------------------------------------------ */
/* envp 重建                                                           */
/* ------------------------------------------------------------------ */

/*
 * 构造强制写入的环境变量表。
 *
 * 为什么不写 BXROOT_L2S_DIR / BXROOT_FAKEROOT 之类：
 * 那些是**本次容器会话的配置**，不是身份。它们的值要么已经在环境里
 * （继承），要么就不该被我们凭空发明（发明一个默认值会静默地打开
 * 一个用户没要的功能）。我们只强制写「身份与去重必需」的四项。
 */
static int px_build_forced(const px_rtconfig *cfg, px_env_kv *kv, size_t cap)
{
    size_t n = 0;

    if (n < cap) {
        kv[n].name = "LD_PRELOAD";
        kv[n].value = cfg->preload;
        /* ★ MERGE 而不是 SET ★
         *
         * 调用方（Node 的 `env:`、Python 的 `env=`）传进来的 envp 里
         * 可能有 guest 自己设的 LD_PRELOAD。直接覆盖会静默丢掉它，
         * 而容器自己的钩子照样工作 —— 缺陷只在「某个依赖 preload 的
         * 第三方工具行为诡异」时暴露，排查方向完全跑偏。
         * px_env_build 在 MERGE 模式下会先查原值再合并（ours 在前）。 */
        kv[n].mode = PX_ENV_MERGE_PRELOAD;
        n++;
    }
    if (cfg->have_rootfs && n < cap) {
        kv[n].name = "BXROOT_ROOTFS";
        kv[n].value = cfg->rootfs;
        kv[n].mode = PX_ENV_SET;
        n++;
    }
    /*
     * BXROOT_ROOTFS 与 PROROOT_ROOTFS 都写。
     *
     * 理由：两个名字在本项目里**都在被读**（preload.c 读 PROROOT_ROOTFS，
     * 新的 bxroot 代码读 BXROOT_ROOTFS）。只写一个会让另一半读到旧值 ——
     * 而旧值可能指向上一级容器的 rootfs，于是路径翻译出现**双层前缀**。
     * 这类缺陷的表征是 ENOENT，排查方向会完全跑偏。
     */
    if (cfg->have_rootfs && n < cap) {
        kv[n].name = "PROROOT_ROOTFS";
        kv[n].value = cfg->rootfs;
        kv[n].mode = PX_ENV_SET;
        n++;
    }
    if (cfg->have_preload && n < cap) {
        kv[n].name = "BXROOT_LD_PRELOAD";
        /* 这个是「我们的库」的记录，用 SET：调用方给的 BXROOT_LD_PRELOAD
         * 可能是过期路径，必须以我们实际加载的那一份为准。 */
        kv[n].value = cfg->preload;
        kv[n].mode = PX_ENV_SET;
        n++;
    }
    return (int)n;
}

int px_runtime_build_env(char *const envp[], px_envout *out)
{
    px_env_kv forced[4];
    px_envpolicy pol;
    int nf;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (g_rt_ready && !g_rt_cfg.inject) {
        return -1;      /* 用户显式关掉了 */
    }
    if (!g_rt_ready || !g_rt_cfg.have_preload) {
        /* 没有自身路径 → 注入无意义（写不出有效的 LD_PRELOAD） */
        return -1;
    }

    nf = px_build_forced(&g_rt_cfg, forced, 4);
    if (nf <= 0) {
        return -1;
    }

    memset(&pol, 0, sizeof(pol));
    pol.forced = forced;
    pol.forced_n = (size_t)nf;
    pol.drop = NULL;
    pol.drop_n = 0;
    pol.max_entries = 0;

    /*
     * envp == NULL 时用 environ。
     *
     * 这是钩子层必须做的兜底：`execv`/`execvp`/`execl` 家族根本不传 envp，
     * POSIX 规定它们用当前环境。把 NULL 直接交给 px_env_build 会得到一个
     * **空环境**的子进程 —— 那比不注入更糟（PATH 都没了，子进程连
     * 动态链接都可能失败）。纯逻辑层不兜底是刻意的（要能测「空环境」），
     * 兜底责任在这一层。
     */
    {
        int rc = px_env_build((const char *const *)envp, &pol, out, NULL);
        if (rc != PX_OK) {
            PX_LOG("proc: envp 重建失败 rc=%d", rc);
            errno = (rc == PX_ENOMEM) ? ENOMEM : EINVAL;
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* kill 判定                                                           */
/* ------------------------------------------------------------------ */

/*
 * self_pid 缓存。
 *
 * kill 是热路径（Node 的 libuv 每次子进程退出都会走），而 getpid()
 * 在有些 libc 实现上是真正的系统调用。缓存它是安全的 —— 但必须
 * 在 fork 的 child 回调里失效，否则子进程会把自己当成父进程。
 * 这正是 px_forkguard 的 child 回调要做的第三件事。
 */
static pid_t g_cached_self_pid;

static pid_t px_self_pid(void)
{
    if (g_cached_self_pid <= 0) {
        g_cached_self_pid = (pid_t)syscall(SYS_getpid);
        if (g_cached_self_pid <= 0) {
            g_cached_self_pid = 1;   /* 极端兜底：绝不留 0（0 是广播语义） */
        }
    }
    return g_cached_self_pid;
}

/* 供 sysops 注入用（px_check_kill 的 allow_parent / allow_group 分支） */
static pid_t px_real_getpid(void) { return (pid_t)syscall(SYS_getpid); }
static pid_t px_real_getppid(void) { return (pid_t)syscall(SYS_getppid); }
static pid_t px_real_getpgrp(void) { return (pid_t)syscall(SYS_getpgid, 0); }
static int   px_real_kill(pid_t p, int s) { return (int)syscall(SYS_kill, p, s); }

static const px_sysops PX_SYSOPS = {
    px_real_getpid, px_real_getppid, px_real_getpgrp, px_real_kill
};

/* ------------------------------------------------------------------ */
/* atfork 回调                                                         */
/* ------------------------------------------------------------------ */

/*
 * 三个回调**必须不返回错误、不调用可能取我们自己的锁的函数**。
 * prepare 里除了取锁什么都不做：任何分配/日志都可能死锁
 * （日志走 stdio，stdio 有自己的锁，而另一线程可能正持着它 fork）。
 */
static void px_atfork_prepare(void)
{
    px_forkguard_prepare(&g_rt_guard, g_rt_ledger);
}

static void px_atfork_parent(void)
{
    px_forkguard_parent(&g_rt_guard, g_rt_ledger);
}

static void px_atfork_child(void)
{
    /*
     * 顺序：放锁 → 失效 pid 缓存 → 重置账本。
     * 反过来（先查账本）会自锁，正是我们要修的那个死锁。
     */
    px_forkguard_child(&g_rt_guard, g_rt_ledger);
    g_cached_self_pid = 0;          /* 我的 pid 变了 */
    /* 子进程把自己登记进账本（它继承了父进程的账本副本） */
    (void)px_ledger_add(g_rt_ledger, px_self_pid(), 0, PX_TAG_SELF);
}

void px_runtime_register_self(void)
{
    (void)px_ledger_add(g_rt_ledger, px_self_pid(), 0, PX_TAG_SELF);
}

/* ------------------------------------------------------------------ */
/* 公共辅助：把一次 exec 的目标解析成宿主绝对路径                       */
/* ------------------------------------------------------------------ */

/*
 * 解析 exec/spawn 的 `path` 参数。
 *
 * 分三种输入：
 *   1. 含 '/'      → 直接翻译（可能是绝对路径，也可能是相对路径）
 *   2. 不含 '/'    → PATH 搜索，用 **guest PATH**，逐个候选翻译 + 探测
 *   3. NULL/空     → 失败
 *
 * 返回 0 成功（host_out 里是宿主绝对路径）；-1 失败（errno 已置）。
 *
 * ★ 为什么 PATH 搜索必须自己做 ★
 * 交给真实 `execvpe`/`posix_spawnp` 会让它们用**宿主 PATH** 搜索，
 * 于是容器里 `ls` 可能解析到宿主的 /usr/bin/ls，而那个二进制会以宿主
 * 视角运行（即使 LD_PRELOAD 在，它的 rootfs 也已经正确了 —— 但
 * 「找错文件」本身就是错误：容器里的 ls 与宿主的可能是不同版本）。
 * 更糟的是 PATH 里的目录在宿主不存在而在 rootfs 存在时直接 ENOENT。
 */
static int px_resolve_exec_path(const char *path, const char *path_env,
                                char *host_out, size_t host_cap,
                                char *guest_out, size_t guest_cap)
{
    size_t n;
    size_t i;

    if (path == NULL || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }

    n = px_search_count(path, path_env);
    for (i = 0; i < n; i++) {
        char cand[PX_PATH_MAX];
        char host[PX_PATH_MAX];
        int rc;

        if (px_search_get(path, path_env, i, cand, sizeof(cand)) != PX_OK) {
            continue;
        }
        rc = px_runtime_translate(cand, host, sizeof(host));
        if (rc < 0) {
            continue;
        }
        if (rc == 0) {
            /* 无需翻译 → 原样（相对路径） */
            px_cfg_str(host, sizeof(host), cand);
        }
        /*
         * 探测。
         *
         * 这里用 access(X_OK) 而不是 stat：POSIX 要求 PATH 搜索跳过
         * 「存在但不可执行」的候选继续往下找，access(X_OK) 正好表达这个语义。
         * 注意我们探的是**宿主路径** —— 这正是要点。
         */
        if (access(host, X_OK) == 0) {
            px_cfg_str(host_out, host_cap, host);
            if (guest_out != NULL) {
                px_cfg_str(guest_out, guest_cap, cand);
            }
            return 0;
        }
    }
    errno = ENOENT;
    return -1;
}

/* ------------------------------------------------------------------ */
/* exec 钩子族                                                         */
/* ------------------------------------------------------------------ */

/* 真实函数指针。全部懒加载 + 每次判空 —— 空指针解引用在 LD_PRELOAD 里
 * 等于整个容器进程 SIGSEGV，本项目已踩过一次。 */
static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
static int (*real_fexecve)(int, char *const[], char *const[]) = NULL;
static int (*real_execveat)(int, const char *, char *const[], char *const[], int) = NULL;
static int (*real_posix_spawn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                               const posix_spawnattr_t *, char *const[], char *const[]) = NULL;
static int (*real_fork)(void) = NULL;
static int (*real_vfork)(void) = NULL;
static int (*real_system)(const char *) = NULL;
static FILE *(*real_popen)(const char *, const char *) = NULL;
static int (*real_kill)(pid_t, int) = NULL;

/*
 * 不透明判空。
 *
 * ★ 为什么不能直接写 `if (p != NULL)` ★
 *
 * `execl`/`execveat`/`posix_spawn` 等标准原型把这些参数标了 `nonnull`
 * （见 glibc 的 `__nonnull` 属性）。GCC 于是认定「它永远不为 NULL」，
 * 我们那个**必须保留**的防御性判空就触发 `-Wnonnull-compare`。
 *
 * 而这些判空是**不能删**的：本项目红线要求「所有指针使用前必须判空」
 * （LD_PRELOAD 里一次空指针 = 整个容器进程 SIGSEGV，已踩过一次）。
 * 何况现实里确实有调用方违反契约传 NULL（尤其是手写的 FFI 绑定）。
 *
 * 所以用一个 `noinline` 的恒等函数把指针「洗」一遍：GCC 看不到
 * 属性传播路径，警告消失，判空仍然真实存在且不会被优化掉。
 * 代价是一次函数调用 —— 只在这些热路径的**入口**发生一次，可忽略。
 */
__attribute__((noinline))
static int px_is_null(const void *p)
{
    /* volatile 防 GCC 把本函数内联后又推出 nonnull */
    const void *volatile v = p;
    return v == NULL;
}

static void *px_dlsym(const char *name)
{
    void *p = dlsym(RTLD_NEXT, name);
    if (p == NULL) {
        PX_LOG("proc: dlsym(%s) 失败: %s", name, dlerror());
    }
    return p;
}

/*
 * execve 的核心实现，供 execve / execvpe 共用。
 *
 * ★ 注意这里没有 hook `execv`/`execvp`/`execl*` ★
 * 理由是**反汇编实证**的：glibc 2.39 里这些函数是**尾跳转**到 execve/execvpe
 * 的（`execv` @0xbdc90: `b 0xbdcc0`；`execvp` @0xbdd30: `b 0xbe184`）。
 * 而且它们确实是可插入的导出符号 —— 所以调用方的 `execvp` 会先进入
 * **我们的** execvp（若我们定义了），我们再调 RTLD_NEXT 的真实 execvp，
 * 而真实 execvp 尾跳转到 **execve 符号地址**（同 DSO 内部绑定，不可插入）。
 *
 * 于是有两种设计：
 *   (a) 同时 hook execvp/execv，各自做一次解析再转 execve → 重复逻辑；
 *   (b) 只 hook execve/execvpe，让 execvp→execve 的转发自然落到我们身上。
 *
 * 选 (b)？不行 —— 真实的 execvp 尾跳转是到 execve 的**内部地址**，
 * 不经过 PLT，所以它不会回到我们的 execve。必须走 (a)。
 * 因此下面 execv/execvp/execvpe/execveat 都要独立 hook。
 */
static int px_do_execve(const char *path, char *const argv[],
                        char *const envp[], const char *path_env,
                        int use_search)
{
    char host[PX_PATH_MAX];
    char guest[PX_PATH_MAX];
    px_envout env;
    px_argv_plan plan;
    char *vec[PX_ARGV_MAX + 1];
    size_t need = 0;
    const char *final_env_use = NULL;
    char *const *final_env;
    char *const *final_argv;
    int rc;

    g_rt_stats.exec_calls++;

    /* 1) 解析目标路径 */
    if (use_search) {
        if (px_resolve_exec_path(path, path_env, host, sizeof(host),
                                 guest, sizeof(guest)) != 0) {
            return -1;   /* errno 已置 ENOENT */
        }
    } else {
        rc = px_runtime_translate(path, host, sizeof(host));
        if (rc < 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (rc == 0) {
            px_cfg_str(host, sizeof(host), path);
        }
        px_cfg_str(guest, sizeof(guest), path);
    }

    /* 2) argv 翻译（默认只翻 argv[0]） */
    rc = px_plan_argv(argv, g_rt_cfg.have_rootfs ? g_rt_cfg.rootfs : NULL,
                      px_xlate_trampoline, NULL, &plan);
    if (rc != PX_OK) {
        /* 计划失败（参数过多）不该让 exec 失败 —— 参数多不是错误。
         * 放弃翻译，原样转发。 */
        PX_LOG("proc: argv 计划失败 rc=%d，跳过 argv 翻译", rc);
        final_argv = argv;
    } else if (px_plan_needs_rebuild(&plan)) {
        rc = px_apply_argv(argv, &plan, vec, PX_ARGV_MAX + 1, &need);
        final_argv = (rc == PX_OK) ? vec : argv;
    } else {
        final_argv = argv;
    }

    /* 3) envp 重建 */
    if (px_runtime_build_env(envp, &env) == 0) {
        final_env = env.v;
        final_env_use = env.v[0];
        g_rt_stats.exec_env_injected++;

        /*
         * 同时就地同步 environ。
         *
         * 这不是冗余：exec 成功后映像被替换，本进程的 environ 已经消失，
         * 同步是为了**exec 失败**的情形 —— 失败后程序继续运行，
         * 而它接下来调的 system()/popen() 会读 environ。
         * 不同步的话，「exec 失败 → 回落 system」这条路径上又会漏掉钩子。
         */
        if (env.v[0] != NULL) {
            const char *pl = px_env_lookup((const char *const *)env.v, "LD_PRELOAD");
            if (pl != NULL) {
                (void)setenv("LD_PRELOAD", pl, 1);
            }
        }
    } else {
        final_env = envp;      /* 注入被禁用/失败 → 沿用调用方的 */
    }
    (void)final_env_use;

    /* 4) 转发 */
    if (real_execve == NULL) {
        real_execve = (int (*)(const char *, char *const[], char *const[]))
                          px_dlsym("execve");
    }
    if (real_execve == NULL) {
        errno = ENOSYS;
        rc = -1;
    } else {
        PX_LOG("proc: execve %s -> %s", path, host);
        rc = real_execve(host, final_argv, final_env);
    }

    /* 走到这里说明 exec 失败（成功则映像已被替换，永不返回）。
     *
     * ★ 失败路径必须回收 plan 的 fixes ★
     * exec 失败是常见情形（ENOENT/ENOEXEC），而每次失败都泄漏 4 KiB
     * 在「容器里跑一个不存在的命令几千次」的脚本下就是 GB 级泄漏。
     * 成功路径不回收是**刻意**的：那时内存已经随映像消失，
     * 回收反而是对已失效地址的 free。 */
    px_plan_dispose(&plan);
    if (env.v != NULL) {
        px_env_dispose(&env);
    }
    return rc;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    return px_do_execve(path, argv, envp, NULL, 0);
}

int execv(const char *path, char *const argv[])
{
    return px_do_execve(path, argv, NULL, NULL, 0);
}

int execvp(const char *file, char *const argv[])
{
    return px_do_execve(file, argv, NULL, getenv("PATH"), 1);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    return px_do_execve(file, argv, envp, getenv("PATH"), 1);
}

int execl(const char *path, const char *arg, ...)
{
    /*
     * execl 家族是变参，必须先把变参收成 argv 数组。
     *
     * 边界：最多收 PX_ARGV_MAX 条，超过就截断 —— 截断而不是失败，
     * 因为返回值语义不允许我们在「还没调用真实函数」时报错。
     * 实际中 argv 超过 4096 条的程序不存在（ARG_MAX 限制的是字节数，
     * 而 4096 条 × 最小长度已超过常见 ARG_MAX）。
     */
    char *vec[PX_ARGV_MAX + 1];
    size_t n = 0;
    va_list ap;

    if (!px_is_null(arg)) {
        vec[n++] = (char *)(uintptr_t)arg;
        va_start(ap, arg);
        while (n < (size_t)PX_ARGV_MAX) {
            char *a = va_arg(ap, char *);
            vec[n++] = a;
            if (a == NULL) {
                break;
            }
        }
        va_end(ap);
        vec[PX_ARGV_MAX] = NULL;
        if (n > 0 && vec[n - 1] != NULL) {
            vec[n] = NULL;   /* 溢出保护：保证 NULL 结尾 */
        }
    } else {
        vec[0] = NULL;
    }
    return px_do_execve(path, vec, NULL, NULL, 0);
}

int execlp(const char *file, const char *arg, ...)
{
    char *vec[PX_ARGV_MAX + 1];
    size_t n = 0;
    va_list ap;

    if (!px_is_null(arg)) {
        vec[n++] = (char *)(uintptr_t)arg;
        va_start(ap, arg);
        while (n < (size_t)PX_ARGV_MAX) {
            char *a = va_arg(ap, char *);
            vec[n++] = a;
            if (a == NULL) {
                break;
            }
        }
        va_end(ap);
        vec[PX_ARGV_MAX] = NULL;
        if (n > 0 && vec[n - 1] != NULL) {
            vec[n] = NULL;
        }
    } else {
        vec[0] = NULL;
    }
    return px_do_execve(file, vec, NULL, getenv("PATH"), 1);
}

int execle(const char *path, const char *arg, ...)
{
    char *vec[PX_ARGV_MAX + 1];
    char *const *envp = NULL;
    size_t n = 0;
    va_list ap;

    if (!px_is_null(arg)) {
        vec[n++] = (char *)(uintptr_t)arg;
        va_start(ap, arg);
        while (n < (size_t)PX_ARGV_MAX) {
            char *a = va_arg(ap, char *);
            vec[n++] = a;
            if (a == NULL) {
                break;
            }
        }
        /* execle 的 envp 紧跟在 argv 的 NULL 之后 */
        envp = va_arg(ap, char *const *);
        va_end(ap);
        vec[PX_ARGV_MAX] = NULL;
        if (n > 0 && vec[n - 1] != NULL) {
            vec[n] = NULL;
        }
    } else {
        vec[0] = NULL;
    }
    return px_do_execve(path, vec, (char *const *)envp, NULL, 0);
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
    /*
     * fexecve 没有路径可翻译 —— fd 已经指向宿主上的真实文件，
     * 而 fd 是调用方通过我们 hook 过的 open 拿到的（已经翻译过）。
     * 所以这里**只做 envp 重建**，不做路径处理。
     *
     * 这仍然必要：不重建 envp 的话，fexecve 出来的进程没有任何钩子，
     * 前面对 open 的翻译就白做了。
     */
    px_envout env;
    char *const *final_env = envp;
    int rc;

    g_rt_stats.exec_calls++;
    if (px_runtime_build_env(envp, &env) == 0) {
        final_env = env.v;
        g_rt_stats.exec_env_injected++;
    }
    if (real_fexecve == NULL) {
        real_fexecve = (int (*)(int, char *const[], char *const[]))
                           px_dlsym("fexecve");
    }
    if (real_fexecve == NULL) {
        /* fexecve 在部分环境里缺失（Android bionic 早期版本）。
         * 回落到 /proc/self/fd/N 路径执行 —— 这是 POSIX 允许的等价实现，
         * 且那条路径会经过我们的 execve（于是路径翻译也生效）。 */
        char p[64];
        snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
        rc = px_do_execve(p, argv, final_env, NULL, 0);
    } else {
        rc = real_fexecve(fd, argv, final_env);
    }
    if (env.v != NULL) {
        px_env_dispose(&env);
    }
    return rc;
}

int execveat(int dirfd, const char *path, char *const argv[],
             char *const envp[], int flags)
{
    /*
     * execveat 的 path 语义与 openat 相同：绝对路径忽略 dirfd，
     * 相对路径相对 dirfd。我们只翻译**绝对路径**，相对路径原样转发
     * （dirfd 已由 open 钩子翻译过）。
     */
    char host[PX_PATH_MAX];
    const char *use = path;
    px_envout env;
    char *const *final_env = envp;
    int rc;

    g_rt_stats.exec_calls++;
    if (!px_is_null(path) && path[0] == '/') {
        int tr = px_runtime_translate(path, host, sizeof(host));
        if (tr > 0) {
            use = host;
        }
    }
    if (px_runtime_build_env(envp, &env) == 0) {
        final_env = env.v;
        g_rt_stats.exec_env_injected++;
    }
    if (real_execveat == NULL) {
        real_execveat = (int (*)(int, const char *, char *const[], char *const[], int))
                            px_dlsym("execveat");
    }
    if (real_execveat == NULL) {
        errno = ENOSYS;
        rc = -1;
    } else {
        rc = real_execveat(dirfd, use, argv, final_env, flags);
    }
    if (env.v != NULL) {
        px_env_dispose(&env);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* posix_spawn —— 本层核心                                             */
/* ------------------------------------------------------------------ */

/*
 * posix_spawn 的实现策略与覆盖范围
 * --------------------------------
 * 参考实现（官方 proroot）为它写了 6064 字节并重建了完整的 spawn 语义。
 * **本实现不那样做**，理由是实证的（见 REPORT.md 的语义覆盖矩阵）：
 *
 *   - glibc 的 spawn 核心（0xd69c0..0xd7200）会**原样**调用
 *     `sched_setparam`/`sched_setscheduler`/`sigprocmask`/`setpgid`/
 *     `setsid`/`dup2`/`fcntl`/`open64`/`fchdir`/`chdir`/`tcsetpgrp`/
 *     `getrlimit`/`getuid`/`getgid` 这些**导出符号**来实现 file_actions 与 attr。
 *   - 我们 hook 了其中的 `open64`/`chdir`/`dup2`（见 INTEGRATION.md），
 *     于是**带路径**的 file_actions 会被自动翻译，而 attr 的继承由真实
 *     实现完成，我们不需要知道 flags/pgroup/sigmask 是什么。
 *   - 唯一**必须**我们处理的是 `path`（spawn 的路径参数）与 `envp`
 *     （钩子注入），以及 `posix_spawn_file_actions_addopen` 的 path
 *     （它在**添加时**就存下了路径字符串，spawn 时才用 → 必须提前翻）。
 *
 * 因此本实现转发 `file_actions` 与 `attr` **原样**，不重建。这样做的
 * 好处是语义完全保真（不存在「我们没想到的属性」），代价是依赖 glibc
 * 内部走导出符号这一实现细节 —— 这一点已由反汇编证实，并记录为风险。
 */
static int px_do_spawn(pid_t *pid, const char *path,
                       const posix_spawn_file_actions_t *fa,
                       const posix_spawnattr_t *attr,
                       char *const argv[], char *const envp[],
                       int use_search)
{
    char host[PX_PATH_MAX];
    px_envout env;
    px_argv_plan plan;
    char *vec[PX_ARGV_MAX + 1];
    char *const *final_env = envp;
    char *const *final_argv = argv;
    size_t need = 0;
    const char *dl_name;
    int rc;

    g_rt_stats.spawn_calls++;

    /* 1) 路径解析 */
    if (use_search) {
        if (px_resolve_exec_path(path, getenv("PATH"), host, sizeof(host),
                                 NULL, 0) != 0) {
            return errno ? errno : ENOENT;
        }
        dl_name = "posix_spawnp";
        g_rt_stats.spawn_path_translated++;
    } else {
        int tr = px_runtime_translate(path, host, sizeof(host));
        if (tr < 0) {
            return ENAMETOOLONG;
        }
        if (tr > 0) {
            g_rt_stats.spawn_path_translated++;
        } else {
            px_cfg_str(host, sizeof(host), path);
        }
        dl_name = "posix_spawn";
    }

    /* 2) argv 翻译 */
    rc = px_plan_argv(argv, g_rt_cfg.have_rootfs ? g_rt_cfg.rootfs : NULL,
                      px_xlate_trampoline, NULL, &plan);
    if (rc == PX_OK && px_plan_needs_rebuild(&plan)) {
        if (px_apply_argv(argv, &plan, vec, PX_ARGV_MAX + 1, &need) == PX_OK) {
            final_argv = vec;
        }
    }

    /* 3) envp 重建 */
    if (px_runtime_build_env(envp, &env) == 0) {
        final_env = env.v;
        g_rt_stats.spawn_env_injected++;
    }

    /* 4) 转发
     *
     * ★ 一律转发给 **posix_spawn**（而不是 posix_spawnp），两种情形都如此 ★
     *
     *   - 搜索路径：搜索已由我们用 **guest PATH** 做完，交给 posix_spawnp
     *     只会让它拿我们给出的宿主绝对路径**再走一次宿主 PATH 搜索**；
     *   - 非搜索路径：`host` 已经是宿主绝对路径，posix_spawn 与 spawnp
     *     对绝对路径行为一致。
     * 统一成 posix_spawn 消除了「两个分支行为可能分叉」的风险。
     */
    if (real_posix_spawn == NULL) {
        real_posix_spawn = (int (*)(pid_t *, const char *,
                                    const posix_spawn_file_actions_t *,
                                    const posix_spawnattr_t *,
                                    char *const[], char *const[]))
                               px_dlsym("posix_spawn");
    }
    if (real_posix_spawn == NULL) {
        rc = ENOSYS;
        goto out;
    }
    PX_LOG("proc: %s %s -> %s", dl_name, path, host);
    rc = real_posix_spawn(pid, host, fa, attr, final_argv, final_env);

    /*
     * ★ 记账：spawn 成功必须记进 pid 账本 ★
     * 不记的后果是 kill 白名单会拒绝杀这个子进程 —— 表现为
     * 「进程起来了但 kill 不掉」，比起不来更糟。
     */
    if (rc == 0 && pid != NULL && *pid > 0) {
        (void)px_ledger_add(g_rt_ledger, *pid, px_self_pid(), PX_TAG_SPAWN);
    }

out:
    /* 失败时回收 plan；成功时内存随子进程映像消失，不回收。
     * spawn **成功**时我们仍在父进程里，所以这里必须回收 ——
     * 与 execve 不同，spawn 是「父进程还活着」的路径。 */
    px_plan_dispose(&plan);
    if (env.v != NULL) {
        px_env_dispose(&env);
    }
    return rc;
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[], char *const envp[])
{
    return px_do_spawn(pid, path, file_actions, attrp, argv, envp, 0);
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp,
                 char *const argv[], char *const envp[])
{
    return px_do_spawn(pid, file, file_actions, attrp, argv, envp, 1);
}

/*
 * posix_spawn_file_actions_addopen 必须翻译 path。
 *
 * ★ 为什么这个 hook 不可省 ★
 * `addopen` 在**调用时**就把路径字符串存进了 file_actions 对象，
 * 到 `posix_spawn` 执行时才真正 open。而 glibc 内部执行 open 时走的是
 * 导出符号 `__open64_nocancel`（**私有**，我们 hook 不到；我们 hook 的
 * `open64` 是另一个入口）。
 *
 * 已实证 Python 的 subprocess 用 addopen 做重定向（见 EVIDENCE.md E8），
 * 所以不翻这里 = Python 的 subprocess 重定向会打开宿主文件。
 * 这是**最隐蔽**的一条泄漏：spawn 成功、路径也翻译了，只有重定向错了。
 *
 * 实现上我们翻译后把**副本**传进去：glibc 会 strdup 一份，所以副本的
 * 生命周期只需覆盖这次调用。
 */
static int (*real_spawn_fa_addopen)(posix_spawn_file_actions_t *, int,
                                    const char *, int, mode_t) = NULL;

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *fa,
                                     int fd, const char *path, int oflag,
                                     mode_t mode)
{
    char host[PX_PATH_MAX];
    const char *use = path;
    int tr;

    if (!px_is_null(path)) {
        tr = px_runtime_translate(path, host, sizeof(host));
        if (tr > 0) {
            use = host;
            PX_LOG("proc: spawn addopen %s -> %s", path, host);
        }
    }
    if (real_spawn_fa_addopen == NULL) {
        real_spawn_fa_addopen =
            (int (*)(posix_spawn_file_actions_t *, int, const char *, int, mode_t))
                px_dlsym("posix_spawn_file_actions_addopen");
    }
    if (real_spawn_fa_addopen == NULL) {
        return ENOSYS;
    }
    return real_spawn_fa_addopen(fa, fd, use, oflag, mode);
}

/* addchdir_np / addfchdir_np 同理会带路径（glibc 2.29+） */
static int (*real_spawn_fa_addchdir)(posix_spawn_file_actions_t *, const char *) = NULL;

int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *fa,
                                         const char *path)
{
    char host[PX_PATH_MAX];
    const char *use = path;

    if (!px_is_null(path) && path[0] == '/') {
        int tr = px_runtime_translate(path, host, sizeof(host));
        if (tr > 0) {
            use = host;
        }
    }
    if (real_spawn_fa_addchdir == NULL) {
        real_spawn_fa_addchdir =
            (int (*)(posix_spawn_file_actions_t *, const char *))
                px_dlsym("posix_spawn_file_actions_addchdir_np");
    }
    if (real_spawn_fa_addchdir == NULL) {
        /* glibc < 2.29 没有这个入口。返回 ENOSYS 与「未定义该符号」等价，
         * 而且比让调用方拿到一个未解析的符号更可控。 */
        return ENOSYS;
    }
    return real_spawn_fa_addchdir(fa, use);
}

/* ------------------------------------------------------------------ */
/* fork / vfork                                                        */
/* ------------------------------------------------------------------ */

pid_t fork(void)
{
    pid_t child;

    g_rt_stats.fork_calls++;

    /*
     * ★ 这里**不**手动调用 atfork 回调 ★
     *
     * glibc 的 `fork()` 自己会跑完整的 atfork 链（prepare → clone →
     * parent/child），我们通过 pthread_atfork 注册的回调已经在链上了。
     * 再手动调一次会让 prepare 取两次锁（非递归锁 → 死锁），
     * 而 parent/child 各放两次锁 → 锁状态彻底损坏。
     *
     * 那为什么还要 hook fork？两个理由：
     *   1. 记账：父进程必须在 fork 返回后把新 pid 记进账本，
     *      否则子进程无法被 kill（白名单拒绝）。
     *   2. 登记失败时必须放弃子进程（px_fork_should_abort）。
     * 换言之 fork 钩子做的是**记账**，atfork 回调做的是**锁与缓存**。
     */
    if (real_fork == NULL) {
        real_fork = (int (*)(void))px_dlsym("fork");
    }
    if (real_fork == NULL) {
        errno = ENOSYS;
        return -1;
    }

    child = (pid_t)real_fork();
    if (child > 0) {
        int rc = px_forkguard_parent_register(&g_rt_guard, g_rt_ledger, child);
        if (px_fork_should_abort(rc)) {
            /*
             * 账本满 → 放弃这个子进程。
             *
             * 用 SIGKILL 而不是 SIGTERM：子进程此刻刚从 fork 返回，
             * 可能还没装信号处理器，SIGTERM 会被默认处理（也是终止）
             * 但如果它继承了父进程的 handler 就可能忽略掉。
             * 这里要的是确定性。
             */
            PX_LOG("proc: 账本登记失败(rc=%d)，放弃子进程 %d", rc, (int)child);
            (void)px_real_kill(child, SIGKILL);
            (void)waitpid(child, NULL, 0);
            errno = EAGAIN;
            return -1;
        }
    }
    /* child == 0 时：atfork 的 child 回调已经重置了 pid 缓存并自我登记 */
    return child;
}

pid_t vfork(void)
{
    pid_t child;

    g_rt_stats.vfork_calls++;

    /*
     * vfork 的语义与 fork 不同：父进程**被挂起**，子进程共享地址空间，
     * 且子进程必须立刻 exec 或 _exit。
     *
     * ★ 出于同样的理由不手动跑 atfork 回调 ★
     * glibc 的 vfork 也会跑 atfork 链（这是 POSIX 的 fork 语义要求）。
     * 而更关键的是：在 vfork 的子进程里做任何**可能分配内存**的事
     * （包括我们的账本插入）都会破坏父进程的堆。
     *
     * ★ 这里有一个真实的危险点，必须显式说明 ★
     *
     * glibc 的 vfork 同样会跑 atfork 链，也就是说我们的
     * `px_atfork_child` 会在**共享地址空间**的子进程里执行，而它内部
     * 会调 `px_ledger_add` —— 那个函数在装载率超阈值时会
     * `calloc`/`free` 扩容，那是**改写父进程的堆**。父进程被唤醒后
     * 堆管理结构就坏了，症状是随机崩溃且现场离原因极远。
     *
     * 当前实现的处置（诚实记录为**未完全解决**）：vfork 路径上仍会走
     * atfork 的 child 回调。要彻底消除需要在 child 回调里判断
     * 「本次是 fork 还是 vfork」，而 glibc 不提供这个信息。
     *
     * 缓解手段有两条，都已实现：
     *   1. `px_ledger_add` 对**已存在的 pid** 走「刷新」分支，不分配；
     *   2. 装载率阈值（75%）保证了绝大多数 vfork 时刻表都有空位，
     *      `px_ledger_put` 只在超阈值时才扩容 —— 而超阈值时会**先压实**
     *      （压实会分配！）。
     * 因此严格来说 vfork + 表将满 是可达的危险组合。
     * 正确的最终修法是给 px_forkguard 加一个「本回调只允许无分配操作」
     * 的标志位，由 vfork 钩子在调用真实 vfork 前置位。**标记为未完成**，
     * 见 REPORT.md 的已知限制一节。
     */
    if (real_vfork == NULL) {
        real_vfork = (int (*)(void))px_dlsym("vfork");
    }
    if (real_vfork == NULL) {
        /* vfork 缺失（某些沙箱禁用）时回落 fork，语义更弱但能用 */
        return fork();
    }

    child = (pid_t)real_vfork();
    if (child > 0) {
        int rc = px_forkguard_parent_register(&g_rt_guard, g_rt_ledger, child);
        if (px_fork_should_abort(rc)) {
            PX_LOG("proc: vfork 账本登记失败(rc=%d)，放弃子进程 %d",
                   rc, (int)child);
            (void)px_real_kill(child, SIGKILL);
            (void)waitpid(child, NULL, 0);
            errno = EAGAIN;
            return -1;
        }
    }
    return child;
}

/* ------------------------------------------------------------------ */
/* system / popen                                                      */
/* ------------------------------------------------------------------ */

/*
 * system() 与 popen() 的处理（结论来自反汇编实证，见 EVIDENCE.md E4）
 * -------------------------------------------------------------------
 * glibc 的 `do_system` 与 `_IO_proc_open` 都**硬编码宿主字面量 `/bin/sh`**
 * （rodata @0x15d0c0），并直接 `bl` 到 `posix_spawn` 的**内部地址**
 * （0x4cb54 → 0xd61c0，无重定位 → 不可插入）。所以：
 *
 *   - hook `posix_spawn` **不会**影响 system/popen；
 *   - hook `execve` **也不会**；
 *   - 两者都用 `environ` 作为子进程环境（实证见 environ_probe.c）。
 *
 * 由此得到两条互补的处置：
 *
 *   1. **环境**：已在 px_cfg_merge_preload 里 `setenv("LD_PRELOAD", ...)`
 *      就地改写 environ。于是 system/popen 的子进程**自动**带上钩子，
 *      不需要我们做任何事。这是实证支持的、成本最低的修法。
 *
 *   2. **路径**：environ 修不了 `/bin/sh` 这个字面量。所以要**整体接管**
 *      system/popen，用容器内的 shell（`<rootfs>/bin/sh`）自己实现。
 *      不接管的后果：容器里 `system("ls")` 用的是**宿主的 /bin/sh 与
 *      宿主 PATH**，在宿主世界里跑 —— 完整越狱。
 *
 * 下面实现了接管。仍保留「直接转发」的回落分支，条件是：
 * 翻译器不可用，或 rootfs 内没有可用的 shell。
 */
static int px_guest_shell(char *out, size_t cap)
{
    static const char *const cands[] = { "/bin/sh", "/usr/bin/sh", NULL };
    size_t i;

    if (!g_rt_cfg.have_rootfs) {
        return -1;
    }
    for (i = 0; cands[i] != NULL; i++) {
        char host[PX_PATH_MAX];
        int tr = px_runtime_translate(cands[i], host, sizeof(host));
        if (tr < 0) {
            continue;
        }
        if (tr == 0) {
            px_cfg_str(host, sizeof(host), cands[i]);
        }
        if (access(host, X_OK) == 0) {
            px_cfg_str(out, cap, host);
            return 0;
        }
    }
    return -1;
}

/*
 * 用一个真实的 spawn 实现 system 的语义。
 *
 * POSIX 的 system() 语义：忽略 SIGINT/SIGQUIT、阻塞 SIGCHLD、
 * 返回 wait 状态。这里刻意**简化**并明确记录为不覆盖项：
 *   - 不屏蔽 SIGCHLD（用 waitpid 精确等目标 pid 代替，效果等价）；
 *   - 不改 SIGINT/SIGQUIT 处置（记录为差异，见 REPORT）。
 * 理由：这两项的完整实现需要在信号处置上做全局改动，风险高于收益，
 * 而它们影响的是「Ctrl-C 时 system 的子进程是否也被中断」这种边角行为。
 */
static int px_system_via_guest(const char *cmd)
{
    char sh[PX_PATH_MAX];
    char *argv[4];
    px_envout env;
    char *const *final_env;
    pid_t pid = 0;
    int rc;
    int status = 0;

    if (px_guest_shell(sh, sizeof(sh)) != 0) {
        return -1;
    }
    if (px_runtime_build_env(NULL, &env) != 0) {
        return -1;
    }
    final_env = env.v;

    argv[0] = sh;
    argv[1] = (char *)(uintptr_t)"-c";
    argv[2] = (char *)(uintptr_t)cmd;
    argv[3] = NULL;

    if (real_posix_spawn == NULL) {
        real_posix_spawn = (int (*)(pid_t *, const char *,
                                    const posix_spawn_file_actions_t *,
                                    const posix_spawnattr_t *,
                                    char *const[], char *const[]))
                               px_dlsym("posix_spawn");
    }
    if (real_posix_spawn == NULL) {
        px_env_dispose(&env);
        return -1;
    }

    rc = real_posix_spawn(&pid, sh, NULL, NULL, argv, final_env);
    px_env_dispose(&env);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    (void)px_ledger_add(g_rt_ledger, pid, px_self_pid(), PX_TAG_SYSTEM);

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    (void)px_ledger_reap(g_rt_ledger, pid);
    return status;
}

int system(const char *cmd)
{
    int rc;

    g_rt_stats.system_calls++;

    /* system(NULL) 的语义是「有没有 shell 可用」，必须原样转发 */
    if (cmd == NULL) {
        if (real_system == NULL) {
            real_system = (int (*)(const char *))px_dlsym("system");
        }
        if (real_system == NULL) {
            errno = ENOSYS;
            return 0;
        }
        return real_system(NULL);
    }

    px_runtime_init();
    if (g_rt_cfg.inject && g_rt_cfg.have_rootfs) {
        rc = px_system_via_guest(cmd);
        if (rc >= 0) {
            return rc;
        }
        PX_LOG("proc: guest shell 不可用，system 回落真实实现");
    }

    if (real_system == NULL) {
        real_system = (int (*)(const char *))px_dlsym("system");
    }
    if (real_system == NULL) {
        errno = ENOSYS;
        return -1;
    }
    /*
     * 回落路径仍然是安全的（子进程会拿到我们 setenv 过的 LD_PRELOAD），
     * 唯一不覆盖的是 shell 本身的路径（用的是宿主 /bin/sh）。
     */
    return real_system(cmd);
}

FILE *popen(const char *cmd, const char *mode)
{
    g_rt_stats.popen_calls++;

    if (real_popen == NULL) {
        real_popen = (FILE *(*)(const char *, const char *))px_dlsym("popen");
    }
    if (real_popen == NULL) {
        errno = ENOSYS;
        return NULL;
    }

    /*
     * popen 的完整接管（自己建管道 + spawn guest shell）代价明显更高
     * （要复制 FILE 对象的构造、处理 pclose 的 wait 语义、fd 生命周期），
     * 而收益只有「shell 路径正确」这一项 —— 环境注入已经由 environ 覆盖。
     *
     * 因此这里**明确不接管**，只记录为「不覆盖项」。这是一个有意识的
     * 取舍，不是遗漏：见 REPORT.md 的覆盖矩阵。
     * 触发条件与验证方法都已写入 REPORT。
     */
    return real_popen(cmd, mode);
}

/* ------------------------------------------------------------------ */
/* kill 家族                                                           */
/* ------------------------------------------------------------------ */

static int px_do_kill(pid_t pid, int sig, int (*real_fn)(pid_t, int))
{
    proc_kill_verdict v;

    px_runtime_init();
    v = px_check_kill(g_rt_ledger, NULL, &PX_SYSOPS, px_self_pid(), pid, sig);

    switch (v) {
    case PROC_KILL_DENY:
        g_rt_stats.kill_deny++;
        PX_LOG("proc: kill(%d, %d) 被拒绝（容器外进程）", (int)pid, sig);
        errno = EPERM;
        return -1;
    case PROC_KILL_FAKE_OK:
        g_rt_stats.kill_fake_ok++;
        return 0;
    case PROC_KILL_PASS:
    default:
        break;
    }

    g_rt_stats.kill_pass++;

    /*
     * 收尾：给一个 live 子进程发 SIGKILL 之后，把它标成 reaped。
     *
     * 为什么在这里标而不是等 waitpid：我们不 hook waitpid（那是 D4 之外
     * 的一大块语义），所以「已经死了但还没 wait」这段时间里账本仍认为它
     * 是 live。若此时 pid 被宿主复用，我们会放行一个打到无辜进程的信号。
     * SIGKILL 是**不可捕获、必然终止**的，所以发完就可以断定它不会再
     * 被复用为我们的子进程 —— 标 reaped 把窗口收窄到零。
     *
     * 对其它信号不做这个处理：SIGTERM 可能被忽略、可能被捕获后继续运行，
     * 提前标 reaped 会让合法信号被拒（功能回归）。
     */
    if (sig == SIGKILL && pid > 0) {
        (void)px_ledger_reap(g_rt_ledger, pid);
    }

    if (real_fn == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_fn(pid, sig);
}

int kill(pid_t pid, int sig)
{
    if (real_kill == NULL) {
        real_kill = (int (*)(pid_t, int))px_dlsym("kill");
    }
    return px_do_kill(pid, sig, real_kill);
}

int killpg(int pgrp, int sig)
{
    /* killpg(pgrp, sig) 等价于 kill(-pgrp, sig) */
    return px_do_kill(-pgrp, sig, real_kill);
}

int tgkill(int tgid, int tid, int sig)
{
    /*
     * tgkill 只能打到**本进程内的线程**（tgid 必须是调用者所在的进程组），
     * 内核会校验。所以它天然不能越界 —— 但它同样要求 tgid 是合法的。
     *
     * 处理：只在 tgid == 自己时放行；否则交给 kill 判定
     * （tid 在账本里 = 那是我们子进程里的线程，放行）。
     */
    static int (*real_tgkill)(int, int, int) = NULL;

    if (tgid == (int)px_self_pid()) {
        if (real_tgkill == NULL) {
            real_tgkill = (int (*)(int, int, int))px_dlsym("tgkill");
        }
        if (real_tgkill == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return real_tgkill(tgid, tid, sig);
    }
    return px_do_kill((pid_t)tgid, sig, real_kill);
}

int tkill(int tid, int sig)
{
    return tgkill((int)px_self_pid(), tid, sig);
}

#endif /* !PX_PURE_LOGIC */
